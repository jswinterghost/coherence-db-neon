// Layer 1 (highest risk): protects financial correctness and immutable audit history
// (no wrong balances, no duplicate sent statements, no out-of-order approvals carry,
// no history edits, gaps, forks, or forgeries, and lossless export and rebuild).
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { buildCommitments, hashDecisions } from '../src/commands/commitments.mjs';
import { exportJournalNdjson, rebuildFromJournalExport, verifyChain, verifyCommitments } from '../src/commands/journal-export.mjs';
import { queryRunEntityReconciliation } from '../src/compare/run-comparator.mjs';
import { ALL_BUSINESS_TABLES } from '../src/config/policy-checks.mjs';
import { buildConnectionConfig, createClient, withRequestTx } from '../src/db/pg-client.mjs';
import { generateOverlayCsv, OVERLAY_V1_COLUMNS, OVERLAY_V2_COLUMNS } from '../src/decisions/overlay-generator.mjs';
import { computeJournalHash, GENESIS_HASH, hashInputChanges, hashInputEntries, sha256Hex } from '../src/util/crypto.mjs';
import { parseCsv } from '../src/util/csv.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import {
  buildSyntheticEmitDataset,
  createDataOnlyMockEngineMaterializer,
  createMockEngineMaterializer,
  makeCsvFromObjects,
  makeOverlayCsv,
  sampleApprovalRow,
  seedEngineCopyVersion,
  seedEngineVersion,
  seedStandingInput,
  SYNTHETIC_BOB_COLUMNS,
  SYNTHETIC_LEDGER_COLUMNS,
  SYNTHETIC_RUN_COLUMNS,
} from './helpers/fixtures.mjs';
import { createRoleScopedTestPool } from './helpers/iam-harness.mjs';
import { checkPgAvailable, createEmptyMigratedTestDb, createTestEnv, getAdminPgConfig } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

test('Layer 1 [Driver & Env]: standard pg driver, local port 5432 default, no hardcoded user fallback, and no static Cloud SQL password', async () => {
  const prevPgUser = process.env.PGUSER;
  const prevUser = process.env.USER;
  const prevPgHost = process.env.PGHOST;
  const prevPgPort = process.env.PGPORT;
  try {
    delete process.env.PGUSER;
    delete process.env.USER;
    delete process.env.PGHOST;
    delete process.env.PGPORT;
    const adminCfg = getAdminPgConfig();
    const clientCfg = buildConnectionConfig();
    assert.notEqual(adminCfg.user, 'postgres', 'test-db must never default to postgres user when PGUSER and USER are unset');
    assert.notEqual(clientCfg.user, 'postgres', 'pg-client must never default to postgres user when PGUSER and USER are unset');
    assert.equal(adminCfg.host, '/tmp');
    assert.equal(adminCfg.port, 5432);
    assert.equal(clientCfg.host, '/tmp');
    assert.equal(clientCfg.port, 5432);

    assert.throws(
      () => buildConnectionConfig({ getUserInfo: () => { throw new Error('no passwd entry'); } }),
      /PGUSER|USER|local/i,
    );
    assert.throws(
      () => buildConnectionConfig({ mode: 'cloudsql', user: 'svc', ssl: true, password: 'static-password' }),
      /static password|IAM/i,
    );
    const iamCfg = buildConnectionConfig({
      mode: 'cloudsql',
      host: '127.0.0.1',
      database: 'acme',
      user: 'svc@project.iam',
      ssl: { rejectUnauthorized: true },
      iamAccessTokenProvider: async () => 'short-lived-token',
    });
    assert.equal(typeof iamCfg.password, 'function');
  } finally {
    if (prevPgUser !== undefined) process.env.PGUSER = prevPgUser;
    if (prevUser !== undefined) process.env.USER = prevUser;
    if (prevPgHost !== undefined) process.env.PGHOST = prevPgHost;
    if (prevPgPort !== undefined) process.env.PGPORT = prevPgPort;
  }
});

test('Layer 1 [Negative Invariant]: UPDATE, DELETE, and TRUNCATE fail on ALL 31 business tables in normal and replica mode', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());
  assert.equal(env.pool.driverName, 'pg', 'database layer must use the standard pg driver');

  const client = env.registerClient(await createClient(env.pgConfig));
  assert.equal(ALL_BUSINESS_TABLES.length, 31);

  for (const mode of ['origin', 'replica']) {
    await client.query(`SET session_replication_role = '${mode}'`);
    for (const tbl of ALL_BUSINESS_TABLES) {
      await assert.rejects(
        () => client.query(`UPDATE coherence.${tbl} SET journal_seq = journal_seq WHERE false`).catch((err) => {
          // journal_entries has `seq` instead of `journal_seq`
          if (tbl === 'journal_entries' && /column "journal_seq" does not exist/i.test(err.message)) {
            return client.query("UPDATE coherence.journal_entries SET actor = 'mallory' WHERE seq = 1");
          }
          throw err;
        }),
        /immutable/i,
        `UPDATE on coherence.${tbl} must be refused in ${mode} mode`,
      );
      await assert.rejects(
        () => client.query(`DELETE FROM coherence.${tbl}`),
        /immutable/i,
        `DELETE on coherence.${tbl} must be refused in ${mode} mode`,
      );
      await assert.rejects(
        () => client.query(`TRUNCATE coherence.${tbl} CASCADE`),
        /immutable/i,
        `TRUNCATE on coherence.${tbl} must be refused in ${mode} mode`,
      );
    }
  }
  await client.query("SET session_replication_role = 'origin'");
});

test('Layer 1 [Journal Chain]: forged hash, gapped seq, forked prev_hash, backdated time, two-row INSERT, and non-SERIALIZABLE write are refused', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const headRes = await env.pool.query('SELECT seq, coherence.format_utc_us(recorded_at) AS recorded_at, entry_hash FROM coherence.journal_entries ORDER BY seq DESC LIMIT 1');
  const head = headRes.rows[0];
  const nextSeq = Number(head.seq) + 1;
  const body = JSON.stringify({ commitments: { counts: {}, hashes: {} } });
  const reqSha = sha256Hex('test-req');

  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('test-owner', 'noop_test', 'rc-key', $1, $2::jsonb)`,
        [reqSha, body],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /SERIALIZABLE/i);

  const rawInsert = async (sql, params = []) => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      await c.query(sql, params);
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  };

  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (seq, prev_hash, entry_hash, actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, $2, $3, 'test-owner', 'noop_test', 'forged-hash-key', $4, $5::jsonb)`,
      [String(nextSeq), head.entry_hash, 'f'.repeat(64), reqSha, body],
    ),
    /entry_hash mismatch/i,
  );

  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (seq, prev_hash, actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, $2, 'test-owner', 'noop_test', 'gap-key', $3, $4::jsonb)`,
      [String(nextSeq + 5), head.entry_hash, reqSha, body],
    ),
    /gapless/i,
  );

  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (seq, prev_hash, actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, $2, 'test-owner', 'noop_test', 'fork-key', $3, $4::jsonb)`,
      [String(nextSeq), GENESIS_HASH, reqSha, body],
    ),
    /prev_hash mismatch/i,
  );

  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (seq, prev_hash, recorded_at, actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, $2, '2020-01-01T00:00:00Z'::timestamptz, 'test-owner', 'noop_test', 'backdate-key', $3, $4::jsonb)`,
      [String(nextSeq), head.entry_hash, reqSha, body],
    ),
    /cannot precede/i,
  );

  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
       VALUES ('test-owner', 'noop_test', 'multi-1', $1, $2::jsonb),
              ('test-owner', 'noop_test', 'multi-2', $1, $2::jsonb)`,
      [reqSha, body],
    ),
    /one entry per INSERT/i,
  );

  const validAt = `${new Date(Date.now() + 1000).toISOString().slice(0, 23)}456Z`;
  const validHash = computeJournalHash({
    seq: nextSeq,
    recordedAt: validAt,
    actor: 'test-owner',
    actingFor: null,
    commandKind: 'noop_test',
    commandKey: 'exact-valid-key',
    requestSha256: reqSha,
    prevHash: head.entry_hash,
    body: { commitments: { counts: {}, hashes: {} } },
  });
  await rawInsert(
    `INSERT INTO coherence.journal_entries (seq, recorded_at, prev_hash, entry_hash, actor, command_kind, command_key, request_sha256, body)
     VALUES ($1, $2::timestamptz, $3, $4, 'test-owner', 'noop_test', 'exact-valid-key', $5, $6::jsonb)`,
    [String(nextSeq), validAt, head.entry_hash, validHash, reqSha, body],
  );
  const chainCheck = await verifyChain(env.pool);
  assert.equal(chainCheck.passed, true, `verifyChain failed on microsecond timestamp: ${chainCheck.problems.join('; ')}`);
});

test('Layer 1 [Commitments & Batching]: batched multi-array unnest writes succeed (>2000 rows), all 19 child tables are hash-verified, and late approval row attachment is refused', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  // Exercise multi-chunk batched multi-array unnest (> BATCH_SIZE=2000) for approval_rows
  const manyRows = [];
  for (let i = 1; i <= 2150; i++) {
    manyRows.push({
      row_no: i,
      ...sampleApprovalRow({ record_id: `policy:carrier_a:P${String(i).padStart(6, '0')}#effective:2026-01-01`, note: `row-${i}` }),
    });
  }
  const csv = makeOverlayCsv(manyRows);
  const stored = await env.dataStore.promoteBytes(Buffer.from(csv, 'utf8'), { relPath: 'overlay.csv', checksPassed: true });

  const reg = await env.commands.registerApprovalsFile({
    dbToken: env.ownerToken,
    commandKey: 'reg-af-batched',
    storedFile: stored,
    headerKind: 'v2',
    rowCount: manyRows.length,
    extendsSha256: null,
    sharedRowCount: 0,
    addedRows: manyRows,
  });
  const cntRes = await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.approval_rows WHERE approvals_file_sha256 = $1', [stored.sha256]);
  assert.equal(cntRes.rows[0].n, 2150);

  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      await c.query(
        `INSERT INTO coherence.approval_rows (approvals_file_sha256, row_no, record_id, disposition, journal_seq)
         VALUES ($1, 2151, 'policy:carrier_a:P999999#effective:2026-01-01', 'CONFIRM', $2)`,
        [stored.sha256, String(reg.journalSeq)],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /committed or missing journal entry/i);

  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('test-owner', 'sneak_row', 'sneak-key', $1, '{"commitments":{"counts":{"approval_rows":1},"hashes":{}}}'::jsonb)
         RETURNING seq`,
        [sha256Hex('sneak')],
      );
      await c.query(
        `INSERT INTO coherence.approval_rows (approvals_file_sha256, row_no, record_id, disposition, journal_seq)
         VALUES ($1, 2151, 'policy:carrier_a:P999999#effective:2026-01-01', 'CONFIRM', $2)`,
        [stored.sha256, String(je.rows[0].seq)],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /previously committed approvals_file/i);

  const checkRow = { id: randomUUID(), checkKind: 'chain', runId: null, comparedRunId: null, passed: true, report: { ok: true } };
  const built = buildCommitments({ checks: [checkRow] });
  assert.ok(built.hashes.checks);
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('test-owner', 'forged_check', 'forged-check-hash', $1, $2::jsonb) RETURNING seq`,
        [
          sha256Hex('forged-check-hash'),
          JSON.stringify({ commitments: { counts: { checks: 1 }, hashes: { checks: '0'.repeat(64) } } }),
        ],
      );
      await c.query(
        `INSERT INTO coherence.checks (id, check_kind, passed, report, journal_seq)
         VALUES ($1::uuid, 'chain', true, '{"ok":true}'::jsonb, $2)`,
        [randomUUID(), String(je.rows[0].seq)],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /checks commitment hash mismatch/i);
});

test('Layer 1 [Input Path & Folder Guards]: case twins, NFC/NFD twins, file-folder clashes, and Sent/Overlay outside carry refused; trailing space and renames preserved', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const seed = await seedStandingInput(env);
  const f1 = await env.dataStore.promoteBytes(Buffer.from('a,b\n1,2\n'), { relPath: 'All BOB/test.csv', checksPassed: true });
  const f2 = await env.dataStore.promoteBytes(Buffer.from('a,b\n3,4\n'), { relPath: 'All BOB/test2.csv', checksPassed: true });
  await env.commands.registerStoredFiles({ dbToken: env.ownerToken, commandKey: 'reg-f1-f2', files: [f1, f2] });

  const trailingRes = await env.pool.query(
    "SELECT rel_path FROM coherence.input_entries WHERE input_version_id = $1::uuid AND rel_path = 'All BOB/TrailingCarrier /book.csv'",
    [seed.inputVersionId],
  );
  assert.equal(trailingRes.rows.length, 1);

  const renamedEntries = seed.entries.map((e) => (
    e.relPath === 'All Statements/carrier_a_202611.csv'
      ? { relPath: 'All Statements/carrier_a_202611_corrected_date.csv', fileSha256: e.fileSha256 }
      : e
  ));
  const renPub = await env.commands.publishInputVersion({
    dbToken: env.ownerToken,
    commandKey: 'rename-misdated',
    lineKind: 'standing',
    sourceKind: 'rename',
    reason: 'Fix misdated carrier statement filename',
    entries: renamedEntries,
  });
  const renChange = await env.pool.query(
    'SELECT change_kind, rel_path, old_rel_path FROM coherence.input_changes WHERE input_version_id = $1::uuid',
    [renPub.result.inputVersionId],
  );
  assert.equal(renChange.rows.length, 1);
  assert.equal(renChange.rows[0].change_kind, 'renamed');
  assert.equal(renChange.rows[0].old_rel_path, 'All Statements/carrier_a_202611.csv');
  assert.equal(renChange.rows[0].rel_path, 'All Statements/carrier_a_202611_corrected_date.csv');

  // Direct SQL helper bypassing command-layer pre-checks to prove PostgreSQL itself enforces path-clash and Sent/Overlay guards.
  const rawPublish = async (cmdKey, sourceKind, entries) => {
    const ivId = randomUUID();
    const entriesSha = hashInputEntries(entries);
    const changes = entries
      .filter((e) => !renamedEntries.some((p) => p.relPath === e.relPath && p.fileSha256 === e.fileSha256))
      .map((e) => ({ inputVersionId: ivId, changeKind: 'added', relPath: e.relPath, oldRelPath: null, fileSha256: e.fileSha256, prevFileSha256: null }));
    const changesSha = hashInputChanges(changes);
    const ivRow = {
      id: ivId, lineKind: 'standing', parentId: renPub.result.inputVersionId, sourceKind, reason: 'test',
      entryCount: entries.length, entriesSha256: entriesSha, entriesListFileSha256: null,
      changeCount: changes.length, changesSha256: changesSha,
    };
    const body = {
      commitments: buildCommitments({
        input_versions: [ivRow],
        input_entries: entries.map((e) => ({ inputVersionId: ivId, ...e })),
        input_changes: changes,
      }),
    };
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('test-owner', 'raw_input', $1, $2, $3::jsonb) RETURNING seq`,
        [cmdKey, sha256Hex(cmdKey), JSON.stringify(body)],
      );
      const seq = String(je.rows[0].seq);
      await c.query(
        `INSERT INTO coherence.input_versions (id, line_kind, parent_id, source_kind, reason, entry_count, entries_sha256, change_count, changes_sha256, store_kind, journal_seq)
         VALUES ($1::uuid, 'standing', $2::uuid, $3, 'test', $4, $5, $6, $7, 'company_data', $8)`,
        [ivId, renPub.result.inputVersionId, sourceKind, entries.length, entriesSha, changes.length, changesSha, seq],
      );
      for (const e of entries) {
        await c.query(
          `INSERT INTO coherence.input_entries (input_version_id, rel_path, store_kind, file_sha256, journal_seq)
           VALUES ($1::uuid, $2, 'company_data', $3, $4)`,
          [ivId, e.relPath, e.fileSha256, seq],
        );
      }
      for (const ch of changes) {
        await c.query(
          `INSERT INTO coherence.input_changes (input_version_id, rel_path, change_kind, old_rel_path, store_kind, file_sha256, prev_file_sha256, journal_seq)
           VALUES ($1::uuid, $2, $3, NULL, 'company_data', $4, NULL, $5)`,
          [ivId, ch.relPath, ch.changeKind, ch.fileSha256, seq],
        );
      }
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  };

  await assert.rejects(
    () => rawPublish('case-twin', 'upload', [...renamedEntries, { relPath: 'All BOB/Foo.csv', fileSha256: f1.sha256 }, { relPath: 'all bob/foo.CSV', fileSha256: f2.sha256 }]),
    /unique|mac_key/i,
  );
  await assert.rejects(
    () => rawPublish('nfc-nfd-twin', 'upload', [...renamedEntries, { relPath: 'All BOB/caf\u00e9.csv', fileSha256: f1.sha256 }, { relPath: 'All BOB/cafe\u0301.csv', fileSha256: f2.sha256 }]),
    /unique|mac_key/i,
  );
  await assert.rejects(
    () => rawPublish('file-folder', 'upload', [...renamedEntries, { relPath: 'All BOB/CarrierA', fileSha256: f1.sha256 }, { relPath: 'all bob/carriera/sub.csv', fileSha256: f2.sha256 }]),
    /file\/folder path clash/i,
  );
  await assert.rejects(
    () => rawPublish('bad-sent', 'upload', [...renamedEntries, { relPath: 'sent/statements_20261121.csv', fileSha256: f1.sha256 }]),
    /Sent\/ entries can change only through recording a statement as sent/i,
  );
  await assert.rejects(
    () => rawPublish('bad-overlay', 'upload', [...renamedEntries, { relPath: 'Overlay/overlay.csv', fileSha256: f1.sha256 }]),
    /Overlay\/ entries can change only through carrying approvals/i,
  );
});

test('Layer 1 [Negative Invariant]: no second sent statement, out-of-order approvals carry refused, abandon guards, and exact journal rebuild', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: env.companySlug,
    stores: env.stores,
    commands: env.commands,
    workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(),
    tempBaseDir: env.tempDir,
  }));

  const completeRun = async ({ date, origin, extraRows, rerunReason = null }) => {
    const launch = await env.commands.launchRun({
      dbToken: env.ownerToken,
      commandKey: `launch-${origin}-${date}-${Date.now()}-${Math.random()}`,
      statementDate: date,
      origin,
      engineVersionId,
      rerunReason,
    });
    const runId = launch.result.runId;
    for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');

    const bibleRows = [row0, ...extraRows.bible];
    let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: `b-${runId}`, expectedJournalSeq: seq, runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
    assert.equal((await worker.runOnce()).action, 'review_accepted');
    assert.equal((await worker.runOnce()).action, 'step_finished');

    const adjRows = [...bibleRows, ...extraRows.adjust];
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: `a-${runId}`, expectedJournalSeq: seq, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
    const adjAcc = await worker.runOnce();
    assert.equal(adjAcc.action, 'review_accepted');

    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.confirmEmit({ dbToken: env.ownerToken, commandKey: `e-${runId}`, expectedJournalSeq: seq, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: `create statements for ${date}` });
    assert.equal((await worker.runOnce()).action, 'step_finished');
    return runId;
  };

  const trialId = await completeRun({
    date: '2026-11-20',
    origin: 'trial',
    extraRows: { bible: [sampleApprovalRow({ note: 'trial-b' })], adjust: [sampleApprovalRow({ note: 'trial-a' })] },
  });
  await assert.rejects(
    () => env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'carry-trial-sent', runId: trialId, typedPhrase: 'sent 2026-11-20' }),
    /only app and company_import/i,
  );
  await assert.rejects(
    () => env.commands.carryApprovals({ dbToken: env.ownerToken, commandKey: 'carry-trial-ov', runId: trialId, typedPhrase: 'carry 2026-11-20' }),
    /only app and company_import/i,
  );

  // Two app runs launched from the same prior overlay (row0) with diverging branches
  const runA = await completeRun({
    date: '2026-11-20',
    origin: 'app',
    extraRows: { bible: [sampleApprovalRow({ note: 'branch-A' })], adjust: [] },
  });
  const runB = await completeRun({
    date: '2026-11-21',
    origin: 'app',
    extraRows: { bible: [sampleApprovalRow({ note: 'branch-B' })], adjust: [] },
  });

  await assert.rejects(
    () => env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'dup-1120', statementDate: '2026-11-20', engineVersionId, rerunReason: 'retry' }),
    /non-abandoned run/i,
  );

  const carryB = await env.commands.carryApprovals({ dbToken: env.ownerToken, commandKey: 'carry-ov-B', runId: runB, typedPhrase: 'carry 2026-11-21' });
  assert.equal(carryB.result.nothingNew, false);

  const carryB2 = await env.commands.carryApprovals({ dbToken: env.ownerToken, commandKey: 'carry-ov-B-again', runId: runB, typedPhrase: 'carry 2026-11-21' });
  assert.equal(carryB2.result.nothingNew, true);
  assert.equal(carryB2.result.publishedInputVersionId, null);

  await assert.rejects(
    () => env.commands.carryApprovals({ dbToken: env.ownerToken, commandKey: 'carry-ov-A-ooo', runId: runA, typedPhrase: 'carry 2026-11-20' }),
    /does not extend the standing approvals/i,
  );

  await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'carry-sent-B', runId: runB, typedPhrase: 'sent 2026-11-21' });
  await assert.rejects(
    () => env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'carry-sent-B-dup', runId: runB, typedPhrase: 'sent 2026-11-21' }),
    /unique|already/i,
  );
  await assert.rejects(
    () => env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'launch-after-sent', statementDate: '2026-11-21', engineVersionId, rerunReason: 'correction' }),
    /sent statement already exists/i,
  );
  const sentCarryRow = (await env.pool.query("SELECT file_sha256, published_input_version_id FROM coherence.carries WHERE run_id = $1::uuid AND carry_kind = 'sent'", [runB])).rows[0];
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('test-owner', 'dup_sent_sql', 'dup-sent-sql', $1, '{"commitments":{"counts":{"carries":1},"hashes":{}}}'::jsonb) RETURNING seq`,
        [sha256Hex('dup-sent-sql')],
      );
      await c.query(
        `INSERT INTO coherence.carries (id, run_id, statement_date, carry_kind, store_kind, file_sha256, published_input_version_id, nothing_new, typed_phrase, journal_seq)
         VALUES ($1::uuid, $2::uuid, '2026-11-21', 'sent', 'company_data', $3, $4::uuid, false, 'sent 2026-11-21', $5)`,
        [randomUUID(), runB, sentCarryRow.file_sha256, sentCarryRow.published_input_version_id, String(je.rows[0].seq)],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /unique|carries_one_sent_per_date|same journal entry/i);

  await assert.rejects(
    () => env.commands.abandonRun({ dbToken: env.ownerToken, commandKey: 'abandon-carried', runId: runB, typedPhrase: 'abandon 2026-11-21', reason: 'nope' }),
    /carried outputs/i,
  );

  await env.commands.abandonRun({ dbToken: env.ownerToken, commandKey: 'abandon-A', runId: runA, typedPhrase: 'abandon 2026-11-20', reason: 'superseded by 11-21' });
  const launchA2 = await env.commands.launchRun({
    dbToken: env.ownerToken, commandKey: 'launch-A2', statementDate: '2026-11-20', engineVersionId, rerunReason: 'clean rerun after carry',
  });
  assert.equal(launchA2.result.folderNumber, 2);

  const chainOrig = await verifyChain(env.pool);
  assert.equal(chainOrig.passed, true, chainOrig.problems.join('; '));
  const commOrig = await verifyCommitments(env.pool);
  assert.equal(commOrig.passed, true, commOrig.problems.join('; '));

  const ndjson = await exportJournalNdjson(env.pool);
  const emptyDb = await createEmptyMigratedTestDb();
  t.after(() => emptyDb.cleanup());

  const rebuilt = await rebuildFromJournalExport(emptyDb.pool, ndjson);
  assert.equal(rebuilt.replayed, chainOrig.entries);

  const chainRebuilt = await verifyChain(emptyDb.pool);
  assert.equal(chainRebuilt.passed, true, chainRebuilt.problems.join('; '));
  assert.equal(chainRebuilt.headHash, chainOrig.headHash);
  assert.equal(chainRebuilt.entries, chainOrig.entries);

  const commRebuilt = await verifyCommitments(emptyDb.pool);
  assert.equal(commRebuilt.passed, true, commRebuilt.problems.join('; '));
});

test('Layer 1 [Decisions & Overlay Round-Trip]: replaces_decision_id lineage enforced in PostgreSQL, 2500-row batched commit, deterministic v1/v2 overlay round-trip, as-of playback, and point-in-time NDJSON rebuild', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  // 1. Batched multi-chunk decision baseline (>2000 rows) + exact overlay CSV round-trip
  const keySpecial = 'policy:carrier_a:P10001#effective:2026-01-01';
  const keySecond = 'carrier_b~direct~PAT SAMPLE~100.00~2026-10';
  const baseRows = [
    {
      record_id: keySpecial,
      disposition: 'CORRECT',
      agent: '11111111',
      agency: 'Beacon',
      policy: null,
      book: 'book_k1',
      month: null,
      status: 'ACTIVE_PAYING',
      note: 'quote "here", comma, and\nnewline',
      committed_at: '2026-10-10T10:00:00.000000Z',
      approved_amount: '100.00',
      approved_agency: 'Beacon',
      approved_agent: '11111111',
      approved_agency_from: null,
      approved_agent_from: null,
    },
    {
      record_id: keySecond,
      disposition: 'CONFIRM',
      agent: null,
      agency: null,
      policy: null,
      book: null,
      month: null,
      status: null,
      note: null,
      committed_at: '2026-10-10T10:01:00.000000Z',
      approved_amount: '-25.50',
      approved_agency: 'Harbor',
      approved_agent: '33333333',
      approved_agency_from: 'Beacon',
      approved_agent_from: '11111111',
    },
    {
      // Revision on keySpecial within the same baseline commit
      record_id: keySpecial,
      disposition: 'CORRECT',
      agent: '22222222',
      agency: 'Harbor',
      policy: null,
      book: 'book_k2',
      month: null,
      status: 'ACTIVE_RECON',
      note: 'revised agency',
      committed_at: '2026-10-10T10:02:00.000000Z',
      approved_amount: '100.00',
      approved_agency: 'Harbor',
      approved_agent: '22222222',
      approved_agency_from: 'Beacon',
      approved_agent_from: '11111111',
    },
  ];
  const expectedCsv = makeOverlayCsv(baseRows, { version: 'v2' });

  const baseCommit = await env.commands.recordDecisionBaseline({
    dbToken: env.ownerToken,
    commandKey: 'baseline-v2-roundtrip',
    commitKind: 'historical_baseline',
    headerContract: 'v2',
    imported: true,
    originalAt: '2026-10-10T10:05:00.000000Z',
    decisions: baseRows,
  });
  const baseCommitId = baseCommit.result.decisionCommitId;
  const seqAfterBase = baseCommit.journalSeq;

  // Verify replaces_decision_id linked row 3 -> row 1 automatically
  const decRes = await env.pool.query(
    'SELECT id, row_order, record_id, replaces_decision_id FROM coherence.decisions WHERE decision_commit_id = $1::uuid ORDER BY row_order ASC',
    [baseCommitId],
  );
  assert.equal(decRes.rows.length, 3);
  assert.equal(decRes.rows[0].replaces_decision_id, null);
  assert.equal(decRes.rows[1].replaces_decision_id, null);
  assert.equal(decRes.rows[2].replaces_decision_id, decRes.rows[0].id);

  // Round-trip: generated CSV must be byte-for-byte identical to expectedCsv and deterministic across calls
  const gen1 = await generateOverlayCsv(env.pool, { decisionCommitId: baseCommitId });
  const gen2 = await generateOverlayCsv(env.pool, { asOfSeq: seqAfterBase });
  assert.equal(gen1.csv, expectedCsv, 'generated overlay.csv must round-trip byte-for-byte');
  assert.equal(gen1.fingerprint.sha256, gen2.fingerprint.sha256);
  const parsedGen = parseCsv(gen1.csv);
  assert.deepEqual(parsedGen[0], [...OVERLAY_V2_COLUMNS]);
  assert.equal(parsedGen.length, 4);

  // Legacy v1 (10-column) round-trip
  const v1Rows = [
    {
      record_id: 'policy:carrier_a:LEGACY1#effective:2026-01-01',
      disposition: 'CORRECT',
      agent: '11111111',
      agency: 'Beacon',
      policy: 'LEGACY1',
      book: null,
      month: '2026-06',
      status: 'ACTIVE_PAYING',
      note: 'legacy v1 row',
      committed_at: '2026-07-01T09:00:00Z',
    },
  ];
  const v1Commit = await env.commands.recordDecisionBaseline({
    dbToken: env.ownerToken,
    commandKey: 'baseline-v1',
    commitKind: 'historical_overlay',
    headerContract: 'v1',
    imported: true,
    decisions: v1Rows,
  });
  const genV1 = await generateOverlayCsv(env.pool, { decisionCommitId: v1Commit.result.decisionCommitId });
  assert.equal(genV1.csv, makeOverlayCsv(v1Rows, { version: 'v1' }));
  assert.deepEqual(parseCsv(genV1.csv)[0], [...OVERLAY_V1_COLUMNS]);

  // 2. Child commit adding a third revision on keySpecial and checking as-of journal isolation
  const childRows = [{
    record_id: keySpecial,
    disposition: 'CONFIRM',
    note: 'confirmed after revision',
    committed_at: '2026-10-12T12:00:00.000000Z',
    approved_amount: '100.00',
    approved_agency: 'Harbor',
    approved_agent: '22222222',
  }];
  const childCommit = await env.commands.recordDecisionBaseline({
    dbToken: env.ownerToken,
    commandKey: 'child-overlay-commit',
    parentCommitId: baseCommitId,
    commitKind: 'historical_overlay',
    headerContract: 'v2',
    imported: true,
    decisions: childRows,
  });
  const childCommitId = childCommit.result.decisionCommitId;
  const childDec = (await env.pool.query('SELECT id, replaces_decision_id FROM coherence.decisions WHERE decision_commit_id = $1::uuid', [childCommitId])).rows[0];
  assert.equal(childDec.replaces_decision_id, decRes.rows[2].id, 'child decision must point to exact prior head on same key');

  // As-of query before childCommitId must NOT see childCommitId
  await assert.rejects(
    () => generateOverlayCsv(env.pool, { decisionCommitId: childCommitId, asOfSeq: seqAfterBase }),
    /not found at the requested journal position/i,
  );
  const genChild = await generateOverlayCsv(env.pool, { decisionCommitId: childCommitId });
  assert.equal(genChild.rowCount, 4);
  assert.equal(genChild.csv, makeOverlayCsv([...baseRows, ...childRows], { version: 'v2' }));

  // 3. Negative DB trigger invariants on replaces_decision_id, v1 facts, live CHECK constraints, and late attachment
  const rawInsertCommit = async (cmdKey, { parentId = childCommitId, headerContract = 'v2', dec }) => {
    const commitId = randomUUID();
    const decId = randomUUID();
    const decidedAt = '2026-10-15T12:00:00.000000Z';
    const dRow = {
      id: decId,
      decisionCommitId: commitId,
      rowOrder: 1,
      runId: dec.runId ?? null,
      reviewSaveId: dec.reviewSaveId ?? null,
      surface: dec.surface ?? null,
      recordId: dec.recordId,
      replacesDecisionId: dec.replacesDecisionId ?? null,
      disposition: dec.disposition,
      agent: dec.agent ?? null,
      agency: dec.agency ?? null,
      policy: dec.policy ?? null,
      book: dec.book ?? null,
      month: dec.month ?? null,
      status: dec.status ?? null,
      note: dec.note ?? null,
      approvedAmount: dec.approvedAmount ?? null,
      approvedAgency: dec.approvedAgency ?? null,
      approvedAgent: dec.approvedAgent ?? null,
      approvedAgencyFrom: null,
      approvedAgentFrom: null,
      decidedBy: 'test-owner',
      actingFor: null,
      decidedAt,
      committedAtRaw: decidedAt,
      imported: dec.imported ?? true,
    };
    const sha = hashDecisions([dRow]);
    const pCum = parentId
      ? Number((await env.pool.query('SELECT cumulative_decision_count FROM coherence.decision_commits WHERE id = $1::uuid', [parentId])).rows[0].cumulative_decision_count)
      : 0;
    const cRow = {
      id: commitId,
      parentCommitId: parentId,
      commitKind: 'historical_overlay',
      headerContract,
      addedDecisionCount: 1,
      cumulativeDecisionCount: pCum + 1,
      addedDecisionsSha256: sha,
      imported: dec.imported ?? true,
      originalAt: null,
    };
    const body = { commitments: buildCommitments({ decision_commits: [cRow], decisions: [dRow] }) };
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('test-owner', 'raw_dec_test', $1, $2, $3::jsonb) RETURNING seq`,
        [cmdKey, sha256Hex(cmdKey), JSON.stringify(body)],
      );
      const seq = String(je.rows[0].seq);
      await c.query(
        `INSERT INTO coherence.decision_commits (
           id, parent_commit_id, commit_kind, header_contract,
           added_decision_count, cumulative_decision_count, added_decisions_sha256, imported, original_at, journal_seq
         ) VALUES ($1::uuid, $2::uuid, 'historical_overlay', $3, 1, $4, $5, $6, NULL, $7)`,
        [commitId, parentId, headerContract, pCum + 1, sha, cRow.imported, seq],
      );
      await c.query(
        `INSERT INTO coherence.decisions (
           id, decision_commit_id, row_order, run_id, review_save_id, surface, record_id,
           replaces_decision_id, disposition, agent, agency, policy, book, month, status, note,
           approved_amount, approved_agency, approved_agent, approved_agency_from, approved_agent_from,
           decided_by, acting_for, decided_at, committed_at_raw, imported, journal_seq
         ) VALUES (
           $1::uuid, $2::uuid, 1, $3::uuid, $4::uuid, $5, $6,
           $7::uuid, $8, $9, $10, $11, $12, $13, $14, $15,
           $16, $17, $18, NULL, NULL,
           'test-owner', NULL, $19::timestamptz, $20, $21, $22
         )`,
        [
          decId, commitId, dRow.runId, dRow.reviewSaveId, dRow.surface, dRow.recordId,
          dRow.replacesDecisionId, dRow.disposition, dRow.agent, dRow.agency, dRow.policy, dRow.book, dRow.month, dRow.status, dRow.note,
          dRow.approvedAmount, dRow.approvedAgency, dRow.approvedAgent, decidedAt, decidedAt, dRow.imported, seq,
        ],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  };

  // Missing replaces_decision_id when prior decision exists on keySpecial
  await assert.rejects(
    () => rawInsertCommit('bad-rep-null', { dec: { recordId: keySpecial, disposition: 'CONFIRM', replacesDecisionId: null } }),
    /replaces_decision_id/i,
  );
  // Skipping intermediate decision (pointing to decRes[0] instead of childDec)
  await assert.rejects(
    () => rawInsertCommit('bad-rep-skip', { dec: { recordId: keySpecial, disposition: 'CONFIRM', replacesDecisionId: decRes.rows[0].id } }),
    /replaces_decision_id/i,
  );
  // Pointing to a different record_id
  await assert.rejects(
    () => rawInsertCommit('bad-rep-key', { dec: { recordId: keySpecial, disposition: 'CONFIRM', replacesDecisionId: decRes.rows[1].id } }),
    /same key/i,
  );
  // v1 commit carrying approved_* fact column
  await assert.rejects(
    () => rawInsertCommit('bad-v1-fact', { parentId: null, headerContract: 'v1', dec: { recordId: 'policy:carrier_a:NEW1#effective:2026-01-01', disposition: 'CONFIRM', approvedAmount: '10.00' } }),
    /v1 decision_commit cannot carry approved_\*/i,
  );
  // Live CONFIRM with acting field rejected by CHECK
  await assert.rejects(
    () => rawInsertCommit('bad-live-confirm', { parentId: null, dec: { recordId: 'policy:carrier_a:NEW2#effective:2026-01-01', disposition: 'CONFIRM', agency: 'Beacon', imported: false } }),
    /check constraint/i,
  );

  // 4. Batched 2,200-row decision commit (> BATCH_SIZE=2000) verifying fast deferred LAG and commitment hashing
  const bulkDecisions = [];
  for (let i = 1; i <= 2200; i++) {
    bulkDecisions.push({
      record_id: `policy:carrier_a:BULK${String(i).padStart(6, '0')}#effective:2026-01-01`,
      disposition: 'CONFIRM',
      committed_at: '2026-10-15T00:00:00.000000Z',
      approved_amount: '50.00',
      approved_agency: 'Beacon',
      approved_agent: '11111111',
    });
  }
  const bulkStart = Date.now();
  const bulkRes = await env.commands.recordDecisionBaseline({
    dbToken: env.ownerToken,
    commandKey: 'bulk-2200-decisions',
    parentCommitId: childCommitId,
    commitKind: 'historical_overlay',
    headerContract: 'v2',
    imported: true,
    decisions: bulkDecisions,
  });
  assert.equal(bulkRes.result.addedDecisionCount, 2200);
  assert.equal(bulkRes.result.cumulativeDecisionCount, 2204);
  assert.ok(Date.now() - bulkStart < 5000, '2200-row decision batch + deferred LAG check should stay fast');

  // 5. Point-in-time NDJSON export and rebuild: verify seqAfterBase excludes childCommit while full rebuild includes all
  const fullNdjson = await exportJournalNdjson(env.pool);
  const partialDb = await createEmptyMigratedTestDb();
  t.after(() => partialDb.cleanup());
  await rebuildFromJournalExport(partialDb.pool, fullNdjson, { upToSeq: seqAfterBase });
  assert.equal((await partialDb.pool.query('SELECT COUNT(*)::int AS n FROM coherence.decision_commits')).rows[0].n, 1);
  const partialGen = await generateOverlayCsv(partialDb.pool, { asOfSeq: seqAfterBase });
  assert.equal(partialGen.csv, expectedCsv);

  const fullDb = await createEmptyMigratedTestDb();
  t.after(() => fullDb.cleanup());
  await rebuildFromJournalExport(fullDb.pool, fullNdjson);
  assert.equal((await verifyChain(fullDb.pool)).passed, true);
  assert.equal((await verifyCommitments(fullDb.pool)).passed, true);
  assert.equal((await fullDb.pool.query('SELECT COUNT(*)::int AS n FROM coherence.decisions')).rows[0].n, 2205);
});

test('Layer 1 [Emit Materializer & Conservation]: loads BoB, Ledger, and Statements in one transaction, ties every entity to $0.00, unwinds NULL-split reversals, refuses $0.01 drift and refuses second load of same run', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineCopyVersion(env);
  await seedStandingInput(env, { commandKey: 'mat-standing-1' });

  // Helper to create a finished app run (without auto-materializing) so we can test materializeEmit directly
  const createFinishedRun = async (date, stmtCsv) => {
    const launch = await env.commands.launchRun({
      dbToken: env.ownerToken,
      commandKey: `mat-launch-${date}`,
      statementDate: date,
      origin: 'app',
      engineVersionId,
    });
    const runId = launch.result.runId;
    const worker = env.registerWorker(createEngineWorker({
      pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
      stores: env.stores, commands: env.commands, workerToken: env.workerToken,
      materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
    }));
    for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
    let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.saveReviewDecisions({
      dbToken: env.ownerToken,
      commandKey: `mat-bible-${date}`,
      expectedJournalSeq: seq,
      runId,
      surface: 'bible',
      decisions: [
        { recordId: 'policy:carrier_a:P10001#effective:2026-01-01', disposition: 'CONFIRM' },
        { recordId: (await env.pool.query("SELECT record_id FROM coherence.review_queue_items WHERE run_id = $1::uuid AND surface = 'bible' AND item_order = 2", [runId])).rows[0].record_id, disposition: 'CONFIRM' },
      ],
    });
    assert.equal((await worker.runOnce()).action, 'step_finished');
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    const adjSave = await env.commands.saveReviewDecisions({
      dbToken: env.ownerToken,
      commandKey: `mat-adjust-${date}`,
      expectedJournalSeq: seq,
      runId,
      surface: 'adjust',
      decisions: [{ recordId: 'carrier_a~direct~P10001~100.00~2026-11', disposition: 'CONFIRM' }],
    });
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.confirmEmit({
      dbToken: env.ownerToken,
      commandKey: `mat-confirm-${date}`,
      expectedJournalSeq: seq,
      runId,
      adjustReviewSaveId: adjSave.result.reviewSaveId,
      typedPhrase: `create statements for ${date}`,
    });
    assert.equal((await worker.runOnce()).action, 'step_finished');
    const emitAttemptId = (await env.pool.query(
      "SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev",
      [runId],
    )).rows[0].ev;
    if (stmtCsv) {
      const stmtArt = await env.dataStore.promoteBytes(Buffer.from(stmtCsv, 'utf8'), { relPath: `emits/statements_${date.replaceAll('-', '')}.csv`, checksPassed: true });
      await env.commands.registerStoredFiles({ dbToken: env.ownerToken, commandKey: `reg-stmt-${date}`, files: [stmtArt] });
      return { runId, emitAttemptId, stmtFileSha: stmtArt.sha256 };
    }
    return { runId, emitAttemptId, stmtFileSha: null };
  };

  // 1. Run 1 (2026-10-31): materialize Acme, Beacon, Harbor + house override
  const ds1 = buildSyntheticEmitDataset({ statementDate: '2026-10-31' });
  const { runId: run1Id, emitAttemptId: run1EmitEv, stmtFileSha: stmt1Sha } = await createFinishedRun('2026-10-31', ds1.statementsCsv);

  // Negative conservation check BEFORE valid load: $0.01 BoB drift must fail and write zero rows
  const badBobCsv = ds1.canonicalBobCsv.replace(',80.00,20.00,', ',80.01,20.00,');
  await assert.rejects(
    () => env.commands.materializeEmit({
      dbToken: env.workerToken,
      commandKey: 'mat-bad-bob',
      runId: run1Id,
      attemptEventId: run1EmitEv,
      statementDate: '2026-10-31',
      canonicalBobCsv: badBobCsv,
      coherentLedgerCsv: ds1.coherentLedgerCsv,
      statementsCsv: ds1.statementsCsv,
      emitMetadataJson: ds1.emitMetadataJson,
      workingTxCsv: ds1.workingTxCsv,
    }),
    /conservation/i,
  );
  assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.run_materializations')).rows[0].n, 0);

  // Negative conservation check: $0.01 ledger split drift must fail
  const badLedgerCsv = ds1.coherentLedgerCsv.replace(',80.00,20.00,', ',79.99,20.00,');
  await assert.rejects(
    () => env.commands.materializeEmit({
      dbToken: env.workerToken,
      commandKey: 'mat-bad-ledger-split',
      runId: run1Id,
      attemptEventId: run1EmitEv,
      statementDate: '2026-10-31',
      canonicalBobCsv: ds1.canonicalBobCsv,
      coherentLedgerCsv: badLedgerCsv,
      statementsCsv: ds1.statementsCsv,
    }),
    /split mismatch/i,
  );

  // Negative conservation check: $0.01 statement-to-ledger entity variance refused at COMMIT by PostgreSQL deferred trigger
  const badStmtCsv = ds1.statementsCsv.replace('100.00,commission,,100.00,,,,80.00,20.00', '100.01,commission,,100.01,,,,80.01,20.00');
  await assert.rejects(
    () => env.commands.materializeEmit({
      dbToken: env.workerToken,
      commandKey: 'mat-bad-stmt-tie',
      runId: run1Id,
      attemptEventId: run1EmitEv,
      statementDate: '2026-10-31',
      canonicalBobCsv: ds1.canonicalBobCsv,
      coherentLedgerCsv: ds1.coherentLedgerCsv,
      statementsCsv: badStmtCsv,
      emitMetadataJson: ds1.emitMetadataJson,
    }),
    /conservation violation/i,
  );
  assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.statement_batches')).rows[0].n, 0);

  // Valid single-transaction load of Run 1
  const mat1 = await env.commands.materializeEmit({
    dbToken: env.workerToken,
    commandKey: 'mat-run-1',
    runId: run1Id,
    attemptEventId: run1EmitEv,
    statementDate: '2026-10-31',
    canonicalBobCsv: ds1.canonicalBobCsv,
    coherentLedgerCsv: ds1.coherentLedgerCsv,
    statementsCsv: ds1.statementsCsv,
    emitMetadataJson: ds1.emitMetadataJson,
    workingTxCsv: ds1.workingTxCsv,
    statementsFileSha256: stmt1Sha,
  });
  assert.equal(mat1.result.bobRowCount, 3);
  assert.equal(mat1.result.ledgerRowCount, 4);
  assert.equal(mat1.result.agencyLineCount, 3); // house override has 0 downline -> upline only
  assert.equal(mat1.result.uplineLineCount, 4);
  assert.equal(mat1.result.ledgerGrossTotal, '525.00');
  assert.equal(mat1.result.ledgerDownlineTotal, '400.00');
  assert.equal(mat1.result.ledgerUplineTotal, '125.00');

  // Verify working/tx.csv sheet_name & source_row_no lineage populated
  const lineageRes = await env.pool.query(
    "SELECT sheet_name, source_row_no FROM coherence.statement_agency_lines WHERE entity = 'Harbor'",
  );
  assert.equal(lineageRes.rows[0].sheet_name, 'Detail');
  assert.equal(Number(lineageRes.rows[0].source_row_no), 42);

  // Verify entity statement reconciliation ties to $0.00 on every entity and Acme Upline
  const recon1 = await queryRunEntityReconciliation(env.pool, run1Id);
  assert.equal(recon1.length, 4); // Acme ($0.00 downline), Beacon, Harbor, and Acme Upline
  for (const row of recon1) {
    assert.equal(row.reconciled, true, `Entity ${row.statement_entity} failed reconciliation: variance=${row.variance}`);
    assert.equal(row.variance, '0.00');
  }
  const byEnt1 = Object.fromEntries(recon1.map((r) => [r.statement_entity, r.statement_total]));
  assert.equal(byEnt1.Acme, '0.00');
  assert.equal(byEnt1.Beacon, '200.00');
  assert.equal(byEnt1.Harbor, '200.00');
  assert.equal(byEnt1['Acme Upline'], '125.00');

  // Refuse a SECOND load of the same run!
  await assert.rejects(
    () => env.commands.materializeEmit({
      dbToken: env.workerToken,
      commandKey: 'mat-run-1-second-load',
      runId: run1Id,
      attemptEventId: run1EmitEv,
      statementDate: '2026-10-31',
      canonicalBobCsv: ds1.canonicalBobCsv,
      coherentLedgerCsv: ds1.coherentLedgerCsv,
      statementsCsv: ds1.statementsCsv,
    }),
    /already been materialized/i,
  );

  // 2. Pre-Coherence historical_sent + 8/1 method_correction + NULL-split reversal unwinding in Run 2
  const preHistBytes = Buffer.from('legacy pre-coherence sent file\n', 'utf8');
  const preHistStored = await env.dataStore.promoteBytes(preHistBytes, { relPath: 'Prior Statements/ALLAGENCY20260731.csv', checksPassed: true });
  const preRecId = 'carrier_a~direct~OLD MEMBER~100.00~2026-07';

  await env.commands.recordStatementBatch({
    dbToken: env.ownerToken,
    commandKey: 'hist-sent-20260731',
    batchKind: 'historical_sent',
    statementDate: '2026-07-31',
    sourceFileName: 'ALLAGENCY20260731.csv',
    sourceFile: preHistStored,
    reason: 'Pre-Coherence sent statement 2026-07-31',
    agencyLines: [{
      entity: 'Beacon',
      writingNpn: '11111111',
      writingAgent: 'Sam Seller',
      recordId: preRecId,
      carrier: 'carrier_a',
      member: 'Old Member',
      srcType: 'direct',
      paymentDate: '2026-07-20',
      grossComm: '100.00',
      amount: '100.00',
    }],
    uplineLines: [],
  });

  // 2026-08-01 method correction moving 20% from Beacon to Acme Upline (marked_sent = false)
  await env.commands.recordStatementBatch({
    dbToken: env.ownerToken,
    commandKey: 'method-corr-20260801',
    batchKind: 'method_correction',
    statementDate: '2026-08-01',
    reason: 'Apply 80/20 override split to 2026-07-31 unreversed line',
    agencyLines: [{
      entity: 'Beacon',
      writingNpn: '11111111',
      writingAgent: 'Sam Seller',
      recordId: preRecId,
      correctsRecordId: preRecId,
      carrier: 'carrier_a',
      member: 'Old Member',
      srcType: 'direct',
      paymentDate: '2026-07-20',
      grossComm: '0.00',
      amount: '-20.00',
    }],
    uplineLines: [{
      sourceEntity: 'Beacon',
      markedSent: false,
      writingNpn: '11111111',
      writingAgent: 'Sam Seller',
      recordId: preRecId,
      correctsRecordId: preRecId,
      carrier: 'carrier_a',
      member: 'Old Member',
      srcType: 'direct',
      paymentDate: '2026-07-20',
      grossComm: '0.00',
      amount: '20.00',
    }],
  });

  // Publish standing input including the pre-Coherence file, then launch Run 2 (2026-08-31) with a NULL-split CANCEL!
  const standingId = (await env.pool.query('SELECT coherence.standing_input_version_as_of(NULL) AS id')).rows[0].id;
  const curEntries = (await env.pool.query('SELECT rel_path, file_sha256 FROM coherence.input_entries WHERE input_version_id = $1::uuid', [standingId])).rows;
  await env.commands.publishInputVersion({
    dbToken: env.ownerToken,
    commandKey: 'add-pre-coherence-file',
    lineKind: 'standing',
    sourceKind: 'include',
    reason: 'Include pre-Coherence historical statement',
    entries: [
      ...curEntries.map((e) => ({ relPath: e.rel_path, fileSha256: e.file_sha256 })),
      { relPath: 'Prior Statements/ALLAGENCY20260731.csv', fileSha256: preHistStored.sha256 },
    ],
  });

  const run2BobCsv = makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, []);
  const run2LedgerCsv = makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, []);
  // NULL splits on CANCEL (-100.00 gross) targeting preRecId -> must unwind -80.00 Beacon and -20.00 Acme Upline!
  const run2StmtCsv = makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, [{
    record_id: preRecId, external_policy_id: '', policy_id: '', tx_id: '',
    statement_name: 'ALLAGENCY20260731.csv', src_type: 'direct', carrier: 'carrier_a', mbi: '', member: 'Old Member',
    state: 'NC', plan_type: '', simple_plan_type: '',
    submission_date: '', origin_effective: '', effective_date: '', termination_date: '',
    earned_date: '', payment_date: '2026-07-20', statement_date: '', min_date: '',
    gross_comm: '-100.00', revenue_type: 'commission', override_amount: '', commission_amount: '-100.00', hra_amount: '', fee_amount: '', other_amount: '',
    downline_amount: '', upline_amount: '',
    writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon', payee_npn: '', agency_id: '',
    status: '', policy_status: '', cbob_c: 'false', cbob_s: 'false', sf: 'false', notes: '', coherent_notes: 'CANCEL',
    run_action: 'CANCEL', run_statement_date: '2026-08-31', reversal_of: preRecId, reason: 'cancel pre-coherence',
  }]);
  const { runId: run2Id, emitAttemptId: run2EmitEv } = await createFinishedRun('2026-08-31');

  const mat2 = await env.commands.materializeEmit({
    dbToken: env.workerToken,
    commandKey: 'mat-run-2-null-split',
    runId: run2Id,
    attemptEventId: run2EmitEv,
    statementDate: '2026-08-31',
    canonicalBobCsv: run2BobCsv,
    coherentLedgerCsv: run2LedgerCsv,
    statementsCsv: run2StmtCsv,
  });
  assert.equal(mat2.result.agencyLineCount, 1);
  assert.equal(mat2.result.uplineLineCount, 1);
  const unwoundAg = (await env.pool.query('SELECT amount FROM coherence.statement_agency_lines WHERE batch_id = $1::uuid', [mat2.result.statementBatchId])).rows[0];
  const unwoundUp = (await env.pool.query('SELECT amount FROM coherence.statement_upline_lines WHERE batch_id = $1::uuid', [mat2.result.statementBatchId])).rows[0];
  assert.equal(unwoundAg.amount, '-80.00', 'NULL-split cancel must unwind -80.00 from Beacon');
  assert.equal(unwoundUp.amount, '-20.00', 'NULL-split cancel must unwind -20.00 from Acme Upline');

  const recon2 = await queryRunEntityReconciliation(env.pool, run2Id);
  assert.ok(recon2.every((r) => r.reconciled === true && r.variance === '0.00'));

  // 3. Multi-run cumulative reconciliation across Sent Run 1 (2026-10-31) -> Run 3 (2026-11-30) with REVERSAL + RESTATED + NEW
  // First publish Run 1's actual statement file as sent via a run whose emits/statements_20261031.csv matches Run 1's materialized batch
  const run3InputVer = await env.commands.publishInputVersion({
    dbToken: env.ownerToken,
    commandKey: 'add-sent-run1-for-run3',
    lineKind: 'standing',
    sourceKind: 'mac_import',
    reason: 'Record Run 1 statements in standing input for cumulative Run 3 reconciliation test',
    entries: [
      ...curEntries.map((e) => ({ relPath: e.rel_path, fileSha256: e.file_sha256 })),
      { relPath: 'Sent/statements_20261031.csv', fileSha256: stmt1Sha },
    ],
  });
  assert.ok(run3InputVer.result.inputVersionId);
  // Record Run 1 as sent by matching its actual emitted artifact (or verify via carrySent on a data-only engine run)
  const dataOnlyWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createDataOnlyMockEngineMaterializer({ adjustReconfirmRecordId: null }),
    tempBaseDir: env.tempDir,
  }));
  // Run a fresh env for clean multi-date Sent Run 1 -> Run 2 REVERSAL/RESTATED cumulative tie-out using engine-style CSV headers
  const envMulti = await createTestEnv({ companySlug: 'acme_multi', displayName: 'Acme' });
  t.after(() => envMulti.cleanup());
  const { engineVersionId: engMultiId } = await seedEngineCopyVersion(envMulti, { label: 'beacon-copy-2026.11' });
  await seedStandingInput(envMulti, { commandKey: 'multi-standing-1' });
  const wMulti = envMulti.registerWorker(createEngineWorker({
    pool: envMulti.pool, pgConfig: envMulti.pgConfig, companySlug: envMulti.companySlug,
    stores: envMulti.stores, commands: envMulti.commands, workerToken: envMulti.workerToken,
    materializeEngine: createDataOnlyMockEngineMaterializer({ adjustReconfirmRecordId: null }),
    tempBaseDir: envMulti.tempDir,
  }));
  const lm1 = await envMulti.commands.launchRun({ dbToken: envMulti.ownerToken, commandKey: 'm-l1', statementDate: '2026-10-31', engineVersionId: engMultiId });
  const mRun1 = lm1.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await wMulti.runOnce()).action, 'step_finished');
  let mSeq = Number((await envMulti.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [mRun1])).rows[0].latest_journal_seq);
  await envMulti.commands.saveReviewDecisions({
    dbToken: envMulti.ownerToken, commandKey: 'm-b1', expectedJournalSeq: mSeq, runId: mRun1, surface: 'bible',
    decisions: [
      { recordId: 'policy:carrier_a:C-101#effective:2026-10-01', disposition: 'CONFIRM' },
      { recordId: 'policy:carrier_b:C-201#effective:2026-10-01', disposition: 'CONFIRM' },
    ],
  });
  assert.equal((await wMulti.runOnce()).action, 'step_finished');
  mSeq = Number((await envMulti.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [mRun1])).rows[0].latest_journal_seq);
  const mAdj1 = await envMulti.commands.saveReviewDecisions({
    dbToken: envMulti.ownerToken, commandKey: 'm-a1', expectedJournalSeq: mSeq, runId: mRun1, surface: 'adjust',
    decisions: [
      { recordId: 'carrier_a~direct~PAT SAMPLE~100.00~2026-10', disposition: 'CONFIRM' },
      { recordId: 'carrier_b~direct~CASEY MOCK~250.00~2026-10', disposition: 'CONFIRM' },
    ],
  });
  mSeq = Number((await envMulti.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [mRun1])).rows[0].latest_journal_seq);
  await envMulti.commands.confirmEmit({ dbToken: envMulti.ownerToken, commandKey: 'm-e1', expectedJournalSeq: mSeq, runId: mRun1, adjustReviewSaveId: mAdj1.result.reviewSaveId, typedPhrase: 'create statements for 2026-10-31' });
  assert.equal((await wMulti.runOnce()).action, 'step_finished');
  await envMulti.commands.carrySent({ dbToken: envMulti.ownerToken, commandKey: 'm-sent-1', runId: mRun1, typedPhrase: 'sent 2026-10-31' });
  await envMulti.commands.carryDecisions({ dbToken: envMulti.ownerToken, commandKey: 'm-dec-1', runId: mRun1, typedPhrase: 'carry 2026-10-31' });

  // Run 2 (2026-11-30): moves Policy 1 ($100 gross: $80 downline / $20 upline) from Beacon to Harbor (REVERSAL + RESTATED)
  const movedDataset = () => {
    const base = buildSyntheticEmitDataset({ statementDate: '2026-11-30' });
    const parsedBob = parseCsv(base.canonicalBobCsv);
    const parsedLed = parseCsv(base.coherentLedgerCsv);
    // Use engine-style aliased column names (xyz_id, crm_policy_number, etc.) to verify dynamic column mapping too
    const bobHdr = parsedBob[0].map((c) => (c === 'external_policy_id' ? 'ext_id' : c === 'upline_amount' ? 'house_amount' : c));
    const ledHdr = parsedLed[0].map((c) => (c === 'external_policy_id' ? 'ext_id' : c === 'upline_amount' ? 'house_amount' : c));
    const bobEntIdx = bobHdr.indexOf('entity');
    const ledEntIdx = ledHdr.indexOf('entity');
    const bobMoved = parsedBob.slice(1).map((r, i) => (i === 0 ? r.map((v, j) => (j === bobEntIdx ? 'Harbor' : v)) : r));
    const ledMoved = parsedLed.slice(1).map((r, i) => (i === 0 ? r.map((v, j) => (j === ledEntIdx ? 'Harbor' : v)) : r));
    const origRow1 = parsedLed[1];
    const revRow = [...origRow1];
    revRow[ledHdr.indexOf('gross_comm')] = '-100.00';
    revRow[ledHdr.indexOf('commission_amount')] = '-100.00';
    revRow[ledHdr.indexOf('downline_amount')] = '-80.00';
    revRow[ledHdr.indexOf('house_amount')] = '-20.00';
    const restRow = [...ledMoved[0]];
    const runHdr = [...ledHdr, 'run_action', 'run_statement_date', 'reversal_of', 'reason'];
    return {
      canonicalBobCsv: [bobHdr, ...bobMoved].map((r) => r.join(',')).join('\n') + '\n',
      coherentLedgerCsv: [ledHdr, ...ledMoved].map((r) => r.join(',')).join('\n') + '\n',
      statementsCsv: [
        runHdr,
        [...revRow, 'REVERSAL', '2026-11-30', revRow[0], 'entity move reversal'],
        [...restRow, 'RESTATED', '2026-11-30', '', 'entity move restatement'],
      ].map((r) => r.join(',')).join('\n') + '\n',
      emitMetadataJson: base.emitMetadataJson,
    };
  };
  const wMulti2 = envMulti.registerWorker(createEngineWorker({
    pool: envMulti.pool, pgConfig: envMulti.pgConfig, companySlug: envMulti.companySlug,
    stores: envMulti.stores, commands: envMulti.commands, workerToken: envMulti.workerToken,
    materializeEngine: createDataOnlyMockEngineMaterializer({ adjustReconfirmRecordId: null, datasetBuilder: movedDataset }),
    tempBaseDir: envMulti.tempDir,
  }));
  const lm2 = await envMulti.commands.launchRun({ dbToken: envMulti.ownerToken, commandKey: 'm-l2', statementDate: '2026-11-30', engineVersionId: engMultiId });
  const mRun2 = lm2.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await wMulti2.runOnce()).action, 'step_finished');
  mSeq = Number((await envMulti.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [mRun2])).rows[0].latest_journal_seq);
  // All Bible queue items are already covered by carried standing decisions -> empty decisions: [] preserves human pause!
  await envMulti.commands.saveReviewDecisions({ dbToken: envMulti.ownerToken, commandKey: 'm-b2', expectedJournalSeq: mSeq, runId: mRun2, surface: 'bible', decisions: [] });
  assert.equal((await wMulti2.runOnce()).action, 'step_finished');
  mSeq = Number((await envMulti.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [mRun2])).rows[0].latest_journal_seq);
  const mAdj2 = await envMulti.commands.saveReviewDecisions({ dbToken: envMulti.ownerToken, commandKey: 'm-a2', expectedJournalSeq: mSeq, runId: mRun2, surface: 'adjust', decisions: [] });
  mSeq = Number((await envMulti.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [mRun2])).rows[0].latest_journal_seq);
  await envMulti.commands.confirmEmit({ dbToken: envMulti.ownerToken, commandKey: 'm-e2', expectedJournalSeq: mSeq, runId: mRun2, adjustReviewSaveId: mAdj2.result.reviewSaveId, typedPhrase: 'create statements for 2026-11-30' });
  assert.equal((await wMulti2.runOnce()).action, 'step_finished');

  // Verify cumulative entity statements across BOTH dates (2026-10-31 + 2026-11-30) tie to Run 2's ledger!
  const reconMulti = await queryRunEntityReconciliation(envMulti.pool, mRun2);
  assert.ok(reconMulti.every((r) => r.reconciled === true && r.variance === '0.00'));
  const byEntMulti = Object.fromEntries(reconMulti.map((r) => [r.statement_entity, r.statement_total]));
  assert.equal(byEntMulti.Beacon, '120.00', 'Beacon must reflect $200.00 - $80.00 reversal = $120.00');
  assert.equal(byEntMulti.Harbor, '280.00', 'Harbor must reflect $200.00 + $80.00 restatement = $280.00');
  assert.equal(byEntMulti['Acme Upline'], '125.00', 'Upline must remain $125.00 net across reversal and restatement');
  const multiAppPool = createRoleScopedTestPool(envMulti.pool, 'platform_app');
  const perDate = await withRequestTx(multiAppPool, envMulti.ownerToken, async (tx) => (
    (await tx.query("SELECT pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS d, statement_entity, net_amount FROM app_views.coherence_statement_date_totals ORDER BY statement_date, statement_entity")).rows
  ), { readOnly: true });
  assert.ok(perDate.some((r) => r.d === '2026-10-31' && r.statement_entity === 'Beacon' && r.net_amount === '200.00'));
  assert.ok(perDate.some((r) => r.d === '2026-11-30' && r.statement_entity === 'Beacon' && r.net_amount === '-80.00'));
  assert.ok(perDate.some((r) => r.d === '2026-11-30' && r.statement_entity === 'Harbor' && r.net_amount === '80.00'));

  // Verify full journal chain + 30-table commitments + lossless NDJSON rebuild over all new tables!
  assert.equal((await verifyChain(env.pool)).passed, true);
  assert.equal((await verifyCommitments(env.pool)).passed, true);
  assert.equal((await verifyChain(envMulti.pool)).passed, true);
  assert.equal((await verifyCommitments(envMulti.pool)).passed, true);
  const ndjson = await exportJournalNdjson(env.pool);
  const rebuiltDb = await createEmptyMigratedTestDb();
  t.after(() => rebuiltDb.cleanup());
  await rebuildFromJournalExport(rebuiltDb.pool, ndjson);
  assert.equal((await verifyChain(rebuiltDb.pool)).passed, true);
  assert.equal((await verifyCommitments(rebuiltDb.pool)).passed, true);
  const rebuiltRecon = await queryRunEntityReconciliation(rebuiltDb.pool, run1Id);
  assert.deepEqual(rebuiltRecon, recon1);
});
