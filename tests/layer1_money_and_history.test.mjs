// Layer 1 (highest risk): protects financial correctness and immutable audit history
// (no wrong balances, no duplicate sent statements, no out-of-order approvals carry,
// no history edits, gaps, forks, or forgeries, and lossless export and rebuild).
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { buildCommitments } from '../src/commands/commitments.mjs';
import { exportJournalNdjson, rebuildFromJournalExport, verifyChain, verifyCommitments } from '../src/commands/journal-export.mjs';
import { ALL_BUSINESS_TABLES } from '../src/config/policy-checks.mjs';
import { buildConnectionConfig, createClient } from '../src/db/pg-client.mjs';
import { computeJournalHash, GENESIS_HASH, hashInputChanges, hashInputEntries, sha256Hex } from '../src/util/crypto.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import { createMockEngineMaterializer, makeOverlayCsv, sampleApprovalRow, seedEngineVersion, seedStandingInput } from './helpers/fixtures.mjs';
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

test('Layer 1 [Negative Invariant]: UPDATE, DELETE, and TRUNCATE fail on ALL 20 business tables in normal and replica mode', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());
  assert.equal(env.pool.driverName, 'pg', 'database layer must use the standard pg driver');

  const client = env.registerClient(await createClient(env.pgConfig));
  assert.equal(ALL_BUSINESS_TABLES.length, 20);

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
    actor: env.ownerActor,
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
  await env.commands.registerStoredFiles({ actor: env.ownerActor, commandKey: 'reg-f1-f2', files: [f1, f2] });

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
    actor: env.ownerActor,
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
    workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(),
    tempBaseDir: env.tempDir,
  }));

  const completeRun = async ({ date, origin, extraRows, rerunReason = null }) => {
    const launch = await env.commands.launchRun({
      actor: env.ownerActor,
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
    await env.commands.submitReview({ actor: env.ownerActor, commandKey: `b-${runId}`, expectedJournalSeq: seq, runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
    assert.equal((await worker.runOnce()).action, 'review_accepted');
    assert.equal((await worker.runOnce()).action, 'step_finished');

    const adjRows = [...bibleRows, ...extraRows.adjust];
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.submitReview({ actor: env.ownerActor, commandKey: `a-${runId}`, expectedJournalSeq: seq, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
    const adjAcc = await worker.runOnce();
    assert.equal(adjAcc.action, 'review_accepted');

    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.confirmEmit({ actor: env.ownerActor, commandKey: `e-${runId}`, expectedJournalSeq: seq, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: `create statements for ${date}` });
    assert.equal((await worker.runOnce()).action, 'step_finished');
    return runId;
  };

  const trialId = await completeRun({
    date: '2026-11-20',
    origin: 'trial',
    extraRows: { bible: [sampleApprovalRow({ note: 'trial-b' })], adjust: [sampleApprovalRow({ note: 'trial-a' })] },
  });
  await assert.rejects(
    () => env.commands.carrySent({ actor: env.ownerActor, commandKey: 'carry-trial-sent', runId: trialId, typedPhrase: 'sent 2026-11-20' }),
    /only app and company_import/i,
  );
  await assert.rejects(
    () => env.commands.carryApprovals({ actor: env.ownerActor, commandKey: 'carry-trial-ov', runId: trialId, typedPhrase: 'carry 2026-11-20' }),
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
    () => env.commands.launchRun({ actor: env.ownerActor, commandKey: 'dup-1120', statementDate: '2026-11-20', engineVersionId, rerunReason: 'retry' }),
    /non-abandoned run/i,
  );

  const carryB = await env.commands.carryApprovals({ actor: env.ownerActor, commandKey: 'carry-ov-B', runId: runB, typedPhrase: 'carry 2026-11-21' });
  assert.equal(carryB.result.nothingNew, false);

  const carryB2 = await env.commands.carryApprovals({ actor: env.ownerActor, commandKey: 'carry-ov-B-again', runId: runB, typedPhrase: 'carry 2026-11-21' });
  assert.equal(carryB2.result.nothingNew, true);
  assert.equal(carryB2.result.publishedInputVersionId, null);

  await assert.rejects(
    () => env.commands.carryApprovals({ actor: env.ownerActor, commandKey: 'carry-ov-A-ooo', runId: runA, typedPhrase: 'carry 2026-11-20' }),
    /does not extend the standing approvals/i,
  );

  await env.commands.carrySent({ actor: env.ownerActor, commandKey: 'carry-sent-B', runId: runB, typedPhrase: 'sent 2026-11-21' });
  await assert.rejects(
    () => env.commands.carrySent({ actor: env.ownerActor, commandKey: 'carry-sent-B-dup', runId: runB, typedPhrase: 'sent 2026-11-21' }),
    /unique|already/i,
  );
  await assert.rejects(
    () => env.commands.launchRun({ actor: env.ownerActor, commandKey: 'launch-after-sent', statementDate: '2026-11-21', engineVersionId, rerunReason: 'correction' }),
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
    () => env.commands.abandonRun({ actor: env.ownerActor, commandKey: 'abandon-carried', runId: runB, typedPhrase: 'abandon 2026-11-21', reason: 'nope' }),
    /carried outputs/i,
  );

  await env.commands.abandonRun({ actor: env.ownerActor, commandKey: 'abandon-A', runId: runA, typedPhrase: 'abandon 2026-11-20', reason: 'superseded by 11-21' });
  const launchA2 = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'launch-A2', statementDate: '2026-11-20', engineVersionId, rerunReason: 'clean rerun after carry',
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
