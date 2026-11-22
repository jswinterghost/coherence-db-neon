// ============================================================================
// LAYER 1 (HIGHEST RISK): MONEY AND HISTORY
// Protects: financial correctness and immutable audit history — preventing a
// wrong or lost commission/statement amount, a statement sent twice for a date,
// an out-of-order approvals carry dropping prior approvals, history rewritten,
// gapped, forked, or forged, or lossy export/rebuild.
// ============================================================================
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { ALL_BUSINESS_TABLES } from '../src/config/policy-checks.mjs';
import { exportJournalNdjson, rebuildFromJournalExport, verifyChain, verifyCommitments } from '../src/commands/journal-export.mjs';
import { buildConnectionConfig, createClient } from '../src/db/pg-client.mjs';
import { computeJournalHash, GENESIS_HASH, hashInputChanges, hashInputEntries, sha256Hex } from '../src/util/crypto.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import { createMockEngineMaterializer, makeOverlayCsv, sampleApprovalRow, seedEngineVersion, seedStandingInput } from './helpers/fixtures.mjs';
import { checkPgAvailable, createEmptyMigratedTestDb, createTestEnv, getAdminPgConfig } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

test('Layer 1 [Driver & Env]: uses standard pg driver and never signs in as postgres when PGUSER and USER are unset', async () => {
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
    assert.equal(adminCfg.port, 5433);
    assert.equal(clientCfg.host, '/tmp');
    assert.equal(clientCfg.port, 5433);
  } finally {
    if (prevPgUser !== undefined) process.env.PGUSER = prevPgUser;
    if (prevUser !== undefined) process.env.USER = prevUser;
    if (prevPgHost !== undefined) process.env.PGHOST = prevPgHost;
    if (prevPgPort !== undefined) process.env.PGPORT = prevPgPort;
  }
});

test('Layer 1 [Negative Invariant — R9.1]: UPDATE, DELETE, and TRUNCATE fail on ALL 20 business tables (normal AND replica mode)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
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

test('Layer 1 [R9.2 & R11]: forged hash, gapped seq, forked prev_hash, backdated time, two-row INSERT, and non-SERIALIZABLE write are refused (never overwritten)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const headRes = await env.pool.query('SELECT seq, coherence.format_utc_us(recorded_at) AS recorded_at, entry_hash FROM coherence.journal_entries ORDER BY seq DESC LIMIT 1');
  const head = headRes.rows[0];
  const nextSeq = Number(head.seq) + 1;
  const body = JSON.stringify({ commitments: { counts: {}, hashes: {} } });
  const reqSha = sha256Hex('test-req');

  // 1. Non-SERIALIZABLE (READ COMMITTED) refused
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('kairon', 'noop_test', 'rc-key', $1, $2::jsonb)`,
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

  // 2. Forged entry_hash refused (trigger verifies instead of overwriting!)
  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (seq, prev_hash, entry_hash, actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, $2, $3, 'kairon', 'noop_test', 'forged-hash-key', $4, $5::jsonb)`,
      [String(nextSeq), head.entry_hash, 'f'.repeat(64), reqSha, body],
    ),
    /entry_hash mismatch/i,
  );

  // 3. Gapped seq refused (trigger verifies instead of overwriting!)
  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (seq, prev_hash, actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, $2, 'kairon', 'noop_test', 'gap-key', $3, $4::jsonb)`,
      [String(nextSeq + 5), head.entry_hash, reqSha, body],
    ),
    /gapless/i,
  );

  // 4. Forked prev_hash refused
  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (seq, prev_hash, actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, $2, 'kairon', 'noop_test', 'fork-key', $3, $4::jsonb)`,
      [String(nextSeq), GENESIS_HASH, reqSha, body],
    ),
    /prev_hash mismatch/i,
  );

  // 5. Backdated recorded_at refused
  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (seq, prev_hash, recorded_at, actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, $2, '2020-01-01T00:00:00Z'::timestamptz, 'kairon', 'noop_test', 'backdate-key', $3, $4::jsonb)`,
      [String(nextSeq), head.entry_hash, reqSha, body],
    ),
    /cannot precede/i,
  );

  // 6. Two-row single INSERT statement refused (R9.2 & R11 multi-row audit)
  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
       VALUES ('kairon', 'noop_test', 'multi-1', $1, $2::jsonb),
              ('kairon', 'noop_test', 'multi-2', $1, $2::jsonb)`,
      [reqSha, body],
    ),
    /one entry per INSERT/i,
  );

  // 7. Exact given seq, prev_hash, recorded_at (including non-zero microseconds), and valid entry_hash succeeds!
  const validAt = `${new Date(Date.now() + 1000).toISOString().slice(0, 23)}456Z`;
  const validHash = computeJournalHash({
    seq: nextSeq,
    recordedAt: validAt,
    actor: 'kairon',
    actingFor: null,
    commandKind: 'noop_test',
    commandKey: 'exact-valid-key',
    requestSha256: reqSha,
    prevHash: head.entry_hash,
    body: { commitments: { counts: {}, hashes: {} } },
  });
  await rawInsert(
    `INSERT INTO coherence.journal_entries (seq, recorded_at, prev_hash, entry_hash, actor, command_kind, command_key, request_sha256, body)
     VALUES ($1, $2::timestamptz, $3, $4, 'kairon', 'noop_test', 'exact-valid-key', $5, $6::jsonb)`,
    [String(nextSeq), validAt, head.entry_hash, validHash, reqSha, body],
  );
  const chainCheck = await verifyChain(env.pool);
  assert.equal(chainCheck.passed, true, `verifyChain failed on microsecond timestamp: ${chainCheck.problems.join('; ')}`);
});

test('Layer 1 [R9.3, R10.10 & R18]: batched multi-array unnest writes succeed (>2000 rows) and adding a row to a committed approvals file is refused', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  // Exercise multi-chunk batched multi-array unnest (> BATCH_SIZE=2000) for approval_rows
  const manyRows = [];
  for (let i = 1; i <= 2150; i++) {
    manyRows.push({
      row_no: i,
      ...sampleApprovalRow({ record_id: `policy:aetna:P${String(i).padStart(6, '0')}#effective:2026-01-01`, note: `row-${i}` }),
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

  // Attempt 1: insert extra row referencing original committed journal_seq -> REFUSED
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      await c.query(
        `INSERT INTO coherence.approval_rows (approvals_file_sha256, row_no, record_id, disposition, journal_seq)
         VALUES ($1, 2151, 'policy:aetna:P999999#effective:2026-01-01', 'CONFIRM', $2)`,
        [stored.sha256, String(reg.journalSeq)],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /committed or missing journal entry/i);

  // Attempt 2: insert extra row in a brand-new journal entry -> REFUSED
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('kairon', 'sneak_row', 'sneak-key', $1, '{"commitments":{"counts":{"approval_rows":1},"hashes":{}}}'::jsonb)
         RETURNING seq`,
        [sha256Hex('sneak')],
      );
      await c.query(
        `INSERT INTO coherence.approval_rows (approvals_file_sha256, row_no, record_id, disposition, journal_seq)
         VALUES ($1, 2151, 'policy:aetna:P999999#effective:2026-01-01', 'CONFIRM', $2)`,
        [stored.sha256, String(je.rows[0].seq)],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /previously committed approvals_file/i);
});

test('Layer 1 [R9.5, R11 (DS-1, DS-2, 11/21 renames)]: case twins, NFC/NFD twins, file-folder clashes, and Sent/Overlay outside carry refused; trailing space & renames preserved', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const seed = await seedStandingInput(env);
  const f1 = await env.dataStore.promoteBytes(Buffer.from('a,b\n1,2\n'), { relPath: 'All BOB/test.csv', checksPassed: true });
  const f2 = await env.dataStore.promoteBytes(Buffer.from('a,b\n3,4\n'), { relPath: 'All BOB/test2.csv', checksPassed: true });
  await env.commands.registerStoredFiles({ actor: env.ownerActor, commandKey: 'reg-f1-f2', files: [f1, f2] });

  // Verify trailing-space path `All BOB/Molina /book.csv` was stored verbatim without trimming!
  const molinaRes = await env.pool.query(
    "SELECT rel_path FROM coherence.input_entries WHERE input_version_id = $1::uuid AND rel_path = 'All BOB/Molina /book.csv'",
    [seed.inputVersionId],
  );
  assert.equal(molinaRes.rows.length, 1);

  // R11 (11/21 misdated files): renaming a file with identical bytes records change_kind='renamed' keeping history
  const renamedEntries = seed.entries.map((e) => (
    e.relPath === 'All Statements/aetna_202611.csv'
      ? { relPath: 'All Statements/aetna_202611_corrected_date.csv', fileSha256: e.fileSha256 }
      : e
  ));
  const renPub = await env.commands.publishInputVersion({
    actor: env.ownerActor,
    commandKey: 'rename-misdated',
    lineKind: 'standing',
    sourceKind: 'rename',
    reason: 'Fix misdated carrier statement filename (11/21)',
    entries: renamedEntries,
  });
  const renChange = await env.pool.query(
    'SELECT change_kind, rel_path, old_rel_path FROM coherence.input_changes WHERE input_version_id = $1::uuid',
    [renPub.result.inputVersionId],
  );
  assert.equal(renChange.rows.length, 1);
  assert.equal(renChange.rows[0].change_kind, 'renamed');
  assert.equal(renChange.rows[0].old_rel_path, 'All Statements/aetna_202611.csv');
  assert.equal(renChange.rows[0].rel_path, 'All Statements/aetna_202611_corrected_date.csv');

  // Direct SQL helper bypassing JS pre-check so we prove the DATABASE ITSELF enforces DS-1 and DS-2!
  const rawPublish = async (cmdKey, sourceKind, entries) => {
    const ivId = randomUUID();
    const entriesSha = hashInputEntries(entries);
    const changes = entries
      .filter((e) => !renamedEntries.some((p) => p.relPath === e.relPath && p.fileSha256 === e.fileSha256))
      .map((e) => ({ inputVersionId: ivId, changeKind: 'added', relPath: e.relPath, oldRelPath: null, fileSha256: e.fileSha256, prevFileSha256: null }));
    const changesSha = hashInputChanges(changes);
    const body = {
      commitments: {
        counts: { input_versions: 1, input_entries: entries.length, input_changes: changes.length },
        hashes: { input_entries: entriesSha, input_changes: changesSha },
      },
    };
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('kairon', 'raw_input', $1, $2, $3::jsonb) RETURNING seq`,
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

  // 1. Case twins refused by DB UNIQUE(input_version_id, mac_key)
  await assert.rejects(
    () => rawPublish('case-twin', 'upload', [...renamedEntries, { relPath: 'All BOB/Foo.csv', fileSha256: f1.sha256 }, { relPath: 'all bob/foo.CSV', fileSha256: f2.sha256 }]),
    /unique|mac_key/i,
  );
  // 2. NFC vs NFD twins refused by DB UNIQUE(input_version_id, mac_key)
  await assert.rejects(
    () => rawPublish('nfc-nfd-twin', 'upload', [...renamedEntries, { relPath: 'All BOB/caf\u00e9.csv', fileSha256: f1.sha256 }, { relPath: 'All BOB/cafe\u0301.csv', fileSha256: f2.sha256 }]),
    /unique|mac_key/i,
  );
  // 3. File-folder clash (ignoring case) refused by DB trigger
  await assert.rejects(
    () => rawPublish('file-folder', 'upload', [...renamedEntries, { relPath: 'All BOB/Aetna', fileSha256: f1.sha256 }, { relPath: 'all bob/aetna/sub.csv', fileSha256: f2.sha256 }]),
    /file\/folder path clash/i,
  );
  // 4. Changing Sent/ outside a carry refused by DB trigger (even lowercase `sent/`)
  await assert.rejects(
    () => rawPublish('bad-sent', 'upload', [...renamedEntries, { relPath: 'sent/statements_20261121.csv', fileSha256: f1.sha256 }]),
    /Sent\/ entries can change only through recording a statement as sent/i,
  );
  // 5. Changing Overlay/ outside a carry refused by DB trigger
  await assert.rejects(
    () => rawPublish('bad-overlay', 'upload', [...renamedEntries, { relPath: 'Overlay/overlay.csv', fileSha256: f1.sha256 }]),
    /Overlay\/ entries can change only through carrying approvals/i,
  );
});

test('Layer 1 [Negative Invariant — No second sent statement, S-8 out-of-order approvals carry, abandon guards & exact journal rebuild]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:aetna:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: 'phalanx',
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
    assert.equal((await worker.runOnce()).action, 'step_finished'); // adjust

    const adjRows = [...bibleRows, ...extraRows.adjust];
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.submitReview({ actor: env.ownerActor, commandKey: `a-${runId}`, expectedJournalSeq: seq, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
    const adjAcc = await worker.runOnce();
    assert.equal(adjAcc.action, 'review_accepted');

    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.confirmEmit({ actor: env.ownerActor, commandKey: `e-${runId}`, expectedJournalSeq: seq, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: `create statements for ${date}` });
    assert.equal((await worker.runOnce()).action, 'step_finished'); // emit
    return runId;
  };

  // 1. Trial run completes -> NEVER allowed to carry sent or approvals (R8)
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

  // 2. Two app runs launched from the SAME prior overlay (row0) with diverging branches
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

  // Launch another 11/20 app run while runA is finished with no carries -> refused until runA is abandoned!
  await assert.rejects(
    () => env.commands.launchRun({ actor: env.ownerActor, commandKey: 'dup-1120', statementDate: '2026-11-20', engineVersionId, rerunReason: 'retry' }),
    /non-abandoned run/i,
  );

  // Carry Run B's approvals -> standing overlay advances to branch-B
  const carryB = await env.commands.carryApprovals({ actor: env.ownerActor, commandKey: 'carry-ov-B', runId: runB, typedPhrase: 'carry 2026-11-21' });
  assert.equal(carryB.result.nothingNew, false);

  // Carrying Run B's approvals AGAIN -> nothing_new = true
  const carryB2 = await env.commands.carryApprovals({ actor: env.ownerActor, commandKey: 'carry-ov-B-again', runId: runB, typedPhrase: 'carry 2026-11-21' });
  assert.equal(carryB2.result.nothingNew, true);
  assert.equal(carryB2.result.publishedInputVersionId, null);

  // S-8 / R18: Carrying older Run A's approvals AFTER Run B's would drop branch-B -> REFUSED BY DATABASE!
  await assert.rejects(
    () => env.commands.carryApprovals({ actor: env.ownerActor, commandKey: 'carry-ov-A-ooo', runId: runA, typedPhrase: 'carry 2026-11-20' }),
    /does not extend the standing approvals/i,
  );

  // NEGATIVE INVARIANT: No second sent statement for a date (via command, via launch, and via raw SQL)!
  await env.commands.carrySent({ actor: env.ownerActor, commandKey: 'carry-sent-B', runId: runB, typedPhrase: 'sent 2026-11-21' });
  await assert.rejects(
    () => env.commands.carrySent({ actor: env.ownerActor, commandKey: 'carry-sent-B-dup', runId: runB, typedPhrase: 'sent 2026-11-21' }),
    /unique|already/i,
  );
  await assert.rejects(
    () => env.commands.launchRun({ actor: env.ownerActor, commandKey: 'launch-after-sent', statementDate: '2026-11-21', engineVersionId, rerunReason: 'correction' }),
    /sent statement already exists/i,
  );
  // Direct SQL check on carries_one_sent_per_date unique index
  const sentCarryRow = (await env.pool.query("SELECT file_sha256, published_input_version_id FROM coherence.carries WHERE run_id = $1::uuid AND carry_kind = 'sent'", [runB])).rows[0];
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('kairon', 'dup_sent_sql', 'dup-sent-sql', $1, '{"commitments":{"counts":{"carries":1},"hashes":{}}}'::jsonb) RETURNING seq`,
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

  // Abandoning Run B after carry refused!
  await assert.rejects(
    () => env.commands.abandonRun({ actor: env.ownerActor, commandKey: 'abandon-carried', runId: runB, typedPhrase: 'abandon 2026-11-21', reason: 'nope' }),
    /carried outputs/i,
  );

  // Abandon uncarried Run A -> succeeds, and re-launching 2026-11-20 gets folder_number = 2!
  await env.commands.abandonRun({ actor: env.ownerActor, commandKey: 'abandon-A', runId: runA, typedPhrase: 'abandon 2026-11-20', reason: 'superseded by 11-21' });
  const launchA2 = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'launch-A2', statementDate: '2026-11-20', engineVersionId, rerunReason: 'clean rerun after carry',
  });
  assert.equal(launchA2.result.folderNumber, 2);

  // R10.12 & R18: Export full journal and rebuild into a brand-new neon_test_* DB verifying EVERY hash & commitment!
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
