// Layer 4: protects historical import continuity, byte-for-byte folder rebuild,
// input-first run comparison, substance takeover checks, and identical replay of committed runs.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { assertLocalPgHost, assertSafeStoresDir, ensureProofIamSubjectsForBatches, runHistoryPlan, runHistoryProof } from '../scripts/prove-history.mjs';
import { createAppCommands } from '../src/commands/app-cmd.mjs';
import { compareDatabasesAsOf, exportJournalNdjson, rebuildFromJournalExport, verifyChain, verifyCommitments } from '../src/commands/journal-export.mjs';
import { verifyOverlayReconstruction } from '../src/compare/overlay-reconstruction.mjs';
import { compareCsvExactText, compareDbRuns, compareRunFolders, mapEntitiesCsv, queryRunEntityReconciliation } from '../src/compare/run-comparator.mjs';
import { createPool, withRequestTx } from '../src/db/pg-client.mjs';
import { formatOverlayCsvFromRows, generateOverlayCsv } from '../src/decisions/overlay-generator.mjs';
import {
  buildImportManifest,
  createCommitBundle,
  executeHistoryImport,
  importSingleRunFolder,
  loadImportManifestFile,
  parseApprovalsFile,
  readLegacySqliteSnapshot,
  readLegacyStatementBatches,
  resolveLiveProofConfig,
} from '../src/importer/history-importer.mjs';
import { findLatestPublishedRun } from '../src/readers/downstream-reader.mjs';
import { formatTimestampUtcUs } from '../src/util/crypto.mjs';
import { buildAttemptWorkspace } from '../src/worker/folder-builder.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import {
  createMockEngineMaterializer,
  createStdlibMockCoherenceRepo,
  createTestOverlayParser,
  makeCsvFromObjects,
  makeOverlayCsv,
  sampleApprovalRow,
  seedEngineVersion,
  seedStandingInput,
  SYNTHETIC_BOB_COLUMNS,
  SYNTHETIC_LEDGER_COLUMNS,
  SYNTHETIC_RUN_COLUMNS,
} from './helpers/fixtures.mjs';
import { createRoleScopedTestPool, seedCoherenceIamFixture } from './helpers/iam-harness.mjs';
import { checkPgAvailable, createEmptyMigratedTestDb, createTestEnv } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

function sha256Utf8(text) {
  return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

async function writeTree(baseDir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = join(baseDir, ...rel.split('/'));
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
}

async function snapshotImportWriteState(env) {
  const [runsRes, commitsRes, journalRes] = await Promise.all([
    env.pool.query('SELECT id FROM coherence.runs ORDER BY id'),
    env.pool.query('SELECT id FROM coherence.decision_commits ORDER BY id'),
    env.pool.query('SELECT seq::text AS seq, command_kind, command_key, entry_hash FROM coherence.journal_entries ORDER BY seq'),
  ]);
  return {
    runIds: runsRes.rows.map((r) => r.id),
    commitIds: commitsRes.rows.map((r) => r.id),
    journalRows: journalRes.rows,
    codeObjects: env.codeBackend.listObjectNames(),
    dataObjects: env.dataBackend.listObjectNames(),
  };
}

async function assertNothingWrittenSince(env, before, label, { expectEmptyCommits = true } = {}) {
  const after = await snapshotImportWriteState(env);
  assert.ok(before.journalRows.length >= 1, `${label}: expected pre-existing journal entry before import call`);
  assert.equal(after.runIds.length, 0, `${label}: coherence.runs must hold no rows, got ${after.runIds.length}`);
  if (expectEmptyCommits) {
    assert.equal(after.commitIds.length, 0, `${label}: coherence.decision_commits must hold no rows, got ${after.commitIds.length}`);
  } else {
    assert.deepEqual(after.commitIds, before.commitIds, `${label}: coherence.decision_commits must hold what it held before the call`);
  }
  assert.deepEqual(after.journalRows, before.journalRows, `${label}: coherence.journal_entries must hold what it held before the call`);
  assert.deepEqual(after.codeObjects, [], `${label}: env.codeBackend must hold no objects`);
  assert.deepEqual(after.dataObjects, [], `${label}: env.dataBackend must hold no objects`);
}

test('Layer 4 [Import, Rebuild, Replay & Working-Table Verification]: read-only import keeps working tables bytes, idempotent re-import adds nothing, byte-for-byte rebuild and replay pass, and on-demand working rebuild verifies SHA-256', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const parseOverlay = createTestOverlayParser();

  const fakeCoherence = join(env.tempDir, 'fake-coherence');
  const fakeNusearData = join(env.tempDir, 'fake-nusear-data');

  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:PRIOR#effective:2026-01-01' });
  const rowBible = sampleApprovalRow({ record_id: 'policy:carrier_a:P10001#effective:2026-01-01', note: 'bible' });
  const rowAdj = sampleApprovalRow({ record_id: 'carrier_a~direct~P10001~100.00~2026-11', note: 'adjust' });
  const priorCsv = makeOverlayCsv([row0]);
  const bibleCsv = makeOverlayCsv([row0, rowBible]);
  const adjCsv = makeOverlayCsv([row0, rowBible, rowAdj]);

  const born1121 = '2026-11-21T15:00:00.123456789';
  const run1121Dir = join(fakeCoherence, 'runs', '2026-11-21');
  const sharedInput = {
    'Agent Data/cleanagentdata.csv': 'agent_name,agent_npn,entity,start_date\nJane Agent,12345678,Acme,01/01/2025\n',
    'All Statements/carrier_a_202611.csv': 'member,policy_number,amount\nTest Member,P10001,100.00\n',
    'All BOB/TrailingCarrier /book.csv': 'member,policy_number,status\nTest Member,P10001,ACTIVE\n',
    'EnrollSys/enrollments.csv': 'member,policy_number,npn\nTest Member,P10001,12345678\n',
    'Overlay/overlay.csv': priorCsv,
    '.DS_Store': 'finder-ds-store',
  };

  await writeTree(join(fakeCoherence, 'input'), sharedInput);
  await writeTree(join(run1121Dir, 'input'), sharedInput);

  const trailingHash = createHash('sha256').update(sharedInput['All BOB/TrailingCarrier /book.csv']).digest('hex').slice(0, 12);
  const unidHash = createHash('sha256').update(`${born1121}:0`).digest('hex');

  const workingFiles = {};
  for (const name of ['cbob', 'sf', 'tx_tx', 'tx_cbob', 'tx_sf', 'cbob_sf', 'pbob']) {
    workingFiles[`working/${name}.csv`] = `id,tag\n1,${trailingHash}\n`;
  }
  workingFiles['working/tx.csv'] = `id,tag\n1,${trailingHash}\n2,attributed\n`;

  const bibleItems = [
    { record_id: 'policy:carrier_a:P10001#effective:2026-01-01', case: 'BIBLE', subtype: 'CONFLICT', amount: '100.00' },
    { record_id: `policy:carrier_a:unidentified:${unidHash}`, case: 'BIBLE', subtype: 'HOUSE', amount: '50.00' },
  ];
  const bibleCfg = { statementDate: '2026-11-21', build: '809c6ea', stamped: true, surface: 'bible', runBorn: born1121, queue: bibleItems, overlay: [], checksum: unidHash.slice(0, 16) };
  const adjItems = [{ record_id: 'carrier_a~direct~P10001~100.00~2026-11', case: 'NEW', subtype: 'NEW_BUSINESS', amount: '100.00' }];
  const adjCfg = { statementDate: '2026-11-21', build: '809c6ea', stamped: true, surface: 'adjust', runBorn: born1121, queue: adjItems, overlay: [], checksum: 'adj123' };

  await writeTree(run1121Dir, {
    ...workingFiles,
    'bible.csv': `record_id,case,subtype,amount\r\npolicy:carrier_a:P10001#effective:2026-01-01,BIBLE,CONFLICT,100.00\r\npolicy:carrier_a:unidentified:${unidHash},BIBLE,HOUSE,50.00\r\n`,
    'bible.html': `<!doctype html><html><head><title>Coherence Bible</title><script>window.__ADJUST_CONFIG__=${JSON.stringify(bibleCfg)};</script></head><body>bible</body></html>`,
    'adjust.csv': 'record_id,case,subtype,amount\r\ncarrier_a~direct~P10001~100.00~2026-11,NEW,NEW_BUSINESS,100.00\r\n',
    'adjust.html': `<!doctype html><html><head><title>Coherence Adjust</title><script>window.__ADJUST_CONFIG__=${JSON.stringify(adjCfg)};</script></head><body>adjust</body></html>`,
    'overlay.csv': adjCsv,
    'emits/statements_20261121.csv': 'record_id,entity,writing_npn,gross_comm,downline_amount,run_action\ncarrier_a~direct~P10001~100.00~2026-11,Acme,12345678,100.00,80.00,NEW\n',
    'emits/adjustments.csv': adjCsv,
    'emits/overlay.csv': adjCsv,
    'emits/bundles/entity-managers/Acme/data/canonical_bob.csv': 'member,entity,carrier,policy_id,gross_comm\nTest Member,Acme,carrier_a,1,100.00\n',
    'emits/bundles/entity-managers/Acme/data/coherent_ledger.csv': 'member,entity,carrier,gross_comm\nTest Member,Acme,carrier_a,100.00\n',
    'emits/bundles/entity-managers/Acme/viewer.html': `<!doctype html><html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify({ name: 'Entity Manager', title: 'Acme', statementDate: '2026-11-21', build: '809c6ea', stamped: true, role: 'ENTITY_MANAGER', features: { CANONICAL_BOB: { canonical_bob: 'data/canonical_bob.csv' }, COHERENT_LEDGER: { coherent_ledger: 'data/coherent_ledger.csv' } }, defaultVisible: { CANONICAL_BOB: { canonical_bob: ['member', 'entity'] } }, defaultFilters: {} })};</script></head><body>viewer</body></html>`,
    'emits/bundles/selling-agents/Acme/jane-agent/data/Acme_jane-agent_12345678_bob.csv': 'member,entity,carrier,status,writing_npn,writing_agent,amount,gross_comm\nTest Member,Acme,carrier_a,ACTIVE_PAYING,12345678,Jane Agent,100.00,100.00\n',
    'emits/bundles/selling-agents/Acme/jane-agent/viewer.html': `<!doctype html><html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify({ name: 'Jane Agent', title: '12345678', statementDate: '2026-11-21', build: '809c6ea', stamped: true, role: 'SELLING_AGENT', features: { BOB: { bob: 'data/Acme_jane-agent_12345678_bob.csv' } }, defaultVisible: { BOB: { bob: ['member', 'entity', 'amount'] } }, defaultFilters: { BOB: { bob: { amount: { positiveOnly: true }, carrier: { include: ['carrier_a'] } } } } })};</script></head><body>viewer</body></html>`,
    'run.json': `${JSON.stringify({
      date: '2026-11-21',
      born: born1121,
      steps: {
        assign: { at: '2026-11-21T15:00:01', code: '809c6ea', seconds: 19.5 },
        attribute: { at: '2026-11-21T15:00:41', code: '809c6ea', seconds: 39.2 },
        bible: { at: '2026-11-21T15:01:20', code: '809c6ea', seconds: 37.9, bible_items: 2 },
        adjust: { at: '2026-11-21T15:35:58', code: '809c6ea', seconds: 41.1, queue_items: 1 },
        emit: { at: '2026-11-21T15:38:15', code: '809c6ea', seconds: 134.8, statements: 1 },
      },
    }, null, 2)}\n`,
  });

  // Legacy run with missing birth timestamp and root overlay.csv only.
  await writeTree(join(fakeCoherence, 'runs', '2026-09-30'), {
    'input/Agent Data/cleanagentdata.csv': sharedInput['Agent Data/cleanagentdata.csv'],
    'overlay.csv': priorCsv,
    'working/tx.csv': 'id\n1\n',
    'bible.csv': 'record_id\n',
    'run.json': JSON.stringify({ date: '2026-09-30', steps: { assign: { at: '2026-09-30T10:00:00', code: 'abc1234+' }, attribute: { at: '2026-09-30T10:01:00', code: 'abc1234+' }, bible: { at: '2026-09-30T10:02:00', code: 'abc1234+' } } }),
  });

  await writeTree(join(fakeCoherence, 'runs', 'Incident Report', '2026-11-03 Slate'), {
    'override_only.csv': 'policy\nP1\n',
    'build_slate.py': 'print("incident script")\n',
  });

  await writeTree(join(fakeNusearData, 'coherence-runs', '2026-11-21'), {
    'bible-review-2026-11-21T15-35-17-068Z.csv': bibleCsv,
    'adjust-review-2026-11-21T15-36-12-986Z.csv': adjCsv,
  });

  const manifest = await buildImportManifest({
    companySlug: env.companySlug,
    coherenceRoot: fakeCoherence,
    nusearDataDir: fakeNusearData,
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha256Utf8(priorCsv) }],
    },
  });
  assert.equal(manifest.macRuns.length, 2);
  assert.equal(manifest.nusearMacSaves['2026-11-21'].length, 2);
  assert.equal(manifest.incidentReportFiles.length, 2);

  const report1 = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, dbToken: env.ownerToken,
    manifest, parseOverlay, verifyRebuild: true, tempBaseDir: env.tempDir,
  });
  assert.equal(report1.passed, true, `Import failed: ${report1.problems.join('; ')}`);
  assert.equal(report1.importedRuns.length, 2);
  assert.ok(report1.rebuildChecks.every((c) => c.passed));

  // Imported runs retain working-table bytes in company_data so historical folders rebuild byte for byte.
  const orig1121Id = report1.importedRuns.find((r) => r.statementDate === '2026-11-21').runId;
  const workingArts = await env.pool.query(
    `SELECT e.step, a.rel_path, a.file_sha256
     FROM coherence.artifacts a
     JOIN coherence.step_attempt_events e ON e.id = a.attempt_event_id
     WHERE e.run_id = $1::uuid AND a.rel_path LIKE 'working/%'`,
    [orig1121Id],
  );
  assert.equal(workingArts.rows.length, 8);
  for (const w of workingArts.rows) {
    assert.ok((await env.dataStore.readVerified(w.file_sha256)).length > 0);
  }

  const sep30 = await env.pool.query(
    `SELECT e.born FROM coherence.step_attempt_events e
     JOIN coherence.runs r ON r.id = e.run_id
     WHERE r.source_folder = '2026-09-30' AND e.step = 'assign' AND e.event_kind = 'finished'`,
  );
  assert.equal(sep30.rows[0].born, null);

  const badStoreCheck = await env.pool.query(
    "SELECT COUNT(*)::int AS n FROM coherence.imported_files WHERE rel_path LIKE '%.py' AND store_kind <> 'nusear_code'",
  );
  assert.equal(badStoreCheck.rows[0].n, 0);

  const report2 = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, dbToken: env.ownerToken,
    manifest, parseOverlay, verifyRebuild: false, tempBaseDir: env.tempDir,
  });
  assert.equal(report2.importedRuns.length, 0);
  assert.equal(report2.skippedRuns.length, 2);
  assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.runs')).rows[0].n, 2);

  const replayLaunch = await env.commands.launchRun({
    dbToken: env.ownerToken, commandKey: 'replay-1121', statementDate: '2026-11-21',
    origin: 'replay', replaysRunId: orig1121Id, engineVersionId, emitMode: 'coherence',
  });
  const replayRunId = replayLaunch.result.runId;

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer({ fixedCodeHash: '809c6ea' }), tempBaseDir: env.tempDir,
  }));

  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [replayRunId])).rows[0].latest_journal_seq);
  await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: 'rep-b', expectedJournalSeq: seq, runId: replayRunId, surface: 'bible', csvBytes: Buffer.from(bibleCsv, 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished');

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [replayRunId])).rows[0].latest_journal_seq);
  await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: 'rep-a', expectedJournalSeq: seq, runId: replayRunId, surface: 'adjust', csvBytes: Buffer.from(adjCsv, 'utf8') });
  const repAdj = await worker.runOnce();
  assert.equal(repAdj.action, 'review_accepted');

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [replayRunId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ dbToken: env.ownerToken, commandKey: 'rep-e', expectedJournalSeq: seq, runId: replayRunId, adjustReviewSaveId: repAdj.reviewSaveId, typedPhrase: 'create statements for 2026-11-21' });
  assert.equal((await worker.runOnce()).action, 'step_finished');

  const replayProof = await compareDbRuns({
    pool: env.pool, stores: env.stores, leftRunId: replayRunId, rightRunId: orig1121Id,
    mode: 'replay', commands: env.commands, dbToken: env.ownerToken, tempBaseDir: env.tempDir,
  });
  assert.equal(replayProof.inputs.passed, true);
  assert.equal(replayProof.passed, true, `Replay mismatch: ${JSON.stringify(replayProof.tree.unexpectedDiffs)}`);

  // New runs whose derivable working/ bytes are omitted rebuild working/ on demand and verify every rebuilt file against its recorded SHA-256.
  const replayRunRow = (await env.pool.query(
    `SELECT id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date, origin, input_version_id,
            prior_approvals_sha256, engine_version_id, replays_run_id
     FROM coherence.runs WHERE id = $1::uuid`,
    [replayRunId],
  )).rows[0];
  const replayArts = (await env.pool.query(
    `SELECT e.step, a.rel_path, a.file_sha256 FROM coherence.artifacts a
     JOIN coherence.step_attempt_events e ON e.id = a.attempt_event_id
     WHERE e.run_id = $1::uuid`,
    [replayRunId],
  )).rows;
  const txAttrSha = replayArts.find((a) => a.step === 'attribute' && a.rel_path === 'working/tx.csv').file_sha256;
  const bibleCsvSha = replayArts.find((a) => a.rel_path === 'bible.csv').file_sha256;

  const makeMissingStore = (omitSet) => {
    const wrappedData = {
      ...env.stores.dataStore,
      readVerified: async (sha, meta, opts) => {
        if (omitSet.has(sha)) {
          const err = new Error('Working table stored as fingerprint only');
          err.code = 'NOT_FOUND';
          throw err;
        }
        return env.stores.dataStore.readVerified(sha, meta, opts);
      },
    };
    return {
      ...env.stores,
      dataStore: wrappedData,
      readVerified: (storeKind, sha, meta, opts) => (
        storeKind === 'company_data' ? wrappedData.readVerified(sha, meta, opts) : env.stores.codeStore.readVerified(sha, meta, opts)
      ),
    };
  };

  let rebuiltOnDemandCalled = false;
  const ws = await buildAttemptWorkspace({
    db: env.pool,
    run: replayRunRow,
    step: 'bible',
    stores: makeMissingStore(new Set(workingArts.rows.map((w) => w.file_sha256))),
    tempBaseDir: env.tempDir,
    materializeEngine: createMockEngineMaterializer({ fixedCodeHash: '809c6ea' }),
    rebuildWorkingOnDemand: async ({ runDir }) => {
      rebuiltOnDemandCalled = true;
      await writeTree(runDir, workingFiles);
    },
  });
  try {
    assert.equal(rebuiltOnDemandCalled, true, 'rebuildWorkingOnDemand hook must fire when working bytes are omitted');
  } finally {
    await ws.cleanup();
  }

  await assert.rejects(
    () => buildAttemptWorkspace({
      db: env.pool,
      run: replayRunRow,
      step: 'adjust',
      stores: makeMissingStore(new Set([txAttrSha])),
      tempBaseDir: env.tempDir,
      materializeEngine: createMockEngineMaterializer({ fixedCodeHash: '809c6ea' }),
      rebuildWorkingOnDemand: async ({ runDir }) => {
        await writeTree(runDir, { 'working/tx.csv': 'id,tag\n999,tampered\n' });
      },
    }),
    (err) => err?.code === 'WORKING_REBUILD_FINGERPRINT_MISMATCH',
  );

  let calledForBible = false;
  await assert.rejects(
    () => buildAttemptWorkspace({
      db: env.pool,
      run: replayRunRow,
      step: 'adjust',
      stores: makeMissingStore(new Set([bibleCsvSha])),
      tempBaseDir: env.tempDir,
      materializeEngine: createMockEngineMaterializer({ fixedCodeHash: '809c6ea' }),
      rebuildWorkingOnDemand: async () => { calledForBible = true; },
    }),
    (err) => err?.code === 'NOT_FOUND',
  );
  assert.equal(calledForBible, false);
});

test('Layer 4 [Worker Default Working Rebuild]: worker rebuilds omitted working tables on demand and verifies SHA-256 before continuing', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));
  const launch = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'wk-reb-launch', statementDate: '2026-11-21', engineVersionId });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');

  const workingShas = new Set((await env.pool.query(
    `SELECT a.file_sha256 FROM coherence.artifacts a
     JOIN coherence.step_attempt_events e ON e.id = a.attempt_event_id
     WHERE e.run_id = $1::uuid AND a.rel_path LIKE 'working/%'`,
    [runId],
  )).rows.map((r) => r.file_sha256));

  const omitStores = {
    ...env.stores,
    dataStore: {
      ...env.stores.dataStore,
      readVerified: async (sha, meta, opts) => {
        if (workingShas.has(sha)) throw Object.assign(new Error('omitted working file'), { code: 'NOT_FOUND' });
        return env.stores.dataStore.readVerified(sha, meta, opts);
      },
    },
    readVerified: (kind, sha, meta, opts) => (
      kind === 'company_data' && workingShas.has(sha)
        ? Promise.reject(Object.assign(new Error('omitted working file'), { code: 'NOT_FOUND' }))
        : env.stores.readVerified(kind, sha, meta, opts)
    ),
  };

  const seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.submitReview({
    dbToken: env.ownerToken, commandKey: 'wk-reb-bible', expectedJournalSeq: seq, runId, surface: 'bible',
    csvBytes: Buffer.from(makeOverlayCsv([row0, sampleApprovalRow({ note: 'ok' })]), 'utf8'),
  });
  const rebuildWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: omitStores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));
  assert.equal((await rebuildWorker.runOnce()).action, 'review_accepted');
  assert.equal((await rebuildWorker.runOnce()).action, 'step_finished');
});

test('Layer 4 [Importer Safety & Config]: Python-only overlay parsing, failed git commit archiving, corrupt SQLite refusal, and config-driven company profiles', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'coherence-imp-safe-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:P1#effective:2026-01-01' });
  const ovPath = join(dir, 'overlay.csv');
  await writeFile(ovPath, makeOverlayCsv([row0]), 'utf8');
  await assert.rejects(
    () => parseApprovalsFile(ovPath),
    (err) => err?.code === 'OVERLAY_PARSER_CONFIG_REQUIRED',
  );

  const badDb = join(dir, 'corrupt.sqlite');
  await writeFile(badDb, 'not a valid sqlite database', 'utf8');
  await assert.rejects(
    () => buildImportManifest({ companySlug: 'acme', nusearSqlitePath: badDb }),
    /SQLITE|sqlite|corrupt|database/i,
  );

  const invokeLog = join(dir, 'invocations.log');
  const fakeCheckerOk = join(dir, 'fake_checker_ok.py');
  await writeFile(fakeCheckerOk, [
    'import argparse, csv, json',
    'from pathlib import Path',
    'p = argparse.ArgumentParser()',
    'p.add_argument("--parse-only", action="store_true")',
    'p.add_argument("--extends", default=None)',
    'p.add_argument("--out", default=None)',
    'p.add_argument("args", nargs="+")',
    'a = p.parse_args()',
    `with open(${JSON.stringify(invokeLog)}, "a", encoding="utf-8") as fh: fh.write(f"parse_only={a.parse_only}\\n")`,
    'V2 = ("record_id","disposition","agent","agency","policy","book","month","status","note","committed_at","approved_amount","approved_agency","approved_agent","approved_agency_from","approved_agent_from")',
    'def rd(fp):',
    '    rows = list(csv.reader(open(fp, newline="", encoding="utf-8-sig")))',
    '    return [{c: (None if i >= len(r) or r[i] == "" else r[i]) for i, c in enumerate(V2)} for r in rows[1:] if any(r)]',
    'rows = rd(a.args[0])',
    'parent = rd(a.extends) if a.extends else []',
    'shared = len(parent)',
    'new_rows = [{"row_no": shared + i + 1, **r} for i, r in enumerate(rows[shared:])]',
    'payload = {"header_kind": "v2", "rows": len(rows), "shared": shared, "new_rows": new_rows}',
    'if a.out: Path(a.out).write_text(json.dumps(payload), encoding="utf-8")',
    'print(json.dumps({"rows": len(rows)}))',
  ].join('\n'), 'utf8');
  const fakeCheckerFail = join(dir, 'fake_checker_fail.py');
  await writeFile(fakeCheckerFail, 'import sys\nprint("bad overlay", file=sys.stderr)\nsys.exit(2)\n', 'utf8');

  const fakeGitFail = join(dir, 'fake-git-fail');
  await writeFile(fakeGitFail, '#!/bin/sh\necho "fatal: bad object" >&2\nexit 128\n', 'utf8');
  await chmod(fakeGitFail, 0o700);

  const legacyRoot = join(dir, 'legacy-host');
  const dataDir = join(dir, 'nusear-data');
  const safeOvCsv = makeOverlayCsv([row0]);
  await writeTree(join(legacyRoot, 'runs', '2026-11-21'), {
    'input/a.csv': 'x\n1\n',
    'overlay.csv': safeOvCsv,
    'run.json': JSON.stringify({ date: '2026-11-21', born: '2026-11-21T10:00:00.000000001', steps: { assign: { at: '2026-11-21T10:00:01', code: 'deadbeef', seconds: 1 } } }),
  });
  await writeTree(join(legacyRoot, 'input'), { 'a.csv': 'x\n1\n' });
  await writeTree(join(dataDir, 'company-workspaces', 'beacon', '2026-11-15', 'runs', '2026-11-15'), {
    'input/a.csv': 'x\n1\n',
    'run.json': JSON.stringify({ date: '2026-11-15', born: 'b2', steps: { assign: { at: '2026-11-15T10:00:00', code: '809c6ea', seconds: 1 } } }),
  });
  await writeTree(join(dataDir, 'company-environments', 'beacon', 'incoming'), { 'b.csv': 'y\n2\n' });

  const env1 = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env1.cleanup());
  const acmeManifest = await buildImportManifest({
    companySlug: 'acme',
    coherenceRoot: legacyRoot,
    nusearDataDir: dataDir,
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-11-21', sha256: sha256Utf8(safeOvCsv) }],
    },
  });
  assert.equal(acmeManifest.macRuns.length, 1);
  assert.equal(acmeManifest.currentInputDir, join(legacyRoot, 'input'));

  const repMissingCommit = await executeHistoryImport({
    pool: env1.pool, stores: env1.stores, commands: env1.commands, dbToken: env1.ownerToken,
    manifest: acmeManifest, pythonPath: 'python3', coherenceRepo: dir, overlayCheckPath: fakeCheckerOk,
    gitBin: fakeGitFail, verifyRebuild: false, tempBaseDir: env1.tempDir,
  });
  assert.equal(repMissingCommit.passed, false);
  assert.ok(repMissingCommit.problems.some((p) => p.includes('deadbeef')));
  assert.ok((await readFile(invokeLog, 'utf8')).includes('parse_only=True'));

  const env2 = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env2.cleanup());
  await assert.rejects(
    () => executeHistoryImport({
      pool: env2.pool, stores: env2.stores, commands: env2.commands, dbToken: env2.ownerToken,
      manifest: acmeManifest, pythonPath: 'python3', coherenceRepo: dir, overlayCheckPath: fakeCheckerFail,
      allowedMissingCommits: ['deadbeef'], verifyRebuild: false, tempBaseDir: env2.tempDir,
    }),
    (err) => err?.code === 'OVERLAY_PARSE_FAILED',
  );

  const beaconManifest = await buildImportManifest({
    companySlug: 'beacon',
    coherenceRoot: legacyRoot,
    nusearDataDir: dataDir,
    importConfig: {
      includeLegacyHostHistory: false,
      useCompanyIncomingInput: true,
      emitRules: [{ fromDate: '2026-11-12', emitMode: 'generated', emitDisplay: 'Beacon', emitKeep: ['INVESTOR'], emitNoManager: ['PartnerAgency'] }],
    },
  });
  assert.equal(beaconManifest.macRuns.length, 0);
  assert.equal(beaconManifest.companyRuns.length, 1);
  assert.equal(beaconManifest.currentInputDir, join(dataDir, 'company-environments', 'beacon', 'incoming'));

  const env3 = await createTestEnv({ companySlug: 'beacon', displayName: 'Beacon' });
  t.after(() => env3.cleanup());
  const beaconRep = await executeHistoryImport({
    pool: env3.pool, stores: env3.stores, commands: env3.commands, dbToken: env3.ownerToken,
    manifest: beaconManifest, verifyRebuild: false, tempBaseDir: env3.tempDir,
  });
  assert.equal(beaconRep.passed, true);
  const bRun = (await env3.pool.query('SELECT emit_mode, emit_display, emit_no_manager FROM coherence.runs LIMIT 1')).rows[0];
  assert.equal(bRun.emit_mode, 'generated');
  assert.equal(bRun.emit_display, 'Beacon');
  assert.deepEqual(bRun.emit_no_manager, ['PartnerAgency']);
});

test('Layer 4 [Run Comparator]: inputs checked first, trial allowed diffs, money diffs rejected, generic entity_mapped with bundle verification, and substance takeover mode', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'coherence-cmp-unit-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const left = join(dir, 'left');
  const right = join(dir, 'right');

  await writeTree(left, { 'input/Agent Data/cleanagentdata.csv': 'agent_name,entity\nA,Acme\n', 'run.json': '{"date":"2026-11-20","steps":{}}' });
  await writeTree(right, { 'input/Agent Data/cleanagentdata.csv': 'agent_name,entity\nA,SubAgency\n', 'run.json': '{"date":"2026-11-20","steps":{}}' });
  const inputMismatch = await compareRunFolders(left, right, { mode: 'trial' });
  assert.equal(inputMismatch.inputs.passed, false);
  assert.equal(inputMismatch.passed, false);
  assert.equal(inputMismatch.inputs.changed[0].relPath, 'input/Agent Data/cleanagentdata.csv');

  const t1 = join(dir, 'trial-1');
  const t2 = join(dir, 'trial-2');
  const rowA = sampleApprovalRow({ record_id: `policy:carrier_a:unidentified:${'a'.repeat(64)}`, committed_at: '2026-11-21T10:00:00Z' });
  const rowB = sampleApprovalRow({ record_id: `policy:carrier_a:unidentified:${'b'.repeat(64)}`, committed_at: '2026-11-21T11:00:00Z' });
  await writeTree(t1, {
    'input/a.csv': 'x\n1\n',
    'overlay.csv': makeOverlayCsv([rowA]),
    'emits/statements_20261121.csv': 'record_id,gross_comm\nr1,100.00\n',
    'run.json': JSON.stringify({ date: '2026-11-21', born: '2026-11-21T10:00:00.000000001', steps: { assign: { at: '10:00', code: '809c6ea', seconds: 20 } } }),
  });
  await writeTree(t2, {
    'input/a.csv': 'x\n1\n',
    'overlay.csv': makeOverlayCsv([rowB]),
    'emits/statements_20261121.csv': 'record_id,gross_comm\nr1,100.00\n',
    'run.json': JSON.stringify({ date: '2026-11-21', born: '2026-11-21T11:00:00.000000002', steps: { assign: { at: '11:00', code: '809c6ea', seconds: 22 } } }),
  });
  const trialOk = await compareRunFolders(t1, t2, { mode: 'trial' });
  assert.equal(trialOk.passed, true);
  assert.equal(trialOk.tree.allowedDiffs.length, 2);

  await writeFile(join(t2, 'emits', 'statements_20261121.csv'), 'record_id,gross_comm\nr1,99.00\n', 'utf8');
  const moneyDiff = await compareRunFolders(t1, t2, { mode: 'trial' });
  assert.equal(moneyDiff.passed, false);
  assert.ok(moneyDiff.tree.unexpectedDiffs.some((d) => d.relPath === 'emits/statements_20261121.csv'));

  const mappedCsv = mapEntitiesCsv('entity,amount\nSubAgency,10\nPartnerAgency,20\n', { targetEntity: 'Acme', preserveEntities: ['PartnerAgency'] });
  assert.ok(mappedCsv.includes('Acme,10'));
  assert.ok(mappedCsv.includes('PartnerAgency,20'));

  const refDir = join(dir, 'ref');
  const mappedDir = join(dir, 'mapped');
  const viewerCfg = {
    name: 'Entity Manager', title: 'Acme', statementDate: '2026-11-21', build: '809c6ea', stamped: true,
    role: 'ENTITY_MANAGER',
    features: {
      CANONICAL_BOB: { canonical_bob: 'data/canonical_bob.csv' },
      COHERENT_LEDGER: { coherent_ledger: 'data/coherent_ledger.csv' },
    },
  };
  await writeTree(refDir, {
    'input/Agent Data/cleanagentdata.csv': 'agent_name,entity\nA,SubAgency\nB,PartnerAgency\n',
    'emits/statements_20261121.csv': 'record_id,entity,gross_comm\nr1,SubAgency,100.00\nr2,PartnerAgency,50.00\n',
    'run.json': JSON.stringify({ date: '2026-11-21', born: 'b1', steps: { emit: { at: '10:00', code: '809c6ea', seconds: 100 } } }),
  });
  await writeTree(mappedDir, {
    'input/Agent Data/cleanagentdata.csv': 'agent_name,entity\nA,Acme\nB,PartnerAgency\n',
    'emits/statements_20261121.csv': 'record_id,entity,gross_comm\nr1,Acme,100.00\nr2,PartnerAgency,50.00\n',
    'company_manifest.json': JSON.stringify([{ output: 'entity-managers/Acme', role: 'ENTITY_MANAGER', scope: 'all' }]),
    'emits/bundles/entity-managers/Acme/viewer.html': `<!doctype html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify(viewerCfg)};</script></head>`,
    'emits/bundles/entity-managers/Acme/data/canonical_bob.csv': 'entity\nAcme\n',
    'run.json': JSON.stringify({ date: '2026-11-21', born: 'b2', steps: { emit: { at: '11:00', code: '809c6ea', seconds: 105 } } }),
  });
  const missingBundleCsv = await compareRunFolders(mappedDir, refDir, {
    mode: 'entity_mapped',
    entityMapping: { targetEntity: 'Acme', preserveEntities: ['PartnerAgency'] },
  });
  assert.equal(missingBundleCsv.passed, false);
  assert.equal(missingBundleCsv.tree.manifestBundleCheck.passed, false);

  await writeFile(join(mappedDir, 'emits/bundles/entity-managers/Acme/data/coherent_ledger.csv'), 'entity,gross_comm\nAcme,100.00\n', 'utf8');
  const entityMappedOk = await compareRunFolders(mappedDir, refDir, {
    mode: 'entity_mapped',
    entityMapping: { targetEntity: 'Acme', preserveEntities: ['PartnerAgency'] },
  });
  assert.equal(entityMappedOk.passed, true);
  assert.equal(entityMappedOk.tree.manifestBundleCheck.passed, true);

  const subL = join(dir, 'sub-left');
  const subR = join(dir, 'sub-right');
  await writeTree(subL, {
    'input/a.csv': 'k\n1\n',
    'bible.html': '<!doctype html><body>presentation v1</body>',
    'emits/bundles/entity-managers/Acme/data/canonical_bob.csv': 'member,entity,policy_id\nM1,Acme,P1\n',
    'emits/bundles/entity-managers/Acme/data/coherent_ledger.csv': 'member,entity,gross_comm\nM1,Acme,100.00\n',
    'emits/entity_statements/Acme.csv': 'entity,total\nAcme,100.00\n',
    'emits/bundles/selling-agents/Acme/jane/data/bob.csv': 'member\nLEFT_ONLY\n',
  });
  await writeTree(subR, {
    'input/a.csv': 'k\n1\n',
    'bible.html': '<!doctype html><body>presentation v2</body>',
    'emits/bundles/entity-managers/Acme/data/canonical_bob.csv': 'member,entity,policy_id\nM1,Acme,P1\n',
    'emits/bundles/entity-managers/Acme/data/coherent_ledger.csv': 'member,entity,gross_comm\nM1,Acme,100.00\n',
    'emits/entity_statements/Acme.csv': 'entity,total\nAcme,100.00\n',
    'emits/bundles/selling-agents/Acme/jane/data/bob.csv': 'member\nRIGHT_ONLY\n',
  });
  const subOk = await compareRunFolders(subL, subR, { mode: 'substance' });
  assert.equal(subOk.passed, true);
  assert.equal(subOk.substance.passed, true);

  await writeFile(join(subR, 'emits/entity_statements/Acme.csv'), 'entity,total\nAcme,99.00\n', 'utf8');
  const subDiff = await compareRunFolders(subL, subR, { mode: 'substance' });
  assert.equal(subDiff.passed, false);
});

test('Layer 4 [Live Proof Config]: opt-in live proof requires explicit COHERENCE_REPO, NUSEAR_DATA_DIR, and COHERENCE_PROOF_COMPANY', () => {
  assert.equal(resolveLiveProofConfig({}), null);
  assert.throws(
    () => resolveLiveProofConfig({ COHERENCE_LIVE_PROOF: '1' }),
    /COHERENCE_REPO.*NUSEAR_DATA_DIR.*COHERENCE_PROOF_COMPANY/,
  );
  const cfg = resolveLiveProofConfig({
    COHERENCE_LIVE_PROOF: '1',
    COHERENCE_REPO: '/tmp/example-repo',
    NUSEAR_DATA_DIR: '/tmp/example-data',
    COHERENCE_PROOF_COMPANY: 'acme',
  });
  assert.equal(cfg.companySlug, 'acme');
});

// Opt-in live import proof: requires COHERENCE_LIVE_PROOF=1, COHERENCE_REPO, NUSEAR_DATA_DIR, and COHERENCE_PROOF_COMPANY so default runs never read live data.
test('Layer 4 [opt-in COHERENCE_LIVE_PROOF=1]: import configured historical run read-only and rebuild byte-for-byte', {
  skip: (!pgCheck.available && pgCheck.reason) || (process.env.COHERENCE_LIVE_PROOF !== '1' && 'Set COHERENCE_LIVE_PROOF=1 with COHERENCE_REPO, NUSEAR_DATA_DIR, and COHERENCE_PROOF_COMPANY to run opt-in live proof'),
}, async (t) => {
  const cfg = resolveLiveProofConfig(process.env);
  const env = await createTestEnv({ companySlug: cfg.companySlug, displayName: cfg.companySlug });
  t.after(() => env.cleanup());

  const fullManifest = await buildImportManifest({
    companySlug: cfg.companySlug,
    coherenceRoot: cfg.coherenceRepo,
    nusearDataDir: cfg.nusearDataDir,
    importConfig: { includeLegacyHostHistory: cfg.includeLegacyHostHistory },
  });
  const selectedDate = cfg.statementDate || fullManifest.macRuns.at(-1)?.sourceFolder;
  const scopedManifest = {
    ...fullManifest,
    macRuns: fullManifest.macRuns.filter((r) => r.sourceFolder === selectedDate),
    companyRuns: [],
    currentInputDir: null,
    currentInputFiles: [],
    incidentReportFiles: [],
    standaloneFiles: [],
  };
  assert.equal(scopedManifest.macRuns.length, 1);

  const report = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest: scopedManifest,
    pythonPath: cfg.pythonPath,
    coherenceRepo: cfg.coherenceRepo,
    verifyRebuild: true,
    tempBaseDir: env.tempDir,
  });
  assert.equal(report.passed, true, `Live import/rebuild failed: ${report.problems.join('; ')}`);
  assert.equal(report.rebuildChecks[0].passed, true);
});

const execFileAsync = promisify(execFile);

test('Layer 4 [Engine Commit Bundle]: a commit named by its short id is bundled with its history, and the source repository is left unchanged', async () => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-bundle-test-'));
  try {
    const repo = join(work, 'engine');
    await mkdir(repo, { recursive: true });
    const git = (args) => execFileAsync('git', ['-c', 'user.name=Test', '-c', 'user.email=test@example.com', ...args], { cwd: repo });
    await git(['init', '--quiet']);
    await git(['commit', '--allow-empty', '--quiet', '-m', 'first']);
    await writeFile(join(repo, 'a.txt'), 'a');
    await git(['add', 'a.txt']);
    await git(['commit', '--quiet', '-m', 'second']);
    const head = (await git(['rev-parse', 'HEAD'])).stdout.trim();
    const refsBefore = (await git(['for-each-ref'])).stdout;
    const bundlePath = join(work, 'engine.bundle');
    const full = await createCommitBundle({ repo, commit: head.slice(0, 7), workDir: work, bundlePath });
    assert.equal(full, head);
    const heads = (await execFileAsync('git', ['bundle', 'list-heads', bundlePath])).stdout;
    assert.ok(heads.includes(head), 'the bundle names the commit');
    assert.equal((await git(['for-each-ref'])).stdout, refsBefore, 'no ref was added to the source repository');
  } finally {
    await rm(work, { recursive: true, force: true });
  }
});

test('Layer 4 [Historical Overlays, Branching, Layer 2 Reconstruction & G3 Prefix Mismatch]: parses strictly through coherence_overlay_check.py --parse-only, chains decision_commits/replaces_decision_id, attaches divergent branch to deepest ancestor, fails loudly on G3 mismatch, and passes Layer 2 check', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);

  const r1V1 = {
    record_id: 'policy:carrier_a:P100#effective:2026-01-01',
    disposition: 'CORRECT', agent: '11111111', agency: 'Beacon', policy: null,
    book: null, month: null, status: 'ACTIVE_PAYING', note: 'v1 initial', committed_at: '2026-09-30T10:00:00Z',
  };
  const r2V1 = {
    record_id: 'carrier_a~direct~PAT SAMPLE~100.00~2026-09',
    disposition: 'CONFIRM', agent: null, agency: null, policy: null,
    book: null, month: null, status: null, note: 'confirmed', committed_at: '2026-09-30T10:05:00Z',
  };
  const r3Rev = sampleApprovalRow({
    record_id: 'policy:carrier_a:P100#effective:2026-01-01',
    disposition: 'CORRECT', agent: '22222222', agency: 'Harbor', status: 'ACTIVE_RECON',
    note: 'revised agency', committed_at: '2026-10-12T11:00:00Z',
    approved_amount: '100.00', approved_agency: 'Harbor', approved_agent: '22222222',
  });
  const r4Adj = sampleApprovalRow({
    record_id: 'carrier_a~direct~LEE DEMO~50.00~2026-10',
    disposition: 'CONFIRM', agent: null, agency: null, status: null, note: 'adj ok',
    committed_at: '2026-10-12T12:00:00Z', approved_amount: '50.00', approved_agency: 'Beacon', approved_agent: '11111111',
  });
  const r3AltBranch = sampleApprovalRow({
    record_id: 'policy:carrier_a:P200#effective:2026-02-01',
    disposition: 'CORRECT', agent: '33333333', agency: 'Beacon', status: 'ACTIVE_PAYING',
    note: 'divergent branch', committed_at: '2026-10-12T09:00:00Z',
    approved_amount: '75.00', approved_agency: 'Beacon', approved_agent: '33333333',
  });

  const v1Csv = makeOverlayCsv([r1V1, r2V1], { version: 'v1' });
  const v2PriorCsv = makeOverlayCsv([r1V1, r2V1], { version: 'v2' });
  const v2BibleCsv = makeOverlayCsv([r1V1, r2V1, r3Rev], { version: 'v2' });
  const v2AdjCsv = makeOverlayCsv([r1V1, r2V1, r3Rev, r4Adj], { version: 'v2' });
  const v2BranchCsv = makeOverlayCsv([r1V1, r2V1, r3AltBranch], { version: 'v2' });

  const cohRoot = join(env.tempDir, 'hist-coherence');
  const dataRoot = join(env.tempDir, 'hist-data');

  // Run 1 (2026-09-30): v1 10-column overlay baseline
  await writeTree(join(cohRoot, 'runs', '2026-09-30'), {
    'input/a.csv': 'k\n1\n',
    'bible.csv': 'record_id,case,subtype,amount\npolicy:carrier_a:P100#effective:2026-01-01,BIBLE,CONFLICT,100.00\n',
    'overlay.csv': v1Csv,
    'run.json': JSON.stringify({ date: '2026-09-30', steps: { assign: { at: '2026-09-30T10:00:00', code: 'dirty+' }, bible: { at: '2026-09-30T10:01:00', code: 'dirty+' } } }),
  });

  // Run 2 (2026-10-12): main branch upgrading v1 -> v2 with Bible save + Adjust save + emits/overlay.csv
  await writeTree(join(cohRoot, 'runs', '2026-10-12'), {
    'input/a.csv': 'k\n1\n',
    'input/Overlay/overlay.csv': v2PriorCsv,
    'bible.csv': 'record_id,case,subtype,amount\npolicy:carrier_a:P100#effective:2026-01-01,BIBLE,CONFLICT,100.00\n',
    'adjust.csv': 'record_id,case,subtype,amount\ncarrier_a~direct~LEE DEMO~50.00~2026-10,NEW,NEW_BUSINESS,50.00\n',
    'overlay.csv': v2AdjCsv,
    'emits/overlay.csv': v2AdjCsv,
    'emits/statements_20261012.csv': 'record_id,entity,gross_comm,downline_amount,run_action\n',
    'run.json': JSON.stringify({ date: '2026-10-12', steps: { assign: { at: '2026-10-12T10:00:00' }, bible: { at: '2026-10-12T10:01:00' }, adjust: { at: '2026-10-12T11:10:00' }, emit: { at: '2026-10-12T12:10:00' } } }),
  });
  await writeTree(join(dataRoot, 'coherence-runs', '2026-10-12'), {
    'bible-review-2026-10-12T11-00-00-000Z.csv': v2BibleCsv,
    'adjust-review-2026-10-12T12-00-00-000Z.csv': v2AdjCsv,
  });

  // Run 3 (archive/v2/2026-10-12): divergent branch attaching to deepest matching ancestor ([r1V1, r2V1])
  await writeTree(join(cohRoot, 'runs', 'archive', 'v2', '2026-10-12'), {
    'input/a.csv': 'k\n1\n',
    'bible.csv': 'record_id,case,subtype,amount\npolicy:carrier_a:P200#effective:2026-02-01,BIBLE,CONFLICT,75.00\n',
    'overlay.csv': v2BranchCsv,
    'run.json': JSON.stringify({ date: '2026-10-12', steps: { assign: { at: '2026-10-12T08:00:00' }, bible: { at: '2026-10-12T08:01:00' } } }),
  });

  await writeTree(join(cohRoot, 'input'), {
    'a.csv': 'k\n1\n',
    'Overlay/overlay.csv': v2AdjCsv,
  });

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    coherenceRoot: cohRoot,
    nusearDataDir: dataRoot,
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha256Utf8(v1Csv) }],
    },
  });

  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: true,
    tempBaseDir: env.tempDir,
  });
  assert.equal(rep.passed, true, `Overlay import failed: ${rep.problems.join('; ')}`);

  // Verify decision_commits DAG: divergent archive/v2/2026-10-12 attached to a 2-row ancestor (NOT null, NOT main 4-row commit).
  const commits = (await env.pool.query(
    'SELECT id, parent_commit_id, header_contract, added_decision_count, cumulative_decision_count FROM coherence.decision_commits ORDER BY journal_seq ASC, cumulative_decision_count ASC',
  )).rows;
  const branchSave = (await env.pool.query(
    `SELECT rs.decision_commit_id, dc.parent_commit_id, p.cumulative_decision_count AS parent_cum
     FROM coherence.review_saves rs
     JOIN coherence.runs r ON r.id = rs.run_id
     JOIN coherence.decision_commits dc ON dc.id = rs.decision_commit_id
     LEFT JOIN coherence.decision_commits p ON p.id = dc.parent_commit_id
     WHERE r.source_folder = 'archive/v2/2026-10-12'`,
  )).rows[0];
  assert.ok(branchSave.parent_commit_id, 'divergent branch must attach to deepest matching ancestor, never reset to null');
  assert.equal(Number(branchSave.parent_cum), 2);
  assert.ok(commits.some((c) => c.header_contract === 'v1' && Number(c.cumulative_decision_count) === 2));

  // Verify replaces_decision_id linked r3Rev -> r1V1 across commits!
  const p100Chain = (await env.pool.query(
    `SELECT id, replaces_decision_id, agency FROM coherence.decisions
     WHERE record_id = 'policy:carrier_a:P100#effective:2026-01-01'
     ORDER BY journal_seq ASC, row_order ASC`,
  )).rows;
  assert.equal(p100Chain.length, 2);
  assert.equal(p100Chain[0].replaces_decision_id, null);
  assert.equal(p100Chain[1].replaces_decision_id, p100Chain[0].id);
  assert.equal(p100Chain[1].agency, 'Harbor');

  // Layer 2 check: verifyOverlayReconstruction passes across all checkpoints (v1 + v2 + divergent branch + standing head)
  const l2 = await verifyOverlayReconstruction({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    tempBaseDir: env.tempDir,
  });
  assert.equal(l2.passed, true, `Layer 2 failed: ${l2.problems.join('; ')}`);
  assert.ok(l2.checkpointsChecked >= 5, `expected >= 5 checkpoints checked, got ${l2.checkpointsChecked}`);
  assert.equal(l2.replacementChainViolations, 0);
  assert.equal(l2.currentParityMismatches, 0);
  assert.equal(l2.bibleAppliedParityMismatches, 0);
  const l2CheckRow = (await env.pool.query("SELECT passed FROM coherence.checks WHERE check_kind = 'overlay_reconstruction'")).rows;
  assert.equal(l2CheckRow.length, 1);
  assert.equal(l2CheckRow[0].passed, true);

  // G3 Negative Test: prefix mismatch within a run MUST fail loudly with run, checkpoint, and first differing row number (never silent reset).
  const badEnv = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => badEnv.cleanup());
  const badCoh = join(badEnv.tempDir, 'bad-coh');
  const badData = join(badEnv.tempDir, 'bad-data');
  const r2Tampered = { ...r2V1, note: 'TAMPERED ROW 2' };
  await writeTree(join(badCoh, 'runs', '2026-10-12'), {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': v2PriorCsv,
    'run.json': JSON.stringify({ date: '2026-10-12', steps: { assign: { at: '2026-10-12T10:00:00' }, bible: { at: '2026-10-12T10:01:00' } } }),
  });
  await writeTree(join(badCoh, 'runs', '2026-10-15'), {
    'input/Overlay/overlay.csv': v2PriorCsv,
    'overlay.csv': makeOverlayCsv([r1V1, r2Tampered, r3Rev], { version: 'v2' }),
    'run.json': JSON.stringify({ date: '2026-10-15', steps: { assign: { at: '2026-10-15T10:00:00' }, bible: { at: '2026-10-15T10:01:00' }, adjust: { at: '2026-10-15T10:02:00' } } }),
  });
  await writeTree(join(badData, 'coherence-runs', '2026-10-15'), {
    'bible-review-2026-10-15T10-05-00-000Z.csv': v2BibleCsv,
    'adjust-review-2026-10-15T10-10-00-000Z.csv': makeOverlayCsv([r1V1, r2Tampered, r3Rev, r4Adj], { version: 'v2' }),
  });
  const badManifest = await buildImportManifest({
    companySlug: 'acme',
    coherenceRoot: badCoh,
    nusearDataDir: badData,
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-10-12', sha256: sha256Utf8(v2PriorCsv) }],
    },
  });
  await assert.rejects(
    () => executeHistoryImport({
      pool: badEnv.pool,
      stores: badEnv.stores,
      commands: badEnv.commands,
      dbToken: badEnv.ownerToken,
      manifest: badManifest,
      pythonPath: 'python3',
      coherenceRepo: mockRepo,
      tempBaseDir: badEnv.tempDir,
    }),
    (err) => {
      assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH');
      assert.equal(err.firstDifferingRow, 2);
      assert.ok(String(err.message).includes('2026-10-15'));
      assert.ok(String(err.message).includes('adjust-review-2026-10-15T10-10-00-000Z.csv'));
      assert.ok(String(err.message).includes('2'));
      return true;
    },
  );
});

test('Layer 4 [G4 Config-Driven Manifest, All Sources, Company Sent Provenance & Idempotency]: imports standing input, abandoned runs, audit.json, replaced/, finished/, answer-key, local cloud mirror, Incident Report, 8 SQLite tables, preserves 11/11 sent provenance without upgrading unsent runs, routes code only to nusear_code, and re-imports idempotently', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const srcRoot = join(env.tempDir, 'sources');

  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:P1#effective:2026-01-01' });
  const ovCsv = makeOverlayCsv([row0], { version: 'v2' });

  // Standing input with trailing-space folder + .DS_Store
  await writeTree(join(srcRoot, 'standing-input'), {
    'Agent Data/cleanagentdata.csv': 'agent_name,agent_npn,entity,start_date\nSam Seller,11111111,Beacon,01/01/2025\n',
    'All BOB/TrailingCarrier /book.csv': 'member,policy_number\nPat Sample,P1\n',
    'Overlay/overlay.csv': ovCsv,
    '.DS_Store': 'finder-bytes',
  });

  // Legacy run (2026-11-02): pinned fresh root with no frozen prior
  await writeTree(join(srcRoot, 'legacy-runs', '2026-11-02'), {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'emits/statements_20261102.csv': 'record_id,entity,gross_comm,downline_amount,run_action\n',
    'run.json': JSON.stringify({ date: '2026-11-02', steps: { assign: { at: '2026-11-02T10:00:00' }, emit: { at: '2026-11-02T10:05:00' } } }),
  });

  // Company run 2026-11-11: header-only statements, recorded as sent in company-environment audit.json!
  await writeTree(join(srcRoot, 'company-ws', '2026-11-11', 'runs', '2026-11-11'), {
    'input/Overlay/overlay.csv': ovCsv,
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'emits/statements_20261111.csv': 'record_id,entity,gross_comm,downline_amount,run_action\n',
    'run.json': JSON.stringify({ date: '2026-11-11', steps: { assign: { at: '2026-11-11T10:00:00' }, emit: { at: '2026-11-11T10:05:00' } } }),
  });

  // Company run 2026-11-12: finished emit, NOT recorded as sent in company environment (must never be upgraded!)
  await writeTree(join(srcRoot, 'company-ws', '2026-11-12', 'runs', '2026-11-12'), {
    'input/Overlay/overlay.csv': ovCsv,
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'emits/statements_20261112.csv': 'record_id,entity,gross_comm,downline_amount,run_action\n',
    'run.json': JSON.stringify({ date: '2026-11-12', steps: { assign: { at: '2026-11-12T10:00:00' }, emit: { at: '2026-11-12T10:05:00' } } }),
  });

  // Abandoned company run (with run.json) + standalone abandoned log
  await writeTree(join(srcRoot, 'company-abandoned', '2026-11-09'), {
    'input/Overlay/overlay.csv': ovCsv,
    'overlay.csv': ovCsv,
    'emits/statements_20261109.csv': 'record_id,entity,gross_comm,downline_amount,run_action\n',
    'run.json': JSON.stringify({ date: '2026-11-09', steps: { assign: { at: '2026-11-09T10:00:00' }, emit: { at: '2026-11-09T10:02:00' } } }),
  });
  await writeTree(join(srcRoot, 'company-abandoned'), {
    'orphan-notes.txt': 'abandoned note\n',
  });

  // Company environment: audit.json (recording 2026-11-11 sent), replaced/, finished/ (with code-bearing .html), answer-key-*.json
  await writeTree(join(srcRoot, 'company-env'), {
    'audit.json': JSON.stringify({
      events: [
        { id: 'evt-1111', action: 'record_sent', statementDate: '2026-11-11', at: '2026-11-11T15:00:00Z', actor: 'company-operator' },
      ],
    }),
    'answer-key-2026-11-11.json': JSON.stringify({ statementDate: '2026-11-11', totals: { Beacon: '0.00' } }),
    'replaced/old-carrier.csv': 'k\nold\n',
    'finished/2026-11-11/summary.csv': 'k\ndone\n',
    'finished/2026-11-11/viewer.html': '<!doctype html><html><body>legacy viewer</body></html>',
    'staging/new-upload.csv': 'k\nstaged\n',
    'documents/memo.txt': 'memo\n',
    'inventories/inv.json': '{"count":1}\n',
  });

  // Local cloud mirror folder (zero network!) with valid SHA-256 object + mid-buffer embedded <script> file
  const cleanObjBytes = Buffer.from('col\nval\n', 'utf8');
  const cleanObjSha = createHash('sha256').update(cleanObjBytes).digest('hex');
  const sneakyScriptCsv = `${'a,b\n'.repeat(3000)}<script>alert(1)</script>\n`;
  await writeTree(join(srcRoot, 'cloud-mirror'), {
    'lists/standing-list.json': JSON.stringify({ objects: [cleanObjSha] }),
    [`objects/${cleanObjSha}`]: cleanObjBytes.toString('utf8'),
    'finished/sneaky.csv': sneakyScriptCsv,
  });

  // Incident Report with code-bearing .py
  await writeTree(join(srcRoot, 'incident-report'), {
    'report.csv': 'k\n1\n',
    'build_slate.py': 'print("script")\n',
  });

  // Create real 8-table legacy SQLite database via node:sqlite
  const sqlitePath = join(srcRoot, 'legacy.sqlite');
  const { DatabaseSync } = await import('node:sqlite');
  const sq = new DatabaseSync(sqlitePath);
  try {
    sq.exec(`
      CREATE TABLE coherence_run_records (date TEXT, status TEXT);
      CREATE TABLE coherence_run_events (id INTEGER PRIMARY KEY, date TEXT, kind TEXT);
      CREATE TABLE coherence_run_drafts (date TEXT, surface TEXT, body TEXT);
      CREATE TABLE coherence_run_settings (key TEXT, value TEXT);
      CREATE TABLE company_run_records (company TEXT, date TEXT, status TEXT, sent_at TEXT);
      CREATE TABLE company_run_events (id INTEGER PRIMARY KEY, company TEXT, date TEXT, kind TEXT);
      CREATE TABLE company_run_drafts (company TEXT, date TEXT, surface TEXT, body TEXT);
      CREATE TABLE company_intake_events (id INTEGER PRIMARY KEY, company TEXT, kind TEXT);
      INSERT INTO coherence_run_records VALUES ('2026-11-02', 'done');
      INSERT INTO coherence_run_events VALUES (1, '2026-11-02', 'finished'), (2, '2026-11-02', 'carried');
      INSERT INTO coherence_run_drafts VALUES ('2026-11-02', 'bible', '[]');
      INSERT INTO coherence_run_settings VALUES ('mode', 'coherence');
      INSERT INTO company_run_records VALUES ('acme', '2026-11-11', 'sent', '2026-11-11T15:00:00Z'), ('acme', '2026-11-12', 'done', NULL);
      INSERT INTO company_run_events VALUES (10, 'acme', '2026-11-11', 'sent');
      INSERT INTO company_run_drafts VALUES ('acme', '2026-11-12', 'adjust', '[]');
      INSERT INTO company_intake_events VALUES (20, 'acme', 'upload'), (21, 'acme', 'include');
    `);
  } finally {
    sq.close();
  }

  // Write config-driven JSON manifest file
  const manifestPath = join(env.tempDir, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    companySlug: 'acme',
    displayName: 'Acme',
    defaultEmitMode: 'coherence',
    coherenceRepo: mockRepo,
    pythonPath: 'python3',
    sources: {
      legacyRunsRoot: 'sources/legacy-runs',
      standingInputDir: 'sources/standing-input',
      incidentReportDir: 'sources/incident-report',
      companyWorkspacesDir: 'sources/company-ws',
      companyAbandonedDir: 'sources/company-abandoned',
      companyEnvironmentDir: 'sources/company-env',
      cloudMirrorDir: 'sources/cloud-mirror',
      legacySqlitePath: 'sources/legacy.sqlite',
    },
    importConfig: {
      includeLegacyHostHistory: true,
      includeLegacySqliteTables: true,
      useCompanyIncomingInput: false,
      currentInputSourceKind: 'mac_import',
      freshOverlayRoots: [{ sourceFolder: '2026-11-02', sha256: sha256Utf8(ovCsv) }],
    },
  }, null, 2), 'utf8');

  const manifest = await loadImportManifestFile(manifestPath);
  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest,
    verifyRebuild: true,
    tempBaseDir: env.tempDir,
  });
  assert.equal(rep.passed, true, `G4 import failed: ${rep.problems.join('; ')}`);
  assert.equal(rep.rebuildChecks.length, 4, 'legacy + 2 company + 1 abandoned run rebuilt');
  assert.ok(rep.rebuildChecks.every((c) => c.passed));
  assert.equal(rep.standingInputRebuildCheck.passed, true);
  assert.equal(rep.incidentReportRebuildCheck.passed, true);
  assert.equal(rep.standaloneRebuildCheck.passed, true);
  assert.equal(rep.objectCheck.passed, true);
  assert.equal(rep.objectCheck.codeInDataStoreCount, 0);

  // Verify all 8 legacy SQLite tables matched exact row counts!
  assert.deepEqual(rep.sqliteParity.imported, {
    coherence_run_records: 1,
    coherence_run_events: 2,
    coherence_run_drafts: 1,
    coherence_run_settings: 1,
    company_run_records: 2,
    company_run_events: 1,
    company_run_drafts: 1,
    company_intake_events: 2,
  });

  // Verify code-bearing files (viewer.html, build_slate.py, mid-buffer sneaky.csv) went ONLY to nusear_code!
  const codeRows = (await env.pool.query(
    `SELECT rel_path, store_kind, artifact_kind FROM coherence.imported_files
     WHERE rel_path LIKE '%viewer.html' OR rel_path LIKE '%build_slate.py' OR rel_path LIKE '%sneaky.csv'
     ORDER BY rel_path`,
  )).rows;
  assert.equal(codeRows.length, 3);
  for (const row of codeRows) {
    assert.equal(row.store_kind, 'nusear_code', `${row.rel_path} must go strictly to nusear_code`);
    assert.equal(row.artifact_kind, 'code_bearing');
  }

  // Verify 2026-11-11 company run preserved as company_import WITH sent carry citing audit.json provenance,
  // while 2026-11-12 company run has NO sent carry (never upgraded!).
  const sentCarries = (await env.pool.query(
    `SELECT c.statement_date::text, r.origin, r.source_folder, je.body->'sentProvenance' AS prov
     FROM coherence.carries c
     JOIN coherence.runs r ON r.id = c.run_id
     JOIN coherence.journal_entries je ON je.seq = c.journal_seq
     WHERE c.carry_kind = 'sent'`,
  )).rows;
  assert.equal(sentCarries.length, 1);
  assert.equal(sentCarries[0].statement_date, '2026-11-11');
  assert.equal(sentCarries[0].origin, 'company_import');
  assert.equal(sentCarries[0].prov.source, 'company-environment/audit.json');
  assert.equal(sentCarries[0].prov.recordId, 'evt-1111');

  // Verify abandoned company run is excluded from findLatestPublishedRun (strictly via platform_app + app_views)!
  const iamG4 = env.iam;
  const appPoolG4 = createRoleScopedTestPool(env.pool, 'platform_app');
  const latestPub = await findLatestPublishedRun(appPoolG4, iamG4.tokens.owner);
  assert.equal(latestPub.statement_date, '2026-11-12');

  // Verify idempotency: re-importing the same manifest adds ZERO new rows across all business tables!
  const countSnapshot = async () => {
    const out = {};
    for (const tbl of ['runs', 'stored_files', 'decision_commits', 'decisions', 'generated_overlays', 'input_versions', 'imported_files', 'carries']) {
      out[tbl] = Number((await env.pool.query(`SELECT COUNT(*)::int AS n FROM coherence.${tbl}`)).rows[0].n);
    }
    return out;
  };
  const before = await countSnapshot();
  const rep2 = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest,
    verifyRebuild: false,
    recordCheck: false,
    tempBaseDir: env.tempDir,
  });
  const after = await countSnapshot();
  assert.equal(rep2.passed, true);
  assert.equal(rep2.importedRuns.length, 0);
  assert.deepEqual(after, before, 're-importing the same manifest must add zero records or stored files');
});

test('Layer 4 [Pre-Coherence 5 Sent Dates & 2 Method Corrections]: imports via python/coherence_legacy_statements.py into statement_batches, statement_agency_lines, and statement_upline_lines with exact netting and idempotency', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const stmtDir = join(env.tempDir, 'pre-coherence-statements');

  const plxCols = 'Statement,WritingAgent,WritingAgentNPN,PolicyHolderName,MBI,State,Carrier,EffectiveDate,PlanType,SimplifiedCoverageType,PolicyNumber,CommissionAmount,Note,RevenueType,EarnedDate,PaymentDate,entity,DLTotal,ULTotal';
  const plxRow = (dt, dl, ul, gross) => `${dt} - CarrierA,Sam Seller,11111111,Pat Sample,1AB2CD3EF45,NC,CarrierA,2026-01-01,MA,MA,POL1,${gross},plx,Commission,${dt},${dt},Beacon,${dl},${ul}`;
  await writeTree(stmtDir, {
    'BEA20260325.csv': 'Statement,Carrier,Revenue Type,Commission Amount,Writing Agent NPN,Writing Agent,Policy Holder Name,MBI,Policy Number,Earned Date,Payment Date,Effective Date,Note,State,Plan Type,Simplified Coverage Type\n2026-03-06,CarrierA,Commission,$ 100.00,11111111,Sam Seller,Pat Sample,1AB2CD3EF45,POL1,2026-03-01,2026-03-06,2026-01-01,mar,NC,MA,MA\n',
    'plxSpark20260429.csv': `${plxCols}\n${plxRow('2026-04-15', '80.00', '20.00', '100.00')}\n`,
    'plxSpark20260531.csv': `${plxCols}\n${plxRow('2026-05-15', '80.00', '20.00', '100.00')}\n`,
    'plxSpark20260630.csv': `${plxCols}\n${plxRow('2026-06-15', '80.00', '20.00', '100.00')}\n`,
    'ALLAGENCY20260731Spark.csv': 'entity,npn,agent,member,mbi,policy_number,carrier,channel,amount,earned,payment,note,state,plan_type,coverage_type,effective,submitted\nBeacon,11111111,Sam Seller,Pat Sample,1AB2CD3EF45,POL1,carriera,spark,100.00,2026-07-01,2026-07-15,jul,NC,MA,MA,2026-01-01,2026-01-01\nAcme,22222222,House Rep,Lee Demo,2CD3EF4GH56,POL2,carriera,spark,50.00,2026-07-01,2026-07-15,jul,NC,MA,MA,2026-01-01,2026-01-01\n',
  });

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      preCoherenceStatementsDir: stmtDir,
      methodCorrections: [
        {
          kind: 'split_reallocation',
          statementDate: '2026-08-01',
          sourceGrammar: 'all_agency',
          unreversedOnly: false,
          uplineRate: '0.20',
          excludeEntities: ['Acme'],
          expectedAgencyNetCents: -2000,
          expectedUplineNetCents: 2000,
          reason: '2026-08-01 80/20 split correction',
        },
        {
          kind: 'upline_takeback',
          statementDate: '2026-08-31',
          sourceGrammar: 'plx_layout',
          expectedAgencyNetCents: 0,
          expectedUplineNetCents: -6000,
          reason: '2026-08-31 historical ULTotal take-back',
        },
      ],
    },
  });

  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: env.tempDir,
  });
  assert.equal(rep.passed, true, rep.problems.join('; '));
  assert.equal(rep.preCoherenceBatchesImported, 5);
  assert.equal(rep.methodCorrectionBatchesImported, 2);

  const batches = (await env.pool.query(
    `SELECT batch_kind, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS dt,
            agency_line_count, agency_net_total::text, upline_line_count, upline_net_total::text
     FROM coherence.statement_batches
     ORDER BY statement_date ASC, batch_kind ASC`,
  )).rows;
  assert.equal(batches.length, 7);
  assert.equal(batches.filter((b) => b.batch_kind === 'historical_sent').length, 5);
  assert.equal(batches.filter((b) => b.batch_kind === 'method_correction').length, 2);

  // Verify cumulative totals through app_views as platform_app:
  // Beacon: 100 (3/25) + 80*3 (4/29..6/30) + 100 (7/31) - 20 (8/1 split) = 420.00
  // Acme: 50 (7/31, excluded from 8/1 split) = 50.00
  // Acme Upline: 20*3 (4/29..6/30) + 20 (8/1 split) - 60 (8/31 take-back) = 20.00
  const entTotals = await withRequestTx(createRoleScopedTestPool(env.pool, 'platform_app'), env.ownerToken, async (tx) => (
    (await tx.query(
      `SELECT statement_entity, SUM(net_amount)::numeric(14,2)::text AS total
       FROM app_views.coherence_statement_date_totals
       GROUP BY statement_entity
       ORDER BY statement_entity COLLATE "C"`,
    )).rows
  ), { readOnly: true });
  assert.deepEqual(entTotals, [
    { statement_entity: 'Acme', total: '50.00' },
    { statement_entity: 'Acme Upline', total: '20.00' },
    { statement_entity: 'Beacon', total: '420.00' },
  ]);

  // Verify idempotency on re-import
  const rep2 = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    recordCheck: false,
    tempBaseDir: env.tempDir,
  });
  assert.equal(rep2.preCoherenceBatchesImported, 0);
  assert.equal(rep2.methodCorrectionBatchesImported, 0);
  assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.statement_batches')).rows[0].n, 7);
});

test('Layer 4 [Fix 2 - Legacy Bridge Derived Corrections]: plx upline-only rows without $0 agency lines, loud unreversedOnly/agents.lookup failures, Coherence ROUND_HALF_UP rounding (positive and negative half-cents), and cent-exact expected totals abort', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const stmtDir = join(env.tempDir, 'legacy-stmts');
  const sentDir = join(env.tempDir, 'sent-dir');
  const agentsCsv = join(env.tempDir, 'cleanagentdata.csv');

  const plantedMember = 'Zelda Q. Plantedname';
  const plxCols = 'Statement,WritingAgent,WritingAgentNPN,PolicyHolderName,MBI,State,Carrier,EffectiveDate,PlanType,SimplifiedCoverageType,PolicyNumber,CommissionAmount,Note,RevenueType,EarnedDate,PaymentDate,entity,DLTotal,ULTotal';
  await writeTree(stmtDir, {
    'plxSpark20260429.csv': [
      plxCols,
      // Blank DLTotal with non-zero ULTotal -> must emit upline line only, zero agency line
      `2026-04-15 - CarrierA,Sam Seller,11111111,${plantedMember},1AB2CD3EF45,NC,CarrierA,2026-01-01,MA,MA,POL1,25.00,blank-dl,Commission,2026-04-01,2026-04-15,Beacon,,25.00`,
      // $0.00 DLTotal with non-zero ULTotal -> must emit upline line only, no $0.00 agency line
      `2026-04-15 - CarrierA,Sam Seller,11111111,${plantedMember},1AB2CD3EF45,NC,CarrierA,2026-01-01,MA,MA,POL2,15.00,zero-dl,Commission,2026-04-01,2026-04-15,Beacon,0.00,15.00`,
      // Standard split row
      `2026-04-15 - CarrierA,Sam Seller,11111111,${plantedMember},1AB2CD3EF45,NC,CarrierA,2026-01-01,MA,MA,POL3,100.00,both,Commission,2026-04-01,2026-04-15,Beacon,80.00,20.00`,
    ].join('\n') + '\n',
    'ALLAGENCY20260731Spark.csv': [
      'entity,npn,agent,member,mbi,policy_number,carrier,channel,amount,earned,payment,note,state,plan_type,coverage_type,effective,submitted',
      // 0.05 at 50% split: downline = round_half_up(0.025) = 0.03, upline = 0.05 - 0.03 = 0.02 (HALF_EVEN would give 0.02 / 0.03)
      `Beacon,11111111,Sam Seller,${plantedMember},1AB2CD3EF45,POL4,carriera,spark,0.05,2026-07-01,2026-07-15,half1,NC,MA,MA,2026-01-01,2026-01-01`,
      // 0.03 at 50% split: downline = round_half_up(0.015) = 0.02, upline = 0.03 - 0.02 = 0.01
      `Beacon,11111111,Sam Seller,${plantedMember},1AB2CD3EF45,POL5,carriera,spark,0.03,2026-07-01,2026-07-15,half2,NC,MA,MA,2026-01-01,2026-01-01`,
      // 0.15 at 70% split: downline = round_half_up(0.105) = 0.11, upline = 0.15 - 0.11 = 0.04 (HALF_EVEN would give 0.10 / 0.05)
      `Beacon,22222222,Pat Rep,${plantedMember},1AB2CD3EF45,POL6,carriera,spark,0.15,2026-07-01,2026-07-15,half3,NC,MA,MA,2026-01-01,2026-01-01`,
    ].join('\n') + '\n',
    'ALLAGENCY20260731NegSpark.csv': [
      'entity,npn,agent,member,mbi,policy_number,carrier,channel,amount,earned,payment,note,state,plan_type,coverage_type,effective,submitted',
      // -0.05 at 50% split: downline = round_half_up(-0.025) = -0.03, upline = -0.05 - (-0.03) = -0.02 (HALF_EVEN would give -0.02 / -0.03)
      `Beacon,11111111,Sam Seller,${plantedMember},1AB2CD3EF45,POL7,carriera,spark,-0.05,2026-07-01,2026-07-15,neghalf1,NC,MA,MA,2026-01-01,2026-01-01`,
      // -0.15 at 70% split: downline = round_half_up(-0.105) = -0.11, upline = -0.15 - (-0.11) = -0.04 (HALF_EVEN would give -0.10 / -0.05)
      `Beacon,22222222,Pat Rep,${plantedMember},1AB2CD3EF45,POL8,carriera,spark,-0.15,2026-07-01,2026-07-15,neghalf2,NC,MA,MA,2026-01-01,2026-01-01`,
      // -0.03 at 50% split: downline = round_half_up(-0.015) = -0.02, upline = -0.03 - (-0.02) = -0.01
      `Beacon,11111111,Sam Seller,${plantedMember},1AB2CD3EF45,POL9,carriera,spark,-0.03,2026-07-01,2026-07-15,neghalf3,NC,MA,MA,2026-01-01,2026-01-01`,
    ].join('\n') + '\n',
  });
  await mkdir(sentDir, { recursive: true });
  await writeFile(
    agentsCsv,
    'agent_name,agent_npn,entity,split_percentage\nSam Seller,11111111,Beacon,50%\nPat Rep,22222222,Beacon,70%\n',
    'utf8',
  );

  // 1) plx upline-only rows + Coherence ROUND_HALF_UP rounding (positive and negative) + exact expected cents succeed
  const okParsed = await readLegacyStatementBatches({ companyDisplayName: 'Acme',
    statementsDir: stmtDir,
    sentDir,
    agentsCsvPath: agentsCsv,
    methodCorrections: [
      {
        kind: 'split_reallocation',
        statementDate: '2026-08-01',
        sourceGrammar: 'all_agency',
        sourceFiles: ['ALLAGENCY20260731Spark.csv'],
        unreversedOnly: true,
        useAgentsSplit: true,
        expectedAgencyNetCents: -7,
        expectedUplineNetCents: 7,
        reason: '2026-08-01 split reallocation positive half-cents',
      },
      {
        kind: 'split_reallocation',
        statementDate: '2026-08-02',
        sourceGrammar: 'all_agency',
        sourceFiles: ['ALLAGENCY20260731NegSpark.csv'],
        unreversedOnly: true,
        useAgentsSplit: true,
        expectedAgencyNetCents: 7,
        expectedUplineNetCents: -7,
        reason: '2026-08-02 split reallocation negative half-cents',
      },
      {
        kind: 'upline_takeback',
        statementDate: '2026-08-31',
        sourceGrammar: 'plx_layout',
        expectedAgencyNetCents: 0,
        expectedUplineNetCents: -6000,
        reason: '2026-08-31 upline take-back',
      },
    ],
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    tempBaseDir: env.tempDir,
  });
  const plxBatch = okParsed.historicalBatches.find((b) => b.sourceFileName === 'plxSpark20260429.csv');
  assert.equal(plxBatch.agencyLineCount, 1, 'must emit no $0.00 agency lines for blank or 0.00 DLTotal rows with ULTotal');
  assert.equal(plxBatch.agencyNetTotal, '80.00');
  assert.equal(plxBatch.uplineLineCount, 3, 'must capture blank-DLTotal, zero-DLTotal, and split upline lines');
  assert.equal(plxBatch.uplineNetTotal, '60.00');
  assert.equal(okParsed.methodCorrectionBatches[0].agencyNetTotal, '-0.07');
  assert.equal(okParsed.methodCorrectionBatches[0].uplineNetTotal, '0.07');
  assert.deepEqual(okParsed.methodCorrectionBatches[0].agencyLines.map((l) => l.amount), ['-0.02', '-0.01', '-0.04']);
  assert.deepEqual(okParsed.methodCorrectionBatches[0].uplineLines.map((l) => l.amount), ['0.02', '0.01', '0.04']);
  assert.equal(okParsed.methodCorrectionBatches[1].agencyNetTotal, '0.07');
  assert.equal(okParsed.methodCorrectionBatches[1].uplineNetTotal, '-0.07');
  assert.deepEqual(okParsed.methodCorrectionBatches[1].agencyLines.map((l) => l.amount), ['0.02', '0.04', '0.01']);
  assert.deepEqual(okParsed.methodCorrectionBatches[1].uplineLines.map((l) => l.amount), ['-0.02', '-0.04', '-0.01']);
  assert.equal(okParsed.methodCorrectionBatches[2].uplineNetTotal, '-60.00');

  // 2) unreversedOnly without readable sentDir must fail loudly
  await assert.rejects(
    () => readLegacyStatementBatches({ companyDisplayName: 'Acme',
      statementsDir: stmtDir,
      sentDir: null,
      agentsCsvPath: agentsCsv,
      methodCorrections: [{
        kind: 'split_reallocation',
        statementDate: '2026-08-01',
        sourceGrammar: 'all_agency',
        sourceFiles: ['ALLAGENCY20260731Spark.csv'],
        unreversedOnly: true,
        useAgentsSplit: true,
        expectedAgencyNetCents: -7,
        expectedUplineNetCents: 7,
      }],
      pythonPath: 'python3',
      coherenceRepo: mockRepo,
      tempBaseDir: env.tempDir,
    }),
    /sentDir|sent folder|unreversedOnly/i,
  );

  // 3) agents.lookup() finding no agent under useAgentsSplit must fail loudly (no silent skip)
  const missingAgentCsv = join(env.tempDir, 'missing-agent.csv');
  await writeFile(missingAgentCsv, 'agent_name,agent_npn,entity,split_percentage\nSam Seller,11111111,Beacon,50%\n', 'utf8');
  await assert.rejects(
    () => readLegacyStatementBatches({ companyDisplayName: 'Acme',
      statementsDir: stmtDir,
      sentDir,
      agentsCsvPath: missingAgentCsv,
      methodCorrections: [{
        kind: 'split_reallocation',
        statementDate: '2026-08-01',
        sourceGrammar: 'all_agency',
        sourceFiles: ['ALLAGENCY20260731Spark.csv'],
        unreversedOnly: true,
        useAgentsSplit: true,
        expectedAgencyNetCents: -7,
        expectedUplineNetCents: 7,
      }],
      pythonPath: 'python3',
      coherenceRepo: mockRepo,
      tempBaseDir: env.tempDir,
    }),
    (err) => {
      assert.match(err.message, /agent|lookup|useAgentsSplit/i);
      assert.equal(err.message.includes(plantedMember), false);
      return true;
    },
  );

  // 4) Missing expected totals on a method_correction spec must fail loudly
  await assert.rejects(
    () => readLegacyStatementBatches({ companyDisplayName: 'Acme',
      statementsDir: stmtDir,
      sentDir,
      agentsCsvPath: agentsCsv,
      methodCorrections: [{
        kind: 'upline_takeback',
        statementDate: '2026-08-31',
        sourceGrammar: 'plx_layout',
      }],
      pythonPath: 'python3',
      coherenceRepo: mockRepo,
      tempBaseDir: env.tempDir,
    }),
    /expectedAgencyNetCents|expectedUplineNetCents/i,
  );

  // 5) One-cent difference aborts import loudly naming ONLY the correction and the two totals (no PHI, zero DB batches written)
  const offByOneManifest = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      preCoherenceStatementsDir: stmtDir,
      preCoherenceSentDir: sentDir,
      preCoherenceAgentsCsv: agentsCsv,
      methodCorrections: [{
        kind: 'upline_takeback',
        statementDate: '2026-08-31',
        sourceGrammar: 'plx_layout',
        expectedAgencyNetCents: 0,
        expectedUplineNetCents: -6001, // 1 cent off from -6000
        reason: `sensitive reason ${plantedMember}`,
      }],
    },
  });
  await assert.rejects(
    () => executeHistoryImport({
      pool: env.pool,
      stores: env.stores,
      commands: env.commands,
      dbToken: env.ownerToken,
      manifest: offByOneManifest,
      pythonPath: 'python3',
      coherenceRepo: mockRepo,
      verifyRebuild: false,
      tempBaseDir: env.tempDir,
    }),
    (err) => {
      assert.ok(err.message.includes('2026-08-31'), 'must name correction date');
      assert.ok(err.message.includes('upline_takeback'), 'must name correction kind');
      assert.ok(err.message.includes('-6001'), 'must include expected total');
      assert.ok(err.message.includes('-6000'), 'must include actual total');
      assert.equal(err.message.includes(plantedMember), false, 'must never leak member name or extra text');
      return true;
    },
  );
  assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.statement_batches')).rows[0].n, 0);

  // 6) Fixed-rate split_reallocation (useAgentsSplit: false) also uses Coherence ROUND_HALF_UP downline = round_half_up(amount * split), upline = amount - downline
  const fixedRateRes = await readLegacyStatementBatches({ companyDisplayName: 'Acme',
    statementsDir: stmtDir,
    sentDir,
    methodCorrections: [
      {
        kind: 'split_reallocation',
        statementDate: '2026-08-01',
        sourceGrammar: 'all_agency',
        sourceFiles: ['ALLAGENCY20260731Spark.csv'],
        unreversedOnly: true,
        useAgentsSplit: false,
        uplineRate: '0.50', // 0.05 -> dl 0.03 ul 0.02; 0.03 -> dl 0.02 ul 0.01; 0.15 -> dl 0.08 ul 0.07 => total ul = 0.10
        expectedAgencyNetCents: -10,
        expectedUplineNetCents: 10,
      },
      {
        kind: 'split_reallocation',
        statementDate: '2026-08-02',
        sourceGrammar: 'all_agency',
        sourceFiles: ['ALLAGENCY20260731NegSpark.csv'],
        unreversedOnly: true,
        useAgentsSplit: false,
        uplineRate: '0.50', // -0.05 -> dl -0.03 ul -0.02; -0.15 -> dl -0.08 ul -0.07; -0.03 -> dl -0.02 ul -0.01 => total ul = -0.10
        expectedAgencyNetCents: 10,
        expectedUplineNetCents: -10,
      },
    ],
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    tempBaseDir: env.tempDir,
  });
  assert.equal(fixedRateRes.methodCorrectionBatches[0].agencyNetTotal, '-0.10');
  assert.equal(fixedRateRes.methodCorrectionBatches[0].uplineNetTotal, '0.10');
  assert.deepEqual(fixedRateRes.methodCorrectionBatches[0].uplineLines.map((l) => l.amount), ['0.02', '0.01', '0.07']);
  assert.equal(fixedRateRes.methodCorrectionBatches[1].agencyNetTotal, '0.10');
  assert.equal(fixedRateRes.methodCorrectionBatches[1].uplineNetTotal, '-0.10');
  assert.deepEqual(fixedRateRes.methodCorrectionBatches[1].uplineLines.map((l) => l.amount), ['-0.02', '-0.07', '-0.01']);
});

test('Layer 4 [8/1 Split Reallocation & 8/31 Upline Takeback Direction]: proves split_reallocation sign follows unreversed ALLAGENCY net sign, reconciles to Coherent Ledger at $0.00 variance, rejects inverted signs at COMMIT, and proves upline_takeback negates historical plx ULTotal', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const allAgencyHdr = 'entity,npn,agent,member,mbi,policy_number,carrier,channel,amount,earned,payment,note,state,plan_type,coverage_type,effective,submitted';
  const plxHdr = 'Statement,WritingAgent,WritingAgentNPN,PolicyHolderName,MBI,State,Carrier,EffectiveDate,PlanType,SimplifiedCoverageType,PolicyNumber,CommissionAmount,Note,RevenueType,EarnedDate,PaymentDate,entity,DLTotal,ULTotal';
  const sentHdr = 'record_id,entity,writing_npn,gross_comm,run_action,reversal_of,statement_name';

  // 1) Positive-net unreversed ALLAGENCY lines after Sent/ reversal settlement -> agency -, upline +
  const envPos = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => envPos.cleanup());
  const mockRepoPos = join(envPos.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepoPos);
  const posStmtDir = join(envPos.tempDir, 'pos-stmts');
  const posSentDir = join(envPos.tempDir, 'pos-sent');
  await writeTree(posStmtDir, {
    'ALLAGENCY20260731Spark.csv': [
      allAgencyHdr,
      // Reversed in Sent/ below (must be excluded by unreversedOnly: true)
      'Beacon,11111111,Sam Seller,Pat Sample,1AB2CD3EF45,POL101,carriera,spark,250.00,2026-07-01,2026-07-15,rev,NC,MA,MA,2026-01-01,2026-01-01',
      // Surviving positive +150.00 -> downline +120.00, upline +30.00 (agency -30.00, upline +30.00)
      'Beacon,11111111,Sam Seller,Lee Demo,2CD3EF4GH56,POL102,carriera,spark,150.00,2026-07-01,2026-07-15,pos,NC,MA,MA,2026-01-01,2026-01-01',
      // Surviving chargeback -50.00 -> downline -40.00, upline -10.00 (agency +10.00, upline -10.00)
      'Harbor,22222222,Pat Rep,Kim Test,3EF4GH5JK67,POL103,carriera,spark,-50.00,2026-07-01,2026-07-15,cb,NC,MA,MA,2026-01-01,2026-01-01',
      // House entity excluded by excludeEntities: ['Acme']
      'Acme,33333333,House Rep,Max Sample,4GH5JK6LM78,POL104,carriera,spark,80.00,2026-07-01,2026-07-15,house,NC,MA,MA,2026-01-01,2026-01-01',
    ].join('\n') + '\n',
    'plxSpark20260429.csv': [
      plxHdr,
      '2026-04-15 - CarrierA,Sam Seller,11111111,Lee Demo,2CD3EF4GH56,NC,CarrierA,2026-01-01,MA,MA,POL102,300.00,pos-ul,Commission,2026-04-01,2026-04-15,Beacon,240.00,60.00',
      '2026-04-15 - CarrierA,Pat Rep,22222222,Kim Test,3EF4GH5JK67,NC,CarrierA,2026-01-01,MA,MA,POL103,-75.00,neg-ul,Commission,2026-04-01,2026-04-15,Harbor,-60.00,-15.00',
    ].join('\n') + '\n',
  });
  await writeTree(posSentDir, {
    'statements_20260831.csv': [
      sentHdr,
      'carriera~spark~1AB2CD3EF45~250.00~2026-07,Beacon,11111111,-250.00,REVERSAL,carriera~spark~1AB2CD3EF45~250.00~2026-07,ALLAGENCY20260731Spark.csv',
    ].join('\n') + '\n',
  });
  const posRes = await readLegacyStatementBatches({ companyDisplayName: 'Acme',
    statementsDir: posStmtDir,
    sentDir: posSentDir,
    methodCorrections: [
      {
        kind: 'split_reallocation',
        statementDate: '2026-08-01',
        sourceGrammar: 'all_agency',
        unreversedOnly: true,
        useAgentsSplit: false,
        uplineRate: '0.20',
        excludeEntities: ['Acme'],
        expectedAgencyNetCents: -2000,
        expectedUplineNetCents: 2000,
        reason: '80/20 split on positive-net unreversed ALLAGENCY lines',
      },
      {
        kind: 'upline_takeback',
        statementDate: '2026-08-31',
        sourceGrammar: 'plx_layout',
        expectedAgencyNetCents: 0,
        expectedUplineNetCents: -4500,
        reason: 'historical plx ULTotal take-back',
      },
    ],
    pythonPath: 'python3',
    coherenceRepo: mockRepoPos,
    tempBaseDir: envPos.tempDir,
  });
  assert.equal(posRes.methodCorrectionBatches[0].agencyNetTotal, '-20.00');
  assert.equal(posRes.methodCorrectionBatches[0].uplineNetTotal, '20.00');
  assert.deepEqual(
    posRes.methodCorrectionBatches[0].agencyLines.map((l) => [l.entity, l.amount]),
    [['Beacon', '-30.00'], ['Harbor', '10.00']],
  );
  assert.deepEqual(
    posRes.methodCorrectionBatches[0].uplineLines.map((l) => [l.sourceEntity, l.amount]),
    [['Beacon', '30.00'], ['Harbor', '-10.00']],
  );
  assert.equal(posRes.methodCorrectionBatches[1].agencyNetTotal, '0.00');
  assert.equal(posRes.methodCorrectionBatches[1].uplineNetTotal, '-45.00');
  assert.deepEqual(
    posRes.methodCorrectionBatches[1].uplineLines.map((l) => l.amount),
    ['-60.00', '15.00'],
  );

  // 2) Negative-net unreversed ALLAGENCY lines (chargebacks > commissions after Sent/ reversals)
  //    reproduce the exact opposite-sign mismatch and prove agency + / upline - is required for $0.00 Ledger tie-out.
  const negAllAgencyCsv = [
    allAgencyHdr,
    // Reversed in Sent/ below (excluded by unreversedOnly: true)
    'Beacon,11111111,Sam Seller,Pat Sample,1AB2CD3EF45,POL201,carriera,spark,500.00,2026-07-01,2026-07-15,rev,NC,MA,MA,2026-01-01,2026-01-01',
    // Surviving positive +40.00 -> downline +32.00, upline +8.00 (8/1: agency -8.00, upline +8.00)
    'Beacon,11111111,Sam Seller,Lee Demo,2CD3EF4GH56,POL202,carriera,spark,40.00,2026-07-01,2026-07-15,pos,NC,MA,MA,2026-01-01,2026-01-01',
    // Surviving chargeback -140.00 -> downline -112.00, upline -28.00 (8/1: agency +28.00, upline -28.00)
    'Harbor,22222222,Pat Rep,Kim Test,3EF4GH5JK67,POL203,carriera,spark,-140.00,2026-07-01,2026-07-15,cb,NC,MA,MA,2026-01-01,2026-01-01',
    // House entity excluded by excludeEntities: ['Acme']
    'Acme,33333333,House Rep,Max Sample,4GH5JK6LM78,POL204,carriera,spark,75.00,2026-07-01,2026-07-15,house,NC,MA,MA,2026-01-01,2026-01-01',
  ].join('\n') + '\n';
  const negSentCsv = [
    sentHdr,
    'carriera~spark~1AB2CD3EF45~500.00~2026-07,Beacon,11111111,-500.00,CANCEL,carriera~spark~1AB2CD3EF45~500.00~2026-07,ALLAGENCY20260731Spark.csv',
  ].join('\n') + '\n';

  const negStmtDir = join(envPos.tempDir, 'neg-stmts');
  const negSentDir = join(envPos.tempDir, 'neg-sent');
  await writeTree(negStmtDir, { 'ALLAGENCY20260731Spark.csv': negAllAgencyCsv });
  await writeTree(negSentDir, { 'statements_20260831.csv': negSentCsv });

  // Expecting agency - / upline + against negative-net surviving lines produces the exact opposite-sign error
  await assert.rejects(
    () => readLegacyStatementBatches({ companyDisplayName: 'Acme',
      statementsDir: negStmtDir,
      sentDir: negSentDir,
      methodCorrections: [{
        kind: 'split_reallocation',
        statementDate: '2026-08-01',
        sourceGrammar: 'all_agency',
        unreversedOnly: true,
        useAgentsSplit: false,
        uplineRate: '0.20',
        excludeEntities: ['Acme'],
        expectedAgencyNetCents: -2000,
        expectedUplineNetCents: 2000,
      }],
      pythonPath: 'python3',
      coherenceRepo: mockRepoPos,
      tempBaseDir: envPos.tempDir,
    }),
    (err) => {
      assert.equal(err.code, 'LEGACY_STATEMENT_READ_FAILED');
      assert.ok(err.message.includes('agency expected -2000 cents vs 2000 cents; upline expected 2000 cents vs -2000 cents.'));
      return true;
    },
  );

  // End-to-end PostgreSQL conservation proof: agency +20.00 / upline -20.00 reconciles at $0.00 variance,
  // while the inverted direction (-20.00 / +20.00) is rejected by trg_run_materializations_verify_deferred.
  const runNegConservationCheck = async (invertCorrectionSign) => {
    const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
    t.after(() => env.cleanup());
    const { engineVersionId } = await seedEngineVersion(env);
    await seedStandingInput(env, { commandKey: `neg-standing-${invertCorrectionSign}` });

    const parsed = await readLegacyStatementBatches({ companyDisplayName: 'Acme',
      statementsDir: negStmtDir,
      sentDir: negSentDir,
      methodCorrections: [{
        kind: 'split_reallocation',
        statementDate: '2026-08-01',
        sourceGrammar: 'all_agency',
        unreversedOnly: true,
        useAgentsSplit: false,
        uplineRate: '0.20',
        excludeEntities: ['Acme'],
        expectedAgencyNetCents: 2000,
        expectedUplineNetCents: -2000,
      }],
      pythonPath: 'python3',
      coherenceRepo: mockRepoPos,
      tempBaseDir: env.tempDir,
    });

    const histBatch = parsed.historicalBatches[0];
    const corrBatch = parsed.methodCorrectionBatches[0];
    const histStored = await env.dataStore.promoteBytes(Buffer.from(negAllAgencyCsv, 'utf8'), {
      relPath: 'Prior Statements/ALLAGENCY20260731Spark.csv',
      checksPassed: true,
    });
    await env.commands.recordStatementBatch({
      dbToken: env.ownerToken,
      commandKey: 'hist-allagency-20260731',
      batchKind: 'historical_sent',
      statementDate: '2026-07-31',
      sourceFileName: 'ALLAGENCY20260731Spark.csv',
      sourceFile: histStored,
      reason: 'Imported 2026-07-31 ALLAGENCY statement',
      agencyLines: histBatch.agencyLines,
      uplineLines: histBatch.uplineLines,
    });

    const flipAmt = (s) => (s.startsWith('-') ? s.slice(1) : `-${s}`);
    const corrAgLines = invertCorrectionSign
      ? corrBatch.agencyLines.map((l) => ({ ...l, amount: flipAmt(l.amount) }))
      : corrBatch.agencyLines;
    const corrUpLines = invertCorrectionSign
      ? corrBatch.uplineLines.map((l) => ({ ...l, amount: flipAmt(l.amount) }))
      : corrBatch.uplineLines;
    await env.commands.recordStatementBatch({
      dbToken: env.ownerToken,
      commandKey: 'corr-allagency-20260801',
      batchKind: 'method_correction',
      statementDate: '2026-08-01',
      reason: '2026-08-01 80/20 split reallocation on unreversed ALLAGENCY lines',
      agencyLines: corrAgLines,
      uplineLines: corrUpLines,
    });

    const standingId = (await env.pool.query('SELECT coherence.standing_input_version_as_of(NULL) AS id')).rows[0].id;
    const curEntries = (await env.pool.query(
      'SELECT rel_path, file_sha256 FROM coherence.input_entries WHERE input_version_id = $1::uuid',
      [standingId],
    )).rows;
    await env.commands.publishInputVersion({
      dbToken: env.ownerToken,
      commandKey: 'include-allagency-input',
      lineKind: 'standing',
      sourceKind: 'include',
      reason: 'Include pre-Coherence ALLAGENCY file',
      entries: [
        ...curEntries.map((e) => ({ relPath: e.rel_path, fileSha256: e.file_sha256 })),
        { relPath: 'Prior Statements/ALLAGENCY20260731Spark.csv', fileSha256: histStored.sha256 },
      ],
    });

    const launch = await env.commands.launchRun({
      dbToken: env.ownerToken,
      commandKey: 'launch-20260831',
      statementDate: '2026-08-31',
      origin: 'app',
      engineVersionId,
    });
    const runId = launch.result.runId;
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
    for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
    let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.saveReviewDecisions({
      dbToken: env.ownerToken,
      commandKey: 'bible-20260831',
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
      commandKey: 'adjust-20260831',
      expectedJournalSeq: seq,
      runId,
      surface: 'adjust',
      decisions: [{ recordId: 'carrier_a~direct~P10001~100.00~2026-11', disposition: 'CONFIRM' }],
    });
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.confirmEmit({
      dbToken: env.ownerToken,
      commandKey: 'confirm-20260831',
      expectedJournalSeq: seq,
      runId,
      adjustReviewSaveId: adjSave.result.reviewSaveId,
      typedPhrase: 'create statements for 2026-08-31',
    });
    assert.equal((await worker.runOnce()).action, 'step_finished');

    // Coherent Ledger holds exact 80/20 splits for the 3 surviving lines (POL201 was cancelled).
    const bobCsv = makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, [
      {
        external_policy_id: 'POL202', policy_id: '202', carrier_policy_number: 'POL202', crm_policy_number: '',
        enrollment_code: '', carrier: 'carriera', plan_type: 'MA', plan_name: 'MA', simple_plan_type: 'MA',
        mbi: '2CD3EF4GH56', member: 'Demo Lee', dob: '', phone: '', email: '', address: '', county: '', state: 'NC',
        submission_date: '2026-01-01', origin_effective: '2026-01-01', effective_date: '2026-01-01', termination_date: '',
        min_date: '2026-01-01', anchor_date: '2026-01-01', amount: '32.00', upline_amount: '8.00',
        writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon', agency_id: '', status: 'ACTIVE',
        conflicts: '', spine_source: 'tx', confidence_level: '1',
      },
      {
        external_policy_id: 'POL203', policy_id: '203', carrier_policy_number: 'POL203', crm_policy_number: '',
        enrollment_code: '', carrier: 'carriera', plan_type: 'MA', plan_name: 'MA', simple_plan_type: 'MA',
        mbi: '3EF4GH5JK67', member: 'Kim Test', dob: '', phone: '', email: '', address: '', county: '', state: 'NC',
        submission_date: '2026-01-01', origin_effective: '2026-01-01', effective_date: '2026-01-01', termination_date: '',
        min_date: '2026-01-01', anchor_date: '2026-01-01', amount: '-112.00', upline_amount: '-28.00',
        writing_npn: '22222222', writing_agent: 'Pat Rep', entity: 'Harbor', agency_id: '', status: 'ACTIVE',
        conflicts: '', spine_source: 'tx', confidence_level: '1',
      },
      {
        external_policy_id: 'POL204', policy_id: '204', carrier_policy_number: 'POL204', crm_policy_number: '',
        enrollment_code: '', carrier: 'carriera', plan_type: 'MA', plan_name: 'MA', simple_plan_type: 'MA',
        mbi: '4GH5JK6LM78', member: 'Max Sample', dob: '', phone: '', email: '', address: '', county: '', state: 'NC',
        submission_date: '2026-01-01', origin_effective: '2026-01-01', effective_date: '2026-01-01', termination_date: '',
        min_date: '2026-01-01', anchor_date: '2026-01-01', amount: '75.00', upline_amount: '0.00',
        writing_npn: '33333333', writing_agent: 'House Rep', entity: 'Acme', agency_id: '', status: 'ACTIVE',
        conflicts: '', spine_source: 'tx', confidence_level: '1',
      },
    ]);
    const ledgerCsv = makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, [
      {
        record_id: 'carriera~spark~2CD3EF4GH56~40.00~2026-07', external_policy_id: 'POL202', policy_id: '202', tx_id: '202',
        statement_name: 'ALLAGENCY20260731Spark.csv', src_type: 'spark', carrier: 'carriera', mbi: '2CD3EF4GH56', member: 'Demo Lee',
        state: 'NC', plan_type: 'MA', simple_plan_type: 'MA', submission_date: '2026-01-01', origin_effective: '2026-01-01',
        effective_date: '2026-01-01', termination_date: '', earned_date: '2026-07-01', payment_date: '2026-07-15',
        statement_date: '2026-07-31', min_date: '2026-01-01', gross_comm: '40.00', revenue_type: 'override',
        override_amount: '40.00', commission_amount: '', hra_amount: '', fee_amount: '', other_amount: '',
        downline_amount: '32.00', upline_amount: '8.00', writing_npn: '11111111', writing_agent: 'Sam Seller',
        entity: 'Beacon', payee_npn: '', agency_id: '', status: 'ACTIVE', policy_status: 'active',
        cbob_c: 'false', cbob_s: 'false', sf: 'false', notes: 'pos', coherent_notes: '',
      },
      {
        record_id: 'carriera~spark~3EF4GH5JK67~-140.00~2026-07', external_policy_id: 'POL203', policy_id: '203', tx_id: '203',
        statement_name: 'ALLAGENCY20260731Spark.csv', src_type: 'spark', carrier: 'carriera', mbi: '3EF4GH5JK67', member: 'Kim Test',
        state: 'NC', plan_type: 'MA', simple_plan_type: 'MA', submission_date: '2026-01-01', origin_effective: '2026-01-01',
        effective_date: '2026-01-01', termination_date: '', earned_date: '2026-07-01', payment_date: '2026-07-15',
        statement_date: '2026-07-31', min_date: '2026-01-01', gross_comm: '-140.00', revenue_type: 'override',
        override_amount: '-140.00', commission_amount: '', hra_amount: '', fee_amount: '', other_amount: '',
        downline_amount: '-112.00', upline_amount: '-28.00', writing_npn: '22222222', writing_agent: 'Pat Rep',
        entity: 'Harbor', payee_npn: '', agency_id: '', status: 'ACTIVE', policy_status: 'active',
        cbob_c: 'false', cbob_s: 'false', sf: 'false', notes: 'cb', coherent_notes: '',
      },
      {
        record_id: 'carriera~spark~4GH5JK6LM78~75.00~2026-07', external_policy_id: 'POL204', policy_id: '204', tx_id: '204',
        statement_name: 'ALLAGENCY20260731Spark.csv', src_type: 'spark', carrier: 'carriera', mbi: '4GH5JK6LM78', member: 'Max Sample',
        state: 'NC', plan_type: 'MA', simple_plan_type: 'MA', submission_date: '2026-01-01', origin_effective: '2026-01-01',
        effective_date: '2026-01-01', termination_date: '', earned_date: '2026-07-01', payment_date: '2026-07-15',
        statement_date: '2026-07-31', min_date: '2026-01-01', gross_comm: '75.00', revenue_type: 'override',
        override_amount: '75.00', commission_amount: '', hra_amount: '', fee_amount: '', other_amount: '',
        downline_amount: '75.00', upline_amount: '0.00', writing_npn: '33333333', writing_agent: 'House Rep',
        entity: 'Acme', payee_npn: '', agency_id: '', status: 'ACTIVE', policy_status: 'active',
        cbob_c: 'false', cbob_s: 'false', sf: 'false', notes: 'house', coherent_notes: '',
      },
    ]);
    const stmtCsv = makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, [{
      record_id: 'carriera~spark~1AB2CD3EF45~500.00~2026-07', external_policy_id: '', policy_id: '', tx_id: '',
      statement_name: 'ALLAGENCY20260731Spark.csv', src_type: 'spark', carrier: 'carriera', mbi: '1AB2CD3EF45', member: 'Pat Sample',
      state: 'NC', plan_type: 'MA', simple_plan_type: 'MA', submission_date: '', origin_effective: '',
      effective_date: '', termination_date: '', earned_date: '2026-07-01', payment_date: '2026-07-15',
      statement_date: '', min_date: '', gross_comm: '-500.00', revenue_type: 'override',
      override_amount: '-500.00', commission_amount: '', hra_amount: '', fee_amount: '', other_amount: '',
      downline_amount: '', upline_amount: '', writing_npn: '11111111', writing_agent: 'Sam Seller',
      entity: 'Beacon', payee_npn: '', agency_id: '', status: '', policy_status: '',
      cbob_c: 'false', cbob_s: 'false', sf: 'false', notes: 'rev', coherent_notes: 'CANCEL',
      run_action: 'CANCEL', run_statement_date: '2026-08-31',
      reversal_of: 'carriera~spark~1AB2CD3EF45~500.00~2026-07', reason: 'cancel reversed ALLAGENCY line',
    }]);

    const emitAttemptId = (await env.pool.query(
      "SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev",
      [runId],
    )).rows[0].ev;

    return {
      env,
      runId,
      materialize: () => env.commands.materializeEmit({
        dbToken: env.workerToken,
        commandKey: 'mat-20260831',
        runId,
        attemptEventId: emitAttemptId,
        statementDate: '2026-08-31',
        canonicalBobCsv: bobCsv,
        coherentLedgerCsv: ledgerCsv,
        statementsCsv: stmtCsv,
      }),
    };
  };

  // Correct direction (agency +20.00, upline -20.00) passes deferred conservation trigger with $0.00 variance
  const good = await runNegConservationCheck(false);
  await good.materialize();
  const recon = await queryRunEntityReconciliation(good.env.pool, good.runId);
  assert.ok(recon.every((r) => r.reconciled === true && r.variance === '0.00'));
  const byEnt = Object.fromEntries(recon.map((r) => [r.statement_entity, r.statement_total]));
  assert.deepEqual(byEnt, {
    Acme: '75.00',
    'Acme Upline': '-20.00',
    Beacon: '32.00',
    Harbor: '-112.00',
  });

  // Inverted direction (agency -20.00, upline +20.00) is rejected by PostgreSQL conservation trigger
  const bad = await runNegConservationCheck(true);
  await assert.rejects(() => bad.materialize(), /conservation violation/i);
});

test('Layer 4 [Plx ULTotal Per-File Rounding]: sums exact sub-cent ULTotal values and rounds once per statement file (ROUND_HALF_UP), keeps each line amount as Coherence shows it, preserves 8/1 split and all other totals, and passes PostgreSQL conservation', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({
    companySlug: 'acme',
    displayName: 'Acme',
  });
  t.after(() => env.cleanup());

  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const stmtDir = join(env.tempDir, 'subcent-stmts');
  const sentDir = join(env.tempDir, 'subcent-sent');

  const plxCols = 'Statement,WritingAgent,WritingAgentNPN,PolicyHolderName,MBI,State,Carrier,EffectiveDate,PlanType,SimplifiedCoverageType,PolicyNumber,CommissionAmount,Note,RevenueType,EarnedDate,PaymentDate,entity,DLTotal,ULTotal';
  const plxRow = (dt, pol, mbi, entity, dl, ul, gross, note) =>
    `${dt} - CarrierA,Sam Seller,11111111,Pat Sample,${mbi},NC,CarrierA,2026-01-01,MA,MA,${pol},${gross},${note},Commission,${dt},${dt},${entity},${dl},${ul}`;
  const allAgencyHdr = 'entity,npn,agent,member,mbi,policy_number,carrier,channel,amount,earned,payment,note,state,plan_type,coverage_type,effective,submitted';
  const sentHdr = 'record_id,entity,writing_npn,gross_comm,run_action,reversal_of,statement_name';

  // Three plx files with sub-cent ULTotal values where per-cell rounding differs from rounding once per file:
  // 1) plxSpark20260429.csv: 5 rows of ULTotal 20.005 -> exact sum 100.025 -> ROUND_HALF_UP = 100.03
  //    (per-cell ROUND_HALF_UP sums to 100.05; ROUND_HALF_EVEN would give 100.02; rounding diff = -0.02)
  // 2) plxSpark20260531.csv: 3 rows of 10.005 + 1 row of 10.006 -> exact sum 40.021 -> ROUND_HALF_UP = 40.02
  //    (per-cell ROUND_HALF_UP sums to 40.04; rounding diff = -0.02)
  // 3) plxSpark20260630.csv: 3 rows of 10.004 + 1 blank-DL row of 0.004 -> exact sum 30.016 -> ROUND_HALF_UP = 30.02
  //    (per-cell ROUND_HALF_UP sums to 30.00; rounding diff = +0.02)
  // Combined exact-per-file upline = 100.03 + 40.02 + 30.02 = 170.07 (take-back = -17007 cents),
  // whereas per-cell rounding gives 100.05 + 40.04 + 30.00 = 170.09 (take-back = -17009 cents).
  await writeTree(stmtDir, {
    'BEA20260325.csv': 'Statement,Carrier,Revenue Type,Commission Amount,Writing Agent NPN,Writing Agent,Policy Holder Name,MBI,Policy Number,Earned Date,Payment Date,Effective Date,Note,State,Plan Type,Simplified Coverage Type\n2026-03-06,CarrierA,Commission,$ 125.00,11111111,Sam Seller,Pat Sample,1AB2CD3EF45,POL1,2026-03-01,2026-03-06,2026-01-01,mar,NC,MA,MA\n',
    'plxSpark20260429.csv': [
      plxCols,
      plxRow('2026-04-15', 'P401', '1AB2CD3EF41', 'Beacon', '80.00', '20.005', '100.005', 'r1'),
      plxRow('2026-04-15', 'P402', '1AB2CD3EF42', 'Beacon', '80.00', '20.005', '100.005', 'r2'),
      plxRow('2026-04-15', 'P403', '1AB2CD3EF43', 'Beacon', '80.00', '20.005', '100.005', 'r3'),
      plxRow('2026-04-15', 'P404', '1AB2CD3EF44', 'Harbor', '80.00', '20.005', '100.005', 'r4'),
      plxRow('2026-04-15', 'P405', '1AB2CD3EF45', 'Harbor', '80.00', '20.005', '100.005', 'r5'),
    ].join('\n') + '\n',
    'plxSpark20260531.csv': [
      plxCols,
      plxRow('2026-05-15', 'P501', '2AB2CD3EF51', 'Beacon', '40.00', '10.005', '50.005', 'm1'),
      plxRow('2026-05-15', 'P502', '2AB2CD3EF52', 'Beacon', '40.00', '10.005', '50.005', 'm2'),
      plxRow('2026-05-15', 'P503', '2AB2CD3EF53', 'Harbor', '40.00', '10.005', '50.005', 'm3'),
      plxRow('2026-05-15', 'P504', '2AB2CD3EF54', 'Harbor', '40.00', '10.006', '50.006', 'm4'),
    ].join('\n') + '\n',
    'plxSpark20260630.csv': [
      plxCols,
      plxRow('2026-06-15', 'P601', '3AB2CD3EF61', 'Beacon', '40.00', '10.004', '50.004', 'j1'),
      plxRow('2026-06-15', 'P602', '3AB2CD3EF62', 'Beacon', '40.00', '10.004', '50.004', 'j2'),
      plxRow('2026-06-15', 'P603', '3AB2CD3EF63', 'Harbor', '40.00', '10.004', '50.004', 'j3'),
      // Sub-cent ULTotal that rounds to 0.00 on its own must still contribute to the file's exact ULTotal sum
      plxRow('2026-06-15', 'P604', '3AB2CD3EF64', 'Harbor', '', '0.004', '0.004', 'j4'),
    ].join('\n') + '\n',
    'ALLAGENCY20260731Spark.csv': [
      allAgencyHdr,
      'Beacon,11111111,Sam Seller,Pat Sample,4AB2CD3EF71,POL701,carriera,spark,200.00,2026-07-01,2026-07-15,rev,NC,MA,MA,2026-01-01,2026-01-01',
      'Beacon,11111111,Sam Seller,Lee Demo,4AB2CD3EF72,POL702,carriera,spark,100.00,2026-07-01,2026-07-15,pos,NC,MA,MA,2026-01-01,2026-01-01',
      'Harbor,22222222,Pat Rep,Kim Test,4AB2CD3EF73,POL703,carriera,spark,-40.00,2026-07-01,2026-07-15,cb,NC,MA,MA,2026-01-01,2026-01-01',
      'Acme,33333333,House Rep,Max Sample,4AB2CD3EF74,POL704,carriera,spark,50.00,2026-07-01,2026-07-15,house,NC,MA,MA,2026-01-01,2026-01-01',
    ].join('\n') + '\n',
  });
  await writeTree(sentDir, {
    'statements_20260831.csv': [
      sentHdr,
      'carriera~spark~4AB2CD3EF71~200.00~2026-07,Beacon,11111111,-200.00,REVERSAL,carriera~spark~4AB2CD3EF71~200.00~2026-07,ALLAGENCY20260731Spark.csv',
    ].join('\n') + '\n',
  });

  const corrections = [
    {
      kind: 'split_reallocation',
      statementDate: '2026-08-01',
      sourceGrammar: 'all_agency',
      unreversedOnly: true,
      useAgentsSplit: false,
      uplineRate: '0.20',
      excludeEntities: ['Acme'],
      // Surviving non-Acme: Beacon +100 -> -20/+20, Harbor -40 -> +8/-8 => agency -12.00, upline +12.00
      expectedAgencyNetCents: -1200,
      expectedUplineNetCents: 1200,
      reason: '2026-08-01 80/20 split correction',
    },
    {
      kind: 'upline_takeback',
      statementDate: '2026-08-31',
      sourceGrammar: 'plx_layout',
      expectedAgencyNetCents: 0,
      expectedUplineNetCents: -17007,
      reason: '2026-08-31 historical plx ULTotal take-back',
    },
  ];

  // Old per-cell rounded total (-17009 cents vs exact-per-file -17007 cents) must be rejected.
  await assert.rejects(
    () => readLegacyStatementBatches({ companyDisplayName: 'Acme',
      statementsDir: stmtDir,
      sentDir,
      methodCorrections: [
        corrections[0],
        { ...corrections[1], expectedUplineNetCents: -17009 },
      ],
      pythonPath: 'python3',
      coherenceRepo: mockRepo,
      tempBaseDir: env.tempDir,
    }),
    (err) => {
      assert.equal(err.code, 'LEGACY_STATEMENT_READ_FAILED');
      assert.ok(String(err.message).includes('-17009'), `expected -17009 in message, got: ${err.message}`);
      assert.ok(String(err.message).includes('-17007'), `expected -17007 in message, got: ${err.message}`);
      return true;
    },
  );

  const parsed = await readLegacyStatementBatches({ companyDisplayName: 'Acme',
    statementsDir: stmtDir,
    sentDir,
    methodCorrections: corrections,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    tempBaseDir: env.tempDir,
  });

  const byFile = Object.fromEntries(parsed.historicalBatches.map((b) => [b.sourceFileName, b]));

  // Verify every non-ULTotal batch and every agency total is completely unchanged
  assert.equal(byFile['BEA20260325.csv'].agencyNetTotal, '125.00');
  assert.equal(byFile['BEA20260325.csv'].uplineNetTotal, '0.00');
  assert.equal(byFile['plxSpark20260429.csv'].agencyNetTotal, '400.00');
  assert.equal(byFile['plxSpark20260531.csv'].agencyNetTotal, '160.00');
  assert.equal(byFile['plxSpark20260630.csv'].agencyNetTotal, '120.00');
  assert.equal(byFile['ALLAGENCY20260731Spark.csv'].agencyNetTotal, '310.00');
  assert.equal(byFile['ALLAGENCY20260731Spark.csv'].uplineNetTotal, '0.00');

  const isRoundingLine = (l) => l.srcType === 'rounding_adjustment';

  // Verify each plx file rounds exact ULTotal once (ROUND_HALF_UP) while keeping each row's own amount,
  // and marks rounding adjustments via typed fields (srcType / revenueType = 'rounding_adjustment'), never a FILE_ROUNDING name.
  assert.equal(byFile['plxSpark20260429.csv'].uplineNetTotal, '100.03');
  assert.deepEqual(
    byFile['plxSpark20260429.csv'].uplineLines.filter((l) => !isRoundingLine(l)).map((l) => l.amount),
    ['20.01', '20.01', '20.01', '20.01', '20.01'],
    'each row line must keep its own rounded-to-cent amount as Coherence shows it',
  );
  assert.deepEqual(
    byFile['plxSpark20260429.csv'].uplineLines.filter(isRoundingLine).map((l) => l.amount),
    ['-0.02'],
  );

  assert.equal(byFile['plxSpark20260531.csv'].uplineNetTotal, '40.02');
  assert.deepEqual(
    byFile['plxSpark20260531.csv'].uplineLines.filter((l) => !isRoundingLine(l)).map((l) => l.amount),
    ['10.01', '10.01', '10.01', '10.01'],
  );
  assert.deepEqual(
    byFile['plxSpark20260531.csv'].uplineLines.filter(isRoundingLine).map((l) => l.amount),
    ['-0.02'],
  );

  assert.equal(byFile['plxSpark20260630.csv'].uplineNetTotal, '30.02');
  assert.deepEqual(
    byFile['plxSpark20260630.csv'].uplineLines.filter((l) => !isRoundingLine(l)).map((l) => l.amount),
    ['10.00', '10.00', '10.00'],
  );
  assert.deepEqual(
    byFile['plxSpark20260630.csv'].uplineLines.filter(isRoundingLine).map((l) => l.amount),
    ['0.02'],
  );

  // Verify 8/1 split_reallocation is unchanged
  const splitBatch = parsed.methodCorrectionBatches[0];
  assert.equal(splitBatch.agencyNetTotal, '-12.00');
  assert.equal(splitBatch.uplineNetTotal, '12.00');
  assert.deepEqual(splitBatch.agencyLines.map((l) => [l.entity, l.amount]), [['Beacon', '-20.00'], ['Harbor', '8.00']]);
  assert.deepEqual(splitBatch.uplineLines.map((l) => [l.sourceEntity, l.amount]), [['Beacon', '20.00'], ['Harbor', '-8.00']]);

  // Verify 8/31 upline_takeback totals -170.07 while keeping each row's negated line amount
  const takebackBatch = parsed.methodCorrectionBatches[1];
  assert.equal(takebackBatch.agencyNetTotal, '0.00');
  assert.equal(takebackBatch.uplineNetTotal, '-170.07');
  assert.deepEqual(
    takebackBatch.uplineLines.filter((l) => !isRoundingLine(l)).map((l) => l.amount),
    ['-20.01', '-20.01', '-20.01', '-20.01', '-20.01', '-10.01', '-10.01', '-10.01', '-10.01', '-10.00', '-10.00', '-10.00'],
  );
  assert.deepEqual(
    takebackBatch.uplineLines.filter(isRoundingLine).map((l) => l.amount),
    ['0.02', '0.02', '-0.02'],
  );
  for (const b of [byFile['plxSpark20260429.csv'], byFile['plxSpark20260531.csv'], byFile['plxSpark20260630.csv'], takebackBatch]) {
    for (const l of b.uplineLines) {
      assert.notEqual(l.sourceEntity, 'FILE_ROUNDING', 'rounding lines must not rely on a FILE_ROUNDING entity name');
      if (isRoundingLine(l)) {
        assert.equal(l.revenueType, 'rounding_adjustment');
        assert.equal(l.sourceEntity, 'Acme', 'a rounding line on the upline statement comes from the company itself, never a made-up Upline');
      }
    }
  }

  // Verify negative half-cent tie (ROUND_HALF_UP away from zero) and per-file vs cross-file rounding
  const edgeDir = join(env.tempDir, 'subcent-edge');
  await writeTree(edgeDir, {
    // 5 rows of -10.005 -> exact -50.025 -> ROUND_HALF_UP = -50.03 (per-cell -50.05; HALF_EVEN -50.02)
    'plxSpark20260429.csv': [
      plxCols,
      plxRow('2026-04-15', 'N1', '5AB2CD3EF81', 'Beacon', '-40.00', '-10.005', '-50.005', 'n1'),
      plxRow('2026-04-15', 'N2', '5AB2CD3EF82', 'Beacon', '-40.00', '-10.005', '-50.005', 'n2'),
      plxRow('2026-04-15', 'N3', '5AB2CD3EF83', 'Beacon', '-40.00', '-10.005', '-50.005', 'n3'),
      plxRow('2026-04-15', 'N4', '5AB2CD3EF84', 'Beacon', '-40.00', '-10.005', '-50.005', 'n4'),
      plxRow('2026-04-15', 'N5', '5AB2CD3EF85', 'Beacon', '-40.00', '-10.005', '-50.005', 'n5'),
    ].join('\n') + '\n',
    // Two files each with exact sum 10.004 -> rounded once per statement file: 10.00 + 10.00 = 20.00
    // (NOT 20.01 as cross-file rounding of 20.008 would yield), with zero extra rounding lines
    'plxSpark20260531.csv': [
      plxCols,
      plxRow('2026-05-15', 'F1', '5AB2CD3EF86', 'Beacon', '40.00', '10.004', '50.004', 'f1'),
    ].join('\n') + '\n',
    'plxSpark20260630.csv': [
      plxCols,
      plxRow('2026-06-15', 'F2', '5AB2CD3EF87', 'Beacon', '40.00', '10.004', '50.004', 'f2'),
    ].join('\n') + '\n',
  });
  const edgeParsed = await readLegacyStatementBatches({ companyDisplayName: 'Acme',
    statementsDir: edgeDir,
    methodCorrections: [{
      kind: 'upline_takeback',
      statementDate: '2026-08-31',
      sourceGrammar: 'plx_layout',
      // -(-50.03 + 10.00 + 10.00) = +30.03 (+3003 cents)
      expectedAgencyNetCents: 0,
      expectedUplineNetCents: 3003,
      reason: 'negative half-cent tie and per-file rounding take-back',
    }],
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    tempBaseDir: env.tempDir,
  });
  const edgeByFile = Object.fromEntries(edgeParsed.historicalBatches.map((b) => [b.sourceFileName, b]));
  assert.equal(edgeByFile['plxSpark20260429.csv'].uplineNetTotal, '-50.03');
  assert.equal(edgeByFile['plxSpark20260531.csv'].uplineNetTotal, '10.00');
  assert.equal(edgeByFile['plxSpark20260531.csv'].uplineLineCount, 1, 'no rounding adjustment line when per-file rounded equals line sum');
  assert.equal(edgeByFile['plxSpark20260630.csv'].uplineNetTotal, '10.00');
  assert.equal(edgeByFile['plxSpark20260630.csv'].uplineLineCount, 1, 'no rounding adjustment line when per-file rounded equals line sum');
  assert.equal(edgeParsed.methodCorrectionBatches[0].uplineNetTotal, '30.03');

  // End-to-end PostgreSQL import: passes trg_statement_batches_verify_deferred, nets historical plx upline + 8/31 take-back
  // to $0.00 across both batch totals and per-record_id balances, and stays idempotent on re-import.
  const manifest = await buildImportManifest({
    companySlug: 'acme',
    displayName: 'Acme',
    sources: {
      preCoherenceStatementsDir: stmtDir,
      preCoherenceSentDir: sentDir,
      methodCorrections: corrections,
    },
  });
  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: env.tempDir,
  });
  assert.equal(rep.passed, true, rep.problems.join('; '));
  assert.equal(rep.preCoherenceBatchesImported, 5);
  assert.equal(rep.methodCorrectionBatchesImported, 2);

  // Verify every date's upline total in PostgreSQL matches exact-per-file rounded totals and cumulative upline equals 8/1 split (+12.00)
  const plxAppPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const uplineByDate = await withRequestTx(plxAppPool, env.ownerToken, async (tx) => (
    (await tx.query(
      `SELECT pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS dt, SUM(net_amount)::numeric(14,2)::text AS total
       FROM app_views.coherence_statement_date_totals
       WHERE account_kind = 'upline'
       GROUP BY statement_date
       ORDER BY statement_date ASC`,
    )).rows
  ), { readOnly: true });
  assert.deepEqual(uplineByDate, [
    { dt: '2026-04-29', total: '100.03' },
    { dt: '2026-05-31', total: '40.02' },
    { dt: '2026-06-30', total: '30.02' },
    { dt: '2026-08-01', total: '12.00' },
    { dt: '2026-08-31', total: '-170.07' },
  ]);

  // Verify every plx record_id (both row lines and per-file rounding adjustment lines) nets to exact 0.00 in statement_upline_lines
  const nonzeroPlxRecords = (await env.pool.query(
    `SELECT record_id, SUM(amount)::numeric(14,2)::text AS net
     FROM coherence.statement_upline_lines
     WHERE source_file LIKE 'plxSpark%'
     GROUP BY record_id
     HAVING SUM(amount) <> 0.00`,
  )).rows;
  assert.deepEqual(nonzeroPlxRecords, [], 'every plxSpark upline record_id (including rounding lines) must net to 0.00 after 8/31 take-back');

  // Verify cumulative entity totals across all batches
  const entTotals = await withRequestTx(plxAppPool, env.ownerToken, async (tx) => (
    (await tx.query(
      `SELECT statement_entity, SUM(net_amount)::numeric(14,2)::text AS total
       FROM app_views.coherence_statement_date_totals
       GROUP BY statement_entity
       ORDER BY statement_entity COLLATE "C"`,
    )).rows
  ), { readOnly: true });
  // Acme: 50.00 (7/31)
  // Acme Upline: 100.03 + 40.02 + 30.02 + 12.00 - 170.07 = 12.00
  // Beacon: 125 (3/25) + 240 (4/29) + 80 (5/31) + 80 (6/30) + 300 (7/31) - 20 (8/1) = 805.00
  // Harbor: 160 (4/29) + 80 (5/31) + 40 (6/30) - 40 (7/31) + 8 (8/1) = 248.00
  assert.deepEqual(entTotals, [
    { statement_entity: 'Acme', total: '50.00' },
    { statement_entity: 'Acme Upline', total: '12.00' },
    { statement_entity: 'Beacon', total: '805.00' },
    { statement_entity: 'Harbor', total: '248.00' },
  ]);

  // Verify idempotency on re-import
  const rep2 = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    recordCheck: false,
    tempBaseDir: env.tempDir,
  });
  assert.equal(rep2.preCoherenceBatchesImported, 0);
  assert.equal(rep2.methodCorrectionBatchesImported, 0);
  const tenantOrgId = (await env.pool.query('SELECT tenant_org_id FROM iam.database_context WHERE singleton = true')).rows[0].tenant_org_id;
  const roundingOwners = (await env.pool.query(
    "SELECT DISTINCT source_entity, organization_id FROM coherence.statement_upline_lines WHERE src_type = 'rounding_adjustment'",
  )).rows;
  assert.deepEqual(roundingOwners, [{ source_entity: 'Acme', organization_id: tenantOrgId }], 'every rounding line belongs to the company root');

  // Both sides of the bridge refuse to read without the company's name.
  for (const companyDisplayName of [undefined, '   ']) {
    await assert.rejects(
      () => readLegacyStatementBatches({ companyDisplayName, statementsDir: stmtDir, pythonPath: 'python3', coherenceRepo: mockRepo, tempBaseDir: env.tempDir }),
      (err) => err?.code === 'LEGACY_READER_CONFIG_REQUIRED' && /company display name/.test(err.message),
    );
  }
  const bareSpecDir = await mkdtemp(join(env.tempDir, 'bare-spec-'));
  await writeFile(join(bareSpecDir, 'spec.json'), JSON.stringify({ statementsDir: stmtDir, sentDir: null, agentsCsvPath: null, methodCorrections: [] }));
  await assert.rejects(
    () => execFileAsync('python3', [join(dirname(fileURLToPath(import.meta.url)), '..', 'python', 'coherence_legacy_statements.py'), '--spec', join(bareSpecDir, 'spec.json'), '--out', join(bareSpecDir, 'out.json')], {
      cwd: mockRepo,
      env: { ...process.env, PYTHONPATH: mockRepo, PYTHONDONTWRITEBYTECODE: '1' },
    }),
    (err) => /companyDisplayName/.test(String(err?.stderr || '')),
  );

  // Full PostgreSQL Emit conservation check (trg_run_materializations_verify_deferred + v_entity_statement_reconciliation)
  // proving that sub-cent plxSpark historical upline + 8/31 take-back (including rounding lines) tie out at $0.00 variance
  // both in aggregate and record-by-record.
  const envMat = await createTestEnv({
    companySlug: 'acme',
    displayName: 'Acme',
  });
  t.after(() => envMat.cleanup());
  const { engineVersionId } = await seedEngineVersion(envMat);
  await seedStandingInput(envMat, { commandKey: 'subcent-standing' });

  const matStmtDir = join(envMat.tempDir, 'mat-stmts');
  const matPlxCsv = [
    plxCols,
    plxRow('2026-04-15', 'P901', '9AB2CD3EF91', 'Beacon', '80.00', '20.005', '100.005', 'm1'),
    plxRow('2026-04-15', 'P902', '9AB2CD3EF92', 'Beacon', '80.00', '20.005', '100.005', 'm2'),
    plxRow('2026-04-15', 'P903', '9AB2CD3EF93', 'Beacon', '80.00', '20.005', '100.005', 'm3'),
    plxRow('2026-04-15', 'P904', '9AB2CD3EF94', 'Beacon', '80.00', '20.005', '100.005', 'm4'),
    plxRow('2026-04-15', 'P905', '9AB2CD3EF95', 'Beacon', '80.00', '20.005', '100.005', 'm5'),
  ].join('\n') + '\n';
  await writeTree(matStmtDir, { 'plxSpark20260429.csv': matPlxCsv });

  const matParsed = await readLegacyStatementBatches({ companyDisplayName: 'Acme',
    statementsDir: matStmtDir,
    methodCorrections: [{
      kind: 'upline_takeback',
      statementDate: '2026-08-31',
      sourceGrammar: 'plx_layout',
      expectedAgencyNetCents: 0,
      expectedUplineNetCents: -10003,
      reason: '2026-08-31 plx ULTotal take-back',
    }],
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    tempBaseDir: envMat.tempDir,
  });
  const matPlxStored = await envMat.dataStore.promoteBytes(Buffer.from(matPlxCsv, 'utf8'), {
    relPath: 'Prior Statements/plxSpark20260429.csv',
    checksPassed: true,
  });
  await envMat.commands.recordStatementBatch({
    dbToken: envMat.ownerToken,
    commandKey: 'hist-plx-20260429',
    batchKind: 'historical_sent',
    statementDate: '2026-04-29',
    sourceFileName: 'plxSpark20260429.csv',
    sourceFile: matPlxStored,
    reason: 'Imported 2026-04-29 plx statement',
    agencyLines: matParsed.historicalBatches[0].agencyLines,
    uplineLines: matParsed.historicalBatches[0].uplineLines,
  });
  await envMat.commands.recordStatementBatch({
    dbToken: envMat.ownerToken,
    commandKey: 'corr-plx-takeback-20260831',
    batchKind: 'method_correction',
    statementDate: '2026-08-31',
    reason: '2026-08-31 plx ULTotal take-back',
    agencyLines: matParsed.methodCorrectionBatches[0].agencyLines,
    uplineLines: matParsed.methodCorrectionBatches[0].uplineLines,
  });

  const standingId = (await envMat.pool.query('SELECT coherence.standing_input_version_as_of(NULL) AS id')).rows[0].id;
  const curEntries = (await envMat.pool.query(
    'SELECT rel_path, file_sha256 FROM coherence.input_entries WHERE input_version_id = $1::uuid',
    [standingId],
  )).rows;
  await envMat.commands.publishInputVersion({
    dbToken: envMat.ownerToken,
    commandKey: 'include-plx-input',
    lineKind: 'standing',
    sourceKind: 'include',
    reason: 'Include pre-Coherence plx file',
    entries: [
      ...curEntries.map((e) => ({ relPath: e.rel_path, fileSha256: e.file_sha256 })),
      { relPath: 'Prior Statements/plxSpark20260429.csv', fileSha256: matPlxStored.sha256 },
    ],
  });

  const launch = await envMat.commands.launchRun({
    dbToken: envMat.ownerToken,
    commandKey: 'launch-subcent-20260831',
    statementDate: '2026-08-31',
    origin: 'app',
    engineVersionId,
  });
  const runId = launch.result.runId;
  const worker = envMat.registerWorker(createEngineWorker({
    pool: envMat.pool,
    pgConfig: envMat.pgConfig,
    companySlug: envMat.companySlug,
    stores: envMat.stores,
    commands: envMat.commands,
    workerToken: envMat.workerToken,
    materializeEngine: createMockEngineMaterializer(),
    tempBaseDir: envMat.tempDir,
  }));
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  let seq = Number((await envMat.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await envMat.commands.saveReviewDecisions({
    dbToken: envMat.ownerToken,
    commandKey: 'bible-subcent-20260831',
    expectedJournalSeq: seq,
    runId,
    surface: 'bible',
    decisions: [
      { recordId: 'policy:carrier_a:P10001#effective:2026-01-01', disposition: 'CONFIRM' },
      { recordId: (await envMat.pool.query("SELECT record_id FROM coherence.review_queue_items WHERE run_id = $1::uuid AND surface = 'bible' AND item_order = 2", [runId])).rows[0].record_id, disposition: 'CONFIRM' },
    ],
  });
  assert.equal((await worker.runOnce()).action, 'step_finished');
  seq = Number((await envMat.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const adjSave = await envMat.commands.saveReviewDecisions({
    dbToken: envMat.ownerToken,
    commandKey: 'adjust-subcent-20260831',
    expectedJournalSeq: seq,
    runId,
    surface: 'adjust',
    decisions: [{ recordId: 'carrier_a~direct~P10001~100.00~2026-11', disposition: 'CONFIRM' }],
  });
  seq = Number((await envMat.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await envMat.commands.confirmEmit({
    dbToken: envMat.ownerToken,
    commandKey: 'confirm-subcent-20260831',
    expectedJournalSeq: seq,
    runId,
    adjustReviewSaveId: adjSave.result.reviewSaveId,
    typedPhrase: 'create statements for 2026-08-31',
  });
  assert.equal((await worker.runOnce()).action, 'step_finished');

  const bobCsv = makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, [{
    external_policy_id: 'P999', policy_id: '999', carrier_policy_number: 'P999', crm_policy_number: '',
    enrollment_code: '', carrier: 'carriera', plan_type: 'MA', plan_name: 'MA', simple_plan_type: 'MA',
    mbi: '9AB2CD3EF99', member: 'Pat Sample', dob: '', phone: '', email: '', address: '', county: '', state: 'NC',
    submission_date: '2026-01-01', origin_effective: '2026-01-01', effective_date: '2026-01-01', termination_date: '',
    min_date: '2026-01-01', anchor_date: '2026-01-01', amount: '400.00', upline_amount: '100.00',
    writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon', agency_id: '', status: 'ACTIVE',
    conflicts: '', spine_source: 'tx', confidence_level: '1',
  }]);
  const ledgerCsv = makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, [{
    record_id: 'carriera~spark~9AB2CD3EF99~500.00~2026-08', external_policy_id: 'P999', policy_id: '999', tx_id: '999',
    statement_name: 'statements_20260831.csv', src_type: 'spark', carrier: 'carriera', mbi: '9AB2CD3EF99', member: 'Pat Sample',
    state: 'NC', plan_type: 'MA', simple_plan_type: 'MA', submission_date: '2026-01-01', origin_effective: '2026-01-01',
    effective_date: '2026-01-01', termination_date: '', earned_date: '2026-08-01', payment_date: '2026-08-15',
    statement_date: '2026-08-31', min_date: '2026-01-01', gross_comm: '500.00', revenue_type: 'commission',
    override_amount: '', commission_amount: '500.00', hra_amount: '', fee_amount: '', other_amount: '',
    downline_amount: '400.00', upline_amount: '100.00', writing_npn: '11111111', writing_agent: 'Sam Seller',
    entity: 'Beacon', payee_npn: '', agency_id: '', status: 'ACTIVE', policy_status: 'active',
    cbob_c: 'false', cbob_s: 'false', sf: 'false', notes: 'rep', coherent_notes: '',
  }]);
  const cancelRows = matParsed.historicalBatches[0].agencyLines.map((al) => ({
    record_id: al.recordId, external_policy_id: al.externalPolicyId, policy_id: '', tx_id: '',
    statement_name: 'plxSpark20260429.csv', src_type: 'spark', carrier: 'carriera', mbi: al.mbi, member: al.member,
    state: 'NC', plan_type: 'MA', simple_plan_type: 'MA', submission_date: '', origin_effective: '',
    effective_date: '', termination_date: '', earned_date: '2026-04-15', payment_date: '2026-04-15',
    statement_date: '', min_date: '', gross_comm: '-80.00', revenue_type: 'commission',
    override_amount: '', commission_amount: '-80.00', hra_amount: '', fee_amount: '', other_amount: '',
    downline_amount: '-80.00', upline_amount: '0.00', writing_npn: '11111111', writing_agent: 'Sam Seller',
    entity: 'Beacon', payee_npn: '', agency_id: '', status: '', policy_status: '',
    cbob_c: 'false', cbob_s: 'false', sf: 'false', notes: 'cancel', coherent_notes: 'CANCEL',
    run_action: 'CANCEL', run_statement_date: '2026-08-31',
    reversal_of: al.recordId, reason: 'era cancel plxSpark row',
  }));
  const stmtCsv = makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, [
    ...cancelRows,
    {
      record_id: 'carriera~spark~9AB2CD3EF99~500.00~2026-08', external_policy_id: 'P999', policy_id: '999', tx_id: '999',
      statement_name: 'statements_20260831.csv', src_type: 'spark', carrier: 'carriera', mbi: '9AB2CD3EF99', member: 'Pat Sample',
      state: 'NC', plan_type: 'MA', simple_plan_type: 'MA', submission_date: '2026-01-01', origin_effective: '2026-01-01',
      effective_date: '2026-01-01', termination_date: '', earned_date: '2026-08-01', payment_date: '2026-08-15',
      statement_date: '2026-08-31', min_date: '2026-01-01', gross_comm: '500.00', revenue_type: 'commission',
      override_amount: '', commission_amount: '500.00', hra_amount: '', fee_amount: '', other_amount: '',
      downline_amount: '400.00', upline_amount: '100.00', writing_npn: '11111111', writing_agent: 'Sam Seller',
      entity: 'Beacon', payee_npn: '', agency_id: '', status: 'ACTIVE', policy_status: 'active',
      cbob_c: 'false', cbob_s: 'false', sf: 'false', notes: 'rep', coherent_notes: '',
      run_action: 'NEW', run_statement_date: '2026-08-31',
      reversal_of: '', reason: 'replacement ledger row',
    },
  ]);

  const subcentEmitEv = (await envMat.pool.query(
    "SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev",
    [runId],
  )).rows[0].ev;
  await envMat.commands.materializeEmit({
    dbToken: envMat.workerToken,
    commandKey: 'mat-subcent-20260831',
    runId,
    attemptEventId: subcentEmitEv,
    statementDate: '2026-08-31',
    canonicalBobCsv: bobCsv,
    coherentLedgerCsv: ledgerCsv,
    statementsCsv: stmtCsv,
  });

  const recon = await queryRunEntityReconciliation(envMat.pool, runId);
  assert.ok(recon.every((r) => r.reconciled === true && r.variance === '0.00'));
  assert.deepEqual(
    Object.fromEntries(recon.map((r) => [r.statement_entity, r.statement_total])),
    { 'Acme Upline': '100.00', Beacon: '400.00' },
  );

  // Verify app_views.coherence_statement_totals separates typed rounding_adjustment rows from statement (src_type, payment_month) rows,
  // and Layer 3 run-comparator line counts exclude synthetic rounding adjustments while keeping exact entity parity.
  const viewTotals = await withRequestTx(createRoleScopedTestPool(envMat.pool, 'platform_app'), envMat.ownerToken, async (tx) => (
    (await tx.query(
      `SELECT t.account_kind, t.src_type, t.payment_month, t.line_count::int AS line_count, t.net_amount::text AS net_amount
       FROM app_views.coherence_statement_totals t
       JOIN app_views.coherence_effective_statement_batches($1::uuid) eff ON eff.batch_id = t.batch_id
       WHERE t.src_type = 'rounding_adjustment'
       ORDER BY t.statement_date ASC`,
      [runId],
    )).rows
  ), { readOnly: true });
  assert.deepEqual(viewTotals, [
    { account_kind: 'upline', src_type: 'rounding_adjustment', payment_month: null, line_count: 1, net_amount: '-0.02' },
    { account_kind: 'upline', src_type: 'rounding_adjustment', payment_month: null, line_count: 1, net_amount: '0.02' },
  ]);

  const roPool = createRoleScopedTestPool(envMat.pool, 'platform_readonly');
  const cmpParity = await compareDbRuns({
    pool: roPool,
    stores: envMat.stores,
    leftRunId: runId,
    rightRunId: runId,
    mode: 'substance',
    expectedEntityParity: {
      datesChecked: 2,
      filesChecked: 4,
      totalLines: 22,
      ledgerGrossTotal: '500.00',
      perEntityTotals: { 'Acme Upline': '100.00', Beacon: '400.00' },
    },
    tempBaseDir: envMat.tempDir,
  });
  assert.equal(cmpParity.passed, true, `Layer 3 comparator parity as platform_readonly failed: ${cmpParity.problems.join('; ')}`);
  assert.equal(cmpParity.gates.gate4.entityStatements.dbReconciliation.totalLines, 22);
  assert.equal(cmpParity.gates.gate4.entityStatements.dbReconciliation.roundingAdjustmentLines, 2);
});

test('Layer 4 [Fix 3 - Consistent SQLite Snapshot & Sidecar Guard]: never reads live WAL DB directly, takes one consistent copy into temp dir, refuses -wal/-shm without consistent copy, and reads counts + all 8 tables from that one copy in one read transaction', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const { DatabaseSync } = await import('node:sqlite');
  const sqlitePath = join(env.tempDir, 'live-wal.sqlite');
  const liveDb = new DatabaseSync(sqlitePath);
  t.after(() => { try { liveDb.close(); } catch {} });

  liveDb.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE coherence_run_records (date TEXT, status TEXT);
    CREATE TABLE coherence_run_events (id INTEGER PRIMARY KEY, date TEXT, kind TEXT);
    CREATE TABLE coherence_run_drafts (date TEXT, surface TEXT, body TEXT);
    CREATE TABLE coherence_run_settings (key TEXT, value TEXT);
    CREATE TABLE company_run_records (company TEXT, date TEXT, status TEXT, sent_at TEXT);
    CREATE TABLE company_run_events (id INTEGER PRIMARY KEY, company TEXT, date TEXT, kind TEXT);
    CREATE TABLE company_run_drafts (company TEXT, date TEXT, surface TEXT, body TEXT);
    CREATE TABLE company_intake_events (id INTEGER PRIMARY KEY, company TEXT, kind TEXT);
    INSERT INTO coherence_run_records VALUES ('2026-11-02', 'done');
    INSERT INTO coherence_run_events VALUES (1, '2026-11-02', 'finished');
    INSERT INTO coherence_run_drafts VALUES ('2026-11-02', 'bible', '[]');
    INSERT INTO coherence_run_settings VALUES ('mode', 'coherence');
    INSERT INTO company_run_records VALUES ('acme', '2026-11-11', 'done', NULL);
    INSERT INTO company_run_events VALUES (10, 'acme', '2026-11-11', 'sent');
    INSERT INTO company_run_drafts VALUES ('acme', '2026-11-11', 'adjust', '[]');
    INSERT INTO company_intake_events VALUES (20, 'acme', 'upload');
  `);
  // Leave an active uncommitted transaction open while -wal and -shm exist on disk!
  liveDb.exec("BEGIN IMMEDIATE; INSERT INTO company_intake_events VALUES (999, 'acme', 'uncommitted');");

  // Direct read without consistent copy MUST refuse when -wal or -shm sidecar exists
  await assert.rejects(
    () => readLegacySqliteSnapshot(sqlitePath, {
      companySlug: 'acme',
      includeLegacySqliteTables: true,
      tempBaseDir: env.tempDir,
      takeConsistentCopy: false,
    }),
    (err) => err?.code === 'SQLITE_WAL_SIDECAR_PRESENT',
  );

  // Consistent copy succeeds even with live WAL + uncommitted writer, seeing committed rows only
  const manifest = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacySqlitePath: sqlitePath },
    importConfig: { includeLegacyHostHistory: true, includeLegacySqliteTables: true },
    tempBaseDir: env.tempDir,
  });
  assert.equal(manifest.sqliteCounts.company_intake_events, 1, 'must see committed WAL row and exclude uncommitted row');

  // Roll back uncommitted tx and commit a NEW row to the live DB AFTER manifest was built:
  // executeHistoryImport must reuse the single consistent snapshot so counts and rows stay 100% consistent!
  liveDb.exec("ROLLBACK; INSERT INTO company_intake_events VALUES (21, 'acme', 'later_live_write');");

  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest,
    verifyRebuild: false,
    tempBaseDir: env.tempDir,
  });
  assert.equal(rep.passed, true, `Import failed: ${rep.problems.join('; ')}`);
  assert.equal(rep.sqliteParity.source.company_intake_events, 1);
  assert.equal(rep.sqliteParity.imported.company_intake_events, 1);
});

test('Layer 4 [Fix 4 - Journal Rebuild Topological Ordering]: imported run with 10 chained checkpoints revising the same key in one journal entry rebuilds deterministically every time', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const cohRoot = join(env.tempDir, 'coh-fix4');
  const dataRoot = join(env.tempDir, 'data-fix4');

  const targetKey = 'policy:carrier_a:P900#effective:2026-01-01';
  const rows = [];
  for (let i = 0; i < 10; i++) {
    rows.push(sampleApprovalRow({
      record_id: targetKey,
      disposition: 'CORRECT',
      agency: i % 2 === 0 ? 'Beacon' : 'Harbor',
      note: `rev-${i}`,
      committed_at: `2026-11-15T10:${String(i).padStart(2, '0')}:00Z`,
    }));
  }

  // 10 timestamped saves starting from a pinned fresh root (10 commits + 10 approvals_files in ONE journal entry!)
  const save0Csv = makeOverlayCsv(rows.slice(0, 1), { version: 'v2' });
  await writeTree(join(cohRoot, 'runs', '2026-11-15'), {
    'input/a.csv': 'k\n1\n',
    'bible.csv': `record_id,case,subtype,amount\n${targetKey},BIBLE,CONFLICT,100.00\n`,
    'overlay.csv': makeOverlayCsv(rows, { version: 'v2' }),
    'run.json': JSON.stringify({
      date: '2026-11-15',
      steps: {
        assign: { at: '2026-11-15T09:50:00' },
        bible: { at: '2026-11-15T09:55:00' },
      },
    }),
  });
  const saveFiles = {};
  for (let i = 0; i < 10; i++) {
    saveFiles[`bible-review-2026-11-15T10-${String(i).padStart(2, '0')}-00-000Z.csv`] = makeOverlayCsv(rows.slice(0, i + 1), { version: 'v2' });
  }
  await writeTree(join(dataRoot, 'coherence-runs', '2026-11-15'), saveFiles);

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    coherenceRoot: cohRoot,
    nusearDataDir: dataRoot,
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-11-15', sha256: sha256Utf8(save0Csv) }],
    },
  });

  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: env.tempDir,
  });
  assert.equal(rep.passed, true, `Import failed: ${rep.problems.join('; ')}`);
  assert.equal(rep.importedRuns[0].decisionCommits, 10);
  assert.equal(rep.importedRuns[0].decisions, 10);

  const tipSeq = Number((await env.pool.query('SELECT MAX(seq)::bigint AS s FROM coherence.journal_entries')).rows[0].s);
  const ndjson = await exportJournalNdjson(env.pool);
  const emptyDb = await createEmptyMigratedTestDb();
  t.after(() => emptyDb.cleanup());

  const reb = await rebuildFromJournalExport(emptyDb.pool, ndjson);
  assert.equal(reb.replayed, tipSeq);

  const cmp = await compareDatabasesAsOf(env.pool, emptyDb.pool, tipSeq);
  assert.equal(cmp.passed, true, `Layer 4 rebuild comparison failed: ${cmp.problems.join('; ')}`);
});

test('Layer 4 [Fix 5 - Long Path Command Keys <= 200 chars]: 300-character paths in comparator checks and standalone overlay checkpoints hash safely below 200-char command_key limit', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);

  // Construct a real filesystem directory whose absolute path is > 300 characters (segments <= 60 chars each for POSIX NAME_MAX safety)
  const segs = Array.from({ length: 6 }, (_, i) => `segment_${i}_${'x'.repeat(45)}`);
  const longDir = join(env.tempDir, ...segs);
  assert.ok(longDir.length > 300, `expected > 300 char path, got ${longDir.length}`);

  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:P500#effective:2026-01-01', note: 'long-path' });
  const row1 = sampleApprovalRow({ record_id: 'policy:carrier_a:P501#effective:2026-01-01', note: 'long-path-cp' });
  const ovCsv = makeOverlayCsv([row0], { version: 'v2' });
  const cpCsv = makeOverlayCsv([row0, row1], { version: 'v2' });
  const longCheckpointPath = join(longDir, 'standalone_overlay_checkpoint.csv');
  const longRightRunDir = join(longDir, 'ref-run-2026-11-02');
  const runFiles = {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'emits/canonical_bob.csv': 'policy_id,member,entity,amount,upline_amount\n1,Pat Sample,Beacon,80.00,20.00\n',
    'emits/coherent_ledger.csv': 'tx_id,record_id,policy_id,member,entity,gross_comm,downline_amount,upline_amount\n1,r1,1,Pat Sample,Beacon,100.00,80.00,20.00\n',
    'run.json': JSON.stringify({ date: '2026-11-02', steps: { assign: { at: '2026-11-02T10:00:00' }, emit: { at: '2026-11-02T10:05:00' } } }),
  };
  await writeTree(longRightRunDir, runFiles);
  await writeTree(join(env.tempDir, 'runs', '2026-11-02'), runFiles);
  await writeFile(longCheckpointPath, cpCsv, 'utf8');
  assert.ok(longCheckpointPath.length > 300);
  assert.ok(longRightRunDir.length > 300);

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacyRunsRoot: join(env.tempDir, 'runs') },
    overlayCheckpoints: [{ absPath: longCheckpointPath, originalAt: '2026-11-03T10:00:00Z' }],
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-11-02', sha256: sha256Utf8(ovCsv) }],
    },
  });

  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: env.tempDir,
  });
  assert.equal(rep.passed, true, `Import failed: ${rep.problems.join('; ')}`);

  const runId = rep.importedRuns[0].runId;
  const cmpRep = await compareDbRuns({
    pool: env.pool,
    stores: env.stores,
    leftRunId: runId,
    rightFolderDir: longRightRunDir,
    mode: 'substance',
    requireConservation: true,
    commands: env.commands,
    dbToken: env.ownerToken,
    tempBaseDir: env.tempDir,
  });
  assert.equal(cmpRep.passed, true, `Comparator failed: ${cmpRep.problems.join('; ')}`);

  const keys = (await env.pool.query('SELECT command_key FROM coherence.journal_entries')).rows.map((r) => r.command_key);
  assert.ok(keys.length > 0);
  for (const k of keys) {
    assert.ok(k.length <= 200, `command_key exceeded 200 chars: ${k.length}`);
  }
});

test('Layer 4 [Fix 6 - Chronological Same-Date Runs & Merged Checkpoints]: orders same-date drafts/archives before primary by recorded start and merges manifest overlayCheckpoints by time so valid shorter prefixes always find their ancestor', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const runsRoot = join(env.tempDir, 'runs-fix6');
  const cpDir = join(env.tempDir, 'cps-fix6');

  const mkRow = (n) => sampleApprovalRow({
    record_id: `policy:carrier_a:P60${n}#effective:2026-01-01`,
    note: `step-${n}`,
    committed_at: `2026-10-1${n}T08:00:00Z`,
  });
  const rows = [mkRow(1), mkRow(2), mkRow(3), mkRow(4), mkRow(5), mkRow(6)];

  // Standalone checkpoints that belong BEFORE and BETWEEN runs chronologically
  const cpEarly = join(cpDir, 'cp-early.csv');
  const cpMid = join(cpDir, 'cp-mid.csv');
  const cpEarlyCsv = makeOverlayCsv(rows.slice(0, 1), { version: 'v2' });
  await mkdir(cpDir, { recursive: true });
  await writeFile(cpEarly, cpEarlyCsv, 'utf8');
  await writeFile(cpMid, makeOverlayCsv(rows.slice(0, 3), { version: 'v2' }), 'utf8');

  // Same-date 2026-10-12: archive/draft1 (started 08:00, 2 rows) must run BEFORE primary 2026-10-12 (started 10:00, 4 rows)
  // even though "2026-10-12" sorts before "archive/draft1/2026-10-12" lexicographically!
  await writeTree(join(runsRoot, 'archive', 'draft1', '2026-10-12'), {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': makeOverlayCsv(rows.slice(0, 2), { version: 'v2' }),
    'run.json': JSON.stringify({ date: '2026-10-12', steps: { assign: { at: '2026-10-12T08:00:00Z' }, bible: { at: '2026-10-12T08:05:00Z' } } }),
  });
  await writeTree(join(runsRoot, '2026-10-12'), {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': makeOverlayCsv(rows.slice(0, 4), { version: 'v2' }),
    'run.json': JSON.stringify({ date: '2026-10-12', steps: { assign: { at: '2026-10-12T10:00:00Z' }, bible: { at: '2026-10-12T10:05:00Z' } } }),
  });

  // Same-date 2026-10-14 without step timestamps: archive must still precede primary
  await writeTree(join(runsRoot, 'archive', 'nots', '2026-10-14'), {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': makeOverlayCsv(rows.slice(0, 5), { version: 'v2' }),
    'run.json': JSON.stringify({ date: '2026-10-14', steps: { assign: {}, bible: {} } }),
  });
  await writeTree(join(runsRoot, '2026-10-14'), {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': makeOverlayCsv(rows.slice(0, 6), { version: 'v2' }),
    'run.json': JSON.stringify({ date: '2026-10-14', steps: { assign: {}, bible: {} } }),
  });

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacyRunsRoot: runsRoot },
    overlayCheckpoints: [
      { label: 'mid-2026-10-12', absPath: cpMid, originalAt: '2026-10-12T09:00:00Z' },
      { label: 'early-2026-10-10', absPath: cpEarly, originalAt: '2026-10-10T09:00:00Z' },
    ],
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: 'overlay-checkpoints/early-2026-10-10', sha256: sha256Utf8(cpEarlyCsv) }],
    },
  });

  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: true,
    tempBaseDir: env.tempDir,
  });
  assert.equal(rep.passed, true, `Import failed: ${rep.problems.join('; ')}`);

  // Verify the single linear parent chain 1 -> 2 -> 3 -> 4 -> 5 -> 6 with zero disjoint roots
  const commits = (await env.pool.query(
    'SELECT id, parent_commit_id, cumulative_decision_count FROM coherence.decision_commits ORDER BY cumulative_decision_count ASC',
  )).rows;
  assert.deepEqual(commits.map((c) => Number(c.cumulative_decision_count)), [1, 2, 3, 4, 5, 6]);
  assert.equal(commits[0].parent_commit_id, null);
  for (let i = 1; i < commits.length; i++) {
    assert.equal(commits[i].parent_commit_id, commits[i - 1].id, `commit ${i + 1} must extend commit ${i}`);
  }
});

test('Layer 4 [Fix 7 & Note 3 - Standing Sent Idempotency & Missing Statements Problem]: re-importing with Sent/statements_<date>.csv already in standing input adds zero rows, and a declared sent record lacking a statements file is listed in problems', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const srcRoot = join(env.tempDir, 'src-fix7');
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:P700#effective:2026-01-01' });
  const ovCsv = makeOverlayCsv([row0], { version: 'v2' });
  const stmt1111 = 'record_id,entity,gross_comm,downline_amount,run_action\n';

  // Standing input ALREADY holds Sent/statements_20261111.csv!
  await writeTree(join(srcRoot, 'standing-input'), {
    'Agent Data/cleanagentdata.csv': 'agent_name,agent_npn,entity\nSam Seller,11111111,Beacon\n',
    'Overlay/overlay.csv': ovCsv,
    'Sent/statements_20261111.csv': stmt1111,
  });
  await writeTree(join(srcRoot, 'company-ws', '2026-11-11', 'runs', '2026-11-11'), {
    'input/Overlay/overlay.csv': ovCsv,
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'emits/statements_20261111.csv': stmt1111,
    'run.json': JSON.stringify({ date: '2026-11-11', steps: { assign: { at: '2026-11-11T10:00:00' }, emit: { at: '2026-11-11T10:05:00' } } }),
  });
  await writeTree(join(srcRoot, 'company-env'), {
    'audit.json': JSON.stringify({
      events: [{ id: 'evt-1111', action: 'record_sent', statementDate: '2026-11-11', at: '2026-11-11T15:00:00Z' }],
    }),
  });

  await env.commands.recordDecisionBaseline({
    dbToken: env.ownerToken,
    commandKey: 'seed-fix7-baseline',
    commitKind: 'historical_baseline',
    headerContract: 'v2',
    imported: true,
    decisions: [row0],
  });

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      standingInputDir: join(srcRoot, 'standing-input'),
      companyWorkspacesDir: join(srcRoot, 'company-ws'),
      companyEnvironmentDir: join(srcRoot, 'company-env'),
    },
    importConfig: { includeLegacyHostHistory: false, useCompanyIncomingInput: false, currentInputSourceKind: 'company_import' },
  });

  const rep1 = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, dbToken: env.ownerToken,
    manifest, pythonPath: 'python3', coherenceRepo: mockRepo, verifyRebuild: true, tempBaseDir: env.tempDir,
  });
  assert.equal(rep1.passed, true, `First import failed: ${rep1.problems.join('; ')}`);
  assert.equal(rep1.standingInputRebuildCheck.passed, true);

  const snapCounts = async () => {
    const out = {};
    for (const tbl of ['runs', 'stored_files', 'decision_commits', 'decisions', 'generated_overlays', 'input_versions', 'imported_files', 'carries']) {
      out[tbl] = Number((await env.pool.query(`SELECT COUNT(*)::int AS n FROM coherence.${tbl}`)).rows[0].n);
    }
    return out;
  };
  const before = await snapCounts();

  // Second import with Sent/statements_20261111.csv present MUST add zero rows and pass rebuild!
  const rep2 = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, dbToken: env.ownerToken,
    manifest, pythonPath: 'python3', coherenceRepo: mockRepo, verifyRebuild: true, recordCheck: false, tempBaseDir: env.tempDir,
  });
  const after = await snapCounts();
  assert.equal(rep2.passed, true, `Second import failed: ${rep2.problems.join('; ')}`);
  assert.equal(rep2.standingInputRebuildCheck.passed, true);
  assert.deepEqual(after, before, 're-importing with Sent/statements_<date>.csv present must add zero rows');

  // Item 6: historical company_import run without audit.json whose emits/statements_<date>.csv matches
  // standing Sent/statements_<date>.csv byte-for-byte MUST still receive a sent carry in coherence.carries!
  const envStandingSent = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => envStandingSent.cleanup());
  const ssRoot = join(envStandingSent.tempDir, 'src-standing-sent');
  await writeTree(join(ssRoot, 'company-ws', '2026-11-11', 'runs', '2026-11-11'), {
    'input/Overlay/overlay.csv': ovCsv,
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'run.json': JSON.stringify({ date: '2026-11-11', steps: { assign: { at: '2026-11-11T10:00:00' }, emit: { at: '2026-11-11T10:05:00' } } }),
    'emits/statements_20261111.csv': stmt1111,
  });
  await writeTree(join(ssRoot, 'standing-input'), {
    'Carrier/c.csv': 'k\n1\n',
    'Overlay/overlay.csv': ovCsv,
    'Sent/statements_20261111.csv': stmt1111,
  });
  await envStandingSent.commands.recordDecisionBaseline({
    dbToken: envStandingSent.ownerToken,
    commandKey: 'seed-standing-sent-baseline',
    commitKind: 'historical_baseline',
    headerContract: 'v2',
    imported: true,
    decisions: [row0],
  });
  const ssManifest = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      standingInputDir: join(ssRoot, 'standing-input'),
      companyWorkspacesDir: join(ssRoot, 'company-ws'),
    },
    importConfig: { includeLegacyHostHistory: false, useCompanyIncomingInput: false, currentInputSourceKind: 'company_import' },
  });
  const ssRep = await executeHistoryImport({
    pool: envStandingSent.pool, stores: envStandingSent.stores, commands: envStandingSent.commands, dbToken: envStandingSent.ownerToken,
    manifest: ssManifest, pythonPath: 'python3', coherenceRepo: mockRepo, verifyRebuild: true, tempBaseDir: envStandingSent.tempDir,
  });
  assert.equal(ssRep.passed, true, `Standing Sent import failed: ${ssRep.problems.join('; ')}`);
  const ssCarries = (await envStandingSent.pool.query(
    "SELECT carry_kind, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS dt FROM coherence.carries WHERE carry_kind = 'sent'",
  )).rows;
  assert.deepEqual(ssCarries, [{ carry_kind: 'sent', dt: '2026-11-11' }], 'importer must record a sent carry for historical sent run matching standing Sent/statements_<date>.csv');

  // Fix round 2 (C4): two non-abandoned company runs matching the same date's standing Sent file
  // without explicit provenance must NEVER queue two sent carries and must report a problem!
  const envDupSent = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => envDupSent.cleanup());
  const dupRoot = join(envDupSent.tempDir, 'src-dup-standing-sent');
  await writeTree(join(dupRoot, 'company-ws', '2026-11-11', 'runs', '2026-11-11'), {
    'input/Overlay/overlay.csv': ovCsv,
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'run.json': JSON.stringify({ date: '2026-11-11', steps: { assign: { at: '2026-11-11T09:00:00' }, emit: { at: '2026-11-11T09:05:00' } } }),
    'emits/statements_20261111.csv': stmt1111,
  });
  await writeTree(join(dupRoot, 'company-ws', '2026-11-11-alt', 'runs', '2026-11-11'), {
    'input/Overlay/overlay.csv': ovCsv,
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'run.json': JSON.stringify({ date: '2026-11-11', steps: { assign: { at: '2026-11-11T10:00:00' }, emit: { at: '2026-11-11T10:05:00' } } }),
    'emits/statements_20261111.csv': stmt1111,
  });
  await writeTree(join(dupRoot, 'standing-input'), {
    'Carrier/c.csv': 'k\n1\n',
    'Overlay/overlay.csv': ovCsv,
    'Sent/statements_20261111.csv': stmt1111,
  });
  await envDupSent.commands.recordDecisionBaseline({
    dbToken: envDupSent.ownerToken,
    commandKey: 'seed-dup-sent-baseline',
    commitKind: 'historical_baseline',
    headerContract: 'v2',
    imported: true,
    decisions: [row0],
  });
  const dupManifest = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      standingInputDir: join(dupRoot, 'standing-input'),
      companyWorkspacesDir: join(dupRoot, 'company-ws'),
    },
    importConfig: { includeLegacyHostHistory: false, useCompanyIncomingInput: false, currentInputSourceKind: 'company_import' },
  });
  dupManifest.companyRuns.push({
    origin: 'company_import',
    statementDate: '2026-11-11',
    sourceFolder: 'company-workspaces/acme/2026-11-11-alt/runs/2026-11-11',
    absPath: join(dupRoot, 'company-ws', '2026-11-11-alt', 'runs', '2026-11-11'),
    abandoned: false,
  });
  const dupRep = await executeHistoryImport({
    pool: envDupSent.pool, stores: envDupSent.stores, commands: envDupSent.commands, dbToken: envDupSent.ownerToken,
    manifest: dupManifest, pythonPath: 'python3', coherenceRepo: mockRepo, verifyRebuild: false, tempBaseDir: envDupSent.tempDir,
  });
  assert.equal(dupRep.passed, false, 'two non-abandoned runs matching one Sent file without explicit provenance must report a problem');
  assert.ok(
    dupRep.problems.some((p) => /multiple non-abandoned runs/i.test(p) && /2026-11-11/.test(p)),
    `expected ambiguity problem for 2026-11-11, got: ${JSON.stringify(dupRep.problems)}`,
  );
  const dupCarries = (await envDupSent.pool.query(
    "SELECT id FROM coherence.carries WHERE carry_kind = 'sent' AND statement_date = '2026-11-11'::date",
  )).rows;
  assert.equal(dupCarries.length, 0, 'ambiguous sent runs must queue zero sent carries');

  // Note 3: declared sent record whose company run has no statements file must be listed in problems
  const envMissing = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => envMissing.cleanup());
  const missRoot = join(envMissing.tempDir, 'src-missing-stmt');
  await writeTree(join(missRoot, 'company-ws', '2026-11-11', 'runs', '2026-11-11'), {
    'input/Overlay/overlay.csv': ovCsv,
    'overlay.csv': ovCsv,
    'run.json': JSON.stringify({ date: '2026-11-11', steps: { assign: { at: '2026-11-11T10:00:00' }, emit: { at: '2026-11-11T10:05:00' } } }),
  });
  await writeTree(join(missRoot, 'company-env'), {
    'audit.json': JSON.stringify({
      events: [{ id: 'evt-1111', action: 'record_sent', statementDate: '2026-11-11', at: '2026-11-11T15:00:00Z' }],
    }),
  });
  await envMissing.commands.recordDecisionBaseline({
    dbToken: envMissing.ownerToken,
    commandKey: 'seed-fix7-missing-baseline',
    commitKind: 'historical_baseline',
    headerContract: 'v2',
    imported: true,
    decisions: [row0],
  });
  const missManifest = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      companyWorkspacesDir: join(missRoot, 'company-ws'),
      companyEnvironmentDir: join(missRoot, 'company-env'),
    },
    importConfig: { includeLegacyHostHistory: false },
  });
  const missRep = await executeHistoryImport({
    pool: envMissing.pool, stores: envMissing.stores, commands: envMissing.commands, dbToken: envMissing.ownerToken,
    manifest: missManifest, pythonPath: 'python3', coherenceRepo: mockRepo, verifyRebuild: false, tempBaseDir: envMissing.tempDir,
  });
  assert.equal(missRep.passed, false);
  assert.ok(
    missRep.problems.some((p) => p.includes('2026-11-11') && /statements/i.test(p)),
    `expected missing statements problem for 2026-11-11, got: ${JSON.stringify(missRep.problems)}`,
  );
});

test('Layer 4 [Fix 8 & Note 1 - Blank committed_at on Imported Rows & Zero-Checkpoint Layer 2 Guard]: imported rows with blank committed_at generate blank (no decided_at fallback) and verifyOverlayReconstruction fails on zero checkpoints for a populated import', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  // Unit check: imported row with null committed_at_raw stays blank; live row still uses decided_at
  const impFmt = formatOverlayCsvFromRows([{
    record_id: 'policy:carrier_a:P800#effective:2026-01-01',
    disposition: 'CONFIRM',
    decided_at: '2026-11-20T10:00:00.000000Z',
    committed_at_raw: null,
    imported: true,
  }], { headerContract: 'v2' });
  assert.equal(impFmt.rows[0].committed_at, null, 'imported row with blank committed_at must stay blank');

  const liveFmt = formatOverlayCsvFromRows([{
    record_id: 'policy:carrier_a:P801#effective:2026-01-01',
    disposition: 'CONFIRM',
    decided_at: '2026-11-20T10:00:00.000000Z',
    committed_at_raw: null,
    imported: false,
  }], { headerContract: 'v2' });
  assert.equal(liveFmt.rows[0].committed_at, '2026-11-20T10:00:00.000000Z', 'live row still uses decided_at');

  // End-to-end Layer 2 reconstruction with blank committed_at on an imported run
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);

  const blankCommittedRow = sampleApprovalRow({
    record_id: 'policy:carrier_a:P802#effective:2026-01-01',
    disposition: 'CORRECT',
    agency: 'Beacon',
    committed_at: null,
    note: 'legacy blank committed_at',
  });
  const blankCsv = makeOverlayCsv([blankCommittedRow], { version: 'v2' });
  await writeTree(join(env.tempDir, 'runs', '2026-11-16'), {
    'input/a.csv': 'k\n1\n',
    'bible.csv': 'record_id,case,subtype,amount\npolicy:carrier_a:P802#effective:2026-01-01,BIBLE,CONFLICT,100.00\n',
    'overlay.csv': blankCsv,
    'run.json': JSON.stringify({ date: '2026-11-16', steps: { assign: { at: '2026-11-16T10:00:00' }, bible: { at: '2026-11-16T10:01:00' } } }),
  });

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacyRunsRoot: join(env.tempDir, 'runs') },
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-11-16', sha256: sha256Utf8(blankCsv) }],
    },
  });
  const rep = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, dbToken: env.ownerToken,
    manifest, pythonPath: 'python3', coherenceRepo: mockRepo, verifyRebuild: false, tempBaseDir: env.tempDir,
  });
  assert.equal(rep.passed, true, rep.problems.join('; '));

  const gen = await generateOverlayCsv(env.pool, { runId: rep.importedRuns[0].runId });
  assert.equal(gen.rows[0].committed_at, null, 'generated overlay for imported row must keep committed_at blank');

  const l2 = await verifyOverlayReconstruction({
    pool: env.pool, stores: env.stores, commands: env.commands, dbToken: env.ownerToken,
    pythonPath: 'python3', coherenceRepo: mockRepo, tempBaseDir: env.tempDir,
  });
  assert.equal(l2.passed, true, `Layer 2 failed on blank committed_at: ${l2.problems.join('; ')}`);
  assert.equal(l2.checkpointsChecked, 1);

  // Note 1: verifyOverlayReconstruction fails when zero checkpoints were checked on a populated import
  const envEmptyOv = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => envEmptyOv.cleanup());
  await writeTree(join(envEmptyOv.tempDir, 'runs-no-ov', '2026-11-18'), {
    'input/a.csv': 'k\n1\n',
    'run.json': JSON.stringify({ date: '2026-11-18', steps: { assign: { at: '2026-11-18T10:00:00' } } }),
  });
  const noOvManifest = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacyRunsRoot: join(envEmptyOv.tempDir, 'runs-no-ov') },
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
  });
  const noOvRep = await executeHistoryImport({
    pool: envEmptyOv.pool, stores: envEmptyOv.stores, commands: envEmptyOv.commands, dbToken: envEmptyOv.ownerToken,
    manifest: noOvManifest, pythonPath: 'python3', coherenceRepo: mockRepo, verifyRebuild: false, tempBaseDir: envEmptyOv.tempDir,
  });
  assert.equal(noOvRep.passed, true);

  const l2Zero = await verifyOverlayReconstruction({
    pool: envEmptyOv.pool, stores: envEmptyOv.stores,
    pythonPath: 'python3', coherenceRepo: mockRepo, tempBaseDir: envEmptyOv.tempDir,
  });
  assert.equal(l2Zero.checkpointsChecked, 0);
  assert.equal(l2Zero.passed, false, 'verifyOverlayReconstruction must fail when zero checkpoints were checked on a populated import');
  assert.ok(l2Zero.problems.some((p) => /zero checkpoints/i.test(p)));
});

test('Layer 4 [Fix 9 - Abandoned Imported Company Runs & Partly Finished Run Rebuild]: abandoned company runs are abandoned in PG (never published, never carried, invisible through entity views), post-import abandonment of normal imports remains refused, and every file of partly finished or zero-step abandoned runs rebuilds byte for byte', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const srcRoot = join(env.tempDir, 'src-fix9');
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:P900#effective:2026-01-01' });
  const ovCsv = makeOverlayCsv([row0], { version: 'v2' });
  const bobCsv = 'policy_id,member,entity,amount,upline_amount\n1,Pat Sample,Beacon,80.00,20.00\n';
  const ledCsv = 'tx_id,record_id,policy_id,src_type,member,entity,gross_comm,commission_amount,downline_amount,upline_amount\n1,r1,1,direct,Pat Sample,Beacon,100.00,100.00,80.00,20.00\n';
  const stmtCsv = 'record_id,entity,gross_comm,downline_amount,upline_amount,run_action\nr1,Beacon,100.00,80.00,20.00,NEW\n';

  // 1) Non-abandoned company run (2026-11-11)
  await writeTree(join(srcRoot, 'company-ws', '2026-11-11', 'runs', '2026-11-11'), {
    'input/Overlay/overlay.csv': ovCsv,
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'emits/statements_20261111.csv': stmtCsv,
    'run.json': JSON.stringify({ date: '2026-11-11', steps: { assign: { at: '2026-11-11T10:00:00' }, emit: { at: '2026-11-11T10:05:00' } } }),
  });

  // 2) Finished abandoned company run with a LATER date (2026-11-15)
  await writeTree(join(srcRoot, 'company-abandoned', '2026-11-15'), {
    'input/Overlay/overlay.csv': ovCsv,
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'emits/canonical_bob.csv': bobCsv,
    'emits/coherent_ledger.csv': ledCsv,
    'emits/statements_20261115.csv': stmtCsv,
    'run.json': JSON.stringify({ date: '2026-11-15', steps: { assign: { at: '2026-11-15T10:00:00' }, emit: { at: '2026-11-15T10:05:00' } } }),
  });

  // 3) Partly finished abandoned company run (only assign finished, yet bible.csv, adjust.csv, emits/partial.csv, partial viewer.html exist!)
  await writeTree(join(srcRoot, 'company-abandoned', '2026-11-13'), {
    'input/Overlay/overlay.csv': ovCsv,
    'working/tx.csv': 'id\n1\n',
    'bible.csv': 'record_id,case\npolicy:carrier_a:P900#effective:2026-01-01,BIBLE\n',
    'adjust.csv': 'record_id,case\nr1,NEW\n',
    'emits/partial_draft.csv': 'x\n1\n',
    'emits/partial_viewer.html': '<!doctype html><html><body>partial</body></html>',
    'notes.txt': 'stopped mid-run\n',
    'run.json': JSON.stringify({ date: '2026-11-13', steps: { assign: { at: '2026-11-13T10:00:00' } } }),
  });

  // 4) Zero-steps-finished abandoned company run (run.json steps: {} with partial working file & crash log!)
  await writeTree(join(srcRoot, 'company-abandoned', '2026-11-14'), {
    'input/a.csv': 'k\n1\n',
    'working/partial.csv': 'id\n9\n',
    'crash.log': 'interrupted during assign\n',
    'run.json': JSON.stringify({ date: '2026-11-14', steps: {} }),
  });

  await env.commands.recordDecisionBaseline({
    dbToken: env.ownerToken,
    commandKey: 'seed-fix9-baseline',
    commitKind: 'historical_baseline',
    headerContract: 'v2',
    imported: true,
    decisions: [row0],
  });

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      companyWorkspacesDir: join(srcRoot, 'company-ws'),
      companyAbandonedDir: join(srcRoot, 'company-abandoned'),
    },
    importConfig: { includeLegacyHostHistory: false },
  });

  const rep = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, dbToken: env.ownerToken,
    manifest, pythonPath: 'python3', coherenceRepo: mockRepo, verifyRebuild: true, tempBaseDir: env.tempDir,
  });
  assert.equal(rep.passed, true, `Import/rebuild failed: ${rep.problems.join('; ')}`);
  assert.equal(rep.rebuildChecks.length, 4);
  for (const chk of rep.rebuildChecks) {
    assert.equal(chk.passed, true, `Layer 1 rebuild failed for ${chk.sourceFolder}: ${JSON.stringify(chk)}`);
  }

  const runByDate = new Map(rep.importedRuns.map((r) => [r.statementDate, r.runId]));
  const live1111 = runByDate.get('2026-11-11');
  const ab1113 = runByDate.get('2026-11-13');
  const ab1114 = runByDate.get('2026-11-14');
  const ab1115 = runByDate.get('2026-11-15');

  // Every abandoned company run must have a row in coherence.abandonments and stage = 'abandoned'
  for (const abId of [ab1113, ab1114, ab1115]) {
    const abRow = (await env.pool.query('SELECT id FROM coherence.abandonments WHERE run_id = $1::uuid', [abId])).rows;
    assert.equal(abRow.length, 1, `abandoned run ${abId} must have a row in coherence.abandonments`);
    const stage = (await env.pool.query('SELECT coherence.run_stage($1::uuid) AS st', [abId])).rows[0].st;
    assert.equal(stage, 'abandoned');
  }

  // Never published: findLatestPublishedRun skips 2026-11-15 and returns 2026-11-11; abandoned run is absent from app_views.coherence_published_runs!
  const iamFix9 = env.iam;
  const appPoolFix9 = createRoleScopedTestPool(env.pool, 'platform_app');
  const latestPub = await findLatestPublishedRun(appPoolFix9, iamFix9.tokens.entityMgr);
  assert.equal(latestPub.id, live1111);
  const abEmitEv = (await env.pool.query(
    "SELECT id FROM coherence.step_attempt_events WHERE run_id = $1::uuid AND step = 'emit' AND event_kind = 'finished'",
    [ab1115],
  )).rows[0].id;
  const pubMatches = await withRequestTx(appPoolFix9, env.ownerToken, async (tx) => (
    (await tx.query('SELECT id FROM app_views.coherence_published_runs WHERE id = $1::uuid OR emit_attempt_event_id = $2::uuid', [ab1115, abEmitEv])).rows
  ), { readOnly: true });
  assert.equal(pubMatches.length, 0, 'abandoned imported company run emit attempt must never be published');

  // Never carried: carrySent on abandoned imported company run is refused by PostgreSQL
  await env.commands.publishInputVersion({
    dbToken: env.ownerToken, commandKey: 'seed-standing-fix9', lineKind: 'standing', sourceKind: 'company_import',
    reason: 'base', entries: [], storedFiles: [],
  });
  await assert.rejects(
    () => env.commands.carrySent({
      dbToken: env.ownerToken, commandKey: 'carry-abandoned-1115', runId: ab1115, typedPhrase: 'sent 2026-11-15',
    }),
    /abandoned/i,
  );

  // Materialize abandoned run before NDJSON rebuild so rebuild comparison verifies identical pre-backfill rows
  await env.commands.materializeEmit({
    dbToken: env.workerToken,
    commandKey: 'mat-abandoned-1115',
    runId: ab1115,
    attemptEventId: abEmitEv,
    statementDate: '2026-11-15',
    canonicalBobCsv: bobCsv,
    coherentLedgerCsv: ledCsv,
    statementsCsv: stmtCsv,
  });

  // Non-abandoned imported runs still cannot be abandoned after import
  await assert.rejects(
    () => env.commands.abandonRun({
      dbToken: env.ownerToken, commandKey: 'abandon-live-import-1111', runId: live1111, typedPhrase: 'abandon 2026-11-11', reason: 'not allowed',
    }),
    /imported historical runs cannot be abandoned/i,
  );

  // Layer 4 NDJSON export + rebuild reproduces all runs, abandonments, and partial run files
  const tipSeq = Number((await env.pool.query('SELECT MAX(seq)::bigint AS s FROM coherence.journal_entries')).rows[0].s);
  const ndjson = await exportJournalNdjson(env.pool);
  const emptyDb = await createEmptyMigratedTestDb();
  t.after(() => emptyDb.cleanup());
  await rebuildFromJournalExport(emptyDb.pool, ndjson);
  const cmp = await compareDatabasesAsOf(env.pool, emptyDb.pool, tipSeq);
  assert.equal(cmp.passed, true, `Layer 4 rebuild failed for abandoned runs: ${cmp.problems.join('; ')}`);

  // Never visible through app_views.*: even when materialized and FK-backfilled, platform_app Entity Manager sees 0 rows for abandoned run
  await env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys()');
  await withRequestTx(appPoolFix9, iamFix9.tokens.entityMgr, async (tx) => {
    const emBob = (await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE run_id = $1::uuid', [ab1115])).rows[0].n;
    const emLines = (await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_entity_statement_lines')).rows[0].n;
    assert.equal(emBob, 0, 'abandoned company run must be invisible in app_views.coherence_bob');
    assert.equal(emLines, 0, 'abandoned company run must be invisible in app_views.coherence_entity_statement_lines');
  }, { readOnly: true });
});

test('Layer 4 [Substance Comparator PHI-Free & Parameterized Columns]: planted name, MBI, address, phone, and record_id in differing cells never appear in report', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'coherence-phi-cmp-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const left = join(dir, 'left');
  const right = join(dir, 'right');
  const planted = {
    name: 'Zelda Q. Plantedname',
    mbi: '1EG4-TE5-MK72',
    address: '742 Evergreen Terrace',
    phone: '555-867-5309',
    recordId: 'carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11',
  };
  await writeTree(left, {
    'input/a.csv': 'k\n1\n',
    'emits/canonical_bob.csv': `policy_id,member,mbi,address,phone,entity,amount\n1,${planted.name},${planted.mbi},${planted.address},${planted.phone},Beacon,100.00\n`,
    'emits/coherent_ledger.csv': `tx_id,record_id,member,entity,gross_comm,downline_amount,upline_amount\n1,${planted.recordId},${planted.name},Beacon,125.00,100.00,25.00\n`,
    'emits/statements_20261121.csv': `record_id,member,entity,gross_comm,downline_amount,upline_amount,run_action\n${planted.recordId},${planted.name},Beacon,125.00,100.00,25.00,NEW\n`,
  });
  await writeTree(right, {
    'input/a.csv': 'k\n1\n',
    'emits/canonical_bob.csv': `policy_id,member,mbi,address,phone,entity,amount\n1,Different Person,9ZZ9-YY8-XX76,999 Other Rd,555-000-0000,Harbor,99.99\n`,
    'emits/coherent_ledger.csv': `tx_id,record_id,member,entity,gross_comm,downline_amount,upline_amount\n1,carrier_a~direct~OTHER~99.99~2026-11,Different Person,Harbor,124.99,99.99,25.00\n`,
    'emits/statements_20261121.csv': `record_id,member,entity,gross_comm,downline_amount,upline_amount,run_action\ncarrier_a~direct~OTHER~99.99~2026-11,Different Person,Harbor,124.99,99.99,25.00,NEW\n`,
  });

  const rep = await compareRunFolders(left, right, {
    mode: 'substance',
    columns: {
      bob: ['policy_id', 'member', 'mbi', 'address', 'phone', 'entity', 'amount'],
      ledger: ['tx_id', 'record_id', 'member', 'entity', 'gross_comm', 'downline_amount', 'upline_amount'],
      statements: ['record_id', 'member', 'entity', 'gross_comm', 'downline_amount', 'upline_amount', 'run_action'],
    },
    requireStatementsDelta: true,
    requireConservation: true,
  });

  assert.equal(rep.passed, false);
  assert.equal(rep.gates.gate1.passed, true);
  assert.equal(rep.gates.gate2.passed, false);
  assert.equal(rep.gates.gate3.passed, false);
  assert.equal(rep.gates.gate4.passed, false);
  assert.equal(rep.substance.bob.moneyCentDeltas.amount, 1);
  assert.equal(rep.substance.bob.differingRows[0].rowNumber, 1);
  assert.ok(rep.substance.bob.differingRows[0].columns.includes('member'));
  assert.ok(rep.substance.bob.differingRows[0].columns.includes('amount'));

  const json = JSON.stringify(rep);
  for (const val of Object.values(planted)) {
    assert.equal(json.includes(val), false, `comparator report must never leak planted value "${val}"`);
  }
  assert.equal(json.includes('Different Person'), false);
  assert.equal(json.includes('9ZZ9-YY8-XX76'), false);
  assert.equal(json.includes('999 Other Rd'), false);
  assert.equal(json.includes('555-000-0000'), false);

  // Parameterized column contract check: wrong expected column list must fail headerMatches
  const badCols = compareCsvExactText('a,b\n1,2\n', 'a,b\n1,2\n', { expectedColumns: ['a', 'c'] });
  assert.equal(badCols.passed, false);
  assert.equal(badCols.headerMatches, false);
  assert.deepEqual(badCols.missingLeftColumns, ['c']);
});

test('Layer 4 [Fix 1 - compareCsvExactText PHI-free export]: exported compareCsvExactText omits _parsed and JSON.stringify holds no planted name, member id, or record id', () => {
  const planted = {
    name: 'Zelda Q. Plantedname',
    mbi: '1EG4-TE5-MK72',
    recordId: 'carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11',
  };
  const leftCsv = `record_id,member,mbi,amount\n${planted.recordId},${planted.name},${planted.mbi},100.00\n`;
  const rightCsv = `record_id,member,mbi,amount\n${planted.recordId},${planted.name},${planted.mbi},100.00\n`;
  const rightDiffCsv = `record_id,member,mbi,amount\ncarrier_a~direct~OTHER~99.00~2026-11,Other Name,9ZZ9-YY8-XX76,99.00\n`;

  for (const res of [
    compareCsvExactText(leftCsv, rightCsv, { tableName: 'canonical_bob' }),
    compareCsvExactText(leftCsv, rightDiffCsv, { tableName: 'canonical_bob' }),
  ]) {
    assert.equal(Object.hasOwn(res, '_parsed'), false, 'exported compareCsvExactText must not include _parsed');
    const json = JSON.stringify(res);
    for (const val of Object.values(planted)) {
      assert.equal(json.includes(val), false, `compareCsvExactText JSON leaked planted value "${val}"`);
    }
  }
});

test('Layer 4 [Fix 11 - Conservation Rollup & Unparseable Money Cells]: requireConservation requires bobRollupChecked and non-empty unparseable money cell is a violation, never $0.00', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'coherence-cons-fix11-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  // Case A: canonical_bob lacks upline_amount column -> bobRollupChecked is false -> must fail under requireConservation: true
  const noRollupL = join(dir, 'no-rollup-l');
  const noRollupR = join(dir, 'no-rollup-r');
  const noRollupFiles = {
    'input/a.csv': 'k\n1\n',
    'emits/canonical_bob.csv': 'policy_id,member,entity,amount\n1,Pat Sample,Beacon,80.00\n',
    'emits/coherent_ledger.csv': 'tx_id,record_id,policy_id,member,entity,gross_comm,downline_amount,upline_amount\n1,r1,1,Pat Sample,Beacon,100.00,80.00,20.00\n',
  };
  await writeTree(noRollupL, noRollupFiles);
  await writeTree(noRollupR, noRollupFiles);
  const noRollupRep = await compareRunFolders(noRollupL, noRollupR, { mode: 'substance', requireConservation: true });
  assert.equal(noRollupRep.substance.ledger.conservation.bobRollupChecked, false);
  assert.equal(noRollupRep.substance.ledger.conservation.passed, false);
  assert.equal(noRollupRep.gates.gate3.passed, false);
  assert.equal(noRollupRep.passed, false);

  // Case B: non-empty unparseable money cell in canonical_bob where treating it as $0.00 would falsely balance
  const badMoneyL = join(dir, 'bad-money-l');
  const badMoneyR = join(dir, 'bad-money-r');
  const badMoneyFiles = {
    'input/a.csv': 'k\n1\n',
    'emits/canonical_bob.csv': 'policy_id,member,entity,amount,upline_amount\n1,Pat Sample,Beacon,NOT_MONEY,20.00\n',
    'emits/coherent_ledger.csv': 'tx_id,record_id,policy_id,member,entity,gross_comm,downline_amount,upline_amount\n1,r1,1,Pat Sample,Beacon,20.00,0.00,20.00\n',
  };
  await writeTree(badMoneyL, badMoneyFiles);
  await writeTree(badMoneyR, badMoneyFiles);
  const badMoneyRep = await compareRunFolders(badMoneyL, badMoneyR, { mode: 'substance', requireConservation: true });
  assert.equal(badMoneyRep.substance.ledger.conservation.passed, false);
  assert.ok(badMoneyRep.substance.ledger.conservation.bobMoneyParseViolationCount >= 1);
  assert.deepEqual(badMoneyRep.substance.ledger.conservation.bobMoneyParseViolationRowNumbers, [1]);
  assert.equal(badMoneyRep.gates.gate3.passed, false);
  assert.equal(badMoneyRep.passed, false);
  assert.equal(JSON.stringify(badMoneyRep).includes('NOT_MONEY'), false);
});

test('Layer 4 [Proof Runner CLI scripts/prove-history.mjs]: migrates fresh test_* DB, imports synthetic manifest read-only, passes Layers 0, 1, 2, 4 and comparator with PHI-free stdout, and rejects non-test_* database names', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-prove-cli-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  // Verify non-test_* database name is strictly refused
  await assert.rejects(
    () => execFileAsync(process.execPath, ['scripts/prove-history.mjs', '--manifest', join(work, 'none.json'), '--database', 'prod_db'], {
      cwd: process.cwd(),
      env: process.env,
    }),
    (err) => String(err.stderr || '').includes('INVALID_TEST_DATABASE_NAME'),
  );

  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const plantedMember = 'Zelda Q. Plantedname';
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:P1#effective:2026-01-01', note: 'base' });
  const row1 = sampleApprovalRow({ record_id: `carrier_a~direct~${plantedMember}~100.00~2026-11`, disposition: 'CONFIRM', agent: null, agency: null, status: null, note: 'adj' });
  const priorCsv = makeOverlayCsv([row0], { version: 'v2' });
  const finalCsv = makeOverlayCsv([row0, row1], { version: 'v2' });

  const bobCsv = `policy_id,member,entity,amount,upline_amount\n1,${plantedMember},Beacon,80.00,20.00\n`;
  const ledCsv = `tx_id,record_id,policy_id,member,entity,gross_comm,downline_amount,upline_amount\n1,carrier_a~direct~${plantedMember}~100.00~2026-11,1,${plantedMember},Beacon,100.00,80.00,20.00\n`;
  const stmtCsv = `record_id,member,entity,gross_comm,downline_amount,upline_amount,run_action\ncarrier_a~direct~${plantedMember}~100.00~2026-11,${plantedMember},Beacon,100.00,80.00,20.00,NEW\n`;

  const runFiles = {
    'input/Agent Data/cleanagentdata.csv': 'agent_name,agent_npn,entity\nSam Seller,11111111,Beacon\n',
    'input/Overlay/overlay.csv': priorCsv,
    'bible.csv': 'record_id,case,subtype,amount\npolicy:carrier_a:P1#effective:2026-01-01,BIBLE,CONFLICT,100.00\n',
    'overlay.csv': finalCsv,
    'emits/overlay.csv': finalCsv,
    'emits/canonical_bob.csv': bobCsv,
    'emits/coherent_ledger.csv': ledCsv,
    'emits/statements_20261102.csv': stmtCsv,
    'run.json': JSON.stringify({ date: '2026-11-02', steps: { assign: { at: '2026-11-02T10:00:00' }, bible: { at: '2026-11-02T10:01:00' }, emit: { at: '2026-11-02T10:05:00' } } }),
  };
  await writeTree(join(work, 'src', 'runs', '2026-10-12'), {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': priorCsv,
    'emits/overlay.csv': priorCsv,
    'run.json': JSON.stringify({ date: '2026-10-12', steps: { assign: { at: '2026-10-12T10:00:00' }, emit: { at: '2026-10-12T10:05:00' } } }),
  });
  await writeTree(join(work, 'src', 'runs', '2026-11-02'), runFiles);
  await writeTree(join(work, 'src', 'ref-2026-11-02'), runFiles);
  await writeTree(join(work, 'src', 'input'), {
    'Agent Data/cleanagentdata.csv': runFiles['input/Agent Data/cleanagentdata.csv'],
    'Overlay/overlay.csv': finalCsv,
  });

  const manifestPath = join(work, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    companySlug: 'acme',
    displayName: 'Acme',
    defaultEmitMode: 'coherence',
    coherenceRepo: mockRepo,
    pythonPath: 'python3',
    sources: {
      legacyRunsRoot: 'src/runs',
      standingInputDir: 'src/input',
    },
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      currentInputSourceKind: 'mac_import',
      freshOverlayRoots: [{ sourceFolder: '2026-10-12', sha256: sha256Utf8(priorCsv) }],
    },
    compareTargets: [
      {
        label: '2026-11-02 substance parity',
        leftRunSourceFolder: '2026-11-02',
        rightDir: 'src/ref-2026-11-02',
        requireStatementsDelta: true,
        requireConservation: true,
      },
    ],
  }, null, 2), 'utf8');

  const dbName = `test_prove_cli_${createHash('sha256').update(work).digest('hex').slice(0, 8)}`;
  const { stdout } = await execFileAsync(
    process.execPath,
    ['scripts/prove-history.mjs', '--manifest', manifestPath, '--database', dbName, '--drop-db'],
    { cwd: process.cwd(), env: process.env, maxBuffer: 8 * 1024 * 1024 },
  );

  assert.equal(stdout.includes(plantedMember), false, 'proof runner CLI stdout must never contain member names');
  const summary = JSON.parse(stdout);
  assert.equal(summary.passed, true, `proof runner failed: ${JSON.stringify(summary.problems)}`);
  assert.equal(summary.layer0.passed, true);
  assert.equal(summary.layer0.objects.codeInDataStoreCount, 0);
  assert.equal(summary.layer1.passed, true);
  assert.equal(summary.layer1.idempotency.passed, true);
  assert.equal(summary.layer2.passed, true);
  assert.ok(summary.layer2.checkpointsChecked >= 2);
  assert.equal(summary.layer4.passed, true);
  assert.ok(summary.layer4.moments.length >= 2);
  assert.equal(summary.comparator.ran, true);
  assert.equal(summary.comparator.passed, true);
  assert.equal(summary.comparator.targets[0].gates.gate1.passed, true);
  assert.equal(summary.comparator.targets[0].gates.gate2.passed, true);
  assert.equal(summary.comparator.targets[0].gates.gate3.passed, true);
  assert.equal(summary.comparator.targets[0].gates.gate4.passed, true);

  // Fix round 2 (C5): ensureProofIamSubjectsForBatches clamps generated slugs <= 48 chars
  // (base cut to 40 before _N with trailing _ removed) and lowercases generated emails.
  const envSubj = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => envSubj.cleanup());
  const longEnt1 = 'Very Long Synthetic Brokerage Group Alpha One Hundred Twenty Three LLC';
  const longEnt2 = 'Very Long Synthetic Brokerage Group Alpha Two Hundred Forty Six LLC';
  const trailingUnderscoreEnt = `${'a'.repeat(39)} extra words beyond forty characters`;
  await ensureProofIamSubjectsForBatches(envSubj.pool, {
    companyOrgId: envSubj.iam.ids.companyOrg,
    environment: envSubj.iam.environment,
    bridgeResult: {
      historicalBatches: [{
        agencyLines: [
          { entity: longEnt1, writingNpn: '88888888' },
          { entity: longEnt2, writingNpn: '99999999' },
          { entity: trailingUnderscoreEnt, writingNpn: '77777777' },
        ],
        uplineLines: [],
      }],
      methodCorrectionBatches: [],
    },
  });
  const seededOrgs = (await envSubj.pool.query(
    `SELECT slug, display_name FROM iam.organization_versions
     WHERE superseded_by_id IS NULL AND display_name = ANY($1::text[])
     ORDER BY display_name`,
    [[longEnt1, longEnt2, trailingUnderscoreEnt]],
  )).rows;
  assert.equal(seededOrgs.length, 3);
  for (const row of seededOrgs) {
    assert.ok(row.slug.length <= 48, `slug too long (${row.slug.length}): ${row.slug}`);
    assert.match(row.slug, /^[a-z0-9][a-z0-9_-]{0,47}$/);
    assert.ok(!row.slug.endsWith('_'), `slug must not have trailing underscore: ${row.slug}`);
  }
  const seededPeople = (await envSubj.pool.query(
    `SELECT npn, primary_email FROM iam.person_versions
     WHERE superseded_by_id IS NULL AND npn = ANY($1::text[])
     ORDER BY npn`,
    [['88888888', '99999999', '77777777']],
  )).rows;
  assert.equal(seededPeople.length, 3);
  for (const row of seededPeople) {
    assert.equal(row.primary_email, row.primary_email.toLowerCase(), `generated email must be lowercased: ${row.primary_email}`);
  }
});

test('Layer 4 [Fix 10 & Note 2 - Proof Runner Missing Right Run, Configured Folders, Local PGHOST & Temp Cleanup]: missing right run fails by name, missing configured folders fail loudly, non-local PGHOST is refused, and proof temp folder is always cleaned up', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-prove-fix10-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  // 1) Non-local PGHOST is strictly refused before touching any DB
  await assert.rejects(
    () => execFileAsync(process.execPath, ['scripts/prove-history.mjs', '--manifest', join(work, 'none.json'), '--database', 'test_nonlocal_pg'], {
      cwd: process.cwd(),
      env: { ...process.env, PGHOST: '10.20.30.40' },
    }),
    (err) => String(err.stderr || '').includes('NON_LOCAL_PGHOST'),
  );

  // 2) Missing configured source folder in manifest fails loudly (never silently skips)
  const badFolderManifest = join(work, 'bad-folder-manifest.json');
  await writeFile(badFolderManifest, JSON.stringify({
    companySlug: 'acme',
    sources: {
      companyWorkspacesDir: 'does-not-exist-ws',
    },
  }), 'utf8');
  await assert.rejects(
    () => loadImportManifestFile(badFolderManifest),
    (err) => err?.code === 'MANIFEST_FOLDER_MISSING' && String(err.message).includes('companyWorkspacesDir'),
  );

  // 3) Comparator target whose right run is missing fails by name AND external storesDir still cleans tempRoot
  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:P1000#effective:2026-01-01' });
  const ovCsv = makeOverlayCsv([row0], { version: 'v2' });
  await writeTree(join(work, 'src', 'runs', '2026-11-02'), {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'emits/canonical_bob.csv': 'policy_id,member,entity,amount,upline_amount\n1,Pat Sample,Beacon,80.00,20.00\n',
    'emits/coherent_ledger.csv': 'tx_id,record_id,policy_id,member,entity,gross_comm,downline_amount,upline_amount\n1,r1,1,Pat Sample,Beacon,100.00,80.00,20.00\n',
    'run.json': JSON.stringify({ date: '2026-11-02', steps: { assign: { at: '2026-11-02T10:00:00' }, emit: { at: '2026-11-02T10:05:00' } } }),
  });

  const missingRightManifest = join(work, 'missing-right-manifest.json');
  await writeFile(missingRightManifest, JSON.stringify({
    companySlug: 'acme',
    coherenceRepo: mockRepo,
    pythonPath: 'python3',
    sources: { legacyRunsRoot: 'src/runs' },
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-11-02', sha256: sha256Utf8(ovCsv) }],
    },
    compareTargets: [
      {
        label: 'missing-right-target',
        leftRunSourceFolder: '2026-11-02',
        rightRunSourceFolder: '2026-11-99-missing',
      },
    ],
  }), 'utf8');

  const scratchRoot = join(work, 'proof-scratch');
  const extStoresDir = join(work, 'ext-stores');
  await mkdir(scratchRoot, { recursive: true });
  const dbName = `test_prove_f10_${createHash('sha256').update(work).digest('hex').slice(0, 8)}`;
  const summary = await runHistoryProof({
    manifestPath: missingRightManifest,
    database: dbName,
    dropDb: true,
    storesDir: extStoresDir,
    tempRoot: scratchRoot,
  });

  assert.equal(summary.passed, false);
  assert.equal(summary.comparator.passed, false);
  assert.equal(summary.comparator.targets.length, 1);
  assert.equal(summary.comparator.targets[0].passed, false);
  assert.ok(
    summary.comparator.targets[0].problems.some((p) => p.includes('2026-11-99-missing')),
    `expected missing right run named in problems, got: ${JSON.stringify(summary.comparator.targets[0].problems)}`,
  );

  // Temporary folder inside scratchRoot MUST be completely cleaned even when storesDir was passed!
  const remainingTemp = await readdir(scratchRoot);
  assert.deepEqual(remainingTemp, [], `proof runner leaked temporary directories: ${JSON.stringify(remainingTemp)}`);
});

test('Layer 4 [Fix2-2 - Gate 4 Non-Vacuous Entity Parity]: fails naming missing run_materializations when expectedEntityParity is given, and compares entity totals over the union so unexpected extra entities fail', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const srcRoot = join(env.tempDir, 'src-gate4');
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:P401#effective:2026-01-01' });
  const ovCsv = makeOverlayCsv([row0], { version: 'v2' });

  const bobCsv = [
    'policy_id,member,entity,amount,upline_amount',
    '1,Pat Sample,Beacon,80.00,20.00',
    '2,Chris Sample,Harbor,40.00,10.00',
  ].join('\n') + '\n';
  const ledCsv = [
    'tx_id,record_id,policy_id,src_type,member,entity,gross_comm,commission_amount,downline_amount,upline_amount',
    '1,r-beacon-1,1,direct,Pat Sample,Beacon,100.00,100.00,80.00,20.00',
    '2,r-harbor-1,2,direct,Chris Sample,Harbor,50.00,50.00,40.00,10.00',
  ].join('\n') + '\n';
  const stmtCsv = [
    'record_id,entity,gross_comm,downline_amount,upline_amount,run_action',
    'r-beacon-1,Beacon,100.00,80.00,20.00,NEW',
    'r-harbor-1,Harbor,50.00,40.00,10.00,NEW',
  ].join('\n') + '\n';

  const runFiles = {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'emits/canonical_bob.csv': bobCsv,
    'emits/coherent_ledger.csv': ledCsv,
    'emits/statements_20261102.csv': stmtCsv,
    'run.json': JSON.stringify({ date: '2026-11-02', steps: { assign: { at: '2026-11-02T10:00:00' }, emit: { at: '2026-11-02T10:05:00' } } }),
  };
  await writeTree(join(srcRoot, 'runs', '2026-11-02'), runFiles);
  const refDir = join(srcRoot, 'ref-2026-11-02');
  await writeTree(refDir, runFiles);

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacyRunsRoot: join(srcRoot, 'runs') },
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-11-02', sha256: sha256Utf8(ovCsv) }],
    },
  });
  const imp = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, dbToken: env.ownerToken,
    manifest, pythonPath: 'python3', coherenceRepo: mockRepo, verifyRebuild: false, tempBaseDir: env.tempDir,
  });
  assert.equal(imp.passed, true);
  const leftRunId = imp.importedRuns[0].runId;

  // 1) Before run_materializations exists, passing expectedEntityParity MUST check Gate 4 and fail naming run_materializations
  const missingMatRep = await compareDbRuns({
    pool: env.pool,
    stores: env.stores,
    leftRunId,
    rightFolderDir: refDir,
    mode: 'substance',
    requireStatementsDelta: true,
    requireConservation: true,
    expectedEntityParity: {
      perEntityTotals: { Beacon: '80.00', Harbor: '40.00', 'Acme Upline': '30.00' },
    },
    tempBaseDir: env.tempDir,
  });
  assert.equal(missingMatRep.gates.gate4.entityStatements.dbReconciliation.checked, true, 'Gate 4 must be checked when expectedEntityParity is given');
  assert.equal(missingMatRep.gates.gate4.entityStatements.dbReconciliation.passed, false, 'Gate 4 must fail when left run has no run_materializations row');
  assert.equal(missingMatRep.gates.gate4.passed, false);
  assert.equal(missingMatRep.passed, false);
  assert.equal(missingMatRep.stoppedAtGate, 4);
  assert.ok(
    missingMatRep.problems.some((p) => /run_materializations/i.test(p)),
    `expected problems to name missing run_materializations, got: ${JSON.stringify(missingMatRep.problems)}`,
  );

  // Materialize the Emit so run_materializations and entity statement views are populated
  const emitEv = (await env.pool.query(
    "SELECT id FROM coherence.step_attempt_events WHERE run_id = $1::uuid AND step = 'emit' AND event_kind = 'finished'",
    [leftRunId],
  )).rows[0].id;
  await env.commands.materializeEmit({
    dbToken: env.workerToken,
    commandKey: 'mat-gate4-test',
    runId: leftRunId,
    attemptEventId: emitEv,
    statementDate: '2026-11-02',
    canonicalBobCsv: bobCsv,
    coherentLedgerCsv: ledCsv,
    statementsCsv: stmtCsv,
  });

  // 2) Exact entity parity passes Gate 4
  const okRep = await compareDbRuns({
    pool: env.pool,
    stores: env.stores,
    leftRunId,
    rightFolderDir: refDir,
    mode: 'substance',
    requireStatementsDelta: true,
    requireConservation: true,
    expectedEntityParity: {
      datesChecked: 1,
      filesChecked: 3,
      totalLines: 4,
      ledgerGrossTotal: '150.00',
      perEntityTotals: { Beacon: '80.00', Harbor: '40.00', 'Acme Upline': '30.00' },
    },
    tempBaseDir: env.tempDir,
  });
  assert.equal(okRep.passed, true, `expected exact parity to pass, got: ${JSON.stringify(okRep.problems)}`);
  assert.equal(okRep.gates.gate4.passed, true);

  // 3) Unexpected extra actual entity (Harbor present in DB, omitted from expectedEntityParity) MUST fail Gate 4
  const extraEntityRep = await compareDbRuns({
    pool: env.pool,
    stores: env.stores,
    leftRunId,
    rightFolderDir: refDir,
    mode: 'substance',
    requireStatementsDelta: true,
    requireConservation: true,
    expectedEntityParity: {
      perEntityTotals: { Beacon: '80.00', 'Acme Upline': '30.00' },
    },
    tempBaseDir: env.tempDir,
  });
  assert.equal(extraEntityRep.gates.gate4.entityStatements.dbReconciliation.checked, true);
  assert.equal(extraEntityRep.gates.gate4.entityStatements.dbReconciliation.passed, false);
  assert.equal(extraEntityRep.gates.gate4.entityStatements.dbReconciliation.expectedParityPassed, false);
  assert.ok(
    extraEntityRep.gates.gate4.entityStatements.dbReconciliation.expectedParityProblems.some((p) => p.includes('Harbor')),
    `expected Harbor in expectedParityProblems, got: ${JSON.stringify(extraEntityRep.gates.gate4.entityStatements.dbReconciliation.expectedParityProblems)}`,
  );
  assert.equal(extraEntityRep.gates.gate4.passed, false);
  assert.equal(extraEntityRep.passed, false);
  assert.equal(extraEntityRep.stoppedAtGate, 4);
  assert.ok(
    extraEntityRep.problems.some((p) => p.includes('Harbor')),
    `expected Harbor named in Gate 4 problems, got: ${JSON.stringify(extraEntityRep.problems)}`,
  );
});

test('Layer 4 [Fix2-3 - Zone-Less Timestamps on Non-UTC Session]: normalizes manifest checkpoint originalAt like run.json and stores standalone files originalAt as UTC so commitment hash and PostgreSQL agree under America/New_York', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  let nyPool = null;
  t.after(async () => {
    if (nyPool) await nyPool.end().catch(() => {});
    await env.cleanup();
  });

  await env.pool.query(`ALTER DATABASE "${env.dbName}" SET TimeZone = 'America/New_York'`);
  nyPool = await createPool(env.pgConfig);
  assert.equal((await nyPool.query("SELECT current_setting('TimeZone') AS tz")).rows[0].tz, 'America/New_York');
  const nyCommands = createAppCommands({ pool: nyPool, stores: env.stores });

  const zonelessTs = '2026-10-15T10:30:00';

  // 1) Direct importStandaloneFiles with a zone-less originalAt MUST store normalized UTC matching commitment hash on America/New_York session
  const directFile = await env.dataStore.promoteBytes(Buffer.from('hello standalone\n', 'utf8'), { relPath: 'standalone/note.txt', checksPassed: true });
  await nyCommands.importStandaloneFiles({
    dbToken: env.ownerToken,
    commandKey: 'fix2-3-standalone-zoneless',
    files: [{
      area: 'other',
      relPath: 'standalone/note.txt',
      artifactKind: 'data',
      storeKind: 'company_data',
      fileSha256: directFile.sha256,
      originalAt: zonelessTs,
      metadata: {},
    }],
    storedFiles: [directFile],
  });
  const directRow = (await nyPool.query(
    "SELECT coherence.format_utc_us(original_at) AS orig_utc FROM coherence.imported_files WHERE rel_path = 'standalone/note.txt'",
  )).rows[0];
  assert.equal(directRow.orig_utc, formatTimestampUtcUs(zonelessTs));

  // 2) Manifest overlayCheckpoint with zone-less originalAt MUST normalize via local-time parser just like run.json and pass commitments under America/New_York
  const mockRepo = join(env.tempDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const srcRoot = join(env.tempDir, 'src-zoneless');
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:PZ1#effective:2026-01-01', note: 'cp' });
  const row1 = sampleApprovalRow({ record_id: 'policy:carrier_a:PZ2#effective:2026-01-01', note: 'run' });
  const cpPath = join(srcRoot, 'cp-zoneless.csv');
  const cpCsv = makeOverlayCsv([row0], { version: 'v2' });
  await mkdir(srcRoot, { recursive: true });
  await writeFile(cpPath, cpCsv, 'utf8');
  await writeTree(join(srcRoot, 'runs', '2026-10-16'), {
    'input/a.csv': 'k\n1\n',
    'input/Overlay/overlay.csv': cpCsv,
    'overlay.csv': makeOverlayCsv([row0, row1], { version: 'v2' }),
    'run.json': JSON.stringify({ date: '2026-10-16', steps: { assign: { at: zonelessTs } } }),
  });

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacyRunsRoot: join(srcRoot, 'runs') },
    overlayCheckpoints: [{ label: 'zoneless-cp', absPath: cpPath, originalAt: zonelessTs }],
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: 'overlay-checkpoints/zoneless-cp', sha256: sha256Utf8(cpCsv) }],
    },
  });

  const imp = await executeHistoryImport({
    pool: nyPool,
    stores: env.stores,
    commands: nyCommands,
    dbToken: env.ownerToken,
    manifest,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: env.tempDir,
  });
  assert.equal(imp.passed, true, `import failed on America/New_York session: ${JSON.stringify(imp.problems)}`);

  const expectedLocalNormalizedUtc = formatTimestampUtcUs(new Date(zonelessTs).toISOString());
  const runStepOrig = (await nyPool.query(
    "SELECT coherence.format_utc_us(original_at) AS orig_utc FROM coherence.step_attempt_events WHERE step = 'assign' AND event_kind = 'finished'",
  )).rows[0].orig_utc;
  const cpImpRow = (await nyPool.query(
    "SELECT coherence.format_utc_us(original_at) AS orig_utc, metadata->>'decisionCommitId' AS commit_id FROM coherence.imported_files WHERE rel_path = 'overlay-checkpoints/zoneless-cp'",
  )).rows[0];
  const cpCommitOrig = (await nyPool.query(
    'SELECT coherence.format_utc_us(original_at) AS orig_utc FROM coherence.decision_commits WHERE id = $1::uuid',
    [cpImpRow.commit_id],
  )).rows[0].orig_utc;

  assert.equal(runStepOrig, expectedLocalNormalizedUtc);
  assert.equal(cpImpRow.orig_utc, runStepOrig, 'checkpoint imported_files.original_at must match run.json local-time normalization');
  assert.equal(cpCommitOrig, runStepOrig, 'checkpoint decision_commits.original_at must match run.json local-time normalization');

  const chainCheck = await verifyChain(nyPool);
  const commitCheck = await verifyCommitments(nyPool);
  assert.equal(chainCheck.passed, true, `chain check failed: ${JSON.stringify(chainCheck.problems)}`);
  assert.equal(commitCheck.passed, true, `commitment check failed: ${JSON.stringify(commitCheck.problems)}`);
});

test('Layer 4 [Fix2-4a - Proof Runner /cloudsql Refusal & Local Mode Pinning]: refuses any PGHOST under /cloudsql and pins local mode even when COHERENCE_PG_MODE=cloudsql', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-prove-cloudsql-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  for (const badHost of [
    '/cloudsql',
    '/cloudsql/proj:us-central1:prod',
    '//cloudsql/proj:us-central1:prod',
    '/tmp/../cloudsql/proj:us-central1:prod',
    '/CloudSQL/proj:us-central1:prod',
  ]) {
    assert.throws(
      () => assertLocalPgHost(badHost),
      (err) => err?.code === 'NON_LOCAL_PGHOST',
      `expected assertLocalPgHost(${JSON.stringify(badHost)}) to refuse with NON_LOCAL_PGHOST`,
    );
  }

  await assert.rejects(
    () => execFileAsync(process.execPath, ['scripts/prove-history.mjs', '--manifest', join(work, 'none.json'), '--database', 'test_cloudsql_refuse'], {
      cwd: process.cwd(),
      env: { ...process.env, PGHOST: '/cloudsql/proj:us-central1:prod' },
    }),
    (err) => String(err.stderr || '').includes('NON_LOCAL_PGHOST'),
  );

  // Pinning mode: 'local' means proof runner succeeds on local PG even if COHERENCE_PG_MODE=cloudsql is set in env
  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:P410#effective:2026-01-01' });
  const ovCsv = makeOverlayCsv([row0], { version: 'v2' });
  await writeTree(join(work, 'src', 'runs', '2026-11-02'), {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': ovCsv,
    'emits/overlay.csv': ovCsv,
    'run.json': JSON.stringify({ date: '2026-11-02', steps: { assign: { at: '2026-11-02T10:00:00' }, emit: { at: '2026-11-02T10:05:00' } } }),
  });
  const manifestPath = join(work, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    companySlug: 'acme',
    coherenceRepo: mockRepo,
    pythonPath: 'python3',
    sources: { legacyRunsRoot: 'src/runs' },
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-11-02', sha256: sha256Utf8(ovCsv) }],
    },
  }), 'utf8');

  const dbName = `test_prove_pin_${createHash('sha256').update(work).digest('hex').slice(0, 8)}`;
  const { stdout } = await execFileAsync(
    process.execPath,
    ['scripts/prove-history.mjs', '--manifest', manifestPath, '--database', dbName, '--drop-db'],
    {
      cwd: process.cwd(),
      env: { ...process.env, COHERENCE_PG_MODE: 'cloudsql' },
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  const summary = JSON.parse(stdout);
  assert.equal(summary.passed, true, `proof runner should succeed in pinned local mode despite COHERENCE_PG_MODE=cloudsql: ${JSON.stringify(summary.problems)}`);
});

test('Layer 4 [Proof Runner --plan Mode]: counts runs/files/bytes accurately across all areas without reading file contents or touching a database, counts unreadable files, and prints only counts and names', async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-prove-plan-ok-'));
  const unreadablePaths = [];
  t.after(async () => {
    for (const p of unreadablePaths) {
      await chmod(p, 0o600).catch(() => {});
    }
    await rm(work, { recursive: true, force: true });
  });

  const secretContent = 'SECRET_MEMBER_CONTENT_DO_NOT_READ_888\n';
  const secretFilename = 'Pat_Sample_SecretFile_999.csv';

  const legacyRun1Files = {
    'run.json': '{"date":"2026-10-21"}\n',
    [`input/${secretFilename}`]: secretContent,
    'emits/statements_20261021.csv': 'record_id,amount\n',
  };
  const legacyRun2Files = {
    'run.json': '{"date":"2026-08-31"}\n',
    'overlay.csv': 'record_id,disposition\n',
  };
  const incidentFiles = {
    '2026-11-03/report.csv': 'k\n1\n',
    '2026-11-03/helper.py': 'print("ok")\n',
  };
  const standingFiles = {
    'Agent Data/cleanagentdata.csv': 'agent_name,agent_npn\nSam,11111111\n',
    [`All BOB/TrailingCarrier /${secretFilename}`]: secretContent,
    'Overlay/overlay.csv': 'record_id,disposition\n',
    'PreStatements/stmt_20260325.csv': 'a,b\n1,2\n',
    'PreStatements/.DS_Store': 'ignored-by-pre-coherence',
    'Sent/statements_20260831.csv': 'record_id\n',
  };
  const companyRunFiles = {
    'run.json': '{"date":"2026-11-03"}\n',
    'emits/canonical_bob.csv': 'policy_id,amount\n1,10.00\n',
  };
  const abandonedRunFiles = {
    'run.json': 'NOT_EVEN_VALID_JSON_BECAUSE_PLAN_NEVER_READS_IT',
    'working/tx.csv': 'id\n1\n',
  };
  const abandonedStandalone = { 'orphan-notes.txt': 'abandoned-note\n' };
  const legacySavesFiles = {
    '2026-10-21/bible-review-2026-10-21T10-00-00-000Z.csv': 'record_id\n',
    '2026-10-21/run.log': 'log-line\n',
  };
  const companySavesFiles = {
    '2026-11-03/adjust-review-2026-11-03T10-00-00-000Z.csv': 'record_id\n',
  };
  const companyEnvFiles = {
    'audit.json': 'INVALID_JSON_MUST_NEVER_BE_READ',
    'answer-key-2026-11-03.json': '{"ok":true}\n',
    'finished/2026-11-03/summary.csv': 'k\n1\n',
    'replaced/old.csv': 'k\n0\n',
    'incoming/ignored-when-not-standing.csv': 'ignored\n',
  };
  const cloudMirrorFiles = {
    'lists/standing.json': '{"files":[]}\n',
    'objects/deadbeef': 'bytes\n',
  };
  const checkpointBytes = 'record_id,disposition\n';
  const sqliteFakeBytes = 'NOT_A_REAL_SQLITE_FILE_MUST_NEVER_BE_OPENED';

  const byteLen = (obj) => Object.values(obj).reduce((sum, s) => sum + Buffer.byteLength(s, 'utf8'), 0);

  await writeTree(join(work, 'coherence', 'runs', '2026-10-21'), legacyRun1Files);
  await writeTree(join(work, 'coherence', 'runs', 'archive', 'v1', '2026-08-31'), legacyRun2Files);
  await writeTree(join(work, 'coherence', 'runs', 'Incident Report'), incidentFiles);
  await writeTree(join(work, 'coherence', 'input'), standingFiles);
  await writeTree(join(work, 'nusear', 'company-workspaces', 'acme', '2026-11-03', 'runs', '2026-11-03'), companyRunFiles);
  await writeTree(join(work, 'nusear', 'company-abandoned', 'acme', 'abandoned-no-date'), abandonedRunFiles);
  await writeTree(join(work, 'nusear', 'company-abandoned', 'acme'), abandonedStandalone);
  await writeTree(join(work, 'nusear', 'coherence-runs'), legacySavesFiles);
  await writeTree(join(work, 'nusear', 'company-runs', 'acme'), companySavesFiles);
  await writeTree(join(work, 'nusear', 'company-environments', 'acme'), companyEnvFiles);
  await writeTree(join(work, 'cloud-mirror'), cloudMirrorFiles);
  await writeTree(join(work, 'checkpoints'), { 'pre-1021.csv': checkpointBytes });
  await writeTree(join(work, 'backups'), { 'nusear2.sqlite': sqliteFakeBytes });
  await writeTree(join(work, 'ref-2026-10-21'), legacyRun1Files);

  // Make multiple files unreadable (mode 000): stat/readdir succeed while any file read would fail with EACCES.
  const toLock = [
    join(work, 'coherence', 'runs', '2026-10-21', 'run.json'),
    join(work, 'coherence', 'runs', '2026-10-21', 'input', secretFilename),
    join(work, 'coherence', 'input', 'Agent Data', 'cleanagentdata.csv'),
    join(work, 'coherence', 'input', 'All BOB', 'TrailingCarrier ', secretFilename),
    join(work, 'nusear', 'company-environments', 'acme', 'audit.json'),
    join(work, 'checkpoints', 'pre-1021.csv'),
    join(work, 'backups', 'nusear2.sqlite'),
  ];
  for (const p of toLock) {
    await chmod(p, 0o000);
    unreadablePaths.push(p);
  }

  const manifestPath = join(work, 'plan-manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    companySlug: 'acme',
    displayName: 'Acme',
    coherenceRoot: 'coherence',
    coherenceRepo: 'coherence',
    nusearDataDir: 'nusear',
    nusearSqlitePath: 'backups/nusear2.sqlite',
    pythonPath: 'python3',
    sources: {
      legacyRunsRoot: 'coherence/runs',
      standingInputDir: 'coherence/input',
      incidentReportDir: 'coherence/runs/Incident Report',
      legacyReviewSavesDir: 'nusear/coherence-runs',
      companyWorkspacesDir: 'nusear/company-workspaces/acme',
      companyAbandonedDir: 'nusear/company-abandoned/acme',
      companyReviewSavesDir: 'nusear/company-runs/acme',
      companyEnvironmentDir: 'nusear/company-environments/acme',
      cloudMirrorDir: 'cloud-mirror',
      legacySqlitePath: 'backups/nusear2.sqlite',
      preCoherenceStatementsDir: 'coherence/input/PreStatements',
      preCoherenceSentDir: 'coherence/input/Sent',
      preCoherenceAgentsCsv: 'coherence/input/Agent Data/cleanagentdata.csv',
      methodCorrections: [
        { kind: 'split_reallocation', statementDate: '2026-08-01', expectedAgencyNetCents: -100, expectedUplineNetCents: 100 },
      ],
    },
    importConfig: {
      includeLegacyHostHistory: true,
      includeLegacySqliteTables: true,
      useCompanyIncomingInput: false,
    },
    overlayCheckpoints: [
      { label: 'pre-1021-checkpoint', path: 'checkpoints/pre-1021.csv' },
    ],
    compareTargets: [
      {
        label: 'ref-2026-10-21',
        leftRunSourceFolder: '2026-10-21',
        rightDir: 'ref-2026-10-21',
      },
      {
        label: 'company-2026-11-03',
        leftRunSourceFolder: 'company-workspaces/acme/2026-11-03/runs/2026-11-03',
        rightDir: 'nusear/company-workspaces/acme/2026-11-03/runs/2026-11-03',
      },
    ],
  }, null, 2), 'utf8');

  // Run via CLI with unreachable PGHOST/PGPORT to prove --plan touches no database.
  const { stdout, stderr } = await execFileAsync(
    process.execPath,
    ['scripts/prove-history.mjs', '--manifest', manifestPath, '--plan'],
    {
      cwd: process.cwd(),
      env: { ...process.env, PGHOST: '10.20.30.40', PGPORT: '1' },
      maxBuffer: 4 * 1024 * 1024,
    },
  );
  assert.equal(stderr, '');

  // Nothing printed except counts and names (zero file contents, zero inner filenames, zero temp paths).
  assert.equal(stdout.includes(secretContent.trim()), false, '--plan must never print file contents');
  assert.equal(stdout.includes(secretFilename), false, '--plan must never print source filenames');
  assert.equal(stdout.includes(work), false, '--plan must never print filesystem paths');
  assert.equal(stdout.includes('NOT_EVEN_VALID_JSON'), false);
  assert.equal(stdout.includes('NOT_A_REAL_SQLITE'), false);

  const summary = JSON.parse(stdout);
  assert.deepEqual(Object.keys(summary).sort(), [
    'areas',
    'companySlug',
    'compareTargets',
    'methodCorrectionsCount',
    'missing',
    'mode',
    'passed',
    'totals',
  ]);
  assert.equal(summary.mode, 'plan');
  assert.equal(summary.passed, true);
  assert.equal(summary.companySlug, 'acme');
  assert.equal(summary.methodCorrectionsCount, 1);
  assert.deepEqual(summary.missing, []);

  assert.deepEqual(summary.areas.legacyRuns, {
    configured: true,
    found: true,
    runs: 2,
    files: Object.keys(legacyRun1Files).length + Object.keys(legacyRun2Files).length,
    bytes: byteLen(legacyRun1Files) + byteLen(legacyRun2Files),
  });
  assert.deepEqual(summary.areas.companyRuns, {
    configured: true,
    found: true,
    runs: 1,
    files: Object.keys(companyRunFiles).length,
    bytes: byteLen(companyRunFiles),
  });
  assert.deepEqual(summary.areas.abandonedRuns, {
    configured: true,
    found: true,
    runs: 1,
    files: Object.keys(abandonedRunFiles).length + Object.keys(abandonedStandalone).length,
    bytes: byteLen(abandonedRunFiles) + byteLen(abandonedStandalone),
  });
  assert.deepEqual(summary.areas.standingInput, {
    configured: true,
    found: true,
    runs: 0,
    files: Object.keys(standingFiles).length,
    bytes: byteLen(standingFiles),
  });
  assert.deepEqual(summary.areas.incidentReport, {
    configured: true,
    found: true,
    runs: 0,
    files: Object.keys(incidentFiles).length,
    bytes: byteLen(incidentFiles),
  });
  assert.deepEqual(summary.areas.legacyReviewSaves, {
    configured: true,
    found: true,
    runs: 0,
    files: Object.keys(legacySavesFiles).length,
    bytes: byteLen(legacySavesFiles),
  });
  assert.deepEqual(summary.areas.companyReviewSaves, {
    configured: true,
    found: true,
    runs: 0,
    files: Object.keys(companySavesFiles).length,
    bytes: byteLen(companySavesFiles),
  });
  const countedCompEnv = {
    'audit.json': companyEnvFiles['audit.json'],
    'answer-key-2026-11-03.json': companyEnvFiles['answer-key-2026-11-03.json'],
    'finished/2026-11-03/summary.csv': companyEnvFiles['finished/2026-11-03/summary.csv'],
    'replaced/old.csv': companyEnvFiles['replaced/old.csv'],
  };
  assert.deepEqual(summary.areas.companyEnvironment, {
    configured: true,
    found: true,
    runs: 0,
    files: Object.keys(countedCompEnv).length,
    bytes: byteLen(countedCompEnv),
  });
  assert.deepEqual(summary.areas.cloudMirror, {
    configured: true,
    found: true,
    runs: 0,
    files: Object.keys(cloudMirrorFiles).length,
    bytes: byteLen(cloudMirrorFiles),
  });
  assert.deepEqual(summary.areas.preCoherenceStatements, {
    configured: true,
    found: true,
    runs: 0,
    files: 1,
    bytes: Buffer.byteLength(standingFiles['PreStatements/stmt_20260325.csv'], 'utf8'),
  });
  assert.deepEqual(summary.areas.preCoherenceSent, {
    configured: true,
    found: true,
    runs: 0,
    files: 1,
    bytes: Buffer.byteLength(standingFiles['Sent/statements_20260831.csv'], 'utf8'),
  });
  assert.deepEqual(summary.areas.preCoherenceAgents, {
    configured: true,
    found: true,
    runs: 0,
    files: 1,
    bytes: Buffer.byteLength(standingFiles['Agent Data/cleanagentdata.csv'], 'utf8'),
  });
  assert.deepEqual(summary.areas.overlayCheckpoints, {
    configured: true,
    found: true,
    runs: 0,
    files: 1,
    bytes: Buffer.byteLength(checkpointBytes, 'utf8'),
  });
  assert.deepEqual(summary.areas.legacySqlite, {
    configured: true,
    found: true,
    runs: 0,
    files: 1,
    bytes: Buffer.byteLength(sqliteFakeBytes, 'utf8'),
  });

  // Totals deduplicate overlapping subpaths under standingInput (PreStatements, Sent, Agent Data).
  const expectedUniqueFiles = summary.areas.legacyRuns.files
    + summary.areas.companyRuns.files
    + summary.areas.abandonedRuns.files
    + summary.areas.standingInput.files
    + summary.areas.incidentReport.files
    + summary.areas.legacyReviewSaves.files
    + summary.areas.companyReviewSaves.files
    + summary.areas.companyEnvironment.files
    + summary.areas.cloudMirror.files
    + summary.areas.overlayCheckpoints.files
    + summary.areas.legacySqlite.files;
  const expectedUniqueBytes = summary.areas.legacyRuns.bytes
    + summary.areas.companyRuns.bytes
    + summary.areas.abandonedRuns.bytes
    + summary.areas.standingInput.bytes
    + summary.areas.incidentReport.bytes
    + summary.areas.legacyReviewSaves.bytes
    + summary.areas.companyReviewSaves.bytes
    + summary.areas.companyEnvironment.bytes
    + summary.areas.cloudMirror.bytes
    + summary.areas.overlayCheckpoints.bytes
    + summary.areas.legacySqlite.bytes;
  assert.deepEqual(summary.totals, {
    runs: 4,
    files: expectedUniqueFiles,
    bytes: expectedUniqueBytes,
  });

  assert.deepEqual(summary.compareTargets, [
    { name: 'ref-2026-10-21', status: 'found', left: 'found', right: 'found' },
    { name: 'company-2026-11-03', status: 'found', left: 'found', right: 'found' },
  ]);

  // Direct API call returns the identical structure.
  const direct = await runHistoryPlan({ manifestPath });
  assert.deepEqual(direct, summary);
});

test('Layer 4 [Proof Runner --plan Missing Sources & Targets]: exits 1 and names every missing configured folder, file, checkpoint, and comparison target by manifest key', async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-prove-plan-miss-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  await writeTree(join(work, 'runs', '2026-11-02'), {
    'run.json': '{"date":"2026-11-02"}\n',
    'overlay.csv': 'record_id\n',
  });
  await writeTree(join(work, 'ref-ok'), {
    'run.json': '{"date":"2026-11-02"}\n',
  });

  const manifestPath = join(work, 'missing-manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    companySlug: 'acme',
    pythonPath: 'venv/bin/missing-python',
    sources: {
      legacyRunsRoot: 'runs',
      companyWorkspacesDir: 'missing-company-ws',
      preCoherenceStatementsDir: 'missing-pre-statements',
      legacySqlitePath: 'missing-backup.sqlite',
    },
    overlayCheckpoints: [
      { label: 'missing-cp', path: 'missing-overlay.csv' },
    ],
    compareTargets: [
      {
        label: 'target-missing-right-dir',
        leftRunSourceFolder: '2026-11-02',
        rightDir: 'no-such-right-dir',
      },
      {
        label: 'target-missing-left-run',
        leftRunSourceFolder: '2026-11-99-absent',
        rightDir: 'ref-ok',
      },
      {
        label: 'target-present',
        leftRunSourceFolder: '2026-11-02',
        rightDir: 'ref-ok',
      },
    ],
  }, null, 2), 'utf8');

  let exitCode = 0;
  let stdout = '';
  try {
    await execFileAsync(
      process.execPath,
      ['scripts/prove-history.mjs', '--manifest', manifestPath, '--plan'],
      { cwd: process.cwd(), env: { ...process.env, PGHOST: '10.20.30.40' } },
    );
  } catch (err) {
    exitCode = err.code;
    stdout = String(err.stdout || '');
  }

  assert.equal(exitCode, 1, '--plan must exit with code 1 when any configured folder, file, or target is missing');
  assert.equal(stdout.includes(work), false, '--plan error output must not print raw filesystem paths');

  const summary = JSON.parse(stdout);
  assert.equal(summary.mode, 'plan');
  assert.equal(summary.passed, false);
  assert.equal(summary.areas.legacyRuns.runs, 1);
  assert.equal(summary.areas.legacyRuns.files, 2);
  assert.equal(summary.areas.companyRuns.configured, true);
  assert.equal(summary.areas.companyRuns.found, false);

  assert.deepEqual(summary.compareTargets, [
    { name: 'target-missing-right-dir', status: 'missing', left: 'found', right: 'missing' },
    { name: 'target-missing-left-run', status: 'missing', left: 'missing', right: 'found' },
    { name: 'target-present', status: 'found', left: 'found', right: 'found' },
  ]);

  const missingKeys = summary.missing.map((m) => m.key);
  assert.deepEqual(missingKeys, [
    'pythonPath',
    'sources.companyWorkspacesDir',
    'sources.preCoherenceStatementsDir',
    'sources.legacySqlitePath',
    'overlayCheckpoints[0]',
    'compareTargets[0].rightDir',
    'compareTargets[1].leftRunSourceFolder',
  ]);
});

test('Layer 4 [Real-History Manifest Schema]: config manifest declares every key read by loadImportManifestFile without touching live folders', async () => {
  const manifestRaw = JSON.parse(await readFile(join(process.cwd(), 'config', 'phalanx-history.manifest.json'), 'utf8'));
  assert.equal(manifestRaw.companySlug, 'phalanx');
  assert.equal(manifestRaw.displayName, 'Phalanx');
  assert.equal(manifestRaw.defaultEmitMode, 'coherence');
  assert.equal(typeof manifestRaw.coherenceRoot, 'string');
  assert.equal(typeof manifestRaw.coherenceRepo, 'string');
  assert.equal(typeof manifestRaw.nusearDataDir, 'string');
  assert.equal(typeof manifestRaw.nusearSqlitePath, 'string');
  assert.equal(manifestRaw.nusearSqlitePath.includes('/data/nusear2.sqlite'), false, 'must point to consistent backup copy, never live data/nusear2.sqlite');
  assert.equal(manifestRaw.sources.legacySqlitePath, manifestRaw.nusearSqlitePath);
  assert.equal(typeof manifestRaw.pythonPath, 'string');
  assert.equal(typeof manifestRaw.overlayCheckPath, 'string');
  assert.equal(typeof manifestRaw.legacyBridgePath, 'string');

  const expectedSourceKeys = [
    'legacyRunsRoot',
    'standingInputDir',
    'incidentReportDir',
    'legacyReviewSavesDir',
    'companyWorkspacesDir',
    'companyAbandonedDir',
    'companyReviewSavesDir',
    'companyEnvironmentDir',
    'cloudMirrorDir',
    'legacySqlitePath',
    'preCoherenceStatementsDir',
    'preCoherenceSentDir',
    'preCoherenceAgentsCsv',
    'methodCorrections',
  ];
  for (const key of expectedSourceKeys) {
    assert.equal(Object.prototype.hasOwnProperty.call(manifestRaw.sources, key), true, `manifest.sources missing key ${key}`);
  }
  assert.equal(manifestRaw.sources.methodCorrections.length, 2);
  for (const corr of manifestRaw.sources.methodCorrections) {
    assert.equal(Number.isInteger(corr.expectedAgencyNetCents), true);
    assert.equal(Number.isInteger(corr.expectedUplineNetCents), true);
  }
  const corr0801 = manifestRaw.sources.methodCorrections.find((c) => c.statementDate === '2026-08-01');
  const corr0831 = manifestRaw.sources.methodCorrections.find((c) => c.statementDate === '2026-08-31');
  assert.ok(corr0801, 'manifest must declare 2026-08-01 method correction');
  assert.equal(corr0801.expectedAgencyNetCents, 233678);
  assert.equal(corr0801.expectedUplineNetCents, -233678);
  assert.ok(corr0831, 'manifest must declare 2026-08-31 method correction');
  assert.equal(corr0831.expectedAgencyNetCents, 0);
  assert.equal(corr0831.expectedUplineNetCents, -17764809);
  assert.equal(manifestRaw.importConfig.includeLegacyHostHistory, true);
  assert.equal(manifestRaw.importConfig.includeLegacySqliteTables, true);
  assert.equal(manifestRaw.importConfig.useCompanyIncomingInput, false);
  assert.equal(manifestRaw.importConfig.allowDisjointOverlayRoots, false);
  assert.equal(Object.prototype.hasOwnProperty.call(manifestRaw.importConfig, 'allowedDisjointOverlaySourceFolders'), false);
  assert.deepEqual(manifestRaw.importConfig.freshOverlayRoots, [
    {
      sourceFolder: '2026-07-31',
      sha256: '4a316f602bc01f1908c96809786073a2d0156045d1921ec51ebd44804852b601',
    },
    {
      sourceFolder: '2026-08-25',
      sha256: '26f50cbbf6b10638cecbc1300f4a4c53b29d0b1a705c61c54a641569be9a479a',
    },
    {
      sourceFolder: '2026-08-31',
      sha256: '20a4c5f94bac4d49aa564204ec142e637b4fea44a6f68fcdac3f0634a080cb20',
    },
    {
      sourceFolder: 'Historical 2026-08-31/2026-08-31',
      sha256: '9bdb4be772aa75308a00fc4fe0980da60a998161e740121bdd08da888b008837',
    },
    {
      sourceFolder: 'archive/v1/2026-07-31',
      sha256: '4a316f602bc01f1908c96809786073a2d0156045d1921ec51ebd44804852b601',
    },
    {
      sourceFolder: 'archive/v1/2026-08-25',
      sha256: '26f50cbbf6b10638cecbc1300f4a4c53b29d0b1a705c61c54a641569be9a479a',
    },
    {
      sourceFolder: 'archive/v1/2026-08-31',
      sha256: '20a4c5f94bac4d49aa564204ec142e637b4fea44a6f68fcdac3f0634a080cb20',
    },
    {
      sourceFolder: 'archive/v1/Historical 2026-08-31/2026-08-31',
      sha256: '9bdb4be772aa75308a00fc4fe0980da60a998161e740121bdd08da888b008837',
    },
  ]);
  assert.deepEqual(manifestRaw.importConfig.carriedPriors, [
    {
      sourceFolder: 'archive/provisional/2026-10-01',
      sha256: 'f26f933e2f1d9bb2cc751486bcd28eef0d5d000d2c522b4919f89227a1b66af0',
      extendsRowCount: 22334,
      reason: '220 CONFIRM references appended to the live approval log between the final 9/30 overlay and the 10/01 freeze, re-keying the same saved 9/30 Bible decisions from temporary #id keys to dated period keys after the Bible key law changed; proved references, not new business decisions (Coherence TODO.md, Replacement 2026-10-11 baseline)',
    },
  ]);
  assert.equal(Array.isArray(manifestRaw.overlayCheckpoints), true);
  assert.equal(manifestRaw.compareTargets.length, 11);
  for (const target of manifestRaw.compareTargets) {
    assert.equal(typeof target.label, 'string');
    assert.equal(typeof target.leftRunSourceFolder, 'string');
    assert.equal(typeof target.rightDir, 'string');
    assert.equal(target.requireStatementsDelta, true);
    assert.equal(target.requireConservation, true);
  }
});

test('Layer 4 [Fix3-6 - Proof Runner Refuses Unsafe --stores-dir]: refuses --stores-dir equal to or inside coherenceRoot, coherenceRepo, nusearDataDir, or any configured source path without creating folders', async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix3-storesdir-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const cohRoot = join(work, 'coherence');
  const cohRepo = join(work, 'coherence-repo');
  const nusearDir = join(work, 'nusear-data');
  const extLegacyRuns = join(work, 'extra-legacy-runs');
  const extStanding = join(work, 'extra-standing');
  const extRightDir = join(work, 'extra-compare-right');
  for (const d of [cohRoot, cohRepo, nusearDir, extLegacyRuns, extStanding, extRightDir]) {
    await mkdir(d, { recursive: true });
  }

  const manifestPath = join(work, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    companySlug: 'acme',
    coherenceRoot: cohRoot,
    coherenceRepo: cohRepo,
    nusearDataDir: nusearDir,
    sources: {
      legacyRunsRoot: extLegacyRuns,
      standingInputDir: extStanding,
    },
    compareTargets: [
      { label: 't1', leftRunSourceFolder: '2026-11-02', rightDir: extRightDir },
    ],
  }, null, 2), 'utf8');

  const unsafeDirs = [
    cohRoot,
    join(cohRoot, 'stores'),
    cohRepo,
    join(cohRepo, 'sub', 'stores'),
    nusearDir,
    join(nusearDir, 'stores'),
    extLegacyRuns,
    join(extLegacyRuns, 'stores'),
    extStanding,
    join(extStanding, 'stores'),
    extRightDir,
    join(extRightDir, 'stores'),
  ];

  for (const badStoresDir of unsafeDirs) {
    await assert.rejects(
      () => runHistoryProof({
        manifestPath,
        database: 'test_unsafe_stores_dir',
        storesDir: badStoresDir,
        tempRoot: work,
      }),
      (err) => {
        assert.equal(err.code, 'UNSAFE_STORES_DIR', `expected UNSAFE_STORES_DIR for ${badStoresDir}, got ${err?.code}: ${err?.message}`);
        return true;
      },
      `must refuse unsafe storesDir ${badStoresDir}`,
    );
  }

  // CLI check: refuses --stores-dir inside coherenceRoot and creates no directory inside it.
  const cliBadStores = join(cohRoot, 'should-not-be-created');
  await assert.rejects(
    () => execFileAsync(
      process.execPath,
      ['scripts/prove-history.mjs', '--manifest', manifestPath, '--database', 'test_unsafe_stores_cli', '--stores-dir', cliBadStores],
      { cwd: process.cwd(), env: { ...process.env, PGHOST: '/tmp', PGPORT: '5433' } },
    ),
    (err) => {
      assert.ok(String(err.stderr || '').includes('UNSAFE_STORES_DIR'), `expected UNSAFE_STORES_DIR on stderr, got: ${err.stderr}`);
      return true;
    },
  );
  const cohEntries = await readdir(cohRoot);
  assert.deepEqual(cohEntries, [], 'refused --stores-dir must never create any file or folder inside coherenceRoot');

  // Symlink pointing inside coherenceRoot must also be refused, while a sibling with a shared name prefix is allowed.
  const linkToCoh = join(work, 'symlink-to-coh');
  await symlink(cohRoot, linkToCoh);
  await assert.rejects(
    () => assertSafeStoresDir(join(linkToCoh, 'stores'), manifestPath),
    (err) => err.code === 'UNSAFE_STORES_DIR',
    'symlink pointing inside coherenceRoot must be refused',
  );
  await assertSafeStoresDir(join(work, 'coherence-stores'), manifestPath);
});

test('Layer 4 [Fix4-1 - Overlay Lineage Law & Pinned freshOverlayRoots]: four kinds of fresh root succeed only when listed with exact SHA-256, byte-identical archive/v1 copies make no new root, v2 extends v1 prior, branching from shared prior succeeds, every root is reported with folder/commitId/sha256/rowCount, and wrong SHA-256, unlisted fresh root, non-extending run files, or unmatched standing/company priors fail closed', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix4-lineage-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);

  const shaOf = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

  const mkV1Row = (id, note, at = '2026-08-01T10:00:00Z') => ({
    record_id: id,
    disposition: 'CORRECT',
    agent: '11111111',
    agency: 'Beacon',
    policy: null,
    book: null,
    month: null,
    status: 'ACTIVE_PAYING',
    note,
    committed_at: at,
  });
  const mkV2Row = (id, note, at = '2026-10-19T10:00:00Z') => sampleApprovalRow({
    record_id: id,
    disposition: 'CONFIRM',
    agent: null,
    agency: null,
    status: null,
    note,
    committed_at: at,
    approved_amount: '100.00',
    approved_agency: 'Beacon',
    approved_agent: '11111111',
  });

  // Four distinct fresh-start v1 overlays (zero shared leading rows).
  const root0731Rows = [
    mkV1Row('policy:carrier_a:R0731_1#effective:2026-01-01', 'root-0731-1'),
  ];
  const root0825Rows = [
    mkV1Row('policy:carrier_a:R0825_1#effective:2026-01-01', 'root-0825-1'),
    mkV1Row('policy:carrier_a:R0825_2#effective:2026-01-01', 'root-0825-2'),
  ];
  const root0831Rows = [
    mkV1Row('policy:carrier_a:R0831_1#effective:2026-01-01', 'root-0831-1'),
    mkV1Row('policy:carrier_a:R0831_2#effective:2026-01-01', 'root-0831-2'),
    mkV1Row('policy:carrier_a:R0831_3#effective:2026-01-01', 'root-0831-3'),
  ];
  const rootHist0831Rows = [
    mkV1Row('policy:carrier_a:RHIST_1#effective:2026-01-01', 'root-hist-1'),
    mkV1Row('policy:carrier_a:RHIST_2#effective:2026-01-01', 'root-hist-2'),
  ];

  const row0930 = mkV1Row('policy:carrier_a:R0930_1#effective:2026-01-01', 'sep30-added', '2026-09-30T10:00:00Z');
  const row1012 = mkV1Row('policy:carrier_a:R1012_1#effective:2026-01-01', 'oct12-added', '2026-10-12T10:00:00Z');
  const row1019 = mkV2Row('carrier_a~direct~P1019~100.00~2026-10', 'oct19-v2', '2026-10-19T10:00:00Z');
  const row1021 = mkV2Row('carrier_a~direct~P1021~100.00~2026-10', 'oct21-v2', '2026-10-21T10:00:00Z');
  const row1102 = mkV2Row('carrier_a~direct~P1102~100.00~2026-11', 'nov02-v2', '2026-11-02T10:00:00Z');
  const row1103 = mkV2Row('carrier_a~direct~P1103~100.00~2026-11', 'nov03-co', '2026-11-03T10:00:00Z');
  const wrongRow = mkV2Row('policy:carrier_a:WRONG#effective:2026-01-01', 'wrong');

  const csv0731 = makeOverlayCsv(root0731Rows, { version: 'v1' });
  const csv0825 = makeOverlayCsv(root0825Rows, { version: 'v1' });
  const csv0831 = makeOverlayCsv(root0831Rows, { version: 'v1' });
  const csvHist0831 = makeOverlayCsv(rootHist0831Rows, { version: 'v1' });
  const csv0930 = makeOverlayCsv([...root0831Rows, row0930], { version: 'v1' });
  const csv1012 = makeOverlayCsv([...root0831Rows, row0930, row1012], { version: 'v1' });
  // v2 files extending v1 10/12 prior (first 5 rows have empty approval fact columns, matching overlay._read of v1).
  const csv1019 = makeOverlayCsv([...root0831Rows, row0930, row1012, row1019], { version: 'v2' });
  const csv1021 = makeOverlayCsv([...root0831Rows, row0930, row1012, row1021], { version: 'v2' });
  const csv1102 = makeOverlayCsv([...root0831Rows, row0930, row1012, row1102], { version: 'v2' });
  const csv1103 = makeOverlayCsv([...root0831Rows, row0930, row1012, row1102, row1103], { version: 'v2' });
  const csvWrong = makeOverlayCsv([wrongRow], { version: 'v2' });

  const sha0731 = shaOf(csv0731);
  const sha0825 = shaOf(csv0825);
  const sha0831 = shaOf(csv0831);
  const shaHist0831 = shaOf(csvHist0831);

  const validFreshRoots = [
    { sourceFolder: '2026-07-31', sha256: sha0731 },
    { sourceFolder: '2026-08-25', sha256: sha0825 },
    { sourceFolder: '2026-08-31', sha256: sha0831 },
    { sourceFolder: 'Historical 2026-08-31/2026-08-31', sha256: shaHist0831 },
    { sourceFolder: 'archive/v1/2026-07-31', sha256: sha0731 },
    { sourceFolder: 'archive/v1/2026-08-25', sha256: sha0825 },
    { sourceFolder: 'archive/v1/2026-08-31', sha256: sha0831 },
    { sourceFolder: 'archive/v1/Historical 2026-08-31/2026-08-31', sha256: shaHist0831 },
  ];

  const makeRun = (date, { priorCsv = null, overlayCsv = null, emitOverlayCsv = null, born }) => ({
    ...(priorCsv !== null ? { 'input/Overlay/overlay.csv': priorCsv } : {}),
    'input/a.csv': 'k\n1\n',
    ...(overlayCsv !== null ? { 'overlay.csv': overlayCsv } : {}),
    ...(emitOverlayCsv !== null ? { 'emits/overlay.csv': emitOverlayCsv } : {}),
    'emits/canonical_bob.csv': 'policy_id,member,entity,amount,upline_amount\n1,Pat Sample,Beacon,80.00,20.00\n',
    'emits/coherent_ledger.csv': 'tx_id,record_id,policy_id,member,entity,gross_comm,downline_amount,upline_amount\n1,r1,1,Pat Sample,Beacon,100.00,80.00,20.00\n',
    'run.json': JSON.stringify({ date, born, steps: { assign: { at: born }, emit: { at: born } } }),
  });

  // 1) Refuse allowDisjointOverlayRoots: true and removed allowedDisjointOverlaySourceFolders in plan and import.
  const cfgCheckRoot = join(work, 'cfg-check');
  await writeTree(join(cfgCheckRoot, 'runs', '2026-07-31'), makeRun('2026-07-31', { overlayCsv: csv0731, born: '2026-07-31T10:00:00Z' }));
  const forbidTruePath = join(cfgCheckRoot, 'forbid-true.json');
  await writeFile(forbidTruePath, JSON.stringify({
    companySlug: 'acme',
    sources: { legacyRunsRoot: 'runs' },
    importConfig: { includeLegacyHostHistory: true, allowDisjointOverlayRoots: true },
  }), 'utf8');
  await assert.rejects(() => runHistoryPlan({ manifestPath: forbidTruePath }), (err) => err.code === 'DISJOINT_OVERLAY_ROOTS_FORBIDDEN');
  await assert.rejects(() => loadImportManifestFile(forbidTruePath, { tempBaseDir: work }), (err) => err.code === 'DISJOINT_OVERLAY_ROOTS_FORBIDDEN');

  const removedKeyPath = join(cfgCheckRoot, 'removed-key.json');
  await writeFile(removedKeyPath, JSON.stringify({
    companySlug: 'acme',
    sources: { legacyRunsRoot: 'runs' },
    importConfig: { includeLegacyHostHistory: true, allowedDisjointOverlaySourceFolders: ['archive/v1'] },
  }), 'utf8');
  await assert.rejects(() => runHistoryPlan({ manifestPath: removedKeyPath }), (err) => err.code === 'INVALID_IMPORT_CONFIG');

  // 2) Full happy path: all 4 fresh roots + all 4 byte-identical archive/v1 copies + v1 chain (08/31 -> 09/30 -> 10/12)
  //    + v2 branching from v1 10/12 prior (10/19, 10/21, 11/02) + company run 11/03 extending 11/02 + standing overlay.
  const okRoot = join(work, 'ok-full');
  await writeTree(join(okRoot, 'runs', '2026-07-31'), makeRun('2026-07-31', { overlayCsv: csv0731, emitOverlayCsv: csv0731, born: '2026-07-31T10:00:00Z' }));
  await writeTree(join(okRoot, 'runs', 'archive', 'v1', '2026-07-31'), makeRun('2026-07-31', { overlayCsv: csv0731, emitOverlayCsv: csv0731, born: '2026-07-31T10:00:00Z' }));
  await writeTree(join(okRoot, 'runs', '2026-08-25'), makeRun('2026-08-25', { overlayCsv: csv0825, emitOverlayCsv: csv0825, born: '2026-08-25T10:00:00Z' }));
  await writeTree(join(okRoot, 'runs', 'archive', 'v1', '2026-08-25'), makeRun('2026-08-25', { overlayCsv: csv0825, emitOverlayCsv: csv0825, born: '2026-08-25T10:00:00Z' }));
  await writeTree(join(okRoot, 'runs', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csv0831, emitOverlayCsv: csv0831, born: '2026-08-31T10:00:00Z' }));
  await writeTree(join(okRoot, 'runs', 'archive', 'v1', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csv0831, emitOverlayCsv: csv0831, born: '2026-08-31T10:00:00Z' }));
  await writeTree(join(okRoot, 'runs', 'Historical 2026-08-31', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csvHist0831, emitOverlayCsv: csvHist0831, born: '2026-08-31T09:00:00Z' }));
  await writeTree(join(okRoot, 'runs', 'archive', 'v1', 'Historical 2026-08-31', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csvHist0831, emitOverlayCsv: csvHist0831, born: '2026-08-31T09:00:00Z' }));
  await writeTree(join(okRoot, 'runs', '2026-09-30'), makeRun('2026-09-30', { priorCsv: csv0831, overlayCsv: csv0930, emitOverlayCsv: csv0930, born: '2026-09-30T10:00:00Z' }));
  await writeTree(join(okRoot, 'runs', '2026-10-12'), makeRun('2026-10-12', { priorCsv: csv0930, overlayCsv: csv1012, emitOverlayCsv: csv1012, born: '2026-10-12T10:00:00Z' }));
  await writeTree(join(okRoot, 'runs', '2026-10-19'), makeRun('2026-10-19', { priorCsv: csv1012, overlayCsv: csv1019, emitOverlayCsv: csv1019, born: '2026-10-19T10:00:00Z' }));
  await writeTree(join(okRoot, 'runs', '2026-10-21'), makeRun('2026-10-21', { priorCsv: csv1012, overlayCsv: csv1021, emitOverlayCsv: csv1021, born: '2026-10-21T10:00:00Z' }));
  await writeTree(join(okRoot, 'runs', '2026-11-02'), makeRun('2026-11-02', { priorCsv: csv1012, overlayCsv: csv1102, emitOverlayCsv: csv1102, born: '2026-11-02T10:00:00Z' }));
  await writeTree(join(okRoot, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', { priorCsv: csv1102, overlayCsv: csv1103, emitOverlayCsv: csv1103, born: '2026-11-03T10:00:00Z' }));
  await writeTree(join(okRoot, 'standing-input'), { 'Overlay/overlay.csv': csv1103 });

  const okManifestPath = join(okRoot, 'manifest.json');
  await writeFile(okManifestPath, JSON.stringify({
    companySlug: 'acme',
    coherenceRepo: mockRepo,
    pythonPath: 'python3',
    sources: {
      legacyRunsRoot: 'runs',
      standingInputDir: 'standing-input',
      companyWorkspacesDir: 'company-ws',
    },
    importConfig: {
      includeLegacyHostHistory: true,
      includeLegacySqliteTables: false,
      useCompanyIncomingInput: false,
      allowDisjointOverlayRoots: false,
      freshOverlayRoots: validFreshRoots,
    },
  }, null, 2), 'utf8');

  const okPlan = await runHistoryPlan({ manifestPath: okManifestPath });
  assert.equal(okPlan.passed, true);

  const proofDb = `test_fix4_full_${createHash('sha256').update(okRoot).digest('hex').slice(0, 8)}`;
  const proofSummary = await runHistoryProof({
    manifestPath: okManifestPath,
    database: proofDb,
    dropDb: true,
    tempRoot: work,
  });
  assert.equal(proofSummary.passed, true, `proof failed: ${JSON.stringify(proofSummary.problems)}`);
  assert.equal(proofSummary.layer2.passed, true);
  // Byte-identical archive/v1 copies must resolve to the same commit and make NO new root -> exactly 4 roots total!
  assert.equal(proofSummary.layer1.overlayRootCount, 4, 'byte-identical archive copies must make no new root');
  assert.equal(proofSummary.layer1.overlayRoots.length, 4);
  const reportedBySha = new Map(proofSummary.layer1.overlayRoots.map((r) => [r.sha256, r]));
  assert.equal(reportedBySha.get(sha0731)?.rowCount, 1);
  assert.equal(reportedBySha.get(sha0825)?.rowCount, 2);
  assert.equal(reportedBySha.get(sha0831)?.rowCount, 3);
  assert.equal(reportedBySha.get(shaHist0831)?.rowCount, 2);
  assert.deepEqual(reportedBySha.get(sha0731)?.folders, ['archive/v1/2026-07-31', '2026-07-31']);
  assert.deepEqual(reportedBySha.get(sha0825)?.folders, ['archive/v1/2026-08-25', '2026-08-25']);
  assert.deepEqual(reportedBySha.get(sha0831)?.folders, ['archive/v1/2026-08-31', '2026-08-31']);
  assert.deepEqual(
    [...(reportedBySha.get(shaHist0831)?.folders || [])].sort(),
    ['Historical 2026-08-31/2026-08-31', 'archive/v1/Historical 2026-08-31/2026-08-31'],
  );
  assert.equal(proofSummary.layer1.carriedPriorCount, 0);
  assert.deepEqual(proofSummary.layer1.carriedPriors, []);
  for (const r of proofSummary.layer1.overlayRoots) {
    assert.equal(typeof r.folder, 'string');
    assert.equal(Array.isArray(r.folders) && r.folders.length >= 1, true);
    assert.equal(r.folders[0], r.folder);
    assert.match(r.commitId, /^[0-9a-f-]{36}$/);
    assert.match(r.sha256, /^[0-9a-f]{64}$/);
    assert.equal(Number.isInteger(r.rowCount) && r.rowCount > 0, true);
  }

  // Helper to assert OVERLAY_PREFIX_MISMATCH on negative cases.
  const expectPrefixMismatch = async (caseName, freshOverlayRoots, setupTree) => {
    const dir = join(work, caseName);
    await mkdir(join(dir, 'runs'), { recursive: true });
    await mkdir(join(dir, 'company-ws'), { recursive: true });
    await mkdir(join(dir, 'standing-input'), { recursive: true });
    await setupTree(dir);
    const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
    t.after(() => env.cleanup());
    const manifest = await buildImportManifest({
      companySlug: 'acme',
      sources: {
        legacyRunsRoot: join(dir, 'runs'),
        companyWorkspacesDir: join(dir, 'company-ws'),
        standingInputDir: join(dir, 'standing-input'),
      },
      importConfig: {
        includeLegacyHostHistory: true,
        includeLegacySqliteTables: false,
        useCompanyIncomingInput: false,
        allowDisjointOverlayRoots: false,
        freshOverlayRoots,
      },
      tempBaseDir: work,
    });
    await assert.rejects(
      () => executeHistoryImport({
        pool: env.pool,
        stores: env.stores,
        commands: env.commands,
        dbToken: env.ownerToken,
        manifest,
        pythonPath: 'python3',
        coherenceRepo: mockRepo,
        verifyRebuild: false,
        tempBaseDir: work,
      }),
      (err) => {
        assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH', `${caseName}: expected OVERLAY_PREFIX_MISMATCH, got ${err?.code}: ${err?.message}`);
        return true;
      },
      `${caseName} must fail with OVERLAY_PREFIX_MISMATCH`,
    );
  };

  // 3) Each of the 4 fresh root kinds fails when unlisted OR when its SHA-256 is wrong.
  const fourCases = [
    ['unlisted-0731', '2026-07-31', csv0731, '2026-07-31T10:00:00Z'],
    ['unlisted-0825', '2026-08-25', csv0825, '2026-08-25T10:00:00Z'],
    ['unlisted-0831', '2026-08-31', csv0831, '2026-08-31T10:00:00Z'],
    ['unlisted-hist', 'Historical 2026-08-31/2026-08-31', csvHist0831, '2026-08-31T09:00:00Z'],
  ];
  for (const [label, folder, csvText, born] of fourCases) {
    const date = folder.slice(-10);
    await expectPrefixMismatch(label, [], async (dir) => {
      await writeTree(join(dir, 'runs', ...folder.split('/')), makeRun(date, { overlayCsv: csvText, born }));
    });
    const wrongSha = shaOf(`${csvText}#tampered`);
    await expectPrefixMismatch(`${label}-wrong-sha`, [{ sourceFolder: folder, sha256: wrongSha }], async (dir) => {
      await writeTree(join(dir, 'runs', ...folder.split('/')), makeRun(date, { overlayCsv: csvText, born }));
    });
  }

  // Exact folder matching only: parent prefix "archive/v1" must never match "archive/v1/2026-07-31".
  await expectPrefixMismatch('prefix-folder-does-not-match-fresh-root', [{ sourceFolder: 'archive/v1', sha256: sha0731 }], async (dir) => {
    await writeTree(join(dir, 'runs', 'archive', 'v1', '2026-07-31'), makeRun('2026-07-31', { overlayCsv: csv0731, born: '2026-07-31T10:00:00Z' }));
  });

  // 4) Run WITH a prior whose overlay.csv OR emits/overlay.csv does not extend that prior fails,
  //    including a v2 file that alters a v1 prior row's fact column.
  await expectPrefixMismatch('run-overlay-does-not-extend-prior', [{ sourceFolder: '2026-08-31', sha256: sha0831 }], async (dir) => {
    await writeTree(join(dir, 'runs', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csv0831, born: '2026-08-31T10:00:00Z' }));
    await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { priorCsv: csv0831, overlayCsv: csvWrong, emitOverlayCsv: csvWrong, born: '2026-09-30T10:00:00Z' }));
  });
  await expectPrefixMismatch('run-emit-overlay-does-not-extend-prior', [{ sourceFolder: '2026-08-31', sha256: sha0831 }], async (dir) => {
    await writeTree(join(dir, 'runs', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csv0831, born: '2026-08-31T10:00:00Z' }));
    await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { priorCsv: csv0831, overlayCsv: csv0930, emitOverlayCsv: csvWrong, born: '2026-09-30T10:00:00Z' }));
  });
  const csvV2AlteredV1Row = makeOverlayCsv([
    { ...root0831Rows[0], approved_amount: '99.00' },
    root0831Rows[1],
    root0831Rows[2],
    row1019,
  ], { version: 'v2' });
  await expectPrefixMismatch('run-v2-alters-v1-prior-fact', [{ sourceFolder: '2026-08-31', sha256: sha0831 }], async (dir) => {
    await writeTree(join(dir, 'runs', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csv0831, born: '2026-08-31T10:00:00Z' }));
    await writeTree(join(dir, 'runs', '2026-10-19'), makeRun('2026-10-19', { priorCsv: csv0831, overlayCsv: csvV2AlteredV1Row, emitOverlayCsv: csvV2AlteredV1Row, born: '2026-10-19T10:00:00Z' }));
  });

  // 5) Run WITH a prior that does NOT equal a known commit (extended beyond known commit, truncated, or unknown) fails.
  const csvTruncated0831 = makeOverlayCsv(root0831Rows.slice(0, 2), { version: 'v1' });
  await expectPrefixMismatch('prior-extends-rather-than-equals-commit', [{ sourceFolder: '2026-08-31', sha256: sha0831 }], async (dir) => {
    await writeTree(join(dir, 'runs', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csv0831, born: '2026-08-31T10:00:00Z' }));
    await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { priorCsv: csv0930, overlayCsv: csv0930, born: '2026-09-30T10:00:00Z' }));
  });
  await expectPrefixMismatch('prior-truncated-below-commit', [{ sourceFolder: '2026-08-31', sha256: sha0831 }], async (dir) => {
    await writeTree(join(dir, 'runs', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csv0831, born: '2026-08-31T10:00:00Z' }));
    await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { priorCsv: csvTruncated0831, overlayCsv: csv0831, born: '2026-09-30T10:00:00Z' }));
  });

  // 6) Standing overlay that matches no commit fails (both when commits exist and when none exist).
  await expectPrefixMismatch('standing-matches-no-commit', [{ sourceFolder: '2026-08-31', sha256: sha0831 }], async (dir) => {
    await writeTree(join(dir, 'runs', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csv0831, born: '2026-08-31T10:00:00Z' }));
    await writeTree(join(dir, 'standing-input'), { 'Overlay/overlay.csv': csv0930 });
  });
  await expectPrefixMismatch('standing-alone-cannot-be-root', [], async (dir) => {
    await writeTree(join(dir, 'standing-input'), { 'Overlay/overlay.csv': csv0831 });
  });

  // 7) Company run prior that matches no commit fails (both when commits exist and when none exist).
  await expectPrefixMismatch('company-prior-matches-no-commit', [{ sourceFolder: '2026-08-31', sha256: sha0831 }], async (dir) => {
    await writeTree(join(dir, 'runs', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csv0831, born: '2026-08-31T10:00:00Z' }));
    await writeTree(join(dir, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', { priorCsv: csv0930, overlayCsv: csv0930, born: '2026-11-03T10:00:00Z' }));
  });
  await expectPrefixMismatch('company-prior-alone-cannot-be-root', [], async (dir) => {
    await writeTree(join(dir, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', { priorCsv: csv0831, overlayCsv: csv0831, born: '2026-11-03T10:00:00Z' }));
  });
});

test('Layer 4 [Fix4-2 - Empty Prior approvals_files, Same-Date Draft Sorting & importSingleRunFolder Early Config Check]: empty starting prior followed by extending or fresh-root overlay does not violate approvals_files trigger, same-date draft/historical folder sorting before committed run does not falsely reject it, and importSingleRunFolder validates config before early return', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix4-r2-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const shaOf = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

  const row1 = sampleApprovalRow({ record_id: 'policy:carrier_a:E1#effective:2026-01-01', note: 'r1' });
  const row2 = sampleApprovalRow({ record_id: 'policy:carrier_a:E2#effective:2026-01-01', note: 'r2' });
  const rowDraft = sampleApprovalRow({ record_id: 'policy:carrier_a:DR1#effective:2026-01-01', note: 'draft' });
  const rowFresh = sampleApprovalRow({ record_id: 'policy:carrier_a:FR1#effective:2026-01-01', note: 'fresh' });

  const emptyCsv = makeOverlayCsv([], { version: 'v2' });
  const csv1 = makeOverlayCsv([row1], { version: 'v2' });
  const csv12 = makeOverlayCsv([row1, row2], { version: 'v2' });
  const csvDraft = makeOverlayCsv([rowDraft], { version: 'v2' });
  const csvFresh = makeOverlayCsv([rowFresh], { version: 'v2' });

  const makeRun = (date, { priorCsv = null, overlayCsv = null, born }) => ({
    ...(priorCsv !== null ? { 'input/Overlay/overlay.csv': priorCsv } : {}),
    'input/a.csv': 'k\n1\n',
    ...(overlayCsv !== null ? { 'overlay.csv': overlayCsv, 'emits/overlay.csv': overlayCsv } : {}),
    'run.json': JSON.stringify({ date, born, steps: { assign: { at: born }, emit: { at: born } } }),
  });

  // Case 1: Empty starting prior followed by an overlay extending a known earlier commit (must NOT fail trg_approvals_files_before
  //         by setting extends_sha256 to the 0-row prior with shared_row_count = 1).
  const emptyExtDir = join(work, 'empty-prior-extends');
  await writeTree(join(emptyExtDir, 'runs', '2026-08-25'), makeRun('2026-08-25', { overlayCsv: csv1, born: '2026-08-25T10:00:00Z' }));
  await writeTree(join(emptyExtDir, 'runs', '2026-08-31'), makeRun('2026-08-31', { priorCsv: emptyCsv, overlayCsv: csv12, born: '2026-08-31T10:00:00Z' }));

  const env1 = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env1.cleanup());
  const manifest1 = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacyRunsRoot: join(emptyExtDir, 'runs') },
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-08-25', sha256: shaOf(csv1) }],
    },
    tempBaseDir: work,
  });
  const rep1 = await executeHistoryImport({
    pool: env1.pool,
    stores: env1.stores,
    commands: env1.commands,
    dbToken: env1.ownerToken,
    manifest: manifest1,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: work,
  });
  assert.equal(rep1.passed, true, rep1.problems.join('; '));
  const af12 = (await env1.pool.query(
    'SELECT row_count, extends_sha256, shared_row_count FROM coherence.approvals_files WHERE file_sha256 = $1',
    [shaOf(csv12)],
  )).rows[0];
  assert.equal(Number(af12.row_count), 2);
  assert.equal(af12.extends_sha256, null, 'approvals_files row after empty prior must not claim extends_sha256 with mismatched shared_row_count');
  assert.equal(Number(af12.shared_row_count), 0);

  // Case 2: Same-date draft/historical folder sorting BEFORE the committed run (2026-08-31) whose starting prior is empty
  //         and whose overlay.csv is either a pinned fresh root (succeeds) or unlisted (fails closed).
  const sameDateDir = join(work, 'same-date-draft');
  await writeTree(join(sameDateDir, 'runs', 'Historical 2026-08-31', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csvDraft, born: '2026-08-31T08:00:00Z' }));
  await writeTree(join(sameDateDir, 'runs', '2026-08-31'), makeRun('2026-08-31', { priorCsv: emptyCsv, overlayCsv: csvFresh, born: '2026-08-31T10:00:00Z' }));

  const env2 = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env2.cleanup());
  const manifest2 = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacyRunsRoot: join(sameDateDir, 'runs') },
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [
        { sourceFolder: 'Historical 2026-08-31/2026-08-31', sha256: shaOf(csvDraft) },
        { sourceFolder: '2026-08-31', sha256: shaOf(csvFresh) },
      ],
    },
    tempBaseDir: work,
  });
  const rep2 = await executeHistoryImport({
    pool: env2.pool,
    stores: env2.stores,
    commands: env2.commands,
    dbToken: env2.ownerToken,
    manifest: manifest2,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: work,
  });
  assert.equal(rep2.passed, true, rep2.problems.join('; '));
  assert.equal(rep2.overlayRoots.length, 2);

  // Same-date draft before committed run with empty prior AND empty overlay.csv must also not be falsely rejected.
  const sameDateEmptyDir = join(work, 'same-date-empty');
  await writeTree(join(sameDateEmptyDir, 'runs', 'Historical 2026-08-31', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csvDraft, born: '2026-08-31T08:00:00Z' }));
  await writeTree(join(sameDateEmptyDir, 'runs', '2026-08-31'), makeRun('2026-08-31', { priorCsv: emptyCsv, overlayCsv: emptyCsv, born: '2026-08-31T10:00:00Z' }));
  const env2b = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env2b.cleanup());
  const manifest2b = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacyRunsRoot: join(sameDateEmptyDir, 'runs') },
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: 'Historical 2026-08-31/2026-08-31', sha256: shaOf(csvDraft) }],
    },
    tempBaseDir: work,
  });
  const rep2b = await executeHistoryImport({
    pool: env2b.pool,
    stores: env2b.stores,
    commands: env2b.commands,
    dbToken: env2b.ownerToken,
    manifest: manifest2b,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: work,
  });
  assert.equal(rep2b.passed, true, rep2b.problems.join('; '));

  // Unlisted fresh root after empty prior MUST fail closed with OVERLAY_PREFIX_MISMATCH.
  const env2c = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env2c.cleanup());
  const manifest2c = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacyRunsRoot: join(sameDateDir, 'runs') },
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: 'Historical 2026-08-31/2026-08-31', sha256: shaOf(csvDraft) }],
    },
    tempBaseDir: work,
  });
  await assert.rejects(
    () => executeHistoryImport({
      pool: env2c.pool,
      stores: env2c.stores,
      commands: env2c.commands,
      dbToken: env2c.ownerToken,
      manifest: manifest2c,
      pythonPath: 'python3',
      coherenceRepo: mockRepo,
      verifyRebuild: false,
      tempBaseDir: work,
    }),
    (err) => err.code === 'OVERLAY_PREFIX_MISMATCH',
  );

  // Case 3: importSingleRunFolder must call normalizeImportConfig BEFORE its already-imported early return.
  const alreadyRunItem = manifest1.macRuns.find((r) => r.sourceFolder === '2026-08-25');
  await assert.rejects(
    () => importSingleRunFolder({
      pool: env1.pool,
      stores: env1.stores,
      commands: env1.commands,
      dbToken: env1.ownerToken,
      companySlug: 'acme',
      runItem: alreadyRunItem,
      importConfig: { allowDisjointOverlayRoots: true },
      pythonPath: 'python3',
      coherenceRepo: mockRepo,
      tempBaseDir: work,
    }),
    (err) => err.code === 'DISJOINT_OVERLAY_ROOTS_FORBIDDEN',
    'importSingleRunFolder must validate importConfig before its early return for already-imported runs',
  );
});

test('Layer 4 [Fix4-3 - Proof Runner Path Safety (..stores and code/data Containment)]: treats ..stores inside a protected path as inside and refuses --stores-dir whose code or data folder equals or contains any protected path', async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix4-storesdir-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const nusearRepo = join(work, 'nusear-repo');
  const nusearData = join(nusearRepo, 'data');
  const cohRoot = join(work, 'coherence');
  const parentOfCode = join(work, 'parent-of-code');
  const nestedCohRepo = join(parentOfCode, 'code', 'coherence');
  const parentOfData = join(work, 'parent-of-data');
  const nestedRuns = join(parentOfData, 'data', 'runs');
  for (const d of [nusearData, cohRoot, nestedCohRepo, nestedRuns]) {
    await mkdir(d, { recursive: true });
  }

  const manifestPath = join(work, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    companySlug: 'acme',
    coherenceRoot: cohRoot,
    coherenceRepo: nestedCohRepo,
    nusearDataDir: nusearData,
    sources: {
      legacyRunsRoot: nestedRuns,
    },
  }, null, 2), 'utf8');

  // 1) ..stores inside a protected folder must be treated as INSIDE, never allowed.
  await assert.rejects(
    () => assertSafeStoresDir(join(cohRoot, '..stores'), manifestPath),
    (err) => err.code === 'UNSAFE_STORES_DIR',
    '..stores inside coherenceRoot must be refused as UNSAFE_STORES_DIR',
  );
  await assert.rejects(
    () => assertSafeStoresDir(join(nusearData, '..stores', 'sub'), manifestPath),
    (err) => err.code === 'UNSAFE_STORES_DIR',
    '..stores/sub inside nusearDataDir must be refused as UNSAFE_STORES_DIR',
  );

  // 2) --stores-dir set to the Nusear repo root would write into nusearRepo/data (== nusearDataDir) -> must be refused.
  await assert.rejects(
    () => assertSafeStoresDir(nusearRepo, manifestPath),
    (err) => err.code === 'UNSAFE_STORES_DIR',
    'Nusear repo root as --stores-dir must be refused because its data/ folder equals nusearDataDir',
  );

  // 3) --stores-dir whose code/ or data/ subfolder CONTAINS a protected path -> must be refused.
  await assert.rejects(
    () => assertSafeStoresDir(parentOfCode, manifestPath),
    (err) => err.code === 'UNSAFE_STORES_DIR',
    '--stores-dir whose code/ folder contains coherenceRepo must be refused',
  );
  await assert.rejects(
    () => assertSafeStoresDir(parentOfData, manifestPath),
    (err) => err.code === 'UNSAFE_STORES_DIR',
    '--stores-dir whose data/ folder contains sources.legacyRunsRoot must be refused',
  );

  // 4) Symlink at <storesDir>/data pointing to nusearDataDir -> must be refused.
  const symlinkStores = join(work, 'symlink-stores');
  await mkdir(symlinkStores, { recursive: true });
  await symlink(nusearData, join(symlinkStores, 'data'));
  await assert.rejects(
    () => assertSafeStoresDir(symlinkStores, manifestPath),
    (err) => err.code === 'UNSAFE_STORES_DIR',
    'symlink at <storesDir>/data pointing to nusearDataDir must be refused',
  );

  // 5) Genuine sibling ..stores outside protected paths remains allowed.
  await assertSafeStoresDir(join(work, '..stores'), manifestPath);
});

test('Layer 4 [Fix5-1 - Carried Priors & --plan Validation]: accepts a frozen prior holding a reference append made outside any run only with exact folder, SHA-256 and extendsRowCount, records it as a reference append with its reason, reports it in summary, lets a later byte-identical prior equal it, and checks freshOverlayRoots and carriedPriors folders in --plan', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const CARRIED_REASON = 'Made-up reference append: two CONFIRM references re-keying earlier decisions, appended outside any run.';
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix5-carried-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const shaOf = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

  const mkV1Row = (id, note, at = '2026-09-30T10:00:00Z') => ({
    record_id: id,
    disposition: 'CORRECT',
    agent: '11111111',
    agency: 'Beacon',
    policy: null,
    book: null,
    month: null,
    status: 'ACTIVE_PAYING',
    note,
    committed_at: at,
  });

  const rows0930 = [
    mkV1Row('policy:carrier_a:C0930_1#effective:2026-01-01', 'sep30-1'),
    mkV1Row('policy:carrier_a:C0930_2#effective:2026-01-01', 'sep30-2'),
    mkV1Row('policy:carrier_a:C0930_3#effective:2026-01-01', 'sep30-3'),
  ];
  const referenceRows = [
    mkV1Row('policy:carrier_a:REFERENCE_1#effective:2026-01-01', 'reference-1', '2026-10-01T08:00:00Z'),
    mkV1Row('policy:carrier_a:REFERENCE_2#effective:2026-01-01', 'reference-2', '2026-10-01T08:05:00Z'),
  ];
  const row1001Final = mkV1Row('policy:carrier_a:C1001_1#effective:2026-01-01', 'oct01-final', '2026-10-01T14:00:00Z');

  const csv0930 = makeOverlayCsv(rows0930, { version: 'v1' });
  const csvCarried = makeOverlayCsv([...rows0930, ...referenceRows], { version: 'v1' });
  const csv1001Final = makeOverlayCsv([...rows0930, ...referenceRows, row1001Final], { version: 'v1' });
  const csvEmptyV1 = makeOverlayCsv([], { version: 'v1' });

  const sha0930 = shaOf(csv0930);
  const shaCarried = shaOf(csvCarried);

  const makeRun = (date, { priorCsv = null, overlayCsv = null, emitOverlayCsv = null, born }) => ({
    ...(priorCsv !== null ? { 'input/Overlay/overlay.csv': priorCsv } : {}),
    'input/a.csv': 'k\n1\n',
    ...(overlayCsv !== null ? { 'overlay.csv': overlayCsv } : {}),
    ...(emitOverlayCsv !== null ? { 'emits/overlay.csv': emitOverlayCsv } : {}),
    'run.json': JSON.stringify({ date, born, steps: { assign: { at: born }, emit: { at: born } } }),
  });

  // 1) Happy path via full proof runner (Layers 0, 1, 2, 4 + idempotency).
  const okRoot = join(work, 'ok-carried');
  await writeTree(join(okRoot, 'runs', '2026-09-30'), makeRun('2026-09-30', {
    overlayCsv: csv0930,
    emitOverlayCsv: csv0930,
    born: '2026-09-30T10:00:00Z',
  }));
  await writeTree(join(okRoot, 'runs', 'archive', 'provisional', '2026-10-01'), makeRun('2026-10-01', {
    priorCsv: csvCarried,
    emitOverlayCsv: csvCarried,
    born: '2026-10-01T09:00:00Z',
  }));
  await writeTree(join(okRoot, 'runs', '2026-10-01'), makeRun('2026-10-01', {
    priorCsv: csvCarried,
    overlayCsv: csv1001Final,
    emitOverlayCsv: csv1001Final,
    born: '2026-10-01T12:00:00Z',
  }));
  await writeTree(join(okRoot, 'standing-input'), { 'Overlay/overlay.csv': csv1001Final });

  const okManifestPath = join(okRoot, 'manifest.json');
  await writeFile(okManifestPath, JSON.stringify({
    companySlug: 'acme',
    coherenceRepo: mockRepo,
    pythonPath: 'python3',
    sources: {
      legacyRunsRoot: 'runs',
      standingInputDir: 'standing-input',
    },
    importConfig: {
      includeLegacyHostHistory: true,
      includeLegacySqliteTables: false,
      useCompanyIncomingInput: false,
      allowDisjointOverlayRoots: false,
      freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha0930 }],
      carriedPriors: [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3, reason: CARRIED_REASON }],
    },
  }, null, 2), 'utf8');

  const planOk = await runHistoryPlan({ manifestPath: okManifestPath });
  assert.equal(planOk.passed, true, `plan should pass: ${JSON.stringify(planOk.missing)}`);
  assert.deepEqual(planOk.missing, []);

  const proofDb = `test_fix5_carried_${createHash('sha256').update(okRoot).digest('hex').slice(0, 8)}`;
  const summary = await runHistoryProof({
    manifestPath: okManifestPath,
    database: proofDb,
    dropDb: false,
    tempRoot: work,
  });
  t.after(async () => {
    const admin = await createPool({
      mode: 'local',
      host: process.env.PGHOST || '/tmp',
      port: Number(process.env.PGPORT || 5432),
      database: 'postgres',
      user: process.env.PGUSER || undefined,
    });
    try {
      await admin.query('SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()', [proofDb]);
      await admin.query(`DROP DATABASE IF EXISTS "${proofDb}"`);
    } finally {
      await admin.end();
    }
  });

  assert.equal(summary.passed, true, `proof failed: ${JSON.stringify(summary.problems)}`);
  assert.equal(summary.layer1.carriedPriorCount, 1);
  assert.equal(summary.layer1.carriedPriors.length, 1);
  const cpEntry = summary.layer1.carriedPriors[0];
  assert.equal(cpEntry.folder, 'archive/provisional/2026-10-01');
  assert.match(cpEntry.commitId, /^[0-9a-f-]{36}$/);
  assert.match(cpEntry.parentCommitId, /^[0-9a-f-]{36}$/);
  assert.equal(cpEntry.sha256, shaCarried);
  assert.equal(cpEntry.rowsAdded, 2);

  // Verify DB records: child commit of 9/30 with kind historical_overlay, marked as a reference append,
  // and 2026-10-01's prior equals that exact commit.
  const verifyPool = await createPool({
    mode: 'local',
    host: process.env.PGHOST || '/tmp',
    port: Number(process.env.PGPORT || 5432),
    database: proofDb,
    user: process.env.PGUSER || undefined,
  });
  try {
    const dcRow = (await verifyPool.query(
      'SELECT id, parent_commit_id, commit_kind, added_decision_count, cumulative_decision_count FROM coherence.decision_commits WHERE id = $1::uuid',
      [cpEntry.commitId],
    )).rows[0];
    assert.ok(dcRow);
    assert.equal(dcRow.parent_commit_id, cpEntry.parentCommitId);
    assert.equal(dcRow.commit_kind, 'historical_overlay');
    assert.equal(Number(dcRow.added_decision_count), 2);
    assert.equal(Number(dcRow.cumulative_decision_count), 5);

    const decRows = (await verifyPool.query(
      'SELECT run_id, decided_by FROM coherence.decisions WHERE decision_commit_id = $1::uuid ORDER BY row_order ASC',
      [cpEntry.commitId],
    )).rows;
    assert.equal(decRows.length, 2);
    for (const d of decRows) {
      assert.equal(d.run_id, null, 'a reference append made outside any run must not be attributed to the carrying run');
      assert.equal(d.decided_by, 'historical_import_reference_append');
    }

    const impRow = (await verifyPool.query(
      "SELECT metadata FROM coherence.imported_files WHERE area = 'other' AND rel_path = 'carried-priors/archive/provisional/2026-10-01/overlay.csv'",
    )).rows[0];
    assert.ok(impRow, 'carried prior provenance record must exist in imported_files');
    assert.equal(impRow.metadata.carriedPrior, true);
    assert.equal(impRow.metadata.referenceAppend, true);
    assert.equal(impRow.metadata.reason, CARRIED_REASON, 'the pinned reason is kept verbatim in the provenance record');
    assert.equal(impRow.metadata.decisionCommitId, cpEntry.commitId);
    assert.equal(impRow.metadata.parentCommitId, cpEntry.parentCommitId);
    assert.equal(impRow.metadata.rowsAdded, 2);

    const run1001 = (await verifyPool.query(
      "SELECT prior_decision_commit_id FROM coherence.runs WHERE source_folder = '2026-10-01'",
    )).rows[0];
    assert.equal(run1001.prior_decision_commit_id, cpEntry.commitId, '2026-10-01 prior must equal the carried prior commit');
  } finally {
    await verifyPool.end();
  }

  // 2) Negative cases: unlisted folder, wrong SHA-256, wrong extendsRowCount, header-only prior in carriedPriors folder, bad leading prefix.
  const expectCarriedFail = async (caseName, carriedPriors, provPriorCsv = csvCarried, assertErr = null, extraFreshRoots = [], { expectNoWrites = false } = {}) => {
    const dir = join(work, caseName);
    await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', {
      overlayCsv: csv0930,
      emitOverlayCsv: csv0930,
      born: '2026-09-30T10:00:00Z',
    }));
    await writeTree(join(dir, 'runs', 'archive', 'provisional', '2026-10-01'), makeRun('2026-10-01', {
      priorCsv: provPriorCsv,
      emitOverlayCsv: provPriorCsv,
      born: '2026-10-01T09:00:00Z',
    }));
    const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
    t.after(() => env.cleanup());
    const manifest = await buildImportManifest({
      companySlug: 'acme',
      sources: { legacyRunsRoot: join(dir, 'runs') },
      importConfig: {
        includeLegacyHostHistory: true,
        includeLegacySqliteTables: false,
        useCompanyIncomingInput: false,
        freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha0930 }, ...extraFreshRoots],
        carriedPriors,
      },
      tempBaseDir: work,
    });
    const before = expectNoWrites ? await snapshotImportWriteState(env) : null;
    await assert.rejects(
      () => executeHistoryImport({
        pool: env.pool,
        stores: env.stores,
        commands: env.commands,
        dbToken: env.ownerToken,
        manifest,
        pythonPath: 'python3',
        coherenceRepo: mockRepo,
        verifyRebuild: false,
        tempBaseDir: work,
      }),
      (err) => {
        assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH', `${caseName}: got ${err?.code}: ${err?.message}`);
        if (assertErr) assertErr(err);
        return true;
      },
    );
    if (expectNoWrites) {
      await assertNothingWrittenSince(env, before, caseName);
    }
  };

  await expectCarriedFail('carried-unlisted', []);
  // A pinned folder this import never meets fails before any write, as --plan does (the round 5 and 6 reviews).
  await expectCarriedFail(
    'carried-pin-folder-missing',
    [
      { sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3 },
      { sourceFolder: 'archive/provisional/2026-10-99', sha256: shaCarried, extendsRowCount: 3 },
    ],
    csvCarried,
    (err) => assert.deepEqual(err.unmetPins, ['importConfig.carriedPriors archive/provisional/2026-10-99']),
    [],
    { expectNoWrites: true },
  );
  await expectCarriedFail(
    'fresh-pin-folder-missing',
    [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3 }],
    csvCarried,
    (err) => assert.deepEqual(err.unmetPins, ['importConfig.freshOverlayRoots archive/v1/2026-09-99']),
    [{ sourceFolder: 'archive/v1/2026-09-99', sha256: sha0930 }],
    { expectNoWrites: true },
  );
  await expectCarriedFail('carried-wrong-folder', [
    { sourceFolder: '2026-10-01', sha256: shaCarried, extendsRowCount: 3 },
  ]);
  await expectCarriedFail('carried-wrong-sha', [
    { sourceFolder: 'archive/provisional/2026-10-01', sha256: shaOf(`${csvCarried}#bad`), extendsRowCount: 3 },
  ]);
  await expectCarriedFail('carried-wrong-count-low', [
    { sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 2 },
  ]);
  await expectCarriedFail('carried-wrong-count-equal', [
    { sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 5 },
  ]);
  await expectCarriedFail(
    'carried-header-only-prior',
    [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: shaOf(csvEmptyV1), extendsRowCount: 3 }],
    csvEmptyV1,
    (err) => {
      assert.equal(String(err.message).includes('SHA-256 mismatch'), false, `expected empty-prior guard, not SHA mismatch: ${err.message}`);
      assert.ok(String(err.message).includes('does not extend a known decision commit of exactly 3 rows'), err.message);
    },
  );
  const csvCarriedBadPrefix = makeOverlayCsv([
    rows0930[0],
    { ...rows0930[1], note: 'altered-leading-row-2' },
    rows0930[2],
    ...referenceRows,
  ], { version: 'v1' });
  await expectCarriedFail(
    'carried-bad-prefix',
    [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: shaOf(csvCarriedBadPrefix), extendsRowCount: 3 }],
    csvCarriedBadPrefix,
    (err) => {
      assert.equal(String(err.message).includes('SHA-256 mismatch'), false, `expected leading-prefix mismatch, not SHA mismatch: ${err.message}`);
      assert.equal(err.firstDifferingRow, 2);
      assert.ok(String(err.message).includes('does not extend a known decision commit of exactly 3 rows'), err.message);
    },
  );

  // 3) Invalid carriedPriors config entries fail with INVALID_IMPORT_CONFIG.
  for (const badEntries of [
    [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 0 }],
    [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: -1 }],
    [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: '3' }],
    [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: 'not-a-sha', extendsRowCount: 3 }],
    [{ sourceFolder: 'standing-overlay/overlay.csv', sha256: shaCarried, extendsRowCount: 3 }],
    [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3, reason: '' }],
    [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3, reason: '   ' }],
    [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3, reason: 7 }],
    [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3, reason: 'x'.repeat(601) }],
    [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3, reason: 'two\nlines' }],
    [
      { sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3, reason: CARRIED_REASON },
      { sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3, reason: 'A different reason.' },
    ],
  ]) {
    await assert.rejects(
      () => buildImportManifest({
        companySlug: 'acme',
        importConfig: { carriedPriors: badEntries },
        tempBaseDir: work,
      }),
      (err) => err.code === 'INVALID_IMPORT_CONFIG',
    );
  }

  // 3b) A repeated entry with the same SHA-256, row count and reason is one pin, not a conflict.
  const dedupManifest = await buildImportManifest({
    companySlug: 'acme',
    importConfig: {
      carriedPriors: [
        { sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3, reason: CARRIED_REASON },
        { sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3, reason: CARRIED_REASON },
      ],
    },
    tempBaseDir: work,
  });
  assert.deepEqual(dedupManifest.importConfig?.carriedPriors?.map((pin) => pin.reason), [CARRIED_REASON]);

  // 4) --plan checks that every freshOverlayRoots and carriedPriors folder names a discovered run.
  const planMissingPath = join(okRoot, 'plan-missing-pins.json');
  await writeFile(planMissingPath, JSON.stringify({
    companySlug: 'acme',
    coherenceRepo: mockRepo,
    pythonPath: 'python3',
    sources: {
      legacyRunsRoot: 'runs',
      standingInputDir: 'standing-input',
    },
    importConfig: {
      includeLegacyHostHistory: true,
      includeLegacySqliteTables: false,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [
        { sourceFolder: '2026-09-30', sha256: sha0930 },
        { sourceFolder: 'archive/v1/2026-09-99', sha256: sha0930 },
      ],
      carriedPriors: [
        { sourceFolder: 'archive/provisional/2026-10-01', sha256: shaCarried, extendsRowCount: 3 },
        { sourceFolder: 'archive/provisional/2026-10-99', sha256: shaCarried, extendsRowCount: 3 },
      ],
    },
  }, null, 2), 'utf8');

  const planBad = await runHistoryPlan({ manifestPath: planMissingPath });
  assert.equal(planBad.passed, false);
  assert.deepEqual(
    planBad.missing.map((m) => [m.key, m.kind, m.name]),
    [
      ['importConfig.freshOverlayRoots[1].sourceFolder', 'run', 'archive/v1/2026-09-99'],
      ['importConfig.carriedPriors[1].sourceFolder', 'run', 'archive/provisional/2026-10-99'],
    ],
  );
});

test('Layer 4 [Fix5-2 - Header-Only File in Pinned Root Folder Fails]: an empty header-only overlay.csv in a pinned freshOverlayRoots folder is checked against its SHA-256 before any empty-commit early return (both with no prior and with an empty 0-row prior)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix5-empty-root-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const shaOf = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

  const row1 = sampleApprovalRow({ record_id: 'policy:carrier_a:PIN1#effective:2026-01-01', note: 'pinned' });
  const realCsv = makeOverlayCsv([row1], { version: 'v2' });
  const headerOnlyCsv = makeOverlayCsv([], { version: 'v2' });
  const realSha = shaOf(realCsv);

  for (const [label, withEmptyPrior] of [['no-prior', false], ['empty-prior', true]]) {
    const dir = join(work, label);
    await writeTree(join(dir, 'runs', '2026-07-31'), {
      ...(withEmptyPrior ? { 'input/Overlay/overlay.csv': headerOnlyCsv } : {}),
      'input/a.csv': 'k\n1\n',
      'overlay.csv': headerOnlyCsv,
      'emits/overlay.csv': headerOnlyCsv,
      'run.json': JSON.stringify({ date: '2026-07-31', born: '2026-07-31T10:00:00Z', steps: { assign: { at: '2026-07-31T10:00:00Z' }, emit: { at: '2026-07-31T10:00:00Z' } } }),
    });
    const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
    t.after(() => env.cleanup());
    const manifest = await buildImportManifest({
      companySlug: 'acme',
      sources: { legacyRunsRoot: join(dir, 'runs') },
      importConfig: {
        includeLegacyHostHistory: true,
        includeLegacySqliteTables: false,
        useCompanyIncomingInput: false,
        freshOverlayRoots: [{ sourceFolder: '2026-07-31', sha256: realSha }],
      },
      tempBaseDir: work,
    });
    await assert.rejects(
      () => executeHistoryImport({
        pool: env.pool,
        stores: env.stores,
        commands: env.commands,
        dbToken: env.ownerToken,
        manifest,
        pythonPath: 'python3',
        coherenceRepo: mockRepo,
        verifyRebuild: false,
        tempBaseDir: work,
      }),
      (err) => {
        assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH', `${label}: got ${err?.code}: ${err?.message}`);
        return true;
      },
    );
  }
});

test('Layer 4 [Fix5-3 - 0-Row Commits Never Satisfy exact_known_commit After Non-Empty Commits & Company Run Does Not Reattach to Non-Empty Ancestor]: an earlier 0-row draft never lets an empty standing overlay or empty company prior pass once any non-empty commit exists, and a company run starting from a 0-row commit extends that 0-row commit rather than attaching to a non-empty ancestor', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix5-zero-row-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const shaOf = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

  const row1 = sampleApprovalRow({ record_id: 'policy:carrier_a:Z1#effective:2026-01-01', note: 'r1' });
  const row2 = sampleApprovalRow({ record_id: 'policy:carrier_a:Z2#effective:2026-01-01', note: 'r2' });
  const emptyCsv = makeOverlayCsv([], { version: 'v2' });
  const csv1 = makeOverlayCsv([row1], { version: 'v2' });
  const csv12 = makeOverlayCsv([row1, row2], { version: 'v2' });

  const makeRun = (date, { priorCsv = null, overlayCsv = null, born }) => ({
    ...(priorCsv !== null ? { 'input/Overlay/overlay.csv': priorCsv } : {}),
    'input/a.csv': 'k\n1\n',
    ...(overlayCsv !== null ? { 'overlay.csv': overlayCsv, 'emits/overlay.csv': overlayCsv } : {}),
    'run.json': JSON.stringify({ date, born, steps: { assign: { at: born }, emit: { at: born } } }),
  });

  // 1) Earlier 0-row draft + non-empty run -> empty standing overlay MUST fail.
  const standDir = join(work, 'empty-standing');
  await writeTree(join(standDir, 'runs', 'archive', 'draft', '2026-07-15'), makeRun('2026-07-15', { overlayCsv: emptyCsv, born: '2026-07-15T10:00:00Z' }));
  await writeTree(join(standDir, 'runs', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csv1, born: '2026-08-31T10:00:00Z' }));
  await writeTree(join(standDir, 'standing-input'), { 'Overlay/overlay.csv': emptyCsv });
  const env1 = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env1.cleanup());
  const m1 = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      legacyRunsRoot: join(standDir, 'runs'),
      standingInputDir: join(standDir, 'standing-input'),
    },
    importConfig: {
      includeLegacyHostHistory: true,
      includeLegacySqliteTables: false,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-08-31', sha256: shaOf(csv1) }],
    },
    tempBaseDir: work,
  });
  await assert.rejects(
    () => executeHistoryImport({
      pool: env1.pool,
      stores: env1.stores,
      commands: env1.commands,
      dbToken: env1.ownerToken,
      manifest: m1,
      pythonPath: 'python3',
      coherenceRepo: mockRepo,
      verifyRebuild: false,
      tempBaseDir: work,
    }),
    (err) => err.code === 'OVERLAY_PREFIX_MISMATCH',
    'empty standing overlay must fail once a non-empty commit exists even if an earlier 0-row draft exists',
  );

  // 2) Earlier 0-row draft + non-empty run -> company run with empty prior MUST fail (both empty overlay and overlay extending non-empty run).
  for (const [label, compOverlay] of [['company-empty-prior-extends', csv12], ['company-empty-prior-empty-ov', emptyCsv]]) {
    const dir = join(work, label);
    await writeTree(join(dir, 'runs', 'archive', 'draft', '2026-07-15'), makeRun('2026-07-15', { overlayCsv: emptyCsv, born: '2026-07-15T10:00:00Z' }));
    await writeTree(join(dir, 'runs', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csv1, born: '2026-08-31T10:00:00Z' }));
    await writeTree(join(dir, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', {
      priorCsv: emptyCsv,
      overlayCsv: compOverlay,
      born: '2026-11-03T10:00:00Z',
    }));
    const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
    t.after(() => env.cleanup());
    const manifest = await buildImportManifest({
      companySlug: 'acme',
      sources: {
        legacyRunsRoot: join(dir, 'runs'),
        companyWorkspacesDir: join(dir, 'company-ws'),
      },
      importConfig: {
        includeLegacyHostHistory: true,
        includeLegacySqliteTables: false,
        useCompanyIncomingInput: false,
        freshOverlayRoots: [{ sourceFolder: '2026-08-31', sha256: shaOf(csv1) }],
      },
      tempBaseDir: work,
    });
    await assert.rejects(
      () => executeHistoryImport({
        pool: env.pool,
        stores: env.stores,
        commands: env.commands,
        dbToken: env.ownerToken,
        manifest,
        pythonPath: 'python3',
        coherenceRepo: mockRepo,
        verifyRebuild: false,
        tempBaseDir: work,
      }),
      (err) => err.code === 'OVERLAY_PREFIX_MISMATCH',
      `${label}: empty company prior must fail once any non-empty commit exists`,
    );
  }

  // 3) Company run starting from a 0-row commit when NO non-empty commit exists extends that 0-row commit directly
  //    (never reattaching to a non-empty ancestor), and a subsequent company run with an empty prior then fails closed.
  const firstCoDir = join(work, 'first-company-from-zero');
  await writeTree(join(firstCoDir, 'runs', 'archive', 'draft', '2026-07-15'), makeRun('2026-07-15', { overlayCsv: emptyCsv, born: '2026-07-15T10:00:00Z' }));
  await writeTree(join(firstCoDir, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', {
    priorCsv: emptyCsv,
    overlayCsv: csv1,
    born: '2026-11-03T10:00:00Z',
  }));
  const env3 = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env3.cleanup());
  const m3 = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      legacyRunsRoot: join(firstCoDir, 'runs'),
      companyWorkspacesDir: join(firstCoDir, 'company-ws'),
    },
    importConfig: {
      includeLegacyHostHistory: true,
      includeLegacySqliteTables: false,
      useCompanyIncomingInput: false,
    },
    tempBaseDir: work,
  });
  const rep3 = await executeHistoryImport({
    pool: env3.pool,
    stores: env3.stores,
    commands: env3.commands,
    dbToken: env3.ownerToken,
    manifest: m3,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: work,
  });
  assert.equal(rep3.passed, true, rep3.problems.join('; '));
  const coRunRow = (await env3.pool.query(
    "SELECT id, prior_decision_commit_id FROM coherence.runs WHERE source_folder = 'company-workspaces/acme/2026-11-03/runs/2026-11-03'",
  )).rows[0];
  const coOverlayCommit = (await env3.pool.query(
    `SELECT dc.id, dc.parent_commit_id, dc.cumulative_decision_count
     FROM coherence.generated_overlays go
     JOIN coherence.decision_commits dc ON dc.id = go.decision_commit_id
     WHERE go.run_id = $1::uuid AND go.purpose = 'historical_source'`,
    [coRunRow.id],
  )).rows[0];
  assert.equal(coOverlayCommit.parent_commit_id, coRunRow.prior_decision_commit_id, 'company run overlay must extend its own 0-row prior commit');
  assert.equal(Number(coOverlayCommit.cumulative_decision_count), 1);

  // Now that a non-empty commit exists, adding another company run with an empty prior MUST fail closed.
  await writeTree(join(firstCoDir, 'company-ws', '2026-11-04', 'runs', '2026-11-04'), makeRun('2026-11-04', {
    priorCsv: emptyCsv,
    overlayCsv: csv12,
    born: '2026-11-04T10:00:00Z',
  }));
  const m3b = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      legacyRunsRoot: join(firstCoDir, 'runs'),
      companyWorkspacesDir: join(firstCoDir, 'company-ws'),
    },
    importConfig: {
      includeLegacyHostHistory: true,
      includeLegacySqliteTables: false,
      useCompanyIncomingInput: false,
    },
    tempBaseDir: work,
  });
  await assert.rejects(
    () => executeHistoryImport({
      pool: env3.pool,
      stores: env3.stores,
      commands: env3.commands,
      dbToken: env3.ownerToken,
      manifest: m3b,
      pythonPath: 'python3',
      coherenceRepo: mockRepo,
      verifyRebuild: false,
      tempBaseDir: work,
    }),
    (err) => err.code === 'OVERLAY_PREFIX_MISMATCH',
  );
});

test('Layer 4 [Fix5-4 - Fresh Roots Are historical_overlay & Standing Head Always Verified]: run- and checkpoint-created fresh roots use commit_kind historical_overlay, backfilling a fresh root never moves standing_decision_head_as_of(NULL), and drift in standing_decision_head_as_of(NULL) is caught even when standing-overlay/overlay.csv was already imported', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix5-head-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const shaOf = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

  const row0731 = sampleApprovalRow({ record_id: 'policy:carrier_a:H0731#effective:2026-01-01', note: 'backfill-run' });
  const rowCp = sampleApprovalRow({ record_id: 'policy:carrier_a:HCP#effective:2026-01-01', note: 'backfill-cp' });
  const row0831 = sampleApprovalRow({ record_id: 'policy:carrier_a:H0831#effective:2026-01-01', note: 'main-root' });
  const row0930 = sampleApprovalRow({ record_id: 'policy:carrier_a:H0930#effective:2026-01-01', note: 'main-head' });

  const csv0731 = makeOverlayCsv([row0731], { version: 'v2' });
  const csvCp = makeOverlayCsv([rowCp], { version: 'v2' });
  const csv0831 = makeOverlayCsv([row0831], { version: 'v2' });
  const csv0930 = makeOverlayCsv([row0831, row0930], { version: 'v2' });

  const makeRun = (date, { priorCsv = null, overlayCsv = null, born }) => ({
    ...(priorCsv !== null ? { 'input/Overlay/overlay.csv': priorCsv } : {}),
    'input/a.csv': 'k\n1\n',
    ...(overlayCsv !== null ? { 'overlay.csv': overlayCsv, 'emits/overlay.csv': overlayCsv } : {}),
    'run.json': JSON.stringify({ date, born, steps: { assign: { at: born }, emit: { at: born } } }),
  });

  const dir = join(work, 'backfill-test');
  await writeTree(join(dir, 'runs', '2026-08-31'), makeRun('2026-08-31', { overlayCsv: csv0831, born: '2026-08-31T10:00:00Z' }));
  await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { priorCsv: csv0831, overlayCsv: csv0930, born: '2026-09-30T10:00:00Z' }));
  await writeTree(join(dir, 'standing-input'), { 'Overlay/overlay.csv': csv0930 });

  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const m1 = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      legacyRunsRoot: join(dir, 'runs'),
      standingInputDir: join(dir, 'standing-input'),
    },
    importConfig: {
      includeLegacyHostHistory: true,
      includeLegacySqliteTables: false,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: '2026-08-31', sha256: shaOf(csv0831) }],
    },
    tempBaseDir: work,
  });
  const rep1 = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest: m1,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: work,
  });
  assert.equal(rep1.passed, true, rep1.problems.join('; '));
  assert.equal(rep1.overlayRoots.length, 1);

  const root0831Row = (await env.pool.query(
    'SELECT commit_kind FROM coherence.decision_commits WHERE id = $1::uuid',
    [rep1.overlayRoots[0].commitId],
  )).rows[0];
  assert.equal(root0831Row.commit_kind, 'historical_overlay', 'run-created fresh root must be historical_overlay, never historical_baseline');

  const head1 = (await env.pool.query('SELECT coherence.standing_decision_head_as_of(NULL) AS id')).rows[0].id;
  assert.equal(head1, rep1.standingDecisionCommitId);
  const head1Row = (await env.pool.query(
    'SELECT commit_kind, cumulative_decision_count FROM coherence.decision_commits WHERE id = $1::uuid',
    [head1],
  )).rows[0];
  assert.equal(head1Row.commit_kind, 'historical_baseline');
  assert.equal(Number(head1Row.cumulative_decision_count), 2);

  // Backfill an older fresh-root run (2026-07-31) AND a fresh-root standalone checkpoint with the SAME standing overlay.
  await writeTree(join(dir, 'runs', '2026-07-31'), makeRun('2026-07-31', { overlayCsv: csv0731, born: '2026-07-31T10:00:00Z' }));
  const cpPath = join(dir, 'backfill-cp.csv');
  await writeFile(cpPath, csvCp, 'utf8');

  const m2 = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      legacyRunsRoot: join(dir, 'runs'),
      standingInputDir: join(dir, 'standing-input'),
    },
    overlayCheckpoints: [
      { label: 'backfill-cp', absPath: cpPath, originalAt: '2026-07-20T10:00:00Z', commitKind: 'historical_baseline' },
    ],
    importConfig: {
      includeLegacyHostHistory: true,
      includeLegacySqliteTables: false,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [
        { sourceFolder: '2026-08-31', sha256: shaOf(csv0831) },
        { sourceFolder: '2026-07-31', sha256: shaOf(csv0731) },
        { sourceFolder: 'overlay-checkpoints/backfill-cp', sha256: shaOf(csvCp) },
      ],
    },
    tempBaseDir: work,
  });
  const rep2 = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    dbToken: env.ownerToken,
    manifest: m2,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: work,
  });
  assert.equal(rep2.passed, true, rep2.problems.join('; '));
  assert.equal(rep2.overlayRoots.length, 2);
  for (const r of rep2.overlayRoots) {
    const row = (await env.pool.query(
      'SELECT commit_kind FROM coherence.decision_commits WHERE id = $1::uuid',
      [r.commitId],
    )).rows[0];
    assert.equal(row.commit_kind, 'historical_overlay', `backfilled root ${r.folder} must be historical_overlay`);
  }

  const head2 = (await env.pool.query('SELECT coherence.standing_decision_head_as_of(NULL) AS id')).rows[0].id;
  assert.equal(head2, head1, 'backfilling fresh roots must never move standing_decision_head_as_of(NULL)');
  assert.equal(rep2.standingDecisionCommitId, head1);

  // Verify that if standing_decision_head_as_of(NULL) drifts away (e.g. an explicit baseline moves it),
  // re-running executeHistoryImport with the already-imported standing overlay catches it instead of returning stale metadata.
  await env.commands.recordDecisionBaseline({
    dbToken: env.ownerToken,
    commandKey: 'fix5-explicit-drift-baseline',
    parentCommitId: null,
    commitKind: 'historical_baseline',
    headerContract: 'v2',
    imported: true,
    decisions: [row0731],
  });
  await assert.rejects(
    () => executeHistoryImport({
      pool: env.pool,
      stores: env.stores,
      commands: env.commands,
      dbToken: env.ownerToken,
      manifest: m2,
      pythonPath: 'python3',
      coherenceRepo: mockRepo,
      verifyRebuild: false,
      tempBaseDir: work,
    }),
    (err) => err.code === 'STANDING_DECISION_HEAD_MISMATCH',
    'must verify standing_decision_head_as_of(NULL) even when standing-overlay/overlay.csv was already imported',
  );
});

test('Layer 4 [Fix6-1 - Pinned Files Cannot Be Bypassed & Company Runs Require Frozen Prior]: carriedPriors without frozen prior or on company_import fails closed, freshOverlayRoots with non-empty prior or no verified checkpoint fails closed, and company_import without frozen prior while having overlay.csv, emits/overlay.csv, or review saves fails closed', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix6-pins-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const shaOf = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

  const row1 = sampleApprovalRow({ record_id: 'policy:carrier_a:F6_1#effective:2026-01-01', note: 'base-1' });
  const row2 = sampleApprovalRow({ record_id: 'policy:carrier_a:F6_2#effective:2026-01-01', note: 'ext-2' });
  const row3 = sampleApprovalRow({ record_id: 'policy:carrier_a:F6_3#effective:2026-01-01', note: 'ext-3' });

  const emptyCsv = makeOverlayCsv([], { version: 'v2' });
  const csv1 = makeOverlayCsv([row1], { version: 'v2' });
  const csv12 = makeOverlayCsv([row1, row2], { version: 'v2' });
  const csv123 = makeOverlayCsv([row1, row2, row3], { version: 'v2' });

  const sha1 = shaOf(csv1);
  const sha12 = shaOf(csv12);

  const makeRun = (date, { priorCsv = null, overlayCsv = null, emitOverlayCsv = null, born, steps = null }) => ({
    ...(priorCsv !== null ? { 'input/Overlay/overlay.csv': priorCsv } : {}),
    'input/a.csv': 'k\n1\n',
    ...(overlayCsv !== null ? { 'overlay.csv': overlayCsv } : {}),
    ...(emitOverlayCsv !== null ? { 'emits/overlay.csv': emitOverlayCsv } : {}),
    'run.json': JSON.stringify({
      date,
      born,
      steps: steps || { assign: { at: born }, emit: { at: born } },
    }),
  });

  const expectMismatch = async (caseName, { setup, importConfig, overlayCheckpoints = [], assertErr = null, expectNoWrites = false }) => {
    const dir = join(work, caseName);
    await mkdir(join(dir, 'runs'), { recursive: true });
    await mkdir(join(dir, 'company-ws'), { recursive: true });
    await mkdir(join(dir, 'company-saves'), { recursive: true });
    await setup(dir);

    const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
    t.after(() => env.cleanup());

    const manifest = await buildImportManifest({
      companySlug: 'acme',
      sources: {
        legacyRunsRoot: join(dir, 'runs'),
        companyWorkspacesDir: join(dir, 'company-ws'),
        companyReviewSavesDir: join(dir, 'company-saves'),
      },
      overlayCheckpoints,
      importConfig: {
        includeLegacyHostHistory: true,
        includeLegacySqliteTables: false,
        useCompanyIncomingInput: false,
        ...importConfig,
      },
      tempBaseDir: work,
    });

    const before = expectNoWrites ? await snapshotImportWriteState(env) : null;
    await assert.rejects(
      () => executeHistoryImport({
        pool: env.pool,
        stores: env.stores,
        commands: env.commands,
        dbToken: env.ownerToken,
        manifest,
        pythonPath: 'python3',
        coherenceRepo: mockRepo,
        verifyRebuild: false,
        tempBaseDir: work,
      }),
      (err) => {
        assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH', `${caseName}: expected OVERLAY_PREFIX_MISMATCH, got ${err?.code}: ${err?.message}`);
        if (assertErr) assertErr(err);
        return true;
      },
      `${caseName} must fail closed with OVERLAY_PREFIX_MISMATCH`,
    );
    if (expectNoWrites) {
      await assertNothingWrittenSince(env, before, caseName);
    }
  };

  // 1a) carriedPriors folder missing input/Overlay/overlay.csv, with overlay.csv extending known commit (must NOT fall to no_prior_run_start).
  await expectMismatch('carried-missing-prior-with-overlay', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
      await writeTree(join(dir, 'runs', 'archive', 'provisional', '2026-10-01'), makeRun('2026-10-01', { overlayCsv: csv12, emitOverlayCsv: csv12, born: '2026-10-01T09:00:00Z' }));
    },
    importConfig: {
      freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
      carriedPriors: [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: sha12, extendsRowCount: 1 }],
    },
  });

  // 1b) carriedPriors folder missing input/Overlay/overlay.csv and having no overlay files at all.
  await expectMismatch('carried-missing-prior-no-overlay', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
      await writeTree(join(dir, 'runs', 'archive', 'provisional', '2026-10-01'), makeRun('2026-10-01', { born: '2026-10-01T09:00:00Z' }));
    },
    importConfig: {
      freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
      carriedPriors: [{ sourceFolder: 'archive/provisional/2026-10-01', sha256: sha12, extendsRowCount: 1 }],
    },
  });

  // 1c) company_import run listed in carriedPriors (even when its frozen prior equals a known commit!).
  await expectMismatch('carried-company-run-with-valid-prior', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
      await writeTree(join(dir, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', { priorCsv: csv1, overlayCsv: csv12, emitOverlayCsv: csv12, born: '2026-11-03T10:00:00Z' }));
    },
    importConfig: {
      freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
      carriedPriors: [{ sourceFolder: 'company-workspaces/acme/2026-11-03/runs/2026-11-03', sha256: sha1, extendsRowCount: 1 }],
    },
    assertErr: (err) => assert.deepEqual(err.unmetPins, [
      'importConfig.carriedPriors company-workspaces/acme/2026-11-03/runs/2026-11-03 names a company run',
    ]),
    expectNoWrites: true,
  });

  // 1d) company_import run listed in carriedPriors without a frozen prior.
  await expectMismatch('carried-company-run-no-prior', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
      await writeTree(join(dir, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', { born: '2026-11-03T10:00:00Z', steps: { assign: { at: '2026-11-03T10:00:00Z' } } }));
    },
    importConfig: {
      freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
      carriedPriors: [{ sourceFolder: 'company-workspaces/acme/2026-11-03/runs/2026-11-03', sha256: sha1, extendsRowCount: 1 }],
    },
    assertErr: (err) => assert.deepEqual(err.unmetPins, [
      'importConfig.carriedPriors company-workspaces/acme/2026-11-03/runs/2026-11-03 names a company run',
    ]),
    expectNoWrites: true,
  });

  // 2a) freshOverlayRoots folder with a non-empty frozen prior AND extending overlay.csv (must NOT bypass pin via parent.cumulativeCount > 0).
  await expectMismatch('fresh-root-non-empty-prior-with-overlay', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
      await writeTree(join(dir, 'runs', '2026-10-01'), makeRun('2026-10-01', { priorCsv: csv1, overlayCsv: csv12, emitOverlayCsv: csv12, born: '2026-10-01T10:00:00Z' }));
    },
    importConfig: {
      freshOverlayRoots: [
        { sourceFolder: '2026-09-30', sha256: sha1 },
        { sourceFolder: '2026-10-01', sha256: sha12 },
      ],
    },
  });

  // 2b) freshOverlayRoots folder with a non-empty frozen prior and NO run overlay.csv.
  await expectMismatch('fresh-root-non-empty-prior-no-overlay', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
      await writeTree(join(dir, 'runs', '2026-10-01'), makeRun('2026-10-01', { priorCsv: csv1, born: '2026-10-01T10:00:00Z' }));
    },
    importConfig: {
      freshOverlayRoots: [
        { sourceFolder: '2026-09-30', sha256: sha1 },
        { sourceFolder: '2026-10-01', sha256: sha1 },
      ],
    },
  });

  // 2c) freshOverlayRoots folder with NO overlay checkpoints at all (missing pinned file).
  await expectMismatch('fresh-root-missing-all-overlays', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', '2026-07-31'), makeRun('2026-07-31', { born: '2026-07-31T10:00:00Z' }));
    },
    importConfig: {
      freshOverlayRoots: [{ sourceFolder: '2026-07-31', sha256: sha1 }],
    },
  });

  // 2d) freshOverlayRoots folder with ONLY an empty 0-row frozen prior and NO run overlay checkpoints.
  await expectMismatch('fresh-root-only-empty-prior', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', '2026-07-31'), makeRun('2026-07-31', { priorCsv: emptyCsv, born: '2026-07-31T10:00:00Z' }));
    },
    importConfig: {
      freshOverlayRoots: [{ sourceFolder: '2026-07-31', sha256: sha1 }],
    },
  });

  // 2e) company_import run listed in freshOverlayRoots (even starting from a 0-row prior with matching overlay.csv).
  await expectMismatch('fresh-root-company-run', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', 'archive', 'draft', '2026-07-15'), makeRun('2026-07-15', { overlayCsv: emptyCsv, born: '2026-07-15T10:00:00Z' }));
      await writeTree(join(dir, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', { priorCsv: emptyCsv, overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-11-03T10:00:00Z' }));
    },
    importConfig: {
      freshOverlayRoots: [{ sourceFolder: 'company-workspaces/acme/2026-11-03/runs/2026-11-03', sha256: sha1 }],
    },
    assertErr: (err) => assert.deepEqual(err.unmetPins, [
      'importConfig.freshOverlayRoots company-workspaces/acme/2026-11-03/runs/2026-11-03 names a company run',
    ]),
    expectNoWrites: true,
  });

  // 3a) company_import run missing frozen prior while having overlay.csv (even when overlay.csv extends a known commit).
  await expectMismatch('company-missing-prior-with-root-overlay', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
      await writeTree(join(dir, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', { overlayCsv: csv12, born: '2026-11-03T10:00:00Z' }));
    },
    importConfig: {
      freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
    },
  });

  // 3b) company_import run missing frozen prior while having emits/overlay.csv (even when emits/overlay.csv extends a known commit).
  await expectMismatch('company-missing-prior-with-emit-overlay', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
      await writeTree(join(dir, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', { emitOverlayCsv: csv12, born: '2026-11-03T10:00:00Z' }));
    },
    importConfig: {
      freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
    },
  });

  // 3c) company_import run missing frozen prior while having timestamped company review saves.
  await expectMismatch('company-missing-prior-with-review-save', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
      await writeTree(join(dir, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', { born: '2026-11-03T10:00:00Z', steps: { assign: { at: '2026-11-03T10:00:00Z' }, bible: { at: '2026-11-03T10:05:00Z' } } }));
      await writeTree(join(dir, 'company-saves', '2026-11-03'), {
        'bible-review-2026-11-03T10-06-00-000Z.csv': csv12,
      });
    },
    importConfig: {
      freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
    },
  });

  // 3d) Positive control: company_import run without frozen prior AND without overlay.csv, emits/overlay.csv, or review saves still imports cleanly.
  const okCoDir = join(work, 'company-assign-only-no-overlays');
  await writeTree(join(okCoDir, 'company-ws', '2026-11-04', 'runs', '2026-11-04'), makeRun('2026-11-04', {
    born: '2026-11-04T10:00:00Z',
    steps: { assign: { at: '2026-11-04T10:00:00Z' } },
  }));
  const okCoEnv = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => okCoEnv.cleanup());
  const okCoManifest = await buildImportManifest({
    companySlug: 'acme',
    sources: { companyWorkspacesDir: join(okCoDir, 'company-ws') },
    importConfig: { includeLegacyHostHistory: false, includeLegacySqliteTables: false },
    tempBaseDir: work,
  });
  const okCoRep = await executeHistoryImport({
    pool: okCoEnv.pool,
    stores: okCoEnv.stores,
    commands: okCoEnv.commands,
    dbToken: okCoEnv.ownerToken,
    manifest: okCoManifest,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: work,
  });
  assert.equal(okCoRep.passed, true, okCoRep.problems.join('; '));
  assert.equal(okCoRep.importedRuns.length, 1);

  // 4) Standalone checkpoint with extendsCommitId listed in freshOverlayRoots fails closed.
  const cpDir = join(work, 'cp-extends-pinned');
  const cpPath = join(cpDir, 'ext-cp.csv');
  await mkdir(cpDir, { recursive: true });
  await writeFile(cpPath, csv123, 'utf8');
  await writeTree(join(cpDir, 'runs', '2026-09-30'), makeRun('2026-09-30', {
    priorCsv: csv12,
    overlayCsv: csv123,
    emitOverlayCsv: csv123,
    born: '2026-09-30T10:00:00Z',
  }));
  const cpEnv = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => cpEnv.cleanup());
  const baseCommit = await cpEnv.commands.recordDecisionBaseline({
    dbToken: cpEnv.ownerToken,
    commandKey: 'fix6-cp-base',
    commitKind: 'historical_overlay',
    headerContract: 'v2',
    imported: true,
    decisions: [row1, row2],
  });
  const cpManifest = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacyRunsRoot: join(cpDir, 'runs') },
    overlayCheckpoints: [{
      label: 'ext-cp',
      absPath: cpPath,
      extendsCommitId: baseCommit.result.decisionCommitId,
      originalAt: '2026-11-05T10:00:00Z',
    }],
    importConfig: {
      includeLegacyHostHistory: true,
      includeLegacySqliteTables: false,
      useCompanyIncomingInput: false,
      freshOverlayRoots: [{ sourceFolder: 'overlay-checkpoints/ext-cp', sha256: shaOf(csv123) }],
    },
    tempBaseDir: work,
  });
  const beforeCp = await snapshotImportWriteState(cpEnv);
  await assert.rejects(
    () => executeHistoryImport({
      pool: cpEnv.pool,
      stores: cpEnv.stores,
      commands: cpEnv.commands,
      dbToken: cpEnv.ownerToken,
      manifest: cpManifest,
      pythonPath: 'python3',
      coherenceRepo: mockRepo,
      verifyRebuild: false,
      tempBaseDir: work,
    }),
    (err) => {
      assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH');
      assert.deepEqual(err.unmetPins, [
        'importConfig.freshOverlayRoots overlay-checkpoints/ext-cp names a checkpoint that extends a commit',
      ]);
      return true;
    },
    'standalone checkpoint with extendsCommitId must not be accepted in freshOverlayRoots',
  );
  await assertNothingWrittenSince(cpEnv, beforeCp, 'cp-extends-pinned', { expectEmptyCommits: false });

  await expectMismatch('cp-extends-pinned-empty-db', {
    setup: async (dir) => {
      await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
    },
    overlayCheckpoints: [{
      label: 'ext-cp',
      absPath: cpPath,
      extendsCommitId: '00000000-0000-4000-8000-000000000001',
      originalAt: '2026-11-05T10:00:00Z',
    }],
    importConfig: {
      freshOverlayRoots: [
        { sourceFolder: '2026-09-30', sha256: sha1 },
        { sourceFolder: 'overlay-checkpoints/ext-cp', sha256: shaOf(csv123) },
      ],
    },
    assertErr: (err) => assert.deepEqual(err.unmetPins, [
      'importConfig.freshOverlayRoots overlay-checkpoints/ext-cp names a checkpoint that extends a commit',
    ]),
    expectNoWrites: true,
  });
});

test('Layer 4 [Fix6-2 - Plan Check Agrees With Import for Legacy Runs and Standalone Checkpoints]: --plan tracks legacy runs apart from company and abandoned runs, requires carriedPriors to name discovered legacy runs, allows freshOverlayRoots to name discovered legacy runs or standalone checkpoints by safeOverlayCheckpointRelPath, and keeps compareTargets spanning all run kinds', async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix6-plan-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const shaC = 'c'.repeat(64);
  const cpFallbackLabel = '../unsafe-label';
  const cpFallbackHash = createHash('sha256').update(cpFallbackLabel, 'utf8').digest('hex').slice(0, 16);
  const cpFallbackRelPath = `overlay-checkpoints/${cpFallbackHash}/fallback_cp.csv`;

  await writeTree(join(work, 'runs', '2026-09-30'), {
    'input/a.csv': 'k\n1\n',
    'run.json': JSON.stringify({ date: '2026-09-30', steps: {} }),
  });
  await writeTree(join(work, 'runs', 'archive', 'provisional', '2026-10-01'), {
    'input/a.csv': 'k\n1\n',
    'run.json': JSON.stringify({ date: '2026-10-01', steps: {} }),
  });
  await writeTree(join(work, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), {
    'input/a.csv': 'k\n1\n',
    'run.json': JSON.stringify({ date: '2026-11-03', steps: {} }),
  });
  await writeTree(join(work, 'company-abandoned', '2026-11-09'), {
    'input/a.csv': 'k\n1\n',
    'run.json': JSON.stringify({ date: '2026-11-09', steps: {} }),
  });
  await writeTree(join(work, 'checkpoints'), {
    'early.csv': 'record_id,disposition\n',
    'fallback_cp.csv': 'record_id,disposition\n',
    'extends_cp.csv': 'record_id,disposition\n',
  });

  const baseSources = {
    legacyRunsRoot: 'runs',
    companyWorkspacesDir: 'company-ws',
    companyAbandonedDir: 'company-abandoned',
  };

  // 1) Happy path: legacy run + standalone checkpoints (normal label & sanitized fallback) in freshOverlayRoots,
  //    legacy run in carriedPriors, and compareTargets covering legacy, company, and abandoned runs.
  const okManifest = join(work, 'plan-ok.json');
  await writeFile(okManifest, JSON.stringify({
    companySlug: 'acme',
    sources: baseSources,
    overlayCheckpoints: [
      { label: 'early-cp', path: 'checkpoints/early.csv' },
      { label: cpFallbackLabel, path: 'checkpoints/fallback_cp.csv' },
    ],
    importConfig: {
      includeLegacyHostHistory: true,
      freshOverlayRoots: [
        { sourceFolder: '2026-09-30', sha256: shaA },
        { sourceFolder: 'overlay-checkpoints/early-cp', sha256: shaB },
        { sourceFolder: cpFallbackRelPath, sha256: shaC },
      ],
      carriedPriors: [
        { sourceFolder: 'archive/provisional/2026-10-01', sha256: shaA, extendsRowCount: 3 },
      ],
    },
    compareTargets: [
      { label: 'legacy', leftRunSourceFolder: '2026-09-30', rightDir: 'runs/2026-09-30' },
      { label: 'company', leftRunSourceFolder: 'company-workspaces/acme/2026-11-03/runs/2026-11-03', rightDir: 'company-ws/2026-11-03/runs/2026-11-03' },
      { label: 'abandoned', leftRunSourceFolder: 'company-abandoned/acme/2026-11-09', rightDir: 'company-abandoned/2026-11-09' },
    ],
  }, null, 2), 'utf8');

  const planOk = await runHistoryPlan({ manifestPath: okManifest });
  assert.equal(planOk.passed, true, `expected plan to pass, missing: ${JSON.stringify(planOk.missing)}`);
  assert.deepEqual(planOk.missing, []);
  assert.equal(planOk.compareTargets.every((c) => c.status === 'found'), true);

  // 2) Negative path: company run, abandoned run, checkpoint with extendsCommitId, or missing checkpoint
  //    in carriedPriors / freshOverlayRoots must ALL fail --plan.
  const badManifest = join(work, 'plan-bad.json');
  await writeFile(badManifest, JSON.stringify({
    companySlug: 'acme',
    sources: baseSources,
    overlayCheckpoints: [
      { label: 'early-cp', path: 'checkpoints/early.csv' },
      { label: 'missing-cp', path: 'checkpoints/does-not-exist.csv' },
      { label: 'extends-cp', path: 'checkpoints/extends_cp.csv', extendsCommitId: '00000000-0000-4000-8000-000000000001' },
    ],
    importConfig: {
      includeLegacyHostHistory: true,
      freshOverlayRoots: [
        { sourceFolder: 'company-workspaces/acme/2026-11-03/runs/2026-11-03', sha256: shaA },
        { sourceFolder: 'company-abandoned/acme/2026-11-09', sha256: shaA },
        { sourceFolder: 'overlay-checkpoints/missing-cp', sha256: shaB },
        { sourceFolder: 'overlay-checkpoints/extends-cp', sha256: shaC },
      ],
      carriedPriors: [
        { sourceFolder: 'company-workspaces/acme/2026-11-03/runs/2026-11-03', sha256: shaA, extendsRowCount: 3 },
        { sourceFolder: 'company-abandoned/acme/2026-11-09', sha256: shaA, extendsRowCount: 3 },
        { sourceFolder: 'overlay-checkpoints/early-cp', sha256: shaB, extendsRowCount: 3 },
      ],
    },
  }, null, 2), 'utf8');

  const planBad = await runHistoryPlan({ manifestPath: badManifest });
  assert.equal(planBad.passed, false);
  assert.deepEqual(
    planBad.missing.map((m) => [m.key, m.kind, m.name]),
    [
      ['overlayCheckpoints[1]', 'file', 'missing-cp'],
      ['importConfig.freshOverlayRoots[0].sourceFolder', 'wrong_kind_company_run', 'company-workspaces/acme/2026-11-03/runs/2026-11-03'],
      ['importConfig.freshOverlayRoots[1].sourceFolder', 'wrong_kind_company_run', 'company-abandoned/acme/2026-11-09'],
      ['importConfig.freshOverlayRoots[2].sourceFolder', 'run', 'overlay-checkpoints/missing-cp'],
      ['importConfig.freshOverlayRoots[3].sourceFolder', 'wrong_kind_extending_checkpoint', 'overlay-checkpoints/extends-cp'],
      ['importConfig.carriedPriors[0].sourceFolder', 'wrong_kind_company_run', 'company-workspaces/acme/2026-11-03/runs/2026-11-03'],
      ['importConfig.carriedPriors[1].sourceFolder', 'wrong_kind_company_run', 'company-abandoned/acme/2026-11-09'],
      ['importConfig.carriedPriors[2].sourceFolder', 'wrong_kind_standalone_checkpoint', 'overlay-checkpoints/early-cp'],
    ],
  );
});

test('Layer 4 [Fix7-1 - Pre-Write Pin Checks, Direct Single-Run Guards & Shared-Key Cross-Kind Collisions]: proves zero-write assertions fail if pin checks run after the loop, refuses standalone checkpoints in carriedPriors before any write, exercises direct importSingleRunFolder company_import guards, and refuses shared keys across kinds regardless of timeline order', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix7-pins-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const shaOf = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

  const row1 = sampleApprovalRow({ record_id: 'policy:carrier_a:F7_1#effective:2026-01-01', note: 'base-1' });
  const row2 = sampleApprovalRow({ record_id: 'policy:carrier_a:F7_2#effective:2026-01-01', note: 'ext-2' });
  const row3 = sampleApprovalRow({ record_id: 'policy:carrier_a:F7_3#effective:2026-01-01', note: 'ext-3' });

  const csv1 = makeOverlayCsv([row1], { version: 'v2' });
  const csv12 = makeOverlayCsv([row1, row2], { version: 'v2' });
  const csv123 = makeOverlayCsv([row1, row2, row3], { version: 'v2' });

  const sha1 = shaOf(csv1);
  const sha12 = shaOf(csv12);
  const sha123 = shaOf(csv123);

  const makeRun = (date, { priorCsv = null, overlayCsv = null, emitOverlayCsv = null, born }) => ({
    ...(priorCsv !== null ? { 'input/Overlay/overlay.csv': priorCsv } : {}),
    'input/a.csv': 'k\n1\n',
    ...(overlayCsv !== null ? { 'overlay.csv': overlayCsv } : {}),
    ...(emitOverlayCsv !== null ? { 'emits/overlay.csv': emitOverlayCsv } : {}),
    'run.json': JSON.stringify({
      date,
      born,
      steps: { assign: { at: born }, emit: { at: born } },
    }),
  });

  const runPostLoopPinCheckScratch = async ({ env, manifest }) => {
    const runs = [
      ...(manifest.macRuns || []),
      ...(manifest.companyRuns || []),
      ...(manifest.abandonedRuns || []),
    ].sort((a, b) => a.statementDate.localeCompare(b.statementDate) || a.sourceFolder.localeCompare(b.sourceFolder));

    for (const runItem of runs) {
      await importSingleRunFolder({
        pool: env.pool,
        stores: env.stores,
        commands: env.commands,
        dbToken: env.ownerToken,
        companySlug: manifest.companySlug,
        runItem,
        importConfig: manifest.importConfig,
        pythonPath: 'python3',
        coherenceRepo: mockRepo,
        tempBaseDir: work,
      });
    }

    const legacyRuns = new Set(runs.filter((r) => r.origin === 'mac_import').map((r) => r.sourceFolder));
    const otherRuns = new Set(runs.filter((r) => r.origin !== 'mac_import').map((r) => r.sourceFolder));
    const unmetPins = [];
    for (const pin of manifest.importConfig.freshOverlayRoots || []) {
      const sf = pin.sourceFolder;
      if (otherRuns.has(sf)) unmetPins.push(`importConfig.freshOverlayRoots ${sf} names a company run`);
      else if (!legacyRuns.has(sf)) unmetPins.push(`importConfig.freshOverlayRoots ${sf}`);
    }
    for (const pin of manifest.importConfig.carriedPriors || []) {
      const sf = pin.sourceFolder;
      if (otherRuns.has(sf)) unmetPins.push(`importConfig.carriedPriors ${sf} names a company run`);
      else if (!legacyRuns.has(sf)) unmetPins.push(`importConfig.carriedPriors ${sf}`);
    }
    if (unmetPins.length > 0) {
      const err = new Error(`Post-loop pin mismatch: ${unmetPins.join('; ')}`);
      err.code = 'OVERLAY_PREFIX_MISMATCH';
      err.unmetPins = unmetPins;
      throw err;
    }
  };

  {
    const dir = join(work, 'scratch-post-loop-missing');
    await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
    await writeTree(join(dir, 'runs', 'archive', 'provisional', '2026-10-01'), makeRun('2026-10-01', { priorCsv: csv12, emitOverlayCsv: csv12, born: '2026-10-01T09:00:00Z' }));
    const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
    t.after(() => env.cleanup());
    const manifest = await buildImportManifest({
      companySlug: 'acme',
      sources: { legacyRunsRoot: join(dir, 'runs') },
      importConfig: {
        includeLegacyHostHistory: true,
        includeLegacySqliteTables: false,
        useCompanyIncomingInput: false,
        freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
        carriedPriors: [
          { sourceFolder: 'archive/provisional/2026-10-01', sha256: sha12, extendsRowCount: 1 },
          { sourceFolder: 'archive/provisional/2026-10-99', sha256: sha12, extendsRowCount: 1 },
        ],
      },
      tempBaseDir: work,
    });
    const before = await snapshotImportWriteState(env);
    await assert.rejects(
      () => runPostLoopPinCheckScratch({ env, manifest }),
      (err) => {
        assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH');
        assert.deepEqual(err.unmetPins, ['importConfig.carriedPriors archive/provisional/2026-10-99']);
        return true;
      },
    );
    await assert.rejects(
      () => assertNothingWrittenSince(env, before, 'scratch-post-loop-missing'),
      assert.AssertionError,
    );
    const after = await snapshotImportWriteState(env);
    assert.equal(after.runIds.length, 2);
    assert.equal(after.commitIds.length, 2);
    assert.ok(after.journalRows.length > before.journalRows.length);
    assert.ok(after.dataObjects.length > 0);
  }

  {
    const dir = join(work, 'scratch-post-loop-company');
    await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
    await writeTree(join(dir, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', { priorCsv: csv1, overlayCsv: csv12, emitOverlayCsv: csv12, born: '2026-11-03T10:00:00Z' }));
    const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
    t.after(() => env.cleanup());
    const manifest = await buildImportManifest({
      companySlug: 'acme',
      sources: {
        legacyRunsRoot: join(dir, 'runs'),
        companyWorkspacesDir: join(dir, 'company-ws'),
      },
      importConfig: {
        includeLegacyHostHistory: true,
        includeLegacySqliteTables: false,
        useCompanyIncomingInput: false,
        freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
        carriedPriors: [{ sourceFolder: 'company-workspaces/acme/2026-11-03/runs/2026-11-03', sha256: sha1, extendsRowCount: 1 }],
      },
      tempBaseDir: work,
    });
    const before = await snapshotImportWriteState(env);
    await assert.rejects(
      () => runPostLoopPinCheckScratch({ env, manifest }),
      (err) => err.code === 'OVERLAY_PREFIX_MISMATCH',
    );
    await assert.rejects(
      () => assertNothingWrittenSince(env, before, 'scratch-post-loop-company'),
      assert.AssertionError,
    );
    const after = await snapshotImportWriteState(env);
    assert.equal(after.runIds.length, 1);
    assert.equal(after.commitIds.length, 1);
    assert.ok(after.journalRows.length > before.journalRows.length);
    assert.ok(after.dataObjects.length > 0);
  }

  for (const [caseName, label, extendsCommitId] of [
    ['carried-standalone-checkpoint-plain', 'standalone-cp', null],
    ['carried-standalone-checkpoint-extending', 'standalone-ext-cp', '00000000-0000-4000-8000-000000000001'],
  ]) {
    const dir = join(work, caseName);
    await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
    const cpPath = join(dir, 'checkpoints', `${label}.csv`);
    await mkdir(dirname(cpPath), { recursive: true });
    await writeFile(cpPath, csv12, 'utf8');

    const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
    t.after(() => env.cleanup());
    const manifest = await buildImportManifest({
      companySlug: 'acme',
      sources: { legacyRunsRoot: join(dir, 'runs') },
      overlayCheckpoints: [{
        label,
        absPath: cpPath,
        ...(extendsCommitId ? { extendsCommitId } : {}),
        originalAt: '2026-10-02T10:00:00Z',
      }],
      importConfig: {
        includeLegacyHostHistory: true,
        includeLegacySqliteTables: false,
        useCompanyIncomingInput: false,
        freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
        carriedPriors: [{ sourceFolder: `overlay-checkpoints/${label}`, sha256: sha12, extendsRowCount: 1 }],
      },
      tempBaseDir: work,
    });
    const before = await snapshotImportWriteState(env);
    await assert.rejects(
      () => executeHistoryImport({
        pool: env.pool,
        stores: env.stores,
        commands: env.commands,
        dbToken: env.ownerToken,
        manifest,
        pythonPath: 'python3',
        coherenceRepo: mockRepo,
        verifyRebuild: false,
        tempBaseDir: work,
      }),
      (err) => {
        assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH', `${caseName}: got ${err?.code}: ${err?.message}`);
        assert.deepEqual(err.unmetPins, [`importConfig.carriedPriors overlay-checkpoints/${label} names a standalone checkpoint`]);
        return true;
      },
    );
    await assertNothingWrittenSince(env, before, caseName);
  }

  {
    const dir = join(work, 'direct-single-run-company');
    await writeTree(join(dir, 'company-ws', '2026-11-03', 'runs', '2026-11-03'), makeRun('2026-11-03', {
      priorCsv: csv1,
      overlayCsv: csv12,
      emitOverlayCsv: csv12,
      born: '2026-11-03T10:00:00Z',
    }));
    const manifest = await buildImportManifest({
      companySlug: 'acme',
      sources: { companyWorkspacesDir: join(dir, 'company-ws') },
      importConfig: { includeLegacyHostHistory: false, includeLegacySqliteTables: false },
      tempBaseDir: work,
    });
    const companyRunItem = manifest.companyRuns[0];
    assert.equal(companyRunItem.origin, 'company_import');
    assert.equal(companyRunItem.sourceFolder, 'company-workspaces/acme/2026-11-03/runs/2026-11-03');

    for (const [caseName, importConfig, expectedCheckpoint, expectedPhrase] of [
      [
        'direct-company-fresh-root',
        { freshOverlayRoots: [{ sourceFolder: companyRunItem.sourceFolder, sha256: sha12 }] },
        'overlay.csv',
        'importConfig.freshOverlayRoots',
      ],
      [
        'direct-company-carried-prior',
        { carriedPriors: [{ sourceFolder: companyRunItem.sourceFolder, sha256: sha1, extendsRowCount: 1 }] },
        'input/Overlay/overlay.csv',
        'importConfig.carriedPriors',
      ],
    ]) {
      const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
      t.after(() => env.cleanup());
      const before = await snapshotImportWriteState(env);
      await assert.rejects(
        () => importSingleRunFolder({
          pool: env.pool,
          stores: env.stores,
          commands: env.commands,
          dbToken: env.ownerToken,
          companySlug: 'acme',
          runItem: companyRunItem,
          importConfig,
          pythonPath: 'python3',
          coherenceRepo: mockRepo,
          tempBaseDir: work,
        }),
        (err) => {
          assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH', `${caseName}: got ${err?.code}: ${err?.message}`);
          assert.equal(err.run, `company_import:${companyRunItem.sourceFolder}`);
          assert.equal(err.checkpoint, expectedCheckpoint);
          assert.equal(err.firstDifferingRow, 1);
          assert.equal(err.unmetPins, undefined);
          assert.ok(String(err.message).includes(expectedPhrase), err.message);
          assert.ok(String(err.message).includes('company_import'), err.message);
          return true;
        },
      );
      await assertNothingWrittenSince(env, before, caseName);
    }
  }

  for (const [orderName, legacyBorn, companyBorn] of [
    ['legacy-before-company', '2026-11-03T08:00:00Z', '2026-11-03T12:00:00Z'],
    ['company-before-legacy', '2026-11-03T12:00:00Z', '2026-11-03T08:00:00Z'],
  ]) {
    const sharedKey = 'company-workspaces/acme/2026-11-03';
    for (const [pinKind, importConfig, expectedUnmet] of [
      [
        'fresh',
        {
          freshOverlayRoots: [
            { sourceFolder: '2026-09-30', sha256: sha1 },
            { sourceFolder: sharedKey, sha256: sha12 },
          ],
        },
        [`importConfig.freshOverlayRoots ${sharedKey} names a company run`],
      ],
      [
        'carried',
        {
          freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
          carriedPriors: [{ sourceFolder: sharedKey, sha256: sha1, extendsRowCount: 1 }],
        },
        [`importConfig.carriedPriors ${sharedKey} names a company run`],
      ],
    ]) {
      const caseName = `shared-key-run-${pinKind}-${orderName}`;
      const dir = join(work, caseName);
      await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
      await writeTree(join(dir, 'runs', 'company-workspaces', 'acme', '2026-11-03'), makeRun('2026-11-03', {
        priorCsv: csv1,
        overlayCsv: csv12,
        emitOverlayCsv: csv12,
        born: legacyBorn,
      }));
      await writeTree(join(dir, 'company-ws', '2026-11-03'), makeRun('2026-11-03', {
        priorCsv: csv1,
        overlayCsv: csv12,
        emitOverlayCsv: csv12,
        born: companyBorn,
      }));

      const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
      t.after(() => env.cleanup());
      const manifest = await buildImportManifest({
        companySlug: 'acme',
        sources: {
          legacyRunsRoot: join(dir, 'runs'),
          companyWorkspacesDir: join(dir, 'company-ws'),
        },
        importConfig: {
          includeLegacyHostHistory: true,
          includeLegacySqliteTables: false,
          useCompanyIncomingInput: false,
          ...importConfig,
        },
        tempBaseDir: work,
      });
      assert.equal(manifest.macRuns.some((r) => r.origin === 'mac_import' && r.sourceFolder === sharedKey), true);
      assert.equal(manifest.companyRuns.some((r) => r.origin === 'company_import' && r.sourceFolder === sharedKey), true);

      const before = await snapshotImportWriteState(env);
      await assert.rejects(
        () => executeHistoryImport({
          pool: env.pool,
          stores: env.stores,
          commands: env.commands,
          dbToken: env.ownerToken,
          manifest,
          pythonPath: 'python3',
          coherenceRepo: mockRepo,
          verifyRebuild: false,
          tempBaseDir: work,
        }),
        (err) => {
          assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH', `${caseName}: got ${err?.code}: ${err?.message}`);
          assert.deepEqual(err.unmetPins, expectedUnmet);
          return true;
        },
      );
      await assertNothingWrittenSince(env, before, caseName);
    }
  }

  for (const [orderName, plainAt, extendingAt, extendingFirst] of [
    ['plain-before-extending', '2026-11-05T08:00:00Z', '2026-11-05T12:00:00Z', false],
    ['extending-before-plain', '2026-11-05T12:00:00Z', '2026-11-05T08:00:00Z', true],
  ]) {
    const caseName = `shared-key-checkpoint-${orderName}`;
    const dir = join(work, caseName);
    await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
    const plainPath = join(dir, 'checkpoints', 'plain.csv');
    const extPath = join(dir, 'checkpoints', 'ext.csv');
    await mkdir(dirname(plainPath), { recursive: true });
    await writeFile(plainPath, csv1, 'utf8');
    await writeFile(extPath, csv123, 'utf8');

    const plainCp = { label: 'shared-cp', absPath: plainPath, originalAt: plainAt };
    const extCp = { label: 'shared-cp', absPath: extPath, extendsCommitId: '00000000-0000-4000-8000-000000000001', originalAt: extendingAt };
    const overlayCheckpoints = extendingFirst ? [extCp, plainCp] : [plainCp, extCp];

    const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
    t.after(() => env.cleanup());
    const manifest = await buildImportManifest({
      companySlug: 'acme',
      sources: { legacyRunsRoot: join(dir, 'runs') },
      overlayCheckpoints,
      importConfig: {
        includeLegacyHostHistory: true,
        includeLegacySqliteTables: false,
        useCompanyIncomingInput: false,
        freshOverlayRoots: [
          { sourceFolder: '2026-09-30', sha256: sha1 },
          { sourceFolder: 'overlay-checkpoints/shared-cp', sha256: sha123 },
        ],
      },
      tempBaseDir: work,
    });
    const before = await snapshotImportWriteState(env);
    await assert.rejects(
      () => executeHistoryImport({
        pool: env.pool,
        stores: env.stores,
        commands: env.commands,
        dbToken: env.ownerToken,
        manifest,
        pythonPath: 'python3',
        coherenceRepo: mockRepo,
        verifyRebuild: false,
        tempBaseDir: work,
      }),
      (err) => {
        assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH', `${caseName}: got ${err?.code}: ${err?.message}`);
        assert.deepEqual(err.unmetPins, ['importConfig.freshOverlayRoots overlay-checkpoints/shared-cp names a checkpoint that extends a commit']);
        return true;
      },
    );
    await assertNothingWrittenSince(env, before, caseName);
  }

  for (const [orderName, legacyBorn, cpAt] of [
    ['legacy-before-checkpoint', '2026-10-05T08:00:00Z', '2026-10-05T12:00:00Z'],
    ['checkpoint-before-legacy', '2026-10-05T12:00:00Z', '2026-10-05T08:00:00Z'],
  ]) {
    const caseName = `shared-key-legacy-vs-checkpoint-${orderName}`;
    const sharedKey = 'overlay-checkpoints/2026-10-05';
    const dir = join(work, caseName);
    await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
    await writeTree(join(dir, 'runs', 'overlay-checkpoints', '2026-10-05'), makeRun('2026-10-05', {
      priorCsv: csv12,
      emitOverlayCsv: csv12,
      born: legacyBorn,
    }));
    const cpPath = join(dir, 'checkpoints', '2026-10-05.csv');
    await mkdir(dirname(cpPath), { recursive: true });
    await writeFile(cpPath, csv12, 'utf8');

    const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
    t.after(() => env.cleanup());
    const manifest = await buildImportManifest({
      companySlug: 'acme',
      sources: { legacyRunsRoot: join(dir, 'runs') },
      overlayCheckpoints: [{ label: '2026-10-05', absPath: cpPath, originalAt: cpAt }],
      importConfig: {
        includeLegacyHostHistory: true,
        includeLegacySqliteTables: false,
        useCompanyIncomingInput: false,
        freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
        carriedPriors: [{ sourceFolder: sharedKey, sha256: sha12, extendsRowCount: 1 }],
      },
      tempBaseDir: work,
    });
    assert.equal(manifest.macRuns.some((r) => r.origin === 'mac_import' && r.sourceFolder === sharedKey), true);

    const before = await snapshotImportWriteState(env);
    await assert.rejects(
      () => executeHistoryImport({
        pool: env.pool,
        stores: env.stores,
        commands: env.commands,
        dbToken: env.ownerToken,
        manifest,
        pythonPath: 'python3',
        coherenceRepo: mockRepo,
        verifyRebuild: false,
        tempBaseDir: work,
      }),
      (err) => {
        assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH', `${caseName}: got ${err?.code}: ${err?.message}`);
        assert.deepEqual(err.unmetPins, [`importConfig.carriedPriors ${sharedKey} names a standalone checkpoint`]);
        return true;
      },
    );
    await assertNothingWrittenSince(env, before, caseName);
  }
});

test('Layer 4 [Fix8 - Plan Check Refuses Shared Pin Keys Across Kinds Exactly As Import Does]: --plan uses the same four target sets and forbidden-kind-first rule as executeHistoryImport for legacy/company runs, legacy/abandoned runs, plain/extending checkpoints, legacy/plain checkpoints, and legacy/extending checkpoints', async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix8-plan-shared-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const extCommitId = '00000000-0000-4000-8000-000000000001';

  const makeMetaRun = (date) => ({
    'input/a.csv': 'k\n1\n',
    'run.json': JSON.stringify({ date, steps: {} }),
  });

  const runPlanForCase = async (caseName, manifestObj) => {
    const manifestPath = join(work, `${caseName}.manifest.json`);
    await writeFile(manifestPath, JSON.stringify(manifestObj, null, 2), 'utf8');
    const plan = await runHistoryPlan({ manifestPath });
    assert.equal(JSON.stringify(plan).includes(work), false, `${caseName}: plan output must not leak raw paths`);
    return plan;
  };

  // 1) Fix7-1 shared-key fixture: legacy run + company run sharing company-workspaces/acme/2026-11-03.
  await t.test('legacy run + company run shared key fails --plan for freshOverlayRoots and carriedPriors', async () => {
    const dir = join(work, 'legacy-plus-company');
    const sharedKey = 'company-workspaces/acme/2026-11-03';
    await writeTree(join(dir, 'runs', '2026-09-30'), makeMetaRun('2026-09-30'));
    await writeTree(join(dir, 'runs', 'company-workspaces', 'acme', '2026-11-03'), makeMetaRun('2026-11-03'));
    await writeTree(join(dir, 'company-ws', '2026-11-03'), makeMetaRun('2026-11-03'));

    const sources = {
      legacyRunsRoot: join(dir, 'runs'),
      companyWorkspacesDir: join(dir, 'company-ws'),
    };

    const planFresh = await runPlanForCase('legacy-plus-company-fresh', {
      companySlug: 'acme',
      sources,
      importConfig: {
        includeLegacyHostHistory: true,
        freshOverlayRoots: [
          { sourceFolder: '2026-09-30', sha256: shaA },
          { sourceFolder: sharedKey, sha256: shaB },
        ],
      },
    });
    assert.equal(planFresh.passed, false);
    assert.deepEqual(
      planFresh.missing.map((m) => [m.key, m.kind, m.name]),
      [['importConfig.freshOverlayRoots[1].sourceFolder', 'wrong_kind_company_run', sharedKey]],
    );

    const planCarried = await runPlanForCase('legacy-plus-company-carried', {
      companySlug: 'acme',
      sources,
      importConfig: {
        includeLegacyHostHistory: true,
        freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: shaA }],
        carriedPriors: [{ sourceFolder: sharedKey, sha256: shaB, extendsRowCount: 1 }],
      },
    });
    assert.equal(planCarried.passed, false);
    assert.deepEqual(
      planCarried.missing.map((m) => [m.key, m.kind, m.name]),
      [['importConfig.carriedPriors[0].sourceFolder', 'wrong_kind_company_run', sharedKey]],
    );
  });

  // 2) Shared-key fixture: legacy run + abandoned company run sharing company-abandoned/acme/2026-11-09.
  await t.test('legacy run + abandoned run shared key fails --plan for freshOverlayRoots and carriedPriors', async () => {
    const dir = join(work, 'legacy-plus-abandoned');
    const sharedKey = 'company-abandoned/acme/2026-11-09';
    await writeTree(join(dir, 'runs', '2026-09-30'), makeMetaRun('2026-09-30'));
    await writeTree(join(dir, 'runs', 'company-abandoned', 'acme', '2026-11-09'), makeMetaRun('2026-11-09'));
    await writeTree(join(dir, 'company-abandoned', '2026-11-09'), makeMetaRun('2026-11-09'));

    const sources = {
      legacyRunsRoot: join(dir, 'runs'),
      companyAbandonedDir: join(dir, 'company-abandoned'),
    };

    const planFresh = await runPlanForCase('legacy-plus-abandoned-fresh', {
      companySlug: 'acme',
      sources,
      importConfig: {
        includeLegacyHostHistory: true,
        freshOverlayRoots: [
          { sourceFolder: '2026-09-30', sha256: shaA },
          { sourceFolder: sharedKey, sha256: shaB },
        ],
      },
    });
    assert.equal(planFresh.passed, false);
    assert.deepEqual(
      planFresh.missing.map((m) => [m.key, m.kind, m.name]),
      [['importConfig.freshOverlayRoots[1].sourceFolder', 'wrong_kind_company_run', sharedKey]],
    );

    const planCarried = await runPlanForCase('legacy-plus-abandoned-carried', {
      companySlug: 'acme',
      sources,
      importConfig: {
        includeLegacyHostHistory: true,
        freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: shaA }],
        carriedPriors: [{ sourceFolder: sharedKey, sha256: shaB, extendsRowCount: 1 }],
      },
    });
    assert.equal(planCarried.passed, false);
    assert.deepEqual(
      planCarried.missing.map((m) => [m.key, m.kind, m.name]),
      [['importConfig.carriedPriors[0].sourceFolder', 'wrong_kind_company_run', sharedKey]],
    );
  });

  // 3) Fix7-1 shared-key fixture: plain checkpoint + extending checkpoint sharing overlay-checkpoints/shared-cp (both orders).
  await t.test('plain checkpoint + extending checkpoint shared key fails --plan in both orders', async () => {
    const dir = join(work, 'plain-plus-extending-cp');
    const sharedKey = 'overlay-checkpoints/shared-cp';
    await writeTree(join(dir, 'runs', '2026-09-30'), makeMetaRun('2026-09-30'));
    await writeTree(join(dir, 'checkpoints'), {
      'plain.csv': 'record_id,disposition\n',
      'ext.csv': 'record_id,disposition\n',
    });

    const plainCp = { label: 'shared-cp', path: join(dir, 'checkpoints', 'plain.csv') };
    const extCp = { label: 'shared-cp', path: join(dir, 'checkpoints', 'ext.csv'), extendsCommitId: extCommitId };

    for (const [orderName, overlayCheckpoints] of [
      ['plain-first', [plainCp, extCp]],
      ['extending-first', [extCp, plainCp]],
    ]) {
      const planFresh = await runPlanForCase(`cp-shared-fresh-${orderName}`, {
        companySlug: 'acme',
        sources: { legacyRunsRoot: join(dir, 'runs') },
        overlayCheckpoints,
        importConfig: {
          includeLegacyHostHistory: true,
          freshOverlayRoots: [
            { sourceFolder: '2026-09-30', sha256: shaA },
            { sourceFolder: sharedKey, sha256: shaB },
          ],
        },
      });
      assert.equal(planFresh.passed, false, `${orderName}: freshOverlayRoots must fail --plan`);
      assert.deepEqual(
        planFresh.missing.map((m) => [m.key, m.kind, m.name]),
        [['importConfig.freshOverlayRoots[1].sourceFolder', 'wrong_kind_extending_checkpoint', sharedKey]],
      );

      const planCarried = await runPlanForCase(`cp-shared-carried-${orderName}`, {
        companySlug: 'acme',
        sources: { legacyRunsRoot: join(dir, 'runs') },
        overlayCheckpoints,
        importConfig: {
          includeLegacyHostHistory: true,
          freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: shaA }],
          carriedPriors: [{ sourceFolder: sharedKey, sha256: shaB, extendsRowCount: 1 }],
        },
      });
      assert.equal(planCarried.passed, false, `${orderName}: carriedPriors must fail --plan`);
      assert.deepEqual(
        planCarried.missing.map((m) => [m.key, m.kind, m.name]),
        [['importConfig.carriedPriors[0].sourceFolder', 'wrong_kind_standalone_checkpoint', sharedKey]],
      );
    }
  });

  // 4) Fix7-1 shared-key fixture: legacy run + plain standalone checkpoint sharing overlay-checkpoints/2026-10-05.
  await t.test('legacy run + plain standalone checkpoint shared key fails --plan for carriedPriors and allows freshOverlayRoots', async () => {
    const dir = join(work, 'legacy-plus-plain-cp');
    const sharedKey = 'overlay-checkpoints/2026-10-05';
    await writeTree(join(dir, 'runs', '2026-09-30'), makeMetaRun('2026-09-30'));
    await writeTree(join(dir, 'runs', 'overlay-checkpoints', '2026-10-05'), makeMetaRun('2026-10-05'));
    await writeTree(join(dir, 'checkpoints'), { '2026-10-05.csv': 'record_id,disposition\n' });

    const planCarried = await runPlanForCase('legacy-plus-plain-cp-carried', {
      companySlug: 'acme',
      sources: { legacyRunsRoot: join(dir, 'runs') },
      overlayCheckpoints: [{ label: '2026-10-05', path: join(dir, 'checkpoints', '2026-10-05.csv') }],
      importConfig: {
        includeLegacyHostHistory: true,
        freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: shaA }],
        carriedPriors: [{ sourceFolder: sharedKey, sha256: shaB, extendsRowCount: 1 }],
      },
    });
    assert.equal(planCarried.passed, false);
    assert.deepEqual(
      planCarried.missing.map((m) => [m.key, m.kind, m.name]),
      [['importConfig.carriedPriors[0].sourceFolder', 'wrong_kind_standalone_checkpoint', sharedKey]],
    );

    const planFreshAllowed = await runPlanForCase('legacy-plus-plain-cp-fresh-ok', {
      companySlug: 'acme',
      sources: { legacyRunsRoot: join(dir, 'runs') },
      overlayCheckpoints: [{ label: '2026-10-05', path: join(dir, 'checkpoints', '2026-10-05.csv') }],
      importConfig: {
        includeLegacyHostHistory: true,
        freshOverlayRoots: [
          { sourceFolder: '2026-09-30', sha256: shaA },
          { sourceFolder: sharedKey, sha256: shaB },
        ],
      },
    });
    assert.equal(planFreshAllowed.passed, true);
    assert.deepEqual(planFreshAllowed.missing, []);
  });

  // 5) Shared-key fixture: legacy run + extending checkpoint sharing overlay-checkpoints/2026-10-05.
  await t.test('legacy run + extending checkpoint shared key fails --plan for freshOverlayRoots and carriedPriors', async () => {
    const dir = join(work, 'legacy-plus-extending-cp');
    const sharedKey = 'overlay-checkpoints/2026-10-05';
    await writeTree(join(dir, 'runs', '2026-09-30'), makeMetaRun('2026-09-30'));
    await writeTree(join(dir, 'runs', 'overlay-checkpoints', '2026-10-05'), makeMetaRun('2026-10-05'));
    await writeTree(join(dir, 'checkpoints'), { '2026-10-05.csv': 'record_id,disposition\n' });

    const cp = {
      label: '2026-10-05',
      path: join(dir, 'checkpoints', '2026-10-05.csv'),
      extendsCommitId: extCommitId,
    };

    const planFresh = await runPlanForCase('legacy-plus-extending-cp-fresh', {
      companySlug: 'acme',
      sources: { legacyRunsRoot: join(dir, 'runs') },
      overlayCheckpoints: [cp],
      importConfig: {
        includeLegacyHostHistory: true,
        freshOverlayRoots: [
          { sourceFolder: '2026-09-30', sha256: shaA },
          { sourceFolder: sharedKey, sha256: shaB },
        ],
      },
    });
    assert.equal(planFresh.passed, false);
    assert.deepEqual(
      planFresh.missing.map((m) => [m.key, m.kind, m.name]),
      [['importConfig.freshOverlayRoots[1].sourceFolder', 'wrong_kind_extending_checkpoint', sharedKey]],
    );

    const planCarried = await runPlanForCase('legacy-plus-extending-cp-carried', {
      companySlug: 'acme',
      sources: { legacyRunsRoot: join(dir, 'runs') },
      overlayCheckpoints: [cp],
      importConfig: {
        includeLegacyHostHistory: true,
        freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: shaA }],
        carriedPriors: [{ sourceFolder: sharedKey, sha256: shaB, extendsRowCount: 1 }],
      },
    });
    assert.equal(planCarried.passed, false);
    assert.deepEqual(
      planCarried.missing.map((m) => [m.key, m.kind, m.name]),
      [['importConfig.carriedPriors[0].sourceFolder', 'wrong_kind_standalone_checkpoint', sharedKey]],
    );
  });
});

test('Layer 4 [Fix8 - Import Agrees With Plan on Legacy Run Plus Extending Checkpoint]: executeHistoryImport refuses a shared key between a legacy run and an extending checkpoint before any write for both freshOverlayRoots and carriedPriors regardless of timeline order', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-fix8-import-shared-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const shaOf = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

  const row1 = sampleApprovalRow({ record_id: 'policy:carrier_a:F8_1#effective:2026-01-01', note: 'base-1' });
  const row2 = sampleApprovalRow({ record_id: 'policy:carrier_a:F8_2#effective:2026-01-01', note: 'ext-2' });
  const csv1 = makeOverlayCsv([row1], { version: 'v2' });
  const csv12 = makeOverlayCsv([row1, row2], { version: 'v2' });
  const sha1 = shaOf(csv1);
  const sha12 = shaOf(csv12);
  const extCommitId = '00000000-0000-4000-8000-000000000001';
  const sharedKey = 'overlay-checkpoints/2026-10-05';

  const makeRun = (date, { priorCsv = null, overlayCsv = null, emitOverlayCsv = null, born }) => ({
    ...(priorCsv !== null ? { 'input/Overlay/overlay.csv': priorCsv } : {}),
    'input/a.csv': 'k\n1\n',
    ...(overlayCsv !== null ? { 'overlay.csv': overlayCsv } : {}),
    ...(emitOverlayCsv !== null ? { 'emits/overlay.csv': emitOverlayCsv } : {}),
    'run.json': JSON.stringify({
      date,
      born,
      steps: { assign: { at: born }, emit: { at: born } },
    }),
  });

  for (const [orderName, legacyBorn, cpAt] of [
    ['legacy-before-checkpoint', '2026-10-05T08:00:00Z', '2026-10-05T12:00:00Z'],
    ['checkpoint-before-legacy', '2026-10-05T12:00:00Z', '2026-10-05T08:00:00Z'],
  ]) {
    for (const [pinKind, importConfig, expectedUnmet] of [
      [
        'fresh',
        {
          freshOverlayRoots: [
            { sourceFolder: '2026-09-30', sha256: sha1 },
            { sourceFolder: sharedKey, sha256: sha12 },
          ],
        },
        [`importConfig.freshOverlayRoots ${sharedKey} names a checkpoint that extends a commit`],
      ],
      [
        'carried',
        {
          freshOverlayRoots: [{ sourceFolder: '2026-09-30', sha256: sha1 }],
          carriedPriors: [{ sourceFolder: sharedKey, sha256: sha12, extendsRowCount: 1 }],
        },
        [`importConfig.carriedPriors ${sharedKey} names a standalone checkpoint`],
      ],
    ]) {
      const caseName = `legacy-plus-extending-cp-${pinKind}-${orderName}`;
      const dir = join(work, caseName);
      await writeTree(join(dir, 'runs', '2026-09-30'), makeRun('2026-09-30', { overlayCsv: csv1, emitOverlayCsv: csv1, born: '2026-09-30T10:00:00Z' }));
      await writeTree(join(dir, 'runs', 'overlay-checkpoints', '2026-10-05'), makeRun('2026-10-05', {
        priorCsv: csv12,
        emitOverlayCsv: csv12,
        born: legacyBorn,
      }));
      const cpPath = join(dir, 'checkpoints', '2026-10-05.csv');
      await mkdir(dirname(cpPath), { recursive: true });
      await writeFile(cpPath, csv12, 'utf8');

      const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
      t.after(() => env.cleanup());
      const manifest = await buildImportManifest({
        companySlug: 'acme',
        sources: { legacyRunsRoot: join(dir, 'runs') },
        overlayCheckpoints: [{ label: '2026-10-05', absPath: cpPath, extendsCommitId: extCommitId, originalAt: cpAt }],
        importConfig: {
          includeLegacyHostHistory: true,
          includeLegacySqliteTables: false,
          useCompanyIncomingInput: false,
          ...importConfig,
        },
        tempBaseDir: work,
      });

      const before = await snapshotImportWriteState(env);
      await assert.rejects(
        () => executeHistoryImport({
          pool: env.pool,
          stores: env.stores,
          commands: env.commands,
          dbToken: env.ownerToken,
          manifest,
          pythonPath: 'python3',
          coherenceRepo: mockRepo,
          verifyRebuild: false,
          tempBaseDir: work,
        }),
        (err) => {
          assert.equal(err.code, 'OVERLAY_PREFIX_MISMATCH', `${caseName}: got ${err?.code}: ${err?.message}`);
          assert.deepEqual(err.unmetPins, expectedUnmet);
          return true;
        },
      );
      await assertNothingWrittenSince(env, before, caseName);
    }
  }
});
