// Layer 4: protects historical import continuity, byte-for-byte folder rebuild,
// input-first run comparison, substance takeover checks, and identical replay of committed runs.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { assertLocalPgHost, runHistoryProof } from '../scripts/prove-history.mjs';
import { createCommandLayer } from '../src/commands/command-layer.mjs';
import { compareDatabasesAsOf, exportJournalNdjson, rebuildFromJournalExport, verifyChain, verifyCommitments } from '../src/commands/journal-export.mjs';
import { verifyOverlayReconstruction } from '../src/compare/overlay-reconstruction.mjs';
import { compareCsvExactText, compareDbRuns, compareRunFolders, mapEntitiesCsv } from '../src/compare/run-comparator.mjs';
import { createPool } from '../src/db/pg-client.mjs';
import { formatOverlayCsvFromRows, generateOverlayCsv } from '../src/decisions/overlay-generator.mjs';
import {
  buildImportManifest,
  createCommitBundle,
  executeHistoryImport,
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
import { checkPgAvailable, createEmptyMigratedTestDb, createTestEnv } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

async function writeTree(baseDir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = join(baseDir, ...rel.split('/'));
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
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
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
  });
  assert.equal(manifest.macRuns.length, 2);
  assert.equal(manifest.nusearMacSaves['2026-11-21'].length, 2);
  assert.equal(manifest.incidentReportFiles.length, 2);

  const report1 = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, actor: env.ownerActor,
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
    pool: env.pool, stores: env.stores, commands: env.commands, actor: env.ownerActor,
    manifest, parseOverlay, verifyRebuild: false, tempBaseDir: env.tempDir,
  });
  assert.equal(report2.importedRuns.length, 0);
  assert.equal(report2.skippedRuns.length, 2);
  assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.runs')).rows[0].n, 2);

  const replayLaunch = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'replay-1121', statementDate: '2026-11-21',
    origin: 'replay', replaysRunId: orig1121Id, engineVersionId, emitMode: 'coherence',
  });
  const replayRunId = replayLaunch.result.runId;

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer({ fixedCodeHash: '809c6ea' }), tempBaseDir: env.tempDir,
  }));

  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [replayRunId])).rows[0].latest_journal_seq);
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'rep-b', expectedJournalSeq: seq, runId: replayRunId, surface: 'bible', csvBytes: Buffer.from(bibleCsv, 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished');

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [replayRunId])).rows[0].latest_journal_seq);
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'rep-a', expectedJournalSeq: seq, runId: replayRunId, surface: 'adjust', csvBytes: Buffer.from(adjCsv, 'utf8') });
  const repAdj = await worker.runOnce();
  assert.equal(repAdj.action, 'review_accepted');

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [replayRunId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ actor: env.ownerActor, commandKey: 'rep-e', expectedJournalSeq: seq, runId: replayRunId, adjustReviewSaveId: repAdj.reviewSaveId, typedPhrase: 'create statements for 2026-11-21' });
  assert.equal((await worker.runOnce()).action, 'step_finished');

  const replayProof = await compareDbRuns({
    pool: env.pool, stores: env.stores, leftRunId: replayRunId, rightRunId: orig1121Id,
    mode: 'replay', commands: env.commands, actor: env.ownerActor, tempBaseDir: env.tempDir,
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
    stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));
  const launch = await env.commands.launchRun({ actor: env.ownerActor, commandKey: 'wk-reb-launch', statementDate: '2026-11-21', engineVersionId });
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
    actor: env.ownerActor, commandKey: 'wk-reb-bible', expectedJournalSeq: seq, runId, surface: 'bible',
    csvBytes: Buffer.from(makeOverlayCsv([row0, sampleApprovalRow({ note: 'ok' })]), 'utf8'),
  });
  const rebuildWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: omitStores, commands: env.commands, workerActor: env.workerActor,
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
  await writeTree(join(legacyRoot, 'runs', '2026-11-21'), {
    'input/Overlay/overlay.csv': makeOverlayCsv([row0]),
    'overlay.csv': makeOverlayCsv([row0]),
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
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
  });
  assert.equal(acmeManifest.macRuns.length, 1);
  assert.equal(acmeManifest.currentInputDir, join(legacyRoot, 'input'));

  const repMissingCommit = await executeHistoryImport({
    pool: env1.pool, stores: env1.stores, commands: env1.commands, actor: env1.ownerActor,
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
      pool: env2.pool, stores: env2.stores, commands: env2.commands, actor: env2.ownerActor,
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
    pool: env3.pool, stores: env3.stores, commands: env3.commands, actor: env3.ownerActor,
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
    actor: env.ownerActor,
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
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
  });

  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    actor: env.ownerActor,
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
    actor: env.ownerActor,
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
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
  });
  await assert.rejects(
    () => executeHistoryImport({
      pool: badEnv.pool,
      stores: badEnv.stores,
      commands: badEnv.commands,
      actor: badEnv.ownerActor,
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

  // Legacy run (2026-11-02)
  await writeTree(join(srcRoot, 'legacy-runs', '2026-11-02'), {
    'input/Overlay/overlay.csv': ovCsv,
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
    },
  }, null, 2), 'utf8');

  const manifest = await loadImportManifestFile(manifestPath);
  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    actor: env.ownerActor,
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

  // Verify abandoned company run is excluded from findLatestPublishedRun!
  const latestPub = await findLatestPublishedRun(env.pool);
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
    actor: env.ownerActor,
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
    actor: env.ownerActor,
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

  // Verify cumulative totals through coherence_views:
  // Beacon: 100 (3/25) + 80*3 (4/29..6/30) + 100 (7/31) - 20 (8/1 split) = 420.00
  // Acme: 50 (7/31, excluded from 8/1 split) = 50.00
  // Acme Upline: 20*3 (4/29..6/30) + 20 (8/1 split) - 60 (8/31 take-back) = 20.00
  const entTotals = (await env.pool.query(
    `SELECT statement_entity, SUM(net_amount)::numeric(14,2)::text AS total
     FROM coherence_views.v_entity_statement_date_totals
     GROUP BY statement_entity
     ORDER BY statement_entity COLLATE "C"`,
  )).rows;
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
    actor: env.ownerActor,
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
  const okParsed = await readLegacyStatementBatches({
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
    () => readLegacyStatementBatches({
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
    () => readLegacyStatementBatches({
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
    () => readLegacyStatementBatches({
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
      actor: env.ownerActor,
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
  const fixedRateRes = await readLegacyStatementBatches({
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
    actor: env.ownerActor,
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

  // Prior overlay has rev-0; 9 timestamped saves extend it one revision at a time (10 commits + 10 approvals_files in ONE journal entry!)
  await writeTree(join(cohRoot, 'runs', '2026-11-15'), {
    'input/a.csv': 'k\n1\n',
    'input/Overlay/overlay.csv': makeOverlayCsv(rows.slice(0, 1), { version: 'v2' }),
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
  for (let i = 1; i < 10; i++) {
    saveFiles[`bible-review-2026-11-15T10-${String(i).padStart(2, '0')}-00-000Z.csv`] = makeOverlayCsv(rows.slice(0, i + 1), { version: 'v2' });
  }
  await writeTree(join(dataRoot, 'coherence-runs', '2026-11-15'), saveFiles);

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    coherenceRoot: cohRoot,
    nusearDataDir: dataRoot,
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
  });

  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    actor: env.ownerActor,
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
    'input/Overlay/overlay.csv': ovCsv,
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
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
  });

  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    actor: env.ownerActor,
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
    actor: env.ownerActor,
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
  await mkdir(cpDir, { recursive: true });
  await writeFile(cpEarly, makeOverlayCsv(rows.slice(0, 1), { version: 'v2' }), 'utf8');
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
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
  });

  const rep = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    actor: env.ownerActor,
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
    pool: env.pool, stores: env.stores, commands: env.commands, actor: env.ownerActor,
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
    pool: env.pool, stores: env.stores, commands: env.commands, actor: env.ownerActor,
    manifest, pythonPath: 'python3', coherenceRepo: mockRepo, verifyRebuild: true, recordCheck: false, tempBaseDir: env.tempDir,
  });
  const after = await snapCounts();
  assert.equal(rep2.passed, true, `Second import failed: ${rep2.problems.join('; ')}`);
  assert.equal(rep2.standingInputRebuildCheck.passed, true);
  assert.deepEqual(after, before, 're-importing with Sent/statements_<date>.csv present must add zero rows');

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
  const missManifest = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      companyWorkspacesDir: join(missRoot, 'company-ws'),
      companyEnvironmentDir: join(missRoot, 'company-env'),
    },
    importConfig: { includeLegacyHostHistory: false },
  });
  const missRep = await executeHistoryImport({
    pool: envMissing.pool, stores: envMissing.stores, commands: envMissing.commands, actor: envMissing.ownerActor,
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
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
  });
  const rep = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, actor: env.ownerActor,
    manifest, pythonPath: 'python3', coherenceRepo: mockRepo, verifyRebuild: false, tempBaseDir: env.tempDir,
  });
  assert.equal(rep.passed, true, rep.problems.join('; '));

  const gen = await generateOverlayCsv(env.pool, { runId: rep.importedRuns[0].runId });
  assert.equal(gen.rows[0].committed_at, null, 'generated overlay for imported row must keep committed_at blank');

  const l2 = await verifyOverlayReconstruction({
    pool: env.pool, stores: env.stores, commands: env.commands, actor: env.ownerActor,
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
    pool: envEmptyOv.pool, stores: envEmptyOv.stores, commands: envEmptyOv.commands, actor: envEmptyOv.ownerActor,
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

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      companyWorkspacesDir: join(srcRoot, 'company-ws'),
      companyAbandonedDir: join(srcRoot, 'company-abandoned'),
    },
    importConfig: { includeLegacyHostHistory: false },
  });

  const rep = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, actor: env.ownerActor,
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

  // Never published: findLatestPublishedRun skips 2026-11-15 and returns 2026-11-11; attempt_is_published_run is false!
  const latestPub = await findLatestPublishedRun(env.pool);
  assert.equal(latestPub.id, live1111);
  const abEmitEv = (await env.pool.query(
    "SELECT id FROM coherence.step_attempt_events WHERE run_id = $1::uuid AND step = 'emit' AND event_kind = 'finished'",
    [ab1115],
  )).rows[0].id;
  const isPub = (await env.pool.query('SELECT coherence.attempt_is_published_run($1::uuid) AS pub', [abEmitEv])).rows[0].pub;
  assert.equal(isPub, false, 'abandoned imported company run emit attempt must never be published');

  // Never carried: carrySent on abandoned imported company run is refused by PostgreSQL
  await env.commands.publishInputVersion({
    actor: env.ownerActor, commandKey: 'seed-standing-fix9', lineKind: 'standing', sourceKind: 'company_import',
    reason: 'base', entries: [], storedFiles: [],
  });
  await assert.rejects(
    () => env.commands.carrySent({
      actor: env.ownerActor, commandKey: 'carry-abandoned-1115', runId: ab1115, typedPhrase: 'sent 2026-11-15',
    }),
    /abandoned/i,
  );

  // Never visible through entity views: even if materialized, scoped roles see 0 rows for abandoned run
  await env.commands.materializeEmit({
    actor: env.workerActor,
    commandKey: 'mat-abandoned-1115',
    runId: ab1115,
    attemptEventId: abEmitEv,
    statementDate: '2026-11-15',
    canonicalBobCsv: bobCsv,
    coherentLedgerCsv: ledCsv,
    statementsCsv: stmtCsv,
  });
  const c = await env.pool.connect();
  try {
    await c.query('BEGIN');
    await c.query('SET LOCAL ROLE coherence_entity_manager_ro');
    await c.query("SELECT pg_catalog.set_config('app.access_tier', 'entity_manager', true)");
    const emBob = (await c.query('SELECT COUNT(*)::int AS n FROM coherence_views.v_canonical_bob WHERE run_id = $1::uuid', [ab1115])).rows[0].n;
    const emLines = (await c.query('SELECT COUNT(*)::int AS n FROM coherence_views.v_entity_statement_lines')).rows[0].n;
    assert.equal(emBob, 0, 'abandoned company run must be invisible in v_canonical_bob');
    assert.equal(emLines, 0, 'abandoned company run must be invisible in v_entity_statement_lines');
    await c.query('ROLLBACK');
  } finally {
    c.release();
  }

  // Non-abandoned imported runs still cannot be abandoned after import
  await assert.rejects(
    () => env.commands.abandonRun({
      actor: env.ownerActor, commandKey: 'abandon-live-import-1111', runId: live1111, typedPhrase: 'abandon 2026-11-11', reason: 'not allowed',
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
    'input/Overlay/overlay.csv': ovCsv,
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
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
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
    'input/Overlay/overlay.csv': ovCsv,
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
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
  });
  const imp = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, actor: env.ownerActor,
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
    actor: env.workerActor,
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
  const nyCommands = createCommandLayer({ pool: nyPool, companySlug: env.companySlug, stores: env.stores });

  const zonelessTs = '2026-10-15T10:30:00';

  // 1) Direct importStandaloneFiles with a zone-less originalAt MUST store normalized UTC matching commitment hash on America/New_York session
  const directFile = await env.dataStore.promoteBytes(Buffer.from('hello standalone\n', 'utf8'), { relPath: 'standalone/note.txt', checksPassed: true });
  await nyCommands.importStandaloneFiles({
    actor: env.ownerActor,
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
  await mkdir(srcRoot, { recursive: true });
  await writeFile(cpPath, makeOverlayCsv([row0], { version: 'v2' }), 'utf8');
  await writeTree(join(srcRoot, 'runs', '2026-10-16'), {
    'input/a.csv': 'k\n1\n',
    'input/Overlay/overlay.csv': makeOverlayCsv([row0], { version: 'v2' }),
    'overlay.csv': makeOverlayCsv([row0, row1], { version: 'v2' }),
    'run.json': JSON.stringify({ date: '2026-10-16', steps: { assign: { at: zonelessTs } } }),
  });

  const manifest = await buildImportManifest({
    companySlug: 'acme',
    sources: { legacyRunsRoot: join(srcRoot, 'runs') },
    overlayCheckpoints: [{ label: 'zoneless-cp', absPath: cpPath, originalAt: zonelessTs }],
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
  });

  const imp = await executeHistoryImport({
    pool: nyPool,
    stores: env.stores,
    commands: nyCommands,
    actor: env.ownerActor,
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
    'input/Overlay/overlay.csv': ovCsv,
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
    importConfig: { includeLegacyHostHistory: true, useCompanyIncomingInput: false },
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
