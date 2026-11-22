// ============================================================================
// LAYER 4: THE IMPORT AND THE PROOFS
// Protects: historical continuity and equivalence against the Mac ("the Bible")
// — preventing silent drift during migration, loss of historical runs, review
// saves, or working tables' bytes, false equivalence when inputs differ, or
// inability to replay committed runs identically.
// ============================================================================
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { compareDbRuns, compareRunFolders } from '../src/compare/run-comparator.mjs';
import { buildImportManifest, executeHistoryImport } from '../src/importer/history-importer.mjs';
import { buildAttemptWorkspace } from '../src/worker/folder-builder.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import { createMockEngineMaterializer, makeOverlayCsv, sampleApprovalRow, seedEngineVersion } from './helpers/fixtures.mjs';
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

async function writeTree(baseDir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = join(baseDir, ...rel.split('/'));
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
}

test('Layer 4 [R12, R10.11, R13.1, R13.2 & Clarification #5]: read-only import keeps working tables bytes, idempotent re-import adds nothing, byte-for-byte rebuild and identical replay with birth write-back pass', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);

  const fakeCoherence = join(env.tempDir, 'fake-coherence');
  const fakeNusearData = join(env.tempDir, 'fake-nusear-data');

  const row0 = sampleApprovalRow({ record_id: 'policy:aetna:PRIOR#effective:2026-01-01' });
  const rowBible = sampleApprovalRow({ record_id: 'policy:aetna:P10001#effective:2026-01-01', note: 'bible' });
  const rowAdj = sampleApprovalRow({ record_id: 'aetna~direct~P10001~100.00~2026-11', note: 'adjust' });
  const priorCsv = makeOverlayCsv([row0]);
  const bibleCsv = makeOverlayCsv([row0, rowBible]);
  const adjCsv = makeOverlayCsv([row0, rowBible, rowAdj]);

  const born1121 = '2026-11-21T15:00:00.123456789';
  const run1121Dir = join(fakeCoherence, 'runs', '2026-11-21');
  const sharedInput = {
    'Agent Data/cleanagentdata.csv': 'agent_name,agent_npn,entity,start_date\nJane Agent,12345678,Phalanx,01/01/2025\n',
    'All Statements/aetna_202611.csv': 'member,policy_number,amount\nTest Member,P10001,100.00\n',
    'All BOB/Molina /book.csv': 'member,policy_number,status\nTest Member,P10001,ACTIVE\n',
    'Sunfire/enrollments.csv': 'member,policy_number,npn\nTest Member,P10001,12345678\n',
    'Overlay/overlay.csv': priorCsv,
    '.DS_Store': 'finder-ds-store',
  };

  await writeTree(join(fakeCoherence, 'input'), sharedInput);
  await writeTree(join(run1121Dir, 'input'), sharedInput);

  const molinaHash = createHash('sha256').update(sharedInput['All BOB/Molina /book.csv']).digest('hex').slice(0, 12);
  const unidHash = createHash('sha256').update(`${born1121}:0`).digest('hex');

  const workingFiles = {};
  for (const name of ['cbob', 'sf', 'tx_tx', 'tx_cbob', 'tx_sf', 'cbob_sf', 'pbob']) {
    workingFiles[`working/${name}.csv`] = `id,tag\n1,${molinaHash}\n`;
  }
  workingFiles['working/tx.csv'] = `id,tag\n1,${molinaHash}\n2,attributed\n`;

  const bibleItems = [
    { record_id: 'policy:aetna:P10001#effective:2026-01-01', case: 'BIBLE', subtype: 'CONFLICT', amount: '100.00' },
    { record_id: `policy:aetna:unidentified:${unidHash}`, case: 'BIBLE', subtype: 'HOUSE', amount: '50.00' },
  ];
  const bibleCfg = { statementDate: '2026-11-21', build: '809c6ea', stamped: true, surface: 'bible', runBorn: born1121, queue: bibleItems, overlay: [], checksum: unidHash.slice(0, 16) };
  const adjItems = [{ record_id: 'aetna~direct~P10001~100.00~2026-11', case: 'NEW', subtype: 'NEW_BUSINESS', amount: '100.00' }];
  const adjCfg = { statementDate: '2026-11-21', build: '809c6ea', stamped: true, surface: 'adjust', runBorn: born1121, queue: adjItems, overlay: [], checksum: 'adj123' };

  await writeTree(run1121Dir, {
    ...workingFiles,
    'bible.csv': `record_id,case,subtype,amount\r\npolicy:aetna:P10001#effective:2026-01-01,BIBLE,CONFLICT,100.00\r\npolicy:aetna:unidentified:${unidHash},BIBLE,HOUSE,50.00\r\n`,
    'bible.html': `<!doctype html><html><head><title>Coherence Bible</title><script>window.__ADJUST_CONFIG__=${JSON.stringify(bibleCfg)};</script></head><body>bible</body></html>`,
    'adjust.csv': 'record_id,case,subtype,amount\r\naetna~direct~P10001~100.00~2026-11,NEW,NEW_BUSINESS,100.00\r\n',
    'adjust.html': `<!doctype html><html><head><title>Coherence Adjust</title><script>window.__ADJUST_CONFIG__=${JSON.stringify(adjCfg)};</script></head><body>adjust</body></html>`,
    'overlay.csv': adjCsv,
    'emits/statements_20261121.csv': 'record_id,entity,writing_npn,gross_comm,downline_amount,run_action\naetna~direct~P10001~100.00~2026-11,Phalanx,12345678,100.00,80.00,NEW\n',
    'emits/adjustments.csv': adjCsv,
    'emits/overlay.csv': adjCsv,
    'emits/bundles/entity-managers/Phalanx/data/canonical_bob.csv': 'member,entity,carrier,policy_id,gross_comm\nTest Member,Phalanx,aetna,1,100.00\n',
    'emits/bundles/entity-managers/Phalanx/data/coherent_ledger.csv': 'member,entity,carrier,gross_comm\nTest Member,Phalanx,aetna,100.00\n',
    'emits/bundles/entity-managers/Phalanx/viewer.html': `<!doctype html><html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify({ name: 'Entity Manager', title: 'Phalanx', statementDate: '2026-11-21', build: '809c6ea', stamped: true, role: 'ENTITY_MANAGER', features: { CANONICAL_BOB: { canonical_bob: 'data/canonical_bob.csv' }, COHERENT_LEDGER: { coherent_ledger: 'data/coherent_ledger.csv' } }, defaultVisible: { CANONICAL_BOB: { canonical_bob: ['member', 'entity'] } }, defaultFilters: {} })};</script></head><body>viewer</body></html>`,
    'emits/bundles/selling-agents/Phalanx/jane-agent/data/Phalanx_jane-agent_12345678_bob.csv': 'member,entity,carrier,status,writing_npn,writing_agent,amount,gross_comm\nTest Member,Phalanx,aetna,ACTIVE_PAYING,12345678,Jane Agent,100.00,100.00\n',
    'emits/bundles/selling-agents/Phalanx/jane-agent/viewer.html': `<!doctype html><html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify({ name: 'Jane Agent', title: '12345678', statementDate: '2026-11-21', build: '809c6ea', stamped: true, role: 'SELLING_AGENT', features: { BOB: { bob: 'data/Phalanx_jane-agent_12345678_bob.csv' } }, defaultVisible: { BOB: { bob: ['member', 'entity', 'amount'] } }, defaultFilters: { BOB: { bob: { amount: { positiveOnly: true }, carrier: { include: ['aetna'] } } } } })};</script></head><body>viewer</body></html>`,
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

  // Pre-10/21 run with missing birth and root overlay.csv only
  await writeTree(join(fakeCoherence, 'runs', '2026-09-30'), {
    'input/Agent Data/cleanagentdata.csv': sharedInput['Agent Data/cleanagentdata.csv'],
    'overlay.csv': priorCsv,
    'working/tx.csv': 'id\n1\n',
    'bible.csv': 'record_id\n',
    'run.json': JSON.stringify({ date: '2026-09-30', steps: { assign: { at: '2026-09-30T10:00:00', code: 'abc1234+' }, attribute: { at: '2026-09-30T10:01:00', code: 'abc1234+' }, bible: { at: '2026-09-30T10:02:00', code: 'abc1234+' } } }),
  });

  // Incident Report (CSV -> company_data, .py -> nusear_code!)
  await writeTree(join(fakeCoherence, 'runs', 'Incident Report', '2026-11-03 Slate'), {
    'override_only.csv': 'policy\nP1\n',
    'build_slate.py': 'print("incident script")\n',
  });

  // Nusear timestamped review saves for 2026-11-21
  await writeTree(join(fakeNusearData, 'coherence-runs', '2026-11-21'), {
    'bible-review-2026-11-21T15-35-17-068Z.csv': bibleCsv,
    'adjust-review-2026-11-21T15-36-12-986Z.csv': adjCsv,
  });

  // 1. Read-only manifest
  const manifest = await buildImportManifest({ companySlug: 'phalanx', coherenceRoot: fakeCoherence, nusearDataDir: fakeNusearData });
  assert.equal(manifest.macRuns.length, 2);
  assert.equal(manifest.nusearMacSaves['2026-11-21'].length, 2);
  assert.equal(manifest.incidentReportFiles.length, 2);

  // 2. Import + byte-for-byte rebuild proof
  const report1 = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, actor: env.ownerActor,
    manifest, verifyRebuild: true, tempBaseDir: env.tempDir,
  });
  assert.equal(report1.passed, true, `Import failed: ${report1.problems.join('; ')}`);
  assert.equal(report1.importedRuns.length, 2);
  assert.ok(report1.rebuildChecks.every((c) => c.passed));

  // Clarification #5: imported runs KEEP their working tables' bytes in company_data
  const orig1121Id = report1.importedRuns.find((r) => r.statementDate === '2026-11-21').runId;
  const workingArts = await env.pool.query(
    `SELECT a.rel_path, a.file_sha256
     FROM coherence.artifacts a
     JOIN coherence.step_attempt_events e ON e.id = a.attempt_event_id
     WHERE e.run_id = $1::uuid AND a.rel_path LIKE 'working/%'`,
    [orig1121Id],
  );
  assert.equal(workingArts.rows.length, 8);
  for (const w of workingArts.rows) {
    assert.ok((await env.dataStore.readVerified(w.file_sha256)).length > 0);
  }

  // Missing birth stayed NULL on 2026-09-30 (R12.3)
  const sep30 = await env.pool.query(
    `SELECT e.born FROM coherence.step_attempt_events e
     JOIN coherence.runs r ON r.id = e.run_id
     WHERE r.source_folder = '2026-09-30' AND e.step = 'assign' AND e.event_kind = 'finished'`,
  );
  assert.equal(sep30.rows[0].born, null);

  // Code-bearing files (.py) went ONLY to nusear_code
  const badStoreCheck = await env.pool.query(
    "SELECT COUNT(*)::int AS n FROM coherence.imported_files WHERE rel_path LIKE '%.py' AND store_kind <> 'nusear_code'",
  );
  assert.equal(badStoreCheck.rows[0].n, 0);

  // 3. R10.11 Idempotency: re-running import adds zero new runs
  const report2 = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, actor: env.ownerActor,
    manifest, verifyRebuild: false, tempBaseDir: env.tempDir,
  });
  assert.equal(report2.importedRuns.length, 0);
  assert.equal(report2.skippedRuns.length, 2);
  assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.runs')).rows[0].n, 2);

  // 4. R13.2 Replay proof with recorded birth write-back
  const replayLaunch = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'replay-1121', statementDate: '2026-11-21',
    origin: 'replay', replaysRunId: orig1121Id, engineVersionId, emitMode: 'coherence',
  });
  const replayRunId = replayLaunch.result.runId;

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: 'phalanx', stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer({ fixedCodeHash: '809c6ea' }), tempBaseDir: env.tempDir,
  }));

  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [replayRunId])).rows[0].latest_journal_seq);
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'rep-b', expectedJournalSeq: seq, runId: replayRunId, surface: 'bible', csvBytes: Buffer.from(bibleCsv, 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished'); // adjust

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [replayRunId])).rows[0].latest_journal_seq);
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'rep-a', expectedJournalSeq: seq, runId: replayRunId, surface: 'adjust', csvBytes: Buffer.from(adjCsv, 'utf8') });
  const repAdj = await worker.runOnce();
  assert.equal(repAdj.action, 'review_accepted');

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [replayRunId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ actor: env.ownerActor, commandKey: 'rep-e', expectedJournalSeq: seq, runId: replayRunId, adjustReviewSaveId: repAdj.reviewSaveId, typedPhrase: 'create statements for 2026-11-21' });
  assert.equal((await worker.runOnce()).action, 'step_finished'); // emit

  const replayProof = await compareDbRuns({
    pool: env.pool, stores: env.stores, leftRunId: replayRunId, rightRunId: orig1121Id,
    mode: 'replay', commands: env.commands, actor: env.ownerActor, tempBaseDir: env.tempDir,
  });
  assert.equal(replayProof.inputs.passed, true);
  assert.equal(replayProof.passed, true, `Replay mismatch: ${JSON.stringify(replayProof.tree.unexpectedDiffs)}`);

  // Clarification #5 & R17.3: once replay is proved, a new run whose derivable working/ bytes are omitted
  // from object storage can rebuild working/ on demand via rebuildWorkingOnDemand and verify fingerprints!
  const replayRunRow = (await env.pool.query(
    `SELECT id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date, origin, input_version_id,
            prior_approvals_sha256, engine_version_id, replays_run_id
     FROM coherence.runs WHERE id = $1::uuid`,
    [replayRunId],
  )).rows[0];
  const emptyDataStore = {
    ...env.stores.dataStore,
    readVerified: async (sha, meta, opts) => {
      // Simulate working/tx.csv being stored as fingerprint-only (absent from object storage)
      if (workingArts.rows.some((w) => w.file_sha256 === sha)) {
        const err = new Error('Working table stored as fingerprint only');
        err.code = 'NOT_FOUND';
        throw err;
      }
      return env.stores.dataStore.readVerified(sha, meta, opts);
    },
  };
  let rebuiltOnDemandCalled = false;
  const ws = await buildAttemptWorkspace({
    db: env.pool,
    run: replayRunRow,
    step: 'bible',
    stores: {
      ...env.stores,
      dataStore: emptyDataStore,
      readVerified: (storeKind, sha, meta, opts) => (
        storeKind === 'company_data' ? emptyDataStore.readVerified(sha, meta, opts) : env.stores.codeStore.readVerified(sha, meta, opts)
      ),
    },
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
});

test('Layer 4 [R13.4 & R11 (11/20 EYES on runs)]: comparator checks inputs first, honors trial allowed diffs, rejects real money diffs, and maps Clearpath vs Mac entities', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'coherence-cmp-unit-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const left = join(dir, 'left');
  const right = join(dir, 'right');

  // 1. 11/20 agent file mismatch MUST fail inputs check FIRST
  await writeTree(left, { 'input/Agent Data/cleanagentdata.csv': 'agent_name,entity\nA,Phalanx\n', 'run.json': '{"date":"2026-11-20","steps":{}}' });
  await writeTree(right, { 'input/Agent Data/cleanagentdata.csv': 'agent_name,entity\nA,Apex\n', 'run.json': '{"date":"2026-11-20","steps":{}}' });
  const inputMismatch = await compareRunFolders(left, right, { mode: 'trial' });
  assert.equal(inputMismatch.inputs.passed, false);
  assert.equal(inputMismatch.passed, false);
  assert.equal(inputMismatch.inputs.changed[0].relPath, 'input/Agent Data/cleanagentdata.csv');

  // 2. Trial allows runBorn, committed_at, unidentified: keys; rejects a real money diff
  const t1 = join(dir, 'trial-1');
  const t2 = join(dir, 'trial-2');
  const rowA = sampleApprovalRow({ record_id: `policy:aetna:unidentified:${'a'.repeat(64)}`, committed_at: '2026-11-21T10:00:00Z' });
  const rowB = sampleApprovalRow({ record_id: `policy:aetna:unidentified:${'b'.repeat(64)}`, committed_at: '2026-11-21T11:00:00Z' });
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

  // Money mismatch ($100.00 vs $99.00) MUST FAIL!
  await writeFile(join(t2, 'emits', 'statements_20261121.csv'), 'record_id,gross_comm\nr1,99.00\n', 'utf8');
  const moneyDiff = await compareRunFolders(t1, t2, { mode: 'trial' });
  assert.equal(moneyDiff.passed, false);
  assert.ok(moneyDiff.tree.unexpectedDiffs.some((d) => d.relPath === 'emits/statements_20261121.csv'));

  // 3. Clearpath vs Mac entity mapping
  const macDir = join(dir, 'mac');
  const cpDir = join(dir, 'cp');
  await writeTree(macDir, {
    'input/Agent Data/cleanagentdata.csv': 'agent_name,entity\nA,Apex\nB,InsureItAll\n',
    'emits/statements_20261121.csv': 'record_id,entity,gross_comm\nr1,Apex,100.00\nr2,InsureItAll,50.00\n',
    'run.json': JSON.stringify({ date: '2026-11-21', born: 'b1', steps: { emit: { at: '10:00', code: '809c6ea', seconds: 100 } } }),
  });
  await writeTree(cpDir, {
    'input/Agent Data/cleanagentdata.csv': 'agent_name,entity\nA,Clearpath\nB,InsureItAll\n',
    'emits/statements_20261121.csv': 'record_id,entity,gross_comm\nr1,Clearpath,100.00\nr2,InsureItAll,50.00\n',
    'company_manifest.json': JSON.stringify([{ output: 'entity-managers/Clearpath', role: 'ENTITY_MANAGER', scope: 'all' }]),
    'emits/bundles/entity-managers/Clearpath/data/canonical_bob.csv': 'entity\nClearpath\n',
    'run.json': JSON.stringify({ date: '2026-11-21', born: 'b2', steps: { emit: { at: '11:00', code: '809c6ea', seconds: 105 } } }),
  });
  const cpVsMac = await compareRunFolders(cpDir, macDir, { mode: 'clearpath_vs_mac' });
  assert.equal(cpVsMac.passed, true);
  assert.equal(cpVsMac.tree.clearpathManifestCheck.passed, true);
});

// R18 live Mac proof (explicit opt-in COHERENCE_MAC_PROOF=1 so default test runs obey W-9 and never touch live paths!)
test('Layer 4 [R18 opt-in COHERENCE_MAC_PROOF=1]: import Mac 2026-11-21 read-only and rebuild byte-for-byte', {
  skip: (!pgCheck.available && pgCheck.reason) || (process.env.COHERENCE_MAC_PROOF !== '1' && 'Set COHERENCE_MAC_PROOF=1 to run read-only live Mac proof'),
}, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const coherenceRoot = process.env.COHERENCE_REPO || '/Users/marcsmac/Code/coherence';
  const nusearDataDir = process.env.NUSEAR_DATA_DIR || '/Users/marcsmac/Code/nusear2.com/data';
  const fullManifest = await buildImportManifest({ companySlug: 'phalanx', coherenceRoot, nusearDataDir });
  const only1121 = {
    ...fullManifest,
    macRuns: fullManifest.macRuns.filter((r) => r.sourceFolder === '2026-11-21'),
    companyRuns: [],
    currentInputDir: null,
    currentInputFiles: [],
    incidentReportFiles: [],
    standaloneFiles: [],
  };
  assert.equal(only1121.macRuns.length, 1);

  const report = await executeHistoryImport({
    pool: env.pool, stores: env.stores, commands: env.commands, actor: env.ownerActor,
    manifest: only1121, coherenceRepo: coherenceRoot, verifyRebuild: true, tempBaseDir: env.tempDir,
  });
  assert.equal(report.passed, true, `Mac 11/21 import/rebuild failed: ${report.problems.join('; ')}`);
  assert.equal(report.rebuildChecks[0].passed, true);
});
