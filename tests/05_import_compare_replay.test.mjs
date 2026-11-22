// R12, R13, R18 history importer, idempotency, byte-for-byte folder rebuild, replay proof,
// trial comparison, Clearpath-vs-Mac entity mapping, and gated live Mac 11/21 / 10/21 / 11/02 proofs.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { compareDbRuns, compareRunFolders } from '../src/compare/run-comparator.mjs';
import { buildImportManifest, executeHistoryImport } from '../src/importer/history-importer.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';
import { createMockEngineMaterializer, makeOverlayCsv, sampleApprovalRow, seedEngineVersion } from './helpers/fixtures.mjs';

const pgCheck = await checkPgAvailable();

async function writeTree(baseDir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = join(baseDir, ...rel.split('/'));
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
}

test('R12, R10.11, R13.1, R13.2 & R18: manifest-first read-only import, idempotency, byte-for-byte rebuild, and identical replay with birth write-back', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);

  // Build a synthetic Mac tree with:
  // - a completed 2026-11-21 run (including trailing space folder `All BOB/Molina `, `.DS_Store`, html viewers/reviews)
  // - an older pre-10/21 run with missing `born` and only root overlay.csv
  // - Incident Report containing both CSV data and a `.py` script (which MUST go to codeStore!)
  // - Nusear review saves under data/coherence-runs/2026-11-21/
  const fakeCoherence = join(env.tempDir, 'fake-coherence');
  const fakeNusearData = join(env.tempDir, 'fake-nusear-data');

  const row0 = sampleApprovalRow({ record_id: 'policy:aetna:PRIOR#effective:2026-01-01' });
  const rowBible = sampleApprovalRow({ record_id: 'policy:aetna:P10001#effective:2026-01-01', note: 'bible' });
  const rowAdj = sampleApprovalRow({ record_id: 'aetna~direct~P10001~100.00~2026-11', note: 'adjust' });
  const priorCsv = makeOverlayCsv([row0]);
  const bibleCsv = makeOverlayCsv([row0, rowBible]);
  const adjCsv = makeOverlayCsv([row0, rowBible, rowAdj]);

  // First run our mock engine once to create a genuinely deterministic reference run for 2026-11-21!
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

  // Seed fake-coherence/input and runs/2026-11-21 + pre-10/21 runs/2026-09-30 + Incident Report
  await writeTree(join(fakeCoherence, 'input'), sharedInput);
  await writeTree(join(run1121Dir, 'input'), sharedInput);
  // Compute matching deterministic outputs as mock engine produces for born1121
  const { createHash } = await import('node:crypto');
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

  // 1. Build manifest (read-only) BEFORE importing
  const manifest = await buildImportManifest({
    companySlug: 'phalanx',
    coherenceRoot: fakeCoherence,
    nusearDataDir: fakeNusearData,
  });
  assert.equal(manifest.macRuns.length, 2);
  assert.equal(manifest.nusearMacSaves['2026-11-21'].length, 2);
  assert.equal(manifest.incidentReportFiles.length, 2);

  // 2. Execute import + byte-for-byte rebuild proof!
  const report1 = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    actor: env.ownerActor,
    manifest,
    verifyRebuild: true,
    tempBaseDir: env.tempDir,
  });
  assert.equal(report1.passed, true, `Import failed: ${report1.problems.join('; ')}`);
  assert.equal(report1.importedRuns.length, 2);
  assert.equal(report1.rebuildChecks.length, 2);
  assert.ok(report1.rebuildChecks.every((c) => c.passed), 'every imported run folder must rebuild byte-for-byte identical');

  // Verify missing birth stayed NULL on 2026-09-30 (R12.3)
  const sep30 = await env.pool.query(
    `SELECT e.born FROM coherence.step_attempt_events e
     JOIN coherence.runs r ON r.id = e.run_id
     WHERE r.source_folder = '2026-09-30' AND e.step = 'assign' AND e.event_kind = 'finished'`,
  );
  assert.equal(sep30.rows[0].born, null);

  // Verify code-bearing files (html, py) went ONLY to codeStore, NEVER to dataStore
  const badStoreCheck = await env.pool.query(
    "SELECT COUNT(*)::int AS n FROM coherence.imported_files WHERE rel_path LIKE '%.py' AND store_kind <> 'nusear_code'",
  );
  assert.equal(badStoreCheck.rows[0].n, 0);

  // 3. R10.11 Idempotency: running the exact import again adds NOTHING!
  const seqBeforeReimport = Number((await env.pool.query('SELECT MAX(seq) AS m FROM coherence.journal_entries')).rows[0].m);
  const report2 = await executeHistoryImport({
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    actor: env.ownerActor,
    manifest,
    verifyRebuild: false,
    tempBaseDir: env.tempDir,
  });
  assert.equal(report2.importedRuns.length, 0);
  assert.equal(report2.skippedRuns.length, 2);
  // Only the new check record (if report changed) or identical idempotent check is recorded; zero new runs or versions!
  const runsCount = (await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.runs')).rows[0].n;
  assert.equal(runsCount, 2);
  assert.ok(seqBeforeReimport > 0);

  // 4. R13.2 Replay proof: replay the imported 2026-11-21 run from DB with recorded birth write-back!
  const orig1121Id = report1.importedRuns.find((r) => r.statementDate === '2026-11-21').runId;
  const replayLaunch = await env.commands.launchRun({
    actor: env.ownerActor,
    commandKey: 'replay-1121',
    statementDate: '2026-11-21',
    origin: 'replay',
    replaysRunId: orig1121Id,
    engineVersionId,
    emitMode: 'coherence',
  });
  const replayRunId = replayLaunch.result.runId;

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: 'phalanx',
    stores: env.stores,
    commands: env.commands,
    workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer({ fixedCodeHash: '809c6ea' }),
    tempBaseDir: env.tempDir,
  }));

  // assign -> attribute (writes back recorded born1121!) -> bible
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

  // Compare replayed DB run against original imported 2026-11-21 DB run!
  const replayProof = await compareDbRuns({
    pool: env.pool,
    stores: env.stores,
    leftRunId: replayRunId,
    rightRunId: orig1121Id,
    mode: 'replay',
    commands: env.commands,
    actor: env.ownerActor,
    tempBaseDir: env.tempDir,
  });
  assert.equal(replayProof.inputs.passed, true);
  assert.equal(replayProof.passed, true, `Replay mismatch: ${JSON.stringify(replayProof.tree.unexpectedDiffs)}`);
});

test('R13.4 & R11 (11/20 EYES on runs): comparator checks inputs first, honors trial allowed diffs, and maps Clearpath vs Mac entities', async (t) => {
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
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

  // 2. Trial comparison allows runBorn, committed_at, and unidentified: keys, while rejecting real money diffs
  const t1 = join(dir, 'trial-1');
  const t2 = join(dir, 'trial-2');
  const rowA = sampleApprovalRow({ record_id: 'policy:aetna:unidentified:' + 'a'.repeat(64), committed_at: '2026-11-21T10:00:00Z' });
  const rowB = sampleApprovalRow({ record_id: 'policy:aetna:unidentified:' + 'b'.repeat(64), committed_at: '2026-11-21T11:00:00Z' });
  await writeTree(t1, {
    'input/a.csv': 'x\n1\n',
    'overlay.csv': makeOverlayCsv([rowA]),
    'run.json': JSON.stringify({ date: '2026-11-21', born: '2026-11-21T10:00:00.000000001', steps: { assign: { at: '10:00', code: '809c6ea', seconds: 20 } } }),
  });
  await writeTree(t2, {
    'input/a.csv': 'x\n1\n',
    'overlay.csv': makeOverlayCsv([rowB]),
    'run.json': JSON.stringify({ date: '2026-11-21', born: '2026-11-21T11:00:00.000000002', steps: { assign: { at: '11:00', code: '809c6ea', seconds: 22 } } }),
  });
  const trialOk = await compareRunFolders(t1, t2, { mode: 'trial' });
  assert.equal(trialOk.passed, true);
  assert.equal(trialOk.tree.allowedDiffs.length, 2);

  // 3. Clearpath vs Mac entity mapping: InsureItAll stays InsureItAll, every other entity maps to Clearpath + manifest verified
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
test('R18 live Mac proof (opt-in COHERENCE_MAC_PROOF=1): import Mac 2026-11-21 read-only and rebuild byte-for-byte', {
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
    pool: env.pool,
    stores: env.stores,
    commands: env.commands,
    actor: env.ownerActor,
    manifest: only1121,
    coherenceRepo: coherenceRoot,
    verifyRebuild: true,
    tempBaseDir: env.tempDir,
  });
  assert.equal(report.passed, true, `Mac 11/21 import/rebuild failed: ${report.problems.join('; ')}`);
  assert.equal(report.rebuildChecks[0].passed, true);
});
