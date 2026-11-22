// Layer 4: protects historical import continuity, byte-for-byte folder rebuild,
// input-first run comparison, substance takeover checks, and identical replay of committed runs.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { compareDbRuns, compareRunFolders, mapEntitiesCsv } from '../src/compare/run-comparator.mjs';
import {
  createCommitBundle,
  buildImportManifest,
  executeHistoryImport,
  parseApprovalsFile,
  resolveLiveProofConfig,
} from '../src/importer/history-importer.mjs';
import { buildAttemptWorkspace } from '../src/worker/folder-builder.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import {
  createMockEngineMaterializer,
  createTestOverlayParser,
  makeOverlayCsv,
  sampleApprovalRow,
  seedEngineVersion,
  seedStandingInput,
} from './helpers/fixtures.mjs';
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';

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
