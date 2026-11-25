// Layer 5: protects downstream readers, signed feeds, ambiguity checks on entity bundles,
// refusal of removed per-recipient bundle paths, non-sandboxed data headers, server-only viewer parsing,
// and review-app drift detection -- all executed strictly as platform_app through app_views.* and app_cmd.*.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  createDatabaseCoherenceReader,
  createSignedAgentFeedReader,
  HOUSE_FEATURES,
  signRequest,
} from '../src/readers/downstream-reader.mjs';
import { sha256Hex } from '../src/util/crypto.mjs';
import { parseCsv } from '../src/util/csv.mjs';
import { checkReviewAppDrift } from '../src/web/drift-check.mjs';
import { createWebHandlers } from '../src/web/handlers.mjs';
import { createCoherenceRouter } from '../src/web/router.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import {
  buildSyntheticEmitDataset,
  createDataOnlyMockEngineMaterializer,
  createMockEngineMaterializer,
  makeOverlayCsv,
  sampleApprovalRow,
  seedEngineCopyVersion,
  seedEngineVersion,
  seedStandingInput,
} from './helpers/fixtures.mjs';
import { createRoleScopedTestPool, seedCoherenceIamFixture } from './helpers/iam-harness.mjs';
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

async function runFullCompletedRun(env, worker, { date, origin = 'app', engineVersionId, row0 }) {
  const launch = await env.commands.launchRun({
    dbToken: env.ownerToken, commandKey: `launch-${origin}-${date}`, statementDate: date, origin, engineVersionId,
  });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');

  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const bibleRows = [row0, sampleApprovalRow({ record_id: `policy:carrier_a:B-${date}#effective:2026-01-01` })];
  await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: `b-${runId}`, expectedJournalSeq: seq, runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished');

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const adjRows = [...bibleRows, sampleApprovalRow({ record_id: `carrier_a~direct~A-${date}~100.00~2026-11` })];
  await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: `a-${runId}`, expectedJournalSeq: seq, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
  const adjAcc = await worker.runOnce();
  assert.equal(adjAcc.action, 'review_accepted');

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ dbToken: env.ownerToken, commandKey: `e-${runId}`, expectedJournalSeq: seq, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: `create statements for ${date}` });
  assert.equal((await worker.runOnce()).action, 'step_finished');
  return runId;
}

test('Layer 5 [Downstream Readers & Signed Feed]: selects newest finished non-abandoned app/company_import run, enforces DB zero-dollar isolation via app_views, checks HMAC, and rejects ambiguous entity bundles', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));

  const run1120 = await runFullCompletedRun(env, worker, { date: '2026-11-20', origin: 'app', engineVersionId, row0 });
  await runFullCompletedRun(env, worker, { date: '2026-11-21', origin: 'trial', engineVersionId, row0 });
  const abandonedId = await runFullCompletedRun(env, worker, { date: '2026-11-22', origin: 'app', engineVersionId, row0 });
  await env.commands.abandonRun({
    dbToken: env.ownerToken, commandKey: 'abandon-1122', runId: abandonedId, typedPhrase: 'abandon 2026-11-22', reason: 'bad run',
  });

  // Materialize synthetic Book of Business / statements / ledger for run1120 and seed IAM world
  const emitEv1120 = (await env.pool.query(
    "SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev",
    [run1120],
  )).rows[0].ev;
  const ds = buildSyntheticEmitDataset({ statementDate: '2026-11-20' });
  await env.commands.materializeEmit({
    dbToken: env.workerToken,
    commandKey: 'l5-mat-1120',
    runId: run1120,
    attemptEventId: emitEv1120,
    statementDate: '2026-11-20',
    canonicalBobCsv: ds.canonicalBobCsv,
    coherentLedgerCsv: ds.coherentLedgerCsv,
    statementsCsv: ds.statementsCsv,
  });

  const iam = env.iam;
  await env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys()');
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');

  const reader = createDatabaseCoherenceReader({ pool: appPool, stores: env.stores, entity: 'Acme' });
  const sum = await reader.summary(iam.tokens.entityMgr);
  assert.equal(sum.available, true);
  assert.equal(sum.run, '2026-11-20');
  assert.equal(sum.sent, false);

  const bobFile = await reader.file(iam.tokens.entityMgr, 'data/canonical_bob.csv', false);
  assert.ok(bobFile.body.toString('utf8').includes('Test Member'));
  const ledgerFile = await reader.file(iam.tokens.entityMgr, 'data/coherent_ledger.csv', false);
  assert.ok(ledgerFile.body.toString('utf8').includes('100.00'));
  await assert.rejects(() => reader.file(iam.tokens.entityMgr, 'viewer.html', false), /not part of the run/i);

  // Non-entity-manager roles (selling agent, agency manager) cannot read Entity Manager bundles
  assert.equal((await reader.summary(iam.tokens.agentA)).available, false);
  assert.equal((await reader.summary(iam.tokens.agencyMgr)).available, false);

  const secret = 's'.repeat(40);
  const feed = createSignedAgentFeedReader({ pool: appPool, stores: env.stores, entity: 'Acme', secret });
  const sig = signRequest(secret, 'GET', '/feeds/acme/agent-book');
  assert.equal(feed.verify('GET', '/feeds/acme/agent-book', sig), true);
  assert.equal(feed.verify('GET', '/feeds/acme/agent-book', sig), false, 'replayed nonce must be refused');

  // Unsent run is hidden from Selling Agent until carrySent
  assert.equal((await feed.agentBook(iam.tokens.agentA)).eligible, false);

  // Record 2026-11-20 as sent
  await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'l5-sent-1120', runId: run1120, typedPhrase: 'sent 2026-11-20' });

  // Selling Agent A (NPN 11111111) sees strictly own NPN row and NULL dollars strictly from PostgreSQL app_views
  const agentBook = await feed.agentBook(iam.tokens.agentA);
  assert.equal(agentBook.eligible, true);
  assert.equal(agentBook.run, '2026-11-20');
  assert.equal(agentBook.sent, true);
  assert.equal(agentBook.rows, 1);
  assert.equal(agentBook.policies[0].writing_npn, '11111111');
  assert.equal(agentBook.policies[0].amount, null, 'PostgreSQL app_views must project NULL amount for selling agent');
  assert.equal(agentBook.policies[0].upline_amount, null, 'PostgreSQL app_views must project NULL upline_amount for selling agent');
  const [header, row1] = parseCsv(agentBook.csv);
  const amountIdx = header.indexOf('amount');
  const uplineIdx = header.indexOf('upline_amount');
  assert.equal(row1[amountIdx], '', 'agent CSV amount cell must be blank (NULL in PostgreSQL)');
  assert.equal(row1[uplineIdx], '', 'agent CSV upline_amount cell must be blank (NULL in PostgreSQL)');
  assert.ok(!agentBook.csv.includes('100.00'), 'agent CSV must contain zero dollar values');

  const houseSum = await feed.houseSummary(iam.tokens.entityMgr);
  assert.equal(houseSum.available, true);
  assert.equal(houseSum.sent, true);
  for (const f of Object.keys(houseSum.viewer.features)) assert.ok(HOUSE_FEATURES.includes(f));
  assert.equal((await feed.houseSummary(iam.tokens.agentA)).available, false);

  const envAmbig = await createTestEnv({ companySlug: 'beacon', displayName: 'Beacon' });
  t.after(() => envAmbig.cleanup());
  const mkViewer = (name) => Buffer.from(
    `<!doctype html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify({ name: 'Entity Manager', title: name, statementDate: '2026-11-21', role: 'ENTITY_MANAGER', features: { CANONICAL_BOB: { canonical_bob: 'data/canonical_bob.csv' } } })};</script></head>`,
    'utf8',
  );
  const vA = await envAmbig.stores.promoteArtifact('emits/bundles/entity-managers/EntityA/viewer.html', mkViewer('EntityA'), { checksPassed: true });
  const vB = await envAmbig.stores.promoteArtifact('emits/bundles/entity-managers/EntityB/viewer.html', mkViewer('EntityB'), { checksPassed: true });
  const dummyInput = await envAmbig.dataStore.promoteBytes(Buffer.from('k\n1\n'), { relPath: 'a.csv', checksPassed: true });
  await envAmbig.commands.importHistoricalRun({
    dbToken: envAmbig.ownerToken,
    commandKey: 'ambig-entity-bundles',
    run: { origin: 'company_import', statementDate: '2026-11-21', sourceFolder: 'company-workspaces/beacon/2026-11-21/runs/2026-11-21', emitMode: 'coherence' },
    inputVersion: { reason: 'test' },
    inputEntries: [{ relPath: 'a.csv', fileSha256: dummyInput.sha256 }],
    stepAttempts: [{
      step: 'emit',
      attemptNo: 1,
      artifacts: [
        { relPath: vA.relPath, artifactKind: vA.artifactKind, storeKind: vA.storeKind, fileSha256: vA.sha256 },
        { relPath: vB.relPath, artifactKind: vB.artifactKind, storeKind: vB.storeKind, fileSha256: vB.sha256 },
      ],
    }],
    storedFiles: [dummyInput, vA, vB],
  });
  const iamAmbig = envAmbig.iam;
  const appPoolAmbig = createRoleScopedTestPool(envAmbig.pool, 'platform_app');
  const ambigReader = createDatabaseCoherenceReader({ pool: appPoolAmbig, stores: envAmbig.stores, entity: 'UnmatchedEntity' });
  await assert.rejects(() => ambigReader.summary(iamAmbig.tokens.entityMgr), (err) => err?.code === 'AMBIGUOUS_ENTITY_BUNDLE');
});

test('Layer 5 [Web Screens & Dropped Viewers]: web endpoints, History as-of, non-sandboxed headers, and refusal of removed per-recipient bundle paths strictly as platform_app', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));

  const stagedBytes = Buffer.from('col\nnew-month\n', 'utf8');
  const stagedPromoted = await env.dataStore.promoteBytes(stagedBytes, { relPath: 'staging/new_stmt.csv', checksPassed: true });
  await env.commands.importStandaloneFiles({
    dbToken: env.ownerToken,
    commandKey: 'stage-one',
    files: [{ area: 'staging', relPath: 'staging/new_stmt.csv', artifactKind: 'data', storeKind: 'company_data', fileSha256: stagedPromoted.sha256 }],
    storedFiles: [stagedPromoted],
  });

  const launch = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'web-launch', statementDate: '2026-11-21', engineVersionId });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  const seqAtBible = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);

  const bibleRows = [row0, sampleApprovalRow({ record_id: 'policy:carrier_a:P10001#effective:2026-01-01', note: 'web-bible' })];
  await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: 'web-b', expectedJournalSeq: seqAtBible, runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished');
  const seqAtAdjust = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);

  const adjRows = [...bibleRows, sampleApprovalRow({ record_id: 'carrier_a~direct~P10001~100.00~2026-11', note: 'web-adj' })];
  await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: 'web-a', expectedJournalSeq: seqAtAdjust, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
  const adjAcc = await worker.runOnce();
  assert.equal(adjAcc.action, 'review_accepted');

  const seqReady = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ dbToken: env.ownerToken, commandKey: 'web-e', expectedJournalSeq: seqReady, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: 'create statements for 2026-11-21' });
  assert.equal((await worker.runOnce()).action, 'step_finished');

  const iam = env.iam;
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const readonlyPool = createRoleScopedTestPool(env.pool, 'platform_readonly');
  const handlers = createWebHandlers({ pool: appPool, readonlyPool, companySlug: env.companySlug, stores: env.stores });
  let currentToken = iam.tokens.owner;
  const router = createCoherenceRouter({
    handlersByCompany: new Map([[env.companySlug, handlers]]),
    authenticate: async () => currentToken,
  });

  const server = createServer((req, res) => { void router(req, res); });
  await new Promise((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
  t.after(() => new Promise((resolvePromise) => server.close(resolvePromise)));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  const reqJson = async (path, opts = {}) => {
    const res = await fetch(`${baseUrl}${path}`, opts);
    return { status: res.status, headers: res.headers, body: await res.json() };
  };

  const staging = await reqJson('/api/coherence/acme/inputs/staging');
  assert.equal(staging.status, 200);
  assert.equal(staging.body.files.length, 1);
  const incRes = await reqJson('/api/coherence/acme/inputs/include', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      commandKey: 'include-new-stmt',
      stagingFileSha256: stagedPromoted.sha256,
      targetRelPath: 'All Statements/new_stmt.csv',
      reason: 'Monthly carrier file included',
    }),
  });
  assert.equal(incRes.status, 201);

  const revCfg = await reqJson(`/api/coherence/acme/runs/${runId}/review/bible/config`);
  assert.equal(revCfg.status, 200);
  assert.equal(revCfg.body.surface, 'bible');
  assert.equal(revCfg.body.config.stamped, true);
  const csp = revCfg.headers.get('content-security-policy') || '';
  assert.ok(!csp.includes('sandbox'), 'responses must never set a sandbox CSP that blocks signed-in data fetches');
  assert.equal(revCfg.headers.get('cache-control'), 'private, no-store');
  assert.equal((await reqJson(`/api/coherence/acme/runs/${runId}/outputs/file?path=emits/bundles/entity-managers/Acme/viewer.html`)).status, 403);

  const asOf = await reqJson(`/api/coherence/acme/history/as-of?seq=${seqAtBible}`);
  assert.equal(asOf.status, 200);
  assert.equal(asOf.body.runs.find((r) => r.id === runId).stage, 'waiting for Bible');

  const runJournal = await reqJson(`/api/coherence/acme/runs/${runId}/journal`);
  assert.equal(runJournal.status, 200);
  assert.ok(runJournal.body.entries.length >= 6);

  const keyHist = await reqJson('/api/coherence/acme/approvals/history', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recordId: 'policy:carrier_a:P10001#effective:2026-01-01' }),
  });
  assert.equal(keyHist.status, 200);
  assert.equal(keyHist.body.history.length, 1);
  assert.equal(keyHist.body.history[0].note, 'web-bible');

  const chainChk = await reqJson('/api/coherence/acme/checks/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ commandKey: 'chk-chain-web', checkKind: 'chain' }),
  });
  assert.equal(chainChk.status, 201);
  assert.equal(chainChk.body.passed, true);

  for (const path of [
    '/api/coherence/acme/bundles',
    '/api/coherence/acme/bundles/config?output=selling-agents/Acme/jane-agent',
    '/api/coherence/acme/bundles/file?output=selling-agents/Acme/jane-agent&path=data/bob.csv',
  ]) {
    assert.equal((await reqJson(path)).status, 404, `removed bundle route ${path} must be refused with 404`);
  }

  // Selling Agent sees 0 rows across management surfaces, 403 on writes, and 404 on removed bundle routes
  currentToken = iam.tokens.agentA;
  assert.deepEqual((await reqJson(`/api/coherence/acme/runs/${runId}/journal`)).body.entries, []);
  assert.deepEqual((await reqJson('/api/coherence/acme/inputs/versions')).body.versions, []);
  assert.deepEqual((await reqJson('/api/coherence/acme/approvals/history', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ recordId: 'policy:carrier_a:P10001#effective:2026-01-01' }),
  })).body.history, []);
  assert.equal((await reqJson('/api/coherence/acme/checks/run', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ commandKey: 'ag-chk', checkKind: 'chain' }),
  })).status, 403);
  assert.equal((await reqJson('/api/coherence/acme/bundles')).status, 404);
});

test('Layer 5 [Review App Drift Check]: verifies via readSourceFile hook, detects copy drift, fails closed on unreadable source or missing tag, and supports explicit offline mode', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'coherence-drift-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const srcText = 'export const REVIEW_CONTRACT = 1;\n';
  const srcHash = sha256Hex(srcText);
  await mkdir(join(dir, 'coherence', 'web', 'src', 'adjust'), { recursive: true });
  await mkdir(join(dir, 'nusear', 'src', 'adjust'), { recursive: true });
  await writeFile(join(dir, 'coherence', 'web', 'src', 'adjust', 'queue.ts'), srcText, 'utf8');
  await writeFile(join(dir, 'nusear', 'src', 'adjust', 'queue.ts'), srcText, 'utf8');

  const provenance = {
    tag: 'v2.2.5',
    records: [{ source: 'web/src/adjust/queue.ts', copy: 'src/adjust/queue.ts', sourceSha256: srcHash, copySha256: srcHash, adaptation: 'None' }],
  };

  const seenCalls = [];
  const readSourceFile = async (tag, relPath) => {
    seenCalls.push([tag, relPath]);
    return readFile(join(dir, 'coherence', ...relPath.split('/')));
  };

  const clean = await checkReviewAppDrift({ provenance, nusearUiRoot: join(dir, 'nusear'), readSourceFile });
  assert.equal(clean.passed, true);
  assert.equal(clean.sourceVerified, true);
  assert.equal(clean.checkedCopies, 1);
  assert.deepEqual(seenCalls, [['v2.2.5', 'web/src/adjust/queue.ts']]);

  const badRepo = await checkReviewAppDrift({
    provenance,
    nusearUiRoot: join(dir, 'nusear'),
    coherenceRepo: join(dir, 'nonexistent-repo'),
  });
  assert.equal(badRepo.passed, false);
  assert.equal(badRepo.sourceVerified, false);
  assert.ok(badRepo.problems.some((p) => p.includes('Unable to read Coherence source')));

  const missingTag = await checkReviewAppDrift({
    provenance: { records: provenance.records },
    nusearUiRoot: join(dir, 'nusear'),
    coherenceRepo: dir,
  });
  assert.equal(missingTag.passed, false);

  const offlineOnly = await checkReviewAppDrift({
    provenance,
    nusearUiRoot: join(dir, 'nusear'),
    allowOfflineCopyOnly: true,
  });
  assert.equal(offlineOnly.passed, true);
  assert.equal(offlineOnly.sourceVerified, false);

  await writeFile(join(dir, 'nusear', 'src', 'adjust', 'queue.ts'), 'export const REVIEW_CONTRACT = 2;\n', 'utf8');
  const drifted = await checkReviewAppDrift({ provenance, nusearUiRoot: join(dir, 'nusear'), readSourceFile });
  assert.equal(drifted.passed, false);
  assert.ok(drifted.problems.some((p) => p.includes('drifted')));
});

test('Layer 5 [JSON Review API & Decision History]: serves bible.json/adjust.json configs, commits POST .../review/:surface/save synchronously, refuses View-As/stale/GET history, and returns replacesDecisionId chain strictly as platform_app', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'beacon', displayName: 'Beacon' });
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineCopyVersion(env);
  await seedStandingInput(env, { commandKey: 'web-dec-standing' });
  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createDataOnlyMockEngineMaterializer({ adjustReconfirmRecordId: null }),
    tempBaseDir: env.tempDir,
  }));

  const launch = await env.commands.launchRun({
    dbToken: env.ownerToken, commandKey: 'web-dec-launch', statementDate: '2026-10-31', engineVersionId,
  });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');

  const iam = env.iam;
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const handlers = createWebHandlers({ pool: appPool, companySlug: env.companySlug, stores: env.stores });
  let currentToken = iam.tokens.owner;
  const router = createCoherenceRouter({
    handlersByCompany: new Map([[env.companySlug, handlers]]),
    authenticate: async () => currentToken,
  });
  const server = createServer((req, res) => { void router(req, res); });
  await new Promise((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
  t.after(() => new Promise((resolvePromise) => server.close(resolvePromise)));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  const reqJson = async (path, opts = {}) => {
    const res = await fetch(`${baseUrl}${path}`, opts);
    return { status: res.status, body: await res.json() };
  };

  // Reads bible.json from company_data with zero HTML files
  const cfg = await reqJson(`/api/coherence/beacon/runs/${runId}/review/bible/config`);
  assert.equal(cfg.status, 200);
  assert.equal(cfg.body.config.surface, 'bible');
  assert.equal(cfg.body.config.queue.length, 2);

  const detail = await reqJson(`/api/coherence/beacon/runs/${runId}`);
  const seq = detail.body.latestJournalSeq;

  // View-As refuses POST /review/bible/save with 403 VIEW_AS_READ_ONLY strictly in PostgreSQL
  currentToken = iam.tokens.viewAsAgentA;
  const vaRes = await reqJson(`/api/coherence/beacon/runs/${runId}/review/bible/save`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      commandKey: 'web-va-save',
      expectedJournalSeq: seq,
      decisions: cfg.body.config.queue.map((q) => ({ recordId: q.record_id, disposition: 'CONFIRM' })),
    }),
  });
  assert.equal(vaRes.status, 403);
  assert.equal(vaRes.body.code, 'VIEW_AS_READ_ONLY');

  // Owner commits Bible decisions synchronously via app_cmd.coherence_save_review_decisions
  currentToken = iam.tokens.owner;
  const save1 = await reqJson(`/api/coherence/beacon/runs/${runId}/review/bible/save`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      commandKey: 'web-bible-save-1',
      expectedJournalSeq: seq,
      decisions: [
        { recordId: cfg.body.config.queue[0].record_id, disposition: 'CONFIRM', note: 'first' },
        { recordId: cfg.body.config.queue[1].record_id, disposition: 'CONFIRM', note: 'first' },
      ],
    }),
  });
  assert.equal(save1.status, 201);
  assert.ok(save1.body.result.decisionCommitId);

  // Stale save with old seq returns 409
  const stale = await reqJson(`/api/coherence/beacon/runs/${runId}/review/bible/save`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      commandKey: 'web-bible-save-stale',
      expectedJournalSeq: seq,
      decisions: [{ recordId: cfg.body.config.queue[0].record_id, disposition: 'CORRECT', agency: 'Beacon' }],
    }),
  });
  assert.equal(stale.status, 409);

  // GET /decisions/history returns 405; query param recordId returns 400; POST returns chain
  assert.equal((await reqJson('/api/coherence/beacon/decisions/history')).status, 405);
  assert.equal((await reqJson('/api/coherence/beacon/decisions/history?recordId=policy:carrier_a:C-101')).status, 400);

  const hist = await reqJson('/api/coherence/beacon/decisions/history', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recordId: cfg.body.config.queue[0].record_id }),
  });
  assert.equal(hist.status, 200);
  assert.equal(hist.body.history.length, 1);
  assert.equal(hist.body.history[0].replacesDecisionId, null);
  assert.equal(hist.body.history[0].note, 'first');

  // Finding 8 guard: POST /checks/run without readonlyPool refuses 503 CHECK_READER_NOT_CONFIGURED
  // (never falls back to pool), while unauthorized callers still get 403 first.
  currentToken = iam.tokens.agentA;
  const unauthNoRo = await reqJson('/api/coherence/beacon/checks/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ commandKey: 'no-ro-unauth', checkKind: 'chain' }),
  });
  assert.equal(unauthNoRo.status, 403);

  currentToken = iam.tokens.owner;
  const noRo = await reqJson('/api/coherence/beacon/checks/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ commandKey: 'no-ro-owner', checkKind: 'chain' }),
  });
  assert.equal(noRo.status, 503);
  assert.equal(noRo.body.code, 'CHECK_READER_NOT_CONFIGURED');

  // Passing the writing pool as readonlyPool is also refused with 503 CHECK_READER_NOT_CONFIGURED.
  const samePoolHandlers = createWebHandlers({ pool: appPool, readonlyPool: appPool, companySlug: env.companySlug, stores: env.stores });
  await assert.rejects(
    () => samePoolHandlers.runVerificationCheck(iam.tokens.owner, { commandKey: 'same-pool-chk', checkKind: 'chain' }),
    (err) => err?.status === 503 && err?.code === 'CHECK_READER_NOT_CONFIGURED',
  );

  // Misconfigured distinct readonlyPool (e.g. platform_app hitting 42501 on coherence.*) maps through mapPgError to 403 FORBIDDEN (never raw 500).
  const badRoPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const badRoHandlers = createWebHandlers({ pool: appPool, readonlyPool: badRoPool, companySlug: env.companySlug, stores: env.stores });
  const badRouter = createCoherenceRouter({
    handlersByCompany: new Map([[env.companySlug, badRoHandlers]]),
    authenticate: async () => iam.tokens.owner,
  });
  const badServer = createServer((req, res) => { void badRouter(req, res); });
  await new Promise((resolvePromise) => badServer.listen(0, '127.0.0.1', resolvePromise));
  t.after(() => new Promise((resolvePromise) => badServer.close(resolvePromise)));
  const badRes = await fetch(`http://127.0.0.1:${badServer.address().port}/api/coherence/beacon/checks/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ commandKey: 'bad-ro-chk', checkKind: 'chain' }),
  });
  const badBody = await badRes.json();
  assert.equal(badRes.status, 403);
  assert.equal(badBody.code, 'FORBIDDEN');
});
