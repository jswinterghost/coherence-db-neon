// Layer 5: protects downstream readers, signed agent feeds, ambiguity checks on entity bundles,
// refusal of removed per-recipient bundle paths, non-sandboxed data headers, server-only viewer parsing,
// and review-app drift detection.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  createDatabaseCoherenceReader,
  createSignedAgentFeedReader,
  DEFAULT_AGENT_BOOK_COLUMNS,
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
  createDataOnlyMockEngineMaterializer,
  createMockEngineMaterializer,
  makeOverlayCsv,
  sampleApprovalRow,
  seedEngineCopyVersion,
  seedEngineVersion,
  seedStandingInput,
} from './helpers/fixtures.mjs';
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

async function runFullCompletedRun(env, worker, { date, origin = 'app', engineVersionId, row0 }) {
  const launch = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: `launch-${origin}-${date}`, statementDate: date, origin, engineVersionId,
  });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');

  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const bibleRows = [row0, sampleApprovalRow({ record_id: `policy:carrier_a:B-${date}#effective:2026-01-01` })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: `b-${runId}`, expectedJournalSeq: seq, runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished');

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const adjRows = [...bibleRows, sampleApprovalRow({ record_id: `carrier_a~direct~A-${date}~100.00~2026-11` })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: `a-${runId}`, expectedJournalSeq: seq, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
  const adjAcc = await worker.runOnce();
  assert.equal(adjAcc.action, 'review_accepted');

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ actor: env.ownerActor, commandKey: `e-${runId}`, expectedJournalSeq: seq, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: `create statements for ${date}` });
  assert.equal((await worker.runOnce()).action, 'step_finished');
  return runId;
}

test('Layer 5 [Downstream Readers & Signed Feed]: selects newest finished non-abandoned app/company_import run, strips dollar columns, checks HMAC, and rejects ambiguous entity bundles', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));

  await runFullCompletedRun(env, worker, { date: '2026-11-20', origin: 'app', engineVersionId, row0 });
  await runFullCompletedRun(env, worker, { date: '2026-11-21', origin: 'trial', engineVersionId, row0 });
  const abandonedId = await runFullCompletedRun(env, worker, { date: '2026-11-22', origin: 'app', engineVersionId, row0 });
  await env.commands.abandonRun({
    actor: env.ownerActor, commandKey: 'abandon-1122', runId: abandonedId, typedPhrase: 'abandon 2026-11-22', reason: 'bad run',
  });

  const reader = createDatabaseCoherenceReader({ pool: env.pool, stores: env.stores, entity: 'Acme' });
  const sum = await reader.summary();
  assert.equal(sum.available, true);
  assert.equal(sum.run, '2026-11-20');
  assert.equal(sum.sent, false);

  const bobFile = await reader.file('data/canonical_bob.csv', false);
  assert.ok(bobFile.body.toString('utf8').includes('Test Member'));
  const ledgerFile = await reader.file('data/coherent_ledger.csv', false);
  assert.ok(ledgerFile.body.toString('utf8').includes('100.00'));
  await assert.rejects(() => reader.file('viewer.html', false), /not part of the run/i);

  const secret = 's'.repeat(40);
  const feed = createSignedAgentFeedReader({ pool: env.pool, stores: env.stores, entity: 'Acme', secret });
  const sig = signRequest(secret, 'GET', '/feeds/acme/agent-book?name=Jane+Agent');
  assert.equal(feed.verify('GET', '/feeds/acme/agent-book?name=Jane+Agent', sig), true);
  assert.equal(feed.verify('GET', '/feeds/acme/agent-book?name=Jane+Agent', sig), false, 'replayed nonce must be refused');

  const agentBook = await feed.agentBook('Jane Agent');
  assert.equal(agentBook.eligible, true);
  assert.equal(agentBook.run, '2026-11-20');
  const [header] = parseCsv(agentBook.csv);
  assert.ok(!header.includes('amount'), 'selling agent amount column must be stripped');
  assert.ok(!header.includes('gross_comm'), 'gross_comm must be stripped');
  for (const col of header) assert.ok(DEFAULT_AGENT_BOOK_COLUMNS.includes(col));
  assert.ok(!agentBook.viewer.defaultVisible.BOB.bob.includes('amount'));
  assert.equal(agentBook.viewer.defaultFilters.BOB.bob.amount, undefined);

  const houseSum = await feed.houseSummary();
  assert.equal(houseSum.available, true);
  for (const f of Object.keys(houseSum.viewer.features)) assert.ok(HOUSE_FEATURES.includes(f));

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
    actor: envAmbig.ownerActor,
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
  const ambigReader = createDatabaseCoherenceReader({ pool: envAmbig.pool, stores: envAmbig.stores, entity: 'UnmatchedEntity' });
  await assert.rejects(() => ambigReader.summary(), (err) => err?.code === 'AMBIGUOUS_ENTITY_BUNDLE');
});

test('Layer 5 [Web Screens & Dropped Viewers]: web endpoints, History as-of, non-sandboxed headers, and refusal of removed per-recipient bundle paths', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));

  const stagedBytes = Buffer.from('col\nnew-month\n', 'utf8');
  const stagedPromoted = await env.dataStore.promoteBytes(stagedBytes, { relPath: 'staging/new_stmt.csv', checksPassed: true });
  await env.commands.importStandaloneFiles({
    actor: env.ownerActor,
    commandKey: 'stage-one',
    files: [{ area: 'staging', relPath: 'staging/new_stmt.csv', artifactKind: 'data', storeKind: 'company_data', fileSha256: stagedPromoted.sha256 }],
    storedFiles: [stagedPromoted],
  });

  const launch = await env.commands.launchRun({ actor: env.ownerActor, commandKey: 'web-launch', statementDate: '2026-11-21', engineVersionId });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  const seqAtBible = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);

  const bibleRows = [row0, sampleApprovalRow({ record_id: 'policy:carrier_a:P10001#effective:2026-01-01', note: 'web-bible' })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'web-b', expectedJournalSeq: seqAtBible, runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished');
  const seqAtAdjust = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);

  const adjRows = [...bibleRows, sampleApprovalRow({ record_id: 'carrier_a~direct~P10001~100.00~2026-11', note: 'web-adj' })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'web-a', expectedJournalSeq: seqAtAdjust, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
  const adjAcc = await worker.runOnce();
  assert.equal(adjAcc.action, 'review_accepted');

  const seqReady = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ actor: env.ownerActor, commandKey: 'web-e', expectedJournalSeq: seqReady, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: 'create statements for 2026-11-21' });
  assert.equal((await worker.runOnce()).action, 'step_finished');

  const handlers = createWebHandlers({ pool: env.pool, companySlug: env.companySlug, stores: env.stores, commands: env.commands });
  let currentActor = env.ownerActor;
  const router = createCoherenceRouter({
    handlersByCompany: new Map([[env.companySlug, handlers]]),
    authenticate: async () => currentActor,
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

  currentActor = { id: 'jane-agent', kind: 'recipient', company: 'acme' };
  assert.equal((await reqJson(`/api/coherence/acme/runs/${runId}/journal`)).status, 403);
  assert.equal((await reqJson('/api/coherence/acme/inputs/versions')).status, 403);
  assert.equal((await reqJson('/api/coherence/acme/approvals/history', { method: 'POST', body: JSON.stringify({ recordId: 'x' }) })).status, 403);
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

test('Layer 5 [JSON Review API & Decision History]: serves bible.json/adjust.json configs, commits POST .../review/:surface/save synchronously, refuses View-As/stale/GET history, and returns replacesDecisionId chain', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'beacon', displayName: 'Beacon' });
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineCopyVersion(env);
  await seedStandingInput(env, { commandKey: 'web-dec-standing' });
  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createDataOnlyMockEngineMaterializer({ adjustReconfirmRecordId: null }),
    tempBaseDir: env.tempDir,
  }));

  const launch = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'web-dec-launch', statementDate: '2026-10-31', engineVersionId,
  });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');

  const handlers = createWebHandlers({ pool: env.pool, companySlug: env.companySlug, stores: env.stores, commands: env.commands });
  let currentActor = env.ownerActor;
  const router = createCoherenceRouter({
    handlersByCompany: new Map([[env.companySlug, handlers]]),
    authenticate: async () => currentActor,
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

  // View-As refuses POST /review/bible/save with 403
  currentActor = { id: 'test-owner', kind: 'owner', viewingAs: { id: 'viewer', kind: 'recipient' } };
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

  // Owner commits Bible decisions synchronously
  currentActor = env.ownerActor;
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
});
