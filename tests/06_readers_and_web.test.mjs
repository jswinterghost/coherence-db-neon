// R15, R16, R14.2, R11 (sandboxed viewer audit) tests for downstream readers, Clearpath feed,
// HTTP web handlers, History "as of", recipient bundle scope checks, and review app drift check.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import {
  AGENT_BOOK_COLUMNS,
  createDatabaseClearpathFeed,
  createDatabaseCoherenceReader,
  HOUSE_FEATURES,
  signRequest,
} from '../src/readers/downstream-reader.mjs';
import { checkReviewAppDrift } from '../src/web/drift-check.mjs';
import { createWebHandlers } from '../src/web/handlers.mjs';
import { createCoherenceRouter } from '../src/web/router.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import { sha256Hex } from '../src/util/crypto.mjs';
import { parseCsv } from '../src/util/csv.mjs';
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';
import { createMockEngineMaterializer, makeOverlayCsv, sampleApprovalRow, seedEngineVersion, seedStandingInput } from './helpers/fixtures.mjs';

const pgCheck = await checkPgAvailable();

async function runFullCompletedRun(env, worker, { date, origin = 'app', engineVersionId, row0 }) {
  const launch = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: `launch-${origin}-${date}`, statementDate: date, origin, engineVersionId,
  });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');

  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const bibleRows = [row0, sampleApprovalRow({ record_id: `policy:aetna:B-${date}#effective:2026-01-01` })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: `b-${runId}`, expectedJournalSeq: seq, runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished'); // adjust

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const adjRows = [...bibleRows, sampleApprovalRow({ record_id: `aetna~direct~A-${date}~100.00~2026-11` })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: `a-${runId}`, expectedJournalSeq: seq, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
  const adjAcc = await worker.runOnce();
  assert.equal(adjAcc.action, 'review_accepted');

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ actor: env.ownerActor, commandKey: `e-${runId}`, expectedJournalSeq: seq, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: `create statements for ${date}` });
  assert.equal((await worker.runOnce()).action, 'step_finished'); // emit
  return runId;
}

test('R15: downstream reader selects only newest finished non-abandoned app/company_import run, and Clearpath feed strips dollar columns and checks HMAC', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
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

  // 1. Finished app run on 2026-11-20
  await runFullCompletedRun(env, worker, { date: '2026-11-20', origin: 'app', engineVersionId, row0 });
  // 2. Newer finished TRIAL run on 2026-11-21 -> MUST BE IGNORED by downstream reader!
  await runFullCompletedRun(env, worker, { date: '2026-11-21', origin: 'trial', engineVersionId, row0 });
  // 3. Newer finished ABANDONED app run on 2026-11-22 -> MUST BE IGNORED by downstream reader!
  const abandonedId = await runFullCompletedRun(env, worker, { date: '2026-11-22', origin: 'app', engineVersionId, row0 });
  await env.commands.abandonRun({
    actor: env.ownerActor, commandKey: 'abandon-1122', runId: abandonedId, typedPhrase: 'abandon 2026-11-22', reason: 'bad run',
  });

  const reader = createDatabaseCoherenceReader({ pool: env.pool, stores: env.stores, entity: 'Phalanx' });
  const sum = await reader.summary();
  assert.equal(sum.available, true);
  assert.equal(sum.run, '2026-11-20', 'must select newest finished non-abandoned app/company_import run, ignoring trial and abandoned');
  assert.equal(sum.sent, false);

  const bobFile = await reader.file('data/canonical_bob.csv', false);
  assert.ok(bobFile.body.toString('utf8').includes('Test Member'));
  await assert.rejects(() => reader.file('viewer.html', false), /not part of the run/i);

  // Clearpath feed: HMAC + replay check + no-dollar AGENT_BOOK_COLUMNS filter
  const secret = 's'.repeat(40);
  const feed = createDatabaseClearpathFeed({ pool: env.pool, stores: env.stores, entity: 'Phalanx', secret });
  const sig = signRequest(secret, 'GET', '/feeds/clearpath/agent-book?name=Jane+Agent');
  assert.equal(feed.verify('GET', '/feeds/clearpath/agent-book?name=Jane+Agent', sig), true);
  assert.equal(feed.verify('GET', '/feeds/clearpath/agent-book?name=Jane+Agent', sig), false, 'replayed nonce must be refused');

  const agentBook = await feed.agentBook('Jane Agent');
  assert.equal(agentBook.eligible, true);
  assert.equal(agentBook.run, '2026-11-20');
  const [header] = parseCsv(agentBook.csv);
  assert.ok(!header.includes('amount'), 'selling agent amount column MUST be stripped');
  assert.ok(!header.includes('gross_comm'), 'gross_comm MUST be stripped');
  for (const col of header) assert.ok(AGENT_BOOK_COLUMNS.includes(col));
  assert.ok(!agentBook.viewer.defaultVisible.BOB.bob.includes('amount'));
  assert.equal(agentBook.viewer.defaultFilters.BOB.bob.amount, undefined);

  const houseSum = await feed.houseSummary();
  assert.equal(houseSum.available, true);
  for (const f of Object.keys(houseSum.viewer.features)) assert.ok(HOUSE_FEATURES.includes(f));
});

test('R16, R4, R14.2 & R11 (sandboxed viewer audit): web endpoints, History as-of, recipient bundle scoping, and non-sandboxed headers', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
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

  // Stage a file to test R16.1 "Include in calculations"
  const stagedBytes = Buffer.from('col\nnew-month\n', 'utf8');
  const stagedPromoted = await env.dataStore.promoteBytes(stagedBytes, { relPath: 'staging/new_stmt.csv', checksPassed: true });
  await env.commands.importStandaloneFiles({
    actor: env.ownerActor,
    commandKey: 'stage-one',
    files: [{ area: 'staging', relPath: 'staging/new_stmt.csv', artifactKind: 'data', storeKind: 'company_data', fileSha256: stagedPromoted.sha256 }],
    storedFiles: [stagedPromoted],
  });

  // Complete one run and record seq right after Bible for "as of" history test!
  const launch = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'web-launch', statementDate: '2026-11-21', engineVersionId,
  });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  const seqAtBible = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);

  const bibleRows = [row0, sampleApprovalRow({ record_id: 'policy:aetna:P10001#effective:2026-01-01', note: 'web-bible' })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'web-b', expectedJournalSeq: seqAtBible, runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished'); // adjust
  const seqAtAdjust = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);

  const adjRows = [...bibleRows, sampleApprovalRow({ record_id: 'aetna~direct~P10001~100.00~2026-11', note: 'web-adj' })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'web-a', expectedJournalSeq: seqAtAdjust, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
  const adjAcc = await worker.runOnce();
  assert.equal(adjAcc.action, 'review_accepted');

  const seqReady = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ actor: env.ownerActor, commandKey: 'web-e', expectedJournalSeq: seqReady, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: 'create statements for 2026-11-21' });
  assert.equal((await worker.runOnce()).action, 'step_finished'); // emit

  const handlers = createWebHandlers({ pool: env.pool, companySlug: 'phalanx', stores: env.stores, commands: env.commands, entity: 'Phalanx' });
  let currentActor = env.ownerActor;
  const router = createCoherenceRouter({
    handlersByCompany: new Map([['phalanx', handlers]]),
    authenticate: async () => currentActor,
  });

  const server = createServer((req, res) => { void router(req, res); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  const reqJson = async (path, opts = {}) => {
    const res = await fetch(`${baseUrl}${path}`, opts);
    return { status: res.status, headers: res.headers, body: await res.json() };
  };

  // 1. R16.1 Staging + Include in calculations
  const staging = await reqJson('/api/coherence/phalanx/inputs/staging');
  assert.equal(staging.status, 200);
  assert.equal(staging.body.files.length, 1);
  const incRes = await reqJson('/api/coherence/phalanx/inputs/include', {
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

  // 2. R16.2 Review config returns JSON only (never HTML code!), outputs refuses viewer.html
  const revCfg = await reqJson(`/api/coherence/phalanx/runs/${runId}/review/bible/config`);
  assert.equal(revCfg.status, 200);
  assert.equal(revCfg.body.surface, 'bible');
  assert.equal(revCfg.body.config.stamped, true);

  const htmlDownload = await reqJson(`/api/coherence/phalanx/runs/${runId}/outputs/file?path=emits/bundles/entity-managers/Phalanx/viewer.html`);
  assert.equal(htmlDownload.status, 403);

  // 3. R16.3 History "as of", run journal, and approval key history (via POST body so record_id stays out of URL logs!)
  const asOf = await reqJson(`/api/coherence/phalanx/history/as-of?seq=${seqAtBible}`);
  assert.equal(asOf.status, 200);
  assert.equal(asOf.body.runs.find((r) => r.id === runId).stage, 'waiting for Bible');

  const runJournal = await reqJson(`/api/coherence/phalanx/runs/${runId}/journal`);
  assert.equal(runJournal.status, 200);
  assert.ok(runJournal.body.entries.length >= 6);

  const keyHist = await reqJson('/api/coherence/phalanx/approvals/history', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recordId: 'policy:aetna:P10001#effective:2026-01-01' }),
  });
  assert.equal(keyHist.status, 200);
  assert.equal(keyHist.body.history.length, 1);
  assert.equal(keyHist.body.history[0].note, 'web-bible');

  // 4. R16.4 Checks endpoint
  const chainChk = await reqJson('/api/coherence/phalanx/checks/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ commandKey: 'chk-chain-web', checkKind: 'chain' }),
  });
  assert.equal(chainChk.status, 201);
  assert.equal(chainChk.body.passed, true);

  // 5. R16.5 & R4.4 & R14.2 & R11 sandboxed viewer audit: Recipient bundle access
  currentActor = {
    id: 'jane-agent',
    kind: 'recipient',
    company: 'phalanx',
    recipientRole: 'SELLING_AGENT',
    recipientName: 'Jane Agent',
    recipientScope: { npns: ['12345678'], entities: ['Phalanx'] },
  };

  // Recipient MUST be refused journal, inputs, and approvals!
  assert.equal((await reqJson(`/api/coherence/phalanx/runs/${runId}/journal`)).status, 403);
  assert.equal((await reqJson('/api/coherence/phalanx/inputs/versions')).status, 403);
  assert.equal((await reqJson('/api/coherence/phalanx/approvals/history', { method: 'POST', body: JSON.stringify({ recordId: 'x' }) })).status, 403);

  // Recipient sees ONLY their own bundle, NOT Entity Manager's!
  const bundles = await reqJson('/api/coherence/phalanx/bundles');
  assert.equal(bundles.status, 200);
  assert.equal(bundles.body.bundles.length, 1);
  assert.equal(bundles.body.bundles[0].output, 'selling-agents/Phalanx/jane-agent');

  // Accessing Entity Manager bundle -> 403!
  assert.equal((await reqJson('/api/coherence/phalanx/bundles/config?output=entity-managers/Phalanx')).status, 403);

  // Accessing own bundle config + data file -> 200 with NO sandbox CSP blocking data loading (R11 audit)!
  const ownCfg = await reqJson('/api/coherence/phalanx/bundles/config?output=selling-agents/Phalanx/jane-agent');
  assert.equal(ownCfg.status, 200);
  const csp = ownCfg.headers.get('content-security-policy') || '';
  assert.ok(!csp.includes('sandbox'), 'bundle response must NEVER set a sandbox CSP that blocks CoherenceScreen data fetches (R11)');
  assert.equal(ownCfg.headers.get('cache-control'), 'private, no-store');

  const ownCsvRes = await fetch(`${baseUrl}/api/coherence/phalanx/bundles/file?output=selling-agents/Phalanx/jane-agent&path=${encodeURIComponent(ownCfg.body.viewer.features.BOB.bob)}`);
  assert.equal(ownCsvRes.status, 200);
  assert.ok((await ownCsvRes.text()).includes('Test Member'));
});

test('R16.2: review app drift check against Coherence web/src/adjust passes on clean copy and detects drift', async (t) => {
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
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

  const clean = await checkReviewAppDrift({ provenance, nusearUiRoot: join(dir, 'nusear'), sourceDir: join(dir, 'coherence') });
  assert.equal(clean.passed, true);
  assert.equal(clean.checkedCopies, 1);

  // Introduce unapproved drift in copy
  await writeFile(join(dir, 'nusear', 'src', 'adjust', 'queue.ts'), 'export const REVIEW_CONTRACT = 2;\n', 'utf8');
  const drifted = await checkReviewAppDrift({ provenance, nusearUiRoot: join(dir, 'nusear'), sourceDir: join(dir, 'coherence') });
  assert.equal(drifted.passed, false);
  assert.ok(drifted.problems.some((p) => p.includes('drifted')));
});
