// Layer 2: protects member PHI confidentiality, Nusear source-code isolation,
// and database and infrastructure security policies.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { chmod, mkdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { assertCanRead, assertCanWrite } from '../src/commands/authz.mjs';
import {
  validateCloudSqlConfig,
  verifyCloudSqlConfigFile,
  verifyDatabaseConfigInvariants,
  verifyPgHbaFile,
} from '../src/config/policy-checks.mjs';
import { createClient } from '../src/db/pg-client.mjs';
import { createFileObjectStore, createMemoryObjectStore } from '../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../src/storage/stores.mjs';
import { crc32cBase64, fingerprintBytes, sha256Hex } from '../src/util/crypto.mjs';
import { createSafeLogger, redactPhi, sanitizeErrorMessage } from '../src/util/redact.mjs';
import { createWebHandlers } from '../src/web/handlers.mjs';
import { createCoherenceRouter } from '../src/web/router.mjs';
import { buildAttemptWorkspace, defaultMaterializeEngine } from '../src/worker/folder-builder.mjs';
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
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';

const execFileAsync = promisify(execFile);
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pgCheck = await checkPgAvailable();

test('Layer 2 [Storage Integrity]: CRC32C vectors, promotion-before-checks refusal, MD5+CRC32C verification, and filesystem create-only store', async (t) => {
  assert.equal(crc32cBase64(Buffer.alloc(0)), 'AAAAAA==');
  assert.equal(crc32cBase64(Buffer.from('123456789', 'ascii')), '4waSgw==');

  const mem = createMemoryObjectStore({ label: 'data-mem' });
  const dataStore = createDataStore({ backend: mem });
  const payload = Buffer.from('col1,col2\n1,2\n', 'utf8');

  await assert.rejects(
    () => dataStore.promoteBytes(payload, { relPath: 'overlay.csv', checksPassed: false }),
    /PROMOTION_BEFORE_CHECKS|before required checks/i,
  );
  assert.equal(mem.listObjectNames().length, 0);

  mem.hooks.failNextCreate = new Error('transient network reset');
  await assert.rejects(
    () => dataStore.promoteBytes(payload, { relPath: 'overlay.csv', checksPassed: true }),
    /transient network reset/i,
  );
  assert.equal(mem.listObjectNames().length, 0);

  const first = await dataStore.promoteBytes(payload, { relPath: 'overlay.csv', checksPassed: true });
  assert.equal(first.alreadyExisted, false);
  assert.equal(first.objectName, `objects/${first.sha256}`);

  const second = await dataStore.promoteBytes(payload, { relPath: 'overlay.csv', checksPassed: true });
  assert.equal(second.alreadyExisted, true);
  assert.equal(second.md5B64, first.md5B64);
  assert.equal(second.crc32cB64, first.crc32cB64);

  mem.hooks.corruptStoredMeta.set(first.objectName, { crc32cB64: 'AAAAAA==' });
  await assert.rejects(
    () => dataStore.promoteBytes(payload, { relPath: 'overlay.csv', checksPassed: true }),
    /checksum mismatch/i,
  );
  mem.hooks.corruptStoredMeta.clear();

  const dir = await mkdtemp(join(tmpdir(), 'coherence-filestore-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const fsStore = createDataStore({ backend: createFileObjectStore({ rootDir: dir }) });
  const bytes = Buffer.from('a,b\n10,20\n', 'utf8');
  const r1 = await fsStore.promoteBytes(bytes, { relPath: 'statements_20261121.csv', checksPassed: true });
  assert.equal(r1.alreadyExisted, false);
  const r2 = await fsStore.promoteBytes(bytes, { relPath: 'statements_20261121.csv', checksPassed: true });
  assert.equal(r2.alreadyExisted, true);
  assert.deepEqual(await fsStore.readVerified(r1.sha256, r1), bytes);
});

test('Layer 2 [Negative Invariant]: zero code-bearing files or engine bytes can ever enter a company store (including mid-file script tags)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const codeMem = createMemoryObjectStore({ label: 'nusear-code' });
  const dataMem = createMemoryObjectStore({ label: 'company-data' });
  const codeStore = createCodeStore({ backend: codeMem });
  const dataStore = createDataStore({ backend: dataMem });

  assert.throws(() => createStorePair({ codeStore, dataStore: createDataStore({ backend: codeMem }) }), /never share/i);
  const stores = createStorePair({ codeStore, dataStore });

  const midBufferScriptCsv = `${'a,b\n'}${'1,2\n'.repeat(3000)}<script>window.__VIEWER_CONFIG__={}</script>\n${'3,4\n'.repeat(4500)}`;
  assert.ok(Buffer.byteLength(midBufferScriptCsv, 'utf8') > 30_000);

  for (const [relPath, content] of [
    ['bible.html', '<!doctype html><html></html>'],
    ['company_emit.py', 'print("hi")'],
    ['coherence.bundle', '# v2 git bundle\n'],
    ['viewer.mjs', 'export default 1;'],
    ['fake.csv', 'window.__VIEWER_CONFIG__={"a":1};'],
    ['disguised.csv', '<!DOCTYPE html><html><script>alert(1)</script></html>'],
    ['mid-buffer-script.csv', midBufferScriptCsv],
  ]) {
    await assert.rejects(
      () => dataStore.promoteBytes(Buffer.from(content, 'utf8'), { relPath, checksPassed: true }),
      /CODE_IN_DATA_STORE_FORBIDDEN|code-bearing/i,
      `${relPath} must never enter company_data`,
    );
  }
  assert.equal(dataMem.listObjectNames().length, 0);

  const viewerArt = await stores.promoteArtifact('emits/bundles/entity-managers/Acme/viewer.html', Buffer.from('<!doctype html><html></html>'), { checksPassed: true });
  const csvArt = await stores.promoteArtifact('emits/statements_20261121.csv', Buffer.from('a,b\n1,2\n'), { checksPassed: true });
  assert.equal(viewerArt.storeKind, 'nusear_code');
  assert.equal(viewerArt.artifactKind, 'code_bearing');
  assert.equal(csvArt.storeKind, 'company_data');
  assert.equal(csvArt.artifactKind, 'data');
  assert.equal(dataMem.listObjectNames()[0], `objects/${fingerprintBytes(Buffer.from('a,b\n1,2\n')).sha256}`);

  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const sha = sha256Hex('abc');
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('test-owner', 'bad_obj', 'bad-obj-key', $1, '{"commitments":{"counts":{"stored_files":1},"hashes":{}}}'::jsonb) RETURNING seq`,
        [sha256Hex('bad-obj')],
      );
      await c.query(
        `INSERT INTO coherence.stored_files (store_kind, sha256, byte_size, md5_b64, crc32c_b64, object_name, journal_seq)
         VALUES ('company_data', $1, 3, 'kAFQmDzST7DWlj99KOF/cg==', 'Nks/tw==', 'wrong/name', $2)`,
        [sha, String(je.rows[0].seq)],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /object_name|check constraint/i);

  const fakeDataFile = await env.dataStore.promoteBytes(Buffer.from('a,b\n1,2\n'), { relPath: 'bible.csv', checksPassed: true });
  await env.commands.registerStoredFiles({ actor: env.ownerActor, commandKey: 'reg-art-test', files: [fakeDataFile] });
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const runId = randomUUID();
      const evId = randomUUID();
      const snapId = randomUUID();
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('test-owner', 'bad_art', 'bad-art-key', $1, '{"commitments":{"counts":{"input_versions":1,"runs":1,"step_attempt_events":1,"artifacts":1},"hashes":{}}}'::jsonb) RETURNING seq`,
        [sha256Hex('bad-art')],
      );
      const seq = String(je.rows[0].seq);
      await c.query(
        `INSERT INTO coherence.input_versions (id, line_kind, source_kind, reason, entry_count, entries_sha256, change_count, changes_sha256, store_kind, journal_seq)
         VALUES ($1::uuid, 'snapshot', 'mac_import', 'test', 0, $2, 0, $2, 'company_data', $3)`,
        [snapId, sha256Hex(''), seq],
      );
      await c.query(
        `INSERT INTO coherence.runs (id, statement_date, folder_number, origin, input_version_id, emit_mode, source_folder, journal_seq)
         VALUES ($1::uuid, '2026-11-21', 1, 'mac_import', $2::uuid, 'coherence', 'test-bad-art', $3)`,
        [runId, snapId, seq],
      );
      await c.query(
        `INSERT INTO coherence.step_attempt_events (id, run_id, step, attempt_no, event_kind, artifact_count, artifacts_sha256, journal_seq)
         VALUES ($1::uuid, $2::uuid, 'bible', 1, 'finished', 1, $3, $4)`,
        [evId, runId, sha256Hex('x'), seq],
      );
      await c.query(
        `INSERT INTO coherence.artifacts (attempt_event_id, rel_path, artifact_kind, store_kind, file_sha256, journal_seq)
         VALUES ($1::uuid, 'bible.html', 'data', 'company_data', $2, $3)`,
        [evId, fakeDataFile.sha256, seq],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /code-bearing/i);
});

test('Layer 2 [Negative Invariant]: no record id, member identifier, or SQL parameter appears in any log, error, URL, or Python overlay-checker stderr', async (t) => {
  const raw = [
    'Failed on carrier_b~direct~SMITH JOHN~100.00~2026-11',
    'and policy:carrier_a:H12345#effective:2026-01-01',
    'MBI 1EG4-TE5-MK72 SSN 123-45-6789 email jane@example.com phone (555) 123-4567',
    'DETAIL: Key (record_id)=(carrier_b~direct~DOE JANE~50.00) already exists.',
    'Failing row contains (1, SECRET_MEMBER_VAL)',
    "PARAMETERS: $1 = 'carrier_b~direct~LEAKED~100.00', $2 = '555-987-6543'",
  ].join(' ');
  const cleaned = redactPhi(raw);
  for (const forbidden of ['SMITH', 'JOHN', 'H12345', '1EG4-TE5-MK72', '123-45-6789', 'jane@example.com', '555', 'DOE', 'JANE', 'SECRET_MEMBER_VAL', 'LEAKED']) {
    assert.ok(!cleaned.includes(forbidden), `redactPhi leaked sensitive token: ${forbidden}`);
  }
  const errMsg = sanitizeErrorMessage(new Error(raw));
  for (const forbidden of ['SMITH', 'JOHN', 'H12345', 'SECRET_MEMBER_VAL', 'LEAKED']) {
    assert.ok(!errMsg.includes(forbidden), `sanitizeErrorMessage leaked: ${forbidden}`);
  }

  // Pipe-delimited Coherence record IDs (carrier|channel|subject|amount|stamp from coherence/phase3/statement.py)
  const pipeRaw = [
    'Failed on carrier_a|direct|1EG4TE5MK72|100.00|2026-11',
    'and carrier_a|direct|PN:POL99881|-50.25|2026-11-15',
    'and carrier_b|slate|NM:doe,jane|42.50|2026-03',
    'and carrier_b|danman|NM:de,la,cruz,maria|-7.07|2026-01-18',
    'and carrier_a|direct|98765432|25.00|2026-11',
    'and carrier_a|direct|None|15.00|2026-11',
    'and None|direct|NM:smith,robert|100.00|None',
    'json={"record_id":"carrier_a|direct|NM:taylor,pat|12.34|2026-05"}',
  ].join(' ');
  const pipeCleaned = redactPhi(pipeRaw);
  for (const forbidden of ['1EG4TE5MK72', 'POL99881', 'doe,jane', 'de,la,cruz,maria', '98765432', 'smith,robert', 'taylor,pat']) {
    assert.ok(!pipeCleaned.includes(forbidden), `redactPhi leaked pipe record_id token: ${forbidden}`);
  }
  assert.ok(pipeCleaned.includes('[redacted-record-id]'), 'redactPhi must replace pipe record_ids with [redacted-record-id]');
  const pipeErrMsg = sanitizeErrorMessage(new Error(pipeRaw));
  for (const forbidden of ['POL99881', 'doe,jane', 'de,la,cruz,maria', 'smith,robert', 'taylor,pat']) {
    assert.ok(!pipeErrMsg.includes(forbidden), `sanitizeErrorMessage leaked pipe record_id token: ${forbidden}`);
  }
  // Benign pipe-separated log fields must not be falsely redacted
  const benignPipe = 'status=ok | count=3 | mode=local';
  assert.equal(redactPhi(benignPipe), benignPipe);

  const captured = [];
  const logger = createSafeLogger({
    log: (line) => captured.push(line),
    warn: (line) => captured.push(line),
    error: (line) => captured.push(line),
  });
  logger.error('db_failure', {
    recordId: 'policy:carrier_a:P99999#effective:2026-01-01',
    sqlParams: ['carrier_b~direct~MEMBER_ONE~100.00', '1EG4-TE5-MK72'],
    detail: "Key (policy)=(SECRET_POLICY) $1 = 'HIDDEN_VAL'",
  });
  const logged = captured.join('\n');
  for (const forbidden of ['P99999', 'MEMBER_ONE', '1EG4-TE5-MK72', 'SECRET_POLICY', 'HIDDEN_VAL']) {
    assert.ok(!logged.includes(forbidden), `safe logger leaked: ${forbidden}`);
  }

  if (pgCheck.available) {
    const env = await createTestEnv();
    try {
      const secretRow = sampleApprovalRow({
        record_id: 'carrier_b~direct~SECRET MEMBER~100.00~2026-11',
        approved_amount: '999.99',
      });
      const csv = makeOverlayCsv([secretRow]);
      const stored = await env.dataStore.promoteBytes(Buffer.from(csv, 'utf8'), { relPath: 'overlay.csv', checksPassed: true });
      // Trigger DB invariant error: header_kind='v1' cannot carry approved_* columns!
      let caught = null;
      try {
        await env.commands.registerApprovalsFile({
          actor: env.ownerActor,
          commandKey: 'pg-err-redact-test',
          storedFile: stored,
          headerKind: 'v1',
          rowCount: 1,
          extendsSha256: null,
          sharedRowCount: 0,
          addedRows: [{ row_no: 1, ...secretRow }],
        });
      } catch (err) {
        caught = err;
      }
      assert.ok(caught, 'DB must reject v1 approvals_file carrying approved_* columns');
      for (const secret of ['SECRET', 'MEMBER', '999.99', 'carrier_b~direct']) {
        assert.ok(!String(caught.message).includes(secret), `command-layer error leaked ${secret}`);
      }
    } finally {
      await env.cleanup();
    }
  }

  const pyStubDir = await mkdtemp(join(tmpdir(), 'coherence-py-phi-'));
  t.after(() => rm(pyStubDir, { recursive: true, force: true }));
  await mkdir(join(pyStubDir, 'polars'), { recursive: true });
  await mkdir(join(pyStubDir, 'coherence'), { recursive: true });
  await writeFile(join(pyStubDir, 'polars', '__init__.py'), [
    'class Frame:',
    '    def __init__(self, cols): self.columns = cols',
    'def read_csv(path, **kw):',
    '    return Frame(("record_id","disposition","agent","agency","policy","book","month","status","note","committed_at","approved_amount","approved_agency","approved_agent","approved_agency_from","approved_agent_from"))',
  ].join('\n'), 'utf8');
  await writeFile(join(pyStubDir, 'coherence', '__init__.py'), '', 'utf8');
  await writeFile(join(pyStubDir, 'coherence', 'run.py'), 'from pathlib import Path\ndef root(d): return Path(d)\n', 'utf8');
  await writeFile(join(pyStubDir, 'coherence', 'overlay.py'), [
    'ADJUSTMENT_COLUMNS_V1 = ("record_id","disposition","agent","agency","policy","book","month","status","note","committed_at")',
    'ADJUSTMENT_COLUMNS = ADJUSTMENT_COLUMNS_V1 + ("approved_amount","approved_agency","approved_agent","approved_agency_from","approved_agent_from")',
    'PRIOR_REL = "input/Overlay/overlay.csv"',
    'RUN_REL = "overlay.csv"',
    'def _read(path):',
    '    raise RuntimeError("Parse error on carrier_b~direct~SENSITIVE MEMBER~100.00 MBI 1EG4-TE5-MK72")',
  ].join('\n'), 'utf8');
  await writeFile(join(pyStubDir, 'cand.csv'), 'record_id\n', 'utf8');
  let pyStderr = '';
  let pyExit = 0;
  try {
    await execFileAsync('python3', [join(REPO_ROOT, 'python', 'coherence_overlay_check.py'), '--parse-only', join(pyStubDir, 'cand.csv')], {
      env: { ...process.env, PYTHONPATH: pyStubDir },
    });
  } catch (err) {
    pyExit = err.code || 1;
    pyStderr = String(err.stderr || '');
  }
  assert.notEqual(pyExit, 0);
  for (const leaked of ['SENSITIVE', 'MEMBER', 'carrier_b~direct', '1EG4-TE5-MK72']) {
    assert.ok(!pyStderr.includes(leaked), `coherence_overlay_check.py stderr leaked ${leaked}`);
  }

  const router = createCoherenceRouter({
    handlersByCompany: new Map([['acme', { getApprovalKeyHistory: async () => ({ history: [] }) }]]),
    authenticate: async () => ({ id: 'test-owner', kind: 'owner' }),
  });
  const server = createServer((req, res) => { void router(req, res); });
  await new Promise((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
  try {
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const r1 = await fetch(`${baseUrl}/api/coherence/acme/approvals/history?recordId=policy:carrier_a:P10001`);
    assert.equal(r1.status, 400);
    const b1 = await r1.text();
    assert.ok(!b1.includes('P10001'), 'error response must never echo recordId from URL');

    const r1Pipe = await fetch(`${baseUrl}/api/coherence/acme/runs?q=${encodeURIComponent('carrier_a|direct|NM:doe,jane|100.00|2026-11')}`);
    assert.equal(r1Pipe.status, 400);
    const b1Pipe = await r1Pipe.text();
    assert.ok(!b1Pipe.includes('doe,jane'), 'error response must never echo pipe record_id from URL');

    const r2 = await fetch(`${baseUrl}/api/coherence/acme/approvals/history`);
    assert.equal(r2.status, 405, 'GET /approvals/history must be refused so recordIds stay in POST JSON body');

    const r3 = await fetch(`${baseUrl}/api/coherence/acme/runs/carrier_b~direct~SMITH%20JOHN~100.00~2026-11`);
    assert.equal(r3.status, 400);
    const b3 = await r3.text();
    assert.ok(!b3.includes('SMITH'), 'error response must never echo tilde recordId from URL');
  } finally {
    await new Promise((resolvePromise) => server.close(resolvePromise));
  }
});

test('Layer 2 [Negative Invariant]: View-As never writes, worker-only exclusivity, explicit company_admin grants, and zero path from customer roles to code', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  assert.throws(
    () => assertCanWrite(env.ownerActor, 'finish_attempt', { companySlug: env.companySlug, allowWorkerOverride: true }),
    (err) => err?.code === 'WORKER_ONLY' && err?.status === 403,
  );
  assert.throws(
    () => assertCanRead({ id: 'acme-admin', kind: 'company_admin', company: 'acme' }, 'runs', { companySlug: 'acme' }),
    (err) => err?.status === 403,
  );
  assert.throws(
    () => assertCanRead({ id: 'acme-admin', kind: 'company_admin', company: 'acme', grants: ['runs', 'checks'] }, 'checks', { companySlug: 'acme' }),
    (err) => err?.status === 403,
  );

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
  const launch = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'sec-launch', statementDate: '2026-11-21', engineVersionId,
  });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const bibleRows = [row0, sampleApprovalRow({ record_id: 'policy:carrier_a:P10001#effective:2026-01-01' })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'sec-b', expectedJournalSeq: seq, runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished');
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const adjRows = [...bibleRows, sampleApprovalRow({ record_id: 'carrier_a~direct~P10001~100.00~2026-11' })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'sec-a', expectedJournalSeq: seq, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
  const adjAcc = await worker.runOnce();
  assert.equal(adjAcc.action, 'review_accepted');
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ actor: env.ownerActor, commandKey: 'sec-e', expectedJournalSeq: seq, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: 'create statements for 2026-11-21' });
  assert.equal((await worker.runOnce()).action, 'step_finished');

  const viewAsOwner = { id: 'test-owner', kind: 'owner', viewingAs: { id: 'jane-agent', kind: 'recipient' } };
  await assert.rejects(() => env.commands.launchRun({ actor: viewAsOwner, commandKey: 'va-1', statementDate: '2026-11-22', engineVersionId }), /viewing as/i);
  await assert.rejects(() => env.commands.carrySent({ actor: viewAsOwner, commandKey: 'va-2', runId, typedPhrase: 'sent 2026-11-21' }), /viewing as/i);
  await assert.rejects(() => env.commands.carryApprovals({ actor: viewAsOwner, commandKey: 'va-3', runId, typedPhrase: 'carry 2026-11-21' }), /viewing as/i);
  await assert.rejects(() => env.commands.abandonRun({ actor: viewAsOwner, commandKey: 'va-4', runId, typedPhrase: 'abandon 2026-11-21', reason: 'nope' }), /viewing as/i);
  await assert.rejects(() => env.commands.saveReviewDraft({ actor: viewAsOwner, runId, surface: 'adjust', attemptNo: 1, born: 'b', checksum: 'c', rows: [] }), /viewing as/i);

  const handlers = createWebHandlers({ pool: env.pool, companySlug: env.companySlug, stores: env.stores, commands: env.commands });
  let currentActor = null;
  const router = createCoherenceRouter({
    handlersByCompany: new Map([[env.companySlug, handlers]]),
    authenticate: async () => currentActor,
  });
  const server = createServer((req, res) => { void router(req, res); });
  await new Promise((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
  t.after(() => new Promise((resolvePromise) => server.close(resolvePromise)));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  const customerActors = [
    { id: 'acme-admin', kind: 'company_admin', company: 'acme', grants: ['inputs', 'runs', 'outputs'] },
    { id: 'jane-agent', kind: 'recipient', company: 'acme' },
  ];

  for (const cust of customerActors) {
    currentActor = cust;
    for (const badPath of [
      'emits/bundles/entity-managers/Acme/viewer.html',
      'emits/bundles/selling-agents/Acme/jane-agent/viewer.html',
      'bible.html',
      'adjust.html',
      'company_emit.py',
    ]) {
      const outRes = await fetch(`${baseUrl}/api/coherence/acme/runs/${runId}/outputs/file?path=${encodeURIComponent(badPath)}`);
      assert.equal(outRes.status, 403, `${cust.kind} must receive 403 for outputs/file?path=${badPath}`);
    }

    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/bundles`)).status, 404);
    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/bundles/config?output=selling-agents/Acme/jane-agent`)).status, 404);
    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/bundles/file?output=selling-agents/Acme/jane-agent&path=viewer.html`)).status, 404);

    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/runs/${runId}/review/bible/config`)).status, 403);
    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/runs/${runId}/review/adjust/config`)).status, 403);
    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/review-drift`)).status, 403);
    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/runs/${runId}/journal`)).status, 403);
    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/checks`)).status, 403);
    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/approvals/history`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ recordId: 'x' }),
    })).status, 403);

    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/runs`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ commandKey: 'cust-launch', statementDate: '2026-11-22', engineVersionId }),
    })).status, 403);
  }

  currentActor = customerActors[0];
  const outList = await (await fetch(`${baseUrl}/api/coherence/acme/runs/${runId}/outputs`)).json();
  assert.ok(outList.files.length > 0);
  assert.ok(outList.files.every((f) => !/\.(html|js|mjs|py|sh|css)$/i.test(f.relPath)), 'company_admin output listing must never include code-bearing files');
});

test('Layer 2 [Workspace Code Isolation]: sealed wrapper verification rejects missing overlay checker and workspaces exclude bible.html and adjust.html', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());
  const dir = await mkdtemp(join(tmpdir(), 'coherence-ws-iso-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const fakeGit = join(dir, 'fake-git');
  await writeFile(fakeGit, [
    '#!/bin/sh',
    'if [ "$1" = "clone" ]; then',
    '  mkdir -p "$5/coherence"',
    '  printf "" > "$5/coherence/__init__.py"',
    '  exit 0',
    'fi',
    'exit 0',
  ].join('\n'), 'utf8');
  await chmod(fakeGit, 0o700);

  const promo = (relPath, text) => env.codeStore.promoteBytes(Buffer.from(text, 'utf8'), { relPath, checksPassed: true });
  const companyEmitPy = '# emit\n';
  const pagesLawPy = '# pages\n';
  const gitBundle = await promo('engine/coherence.bundle', '# v2 git bundle\n');
  const codeManifest = await promo('engine/code-manifest.json', JSON.stringify({ 'coherence/__init__.py': sha256Hex('') }));
  const pythonLock = await promo('engine/uv.lock', 'v=1\n');
  const pythonWheels = await promo('engine/wheels.tar', 'w');
  const webLock = await promo('engine/pnpm-lock.yaml', 'v=9\n');
  const webPackages = await promo('engine/web.tar', 'p');
  const wrapperBundle = await promo('engine/wrappers.json', JSON.stringify({
    'company_emit.py': companyEmitPy,
    'pages_law.py': pagesLawPy,
  }));

  const reg = await env.commands.registerEngineVersion({
    actor: env.ownerActor,
    commandKey: 'missing-overlay-eng',
    label: 'v-missing-overlay',
    coherenceCommit: '809c6ea',
    gitBundle, codeManifest, pythonLock, pythonWheels, webLock, webPackages, wrapperBundle,
    nusearCommit: 'abc1234',
    companyEmitSha256: sha256Hex(companyEmitPy),
    pagesLawSha256: sha256Hex(pagesLawPy),
    overlayCheckSha256: sha256Hex('expected-overlay'),
    toolchain: { os: 'Linux', os_version: '6', arch: 'x64', python: '3.12', uv: '0.5', node: '22', pnpm: '9', tz: 'America/New_York', lang: 'en_US.UTF-8', lc_all: 'en_US.UTF-8', pythonutf8: '1' },
  });
  const engRow = (await env.pool.query('SELECT * FROM coherence.engine_versions WHERE id = $1::uuid', [reg.result.engineVersionId])).rows[0];
  await assert.rejects(
    () => defaultMaterializeEngine({ engineVersion: engRow, workspaceDir: join(dir, 'ws'), codeStore: env.codeStore, gitBin: fakeGit }),
    (err) => err?.code === 'WRAPPER_MISSING',
  );

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));
  const launch = await env.commands.launchRun({ actor: env.ownerActor, commandKey: 'ws-iso-launch', statementDate: '2026-11-21', engineVersionId });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  const seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.submitReview({
    actor: env.ownerActor, commandKey: 'ws-iso-bible', expectedJournalSeq: seq, runId, surface: 'bible',
    csvBytes: Buffer.from(makeOverlayCsv([row0, sampleApprovalRow({ note: 'b' })]), 'utf8'),
  });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished');

  const runRow = (await env.pool.query(
    `SELECT id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date, origin, input_version_id,
            prior_approvals_sha256, engine_version_id, replays_run_id
     FROM coherence.runs WHERE id = $1::uuid`,
    [runId],
  )).rows[0];

  const wsAdjust = await buildAttemptWorkspace({
    db: env.pool, run: runRow, step: 'adjust', stores: env.stores, tempBaseDir: env.tempDir, materializeEngine: createMockEngineMaterializer(),
  });
  try {
    assert.equal(await stat(join(wsAdjust.runDir, 'bible.html')).then(() => true, () => false), false);
    assert.equal(await stat(join(wsAdjust.runDir, 'bible.csv')).then(() => true, () => false), true);
    assert.equal(await stat(join(wsAdjust.runDir, 'working', 'tx.csv')).then(() => true, () => false), true);
  } finally {
    await wsAdjust.cleanup();
  }

  const wsEmit = await buildAttemptWorkspace({
    db: env.pool, run: runRow, step: 'emit', stores: env.stores, tempBaseDir: env.tempDir, materializeEngine: createMockEngineMaterializer(),
  });
  try {
    assert.equal(await stat(join(wsEmit.runDir, 'bible.html')).then(() => true, () => false), false);
    assert.equal(await stat(join(wsEmit.runDir, 'adjust.html')).then(() => true, () => false), false);
    assert.equal(await stat(join(wsEmit.runDir, 'adjust.csv')).then(() => true, () => false), true);
  } finally {
    await wsEmit.cleanup();
  }
});

test('Layer 2 [Config Assertions]: roles/grants, ENABLE ALWAYS triggers, fixed search_path, trojan search_path, active pg_hba.conf via SHOW hba_file, and Cloud SQL policy', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const dbCfg = await verifyDatabaseConfigInvariants(env.pool);
  assert.equal(dbCfg.passed, true, `Database config audit failed:\n${dbCfg.problems.join('\n')}`);
  assert.equal(dbCfg.checkedBusinessTables, 31);
  assert.ok(dbCfg.checkedFunctions >= 40);

  const client = env.registerClient(await createClient(env.pgConfig));
  await client.query(`
    CREATE SCHEMA trojan;
    CREATE FUNCTION trojan.sha256(bytea) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$ SELECT '\\xdeadbeef'::bytea; $$;
    CREATE FUNCTION trojan.lower(text) RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT 'hijacked'; $$;
  `);
  await client.query('SET search_path = trojan, public');
  const hashRes = await client.query("SELECT coherence.sha256_text('hello') AS h");
  assert.equal(hashRes.rows[0].h, sha256Hex('hello'));
  await client.query('RESET search_path');

  await client.query('SET ROLE coherence_app');
  for (const [tbl, lockMode] of [
    ['journal_entries', 'EXCLUSIVE'],
    ['runs', 'SHARE'],
    ['input_entries', 'ACCESS EXCLUSIVE'],
  ]) {
    await assert.rejects(async () => {
      await client.query('BEGIN');
      try {
        await client.query(`LOCK TABLE coherence.${tbl} IN ${lockMode} MODE`);
      } finally {
        await client.query('ROLLBACK').catch(() => {});
      }
    }, /permission denied/i);
  }
  await client.query('RESET ROLE');

  const hba = await verifyPgHbaFile({ pool: env.pool });
  assert.equal(hba.passed, true, `pg_hba.conf check failed: ${hba.problems.join('; ')}`);
  assert.ok(hba.ruleCount >= 2);
  assert.ok(hba.rules.every((r) => r.method !== 'trust'));

  const prevHbaEnv = process.env.COHERENCE_PG_HBA_PATH;
  try {
    delete process.env.COHERENCE_PG_HBA_PATH;
    await assert.rejects(() => verifyPgHbaFile(), /pool|filePath|COHERENCE_PG_HBA_PATH/i);
  } finally {
    if (prevHbaEnv !== undefined) process.env.COHERENCE_PG_HBA_PATH = prevHbaEnv;
  }

  const tmpHba = join(env.tempDir, 'bad_pg_hba.conf');
  await writeFile(tmpHba, 'local all all trust\nhost all all 127.0.0.1/32 scram-sha-256\n', 'utf8');
  const badHba = await verifyPgHbaFile(tmpHba);
  assert.equal(badHba.passed, false);
  assert.ok(badHba.problems.some((p) => /trust/i.test(p)));

  const csql = await verifyCloudSqlConfigFile();
  assert.equal(csql.passed, true, `Cloud SQL policy check failed: ${csql.problems.join('; ')}`);
  assert.equal(csql.config.ipConfiguration.requireSsl, true);
  assert.deepEqual(csql.config.ipConfiguration.authorizedNetworks, []);
  assert.equal(csql.config.databaseFlags['pgaudit.log_parameter'], 'off');
  assert.equal(csql.config.databaseFlags['log_parameter_max_length'], '0');

  const badCsql = validateCloudSqlConfig({
    ...csql.config,
    ipConfiguration: { ...csql.config.ipConfiguration, requireSsl: false, authorizedNetworks: [{ value: '0.0.0.0/0' }] },
    databaseFlags: { ...csql.config.databaseFlags, 'pgaudit.log_parameter': 'on' },
  });
  assert.equal(badCsql.passed, false);
  assert.ok(badCsql.problems.some((p) => /requireSsl/i.test(p)));
  assert.ok(badCsql.problems.some((p) => /authorizedNetworks/i.test(p)));
  assert.ok(badCsql.problems.some((p) => /pgaudit\.log_parameter/i.test(p)));
});

test('Layer 2 [Cross-Entity & Zero-Dollar Isolation]: FORCE RLS, physical upline/financial walls, security_barrier side-channel defense across all 5 scoped roles, and View-As refusal on review saves', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineCopyVersion(env);
  await seedStandingInput(env, { commandKey: 'rls-standing' });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createDataOnlyMockEngineMaterializer({ adjustReconfirmRecordId: null }),
    tempBaseDir: env.tempDir,
  }));

  // Complete Run 1 (2026-10-31) with Acme, Beacon (NPN 11111111 + 22222222 both named "Sam Seller"), and Harbor, then record as sent
  const l1 = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'rls-launch-1', statementDate: '2026-10-31', engineVersionId,
  });
  const run1Id = l1.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].latest_journal_seq);

  // View-As MUST refuse saveReviewDecisions, carryDecisions, recordDecisionBaseline, recordStatementBatch, and materializeEmit
  const viewAsOwner = { id: 'test-owner', kind: 'owner', viewingAs: { id: 'beacon-mgr', kind: 'recipient' } };
  await assert.rejects(
    () => env.commands.saveReviewDecisions({
      actor: viewAsOwner, commandKey: 'va-save', expectedJournalSeq: seq, runId: run1Id, surface: 'bible',
      decisions: [{ recordId: 'policy:carrier_a:C-101#effective:2026-10-01', disposition: 'CONFIRM' }],
    }),
    (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY',
  );
  await assert.rejects(
    () => env.commands.carryDecisions({ actor: viewAsOwner, commandKey: 'va-carry-dec', runId: run1Id, typedPhrase: 'carry 2026-10-31' }),
    (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY',
  );
  await assert.rejects(
    () => env.commands.recordDecisionBaseline({ actor: viewAsOwner, commandKey: 'va-base', decisions: [] }),
    (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY',
  );
  await assert.rejects(
    () => env.commands.materializeEmit({ actor: viewAsOwner, commandKey: 'va-mat', runId: run1Id }),
    (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY',
  );

  await env.commands.saveReviewDecisions({
    actor: env.ownerActor, commandKey: 'rls-bible-1', expectedJournalSeq: seq, runId: run1Id, surface: 'bible',
    decisions: [
      { recordId: 'policy:carrier_a:C-101#effective:2026-10-01', disposition: 'CONFIRM' },
      { recordId: 'policy:carrier_b:C-201#effective:2026-10-01', disposition: 'CONFIRM' },
    ],
  });
  assert.equal((await worker.runOnce()).action, 'step_finished');
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].latest_journal_seq);
  const adj1 = await env.commands.saveReviewDecisions({
    actor: env.ownerActor, commandKey: 'rls-adj-1', expectedJournalSeq: seq, runId: run1Id, surface: 'adjust',
    decisions: [
      { recordId: 'carrier_a~direct~PAT SAMPLE~100.00~2026-10', disposition: 'CONFIRM' },
      { recordId: 'carrier_b~direct~CASEY MOCK~250.00~2026-10', disposition: 'CONFIRM' },
    ],
  });
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({
    actor: env.ownerActor, commandKey: 'rls-emit-1', expectedJournalSeq: seq, runId: run1Id,
    adjustReviewSaveId: adj1.result.reviewSaveId, typedPhrase: 'create statements for 2026-10-31',
  });
  assert.equal((await worker.runOnce()).action, 'step_finished');

  // Before carrySent, agency_manager must see ZERO statement lines (unsent run stays outside official statements)
  const runScoped = async (role, settings, fn) => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN TRANSACTION READ ONLY');
      await c.query(`SET LOCAL ROLE ${role}`);
      for (const [k, v] of Object.entries(settings)) {
        await c.query('SELECT pg_catalog.set_config($1, $2, true)', [k, v]);
      }
      const res = await fn(c);
      await c.query('COMMIT');
      return res;
    } catch (err) {
      await c.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      c.release();
    }
  };

  const unsentCount = await runScoped('coherence_agency_manager_ro', { 'app.allowed_entities': 'Beacon' }, async (c) => (
    (await c.query('SELECT COUNT(*)::int AS n FROM coherence_views.agency_statement_lines')).rows[0].n
  ));
  assert.equal(unsentCount, 0, 'unsent run emission must stay hidden from downline agencies until carrySent');

  // Record Run 1 as sent
  await env.commands.carrySent({ actor: env.ownerActor, commandKey: 'rls-sent-1', runId: run1Id, typedPhrase: 'sent 2026-10-31' });

  // 1. coherence_agency_manager_ro: sees ONLY Beacon, 0 rows when unset, 42501 on upline/ledger/upline_amount/journal, safe under division-by-zero side-channel
  await runScoped('coherence_agency_manager_ro', { 'app.allowed_entities': 'Beacon' }, async (c) => {
    const bob = (await c.query('SELECT entity, policy_id, amount FROM coherence_views.agency_bob ORDER BY policy_id')).rows;
    assert.equal(bob.length, 2);
    assert.ok(bob.every((r) => r.entity === 'Beacon'));
    const lines = (await c.query('SELECT entity, amount FROM coherence_views.agency_statement_lines')).rows;
    assert.equal(lines.length, 2);
    assert.ok(lines.every((r) => r.entity === 'Beacon'));
    const totals = (await c.query('SELECT entity, net_amount FROM coherence_views.agency_statement_totals')).rows;
    assert.equal(totals.length, 1);
    assert.equal(totals[0].net_amount, '200.00');

    // Side-channel security_barrier check: Harbor rows must never reach user WHERE expression
    const sideChannel = (await c.query(
      "SELECT COUNT(*)::int AS n FROM coherence_views.agency_statement_lines WHERE 1 / CASE WHEN entity = 'Harbor' THEN 0 ELSE 1 END = 1",
    )).rows[0].n;
    assert.equal(sideChannel, 2);
  });

  // Fail-closed when app.allowed_entities is unset
  const agUnset = await runScoped('coherence_agency_manager_ro', {}, async (c) => (
    (await c.query('SELECT COUNT(*)::int AS n FROM coherence_views.agency_statement_lines')).rows[0].n
  ));
  assert.equal(agUnset, 0, 'agency manager must see 0 rows when app.allowed_entities is unset');

  for (const forbiddenSql of [
    'SELECT * FROM coherence.statement_upline_lines',
    'SELECT * FROM coherence.coherent_ledger_rows',
    'SELECT upline_amount FROM coherence.bob_policy_financials',
    'SELECT * FROM coherence.decisions',
    'SELECT * FROM coherence.journal_entries',
  ]) {
    await assert.rejects(
      () => runScoped('coherence_agency_manager_ro', { 'app.allowed_entities': 'Beacon' }, (c) => c.query(forbiddenSql)),
      (err) => err?.code === '42501',
      `coherence_agency_manager_ro must get 42501 on: ${forbiddenSql}`,
    );
  }

  // 2. coherence_agent_ro: strictly scoped by NPN (distinguishes same-name agents 11111111 vs 22222222) and zero dollars
  await runScoped('coherence_agent_ro', { 'app.allowed_entities': 'Beacon', 'app.actor_npn': '11111111' }, async (c) => {
    const bob = (await c.query('SELECT policy_id, writing_npn, writing_agent FROM coherence_views.agent_bob')).rows;
    assert.equal(bob.length, 1);
    assert.equal(bob[0].writing_npn, '11111111');
    const act = (await c.query('SELECT entity, writing_npn FROM coherence_views.agent_statement_activity')).rows;
    assert.equal(act.length, 1);
    assert.equal(act[0].writing_npn, '11111111');
  });
  const agtUnset = await runScoped('coherence_agent_ro', { 'app.allowed_entities': 'Beacon' }, async (c) => (
    (await c.query('SELECT COUNT(*)::int AS n FROM coherence_views.agent_bob')).rows[0].n
  ));
  assert.equal(agtUnset, 0, 'agent must see 0 rows when app.actor_npn is unset');

  for (const forbiddenSql of [
    'SELECT * FROM coherence.bob_policy_financials',
    'SELECT amount FROM coherence.statement_agency_lines',
    'SELECT gross_comm FROM coherence.statement_agency_lines',
    'SELECT * FROM coherence.statement_upline_lines',
    'SELECT * FROM coherence.coherent_ledger_rows',
  ]) {
    await assert.rejects(
      () => runScoped('coherence_agent_ro', { 'app.allowed_entities': 'Beacon', 'app.actor_npn': '11111111' }, (c) => c.query(forbiddenSql)),
      (err) => err?.code === '42501',
      `coherence_agent_ro must get 42501 on: ${forbiddenSql}`,
    );
  }

  // 3. coherence_retention_ro: scoped to Harbor, zero dollar access
  await runScoped('coherence_retention_ro', { 'app.allowed_entities': 'Harbor' }, async (c) => {
    const bob = (await c.query('SELECT entity FROM coherence_views.retention_bob')).rows;
    assert.equal(bob.length, 1);
    assert.equal(bob[0].entity, 'Harbor');
  });
  await assert.rejects(
    () => runScoped('coherence_retention_ro', { 'app.allowed_entities': 'Harbor' }, (c) => c.query('SELECT amount FROM coherence.statement_agency_lines')),
    (err) => err?.code === '42501',
  );

  // 4. coherence_entity_manager_ro: full BoB, ledger, all entities + Acme Upline, reconciliation view, zero journal/decision access
  await runScoped('coherence_entity_manager_ro', { 'app.access_tier': 'entity_manager' }, async (c) => {
    const bob = (await c.query('SELECT COUNT(*)::int AS n FROM coherence_views.v_canonical_bob')).rows[0].n;
    assert.equal(bob, 3);
    const recon = (await c.query('SELECT * FROM coherence_views.v_entity_statement_reconciliation($1::uuid)', [run1Id])).rows;
    assert.equal(recon.length, 4);
    assert.ok(recon.every((r) => r.reconciled && r.variance === '0.00'));
  });
  const emUnset = await runScoped('coherence_entity_manager_ro', {}, async (c) => (
    (await c.query('SELECT COUNT(*)::int AS n FROM coherence_views.v_canonical_bob')).rows[0].n
  ));
  assert.equal(emUnset, 0, 'entity manager must see 0 rows when app.access_tier is unset');
  await assert.rejects(
    () => runScoped('coherence_entity_manager_ro', { 'app.access_tier': 'entity_manager' }, (c) => c.query('SELECT * FROM coherence.journal_entries')),
    (err) => err?.code === '42501',
  );

  // 5. coherence_investor_ro: BoB only, zero ledger or statement access
  await runScoped('coherence_investor_ro', { 'app.access_tier': 'investor' }, async (c) => {
    const bob = (await c.query('SELECT COUNT(*)::int AS n FROM coherence_views.investor_bob')).rows[0].n;
    assert.equal(bob, 3);
  });
  for (const forbiddenSql of [
    'SELECT * FROM coherence.coherent_ledger_rows',
    'SELECT * FROM coherence.statement_agency_lines',
    'SELECT * FROM coherence.statement_upline_lines',
  ]) {
    await assert.rejects(
      () => runScoped('coherence_investor_ro', { 'app.access_tier': 'investor' }, (c) => c.query(forbiddenSql)),
      (err) => err?.code === '42501',
      `coherence_investor_ro must get 42501 on: ${forbiddenSql}`,
    );
  }
});
