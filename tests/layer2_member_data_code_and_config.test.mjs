// Layer 2: protects member PHI confidentiality, Nusear source-code isolation,
// and database and infrastructure security policies.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { chmod, mkdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { createAppCommands } from '../src/commands/app-cmd.mjs';
import {
  PLATFORM_ROLES,
  validateCloudSqlConfig,
  verifyCloudSqlConfigFile,
  verifyDatabaseConfigInvariants,
  verifyIamConfigInvariants,
  verifyPgHbaFile,
} from '../src/config/policy-checks.mjs';
import { createClient, withRequestTx } from '../src/db/pg-client.mjs';
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
import { createRoleScopedTestPool, seedCoherenceIamFixture } from './helpers/iam-harness.mjs';
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
  await env.commands.registerStoredFiles({ dbToken: env.ownerToken, commandKey: 'reg-art-test', files: [fakeDataFile] });
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
          dbToken: env.ownerToken,
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

test('Layer 2 [Negative Invariant]: View-As never writes, worker-only exclusivity, explicit company_admin grants, and zero path from customer roles to code (enforced strictly in PostgreSQL as platform_app)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const iam = env.iam;
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const workerPool = createRoleScopedTestPool(env.pool, 'platform_worker');
  const readonlyPool = createRoleScopedTestPool(env.pool, 'platform_readonly');
  const appCommands = createAppCommands({ pool: appPool, stores: env.stores });

  // Worker-only exclusivity enforced in PostgreSQL: platform_app lacks EXECUTE (42501), and even
  // platform_worker carrying a human Owner signed token is refused with 42501 WORKER_ONLY.
  await assert.rejects(
    () => withRequestTx(appPool, iam.tokens.owner, (tx) => (
      tx.query(`SELECT app_cmd.coherence_finish_attempt($1, $2, '{}'::jsonb)`, ['bad-fin-app', sha256Hex('bad-fin-app')])
    ), { readOnly: false, serializable: true }),
    (err) => err?.code === '42501',
  );
  await assert.rejects(
    () => withRequestTx(workerPool, iam.tokens.owner, (tx) => (
      tx.query(`SELECT app_cmd.coherence_finish_attempt($1, $2, '{}'::jsonb)`, ['bad-fin-human', sha256Hex('bad-fin-human')])
    ), { readOnly: false, serializable: true }),
    (err) => err?.code === '42501' && /WORKER_ONLY|FORBIDDEN/i.test(err.message),
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
    workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(),
    tempBaseDir: env.tempDir,
  }));
  const launch = await env.commands.launchRun({
    dbToken: env.ownerToken, commandKey: 'sec-launch', statementDate: '2026-11-21', engineVersionId,
  });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const bibleRows = [row0, sampleApprovalRow({ record_id: 'policy:carrier_a:P10001#effective:2026-01-01' })];
  await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: 'sec-b', expectedJournalSeq: seq, runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished');
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const adjRows = [...bibleRows, sampleApprovalRow({ record_id: 'carrier_a~direct~P10001~100.00~2026-11' })];
  await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: 'sec-a', expectedJournalSeq: seq, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
  const adjAcc = await worker.runOnce();
  assert.equal(adjAcc.action, 'review_accepted');
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ dbToken: env.ownerToken, commandKey: 'sec-e', expectedJournalSeq: seq, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: 'create statements for 2026-11-21' });
  assert.equal((await worker.runOnce()).action, 'step_finished');

  // View-As refusal enforced strictly by PostgreSQL (withRequestTx READ ONLY + iam.assert_can_write 42501 VIEW_AS_READ_ONLY).
  const vaTok = iam.tokens.viewAsAgentA;
  await assert.rejects(() => appCommands.launchRun({ dbToken: vaTok, commandKey: 'va-1', statementDate: '2026-11-22', engineVersionId }), (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY');
  await assert.rejects(() => appCommands.carrySent({ dbToken: vaTok, commandKey: 'va-2', runId, typedPhrase: 'sent 2026-11-21' }), (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY');
  await assert.rejects(() => appCommands.carryApprovals({ dbToken: vaTok, commandKey: 'va-3', runId, typedPhrase: 'carry 2026-11-21' }), (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY');
  await assert.rejects(() => appCommands.abandonRun({ dbToken: vaTok, commandKey: 'va-4', runId, typedPhrase: 'abandon 2026-11-21', reason: 'nope' }), (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY');
  await assert.rejects(() => appCommands.saveReviewDraft({ dbToken: vaTok, runId, surface: 'adjust', attemptNo: 1, born: 'b', checksum: 'c', rows: [] }), (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY');

  const handlers = createWebHandlers({ pool: appPool, readonlyPool, companySlug: env.companySlug, stores: env.stores });
  let currentToken = '';
  const router = createCoherenceRouter({
    handlersByCompany: new Map([[env.companySlug, handlers]]),
    authenticate: async () => currentToken,
  });
  const server = createServer((req, res) => { void router(req, res); });
  await new Promise((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
  t.after(() => new Promise((resolvePromise) => server.close(resolvePromise)));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  // Explicit company_admin per-area grants enforced strictly in PostgreSQL:
  // Workshop holders (including companyAdminRunsOnly) see unfinished/unsent runs; finished-goods
  // readers (agencyMgr) get 0 runs, 0 input versions, and 0 output files.
  currentToken = iam.tokens.agencyMgr;
  assert.deepEqual((await (await fetch(`${baseUrl}/api/coherence/acme/runs`)).json()).runs, []);
  assert.deepEqual((await (await fetch(`${baseUrl}/api/coherence/acme/inputs/versions`)).json()).versions, []);
  assert.deepEqual((await (await fetch(`${baseUrl}/api/coherence/acme/runs/${runId}/outputs`)).json()).files, []);

  currentToken = iam.tokens.companyAdminRunsOnly;
  assert.equal((await (await fetch(`${baseUrl}/api/coherence/acme/runs`)).json()).runs.length, 1);
  await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'sec-carry-sent', runId, typedPhrase: 'sent 2026-11-21' });

  // companyAdminNoGrants sees 0 runs, 0 input versions, and 0 output files.
  currentToken = iam.tokens.companyAdminNoGrants;
  assert.deepEqual((await (await fetch(`${baseUrl}/api/coherence/acme/runs`)).json()).runs, []);
  assert.deepEqual((await (await fetch(`${baseUrl}/api/coherence/acme/inputs/versions`)).json()).versions, []);
  assert.deepEqual((await (await fetch(`${baseUrl}/api/coherence/acme/runs/${runId}/outputs`)).json()).files, []);

  // companyAdminRunsOnly sees runs, but 0 input versions and 0 output files.
  currentToken = iam.tokens.companyAdminRunsOnly;
  assert.equal((await (await fetch(`${baseUrl}/api/coherence/acme/runs`)).json()).runs.length, 1);
  assert.deepEqual((await (await fetch(`${baseUrl}/api/coherence/acme/inputs/versions`)).json()).versions, []);
  assert.deepEqual((await (await fetch(`${baseUrl}/api/coherence/acme/runs/${runId}/outputs`)).json()).files, []);

  const customerTokens = [
    ['company_admin', iam.tokens.companyAdmin],
    ['company_admin_runs_only', iam.tokens.companyAdminRunsOnly],
    ['selling_agent', iam.tokens.agentA],
  ];

  for (const [label, tok] of customerTokens) {
    currentToken = tok;
    for (const badPath of [
      'emits/bundles/entity-managers/Acme/viewer.html',
      'emits/bundles/selling-agents/Acme/jane-agent/viewer.html',
      'bible.html',
      'adjust.html',
      'company_emit.py',
    ]) {
      const outRes = await fetch(`${baseUrl}/api/coherence/acme/runs/${runId}/outputs/file?path=${encodeURIComponent(badPath)}`);
      assert.equal(outRes.status, 403, `${label} must receive 403 for outputs/file?path=${badPath}`);
    }

    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/bundles`)).status, 404);
    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/bundles/config?output=selling-agents/Acme/jane-agent`)).status, 404);
    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/bundles/file?output=selling-agents/Acme/jane-agent&path=viewer.html`)).status, 404);

    if (label !== 'company_admin') {
      assert.equal((await fetch(`${baseUrl}/api/coherence/acme/runs/${runId}/review/bible/config`)).status, 404, `${label} must receive 0 rows (404) on review/bible/config`);
      assert.equal((await fetch(`${baseUrl}/api/coherence/acme/runs/${runId}/review/adjust/config`)).status, 404, `${label} must receive 0 rows (404) on review/adjust/config`);
      assert.equal((await fetch(`${baseUrl}/api/coherence/acme/review-drift`)).status, 403, `${label} must be refused on review-drift`);
      assert.deepEqual((await (await fetch(`${baseUrl}/api/coherence/acme/runs/${runId}/journal`)).json()).entries, [], `${label} must see 0 journal entries`);
      assert.deepEqual((await (await fetch(`${baseUrl}/api/coherence/acme/checks`)).json()).checks, [], `${label} must see 0 checks`);
      assert.deepEqual((await (await fetch(`${baseUrl}/api/coherence/acme/approvals/history`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ recordId: 'policy:carrier_a:P10001#effective:2026-01-01' }),
      })).json()).history, [], `${label} must see 0 approval history rows`);
    }

    assert.equal((await fetch(`${baseUrl}/api/coherence/acme/runs`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ commandKey: `cust-launch-${label}`, statementDate: '2026-11-22', engineVersionId }),
    })).status, 403, `${label} must get 403 on POST /runs`);
  }

  currentToken = iam.tokens.companyAdmin;
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
    dbToken: env.ownerToken,
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
    stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));
  const launch = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'ws-iso-launch', statementDate: '2026-11-21', engineVersionId });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  const seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.submitReview({
    dbToken: env.ownerToken, commandKey: 'ws-iso-bible', expectedJournalSeq: seq, runId, surface: 'bible',
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
  assert.equal(dbCfg.checkedAppViews, 39);
  assert.equal(dbCfg.checkedAppCmdFunctions, 33);
  assert.ok(dbCfg.checkedFunctions >= 40);

  const iamCfg = await verifyIamConfigInvariants(env.pool);
  assert.equal(iamCfg.passed, true, `IAM config audit failed:\n${iamCfg.problems.join('\n')}`);
  assert.equal(iamCfg.checkedBusinessTables, dbCfg.checkedBusinessTables);

  // Retired schema coherence_views must not exist.
  const viewsSchema = await env.pool.query(
    "SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname = 'coherence_views'",
  );
  assert.equal(viewsSchema.rows.length, 0, 'retired schema coherence_views must not exist');

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

  // Active platform_* roles cannot escalate table locks on business tables.
  for (const roleName of ['platform_app', 'platform_writer', 'platform_worker']) {
    await client.query(`SET ROLE ${roleName}`);
    try {
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
        }, /permission denied/i, `${roleName} must not acquire ${lockMode} lock on coherence.${tbl}`);
      }
    } finally {
      await client.query('RESET ROLE');
    }
  }

  // Any pre-IAM retired roles still present cluster-wide must hold zero privileges on coherence.*.
  const existingRetired = (await client.query(
    `SELECT rolname FROM pg_catalog.pg_roles
     WHERE rolname = ANY($1::text[])
     ORDER BY rolname`,
    [[
      'coherence_app', 'coherence_worker', 'coherence_readonly',
      'coherence_entity_manager_ro', 'coherence_agency_manager_ro',
      'coherence_agent_ro', 'coherence_retention_ro', 'coherence_investor_ro',
    ]],
  )).rows.map((r) => r.rolname);
  for (const retiredRole of existingRetired) {
    await client.query(`SET ROLE ${retiredRole}`);
    try {
      for (const sql of ['SELECT * FROM coherence.runs LIMIT 1', 'SELECT * FROM coherence.bob_policies LIMIT 1']) {
        await assert.rejects(
          () => client.query(sql),
          (err) => err?.code === '42501',
          `retired role ${retiredRole} must get 42501 on: ${sql}`,
        );
      }
    } finally {
      await client.query('RESET ROLE');
    }
  }

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
  for (const roleName of PLATFORM_ROLES) {
    assert.ok(csql.config.roles[roleName], `cloudsql-instance.json must declare ${roleName}`);
  }
  assert.deepEqual(csql.config.roles.platform_app.businessTables, []);
  assert.deepEqual(csql.config.roles.platform_worker.businessTables, ['SELECT']);
  assert.deepEqual(csql.config.roles.platform_writer.businessTables, ['SELECT', 'INSERT']);
  assert.deepEqual(csql.config.roles.platform_readonly.businessTables, ['SELECT']);
  assert.deepEqual(csql.config.roles.platform_iam_sync.agentAffiliations, ['SELECT']);
  assert.deepEqual(csql.config.roles.platform_iam_sync.roleGrantPeople, ['SELECT']);
  assert.deepEqual(csql.config.roles.platform_iam_sync.personAuthIdentities, []);
  assert.deepEqual(csql.config.roles.platform_iam_sync.signingKeyScopes, ['nusear_staff', 'service']);
  for (const retired of ['coherence_app', 'coherence_worker', 'coherence_readonly']) {
    assert.equal(csql.config.roles[retired], undefined, `cloudsql-instance.json must retire ${retired}`);
  }

  const badCsql = validateCloudSqlConfig({
    ...csql.config,
    ipConfiguration: { ...csql.config.ipConfiguration, requireSsl: false, authorizedNetworks: [{ value: '0.0.0.0/0' }] },
    databaseFlags: { ...csql.config.databaseFlags, 'pgaudit.log_parameter': 'on' },
    roles: {
      ...csql.config.roles,
      coherence_app: { businessTables: ['SELECT', 'INSERT'] },
      platform_app: { businessTables: ['SELECT'], appViews: ['SELECT'], appCmd: ['EXECUTE'] },
      platform_worker: { businessTables: ['SELECT', 'INSERT'], appCmd: ['EXECUTE'] },
      platform_iam_sync: {
        ...csql.config.roles.platform_iam_sync,
        personAuthIdentities: ['SELECT'],
        signingKeyScopes: ['company_local', 'nusear_staff', 'service'],
      },
    },
  });
  assert.equal(badCsql.passed, false);
  assert.ok(badCsql.problems.some((p) => /requireSsl/i.test(p)));
  assert.ok(badCsql.problems.some((p) => /authorizedNetworks/i.test(p)));
  assert.ok(badCsql.problems.some((p) => /pgaudit\.log_parameter/i.test(p)));
  assert.ok(badCsql.problems.some((p) => /coherence_app/i.test(p)));
  assert.ok(badCsql.problems.some((p) => /platform_app/i.test(p)));
  assert.ok(badCsql.problems.some((p) => /platform_worker/i.test(p)));
  assert.ok(badCsql.problems.some((p) => /platform_iam_sync.*personAuthIdentities/i.test(p)));
  assert.ok(badCsql.problems.some((p) => /platform_iam_sync.*signingKeyScopes/i.test(p)));
});

test('Layer 2 [Cross-Entity & Zero-Dollar Isolation]: FORCE RLS, physical upline/financial walls, security_barrier side-channel defense across all 5 scoped roles, and View-As refusal on review saves', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineCopyVersion(env);
  await seedStandingInput(env, { commandKey: 'rls-standing' });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createDataOnlyMockEngineMaterializer({ adjustReconfirmRecordId: null }),
    tempBaseDir: env.tempDir,
  }));

  // Complete Run 1 (2026-10-31) with Acme, Beacon (NPN 11111111 + 22222222 both named "Sam Seller"), and Harbor, then record as sent
  const l1 = await env.commands.launchRun({
    dbToken: env.ownerToken, commandKey: 'rls-launch-1', statementDate: '2026-10-31', engineVersionId,
  });
  const run1Id = l1.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].latest_journal_seq);

  const iam = env.iam;
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const appCommands = createAppCommands({ pool: appPool, stores: env.stores });

  // View-As MUST refuse saveReviewDecisions, carryDecisions, recordDecisionBaseline, and materializeEmit strictly in PostgreSQL
  const viewAsTok = iam.tokens.viewAsAgencyMgr;
  await assert.rejects(
    () => appCommands.saveReviewDecisions({
      dbToken: viewAsTok, commandKey: 'va-save', expectedJournalSeq: seq, runId: run1Id, surface: 'bible',
      decisions: [{ recordId: 'policy:carrier_a:C-101#effective:2026-10-01', disposition: 'CONFIRM' }],
    }),
    (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY',
  );
  await assert.rejects(
    () => appCommands.carryDecisions({ dbToken: viewAsTok, commandKey: 'va-carry-dec', runId: run1Id, typedPhrase: 'carry 2026-10-31' }),
    (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY',
  );
  await assert.rejects(
    () => appCommands.recordDecisionBaseline({ dbToken: viewAsTok, commandKey: 'va-base', decisions: [] }),
    (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY',
  );
  await assert.rejects(
    () => appCommands.materializeEmit({ dbToken: viewAsTok, commandKey: 'va-mat', runId: run1Id }),
    (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY',
  );

  await env.commands.saveReviewDecisions({
    dbToken: env.ownerToken, commandKey: 'rls-bible-1', expectedJournalSeq: seq, runId: run1Id, surface: 'bible',
    decisions: [
      { recordId: 'policy:carrier_a:C-101#effective:2026-10-01', disposition: 'CONFIRM' },
      { recordId: 'policy:carrier_b:C-201#effective:2026-10-01', disposition: 'CONFIRM' },
    ],
  });
  assert.equal((await worker.runOnce()).action, 'step_finished');
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].latest_journal_seq);
  const adj1 = await env.commands.saveReviewDecisions({
    dbToken: env.ownerToken, commandKey: 'rls-adj-1', expectedJournalSeq: seq, runId: run1Id, surface: 'adjust',
    decisions: [
      { recordId: 'carrier_a~direct~PAT SAMPLE~100.00~2026-10', disposition: 'CONFIRM' },
      { recordId: 'carrier_b~direct~CASEY MOCK~250.00~2026-10', disposition: 'CONFIRM' },
    ],
  });
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({
    dbToken: env.ownerToken, commandKey: 'rls-emit-1', expectedJournalSeq: seq, runId: run1Id,
    adjustReviewSaveId: adj1.result.reviewSaveId, typedPhrase: 'create statements for 2026-10-31',
  });
  assert.equal((await worker.runOnce()).action, 'step_finished');

  await env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys()');

  const runAsApp = (token, fn) => withRequestTx(appPool, token, fn, { readOnly: true });

  // Before carrySent, agency_manager must see ZERO statement lines (unsent run stays outside official statements)
  const unsentCount = await runAsApp(iam.tokens.agencyMgr, async (c) => (
    (await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n
  ));
  assert.equal(unsentCount, 0, 'unsent run emission must stay hidden from downline agencies until carrySent');

  // Record Run 1 as sent
  await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'rls-sent-1', runId: run1Id, typedPhrase: 'sent 2026-10-31' });

  // 1. Agency Manager (Beacon): sees ONLY Beacon + agency amount, 0 Harbor, 0 upline, 0 ledger, NULL gross_comm/upline_amount, safe under division-by-zero side-channel
  await runAsApp(iam.tokens.agencyMgr, async (c) => {
    const bob = (await c.query('SELECT entity, policy_id, amount, upline_amount FROM app_views.coherence_bob ORDER BY policy_id')).rows;
    assert.equal(bob.length, 2);
    assert.ok(bob.every((r) => r.entity === 'Beacon' && r.upline_amount === null));
    const lines = (await c.query('SELECT entity, amount, gross_comm FROM app_views.coherence_statement_agency_lines')).rows;
    assert.equal(lines.length, 2);
    assert.ok(lines.every((r) => r.entity === 'Beacon' && r.gross_comm === null));
    const totals = (await c.query('SELECT statement_entity, net_amount FROM app_views.coherence_statement_totals')).rows;
    assert.equal(totals.length, 1);
    assert.equal(totals[0].net_amount, '200.00');
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_upline_lines')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_journal')).rows[0].n, 0);

    // Side-channel security_barrier check: Harbor rows must never reach user WHERE expression
    const sideChannel = (await c.query(
      "SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines WHERE 1 / CASE WHEN entity = 'Harbor' THEN 0 ELSE 1 END = 1",
    )).rows[0].n;
    assert.equal(sideChannel, 2);
  });

  // Fail-closed when app.session_token is unset
  const agUnset = await runAsApp(null, async (c) => (
    (await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n
  ));
  assert.equal(agUnset, 0, 'unset session token must see 0 rows');

  // Direct base-table access MUST return SQLSTATE 42501 for platform_app
  for (const forbiddenSql of [
    'SELECT * FROM coherence.statement_upline_lines',
    'SELECT * FROM coherence.coherent_ledger_rows',
    'SELECT upline_amount FROM coherence.bob_policy_financials',
    'SELECT * FROM coherence.decisions',
    'SELECT * FROM coherence.journal_entries',
  ]) {
    await assert.rejects(
      () => runAsApp(iam.tokens.agencyMgr, (c) => c.query(forbiddenSql)),
      (err) => err?.code === '42501',
      `platform_app must get 42501 on base table: ${forbiddenSql}`,
    );
  }

  // 2. Selling Agent (NPN 11111111): strictly own NPN (distinguishes same-name 11111111 vs 22222222), zero BoB dollars, and zero Coherence statements
  await runAsApp(iam.tokens.agentA, async (c) => {
    const bob = (await c.query('SELECT policy_id, writing_npn, writing_agent, amount, upline_amount FROM app_views.coherence_bob')).rows;
    assert.equal(bob.length, 1);
    assert.equal(bob[0].writing_npn, '11111111');
    assert.equal(bob[0].amount, null);
    assert.equal(bob[0].upline_amount, null);
    const act = (await c.query('SELECT entity, writing_npn, amount, gross_comm, record_id FROM app_views.coherence_statement_agency_lines')).rows;
    assert.equal(act.length, 0);
  });

  // 3. Agency-wide zero-dollar reader (test-only custom role scoped to Harbor) sees Harbor with zero dollars;
  //    built-in retention_agent (self-only) sees zero rows of another Harbor agent's policies.
  await runAsApp(iam.tokens.harborZeroDollarReader, async (c) => {
    const bob = (await c.query('SELECT entity, amount, upline_amount FROM app_views.coherence_bob')).rows;
    assert.equal(bob.length, 1);
    assert.equal(bob[0].entity, 'Harbor');
    assert.equal(bob[0].amount, null);
    assert.equal(bob[0].upline_amount, null);
  });
  await runAsApp(iam.tokens.retentionAgent, async (c) => {
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n, 0);
  });

  // 4. Entity Manager: full BoB, ledger, all entities + Acme Upline, reconciliation view, and full workshop (journal included)
  await runAsApp(iam.tokens.entityMgr, async (c) => {
    const bob = (await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n;
    assert.equal(bob, 3);
    const recon = (await c.query('SELECT * FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid', [run1Id])).rows;
    assert.equal(recon.length, 4);
    assert.ok(recon.every((r) => r.reconciled && r.variance === '0.00'));
    assert.ok((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_journal')).rows[0].n > 0);
  });

  // 5. Investor: empty role (zero rights by default), zero rows across all Coherence views
  await runAsApp(iam.tokens.investor, async (c) => {
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_upline_lines')).rows[0].n, 0);
  });
});
