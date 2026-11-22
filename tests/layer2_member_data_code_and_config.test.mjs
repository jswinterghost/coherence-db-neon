// ============================================================================
// LAYER 2: MEMBER DATA, CODE PROTECTION, AND SECURITY CONFIGURATION
// Protects: member PHI confidentiality, Nusear source code isolation, and
// database/infrastructure security configuration — preventing code or engine
// bytes from entering a company store, preventing record ids / member PHI /
// SQL parameters from appearing in any log, error, or URL, preventing writes
// during "View as", preventing any path from a customer role to code, and
// proving PostgreSQL roles, ENABLE ALWAYS triggers, fixed search_paths,
// local pg_hba.conf, and Cloud SQL policy match requirements.
// ============================================================================
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
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
import { createEngineWorker } from '../src/worker/worker.mjs';
import { createMockEngineMaterializer, makeOverlayCsv, sampleApprovalRow, seedEngineVersion, seedStandingInput } from './helpers/fixtures.mjs';
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

test('Layer 2 [Storage Integrity — R6.2, R10.8]: CRC32C vectors, promotion-before-checks refusal, MD5+CRC32C verification, and filesystem create-only store', async (t) => {
  assert.equal(crc32cBase64(Buffer.alloc(0)), 'AAAAAA==');
  assert.equal(crc32cBase64(Buffer.from('123456789', 'ascii')), '4waSgw==');

  const mem = createMemoryObjectStore({ label: 'data-mem' });
  const dataStore = createDataStore({ backend: mem });
  const payload = Buffer.from('col1,col2\n1,2\n', 'utf8');

  // 1. Promotion before checksPassed=true MUST be refused with ZERO objects stored
  await assert.rejects(
    () => dataStore.promoteBytes(payload, { relPath: 'overlay.csv', checksPassed: false }),
    /PROMOTION_BEFORE_CHECKS|before required checks/i,
  );
  assert.equal(mem.listObjectNames().length, 0);

  // 2. Interrupted promotion resumes safely
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

  // 3. Corrupted CRC32C on existing object is REFUSED
  mem.hooks.corruptStoredMeta.set(first.objectName, { crc32cB64: 'AAAAAA==' });
  await assert.rejects(
    () => dataStore.promoteBytes(payload, { relPath: 'overlay.csv', checksPassed: true }),
    /checksum mismatch/i,
  );
  mem.hooks.corruptStoredMeta.clear();

  // 4. Filesystem create-only store
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

test('Layer 2 [Negative Invariant — R1.6, R6.6, R6.11, R9.7, R14.1]: zero code-bearing files or engine bytes can ever enter a company store (storage + DB)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  // 1. Storage layer checks
  const codeMem = createMemoryObjectStore({ label: 'nusear-code' });
  const dataMem = createMemoryObjectStore({ label: 'company-data' });
  const codeStore = createCodeStore({ backend: codeMem });
  const dataStore = createDataStore({ backend: dataMem });

  assert.throws(() => createStorePair({ codeStore, dataStore: createDataStore({ backend: codeMem }) }), /never share/i);
  const stores = createStorePair({ codeStore, dataStore });

  for (const [relPath, content] of [
    ['bible.html', '<!doctype html><html></html>'],
    ['company_emit.py', 'print("hi")'],
    ['coherence.bundle', '# v2 git bundle\n'],
    ['viewer.mjs', 'export default 1;'],
    ['fake.csv', 'window.__VIEWER_CONFIG__={"a":1};'],
    ['disguised.csv', '<!DOCTYPE html><html><script>alert(1)</script></html>'],
  ]) {
    await assert.rejects(
      () => dataStore.promoteBytes(Buffer.from(content, 'utf8'), { relPath, checksPassed: true }),
      /CODE_IN_DATA_STORE_FORBIDDEN|code-bearing/i,
      `${relPath} must never enter company_data`,
    );
  }
  assert.equal(dataMem.listObjectNames().length, 0);

  const viewerArt = await stores.promoteArtifact('emits/bundles/entity-managers/Phalanx/viewer.html', Buffer.from('<!doctype html><html></html>'), { checksPassed: true });
  const csvArt = await stores.promoteArtifact('emits/statements_20261121.csv', Buffer.from('a,b\n1,2\n'), { checksPassed: true });
  assert.equal(viewerArt.storeKind, 'nusear_code');
  assert.equal(viewerArt.artifactKind, 'code_bearing');
  assert.equal(csvArt.storeKind, 'company_data');
  assert.equal(csvArt.artifactKind, 'data');
  assert.equal(dataMem.listObjectNames()[0], `objects/${fingerprintBytes(Buffer.from('a,b\n1,2\n')).sha256}`);

  // 2. Database-enforced checks (R9.7)
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const sha = sha256Hex('abc');
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('kairon', 'bad_obj', 'bad-obj-key', $1, '{"commitments":{"counts":{"stored_files":1},"hashes":{}}}'::jsonb) RETURNING seq`,
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
         VALUES ('kairon', 'bad_art', 'bad-art-key', $1, '{"commitments":{"counts":{"input_versions":1,"runs":1,"step_attempt_events":1,"artifacts":1},"hashes":{}}}'::jsonb) RETURNING seq`,
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

test('Layer 2 [Negative Invariant — R14.3]: no record id, member identifier, or SQL parameter appears in any log, error, or URL', async () => {
  // 1. Strings & errors (including spaces inside tilde record_ids AND PostgreSQL DETAIL/PARAMETERS SQL values!)
  const raw = [
    'Failed on uhc~direct~SMITH JOHN~100.00~2026-11',
    'and policy:aetna:H12345#effective:2026-01-01',
    'MBI 1EG4-TE5-MK72 SSN 123-45-6789 email jane@example.com phone (555) 123-4567',
    'DETAIL: Key (record_id)=(uhc~direct~DOE JANE~50.00) already exists.',
    'Failing row contains (1, SECRET_MEMBER_VAL)',
    "PARAMETERS: $1 = 'uhc~direct~LEAKED~10.00', $2 = '555-987-6543'",
  ].join(' ');
  const cleaned = redactPhi(raw);
  for (const forbidden of ['SMITH', 'JOHN', 'H12345', '1EG4-TE5-MK72', '123-45-6789', 'jane@example.com', '555', 'DOE', 'JANE', 'SECRET_MEMBER_VAL', 'LEAKED']) {
    assert.ok(!cleaned.includes(forbidden), `redactPhi leaked sensitive token: ${forbidden}`);
  }
  const errMsg = sanitizeErrorMessage(new Error(raw));
  for (const forbidden of ['SMITH', 'JOHN', 'H12345', 'SECRET_MEMBER_VAL', 'LEAKED']) {
    assert.ok(!errMsg.includes(forbidden), `sanitizeErrorMessage leaked: ${forbidden}`);
  }

  // 2. Structured logger scrubs sensitive keys AND values
  const captured = [];
  const logger = createSafeLogger({
    log: (line) => captured.push(line),
    warn: (line) => captured.push(line),
    error: (line) => captured.push(line),
  });
  logger.error('db_failure', {
    recordId: 'policy:aetna:P99999#effective:2026-01-01',
    sqlParams: ['uhc~direct~MEMBER_ONE~100.00', '1EG4-TE5-MK72'],
    detail: "Key (policy)=(SECRET_POLICY) $1 = 'HIDDEN_VAL'",
  });
  const logged = captured.join('\n');
  for (const forbidden of ['P99999', 'MEMBER_ONE', '1EG4-TE5-MK72', 'SECRET_POLICY', 'HIDDEN_VAL']) {
    assert.ok(!logged.includes(forbidden), `safe logger leaked: ${forbidden}`);
  }

  // 3. Real PostgreSQL error through command-layer must NOT leak member record_id or SQL parameters
  if (pgCheck.available) {
    const env = await createTestEnv();
    try {
      const secretRow = sampleApprovalRow({
        record_id: 'uhc~direct~SECRET MEMBER~100.00~2026-11',
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
      for (const secret of ['SECRET', 'MEMBER', '999.99', 'uhc~direct']) {
        assert.ok(!String(caught.message).includes(secret), `command-layer error leaked ${secret}`);
      }
    } finally {
      await env.cleanup();
    }
  }

  // 4. HTTP router refuses any record_id / policy key / member identifier in URLs AND refuses GET /approvals/history
  const router = createCoherenceRouter({
    handlersByCompany: new Map([['phalanx', { getApprovalKeyHistory: async () => ({ history: [] }) }]]),
    authenticate: async () => ({ id: 'kairon', kind: 'owner' }),
  });
  const server = createServer((req, res) => { void router(req, res); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const r1 = await fetch(`${baseUrl}/api/coherence/phalanx/approvals/history?recordId=policy:aetna:P10001`);
    assert.equal(r1.status, 400);
    const b1 = await r1.text();
    assert.ok(!b1.includes('P10001'), 'error response must never echo recordId from URL');

    const r2 = await fetch(`${baseUrl}/api/coherence/phalanx/approvals/history`);
    assert.equal(r2.status, 405, 'GET /approvals/history must be refused so recordIds stay in POST JSON body');

    const r3 = await fetch(`${baseUrl}/api/coherence/phalanx/runs/uhc~direct~SMITH%20JOHN~100.00~2026-11`);
    assert.equal(r3.status, 400);
    const b3 = await r3.text();
    assert.ok(!b3.includes('SMITH'), 'error response must never echo tilde recordId from URL');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('Layer 2 [Negative Invariant — R4.5 & R1.6]: no write while viewing as someone, and zero path from customer roles (company_admin, recipient) to any code', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:aetna:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  // Complete a run so outputs, review HTMLs, and viewer HTMLs exist in the DB + stores
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
  const launch = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'sec-launch', statementDate: '2026-11-21', engineVersionId,
  });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const bibleRows = [row0, sampleApprovalRow({ record_id: 'policy:aetna:P10001#effective:2026-01-01' })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'sec-b', expectedJournalSeq: seq, runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished'); // adjust
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const adjRows = [...bibleRows, sampleApprovalRow({ record_id: 'aetna~direct~P10001~100.00~2026-11' })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'sec-a', expectedJournalSeq: seq, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
  const adjAcc = await worker.runOnce();
  assert.equal(adjAcc.action, 'review_accepted');
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ actor: env.ownerActor, commandKey: 'sec-e', expectedJournalSeq: seq, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: 'create statements for 2026-11-21' });
  assert.equal((await worker.runOnce()).action, 'step_finished'); // emit

  // 1. Negative invariant: "View as" NEVER writes (every human write command refused!)
  const viewAsOwner = { id: 'kairon', kind: 'owner', viewingAs: { id: 'jane-agent', kind: 'recipient' } };
  await assert.rejects(() => env.commands.launchRun({ actor: viewAsOwner, commandKey: 'va-1', statementDate: '2026-11-22', engineVersionId }), /viewing as/i);
  await assert.rejects(() => env.commands.carrySent({ actor: viewAsOwner, commandKey: 'va-2', runId, typedPhrase: 'sent 2026-11-21' }), /viewing as/i);
  await assert.rejects(() => env.commands.carryApprovals({ actor: viewAsOwner, commandKey: 'va-3', runId, typedPhrase: 'carry 2026-11-21' }), /viewing as/i);
  await assert.rejects(() => env.commands.abandonRun({ actor: viewAsOwner, commandKey: 'va-4', runId, typedPhrase: 'abandon 2026-11-21', reason: 'nope' }), /viewing as/i);
  await assert.rejects(() => env.commands.saveReviewDraft({ actor: viewAsOwner, runId, surface: 'adjust', attemptNo: 1, born: 'b', checksum: 'c', rows: [] }), /viewing as/i);

  // 2. Negative invariant: NO path from a customer role (company_admin or recipient) to ANY code!
  const handlers = createWebHandlers({ pool: env.pool, companySlug: 'phalanx', stores: env.stores, commands: env.commands, entity: 'Phalanx' });
  let currentActor = null;
  const router = createCoherenceRouter({
    handlersByCompany: new Map([['phalanx', handlers]]),
    authenticate: async () => currentActor,
  });
  const server = createServer((req, res) => { void router(req, res); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  const customerActors = [
    { id: 'phalanx-admin', kind: 'company_admin', company: 'phalanx' },
    {
      id: 'jane-agent',
      kind: 'recipient',
      company: 'phalanx',
      recipientRole: 'SELLING_AGENT',
      recipientName: 'Jane Agent',
      recipientScope: { npns: ['12345678'], entities: ['Phalanx'] },
    },
  ];

  for (const cust of customerActors) {
    currentActor = cust;
    // Code-bearing file downloads refused on outputs & bundles
    for (const badPath of [
      'emits/bundles/entity-managers/Phalanx/viewer.html',
      'emits/bundles/selling-agents/Phalanx/jane-agent/viewer.html',
      'bible.html',
      'adjust.html',
      'company_emit.py',
    ]) {
      const outRes = await fetch(`${baseUrl}/api/coherence/phalanx/runs/${runId}/outputs/file?path=${encodeURIComponent(badPath)}`);
      assert.equal(outRes.status, 403, `${cust.kind} must receive 403 for outputs/file?path=${badPath}`);
    }
    const bHtml = await fetch(`${baseUrl}/api/coherence/phalanx/bundles/file?output=selling-agents/Phalanx/jane-agent&path=viewer.html`);
    assert.equal(bHtml.status, 403, `${cust.kind} must receive 403 for bundles/file?path=viewer.html`);

    // Review pages (bible.html/adjust.html), review-drift (source code check), journal, approvals all 403!
    assert.equal((await fetch(`${baseUrl}/api/coherence/phalanx/runs/${runId}/review/bible/config`)).status, 403);
    assert.equal((await fetch(`${baseUrl}/api/coherence/phalanx/runs/${runId}/review/adjust/config`)).status, 403);
    assert.equal((await fetch(`${baseUrl}/api/coherence/phalanx/review-drift`)).status, 403);
    assert.equal((await fetch(`${baseUrl}/api/coherence/phalanx/runs/${runId}/journal`)).status, 403);
    assert.equal((await fetch(`${baseUrl}/api/coherence/phalanx/approvals/history`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ recordId: 'x' }),
    })).status, 403);

    // Every write route refused 403!
    assert.equal((await fetch(`${baseUrl}/api/coherence/phalanx/runs`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ commandKey: 'cust-launch', statementDate: '2026-11-22', engineVersionId }),
    })).status, 403);

    // Allowed bundle config response contains ONLY JSON metadata, ZERO HTML/script/JS code (viewer.html stays on server)!
    const cfgRes = await fetch(`${baseUrl}/api/coherence/phalanx/bundles/config?output=selling-agents/Phalanx/jane-agent`);
    assert.equal(cfgRes.status, 200);
    const cfgText = await cfgRes.text();
    assert.ok(!/<script|<!doctype|<html|window\.__VIEWER_CONFIG__/i.test(cfgText), 'bundle config must never leak viewer.html code bytes');
  }

  // Output listing for company_admin contains ZERO code-bearing files
  currentActor = customerActors[0];
  const outList = await (await fetch(`${baseUrl}/api/coherence/phalanx/runs/${runId}/outputs`)).json();
  assert.ok(outList.files.length > 0);
  assert.ok(outList.files.every((f) => !/\.(html|js|mjs|py|sh|css)$/i.test(f.relPath)), 'company_admin output listing must never include code-bearing files');
});

test('Layer 2 [Config Assertions — Item 9]: roles/grants, ENABLE ALWAYS triggers, fixed search_path on every function, trojan search_path, local pg_hba.conf, and Cloud SQL policy checklist', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  // 1. Live DB catalog configuration audit:
  //    - coherence_app has strictly SELECT + INSERT on all 20 business tables (no UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER)
  //    - coherence_worker has strictly SELECT + INSERT on all 20 business tables
  //    - coherence_readonly has strictly SELECT; PUBLIC has zero privileges
  //    - trg_immutable is present and ENABLE ALWAYS (tgenabled='A') on ALL 20 business tables
  //    - EVERY function in schema coherence pins SET search_path = pg_catalog
  const dbCfg = await verifyDatabaseConfigInvariants(env.pool);
  assert.equal(dbCfg.passed, true, `Database config audit failed:\n${dbCfg.problems.join('\n')}`);
  assert.equal(dbCfg.checkedBusinessTables, 20);
  assert.ok(dbCfg.checkedFunctions >= 40);

  // 2. Runtime proof: trojan search_path cannot hijack functions, and coherence_app cannot acquire EXCLUSIVE/SHARE/ACCESS EXCLUSIVE locks
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

  // 3. Local pg_hba.conf (/opt/homebrew/var/postgresql@17/pg_hba.conf) has NO trust line
  const hba = await verifyPgHbaFile();
  assert.equal(hba.passed, true, `pg_hba.conf check failed: ${hba.problems.join('; ')}`);
  assert.ok(hba.ruleCount >= 2);
  assert.ok(hba.rules.every((r) => r.method !== 'trust'));

  // Negative check: verifyPgHbaFile MUST catch a trust line!
  const tmpHba = join(env.tempDir, 'bad_pg_hba.conf');
  await writeFile(tmpHba, 'local all all trust\nhost all all 127.0.0.1/32 scram-sha-256\n', 'utf8');
  const badHba = await verifyPgHbaFile(tmpHba);
  assert.equal(badHba.passed, false);
  assert.ok(badHba.problems.some((p) => /trust/i.test(p)));

  // 4. Cloud SQL policy checklist reading config/cloudsql-instance.json (TLS required, no authorized networks, pgaudit parameters off)
  const csql = await verifyCloudSqlConfigFile();
  assert.equal(csql.passed, true, `Cloud SQL policy check failed: ${csql.problems.join('; ')}`);
  assert.equal(csql.config.ipConfiguration.requireSsl, true);
  assert.deepEqual(csql.config.ipConfiguration.authorizedNetworks, []);
  assert.equal(csql.config.databaseFlags['pgaudit.log_parameter'], 'off');
  assert.equal(csql.config.databaseFlags['log_parameter_max_length'], '0');

  // Negative check: validateCloudSqlConfig MUST reject weakened settings!
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
