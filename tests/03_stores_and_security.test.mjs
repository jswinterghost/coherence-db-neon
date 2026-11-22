// R6.2, R6.6, R6.11, R9.7, R10.8, R14, R18 tests for the two separated stores and PHI redaction.
// Runs without needing PostgreSQL!
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createFileObjectStore, createMemoryObjectStore } from '../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../src/storage/stores.mjs';
import { crc32cBase64, fingerprintBytes } from '../src/util/crypto.mjs';
import { redactPhi, sanitizeErrorMessage } from '../src/util/redact.mjs';

test('CRC32C Castagnoli matches RFC 3720 / Google Cloud Storage test vectors', () => {
  assert.equal(crc32cBase64(Buffer.alloc(0)), 'AAAAAA==');
  assert.equal(crc32cBase64(Buffer.from('123456789', 'ascii')), '4waSgw==');
});

test('R10.8 & R11 audit: promotion before checks is refused, create-only verifies MD5+CRC32C including on existing object, and interrupted promotion resumes safely', async () => {
  const mem = createMemoryObjectStore({ label: 'data-mem' });
  const dataStore = createDataStore({ backend: mem });
  const payload = Buffer.from('col1,col2\n1,2\n', 'utf8');

  // 1. Promotion before checksPassed=true MUST be refused with ZERO objects stored
  await assert.rejects(
    () => dataStore.promoteBytes(payload, { relPath: 'overlay.csv', checksPassed: false }),
    /PROMOTION_BEFORE_CHECKS|before required checks/i,
  );
  assert.equal(mem.listObjectNames().length, 0);

  // 2. Simulated interrupted promotion (network error on first attempt) -> retry succeeds cleanly
  mem.hooks.failNextCreate = new Error('transient network reset');
  await assert.rejects(
    () => dataStore.promoteBytes(payload, { relPath: 'overlay.csv', checksPassed: true }),
    /transient network reset/i,
  );
  assert.equal(mem.listObjectNames().length, 0);

  const first = await dataStore.promoteBytes(payload, { relPath: 'overlay.csv', checksPassed: true });
  assert.equal(first.alreadyExisted, false);
  assert.equal(first.objectName, `objects/${first.sha256}`);

  // 3. Re-promoting identical bytes returns alreadyExisted=true after verifying MD5 + CRC32C
  const second = await dataStore.promoteBytes(payload, { relPath: 'overlay.csv', checksPassed: true });
  assert.equal(second.alreadyExisted, true);
  assert.equal(second.md5B64, first.md5B64);
  assert.equal(second.crc32cB64, first.crc32cB64);

  // 4. Existing object with corrupted CRC32C (even with valid MD5!) is REFUSED (R10.8)
  mem.hooks.corruptStoredMeta.set(first.objectName, { crc32cB64: 'AAAAAA==' });
  await assert.rejects(
    () => dataStore.promoteBytes(payload, { relPath: 'overlay.csv', checksPassed: true }),
    /checksum mismatch/i,
  );
  mem.hooks.corruptStoredMeta.clear();
});

test('R6.2 filesystem create-only store never overwrites and verifies fingerprints on read', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'coherence-filestore-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const backend = createFileObjectStore({ rootDir: dir });
  const store = createDataStore({ backend });
  const bytes = Buffer.from('a,b\n10,20\n', 'utf8');

  const res1 = await store.promoteBytes(bytes, { relPath: 'statements_20261121.csv', checksPassed: true });
  assert.equal(res1.alreadyExisted, false);
  const res2 = await store.promoteBytes(bytes, { relPath: 'statements_20261121.csv', checksPassed: true });
  assert.equal(res2.alreadyExisted, true);

  const readBack = await store.readVerified(res1.sha256, res1);
  assert.deepEqual(readBack, bytes);
});

test('R1.6, R6.6, R6.11, R9.7, R14.1 & R18: zero engine or code-bearing files can reach a company data store, and stores cannot be mixed', async () => {
  const codeMem = createMemoryObjectStore({ label: 'nusear-code' });
  const dataMem = createMemoryObjectStore({ label: 'company-data' });
  const codeStore = createCodeStore({ backend: codeMem });
  const dataStore = createDataStore({ backend: dataMem });

  // Mixing same backend is refused
  assert.throws(() => createStorePair({ codeStore, dataStore: createDataStore({ backend: codeMem }) }), /never share/i);

  const stores = createStorePair({ codeStore, dataStore });

  // Direct attempts to store engine/code/HTML/disguised HTML in company data store MUST fail
  await assert.rejects(
    () => dataStore.promoteBytes(Buffer.from('<!doctype html><html></html>'), { relPath: 'bible.html', checksPassed: true }),
    /CODE_IN_DATA_STORE_FORBIDDEN|code-bearing/i,
  );
  await assert.rejects(
    () => dataStore.promoteBytes(Buffer.from('print("hi")'), { relPath: 'company_emit.py', checksPassed: true }),
    /code-bearing/i,
  );
  await assert.rejects(
    () => dataStore.promoteBytes(Buffer.from('# v2 git bundle\n'), { relPath: 'coherence.bundle', checksPassed: true }),
    /code-bearing/i,
  );
  // Disguised viewer HTML saved under a fake .csv name still caught by content inspection!
  await assert.rejects(
    () => dataStore.promoteBytes(Buffer.from('window.__VIEWER_CONFIG__={"a":1};'), { relPath: 'fake.csv', checksPassed: true }),
    /code-bearing/i,
  );
  assert.equal(dataMem.listObjectNames().length, 0);

  // Artifact routing sends viewer.html & bible.html to codeStore and CSVs to dataStore
  const viewerArt = await stores.promoteArtifact('emits/bundles/entity-managers/Phalanx/viewer.html', Buffer.from('<!doctype html><html></html>'), { checksPassed: true });
  const csvArt = await stores.promoteArtifact('emits/statements_20261121.csv', Buffer.from('a,b\n1,2\n'), { checksPassed: true });
  assert.equal(viewerArt.storeKind, 'nusear_code');
  assert.equal(viewerArt.artifactKind, 'code_bearing');
  assert.equal(csvArt.storeKind, 'company_data');
  assert.equal(csvArt.artifactKind, 'data');
  assert.equal(codeMem.listObjectNames().length, 1);
  assert.equal(dataMem.listObjectNames().length, 1);
  assert.equal(dataMem.listObjectNames()[0], `objects/${fingerprintBytes(Buffer.from('a,b\n1,2\n')).sha256}`);
});

test('R14.3: PHI redaction scrubs record_ids, policy keys, MBIs, SSNs, emails, and phone numbers from errors and logs', () => {
  const raw = 'Uncommitted item uhc~direct~DOE_JANE~100.00~2026-11 and policy:aetna:H12345#effective:2026-01-01 MBI 1EG4-TE5-MK72 email jane@example.com phone (555) 123-4567';
  const cleaned = redactPhi(raw);
  assert.ok(!cleaned.includes('DOE_JANE'));
  assert.ok(!cleaned.includes('H12345'));
  assert.ok(!cleaned.includes('1EG4-TE5-MK72'));
  assert.ok(!cleaned.includes('jane@example.com'));
  assert.ok(!cleaned.includes('555'));
  const errMsg = sanitizeErrorMessage(new Error(raw));
  assert.ok(!errMsg.includes('DOE_JANE'));
});
