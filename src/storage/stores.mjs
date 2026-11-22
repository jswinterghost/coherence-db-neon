import { readFile } from 'node:fs/promises';
import { fingerprintBytes, SHA256_RE } from '../util/crypto.mjs';
import { AppError } from '../util/redact.mjs';
import {
  assertDataSafeForCompanyStore,
  classifyArtifact,
  contentTypeForPath,
  objectNameForSha256,
  STORE_KINDS,
} from './artifact-policy.mjs';

function makeStore({ backend, storeKind, enforceDataOnly }) {
  if (!backend || typeof backend.createObject !== 'function' || typeof backend.readObject !== 'function') {
    throw new Error(`Store (${storeKind}) requires a valid object-store backend.`);
  }

  async function promoteBytes(bytes, { relPath = '', checksPassed = false, contentType = null, signal = null } = {}) {
    if (checksPassed !== true) {
      throw new AppError(
        'Cannot promote bytes to object store before required checks have passed.',
        409,
        'PROMOTION_BEFORE_CHECKS',
      );
    }
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    if (enforceDataOnly) {
      assertDataSafeForCompanyStore(relPath, buf);
    }
    const fp = fingerprintBytes(buf);
    const objectName = objectNameForSha256(fp.sha256);
    const stored = await backend.createObject(objectName, buf, {
      contentType: contentType || contentTypeForPath(relPath),
      signal,
    });
    return {
      storeKind,
      sha256: fp.sha256,
      byteSize: stored.byteSize,
      md5B64: stored.md5B64,
      crc32cB64: stored.crc32cB64,
      objectName,
      alreadyExisted: stored.alreadyExisted,
    };
  }

  async function promoteFile(filePath, opts = {}) {
    const buf = await readFile(filePath);
    return promoteBytes(buf, { ...opts, relPath: opts.relPath || filePath });
  }

  async function readVerified(sha256, expected = null, { signal = null } = {}) {
    const objectName = objectNameForSha256(sha256);
    const buf = await backend.readObject(objectName, { signal });
    const fp = fingerprintBytes(buf);
    if (fp.sha256 !== sha256) {
      throw new AppError(`Stored object ${objectName} failed SHA-256 verification on read.`, 502, 'READ_INTEGRITY_FAILED');
    }
    if (expected) {
      if (expected.byteSize != null && fp.byteSize !== Number(expected.byteSize)) {
        throw new AppError(`Stored object ${objectName} size mismatch on read.`, 502, 'READ_INTEGRITY_FAILED');
      }
      if (expected.md5B64 && fp.md5B64 !== expected.md5B64) {
        throw new AppError(`Stored object ${objectName} MD5 mismatch on read.`, 502, 'READ_INTEGRITY_FAILED');
      }
      if (expected.crc32cB64 && fp.crc32cB64 !== expected.crc32cB64) {
        throw new AppError(`Stored object ${objectName} CRC32C mismatch on read.`, 502, 'READ_INTEGRITY_FAILED');
      }
    }
    return buf;
  }

  async function verifyObject(descriptor, { deep = false } = {}) {
    if (descriptor.storeKind && descriptor.storeKind !== storeKind) {
      return { ok: false, reason: `storeKind mismatch (${descriptor.storeKind} != ${storeKind})` };
    }
    const objectName = objectNameForSha256(descriptor.sha256);
    if (descriptor.objectName && descriptor.objectName !== objectName) {
      return { ok: false, reason: `objectName not derived from sha256 (${descriptor.objectName})` };
    }
    const meta = await backend.statObject(objectName);
    if (!meta) return { ok: false, reason: 'object missing from store' };
    if (
      Number(meta.byteSize) !== Number(descriptor.byteSize)
      || meta.md5B64 !== descriptor.md5B64
      || meta.crc32cB64 !== descriptor.crc32cB64
    ) {
      return { ok: false, reason: 'metadata checksum mismatch' };
    }
    if (deep) {
      try {
        await readVerified(descriptor.sha256, descriptor);
      } catch (err) {
        return { ok: false, reason: err.message };
      }
    }
    return { ok: true };
  }

  return {
    storeKind,
    backend,
    promoteBytes,
    promoteFile,
    readVerified,
    verifyObject,
    statBySha256: (sha256) => backend.statObject(objectNameForSha256(sha256)),
  };
}

export function createCodeStore({ backend }) {
  return makeStore({ backend, storeKind: STORE_KINDS.CODE, enforceDataOnly: false });
}

export function createDataStore({ backend }) {
  const base = makeStore({ backend, storeKind: STORE_KINDS.DATA, enforceDataOnly: true });

  /**
   * Stages unverified review bytes outside objects/<sha256> until the worker validates and promotes them.
   */
  async function stageReview({ submissionId, bytes }) {
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    assertDataSafeForCompanyStore('overlay.csv', buf);
    const fp = fingerprintBytes(buf);
    const stagedObjectName = `staging/reviews/${submissionId}/${fp.sha256}`;
    await backend.writeStagingObject(stagedObjectName, buf, 'text/csv; charset=utf-8');
    return { ...fp, stagedObjectName };
  }

  async function readStagedReview({ submissionId, sha256 }) {
    if (!SHA256_RE.test(sha256)) throw new AppError('Invalid staged SHA-256.', 400, 'INVALID_SHA256');
    const stagedObjectName = `staging/reviews/${submissionId}/${sha256}`;
    const buf = await backend.readStagingObject(stagedObjectName);
    const fp = fingerprintBytes(buf);
    if (fp.sha256 !== sha256) {
      throw new AppError('Staged review bytes failed SHA-256 check.', 502, 'STAGED_INTEGRITY_FAILED');
    }
    return buf;
  }

  return {
    ...base,
    stageReview,
    readStagedReview,
  };
}

export function createStorePair({ codeStore, dataStore }) {
  if (!codeStore || codeStore.storeKind !== STORE_KINDS.CODE) {
    throw new Error('createStorePair requires a nusear_code store.');
  }
  if (!dataStore || dataStore.storeKind !== STORE_KINDS.DATA) {
    throw new Error('createStorePair requires a company_data store.');
  }
  if (codeStore.backend === dataStore.backend || codeStore.backend.id === dataStore.backend.id) {
    throw new AppError('Nusear code store and company data store must never share the same backend or bucket.', 500, 'MIXED_STORES');
  }

  function forKind(storeKind) {
    if (storeKind === STORE_KINDS.CODE) return codeStore;
    if (storeKind === STORE_KINDS.DATA) return dataStore;
    throw new AppError(`Unknown store kind: ${storeKind}`, 400, 'INVALID_STORE_KIND');
  }

  async function promoteArtifact(relPath, bytes, { checksPassed = false, signal = null } = {}) {
    const { artifactKind, storeKind } = classifyArtifact(relPath, bytes);
    const target = forKind(storeKind);
    const stored = await target.promoteBytes(bytes, { relPath, checksPassed, signal });
    return { ...stored, relPath, artifactKind };
  }

  async function readVerified(storeKind, sha256, expected = null, opts = {}) {
    return forKind(storeKind).readVerified(sha256, expected, opts);
  }

  async function verifyObject(descriptor, opts = {}) {
    return forKind(descriptor.storeKind).verifyObject(descriptor, opts);
  }

  return {
    codeStore,
    dataStore,
    forKind,
    promoteArtifact,
    readVerified,
    verifyObject,
  };
}
