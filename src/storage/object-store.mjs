// Create-only object storage backends (Google Cloud Storage, local filesystem, and in-memory) verifying both MD5 and CRC32C checksums on every write and reuse.
import { createHash, createSign, randomBytes } from 'node:crypto';
import { mkdir, readFile, stat, unlink, writeFile, link } from 'node:fs/promises';
import { Agent as HttpAgent, request as httpRequest } from 'node:http';
import { Agent as HttpsAgent, request as httpsRequest } from 'node:https';
import { dirname, join, resolve } from 'node:path';
import { crc32cBase64, fingerprintBytes, md5Base64 } from '../util/crypto.mjs';
import { AppError } from '../util/redact.mjs';

const GCS_SCOPE = 'https://www.googleapis.com/auth/devstorage.read_write';
const base64url = (value) => Buffer.from(value).toString('base64url');

const AGENTS = {
  'http:': new HttpAgent({ keepAlive: true, maxSockets: 16, timeout: 30_000 }),
  'https:': new HttpsAgent({ keepAlive: true, maxSockets: 16, timeout: 30_000 }),
};

export function sendHttp1(url, { method = 'GET', headers = {}, body = null, signal = null } = {}, retry = true) {
  const address = new URL(url);
  const agent = AGENTS[address.protocol];
  const bytes = body == null
    ? null
    : typeof body === 'string' || body instanceof URLSearchParams
      ? Buffer.from(String(body))
      : ArrayBuffer.isView(body)
        ? Buffer.from(body.buffer, body.byteOffset, body.byteLength)
        : undefined;
  if (!agent || bytes === undefined) {
    return Promise.reject(new TypeError('Only http/https requests with text, bytes, or form fields are supported.'));
  }
  if (signal?.aborted) return Promise.reject(signal.reason);
  return new Promise((resolvePromise, rejectPromise) => {
    let answered = false;
    const req = (address.protocol === 'https:' ? httpsRequest : httpRequest)(
      address,
      { method, agent, headers: bytes ? { ...headers, 'Content-Length': bytes.length } : headers },
      (res) => {
        answered = true;
        const chunks = [];
        const cut = (cause) => done(new Error('The storage response was cut short.', { cause }));
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('error', cut);
        res.on('close', () => { if (!res.complete) cut(); });
        res.on('end', () => {
          const all = Buffer.concat(chunks);
          done(null, {
            ok: res.statusCode >= 200 && res.statusCode < 300,
            status: res.statusCode,
            json: async () => JSON.parse(all.toString('utf8')),
            arrayBuffer: async () => (
              all.byteLength === all.buffer.byteLength
                ? all.buffer
                : all.buffer.slice(all.byteOffset, all.byteOffset + all.byteLength)
            ),
          });
        });
      },
    );
    const stop = () => { req.destroy(); rejectPromise(signal.reason); };
    const done = (err, res) => {
      signal?.removeEventListener('abort', stop);
      if (err) rejectPromise(err);
      else resolvePromise(res);
    };
    req.on('error', (err) => {
      if (answered || !retry || !req.reusedSocket || !['ECONNRESET', 'EPIPE'].includes(err.code) || signal?.aborted) {
        return done(err);
      }
      signal?.removeEventListener('abort', stop);
      resolvePromise(sendHttp1(url, { method, headers, body, signal }, false));
    });
    signal?.addEventListener('abort', stop, { once: true });
    req.end(bytes ?? undefined);
  });
}

function assertChecksumsMatch(objectName, actual, expected) {
  if (
    Number(actual.byteSize) !== Number(expected.byteSize)
    || actual.md5B64 !== expected.md5B64
    || actual.crc32cB64 !== expected.crc32cB64
  ) {
    throw new AppError(
      `Storage checksum mismatch for ${objectName}: expected size=${expected.byteSize}, md5=${expected.md5B64}, crc32c=${expected.crc32cB64}; store reported size=${actual.byteSize}, md5=${actual.md5B64}, crc32c=${actual.crc32cB64}.`,
      502,
      'STORAGE_CHECKSUM_MISMATCH',
    );
  }
}

/**
 * Google Cloud Storage create-only backend: sets ifGenerationMatch=0, never deletes objects,
 * and verifies both MD5 and CRC32C on upload and when resuming on 412/409.
 */
export function createGcsObjectStore({
  bucket,
  keyFile = '',
  fetchImpl = sendHttp1,
  apiBase = 'https://storage.googleapis.com',
  now = () => Date.now(),
} = {}) {
  if (!bucket) throw new Error('GCS object store requires a bucket name.');
  let token = null;
  let pendingToken = null;

  const loadKey = async () => {
    if (!keyFile) throw new AppError('No Google service account key file is configured.', 503, 'MISSING_KEY');
    const info = await stat(keyFile).catch(() => null);
    if (!info) throw new AppError('The Google key file is missing.', 503, 'MISSING_KEY');
    if (info.mode & 0o077) throw new AppError('The Google key file must have mode 600.', 503, 'INSECURE_KEY');
    const parsed = JSON.parse(await readFile(keyFile, 'utf8'));
    if (parsed.type !== 'service_account' || !parsed.client_email || !parsed.private_key || !parsed.token_uri) {
      throw new AppError('The Google key file is not a valid service account key.', 503, 'INVALID_KEY');
    }
    return parsed;
  };

  const getAccessToken = async () => {
    if (token && token.until > now() + 60_000) return token.value;
    pendingToken ||= (async () => {
      const account = await loadKey();
      const issued = Math.floor(now() / 1000);
      const unsigned = `${base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${base64url(JSON.stringify({
        iss: account.client_email, scope: GCS_SCOPE, aud: account.token_uri, iat: issued, exp: issued + 3600,
      }))}`;
      const signature = createSign('RSA-SHA256').update(unsigned).sign(account.private_key, 'base64url');
      const res = await fetchImpl(account.token_uri, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          assertion: `${unsigned}.${signature}`,
        }),
        signal: AbortSignal.timeout(20_000),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || !body.access_token) {
        throw new AppError(`Google token exchange failed (${res.status}).`, 502, 'GCS_AUTH_FAILED');
      }
      token = { value: body.access_token, until: now() + (Number(body.expires_in) || 3600) * 1000 };
      return token.value;
    })().finally(() => { pendingToken = null; });
    return pendingToken;
  };

  const objectUrl = (name) => `${apiBase}/storage/v1/b/${encodeURIComponent(bucket)}/o/${encodeURIComponent(name)}`;

  const call = async (url, options = {}) => {
    const res = await fetchImpl(url, {
      ...options,
      headers: { ...(options.headers || {}), Authorization: `Bearer ${await getAccessToken()}` },
      signal: options.signal ?? AbortSignal.timeout(120_000),
    });
    if (res.status === 412 || res.status === 409) {
      throw new AppError('Object already exists in bucket; nothing was overwritten.', 409, 'ALREADY_EXISTS');
    }
    if (res.status === 404) {
      throw new AppError('Object not found in bucket.', 404, 'NOT_FOUND');
    }
    if (!res.ok) {
      throw new AppError(`Google Cloud Storage returned HTTP ${res.status}.`, 502, 'GCS_ERROR');
    }
    return res;
  };

  async function statObject(objectName) {
    try {
      const meta = await (await call(`${objectUrl(objectName)}?fields=name,size,md5Hash,crc32c,generation`)).json();
      return {
        objectName: meta.name,
        byteSize: Number(meta.size),
        md5B64: meta.md5Hash,
        crc32cB64: meta.crc32c,
        generation: meta.generation,
      };
    } catch (err) {
      if (err.status === 404) return null;
      throw err;
    }
  }

  async function createObject(objectName, bytes, { contentType = 'application/octet-stream', signal } = {}) {
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    const expected = { byteSize: buf.length, md5B64: md5Base64(buf), crc32cB64: crc32cBase64(buf) };
    const query = new URLSearchParams({ uploadType: 'media', name: objectName, ifGenerationMatch: '0' });
    let alreadyExisted = false;
    let stored;
    try {
      const meta = await (await call(`${apiBase}/upload/storage/v1/b/${encodeURIComponent(bucket)}/o?${query}`, {
        method: 'POST',
        headers: { 'Content-Type': contentType },
        body: buf,
        signal,
      })).json();
      stored = {
        objectName: meta.name || objectName,
        byteSize: Number(meta.size),
        md5B64: meta.md5Hash,
        crc32cB64: meta.crc32c,
        generation: meta.generation,
      };
    } catch (err) {
      if (err.status !== 409) throw err;
      const existing = await statObject(objectName);
      if (!existing) throw err;
      assertChecksumsMatch(objectName, existing, expected);
      stored = existing;
      alreadyExisted = true;
    }
    assertChecksumsMatch(objectName, stored, expected);
    return { ...stored, alreadyExisted };
  }

  async function readObject(objectName, { signal } = {}) {
    const res = await call(`${objectUrl(objectName)}?alt=media`, { signal });
    return Buffer.from(await res.arrayBuffer());
  }

  return {
    id: `gcs:${bucket}`,
    bucket,
    statObject,
    createObject,
    readObject,
    writeStagingObject: (name, bytes, contentType) => createObject(name, bytes, { contentType }),
    readStagingObject: (name) => readObject(name),
  };
}

/**
 * Local filesystem create-only backend (development & tests).
 * Uses exclusive file links so promoted objects are never overwritten or deleted.
 */
export function createFileObjectStore({ rootDir, label = null } = {}) {
  if (!rootDir) throw new Error('File object store requires rootDir.');
  const base = resolve(rootDir);

  const safeResolve = (objectName) => {
    const full = resolve(base, ...String(objectName).split('/'));
    if (!full.startsWith(`${base}/`) && full !== base) {
      throw new AppError('Invalid object name escaping store root.', 400, 'INVALID_OBJECT_NAME');
    }
    return full;
  };

  async function statObject(objectName) {
    const path = safeResolve(objectName);
    const info = await stat(path).catch(() => null);
    if (!info || !info.isFile()) return null;
    const bytes = await readFile(path);
    const fp = fingerprintBytes(bytes);
    return {
      objectName,
      byteSize: fp.byteSize,
      md5B64: fp.md5B64,
      crc32cB64: fp.crc32cB64,
      generation: String(info.ino),
    };
  }

  async function createObject(objectName, bytes) {
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    const expected = { byteSize: buf.length, md5B64: md5Base64(buf), crc32cB64: crc32cBase64(buf) };
    const target = safeResolve(objectName);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    const tmp = `${target}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`;
    await writeFile(tmp, buf, { mode: 0o444, flag: 'wx' });
    let alreadyExisted = false;
    try {
      // Hard-link is strictly atomic and create-only (fails with EEXIST if target already exists).
      await link(tmp, target);
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      alreadyExisted = true;
    } finally {
      await unlink(tmp).catch(() => {});
    }
    const actual = await statObject(objectName);
    if (!actual) throw new AppError(`Failed to read back stored object ${objectName}.`, 502, 'STORAGE_READBACK_FAILED');
    assertChecksumsMatch(objectName, actual, expected);
    return { ...actual, alreadyExisted };
  }

  async function readObject(objectName) {
    const path = safeResolve(objectName);
    try {
      return await readFile(path);
    } catch (err) {
      if (err.code === 'ENOENT') throw new AppError('Object not found in store.', 404, 'NOT_FOUND');
      throw err;
    }
  }

  return {
    id: label || `file:${base}`,
    rootDir: base,
    statObject,
    createObject,
    readObject,
    writeStagingObject: (name, bytes) => createObject(name, bytes),
    readStagingObject: (name) => readObject(name),
  };
}

/**
 * In-memory create-only backend for tests, with optional fault injection hooks (failNextCreate, corruptStoredMeta, onCreate).
 */
export function createMemoryObjectStore({ label = `mem:${randomBytes(4).toString('hex')}` } = {}) {
  const objects = new Map();
  let generationSeq = 1;
  const hooks = {
    failNextCreate: null,
    corruptStoredMeta: new Map(), // objectName -> override { md5B64?, crc32cB64?, byteSize? }
    onCreate: null,
  };

  async function statObject(objectName) {
    const rec = objects.get(objectName);
    if (!rec) return null;
    const override = hooks.corruptStoredMeta.get(objectName);
    return {
      objectName,
      byteSize: override?.byteSize ?? rec.byteSize,
      md5B64: override?.md5B64 ?? rec.md5B64,
      crc32cB64: override?.crc32cB64 ?? rec.crc32cB64,
      generation: rec.generation,
    };
  }

  async function createObject(objectName, bytes) {
    if (hooks.onCreate) hooks.onCreate(objectName);
    if (hooks.failNextCreate) {
      const err = hooks.failNextCreate;
      hooks.failNextCreate = null;
      throw typeof err === 'function' ? err(objectName) : err;
    }
    const buf = Buffer.isBuffer(bytes) ? Buffer.from(bytes) : Buffer.from(bytes);
    const expected = { byteSize: buf.length, md5B64: md5Base64(buf), crc32cB64: crc32cBase64(buf) };
    let alreadyExisted = false;
    if (objects.has(objectName)) {
      alreadyExisted = true;
    } else {
      objects.set(objectName, {
        bytes: buf,
        byteSize: expected.byteSize,
        md5B64: expected.md5B64,
        crc32cB64: expected.crc32cB64,
        generation: String(generationSeq++),
      });
    }
    const actual = await statObject(objectName);
    assertChecksumsMatch(objectName, actual, expected);
    return { ...actual, alreadyExisted };
  }

  async function readObject(objectName) {
    const rec = objects.get(objectName);
    if (!rec) throw new AppError('Object not found in store.', 404, 'NOT_FOUND');
    return Buffer.from(rec.bytes);
  }

  return {
    id: label,
    objects,
    hooks,
    listObjectNames: () => [...objects.keys()].sort(),
    statObject,
    createObject,
    readObject,
    writeStagingObject: (name, bytes) => createObject(name, bytes),
    readStagingObject: (name) => readObject(name),
  };
}
