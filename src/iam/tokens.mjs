// Signed session token minting, short-lived renewing token providers, and mode-600 key-file helpers.
// Secret bytes stay strictly in memory or mode-600 files outside any git tree and are zeroed after use.
import { createHmac, randomUUID } from 'node:crypto';
import { chmod, lstat, mkdir, readFile, realpath, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppError } from '../util/redact.mjs';

const DEFAULT_REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const VALID_ENVIRONMENTS = new Set(['prod', 'dev', 'local']);
const VALID_KEY_SCOPES = new Set(['company_local', 'nusear_staff', 'service']);
const KEY_ID_RE = /^[a-z0-9_-]{4,32}$/;
const HEX_SECRET_RE = /^[0-9a-f]{64,}$/i;

function isSameOrInsidePath(candidatePath, protectedPath) {
  const norm = (p) => (process.platform === 'darwin' || process.platform === 'win32' ? p.toLowerCase() : p);
  const rel = relative(norm(protectedPath), norm(candidatePath));
  if (rel === '') return true;
  if (isAbsolute(rel)) return false;
  return rel !== '..' && !rel.startsWith(`..${sep}`);
}

async function resolveCanonicalPath(targetPath) {
  const abs = resolve(targetPath);
  const trailing = [];
  let cur = abs;
  while (true) {
    try {
      const real = await realpath(cur);
      return trailing.length ? join(real, ...trailing.reverse()) : real;
    } catch {
      const parent = dirname(cur);
      if (parent === cur) return abs;
      trailing.push(basename(cur));
      cur = parent;
    }
  }
}

async function hasGitMarkerInAncestors(absPath) {
  let cur = absPath;
  while (true) {
    if (basename(cur) === '.git') return cur;
    const gitEntry = join(cur, '.git');
    const exists = await lstat(gitEntry).then(() => true, () => false);
    if (exists) return cur;
    const parent = dirname(cur);
    if (parent === cur) return null;
    cur = parent;
  }
}

/**
 * Refuses any signing-keys folder located inside the repository or inside any .git working tree
 * (including git worktrees whose .git marker is a file) across both logical and canonical paths.
 */
export async function assertSafeKeysDir(keysDir, { repoRoot = DEFAULT_REPO_ROOT } = {}) {
  if (typeof keysDir !== 'string' || !keysDir.trim()) {
    throw new AppError('keysDir must be a non-empty directory path.', 400, 'MISSING_KEYS_DIR');
  }
  const absDir = resolve(keysDir);
  const canonicalDir = await resolveCanonicalPath(absDir);
  const absRepo = resolve(repoRoot);
  const canonicalRepo = await resolveCanonicalPath(absRepo);

  if (isSameOrInsidePath(absDir, absRepo) || isSameOrInsidePath(canonicalDir, canonicalRepo)) {
    throw new AppError(
      `Refusing keys directory inside the repository: ${absDir}`,
      400,
      'UNSAFE_KEYS_DIR',
    );
  }
  const gitRoot = (await hasGitMarkerInAncestors(absDir)) || (await hasGitMarkerInAncestors(canonicalDir));
  if (gitRoot) {
    throw new AppError(
      `Refusing keys directory inside a .git tree (${gitRoot}): ${absDir}`,
      400,
      'UNSAFE_KEYS_DIR',
    );
  }
  return absDir;
}

/**
 * Verifies an existing keys directory has strict mode 0700 (never chmod-ing an existing folder).
 * Returns true if the directory already exists and passed verification, or false if not yet created.
 */
export async function checkExistingPrivateKeyDir(dirPath, { repoRoot = DEFAULT_REPO_ROOT } = {}) {
  const absDir = await assertSafeKeysDir(dirPath, { repoRoot });
  const existing = await lstat(absDir).then(
    (s) => s,
    (err) => (err?.code === 'ENOENT' ? null : Promise.reject(err)),
  );
  if (!existing) return { exists: false, absDir };
  if (!existing.isDirectory()) {
    throw new AppError(`Keys directory path must be a real directory (not a file or symlink): ${absDir}`, 400, 'INSECURE_KEYS_DIR');
  }
  if (existing.mode & 0o077) {
    throw new AppError(
      `Existing keys directory must have mode 0700 (no group or world permissions); refusing to chmod existing directory: ${absDir}`,
      400,
      'INSECURE_KEYS_DIR',
    );
  }
  return { exists: true, absDir };
}

/**
 * Ensures the keys directory exists with strict mode 0700 outside any repository or .git tree.
 * Checks permissions of any existing folder without ever calling chmod on an existing parent.
 */
export async function ensurePrivateKeyDir(dirPath, { repoRoot = DEFAULT_REPO_ROOT } = {}) {
  const { exists, absDir } = await checkExistingPrivateKeyDir(dirPath, { repoRoot });
  if (exists) return absDir;

  // Create only missing directories with mode 0700; never chmod any pre-existing ancestor.
  const toCreate = [];
  let cur = absDir;
  while (true) {
    const info = await (cur === absDir ? lstat : stat)(cur).then(
      (s) => s,
      (err) => (err?.code === 'ENOENT' ? null : Promise.reject(err)),
    );
    if (info) {
      if (!info.isDirectory()) {
        throw new AppError(`Ancestor path is not a directory: ${cur}`, 400, 'INSECURE_KEYS_DIR');
      }
      break;
    }
    toCreate.push(cur);
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  for (const dir of toCreate.reverse()) {
    await mkdir(dir, { mode: 0o700 });
  }
  const created = await lstat(absDir);
  if (!created.isDirectory() || (created.mode & 0o077)) {
    throw new AppError(
      `Newly created keys directory does not have mode 0700 (check process umask): ${absDir}`,
      400,
      'INSECURE_KEYS_DIR',
    );
  }
  return absDir;
}

export function mintSignedSessionToken({
  keyId,
  secretBytes,
  environment,
  actorPersonId,
  viewAsPersonId = null,
  sessionId = randomUUID(),
  ttlSeconds = 300,
  expEpoch = null,
}) {
  if (!KEY_ID_RE.test(String(keyId || ''))) {
    throw new AppError('Invalid signing keyId.', 400, 'INVALID_KEY_ID');
  }
  if (!VALID_ENVIRONMENTS.has(environment)) {
    throw new AppError(`Invalid token environment: ${String(environment)}`, 400, 'INVALID_ENVIRONMENT');
  }
  if (!Buffer.isBuffer(secretBytes) || secretBytes.length < 32) {
    throw new AppError('Signing secret must be a Buffer of at least 32 bytes.', 400, 'INVALID_SIGNING_SECRET');
  }
  if (typeof actorPersonId !== 'string' || actorPersonId.trim().length === 0) {
    throw new AppError('actorPersonId is required to mint a session token.', 400, 'MISSING_ACTOR_PERSON_ID');
  }
  const effectiveExp = expEpoch != null
    ? Math.floor(Number(expEpoch))
    : Math.floor(Date.now() / 1000) + Math.max(1, Math.floor(Number(ttlSeconds)));
  const viewAsPart = viewAsPersonId ?? '-';
  const payload = `v1|${keyId}|${environment}|${sessionId}|${actorPersonId}|${viewAsPart}|${effectiveExp}`;
  const sig = createHmac('sha256', secretBytes).update(payload, 'utf8').digest('hex');
  return `${payload}|${sig}`;
}

/**
 * Creates a short-lived renewing session token provider (default 5-minute TTL, renewing 60s before
 * expiry) that takes ownership of secretBytes and zeroes them in dispose().
 */
export function createRenewingTokenProvider({
  keyId,
  secretBytes,
  environment,
  actorPersonId,
  viewAsPersonId = null,
  ttlSeconds = 300,
  renewBeforeSeconds = 60,
  nowMs = () => Date.now(),
}) {
  if (!KEY_ID_RE.test(String(keyId || ''))) {
    throw new AppError('Invalid signing keyId.', 400, 'INVALID_KEY_ID');
  }
  if (!VALID_ENVIRONMENTS.has(environment)) {
    throw new AppError(`Invalid token environment: ${String(environment)}`, 400, 'INVALID_ENVIRONMENT');
  }
  if (!Buffer.isBuffer(secretBytes) || secretBytes.length < 32) {
    throw new AppError('Signing secret must be a Buffer of at least 32 bytes.', 400, 'INVALID_SIGNING_SECRET');
  }
  if (typeof actorPersonId !== 'string' || actorPersonId.trim().length === 0) {
    throw new AppError('actorPersonId is required to create a session token provider.', 400, 'MISSING_ACTOR_PERSON_ID');
  }
  const effectiveTtl = Math.max(2, Math.floor(Number(ttlSeconds)));
  const effectiveRenewBefore = Math.min(
    Math.max(0, Math.floor(Number(renewBeforeSeconds))),
    effectiveTtl - 1,
  );
  let disposed = false;
  let cachedToken = null;
  let cachedExpEpoch = 0;

  function getToken() {
    if (disposed) {
      throw new AppError('Session token provider has been disposed.', 400, 'TOKEN_PROVIDER_DISPOSED');
    }
    const nowSec = Math.floor(nowMs() / 1000);
    if (!cachedToken || nowSec >= cachedExpEpoch - effectiveRenewBefore) {
      cachedExpEpoch = nowSec + effectiveTtl;
      cachedToken = mintSignedSessionToken({
        keyId,
        secretBytes,
        environment,
        actorPersonId,
        viewAsPersonId,
        expEpoch: cachedExpEpoch,
      });
    }
    return cachedToken;
  }

  function dispose() {
    if (disposed) return;
    disposed = true;
    cachedToken = null;
    cachedExpEpoch = 0;
    secretBytes.fill(0);
  }

  return { getToken, dispose };
}

export function keyFilePath(keysDir, { companySlug, environment, keyScope }) {
  return join(resolve(keysDir), `${companySlug}-${environment}-${keyScope}.key.json`);
}

export async function writeKeyFile({
  filePath,
  keyId,
  environment,
  keyScope,
  companySlug,
  secretBytes,
  repoRoot = DEFAULT_REPO_ROOT,
}) {
  if (!Buffer.isBuffer(secretBytes) || secretBytes.length < 32) {
    throw new AppError('Signing secret must be a Buffer of at least 32 bytes.', 400, 'INVALID_SIGNING_SECRET');
  }
  const absPath = resolve(filePath);
  const parentDir = dirname(absPath);
  await ensurePrivateKeyDir(parentDir, { repoRoot });
  const doc = {
    keyId,
    environment,
    keyScope,
    companySlug,
    secretHex: secretBytes.toString('hex'),
  };
  await writeFile(absPath, `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  await chmod(absPath, 0o600);
  return absPath;
}

export async function readKeyFile(filePath) {
  const absPath = resolve(filePath);
  const info = await lstat(absPath).catch(() => null);
  if (!info || !info.isFile()) {
    throw new AppError(`Signing key file not found (or not a regular file): ${absPath}`, 400, 'MISSING_KEY_FILE');
  }
  if (info.mode & 0o077) {
    throw new AppError(`Signing key file must have mode 600 (no group or world permissions): ${absPath}`, 400, 'INSECURE_KEY_FILE');
  }
  let parsed;
  try {
    parsed = JSON.parse(await readFile(absPath, 'utf8'));
  } catch {
    throw new AppError(`Signing key file is not valid JSON: ${absPath}`, 400, 'INVALID_KEY_FILE');
  }
  if (!KEY_ID_RE.test(String(parsed?.keyId || ''))) {
    throw new AppError(`Signing key file has invalid keyId: ${absPath}`, 400, 'INVALID_KEY_FILE');
  }
  if (!VALID_ENVIRONMENTS.has(parsed?.environment)) {
    throw new AppError(`Signing key file has invalid environment: ${absPath}`, 400, 'INVALID_KEY_FILE');
  }
  if (!VALID_KEY_SCOPES.has(parsed?.keyScope)) {
    throw new AppError(`Signing key file has invalid keyScope: ${absPath}`, 400, 'INVALID_KEY_FILE');
  }
  if (typeof parsed?.secretHex !== 'string' || !HEX_SECRET_RE.test(parsed.secretHex) || parsed.secretHex.length % 2 !== 0) {
    throw new AppError(`Signing key file has invalid secret payload: ${absPath}`, 400, 'INVALID_KEY_FILE');
  }
  return {
    filePath: absPath,
    keyId: parsed.keyId,
    environment: parsed.environment,
    keyScope: parsed.keyScope,
    companySlug: typeof parsed.companySlug === 'string' && parsed.companySlug.trim() ? parsed.companySlug.trim() : null,
    secretBytes: Buffer.from(parsed.secretHex, 'hex'),
  };
}
