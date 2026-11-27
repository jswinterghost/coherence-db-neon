// Source-path safety and separated code/data store path guards for read-only history imports.
import { readFile, realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { AppError } from '../util/redact.mjs';

export async function resolveCanonicalPath(targetPath) {
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

export function isSameOrInsidePath(candidatePath, protectedPath) {
  const norm = (p) => (process.platform === 'darwin' || process.platform === 'win32' ? p.toLowerCase() : p);
  const rel = relative(norm(protectedPath), norm(candidatePath));
  if (rel === '') return true;
  if (isAbsolute(rel)) return false;
  return rel !== '..' && !rel.startsWith(`..${sep}`);
}

/**
 * Refuses code and data store directories that are identical or where either sits inside the other
 * (checked across both logical and symlink-resolved canonical paths) before any folder is created.
 */
export async function assertDistinctCodeAndDataStores(codeDir, dataDir) {
  const codeResolved = resolve(codeDir);
  const dataResolved = resolve(dataDir);
  const codeCanonical = await resolveCanonicalPath(codeResolved);
  const dataCanonical = await resolveCanonicalPath(dataResolved);

  if (
    isSameOrInsidePath(codeResolved, dataResolved)
    || isSameOrInsidePath(dataResolved, codeResolved)
    || isSameOrInsidePath(codeCanonical, dataCanonical)
    || isSameOrInsidePath(dataCanonical, codeCanonical)
  ) {
    throw new AppError(
      'Refusing overlapping --code-store-dir and --data-store-dir: code and data stores must be distinct folders, neither inside the other.',
      400,
      'OVERLAPPING_STORE_DIRS',
    );
  }
}

async function collectManifestProtectedEntries(manifestPath) {
  const absManifest = resolve(manifestPath);
  const baseDir = dirname(absManifest);
  const raw = JSON.parse(await readFile(absManifest, 'utf8'));
  const resolveManifestPath = (val) => (
    typeof val === 'string' && val.trim()
      ? (isAbsolute(val) ? resolve(val) : resolve(baseDir, val))
      : null
  );

  const protectedEntries = [];
  const addProtected = (key, val) => {
    const resolved = resolveManifestPath(val);
    if (resolved) protectedEntries.push({ key, path: resolved });
  };

  addProtected('coherenceRoot', raw?.coherenceRoot);
  addProtected('coherenceRepo', raw?.coherenceRepo);
  addProtected('nusearDataDir', raw?.nusearDataDir);
  addProtected('nusearSqlitePath', raw?.nusearSqlitePath);

  if (raw?.sources && typeof raw.sources === 'object') {
    for (const [key, val] of Object.entries(raw.sources)) {
      if (typeof val === 'string') addProtected(`sources.${key}`, val);
    }
  }
  if (Array.isArray(raw?.overlayCheckpoints)) {
    raw.overlayCheckpoints.forEach((cp, idx) => {
      addProtected(`overlayCheckpoints[${idx}]`, cp?.path || cp?.absPath);
    });
  }
  if (Array.isArray(raw?.compareTargets)) {
    raw.compareTargets.forEach((ct, idx) => {
      addProtected(`compareTargets[${idx}].leftDir`, ct?.leftDir);
      addProtected(`compareTargets[${idx}].rightDir`, ct?.rightDir);
    });
  }
  return protectedEntries;
}

export async function assertSafeStoreTargets(writeTargets, manifestPath) {
  if (!Array.isArray(writeTargets) || writeTargets.length === 0) return;
  const protectedEntries = await collectManifestProtectedEntries(manifestPath);
  const resolvedTargets = [];
  for (const t of writeTargets) {
    if (!t?.path) continue;
    const resolved = resolve(t.path);
    resolvedTargets.push({
      label: t.label || 'store path',
      resolved,
      canonical: await resolveCanonicalPath(resolved),
      checkContainsProtected: Boolean(t.checkContainsProtected),
    });
  }

  for (const entry of protectedEntries) {
    const protectedCanonical = await resolveCanonicalPath(entry.path);
    for (const target of resolvedTargets) {
      if (
        isSameOrInsidePath(target.resolved, entry.path)
        || isSameOrInsidePath(target.canonical, protectedCanonical)
      ) {
        throw new AppError(
          `Refusing ${target.label} equal to or inside configured source path (${entry.key}).`,
          400,
          'UNSAFE_STORES_DIR',
        );
      }
      if (
        target.checkContainsProtected
        && (
          isSameOrInsidePath(entry.path, target.resolved)
          || isSameOrInsidePath(protectedCanonical, target.canonical)
        )
      ) {
        throw new AppError(
          `Refusing ${target.label} because it would contain configured source path (${entry.key}).`,
          400,
          'UNSAFE_STORES_DIR',
        );
      }
    }
  }
}

export async function assertSafeStoresDir(storesDir, manifestPath) {
  if (!storesDir) return;
  const candidateResolved = resolve(storesDir);
  await assertSafeStoreTargets([
    { label: '--stores-dir', path: candidateResolved, checkContainsProtected: false },
    { label: '--stores-dir/code', path: join(candidateResolved, 'code'), checkContainsProtected: true },
    { label: '--stores-dir/data', path: join(candidateResolved, 'data'), checkContainsProtected: true },
  ], manifestPath);
}
