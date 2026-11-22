// Run folder builder & verifier (R5.2, R5.6, R10.9, R13.2, R17.3).
// Builds a fresh, isolated, writable workspace from the database + separated stores, checks every SHA-256,
// re-hashes frozen input after every step, and always removes the temporary workspace afterwards.
import { execFile } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { fingerprintBytes, sha256Hex } from '../util/crypto.mjs';
import { assertValidRelPath } from '../util/csv.mjs';
import { AppError } from '../util/redact.mjs';

const execFileAsync = promisify(execFile);
const DEFAULT_OVERLAY_CHECK = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'python', 'coherence_overlay_check.py');

export async function listFilesRecursive(rootDir, { skipTopDirs = new Set() } = {}) {
  const results = [];
  const walk = async (dir) => {
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (dir === rootDir && skipTopDirs.has(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile()) {
        results.push(relative(rootDir, full).split(sep).join('/'));
      }
    }
  };
  await walk(rootDir);
  return results.sort();
}

/**
 * Checks whether the filesystem under `inputDir` treats "ALL BOB" and "All BOB" as the same folder (R5.6).
 */
export async function verifyCaseInsensitiveAllBob(inputDir) {
  const hasAllBobMixed = await stat(join(inputDir, 'All BOB')).then((s) => s.isDirectory(), () => false);
  if (!hasAllBobMixed) return;
  const hasAllBobUpper = await stat(join(inputDir, 'ALL BOB')).then((s) => s.isDirectory(), () => false);
  if (!hasAllBobUpper) {
    throw new AppError(
      'Coherence intake.py expects ALL BOB while the input folder is All BOB; this workspace requires a case-insensitive filesystem (R5.6).',
      500,
      'CASE_SENSITIVE_FS_UNSUPPORTED',
    );
  }
}

/**
 * Default engine materializer: extracts the sealed git bundle and wrapper scripts from Nusear's code store,
 * checks out the exact recorded commit, verifies every code file against code_manifest_sha256,
 * verifies git status --porcelain is clean, and verifies wrapper script SHA-256s (R5.6, R6.6, CR-7).
 */
export async function defaultMaterializeEngine({
  engineVersion,
  workspaceDir,
  codeStore,
  pythonPath = process.env.COHERENCE_PYTHON || 'python3',
  gitBin = '/usr/bin/git',
  pnpmBin = '/opt/homebrew/bin/pnpm',
  installWebDeps = false,
  signal = null,
}) {
  const bundleBytes = await codeStore.readVerified(engineVersion.git_bundle_sha256, null, { signal });
  const bundlePath = join(dirname(workspaceDir), `engine-${engineVersion.coherence_commit}.bundle`);
  await writeFile(bundlePath, bundleBytes, { mode: 0o600 });
  try {
    await execFileAsync(gitBin, ['clone', '--quiet', '--no-checkout', bundlePath, workspaceDir], { signal });
    await execFileAsync(gitBin, ['-C', workspaceDir, 'checkout', '--quiet', '--detach', engineVersion.coherence_commit], { signal });
  } finally {
    await rm(bundlePath, { force: true }).catch(() => {});
  }

  // Verify every code file against code_manifest_sha256
  const manifestBytes = await codeStore.readVerified(engineVersion.code_manifest_sha256, null, { signal });
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const present = await listFilesRecursive(workspaceDir, { skipTopDirs: new Set(['.git', '.venv', 'input', 'runs', 'scratch']) });
  const expectedFiles = Object.keys(manifest).sort();
  if (present.length !== expectedFiles.length || present.some((f, idx) => f !== expectedFiles[idx])) {
    throw new AppError('Checked-out engine file list does not match sealed code manifest (R6.6).', 502, 'ENGINE_VERIFY_FAILED');
  }
  for (const [relPath, expectedSha] of Object.entries(manifest)) {
    const fileBytes = await readFile(join(workspaceDir, ...relPath.split('/')));
    if (sha256Hex(fileBytes) !== expectedSha) {
      throw new AppError(`Checked-out engine file ${relPath} failed SHA-256 verification.`, 502, 'ENGINE_VERIFY_FAILED');
    }
  }

  // Verify clean checkout (R5.6: no '+' suffix on git code_hash)
  const { stdout: statusOut } = await execFileAsync(gitBin, ['-C', workspaceDir, 'status', '--porcelain'], { signal });
  if (statusOut.trim().length > 0) {
    throw new AppError('Engine checkout is not clean after materialization (R5.6).', 502, 'ENGINE_DIRTY');
  }

  // Extract and verify wrapper bundle from Nusear code store (CR-7)
  const wrapperDir = join(dirname(workspaceDir), 'wrappers');
  await mkdir(wrapperDir, { recursive: true, mode: 0o700 });
  const wrapperBytes = await codeStore.readVerified(engineVersion.wrapper_bundle_sha256, null, { signal });
  const wrapperPkg = JSON.parse(wrapperBytes.toString('utf8'));
  const verifyAndWrite = async (name, expectedSha, fallbackPath = null) => {
    const content = wrapperPkg[name];
    if (typeof content !== 'string') {
      if (fallbackPath) return fallbackPath;
      throw new AppError(`Wrapper bundle is missing ${name}.`, 502, 'WRAPPER_MISSING');
    }
    const buf = Buffer.from(content, 'utf8');
    if (sha256Hex(buf) !== expectedSha) {
      throw new AppError(`Wrapper ${name} SHA-256 does not match engine version record (CR-7).`, 502, 'WRAPPER_VERIFY_FAILED');
    }
    const target = join(wrapperDir, name);
    await writeFile(target, buf, { mode: 0o600 });
    return target;
  };
  const companyEmitPath = await verifyAndWrite('company_emit.py', engineVersion.company_emit_sha256);
  await verifyAndWrite('pages_law.py', engineVersion.pages_law_sha256);
  const overlayCheckPath = await verifyAndWrite('coherence_overlay_check.py', engineVersion.overlay_check_sha256, DEFAULT_OVERLAY_CHECK);

  if (installWebDeps) {
    await execFileAsync(pnpmBin, ['install', '--frozen-lockfile', '--offline', '--reporter=silent'], {
      cwd: join(workspaceDir, 'web'),
      signal,
    });
  }

  return { pythonPath, companyEmitPath, overlayCheckPath, wrapperDir };
}

/**
 * Writes an input version's entries into `targetDir`, preserving exact paths (including trailing spaces!),
 * verifying every file's SHA-256, MD5, CRC32C, and size against the database + data store.
 */
export async function materializeInputEntries({ db, inputVersionId, targetDir, dataStore, signal = null }) {
  const res = await db.query(
    `SELECT ie.rel_path, ie.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
     FROM coherence.input_entries ie
     JOIN coherence.stored_files sf ON sf.store_kind = ie.store_kind AND sf.sha256 = ie.file_sha256
     WHERE ie.input_version_id = $1::uuid
     ORDER BY ie.rel_path COLLATE "C"`,
    [inputVersionId],
  );
  await mkdir(targetDir, { recursive: true, mode: 0o700 });
  const expectedHashes = new Map();
  for (const row of res.rows) {
    assertValidRelPath(row.rel_path, 'input entry');
    const bytes = await dataStore.readVerified(row.file_sha256, {
      byteSize: Number(row.byte_size),
      md5B64: row.md5_b64,
      crc32cB64: row.crc32c_b64,
    }, { signal });
    const fullPath = join(targetDir, ...row.rel_path.split('/'));
    await mkdir(dirname(fullPath), { recursive: true, mode: 0o700 });
    await writeFile(fullPath, bytes, { mode: 0o600, flag: 'wx' });
    expectedHashes.set(row.rel_path, row.file_sha256);
  }
  await verifyCaseInsensitiveAllBob(targetDir);
  return expectedHashes;
}

/**
 * R10.9: Re-hashes every file inside runs/<date>/input/ after a step completes to prove Coherence
 * never mutated the frozen input.
 */
export async function verifyFrozenInputUnchanged(frozenInputDir, expectedHashes) {
  const actualFiles = await listFilesRecursive(frozenInputDir);
  const expectedFiles = [...expectedHashes.keys()].sort();
  if (actualFiles.length !== expectedFiles.length) {
    throw new AppError(
      `Frozen input file count changed during step (expected ${expectedFiles.length}, found ${actualFiles.length}) (R10.9).`,
      500,
      'FROZEN_INPUT_MUTATED',
    );
  }
  for (let i = 0; i < expectedFiles.length; i++) {
    if (actualFiles[i] !== expectedFiles[i]) {
      throw new AppError(`Frozen input path list changed during step (R10.9).`, 500, 'FROZEN_INPUT_MUTATED');
    }
    const bytes = await readFile(join(frozenInputDir, ...actualFiles[i].split('/')));
    const actualSha = sha256Hex(bytes);
    if (actualSha !== expectedHashes.get(actualFiles[i])) {
      throw new AppError(`Frozen input file ${actualFiles[i]} changed during step (R10.9).`, 500, 'FROZEN_INPUT_MUTATED');
    }
  }
}

/**
 * Loads the current non-superseded finished artifacts of a run up through the required steps
 * into `runs/<date>/`, verifying every SHA-256.
 */
export async function materializePriorRunArtifacts({ db, runId, runDir, stepsToRestore, stores, signal = null }) {
  const restored = new Map();
  for (const step of stepsToRestore) {
    const evRes = await db.query(
      `SELECT id, born FROM coherence.step_attempt_events
       WHERE id = coherence.current_finished_attempt($1::uuid, $2)`,
      [runId, step],
    );
    if (evRes.rows.length === 0) continue;
    const evId = evRes.rows[0].id;
    const artRes = await db.query(
      `SELECT a.rel_path, a.artifact_kind, a.store_kind, a.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
       FROM coherence.artifacts a
       JOIN coherence.stored_files sf ON sf.store_kind = a.store_kind AND sf.sha256 = a.file_sha256
       WHERE a.attempt_event_id = $1::uuid
       ORDER BY a.rel_path COLLATE "C"`,
      [evId],
    );
    for (const row of artRes.rows) {
      assertValidRelPath(row.rel_path, 'artifact');
      // Never write code-bearing artifacts from earlier steps if not needed for computation,
      // EXCEPT restore full tree when requested (e.g. rebuild proof)
      const bytes = await stores.readVerified(row.store_kind, row.file_sha256, {
        byteSize: Number(row.byte_size),
        md5B64: row.md5_b64,
        crc32cB64: row.crc32c_b64,
      }, { signal });
      const target = join(runDir, ...row.rel_path.split('/'));
      await mkdir(dirname(target), { recursive: true, mode: 0o700 });
      await writeFile(target, bytes, { mode: 0o600 });
      restored.set(row.rel_path, row.file_sha256);
    }
  }
  return restored;
}

/**
 * Builds a complete, verified, isolated temporary workspace for one attempt or review check (R10.9).
 * Caller MUST invoke `cleanup()` in a `finally` block.
 */
export async function buildAttemptWorkspace({
  db,
  run,
  step,
  stores,
  tempBaseDir = tmpdir(),
  materializeEngine = defaultMaterializeEngine,
  rebuildWorkingOnDemand = null,
  signal = null,
}) {
  const outerDir = await mkdtemp(join(tempBaseDir, `coherence-work-${run.statement_date}-${step}-`));
  await chmod(outerDir, 0o700);
  const workspaceDir = join(outerDir, 'workspace');
  await mkdir(workspaceDir, { recursive: true, mode: 0o700 });

  const cleanup = async () => {
    await rm(outerDir, { recursive: true, force: true }).catch(() => {});
  };

  try {
    const engRes = await db.query('SELECT * FROM coherence.engine_versions WHERE id = $1::uuid', [run.engine_version_id]);
    if (engRes.rows.length === 0) throw new AppError('Run engine_version not found.', 500, 'ENGINE_NOT_FOUND');
    const engineVersion = engRes.rows[0];

    const engineRuntime = await materializeEngine({
      engineVersion,
      workspaceDir,
      codeStore: stores.codeStore,
      signal,
    });

    await mkdir(join(workspaceDir, 'runs'), { recursive: true, mode: 0o700 });
    const runDir = join(workspaceDir, 'runs', run.statement_date);

    let expectedInputHashes;
    if (step === 'assign') {
      // Assign copies workspace/input -> workspace/runs/<date>/input
      expectedInputHashes = await materializeInputEntries({
        db,
        inputVersionId: run.input_version_id,
        targetDir: join(workspaceDir, 'input'),
        dataStore: stores.dataStore,
        signal,
      });
    } else {
      // Later steps read ONLY inside runs/<date>/ (R5.2)
      await mkdir(runDir, { recursive: true, mode: 0o700 });
      expectedInputHashes = await materializeInputEntries({
        db,
        inputVersionId: run.input_version_id,
        targetDir: join(runDir, 'input'),
        dataStore: stores.dataStore,
        signal,
      });

      const restoreSteps = step === 'attribute'
        ? ['assign']
        : step === 'bible'
          ? ['assign', 'attribute']
          : step === 'adjust'
            ? ['assign', 'attribute', 'bible']
            : step === 'emit'
              ? ['assign', 'attribute', 'bible', 'adjust']
              : ['assign', 'attribute', 'bible'];

      try {
        await materializePriorRunArtifacts({ db, runId: run.id, runDir, stepsToRestore: restoreSteps, stores, signal });
      } catch (err) {
        // R17.3: If derivable working tables were stored as fingerprints only and are absent from object storage,
        // rebuild them on demand and prove every rebuilt file matches its recorded fingerprint.
        if (err?.code === 'NOT_FOUND' && typeof rebuildWorkingOnDemand === 'function') {
          await rebuildWorkingOnDemand({ workspaceDir, runDir, engineRuntime, expectedInputHashes });
        } else {
          throw err;
        }
      }

      // Restore run-local overlay.csv for adjust, emit, or adjust review checks
      if (step === 'adjust' || step === 'review_adjust') {
        const saveRes = await db.query(
          `SELECT rs.approvals_file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
           FROM coherence.review_saves rs
           JOIN coherence.stored_files sf ON sf.store_kind = 'company_data' AND sf.sha256 = rs.approvals_file_sha256
           WHERE rs.run_id = $1::uuid AND rs.surface = 'bible'
             AND rs.attempt_event_id = coherence.current_finished_attempt($1::uuid, 'bible')
           ORDER BY rs.journal_seq DESC LIMIT 1`,
          [run.id],
        );
        if (saveRes.rows.length > 0) {
          const row = saveRes.rows[0];
          const bytes = await stores.dataStore.readVerified(row.approvals_file_sha256, {
            byteSize: Number(row.byte_size), md5B64: row.md5_b64, crc32cB64: row.crc32c_b64,
          }, { signal });
          await writeFile(join(runDir, 'overlay.csv'), bytes, { mode: 0o600 });
        }
      } else if (step === 'emit') {
        const saveRes = await db.query(
          `SELECT rs.approvals_file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
           FROM coherence.review_saves rs
           JOIN coherence.stored_files sf ON sf.store_kind = 'company_data' AND sf.sha256 = rs.approvals_file_sha256
           WHERE rs.run_id = $1::uuid AND rs.surface = 'adjust'
             AND rs.attempt_event_id = coherence.current_finished_attempt($1::uuid, 'adjust')
           ORDER BY rs.journal_seq DESC LIMIT 1`,
          [run.id],
        );
        if (saveRes.rows.length > 0) {
          const row = saveRes.rows[0];
          const bytes = await stores.dataStore.readVerified(row.approvals_file_sha256, {
            byteSize: Number(row.byte_size), md5B64: row.md5_b64, crc32cB64: row.crc32c_b64,
          }, { signal });
          await writeFile(join(runDir, 'overlay.csv'), bytes, { mode: 0o600 });
        }
      }

      // R13.2: For replay runs, write back the replayed run's recorded `born` into run.json after assign
      if (run.origin === 'replay' && run.replays_run_id) {
        const origBornRes = await db.query(
          `SELECT born FROM coherence.step_attempt_events
           WHERE run_id = $1::uuid AND step = 'assign' AND event_kind = 'finished' AND born IS NOT NULL
           ORDER BY attempt_no DESC LIMIT 1`,
          [run.replays_run_id],
        );
        const origBorn = origBornRes.rows[0]?.born;
        const runJsonPath = join(runDir, 'run.json');
        if (origBorn && await stat(runJsonPath).then(() => true, () => false)) {
          const state = JSON.parse(await readFile(runJsonPath, 'utf8'));
          state.born = origBorn;
          await writeFile(runJsonPath, `${JSON.stringify(state, null, 2)}\n`, 'utf8');
        }
      }
    }

    return { outerDir, workspaceDir, runDir, engineRuntime, expectedInputHashes, cleanup };
  } catch (err) {
    await cleanup();
    throw err;
  }
}

/**
 * Reconstructs a complete historical or completed run folder from the database + stores into `targetDir`
 * for storage/rebuild proof (R12.4, R13.1).
 */
export async function rebuildRunFolderFromDb({ db, runId, targetDir, stores, includeCodeBearing = true }) {
  const runRes = await db.query(
    `SELECT id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date, input_version_id
     FROM coherence.runs WHERE id = $1::uuid`,
    [runId],
  );
  if (runRes.rows.length === 0) throw new AppError('Run not found.', 404, 'RUN_NOT_FOUND');
  const run = runRes.rows[0];
  await mkdir(targetDir, { recursive: true, mode: 0o700 });

  // 1. Rebuild frozen input/
  await materializeInputEntries({
    db,
    inputVersionId: run.input_version_id,
    targetDir: join(targetDir, 'input'),
    dataStore: stores.dataStore,
  });

  // 2. Rebuild each finished non-superseded step's artifacts in step order
  for (const step of ['assign', 'attribute', 'bible', 'adjust', 'emit']) {
    const evRes = await db.query(
      "SELECT coherence.current_finished_attempt($1::uuid, $2) AS ev_id",
      [runId, step],
    );
    const evId = evRes.rows[0]?.ev_id;
    if (!evId) continue;
    const artRes = await db.query(
      `SELECT a.rel_path, a.artifact_kind, a.store_kind, a.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
       FROM coherence.artifacts a
       JOIN coherence.stored_files sf ON sf.store_kind = a.store_kind AND sf.sha256 = a.file_sha256
       WHERE a.attempt_event_id = $1::uuid
       ORDER BY a.rel_path COLLATE "C"`,
      [evId],
    );
    for (const row of artRes.rows) {
      if (!includeCodeBearing && row.artifact_kind === 'code_bearing') continue;
      const bytes = await stores.readVerified(row.store_kind, row.file_sha256, {
        byteSize: Number(row.byte_size), md5B64: row.md5_b64, crc32cB64: row.crc32c_b64,
      });
      const outPath = join(targetDir, ...row.rel_path.split('/'));
      await mkdir(dirname(outPath), { recursive: true, mode: 0o700 });
      await writeFile(outPath, bytes, { mode: 0o600 });
    }
  }

  // 3. Restore latest run-local overlay.csv if any review_saves exist and overlay.csv wasn't already written
  const saveRes = await db.query(
    `SELECT rs.approvals_file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
     FROM coherence.review_saves rs
     JOIN coherence.stored_files sf ON sf.store_kind = 'company_data' AND sf.sha256 = rs.approvals_file_sha256
     WHERE rs.run_id = $1::uuid
     ORDER BY rs.journal_seq DESC LIMIT 1`,
    [runId],
  );
  if (saveRes.rows.length > 0) {
    const row = saveRes.rows[0];
    const overlayPath = join(targetDir, 'overlay.csv');
    if (!(await stat(overlayPath).then(() => true, () => false))) {
      const bytes = await stores.dataStore.readVerified(row.approvals_file_sha256, {
        byteSize: Number(row.byte_size), md5B64: row.md5_b64, crc32cB64: row.crc32c_b64,
      });
      await writeFile(overlayPath, bytes, { mode: 0o600 });
    }
  }

  const allFiles = await listFilesRecursive(targetDir);
  const map = {};
  for (const rel of allFiles) {
    map[rel] = fingerprintBytes(await readFile(join(targetDir, ...rel.split('/')))).sha256;
  }
  return { targetDir, files: allFiles.length, hashes: map };
}
