// Read-only, manifest-first, idempotent history importer: separates code and data stores by SHA-256
// and verifies byte-for-byte folder rebuild.
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { STORE_KINDS } from '../storage/artifact-policy.mjs';
import { fingerprintBytes, sha256Hex } from '../util/crypto.mjs';
import { isValidIsoDate, normalizeMacKey } from '../util/csv.mjs';
import { AppError, sanitizeErrorMessage } from '../util/redact.mjs';
import { verifyObjects } from '../commands/journal-export.mjs';
import { listFilesRecursive, rebuildRunFolderFromDb } from '../worker/folder-builder.mjs';

const execFileAsync = promisify(execFile);
const DEFAULT_OVERLAY_CHECK = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'python', 'coherence_overlay_check.py');

const REVIEW_SAVE_RE = /^(bible|adjust)-review-(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z\.csv$/;

function parseReviewSaveTimestamp(filename) {
  const m = REVIEW_SAVE_RE.exec(filename);
  if (!m) return null;
  return {
    surface: m[1],
    originalAt: `${m[2]}T${m[3]}:${m[4]}:${m[5]}.${m[6]}000Z`,
  };
}

function parseLocalRunJsonTime(text) {
  if (!text || typeof text !== 'string') return null;
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function normalizeImportConfig(importConfig = {}) {
  const includeLegacyHostHistory = Boolean(importConfig.includeLegacyHostHistory);
  return {
    includeLegacyHostHistory,
    includeLegacySqliteTables: Boolean(importConfig.includeLegacySqliteTables ?? includeLegacyHostHistory),
    useCompanyIncomingInput: importConfig.useCompanyIncomingInput ?? !includeLegacyHostHistory,
    currentInputSourceKind: importConfig.currentInputSourceKind || (includeLegacyHostHistory ? 'mac_import' : 'company_import'),
    emitRules: Array.isArray(importConfig.emitRules) ? importConfig.emitRules : [],
    defaultCompanyEmit: importConfig.defaultCompanyEmit || {
      emitMode: 'coherence',
      emitDisplay: null,
      emitKeep: [],
      emitNoManager: [],
    },
  };
}

/**
 * Resolves opt-in live import proof settings strictly from environment variables so default test runs
 * never read live folders and no host paths or customer slugs live in source code.
 */
/**
 * Writes a git bundle holding `commit` and its whole history, without writing anything into `repo`.
 * A bundle needs a named ref, and a bare commit id is not one, so the ref lives in a throwaway bare
 * repository that borrows `repo`'s objects through git's alternates file.
 */
export async function createCommitBundle({ gitBin = 'git', repo, commit, workDir, bundlePath }) {
  const { stdout: fullSha } = await execFileAsync(gitBin, ['-C', repo, 'rev-parse', '--verify', `${commit}^{commit}`]);
  const { stdout: commonDir } = await execFileAsync(gitBin, ['-C', repo, 'rev-parse', '--path-format=absolute', '--git-common-dir']);
  const scratch = join(workDir, 'bundle-source.git');
  await execFileAsync(gitBin, ['init', '--quiet', '--bare', scratch]);
  await writeFile(join(scratch, 'objects', 'info', 'alternates'), `${join(commonDir.trim(), 'objects')}\n`);
  await execFileAsync(gitBin, ['-C', scratch, 'update-ref', 'refs/heads/engine', fullSha.trim()]);
  await execFileAsync(gitBin, ['-C', scratch, 'bundle', 'create', bundlePath, 'refs/heads/engine']);
  return fullSha.trim();
}

export function resolveLiveProofConfig(env = process.env) {
  if (env.COHERENCE_LIVE_PROOF !== '1') {
    return null;
  }
  const missing = [];
  if (!env.COHERENCE_REPO) missing.push('COHERENCE_REPO');
  if (!env.NUSEAR_DATA_DIR) missing.push('NUSEAR_DATA_DIR');
  if (!env.COHERENCE_PROOF_COMPANY) missing.push('COHERENCE_PROOF_COMPANY');
  if (missing.length > 0) {
    throw new AppError(
      `Live proof requires environment variables: ${missing.join(', ')}.`,
      400,
      'LIVE_PROOF_CONFIG_MISSING',
    );
  }
  return {
    coherenceRepo: env.COHERENCE_REPO,
    nusearDataDir: env.NUSEAR_DATA_DIR,
    companySlug: env.COHERENCE_PROOF_COMPANY,
    statementDate: env.COHERENCE_PROOF_DATE || null,
    pythonPath: env.COHERENCE_PYTHON || null,
    includeLegacyHostHistory: env.COHERENCE_PROOF_INCLUDE_LEGACY !== '0',
  };
}

/**
 * Parses an approvals file exclusively through Coherence's own Python reader via
 * coherence_overlay_check.py --parse-only; never falls back to a JavaScript CSV parser.
 */
export async function parseApprovalsFile(filePath, {
  parentPath = null,
  pythonPath = null,
  coherenceRepo = null,
  overlayCheckPath = DEFAULT_OVERLAY_CHECK,
  tempBaseDir = tmpdir(),
} = {}) {
  if (!pythonPath || !coherenceRepo) {
    throw new AppError(
      'Parsing an approvals file requires pythonPath and coherenceRepo so only Coherence parses overlay files.',
      400,
      'OVERLAY_PARSER_CONFIG_REQUIRED',
    );
  }

  const outDir = await mkdtemp(join(tempBaseDir, 'coherence-parse-ov-'));
  const outJson = join(outDir, 'parsed.json');
  try {
    const args = [overlayCheckPath, '--parse-only', filePath, '--out', outJson];
    if (parentPath) args.push('--extends', parentPath);
    try {
      await execFileAsync(pythonPath, args, {
        cwd: coherenceRepo,
        env: { ...process.env, LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8', PYTHONUTF8: '1', PYTHONPATH: coherenceRepo },
        maxBuffer: 16 * 1024 * 1024,
      });
    } catch (err) {
      const stderrText = String(err?.stderr || '');
      if (/does not begin with/i.test(stderrText)) {
        throw new AppError('Approvals file does not begin with every row of its parent.', 422, 'OVERLAY_PREFIX_MISMATCH');
      }
      throw new AppError(
        `Approvals file parser failed: ${sanitizeErrorMessage(stderrText || err, 'Overlay checker exited non-zero.')}`,
        422,
        'OVERLAY_PARSE_FAILED',
      );
    }
    const data = JSON.parse(await readFile(outJson, 'utf8'));
    return {
      headerKind: data.header_kind,
      rowCount: data.rows,
      sharedRowCount: data.shared,
      addedRows: data.new_rows,
    };
  } finally {
    await rm(outDir, { recursive: true, force: true }).catch(() => {});
  }
}

/**
 * Discovers historical run folders structurally by checking directory layout and run.json presence
 * without opening member data files.
 */
async function discoverLegacyRunFolders(runsRoot) {
  const found = [];
  const scanDir = async (dir, depth = 0) => {
    if (depth > 4) return;
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name === 'Incident Report') continue;
      const full = join(dir, entry.name);
      const hasRunJson = await stat(join(full, 'run.json')).then((s) => s.isFile(), () => false);
      if (hasRunJson && isValidIsoDate(entry.name)) {
        found.push({
          origin: 'mac_import',
          statementDate: entry.name,
          sourceFolder: relative(runsRoot, full).split(sep).join('/'),
          absPath: full,
        });
      } else {
        await scanDir(full, depth + 1);
      }
    }
  };
  await scanDir(runsRoot);
  return found.sort((a, b) => a.statementDate.localeCompare(b.statementDate) || a.sourceFolder.localeCompare(b.sourceFolder));
}

async function discoverCompanyRunFolders(workspacesDir, companySlug) {
  const companyWs = join(workspacesDir, companySlug);
  const found = [];
  const entries = await readdir(companyWs, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    if (!entry.isDirectory() || !isValidIsoDate(entry.name)) continue;
    const runPath = join(companyWs, entry.name, 'runs', entry.name);
    const hasRunJson = await stat(join(runPath, 'run.json')).then((s) => s.isFile(), () => false);
    if (hasRunJson) {
      found.push({
        origin: 'company_import',
        statementDate: entry.name,
        sourceFolder: `company-workspaces/${companySlug}/${entry.name}/runs/${entry.name}`,
        absPath: runPath,
      });
    }
  }
  return found.sort((a, b) => a.statementDate.localeCompare(b.statementDate));
}

async function openSqliteReadOnly(sqlitePath) {
  let info;
  try {
    info = await stat(sqlitePath);
  } catch {
    throw new AppError(`Legacy SQLite database not found at ${sqlitePath}.`, 404, 'SQLITE_NOT_FOUND');
  }
  if (!info.isFile()) {
    throw new AppError(`Legacy SQLite path is not a regular file: ${sqlitePath}.`, 400, 'SQLITE_INVALID_PATH');
  }
  let DatabaseSync;
  try {
    ({ DatabaseSync } = await import('node:sqlite'));
  } catch (err) {
    throw new AppError(`node:sqlite is unavailable: ${sanitizeErrorMessage(err)}`, 500, 'SQLITE_UNAVAILABLE');
  }
  try {
    const sq = new DatabaseSync(sqlitePath, { open: true, readOnly: true });
    // Force SQLite to validate the database header immediately rather than deferring to the first query.
    sq.prepare('SELECT 1 FROM sqlite_master LIMIT 1').get();
    return sq;
  } catch (err) {
    throw new AppError(`Failed to open legacy SQLite database: ${sanitizeErrorMessage(err)}`, 500, 'SQLITE_READ_FAILED');
  }
}

function getExpectedSqliteQueries(companySlug, includeLegacySqliteTables) {
  const queries = [];
  if (includeLegacySqliteTables) {
    queries.push(
      ['coherence_run_records', 'SELECT COUNT(*) AS n FROM coherence_run_records', 'SELECT * FROM coherence_run_records ORDER BY date', []],
      ['coherence_run_events', 'SELECT COUNT(*) AS n FROM coherence_run_events', 'SELECT * FROM coherence_run_events ORDER BY id', []],
      ['coherence_run_drafts', 'SELECT COUNT(*) AS n FROM coherence_run_drafts', 'SELECT * FROM coherence_run_drafts ORDER BY date, surface', []],
      ['coherence_run_settings', 'SELECT COUNT(*) AS n FROM coherence_run_settings', 'SELECT * FROM coherence_run_settings ORDER BY key', []],
    );
  }
  queries.push(
    ['company_run_records', 'SELECT COUNT(*) AS n FROM company_run_records WHERE company = ?', 'SELECT * FROM company_run_records WHERE company = ? ORDER BY date', [companySlug]],
    ['company_run_events', 'SELECT COUNT(*) AS n FROM company_run_events WHERE company = ?', 'SELECT * FROM company_run_events WHERE company = ? ORDER BY id', [companySlug]],
    ['company_run_drafts', 'SELECT COUNT(*) AS n FROM company_run_drafts WHERE company = ?', 'SELECT * FROM company_run_drafts WHERE company = ? ORDER BY date, surface', [companySlug]],
    ['company_intake_events', 'SELECT COUNT(*) AS n FROM company_intake_events WHERE company = ?', 'SELECT * FROM company_intake_events WHERE company = ? ORDER BY id', [companySlug]],
  );
  return queries;
}

/**
 * Builds a complete read-only import manifest listing all source folders, files, review saves,
 * and SQLite record counts before reading file contents or writing to PostgreSQL.
 */
export async function buildImportManifest({
  companySlug,
  coherenceRoot = null,
  nusearDataDir = null,
  nusearSqlitePath = null,
  importConfig = {},
} = {}) {
  const config = normalizeImportConfig(importConfig);
  const manifest = {
    companySlug,
    importConfig: config,
    generatedAt: new Date().toISOString(),
    macRuns: [],
    companyRuns: [],
    currentInputDir: null,
    currentInputFiles: [],
    incidentReportFiles: [],
    nusearMacSaves: {},     // date -> [{ filename, absPath, surface, originalAt }]
    nusearCompanySaves: {}, // date -> [{ filename, absPath, surface, originalAt }]
    standaloneFiles: [],    // { area, relPath, absPath }
    sqliteCounts: {},
  };

  if (config.includeLegacyHostHistory && coherenceRoot) {
    const runsRoot = join(coherenceRoot, 'runs');
    manifest.macRuns = await discoverLegacyRunFolders(runsRoot);

    const incidentRoot = join(runsRoot, 'Incident Report');
    const incidentFiles = await listFilesRecursive(incidentRoot);
    manifest.incidentReportFiles = incidentFiles.map((rel) => ({
      area: 'incident_report',
      relPath: `Incident Report/${rel}`,
      absPath: join(incidentRoot, ...rel.split('/')),
    }));

    const legacyInput = join(coherenceRoot, 'input');
    if (await stat(legacyInput).then((s) => s.isDirectory(), () => false)) {
      manifest.currentInputDir = legacyInput;
      manifest.currentInputFiles = await listFilesRecursive(legacyInput);
    }

    if (nusearDataDir) {
      const legacyRunsData = join(nusearDataDir, 'coherence-runs');
      const dates = await readdir(legacyRunsData, { withFileTypes: true }).catch(() => []);
      for (const d of dates) {
        if (!d.isDirectory() || !isValidIsoDate(d.name)) continue;
        const files = (await readdir(join(legacyRunsData, d.name)).catch(() => [])).sort();
        const saves = [];
        for (const f of files) {
          const parsed = parseReviewSaveTimestamp(f);
          const absPath = join(legacyRunsData, d.name, f);
          if (parsed) {
            saves.push({ filename: f, absPath, ...parsed });
          } else {
            manifest.standaloneFiles.push({ area: 'nusear_log', relPath: `coherence-runs/${d.name}/${f}`, absPath });
          }
        }
        if (saves.length) manifest.nusearMacSaves[d.name] = saves;
      }
    }
  }

  if (nusearDataDir) {
    manifest.companyRuns = await discoverCompanyRunFolders(join(nusearDataDir, 'company-workspaces'), companySlug);

    const compRunsData = join(nusearDataDir, 'company-runs', companySlug);
    const dates = await readdir(compRunsData, { withFileTypes: true }).catch(() => []);
    for (const d of dates) {
      if (!d.isDirectory() || !isValidIsoDate(d.name)) continue;
      const files = (await readdir(join(compRunsData, d.name)).catch(() => [])).sort();
      const saves = [];
      for (const f of files) {
        const parsed = parseReviewSaveTimestamp(f);
        const absPath = join(compRunsData, d.name, f);
        if (parsed) {
          saves.push({ filename: f, absPath, ...parsed });
        } else {
          manifest.standaloneFiles.push({ area: 'nusear_log', relPath: `company-runs/${companySlug}/${d.name}/${f}`, absPath });
        }
      }
      if (saves.length) manifest.nusearCompanySaves[d.name] = saves;
    }

    // Company incoming input folder when not importing from a separate legacy host input directory.
    const compEnv = join(nusearDataDir, 'company-environments', companySlug);
    if (config.useCompanyIncomingInput) {
      const incomingDir = join(compEnv, 'incoming');
      if (await stat(incomingDir).then((s) => s.isDirectory(), () => false)) {
        manifest.currentInputDir = incomingDir;
        manifest.currentInputFiles = await listFilesRecursive(incomingDir);
      }
    }
    for (const [sub, area] of [['staging', 'staging'], ['documents', 'documents'], ['inventories', 'archive_inventory']]) {
      const subDir = join(compEnv, sub);
      const files = await listFilesRecursive(subDir);
      for (const rel of files) {
        manifest.standaloneFiles.push({ area, relPath: `${sub}/${rel}`, absPath: join(subDir, ...rel.split('/')) });
      }
    }
  }

  if (nusearSqlitePath) {
    const sq = await openSqliteReadOnly(nusearSqlitePath);
    try {
      for (const [tbl, countSql, , params] of getExpectedSqliteQueries(companySlug, config.includeLegacySqliteTables)) {
        try {
          manifest.sqliteCounts[tbl] = Number(sq.prepare(countSql).get(...params)?.n ?? 0);
        } catch (err) {
          throw new AppError(
            `Failed to count legacy SQLite table ${tbl}: ${sanitizeErrorMessage(err)}`,
            500,
            'SQLITE_READ_FAILED',
          );
        }
      }
    } finally {
      sq.close();
    }
  }

  return manifest;
}

function partitionRunFilesByStep(allFiles, stepsDone) {
  const byStep = { assign: [], attribute: [], bible: [], adjust: [], emit: [] };
  const lastStep = ['emit', 'adjust', 'bible', 'attribute', 'assign'].find((s) => stepsDone.includes(s)) || 'assign';

  for (const rel of allFiles) {
    if (rel.startsWith('input/')) continue; // input/ is stored in the run's snapshot input_version
    if (rel === 'run.json') {
      byStep[lastStep].push(rel);
    } else if (rel.startsWith('working/')) {
      byStep[stepsDone.includes('attribute') ? 'attribute' : 'assign'].push(rel);
    } else if (rel === 'bible.csv' || rel === 'bible.html') {
      byStep.bible.push(rel);
    } else if (rel === 'adjust.csv' || rel === 'adjust.html') {
      byStep.adjust.push(rel);
    } else if (rel.startsWith('emits/') || rel === 'company_manifest.json') {
      byStep.emit.push(rel);
    } else if (rel === 'overlay.csv') {
      // overlay.csv is tracked via review_saves / approvals_files; also attach to adjust (or bible/emit) so exact folder rebuild reproduces it byte-for-byte
      const ownerStep = stepsDone.includes('adjust') ? 'adjust' : (stepsDone.includes('bible') ? 'bible' : lastStep);
      byStep[ownerStep].push(rel);
    } else {
      byStep[lastStep].push(rel);
    }
  }
  return byStep;
}

function inferEmitSettings(runItem, allFiles, importConfig = {}) {
  if (runItem.origin === 'mac_import') {
    return { emitMode: 'coherence', emitDisplay: null, emitKeep: [], emitNoManager: [] };
  }
  const hasCompanyManifest = allFiles.includes('company_manifest.json');
  const rules = Array.isArray(importConfig.emitRules) ? importConfig.emitRules : [];
  for (const rule of rules) {
    const matches = rule.matchManifestOrFromDate
      ? (hasCompanyManifest || (rule.fromDate && runItem.statementDate >= rule.fromDate))
      : ((!rule.fromDate || runItem.statementDate >= rule.fromDate) && (!rule.requireManifest || hasCompanyManifest));
    if (matches) {
      return {
        emitMode: rule.emitMode,
        emitDisplay: rule.emitDisplay ?? null,
        emitKeep: Array.isArray(rule.emitKeep) ? [...rule.emitKeep] : [],
        emitNoManager: Array.isArray(rule.emitNoManager) ? [...rule.emitNoManager] : [],
      };
    }
  }
  const fallback = importConfig.defaultCompanyEmit || {};
  return {
    emitMode: fallback.emitMode || 'coherence',
    emitDisplay: fallback.emitDisplay ?? null,
    emitKeep: Array.isArray(fallback.emitKeep) ? [...fallback.emitKeep] : [],
    emitNoManager: Array.isArray(fallback.emitNoManager) ? [...fallback.emitNoManager] : [],
  };
}

export async function importSingleRunFolder({
  pool,
  stores,
  commands,
  actor,
  companySlug,
  runItem,
  nusearSaves = [],
  importConfig = {},
  parseOverlay = parseApprovalsFile,
  pythonPath = null,
  coherenceRepo = null,
  overlayCheckPath = DEFAULT_OVERLAY_CHECK,
  gitBin = '/usr/bin/git',
  allowedMissingCommits = [],
  tempBaseDir = tmpdir(),
}) {
  // Check idempotency early before promoting bytes unnecessarily
  const existing = await pool.query(
    'SELECT id FROM coherence.runs WHERE origin = $1 AND source_folder = $2',
    [runItem.origin, runItem.sourceFolder],
  );
  if (existing.rows.length > 0) {
    return {
      runId: existing.rows[0].id,
      alreadyImported: true,
      sourceFolder: runItem.sourceFolder,
      commitArchiveFailures: [],
    };
  }

  const runJsonRaw = await readFile(join(runItem.absPath, 'run.json'), 'utf8');
  const runJson = JSON.parse(runJsonRaw);
  const stepsObj = runJson.steps && typeof runJson.steps === 'object' ? runJson.steps : {};
  const stepsDone = ['assign', 'attribute', 'bible', 'adjust', 'emit'].filter((s) => Boolean(stepsObj[s]));

  const allowedMissingSet = new Set(allowedMissingCommits);
  const commitsPromoted = [];
  const commitArchiveFailures = [];
  if (coherenceRepo) {
    const commits = new Set(
      Object.values(stepsObj)
        .map((s) => s?.code)
        .filter((c) => typeof c === 'string' && /^[0-9a-f]{7,40}$/.test(c)),
    );
    for (const shortCommit of commits) {
      const tmpDir = await mkdtemp(join(tempBaseDir, 'coherence-git-bundle-'));
      const bundlePath = join(tmpDir, `${shortCommit}.bundle`);
      try {
        await createCommitBundle({ gitBin, repo: coherenceRepo, commit: shortCommit, workDir: tmpDir, bundlePath });
        const bytes = await readFile(bundlePath);
        const promoted = await stores.codeStore.promoteBytes(bytes, {
          relPath: `git-bundles/${shortCommit}.bundle`,
          checksPassed: true,
        });
        commitsPromoted.push(promoted);
      } catch (err) {
        if (!allowedMissingSet.has(shortCommit)) {
          commitArchiveFailures.push({
            commit: shortCommit,
            sourceFolder: runItem.sourceFolder,
            error: sanitizeErrorMessage(err?.stderr || err, 'Commit not reachable in repository.'),
          });
        }
      } finally {
        await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
      }
    }
  }

  const allFiles = await listFilesRecursive(runItem.absPath);
  const storedFiles = [...commitsPromoted];
  const inputEntries = [];

  const inputFiles = allFiles.filter((rel) => rel.startsWith('input/'));
  let priorOverlayAbsPath = null;
  let priorOverlaySha = null;
  for (const fullRel of inputFiles) {
    const relPath = fullRel.slice('input/'.length);
    const absPath = join(runItem.absPath, ...fullRel.split('/'));
    const bytes = await readFile(absPath);
    const promoted = await stores.dataStore.promoteBytes(bytes, { relPath, checksPassed: true });
    storedFiles.push(promoted);
    inputEntries.push({ relPath, fileSha256: promoted.sha256 });
    if (normalizeMacKey(relPath) === 'overlay/overlay.csv') {
      priorOverlayAbsPath = absPath;
      priorOverlaySha = promoted.sha256;
    }
  }

  // 2. Parse & chain approvals files: frozen prior -> Nusear saves (sorted by timestamp) -> final overlay.csv / emits/overlay.csv
  const approvalsFiles = [];
  const reviewSaves = [];
  let prevOverlayPath = null;
  let prevOverlaySha = null;
  const parseOpts = { pythonPath, coherenceRepo, overlayCheckPath, tempBaseDir };

  const registerOverlayCandidate = async (absPath, promotedFile) => {
    let parsed;
    let extendsSha256 = null;
    if (prevOverlayPath && prevOverlaySha !== promotedFile.sha256) {
      try {
        parsed = await parseOverlay(absPath, { ...parseOpts, parentPath: prevOverlayPath });
        extendsSha256 = prevOverlaySha;
      } catch (err) {
        if (err?.code === 'OVERLAY_PREFIX_MISMATCH') {
          parsed = await parseOverlay(absPath, { ...parseOpts, parentPath: null });
          extendsSha256 = null;
        } else {
          throw err;
        }
      }
    } else {
      parsed = await parseOverlay(absPath, { ...parseOpts, parentPath: null });
    }
    if (!approvalsFiles.some((af) => af.fileSha256 === promotedFile.sha256)) {
      approvalsFiles.push({
        fileSha256: promotedFile.sha256,
        headerKind: parsed.headerKind,
        rowCount: parsed.rowCount,
        extendsSha256,
        sharedRowCount: parsed.sharedRowCount,
        addedRows: parsed.addedRows,
      });
    }
    prevOverlayPath = absPath;
    prevOverlaySha = promotedFile.sha256;
  };

  if (priorOverlayAbsPath && priorOverlaySha) {
    const priorStored = storedFiles.find((f) => f.sha256 === priorOverlaySha);
    await registerOverlayCandidate(priorOverlayAbsPath, priorStored);
  }

  const orderedSaves = [...nusearSaves].sort((a, b) => a.originalAt.localeCompare(b.originalAt));
  if (orderedSaves.length > 0) {
    for (const save of orderedSaves) {
      const bytes = await readFile(save.absPath);
      const promoted = await stores.dataStore.promoteBytes(bytes, { relPath: 'overlay.csv', checksPassed: true });
      storedFiles.push(promoted);
      await registerOverlayCandidate(save.absPath, promoted);
      reviewSaves.push({
        surface: save.surface,
        approvalsFileSha256: promoted.sha256,
        originalAt: save.originalAt,
      });
    }
  } else {
    // Historical runs without individual timestamped review saves fall back to their final approvals file (root overlay.csv, else emits/overlay.csv).
    const fallbackRel = allFiles.includes('overlay.csv')
      ? 'overlay.csv'
      : (allFiles.includes('emits/overlay.csv') ? 'emits/overlay.csv' : null);
    if (fallbackRel) {
      const absPath = join(runItem.absPath, ...fallbackRel.split('/'));
      const info = await stat(absPath);
      const bytes = await readFile(absPath);
      const promoted = await stores.dataStore.promoteBytes(bytes, { relPath: fallbackRel, checksPassed: true });
      storedFiles.push(promoted);
      await registerOverlayCandidate(absPath, promoted);
      const surface = stepsDone.includes('adjust') ? 'adjust' : 'bible';
      if (stepsDone.includes(surface)) {
        reviewSaves.push({
          surface,
          approvalsFileSha256: promoted.sha256,
          originalAt: info.mtime.toISOString(),
        });
      }
    }
  }

  const byStep = partitionRunFilesByStep(allFiles, stepsDone);
  const stepAttempts = [];
  for (const step of stepsDone) {
    const stepFiles = byStep[step] || [];
    const artifacts = [];
    for (const relPath of stepFiles) {
      const absPath = join(runItem.absPath, ...relPath.split('/'));
      const bytes = await readFile(absPath);
      const promoted = await stores.promoteArtifact(relPath, bytes, { checksPassed: true });
      storedFiles.push(promoted);
      artifacts.push({
        relPath,
        artifactKind: promoted.artifactKind,
        storeKind: promoted.storeKind,
        fileSha256: promoted.sha256,
      });
      if (relPath === 'emits/overlay.csv' && !approvalsFiles.some((af) => af.fileSha256 === promoted.sha256)) {
        await registerOverlayCandidate(absPath, promoted);
      }
    }
    const stepMeta = stepsObj[step] || {};
    stepAttempts.push({
      step,
      attemptNo: 1,
      born: step === 'assign' ? (runJson.born ?? null) : null, // Preserve NULL when a historical run.json has no born timestamp; never synthesize one.
      census: stepMeta,
      finishedAt: parseLocalRunJsonTime(stepMeta.at),
      artifacts,
    });
  }

  const emitSettings = inferEmitSettings(runItem, allFiles, importConfig);
  const cmdKey = `import-run:${runItem.origin}:${runItem.sourceFolder}`;
  const res = await commands.importHistoricalRun({
    actor,
    commandKey: cmdKey,
    run: {
      origin: runItem.origin,
      statementDate: runItem.statementDate,
      folderNumber: 1,
      sourceFolder: runItem.sourceFolder,
      ...emitSettings,
    },
    inputVersion: { reason: `Imported frozen input from ${runItem.sourceFolder}` },
    inputEntries,
    approvalsFiles,
    stepAttempts,
    reviewSaves,
    storedFiles,
  });

  return {
    runId: res.result.runId,
    alreadyImported: Boolean(res.result.alreadyImported || res.idempotent),
    sourceFolder: runItem.sourceFolder,
    statementDate: runItem.statementDate,
    inputFiles: inputEntries.length,
    steps: stepAttempts.length,
    reviewSaves: reviewSaves.length,
    journalSeq: res.journalSeq,
    commitArchiveFailures,
  };
}

export async function executeHistoryImport({
  pool,
  stores,
  commands,
  actor,
  manifest,
  importConfig = null,
  parseOverlay = parseApprovalsFile,
  pythonPath = null,
  coherenceRepo = null,
  overlayCheckPath = DEFAULT_OVERLAY_CHECK,
  gitBin = '/usr/bin/git',
  allowedMissingCommits = [],
  nusearSqlitePath = null,
  verifyRebuild = true,
  tempBaseDir = tmpdir(),
}) {
  const effectiveConfig = normalizeImportConfig(importConfig || manifest.importConfig || {});
  const report = {
    companySlug: manifest.companySlug,
    importedRuns: [],
    skippedRuns: [],
    commitArchiveFailures: [],
    currentInputVersionId: null,
    standaloneFilesImported: 0,
    nusearRecordsImported: 0,
    rebuildChecks: [],
    objectCheck: null,
    sqliteParity: { source: manifest.sqliteCounts, imported: {} },
    passed: true,
    problems: [],
  };

  const allRuns = [
    ...manifest.macRuns.map((r) => ({ item: r, saves: manifest.nusearMacSaves[r.statementDate] || [] })),
    ...manifest.companyRuns.map((r) => ({ item: r, saves: manifest.nusearCompanySaves[r.statementDate] || [] })),
  ];

  for (const { item, saves } of allRuns) {
    const res = await importSingleRunFolder({
      pool,
      stores,
      commands,
      actor,
      companySlug: manifest.companySlug,
      runItem: item,
      nusearSaves: saves,
      importConfig: effectiveConfig,
      parseOverlay,
      pythonPath,
      coherenceRepo,
      overlayCheckPath,
      gitBin,
      allowedMissingCommits,
      tempBaseDir,
    });
    if (res.commitArchiveFailures && res.commitArchiveFailures.length > 0) {
      report.commitArchiveFailures.push(...res.commitArchiveFailures);
      for (const fail of res.commitArchiveFailures) {
        report.problems.push(`Failed to archive git commit ${fail.commit} for ${fail.sourceFolder}: ${fail.error}`);
      }
    }
    if (res.alreadyImported) report.skippedRuns.push(res);
    else report.importedRuns.push(res);
  }

  // Import current standing input folder (idempotent per content digest via commandKey).
  if (manifest.currentInputDir && manifest.currentInputFiles.length > 0) {
    const entries = [];
    const storedFiles = [];
    let overlayAbs = null;
    let overlayStored = null;
    for (const relPath of manifest.currentInputFiles) {
      const absPath = join(manifest.currentInputDir, ...relPath.split('/'));
      const bytes = await readFile(absPath);
      const promoted = await stores.dataStore.promoteBytes(bytes, { relPath, checksPassed: true });
      storedFiles.push(promoted);
      entries.push({ relPath, fileSha256: promoted.sha256 });
      if (normalizeMacKey(relPath) === 'overlay/overlay.csv') {
        overlayAbs = absPath;
        overlayStored = promoted;
      }
    }
    if (overlayAbs && overlayStored) {
      const parsed = await parseOverlay(overlayAbs, {
        parentPath: null,
        pythonPath,
        coherenceRepo,
        overlayCheckPath,
        tempBaseDir,
      });
      await commands.registerApprovalsFile({
        actor,
        commandKey: `import-current-overlay:${manifest.companySlug}:${overlayStored.sha256}`,
        storedFile: overlayStored,
        headerKind: parsed.headerKind,
        rowCount: parsed.rowCount,
        extendsSha256: null,
        sharedRowCount: 0,
        addedRows: parsed.addedRows,
      });
    }
    const entriesDigest = sha256Hex(JSON.stringify(entries.map((e) => [e.relPath, e.fileSha256]).sort()));
    const ivRes = await commands.publishInputVersion({
      actor,
      commandKey: `import-current-input:${manifest.companySlug}:${entriesDigest}`,
      lineKind: 'standing',
      sourceKind: effectiveConfig.currentInputSourceKind,
      reason: `Import current standing input from ${manifest.currentInputDir}`,
      entries,
      storedFiles,
    });
    report.currentInputVersionId = ivRes.result.inputVersionId;
  }

  const standaloneAll = [...manifest.incidentReportFiles, ...manifest.standaloneFiles];
  if (standaloneAll.length > 0) {
    const files = [];
    const storedFiles = [];
    for (const f of standaloneAll) {
      const bytes = await readFile(f.absPath);
      const info = await stat(f.absPath);
      const promoted = await stores.promoteArtifact(f.relPath, bytes, { checksPassed: true });
      storedFiles.push(promoted);
      files.push({
        area: f.area,
        relPath: f.relPath,
        artifactKind: promoted.artifactKind,
        storeKind: promoted.storeKind,
        fileSha256: promoted.sha256,
        originalAt: info.mtime.toISOString(),
        metadata: { byteSize: promoted.byteSize },
      });
    }
    const keyHash = sha256Hex(JSON.stringify(files.map((f) => [f.area, f.relPath, f.fileSha256]).sort()));
    const res = await commands.importStandaloneFiles({
      actor,
      commandKey: `import-standalone:${manifest.companySlug}:${keyHash}`,
      files,
      storedFiles,
    });
    report.standaloneFilesImported = res.result.importedCount;
  }

  // Archive all legacy SQLite run records (including events predating record clears) as an immutable JSON snapshot.
  if (nusearSqlitePath) {
    const sq = await openSqliteReadOnly(nusearSqlitePath);
    const snapshot = {};
    try {
      for (const [tbl, , selectSql, params] of getExpectedSqliteQueries(manifest.companySlug, effectiveConfig.includeLegacySqliteTables)) {
        try {
          snapshot[tbl] = sq.prepare(selectSql).all(...params);
        } catch (err) {
          throw new AppError(
            `Failed to read legacy SQLite table ${tbl}: ${sanitizeErrorMessage(err)}`,
            500,
            'SQLITE_READ_FAILED',
          );
        }
      }
    } finally {
      sq.close();
    }
    for (const [k, rows] of Object.entries(snapshot)) report.sqliteParity.imported[k] = rows.length;
    const snapBytes = Buffer.from(`${JSON.stringify(snapshot, null, 2)}\n`, 'utf8');
    const promoted = await stores.dataStore.promoteBytes(snapBytes, {
      relPath: `nusear-records/${manifest.companySlug}-sqlite-snapshot.json`,
      checksPassed: true,
      contentType: 'application/json',
    });
    await commands.importStandaloneFiles({
      actor,
      commandKey: `import-nusear-sqlite:${manifest.companySlug}:${promoted.sha256}`,
      files: [{
        area: 'nusear_record',
        relPath: `nusear-records/${manifest.companySlug}-sqlite-snapshot.json`,
        artifactKind: 'data',
        storeKind: STORE_KINDS.DATA,
        fileSha256: promoted.sha256,
        metadata: { counts: report.sqliteParity.imported },
      }],
      storedFiles: [promoted],
    });
    report.nusearRecordsImported = Object.values(report.sqliteParity.imported).reduce((a, b) => a + b, 0);
  }

  if (verifyRebuild) {
    for (const { item } of allRuns) {
      const runRow = await pool.query(
        'SELECT id FROM coherence.runs WHERE origin = $1 AND source_folder = $2',
        [item.origin, item.sourceFolder],
      );
      if (runRow.rows.length === 0) {
        report.problems.push(`Run ${item.sourceFolder} missing from DB after import.`);
        continue;
      }
      const runId = runRow.rows[0].id;
      const tmpRebuild = await mkdtemp(join(tempBaseDir, `coherence-rebuild-proof-${item.statementDate}-`));
      try {
        const rebuilt = await rebuildRunFolderFromDb({ db: pool, runId, targetDir: tmpRebuild, stores });
        const origFiles = await listFilesRecursive(item.absPath);
        const origHashes = {};
        for (const rel of origFiles) {
          origHashes[rel] = fingerprintBytes(await readFile(join(item.absPath, ...rel.split('/')))).sha256;
        }
        const onlySource = origFiles.filter((f) => !(f in rebuilt.hashes));
        const onlyRebuilt = Object.keys(rebuilt.hashes).filter((f) => !(f in origHashes));
        const changed = origFiles.filter((f) => f in rebuilt.hashes && origHashes[f] !== rebuilt.hashes[f]);
        const ok = onlySource.length === 0 && onlyRebuilt.length === 0 && changed.length === 0;
        report.rebuildChecks.push({
          runId,
          sourceFolder: item.sourceFolder,
          files: origFiles.length,
          passed: ok,
          onlySource: onlySource.slice(0, 10),
          onlyRebuilt: onlyRebuilt.slice(0, 10),
          changed: changed.slice(0, 10),
        });
        if (!ok) report.problems.push(`Rebuild mismatch for ${item.sourceFolder}`);
      } finally {
        await rm(tmpRebuild, { recursive: true, force: true }).catch(() => {});
      }
    }
  }

  report.objectCheck = await verifyObjects(pool, stores, { deep: true });
  if (!report.objectCheck.passed) {
    report.problems.push(...report.objectCheck.problems);
  }

  for (const [tbl, expected] of Object.entries(manifest.sqliteCounts || {})) {
    const actual = report.sqliteParity.imported[tbl];
    if (actual !== expected) {
      report.problems.push(`SQLite count mismatch for ${tbl}: source=${expected}, imported=${actual}`);
    }
  }

  report.passed = report.problems.length === 0;

  const reportDigest = createHash('sha256').update(JSON.stringify(report)).digest('hex');
  await commands.recordCheck({
    actor,
    commandKey: `check-import:${manifest.companySlug}:${reportDigest}`,
    checkKind: 'import',
    passed: report.passed,
    report,
  });

  return report;
}
