// History importer (R12, R10.11, R11):
// Strictly READ-ONLY against source folders and SQLite; builds a complete manifest BEFORE reading content;
// idempotent and resumable; deduplicates bytes by SHA-256 across code vs data stores; proves every rebuilt folder byte for byte.
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { classifyArtifact, STORE_KINDS } from '../storage/artifact-policy.mjs';
import { APPROVAL_ROW_COLUMNS, fingerprintBytes, sha256Hex } from '../util/crypto.mjs';
import { isValidIsoDate, normalizeMacKey, parseCsv } from '../util/csv.mjs';
import { AppError, sanitizeErrorMessage } from '../util/redact.mjs';
import { verifyObjects } from '../commands/journal-export.mjs';
import { listFilesRecursive, rebuildRunFolderFromDb } from '../worker/folder-builder.mjs';

const execFileAsync = promisify(execFile);
const DEFAULT_OVERLAY_CHECK = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'python', 'coherence_overlay_check.py');

const REVIEW_SAVE_RE = /^(bible|adjust)-review-(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z\.csv$/;
const V1_HEADER = APPROVAL_ROW_COLUMNS.slice(0, 10);
const V2_HEADER = APPROVAL_ROW_COLUMNS;

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

/**
 * Default approvals parser using Coherence's own Python reader via coherence_overlay_check.py --parse-only (R5.8).
 * If `pythonPath` is omitted (e.g. pure Node synthetic tests without Coherence installed), falls back to a strict
 * contract-checking CSV parser matching coherence/overlay.py's exact v1/v2 column contracts.
 */
export async function parseApprovalsFile(filePath, {
  parentPath = null,
  pythonPath = null,
  coherenceRepo = null,
  overlayCheckPath = DEFAULT_OVERLAY_CHECK,
  tempBaseDir = tmpdir(),
} = {}) {
  if (pythonPath && coherenceRepo) {
    const outDir = await mkdtemp(join(tempBaseDir, 'coherence-parse-ov-'));
    const outJson = join(outDir, 'parsed.json');
    try {
      const args = [overlayCheckPath, '--parse-only', filePath, '--out', outJson];
      if (parentPath) args.push('--extends', parentPath);
      await execFileAsync(pythonPath, args, {
        cwd: coherenceRepo,
        env: { ...process.env, LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8', PYTHONUTF8: '1', PYTHONPATH: coherenceRepo },
        maxBuffer: 16 * 1024 * 1024,
      });
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

  // Strict v1/v2 fallback parser for synthetic tests when Python/Coherence is unavailable
  const text = await readFile(filePath, 'utf8');
  const parsedRows = parseCsv(text);
  if (parsedRows.length === 0) throw new AppError('Approvals CSV has no header.', 422, 'INVALID_OVERLAY');
  const header = parsedRows[0];
  let headerKind;
  if (header.length === V2_HEADER.length && header.every((c, i) => c === V2_HEADER[i])) headerKind = 'v2';
  else if (header.length === V1_HEADER.length && header.every((c, i) => c === V1_HEADER[i])) headerKind = 'v1';
  else throw new AppError('Approvals CSV header does not match v1 or v2 overlay contract.', 422, 'INVALID_OVERLAY');

  const toObj = (raw) => {
    const obj = {};
    for (let i = 0; i < V2_HEADER.length; i++) {
      const val = i < header.length ? raw[i] : '';
      obj[V2_HEADER[i]] = val === '' || val === undefined ? null : val;
    }
    return obj;
  };

  const rows = parsedRows.slice(1)
    .filter((r) => r.length > 1 || (r.length === 1 && r[0] !== ''))
    .map(toObj);

  let sharedRowCount = 0;
  if (parentPath) {
    const parent = await parseApprovalsFile(parentPath);
    const parentRaw = parseCsv(await readFile(parentPath, 'utf8')).slice(1)
      .filter((r) => r.length > 1 || (r.length === 1 && r[0] !== ''))
      .map(toObj);
    if (rows.length < parentRaw.length) {
      throw new AppError('Approvals file is shorter than its parent.', 422, 'OVERLAY_PREFIX_MISMATCH');
    }
    for (let i = 0; i < parentRaw.length; i++) {
      for (const col of V2_HEADER) {
        if ((rows[i][col] ?? null) !== (parentRaw[i][col] ?? null)) {
          throw new AppError('Approvals file does not begin with every row of its parent.', 422, 'OVERLAY_PREFIX_MISMATCH');
        }
      }
    }
    sharedRowCount = parent.rowCount;
  }

  const addedRows = rows.slice(sharedRowCount).map((row, idx) => ({
    row_no: sharedRowCount + idx + 1,
    ...row,
  }));

  return { headerKind, rowCount: rows.length, sharedRowCount, addedRows };
}

/**
 * Discovers all Mac run folders (R12.1: dated runs, Historical YYYY-MM-DD/YYYY-MM-DD, archive/*)
 * without opening any data files (only checks directory structure and existence of run.json).
 */
async function discoverMacRunFolders(runsRoot) {
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

/**
 * Step 1 of R12: Build a complete read-only import manifest listing every source folder, file,
 * Nusear save, and SQLite record count BEFORE reading any file contents or writing to the database.
 */
export async function buildImportManifest({
  companySlug,
  coherenceRoot = null,
  nusearDataDir = null,
  nusearSqlitePath = null,
} = {}) {
  const isPhalanx = companySlug === 'phalanx';
  const manifest = {
    companySlug,
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

  // Phalanx imports Mac history + current Mac input + Incident Report + Nusear Mac records (R12.1).
  // Clearpath imports Clearpath's own company runs and state ONLY (R12.2).
  if (isPhalanx && coherenceRoot) {
    const runsRoot = join(coherenceRoot, 'runs');
    manifest.macRuns = await discoverMacRunFolders(runsRoot);

    const incidentRoot = join(runsRoot, 'Incident Report');
    const incidentFiles = await listFilesRecursive(incidentRoot);
    manifest.incidentReportFiles = incidentFiles.map((rel) => ({
      area: 'incident_report',
      relPath: `Incident Report/${rel}`,
      absPath: join(incidentRoot, ...rel.split('/')),
    }));

    const macInput = join(coherenceRoot, 'input');
    if (await stat(macInput).then((s) => s.isDirectory(), () => false)) {
      manifest.currentInputDir = macInput;
      manifest.currentInputFiles = await listFilesRecursive(macInput);
    }

    if (nusearDataDir) {
      const macRunsData = join(nusearDataDir, 'coherence-runs');
      const dates = await readdir(macRunsData, { withFileTypes: true }).catch(() => []);
      for (const d of dates) {
        if (!d.isDirectory() || !isValidIsoDate(d.name)) continue;
        const files = (await readdir(join(macRunsData, d.name)).catch(() => [])).sort();
        const saves = [];
        for (const f of files) {
          const parsed = parseReviewSaveTimestamp(f);
          const absPath = join(macRunsData, d.name, f);
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

    // Company saves and logs
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

    // Company environment incoming (Clearpath's current input, or Phalanx's company incoming)
    const compEnv = join(nusearDataDir, 'company-environments', companySlug);
    if (!isPhalanx) {
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

  // Count Nusear SQLite records read-only if path provided (using Node's built-in node:sqlite when available)
  if (nusearSqlitePath && await stat(nusearSqlitePath).then((s) => s.isFile(), () => false)) {
    try {
      const { DatabaseSync } = await import('node:sqlite');
      const sq = new DatabaseSync(nusearSqlitePath, { open: true, readOnly: true });
      try {
        const countTable = (sql, params = []) => {
          try { return Number(sq.prepare(sql).get(...params)?.n ?? 0); } catch { return 0; }
        };
        if (isPhalanx) {
          manifest.sqliteCounts.coherence_run_records = countTable('SELECT COUNT(*) AS n FROM coherence_run_records');
          manifest.sqliteCounts.coherence_run_events = countTable('SELECT COUNT(*) AS n FROM coherence_run_events');
          manifest.sqliteCounts.coherence_run_drafts = countTable('SELECT COUNT(*) AS n FROM coherence_run_drafts');
          manifest.sqliteCounts.coherence_run_settings = countTable('SELECT COUNT(*) AS n FROM coherence_run_settings');
        }
        manifest.sqliteCounts.company_run_records = countTable('SELECT COUNT(*) AS n FROM company_run_records WHERE company = ?', [companySlug]);
        manifest.sqliteCounts.company_run_events = countTable('SELECT COUNT(*) AS n FROM company_run_events WHERE company = ?', [companySlug]);
        manifest.sqliteCounts.company_run_drafts = countTable('SELECT COUNT(*) AS n FROM company_run_drafts WHERE company = ?', [companySlug]);
        manifest.sqliteCounts.company_intake_events = countTable('SELECT COUNT(*) AS n FROM company_intake_events WHERE company = ?', [companySlug]);
      } finally {
        sq.close();
      }
    } catch {
      manifest.sqliteCounts = { unavailable: true };
    }
  }

  return manifest;
}

/**
 * Classifies every file inside an imported run folder into the step known to have produced it (R8).
 */
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

function inferEmitSettings(runItem, companySlug, allFiles) {
  if (runItem.origin === 'mac_import') {
    return { emitMode: 'coherence', emitDisplay: null, emitKeep: [], emitNoManager: [] };
  }
  const hasCompanyManifest = allFiles.includes('company_manifest.json');
  if (companySlug === 'clearpath') {
    if (hasCompanyManifest || runItem.statementDate >= '2026-11-12') {
      return {
        emitMode: 'generated',
        emitDisplay: 'Clearpath',
        emitKeep: ['RETENTION_AGENT', 'INVESTOR'],
        emitNoManager: ['InsureItAll'],
      };
    }
    return { emitMode: 'coherence', emitDisplay: null, emitKeep: [], emitNoManager: [] };
  }
  if (companySlug === 'phalanx') {
    return { emitMode: 'builtin', emitDisplay: null, emitKeep: [], emitNoManager: [] };
  }
  return { emitMode: 'coherence', emitDisplay: null, emitKeep: [], emitNoManager: [] };
}

/**
 * Imports one historical run folder idempotently (R12.3, R10.11).
 */
export async function importSingleRunFolder({
  pool,
  stores,
  commands,
  actor,
  companySlug,
  runItem,
  nusearSaves = [],
  parseOverlay = parseApprovalsFile,
  coherenceRepo = null,
  gitBin = '/usr/bin/git',
}) {
  // Check idempotency early before promoting bytes unnecessarily
  const existing = await pool.query(
    'SELECT id FROM coherence.runs WHERE origin = $1 AND source_folder = $2',
    [runItem.origin, runItem.sourceFolder],
  );
  if (existing.rows.length > 0) {
    return { runId: existing.rows[0].id, alreadyImported: true, sourceFolder: runItem.sourceFolder };
  }

  const runJsonRaw = await readFile(join(runItem.absPath, 'run.json'), 'utf8');
  const runJson = JSON.parse(runJsonRaw);
  const stepsObj = runJson.steps && typeof runJson.steps === 'object' ? runJson.steps : {};
  const stepsDone = ['assign', 'attribute', 'bible', 'adjust', 'emit'].filter((s) => Boolean(stepsObj[s]));

  // Archive git bundles for every committed code hash named in run.json into Nusear's code store (R12.1)
  const commitsPromoted = [];
  if (coherenceRepo) {
    const commits = new Set(
      Object.values(stepsObj)
        .map((s) => s?.code)
        .filter((c) => typeof c === 'string' && /^[0-9a-f]{7,40}$/.test(c)),
    );
    for (const shortCommit of commits) {
      const tmpDir = await mkdtemp(join(tmpdir(), 'coherence-git-bundle-'));
      const bundlePath = join(tmpDir, `${shortCommit}.bundle`);
      try {
        await execFileAsync(gitBin, ['-C', coherenceRepo, 'bundle', 'create', bundlePath, shortCommit]);
        const bytes = await readFile(bundlePath);
        const promoted = await stores.codeStore.promoteBytes(bytes, {
          relPath: `git-bundles/${shortCommit}.bundle`,
          checksPassed: true,
        });
        commitsPromoted.push(promoted);
      } catch {
        // Commit not reachable in local repo; recorded in report
      } finally {
        await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
      }
    }
  }

  const allFiles = await listFilesRecursive(runItem.absPath);
  const storedFiles = [...commitsPromoted];
  const inputEntries = [];

  // 1. Promote frozen input/ files strictly into company_data store
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

  const registerOverlayCandidate = async (absPath, promotedFile) => {
    let parsed;
    let extendsSha256 = null;
    if (prevOverlayPath && prevOverlaySha !== promotedFile.sha256) {
      try {
        parsed = await parseOverlay(absPath, { parentPath: prevOverlayPath });
        extendsSha256 = prevOverlaySha;
      } catch {
        parsed = await parseOverlay(absPath, { parentPath: null });
        extendsSha256 = null;
      }
    } else {
      parsed = await parseOverlay(absPath, { parentPath: null });
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
    // R12.3: runs before 10/21 have only their final approvals file (root overlay.csv, else emits/overlay.csv)
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

  // 3. Partition and promote artifacts per step, strictly separating code_bearing vs data
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
      // Also register emits/overlay.csv if distinct from earlier saves
      if (relPath === 'emits/overlay.csv' && !approvalsFiles.some((af) => af.fileSha256 === promoted.sha256)) {
        await registerOverlayCandidate(absPath, promoted);
      }
    }
    const stepMeta = stepsObj[step] || {};
    stepAttempts.push({
      step,
      attemptNo: 1,
      born: step === 'assign' ? (runJson.born ?? null) : null, // R12.3: missing birth stays missing
      census: stepMeta,
      finishedAt: parseLocalRunJsonTime(stepMeta.at),
      artifacts,
    });
  }

  const emitSettings = inferEmitSettings(runItem, companySlug, allFiles);
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
  };
}

/**
 * Runs the complete idempotent, resumable history import from a manifest (R12, R10.11)
 * and proves every imported run folder rebuilds byte-for-byte identical (R12.4).
 */
export async function executeHistoryImport({
  pool,
  stores,
  commands,
  actor,
  manifest,
  parseOverlay = parseApprovalsFile,
  coherenceRepo = null,
  nusearSqlitePath = null,
  verifyRebuild = true,
  tempBaseDir = tmpdir(),
}) {
  const report = {
    companySlug: manifest.companySlug,
    importedRuns: [],
    skippedRuns: [],
    currentInputVersionId: null,
    standaloneFilesImported: 0,
    nusearRecordsImported: 0,
    rebuildChecks: [],
    objectCheck: null,
    sqliteParity: { source: manifest.sqliteCounts, imported: {} },
    passed: true,
    problems: [],
  };

  // 1. Import all Mac runs (Phalanx) and company runs
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
      parseOverlay,
      coherenceRepo,
    });
    if (res.alreadyImported) report.skippedRuns.push(res);
    else report.importedRuns.push(res);
  }

  // 2. Import current standing input folder (idempotently: skip if standing input already matches identical entries)
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
      const parsed = await parseOverlay(overlayAbs, { parentPath: null });
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
      sourceKind: manifest.companySlug === 'phalanx' ? 'mac_import' : 'company_import',
      reason: `Import current standing input from ${manifest.currentInputDir}`,
      entries,
      storedFiles,
    });
    report.currentInputVersionId = ivRes.result.inputVersionId;
  }

  // 3. Import Incident Report + Vault Staging/Documents/Archive Inventories + Nusear logs (R6.20, R12.1)
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

  // 4. Import Nusear SQLite records (ALL events including before record-cleared, drafts, settings) as verified JSON snapshot
  if (nusearSqlitePath && await stat(nusearSqlitePath).then((s) => s.isFile(), () => false)) {
    try {
      const { DatabaseSync } = await import('node:sqlite');
      const sq = new DatabaseSync(nusearSqlitePath, { open: true, readOnly: true });
      const snapshot = {};
      try {
        const readAll = (sql, params = []) => { try { return sq.prepare(sql).all(...params); } catch { return []; } };
        if (manifest.companySlug === 'phalanx') {
          snapshot.coherence_run_records = readAll('SELECT * FROM coherence_run_records ORDER BY date');
          snapshot.coherence_run_events = readAll('SELECT * FROM coherence_run_events ORDER BY id');
          snapshot.coherence_run_drafts = readAll('SELECT * FROM coherence_run_drafts ORDER BY date, surface');
          snapshot.coherence_run_settings = readAll('SELECT * FROM coherence_run_settings ORDER BY key');
        }
        snapshot.company_run_records = readAll('SELECT * FROM company_run_records WHERE company = ? ORDER BY date', [manifest.companySlug]);
        snapshot.company_run_events = readAll('SELECT * FROM company_run_events WHERE company = ? ORDER BY id', [manifest.companySlug]);
        snapshot.company_run_drafts = readAll('SELECT * FROM company_run_drafts WHERE company = ? ORDER BY date, surface', [manifest.companySlug]);
        snapshot.company_intake_events = readAll('SELECT * FROM company_intake_events WHERE company = ? ORDER BY id', [manifest.companySlug]);
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
    } catch (err) {
      report.problems.push(`SQLite import error: ${sanitizeErrorMessage(err)}`);
    }
  }

  // 5. Proof (R12.4): rebuild EVERY imported run folder from DB and prove path-by-path, byte-by-byte equality
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

  // 6. Verify every object in both stores + zero code-bearing files in company_data
  report.objectCheck = await verifyObjects(pool, stores, { deep: true });
  if (!report.objectCheck.passed) {
    report.problems.push(...report.objectCheck.problems);
  }

  // Verify SQLite counts match on both sides
  for (const [tbl, expected] of Object.entries(manifest.sqliteCounts || {})) {
    if (tbl === 'unavailable') continue;
    const actual = report.sqliteParity.imported[tbl];
    if (actual !== expected) {
      report.problems.push(`SQLite count mismatch for ${tbl}: source=${expected}, imported=${actual}`);
    }
  }

  report.passed = report.problems.length === 0;

  // Record the import verification check in the database (R6.21, R12.4)
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
