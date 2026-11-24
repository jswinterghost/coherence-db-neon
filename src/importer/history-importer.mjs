// Read-only, manifest-first, config-driven, idempotent history importer:
// imports historical overlays into prefix-chained decision records (strictly through Coherence's Python reader),
// archives all company/legacy sources with full-buffer code-versus-data separation,
// imports pre-Coherence sent dates and method corrections into statement_batches,
// preserves company-run sent provenance, and verifies byte-for-byte Layer 1 rebuild.
import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  formatOverlayCsvFromRows,
  OVERLAY_V2_COLUMNS,
} from '../decisions/overlay-generator.mjs';
import { STORE_KINDS } from '../storage/artifact-policy.mjs';
import { canonicalJson, fingerprintBytes, formatTimestampUtcUs, sha256Hex } from '../util/crypto.mjs';
import { isValidIsoDate, normalizeMacKey, parseCsv } from '../util/csv.mjs';
import { AppError, sanitizeErrorMessage } from '../util/redact.mjs';
import { verifyObjects } from '../commands/journal-export.mjs';
import { hashDecisions } from '../commands/commitments.mjs';
import { parseCents } from '../worker/emit-materializer.mjs';
import { listFilesRecursive, materializeInputEntries, rebuildRunFolderFromDb } from '../worker/folder-builder.mjs';

const execFileAsync = promisify(execFile);
const DEFAULT_OVERLAY_CHECK = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'python', 'coherence_overlay_check.py');
const DEFAULT_LEGACY_STATEMENTS_BRIDGE = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'python', 'coherence_legacy_statements.py');

const REVIEW_SAVE_RE = /^(bible|adjust)-review-(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z\.csv$/;
const ANSWER_KEY_RE = /^answer-key-.*\.json$/i;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const FIRST_DIFF_ROW_RE = /first differing row:\s*(\d+)/i;

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
  const normalized = text.trim().replace(/(\.\d{3})\d+/, '$1');
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function parseTimestampMs(text) {
  if (!text || typeof text !== 'string') return null;
  const normalized = text.trim().replace(/(\.\d{3})\d+/, '$1');
  const ms = Date.parse(normalized);
  return Number.isNaN(ms) ? null : ms;
}

async function readRunRecordedStartMs(runAbsPath) {
  try {
    const raw = await readFile(join(runAbsPath, 'run.json'), 'utf8');
    const parsed = JSON.parse(raw);
    const candidates = [];
    const bornMs = parseTimestampMs(parsed?.born);
    if (bornMs != null) candidates.push(bornMs);
    if (parsed?.steps && typeof parsed.steps === 'object') {
      for (const meta of Object.values(parsed.steps)) {
        const stepMs = parseTimestampMs(meta?.at);
        if (stepMs != null) candidates.push(stepMs);
      }
    }
    return candidates.length > 0 ? Math.min(...candidates) : null;
  } catch {
    return null;
  }
}

function isDraftOrArchiveRun(runItem) {
  if (runItem.abandoned) return true;
  if (runItem.origin === 'mac_import' && runItem.sourceFolder !== runItem.statementDate) return true;
  if (/(^|\/)(archive|draft|drafts|provisional|abandoned)(\/|$)/i.test(runItem.sourceFolder || '')) return true;
  return false;
}

function normalizeOverlayRow(row) {
  const out = {};
  for (const col of OVERLAY_V2_COLUMNS) {
    const val = row?.[col];
    out[col] = val == null || val === '' ? null : String(val);
  }
  return out;
}

function rowSignature(row) {
  const norm = normalizeOverlayRow(row);
  return canonicalJson(OVERLAY_V2_COLUMNS.map((c) => norm[c]));
}

function resolveMaybeRelative(baseDir, value) {
  if (!value || typeof value !== 'string') return null;
  return isAbsolute(value) ? value : resolve(baseDir, value);
}

function makeHashedCommandKey(prefix, parts) {
  return `${prefix}:${sha256Hex(canonicalJson(parts))}`;
}

function safeOverlayCheckpointRelPath(label, absPath) {
  const cleaned = String(label || '').replace(/^\/+/, '').replace(/\/+/g, '/').replace(/\/+$/, '');
  if (cleaned && !/(^|\/)\.\.?($|\/)/.test(cleaned) && !cleaned.includes('\\') && !/[\x01-\x1f\x7f]/.test(cleaned)) {
    return `overlay-checkpoints/${cleaned}`;
  }
  const base = basename(absPath || 'overlay.csv').replace(/[^A-Za-z0-9._-]/g, '_') || 'overlay.csv';
  return `overlay-checkpoints/${sha256Hex(String(label || absPath)).slice(0, 16)}/${base}`;
}

function validatePinnedSourceFolder(sourceFolder, configKey) {
  if (typeof sourceFolder !== 'string' || sourceFolder.length === 0 || sourceFolder !== sourceFolder.trim()) {
    throw new AppError(
      `Each ${configKey} entry must declare a non-empty trimmed sourceFolder string.`,
      400,
      'INVALID_IMPORT_CONFIG',
    );
  }
  if (
    sourceFolder.startsWith('/')
    || sourceFolder.endsWith('/')
    || sourceFolder.includes('\\')
    || sourceFolder.includes('//')
    || /[\x01-\x1f\x7f*?]/.test(sourceFolder)
    || sourceFolder.split('/').some((seg) => !seg || seg === '.' || seg === '..')
  ) {
    throw new AppError(
      `Invalid sourceFolder in ${configKey}: ${sourceFolder}`,
      400,
      'INVALID_IMPORT_CONFIG',
    );
  }
  const lowerSf = sourceFolder.toLowerCase();
  if (
    lowerSf === 'standing_input'
    || lowerSf === 'standing-overlay'
    || lowerSf === 'input/overlay'
    || lowerSf === 'input/overlay/overlay.csv'
    || lowerSf.startsWith('standing-overlay/')
  ) {
    throw new AppError(
      `${configKey} cannot include the standing overlay: ${sourceFolder}`,
      400,
      'INVALID_IMPORT_CONFIG',
    );
  }
}

function normalizeFreshOverlayRoots(raw) {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    throw new AppError(
      'importConfig.freshOverlayRoots must be an array of { sourceFolder, sha256 } entries.',
      400,
      'INVALID_IMPORT_CONFIG',
    );
  }
  const byFolder = new Map();
  const out = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new AppError(
        'Each entry in importConfig.freshOverlayRoots must be an object with { sourceFolder, sha256 }.',
        400,
        'INVALID_IMPORT_CONFIG',
      );
    }
    const { sourceFolder, sha256 } = item;
    validatePinnedSourceFolder(sourceFolder, 'importConfig.freshOverlayRoots');
    if (typeof sha256 !== 'string' || !SHA256_HEX_RE.test(sha256)) {
      throw new AppError(
        `Invalid sha256 in importConfig.freshOverlayRoots for ${sourceFolder}: must be a 64-character lowercase hex SHA-256 digest.`,
        400,
        'INVALID_IMPORT_CONFIG',
      );
    }
    if (byFolder.has(sourceFolder)) {
      if (byFolder.get(sourceFolder) !== sha256) {
        throw new AppError(
          `Conflicting sha256 entries in importConfig.freshOverlayRoots for ${sourceFolder}.`,
          400,
          'INVALID_IMPORT_CONFIG',
        );
      }
      continue;
    }
    byFolder.set(sourceFolder, sha256);
    out.push({ sourceFolder, sha256 });
  }
  return out;
}

function findPinnedFreshOverlayRoot(sourceFolder, freshOverlayRoots) {
  if (!sourceFolder || !Array.isArray(freshOverlayRoots) || freshOverlayRoots.length === 0) return null;
  const sf = String(sourceFolder);
  for (const entry of freshOverlayRoots) {
    if (entry.sourceFolder === sf) return entry;
  }
  return null;
}

function normalizeCarriedPriors(raw) {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    throw new AppError(
      'importConfig.carriedPriors must be an array of { sourceFolder, sha256, extendsRowCount, reason? } entries.',
      400,
      'INVALID_IMPORT_CONFIG',
    );
  }
  const byFolder = new Map();
  const out = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new AppError(
        'Each entry in importConfig.carriedPriors must be an object with { sourceFolder, sha256, extendsRowCount, reason? }.',
        400,
        'INVALID_IMPORT_CONFIG',
      );
    }
    const { sourceFolder, sha256, extendsRowCount, reason } = item;
    validatePinnedSourceFolder(sourceFolder, 'importConfig.carriedPriors');
    if (reason !== undefined && reason !== null && (typeof reason !== 'string' || !reason.trim() || reason.length > 600 || /[\x00-\x1f\x7f]/.test(reason))) {
      throw new AppError(
        `Invalid reason in importConfig.carriedPriors for ${sourceFolder}: when given, a reason is one non-empty line of at most 600 characters saying why the reference keeps this prior.`,
        400,
        'INVALID_IMPORT_CONFIG',
      );
    }
    if (typeof sha256 !== 'string' || !SHA256_HEX_RE.test(sha256)) {
      throw new AppError(
        `Invalid sha256 in importConfig.carriedPriors for ${sourceFolder}: must be a 64-character lowercase hex SHA-256 digest.`,
        400,
        'INVALID_IMPORT_CONFIG',
      );
    }
    if (!Number.isInteger(extendsRowCount) || extendsRowCount <= 0) {
      throw new AppError(
        `Invalid extendsRowCount in importConfig.carriedPriors for ${sourceFolder}: must be a positive integer.`,
        400,
        'INVALID_IMPORT_CONFIG',
      );
    }
    if (byFolder.has(sourceFolder)) {
      const prev = byFolder.get(sourceFolder);
      if (prev.sha256 !== sha256 || prev.extendsRowCount !== extendsRowCount || prev.reason !== (reason ?? null)) {
        throw new AppError(
          `Conflicting entries in importConfig.carriedPriors for ${sourceFolder}.`,
          400,
          'INVALID_IMPORT_CONFIG',
        );
      }
      continue;
    }
    const entry = { sourceFolder, sha256, extendsRowCount, reason: reason ?? null };
    byFolder.set(sourceFolder, entry);
    out.push(entry);
  }
  return out;
}

function findPinnedCarriedPrior(sourceFolder, carriedPriors) {
  if (!sourceFolder || !Array.isArray(carriedPriors) || carriedPriors.length === 0) return null;
  const sf = String(sourceFolder);
  for (const entry of carriedPriors) {
    if (entry.sourceFolder === sf) return entry;
  }
  return null;
}

function normalizeImportConfig(importConfig = {}) {
  if (importConfig.allowDisjointOverlayRoots) {
    throw new AppError(
      'importConfig.allowDisjointOverlayRoots cannot be true; pin explicit fresh starts with { sourceFolder, sha256 } in importConfig.freshOverlayRoots instead.',
      400,
      'DISJOINT_OVERLAY_ROOTS_FORBIDDEN',
    );
  }
  if (importConfig.allowedDisjointOverlaySourceFolders !== undefined) {
    throw new AppError(
      'importConfig.allowedDisjointOverlaySourceFolders has been removed; pin explicit fresh starts with { sourceFolder, sha256 } in importConfig.freshOverlayRoots instead.',
      400,
      'INVALID_IMPORT_CONFIG',
    );
  }
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
    allowedMissingCommits: Array.isArray(importConfig.allowedMissingCommits) ? [...importConfig.allowedMissingCommits] : [],
    allowDisjointOverlayRoots: false,
    freshOverlayRoots: normalizeFreshOverlayRoots(importConfig.freshOverlayRoots),
    carriedPriors: normalizeCarriedPriors(importConfig.carriedPriors),
    companySentRecords: importConfig.companySentRecords && typeof importConfig.companySentRecords === 'object'
      ? { ...importConfig.companySentRecords }
      : {},
    legacyStatementConfig: importConfig.legacyStatementConfig && typeof importConfig.legacyStatementConfig === 'object'
      ? { ...importConfig.legacyStatementConfig }
      : null,
  };
}

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
  includeAnswers = false,
  bibleKeys = null,
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
    if (includeAnswers) args.push('--answers');
    if (Array.isArray(bibleKeys)) {
      const keysPath = join(outDir, 'bible-keys.json');
      await writeFile(keysPath, JSON.stringify(bibleKeys), 'utf8');
      args.push('--bible-keys-file', keysPath);
    }
    try {
      await execFileAsync(pythonPath, args, {
        cwd: coherenceRepo,
        env: {
          ...process.env,
          LANG: 'en_US.UTF-8',
          LC_ALL: 'en_US.UTF-8',
          PYTHONUTF8: '1',
          PYTHONDONTWRITEBYTECODE: '1',
          PYTHONPATH: coherenceRepo,
        },
        maxBuffer: 64 * 1024 * 1024,
      });
    } catch (err) {
      const stderrText = String(err?.stderr || '');
      if (/does not begin with/i.test(stderrText)) {
        const rowMatch = FIRST_DIFF_ROW_RE.exec(stderrText);
        const firstDifferingRow = rowMatch ? Number.parseInt(rowMatch[1], 10) : 1;
        const appErr = new AppError(
          `Approvals file does not begin with every row of its parent (first differing row: ${firstDifferingRow}).`,
          422,
          'OVERLAY_PREFIX_MISMATCH',
        );
        appErr.firstDifferingRow = firstDifferingRow;
        throw appErr;
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
      ...(data.current_by_key ? { currentByKey: data.current_by_key } : {}),
      ...(data.bible_answers_by_key ? { bibleAnswersByKey: data.bible_answers_by_key } : {}),
    };
  } finally {
    await rm(outDir, { recursive: true, force: true }).catch(() => {});
  }
}

function validateMethodCorrectionSpecs(methodCorrections) {
  if (!Array.isArray(methodCorrections)) return;
  for (const corr of methodCorrections) {
    const label = `${corr?.statementDate || 'unknown'} (${corr?.kind || 'unknown'})`;
    if (!Number.isInteger(corr?.expectedAgencyNetCents) || !Number.isInteger(corr?.expectedUplineNetCents)) {
      throw new AppError(
        `Method correction ${label} must state integer expectedAgencyNetCents and expectedUplineNetCents.`,
        400,
        'METHOD_CORRECTION_EXPECTED_TOTALS_REQUIRED',
      );
    }
  }
}

function verifyMethodCorrectionBatches(specs, batches) {
  const specList = Array.isArray(specs) ? specs : [];
  const batchList = Array.isArray(batches) ? batches : [];
  if (specList.length !== batchList.length) {
    throw new AppError(
      `Method correction batch count mismatch: expected ${specList.length}, actual ${batchList.length}.`,
      422,
      'METHOD_CORRECTION_TOTAL_MISMATCH',
    );
  }
  const sumLinesCents = (lines) => {
    let total = 0n;
    for (const l of (lines || [])) {
      const c = parseCents(l?.amount);
      if (c == null) {
        throw new AppError('Method correction line has missing or unparseable amount.', 422, 'METHOD_CORRECTION_INVALID_AMOUNT');
      }
      total += c;
    }
    return Number(total);
  };
  for (let i = 0; i < specList.length; i++) {
    const spec = specList[i];
    const batch = batchList[i];
    const label = `${spec.statementDate} (${spec.kind})`;
    const expAg = spec.expectedAgencyNetCents;
    const expUp = spec.expectedUplineNetCents;
    const actAg = sumLinesCents(batch?.agencyLines);
    const actUp = sumLinesCents(batch?.uplineLines);
    if (actAg !== expAg && actUp !== expUp) {
      throw new AppError(
        `Method correction ${label} net total mismatch: agency expected ${expAg} cents vs ${actAg} cents; upline expected ${expUp} cents vs ${actUp} cents.`,
        422,
        'METHOD_CORRECTION_TOTAL_MISMATCH',
      );
    }
    if (actAg !== expAg) {
      throw new AppError(
        `Method correction ${label} agency total mismatch: expected ${expAg} cents, actual ${actAg} cents.`,
        422,
        'METHOD_CORRECTION_TOTAL_MISMATCH',
      );
    }
    if (actUp !== expUp) {
      throw new AppError(
        `Method correction ${label} upline total mismatch: expected ${expUp} cents, actual ${actUp} cents.`,
        422,
        'METHOD_CORRECTION_TOTAL_MISMATCH',
      );
    }
  }
}

/**
 * Calls the small Python bridge (python/coherence_legacy_statements.py) that delegates strictly to
 * Coherence's own legacy statement reader and returns normalized historical_sent and method_correction batches.
 */
export async function readLegacyStatementBatches({
  statementsDir,
  pythonPath,
  coherenceRepo,
  bridgePath = DEFAULT_LEGACY_STATEMENTS_BRIDGE,
  sentDir = null,
  agentsCsvPath = null,
  methodCorrections = [],
  tempBaseDir = tmpdir(),
} = {}) {
  if (!pythonPath || !coherenceRepo) {
    throw new AppError(
      'Reading pre-Coherence statement batches requires pythonPath and coherenceRepo so only Coherence parses legacy statements.',
      400,
      'LEGACY_READER_CONFIG_REQUIRED',
    );
  }
  validateMethodCorrectionSpecs(methodCorrections);
  const outDir = await mkdtemp(join(tempBaseDir, 'coherence-legacy-stmt-'));
  const outJson = join(outDir, 'batches.json');
  const specPath = join(outDir, 'spec.json');
  try {
    await writeFile(specPath, JSON.stringify({
      statementsDir,
      sentDir: sentDir || null,
      agentsCsvPath: agentsCsvPath || null,
      methodCorrections: Array.isArray(methodCorrections) ? methodCorrections : [],
    }), 'utf8');
    try {
      await execFileAsync(pythonPath, [bridgePath, '--spec', specPath, '--out', outJson], {
        cwd: coherenceRepo,
        env: {
          ...process.env,
          LANG: 'en_US.UTF-8',
          LC_ALL: 'en_US.UTF-8',
          PYTHONUTF8: '1',
          PYTHONDONTWRITEBYTECODE: '1',
          PYTHONPATH: coherenceRepo,
        },
        maxBuffer: 64 * 1024 * 1024,
      });
    } catch (err) {
      const stderrText = String(err?.stderr || '');
      throw new AppError(
        `Legacy statement reader bridge failed: ${sanitizeErrorMessage(stderrText || err, 'Legacy statement reader exited non-zero.')}`,
        422,
        'LEGACY_STATEMENT_READ_FAILED',
      );
    }
    const parsed = JSON.parse(await readFile(outJson, 'utf8'));
    verifyMethodCorrectionBatches(methodCorrections, parsed.methodCorrectionBatches);
    return parsed;
  } finally {
    await rm(outDir, { recursive: true, force: true }).catch(() => {});
  }
}

async function isDir(path) {
  return stat(path).then((s) => s.isDirectory(), () => false);
}

async function isFile(path) {
  return stat(path).then((s) => s.isFile(), () => false);
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
      const hasRunJson = await isFile(join(full, 'run.json'));
      if (hasRunJson && isValidIsoDate(entry.name)) {
        found.push({
          origin: 'mac_import',
          statementDate: entry.name,
          sourceFolder: relative(runsRoot, full).split(sep).join('/'),
          absPath: full,
          abandoned: false,
        });
      } else {
        await scanDir(full, depth + 1);
      }
    }
  };
  await scanDir(runsRoot);
  return found.sort((a, b) => a.statementDate.localeCompare(b.statementDate) || a.sourceFolder.localeCompare(b.sourceFolder));
}

async function discoverCompanyRunFolders(companyWsDir, companySlug, sourcePrefix = null) {
  const found = [];
  const prefix = sourcePrefix || `company-workspaces/${companySlug}`;
  const entries = await readdir(companyWsDir, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    if (!entry.isDirectory() || !isValidIsoDate(entry.name)) continue;
    const nestedRunPath = join(companyWsDir, entry.name, 'runs', entry.name);
    const directRunPath = join(companyWsDir, entry.name);
    if (await isFile(join(nestedRunPath, 'run.json'))) {
      found.push({
        origin: 'company_import',
        statementDate: entry.name,
        sourceFolder: `${prefix}/${entry.name}/runs/${entry.name}`,
        absPath: nestedRunPath,
        abandoned: false,
      });
    } else if (await isFile(join(directRunPath, 'run.json'))) {
      found.push({
        origin: 'company_import',
        statementDate: entry.name,
        sourceFolder: `${prefix}/${entry.name}`,
        absPath: directRunPath,
        abandoned: false,
      });
    }
  }
  return found.sort((a, b) => a.statementDate.localeCompare(b.statementDate) || a.sourceFolder.localeCompare(b.sourceFolder));
}

async function discoverAbandonedCompanyRuns(abandonedDir, companySlug) {
  const runs = [];
  const standaloneFiles = [];
  const coveredRoots = [];
  if (!(await isDir(abandonedDir))) return { runs, standaloneFiles };

  const scan = async (dir, depth = 0) => {
    if (depth > 5) return;
    const hasRunJson = await isFile(join(dir, 'run.json'));
    if (hasRunJson && dir !== abandonedDir) {
      let statementDate = null;
      const base = relative(abandonedDir, dir).split(sep).join('/');
      const dateMatch = /(\d{4}-\d{2}-\d{2})/.exec(base);
      if (dateMatch && isValidIsoDate(dateMatch[1])) {
        statementDate = dateMatch[1];
      } else {
        try {
          const parsed = JSON.parse(await readFile(join(dir, 'run.json'), 'utf8'));
          if (isValidIsoDate(parsed?.date)) statementDate = parsed.date;
        } catch {}
      }
      if (statementDate) {
        runs.push({
          origin: 'company_import',
          statementDate,
          sourceFolder: `company-abandoned/${companySlug}/${base}`,
          absPath: dir,
          abandoned: true,
        });
        coveredRoots.push(base);
        return;
      }
    }
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (entry.isDirectory()) {
        await scan(join(dir, entry.name), depth + 1);
      }
    }
  };
  await scan(abandonedDir, 0);

  const allFiles = await listFilesRecursive(abandonedDir);
  for (const rel of allFiles) {
    const insideRun = coveredRoots.some((root) => rel === root || rel.startsWith(`${root}/`));
    if (!insideRun) {
      standaloneFiles.push({
        area: 'other',
        relPath: `company-abandoned/${companySlug}/${rel}`,
        absPath: join(abandonedDir, ...rel.split('/')),
      });
    }
  }

  runs.sort((a, b) => a.statementDate.localeCompare(b.statementDate) || a.sourceFolder.localeCompare(b.sourceFolder));
  return { runs, standaloneFiles };
}

async function checkSqliteSidecars(sqlitePath) {
  const [hasWal, hasShm] = await Promise.all([
    isFile(`${sqlitePath}-wal`),
    isFile(`${sqlitePath}-shm`),
  ]);
  return { hasWal, hasShm };
}

/**
 * Takes one consistent copy of a legacy SQLite database into a temporary folder via VACUUM INTO
 * (refusing direct opens when -wal or -shm sidecars exist), then reads table counts, all expected
 * tables (4 or 8), and company_run_records sent provenance from that one copy inside one read transaction.
 */
export async function readLegacySqliteSnapshot(sqlitePath, {
  companySlug,
  includeLegacySqliteTables = false,
  tempBaseDir = tmpdir(),
  takeConsistentCopy = true,
} = {}) {
  let info;
  try {
    info = await stat(sqlitePath);
  } catch {
    throw new AppError(`Legacy SQLite database not found at ${sqlitePath}.`, 404, 'SQLITE_NOT_FOUND');
  }
  if (!info.isFile()) {
    throw new AppError(`Legacy SQLite path is not a regular file: ${sqlitePath}.`, 400, 'SQLITE_INVALID_PATH');
  }

  const { hasWal, hasShm } = await checkSqliteSidecars(sqlitePath);
  if (!takeConsistentCopy && (hasWal || hasShm)) {
    throw new AppError(
      'Refusing to open legacy SQLite database directly because a -wal or -shm sidecar exists; take a consistent copy first.',
      409,
      'SQLITE_WAL_SIDECAR_PRESENT',
    );
  }

  let DatabaseSync;
  try {
    ({ DatabaseSync } = await import('node:sqlite'));
  } catch (err) {
    throw new AppError(`node:sqlite is unavailable: ${sanitizeErrorMessage(err)}`, 500, 'SQLITE_UNAVAILABLE');
  }

  let copyDir = null;
  let targetPath = sqlitePath;
  try {
    if (takeConsistentCopy) {
      copyDir = await mkdtemp(join(tempBaseDir, 'coherence-sqlite-copy-'));
      const copyPath = join(copyDir, 'snapshot.sqlite');
      if (copyPath.includes('\u0000')) {
        throw new AppError('Temporary SQLite copy path contains a NUL byte.', 400, 'SQLITE_INVALID_PATH');
      }
      const escapedCopyPath = copyPath.replaceAll("'", "''");
      let srcDb = null;
      try {
        srcDb = new DatabaseSync(sqlitePath, { open: true, readOnly: true });
        srcDb.exec('PRAGMA busy_timeout = 5000');
        srcDb.exec(`VACUUM INTO '${escapedCopyPath}'`);
      } catch (err) {
        throw new AppError(
          `Failed to take consistent copy of legacy SQLite database: ${sanitizeErrorMessage(err)}`,
          500,
          'SQLITE_READ_FAILED',
        );
      } finally {
        if (srcDb) {
          try { srcDb.close(); } catch {}
        }
      }
      targetPath = copyPath;
    }

    let sq = null;
    const counts = {};
    const tables = {};
    const companySentRecords = {};
    let inTx = false;
    try {
      sq = new DatabaseSync(targetPath, { open: true, readOnly: true });
      sq.prepare('SELECT 1 FROM sqlite_master LIMIT 1').get();
      sq.exec('BEGIN DEFERRED');
      inTx = true;

      for (const [tbl, countSql, selectSql, params] of getExpectedSqliteQueries(companySlug, includeLegacySqliteTables)) {
        try {
          const countVal = Number(sq.prepare(countSql).get(...params)?.n ?? 0);
          const rows = sq.prepare(selectSql).all(...params).map((row) => ({ ...row }));
          if (countVal !== rows.length) {
            throw new AppError(
              `Inconsistent SQLite read for table ${tbl}: count=${countVal}, rows=${rows.length}.`,
              500,
              'SQLITE_READ_INCONSISTENT',
            );
          }
          counts[tbl] = countVal;
          tables[tbl] = rows;
        } catch (err) {
          if (err instanceof AppError) throw err;
          throw new AppError(
            `Failed to read legacy SQLite table ${tbl}: ${sanitizeErrorMessage(err)}`,
            500,
            'SQLITE_READ_FAILED',
          );
        }
      }

      for (const r of (tables.company_run_records || [])) {
        const date = r.date ?? r.statement_date;
        if (!isValidIsoDate(date)) continue;
        const isSent = Boolean(r.sent_at || r.sent === 1 || r.sent === true || String(r.status || '').toLowerCase() === 'sent');
        if (isSent && !companySentRecords[date]) {
          companySentRecords[date] = {
            sent: true,
            source: `sqlite:company_run_records:${companySlug}:${date}`,
            recordedAt: r.sent_at ?? r.updated_at ?? null,
            status: r.status ?? 'sent',
          };
        }
      }

      sq.exec('COMMIT');
      inTx = false;
      return { counts, tables, companySentRecords };
    } catch (err) {
      if (sq && inTx) {
        try { sq.exec('ROLLBACK'); } catch {}
      }
      if (err instanceof AppError) throw err;
      throw new AppError(`Failed to read legacy SQLite copy: ${sanitizeErrorMessage(err)}`, 500, 'SQLITE_READ_FAILED');
    } finally {
      if (sq) {
        try { sq.close(); } catch {}
      }
    }
  } finally {
    if (copyDir) {
      await rm(copyDir, { recursive: true, force: true }).catch(() => {});
    }
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

function extractAuditSentRecords(auditData, sourceLabel = 'company-environment/audit.json') {
  const sentByDate = {};
  const recordSent = (date, detail) => {
    if (!isValidIsoDate(date)) return;
    sentByDate[date] = {
      sent: true,
      source: sourceLabel,
      ...detail,
    };
  };

  if (Array.isArray(auditData)) {
    auditData.forEach((ev, idx) => {
      if (!ev || typeof ev !== 'object') return;
      const action = String(ev.action ?? ev.event ?? ev.kind ?? ev.type ?? '').toLowerCase();
      const date = ev.statementDate ?? ev.statement_date ?? ev.date ?? null;
      if (action === 'sent' || action === 'record_sent' || action === 'carry_sent' || ev.sent === true) {
        recordSent(date, {
          recordIndex: idx,
          action: ev.action ?? ev.event ?? ev.kind ?? 'sent',
          recordedAt: ev.at ?? ev.recordedAt ?? ev.recorded_at ?? ev.timestamp ?? null,
          actor: ev.actor ?? ev.by ?? null,
          recordId: ev.id ?? null,
        });
      }
    });
  } else if (auditData && typeof auditData === 'object') {
    if (Array.isArray(auditData.events)) {
      Object.assign(sentByDate, extractAuditSentRecords(auditData.events, sourceLabel));
    }
    if (auditData.runs && typeof auditData.runs === 'object') {
      for (const [date, info] of Object.entries(auditData.runs)) {
        if (info && (info.sent === true || String(info.status || '').toLowerCase() === 'sent' || info.sentAt || info.sent_at)) {
          recordSent(date, {
            action: 'sent',
            recordedAt: info.sentAt ?? info.sent_at ?? info.at ?? null,
            actor: info.sentBy ?? info.actor ?? null,
            sourceDetail: info.source ?? 'runs',
          });
        }
      }
    }
    if (Array.isArray(auditData.sentDates)) {
      for (const item of auditData.sentDates) {
        if (typeof item === 'string') recordSent(item, { action: 'sent' });
        else if (item && typeof item === 'object') {
          recordSent(item.date ?? item.statementDate, {
            action: 'sent',
            recordedAt: item.recordedAt ?? item.at ?? null,
            actor: item.actor ?? null,
          });
        }
      }
    }
  }
  return sentByDate;
}

async function discoverAbandonedRunsMetadataOnly(abandonedDir, companySlug) {
  const runs = [];
  if (!(await isDir(abandonedDir))) return runs;

  const scan = async (dir, depth = 0) => {
    if (depth > 5) return;
    if (dir !== abandonedDir && await isFile(join(dir, 'run.json'))) {
      const base = relative(abandonedDir, dir).split(sep).join('/');
      runs.push({
        origin: 'company_import',
        sourceFolder: `company-abandoned/${companySlug}/${base}`,
        absPath: dir,
        abandoned: true,
      });
      return;
    }
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (entry.isDirectory()) {
        await scan(join(dir, entry.name), depth + 1);
      }
    }
  };
  await scan(abandonedDir, 0);
  return runs.sort((a, b) => a.sourceFolder.localeCompare(b.sourceFolder));
}

async function measureFileMetadata(filePath, seenPaths = null) {
  const info = await stat(filePath).catch(() => null);
  if (!info || !info.isFile()) return null;
  const bytes = Number(info.size || 0);
  if (seenPaths) seenPaths.set(resolve(filePath), bytes);
  return { files: 1, bytes };
}

async function measureTreeMetadata(rootDir, { skipDsStore = false, seenPaths = null } = {}) {
  let files = 0;
  let bytes = 0;
  const walk = async (dir) => {
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile()) {
        if (skipDsStore && entry.name === '.DS_Store') continue;
        const info = await stat(full).catch(() => null);
        if (!info || !info.isFile()) continue;
        const sz = Number(info.size || 0);
        files += 1;
        bytes += sz;
        if (seenPaths) seenPaths.set(resolve(full), sz);
      }
    }
  };
  await walk(rootDir);
  return { files, bytes };
}

async function measureDateDirFilesMetadata(rootDir, seenPaths = null) {
  let files = 0;
  let bytes = 0;
  const dates = await readdir(rootDir, { withFileTypes: true }).catch(() => []);
  for (const d of dates) {
    if (!d.isDirectory() || !isValidIsoDate(d.name)) continue;
    const entries = await readdir(join(rootDir, d.name), { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const measured = await measureFileMetadata(join(rootDir, d.name, entry.name), seenPaths);
      if (measured) {
        files += measured.files;
        bytes += measured.bytes;
      }
    }
  }
  return { files, bytes };
}

/**
 * Reads only the manifest JSON plus directory listings and file sizes (never reading any source
 * file contents or opening SQLite or PostgreSQL), returning strictly PHI-free counts and names.
 */
export async function planImportManifestFile(manifestPath) {
  const absManifest = resolve(manifestPath);
  const baseDir = dirname(absManifest);
  const raw = JSON.parse(await readFile(absManifest, 'utf8'));
  if (!raw || typeof raw !== 'object' || !raw.companySlug) {
    throw new AppError('Import manifest JSON must declare companySlug.', 400, 'INVALID_MANIFEST');
  }

  const companySlug = String(raw.companySlug);
  const config = normalizeImportConfig(raw.importConfig || {});
  const sources = raw.sources && typeof raw.sources === 'object' ? raw.sources : {};
  const resolvedSources = {
    legacyRunsRoot: resolveMaybeRelative(baseDir, sources.legacyRunsRoot),
    standingInputDir: resolveMaybeRelative(baseDir, sources.standingInputDir),
    incidentReportDir: resolveMaybeRelative(baseDir, sources.incidentReportDir),
    legacyReviewSavesDir: resolveMaybeRelative(baseDir, sources.legacyReviewSavesDir),
    companyWorkspacesDir: resolveMaybeRelative(baseDir, sources.companyWorkspacesDir),
    companyAbandonedDir: resolveMaybeRelative(baseDir, sources.companyAbandonedDir),
    companyReviewSavesDir: resolveMaybeRelative(baseDir, sources.companyReviewSavesDir),
    companyEnvironmentDir: resolveMaybeRelative(baseDir, sources.companyEnvironmentDir),
    cloudMirrorDir: resolveMaybeRelative(baseDir, sources.cloudMirrorDir),
    legacySqlitePath: resolveMaybeRelative(baseDir, sources.legacySqlitePath),
    preCoherenceStatementsDir: resolveMaybeRelative(baseDir, sources.preCoherenceStatementsDir),
    preCoherenceSentDir: resolveMaybeRelative(baseDir, sources.preCoherenceSentDir),
    preCoherenceAgentsCsv: resolveMaybeRelative(baseDir, sources.preCoherenceAgentsCsv),
    methodCorrections: Array.isArray(sources.methodCorrections) ? sources.methodCorrections : [],
  };

  const coherenceRoot = resolveMaybeRelative(baseDir, raw.coherenceRoot);
  const coherenceRepo = resolveMaybeRelative(baseDir, raw.coherenceRepo);
  const nusearDataDir = resolveMaybeRelative(baseDir, raw.nusearDataDir);
  const nusearSqlitePath = resolveMaybeRelative(baseDir, raw.nusearSqlitePath);
  const pythonPath = raw.pythonPath && raw.pythonPath.includes('/')
    ? resolveMaybeRelative(baseDir, raw.pythonPath)
    : null;
  const overlayCheckPath = resolveMaybeRelative(baseDir, raw.overlayCheckPath);
  const legacyBridgePath = resolveMaybeRelative(baseDir, raw.legacyBridgePath);

  const missing = [];
  const checkDirKey = async (key, pathVal) => {
    if (!pathVal) return false;
    const ok = await isDir(pathVal);
    if (!ok) missing.push({ key, kind: 'folder' });
    return ok;
  };
  const checkFileKey = async (key, pathVal) => {
    if (!pathVal) return false;
    const ok = await isFile(pathVal);
    if (!ok) missing.push({ key, kind: 'file' });
    return ok;
  };

  await checkDirKey('coherenceRoot', coherenceRoot);
  await checkDirKey('coherenceRepo', coherenceRepo);
  await checkDirKey('nusearDataDir', nusearDataDir);
  await checkFileKey('nusearSqlitePath', nusearSqlitePath);
  await checkFileKey('pythonPath', pythonPath);
  await checkFileKey('overlayCheckPath', overlayCheckPath);
  await checkFileKey('legacyBridgePath', legacyBridgePath);

  for (const key of CONFIGURED_SOURCE_DIR_KEYS) {
    await checkDirKey(`sources.${key}`, resolvedSources[key]);
  }
  await checkFileKey('sources.preCoherenceAgentsCsv', resolvedSources.preCoherenceAgentsCsv);
  await checkFileKey('sources.legacySqlitePath', resolvedSources.legacySqlitePath);

  const seenPaths = new Map();
  const discoveredRunSourceFolders = new Set();
  const discoveredLegacyRunSourceFolders = new Set();
  const discoveredCheckpointRelPaths = new Set();
  const emptyArea = (configured) => ({ configured: Boolean(configured), found: false, runs: 0, files: 0, bytes: 0 });

  const areas = {
    legacyRuns: emptyArea(resolvedSources.legacyRunsRoot),
    companyRuns: emptyArea(resolvedSources.companyWorkspacesDir),
    abandonedRuns: emptyArea(resolvedSources.companyAbandonedDir),
    standingInput: emptyArea(resolvedSources.standingInputDir),
    incidentReport: emptyArea(resolvedSources.incidentReportDir),
    legacyReviewSaves: emptyArea(resolvedSources.legacyReviewSavesDir),
    companyReviewSaves: emptyArea(resolvedSources.companyReviewSavesDir),
    companyEnvironment: emptyArea(resolvedSources.companyEnvironmentDir),
    cloudMirror: emptyArea(resolvedSources.cloudMirrorDir),
    preCoherenceStatements: emptyArea(resolvedSources.preCoherenceStatementsDir),
    preCoherenceSent: emptyArea(resolvedSources.preCoherenceSentDir),
    preCoherenceAgents: emptyArea(resolvedSources.preCoherenceAgentsCsv),
    overlayCheckpoints: emptyArea(Array.isArray(raw.overlayCheckpoints) && raw.overlayCheckpoints.length > 0),
    legacySqlite: emptyArea(resolvedSources.legacySqlitePath || nusearSqlitePath),
  };

  const legacyRunsRoot = resolvedSources.legacyRunsRoot
    || (config.includeLegacyHostHistory && coherenceRoot ? join(coherenceRoot, 'runs') : null);
  if (legacyRunsRoot && await isDir(legacyRunsRoot)) {
    const runs = await discoverLegacyRunFolders(legacyRunsRoot);
    let files = 0;
    let bytes = 0;
    for (const r of runs) {
      discoveredLegacyRunSourceFolders.add(r.sourceFolder);
      discoveredRunSourceFolders.add(r.sourceFolder);
      const m = await measureTreeMetadata(r.absPath, { seenPaths });
      files += m.files;
      bytes += m.bytes;
    }
    areas.legacyRuns = { configured: Boolean(resolvedSources.legacyRunsRoot), found: true, runs: runs.length, files, bytes };
  }

  const companyWsDir = resolvedSources.companyWorkspacesDir
    || (nusearDataDir ? join(nusearDataDir, 'company-workspaces', companySlug) : null);
  if (companyWsDir && await isDir(companyWsDir)) {
    const runs = await discoverCompanyRunFolders(companyWsDir, companySlug);
    let files = 0;
    let bytes = 0;
    for (const r of runs) {
      discoveredRunSourceFolders.add(r.sourceFolder);
      const m = await measureTreeMetadata(r.absPath, { seenPaths });
      files += m.files;
      bytes += m.bytes;
    }
    areas.companyRuns = { configured: Boolean(resolvedSources.companyWorkspacesDir), found: true, runs: runs.length, files, bytes };
  }

  const companyAbandonedDir = resolvedSources.companyAbandonedDir
    || (nusearDataDir ? join(nusearDataDir, 'company-abandoned', companySlug) : null);
  if (companyAbandonedDir && await isDir(companyAbandonedDir)) {
    const runs = await discoverAbandonedRunsMetadataOnly(companyAbandonedDir, companySlug);
    for (const r of runs) discoveredRunSourceFolders.add(r.sourceFolder);
    const m = await measureTreeMetadata(companyAbandonedDir, { seenPaths });
    areas.abandonedRuns = { configured: Boolean(resolvedSources.companyAbandonedDir), found: true, runs: runs.length, files: m.files, bytes: m.bytes };
  }

  const compEnvDir = resolvedSources.companyEnvironmentDir
    || (nusearDataDir ? join(nusearDataDir, 'company-environments', companySlug) : null);
  const legacyInput = resolvedSources.standingInputDir
    || (config.includeLegacyHostHistory && coherenceRoot ? join(coherenceRoot, 'input') : null);
  let effectiveStandingDir = null;
  if (legacyInput && !config.useCompanyIncomingInput && await isDir(legacyInput)) {
    effectiveStandingDir = legacyInput;
  } else if (resolvedSources.standingInputDir && await isDir(resolvedSources.standingInputDir)) {
    effectiveStandingDir = resolvedSources.standingInputDir;
  } else if (!resolvedSources.standingInputDir && config.useCompanyIncomingInput && compEnvDir && await isDir(join(compEnvDir, 'incoming'))) {
    effectiveStandingDir = join(compEnvDir, 'incoming');
  }
  if (effectiveStandingDir) {
    const m = await measureTreeMetadata(effectiveStandingDir, { seenPaths });
    areas.standingInput = { configured: Boolean(resolvedSources.standingInputDir), found: true, runs: 0, files: m.files, bytes: m.bytes };
  }

  const incidentRoot = resolvedSources.incidentReportDir
    || (config.includeLegacyHostHistory && coherenceRoot ? join(coherenceRoot, 'runs', 'Incident Report') : null);
  if (incidentRoot && await isDir(incidentRoot)) {
    const m = await measureTreeMetadata(incidentRoot, { seenPaths });
    areas.incidentReport = { configured: Boolean(resolvedSources.incidentReportDir), found: true, runs: 0, files: m.files, bytes: m.bytes };
  }

  const legacySavesDir = resolvedSources.legacyReviewSavesDir
    || (config.includeLegacyHostHistory && nusearDataDir ? join(nusearDataDir, 'coherence-runs') : null);
  if (legacySavesDir && await isDir(legacySavesDir)) {
    const m = await measureDateDirFilesMetadata(legacySavesDir, seenPaths);
    areas.legacyReviewSaves = { configured: Boolean(resolvedSources.legacyReviewSavesDir), found: true, runs: 0, files: m.files, bytes: m.bytes };
  }

  const companySavesDir = resolvedSources.companyReviewSavesDir
    || (nusearDataDir ? join(nusearDataDir, 'company-runs', companySlug) : null);
  if (companySavesDir && await isDir(companySavesDir)) {
    const m = await measureDateDirFilesMetadata(companySavesDir, seenPaths);
    areas.companyReviewSaves = { configured: Boolean(resolvedSources.companyReviewSavesDir), found: true, runs: 0, files: m.files, bytes: m.bytes };
  }

  if (compEnvDir && await isDir(compEnvDir)) {
    let files = 0;
    let bytes = 0;
    for (const sub of ['staging', 'documents', 'inventories', 'replaced', 'finished']) {
      const subDir = join(compEnvDir, sub);
      if (await isDir(subDir)) {
        const m = await measureTreeMetadata(subDir, { seenPaths });
        files += m.files;
        bytes += m.bytes;
      }
    }
    const rootEntries = await readdir(compEnvDir, { withFileTypes: true }).catch(() => []);
    for (const entry of rootEntries) {
      if (!entry.isFile()) continue;
      if (entry.name === 'audit.json' || ANSWER_KEY_RE.test(entry.name)) {
        const m = await measureFileMetadata(join(compEnvDir, entry.name), seenPaths);
        if (m) {
          files += m.files;
          bytes += m.bytes;
        }
      }
    }
    areas.companyEnvironment = { configured: Boolean(resolvedSources.companyEnvironmentDir), found: true, runs: 0, files, bytes };
  }

  if (resolvedSources.cloudMirrorDir && await isDir(resolvedSources.cloudMirrorDir)) {
    const m = await measureTreeMetadata(resolvedSources.cloudMirrorDir, { seenPaths });
    areas.cloudMirror = { configured: true, found: true, runs: 0, files: m.files, bytes: m.bytes };
  }

  if (resolvedSources.preCoherenceStatementsDir && await isDir(resolvedSources.preCoherenceStatementsDir)) {
    const m = await measureTreeMetadata(resolvedSources.preCoherenceStatementsDir, { skipDsStore: true, seenPaths });
    areas.preCoherenceStatements = { configured: true, found: true, runs: 0, files: m.files, bytes: m.bytes };
  }

  if (resolvedSources.preCoherenceSentDir && await isDir(resolvedSources.preCoherenceSentDir)) {
    const m = await measureTreeMetadata(resolvedSources.preCoherenceSentDir, { seenPaths });
    areas.preCoherenceSent = { configured: true, found: true, runs: 0, files: m.files, bytes: m.bytes };
  }

  if (resolvedSources.preCoherenceAgentsCsv) {
    const m = await measureFileMetadata(resolvedSources.preCoherenceAgentsCsv, seenPaths);
    if (m) {
      areas.preCoherenceAgents = { configured: true, found: true, runs: 0, files: m.files, bytes: m.bytes };
    }
  }

  const rawCheckpoints = Array.isArray(raw.overlayCheckpoints) ? raw.overlayCheckpoints : [];
  for (let i = 0; i < rawCheckpoints.length; i++) {
    if (rawCheckpoints[i]?.allowDisjointRoot) {
      throw new AppError(
        `overlayCheckpoints[${i}].allowDisjointRoot cannot be true; pin explicit fresh roots in importConfig.freshOverlayRoots instead.`,
        400,
        'DISJOINT_OVERLAY_ROOTS_FORBIDDEN',
      );
    }
  }
  if (rawCheckpoints.length > 0) {
    let foundCount = 0;
    let bytes = 0;
    for (let i = 0; i < rawCheckpoints.length; i++) {
      const cp = rawCheckpoints[i];
      const absPath = resolveMaybeRelative(baseDir, cp?.path || cp?.absPath);
      const measured = absPath ? await measureFileMetadata(absPath, seenPaths) : null;
      if (measured) {
        foundCount += 1;
        bytes += measured.bytes;
        if (!cp?.extendsCommitId) {
          const label = cp?.label || cp?.relPath || absPath;
          discoveredCheckpointRelPaths.add(safeOverlayCheckpointRelPath(label, absPath));
        }
      } else {
        missing.push({
          key: `overlayCheckpoints[${i}]`,
          kind: 'file',
          name: cp?.label || `overlayCheckpoints[${i}]`,
        });
      }
    }
    areas.overlayCheckpoints = {
      configured: true,
      found: foundCount === rawCheckpoints.length,
      runs: 0,
      files: foundCount,
      bytes,
    };
  }

  const effectiveSqlitePath = resolvedSources.legacySqlitePath || nusearSqlitePath || null;
  if (effectiveSqlitePath) {
    const m = await measureFileMetadata(effectiveSqlitePath, seenPaths);
    if (m) {
      areas.legacySqlite = { configured: true, found: true, runs: 0, files: m.files, bytes: m.bytes };
    }
  }

  const rawCompareTargets = Array.isArray(raw.compareTargets) ? raw.compareTargets : [];
  const compareTargets = [];
  for (let i = 0; i < rawCompareTargets.length; i++) {
    const ct = rawCompareTargets[i] || {};
    const name = ct.label
      || (ct.leftRunSourceFolder && ct.rightRunSourceFolder
        ? `${ct.leftRunSourceFolder} vs ${ct.rightRunSourceFolder}`
        : (ct.leftRunSourceFolder || `compareTargets[${i}]`));

    let leftFound = false;
    if (ct.leftRunSourceFolder) {
      leftFound = discoveredRunSourceFolders.has(ct.leftRunSourceFolder);
      if (!leftFound) missing.push({ key: `compareTargets[${i}].leftRunSourceFolder`, kind: 'run', name });
    } else if (ct.leftDir) {
      leftFound = await isDir(resolveMaybeRelative(baseDir, ct.leftDir));
      if (!leftFound) missing.push({ key: `compareTargets[${i}].leftDir`, kind: 'folder', name });
    } else {
      missing.push({ key: `compareTargets[${i}].left`, kind: 'target', name });
    }

    let rightFound = false;
    if (ct.rightRunSourceFolder) {
      rightFound = discoveredRunSourceFolders.has(ct.rightRunSourceFolder);
      if (!rightFound) missing.push({ key: `compareTargets[${i}].rightRunSourceFolder`, kind: 'run', name });
    } else if (ct.rightDir) {
      rightFound = await isDir(resolveMaybeRelative(baseDir, ct.rightDir));
      if (!rightFound) missing.push({ key: `compareTargets[${i}].rightDir`, kind: 'folder', name });
    } else {
      missing.push({ key: `compareTargets[${i}].right`, kind: 'target', name });
    }

    compareTargets.push({
      name,
      status: leftFound && rightFound ? 'found' : 'missing',
      left: leftFound ? 'found' : 'missing',
      right: rightFound ? 'found' : 'missing',
    });
  }

  for (let i = 0; i < config.freshOverlayRoots.length; i++) {
    const entry = config.freshOverlayRoots[i];
    if (
      !discoveredLegacyRunSourceFolders.has(entry.sourceFolder)
      && !discoveredCheckpointRelPaths.has(entry.sourceFolder)
    ) {
      missing.push({
        key: `importConfig.freshOverlayRoots[${i}].sourceFolder`,
        kind: 'run',
        name: entry.sourceFolder,
      });
    }
  }
  for (let i = 0; i < config.carriedPriors.length; i++) {
    const entry = config.carriedPriors[i];
    if (!discoveredLegacyRunSourceFolders.has(entry.sourceFolder)) {
      missing.push({
        key: `importConfig.carriedPriors[${i}].sourceFolder`,
        kind: 'run',
        name: entry.sourceFolder,
      });
    }
  }

  let totalBytes = 0;
  for (const sz of seenPaths.values()) totalBytes += sz;
  const totalRuns = areas.legacyRuns.runs + areas.companyRuns.runs + areas.abandonedRuns.runs;

  return {
    mode: 'plan',
    passed: missing.length === 0,
    companySlug,
    areas,
    totals: {
      runs: totalRuns,
      files: seenPaths.size,
      bytes: totalBytes,
    },
    methodCorrectionsCount: resolvedSources.methodCorrections.length,
    compareTargets,
    missing,
  };
}

/**
 * Loads a company-agnostic JSON manifest file describing all read-only history sources
 * and builds the resolved import manifest without hardcoding any company names in code.
 */
export async function loadImportManifestFile(manifestPath, { tempBaseDir = tmpdir() } = {}) {
  const absManifest = resolve(manifestPath);
  const baseDir = dirname(absManifest);
  const raw = JSON.parse(await readFile(absManifest, 'utf8'));
  if (!raw || typeof raw !== 'object' || !raw.companySlug) {
    throw new AppError('Import manifest JSON must declare companySlug.', 400, 'INVALID_MANIFEST');
  }

  const sources = raw.sources && typeof raw.sources === 'object' ? raw.sources : {};
  const resolvedSources = {
    legacyRunsRoot: resolveMaybeRelative(baseDir, sources.legacyRunsRoot),
    standingInputDir: resolveMaybeRelative(baseDir, sources.standingInputDir),
    incidentReportDir: resolveMaybeRelative(baseDir, sources.incidentReportDir),
    legacyReviewSavesDir: resolveMaybeRelative(baseDir, sources.legacyReviewSavesDir),
    companyWorkspacesDir: resolveMaybeRelative(baseDir, sources.companyWorkspacesDir),
    companyAbandonedDir: resolveMaybeRelative(baseDir, sources.companyAbandonedDir),
    companyReviewSavesDir: resolveMaybeRelative(baseDir, sources.companyReviewSavesDir),
    companyEnvironmentDir: resolveMaybeRelative(baseDir, sources.companyEnvironmentDir),
    cloudMirrorDir: resolveMaybeRelative(baseDir, sources.cloudMirrorDir),
    legacySqlitePath: resolveMaybeRelative(baseDir, sources.legacySqlitePath),
    preCoherenceStatementsDir: resolveMaybeRelative(baseDir, sources.preCoherenceStatementsDir),
    preCoherenceSentDir: resolveMaybeRelative(baseDir, sources.preCoherenceSentDir),
    preCoherenceAgentsCsv: resolveMaybeRelative(baseDir, sources.preCoherenceAgentsCsv),
    methodCorrections: Array.isArray(sources.methodCorrections) ? sources.methodCorrections : [],
  };

  const overlayCheckpoints = Array.isArray(raw.overlayCheckpoints)
    ? raw.overlayCheckpoints.map((cp) => ({
      ...cp,
      absPath: resolveMaybeRelative(baseDir, cp.path || cp.absPath),
    }))
    : [];

  const compareTargets = Array.isArray(raw.compareTargets)
    ? raw.compareTargets.map((ct) => ({
      ...ct,
      leftDir: resolveMaybeRelative(baseDir, ct.leftDir),
      rightDir: resolveMaybeRelative(baseDir, ct.rightDir),
    }))
    : [];

  const manifest = await buildImportManifest({
    companySlug: raw.companySlug,
    displayName: raw.displayName || raw.companySlug,
    defaultEmitMode: raw.defaultEmitMode || 'coherence',
    coherenceRoot: resolveMaybeRelative(baseDir, raw.coherenceRoot),
    nusearDataDir: resolveMaybeRelative(baseDir, raw.nusearDataDir),
    nusearSqlitePath: resolvedSources.legacySqlitePath || resolveMaybeRelative(baseDir, raw.nusearSqlitePath),
    sources: resolvedSources,
    overlayCheckpoints,
    compareTargets,
    importConfig: raw.importConfig || {},
    tempBaseDir,
  });

  manifest.manifestPath = absManifest;
  manifest.coherenceRepo = resolveMaybeRelative(baseDir, raw.coherenceRepo) || resolveMaybeRelative(baseDir, raw.coherenceRoot);
  if (raw.coherenceRepo && !(await isDir(manifest.coherenceRepo))) {
    throw new AppError(
      `Configured manifest folder coherenceRepo does not exist: ${manifest.coherenceRepo}`,
      400,
      'MANIFEST_FOLDER_MISSING',
    );
  }
  manifest.pythonPath = raw.pythonPath ? (raw.pythonPath.includes('/') ? resolveMaybeRelative(baseDir, raw.pythonPath) : raw.pythonPath) : null;
  manifest.overlayCheckPath = resolveMaybeRelative(baseDir, raw.overlayCheckPath) || null;
  manifest.legacyBridgePath = resolveMaybeRelative(baseDir, raw.legacyBridgePath) || null;
  return manifest;
}

const CONFIGURED_SOURCE_DIR_KEYS = [
  'legacyRunsRoot',
  'standingInputDir',
  'incidentReportDir',
  'legacyReviewSavesDir',
  'companyWorkspacesDir',
  'companyAbandonedDir',
  'companyReviewSavesDir',
  'companyEnvironmentDir',
  'cloudMirrorDir',
  'preCoherenceStatementsDir',
  'preCoherenceSentDir',
];

async function validateConfiguredManifestPaths({ coherenceRoot, nusearDataDir, sources, overlayCheckpoints }) {
  if (coherenceRoot && !(await isDir(coherenceRoot))) {
    throw new AppError(`Configured manifest folder coherenceRoot does not exist: ${coherenceRoot}`, 400, 'MANIFEST_FOLDER_MISSING');
  }
  if (nusearDataDir && !(await isDir(nusearDataDir))) {
    throw new AppError(`Configured manifest folder nusearDataDir does not exist: ${nusearDataDir}`, 400, 'MANIFEST_FOLDER_MISSING');
  }
  if (sources && typeof sources === 'object') {
    for (const key of CONFIGURED_SOURCE_DIR_KEYS) {
      const val = sources[key];
      if (val && !(await isDir(val))) {
        throw new AppError(`Configured manifest folder sources.${key} does not exist: ${val}`, 400, 'MANIFEST_FOLDER_MISSING');
      }
    }
    if (sources.preCoherenceAgentsCsv && !(await isFile(sources.preCoherenceAgentsCsv))) {
      throw new AppError(
        `Configured manifest file sources.preCoherenceAgentsCsv does not exist: ${sources.preCoherenceAgentsCsv}`,
        400,
        'MANIFEST_FILE_MISSING',
      );
    }
  }
  for (const cp of (overlayCheckpoints || [])) {
    if (cp?.allowDisjointRoot) {
      throw new AppError(
        'overlayCheckpoints entries cannot set allowDisjointRoot: true; pin explicit fresh roots in importConfig.freshOverlayRoots instead.',
        400,
        'DISJOINT_OVERLAY_ROOTS_FORBIDDEN',
      );
    }
    const absPath = cp?.absPath || cp?.path;
    if (!absPath || !(await isFile(absPath))) {
      throw new AppError(
        `Configured overlay checkpoint file does not exist: ${absPath || '(empty)'}`,
        400,
        'MANIFEST_FILE_MISSING',
      );
    }
  }
}

/**
 * Builds a complete read-only import manifest listing all source folders, files, review saves,
 * company environment files, local cloud mirror files, abandoned runs, pre-Coherence statements,
 * and SQLite record counts before reading member data or writing to PostgreSQL.
 */
export async function buildImportManifest({
  companySlug,
  displayName = null,
  defaultEmitMode = 'coherence',
  coherenceRoot = null,
  nusearDataDir = null,
  nusearSqlitePath = null,
  sources = {},
  overlayCheckpoints = [],
  compareTargets = [],
  importConfig = {},
  tempBaseDir = tmpdir(),
} = {}) {
  const config = normalizeImportConfig(importConfig);
  const resolvedSqlitePath = sources.legacySqlitePath || nusearSqlitePath || null;
  await validateConfiguredManifestPaths({ coherenceRoot, nusearDataDir, sources, overlayCheckpoints });

  const manifest = {
    companySlug,
    displayName: displayName || companySlug,
    defaultEmitMode,
    importConfig: config,
    generatedAt: new Date().toISOString(),
    macRuns: [],
    companyRuns: [],
    abandonedRuns: [],
    currentInputDir: null,
    currentInputFiles: [],
    incidentReportDir: null,
    incidentReportFiles: [],
    nusearMacSaves: {},       // date -> [{ filename, absPath, surface, originalAt }]
    nusearCompanySaves: {},   // date -> [{ filename, absPath, surface, originalAt }]
    companyEnvironmentDir: null,
    cloudMirrorDir: null,
    standaloneFiles: [],      // { area, relPath, absPath, verifySha256FromName? }
    overlayCheckpoints: [...overlayCheckpoints],
    companySentRecords: { ...config.companySentRecords },
    preCoherenceStatements: null,
    sqlitePath: resolvedSqlitePath,
    sqliteCounts: {},
    sqliteSnapshot: null,
    sqliteSnapshotPath: null,
    compareTargets: [...compareTargets],
  };

  const legacyRunsRoot = sources.legacyRunsRoot || (config.includeLegacyHostHistory && coherenceRoot ? join(coherenceRoot, 'runs') : null);
  const incidentRoot = sources.incidentReportDir || (config.includeLegacyHostHistory && coherenceRoot ? join(coherenceRoot, 'runs', 'Incident Report') : null);
  const legacyInput = sources.standingInputDir || (config.includeLegacyHostHistory && coherenceRoot ? join(coherenceRoot, 'input') : null);
  const legacyReviewSavesDir = sources.legacyReviewSavesDir || (config.includeLegacyHostHistory && nusearDataDir ? join(nusearDataDir, 'coherence-runs') : null);

  if (legacyRunsRoot && await isDir(legacyRunsRoot)) {
    manifest.macRuns = await discoverLegacyRunFolders(legacyRunsRoot);
  }

  if (incidentRoot && await isDir(incidentRoot)) {
    manifest.incidentReportDir = incidentRoot;
    const incidentFiles = await listFilesRecursive(incidentRoot);
    manifest.incidentReportFiles = incidentFiles.map((rel) => ({
      area: 'incident_report',
      relPath: `Incident Report/${rel}`,
      absPath: join(incidentRoot, ...rel.split('/')),
    }));
  }

  if (legacyInput && !config.useCompanyIncomingInput && await isDir(legacyInput)) {
    manifest.currentInputDir = legacyInput;
    manifest.currentInputFiles = await listFilesRecursive(legacyInput);
  } else if (sources.standingInputDir && await isDir(sources.standingInputDir)) {
    manifest.currentInputDir = sources.standingInputDir;
    manifest.currentInputFiles = await listFilesRecursive(sources.standingInputDir);
  }

  if (legacyReviewSavesDir && await isDir(legacyReviewSavesDir)) {
    const dates = await readdir(legacyReviewSavesDir, { withFileTypes: true }).catch(() => []);
    for (const d of dates) {
      if (!d.isDirectory() || !isValidIsoDate(d.name)) continue;
      const files = (await readdir(join(legacyReviewSavesDir, d.name)).catch(() => [])).sort();
      const saves = [];
      for (const f of files) {
        const parsed = parseReviewSaveTimestamp(f);
        const absPath = join(legacyReviewSavesDir, d.name, f);
        if (parsed) {
          saves.push({ filename: f, absPath, ...parsed });
        } else if (await isFile(absPath)) {
          manifest.standaloneFiles.push({ area: 'nusear_log', relPath: `coherence-runs/${d.name}/${f}`, absPath });
        }
      }
      if (saves.length) manifest.nusearMacSaves[d.name] = saves;
    }
  }

  const companyWsDir = sources.companyWorkspacesDir || (nusearDataDir ? join(nusearDataDir, 'company-workspaces', companySlug) : null);
  if (companyWsDir && await isDir(companyWsDir)) {
    manifest.companyRuns = await discoverCompanyRunFolders(companyWsDir, companySlug);
  }

  const companyAbandonedDir = sources.companyAbandonedDir || (nusearDataDir ? join(nusearDataDir, 'company-abandoned', companySlug) : null);
  if (companyAbandonedDir && await isDir(companyAbandonedDir)) {
    const discovered = await discoverAbandonedCompanyRuns(companyAbandonedDir, companySlug);
    manifest.abandonedRuns = discovered.runs;
    manifest.standaloneFiles.push(...discovered.standaloneFiles);
  }

  const compRunsData = sources.companyReviewSavesDir || (nusearDataDir ? join(nusearDataDir, 'company-runs', companySlug) : null);
  if (compRunsData && await isDir(compRunsData)) {
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
        } else if (await isFile(absPath)) {
          manifest.standaloneFiles.push({ area: 'nusear_log', relPath: `company-runs/${companySlug}/${d.name}/${f}`, absPath });
        }
      }
      if (saves.length) manifest.nusearCompanySaves[d.name] = saves;
    }
  }

  const compEnv = sources.companyEnvironmentDir || (nusearDataDir ? join(nusearDataDir, 'company-environments', companySlug) : null);
  if (compEnv && await isDir(compEnv)) {
    manifest.companyEnvironmentDir = compEnv;
    if (config.useCompanyIncomingInput && !manifest.currentInputDir) {
      const incomingDir = join(compEnv, 'incoming');
      if (await isDir(incomingDir)) {
        manifest.currentInputDir = incomingDir;
        manifest.currentInputFiles = await listFilesRecursive(incomingDir);
      }
    }

    // Standard company environment subdirectories plus G4 additions (replaced/, finished/).
    for (const [sub, area, relPrefix] of [
      ['staging', 'staging', 'staging'],
      ['documents', 'documents', 'documents'],
      ['inventories', 'archive_inventory', 'inventories'],
      ['replaced', 'other', 'company-environment/replaced'],
      ['finished', 'other', 'company-environment/finished'],
    ]) {
      const subDir = join(compEnv, sub);
      const files = await listFilesRecursive(subDir);
      for (const rel of files) {
        manifest.standaloneFiles.push({
          area,
          relPath: `${relPrefix}/${rel}`,
          absPath: join(subDir, ...rel.split('/')),
        });
      }
    }

    // Top-level audit.json and answer-key-*.json in company environment.
    const rootEntries = await readdir(compEnv, { withFileTypes: true }).catch(() => []);
    for (const entry of rootEntries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isFile()) continue;
      const absPath = join(compEnv, entry.name);
      if (entry.name === 'audit.json') {
        manifest.standaloneFiles.push({
          area: 'nusear_record',
          relPath: 'company-environment/audit.json',
          absPath,
        });
        try {
          const auditJson = JSON.parse(await readFile(absPath, 'utf8'));
          const detected = extractAuditSentRecords(auditJson, 'company-environment/audit.json');
          for (const [date, prov] of Object.entries(detected)) {
            if (!manifest.companySentRecords[date]) {
              manifest.companySentRecords[date] = prov;
            }
          }
        } catch (err) {
          throw new AppError(
            `Failed to parse company environment audit.json: ${sanitizeErrorMessage(err)}`,
            422,
            'INVALID_AUDIT_JSON',
          );
        }
      } else if (ANSWER_KEY_RE.test(entry.name)) {
        manifest.standaloneFiles.push({
          area: 'nusear_record',
          relPath: `company-environment/${entry.name}`,
          absPath,
        });
      }
    }
  }

  // Local read-only mirror of cloud lists and objects (the importer never uses the network).
  if (sources.cloudMirrorDir && await isDir(sources.cloudMirrorDir)) {
    manifest.cloudMirrorDir = sources.cloudMirrorDir;
    const mirrorFiles = await listFilesRecursive(sources.cloudMirrorDir);
    for (const rel of mirrorFiles) {
      const absPath = join(sources.cloudMirrorDir, ...rel.split('/'));
      const parts = rel.split('/');
      const verifySha = parts.length === 2 && parts[0] === 'objects' && SHA256_HEX_RE.test(parts[1]) ? parts[1] : null;
      manifest.standaloneFiles.push({
        area: 'archive_inventory',
        relPath: `cloud-mirror/${rel}`,
        absPath,
        verifySha256FromName: verifySha,
      });
    }
  }

  if (sources.preCoherenceStatementsDir && await isDir(sources.preCoherenceStatementsDir)) {
    const stmtFiles = await listFilesRecursive(sources.preCoherenceStatementsDir);
    manifest.preCoherenceStatements = {
      statementsDir: sources.preCoherenceStatementsDir,
      sentDir: sources.preCoherenceSentDir || null,
      agentsCsvPath: sources.preCoherenceAgentsCsv || null,
      methodCorrections: Array.isArray(sources.methodCorrections) ? sources.methodCorrections : [],
      files: stmtFiles.filter((f) => f !== '.DS_Store' && !f.endsWith('/.DS_Store')),
    };
  }

  if (resolvedSqlitePath) {
    const snap = await readLegacySqliteSnapshot(resolvedSqlitePath, {
      companySlug,
      includeLegacySqliteTables: config.includeLegacySqliteTables,
      tempBaseDir,
      takeConsistentCopy: true,
    });
    manifest.sqliteCounts = snap.counts;
    manifest.sqliteSnapshot = snap.tables;
    manifest.sqliteSnapshotPath = resolvedSqlitePath;
    for (const [date, prov] of Object.entries(snap.companySentRecords)) {
      if (!manifest.companySentRecords[date]) {
        manifest.companySentRecords[date] = prov;
      }
    }
  }

  return manifest;
}

function partitionRunFilesByStep(allFiles, stepsDone) {
  const byStep = { assign: [], attribute: [], bible: [], adjust: [], emit: [] };
  const lastStep = ['emit', 'adjust', 'bible', 'attribute', 'assign'].find((s) => stepsDone.includes(s)) || null;
  if (!lastStep) return byStep;

  for (const rel of allFiles) {
    if (rel.startsWith('input/')) continue; // input/ is stored in the run's snapshot input_version
    if (rel === 'run.json') {
      byStep[lastStep].push(rel);
    } else if (rel.startsWith('working/')) {
      const target = stepsDone.includes('attribute') ? 'attribute' : (stepsDone.includes('assign') ? 'assign' : lastStep);
      byStep[target].push(rel);
    } else if (rel === 'bible.csv' || rel === 'bible.html' || rel === 'bible.json') {
      byStep[stepsDone.includes('bible') ? 'bible' : lastStep].push(rel);
    } else if (rel === 'adjust.csv' || rel === 'adjust.html' || rel === 'adjust.json') {
      byStep[stepsDone.includes('adjust') ? 'adjust' : lastStep].push(rel);
    } else if (rel.startsWith('emits/') || rel === 'company_manifest.json') {
      byStep[stepsDone.includes('emit') ? 'emit' : lastStep].push(rel);
    } else if (rel === 'overlay.csv') {
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

function parseReviewQueueCsv(csvText, surface) {
  const matrix = parseCsv(csvText);
  if (matrix.length < 2) return [];
  const header = matrix[0];
  const idxOf = (name) => header.indexOf(name);
  const ridIdx = idxOf('record_id');
  if (ridIdx < 0) return [];
  const caseIdx = idxOf('case') >= 0 ? idxOf('case') : idxOf('case_kind');
  const subIdx = idxOf('subtype');
  const entIdx = idxOf('entity');
  const npnIdx = idxOf('npn');
  const amtIdx = idxOf('amount');
  const efIdx = idxOf('entity_from');
  const nfIdx = idxOf('npn_from');

  const items = [];
  const opt = (row, idx) => (idx >= 0 && row[idx] !== undefined && row[idx] !== '' ? row[idx] : null);
  for (let i = 1; i < matrix.length; i++) {
    const row = matrix[i];
    const recordId = opt(row, ridIdx);
    if (!recordId) continue;
    items.push({
      attemptStep: surface,
      itemOrder: items.length + 1,
      surface,
      recordId,
      caseKind: opt(row, caseIdx),
      subtype: opt(row, subIdx),
      entity: opt(row, entIdx),
      npn: opt(row, npnIdx),
      amount: opt(row, amtIdx),
      entityFrom: opt(row, efIdx),
      npnFrom: opt(row, nfIdx),
      needsReconfirm: false,
    });
  }
  return items;
}

/**
 * Tracks all known decision_commits across the database and current import batch so
 * prefix-chaining, replaces_decision_id linking, deepest-ancestor branch attachment,
 * and loud G3 prefix-mismatch reporting are exact and deterministic.
 */
async function loadDecisionLineageTracker(pool) {
  const commits = [];
  const byId = new Map();

  const priorOnlyEmptyRes = await pool.query(
    `SELECT DISTINCT dc.id
     FROM coherence.decision_commits dc
     WHERE dc.cumulative_decision_count = 0
       AND EXISTS (
         SELECT 1 FROM coherence.generated_overlays go
         WHERE go.decision_commit_id = dc.id AND go.purpose = 'prior_input'
       )
       AND NOT EXISTS (
         SELECT 1 FROM coherence.generated_overlays go
         WHERE go.decision_commit_id = dc.id AND go.purpose <> 'prior_input'
       )
       AND NOT EXISTS (
         SELECT 1 FROM coherence.review_saves rs
         WHERE rs.decision_commit_id = dc.id
       )
       AND NOT EXISTS (
         SELECT 1 FROM coherence.imported_files i
         WHERE i.metadata->>'decisionCommitId' = dc.id::text
       )`,
  );
  const priorOnlyEmptyIds = new Set(priorOnlyEmptyRes.rows.map((r) => r.id));

  const res = await pool.query(
    `SELECT id, parent_commit_id, commit_kind, header_contract, cumulative_decision_count, journal_seq
     FROM coherence.decision_commits
     ORDER BY journal_seq ASC, cumulative_decision_count ASC, id::text COLLATE "C"`,
  );

  for (const row of res.rows) {
    const decRes = await pool.query(
      `SELECT id, record_id, disposition, agent, agency, policy, book, month, status, note,
              committed_at_raw, approved_amount, approved_agency, approved_agent,
              approved_agency_from, approved_agent_from
       FROM coherence.decisions_in_commit($1::uuid)
       ORDER BY seq_order ASC`,
      [row.id],
    );
    const normalizedRows = decRes.rows.map((r) => normalizeOverlayRow({
      ...r,
      committed_at: r.committed_at_raw,
    }));
    const signatures = normalizedRows.map((r) => rowSignature(r));
    const headByRecordId = new Map();
    for (const r of decRes.rows) {
      headByRecordId.set(r.record_id, r.id);
    }
    const cumulativeCount = Number(row.cumulative_decision_count);
    const entry = {
      id: row.id,
      parentCommitId: row.parent_commit_id,
      commitKind: row.commit_kind,
      headerContract: row.header_contract,
      cumulativeCount,
      priorOnly: cumulativeCount === 0 && priorOnlyEmptyIds.has(row.id),
      rows: normalizedRows,
      signatures,
      headByRecordId,
      persisted: true,
    };
    commits.push(entry);
    byId.set(entry.id, entry);
  }

  return {
    commits,
    byId,
    findEmptyCommit(headerContract) {
      return commits.find((c) => c.cumulativeCount === 0 && c.headerContract === headerContract) || null;
    },
    markNotPriorOnly(commitId) {
      const entry = byId.get(commitId);
      if (entry) entry.priorOnly = false;
    },
    findExactMatchingCommit(candidateSigs, preferredHeader) {
      if (candidateSigs.length === 0 && commits.some((c) => c.cumulativeCount > 0)) {
        return null;
      }
      let best = null;
      for (const c of commits) {
        if (c.cumulativeCount !== candidateSigs.length) continue;
        if (c.cumulativeCount === 0 && c.priorOnly) continue;
        let matches = true;
        for (let i = 0; i < c.cumulativeCount; i++) {
          if (c.signatures[i] !== candidateSigs[i]) {
            matches = false;
            break;
          }
        }
        if (!matches) continue;
        if (
          !best
          || (c.headerContract === preferredHeader && best.headerContract !== preferredHeader)
        ) {
          best = c;
        }
      }
      return best;
    },
    findMatchingAncestorWithRowCount(candidateSigs, expectedRowCount, preferredHeader) {
      if (!Number.isInteger(expectedRowCount) || expectedRowCount <= 0) return null;
      if (candidateSigs.length <= expectedRowCount) return null;
      let best = null;
      for (const c of commits) {
        if (c.cumulativeCount !== expectedRowCount) continue;
        let matches = true;
        for (let i = 0; i < expectedRowCount; i++) {
          if (c.signatures[i] !== candidateSigs[i]) {
            matches = false;
            break;
          }
        }
        if (!matches) continue;
        if (
          !best
          || (c.headerContract === preferredHeader && best.headerContract !== preferredHeader)
        ) {
          best = c;
        }
      }
      return best;
    },
    findDeepestMatchingAncestor(candidateSigs, preferredHeader) {
      let best = null;
      for (const c of commits) {
        if (c.cumulativeCount === 0 || c.cumulativeCount > candidateSigs.length) continue;
        let matches = true;
        for (let i = 0; i < c.cumulativeCount; i++) {
          if (c.signatures[i] !== candidateSigs[i]) {
            matches = false;
            break;
          }
        }
        if (!matches) continue;
        if (
          !best
          || c.cumulativeCount > best.cumulativeCount
          || (c.cumulativeCount === best.cumulativeCount && c.headerContract === preferredHeader && best.headerContract !== preferredHeader)
        ) {
          best = c;
        }
      }
      return best;
    },
    findClosestMismatchRow(candidateSigs) {
      let longestPrefix = 0;
      for (const c of commits) {
        if (c.cumulativeCount === 0) continue;
        let matched = 0;
        const limit = Math.min(c.cumulativeCount, candidateSigs.length);
        while (matched < limit && c.signatures[matched] === candidateSigs[matched]) {
          matched += 1;
        }
        if (matched > longestPrefix) longestPrefix = matched;
      }
      return longestPrefix + 1;
    },
    registerCommit({
      id,
      parentCommitId,
      commitKind,
      headerContract,
      addedRows,
      addedDecisionIds,
      persisted = false,
      priorOnly = false,
    }) {
      const parent = parentCommitId ? byId.get(parentCommitId) : null;
      const rows = [...(parent ? parent.rows : []), ...addedRows.map(normalizeOverlayRow)];
      const signatures = [...(parent ? parent.signatures : []), ...addedRows.map(rowSignature)];
      const headByRecordId = new Map(parent ? parent.headByRecordId : []);
      for (let i = 0; i < addedRows.length; i++) {
        headByRecordId.set(addedRows[i].record_id, addedDecisionIds[i]);
      }
      const entry = {
        id,
        parentCommitId,
        commitKind,
        headerContract,
        cumulativeCount: rows.length,
        priorOnly: rows.length === 0 && Boolean(priorOnly),
        rows,
        signatures,
        headByRecordId,
        persisted,
      };
      commits.push(entry);
      byId.set(id, entry);
      return entry;
    },
  };
}

function safeUtcUs(primary, fallbackA, fallbackB) {
  for (const candidate of [primary, fallbackA, fallbackB]) {
    if (candidate == null || candidate === '') continue;
    try {
      return formatTimestampUtcUs(candidate);
    } catch {}
  }
  return formatTimestampUtcUs(new Date());
}

function buildDecisionRowsForCommit({
  commitId,
  parentHeadByKey,
  addedRows,
  headerContract,
  runId = '__THIS_RUN__',
  reviewSaveId = null,
  surface = null,
  decidedBy = 'historical_import',
  originalAt = null,
}) {
  const headByKey = new Map(parentHeadByKey || []);
  const nowIso = formatTimestampUtcUs(new Date());
  const decisionIds = [];
  const decisionRows = addedRows.map((raw, idx) => {
    const id = randomUUID();
    const recordId = raw.record_id;
    const replacesDecisionId = headByKey.get(recordId) ?? null;
    headByKey.set(recordId, id);
    decisionIds.push(id);
    const norm = normalizeOverlayRow(raw);
    return {
      id,
      decisionCommitId: commitId,
      rowOrder: idx + 1,
      runId,
      reviewSaveId,
      surface,
      recordId,
      replacesDecisionId,
      disposition: norm.disposition || 'CONFIRM',
      agent: norm.agent,
      agency: norm.agency,
      policy: norm.policy,
      book: norm.book,
      month: norm.month,
      status: norm.status,
      note: norm.note,
      approvedAmount: headerContract === 'v1' ? null : norm.approved_amount,
      approvedAgency: headerContract === 'v1' ? null : norm.approved_agency,
      approvedAgent: headerContract === 'v1' ? null : norm.approved_agent,
      approvedAgencyFrom: headerContract === 'v1' ? null : norm.approved_agency_from,
      approvedAgentFrom: headerContract === 'v1' ? null : norm.approved_agent_from,
      decidedBy,
      actingFor: null,
      decidedAt: safeUtcUs(norm.committed_at, originalAt, nowIso),
      committedAtRaw: norm.committed_at,
      originalAt,
      imported: true,
    };
  });
  return { decisionRows, decisionIds };
}

async function resolveOverlayCheckpoint({
  tracker,
  absPath,
  fileSha256 = null,
  checkpointLabel,
  runLabel,
  mode = 'no_prior_run_start',
  requiredParentCommitId = null,
  requiredParentPath = null,
  freshRootEntry = null,
  carriedPriorEntry = null,
  allowEmptyParentReattach = false,
  commitKind = 'historical_overlay',
  runId = '__THIS_RUN__',
  reviewSaveId = null,
  surface = null,
  decidedBy = 'historical_import',
  originalAt = null,
  parseOverlay,
  parseOpts,
  tempBaseDir,
}) {
  const throwPrefixMismatch = (firstRow, detail) => {
    const mismatch = new AppError(
      `Overlay prefix mismatch in run ${runLabel} at checkpoint ${checkpointLabel}${detail ? `: ${detail}` : ''} (first differing row: ${firstRow}).`,
      422,
      'OVERLAY_PREFIX_MISMATCH',
    );
    mismatch.run = runLabel;
    mismatch.checkpoint = checkpointLabel;
    mismatch.firstDifferingRow = firstRow;
    throw mismatch;
  };

  const getOrCreateEmptyCommit = (fullParsed, { priorOnly = false } = {}) => {
    const existingEmpty = tracker.findEmptyCommit(fullParsed.headerKind);
    if (existingEmpty) {
      if (!priorOnly) tracker.markNotPriorOnly(existingEmpty.id);
      return {
        commitId: existingEmpty.id,
        reused: true,
        isFreshRoot: false,
        isCarriedPrior: false,
        resolvedRootCommitId: null,
        parsedAgainstRequiredParent: false,
        verifiedFreshRootPin: false,
        headerContract: fullParsed.headerKind,
        rowCount: 0,
        parsed: fullParsed,
        newCommit: null,
        newDecisions: [],
      };
    }
    const commitId = randomUUID();
    const newCommit = {
      id: commitId,
      parentCommitId: null,
      commitKind,
      headerContract: fullParsed.headerKind,
      addedDecisionCount: 0,
      cumulativeDecisionCount: 0,
      addedDecisionsSha256: hashDecisions([]),
      imported: true,
      originalAt,
    };
    tracker.registerCommit({
      id: commitId,
      parentCommitId: null,
      commitKind,
      headerContract: fullParsed.headerKind,
      addedRows: [],
      addedDecisionIds: [],
      persisted: false,
      priorOnly,
    });
    return {
      commitId,
      reused: false,
      isFreshRoot: false,
      isCarriedPrior: false,
      resolvedRootCommitId: null,
      parsedAgainstRequiredParent: false,
      verifiedFreshRootPin: false,
      headerContract: fullParsed.headerKind,
      rowCount: 0,
      parsed: fullParsed,
      newCommit,
      newDecisions: [],
    };
  };

  const extendSpecificParent = async (
    parent,
    parentPath,
    {
      parsedAgainstRequiredParent,
      requireExactZeroAdded = false,
      runIdOverride = undefined,
      decidedByOverride = undefined,
    },
  ) => {
    let tempParentDir = null;
    let parentCsvPath = parentPath;
    try {
      if (!parentCsvPath) {
        tempParentDir = await mkdtemp(join(tempBaseDir, 'coherence-parent-ov-'));
        parentCsvPath = join(tempParentDir, 'parent-overlay.csv');
        const formatted = formatOverlayCsvFromRows(parent.rows, { headerContract: parent.headerContract });
        await writeFile(parentCsvPath, formatted.bytes);
      }
      let parsed;
      try {
        parsed = await parseOverlay(absPath, { ...parseOpts, parentPath: parentCsvPath });
      } catch (err) {
        if (err?.code === 'OVERLAY_PREFIX_MISMATCH') {
          throwPrefixMismatch(err.firstDifferingRow ?? 1, null);
        }
        throw err;
      }
      if (requireExactZeroAdded && parsed.addedRows.length !== 0) {
        throwPrefixMismatch(parent.cumulativeCount + 1, 'does not equal any known decision commit');
      }
      if (parsed.addedRows.length === 0 && parsed.headerKind === parent.headerContract) {
        if (!requireExactZeroAdded) tracker.markNotPriorOnly(parent.id);
        return {
          commitId: parent.id,
          reused: true,
          isFreshRoot: false,
          isCarriedPrior: false,
          resolvedRootCommitId: null,
          parsedAgainstRequiredParent,
          verifiedFreshRootPin: false,
          headerContract: parsed.headerKind,
          rowCount: parsed.rowCount,
          parsed,
          newCommit: null,
          newDecisions: [],
        };
      }
      const commitId = randomUUID();
      const { decisionRows, decisionIds } = buildDecisionRowsForCommit({
        commitId,
        parentHeadByKey: parent.headByRecordId,
        addedRows: parsed.addedRows,
        headerContract: parsed.headerKind,
        runId: runIdOverride !== undefined ? runIdOverride : runId,
        reviewSaveId,
        surface,
        decidedBy: decidedByOverride !== undefined ? decidedByOverride : decidedBy,
        originalAt,
      });
      const newCommit = {
        id: commitId,
        parentCommitId: parent.id,
        commitKind,
        headerContract: parsed.headerKind,
        addedDecisionCount: decisionRows.length,
        cumulativeDecisionCount: parsed.rowCount,
        addedDecisionsSha256: hashDecisions(decisionRows),
        imported: true,
        originalAt,
      };
      tracker.registerCommit({
        id: commitId,
        parentCommitId: parent.id,
        commitKind,
        headerContract: parsed.headerKind,
        addedRows: parsed.addedRows,
        addedDecisionIds: decisionIds,
        persisted: false,
        priorOnly: false,
      });
      return {
        commitId,
        reused: false,
        isFreshRoot: false,
        isCarriedPrior: false,
        resolvedRootCommitId: null,
        parsedAgainstRequiredParent,
        verifiedFreshRootPin: false,
        headerContract: parsed.headerKind,
        rowCount: parsed.rowCount,
        parsed,
        newCommit,
        newDecisions: decisionRows,
      };
    } finally {
      if (tempParentDir) await rm(tempParentDir, { recursive: true, force: true }).catch(() => {});
    }
  };

  let preParsedStandalone = null;

  if (mode === 'extend_run_parent') {
    const parent = requiredParentCommitId ? tracker.byId.get(requiredParentCommitId) : null;
    if (!parent) {
      throw new AppError(`Missing parent decision commit for ${runLabel} (${checkpointLabel}).`, 500, 'PARENT_COMMIT_MISSING');
    }
    if (parent.cumulativeCount > 0) {
      if (freshRootEntry) {
        throwPrefixMismatch(1, `cannot apply importConfig.freshOverlayRoots (${freshRootEntry.sourceFolder}) after a non-empty parent commit`);
      }
      return extendSpecificParent(parent, requiredParentPath, { parsedAgainstRequiredParent: true });
    }
    if (freshRootEntry && (!fileSha256 || freshRootEntry.sha256 !== fileSha256)) {
      throwPrefixMismatch(1, `SHA-256 mismatch against importConfig.freshOverlayRoots for ${freshRootEntry.sourceFolder}`);
    }
    const verifiedFreshRootPin = Boolean(freshRootEntry);
    if (!allowEmptyParentReattach) {
      const ext = await extendSpecificParent(parent, requiredParentPath, { parsedAgainstRequiredParent: true });
      return { ...ext, verifiedFreshRootPin };
    }
    // Empty prior (0 rows): the run's files extend nothing, so empty files stay empty and
    // non-empty files either match/extend a known commit or start a fresh root only under rule 2.
    preParsedStandalone = await parseOverlay(absPath, { ...parseOpts, parentPath: null });
    if (preParsedStandalone.addedRows.length === 0) {
      return { ...getOrCreateEmptyCommit(preParsedStandalone, { priorOnly: false }), verifiedFreshRootPin };
    }
  } else if (mode === 'exact_known_commit' || mode === 'legacy_frozen_prior') {
    const fullParsed = await parseOverlay(absPath, { ...parseOpts, parentPath: null });
    const allRows = fullParsed.addedRows;
    const sigs = allRows.map(rowSignature);

    if (mode === 'legacy_frozen_prior' && carriedPriorEntry) {
      if (!fileSha256 || carriedPriorEntry.sha256 !== fileSha256) {
        const firstRow = allRows.length === 0 ? 1 : tracker.findClosestMismatchRow(sigs);
        throwPrefixMismatch(firstRow, `SHA-256 mismatch against importConfig.carriedPriors for ${carriedPriorEntry.sourceFolder}`);
      }
    }

    if (allRows.length === 0 && mode === 'legacy_frozen_prior') {
      if (carriedPriorEntry) {
        throwPrefixMismatch(
          1,
          `does not extend a known decision commit of exactly ${carriedPriorEntry.extendsRowCount} rows as configured in importConfig.carriedPriors for ${carriedPriorEntry.sourceFolder}`,
        );
      }
      return getOrCreateEmptyCommit(fullParsed, { priorOnly: true });
    }

    const exactCommit = tracker.findExactMatchingCommit(sigs, fullParsed.headerKind);
    if (!exactCommit) {
      if (mode === 'legacy_frozen_prior' && carriedPriorEntry) {
        const carriedParent = tracker.findMatchingAncestorWithRowCount(
          sigs,
          carriedPriorEntry.extendsRowCount,
          fullParsed.headerKind,
        );
        if (!carriedParent) {
          const firstRow = allRows.length === 0 ? 1 : tracker.findClosestMismatchRow(sigs);
          throwPrefixMismatch(
            firstRow,
            `does not extend a known decision commit of exactly ${carriedPriorEntry.extendsRowCount} rows as configured in importConfig.carriedPriors for ${carriedPriorEntry.sourceFolder}`,
          );
        }
        const carriedRes = await extendSpecificParent(carriedParent, null, {
          parsedAgainstRequiredParent: false,
          runIdOverride: null,
          decidedByOverride: 'historical_import_reference_append',
        });
        return {
          ...carriedRes,
          isCarriedPrior: true,
          parentCommitId: carriedParent.id,
          addedRowCount: carriedRes.parsed.addedRows.length,
        };
      }
      const firstRow = allRows.length === 0 ? 1 : tracker.findClosestMismatchRow(sigs);
      throwPrefixMismatch(firstRow, 'does not equal any known decision commit');
    }
    if (exactCommit.cumulativeCount === 0) {
      if (exactCommit.headerContract === fullParsed.headerKind) {
        return {
          commitId: exactCommit.id,
          reused: true,
          isFreshRoot: false,
          isCarriedPrior: false,
          resolvedRootCommitId: null,
          parsedAgainstRequiredParent: false,
          verifiedFreshRootPin: false,
          headerContract: fullParsed.headerKind,
          rowCount: 0,
          parsed: fullParsed,
          newCommit: null,
          newDecisions: [],
        };
      }
      const commitId = randomUUID();
      const newCommit = {
        id: commitId,
        parentCommitId: exactCommit.id,
        commitKind,
        headerContract: fullParsed.headerKind,
        addedDecisionCount: 0,
        cumulativeDecisionCount: 0,
        addedDecisionsSha256: hashDecisions([]),
        imported: true,
        originalAt,
      };
      tracker.registerCommit({
        id: commitId,
        parentCommitId: exactCommit.id,
        commitKind,
        headerContract: fullParsed.headerKind,
        addedRows: [],
        addedDecisionIds: [],
        persisted: false,
        priorOnly: false,
      });
      return {
        commitId,
        reused: false,
        isFreshRoot: false,
        isCarriedPrior: false,
        resolvedRootCommitId: null,
        parsedAgainstRequiredParent: false,
        verifiedFreshRootPin: false,
        headerContract: fullParsed.headerKind,
        rowCount: 0,
        parsed: fullParsed,
        newCommit,
        newDecisions: [],
      };
    }
    return extendSpecificParent(exactCommit, null, {
      parsedAgainstRequiredParent: false,
      requireExactZeroAdded: true,
    });
  }

  // No-prior run start (or first non-empty file after an empty 0-row prior).
  if (freshRootEntry && (!fileSha256 || freshRootEntry.sha256 !== fileSha256)) {
    throwPrefixMismatch(1, `SHA-256 mismatch against importConfig.freshOverlayRoots for ${freshRootEntry.sourceFolder}`);
  }
  const verifiedFreshRootPin = Boolean(freshRootEntry);

  const fullParsed = preParsedStandalone || await parseOverlay(absPath, { ...parseOpts, parentPath: null });
  const allRows = fullParsed.addedRows;
  const sigs = allRows.map(rowSignature);

  if (allRows.length === 0) {
    return { ...getOrCreateEmptyCommit(fullParsed, { priorOnly: false }), verifiedFreshRootPin };
  }

  const ancestor = tracker.findDeepestMatchingAncestor(sigs, fullParsed.headerKind);
  if (ancestor) {
    const extended = await extendSpecificParent(ancestor, null, { parsedAgainstRequiredParent: false });
    if (extended.reused && ancestor.parentCommitId === null && ancestor.cumulativeCount > 0) {
      return { ...extended, resolvedRootCommitId: ancestor.id, verifiedFreshRootPin };
    }
    return { ...extended, verifiedFreshRootPin };
  }

  if (!freshRootEntry) {
    const firstRow = tracker.findClosestMismatchRow(sigs);
    throwPrefixMismatch(firstRow, 'does not extend any known decision commit and is not listed in importConfig.freshOverlayRoots');
  }

  const commitId = randomUUID();
  const rootKind = 'historical_overlay';
  const { decisionRows, decisionIds } = buildDecisionRowsForCommit({
    commitId,
    parentHeadByKey: null,
    addedRows: allRows,
    headerContract: fullParsed.headerKind,
    runId,
    reviewSaveId,
    surface,
    decidedBy,
    originalAt,
  });
  const newCommit = {
    id: commitId,
    parentCommitId: null,
    commitKind: rootKind,
    headerContract: fullParsed.headerKind,
    addedDecisionCount: decisionRows.length,
    cumulativeDecisionCount: allRows.length,
    addedDecisionsSha256: hashDecisions(decisionRows),
    imported: true,
    originalAt,
  };
  tracker.registerCommit({
    id: commitId,
    parentCommitId: null,
    commitKind: rootKind,
    headerContract: fullParsed.headerKind,
    addedRows: allRows,
    addedDecisionIds: decisionIds,
    persisted: false,
    priorOnly: false,
  });
  return {
    commitId,
    reused: false,
    isFreshRoot: true,
    isCarriedPrior: false,
    resolvedRootCommitId: null,
    parsedAgainstRequiredParent: false,
    verifiedFreshRootPin: true,
    headerContract: fullParsed.headerKind,
    rowCount: allRows.length,
    parsed: fullParsed,
    newCommit,
    newDecisions: decisionRows,
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
  lineageTracker = null,
  parseOverlay = parseApprovalsFile,
  pythonPath = null,
  coherenceRepo = null,
  overlayCheckPath = DEFAULT_OVERLAY_CHECK,
  gitBin = '/usr/bin/git',
  allowedMissingCommits = [],
  tempBaseDir = tmpdir(),
}) {
  const effectiveConfig = normalizeImportConfig(importConfig);

  const pinnedFreshRoot = findPinnedFreshOverlayRoot(
    runItem.sourceFolder,
    effectiveConfig.freshOverlayRoots,
  );
  const pinnedCarriedPrior = findPinnedCarriedPrior(
    runItem.sourceFolder,
    effectiveConfig.carriedPriors,
  );
  const runLabel = `${runItem.origin}:${runItem.sourceFolder}`;
  const throwRunPrefixMismatch = (checkpointLabel, firstRow, detail) => {
    const mismatch = new AppError(
      `Overlay prefix mismatch in run ${runLabel} at checkpoint ${checkpointLabel}${detail ? `: ${detail}` : ''} (first differing row: ${firstRow}).`,
      422,
      'OVERLAY_PREFIX_MISMATCH',
    );
    mismatch.run = runLabel;
    mismatch.checkpoint = checkpointLabel;
    mismatch.firstDifferingRow = firstRow;
    throw mismatch;
  };
  if (pinnedCarriedPrior && runItem.origin === 'company_import') {
    throwRunPrefixMismatch(
      'input/Overlay/overlay.csv',
      1,
      `importConfig.carriedPriors applies only to legacy runs and cannot list company_import run ${pinnedCarriedPrior.sourceFolder}`,
    );
  }
  if (pinnedFreshRoot && runItem.origin === 'company_import') {
    throwRunPrefixMismatch(
      'overlay.csv',
      1,
      `importConfig.freshOverlayRoots applies only to legacy runs and standalone checkpoints and cannot list company_import run ${pinnedFreshRoot.sourceFolder}`,
    );
  }

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
      statementDate: runItem.statementDate,
      origin: runItem.origin,
      abandoned: Boolean(runItem.abandoned),
      commitArchiveFailures: [],
      overlayRoots: [],
      resolvedOverlayRoots: [],
      carriedPriors: [],
    };
  }

  const tracker = lineageTracker || await loadDecisionLineageTracker(pool);

  const runJsonRaw = await readFile(join(runItem.absPath, 'run.json'), 'utf8');
  const runJson = JSON.parse(runJsonRaw);
  const stepsObj = runJson.steps && typeof runJson.steps === 'object' ? runJson.steps : {};
  const stepsDone = ['assign', 'attribute', 'bible', 'adjust', 'emit'].filter((s) => Boolean(stepsObj[s]));

  const allowedMissingSet = new Set([...(allowedMissingCommits || []), ...effectiveConfig.allowedMissingCommits]);
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
  const hasPriorOverlayInput = inputFiles.some(
    (fullRel) => normalizeMacKey(fullRel.slice('input/'.length)) === 'overlay/overlay.csv',
  );
  if (pinnedCarriedPrior && !hasPriorOverlayInput) {
    throwRunPrefixMismatch(
      'input/Overlay/overlay.csv',
      1,
      `missing frozen prior input/Overlay/overlay.csv required by importConfig.carriedPriors for ${pinnedCarriedPrior.sourceFolder}`,
    );
  }
  const hasRunOverlayCheckpoints = nusearSaves.length > 0 || allFiles.some((rel) => {
    const k = normalizeMacKey(rel);
    return k === 'overlay.csv' || k === 'emits/overlay.csv';
  });
  if (runItem.origin === 'company_import' && !hasPriorOverlayInput && hasRunOverlayCheckpoints) {
    throwRunPrefixMismatch(
      'input/Overlay/overlay.csv',
      1,
      `company_import run ${runItem.sourceFolder} has overlay checkpoint(s) without a frozen prior input/Overlay/overlay.csv`,
    );
  }
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

  // Parse & prefix-chain every overlay checkpoint strictly via Coherence's Python reader into
  // decision_commits, decisions (with replaces_decision_id), generated_overlays, and approvals_files.
  const approvalsFiles = [];
  const decisionCommits = [];
  const decisions = [];
  const generatedOverlays = [];
  const reviewSaves = [];
  const overlayRoots = [];
  const resolvedOverlayRoots = [];
  const carriedPriors = [];
  const extraImportedFiles = [];
  const safeSourceFolder = String(runItem.sourceFolder || '').replace(/^\/+/, '').replace(/\/+/g, '/').replace(/\/+$/, '');

  let prevRunCommitId = null;
  let prevRunOverlayPath = null;
  let prevRunOverlaySha = null;
  let prevRunOverlayRowCount = 0;
  let priorDecisionCommitId = null;
  let freshRootVerified = false;
  const parseOpts = { pythonPath, coherenceRepo, overlayCheckPath, tempBaseDir };

  const ingestCheckpoint = async ({
    absPath,
    promotedFile,
    checkpointLabel,
    purpose,
    attemptStep = null,
    surface = null,
    reviewSaveId = null,
    originalAt = null,
    isRunStart = false,
    isPrior = false,
  }) => {
    if (!isPrior && isRunStart && runItem.origin === 'company_import') {
      throwRunPrefixMismatch(
        checkpointLabel,
        1,
        `company_import run ${runItem.sourceFolder} is missing frozen prior input/Overlay/overlay.csv`,
      );
    }
    const mode = isPrior
      ? (runItem.origin === 'company_import' ? 'exact_known_commit' : 'legacy_frozen_prior')
      : (isRunStart ? 'no_prior_run_start' : 'extend_run_parent');
    const requireParentId = mode === 'extend_run_parent' ? prevRunCommitId : null;
    const requireParentPath = mode === 'extend_run_parent' ? prevRunOverlayPath : null;
    const res = await resolveOverlayCheckpoint({
      tracker,
      absPath,
      fileSha256: promotedFile.sha256,
      checkpointLabel,
      runLabel,
      mode,
      requiredParentCommitId: requireParentId,
      requiredParentPath: requireParentPath,
      freshRootEntry: !isPrior && !freshRootVerified ? pinnedFreshRoot : null,
      carriedPriorEntry: isPrior && runItem.origin !== 'company_import' ? pinnedCarriedPrior : null,
      allowEmptyParentReattach: runItem.origin !== 'company_import',
      commitKind: 'historical_overlay',
      runId: '__THIS_RUN__',
      reviewSaveId,
      surface,
      decidedBy: 'historical_import',
      originalAt,
      parseOverlay,
      parseOpts,
      tempBaseDir,
    });
    if (res.verifiedFreshRootPin) freshRootVerified = true;

    if (res.newCommit) decisionCommits.push(res.newCommit);
    if (res.newDecisions.length) decisions.push(...res.newDecisions);
    if (res.isFreshRoot) {
      overlayRoots.push({
        folder: runItem.sourceFolder,
        folders: [runItem.sourceFolder],
        commitId: res.commitId,
        sha256: promotedFile.sha256,
        rowCount: res.rowCount,
      });
    } else if (res.resolvedRootCommitId) {
      resolvedOverlayRoots.push({
        folder: runItem.sourceFolder,
        commitId: res.resolvedRootCommitId,
        sha256: promotedFile.sha256,
        rowCount: res.rowCount,
      });
    }
    if (res.isCarriedPrior) {
      carriedPriors.push({
        folder: runItem.sourceFolder,
        commitId: res.commitId,
        parentCommitId: res.parentCommitId,
        sha256: promotedFile.sha256,
        rowsAdded: res.addedRowCount,
      });
      extraImportedFiles.push({
        area: 'other',
        relPath: `carried-priors/${safeSourceFolder}/overlay.csv`,
        artifactKind: 'data',
        storeKind: STORE_KINDS.DATA,
        fileSha256: promotedFile.sha256,
        originalAt,
        metadata: {
          carriedPrior: true,
          referenceAppend: true,
          reason: pinnedCarriedPrior?.reason ?? null,
          sourceFolder: runItem.sourceFolder,
          decisionCommitId: res.commitId,
          parentCommitId: res.parentCommitId,
          extendsRowCount: pinnedCarriedPrior?.extendsRowCount ?? null,
          rowsAdded: res.addedRowCount,
          rowCount: res.rowCount,
          headerContract: res.headerContract,
        },
      });
    }

    // Keep legacy approvals_files populated strictly without any silent prefix reset or invalid extends_sha256.
    if (!approvalsFiles.some((af) => af.fileSha256 === promotedFile.sha256)) {
      const canExtendPrevRunFile = Boolean(
        !isRunStart
        && prevRunOverlaySha
        && prevRunOverlaySha !== promotedFile.sha256
        && prevRunOverlayRowCount > 0
        && res.parsedAgainstRequiredParent
        && res.parsed.sharedRowCount === prevRunOverlayRowCount,
      );
      const sameRunExtends = canExtendPrevRunFile ? prevRunOverlaySha : null;
      const afParsed = sameRunExtends
        ? res.parsed
        : await parseOverlay(absPath, { ...parseOpts, parentPath: null });
      approvalsFiles.push({
        fileSha256: promotedFile.sha256,
        headerKind: afParsed.headerKind,
        rowCount: afParsed.rowCount,
        extendsSha256: sameRunExtends,
        sharedRowCount: sameRunExtends ? afParsed.sharedRowCount : 0,
        addedRows: afParsed.addedRows,
      });
    }

    generatedOverlays.push({
      id: randomUUID(),
      decisionCommitId: res.commitId,
      purpose,
      attemptStep,
      headerContract: res.headerContract,
      rowCount: res.rowCount,
      fileSha256: promotedFile.sha256,
    });

    prevRunCommitId = res.commitId;
    prevRunOverlayPath = absPath;
    prevRunOverlaySha = promotedFile.sha256;
    prevRunOverlayRowCount = res.rowCount;
    return res;
  };

  if (priorOverlayAbsPath && priorOverlaySha) {
    const priorStored = storedFiles.find((f) => f.sha256 === priorOverlaySha);
    const priorInfo = await stat(priorOverlayAbsPath);
    const priorRes = await ingestCheckpoint({
      absPath: priorOverlayAbsPath,
      promotedFile: priorStored,
      checkpointLabel: 'input/Overlay/overlay.csv',
      purpose: 'prior_input',
      originalAt: priorInfo.mtime.toISOString(),
      isRunStart: true,
      isPrior: true,
    });
    if (pinnedFreshRoot && priorRes.rowCount > 0) {
      throwRunPrefixMismatch(
        'input/Overlay/overlay.csv',
        1,
        `folder listed in importConfig.freshOverlayRoots (${pinnedFreshRoot.sourceFolder}) cannot have a non-empty frozen prior`,
      );
    }
    priorDecisionCommitId = priorRes.commitId;
  }

  const orderedSaves = [...nusearSaves].sort((a, b) => a.originalAt.localeCompare(b.originalAt));
  if (orderedSaves.length > 0) {
    for (const save of orderedSaves) {
      const bytes = await readFile(save.absPath);
      const promoted = await stores.dataStore.promoteBytes(bytes, { relPath: 'overlay.csv', checksPassed: true });
      storedFiles.push(promoted);
      const saveId = randomUUID();
      const canAttachSave = stepsDone.includes(save.surface);
      const res = await ingestCheckpoint({
        absPath: save.absPath,
        promotedFile: promoted,
        checkpointLabel: save.filename,
        purpose: save.surface === 'bible' ? 'bible_review' : 'adjust_review',
        attemptStep: canAttachSave ? save.surface : null,
        surface: canAttachSave ? save.surface : null,
        reviewSaveId: canAttachSave ? saveId : null,
        originalAt: save.originalAt,
        isRunStart: prevRunCommitId === null,
      });
      if (canAttachSave) {
        reviewSaves.push({
          id: saveId,
          surface: save.surface,
          approvalsFileSha256: promoted.sha256,
          decisionCommitId: res.commitId,
          originalAt: save.originalAt,
        });
      }
    }
  } else {
    // Historical runs without individual timestamped review saves fall back to root overlay.csv, else emits/overlay.csv.
    const fallbackRel = allFiles.includes('overlay.csv')
      ? 'overlay.csv'
      : (allFiles.includes('emits/overlay.csv') ? 'emits/overlay.csv' : null);
    if (fallbackRel) {
      const absPath = join(runItem.absPath, ...fallbackRel.split('/'));
      const info = await stat(absPath);
      const bytes = await readFile(absPath);
      const promoted = await stores.dataStore.promoteBytes(bytes, { relPath: fallbackRel, checksPassed: true });
      storedFiles.push(promoted);
      const surface = stepsDone.includes('adjust') ? 'adjust' : 'bible';
      const canAttachSave = stepsDone.includes(surface);
      const saveId = randomUUID();
      const res = await ingestCheckpoint({
        absPath,
        promotedFile: promoted,
        checkpointLabel: fallbackRel,
        purpose: fallbackRel === 'emits/overlay.csv' ? 'emit_output' : 'historical_source',
        attemptStep: canAttachSave ? surface : null,
        surface: canAttachSave ? surface : null,
        reviewSaveId: canAttachSave ? saveId : null,
        originalAt: info.mtime.toISOString(),
        isRunStart: prevRunCommitId === null,
      });
      if (canAttachSave) {
        reviewSaves.push({
          id: saveId,
          surface,
          approvalsFileSha256: promoted.sha256,
          decisionCommitId: res.commitId,
          originalAt: info.mtime.toISOString(),
        });
      }
    }
  }

  // If root overlay.csv exists alongside timestamped review saves and differs from the last save, verify prefix and record it.
  if (orderedSaves.length > 0 && allFiles.includes('overlay.csv')) {
    const absPath = join(runItem.absPath, 'overlay.csv');
    const bytes = await readFile(absPath);
    const promoted = await stores.dataStore.promoteBytes(bytes, { relPath: 'overlay.csv', checksPassed: true });
    storedFiles.push(promoted);
    if (promoted.sha256 !== prevRunOverlaySha) {
      const info = await stat(absPath);
      await ingestCheckpoint({
        absPath,
        promotedFile: promoted,
        checkpointLabel: 'overlay.csv',
        purpose: 'historical_source',
        originalAt: info.mtime.toISOString(),
        isRunStart: prevRunCommitId === null,
      });
    }
  }

  const byStep = partitionRunFilesByStep(allFiles, stepsDone);
  const stepAttempts = [];
  const reviewQueueItems = [];

  if (stepsDone.length === 0) {
    // Partly finished run where no step completed in run.json: retain every non-input file
    // via imported_files (routed strictly through promoteArtifact for code/data separation)
    // so Layer 1 rebuilds the run folder byte for byte.
    const nonInputFiles = allFiles.filter((rel) => !rel.startsWith('input/'));
    for (const relPath of nonInputFiles) {
      const absPath = join(runItem.absPath, ...relPath.split('/'));
      const info = await stat(absPath);
      const bytes = await readFile(absPath);
      const promoted = await stores.promoteArtifact(relPath, bytes, { checksPassed: true });
      storedFiles.push(promoted);
      if (relPath === 'emits/overlay.csv') {
        const alreadyRecordedEmitReceipt = generatedOverlays.some(
          (go) => go.purpose === 'emit_output' && go.fileSha256 === promoted.sha256,
        );
        if (!alreadyRecordedEmitReceipt) {
          await ingestCheckpoint({
            absPath,
            promotedFile: promoted,
            checkpointLabel: 'emits/overlay.csv',
            purpose: 'emit_output',
            attemptStep: null,
            originalAt: info.mtime.toISOString(),
            isRunStart: prevRunCommitId === null,
          });
        }
      }
      const safeSource = String(runItem.sourceFolder || '').replace(/^\/+/, '').replace(/\/+/g, '/').replace(/\/+$/, '');
      extraImportedFiles.push({
        area: 'other',
        relPath: `run-partial-files/${safeSource}/${relPath}`,
        artifactKind: promoted.artifactKind,
        storeKind: promoted.storeKind,
        fileSha256: promoted.sha256,
        originalAt: info.mtime.toISOString(),
        metadata: {
          runId: '__THIS_RUN__',
          runRelPath: relPath,
          partialRunArtifact: true,
        },
      });
    }
  }

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
      if (relPath === 'bible.csv' && step === 'bible') {
        reviewQueueItems.push(...parseReviewQueueCsv(bytes.toString('utf8'), 'bible'));
      } else if (relPath === 'adjust.csv' && step === 'adjust') {
        reviewQueueItems.push(...parseReviewQueueCsv(bytes.toString('utf8'), 'adjust'));
      }
      if (relPath === 'emits/overlay.csv') {
        const alreadyRecordedEmitReceipt = generatedOverlays.some(
          (go) => go.purpose === 'emit_output' && go.fileSha256 === promoted.sha256,
        );
        if (!alreadyRecordedEmitReceipt) {
          const info = await stat(absPath);
          await ingestCheckpoint({
            absPath,
            promotedFile: promoted,
            checkpointLabel: 'emits/overlay.csv',
            purpose: 'emit_output',
            attemptStep: 'emit',
            originalAt: info.mtime.toISOString(),
            isRunStart: prevRunCommitId === null,
          });
        }
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

  if (pinnedFreshRoot && !freshRootVerified) {
    throwRunPrefixMismatch(
      'overlay.csv',
      1,
      `folder listed in importConfig.freshOverlayRoots (${pinnedFreshRoot.sourceFolder}) finished without any checkpoint verified against its pinned SHA-256`,
    );
  }

  const emitSettings = inferEmitSettings(runItem, allFiles, effectiveConfig);
  const cmdKey = makeHashedCommandKey('import-run', [runItem.origin, runItem.sourceFolder]);
  const abandonmentSpec = runItem.abandoned && runItem.origin === 'company_import'
    ? {
      typedPhrase: `abandon ${runItem.statementDate}`,
      reason: `Imported abandoned company run from ${runItem.sourceFolder}`,
    }
    : null;
  const res = await commands.importHistoricalRun({
    actor,
    commandKey: cmdKey,
    run: {
      origin: runItem.origin,
      statementDate: runItem.statementDate,
      folderNumber: 1,
      sourceFolder: runItem.sourceFolder,
      priorDecisionCommitId,
      rerunReason: runItem.abandoned ? `Imported abandoned run from ${runItem.sourceFolder}` : null,
      ...emitSettings,
    },
    inputVersion: { reason: `Imported frozen input from ${runItem.sourceFolder}` },
    inputEntries,
    approvalsFiles,
    decisionCommits,
    decisions,
    generatedOverlays,
    reviewQueueItems,
    stepAttempts,
    reviewSaves,
    storedFiles,
    extraImportedFiles,
    abandonment: abandonmentSpec,
  });

  return {
    runId: res.result.runId,
    alreadyImported: Boolean(res.result.alreadyImported || res.idempotent),
    sourceFolder: runItem.sourceFolder,
    statementDate: runItem.statementDate,
    origin: runItem.origin,
    abandoned: Boolean(runItem.abandoned),
    stepsDone,
    inputFiles: inputEntries.length,
    steps: stepAttempts.length,
    reviewSaves: reviewSaves.length,
    decisionCommits: decisionCommits.length,
    decisions: decisions.length,
    generatedOverlays: generatedOverlays.length,
    journalSeq: res.journalSeq,
    commitArchiveFailures,
    overlayRoots,
    resolvedOverlayRoots,
    carriedPriors,
  };
}

async function verifyDirectoryRebuild({ sourceDir, expectedFiles, rebuiltDir }) {
  const origHashes = {};
  for (const rel of expectedFiles) {
    origHashes[rel] = fingerprintBytes(await readFile(join(sourceDir, ...rel.split('/')))).sha256;
  }
  const rebuiltFiles = await listFilesRecursive(rebuiltDir);
  const rebuiltHashes = {};
  for (const rel of rebuiltFiles) {
    rebuiltHashes[rel] = fingerprintBytes(await readFile(join(rebuiltDir, ...rel.split('/')))).sha256;
  }
  const onlySource = expectedFiles.filter((f) => !(f in rebuiltHashes));
  const onlyRebuilt = rebuiltFiles.filter((f) => !(f in origHashes));
  const changed = expectedFiles.filter((f) => f in rebuiltHashes && origHashes[f] !== rebuiltHashes[f]);
  return {
    files: expectedFiles.length,
    passed: onlySource.length === 0 && onlyRebuilt.length === 0 && changed.length === 0,
    onlySource: onlySource.slice(0, 10),
    onlyRebuilt: onlyRebuilt.slice(0, 10),
    changed: changed.slice(0, 10),
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
  readLegacyStatements = readLegacyStatementBatches,
  pythonPath = null,
  coherenceRepo = null,
  overlayCheckPath = null,
  legacyBridgePath = null,
  gitBin = '/usr/bin/git',
  allowedMissingCommits = [],
  nusearSqlitePath = null,
  verifyRebuild = true,
  recordCheck = true,
  tempBaseDir = tmpdir(),
}) {
  const effectiveConfig = normalizeImportConfig(importConfig || manifest.importConfig || {});
  const resolvedPythonPath = pythonPath || manifest.pythonPath || null;
  const resolvedCoherenceRepo = coherenceRepo || manifest.coherenceRepo || null;
  const resolvedOverlayCheckPath = overlayCheckPath || manifest.overlayCheckPath || DEFAULT_OVERLAY_CHECK;
  const resolvedLegacyBridgePath = legacyBridgePath || manifest.legacyBridgePath || DEFAULT_LEGACY_STATEMENTS_BRIDGE;
  const resolvedSqlitePath = nusearSqlitePath || manifest.sqlitePath || null;
  const mergedAllowedMissing = [...new Set([...(allowedMissingCommits || []), ...effectiveConfig.allowedMissingCommits])];

  const report = {
    companySlug: manifest.companySlug,
    importedRuns: [],
    skippedRuns: [],
    commitArchiveFailures: [],
    overlayRoots: [],
    carriedPriors: [],
    companySentCarries: [],
    currentInputVersionId: null,
    standingDecisionCommitId: null,
    standaloneFilesImported: 0,
    standaloneOverlayCommits: 0,
    preCoherenceBatchesImported: 0,
    methodCorrectionBatchesImported: 0,
    nusearRecordsImported: 0,
    rebuildChecks: [],
    standingInputRebuildCheck: null,
    incidentReportRebuildCheck: null,
    standaloneRebuildCheck: null,
    objectCheck: null,
    sqliteParity: { source: manifest.sqliteCounts || {}, imported: {} },
    passed: true,
    problems: [],
  };

  const lineageTracker = await loadDecisionLineageTracker(pool);

  // Merge all runs and manifest standalone overlay checkpoints into one chronological timeline
  // (by each run's recorded start, drafts/archives/abandoned before the primary run) so a valid
  // shorter prefix never runs after a longer descendant and fails to find its ancestor.
  const rawRunEntries = [
    ...(manifest.macRuns || []).map((r) => ({
      item: r,
      saves: r.sourceFolder === r.statementDate ? (manifest.nusearMacSaves?.[r.statementDate] || []) : [],
    })),
    ...(manifest.companyRuns || []).map((r) => ({ item: r, saves: manifest.nusearCompanySaves?.[r.statementDate] || [] })),
    ...(manifest.abandonedRuns || []).map((r) => ({ item: r, saves: [] })),
  ];

  const timelineItems = [];
  for (const { item, saves } of rawRunEntries) {
    const draftRank = isDraftOrArchiveRun(item) ? 0 : 1;
    const recordedStartMs = await readRunRecordedStartMs(item.absPath);
    const fallbackMs = Date.parse(`${item.statementDate}T${draftRank === 0 ? '00:00:00.000' : '12:00:00.000'}Z`);
    timelineItems.push({
      kind: 'run',
      item,
      saves,
      statementDate: item.statementDate,
      draftRank,
      originRank: item.origin === 'mac_import' ? 0 : 1,
      sortTimeMs: recordedStartMs ?? fallbackMs,
      tieKey: item.sourceFolder,
    });
  }

  for (const cp of (manifest.overlayCheckpoints || [])) {
    const absPath = cp.absPath || cp.path;
    const label = cp.label || cp.relPath || absPath;
    const info = await stat(absPath);
    const parsedNameTs = parseReviewSaveTimestamp(basename(absPath))?.originalAt || null;
    const originalAtIso = parseLocalRunJsonTime(cp.originalAt)
      || parsedNameTs
      || (cp.statementDate && isValidIsoDate(cp.statementDate) ? `${cp.statementDate}T00:00:00.000Z` : null)
      || info.mtime.toISOString();
    const sortTimeMs = parseTimestampMs(originalAtIso) ?? info.mtimeMs;
    const cpDate = (cp.statementDate && isValidIsoDate(cp.statementDate))
      ? cp.statementDate
      : new Date(sortTimeMs).toISOString().slice(0, 10);
    timelineItems.push({
      kind: 'checkpoint',
      cp,
      absPath,
      label,
      info,
      originalAtIso,
      statementDate: cpDate,
      draftRank: 0,
      originRank: -1,
      sortTimeMs,
      tieKey: label,
    });
  }

  timelineItems.sort((a, b) => (
    (a.sortTimeMs - b.sortTimeMs)
    || a.statementDate.localeCompare(b.statementDate)
    || (a.draftRank - b.draftRank)
    || (a.originRank - b.originRank)
    || a.tieKey.localeCompare(b.tieKey)
  ));

  const allRuns = timelineItems.filter((entry) => entry.kind === 'run');
  const parseOpts = {
    pythonPath: resolvedPythonPath,
    coherenceRepo: resolvedCoherenceRepo,
    overlayCheckPath: resolvedOverlayCheckPath,
    tempBaseDir,
  };
  const runIdBySource = new Map();
  const standaloneOverlayArchive = [];
  const overlayRootsByCommitId = new Map();
  const recordCreatedRoot = (root) => {
    const existing = overlayRootsByCommitId.get(root.commitId);
    if (existing) {
      for (const f of (root.folders && root.folders.length ? root.folders : [root.folder])) {
        if (!existing.folders.includes(f)) existing.folders.push(f);
      }
      return;
    }
    const entry = {
      folder: root.folder,
      folders: [...new Set(root.folders && root.folders.length ? root.folders : [root.folder])],
      commitId: root.commitId,
      sha256: root.sha256,
      rowCount: root.rowCount,
    };
    overlayRootsByCommitId.set(root.commitId, entry);
    report.overlayRoots.push(entry);
  };
  const recordResolvedRoot = (resolved) => {
    const existing = overlayRootsByCommitId.get(resolved.commitId);
    if (existing && !existing.folders.includes(resolved.folder)) {
      existing.folders.push(resolved.folder);
    }
  };

  // PIN TARGETS, BEFORE ANY WRITE (the round 5 and 6 reviews, matching --plan): every freshOverlayRoots pin names a legacy run or a
  // standalone checkpoint that does not extend a commit, and every carriedPriors pin names a legacy run. A pin naming nothing found
  // (a missing folder or one that lost its run.json) or the wrong kind fails here, before any file or row is written.
  {
    // Sets of every target of each kind, so a key that two items share is judged by all of them, whatever the timeline order.
    const legacyRuns = new Set(), otherRuns = new Set(), plainCheckpoints = new Set(), extendingCheckpoints = new Set();
    for (const e of timelineItems) {
      if (e.kind === 'run') (e.item.origin === 'mac_import' ? legacyRuns : otherRuns).add(e.item.sourceFolder);
      else (e.cp.extendsCommitId ? extendingCheckpoints : plainCheckpoints).add(safeOverlayCheckpointRelPath(e.label, e.absPath));
    }
    const unmetPins = [];
    for (const pin of effectiveConfig.freshOverlayRoots || []) {
      const sf = pin.sourceFolder;
      if (otherRuns.has(sf)) unmetPins.push(`importConfig.freshOverlayRoots ${sf} names a company run`);
      else if (extendingCheckpoints.has(sf)) unmetPins.push(`importConfig.freshOverlayRoots ${sf} names a checkpoint that extends a commit`);
      else if (!legacyRuns.has(sf) && !plainCheckpoints.has(sf)) unmetPins.push(`importConfig.freshOverlayRoots ${sf}`);
    }
    for (const pin of effectiveConfig.carriedPriors || []) {
      const sf = pin.sourceFolder;
      if (otherRuns.has(sf)) unmetPins.push(`importConfig.carriedPriors ${sf} names a company run`);
      else if (plainCheckpoints.has(sf) || extendingCheckpoints.has(sf)) unmetPins.push(`importConfig.carriedPriors ${sf} names a standalone checkpoint`);
      else if (!legacyRuns.has(sf)) unmetPins.push(`importConfig.carriedPriors ${sf}`);
    }
    if (unmetPins.length > 0) {
      const unmet = new AppError(
        `Overlay prefix mismatch: pinned overlay folders not found in this import, or of the wrong kind: ${unmetPins.join('; ')}.`,
        422,
        'OVERLAY_PREFIX_MISMATCH',
      );
      unmet.unmetPins = unmetPins;
      throw unmet;
    }
  }

  for (const entry of timelineItems) {
    if (entry.kind === 'run') {
      const { item, saves } = entry;
      const res = await importSingleRunFolder({
        pool,
        stores,
        commands,
        actor,
        companySlug: manifest.companySlug,
        runItem: item,
        nusearSaves: saves,
        importConfig: effectiveConfig,
        lineageTracker,
        parseOverlay,
        pythonPath: resolvedPythonPath,
        coherenceRepo: resolvedCoherenceRepo,
        overlayCheckPath: resolvedOverlayCheckPath,
        gitBin,
        allowedMissingCommits: mergedAllowedMissing,
        tempBaseDir,
      });
      runIdBySource.set(`${item.origin}:${item.sourceFolder}`, res);
      if (res.overlayRoots && res.overlayRoots.length > 0) {
        for (const root of res.overlayRoots) recordCreatedRoot(root);
      }
      if (res.resolvedOverlayRoots && res.resolvedOverlayRoots.length > 0) {
        for (const resolved of res.resolvedOverlayRoots) recordResolvedRoot(resolved);
      }
      if (res.carriedPriors && res.carriedPriors.length > 0) {
        report.carriedPriors.push(...res.carriedPriors);
      }
      if (res.commitArchiveFailures && res.commitArchiveFailures.length > 0) {
        report.commitArchiveFailures.push(...res.commitArchiveFailures);
        for (const fail of res.commitArchiveFailures) {
          report.problems.push(`Failed to archive git commit ${fail.commit} for ${fail.sourceFolder}: ${fail.error}`);
        }
      }
      if (res.alreadyImported) report.skippedRuns.push(res);
      else report.importedRuns.push(res);
    } else {
      const { cp, absPath, label, originalAtIso } = entry;
      if (cp?.allowDisjointRoot) {
        throw new AppError(
          'overlayCheckpoints entries cannot set allowDisjointRoot: true; pin explicit fresh roots in importConfig.freshOverlayRoots instead.',
          400,
          'DISJOINT_OVERLAY_ROOTS_FORBIDDEN',
        );
      }
      const relArchivePath = safeOverlayCheckpointRelPath(label, absPath);
      const cpPinnedCarriedPrior = findPinnedCarriedPrior(relArchivePath, effectiveConfig.carriedPriors);
      if (cpPinnedCarriedPrior) {
        const mismatch = new AppError(
          `Overlay prefix mismatch in run ${cp.runLabel || 'manifest_checkpoint'} at checkpoint ${label}: importConfig.carriedPriors applies only to legacy runs and cannot list standalone checkpoint ${cpPinnedCarriedPrior.sourceFolder} (first differing row: 1).`,
          422,
          'OVERLAY_PREFIX_MISMATCH',
        );
        mismatch.run = cp.runLabel || 'manifest_checkpoint';
        mismatch.checkpoint = label;
        mismatch.firstDifferingRow = 1;
        throw mismatch;
      }
      const cpPinnedFreshRoot = findPinnedFreshOverlayRoot(relArchivePath, effectiveConfig.freshOverlayRoots);
      if (cp.extendsCommitId && cpPinnedFreshRoot) {
        const mismatch = new AppError(
          `Overlay prefix mismatch in run ${cp.runLabel || 'manifest_checkpoint'} at checkpoint ${label}: checkpoint with extendsCommitId cannot be listed in importConfig.freshOverlayRoots (${cpPinnedFreshRoot.sourceFolder}) (first differing row: 1).`,
          422,
          'OVERLAY_PREFIX_MISMATCH',
        );
        mismatch.run = cp.runLabel || 'manifest_checkpoint';
        mismatch.checkpoint = label;
        mismatch.firstDifferingRow = 1;
        throw mismatch;
      }
      const bytes = await readFile(absPath);
      const promoted = await stores.dataStore.promoteBytes(bytes, { relPath: 'overlay.csv', checksPassed: true });

      const existingImp = await pool.query(
        "SELECT id, metadata FROM coherence.imported_files WHERE area = 'other' AND rel_path = $1 AND file_sha256 = $2",
        [relArchivePath, promoted.sha256],
      );
      if (existingImp.rows.length > 0) continue;

      const cpFreshRootEntry = cp.extendsCommitId ? null : cpPinnedFreshRoot;
      const res = await resolveOverlayCheckpoint({
        tracker: lineageTracker,
        absPath,
        fileSha256: promoted.sha256,
        checkpointLabel: label,
        runLabel: cp.runLabel || 'manifest_checkpoint',
        mode: cp.extendsCommitId ? 'extend_run_parent' : 'no_prior_run_start',
        requiredParentCommitId: cp.extendsCommitId || null,
        freshRootEntry: cpFreshRootEntry,
        allowEmptyParentReattach: false,
        commitKind: 'historical_overlay',
        runId: null,
        reviewSaveId: null,
        surface: null,
        decidedBy: cp.actor || 'historical_import',
        originalAt: originalAtIso,
        parseOverlay,
        parseOpts,
        tempBaseDir,
      });

      if (res.isFreshRoot) {
        recordCreatedRoot({
          folder: relArchivePath,
          folders: [relArchivePath],
          commitId: res.commitId,
          sha256: promoted.sha256,
          rowCount: res.rowCount,
        });
      } else if (res.resolvedRootCommitId) {
        recordResolvedRoot({
          folder: relArchivePath,
          commitId: res.resolvedRootCommitId,
          sha256: promoted.sha256,
          rowCount: res.rowCount,
        });
      }

      if (res.newCommit) {
        await commands.recordDecisionBaseline({
          actor,
          commandKey: makeHashedCommandKey('import-overlay-checkpoint', [manifest.companySlug, label, promoted.sha256]),
          decisionCommitId: res.commitId,
          parentCommitId: res.newCommit.parentCommitId,
          commitKind: res.newCommit.commitKind,
          headerContract: res.headerContract,
          imported: true,
          originalAt: res.newCommit.originalAt,
          decisions: res.newDecisions,
        });
        report.standaloneOverlayCommits += 1;
      }

      standaloneOverlayArchive.push({
        file: {
          area: 'other',
          relPath: relArchivePath,
          artifactKind: 'data',
          storeKind: STORE_KINDS.DATA,
          fileSha256: promoted.sha256,
          originalAt: originalAtIso,
          metadata: {
            overlayCheckpoint: true,
            decisionCommitId: res.commitId,
            headerContract: res.headerContract,
            rowCount: res.rowCount,
            byteSize: promoted.byteSize,
          },
        },
        storedFile: promoted,
      });
    }
  }
  if (standaloneOverlayArchive.length > 0) {
    const keyHash = sha256Hex(JSON.stringify(standaloneOverlayArchive.map((x) => [x.file.relPath, x.file.fileSha256]).sort()));
    await commands.importStandaloneFiles({
      actor,
      commandKey: makeHashedCommandKey('import-overlay-checkpoints-archive', [manifest.companySlug, keyHash]),
      files: standaloneOverlayArchive.map((x) => x.file),
      storedFiles: standaloneOverlayArchive.map((x) => x.storedFile),
    });
  }

  // Prepare environment-proven sent markers for non-abandoned company_import runs (applied after standing input base exists).
  const companySentRecords = manifest.companySentRecords || {};
  const declaredSentKeys = new Set();
  const pendingCompanySentCarries = [];
  const handledSentDates = new Set();
  for (const item of (manifest.companyRuns || [])) {
    if (item.abandoned) continue;
    const sentProv = companySentRecords[item.statementDate] || item.sentProvenance || null;
    if (!sentProv || sentProv.sent === false) continue;

    handledSentDates.add(item.statementDate);
    const imported = runIdBySource.get(`${item.origin}:${item.sourceFolder}`);
    if (!imported?.runId) {
      report.problems.push(`Declared sent record for ${item.statementDate} (${item.sourceFolder}) has no imported run.`);
      continue;
    }

    const expectedStatementsRel = `emits/statements_${item.statementDate.replaceAll('-', '')}.csv`;
    const emitCheck = await pool.query(
      `SELECT e.id, a.file_sha256
       FROM coherence.step_attempt_events e
       JOIN coherence.artifacts a ON a.attempt_event_id = e.id
       WHERE e.run_id = $1::uuid AND e.step = 'emit' AND e.event_kind = 'finished'
         AND a.rel_path = $2
       LIMIT 1`,
      [imported.runId, expectedStatementsRel],
    );
    if (emitCheck.rows.length === 0) {
      report.problems.push(
        `Declared sent record for ${item.statementDate} (${item.sourceFolder}) has no finished Emit statements file (${expectedStatementsRel}).`,
      );
      continue;
    }

    const sentMacKey = `sent/statements_${item.statementDate.replaceAll('-', '')}.csv`;
    // Always exclude every manifest-declared sent date with a finished Emit from standing base entries
    // whether or not its carry already exists in PostgreSQL, keeping re-import idempotent.
    declaredSentKeys.add(sentMacKey);

    const existingCarry = await pool.query(
      "SELECT id FROM coherence.carries WHERE statement_date = $1::date AND carry_kind = 'sent'",
      [item.statementDate],
    );
    if (existingCarry.rows.length > 0) {
      report.companySentCarries.push({
        runId: imported.runId,
        statementDate: item.statementDate,
        alreadyRecorded: true,
        source: sentProv.source || 'company-environment',
      });
      continue;
    }

    pendingCompanySentCarries.push({
      runId: imported.runId,
      item,
      sentProv,
      sentMacKey,
    });
  }

  for (const [sentDate, sentProv] of Object.entries(companySentRecords)) {
    if (!sentProv || sentProv.sent === false) continue;
    if (!handledSentDates.has(sentDate)) {
      report.problems.push(`Declared sent record for ${sentDate} has no matching non-abandoned company run with a statements file.`);
    }
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
      const info = await stat(overlayAbs);
      const existingStandingCommit = await pool.query(
        "SELECT metadata->>'decisionCommitId' AS commit_id FROM coherence.imported_files WHERE area = 'other' AND rel_path = 'standing-overlay/overlay.csv' AND file_sha256 = $1",
        [overlayStored.sha256],
      );
      let expectedStandingCommitId;
      if (existingStandingCommit.rows.length > 0 && existingStandingCommit.rows[0].commit_id) {
        expectedStandingCommitId = existingStandingCommit.rows[0].commit_id;
      } else {
        const standingRes = await resolveOverlayCheckpoint({
          tracker: lineageTracker,
          absPath: overlayAbs,
          fileSha256: overlayStored.sha256,
          checkpointLabel: 'standing:input/Overlay/overlay.csv',
          runLabel: 'standing_input',
          mode: 'exact_known_commit',
          requiredParentCommitId: null,
          freshRootEntry: null,
          commitKind: 'historical_baseline',
          runId: null,
          reviewSaveId: null,
          surface: null,
          decidedBy: 'historical_import',
          originalAt: info.mtime.toISOString(),
          parseOverlay,
          parseOpts,
          tempBaseDir,
        });
        const parsed = await parseOverlay(overlayAbs, { ...parseOpts, parentPath: null });
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
        let standingCommitId = standingRes.commitId;
        if (standingRes.newCommit) {
          await commands.recordDecisionBaseline({
            actor,
            commandKey: `import-standing-decision-head:${manifest.companySlug}:${overlayStored.sha256}`,
            decisionCommitId: standingRes.commitId,
            parentCommitId: standingRes.newCommit.parentCommitId,
            commitKind: 'historical_baseline',
            headerContract: standingRes.headerContract,
            imported: true,
            originalAt: standingRes.newCommit.originalAt,
            decisions: standingRes.newDecisions,
          });
        } else {
          // Ensure standing_decision_head_as_of resolves to this commit by recording a 0-row baseline head pointer if needed.
          const currentHead = (await pool.query('SELECT coherence.standing_decision_head_as_of(NULL) AS id')).rows[0]?.id;
          if (currentHead !== standingCommitId) {
            const headId = randomUUID();
            const baselineRes = await commands.recordDecisionBaseline({
              actor,
              commandKey: `import-standing-decision-head:${manifest.companySlug}:${overlayStored.sha256}`,
              decisionCommitId: headId,
              parentCommitId: standingCommitId,
              commitKind: 'historical_baseline',
              headerContract: standingRes.headerContract,
              imported: true,
              originalAt: info.mtime.toISOString(),
              decisions: [],
            });
            standingCommitId = baselineRes.result.decisionCommitId;
            lineageTracker.registerCommit({
              id: standingCommitId,
              parentCommitId: standingRes.commitId,
              commitKind: 'historical_baseline',
              headerContract: standingRes.headerContract,
              addedRows: [],
              addedDecisionIds: [],
              persisted: true,
            });
          }
        }
        expectedStandingCommitId = standingCommitId;
        await commands.importStandaloneFiles({
          actor,
          commandKey: `import-standing-overlay-receipt:${manifest.companySlug}:${overlayStored.sha256}`,
          files: [{
            area: 'other',
            relPath: 'standing-overlay/overlay.csv',
            artifactKind: 'data',
            storeKind: STORE_KINDS.DATA,
            fileSha256: overlayStored.sha256,
            originalAt: info.mtime.toISOString(),
            metadata: {
              overlayCheckpoint: true,
              standingHead: true,
              decisionCommitId: standingCommitId,
              headerContract: standingRes.headerContract,
              rowCount: standingRes.rowCount,
            },
          }],
          storedFiles: [overlayStored],
        });
      }
      const verifiedStandingHead = (await pool.query('SELECT coherence.standing_decision_head_as_of(NULL) AS id')).rows[0]?.id ?? null;
      if (verifiedStandingHead !== expectedStandingCommitId) {
        throw new AppError(
          `Standing decision head mismatch: standing_decision_head_as_of(NULL) returned ${verifiedStandingHead ?? 'NULL'}, expected ${expectedStandingCommitId}.`,
          422,
          'STANDING_DECISION_HEAD_MISMATCH',
        );
      }
      report.standingDecisionCommitId = verifiedStandingHead;
    }

    const baseEntries = entries.filter((e) => !declaredSentKeys.has(normalizeMacKey(e.relPath)));
    const entriesDigest = sha256Hex(JSON.stringify(baseEntries.map((e) => [e.relPath, e.fileSha256]).sort()));
    const ivRes = await commands.publishInputVersion({
      actor,
      commandKey: `import-current-input:${manifest.companySlug}:${entriesDigest}`,
      lineKind: 'standing',
      sourceKind: effectiveConfig.currentInputSourceKind,
      reason: `Import current standing input from ${manifest.currentInputDir}`,
      entries: baseEntries,
      storedFiles,
    });
    report.currentInputVersionId = ivRes.result.inputVersionId;
    if (entries.length !== baseEntries.length && pendingCompanySentCarries.length === 0) {
      const headRes = await pool.query('SELECT coherence.standing_input_version_as_of(NULL) AS id');
      if (headRes.rows[0]?.id) {
        report.currentInputVersionId = headRes.rows[0].id;
      }
    }
  }

  // Record environment-proven sent markers for non-abandoned company_import runs (never dropped, never upgraded).
  if (pendingCompanySentCarries.length > 0) {
    const existingStanding = await pool.query(
      "SELECT id FROM coherence.input_versions WHERE line_kind = 'standing' ORDER BY journal_seq DESC LIMIT 1",
    );
    if (existingStanding.rows.length === 0) {
      await commands.publishInputVersion({
        actor,
        commandKey: `import-standing-base:${manifest.companySlug}`,
        lineKind: 'standing',
        sourceKind: 'company_import',
        reason: 'Initialize standing input base prior to importing company environment sent markers',
        entries: [],
        storedFiles: [],
      });
    }
    for (const pending of pendingCompanySentCarries) {
      const { runId, item, sentProv } = pending;
      const sourceRef = sentProv.source || 'company-environment';
      const carryRes = await commands.carrySent({
        actor,
        commandKey: makeHashedCommandKey('import-company-sent', [manifest.companySlug, item.sourceFolder, item.statementDate]),
        runId,
        typedPhrase: `sent ${item.statementDate}`,
        reason: `Imported company environment sent marker for ${item.statementDate} from ${sourceRef}`,
        provenance: {
          sourceFolder: item.sourceFolder,
          statementDate: item.statementDate,
          ...sentProv,
        },
      });
      report.companySentCarries.push({
        runId,
        carryId: carryRes.result.carryId,
        statementDate: item.statementDate,
        alreadyRecorded: Boolean(carryRes.idempotent),
        source: sourceRef,
      });
      if (manifest.currentInputFiles.some((rel) => normalizeMacKey(rel) === pending.sentMacKey)) {
        report.currentInputVersionId = carryRes.result.publishedInputVersionId;
      }
    }
  }

  // Import standalone files (Incident Report, company environment audit/replaced/finished/answer-keys, cloud mirror, logs).
  const standaloneAll = [...(manifest.incidentReportFiles || []), ...(manifest.standaloneFiles || [])];
  if (standaloneAll.length > 0) {
    const files = [];
    const storedFiles = [];
    for (const f of standaloneAll) {
      const bytes = await readFile(f.absPath);
      const fp = fingerprintBytes(bytes);
      if (f.verifySha256FromName && fp.sha256 !== f.verifySha256FromName) {
        throw new AppError(
          `Cloud mirror object ${f.relPath} failed SHA-256 verification against filename digest.`,
          422,
          'MIRROR_OBJECT_DIGEST_MISMATCH',
        );
      }
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

  // Import pre-Coherence sent statement dates and method-change corrections via Coherence's legacy Python reader bridge.
  if (manifest.preCoherenceStatements) {
    const preSpec = manifest.preCoherenceStatements;
    validateMethodCorrectionSpecs(preSpec.methodCorrections);
    const bridgeResult = await readLegacyStatements({
      statementsDir: preSpec.statementsDir,
      sentDir: preSpec.sentDir,
      agentsCsvPath: preSpec.agentsCsvPath,
      methodCorrections: preSpec.methodCorrections,
      pythonPath: resolvedPythonPath,
      coherenceRepo: resolvedCoherenceRepo,
      bridgePath: resolvedLegacyBridgePath,
      tempBaseDir,
    });
    verifyMethodCorrectionBatches(preSpec.methodCorrections, bridgeResult.methodCorrectionBatches);

    for (const batch of (bridgeResult.historicalBatches || [])) {
      const srcAbs = join(preSpec.statementsDir, ...batch.sourceFileName.split('/'));
      const srcBytes = await readFile(srcAbs);
      const promoted = await stores.dataStore.promoteBytes(srcBytes, {
        relPath: batch.sourceFileName,
        checksPassed: true,
      });
      const cmdKey = makeHashedCommandKey('import-historical-sent', [
        manifest.companySlug,
        batch.statementDate,
        batch.sourceFileName,
        promoted.sha256,
      ]);
      const res = await commands.recordStatementBatch({
        actor,
        commandKey: cmdKey,
        batchKind: 'historical_sent',
        statementDate: batch.statementDate,
        sourceFileName: batch.sourceFileName,
        sourceFile: promoted,
        reason: batch.reason || `Imported pre-Coherence sent statement ${batch.sourceFileName}`,
        agencyLines: batch.agencyLines || [],
        uplineLines: batch.uplineLines || [],
      });
      if (!res.idempotent) report.preCoherenceBatchesImported += 1;
    }

    const correctionManifestEntries = [];
    for (const corr of (bridgeResult.methodCorrectionBatches || [])) {
      const corrDoc = {
        statementDate: corr.statementDate,
        correctionKind: corr.correctionKind || 'method_correction',
        reason: corr.reason,
        agencyLineCount: (corr.agencyLines || []).length,
        uplineLineCount: (corr.uplineLines || []).length,
      };
      const corrBytes = Buffer.from(`${JSON.stringify(corrDoc, null, 2)}\n`, 'utf8');
      const promoted = await stores.dataStore.promoteBytes(corrBytes, {
        relPath: `method-corrections/${corr.statementDate}-${corr.correctionKind || 'correction'}.json`,
        checksPassed: true,
        contentType: 'application/json',
      });
      const contentDigest = sha256Hex(canonicalJson({
        statementDate: corr.statementDate,
        reason: corr.reason,
        agencyLines: corr.agencyLines || [],
        uplineLines: corr.uplineLines || [],
      }));
      const cmdKey = `import-method-correction:${manifest.companySlug}:${corr.statementDate}:${contentDigest}`;
      const res = await commands.recordStatementBatch({
        actor,
        commandKey: cmdKey,
        batchKind: 'method_correction',
        statementDate: corr.statementDate,
        sourceFileName: corr.sourceFileName || `method_correction_${corr.statementDate}.json`,
        sourceFile: promoted,
        reason: corr.reason || `Method correction for ${corr.statementDate}`,
        agencyLines: corr.agencyLines || [],
        uplineLines: corr.uplineLines || [],
      });
      if (!res.idempotent) report.methodCorrectionBatchesImported += 1;
      correctionManifestEntries.push({
        file: {
          area: 'other',
          relPath: `method-corrections/${corr.statementDate}-${corr.correctionKind || 'correction'}.json`,
          artifactKind: 'data',
          storeKind: STORE_KINDS.DATA,
          fileSha256: promoted.sha256,
          metadata: corrDoc,
        },
        storedFile: promoted,
      });
    }
    if (correctionManifestEntries.length > 0) {
      const corrHash = sha256Hex(JSON.stringify(correctionManifestEntries.map((x) => [x.file.relPath, x.file.fileSha256]).sort()));
      await commands.importStandaloneFiles({
        actor,
        commandKey: `import-method-correction-manifests:${manifest.companySlug}:${corrHash}`,
        files: correctionManifestEntries.map((x) => x.file),
        storedFiles: correctionManifestEntries.map((x) => x.storedFile),
      });
    }
  }

  // Archive all legacy SQLite run records (all 8 tables when includeLegacySqliteTables is true) as an immutable JSON snapshot.
  // Reuse the single consistent snapshot taken during manifest build when the path matches; otherwise take one consistent copy now.
  if (resolvedSqlitePath) {
    let snapshot;
    if (
      manifest.sqliteSnapshot
      && manifest.sqliteSnapshotPath === resolvedSqlitePath
      && (!nusearSqlitePath || nusearSqlitePath === manifest.sqlitePath)
    ) {
      snapshot = manifest.sqliteSnapshot;
    } else {
      const snap = await readLegacySqliteSnapshot(resolvedSqlitePath, {
        companySlug: manifest.companySlug,
        includeLegacySqliteTables: effectiveConfig.includeLegacySqliteTables,
        tempBaseDir,
        takeConsistentCopy: true,
      });
      snapshot = snap.tables;
      if (Object.keys(report.sqliteParity.source).length === 0) {
        report.sqliteParity.source = snap.counts;
      }
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

  // Layer 1 Byte-for-Byte Rebuild Verification: runs, standing input/, Incident Report, and standalone areas.
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

    // Verify standing input/ byte-for-byte rebuild.
    if (manifest.currentInputDir && manifest.currentInputFiles.length > 0 && report.currentInputVersionId) {
      const tmpInput = await mkdtemp(join(tempBaseDir, 'coherence-rebuild-input-'));
      try {
        await materializeInputEntries({
          db: pool,
          inputVersionId: report.currentInputVersionId,
          targetDir: tmpInput,
          dataStore: stores.dataStore,
        });
        const chk = await verifyDirectoryRebuild({
          sourceDir: manifest.currentInputDir,
          expectedFiles: manifest.currentInputFiles,
          rebuiltDir: tmpInput,
        });
        report.standingInputRebuildCheck = chk;
        if (!chk.passed) report.problems.push('Standing input rebuild mismatch.');
      } finally {
        await rm(tmpInput, { recursive: true, force: true }).catch(() => {});
      }
    }

    // Verify Incident Report/ byte-for-byte rebuild.
    if (manifest.incidentReportDir && (manifest.incidentReportFiles || []).length > 0) {
      const tmpInc = await mkdtemp(join(tempBaseDir, 'coherence-rebuild-incident-'));
      try {
        const incRows = (await pool.query(
          `SELECT i.rel_path, i.store_kind, i.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
           FROM coherence.imported_files i
           JOIN coherence.stored_files sf ON sf.store_kind = i.store_kind AND sf.sha256 = i.file_sha256
           WHERE i.area = 'incident_report'
           ORDER BY i.rel_path COLLATE "C"`,
        )).rows;
        for (const r of incRows) {
          const subRel = r.rel_path.replace(/^Incident Report\//, '');
          const bytes = await stores.readVerified(r.store_kind, r.file_sha256, {
            byteSize: Number(r.byte_size), md5B64: r.md5_b64, crc32cB64: r.crc32c_b64,
          });
          const dest = join(tmpInc, ...subRel.split('/'));
          await mkdir(dirname(dest), { recursive: true, mode: 0o700 });
          await writeFile(dest, bytes, { mode: 0o600 });
        }
        const expected = manifest.incidentReportFiles.map((f) => f.relPath.replace(/^Incident Report\//, ''));
        const chk = await verifyDirectoryRebuild({
          sourceDir: manifest.incidentReportDir,
          expectedFiles: expected,
          rebuiltDir: tmpInc,
        });
        report.incidentReportRebuildCheck = chk;
        if (!chk.passed) report.problems.push('Incident Report rebuild mismatch.');
      } finally {
        await rm(tmpInc, { recursive: true, force: true }).catch(() => {});
      }
    }

    // Verify all standalone imported areas byte-for-byte against source files.
    if ((manifest.standaloneFiles || []).length > 0) {
      const dbStand = (await pool.query(
        `SELECT i.area, i.rel_path, i.store_kind, i.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
         FROM coherence.imported_files i
         JOIN coherence.stored_files sf ON sf.store_kind = i.store_kind AND sf.sha256 = i.file_sha256`,
      )).rows;
      const byKey = new Map(dbStand.map((r) => [`${r.area}:${r.rel_path}`, r]));
      const missing = [];
      const changed = [];
      for (const f of manifest.standaloneFiles) {
        const rec = byKey.get(`${f.area}:${f.relPath}`);
        if (!rec) {
          missing.push(f.relPath);
          continue;
        }
        const origSha = fingerprintBytes(await readFile(f.absPath)).sha256;
        const rebuiltBytes = await stores.readVerified(rec.store_kind, rec.file_sha256, {
          byteSize: Number(rec.byte_size), md5B64: rec.md5_b64, crc32cB64: rec.crc32c_b64,
        });
        if (fingerprintBytes(rebuiltBytes).sha256 !== origSha) {
          changed.push(f.relPath);
        }
      }
      report.standaloneRebuildCheck = {
        files: manifest.standaloneFiles.length,
        passed: missing.length === 0 && changed.length === 0,
        missing: missing.slice(0, 10),
        changed: changed.slice(0, 10),
      };
      if (!report.standaloneRebuildCheck.passed) {
        report.problems.push(`Standalone file rebuild mismatch (missing=${missing.length}, changed=${changed.length}).`);
      }
    }
  }

  report.objectCheck = await verifyObjects(pool, stores, { deep: true });
  if (!report.objectCheck.passed) {
    report.problems.push(...report.objectCheck.problems);
  }

  for (const [tbl, expected] of Object.entries(report.sqliteParity.source || {})) {
    const actual = report.sqliteParity.imported[tbl];
    if (actual !== expected) {
      report.problems.push(`SQLite count mismatch for ${tbl}: source=${expected}, imported=${actual}`);
    }
  }

  report.passed = report.problems.length === 0;

  if (recordCheck) {
    const reportDigest = createHash('sha256').update(JSON.stringify(report)).digest('hex');
    await commands.recordCheck({
      actor,
      commandKey: makeHashedCommandKey('check-import', [manifest.companySlug, reportDigest]),
      checkKind: 'import',
      passed: report.passed,
      report,
    });
  }

  return report;
}
