// Comparison of two run folders and proof checks (R11 EYES on runs, R13.1-R13.4).
// Always compares inputs file-by-file by SHA-256 FIRST, then whole trees with mode-specific allowed differences.
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fingerprintBytes, sha256Hex } from '../util/crypto.mjs';
import { parseCsv, toCsv } from '../util/csv.mjs';
import { listFilesRecursive, rebuildRunFolderFromDb } from '../worker/folder-builder.mjs';

const ADJUST_STAMP_START = '<script>window.__ADJUST_CONFIG__=';
const ADJUST_STAMP_END = ';</script></head>';
const UNIDENTIFIED_KEY_RE = /^policy:([^:]+):unidentified:[0-9a-f]{64}$/;

const isDsStore = (relPath) => relPath === '.DS_Store' || relPath.endsWith('/.DS_Store');

function normalizeRunJson(jsonText, { allowBornDiff = false } = {}) {
  const parsed = JSON.parse(jsonText);
  const steps = {};
  for (const [step, meta] of Object.entries(parsed.steps || {})) {
    const clean = { ...(meta || {}) };
    delete clean.at;
    delete clean.seconds;
    steps[step] = clean;
  }
  return {
    date: parsed.date ?? null,
    born: allowBornDiff ? '<ALLOWED_BORN>' : (parsed.born ?? null),
    steps,
  };
}

function normalizeUnidentifiedKey(value) {
  if (typeof value !== 'string') return value;
  const m = UNIDENTIFIED_KEY_RE.exec(value);
  return m ? `policy:${m[1]}:unidentified:<BIRTH_KEY>` : value;
}

function normalizeCsvForTrial(text, { stripCommittedAt = false, normalizeUnidentified = true } = {}) {
  const rows = parseCsv(text);
  if (rows.length === 0) return '';
  const header = rows[0];
  const committedIdx = stripCommittedAt ? header.indexOf('committed_at') : -1;
  const recordIdIdx = header.indexOf('record_id');
  const mapped = rows.slice(1).map((row) => row.map((cell, idx) => {
    if (idx === committedIdx) return '<COMMITTED_AT>';
    if (normalizeUnidentified && idx === recordIdIdx) return normalizeUnidentifiedKey(cell);
    return cell;
  }));
  // Sort rows whose key became placeholder so unidentified key hash order does not cause false diffs
  if (normalizeUnidentified && recordIdIdx >= 0) {
    mapped.sort((a, b) => a.join('\u0000').localeCompare(b.join('\u0000')));
  }
  return toCsv([header, ...mapped]);
}

function normalizeReviewHtmlForTrial(html) {
  const headIdx = html.indexOf('</head>');
  const start = html.lastIndexOf(ADJUST_STAMP_START, headIdx);
  const end = start >= 0 ? html.indexOf(ADJUST_STAMP_END, start) : -1;
  if (start < 0 || end < 0) return { shell: html, config: null };
  const shell = html.slice(0, start) + html.slice(end + ADJUST_STAMP_END.length);
  const cfg = JSON.parse(html.slice(start + ADJUST_STAMP_START.length, end));
  cfg.runBorn = '<RUN_BORN>';
  cfg.checksum = '<CHECKSUM>';
  if (Array.isArray(cfg.overlay)) {
    cfg.overlay = cfg.overlay.map((row) => ({
      ...row,
      record_id: normalizeUnidentifiedKey(row.record_id),
      committed_at: '<COMMITTED_AT>',
    }));
  }
  if (Array.isArray(cfg.queue)) {
    cfg.queue = cfg.queue
      .map((item) => ({ ...item, record_id: normalizeUnidentifiedKey(item.record_id) }))
      .sort((a, b) => String(a.record_id).localeCompare(String(b.record_id)));
  }
  if (cfg.evidence && typeof cfg.evidence === 'object') {
    const normEv = {};
    for (const [k, v] of Object.entries(cfg.evidence)) {
      const nk = normalizeUnidentifiedKey(k);
      normEv[nk] = normEv[nk] ? [normEv[nk], v] : v;
    }
    cfg.evidence = normEv;
  }
  return { shell, config: cfg };
}

/**
 * R13.4 Clearpath-vs-Mac entity mapping: maps every entity column value except InsureItAll to Clearpath.
 */
export function mapEntitiesToClearpathCsv(text) {
  const rows = parseCsv(text);
  if (rows.length === 0) return '';
  const header = rows[0];
  const entityCols = header
    .map((col, idx) => (['entity', 'entity_from', 'agency', 'approved_agency', 'approved_agency_from'].includes(col) ? idx : -1))
    .filter((idx) => idx >= 0);
  if (entityCols.length === 0) return toCsv(rows);
  const mapped = rows.slice(1).map((row) => row.map((cell, idx) => {
    if (!entityCols.includes(idx)) return cell;
    const trimmed = String(cell ?? '').trim();
    if (!trimmed || trimmed === 'InsureItAll') return cell;
    return 'Clearpath';
  }));
  return toCsv([header, ...mapped]);
}

function classifyAllowedDiff(relPath, leftBytes, rightBytes, mode) {
  if (mode === 'storage') return null;

  if (relPath === 'run.json') {
    try {
      const allowBornDiff = mode === 'trial' || mode === 'clearpath_vs_mac';
      const l = normalizeRunJson(leftBytes.toString('utf8'), { allowBornDiff });
      const r = normalizeRunJson(rightBytes.toString('utf8'), { allowBornDiff });
      if (JSON.stringify(l) === JSON.stringify(r)) {
        return allowBornDiff ? 'run.json times/birth only' : 'run.json step at/seconds only';
      }
    } catch { /* fall through as unexpected diff */ }
    return null;
  }

  if (mode === 'trial') {
    if (relPath === 'bible.html' || relPath === 'adjust.html') {
      try {
        const l = normalizeReviewHtmlForTrial(leftBytes.toString('utf8'));
        const r = normalizeReviewHtmlForTrial(rightBytes.toString('utf8'));
        if (l.shell === r.shell && JSON.stringify(l.config) === JSON.stringify(r.config)) {
          return 'review page runBorn/checksum/committed_at/unidentified keys only';
        }
      } catch { /* unexpected */ }
      return null;
    }
    if (relPath === 'overlay.csv' || relPath === 'emits/overlay.csv' || relPath === 'emits/adjustments.csv') {
      try {
        const l = normalizeCsvForTrial(leftBytes.toString('utf8'), { stripCommittedAt: true, normalizeUnidentified: true });
        const r = normalizeCsvForTrial(rightBytes.toString('utf8'), { stripCommittedAt: true, normalizeUnidentified: true });
        if (l === r) return 'approvals committed_at/unidentified keys only';
      } catch { /* unexpected */ }
      return null;
    }
    if (relPath === 'bible.csv' || relPath === 'adjust.csv') {
      try {
        const l = normalizeCsvForTrial(leftBytes.toString('utf8'), { stripCommittedAt: false, normalizeUnidentified: true });
        const r = normalizeCsvForTrial(rightBytes.toString('utf8'), { stripCommittedAt: false, normalizeUnidentified: true });
        if (l === r) return 'unidentified Bible keys only';
      } catch { /* unexpected */ }
      return null;
    }
  }

  if (mode === 'clearpath_vs_mac' && relPath.endsWith('.csv') && !relPath.startsWith('emits/bundles/')) {
    try {
      const l = mapEntitiesToClearpathCsv(leftBytes.toString('utf8'));
      const r = mapEntitiesToClearpathCsv(rightBytes.toString('utf8'));
      if (l === r) return 'entities mapped to Clearpath (except InsureItAll)';
    } catch { /* unexpected */ }
    return null;
  }

  return null;
}

/**
 * Compares two run folders on disk (R13, R11 EYES on runs).
 * Always compares input/ file-by-file by SHA-256 first, then the remaining output tree.
 * mode: 'storage' | 'replay' | 'shadow' | 'trial' | 'clearpath_vs_mac'
 */
export async function compareRunFolders(leftDir, rightDir, {
  mode = 'replay',
  includeDsStore = (mode === 'storage'),
  leftLabel = leftDir,
  rightLabel = rightDir,
} = {}) {
  const filterFiles = (files) => (includeDsStore ? files : files.filter((f) => !isDsStore(f)));
  const leftAll = filterFiles(await listFilesRecursive(leftDir));
  const rightAll = filterFiles(await listFilesRecursive(rightDir));

  const hashTree = async (root, files) => {
    const map = new Map();
    for (const rel of files) {
      const bytes = await readFile(join(root, ...rel.split('/')));
      map.set(rel, { sha256: fingerprintBytes(bytes).sha256, bytes });
    }
    return map;
  };

  const leftMap = await hashTree(leftDir, leftAll);
  const rightMap = await hashTree(rightDir, rightAll);

  // 1. Compare input/ FIRST (R11 EYES on runs, R13.4: "inputs first, then whole trees")
  const leftInputs = leftAll.filter((f) => f.startsWith('input/'));
  const rightInputs = rightAll.filter((f) => f.startsWith('input/'));
  const inputReport = { same: 0, changed: [], onlyLeft: [], onlyRight: [], passed: true };

  for (const rel of leftInputs) {
    if (!rightMap.has(rel)) {
      inputReport.onlyLeft.push(rel);
    } else if (leftMap.get(rel).sha256 === rightMap.get(rel).sha256) {
      inputReport.same += 1;
    } else if (mode === 'clearpath_vs_mac' && rel === 'input/Agent Data/cleanagentdata.csv') {
      const l = mapEntitiesToClearpathCsv(leftMap.get(rel).bytes.toString('utf8'));
      const r = mapEntitiesToClearpathCsv(rightMap.get(rel).bytes.toString('utf8'));
      if (l === r) inputReport.same += 1;
      else inputReport.changed.push({ relPath: rel, leftSha256: leftMap.get(rel).sha256, rightSha256: rightMap.get(rel).sha256 });
    } else {
      inputReport.changed.push({ relPath: rel, leftSha256: leftMap.get(rel).sha256, rightSha256: rightMap.get(rel).sha256 });
    }
  }
  for (const rel of rightInputs) {
    if (!leftMap.has(rel)) inputReport.onlyRight.push(rel);
  }
  inputReport.passed = inputReport.changed.length === 0 && inputReport.onlyLeft.length === 0 && inputReport.onlyRight.length === 0;

  // 2. Compare output tree (everything outside input/)
  const leftOut = leftAll.filter((f) => !f.startsWith('input/'));
  const rightOut = rightAll.filter((f) => !f.startsWith('input/'));
  const treeReport = {
    same: 0,
    allowedDiffs: [],
    unexpectedDiffs: [],
    onlyLeft: [],
    onlyRight: [],
    clearpathManifestCheck: null,
    passed: true,
  };

  for (const rel of leftOut) {
    if (mode === 'clearpath_vs_mac' && (rel.startsWith('emits/bundles/') || rel === 'company_manifest.json')) {
      continue; // Clearpath bundles checked against Clearpath's own company_manifest.json below (R13.4)
    }
    if (!rightMap.has(rel)) {
      treeReport.onlyLeft.push(rel);
    } else if (leftMap.get(rel).sha256 === rightMap.get(rel).sha256) {
      treeReport.same += 1;
    } else {
      const allowedReason = classifyAllowedDiff(rel, leftMap.get(rel).bytes, rightMap.get(rel).bytes, mode);
      if (allowedReason) {
        treeReport.allowedDiffs.push({ relPath: rel, reason: allowedReason });
      } else {
        treeReport.unexpectedDiffs.push({
          relPath: rel,
          leftSha256: leftMap.get(rel).sha256,
          rightSha256: rightMap.get(rel).sha256,
        });
      }
    }
  }
  for (const rel of rightOut) {
    if (mode === 'clearpath_vs_mac' && (rel.startsWith('emits/bundles/') || rel === 'company_manifest.json')) continue;
    if (!leftMap.has(rel)) treeReport.onlyRight.push(rel);
  }

  // R13.4: Clearpath bundles verified against Clearpath's own company_manifest.json
  if (mode === 'clearpath_vs_mac') {
    const manifestEntry = leftMap.get('company_manifest.json') || rightMap.get('company_manifest.json');
    const clearpathSide = leftMap.has('company_manifest.json') ? leftMap : rightMap;
    if (!manifestEntry) {
      treeReport.clearpathManifestCheck = { passed: false, reason: 'company_manifest.json missing from Clearpath run' };
    } else {
      const manifestList = JSON.parse(manifestEntry.bytes.toString('utf8'));
      const missingBundles = [];
      for (const bundle of manifestList) {
        const prefix = `emits/bundles/${bundle.output}/`;
        const hasAny = [...clearpathSide.keys()].some((k) => k.startsWith(prefix));
        if (!hasAny) missingBundles.push(bundle.output);
      }
      treeReport.clearpathManifestCheck = {
        passed: missingBundles.length === 0,
        declaredBundles: manifestList.length,
        missingBundles,
      };
    }
  }

  treeReport.passed = treeReport.unexpectedDiffs.length === 0
    && treeReport.onlyLeft.length === 0
    && treeReport.onlyRight.length === 0
    && (treeReport.clearpathManifestCheck ? treeReport.clearpathManifestCheck.passed : true);

  const passed = inputReport.passed && treeReport.passed;
  return {
    mode,
    leftLabel,
    rightLabel,
    passed,
    inputs: inputReport,
    tree: treeReport,
  };
}

/**
 * Rebuilds two runs stored in the database (or one DB run vs a reference folder on disk) into temporary
 * directories, compares them per R13, optionally records a `checks` row, and removes temporary directories.
 */
export async function compareDbRuns({
  pool,
  stores,
  leftRunId,
  rightRunId = null,
  rightFolderDir = null,
  mode = 'replay',
  commands = null,
  actor = null,
  tempBaseDir = tmpdir(),
}) {
  const tmpLeft = await mkdtemp(join(tempBaseDir, 'coherence-cmp-left-'));
  const tmpRight = rightRunId ? await mkdtemp(join(tempBaseDir, 'coherence-cmp-right-')) : null;
  try {
    await rebuildRunFolderFromDb({ db: pool, runId: leftRunId, targetDir: tmpLeft, stores });
    const rightPath = rightRunId
      ? (await rebuildRunFolderFromDb({ db: pool, runId: rightRunId, targetDir: tmpRight, stores }), tmpRight)
      : rightFolderDir;
    const report = await compareRunFolders(tmpLeft, rightPath, {
      mode,
      leftLabel: `run:${leftRunId}`,
      rightLabel: rightRunId ? `run:${rightRunId}` : rightFolderDir,
    });
    if (commands && actor) {
      const checkKind = mode === 'shadow' ? 'shadow' : mode === 'replay' ? 'replay' : 'trial_comparison';
      const digest = sha256Hex(JSON.stringify(report));
      await commands.recordCheck({
        actor,
        commandKey: `check-${checkKind}:${leftRunId}:${rightRunId || rightFolderDir}:${digest}`,
        checkKind,
        runId: leftRunId,
        comparedRunId: rightRunId,
        passed: report.passed,
        report,
      });
    }
    return report;
  } finally {
    await rm(tmpLeft, { recursive: true, force: true }).catch(() => {});
    if (tmpRight) await rm(tmpRight, { recursive: true, force: true }).catch(() => {});
  }
}
