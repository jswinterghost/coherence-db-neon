// Compares two run folders: verifies input/ file by file by SHA-256 first, then compares the output
// tree or substance tables under mode-specific rules.
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { extractViewerConfig } from '../readers/downstream-reader.mjs';
import { fingerprintBytes, sha256Hex } from '../util/crypto.mjs';
import { parseCsv, toCsv } from '../util/csv.mjs';
import { AppError } from '../util/redact.mjs';
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

export function mapEntitiesCsv(text, { targetEntity, preserveEntities = [] } = {}) {
  if (!targetEntity || typeof targetEntity !== 'string') {
    throw new AppError('entityMapping.targetEntity is required for entity-mapped CSV comparison.', 400, 'INVALID_ENTITY_MAPPING');
  }
  const preserveSet = new Set(preserveEntities);
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
    if (!trimmed || preserveSet.has(trimmed)) return cell;
    return targetEntity;
  }));
  return toCsv([header, ...mapped]);
}

function canonicalizeSubstanceCsv(bytes, entityMapping = null) {
  const text = bytes.toString('utf8');
  if (entityMapping?.targetEntity) {
    return mapEntitiesCsv(text, entityMapping);
  }
  const rows = parseCsv(text);
  return rows.length === 0 ? '' : toCsv(rows);
}

function classifyAllowedDiff(relPath, leftBytes, rightBytes, mode, entityMapping = null) {
  if (mode === 'storage') return null;

  if (relPath === 'run.json') {
    try {
      const allowBornDiff = mode === 'trial' || mode === 'entity_mapped';
      const l = normalizeRunJson(leftBytes.toString('utf8'), { allowBornDiff });
      const r = normalizeRunJson(rightBytes.toString('utf8'), { allowBornDiff });
      if (JSON.stringify(l) === JSON.stringify(r)) {
        return allowBornDiff ? 'run.json times/birth only' : 'run.json step at/seconds only';
      }
    } catch { /* Parse errors fail closed: treat file as an unexpected diff. */ }
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
      } catch {}
      return null;
    }
    if (relPath === 'overlay.csv' || relPath === 'emits/overlay.csv' || relPath === 'emits/adjustments.csv') {
      try {
        const l = normalizeCsvForTrial(leftBytes.toString('utf8'), { stripCommittedAt: true, normalizeUnidentified: true });
        const r = normalizeCsvForTrial(rightBytes.toString('utf8'), { stripCommittedAt: true, normalizeUnidentified: true });
        if (l === r) return 'approvals committed_at/unidentified keys only';
      } catch {}
      return null;
    }
    if (relPath === 'bible.csv' || relPath === 'adjust.csv') {
      try {
        const l = normalizeCsvForTrial(leftBytes.toString('utf8'), { stripCommittedAt: false, normalizeUnidentified: true });
        const r = normalizeCsvForTrial(rightBytes.toString('utf8'), { stripCommittedAt: false, normalizeUnidentified: true });
        if (l === r) return 'unidentified Bible keys only';
      } catch {}
      return null;
    }
  }

  if (mode === 'entity_mapped' && relPath.endsWith('.csv') && !relPath.startsWith('emits/bundles/')) {
    try {
      const l = mapEntitiesCsv(leftBytes.toString('utf8'), entityMapping);
      const r = mapEntitiesCsv(rightBytes.toString('utf8'), entityMapping);
      if (l === r) return `entities mapped to ${entityMapping.targetEntity}`;
    } catch {}
    return null;
  }

  return null;
}

function verifyManifestBundles(sideMap, manifestEntry) {
  if (!manifestEntry) {
    return { passed: false, declaredBundles: 0, missingBundles: [], missingBundleFiles: [], reason: 'company_manifest.json missing from run' };
  }
  const manifestList = JSON.parse(manifestEntry.bytes.toString('utf8'));
  const missingBundles = [];
  const missingBundleFiles = [];

  for (const bundle of manifestList) {
    const prefix = `emits/bundles/${bundle.output}/`;
    const viewerKey = `${prefix}viewer.html`;
    const requiredFiles = new Set();

    if (Array.isArray(bundle.files)) {
      for (const rel of bundle.files) requiredFiles.add(rel);
    }

    const viewerEntry = sideMap.get(viewerKey);
    if (viewerEntry) {
      try {
        const cfg = extractViewerConfig(viewerEntry.bytes.toString('utf8'));
        for (const tables of Object.values(cfg.features || {})) {
          for (const rel of Object.values(tables || {})) {
            if (typeof rel === 'string') requiredFiles.add(rel);
          }
        }
      } catch {
        missingBundleFiles.push({ bundle: bundle.output, file: 'viewer.html', reason: 'invalid viewer config' });
      }
    }

    const sideKeys = [...sideMap.keys()].filter((k) => k.startsWith(prefix));
    if (sideKeys.length === 0) {
      missingBundles.push(bundle.output);
      continue;
    }

    if (requiredFiles.size === 0 && !viewerEntry) {
      const hasDataCsv = sideKeys.some((k) => k.endsWith('.csv'));
      if (!hasDataCsv) missingBundles.push(bundle.output);
      continue;
    }

    for (const rel of requiredFiles) {
      const fullKey = `${prefix}${rel}`;
      if (!sideMap.has(fullKey)) {
        missingBundleFiles.push({ bundle: bundle.output, file: rel, reason: 'missing required bundle file' });
      }
    }
  }

  return {
    passed: missingBundles.length === 0 && missingBundleFiles.length === 0,
    declaredBundles: manifestList.length,
    missingBundles,
    missingBundleFiles,
  };
}

function discoverSubstanceTables(sideMap, { entity = null } = {}) {
  const keys = [...sideMap.keys()].sort();
  const pickEntityManagerPrefix = () => {
    const prefixes = new Set();
    for (const k of keys) {
      const m = /^(emits\/bundles\/entity-managers\/[^/]+\/)/.exec(k);
      if (m) prefixes.add(m[1]);
    }
    const list = [...prefixes].sort();
    if (list.length === 0) return null;
    if (entity) {
      const exact = `emits/bundles/entity-managers/${entity}/`;
      if (prefixes.has(exact)) return exact;
    }
    if (list.length === 1) return list[0];
    throw new AppError(
      'Multiple entity-manager bundles exist in run; pass target entity for substance comparison.',
      409,
      'AMBIGUOUS_ENTITY_BUNDLE',
    );
  };

  const emPrefix = pickEntityManagerPrefix();
  let viewerCfg = null;
  if (emPrefix && sideMap.has(`${emPrefix}viewer.html`)) {
    try {
      viewerCfg = extractViewerConfig(sideMap.get(`${emPrefix}viewer.html`).bytes.toString('utf8'));
    } catch {
      viewerCfg = null;
    }
  }

  const tables = new Map();

  // Canonical Book of Business
  if (sideMap.has('emits/canonical_bob.csv')) {
    tables.set('canonical_bob', sideMap.get('emits/canonical_bob.csv'));
  } else if (emPrefix && viewerCfg?.features?.CANONICAL_BOB) {
    const entries = Object.entries(viewerCfg.features.CANONICAL_BOB);
    for (const [tblKey, rel] of entries) {
      const full = `${emPrefix}${rel}`;
      if (sideMap.has(full)) {
        tables.set(entries.length === 1 ? 'canonical_bob' : `canonical_bob/${tblKey}`, sideMap.get(full));
      }
    }
  } else if (emPrefix && sideMap.has(`${emPrefix}data/canonical_bob.csv`)) {
    tables.set('canonical_bob', sideMap.get(`${emPrefix}data/canonical_bob.csv`));
  }

  // Coherent Ledger
  if (sideMap.has('emits/coherent_ledger.csv')) {
    tables.set('coherent_ledger', sideMap.get('emits/coherent_ledger.csv'));
  } else if (emPrefix && viewerCfg?.features?.COHERENT_LEDGER) {
    const entries = Object.entries(viewerCfg.features.COHERENT_LEDGER);
    for (const [tblKey, rel] of entries) {
      const full = `${emPrefix}${rel}`;
      if (sideMap.has(full)) {
        tables.set(entries.length === 1 ? 'coherent_ledger' : `coherent_ledger/${tblKey}`, sideMap.get(full));
      }
    }
  } else if (emPrefix && sideMap.has(`${emPrefix}data/coherent_ledger.csv`)) {
    tables.set('coherent_ledger', sideMap.get(`${emPrefix}data/coherent_ledger.csv`));
  }

  // Statements per entity (when present on a run)
  for (const k of keys) {
    if (k.startsWith('emits/entity_statements/') && k.endsWith('.csv')) {
      const name = k.slice('emits/entity_statements/'.length);
      tables.set(`entity_statements/${name}`, sideMap.get(k));
    } else if (emPrefix && k.startsWith(`${emPrefix}data/entity_statements/`) && k.endsWith('.csv')) {
      const name = k.slice(`${emPrefix}data/entity_statements/`.length);
      tables.set(`entity_statements/${name}`, sideMap.get(k));
    }
  }
  if (emPrefix && viewerCfg?.features?.ENTITY_STATEMENTS) {
    for (const [tblKey, rel] of Object.entries(viewerCfg.features.ENTITY_STATEMENTS)) {
      const full = `${emPrefix}${rel}`;
      if (sideMap.has(full)) {
        tables.set(`entity_statements/${tblKey}`, sideMap.get(full));
      }
    }
  }

  return tables;
}

/**
 * Compares two run folders on disk, checking input/ by SHA-256 before the output tree or substance tables.
 * Supported modes: 'storage', 'replay', 'shadow', 'trial', 'entity_mapped', 'substance'.
 */
export async function compareRunFolders(leftDir, rightDir, {
  mode = 'replay',
  entityMapping = null,
  entity = null,
  includeDsStore = (mode === 'storage'),
  leftLabel = leftDir,
  rightLabel = rightDir,
} = {}) {
  if (mode === 'entity_mapped' && !entityMapping?.targetEntity) {
    throw new AppError('entity_mapped mode requires entityMapping.targetEntity from company configuration.', 400, 'INVALID_ENTITY_MAPPING');
  }

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

  const leftInputs = leftAll.filter((f) => f.startsWith('input/'));
  const rightInputs = rightAll.filter((f) => f.startsWith('input/'));
  const inputReport = { same: 0, changed: [], onlyLeft: [], onlyRight: [], passed: true };

  for (const rel of leftInputs) {
    if (!rightMap.has(rel)) {
      inputReport.onlyLeft.push(rel);
    } else if (leftMap.get(rel).sha256 === rightMap.get(rel).sha256) {
      inputReport.same += 1;
    } else if ((mode === 'entity_mapped' || (mode === 'substance' && entityMapping?.targetEntity)) && rel === 'input/Agent Data/cleanagentdata.csv') {
      const l = mapEntitiesCsv(leftMap.get(rel).bytes.toString('utf8'), entityMapping);
      const r = mapEntitiesCsv(rightMap.get(rel).bytes.toString('utf8'), entityMapping);
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

  if (mode === 'substance') {
    const leftTables = discoverSubstanceTables(leftMap, { entity });
    const rightTables = discoverSubstanceTables(rightMap, { entity });
    const missingRequired = [];
    for (const required of ['canonical_bob', 'coherent_ledger']) {
      const hasLeft = leftTables.has(required) || [...leftTables.keys()].some((k) => k.startsWith(`${required}/`));
      const hasRight = rightTables.has(required) || [...rightTables.keys()].some((k) => k.startsWith(`${required}/`));
      if (!hasLeft) missingRequired.push({ side: 'left', table: required });
      if (!hasRight) missingRequired.push({ side: 'right', table: required });
    }

    const same = [];
    const unexpectedDiffs = [];
    const onlyLeft = [];
    const onlyRight = [];

    for (const [name, leftEntry] of leftTables.entries()) {
      if (!rightTables.has(name)) {
        onlyLeft.push(name);
        continue;
      }
      const rightEntry = rightTables.get(name);
      const lCanon = canonicalizeSubstanceCsv(leftEntry.bytes, entityMapping);
      const rCanon = canonicalizeSubstanceCsv(rightEntry.bytes, entityMapping);
      if (lCanon === rCanon) {
        same.push(name);
      } else {
        unexpectedDiffs.push({
          table: name,
          leftSha256: leftEntry.sha256,
          rightSha256: rightEntry.sha256,
        });
      }
    }
    for (const name of rightTables.keys()) {
      if (!leftTables.has(name)) onlyRight.push(name);
    }

    const substancePassed = missingRequired.length === 0
      && unexpectedDiffs.length === 0
      && onlyLeft.length === 0
      && onlyRight.length === 0;

    return {
      mode,
      leftLabel,
      rightLabel,
      passed: inputReport.passed && substancePassed,
      inputs: inputReport,
      substance: {
        same,
        missingRequired,
        unexpectedDiffs,
        onlyLeft,
        onlyRight,
        passed: substancePassed,
      },
      tree: null,
    };
  }

  const leftOut = leftAll.filter((f) => !f.startsWith('input/'));
  const rightOut = rightAll.filter((f) => !f.startsWith('input/'));
  const treeReport = {
    same: 0,
    allowedDiffs: [],
    unexpectedDiffs: [],
    onlyLeft: [],
    onlyRight: [],
    manifestBundleCheck: null,
    passed: true,
  };

  for (const rel of leftOut) {
    if (mode === 'entity_mapped' && (rel.startsWith('emits/bundles/') || rel === 'company_manifest.json')) {
      continue;
    }
    if (!rightMap.has(rel)) {
      treeReport.onlyLeft.push(rel);
    } else if (leftMap.get(rel).sha256 === rightMap.get(rel).sha256) {
      treeReport.same += 1;
    } else {
      const allowedReason = classifyAllowedDiff(rel, leftMap.get(rel).bytes, rightMap.get(rel).bytes, mode, entityMapping);
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
    if (mode === 'entity_mapped' && (rel.startsWith('emits/bundles/') || rel === 'company_manifest.json')) continue;
    if (!leftMap.has(rel)) treeReport.onlyRight.push(rel);
  }

  if (mode === 'entity_mapped') {
    const manifestEntry = leftMap.get('company_manifest.json') || rightMap.get('company_manifest.json');
    const targetSide = leftMap.has('company_manifest.json') ? leftMap : rightMap;
    treeReport.manifestBundleCheck = verifyManifestBundles(targetSide, manifestEntry);
  }

  treeReport.passed = treeReport.unexpectedDiffs.length === 0
    && treeReport.onlyLeft.length === 0
    && treeReport.onlyRight.length === 0
    && (treeReport.manifestBundleCheck ? treeReport.manifestBundleCheck.passed : true);

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

export async function compareDbRuns({
  pool,
  stores,
  leftRunId,
  rightRunId = null,
  rightFolderDir = null,
  mode = 'replay',
  entityMapping = null,
  entity = null,
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
      entityMapping,
      entity,
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
