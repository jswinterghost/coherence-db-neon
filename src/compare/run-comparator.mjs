// Compares two run folders or database runs: verifies input/ file by file by SHA-256 first,
// then compares outputs or substance tables (Gates 1 to 4: inputs, Canonical BoB, Coherent Ledger,
// run delta statements and per-entity statements) cell for cell as exact UTF-8 text with strictly
// PHI-free reports (counts, SHA-256 digests, column names, row numbers, and cent deltas only).
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { extractViewerConfig } from '../readers/downstream-reader.mjs';
import { canonicalJson, fingerprintBytes, sha256Hex } from '../util/crypto.mjs';
import { normalizeMacKey, parseCsv, toCsv } from '../util/csv.mjs';
import { AppError } from '../util/redact.mjs';
import { formatCents, parseCents } from '../worker/emit-materializer.mjs';
import { listFilesRecursive, rebuildRunFolderFromDb } from '../worker/folder-builder.mjs';

const ADJUST_STAMP_START = '<script>window.__ADJUST_CONFIG__=';
const ADJUST_STAMP_END = ';</script></head>';
const UNIDENTIFIED_KEY_RE = /^policy:([^:]+):unidentified:[0-9a-f]{64}$/;
const STATEMENTS_DELTA_RE = /^emits\/statements_(\d{8})\.csv$/;
const DEFAULT_MAX_DIFF_ROWS = 50;

const STANDARD_MONEY_COLS = new Set([
  'amount',
  'gross_comm',
  'downline_amount',
  'upline_amount',
  'override_amount',
  'commission_amount',
  'hra_amount',
  'fee_amount',
  'other_amount',
  'approved_amount',
  'total',
  'net_amount',
]);

const STANDARD_NON_UPLINE_AMOUNT_COLS = new Set([
  'amount',
  'downline_amount',
  'override_amount',
  'commission_amount',
  'hra_amount',
  'fee_amount',
  'other_amount',
  'approved_amount',
]);

const isDsStore = (relPath) => relPath === '.DS_Store' || relPath.endsWith('/.DS_Store');

function isMoneyColumn(colName, extraMoneyCols = null) {
  if (extraMoneyCols && extraMoneyCols.has(colName)) return true;
  return STANDARD_MONEY_COLS.has(colName) || colName.endsWith('_amount') || colName.endsWith('_total');
}

function tryParseCents(text) {
  try {
    return parseCents(text);
  } catch {
    return null;
  }
}

function parseMoneyCellStrict(text) {
  const trimmed = String(text ?? '').trim();
  if (trimmed === '') return { ok: true, cents: null };
  try {
    return { ok: true, cents: parseCents(trimmed) };
  } catch {
    return { ok: false, cents: null };
  }
}

function resolveUplineAmountColumn(header, explicitCol = null) {
  if (explicitCol) return header.includes(explicitCol) ? explicitCol : null;
  if (header.includes('upline_amount')) return 'upline_amount';
  return header.find((c) => c.endsWith('_amount') && !STANDARD_NON_UPLINE_AMOUNT_COLS.has(c)) || null;
}

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

function compareCsvExactTextWithParsed(leftBytes, rightBytes, {
  tableName = 'table',
  expectedColumns = null,
  moneyColumns = null,
  entityMapping = null,
  maxDiffRows = DEFAULT_MAX_DIFF_ROWS,
} = {}) {
  const leftBuf = Buffer.isBuffer(leftBytes) ? leftBytes : Buffer.from(String(leftBytes ?? ''), 'utf8');
  const rightBuf = Buffer.isBuffer(rightBytes) ? rightBytes : Buffer.from(String(rightBytes ?? ''), 'utf8');
  const leftSha256 = fingerprintBytes(leftBuf).sha256;
  const rightSha256 = fingerprintBytes(rightBuf).sha256;

  let leftText = leftBuf.toString('utf8');
  let rightText = rightBuf.toString('utf8');
  if (entityMapping?.targetEntity) {
    leftText = mapEntitiesCsv(leftText, entityMapping);
    rightText = mapEntitiesCsv(rightText, entityMapping);
  }

  const leftMatrix = parseCsv(leftText);
  const rightMatrix = parseCsv(rightText);
  const leftHeader = leftMatrix[0] || [];
  const rightHeader = rightMatrix[0] || [];
  const leftRows = leftMatrix.slice(1).filter((r) => !(r.length === 1 && r[0] === ''));
  const rightRows = rightMatrix.slice(1).filter((r) => !(r.length === 1 && r[0] === ''));

  const extraMoneySet = Array.isArray(moneyColumns) ? new Set(moneyColumns) : null;

  // Validate headers strictly against each other and against expectedColumns (if parameterized).
  const expectedList = Array.isArray(expectedColumns) && expectedColumns.length > 0 ? [...expectedColumns] : null;
  const leftHeaderSet = new Set(leftHeader);
  const rightHeaderSet = new Set(rightHeader);

  const missingLeftColumns = expectedList ? expectedList.filter((c) => !leftHeaderSet.has(c)) : [];
  const missingRightColumns = expectedList ? expectedList.filter((c) => !rightHeaderSet.has(c)) : [];
  const extraLeftColumns = expectedList ? leftHeader.filter((c) => !expectedList.includes(c)) : [];
  const extraRightColumns = expectedList ? rightHeader.filter((c) => !expectedList.includes(c)) : [];

  const leftMatchesExpected = !expectedList || (
    leftHeader.length === expectedList.length && leftHeader.every((c, idx) => c === expectedList[idx])
  );
  const rightMatchesExpected = !expectedList || (
    rightHeader.length === expectedList.length && rightHeader.every((c, idx) => c === expectedList[idx])
  );
  const headersIdentical = leftHeader.length === rightHeader.length
    && leftHeader.every((c, idx) => c === rightHeader[idx]);
  const headerMatches = headersIdentical && leftMatchesExpected && rightMatchesExpected;

  const compareCols = expectedList
    ? expectedList.filter((c) => leftHeaderSet.has(c) && rightHeaderSet.has(c))
    : (headersIdentical ? leftHeader : leftHeader.filter((c) => rightHeaderSet.has(c)));

  const leftIdxMap = new Map(leftHeader.map((c, i) => [c, i]));
  const rightIdxMap = new Map(rightHeader.map((c, i) => [c, i]));

  const columnMismatchCounts = {};
  const moneyCentDeltaTotals = {};
  const differingRows = [];
  let differingRowCount = 0;

  const minRows = Math.min(leftRows.length, rightRows.length);
  for (let r = 0; r < minRows; r++) {
    const lRow = leftRows[r];
    const rRow = rightRows[r];
    const diffCols = [];
    const rowCentDeltas = {};

    for (const col of compareCols) {
      const li = leftIdxMap.get(col);
      const ri = rightIdxMap.get(col);
      const lVal = li < lRow.length ? lRow[li] : undefined;
      const rVal = ri < rRow.length ? rRow[ri] : undefined;
      if (lVal !== rVal) {
        diffCols.push(col);
        columnMismatchCounts[col] = (columnMismatchCounts[col] || 0) + 1;
        if (isMoneyColumn(col, extraMoneySet)) {
          const lc = tryParseCents(lVal ?? '');
          const rc = tryParseCents(rVal ?? '');
          if (lc != null && rc != null) {
            const delta = lc - rc;
            rowCentDeltas[col] = Number(delta);
            moneyCentDeltaTotals[col] = (moneyCentDeltaTotals[col] ?? 0n) + delta;
          }
        }
      }
    }

    if (lRow.length !== leftHeader.length || rRow.length !== rightHeader.length) {
      if (!diffCols.includes('_row_width')) diffCols.push('_row_width');
      columnMismatchCounts._row_width = (columnMismatchCounts._row_width || 0) + 1;
    }

    if (diffCols.length > 0) {
      differingRowCount += 1;
      if (differingRows.length < maxDiffRows) {
        const entry = { rowNumber: r + 1, columns: diffCols };
        if (Object.keys(rowCentDeltas).length > 0) entry.centDeltas = rowCentDeltas;
        differingRows.push(entry);
      }
    }
  }

  // Account for extra rows on left or right in aggregate money cent deltas (still zero cell text!).
  if (leftRows.length !== rightRows.length) {
    const extraCount = Math.abs(leftRows.length - rightRows.length);
    differingRowCount += extraCount;
    const extraSide = leftRows.length > rightRows.length ? leftRows : rightRows;
    const sign = leftRows.length > rightRows.length ? 1n : -1n;
    const idxMap = leftRows.length > rightRows.length ? leftIdxMap : rightIdxMap;
    for (let r = minRows; r < extraSide.length; r++) {
      const row = extraSide[r];
      const rowCentDeltas = {};
      for (const col of compareCols) {
        if (!isMoneyColumn(col, extraMoneySet)) continue;
        const idx = idxMap.get(col);
        const cents = idx < row.length ? tryParseCents(row[idx]) : null;
        if (cents != null && cents !== 0n) {
          const delta = sign * cents;
          rowCentDeltas[col] = Number(delta);
          moneyCentDeltaTotals[col] = (moneyCentDeltaTotals[col] ?? 0n) + delta;
        }
      }
      if (differingRows.length < maxDiffRows) {
        const entry = {
          rowNumber: r + 1,
          columns: [leftRows.length > rightRows.length ? '_only_left_row' : '_only_right_row'],
        };
        if (Object.keys(rowCentDeltas).length > 0) entry.centDeltas = rowCentDeltas;
        differingRows.push(entry);
      }
    }
  }

  const moneyCentDeltas = {};
  for (const [col, cents] of Object.entries(moneyCentDeltaTotals)) {
    moneyCentDeltas[col] = Number(cents);
  }

  const passed = headerMatches
    && leftRows.length === rightRows.length
    && differingRowCount === 0;

  const report = {
    table: tableName,
    passed,
    leftSha256,
    rightSha256,
    leftRowCount: leftRows.length,
    rightRowCount: rightRows.length,
    leftColumnCount: leftHeader.length,
    rightColumnCount: rightHeader.length,
    expectedColumns: expectedList,
    headerMatches,
    missingLeftColumns,
    missingRightColumns,
    extraLeftColumns,
    extraRightColumns,
    differingRowCount,
    columnMismatchCounts,
    moneyCentDeltas,
    differingRows,
  };
  return {
    report,
    parsed: {
      leftHeader,
      leftRows,
      rightHeader,
      rightRows,
    },
  };
}

/**
 * Compares two CSV buffers cell for cell as exact UTF-8 text (never coercing '100.00' to '100'),
 * optionally parameterized by an explicit column list, and returns a strictly PHI-free diff report
 * containing ONLY counts, SHA-256 digests, column names, 1-based row numbers, and integer cent deltas.
 */
export function compareCsvExactText(leftBytes, rightBytes, options = {}) {
  return compareCsvExactTextWithParsed(leftBytes, rightBytes, options).report;
}

function verifyLedgerAndBobConservation(bobParsed, ledgerParsed, { uplineAmountColumn = null } = {}) {
  const lHdr = ledgerParsed.leftHeader;
  const lRows = ledgerParsed.leftRows;
  const grossIdx = lHdr.indexOf('gross_comm');
  const downIdx = lHdr.indexOf('downline_amount');
  const upCol = resolveUplineAmountColumn(lHdr, uplineAmountColumn);
  const upIdx = upCol ? lHdr.indexOf(upCol) : -1;
  const policyIdx = lHdr.indexOf('policy_id');

  const hasSplitCols = grossIdx >= 0 && downIdx >= 0 && upIdx >= 0;
  if (!hasSplitCols) {
    return {
      checked: false,
      passed: true,
      splitViolationCount: 0,
      splitViolationRowNumbers: [],
      bobRollupChecked: false,
      bobMoneyParseViolationCount: 0,
      bobMoneyParseViolationRowNumbers: [],
      bobDownlineRemainderCents: 0,
      bobUplineRemainderCents: 0,
    };
  }

  const splitViolationRowNumbers = [];
  let splitViolationCount = 0;
  let ledGrossCents = 0n;
  let ledDownCents = 0n;
  let ledUpCents = 0n;
  let polLedDownCents = 0n;
  let polLedUpCents = 0n;

  for (let i = 0; i < lRows.length; i++) {
    const r = lRows[i];
    const g = tryParseCents(r[grossIdx] ?? '');
    const d = tryParseCents(r[downIdx] ?? '');
    const u = tryParseCents(r[upIdx] ?? '');
    if (g == null || d == null || u == null || d + u !== g) {
      splitViolationCount += 1;
      if (splitViolationRowNumbers.length < DEFAULT_MAX_DIFF_ROWS) {
        splitViolationRowNumbers.push(i + 1);
      }
      continue;
    }
    ledGrossCents += g;
    ledDownCents += d;
    ledUpCents += u;
    const pid = policyIdx >= 0 ? String(r[policyIdx] ?? '').trim() : '';
    if (pid !== '') {
      polLedDownCents += d;
      polLedUpCents += u;
    }
  }

  let bobRollupChecked = false;
  let bobMoneyParseViolationCount = 0;
  const bobMoneyParseViolationRowNumbers = [];
  let bobDownlineRemainderCents = 0;
  let bobUplineRemainderCents = 0;
  if (bobParsed) {
    const bHdr = bobParsed.leftHeader;
    const bRows = bobParsed.leftRows;
    const bAmtIdx = bHdr.indexOf('amount');
    const bUpCol = resolveUplineAmountColumn(bHdr, uplineAmountColumn);
    const bUpIdx = bUpCol ? bHdr.indexOf(bUpCol) : -1;
    if (bAmtIdx >= 0 && bUpIdx >= 0) {
      bobRollupChecked = true;
      let bobDown = 0n;
      let bobUp = 0n;
      for (let i = 0; i < bRows.length; i++) {
        const r = bRows[i];
        const a = parseMoneyCellStrict(r[bAmtIdx] ?? '');
        const u = parseMoneyCellStrict(r[bUpIdx] ?? '');
        if (!a.ok || !u.ok) {
          bobMoneyParseViolationCount += 1;
          if (bobMoneyParseViolationRowNumbers.length < DEFAULT_MAX_DIFF_ROWS) {
            bobMoneyParseViolationRowNumbers.push(i + 1);
          }
          continue;
        }
        if (a.cents != null) bobDown += a.cents;
        if (u.cents != null) bobUp += u.cents;
      }
      bobDownlineRemainderCents = Number(bobDown - polLedDownCents);
      bobUplineRemainderCents = Number(bobUp - polLedUpCents);
    }
  }

  return {
    checked: true,
    passed: splitViolationCount === 0
      && bobMoneyParseViolationCount === 0
      && bobDownlineRemainderCents === 0
      && bobUplineRemainderCents === 0,
    splitViolationCount,
    splitViolationRowNumbers,
    ledgerGrossTotal: formatCents(ledGrossCents),
    ledgerDownlineTotal: formatCents(ledDownCents),
    ledgerUplineTotal: formatCents(ledUpCents),
    bobRollupChecked,
    bobMoneyParseViolationCount,
    bobMoneyParseViolationRowNumbers,
    bobDownlineRemainderCents,
    bobUplineRemainderCents,
  };
}

function compareEmitMetadata(leftMetaObj, rightMetaObj) {
  if (!leftMetaObj && !rightMetaObj) {
    return { checked: false, passed: true, statusMismatchCount: 0, trajectoryMismatchCount: 0 };
  }
  if (!leftMetaObj || !rightMetaObj) {
    return { checked: true, passed: false, statusMismatchCount: 1, trajectoryMismatchCount: 1, reason: 'metadata missing on one side' };
  }
  const compareKeyMap = (a, b) => {
    const mapA = a && typeof a === 'object' ? a : {};
    const mapB = b && typeof b === 'object' ? b : {};
    const keys = new Set([...Object.keys(mapA), ...Object.keys(mapB)]);
    let mismatches = 0;
    for (const k of keys) {
      if (canonicalJson(mapA[k] ?? null) !== canonicalJson(mapB[k] ?? null)) {
        mismatches += 1;
      }
    }
    return mismatches;
  };
  const statusMismatchCount = compareKeyMap(leftMetaObj.coherentStatus, rightMetaObj.coherentStatus);
  const trajectoryMismatchCount = compareKeyMap(leftMetaObj.coherentTrajectory, rightMetaObj.coherentTrajectory);
  return {
    checked: true,
    passed: statusMismatchCount === 0 && trajectoryMismatchCount === 0,
    statusMismatchCount,
    trajectoryMismatchCount,
  };
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

function discoverSubstanceArtifacts(sideMap, { entity = null } = {}) {
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

  let canonicalBob = null;
  if (sideMap.has('emits/canonical_bob.csv')) {
    canonicalBob = sideMap.get('emits/canonical_bob.csv');
  } else if (emPrefix && viewerCfg?.features?.CANONICAL_BOB) {
    const firstRel = Object.values(viewerCfg.features.CANONICAL_BOB)[0];
    if (firstRel && sideMap.has(`${emPrefix}${firstRel}`)) canonicalBob = sideMap.get(`${emPrefix}${firstRel}`);
  } else if (emPrefix && sideMap.has(`${emPrefix}data/canonical_bob.csv`)) {
    canonicalBob = sideMap.get(`${emPrefix}data/canonical_bob.csv`);
  }

  let coherentLedger = null;
  if (sideMap.has('emits/coherent_ledger.csv')) {
    coherentLedger = sideMap.get('emits/coherent_ledger.csv');
  } else if (emPrefix && viewerCfg?.features?.COHERENT_LEDGER) {
    const firstRel = Object.values(viewerCfg.features.COHERENT_LEDGER)[0];
    if (firstRel && sideMap.has(`${emPrefix}${firstRel}`)) coherentLedger = sideMap.get(`${emPrefix}${firstRel}`);
  } else if (emPrefix && sideMap.has(`${emPrefix}data/coherent_ledger.csv`)) {
    coherentLedger = sideMap.get(`${emPrefix}data/coherent_ledger.csv`);
  }

  let statementsDelta = null;
  let statementsDeltaRelPath = null;
  for (const k of keys) {
    if (STATEMENTS_DELTA_RE.test(k)) {
      statementsDelta = sideMap.get(k);
      statementsDeltaRelPath = k;
      break;
    }
  }

  let emitMetadata = null;
  if (sideMap.has('emits/emit_metadata.json')) {
    try {
      emitMetadata = JSON.parse(sideMap.get('emits/emit_metadata.json').bytes.toString('utf8'));
    } catch {
      emitMetadata = null;
    }
  } else if (viewerCfg && (viewerCfg.coherentStatus || viewerCfg.coherentTrajectory)) {
    emitMetadata = {
      coherentStatus: viewerCfg.coherentStatus || {},
      coherentTrajectory: viewerCfg.coherentTrajectory || {},
    };
  }

  const entityStatements = new Map();
  for (const k of keys) {
    if (k.startsWith('emits/entity_statements/') && k.endsWith('.csv')) {
      entityStatements.set(k.slice('emits/entity_statements/'.length), sideMap.get(k));
    } else if (emPrefix && k.startsWith(`${emPrefix}data/entity_statements/`) && k.endsWith('.csv')) {
      entityStatements.set(k.slice(`${emPrefix}data/entity_statements/`.length), sideMap.get(k));
    }
  }
  if (emPrefix && viewerCfg?.features?.ENTITY_STATEMENTS) {
    for (const [tblKey, rel] of Object.entries(viewerCfg.features.ENTITY_STATEMENTS)) {
      const full = `${emPrefix}${rel}`;
      if (sideMap.has(full)) entityStatements.set(tblKey, sideMap.get(full));
    }
  }

  return {
    canonicalBob,
    coherentLedger,
    statementsDelta,
    statementsDeltaRelPath,
    emitMetadata,
    entityStatements,
  };
}

async function evaluateDbEntityStatementsGate(pool, { leftRunId, rightRunId = null, expectedEntityParity = null }) {
  const matCheck = await pool.query(
    'SELECT attempt_event_id, ledger_gross_total::text AS ledger_gross_total FROM coherence.run_materializations WHERE run_id = $1::uuid',
    [leftRunId],
  );
  if (matCheck.rows.length === 0) {
    if (expectedEntityParity && typeof expectedEntityParity === 'object') {
      const reason = 'left run has no run_materializations row';
      return {
        checked: true,
        passed: false,
        reconciled: false,
        reason,
        datesChecked: 0,
        filesChecked: 0,
        totalLines: 0,
        perEntityTotals: {},
        entityVariancesCents: {},
        unreconciledEntities: 0,
        recordMismatchCount: 0,
        ledgerGrossTotal: null,
        ledgerRemainderCents: null,
        rightComparison: null,
        expectedParityPassed: false,
        expectedParityProblems: [reason],
      };
    }
    return { checked: false, passed: true, reason: 'left run has no run_materializations row' };
  }

  const recRes = await pool.query(
    `SELECT statement_entity, account_kind, statement_total::text AS statement_total,
            ledger_total::text AS ledger_total, variance::text AS variance, reconciled
     FROM coherence_views.v_entity_statement_reconciliation($1::uuid)`,
    [leftRunId],
  );
  const perEntityTotals = {};
  const entityVariancesCents = {};
  let ledgerRemainderCents = 0n;
  let unreconciledEntities = 0;

  for (const r of recRes.rows) {
    const stmtCents = parseCents(r.statement_total) ?? 0n;
    const varCents = parseCents(r.variance) ?? 0n;
    perEntityTotals[r.statement_entity] = formatCents(stmtCents);
    entityVariancesCents[r.statement_entity] = Number(varCents);
    ledgerRemainderCents += varCents;
    if (!r.reconciled || varCents !== 0n) unreconciledEntities += 1;
  }

  // Record-level variance count (strictly PHI-free: only count, never record_id values).
  const recVarRes = await pool.query(
    `WITH rm AS (SELECT attempt_event_id FROM coherence.run_materializations WHERE run_id = $1::uuid),
          eff AS (SELECT batch_id FROM coherence.run_effective_statement_batches($1::uuid)),
          s_ag AS (
            SELECT sal.record_id, sal.entity, COALESCE(pg_catalog.sum(sal.amount), 0.00) AS amt
            FROM coherence.statement_agency_lines sal JOIN eff ON eff.batch_id = sal.batch_id
            GROUP BY sal.record_id, sal.entity
          ),
          l_ag AS (
            SELECT clr.record_id, clr.entity, COALESCE(pg_catalog.sum(clr.downline_amount), 0.00) AS amt
            FROM coherence.coherent_ledger_rows clr JOIN rm ON rm.attempt_event_id = clr.attempt_event_id
            GROUP BY clr.record_id, clr.entity
          ),
          s_up AS (
            SELECT sul.record_id, COALESCE(pg_catalog.sum(sul.amount), 0.00) AS amt
            FROM coherence.statement_upline_lines sul JOIN eff ON eff.batch_id = sul.batch_id
            GROUP BY sul.record_id
          ),
          l_up AS (
            SELECT clr.record_id, COALESCE(pg_catalog.sum(clr.upline_amount), 0.00) AS amt
            FROM coherence.coherent_ledger_rows clr JOIN rm ON rm.attempt_event_id = clr.attempt_event_id
            GROUP BY clr.record_id
          )
     SELECT (
       (SELECT pg_catalog.count(*)::int FROM s_ag FULL OUTER JOIN l_ag ON l_ag.record_id = s_ag.record_id AND l_ag.entity = s_ag.entity
        WHERE COALESCE(s_ag.amt, 0.00) <> COALESCE(l_ag.amt, 0.00))
       + (SELECT pg_catalog.count(*)::int FROM s_up FULL OUTER JOIN l_up ON l_up.record_id = s_up.record_id
          WHERE COALESCE(s_up.amt, 0.00) <> COALESCE(l_up.amt, 0.00))
     ) AS mismatch_count`,
    [leftRunId],
  );
  const recordMismatchCount = Number(recVarRes.rows[0]?.mismatch_count ?? 0);

  const totalsRes = await pool.query(
    `SELECT pg_catalog.to_char(t.statement_date, 'YYYY-MM-DD') AS statement_date,
            t.statement_entity, t.account_kind, t.src_type, t.payment_month,
            t.line_count::bigint AS line_count, t.net_amount::text AS net_amount
     FROM coherence_views.v_entity_statement_totals t
     JOIN coherence.run_effective_statement_batches($1::uuid) eff ON eff.batch_id = t.batch_id`,
    [leftRunId],
  );
  const distinctDates = new Set();
  const distinctDateEntities = new Set();
  let totalLines = 0;
  for (const r of totalsRes.rows) {
    distinctDates.add(r.statement_date);
    distinctDateEntities.add(`${r.statement_date}:${r.statement_entity}`);
    totalLines += Number(r.line_count);
  }

  // If rightRunId is also materialized, compute exact per-entity cent deltas between left and right runs.
  let rightComparison = null;
  let entityCentDeltas = null;
  let rightComparisonPassed = true;
  if (rightRunId) {
    const rightMat = await pool.query(
      'SELECT attempt_event_id FROM coherence.run_materializations WHERE run_id = $1::uuid',
      [rightRunId],
    );
    if (rightMat.rows.length > 0) {
      const rightRecRes = await pool.query(
        `SELECT statement_entity, statement_total::text AS statement_total
         FROM coherence_views.v_entity_statement_reconciliation($1::uuid)`,
        [rightRunId],
      );
      const rightTotals = {};
      for (const r of rightRecRes.rows) rightTotals[r.statement_entity] = r.statement_total;
      const allEntities = [...new Set([...Object.keys(perEntityTotals), ...Object.keys(rightTotals)])].sort();
      entityCentDeltas = {};
      let differingEntities = 0;
      for (const ent of allEntities) {
        const lc = parseCents(perEntityTotals[ent] ?? '0.00') ?? 0n;
        const rc = parseCents(rightTotals[ent] ?? '0.00') ?? 0n;
        const delta = Number(lc - rc);
        entityCentDeltas[ent] = delta;
        if (delta !== 0) differingEntities += 1;
      }
      rightComparisonPassed = differingEntities === 0;
      rightComparison = {
        passed: rightComparisonPassed,
        differingEntityCount: differingEntities,
        entityCentDeltas,
      };
    }
  }

  let expectedParityPassed = true;
  const expectedParityProblems = [];
  if (expectedEntityParity && typeof expectedEntityParity === 'object') {
    if (expectedEntityParity.datesChecked != null && distinctDates.size !== Number(expectedEntityParity.datesChecked)) {
      expectedParityPassed = false;
      expectedParityProblems.push(`datesChecked expected ${expectedEntityParity.datesChecked}, got ${distinctDates.size}`);
    }
    if (expectedEntityParity.filesChecked != null && distinctDateEntities.size !== Number(expectedEntityParity.filesChecked)) {
      expectedParityPassed = false;
      expectedParityProblems.push(`filesChecked expected ${expectedEntityParity.filesChecked}, got ${distinctDateEntities.size}`);
    }
    if (expectedEntityParity.totalLines != null && totalLines !== Number(expectedEntityParity.totalLines)) {
      expectedParityPassed = false;
      expectedParityProblems.push(`totalLines expected ${expectedEntityParity.totalLines}, got ${totalLines}`);
    }
    if (expectedEntityParity.ledgerGrossTotal != null && matCheck.rows[0].ledger_gross_total !== String(expectedEntityParity.ledgerGrossTotal)) {
      expectedParityPassed = false;
      expectedParityProblems.push(`ledgerGrossTotal expected ${expectedEntityParity.ledgerGrossTotal}, got ${matCheck.rows[0].ledger_gross_total}`);
    }
    if (expectedEntityParity.perEntityTotals && typeof expectedEntityParity.perEntityTotals === 'object') {
      const expectedMap = expectedEntityParity.perEntityTotals;
      const allEntities = [...new Set([...Object.keys(expectedMap), ...Object.keys(perEntityTotals)])].sort();
      for (const ent of allEntities) {
        const hasExpected = Object.prototype.hasOwnProperty.call(expectedMap, ent);
        const hasActual = Object.prototype.hasOwnProperty.call(perEntityTotals, ent);
        if (!hasExpected) {
          expectedParityPassed = false;
          const actualAmt = perEntityTotals[ent] ?? '0.00';
          const delta = Number(parseCents(actualAmt) ?? 0n);
          expectedParityProblems.push(`unexpected entity ${ent} total ${actualAmt} (delta ${delta} cents)`);
          continue;
        }
        const expectedAmt = String(expectedMap[ent]);
        const actualAmt = hasActual ? perEntityTotals[ent] : '0.00';
        if (actualAmt !== expectedAmt) {
          expectedParityPassed = false;
          const delta = Number((parseCents(actualAmt) ?? 0n) - (parseCents(expectedAmt) ?? 0n));
          expectedParityProblems.push(`entity ${ent} total delta ${delta} cents`);
        }
      }
    }
  }

  const passed = unreconciledEntities === 0
    && recordMismatchCount === 0
    && ledgerRemainderCents === 0n
    && rightComparisonPassed
    && expectedParityPassed;

  return {
    checked: true,
    passed,
    reconciled: unreconciledEntities === 0 && recordMismatchCount === 0,
    datesChecked: distinctDates.size,
    filesChecked: distinctDateEntities.size,
    totalLines,
    perEntityTotals,
    entityVariancesCents,
    unreconciledEntities,
    recordMismatchCount,
    ledgerGrossTotal: matCheck.rows[0].ledger_gross_total,
    ledgerRemainderCents: Number(ledgerRemainderCents),
    rightComparison,
    expectedParityPassed,
    expectedParityProblems,
  };
}

/**
 * Compares two run folders on disk, checking input/ by SHA-256 first (Gate 1), then comparing
 * outputs or substance tables (Gates 2 to 4) under mode-specific rules.
 * Supported modes: 'storage', 'replay', 'shadow', 'trial', 'entity_mapped', 'substance'.
 */
export async function compareRunFolders(leftDir, rightDir, {
  mode = 'replay',
  entityMapping = null,
  entity = null,
  columns = {},
  moneyColumns = null,
  uplineAmountColumn = null,
  requireStatementsDelta = false,
  requireConservation = false,
  allowOverlayLineEndingDiff = (mode === 'substance'),
  includeDsStore = (mode === 'storage'),
  dbContext = null,
  expectedEntityParity = null,
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

  // Gate 1: Inputs first (Eyes protocol: every input file compared by SHA-256).
  const leftInputs = leftAll.filter((f) => f.startsWith('input/'));
  const rightInputs = rightAll.filter((f) => f.startsWith('input/'));
  const inputReport = {
    fileCount: leftInputs.length,
    same: 0,
    changed: [],
    onlyLeft: [],
    onlyRight: [],
    overlayRowCheck: null,
    passed: true,
  };

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
    } else if (allowOverlayLineEndingDiff && normalizeMacKey(rel) === 'input/overlay/overlay.csv') {
      const ovCmp = compareCsvExactText(leftMap.get(rel).bytes, rightMap.get(rel).bytes, { tableName: rel });
      inputReport.overlayRowCheck = ovCmp;
      if (ovCmp.passed) {
        inputReport.same += 1;
      } else {
        inputReport.changed.push({ relPath: rel, leftSha256: leftMap.get(rel).sha256, rightSha256: rightMap.get(rel).sha256 });
      }
    } else {
      inputReport.changed.push({ relPath: rel, leftSha256: leftMap.get(rel).sha256, rightSha256: rightMap.get(rel).sha256 });
    }
  }
  for (const rel of rightInputs) {
    if (!leftMap.has(rel)) inputReport.onlyRight.push(rel);
  }
  inputReport.passed = inputReport.changed.length === 0 && inputReport.onlyLeft.length === 0 && inputReport.onlyRight.length === 0;

  if (mode === 'substance') {
    const executedAtUtc = new Date().toISOString();
    const problems = [];

    // Gate 1 hard stop: never claim substance parity when inputs differ.
    if (!inputReport.passed) {
      problems.push(
        `Gate 1 failed: input mismatch (changed=${inputReport.changed.length}, onlyLeft=${inputReport.onlyLeft.length}, onlyRight=${inputReport.onlyRight.length})`,
      );
      return {
        layer: 3,
        mode,
        leftLabel,
        rightLabel,
        executedAtUtc,
        passed: false,
        stoppedAtGate: 1,
        inputs: inputReport,
        gates: {
          gate1: { passed: false, inputs: inputReport },
          gate2: { passed: false, skipped: true, reason: 'stopped_at_gate_1' },
          gate3: { passed: false, skipped: true, reason: 'stopped_at_gate_1' },
          gate4: { passed: false, skipped: true, reason: 'stopped_at_gate_1' },
        },
        substance: {
          passed: false,
          skipped: true,
          reason: 'stopped_at_gate_1',
          same: [],
          missingRequired: [],
          unexpectedDiffs: [],
          onlyLeft: [],
          onlyRight: [],
          bob: null,
          ledger: null,
          statementsDelta: null,
          entityStatements: null,
        },
        entityStatements: null,
        tree: null,
        problems,
      };
    }

    const leftArt = discoverSubstanceArtifacts(leftMap, { entity });
    const rightArt = discoverSubstanceArtifacts(rightMap, { entity });

    const same = [];
    const missingRequired = [];
    const unexpectedDiffs = [];
    const onlyLeft = [];
    const onlyRight = [];

    // Gate 2: Canonical Book of Business (exact UTF-8 cell-for-cell + metadata status/trajectory).
    let bobCmp = null;
    let bobParsed = null;
    if (!leftArt.canonicalBob) missingRequired.push({ side: 'left', table: 'canonical_bob' });
    if (!rightArt.canonicalBob) missingRequired.push({ side: 'right', table: 'canonical_bob' });
    if (leftArt.canonicalBob && rightArt.canonicalBob) {
      ({ report: bobCmp, parsed: bobParsed } = compareCsvExactTextWithParsed(leftArt.canonicalBob.bytes, rightArt.canonicalBob.bytes, {
        tableName: 'canonical_bob',
        expectedColumns: columns.bob || null,
        moneyColumns,
        entityMapping,
      }));
      const metaCheck = compareEmitMetadata(leftArt.emitMetadata, rightArt.emitMetadata);
      bobCmp.metadataCheck = metaCheck;
      bobCmp.passed = bobCmp.passed && metaCheck.passed;
      if (bobCmp.passed) same.push('canonical_bob');
      else {
        unexpectedDiffs.push({
          table: 'canonical_bob',
          leftSha256: bobCmp.leftSha256,
          rightSha256: bobCmp.rightSha256,
          differingRowCount: bobCmp.differingRowCount,
          columnMismatchCounts: bobCmp.columnMismatchCounts,
          moneyCentDeltas: bobCmp.moneyCentDeltas,
        });
        problems.push(`Gate 2 failed: canonical_bob mismatch (differingRows=${bobCmp.differingRowCount})`);
      }
    } else {
      problems.push('Gate 2 failed: canonical_bob missing on one or both sides');
    }
    const gate2Passed = Boolean(bobCmp && bobCmp.passed);

    // Gate 3: Coherent Ledger (exact UTF-8 cell-for-cell + split & BoB-to-Ledger rollup conservation).
    let ledgerCmp = null;
    let ledgerParsed = null;
    let conservationCheck = null;
    if (!leftArt.coherentLedger) missingRequired.push({ side: 'left', table: 'coherent_ledger' });
    if (!rightArt.coherentLedger) missingRequired.push({ side: 'right', table: 'coherent_ledger' });
    if (leftArt.coherentLedger && rightArt.coherentLedger) {
      ({ report: ledgerCmp, parsed: ledgerParsed } = compareCsvExactTextWithParsed(leftArt.coherentLedger.bytes, rightArt.coherentLedger.bytes, {
        tableName: 'coherent_ledger',
        expectedColumns: columns.ledger || null,
        moneyColumns,
        entityMapping,
      }));
      conservationCheck = verifyLedgerAndBobConservation(bobParsed, ledgerParsed, {
        uplineAmountColumn,
      });
      if (requireConservation && (!conservationCheck.checked || !conservationCheck.bobRollupChecked)) {
        conservationCheck.passed = false;
      }
      ledgerCmp.conservation = conservationCheck;
      ledgerCmp.passed = ledgerCmp.passed && conservationCheck.passed;
      if (ledgerCmp.passed) same.push('coherent_ledger');
      else {
        unexpectedDiffs.push({
          table: 'coherent_ledger',
          leftSha256: ledgerCmp.leftSha256,
          rightSha256: ledgerCmp.rightSha256,
          differingRowCount: ledgerCmp.differingRowCount,
          columnMismatchCounts: ledgerCmp.columnMismatchCounts,
          moneyCentDeltas: ledgerCmp.moneyCentDeltas,
        });
        problems.push(`Gate 3 failed: coherent_ledger mismatch (differingRows=${ledgerCmp.differingRowCount}, conservation=${conservationCheck.passed})`);
      }
    } else {
      problems.push('Gate 3 failed: coherent_ledger missing on one or both sides');
    }
    const gate3Passed = Boolean(ledgerCmp && ledgerCmp.passed);

    // Gate 4: Run Delta statements_YYYYMMDD.csv and Entity Statements (folder CSVs + DB views if present).
    let statementsDeltaCmp = null;
    let statementsDeltaPassed = true;
    if (leftArt.statementsDelta || rightArt.statementsDelta || requireStatementsDelta) {
      if (!leftArt.statementsDelta) {
        missingRequired.push({ side: 'left', table: 'statements_delta' });
        statementsDeltaPassed = false;
        problems.push('Gate 4 failed: statements_YYYYMMDD.csv missing on left side');
      }
      if (!rightArt.statementsDelta) {
        missingRequired.push({ side: 'right', table: 'statements_delta' });
        statementsDeltaPassed = false;
        problems.push('Gate 4 failed: statements_YYYYMMDD.csv missing on right side');
      }
      if (leftArt.statementsDelta && rightArt.statementsDelta) {
        statementsDeltaCmp = compareCsvExactText(leftArt.statementsDelta.bytes, rightArt.statementsDelta.bytes, {
          tableName: leftArt.statementsDeltaRelPath || 'statements_delta',
          expectedColumns: columns.statements || null,
          moneyColumns,
          entityMapping,
        });
        statementsDeltaPassed = statementsDeltaCmp.passed;
        if (statementsDeltaCmp.passed) {
          same.push('statements_delta');
        } else {
          unexpectedDiffs.push({
            table: 'statements_delta',
            leftSha256: statementsDeltaCmp.leftSha256,
            rightSha256: statementsDeltaCmp.rightSha256,
            differingRowCount: statementsDeltaCmp.differingRowCount,
            columnMismatchCounts: statementsDeltaCmp.columnMismatchCounts,
            moneyCentDeltas: statementsDeltaCmp.moneyCentDeltas,
          });
          problems.push(`Gate 4 failed: statements_delta mismatch (differingRows=${statementsDeltaCmp.differingRowCount})`);
        }
      }
    }

    const entityFileResults = {};
    let entityFilesPassed = true;
    for (const [name, leftEntry] of leftArt.entityStatements.entries()) {
      if (!rightArt.entityStatements.has(name)) {
        onlyLeft.push(`entity_statements/${name}`);
        entityFilesPassed = false;
        problems.push(`Gate 4 failed: entity statement ${name} only on left side`);
        continue;
      }
      const rightEntry = rightArt.entityStatements.get(name);
      const cmp = compareCsvExactText(leftEntry.bytes, rightEntry.bytes, {
        tableName: `entity_statements/${name}`,
        expectedColumns: columns.entityStatements || null,
        moneyColumns,
        entityMapping,
      });
      entityFileResults[name] = cmp;
      if (cmp.passed) {
        same.push(`entity_statements/${name}`);
      } else {
        entityFilesPassed = false;
        unexpectedDiffs.push({
          table: `entity_statements/${name}`,
          leftSha256: cmp.leftSha256,
          rightSha256: cmp.rightSha256,
          differingRowCount: cmp.differingRowCount,
          columnMismatchCounts: cmp.columnMismatchCounts,
          moneyCentDeltas: cmp.moneyCentDeltas,
        });
        problems.push(`Gate 4 failed: entity statement ${name} mismatch (differingRows=${cmp.differingRowCount})`);
      }
    }
    for (const name of rightArt.entityStatements.keys()) {
      if (!leftArt.entityStatements.has(name)) {
        onlyRight.push(`entity_statements/${name}`);
        entityFilesPassed = false;
        problems.push(`Gate 4 failed: entity statement ${name} only on right side`);
      }
    }

    let dbEntityReport = null;
    if (dbContext?.pool && dbContext?.leftRunId) {
      dbEntityReport = await evaluateDbEntityStatementsGate(dbContext.pool, {
        leftRunId: dbContext.leftRunId,
        rightRunId: dbContext.rightRunId || null,
        expectedEntityParity,
      });
      if (dbEntityReport.checked && !dbEntityReport.passed) {
        if (dbEntityReport.reason) {
          problems.push(`Gate 4 failed: ${dbEntityReport.reason}`);
        } else {
          const parityDetail = dbEntityReport.expectedParityProblems?.length
            ? `, parity=[${dbEntityReport.expectedParityProblems.join('; ')}]`
            : '';
          problems.push(
            `Gate 4 failed: entity statement reconciliation or parity mismatch (unreconciled=${dbEntityReport.unreconciledEntities}, recordMismatches=${dbEntityReport.recordMismatchCount}, rightMatch=${dbEntityReport.rightComparison?.passed ?? true}${parityDetail})`,
          );
        }
      }
    } else if (expectedEntityParity && typeof expectedEntityParity === 'object') {
      const reason = 'expectedEntityParity requested without a database run (no run_materializations row)';
      dbEntityReport = {
        checked: true,
        passed: false,
        reconciled: false,
        reason,
        datesChecked: 0,
        filesChecked: 0,
        totalLines: 0,
        perEntityTotals: {},
        entityVariancesCents: {},
        unreconciledEntities: 0,
        recordMismatchCount: 0,
        ledgerGrossTotal: null,
        ledgerRemainderCents: null,
        rightComparison: null,
        expectedParityPassed: false,
        expectedParityProblems: [reason],
      };
      problems.push(`Gate 4 failed: ${reason}`);
    }

    const dbEntityPassed = dbEntityReport ? (!dbEntityReport.checked || dbEntityReport.passed) : true;
    const gate4Passed = statementsDeltaPassed && entityFilesPassed && dbEntityPassed;

    const bobClean = bobCmp;
    const ledgerClean = ledgerCmp;
    const stmtDeltaClean = statementsDeltaCmp;
    const entityStatementsSummary = {
      passed: entityFilesPassed && dbEntityPassed,
      folderFilesChecked: Object.keys(entityFileResults).length,
      folderFiles: entityFileResults,
      dbReconciliation: dbEntityReport,
      datesChecked: dbEntityReport?.datesChecked ?? null,
      filesChecked: dbEntityReport?.filesChecked ?? Object.keys(entityFileResults).length,
      totalLines: dbEntityReport?.totalLines ?? null,
      perEntityTotals: dbEntityReport?.perEntityTotals ?? null,
      entityCentDeltas: dbEntityReport?.rightComparison?.entityCentDeltas ?? null,
      ledgerGrossTotal: dbEntityReport?.ledgerGrossTotal ?? conservationCheck?.ledgerGrossTotal ?? null,
      ledgerRemainderCents: dbEntityReport?.ledgerRemainderCents ?? null,
    };

    const substancePassed = gate2Passed && gate3Passed && gate4Passed
      && missingRequired.length === 0
      && unexpectedDiffs.length === 0
      && onlyLeft.length === 0
      && onlyRight.length === 0;

    const stoppedAtGate = !gate2Passed ? 2 : (!gate3Passed ? 3 : (!gate4Passed ? 4 : null));

    return {
      layer: 3,
      mode,
      leftLabel,
      rightLabel,
      executedAtUtc,
      passed: inputReport.passed && substancePassed,
      stoppedAtGate,
      inputs: inputReport,
      gates: {
        gate1: { passed: true, inputs: inputReport },
        gate2: { passed: gate2Passed, bob: bobClean },
        gate3: { passed: gate3Passed, ledger: ledgerClean },
        gate4: { passed: gate4Passed, statementsDelta: stmtDeltaClean, entityStatements: entityStatementsSummary },
      },
      substance: {
        passed: substancePassed,
        same,
        missingRequired,
        unexpectedDiffs,
        onlyLeft,
        onlyRight,
        bob: bobClean,
        ledger: ledgerClean,
        statementsDelta: stmtDeltaClean,
        entityStatements: entityStatementsSummary,
      },
      entityStatements: entityStatementsSummary,
      tree: null,
      problems,
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
  columns = {},
  moneyColumns = null,
  uplineAmountColumn = null,
  requireStatementsDelta = false,
  requireConservation = false,
  expectedEntityParity = null,
  checkKind = null,
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
      columns,
      moneyColumns,
      uplineAmountColumn,
      requireStatementsDelta,
      requireConservation,
      expectedEntityParity,
      dbContext: mode === 'substance' ? { pool, leftRunId, rightRunId } : null,
      leftLabel: `run:${leftRunId}`,
      rightLabel: rightRunId ? `run:${rightRunId}` : rightFolderDir,
    });
    if (commands && actor) {
      const resolvedCheckKind = checkKind || (mode === 'shadow' ? 'shadow' : (mode === 'replay' || mode === 'substance' ? 'replay' : 'trial_comparison'));
      const digest = sha256Hex(JSON.stringify(report));
      const keyDigest = sha256Hex(canonicalJson([resolvedCheckKind, leftRunId, rightRunId || rightFolderDir || null, digest]));
      await commands.recordCheck({
        actor,
        commandKey: `check-${resolvedCheckKind}:${keyDigest}`,
        checkKind: resolvedCheckKind,
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
