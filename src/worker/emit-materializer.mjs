// Parses canonical_bob.csv, coherent_ledger.csv, statements_YYYYMMDD.csv, optional emit_metadata.json,
// and optional working/tx.csv into conservation-checked records ready for atomic PostgreSQL loading.
import { randomUUID } from 'node:crypto';
import {
  hashBobRows,
  hashLedgerRows,
  hashStatementAgencyLines,
  hashStatementUplineLines,
} from '../journal/commitments.mjs';
import { isValidIsoDate, parseCsv } from '../util/csv.mjs';
import { AppError } from '../util/redact.mjs';

const STANDARD_AMOUNT_COLUMNS = new Set([
  'amount',
  'downline_amount',
  'override_amount',
  'commission_amount',
  'hra_amount',
  'fee_amount',
  'other_amount',
  'approved_amount',
]);

const BUCKET_COLS = [
  'override_amount',
  'commission_amount',
  'hra_amount',
  'fee_amount',
  'other_amount',
];

function formatCellRef(context) {
  if (!context) return '';
  if (typeof context === 'string') return ` (${context})`;
  const parts = [];
  if (context.table) parts.push(`table ${context.table}`);
  if (context.column) parts.push(`column ${context.column}`);
  if (context.rowNo != null) parts.push(`row ${context.rowNo}`);
  return parts.length > 0 ? ` (${parts.join(', ')})` : '';
}

export function parseCents(val, context = null) {
  if (val == null) return null;
  const s = String(val).trim();
  if (s === '') return null;
  const m = /^([+-])?(\d+)(?:\.(\d+))?$/.exec(s);
  if (!m) {
    throw new AppError(`INVALID_MONEY_AMOUNT: invalid monetary amount${formatCellRef(context)}.`, 422, 'INVALID_MONEY_AMOUNT');
  }
  const frac = (m[3] || '').padEnd(2, '0');
  if (frac.length > 2) {
    throw new AppError(`INVALID_MONEY_AMOUNT: monetary amount exceeds 2 decimal places${formatCellRef(context)}.`, 422, 'INVALID_MONEY_AMOUNT');
  }
  const abs = BigInt(m[2]) * 100n + BigInt(frac);
  return m[1] === '-' ? -abs : abs;
}

export function formatCents(cents) {
  if (cents == null) return null;
  const neg = cents < 0n;
  const abs = neg ? -cents : cents;
  const whole = abs / 100n;
  const frac = String(abs % 100n).padStart(2, '0');
  return `${neg && abs !== 0n ? '-' : ''}${whole}.${frac}`;
}

function emptyToNull(val) {
  if (val == null) return null;
  const s = String(val);
  return s === '' ? null : s;
}

function parseIntOrNull(val, context = null) {
  const s = emptyToNull(val);
  if (s === null) return null;
  if (!/^-?\d+$/.test(s.trim())) {
    throw new AppError(`INVALID_INTEGER: invalid integer${formatCellRef(context)}.`, 422, 'INVALID_INTEGER');
  }
  return Number.parseInt(s.trim(), 10);
}

function parseBool(val, context = null) {
  if (typeof val === 'boolean') return val;
  const s = String(val ?? '').trim().toLowerCase();
  if (s === 'true' || s === '1' || s === 't' || s === 'yes') return true;
  if (s === 'false' || s === '0' || s === 'f' || s === 'no' || s === '') return false;
  throw new AppError(`INVALID_BOOLEAN: invalid boolean${formatCellRef(context)}.`, 422, 'INVALID_BOOLEAN');
}

function parseDateOrNull(val, context = null) {
  const s = emptyToNull(val);
  if (s === null) return null;
  const trimmed = s.trim();
  if (!isValidIsoDate(trimmed)) {
    throw new AppError(`INVALID_DATE: invalid ISO date${formatCellRef(context)}.`, 422, 'INVALID_DATE');
  }
  return trimmed;
}

export function parseCsvObjects(csvText, label = 'CSV') {
  const text = Buffer.isBuffer(csvText) ? csvText.toString('utf8') : String(csvText ?? '');
  const matrix = parseCsv(text);
  if (matrix.length === 0) {
    throw new AppError(`${label} is empty and has no header row.`, 422, 'EMPTY_CSV');
  }
  const header = matrix[0];
  const rows = [];
  for (let i = 1; i < matrix.length; i++) {
    const raw = matrix[i];
    if (raw.length === 1 && raw[0] === '') continue;
    const obj = { _rowNo: i };
    for (let j = 0; j < header.length; j++) {
      obj[header[j]] = j < raw.length ? raw[j] : '';
    }
    rows.push(obj);
  }
  return { header, rows };
}

/**
 * Resolves company-agnostic database field names against either neutral CSV headers
 * or engine-emitted CSV headers without hardcoding any company or vendor name.
 */
export function resolveCsvColumnMap(header, overrides = {}) {
  const set = new Set(header);
  const externalPolicyId = overrides.externalPolicyId
    || (set.has('external_policy_id') ? 'external_policy_id' : null)
    || header.find((c) => /^[a-z]{2,4}_id$/.test(c) && c !== 'tx_id')
    || null;
  const crmPolicyNumber = overrides.crmPolicyNumber
    || (set.has('crm_policy_number') ? 'crm_policy_number' : null)
    || header.find((c) => c.endsWith('_policy_number') && c !== 'carrier_policy_number')
    || null;
  const enrollmentCode = overrides.enrollmentCode
    || (set.has('enrollment_code') ? 'enrollment_code' : null)
    || header.find((c) => c.endsWith('_enrollment_code'))
    || null;
  const uplineAmount = overrides.uplineAmount
    || (set.has('upline_amount') ? 'upline_amount' : null)
    || header.find((c) => c.endsWith('_amount') && !STANDARD_AMOUNT_COLUMNS.has(c))
    || null;
  return { externalPolicyId, crmPolicyNumber, enrollmentCode, uplineAmount };
}

export function parseWorkingTxMap(workingTxCsv) {
  const map = new Map();
  if (!workingTxCsv) return map;
  const { header, rows } = parseCsvObjects(workingTxCsv, 'working/tx.csv');
  if (!header.includes('tx_id')) return map;
  for (const r of rows) {
    const txId = parseIntOrNull(r.tx_id, { table: 'working/tx.csv', column: 'tx_id', rowNo: r._rowNo });
    if (txId == null) continue;
    const posCol = r.source_position !== undefined ? 'source_position' : 'source_row_no';
    const pos = parseIntOrNull(r.source_position ?? r.source_row_no, { table: 'working/tx.csv', column: posCol, rowNo: r._rowNo });
    map.set(txId, {
      filename: emptyToNull(r.filename),
      sheetName: emptyToNull(r.sheet_name),
      sourceRowNo: pos && pos >= 1 ? pos : null,
    });
  }
  return map;
}

/**
 * Parses and validates canonical_bob.csv, coherent_ledger.csv, and statements_YYYYMMDD.csv,
 * resolves any NULL-split pre-Coherence reversals against standing entity/upline balances,
 * verifies exact BoB-to-Ledger and statement tie-outs, and builds records for atomic loading.
 */
export async function prepareEmitMaterialization({
  db,
  runId,
  attemptEventId,
  statementDate,
  canonicalBobCsv,
  coherentLedgerCsv,
  statementsCsv,
  emitMetadataJson = null,
  workingTxCsv = null,
  statementsFileName = null,
  statementsFileSha256 = null,
  statementBatchId = randomUUID(),
  reconciliationMode = 'strict_entity_ledger',
  columnMap = {},
}) {
  if (!isValidIsoDate(statementDate)) {
    throw new AppError('statementDate must be a valid ISO date.', 400, 'INVALID_DATE');
  }
  if (!attemptEventId) {
    throw new AppError('attemptEventId is required to prepare Emit materialization.', 400, 'MISSING_ATTEMPT_EVENT_ID');
  }
  const stamp = statementDate.replaceAll('-', '');
  const resolvedFileName = statementsFileName || `statements_${stamp}.csv`;

  let metadata = {};
  if (emitMetadataJson) {
    metadata = typeof emitMetadataJson === 'string' || Buffer.isBuffer(emitMetadataJson)
      ? JSON.parse(Buffer.isBuffer(emitMetadataJson) ? emitMetadataJson.toString('utf8') : emitMetadataJson)
      : emitMetadataJson;
  }
  const coherentStatusMap = metadata.coherentStatus || {};
  const coherentTrajectoryMap = metadata.coherentTrajectory || {};
  const corpusTail = emptyToNull(metadata.corpusTail);
  const agencyStart = parseDateOrNull(metadata.agencyStart, { table: 'emit_metadata', column: 'agencyStart' });

  const workingTxMap = parseWorkingTxMap(workingTxCsv);

  // 1. Parse Canonical Book of Business into zero-dollar bob_policies and 1:1 bob_policy_financials.
  const bobParsed = parseCsvObjects(canonicalBobCsv, 'canonical_bob.csv');
  const bobCols = resolveCsvColumnMap(bobParsed.header, columnMap);
  const bobPolicies = [];
  const bobFinancials = [];
  let bobDownlineCents = 0n;
  let bobUplineCents = 0n;

  for (const row of bobParsed.rows) {
    const bobCell = (column) => ({ table: 'canonical_bob.csv', column, rowNo: row._rowNo });
    const policyId = parseIntOrNull(row.policy_id, bobCell('policy_id'));
    if (policyId == null) {
      throw new AppError(`MISSING_POLICY_ID: missing integer policy_id${formatCellRef(bobCell('policy_id'))}.`, 422, 'MISSING_POLICY_ID');
    }
    const entity = emptyToNull(row.entity);
    if (!entity) {
      throw new AppError(`MISSING_ENTITY: missing entity${formatCellRef(bobCell('entity'))}.`, 422, 'MISSING_ENTITY');
    }
    const writingNpn = emptyToNull(row.writing_npn);
    const amountCents = parseCents(row.amount, bobCell('amount'));
    const uplineCents = bobCols.uplineAmount ? parseCents(row[bobCols.uplineAmount], bobCell(bobCols.uplineAmount)) : null;
    if (amountCents != null) bobDownlineCents += amountCents;
    if (uplineCents != null) bobUplineCents += uplineCents;

    const pidKey = String(policyId);
    bobPolicies.push({
      attemptEventId,
      policyId,
      runId,
      externalPolicyId: bobCols.externalPolicyId ? emptyToNull(row[bobCols.externalPolicyId]) : null,
      carrierPolicyNumber: emptyToNull(row.carrier_policy_number),
      crmPolicyNumber: bobCols.crmPolicyNumber ? emptyToNull(row[bobCols.crmPolicyNumber]) : null,
      carrier: emptyToNull(row.carrier),
      planType: emptyToNull(row.plan_type),
      planName: emptyToNull(row.plan_name),
      simplePlanType: emptyToNull(row.simple_plan_type),
      mbi: emptyToNull(row.mbi),
      member: emptyToNull(row.member),
      dob: emptyToNull(row.dob),
      phone: emptyToNull(row.phone),
      email: emptyToNull(row.email),
      address: emptyToNull(row.address),
      county: emptyToNull(row.county),
      state: emptyToNull(row.state),
      submissionDate: parseDateOrNull(row.submission_date, bobCell('submission_date')),
      originEffective: parseDateOrNull(row.origin_effective, bobCell('origin_effective')),
      effectiveDate: parseDateOrNull(row.effective_date, bobCell('effective_date')),
      terminationDate: parseDateOrNull(row.termination_date, bobCell('termination_date')),
      writingNpn,
      writingAgent: emptyToNull(row.writing_agent),
      entity,
      status: emptyToNull(row.status),
      coherentStatus: emptyToNull(coherentStatusMap[pidKey] ?? row.coherent_status),
    });

    bobFinancials.push({
      attemptEventId,
      policyId,
      entity,
      writingNpn,
      amount: formatCents(amountCents),
      uplineAmount: formatCents(uplineCents),
      enrollmentCode: bobCols.enrollmentCode ? emptyToNull(row[bobCols.enrollmentCode]) : null,
      minDate: parseDateOrNull(row.min_date, bobCell('min_date')),
      anchorDate: parseDateOrNull(row.anchor_date, bobCell('anchor_date')),
      agencyId: emptyToNull(row.agency_id),
      conflicts: emptyToNull(row.conflicts),
      spineSource: emptyToNull(row.spine_source),
      confidenceLevel: parseIntOrNull(row.confidence_level, bobCell('confidence_level')),
      coherentTrajectory: coherentTrajectoryMap[pidKey] ?? null,
    });
  }

  // 2. Parse Coherent Ledger and verify row-level split + one-hot revenue bucket invariants.
  const ledgerParsed = parseCsvObjects(coherentLedgerCsv, 'coherent_ledger.csv');
  const ledCols = resolveCsvColumnMap(ledgerParsed.header, columnMap);
  if (!ledCols.uplineAmount) {
    throw new AppError('coherent_ledger.csv is missing its upline amount split column.', 422, 'MISSING_UPLINE_COLUMN');
  }
  const ledgerRows = [];
  let ledgerGrossCents = 0n;
  let ledgerDownlineCents = 0n;
  let ledgerUplineCents = 0n;
  let policyLinkedDownlineCents = 0n;
  let policyLinkedUplineCents = 0n;

  for (const row of ledgerParsed.rows) {
    const ledCell = (column) => ({ table: 'coherent_ledger.csv', column, rowNo: row._rowNo });
    const txId = parseIntOrNull(row.tx_id, ledCell('tx_id'));
    if (txId == null) {
      throw new AppError(`MISSING_TX_ID: missing integer tx_id${formatCellRef(ledCell('tx_id'))}.`, 422, 'MISSING_TX_ID');
    }
    const recordId = emptyToNull(row.record_id);
    const entity = emptyToNull(row.entity);
    const srcType = emptyToNull(row.src_type);
    if (!recordId || !entity || !srcType) {
      throw new AppError(
        `MISSING_LEDGER_FIELDS: missing required record_id, entity, or src_type (table coherent_ledger.csv, row ${row._rowNo}).`,
        422,
        'MISSING_LEDGER_FIELDS',
      );
    }

    const grossCents = parseCents(row.gross_comm, ledCell('gross_comm'));
    const downlineCents = parseCents(row.downline_amount, ledCell('downline_amount'));
    const uplineCents = parseCents(row[ledCols.uplineAmount], ledCell(ledCols.uplineAmount));
    if (grossCents == null || downlineCents == null || uplineCents == null) {
      throw new AppError(
        `NULL_LEDGER_SPLIT: missing gross_comm, downline_amount, or upline split (table coherent_ledger.csv, row ${row._rowNo}).`,
        422,
        'NULL_LEDGER_SPLIT',
      );
    }
    if (downlineCents + uplineCents !== grossCents) {
      throw new AppError(
        `Ledger split mismatch on tx ${txId}: downline (${formatCents(downlineCents)}) + upline (${formatCents(uplineCents)}) != gross (${formatCents(grossCents)}).`,
        409,
        'CONSERVATION_MISMATCH',
      );
    }

    const buckets = {};
    let hotCount = 0;
    let hotVal = null;
    for (const col of BUCKET_COLS) {
      const c = parseCents(row[col], ledCell(col));
      buckets[col] = formatCents(c);
      if (c != null) {
        hotCount += 1;
        hotVal = c;
      }
    }
    if (hotCount !== 1 || hotVal !== grossCents) {
      throw new AppError(`Ledger row tx ${txId} must have exactly one revenue bucket equal to gross_comm.`, 409, 'INVALID_REVENUE_BUCKET');
    }

    const policyId = parseIntOrNull(row.policy_id, ledCell('policy_id'));
    ledgerGrossCents += grossCents;
    ledgerDownlineCents += downlineCents;
    ledgerUplineCents += uplineCents;
    if (policyId != null) {
      policyLinkedDownlineCents += downlineCents;
      policyLinkedUplineCents += uplineCents;
    }

    const txMeta = workingTxMap.get(txId);
    ledgerRows.push({
      attemptEventId,
      txId,
      runId,
      recordId,
      externalPolicyId: ledCols.externalPolicyId ? emptyToNull(row[ledCols.externalPolicyId]) : null,
      policyId,
      statementName: emptyToNull(row.statement_name),
      srcType,
      carrier: emptyToNull(row.carrier),
      mbi: emptyToNull(row.mbi),
      member: emptyToNull(row.member),
      state: emptyToNull(row.state),
      planType: emptyToNull(row.plan_type),
      simplePlanType: emptyToNull(row.simple_plan_type),
      submissionDate: parseDateOrNull(row.submission_date, ledCell('submission_date')),
      originEffective: parseDateOrNull(row.origin_effective, ledCell('origin_effective')),
      effectiveDate: parseDateOrNull(row.effective_date, ledCell('effective_date')),
      terminationDate: parseDateOrNull(row.termination_date, ledCell('termination_date')),
      earnedDate: parseDateOrNull(row.earned_date, ledCell('earned_date')),
      paymentDate: parseDateOrNull(row.payment_date, ledCell('payment_date')),
      statementDate: parseDateOrNull(row.statement_date, ledCell('statement_date')),
      minDate: parseDateOrNull(row.min_date, ledCell('min_date')),
      grossComm: formatCents(grossCents),
      revenueType: emptyToNull(row.revenue_type),
      overrideAmount: buckets.override_amount,
      commissionAmount: buckets.commission_amount,
      hraAmount: buckets.hra_amount,
      feeAmount: buckets.fee_amount,
      otherAmount: buckets.other_amount,
      downlineAmount: formatCents(downlineCents),
      uplineAmount: formatCents(uplineCents),
      writingNpn: emptyToNull(row.writing_npn),
      writingAgent: emptyToNull(row.writing_agent),
      entity,
      payeeNpn: emptyToNull(row.payee_npn),
      agencyId: emptyToNull(row.agency_id),
      status: emptyToNull(row.status),
      policyStatus: emptyToNull(row.policy_status),
      cbobC: parseBool(row.cbob_c, ledCell('cbob_c')),
      cbobS: parseBool(row.cbob_s, ledCell('cbob_s')),
      sf: parseBool(row.sf, ledCell('sf')),
      notes: emptyToNull(row.notes),
      coherentNotes: emptyToNull(row.coherent_notes),
      sheetName: txMeta?.sheetName ?? emptyToNull(row.sheet_name),
      sourceRowNo: txMeta?.sourceRowNo ?? parseIntOrNull(row.source_row_no, ledCell('source_row_no')),
    });
  }

  // BoB-to-Ledger rollup conservation check before write.
  if (bobDownlineCents !== policyLinkedDownlineCents || bobUplineCents !== policyLinkedUplineCents) {
    throw new AppError(
      `Conservation check failed: BoB totals (${formatCents(bobDownlineCents)} / ${formatCents(bobUplineCents)}) do not match policy-linked ledger splits (${formatCents(policyLinkedDownlineCents)} / ${formatCents(policyLinkedUplineCents)}).`,
      409,
      'CONSERVATION_MISMATCH',
    );
  }

  // 3. Parse statements_YYYYMMDD.csv into physically separate agency and upline statement lines.
  const stmtParsed = parseCsvObjects(statementsCsv, resolvedFileName);
  const stmtCols = resolveCsvColumnMap(stmtParsed.header, columnMap);
  const agencyLines = [];
  const uplineLines = [];
  let agencyLineNo = 0;
  let uplineLineNo = 0;
  let agencyNetCents = 0n;
  let uplineNetCents = 0n;
  let statementsGrossCents = 0n;

  // Standing balances cache for NULL-split pre-Coherence reversals/cancels.
  const priorBalanceCache = new Map();
  async function loadStandingBalance(targetRecordId, entity) {
    const key = `${targetRecordId}\u0000${entity}`;
    if (priorBalanceCache.has(key)) return priorBalanceCache.get(key);
    const [agRes, upRes] = await Promise.all([
      db.query(
        `SELECT COALESCE(pg_catalog.sum(sal.amount), 0.00)::text AS total
         FROM coherence.statement_agency_lines sal
         JOIN coherence.run_effective_statement_batches($1::uuid) eff ON eff.batch_id = sal.batch_id
         WHERE sal.record_id = $2 AND sal.entity = $3 AND sal.statement_date < $4::date`,
        [runId, targetRecordId, entity, statementDate],
      ),
      db.query(
        `SELECT COALESCE(pg_catalog.sum(sul.amount), 0.00)::text AS total
         FROM coherence.statement_upline_lines sul
         JOIN coherence.run_effective_statement_batches($1::uuid) eff ON eff.batch_id = sul.batch_id
         WHERE sul.record_id = $2 AND sul.statement_date < $3::date`,
        [runId, targetRecordId, statementDate],
      ),
    ]);
    const bal = {
      agencyCents: parseCents(agRes.rows[0]?.total ?? '0.00'),
      uplineCents: parseCents(upRes.rows[0]?.total ?? '0.00'),
    };
    priorBalanceCache.set(key, bal);
    return bal;
  }

  for (const row of stmtParsed.rows) {
    const stmtCell = (column) => ({ table: resolvedFileName, column, rowNo: row._rowNo });
    const runAction = emptyToNull(row.run_action);
    if (!['NEW', 'RESTATED', 'REVERSAL', 'CANCEL'].includes(runAction)) {
      throw new AppError(
        `INVALID_RUN_ACTION: invalid statement run_action${formatCellRef(stmtCell('run_action'))}.`,
        422,
        'INVALID_RUN_ACTION',
      );
    }
    const recordId = emptyToNull(row.record_id);
    const entity = emptyToNull(row.entity);
    if (!recordId || !entity) {
      throw new AppError(
        `MISSING_STATEMENT_FIELDS: missing required record_id or entity (table ${resolvedFileName}, row ${row._rowNo}).`,
        422,
        'MISSING_STATEMENT_FIELDS',
      );
    }
    const grossCents = parseCents(row.gross_comm, stmtCell('gross_comm'));
    if (grossCents == null) {
      throw new AppError(
        `MISSING_GROSS_COMM: missing gross_comm${formatCellRef(stmtCell('gross_comm'))}.`,
        422,
        'MISSING_GROSS_COMM',
      );
    }
    statementsGrossCents += grossCents;

    let downlineCents = parseCents(row.downline_amount, stmtCell('downline_amount'));
    let uplineCents = stmtCols.uplineAmount ? parseCents(row[stmtCols.uplineAmount], stmtCell(stmtCols.uplineAmount)) : null;

    if (downlineCents != null && uplineCents != null) {
      if (downlineCents + uplineCents !== grossCents) {
        throw new AppError(
          `Statement split mismatch at row ${row._rowNo}: downline + upline != gross_comm.`,
          409,
          'CONSERVATION_MISMATCH',
        );
      }
    } else if (downlineCents == null && uplineCents == null && (runAction === 'REVERSAL' || runAction === 'CANCEL')) {
      const targetKey = emptyToNull(row.reversal_of) || recordId;
      const standing = await loadStandingBalance(targetKey, entity);
      if (-(standing.agencyCents + standing.uplineCents) === grossCents) {
        downlineCents = -standing.agencyCents;
        uplineCents = -standing.uplineCents;
      } else if (standing.uplineCents === 0n) {
        downlineCents = grossCents;
        uplineCents = 0n;
      } else {
        throw new AppError(
          `Cannot unwind NULL-split ${runAction} at row ${row._rowNo}: prior standing balance does not match negated gross.`,
          409,
          'UNRESOLVABLE_NULL_SPLIT',
        );
      }
    } else {
      throw new AppError(
        `Statement row ${row._rowNo} (${runAction}) must provide both downline_amount and upline split.`,
        422,
        'MISSING_SPLITS',
      );
    }

    const txId = parseIntOrNull(row.tx_id, stmtCell('tx_id'));
    const txMeta = txId != null ? workingTxMap.get(txId) : null;
    const baseLine = {
      batchId: statementBatchId,
      statementDate,
      entryKind: 'run_emission',
      runAction,
      writingNpn: emptyToNull(row.writing_npn),
      writingAgent: emptyToNull(row.writing_agent),
      recordId,
      reversalOf: emptyToNull(row.reversal_of),
      correctsRecordId: null,
      sourceFile: txMeta?.filename ?? emptyToNull(row.statement_name) ?? resolvedFileName,
      sheetName: txMeta?.sheetName ?? emptyToNull(row.sheet_name),
      sourceRowNo: txMeta?.sourceRowNo ?? row._rowNo,
      srcType: emptyToNull(row.src_type),
      carrier: emptyToNull(row.carrier),
      mbi: emptyToNull(row.mbi),
      member: emptyToNull(row.member),
      externalPolicyId: stmtCols.externalPolicyId ? emptyToNull(row[stmtCols.externalPolicyId]) : null,
      policyId: parseIntOrNull(row.policy_id, stmtCell('policy_id')),
      txId,
      planType: emptyToNull(row.plan_type),
      simplePlanType: emptyToNull(row.simple_plan_type),
      state: emptyToNull(row.state),
      submissionDate: parseDateOrNull(row.submission_date, stmtCell('submission_date')),
      originEffective: parseDateOrNull(row.origin_effective, stmtCell('origin_effective')),
      effectiveDate: parseDateOrNull(row.effective_date, stmtCell('effective_date')),
      terminationDate: parseDateOrNull(row.termination_date, stmtCell('termination_date')),
      earnedDate: parseDateOrNull(row.earned_date, stmtCell('earned_date')),
      paymentDate: parseDateOrNull(row.payment_date, stmtCell('payment_date')),
      postedStatementDate: parseDateOrNull(row.statement_date, stmtCell('statement_date')),
      revenueType: emptyToNull(row.revenue_type),
      grossComm: formatCents(grossCents),
      reason: emptyToNull(row.reason),
      notes: emptyToNull(row.notes),
    };

    if (downlineCents !== 0n || (downlineCents === 0n && uplineCents === 0n)) {
      agencyLineNo += 1;
      agencyNetCents += downlineCents;
      agencyLines.push({
        ...baseLine,
        lineNo: agencyLineNo,
        entity,
        amount: formatCents(downlineCents),
      });
    }

    if (uplineCents !== 0n) {
      uplineLineNo += 1;
      uplineNetCents += uplineCents;
      uplineLines.push({
        ...baseLine,
        lineNo: uplineLineNo,
        sourceEntity: entity,
        markedSent: true,
        amount: formatCents(uplineCents),
      });
    }
  }

  if (agencyNetCents + uplineNetCents !== statementsGrossCents) {
    throw new AppError(
      'Conservation check failed: agency + upline statement lines do not sum to statements CSV net.',
      409,
      'CONSERVATION_MISMATCH',
    );
  }

  const agencyLinesSha256 = hashStatementAgencyLines(agencyLines);
  const uplineLinesSha256 = hashStatementUplineLines(uplineLines);
  const bobRowsSha256 = hashBobRows(bobPolicies, bobFinancials);
  const ledgerRowsSha256 = hashLedgerRows(ledgerRows);

  const statementBatch = {
    id: statementBatchId,
    batchKind: 'run_emission',
    statementDate,
    runId,
    attemptEventId,
    sourceFileName: resolvedFileName,
    sourceStoreKind: statementsFileSha256 ? 'company_data' : null,
    sourceFileSha256: statementsFileSha256 ?? null,
    reason: `Emit statements for ${statementDate}`,
    agencyLineCount: agencyLines.length,
    agencyLinesSha256,
    agencyNetTotal: formatCents(agencyNetCents),
    uplineLineCount: uplineLines.length,
    uplineLinesSha256,
    uplineNetTotal: formatCents(uplineNetCents),
  };

  const runMaterialization = {
    attemptEventId,
    runId,
    statementDate,
    reconciliationMode,
    bobRowCount: bobPolicies.length,
    bobRowsSha256,
    bobDownlineTotal: formatCents(bobDownlineCents),
    bobUplineTotal: formatCents(bobUplineCents),
    ledgerRowCount: ledgerRows.length,
    ledgerRowsSha256,
    ledgerGrossTotal: formatCents(ledgerGrossCents),
    ledgerDownlineTotal: formatCents(ledgerDownlineCents),
    ledgerUplineTotal: formatCents(ledgerUplineCents),
    statementBatchId,
    corpusTail,
    agencyStart,
  };

  return {
    statementBatch,
    agencyLines,
    uplineLines,
    runMaterialization,
    bobPolicies,
    bobFinancials,
    ledgerRows,
  };
}
