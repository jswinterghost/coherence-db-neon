// Pure parameter validators, SQL filter/sort builders, CSV encoders, and row mappers
// for read-only Coherence screen view handlers (zero database I/O, zero authorization logic).
import { gzipSync } from 'node:zlib';
import { formatTimestampUtcUs } from '../util/crypto.mjs';
import { isValidIsoDate, toCsv } from '../util/csv.mjs';
import { AppError } from '../util/redact.mjs';

export const DEFAULT_LIMIT = 200;
export const MAX_JSON_LIMIT = 5000;
export const MAX_CSV_LIMIT = 50000;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MONTH_RE = /^\d{4}-(0[1-9]|1[0-2])$/;

export const trimOpt = (v) => (v == null || String(v).trim() === '' ? null : String(v).trim());
export const escapeLike = (v) => String(v).replace(/[\\%_]/g, '\\$&');
export const numOrNull = (v) => (v == null ? null : Number(v));

export const BOB_SORT_COLS = new Map([
  ['policyId', 'f.policy_id'], ['externalPolicyId', 'f.external_policy_id'], ['entity', 'f.entity'],
  ['carrier', 'f.carrier'], ['planType', 'f.plan_type'], ['simplePlanType', 'f.simple_plan_type'],
  ['planName', 'f.plan_name'], ['state', 'f.state'], ['status', 'f.status'],
  ['coherentStatus', 'f.coherent_status'], ['effectiveDate', 'f.effective_date'],
  ['originEffective', 'f.origin_effective'], ['submissionDate', 'f.submission_date'],
  ['terminationDate', 'f.termination_date'], ['writingAgent', 'f.writing_agent'],
  ['writingNpn', 'f.writing_npn'], ['amount', 'f.amount'], ['uplineAmount', 'f.upline_amount'],
  ['member', 'f.member'],
]);

export const LEDGER_SORT_COLS = new Map([
  ['txId', 'f.tx_id'], ['policyId', 'f.policy_id'], ['entity', 'f.entity'], ['carrier', 'f.carrier'],
  ['srcType', 'f.src_type'], ['revenueType', 'f.revenue_type'], ['statementDate', 'f.statement_date'],
  ['paymentDate', 'f.payment_date'], ['earnedDate', 'f.earned_date'], ['effectiveDate', 'f.effective_date'],
  ['grossComm', 'f.gross_comm'], ['downlineAmount', 'f.downline_amount'],
  ['uplineAmount', 'f.upline_amount'], ['writingAgent', 'f.writing_agent'], ['writingNpn', 'f.writing_npn'],
  ['status', 'f.status'], ['sheetName', 'f.sheet_name'], ['sourceRowNo', 'f.source_row_no'],
  ['member', 'f.member'],
]);

export const STATEMENT_LINE_SORT_COLS = new Map([
  ['statementDate', 'l.statement_date'], ['lineNo', 'l.line_no'],
  ['statementEntity', 'l.statement_entity'], ['sourceEntity', 'l.source_entity'],
  ['accountKind', 'l.account_kind'], ['runAction', 'l.run_action'], ['srcType', 'l.src_type'],
  ['carrier', 'l.carrier'], ['paymentDate', 'l.payment_date'], ['earnedDate', 'l.earned_date'],
  ['effectiveDate', 'l.effective_date'], ['amount', 'l.amount'], ['grossComm', 'l.gross_comm'],
  ['writingAgent', 'l.writing_agent'], ['writingNpn', 'l.writing_npn'], ['policyId', 'l.policy_id'],
  ['txId', 'l.tx_id'], ['sourceFile', 'l.source_file'], ['sheetName', 'l.sheet_name'],
  ['sourceRowNo', 'l.source_row_no'], ['member', 'l.member'],
]);

const toCamel = (snake) => snake.replace(/_([a-z])/g, (_, ch) => ch.toUpperCase());
const specFromCols = (cols) => Object.freeze(cols.map((c) => Object.freeze([c, toCamel(c)])));

export const BOB_CSV_SPEC = specFromCols([
  'policy_id', 'external_policy_id', 'carrier_policy_number', 'crm_policy_number',
  'enrollment_code', 'entity', 'carrier', 'status', 'coherent_status', 'plan_type',
  'simple_plan_type', 'plan_name', 'mbi', 'member', 'dob', 'phone', 'email', 'address',
  'county', 'state', 'submission_date', 'origin_effective', 'effective_date',
  'termination_date', 'min_date', 'anchor_date', 'writing_npn', 'writing_agent',
  'agency_id', 'amount', 'upline_amount', 'conflicts', 'spine_source',
  'confidence_level', 'coherent_trajectory',
]);

export const LEDGER_CSV_SPEC = specFromCols([
  'tx_id', 'policy_id', 'external_policy_id', 'record_id', 'statement_name', 'src_type',
  'carrier', 'mbi', 'member', 'state', 'plan_type', 'simple_plan_type', 'submission_date',
  'origin_effective', 'effective_date', 'termination_date', 'earned_date', 'payment_date',
  'statement_date', 'min_date', 'gross_comm', 'revenue_type', 'override_amount',
  'commission_amount', 'hra_amount', 'fee_amount', 'other_amount', 'downline_amount',
  'upline_amount', 'writing_npn', 'writing_agent', 'entity', 'payee_npn', 'agency_id',
  'status', 'policy_status', 'cbob_c', 'cbob_s', 'sf', 'notes', 'coherent_notes',
  'sheet_name', 'source_row_no',
]);

export const STATEMENT_LINE_CSV_SPEC = specFromCols([
  'batch_id', 'batch_kind', 'is_sent', 'line_no', 'statement_date', 'entry_kind',
  'run_action', 'statement_entity', 'account_kind', 'source_entity', 'marked_sent',
  'writing_npn', 'writing_agent', 'record_id', 'reversal_of', 'corrects_record_id',
  'source_file', 'sheet_name', 'source_row_no', 'src_type', 'carrier', 'mbi', 'member',
  'external_policy_id', 'policy_id', 'tx_id', 'plan_type', 'simple_plan_type', 'state',
  'submission_date', 'origin_effective', 'effective_date', 'termination_date',
  'earned_date', 'payment_date', 'posted_statement_date', 'revenue_type', 'gross_comm',
  'amount', 'reason', 'notes',
]);

export function parseUuid(value, name) {
  const s = trimOpt(value);
  if (!s) return null;
  if (!UUID_RE.test(s)) throw new AppError(`${name} must be a valid UUID.`, 400, 'INVALID_UUID');
  return s;
}

export function parseDate(value, name) {
  const s = trimOpt(value);
  if (!s) return null;
  if (!isValidIsoDate(s)) throw new AppError(`${name} must be a valid YYYY-MM-DD date.`, 400, 'INVALID_DATE');
  return s;
}

export function parseMonth(value, name) {
  const s = trimOpt(value);
  if (!s) return null;
  if (!MONTH_RE.test(s)) throw new AppError(`${name} must be a valid YYYY-MM month.`, 400, 'INVALID_MONTH');
  return s;
}

export function parseIntParam(value, name, { min = -2147483648, max = 2147483647, defaultValue = null, required = false } = {}) {
  const s = trimOpt(value);
  if (!s) {
    if (required) throw new AppError(`${name} must be an integer.`, 400, 'INVALID_PARAM');
    return defaultValue;
  }
  if (!/^-?\d+$/.test(s)) throw new AppError(`${name} must be an integer.`, 400, 'INVALID_PARAM');
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n < min || n > max) {
    throw new AppError(`${name} must be an integer between ${min} and ${max}.`, 400, 'INVALID_PARAM');
  }
  return n;
}

export function parseBoolParam(value, name, defaultValue = null) {
  if (value === true || value === false) return value;
  const s = trimOpt(value);
  if (!s) return defaultValue;
  const low = s.toLowerCase();
  if (low === 'true' || low === '1') return true;
  if (low === 'false' || low === '0') return false;
  throw new AppError(`${name} must be true or false.`, 400, 'INVALID_PARAM');
}

export function parseEnum(value, name, allowed, defaultValue = null) {
  const s = trimOpt(value);
  if (!s) return defaultValue;
  if (!allowed.includes(s)) throw new AppError(`${name} must be one of: ${allowed.join(', ')}.`, 400, 'INVALID_PARAM');
  return s;
}

export function parseSort(sort, dir, colMap, defaultKey, defaultDir = 'asc') {
  const key = trimOpt(sort) || defaultKey;
  const sqlCol = colMap.get(key);
  if (!sqlCol) throw new AppError(`Unsupported sort column: ${key}.`, 400, 'INVALID_SORT');
  const rawDir = (trimOpt(dir) || defaultDir).toLowerCase();
  if (rawDir !== 'asc' && rawDir !== 'desc') throw new AppError('dir must be asc or desc.', 400, 'INVALID_SORT');
  return { sqlCol, sqlDir: rawDir.toUpperCase() };
}

export function parseFormat(value) {
  const s = (trimOpt(value) || 'json').toLowerCase();
  if (s !== 'json' && s !== 'csv') throw new AppError('format must be json or csv.', 400, 'INVALID_FORMAT');
  return s;
}

export function assertCsvRowLimit(totalCount, maxRows = MAX_CSV_LIMIT) {
  if (totalCount > maxRows) {
    throw new AppError(
      `CSV export has ${totalCount} rows, exceeding the maximum of ${maxRows} rows. Narrow your filters and retry.`,
      413,
      'EXPORT_TOO_LARGE',
    );
  }
}

export function parsePageOptions(opts, colMap, defaultKey, defaultDir = 'asc', maxCsvRows = MAX_CSV_LIMIT) {
  const format = parseFormat(opts.format);
  const { sqlCol, sqlDir } = parseSort(opts.sort, opts.dir, colMap, defaultKey, defaultDir);
  const limit = format === 'csv'
    ? maxCsvRows
    : parseIntParam(opts.limit, 'limit', { min: 1, max: MAX_JSON_LIMIT, defaultValue: DEFAULT_LIMIT });
  const offset = format === 'csv'
    ? 0
    : parseIntParam(opts.offset, 'offset', { min: 0, max: 10000000, defaultValue: 0 });
  return { format, sqlCol, sqlDir, limit, offset, acceptsGzip: Boolean(opts.acceptsGzip) };
}

export function appendSearchFilter(conds, params, search, exprs) {
  if (!search) return;
  params.push(`%${escapeLike(search)}%`);
  const p = `$${params.length}`;
  conds.push(`(${exprs.map((e) => `COALESCE(${e}, '') ILIKE ${p} ESCAPE '\\'`).join(' OR ')})`);
}

export function csvCell(val) {
  if (val == null) return '';
  return typeof val === 'object' ? JSON.stringify(val) : String(val);
}

export function buildCsvFile(name, headers, rowArrays, acceptsGzip = false) {
  const buf = Buffer.from(toCsv([headers, ...rowArrays]), 'utf8');
  return {
    format: 'csv',
    file: { name, body: acceptsGzip ? gzipSync(buf) : buf, gzip: Boolean(acceptsGzip) },
  };
}

export function buildSpecCsvFile(name, spec, objects, acceptsGzip = false) {
  const headers = spec.map(([col]) => col);
  const rows = objects.map((obj) => spec.map(([, prop]) => csvCell(obj[prop])));
  return buildCsvFile(name, headers, rows, acceptsGzip);
}

export function mapPublishedRun(r, extra = {}) {
  return {
    id: r.id,
    statementDate: r.statement_date,
    stamp: r.stamp,
    folderNumber: Number(r.folder_number),
    origin: r.origin,
    sent: Boolean(r.sent),
    emitAttemptEventId: r.emit_attempt_event_id,
    emitMode: r.emit_mode,
    emitDisplay: r.emit_display,
    emitJournalSeq: Number(r.emit_journal_seq),
    journalSeq: Number(r.journal_seq),
    ...extra,
  };
}

export function mapBobRow(r) {
  return {
    attemptEventId: r.attempt_event_id, runId: r.run_id, organizationId: r.organization_id,
    writingPersonId: r.writing_person_id, policyId: Number(r.policy_id),
    externalPolicyId: r.external_policy_id, carrierPolicyNumber: r.carrier_policy_number,
    crmPolicyNumber: r.crm_policy_number, enrollmentCode: r.enrollment_code,
    carrier: r.carrier, planType: r.plan_type, planName: r.plan_name,
    simplePlanType: r.simple_plan_type, mbi: r.mbi, member: r.member, dob: r.dob,
    phone: r.phone, email: r.email, address: r.address, county: r.county, state: r.state,
    submissionDate: r.submission_date, originEffective: r.origin_effective,
    effectiveDate: r.effective_date, terminationDate: r.termination_date,
    minDate: r.min_date, anchorDate: r.anchor_date, amount: r.amount,
    uplineAmount: r.upline_amount, writingNpn: r.writing_npn, writingAgent: r.writing_agent,
    entity: r.entity, agencyId: r.agency_id, status: r.status,
    coherentStatus: r.coherent_status, conflicts: r.conflicts, spineSource: r.spine_source,
    confidenceLevel: numOrNull(r.confidence_level), coherentTrajectory: r.coherent_trajectory,
    journalSeq: Number(r.journal_seq),
  };
}

export function mapLedgerRow(r) {
  return {
    attemptEventId: r.attempt_event_id, txId: Number(r.tx_id), runId: r.run_id,
    organizationId: r.organization_id, writingPersonId: r.writing_person_id,
    recordId: r.record_id, externalPolicyId: r.external_policy_id,
    policyId: numOrNull(r.policy_id), statementName: r.statement_name, srcType: r.src_type,
    carrier: r.carrier, mbi: r.mbi, member: r.member, state: r.state, planType: r.plan_type,
    simplePlanType: r.simple_plan_type, submissionDate: r.submission_date,
    originEffective: r.origin_effective, effectiveDate: r.effective_date,
    terminationDate: r.termination_date, earnedDate: r.earned_date,
    paymentDate: r.payment_date, statementDate: r.statement_date, minDate: r.min_date,
    grossComm: r.gross_comm, revenueType: r.revenue_type, overrideAmount: r.override_amount,
    commissionAmount: r.commission_amount, hraAmount: r.hra_amount, feeAmount: r.fee_amount,
    otherAmount: r.other_amount, downlineAmount: r.downline_amount, uplineAmount: r.upline_amount,
    writingNpn: r.writing_npn, writingAgent: r.writing_agent, entity: r.entity,
    payeeNpn: r.payee_npn, agencyId: r.agency_id, status: r.status,
    policyStatus: r.policy_status, cbobC: Boolean(r.cbob_c), cbobS: Boolean(r.cbob_s),
    sf: Boolean(r.sf), notes: r.notes, coherentNotes: r.coherent_notes,
    sheetName: r.sheet_name, sourceRowNo: numOrNull(r.source_row_no),
    journalSeq: Number(r.journal_seq),
  };
}

export function mapStatementBatch(r, entities = []) {
  return {
    id: r.id, batchKind: r.batch_kind, statementDate: r.statement_date, runId: r.run_id,
    attemptEventId: r.attempt_event_id, sourceFileName: r.source_file_name, reason: r.reason,
    isSent: Boolean(r.is_sent), agencyLineCount: numOrNull(r.agency_line_count),
    agencyLinesSha256: r.agency_lines_sha256, agencyNetTotal: r.agency_net_total,
    uplineLineCount: numOrNull(r.upline_line_count), uplineLinesSha256: r.upline_lines_sha256,
    uplineNetTotal: r.upline_net_total, journalSeq: Number(r.journal_seq), entities,
  };
}

export function mapStatementLine(r) {
  return {
    batchId: r.batch_id, batchKind: r.batch_kind, isSent: Boolean(r.is_sent),
    lineNo: Number(r.line_no), statementDate: r.statement_date, entryKind: r.entry_kind,
    runAction: r.run_action, organizationId: r.organization_id,
    sourceOrganizationId: r.source_organization_id, writingPersonId: r.writing_person_id,
    statementEntity: r.statement_entity, accountKind: r.account_kind,
    sourceEntity: r.source_entity, markedSent: Boolean(r.marked_sent),
    writingNpn: r.writing_npn, writingAgent: r.writing_agent, recordId: r.record_id,
    reversalOf: r.reversal_of, correctsRecordId: r.corrects_record_id,
    sourceFile: r.source_file, sheetName: r.sheet_name, sourceRowNo: Number(r.source_row_no),
    srcType: r.src_type, carrier: r.carrier, mbi: r.mbi, member: r.member,
    externalPolicyId: r.external_policy_id, policyId: numOrNull(r.policy_id),
    txId: numOrNull(r.tx_id), planType: r.plan_type, simplePlanType: r.simple_plan_type,
    state: r.state, submissionDate: r.submission_date, originEffective: r.origin_effective,
    effectiveDate: r.effective_date, terminationDate: r.termination_date,
    earnedDate: r.earned_date, paymentDate: r.payment_date,
    postedStatementDate: r.posted_statement_date, revenueType: r.revenue_type,
    grossComm: r.gross_comm, amount: r.amount, reason: r.reason, notes: r.notes,
    journalSeq: Number(r.journal_seq),
  };
}

export function mapStatementAppearance(r) {
  return {
    policyId: numOrNull(r.policy_id), txId: numOrNull(r.tx_id), recordId: r.record_id,
    statementDate: r.statement_date, organizationId: r.organization_id,
    statementEntity: r.statement_entity, accountKind: r.account_kind,
    runAction: r.run_action, appearances: Number(r.appearances), netAmount: r.net_amount,
  };
}

export function mapDecisionRow(r) {
  return {
    id: r.id, decisionCommitId: r.decision_commit_id, rowOrder: Number(r.row_order),
    runId: r.run_id, reviewSaveId: r.review_save_id, surface: r.surface,
    recordId: r.record_id, replacesDecisionId: r.replaces_decision_id,
    disposition: r.disposition, agent: r.agent, agency: r.agency, policy: r.policy,
    book: r.book, month: r.month, status: r.status, note: r.note,
    approvedAmount: r.approved_amount, approvedAgency: r.approved_agency,
    approvedAgent: r.approved_agent, approvedAgencyFrom: r.approved_agency_from,
    approvedAgentFrom: r.approved_agent_from, decidedBy: r.decided_by,
    decidedByDisplay: r.decided_by_display, actingFor: r.acting_for ?? null,
    decidedAt: formatTimestampUtcUs(r.decided_at),
    committedAt: r.committed_at_raw ?? formatTimestampUtcUs(r.decided_at),
    imported: Boolean(r.imported), journalSeq: Number(r.journal_seq),
  };
}
