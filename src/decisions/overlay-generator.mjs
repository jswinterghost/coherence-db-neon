// Deterministic overlay.csv generator from immutable PostgreSQL decision records.
// Produces exact v1 (10-column) or v2 (15-column) RFC 4180 CSV with LF line endings
// matching coherence/overlay.py's ADJUSTMENT_COLUMNS_V1 and ADJUSTMENT_COLUMNS contracts.
import { fingerprintBytes, formatTimestampUtcUs } from '../util/crypto.mjs';
import { toCsv } from '../util/csv.mjs';
import { AppError } from '../util/redact.mjs';

export const OVERLAY_V1_COLUMNS = Object.freeze([
  'record_id',
  'disposition',
  'agent',
  'agency',
  'policy',
  'book',
  'month',
  'status',
  'note',
  'committed_at',
]);

export const OVERLAY_FACT_COLUMNS = Object.freeze([
  'approved_amount',
  'approved_agency',
  'approved_agent',
  'approved_agency_from',
  'approved_agent_from',
]);

export const OVERLAY_V2_COLUMNS = Object.freeze([
  ...OVERLAY_V1_COLUMNS,
  ...OVERLAY_FACT_COLUMNS,
]);

export const POLICY_STATUSES = Object.freeze([
  'ACTIVE_PAYING',
  'ACTIVE_IMPLIED',
  'INACTIVE_IMPLIED',
  'ACTIVE_RECON',
  'CLAWBACK',
  'TERMINATED',
  'NEVER_IN_FORCE',
  'PENDING',
  'REVERSED',
  'INACTIVE',
  'UNKNOWN',
  'ACTIVE_INTERIM',
]);

export const LIVE_DISPOSITIONS = Object.freeze(['CONFIRM', 'CORRECT']);

function toOverlayRecord(row) {
  const isImported = Boolean(row.imported);
  const explicitCommittedAt = row.committed_at_raw
    ?? row.committedAtRaw
    ?? row.committed_at
    ?? row.committedAt
    ?? null;
  const committedAt = explicitCommittedAt !== null
    ? explicitCommittedAt
    : (isImported
      ? null
      : ((row.decided_at ?? row.decidedAt) ? formatTimestampUtcUs(row.decided_at ?? row.decidedAt) : null));
  return {
    record_id: row.record_id ?? row.recordId ?? null,
    disposition: row.disposition ?? null,
    agent: row.agent ?? null,
    agency: row.agency ?? null,
    policy: row.policy ?? null,
    book: row.book ?? null,
    month: row.month ?? null,
    status: row.status ?? null,
    note: row.note ?? null,
    committed_at: committedAt,
    approved_amount: row.approved_amount ?? row.approvedAmount ?? null,
    approved_agency: row.approved_agency ?? row.approvedAgency ?? null,
    approved_agent: row.approved_agent ?? row.approvedAgent ?? null,
    approved_agency_from: row.approved_agency_from ?? row.approvedAgencyFrom ?? null,
    approved_agent_from: row.approved_agent_from ?? row.approvedAgentFrom ?? null,
  };
}

/**
 * Pure deterministic serializer producing RFC 4180 CSV with LF endings matching Polars write_csv
 * and coherence/overlay.py's _read() contract.
 */
export function formatOverlayCsvFromRows(rows = [], { headerContract = 'v2' } = {}) {
  if (headerContract !== 'v1' && headerContract !== 'v2') {
    throw new AppError(`Unsupported overlay headerContract: ${headerContract}`, 400, 'INVALID_HEADER_CONTRACT');
  }
  const cols = headerContract === 'v1' ? OVERLAY_V1_COLUMNS : OVERLAY_V2_COLUMNS;
  const normalized = rows.map(toOverlayRecord);
  const matrix = [
    [...cols],
    ...normalized.map((rec) => cols.map((col) => (rec[col] == null ? '' : String(rec[col])))),
  ];
  const csv = toCsv(matrix);
  const bytes = Buffer.from(csv, 'utf8');
  return {
    headerContract,
    rowCount: normalized.length,
    rows: normalized,
    csv,
    bytes,
    fingerprint: fingerprintBytes(bytes),
  };
}

/**
 * Resolves the effective decision_commit_id as of a given journal position (asOfSeq),
 * optionally scoped to a specific decisionCommitId or runId (+ surface).
 */
export async function resolveDecisionCommitAsOf(
  db,
  { decisionCommitId = null, runId = null, surface = null, asOfSeq = null } = {},
) {
  const limitSeq = asOfSeq != null ? String(asOfSeq) : '9223372036854775807';
  let resolvedId = decisionCommitId;

  if (!resolvedId && runId) {
    const saveParams = surface ? [runId, limitSeq, surface] : [runId, limitSeq];
    const saveSql = surface
      ? `SELECT decision_commit_id
         FROM coherence.review_saves
         WHERE run_id = $1::uuid AND journal_seq <= $2::bigint AND surface = $3
           AND decision_commit_id IS NOT NULL
         ORDER BY journal_seq DESC LIMIT 1`
      : `SELECT decision_commit_id
         FROM coherence.review_saves
         WHERE run_id = $1::uuid AND journal_seq <= $2::bigint
           AND decision_commit_id IS NOT NULL
         ORDER BY journal_seq DESC LIMIT 1`;
    const saveRes = await db.query(saveSql, saveParams);
    if (saveRes.rows.length > 0) {
      resolvedId = saveRes.rows[0].decision_commit_id;
    } else {
      const runRes = await db.query(
        'SELECT prior_decision_commit_id FROM coherence.runs WHERE id = $1::uuid AND journal_seq <= $2::bigint',
        [runId, limitSeq],
      );
      if (runRes.rows.length === 0) {
        throw new AppError('Run not found at the requested journal position.', 404, 'RUN_NOT_FOUND');
      }
      resolvedId = runRes.rows[0].prior_decision_commit_id ?? null;
    }
  } else if (!resolvedId) {
    const headRes = await db.query(
      'SELECT coherence.standing_decision_head_as_of($1::bigint) AS id',
      [asOfSeq != null ? String(asOfSeq) : null],
    );
    resolvedId = headRes.rows[0]?.id ?? null;
  }

  if (!resolvedId) {
    return { decisionCommitId: null, headerContract: 'v2', cumulativeDecisionCount: 0, journalSeq: null };
  }

  const commitRes = await db.query(
    `SELECT id, header_contract, cumulative_decision_count, journal_seq
     FROM coherence.decision_commits
     WHERE id = $1::uuid AND journal_seq <= $2::bigint`,
    [resolvedId, limitSeq],
  );
  if (commitRes.rows.length === 0) {
    throw new AppError('Decision commit not found at the requested journal position.', 404, 'DECISION_COMMIT_NOT_FOUND');
  }
  const c = commitRes.rows[0];
  return {
    decisionCommitId: c.id,
    headerContract: c.header_contract,
    cumulativeDecisionCount: Number(c.cumulative_decision_count),
    journalSeq: Number(c.journal_seq),
  };
}

/**
 * Generates an overlay.csv deterministically from immutable PostgreSQL decision records
 * as of any journal position, commit id, or run review state.
 */
export async function generateOverlayCsv(
  db,
  { decisionCommitId = null, runId = null, surface = null, asOfSeq = null, headerContract = null } = {},
) {
  const resolved = await resolveDecisionCommitAsOf(db, { decisionCommitId, runId, surface, asOfSeq });
  const effectiveHeader = headerContract || resolved.headerContract || 'v2';

  if (!resolved.decisionCommitId) {
    const formatted = formatOverlayCsvFromRows([], { headerContract: effectiveHeader });
    return {
      decisionCommitId: null,
      asOfSeq: asOfSeq != null ? Number(asOfSeq) : null,
      commitJournalSeq: null,
      ...formatted,
    };
  }

  const rowsRes = await db.query(
    `SELECT seq_order, record_id, disposition, agent, agency, policy, book, month, status, note,
            coherence.format_utc_us(decided_at) AS decided_at, committed_at_raw, imported,
            approved_amount, approved_agency, approved_agent, approved_agency_from, approved_agent_from
     FROM coherence.decisions_in_commit($1::uuid)
     ORDER BY seq_order ASC`,
    [resolved.decisionCommitId],
  );

  const formatted = formatOverlayCsvFromRows(rowsRes.rows, { headerContract: effectiveHeader });
  return {
    decisionCommitId: resolved.decisionCommitId,
    asOfSeq: asOfSeq != null ? Number(asOfSeq) : null,
    commitJournalSeq: resolved.journalSeq,
    ...formatted,
  };
}
