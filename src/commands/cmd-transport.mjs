// Command transport and payload normalizers: runs every Coherence write inside withRequestTx
// using one PostgreSQL error mapping (mapPgError from src/db/pg-client.mjs).
import { mapPgError, withRequestTx } from '../db/pg-client.mjs';
import { canonicalJson, formatTimestampUtcUs, sha256Hex } from '../util/crypto.mjs';
import { AppError } from '../util/redact.mjs';

export function hashCommandPayload(commandKind, payload) {
  return sha256Hex(canonicalJson({ commandKind, payload }));
}

function normOpt(v) {
  return v == null || v === '' ? null : String(v);
}

export function safeTimestampIso(raw, fallbackIso = null) {
  for (const val of [raw, fallbackIso]) {
    if (!val) continue;
    try {
      return formatTimestampUtcUs(val);
    } catch {}
  }
  return formatTimestampUtcUs(new Date());
}

export function toSeqOrNull(expectedJournalSeq) {
  if (expectedJournalSeq === null || expectedJournalSeq === undefined || expectedJournalSeq === '') return null;
  const n = Number(expectedJournalSeq);
  if (!Number.isInteger(n) || n < 0) {
    throw new AppError('expectedJournalSeq must be a non-negative integer.', 400, 'INVALID_JOURNAL_SEQ');
  }
  return String(n);
}

export function normalizeStoredFile(f) {
  if (!f || typeof f !== 'object') return null;
  const sha256 = f.sha256;
  return {
    store_kind: f.store_kind ?? f.storeKind,
    sha256,
    byte_size: Number(f.byte_size ?? f.byteSize),
    md5_b64: f.md5_b64 ?? f.md5B64,
    crc32c_b64: f.crc32c_b64 ?? f.crc32cB64,
    object_name: f.object_name ?? f.objectName ?? `objects/${sha256}`,
  };
}

export function normalizeApprovalRow(r, defaultRowNo = null) {
  return {
    row_no: Number(r.row_no ?? r.rowNo ?? defaultRowNo),
    record_id: r.record_id ?? r.recordId,
    disposition: r.disposition,
    agent: normOpt(r.agent),
    agency: normOpt(r.agency),
    policy: normOpt(r.policy),
    book: normOpt(r.book),
    month: normOpt(r.month),
    status: normOpt(r.status),
    note: normOpt(r.note),
    committed_at: normOpt(r.committed_at ?? r.committedAt),
    approved_amount: normOpt(r.approved_amount ?? r.approvedAmount),
    approved_agency: normOpt(r.approved_agency ?? r.approvedAgency),
    approved_agent: normOpt(r.approved_agent ?? r.approvedAgent),
    approved_agency_from: normOpt(r.approved_agency_from ?? r.approvedAgencyFrom),
    approved_agent_from: normOpt(r.approved_agent_from ?? r.approvedAgentFrom),
  };
}

export function normalizeDecisionInput(d, { fallbackDecidedAt = null } = {}) {
  const committedAtRaw = d.committed_at_raw !== undefined
    ? normOpt(d.committed_at_raw)
    : (d.committedAtRaw !== undefined
      ? normOpt(d.committedAtRaw)
      : (d.committed_at !== undefined || d.committedAt !== undefined ? normOpt(d.committed_at ?? d.committedAt) : undefined));
  const rawDecidedAt = d.decided_at ?? d.decidedAt ?? null;
  const decidedAt = rawDecidedAt || fallbackDecidedAt
    ? safeTimestampIso(rawDecidedAt, fallbackDecidedAt)
    : undefined;
  return {
    ...(d.id ? { id: d.id } : {}),
    ...(d.decision_commit_id || d.decisionCommitId ? { decision_commit_id: d.decision_commit_id ?? d.decisionCommitId } : {}),
    ...(d.row_order != null || d.rowOrder != null ? { row_order: Number(d.row_order ?? d.rowOrder) } : {}),
    ...((d.run_id !== undefined || d.runId !== undefined) ? { run_id: d.run_id ?? d.runId ?? null } : {}),
    ...((d.review_save_id !== undefined || d.reviewSaveId !== undefined) ? { review_save_id: d.review_save_id ?? d.reviewSaveId ?? null } : {}),
    ...((d.surface !== undefined) ? { surface: d.surface ?? null } : {}),
    ...((d.replaces_decision_id !== undefined || d.replacesDecisionId !== undefined)
      ? { replaces_decision_id: d.replaces_decision_id ?? d.replacesDecisionId ?? null }
      : {}),
    record_id: d.record_id ?? d.recordId,
    disposition: d.disposition,
    agent: normOpt(d.agent),
    agency: normOpt(d.agency),
    policy: normOpt(d.policy),
    book: normOpt(d.book),
    month: normOpt(d.month),
    status: normOpt(d.status),
    note: normOpt(d.note),
    approved_amount: normOpt(d.approved_amount ?? d.approvedAmount),
    approved_agency: normOpt(d.approved_agency ?? d.approvedAgency),
    approved_agent: normOpt(d.approved_agent ?? d.approvedAgent),
    approved_agency_from: normOpt(d.approved_agency_from ?? d.approvedAgencyFrom),
    approved_agent_from: normOpt(d.approved_agent_from ?? d.approvedAgentFrom),
    ...(d.decided_by || d.decidedBy ? { decided_by: d.decided_by ?? d.decidedBy } : {}),
    ...(d.acting_for || d.actingFor ? { acting_for: d.acting_for ?? d.actingFor } : {}),
    ...(decidedAt !== undefined ? { decided_at: decidedAt } : {}),
    ...(committedAtRaw !== undefined ? { committed_at_raw: committedAtRaw } : {}),
  };
}

export function normalizeStatementLine(l, { isUpline = false } = {}) {
  return {
    line_no: l.line_no ?? l.lineNo ?? null,
    entry_kind: l.entry_kind ?? l.entryKind ?? null,
    run_action: l.run_action ?? l.runAction ?? null,
    ...(isUpline
      ? {
        source_entity: l.source_entity ?? l.sourceEntity ?? l.entity ?? null,
        marked_sent: l.marked_sent ?? l.markedSent ?? null,
      }
      : { entity: l.entity ?? null }),
    organization_id: l.organization_id ?? l.organizationId ?? null,
    writing_npn: l.writing_npn ?? l.writingNpn ?? null,
    writing_person_id: l.writing_person_id ?? l.writingPersonId ?? null,
    writing_agent: l.writing_agent ?? l.writingAgent ?? null,
    record_id: l.record_id ?? l.recordId ?? null,
    reversal_of: l.reversal_of ?? l.reversalOf ?? null,
    corrects_record_id: l.corrects_record_id ?? l.correctsRecordId ?? null,
    source_file: l.source_file ?? l.sourceFile ?? null,
    sheet_name: l.sheet_name ?? l.sheetName ?? null,
    source_row_no: l.source_row_no ?? l.sourceRowNo ?? null,
    src_type: l.src_type ?? l.srcType ?? null,
    carrier: l.carrier ?? null,
    mbi: l.mbi ?? null,
    member: l.member ?? null,
    external_policy_id: l.external_policy_id ?? l.externalPolicyId ?? null,
    policy_id: l.policy_id ?? l.policyId ?? null,
    tx_id: l.tx_id ?? l.txId ?? null,
    plan_type: l.plan_type ?? l.planType ?? null,
    simple_plan_type: l.simple_plan_type ?? l.simplePlanType ?? null,
    state: l.state ?? null,
    submission_date: l.submission_date ?? l.submissionDate ?? null,
    origin_effective: l.origin_effective ?? l.originEffective ?? null,
    effective_date: l.effective_date ?? l.effectiveDate ?? null,
    termination_date: l.termination_date ?? l.terminationDate ?? null,
    earned_date: l.earned_date ?? l.earnedDate ?? null,
    payment_date: l.payment_date ?? l.paymentDate ?? null,
    posted_statement_date: l.posted_statement_date ?? l.postedStatementDate ?? null,
    revenue_type: l.revenue_type ?? l.revenueType ?? null,
    gross_comm: l.gross_comm ?? l.grossComm ?? null,
    amount: l.amount ?? null,
    reason: l.reason ?? null,
    notes: l.notes ?? null,
  };
}

export function cmdReturn(out, buildFresh) {
  if (out.idempotent && out.result && typeof out.result === 'object') {
    return {
      idempotent: true,
      journalSeq: Number(out.journal_seq),
      result: out.result,
    };
  }
  return {
    idempotent: false,
    journalSeq: Number(out.journal_seq),
    result: buildFresh(out),
  };
}

export function createCommandTransport({ pool }) {
  async function runCmd({ client = null, dbToken = null, serializable = true }, fn) {
    const target = client || pool;
    const token = typeof dbToken === 'string' ? dbToken : '';
    try {
      return await withRequestTx(target, token, fn, { readOnly: false, serializable });
    } catch (err) {
      throw mapPgError(err);
    }
  }

  async function execSql(auth, sql, params) {
    return runCmd(auth, async (tx) => (await tx.query(sql, params)).rows[0].res);
  }

  return { runCmd, execSql };
}
