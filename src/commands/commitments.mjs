// Canonical journal commitment builders matching migrations/002_invariants_and_triggers.sql byte for byte.
import {
  canonicalJson,
  compareUtf8Bytes,
  formatTimestampUtcUs,
  sha256Hex,
} from '../util/crypto.mjs';

export const BUSINESS_TABLES = [
  'company_meta',
  'stored_files',
  'engine_versions',
  'input_versions',
  'input_entries',
  'input_changes',
  'approvals_files',
  'approval_rows',
  'runs',
  'step_requests',
  'cancel_requests',
  'step_attempt_events',
  'artifacts',
  'review_saves',
  'emit_confirmations',
  'carries',
  'abandonments',
  'imported_files',
  'checks',
];

function hashLines(lines) {
  return sha256Hex(lines.join(''));
}

export function hashStoredFilesTable(rows) {
  const sorted = [...rows].sort((a, b) => (
    compareUtf8Bytes(a.storeKind ?? a.store_kind, b.storeKind ?? b.store_kind)
    || compareUtf8Bytes(a.sha256, b.sha256)
  ));
  return hashLines(sorted.map((r) => `${canonicalJson([
    r.storeKind ?? r.store_kind,
    r.sha256,
    Number(r.byteSize ?? r.byte_size),
    r.md5B64 ?? r.md5_b64,
    r.crc32cB64 ?? r.crc32c_b64,
    r.objectName ?? r.object_name,
  ])}\n`));
}

export function hashInputEntriesTable(rows) {
  const sorted = [...rows].sort((a, b) => (
    compareUtf8Bytes(a.inputVersionId ?? a.input_version_id, b.inputVersionId ?? b.input_version_id)
    || compareUtf8Bytes(a.relPath ?? a.rel_path, b.relPath ?? b.rel_path)
  ));
  return hashLines(sorted.map((r) => `${canonicalJson([
    r.relPath ?? r.rel_path,
    r.fileSha256 ?? r.file_sha256,
  ])}\n`));
}

export function hashInputChangesTable(rows) {
  const sorted = [...rows].sort((a, b) => (
    compareUtf8Bytes(a.inputVersionId ?? a.input_version_id, b.inputVersionId ?? b.input_version_id)
    || compareUtf8Bytes(a.relPath ?? a.rel_path, b.relPath ?? b.rel_path)
  ));
  return hashLines(sorted.map((r) => `${canonicalJson([
    r.changeKind ?? r.change_kind,
    r.relPath ?? r.rel_path,
    r.oldRelPath ?? r.old_rel_path ?? null,
    r.fileSha256 ?? r.file_sha256 ?? null,
    r.prevFileSha256 ?? r.prev_file_sha256 ?? null,
  ])}\n`));
}

export function hashArtifactsTable(rows) {
  const sorted = [...rows].sort((a, b) => (
    compareUtf8Bytes(a.attemptEventId ?? a.attempt_event_id, b.attemptEventId ?? b.attempt_event_id)
    || compareUtf8Bytes(a.relPath ?? a.rel_path, b.relPath ?? b.rel_path)
  ));
  return hashLines(sorted.map((r) => `${canonicalJson([
    r.relPath ?? r.rel_path,
    r.artifactKind ?? r.artifact_kind,
    r.storeKind ?? r.store_kind,
    r.fileSha256 ?? r.file_sha256,
  ])}\n`));
}

export function hashApprovalRowsTable(rows) {
  const sorted = [...rows].sort((a, b) => (
    compareUtf8Bytes(
      a.approvalsFileSha256 ?? a.approvals_file_sha256,
      b.approvalsFileSha256 ?? b.approvals_file_sha256,
    )
    || Number(a.rowNo ?? a.row_no) - Number(b.rowNo ?? b.row_no)
  ));
  return hashLines(sorted.map((r) => `${canonicalJson([
    Number(r.rowNo ?? r.row_no),
    r.record_id ?? r.recordId,
    r.disposition ?? null,
    r.agent ?? null,
    r.agency ?? null,
    r.policy ?? null,
    r.book ?? null,
    r.month ?? null,
    r.status ?? null,
    r.note ?? null,
    r.committed_at ?? r.committedAt ?? null,
    r.approved_amount ?? r.approvedAmount ?? null,
    r.approved_agency ?? r.approvedAgency ?? null,
    r.approved_agent ?? r.approvedAgent ?? null,
    r.approved_agency_from ?? r.approvedAgencyFrom ?? null,
    r.approved_agent_from ?? r.approvedAgentFrom ?? null,
  ])}\n`));
}

export function hashRunsTable(rows) {
  const sorted = [...rows].sort((a, b) => compareUtf8Bytes(a.id, b.id));
  return hashLines(sorted.map((r) => `${canonicalJson([
    r.id,
    r.statementDate ?? r.statement_date,
    Number(r.folderNumber ?? r.folder_number),
    r.origin,
    r.inputVersionId ?? r.input_version_id,
    r.priorApprovalsSha256 ?? r.prior_approvals_sha256 ?? null,
    r.engineVersionId ?? r.engine_version_id ?? null,
    r.emitMode ?? r.emit_mode,
    r.emitDisplay ?? r.emit_display ?? null,
    r.emitKeep ?? r.emit_keep ?? [],
    r.emitNoManager ?? r.emit_no_manager ?? [],
    r.replaysRunId ?? r.replays_run_id ?? null,
    r.comparedRunId ?? r.compared_run_id ?? null,
    r.rerunReason ?? r.rerun_reason ?? null,
    r.sourceFolder ?? r.source_folder ?? null,
  ])}\n`));
}

export function hashCarriesTable(rows) {
  const sorted = [...rows].sort((a, b) => compareUtf8Bytes(a.id, b.id));
  return hashLines(sorted.map((r) => `${canonicalJson([
    r.id,
    r.runId ?? r.run_id,
    r.statementDate ?? r.statement_date,
    r.carryKind ?? r.carry_kind,
    r.fileSha256 ?? r.file_sha256,
    r.publishedInputVersionId ?? r.published_input_version_id ?? null,
    Boolean(r.nothingNew ?? r.nothing_new),
    r.typedPhrase ?? r.typed_phrase,
  ])}\n`));
}

export function hashAbandonmentsTable(rows) {
  const sorted = [...rows].sort((a, b) => compareUtf8Bytes(a.id, b.id));
  return hashLines(sorted.map((r) => `${canonicalJson([
    r.id,
    r.runId ?? r.run_id,
    r.typedPhrase ?? r.typed_phrase,
    r.reason,
  ])}\n`));
}

export function hashEmitConfirmationsTable(rows) {
  const sorted = [...rows].sort((a, b) => compareUtf8Bytes(a.id, b.id));
  return hashLines(sorted.map((r) => `${canonicalJson([
    r.id,
    r.runId ?? r.run_id,
    r.adjustReviewSaveId ?? r.adjust_review_save_id,
    r.typedPhrase ?? r.typed_phrase,
  ])}\n`));
}

export function hashReviewSavesTable(rows) {
  const sorted = [...rows].sort((a, b) => compareUtf8Bytes(a.id, b.id));
  return hashLines(sorted.map((r) => `${canonicalJson([
    r.id,
    r.runId ?? r.run_id,
    r.surface,
    r.attemptEventId ?? r.attempt_event_id,
    r.approvalsFileSha256 ?? r.approvals_file_sha256,
    Boolean(r.imported),
    (r.originalAt ?? r.original_at) ? formatTimestampUtcUs(r.originalAt ?? r.original_at) : null,
    r.submissionId ?? r.submission_id ?? null,
  ])}\n`));
}

export function hashStepRequestsTable(rows) {
  const sorted = [...rows].sort((a, b) => compareUtf8Bytes(a.id, b.id));
  return hashLines(sorted.map((r) => `${canonicalJson([
    r.id,
    r.runId ?? r.run_id,
    r.step,
    r.reason,
    r.emitConfirmationId ?? r.emit_confirmation_id ?? null,
  ])}\n`));
}

export function hashStepAttemptEventsTable(rows) {
  const sorted = [...rows].sort((a, b) => compareUtf8Bytes(a.id, b.id));
  return hashLines(sorted.map((r) => `${canonicalJson([
    r.id,
    r.runId ?? r.run_id,
    r.step,
    Number(r.attemptNo ?? r.attempt_no),
    r.eventKind ?? r.event_kind,
    r.stepRequestId ?? r.step_request_id ?? null,
    r.cancelRequestId ?? r.cancel_request_id ?? null,
    r.born ?? null,
    r.logFileSha256 ?? r.log_file_sha256 ?? null,
    (r.artifactCount ?? r.artifact_count) == null ? null : Number(r.artifactCount ?? r.artifact_count),
    r.artifactsSha256 ?? r.artifacts_sha256 ?? null,
  ])}\n`));
}

const TABLE_HASHERS = {
  stored_files: hashStoredFilesTable,
  input_entries: hashInputEntriesTable,
  input_changes: hashInputChangesTable,
  artifacts: hashArtifactsTable,
  approval_rows: hashApprovalRowsTable,
  runs: hashRunsTable,
  carries: hashCarriesTable,
  abandonments: hashAbandonmentsTable,
  emit_confirmations: hashEmitConfirmationsTable,
  review_saves: hashReviewSavesTable,
  step_requests: hashStepRequestsTable,
  step_attempt_events: hashStepAttemptEventsTable,
};

/**
 * Builds the `commitments` object embedded into journal_entries.body from the exact rows being written.
 */
export function buildCommitments(tables = {}) {
  const counts = {};
  const hashes = {};
  for (const [tableName, rows] of Object.entries(tables)) {
    if (!rows || rows.length === 0) continue;
    counts[tableName] = rows.length;
    if (TABLE_HASHERS[tableName]) {
      hashes[tableName] = TABLE_HASHERS[tableName](rows);
    }
  }
  return { counts, hashes };
}
