// Human runtime commands for Coherence web screens, executed strictly through app_cmd.coherence_*.
import { randomUUID } from 'node:crypto';
import { objectNameForSha256 } from '../storage/artifact-policy.mjs';
import { canonicalInputEntriesText, fingerprintBytes, sha256Hex } from '../util/crypto.mjs';
import { assertValidRelPath, findPathClashes } from '../util/csv.mjs';
import { AppError } from '../util/redact.mjs';
import {
  cmdReturn,
  createCommandTransport,
  hashCommandPayload,
  normalizeDecisionInput,
  normalizeStoredFile,
  toSeqOrNull,
} from './cmd-transport.mjs';

export function createRuntimeCommands({ pool = null, transport = null, stores = null }) {
  const { runCmd, execSql } = transport || createCommandTransport({ pool });

  async function publishInputVersion({
    dbToken,
    commandKey,
    expectedJournalSeq = null,
    id = null,
    inputVersionId = null,
    lineKind = 'standing',
    sourceKind,
    reason,
    entries = [],
    changes = undefined,
    storedFiles = [],
    entriesListFileSha256 = null,
    storeCanonicalList = false,
  }) {
    if (!Array.isArray(entries)) throw new AppError('entries must be an array.', 400, 'INVALID_ENTRIES');
    const normEntries = entries.map((e) => {
      const relPath = e.rel_path ?? e.relPath;
      assertValidRelPath(relPath, 'entry relPath');
      return { rel_path: relPath, file_sha256: e.file_sha256 ?? e.fileSha256 };
    });
    const clashes = findPathClashes(normEntries.map((e) => e.rel_path));
    if (clashes.length > 0) {
      throw new AppError(`Input version contains conflicting paths (${clashes[0].kind}).`, 409, 'PATH_CLASH');
    }

    let listSha = entriesListFileSha256;
    let listBytes = null;
    const allFiles = [...storedFiles];
    if (storeCanonicalList && stores?.dataStore) {
      listBytes = Buffer.from(canonicalInputEntriesText(normEntries), 'utf8');
      const fp = fingerprintBytes(listBytes);
      allFiles.push({
        storeKind: stores.dataStore.storeKind,
        sha256: fp.sha256,
        byteSize: fp.byteSize,
        md5B64: fp.md5B64,
        crc32cB64: fp.crc32cB64,
        objectName: objectNameForSha256(fp.sha256),
      });
      listSha = fp.sha256;
    }

    const normChanges = changes === undefined || changes === null
      ? null
      : changes.map((c) => ({
        change_kind: c.change_kind ?? c.changeKind,
        rel_path: c.rel_path ?? c.relPath,
        old_rel_path: c.old_rel_path ?? c.oldRelPath ?? null,
        file_sha256: c.file_sha256 ?? c.fileSha256 ?? null,
        prev_file_sha256: c.prev_file_sha256 ?? c.prevFileSha256 ?? null,
      }));
    const normFiles = allFiles.map(normalizeStoredFile);
    const reqSha = hashCommandPayload('publish_input_version', {
      lineKind, sourceKind, reason, entries: normEntries, changes: normChanges, storedFiles: normFiles, entriesListFileSha256: listSha,
    });
    const out = await runCmd({ dbToken }, async (tx) => {
      const res = (await tx.query(
        `SELECT app_cmd.coherence_publish_input_version(
           $1, $2, $3::bigint, $4, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb, $10, $11::uuid
         ) AS res`,
        [
          commandKey, reqSha, toSeqOrNull(expectedJournalSeq), lineKind, sourceKind, reason,
          JSON.stringify(normEntries), normChanges === null ? null : JSON.stringify(normChanges),
          JSON.stringify(normFiles), listSha, inputVersionId ?? id,
        ],
      )).rows[0].res;
      if (listBytes && !res.idempotent) {
        await stores.dataStore.promoteBytes(listBytes, {
          relPath: 'input-entries.canonical.ndjson',
          checksPassed: true,
          contentType: 'application/x-ndjson',
        });
      }
      return res;
    });
    return cmdReturn(out, (o) => ({ inputVersionId: o.input_version_id }));
  }

  async function includeStagingFile({
    dbToken,
    commandKey,
    expectedJournalSeq = null,
    stagingFileSha256,
    targetRelPath,
    reason,
    inputVersionId = null,
  }) {
    assertValidRelPath(targetRelPath, 'targetRelPath');
    if (!reason || !String(reason).trim()) {
      throw new AppError('A reason is required to include a file in calculations.', 400, 'MISSING_REASON');
    }
    const trimmedReason = String(reason).trim();
    const reqSha = hashCommandPayload('include_staging_file', {
      stagingFileSha256, targetRelPath, reason: trimmedReason,
    });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_include_staging_file($1, $2, $3::bigint, $4, $5, $6, $7::uuid) AS res',
      [commandKey, reqSha, toSeqOrNull(expectedJournalSeq), stagingFileSha256, targetRelPath, trimmedReason, inputVersionId],
    );
    if (out.unchanged) {
      return { unchanged: true, inputVersionId: out.input_version_id, targetRelPath };
    }
    return cmdReturn(out, (o) => ({ inputVersionId: o.input_version_id }));
  }

  async function launchRun({
    dbToken,
    commandKey,
    expectedJournalSeq = null,
    statementDate,
    engineVersionId,
    origin = 'app',
    inputVersionId = null,
    priorDecisionCommitId = null,
    emitMode = null,
    emitDisplay = null,
    emitKeep = null,
    emitNoManager = null,
    replaysRunId = null,
    comparedRunId = null,
    rerunReason = null,
    id = null,
    runId = null,
    requestId = null,
  }) {
    const reqSha = hashCommandPayload('launch_run', {
      statementDate, engineVersionId, origin, inputVersionId, priorDecisionCommitId,
      emitMode, emitDisplay, emitKeep, emitNoManager, replaysRunId, comparedRunId, rerunReason,
    });
    const out = await execSql(
      { dbToken },
      `SELECT app_cmd.coherence_launch_run(
         $1, $2, $3::bigint, $4::date, $5::uuid, $6, $7::uuid, $8::uuid,
         $9, $10, $11::text[], $12::text[], $13::uuid, $14::uuid, $15, $16::uuid, $17::uuid
       ) AS res`,
      [
        commandKey, reqSha, toSeqOrNull(expectedJournalSeq), statementDate, engineVersionId,
        origin, inputVersionId, priorDecisionCommitId, emitMode, emitDisplay, emitKeep, emitNoManager,
        replaysRunId, comparedRunId, rerunReason, runId ?? id, requestId,
      ],
    );
    return cmdReturn(out, (o) => ({
      runId: o.run_id,
      stepRequestId: o.step_request_id,
      statementDate,
      folderNumber: o.folder_number != null ? Number(o.folder_number) : undefined,
      origin,
      priorDecisionCommitId: o.prior_decision_commit_id ?? null,
    }));
  }

  async function requestCancel({
    dbToken,
    commandKey,
    expectedJournalSeq = null,
    runId,
    step,
    attemptNo,
    typedPhrase,
    reason = '',
    cancelRequestId = null,
  }) {
    const reqSha = hashCommandPayload('request_cancel', { runId, step, attemptNo: Number(attemptNo), typedPhrase, reason });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_request_cancel($1, $2, $3::bigint, $4::uuid, $5, $6::integer, $7, $8, $9::uuid) AS res',
      [commandKey, reqSha, toSeqOrNull(expectedJournalSeq), runId, step, Number(attemptNo), typedPhrase, reason, cancelRequestId],
    );
    return cmdReturn(out, (o) => ({ cancelRequestId: o.cancel_request_id, runId, step, attemptNo: Number(attemptNo) }));
  }

  async function requestRetry({ dbToken, commandKey, expectedJournalSeq = null, runId, step, requestId = null }) {
    const reqSha = hashCommandPayload('request_retry', { runId, step });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_request_retry($1, $2, $3::bigint, $4::uuid, $5, $6::uuid) AS res',
      [commandKey, reqSha, toSeqOrNull(expectedJournalSeq), runId, step, requestId],
    );
    return cmdReturn(out, (o) => ({ stepRequestId: o.step_request_id, runId, step }));
  }

  async function submitReview({
    dbToken,
    commandKey,
    expectedJournalSeq,
    runId,
    surface,
    csvBytes,
    submissionId = randomUUID(),
  }) {
    if (!['bible', 'adjust'].includes(surface)) {
      throw new AppError('Review surface must be bible or adjust.', 400, 'INVALID_SURFACE');
    }
    if (typeof commandKey !== 'string' || !commandKey.length) {
      throw new AppError('Review submission requires commandKey.', 400, 'MISSING_COMMAND_KEY');
    }
    if (expectedJournalSeq === null || expectedJournalSeq === undefined || !Number.isInteger(Number(expectedJournalSeq)) || Number(expectedJournalSeq) < 0) {
      throw new AppError('Review submission requires expectedJournalSeq.', 400, 'MISSING_JOURNAL_SEQ');
    }
    const buf = Buffer.isBuffer(csvBytes) ? csvBytes : Buffer.from(String(csvBytes ?? ''), 'utf8');
    if (buf.length === 0) throw new AppError('Review file cannot be empty.', 400, 'EMPTY_REVIEW');
    if (!stores?.dataStore) throw new AppError('Company data store is required to stage reviews.', 500, 'STORE_NOT_CONFIGURED');

    const stagedSha256 = sha256Hex(buf);
    const reqSha = hashCommandPayload('submit_review', {
      runId, surface, stagedSha256, expectedJournalSeq: Number(expectedJournalSeq),
    });

    const out = await runCmd({ dbToken }, async (tx) => {
      const res = (await tx.query(
        'SELECT app_cmd.coherence_submit_review($1, $2, $3::bigint, $4::uuid, $5, $6, $7::uuid) AS res',
        [commandKey, reqSha, String(Number(expectedJournalSeq)), runId, surface, stagedSha256, submissionId],
      )).rows[0].res;
      if (!res.idempotent) {
        await stores.dataStore.stageReview({ submissionId: res.submission_id, bytes: buf });
      }
      return res;
    });
    return {
      idempotent: Boolean(out.idempotent),
      submissionId: out.submission_id,
      status: out.status,
      stagedSha256,
    };
  }

  async function saveReviewDraft({ dbToken, runId, surface, attemptNo, born = null, checksum, rows }) {
    if (!['bible', 'adjust'].includes(surface)) throw new AppError('Invalid surface.', 400, 'INVALID_SURFACE');
    if (!Array.isArray(rows)) throw new AppError('Draft rows must be an array.', 400, 'INVALID_DRAFT');
    const out = await execSql(
      { dbToken, serializable: false },
      'SELECT app_cmd.coherence_save_review_draft($1::uuid, $2, $3::integer, $4, $5::jsonb, $6) AS res',
      [runId, surface, Number(attemptNo), checksum, JSON.stringify(rows), born],
    );
    return {
      saved: Number(out.saved ?? rows.length),
      runId: out.run_id ?? runId,
      surface: out.surface ?? surface,
      attemptNo: Number(out.attempt_no ?? attemptNo),
    };
  }

  async function saveReviewDecisions({
    dbToken,
    commandKey,
    expectedJournalSeq,
    runId,
    surface,
    decisions = [],
    decisionCommitId = null,
    reviewSaveId = null,
    adjustRequestId = null,
  }) {
    if (!Array.isArray(decisions)) {
      throw new AppError('decisions must be an array.', 400, 'INVALID_DECISIONS');
    }
    const normDecisions = decisions.map((d) => normalizeDecisionInput(d));
    const reqSha = hashCommandPayload('save_review_decisions', {
      runId, surface, expectedJournalSeq: expectedJournalSeq != null ? Number(expectedJournalSeq) : null, decisions: normDecisions,
    });
    const out = await execSql(
      { dbToken },
      `SELECT app_cmd.coherence_save_review_decisions(
         $1, $2, $3::bigint, $4::uuid, $5, $6::jsonb, $7::uuid, $8::uuid, $9::uuid
       ) AS res`,
      [
        commandKey, reqSha, toSeqOrNull(expectedJournalSeq), runId, surface,
        JSON.stringify(normDecisions), decisionCommitId, reviewSaveId, adjustRequestId,
      ],
    );
    return cmdReturn(out, (o) => ({
      decisionCommitId: o.decision_commit_id,
      reviewSaveId: o.review_save_id,
      runId,
      surface,
      addedCount: normDecisions.length,
    }));
  }

  async function confirmEmit({
    dbToken,
    commandKey,
    expectedJournalSeq = null,
    runId,
    adjustReviewSaveId,
    typedPhrase,
    confirmationId = null,
    requestId = null,
  }) {
    const reqSha = hashCommandPayload('confirm_emit', { runId, adjustReviewSaveId, typedPhrase });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_confirm_emit($1, $2, $3::bigint, $4::uuid, $5::uuid, $6, $7::uuid, $8::uuid) AS res',
      [commandKey, reqSha, toSeqOrNull(expectedJournalSeq), runId, adjustReviewSaveId, typedPhrase, confirmationId, requestId],
    );
    return cmdReturn(out, (o) => ({ emitConfirmationId: o.emit_confirmation_id, stepRequestId: o.step_request_id ?? null, runId }));
  }

  async function carrySent({
    dbToken,
    commandKey,
    expectedJournalSeq = null,
    runId,
    typedPhrase,
    reason = null,
    provenance = null,
    sentProvenance = null,
    carryId = null,
    inputVersionId = null,
  }) {
    const prov = sentProvenance ?? provenance;
    const reqSha = hashCommandPayload('carry_sent', { runId, typedPhrase, reason, sentProvenance: prov });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_carry_sent($1, $2, $3::bigint, $4::uuid, $5, $6, $7::uuid, $8::uuid, $9::jsonb) AS res',
      [
        commandKey, reqSha, toSeqOrNull(expectedJournalSeq), runId, typedPhrase, reason, carryId, inputVersionId,
        prov ? JSON.stringify(prov) : null,
      ],
    );
    return cmdReturn(out, (o) => ({ carryId: o.carry_id, publishedInputVersionId: o.published_input_version_id ?? null }));
  }

  async function carryApprovals({
    dbToken,
    commandKey,
    expectedJournalSeq = null,
    runId,
    typedPhrase,
    carryId = null,
    inputVersionId = null,
  }) {
    const reqSha = hashCommandPayload('carry_approvals', { runId, typedPhrase });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_carry_approvals($1, $2, $3::bigint, $4::uuid, $5, $6::uuid, $7::uuid) AS res',
      [commandKey, reqSha, toSeqOrNull(expectedJournalSeq), runId, typedPhrase, carryId, inputVersionId],
    );
    return cmdReturn(out, (o) => ({
      carryId: o.carry_id,
      publishedInputVersionId: o.published_input_version_id ?? null,
      nothingNew: Boolean(o.nothing_new),
    }));
  }

  async function carryDecisions({
    dbToken,
    commandKey,
    expectedJournalSeq = null,
    runId,
    typedPhrase,
    receiptFileSha256 = null,
    carryId = null,
  }) {
    const reqSha = hashCommandPayload('carry_decisions', { runId, typedPhrase, receiptFileSha256 });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_carry_decisions($1, $2, $3::bigint, $4::uuid, $5, $6, $7::uuid) AS res',
      [commandKey, reqSha, toSeqOrNull(expectedJournalSeq), runId, typedPhrase, receiptFileSha256, carryId],
    );
    return cmdReturn(out, (o) => ({
      carryId: o.carry_id,
      carriedDecisionCommitId: o.carried_decision_commit_id ?? null,
      nothingNew: Boolean(o.nothing_new),
    }));
  }

  async function abandonRun({
    dbToken,
    commandKey,
    expectedJournalSeq = null,
    runId,
    typedPhrase,
    reason,
    abandonmentId = null,
  }) {
    const reqSha = hashCommandPayload('abandon_run', { runId, typedPhrase, reason });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_abandon_run($1, $2, $3::bigint, $4::uuid, $5, $6, $7::uuid) AS res',
      [commandKey, reqSha, toSeqOrNull(expectedJournalSeq), runId, typedPhrase, reason, abandonmentId],
    );
    return cmdReturn(out, (o) => ({ abandonmentId: o.abandonment_id, runId: o.run_id ?? runId, abandoned: true }));
  }

  async function recordCheck({
    dbToken,
    commandKey,
    checkKind,
    passed,
    report,
    runId = null,
    comparedRunId = null,
    checkId = null,
  }) {
    const reqSha = hashCommandPayload('record_check', { checkKind, passed: Boolean(passed), report, runId, comparedRunId });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_record_check($1, $2, $3, $4::boolean, $5::jsonb, $6::uuid, $7::uuid, $8::uuid) AS res',
      [commandKey, reqSha, checkKind, Boolean(passed), JSON.stringify(report), runId, comparedRunId, checkId],
    );
    return cmdReturn(out, (o) => ({ checkId: o.check_id, passed: Boolean(passed) }));
  }

  async function authorizeCheckRun({ dbToken }) {
    return runCmd({ dbToken, serializable: false }, async (tx) => (
      Boolean((await tx.query('SELECT app_cmd.coherence_authorize_check_run() AS ok')).rows[0]?.ok)
    ));
  }

  return {
    publishInputVersion,
    includeStagingFile,
    launchRun,
    requestCancel,
    requestRetry,
    submitReview,
    saveReviewDraft,
    saveReviewDecisions,
    confirmEmit,
    carrySent,
    carryApprovals,
    carryDecisions,
    abandonRun,
    recordCheck,
    authorizeCheckRun,
  };
}
