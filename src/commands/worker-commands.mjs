// Worker-only and Emit materialization commands, executed strictly through app_cmd.coherence_*.
import { randomUUID } from 'node:crypto';
import { AppError } from '../util/redact.mjs';
import { prepareEmitMaterialization } from '../worker/emit-materializer.mjs';
import {
  cmdReturn,
  createCommandTransport,
  hashCommandPayload,
  normalizeApprovalRow,
  normalizeStatementLine,
  normalizeStoredFile,
} from './cmd-transport.mjs';

function preparedMatToSqlPayload(mat) {
  return {
    statement_batch: {
      id: mat.statementBatch.id,
      batch_kind: mat.statementBatch.batchKind,
      statement_date: mat.statementBatch.statementDate,
      source_file_name: mat.statementBatch.sourceFileName,
      source_file_sha256: mat.statementBatch.sourceFileSha256,
      reason: mat.statementBatch.reason,
      agency_line_count: mat.statementBatch.agencyLineCount,
      agency_lines_sha256: mat.statementBatch.agencyLinesSha256,
      agency_net_total: mat.statementBatch.agencyNetTotal,
      upline_line_count: mat.statementBatch.uplineLineCount,
      upline_lines_sha256: mat.statementBatch.uplineLinesSha256,
      upline_net_total: mat.statementBatch.uplineNetTotal,
    },
    run_materialization: {
      attempt_event_id: mat.runMaterialization.attemptEventId,
      run_id: mat.runMaterialization.runId,
      statement_date: mat.runMaterialization.statementDate,
      reconciliation_mode: mat.runMaterialization.reconciliationMode,
      bob_row_count: mat.runMaterialization.bobRowCount,
      bob_rows_sha256: mat.runMaterialization.bobRowsSha256,
      bob_downline_total: mat.runMaterialization.bobDownlineTotal,
      bob_upline_total: mat.runMaterialization.bobUplineTotal,
      ledger_row_count: mat.runMaterialization.ledgerRowCount,
      ledger_rows_sha256: mat.runMaterialization.ledgerRowsSha256,
      ledger_gross_total: mat.runMaterialization.ledgerGrossTotal,
      ledger_downline_total: mat.runMaterialization.ledgerDownlineTotal,
      ledger_upline_total: mat.runMaterialization.ledgerUplineTotal,
      corpus_tail: mat.runMaterialization.corpusTail,
      agency_start: mat.runMaterialization.agencyStart,
    },
    agency_lines: mat.agencyLines.map((l) => normalizeStatementLine(l, { isUpline: false })),
    upline_lines: mat.uplineLines.map((l) => normalizeStatementLine(l, { isUpline: true })),
    bob_policies: mat.bobPolicies.map((p) => ({
      policy_id: p.policyId,
      external_policy_id: p.externalPolicyId,
      carrier_policy_number: p.carrierPolicyNumber,
      crm_policy_number: p.crmPolicyNumber,
      carrier: p.carrier,
      plan_type: p.planType,
      plan_name: p.planName,
      simple_plan_type: p.simplePlanType,
      mbi: p.mbi,
      member: p.member,
      dob: p.dob,
      phone: p.phone,
      email: p.email,
      address: p.address,
      county: p.county,
      state: p.state,
      submission_date: p.submissionDate,
      origin_effective: p.originEffective,
      effective_date: p.effectiveDate,
      termination_date: p.terminationDate,
      writing_npn: p.writingNpn,
      writing_person_id: p.writingPersonId ?? null,
      writing_agent: p.writingAgent,
      entity: p.entity,
      organization_id: p.organizationId ?? null,
      status: p.status,
      coherent_status: p.coherentStatus,
    })),
    bob_financials: mat.bobFinancials.map((f) => ({
      policy_id: f.policyId,
      entity: f.entity,
      organization_id: f.organizationId ?? null,
      writing_npn: f.writingNpn,
      writing_person_id: f.writingPersonId ?? null,
      amount: f.amount,
      upline_amount: f.uplineAmount,
      enrollment_code: f.enrollmentCode,
      min_date: f.minDate,
      anchor_date: f.anchorDate,
      agency_id: f.agencyId,
      conflicts: f.conflicts,
      spine_source: f.spineSource,
      confidence_level: f.confidenceLevel,
      coherent_trajectory: f.coherentTrajectory,
    })),
    ledger_rows: mat.ledgerRows.map((r) => ({
      tx_id: r.txId,
      record_id: r.recordId,
      external_policy_id: r.externalPolicyId,
      policy_id: r.policyId,
      statement_name: r.statementName,
      src_type: r.srcType,
      carrier: r.carrier,
      mbi: r.mbi,
      member: r.member,
      state: r.state,
      plan_type: r.planType,
      simple_plan_type: r.simplePlanType,
      submission_date: r.submissionDate,
      origin_effective: r.originEffective,
      effective_date: r.effectiveDate,
      termination_date: r.terminationDate,
      earned_date: r.earnedDate,
      payment_date: r.paymentDate,
      statement_date: r.statementDate,
      min_date: r.minDate,
      gross_comm: r.grossComm,
      revenue_type: r.revenueType,
      override_amount: r.overrideAmount,
      commission_amount: r.commissionAmount,
      hra_amount: r.hraAmount,
      fee_amount: r.feeAmount,
      other_amount: r.otherAmount,
      downline_amount: r.downlineAmount,
      upline_amount: r.uplineAmount,
      writing_npn: r.writingNpn,
      writing_person_id: r.writingPersonId ?? null,
      writing_agent: r.writingAgent,
      entity: r.entity,
      organization_id: r.organizationId ?? null,
      payee_npn: r.payeeNpn,
      agency_id: r.agencyId,
      status: r.status,
      policy_status: r.policyStatus,
      cbob_c: r.cbobC,
      cbob_s: r.cbobS,
      sf: r.sf,
      notes: r.notes,
      coherent_notes: r.coherentNotes,
      sheet_name: r.sheetName,
      source_row_no: r.sourceRowNo,
    })),
  };
}

export function createWorkerCommands({ pool = null, transport = null }) {
  const { runCmd, execSql } = transport || createCommandTransport({ pool });

  async function expireOldDrafts({ client = null, dbToken = null } = {}) {
    const out = await execSql(
      { client, dbToken, serializable: false },
      'SELECT app_cmd.coherence_expire_old_drafts() AS res',
      [],
    );
    return { deleted: Number(out.deleted ?? 0) };
  }

  async function materializeEmit({
    dbToken,
    commandKey,
    payload = null,
    runId = null,
    attemptEventId = null,
    statementDate = null,
    canonicalBobCsv = null,
    coherentLedgerCsv = null,
    statementsCsv = null,
    emitMetadataJson = null,
    workingTxCsv = null,
    statementsFileName = null,
    statementsFileSha256 = null,
    statementBatchId = undefined,
    reconciliationMode = 'strict_entity_ledger',
    columnMap = {},
  }) {
    const out = await runCmd({ dbToken }, async (tx) => {
      let bodyPayload = payload;
      if (!bodyPayload && canonicalBobCsv != null) {
        const isWorker = (await tx.query(
          "SELECT pg_catalog.pg_has_role(current_user, 'platform_worker', 'MEMBER') AS ok",
        )).rows[0]?.ok === true;
        if (!isWorker) {
          throw new AppError('CSV-mode materializeEmit is worker-only.', 403, 'WORKER_ONLY');
        }
        if (!statementDate || !attemptEventId) {
          throw new AppError(
            'CSV-mode materializeEmit requires statementDate and attemptEventId.',
            400,
            'MISSING_MATERIALIZATION_CONTEXT',
          );
        }
        const mat = await prepareEmitMaterialization({
          db: tx,
          runId,
          attemptEventId,
          statementDate,
          canonicalBobCsv,
          coherentLedgerCsv,
          statementsCsv,
          emitMetadataJson,
          workingTxCsv,
          statementsFileName,
          statementsFileSha256,
          ...(statementBatchId ? { statementBatchId } : {}),
          reconciliationMode,
          columnMap,
        });
        bodyPayload = preparedMatToSqlPayload(mat);
      } else if (!bodyPayload) {
        bodyPayload = {
          run_materialization: {
            ...(runId ? { run_id: runId } : {}),
            ...(attemptEventId ? { attempt_event_id: attemptEventId } : {}),
          },
        };
      }
      const reqPayload = bodyPayload?.statement_batch && !statementBatchId && !payload?.statement_batch?.id
        ? { ...bodyPayload, statement_batch: { ...bodyPayload.statement_batch, id: null } }
        : bodyPayload;
      const reqSha = hashCommandPayload('materialize_emit', reqPayload);
      return (await tx.query(
        'SELECT app_cmd.coherence_materialize_emit($1, $2, $3::jsonb) AS res',
        [commandKey, reqSha, JSON.stringify(bodyPayload)],
      )).rows[0].res;
    });
    return cmdReturn(out, (o) => ({
      attemptEventId: attemptEventId ?? null,
      runId: o.run_id,
      statementBatchId: o.statement_batch_id,
      bobRowCount: o.bob_row_count != null ? Number(o.bob_row_count) : undefined,
      ledgerRowCount: o.ledger_row_count != null ? Number(o.ledger_row_count) : undefined,
      agencyLineCount: o.agency_line_count != null ? Number(o.agency_line_count) : undefined,
      uplineLineCount: o.upline_line_count != null ? Number(o.upline_line_count) : undefined,
      ledgerGrossTotal: o.ledger_gross_total,
      ledgerDownlineTotal: o.ledger_downline_total,
      ledgerUplineTotal: o.ledger_upline_total,
    }));
  }

  async function startStepAttempt({ client = null, dbToken = null, commandKey, runId, step, stepRequestId, eventId = null }) {
    const reqSha = hashCommandPayload('start_attempt', { runId, step, stepRequestId });
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, $4, $5::uuid, $6::uuid) AS res',
      [commandKey, reqSha, runId, step, stepRequestId, eventId],
    );
    return cmdReturn(out, (o) => ({ attemptEventId: o.attempt_event_id, attemptNo: Number(o.attempt_no), runId, step }));
  }

  async function finishStepAttempt({
    client = null,
    dbToken = null,
    commandKey,
    eventId = null,
    nextRequestId = null,
    runId,
    step,
    attemptNo,
    census = {},
    born = null,
    logFile = null,
    artifacts = [],
    storedFiles = [],
    queueItems = [],
    generatedOverlays = [],
    emitMaterializationInput = null,
    continueToNextStep = (step === 'assign' || step === 'attribute'),
  }) {
    if (!client) throw new AppError("finishStepAttempt must run on the worker's slot connection.", 500, 'SLOT_CONNECTION_REQUIRED');
    const resolvedEventId = eventId ?? randomUUID();
    const out = await runCmd({ client, dbToken }, async (tx) => {
      let emitMat = null;
      if (emitMaterializationInput && step === 'emit') {
        const mat = await prepareEmitMaterialization({
          db: tx,
          runId,
          attemptEventId: resolvedEventId,
          ...emitMaterializationInput,
        });
        emitMat = preparedMatToSqlPayload(mat);
      }
      const payload = {
        event_id: resolvedEventId,
        ...(nextRequestId ? { next_request_id: nextRequestId } : {}),
        run_id: runId,
        step,
        attempt_no: Number(attemptNo),
        census,
        born,
        log_file: logFile ? normalizeStoredFile(logFile) : null,
        stored_files: storedFiles.map(normalizeStoredFile),
        artifacts: artifacts.map((a) => ({
          rel_path: a.rel_path ?? a.relPath,
          artifact_kind: a.artifact_kind ?? a.artifactKind,
          store_kind: a.store_kind ?? a.storeKind,
          file_sha256: a.file_sha256 ?? a.fileSha256,
        })),
        review_queue_items: queueItems.map((q, idx) => ({
          item_order: Number(q.item_order ?? q.itemOrder ?? (idx + 1)),
          surface: q.surface ?? step,
          record_id: q.record_id ?? q.recordId,
          case_kind: q.case_kind ?? q.caseKind ?? q.case ?? null,
          subtype: q.subtype ?? null,
          entity: q.entity ?? null,
          npn: q.npn ?? null,
          amount: q.amount ?? null,
          entity_from: q.entity_from ?? q.entityFrom ?? null,
          npn_from: q.npn_from ?? q.npnFrom ?? null,
          needs_reconfirm: Boolean(q.needs_reconfirm ?? q.needsReconfirm),
        })),
        generated_overlays: generatedOverlays.map((g) => ({
          ...(g.id ? { id: g.id } : {}),
          decision_commit_id: g.decision_commit_id ?? g.decisionCommitId,
          purpose: g.purpose,
          header_contract: g.header_contract ?? g.headerContract ?? 'v2',
          row_count: Number(g.row_count ?? g.rowCount),
          file_sha256: g.file_sha256 ?? g.fileSha256,
        })),
        continue_to_next_step: Boolean(continueToNextStep),
        ...(emitMat ? { emit_materialization: emitMat } : {}),
      };
      const reqPayload = {
        ...payload,
        event_id: eventId ?? null,
        ...(emitMat && !emitMaterializationInput?.statementBatchId
          ? {
            emit_materialization: {
              ...emitMat,
              statement_batch: { ...emitMat.statement_batch, id: null },
              run_materialization: { ...emitMat.run_materialization, attempt_event_id: eventId ?? null },
            },
          }
          : {}),
      };
      const reqSha = hashCommandPayload('finish_attempt', reqPayload);
      return (await tx.query(
        'SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb) AS res',
        [commandKey, reqSha, JSON.stringify(payload)],
      )).rows[0].res;
    });
    return cmdReturn(out, (o) => ({
      attemptEventId: o.attempt_event_id,
      nextRequestId: o.next_request_id ?? null,
      nextStep: o.next_step ?? null,
      statementBatchId: o.statement_batch_id ?? null,
    }));
  }

  async function failStepAttempt({
    client = null,
    dbToken = null,
    commandKey,
    runId,
    step,
    attemptNo,
    errorSummary = '',
    logFile = null,
    storedFiles = [],
    eventId = null,
  }) {
    const normLog = logFile ? normalizeStoredFile(logFile) : null;
    const normFiles = storedFiles.map(normalizeStoredFile);
    const reqSha = hashCommandPayload('fail_attempt', {
      runId, step, attemptNo: Number(attemptNo), errorSummary, logFile: normLog, storedFiles: normFiles,
    });
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.coherence_fail_attempt($1, $2, $3::uuid, $4, $5::integer, $6, $7::jsonb, $8::jsonb, $9::uuid) AS res',
      [commandKey, reqSha, runId, step, Number(attemptNo), errorSummary, normLog ? JSON.stringify(normLog) : null, JSON.stringify(normFiles), eventId],
    );
    return cmdReturn(out, (o) => ({ attemptEventId: o.attempt_event_id }));
  }

  async function cancelStepAttempt({
    client = null,
    dbToken = null,
    commandKey,
    runId,
    step,
    attemptNo,
    cancelRequestId,
    logFile = null,
    storedFiles = [],
    eventId = null,
  }) {
    const normLog = logFile ? normalizeStoredFile(logFile) : null;
    const normFiles = storedFiles.map(normalizeStoredFile);
    const reqSha = hashCommandPayload('cancel_attempt', {
      runId, step, attemptNo: Number(attemptNo), cancelRequestId, logFile: normLog, storedFiles: normFiles,
    });
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.coherence_cancel_attempt($1, $2, $3::uuid, $4, $5::integer, $6::uuid, $7::jsonb, $8::jsonb, $9::uuid) AS res',
      [commandKey, reqSha, runId, step, Number(attemptNo), cancelRequestId, normLog ? JSON.stringify(normLog) : null, JSON.stringify(normFiles), eventId],
    );
    return cmdReturn(out, (o) => ({ attemptEventId: o.attempt_event_id }));
  }

  async function interruptStepAttempt({
    client = null,
    dbToken = null,
    commandKey,
    runId,
    step,
    attemptNo,
    errorSummary = 'Worker connection lost before step completed.',
    eventId = null,
  }) {
    const reqSha = hashCommandPayload('interrupt_attempt', { runId, step, attemptNo: Number(attemptNo), errorSummary });
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.coherence_interrupt_attempt($1, $2, $3::uuid, $4, $5::integer, $6, $7::uuid) AS res',
      [commandKey, reqSha, runId, step, Number(attemptNo), errorSummary, eventId],
    );
    return cmdReturn(out, (o) => ({ attemptEventId: o.attempt_event_id }));
  }

  async function acceptReviewSubmission({
    client = null,
    dbToken = null,
    commandKey,
    submissionId,
    storedFile,
    headerKind,
    rowCount,
    extendsSha256 = null,
    sharedRowCount = 0,
    addedRows = [],
    reviewSaveId = null,
    adjustRequestId = null,
  }) {
    const normFile = normalizeStoredFile(storedFile);
    const normRows = addedRows.map((r, idx) => normalizeApprovalRow(r, Number(sharedRowCount) + idx + 1));
    const payload = {
      submission_id: submissionId,
      ...(reviewSaveId ? { review_save_id: reviewSaveId } : {}),
      ...(adjustRequestId ? { adjust_request_id: adjustRequestId } : {}),
      stored_file: normFile,
      header_kind: headerKind,
      row_count: Number(rowCount),
      extends_sha256: extendsSha256,
      shared_row_count: Number(sharedRowCount),
      added_rows: normRows,
    };
    const reqSha = hashCommandPayload('save_review', {
      submission_id: submissionId,
      stored_file: normFile,
      header_kind: headerKind,
      row_count: Number(rowCount),
      extends_sha256: extendsSha256,
      shared_row_count: Number(sharedRowCount),
      added_rows: normRows,
    });
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.coherence_accept_review_submission($1, $2, $3::jsonb) AS res',
      [commandKey, reqSha, JSON.stringify(payload)],
    );
    const wrapped = cmdReturn(out, (o) => ({ reviewSaveId: o.review_save_id, submissionId }));
    return {
      ...wrapped,
      reviewSaveId: wrapped.result.reviewSaveId,
    };
  }

  async function rejectReviewSubmission({
    client = null,
    dbToken = null,
    submissionId,
    status = 'rejected',
    reason = 'Review file rejected.',
  }) {
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.coherence_reject_review_submission($1::uuid, $2, $3) AS res',
      [submissionId, status, reason],
    );
    return { submissionId: out.submission_id, status: out.status };
  }

  return {
    startStepAttempt,
    finishStepAttempt,
    failStepAttempt,
    cancelStepAttempt,
    interruptStepAttempt,
    acceptReviewSubmission,
    rejectReviewSubmission,
    expireOldDrafts,
    materializeEmit,
  };
}
