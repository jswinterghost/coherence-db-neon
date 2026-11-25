// Single database-enforced write bridge: executes every Coherence command strictly through
// app_cmd.coherence_* SECURITY DEFINER functions in PostgreSQL via withRequestTx and a signed dbToken.
import { randomUUID } from 'node:crypto';
import { withRequestTx } from '../db/pg-client.mjs';
import { objectNameForSha256 } from '../storage/artifact-policy.mjs';
import { canonicalInputEntriesText, canonicalJson, fingerprintBytes, formatTimestampUtcUs, sha256Hex } from '../util/crypto.mjs';
import { assertValidRelPath, findPathClashes, isValidIsoDate } from '../util/csv.mjs';
import { AppError, sanitizeErrorMessage } from '../util/redact.mjs';
import { prepareEmitMaterialization } from '../worker/emit-materializer.mjs';

function extractErrorCodePrefix(rawMessage) {
  const m = /^([A-Z][A-Z0-9_]{2,50}):/.exec(String(rawMessage || '').trim());
  return m ? m[1] : null;
}

export function mapPgError(error) {
  if (error instanceof AppError) return error;
  const pgCode = error?.code;
  const rawMessage = String(error?.message || '');
  const prefix = extractErrorCodePrefix(rawMessage);
  const msg = sanitizeErrorMessage(error, 'Database refused the change.');

  if (pgCode === '42501') {
    if (prefix === 'VIEW_AS_READ_ONLY' || /VIEW_AS_READ_ONLY/i.test(rawMessage)) {
      return new AppError('Cannot make changes while viewing as another user.', 403, 'VIEW_AS_READ_ONLY');
    }
    if (prefix === 'WORKER_ONLY') {
      return new AppError('Only the Coherence engine worker service identity may perform this operation.', 403, 'WORKER_ONLY');
    }
    if (prefix === 'HUMAN_ONLY') {
      return new AppError('The worker service identity cannot execute human decision commands.', 403, 'HUMAN_ONLY');
    }
    return new AppError('Insufficient database privilege for this operation.', 403, 'FORBIDDEN');
  }
  if (pgCode === '25006') {
    return new AppError('Cannot make changes in a read-only transaction.', 403, 'VIEW_AS_READ_ONLY');
  }
  if (pgCode === 'P0002') {
    return new AppError(msg, 404, prefix || 'NOT_FOUND');
  }
  if (pgCode === '40001') {
    if (prefix === 'STALE_JOURNAL_POSITION' || /STALE_JOURNAL_POSITION/i.test(rawMessage)) {
      return new AppError('State changed since the screen loaded; reload and try again.', 409, 'STALE_JOURNAL_POSITION');
    }
    return new AppError('Concurrent change conflicted; retry with current state.', 409, 'SERIALIZATION_FAILURE');
  }
  if (pgCode === '23505') {
    return new AppError(msg, 409, prefix || 'UNIQUE_VIOLATION');
  }
  if (pgCode === '22023') {
    const isInputErr = prefix && (prefix.startsWith('MISSING_') || prefix.startsWith('INVALID_'));
    return new AppError(msg, isInputErr ? 400 : 409, prefix || 'INVARIANT_VIOLATION');
  }
  if (pgCode === '23514') {
    return new AppError(msg, 409, prefix || 'INVARIANT_VIOLATION');
  }
  if (pgCode === '23503') {
    return new AppError(msg, 409, prefix || 'REFERENCE_VIOLATION');
  }
  if (pgCode === '55000') {
    return new AppError(msg, 409, prefix || 'STATE_CONFLICT');
  }
  return new AppError(msg, 500, 'DB_ERROR');
}

function hashCommandPayload(commandKind, payload) {
  return sha256Hex(canonicalJson({ commandKind, payload }));
}

function normOpt(v) {
  return v == null || v === '' ? null : String(v);
}

function safeTimestampIso(raw, fallbackIso = null) {
  for (const val of [raw, fallbackIso]) {
    if (!val) continue;
    try {
      return formatTimestampUtcUs(val);
    } catch {}
  }
  return formatTimestampUtcUs(new Date());
}

function toSeqOrNull(expectedJournalSeq) {
  if (expectedJournalSeq === null || expectedJournalSeq === undefined || expectedJournalSeq === '') return null;
  const n = Number(expectedJournalSeq);
  if (!Number.isInteger(n) || n < 0) {
    throw new AppError('expectedJournalSeq must be a non-negative integer.', 400, 'INVALID_JOURNAL_SEQ');
  }
  return String(n);
}

function normalizeStoredFile(f) {
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

function normalizeApprovalRow(r, defaultRowNo = null) {
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

function normalizeDecisionInput(d, { fallbackDecidedAt = null } = {}) {
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

function normalizeStatementLine(l, { isUpline = false } = {}) {
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

function cmdReturn(out, buildFresh) {
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

export function createAppCommands({ pool, stores = null }) {
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

  async function initCompany({
    dbToken,
    commandKey,
    slug,
    displayName,
    defaultEmitMode = 'builtin',
    defaultEmitDisplay = null,
    defaultEmitKeep = [],
    defaultEmitNoManager = [],
  }) {
    const reqSha = hashCommandPayload('init_company', {
      slug, displayName, defaultEmitMode, defaultEmitDisplay, defaultEmitKeep, defaultEmitNoManager,
    });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_init_company($1, $2, $3, $4, $5, $6, $7::text[], $8::text[]) AS res',
      [commandKey, reqSha, slug, displayName, defaultEmitMode, defaultEmitDisplay, defaultEmitKeep, defaultEmitNoManager],
    );
    return cmdReturn(out, (o) => ({ companySlug: o.company_slug ?? slug, displayName, defaultEmitMode }));
  }

  async function registerStoredFiles({ dbToken, commandKey, files = [] }) {
    const norm = files.map(normalizeStoredFile);
    const reqSha = hashCommandPayload('register_stored_files', { files: norm });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_register_stored_files($1, $2, $3::jsonb) AS res',
      [commandKey, reqSha, JSON.stringify(norm)],
    );
    return cmdReturn(out, (o) => {
      const cnt = Number(o.inserted_count ?? o.registered ?? 0);
      return { insertedCount: cnt, registered: cnt };
    });
  }

  async function registerEngineVersion({ dbToken, commandKey, payload = null, ...rest }) {
    const fileObjs = [
      rest.gitBundle, rest.codeManifest, rest.pythonLock, rest.pythonWheels,
      rest.webLock, rest.webPackages, rest.wrapperBundle, rest.patchDiff,
      ...(rest.storedFiles ?? rest.stored_files ?? []),
    ].filter(Boolean);
    const p = payload || {
      ...(rest.id ? { id: rest.id } : {}),
      label: rest.label,
      coherence_commit: rest.coherenceCommit ?? rest.coherence_commit,
      engine_kind: rest.engineKind ?? rest.engine_kind ?? 'legacy_sealed',
      upstream_commit: rest.upstreamCommit ?? rest.upstream_commit ?? null,
      patch_diff_sha256: rest.patchDiffSha256 ?? rest.patch_diff_sha256 ?? rest.patchDiff?.sha256 ?? null,
      git_bundle_sha256: rest.gitBundleSha256 ?? rest.git_bundle_sha256 ?? rest.gitBundle?.sha256 ?? null,
      code_manifest_sha256: rest.codeManifestSha256 ?? rest.code_manifest_sha256 ?? rest.codeManifest?.sha256 ?? null,
      python_lock_sha256: rest.pythonLockSha256 ?? rest.python_lock_sha256 ?? rest.pythonLock?.sha256 ?? null,
      python_wheels_sha256: rest.pythonWheelsSha256 ?? rest.python_wheels_sha256 ?? rest.pythonWheels?.sha256 ?? null,
      web_lock_sha256: rest.webLockSha256 ?? rest.web_lock_sha256 ?? rest.webLock?.sha256 ?? null,
      web_packages_sha256: rest.webPackagesSha256 ?? rest.web_packages_sha256 ?? rest.webPackages?.sha256 ?? null,
      wrapper_bundle_sha256: rest.wrapperBundleSha256 ?? rest.wrapper_bundle_sha256 ?? rest.wrapperBundle?.sha256 ?? null,
      nusear_commit: rest.nusearCommit ?? rest.nusear_commit,
      company_emit_sha256: rest.companyEmitSha256 ?? rest.company_emit_sha256 ?? null,
      pages_law_sha256: rest.pagesLawSha256 ?? rest.pages_law_sha256 ?? null,
      overlay_check_sha256: rest.overlayCheckSha256 ?? rest.overlay_check_sha256,
      toolchain: rest.toolchain,
      container_digest: rest.containerDigest ?? rest.container_digest ?? null,
      stored_files: fileObjs.map(normalizeStoredFile),
    };
    const reqSha = hashCommandPayload('register_engine_version', p);
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_register_engine_version($1, $2, $3::jsonb) AS res',
      [commandKey, reqSha, JSON.stringify(p)],
    );
    return cmdReturn(out, (o) => ({ engineVersionId: o.engine_version_id, label: p.label }));
  }

  async function registerApprovalsFile({
    dbToken,
    commandKey,
    storedFile,
    headerKind,
    rowCount,
    extendsSha256 = null,
    sharedRowCount = 0,
    addedRows = [],
  }) {
    const normFile = normalizeStoredFile(storedFile);
    const normRows = addedRows.map((r, idx) => normalizeApprovalRow(r, Number(sharedRowCount) + idx + 1));
    const reqSha = hashCommandPayload('register_approvals_file', {
      storedFile: normFile, headerKind, rowCount, extendsSha256, sharedRowCount, addedRows: normRows,
    });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_register_approvals_file($1, $2, $3::jsonb, $4, $5::integer, $6, $7::integer, $8::jsonb) AS res',
      [commandKey, reqSha, JSON.stringify(normFile), headerKind, Number(rowCount), extendsSha256, Number(sharedRowCount), JSON.stringify(normRows)],
    );
    return cmdReturn(out, (o) => ({ fileSha256: o.file_sha256, rowCount: Number(rowCount), alreadyRegistered: Boolean(o.already_registered) }));
  }

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

  async function getReviewDraft({ dbToken = null, runId, surface, attemptNo }) {
    const token = typeof dbToken === 'string' ? dbToken : '';
    try {
      return await withRequestTx(pool, token, async (tx) => {
        const res = await tx.query(
          `SELECT run_id, surface, attempt_no, born, checksum, rows_json, updated_at, expires_at
           FROM app_views.coherence_review_drafts
           WHERE run_id = $1::uuid AND surface = $2 AND attempt_no = $3
             AND expires_at > pg_catalog.clock_timestamp()`,
          [runId, surface, Number(attemptNo)],
        );
        if (res.rows.length === 0) return null;
        const row = res.rows[0];
        return {
          runId: row.run_id,
          surface: row.surface,
          attemptNo: Number(row.attempt_no),
          born: row.born,
          checksum: row.checksum,
          rows: row.rows_json,
          updatedAt: formatTimestampUtcUs(row.updated_at),
          expiresAt: formatTimestampUtcUs(row.expires_at),
        };
      }, { readOnly: true });
    } catch (err) {
      throw mapPgError(err);
    }
  }

  async function expireOldDrafts({ client = null, dbToken = null } = {}) {
    const out = await execSql(
      { client, dbToken, serializable: false },
      'SELECT app_cmd.coherence_expire_old_drafts() AS res',
      [],
    );
    return { deleted: Number(out.deleted ?? 0) };
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

  async function recordDecisionBaseline({
    dbToken,
    commandKey,
    payload = null,
    decisionCommitId = null,
    parentCommitId = null,
    commitKind = 'historical_baseline',
    headerContract = 'v2',
    imported = true,
    originalAt = null,
    decisions = [],
  }) {
    const bodyPayload = payload || {
      ...(decisionCommitId ? { decision_commit_id: decisionCommitId } : {}),
      ...(parentCommitId ? { parent_commit_id: parentCommitId } : {}),
      commit_kind: commitKind,
      header_contract: headerContract,
      imported: Boolean(imported),
      ...(originalAt ? { original_at: safeTimestampIso(originalAt) } : {}),
      decisions,
    };
    const origFallback = bodyPayload.original_at ?? null;
    const normPayload = {
      ...bodyPayload,
      ...(Array.isArray(bodyPayload?.decisions)
        ? { decisions: bodyPayload.decisions.map((d) => normalizeDecisionInput(d, { fallbackDecidedAt: origFallback })) }
        : {}),
    };
    const reqSha = hashCommandPayload('record_decision_baseline', normPayload);
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_record_decision_baseline($1, $2, $3::jsonb) AS res',
      [commandKey, reqSha, JSON.stringify(normPayload)],
    );
    return cmdReturn(out, (o) => ({
      decisionCommitId: o.decision_commit_id,
      addedDecisionCount: Number(o.added_count ?? 0),
      cumulativeDecisionCount: Number(o.cumulative_count ?? o.added_count ?? 0),
    }));
  }

  async function recordStatementBatch({
    dbToken,
    commandKey,
    payload = null,
    batchId = null,
    batchKind = null,
    statementDate = null,
    sourceFileName = null,
    sourceFile = null,
    reason = null,
    agencyLines = [],
    uplineLines = [],
  }) {
    let bodyPayload = payload;
    if (!bodyPayload) {
      if (!['historical_sent', 'method_correction'].includes(batchKind)) {
        throw new AppError('Standalone statement batchKind must be historical_sent or method_correction.', 400, 'INVALID_BATCH_KIND');
      }
      if (!isValidIsoDate(statementDate)) {
        throw new AppError('statementDate must be a valid ISO date.', 400, 'INVALID_DATE');
      }
      bodyPayload = {
        ...(batchId ? { batch_id: batchId } : {}),
        batch_kind: batchKind,
        statement_date: statementDate,
        source_file_name: sourceFileName,
        source_file: sourceFile ? normalizeStoredFile(sourceFile) : null,
        reason,
        agency_lines: agencyLines.map((l) => normalizeStatementLine(l, { isUpline: false })),
        upline_lines: uplineLines.map((l) => normalizeStatementLine(l, { isUpline: true })),
      };
    }
    const reqSha = hashCommandPayload('record_statement_batch', bodyPayload);
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_record_statement_batch($1, $2, $3::jsonb) AS res',
      [commandKey, reqSha, JSON.stringify(bodyPayload)],
    );
    return cmdReturn(out, (o) => ({
      batchId: o.batch_id,
      agencyLineCount: o.agency_line_count != null ? Number(o.agency_line_count) : undefined,
      uplineLineCount: o.upline_line_count != null ? Number(o.upline_line_count) : undefined,
    }));
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

  async function importStandaloneFiles({ dbToken, commandKey, payload = null, files = [], storedFiles = [] }) {
    const bodyPayload = payload || {
      files: files.map((f) => ({
        ...(f.id ? { id: f.id } : {}),
        area: f.area,
        rel_path: f.rel_path ?? f.relPath,
        artifact_kind: f.artifact_kind ?? f.artifactKind ?? 'data',
        store_kind: f.store_kind ?? f.storeKind ?? 'company_data',
        file_sha256: f.file_sha256 ?? f.fileSha256,
        original_at: f.original_at ?? f.originalAt ? safeTimestampIso(f.original_at ?? f.originalAt) : null,
        metadata: f.metadata ?? {},
      })),
      stored_files: storedFiles.map(normalizeStoredFile),
    };
    const reqSha = hashCommandPayload('import_standalone_files', bodyPayload);
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_import_standalone_files($1, $2, $3::jsonb) AS res',
      [commandKey, reqSha, JSON.stringify(bodyPayload)],
    );
    return cmdReturn(out, (o) => {
      const cnt = Number(o.imported ?? 0);
      return { importedCount: cnt, imported: cnt };
    });
  }

  async function importHistoricalRun({
    dbToken,
    commandKey,
    payload = null,
    run = null,
    inputVersion = {},
    inputEntries = [],
    approvalsFiles = [],
    decisionCommits = [],
    decisions = [],
    generatedOverlays = [],
    reviewQueueItems = [],
    stepAttempts = [],
    reviewSaves = [],
    storedFiles = [],
    extraImportedFiles = [],
    abandonment = null,
  }) {
    const bodyPayload = payload || {
      run: {
        ...(run.id ? { id: run.id } : {}),
        origin: run.origin,
        statement_date: run.statement_date ?? run.statementDate,
        folder_number: run.folder_number ?? run.folderNumber ?? 1,
        emit_mode: run.emit_mode ?? run.emitMode ?? 'coherence',
        emit_display: run.emit_display ?? run.emitDisplay ?? null,
        emit_keep: run.emit_keep ?? run.emitKeep ?? [],
        emit_no_manager: run.emit_no_manager ?? run.emitNoManager ?? [],
        prior_decision_commit_id: run.prior_decision_commit_id ?? run.priorDecisionCommitId ?? null,
        engine_version_id: run.engine_version_id ?? run.engineVersionId ?? null,
        rerun_reason: run.rerun_reason ?? run.rerunReason ?? null,
        source_folder: run.source_folder ?? run.sourceFolder,
      },
      input_version: {
        ...(inputVersion?.id ? { id: inputVersion.id } : {}),
        reason: inputVersion?.reason ?? null,
      },
      input_entries: inputEntries.map((e) => ({
        rel_path: e.rel_path ?? e.relPath,
        file_sha256: e.file_sha256 ?? e.fileSha256,
      })),
      approvals_files: approvalsFiles.map((af) => {
        const shared = Number(af.shared_row_count ?? af.sharedRowCount ?? 0);
        return {
          file_sha256: af.file_sha256 ?? af.fileSha256,
          header_kind: af.header_kind ?? af.headerKind,
          row_count: Number(af.row_count ?? af.rowCount),
          extends_sha256: af.extends_sha256 ?? af.extendsSha256 ?? null,
          shared_row_count: shared,
          added_rows: (af.added_rows ?? af.addedRows ?? []).map((r, idx) => normalizeApprovalRow(r, shared + idx + 1)),
        };
      }),
      decision_commits: decisionCommits.map((dc) => ({
        id: dc.id,
        parent_commit_id: dc.parent_commit_id ?? dc.parentCommitId ?? null,
        commit_kind: dc.commit_kind ?? dc.commitKind ?? 'historical_overlay',
        header_contract: dc.header_contract ?? dc.headerContract ?? 'v2',
        cumulative_decision_count: Number(dc.cumulative_decision_count ?? dc.cumulativeDecisionCount),
        original_at: dc.original_at ?? dc.originalAt ? safeTimestampIso(dc.original_at ?? dc.originalAt) : null,
      })),
      decisions: decisions.map((d) => normalizeDecisionInput(d, { fallbackDecidedAt: d.original_at ?? d.originalAt ?? null })),
      generated_overlays: generatedOverlays.map((g) => ({
        ...(g.id ? { id: g.id } : {}),
        decision_commit_id: g.decision_commit_id ?? g.decisionCommitId,
        purpose: g.purpose,
        attempt_event_id: g.attempt_event_id ?? g.attemptEventId ?? null,
        attempt_step: g.attempt_step ?? g.attemptStep ?? null,
        header_contract: g.header_contract ?? g.headerContract ?? 'v2',
        row_count: Number(g.row_count ?? g.rowCount),
        file_sha256: g.file_sha256 ?? g.fileSha256,
      })),
      review_queue_items: reviewQueueItems.map((q, idx) => ({
        attempt_event_id: q.attempt_event_id ?? q.attemptEventId ?? null,
        attempt_step: q.attempt_step ?? q.attemptStep ?? null,
        item_order: Number(q.item_order ?? q.itemOrder ?? (idx + 1)),
        surface: q.surface,
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
      step_attempts: stepAttempts.map((st) => ({
        ...(st.start_event_id || st.startEventId ? { start_event_id: st.start_event_id ?? st.startEventId } : {}),
        ...(st.finish_event_id || st.finishEventId ? { finish_event_id: st.finish_event_id ?? st.finishEventId } : {}),
        step: st.step,
        attempt_no: Number(st.attempt_no ?? st.attemptNo ?? 1),
        born: st.born ?? null,
        log_file_sha256: st.log_file_sha256 ?? st.logFileSha256 ?? null,
        census: st.census ?? {},
        started_at: st.started_at ?? st.startedAt ? safeTimestampIso(st.started_at ?? st.startedAt) : null,
        finished_at: st.finished_at ?? st.finishedAt ? safeTimestampIso(st.finished_at ?? st.finishedAt) : null,
        artifacts: (st.artifacts || []).map((a) => ({
          rel_path: a.rel_path ?? a.relPath,
          artifact_kind: a.artifact_kind ?? a.artifactKind,
          store_kind: a.store_kind ?? a.storeKind,
          file_sha256: a.file_sha256 ?? a.fileSha256,
        })),
      })),
      review_saves: reviewSaves.map((rs) => ({
        ...(rs.id ? { id: rs.id } : {}),
        surface: rs.surface,
        attempt_event_id: rs.attempt_event_id ?? rs.attemptEventId ?? null,
        approvals_file_sha256: rs.approvals_file_sha256 ?? rs.approvalsFileSha256 ?? null,
        decision_commit_id: rs.decision_commit_id ?? rs.decisionCommitId ?? null,
        original_at: rs.original_at ?? rs.originalAt ? safeTimestampIso(rs.original_at ?? rs.originalAt) : null,
      })),
      stored_files: storedFiles.map(normalizeStoredFile),
      extra_imported_files: extraImportedFiles.map((f) => ({
        ...(f.id ? { id: f.id } : {}),
        area: f.area ?? 'other',
        rel_path: f.rel_path ?? f.relPath,
        artifact_kind: f.artifact_kind ?? f.artifactKind ?? 'data',
        store_kind: f.store_kind ?? f.storeKind ?? 'company_data',
        file_sha256: f.file_sha256 ?? f.fileSha256,
        original_at: f.original_at ?? f.originalAt ? safeTimestampIso(f.original_at ?? f.originalAt) : null,
        metadata: f.metadata ?? {},
      })),
      abandonment: abandonment
        ? {
          ...(abandonment.id ? { id: abandonment.id } : {}),
          typed_phrase: abandonment.typed_phrase ?? abandonment.typedPhrase,
          reason: abandonment.reason,
        }
        : null,
    };
    const reqSha = hashCommandPayload('import_historical_run', bodyPayload);
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_import_historical_run($1, $2, $3::jsonb) AS res',
      [commandKey, reqSha, JSON.stringify(bodyPayload)],
    );
    return cmdReturn(out, (o) => ({ runId: o.run_id, alreadyImported: Boolean(o.already_imported) }));
  }

  async function recordGeneratedOverlay({
    dbToken,
    commandKey,
    decisionCommitId,
    runId,
    purpose,
    headerContract = 'v2',
    rowCount,
    storedFile,
    attemptEventId = null,
    overlayId = null,
  }) {
    const normFile = normalizeStoredFile(storedFile);
    const reqSha = hashCommandPayload('record_generated_overlay', {
      decisionCommitId, runId, purpose, headerContract, rowCount: Number(rowCount), storedFile: normFile, attemptEventId,
    });
    const out = await execSql(
      { dbToken },
      'SELECT app_cmd.coherence_record_generated_overlay($1, $2, $3::uuid, $4::uuid, $5, $6, $7::integer, $8::jsonb, $9::uuid, $10::uuid) AS res',
      [commandKey, reqSha, decisionCommitId, runId, purpose, headerContract, Number(rowCount), JSON.stringify(normFile), attemptEventId, overlayId],
    );
    return cmdReturn(out, (o) => ({ overlayId: o.overlay_id, decisionCommitId, fileSha256: normFile?.sha256 }));
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

  // Worker-only commands (executed strictly via platform_worker with signed workerToken).
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
    initCompany,
    registerStoredFiles,
    registerEngineVersion,
    registerApprovalsFile,
    recordDecisionBaseline,
    publishInputVersion,
    includeStagingFile,
    launchRun,
    startStepAttempt,
    finishStepAttempt,
    failStepAttempt,
    cancelStepAttempt,
    interruptStepAttempt,
    requestCancel,
    requestRetry,
    submitReview,
    acceptReviewSubmission,
    rejectReviewSubmission,
    saveReviewDecisions,
    recordGeneratedOverlay,
    saveReviewDraft,
    getReviewDraft,
    expireOldDrafts,
    confirmEmit,
    carrySent,
    carryApprovals,
    carryDecisions,
    recordStatementBatch,
    materializeEmit,
    abandonRun,
    importHistoricalRun,
    importStandaloneFiles,
    recordCheck,
    authorizeCheckRun,
  };
}
