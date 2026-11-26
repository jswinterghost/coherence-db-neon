// Company setup, artifact/engine registration, and historical import commands,
// executed strictly through app_cmd.coherence_*.
import { isValidIsoDate } from '../util/csv.mjs';
import { AppError } from '../util/redact.mjs';
import {
  cmdReturn,
  createCommandTransport,
  hashCommandPayload,
  normalizeApprovalRow,
  normalizeDecisionInput,
  normalizeStatementLine,
  normalizeStoredFile,
  safeTimestampIso,
} from './cmd-transport.mjs';

export function createImportCommands({ pool = null, transport = null }) {
  const { execSql } = transport || createCommandTransport({ pool });

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

  return {
    initCompany,
    registerStoredFiles,
    registerEngineVersion,
    registerApprovalsFile,
    recordDecisionBaseline,
    recordStatementBatch,
    importStandaloneFiles,
    importHistoricalRun,
    recordGeneratedOverlay,
  };
}
