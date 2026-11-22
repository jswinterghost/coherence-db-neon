// Coherence engine worker: holds the company running slot on a dedicated PostgreSQL connection,
// reconciles dead attempts first, checks queued review submissions, then executes queued steps.
import { cp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AppError, createSafeLogger, sanitizeErrorMessage } from '../util/redact.mjs';
import { parseCsvObjects } from './emit-materializer.mjs';
import { buildAttemptWorkspace, listFilesRecursive, verifyFrozenInputUnchanged } from './folder-builder.mjs';
import { buildStepArgs, DEFAULT_STEP_TIMEOUT_MS, runCoherenceProcess, runOverlayCheck } from './engine-runner.mjs';
import { reconcileInterruptedAttempts } from './reconciler.mjs';
import { acquireRunningSlot } from './slot.mjs';

const STEP_ARTIFACT_FILTERS = {
  assign: (rel) => rel === 'run.json' || rel.startsWith('working/'),
  attribute: (rel) => rel === 'run.json' || rel.startsWith('working/'),
  bible: (rel) => rel === 'run.json' || rel === 'bible.csv' || rel === 'bible.html' || rel === 'bible.json',
  adjust: (rel) => rel === 'run.json' || rel === 'adjust.csv' || rel === 'adjust.html' || rel === 'adjust.json',
  emit: (rel) => rel === 'run.json' || rel === 'company_manifest.json' || rel.startsWith('emits/'),
};

export function createEngineWorker({
  pool,
  pgConfig,
  clientFactory = null,
  companySlug,
  stores,
  commands,
  workerActor = { id: `coherence-worker:${companySlug}`, kind: 'worker' },
  materializeEngine = undefined,
  rebuildWorkingOnDemand = null,
  tempBaseDir = tmpdir(),
  pollIntervalMs = 1500,
  stepTimeoutMs = DEFAULT_STEP_TIMEOUT_MS,
  cancelPollMs = 500,
  livenessIntervalMs = 2000,
  livenessTimeoutMs = 3000,
  onLivenessQuery = null,
  onSlotLost = null,
  onAfterStart = null, // Optional lifecycle callback invoked immediately after step start is recorded.
  onBeforeFinish = null, // Optional lifecycle callback invoked after artifact promotion and before recording finish.
  logger = createSafeLogger(),
}) {
  let running = false;
  let loopPromise = null;
  let activeSlot = null;
  let stopRequested = false;

  async function defaultRebuildWorking({ outerDir, workspaceDir, runDir, run, stepsToRestore, engineRuntime, signal }) {
    const wsInput = join(workspaceDir, 'input');
    await rm(wsInput, { recursive: true, force: true }).catch(() => {});
    await cp(join(runDir, 'input'), wsInput, { recursive: true });
    try {
      const rebuildSteps = stepsToRestore.includes('attribute') ? ['assign', 'attribute'] : ['assign'];
      for (const rebuildStep of rebuildSteps) {
        const proc = await runCoherenceProcess({
          pythonPath: engineRuntime.pythonPath,
          args: buildStepArgs({ step: rebuildStep, statementDate: run.statement_date }),
          workspaceDir,
          logPath: join(outerDir, `rebuild-${rebuildStep}.log`),
          timeoutMs: stepTimeoutMs,
          slotSignal: signal,
          logger,
        });
        if (proc.outcome !== 'exited' || proc.exitCode !== 0) {
          throw new AppError(
            `On-demand working rebuild step ${rebuildStep} failed (${proc.outcome}, exit ${proc.exitCode}).`,
            502,
            'WORKING_REBUILD_FAILED',
          );
        }
      }
    } finally {
      await rm(wsInput, { recursive: true, force: true }).catch(() => {});
    }
  }

  const effectiveRebuildWorking = rebuildWorkingOnDemand || defaultRebuildWorking;

  async function processPendingReview(slot) {
    const subRes = await slot.runExclusive((client) => client.query(
      `SELECT rs.*, r.id AS r_id, pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date,
              r.origin, r.input_version_id, r.prior_approvals_sha256, r.engine_version_id,
              r.emit_mode, r.emit_display, r.emit_keep, r.emit_no_manager, r.replays_run_id
       FROM coherence.review_submissions rs
       JOIN coherence.runs r ON r.id = rs.run_id
       WHERE rs.status = 'pending'
       ORDER BY rs.created_at ASC
       LIMIT 1`,
    ));
    if (subRes.rows.length === 0) return null;
    const sub = subRes.rows[0];
    const run = {
      id: sub.r_id,
      statement_date: sub.statement_date,
      origin: sub.origin,
      input_version_id: sub.input_version_id,
      prior_approvals_sha256: sub.prior_approvals_sha256,
      engine_version_id: sub.engine_version_id,
      emit_mode: sub.emit_mode,
      emit_display: sub.emit_display,
      emit_keep: sub.emit_keep,
      emit_no_manager: sub.emit_no_manager,
      replays_run_id: sub.replays_run_id,
    };

    let workspace = null;
    try {
      const csvBytes = await stores.dataStore.readStagedReview({
        submissionId: sub.id,
        sha256: sub.staged_sha256,
      });
      slot.assertHeld();

      workspace = await buildAttemptWorkspace({
        db: pool,
        run,
        step: sub.surface === 'adjust' ? 'review_adjust' : 'review_bible',
        stores,
        tempBaseDir,
        materializeEngine,
        rebuildWorkingOnDemand: effectiveRebuildWorking,
        signal: slot.signal,
      });
      slot.assertHeld();

      const candidatePath = join(workspace.outerDir, 'candidate-overlay.csv');
      const outJsonPath = join(workspace.outerDir, 'overlay-check-result.json');
      await writeFile(candidatePath, csvBytes, { mode: 0o600 });

      const checked = await runOverlayCheck({
        pythonPath: workspace.engineRuntime.pythonPath,
        overlayCheckPath: workspace.engineRuntime.overlayCheckPath,
        workspaceDir: workspace.workspaceDir,
        statementDate: run.statement_date,
        candidatePath,
        surface: sub.surface,
        outJsonPath,
        slotSignal: slot.signal,
        logger,
      });

      if (slot.isLost()) return { action: 'slot_lost', submissionId: sub.id };

      if (!checked.ok) {
        // Rejected review submissions are finalized without promoting bytes so they never stall the worker queue.
        const rejected = await slot.runExclusive((client) => commands.rejectReviewSubmission({
          client,
          actor: workerActor,
          submissionId: sub.id,
          status: 'rejected',
          reason: checked.error,
        }));
        logger.info('review_submission_rejected', { submissionId: sub.id, runId: run.id, surface: sub.surface });
        return { action: 'review_rejected', ...rejected };
      }

      let extendsSha256 = run.prior_approvals_sha256 || null;
      if (sub.surface === 'adjust') {
        const bibleSaveRes = await slot.runExclusive((client) => client.query(
          `SELECT approvals_file_sha256 FROM coherence.review_saves
           WHERE run_id = $1::uuid AND surface = 'bible'
             AND attempt_event_id = coherence.current_finished_attempt($1::uuid, 'bible')
           ORDER BY journal_seq DESC LIMIT 1`,
          [run.id],
        ));
        if (bibleSaveRes.rows.length > 0) extendsSha256 = bibleSaveRes.rows[0].approvals_file_sha256;
      }

      // Promote bytes to object storage only after Coherence's overlay check passes.
      slot.assertHeld();
      const storedFile = await stores.dataStore.promoteBytes(csvBytes, {
        relPath: 'overlay.csv',
        checksPassed: true,
        signal: slot.signal,
      });
      if (slot.isLost()) return { action: 'slot_lost', submissionId: sub.id };

      // If content is identical to extendsSha256, it reuses the existing approvals_file (no self-extension).
      const finalExtends = storedFile.sha256 === extendsSha256 ? null : extendsSha256;
      const accepted = await slot.runExclusive((client) => commands.acceptReviewSubmission({
        client,
        actor: workerActor,
        commandKey: `save-review:${sub.command_key}`,
        submissionId: sub.id,
        storedFile,
        headerKind: checked.result.header_kind,
        rowCount: checked.result.rows,
        extendsSha256: finalExtends,
        sharedRowCount: checked.result.shared,
        addedRows: checked.result.new_rows,
      }));
      logger.info('review_submission_accepted', { submissionId: sub.id, runId: run.id, surface: sub.surface, journalSeq: accepted.journalSeq });
      return { action: 'review_accepted', ...accepted };
    } catch (err) {
      if (slot.isLost()) return { action: 'slot_lost', submissionId: sub.id };
      // Finalize unexpected review-check errors as failed so a bad submission cannot wedge the worker.
      const failed = await slot.runExclusive((client) => commands.rejectReviewSubmission({
        client,
        actor: workerActor,
        submissionId: sub.id,
        status: err?.status === 409 ? 'rejected' : 'failed',
        reason: sanitizeErrorMessage(err, 'Review check failed.'),
      })).catch(() => null);
      logger.warn('review_submission_failed', { submissionId: sub.id, runId: run.id, reason: sanitizeErrorMessage(err) });
      return { action: 'review_failed', submissionId: sub.id, result: failed };
    } finally {
      if (workspace) await workspace.cleanup();
    }
  }

  async function processNextStepRequest(slot) {
    const reqRes = await slot.runExclusive((client) => client.query(
      `SELECT sr.id AS req_id, sr.run_id, sr.step, sr.reason, sr.emit_confirmation_id,
              pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date,
              r.origin, r.input_version_id, r.prior_approvals_sha256, r.prior_decision_commit_id,
              r.engine_version_id, r.emit_mode, r.emit_display, r.emit_keep, r.emit_no_manager, r.replays_run_id
       FROM coherence.step_requests sr
       JOIN coherence.runs r ON r.id = sr.run_id
       WHERE NOT EXISTS (SELECT 1 FROM coherence.abandonments a WHERE a.run_id = sr.run_id)
         AND NOT EXISTS (SELECT 1 FROM coherence.step_attempt_events s WHERE s.step_request_id = sr.id)
       ORDER BY sr.journal_seq ASC
       LIMIT 1`,
    ));
    if (reqRes.rows.length === 0) return null;
    const req = reqRes.rows[0];
    const run = {
      id: req.run_id,
      statement_date: req.statement_date,
      origin: req.origin,
      input_version_id: req.input_version_id,
      prior_approvals_sha256: req.prior_approvals_sha256,
      prior_decision_commit_id: req.prior_decision_commit_id,
      engine_version_id: req.engine_version_id,
      emit_mode: req.emit_mode,
      emit_display: req.emit_display,
      emit_keep: req.emit_keep,
      emit_no_manager: req.emit_no_manager,
      replays_run_id: req.replays_run_id,
    };

    const started = await slot.runExclusive((client) => commands.startStepAttempt({
      client,
      actor: workerActor,
      commandKey: `start-attempt:${req.req_id}`,
      runId: run.id,
      step: req.step,
      stepRequestId: req.req_id,
    }));
    const attemptNo = started.result.attemptNo;
    logger.info('step_started', { runId: run.id, step: req.step, attemptNo });

    if (typeof onAfterStart === 'function') {
      await onAfterStart({ slot, run, step: req.step, attemptNo });
      if (slot.isLost()) return { action: 'slot_lost', runId: run.id, step: req.step, attemptNo };
    }

    let workspace = null;
    try {
      workspace = await buildAttemptWorkspace({
        db: pool,
        run,
        step: req.step,
        stores,
        tempBaseDir,
        materializeEngine,
        rebuildWorkingOnDemand: effectiveRebuildWorking,
        signal: slot.signal,
      });
      slot.assertHeld();

      const logPath = join(workspace.outerDir, `${req.step}-attempt-${attemptNo}.log`);
      const args = buildStepArgs({
        step: req.step,
        statementDate: run.statement_date,
        emitMode: run.emit_mode,
        emitDisplay: run.emit_display,
        emitKeep: run.emit_keep,
        emitNoManager: run.emit_no_manager,
        companyEmitPath: workspace.engineRuntime.companyEmitPath,
        engineKind: workspace.engineRuntime.engineKind,
      });

      const checkCancelled = async () => {
        const res = await pool.query(
          `SELECT id FROM coherence.cancel_requests
           WHERE run_id = $1::uuid AND step = $2 AND attempt_no = $3
           ORDER BY journal_seq ASC LIMIT 1`,
          [run.id, req.step, attemptNo],
        );
        return res.rows[0] || null;
      };

      const proc = await runCoherenceProcess({
        pythonPath: workspace.engineRuntime.pythonPath,
        args,
        workspaceDir: workspace.workspaceDir,
        logPath,
        timeoutMs: stepTimeoutMs,
        slotSignal: slot.signal,
        checkCancelled,
        cancelPollMs,
        logger,
      });

      // After slot loss, exit without recording an end event so the reconciler marks the attempt interrupted.
      if (slot.isLost() || proc.outcome === 'slot_lost') {
        logger.warn('step_aborted_slot_lost', { runId: run.id, step: req.step, attemptNo });
        return { action: 'slot_lost', runId: run.id, step: req.step, attemptNo };
      }

      const logStored = await stores.dataStore.promoteBytes(proc.logBytes, {
        relPath: `logs/${req.step}-${attemptNo}.log`,
        checksPassed: true,
        contentType: 'text/plain; charset=utf-8',
        signal: slot.signal,
      });

      if (slot.isLost()) return { action: 'slot_lost', runId: run.id, step: req.step, attemptNo };

      if (proc.outcome === 'cancelled') {
        const res = await slot.runExclusive((client) => commands.cancelStepAttempt({
          client,
          actor: workerActor,
          commandKey: `cancel-attempt:${run.id}:${req.step}:${attemptNo}`,
          runId: run.id,
          step: req.step,
          attemptNo,
          cancelRequestId: proc.cancelRequestId,
          logFile: logStored,
          errorSummary: 'Cancelled by user request.',
        }));
        return { action: 'step_cancelled', runId: run.id, step: req.step, attemptNo, journalSeq: res.journalSeq };
      }

      if (proc.outcome === 'timed_out' || proc.outcome === 'cancel_poll_failed') {
        const summary = proc.outcome === 'timed_out'
          ? `Step exceeded time limit (${Math.round(stepTimeoutMs / 1000)} s) and its process group was stopped.`
          : 'Cancel status polling failed repeatedly; process group stopped.';
        const res = await slot.runExclusive((client) => commands.failStepAttempt({
          client,
          actor: workerActor,
          commandKey: `fail-attempt:${run.id}:${req.step}:${attemptNo}`,
          runId: run.id,
          step: req.step,
          attemptNo,
          logFile: logStored,
          errorSummary: summary,
        }));
        return {
          action: proc.outcome === 'timed_out' ? 'step_timed_out' : 'step_failed',
          runId: run.id,
          step: req.step,
          attemptNo,
          journalSeq: res.journalSeq,
        };
      }

      const runJsonPath = join(workspace.runDir, 'run.json');
      let runJson = null;
      try { runJson = JSON.parse(await readFile(runJsonPath, 'utf8')); } catch { runJson = null; }

      if (proc.exitCode !== 0 || !runJson?.steps?.[req.step]) {
        const reason = proc.tailLines.slice(-5).join(' | ') || `Step exited with code ${proc.exitCode} without recording completion in run.json.`;
        const res = await slot.runExclusive((client) => commands.failStepAttempt({
          client,
          actor: workerActor,
          commandKey: `fail-attempt:${run.id}:${req.step}:${attemptNo}`,
          runId: run.id,
          step: req.step,
          attemptNo,
          logFile: logStored,
          errorSummary: reason,
        }));
        return { action: 'step_failed', runId: run.id, step: req.step, attemptNo, journalSeq: res.journalSeq };
      }

      await verifyFrozenInputUnchanged(join(workspace.runDir, 'input'), workspace.expectedInputHashes);

      const filter = STEP_ARTIFACT_FILTERS[req.step];
      const allRunFiles = await listFilesRecursive(workspace.runDir, { skipTopDirs: new Set(['input']) });
      const stepRelPaths = allRunFiles.filter(filter);

      const artifacts = [];
      const storedFiles = [];
      const artifactBytesByPath = new Map();
      for (const relPath of stepRelPaths) {
        slot.assertHeld();
        const bytes = await readFile(join(workspace.runDir, ...relPath.split('/')));
        const promoted = await stores.promoteArtifact(relPath, bytes, { checksPassed: true, signal: slot.signal });
        storedFiles.push(promoted);
        artifactBytesByPath.set(relPath, { bytes, promoted });
        artifacts.push({
          relPath,
          artifactKind: promoted.artifactKind,
          storeKind: promoted.storeKind,
          fileSha256: promoted.sha256,
        });
      }

      const generatedOverlays = [];
      for (const gen of workspace.generatedOverlays || []) {
        if (!gen.decisionCommitId) continue;
        slot.assertHeld();
        const promoted = await stores.dataStore.promoteBytes(gen.bytes, {
          relPath: 'overlay.csv',
          checksPassed: true,
          signal: slot.signal,
        });
        storedFiles.push(promoted);
        generatedOverlays.push({
          decisionCommitId: gen.decisionCommitId,
          purpose: gen.purpose,
          headerContract: gen.headerContract,
          rowCount: gen.rowCount,
          fileSha256: promoted.sha256,
        });
      }

      const queueItems = [];
      if (req.step === 'bible' || req.step === 'adjust') {
        const csvEntry = artifactBytesByPath.get(`${req.step}.csv`);
        const jsonEntry = artifactBytesByPath.get(`${req.step}.json`);
        let reconfirmMap = {};
        if (jsonEntry) {
          try {
            const parsedCfg = JSON.parse(jsonEntry.bytes.toString('utf8'));
            if (parsedCfg?.reconfirm && typeof parsedCfg.reconfirm === 'object') {
              reconfirmMap = parsedCfg.reconfirm;
            }
          } catch {
            reconfirmMap = {};
          }
        }
        if (csvEntry) {
          const parsedQueue = parseCsvObjects(csvEntry.bytes, `${req.step}.csv`);
          parsedQueue.rows.forEach((row, idx) => {
            if (!row.record_id) return;
            queueItems.push({
              itemOrder: idx + 1,
              surface: req.step,
              recordId: row.record_id,
              caseKind: row.case || row.case_kind || null,
              subtype: row.subtype || null,
              entity: row.entity || null,
              npn: row.npn || null,
              amount: row.amount || null,
              entityFrom: row.entity_from || null,
              npnFrom: row.npn_from || null,
              needsReconfirm: Boolean(reconfirmMap[row.record_id]),
            });
          });
        }
      }

      let emitMaterializationInput = null;
      if (req.step === 'emit') {
        const stamp = run.statement_date.replaceAll('-', '');
        const bobEntry = artifactBytesByPath.get('emits/canonical_bob.csv');
        const ledEntry = artifactBytesByPath.get('emits/coherent_ledger.csv');
        const stmtRel = `emits/statements_${stamp}.csv`;
        const stmtEntry = artifactBytesByPath.get(stmtRel);
        if (bobEntry && ledEntry && stmtEntry) {
          const metaEntry = artifactBytesByPath.get('emits/emit_metadata.json')
            || artifactBytesByPath.get('emits/policy_status_meta.json');
          const workingTxCsv = await readFile(join(workspace.runDir, 'working', 'tx.csv'), 'utf8').catch(() => null);
          emitMaterializationInput = {
            statementDate: run.statement_date,
            canonicalBobCsv: bobEntry.bytes.toString('utf8'),
            coherentLedgerCsv: ledEntry.bytes.toString('utf8'),
            statementsCsv: stmtEntry.bytes.toString('utf8'),
            emitMetadataJson: metaEntry ? metaEntry.bytes.toString('utf8') : null,
            workingTxCsv,
            statementsFileName: `statements_${stamp}.csv`,
            statementsFileSha256: stmtEntry.promoted.sha256,
          };
        }
      }

      if (typeof onBeforeFinish === 'function') {
        await onBeforeFinish({ slot, run, step: req.step, attemptNo, artifacts });
      }
      if (slot.isLost()) return { action: 'slot_lost', runId: run.id, step: req.step, attemptNo };

      const census = {
        ...runJson.steps[req.step],
        durationMs: proc.durationMs,
        exitCode: proc.exitCode,
      };
      const born = req.step === 'assign' ? (runJson.born || null) : null;

      const finished = await slot.runExclusive((client) => commands.finishStepAttempt({
        client,
        actor: workerActor,
        commandKey: `finish-attempt:${run.id}:${req.step}:${attemptNo}`,
        runId: run.id,
        step: req.step,
        attemptNo,
        census,
        born,
        logFile: logStored,
        artifacts,
        storedFiles,
        queueItems,
        generatedOverlays,
        emitMaterializationInput,
      }));
      logger.info('step_finished', { runId: run.id, step: req.step, attemptNo, artifacts: artifacts.length, journalSeq: finished.journalSeq });
      return { action: 'step_finished', runId: run.id, step: req.step, attemptNo, journalSeq: finished.journalSeq, nextStep: finished.result.nextStep };
    } catch (err) {
      if (slot.isLost()) return { action: 'slot_lost', runId: run.id, step: req.step, attemptNo };
      const failed = await slot.runExclusive((client) => commands.failStepAttempt({
        client,
        actor: workerActor,
        commandKey: `fail-attempt:${run.id}:${req.step}:${attemptNo}`,
        runId: run.id,
        step: req.step,
        attemptNo,
        errorSummary: sanitizeErrorMessage(err, 'Step execution failed.'),
      })).catch(() => null);
      logger.error('step_error', { runId: run.id, step: req.step, attemptNo, reason: sanitizeErrorMessage(err) });
      return { action: 'step_failed', runId: run.id, step: req.step, attemptNo, result: failed };
    } finally {
      if (workspace) await workspace.cleanup();
    }
  }

  async function runOnce() {
    const slot = await acquireRunningSlot({
      pgConfig,
      clientFactory: clientFactory || undefined,
      livenessIntervalMs,
      livenessTimeoutMs,
      onLivenessQuery,
      onSlotLost,
      logger,
    });
    if (!slot) return { action: 'slot_busy' };
    activeSlot = slot;
    try {
      const rec = await reconcileInterruptedAttempts({ pool, slot, commands, workerActor });
      if (slot.isLost()) return { action: 'slot_lost', reconciled: rec.interrupted.length };

      const rev = await processPendingReview(slot);
      if (rev) return { ...rev, reconciled: rec.interrupted.length };
      if (slot.isLost()) return { action: 'slot_lost', reconciled: rec.interrupted.length };

      const stepRes = await processNextStepRequest(slot);
      if (stepRes) return { ...stepRes, reconciled: rec.interrupted.length };

      return { action: 'idle', reconciled: rec.interrupted.length };
    } finally {
      activeSlot = null;
      await slot.release();
    }
  }

  function start() {
    if (running) return;
    running = true;
    stopRequested = false;
    loopPromise = (async () => {
      while (!stopRequested) {
        try {
          const outcome = await runOnce();
          if (outcome.action !== 'idle' && outcome.action !== 'slot_busy' && !stopRequested) {
            continue; // immediately pick up next queued item (e.g. assign -> attribute -> bible)
          }
        } catch (err) {
          logger.error('worker_cycle_error', { reason: sanitizeErrorMessage(err) });
        }
        if (!stopRequested) {
          await new Promise((resolvePromise) => {
            const t = setTimeout(resolvePromise, pollIntervalMs);
            if (typeof t.unref === 'function') t.unref();
          });
        }
      }
      running = false;
    })();
  }

  async function stop() {
    stopRequested = true;
    if (activeSlot) {
      activeSlot.abort('Worker shutdown requested');
      await activeSlot.release().catch(() => {});
    }
    if (loopPromise) {
      await loopPromise;
      loopPromise = null;
    }
    running = false;
  }

  return {
    runOnce,
    start,
    stop,
    isRunning: () => running,
  };
}
