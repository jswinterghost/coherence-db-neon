// Reconciler: marks open attempts left behind by dead workers as interrupted before any new work runs,
// and deletes expired review drafts.
import { AppError } from '../util/redact.mjs';

export async function findOpenAttempts(db) {
  const res = await db.query(
    `SELECT s.id AS start_event_id, s.run_id, s.step, s.attempt_no, s.slot_backend_pid, s.slot_backend_start
     FROM coherence.step_attempt_events s
     JOIN coherence.runs r ON r.id = s.run_id
     WHERE r.origin NOT IN ('mac_import', 'company_import')
       AND s.event_kind = 'started'
       AND NOT EXISTS (
         SELECT 1 FROM coherence.step_attempt_events e
         WHERE e.run_id = s.run_id
           AND e.step = s.step
           AND e.attempt_no = s.attempt_no
           AND e.event_kind IN ('finished', 'failed', 'interrupted', 'cancelled')
       )
     ORDER BY s.journal_seq ASC`,
  );
  return res.rows.map((r) => ({
    startEventId: r.start_event_id,
    runId: r.run_id,
    step: r.step,
    attemptNo: Number(r.attempt_no),
    slotBackendPid: r.slot_backend_pid,
    slotBackendStart: r.slot_backend_start,
  }));
}

/**
 * Reconciles dead open attempts when the running slot is free or held by a replacement worker;
 * PostgreSQL refuses interruption while the original starter still holds the slot.
 */
export async function reconcileInterruptedAttempts({
  pool,
  slot = null,
  commands,
  workerToken,
}) {
  if (typeof workerToken !== 'string' || !workerToken.trim()) {
    throw new AppError('Reconciler requires a signed workerToken.', 400, 'MISSING_WORKER_TOKEN');
  }
  const db = slot ? slot.client : pool;
  const open = await findOpenAttempts(db);
  const interrupted = [];

  for (const item of open) {
    const record = async (client) => commands.interruptStepAttempt({
      client,
      dbToken: workerToken,
      commandKey: `reconcile-interrupted:${item.startEventId}`,
      runId: item.runId,
      step: item.step,
      attemptNo: item.attemptNo,
      errorSummary: 'The worker connection ended before this step finished; nothing was retried automatically.',
    });

    const res = slot
      ? await slot.runExclusive((client) => record(client))
      : await record(null);

    interrupted.push({
      runId: item.runId,
      step: item.step,
      attemptNo: item.attemptNo,
      journalSeq: res.journalSeq,
    });
  }

  const expire = (client) => commands.expireOldDrafts({
    client,
    dbToken: workerToken,
  });
  if (slot) {
    await slot.runExclusive((client) => expire(client));
  } else {
    await expire(null);
  }

  return { interrupted };
}
