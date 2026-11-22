// Reconciler (R10.1): finds open step attempts left behind by dead workers and marks them interrupted
// BEFORE anything else runs. Also cleans up expired operational review drafts (R6.16).

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
 * Reconciles every dead open attempt. Can be called either holding the slot (on a new worker connection)
 * or without the slot when the slot is free; PostgreSQL's trigger refuses interruption if the original
 * owning worker still holds the slot (R8, R10.1).
 */
export async function reconcileInterruptedAttempts({
  pool,
  slot = null,
  commands,
  workerActor,
}) {
  const db = slot ? slot.client : pool;
  const open = await findOpenAttempts(db);
  const interrupted = [];

  for (const item of open) {
    const record = async (client) => commands.interruptStepAttempt({
      client,
      actor: workerActor,
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

  // Operational cleanup of expired 30-day review drafts (R6.16)
  if (!slot) {
    await commands.expireOldDrafts();
  } else {
    await slot.runExclusive((client) => client.query('DELETE FROM coherence.review_drafts WHERE expires_at <= pg_catalog.clock_timestamp()'));
  }

  return { interrupted };
}
