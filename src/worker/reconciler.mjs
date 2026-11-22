// Reconciler: marks open attempts left behind by dead workers as interrupted before any new work runs,
// and deletes expired review drafts.

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

  if (!slot) {
    await commands.expireOldDrafts();
  } else {
    await slot.runExclusive((client) => client.query('DELETE FROM coherence.review_drafts WHERE expires_at <= pg_catalog.clock_timestamp()'));
  }

  return { interrupted };
}
