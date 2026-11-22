// Company running-slot holder backed by a dedicated PostgreSQL session advisory lock;
// liveness checks run strictly between transactions with a bounded timeout.
import { createClient } from '../db/pg-client.mjs';
import { AppError, createSafeLogger, sanitizeErrorMessage } from '../util/redact.mjs';

export async function acquireRunningSlot({
  pgConfig,
  clientFactory = () => createClient(pgConfig),
  livenessIntervalMs = 2000,
  livenessTimeoutMs = 3000,
  onSlotLost = null,
  onLivenessQuery = null,
  logger = createSafeLogger(),
} = {}) {
  const client = await clientFactory();
  const controller = new AbortController();
  let lost = false;
  let released = false;
  let inTransaction = false;
  let checking = false;
  let timer = null;

  const markLost = (reason) => {
    if (lost) return;
    lost = true;
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    const err = reason instanceof Error ? reason : new Error(String(reason || 'Company running slot was lost.'));
    if (!controller.signal.aborted) controller.abort(err);
    if (typeof onSlotLost === 'function') {
      try {
        onSlotLost(err);
      } catch (listenerErr) {
        if (logger && typeof logger.error === 'function') {
          logger.error('slot_lost_listener_error', { reason: sanitizeErrorMessage(listenerErr) });
        }
      }
    }
  };

  client.on('error', (err) => markLost(err));
  client.on('end', () => { if (!released) markLost(new Error('Slot PostgreSQL connection ended unexpectedly.')); });

  const lockRes = await client.query(
    'SELECT pg_catalog.pg_try_advisory_lock(coherence.slot_class_id(), coherence.slot_obj_id()) AS acquired, pg_catalog.pg_backend_pid() AS pid',
  );
  if (!lockRes.rows[0]?.acquired) {
    released = true;
    await client.end().catch(() => {});
    return null;
  }
  const backendPid = Number(lockRes.rows[0].pid);

  async function checkLivenessOnce() {
    // Never run a liveness query while a transaction is open on the same connection.
    if (lost || released || inTransaction || checking) return !lost;
    checking = true;
    let timeoutHandle = null;
    try {
      if (typeof onLivenessQuery === 'function') onLivenessQuery({ inTransaction });
      const res = await Promise.race([
        client.query('SELECT coherence.this_connection_holds_slot() AS held'),
        new Promise((_, reject) => {
          timeoutHandle = setTimeout(() => reject(new Error('Slot liveness check timed out.')), livenessTimeoutMs);
        }),
      ]);
      if (!res?.rows?.[0]?.held) {
        markLost(new Error('PostgreSQL session no longer holds the company running slot.'));
        return false;
      }
      return true;
    } catch (err) {
      markLost(err);
      return false;
    } finally {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      checking = false;
    }
  }

  if (livenessIntervalMs > 0) {
    timer = setInterval(() => { void checkLivenessOnce(); }, livenessIntervalMs);
    if (typeof timer.unref === 'function') timer.unref();
  }

  /**
   * Runs a transactional callback on the slot connection while pausing liveness queries
   * so no probe runs mid-transaction.
   */
  async function runExclusive(fn) {
    if (lost || released) throw new AppError('Company running slot was lost.', 409, 'SLOT_LOST');
    // Wait for any in-flight liveness query to complete before opening a transaction on the same connection.
    while (checking) {
      await new Promise((r) => setTimeout(r, 10));
      if (lost || released) throw new AppError('Company running slot was lost.', 409, 'SLOT_LOST');
    }
    inTransaction = true;
    try {
      return await fn(client);
    } finally {
      inTransaction = false;
    }
  }

  async function release() {
    if (released) return;
    released = true;
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    if (!lost) {
      try {
        await client.query('SELECT pg_catalog.pg_advisory_unlock(coherence.slot_class_id(), coherence.slot_obj_id())');
      } catch { /* Session advisory locks release automatically if the connection already closed. */ }
    }
    await client.end().catch(() => {});
  }

  return {
    client,
    backendPid,
    signal: controller.signal,
    isLost: () => lost,
    isInTransaction: () => inTransaction,
    assertHeld() {
      if (lost || released) throw new AppError('Company running slot was lost.', 409, 'SLOT_LOST');
    },
    abort(reason = 'Worker stopping') {
      markLost(new Error(reason));
    },
    checkLivenessOnce,
    runExclusive,
    release,
  };
}
