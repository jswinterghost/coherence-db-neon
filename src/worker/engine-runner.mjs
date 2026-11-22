// Coherence step process runner: spawns each step in its own process group with pinned UTF-8
// and America/New_York environment, stopping the whole process group on cancel, timeout, or slot loss.
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { redactPhi, sanitizeErrorMessage } from '../util/redact.mjs';

export const STEP_MODULES = Object.freeze({
  assign: 'coherence.phase1.assign',
  attribute: 'coherence.phase2.attribute',
  bible: 'coherence.phase3.bible',
  adjust: 'coherence.phase3.adjust',
  emit: 'coherence.phase4.emit',
});

export const DEFAULT_STEP_TIMEOUT_MS = 15 * 60 * 1000;
export const DEFAULT_MAX_CANCEL_POLL_FAILURES = 3;

export function buildCoherenceEnv(workspaceDir, extraEnv = {}) {
  // Pin UTF-8 locale and America/New_York timezone for deterministic Coherence output.
  return {
    PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
    HOME: process.env.HOME || '',
    LANG: 'en_US.UTF-8',
    LC_ALL: 'en_US.UTF-8',
    PYTHONUTF8: '1',
    TZ: 'America/New_York',
    NO_COLOR: '1',
    PYTHONDONTWRITEBYTECODE: '1',
    PYTHONPATH: workspaceDir,
    ...extraEnv,
  };
}

export function buildStepArgs({ step, statementDate, emitMode = 'coherence', emitDisplay = null, emitKeep = [], emitNoManager = [], companyEmitPath = null }) {
  if (step !== 'emit' || emitMode === 'coherence') {
    return ['-m', STEP_MODULES[step], statementDate];
  }
  if (!companyEmitPath) {
    throw new Error(`Emit mode '${emitMode}' requires a sealed company_emit.py path.`);
  }
  if (emitMode === 'builtin') {
    return [companyEmitPath, statementDate, '--builtin'];
  }
  if (emitMode === 'generated') {
    const args = [companyEmitPath, statementDate, '--display', emitDisplay];
    if (emitKeep && emitKeep.length > 0) args.push('--keep', emitKeep.join(','));
    if (emitNoManager && emitNoManager.length > 0) args.push('--no-manager', emitNoManager.join(','));
    return args;
  }
  throw new Error(`Unknown emitMode: ${emitMode}`);
}

export function killProcessGroup(pid, graceMs = 3000, { killFn = process.kill, logger = null, onError = null } = {}) {
  if (!pid) return;

  const reportError = (err, targetPid, sig) => {
    if (logger && typeof logger.error === 'function') {
      logger.error('process_group_kill_failed', {
        pid: targetPid,
        signal: sig,
        code: err?.code || null,
        reason: sanitizeErrorMessage(err),
      });
    }
    if (typeof onError === 'function') onError(err, { pid: targetPid, signal: sig });
  };

  const sendSignal = (sig) => {
    try {
      killFn(-pid, sig);
      return;
    } catch (groupErr) {
      if (groupErr?.code !== 'ESRCH') {
        reportError(groupErr, -pid, sig);
      }
      try {
        killFn(pid, sig);
      } catch (pidErr) {
        if (pidErr?.code !== 'ESRCH') {
          reportError(pidErr, pid, sig);
        }
      }
    }
  };

  sendSignal('SIGTERM');
  const timer = setTimeout(() => {
    sendSignal('SIGKILL');
  }, graceMs);
  if (typeof timer.unref === 'function') timer.unref();
  return timer;
}

export async function runCoherenceProcess({
  pythonPath,
  args,
  workspaceDir,
  logPath,
  timeoutMs = DEFAULT_STEP_TIMEOUT_MS,
  slotSignal = null,
  checkCancelled = null,
  cancelPollMs = 500,
  maxCancelPollFailures = DEFAULT_MAX_CANCEL_POLL_FAILURES,
  killGraceMs = 2000,
  logger = null,
  extraEnv = {},
}) {
  const startedAt = Date.now();
  const env = buildCoherenceEnv(workspaceDir, extraEnv);
  const logStream = createWriteStream(logPath, { mode: 0o600 });
  const tailLines = [];

  const appendLog = (chunk) => {
    logStream.write(chunk);
    const lines = String(chunk).split('\n').filter((line) => line.length > 0);
    for (const line of lines) tailLines.push(redactPhi(line));
    if (tailLines.length > 80) tailLines.splice(0, tailLines.length - 80);
  };

  appendLog(`$ ${pythonPath} ${args.join(' ')}\n`);

  let outcome = 'exited';
  let cancelRequestId = null;
  let killTimer = null;

  const exitCode = await new Promise((resolvePromise) => {
    let settled = false;
    let timeoutHandle = null;
    let cancelHandle = null;
    let consecutiveCancelPollErrors = 0;

    const child = spawn(pythonPath, args, {
      cwd: workspaceDir,
      env,
      detached: true, // Detached process group leader so process.kill(-pid) terminates child build tools (Vite/pnpm) cleanly.
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const stopChild = (reason, cancelId = null) => {
      if (outcome === 'exited') {
        outcome = reason;
        cancelRequestId = cancelId;
        appendLog(`\n[worker] stopping process group (${reason})\n`);
        killTimer = killProcessGroup(child.pid, killGraceMs, { logger });
      }
    };

    const onSlotAbort = () => stopChild('slot_lost');
    if (slotSignal) {
      if (slotSignal.aborted) onSlotAbort();
      else slotSignal.addEventListener('abort', onSlotAbort, { once: true });
    }

    if (timeoutMs > 0) {
      timeoutHandle = setTimeout(() => stopChild('timed_out'), timeoutMs);
      if (typeof timeoutHandle.unref === 'function') timeoutHandle.unref();
    }

    if (typeof checkCancelled === 'function' && cancelPollMs > 0) {
      cancelHandle = setInterval(async () => {
        if (settled || outcome !== 'exited') return;
        try {
          const found = await checkCancelled();
          consecutiveCancelPollErrors = 0;
          if (found) stopChild('cancelled', found.id);
        } catch (err) {
          consecutiveCancelPollErrors += 1;
          const safeReason = sanitizeErrorMessage(err, 'Cancel status check failed.');
          appendLog(`[worker] cancel poll error (${consecutiveCancelPollErrors}/${maxCancelPollFailures}): ${safeReason}\n`);
          if (logger && typeof logger.warn === 'function') {
            logger.warn('cancel_poll_failed', {
              consecutiveFailures: consecutiveCancelPollErrors,
              maxFailures: maxCancelPollFailures,
              reason: safeReason,
            });
          }
          if (consecutiveCancelPollErrors >= maxCancelPollFailures) {
            if (logger && typeof logger.error === 'function') {
              logger.error('cancel_poll_threshold_exceeded', {
                consecutiveFailures: consecutiveCancelPollErrors,
                reason: safeReason,
              });
            }
            stopChild('cancel_poll_failed');
          }
        }
      }, cancelPollMs);
      if (typeof cancelHandle.unref === 'function') cancelHandle.unref();
    }

    const finish = (code) => {
      if (settled) return;
      settled = true;
      if (timeoutHandle) clearTimeout(timeoutHandle);
      if (cancelHandle) clearInterval(cancelHandle);
      if (killTimer) clearTimeout(killTimer);
      if (slotSignal) slotSignal.removeEventListener('abort', onSlotAbort);
      logStream.end(() => resolvePromise(code ?? 1));
    };

    child.stdout.on('data', appendLog);
    child.stderr.on('data', appendLog);
    child.on('error', (err) => {
      appendLog(`[worker] spawn error: ${err.message}\n`);
      finish(1);
    });
    child.on('close', (code) => finish(code));
  });

  const logBytes = await readFile(logPath).catch(() => Buffer.alloc(0));
  return {
    exitCode,
    outcome,
    cancelRequestId,
    logBytes,
    tailLines,
    durationMs: Date.now() - startedAt,
  };
}

export async function runOverlayCheck({
  pythonPath,
  overlayCheckPath,
  workspaceDir,
  statementDate,
  candidatePath,
  surface,
  outJsonPath,
  timeoutMs = 300_000,
  slotSignal = null,
  logger = null,
  extraEnv = {},
}) {
  const args = [overlayCheckPath, statementDate, candidatePath, surface, '--out', outJsonPath];
  const env = buildCoherenceEnv(workspaceDir, extraEnv);
  return new Promise((resolvePromise) => {
    let settled = false;
    let timeoutHandle = null;
    let killTimer = null;
    const child = spawn(pythonPath, args, {
      cwd: workspaceDir,
      env,
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdoutChunks = [];
    const stderrChunks = [];

    const abortChild = () => { killTimer = killProcessGroup(child.pid, 1500, { logger }); };
    if (slotSignal) {
      if (slotSignal.aborted) abortChild();
      else slotSignal.addEventListener('abort', abortChild, { once: true });
    }
    timeoutHandle = setTimeout(abortChild, timeoutMs);
    if (typeof timeoutHandle.unref === 'function') timeoutHandle.unref();

    const done = async (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutHandle);
      if (killTimer) clearTimeout(killTimer);
      if (slotSignal) slotSignal.removeEventListener('abort', abortChild);
      const stderr = redactPhi(Buffer.concat(stderrChunks).toString('utf8').trim());
      if (code !== 0) {
        return resolvePromise({ ok: false, error: stderr || 'Coherence rejected the review file.' });
      }
      try {
        const parsed = JSON.parse(await readFile(outJsonPath, 'utf8'));
        return resolvePromise({ ok: true, result: parsed });
      } catch {
        return resolvePromise({ ok: false, error: 'Overlay check did not produce a valid JSON report.' });
      }
    };

    child.stdout.on('data', (c) => stdoutChunks.push(c));
    child.stderr.on('data', (c) => stderrChunks.push(c));
    child.on('error', (err) => done(1, stderrChunks.push(Buffer.from(err.message))));
    child.on('close', (code) => { void done(code); });
  });
}
