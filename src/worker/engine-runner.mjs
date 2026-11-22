// Coherence step process runner (R5.1, R5.6, R5.7, R10.3, R10.4).
// Spawns Coherence in its own process group with UTF-8 / America/New_York env,
// and terminates the entire process group on cancel, 15-minute timeout, or slot loss.
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { redactPhi } from '../util/redact.mjs';

export const STEP_MODULES = Object.freeze({
  assign: 'coherence.phase1.assign',
  attribute: 'coherence.phase2.attribute',
  bible: 'coherence.phase3.bible',
  adjust: 'coherence.phase3.adjust',
  emit: 'coherence.phase4.emit',
});

export const DEFAULT_STEP_TIMEOUT_MS = 15 * 60 * 1000; // R10.4: 15 minutes

export function buildCoherenceEnv(workspaceDir, extraEnv = {}) {
  // R5.6: UTF-8 locale and America/New_York timezone required for determinism.
  return {
    PATH: process.env.PATH || '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
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
    throw new Error(`Emit mode '${emitMode}' requires sealed company_emit.py path (CR-7).`);
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

export function killProcessGroup(pid, graceMs = 3000) {
  if (!pid) return;
  try {
    process.kill(-pid, 'SIGTERM');
  } catch {
    try { process.kill(pid, 'SIGTERM'); } catch { /* already dead */ }
  }
  const timer = setTimeout(() => {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      try { process.kill(pid, 'SIGKILL'); } catch { /* already dead */ }
    }
  }, graceMs);
  if (typeof timer.unref === 'function') timer.unref();
  return timer;
}

/**
 * Spawns one Coherence step in its own process group.
 * Returns { exitCode, outcome: 'exited'|'cancelled'|'timed_out'|'slot_lost', cancelRequestId, logBytes, tailLines, durationMs }.
 */
export async function runCoherenceProcess({
  pythonPath,
  args,
  workspaceDir,
  logPath,
  timeoutMs = DEFAULT_STEP_TIMEOUT_MS,
  slotSignal = null,
  checkCancelled = null,
  cancelPollMs = 500,
  killGraceMs = 2000,
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

    const child = spawn(pythonPath, args, {
      cwd: workspaceDir,
      env,
      detached: true, // own process group so the whole tree (including Vite/pnpm) can be killed cleanly (R10.3)
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const stopChild = (reason, cancelId = null) => {
      if (outcome === 'exited') {
        outcome = reason;
        cancelRequestId = cancelId;
        appendLog(`\n[worker] stopping process group (${reason})\n`);
        killTimer = killProcessGroup(child.pid, killGraceMs);
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
          if (found) stopChild('cancelled', found.id);
        } catch { /* ignore transient poll failure */ }
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

/**
 * Runs the sealed extended overlay checker script (R5.8) inside a verified workspace.
 */
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

    const abortChild = () => { killTimer = killProcessGroup(child.pid, 1500); };
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
