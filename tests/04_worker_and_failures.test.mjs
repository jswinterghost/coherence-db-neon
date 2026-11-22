// R5, R10, R11 (RP-1, RP-2, CR-6, W-4, W-9), R18 engine worker, slot, reconciler, cancel, timeout, and failure tests.
import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import { createClient } from '../src/db/pg-client.mjs';
import { verifyObjects } from '../src/commands/journal-export.mjs';
import { reconcileInterruptedAttempts } from '../src/worker/reconciler.mjs';
import { acquireRunningSlot } from '../src/worker/slot.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';
import { createMockEngineMaterializer, makeOverlayCsv, sampleApprovalRow, seedEngineVersion, seedStandingInput } from './helpers/fixtures.mjs';

const pgCheck = await checkPgAvailable();

test('R9.6 & R10.3 & R11 audit: running slot mutual exclusion and out-of-transaction liveness checks', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  let livenessInTxCount = 0;
  let livenessQueries = 0;
  const slot1 = await acquireRunningSlot({
    pgConfig: env.pgConfig,
    livenessIntervalMs: 50,
    livenessTimeoutMs: 2000,
    onLivenessQuery: ({ inTransaction }) => {
      livenessQueries += 1;
      if (inTransaction) livenessInTxCount += 1;
    },
  });
  assert.ok(slot1, 'first worker should acquire the company running slot');
  t.after(() => slot1.release());

  // Second connection cannot acquire the slot while first holds it
  const slot2 = await acquireRunningSlot({ pgConfig: env.pgConfig, livenessIntervalMs: 0 });
  assert.equal(slot2, null, 'second worker must be refused while slot is held');

  // Hold an active transaction longer than several liveness intervals -> ZERO liveness queries inside tx!
  await slot1.runExclusive(async (client) => {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    await new Promise((r) => setTimeout(r, 180));
    await client.query('COMMIT');
  });
  await new Promise((r) => setTimeout(r, 120));
  assert.equal(livenessInTxCount, 0, 'liveness query must NEVER run inside a transaction (R10.3, R11)');
  assert.ok(livenessQueries >= 1, 'liveness check should run between operations');

  await slot1.release();
  const slot3 = await acquireRunningSlot({ pgConfig: env.pgConfig, livenessIntervalMs: 0 });
  assert.ok(slot3, 'slot must be immediately free after release');
  await slot3.release();
});

test('R10.7, R10.9 & R18: rejected review submission does not promote bytes or stall worker; frozen input mutation fails step; zero code in data store', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:aetna:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: 'phalanx',
    stores: env.stores,
    commands: env.commands,
    workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(),
    tempBaseDir: env.tempDir,
  }));

  const launch = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'launch-rev-test', statementDate: '2026-11-21', engineVersionId,
  });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) {
    assert.equal((await worker.runOnce()).action, 'step_finished');
  }

  // RP-1: Between finished steps / waiting for Bible, reconciler finds ZERO open attempts
  const recIdle = await reconcileInterruptedAttempts({ pool: env.pool, commands: env.commands, workerActor: env.workerActor });
  assert.equal(recIdle.interrupted.length, 0);

  // Submit a BAD review file (drops prior row!)
  const badCsv = makeOverlayCsv([sampleApprovalRow({ record_id: 'policy:aetna:OTHER#effective:2026-01-01' })]);
  const seq1 = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const badSub = await env.commands.submitReview({
    actor: env.ownerActor, commandKey: 'sub-bad', expectedJournalSeq: seq1, runId, surface: 'bible', csvBytes: Buffer.from(badCsv, 'utf8'),
  });
  const objectsBefore = env.dataBackend.listObjectNames().filter((n) => n.startsWith('objects/')).length;

  const badOutcome = await worker.runOnce();
  assert.equal(badOutcome.action, 'review_rejected');
  // Bytes must NOT have been promoted to objects/<sha256> (R10.8)
  const objectsAfterBad = env.dataBackend.listObjectNames().filter((n) => n.startsWith('objects/')).length;
  assert.equal(objectsAfterBad, objectsBefore);

  const badRow = await env.pool.query('SELECT status, result_message FROM coherence.review_submissions WHERE id = $1::uuid', [badSub.submissionId]);
  assert.equal(badRow.rows[0].status, 'rejected');

  // Worker is NOT stalled: submit a valid Bible review next -> accepted immediately!
  const goodCsv = makeOverlayCsv([row0, sampleApprovalRow({ record_id: 'policy:aetna:P10001#effective:2026-01-01' })]);
  await env.commands.submitReview({
    actor: env.ownerActor, commandKey: 'sub-good', expectedJournalSeq: seq1, runId, surface: 'bible', csvBytes: Buffer.from(goodCsv, 'utf8'),
  });
  const goodOutcome = await worker.runOnce();
  assert.equal(goodOutcome.action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished'); // adjust

  // Verify zero code-bearing files in dataStore
  const objCheck = await verifyObjects(env.pool, env.stores, { deep: true });
  assert.equal(objCheck.passed, true);

  // R10.9: Verify mutating frozen input inside a step fails the step
  const mutWorker = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: 'phalanx',
    stores: env.stores,
    commands: env.commands,
    workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer({ mutateFrozenInputStep: 'assign' }),
    tempBaseDir: env.tempDir,
  }));
  const launch2 = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'launch-mut', statementDate: '2026-11-22', engineVersionId,
  });
  const mutRes = await mutWorker.runOnce();
  assert.equal(mutRes.action, 'step_failed');
  const stage2 = (await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [launch2.result.runId])).rows[0].stage;
  assert.equal(stage2, 'failed');
});

test('R10.1, R10.2, R11 (RP-1, RP-2, W-4) & R18: worker killed after start and after Coherence mark before DB finish -> never finished, reconciler marks interrupted', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  await seedStandingInput(env);

  const launch = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'launch-kill', statementDate: '2026-11-21', engineVersionId,
  });
  const runId = launch.result.runId;

  // Case 1: Worker's PostgreSQL backend dies right AFTER `assign` starts (simulates crash/dropped connection mid-step)
  const adminKiller = await createClient(env.pgConfig);
  t.after(() => adminKiller.end());

  const dyingWorker1 = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: 'phalanx',
    stores: env.stores,
    commands: env.commands,
    workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(),
    tempBaseDir: env.tempDir,
    livenessIntervalMs: 50,
    onAfterStart: async ({ slot }) => {
      // Terminate this worker's PG backend to simulate dropped network / dead Mac!
      await adminKiller.query('SELECT pg_catalog.pg_terminate_backend($1)', [slot.backendPid]);
      await new Promise((r) => setTimeout(r, 150));
    },
  }));

  const killedRes1 = await dyingWorker1.runOnce();
  assert.equal(killedRes1.action, 'slot_lost');

  // Reconciler marks open assign attempt 1 interrupted before anything else runs (R10.1, W-4)
  const rec1 = await reconcileInterruptedAttempts({ pool: env.pool, commands: env.commands, workerActor: env.workerActor });
  assert.equal(rec1.interrupted.length, 1);
  assert.equal(rec1.interrupted[0].step, 'assign');
  assert.equal(rec1.interrupted[0].attemptNo, 1);
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].stage, 'interrupted');

  // Retry assign -> now kill worker AFTER Coherence wrote run.json mark, right BEFORE DB finish commit (RP-2)!
  await env.commands.requestRetry({ actor: env.ownerActor, commandKey: 'retry-assign-2', runId, step: 'assign' });
  const dyingWorker2 = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: 'phalanx',
    stores: env.stores,
    commands: env.commands,
    workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(),
    tempBaseDir: env.tempDir,
    livenessIntervalMs: 50,
    onBeforeFinish: async ({ slot }) => {
      await adminKiller.query('SELECT pg_catalog.pg_terminate_backend($1)', [slot.backendPid]);
      await new Promise((r) => setTimeout(r, 150));
    },
  }));

  const killedRes2 = await dyingWorker2.runOnce();
  assert.equal(killedRes2.action, 'slot_lost');

  // RP-2 proof: assign attempt 2 must NOT be recorded finished!
  const finCount = await env.pool.query(
    "SELECT COUNT(*)::int AS n FROM coherence.step_attempt_events WHERE run_id = $1::uuid AND step = 'assign' AND event_kind = 'finished'",
    [runId],
  );
  assert.equal(finCount.rows[0].n, 0);

  // Healthy worker reconciles attempt 2 automatically on next runOnce, then retry succeeds cleanly!
  const healthyWorker = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: 'phalanx',
    stores: env.stores,
    commands: env.commands,
    workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(),
    tempBaseDir: env.tempDir,
  }));
  const idleAfterRec = await healthyWorker.runOnce();
  assert.equal(idleAfterRec.reconciled, 1);

  await env.commands.requestRetry({ actor: env.ownerActor, commandKey: 'retry-assign-3', runId, step: 'assign' });
  const okAssign = await healthyWorker.runOnce();
  assert.equal(okAssign.action, 'step_finished');
  assert.equal(okAssign.attemptNo, 3);
  assert.equal(okAssign.nextStep, 'attribute');

  // RP-1 proof: between assign (finished) and attribute (requested), reconciler marks NOTHING interrupted!
  const recBetween = await reconcileInterruptedAttempts({ pool: env.pool, commands: env.commands, workerActor: env.workerActor });
  assert.equal(recBetween.interrupted.length, 0);
});

test('R10.4 & R18: typed cancel stops the engine entire process group (including grandchild); step time limit stops hung step', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  await seedStandingInput(env);

  // 1. Cancel test with grandchild process
  const grandchildPidFile = join(env.tempDir, 'grandchild.pid');
  const launch1 = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'launch-cancel', statementDate: '2026-11-21', engineVersionId,
  });
  const run1 = launch1.result.runId;

  const cancelWorker = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: 'phalanx',
    stores: env.stores,
    commands: env.commands,
    workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer({
      sleepStep: 'assign',
      sleepSeconds: 30,
      spawnGrandchildPidFile: grandchildPidFile,
    }),
    tempBaseDir: env.tempDir,
    cancelPollMs: 100,
  }));

  const workPromise = cancelWorker.runOnce();
  // Wait for grandchild PID file to appear (confirming step is actively running)
  let grandchildPid = null;
  for (let i = 0; i < 60; i++) {
    if (await stat(grandchildPidFile).then(() => true, () => false)) {
      grandchildPid = Number((await readFile(grandchildPidFile, 'utf8')).trim());
      if (grandchildPid > 0) break;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(grandchildPid > 0, 'grandchild process should have spawned');

  // Issue typed cancel request
  await env.commands.requestCancel({
    actor: env.ownerActor,
    commandKey: 'cancel-run1',
    runId: run1,
    step: 'assign',
    attemptNo: 1,
    typedPhrase: 'cancel 2026-11-21',
    reason: 'stop test step',
  });

  const cancelledOutcome = await workPromise;
  assert.equal(cancelledOutcome.action, 'step_cancelled');
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [run1])).rows[0].stage, 'cancelled');

  // Verify the grandchild process in the process group was ALSO killed!
  await new Promise((r) => setTimeout(r, 200));
  let grandchildAlive = true;
  try { process.kill(grandchildPid, 0); } catch { grandchildAlive = false; }
  assert.equal(grandchildAlive, false, 'process-group kill must terminate grandchild processes too (R10.3, R10.4)');

  // 2. Step time limit test (short 600 ms timeout stops a 30s sleeping step)
  const launch2 = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'launch-timeout', statementDate: '2026-11-22', engineVersionId,
  });
  const timeoutWorker = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: 'phalanx',
    stores: env.stores,
    commands: env.commands,
    workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer({ sleepStep: 'assign', sleepSeconds: 30 }),
    tempBaseDir: env.tempDir,
    stepTimeoutMs: 600,
  }));
  const timedOut = await timeoutWorker.runOnce();
  assert.equal(timedOut.action, 'step_timed_out');
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [launch2.result.runId])).rows[0].stage, 'failed');
});
