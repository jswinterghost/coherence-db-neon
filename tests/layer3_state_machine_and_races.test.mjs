// ============================================================================
// LAYER 3: THE STATE MACHINE AND RACES
// Protects: workflow state integrity, concurrency safety, and worker fault
// recovery — preventing skipped human reviews, race conditions between tabs /
// review saves / Emit confirmations, documentation drifting from executable
// state machines or DB guards, dead workers leaving runs stuck or corrupting
// results, or runaway engine subprocesses surviving cancel/timeout.
// ============================================================================
import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createClient } from '../src/db/pg-client.mjs';
import { verifyObjects } from '../src/commands/journal-export.mjs';
import {
  deriveRunStage,
  generateStateMachineMarkdown,
  RUN_STAGE_MACHINE,
  STEP_ATTEMPT_MACHINE,
  verifyCoherenceStateMachinesAgainstDb,
} from '../src/state-machine/coherence-machines.mjs';
import { defineStateMachine, StateMachineDefinitionError } from '../src/state-machine/declarative-machine.mjs';
import { reconcileInterruptedAttempts } from '../src/worker/reconciler.mjs';
import { acquireRunningSlot } from '../src/worker/slot.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import { createMockEngineMaterializer, makeOverlayCsv, sampleApprovalRow, seedEngineVersion, seedStandingInput } from './helpers/fixtures.mjs';
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pgCheck = await checkPgAvailable();

async function runToBibleWaiting(env, worker, { statementDate = '2026-11-21', origin = 'app', engineVersionId, rerunReason = null } = {}) {
  const launch = await env.commands.launchRun({
    actor: env.ownerActor,
    commandKey: `launch-${origin}-${statementDate}-${Date.now()}-${Math.random()}`,
    statementDate,
    origin,
    engineVersionId,
    rerunReason,
  });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) {
    const step = await worker.runOnce();
    assert.equal(step.action, 'step_finished');
  }
  const st = await env.pool.query('SELECT stage, latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId]);
  assert.equal(st.rows[0].stage, 'waiting for Bible');
  return { runId, latestSeq: Number(st.rows[0].latest_journal_seq) };
}

test('Layer 3 [State Machine as Data — Item 10]: reusable machine validation, PostgreSQL catalog verification, STATE_MACHINE.md parity, and live walkthrough of ALL 11 run stages & 7 step attempt states', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  // 1. Reusable declarative-machine pattern catches broken machines statically (for Nusear's other tools too)
  assert.throws(
    () => defineStateMachine({
      id: 'bad-unreachable',
      title: 'Bad',
      states: [{ id: 'a', initial: true }, { id: 'b', terminal: true }, { id: 'orphan', terminal: true }],
      transitions: [{ id: 'go', from: ['a'], to: 'b' }],
    }),
    StateMachineDefinitionError,
  );
  assert.throws(
    () => defineStateMachine({
      id: 'bad-guard',
      title: 'Bad',
      states: [{ id: 'a', initial: true }, { id: 'b', terminal: true }],
      transitions: [{ id: 'go', from: ['a'], to: 'b', guards: ['nonexistent_guard'] }],
    }),
    StateMachineDefinitionError,
  );
  assert.throws(
    () => defineStateMachine({
      id: 'bad-deadend',
      title: 'Bad',
      states: [{ id: 'a', initial: true }, { id: 'stuck' }],
      transitions: [{ id: 'go', from: ['a'], to: 'stuck' }],
    }),
    StateMachineDefinitionError,
  );

  // 2. Both Coherence machines pass static graph verification and STATE_MACHINE.md matches generated Markdown byte-for-byte
  assert.equal(RUN_STAGE_MACHINE.verifyGraph().ok, true);
  assert.equal(STEP_ATTEMPT_MACHINE.verifyGraph().ok, true);
  const diskDoc = await readFile(resolve(REPO_ROOT, 'STATE_MACHINE.md'), 'utf8');
  assert.equal(diskDoc, generateStateMachineMarkdown(), 'STATE_MACHINE.md must match generated output from src/state-machine/coherence-machines.mjs');

  // Guard evaluator matches declared transitions and every declared guard has an executable predicate
  for (const machine of [RUN_STAGE_MACHINE, STEP_ATTEMPT_MACHINE]) {
    for (const [gId, guard] of Object.entries(machine.spec.guards)) {
      assert.equal(typeof guard.evaluate, 'function', `guard ${machine.id}.${gId} must provide an evaluate predicate`);
      assert.ok(guard.dbEnforcement, `guard ${machine.id}.${gId} must declare dbEnforcement`);
    }
    for (const tr of machine.spec.transitions) {
      const invalidFrom = machine.stateIds.find((s) => !tr.from.includes(s));
      if (invalidFrom) {
        assert.equal(machine.evaluateTransition(tr.id, invalidFrom, {}).ok, false);
      }
    }
  }
  assert.equal(RUN_STAGE_MACHINE.evaluateTransition('launch', 'no open run of the date', { hasSentStatementForDate: true, hasNonAbandonedRunForDate: false }).ok, false);
  assert.equal(RUN_STAGE_MACHINE.evaluateTransition('launch', 'no open run of the date', { hasSentStatementForDate: false, hasNonAbandonedRunForDate: false }).ok, true);

  // 3. Verify every declared table, trigger, function, index, CHECK enum, and coherence.run_stage() literal against live PG 17!
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const dbVerify = await verifyCoherenceStateMachinesAgainstDb(env.pool);
  assert.equal(dbVerify.passed, true, `State machine DB verification failed: ${dbVerify.problems.join('; ')}`);

  // 4. Live DB walkthrough reaching EVERY SINGLE ONE of the 11 run stages and 7 step attempt states!
  const observedRunStages = new Set();
  const observedAttemptStates = new Set();
  const recordStage = async (runId, expectedSnapshot) => {
    const dbStage = (await env.pool.query('SELECT coherence.run_stage($1::uuid, NULL) AS stage', [runId])).rows[0].stage;
    const modelStage = deriveRunStage(expectedSnapshot);
    assert.equal(dbStage, modelStage, `DB stage '${dbStage}' disagreed with declared model stage '${modelStage}'`);
    observedRunStages.add(dbStage);
    return dbStage;
  };

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:aetna:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  // Run 1: preparing -> running a step -> waiting for Bible -> waiting for Adjust -> ready to create statements -> emitting -> done -> abandoned
  const l1 = await env.commands.launchRun({ actor: env.ownerActor, commandKey: 'sm-r1', statementDate: '2026-11-21', engineVersionId });
  const r1 = l1.result.runId;
  observedAttemptStates.add('requested');
  await recordStage(r1, { openRequestStep: 'assign' });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: 'phalanx',
    stores: env.stores,
    commands: env.commands,
    workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(),
    tempBaseDir: env.tempDir,
    onAfterStart: async ({ run, step }) => {
      observedAttemptStates.add('started');
      await recordStage(run.id, { openAttemptStep: step });
    },
  }));
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  observedAttemptStates.add('finished');
  await recordStage(r1, { bibleFinished: true }); // waiting for Bible

  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [r1])).rows[0].latest_journal_seq);
  const bibleRows = [row0, sampleApprovalRow({ record_id: 'policy:aetna:P10001#effective:2026-01-01' })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'sm-b1', expectedJournalSeq: seq, runId: r1, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished'); // adjust 1
  await recordStage(r1, { bibleFinished: true, adjustFinished: true, hasAdjustSaveForCurrentAdjust: false }); // waiting for Adjust

  // Bible re-save supersedes adjust 1 -> proves 'superseded' attempt state!
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [r1])).rows[0].latest_journal_seq);
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'sm-b2', expectedJournalSeq: seq, runId: r1, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv([...bibleRows, sampleApprovalRow({ note: 'b2' })]), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  observedAttemptStates.add('superseded');
  assert.equal((await worker.runOnce()).action, 'step_finished'); // adjust 2

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [r1])).rows[0].latest_journal_seq);
  const adjRows = [...bibleRows, sampleApprovalRow({ note: 'b2' }), sampleApprovalRow({ record_id: 'aetna~direct~P10001~100.00~2026-11' })];
  await env.commands.submitReview({ actor: env.ownerActor, commandKey: 'sm-a1', expectedJournalSeq: seq, runId: r1, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
  const adjAcc = await worker.runOnce();
  assert.equal(adjAcc.action, 'review_accepted');
  await recordStage(r1, { bibleFinished: true, adjustFinished: true, hasAdjustSaveForCurrentAdjust: true }); // ready to create statements

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [r1])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ actor: env.ownerActor, commandKey: 'sm-e1', expectedJournalSeq: seq, runId: r1, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: 'create statements for 2026-11-21' });
  await recordStage(r1, { openRequestStep: 'emit' }); // emitting
  assert.equal((await worker.runOnce()).action, 'step_finished'); // emit
  await recordStage(r1, { emitFinished: true }); // done

  await env.commands.abandonRun({ actor: env.ownerActor, commandKey: 'sm-ab1', runId: r1, typedPhrase: 'abandon 2026-11-21', reason: 'state walkthrough' });
  await recordStage(r1, { abandoned: true }); // abandoned

  // Run 2: failed stage & failed attempt state
  const l2 = await env.commands.launchRun({ actor: env.ownerActor, commandKey: 'sm-r2', statementDate: '2026-11-22', engineVersionId });
  const failWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: 'phalanx', stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer({ failStep: 'assign' }), tempBaseDir: env.tempDir,
  }));
  assert.equal((await failWorker.runOnce()).action, 'step_failed');
  observedAttemptStates.add('failed');
  await recordStage(l2.result.runId, { latestNonSupersededEndKind: 'failed' });

  // Run 3: interrupted stage & interrupted attempt state
  const l3 = await env.commands.launchRun({ actor: env.ownerActor, commandKey: 'sm-r3', statementDate: '2026-11-23', engineVersionId });
  const killer = env.registerClient(await createClient(env.pgConfig));
  const dieWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: 'phalanx', stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir, livenessIntervalMs: 50,
    onAfterStart: async ({ slot }) => {
      await killer.query('SELECT pg_catalog.pg_terminate_backend($1)', [slot.backendPid]);
      await new Promise((r) => setTimeout(r, 120));
    },
  }));
  assert.equal((await dieWorker.runOnce()).action, 'slot_lost');
  const rec = await reconcileInterruptedAttempts({ pool: env.pool, commands: env.commands, workerActor: env.workerActor });
  assert.equal(rec.interrupted.length, 1);
  observedAttemptStates.add('interrupted');
  await recordStage(l3.result.runId, { latestNonSupersededEndKind: 'interrupted' });

  // Run 4: cancelled stage & cancelled attempt state
  const l4 = await env.commands.launchRun({ actor: env.ownerActor, commandKey: 'sm-r4', statementDate: '2026-11-24', engineVersionId });
  const cancelWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: 'phalanx', stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer({ sleepStep: 'assign', sleepSeconds: 20 }), tempBaseDir: env.tempDir, cancelPollMs: 80,
    onAfterStart: async ({ run }) => {
      await env.commands.requestCancel({ actor: env.ownerActor, commandKey: 'sm-c4', runId: run.id, step: 'assign', attemptNo: 1, typedPhrase: 'cancel 2026-11-24', reason: 'sm test' });
    },
  }));
  assert.equal((await cancelWorker.runOnce()).action, 'step_cancelled');
  observedAttemptStates.add('cancelled');
  await recordStage(l4.result.runId, { latestNonSupersededEndKind: 'cancelled' });

  // Assert EVERY declared state in BOTH machines was genuinely reached in live PostgreSQL!
  assert.deepEqual([...observedRunStages].sort(), [...RUN_STAGE_MACHINE.nonPseudoStateIds].sort());
  assert.deepEqual([...observedAttemptStates].sort(), [...STEP_ATTEMPT_MACHINE.nonPseudoStateIds].sort());
});

test('Layer 3 [R10.6 & R4]: idempotent resend acts once, reused command key with any difference is refused, and staff permissions enforced', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  await seedStandingInput(env);

  // R4.2: staff with withheld run-coherence refused; unassigned staff refused
  const withheldStaff = { id: 'bertie', kind: 'nusear_staff', customers: ['phalanx'], withheld: ['run-coherence'] };
  await assert.rejects(
    () => env.commands.launchRun({ actor: withheldStaff, commandKey: 'wh-launch', statementDate: '2026-11-21', engineVersionId }),
    /held back/i,
  );
  const wrongCustStaff = { id: 'alice', kind: 'nusear_staff', customers: ['clearpath'], withheld: [] };
  await assert.rejects(
    () => env.commands.launchRun({ actor: wrongCustStaff, commandKey: 'wc-launch', statementDate: '2026-11-21', engineVersionId }),
    /not assigned/i,
  );

  // R4.5: Nusear support actingFor records acting_for
  const supportActor = { id: 'kairon', kind: 'owner', actingFor: 'phalanx' };
  const first = await env.commands.launchRun({
    actor: supportActor, commandKey: 'launch-idem-key', statementDate: '2026-11-21', engineVersionId,
  });
  assert.equal(first.idempotent, false);
  const jeRow = await env.pool.query('SELECT acting_for FROM coherence.journal_entries WHERE seq = $1', [String(first.journalSeq)]);
  assert.equal(jeRow.rows[0].acting_for, 'phalanx');

  // R10.6: Resend identical request returns first result, writes nothing new
  const resend = await env.commands.launchRun({
    actor: supportActor, commandKey: 'launch-idem-key', statementDate: '2026-11-21', engineVersionId,
  });
  assert.equal(resend.idempotent, true);
  assert.equal(resend.journalSeq, first.journalSeq);
  assert.equal(resend.result.runId, first.result.runId);

  // R10.6: Same key with different content, actingFor, or commandKind is REFUSED (409)
  await assert.rejects(
    () => env.commands.launchRun({ actor: supportActor, commandKey: 'launch-idem-key', statementDate: '2026-11-22', engineVersionId }),
    /already used for a different request/i,
  );
  await assert.rejects(
    () => env.commands.launchRun({ actor: { id: 'kairon', kind: 'owner', actingFor: null }, commandKey: 'launch-idem-key', statementDate: '2026-11-21', engineVersionId }),
    /already used for a different request/i,
  );
  await assert.rejects(
    () => env.commands.abandonRun({ actor: supportActor, commandKey: 'launch-idem-key', runId: first.result.runId, typedPhrase: 'abandon 2026-11-21', reason: 'test' }),
    /already used for a different request/i,
  );
});

test('Layer 3 [R10.5, R8, R11 (CR-1, CR-8, CR-9, CR-10)]: racing commands, review save vs Emit confirmation, Bible re-save rules, and attempt-keyed drafts', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:aetna:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: 'phalanx', stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));

  const { runId, latestSeq } = await runToBibleWaiting(env, worker, { statementDate: '2026-11-21', engineVersionId });

  // R10.5: Two tabs racing with the same expectedJournalSeq -> only one succeeds
  const rowBible1 = sampleApprovalRow({ record_id: 'policy:aetna:P10001#effective:2026-01-01', note: 'tab1' });
  const rowBible2 = sampleApprovalRow({ record_id: 'policy:aetna:P10001#effective:2026-01-01', note: 'tab2' });
  const [r1, r2] = await Promise.allSettled([
    env.commands.submitReview({
      actor: env.ownerActor, commandKey: 'sub-tab-1', expectedJournalSeq: latestSeq,
      runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBible1]), 'utf8'),
    }),
    env.commands.submitReview({
      actor: env.ownerActor, commandKey: 'sub-tab-2', expectedJournalSeq: latestSeq,
      runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBible2]), 'utf8'),
    }),
  ]);
  assert.equal([r1, r2].filter((x) => x.status === 'fulfilled').length, 1);
  assert.equal([r1, r2].filter((x) => x.status === 'rejected').length, 1);

  assert.equal((await worker.runOnce()).action, 'review_accepted');
  const adj1 = await worker.runOnce();
  assert.equal(adj1.action, 'step_finished');
  assert.equal(adj1.step, 'adjust');
  assert.equal(adj1.attemptNo, 1);

  // CR-9: Draft keyed by attempt
  await env.commands.saveReviewDraft({
    actor: env.ownerActor, runId, surface: 'adjust', attemptNo: 1, born: 'b1', checksum: 'c1', rows: [{ record_id: 'x' }],
  });
  assert.ok(await env.commands.getReviewDraft({ runId, surface: 'adjust', attemptNo: 1 }));
  await assert.rejects(
    () => env.commands.saveReviewDraft({ actor: env.ownerActor, runId, surface: 'adjust', attemptNo: 2, born: 'b1', checksum: 'c1', rows: [] }),
    /CR-9|current finished/i,
  );

  // R8: Bible re-save while waiting for Adjust (no Adjust save yet) -> supersedes Adjust 1 and runs Adjust 2
  const seqBeforeResave = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const rowBibleResave = sampleApprovalRow({ record_id: 'policy:aetna:P10001#effective:2026-01-01', note: 'bible-resave' });
  await env.commands.submitReview({
    actor: env.ownerActor, commandKey: 'sub-bible-resave', expectedJournalSeq: seqBeforeResave,
    runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave]), 'utf8'),
  });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  const adj2 = await worker.runOnce();
  assert.equal(adj2.action, 'step_finished');
  assert.equal(adj2.attemptNo, 2);
  assert.equal(await env.commands.getReviewDraft({ runId, surface: 'adjust', attemptNo: 2 }), null);

  // Save Adjust review #1 on attempt 2
  const seqBeforeAdjSave = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const rowAdj1 = sampleApprovalRow({ record_id: 'aetna~direct~P10001~100.00~2026-11', note: 'adj-1' });
  await env.commands.submitReview({
    actor: env.ownerActor, commandKey: 'sub-adj-1', expectedJournalSeq: seqBeforeAdjSave,
    runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave, rowAdj1]), 'utf8'),
  });
  const accAdj1 = await worker.runOnce();
  assert.equal(accAdj1.action, 'review_accepted');

  // CR-8: Bible re-save AFTER Adjust review saved MUST BE REFUSED!
  const seqAfterAdj1 = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await assert.rejects(
    () => env.commands.submitReview({
      actor: env.ownerActor, commandKey: 'sub-bible-after-adj', expectedJournalSeq: seqAfterAdj1,
      runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave]), 'utf8'),
    }),
    /CR-8|Adjust review was saved/i,
  );

  // CR-1: Emit confirmation while review submission is pending MUST BE REFUSED!
  const rowAdj2 = sampleApprovalRow({ record_id: 'aetna~direct~P10001~100.00~2026-11', note: 'adj-2' });
  await env.commands.submitReview({
    actor: env.ownerActor, commandKey: 'sub-adj-2', expectedJournalSeq: seqAfterAdj1,
    runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave, rowAdj1, rowAdj2]), 'utf8'),
  });
  await assert.rejects(
    () => env.commands.confirmEmit({
      actor: env.ownerActor, commandKey: 'emit-while-pending', expectedJournalSeq: seqAfterAdj1,
      runId, adjustReviewSaveId: accAdj1.reviewSaveId, typedPhrase: 'create statements for 2026-11-21',
    }),
    /review submission is waiting|CR-1/i,
  );

  const accAdj2 = await worker.runOnce();
  assert.equal(accAdj2.action, 'review_accepted');

  // R9.4: Emit confirmation naming OLD Adjust save #1 MUST BE REFUSED!
  const seqReady = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await assert.rejects(
    () => env.commands.confirmEmit({
      actor: env.ownerActor, commandKey: 'emit-stale-save', expectedJournalSeq: seqReady,
      runId, adjustReviewSaveId: accAdj1.reviewSaveId, typedPhrase: 'create statements for 2026-11-21',
    }),
    /newest Adjust review save/i,
  );

  await env.commands.confirmEmit({
    actor: env.ownerActor, commandKey: 'emit-ok', expectedJournalSeq: seqReady,
    runId, adjustReviewSaveId: accAdj2.reviewSaveId, typedPhrase: 'create statements for 2026-11-21',
  });

  // CR-1: Saving Adjust review AFTER Emit is confirmed MUST BE REFUSED!
  const seqAfterConfirm = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await assert.rejects(
    () => env.commands.submitReview({
      actor: env.ownerActor, commandKey: 'sub-adj-after-emit-confirm', expectedJournalSeq: seqAfterConfirm,
      runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave, rowAdj1, rowAdj2]), 'utf8'),
    }),
    /CR-1|open request|Emit/i,
  );

  assert.equal((await worker.runOnce()).action, 'step_finished'); // emit

  // CR-10: Drafts refused after Emit
  await assert.rejects(
    () => env.commands.saveReviewDraft({ actor: env.ownerActor, runId, surface: 'adjust', attemptNo: 2, born: 'b1', checksum: 'c2', rows: [] }),
    /CR-10|after Emit/i,
  );
});

test('Layer 3 [R9.6, R10.3 & R11 audit]: running slot mutual exclusion and out-of-transaction liveness checks', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
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
  assert.ok(slot1);
  t.after(() => slot1.release());

  assert.equal(await acquireRunningSlot({ pgConfig: env.pgConfig, livenessIntervalMs: 0 }), null);

  await slot1.runExclusive(async (client) => {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    await new Promise((r) => setTimeout(r, 180));
    await client.query('COMMIT');
  });
  await new Promise((r) => setTimeout(r, 120));
  assert.equal(livenessInTxCount, 0, 'liveness query must NEVER run inside a transaction (R10.3, R11)');
  assert.ok(livenessQueries >= 1);

  await slot1.release();
  const slot3 = await acquireRunningSlot({ pgConfig: env.pgConfig, livenessIntervalMs: 0 });
  assert.ok(slot3);
  await slot3.release();
});

test('Layer 3 [R10.7, R10.9 & R18]: rejected review submission does not promote bytes or stall worker; frozen input mutation fails step', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:aetna:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: 'phalanx', stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));

  const launch = await env.commands.launchRun({ actor: env.ownerActor, commandKey: 'launch-rev-test', statementDate: '2026-11-21', engineVersionId });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');

  // RP-1: Between finished steps / waiting for Bible, reconciler finds ZERO open attempts
  assert.equal((await reconcileInterruptedAttempts({ pool: env.pool, commands: env.commands, workerActor: env.workerActor })).interrupted.length, 0);

  // Bad review file (drops prior row!)
  const badCsv = makeOverlayCsv([sampleApprovalRow({ record_id: 'policy:aetna:OTHER#effective:2026-01-01' })]);
  const seq1 = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const badSub = await env.commands.submitReview({
    actor: env.ownerActor, commandKey: 'sub-bad', expectedJournalSeq: seq1, runId, surface: 'bible', csvBytes: Buffer.from(badCsv, 'utf8'),
  });
  const objectsBefore = env.dataBackend.listObjectNames().filter((n) => n.startsWith('objects/')).length;
  assert.equal((await worker.runOnce()).action, 'review_rejected');
  assert.equal(env.dataBackend.listObjectNames().filter((n) => n.startsWith('objects/')).length, objectsBefore);
  assert.equal((await env.pool.query('SELECT status FROM coherence.review_submissions WHERE id = $1::uuid', [badSub.submissionId])).rows[0].status, 'rejected');

  // Worker NOT stalled -> valid Bible review accepted immediately
  const goodCsv = makeOverlayCsv([row0, sampleApprovalRow({ record_id: 'policy:aetna:P10001#effective:2026-01-01' })]);
  await env.commands.submitReview({
    actor: env.ownerActor, commandKey: 'sub-good', expectedJournalSeq: seq1, runId, surface: 'bible', csvBytes: Buffer.from(goodCsv, 'utf8'),
  });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished'); // adjust
  assert.equal((await verifyObjects(env.pool, env.stores, { deep: true })).passed, true);

  // R10.9: Mutating frozen input inside a step fails the step
  const mutWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: 'phalanx', stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer({ mutateFrozenInputStep: 'assign' }), tempBaseDir: env.tempDir,
  }));
  const launch2 = await env.commands.launchRun({ actor: env.ownerActor, commandKey: 'launch-mut', statementDate: '2026-11-22', engineVersionId });
  assert.equal((await mutWorker.runOnce()).action, 'step_failed');
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [launch2.result.runId])).rows[0].stage, 'failed');
});

test('Layer 3 [R10.1, R10.2, R11 (RP-1, RP-2, W-4) & Clarification #5]: worker death mid-step and before finish -> never finished; reconciler marks interrupted on free OR new-worker slot, refuses while starter holds slot', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  await seedStandingInput(env);

  const launch = await env.commands.launchRun({ actor: env.ownerActor, commandKey: 'launch-kill', statementDate: '2026-11-21', engineVersionId });
  const runId = launch.result.runId;
  const adminKiller = env.registerClient(await createClient(env.pgConfig));

  // Case 1: While original starter STILL holds slot, DB refuses marking attempt interrupted!
  let refusedWhileOwned = false;
  const dyingWorker1 = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: 'phalanx', stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir, livenessIntervalMs: 50,
    onAfterStart: async ({ slot }) => {
      // Attempt to interrupt while original starter holds slot MUST fail!
      await assert.rejects(
        () => env.commands.interruptStepAttempt({
          actor: env.workerActor, commandKey: 'illegal-interrupt-while-alive', runId, step: 'assign', attemptNo: 1,
        }),
        /owning worker still holds the slot/i,
      );
      refusedWhileOwned = true;
      await adminKiller.query('SELECT pg_catalog.pg_terminate_backend($1)', [slot.backendPid]);
      await new Promise((r) => setTimeout(r, 150));
    },
  }));
  assert.equal((await dyingWorker1.runOnce()).action, 'slot_lost');
  assert.equal(refusedWhileOwned, true);

  // Reconciler marks dead attempt interrupted when slot is free
  const rec1 = await reconcileInterruptedAttempts({ pool: env.pool, commands: env.commands, workerActor: env.workerActor });
  assert.equal(rec1.interrupted.length, 1);
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].stage, 'interrupted');

  // Case 2 (RP-2): Kill AFTER Coherence wrote run.json mark, right BEFORE DB finish commit -> NEVER finished!
  await env.commands.requestRetry({ actor: env.ownerActor, commandKey: 'retry-assign-2', runId, step: 'assign' });
  const dyingWorker2 = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: 'phalanx', stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir, livenessIntervalMs: 50,
    onBeforeFinish: async ({ slot }) => {
      await adminKiller.query('SELECT pg_catalog.pg_terminate_backend($1)', [slot.backendPid]);
      await new Promise((r) => setTimeout(r, 150));
    },
  }));
  assert.equal((await dyingWorker2.runOnce()).action, 'slot_lost');
  const finCount = await env.pool.query(
    "SELECT COUNT(*)::int AS n FROM coherence.step_attempt_events WHERE run_id = $1::uuid AND step = 'assign' AND event_kind = 'finished'",
    [runId],
  );
  assert.equal(finCount.rows[0].n, 0);

  // Clarification #5: New healthy worker holding the slot on a DIFFERENT connection reconciles attempt 2 cleanly!
  const healthyWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: 'phalanx', stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));
  const idleAfterRec = await healthyWorker.runOnce();
  assert.equal(idleAfterRec.reconciled, 1);

  await env.commands.requestRetry({ actor: env.ownerActor, commandKey: 'retry-assign-3', runId, step: 'assign' });
  const okAssign = await healthyWorker.runOnce();
  assert.equal(okAssign.action, 'step_finished');
  assert.equal(okAssign.attemptNo, 3);
  assert.equal(okAssign.nextStep, 'attribute');

  // RP-1: Between assign (finished) and attribute (requested), reconciler marks NOTHING interrupted
  assert.equal((await reconcileInterruptedAttempts({ pool: env.pool, commands: env.commands, workerActor: env.workerActor })).interrupted.length, 0);
});

test('Layer 3 [R10.4 & R18]: typed cancel stops entire engine process group (including grandchild); step time limit stops hung step', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  await seedStandingInput(env);

  const grandchildPidFile = join(env.tempDir, 'grandchild.pid');
  const launch1 = await env.commands.launchRun({ actor: env.ownerActor, commandKey: 'launch-cancel', statementDate: '2026-11-21', engineVersionId });
  const run1 = launch1.result.runId;

  const cancelWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: 'phalanx', stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer({ sleepStep: 'assign', sleepSeconds: 30, spawnGrandchildPidFile: grandchildPidFile }),
    tempBaseDir: env.tempDir, cancelPollMs: 100,
  }));

  const workPromise = cancelWorker.runOnce();
  let grandchildPid = null;
  for (let i = 0; i < 60; i++) {
    if (await stat(grandchildPidFile).then(() => true, () => false)) {
      grandchildPid = Number((await readFile(grandchildPidFile, 'utf8')).trim());
      if (grandchildPid > 0) break;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(grandchildPid > 0, 'grandchild process should have spawned');

  await env.commands.requestCancel({
    actor: env.ownerActor, commandKey: 'cancel-run1', runId: run1, step: 'assign', attemptNo: 1,
    typedPhrase: 'cancel 2026-11-21', reason: 'stop test step',
  });

  assert.equal((await workPromise).action, 'step_cancelled');
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [run1])).rows[0].stage, 'cancelled');

  await new Promise((r) => setTimeout(r, 200));
  let grandchildAlive = true;
  try { process.kill(grandchildPid, 0); } catch { grandchildAlive = false; }
  assert.equal(grandchildAlive, false, 'process-group kill must terminate grandchild processes too');

  // Step time limit stops hung step
  const launch2 = await env.commands.launchRun({ actor: env.ownerActor, commandKey: 'launch-timeout', statementDate: '2026-11-22', engineVersionId });
  const timeoutWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: 'phalanx', stores: env.stores, commands: env.commands, workerActor: env.workerActor,
    materializeEngine: createMockEngineMaterializer({ sleepStep: 'assign', sleepSeconds: 30 }),
    tempBaseDir: env.tempDir, stepTimeoutMs: 600,
  }));
  assert.equal((await timeoutWorker.runOnce()).action, 'step_timed_out');
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [launch2.result.runId])).rows[0].stage, 'failed');
});
