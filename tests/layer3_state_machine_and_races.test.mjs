// Layer 3: protects workflow state integrity, concurrency safety, declarative state-machine parity,
// and worker fault recovery.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createCommandLayer } from '../src/commands/command-layer.mjs';
import { verifyChain, verifyCommitments, verifyObjects } from '../src/commands/journal-export.mjs';
import { createClient } from '../src/db/pg-client.mjs';
import {
  deriveRunStage,
  generateStateMachineMarkdown,
  RUN_STAGE_MACHINE,
  STEP_ATTEMPT_MACHINE,
  verifyCoherenceStateMachinesAgainstDb,
} from '../src/state-machine/coherence-machines.mjs';
import { defineStateMachine, StateMachineDefinitionError } from '../src/state-machine/declarative-machine.mjs';
import { createSafeLogger } from '../src/util/redact.mjs';
import { killProcessGroup, runCoherenceProcess } from '../src/worker/engine-runner.mjs';
import { reconcileInterruptedAttempts } from '../src/worker/reconciler.mjs';
import { acquireRunningSlot } from '../src/worker/slot.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import {
  createDataOnlyMockEngineMaterializer,
  createMockEngineMaterializer,
  makeOverlayCsv,
  sampleApprovalRow,
  seedEngineCopyVersion,
  seedEngineVersion,
  seedStandingInput,
} from './helpers/fixtures.mjs';
import { createRoleScopedTestPool, seedCoherenceIamFixture } from './helpers/iam-harness.mjs';
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pgCheck = await checkPgAvailable();

async function runToBibleWaiting(env, worker, { statementDate = '2026-11-21', origin = 'app', engineVersionId, rerunReason = null } = {}) {
  const launch = await env.commands.launchRun({
    dbToken: env.ownerToken,
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

test('Layer 3 [State Machine as Data]: reusable machine validation, strict SQL RETURN literal check, STATE_MACHINE.md parity, and live walkthrough of all 11 run stages and 7 attempt states', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
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

  assert.equal(RUN_STAGE_MACHINE.verifyGraph().ok, true);
  assert.equal(STEP_ATTEMPT_MACHINE.verifyGraph().ok, true);
  const diskDoc = await readFile(resolve(REPO_ROOT, 'STATE_MACHINE.md'), 'utf8');
  assert.equal(diskDoc, generateStateMachineMarkdown(), 'STATE_MACHINE.md must match generated output from src/state-machine/coherence-machines.mjs');

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

  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const dbVerify = await verifyCoherenceStateMachinesAgainstDb(env.pool);
  assert.equal(dbVerify.passed, true, `State machine DB verification failed: ${dbVerify.problems.join('; ')}`);

  await env.pool.query(`
    CREATE OR REPLACE FUNCTION coherence.test_where_only_stage()
    RETURNS text
    LANGUAGE plpgsql STABLE
    SET search_path = pg_catalog
    AS $$
    BEGIN
      IF EXISTS (SELECT 1 FROM coherence.step_attempt_events WHERE event_kind IN ('failed')) THEN
        RETURN 'ok';
      END IF;
      RETURN 'ok';
    END;
    $$;
  `);
  const whereOnlyMachine = defineStateMachine({
    id: 'test-where-only',
    title: 'Where Only Test',
    states: [{ id: 'ok', initial: true }, { id: 'failed', terminal: true }],
    transitions: [{ id: 'fail', from: ['ok'], to: 'failed' }],
    dbChecks: [{ kind: 'derived_stage_literals', function: 'coherence.test_where_only_stage', indirectReturns: ['failed'] }],
  });
  assert.equal((await whereOnlyMachine.verifyAgainstPostgres(env.pool)).passed, false);

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
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const l1 = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'sm-r1', statementDate: '2026-11-21', engineVersionId });
  const r1 = l1.result.runId;
  observedAttemptStates.add('requested');
  await recordStage(r1, { openRequestStep: 'assign' });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: env.companySlug,
    stores: env.stores,
    commands: env.commands,
    workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(),
    tempBaseDir: env.tempDir,
    onAfterStart: async ({ run, step }) => {
      observedAttemptStates.add('started');
      await recordStage(run.id, { openAttemptStep: step });
    },
  }));
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  observedAttemptStates.add('finished');
  await recordStage(r1, { bibleFinished: true });

  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [r1])).rows[0].latest_journal_seq);
  const bibleRows = [row0, sampleApprovalRow({ record_id: 'policy:carrier_a:P10001#effective:2026-01-01' })];
  await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: 'sm-b1', expectedJournalSeq: seq, runId: r1, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished');
  await recordStage(r1, { bibleFinished: true, adjustFinished: true, hasAdjustSaveForCurrentAdjust: false });

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [r1])).rows[0].latest_journal_seq);
  await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: 'sm-b2', expectedJournalSeq: seq, runId: r1, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv([...bibleRows, sampleApprovalRow({ note: 'b2' })]), 'utf8') });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  observedAttemptStates.add('superseded');
  assert.equal((await worker.runOnce()).action, 'step_finished');

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [r1])).rows[0].latest_journal_seq);
  const adjRows = [...bibleRows, sampleApprovalRow({ note: 'b2' }), sampleApprovalRow({ record_id: 'carrier_a~direct~P10001~100.00~2026-11' })];
  await env.commands.submitReview({ dbToken: env.ownerToken, commandKey: 'sm-a1', expectedJournalSeq: seq, runId: r1, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
  const adjAcc = await worker.runOnce();
  assert.equal(adjAcc.action, 'review_accepted');
  await recordStage(r1, { bibleFinished: true, adjustFinished: true, hasAdjustSaveForCurrentAdjust: true });

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [r1])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({ dbToken: env.ownerToken, commandKey: 'sm-e1', expectedJournalSeq: seq, runId: r1, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: 'create statements for 2026-11-21' });
  await recordStage(r1, { openRequestStep: 'emit' });
  assert.equal((await worker.runOnce()).action, 'step_finished');
  await recordStage(r1, { emitFinished: true });

  await env.commands.abandonRun({ dbToken: env.ownerToken, commandKey: 'sm-ab1', runId: r1, typedPhrase: 'abandon 2026-11-21', reason: 'state walkthrough' });
  await recordStage(r1, { abandoned: true });

  const l2 = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'sm-r2', statementDate: '2026-11-22', engineVersionId });
  const failWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer({ failStep: 'assign' }), tempBaseDir: env.tempDir,
  }));
  assert.equal((await failWorker.runOnce()).action, 'step_failed');
  observedAttemptStates.add('failed');
  await recordStage(l2.result.runId, { latestNonSupersededEndKind: 'failed' });

  const l3 = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'sm-r3', statementDate: '2026-11-23', engineVersionId });
  const killer = env.registerClient(await createClient(env.pgConfig));
  const dieWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir, livenessIntervalMs: 50,
    onAfterStart: async ({ slot }) => {
      await killer.query('SELECT pg_catalog.pg_terminate_backend($1)', [slot.backendPid]);
      await new Promise((r) => setTimeout(r, 120));
    },
  }));
  assert.equal((await dieWorker.runOnce()).action, 'slot_lost');
  const rec = await reconcileInterruptedAttempts({ pool: env.pool, commands: env.commands, workerToken: env.workerToken });
  assert.equal(rec.interrupted.length, 1);
  observedAttemptStates.add('interrupted');
  await recordStage(l3.result.runId, { latestNonSupersededEndKind: 'interrupted' });

  const l4 = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'sm-r4', statementDate: '2026-11-24', engineVersionId });
  const cancelWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer({ sleepStep: 'assign', sleepSeconds: 20 }), tempBaseDir: env.tempDir, cancelPollMs: 80,
    onAfterStart: async ({ run }) => {
      await env.commands.requestCancel({ dbToken: env.ownerToken, commandKey: 'sm-c4', runId: run.id, step: 'assign', attemptNo: 1, typedPhrase: 'cancel 2026-11-24', reason: 'sm test' });
    },
  }));
  assert.equal((await cancelWorker.runOnce()).action, 'step_cancelled');
  observedAttemptStates.add('cancelled');
  await recordStage(l4.result.runId, { latestNonSupersededEndKind: 'cancelled' });

  assert.deepEqual([...observedRunStages].sort(), [...RUN_STAGE_MACHINE.nonPseudoStateIds].sort());
  assert.deepEqual([...observedAttemptStates].sort(), [...STEP_ATTEMPT_MACHINE.nonPseudoStateIds].sort());
});

test('Layer 3 [Idempotency & Permissions]: idempotent resend acts once, reused command key with any difference is refused, and staff permissions enforced', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  await seedStandingInput(env);

  const iam = env.iam;
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const appCommands = createCommandLayer({ pool: appPool, companySlug: env.companySlug, stores: env.stores });

  // Database-only IAM additive role enforcement: Nusear Admin lacking coherence_operator role and
  // coherence_operator granted only on another company (Northstar) are both refused with 403 (42501).
  await assert.rejects(
    () => appCommands.launchRun({ dbToken: iam.tokens.adminNoCoh, commandKey: 'wh-launch', statementDate: '2026-11-21', engineVersionId }),
    (err) => err?.status === 403 && err?.code === 'FORBIDDEN',
  );
  await assert.rejects(
    () => appCommands.launchRun({ dbToken: iam.tokens.wrongCoOperator, commandKey: 'wc-launch', statementDate: '2026-11-21', engineVersionId }),
    (err) => err?.status === 403 && err?.code === 'FORBIDDEN',
  );

  // Nusear owner / operator direct writes record acting_for = 'nusear_support'
  const first = await appCommands.launchRun({
    dbToken: iam.tokens.owner, commandKey: 'launch-idem-key', statementDate: '2026-11-21', engineVersionId,
  });
  assert.equal(first.idempotent, false);
  const jeRow = await env.pool.query('SELECT acting_for FROM coherence.journal_entries WHERE seq = $1', [String(first.journalSeq)]);
  assert.equal(jeRow.rows[0].acting_for, 'nusear_support');

  // Item 8: Replay returns the FULL stored result object verbatim (including folderNumber, statementDate, origin, etc.)
  const resend = await appCommands.launchRun({
    dbToken: iam.tokens.owner, commandKey: 'launch-idem-key', statementDate: '2026-11-21', engineVersionId,
  });
  assert.equal(resend.idempotent, true);
  assert.equal(resend.journalSeq, first.journalSeq);
  assert.deepEqual(resend.result, first.result, 'idempotent replay must return the complete stored result object');

  await assert.rejects(
    () => appCommands.launchRun({ dbToken: iam.tokens.owner, commandKey: 'launch-idem-key', statementDate: '2026-11-22', engineVersionId }),
    (err) => err?.status === 409 && /already used for a different request/i.test(err.message),
  );
  await assert.rejects(
    () => appCommands.launchRun({ dbToken: iam.tokens.operator, commandKey: 'launch-idem-key', statementDate: '2026-11-21', engineVersionId }),
    (err) => err?.status === 409 && /already used for a different request/i.test(err.message),
  );
  await assert.rejects(
    () => appCommands.abandonRun({ dbToken: iam.tokens.owner, commandKey: 'launch-idem-key', runId: first.result.runId, typedPhrase: 'abandon 2026-11-21', reason: 'test' }),
    (err) => err?.status === 409 && /already used for a different request/i.test(err.message),
  );

  // Item 8: request_sha256 covers EVERY array in normalized requests (changing an array element with same commandKey refuses 409).
  const fA = await env.dataStore.promoteBytes(Buffer.from('a,b\n1,2\n', 'utf8'), { relPath: 'hist/a.csv', checksPassed: true });
  const fB = await env.dataStore.promoteBytes(Buffer.from('a,b\n3,4\n', 'utf8'), { relPath: 'hist/b.csv', checksPassed: true });
  const hist1 = await appCommands.importHistoricalRun({
    dbToken: iam.tokens.owner,
    commandKey: 'hist-array-hash-key',
    run: { origin: 'company_import', statementDate: '2026-10-01', sourceFolder: 'company-runs/2026-10-01-idem', emitMode: 'coherence' },
    inputVersion: { reason: 'idem array test' },
    inputEntries: [{ relPath: 'hist/a.csv', fileSha256: fA.sha256 }],
    storedFiles: [fA],
  });
  const histReplay = await appCommands.importHistoricalRun({
    dbToken: iam.tokens.owner,
    commandKey: 'hist-array-hash-key',
    run: { origin: 'company_import', statementDate: '2026-10-01', sourceFolder: 'company-runs/2026-10-01-idem', emitMode: 'coherence' },
    inputVersion: { reason: 'idem array test' },
    inputEntries: [{ relPath: 'hist/a.csv', fileSha256: fA.sha256 }],
    storedFiles: [fA],
  });
  assert.equal(histReplay.idempotent, true);
  assert.equal(histReplay.result.runId, hist1.result.runId);
  assert.equal(histReplay.result.alreadyImported, false);
  await assert.rejects(
    () => appCommands.importHistoricalRun({
      dbToken: iam.tokens.owner,
      commandKey: 'hist-array-hash-key',
      run: { origin: 'company_import', statementDate: '2026-10-01', sourceFolder: 'company-runs/2026-10-01-idem', emitMode: 'coherence' },
      inputVersion: { reason: 'idem array test' },
      inputEntries: [{ relPath: 'hist/b.csv', fileSha256: fB.sha256 }],
      storedFiles: [fB],
    }),
    (err) => err?.status === 409 && /already used for a different request/i.test(err.message),
    'reusing commandKey with different inputEntries array content must refuse with 409',
  );
});

test('Layer 3 [Concurrency & Review Guards]: racing commands, review save vs Emit confirmation, Bible re-save rules, and attempt-keyed drafts', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));

  const { runId, latestSeq } = await runToBibleWaiting(env, worker, { statementDate: '2026-11-21', engineVersionId });

  const rowBible1 = sampleApprovalRow({ record_id: 'policy:carrier_a:P10001#effective:2026-01-01', note: 'tab1' });
  const rowBible2 = sampleApprovalRow({ record_id: 'policy:carrier_a:P10001#effective:2026-01-01', note: 'tab2' });
  const [r1, r2] = await Promise.allSettled([
    env.commands.submitReview({
      dbToken: env.ownerToken, commandKey: 'sub-tab-1', expectedJournalSeq: latestSeq,
      runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBible1]), 'utf8'),
    }),
    env.commands.submitReview({
      dbToken: env.ownerToken, commandKey: 'sub-tab-2', expectedJournalSeq: latestSeq,
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

  await env.commands.saveReviewDraft({
    dbToken: env.ownerToken, runId, surface: 'adjust', attemptNo: 1, born: 'b1', checksum: 'c1', rows: [{ record_id: 'x' }],
  });
  assert.ok(await env.commands.getReviewDraft({ dbToken: env.ownerToken, runId, surface: 'adjust', attemptNo: 1 }));
  await assert.rejects(
    () => env.commands.saveReviewDraft({ dbToken: env.ownerToken, runId, surface: 'adjust', attemptNo: 2, born: 'b1', checksum: 'c1', rows: [] }),
    /current finished/i,
  );

  const seqBeforeResave = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const rowBibleResave = sampleApprovalRow({ record_id: 'policy:carrier_a:P10001#effective:2026-01-01', note: 'bible-resave' });
  await env.commands.submitReview({
    dbToken: env.ownerToken, commandKey: 'sub-bible-resave', expectedJournalSeq: seqBeforeResave,
    runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave]), 'utf8'),
  });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  const adj2 = await worker.runOnce();
  assert.equal(adj2.action, 'step_finished');
  assert.equal(adj2.attemptNo, 2);
  assert.equal(await env.commands.getReviewDraft({ dbToken: env.ownerToken, runId, surface: 'adjust', attemptNo: 2 }), null);

  const seqAfterAdj2 = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const rowAdj1 = sampleApprovalRow({ record_id: 'carrier_a~direct~P10001~100.00~2026-11', note: 'adj-1' });
  await env.commands.submitReview({
    dbToken: env.ownerToken, commandKey: 'sub-adj-1', expectedJournalSeq: seqAfterAdj2,
    runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave, rowAdj1]), 'utf8'),
  });
  const accAdj1 = await worker.runOnce();
  assert.equal(accAdj1.action, 'review_accepted');

  const seqAfterAdj1 = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await assert.rejects(
    () => env.commands.submitReview({
      dbToken: env.ownerToken, commandKey: 'sub-bible-after-adj', expectedJournalSeq: seqAfterAdj1,
      runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave]), 'utf8'),
    }),
    /Adjust review was saved/i,
  );

  const rowAdj2 = sampleApprovalRow({ record_id: 'carrier_a~direct~P10001~100.00~2026-11', note: 'adj-2' });
  await env.commands.submitReview({
    dbToken: env.ownerToken, commandKey: 'sub-adj-2', expectedJournalSeq: seqAfterAdj1,
    runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave, rowAdj1, rowAdj2]), 'utf8'),
  });
  await assert.rejects(
    () => env.commands.confirmEmit({
      dbToken: env.ownerToken, commandKey: 'emit-while-pending', expectedJournalSeq: seqAfterAdj1,
      runId, adjustReviewSaveId: accAdj1.reviewSaveId, typedPhrase: 'create statements for 2026-11-21',
    }),
    /review submission is waiting/i,
  );

  const accAdj2 = await worker.runOnce();
  assert.equal(accAdj2.action, 'review_accepted');

  const seqReady = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await assert.rejects(
    () => env.commands.confirmEmit({
      dbToken: env.ownerToken, commandKey: 'emit-stale-save', expectedJournalSeq: seqReady,
      runId, adjustReviewSaveId: accAdj1.reviewSaveId, typedPhrase: 'create statements for 2026-11-21',
    }),
    /newest Adjust review save/i,
  );

  await env.commands.confirmEmit({
    dbToken: env.ownerToken, commandKey: 'emit-ok', expectedJournalSeq: seqReady,
    runId, adjustReviewSaveId: accAdj2.reviewSaveId, typedPhrase: 'create statements for 2026-11-21',
  });

  const seqAfterConfirm = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await assert.rejects(
    () => env.commands.submitReview({
      dbToken: env.ownerToken, commandKey: 'sub-adj-after-emit-confirm', expectedJournalSeq: seqAfterConfirm,
      runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave, rowAdj1, rowAdj2]), 'utf8'),
    }),
    /open request|Emit/i,
  );

  assert.equal((await worker.runOnce()).action, 'step_finished');

  await assert.rejects(
    () => env.commands.saveReviewDraft({ dbToken: env.ownerToken, runId, surface: 'adjust', attemptNo: 2, born: 'b1', checksum: 'c2', rows: [] }),
    /after Emit/i,
  );
});

test('Layer 3 [Running Slot]: mutual exclusion, out-of-transaction liveness checks, and sanitized logging of onSlotLost listener errors', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
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
  assert.equal(livenessInTxCount, 0, 'liveness query must never run inside a transaction');
  assert.ok(livenessQueries >= 1);

  await slot1.release();

  const logs = [];
  const logger = createSafeLogger({ log: (l) => logs.push(l), warn: (l) => logs.push(l), error: (l) => logs.push(l) });
  const slot3 = await acquireRunningSlot({
    pgConfig: env.pgConfig,
    livenessIntervalMs: 0,
    logger,
    onSlotLost: () => { throw new Error('listener exploded carrier_a~direct~HIDDEN PERSON~50.00'); },
  });
  assert.ok(slot3);
  t.after(() => slot3.release());
  slot3.abort('simulated loss');
  assert.equal(slot3.signal.aborted, true);
  assert.ok(logs.some((l) => l.includes('slot_lost_listener_error')));
  assert.ok(logs.every((l) => !l.includes('HIDDEN PERSON')));
});

test('Layer 3 [Review & Input Verification]: rejected review submission does not promote bytes or stall worker; frozen input mutation fails step', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:PRIOR#effective:2026-01-01' });
  await seedStandingInput(env, { withPriorOverlay: { version: 'v2', rows: [row0], csv: makeOverlayCsv([row0]) } });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));

  const launch = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'launch-rev-test', statementDate: '2026-11-21', engineVersionId });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');

  assert.equal((await reconcileInterruptedAttempts({ pool: env.pool, commands: env.commands, workerToken: env.workerToken })).interrupted.length, 0);

  const badCsv = makeOverlayCsv([sampleApprovalRow({ record_id: 'policy:carrier_a:OTHER#effective:2026-01-01' })]);
  const seq1 = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const badSub = await env.commands.submitReview({
    dbToken: env.ownerToken, commandKey: 'sub-bad', expectedJournalSeq: seq1, runId, surface: 'bible', csvBytes: Buffer.from(badCsv, 'utf8'),
  });
  const objectsBefore = env.dataBackend.listObjectNames().filter((n) => n.startsWith('objects/')).length;
  assert.equal((await worker.runOnce()).action, 'review_rejected');
  assert.equal(env.dataBackend.listObjectNames().filter((n) => n.startsWith('objects/')).length, objectsBefore);
  assert.equal((await env.pool.query('SELECT status FROM coherence.review_submissions WHERE id = $1::uuid', [badSub.submissionId])).rows[0].status, 'rejected');

  const goodCsv = makeOverlayCsv([row0, sampleApprovalRow({ record_id: 'policy:carrier_a:P10001#effective:2026-01-01' })]);
  await env.commands.submitReview({
    dbToken: env.ownerToken, commandKey: 'sub-good', expectedJournalSeq: seq1, runId, surface: 'bible', csvBytes: Buffer.from(goodCsv, 'utf8'),
  });
  assert.equal((await worker.runOnce()).action, 'review_accepted');
  assert.equal((await worker.runOnce()).action, 'step_finished');
  assert.equal((await verifyObjects(env.pool, env.stores, { deep: true })).passed, true);

  const mutWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer({ mutateFrozenInputStep: 'assign' }), tempBaseDir: env.tempDir,
  }));
  const launch2 = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'launch-mut', statementDate: '2026-11-22', engineVersionId });
  assert.equal((await mutWorker.runOnce()).action, 'step_failed');
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [launch2.result.runId])).rows[0].stage, 'failed');
});

test('Layer 3 [Worker Death & Reconciliation]: worker death mid-step and before finish never finishes; reconciler marks interrupted on free or replacement slot, refuses while starter holds slot', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  await seedStandingInput(env);

  const launch = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'launch-kill', statementDate: '2026-11-21', engineVersionId });
  const runId = launch.result.runId;
  const adminKiller = env.registerClient(await createClient(env.pgConfig));

  let refusedWhileOwned = false;
  const dyingWorker1 = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir, livenessIntervalMs: 50,
    onAfterStart: async ({ slot }) => {
      await assert.rejects(
        () => env.commands.interruptStepAttempt({
          dbToken: env.workerToken, commandKey: 'illegal-interrupt-while-alive', runId, step: 'assign', attemptNo: 1,
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

  const rec1 = await reconcileInterruptedAttempts({ pool: env.pool, commands: env.commands, workerToken: env.workerToken });
  assert.equal(rec1.interrupted.length, 1);
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].stage, 'interrupted');

  // Kill worker after step completion on disk but before DB finish commit; attempt must never become finished.
  await env.commands.requestRetry({ dbToken: env.ownerToken, commandKey: 'retry-assign-2', runId, step: 'assign' });
  const dyingWorker2 = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
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

  // A replacement worker holding the slot on a new connection reconciles the dead worker's open attempt cleanly.
  const healthyWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer(), tempBaseDir: env.tempDir,
  }));
  const idleAfterRec = await healthyWorker.runOnce();
  assert.equal(idleAfterRec.reconciled, 1);

  await env.commands.requestRetry({ dbToken: env.ownerToken, commandKey: 'retry-assign-3', runId, step: 'assign' });
  const okAssign = await healthyWorker.runOnce();
  assert.equal(okAssign.action, 'step_finished');
  assert.equal(okAssign.attemptNo, 3);
  assert.equal(okAssign.nextStep, 'attribute');

  assert.equal((await reconcileInterruptedAttempts({ pool: env.pool, commands: env.commands, workerToken: env.workerToken })).interrupted.length, 0);
});

test('Layer 3 [Cancel, Timeout & Process Group Safety]: typed cancel stops grandchild, timeout stops hung step, cancel-poll errors escalate, and killProcessGroup reports EPERM', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  await seedStandingInput(env);

  const grandchildPidFile = join(env.tempDir, 'grandchild.pid');
  const launch1 = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'launch-cancel', statementDate: '2026-11-21', engineVersionId });
  const run1 = launch1.result.runId;

  const cancelWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
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
    dbToken: env.ownerToken, commandKey: 'cancel-run1', runId: run1, step: 'assign', attemptNo: 1,
    typedPhrase: 'cancel 2026-11-21', reason: 'stop test step',
  });

  assert.equal((await workPromise).action, 'step_cancelled');
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [run1])).rows[0].stage, 'cancelled');

  await new Promise((r) => setTimeout(r, 200));
  let grandchildAlive = true;
  try { process.kill(grandchildPid, 0); } catch { grandchildAlive = false; }
  assert.equal(grandchildAlive, false, 'process-group kill must terminate grandchild processes too');

  const launch2 = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'launch-timeout', statementDate: '2026-11-22', engineVersionId });
  const timeoutWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug, stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createMockEngineMaterializer({ sleepStep: 'assign', sleepSeconds: 30 }),
    tempBaseDir: env.tempDir, stepTimeoutMs: 600,
  }));
  assert.equal((await timeoutWorker.runOnce()).action, 'step_timed_out');
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [launch2.result.runId])).rows[0].stage, 'failed');

  const pollLogs = [];
  const pollLogger = createSafeLogger({ log: (l) => pollLogs.push(l), warn: (l) => pollLogs.push(l), error: (l) => pollLogs.push(l) });
  const pollDir = await mkdtemp(join(tmpdir(), 'coherence-cancel-poll-'));
  t.after(() => rm(pollDir, { recursive: true, force: true }));
  const pollRes = await runCoherenceProcess({
    pythonPath: 'python3',
    args: ['-c', 'import time; time.sleep(10)'],
    workspaceDir: pollDir,
    logPath: join(pollDir, 'poll.log'),
    timeoutMs: 8000,
    cancelPollMs: 40,
    maxCancelPollFailures: 3,
    logger: pollLogger,
    checkCancelled: async () => { throw new Error('DB poll failed on carrier_a~direct~LEAKED NAME~100.00'); },
  });
  assert.equal(pollRes.outcome, 'cancel_poll_failed');
  assert.ok(pollLogs.some((l) => l.includes('cancel_poll_failed')));
  assert.ok(pollLogs.every((l) => !l.includes('LEAKED NAME')));

  const killLogs = [];
  const killReported = [];
  const killLogger = createSafeLogger({ log: (l) => killLogs.push(l), warn: (l) => killLogs.push(l), error: (l) => killLogs.push(l) });
  const killTimer = killProcessGroup(999999, 20, {
    killFn: () => {
      const e = new Error('Operation not permitted');
      e.code = 'EPERM';
      throw e;
    },
    logger: killLogger,
    onError: (err) => killReported.push(err.code),
  });
  await new Promise((r) => setTimeout(r, 60));
  if (killTimer) clearTimeout(killTimer);
  assert.ok(killReported.includes('EPERM'));
  assert.ok(killLogs.some((l) => l.includes('process_group_kill_failed')));
});

test('Layer 3 [Synchronous Review Command & Engine Copy Workflow]: engine_kind registration, stale/duplicate/race save refusals, queue coverage & reconfirm guards, generated overlays, auto Emit materialization, and S-8 carryDecisions', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  // 1. engine_kind = 'engine_copy' succeeds without node/pnpm/webLock while legacy_sealed still requires them
  const { engineVersionId } = await seedEngineCopyVersion(env);
  const copyRow = (await env.pool.query('SELECT engine_kind, upstream_commit, patch_diff_sha256, web_lock_sha256 FROM coherence.engine_versions WHERE id = $1::uuid', [engineVersionId])).rows[0];
  assert.equal(copyRow.engine_kind, 'engine_copy');
  assert.equal(copyRow.upstream_commit, '809c6ea');
  assert.ok(copyRow.patch_diff_sha256);
  assert.equal(copyRow.web_lock_sha256, null);

  const codePromo = (rel, txt) => env.codeStore.promoteBytes(Buffer.from(txt, 'utf8'), { relPath: rel, checksPassed: true });
  await assert.rejects(
    async () => env.commands.registerEngineVersion({
      dbToken: env.ownerToken,
      commandKey: 'legacy-missing-web',
      label: 'legacy-bad',
      coherenceCommit: '809c6ea',
      engineKind: 'legacy_sealed',
      gitBundle: await codePromo('engine/b.bundle', 'b'),
      codeManifest: await codePromo('engine/m.json', '{}'),
      pythonLock: await codePromo('engine/u.lock', 'v=1'),
      pythonWheels: await codePromo('engine/w.tar', 'w'),
      wrapperBundle: await codePromo('engine/wr.json', '{}'),
      nusearCommit: 'abc1234',
      overlayCheckSha256: '0'.repeat(64),
      toolchain: { os: 'Darwin', os_version: '24', arch: 'arm64', python: '3.12', uv: '0.5', tz: 'America/New_York', lang: 'en_US.UTF-8', lc_all: 'en_US.UTF-8', pythonutf8: '1' },
    }),
    /check constraint|toolchain|kind_requirements/i,
  );

  // 2. Seed standing inputs + standing decision baseline (with an old decision for the Adjust reconfirm key)
  await seedStandingInput(env, { commandKey: 'sync-standing-input' });
  const reconfKey = 'carrier_a~direct~PAT SAMPLE~100.00~2026-10';
  const baseDec = await env.commands.recordDecisionBaseline({
    dbToken: env.ownerToken,
    commandKey: 'sync-baseline',
    commitKind: 'historical_baseline',
    decisions: [{
      recordId: reconfKey,
      disposition: 'CONFIRM',
      approvedAmount: '90.00',
      approvedAgency: 'Beacon',
      approvedAgent: '11111111',
      committedAtRaw: '2026-09-30T15:00:00.000000Z',
    }],
  });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createDataOnlyMockEngineMaterializer({ adjustReconfirmRecordId: reconfKey }),
    tempBaseDir: env.tempDir,
  }));

  // Launch Run 1 (auto-inherits standing prior_decision_commit_id) and Run 2 (for S-8 carry check later)
  const l1 = await env.commands.launchRun({ dbToken: env.ownerToken, commandKey: 'sync-l1', statementDate: '2026-10-31', engineVersionId });
  const run1Id = l1.result.runId;
  assert.equal(l1.result.priorDecisionCommitId, baseDec.result.decisionCommitId);

  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].stage, 'waiting for Bible');

  // Verify review_queue_items populated automatically when bible finished
  const bibleQ = (await env.pool.query("SELECT record_id FROM coherence.review_queue_items WHERE run_id = $1::uuid AND surface = 'bible' ORDER BY item_order", [run1Id])).rows;
  assert.equal(bibleQ.length, 2);

  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].latest_journal_seq);

  // Incomplete Bible save (missing 1 of 2 queue items) refused by PostgreSQL
  await assert.rejects(
    () => env.commands.saveReviewDecisions({
      dbToken: env.ownerToken, commandKey: 'sync-bible-incomplete', expectedJournalSeq: seq,
      runId: run1Id, surface: 'bible',
      decisions: [{ recordId: bibleQ[0].record_id, disposition: 'CONFIRM' }],
    }),
    /queue item\(s\) have no committed decision/i,
  );

  // Stale expectedJournalSeq refused with 409 STALE_JOURNAL_POSITION
  await assert.rejects(
    () => env.commands.saveReviewDecisions({
      dbToken: env.ownerToken, commandKey: 'sync-bible-stale', expectedJournalSeq: seq - 1,
      runId: run1Id, surface: 'bible',
      decisions: bibleQ.map((q) => ({ recordId: q.record_id, disposition: 'CONFIRM' })),
    }),
    (err) => err?.status === 409 && err?.code === 'STALE_JOURNAL_POSITION',
  );

  // Concurrent race of two Bible saves at the same expectedJournalSeq -> exactly one succeeds, one fails
  const [raceA, raceB] = await Promise.allSettled([
    env.commands.saveReviewDecisions({
      dbToken: env.ownerToken, commandKey: 'sync-bible-race-1', expectedJournalSeq: seq,
      runId: run1Id, surface: 'bible',
      decisions: [
        { recordId: bibleQ[0].record_id, disposition: 'CONFIRM', note: 'tab-1' },
        { recordId: bibleQ[1].record_id, disposition: 'CONFIRM', note: 'tab-1' },
      ],
    }),
    env.commands.saveReviewDecisions({
      dbToken: env.ownerToken, commandKey: 'sync-bible-race-2', expectedJournalSeq: seq,
      runId: run1Id, surface: 'bible',
      decisions: [
        { recordId: bibleQ[0].record_id, disposition: 'CONFIRM', note: 'tab-2' },
        { recordId: bibleQ[1].record_id, disposition: 'CONFIRM', note: 'tab-2' },
      ],
    }),
  ]);
  assert.equal([raceA, raceB].filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal([raceA, raceB].filter((r) => r.status === 'rejected').length, 1);
  const winnerKey = raceA.status === 'fulfilled' ? 'sync-bible-race-1' : 'sync-bible-race-2';
  const winnerNote = raceA.status === 'fulfilled' ? 'tab-1' : 'tab-2';
  const winnerRes = raceA.status === 'fulfilled' ? raceA.value : raceB.value;

  // Idempotent resend with same commandKey + identical payload succeeds without duplicating rows
  const idemRes = await env.commands.saveReviewDecisions({
    dbToken: env.ownerToken, commandKey: winnerKey, expectedJournalSeq: seq,
    runId: run1Id, surface: 'bible',
    decisions: [
      { recordId: bibleQ[0].record_id, disposition: 'CONFIRM', note: winnerNote },
      { recordId: bibleQ[1].record_id, disposition: 'CONFIRM', note: winnerNote },
    ],
  });
  assert.equal(idemRes.idempotent, true);
  assert.equal(idemRes.result.reviewSaveId, winnerRes.result.reviewSaveId);

  // Command key reuse with different payload refused with 409 COMMAND_KEY_CONFLICT
  await assert.rejects(
    () => env.commands.saveReviewDecisions({
      dbToken: env.ownerToken, commandKey: winnerKey, expectedJournalSeq: seq,
      runId: run1Id, surface: 'bible',
      decisions: [
        { recordId: bibleQ[0].record_id, disposition: 'CONFIRM', note: 'changed' },
        { recordId: bibleQ[1].record_id, disposition: 'CONFIRM', note: 'changed' },
      ],
    }),
    (err) => err?.status === 409 && err?.code === 'COMMAND_KEY_CONFLICT',
  );

  // Worker executes adjust using deterministically generated overlay.csv (recording generated_overlays receipt)
  assert.equal((await worker.runOnce()).action, 'step_finished');
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].stage, 'waiting for Adjust');
  const genOvCount = (await env.pool.query("SELECT COUNT(*)::int AS n FROM coherence.generated_overlays WHERE run_id = $1::uuid AND purpose = 'bible_review'", [run1Id])).rows[0].n;
  assert.equal(genOvCount, 1);

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].latest_journal_seq);

  // Duplicate Bible re-save with identical decisions refused with 409 DUPLICATE_REVIEW_SAVE
  await assert.rejects(
    () => env.commands.saveReviewDecisions({
      dbToken: env.ownerToken, commandKey: 'sync-bible-dup-noop', expectedJournalSeq: seq,
      runId: run1Id, surface: 'bible',
      decisions: [
        { recordId: bibleQ[0].record_id, disposition: 'CONFIRM', note: winnerNote },
        { recordId: bibleQ[1].record_id, disposition: 'CONFIRM', note: winnerNote },
      ],
    }),
    (err) => err?.status === 409 && err?.code === 'DUPLICATE_REVIEW_SAVE',
  );

  // Changed Bible re-save while waiting for Adjust supersedes Adjust attempt 1 and triggers Adjust attempt 2
  await env.commands.saveReviewDecisions({
    dbToken: env.ownerToken, commandKey: 'sync-bible-revise', expectedJournalSeq: seq,
    runId: run1Id, surface: 'bible',
    decisions: [{ recordId: bibleQ[0].record_id, disposition: 'CORRECT', agency: 'Beacon', status: 'ACTIVE_PAYING', note: 'updated bible' }],
  });
  const adj2Step = await worker.runOnce();
  assert.equal(adj2Step.action, 'step_finished');
  assert.equal(adj2Step.attemptNo, 2);

  // Adjust reconfirmation guard: omitting fresh decision for needs_reconfirm item refused even though prior baseline has it!
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].latest_journal_seq);
  await assert.rejects(
    () => env.commands.saveReviewDecisions({
      dbToken: env.ownerToken, commandKey: 'sync-adj-no-reconfirm', expectedJournalSeq: seq,
      runId: run1Id, surface: 'adjust',
      decisions: [{ recordId: 'carrier_b~direct~CASEY MOCK~250.00~2026-10', disposition: 'CONFIRM' }],
    }),
    /reconfirmation item\(s\) lack a fresh decision in this run/i,
  );

  // Valid Adjust save with fresh decision on reconfirm item + new item
  const adjSave = await env.commands.saveReviewDecisions({
    dbToken: env.ownerToken, commandKey: 'sync-adj-valid', expectedJournalSeq: seq,
    runId: run1Id, surface: 'adjust',
    decisions: [
      { recordId: reconfKey, disposition: 'CONFIRM', approvedAmount: '100.00', approvedAgency: 'Beacon', approvedAgent: '11111111' },
      { recordId: 'carrier_b~direct~CASEY MOCK~250.00~2026-10', disposition: 'CONFIRM', approvedAmount: '250.00', approvedAgency: 'Harbor', approvedAgent: '33333333' },
    ],
  });
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].stage, 'ready to create statements');

  // Confirm Emit + CR-1 (Adjust save refused after Emit confirmation)
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({
    dbToken: env.ownerToken, commandKey: 'sync-confirm-emit', expectedJournalSeq: seq,
    runId: run1Id, adjustReviewSaveId: adjSave.result.reviewSaveId, typedPhrase: 'create statements for 2026-10-31',
  });
  const emitStep = await worker.runOnce();
  assert.equal(emitStep.action, 'step_finished');
  assert.equal((await env.pool.query('SELECT stage FROM coherence.run_states WHERE id = $1::uuid', [run1Id])).rows[0].stage, 'done');

  // Verify automatic Emit materialization populated BoB, Ledger, and Statements atomically with zero HTML artifacts!
  const htmlCount = (await env.pool.query("SELECT COUNT(*)::int AS n FROM coherence.artifacts WHERE rel_path LIKE '%.html'")).rows[0].n;
  assert.equal(htmlCount, 0, 'data-only engine copy must produce zero HTML artifacts');
  const matRow = (await env.pool.query('SELECT bob_row_count, ledger_row_count, ledger_gross_total FROM coherence.run_materializations WHERE run_id = $1::uuid', [run1Id])).rows[0];
  assert.equal(matRow.bob_row_count, 3);
  assert.equal(matRow.ledger_row_count, 4);
  assert.equal(matRow.ledger_gross_total, '525.00');

  // Carry decisions forward: advances standing decision head without adding a new input_versions row
  const ivCountBefore = (await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.input_versions')).rows[0].n;
  const carry1 = await env.commands.carryDecisions({
    dbToken: env.ownerToken, commandKey: 'sync-carry-dec-1', runId: run1Id, typedPhrase: 'carry 2026-10-31',
  });
  assert.equal(carry1.result.nothingNew, false);
  assert.equal(carry1.result.carriedDecisionCommitId, adjSave.result.decisionCommitId);
  assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.input_versions')).rows[0].n, ivCountBefore);
  assert.equal((await env.pool.query('SELECT coherence.standing_decision_head_as_of(NULL) AS h')).rows[0].h, adjSave.result.decisionCommitId);

  // Second carryDecisions on same commit marks nothing_new = true
  const carry2 = await env.commands.carryDecisions({
    dbToken: env.ownerToken, commandKey: 'sync-carry-dec-2', runId: run1Id, typedPhrase: 'carry 2026-10-31',
  });
  assert.equal(carry2.result.nothingNew, true);

  // S-8 out-of-order decision carry refusal: a run branching off baseDec cannot overwrite the newer standing head!
  const lOld = await env.commands.launchRun({
    dbToken: env.ownerToken, commandKey: 'sync-launch-old', statementDate: '2026-11-15',
    priorDecisionCommitId: baseDec.result.decisionCommitId, engineVersionId,
  });
  const oldRunId = lOld.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [oldRunId])).rows[0].latest_journal_seq);
  await env.commands.saveReviewDecisions({
    dbToken: env.ownerToken, commandKey: 'sync-old-bible', expectedJournalSeq: seq, runId: oldRunId, surface: 'bible',
    decisions: bibleQ.map((q) => ({ recordId: q.record_id, disposition: 'CONFIRM', note: 'divergent' })),
  });
  assert.equal((await worker.runOnce()).action, 'step_finished');
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [oldRunId])).rows[0].latest_journal_seq);
  const oldAdj = await env.commands.saveReviewDecisions({
    dbToken: env.ownerToken, commandKey: 'sync-old-adj', expectedJournalSeq: seq, runId: oldRunId, surface: 'adjust',
    decisions: [
      { recordId: reconfKey, disposition: 'CONFIRM', approvedAmount: '100.00', approvedAgency: 'Beacon', approvedAgent: '11111111' },
      { recordId: 'carrier_b~direct~CASEY MOCK~250.00~2026-10', disposition: 'CONFIRM', approvedAmount: '250.00', approvedAgency: 'Harbor', approvedAgent: '33333333' },
    ],
  });
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [oldRunId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({
    dbToken: env.ownerToken, commandKey: 'sync-old-emit', expectedJournalSeq: seq, runId: oldRunId,
    adjustReviewSaveId: oldAdj.result.reviewSaveId, typedPhrase: 'create statements for 2026-11-15',
  });
  assert.equal((await worker.runOnce()).action, 'step_finished');

  await assert.rejects(
    () => env.commands.carryDecisions({
      dbToken: env.ownerToken, commandKey: 'sync-carry-s8-refuse', runId: oldRunId, typedPhrase: 'carry 2026-11-15',
    }),
    /does not extend the standing decision head/i,
  );

  assert.equal((await verifyChain(env.pool)).passed, true);
  assert.equal((await verifyCommitments(env.pool)).passed, true);
});
