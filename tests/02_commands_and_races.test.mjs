// R18, R4, R8, R10.5, R10.6, R10.12, R11 command-layer, race, carry, abandon, and journal-rebuild tests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { exportJournalNdjson, rebuildFromJournalExport, verifyChain, verifyCommitments } from '../src/commands/journal-export.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';
import { createMockEngineMaterializer, makeOverlayCsv, sampleApprovalRow, seedEngineVersion, seedStandingInput } from './helpers/fixtures.mjs';

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
  // assign -> attribute -> bible
  for (let i = 0; i < 3; i++) {
    const step = await worker.runOnce();
    assert.equal(step.action, 'step_finished');
  }
  const st = await env.pool.query('SELECT stage, latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId]);
  assert.equal(st.rows[0].stage, 'waiting for Bible');
  return { runId, latestSeq: Number(st.rows[0].latest_journal_seq) };
}

test('R10.6 & R4.5: idempotent resend acts once, reused command key with any difference is refused, and View-As never writes', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const { engineVersionId } = await seedEngineVersion(env);
  await seedStandingInput(env);

  // R4.5: View-As refuses writes
  const viewingAsActor = { id: 'kairon', kind: 'owner', viewingAs: { id: 'agent-1' } };
  await assert.rejects(
    () => env.commands.launchRun({ actor: viewingAsActor, commandKey: 'va-launch', statementDate: '2026-11-21', engineVersionId }),
    /viewing as/i,
  );

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
    actor: supportActor,
    commandKey: 'launch-idem-key',
    statementDate: '2026-11-21',
    engineVersionId,
  });
  assert.equal(first.idempotent, false);

  const jeRow = await env.pool.query('SELECT acting_for FROM coherence.journal_entries WHERE seq = $1', [String(first.journalSeq)]);
  assert.equal(jeRow.rows[0].acting_for, 'phalanx');

  // R10.6: Resend identical request with same commandKey returns first result, writes nothing new
  const resend = await env.commands.launchRun({
    actor: supportActor,
    commandKey: 'launch-idem-key',
    statementDate: '2026-11-21',
    engineVersionId,
  });
  assert.equal(resend.idempotent, true);
  assert.equal(resend.journalSeq, first.journalSeq);
  assert.equal(resend.result.runId, first.result.runId);

  // R10.6: Same key with different content, different actingFor, or different actor is REFUSED (409)
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

test('R10.5, R8, R11 (CR-1, CR-8, CR-9, CR-10): racing commands, review save vs Emit confirmation, Bible re-save rules, and attempt-keyed drafts', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
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
  const fulfilled = [r1, r2].filter((x) => x.status === 'fulfilled');
  const rejected = [r1, r2].filter((x) => x.status === 'rejected');
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);

  // Worker accepts Bible review + runs Adjust attempt 1
  const accBible = await worker.runOnce();
  assert.equal(accBible.action, 'review_accepted');
  const adj1 = await worker.runOnce();
  assert.equal(adj1.action, 'step_finished');
  assert.equal(adj1.step, 'adjust');
  assert.equal(adj1.attemptNo, 1);

  // CR-9: Save draft on Adjust attempt 1
  await env.commands.saveReviewDraft({
    actor: env.ownerActor, runId, surface: 'adjust', attemptNo: 1, born: 'b1', checksum: 'c1', rows: [{ record_id: 'x' }],
  });
  assert.ok(await env.commands.getReviewDraft({ runId, surface: 'adjust', attemptNo: 1 }));
  // Draft for wrong attempt_no refused!
  await assert.rejects(
    () => env.commands.saveReviewDraft({ actor: env.ownerActor, runId, surface: 'adjust', attemptNo: 2, born: 'b1', checksum: 'c1', rows: [] }),
    /CR-9|current finished/i,
  );

  // R8: Bible re-save while waiting for Adjust (with NO Adjust save yet) IS ALLOWED -> supersedes Adjust attempt 1 and runs Adjust attempt 2!
  const seqBeforeResave = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const rowBibleResave = sampleApprovalRow({ record_id: 'policy:aetna:P10001#effective:2026-01-01', note: 'bible-resave' });
  await env.commands.submitReview({
    actor: env.ownerActor, commandKey: 'sub-bible-resave', expectedJournalSeq: seqBeforeResave,
    runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave]), 'utf8'),
  });
  const accBible2 = await worker.runOnce();
  assert.equal(accBible2.action, 'review_accepted');
  const adj2 = await worker.runOnce();
  assert.equal(adj2.action, 'step_finished');
  assert.equal(adj2.step, 'adjust');
  assert.equal(adj2.attemptNo, 2);

  // CR-9: Draft from Adjust attempt 1 is NOT returned for Adjust attempt 2!
  assert.equal(await env.commands.getReviewDraft({ runId, surface: 'adjust', attemptNo: 2 }), null);

  // Save Adjust review #1 (on Adjust attempt 2)
  const seqBeforeAdjSave = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const rowAdj1 = sampleApprovalRow({ record_id: 'aetna~direct~P10001~100.00~2026-11', note: 'adj-1' });
  await env.commands.submitReview({
    actor: env.ownerActor, commandKey: 'sub-adj-1', expectedJournalSeq: seqBeforeAdjSave,
    runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave, rowAdj1]), 'utf8'),
  });
  const accAdj1 = await worker.runOnce();
  assert.equal(accAdj1.action, 'review_accepted');

  // CR-8: Now that an Adjust review was saved for Adjust's current attempt, Bible re-save MUST BE REFUSED!
  const seqAfterAdj1 = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await assert.rejects(
    () => env.commands.submitReview({
      actor: env.ownerActor, commandKey: 'sub-bible-after-adj', expectedJournalSeq: seqAfterAdj1,
      runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv([row0, rowBibleResave]), 'utf8'),
    }),
    /CR-8|Adjust review was saved/i,
  );

  // CR-1: Submit Adjust re-save #2 (now pending) -> Emit confirmation while review submission is waiting MUST BE REFUSED!
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

  // Worker accepts Adjust re-save #2
  const accAdj2 = await worker.runOnce();
  assert.equal(accAdj2.action, 'review_accepted');

  // R9.4: Emit confirmation naming the OLD Adjust save (#1 instead of newest #2) MUST BE REFUSED!
  const seqReady = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await assert.rejects(
    () => env.commands.confirmEmit({
      actor: env.ownerActor, commandKey: 'emit-stale-save', expectedJournalSeq: seqReady,
      runId, adjustReviewSaveId: accAdj1.reviewSaveId, typedPhrase: 'create statements for 2026-11-21',
    }),
    /newest Adjust review save/i,
  );

  // Confirm Emit naming newest Adjust save #2 -> succeeds!
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

  // Run Emit to done
  const emitRes = await worker.runOnce();
  assert.equal(emitRes.action, 'step_finished');
  assert.equal(emitRes.step, 'emit');

  // CR-10: Drafts refused after Emit
  await assert.rejects(
    () => env.commands.saveReviewDraft({ actor: env.ownerActor, runId, surface: 'adjust', attemptNo: 2, born: 'b1', checksum: 'c2', rows: [] }),
    /CR-10|after Emit/i,
  );
});

test('R8, R9.4, R11 (S-8), R10.12 & R18: carry refusals, out-of-order approvals carry refused, abandon rules, and exact journal export rebuild', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
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

  // Helper to complete a run through Emit
  const completeRun = async ({ date, origin, extraRows, rerunReason = null }) => {
    const { runId } = await runToBibleWaiting(env, worker, { statementDate: date, origin, engineVersionId, rerunReason });
    const bibleRows = [row0, ...extraRows.bible];
    let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.submitReview({ actor: env.ownerActor, commandKey: `b-${runId}`, expectedJournalSeq: seq, runId, surface: 'bible', csvBytes: Buffer.from(makeOverlayCsv(bibleRows), 'utf8') });
    assert.equal((await worker.runOnce()).action, 'review_accepted');
    assert.equal((await worker.runOnce()).action, 'step_finished'); // adjust

    const adjRows = [...bibleRows, ...extraRows.adjust];
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.submitReview({ actor: env.ownerActor, commandKey: `a-${runId}`, expectedJournalSeq: seq, runId, surface: 'adjust', csvBytes: Buffer.from(makeOverlayCsv(adjRows), 'utf8') });
    const adjAcc = await worker.runOnce();
    assert.equal(adjAcc.action, 'review_accepted');

    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.confirmEmit({ actor: env.ownerActor, commandKey: `e-${runId}`, expectedJournalSeq: seq, runId, adjustReviewSaveId: adjAcc.reviewSaveId, typedPhrase: `create statements for ${date}` });
    assert.equal((await worker.runOnce()).action, 'step_finished'); // emit
    return runId;
  };

  // 1. Trial run completes -> NEVER allowed to carry sent or approvals (R8)
  const trialId = await completeRun({
    date: '2026-11-20',
    origin: 'trial',
    extraRows: { bible: [sampleApprovalRow({ note: 'trial-b' })], adjust: [sampleApprovalRow({ note: 'trial-a' })] },
  });
  await assert.rejects(
    () => env.commands.carrySent({ actor: env.ownerActor, commandKey: 'carry-trial-sent', runId: trialId, typedPhrase: 'sent 2026-11-20' }),
    /only app and company_import/i,
  );
  await assert.rejects(
    () => env.commands.carryApprovals({ actor: env.ownerActor, commandKey: 'carry-trial-ov', runId: trialId, typedPhrase: 'carry 2026-11-20' }),
    /only app and company_import/i,
  );

  // 2. Two app runs launched from the SAME prior overlay (row0):
  // Run A (11/20) and Run B (11/21) finish with DIFFERENT branches extending row0!
  const runA = await completeRun({
    date: '2026-11-20',
    origin: 'app',
    extraRows: { bible: [sampleApprovalRow({ note: 'branch-A' })], adjust: [] },
  });
  const runB = await completeRun({
    date: '2026-11-21',
    origin: 'app',
    extraRows: { bible: [sampleApprovalRow({ note: 'branch-B' })], adjust: [] },
  });

  // Launch another 11/20 app run while runA is finished with no carries -> refused until runA is abandoned!
  await assert.rejects(
    () => env.commands.launchRun({ actor: env.ownerActor, commandKey: 'dup-1120', statementDate: '2026-11-20', engineVersionId, rerunReason: 'retry' }),
    /non-abandoned run/i,
  );

  // Carry Run B's approvals first -> standing overlay advances to branch-B
  const carryB = await env.commands.carryApprovals({ actor: env.ownerActor, commandKey: 'carry-ov-B', runId: runB, typedPhrase: 'carry 2026-11-21' });
  assert.equal(carryB.result.nothingNew, false);

  // Carrying Run B's approvals AGAIN -> nothing_new = true!
  const carryB2 = await env.commands.carryApprovals({ actor: env.ownerActor, commandKey: 'carry-ov-B-again', runId: runB, typedPhrase: 'carry 2026-11-21' });
  assert.equal(carryB2.result.nothingNew, true);
  assert.equal(carryB2.result.publishedInputVersionId, null);

  // S-8 / R18: Carrying older Run A's approvals AFTER Run B's would drop branch-B -> REFUSED BY DATABASE!
  await assert.rejects(
    () => env.commands.carryApprovals({ actor: env.ownerActor, commandKey: 'carry-ov-A-ooo', runId: runA, typedPhrase: 'carry 2026-11-20' }),
    /does not extend the standing approvals/i,
  );

  // Carry Sent for Run B -> succeeds; second Sent for 2026-11-21 refused; abandoning Run B after carry refused!
  await env.commands.carrySent({ actor: env.ownerActor, commandKey: 'carry-sent-B', runId: runB, typedPhrase: 'sent 2026-11-21' });
  await assert.rejects(
    () => env.commands.carrySent({ actor: env.ownerActor, commandKey: 'carry-sent-B-dup', runId: runB, typedPhrase: 'sent 2026-11-21' }),
    /unique|already/i,
  );
  await assert.rejects(
    () => env.commands.abandonRun({ actor: env.ownerActor, commandKey: 'abandon-carried', runId: runB, typedPhrase: 'abandon 2026-11-21', reason: 'nope' }),
    /carried outputs/i,
  );

  // Abandon uncarried Run A -> succeeds, and re-launching 2026-11-20 gets folder_number = 2!
  await env.commands.abandonRun({ actor: env.ownerActor, commandKey: 'abandon-A', runId: runA, typedPhrase: 'abandon 2026-11-20', reason: 'superseded by 11-21' });
  const launchA2 = await env.commands.launchRun({
    actor: env.ownerActor, commandKey: 'launch-A2', statementDate: '2026-11-20', engineVersionId, rerunReason: 'clean rerun after carry',
  });
  assert.equal(launchA2.result.folderNumber, 2);

  // Cannot launch 2026-11-21 because sent statement exists for 2026-11-21!
  await assert.rejects(
    () => env.commands.launchRun({ actor: env.ownerActor, commandKey: 'launch-after-sent', statementDate: '2026-11-21', engineVersionId, rerunReason: 'correction' }),
    /sent statement already exists/i,
  );

  // R10.12 & R18: Export full journal and rebuild into a brand-new PostgreSQL 17 database verifying EVERY hash!
  const chainOrig = await verifyChain(env.pool);
  assert.equal(chainOrig.passed, true);
  const commOrig = await verifyCommitments(env.pool);
  assert.equal(commOrig.passed, true);

  const ndjson = await exportJournalNdjson(env.pool);

  // Create a completely blank second DB (without initCompany) to rebuild into
  const rebuildEnv = await createTestEnv({ companySlug: 'placeholder', displayName: 'Placeholder' });
  // Drop placeholder DB and recreate truly empty migrated DB
  t.after(() => rebuildEnv.cleanup());
  const emptyDbName = `${rebuildEnv.dbName}_empty`;
  const adminClient = await (await import('../src/db/pg-client.mjs')).createClient({ ...env.pgConfig, database: 'postgres' });
  try {
    await adminClient.query(`CREATE DATABASE "${emptyDbName}" ENCODING 'UTF8'`);
  } finally {
    await adminClient.end();
  }
  const emptyPool = await (await import('../src/db/pg-client.mjs')).createPool({ ...env.pgConfig, database: emptyDbName });
  t.after(async () => {
    await emptyPool.end().catch(() => {});
    const ac = await (await import('../src/db/pg-client.mjs')).createClient({ ...env.pgConfig, database: 'postgres' });
    try { await ac.query(`DROP DATABASE IF EXISTS "${emptyDbName}"`); } finally { await ac.end(); }
  });
  await (await import('../src/db/migrate.mjs')).runMigrations(emptyPool);

  const rebuilt = await rebuildFromJournalExport(emptyPool, ndjson);
  assert.equal(rebuilt.replayed, chainOrig.entries);

  const chainRebuilt = await verifyChain(emptyPool);
  assert.equal(chainRebuilt.passed, true);
  assert.equal(chainRebuilt.headHash, chainOrig.headHash);
  assert.equal(chainRebuilt.entries, chainOrig.entries);

  const commRebuilt = await verifyCommitments(emptyPool);
  assert.equal(commRebuilt.passed, true);
});
