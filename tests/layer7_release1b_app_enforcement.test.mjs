// Layer 7C: Release 1B application enforcement proof suite.
// Verifies strictly as platform_app against throwaway local test_* PostgreSQL 17 databases:
//  1. Canonical withRequestTx(pool, dbToken, fn): transaction-local token isolation, forced READ ONLY
//     under View-as, deliberate READ WRITE View-as refusal in PostgreSQL, and socket teardown on rollback failure.
//  2. Complete platform_app negative matrix across ALL web handlers, HTTP routes, and downstream readers
//     (every bad token, every audience, same-name agents, dollar canary sweep,
//     tool switch off/on + Nusear bypass & View-as veto, and Migration 010 live catalog audit).
//  3. Live platform_worker end-to-end execution through app_cmd.* (workerToken), worker-only
//     CSV-mode materializeEmit, removal of the legacy privileged write path, and fail-closed actor checks.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import test from 'node:test';
import { createAppCommands } from '../src/commands/app-cmd.mjs';
import { verifyIamConfigInvariants } from '../src/config/policy-checks.mjs';
import { createClient, withRequestTx } from '../src/db/pg-client.mjs';
import {
  createDatabaseCoherenceReader,
  createSignedAgentFeedReader,
  findLatestPublishedRun,
  readCurrentCommissionLedger,
  readCurrentPolicyPeriods,
  readEntityStatementLines,
} from '../src/readers/downstream-reader.mjs';
import { sha256Hex } from '../src/util/crypto.mjs';
import { createWebHandlers } from '../src/web/handlers.mjs';
import { createCoherenceRouter } from '../src/web/router.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import { reconcileInterruptedAttempts } from '../src/worker/reconciler.mjs';
import {
  createDataOnlyMockEngineMaterializer,
  makeCsvFromObjects,
  seedEngineCopyVersion,
  seedStandingInput,
  SYNTHETIC_BOB_COLUMNS,
  SYNTHETIC_LEDGER_COLUMNS,
  SYNTHETIC_RUN_COLUMNS,
} from './helpers/fixtures.mjs';
import {
  createRoleScopedTestPool,
  flipToolSwitch,
} from './helpers/iam-harness.mjs';
import { checkPgAvailable, createTestEnv, withClusterCatalogLock } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

function buildCanaryEmitCsvs({ statementDate }) {
  // Synthetic canary dollars (never real data) across Beacon (two same-name agents 11111111 & 22222222),
  // East Team (44444444), and Harbor (33333333). Every row ties out to $0.00 variance.
  const bobRows = [
    {
      policy_id: '101', carrier_policy_number: 'POL-101', crm_policy_number: 'CRM-101',
      enrollment_code: 'EC-101', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Plan One',
      simple_plan_type: 'MA', mbi: '1AB2-CD3-EF45', member: 'Pat Canary', dob: '1955-01-10',
      phone: '555-0101', email: 'pat@example.test', address: '1 Main', county: 'County A', state: 'FL',
      submission_date: '2026-09-01', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      min_date: '2026-10-01', anchor_date: '2026-10-01',
      amount: '987654.32', upline_amount: '111111.11',
      writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-B', status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
      conflicts: '', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
    },
    {
      policy_id: '102', carrier_policy_number: 'POL-102', crm_policy_number: 'CRM-102',
      enrollment_code: 'EC-102', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Plan Two',
      simple_plan_type: 'MA', mbi: '2BC3-DE4-FG56', member: 'Morgan Canary', dob: '1956-02-11',
      phone: '555-0102', email: 'morgan@example.test', address: '2 Main', county: 'County A', state: 'FL',
      submission_date: '2026-09-02', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      min_date: '2026-10-01', anchor_date: '2026-10-01',
      amount: '123456.78', upline_amount: '22222.22',
      writing_npn: '22222222', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-B', status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
      conflicts: '', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
    },
    {
      policy_id: '103', carrier_policy_number: 'POL-103', crm_policy_number: 'CRM-103',
      enrollment_code: 'EC-103', carrier: 'carrier_b', plan_type: 'MA', plan_name: 'Plan Three',
      simple_plan_type: 'MA', mbi: '3CD4-EF5-GH67', member: 'Taylor Canary', dob: '1957-03-12',
      phone: '555-0103', email: 'taylor@example.test', address: '3 Main', county: 'County B', state: 'TX',
      submission_date: '2026-09-03', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      min_date: '2026-10-01', anchor_date: '2026-10-01',
      amount: '300.00', upline_amount: '50.00',
      writing_npn: '44444444', writing_agent: 'Jamie East', entity: 'East Team',
      agency_id: 'AG-E', status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
      conflicts: '', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
    },
    {
      policy_id: '104', carrier_policy_number: 'POL-104', crm_policy_number: 'CRM-104',
      enrollment_code: 'EC-104', carrier: 'carrier_b', plan_type: 'PDP', plan_name: 'Plan Four',
      simple_plan_type: 'PDP', mbi: '4DE5-FG6-HI78', member: 'Casey Canary', dob: '1958-04-13',
      phone: '555-0104', email: 'casey@example.test', address: '4 Main', county: 'County C', state: 'OH',
      submission_date: '2026-09-04', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      min_date: '2026-10-01', anchor_date: '2026-10-01',
      amount: '44444.44', upline_amount: '5555.56',
      writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor',
      agency_id: 'AG-H', status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
      conflicts: '', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
    },
  ];
  const ledgerRows = [
    {
      tx_id: '1', record_id: `carrier_a~direct~PAT CANARY~1098765.43~${statementDate.slice(0, 7)}`,
      external_policy_id: 'POL-101', policy_id: '101', statement_name: 'carrier_a.csv', src_type: 'direct',
      carrier: 'carrier_a', member: 'Pat Canary', mbi: '1AB2-CD3-EF45',
      state: 'FL', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-01', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      earned_date: '2026-10-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-01',
      gross_comm: '1098765.43', commission_amount: '1098765.43',
      revenue_type: 'commission', writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-B', status: 'ACTIVE_PAYING', policy_status: 'active',
      downline_amount: '987654.32', upline_amount: '111111.11',
    },
    {
      tx_id: '2', record_id: `carrier_a~direct~MORGAN CANARY~145679.00~${statementDate.slice(0, 7)}`,
      external_policy_id: 'POL-102', policy_id: '102', statement_name: 'carrier_a.csv', src_type: 'direct',
      carrier: 'carrier_a', member: 'Morgan Canary', mbi: '2BC3-DE4-FG56',
      state: 'FL', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-02', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      earned_date: '2026-10-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-02',
      gross_comm: '145679.00', commission_amount: '145679.00',
      revenue_type: 'commission', writing_npn: '22222222', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-B', status: 'ACTIVE_PAYING', policy_status: 'active',
      downline_amount: '123456.78', upline_amount: '22222.22',
    },
    {
      tx_id: '3', record_id: `carrier_b~direct~TAYLOR CANARY~350.00~${statementDate.slice(0, 7)}`,
      external_policy_id: 'POL-103', policy_id: '103', statement_name: 'carrier_b.csv', src_type: 'direct',
      carrier: 'carrier_b', member: 'Taylor Canary', mbi: '3CD4-EF5-GH67',
      state: 'TX', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-03', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      earned_date: '2026-10-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-03',
      gross_comm: '350.00', commission_amount: '350.00',
      revenue_type: 'commission', writing_npn: '44444444', writing_agent: 'Jamie East', entity: 'East Team',
      agency_id: 'AG-E', status: 'ACTIVE_PAYING', policy_status: 'active',
      downline_amount: '300.00', upline_amount: '50.00',
    },
    {
      tx_id: '4', record_id: `carrier_b~direct~CASEY CANARY~50000.00~${statementDate.slice(0, 7)}`,
      external_policy_id: 'POL-104', policy_id: '104', statement_name: 'carrier_b.csv', src_type: 'direct',
      carrier: 'carrier_b', member: 'Casey Canary', mbi: '4DE5-FG6-HI78',
      state: 'OH', plan_type: 'PDP', simple_plan_type: 'PDP',
      submission_date: '2026-09-04', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      earned_date: '2026-10-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-04',
      gross_comm: '50000.00', commission_amount: '50000.00',
      revenue_type: 'commission', writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor',
      agency_id: 'AG-H', status: 'ACTIVE_PAYING', policy_status: 'active',
      downline_amount: '44444.44', upline_amount: '5555.56',
    },
  ];
  const stmtRows = ledgerRows.map((r) => ({
    ...r,
    run_action: 'NEW',
    run_statement_date: statementDate,
    reversal_of: '',
    reason: 'canary',
  }));
  return {
    bobRows,
    ledgerRows,
    stmtRows,
    bobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, bobRows),
    ledgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, ledgerRows),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, stmtRows),
  };
}

function buildCumulativeCanaryDataset({ prior, statementDate }) {
  const extraBob = {
    external_policy_id: 'POL-105', policy_id: '105', carrier_policy_number: 'POL-105', crm_policy_number: 'CRM-105',
    enrollment_code: 'EC-105', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Plan Unsent',
    simple_plan_type: 'MA', mbi: '5EF6-GH7-IJ89', member: 'Unsent Canary', dob: '1959-05-14',
    phone: '555-0105', email: 'unsent@example.test', address: '5 Main', county: 'County A', state: 'FL',
    submission_date: '2026-10-05', origin_effective: '2026-11-01', effective_date: '2026-11-01',
    min_date: '2026-10-05', anchor_date: '2026-10-05',
    amount: '77777.77', upline_amount: '11111.11',
    writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
    agency_id: 'AG-B', status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
    conflicts: '', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
  };
  const extraLedger = {
    tx_id: '5', record_id: `carrier_a~direct~UNSENT CANARY~88888.88~${statementDate.slice(0, 7)}`,
    external_policy_id: 'POL-105', policy_id: '105', statement_name: 'carrier_a_unsent.csv', src_type: 'direct',
    carrier: 'carrier_a', member: 'Unsent Canary', mbi: '5EF6-GH7-IJ89',
    state: 'FL', plan_type: 'MA', simple_plan_type: 'MA',
    submission_date: '2026-10-05', origin_effective: '2026-11-01', effective_date: '2026-11-01',
    earned_date: '2026-11-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-10-05',
    gross_comm: '88888.88', commission_amount: '88888.88',
    revenue_type: 'commission', writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
    agency_id: 'AG-B', status: 'ACTIVE_PAYING', policy_status: 'active',
    downline_amount: '77777.77', upline_amount: '11111.11',
  };
  const bobAll = [...prior.bobRows, extraBob];
  const ledgerAll = [...prior.ledgerRows, extraLedger];
  const stmtNew = [{ ...extraLedger, run_action: 'NEW', run_statement_date: statementDate, reversal_of: '', reason: 'unsent' }];
  return {
    canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, bobAll),
    coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, ledgerAll),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, stmtNew),
    emitMetadataJson: JSON.stringify({ statementDate, build: 'copy001', corpusTail: statementDate.slice(0, 7), agencyStart: '2026-01-01' }),
    workingTxCsv: makeCsvFromObjects(['tx_id', 'filename', 'sheet_name', 'source_position'], [{ tx_id: 5, filename: 'carrier_a_unsent.csv', sheet_name: 'Commissions', source_position: 1 }]),
  };
}

test('Layer 7C [withRequestTx Contract]: transaction-local token isolation, forced READ ONLY under View-as, deliberate READ WRITE View-as refusal, and rollback-failure socket teardown', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const iam = env.iam;
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');

  // 1. Inside withRequestTx, current_user is platform_app and app.session_token is set transaction-locally;
  //    immediately after COMMIT or ROLLBACK, the token is gone (fail-closed).
  const inside = await withRequestTx(appPool, iam.tokens.owner, async (tx) => {
    const u = (await tx.query('SELECT current_user AS u, pg_catalog.current_setting(\'app.session_token\', true) AS tok, current_setting(\'transaction_read_only\') AS ro')).rows[0];
    return u;
  }, { readOnly: true });
  assert.equal(inside.u, 'platform_app');
  assert.equal(inside.tok, iam.tokens.owner);
  assert.equal(inside.ro, 'on');

  const outside = await withRequestTx(appPool, '', async (tx) => (
    (await tx.query("SELECT pg_catalog.current_setting('app.session_token', true) AS tok")).rows[0].tok
  ));
  assert.equal(outside, '');

  // 2. View-as token forces BEGIN TRANSACTION READ ONLY even when caller asks for { readOnly: false, serializable: true }!
  const vaRo = await withRequestTx(appPool, iam.tokens.viewAsAgentA, async (tx) => (
    (await tx.query("SELECT current_setting('transaction_read_only') AS ro, iam.is_viewing_as() AS va")).rows[0]
  ), { readOnly: false, serializable: true });
  assert.equal(vaRo.ro, 'on', 'withRequestTx must force READ ONLY when View-as token is active');
  assert.equal(vaRo.va, true);

  // 3. Even if an app bug bypasses withRequestTx and opens a deliberate READ WRITE tx with a View-as token,
  //    PostgreSQL iam.assert_can_write refuses app_cmd.* with SQLSTATE 42501 VIEW_AS_READ_ONLY!
  const rawAppClient = await appPool.connect();
  try {
    await rawAppClient.query('BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE');
    await rawAppClient.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [iam.tokens.viewAsAgentA]);
    await assert.rejects(
      () => rawAppClient.query(
        "SELECT app_cmd.coherence_record_check($1, $2, 'chain', true, '{}'::jsonb)",
        ['delib-rw-va', sha256Hex('delib-rw-va')],
      ),
      (err) => err?.code === '42501' && /VIEW_AS_READ_ONLY/i.test(err.message),
      'deliberate READ WRITE View-as tx must still fail with 42501 VIEW_AS_READ_ONLY',
    );
    await rawAppClient.query('ROLLBACK');
  } finally {
    rawAppClient.release();
  }

  // 4. Pooled connection is destroyed (release(err)) when ROLLBACK fails so state never leaks across requests.
  let releasedWithErr = null;
  const fakePool = {
    async connect() {
      return {
        async query(sql) {
          if (sql.startsWith('BEGIN') || sql.startsWith('SELECT pg_catalog.set_config')) return { rows: [] };
          if (sql === 'ROLLBACK') throw new Error('socket broken during rollback');
          throw new Error('query boom');
        },
        release(err) {
          releasedWithErr = err;
        },
      };
    },
    async end() {},
  };
  await assert.rejects(() => withRequestTx(fakePool, iam.tokens.owner, (tx) => tx.query('SELECT 1')), /query boom/);
  assert.ok(releasedWithErr instanceof Error, 'withRequestTx must pass an Error to client.release() when ROLLBACK fails');
});

test('Layer 7C [Release 1B platform_app Negative Matrix & Canary Sweep]: every HTTP route and downstream reader enforces PostgreSQL-only IAM across all audiences, bad tokens, body-override attacks, output/batch gates, ?asOf= refusal, View-as, tool switches, and Migration 010 catalog audit', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const iam = env.iam;
  const { engineVersionId } = await seedEngineCopyVersion(env);
  await seedStandingInput(env, { commandKey: 'r1b-mat-standing' });

  const canarySent = buildCanaryEmitCsvs({ statementDate: '2026-10-15' });
  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createDataOnlyMockEngineMaterializer({
      adjustReconfirmRecordId: null,
      datasetBuilder: ({ statementDate = '2026-10-31' } = {}) => buildCumulativeCanaryDataset({ prior: canarySent, statementDate }),
    }),
    tempBaseDir: env.tempDir,
  }));

  // Helper to complete a run + attach Entity Manager viewer bundle + materialize canary CSVs
  async function seedCanaryRun({ date, keyPrefix, origin = 'app', markSent = false, abandon = false }) {
    const launch = await env.commands.launchRun({
      dbToken: env.ownerToken, commandKey: `${keyPrefix}-launch`, statementDate: date, origin, engineVersionId,
    });
    const runId = launch.result.runId;
    for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
    let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.saveReviewDecisions({
      dbToken: env.ownerToken, commandKey: `${keyPrefix}-bible`, expectedJournalSeq: seq, runId, surface: 'bible',
      decisions: [
        { recordId: 'policy:carrier_a:C-101#effective:2026-10-01', disposition: 'CONFIRM', note: `note-${date}` },
        { recordId: 'policy:carrier_b:C-201#effective:2026-10-01', disposition: 'CONFIRM', note: `note-${date}` },
      ],
    });
    assert.equal((await worker.runOnce()).action, 'step_finished');
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    const adj = await env.commands.saveReviewDecisions({
      dbToken: env.ownerToken, commandKey: `${keyPrefix}-adj`, expectedJournalSeq: seq, runId, surface: 'adjust',
      decisions: [
        { recordId: 'carrier_a~direct~PAT SAMPLE~100.00~2026-10', disposition: 'CONFIRM', note: `adj-${date}` },
        { recordId: 'carrier_b~direct~CASEY MOCK~250.00~2026-10', disposition: 'CONFIRM', note: `adj-${date}` },
      ],
    });
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.confirmEmit({
      dbToken: env.ownerToken, commandKey: `${keyPrefix}-emit`, expectedJournalSeq: seq, runId,
      adjustReviewSaveId: adj.result.reviewSaveId, typedPhrase: `create statements for ${date}`,
    });
    assert.equal((await worker.runOnce()).action, 'step_finished');
    if (markSent) {
      await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: `${keyPrefix}-sent`, runId, typedPhrase: `sent ${date}` });
    }
    if (abandon) {
      await env.commands.abandonRun({ dbToken: env.ownerToken, commandKey: `${keyPrefix}-ab`, runId, typedPhrase: `abandon ${date}`, reason: 'abandoned synthetic' });
    }
    return runId;
  }

  // Import a sent company run with canary dollar amounts (987654.32, 123456.78, 111111.11) AND Entity Manager bundle
  const emViewerHtml = Buffer.from(
    `<!doctype html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify({
      name: 'Entity Manager', title: 'Acme', statementDate: '2026-10-15', role: 'ENTITY_MANAGER',
      features: { CANONICAL_BOB: { canonical_bob: 'data/canonical_bob.csv' }, COHERENT_LEDGER: { coherent_ledger: 'data/coherent_ledger.csv' } },
    })};</script></head>`,
    'utf8',
  );
  const emViewer = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme/viewer.html', emViewerHtml, { checksPassed: true });
  const emBob = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme/data/canonical_bob.csv', Buffer.from(canarySent.bobCsv, 'utf8'), { checksPassed: true });
  const emLed = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme/data/coherent_ledger.csv', Buffer.from(canarySent.ledgerCsv, 'utf8'), { checksPassed: true });
  const emStmt = await env.stores.promoteArtifact('emits/statements_20261015.csv', Buffer.from(canarySent.statementsCsv, 'utf8'), { checksPassed: true });
  const emMeta = await env.stores.promoteArtifact('emits/emit_metadata.json', Buffer.from(JSON.stringify({ statementDate: '2026-10-15', corpusTail: '2026-10', agencyStart: '2026-01-01' }), 'utf8'), { checksPassed: true });
  const emPolicyMeta = await env.stores.promoteArtifact('emits/policy_status_meta.json', Buffer.from(JSON.stringify({ statementDate: '2026-10-15', policyCount: 4 }), 'utf8'), { checksPassed: true });
  const emRunJson = await env.stores.promoteArtifact('run.json', Buffer.from(JSON.stringify({ date: '2026-10-15', steps: { emit: { at: '2026-10-15T10:00:00' } } }), 'utf8'), { checksPassed: true });
  const emManifestJson = await env.stores.promoteArtifact('company_manifest.json', Buffer.from(JSON.stringify([{ output: 'entity-managers/Acme' }]), 'utf8'), { checksPassed: true });
  const impIn = await env.dataStore.promoteBytes(Buffer.from('k\n1\n', 'utf8'), { relPath: 'imp.csv', checksPassed: true });
  const impRes = await env.commands.importHistoricalRun({
    dbToken: env.ownerToken,
    commandKey: 'r1b-canary-sent',
    run: { origin: 'company_import', statementDate: '2026-10-15', sourceFolder: 'company-workspaces/acme/2026-10-15/runs/2026-10-15', emitMode: 'coherence' },
    inputVersion: { reason: 'canary sent import' },
    inputEntries: [{ relPath: 'imp.csv', fileSha256: impIn.sha256 }],
    stepAttempts: [{
      step: 'emit',
      attemptNo: 1,
      artifacts: [emViewer, emBob, emLed, emStmt, emMeta, emPolicyMeta, emRunJson, emManifestJson].map((f) => ({
        relPath: f.relPath, artifactKind: f.artifactKind, storeKind: f.storeKind, fileSha256: f.sha256,
      })),
    }],
    storedFiles: [impIn, emViewer, emBob, emLed, emStmt, emMeta, emPolicyMeta, emRunJson, emManifestJson],
  });
  const sentRunId = impRes.result.runId;
  const sentEmitEv = (await env.pool.query(
    "SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev",
    [sentRunId],
  )).rows[0].ev;
  await env.commands.materializeEmit({
    dbToken: env.workerToken,
    commandKey: 'r1b-canary-mat',
    runId: sentRunId,
    attemptEventId: sentEmitEv,
    statementDate: '2026-10-15',
    canonicalBobCsv: canarySent.bobCsv,
    coherentLedgerCsv: canarySent.ledgerCsv,
    statementsCsv: canarySent.statementsCsv,
  });
  await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'r1b-canary-carry-sent', runId: sentRunId, typedPhrase: 'sent 2026-10-15' });

  // Also run an UNSENT completed app run (2026-10-31), an ABANDONED run (2026-11-15), and a TRIAL run (2026-11-30)
  const unsentRunId = await seedCanaryRun({ date: '2026-10-31', keyPrefix: 'r1b-unsent', markSent: false });
  const abandonedRunId = await seedCanaryRun({ date: '2026-11-15', keyPrefix: 'r1b-abandoned', markSent: false, abandon: true });
  const trialRunId = await seedCanaryRun({ date: '2026-11-30', keyPrefix: 'r1b-trial', origin: 'trial', markSent: false });

  // Verify zero NULL organization_id on any financial row written through signed tokens (Item 2 & 5).
  for (const tbl of ['bob_policies', 'bob_policy_financials', 'coherent_ledger_rows', 'statement_agency_lines', 'statement_upline_lines']) {
    const nulls = (await env.pool.query(`SELECT COUNT(*)::int AS n FROM coherence.${tbl} WHERE organization_id IS NULL`)).rows[0].n;
    assert.equal(nulls, 0, `coherence.${tbl} must have zero NULL organization_id rows after token-seeded writes`);
  }

  const stagedFile = await env.dataStore.promoteBytes(Buffer.from('a,b\n1,2\n', 'utf8'), { relPath: 'staging/extra.csv', checksPassed: true });
  await env.commands.importStandaloneFiles({
    dbToken: env.ownerToken,
    commandKey: 'r1b-stage-extra',
    files: [{ area: 'staging', relPath: 'staging/extra.csv', artifactKind: 'data', storeKind: 'company_data', fileSha256: stagedFile.sha256 }],
    storedFiles: [stagedFile],
  });
  await env.commands.recordCheck({
    dbToken: env.ownerToken,
    commandKey: 'r1b-seed-chk',
    checkKind: 'chain',
    runId: unsentRunId,
    passed: true,
    report: { ok: true },
  });

  // Verify Migration 010 live catalog audit passes across all 38 app_views.* and 33 app_cmd.*!
  const catalogAudit = await withClusterCatalogLock(() => verifyIamConfigInvariants(env.pool));
  assert.equal(catalogAudit.passed, true, `verifyIamConfigInvariants failed:\n${catalogAudit.problems.join('\n')}`);
  assert.equal(catalogAudit.checkedAppViews, 38);
  assert.equal(catalogAudit.checkedAppCmdFunctions, 33);

  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const readonlyPool = createRoleScopedTestPool(env.pool, 'platform_readonly');
  const handlers = createWebHandlers({ pool: appPool, readonlyPool, companySlug: env.companySlug, stores: env.stores });
  let currentToken = '';
  const router = createCoherenceRouter({
    handlersByCompany: new Map([[env.companySlug, handlers]]),
    authenticate: async () => currentToken,
  });
  const server = createServer((req, res) => { void router(req, res); });
  await new Promise((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
  t.after(() => new Promise((resolvePromise) => server.close(resolvePromise)));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  const callHttp = async (token, path, opts = {}) => {
    currentToken = token;
    const res = await fetch(`${baseUrl}${path}`, opts);
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { json = null; }
    return { status: res.status, text, json };
  };

  const reader = createDatabaseCoherenceReader({ pool: appPool, stores: env.stores, entity: 'Acme' });
  const feed = createSignedAgentFeedReader({ pool: appPool, stores: env.stores, entity: 'Acme', secret: 'x'.repeat(40) });

  // 1. Fail-closed across ALL 7 invalid/unset/tampered/expired/wrong-env/suspended tokens on EVERY path
  const badTokens = [
    ['unset', null],
    ['blank', '   '],
    ['malformed', 'not|a|valid|token'],
    ['tampered', iam.tokens.tampered],
    ['expired', iam.tokens.expired],
    ['wrong_env', iam.tokens.wrongEnv],
    ['suspended', iam.tokens.suspended],
  ];
  for (const [label, tok] of badTokens) {
    assert.equal(await findLatestPublishedRun(appPool, tok), null, `${label}: findLatestPublishedRun must return null`);
    assert.deepEqual(await readCurrentPolicyPeriods(appPool, tok), [], `${label}: policy periods must be empty`);
    assert.deepEqual(await readCurrentCommissionLedger(appPool, tok), [], `${label}: ledger must be empty`);
    assert.deepEqual(await readEntityStatementLines(appPool, tok), [], `${label}: statement lines must be empty`);
    assert.equal((await reader.summary(tok)).available, false, `${label}: reader.summary must be unavailable`);
    assert.equal((await feed.agentBook(tok)).eligible, false, `${label}: agentBook must be ineligible`);
    assert.equal((await feed.houseSummary(tok)).available, false, `${label}: houseSummary must be unavailable`);

    assert.deepEqual((await callHttp(tok, '/api/coherence/acme/runs')).json.runs, [], `${label}: GET /runs must return []`);
    assert.deepEqual((await callHttp(tok, '/api/coherence/acme/inputs/versions')).json.versions, [], `${label}: GET /inputs/versions must return []`);
    assert.deepEqual((await callHttp(tok, '/api/coherence/acme/inputs/staging')).json.files, [], `${label}: GET /inputs/staging must return []`);
    assert.deepEqual((await callHttp(tok, `/api/coherence/acme/runs/${unsentRunId}/journal`)).json.entries, [], `${label}: GET /journal must return []`);
    assert.deepEqual((await callHttp(tok, '/api/coherence/acme/checks')).json.checks, [], `${label}: GET /checks must return []`);
    assert.deepEqual((await callHttp(tok, '/api/coherence/acme/decisions/history', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recordId: 'policy:carrier_a:C-101#effective:2026-10-01' }),
    })).json.history, [], `${label}: POST /decisions/history must return []`);
    assert.equal((await callHttp(tok, `/api/coherence/acme/runs/${unsentRunId}/review/bible/config`)).status, 404, `${label}: review/bible/config must be 404`);
    assert.equal((await callHttp(tok, '/api/coherence/acme/review-drift')).status, 403, `${label}: review-drift must be 403`);
    assert.equal((await callHttp(tok, '/api/coherence/acme/runs', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ commandKey: `bad-tok-launch-${label}`, statementDate: '2026-12-01', engineVersionId }),
    })).status, 403, `${label}: POST /runs must fail 403`);
    assert.equal((await callHttp(tok, '/api/coherence/acme/checks/run', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ commandKey: `bad-tok-chk-${label}`, checkKind: 'chain' }),
    })).status, 403, `${label}: POST /checks/run must fail 403`);
  }

  // 2. Selling Agent A (NPN 11111111): own NPN on sent run only, ZERO dollars, ZERO canary leaks, ZERO unsent/abandoned/other-NPN rows
  const agentABook = await feed.agentBook(iam.tokens.agentA);
  assert.equal(agentABook.eligible, true);
  assert.equal(agentABook.runId, sentRunId);
  assert.equal(agentABook.rows, 1);
  assert.equal(agentABook.policies[0].writing_npn, '11111111');
  assert.equal(agentABook.policies[0].amount, null);
  assert.equal(agentABook.policies[0].upline_amount, null);
  for (const canary of ['987654.32', '123456.78', '111111.11', '1098765.43', '22222222', '33333333', '44444444', 'Morgan Canary', 'Casey Canary']) {
    assert.ok(!agentABook.csv.includes(canary), `Selling Agent A CSV leaked canary ${canary}`);
  }
  assert.deepEqual(await readCurrentCommissionLedger(appPool, iam.tokens.agentA), []);
  assert.equal((await reader.summary(iam.tokens.agentA)).available, false);
  assert.equal((await feed.houseSummary(iam.tokens.agentA)).available, false);

  // 3. Retention Agent (Harbor agency wide row scope + zero dollar rights): sees Harbor only, ZERO dollars, ZERO Beacon rows
  const retBook = await feed.agentBook(iam.tokens.retentionAgent);
  assert.equal(retBook.eligible, true);
  assert.equal(retBook.rows, 1);
  assert.equal(retBook.policies[0].entity, 'Harbor');
  assert.equal(retBook.policies[0].amount, null);
  assert.equal(retBook.policies[0].upline_amount, null);
  for (const canary of ['44444.44', '5555.56', '987654.32', 'Beacon', 'Pat Canary']) {
    assert.ok(!retBook.csv.includes(canary), `Retention Agent CSV leaked canary ${canary}`);
  }

  // 4. Agency Manager (Beacon subtree = Beacon + East Team): sees agency amount, ZERO upline_amount, ZERO Harbor, ZERO ledger, ZERO house bundle
  const mgrPeriods = await readCurrentPolicyPeriods(appPool, iam.tokens.agencyMgr);
  assert.equal(mgrPeriods.length, 3);
  assert.ok(mgrPeriods.every((r) => ['Beacon', 'East Team'].includes(r.entity) && r.amount !== null && r.upline_amount === null));
  const mgrStmts = await readEntityStatementLines(appPool, iam.tokens.agencyMgr);
  assert.equal(mgrStmts.length, 3);
  assert.ok(mgrStmts.every((r) => r.account_kind === 'agency' && r.gross_comm === null));
  assert.deepEqual(await readCurrentCommissionLedger(appPool, iam.tokens.agencyMgr), []);
  assert.equal((await reader.summary(iam.tokens.agencyMgr)).available, false);

  // 5. Investor: BoB with money, ZERO statements, ZERO ledger, ZERO house bundle
  const invPeriods = await readCurrentPolicyPeriods(appPool, iam.tokens.investor);
  assert.equal(invPeriods.length, 4);
  assert.ok(invPeriods.some((r) => r.amount === '987654.32' && r.upline_amount === '111111.11'));
  assert.deepEqual(await readCurrentCommissionLedger(appPool, iam.tokens.investor), []);
  assert.deepEqual(await readEntityStatementLines(appPool, iam.tokens.investor), []);
  assert.equal((await reader.summary(iam.tokens.investor)).available, false);

  // 7. Entity Manager: full BoB + Ledger + Entity Statements + Entity Manager bundle (can read sent 2026-10-15 bundle directly), 0 journal/decisions, 403 on all writes
  const emSum = await reader.summary(iam.tokens.entityMgr, { runId: sentRunId });
  assert.equal(emSum.available, true);
  assert.equal(emSum.sent, true);
  const emBobFile = await reader.file(iam.tokens.entityMgr, 'data/canonical_bob.csv', false, { runId: sentRunId });
  assert.ok(emBobFile.body.toString('utf8').includes('987654.32'));
  assert.equal((await readCurrentCommissionLedger(appPool, iam.tokens.entityMgr)).length > 0, true);
  assert.deepEqual((await callHttp(iam.tokens.entityMgr, `/api/coherence/acme/runs/${unsentRunId}/journal`)).json.entries, []);
  assert.equal((await callHttp(iam.tokens.entityMgr, '/api/coherence/acme/review-drift')).status, 403);

  // 8. Northstar Operator (wrong company): 0 rows everywhere, 403 on every write
  assert.equal(await findLatestPublishedRun(appPool, iam.tokens.wrongCoOperator), null);
  assert.deepEqual(await readCurrentPolicyPeriods(appPool, iam.tokens.wrongCoOperator), []);
  assert.deepEqual((await callHttp(iam.tokens.wrongCoOperator, '/api/coherence/acme/runs')).json.runs, []);
  assert.deepEqual((await callHttp(iam.tokens.wrongCoOperator, '/api/coherence/acme/inputs/versions')).json.versions, []);
  assert.equal((await callHttp(iam.tokens.wrongCoOperator, '/api/coherence/acme/runs', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ commandKey: 'ns-op-launch', statementDate: '2026-12-01', engineVersionId }),
  })).status, 403);

  // 9. Nusear Admin (without coherence_operator): reads management surfaces, 403 on operator & owner writes
  assert.ok((await callHttp(iam.tokens.adminNoCoh, '/api/coherence/acme/runs')).json.runs.length >= 2);
  assert.equal((await callHttp(iam.tokens.adminNoCoh, '/api/coherence/acme/runs', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ commandKey: 'adm-no-coh-launch', statementDate: '2026-12-01', engineVersionId }),
  })).status, 403);

  // 10. Nusear Operator: succeeds on operator write (include staging file), 403 on owner-only writes (abandon, checks/run)
  assert.equal((await callHttp(iam.tokens.operator, '/api/coherence/acme/inputs/include', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      commandKey: 'op-include-extra',
      stagingFileSha256: stagedFile.sha256,
      targetRelPath: 'All Statements/extra_op.csv',
      reason: 'operator includes monthly file',
    }),
  })).status, 201);
  assert.equal((await callHttp(iam.tokens.operator, `/api/coherence/acme/runs/${unsentRunId}/abandon`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ commandKey: 'op-abandon-deny', typedPhrase: 'abandon 2026-10-31', reason: 'no' }),
  })).status, 403);
  assert.equal((await callHttp(iam.tokens.operator, '/api/coherence/acme/checks/run', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ commandKey: 'op-chk-deny', checkKind: 'chain' }),
  })).status, 403);

  // 11. View-as (Owner viewing as Agent A): sees strictly Agent A slice + zero dollars + 403 VIEW_AS_READ_ONLY on EVERY web write route!
  const vaBook = await feed.agentBook(iam.tokens.viewAsAgentA);
  assert.equal(vaBook.eligible, true);
  assert.equal(vaBook.rows, 1);
  assert.equal(vaBook.policies[0].writing_npn, '11111111');
  assert.equal(vaBook.policies[0].amount, null);
  assert.equal(vaBook.policies[0].upline_amount, null);
  assert.ok(!vaBook.csv.includes('987654.32'));
  assert.equal((await reader.summary(iam.tokens.viewAsAgentA)).available, false);

  const viewAsWriteRoutes = [
    ['POST', '/api/coherence/acme/runs', { commandKey: 'va-w-1', statementDate: '2026-12-02', engineVersionId }],
    ['POST', '/api/coherence/acme/inputs/include', { commandKey: 'va-w-2', stagingFileSha256: stagedFile.sha256, targetRelPath: 'All Statements/extra.csv', reason: 'nope' }],
    ['POST', '/api/coherence/acme/inputs/publish', { commandKey: 'va-w-3', lineKind: 'standing', sourceKind: 'upload', reason: 'nope', entries: [] }],
    ['PUT', `/api/coherence/acme/runs/${unsentRunId}/review/bible/draft`, { attemptNo: 1, checksum: 'va', rows: [] }],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/review/bible/save`, { commandKey: 'va-w-4', expectedJournalSeq: 1, decisions: [] }],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/emit`, { commandKey: 'va-w-5', adjustReviewSaveId: unsentRunId, typedPhrase: 'create statements for 2026-10-31' }],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/carry/sent`, { commandKey: 'va-w-6', typedPhrase: 'sent 2026-10-31' }],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/carry/approvals`, { commandKey: 'va-w-7', typedPhrase: 'carry 2026-10-31' }],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/carry/decisions`, { commandKey: 'va-w-8', typedPhrase: 'carry 2026-10-31' }],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/cancel`, { commandKey: 'va-w-9', step: 'assign', attemptNo: 1, typedPhrase: 'cancel', reason: 'no' }],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/retry`, { commandKey: 'va-w-10', step: 'assign' }],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/abandon`, { commandKey: 'va-w-11', typedPhrase: 'abandon 2026-10-31', reason: 'no' }],
    ['POST', '/api/coherence/acme/checks/run', { commandKey: 'va-w-12', checkKind: 'chain' }],
  ];
  for (const [method, path, body] of viewAsWriteRoutes) {
    const res = await callHttp(iam.tokens.viewAsAgentA, path, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    assert.equal(res.status, 403, `View-as ${method} ${path} must return 403 (got ${res.status})`);
    assert.equal(res.json?.code, 'VIEW_AS_READ_ONLY', `View-as ${method} ${path} must return VIEW_AS_READ_ONLY (got ${res.json?.code})`);
  }

  // 12. Tool switch OFF on coherence for Acme: blocks all customers AND Owner View-as Agent, while Nusear Owner direct still sees rows; flipping ON restores exact counts!
  const offSwitchId = await flipToolSwitch(env.pool, {
    organizationId: iam.ids.companyOrg,
    toolId: 'coherence',
    switchState: 'off',
    replacesId: iam.ids.switchAcmeCoherenceId,
    environment: iam.environment,
  });
  assert.equal((await feed.agentBook(iam.tokens.agentA)).eligible, false, 'tool switch off must block Selling Agent');
  assert.deepEqual(await readCurrentPolicyPeriods(appPool, iam.tokens.agencyMgr), [], 'tool switch off must block Agency Manager');
  assert.equal((await reader.summary(iam.tokens.entityMgr, { runId: sentRunId })).available, false, 'tool switch off must block Entity Manager');
  assert.equal((await feed.agentBook(iam.tokens.viewAsAgentA)).eligible, false, 'tool switch off must block Nusear Owner viewing as Agent');
  assert.deepEqual((await callHttp(iam.tokens.companyAdmin, '/api/coherence/acme/runs')).json.runs, [], 'tool switch off must block Company Admin');
  assert.ok((await callHttp(iam.tokens.owner, '/api/coherence/acme/runs')).json.runs.length >= 2, 'Nusear Owner direct bypasses customer tool switch');

  await flipToolSwitch(env.pool, {
    organizationId: iam.ids.companyOrg,
    toolId: 'coherence',
    switchState: 'on',
    replacesId: offSwitchId,
    environment: iam.environment,
  });
  assert.equal((await feed.agentBook(iam.tokens.agentA)).rows, 1, 'restoring tool switch on must restore Agent A exact count');
  assert.equal((await reader.summary(iam.tokens.entityMgr, { runId: sentRunId })).available, true, 'restoring tool switch on must restore Entity Manager');
  // 13. Item 1 HTTP negative test: untrusted JSON body cannot override dbToken, actor, client, runId, or surface!
  const maliciousPayload = {
    dbToken: iam.tokens.owner,
    actor: { id: 'spoof-owner', kind: 'owner' },
    client: {},
    runId: sentRunId,
    surface: 'adjust',
    commandKey: 'spoof-attempt-1',
    expectedJournalSeq: 1,
    statementDate: '2026-12-31',
    engineVersionId,
    origin: 'app',
    lineKind: 'standing',
    sourceKind: 'upload',
    entries: [],
    stagingFileSha256: stagedFile.sha256,
    targetRelPath: 'extra.csv',
    typedPhrase: 'abandon 2026-10-15',
    reason: 'spoof',
    checkKind: 'chain',
    decisions: [],
    attemptNo: 1,
    checksum: 'abc',
    rows: [{ record_id: 'x', disposition: 'CONFIRM' }],
  };
  const spoofRoutes = [
    ['POST', '/api/coherence/acme/runs'],
    ['POST', '/api/coherence/acme/inputs/publish'],
    ['POST', '/api/coherence/acme/inputs/include'],
    ['PUT', `/api/coherence/acme/runs/${unsentRunId}/review/bible/draft`],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/review/bible/save`],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/emit`],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/carry/sent`],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/carry/approvals`],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/carry/decisions`],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/cancel`],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/retry`],
    ['POST', `/api/coherence/acme/runs/${unsentRunId}/abandon`],
    ['POST', '/api/coherence/acme/checks/run'],
  ];
  for (const [method, path] of spoofRoutes) {
    const res = await callHttp(iam.tokens.agentA, path, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(maliciousPayload),
    });
    assert.equal(res.status, 403, `Body override on ${method} ${path} must be refused 403 for agentA (got ${res.status}: ${res.text})`);
  }
  // Confirm URL runId and surface win even when an authorized owner passes different runId/surface in the JSON body.
  const preEmitLaunch = await env.commands.launchRun({
    dbToken: env.ownerToken, commandKey: 'r1b-draft-url-wins-launch', statementDate: '2026-12-15', engineVersionId,
  });
  const preEmitRunId = preEmitLaunch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  const draftRes = await callHttp(iam.tokens.owner, `/api/coherence/acme/runs/${preEmitRunId}/review/bible/draft`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      dbToken: iam.tokens.agentA,
      actor: { id: 'spoof', kind: 'owner' },
      client: {},
      runId: sentRunId,
      surface: 'adjust',
      attemptNo: 1,
      checksum: 'url-wins-chk',
      rows: [{ record_id: 'r1', disposition: 'CONFIRM' }],
    }),
  });
  assert.equal(draftRes.status, 200, `URL-scoped saveReviewDraft must succeed for owner (got ${draftRes.status}: ${draftRes.text})`);
  assert.equal(draftRes.json.runId, preEmitRunId, 'URL runId must override body runId');
  assert.equal(draftRes.json.surface, 'bible', 'URL surface must override body surface');
  const wrongDraft = (await env.pool.query(
    "SELECT 1 FROM coherence.review_drafts WHERE (run_id = $1::uuid AND surface = 'adjust') OR (run_id = $2::uuid AND surface = 'adjust')",
    [sentRunId, preEmitRunId],
  )).rows;
  assert.equal(wrongDraft.length, 0, 'Body runId/surface must never be written to review_drafts');

  // 14. Item 3 platform_app negative tests:
  //     Seed two narrow personas to isolate each gate clause cleanly:
  //     - sentOnlyFinanceTok: all cash/ledger/statements/upline/bob/outputs rights, WITHOUT act:coherence.unpublished.read
  //     - noCashColTok: all ledger/statements/upline/bob/outputs + unpublished.read, WITHOUT col:coherence.statement_cash
  const sentOnlyPersonId = randomUUID();
  const noCashPersonId = randomUUID();
  const subOrgUnpubPersonId = randomUUID();
  {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const jSeq = (await c.query(
        `INSERT INTO platform.audit_journal (
           environment, actor_person_id, recorded_as, target_org_id,
           command_kind, command_key, request_sha256, body
         ) VALUES ($1, NULL, 'service', $2::uuid, 'iam.seed_item3_personas', $3, $4, '{}'::jsonb) RETURNING seq`,
        [iam.environment, iam.ids.companyOrg, `item3-personas-${randomUUID()}`, sha256Hex('item3-personas')],
      )).rows[0].seq;
      const seedNarrowRole = async (personId, slug, display, rightList, { extraSubOrgGrant = null } = {}) => {
        const roleId = randomUUID();
        await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,NULL,$3)', [roleId, slug, jSeq]);
        await c.query(
          "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,$3,false,false,true,'active',$4)",
          [randomUUID(), roleId, display, jSeq],
        );
        for (const r of rightList) {
          await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)", [randomUUID(), roleId, r, jSeq]);
        }
        await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [personId, jSeq]);
        await c.query(
          "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,$3,$3,$4,'active',$5)",
          [randomUUID(), personId, display, `${slug}@acme.example`, jSeq],
        );
        await c.query(
          "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
          [randomUUID(), personId, iam.ids.companyOrg, jSeq],
        );
        await c.query(
          "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
          [randomUUID(), personId, roleId, iam.ids.companyOrg, jSeq],
        );
        if (extraSubOrgGrant) {
          const subRoleId = randomUUID();
          await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,NULL,$3)', [subRoleId, `${slug}_sub`, jSeq]);
          await c.query(
            "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,$3,false,false,true,'active',$4)",
            [randomUUID(), subRoleId, `${display} Sub`, jSeq],
          );
          for (const r of extraSubOrgGrant.rights) {
            await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)", [randomUUID(), subRoleId, r, jSeq]);
          }
          await c.query(
            "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
            [randomUUID(), personId, subRoleId, extraSubOrgGrant.orgId, jSeq],
          );
        }
      };
      await seedNarrowRole(sentOnlyPersonId, 'sent_only_finance', 'Sent Only Finance', [
        'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
        'act:coherence.ledger.read', 'act:coherence.outputs.read', 'act:coherence.runs.read',
        'col:coherence.statement_cash', 'col:coherence.upline_cash',
      ]);
      await seedNarrowRole(noCashPersonId, 'no_cash_col', 'No Cash Col', [
        'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
        'act:coherence.ledger.read', 'act:coherence.outputs.read', 'act:coherence.runs.read',
        'act:coherence.unpublished.read', 'col:coherence.upline_cash',
      ]);
      await seedNarrowRole(subOrgUnpubPersonId, 'sub_org_unpub_finance', 'Sub Org Unpub Finance', [
        'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
        'act:coherence.ledger.read', 'act:coherence.runs.read',
        'col:coherence.statement_cash', 'col:coherence.upline_cash',
      ], {
        extraSubOrgGrant: { orgId: iam.ids.beaconOrg, rights: ['act:coherence.unpublished.read'] },
      });
      await c.query('COMMIT');
    } catch (err) {
      await c.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      c.release();
    }
  }
  const sentOnlyFinanceTok = iam.tokenFor(sentOnlyPersonId);
  const noCashColTok = iam.tokenFor(noCashPersonId);
  const subOrgUnpubTok = iam.tokenFor(subOrgUnpubPersonId);

  //     (a) app_views.coherence_effective_statement_batches strictly gates on run_materializations RLS,
  //         the tenant-wide sent/unpublished.read predicate (matching coherence_entity_statement_reconciliation),
  //         plus ledger/statements/upline + col:coherence.statement_cash + col:coherence.upline_cash.
  const effBatchesFor = async (tok, runId) => withRequestTx(appPool, tok, async (tx) => (
    await tx.query('SELECT batch_id FROM app_views.coherence_effective_statement_batches($1::uuid)', [runId])
  ).rows.map((r) => r.batch_id));
  assert.deepEqual(await effBatchesFor(iam.tokens.companyAdmin, sentRunId), [], 'companyAdmin (no cash/ledger rights) must get 0 effective batches on sent run');
  assert.deepEqual(await effBatchesFor(iam.tokens.agentA, sentRunId), [], 'agentA must get 0 effective batches on sent run');
  assert.deepEqual(await effBatchesFor(iam.tokens.agencyMgr, sentRunId), [], 'agencyMgr (no upline_cash/ledger) must get 0 effective batches on sent run');
  assert.deepEqual(await effBatchesFor(noCashColTok, sentRunId), [], 'caller missing col:coherence.statement_cash must get 0 effective batches even on sent run');
  assert.ok((await effBatchesFor(sentOnlyFinanceTok, sentRunId)).length >= 1, 'sent-only finance caller must see effective batches for sent run');
  assert.deepEqual(await effBatchesFor(sentOnlyFinanceTok, unsentRunId), [], 'caller without unpublished.read must get 0 effective batches for unsent run');
  assert.deepEqual(await effBatchesFor(sentOnlyFinanceTok, trialRunId), [], 'caller without unpublished.read must get 0 effective batches for trial run');
  assert.deepEqual(await effBatchesFor(sentOnlyFinanceTok, abandonedRunId), [], 'caller without unpublished.read must get 0 effective batches for abandoned run');
  assert.ok((await effBatchesFor(subOrgUnpubTok, sentRunId)).length >= 1, 'sub-org unpublished.read caller must still see effective batches for sent run');
  assert.deepEqual(await effBatchesFor(subOrgUnpubTok, unsentRunId), [], 'sub-org-only unpublished.read must get 0 effective batches for unsent run (tenant-wide required)');
  assert.ok((await effBatchesFor(iam.tokens.owner, sentRunId)).length >= 1, 'owner must see effective batches for sent run');
  assert.ok((await effBatchesFor(iam.tokens.owner, unsentRunId)).length >= 1, 'owner with unpublished.read must see effective batches for unsent run');
  assert.deepEqual(await effBatchesFor(iam.tokens.owner, trialRunId), [], 'effective batches must hide trial runs even for owner');
  assert.deepEqual(await effBatchesFor(iam.tokens.owner, abandonedRunId), [], 'effective batches must hide abandoned runs even for owner');

  //     (b) app_views.coherence_run_outputs: EVERY file under emits/ (CSVs, emit_metadata.json,
  //         policy_status_meta.json, etc.) gets the full gate; only run.json and company_manifest.json are exempt.
  const emitOutputsFor = async (tok, runId) => withRequestTx(appPool, tok, async (tx) => (
    await tx.query(
      "SELECT rel_path FROM app_views.coherence_run_outputs WHERE run_id = $1::uuid AND rel_path LIKE 'emits/%' ORDER BY rel_path",
      [runId],
    )
  ).rows.map((r) => r.rel_path));
  const allOutputsFor = async (tok, runId) => withRequestTx(appPool, tok, async (tx) => (
    await tx.query(
      'SELECT rel_path FROM app_views.coherence_run_outputs WHERE run_id = $1::uuid ORDER BY rel_path',
      [runId],
    )
  ).rows.map((r) => r.rel_path));
  assert.deepEqual(await emitOutputsFor(iam.tokens.companyAdmin, sentRunId), [], 'companyAdmin (no cash/ledger rights) must see 0 emits/* files on sent run (emit_metadata.json included)');
  assert.deepEqual(await emitOutputsFor(iam.tokens.companyAdmin, unsentRunId), [], 'companyAdmin must see 0 emits/* files on unsent run (emit_metadata.json included)');
  assert.deepEqual(await emitOutputsFor(iam.tokens.companyAdmin, trialRunId), [], 'companyAdmin must see 0 emits/* files on trial run (emit_metadata.json included)');
  assert.deepEqual(await emitOutputsFor(iam.tokens.companyAdmin, abandonedRunId), [], 'companyAdmin must see 0 emits/* files on abandoned run (emit_metadata.json included)');
  assert.deepEqual(await allOutputsFor(iam.tokens.companyAdmin, sentRunId), ['company_manifest.json', 'run.json'], 'companyAdmin with outputs.read sees only exempt run description files outside emits/');
  assert.deepEqual(await emitOutputsFor(noCashColTok, sentRunId), [], 'caller missing col:coherence.statement_cash must see 0 emits/* files even on sent run');
  const sentFinanceEmits = await emitOutputsFor(sentOnlyFinanceTok, sentRunId);
  assert.ok(sentFinanceEmits.includes('emits/emit_metadata.json'), 'sent-only finance caller must see emits/emit_metadata.json on sent run');
  assert.ok(sentFinanceEmits.includes('emits/policy_status_meta.json'), 'sent-only finance caller must see emits/policy_status_meta.json on sent run');
  assert.deepEqual(await emitOutputsFor(sentOnlyFinanceTok, unsentRunId), [], 'caller without unpublished.read must see 0 emits/* files on unsent run');
  assert.deepEqual(await emitOutputsFor(sentOnlyFinanceTok, trialRunId), [], 'caller without unpublished.read must see 0 emits/* files on trial run');
  assert.deepEqual(await emitOutputsFor(sentOnlyFinanceTok, abandonedRunId), [], 'caller without unpublished.read must see 0 emits/* files on abandoned run');
  const ownerSentEmits = await emitOutputsFor(iam.tokens.owner, sentRunId);
  assert.ok(ownerSentEmits.includes('emits/emit_metadata.json'), 'owner must see emits/emit_metadata.json on sent run');
  const ownerUnsentEmits = await emitOutputsFor(iam.tokens.owner, unsentRunId);
  assert.ok(ownerUnsentEmits.includes('emits/emit_metadata.json'), 'owner with unpublished.read must see emits/emit_metadata.json on unsent run');
  assert.deepEqual(await emitOutputsFor(iam.tokens.owner, trialRunId), [], 'app_views.coherence_run_outputs must hide all emits/* files on trial run');
  assert.deepEqual(await emitOutputsFor(iam.tokens.owner, abandonedRunId), [], 'app_views.coherence_run_outputs must hide all emits/* files on abandoned run');

  //     (c) app_views.coherence_published_runs: unsent runs require unpublished.read (no runs.read fallback).
  //         sentOnlyFinanceTok holds runs.read while newer unsentRunId (2026-10-31) exists after sentRunId (2026-10-15).
  const pubIdsForSentOnly = await withRequestTx(appPool, sentOnlyFinanceTok, async (tx) => (
    await tx.query('SELECT id FROM app_views.coherence_published_runs ORDER BY statement_date DESC')
  ).rows.map((r) => r.id));
  assert.deepEqual(pubIdsForSentOnly, [sentRunId], 'sent-only finance caller holding runs.read must see ONLY sent runs in coherence_published_runs');
  const latestForSentOnly = await findLatestPublishedRun(appPool, sentOnlyFinanceTok);
  assert.equal(latestForSentOnly?.id, sentRunId, 'findLatestPublishedRun for sent-only finance caller holding runs.read must select sentRunId, not newer unsentRunId');
  const sentOnlySummary = await reader.summary(sentOnlyFinanceTok);
  assert.equal(sentOnlySummary.available, true, 'sent-only finance caller reader.summary must succeed on sentRunId');
  assert.equal(sentOnlySummary.runId, sentRunId);

  // Test reconciliation view gates too: sentOnlyFinanceTok and subOrgUnpubTok see sentRunId only; companyAdmin & noCashColTok see 0 rows!
  const reconRunIdsFor = async (tok) => withRequestTx(appPool, tok, async (tx) => (
    await tx.query('SELECT DISTINCT run_id FROM app_views.coherence_entity_statement_reconciliation')
  ).rows.map((r) => r.run_id));
  assert.deepEqual(await reconRunIdsFor(iam.tokens.companyAdmin), [], 'companyAdmin without cash/ledger rights must see 0 reconciliation rows');
  assert.deepEqual(await reconRunIdsFor(noCashColTok), [], 'caller missing statement_cash must see 0 reconciliation rows');
  assert.deepEqual(await reconRunIdsFor(sentOnlyFinanceTok), [sentRunId], 'caller without unpublished.read must see reconciliation ONLY for sent run');
  assert.deepEqual(await reconRunIdsFor(subOrgUnpubTok), [sentRunId], 'sub-org unpublished.read must see reconciliation ONLY for sent run');
  const ownerReconIds = new Set(await reconRunIdsFor(iam.tokens.owner));
  assert.equal(ownerReconIds.has(sentRunId), true);
  assert.equal(ownerReconIds.has(unsentRunId), true);
  assert.equal(ownerReconIds.has(trialRunId), false, 'reconciliation must exclude trial runs');
  assert.equal(ownerReconIds.has(abandonedRunId), false, 'reconciliation must exclude abandoned runs');

  // 15. Item B HTTP negative test: publishInputVersion with storeCanonicalList must check the DB first
  //     and never write a new object to dataStore for agentA, a bad token, or a View-as token.
  {
    const beforeObjs = env.dataStore.backend.listObjectNames();
    const canonicalBody = (key) => JSON.stringify({
      commandKey: key,
      lineKind: 'snapshot',
      sourceKind: 'upload',
      reason: 'canonical list DB-first check',
      entries: [{ relPath: `canonical-probe-${key}.csv`, fileSha256: stagedFile.sha256 }],
      storeCanonicalList: true,
    });
    for (const [label, tok, expectedCode] of [
      ['agentA', iam.tokens.agentA, null],
      ['bad_token', iam.tokens.tampered, null],
      ['view_as', iam.tokens.viewAsAgentA, 'VIEW_AS_READ_ONLY'],
    ]) {
      const res = await callHttp(tok, '/api/coherence/acme/inputs/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: canonicalBody(`canon-neg-${label}`),
      });
      assert.equal(res.status, 403, `storeCanonicalList with ${label} must return 403 (got ${res.status}: ${res.text})`);
      if (expectedCode) {
        assert.equal(res.json?.code, expectedCode, `storeCanonicalList with ${label} must return ${expectedCode}`);
      }
      assert.deepEqual(
        env.dataStore.backend.listObjectNames(),
        beforeObjs,
        `storeCanonicalList rejected for ${label} must leave dataStore with zero new objects`,
      );
    }

    // Positive + idempotent replay check: authorized owner writes canonical list once; replay does not write again.
    const okBody = canonicalBody('canon-pos-owner');
    const okRes = await callHttp(iam.tokens.owner, '/api/coherence/acme/inputs/publish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: okBody,
    });
    assert.equal(okRes.status, 201, `authorized storeCanonicalList must return 201 (got ${okRes.status}: ${okRes.text})`);
    const afterObjs = env.dataStore.backend.listObjectNames();
    assert.equal(afterObjs.length, beforeObjs.length + 1, 'authorized storeCanonicalList must write exactly one new canonical list object');

    let replayCreates = 0;
    env.dataStore.backend.hooks.onCreate = () => { replayCreates += 1; };
    try {
      const replayRes = await callHttp(iam.tokens.owner, '/api/coherence/acme/inputs/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: okBody,
      });
      assert.equal(replayRes.status, 201);
      assert.equal(replayRes.json?.idempotent, true);
      assert.equal(replayCreates, 0, 'idempotent replay of publishInputVersion(storeCanonicalList) must not write to dataStore');
    } finally {
      env.dataStore.backend.hooks.onCreate = null;
    }
  }

  // 16. Item 6 negative test: Sent/statements_<date>.csv in standing input_entries without a sent carry
  //     must NOT mark an unsent run as sent in app_views.coherence_published_runs!
  const fakeSentBytes = await env.dataStore.promoteBytes(Buffer.from('entity,amount\nBeacon,10.00\n', 'utf8'), {
    relPath: 'Sent/statements_20261031.csv',
    checksPassed: true,
  });
  await env.commands.publishInputVersion({
    dbToken: env.ownerToken,
    commandKey: 'r1b-fake-sent-input-entry',
    lineKind: 'standing',
    sourceKind: 'company_import',
    reason: 'add Sent/ file without sent carry',
    entries: [{ relPath: 'Sent/statements_20261031.csv', fileSha256: fakeSentBytes.sha256 }],
    storedFiles: [fakeSentBytes],
  });
  const pubRow = await withRequestTx(appPool, iam.tokens.owner, async (tx) => (
    await tx.query('SELECT sent FROM app_views.coherence_published_runs WHERE id = $1::uuid', [unsentRunId])
  ).rows[0]);
  assert.equal(pubRow?.sent, false, 'app_views.coherence_published_runs must derive sent strictly from coherence.carries (carry_kind = sent)');

  // 16. Item 12 negative test: ?asOf= for a caller without journal.read refuses clearly with 403 instead of returning empty lists!
  const asOfIso = encodeURIComponent(new Date().toISOString());
  for (const path of [
    `/api/coherence/acme/runs?asOf=${asOfIso}`,
    `/api/coherence/acme/inputs/versions?asOf=${asOfIso}`,
    `/api/coherence/acme/runs/${unsentRunId}?asOf=${asOfIso}`,
    `/api/coherence/acme/history/as-of?asOf=${asOfIso}`,
  ]) {
    const denied = await callHttp(iam.tokens.companyAdmin, path);
    assert.equal(denied.status, 403, `companyAdmin without journal.read must get 403 on ${path} (got ${denied.status}: ${denied.text})`);
    assert.equal(denied.json?.code, 'FORBIDDEN', `companyAdmin ?asOf= error code must be FORBIDDEN on ${path}`);
  }
  const ownerAsOf = await callHttp(iam.tokens.owner, `/api/coherence/acme/runs?asOf=${asOfIso}`);
  assert.equal(ownerAsOf.status, 200, 'owner with journal.read must succeed on ?asOf=');
  assert.ok(ownerAsOf.json.runs.length >= 2);
});

test('Layer 7C [Worker app_cmd Path & Privileged-Write Deletion]: privileged write path is completely gone, worker/reconciler mandate workerToken, and platform_worker runs full pipeline strictly via app_cmd.* with non-NULL organization_id', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const iam = env.iam;
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const workerPool = createRoleScopedTestPool(env.pool, 'platform_worker');

  // 1. Privileged write table and functions are deleted from the schema, and worker/reconciler refuse without workerToken.
  const privTbl = (await env.pool.query(
    "SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'coherence' AND c.relname = 'privileged_write_grants'",
  )).rows;
  assert.equal(privTbl.length, 0, 'coherence.privileged_write_grants must be deleted');
  const privFns = (await env.pool.query(
    "SELECT proname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'coherence' AND proname IN ('begin_privileged_write', 'end_privileged_write')",
  )).rows;
  assert.equal(privFns.length, 0, 'begin_privileged_write and end_privileged_write must be deleted');

  assert.throws(
    () => createEngineWorker({
      pool: workerPool,
      pgConfig: env.pgConfig,
      companySlug: 'acme',
      stores: env.stores,
      commands: env.commands,
      workerToken: null,
    }),
    /MISSING_WORKER_TOKEN|signed workerToken/i,
    'createEngineWorker must refuse when workerToken is missing',
  );
  await assert.rejects(
    () => reconcileInterruptedAttempts({ pool: workerPool, commands: env.commands, workerToken: '' }),
    /MISSING_WORKER_TOKEN|signed workerToken/i,
    'reconcileInterruptedAttempts must refuse when workerToken is missing',
  );

  // Passing an actor object without dbToken to createAppCommands fails closed with 403!
  const appCommands = createAppCommands({ pool: appPool, stores: env.stores });
  const workerCommands = createAppCommands({ pool: workerPool, stores: env.stores });
  await assert.rejects(
    () => appCommands.recordCheck({
      actor: { id: 'spoof-owner', kind: 'owner' },
      commandKey: 'no-token-actor-attempt',
      checkKind: 'chain',
      passed: true,
      report: { ok: true },
    }),
    (err) => err?.status === 403,
    'createAppCommands must refuse actor-without-token calls with 403',
  );

  // 2. Seed engine + input via platform_app (operator/owner tokens), then run the entire worker pipeline
  //    strictly as platform_worker using signed workerToken through app_cmd.*.
  const { engineVersionId } = await seedEngineCopyVersion(env);
  await seedStandingInput(env);

  const launch = await appCommands.launchRun({
    dbToken: iam.tokens.operator,
    commandKey: 'worker-token-launch',
    statementDate: '2026-10-31',
    origin: 'app',
    engineVersionId,
  });
  const runId = launch.result.runId;

  const workerClientFactory = async () => {
    const client = await createClient(env.pgConfig);
    await client.query('SET ROLE platform_worker');
    return client;
  };
  const worker = env.registerWorker(createEngineWorker({
    pool: workerPool,
    pgConfig: env.pgConfig,
    clientFactory: workerClientFactory,
    companySlug: 'acme',
    stores: env.stores,
    commands: workerCommands,
    workerToken: iam.tokens.worker,
    materializeEngine: createDataOnlyMockEngineMaterializer({
      adjustReconfirmRecordId: null,
      datasetBuilder: ({ statementDate = '2026-10-31' } = {}) => {
        const d = buildCanaryEmitCsvs({ statementDate });
        return {
          canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, d.bobRows),
          coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, d.ledgerRows),
          statementsCsv: d.statementsCsv,
          emitMetadataJson: JSON.stringify({ statementDate, build: 'copy001', corpusTail: statementDate.slice(0, 7), agencyStart: '2026-01-01' }),
          workingTxCsv: makeCsvFromObjects(['tx_id', 'filename', 'sheet_name', 'source_position'], [
            { tx_id: 1, filename: 'carrier_a.csv', sheet_name: 'Commissions', source_position: 1 },
          ]),
        };
      },
    }),
    tempBaseDir: env.tempDir,
  }));

  // assign -> attribute -> bible strictly as platform_worker
  for (let i = 0; i < 3; i++) {
    assert.equal((await worker.runOnce()).action, 'step_finished');
  }

  // Operator commits Bible decisions via app_cmd
  const bibleQueue = (await env.pool.query(
    "SELECT record_id FROM coherence.review_queue_items WHERE run_id = $1::uuid AND surface = 'bible' ORDER BY item_order",
    [runId],
  )).rows;
  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await appCommands.saveReviewDecisions({
    dbToken: iam.tokens.operator,
    commandKey: 'worker-token-bible-save',
    expectedJournalSeq: seq,
    runId,
    surface: 'bible',
    decisions: bibleQueue.map((q) => ({ recordId: q.record_id, disposition: 'CONFIRM' })),
  });

  // adjust step strictly as platform_worker
  assert.equal((await worker.runOnce()).action, 'step_finished');

  // Operator saves Adjust decisions + confirms Emit via app_cmd
  const adjustQueue = (await env.pool.query(
    "SELECT record_id FROM coherence.review_queue_items WHERE run_id = $1::uuid AND surface = 'adjust' ORDER BY item_order",
    [runId],
  )).rows;
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  const adjSave = await appCommands.saveReviewDecisions({
    dbToken: iam.tokens.operator,
    commandKey: 'worker-token-adjust-save',
    expectedJournalSeq: seq,
    runId,
    surface: 'adjust',
    decisions: adjustQueue.map((q) => ({ recordId: q.record_id, disposition: 'CONFIRM' })),
  });
  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await appCommands.confirmEmit({
    dbToken: iam.tokens.owner,
    commandKey: 'worker-token-confirm-emit',
    expectedJournalSeq: seq,
    runId,
    adjustReviewSaveId: adjSave.result.reviewSaveId,
    typedPhrase: 'create statements for 2026-10-31',
  });

  // Emit + atomic materialization strictly as platform_worker (resolving IAM org/person FKs live!)
  const emitRes = await worker.runOnce();
  if (emitRes.action !== 'step_finished') {
    const errRow = (await env.pool.query('SELECT error_summary FROM coherence.step_attempt_events WHERE run_id = $1::uuid AND step = \'emit\' ORDER BY journal_seq DESC LIMIT 1', [runId])).rows[0];
    assert.fail(`emit returned ${emitRes.action}: ${errRow?.error_summary || JSON.stringify(emitRes)}`);
  }
  assert.equal(emitRes.step, 'emit');

  // Confirm live materialized rows have non-NULL organization_id and are readable via app_views.*!
  const matRows = (await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.run_materializations WHERE run_id = $1::uuid', [runId])).rows[0].n;
  assert.equal(matRows, 1);
  const periods = await readCurrentPolicyPeriods(appPool, iam.tokens.owner);
  assert.equal(periods.length, 4);

  // 3. CSV-mode materializeEmit is worker-only and requires statementDate + attemptEventId:
  //    platform_app never reaches coherence.*, and platform_worker never needs app_views.*.
  const preHistStored = await env.dataStore.promoteBytes(Buffer.from('legacy pre-coherence\n', 'utf8'), {
    relPath: 'Prior Statements/ALLAGENCY20260731.csv',
    checksPassed: true,
  });
  const preRecId = 'carrier_a~direct~OLD WORKER~100.00~2026-07';
  await appCommands.recordStatementBatch({
    dbToken: iam.tokens.owner,
    commandKey: 'worker-csv-pre-hist',
    batchKind: 'historical_sent',
    statementDate: '2026-07-31',
    sourceFileName: 'ALLAGENCY20260731.csv',
    sourceFile: preHistStored,
    reason: 'Pre-Coherence sent statement for worker CSV-mode unwind proof',
    agencyLines: [{
      entity: 'Beacon',
      writingNpn: '11111111',
      writingAgent: 'Sam Seller',
      recordId: preRecId,
      carrier: 'carrier_a',
      member: 'Old Worker',
      srcType: 'direct',
      paymentDate: '2026-07-20',
      grossComm: '100.00',
      amount: '80.00',
    }],
    uplineLines: [{
      sourceEntity: 'Beacon',
      writingNpn: '11111111',
      writingAgent: 'Sam Seller',
      recordId: preRecId,
      carrier: 'carrier_a',
      member: 'Old Worker',
      srcType: 'direct',
      paymentDate: '2026-07-20',
      grossComm: '100.00',
      amount: '20.00',
    }],
  });
  const unwindBobCsv = makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, []);
  const unwindLedgerCsv = makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, []);
  const unwindStmtCsv = makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, [{
    record_id: preRecId, external_policy_id: '', policy_id: '', tx_id: '',
    statement_name: 'ALLAGENCY20260731.csv', src_type: 'direct', carrier: 'carrier_a', mbi: '', member: 'Old Worker',
    state: 'FL', plan_type: '', simple_plan_type: '',
    submission_date: '', origin_effective: '', effective_date: '', termination_date: '',
    earned_date: '', payment_date: '2026-07-20', statement_date: '', min_date: '',
    gross_comm: '-100.00', revenue_type: 'commission', override_amount: '', commission_amount: '-100.00', hra_amount: '', fee_amount: '', other_amount: '',
    downline_amount: '', upline_amount: '',
    writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon', payee_npn: '', agency_id: '',
    status: '', policy_status: '', cbob_c: 'false', cbob_s: 'false', sf: 'false', notes: '', coherent_notes: 'CANCEL',
    run_action: 'CANCEL', run_statement_date: '2026-08-31', reversal_of: preRecId, reason: 'cancel pre-coherence',
  }]);
  const unwindStmtArt = await env.stores.promoteArtifact('emits/statements_20260831.csv', Buffer.from(unwindStmtCsv, 'utf8'), { checksPassed: true });
  const unwindImp = await appCommands.importHistoricalRun({
    dbToken: iam.tokens.owner,
    commandKey: 'worker-csv-unwind-import',
    run: { origin: 'company_import', statementDate: '2026-08-31', sourceFolder: 'company-workspaces/acme/2026-08-31/runs/2026-08-31', emitMode: 'coherence' },
    inputVersion: { reason: 'pre-coherence unwind input' },
    inputEntries: [{ relPath: 'Prior Statements/ALLAGENCY20260731.csv', fileSha256: preHistStored.sha256 }],
    stepAttempts: [{
      step: 'emit',
      attemptNo: 1,
      artifacts: [{ relPath: unwindStmtArt.relPath, artifactKind: unwindStmtArt.artifactKind, storeKind: unwindStmtArt.storeKind, fileSha256: unwindStmtArt.sha256 }],
    }],
    storedFiles: [preHistStored, unwindStmtArt],
  });
  const unwindRunId = unwindImp.result.runId;
  const unwindEmitEv = (await env.pool.query(
    "SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev",
    [unwindRunId],
  )).rows[0].ev;

  // platform_app must be refused with 403 WORKER_ONLY before ever touching coherence.*.
  await assert.rejects(
    () => appCommands.materializeEmit({
      dbToken: iam.tokens.owner,
      commandKey: 'app-csv-mat-refuse',
      runId: unwindRunId,
      attemptEventId: unwindEmitEv,
      statementDate: '2026-08-31',
      canonicalBobCsv: unwindBobCsv,
      coherentLedgerCsv: unwindLedgerCsv,
      statementsCsv: unwindStmtCsv,
    }),
    (err) => err?.status === 403 && err?.code === 'WORKER_ONLY',
    'platform_app CSV-mode materializeEmit must fail closed with 403 WORKER_ONLY',
  );

  // platform_worker omitting statementDate or attemptEventId gets 400 MISSING_MATERIALIZATION_CONTEXT (never hits app_views.*).
  await assert.rejects(
    () => workerCommands.materializeEmit({
      dbToken: iam.tokens.worker,
      commandKey: 'worker-csv-mat-missing-ctx',
      runId: unwindRunId,
      canonicalBobCsv: unwindBobCsv,
      coherentLedgerCsv: unwindLedgerCsv,
      statementsCsv: unwindStmtCsv,
    }),
    (err) => err?.status === 400 && err?.code === 'MISSING_MATERIALIZATION_CONTEXT',
    'platform_worker CSV-mode materializeEmit without statementDate/attemptEventId must fail with 400 MISSING_MATERIALIZATION_CONTEXT',
  );

  // platform_worker providing statementDate + attemptEventId succeeds cleanly including NULL-split balance unwind on coherence.*!
  const workerMat = await workerCommands.materializeEmit({
    dbToken: iam.tokens.worker,
    commandKey: 'worker-csv-mat-unwind-ok',
    runId: unwindRunId,
    attemptEventId: unwindEmitEv,
    statementDate: '2026-08-31',
    canonicalBobCsv: unwindBobCsv,
    coherentLedgerCsv: unwindLedgerCsv,
    statementsCsv: unwindStmtCsv,
  });
  assert.equal(workerMat.result.agencyLineCount, 1);
  assert.equal(workerMat.result.uplineLineCount, 1);
});
