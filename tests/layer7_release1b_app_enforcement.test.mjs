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
import { fingerprintBytes, sha256Hex } from '../src/util/crypto.mjs';
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
  appendIamAuditEntry,
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

  // Verify Migration 010 live catalog audit passes across all 39 app_views.* and 33 app_cmd.*!
  const catalogAudit = await withClusterCatalogLock(() => verifyIamConfigInvariants(env.pool));
  assert.equal(catalogAudit.passed, true, `verifyIamConfigInvariants failed:\n${catalogAudit.problems.join('\n')}`);
  assert.equal(catalogAudit.checkedAppViews, 39);
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
        'col:coherence.member_phi', 'col:coherence.member_contact',
      ]);
      await seedNarrowRole(noCashPersonId, 'no_cash_col', 'No Cash Col', [
        'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
        'act:coherence.ledger.read', 'act:coherence.outputs.read', 'act:coherence.runs.read',
        'act:coherence.unpublished.read', 'col:coherence.upline_cash',
        'col:coherence.member_phi', 'col:coherence.member_contact',
      ]);
      await seedNarrowRole(subOrgUnpubPersonId, 'sub_org_unpub_finance', 'Sub Org Unpub Finance', [
        'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
        'act:coherence.ledger.read', 'act:coherence.runs.read',
        'col:coherence.statement_cash', 'col:coherence.upline_cash',
        'col:coherence.member_phi', 'col:coherence.member_contact',
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

test('Layer 7C [Release C1 - Shared Rights Checks (9a, 9b, Journal Gate) & Store-Kind Boundary Guard (9c)]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const iam = env.iam;
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const workerPool = createRoleScopedTestPool(env.pool, 'platform_worker');
  const appCommands = createAppCommands({ pool: appPool, stores: env.stores });
  const workerCommands = createAppCommands({ pool: workerPool, stores: env.stores });
  const { engineVersionId } = await seedEngineCopyVersion(env);
  await seedStandingInput(env, { commandKey: 'c1-standing-init' });

  // Seed two runs that BOTH carry an Entity Manager viewer bundle:
  //   1) sentRunId   (2026-10-15, SENT)
  //   2) unsentRunId (2026-11-15, UNSENT)
  async function seedBundleRun({ date, keyPrefix, markSent }) {
    const dataset = buildCanaryEmitCsvs({ statementDate: date });
    const viewerHtml = Buffer.from(
      `<!doctype html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify({
        name: 'Entity Manager', title: 'Acme', statementDate: date, role: 'ENTITY_MANAGER',
        features: { CANONICAL_BOB: { canonical_bob: 'data/canonical_bob.csv' }, COHERENT_LEDGER: { coherent_ledger: 'data/coherent_ledger.csv' } },
      })};</script></head>`,
      'utf8',
    );
    const viewer = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme/viewer.html', viewerHtml, { checksPassed: true });
    const bob = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme/data/canonical_bob.csv', Buffer.from(dataset.bobCsv, 'utf8'), { checksPassed: true });
    const led = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme/data/coherent_ledger.csv', Buffer.from(dataset.ledgerCsv, 'utf8'), { checksPassed: true });
    const stmt = await env.stores.promoteArtifact(`emits/statements_${date.replace(/-/g, '')}.csv`, Buffer.from(dataset.statementsCsv, 'utf8'), { checksPassed: true });
    const inp = await env.dataStore.promoteBytes(Buffer.from(`k\n${date}\n`, 'utf8'), { relPath: `imp_${date}.csv`, checksPassed: true });
    const imp = await env.commands.importHistoricalRun({
      dbToken: env.ownerToken,
      commandKey: `${keyPrefix}-import`,
      run: { origin: 'company_import', statementDate: date, sourceFolder: `company-workspaces/acme/${date}/runs/${date}`, emitMode: 'coherence' },
      inputVersion: { reason: `${keyPrefix} import` },
      inputEntries: [{ relPath: `imp_${date}.csv`, fileSha256: inp.sha256 }],
      stepAttempts: [{
        step: 'emit',
        attemptNo: 1,
        artifacts: [viewer, bob, led, stmt].map((f) => ({
          relPath: f.relPath, artifactKind: f.artifactKind, storeKind: f.storeKind, fileSha256: f.sha256,
        })),
      }],
      storedFiles: [inp, viewer, bob, led, stmt],
    });
    const runId = imp.result.runId;
    const emitEv = (await env.pool.query("SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev", [runId])).rows[0].ev;
    await env.commands.materializeEmit({
      dbToken: env.workerToken,
      commandKey: `${keyPrefix}-mat`,
      runId,
      attemptEventId: emitEv,
      statementDate: date,
      canonicalBobCsv: dataset.bobCsv,
      coherentLedgerCsv: dataset.ledgerCsv,
      statementsCsv: dataset.statementsCsv,
    });
    if (markSent) {
      await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: `${keyPrefix}-sent`, runId, typedPhrase: `sent ${date}` });
    }
    return runId;
  }

  const sentRunId = await seedBundleRun({ date: '2026-10-15', keyPrefix: 'c1-sent', markSent: true });
  const unsentRunId = await seedBundleRun({ date: '2026-11-15', keyPrefix: 'c1-unsent', markSent: false });

  // Seed custom test principals in one transaction
  const customPeople = {
    missingStmtCash: randomUUID(),
    missingStmtsRead: randomUUID(),
    missingUplineRead: randomUUID(),
    fullEmSentOnly: randomUUID(),
    disjointUnpub: randomUUID(),
    sentEmSubOrgUnpub: randomUUID(),
    runsReadOnly: randomUUID(),
    outputsReadOnly: randomUUID(),
    decisionsReadOnly: randomUUID(),
  };

  {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const j = await appendIamAuditEntry(c, {
        environment: iam.environment,
        commandKind: 'iam.c1_custom_roles',
        commandKey: 'c1-custom-roles',
        targetOrgId: iam.ids.companyOrg,
      });
      const seq = j.seq;
      const seedCustomPerson = async (personId, slug, grants) => {
        await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [personId, seq]);
        await c.query(
          "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,$3,$3,$4,'active',$5)",
          [randomUUID(), personId, slug, `${slug}@acme.example`, seq],
        );
        const memberOrgs = [...new Set(grants.map((g) => g.orgId))];
        for (const orgId of memberOrgs) {
          await c.query(
            "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
            [randomUUID(), personId, orgId, seq],
          );
        }
        let idx = 0;
        for (const g of grants) {
          idx += 1;
          const roleId = randomUUID();
          await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,NULL,$3)', [roleId, `${slug}_r${idx}`, seq]);
          await c.query(
            "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,$3,false,false,true,'active',$4)",
            [randomUUID(), roleId, `${slug} role ${idx}`, seq],
          );
          for (const rightId of g.rights) {
            await c.query(
              "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
              [randomUUID(), roleId, rightId, seq],
            );
          }
          await c.query(
            "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
            [randomUUID(), personId, roleId, g.orgId, seq],
          );
        }
      };

      const fullEmRights = [
        'act:coherence.bob.read',
        'act:coherence.ledger.read',
        'act:coherence.statements.read',
        'act:coherence.upline.read',
        'col:coherence.statement_cash',
        'col:coherence.upline_cash',
        'col:coherence.member_phi',
        'col:coherence.member_contact',
      ];
      await seedCustomPerson(customPeople.missingStmtCash, 'c1_missing_stmt_cash', [{
        orgId: iam.ids.companyOrg,
        rights: [...fullEmRights.filter((r) => r !== 'col:coherence.statement_cash'), 'act:coherence.unpublished.read'],
      }]);
      await seedCustomPerson(customPeople.missingStmtsRead, 'c1_missing_stmts_read', [{
        orgId: iam.ids.companyOrg,
        rights: [...fullEmRights.filter((r) => r !== 'act:coherence.statements.read'), 'act:coherence.unpublished.read'],
      }]);
      await seedCustomPerson(customPeople.missingUplineRead, 'c1_missing_upline_read', [{
        orgId: iam.ids.companyOrg,
        rights: [...fullEmRights.filter((r) => r !== 'act:coherence.upline.read'), 'act:coherence.unpublished.read'],
      }]);
      await seedCustomPerson(customPeople.fullEmSentOnly, 'c1_full_em_sent', [{
        orgId: iam.ids.companyOrg,
        rights: fullEmRights,
      }]);
      await seedCustomPerson(customPeople.disjointUnpub, 'c1_disjoint_unpub', [
        { orgId: iam.ids.beaconOrg, rights: ['act:coherence.bob.read'] },
        { orgId: iam.ids.harborOrg, rights: ['act:coherence.unpublished.read'] },
      ]);
      await seedCustomPerson(customPeople.sentEmSubOrgUnpub, 'c1_sent_em_sub_unpub', [
        { orgId: iam.ids.companyOrg, rights: fullEmRights },
        { orgId: iam.ids.beaconOrg, rights: ['act:coherence.unpublished.read'] },
      ]);
      await seedCustomPerson(customPeople.runsReadOnly, 'c1_runs_only', [
        { orgId: iam.ids.companyOrg, rights: ['act:coherence.runs.read'] },
      ]);
      await seedCustomPerson(customPeople.outputsReadOnly, 'c1_outputs_only', [
        { orgId: iam.ids.companyOrg, rights: ['act:coherence.bob.read', 'act:coherence.outputs.read'] },
      ]);
      await seedCustomPerson(customPeople.decisionsReadOnly, 'c1_decisions_only', [
        { orgId: iam.ids.companyOrg, rights: ['act:coherence.bob.read', 'act:coherence.decisions.read'] },
      ]);
      await c.query('COMMIT');
    } catch (err) {
      await c.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      c.release();
    }
  }

  const reader = createDatabaseCoherenceReader({ pool: appPool, stores: env.stores, entity: 'Acme' });

  await t.test('Item 1 (9a): custom role missing statement_cash, statements.read, or upline.read gets nothing from coherence_entity_bundle_artifacts, artifacts_iam_read, and stored_files_iam_read', async () => {
    for (const [label, personId] of [
      ['missing col:coherence.statement_cash', customPeople.missingStmtCash],
      ['missing act:coherence.statements.read', customPeople.missingStmtsRead],
      ['missing act:coherence.upline.read', customPeople.missingUplineRead],
    ]) {
      const tok = iam.tokenFor(personId);
      const bundleRows = await withRequestTx(appPool, tok, async (tx) => (
        await tx.query('SELECT run_id, rel_path FROM app_views.coherence_entity_bundle_artifacts')
      ).rows);
      assert.deepEqual(bundleRows, [], `${label} must get 0 rows from app_views.coherence_entity_bundle_artifacts`);

      const sumSent = await reader.summary(tok, { runId: sentRunId });
      assert.equal(sumSent.available, false, `${label} must get available=false from reader.summary on sent run`);
      const sumLatest = await reader.summary(tok);
      assert.equal(sumLatest.available, false, `${label} must get available=false from reader.summary on latest run`);

      // Direct platform_view_owner check confirms artifacts_iam_read and stored_files_iam_read also refuse the EM branch.
      const voClient = await env.pool.connect();
      try {
        await voClient.query('BEGIN TRANSACTION READ ONLY');
        await voClient.query('SET LOCAL ROLE platform_view_owner');
        await voClient.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [tok]);
        const artCnt = (await voClient.query('SELECT COUNT(*)::int AS n FROM coherence.artifacts')).rows[0].n;
        const sfCnt = (await voClient.query('SELECT COUNT(*)::int AS n FROM coherence.stored_files')).rows[0].n;
        await voClient.query('COMMIT');
        assert.equal(artCnt, 0, `${label} must see 0 rows via artifacts_iam_read`);
        assert.equal(sfCnt, 0, `${label} must see 0 rows via stored_files_iam_read`);
      } finally {
        await voClient.query('ROLLBACK').catch(() => {});
        voClient.release();
      }
    }

    // Control: role with all eight entity-finance and member rights reads sentRunId entity bundle cleanly.
    const fullEmTok = iam.tokenFor(customPeople.fullEmSentOnly);
    const controlRows = await withRequestTx(appPool, fullEmTok, async (tx) => (
      await tx.query('SELECT run_id, rel_path FROM app_views.coherence_entity_bundle_artifacts')
    ).rows);
    assert.ok(controlRows.length >= 3 && controlRows.every((r) => r.run_id === sentRunId), 'control role holding all eight entity-finance and member rights must read sentRunId bundle artifacts');
    const controlSum = await reader.summary(fullEmTok);
    assert.equal(controlSum.available, true);
    assert.equal(controlSum.runId, sentRunId);
  });

  await t.test('Item 1 (9b + downstream reader): disjoint bob.read and unpublished.read agencies see no unsent run, and downstream reader picks newest run it can open', async () => {
    const disjointTok = iam.tokenFor(customPeople.disjointUnpub);
    const pubRuns = await withRequestTx(appPool, disjointTok, async (tx) => (
      await tx.query('SELECT id, sent FROM app_views.coherence_published_runs ORDER BY statement_date DESC')
    ).rows);
    assert.deepEqual(pubRuns.map((r) => r.id), [sentRunId], 'caller with bob.read on Beacon and unpublished.read on Harbor must see no unsent run in coherence_published_runs');
    assert.equal(pubRuns[0].sent, true);

    const latestDisjoint = await findLatestPublishedRun(appPool, disjointTok);
    assert.equal(latestDisjoint?.id, sentRunId, 'findLatestPublishedRun must pick sentRunId when bob.read and unpublished.read are disjoint');

    const periodsDisjoint = await readCurrentPolicyPeriods(appPool, disjointTok);
    assert.ok(periodsDisjoint.length > 0 && periodsDisjoint.every((r) => r.run_id === sentRunId), 'policy periods must stay on sentRunId');

    // Downstream reader: caller with all-6 sent EM rights on Acme + unpublished.read ONLY on Beacon
    // can see unsentRunId in coherence_published_runs (for Beacon rows), cannot open unsentRunId's
    // Entity Manager bundle, and must open sentRunId (newest run it can open) instead of failing closed!
    const subUnpubTok = iam.tokenFor(customPeople.sentEmSubOrgUnpub);
    const subSummary = await reader.summary(subUnpubTok);
    assert.equal(subSummary.available, true, 'downstream reader must pick newest run it can open instead of failing closed on unreadable newer unsent run');
    assert.equal(subSummary.runId, sentRunId);
    assert.equal(subSummary.sent, true);
    const subFile = await reader.file(subUnpubTok, 'data/canonical_bob.csv');
    assert.ok(subFile.body.toString('utf8').includes('987654.32'));

    // Control: owner (tenant-wide unpublished.read) opens newer unsentRunId.
    const ownerSummary = await reader.summary(iam.tokens.owner);
    assert.equal(ownerSummary.available, true);
    assert.equal(ownerSummary.runId, unsentRunId);
    assert.equal(ownerSummary.sent, false);

    // Dedicated journal gate view exists and enforces journal.read separately from review drift gate.
    const ownerGate = await withRequestTx(appPool, iam.tokens.owner, async (tx) => (
      await tx.query('SELECT authorized FROM app_views.coherence_journal_gate LIMIT 1')
    ).rows);
    assert.equal(ownerGate.length, 1);
    assert.equal(ownerGate[0].authorized, true);
    const adminGate = await withRequestTx(appPool, iam.tokens.companyAdmin, async (tx) => (
      await tx.query('SELECT authorized FROM app_views.coherence_journal_gate LIMIT 1')
    ).rows);
    assert.deepEqual(adminGate, []);
  });

  await t.test('Item 2 (9c + sibling commands): wrong store_kind is refused across data commands as operator/owner/worker and code command as owner', async () => {
    const fakeCodeBytes = Buffer.from('console.log("not allowed in data command");\n', 'utf8');
    const fakeCodeFp = fingerprintBytes(fakeCodeBytes);
    const fakeCodeFile = {
      storeKind: 'nusear_code',
      sha256: fakeCodeFp.sha256,
      byteSize: fakeCodeFp.byteSize,
      md5B64: fakeCodeFp.md5B64,
      crc32cB64: fakeCodeFp.crc32cB64,
      objectName: `objects/${fakeCodeFp.sha256}`,
    };

    // Preserve current standing entries so publishInputVersion would succeed without the store_kind guard!
    const curStandingId = (await env.pool.query('SELECT coherence.standing_input_version_as_of(NULL) AS id')).rows[0].id;
    const curStandingEntries = (await env.pool.query(
      'SELECT rel_path, file_sha256 FROM coherence.input_entries WHERE input_version_id = $1::uuid ORDER BY rel_path COLLATE "C"',
      [curStandingId],
    )).rows.map((r) => ({ relPath: r.rel_path, fileSha256: r.file_sha256 }));

    // 1. Operator calling publishInputVersion with a nusear_code stored file is refused (9c).
    await assert.rejects(
      () => appCommands.publishInputVersion({
        dbToken: iam.tokens.operator,
        commandKey: 'c1-op-bad-store-publish',
        lineKind: 'standing',
        sourceKind: 'upload',
        reason: 'attempt wrong store_kind',
        entries: curStandingEntries,
        storedFiles: [fakeCodeFile],
      }),
      (err) => err?.status === 403 && err?.code === 'INVALID_STORE',
      'operator publishInputVersion with nusear_code stored_file must be refused with 403 INVALID_STORE',
    );
    const leakedAfterPublish = (await env.pool.query(
      'SELECT COUNT(*)::int AS n FROM coherence.stored_files WHERE sha256 = $1',
      [fakeCodeFp.sha256],
    )).rows[0].n;
    assert.equal(leakedAfterPublish, 0, 'refused publishInputVersion must insert 0 stored_files rows');

    // Also refused even when the nusear_code sha256 ALREADY exists in coherence.stored_files!
    const existingCode = (await env.pool.query(
      "SELECT store_kind, sha256, byte_size, md5_b64, crc32c_b64, object_name FROM coherence.stored_files WHERE store_kind = 'nusear_code' LIMIT 1",
    )).rows[0];
    await assert.rejects(
      () => appCommands.publishInputVersion({
        dbToken: iam.tokens.operator,
        commandKey: 'c1-op-existing-code-publish',
        lineKind: 'standing',
        sourceKind: 'upload',
        reason: 'attempt existing nusear_code row',
        entries: curStandingEntries,
        storedFiles: [{
          storeKind: existingCode.store_kind,
          sha256: existingCode.sha256,
          byteSize: Number(existingCode.byte_size),
          md5B64: existingCode.md5_b64,
          crc32cB64: existingCode.crc32c_b64,
          objectName: existingCode.object_name,
        }],
      }),
      (err) => err?.status === 403 && err?.code === 'INVALID_STORE',
      'operator publishInputVersion must also refuse an already-existing nusear_code stored file',
    );

    // 2. Operator calling registerApprovalsFile with nusear_code is refused.
    await assert.rejects(
      () => appCommands.registerApprovalsFile({
        dbToken: iam.tokens.operator,
        commandKey: 'c1-op-bad-store-approvals',
        storedFile: fakeCodeFile,
        headerKind: 'v2',
        rowCount: 0,
        addedRows: [],
      }),
      (err) => err?.status === 403 && err?.code === 'INVALID_STORE',
      'operator registerApprovalsFile with nusear_code stored_file must be refused with 403 INVALID_STORE',
    );

    // 3. Owner calling recordStatementBatch with nusear_code sourceFile is refused.
    await assert.rejects(
      () => appCommands.recordStatementBatch({
        dbToken: iam.tokens.owner,
        commandKey: 'c1-owner-bad-store-stmt-batch',
        batchKind: 'historical_sent',
        statementDate: '2026-07-10',
        sourceFileName: 'bad.csv',
        sourceFile: fakeCodeFile,
        reason: 'wrong store_kind on statement batch',
        agencyLines: [{
          entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller',
          recordId: 'carrier_a~direct~BAD~10.00~2026-07', sourceFile: 'bad.csv', sourceRowNo: 1,
          grossComm: '10.00', amount: '10.00',
        }],
        uplineLines: [],
      }),
      (err) => err?.status === 403 && err?.code === 'INVALID_STORE',
      'recordStatementBatch with nusear_code sourceFile must be refused with 403 INVALID_STORE',
    );

    // 4. Owner calling registerEngineVersion with company_data stored file is refused (requires nusear_code).
    const fakeDataBytes = Buffer.from('a,b\n1,2\n', 'utf8');
    const fakeDataFp = fingerprintBytes(fakeDataBytes);
    const fakeDataFile = {
      storeKind: 'company_data',
      sha256: fakeDataFp.sha256,
      byteSize: fakeDataFp.byteSize,
      md5B64: fakeDataFp.md5B64,
      crc32cB64: fakeDataFp.crc32cB64,
      objectName: `objects/${fakeDataFp.sha256}`,
    };
    await assert.rejects(
      () => appCommands.registerEngineVersion({
        dbToken: iam.tokens.owner,
        commandKey: 'c1-owner-bad-store-engine',
        label: 'bad-store-engine',
        coherenceCommit: 'abc1234',
        engineKind: 'engine_copy',
        gitBundleSha256: existingCode.sha256,
        codeManifestSha256: existingCode.sha256,
        pythonLockSha256: existingCode.sha256,
        pythonWheelsSha256: existingCode.sha256,
        wrapperBundleSha256: existingCode.sha256,
        nusearCommit: 'def5678',
        companyEmitSha256: existingCode.sha256,
        overlayCheckSha256: existingCode.sha256,
        toolchain: { python: '3.12' },
        containerDigest: 'sha256:' + 'a'.repeat(64),
        storedFiles: [fakeDataFile],
      }),
      (err) => err?.status === 403 && err?.code === 'INVALID_STORE',
      'registerEngineVersion with company_data stored_file must be refused with 403 INVALID_STORE',
    );
    const leakedData = (await env.pool.query(
      'SELECT COUNT(*)::int AS n FROM coherence.stored_files WHERE sha256 = $1',
      [fakeDataFp.sha256],
    )).rows[0].n;
    assert.equal(leakedData, 0, 'refused registerEngineVersion must insert 0 stored_files rows');

    // 5. Worker data commands (failAttempt, cancelAttempt) refuse nusear_code stored files.
    const launch = await appCommands.launchRun({
      dbToken: iam.tokens.operator,
      commandKey: 'c1-worker-bad-store-launch',
      statementDate: '2026-12-05',
      origin: 'trial',
      engineVersionId,
    });
    const runId = launch.result.runId;
    await assert.rejects(
      () => workerCommands.failStepAttempt({
        dbToken: iam.tokens.worker,
        commandKey: 'c1-worker-bad-store-fail',
        runId,
        step: 'assign',
        attemptNo: 1,
        errorSummary: 'bad store kind',
        logFile: fakeCodeFile,
        storedFiles: [fakeCodeFile],
      }),
      (err) => err?.status === 403 && err?.code === 'INVALID_STORE',
      'worker failStepAttempt with nusear_code stored file must be refused with 403 INVALID_STORE',
    );
    await assert.rejects(
      () => workerCommands.cancelStepAttempt({
        dbToken: iam.tokens.worker,
        commandKey: 'c1-worker-bad-store-cancel',
        runId,
        step: 'assign',
        attemptNo: 1,
        cancelRequestId: randomUUID(),
        logFile: fakeCodeFile,
        storedFiles: [fakeCodeFile],
      }),
      (err) => err?.status === 403 && err?.code === 'INVALID_STORE',
      'worker cancelStepAttempt with nusear_code stored file must be refused with 403 INVALID_STORE',
    );
    await assert.rejects(
      () => appCommands.recordGeneratedOverlay({
        dbToken: iam.tokens.owner,
        commandKey: 'c1-owner-bad-store-overlay',
        decisionCommitId: randomUUID(),
        runId,
        purpose: 'assign_input',
        headerContract: 'v2',
        rowCount: 0,
        storedFile: fakeCodeFile,
      }),
      (err) => err?.status === 403 && err?.code === 'INVALID_STORE',
      'recordGeneratedOverlay with nusear_code stored file must be refused with 403 INVALID_STORE',
    );

    // 6. Worker finishStepAttempt log file & acceptReviewSubmission refuse nusear_code stored files (Fix 1 Item 6).
    const slotClient = await workerPool.connect();
    try {
      const slotLock = await slotClient.query('SELECT pg_catalog.pg_try_advisory_lock(coherence.slot_class_id(), coherence.slot_obj_id()) AS ok');
      assert.equal(slotLock.rows[0].ok, true);
      await workerCommands.startStepAttempt({
        client: slotClient,
        dbToken: iam.tokens.worker,
        commandKey: 'c1-worker-bad-store-start-assign',
        runId,
        step: 'assign',
        stepRequestId: launch.result.stepRequestId,
      });
      await assert.rejects(
        () => workerCommands.finishStepAttempt({
          client: slotClient,
          dbToken: iam.tokens.worker,
          commandKey: 'c1-worker-bad-store-finish-log',
          runId,
          step: 'assign',
          attemptNo: 1,
          logFile: fakeCodeFile,
        }),
        (err) => err?.status === 403 && err?.code === 'INVALID_STORE',
        'worker finishStepAttempt with nusear_code logFile must be refused with 403 INVALID_STORE',
      );
      const leakedAfterFinish = (await env.pool.query(
        'SELECT COUNT(*)::int AS n FROM coherence.stored_files WHERE sha256 = $1',
        [fakeCodeFp.sha256],
      )).rows[0].n;
      assert.equal(leakedAfterFinish, 0, 'refused finishStepAttempt must insert 0 stored_files rows');

      // Advance run through assign -> attribute -> bible so acceptReviewSubmission reaches the store_kind guard.
      const finAssign = await workerCommands.finishStepAttempt({
        client: slotClient, dbToken: iam.tokens.worker, commandKey: 'c1-worker-fin-assign',
        runId, step: 'assign', attemptNo: 1, continueToNextStep: true,
      });
      await workerCommands.startStepAttempt({
        client: slotClient, dbToken: iam.tokens.worker, commandKey: 'c1-worker-start-attr',
        runId, step: 'attribute', stepRequestId: finAssign.result.nextRequestId,
      });
      const finAttr = await workerCommands.finishStepAttempt({
        client: slotClient, dbToken: iam.tokens.worker, commandKey: 'c1-worker-fin-attr',
        runId, step: 'attribute', attemptNo: 1, continueToNextStep: true,
      });
      await workerCommands.startStepAttempt({
        client: slotClient, dbToken: iam.tokens.worker, commandKey: 'c1-worker-start-bible',
        runId, step: 'bible', stepRequestId: finAttr.result.nextRequestId,
      });
      await workerCommands.finishStepAttempt({
        client: slotClient, dbToken: iam.tokens.worker, commandKey: 'c1-worker-fin-bible',
        runId, step: 'bible', attemptNo: 1, continueToNextStep: false,
      });

      const runSeq = (await env.pool.query(
        'SELECT latest_journal_seq FROM app_views.coherence_runs WHERE id = $1::uuid',
        [runId],
      )).rows[0]?.latest_journal_seq
        ?? (await env.pool.query('SELECT MAX(journal_seq) AS s FROM coherence.step_attempt_events WHERE run_id = $1::uuid', [runId])).rows[0].s;

      const sub = await appCommands.submitReview({
        dbToken: iam.tokens.operator,
        commandKey: 'c1-op-submit-bad-store-review',
        expectedJournalSeq: Number(runSeq),
        runId,
        surface: 'bible',
        csvBytes: fakeCodeBytes,
      });
      await assert.rejects(
        () => workerCommands.acceptReviewSubmission({
          client: slotClient,
          dbToken: iam.tokens.worker,
          commandKey: 'c1-worker-bad-store-accept-review',
          submissionId: sub.submissionId,
          storedFile: fakeCodeFile,
          headerKind: 'v2',
          rowCount: 0,
          addedRows: [],
        }),
        (err) => err?.status === 403 && err?.code === 'INVALID_STORE',
        'worker acceptReviewSubmission with nusear_code storedFile must be refused with 403 INVALID_STORE',
      );
      const subStatus = (await env.pool.query(
        'SELECT status FROM coherence.review_submissions WHERE id = $1::uuid',
        [sub.submissionId],
      )).rows[0].status;
      assert.equal(subStatus, 'pending', 'refused acceptReviewSubmission must leave submission pending');
      const leakedAfterAccept = (await env.pool.query(
        'SELECT COUNT(*)::int AS n FROM coherence.stored_files WHERE sha256 = $1',
        [fakeCodeFp.sha256],
      )).rows[0].n;
      assert.equal(leakedAfterAccept, 0, 'refused acceptReviewSubmission must insert 0 stored_files rows');
    } finally {
      await slotClient.query('SELECT pg_catalog.pg_advisory_unlock(coherence.slot_class_id(), coherence.slot_obj_id())').catch(() => {});
      slotClient.release();
    }
  });

  await t.test('Fix1 Item 4 / Fix2: platform_readonly keeps working app_views SELECT (coherence_bob & coherence_runs) while platform_worker & platform_app are refused on internal helpers (_read_*, _ro_run_stage, v_current_finished_attempts) and runs.read without unpublished.read sees 0 runs', async () => {
    const inp = await env.dataStore.promoteBytes(Buffer.from('k\nsteps\n', 'utf8'), { relPath: 'imp_steps.csv', checksPassed: true });
    const stepStmt = await env.stores.promoteArtifact('emits/statements_20260915.csv', Buffer.from('record_id\nstep\n', 'utf8'), { checksPassed: true });
    const stepImp = await env.commands.importHistoricalRun({
      dbToken: env.ownerToken,
      commandKey: 'c1-fix1-item4-import',
      run: { origin: 'company_import', statementDate: '2026-09-15', sourceFolder: 'company-workspaces/acme/2026-09-15/runs/2026-09-15', emitMode: 'coherence' },
      inputVersion: { reason: 'step scoping test' },
      inputEntries: [{ relPath: 'imp_steps.csv', fileSha256: inp.sha256 }],
      stepAttempts: ['assign', 'attribute', 'bible', 'adjust', 'emit'].map((step) => ({
        step,
        attemptNo: 1,
        artifacts: step === 'emit'
          ? [{ relPath: stepStmt.relPath, artifactKind: stepStmt.artifactKind, storeKind: stepStmt.storeKind, fileSha256: stepStmt.sha256 }]
          : [],
      })),
      storedFiles: [inp, stepStmt],
    });
    const stepRunId = stepImp.result.runId;

    // platform_worker gets 42501 on app_views._read_* helpers, coherence._ro_run_stage, and coherence.v_current_finished_attempts.
    for (const sql of [
      "SELECT app_views._read_workshop_right('act:coherence.runs.read')",
      'SELECT app_views._read_bob_wide_orgs()',
      `SELECT coherence._ro_run_stage('${stepRunId}'::uuid, NULL)`,
      'SELECT * FROM coherence.v_current_finished_attempts LIMIT 1',
    ]) {
      await assert.rejects(
        () => withRequestTx(workerPool, iam.tokens.owner, (tx) => tx.query(sql), { readOnly: true }),
        (err) => err?.code === '42501',
        `platform_worker must get 42501 on internal helper: ${sql}`,
      );
    }

    // platform_app gets 42501 on coherence._ro_run_stage and coherence.v_current_finished_attempts directly.
    for (const sql of [
      `SELECT coherence._ro_run_stage('${stepRunId}'::uuid, NULL)`,
      'SELECT * FROM coherence.v_current_finished_attempts LIMIT 1',
    ]) {
      await assert.rejects(
        () => withRequestTx(appPool, iam.tokens.owner, (tx) => tx.query(sql), { readOnly: true }),
        (err) => err?.code === '42501',
        `platform_app must get 42501 on internal helper: ${sql}`,
      );
    }

    // platform_readonly keeps EXECUTE on app_views._read_* (like platform_app) so SELECT on app_views.* works.
    const readonlyHelperPool = createRoleScopedTestPool(env.pool, 'platform_readonly');
    const roRuns = await withRequestTx(
      readonlyHelperPool,
      iam.tokens.companyAdmin,
      (tx) => tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_runs'),
      { readOnly: true },
    );
    assert.ok(roRuns.rows[0].n > 0, 'platform_readonly must read app_views.coherence_runs with valid workshop token');
    const roBob = await withRequestTx(
      readonlyHelperPool,
      iam.tokens.entityMgr,
      (tx) => tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob'),
      { readOnly: true },
    );
    assert.ok(roBob.rows[0].n > 0, 'platform_readonly must read app_views.coherence_bob with valid token');

    // All-or-nothing workshop: runs.read without unpublished.read sees 0 runs and NULL stage both before and after carrySent;
    // workshop holders (companyAdmin, owner) see the run and its stage both before and after carrySent.
    const runsOnlyTok = iam.tokenFor(customPeople.runsReadOnly);
    assert.equal(
      (await withRequestTx(appPool, runsOnlyTok, (tx) => tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_runs WHERE id = $1::uuid', [stepRunId]), { readOnly: true })).rows[0].n,
      0,
      'runs.read without unpublished.read must see 0 rows before carrySent',
    );
    assert.equal(
      (await withRequestTx(appPool, runsOnlyTok, (tx) => tx.query('SELECT app_views.coherence_run_stage($1::uuid, NULL) AS st', [stepRunId]), { readOnly: true })).rows[0].st,
      null,
      'runs.read without unpublished.read must get NULL stage before carrySent',
    );
    assert.equal(
      (await withRequestTx(appPool, iam.tokens.companyAdmin, (tx) => tx.query('SELECT app_views.coherence_run_stage($1::uuid, NULL) AS st', [stepRunId]), { readOnly: true })).rows[0].st,
      'done',
      'companyAdmin with workshop access must see unsent run stage',
    );

    await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'c1-fix1-item4-sent', runId: stepRunId, typedPhrase: 'sent 2026-09-15' });

    assert.equal(
      (await withRequestTx(appPool, runsOnlyTok, (tx) => tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_runs WHERE id = $1::uuid', [stepRunId]), { readOnly: true })).rows[0].n,
      0,
      'runs.read without unpublished.read must still see 0 rows in coherence_runs even after carrySent',
    );
    assert.equal(
      (await withRequestTx(appPool, runsOnlyTok, (tx) => tx.query('SELECT app_views.coherence_run_stage($1::uuid, NULL) AS st', [stepRunId]), { readOnly: true })).rows[0].st,
      null,
      'runs.read without unpublished.read must still get NULL stage even after carrySent',
    );
  });

  await t.test('Fix1 Item 5: downstream reader answers unavailable when newest SENT run has no entity-manager bundle instead of falling back to an older sent run', async () => {
    const date = '2026-12-20';
    const dataset = buildCanaryEmitCsvs({ statementDate: date });
    const stmt = await env.stores.promoteArtifact(`emits/statements_${date.replace(/-/g, '')}.csv`, Buffer.from(dataset.statementsCsv, 'utf8'), { checksPassed: true });
    const inp = await env.dataStore.promoteBytes(Buffer.from(`k\n${date}\n`, 'utf8'), { relPath: `imp_${date}.csv`, checksPassed: true });
    const imp = await env.commands.importHistoricalRun({
      dbToken: env.ownerToken,
      commandKey: 'c1-fix1-item5-nobundle-import',
      run: { origin: 'company_import', statementDate: date, sourceFolder: `company-workspaces/acme/${date}/runs/${date}`, emitMode: 'coherence' },
      inputVersion: { reason: 'newest sent run without bundle' },
      inputEntries: [{ relPath: `imp_${date}.csv`, fileSha256: inp.sha256 }],
      stepAttempts: [{
        step: 'emit',
        attemptNo: 1,
        artifacts: [{ relPath: stmt.relPath, artifactKind: stmt.artifactKind, storeKind: stmt.storeKind, fileSha256: stmt.sha256 }],
      }],
      storedFiles: [inp, stmt],
    });
    const newestSentNoBundleId = imp.result.runId;
    await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'c1-fix1-item5-nobundle-sent', runId: newestSentNoBundleId, typedPhrase: `sent ${date}` });

    for (const [label, tok] of [
      ['owner', iam.tokens.owner],
      ['fullEmSentOnly', iam.tokenFor(customPeople.fullEmSentOnly)],
      ['sentEmSubOrgUnpub', iam.tokenFor(customPeople.sentEmSubOrgUnpub)],
    ]) {
      const sum = await reader.summary(tok);
      assert.equal(sum.available, false, `${label}: newest sent run without bundle must answer available=false instead of falling back to older run ${sentRunId} (got ${JSON.stringify(sum)})`);
      await assert.rejects(
        () => reader.file(tok, 'data/canonical_bob.csv'),
        (err) => err?.status === 404 && err?.code === 'NO_RUN',
        `${label}: reader.file must return 404 NO_RUN when newest sent run has no bundle`,
      );
    }

    // Explicit runId for the older sent run still opens cleanly.
    const explicitOld = await reader.summary(iam.tokenFor(customPeople.fullEmSentOnly), { runId: sentRunId });
    assert.equal(explicitOld.available, true);
    assert.equal(explicitOld.runId, sentRunId);
  });
});
