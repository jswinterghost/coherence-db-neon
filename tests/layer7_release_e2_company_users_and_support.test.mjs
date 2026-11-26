// Layer 7E: Release E2 - Each company's own users, per-company sign-in identities,
// signing-key scopes, platform_iam_sync boundary, deterministic Nusear support attribution &
// customer-view masking, removed holding-company user-grant branch, and materialize_emit journal body masking.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';
import { createAppCommands } from '../src/commands/app-cmd.mjs';
import { verifyIamConfigInvariants } from '../src/config/policy-checks.mjs';
import { withRequestTx } from '../src/db/pg-client.mjs';
import { createWebHandlers } from '../src/web/handlers.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
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
  mintSignedToken,
} from './helpers/iam-harness.mjs';
import { checkPgAvailable, createEmptyMigratedTestDb, createTestEnv, withClusterCatalogLock } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

async function inSerializableTx(pool, fn) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    const out = await fn(c);
    await c.query('COMMIT');
    return out;
  } catch (err) {
    await c.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    c.release();
  }
}

async function runAsRole(pool, roleName, { token = null, readOnly = true } = {}, fn) {
  const c = await pool.connect();
  try {
    await c.query(readOnly ? 'BEGIN TRANSACTION READ ONLY' : 'BEGIN TRANSACTION READ WRITE');
    await c.query(`SET LOCAL ROLE "${roleName}"`);
    if (token !== null) {
      await c.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [token]);
    }
    const out = await fn(c);
    await c.query('COMMIT');
    return out;
  } catch (err) {
    await c.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    c.release();
  }
}

function makeMaterializationCsvs({ entity, writingNpn, writingAgent, statementDate = '2026-10-15' }) {
  const bobRows = [{
    policy_id: '501', carrier_policy_number: 'POL-501', crm_policy_number: 'CRM-501',
    enrollment_code: 'EC-501', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Plan 501',
    simple_plan_type: 'MA', mbi: '1AB2-CD3-EF45', member: 'Pat Member', dob: '1955-04-12',
    phone: '555-010-5001', email: 'pat.m@member.example', address: '100 Main St',
    county: 'Orange', state: 'FL',
    submission_date: '2026-09-01', origin_effective: '2026-10-01', effective_date: '2026-10-01',
    min_date: '2026-10-01', anchor_date: '2026-10-01',
    amount: '80.00', upline_amount: '20.00',
    writing_npn: writingNpn, writing_agent: writingAgent, entity,
    agency_id: 'AG-1', status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
    conflicts: '', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
  }];
  const ledgerRows = [{
    tx_id: '501', record_id: 'carrier_a|direct|NM:pat,member|100.00|2026-10',
    external_policy_id: 'POL-501', policy_id: '501', statement_name: 'carrier_a.csv', src_type: 'direct',
    carrier: 'carrier_a', member: 'Pat Member', mbi: '1AB2-CD3-EF45', state: 'FL',
    plan_type: 'MA', simple_plan_type: 'MA',
    submission_date: '2026-09-01', origin_effective: '2026-10-01', effective_date: '2026-10-01',
    earned_date: '2026-10-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-01',
    gross_comm: '100.00', commission_amount: '100.00', revenue_type: 'commission',
    writing_npn: writingNpn, writing_agent: writingAgent, entity,
    agency_id: 'AG-1', status: 'ACTIVE_PAYING', policy_status: 'active',
    notes: 'e2 ledger note', coherent_notes: 'NEW',
    downline_amount: '80.00', upline_amount: '20.00',
  }];
  const stmtRows = [{
    ...ledgerRows[0],
    run_action: 'NEW',
    run_statement_date: statementDate,
    reversal_of: '',
    reason: 'e2 stmt reason',
    notes: 'e2 stmt note',
  }];
  return {
    canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, bobRows),
    coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, ledgerRows),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, stmtRows),
  };
}

test('Layer 7E [E2 Test 1]: same real person exists as nusear_staff and company_local in one database with shared email and NPN, while duplicates within one origin fail', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const staffPersonId = randomUUID();
  const localPersonId = randomUUID();
  const sharedEmail = 'dual.real.person@shared.example';
  const sharedNpn = '81234567';

  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, {
      environment: env.iam.environment,
      targetOrgId: env.iam.ids.companyOrg,
      commandKind: 'iam.e2_dual_origin',
      commandKey: `e2-dual-origin-${randomUUID()}`,
    })).seq;

    await c.query(
      "INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','nusear_staff',$3),($2,'human','company_local',$3)",
      [staffPersonId, localPersonId, seq],
    );
    await c.query(
      `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, npn, status, journal_seq)
       VALUES ($1,$2,'nusear_staff','Pat Support','Pat Support',$5,$6,'active',$7),
              ($3,$4,'company_local','Pat Owner','Pat Owner',$5,$6,'active',$7)`,
      [randomUUID(), staffPersonId, randomUUID(), localPersonId, sharedEmail, sharedNpn, seq],
    );
  });

  const rows = (await env.pool.query(
    'SELECT person_id, principal_origin, primary_email, npn FROM iam.person_versions WHERE primary_email = $1 AND superseded_by_id IS NULL ORDER BY principal_origin',
    [sharedEmail],
  )).rows;
  assert.equal(rows.length, 2, 'same real person must coexist as company_local and nusear_staff with same email and NPN');
  assert.deepEqual(rows.map((r) => r.principal_origin), ['company_local', 'nusear_staff']);

  // Duplicate live email within the same origin fails 23505 (both company_local and nusear_staff).
  for (const origin of ['company_local', 'nusear_staff']) {
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, commandKey: `dup-email-${origin}-${randomUUID()}` })).seq;
        const dupId = randomUUID();
        await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human',$2,$3)", [dupId, origin, seq]);
        await c.query(
          "INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,$3,'Dup','Dup',$4,'active',$5)",
          [randomUUID(), dupId, origin, sharedEmail, seq],
        );
      }),
      (err) => err?.code === '23505',
      `duplicate live primary_email within ${origin} must fail 23505`,
    );

    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, commandKey: `dup-npn-${origin}-${randomUUID()}` })).seq;
        const dupId = randomUUID();
        await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human',$2,$3)", [dupId, origin, seq]);
        await c.query(
          "INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, npn, status, journal_seq) VALUES ($1,$2,$3,'Dup NPN','Dup NPN',$4,$5,'active',$6)",
          [randomUUID(), dupId, origin, `dup.npn.${origin}@example.test`, sharedNpn, seq],
        );
      }),
      (err) => err?.code === '23505',
      `duplicate live npn within ${origin} must fail 23505`,
    );
  }

  // Origin/kind mismatches and person_versions composite FK mismatch fail.
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, commandKey: `bad-svc-origin-${randomUUID()}` })).seq;
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'service','company_local',$2)", [randomUUID(), seq]);
    }),
    (err) => err?.code === '23514',
    'service person with company_local origin must fail 23514',
  );
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, commandKey: `bad-house-origin-${randomUUID()}` })).seq;
      await c.query("INSERT INTO iam.people (id, person_kind, house_org_id, principal_origin, journal_seq) VALUES ($1,'house_account',$2,'nusear_staff',$3)", [randomUUID(), env.iam.ids.beaconOrg, seq]);
    }),
    (err) => err?.code === '23514',
    'house_account with nusear_staff origin must fail 23514',
  );
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, commandKey: `bad-pv-origin-${randomUUID()}` })).seq;
      const pid = randomUUID();
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','nusear_staff',$2)", [pid, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, status, journal_seq) VALUES ($1,$2,'company_local','Wrong','Wrong','active',$3)",
        [randomUUID(), pid, seq],
      );
    }),
    (err) => err?.code === '23503',
    'person_versions.principal_origin mismatching people.principal_origin must fail 23503',
  );
});

test('Layer 7E [E2 Test 2]: writing person on a policy resolves strictly to company_local people (nusear_staff and service ignored and refused)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const staffOnlyId = randomUUID();
  const staffSharedId = randomUUID();
  const localSharedId = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, {
      environment: env.iam.environment,
      targetOrgId: env.iam.ids.companyOrg,
      commandKind: 'iam.e2_writing_person',
      commandKey: `e2-wp-${randomUUID()}`,
    })).seq;
    await c.query(
      `INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq)
       VALUES ($1,'human','nusear_staff',$4),($2,'human','nusear_staff',$4),($3,'human','company_local',$4)`,
      [staffOnlyId, staffSharedId, localSharedId, seq],
    );
    await c.query(
      `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, npn, status, journal_seq)
       VALUES ($1,$2,'nusear_staff','Staff Only NPN','Staff Only NPN','staff.only@nusear.example','88888888','active',$7),
              ($3,$4,'nusear_staff','Staff Shared NPN','Staff Shared NPN','shared.npn@example.test','99999999','active',$7),
              ($5,$6,'company_local','Local Shared NPN','Local Shared NPN','shared.npn@example.test','99999999','active',$7)`,
      [randomUUID(), staffOnlyId, randomUUID(), staffSharedId, randomUUID(), localSharedId, seq],
    );
  });

  // NPN held ONLY by nusear_staff fails UNMAPPED_WRITING_NPN (22023).
  await assert.rejects(
    () => env.pool.query("SELECT coherence._resolve_writing_person_id('88888888', 'bob_policies')"),
    (err) => err?.code === '22023' && /UNMAPPED_WRITING_NPN/i.test(err.message),
    'nusear_staff-only NPN must not resolve as writing_person_id',
  );

  // NPN shared by nusear_staff and company_local resolves cleanly to company_local only.
  const resolved = (await env.pool.query("SELECT coherence._resolve_writing_person_id('99999999', 'bob_policies') AS pid")).rows[0].pid;
  assert.equal(resolved, localSharedId, '_resolve_writing_person_id must resolve shared NPN strictly to company_local person');

  // Explicit p_npn_map pointing to nusear_staff or service fails 23503.
  for (const [label, pid] of [['nusear_staff', staffOnlyId], ['service', env.iam.ids.workerService]]) {
    await assert.rejects(
      () => env.pool.query(
        "SELECT coherence._resolve_writing_person_id('88888888', 'bob_policies', $1::jsonb)",
        [JSON.stringify({ '88888888': pid })],
      ),
      (err) => err?.code === '23503' && /INVALID_NPN_MAP/i.test(err.message),
      `explicit p_npn_map pointing to ${label} must fail 23503`,
    );
  }

  // Recording a statement batch with shared NPN stamps localSharedId, while explicit writingPersonId = nusear_staff fails 23503.
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const appCommands = createAppCommands({ pool: appPool, stores: env.stores });
  await appCommands.recordStatementBatch({
    dbToken: env.ownerToken,
    commandKey: 'e2-wp-shared-batch',
    batchKind: 'historical_sent',
    statementDate: '2026-10-01',
    reason: 'shared npn resolves to company_local',
    agencyLines: [{
      entity: 'Beacon', writingNpn: '99999999', writingAgent: 'Local Shared NPN',
      recordId: 'carrier_a|direct|NM:shared,wp|100.00|2026-10',
      sourceFile: 'wp.csv', sourceRowNo: 1, srcType: 'direct', carrier: 'carrier_a',
      mbi: '1AB2-CD3-EF45', member: 'WP Member', policyId: 601, txId: 601,
      grossComm: '100.00', amount: '80.00',
    }],
    uplineLines: [{
      sourceEntity: 'Beacon', writingNpn: '99999999', writingAgent: 'Local Shared NPN',
      recordId: 'carrier_a|direct|NM:shared,wp|100.00|2026-10',
      sourceFile: 'wp.csv', sourceRowNo: 1, srcType: 'direct', carrier: 'carrier_a',
      mbi: '1AB2-CD3-EF45', member: 'WP Member', policyId: 601, txId: 601,
      grossComm: '100.00', amount: '20.00',
    }],
  });
  const sal = (await env.pool.query("SELECT writing_person_id FROM coherence.statement_agency_lines WHERE writing_npn = '99999999'")).rows;
  assert.equal(sal.length, 1);
  assert.equal(sal[0].writing_person_id, localSharedId, 'statement_agency_lines must stamp company_local writing_person_id');

  await assert.rejects(
    () => appCommands.recordStatementBatch({
      dbToken: env.ownerToken,
      commandKey: 'e2-wp-explicit-staff-bad',
      batchKind: 'historical_sent',
      statementDate: '2026-10-02',
      reason: 'explicit nusear_staff writingPersonId must fail',
      agencyLines: [{
        entity: 'Beacon', writingNpn: '99999999', writingPersonId: staffSharedId, writingAgent: 'Staff Shared NPN',
        recordId: 'carrier_a|direct|NM:bad,wp|100.00|2026-10',
        sourceFile: 'wp2.csv', sourceRowNo: 1, srcType: 'direct', carrier: 'carrier_a',
        mbi: '1AB2-CD3-EF45', member: 'WP Bad', policyId: 602, txId: 602,
        grossComm: '100.00', amount: '80.00',
      }],
      uplineLines: [],
    }),
    (err) => err?.code === '23503' || /INVALID_WRITING_PERSON_ID/i.test(String(err?.message || '')),
    'explicit nusear_staff writingPersonId in command payload must be refused',
  );

  // agent_affiliations rejects nusear_staff and service principals.
  for (const [label, pid] of [['nusear_staff', staffOnlyId], ['service', env.iam.ids.workerService]]) {
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, commandKey: `bad-aff-${label}-${randomUUID()}` })).seq;
        await c.query(
          "INSERT INTO iam.agent_affiliations (id, person_id, npn, agency_org_id, split_bps, agent_file_name, valid_range, status, journal_seq) VALUES ($1,$2,'77665544',$3,8000,'Bad','[2020-01-01,)'::daterange,'active',$4)",
          [randomUUID(), pid, env.iam.ids.beaconOrg, seq],
        );
      }),
      (err) => err?.code === '23514',
      `agent_affiliations for ${label} must fail 23514`,
    );
  }

  // Table-level INSERT guard across all five writing_person_id tables:
  // refuses nusear_staff and service principals on direct INSERT while allowing NULL (for journal replay) and company_local.
  await seedStandingInput(env, { commandKey: 'e2-wp-tbl-standing' });
  const csvs = makeMaterializationCsvs({ entity: 'Beacon', writingNpn: '99999999', writingAgent: 'Local Shared NPN', statementDate: '2026-10-20' });
  const inpFile = await env.dataStore.promoteBytes(Buffer.from('k\n1\n', 'utf8'), { relPath: 'wp_in.csv', checksPassed: true });
  const stmtArt = await env.stores.promoteArtifact('emits/statements_20261020.csv', Buffer.from(csvs.statementsCsv, 'utf8'), { checksPassed: true });
  const impRun = await env.commands.importHistoricalRun({
    dbToken: env.ownerToken,
    commandKey: 'e2-wp-tbl-imp',
    run: { origin: 'company_import', statementDate: '2026-10-20', sourceFolder: 'company-workspaces/acme/2026-10-20/runs/2026-10-20', emitMode: 'coherence' },
    inputVersion: { reason: 'e2 table insert guard seed' },
    inputEntries: [{ relPath: 'wp_in.csv', fileSha256: inpFile.sha256 }],
    stepAttempts: [{
      step: 'emit',
      attemptNo: 1,
      artifacts: [{ relPath: stmtArt.relPath, artifactKind: stmtArt.artifactKind, storeKind: stmtArt.storeKind, fileSha256: stmtArt.sha256 }],
    }],
    storedFiles: [inpFile, stmtArt],
  });
  const emitEvId = (await env.pool.query("SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev", [impRun.result.runId])).rows[0].ev;

  const c = await env.pool.connect();
  try {
    await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    const jSeq = (await c.query(
      `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, 'e2_wp_insert_probe', $2, $3, '{}'::jsonb) RETURNING seq`,
      [localSharedId, `e2-wp-probe-${randomUUID()}`, '0'.repeat(64)],
    )).rows[0].seq;
    const probeBatchId = randomUUID();
    const zeroSha = '0'.repeat(64);
    await c.query(
      `INSERT INTO coherence.statement_batches (
         id, batch_kind, statement_date, run_id, attempt_event_id, reason,
         agency_line_count, agency_lines_sha256, agency_net_total,
         upline_line_count, upline_lines_sha256, upline_net_total, journal_seq
       ) VALUES ($1,'run_emission','2026-10-20',$2,$3,'probe batch',0,$4,0.00,0,$4,0.00,$5)`,
      [probeBatchId, impRun.result.runId, emitEvId, zeroSha, jSeq],
    );
    await c.query(
      `INSERT INTO coherence.run_materializations (
         attempt_event_id, run_id, statement_date, reconciliation_mode,
         bob_row_count, bob_rows_sha256, bob_downline_total, bob_upline_total,
         ledger_row_count, ledger_rows_sha256, ledger_gross_total, ledger_downline_total, ledger_upline_total,
         statement_batch_id, journal_seq
       ) VALUES ($1,$2,'2026-10-20','strict_entity_ledger',0,$3,0.00,0.00,0,$3,0.00,0.00,0.00,$4,$5)`,
      [emitEvId, impRun.result.runId, zeroSha, probeBatchId, jSeq],
    );
    let nextId = 9000;
    const insertTableRow = async (tbl, writingPersonId) => {
      const n = nextId++;
      if (tbl === 'statement_agency_lines') {
        await c.query(
          `INSERT INTO coherence.statement_agency_lines (
             batch_id, line_no, statement_date, entry_kind, run_action, entity,
             writing_npn, writing_agent, organization_id, writing_person_id,
             record_id, source_file, source_row_no, gross_comm, amount, journal_seq
           ) VALUES ($1,$2,'2026-10-20','run_emission','NEW','Beacon','99999999','WP Test',$3,$4,$5,'t.csv',1,100.00,80.00,$6)`,
          [probeBatchId, n, env.iam.ids.beaconOrg, writingPersonId, `rec-sal-${n}`, jSeq],
        );
      } else if (tbl === 'statement_upline_lines') {
        await c.query(
          `INSERT INTO coherence.statement_upline_lines (
             batch_id, line_no, statement_date, entry_kind, run_action, source_entity,
             writing_npn, writing_agent, organization_id, writing_person_id,
             record_id, source_file, source_row_no, gross_comm, amount, journal_seq
           ) VALUES ($1,$2,'2026-10-20','run_emission','NEW','Beacon','99999999','WP Test',$3,$4,$5,'t.csv',1,100.00,20.00,$6)`,
          [probeBatchId, n, env.iam.ids.beaconOrg, writingPersonId, `rec-sul-${n}`, jSeq],
        );
      } else if (tbl === 'bob_policies') {
        await c.query(
          `INSERT INTO coherence.bob_policies (
             attempt_event_id, policy_id, run_id, entity, writing_npn, writing_agent,
             organization_id, writing_person_id, journal_seq
           ) VALUES ($1,$2,$3,'Beacon','99999999','WP Test',$4,$5,$6)`,
          [emitEvId, n, impRun.result.runId, env.iam.ids.beaconOrg, writingPersonId, jSeq],
        );
      } else if (tbl === 'bob_policy_financials') {
        await c.query(
          `INSERT INTO coherence.bob_policies (
             attempt_event_id, policy_id, run_id, entity, writing_npn, writing_agent,
             organization_id, writing_person_id, journal_seq
           ) VALUES ($1,$2,$3,'Beacon','99999999','WP Test',$4,$5,$6)`,
          [emitEvId, n, impRun.result.runId, env.iam.ids.beaconOrg, writingPersonId === null ? null : localSharedId, jSeq],
        );
        if (writingPersonId !== null && writingPersonId !== localSharedId) {
          // Isolate bob_policy_financials's own INSERT guard trigger from bob_policies parity check inside this rolled-back savepoint.
          await c.query('ALTER TABLE coherence.bob_policy_financials DISABLE TRIGGER trg_02_bob_policy_financials_before');
        }
        await c.query(
          `INSERT INTO coherence.bob_policy_financials (
             attempt_event_id, policy_id, entity, writing_npn,
             organization_id, writing_person_id, amount, upline_amount, journal_seq
           ) VALUES ($1,$2,'Beacon','99999999',$3,$4,80.00,20.00,$5)`,
          [emitEvId, n, env.iam.ids.beaconOrg, writingPersonId, jSeq],
        );
      } else if (tbl === 'coherent_ledger_rows') {
        await c.query(
          `INSERT INTO coherence.coherent_ledger_rows (
             attempt_event_id, tx_id, run_id, record_id, src_type,
             gross_comm, commission_amount, downline_amount, upline_amount,
             writing_npn, writing_agent, entity, organization_id, writing_person_id,
             cbob_c, cbob_s, sf, journal_seq
           ) VALUES ($1,$2,$3,$4,'direct',100.00,100.00,80.00,20.00,'99999999','WP Test','Beacon',$5,$6,true,false,false,$7)`,
          [emitEvId, n, impRun.result.runId, `rec-clr-${n}`, env.iam.ids.beaconOrg, writingPersonId, jSeq],
        );
      }
    };

    for (const tbl of [
      'bob_policies',
      'bob_policy_financials',
      'statement_agency_lines',
      'statement_upline_lines',
      'coherent_ledger_rows',
    ]) {
      // NULL writing_person_id stays allowed on INSERT (journal replays).
      await c.query('SAVEPOINT sp_null');
      await insertTableRow(tbl, null);
      await c.query('ROLLBACK TO SAVEPOINT sp_null');

      // company_local writing_person_id succeeds on INSERT.
      await c.query('SAVEPOINT sp_local');
      await insertTableRow(tbl, localSharedId);
      await c.query('ROLLBACK TO SAVEPOINT sp_local');

      // nusear_staff and service writing_person_id are refused on INSERT at the table level.
      for (const [label, badPid] of [['nusear_staff', staffOnlyId], ['service', env.iam.ids.workerService]]) {
        await c.query('SAVEPOINT sp_bad');
        await assert.rejects(
          () => insertTableRow(tbl, badPid),
          (err) => err?.code === '23514' && /company_local/i.test(String(err?.message || '')),
          `coherence.${tbl} must refuse ${label} writing_person_id on direct INSERT`,
        );
        await c.query('ROLLBACK TO SAVEPOINT sp_bad');
      }
    }
    await c.query('ROLLBACK');
  } finally {
    c.release();
  }
});

test('Layer 7E [E2 Test 3]: signing key key_scope is enforced in iam.session_context (company key refused for Nusear support or worker)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  // Seed a real run so app_views.coherence_runs checks are non-vacuous.
  const { engineVersionId } = await seedEngineCopyVersion(env);
  await seedStandingInput(env, { commandKey: 'e2-t3-standing' });
  await env.commands.launchRun({
    dbToken: env.ownerToken,
    commandKey: 'e2-t3-launch',
    statementDate: '2026-10-15',
    engineVersionId,
  });

  const companyKeyId = `k_e2_co_${randomBytes(4).toString('hex')}`;
  const companySecret = randomBytes(32);
  const staffKeyId = `k_e2_st_${randomBytes(4).toString('hex')}`;
  const staffSecret = randomBytes(32);
  const serviceKeyId = `k_e2_sv_${randomBytes(4).toString('hex')}`;
  const serviceSecret = randomBytes(32);

  await env.pool.query(
    `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, key_scope, active_from, active_until)
     VALUES ($1,$2,$7,'company_local',pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours'),
            ($3,$4,$7,'nusear_staff',pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours'),
            ($5,$6,$7,'service',pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours')`,
    [companyKeyId, companySecret, staffKeyId, staffSecret, serviceKeyId, serviceSecret, env.iam.environment],
  );

  const mint = (keyId, secretBytes, actorPersonId, viewAsPersonId = null) => mintSignedToken({
    keyId, secretBytes, environment: env.iam.environment, actorPersonId, viewAsPersonId,
  });

  const forbiddenCases = [
    ['company_local key signing nusear_staff', mint(companyKeyId, companySecret, env.iam.ids.nusearOwner)],
    ['company_local key signing service/worker', mint(companyKeyId, companySecret, env.iam.ids.workerService)],
    ['company_local key with View-as nusear_staff', mint(companyKeyId, companySecret, env.iam.ids.entityMgr, env.iam.ids.nusearOwner)],
    ['company_local key with View-as service', mint(companyKeyId, companySecret, env.iam.ids.entityMgr, env.iam.ids.workerService)],
    ['nusear_staff key signing company_local', mint(staffKeyId, staffSecret, env.iam.ids.entityMgr)],
    ['nusear_staff key signing service/worker', mint(staffKeyId, staffSecret, env.iam.ids.workerService)],
    ['nusear_staff key with View-as service', mint(staffKeyId, staffSecret, env.iam.ids.nusearOwner, env.iam.ids.workerService)],
    ['service key signing company_local', mint(serviceKeyId, serviceSecret, env.iam.ids.entityMgr)],
    ['service key signing nusear_staff', mint(serviceKeyId, serviceSecret, env.iam.ids.nusearOwner)],
    ['service key with View-as company_local', mint(serviceKeyId, serviceSecret, env.iam.ids.workerService, env.iam.ids.agentA)],
  ];

  for (const [label, tok] of forbiddenCases) {
    await runAsRole(env.pool, 'platform_app', { token: tok, readOnly: true }, async (c) => {
      const ctx = (await c.query('SELECT actor_person_id FROM iam.session_context()')).rows[0];
      assert.equal(ctx?.actor_person_id ?? null, null, `${label} must fail closed in iam.session_context()`);
      const orgs = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
      assert.deepEqual(orgs, [], `${label} must yield 0 orgs`);
      const runs = (await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_runs')).rows[0].n;
      assert.equal(runs, 0, `${label} must yield 0 rows from app_views`);
    });
    await assert.rejects(
      () => runAsRole(env.pool, 'platform_app', { token: tok, readOnly: false }, (c) => (
        c.query("SELECT * FROM iam.assert_can_write('act:coherence.run.launch', $1::uuid)", [env.iam.ids.companyOrg])
      )),
      (err) => err?.code === '42501',
      `${label} must be refused 42501 on assert_can_write`,
    );
  }

  // Positive controls: each scope signs its own origin, plus nusear_staff View-as company_local and company_local View-as company_local.
  for (const [label, tok, expectedActor, expectedViewAs, expectRuns] of [
    ['company_local key for entityMgr', mint(companyKeyId, companySecret, env.iam.ids.entityMgr), env.iam.ids.entityMgr, null, 1],
    ['company_local key for entityMgr View-as agentA', mint(companyKeyId, companySecret, env.iam.ids.entityMgr, env.iam.ids.agentA), env.iam.ids.entityMgr, env.iam.ids.agentA, 0],
    ['nusear_staff key for nusearOwner', mint(staffKeyId, staffSecret, env.iam.ids.nusearOwner), env.iam.ids.nusearOwner, null, 1],
    ['nusear_staff key for nusearOwner View-as entityMgr', mint(staffKeyId, staffSecret, env.iam.ids.nusearOwner, env.iam.ids.entityMgr), env.iam.ids.nusearOwner, env.iam.ids.entityMgr, 1],
    ['service key for workerService', mint(serviceKeyId, serviceSecret, env.iam.ids.workerService), env.iam.ids.workerService, null, 0],
  ]) {
    await runAsRole(env.pool, 'platform_app', { token: tok, readOnly: true }, async (c) => {
      const ctx = (await c.query('SELECT actor_person_id, view_as_person_id FROM iam.session_context()')).rows[0];
      assert.equal(ctx.actor_person_id, expectedActor, `${label} must resolve expected actor_person_id`);
      assert.equal(ctx.view_as_person_id, expectedViewAs, `${label} must resolve expected view_as_person_id`);
      const runs = (await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_runs')).rows[0].n;
      assert.equal(runs, expectRuns, `${label} must see ${expectRuns} row(s) in app_views.coherence_runs`);
    });
  }
});

test('Layer 7E [E2 Test 4]: cross-origin role grants, cross-origin memberships, role_version flips, and company_local in control DB are refused', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, environment } = env.iam;

  // 1. company_local granted an is_nusear_internal = true role -> 23514
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment, commandKey: `xorig-1-${randomUUID()}` })).seq;
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), ids.entityMgr, ids.roleNusearAdmin, ids.companyOrg, seq],
      );
    }),
    (err) => err?.code === '23514',
    'company_local person must not be granted an is_nusear_internal role',
  );

  // 2. nusear_staff or service granted an is_nusear_internal = false role -> 23514
  for (const [label, pid] of [['nusear_staff', ids.nusearOperator], ['service', ids.workerService]]) {
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment, commandKey: `xorig-2-${label}-${randomUUID()}` })).seq;
        await c.query(
          "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
          [randomUUID(), pid, ids.roleEntityManager, ids.companyOrg, seq],
        );
      }),
      (err) => err?.code === '23514',
      `${label} must not be granted a customer (is_nusear_internal=false) role`,
    );
  }

  // 3. company_local granted a customer role anchored at platform_root -> 23514
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment, commandKey: `xorig-3-${randomUUID()}` })).seq;
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), ids.entityMgr, ids.roleEntityManager, ids.rootOrg, seq],
      );
    }),
    (err) => err?.code === '23514',
    'company_local person must not hold a role grant anchored at platform_root',
  );

  // 4. Flipping is_nusear_internal on a role_version with live grants -> 23514
  const emRvId = (await env.pool.query(
    'SELECT id FROM iam.role_versions WHERE role_id = $1 AND superseded_by_id IS NULL',
    [ids.roleEntityManager],
  )).rows[0].id;
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment, commandKey: `xorig-4-${randomUUID()}` })).seq;
      await c.query(
        "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, replaces_id, journal_seq) VALUES ($1,$2,'Flipped EM',false,true,true,'active',$3,$4)",
        [randomUUID(), ids.roleEntityManager, emRvId, seq],
      );
    }),
    (err) => err?.code === '23514',
    'flipping is_nusear_internal on a role with incompatible live grants must fail 23514',
  );

  // 5. Company custom role (owner_org_id IS NOT NULL) setting is_nusear_internal = true -> 23514
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment, commandKey: `xorig-5-${randomUUID()}` })).seq;
      const customRoleId = randomUUID();
      await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'custom_bad_int',$2,$3)", [customRoleId, ids.companyOrg, seq]);
      await c.query(
        "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,'Custom Bad',false,true,true,'active',$3)",
        [randomUUID(), customRoleId, seq],
      );
    }),
    (err) => err?.code === '23514',
    'company custom role must not set is_nusear_internal = true',
  );

  // 6. Cross-origin memberships: nusear_staff/service on non-root org or company_local on platform_root -> 23514
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment, commandKey: `xorig-mem-1-${randomUUID()}` })).seq;
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), ids.nusearOperator, ids.companyOrg, seq],
      );
    }),
    (err) => err?.code === '23514',
    'nusear_staff membership on company org must fail 23514',
  );
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment, commandKey: `xorig-mem-2-${randomUUID()}` })).seq;
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), ids.entityMgr, ids.rootOrg, seq],
      );
    }),
    (err) => err?.code === '23514',
    'company_local membership on platform_root must fail 23514',
  );

  // 7. control database forbids company_local people (23514)
  const ctrlDb = await createEmptyMigratedTestDb();
  t.after(() => ctrlDb.cleanup());
  await inSerializableTx(ctrlDb.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: 'local', commandKey: 'ctrl-e2-init' })).seq;
    await c.query(
      "INSERT INTO iam.database_context (singleton, environment, db_role_kind, tenant_org_id, company_slug, support_external_label, journal_seq) VALUES (true,'local','control',NULL,NULL,'Nusear support',$1)",
      [seq],
    );
  });
  await assert.rejects(
    () => inSerializableTx(ctrlDb.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: 'local', commandKey: 'ctrl-e2-bad-local' })).seq;
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','company_local',$2)", [randomUUID(), seq]);
    }),
    (err) => err?.code === '23514',
    'control database must reject company_local people with 23514',
  );
});

test('Layer 7E [E2 Test 5]: per-company sign-in identities resolve strictly in their own company, refuse suspended/revoked identities and persons, and lock down platform_auth_lookup', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const envA = await createTestEnv({ companySlug: 'alpha', displayName: 'Alpha' });
  const envB = await createTestEnv({ companySlug: 'beta', displayName: 'Beta' });
  t.after(() => Promise.all([envA.cleanup(), envB.cleanup()]));

  const issuerA = 'https://clerk.alpha.example';
  const issuerB = 'https://clerk.beta.example';
  const sub1 = 'user_clerk_001';
  const authAId = randomUUID();
  const authBId = randomUUID();

  await inSerializableTx(envA.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, targetOrgId: envA.iam.ids.companyOrg, commandKey: 'auth-a-1' })).seq;
    await c.query(
      `INSERT INTO iam.person_auth_identities (id, person_id, principal_origin, auth_issuer, auth_subject, status, journal_seq)
       VALUES ($1,$2,'company_local',$3,$4,'active',$5)`,
      [authAId, envA.iam.ids.entityMgr, issuerA, sub1, seq],
    );
  });
  await inSerializableTx(envB.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: envB.iam.environment, targetOrgId: envB.iam.ids.companyOrg, commandKey: 'auth-b-1' })).seq;
    await c.query(
      `INSERT INTO iam.person_auth_identities (id, person_id, principal_origin, auth_issuer, auth_subject, status, journal_seq)
       VALUES ($1,$2,'company_local',$3,$4,'active',$5)`,
      [authBId, envB.iam.ids.entityMgr, issuerB, sub1, seq],
    );
  });

  // Company A's (issuerA, sub1) resolves ONLY in Company A; Company B's (issuerB, sub1) resolves ONLY in Company B.
  const hitA = await runAsRole(envA.pool, 'platform_auth_lookup', { readOnly: true }, (c) => (
    c.query('SELECT person_id, principal_origin, company_slug, tenant_org_id, environment FROM iam.resolve_auth_identity($1, $2)', [issuerA, sub1])
  ));
  assert.equal(hitA.rows.length, 1);
  assert.equal(hitA.rows[0].person_id, envA.iam.ids.entityMgr);
  assert.equal(hitA.rows[0].principal_origin, 'company_local');
  assert.equal(hitA.rows[0].company_slug, 'alpha');

  const missBinA = await runAsRole(envA.pool, 'platform_auth_lookup', { readOnly: true }, (c) => (
    c.query('SELECT * FROM iam.resolve_auth_identity($1, $2)', [issuerB, sub1])
  ));
  assert.equal(missBinA.rows.length, 0, 'Company B issuer/subject must resolve nobody in Company A DB');

  const hitB = await runAsRole(envB.pool, 'platform_auth_lookup', { readOnly: true }, (c) => (
    c.query('SELECT person_id, company_slug FROM iam.resolve_auth_identity($1, $2)', [issuerB, sub1])
  ));
  assert.equal(hitB.rows.length, 1);
  assert.equal(hitB.rows[0].person_id, envB.iam.ids.entityMgr);
  assert.equal(hitB.rows[0].company_slug, 'beta');

  const missAinB = await runAsRole(envB.pool, 'platform_auth_lookup', { readOnly: true }, (c) => (
    c.query('SELECT * FROM iam.resolve_auth_identity($1, $2)', [issuerA, sub1])
  ));
  assert.equal(missAinB.rows.length, 0, 'Company A issuer/subject must resolve nobody in Company B DB');

  // Binding a company DB auth identity to nusear_staff, service, or house_account fails 23514.
  await assert.rejects(
    () => inSerializableTx(envA.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: 'auth-bad-staff' })).seq;
      await c.query(
        "INSERT INTO iam.person_auth_identities (id, person_id, principal_origin, auth_issuer, auth_subject, status, journal_seq) VALUES ($1,$2,'nusear_staff',$3,'sub_staff','active',$4)",
        [randomUUID(), envA.iam.ids.nusearOwner, issuerA, seq],
      );
    }),
    (err) => err?.code === '23514',
    'company working DB must forbid nusear_staff auth identities',
  );
  await assert.rejects(
    () => inSerializableTx(envA.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: 'auth-bad-house' })).seq;
      const houseId = randomUUID();
      await c.query("INSERT INTO iam.people (id, person_kind, house_org_id, principal_origin, journal_seq) VALUES ($1,'house_account',$2,'company_local',$3)", [houseId, envA.iam.ids.beaconOrg, seq]);
      await c.query(
        "INSERT INTO iam.person_auth_identities (id, person_id, principal_origin, auth_issuer, auth_subject, status, journal_seq) VALUES ($1,$2,'company_local',$3,'sub_house','active',$4)",
        [randomUUID(), houseId, issuerA, seq],
      );
    }),
    (err) => err?.code === '23514',
    'house_account must not be bound to a sign-in identity',
  );

  // Suspending the auth identity signs nobody in (and blocks duplicate binding while suspended).
  const suspAuthAId = randomUUID();
  await inSerializableTx(envA.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: 'auth-a-suspend' })).seq;
    await c.query(
      `INSERT INTO iam.person_auth_identities (id, person_id, principal_origin, auth_issuer, auth_subject, status, replaces_id, journal_seq)
       VALUES ($1,$2,'company_local',$3,$4,'suspended',$5,$6)`,
      [suspAuthAId, envA.iam.ids.entityMgr, issuerA, sub1, authAId, seq],
    );
  });
  const afterSuspId = await runAsRole(envA.pool, 'platform_auth_lookup', { readOnly: true }, (c) => (
    c.query('SELECT * FROM iam.resolve_auth_identity($1, $2)', [issuerA, sub1])
  ));
  assert.equal(afterSuspId.rows.length, 0, 'suspended auth identity must sign nobody in');

  // While suspended, binding the same (auth_issuer, auth_subject) to another person fails 23505.
  await assert.rejects(
    () => inSerializableTx(envA.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: 'auth-a-dup-while-susp' })).seq;
      await c.query(
        `INSERT INTO iam.person_auth_identities (id, person_id, principal_origin, auth_issuer, auth_subject, status, journal_seq)
         VALUES ($1,$2,'company_local',$3,$4,'active',$5)`,
        [randomUUID(), envA.iam.ids.agentA, issuerA, sub1, seq],
      );
    }),
    (err) => err?.code === '23505',
    'duplicate (auth_issuer, auth_subject) binding while existing identity is suspended must fail 23505',
  );

  // Revoking the auth identity also signs nobody in.
  await inSerializableTx(envA.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: 'auth-a-revoke' })).seq;
    await c.query(
      `INSERT INTO iam.person_auth_identities (id, person_id, principal_origin, auth_issuer, auth_subject, status, replaces_id, journal_seq)
       VALUES ($1,$2,'company_local',$3,$4,'revoked',$5,$6)`,
      [randomUUID(), envA.iam.ids.entityMgr, issuerA, sub1, suspAuthAId, seq],
    );
  });
  const afterRevId = await runAsRole(envA.pool, 'platform_auth_lookup', { readOnly: true }, (c) => (
    c.query('SELECT * FROM iam.resolve_auth_identity($1, $2)', [issuerA, sub1])
  ));
  assert.equal(afterRevId.rows.length, 0, 'revoked auth identity must sign nobody in');

  // Active auth identity on a suspended person signs nobody in.
  await inSerializableTx(envB.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: envB.iam.environment, commandKey: 'auth-b-susp-person' })).seq;
    const prevPv = (await c.query('SELECT id FROM iam.person_versions WHERE person_id = $1 AND superseded_by_id IS NULL', [envB.iam.ids.entityMgr])).rows[0].id;
    await c.query(
      `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, replaces_id, journal_seq)
       VALUES ($1,$2,'company_local','Dana Entity','Dana Entity','dana.em@acme.example','suspended',$3,$4)`,
      [randomUUID(), envB.iam.ids.entityMgr, prevPv, seq],
    );
  });
  const afterSuspPerson = await runAsRole(envB.pool, 'platform_auth_lookup', { readOnly: true }, (c) => (
    c.query('SELECT * FROM iam.resolve_auth_identity($1, $2)', [issuerB, sub1])
  ));
  assert.equal(afterSuspPerson.rows.length, 0, 'active auth identity on a suspended person must sign nobody in');

  // Privilege lockdown: platform_app cannot call resolve_auth_identity or read person_auth_identities;
  // platform_auth_lookup cannot read any base table, app_views, or app_cmd.
  await assert.rejects(
    () => runAsRole(envA.pool, 'platform_app', { token: envA.ownerToken, readOnly: true }, (c) => (
      c.query('SELECT * FROM iam.resolve_auth_identity($1, $2)', [issuerA, sub1])
    )),
    (err) => err?.code === '42501',
    'platform_app must get 42501 on iam.resolve_auth_identity',
  );
  await assert.rejects(
    () => runAsRole(envA.pool, 'platform_app', { token: envA.ownerToken, readOnly: true }, (c) => (
      c.query('SELECT * FROM iam.person_auth_identities LIMIT 1')
    )),
    (err) => err?.code === '42501',
    'platform_app must get 42501 on iam.person_auth_identities',
  );
  for (const sql of [
    'SELECT * FROM iam.person_auth_identities LIMIT 1',
    'SELECT * FROM iam.people LIMIT 1',
    'SELECT * FROM iam_secret.signing_keys LIMIT 1',
    'SELECT * FROM coherence.runs LIMIT 1',
    'SELECT * FROM app_views.coherence_runs LIMIT 1',
  ]) {
    await assert.rejects(
      () => runAsRole(envA.pool, 'platform_auth_lookup', { readOnly: true }, (c) => c.query(sql)),
      (err) => err?.code === '42501',
      `platform_auth_lookup must get 42501 on ${sql}`,
    );
  }
});

test('Layer 7E [E2 Test 6]: platform_iam_sync writes only Nusear people, entity tree, catalog, tool switches, and Nusear/service keys; refuses all company_local writes', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, environment } = env.iam;

  // Allowed writes under platform_iam_sync: Nusear staff person + version + root membership + internal grant + org + tool switch + nusear_staff/service keys.
  const beforeCoKey = (await env.pool.query(
    'SELECT secret_bytes, active_until FROM iam_secret.signing_keys WHERE key_id = $1',
    [env.iam.keyId],
  )).rows[0];
  const syncedStaffId = randomUUID();
  const syncedOrgId = randomUUID();
  const syncedStaffSecret = randomBytes(32);
  const syncedSvcSecret = randomBytes(32);
  await inSerializableTx(env.pool, async (c) => {
    await c.query('SET LOCAL ROLE platform_iam_sync');
    const seq = (await appendIamAuditEntry(c, { environment, commandKind: 'iam.sync_allowed', commandKey: 'sync-allowed-e2' })).seq;

    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'agency',$2)", [syncedOrgId, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'synced_agency','Synced Agency','active',$3)",
      [randomUUID(), syncedOrgId, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), syncedOrgId, ids.companyOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','on','active',$3)",
      [randomUUID(), syncedOrgId, seq],
    );
    await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','nusear_staff',$2)", [syncedStaffId, seq]);
    await c.query(
      "INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'nusear_staff','Synced Support','Synced Support','synced.support@nusear.example','active',$3)",
      [randomUUID(), syncedStaffId, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), syncedStaffId, ids.rootOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
      [randomUUID(), syncedStaffId, ids.roleNusearAdmin, ids.rootOrg, seq],
    );
    await c.query(
      `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, key_scope, active_from)
       VALUES ('k_sync_staff_e2',$1,$3,'nusear_staff',pg_catalog.now() - INTERVAL '1 minute'),
              ('k_sync_svc_e2',$2,$3,'service',pg_catalog.now() - INTERVAL '1 minute')`,
      [syncedStaffSecret, syncedSvcSecret, environment],
    );
    const updAllowed = await c.query(
      "UPDATE iam_secret.signing_keys SET active_until = pg_catalog.now() + INTERVAL '48 hours' WHERE key_id IN ('k_sync_staff_e2', 'k_sync_svc_e2')",
    );
    assert.equal(updAllowed.rowCount, 2, 'platform_iam_sync must update both nusear_staff and service keys');

    // RLS on iam_secret.signing_keys: platform_iam_sync sees 0 company_local keys while reading nusear_staff and service keys.
    const visibleKeys = (await c.query('SELECT key_id, key_scope FROM iam_secret.signing_keys ORDER BY key_id')).rows;
    assert.equal(
      visibleKeys.filter((r) => r.key_scope === 'company_local').length,
      0,
      'platform_iam_sync must see 0 company_local signing keys on SELECT',
    );
    assert.ok(visibleKeys.some((r) => r.key_id === 'k_sync_staff_e2' && r.key_scope === 'nusear_staff'), 'platform_iam_sync must see nusear_staff keys');
    assert.ok(visibleKeys.some((r) => r.key_id === 'k_sync_svc_e2' && r.key_scope === 'service'), 'platform_iam_sync must see service keys');

    // Direct UPDATE targeting a company_local key affects 0 rows under RLS (row stays hidden and untouched).
    const updCo = await c.query(
      "UPDATE iam_secret.signing_keys SET active_until = pg_catalog.now() + INTERVAL '5 minutes' WHERE key_id = $1",
      [env.iam.keyId],
    );
    assert.equal(updCo.rowCount, 0, 'platform_iam_sync UPDATE targeting company_local key must affect 0 rows under RLS');
  });

  // Verify company_local key is untouched and still signs in for company_local; newly synced staff/service keys also sign in.
  const afterCoKey = (await env.pool.query(
    'SELECT secret_bytes, active_until FROM iam_secret.signing_keys WHERE key_id = $1',
    [env.iam.keyId],
  )).rows[0];
  assert.deepEqual(afterCoKey.secret_bytes, beforeCoKey.secret_bytes, 'company_local secret_bytes must remain untouched after sync UPDATE attempt');
  assert.equal(afterCoKey.active_until, beforeCoKey.active_until, 'company_local active_until must remain untouched after sync UPDATE attempt');

  for (const [label, tok, expectedActor] of [
    ['company_local sign-in after sync', env.iam.tokens.entityMgr, ids.entityMgr],
    ['synced nusear_staff key sign-in', mintSignedToken({ keyId: 'k_sync_staff_e2', secretBytes: syncedStaffSecret, environment, actorPersonId: syncedStaffId }), syncedStaffId],
    ['synced service key sign-in', mintSignedToken({ keyId: 'k_sync_svc_e2', secretBytes: syncedSvcSecret, environment, actorPersonId: ids.workerService }), ids.workerService],
  ]) {
    await runAsRole(env.pool, 'platform_app', { token: tok, readOnly: true }, async (c) => {
      const ctx = (await c.query('SELECT actor_person_id FROM iam.session_context()')).rows[0];
      assert.equal(ctx?.actor_person_id, expectedActor, `${label} must succeed in iam.session_context()`);
    });
  }

  // Migration-installed lock: RLS enabled without FORCE, shared owner with iam.session_context() (not platform_iam_sync), only platform_iam_sync policies.
  const skMeta = (await env.pool.query(
    `SELECT c.relrowsecurity, c.relforcerowsecurity, c.relowner = p.proowner AS same_owner,
            pg_catalog.pg_get_userbyid(c.relowner) AS owner_name,
            ARRAY(SELECT DISTINCT r::text FROM pg_catalog.pg_policies pol, pg_catalog.unnest(pol.roles) AS r
                  WHERE pol.schemaname = 'iam_secret' AND pol.tablename = 'signing_keys' ORDER BY r::text) AS pol_roles
     FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     JOIN pg_catalog.pg_proc p ON p.pronamespace = 'iam'::regnamespace AND p.proname = 'session_context' AND p.pronargs = 0
     WHERE n.nspname = 'iam_secret' AND c.relname = 'signing_keys'`,
  )).rows[0];
  assert.deepEqual([skMeta.relrowsecurity, skMeta.relforcerowsecurity, skMeta.same_owner], [true, false, true], 'iam_secret.signing_keys must enable non-forced RLS with same owner as iam.session_context()');
  assert.notEqual(skMeta.owner_name, 'platform_iam_sync', 'iam_secret.signing_keys owner must not be platform_iam_sync');
  assert.deepEqual(skMeta.pol_roles, ['platform_iam_sync'], 'iam_secret.signing_keys policies must target only platform_iam_sync');

  // Refused writes under platform_iam_sync (every single one must fail 42501):
  const entityMgrPvId = (await env.pool.query(
    'SELECT id FROM iam.person_versions WHERE person_id = $1 AND superseded_by_id IS NULL',
    [ids.entityMgr],
  )).rows[0].id;
  const customRoleId = randomUUID();
  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment, targetOrgId: ids.companyOrg, commandKey: 'seed-custom-role-e2' })).seq;
    await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'acme_custom_e2',$2,$3)", [customRoleId, ids.companyOrg, seq]);
    await c.query(
      "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,'Acme Custom',false,false,true,'active',$3)",
      [randomUUID(), customRoleId, seq],
    );
  });

  const syncForbidden = [
    ['insert company_local person', async (c, seq) => {
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','company_local',$2)", [randomUUID(), seq]);
    }],
    ['supersede company_local person_version', async (c, seq) => {
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, replaces_id, journal_seq) VALUES ($1,$2,'company_local','Hijack','Hijack','dana.em@acme.example','active',$3,$4)",
        [randomUUID(), ids.entityMgr, entityMgrPvId, seq],
      );
    }],
    ['insert company_local membership', async (c, seq) => {
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2026-01-01,)'::daterange,'active',$4)",
        [randomUUID(), ids.entityMgr, ids.beaconOrg, seq],
      );
    }],
    ['insert company_local role_grant', async (c, seq) => {
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), ids.entityMgr, ids.roleCompanyAdmin, ids.companyOrg, seq],
      );
    }],
    ['insert agent_affiliations', async (c, seq) => {
      await c.query(
        "INSERT INTO iam.agent_affiliations (id, person_id, npn, agency_org_id, split_bps, agent_file_name, valid_range, status, journal_seq) VALUES ($1,$2,'77788899',$3,8000,'Sync Bad','[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), ids.agentA, ids.beaconOrg, seq],
      );
    }],
    ['insert person_auth_identities', async (c, seq) => {
      await c.query(
        "INSERT INTO iam.person_auth_identities (id, person_id, principal_origin, auth_issuer, auth_subject, status, journal_seq) VALUES ($1,$2,'company_local','https://clerk.acme.example','sub_sync_bad','active',$3)",
        [randomUUID(), ids.entityMgr, seq],
      );
    }],
    ['insert company custom role', async (c, seq) => {
      await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'sync_custom_bad',$2,$3)", [randomUUID(), ids.companyOrg, seq]);
    }],
    ['insert role_rights on company custom role', async (c, seq) => {
      await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,'act:coherence.bob.read','active',$3)", [randomUUID(), customRoleId, seq]);
    }],
    ['insert company_local signing key', async (c) => {
      await c.query(
        "INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, key_scope, active_from) VALUES ('k_sync_co_bad',$1,$2,'company_local',pg_catalog.now())",
        [randomBytes(32), environment],
      );
    }],
    ['re-scope nusear_staff signing key to company_local', async (c) => {
      await c.query(
        "UPDATE iam_secret.signing_keys SET key_scope = 'company_local' WHERE key_id = 'k_sync_staff_e2'",
      );
    }],
    ['upsert conflict against company_local signing key', async (c) => {
      await c.query(
        `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, key_scope, active_from)
         VALUES ($1,$2,$3,'nusear_staff',pg_catalog.now())
         ON CONFLICT (key_id) DO UPDATE SET secret_bytes = EXCLUDED.secret_bytes`,
        [env.iam.keyId, randomBytes(32), environment],
      );
    }],
  ];

  for (const [label, fn] of syncForbidden) {
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        await c.query('SET LOCAL ROLE platform_iam_sync');
        const seq = (await appendIamAuditEntry(c, { environment, commandKey: `sync-bad-${randomUUID()}` })).seq;
        await fn(c, seq);
      }),
      (err) => err?.code === '42501',
      `platform_iam_sync must be refused 42501 on: ${label}`,
    );
  }
});

test('Layer 7E [E2 Test 7]: assert_can_write records writes deterministically (self vs nusear_support vs service) and customer-facing views (journal, decisions, audit) show Nusear support, never the Nusear person name or ID', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, environment } = env.iam;

  const samePersonStaffId = randomUUID();
  const samePersonLocalId = randomUUID();
  const companyJournalReaderId = randomUUID();
  const roleLocalWriter = randomUUID();
  const roleCustJournalDecReader = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment, targetOrgId: ids.companyOrg, commandKey: 'e2-attr-seed' })).seq;

    await c.query(
      `INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq)
       VALUES ($1,'human','nusear_staff',$4),($2,'human','company_local',$4),($3,'human','company_local',$4)`,
      [samePersonStaffId, samePersonLocalId, companyJournalReaderId, seq],
    );
    await c.query(
      `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq)
       VALUES ($1,$2,'nusear_staff','Pat RealName Support','Pat RealName Support','pat.dual@example.test','active',$7),
              ($3,$4,'company_local','Pat Company Owner','Pat Company Owner','pat.dual@example.test','active',$7),
              ($5,$6,'company_local','Sloan Customer Auditor','Sloan Customer Auditor','sloan.audit@acme.example','active',$7)`,
      [randomUUID(), samePersonStaffId, randomUUID(), samePersonLocalId, randomUUID(), companyJournalReaderId, seq],
    );
    await c.query(
      `INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq)
       VALUES ($1,$2,$5,'owner','[2020-01-01,)'::daterange,'active',$7),
              ($3,$4,$6,'owner','[2020-01-01,)'::daterange,'active',$7),
              ($8,$9,$6,'employee','[2020-01-01,)'::daterange,'active',$7)`,
      [randomUUID(), samePersonStaffId, randomUUID(), samePersonLocalId, ids.rootOrg, ids.companyOrg, seq, randomUUID(), companyJournalReaderId],
    );

    // Company-local write role (inputs + decision baseline) and customer reader role (journal + decisions + audit, NO nusear_actor).
    await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'local_writer_e2',$3,$4),($2,'cust_jd_reader_e2',$3,$4)", [roleLocalWriter, roleCustJournalDecReader, ids.companyOrg, seq]);
    await c.query(
      `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq)
       VALUES ($1,$2,'Local Writer',false,false,true,'active',$5),
              ($3,$4,'Customer JD Reader',false,false,true,'active',$5)`,
      [randomUUID(), roleLocalWriter, randomUUID(), roleCustJournalDecReader, seq],
    );
    for (const rightId of ['act:coherence.inputs.publish', 'act:coherence.owner.record_baseline']) {
      await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)", [randomUUID(), roleLocalWriter, rightId, seq]);
    }
    for (const rightId of [
      'act:coherence.journal.read', 'act:coherence.decisions.read', 'act:coherence.runs.read',
      'act:coherence.inputs.read', 'act:coherence.unpublished.read', 'act:platform.audit_journal.read',
      'col:coherence.member_phi',
    ]) {
      await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)", [randomUUID(), roleCustJournalDecReader, rightId, seq]);
    }
    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$10),
              ($5,$6,$7,$8,true,'org_subtree','[2020-01-01,)'::daterange,'active',$10),
              ($9,$11,$12,$8,true,'org_subtree','[2020-01-01,)'::daterange,'active',$10)`,
      [
        randomUUID(), samePersonStaffId, ids.roleNusearOwner, ids.rootOrg,
        randomUUID(), samePersonLocalId, roleLocalWriter, ids.companyOrg,
        randomUUID(), seq, companyJournalReaderId, roleCustJournalDecReader,
      ],
    );
  });

  const staffTok = env.iam.tokenFor(samePersonStaffId, null, { keyScope: 'nusear_staff' });
  const localTok = env.iam.tokenFor(samePersonLocalId, null, { keyScope: 'company_local' });
  const custReaderTok = env.iam.tokenFor(companyJournalReaderId, null, { keyScope: 'company_local' });

  // 1. Direct iam.assert_can_write attribution: nusear_staff -> nusear_support, company_local -> self, service -> service.
  const staffWr = await runAsRole(env.pool, 'platform_app', { token: staffTok, readOnly: false }, (c) => (
    c.query("SELECT actor_person_id, recorded_as FROM iam.assert_can_write('act:coherence.inputs.publish', $1::uuid)", [ids.companyOrg])
  ));
  assert.equal(staffWr.rows[0].actor_person_id, samePersonStaffId);
  assert.equal(staffWr.rows[0].recorded_as, 'nusear_support');

  const localWr = await runAsRole(env.pool, 'platform_app', { token: localTok, readOnly: false }, (c) => (
    c.query("SELECT actor_person_id, recorded_as FROM iam.assert_can_write('act:coherence.inputs.publish', $1::uuid)", [ids.companyOrg])
  ));
  assert.equal(localWr.rows[0].actor_person_id, samePersonLocalId);
  assert.equal(localWr.rows[0].recorded_as, 'self');

  const svcWr = await runAsRole(env.pool, 'platform_app', { token: env.workerToken, readOnly: false }, (c) => (
    c.query("SELECT actor_person_id, recorded_as FROM iam.assert_can_write('act:coherence.checks.record', $1::uuid)", [ids.companyOrg])
  ));
  assert.equal(svcWr.rows[0].actor_person_id, ids.workerService);
  assert.equal(svcWr.rows[0].recorded_as, 'service');

  // 2. Real writes via app_cmd: one decision baseline by Nusear support, one by the company-local user, plus one imported row (non-UUID decided_by).
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const readonlyPool = createRoleScopedTestPool(env.pool, 'platform_readonly');
  const appCommands = createAppCommands({ pool: appPool, stores: env.stores });
  const handlers = createWebHandlers({ pool: appPool, readonlyPool, companySlug: 'acme', stores: env.stores });

  const supportRecId = 'carrier_a|direct|NM:support,dec|100.00|2026-10';
  const localRecId = 'carrier_a|direct|NM:local,dec|100.00|2026-10';
  const importedRecId = 'carrier_a|direct|NM:import,dec|100.00|2026-10';
  const staffImportedRecId = 'carrier_a|direct|NM:staffimp,dec|100.00|2026-10';
  const staffFallbackSpoofRecId = 'carrier_a|direct|NM:stafffb,dec|100.00|2026-10';
  const staffUuidSpoofRecId = 'carrier_a|direct|NM:staffspoof,dec|100.00|2026-10';
  const histLabelRecId = 'carrier_a|direct|NM:histlbl,dec|100.00|2026-08';
  const histDefaultRecId = 'carrier_a|direct|NM:histdef,dec|100.00|2026-08';
  const histUuidSpoofRecId = 'carrier_a|direct|NM:histuuid,dec|100.00|2026-08';

  const supRes = await appCommands.recordDecisionBaseline({
    dbToken: staffTok,
    commandKey: 'e2-support-baseline',
    headerContract: 'v2',
    imported: true,
    decisions: [{
      recordId: supportRecId, disposition: 'CONFIRM', agent: 'Sam Seller', agency: 'Beacon',
      policy: 'POL-1', book: 'MA', month: '2026-10', status: 'ACTIVE', note: 'support action',
    }],
  });
  const locRes = await appCommands.recordDecisionBaseline({
    dbToken: localTok,
    commandKey: 'e2-local-baseline',
    headerContract: 'v2',
    parentCommitId: supRes.result.decisionCommitId,
    imported: true,
    decisions: [{
      recordId: localRecId, disposition: 'CONFIRM', agent: 'Sam Seller', agency: 'Beacon',
      policy: 'POL-2', book: 'MA', month: '2026-10', status: 'ACTIVE', note: 'company owner action',
    }],
  });
  const impRes = await appCommands.recordDecisionBaseline({
    dbToken: localTok,
    commandKey: 'e2-imported-baseline',
    headerContract: 'v2',
    parentCommitId: locRes.result.decisionCommitId,
    imported: true,
    decisions: [{
      recordId: importedRecId, disposition: 'CONFIRM', agent: 'Sam Seller', agency: 'Beacon',
      policy: 'POL-3', book: 'MA', month: '2026-10', status: 'ACTIVE', note: 'historical row',
      decidedBy: 'historical_import', actingFor: null,
    }],
  });
  // Imported baseline called by Nusear support:
  // (a) historical label ('historical_import', actingFor null) must stay acting_for NULL (not stamped 'nusear_support');
  // (b) omitted decidedBy with spoofed actingFor='self' falls back to caller's own actor + 'nusear_support';
  // (c) spoofed company-local person UUID as decidedBy cannot display Nusear support as the company's person.
  const staffImpRes = await appCommands.recordDecisionBaseline({
    dbToken: staffTok,
    commandKey: 'e2-staff-imported-paths',
    headerContract: 'v2',
    parentCommitId: impRes.result.decisionCommitId,
    imported: true,
    decisions: [
      {
        recordId: staffImportedRecId, disposition: 'CONFIRM', agent: 'Sam Seller', agency: 'Beacon',
        policy: 'POL-4', book: 'MA', month: '2026-10', status: 'ACTIVE', note: 'staff importing historical',
        decidedBy: 'historical_import', actingFor: null,
      },
      {
        recordId: staffFallbackSpoofRecId, disposition: 'CONFIRM', agent: 'Sam Seller', agency: 'Beacon',
        policy: 'POL-5', book: 'MA', month: '2026-10', status: 'ACTIVE', note: 'staff fallback no decided_by',
        actingFor: 'self',
      },
      {
        recordId: staffUuidSpoofRecId, disposition: 'CONFIRM', agent: 'Sam Seller', agency: 'Beacon',
        policy: 'POL-6', book: 'MA', month: '2026-10', status: 'ACTIVE', note: 'staff spoofing company local uuid',
        decidedBy: samePersonLocalId, actingFor: 'self',
      },
    ],
  });
  // Live (not imported) baseline with decision rows is also refused by decisions_check (review_save_id required for live rows),
  // while live review decisions via coherence_save_review_decisions always stamp caller actor + acting_for (ignoring payload overrides).
  await assert.rejects(
    () => appCommands.recordDecisionBaseline({
      dbToken: staffTok,
      commandKey: 'e2-live-baseline-nonempty',
      headerContract: 'v2',
      parentCommitId: staffImpRes.result.decisionCommitId,
      imported: false,
      decisions: [{
        recordId: 'carrier_a|direct|NM:livebase,dec|100.00|2026-10', disposition: 'CONFIRM',
        decidedBy: samePersonLocalId, actingFor: 'self',
      }],
    }),
    (err) => err?.code === '23514' || err?.code === 'INVARIANT_VIOLATION',
    'live (not imported) non-empty decision baseline must be refused when review_save_id is absent',
  );
  const { engineVersionId } = await seedEngineCopyVersion(env);
  await seedStandingInput(env, { commandKey: 'e2-t7-live-standing' });
  const liveWorker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createDataOnlyMockEngineMaterializer({ adjustReconfirmRecordId: null }),
    tempBaseDir: env.tempDir,
  }));
  const liveLaunched = await env.commands.launchRun({
    dbToken: env.ownerToken,
    commandKey: 'e2-t7-live-run',
    statementDate: '2026-10-25',
    engineVersionId,
  });
  for (let i = 0; i < 3; i++) assert.equal((await liveWorker.runOnce()).action, 'step_finished');
  const liveSeq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [liveLaunched.result.runId])).rows[0].latest_journal_seq);
  const bibleEvId = (await env.pool.query("SELECT coherence.current_finished_attempt($1::uuid, 'bible') AS ev", [liveLaunched.result.runId])).rows[0].ev;
  const queueKeys = (await env.pool.query(
    'SELECT record_id FROM coherence.review_queue_items WHERE attempt_event_id = $1::uuid ORDER BY record_id',
    [bibleEvId],
  )).rows.map((r) => r.record_id);
  assert.ok(queueKeys.length >= 1, 'bible attempt must have at least one review queue item');
  const liveSupportRecId = queueKeys[0];
  await appCommands.saveReviewDecisions({
    dbToken: staffTok,
    commandKey: 'e2-t7-live-review-spoof',
    expectedJournalSeq: liveSeq,
    runId: liveLaunched.result.runId,
    surface: 'bible',
    decisions: queueKeys.map((recordId) => ({
      recordId,
      disposition: 'CONFIRM',
      decidedBy: samePersonLocalId,
      actingFor: 'self',
    })),
  });

  const histDcId = randomUUID();
  await appCommands.importHistoricalRun({
    dbToken: staffTok,
    commandKey: 'e2-t7-hist-run-decisions',
    run: { origin: 'company_import', statementDate: '2026-08-15', sourceFolder: 'company-runs/2026-08-15-t7', emitMode: 'coherence' },
    inputVersion: { reason: 'e2 t7 historical run decision attribution' },
    decisionCommits: [{ id: histDcId, commitKind: 'historical_overlay', headerContract: 'v2', cumulativeDecisionCount: 3 }],
    decisions: [
      { decisionCommitId: histDcId, rowOrder: 1, recordId: histLabelRecId, disposition: 'CONFIRM', decidedBy: 'legacy_reviewer', actingFor: 'legacy_team' },
      { decisionCommitId: histDcId, rowOrder: 2, recordId: histDefaultRecId, disposition: 'CONFIRM' },
      { decisionCommitId: histDcId, rowOrder: 3, recordId: histUuidSpoofRecId, disposition: 'CONFIRM', decidedBy: samePersonLocalId, actingFor: 'self' },
    ],
  });

  // Verify raw coherence.decisions attribution for every path (imported historical, fallback, UUID spoof, historical run import, and live review save).
  const rawDecMap = new Map(
    (await env.pool.query(
      'SELECT record_id, decided_by, acting_for, imported FROM coherence.decisions WHERE record_id = ANY($1::text[])',
      [[staffImportedRecId, staffFallbackSpoofRecId, staffUuidSpoofRecId, histLabelRecId, histDefaultRecId, histUuidSpoofRecId, liveSupportRecId]],
    )).rows.map((r) => [r.record_id, r]),
  );
  assert.equal(rawDecMap.get(staffImportedRecId).decided_by, 'historical_import', 'imported historical label stays historical_import');
  assert.equal(rawDecMap.get(staffImportedRecId).acting_for, null, 'imported historical label with acting_for null stays null even when called by Nusear support');
  assert.equal(rawDecMap.get(staffFallbackSpoofRecId).decided_by, samePersonStaffId, 'imported row without decided_by falls back to caller actor');
  assert.equal(rawDecMap.get(staffFallbackSpoofRecId).acting_for, 'nusear_support', 'imported row without decided_by stamps caller acting_for, ignoring spoofed actingFor');
  assert.equal(rawDecMap.get(staffUuidSpoofRecId).decided_by, samePersonStaffId, 'imported baseline cannot let Nusear support spoof a company person UUID');
  assert.equal(rawDecMap.get(staffUuidSpoofRecId).acting_for, 'nusear_support', 'spoofed UUID in imported baseline stamps caller nusear_support');
  assert.equal(rawDecMap.get(histLabelRecId).decided_by, 'legacy_reviewer', 'historical run keeps non-id historical label');
  assert.equal(rawDecMap.get(histLabelRecId).acting_for, 'legacy_team', 'historical run keeps carried acting_for for non-id label');
  assert.equal(rawDecMap.get(histDefaultRecId).decided_by, 'historical_import', 'historical run falls back to historical_import when decided_by is omitted');
  assert.equal(rawDecMap.get(histDefaultRecId).acting_for, null);
  assert.equal(rawDecMap.get(histUuidSpoofRecId).decided_by, samePersonStaffId, 'historical run refuses person UUID in decided_by and stamps caller');
  assert.equal(rawDecMap.get(histUuidSpoofRecId).acting_for, 'nusear_support', 'historical run stamps caller acting_for on UUID spoof');
  assert.equal(rawDecMap.get(liveSupportRecId).decided_by, samePersonStaffId, 'live save_review_decisions always stamps caller actor');
  assert.equal(rawDecMap.get(liveSupportRecId).acting_for, 'nusear_support', 'live save_review_decisions always stamps caller acting_for');
  assert.equal(rawDecMap.get(liveSupportRecId).imported, false);

  // Customer views: Nusear support's writes show 'Nusear support' (never Pat RealName Support or UUID);
  // company-local writes show the company-local user's ID and name.
  await withRequestTx(appPool, custReaderTok, async (tx) => {
    const jRows = (await tx.query(
      "SELECT command_key, actor, actor_display, acting_for FROM app_views.coherence_journal WHERE command_key IN ('e2-support-baseline', 'e2-local-baseline') ORDER BY seq",
    )).rows;
    assert.equal(jRows.length, 2);
    assert.equal(jRows[0].command_key, 'e2-support-baseline');
    assert.equal(jRows[0].actor, 'Nusear support', 'customer coherence_journal.actor must mask Nusear support UUID');
    assert.equal(jRows[0].actor_display, 'Nusear support', 'customer coherence_journal.actor_display must mask Nusear person name');
    assert.equal(jRows[0].acting_for, 'nusear_support');
    assert.equal(jRows[1].command_key, 'e2-local-baseline');
    assert.equal(jRows[1].actor, samePersonLocalId, 'customer coherence_journal.actor keeps company-local UUID');
    assert.equal(jRows[1].actor_display, 'Pat Company Owner', 'customer coherence_journal.actor_display shows company-local name');
    assert.equal(jRows[1].acting_for, null);

    const dRows = (await tx.query(
      'SELECT record_id, decided_by, decided_by_display, acting_for FROM app_views.coherence_decisions WHERE record_id = ANY($1::text[]) ORDER BY journal_seq, row_order',
      [[supportRecId, localRecId, importedRecId, staffImportedRecId, staffFallbackSpoofRecId, staffUuidSpoofRecId, histLabelRecId, histDefaultRecId, histUuidSpoofRecId, liveSupportRecId]],
    )).rows;
    const dByRec = new Map(dRows.map((r) => [r.record_id, r]));
    assert.equal(dRows.length, 10);
    assert.equal(dByRec.get(supportRecId).decided_by, 'Nusear support', 'customer coherence_decisions.decided_by must mask Nusear support UUID');
    assert.equal(dByRec.get(supportRecId).decided_by_display, 'Nusear support', 'customer coherence_decisions.decided_by_display must mask Nusear person name');
    assert.equal(dByRec.get(supportRecId).acting_for, 'nusear_support');
    assert.equal(dByRec.get(localRecId).decided_by, samePersonLocalId);
    assert.equal(dByRec.get(localRecId).decided_by_display, 'Pat Company Owner');
    assert.equal(dByRec.get(localRecId).acting_for, null);
    assert.equal(dByRec.get(importedRecId).decided_by, 'historical_import', 'non-UUID historical decided_by must read cleanly without UUID cast errors');
    assert.equal(dByRec.get(importedRecId).decided_by_display, 'historical_import');
    assert.equal(dByRec.get(staffImportedRecId).decided_by, 'historical_import', 'staff-imported historical_import row stays historical_import in customer view');
    assert.equal(dByRec.get(staffImportedRecId).decided_by_display, 'historical_import');
    assert.equal(dByRec.get(staffImportedRecId).acting_for, null);
    assert.equal(dByRec.get(staffFallbackSpoofRecId).decided_by, 'Nusear support');
    assert.equal(dByRec.get(staffFallbackSpoofRecId).decided_by_display, 'Nusear support');
    assert.equal(dByRec.get(staffUuidSpoofRecId).decided_by, 'Nusear support', 'Nusear support spoofing company UUID must still appear as Nusear support, never company person');
    assert.equal(dByRec.get(staffUuidSpoofRecId).decided_by_display, 'Nusear support');
    assert.equal(dByRec.get(histLabelRecId).decided_by, 'legacy_reviewer');
    assert.equal(dByRec.get(histLabelRecId).acting_for, 'legacy_team');
    assert.equal(dByRec.get(histDefaultRecId).decided_by, 'historical_import');
    assert.equal(dByRec.get(histUuidSpoofRecId).decided_by, 'Nusear support', 'historical run UUID spoof must appear as Nusear support, never company person');
    assert.equal(dByRec.get(histUuidSpoofRecId).decided_by_display, 'Nusear support');
    assert.equal(dByRec.get(liveSupportRecId).decided_by, 'Nusear support', 'live Nusear support save must appear as Nusear support, never company person');
    assert.equal(dByRec.get(liveSupportRecId).decided_by_display, 'Nusear support');

    const aRows = (await tx.query(
      "SELECT command_kind, recorded_as, recorded_by_display, actor_person_id FROM app_views.audit_journal WHERE command_kind = 'coherence.record_decision_baseline' ORDER BY seq",
    )).rows;
    assert.ok(aRows.length >= 2);
    assert.equal(aRows[0].recorded_as, 'nusear_support');
    assert.equal(aRows[0].recorded_by_display, 'Nusear support');
    assert.equal(aRows[0].actor_person_id, null);
    assert.equal(aRows[1].recorded_as, 'self');
    assert.equal(aRows[1].recorded_by_display, 'Pat Company Owner');
    assert.equal(aRows[1].actor_person_id, null);
  }, { readOnly: true });

  // Web handlers inherit SQL masking automatically.
  const webDecSup = await handlers.getDecisionKeyHistory(custReaderTok, supportRecId);
  assert.equal(webDecSup.history.length, 1);
  assert.equal(webDecSup.history[0].decidedBy, 'Nusear support');
  assert.equal(webDecSup.history[0].actingFor, 'nusear_support');

  const webHistSup = await handlers.getHistoryAsOf(custReaderTok, { asOfSeq: supRes.journalSeq });
  assert.equal(webHistSup.journalEntry.actor, 'Nusear support');
  assert.equal(webHistSup.journalEntry.actingFor, 'nusear_support');

  // Nusear internal reader (holding col:platform.audit_journal.nusear_actor) sees real Nusear person UUID & name.
  await withRequestTx(appPool, staffTok, async (tx) => {
    const jSup = (await tx.query("SELECT actor, actor_display, acting_for FROM app_views.coherence_journal WHERE command_key = 'e2-support-baseline'")).rows[0];
    assert.equal(jSup.actor, samePersonStaffId);
    assert.equal(jSup.actor_display, 'Pat RealName Support');
    assert.equal(jSup.acting_for, 'nusear_support');

    const dSup = (await tx.query('SELECT decided_by, decided_by_display, acting_for FROM app_views.coherence_decisions WHERE record_id = $1', [supportRecId])).rows[0];
    assert.equal(dSup.decided_by, samePersonStaffId);
    assert.equal(dSup.decided_by_display, 'Pat RealName Support');
    assert.equal(dSup.acting_for, 'nusear_support');
  }, { readOnly: true });
});

test('Layer 7E [E2 Test 8]: holding-company user-grant branch is deleted (grant above the company opens nothing inside it even when all company orgs are live)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, environment } = env.iam;

  const grandHoldingCo = randomUUID();
  const holdingCo = randomUUID();
  const holdingExec = randomUUID();
  const grandHoldingExec = randomUUID();
  const holdingMemTenantGrant = randomUUID();
  const holdingRole = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment, targetOrgId: ids.companyOrg, commandKey: 'e2-holding-gone' })).seq;
    for (const [oid, slug, name] of [
      [grandHoldingCo, 'e2_grand_hold', 'E2 Grand Holding'],
      [holdingCo, 'e2_hold_co', 'E2 Holding'],
    ]) {
      await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'company',$2)", [oid, seq]);
      await c.query("INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,$3,$4,'active',$5)", [randomUUID(), oid, slug, name, seq]);
    }
    const curCompanyEdgeId = (await c.query('SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND superseded_by_id IS NULL', [ids.companyOrg])).rows[0].id;
    await c.query("INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), grandHoldingCo, ids.rootOrg, seq]);
    await c.query("INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), holdingCo, grandHoldingCo, seq]);
    await c.query("INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4,$5)", [randomUUID(), ids.companyOrg, holdingCo, curCompanyEdgeId, seq]);
    for (const oid of [grandHoldingCo, holdingCo]) {
      await c.query("INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','on','active',$3)", [randomUUID(), oid, seq]);
    }

    await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'e2_hold_all',NULL,$2)", [holdingRole, seq]);
    await c.query("INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,'Hold All',false,false,true,'active',$3)", [randomUUID(), holdingRole, seq]);
    for (const rightId of [
      'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
      'act:coherence.ledger.read', 'act:coherence.runs.read', 'act:coherence.inputs.read',
      'act:coherence.outputs.read', 'act:coherence.unpublished.read', 'act:coherence.inputs.publish',
      'col:coherence.statement_cash', 'col:coherence.upline_cash',
      'col:coherence.member_phi', 'col:coherence.member_contact',
    ]) {
      await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)", [randomUUID(), holdingRole, rightId, seq]);
    }

    for (const [pid, name, email, memOrg, grantOrg] of [
      [holdingExec, 'Holding Exec', 'hold.exec@e2.example', holdingCo, holdingCo],
      [grandHoldingExec, 'Grand Holding Exec', 'grand.exec@e2.example', grandHoldingCo, grandHoldingCo],
      [holdingMemTenantGrant, 'Holding Mem Tenant', 'hold.mem@e2.example', holdingCo, ids.companyOrg],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [pid, seq]);
      await c.query("INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,$3,$3,$4,'active',$5)", [randomUUID(), pid, name, email, seq]);
      await c.query("INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'owner','[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), pid, memOrg, seq]);
      await c.query("INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)", [randomUUID(), pid, holdingRole, grantOrg, seq]);
    }
  });

  // Seed a sent statement batch so non-empty company data exists.
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const appCommands = createAppCommands({ pool: appPool, stores: env.stores });
  await appCommands.recordStatementBatch({
    dbToken: env.ownerToken,
    commandKey: 'e2-hold-batch',
    batchKind: 'historical_sent',
    statementDate: '2026-09-15',
    reason: 'holding isolation fixture',
    agencyLines: [{
      entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller',
      recordId: 'carrier_a|direct|NM:hold,pat|100.00|2026-09',
      sourceFile: 'h.csv', sourceRowNo: 1, srcType: 'direct', carrier: 'carrier_a',
      mbi: '1AB2-CD3-EF45', member: 'Pat Hold', policyId: 701, txId: 701,
      grossComm: '100.00', amount: '80.00',
    }],
    uplineLines: [{
      sourceEntity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller',
      recordId: 'carrier_a|direct|NM:hold,pat|100.00|2026-09',
      sourceFile: 'h.csv', sourceRowNo: 1, srcType: 'direct', carrier: 'carrier_a',
      mbi: '1AB2-CD3-EF45', member: 'Pat Hold', policyId: 701, txId: 701,
      grossComm: '100.00', amount: '20.00',
    }],
  });

  // Every holding-company executive gets ZERO orgs, ZERO rows, and 42501 on writes (even with all orgs live).
  for (const [label, pid] of [
    ['holdingExec', holdingExec],
    ['grandHoldingExec', grandHoldingExec],
    ['holdingMemTenantGrant', holdingMemTenantGrant],
  ]) {
    const tok = env.iam.tokenFor(pid, null, { keyScope: 'company_local' });
    await withRequestTx(appPool, tok, async (tx) => {
      assert.deepEqual((await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `${label} must get 0 wide orgs inside company DB`);
      assert.deepEqual((await tx.query("SELECT iam.effective_any_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `${label} must get 0 any orgs inside company DB`);
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n, 0, `${label} must see 0 statement rows`);
    }, { readOnly: true });
    await assert.rejects(
      () => runAsRole(env.pool, 'platform_app', { token: tok, readOnly: false }, (c) => (
        c.query("SELECT * FROM iam.assert_can_write('act:coherence.inputs.publish', $1::uuid)", [ids.companyOrg])
      )),
      (err) => err?.code === '42501',
      `${label} must be refused 42501 on assert_can_write`,
    );
  }

  // Positive control: company's own entityMgr and Nusear owner still see everything inside Acme even when Acme sits under holdingCo.
  for (const [label, tok] of [['entityMgr', env.iam.tokens.entityMgr], ['nusearOwner', env.ownerToken]]) {
    await withRequestTx(appPool, tok, async (tx) => {
      const cnt = (await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n;
      assert.equal(cnt, 1, `${label} must still see Acme rows when Acme sits under a holding company`);
    }, { readOnly: true });
  }
});

test('Layer 7E [E2 Test 9]: app_views.coherence_journal masks materialize_emit body without full entity finance rights, keeps InitPlan single-evaluation, and passes verifyIamConfigInvariants', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, environment } = env.iam;

  const journalPhiNoFinId = randomUUID();
  const emFullJournalId = randomUUID();
  const rPhiNoFin = randomUUID();
  const rFullFin = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment, targetOrgId: ids.companyOrg, commandKey: 'e2-mat-body-personas' })).seq;
    await c.query(
      "INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$3),($2,'human',$3)",
      [journalPhiNoFinId, emFullJournalId, seq],
    );
    await c.query(
      `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq)
       VALUES ($1,$2,'Journal PHI NoFin','Journal PHI NoFin','jphinofin@acme.example','active',$5),
              ($3,$4,'EM Full Journal','EM Full Journal','emfullj@acme.example','active',$5)`,
      [randomUUID(), journalPhiNoFinId, randomUUID(), emFullJournalId, seq],
    );
    await c.query(
      `INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq)
       VALUES ($1,$2,$5,'employee','[2020-01-01,)'::daterange,'active',$6),
              ($3,$4,$5,'owner','[2020-01-01,)'::daterange,'active',$6)`,
      [randomUUID(), journalPhiNoFinId, randomUUID(), emFullJournalId, ids.companyOrg, seq],
    );
    await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'j_phi_nofin_e2',$3,$4),($2,'em_full_j_e2',$3,$4)", [rPhiNoFin, rFullFin, ids.companyOrg, seq]);
    await c.query(
      `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq)
       VALUES ($1,$2,'Journal PHI NoFin',false,false,true,'active',$5),
              ($3,$4,'EM Full Journal',false,false,true,'active',$5)`,
      [randomUUID(), rPhiNoFin, randomUUID(), rFullFin, seq],
    );
    for (const rightId of ['act:coherence.journal.read', 'act:coherence.unpublished.read', 'col:coherence.member_phi']) {
      await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)", [randomUUID(), rPhiNoFin, rightId, seq]);
    }
    for (const rightId of [
      'act:coherence.journal.read', 'act:coherence.unpublished.read',
      'act:coherence.bob.read', 'act:coherence.ledger.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
      'col:coherence.statement_cash', 'col:coherence.upline_cash',
      'col:coherence.member_phi', 'col:coherence.member_contact',
    ]) {
      await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)", [randomUUID(), rFullFin, rightId, seq]);
    }
    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$7,true,'org_subtree','[2020-01-01,)'::daterange,'active',$8),
              ($4,$5,$6,$7,true,'org_subtree','[2020-01-01,)'::daterange,'active',$8)`,
      [randomUUID(), journalPhiNoFinId, rPhiNoFin, randomUUID(), emFullJournalId, rFullFin, ids.companyOrg, seq],
    );
  });

  // Seed standing input, import a finished Emit run, and call standalone materializeEmit so a command_kind = 'materialize_emit' entry exists.
  await seedStandingInput(env, { commandKey: 'e2-mat-standing' });
  const csvs = makeMaterializationCsvs({ entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller' });
  const inpFile = await env.dataStore.promoteBytes(Buffer.from('k\n1\n', 'utf8'), { relPath: 'mat_in.csv', checksPassed: true });
  const stmtArt = await env.stores.promoteArtifact('emits/statements_20261015.csv', Buffer.from(csvs.statementsCsv, 'utf8'), { checksPassed: true });
  const imp = await env.commands.importHistoricalRun({
    dbToken: env.ownerToken,
    commandKey: 'e2-mat-imp',
    run: { origin: 'company_import', statementDate: '2026-10-15', sourceFolder: 'company-workspaces/acme/2026-10-15/runs/2026-10-15', emitMode: 'coherence' },
    inputVersion: { reason: 'e2 materialize_emit test' },
    inputEntries: [{ relPath: 'mat_in.csv', fileSha256: inpFile.sha256 }],
    stepAttempts: [{
      step: 'emit',
      attemptNo: 1,
      artifacts: [{ relPath: stmtArt.relPath, artifactKind: stmtArt.artifactKind, storeKind: stmtArt.storeKind, fileSha256: stmtArt.sha256 }],
    }],
    storedFiles: [inpFile, stmtArt],
  });
  const emitEvId = (await env.pool.query("SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev", [imp.result.runId])).rows[0].ev;
  await env.commands.materializeEmit({
    dbToken: env.workerToken,
    commandKey: 'e2-standalone-mat',
    runId: imp.result.runId,
    attemptEventId: emitEvId,
    statementDate: '2026-10-15',
    canonicalBobCsv: csvs.canonicalBobCsv,
    coherentLedgerCsv: csvs.coherentLedgerCsv,
    statementsCsv: csvs.statementsCsv,
  });
  await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'e2-mat-carry-sent', runId: imp.result.runId, typedPhrase: 'sent 2026-10-15' });

  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const phiNoFinTok = env.iam.tokenFor(journalPhiNoFinId, null, { keyScope: 'company_local' });
  const emFullTok = env.iam.tokenFor(emFullJournalId, null, { keyScope: 'company_local' });

  // Owner & full entity-finance reader see non-null materialize_emit body with ledger totals.
  for (const [label, tok] of [['owner', env.ownerToken], ['emFullJournal', emFullTok]]) {
    const rows = await withRequestTx(appPool, tok, (tx) => (
      tx.query("SELECT command_kind, body FROM app_views.coherence_journal WHERE command_kind IN ('materialize_emit', 'carry_sent') ORDER BY seq")
    ), { readOnly: true });
    const matRow = rows.rows.find((r) => r.command_kind === 'materialize_emit');
    assert.ok(matRow && matRow.body !== null, `${label} must see non-null materialize_emit journal body`);
    assert.equal(matRow.body.result.ledgerGrossTotal, '100.00', `${label} must see ledgerGrossTotal in materialize_emit body`);
    assert.equal(matRow.body.result.ledgerDownlineTotal, '80.00');
    assert.equal(matRow.body.result.ledgerUplineTotal, '20.00');
  }

  // Reader with member_phi but WITHOUT full entity finance gets NULL on materialize_emit (and carry_sent), non-null on others.
  const noFinRows = await withRequestTx(appPool, phiNoFinTok, (tx) => (
    tx.query('SELECT command_kind, body FROM app_views.coherence_journal ORDER BY seq')
  ), { readOnly: true });
  const matNoFin = noFinRows.rows.filter((r) => r.command_kind === 'materialize_emit');
  const sentNoFin = noFinRows.rows.filter((r) => r.command_kind === 'carry_sent');
  const otherNoFin = noFinRows.rows.filter((r) => !['materialize_emit', 'carry_sent'].includes(r.command_kind));
  assert.equal(matNoFin.length, 1, 'materialize_emit journal entry must exist');
  assert.equal(matNoFin[0].body, null, 'materialize_emit journal body must be NULL without full entity finance rights');
  assert.ok(sentNoFin.length >= 1 && sentNoFin.every((r) => r.body === null), 'carry_sent journal body must remain NULL without full entity finance rights');
  assert.ok(otherNoFin.length > 0 && otherNoFin.every((r) => r.body !== null), 'non-finance journal entries stay visible with member_phi');

  // EXPLAIN InitPlan check: coherence_journal evaluates scopes CTE / _read_* helpers once (Actual Loops <= 1).
  const planJson = await withRequestTx(appPool, phiNoFinTok, (tx) => (
    tx.query('EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT * FROM app_views.coherence_journal')
  ), { readOnly: true });
  const planStr = JSON.stringify(planJson.rows[0]['QUERY PLAN'][0]);
  assert.ok(planStr.includes('scopes'), 'coherence_journal plan must materialize scopes CTE once');
  const walkLoops = (node) => {
    const sub = node['Subplan Name'] || '';
    if (sub === 'CTE scopes') {
      assert.equal(Number(node['Actual Loops']), 1, 'CTE scopes must execute exactly once per statement');
    }
    for (const child of node.Plans || []) walkLoops(child);
  };
  walkLoops(planJson.rows[0]['QUERY PLAN'][0].Plan);

  // Live catalog audit passes including E2 roles, tables, and triggers, and fails non-vacuously on E2 privilege mutations.
  const audit = await withClusterCatalogLock(() => verifyIamConfigInvariants(env.pool));
  assert.equal(audit.passed, true, `verifyIamConfigInvariants failed:\n${audit.problems.join('\n')}`);

  const skOwner = (await env.pool.query(
    "SELECT pg_catalog.quote_ident(pg_catalog.pg_get_userbyid(c.relowner)) AS o FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'iam_secret' AND c.relname = 'signing_keys'",
  )).rows[0].o;

  for (const [label, grantSql, revokeSql, expectedRe] of [
    [
      'platform_auth_lookup SELECT on iam.person_auth_identities',
      'GRANT SELECT ON iam.person_auth_identities TO platform_auth_lookup',
      'REVOKE SELECT ON iam.person_auth_identities FROM platform_auth_lookup',
      /platform_auth_lookup.*person_auth_identities/i,
    ],
    [
      'platform_app EXECUTE on iam.resolve_auth_identity',
      'GRANT EXECUTE ON FUNCTION iam.resolve_auth_identity(TEXT, TEXT) TO platform_app',
      'REVOKE EXECUTE ON FUNCTION iam.resolve_auth_identity(TEXT, TEXT) FROM platform_app',
      /resolve_auth_identity/i,
    ],
    [
      'platform_iam_sync INSERT on iam.agent_affiliations',
      'GRANT INSERT ON iam.agent_affiliations TO platform_iam_sync',
      'REVOKE INSERT ON iam.agent_affiliations FROM platform_iam_sync',
      /platform_iam_sync.*agent_affiliations/i,
    ],
    [
      'platform_worker SELECT on iam.person_auth_identities',
      'GRANT SELECT ON iam.person_auth_identities TO platform_worker',
      'REVOKE SELECT ON iam.person_auth_identities FROM platform_worker',
      /platform_worker.*person_auth_identities/i,
    ],
    [
      'platform_worker column-level SELECT on iam.person_auth_identities',
      'GRANT SELECT (auth_subject) ON iam.person_auth_identities TO platform_worker',
      'REVOKE SELECT (auth_subject) ON iam.person_auth_identities FROM platform_worker',
      /platform_worker.*column-level.*person_auth_identities/i,
    ],
    [
      'platform_iam_sync column-level SELECT on iam.person_auth_identities',
      'GRANT SELECT (auth_subject) ON iam.person_auth_identities TO platform_iam_sync',
      'REVOKE SELECT (auth_subject) ON iam.person_auth_identities FROM platform_iam_sync',
      /platform_iam_sync.*column-level.*person_auth_identities/i,
    ],
    [
      'platform_iam_sync column-level INSERT on iam.agent_affiliations',
      'GRANT INSERT (npn) ON iam.agent_affiliations TO platform_iam_sync',
      'REVOKE INSERT (npn) ON iam.agent_affiliations FROM platform_iam_sync',
      /platform_iam_sync.*column-level.*agent_affiliations/i,
    ],
    [
      'platform_iam_sync SELECT on coherence.bob_policies',
      'GRANT SELECT ON coherence.bob_policies TO platform_iam_sync',
      'REVOKE SELECT ON coherence.bob_policies FROM platform_iam_sync',
      /platform_iam_sync.*bob_policies/i,
    ],
    [
      'platform_iam_sync SELECT on app_views.coherence_bob',
      'GRANT SELECT ON app_views.coherence_bob TO platform_iam_sync',
      'REVOKE SELECT ON app_views.coherence_bob FROM platform_iam_sync',
      /platform_iam_sync.*coherence_bob/i,
    ],
    [
      'platform_iam_sync UPDATE on iam.people',
      'GRANT UPDATE ON iam.people TO platform_iam_sync',
      'REVOKE UPDATE ON iam.people FROM platform_iam_sync',
      /platform_iam_sync.*iam\.people/i,
    ],
    [
      'platform_iam_sync DELETE on iam_secret.signing_keys',
      'GRANT DELETE ON iam_secret.signing_keys TO platform_iam_sync',
      'REVOKE DELETE ON iam_secret.signing_keys FROM platform_iam_sync',
      /platform_iam_sync.*signing_keys/i,
    ],
    [
      'disable E2 origin guard trigger on iam.people',
      'ALTER TABLE iam.people DISABLE TRIGGER trg_00b_verify_origin',
      'ALTER TABLE iam.people ENABLE TRIGGER trg_00b_verify_origin',
      /trg_00b_verify_origin.*iam\.people|iam\.people.*trg_00b_verify_origin/i,
    ],
    [
      'disable E2 signing_keys guard trigger',
      'ALTER TABLE iam_secret.signing_keys DISABLE TRIGGER trg_00_verify_signing_key_sync',
      'ALTER TABLE iam_secret.signing_keys ENABLE TRIGGER trg_00_verify_signing_key_sync',
      /trg_00_verify_signing_key_sync/i,
    ],
    [
      'disable E2 role_grants guard trigger',
      'ALTER TABLE iam.role_grants DISABLE TRIGGER trg_role_grants_verify_scope',
      'ALTER TABLE iam.role_grants ENABLE TRIGGER trg_role_grants_verify_scope',
      /trg_role_grants_verify_scope/i,
    ],
    ['disable RLS on iam_secret.signing_keys', 'ALTER TABLE iam_secret.signing_keys DISABLE ROW LEVEL SECURITY', 'ALTER TABLE iam_secret.signing_keys ENABLE ROW LEVEL SECURITY', /iam_secret\.signing_keys.*ROW LEVEL SECURITY/i],
    ['force RLS on iam_secret.signing_keys', 'ALTER TABLE iam_secret.signing_keys FORCE ROW LEVEL SECURITY', 'ALTER TABLE iam_secret.signing_keys NO FORCE ROW LEVEL SECURITY', /iam_secret\.signing_keys.*FORCE ROW LEVEL SECURITY/i],
    ['iam.session_context() owner mismatch', 'ALTER FUNCTION iam.session_context() OWNER TO platform_migrator', `ALTER FUNCTION iam.session_context() OWNER TO ${skOwner}`, /session_context.*owner.*signing_keys/i],
    ['iam_secret.signing_keys owned by platform_iam_sync', 'ALTER TABLE iam_secret.signing_keys OWNER TO platform_iam_sync; ALTER FUNCTION iam.session_context() OWNER TO platform_iam_sync', `ALTER TABLE iam_secret.signing_keys OWNER TO ${skOwner}; ALTER FUNCTION iam.session_context() OWNER TO ${skOwner}`, /signing_keys.*platform_iam_sync/i],
    ['unexpected platform_migrator policy on iam_secret.signing_keys', 'CREATE POLICY signing_keys_mig_bad ON iam_secret.signing_keys FOR ALL TO platform_migrator USING (true)', 'DROP POLICY signing_keys_mig_bad ON iam_secret.signing_keys', /signing_keys_mig_bad.*platform_migrator/i],
    ['platform_writer SELECT on iam_secret.signing_keys', 'GRANT SELECT ON iam_secret.signing_keys TO platform_writer', 'REVOKE SELECT ON iam_secret.signing_keys FROM platform_writer', /platform_writer.*iam_secret\.signing_keys/i],
    ['platform_readonly column SELECT on iam_secret.signing_keys', 'GRANT SELECT (secret_bytes) ON iam_secret.signing_keys TO platform_readonly', 'REVOKE SELECT (secret_bytes) ON iam_secret.signing_keys FROM platform_readonly', /platform_readonly.*iam_secret\.signing_keys/i],
    ['widen platform_iam_sync SELECT policy on iam_secret.signing_keys', 'CREATE POLICY signing_keys_sync_bad_wide ON iam_secret.signing_keys FOR SELECT TO platform_iam_sync USING (true)', 'DROP POLICY signing_keys_sync_bad_wide ON iam_secret.signing_keys', /signing_keys_sync_bad_wide.*iam_secret\.signing_keys/i],
  ]) {
    await env.pool.query(grantSql);
    try {
      const bad = await verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, `catalog audit must fail when ${label}`);
      assert.ok(bad.problems.some((p) => expectedRe.test(p)), `expected audit problem matching ${expectedRe} for ${label}, got: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query(revokeSql);
    }
  }
});
