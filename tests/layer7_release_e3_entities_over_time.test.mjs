// Layer 7F: Release E3 - Entities over time:
// 1. Agency move to an external_upline keeps runoff Emit reconciling to $0.00 and agency-manager reads working while the external upline sees nothing.
// 2. Dated works-for lines replace capacity with work_arrangement + nullable tax_classification and refuse overlapping active lines.
// 3. lead_vendor organizations require a non-blank masked_display_name per company database.
// 4. verifyIamConfigInvariants audits platform_iam_sync's 5 SECURITY INVOKER function-EXECUTE whitelist, zero function ownership, and trg_00b_verify_org_version.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import * as policyChecks from '../src/config/policy-checks.mjs';
import { withRequestTx } from '../src/db/pg-client.mjs';
import {
  makeCsvFromObjects,
  seedStandingInput,
  SYNTHETIC_BOB_COLUMNS,
  SYNTHETIC_LEDGER_COLUMNS,
  SYNTHETIC_RUN_COLUMNS,
} from './helpers/fixtures.mjs';
import {
  appendIamAuditEntry,
  createRoleScopedTestPool,
} from './helpers/iam-harness.mjs';
import {
  checkPgAvailable,
  createTestEnv,
  withClusterCatalogLock,
} from './helpers/test-db.mjs';

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

function makeMultiEntityRunCsvs({ rowsSpec, statementDate }) {
  const bobRows = [];
  const ledgerRows = [];
  const stmtRows = [];

  rowsSpec.forEach((spec, idx) => {
    const num = String(701 + idx);
    const gross = spec.grossComm ?? '100.00';
    const downline = spec.amount ?? '80.00';
    const upline = spec.uplineAmount ?? '20.00';
    const mbi = `1E3${idx}-CD3-EF4${idx}`;
    const member = `Member E3-${idx}`;
    const recId = `carrier_a|direct|NM:member,e3_${idx}|${gross}|${statementDate.slice(0, 7)}`;

    bobRows.push({
      policy_id: num,
      carrier_policy_number: `POL-E3-${num}`,
      crm_policy_number: `CRM-E3-${num}`,
      enrollment_code: `EC-E3-${num}`,
      carrier: 'carrier_a',
      plan_type: 'MA',
      plan_name: `Plan E3 ${num}`,
      simple_plan_type: 'MA',
      mbi,
      member,
      dob: '1954-05-10',
      phone: `555-019-700${idx}`,
      email: `member.e3.${idx}@member.example`,
      address: `${num} Oak Ln`,
      county: 'Orange',
      state: 'FL',
      submission_date: '2026-01-15',
      origin_effective: '2026-02-01',
      effective_date: '2026-02-01',
      min_date: '2026-02-01',
      anchor_date: '2026-02-01',
      amount: downline,
      upline_amount: upline,
      writing_npn: spec.writingNpn,
      writing_agent: spec.writingAgent,
      entity: spec.entity,
      agency_id: `AG-E3-${idx}`,
      status: 'ACTIVE_PAYING',
      coherent_status: 'ACTIVE',
      conflicts: '',
      spine_source: 'TX',
      confidence_level: 100,
      coherent_trajectory: 'STEADY',
    });

    const ledgerRow = {
      tx_id: num,
      record_id: recId,
      external_policy_id: `POL-E3-${num}`,
      policy_id: num,
      statement_name: 'carrier_a.csv',
      src_type: 'direct',
      carrier: 'carrier_a',
      member,
      mbi,
      state: 'FL',
      plan_type: 'MA',
      simple_plan_type: 'MA',
      submission_date: '2026-01-15',
      origin_effective: '2026-02-01',
      effective_date: '2026-02-01',
      earned_date: '2026-02-01',
      payment_date: statementDate,
      statement_date: statementDate,
      min_date: '2026-01-15',
      gross_comm: gross,
      commission_amount: gross,
      revenue_type: 'commission',
      writing_npn: spec.writingNpn,
      writing_agent: spec.writingAgent,
      entity: spec.entity,
      agency_id: `AG-E3-${idx}`,
      status: 'ACTIVE_PAYING',
      policy_status: 'active',
      notes: 'e3 ledger note',
      coherent_notes: 'NEW',
      downline_amount: downline,
      upline_amount: upline,
    };
    ledgerRows.push(ledgerRow);
    stmtRows.push({
      ...ledgerRow,
      run_action: 'NEW',
      run_statement_date: statementDate,
      reversal_of: '',
      reason: 'e3 stmt reason',
      notes: 'e3 stmt note',
    });
  });

  return {
    canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, bobRows),
    coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, ledgerRows),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, stmtRows),
  };
}

async function importAndMaterializeSentRun(env, { statementDate, keyPrefix, rowsSpec }) {
  const csvs = makeMultiEntityRunCsvs({ rowsSpec, statementDate });
  const inpFile = await env.dataStore.promoteBytes(
    Buffer.from(`k\n${keyPrefix}\n`, 'utf8'),
    { relPath: `${keyPrefix}_in.csv`, checksPassed: true },
  );
  const stmtArt = await env.stores.promoteArtifact(
    `emits/statements_${statementDate.replace(/-/g, '')}.csv`,
    Buffer.from(csvs.statementsCsv, 'utf8'),
    { checksPassed: true },
  );
  const imp = await env.commands.importHistoricalRun({
    dbToken: env.ownerToken,
    commandKey: `${keyPrefix}-imp`,
    run: {
      origin: 'company_import',
      statementDate,
      sourceFolder: `company-workspaces/acme/${statementDate}/runs/${statementDate}`,
      emitMode: 'coherence',
    },
    inputVersion: { reason: `e3 run ${keyPrefix}` },
    inputEntries: [{ relPath: `${keyPrefix}_in.csv`, fileSha256: inpFile.sha256 }],
    stepAttempts: [{
      step: 'emit',
      attemptNo: 1,
      artifacts: [{
        relPath: stmtArt.relPath,
        artifactKind: stmtArt.artifactKind,
        storeKind: stmtArt.storeKind,
        fileSha256: stmtArt.sha256,
      }],
    }],
    storedFiles: [inpFile, stmtArt],
  });
  const emitEvId = (await env.pool.query(
    "SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev",
    [imp.result.runId],
  )).rows[0].ev;
  await env.commands.materializeEmit({
    dbToken: env.workerToken,
    commandKey: `${keyPrefix}-mat`,
    runId: imp.result.runId,
    attemptEventId: emitEvId,
    statementDate,
    canonicalBobCsv: csvs.canonicalBobCsv,
    coherentLedgerCsv: csvs.coherentLedgerCsv,
    statementsCsv: csvs.statementsCsv,
  });
  await env.commands.carrySent({
    dbToken: env.ownerToken,
    commandKey: `${keyPrefix}-sent`,
    runId: imp.result.runId,
    typedPhrase: `sent ${statementDate}`,
  });
  return { runId: imp.result.runId, emitEvId };
}

test('Layer 7F [E3 Test 1]: agency move to an external_upline keeps runoff Emit reconciling to $0.00 and agency-manager reads working while the new upline sees nothing', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, environment } = env.iam;

  const movedAgencyOrg = randomUUID();
  const extUplineOrg = randomUUID();
  const postMoveTeamOrg = randomUUID();
  const detachedAgencyOrg = randomUUID();

  const movedAgencyMgr = randomUUID();
  const movedAgent = randomUUID();
  const extUplineMgr = randomUUID();
  const extMemberMovedGrant = randomUUID();
  const postMoveTeamMgr = randomUUID();

  // 1. Seed the moving agency under Acme, its agency manager, and its selling agent.
  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, {
      environment,
      targetOrgId: ids.companyOrg,
      commandKind: 'iam.e3_move_seed',
      commandKey: `e3-move-seed-${randomUUID()}`,
    })).seq;

    await c.query(
      "INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'agency',$3),($2,'agency',$3)",
      [movedAgencyOrg, detachedAgencyOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq)
       VALUES ($1,$2,'insure_agency','Insure Agency','active',$5),
              ($3,$4,'detached_agency','Detached Agency','active',$5)`,
      [randomUUID(), movedAgencyOrg, randomUUID(), detachedAgencyOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq)
       VALUES ($1,$2,$5,'[2024-01-01,)'::daterange,'active',$6),
              ($3,$4,$5,'[2024-01-01,2026-08-01)'::daterange,'active',$6)`,
      [randomUUID(), movedAgencyOrg, randomUUID(), detachedAgencyOrg, ids.companyOrg, seq],
    );

    await c.query(
      "INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','company_local',$3),($2,'human','company_local',$3)",
      [movedAgencyMgr, movedAgent, seq],
    );
    await c.query(
      `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, npn, status, journal_seq)
       VALUES ($1,$2,'company_local','Insure Agency Manager','Insure Agency Manager','mgr@insure.example',NULL,'active',$5),
              ($3,$4,'company_local','Insure Agent','Insure Agent','agent@insure.example','71717171','active',$5)`,
      [randomUUID(), movedAgencyMgr, randomUUID(), movedAgent, seq],
    );
    await c.query(
      `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, tax_classification, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,'employee','w2','[2024-01-01,)'::daterange,'active',$4)`,
      [randomUUID(), movedAgencyMgr, movedAgencyOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.agent_affiliations (id, person_id, npn, agency_org_id, split_bps, agent_file_name, valid_range, status, journal_seq)
       VALUES ($1,$2,'71717171',$3,8000,'Insure Agent','[2024-01-01,)'::daterange,'active',$4)`,
      [randomUUID(), movedAgent, movedAgencyOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$4,true,'org_subtree','[2024-01-01,)'::daterange,'active',$8),
              ($5,$6,$7,$4,false,'self','[2024-01-01,)'::daterange,'active',$8)`,
      [randomUUID(), movedAgencyMgr, ids.roleAgencyManager, movedAgencyOrg, randomUUID(), movedAgent, ids.roleSellingAgent, seq],
    );
  });

  // Seed standing input and a pre-move sent run (2026-07-15).
  await seedStandingInput(env, { commandKey: 'e3-move-standing' });
  const preMoveRun = await importAndMaterializeSentRun(env, {
    statementDate: '2026-07-15',
    keyPrefix: 'e3-pre-move',
    rowsSpec: [
      { entity: 'Insure Agency', writingNpn: '71717171', writingAgent: 'Insure Agent', grossComm: '100.00', amount: '80.00', uplineAmount: '20.00' },
      { entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller', grossComm: '200.00', amount: '160.00', uplineAmount: '40.00' },
    ],
  });

  const extSwitchOnId = randomUUID();

  // 2. Move the agency from Acme [2024-01-01, 2026-08-01) to an external_upline [2026-08-01, ).
  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, {
      environment,
      targetOrgId: ids.companyOrg,
      commandKind: 'iam.e3_move_to_external',
      commandKey: `e3-move-ext-${randomUUID()}`,
    })).seq;

    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'external_upline',$2)", [extUplineOrg, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'ext_upline','External Upline','active',$3)",
      [randomUUID(), extUplineOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), extUplineOrg, ids.rootOrg, seq],
    );

    const oldEdgeId = (await c.query(
      'SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND superseded_by_id IS NULL',
      [movedAgencyOrg],
    )).rows[0].id;
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'[2024-01-01,2026-08-01)'::daterange,'active',$4,$5)",
      [randomUUID(), movedAgencyOrg, ids.companyOrg, oldEdgeId, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2026-08-01,)'::daterange,'active',$4)",
      [randomUUID(), movedAgencyOrg, extUplineOrg, seq],
    );

    // Post-move team added under the moved agency AFTER the move date.
    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'team',$2)", [postMoveTeamOrg, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'post_move_team','Post Move Team','active',$3)",
      [randomUUID(), postMoveTeamOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2026-09-01,)'::daterange,'active',$4)",
      [randomUUID(), postMoveTeamOrg, movedAgencyOrg, seq],
    );

    // Seed external upline users and post-move team manager to prove zero visibility inside Acme DB.
    for (const [pid, name, email, memOrg, roleId, grantOrg] of [
      [extUplineMgr, 'External Upline Mgr', 'mgr@extupline.example', extUplineOrg, ids.roleEntityManager, extUplineOrg],
      [extMemberMovedGrant, 'External Member Moved Grant', 'extmem@extupline.example', extUplineOrg, ids.roleAgencyManager, movedAgencyOrg],
      [postMoveTeamMgr, 'Post Move Team Mgr', 'postteam@insure.example', postMoveTeamOrg, ids.roleAgencyManager, postMoveTeamOrg],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','company_local',$2)", [pid, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'company_local',$3,$3,$4,'active',$5)",
        [randomUUID(), pid, name, email, seq],
      );
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), pid, memOrg, seq],
      );
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), pid, roleId, grantOrg, seq],
      );
    }

    // Seed coherence switch 'on' on the external upline FIRST so zero-visibility checks are non-vacuous;
    // later we supersede it to 'off' and re-check both Acme and external upline visibility.
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','on','active',$3)",
      [extSwitchOnId, extUplineOrg, seq],
    );
  });

  // One parent per day: overlapping edge for the moved agency must fail 23P01.
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment, commandKey: `e3-overlap-edge-${randomUUID()}` })).seq;
      await c.query(
        "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2026-07-15,2026-09-01)'::daterange,'active',$4)",
        [randomUUID(), movedAgencyOrg, ids.northstarOrg, seq],
      );
    }),
    (err) => err?.code === '23P01',
    'overlapping parent edge on moved agency must fail 23P01 (one parent per day)',
  );

  // Closure verification: moved agency stays in Acme closure (and out of Acme live tree); detached active agency without live parent drops out.
  const acmeClosure = (await env.pool.query(
    'SELECT DISTINCT descendant_org_id FROM iam.v_organization_closure WHERE ancestor_org_id = $1::uuid',
    [ids.companyOrg],
  )).rows.map((r) => r.descendant_org_id);
  assert.ok(acmeClosure.includes(movedAgencyOrg), 'moved agency with external_upline live parent must stay in Acme closure');
  assert.ok(!acmeClosure.includes(extUplineOrg), 'external_upline must never enter Acme closure');
  assert.ok(!acmeClosure.includes(postMoveTeamOrg), 'post-move team under moved agency must never enter Acme closure');
  assert.ok(!acmeClosure.includes(detachedAgencyOrg), 'active agency with only an expired edge and no live parent drops from closure');

  const acmeLive = (await env.pool.query(
    'SELECT DISTINCT descendant_org_id FROM iam.v_organization_closure_live WHERE ancestor_org_id = $1::uuid',
    [ids.companyOrg],
  )).rows.map((r) => r.descendant_org_id);
  assert.ok(!acmeLive.includes(movedAgencyOrg), 'moved agency must not appear in Acme live closure');

  const extLive = (await env.pool.query(
    'SELECT DISTINCT descendant_org_id FROM iam.v_organization_closure_live WHERE ancestor_org_id = $1::uuid',
    [extUplineOrg],
  )).rows.map((r) => r.descendant_org_id);
  assert.ok(extLive.includes(movedAgencyOrg) && extLive.includes(postMoveTeamOrg), 'external_upline live closure must hold moved agency and post-move team');

  // 3. Post-move runoff Emit for the moved agency in Acme's DB succeeds and reconciles to $0.00.
  const runoffRun = await importAndMaterializeSentRun(env, {
    statementDate: '2026-11-15',
    keyPrefix: 'e3-runoff',
    rowsSpec: [
      { entity: 'Insure Agency', writingNpn: '71717171', writingAgent: 'Insure Agent', grossComm: '150.00', amount: '120.00', uplineAmount: '30.00' },
      { entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller', grossComm: '200.00', amount: '160.00', uplineAmount: '40.00' },
    ],
  });

  const runoffBob = (await env.pool.query(
    "SELECT organization_id, writing_person_id FROM coherence.bob_policies WHERE run_id = $1::uuid AND entity = 'Insure Agency'",
    [runoffRun.runId],
  )).rows;
  assert.equal(runoffBob.length, 1);
  assert.equal(runoffBob[0].organization_id, movedAgencyOrg);
  assert.equal(runoffBob[0].writing_person_id, movedAgent);

  // External upline and post-move team must be rejected as Coherence entities inside Acme's DB.
  for (const [label, badEntity] of [['external_upline', 'External Upline'], ['post_move_team', 'Post Move Team']]) {
    await assert.rejects(
      () => env.commands.recordStatementBatch({
        dbToken: env.ownerToken,
        commandKey: `e3-reject-${label}-${randomUUID()}`,
        batchKind: 'historical_sent',
        statementDate: '2026-11-15',
        reason: `reject ${label}`,
        agencyLines: [{
          entity: badEntity, writingNpn: null, writingAgent: null,
          recordId: `carrier_a~direct~BAD_${label}~10.00~2026-11`, sourceFile: 'bad.csv', sourceRowNo: 1,
          grossComm: '10.00', amount: '10.00',
        }],
        uplineLines: [],
      }),
      /UNMAPPED_ENTITY/i,
      `${label} must be refused as a Coherence entity in Acme DB`,
    );
  }

  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const movedMgrTok = env.iam.tokenFor(movedAgencyMgr);
  const viewAsMovedMgrTok = env.iam.tokenFor(ids.nusearOwner, movedAgencyMgr);

  const assertVisibilityInvariant = async (phase) => {
    // 4. Acme Entity Manager and Nusear Owner see $0.00 reconciliation across pre-move and runoff runs (and keep workshop access).
    for (const [label, tok] of [['entityMgr', env.iam.tokens.entityMgr], ['nusearOwner', env.ownerToken]]) {
      await withRequestTx(appPool, tok, async (tx) => {
        for (const runId of [preMoveRun.runId, runoffRun.runId]) {
          const recon = (await tx.query(
            'SELECT statement_entity, variance, reconciled FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid',
            [runId],
          )).rows;
          assert.ok(recon.some((r) => r.statement_entity === 'Insure Agency'), `[${phase}] ${label} must see Insure Agency in reconciliation`);
          assert.ok(recon.every((r) => r.reconciled === true && r.variance === '0.00'), `[${phase}] ${label} reconciliation must tie to $0.00`);
        }
        const runCnt = (await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_runs')).rows[0].n;
        assert.ok(runCnt >= 2, `[${phase}] ${label} must retain workshop run visibility after agency move`);
      }, { readOnly: true });
    }

    // 5. Moved agency's manager (direct and View-as) reads Insure Agency BoB and both pre-move & runoff statements, and zero other agencies.
    for (const [label, tok] of [['movedAgencyMgr', movedMgrTok], ['View-as movedAgencyMgr', viewAsMovedMgrTok]]) {
      await withRequestTx(appPool, tok, async (tx) => {
        const bob = (await tx.query('SELECT entity, amount FROM app_views.v_current_policy_periods ORDER BY entity')).rows;
        assert.deepEqual(bob, [{ entity: 'Insure Agency', amount: '120.00' }], `[${phase}] ${label} must see Insure Agency runoff BoB only`);
        const stmts = (await tx.query(
          'SELECT statement_date::text AS d, entity, amount FROM app_views.coherence_statement_agency_lines ORDER BY statement_date',
        )).rows;
        assert.deepEqual(stmts, [
          { d: '2026-07-15', entity: 'Insure Agency', amount: '80.00' },
          { d: '2026-11-15', entity: 'Insure Agency', amount: '120.00' },
        ], `[${phase}] ${label} must see both pre-move and post-move runoff statements for Insure Agency only`);
        assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_upline_lines')).rows[0].n, 0);
        assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger')).rows[0].n, 0);
      }, { readOnly: true });
    }

    // Selling agent at moved agency still reads own runoff policy with NULL dollar columns.
    await withRequestTx(appPool, env.iam.tokenFor(movedAgent), async (tx) => {
      const bob = (await tx.query('SELECT entity, writing_npn, amount, upline_amount FROM app_views.v_current_policy_periods')).rows;
      assert.deepEqual(bob, [{ entity: 'Insure Agency', writing_npn: '71717171', amount: null, upline_amount: null }]);
    }, { readOnly: true });

    // 6. New external upline (and post-move team) see ZERO rows anywhere inside Acme's DB.
    for (const [label, tok] of [
      ['extUplineMgr', env.iam.tokenFor(extUplineMgr)],
      ['View-as extUplineMgr', env.iam.tokenFor(ids.nusearOwner, extUplineMgr)],
      ['extMemberMovedGrant', env.iam.tokenFor(extMemberMovedGrant)],
      ['View-as extMemberMovedGrant', env.iam.tokenFor(ids.nusearOwner, extMemberMovedGrant)],
      ['postMoveTeamMgr', env.iam.tokenFor(postMoveTeamMgr)],
    ]) {
      await withRequestTx(appPool, tok, async (tx) => {
        assert.deepEqual((await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `[${phase}] ${label} must have 0 wide orgs`);
        assert.deepEqual((await tx.query("SELECT iam.effective_any_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `[${phase}] ${label} must have 0 any orgs`);
        for (const viewName of [
          'coherence_bob',
          'v_current_policy_periods',
          'coherence_statement_agency_lines',
          'coherence_statement_upline_lines',
          'coherence_entity_statement_lines',
          'coherence_ledger',
          'coherence_published_runs',
          'coherence_runs',
        ]) {
          const n = (await tx.query(`SELECT COUNT(*)::int AS n FROM app_views.${viewName}`)).rows[0].n;
          assert.equal(n, 0, `[${phase}] ${label} must see 0 rows in app_views.${viewName}`);
        }
      }, { readOnly: true });
    }
  };

  // Phase A: external upline coherence switch is 'on' (proves zero visibility comes from tenant bounding, not a switched-off tool).
  await assertVisibilityInvariant('ext_upline switch=on');

  // Phase B: supersede external upline coherence switch to 'off' and re-check both Acme's reads and external upline's zero visibility.
  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, {
      environment,
      targetOrgId: extUplineOrg,
      commandKind: 'iam.e3_ext_switch_off',
      commandKey: `e3-ext-switch-off-${randomUUID()}`,
    })).seq;
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq) VALUES ($1,$2,'coherence','off','active',$3,$4)",
      [randomUUID(), extUplineOrg, extSwitchOnId, seq],
    );
  });
  await assertVisibilityInvariant('ext_upline switch=off');
});

test('Layer 7F [E3 Test 2]: dated works-for lines carry nullable work_arrangement (no employee default) and tax_classification, satisfy governing membership, and refuse overlapping active lines', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, environment } = env.iam;

  // Verify capacity column is removed and work_arrangement (nullable, no default) + tax_classification exist on iam.organization_memberships.
  const colRows = (await env.pool.query(
    `SELECT column_name, is_nullable, column_default
     FROM information_schema.columns
     WHERE table_schema = 'iam' AND table_name = 'organization_memberships'
     ORDER BY ordinal_position`,
  )).rows;
  const cols = colRows.map((r) => r.column_name);
  const waCol = colRows.find((r) => r.column_name === 'work_arrangement');
  assert.ok(!cols.includes('capacity'), 'iam.organization_memberships must no longer have capacity column');
  assert.ok(waCol, 'iam.organization_memberships must have work_arrangement column');
  assert.equal(waCol.is_nullable, 'YES', 'iam.organization_memberships.work_arrangement must be nullable (service principals and passive investors store NULL)');
  assert.equal(waCol.column_default, null, 'iam.organization_memberships.work_arrangement must have no default');
  assert.ok(cols.includes('tax_classification'), 'iam.organization_memberships must have tax_classification column');

  const viewCols = (await env.pool.query(
    `SELECT column_name
     FROM information_schema.columns
     WHERE table_schema = 'iam' AND table_name = 'v_all_memberships_live'`,
  )).rows.map((r) => r.column_name);
  assert.ok(!viewCols.includes('capacity'), 'iam.v_all_memberships_live must not project removed capacity column');

  const empPerson = randomUUID();
  const selfIntPerson = randomUUID();
  const selfExtPerson = randomUUID();
  const omittedArrangementPerson = randomUUID();
  const passiveInvestorPerson = randomUUID();
  const selfExtMemId = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, {
      environment,
      targetOrgId: ids.companyOrg,
      commandKind: 'iam.e3_works_for_seed',
      commandKey: `e3-wf-seed-${randomUUID()}`,
    })).seq;

    for (const [pid, name, email] of [
      [empPerson, 'Employee Worker', 'emp.wf@acme.example'],
      [selfIntPerson, 'Self Internal Worker', 'self.int@acme.example'],
      [selfExtPerson, 'Self External Worker', 'self.ext@acme.example'],
      [omittedArrangementPerson, 'Omitted Arrangement Member', 'omitted.wf@acme.example'],
      [passiveInvestorPerson, 'Passive Investor Member', 'passive.inv@acme.example'],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','company_local',$2)", [pid, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'company_local',$3,$3,$4,'active',$5)",
        [randomUUID(), pid, name, email, seq],
      );
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), pid, ids.roleAgencyManager, ids.beaconOrg, seq],
      );
    }

    // Insert all three work arrangements + omitted work_arrangement (stores NULL) + explicit NULL (passive investor / service principal).
    await c.query(
      `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, tax_classification, valid_range, status, journal_seq)
       VALUES ($1,$2,$7,'employee','w2','[2020-01-01,)'::daterange,'active',$8),
              ($3,$4,$7,'self_employed_internal','1099','[2020-01-01,)'::daterange,'active',$8),
              ($5,$6,$7,'self_employed_external',NULL,'[2020-01-01,)'::daterange,'active',$8)`,
      [randomUUID(), empPerson, randomUUID(), selfIntPerson, selfExtMemId, selfExtPerson, ids.beaconOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.organization_memberships (id, person_id, organization_id, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)`,
      [randomUUID(), omittedArrangementPerson, ids.beaconOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, tax_classification, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,NULL,NULL,'[2020-01-01,)'::daterange,'active',$4)`,
      [randomUUID(), passiveInvestorPerson, ids.beaconOrg, seq],
    );
  });

  // Verify omitted and explicit-NULL rows stored work_arrangement=NULL (never defaulted to 'employee'),
  // and harness service principal + investor memberships also store work_arrangement=NULL.
  for (const [label, pid] of [
    ['omitted arrangement', omittedArrangementPerson],
    ['explicit NULL passive investor', passiveInvestorPerson],
    ['harness workerService', ids.workerService],
    ['harness investor', ids.investor],
  ]) {
    const row = (await env.pool.query(
      'SELECT work_arrangement, tax_classification FROM iam.organization_memberships WHERE person_id = $1 AND superseded_by_id IS NULL',
      [pid],
    )).rows[0];
    assert.deepEqual(row, { work_arrangement: null, tax_classification: null }, `${label} must store work_arrangement=NULL`);
  }

  // All three arrangements AND NULL work_arrangement satisfy governing membership identically in iam.person_effective_grants().
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  for (const [label, pid] of [
    ['employee', empPerson],
    ['self_employed_internal', selfIntPerson],
    ['self_employed_external', selfExtPerson],
    ['omitted (NULL)', omittedArrangementPerson],
    ['explicit NULL', passiveInvestorPerson],
  ]) {
    await withRequestTx(appPool, env.iam.tokenFor(pid), async (tx) => {
      const orgs = (await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
      assert.ok(orgs.includes(ids.beaconOrg), `${label} works-for line must satisfy governing membership`);
    }, { readOnly: true });
  }

  // Invalid non-NULL work_arrangement and invalid tax_classification must still fail 23514.
  for (const [label, arr, tax, expectedCode] of [
    ['legacy capacity owner', 'owner', null, '23514'],
    ['legacy capacity consultant', 'consultant', '1099', '23514'],
    ['legacy capacity investor', 'investor', null, '23514'],
    ['blank work_arrangement', '', null, '23514'],
    ['invalid tax_classification', 'employee', 'w9', '23514'],
  ]) {
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment, commandKey: `e3-bad-wf-${randomUUID()}` })).seq;
        await c.query(
          `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, tax_classification, valid_range, status, journal_seq)
           VALUES ($1,$2,$3,$4,$5,'[2020-01-01,)'::daterange,'active',$6)`,
          [randomUUID(), empPerson, ids.harborOrg, arr, tax, seq],
        );
      }),
      (err) => err?.code === expectedCode,
      `${label} must fail with ${expectedCode}`,
    );
  }

  // Overlapping active lines for the same (person_id, organization_id) must fail 23P01,
  // even when work_arrangement and tax_classification differ!
  for (const [label, arr, tax, range] of [
    ['same arrangement overlapping', 'employee', 'w2', '[2025-01-01,)'],
    ['different arrangement and tax overlapping', 'self_employed_internal', '1099', '[2024-06-01,2025-06-01)'],
    ['self_employed_external overlapping employee', 'self_employed_external', null, '[2026-01-01,2026-12-31)'],
  ]) {
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment, commandKey: `e3-ovl-wf-${randomUUID()}` })).seq;
        await c.query(
          `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, tax_classification, valid_range, status, journal_seq)
           VALUES ($1,$2,$3,$4,$5,$6::daterange,'active',$7)`,
          [randomUUID(), empPerson, ids.beaconOrg, arr, tax, range, seq],
        );
      }),
      (err) => err?.code === '23P01',
      `overlapping active works-for line (${label}) must fail 23P01`,
    );
  }

  // Allowed transitions: (a) superseding active line via replaces_id, (b) adjacent non-overlapping ranges on same org,
  // (c) overlapping line at a different org, and (d) revoked line overlapping an active line.
  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment, commandKey: `e3-wf-valid-${randomUUID()}` })).seq;

    // (a) Supersede selfExtPerson's active line to set tax_classification = '1099' and close on 2025-01-01.
    await c.query(
      `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, tax_classification, valid_range, status, replaces_id, journal_seq)
       VALUES ($1,$2,$3,'self_employed_external','1099','[2020-01-01,2025-01-01)'::daterange,'active',$4,$5)`,
      [randomUUID(), selfExtPerson, ids.beaconOrg, selfExtMemId, seq],
    );
    // (b) Adjacent non-overlapping line transitioning selfExtPerson to employee / w2 starting 2025-01-01.
    await c.query(
      `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, tax_classification, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,'employee','w2','[2025-01-01,)'::daterange,'active',$4)`,
      [randomUUID(), selfExtPerson, ids.beaconOrg, seq],
    );
    // (c) Same person working at a different organization on overlapping dates.
    await c.query(
      `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, tax_classification, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,'self_employed_internal','1099','[2020-01-01,)'::daterange,'active',$4)`,
      [randomUUID(), empPerson, ids.harborOrg, seq],
    );
    // (d) Revoked line overlapping an active line is allowed.
    await c.query(
      `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, tax_classification, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,'self_employed_external','1099','[2024-01-01,2025-01-01)'::daterange,'revoked',$4)`,
      [randomUUID(), empPerson, ids.beaconOrg, seq],
    );
  });
});

test('Layer 7F [E3 Test 3]: lead_vendor organization requires non-blank masked_display_name per company database', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const envA = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => envA.cleanup());
  const envB = await createTestEnv({ companySlug: 'beta', displayName: 'Beta' });
  t.after(() => envB.cleanup());

  const sharedVendorOrgId = randomUUID();

  // 1. lead_vendor without masked_display_name (omitted, NULL, empty, or whitespace) must be refused with 23514.
  await assert.rejects(
    () => inSerializableTx(envA.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: `e3-lv-omit-${randomUUID()}` })).seq;
      const vid = randomUUID();
      await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'lead_vendor',$2)", [vid, seq]);
      await c.query(
        "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'omit_vendor','Omit Vendor','active',$3)",
        [randomUUID(), vid, seq],
      );
    }),
    (err) => err?.code === '23514',
    'lead_vendor omitting masked_display_name must fail 23514',
  );
  for (const [label, maskedVal] of [['NULL', null], ['empty string', ''], ['whitespace only', '   ']]) {
    await assert.rejects(
      () => inSerializableTx(envA.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: `e3-lv-bad-${randomUUID()}` })).seq;
        const vid = randomUUID();
        await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'lead_vendor',$2)", [vid, seq]);
        await c.query(
          "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, masked_display_name, status, journal_seq) VALUES ($1,$2,'bad_vendor','Bad Vendor',$3,'active',$4)",
          [randomUUID(), vid, maskedVal, seq],
        );
      }),
      (err) => err?.code === '23514',
      `lead_vendor with ${label} masked_display_name must fail 23514`,
    );
  }

  // 2. lead_vendor WITH non-blank masked_display_name succeeds; two companies set independent masked names in their own DBs.
  const vendorVerA1 = randomUUID();
  await inSerializableTx(envA.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: `e3-lv-ok-a-${randomUUID()}` })).seq;
    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'lead_vendor',$2)", [sharedVendorOrgId, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, masked_display_name, status, journal_seq) VALUES ($1,$2,'north_leads','North Leads','Vendor 01','active',$3)",
      [vendorVerA1, sharedVendorOrgId, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), sharedVendorOrgId, envA.iam.ids.companyOrg, seq],
    );
  });
  await inSerializableTx(envB.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: envB.iam.environment, commandKey: `e3-lv-ok-b-${randomUUID()}` })).seq;
    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'lead_vendor',$2)", [sharedVendorOrgId, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, masked_display_name, status, journal_seq) VALUES ($1,$2,'north_leads','North Leads','Lead Source Beta','active',$3)",
      [randomUUID(), sharedVendorOrgId, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), sharedVendorOrgId, envB.iam.ids.companyOrg, seq],
    );
  });

  const maskA = (await envA.pool.query(
    'SELECT masked_display_name FROM iam.organization_versions WHERE organization_id = $1 AND superseded_by_id IS NULL',
    [sharedVendorOrgId],
  )).rows[0].masked_display_name;
  const maskB = (await envB.pool.query(
    'SELECT masked_display_name FROM iam.organization_versions WHERE organization_id = $1 AND superseded_by_id IS NULL',
    [sharedVendorOrgId],
  )).rows[0].masked_display_name;
  assert.equal(maskA, 'Vendor 01');
  assert.equal(maskB, 'Lead Source Beta');

  // 3. Superseding a lead_vendor version without masked_display_name fails (both active and archived).
  for (const nextStatus of ['active', 'archived']) {
    await assert.rejects(
      () => inSerializableTx(envA.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: `e3-lv-sup-bad-${nextStatus}-${randomUUID()}` })).seq;
        await c.query(
          "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, masked_display_name, status, replaces_id, journal_seq) VALUES ($1,$2,'north_leads','North Leads',NULL,$3,$4,$5)",
          [randomUUID(), sharedVendorOrgId, nextStatus, vendorVerA1, seq],
        );
      }),
      (err) => err?.code === '23514',
      `superseding lead_vendor with NULL masked_display_name (${nextStatus}) must fail 23514`,
    );
  }

  // Superseding with a new non-blank masked_display_name succeeds.
  await inSerializableTx(envA.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: `e3-lv-sup-ok-${randomUUID()}` })).seq;
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, masked_display_name, status, replaces_id, journal_seq) VALUES ($1,$2,'north_leads','North Leads','Vendor Alpha','active',$3,$4)",
      [randomUUID(), sharedVendorOrgId, vendorVerA1, seq],
    );
  });

  // 4. Non-lead_vendor org allows NULL masked_display_name but still rejects whitespace-only masked_display_name.
  await assert.rejects(
    () => inSerializableTx(envA.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: `e3-nonlv-blank-${randomUUID()}` })).seq;
      const oid = randomUUID();
      await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'agency',$2)", [oid, seq]);
      await c.query(
        "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, masked_display_name, status, journal_seq) VALUES ($1,$2,'blank_mask_ag','Blank Mask Ag','   ','active',$3)",
        [randomUUID(), oid, seq],
      );
    }),
    (err) => err?.code === '23514',
    'whitespace-only masked_display_name must be rejected on non-lead_vendor orgs too',
  );

  // 5. platform_iam_sync obeys the same rule (refused without masked_display_name, accepted with one).
  await assert.rejects(
    () => inSerializableTx(envA.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_iam_sync');
      const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: `e3-sync-lv-bad-${randomUUID()}` })).seq;
      const vid = randomUUID();
      await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'lead_vendor',$2)", [vid, seq]);
      await c.query(
        "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'sync_bad_lv','Sync Bad LV','active',$3)",
        [randomUUID(), vid, seq],
      );
    }),
    (err) => err?.code === '23514',
    'platform_iam_sync inserting lead_vendor without masked_display_name must fail 23514',
  );
  await inSerializableTx(envA.pool, async (c) => {
    await c.query('SET LOCAL ROLE platform_iam_sync');
    const seq = (await appendIamAuditEntry(c, { environment: envA.iam.environment, commandKey: `e3-sync-lv-ok-${randomUUID()}` })).seq;
    const vid = randomUUID();
    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'lead_vendor',$2)", [vid, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, masked_display_name, status, journal_seq) VALUES ($1,$2,'sync_ok_lv','Sync Ok LV','Vendor 02','active',$3)",
      [randomUUID(), vid, seq],
    );
  });

  // lead_vendor remains refused as a Coherence entity.
  await assert.rejects(
    () => envA.pool.query("SELECT coherence._resolve_entity_org_id('North Leads', 'bob_policies')"),
    /UNMAPPED_ENTITY/i,
  );
});

test('Layer 7F [E3 Test 4]: verifyIamConfigInvariants audits platform_iam_sync 5-function SECURITY INVOKER whitelist, zero function ownership, and trg_00b_verify_org_version', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const expectedSyncFns = [
    'platform.canonical_json(jsonb)',
    'platform.sha256_text(text)',
    'platform.format_utc_us(timestamp with time zone)',
    'platform.compute_journal_hash(bigint, timestamp with time zone, text, uuid, text, uuid, text, text, text, text, jsonb)',
    'iam.business_today(timestamp with time zone)',
  ];
  assert.ok(
    Array.isArray(policyChecks.PLATFORM_IAM_SYNC_FUNCTION_WHITELIST),
    'policy-checks.mjs must export PLATFORM_IAM_SYNC_FUNCTION_WHITELIST',
  );
  assert.deepEqual(
    [...policyChecks.PLATFORM_IAM_SYNC_FUNCTION_WHITELIST].sort(),
    [...expectedSyncFns].sort(),
    'PLATFORM_IAM_SYNC_FUNCTION_WHITELIST must list the exact 5 SECURITY INVOKER helpers',
  );

  const baseline = await withClusterCatalogLock(() => policyChecks.verifyIamConfigInvariants(env.pool));
  assert.equal(baseline.passed, true, `baseline verifyIamConfigInvariants failed:\n${baseline.problems.join('\n')}`);

  const btOwner = (await env.pool.query(
    `SELECT pg_catalog.quote_ident(pg_catalog.pg_get_userbyid(p.proowner)) AS o
     FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'iam' AND p.proname = 'business_today'`,
  )).rows[0].o;

  for (const [label, mutateSql, restoreSql, expectedRe] of [
    [
      'stray EXECUTE on iam.session_context() to platform_iam_sync',
      'GRANT EXECUTE ON FUNCTION iam.session_context() TO platform_iam_sync',
      'REVOKE EXECUTE ON FUNCTION iam.session_context() FROM platform_iam_sync',
      /platform_iam_sync.*session_context/i,
    ],
    [
      'stray EXECUTE on iam.has_right(TEXT, DATE) to platform_iam_sync',
      'GRANT EXECUTE ON FUNCTION iam.has_right(TEXT, DATE) TO platform_iam_sync',
      'REVOKE EXECUTE ON FUNCTION iam.has_right(TEXT, DATE) FROM platform_iam_sync',
      /platform_iam_sync.*has_right/i,
    ],
    [
      'stray EXECUTE on iam_secret.hmac_sha256_hex(BYTEA, TEXT) to platform_iam_sync',
      'GRANT EXECUTE ON FUNCTION iam_secret.hmac_sha256_hex(BYTEA, TEXT) TO platform_iam_sync',
      'REVOKE EXECUTE ON FUNCTION iam_secret.hmac_sha256_hex(BYTEA, TEXT) FROM platform_iam_sync',
      /platform_iam_sync.*hmac_sha256_hex/i,
    ],
    [
      'revoke whitelisted iam.business_today from platform_iam_sync',
      'REVOKE EXECUTE ON FUNCTION iam.business_today(TIMESTAMPTZ) FROM platform_iam_sync',
      'GRANT EXECUTE ON FUNCTION iam.business_today(TIMESTAMPTZ) TO platform_iam_sync',
      /platform_iam_sync.*missing EXECUTE.*business_today/i,
    ],
    [
      'change whitelisted platform_iam_sync helper to SECURITY DEFINER',
      'ALTER FUNCTION iam.business_today(TIMESTAMPTZ) SECURITY DEFINER',
      'ALTER FUNCTION iam.business_today(TIMESTAMPTZ) SECURITY INVOKER',
      /platform_iam_sync.*SECURITY INVOKER.*business_today|business_today.*SECURITY INVOKER/i,
    ],
    [
      'platform_iam_sync owns managed function iam.business_today',
      'ALTER FUNCTION iam.business_today(TIMESTAMPTZ) OWNER TO platform_iam_sync',
      `ALTER FUNCTION iam.business_today(TIMESTAMPTZ) OWNER TO ${btOwner}`,
      /platform_iam_sync.*own.*business_today/i,
    ],
    [
      'platform_iam_sync owns function in public schema',
      "CREATE FUNCTION public.e3_sync_owned_stray() RETURNS INT LANGUAGE sql SET search_path = pg_catalog AS 'SELECT 1'; ALTER FUNCTION public.e3_sync_owned_stray() OWNER TO platform_iam_sync",
      'DROP FUNCTION public.e3_sync_owned_stray()',
      /platform_iam_sync.*own.*e3_sync_owned_stray/i,
    ],
    [
      'disable trg_00b_verify_org_version on iam.organization_versions',
      'ALTER TABLE iam.organization_versions DISABLE TRIGGER trg_00b_verify_org_version',
      'ALTER TABLE iam.organization_versions ENABLE TRIGGER trg_00b_verify_org_version',
      /trg_00b_verify_org_version/i,
    ],
  ]) {
    await env.pool.query(mutateSql);
    try {
      const bad = await withClusterCatalogLock(() => policyChecks.verifyIamConfigInvariants(env.pool));
      assert.equal(bad.passed, false, `verifyIamConfigInvariants must fail when: ${label}`);
      assert.ok(
        bad.problems.some((p) => expectedRe.test(p)),
        `expected problem matching ${expectedRe} for ${label}, got: ${bad.problems.join('; ')}`,
      );
    } finally {
      await env.pool.query(restoreSql);
    }
  }
});
