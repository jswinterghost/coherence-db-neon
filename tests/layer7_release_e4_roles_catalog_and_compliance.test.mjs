// Layer 7G: Release E4 - The roles: one canonical catalog, agents' own pay & company-revenue guard,
// compliance per-NPN scoping (explicit_people), empty new role, empty investor role, EXPLAIN InitPlan,
// and live catalog audit.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import * as policyChecks from '../src/config/policy-checks.mjs';
import { withRequestTx } from '../src/db/pg-client.mjs';
import { sha256Hex } from '../src/util/crypto.mjs';
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
  createEmptyMigratedTestDb,
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

function makeE4RunCsvs({ statementDate, includeRetentionPolicy = false }) {
  const specs = [
    { policyId: '801', entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller', gross: '100.00', amount: '80.00', upline: '20.00' },
    { policyId: '802', entity: 'Beacon', writingNpn: '22222222', writingAgent: 'Sam Seller', gross: '200.00', amount: '160.00', upline: '40.00' },
    { policyId: '803', entity: 'East Team', writingNpn: '44444444', writingAgent: 'Jamie East', gross: '150.00', amount: '120.00', upline: '30.00' },
    { policyId: '804', entity: 'Harbor', writingNpn: '33333333', writingAgent: 'Robin Harbor', gross: '250.00', amount: '200.00', upline: '50.00' },
    ...(includeRetentionPolicy
      ? [{ policyId: '805', entity: 'Harbor', writingNpn: '31313131', writingAgent: 'Jordan Retain', gross: '125.00', amount: '100.00', upline: '25.00' }]
      : []),
  ];
  const bobRows = [];
  const ledgerRows = [];
  const stmtRows = [];

  specs.forEach((s, idx) => {
    const mbi = `4E4${idx}-CD3-EF4${idx}`;
    const member = `Member E4-${idx}`;
    const recId = `carrier_a|direct|NM:member,e4_${idx}|${s.gross}|${statementDate.slice(0, 7)}`;
    bobRows.push({
      policy_id: s.policyId,
      carrier_policy_number: `POL-E4-${s.policyId}`,
      crm_policy_number: `CRM-E4-${s.policyId}`,
      enrollment_code: `EC-E4-${s.policyId}`,
      carrier: 'carrier_a',
      plan_type: 'MA',
      plan_name: `Plan E4 ${s.policyId}`,
      simple_plan_type: 'MA',
      mbi,
      member,
      dob: '1956-04-12',
      phone: `555-014-800${idx}`,
      email: `member.e4.${idx}@member.example`,
      address: `${s.policyId} Pine Rd`,
      county: 'Orange',
      state: 'FL',
      submission_date: '2026-01-15',
      origin_effective: '2026-02-01',
      effective_date: '2026-02-01',
      min_date: '2026-02-01',
      anchor_date: '2026-02-01',
      amount: s.amount,
      upline_amount: s.upline,
      writing_npn: s.writingNpn,
      writing_agent: s.writingAgent,
      entity: s.entity,
      agency_id: `AG-E4-${idx}`,
      status: 'ACTIVE_PAYING',
      coherent_status: 'ACTIVE',
      conflicts: 'e4-conflict-note',
      spine_source: 'TX',
      confidence_level: 100,
      coherent_trajectory: 'STEADY',
    });
    const ledgerRow = {
      tx_id: s.policyId,
      record_id: recId,
      external_policy_id: `POL-E4-${s.policyId}`,
      policy_id: s.policyId,
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
      gross_comm: s.gross,
      commission_amount: s.gross,
      revenue_type: 'commission',
      writing_npn: s.writingNpn,
      writing_agent: s.writingAgent,
      entity: s.entity,
      agency_id: `AG-E4-${idx}`,
      status: 'ACTIVE_PAYING',
      policy_status: 'active',
      notes: 'e4 ledger note',
      coherent_notes: 'NEW',
      downline_amount: s.amount,
      upline_amount: s.upline,
    };
    ledgerRows.push(ledgerRow);
    stmtRows.push({
      ...ledgerRow,
      run_action: 'NEW',
      run_statement_date: statementDate,
      reversal_of: '',
      reason: 'e4 stmt reason',
      notes: 'e4 stmt note',
    });
  });

  return {
    canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, bobRows),
    coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, ledgerRows),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, stmtRows),
  };
}

async function seedSentE4Run(env, { statementDate = '2026-10-31', keyPrefix = 'e4-sent', includeRetentionPolicy = false } = {}) {
  await seedStandingInput(env, { commandKey: `${keyPrefix}-standing` });
  const csvs = makeE4RunCsvs({ statementDate, includeRetentionPolicy });
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
    inputVersion: { reason: `e4 run ${keyPrefix}` },
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

function collectPlanRefStrings(node, out = []) {
  for (const [k, v] of Object.entries(node)) {
    if (k === 'Plans' || k === 'Subplan Name') continue;
    if (typeof v === 'string') out.push(v);
    else if (Array.isArray(v)) {
      for (const item of v) if (typeof item === 'string') out.push(item);
    }
  }
  for (const child of node.Plans || []) collectPlanRefStrings(child, out);
  return out;
}

function inspectNarrowPlanNodes(planRoot) {
  const allRefStrings = collectPlanRefStrings(planRoot).join('\n');
  const perRowSubPlans = [];
  const highLoopNodes = [];
  const hashedOrInitPlans = [];

  const walk = (node, enclosingSubplan = null, enclosingRel = null) => {
    const ownSubplan = node['Subplan Name'] || enclosingSubplan;
    const ownRel = node['Subplan Name'] ? (node['Parent Relationship'] || enclosingRel) : enclosingRel;
    const isInit = ownRel === 'InitPlan' || Boolean(ownSubplan && (ownSubplan.startsWith('InitPlan ') || ownSubplan.startsWith('CTE ')));
    const nodeType = node['Node Type'] || '';
    const fnName = node['Function Name'] || '';
    const fnSchema = node.Schema || '';
    const isReadFn = nodeType === 'Function Scan' && (fnSchema === 'app_views' || fnSchema === 'iam')
      && (fnName.startsWith('_read_') || fnName.startsWith('effective_'));
    if (isReadFn) {
      const label = `${fnSchema}.${fnName}`;
      const loops = Number(node['Actual Loops'] ?? 0);
      if (loops > 1) highLoopNodes.push(`${label} (Actual Loops=${loops})`);
      if (isInit) {
        hashedOrInitPlans.push(`${ownSubplan}:${label}`);
      } else if (ownSubplan && ownSubplan.startsWith('SubPlan ')) {
        const spNum = ownSubplan.match(/^SubPlan (\d+)/)?.[1];
        const unhashedRe = new RegExp(`(?<!hashed )SubPlan ${spNum}\\b`);
        const hashedRe = new RegExp(`hashed SubPlan ${spNum}\\b`);
        if (spNum && hashedRe.test(allRefStrings) && !unhashedRe.test(allRefStrings)) {
          hashedOrInitPlans.push(`${ownSubplan}:${label}`);
        } else {
          perRowSubPlans.push(`${ownSubplan}:${label} (loops=${loops})`);
        }
      }
    }
    for (const child of node.Plans || []) walk(child, ownSubplan, ownRel);
  };
  walk(planRoot);
  return { perRowSubPlans, highLoopNodes, hashedOrInitPlans };
}

test('Layer 7G [E4 Test 1]: compliance user with explicit_people sees strictly permitted NPNs across BoB and statements (direct and View-as), zero money, revocation drops rows, and write/trigger guards hold', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, environment } = env.iam;

  await seedSentE4Run(env);

  const complianceRoleRow = (await env.pool.query(
    "SELECT id FROM iam.roles WHERE owner_org_id IS NULL AND slug = 'compliance'",
  )).rows[0];
  assert.ok(complianceRoleRow, 'canonical catalog must seed built-in compliance role');
  const complianceRoleId = complianceRoleRow.id;

  const complianceA = randomUUID();
  const complianceB = randomUUID();
  const complianceSibling = randomUUID();
  const harborMgr = randomUUID();
  const complianceAGrantId = randomUUID();
  const complianceBGrantId = randomUUID();
  const complianceSiblingGrantId = randomUUID();
  const complianceSiblingWriteGrantId = randomUUID();
  const rgpAgentAId = randomUUID();
  const rgpAgentEastId = randomUUID();
  const writeRoleId = randomUUID();
  const writeGrantId = randomUUID();
  const rgpWriteAgentAId = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, {
      environment,
      targetOrgId: ids.beaconOrg,
      commandKind: 'iam.e4_compliance_seed',
      commandKey: `e4-comp-seed-${randomUUID()}`,
    })).seq;

    for (const [pid, name, email, memOrg] of [
      [complianceA, 'Blake Compliance', 'blake.comp@acme.example', ids.beaconOrg],
      [complianceB, 'Sage Compliance', 'sage.comp@acme.example', ids.beaconOrg],
      [complianceSibling, 'Reese SiblingComp', 'reese.comp@acme.example', ids.beaconOrg],
      [harborMgr, 'Rowan Harbor Mgr', 'rowan.hm@acme.example', ids.harborOrg],
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
    }

    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$4,true,'explicit_people','[2020-01-01,)'::daterange,'active',$12),
              ($5,$6,$3,$4,true,'explicit_people','[2020-01-01,)'::daterange,'active',$12),
              ($7,$8,$3,$4,true,'explicit_people','[2020-01-01,)'::daterange,'active',$12),
              ($9,$10,$11,$13,true,'org_subtree','[2020-01-01,)'::daterange,'active',$12)`,
      [
        complianceAGrantId, complianceA, complianceRoleId, ids.beaconOrg,
        complianceBGrantId, complianceB,
        complianceSiblingGrantId, complianceSibling,
        randomUUID(), harborMgr, ids.roleAgencyManager,
        seq, ids.harborOrg,
      ],
    );

    // Permit agentA and agentEast (child team under Beacon) for complianceA, agentB for complianceB,
    // and sibling-agency agentHarbor on complianceSibling's Beacon-anchored grant.
    await c.query(
      `INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, journal_seq)
       VALUES ($1,$2,$3,'active',$10),
              ($4,$2,$5,'active',$10),
              ($6,$7,$11,'active',$10),
              ($8,$9,$12,'active',$10)`,
      [
        rgpAgentAId, complianceAGrantId, ids.agentA,
        rgpAgentEastId, ids.agentEast,
        randomUUID(), complianceBGrantId,
        randomUUID(), complianceSiblingGrantId,
        seq, ids.agentB, ids.agentHarbor,
      ],
    );

    // Also test explicit_people on assert_can_write via a custom company role holding act:hr.records.write.
    await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'e4_explicit_writer',$2,$3)", [writeRoleId, ids.companyOrg, seq]);
    await c.query(
      "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,'Explicit Writer',false,false,false,'active',$3)",
      [randomUUID(), writeRoleId, seq],
    );
    await c.query(
      "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,'act:hr.records.write','active',$3)",
      [randomUUID(), writeRoleId, seq],
    );
    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$4,true,'explicit_people','[2020-01-01,)'::daterange,'active',$7),
              ($5,$6,$3,$4,true,'explicit_people','[2020-01-01,)'::daterange,'active',$7)`,
      [writeGrantId, complianceA, writeRoleId, ids.beaconOrg, complianceSiblingWriteGrantId, complianceSibling, seq],
    );
    await c.query(
      `INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, journal_seq)
       VALUES ($1,$2,$3,'active',$6),
              ($4,$5,$7,'active',$6)`,
      [rgpWriteAgentAId, writeGrantId, ids.agentA, randomUUID(), complianceSiblingWriteGrantId, seq, ids.agentHarbor],
    );
  });

  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const compATok = env.iam.tokenFor(complianceA);
  const ownerAsCompATok = env.iam.tokenFor(ids.nusearOwner, complianceA);
  const beaconMgrAsCompATok = env.iam.tokenFor(ids.beaconManager, complianceA);

  // 1. Direct Compliance A, Owner View-as Compliance A, Beacon Agency Manager View-as Compliance A,
  //    AND Compliance A Viewing as wider people (beaconManager, entityMgr):
  //    stays strictly inside agentA (Beacon) and agentEast (East Team), ZERO agentB, ZERO Harbor, ZERO dollars/upline/ledger/workshop.
  for (const [label, tok] of [
    ['complianceA direct', compATok],
    ['owner View-as complianceA', ownerAsCompATok],
    ['beaconMgr View-as complianceA', beaconMgrAsCompATok],
    ['complianceA View-as beaconManager (wider)', env.iam.tokenFor(complianceA, ids.beaconManager)],
    ['complianceA View-as entityMgr (wider)', env.iam.tokenFor(complianceA, ids.entityMgr)],
  ]) {
    await withRequestTx(appPool, tok, async (tx) => {
      assert.deepEqual(
        (await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v,
        [],
        `${label} must have no wide org scope`,
      );
      const bob = (await tx.query(
        'SELECT entity, writing_npn, member, mbi, phone, amount, upline_amount FROM app_views.coherence_bob ORDER BY writing_npn',
      )).rows;
      assert.deepEqual(
        bob.map((r) => ({ entity: r.entity, writing_npn: r.writing_npn, amount: r.amount, upline_amount: r.upline_amount })),
        [
          { entity: 'Beacon', writing_npn: '11111111', amount: null, upline_amount: null },
          { entity: 'East Team', writing_npn: '44444444', amount: null, upline_amount: null },
        ],
        `${label} must see strictly agentA and agentEast with NULL money columns in coherence_bob`,
      );
      assert.ok(bob.every((r) => r.member !== null && r.mbi !== null && r.phone !== null), `${label} sees member details for permitted NPNs`);

      const curPol = (await tx.query('SELECT writing_npn, amount, upline_amount FROM app_views.v_current_policy_periods ORDER BY writing_npn')).rows;
      assert.deepEqual(curPol.map((r) => r.writing_npn), ['11111111', '44444444']);
      assert.ok(curPol.every((r) => r.amount === null && r.upline_amount === null));

      const stmts = (await tx.query(
        'SELECT entity, writing_npn, member, mbi, amount, gross_comm, record_id, tx_id FROM app_views.coherence_statement_agency_lines ORDER BY writing_npn',
      )).rows;
      assert.deepEqual(
        stmts.map((r) => ({ entity: r.entity, writing_npn: r.writing_npn, amount: r.amount, gross_comm: r.gross_comm, record_id: r.record_id, tx_id: r.tx_id })),
        [
          { entity: 'Beacon', writing_npn: '11111111', amount: null, gross_comm: null, record_id: null, tx_id: null },
          { entity: 'East Team', writing_npn: '44444444', amount: null, gross_comm: null, record_id: null, tx_id: null },
        ],
        `${label} must see strictly permitted NPNs with zero money in coherence_statement_agency_lines`,
      );
      assert.ok(stmts.every((r) => r.member !== null && r.mbi !== null));

      const totals = (await tx.query('SELECT statement_entity, line_count::int, net_amount FROM app_views.coherence_statement_totals ORDER BY statement_entity')).rows;
      assert.deepEqual(totals, [
        { statement_entity: 'Beacon', line_count: 1, net_amount: null },
        { statement_entity: 'East Team', line_count: 1, net_amount: null },
      ]);

      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_upline_lines')).rows[0].n, 0);
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger')).rows[0].n, 0);
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_runs')).rows[0].n, 0);
    }, { readOnly: true });
  }

  // 2. Disjoint View-as combinations with explicit_people:
  //    - Harbor Agency Manager viewing as Beacon Compliance A -> 0 rows!
  //    - Compliance A ({agentA, agentEast}) viewing as Agent A -> strictly agentA only!
  //    - Compliance A ({agentA, agentEast}) viewing as Agent B -> 0 rows, empty any_orgs, has_right=false!
  //    - Compliance A ({agentA, agentEast}) viewing as Compliance B ({agentB}) -> 0 rows, empty any_orgs, has_right=false!
  await withRequestTx(appPool, env.iam.tokenFor(complianceA, ids.agentA), async (tx) => {
    const bob = (await tx.query('SELECT writing_npn FROM app_views.coherence_bob')).rows;
    assert.deepEqual(bob.map((r) => r.writing_npn), ['11111111'], 'complianceA View-as agentA sees strictly agentA');
  }, { readOnly: true });

  for (const [label, tok] of [
    ['harborMgr View-as complianceA', env.iam.tokenFor(harborMgr, complianceA)],
    ['harborMgr View-as complianceSibling', env.iam.tokenFor(harborMgr, complianceSibling)],
    ['complianceA View-as agentB', env.iam.tokenFor(complianceA, ids.agentB)],
    ['complianceA View-as complianceB', env.iam.tokenFor(complianceA, complianceB)],
  ]) {
    await withRequestTx(appPool, tok, async (tx) => {
      assert.equal((await tx.query("SELECT iam.has_right('act:coherence.bob.read') AS ok")).rows[0].ok, false, `${label}: has_right must be false`);
      assert.deepEqual((await tx.query("SELECT iam.effective_any_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `${label}: effective_any_org_ids must be empty`);
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n, 0, `${label}: 0 BoB rows`);
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n, 0, `${label}: 0 statement rows`);
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_published_runs')).rows[0].n, 0, `${label}: 0 published runs`);
    }, { readOnly: true });
  }

  // 2b. Sibling agency's agent (agentHarbor, Harbor) attached to a Beacon-anchored explicit_people grant
  //     opens NOTHING in Harbor (positive control: harborMgr sees Harbor's 33333333 row).
  await withRequestTx(appPool, env.iam.tokenFor(harborMgr), async (tx) => {
    const harborBob = (await tx.query('SELECT writing_npn FROM app_views.coherence_bob')).rows;
    assert.deepEqual(harborBob.map((r) => r.writing_npn), ['33333333'], 'control: harborMgr sees agentHarbor in Harbor');
  }, { readOnly: true });
  const compSibTok = env.iam.tokenFor(complianceSibling);
  await withRequestTx(appPool, compSibTok, async (tx) => {
    const anyOrgs = (await tx.query("SELECT iam.effective_any_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
    assert.ok(!anyOrgs.includes(ids.harborOrg), 'Beacon explicit_people grant with agentHarbor must never include harborOrg');
    for (const viewName of ['coherence_bob', 'v_current_policy_periods', 'coherence_statement_agency_lines', 'coherence_statement_totals']) {
      assert.equal((await tx.query(`SELECT COUNT(*)::int AS n FROM app_views.${viewName}`)).rows[0].n, 0, `complianceSibling must see 0 rows in ${viewName}`);
    }
  }, { readOnly: true });
  await assert.rejects(
    () => withRequestTx(appPool, compSibTok, (tx) => tx.query(
      "SELECT * FROM iam.assert_can_write('act:hr.records.write', $1::uuid, $2::uuid)",
      [ids.harborOrg, ids.agentHarbor],
    ), { readOnly: false }),
    (err) => err?.code === '42501',
    'Beacon explicit_people write grant with agentHarbor attached must refuse write on sibling harborOrg',
  );

  // 3. assert_can_write with explicit_people: allows agentA, refuses agentB, refuses NULL, refuses View-as.
  await withRequestTx(appPool, compATok, async (tx) => {
    const wr = (await tx.query(
      "SELECT actor_person_id, recorded_as FROM iam.assert_can_write('act:hr.records.write', $1::uuid, $2::uuid)",
      [ids.beaconOrg, ids.agentA],
    )).rows[0];
    assert.deepEqual(wr, { actor_person_id: complianceA, recorded_as: 'self' });
  }, { readOnly: false });
  for (const [label, subj] of [['unpermitted agentB', ids.agentB], ['NULL subject', null]]) {
    await assert.rejects(
      () => withRequestTx(appPool, compATok, (tx) => tx.query(
        "SELECT * FROM iam.assert_can_write('act:hr.records.write', $1::uuid, $2::uuid)",
        [ids.beaconOrg, subj],
      ), { readOnly: false }),
      (err) => err?.code === '42501',
      `explicit_people assert_can_write must refuse ${label}`,
    );
  }
  await assert.rejects(
    () => withRequestTx(appPool, ownerAsCompATok, (tx) => tx.query(
      "SELECT * FROM iam.assert_can_write('act:hr.records.write', $1::uuid, $2::uuid)",
      [ids.beaconOrg, ids.agentA],
    ), { readOnly: false }),
    (err) => err?.code === '42501' && /VIEW_AS_READ_ONLY/.test(err.message),
    'View-as explicit_people write must fail 42501 VIEW_AS_READ_ONLY',
  );

  // 4. Revoking agentA drops agentA's rows immediately while keeping agentEast; revoking agentEast drops all rows to 0!
  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment, targetOrgId: ids.beaconOrg, commandKey: `e4-revoke-a-${randomUUID()}` })).seq;
    await c.query(
      "INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'revoked',$4,$5)",
      [randomUUID(), complianceAGrantId, ids.agentA, rgpAgentAId, seq],
    );
    await c.query(
      "INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'revoked',$4,$5)",
      [randomUUID(), writeGrantId, ids.agentA, rgpWriteAgentAId, seq],
    );
  });

  for (const [label, tok] of [['complianceA after revoking agentA', compATok], ['View-as complianceA after revoking agentA', ownerAsCompATok]]) {
    await withRequestTx(appPool, tok, async (tx) => {
      const bobNpns = (await tx.query('SELECT writing_npn FROM app_views.coherence_bob ORDER BY writing_npn')).rows.map((r) => r.writing_npn);
      assert.deepEqual(bobNpns, ['44444444'], `${label}: revoking agentA drops agentA rows while keeping agentEast`);
      const stmtNpns = (await tx.query('SELECT writing_npn FROM app_views.coherence_statement_agency_lines ORDER BY writing_npn')).rows.map((r) => r.writing_npn);
      assert.deepEqual(stmtNpns, ['44444444'], `${label}: revoking agentA drops agentA statements while keeping agentEast`);
    }, { readOnly: true });
  }
  await assert.rejects(
    () => withRequestTx(appPool, compATok, (tx) => tx.query(
      "SELECT * FROM iam.assert_can_write('act:hr.records.write', $1::uuid, $2::uuid)",
      [ids.beaconOrg, ids.agentA],
    ), { readOnly: false }),
    (err) => err?.code === '42501',
    'revoking agentA from explicit_people write grant must refuse assert_can_write',
  );

  // Revoke remaining person (agentEast) -> drops EVERY view to 0 rows, including published runs & statement batches!
  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment, targetOrgId: ids.beaconOrg, commandKey: `e4-revoke-east-${randomUUID()}` })).seq;
    await c.query(
      "INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'revoked',$4,$5)",
      [randomUUID(), complianceAGrantId, ids.agentEast, rgpAgentEastId, seq],
    );
  });

  for (const [label, tok] of [['complianceA all revoked', compATok], ['View-as complianceA all revoked', ownerAsCompATok]]) {
    await withRequestTx(appPool, tok, async (tx) => {
      assert.equal((await tx.query("SELECT iam.has_right('act:coherence.bob.read') AS ok")).rows[0].ok, false, `${label}: has_right must be false`);
      assert.deepEqual((await tx.query("SELECT iam.effective_any_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `${label}: any_orgs must be empty`);
      for (const viewName of ['coherence_bob', 'v_current_policy_periods', 'coherence_statement_agency_lines', 'coherence_published_runs', 'coherence_statement_batches']) {
        assert.equal((await tx.query(`SELECT COUNT(*)::int AS n FROM app_views.${viewName}`)).rows[0].n, 0, `${label}: ${viewName} must be 0`);
      }
    }, { readOnly: true });
  }

  // 5. Structural guard refusals on compliance & iam.role_grant_people.
  // (a) Granting compliance with org_subtree fails 23514 (allows_org_wide_scope = false).
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment, commandKey: `e4-comp-wide-${randomUUID()}` })).seq;
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), ids.entityMgr, complianceRoleId, ids.companyOrg, seq],
      );
    }),
    (err) => err?.code === '23514' && /ORG_WIDE_SCOPE_FORBIDDEN/.test(err.message),
    'compliance role must refuse org_subtree grant with 23514',
  );

  // (b) role_grant_people pointing to a self or org_subtree grant fails 23514.
  const selfGrantId = (await env.pool.query(
    "SELECT id FROM iam.role_grants WHERE person_id = $1 AND person_scope_mode = 'self' AND superseded_by_id IS NULL",
    [ids.agentA],
  )).rows[0].id;
  const wideGrantId = (await env.pool.query(
    "SELECT id FROM iam.role_grants WHERE person_id = $1 AND person_scope_mode = 'org_subtree' AND superseded_by_id IS NULL",
    [ids.beaconManager],
  )).rows[0].id;
  for (const [label, badGrantId] of [['self grant', selfGrantId], ['org_subtree grant', wideGrantId]]) {
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment, commandKey: `e4-rgp-bad-mode-${randomUUID()}` })).seq;
        await c.query(
          "INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), badGrantId, ids.agentB, seq],
        );
      }),
      (err) => err?.code === '23514' && /EXPLICIT_PEOPLE_SCOPE_REQUIRED/.test(err.message),
      `role_grant_people on ${label} must fail 23514`,
    );
  }

  // (c) role_grant_people with nusear_staff or service subject fails 23514.
  for (const [label, badSubj] of [['nusear_staff', ids.nusearOwner], ['service', ids.workerService]]) {
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment, commandKey: `e4-rgp-bad-orig-${randomUUID()}` })).seq;
        await c.query(
          "INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), complianceBGrantId, badSubj, seq],
        );
      }),
      (err) => err?.code === '23514' && /EXPLICIT_PEOPLE_ORIGIN_MISMATCH/.test(err.message),
      `role_grant_people with ${label} subject must fail 23514`,
    );
  }

  // (c2) Attaching people to a revoked or superseded explicit_people grant fails 23514 EXPLICIT_PEOPLE_GRANT_INACTIVE.
  const replacementGrantId = randomUUID();
  const revokedLiveGrantId = randomUUID();
  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment, targetOrgId: ids.beaconOrg, commandKey: `e4-rgp-inactive-grants-${randomUUID()}` })).seq;
    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, replaces_id, journal_seq)
       VALUES ($1,$2,$3,$4,true,'explicit_people','[2020-06-01,)'::daterange,'active',$5,$9),
              ($6,$7,$3,$4,true,'explicit_people','[2020-01-01,)'::daterange,'revoked',$8,$9)`,
      [replacementGrantId, complianceB, complianceRoleId, ids.beaconOrg, complianceBGrantId, revokedLiveGrantId, complianceSibling, complianceSiblingGrantId, seq],
    );
  });
  for (const [label, inactiveGrantId] of [
    ['superseded active grant', complianceBGrantId],
    ['live revoked grant', revokedLiveGrantId],
    ['grant superseded by revocation', complianceSiblingGrantId],
  ]) {
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment, commandKey: `e4-rgp-inactive-${randomUUID()}` })).seq;
        await c.query(
          "INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), inactiveGrantId, ids.agentA, seq],
        );
      }),
      (err) => err?.code === '23514' && /EXPLICIT_PEOPLE_GRANT_INACTIVE/.test(err.message),
      `attaching role_grant_people to ${label} must fail 23514 EXPLICIT_PEOPLE_GRANT_INACTIVE`,
    );
  }

  // (d) platform_iam_sync cannot insert into iam.role_grant_people (42501); platform_app cannot read/write (42501); table is immutable (55000).
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_iam_sync');
      const seq = (await appendIamAuditEntry(c, { environment, commandKey: `e4-sync-rgp-${randomUUID()}` })).seq;
      await c.query(
        "INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
        [randomUUID(), replacementGrantId, ids.agentA, seq],
      );
    }),
    (err) => err?.code === '42501',
    'platform_iam_sync must be refused 42501 inserting into iam.role_grant_people',
  );
  await assert.rejects(
    () => withRequestTx(appPool, env.ownerToken, (tx) => tx.query('SELECT * FROM iam.role_grant_people LIMIT 1'), { readOnly: true }),
    (err) => err?.code === '42501',
    'platform_app must be refused 42501 selecting iam.role_grant_people',
  );
  for (const sql of [
    "UPDATE iam.role_grant_people SET status = 'revoked'",
    'DELETE FROM iam.role_grant_people',
    'TRUNCATE TABLE iam.role_grant_people',
  ]) {
    await assert.rejects(() => env.pool.query(sql), (err) => err?.code === '55000', `immutable role_grant_people must refuse: ${sql}`);
  }
});

test('Layer 7G [E4 Test 2]: agent and retention-agent roles refuse company revenue (23514), refuse org_subtree (23514), allow own-pay (money_pay), and stay strictly self-scoped', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, environment } = env.iam;

  await t.test('2a: company-revenue guard (23514) allows own-pay rights and blocks statement/upline revenue on all 5 guarded roles', async () => {
    // Verify built-in roles flagged forbids_company_revenue_rights = true.
    const flaggedSlugs = (await env.pool.query(
      `SELECT r.slug
       FROM iam.roles r
       JOIN iam.role_versions rv ON rv.role_id = r.id AND rv.superseded_by_id IS NULL AND rv.status = 'active'
       WHERE r.owner_org_id IS NULL AND rv.forbids_company_revenue_rights = true
       ORDER BY r.slug`,
    )).rows.map((r) => r.slug);
    assert.deepEqual(
      flaggedSlugs,
      ['compliance', 'director_of_operations', 'director_of_sales', 'retention_agent', 'selling_agent'],
      'exact built-in roles setting forbids_company_revenue_rights = true',
    );

    // 1. Inserting any company-revenue right (statement_cash, upline_cash, upline.read, ledger.read) onto
    //    selling_agent, retention_agent, compliance, director_of_sales, or director_of_operations fails 23514.
    const forbiddenCompanyRevenueRights = [
      'col:coherence.statement_cash',
      'col:coherence.upline_cash',
      'act:coherence.upline.read',
      'act:coherence.ledger.read',
    ];
    const guardedRoles = (await env.pool.query(
      "SELECT id, slug FROM iam.roles WHERE owner_org_id IS NULL AND slug = ANY($1::text[]) ORDER BY slug",
      [['selling_agent', 'retention_agent', 'compliance', 'director_of_sales', 'director_of_operations']],
    )).rows;
    assert.equal(guardedRoles.length, 5);

    for (const role of guardedRoles) {
      for (const rightId of forbiddenCompanyRevenueRights) {
        await assert.rejects(
          () => inSerializableTx(env.pool, async (c) => {
            const seq = (await appendIamAuditEntry(c, { environment, commandKey: `e4-forbid-${role.slug}-${rightId}-${randomUUID()}` })).seq;
            await c.query(
              "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
              [randomUUID(), role.id, rightId, seq],
            );
          }),
          (err) => err?.code === '23514' && /COMPANY_REVENUE_RIGHT_FORBIDDEN/.test(err.message),
          `${role.slug} must refuse company-revenue right ${rightId} with 23514`,
        );
      }
    }

    // Also refused under platform_iam_sync (sync cannot sneak company-revenue rights onto selling_agent).
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        await c.query('SET LOCAL ROLE platform_iam_sync');
        const seq = (await appendIamAuditEntry(c, { environment, commandKey: `e4-sync-forbid-${randomUUID()}` })).seq;
        await c.query(
          "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,'col:coherence.statement_cash','active',$3)",
          [randomUUID(), ids.roleSellingAgent, seq],
        );
      }),
      (err) => err?.code === '23514' && /COMPANY_REVENUE_RIGHT_FORBIDDEN/.test(err.message),
      'platform_iam_sync must also be refused adding col:coherence.statement_cash to selling_agent',
    );

    // 2. Bidirectional guard: superseding role_versions on agency_manager (which holds statement_cash) to set forbids_company_revenue_rights = true fails 23514.
    const amRvId = (await env.pool.query(
      'SELECT id FROM iam.role_versions WHERE role_id = $1 AND superseded_by_id IS NULL',
      [ids.roleAgencyManager],
    )).rows[0].id;
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment, commandKey: `e4-flip-forbid-${randomUUID()}` })).seq;
        await c.query(
          `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, forbids_company_revenue_rights, status, replaces_id, journal_seq)
           VALUES ($1,$2,'Agency Manager',false,false,true,true,'active',$3,$4)`,
          [randomUUID(), ids.roleAgencyManager, amRvId, seq],
        );
      }),
      (err) => err?.code === '23514' && /COMPANY_REVENUE_RIGHT_FORBIDDEN/.test(err.message),
      'flipping forbids_company_revenue_rights=true on a role with live company-revenue rights must fail 23514',
    );

    // 3. Agent & retention-agent roles ARE allowed own-pay rights (money_pay), both in built-in catalog and on a fresh custom guarded agent role.
    const customAgentRoleId = randomUUID();
    await inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment, targetOrgId: ids.companyOrg, commandKey: `e4-custom-agent-${randomUUID()}` })).seq;
      await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'custom_own_pay_agent',$2,$3)", [customAgentRoleId, ids.companyOrg, seq]);
      await c.query(
        `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, forbids_company_revenue_rights, status, journal_seq)
         VALUES ($1,$2,'Custom Agent',false,false,false,true,'active',$3)`,
        [randomUUID(), customAgentRoleId, seq],
      );
      for (const rightId of ['act:coherence.bob.read', 'act:payroll.agent_pay.read', 'col:payroll.agent_pay_cash']) {
        await c.query(
          "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), customAgentRoleId, rightId, seq],
        );
      }
    });
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment, targetOrgId: ids.companyOrg, commandKey: `e4-custom-agent-bad-${randomUUID()}` })).seq;
        await c.query(
          "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,'col:coherence.upline_cash','active',$3)",
          [randomUUID(), customAgentRoleId, seq],
        );
      }),
      (err) => err?.code === '23514' && /COMPANY_REVENUE_RIGHT_FORBIDDEN/.test(err.message),
      'custom guarded agent role must refuse col:coherence.upline_cash with 23514',
    );
  });

  await t.test('2b: retention_agent refuses org_subtree grant (23514) and stays strictly self-scoped on own affiliation', async () => {
    // Granting retention_agent or selling_agent with org_subtree must fail 23514 ORG_WIDE_SCOPE_FORBIDDEN.
    for (const [label, roleId] of [
      ['retention_agent', ids.roleRetentionAgent],
      ['selling_agent', ids.roleSellingAgent],
    ]) {
      await assert.rejects(
        () => inSerializableTx(env.pool, async (c) => {
          const seq = (await appendIamAuditEntry(c, { environment, targetOrgId: ids.harborOrg, commandKey: `e4-wide-${label}-${randomUUID()}` })).seq;
          await c.query(
            `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
             VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)`,
            [randomUUID(), ids.entityMgr, roleId, ids.harborOrg, seq],
          );
        }),
        (err) => err?.code === '23514' && /ORG_WIDE_SCOPE_FORBIDDEN/.test(err.message),
        `${label} must refuse org_subtree grant with 23514 ORG_WIDE_SCOPE_FORBIDDEN`,
      );
    }

    // Harness retention persona must be granted 'self' with its own Harbor affiliation.
    const retGrant = (await env.pool.query(
      "SELECT person_scope_mode FROM iam.role_grants WHERE person_id = $1 AND role_id = $2 AND superseded_by_id IS NULL AND status = 'active'",
      [ids.harborRetention, ids.roleRetentionAgent],
    )).rows;
    assert.deepEqual(retGrant.map((r) => r.person_scope_mode), ['self'], 'harness harborRetention must hold a self grant');
    const retAff = (await env.pool.query(
      "SELECT npn, agency_org_id FROM iam.agent_affiliations WHERE person_id = $1 AND superseded_by_id IS NULL AND status = 'active'",
      [ids.harborRetention],
    )).rows;
    assert.deepEqual(
      retAff,
      [{ npn: '31313131', agency_org_id: ids.harborOrg }],
      'harness harborRetention must hold its own active Harbor agent affiliation',
    );

    // Seed a sent run with BOTH agentHarbor (33333333) AND harborRetention (31313131) in Harbor.
    await seedSentE4Run(env, { includeRetentionPolicy: true });

    const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
    for (const [label, tok, expectedNpn] of [
      ['agentA (selling_agent)', env.iam.tokens.agentA, '11111111'],
      ['harborRetention (retention_agent)', env.iam.tokens.retentionAgent, '31313131'],
    ]) {
      await withRequestTx(appPool, tok, async (tx) => {
        assert.equal((await tx.query("SELECT iam.has_right('act:payroll.agent_pay.read') AS ok")).rows[0].ok, true, `${label} must hold act:payroll.agent_pay.read`);
        assert.equal((await tx.query("SELECT iam.has_right('col:payroll.agent_pay_cash') AS ok")).rows[0].ok, true, `${label} must hold col:payroll.agent_pay_cash`);
        assert.equal((await tx.query("SELECT iam.has_right('col:coherence.statement_cash') AS ok")).rows[0].ok, false, `${label} must NOT hold col:coherence.statement_cash`);
        assert.equal((await tx.query("SELECT iam.has_right('col:coherence.upline_cash') AS ok")).rows[0].ok, false, `${label} must NOT hold col:coherence.upline_cash`);
        assert.equal((await tx.query("SELECT iam.has_right('act:coherence.statements.read') AS ok")).rows[0].ok, false, `${label} must NOT hold act:coherence.statements.read`);
        const bob = (await tx.query('SELECT writing_npn, amount, upline_amount FROM app_views.coherence_bob ORDER BY writing_npn')).rows;
        assert.deepEqual(
          bob,
          [{ writing_npn: expectedNpn, amount: null, upline_amount: null }],
          `${label} must see strictly own NPN (${expectedNpn}) with NULL dollars`,
        );
        assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n, 0, `${label} sees 0 Coherence statement rows`);
      }, { readOnly: true });
    }

    // Positive control: test-only agency_zero_dollar_reader sees BOTH Harbor agents' policies with NULL dollars.
    await withRequestTx(appPool, env.iam.tokens.harborZeroDollarReader, async (tx) => {
      const bob = (await tx.query('SELECT entity, writing_npn, amount, upline_amount FROM app_views.coherence_bob ORDER BY writing_npn')).rows;
      assert.deepEqual(
        bob,
        [
          { entity: 'Harbor', writing_npn: '31313131', amount: null, upline_amount: null },
          { entity: 'Harbor', writing_npn: '33333333', amount: null, upline_amount: null },
        ],
        'test-only harborZeroDollarReader sees all Harbor policies with NULL dollars',
      );
    }, { readOnly: true });
  });
});

test('Layer 7G [E4 Test 3]: one canonical catalog seeded once and reused by harness and scripts/prove-history.mjs, all 16 built-in roles exact rights & flags, investor role empty, and new role empty', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const catalogMod = await import('../src/iam/catalog.mjs');
  const { CANONICAL_TOOLS, CANONICAL_RIGHTS, CANONICAL_ROLES, seedIamCatalog } = catalogMod;
  assert.equal(CANONICAL_TOOLS.length, 9);
  assert.equal(CANONICAL_RIGHTS.length, 63);
  assert.equal(CANONICAL_ROLES.length, 16);
  assert.equal(typeof seedIamCatalog, 'function');

  await t.test('3a: seedIamCatalog idempotency, database_context environment & mismatch refusal, and request_sha256 over missing versions & role rights', async (subT) => {
    // 1. Empty migrated DB with NO iam.database_context row falls back to 'local' when environment is omitted.
    const db = await createEmptyMigratedTestDb();
    subT.after(() => db.cleanup());

    const first = await inSerializableTx(db.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_iam_sync');
      return seedIamCatalog(c);
    });
    assert.equal(first.insertedTools, CANONICAL_TOOLS.length);
    assert.equal(first.insertedRights, CANONICAL_RIGHTS.length);
    assert.equal(first.insertedRoles, CANONICAL_ROLES.length);
    assert.ok(first.rolesBySlug instanceof Map);
    const firstJournal = (await db.pool.query(
      'SELECT environment, request_sha256 FROM platform.audit_journal WHERE seq = $1',
      [first.journalSeq],
    )).rows[0];
    assert.equal(firstJournal.environment, 'local', 'missing database_context row must fall back to local');

    const journalBefore = (await db.pool.query('SELECT COUNT(*)::int AS n FROM platform.audit_journal')).rows[0].n;
    const second = await seedIamCatalog(db.pool);
    const journalAfter = (await db.pool.query('SELECT COUNT(*)::int AS n FROM platform.audit_journal')).rows[0].n;
    assert.equal(second.insertedTools, 0, 're-seeding catalog must insert 0 tools');
    assert.equal(second.insertedRights, 0, 're-seeding catalog must insert 0 rights');
    assert.equal(second.insertedRoles, 0, 're-seeding catalog must insert 0 roles');
    assert.equal(second.insertedRoleRights, 0, 're-seeding catalog must insert 0 role_rights');
    assert.equal(journalAfter, journalBefore, 'idempotent re-seed must add 0 extra audit_journal entries');

    for (const role of CANONICAL_ROLES) {
      assert.equal(second.rolesBySlug.get(role.slug), first.rolesBySlug.get(role.slug), `role UUID for ${role.slug} must be stable across idempotent re-seed`);
    }

    // Revoking a right on a built-in role must stay revoked across an idempotent re-seed.
    const acctRoleId = first.rolesBySlug.get('accounting');
    const acctInvRrId = (await db.pool.query(
      "SELECT id FROM iam.role_rights WHERE role_id = $1 AND right_id = 'act:billing.invoices.read' AND superseded_by_id IS NULL",
      [acctRoleId],
    )).rows[0].id;
    await inSerializableTx(db.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: 'local', commandKey: `e4-revoke-acct-inv-${randomUUID()}` })).seq;
      await c.query(
        "INSERT INTO iam.role_rights (id, role_id, right_id, status, replaces_id, journal_seq) VALUES ($1,$2,'act:billing.invoices.read','revoked',$3,$4)",
        [randomUUID(), acctRoleId, acctInvRrId, seq],
      );
    });
    const third = await seedIamCatalog(db.pool);
    assert.equal(third.insertedRoleRights, 0, 're-seeding catalog must not re-grant an explicitly revoked right');
    const revokedStatus = (await db.pool.query(
      "SELECT status FROM iam.role_rights WHERE role_id = $1 AND right_id = 'act:billing.invoices.read' AND superseded_by_id IS NULL",
      [acctRoleId],
    )).rows[0].status;
    assert.equal(revokedStatus, 'revoked', 'explicitly revoked right must remain revoked after catalog re-seed');

    // Upgrade path (Release P3): an existing 15-role DB (missing nusear_contractor and with pre-P3 company_admin rights)
    // picks up nusear_contractor and the missing company_admin rights on its next seedIamCatalog() run.
    const upgradeDb = await createEmptyMigratedTestDb();
    subT.after(() => upgradeDb.cleanup());
    const preP3AdminRights = new Set([
      'act:coherence.bob.read', 'act:coherence.checks.read', 'act:coherence.decisions.read',
      'act:coherence.inputs.read', 'act:coherence.journal.read', 'act:coherence.outputs.read',
      'act:coherence.runs.read', 'act:coherence.unpublished.read', 'act:hr.records.read',
      'act:hr.records.write', 'act:iam.read', 'act:platform.audit_journal.read',
      'col:coherence.member_contact', 'col:coherence.member_phi', 'col:vendors.real_name',
    ]);
    await inSerializableTx(upgradeDb.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: 'local', commandKind: 'iam.seed_pre_p3', commandKey: `pre-p3-${randomUUID()}` })).seq;
      for (const tool of CANONICAL_TOOLS) {
        await c.query(
          'INSERT INTO iam.tools (id, display_name, is_nusear_only, is_customer_switchable, journal_seq) VALUES ($1,$2,$3,$4,$5)',
          [tool.id, tool.displayName, tool.isNusearOnly, tool.isCustomerSwitchable, seq],
        );
      }
      for (const r of CANONICAL_RIGHTS) {
        await c.query(
          `INSERT INTO iam.rights (
             id, right_kind, tool_id, environment_scope, sensitivity_class, is_delegable_power,
             target_schema, target_table, target_column, description, journal_seq
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          [r.id, r.rightKind, r.toolId, r.environmentScope, r.sensitivityClass, r.isDelegablePower, r.targetSchema, r.targetTable, r.targetColumn, r.description, seq],
        );
      }
      for (const role of CANONICAL_ROLES) {
        if (role.slug === 'nusear_contractor') continue;
        const roleId = randomUUID();
        await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,NULL,$3)', [roleId, role.slug, seq]);
        await c.query(
          `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, requires_self_scope, forbids_company_revenue_rights, status, journal_seq)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9)`,
          [randomUUID(), roleId, role.displayName, role.isPinned, role.isNusearInternal, role.allowsOrgWideScope, role.requiresSelfScope, role.forbidsCompanyRevenueRights, seq],
        );
        const rightsToSeed = role.slug === 'company_admin'
          ? role.rights.filter((id) => preP3AdminRights.has(id))
          : role.rights;
        for (const rightId of rightsToSeed) {
          await c.query(
            "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
            [randomUUID(), roleId, rightId, seq],
          );
        }
      }
    });
    const rightsBySlug = async () => {
      const rows = (await upgradeDb.pool.query(
        `SELECT r.slug, rr.right_id FROM iam.role_rights rr JOIN iam.roles r ON r.id = rr.role_id
         WHERE rr.status = 'active' AND rr.superseded_by_id IS NULL ORDER BY r.slug, rr.right_id`,
      )).rows;
      const out = new Map();
      for (const row of rows) out.set(row.slug, [...(out.get(row.slug) || []), row.right_id]);
      return out;
    };
    const versionsBefore = (await upgradeDb.pool.query('SELECT id, role_id, is_pinned, forbids_company_revenue_rights FROM iam.role_versions ORDER BY id')).rows;
    const rightsBefore = await rightsBySlug();
    const upgraded = await inSerializableTx(upgradeDb.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_iam_sync');
      return seedIamCatalog(c);
    });
    assert.equal(upgraded.insertedTools, 0, 'P3 upgrade adds no tools');
    assert.equal(upgraded.insertedRights, 0, 'P3 upgrade adds no rights');
    assert.equal(upgraded.insertedRoles, 1, 'P3 upgrade must add nusear_contractor');
    assert.equal(upgraded.insertedRoleVersions, 1, 'P3 upgrade must add nusear_contractor role_version');
    assert.equal(upgraded.insertedRoleRights, 45, 'P3 upgrade must add 30 rights for nusear_contractor + 15 missing rights for company_admin');
    const upgradeNoop = await seedIamCatalog(upgradeDb.pool);
    assert.equal(upgradeNoop.journalSeq, null, 'second seedIamCatalog after P3 upgrade must be a no-op');
    const versionsAfter = (await upgradeDb.pool.query('SELECT id, role_id, is_pinned, forbids_company_revenue_rights, superseded_by_id FROM iam.role_versions ORDER BY id')).rows;
    for (const before of versionsBefore) {
      const after = versionsAfter.find((v) => v.id === before.id);
      assert.ok(after && after.superseded_by_id === null && after.is_pinned === before.is_pinned
        && after.forbids_company_revenue_rights === before.forbids_company_revenue_rights, 'every earlier role version stays as it was');
    }
    const rightsAfter = await rightsBySlug();
    const entityManagerRights = [...(rightsAfter.get('entity_manager') || [])].sort();
    assert.ok(entityManagerRights.length > 0);
    assert.deepEqual([...rightsAfter.get('company_admin')].sort(), entityManagerRights, 'the administrator holds exactly the entity manager view');
    assert.deepEqual([...rightsAfter.get('nusear_contractor')].sort(), entityManagerRights, 'the Nusear contractor holds exactly the entity manager view');
    for (const [slug, rights] of rightsBefore) {
      if (slug === 'company_admin') continue;
      assert.deepEqual(rightsAfter.get(slug), rights, `${slug}'s rights are unchanged`);
    }

    // 2. When iam.database_context exists (e.g. environment = 'prod'), omitting environment reads 'prod',
    //    and passing a mismatched environment ('local' or 'dev') is refused even after seeding.
    const prodDb = await createEmptyMigratedTestDb();
    subT.after(() => prodDb.cleanup());
    await inSerializableTx(prodDb.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: 'prod', commandKind: 'iam.init_ctx', commandKey: 'e4-prod-ctx' })).seq;
      await c.query(
        `INSERT INTO iam.database_context (singleton, environment, db_role_kind, tenant_org_id, company_slug, support_external_label, journal_seq)
         VALUES (true, 'prod', 'control', NULL, NULL, 'Nusear support', $1)`,
        [seq],
      );
    });
    await assert.rejects(
      () => seedIamCatalog(prodDb.pool, { environment: 'local' }),
      /environment mismatch/i,
      'seedIamCatalog must refuse environment mismatch before seeding',
    );
    const prodSeed = await inSerializableTx(prodDb.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_iam_sync');
      return seedIamCatalog(c);
    });
    const prodJournal = (await prodDb.pool.query(
      'SELECT environment FROM platform.audit_journal WHERE seq = $1',
      [prodSeed.journalSeq],
    )).rows[0];
    assert.equal(prodJournal.environment, 'prod', 'seedIamCatalog without environment must use iam.database_context.environment');
    await assert.rejects(
      () => seedIamCatalog(prodDb.pool, { environment: 'dev' }),
      /environment mismatch/i,
      'seedIamCatalog must refuse environment mismatch even when catalog is already complete',
    );
    const prodNoop = await seedIamCatalog(prodDb.pool, { environment: 'prod' });
    assert.equal(prodNoop.journalSeq, null, 'matching explicit environment succeeds idempotently');
  });

  await t.test('3a-hash: seedIamCatalog request_sha256 includes missing role_versions and role_rights', async (subT) => {
    // 3. Request hash must include missing role_versions and missing role_rights (never collapsing to empty {tools,rights,roles}).
    const emptyDeltaHash = sha256Hex(JSON.stringify({
      commandKind: 'iam.seed_catalog',
      tools: [],
      rights: [],
      roles: [],
    }));
    async function seedPartialAndMeasureHash({ omitVersionSlug = null, omitRightPair = null }) {
      const pDb = await createEmptyMigratedTestDb();
      subT.after(() => pDb.cleanup());
      await inSerializableTx(pDb.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment: 'local', commandKind: 'iam.partial_seed', commandKey: `partial-${randomUUID()}` })).seq;
        for (const t of CANONICAL_TOOLS) {
          await c.query(
            'INSERT INTO iam.tools (id, display_name, is_nusear_only, is_customer_switchable, journal_seq) VALUES ($1,$2,$3,$4,$5)',
            [t.id, t.displayName, t.isNusearOnly, t.isCustomerSwitchable, seq],
          );
        }
        for (const r of CANONICAL_RIGHTS) {
          await c.query(
            `INSERT INTO iam.rights (
               id, right_kind, tool_id, environment_scope, sensitivity_class, is_delegable_power,
               target_schema, target_table, target_column, description, journal_seq
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
            [r.id, r.rightKind, r.toolId, r.environmentScope, r.sensitivityClass, r.isDelegablePower, r.targetSchema, r.targetTable, r.targetColumn, r.description, seq],
          );
        }
        for (const role of CANONICAL_ROLES) {
          const roleId = randomUUID();
          await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,NULL,$3)', [roleId, role.slug, seq]);
          if (role.slug !== omitVersionSlug) {
            await c.query(
              `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, forbids_company_revenue_rights, status, journal_seq)
               VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8)`,
              [randomUUID(), roleId, role.displayName, role.isPinned, role.isNusearInternal, role.allowsOrgWideScope, role.forbidsCompanyRevenueRights, seq],
            );
          }
          for (const rightId of role.rights) {
            if (omitRightPair && omitRightPair[0] === role.slug && omitRightPair[1] === rightId) continue;
            await c.query(
              "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
              [randomUUID(), roleId, rightId, seq],
            );
          }
        }
      });
      const res = await seedIamCatalog(pDb.pool);
      const row = (await pDb.pool.query('SELECT request_sha256 FROM platform.audit_journal WHERE seq = $1', [res.journalSeq])).rows[0];
      return { res, hash: row.request_sha256 };
    }

    const missRightA = await seedPartialAndMeasureHash({ omitRightPair: ['accounting', 'act:billing.invoices.read'] });
    const missRightB = await seedPartialAndMeasureHash({ omitRightPair: ['accounting', 'act:leads.costs.read'] });
    const missVersion = await seedPartialAndMeasureHash({ omitVersionSlug: 'investor' });
    assert.equal(missRightA.res.insertedRoleRights, 1);
    assert.equal(missRightB.res.insertedRoleRights, 1);
    assert.equal(missVersion.res.insertedRoleVersions, 1);
    assert.notEqual(missRightA.hash, emptyDeltaHash, 'missing role_rights must affect request_sha256');
    assert.notEqual(missRightB.hash, emptyDeltaHash, 'missing role_rights must affect request_sha256');
    assert.notEqual(missRightA.hash, missRightB.hash, 'different missing role_rights must yield distinct request_sha256');
    assert.notEqual(missVersion.hash, emptyDeltaHash, 'missing role_versions must affect request_sha256');
    assert.notEqual(missVersion.hash, missRightA.hash, 'missing role_version hash must differ from missing role_right hash');
  });

  // 2. Verify EVERY built-in role's exact rights and flags (all 16) in a harness-seeded DB, so any catalog drift fails.
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  await seedSentE4Run(env);

  await t.test('3b: every built-in role (all 16) has exact expected flags and rights, and entity_manager, company_admin, and nusear_contractor share the exact same full view', async () => {
    const roleRightsRes = await env.pool.query(
      `SELECT r.slug, rv.display_name, rv.is_pinned, rv.is_nusear_internal, rv.allows_org_wide_scope, rv.requires_self_scope, rv.forbids_company_revenue_rights,
              COALESCE(pg_catalog.array_agg(rr.right_id ORDER BY rr.right_id) FILTER (WHERE rr.right_id IS NOT NULL), ARRAY[]::text[]) AS rights
       FROM iam.roles r
       JOIN iam.role_versions rv ON rv.role_id = r.id AND rv.superseded_by_id IS NULL AND rv.status = 'active'
       LEFT JOIN iam.role_rights rr ON rr.role_id = r.id AND rr.superseded_by_id IS NULL AND rr.status = 'active'
       WHERE r.owner_org_id IS NULL
       GROUP BY r.slug, rv.display_name, rv.is_pinned, rv.is_nusear_internal, rv.allows_org_wide_scope, rv.requires_self_scope, rv.forbids_company_revenue_rights
       ORDER BY r.slug`,
    );
    const bySlug = new Map(roleRightsRes.rows.map((r) => [r.slug, r]));

    const expectedNusearRead = [
      'act:billing.invoices.read',
      'act:coherence.bob.read',
      'act:coherence.checks.read',
      'act:coherence.decisions.read',
      'act:coherence.inputs.read',
      'act:coherence.journal.read',
      'act:coherence.ledger.read',
      'act:coherence.outputs.read',
      'act:coherence.runs.read',
      'act:coherence.statements.read',
      'act:coherence.unpublished.read',
      'act:coherence.upline.read',
      'act:hr.records.read',
      'act:iam.read',
      'act:leads.costs.read',
      'act:leads.vendor_bills.read',
      'act:payroll.agent_pay.read',
      'act:payroll.runs.read',
      'act:platform.audit_journal.read',
      'act:referrals.destination.read',
      'act:referrals.read',
      'col:billing.invoice_cash',
      'col:coherence.member_contact',
      'col:coherence.member_phi',
      'col:coherence.statement_cash',
      'col:coherence.upline_cash',
      'col:leads.cost_cash',
      'col:leads.vendor_bill_cash',
      'col:payroll.agent_pay_cash',
      'col:payroll.pay_cash',
      'col:platform.audit_journal.nusear_actor',
      'col:referrals.pay_cash',
      'col:vendors.real_name',
    ];
    const expectedNusearSupport = [
      ...expectedNusearRead,
      'act:coherence.approvals.register',
      'act:coherence.inputs.publish',
      'act:coherence.review.draft',
      'act:coherence.review.save',
      'act:coherence.review.submit',
      'act:coherence.run.cancel',
      'act:coherence.run.launch',
      'act:coherence.run.retry',
      'act:hr.records.write',
      'act:iam.entities.write',
      'act:iam.grants.write',
      'act:iam.people.write',
      'act:iam.roles.write',
      'act:iam.switches.write',
    ].sort();
    const expectedNusearOwner = [
      ...expectedNusearSupport,
      'act:coherence.checks.record',
      'act:coherence.emit.materialize',
      'act:coherence.files.register',
      'act:coherence.overlays.record',
      'act:coherence.owner.abandon_run',
      'act:coherence.owner.carry_approvals',
      'act:coherence.owner.carry_decisions',
      'act:coherence.owner.carry_sent',
      'act:coherence.owner.confirm_emit',
      'act:coherence.owner.import_history',
      'act:coherence.owner.init_company',
      'act:coherence.owner.record_baseline',
      'act:coherence.owner.record_statement_batch',
      'act:coherence.owner.register_engine',
    ].sort();
    const expectedFullEntityRights = [
      'act:billing.invoices.read',
      'act:coherence.bob.read',
      'act:coherence.checks.read',
      'act:coherence.decisions.read',
      'act:coherence.inputs.read',
      'act:coherence.journal.read',
      'act:coherence.ledger.read',
      'act:coherence.outputs.read',
      'act:coherence.runs.read',
      'act:coherence.statements.read',
      'act:coherence.unpublished.read',
      'act:coherence.upline.read',
      'act:hr.records.read',
      'act:hr.records.write',
      'act:iam.read',
      'act:leads.costs.read',
      'act:payroll.agent_pay.read',
      'act:payroll.runs.read',
      'act:platform.audit_journal.read',
      'act:referrals.read',
      'col:billing.invoice_cash',
      'col:coherence.member_contact',
      'col:coherence.member_phi',
      'col:coherence.statement_cash',
      'col:coherence.upline_cash',
      'col:leads.cost_cash',
      'col:payroll.agent_pay_cash',
      'col:payroll.pay_cash',
      'col:referrals.pay_cash',
      'col:vendors.real_name',
    ];
    const expectedAgentRights = [
      'act:coherence.bob.read',
      'act:hr.records.read',
      'act:iam.read',
      'act:payroll.agent_pay.read',
      'act:referrals.read',
      'col:coherence.member_contact',
      'col:coherence.member_phi',
      'col:payroll.agent_pay_cash',
      'col:referrals.pay_cash',
    ];

    const EXPECTED_BUILT_IN_ROLES = {
      nusear_owner: {
        display_name: 'Nusear Owner', is_pinned: true, is_nusear_internal: true, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: false,
        rights: expectedNusearOwner,
      },
      nusear_support: {
        display_name: 'Nusear Support', is_pinned: false, is_nusear_internal: true, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: false,
        rights: expectedNusearSupport,
      },
      nusear_admin: {
        display_name: 'Nusear Admin', is_pinned: false, is_nusear_internal: true, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: false,
        rights: expectedNusearRead,
      },
      coherence_worker_svc: {
        display_name: 'Coherence Worker', is_pinned: true, is_nusear_internal: true, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: false,
        rights: [
          'act:coherence.checks.record',
          'act:coherence.emit.materialize',
          'act:coherence.files.register',
          'act:coherence.overlays.record',
          'act:coherence.worker.attempt',
          'act:coherence.worker.review',
        ],
      },
      owner: {
        display_name: 'Owner', is_pinned: false, is_nusear_internal: false, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: false,
        rights: expectedFullEntityRights,
      },
      entity_manager: {
        display_name: 'Entity Manager', is_pinned: false, is_nusear_internal: false, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: false,
        rights: expectedFullEntityRights,
      },
      company_admin: {
        display_name: 'Administrator', is_pinned: false, is_nusear_internal: false, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: false,
        rights: expectedFullEntityRights,
      },
      nusear_contractor: {
        display_name: 'Nusear Contractor', is_pinned: false, is_nusear_internal: false, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: false,
        rights: expectedFullEntityRights,
      },
      agency_manager: {
        display_name: 'Agency Manager', is_pinned: false, is_nusear_internal: false, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: false,
        rights: [
          'act:coherence.bob.read',
          'act:coherence.statements.read',
          'act:iam.read',
          'col:coherence.member_contact',
          'col:coherence.member_phi',
          'col:coherence.statement_cash',
        ],
      },
      director_of_sales: {
        display_name: 'Director of Sales', is_pinned: false, is_nusear_internal: false, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: true,
        rights: [
          'act:coherence.bob.read',
          'act:iam.read',
          'act:leads.costs.read',
          'col:coherence.member_contact',
          'col:coherence.member_phi',
          'col:leads.cost_cash',
        ],
      },
      director_of_operations: {
        display_name: 'Director of Operations', is_pinned: false, is_nusear_internal: false, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: true,
        rights: [
          'act:coherence.bob.read',
          'act:iam.read',
          'act:leads.costs.read',
          'act:referrals.read',
          'col:coherence.member_contact',
          'col:coherence.member_phi',
          'col:leads.cost_cash',
        ],
      },
      accounting: {
        display_name: 'Accounting', is_pinned: false, is_nusear_internal: false, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: false,
        rights: [
          'act:billing.invoices.read',
          'act:coherence.bob.read',
          'act:coherence.ledger.read',
          'act:coherence.statements.read',
          'act:coherence.upline.read',
          'act:iam.read',
          'act:leads.costs.read',
          'act:payroll.agent_pay.read',
          'act:payroll.runs.read',
          'act:referrals.read',
          'col:billing.invoice_cash',
          'col:coherence.statement_cash',
          'col:coherence.upline_cash',
          'col:leads.cost_cash',
          'col:payroll.agent_pay_cash',
          'col:payroll.pay_cash',
          'col:referrals.pay_cash',
        ],
      },
      compliance: {
        display_name: 'Compliance', is_pinned: false, is_nusear_internal: false, allows_org_wide_scope: false, requires_self_scope: false, forbids_company_revenue_rights: true,
        rights: [
          'act:coherence.bob.read',
          'act:coherence.statements.read',
          'act:iam.read',
          'col:coherence.member_contact',
          'col:coherence.member_phi',
        ],
      },
      retention_agent: {
        display_name: 'Retention Agent', is_pinned: false, is_nusear_internal: false, allows_org_wide_scope: false, requires_self_scope: true, forbids_company_revenue_rights: true,
        rights: expectedAgentRights,
      },
      selling_agent: {
        display_name: 'Agent', is_pinned: false, is_nusear_internal: false, allows_org_wide_scope: false, requires_self_scope: true, forbids_company_revenue_rights: true,
        rights: expectedAgentRights,
      },
      investor: {
        display_name: 'Investor', is_pinned: false, is_nusear_internal: false, allows_org_wide_scope: true, requires_self_scope: false, forbids_company_revenue_rights: false,
        rights: [],
      },
    };

    assert.deepEqual(
      [...bySlug.keys()].sort(),
      Object.keys(EXPECTED_BUILT_IN_ROLES).sort(),
      'exact 16 built-in roles must be seeded with no missing or unexpected built-in roles',
    );
    for (const [slug, expected] of Object.entries(EXPECTED_BUILT_IN_ROLES)) {
      const actual = bySlug.get(slug);
      assert.deepEqual(
        {
          display_name: actual.display_name,
          is_pinned: actual.is_pinned,
          is_nusear_internal: actual.is_nusear_internal,
          allows_org_wide_scope: actual.allows_org_wide_scope,
          requires_self_scope: actual.requires_self_scope,
          forbids_company_revenue_rights: actual.forbids_company_revenue_rights,
          rights: actual.rights,
        },
        expected,
        `built-in role ${slug} flags and rights must match canonical catalog exactly`,
      );
    }

    // Runtime check: entity_manager, company_admin, and nusear_contractor all hold exact ENTITY_MANAGER_RIGHTS
    // (full workshop, statements, upline, ledger, payroll, lead costs, billing, referrals, HR) and zero run/review/Nusear-only writes.
    const emPool = createRoleScopedTestPool(env.pool, 'platform_app');
    const readSnapshot = async (tok) => withRequestTx(emPool, tok, async (tx) => {
      for (const right of expectedFullEntityRights) {
        assert.equal((await tx.query('SELECT iam.has_right($1) AS ok', [right])).rows[0].ok, true, `caller must hold ${right}`);
      }
      for (const forbiddenRight of [
        'col:platform.audit_journal.nusear_actor',
        'act:coherence.run.launch',
        'act:coherence.review.save',
        'act:coherence.owner.confirm_emit',
        'act:iam.roles.write',
      ]) {
        assert.equal((await tx.query('SELECT iam.has_right($1) AS ok', [forbiddenRight])).rows[0].ok, false, `caller must not hold ${forbiddenRight}`);
      }
      assert.ok((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_journal')).rows[0].n > 0);
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_review_drift_gate')).rows[0].n, 1);
      return {
        bob: (await tx.query('SELECT * FROM app_views.coherence_bob ORDER BY policy_id')).rows,
        ledger: (await tx.query('SELECT * FROM app_views.coherence_ledger ORDER BY tx_id')).rows,
        agency: (await tx.query('SELECT * FROM app_views.coherence_statement_agency_lines ORDER BY batch_id, line_no')).rows,
        upline: (await tx.query('SELECT * FROM app_views.coherence_statement_upline_lines ORDER BY batch_id, line_no')).rows,
      };
    }, { readOnly: true });
    const emSnap = await readSnapshot(env.iam.tokens.entityMgr);
    assert.ok(emSnap.bob.length > 0 && emSnap.ledger.length > 0 && emSnap.agency.length > 0 && emSnap.upline.length > 0);
    for (const [label, tok] of [
      ['company_admin', env.iam.tokens.companyAdmin],
      ['nusear_contractor', env.iam.tokens.nusearContractor],
    ]) {
      assert.deepEqual(await readSnapshot(tok), emSnap, `${label} must see exact same Coherence rows, columns, and money as entity_manager`);
    }
  });

  await t.test('3c: investor role empty, new role empty, and scripts/prove-history.mjs catalog reuse', async (subT) => {
    // 3. Runtime checks: investor sees 0 rows everywhere; a brand-new role starts completely empty (0 rights, 0 rows).
    const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
    await withRequestTx(appPool, env.iam.tokens.investor, async (tx) => {
      for (const right of ['act:coherence.bob.read', 'act:coherence.statements.read', 'col:coherence.statement_cash', 'act:payroll.agent_pay.read', 'act:leads.costs.read']) {
        assert.equal((await tx.query('SELECT iam.has_right($1) AS ok', [right])).rows[0].ok, false, `investor must lack ${right}`);
      }
      for (const viewName of ['coherence_bob', 'v_current_policy_periods', 'coherence_statement_agency_lines', 'coherence_statement_upline_lines', 'coherence_ledger', 'coherence_runs', 'coherence_published_runs']) {
        assert.equal((await tx.query(`SELECT COUNT(*)::int AS n FROM app_views.${viewName}`)).rows[0].n, 0, `investor must see 0 rows in ${viewName}`);
      }
    }, { readOnly: true });

    const newRoleId = randomUUID();
    const newRoleUserId = randomUUID();
    await inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: env.iam.ids.companyOrg, commandKey: `e4-new-empty-role-${randomUUID()}` })).seq;
      await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'new_unconfigured_role',$2,$3)", [newRoleId, env.iam.ids.companyOrg, seq]);
      await c.query(
        "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,'New Unconfigured',false,false,true,'active',$3)",
        [randomUUID(), newRoleId, seq],
      );
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','company_local',$2)", [newRoleUserId, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'company_local','Drew NewRole','Drew NewRole','drew.new@acme.example','active',$3)",
        [randomUUID(), newRoleUserId, seq],
      );
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,NULL,'[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), newRoleUserId, env.iam.ids.companyOrg, seq],
      );
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), newRoleUserId, newRoleId, env.iam.ids.companyOrg, seq],
      );
    });

    const newRoleRights = (await env.pool.query(
      'SELECT right_id FROM iam.role_rights WHERE role_id = $1 AND superseded_by_id IS NULL AND status = \'active\'',
      [newRoleId],
    )).rows;
    assert.deepEqual(newRoleRights, [], 'brand-new role must start with zero rights');
    await withRequestTx(appPool, env.iam.tokenFor(newRoleUserId), async (tx) => {
      for (const right of ['act:coherence.bob.read', 'act:coherence.runs.read', 'act:platform.audit_journal.read', 'act:payroll.agent_pay.read']) {
        assert.equal((await tx.query('SELECT iam.has_right($1) AS ok', [right])).rows[0].ok, false, `new empty role user must lack ${right}`);
      }
      for (const viewName of ['coherence_bob', 'coherence_statement_agency_lines', 'coherence_runs', 'coherence_published_runs']) {
        assert.equal((await tx.query(`SELECT COUNT(*)::int AS n FROM app_views.${viewName}`)).rows[0].n, 0, `new empty role user must see 0 rows in ${viewName}`);
      }
    }, { readOnly: true });

    // 4. Verify scripts/prove-history.mjs reuses seedIamCatalog and its importing owner sees every column!
    const proofMod = await import('../scripts/prove-history.mjs');
    assert.equal(typeof proofMod.seedProofIamOwner, 'function', 'scripts/prove-history.mjs must export seedProofIamOwner');
    const proofDb = await createEmptyMigratedTestDb();
    subT.after(() => proofDb.cleanup());
    const proofIam = await proofMod.seedProofIamOwner(proofDb.pool, { companySlug: 'acme', displayName: 'Acme' });
    const proofRoles = (await proofDb.pool.query(
      'SELECT slug FROM iam.roles WHERE owner_org_id IS NULL ORDER BY slug',
    )).rows.map((r) => r.slug);
    assert.deepEqual(
      proofRoles,
      CANONICAL_ROLES.map((r) => r.slug).sort(),
      'scripts/prove-history.mjs must seed the exact canonical role catalog',
    );
    const proofAppPool = createRoleScopedTestPool(proofDb.pool, 'platform_app');
    await withRequestTx(proofAppPool, proofIam.ownerToken, async (tx) => {
      for (const right of [
        'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read', 'act:coherence.ledger.read',
        'act:coherence.unpublished.read', 'act:coherence.runs.read', 'act:coherence.inputs.read', 'act:coherence.outputs.read',
        'act:coherence.decisions.read', 'act:coherence.checks.read', 'act:coherence.journal.read',
        'col:coherence.statement_cash', 'col:coherence.upline_cash', 'col:coherence.member_phi', 'col:coherence.member_contact',
        'col:platform.audit_journal.nusear_actor', 'col:vendors.real_name',
        'act:coherence.owner.import_history', 'act:coherence.emit.materialize',
      ]) {
        assert.equal((await tx.query('SELECT iam.has_right($1) AS ok', [right])).rows[0].ok, true, `proof owner must hold ${right}`);
      }
    }, { readOnly: true });
  });
});

test('Layer 7G [E4 Test 4]: EXPLAIN InitPlan confirms single-evaluation effective_narrow_pairs under explicit_people (direct & View-as) and verifyIamConfigInvariants audits E4 guards', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, environment } = env.iam;

  await seedSentE4Run(env);

  const complianceRoleId = (await env.pool.query(
    "SELECT id FROM iam.roles WHERE owner_org_id IS NULL AND slug = 'compliance'",
  )).rows[0].id;
  const compUser = randomUUID();
  const compGrantId = randomUUID();
  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment, targetOrgId: ids.beaconOrg, commandKey: `e4-explain-seed-${randomUUID()}` })).seq;
    await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','company_local',$2)", [compUser, seq]);
    await c.query(
      "INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'company_local','Ellis Explain','Ellis Explain','ellis.exp@acme.example','active',$3)",
      [randomUUID(), compUser, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), compUser, ids.beaconOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'explicit_people','[2020-01-01,)'::daterange,'active',$5)",
      [compGrantId, compUser, complianceRoleId, ids.beaconOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
      [randomUUID(), compGrantId, ids.agentA, seq],
    );
  });

  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  for (const [who, tok] of [
    ['compliance direct', env.iam.tokenFor(compUser)],
    ['owner View-as compliance', env.iam.tokenFor(ids.nusearOwner, compUser)],
  ]) {
    for (const viewName of [
      'coherence_bob',
      'v_current_policy_periods',
      'coherence_statement_agency_lines',
      'coherence_entity_statement_lines',
    ]) {
      const plan = await withRequestTx(appPool, tok, async (tx) => {
        const res = await tx.query(`EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT * FROM app_views.${viewName}`);
        return res.rows[0]['QUERY PLAN'][0].Plan;
      }, { readOnly: true });
      const stats = inspectNarrowPlanNodes(plan);
      assert.deepEqual(stats.perRowSubPlans, [], `${who} on ${viewName} must have 0 per-row SubPlans`);
      assert.deepEqual(stats.highLoopNodes, [], `${who} on ${viewName} must evaluate every narrow/wide helper at most once per statement`);
      assert.ok(stats.hashedOrInitPlans.length > 0, `${who} on ${viewName} must evaluate read helpers via InitPlan or hashed SubPlan`);
    }
  }

  // Live catalog audit passes cleanly (18 iam tables) and catches deliberate breakage of E4 guards.
  const baseline = await withClusterCatalogLock(() => policyChecks.verifyIamConfigInvariants(env.pool));
  assert.equal(baseline.passed, true, `baseline verifyIamConfigInvariants failed:\n${baseline.problems.join('\n')}`);
  assert.equal(baseline.checkedIamTables, 18, 'expected 18 iam base tables (7 immutable + 11 versioned including role_grant_people)');

  for (const [label, mutateSql, restoreSql, expectedRe] of [
    [
      'grant INSERT on iam.role_grant_people to platform_iam_sync',
      'GRANT INSERT ON iam.role_grant_people TO platform_iam_sync',
      'REVOKE INSERT ON iam.role_grant_people FROM platform_iam_sync',
      /platform_iam_sync.*role_grant_people/i,
    ],
    [
      'disable trg_role_grant_people_verify on iam.role_grant_people',
      'ALTER TABLE iam.role_grant_people DISABLE TRIGGER trg_role_grant_people_verify',
      'ALTER TABLE iam.role_grant_people ENABLE TRIGGER trg_role_grant_people_verify',
      /trg_role_grant_people_verify/i,
    ],
    [
      'disable trg_role_rights_verify_invariants on iam.role_rights',
      'ALTER TABLE iam.role_rights DISABLE TRIGGER trg_role_rights_verify_invariants',
      'ALTER TABLE iam.role_rights ENABLE TRIGGER trg_role_rights_verify_invariants',
      /trg_role_rights_verify_invariants/i,
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
