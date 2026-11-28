// Layer 7H: Release E5 (smaller design) - IAM read views (app_views.iam_* with one vendor-masking rule),
// FORCE RLS across all 18 iam.* tables, Nusear-staff-only app_cmd.iam_* write commands via signed-token bridge,
// refusal proofs (company_local refused on every IAM write; Nusear refused on platform_root, built-in roles,
// and Nusear's own people/memberships/grants; owner & worker powers non-delegable and never addable),
// atomic person + first works-for line creation, data invariants, View-as refusal, and live catalog audit.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { access, readFile } from 'node:fs/promises';
import test from 'node:test';
import * as appCmdMod from '../src/commands/app-cmd.mjs';
import * as catalogMod from '../src/iam/catalog.mjs';
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

const OWNER_POWER_RIGHTS = [
  'act:coherence.owner.confirm_emit',
  'act:coherence.owner.carry_sent',
  'act:coherence.owner.carry_approvals',
  'act:coherence.owner.carry_decisions',
  'act:coherence.owner.abandon_run',
  'act:coherence.owner.init_company',
  'act:coherence.owner.register_engine',
  'act:coherence.owner.record_baseline',
  'act:coherence.owner.record_statement_batch',
  'act:coherence.owner.import_history',
];

const WORKER_OR_OWNER_POWER_RIGHTS = [
  'act:coherence.checks.record',
  'act:coherence.files.register',
  'act:coherence.overlays.record',
  'act:coherence.emit.materialize',
];

const WORKER_POWER_RIGHTS = [
  'act:coherence.worker.attempt',
  'act:coherence.worker.review',
];

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

async function loadIamCmdModule() {
  const mod = await import('../src/commands/iam-cmd.mjs');
  assert.equal(typeof mod.createIamCommands, 'function', 'src/commands/iam-cmd.mjs must export createIamCommands');
  assert.equal(typeof appCmdMod.createIamCommands, 'function', 'src/commands/app-cmd.mjs must compose/export createIamCommands beside createAppCommands');
  return mod;
}

/**
 * Runs a refused write command as an abusing role and proves NOTHING was written:
 * both the target table row count(s) and platform.audit_journal (count + max seq) stay identical.
 */
async function assertRefusedNoWrite(pool, targetTables, fn, checkErr, message) {
  const tables = Array.isArray(targetTables) ? targetTables : [targetTables];
  const snapshot = async () => {
    const audit = (await pool.query(
      'SELECT COUNT(*)::int AS cnt, COALESCE(MAX(seq), 0)::bigint AS max_seq FROM platform.audit_journal',
    )).rows[0];
    const counts = {};
    for (const tbl of tables) {
      counts[tbl] = (await pool.query(`SELECT COUNT(*)::int AS cnt FROM ${tbl}`)).rows[0].cnt;
    }
    return { auditCnt: audit.cnt, auditMaxSeq: String(audit.max_seq), counts };
  };
  const before = await snapshot();
  await assert.rejects(fn, checkErr, message);
  const after = await snapshot();
  assert.deepEqual(after, before, `${message}: target table(s) [${tables.join(', ')}] and platform.audit_journal must be unchanged`);
}

function makeE5RunCsvs({ statementDate = '2026-11-15' } = {}) {
  const specs = [
    { policyId: '901', entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller', gross: '100.00', amount: '80.00', upline: '20.00' },
    { policyId: '902', entity: 'Beacon', writingNpn: '22222222', writingAgent: 'Sam Seller', gross: '200.00', amount: '160.00', upline: '40.00' },
    { policyId: '903', entity: 'East Team', writingNpn: '44444444', writingAgent: 'Jamie East', gross: '150.00', amount: '120.00', upline: '30.00' },
    { policyId: '904', entity: 'Harbor', writingNpn: '33333333', writingAgent: 'Robin Harbor', gross: '250.00', amount: '200.00', upline: '50.00' },
  ];
  const bobRows = [];
  const ledgerRows = [];
  const stmtRows = [];

  specs.forEach((s, idx) => {
    const mbi = `5E5${idx}-CD3-EF5${idx}`;
    const member = `Member E5-${idx}`;
    const recId = `carrier_a|direct|NM:member,e5_${idx}|${s.gross}|${statementDate.slice(0, 7)}`;
    bobRows.push({
      policy_id: s.policyId,
      carrier_policy_number: `POL-E5-${s.policyId}`,
      crm_policy_number: `CRM-E5-${s.policyId}`,
      enrollment_code: `EC-E5-${s.policyId}`,
      carrier: 'carrier_a',
      plan_type: 'MA',
      plan_name: `Plan E5 ${s.policyId}`,
      simple_plan_type: 'MA',
      mbi,
      member,
      dob: '1957-06-14',
      phone: `555-015-900${idx}`,
      email: `member.e5.${idx}@member.example`,
      address: `${s.policyId} Cedar Ave`,
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
      agency_id: `AG-E5-${idx}`,
      status: 'ACTIVE_PAYING',
      coherent_status: 'ACTIVE',
      conflicts: 'e5-conflict-note',
      spine_source: 'TX',
      confidence_level: 100,
      coherent_trajectory: 'STEADY',
    });
    const ledgerRow = {
      tx_id: s.policyId,
      record_id: recId,
      external_policy_id: `POL-E5-${s.policyId}`,
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
      agency_id: `AG-E5-${idx}`,
      status: 'ACTIVE_PAYING',
      policy_status: 'active',
      notes: 'e5 ledger note',
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
      reason: 'e5 stmt reason',
      notes: 'e5 stmt note',
    });
  });

  return {
    canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, bobRows),
    coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, ledgerRows),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, stmtRows),
  };
}

async function seedSentE5Run(env, { statementDate = '2026-11-15', keyPrefix = 'e5-sent' } = {}) {
  await seedStandingInput(env, { commandKey: `${keyPrefix}-standing` });
  const csvs = makeE5RunCsvs({ statementDate });
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
    inputVersion: { reason: `e5 run ${keyPrefix}` },
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
  if (!node || typeof node !== 'object') return out;
  for (const field of ['Filter', 'Index Cond', 'Recheck Cond', 'Hash Cond', 'Join Filter', 'One-Time Filter', 'Function Name', 'Subplan Name']) {
    if (typeof node[field] === 'string') out.push(node[field]);
  }
  if (Array.isArray(node.Output)) out.push(...node.Output.filter((x) => typeof x === 'string'));
  if (Array.isArray(node.Plans)) {
    for (const child of node.Plans) collectPlanRefStrings(child, out);
  }
  return out;
}

function inspectIamViewPlan(planRoot) {
  const initPlans = [];
  const perRowSubPlans = [];
  const highLoopNodes = [];
  const helperRe = /(_read_iam_|_visible_|_real_vendor|_strip_masked_vendors|effective_(wide|any)_org_ids|effective_narrow_pairs|person_effective_grants|session_context)/;

  function walk(node) {
    if (!node || typeof node !== 'object') return;
    const parentRel = node['Parent Relationship'] || '';
    const subplanName = node['Subplan Name'] || '';
    const loops = Number(node['Actual Loops'] || 0);
    if (parentRel === 'InitPlan' || subplanName.startsWith('InitPlan')) {
      initPlans.push({ subplanName, loops, refs: collectPlanRefStrings(node) });
    } else if (parentRel === 'SubPlan' || (subplanName.startsWith('SubPlan') && !subplanName.startsWith('hashed SubPlan'))) {
      const refs = collectPlanRefStrings(node);
      if (refs.some((s) => helperRe.test(s))) {
        perRowSubPlans.push({ subplanName, loops, nodeType: node['Node Type'] });
      }
    }
    const fnName = node['Function Name'] || '';
    if (helperRe.test(fnName) && loops > 1) {
      highLoopNodes.push({ fnName, loops, nodeType: node['Node Type'] });
    }
    if (Array.isArray(node.Plans)) {
      for (const child of node.Plans) walk(child);
    }
  }

  walk(planRoot);
  return { initPlans, perRowSubPlans, highLoopNodes };
}

test('Layer 7H [E5 Test 1]: vendor name masking by role in app_views.iam_organizations (direct & View-as), customer Nusear-staff confidentiality, InitPlan verification, and C3 bridge composition', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, tokenFor } = env.iam;

  const { createIamCommands } = await loadIamCmdModule();
  // Verify src/commands/command-layer.mjs was NOT recreated (C3 layout).
  await assert.rejects(
    () => access(new URL('../src/commands/command-layer.mjs', import.meta.url)),
    'src/commands/command-layer.mjs must not exist in C3 layout',
  );

  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const iamCmd = appCmdMod.createIamCommands({ pool: appPool });
  assert.equal(typeof createIamCommands, 'function');

  // Seed two lead vendors, company owner, and a vendor user using Nusear support (operatorToken).
  const supportTok = env.operatorToken;
  const cobaltOrg = (await iamCmd.createOrganization({
    dbToken: supportTok,
    commandKey: 'e5-t1-cobalt-org',
    orgKind: 'lead_vendor',
    slug: 'cobalt_leads',
    displayName: 'Cobalt Leads',
    parentOrgId: ids.companyOrg,
    maskedDisplayName: 'Vendor 01',
    externalDomain: 'cobalt.example',
  })).result.organizationId;

  const quartzOrg = (await iamCmd.createOrganization({
    dbToken: supportTok,
    commandKey: 'e5-t1-quartz-org',
    orgKind: 'lead_vendor',
    slug: 'quartz_leads',
    displayName: 'Quartz Leads',
    parentOrgId: ids.companyOrg,
    maskedDisplayName: 'Vendor 02',
    externalDomain: 'quartz.example',
  })).result.organizationId;

  const companyOwnerCreated = await iamCmd.createPerson({
    dbToken: supportTok,
    commandKey: 'e5-t1-company-owner',
    organizationId: ids.companyOrg,
    legalName: 'Casey Owner',
    preferredName: 'Casey Owner',
    primaryEmail: 'casey.owner@acme.example',
    workArrangement: 'employee',
    validRange: '[2020-01-01,)',
  });
  const companyOwnerId = companyOwnerCreated.result.personId;
  await iamCmd.grantRole({
    dbToken: supportTok,
    commandKey: 'e5-t1-company-owner-grant',
    personId: companyOwnerId,
    roleId: ids.roleOwner,
    organizationId: ids.companyOrg,
    personScopeMode: 'org_subtree',
    validRange: '[2020-01-01,)',
  });

  // Custom vendor role with act:iam.read + act:leads.vendor_bills.read (no col:vendors.real_name).
  const vendorRoleId = (await iamCmd.createRole({
    dbToken: supportTok,
    commandKey: 'e5-t1-vendor-role',
    ownerOrgId: ids.companyOrg,
    slug: 'lead_vendor_rep',
    displayName: 'Lead Vendor Rep',
    allowsOrgWideScope: true,
    forbidsCompanyRevenueRights: true,
  })).result.roleId;
  await iamCmd.setRoleRight({
    dbToken: supportTok,
    commandKey: 'e5-t1-vendor-role-r1',
    roleId: vendorRoleId,
    rightId: 'act:iam.read',
    status: 'active',
  });
  await iamCmd.setRoleRight({
    dbToken: supportTok,
    commandKey: 'e5-t1-vendor-role-r2',
    roleId: vendorRoleId,
    rightId: 'act:leads.vendor_bills.read',
    status: 'active',
  });

  const cobaltUserId = (await iamCmd.createPerson({
    dbToken: supportTok,
    commandKey: 'e5-t1-cobalt-user',
    organizationId: cobaltOrg,
    legalName: 'Quinn Cobalt',
    preferredName: 'Quinn Cobalt',
    primaryEmail: 'quinn@cobalt.example',
    workArrangement: 'employee',
    validRange: '[2020-01-01,)',
  })).result.personId;
  await iamCmd.grantRole({
    dbToken: supportTok,
    commandKey: 'e5-t1-cobalt-user-grant',
    personId: cobaltUserId,
    roleId: vendorRoleId,
    organizationId: cobaltOrg,
    personScopeMode: 'org_subtree',
    validRange: '[2020-01-01,)',
  });

  const queryVendors = async (tok) => withRequestTx(appPool, tok, async (tx) => (
    (await tx.query(
      `SELECT id, org_kind, slug, display_name, masked_display_name, external_domain, is_vendor_name_masked
       FROM app_views.iam_organizations
       WHERE org_kind = 'lead_vendor'
       ORDER BY masked_display_name`,
    )).rows
  ), { readOnly: true });

  // 1. Nusear staff (owner, support, admin), Company Owner, Entity Manager, Company Admin, Nusear Contractor see REAL vendor names.
  for (const [label, tok] of [
    ['nusear_owner', env.iam.tokens.owner],
    ['nusear_support', env.iam.tokens.operator],
    ['nusear_admin', env.iam.tokens.adminNoCoh],
    ['company_owner', tokenFor(companyOwnerId)],
    ['entity_manager', env.iam.tokens.entityMgr],
    ['company_admin', env.iam.tokens.companyAdmin],
    ['nusear_contractor', env.iam.tokens.nusearContractor],
  ]) {
    const rows = await queryVendors(tok);
    assert.deepEqual(
      rows.map((r) => ({ id: r.id, slug: r.slug, display_name: r.display_name, external_domain: r.external_domain, masked: r.is_vendor_name_masked })),
      [
        { id: cobaltOrg, slug: 'cobalt_leads', display_name: 'Cobalt Leads', external_domain: 'cobalt.example', masked: false },
        { id: quartzOrg, slug: 'quartz_leads', display_name: 'Quartz Leads', external_domain: 'quartz.example', masked: false },
      ],
      `${label} must see real vendor names, slugs, and domains`,
    );
  }

  // 2. Agency Manager, Selling Agent, Retention Agent see MASKED vendor names (slug & external_domain NULL).
  for (const [label, tok] of [
    ['agency_manager', env.iam.tokens.agencyMgr],
    ['selling_agent', env.iam.tokens.agentA],
    ['retention_agent', env.iam.tokens.retentionAgent],
    ['nusear_owner View-as selling_agent', tokenFor(ids.nusearOwner, ids.agentA)],
    ['nusear_owner View-as agency_manager', tokenFor(ids.nusearOwner, ids.beaconManager)],
    ['agency_manager View-as selling_agent', tokenFor(ids.beaconManager, ids.agentA)],
  ]) {
    const rows = await queryVendors(tok);
    assert.deepEqual(
      rows.map((r) => ({ id: r.id, slug: r.slug, display_name: r.display_name, external_domain: r.external_domain, masked: r.is_vendor_name_masked })),
      [
        { id: cobaltOrg, slug: null, display_name: 'Vendor 01', external_domain: null, masked: true },
        { id: quartzOrg, slug: null, display_name: 'Vendor 02', external_domain: null, masked: true },
      ],
      `${label} must see masked vendor names with NULL slug and external_domain`,
    );
  }

  // 3. Cobalt Leads's own user sees Cobalt Leads REAL and Quartz Leads MASKED (direct, Nusear Owner View-as, Company Owner View-as).
  for (const [label, tok] of [
    ['cobalt_user direct', tokenFor(cobaltUserId)],
    ['nusear_owner View-as cobalt_user', tokenFor(ids.nusearOwner, cobaltUserId)],
    ['company_owner View-as cobalt_user', tokenFor(companyOwnerId, cobaltUserId)],
  ]) {
    const rows = await queryVendors(tok);
    assert.deepEqual(
      rows.map((r) => ({ id: r.id, slug: r.slug, display_name: r.display_name, external_domain: r.external_domain, masked: r.is_vendor_name_masked })),
      [
        { id: cobaltOrg, slug: 'cobalt_leads', display_name: 'Cobalt Leads', external_domain: 'cobalt.example', masked: false },
        { id: quartzOrg, slug: null, display_name: 'Vendor 02', external_domain: null, masked: true },
      ],
      `${label} must see own vendor real and sibling vendor masked`,
    );
    const agencies = await withRequestTx(appPool, tok, async (tx) => (
      tx.query("SELECT id FROM app_views.iam_organizations WHERE org_kind IN ('company', 'agency', 'team')")
    ), { readOnly: true });
    assert.deepEqual(agencies.rows, [], `${label} must see zero company/agency/team rows`);
  }

  // 4. Investor (0 rights), disjoint View-as, wrong-company operator, and unauthenticated caller see 0 rows.
  for (const [label, tok] of [
    ['investor', env.iam.tokens.investor],
    ['nusear_owner View-as investor', tokenFor(ids.nusearOwner, ids.investor)],
    ['agency_manager View-as cobalt_user (disjoint orgs)', tokenFor(ids.beaconManager, cobaltUserId)],
    ['wrongCoOperator', env.iam.tokens.wrongCoOperator],
    ['unauthenticated', ''],
  ]) {
    const rows = await queryVendors(tok);
    assert.deepEqual(rows, [], `${label} must see 0 rows in app_views.iam_organizations`);
    const myCtx = await withRequestTx(appPool, tok, (tx) => tx.query('SELECT * FROM app_views.iam_my_context'), { readOnly: true });
    assert.deepEqual(myCtx.rows, [], `${label} must see 0 rows in app_views.iam_my_context`);
  }

  // 5. Customer views never expose nusear_staff/service people or internal roles in app_views.iam_people / iam_roles.
  await withRequestTx(appPool, tokenFor(companyOwnerId), async (tx) => {
    const staffRows = (await tx.query("SELECT id FROM app_views.iam_people WHERE principal_origin <> 'company_local'")).rows;
    assert.deepEqual(staffRows, [], 'company owner must see zero nusear_staff/service rows in app_views.iam_people');
    const intRoles = (await tx.query('SELECT slug FROM app_views.iam_roles WHERE is_nusear_internal = true')).rows;
    assert.deepEqual(intRoles, [], 'company owner must see zero is_nusear_internal roles in app_views.iam_roles');
  }, { readOnly: true });
  await withRequestTx(appPool, tokenFor(ids.nusearOwner, companyOwnerId), async (tx) => {
    const staffRows = (await tx.query("SELECT id FROM app_views.iam_people WHERE principal_origin <> 'company_local'")).rows;
    assert.deepEqual(staffRows, [], 'nusear_owner View-as company_owner must see zero nusear_staff/service rows');
  }, { readOnly: true });
  await withRequestTx(appPool, env.iam.tokens.owner, async (tx) => {
    const staffRows = (await tx.query("SELECT id FROM app_views.iam_people WHERE principal_origin = 'nusear_staff'")).rows;
    assert.ok(staffRows.length >= 1, 'nusear_owner direct sees nusear_staff in app_views.iam_people');
  }, { readOnly: true });

  // 6. EXPLAIN InitPlan check on app_views.iam_organizations and app_views.iam_people,
  //    plus smoke checks on iam_my_context, iam_memberships, iam_agent_affiliations, iam_tool_switches.
  for (const [who, tok] of [
    ['cobalt_user', tokenFor(cobaltUserId)],
    ['agency_manager', env.iam.tokens.agencyMgr],
  ]) {
    for (const viewName of ['iam_organizations', 'iam_people']) {
      const plan = await withRequestTx(appPool, tok, async (tx) => (
        (await tx.query(`EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT * FROM app_views.${viewName}`)).rows[0]['QUERY PLAN'][0].Plan
      ), { readOnly: true });
      const stats = inspectIamViewPlan(plan);
      assert.deepEqual(stats.perRowSubPlans, [], `${who} on ${viewName} must have 0 per-row SubPlans`);
      assert.deepEqual(stats.highLoopNodes, [], `${who} on ${viewName} must evaluate read helpers at most once`);
    }
  }

  await withRequestTx(appPool, env.iam.tokens.agentA, async (tx) => {
    const ctx = (await tx.query('SELECT actor_person_id, effective_person_id, is_viewing_as FROM app_views.iam_my_context')).rows;
    assert.equal(ctx.length, 1);
    assert.equal(ctx[0].effective_person_id, ids.agentA);
    assert.equal(ctx[0].is_viewing_as, false);
    const people = (await tx.query('SELECT id FROM app_views.iam_people')).rows.map((r) => r.id);
    assert.deepEqual(people, [ids.agentA], 'self-scoped agent sees strictly self in app_views.iam_people');
    const affs = (await tx.query('SELECT person_id, npn FROM app_views.iam_agent_affiliations')).rows;
    assert.deepEqual(affs, [{ person_id: ids.agentA, npn: '11111111' }]);
  }, { readOnly: true });

  // Nusear support toggles tool switch on Beacon -> recorded as nusear_support with target_org_id = beaconOrg.
  const swOut = await iamCmd.setToolSwitch({
    dbToken: supportTok,
    commandKey: 'e5-t1-support-vendors-held',
    organizationId: ids.beaconOrg,
    toolId: 'vendors',
    switchState: 'held',
    holdReason: 'Vendor audit hold',
  });
  assert.equal(swOut.result.switchState, 'held');
  const auditRow = (await env.pool.query(
    'SELECT recorded_as, target_org_id FROM platform.audit_journal WHERE seq = $1',
    [swOut.journalSeq],
  )).rows[0];
  assert.deepEqual(auditRow, { recorded_as: 'nusear_support', target_org_id: ids.beaconOrg });
  await withRequestTx(appPool, tokenFor(companyOwnerId), async (tx) => {
    const sw = (await tx.query(
      "SELECT organization_id, tool_id, switch_state, hold_reason FROM app_views.iam_tool_switches WHERE organization_id = $1 AND tool_id = 'vendors'",
      [ids.beaconOrg],
    )).rows;
    assert.deepEqual(sw, [{ organization_id: ids.beaconOrg, tool_id: 'vendors', switch_state: 'held', hold_reason: 'Vendor audit hold' }]);
  }, { readOnly: true });
});

test('Layer 7H [E5 Test 2]: creating a person creates their first works-for line atomically, revoking one role ends only that dated line, and suspending a person zeroes reads and blocks writes immediately while keeping writing_person_id intact', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, tokenFor } = env.iam;

  await seedSentE5Run(env);

  await loadIamCmdModule();
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const iamCmd = appCmdMod.createIamCommands({ pool: appPool });
  const supportTok = env.operatorToken;

  // 1. Creating a person creates their first works-for line in the SAME command so no person is unseen or unanchored.
  const dualCreated = await iamCmd.createPerson({
    dbToken: supportTok,
    commandKey: 'e5-t2-dual-person',
    organizationId: ids.companyOrg,
    legalName: 'Morgan Dual',
    preferredName: 'Morgan Dual',
    primaryEmail: 'morgan.dual@acme.example',
    workArrangement: null,
    validRange: '[2020-01-01,)',
  });
  const dualUser = dualCreated.result.personId;
  assert.ok(dualCreated.result.membershipId, 'createPerson must return the created initial membershipId');
  assert.equal(dualCreated.result.organizationId, ids.companyOrg);
  assert.equal(dualCreated.result.workArrangement, null, 'workArrangement must stay NULL when omitted (no employee default)');

  // Immediately visible in app_views.iam_people and app_views.iam_memberships WITHOUT a separate setMembership call!
  await withRequestTx(appPool, env.iam.tokens.entityMgr, async (tx) => {
    const pRows = (await tx.query('SELECT id, preferred_name FROM app_views.iam_people WHERE id = $1', [dualUser])).rows;
    assert.deepEqual(pRows, [{ id: dualUser, preferred_name: 'Morgan Dual' }], 'new person must be immediately visible in app_views.iam_people');
    const mRows = (await tx.query('SELECT id, organization_id, work_arrangement, status FROM app_views.iam_memberships WHERE person_id = $1', [dualUser])).rows;
    assert.deepEqual(
      mRows,
      [{ id: dualCreated.result.membershipId, organization_id: ids.companyOrg, work_arrangement: null, status: 'active' }],
      'new person must immediately have their first active works-for line in app_views.iam_memberships',
    );
  }, { readOnly: true });

  // Also test default validRange (omitted -> open-ended from business_today).
  const defaultRangePerson = await iamCmd.createPerson({
    dbToken: supportTok,
    commandKey: 'e5-t2-default-range-person',
    organizationId: ids.beaconOrg,
    legalName: 'Jordan DefaultRange',
    preferredName: 'Jordan DefaultRange',
    primaryEmail: 'jordan.def@acme.example',
  });
  assert.ok(defaultRangePerson.result.membershipId, 'createPerson with omitted validRange must still create initial membership');
  await withRequestTx(appPool, env.iam.tokens.agencyMgr, async (tx) => {
    const seen = (await tx.query('SELECT id FROM app_views.iam_people WHERE id = $1', [defaultRangePerson.result.personId])).rows;
    assert.equal(seen.length, 1, 'person created on Beacon must be immediately visible to Beacon agency manager');
  }, { readOnly: true });

  // 2. Multi-role person holding BOTH owner AND investor at companyOrg; drop ONLY owner -> investor stays active.
  const ownerGrantId = (await iamCmd.grantRole({
    dbToken: supportTok,
    commandKey: 'e5-t2-dual-owner-grant',
    personId: dualUser,
    roleId: ids.roleOwner,
    organizationId: ids.companyOrg,
    personScopeMode: 'org_subtree',
    validRange: '[2020-01-01,)',
  })).result.roleGrantId;
  const investorGrantId = (await iamCmd.grantRole({
    dbToken: supportTok,
    commandKey: 'e5-t2-dual-investor-grant',
    personId: dualUser,
    roleId: ids.roleInvestor,
    organizationId: ids.companyOrg,
    personScopeMode: 'org_subtree',
    validRange: '[2020-01-01,)',
  })).result.roleGrantId;

  await withRequestTx(appPool, tokenFor(dualUser), async (tx) => {
    assert.ok((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n > 0);
    assert.ok((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.iam_organizations')).rows[0].n > 0);
  }, { readOnly: true });

  const revokeOut = await iamCmd.revokeRoleGrant({
    dbToken: supportTok,
    commandKey: 'e5-t2-revoke-owner-only',
    roleGrantId: ownerGrantId,
  });
  assert.equal(revokeOut.idempotent, false);
  assert.equal(revokeOut.result.status, 'revoked');
  assert.equal(revokeOut.result.replacesGrantId, ownerGrantId);
  const revokeReplay = await iamCmd.revokeRoleGrant({
    dbToken: supportTok,
    commandKey: 'e5-t2-revoke-owner-only',
    roleGrantId: ownerGrantId,
  });
  assert.equal(revokeReplay.idempotent, true);
  assert.equal(revokeReplay.result.revokedGrantId, revokeOut.result.revokedGrantId);

  await withRequestTx(appPool, supportTok, async (tx) => {
    const grants = (await tx.query(
      'SELECT id, role_slug, status FROM app_views.iam_role_grants WHERE person_id = $1 ORDER BY role_slug',
      [dualUser],
    )).rows;
    assert.deepEqual(
      grants.map((g) => ({ role_slug: g.role_slug, status: g.status })),
      [
        { role_slug: 'investor', status: 'active' },
        { role_slug: 'owner', status: 'revoked' },
      ],
      'revoking owner must end only the owner line and keep investor active',
    );
    assert.equal(grants.find((g) => g.role_slug === 'investor').id, investorGrantId);
  }, { readOnly: true });

  await withRequestTx(appPool, tokenFor(dualUser), async (tx) => {
    assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n, 0);
    assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.iam_organizations')).rows[0].n, 0);
  }, { readOnly: true });

  // Sibling active rights: agentA granted director_of_sales + selling_agent; drop director_of_sales -> selling_agent keeps working.
  const salesDirGrantId = (await iamCmd.grantRole({
    dbToken: supportTok,
    commandKey: 'e5-t2-agentA-salesdir',
    personId: ids.agentA,
    roleId: ids.roleDirectorOfSales,
    organizationId: ids.beaconOrg,
    personScopeMode: 'org_subtree',
    validRange: '[2020-01-01,)',
  })).result.roleGrantId;
  await withRequestTx(appPool, env.iam.tokens.agentA, async (tx) => {
    assert.equal((await tx.query("SELECT iam.has_right('act:leads.costs.read') AS ok")).rows[0].ok, true);
  }, { readOnly: true });
  await iamCmd.revokeRoleGrant({
    dbToken: supportTok,
    commandKey: 'e5-t2-revoke-agentA-salesdir',
    roleGrantId: salesDirGrantId,
  });
  await withRequestTx(appPool, env.iam.tokens.agentA, async (tx) => {
    assert.equal((await tx.query("SELECT iam.has_right('act:leads.costs.read') AS ok")).rows[0].ok, false, 'revoked director_of_sales right must drop immediately');
    const bob = (await tx.query('SELECT writing_npn FROM app_views.coherence_bob')).rows;
    assert.deepEqual(bob.map((r) => r.writing_npn), ['11111111'], 'sibling selling_agent line must stay active');
  }, { readOnly: true });

  // 3. Suspending a person immediately zeroes all reads and blocks writes while keeping writing_person_id intact.
  const writerMgrId = (await iamCmd.createPerson({
    dbToken: supportTok,
    commandKey: 'e5-t2-writer-mgr',
    organizationId: ids.companyOrg,
    legalName: 'Robin Manager',
    preferredName: 'Robin Manager',
    primaryEmail: 'robin.mgr@acme.example',
    workArrangement: 'employee',
    validRange: '[2020-01-01,)',
  })).result.personId;
  await iamCmd.grantRole({
    dbToken: supportTok,
    commandKey: 'e5-t2-writer-mgr-grant',
    personId: writerMgrId,
    roleId: ids.roleOwner,
    organizationId: ids.companyOrg,
    personScopeMode: 'org_subtree',
    validRange: '[2020-01-01,)',
  });

  // Positive control BEFORE suspension: writerMgr reads BoB + IAM and passes assert_can_write('act:hr.records.write').
  const writerMgrTok = tokenFor(writerMgrId);
  await withRequestTx(appPool, writerMgrTok, async (tx) => {
    assert.ok((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n > 0);
    const wr = (await tx.query("SELECT actor_person_id, recorded_as FROM iam.assert_can_write('act:hr.records.write', $1::uuid)", [ids.companyOrg])).rows[0];
    assert.deepEqual(wr, { actor_person_id: writerMgrId, recorded_as: 'self' });
  }, { readOnly: false });

  // Suspend both agentA and writerMgr via app_cmd.iam_set_person_status.
  const suspAgent = await iamCmd.setPersonStatus({
    dbToken: supportTok,
    commandKey: 'e5-t2-suspend-agentA',
    personId: ids.agentA,
    status: 'suspended',
  });
  assert.equal(suspAgent.result.status, 'suspended');
  const suspMgr = await iamCmd.setPersonStatus({
    dbToken: supportTok,
    commandKey: 'e5-t2-suspend-mgr',
    personId: writerMgrId,
    status: 'suspended',
  });
  assert.equal(suspMgr.result.status, 'suspended');

  // Reads zeroed immediately for both suspended users; write guard fails 42501 immediately.
  for (const [label, tok] of [['suspended agentA', env.iam.tokens.agentA], ['suspended writerMgr', writerMgrTok]]) {
    await withRequestTx(appPool, tok, async (tx) => {
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n, 0, `${label} must see 0 BoB rows`);
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.iam_organizations')).rows[0].n, 0, `${label} must see 0 IAM org rows`);
    }, { readOnly: true });
  }
  await assert.rejects(
    () => withRequestTx(appPool, writerMgrTok, (tx) => tx.query("SELECT * FROM iam.assert_can_write('act:hr.records.write', $1::uuid)", [ids.companyOrg]), { readOnly: false }),
    (err) => err?.code === '42501',
    'suspended writerMgr must be blocked from writes immediately',
  );

  // Historical writing_person_id integrity on agentA's policies stays intact!
  const histBob = await withRequestTx(appPool, env.iam.tokens.entityMgr, async (tx) => (
    (await tx.query('SELECT writing_person_id, writing_npn FROM app_views.coherence_bob WHERE writing_npn = $1', ['11111111'])).rows
  ), { readOnly: true });
  assert.equal(histBob.length, 1);
  assert.equal(histBob[0].writing_person_id, ids.agentA, 'suspending agentA must preserve historical writing_person_id');
});

test('Layer 7H [E5 Test 3]: data invariants - new roles start empty, role copy keeps catalog constraints, selling/retention agents and copies stay self-only, external_upline stays under platform_root, and explicit_people carries over and stays inside the company tree', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, tokenFor } = env.iam;

  await seedSentE5Run(env);

  await loadIamCmdModule();
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const iamCmd = appCmdMod.createIamCommands({ pool: appPool });
  const supportTok = env.operatorToken;

  // 3a. Empty new role + copy role keeping constraints + idempotency.
  await t.test('3a: new role starts empty; copyRole copies rights and preserves forbids_company_revenue_rights, allows_org_wide_scope, and requires_self_scope', async () => {
    const emptyRoleId = (await iamCmd.createRole({
      dbToken: supportTok,
      commandKey: 'e5-t3a-empty-role',
      ownerOrgId: ids.companyOrg,
      slug: 'fresh_empty_role',
      displayName: 'Fresh Empty Role',
    })).result.roleId;

    await withRequestTx(appPool, supportTok, async (tx) => {
      const rr = (await tx.query("SELECT right_id FROM app_views.iam_role_rights WHERE role_id = $1 AND status = 'active'", [emptyRoleId])).rows;
      assert.deepEqual(rr, [], 'new role created via app_cmd.iam_create_role must start completely empty');
    }, { readOnly: true });

    const copyRes = await iamCmd.copyRole({
      dbToken: supportTok,
      commandKey: 'e5-t3a-copy-agent',
      sourceRoleId: ids.roleSellingAgent,
      ownerOrgId: ids.companyOrg,
      newSlug: 'custom_field_agent',
      newDisplayName: 'Custom Field Agent',
      addRightIds: ['act:hr.records.write'],
      removeRightIds: ['act:referrals.read'],
    });
    assert.equal(copyRes.idempotent, false);
    const copiedRoleId = copyRes.result.roleId;

    const replay = await iamCmd.copyRole({
      dbToken: supportTok,
      commandKey: 'e5-t3a-copy-agent',
      sourceRoleId: ids.roleSellingAgent,
      ownerOrgId: ids.companyOrg,
      newSlug: 'custom_field_agent',
      newDisplayName: 'Custom Field Agent',
      addRightIds: ['act:hr.records.write'],
      removeRightIds: ['act:referrals.read'],
    });
    assert.equal(replay.idempotent, true);
    assert.equal(replay.result.roleId, copiedRoleId);
    await assert.rejects(
      () => iamCmd.copyRole({
        dbToken: supportTok,
        commandKey: 'e5-t3a-copy-agent',
        sourceRoleId: ids.roleSellingAgent,
        ownerOrgId: ids.companyOrg,
        newSlug: 'custom_field_agent_other',
        newDisplayName: 'Other Name',
      }),
      (err) => err?.status === 409 && err?.code === 'COMMAND_KEY_CONFLICT',
    );

    await withRequestTx(appPool, supportTok, async (tx) => {
      const roleRow = (await tx.query(
        'SELECT slug, display_name, allows_org_wide_scope, requires_self_scope, forbids_company_revenue_rights, is_nusear_internal FROM app_views.iam_roles WHERE id = $1',
        [copiedRoleId],
      )).rows[0];
      assert.deepEqual(roleRow, {
        slug: 'custom_field_agent',
        display_name: 'Custom Field Agent',
        allows_org_wide_scope: false,
        requires_self_scope: true,
        forbids_company_revenue_rights: true,
        is_nusear_internal: false,
      });

      const rights = (await tx.query(
        "SELECT right_id FROM app_views.iam_role_rights WHERE role_id = $1 AND status = 'active' ORDER BY right_id",
        [copiedRoleId],
      )).rows.map((r) => r.right_id);
      assert.ok(rights.includes('act:payroll.agent_pay.read'), 'copied agent keeps own-pay read');
      assert.ok(rights.includes('col:payroll.agent_pay_cash'), 'copied agent keeps own-pay cash');
      assert.ok(rights.includes('act:hr.records.write'), 'copied agent includes added right');
      assert.ok(!rights.includes('act:referrals.read'), 'copied agent omits removed right');
    }, { readOnly: true });

    for (const revRight of ['col:coherence.statement_cash', 'act:coherence.upline.read', 'col:coherence.upline_cash']) {
      await assert.rejects(
        () => iamCmd.setRoleRight({
          dbToken: supportTok,
          commandKey: `e5-t3a-forbid-${revRight}`,
          roleId: copiedRoleId,
          rightId: revRight,
          status: 'active',
        }),
        (err) => err?.status === 409 && err?.code === 'COMPANY_REVENUE_RIGHT_FORBIDDEN',
        `copied selling_agent must refuse ${revRight}`,
      );
    }

    await assert.rejects(
      () => iamCmd.copyRole({
        dbToken: supportTok,
        commandKey: 'e5-t3a-copy-with-rev',
        sourceRoleId: ids.roleSellingAgent,
        ownerOrgId: ids.companyOrg,
        newSlug: 'bad_agent_copy',
        newDisplayName: 'Bad Agent Copy',
        addRightIds: ['col:coherence.statement_cash'],
      }),
      (err) => err?.status === 409 && err?.code === 'COMPANY_REVENUE_RIGHT_FORBIDDEN',
    );

    await assert.rejects(
      () => iamCmd.setRoleRight({
        dbToken: supportTok,
        commandKey: 'e5-t3a-forbid-internal-right',
        roleId: emptyRoleId,
        rightId: 'col:platform.audit_journal.nusear_actor',
        status: 'active',
      }),
      (err) => err?.status === 403,
    );

    await iamCmd.updateRole({
      dbToken: supportTok,
      commandKey: 'e5-t3a-rename-copied',
      roleId: copiedRoleId,
      displayName: 'Senior Field Agent',
    });
    await withRequestTx(appPool, supportTok, async (tx) => {
      const r = (await tx.query('SELECT display_name, allows_org_wide_scope, requires_self_scope, forbids_company_revenue_rights FROM app_views.iam_roles WHERE id = $1', [copiedRoleId])).rows[0];
      assert.deepEqual(r, { display_name: 'Senior Field Agent', allows_org_wide_scope: false, requires_self_scope: true, forbids_company_revenue_rights: true });
    }, { readOnly: true });
  });

  // 3b. Built-in and copied selling_agent / retention_agent grants are self-only (commands + direct SQL).
  await t.test('3b: selling_agent, retention_agent, and their copies stay self-only via requires_self_scope', async () => {
    const newAgentId = (await iamCmd.createPerson({
      dbToken: supportTok,
      commandKey: 'e5-t3b-person',
      organizationId: ids.beaconOrg,
      legalName: 'Taylor SelfOnly',
      preferredName: 'Taylor SelfOnly',
      primaryEmail: 'taylor.self@acme.example',
      npn: '77777777',
      validRange: '[2020-01-01,)',
    })).result.personId;
    await iamCmd.setAgentAffiliation({
      dbToken: supportTok,
      commandKey: 'e5-t3b-aff',
      personId: newAgentId,
      npn: '77777777',
      agencyOrgId: ids.beaconOrg,
      splitBps: 8000,
      agentFileName: 'Taylor SelfOnly',
      validRange: '[2020-01-01,)',
    });

    const copiedRetentionId = (await iamCmd.copyRole({
      dbToken: supportTok,
      commandKey: 'e5-t3b-copy-retention',
      sourceRoleId: ids.roleRetentionAgent,
      ownerOrgId: ids.companyOrg,
      newSlug: 'copied_retention_agent',
      newDisplayName: 'Copied Retention Agent',
    })).result.roleId;
    const copiedSellingId = (await iamCmd.copyRole({
      dbToken: supportTok,
      commandKey: 'e5-t3b-copy-selling',
      sourceRoleId: ids.roleSellingAgent,
      ownerOrgId: ids.companyOrg,
      newSlug: 'copied_selling_agent',
      newDisplayName: 'Copied Selling Agent',
    })).result.roleId;

    for (const [roleLabel, roleId] of [
      ['selling_agent', ids.roleSellingAgent],
      ['retention_agent', ids.roleRetentionAgent],
      ['copied_selling_agent', copiedSellingId],
      ['copied_retention_agent', copiedRetentionId],
    ]) {
      for (const badMode of ['org_subtree', 'explicit_people']) {
        const expectedCode = badMode === 'org_subtree' ? 'ORG_WIDE_SCOPE_FORBIDDEN' : 'AGENT_GRANT_SELF_ONLY';
        await assert.rejects(
          () => iamCmd.grantRole({
            dbToken: supportTok,
            commandKey: `e5-t3b-${roleLabel}-${badMode}`,
            personId: newAgentId,
            roleId,
            organizationId: ids.beaconOrg,
            personScopeMode: badMode,
            validRange: '[2020-01-01,)',
          }),
          (err) => err?.status === 409 && err?.code === expectedCode,
          `${roleLabel} grant with personScopeMode=${badMode} must be refused ${expectedCode}`,
        );
      }
      await assert.rejects(
        () => inSerializableTx(env.pool, async (c) => {
          const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: ids.beaconOrg, commandKey: `e5-t3b-sql-${roleLabel}-${randomUUID()}` })).seq;
          await c.query(
            "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'explicit_people','[2020-01-01,)'::daterange,'active',$5)",
            [randomUUID(), newAgentId, roleId, ids.beaconOrg, seq],
          );
        }),
        (err) => err?.code === '23514' && /AGENT_GRANT_SELF_ONLY/.test(err?.message || ''),
        `direct SQL explicit_people grant of ${roleLabel} must fail trigger with 23514 AGENT_GRANT_SELF_ONLY`,
      );
      const ok = await iamCmd.grantRole({
        dbToken: supportTok,
        commandKey: `e5-t3b-${roleLabel}-self`,
        personId: newAgentId,
        roleId,
        organizationId: ids.beaconOrg,
        personScopeMode: 'self',
        validRange: '[2020-01-01,)',
      });
      assert.equal(ok.result.personScopeMode, 'self');
    }
  });

  // 3c. external_upline stays attached under platform_root open-ended from today.
  await t.test('3c: external_upline attaches under platform_root open-ended from today and refuses non-root parent, future start, finite range, or detachment', async () => {
    await assert.rejects(
      () => iamCmd.createOrganization({
        dbToken: supportTok,
        commandKey: 'e5-t3c-ext-bad-parent',
        orgKind: 'external_upline',
        slug: 'bad_ext_upline',
        displayName: 'Bad External Upline',
        parentOrgId: ids.companyOrg,
      }),
      (err) => err?.status === 409 && err?.code === 'EXTERNAL_UPLINE_PARENT_MUST_BE_ROOT',
    );
    await assert.rejects(
      () => iamCmd.createOrganization({
        dbToken: supportTok,
        commandKey: 'e5-t3c-ext-future',
        orgKind: 'external_upline',
        slug: 'future_ext_upline',
        displayName: 'Future Ext Upline',
        validFrom: '2099-01-01',
      }),
      (err) => err?.status === 409 && /EXTERNAL_UPLINE/.test(err?.code || ''),
    );

    const extCreated = await iamCmd.createOrganization({
      dbToken: supportTok,
      commandKey: 'e5-t3c-ext-ok',
      orgKind: 'external_upline',
      slug: 'other_upline',
      displayName: 'Other Upline',
    });
    const extOrgId = extCreated.result.organizationId;
    const extEdgeId = extCreated.result.edgeId;
    assert.equal(extCreated.result.parentOrgId, ids.rootOrg);

    await withRequestTx(appPool, supportTok, async (tx) => {
      const edges = (await tx.query(
        "SELECT id, parent_org_id, status FROM app_views.iam_organization_edges WHERE child_org_id = $1 AND status = 'active'",
        [extOrgId],
      )).rows;
      assert.equal(edges.length, 1);
      assert.equal(edges[0].parent_org_id, ids.rootOrg);
    }, { readOnly: true });

    for (const [label, params] of [
      ['reparent under company', { parentOrgId: ids.companyOrg, validRange: '[2020-01-01,)', status: 'active' }],
      ['revoke root edge', { parentOrgId: ids.rootOrg, validRange: '[2020-01-01,)', status: 'revoked' }],
      ['future-dated range', { parentOrgId: ids.rootOrg, validRange: '[2099-01-01,)', status: 'active' }],
      ['finite upper bound', { parentOrgId: ids.rootOrg, validRange: '[2020-01-01,2028-01-01)', status: 'active' }],
    ]) {
      await assert.rejects(
        () => iamCmd.setOrganizationEdge({
          dbToken: supportTok,
          commandKey: `e5-t3c-ext-bad-${label}`,
          childOrgId: extOrgId,
          replacesEdgeId: extEdgeId,
          ...params,
        }),
        (err) => err?.status === 409 && /EXTERNAL_UPLINE/.test(err?.code || ''),
        `external_upline ${label} must be refused`,
      );
    }

    const agencyCreated = await iamCmd.createOrganization({
      dbToken: supportTok,
      commandKey: 'e5-t3c-moved-ag',
      orgKind: 'agency',
      slug: 'departing_agency',
      displayName: 'Departing Agency',
      parentOrgId: ids.companyOrg,
      validFrom: '2024-01-01',
    });
    const movedAgId = agencyCreated.result.organizationId;
    const oldAgEdgeId = agencyCreated.result.edgeId;
    const moveRes = await iamCmd.setOrganizationEdge({
      dbToken: supportTok,
      commandKey: 'e5-t3c-move-ag-to-ext',
      childOrgId: movedAgId,
      parentOrgId: extOrgId,
      validRange: '[2026-08-01,)',
      closeEdgeId: oldAgEdgeId,
      closeValidRange: '[2024-01-01,2026-08-01)',
      status: 'active',
    });
    assert.ok(moveRes.result.edgeId);
  });

  // 3d. explicit_people carry-over AND subjects must lie inside the company's own tree.
  await t.test('3d: explicit_people carries active subjects on supersession and refuses subjects outside the company tree (command + direct SQL)', async () => {
    const northstarPersonId = randomUUID();
    await inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: ids.northstarOrg, commandKey: `e5-t3d-ns-${randomUUID()}` })).seq;
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','company_local',$2)", [northstarPersonId, seq]);
      await c.query("INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'company_local','Nova Northstar','Nova Northstar','nova@northstar.example','active',$3)", [randomUUID(), northstarPersonId, seq]);
      await c.query("INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), northstarPersonId, ids.northstarOrg, seq]);
    });

    const compId = (await iamCmd.createPerson({
      dbToken: supportTok,
      commandKey: 'e5-t3d-comp-person',
      organizationId: ids.beaconOrg,
      legalName: 'Drew CarryComp',
      preferredName: 'Drew CarryComp',
      primaryEmail: 'drew.carry@acme.example',
      workArrangement: 'employee',
      validRange: '[2020-01-01,)',
    })).result.personId;

    // Refuses northstarPerson (outside Acme's tree) during grantRole -> nothing written!
    await assertRefusedNoWrite(
      env.pool,
      ['iam.role_grants', 'iam.role_grant_people'],
      () => iamCmd.grantRole({
        dbToken: supportTok,
        commandKey: 'e5-t3d-bad-ns-grant',
        personId: compId,
        roleId: ids.roleCompliance,
        organizationId: ids.beaconOrg,
        personScopeMode: 'explicit_people',
        validRange: '[2020-01-01,)',
        subjectPersonIds: [northstarPersonId],
      }),
      (err) => err?.status === 409 && err?.code === 'EXPLICIT_PEOPLE_OUTSIDE_COMPANY',
      'grantRole must refuse explicit_people subject outside the company tree',
    );

    const g1 = (await iamCmd.grantRole({
      dbToken: supportTok,
      commandKey: 'e5-t3d-comp-grant-1',
      personId: compId,
      roleId: ids.roleCompliance,
      organizationId: ids.beaconOrg,
      personScopeMode: 'explicit_people',
      validRange: '[2020-01-01,)',
      subjectPersonIds: [ids.agentA, ids.agentEast, ids.agentB],
    })).result.roleGrantId;

    // Refuses northstarPerson on setRoleGrantPerson AND on direct SQL INSERT!
    await assertRefusedNoWrite(
      env.pool,
      'iam.role_grant_people',
      () => iamCmd.setRoleGrantPerson({
        dbToken: supportTok,
        commandKey: 'e5-t3d-bad-ns-rgp',
        roleGrantId: g1,
        subjectPersonId: northstarPersonId,
        status: 'active',
      }),
      (err) => err?.status === 409 && err?.code === 'EXPLICIT_PEOPLE_OUTSIDE_COMPANY',
      'setRoleGrantPerson must refuse explicit_people subject outside the company tree',
    );
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: ids.beaconOrg, commandKey: `e5-t3d-sql-ns-${randomUUID()}` })).seq;
        await c.query(
          "INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), g1, northstarPersonId, seq],
        );
      }),
      (err) => err?.code === '23514' && /EXPLICIT_PEOPLE_OUTSIDE_COMPANY/.test(err?.message || ''),
      'direct SQL role_grant_people insert for subject outside company tree must fail 23514 EXPLICIT_PEOPLE_OUTSIDE_COMPANY',
    );

    // Revoke agentB on g1 so only {agentA, agentEast} remain active, then supersede g1 -> g2.
    await iamCmd.setRoleGrantPerson({
      dbToken: supportTok,
      commandKey: 'e5-t3d-revoke-agentB',
      roleGrantId: g1,
      subjectPersonId: ids.agentB,
      status: 'revoked',
    });

    const g2Out = await iamCmd.grantRole({
      dbToken: supportTok,
      commandKey: 'e5-t3d-comp-grant-2',
      personId: compId,
      roleId: ids.roleCompliance,
      organizationId: ids.beaconOrg,
      personScopeMode: 'explicit_people',
      validRange: '[2020-01-01,2029-01-01)',
      replacesGrantId: g1,
    });
    const g2 = g2Out.result.roleGrantId;
    assert.notEqual(g2, g1);
    const g2Replay = await iamCmd.grantRole({
      dbToken: supportTok,
      commandKey: 'e5-t3d-comp-grant-2',
      personId: compId,
      roleId: ids.roleCompliance,
      organizationId: ids.beaconOrg,
      personScopeMode: 'explicit_people',
      validRange: '[2020-01-01,2029-01-01)',
      replacesGrantId: g1,
    });
    assert.equal(g2Replay.idempotent, true);
    assert.equal(g2Replay.result.roleGrantId, g2);
    assert.deepEqual([...g2Out.result.subjectPersonIds].sort(), [ids.agentA, ids.agentEast].sort());

    await withRequestTx(appPool, tokenFor(compId), async (tx) => {
      const npns = (await tx.query('SELECT writing_npn FROM app_views.coherence_bob ORDER BY writing_npn')).rows.map((r) => r.writing_npn);
      assert.deepEqual(npns, ['11111111', '44444444']);
    }, { readOnly: true });

    // Direct SQL supersession of g2 -> g3 also carries active subjects via trg_02_carry_explicit_people.
    const g3 = randomUUID();
    await inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: ids.beaconOrg, commandKey: `e5-direct-carry-${randomUUID()}` })).seq;
      await c.query(
        `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, replaces_id, journal_seq)
         VALUES ($1,$2,$3,$4,true,'explicit_people','[2020-01-01,2030-01-01)'::daterange,'active',$5,$6)`,
        [g3, compId, ids.roleCompliance, ids.beaconOrg, g2, seq],
      );
    });
    await withRequestTx(appPool, supportTok, async (tx) => {
      const unfiltered = (await tx.query(
        'SELECT role_grant_id, subject_person_id, status FROM app_views.iam_role_grant_people ORDER BY role_grant_id, subject_person_id',
      )).rows;
      assert.deepEqual(
        unfiltered,
        [ids.agentA, ids.agentEast].sort().map((sid) => ({ role_grant_id: g3, subject_person_id: sid, status: 'active' })),
        'unfiltered app_views.iam_role_grant_people must omit superseded grants g1 and g2 and show only live grant g3',
      );
    }, { readOnly: true });

    // Attach a Harbor agent (inside Acme tree, outside Beacon manager's scope) to g3;
    // unfiltered app_views.iam_role_grant_people must show only visible subjects to Beacon manager.
    await iamCmd.setRoleGrantPerson({
      dbToken: supportTok,
      commandKey: 'e5-t3d-add-agentHarbor-g3',
      roleGrantId: g3,
      subjectPersonId: ids.agentHarbor,
      status: 'active',
    });
    await withRequestTx(appPool, env.iam.tokens.agencyMgr, async (tx) => {
      const seen = (await tx.query(
        'SELECT role_grant_id, subject_person_id, status FROM app_views.iam_role_grant_people ORDER BY subject_person_id',
      )).rows;
      assert.deepEqual(
        seen,
        [ids.agentA, ids.agentEast].sort().map((sid) => ({ role_grant_id: g3, subject_person_id: sid, status: 'active' })),
        'Beacon manager reading unfiltered app_views.iam_role_grant_people must see only visible Beacon/East subjects, never Harbor subject',
      );
    }, { readOnly: true });
    await withRequestTx(appPool, supportTok, async (tx) => {
      const seen = (await tx.query(
        'SELECT role_grant_id, subject_person_id, status FROM app_views.iam_role_grant_people ORDER BY subject_person_id',
      )).rows;
      assert.deepEqual(
        seen,
        [ids.agentA, ids.agentEast, ids.agentHarbor].sort().map((sid) => ({ role_grant_id: g3, subject_person_id: sid, status: 'active' })),
        'full-company Nusear support sees all three visible subjects on live grant g3 only',
      );
    }, { readOnly: true });

    const revG3 = await iamCmd.revokeRoleGrant({
      dbToken: supportTok,
      commandKey: 'e5-t3d-revoke-g3',
      roleGrantId: g3,
    });
    assert.ok(revG3.result.revokedGrantId);
    await withRequestTx(appPool, supportTok, async (tx) => {
      const rgpUnfiltered = (await tx.query('SELECT id, role_grant_id, subject_person_id FROM app_views.iam_role_grant_people')).rows;
      assert.deepEqual(rgpUnfiltered, [], 'unfiltered app_views.iam_role_grant_people must return 0 rows after g3 is superseded by revocation');
    }, { readOnly: true });
    await withRequestTx(appPool, tokenFor(compId), async (tx) => {
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n, 0);
    }, { readOnly: true });
  });
});

test('Layer 7H [E5 Test 4]: View-as refusal, platform_app zero base-table access, 23P01 -> 409, grant-person state guards, zero existence oracle, seedIamCatalog reuse, deleted delegation helpers absent, and live catalog audit with breakage probes', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, tokenFor } = env.iam;

  await loadIamCmdModule();
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const workerPool = createRoleScopedTestPool(env.pool, 'platform_worker');
  const iamCmd = appCmdMod.createIamCommands({ pool: appPool });
  const supportTok = env.operatorToken;

  // 1. seedIamCatalog reuses isPgPool and withSerializableTx from src/db/pg-client.mjs.
  const catalogSrc = await readFile(new URL('../src/iam/catalog.mjs', import.meta.url), 'utf8');
  assert.match(catalogSrc, /import\s*\{[^}]*\bisPgPool\b[^}]*\bwithSerializableTx\b[^}]*\}\s*from\s*['"]\.\.\/db\/pg-client\.mjs['"]/);
  assert.doesNotMatch(catalogSrc, /BEGIN ISOLATION LEVEL SERIALIZABLE/);

  // 2. Deleted delegation machinery MUST NOT exist in pg_proc.
  const deletedFns = (await env.pool.query(
    `SELECT proname FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'iam'
       AND p.proname = ANY($1::text[])`,
    [[
      '_cmd_assert_holds_rights',
      '_cmd_assert_person_in_scope',
      '_cmd_assert_explicit_subject_in_scope',
      '_cmd_has_platform_root_right',
    ]],
  )).rows;
  assert.deepEqual(deletedFns, [], 'delegation helper functions must be completely deleted from PostgreSQL');

  // 3. View-as refuses EVERY ONE of the 15 iam commands (bridge + deliberate READ WRITE SQL).
  const viewAsTok = tokenFor(ids.nusearOwner, ids.entityMgr);
  const dummyUuid = randomUUID();
  const bridgeCalls = [
    ['createOrganization', () => iamCmd.createOrganization({ dbToken: viewAsTok, commandKey: 'va-1', orgKind: 'agency', slug: 'va_ag', displayName: 'VA Ag', parentOrgId: ids.companyOrg })],
    ['updateOrganization', () => iamCmd.updateOrganization({ dbToken: viewAsTok, commandKey: 'va-2', organizationId: ids.beaconOrg, displayName: 'VA Beacon' })],
    ['setOrganizationEdge', () => iamCmd.setOrganizationEdge({ dbToken: viewAsTok, commandKey: 'va-3', childOrgId: ids.beaconOrg, parentOrgId: ids.companyOrg, validRange: '[2020-01-01,)' })],
    ['createPerson', () => iamCmd.createPerson({ dbToken: viewAsTok, commandKey: 'va-4', organizationId: ids.companyOrg, legalName: 'VA Person', preferredName: 'VA Person' })],
    ['setPersonStatus', () => iamCmd.setPersonStatus({ dbToken: viewAsTok, commandKey: 'va-5', personId: ids.agentA, status: 'suspended' })],
    ['setMembership', () => iamCmd.setMembership({ dbToken: viewAsTok, commandKey: 'va-6', personId: ids.entityMgr, organizationId: ids.companyOrg, validRange: '[2020-01-01,)' })],
    ['setAgentAffiliation', () => iamCmd.setAgentAffiliation({ dbToken: viewAsTok, commandKey: 'va-7', personId: ids.agentA, npn: '99999999', agencyOrgId: ids.beaconOrg, splitBps: 8000, agentFileName: 'VA Agent', validRange: '[2020-01-01,)' })],
    ['createRole', () => iamCmd.createRole({ dbToken: viewAsTok, commandKey: 'va-8', ownerOrgId: ids.companyOrg, slug: 'va_role', displayName: 'VA Role' })],
    ['copyRole', () => iamCmd.copyRole({ dbToken: viewAsTok, commandKey: 'va-9', sourceRoleId: ids.roleSellingAgent, ownerOrgId: ids.companyOrg, newSlug: 'va_copy', newDisplayName: 'VA Copy' })],
    ['updateRole', () => iamCmd.updateRole({ dbToken: viewAsTok, commandKey: 'va-10', roleId: ids.roleCompanyAdminRunsOnly, displayName: 'VA Rename' })],
    ['setRoleRight', () => iamCmd.setRoleRight({ dbToken: viewAsTok, commandKey: 'va-11', roleId: ids.roleCompanyAdminRunsOnly, rightId: 'act:iam.read', status: 'active' })],
    ['grantRole', () => iamCmd.grantRole({ dbToken: viewAsTok, commandKey: 'va-12', personId: ids.agentA, roleId: ids.roleSellingAgent, organizationId: ids.beaconOrg, personScopeMode: 'self', validRange: '[2020-01-01,)' })],
    ['revokeRoleGrant', () => iamCmd.revokeRoleGrant({ dbToken: viewAsTok, commandKey: 'va-13', roleGrantId: dummyUuid })],
    ['setRoleGrantPerson', () => iamCmd.setRoleGrantPerson({ dbToken: viewAsTok, commandKey: 'va-14', roleGrantId: dummyUuid, subjectPersonId: ids.agentA, status: 'active' })],
    ['setToolSwitch', () => iamCmd.setToolSwitch({ dbToken: viewAsTok, commandKey: 'va-15', organizationId: ids.beaconOrg, toolId: 'coherence', switchState: 'off' })],
  ];
  for (const [name, fn] of bridgeCalls) {
    await assert.rejects(fn, (err) => err?.status === 403 && err?.code === 'VIEW_AS_READ_ONLY', `View-as must refuse iamCmd.${name}`);
  }

  const sha = 'a'.repeat(64);
  const directSqlCalls = [
    ['iam_create_organization', `SELECT app_cmd.iam_create_organization('va-s1', '${sha}', 'agency', 'va_s_ag', 'VA S Ag', '${ids.companyOrg}'::uuid)`],
    ['iam_update_organization', `SELECT app_cmd.iam_update_organization('va-s2', '${sha}', '${ids.beaconOrg}'::uuid, NULL, 'VA S')`],
    ['iam_set_organization_edge', `SELECT app_cmd.iam_set_organization_edge('va-s3', '${sha}', '${ids.beaconOrg}'::uuid, '${ids.companyOrg}'::uuid, '[2020-01-01,)'::daterange)`],
    ['iam_create_person', `SELECT app_cmd.iam_create_person('va-s4', '${sha}', '${ids.companyOrg}'::uuid, 'VA S', 'VA S')`],
    ['iam_set_person_status', `SELECT app_cmd.iam_set_person_status('va-s5', '${sha}', '${ids.agentA}'::uuid, 'suspended')`],
    ['iam_set_membership', `SELECT app_cmd.iam_set_membership('va-s6', '${sha}', '${ids.entityMgr}'::uuid, '${ids.companyOrg}'::uuid, '[2020-01-01,)'::daterange)`],
    ['iam_set_agent_affiliation', `SELECT app_cmd.iam_set_agent_affiliation('va-s7', '${sha}', '${ids.agentA}'::uuid, '99999999', '${ids.beaconOrg}'::uuid, 8000, 'VA S', '[2020-01-01,)'::daterange)`],
    ['iam_create_role', `SELECT app_cmd.iam_create_role('va-s8', '${sha}', '${ids.companyOrg}'::uuid, 'va_s_role', 'VA S Role')`],
    ['iam_copy_role', `SELECT app_cmd.iam_copy_role('va-s9', '${sha}', '${ids.roleSellingAgent}'::uuid, '${ids.companyOrg}'::uuid, 'va_s_copy', 'VA S Copy')`],
    ['iam_update_role', `SELECT app_cmd.iam_update_role('va-s10', '${sha}', '${ids.roleCompanyAdminRunsOnly}'::uuid, 'VA S Ren')`],
    ['iam_set_role_right', `SELECT app_cmd.iam_set_role_right('va-s11', '${sha}', '${ids.roleCompanyAdminRunsOnly}'::uuid, 'act:iam.read', 'active')`],
    ['iam_grant_role', `SELECT app_cmd.iam_grant_role('va-s12', '${sha}', '${ids.agentA}'::uuid, '${ids.roleSellingAgent}'::uuid, '${ids.beaconOrg}'::uuid, 'self', '[2020-01-01,)'::daterange)`],
    ['iam_revoke_role_grant', `SELECT app_cmd.iam_revoke_role_grant('va-s13', '${sha}', '${dummyUuid}'::uuid)`],
    ['iam_set_role_grant_person', `SELECT app_cmd.iam_set_role_grant_person('va-s14', '${sha}', '${dummyUuid}'::uuid, '${ids.agentA}'::uuid, 'active')`],
    ['iam_set_tool_switch', `SELECT app_cmd.iam_set_tool_switch('va-s15', '${sha}', '${ids.beaconOrg}'::uuid, 'coherence', 'off')`],
  ];
  for (const [name, sql] of directSqlCalls) {
    await assert.rejects(
      () => inSerializableTx(appPool, async (c) => {
        await c.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [viewAsTok]);
        await c.query(sql);
      }),
      (err) => err?.code === '42501' && /VIEW_AS_READ_ONLY/.test(err?.message || ''),
      `Direct READ WRITE SQL under View-as must refuse app_cmd.${name}`,
    );
  }

  await assert.rejects(
    () => inSerializableTx(workerPool, async (c) => {
      await c.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [env.workerToken]);
      await c.query(`SELECT app_cmd.iam_set_person_status('wrk-1', '${sha}', '${ids.agentA}'::uuid, 'suspended')`);
    }),
    (err) => err?.code === '42501',
    'platform_worker must get 42501 on app_cmd.iam_* functions',
  );

  // 4. platform_app has ZERO base-table access to ALL 18 iam.* tables and internal iam views.
  const iamTables = [...policyChecks.IAM_IMMUTABLE_TABLES, ...policyChecks.IAM_VERSIONED_TABLES];
  assert.equal(iamTables.length, 18);
  for (const tbl of iamTables) {
    await assert.rejects(
      () => withRequestTx(appPool, env.ownerToken, (tx) => tx.query(`SELECT * FROM iam.${tbl} LIMIT 1`), { readOnly: true }),
      (err) => err?.code === '42501',
      `platform_app must get 42501 selecting iam.${tbl}`,
    );
  }
  for (const viewName of ['v_organization_closure', 'v_organization_closure_live', 'v_all_memberships_live', 'v_actor_display_lookup']) {
    await assert.rejects(
      () => withRequestTx(appPool, env.ownerToken, (tx) => tx.query(`SELECT * FROM iam.${viewName} LIMIT 1`), { readOnly: true }),
      (err) => err?.code === '42501',
      `platform_app must get 42501 selecting internal view iam.${viewName}`,
    );
  }

  // 5. 23P01 exclusion violations map to 409 EXCLUSION_VIOLATION via src/db/pg-client.mjs mapPgError.
  await assert.rejects(
    () => iamCmd.setMembership({ dbToken: supportTok, commandKey: 't4-23p01-mem', personId: ids.entityMgr, organizationId: ids.companyOrg, validRange: '[2025-01-01,)' }),
    (err) => err?.status === 409 && err?.code === 'EXCLUSION_VIOLATION',
  );
  await assert.rejects(
    () => iamCmd.setAgentAffiliation({ dbToken: supportTok, commandKey: 't4-23p01-aff', personId: ids.agentA, npn: '11111111', agencyOrgId: ids.beaconOrg, splitBps: 8000, agentFileName: 'Overlap', validRange: '[2025-01-01,)' }),
    (err) => err?.status === 409 && err?.code === 'EXCLUSION_VIOLATION',
  );
  await assert.rejects(
    () => iamCmd.setOrganizationEdge({ dbToken: supportTok, commandKey: 't4-23p01-edge', childOrgId: ids.beaconOrg, parentOrgId: ids.companyOrg, validRange: '[2025-01-01,)' }),
    (err) => err?.status === 409 && err?.code === 'EXCLUSION_VIOLATION',
  );
  await assert.rejects(
    () => iamCmd.grantRole({ dbToken: supportTok, commandKey: 't4-23p01-grant', personId: ids.agentA, roleId: ids.roleSellingAgent, organizationId: ids.beaconOrg, personScopeMode: 'self', validRange: '[2025-01-01,)' }),
    (err) => err?.status === 409 && err?.code === 'EXCLUSION_VIOLATION',
  );

  // 6. iam_set_role_grant_person refuses superseded, revoked, and non-explicit_people grants.
  const wideGrantId = (await env.pool.query(
    "SELECT id FROM iam.role_grants WHERE person_id = $1 AND role_id = $2 AND superseded_by_id IS NULL",
    [ids.beaconManager, ids.roleAgencyManager],
  )).rows[0].id;
  const selfGrantId = (await env.pool.query(
    "SELECT id FROM iam.role_grants WHERE person_id = $1 AND role_id = $2 AND superseded_by_id IS NULL",
    [ids.agentA, ids.roleSellingAgent],
  )).rows[0].id;
  const compPersonId = (await iamCmd.createPerson({
    dbToken: supportTok,
    commandKey: 't4-rgp-comp',
    organizationId: ids.beaconOrg,
    legalName: 'Wynn Comp',
    preferredName: 'Wynn Comp',
    primaryEmail: 'wynn.comp@acme.example',
    validRange: '[2020-01-01,)',
  })).result.personId;
  const g1 = (await iamCmd.grantRole({
    dbToken: supportTok,
    commandKey: 't4-rgp-g1',
    personId: compPersonId,
    roleId: ids.roleCompliance,
    organizationId: ids.beaconOrg,
    personScopeMode: 'explicit_people',
    validRange: '[2020-01-01,)',
    subjectPersonIds: [ids.agentA],
  })).result.roleGrantId;
  const g2 = (await iamCmd.grantRole({
    dbToken: supportTok,
    commandKey: 't4-rgp-g2',
    personId: compPersonId,
    roleId: ids.roleCompliance,
    organizationId: ids.beaconOrg,
    personScopeMode: 'explicit_people',
    validRange: '[2020-01-01,2030-01-01)',
    replacesGrantId: g1,
  })).result.roleGrantId;
  const gRevoked = (await iamCmd.revokeRoleGrant({ dbToken: supportTok, commandKey: 't4-rgp-rev-g2', roleGrantId: g2 })).result.revokedGrantId;

  for (const status of ['active', 'revoked']) {
    for (const [label, grantId, expectedCode] of [
      ['superseded explicit_people grant', g1, 'EXPLICIT_PEOPLE_GRANT_INACTIVE'],
      ['revoked explicit_people grant', gRevoked, 'EXPLICIT_PEOPLE_GRANT_INACTIVE'],
      ['org_subtree grant', wideGrantId, 'EXPLICIT_PEOPLE_SCOPE_REQUIRED'],
      ['self grant', selfGrantId, 'EXPLICIT_PEOPLE_SCOPE_REQUIRED'],
    ]) {
      await assert.rejects(
        () => iamCmd.setRoleGrantPerson({
          dbToken: supportTok,
          commandKey: `t4-rgp-bad-${status}-${label}`,
          roleGrantId: grantId,
          subjectPersonId: ids.agentA,
          status,
        }),
        (err) => err?.status === 409 && err?.code === expectedCode,
        `setRoleGrantPerson(${status}) on ${label} must fail 409 ${expectedCode}`,
      );
    }
  }

  // 7. Zero existence oracle: both callers without IAM write rights AND scoped Nusear support callers
  //    receive 403 FORBIDDEN (never 404) for targets outside their scope whether or not the target exists.
  await t.test('4a: zero existence oracle for callers without rights and sub-org scoped Nusear support across all five target-ID commands', async () => {
  const fakeUuid = randomUUID();
  const beaconOnlySupportId = randomUUID();
  const harborCustomRoleId = (await iamCmd.createRole({
    dbToken: supportTok,
    commandKey: 't4-orc-harbor-role',
    ownerOrgId: ids.harborOrg,
    slug: 't4_harbor_custom_role',
    displayName: 'T4 Harbor Custom Role',
  })).result.roleId;
  const harborCompPersonId = (await iamCmd.createPerson({
    dbToken: supportTok,
    commandKey: 't4-orc-harbor-comp',
    organizationId: ids.harborOrg,
    legalName: 'Hollis HarborComp',
    preferredName: 'Hollis HarborComp',
    primaryEmail: 'hollis.hc@acme.example',
    validRange: '[2020-01-01,)',
  })).result.personId;
  const harborCompGrantId = (await iamCmd.grantRole({
    dbToken: supportTok,
    commandKey: 't4-orc-harbor-comp-grant',
    personId: harborCompPersonId,
    roleId: ids.roleCompliance,
    organizationId: ids.harborOrg,
    personScopeMode: 'explicit_people',
    validRange: '[2020-01-01,)',
    subjectPersonIds: [ids.agentHarbor],
  })).result.roleGrantId;
  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: ids.beaconOrg, commandKey: `t4-orc-bsup-${randomUUID()}` })).seq;
    await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','nusear_staff',$2)", [beaconOnlySupportId, seq]);
    await c.query("INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'nusear_staff','Skyler BeaconScope','Skyler BeaconScope','skyler.bscope@nusear.example','active',$3)", [randomUUID(), beaconOnlySupportId, seq]);
    await c.query("INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), beaconOnlySupportId, ids.rootOrg, seq]);
    await c.query("INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)", [randomUUID(), beaconOnlySupportId, ids.roleNusearSupport, ids.beaconOrg, seq]);
  });
  const beaconOnlySupportTok = tokenFor(beaconOnlySupportId, null, { keyScope: 'nusear_staff' });

  for (const [who, tok] of [
    ['entity_manager (company_local)', env.iam.tokens.entityMgr],
    ['agent (company_local)', env.iam.tokens.agentA],
    ['nusear_admin (read-only staff)', env.iam.tokens.adminNoCoh],
    ['wrongCoOperator (other company)', env.iam.tokens.wrongCoOperator],
    ['beacon_only_support (sub-org scoped staff)', beaconOnlySupportTok],
  ]) {
    for (const [cmdLabel, realFn, fakeFn] of [
      [
        'updateOrganization',
        () => iamCmd.updateOrganization({ dbToken: tok, commandKey: `t4-orc-uorg-r-${who}`, organizationId: ids.harborOrg, displayName: 'X' }),
        () => iamCmd.updateOrganization({ dbToken: tok, commandKey: `t4-orc-uorg-f-${who}`, organizationId: fakeUuid, displayName: 'X' }),
      ],
      [
        'setPersonStatus (no targetOrgId)',
        () => iamCmd.setPersonStatus({ dbToken: tok, commandKey: `t4-orc-sp-r-${who}`, personId: ids.agentHarbor, status: 'suspended' }),
        () => iamCmd.setPersonStatus({ dbToken: tok, commandKey: `t4-orc-sp-f-${who}`, personId: fakeUuid, status: 'suspended' }),
      ],
      [
        'setPersonStatus (out-of-scope targetOrgId)',
        () => iamCmd.setPersonStatus({ dbToken: tok, commandKey: `t4-orc-spo-r-${who}`, personId: ids.agentHarbor, status: 'suspended', targetOrgId: ids.harborOrg }),
        () => iamCmd.setPersonStatus({ dbToken: tok, commandKey: `t4-orc-spo-f-${who}`, personId: fakeUuid, status: 'suspended', targetOrgId: ids.harborOrg }),
      ],
      [
        'updateRole',
        () => iamCmd.updateRole({ dbToken: tok, commandKey: `t4-orc-ur-r-${who}`, roleId: harborCustomRoleId, displayName: 'X' }),
        () => iamCmd.updateRole({ dbToken: tok, commandKey: `t4-orc-ur-f-${who}`, roleId: fakeUuid, displayName: 'X' }),
      ],
      [
        'setRoleRight',
        () => iamCmd.setRoleRight({ dbToken: tok, commandKey: `t4-orc-rr-r-${who}`, roleId: harborCustomRoleId, rightId: 'act:iam.read', status: 'active' }),
        () => iamCmd.setRoleRight({ dbToken: tok, commandKey: `t4-orc-rr-f-${who}`, roleId: fakeUuid, rightId: 'act:iam.read', status: 'active' }),
      ],
      [
        'revokeRoleGrant',
        () => iamCmd.revokeRoleGrant({ dbToken: tok, commandKey: `t4-orc-rg-r-${who}`, roleGrantId: harborCompGrantId }),
        () => iamCmd.revokeRoleGrant({ dbToken: tok, commandKey: `t4-orc-rg-f-${who}`, roleGrantId: fakeUuid }),
      ],
      [
        'setRoleGrantPerson',
        () => iamCmd.setRoleGrantPerson({ dbToken: tok, commandKey: `t4-orc-rgp-r-${who}`, roleGrantId: harborCompGrantId, subjectPersonId: ids.agentA, status: 'active' }),
        () => iamCmd.setRoleGrantPerson({ dbToken: tok, commandKey: `t4-orc-rgp-f-${who}`, roleGrantId: fakeUuid, subjectPersonId: ids.agentA, status: 'active' }),
      ],
      [
        'setToolSwitch',
        () => iamCmd.setToolSwitch({ dbToken: tok, commandKey: `t4-orc-sw-r-${who}`, organizationId: ids.harborOrg, toolId: 'coherence', switchState: 'off' }),
        () => iamCmd.setToolSwitch({ dbToken: tok, commandKey: `t4-orc-sw-f-${who}`, organizationId: fakeUuid, toolId: 'nonexistent_tool', switchState: 'off' }),
      ],
    ]) {
      for (const [kind, fn] of [['real UUID', realFn], ['fake UUID', fakeFn]]) {
        await assert.rejects(
          fn,
          (err) => err?.status === 403 && err?.code === 'FORBIDDEN',
          `${who} calling ${cmdLabel} (${kind}) must get 403 FORBIDDEN (never 404 existence oracle)`,
        );
      }
    }
  }
  // Also verify beacon_only_support with in-scope targetOrgId=beaconOrg gets 403 on BOTH out-of-scope real person and fake UUID,
  // and full-company support gets 403 on nonexistent UUIDs on all five commands.
  for (const [label, fn] of [
    ['beacon_only_support setPersonStatus(agentHarbor, targetOrgId=beaconOrg)', () => iamCmd.setPersonStatus({ dbToken: beaconOnlySupportTok, commandKey: 't4-orc-bs-inorg-r', personId: ids.agentHarbor, status: 'suspended', targetOrgId: ids.beaconOrg })],
    ['beacon_only_support setPersonStatus(fakeUuid, targetOrgId=beaconOrg)', () => iamCmd.setPersonStatus({ dbToken: beaconOnlySupportTok, commandKey: 't4-orc-bs-inorg-f', personId: fakeUuid, status: 'suspended', targetOrgId: ids.beaconOrg })],
    ['full support setPersonStatus(fakeUuid)', () => iamCmd.setPersonStatus({ dbToken: supportTok, commandKey: 't4-orc-full-sp-f', personId: fakeUuid, status: 'suspended' })],
    ['full support updateRole(fakeUuid)', () => iamCmd.updateRole({ dbToken: supportTok, commandKey: 't4-orc-full-ur-f', roleId: fakeUuid, displayName: 'X' })],
    ['full support setRoleRight(fakeUuid)', () => iamCmd.setRoleRight({ dbToken: supportTok, commandKey: 't4-orc-full-rr-f', roleId: fakeUuid, rightId: 'act:iam.read', status: 'active' })],
    ['full support revokeRoleGrant(fakeUuid)', () => iamCmd.revokeRoleGrant({ dbToken: supportTok, commandKey: 't4-orc-full-rg-f', roleGrantId: fakeUuid })],
    ['full support setRoleGrantPerson(fakeUuid)', () => iamCmd.setRoleGrantPerson({ dbToken: supportTok, commandKey: 't4-orc-full-rgp-f', roleGrantId: fakeUuid, subjectPersonId: ids.agentA, status: 'active' })],
  ]) {
    await assert.rejects(
      fn,
      (err) => err?.status === 403 && err?.code === 'FORBIDDEN',
      `${label} must get 403 FORBIDDEN (never 404 existence oracle)`,
    );
  }
  });

  // 8. Live catalog audit covers all 18 iam.* RLS tables, 50 app_views.*, 48 app_cmd.*, 5 IAM_CMD_HELPERS, 8 IAM_RO_LOOKUP_HELPERS, with breakage probes.
  await t.test('4b: live catalog audit covers all 18 iam.* tables, 50 app_views.*, 48 app_cmd.*, and catches breakage probes including legacy audit_journal policy', async () => {
  const baseline = await withClusterCatalogLock(() => policyChecks.verifyIamConfigInvariants(env.pool));
  assert.equal(baseline.passed, true, `baseline verifyIamConfigInvariants failed:\n${baseline.problems.join('\n')}`);
  assert.equal(baseline.checkedIamTables, 18);
  assert.equal(baseline.checkedAppViews, 50);
  assert.equal(baseline.checkedAppCmdFunctions, 48);
  assert.equal(baseline.checkedIamCmdHelpers, 5);
  assert.equal(baseline.checkedIamRoLookupHelpers, 8);
  assert.equal(baseline.checkedAppViewsIamReadHelpers, 7);

  const orgPolQual = (await env.pool.query(
    "SELECT qual FROM pg_catalog.pg_policies WHERE schemaname = 'iam' AND tablename = 'organizations' AND policyname = 'organizations_iam_read'",
  )).rows[0]?.qual;
  assert.ok(orgPolQual);
  const auditPolQual = (await env.pool.query(
    "SELECT qual FROM pg_catalog.pg_policies WHERE schemaname = 'platform' AND tablename = 'audit_journal' AND policyname = 'audit_journal_iam_read'",
  )).rows[0]?.qual;
  assert.ok(auditPolQual);

  for (const [label, mutateSql, restoreSql, expectedRe] of [
    [
      'replace platform.audit_journal RLS policy with legacy iam.effective_wide_org_ids',
      "ALTER POLICY audit_journal_iam_read ON platform.audit_journal USING (target_org_id = ANY(((SELECT iam.effective_wide_org_ids('act:platform.audit_journal.read')))::uuid[]))",
      `ALTER POLICY audit_journal_iam_read ON platform.audit_journal USING (${auditPolQual})`,
      /platform\.audit_journal.*_read_audit_journal_orgs/i,
    ],
    [
      'disable FORCE ROW LEVEL SECURITY on iam.organizations',
      'ALTER TABLE iam.organizations NO FORCE ROW LEVEL SECURITY',
      'ALTER TABLE iam.organizations FORCE ROW LEVEL SECURITY',
      /iam\.organizations.*FORCE ROW LEVEL SECURITY/i,
    ],
    [
      'drop platform_view_owner RLS policy on iam.organizations',
      'DROP POLICY organizations_iam_read ON iam.organizations',
      `CREATE POLICY organizations_iam_read ON iam.organizations FOR SELECT TO platform_view_owner USING (${orgPolQual})`,
      /iam\.organizations.*platform_view_owner|policy/i,
    ],
    [
      'grant SELECT on iam.organizations to platform_app',
      'GRANT SELECT ON iam.organizations TO platform_app',
      'REVOKE SELECT ON iam.organizations FROM platform_app',
      /platform_app.*iam\.organizations/i,
    ],
    [
      'grant INSERT on iam.tools to platform_writer',
      'GRANT INSERT ON iam.tools TO platform_writer',
      'REVOKE INSERT ON iam.tools FROM platform_writer',
      /platform_writer.*iam\.tools/i,
    ],
    [
      'grant SELECT on iam.person_auth_identities to platform_writer',
      'GRANT SELECT ON iam.person_auth_identities TO platform_writer',
      'REVOKE SELECT ON iam.person_auth_identities FROM platform_writer',
      /platform_writer.*iam\.person_auth_identities/i,
    ],
    [
      'grant EXECUTE on app_cmd.iam_set_person_status to platform_worker',
      'GRANT EXECUTE ON FUNCTION app_cmd.iam_set_person_status(TEXT, TEXT, UUID, TEXT, UUID) TO platform_worker',
      'REVOKE EXECUTE ON FUNCTION app_cmd.iam_set_person_status(TEXT, TEXT, UUID, TEXT, UUID) FROM platform_worker',
      /platform_worker.*iam_set_person_status/i,
    ],
    [
      'remove security_barrier from app_views.iam_organizations',
      'ALTER VIEW app_views.iam_organizations SET (security_barrier = false)',
      'ALTER VIEW app_views.iam_organizations SET (security_barrier = true)',
      /iam_organizations.*security_barrier/i,
    ],
    [
      'disable trg_00b_verify_org_edge on iam.organization_edges',
      'ALTER TABLE iam.organization_edges DISABLE TRIGGER trg_00b_verify_org_edge',
      'ALTER TABLE iam.organization_edges ENABLE TRIGGER trg_00b_verify_org_edge',
      /trg_00b_verify_org_edge/i,
    ],
    [
      'disable trg_02_carry_explicit_people on iam.role_grants',
      'ALTER TABLE iam.role_grants DISABLE TRIGGER trg_02_carry_explicit_people',
      'ALTER TABLE iam.role_grants ENABLE TRIGGER trg_02_carry_explicit_people',
      /trg_02_carry_explicit_people/i,
    ],
    [
      're-own iam._cmd_require_nusear_staff to platform_readonly',
      'ALTER FUNCTION iam._cmd_require_nusear_staff(TEXT) OWNER TO platform_readonly',
      'ALTER FUNCTION iam._cmd_require_nusear_staff(TEXT) OWNER TO platform_writer',
      /_cmd_require_nusear_staff.*platform_writer/i,
    ],
    [
      'grant EXECUTE on iam._cmd_require_nusear_staff to platform_app',
      'GRANT EXECUTE ON FUNCTION iam._cmd_require_nusear_staff(TEXT) TO platform_app',
      'REVOKE EXECUTE ON FUNCTION iam._cmd_require_nusear_staff(TEXT) FROM platform_app',
      /platform_app.*_cmd_require_nusear_staff/i,
    ],
    [
      're-own iam._strip_masked_vendors to platform_writer',
      'ALTER FUNCTION iam._strip_masked_vendors(UUID[]) OWNER TO platform_writer',
      'ALTER FUNCTION iam._strip_masked_vendors(UUID[]) OWNER TO platform_readonly',
      /_strip_masked_vendors.*platform_readonly/i,
    ],
    [
      'grant EXECUTE on iam._strip_masked_vendors to platform_app',
      'GRANT EXECUTE ON FUNCTION iam._strip_masked_vendors(UUID[]) TO platform_app',
      'REVOKE EXECUTE ON FUNCTION iam._strip_masked_vendors(UUID[]) FROM platform_app',
      /platform_app.*_strip_masked_vendors/i,
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
});

test('Layer 7H [E5 Test 5 - Refusals]: company_local callers (company owner, entity manager, and a delegated custom role holding every IAM write right) are refused on all 15 app_cmd.iam_* commands with target table and audit journal unchanged', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, tokenFor } = env.iam;

  await loadIamCmdModule();
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const iamCmd = appCmdMod.createIamCommands({ pool: appPool });

  const companyOwnerId = randomUUID();
  const delegatedIamId = randomUUID();
  const delegatedRoleId = randomUUID();
  const compUserId = randomUUID();
  const compGrantId = randomUUID();
  const editableCustomRoleId = randomUUID();
  const beaconMgrGrantId = (await env.pool.query(
    "SELECT id FROM iam.role_grants WHERE person_id = $1 AND role_id = $2 AND superseded_by_id IS NULL AND status = 'active'",
    [ids.beaconManager, ids.roleAgencyManager],
  )).rows[0].id;

  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: ids.companyOrg, commandKey: `e5-t5-seed-${randomUUID()}` })).seq;
    for (const [pid, name, email, orgId] of [
      [companyOwnerId, 'Avery Owner', 'avery.owner@acme.example', ids.companyOrg],
      [delegatedIamId, 'Devon Delegated', 'devon.del@acme.example', ids.companyOrg],
      [compUserId, 'Finley Comp', 'finley.comp@acme.example', ids.beaconOrg],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','company_local',$2)", [pid, seq]);
      await c.query("INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'company_local',$3,$3,$4,'active',$5)", [randomUUID(), pid, name, email, seq]);
      await c.query("INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), pid, orgId, seq]);
    }

    // Delegated custom role explicitly holding ALL 5 IAM write rights + IAM read + bob read!
    await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'delegated_iam_all',$2,$3)", [delegatedRoleId, ids.companyOrg, seq]);
    await c.query("INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,'Delegated IAM All',false,false,true,'active',$3)", [randomUUID(), delegatedRoleId, seq]);
    for (const rightId of [
      'act:iam.read',
      'act:iam.entities.write',
      'act:iam.people.write',
      'act:iam.roles.write',
      'act:iam.grants.write',
      'act:iam.switches.write',
      'act:coherence.bob.read',
    ]) {
      await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)", [randomUUID(), delegatedRoleId, rightId, seq]);
    }

    await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'editable_custom',$2,$3)", [editableCustomRoleId, ids.companyOrg, seq]);
    await c.query("INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,'Editable Custom',false,false,true,'active',$3)", [randomUUID(), editableCustomRoleId, seq]);

    for (const [gid, pid, rid, orgId, mode] of [
      [randomUUID(), companyOwnerId, ids.roleOwner, ids.companyOrg, 'org_subtree'],
      [randomUUID(), delegatedIamId, delegatedRoleId, ids.companyOrg, 'org_subtree'],
      [compGrantId, compUserId, ids.roleCompliance, ids.beaconOrg, 'explicit_people'],
    ]) {
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,$5,'[2020-01-01,)'::daterange,'active',$6)",
        [gid, pid, rid, orgId, mode, seq],
      );
    }
    await c.query(
      "INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
      [randomUUID(), compGrantId, ids.agentA, seq],
    );
  });

  const eastEdgeId = (await env.pool.query(
    "SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND superseded_by_id IS NULL AND status = 'active'",
    [ids.eastTeamOrg],
  )).rows[0].id;

  const abusingCallers = [
    ['company_owner', tokenFor(companyOwnerId)],
    ['entity_manager', env.iam.tokens.entityMgr],
    ['company_admin', env.iam.tokens.companyAdmin],
    ['nusear_contractor', env.iam.tokens.nusearContractor],
    ['delegated_custom_role', tokenFor(delegatedIamId)],
  ];

  // Every company_local abusing caller is refused on ALL 15 app_cmd.iam_* commands with zero writes!
  for (const [who, tok] of abusingCallers) {
    const calls = [
      ['createOrganization', ['iam.organizations', 'iam.organization_versions', 'iam.organization_edges'], () => iamCmd.createOrganization({ dbToken: tok, commandKey: `t5-${who}-1`, orgKind: 'agency', slug: `bad_${who}_ag`, displayName: 'Bad Agency', parentOrgId: ids.companyOrg })],
      ['updateOrganization', 'iam.organization_versions', () => iamCmd.updateOrganization({ dbToken: tok, commandKey: `t5-${who}-2`, organizationId: ids.beaconOrg, displayName: 'Hijacked Beacon' })],
      ['setOrganizationEdge', 'iam.organization_edges', () => iamCmd.setOrganizationEdge({ dbToken: tok, commandKey: `t5-${who}-3`, childOrgId: ids.eastTeamOrg, parentOrgId: ids.harborOrg, validRange: '[2027-01-01,)', closeEdgeId: eastEdgeId, closeValidRange: '[2020-01-01,2027-01-01)' })],
      ['createPerson', ['iam.people', 'iam.person_versions', 'iam.organization_memberships'], () => iamCmd.createPerson({ dbToken: tok, commandKey: `t5-${who}-4`, organizationId: ids.companyOrg, legalName: 'Rogue Person', preferredName: 'Rogue Person', workArrangement: 'employee', validRange: '[2026-01-01,)' })],
      ['setPersonStatus', 'iam.person_versions', () => iamCmd.setPersonStatus({ dbToken: tok, commandKey: `t5-${who}-5`, personId: ids.agentA, status: 'suspended' })],
      ['setMembership', 'iam.organization_memberships', () => iamCmd.setMembership({ dbToken: tok, commandKey: `t5-${who}-6`, personId: ids.agentA, organizationId: ids.harborOrg, validRange: '[2026-01-01,)' })],
      ['setAgentAffiliation', 'iam.agent_affiliations', () => iamCmd.setAgentAffiliation({ dbToken: tok, commandKey: `t5-${who}-7`, personId: ids.agentA, npn: '99112233', agencyOrgId: ids.beaconOrg, splitBps: 7500, agentFileName: 'Rogue Aff', validRange: '[2026-01-01,)' })],
      ['createRole', ['iam.roles', 'iam.role_versions'], () => iamCmd.createRole({ dbToken: tok, commandKey: `t5-${who}-8`, ownerOrgId: ids.companyOrg, slug: `bad_${who}_role`, displayName: 'Bad Role' })],
      ['copyRole', ['iam.roles', 'iam.role_versions', 'iam.role_rights'], () => iamCmd.copyRole({ dbToken: tok, commandKey: `t5-${who}-9`, sourceRoleId: ids.roleInvestor, ownerOrgId: ids.companyOrg, newSlug: `bad_${who}_copy`, newDisplayName: 'Bad Copy' })],
      ['updateRole', 'iam.role_versions', () => iamCmd.updateRole({ dbToken: tok, commandKey: `t5-${who}-10`, roleId: editableCustomRoleId, displayName: 'Hijacked Custom' })],
      ['setRoleRight', 'iam.role_rights', () => iamCmd.setRoleRight({ dbToken: tok, commandKey: `t5-${who}-11`, roleId: editableCustomRoleId, rightId: 'act:coherence.bob.read', status: 'active' })],
      ['grantRole', 'iam.role_grants', () => iamCmd.grantRole({ dbToken: tok, commandKey: `t5-${who}-12`, personId: ids.agentA, roleId: editableCustomRoleId, organizationId: ids.beaconOrg, personScopeMode: 'org_subtree', validRange: '[2026-01-01,)' })],
      ['revokeRoleGrant', 'iam.role_grants', () => iamCmd.revokeRoleGrant({ dbToken: tok, commandKey: `t5-${who}-13`, roleGrantId: beaconMgrGrantId })],
      ['setRoleGrantPerson', 'iam.role_grant_people', () => iamCmd.setRoleGrantPerson({ dbToken: tok, commandKey: `t5-${who}-14`, roleGrantId: compGrantId, subjectPersonId: ids.agentEast, status: 'active' })],
      ['setToolSwitch', 'iam.organization_tool_switches', () => iamCmd.setToolSwitch({ dbToken: tok, commandKey: `t5-${who}-15`, organizationId: ids.beaconOrg, toolId: 'vendors', switchState: 'off' })],
    ];
    for (const [cmdName, tbls, fn] of calls) {
      await assertRefusedNoWrite(
        env.pool,
        tbls,
        fn,
        (err) => err?.status === 403 && err?.code === 'FORBIDDEN',
        `${who} must be refused 403 on ${cmdName}`,
      );
    }
  }

  // Also verify read-only Nusear staff (nusear_admin) and wrong-company Nusear support (wrongCoOperator) cannot write!
  for (const [who, tok] of [
    ['nusear_admin', env.iam.tokens.adminNoCoh],
    ['wrongCoOperator', env.iam.tokens.wrongCoOperator],
  ]) {
    await assertRefusedNoWrite(
      env.pool,
      ['iam.roles', 'iam.role_versions'],
      () => iamCmd.createRole({ dbToken: tok, commandKey: `t5-${who}-role`, ownerOrgId: ids.companyOrg, slug: `bad_${who}`, displayName: 'Bad Role' }),
      (err) => err?.status === 403 && err?.code === 'FORBIDDEN',
      `${who} must be refused 403 creating role in Acme`,
    );
  }

  // Positive control: Nusear support (origin nusear_staff, Nusear-internal grant on Acme) CAN write and is recorded as nusear_support!
  const okRole = await iamCmd.createRole({
    dbToken: env.operatorToken,
    commandKey: 't5-support-ok-role',
    ownerOrgId: ids.companyOrg,
    slug: 'support_created_role',
    displayName: 'Support Created Role',
  });
  assert.ok(okRole.result.roleId);
  const auditRow = (await env.pool.query('SELECT recorded_as, target_org_id FROM platform.audit_journal WHERE seq = $1', [okRole.journalSeq])).rows[0];
  assert.deepEqual(auditRow, { recorded_as: 'nusear_support', target_org_id: ids.companyOrg });
});

test('Layer 7H [E5 Test 6 - Refusals]: Nusear support and Nusear owner are refused at runtime on platform_root, built-in roles (owner_org_id NULL), and Nusear own people/memberships/grants (and platform_root can never be archived), with target tables and audit journal unchanged', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, tokenFor } = env.iam;

  await loadIamCmdModule();
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const iamCmd = appCmdMod.createIamCommands({ pool: appPool });

  // Seed a root-anchored nusear_support caller too so we prove EVEN root-anchored Nusear support and nusear_owner are refused!
  const rootSupportId = randomUUID();
  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: ids.rootOrg, commandKey: `e5-t6-seed-${randomUUID()}` })).seq;
    await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','nusear_staff',$2)", [rootSupportId, seq]);
    await c.query("INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'nusear_staff','Jordan RootSup','Jordan RootSup','jordan.rootsup@nusear.example','active',$3)", [randomUUID(), rootSupportId, seq]);
    await c.query("INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), rootSupportId, ids.rootOrg, seq]);
    await c.query("INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)", [randomUUID(), rootSupportId, ids.roleNusearSupport, ids.rootOrg, seq]);
  });

  const nusearAdminGrantId = (await env.pool.query(
    "SELECT id FROM iam.role_grants WHERE person_id = $1 AND role_id = $2 AND superseded_by_id IS NULL",
    [ids.nusearAdminNoCoh, ids.roleNusearAdmin],
  )).rows[0].id;
  const nusearOwnerGrantId = (await env.pool.query(
    "SELECT id FROM iam.role_grants WHERE person_id = $1 AND role_id = $2 AND superseded_by_id IS NULL",
    [ids.nusearOwner, ids.roleNusearOwner],
  )).rows[0].id;
  const workerGrantId = (await env.pool.query(
    "SELECT id FROM iam.role_grants WHERE person_id = $1 AND role_id = $2 AND superseded_by_id IS NULL",
    [ids.workerService, ids.roleWorkerService],
  )).rows[0].id;
  const companyRootEdgeId = (await env.pool.query(
    "SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND parent_org_id = $2 AND superseded_by_id IS NULL",
    [ids.companyOrg, ids.rootOrg],
  )).rows[0].id;

  const callers = [
    ['tenant_nusear_support', env.operatorToken],
    ['root_nusear_support', tokenFor(rootSupportId, null, { keyScope: 'nusear_staff' })],
    ['nusear_owner', env.ownerToken],
  ];

  for (const [who, tok] of callers) {
    // 1. platform_root targets refused with zero writes.
    for (const [label, tbls, fn] of [
      ['updateOrganization rename platform_root', 'iam.organization_versions', () => iamCmd.updateOrganization({ dbToken: tok, commandKey: `t6-${who}-root-ren`, organizationId: ids.rootOrg, displayName: 'Bad Root' })],
      ['updateOrganization archive platform_root', 'iam.organization_versions', () => iamCmd.updateOrganization({ dbToken: tok, commandKey: `t6-${who}-root-arch`, organizationId: ids.rootOrg, status: 'archived' })],
      ['setToolSwitch on platform_root', 'iam.organization_tool_switches', () => iamCmd.setToolSwitch({ dbToken: tok, commandKey: `t6-${who}-root-sw`, organizationId: ids.rootOrg, toolId: 'vendors', switchState: 'off' })],
      ['createOrganization agency under platform_root', ['iam.organizations', 'iam.organization_versions', 'iam.organization_edges'], () => iamCmd.createOrganization({ dbToken: tok, commandKey: `t6-${who}-root-child`, orgKind: 'agency', slug: `bad_${who}_rchild`, displayName: 'Bad Child', parentOrgId: ids.rootOrg })],
      ['setOrganizationEdge attaching beacon to platform_root', 'iam.organization_edges', () => iamCmd.setOrganizationEdge({ dbToken: tok, commandKey: `t6-${who}-root-edge`, childOrgId: ids.beaconOrg, parentOrgId: ids.rootOrg, validRange: '[2028-01-01,)' })],
      ['setOrganizationEdge revoking company->platform_root edge', 'iam.organization_edges', () => iamCmd.setOrganizationEdge({ dbToken: tok, commandKey: `t6-${who}-root-unhook`, childOrgId: ids.companyOrg, parentOrgId: ids.rootOrg, validRange: '[2020-01-01,)', replacesEdgeId: companyRootEdgeId, status: 'revoked' })],
      ['createPerson on platform_root', ['iam.people', 'iam.person_versions', 'iam.organization_memberships'], () => iamCmd.createPerson({ dbToken: tok, commandKey: `t6-${who}-root-person`, organizationId: ids.rootOrg, legalName: 'Root Person', preferredName: 'Root Person' })],
      ['setMembership on platform_root', 'iam.organization_memberships', () => iamCmd.setMembership({ dbToken: tok, commandKey: `t6-${who}-root-mem`, personId: ids.entityMgr, organizationId: ids.rootOrg, validRange: '[2028-01-01,)' })],
      ['grantRole on platform_root', 'iam.role_grants', () => iamCmd.grantRole({ dbToken: tok, commandKey: `t6-${who}-root-grant`, personId: ids.entityMgr, roleId: ids.roleInvestor, organizationId: ids.rootOrg, personScopeMode: 'org_subtree', validRange: '[2028-01-01,)' })],
      ['createRole owned by platform_root', ['iam.roles', 'iam.role_versions'], () => iamCmd.createRole({ dbToken: tok, commandKey: `t6-${who}-root-role`, ownerOrgId: ids.rootOrg, slug: `bad_${who}_rrole`, displayName: 'Bad Root Role' })],
    ]) {
      await assertRefusedNoWrite(env.pool, tbls, fn, (err) => err?.status === 403, `${who}: ${label} must be refused 403`);
    }

    // 2. Built-in roles (owner_org_id IS NULL) and Nusear-internal roles refused with zero writes.
    for (const [label, tbls, fn] of [
      ['createRole built-in (ownerOrgId=null)', ['iam.roles', 'iam.role_versions'], () => iamCmd.createRole({ dbToken: tok, commandKey: `t6-${who}-bi-create`, ownerOrgId: null, slug: `bad_${who}_bi`, displayName: 'Bad Builtin' })],
      ['copyRole into built-in (ownerOrgId=null)', ['iam.roles', 'iam.role_versions', 'iam.role_rights'], () => iamCmd.copyRole({ dbToken: tok, commandKey: `t6-${who}-bi-copy`, sourceRoleId: ids.roleInvestor, ownerOrgId: null, newSlug: `bad_${who}_bicopy`, newDisplayName: 'Bad BI Copy' })],
      ['copyRole from nusear_support internal role', ['iam.roles', 'iam.role_versions', 'iam.role_rights'], () => iamCmd.copyRole({ dbToken: tok, commandKey: `t6-${who}-int-copy`, sourceRoleId: ids.roleNusearSupport, ownerOrgId: ids.companyOrg, newSlug: `bad_${who}_intcopy`, newDisplayName: 'Bad Int Copy' })],
      ['updateRole built-in investor', 'iam.role_versions', () => iamCmd.updateRole({ dbToken: tok, commandKey: `t6-${who}-bi-upd-inv`, roleId: ids.roleInvestor, displayName: 'Mutated Investor' })],
      ['updateRole built-in nusear_support', 'iam.role_versions', () => iamCmd.updateRole({ dbToken: tok, commandKey: `t6-${who}-bi-upd-sup`, roleId: ids.roleNusearSupport, displayName: 'Mutated Support' })],
      ['setRoleRight active on built-in investor', 'iam.role_rights', () => iamCmd.setRoleRight({ dbToken: tok, commandKey: `t6-${who}-bi-rr-inv`, roleId: ids.roleInvestor, rightId: 'act:iam.read', status: 'active' })],
      ['setRoleRight revoked on built-in agency_manager', 'iam.role_rights', () => iamCmd.setRoleRight({ dbToken: tok, commandKey: `t6-${who}-bi-rr-ag`, roleId: ids.roleAgencyManager, rightId: 'act:coherence.bob.read', status: 'revoked' })],
      ['setRoleRight revoked on built-in nusear_contractor', 'iam.role_rights', () => iamCmd.setRoleRight({ dbToken: tok, commandKey: `t6-${who}-bi-rr-nc`, roleId: ids.roleNusearContractor, rightId: 'act:coherence.bob.read', status: 'revoked' })],
      ['setRoleRight active on built-in nusear_admin (delegable right)', 'iam.role_rights', () => iamCmd.setRoleRight({ dbToken: tok, commandKey: `t6-${who}-bi-rr-adm`, roleId: ids.roleNusearAdmin, rightId: 'act:coherence.run.launch', status: 'active' })],
      ['setRoleRight revoked on built-in nusear_support (delegable right)', 'iam.role_rights', () => iamCmd.setRoleRight({ dbToken: tok, commandKey: `t6-${who}-bi-rr-sup`, roleId: ids.roleNusearSupport, rightId: 'act:coherence.run.launch', status: 'revoked' })],
      ['grantRole Nusear-internal role to company_local', 'iam.role_grants', () => iamCmd.grantRole({ dbToken: tok, commandKey: `t6-${who}-grant-int`, personId: ids.entityMgr, roleId: ids.roleNusearSupport, organizationId: ids.companyOrg, personScopeMode: 'org_subtree', validRange: '[2028-01-01,)' })],
    ]) {
      await assertRefusedNoWrite(env.pool, tbls, fn, (err) => err?.status === 403, `${who}: ${label} must be refused 403`);
    }

    // 3. Nusear's own people, service principals, memberships, affiliations, and grants refused with zero writes.
    for (const [label, tbls, fn] of [
      ['createPerson nusear_staff', ['iam.people', 'iam.person_versions', 'iam.organization_memberships'], () => iamCmd.createPerson({ dbToken: tok, commandKey: `t6-${who}-p-staff`, organizationId: ids.companyOrg, legalName: 'Rogue Staff', preferredName: 'Rogue Staff', principalOrigin: 'nusear_staff' })],
      ['createPerson service', ['iam.people', 'iam.person_versions', 'iam.organization_memberships'], () => iamCmd.createPerson({ dbToken: tok, commandKey: `t6-${who}-p-svc`, organizationId: ids.companyOrg, legalName: 'Rogue Svc', preferredName: 'Rogue Svc', personKind: 'service', principalOrigin: 'service' })],
      ['setPersonStatus suspend nusear_owner', 'iam.person_versions', () => iamCmd.setPersonStatus({ dbToken: tok, commandKey: `t6-${who}-susp-owner`, personId: ids.nusearOwner, status: 'suspended' })],
      ['setPersonStatus suspend nusear_admin', 'iam.person_versions', () => iamCmd.setPersonStatus({ dbToken: tok, commandKey: `t6-${who}-susp-admin`, personId: ids.nusearAdminNoCoh, status: 'suspended' })],
      ['setPersonStatus suspend coherence_worker', 'iam.person_versions', () => iamCmd.setPersonStatus({ dbToken: tok, commandKey: `t6-${who}-susp-worker`, personId: ids.workerService, status: 'suspended' })],
      ['setMembership on nusear_operator at companyOrg', 'iam.organization_memberships', () => iamCmd.setMembership({ dbToken: tok, commandKey: `t6-${who}-mem-staff`, personId: ids.nusearOperator, organizationId: ids.companyOrg, validRange: '[2028-01-01,)' })],
      ['setMembership on coherence_worker at companyOrg', 'iam.organization_memberships', () => iamCmd.setMembership({ dbToken: tok, commandKey: `t6-${who}-mem-svc`, personId: ids.workerService, organizationId: ids.companyOrg, validRange: '[2028-01-01,)' })],
      ['setAgentAffiliation on nusear_operator', 'iam.agent_affiliations', () => iamCmd.setAgentAffiliation({ dbToken: tok, commandKey: `t6-${who}-aff-staff`, personId: ids.nusearOperator, npn: '77665544', agencyOrgId: ids.beaconOrg, splitBps: 8000, agentFileName: 'Bad Staff Aff', validRange: '[2028-01-01,)' })],
      ['grantRole on nusear_operator at companyOrg', 'iam.role_grants', () => iamCmd.grantRole({ dbToken: tok, commandKey: `t6-${who}-gr-staff`, personId: ids.nusearOperator, roleId: ids.roleInvestor, organizationId: ids.companyOrg, personScopeMode: 'org_subtree', validRange: '[2028-01-01,)' })],
      ['grantRole on coherence_worker at companyOrg', 'iam.role_grants', () => iamCmd.grantRole({ dbToken: tok, commandKey: `t6-${who}-gr-svc`, personId: ids.workerService, roleId: ids.roleInvestor, organizationId: ids.companyOrg, personScopeMode: 'org_subtree', validRange: '[2028-01-01,)' })],
      ['revokeRoleGrant on nusear_admin grant', 'iam.role_grants', () => iamCmd.revokeRoleGrant({ dbToken: tok, commandKey: `t6-${who}-rev-admin`, roleGrantId: nusearAdminGrantId })],
      ['revokeRoleGrant on nusear_owner grant', 'iam.role_grants', () => iamCmd.revokeRoleGrant({ dbToken: tok, commandKey: `t6-${who}-rev-owner`, roleGrantId: nusearOwnerGrantId })],
      ['revokeRoleGrant on coherence_worker grant', 'iam.role_grants', () => iamCmd.revokeRoleGrant({ dbToken: tok, commandKey: `t6-${who}-rev-svc`, roleGrantId: workerGrantId })],
    ]) {
      await assertRefusedNoWrite(env.pool, tbls, fn, (err) => err?.status === 403, `${who}: ${label} must be refused 403`);
    }
  }

  // 4. platform_root can NEVER be archived even via direct SQL INSERT into iam.organization_versions!
  const rootVerId = (await env.pool.query(
    'SELECT id FROM iam.organization_versions WHERE organization_id = $1 AND superseded_by_id IS NULL',
    [ids.rootOrg],
  )).rows[0].id;
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: ids.rootOrg, commandKey: `e5-t6-sql-arch-root-${randomUUID()}` })).seq;
      await c.query(
        `INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, replaces_id, journal_seq)
         VALUES ($1, $2, 'nusear', 'Nusear', 'archived', $3, $4)`,
        [randomUUID(), ids.rootOrg, rootVerId, seq],
      );
    }),
    (err) => err?.code === '23514' && /PLATFORM_ROOT_IMMUTABLE_ACTIVE/.test(err?.message || ''),
    'direct SQL archival of platform_root must fail 23514 PLATFORM_ROOT_IMMUTABLE_ACTIVE',
  );
});

test('Layer 7H [E5 Test 7 - Refusals]: owner powers (act:coherence.owner.*) and worker powers are non-delegable in src/iam/catalog.mjs and never addable to any role via setRoleRight or copyRole (with target tables and audit journal unchanged)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids } = env.iam;

  await loadIamCmdModule();
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const iamCmd = appCmdMod.createIamCommands({ pool: appPool });

  // 1. Verify catalog and DB mark every owner power, worker-or-owner power, and worker power isDelegablePower = false.
  const allNonDelegableRights = [...OWNER_POWER_RIGHTS, ...WORKER_OR_OWNER_POWER_RIGHTS, ...WORKER_POWER_RIGHTS];
  const byId = new Map(catalogMod.CANONICAL_RIGHTS.map((r) => [r.id, r]));
  for (const rightId of allNonDelegableRights) {
    const def = byId.get(rightId);
    assert.ok(def, `catalog missing ${rightId}`);
    assert.equal(def.isDelegablePower, false, `${rightId} must have isDelegablePower = false in src/iam/catalog.mjs`);
  }
  const dbFlags = (await env.pool.query(
    'SELECT id, is_delegable_power FROM iam.rights WHERE id = ANY($1::text[]) ORDER BY id',
    [allNonDelegableRights],
  )).rows;
  assert.equal(dbFlags.length, allNonDelegableRights.length);
  for (const row of dbFlags) {
    assert.equal(row.is_delegable_power, false, `${row.id} must have is_delegable_power = false in iam.rights`);
  }

  // Create an empty custom role owned by Acme via Nusear support.
  const customRoleId = (await iamCmd.createRole({
    dbToken: env.operatorToken,
    commandKey: 't7-custom-role',
    ownerOrgId: ids.companyOrg,
    slug: 't7_custom_role',
    displayName: 'T7 Custom Role',
  })).result.roleId;

  // 2. Neither nusear_owner nor nusear_support can add ANY non-delegable right to a role via setRoleRight or copyRole!
  for (const [who, tok] of [
    ['nusear_owner', env.ownerToken],
    ['nusear_support', env.operatorToken],
  ]) {
    for (const rightId of allNonDelegableRights) {
      await assertRefusedNoWrite(
        env.pool,
        'iam.role_rights',
        () => iamCmd.setRoleRight({
          dbToken: tok,
          commandKey: `t7-${who}-rr-${rightId}`,
          roleId: customRoleId,
          rightId,
          status: 'active',
        }),
        (err) => err?.status === 403,
        `${who} must be refused adding non-delegable right ${rightId} via setRoleRight`,
      );
    }
    for (const rightId of [
      ...WORKER_OR_OWNER_POWER_RIGHTS,
      'act:coherence.owner.confirm_emit',
      'act:coherence.owner.abandon_run',
      'act:coherence.owner.import_history',
      'act:coherence.worker.attempt',
      'act:coherence.worker.review',
    ]) {
      await assertRefusedNoWrite(
        env.pool,
        ['iam.roles', 'iam.role_versions', 'iam.role_rights'],
        () => iamCmd.copyRole({
          dbToken: tok,
          commandKey: `t7-${who}-cp-${rightId}`,
          sourceRoleId: ids.roleInvestor,
          ownerOrgId: ids.companyOrg,
          newSlug: `bad_cp_${who}_${rightId.replace(/[^a-z0-9]/g, '_').slice(-18)}`,
          newDisplayName: 'Bad Power Copy',
          addRightIds: [rightId],
        }),
        (err) => err?.status === 403,
        `${who} must be refused adding non-delegable right ${rightId} via copyRole`,
      );
    }
  }

  // 3. Direct SQL INSERT into iam.role_rights for any non-internal role is ALSO refused by iam.trg_verify_role_rights_invariants()
  //    for every non-delegable right and platform_internal right (and flipping an internal role to non-internal is refused too).
  for (const rightId of [...WORKER_OR_OWNER_POWER_RIGHTS, 'act:coherence.owner.confirm_emit', 'act:coherence.worker.attempt']) {
    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: ids.companyOrg, commandKey: `t7-sql-nd-${rightId}-${randomUUID()}` })).seq;
        await c.query(
          "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), customRoleId, rightId, seq],
        );
      }),
      (err) => err?.code === '23514' && /NON_DELEGABLE_RIGHT_FORBIDDEN/.test(err?.message || ''),
      `direct SQL insert of non-delegable right ${rightId} onto non-internal role must fail 23514`,
    );
  }
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: ids.companyOrg, commandKey: `t7-sql-pi-${randomUUID()}` })).seq;
      await c.query(
        "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,'col:platform.audit_journal.nusear_actor','active',$3)",
        [randomUUID(), customRoleId, seq],
      );
    }),
    (err) => err?.code === '23514' && /PLATFORM_INTERNAL_RIGHT_FORBIDDEN/.test(err?.message || ''),
    'direct SQL insert of platform_internal right onto non-internal role must fail 23514',
  );
  // Bidirectional guard: internal role holding non-delegable/platform-internal rights cannot flip to non-internal.
  await assert.rejects(
    () => inSerializableTx(env.pool, async (c) => {
      const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: ids.rootOrg, commandKey: `t7-sql-flip-${randomUUID()}` })).seq;
      const tmpRole = randomUUID();
      const rv1 = randomUUID();
      await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'tmp_int_flip',NULL,$2)", [tmpRole, seq]);
      await c.query("INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,'Tmp Int Flip',false,true,true,'active',$3)", [rv1, tmpRole, seq]);
      await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,'act:coherence.checks.record','active',$3)", [randomUUID(), tmpRole, seq]);
      await c.query("INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, replaces_id, journal_seq) VALUES ($1,$2,'Tmp NonInt Flip',false,false,true,'active',$3,$4)", [randomUUID(), tmpRole, rv1, seq]);
    }),
    (err) => err?.code === '23514' && /NON_DELEGABLE_RIGHT_FORBIDDEN/.test(err?.message || ''),
    'flipping an internal role holding non-delegable rights to non-internal must fail 23514',
  );

  // Positive control: delegable right CAN be added by Nusear support.
  const okRight = await iamCmd.setRoleRight({
    dbToken: env.operatorToken,
    commandKey: 't7-support-delegable-ok',
    roleId: customRoleId,
    rightId: 'act:coherence.bob.read',
    status: 'active',
  });
  assert.equal(okRight.result.status, 'active');
});

test('Layer 7H [E5 Test 8]: one vendor-masking rule across every non-org IAM view (edges and audit_journal included), actual target-org audit entries, and vendor real-identity guard on create/update/replay', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());
  const { ids, tokenFor } = env.iam;

  await loadIamCmdModule();
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const iamCmd = appCmdMod.createIamCommands({ pool: appPool });
  const supportTok = env.operatorToken;

  const cobaltOrg = (await iamCmd.createOrganization({
    dbToken: supportTok,
    commandKey: 't8-cobalt-org',
    orgKind: 'lead_vendor',
    slug: 'cobalt_leads',
    displayName: 'Cobalt Leads',
    parentOrgId: ids.companyOrg,
    maskedDisplayName: 'Vendor 01',
    externalDomain: 'cobalt.example',
  })).result.organizationId;

  const quartzOrg = (await iamCmd.createOrganization({
    dbToken: supportTok,
    commandKey: 't8-quartz-org',
    orgKind: 'lead_vendor',
    slug: 'quartz_leads',
    displayName: 'Quartz Leads',
    parentOrgId: ids.companyOrg,
    maskedDisplayName: 'Vendor 02',
    externalDomain: 'quartz.example',
  })).result.organizationId;

  const companyOwnerId = randomUUID();
  const directorId = randomUUID();
  const accountingId = randomUUID();
  const auditNoVendorId = randomUUID();
  const beaconAuditReaderId = randomUUID();
  const harborAuditReaderId = randomUUID();
  const cobaltUserId = randomUUID();
  const quartzUserId = randomUUID();
  const beaconSupportId = randomUUID();
  const staffNoVendorNameId = randomUUID();
  const cobaltCustomRoleId = randomUUID();
  const quartzCustomRoleId = randomUUID();
  const acmeSecretRoleId = randomUUID();
  const auditOnlyRoleId = randomUUID();
  const staffNoVendorRoleId = randomUUID();

  const northstarOpGrantId = (await env.pool.query(
    'SELECT id FROM iam.role_grants WHERE person_id = $1 AND organization_id = $2 AND superseded_by_id IS NULL',
    [ids.northstarOperator, ids.northstarOrg],
  )).rows[0].id;

  await inSerializableTx(env.pool, async (c) => {
    const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: ids.companyOrg, commandKey: `e5-t8-seed-${randomUUID()}` })).seq;

    for (const [oid, disp] of [[cobaltOrg, 'Cobalt Leads'], [quartzOrg, 'Quartz Leads']]) {
      await c.query(
        "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, hold_reason, status, journal_seq) VALUES ($1,$2,'concurrence','held',$3,'active',$4)",
        [randomUUID(), oid, `${disp} LLC compliance hold`, seq],
      );
    }

    for (const [rid, slug, ownerOrgId, disp, isInt, rights] of [
      [cobaltCustomRoleId, 'cobalt_portal_admin', cobaltOrg, 'Cobalt Leads Admin', false, ['act:iam.read', 'act:leads.vendor_bills.read', 'act:platform.audit_journal.read']],
      [quartzCustomRoleId, 'quartz_portal_admin', quartzOrg, 'Quartz Leads Admin', false, ['act:iam.read', 'act:leads.vendor_bills.read', 'act:platform.audit_journal.read']],
      [acmeSecretRoleId, 'acme_secret_deal_team', ids.companyOrg, 'Acme Secret Deal Team', false, ['act:iam.read']],
      [auditOnlyRoleId, 'company_audit_no_vendor', ids.companyOrg, 'Company Audit No Vendor', false, ['act:iam.read', 'act:platform.audit_journal.read']],
      [staffNoVendorRoleId, 'nusear_entities_no_vendor_name', null, 'Nusear Entities No Vendor Name', true, ['act:iam.read', 'act:iam.entities.write']],
    ]) {
      await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,$3,$4)', [rid, slug, ownerOrgId, seq]);
      await c.query('INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,$3,false,$4,true,\'active\',$5)', [randomUUID(), rid, disp, isInt, seq]);
      for (const rightId of rights) {
        await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)", [randomUUID(), rid, rightId, seq]);
      }
    }

    for (const [pid, origin, name, email, memOrgId, grantOrgId, roleId] of [
      [companyOwnerId, 'company_local', 'Avery CoOwner', 'avery.co@acme.example', ids.companyOrg, ids.companyOrg, ids.roleOwner],
      [directorId, 'company_local', 'Blake Director', 'blake.dir@acme.example', ids.companyOrg, ids.companyOrg, ids.roleDirectorOfSales],
      [accountingId, 'company_local', 'Casey Acct', 'casey.acct@acme.example', ids.companyOrg, ids.companyOrg, ids.roleAccounting],
      [auditNoVendorId, 'company_local', 'Dana AuditNoVend', 'dana.anv@acme.example', ids.companyOrg, ids.companyOrg, auditOnlyRoleId],
      [beaconAuditReaderId, 'company_local', 'Eli BeaconAudit', 'eli.ba@acme.example', ids.beaconOrg, ids.beaconOrg, auditOnlyRoleId],
      [harborAuditReaderId, 'company_local', 'Fran HarborAudit', 'fran.ha@acme.example', ids.harborOrg, ids.harborOrg, auditOnlyRoleId],
      [cobaltUserId, 'company_local', 'Quinn Cobalt', 'quinn@cobalt.example', cobaltOrg, cobaltOrg, cobaltCustomRoleId],
      [quartzUserId, 'company_local', 'Rory Quartz', 'rory@quartz.example', quartzOrg, quartzOrg, quartzCustomRoleId],
      [beaconSupportId, 'nusear_staff', 'Skyler BeaconSup', 'skyler.bs@nusear.example', ids.rootOrg, ids.beaconOrg, ids.roleNusearSupport],
      [staffNoVendorNameId, 'nusear_staff', 'Toby MaskStaff', 'toby.ms@nusear.example', ids.rootOrg, ids.companyOrg, staffNoVendorRoleId],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human',$2,$3)", [pid, origin, seq]);
      await c.query("INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,$3,$4,$4,$5,'active',$6)", [randomUUID(), pid, origin, name, email, seq]);
      await c.query("INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), pid, memOrgId, seq]);
      await c.query("INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)", [randomUUID(), pid, roleId, grantOrgId, seq]);
    }
  });

  // Record a Beacon IAM write and a Cobalt IAM write so we can verify actual target_org_id audit scoping!
  const beaconPersonOut = await iamCmd.createPerson({
    dbToken: supportTok,
    commandKey: 't8-beacon-person',
    organizationId: ids.beaconOrg,
    legalName: 'Gray BeaconHire',
    preferredName: 'Gray BeaconHire',
    primaryEmail: 'gray.bh@acme.example',
  });
  const cobaltPersonOut = await iamCmd.createPerson({
    dbToken: supportTok,
    commandKey: 't8-cobalt-person',
    organizationId: cobaltOrg,
    legalName: 'Harper CobaltHire',
    preferredName: 'Harper CobaltHire',
    primaryEmail: 'harper.ch@cobalt.example',
  });

  const ownerTok = tokenFor(companyOwnerId);
  const directorTok = tokenFor(directorId);
  const accountingTok = tokenFor(accountingId);
  const auditNoVendorTok = tokenFor(auditNoVendorId);
  const beaconAuditTok = tokenFor(beaconAuditReaderId);
  const harborAuditTok = tokenFor(harborAuditReaderId);
  const cobaltTok = tokenFor(cobaltUserId);
  const quartzTok = tokenFor(quartzUserId);
  const beaconSupportTok = tokenFor(beaconSupportId, null, { keyScope: 'nusear_staff' });
  const staffNoVendorTok = tokenFor(staffNoVendorNameId, null, { keyScope: 'nusear_staff' });

  // 8a. Every non-org IAM view (EDGES INCLUDED!) excludes masked vendors for anyone without col:vendors.real_name.
  await t.test('8a: non-staff without col:vendors.real_name see masked names on iam_organizations ONLY and 0 vendor rows on edges/people/memberships/roles/grants/tool_switches/audit_journal', async () => {
    for (const [label, tok] of [
      ['director_of_sales', directorTok],
      ['accounting', accountingTok],
      ['agency_manager', env.iam.tokens.agencyMgr],
      ['selling_agent', env.iam.tokens.agentA],
      ['company_audit_no_vendor', auditNoVendorTok],
      ['nusear_owner View-as director_of_sales', tokenFor(ids.nusearOwner, directorId)],
    ]) {
      await withRequestTx(appPool, tok, async (tx) => {
        const orgs = (await tx.query("SELECT display_name, slug, is_vendor_name_masked FROM app_views.iam_organizations WHERE org_kind = 'lead_vendor' ORDER BY masked_display_name")).rows;
        assert.deepEqual(orgs, [
          { display_name: 'Vendor 01', slug: null, is_vendor_name_masked: true },
          { display_name: 'Vendor 02', slug: null, is_vendor_name_masked: true },
        ], `${label} sees masked vendor catalog in iam_organizations`);
        assert.deepEqual((await tx.query('SELECT id FROM app_views.iam_organization_edges WHERE child_org_id = ANY($1::uuid[])', [[cobaltOrg, quartzOrg]])).rows, [], `${label} must see 0 vendor edges`);
        assert.deepEqual((await tx.query('SELECT id FROM app_views.iam_people WHERE id = ANY($1::uuid[])', [[cobaltUserId, quartzUserId, cobaltPersonOut.result.personId]])).rows, [], `${label} must see 0 vendor people`);
        assert.deepEqual((await tx.query('SELECT id FROM app_views.iam_memberships WHERE organization_id = ANY($1::uuid[])', [[cobaltOrg, quartzOrg]])).rows, [], `${label} must see 0 vendor memberships`);
        assert.deepEqual((await tx.query('SELECT id FROM app_views.iam_roles WHERE id = ANY($1::uuid[])', [[cobaltCustomRoleId, quartzCustomRoleId]])).rows, [], `${label} must see 0 vendor custom roles`);
        assert.deepEqual((await tx.query('SELECT id FROM app_views.iam_role_grants WHERE organization_id = ANY($1::uuid[])', [[cobaltOrg, quartzOrg]])).rows, [], `${label} must see 0 vendor grants`);
        assert.deepEqual((await tx.query('SELECT id, hold_reason FROM app_views.iam_tool_switches WHERE organization_id = ANY($1::uuid[])', [[cobaltOrg, quartzOrg]])).rows, [], `${label} must see 0 vendor tool switches`);
        assert.deepEqual((await tx.query('SELECT seq FROM app_views.audit_journal WHERE target_org_id = ANY($1::uuid[])', [[cobaltOrg, quartzOrg]])).rows, [], `${label} must see 0 vendor audit_journal rows`);
      }, { readOnly: true });
    }
  });

  // 8b. Actual target_org_id audit scoping: Beacon audit reader sees Beacon's IAM audit entry (NOT Harbor or Cobalt); Harbor sees neither; company audit reader without col:vendors.real_name sees Beacon's but NOT Cobalt's; companyOwner WITH col:vendors.real_name sees Cobalt's!
  await t.test('8b: audit entries record the actual target organization (sub-entity scoping works and vendor audit rows stay on vendor org)', async () => {
    const rawAudit = (await env.pool.query(
      'SELECT seq, target_org_id, command_kind FROM platform.audit_journal WHERE seq = ANY($1::bigint[]) ORDER BY seq',
      [[beaconPersonOut.journalSeq, cobaltPersonOut.journalSeq]],
    )).rows;
    assert.deepEqual(
      rawAudit.map((r) => ({ seq: Number(r.seq), target_org_id: r.target_org_id })),
      [
        { seq: beaconPersonOut.journalSeq, target_org_id: ids.beaconOrg },
        { seq: cobaltPersonOut.journalSeq, target_org_id: cobaltOrg },
      ],
      'audit entries must record actual target_org_id (beaconOrg / cobaltOrg, never collapsed to tenant_org_id)',
    );

    await withRequestTx(appPool, beaconAuditTok, async (tx) => {
      const seen = (await tx.query('SELECT seq FROM app_views.audit_journal WHERE seq = ANY($1::bigint[])', [[beaconPersonOut.journalSeq, cobaltPersonOut.journalSeq]])).rows.map((r) => Number(r.seq));
      assert.deepEqual(seen, [beaconPersonOut.journalSeq], 'Beacon audit reader must see Beacon IAM audit entry and 0 Cobalt entries');
    }, { readOnly: true });
    await withRequestTx(appPool, harborAuditTok, async (tx) => {
      const seen = (await tx.query('SELECT seq FROM app_views.audit_journal WHERE seq = ANY($1::bigint[])', [[beaconPersonOut.journalSeq, cobaltPersonOut.journalSeq]])).rows;
      assert.deepEqual(seen, [], 'Harbor audit reader must see 0 Beacon or Cobalt audit entries');
    }, { readOnly: true });
    await withRequestTx(appPool, auditNoVendorTok, async (tx) => {
      const seen = (await tx.query('SELECT seq FROM app_views.audit_journal WHERE seq = ANY($1::bigint[])', [[beaconPersonOut.journalSeq, cobaltPersonOut.journalSeq]])).rows.map((r) => Number(r.seq));
      assert.deepEqual(seen, [beaconPersonOut.journalSeq], 'Company audit reader without col:vendors.real_name sees Beacon entry and 0 Cobalt entries');
    }, { readOnly: true });
    await withRequestTx(appPool, ownerTok, async (tx) => {
      const seen = (await tx.query('SELECT seq FROM app_views.audit_journal WHERE seq = ANY($1::bigint[])', [[beaconPersonOut.journalSeq, cobaltPersonOut.journalSeq]])).rows.map((r) => Number(r.seq));
      assert.deepEqual(seen.sort((a, b) => a - b), [beaconPersonOut.journalSeq, cobaltPersonOut.journalSeq].sort((a, b) => a - b), 'Company owner with col:vendors.real_name sees both Beacon and Cobalt audit entries');
    }, { readOnly: true });
  });

  // 8c. Rival vendor sees own vendor edges/details, ZERO rival edges/details, and ZERO company custom roles.
  await t.test('8c: rival vendor sees own vendor edges/details, 0 rival edges/details, and 0 company custom roles', async () => {
    for (const [label, tok, ownOrg, ownUsers, ownRole, ownHold, rivalOrg] of [
      ['rival vendor quartzUser', quartzTok, quartzOrg, [quartzUserId], quartzCustomRoleId, 'Quartz Leads LLC compliance hold', cobaltOrg],
      ['companyOwner View-as quartzUser', tokenFor(companyOwnerId, quartzUserId), quartzOrg, [quartzUserId], quartzCustomRoleId, 'Quartz Leads LLC compliance hold', cobaltOrg],
      ['cobaltUser', cobaltTok, cobaltOrg, [cobaltUserId, cobaltPersonOut.result.personId].sort(), cobaltCustomRoleId, 'Cobalt Leads LLC compliance hold', quartzOrg],
    ]) {
      await withRequestTx(appPool, tok, async (tx) => {
        assert.deepEqual((await tx.query('SELECT child_org_id FROM app_views.iam_organization_edges')).rows.map((r) => r.child_org_id), [ownOrg], `${label} sees only own vendor edge`);
        assert.deepEqual((await tx.query('SELECT id FROM app_views.iam_people ORDER BY id')).rows.map((r) => r.id), [...ownUsers].sort(), `${label} sees only own vendor people`);
        assert.deepEqual((await tx.query('SELECT DISTINCT organization_id FROM app_views.iam_memberships')).rows.map((r) => r.organization_id), [ownOrg]);
        assert.deepEqual((await tx.query('SELECT organization_id, hold_reason FROM app_views.iam_tool_switches')).rows, [{ organization_id: ownOrg, hold_reason: ownHold }]);
        assert.deepEqual((await tx.query('SELECT id FROM app_views.iam_role_grants WHERE organization_id = $1', [rivalOrg])).rows, []);
        const visibleCustomRoles = (await tx.query('SELECT id FROM app_views.iam_roles WHERE owner_org_id IS NOT NULL')).rows;
        assert.deepEqual(visibleCustomRoles.map((r) => r.id), [ownRole]);
        assert.deepEqual((await tx.query('SELECT role_id FROM app_views.iam_role_rights WHERE role_id = $1', [acmeSecretRoleId])).rows, []);
      }, { readOnly: true });
    }

    // Positive control: companyOwner (holds col:vendors.real_name) sees Cobalt edge, people, roles, tool switches.
    await withRequestTx(appPool, ownerTok, async (tx) => {
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.iam_organization_edges WHERE child_org_id = $1', [cobaltOrg])).rows[0].n, 1);
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.iam_people WHERE id = $1', [cobaltUserId])).rows[0].n, 1);
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.iam_roles WHERE id = $1', [cobaltCustomRoleId])).rows[0].n, 1);
      assert.equal((await tx.query('SELECT COUNT(*)::int AS n FROM app_views.iam_tool_switches WHERE organization_id = $1', [cobaltOrg])).rows[0].n, 1);
    }, { readOnly: true });
  });

  // 8d. show_nusear unlocks grants/memberships only at platform_root, never sibling companies or out-of-scope agencies.
  await t.test('8d: show_nusear grants stay scoped to platform_root', async () => {
    await withRequestTx(appPool, supportTok, async (tx) => {
      assert.deepEqual((await tx.query('SELECT id FROM app_views.iam_role_grants WHERE id = $1 OR organization_id = $2', [northstarOpGrantId, ids.northstarOrg])).rows, []);
      assert.ok((await tx.query('SELECT id FROM app_views.iam_role_grants WHERE organization_id = $1', [ids.rootOrg])).rows.length >= 1);
    }, { readOnly: true });
    await withRequestTx(appPool, beaconSupportTok, async (tx) => {
      assert.deepEqual((await tx.query('SELECT id FROM app_views.iam_role_grants WHERE organization_id = ANY($1::uuid[])', [[ids.harborOrg, ids.northstarOrg]])).rows, []);
      assert.deepEqual((await tx.query('SELECT id FROM app_views.iam_memberships WHERE organization_id = ANY($1::uuid[])', [[ids.harborOrg, ids.northstarOrg]])).rows, []);
    }, { readOnly: true });
  });

  // 8e. Vendor identity guard on create, update, AND idempotent replay without col:vendors.real_name!
  await t.test('8e: vendor real identity guarded on create, update, and replay without col:vendors.real_name', async () => {
    // Creating a lead_vendor without col:vendors.real_name is refused!
    await assertRefusedNoWrite(
      env.pool,
      ['iam.organizations', 'iam.organization_versions'],
      () => iamCmd.createOrganization({
        dbToken: staffNoVendorTok,
        commandKey: 't8-no-realname-create-vendor',
        orgKind: 'lead_vendor',
        slug: 'secret_vendor',
        displayName: 'Secret Vendor LLC',
        parentOrgId: ids.companyOrg,
        maskedDisplayName: 'Vendor 99',
      }),
      (err) => err?.status === 403,
      'staff without col:vendors.real_name must not create a lead_vendor',
    );

    // Updating masked_display_name without col:vendors.real_name works and never echoes real identity (neither fresh nor replay).
    const maskedUpd = await iamCmd.updateOrganization({
      dbToken: staffNoVendorTok,
      commandKey: 't8-mask-update',
      organizationId: cobaltOrg,
      maskedDisplayName: 'Vendor 01 Renamed',
    });
    assert.equal(maskedUpd.result.displayName, 'Vendor 01 Renamed');
    assert.equal(maskedUpd.result.slug, null);
    assert.equal(maskedUpd.result.externalDomain, null);
    assert.doesNotMatch(JSON.stringify(maskedUpd), /Cobalt Leads|cobalt_leads|cobalt\.example/i);

    const maskedReplay = await iamCmd.updateOrganization({
      dbToken: staffNoVendorTok,
      commandKey: 't8-mask-update',
      organizationId: cobaltOrg,
      maskedDisplayName: 'Vendor 01 Renamed',
    });
    assert.equal(maskedReplay.idempotent, true);
    assert.doesNotMatch(JSON.stringify(maskedReplay), /Cobalt Leads|cobalt_leads|cobalt\.example/i);

    // Overwriting real displayName without col:vendors.real_name is refused 403 with zero writes!
    await assertRefusedNoWrite(
      env.pool,
      'iam.organization_versions',
      () => iamCmd.updateOrganization({
        dbToken: staffNoVendorTok,
        commandKey: 't8-mask-overwrite-real',
        organizationId: cobaltOrg,
        displayName: 'Overwritten Name',
      }),
      (err) => err?.status === 403,
      'staff without col:vendors.real_name must not overwrite lead_vendor real display_name',
    );

    // Real name stays preserved for callers with col:vendors.real_name.
    await withRequestTx(appPool, ownerTok, async (tx) => {
      const row = (await tx.query('SELECT slug, display_name, masked_display_name, external_domain FROM app_views.iam_organizations WHERE id = $1', [cobaltOrg])).rows[0];
      assert.deepEqual(row, { slug: 'cobalt_leads', display_name: 'Cobalt Leads', masked_display_name: 'Vendor 01 Renamed', external_domain: 'cobalt.example' });
    }, { readOnly: true });
  });

  // 8f. A lead_vendor is a leaf: iam.trg_verify_org_edge() refuses any organization beneath a lead_vendor
  //     via createOrganization, setOrganizationEdge, and direct SQL INSERT.
  await t.test('8f: lead_vendor is a leaf (createOrganization, setOrganizationEdge, and direct SQL refuse children under a lead_vendor)', async () => {
    for (const [orgKind, slug] of [['team', 'bad_vendor_team'], ['agency', 'bad_vendor_agency'], ['lead_vendor', 'bad_nested_vendor']]) {
      await assertRefusedNoWrite(
        env.pool,
        ['iam.organizations', 'iam.organization_versions', 'iam.organization_edges'],
        () => iamCmd.createOrganization({
          dbToken: supportTok,
          commandKey: `t8-leaf-create-${orgKind}`,
          orgKind,
          slug,
          displayName: `Bad Under Vendor ${orgKind}`,
          parentOrgId: cobaltOrg,
          maskedDisplayName: orgKind === 'lead_vendor' ? 'Vendor 99' : null,
        }),
        (err) => err?.status === 409 && err?.code === 'LEAD_VENDOR_IS_LEAF',
        `createOrganization(${orgKind}) under lead_vendor must fail 409 LEAD_VENDOR_IS_LEAF`,
      );
    }

    const eastEdgeId = (await env.pool.query(
      "SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND superseded_by_id IS NULL AND status = 'active'",
      [ids.eastTeamOrg],
    )).rows[0].id;
    await assertRefusedNoWrite(
      env.pool,
      'iam.organization_edges',
      () => iamCmd.setOrganizationEdge({
        dbToken: supportTok,
        commandKey: 't8-leaf-move-east',
        childOrgId: ids.eastTeamOrg,
        parentOrgId: cobaltOrg,
        validRange: '[2027-01-01,)',
        closeEdgeId: eastEdgeId,
        closeValidRange: '[2020-01-01,2027-01-01)',
      }),
      (err) => err?.status === 409 && err?.code === 'LEAD_VENDOR_IS_LEAF',
      'setOrganizationEdge attaching existing org under lead_vendor must fail 409 LEAD_VENDOR_IS_LEAF',
    );

    await assert.rejects(
      () => inSerializableTx(env.pool, async (c) => {
        const seq = (await appendIamAuditEntry(c, { environment: env.iam.environment, targetOrgId: cobaltOrg, commandKey: `t8-leaf-sql-${randomUUID()}` })).seq;
        const rogueOrg = randomUUID();
        await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'team',$2)", [rogueOrg, seq]);
        await c.query("INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'rogue_vendor_child','Rogue Child','active',$3)", [randomUUID(), rogueOrg, seq]);
        await c.query("INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2026-01-01,)'::daterange,'active',$4)", [randomUUID(), rogueOrg, cobaltOrg, seq]);
      }),
      (err) => err?.code === '23514' && /LEAD_VENDOR_IS_LEAF/.test(err?.message || ''),
      'direct SQL edge under lead_vendor must fail 23514 LEAD_VENDOR_IS_LEAF',
    );
  });

  // 8g. app_views.iam_role_grant_people unfiltered read hides masked vendor subjects without col:vendors.real_name.
  await t.test('8g: unfiltered iam_role_grant_people hides invisible/masked vendor subjects', async () => {
    const compUserId = (await iamCmd.createPerson({
      dbToken: supportTok,
      commandKey: 't8g-comp-user',
      organizationId: ids.beaconOrg,
      legalName: 'Sage CompMask',
      preferredName: 'Sage CompMask',
      primaryEmail: 'sage.cm@acme.example',
      validRange: '[2020-01-01,)',
    })).result.personId;
    const compGrantId = (await iamCmd.grantRole({
      dbToken: supportTok,
      commandKey: 't8g-comp-grant',
      personId: compUserId,
      roleId: ids.roleCompliance,
      organizationId: ids.beaconOrg,
      personScopeMode: 'explicit_people',
      validRange: '[2020-01-01,)',
      subjectPersonIds: [ids.agentA, cobaltUserId],
    })).result.roleGrantId;

    for (const [label, tok] of [
      ['director_of_sales', directorTok],
      ['accounting', accountingTok],
      ['agency_manager', env.iam.tokens.agencyMgr],
      ['company_audit_no_vendor', auditNoVendorTok],
      ['nusear_owner View-as director_of_sales', tokenFor(ids.nusearOwner, directorId)],
    ]) {
      await withRequestTx(appPool, tok, async (tx) => {
        const rows = (await tx.query(
          'SELECT role_grant_id, subject_person_id FROM app_views.iam_role_grant_people ORDER BY subject_person_id',
        )).rows;
        assert.deepEqual(
          rows,
          [{ role_grant_id: compGrantId, subject_person_id: ids.agentA }],
          `${label} reading unfiltered app_views.iam_role_grant_people must see agentA and never masked vendor subject cobaltUserId`,
        );
      }, { readOnly: true });
    }
    await withRequestTx(appPool, ownerTok, async (tx) => {
      const rows = (await tx.query(
        'SELECT role_grant_id, subject_person_id FROM app_views.iam_role_grant_people ORDER BY subject_person_id',
      )).rows;
      assert.deepEqual(
        rows,
        [ids.agentA, cobaltUserId].sort().map((sid) => ({ role_grant_id: compGrantId, subject_person_id: sid })),
        'company owner with col:vendors.real_name sees both agentA and cobaltUserId in unfiltered app_views.iam_role_grant_people',
      );
    }, { readOnly: true });

    // EXPLAIN InitPlan check on app_views.iam_role_grant_people.
    const rgpPlan = await withRequestTx(appPool, directorTok, async (tx) => (
      (await tx.query('EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT * FROM app_views.iam_role_grant_people')).rows[0]['QUERY PLAN'][0].Plan
    ), { readOnly: true });
    const rgpStats = inspectIamViewPlan(rgpPlan);
    assert.deepEqual(rgpStats.perRowSubPlans, [], 'iam_role_grant_people must have 0 per-row SubPlans');
    assert.deepEqual(rgpStats.highLoopNodes, [], 'iam_role_grant_people must evaluate read helpers at most once');
  });

  // 8h. app_views.iam_people masks house_org_id whenever that organization is outside caller's visible detail orgs.
  await t.test('8h: iam_people shows house_org_id only when that organization is in caller visible detail organizations', async () => {

    // House accounts with a secondary membership at Beacon so narrower callers can see the person row
    // while house_org_id (Harbor or masked Cobalt) is outside their visible detail organizations.
    const harborHouseId = (await iamCmd.createPerson({
      dbToken: supportTok,
      commandKey: 't8g-harbor-house',
      organizationId: ids.harborOrg,
      legalName: 'Harbor House Account',
      preferredName: 'Harbor House',
      personKind: 'house_account',
      houseOrgId: ids.harborOrg,
      validRange: '[2020-01-01,)',
    })).result.personId;
    await iamCmd.setMembership({
      dbToken: supportTok,
      commandKey: 't8g-harbor-house-beacon-mem',
      personId: harborHouseId,
      organizationId: ids.beaconOrg,
      validRange: '[2020-01-01,)',
    });
    const cobaltHouseId = (await iamCmd.createPerson({
      dbToken: supportTok,
      commandKey: 't8g-cobalt-house',
      organizationId: cobaltOrg,
      legalName: 'Cobalt House Account',
      preferredName: 'Cobalt House',
      personKind: 'house_account',
      houseOrgId: cobaltOrg,
      validRange: '[2020-01-01,)',
    })).result.personId;
    await iamCmd.setMembership({
      dbToken: supportTok,
      commandKey: 't8g-cobalt-house-beacon-mem',
      personId: cobaltHouseId,
      organizationId: ids.beaconOrg,
      validRange: '[2020-01-01,)',
    });

    const houseMapFor = async (tok) => withRequestTx(appPool, tok, async (tx) => (
      new Map((await tx.query(
        'SELECT id, house_org_id FROM app_views.iam_people WHERE id = ANY($1::uuid[])',
        [[harborHouseId, cobaltHouseId]],
      )).rows.map((r) => [r.id, r.house_org_id]))
    ), { readOnly: true });

    const bmMap = await houseMapFor(env.iam.tokens.agencyMgr);
    assert.equal(bmMap.get(harborHouseId), null, 'Beacon manager must see house_org_id = NULL when house org is Harbor (outside detail orgs)');
    assert.equal(bmMap.get(cobaltHouseId), null, 'Beacon manager must see house_org_id = NULL when house org is masked Cobalt');

    for (const [label, tok] of [
      ['director_of_sales', directorTok],
      ['nusear_owner View-as director_of_sales', tokenFor(ids.nusearOwner, directorId)],
    ]) {
      const dirMap = await houseMapFor(tok);
      assert.equal(dirMap.get(harborHouseId), ids.harborOrg, `${label} sees Harbor house_org_id when Harbor is visible`);
      assert.equal(dirMap.get(cobaltHouseId), null, `${label} must see house_org_id = NULL when house org is masked Cobalt`);
    }

    const ownerMap = await houseMapFor(ownerTok);
    assert.equal(ownerMap.get(harborHouseId), ids.harborOrg, 'company owner sees Harbor house_org_id');
    assert.equal(ownerMap.get(cobaltHouseId), cobaltOrg, 'company owner with col:vendors.real_name sees Cobalt house_org_id');
  });
});
