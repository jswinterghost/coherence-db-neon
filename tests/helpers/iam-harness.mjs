// Test-only IAM seeding, signed token minting, and role-scoped pool harness for Release 1B proofs.
// Never imported by runtime code under src/.
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { sha256Hex } from '../../src/util/crypto.mjs';

export function mintSignedToken({
  keyId,
  secretBytes,
  environment = 'local',
  sessionId = randomUUID(),
  actorPersonId,
  viewAsPersonId = null,
  expEpoch = Math.floor(Date.now() / 1000) + 120,
}) {
  const viewAsPart = viewAsPersonId ?? '-';
  const payload = `v1|${keyId}|${environment}|${sessionId}|${actorPersonId}|${viewAsPart}|${expEpoch}`;
  const sig = createHmac('sha256', secretBytes).update(payload, 'utf8').digest('hex');
  return `${payload}|${sig}`;
}

/**
 * Test-only pg.Pool adapter that sets the session role to roleName (default platform_app) on
 * checkout BEFORE any transaction starts, simulating a service account logged in as platform_app
 * without requiring runtime code to ever execute SET LOCAL ROLE.
 */
export function createRoleScopedTestPool(basePool, roleName = 'platform_app') {
  if (!/^[a-z_][a-z0-9_]*$/.test(roleName)) {
    throw new Error(`Invalid test role name: ${roleName}`);
  }

  async function checkout() {
    const raw = await basePool.connect();
    try {
      await raw.query(`SET ROLE "${roleName}"`);
      await raw.query("SELECT pg_catalog.set_config('app.session_token', '', false)");
    } catch (err) {
      raw.release(err);
      throw err;
    }
    let released = false;
    return {
      query: (...args) => raw.query(...args),
      release(destroyErr) {
        if (released) return;
        released = true;
        if (destroyErr) {
          raw.release(destroyErr);
          return;
        }
        raw.query("RESET ROLE; SELECT pg_catalog.set_config('app.session_token', '', false)")
          .then(() => raw.release(), (e) => raw.release(e));
      },
    };
  }

  return {
    connect: checkout,
    async query(...args) {
      const c = await checkout();
      let failed = null;
      try {
        return await c.query(...args);
      } catch (err) {
        failed = err;
        throw err;
      } finally {
        c.release(failed && !failed.code ? failed : undefined);
      }
    },
    async end() {},
  };
}

export async function appendIamAuditEntry(client, {
  environment = 'local',
  actorPersonId = null,
  recordedAs = 'service',
  targetOrgId = null,
  commandKind = 'iam.seed_r1b',
  commandKey = `seed-${randomUUID()}`,
  body = {},
} = {}) {
  const reqHash = sha256Hex(JSON.stringify({ commandKind, commandKey, body }));
  const res = await client.query(
    `INSERT INTO platform.audit_journal (
       environment, actor_person_id, recorded_as, target_org_id,
       command_kind, command_key, request_sha256, body
     ) VALUES ($1, $2::uuid, $3, $4::uuid, $5, $6, $7, $8::jsonb)
     RETURNING seq`,
    [environment, actorPersonId, recordedAs, targetOrgId, commandKind, commandKey, reqHash, JSON.stringify(body)],
  );
  return res.rows[0];
}

export async function seedCoherenceIamFixture(pool, {
  companySlug = 'acme',
  displayName = 'Acme',
  environment = 'local',
  extraAgencies = [],
  extraAgents = [],
} = {}) {
  const keyId = `k_r1b_${randomBytes(4).toString('hex')}`;
  const secretBytes = randomBytes(32);

  const ids = {
    rootOrg: randomUUID(),
    companyOrg: randomUUID(),
    beaconOrg: randomUUID(),
    eastTeamOrg: randomUUID(),
    harborOrg: randomUUID(),
    northstarOrg: randomUUID(),
    switchAcmeCoherenceId: randomUUID(),

    nusearOwner: randomUUID(),
    nusearAdminNoCoh: randomUUID(),
    nusearOperator: randomUUID(),
    northstarOperator: randomUUID(),
    workerService: randomUUID(),
    entityMgr: randomUUID(),
    companyAdmin: randomUUID(),
    companyAdminRunsOnly: randomUUID(),
    companyAdminNoGrants: randomUUID(),
    investor: randomUUID(),
    beaconManager: randomUUID(),
    leadManager: randomUUID(),
    teamManager: randomUUID(),
    harborRetention: randomUUID(),
    agentA: randomUUID(),
    agentB: randomUUID(),
    agentEast: randomUUID(),
    agentHarbor: randomUUID(),
    suspendedAgent: randomUUID(),

    roleNusearOwner: randomUUID(),
    roleNusearAdmin: randomUUID(),
    roleCoherenceOperator: randomUUID(),
    roleWorkerService: randomUUID(),
    roleEntityManager: randomUUID(),
    roleCompanyAdmin: randomUUID(),
    roleCompanyAdminRunsOnly: randomUUID(),
    roleCompanyAdminNoGrants: randomUUID(),
    roleInvestor: randomUUID(),
    roleAgencyManager: randomUUID(),
    roleTeamManager: randomUUID(),
    roleSellingAgent: randomUUID(),
    roleRetentionAgent: randomUUID(),
  };

  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    const j1 = await appendIamAuditEntry(client, {
      environment,
      commandKind: 'iam.bootstrap_r1b',
      commandKey: `bootstrap-r1b-${randomUUID()}`,
    });
    const seq = j1.seq;

    const orgList = [
      [ids.rootOrg, 'platform_root', 'nusear', 'Nusear', null],
      [ids.companyOrg, 'company', companySlug, displayName, ids.rootOrg],
      [ids.beaconOrg, 'agency', `${companySlug}_beacon`, 'Beacon', ids.companyOrg],
      [ids.eastTeamOrg, 'team', `${companySlug}_east_team`, 'East Team', ids.beaconOrg],
      [ids.harborOrg, 'agency', `${companySlug}_harbor`, 'Harbor', ids.companyOrg],
      [ids.northstarOrg, 'company', 'northstar', 'Northstar', ids.rootOrg],
    ];
    for (const ag of extraAgencies) {
      const agId = ag.id || randomUUID();
      ids[ag.key || ag.slug] = agId;
      orgList.push([agId, ag.kind || 'agency', ag.slug, ag.displayName, ag.parentOrgId || ids.companyOrg]);
    }

    for (const [id, kind] of orgList) {
      await client.query('INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,$2,$3)', [id, kind, seq]);
    }
    await client.query(
      `INSERT INTO iam.database_context (singleton, environment, db_role_kind, tenant_org_id, company_slug, support_external_label, journal_seq)
       VALUES (true, $1, 'company_working', $2, $3, 'Nusear support', $4)`,
      [environment, ids.companyOrg, companySlug, seq],
    );
    await client.query(
      `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, active_from, active_until)
       VALUES ($1, $2, $3, pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours')`,
      [keyId, secretBytes, environment],
    );

    for (const [id, display] of [['coherence', 'Coherence'], ['platform_audit', 'Platform Audit']]) {
      await client.query(
        'INSERT INTO iam.tools (id, display_name, is_nusear_only, is_customer_switchable, journal_seq) VALUES ($1,$2,false,true,$3)',
        [id, display, seq],
      );
    }

    const rights = [
      ['act:coherence.bob.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read Book of Business'],
      ['act:coherence.statements.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read agency statements'],
      ['act:coherence.upline.read', 'action', 'coherence', 'both', 'money_upline', true, null, null, null, 'Read upline statements'],
      ['act:coherence.ledger.read', 'action', 'coherence', 'both', 'money_upline', true, null, null, null, 'Read Coherent Ledger'],
      ['act:coherence.unpublished.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read published unsent runs'],
      ['act:coherence.runs.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read run metadata'],
      ['act:coherence.inputs.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read input versions'],
      ['act:coherence.outputs.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read data-only run outputs'],
      ['act:coherence.decisions.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read decision records and review configs'],
      ['act:coherence.checks.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read check reports'],
      ['act:coherence.journal.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read Coherence journal'],
      ['act:platform.audit_journal.read', 'action', 'platform_audit', 'both', 'ordinary', true, null, null, null, 'Read platform audit journal'],
      ['col:coherence.statement_cash', 'column', 'coherence', 'both', 'money_statement', true, 'coherence', 'bob_policy_financials', 'amount', 'View agency statement cash'],
      ['col:coherence.upline_cash', 'column', 'coherence', 'both', 'money_upline', true, 'coherence', 'bob_policy_financials', 'upline_amount', 'View upline and gross cash'],
      ['col:platform.audit_journal.nusear_actor', 'column', 'platform_audit', 'both', 'platform_internal', true, 'platform', 'audit_journal', 'actor_person_id', 'View Nusear actor identity'],
      ['act:coherence.run.launch', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Launch Coherence run'],
      ['act:coherence.run.retry', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Retry Coherence step'],
      ['act:coherence.run.cancel', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Cancel Coherence step'],
      ['act:coherence.review.submit', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Submit staged review CSV'],
      ['act:coherence.review.save', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Save review decisions'],
      ['act:coherence.review.draft', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Save review draft'],
      ['act:coherence.inputs.publish', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Publish input version'],
      ['act:coherence.approvals.register', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Register approvals file'],
      ['act:coherence.owner.confirm_emit', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Confirm Emit'],
      ['act:coherence.owner.carry_sent', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Carry sent statements'],
      ['act:coherence.owner.carry_approvals', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Carry approvals file'],
      ['act:coherence.owner.carry_decisions', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Carry decisions'],
      ['act:coherence.owner.abandon_run', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Abandon run'],
      ['act:coherence.owner.init_company', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Initialize company metadata'],
      ['act:coherence.owner.register_engine', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Register engine version'],
      ['act:coherence.owner.record_baseline', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Record decision baseline'],
      ['act:coherence.owner.record_statement_batch', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Record standalone statement batch'],
      ['act:coherence.owner.import_history', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Import historical runs and files'],
      ['act:coherence.checks.record', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Record check report'],
      ['act:coherence.files.register', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Register stored files'],
      ['act:coherence.overlays.record', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Record generated overlay'],
      ['act:coherence.emit.materialize', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Materialize Emit outputs'],
      ['act:coherence.worker.attempt', 'action', 'coherence', 'both', 'platform_internal', false, null, null, null, 'Worker step attempt lifecycle'],
      ['act:coherence.worker.review', 'action', 'coherence', 'both', 'platform_internal', false, null, null, null, 'Worker review submission resolution'],
    ];
    for (const r of rights) {
      await client.query(
        `INSERT INTO iam.rights (
           id, right_kind, tool_id, environment_scope, sensitivity_class, is_delegable_power,
           target_schema, target_table, target_column, description, journal_seq
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [...r, seq],
      );
    }

    const roleSpecs = [
      [ids.roleNusearOwner, 'nusear_owner', 'Nusear Owner', true, true, true],
      [ids.roleNusearAdmin, 'nusear_admin', 'Nusear Admin', false, true, true],
      [ids.roleCoherenceOperator, 'coherence_operator', 'Coherence Operator', false, true, true],
      [ids.roleWorkerService, 'coherence_worker_svc', 'Coherence Worker', true, true, true],
      [ids.roleEntityManager, 'entity_manager', 'Entity Manager', false, false, true],
      [ids.roleCompanyAdmin, 'company_admin', 'Company Admin', false, false, true],
      [ids.roleCompanyAdminRunsOnly, 'company_admin_runs_only', 'Company Admin Runs Only', false, false, true],
      [ids.roleCompanyAdminNoGrants, 'company_admin_none', 'Company Admin No Grants', false, false, true],
      [ids.roleInvestor, 'investor', 'Investor', false, false, true],
      [ids.roleAgencyManager, 'agency_manager', 'Agency Manager', false, false, true],
      [ids.roleTeamManager, 'team_manager', 'Team Manager', false, false, false],
      [ids.roleSellingAgent, 'selling_agent', 'Selling Agent', false, false, false],
      [ids.roleRetentionAgent, 'retention_agent', 'Retention Agent', false, false, true],
    ];
    for (const [id, slug, display, pinned, internal, wide] of roleSpecs) {
      await client.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,NULL,$3)', [id, slug, seq]);
      await client.query(
        `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq)
         VALUES ($1,$2,$3,$4,$5,$6,'active',$7)`,
        [randomUUID(), id, display, pinned, internal, wide, seq],
      );
    }

    const addRoleRights = async (roleId, list) => {
      for (const rightId of list) {
        await client.query(
          "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), roleId, rightId, seq],
        );
      }
    };

    const allNonWorkerRights = rights.map((r) => r[0]).filter((id) => !id.startsWith('act:coherence.worker.'));
    await addRoleRights(ids.roleNusearOwner, allNonWorkerRights);
    await addRoleRights(ids.roleNusearAdmin, [
      'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
      'act:coherence.ledger.read', 'act:coherence.unpublished.read', 'act:coherence.runs.read',
      'act:coherence.inputs.read', 'act:coherence.outputs.read', 'act:coherence.decisions.read',
      'act:coherence.checks.read', 'act:coherence.journal.read', 'act:platform.audit_journal.read',
      'col:coherence.statement_cash', 'col:coherence.upline_cash', 'col:platform.audit_journal.nusear_actor',
    ]);
    await addRoleRights(ids.roleCoherenceOperator, [
      'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
      'act:coherence.ledger.read', 'act:coherence.unpublished.read', 'act:coherence.runs.read',
      'act:coherence.inputs.read', 'act:coherence.outputs.read', 'act:coherence.decisions.read',
      'act:coherence.checks.read', 'act:coherence.journal.read', 'act:platform.audit_journal.read',
      'col:coherence.statement_cash', 'col:coherence.upline_cash', 'col:platform.audit_journal.nusear_actor',
      'act:coherence.run.launch', 'act:coherence.run.retry', 'act:coherence.run.cancel',
      'act:coherence.review.submit', 'act:coherence.review.save', 'act:coherence.review.draft',
      'act:coherence.inputs.publish', 'act:coherence.approvals.register',
    ]);
    await addRoleRights(ids.roleWorkerService, [
      'act:coherence.worker.attempt', 'act:coherence.worker.review',
      'act:coherence.checks.record', 'act:coherence.files.register',
      'act:coherence.overlays.record', 'act:coherence.emit.materialize',
    ]);
    await addRoleRights(ids.roleEntityManager, [
      'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
      'act:coherence.ledger.read', 'act:coherence.unpublished.read',
      'act:platform.audit_journal.read',
      'col:coherence.statement_cash', 'col:coherence.upline_cash',
    ]);
    await addRoleRights(ids.roleCompanyAdmin, [
      'act:coherence.runs.read', 'act:coherence.inputs.read', 'act:coherence.outputs.read',
      'act:platform.audit_journal.read',
    ]);
    await addRoleRights(ids.roleCompanyAdminRunsOnly, ['act:coherence.runs.read']);
    await addRoleRights(ids.roleCompanyAdminNoGrants, ['act:platform.audit_journal.read']);
    await addRoleRights(ids.roleInvestor, [
      'act:coherence.bob.read', 'col:coherence.statement_cash', 'col:coherence.upline_cash',
    ]);
    await addRoleRights(ids.roleAgencyManager, [
      'act:coherence.bob.read', 'act:coherence.statements.read', 'col:coherence.statement_cash',
    ]);
    await addRoleRights(ids.roleTeamManager, [
      'act:coherence.bob.read', 'act:coherence.statements.read',
    ]);
    await addRoleRights(ids.roleSellingAgent, [
      'act:coherence.bob.read', 'act:coherence.statements.read',
    ]);
    await addRoleRights(ids.roleRetentionAgent, [
      'act:coherence.bob.read', 'act:coherence.statements.read',
    ]);

    for (const [orgId, , slug, name, parentId] of orgList) {
      await client.query(
        `INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq)
         VALUES ($1,$2,$3,$4,'active',$5)`,
        [randomUUID(), orgId, slug, name, seq],
      );
      if (parentId) {
        await client.query(
          `INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq)
           VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)`,
          [randomUUID(), orgId, parentId, seq],
        );
      }
    }

    await client.query(
      `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq)
       VALUES ($1,$2,'coherence','on','active',$3)`,
      [ids.switchAcmeCoherenceId, ids.companyOrg, seq],
    );
    await client.query(
      `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq)
       VALUES ($1,$2,'platform_audit','on','active',$3)`,
      [randomUUID(), ids.companyOrg, seq],
    );
    for (const toolId of ['coherence', 'platform_audit']) {
      await client.query(
        `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq)
         VALUES ($1,$2,$3,'on','active',$4)`,
        [randomUUID(), ids.northstarOrg, toolId, seq],
      );
    }

    const humanPeople = [
      [ids.nusearOwner, 'Pat Platform', 'pat.owner@nusear.example', null, 'active'],
      [ids.nusearAdminNoCoh, 'Morgan Admin', 'morgan.admin@nusear.example', null, 'active'],
      [ids.nusearOperator, 'Casey Operator', 'casey.op@nusear.example', null, 'active'],
      [ids.northstarOperator, 'Devon Northstar', 'devon.ns@nusear.example', null, 'active'],
      [ids.entityMgr, 'Dana Entity', 'dana.em@acme.example', null, 'active'],
      [ids.companyAdmin, 'Sloan Admin', 'sloan.admin@acme.example', null, 'active'],
      [ids.companyAdminRunsOnly, 'Skylar Runs', 'skylar.runs@acme.example', null, 'active'],
      [ids.companyAdminNoGrants, 'Quinn None', 'quinn.none@acme.example', null, 'active'],
      [ids.investor, 'Avery Investor', 'avery.inv@acme.example', null, 'active'],
      [ids.beaconManager, 'Taylor Beacon', 'taylor.bm@acme.example', null, 'active'],
      [ids.leadManager, 'Lee Lead', 'lee.lm@acme.example', null, 'active'],
      [ids.teamManager, 'Riley Team', 'riley.tm@acme.example', null, 'active'],
      [ids.harborRetention, 'Jordan Retain', 'jordan.ret@acme.example', null, 'active'],
      [ids.agentA, 'Sam Seller', 'sam.a@acme.example', '11111111', 'active'],
      [ids.agentB, 'Sam Seller', 'sam.b@acme.example', '22222222', 'active'],
      [ids.agentEast, 'Jamie East', 'jamie.east@acme.example', '44444444', 'active'],
      [ids.agentHarbor, 'Robin Harbor', 'robin.harbor@acme.example', '33333333', 'active'],
      [ids.suspendedAgent, 'Chris Suspended', 'chris.susp@acme.example', '55555555', 'suspended'],
    ];
    for (const [id, name, email, npn, status] of humanPeople) {
      await client.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [id, seq]);
      await client.query(
        `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, npn, status, journal_seq)
         VALUES ($1,$2,$3,$3,$4,$5,$6,$7)`,
        [randomUUID(), id, name, email, npn, status, seq],
      );
    }
    await client.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'service',$2)", [ids.workerService, seq]);
    await client.query(
      `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, status, journal_seq)
       VALUES ($1,$2,'Coherence Worker','Coherence Worker','active',$3)`,
      [randomUUID(), ids.workerService, seq],
    );

    for (const [personId, orgId, cap] of [
      [ids.nusearOwner, ids.rootOrg, 'owner'],
      [ids.nusearAdminNoCoh, ids.rootOrg, 'employee'],
      [ids.nusearOperator, ids.rootOrg, 'employee'],
      [ids.northstarOperator, ids.rootOrg, 'employee'],
      [ids.workerService, ids.rootOrg, 'employee'],
      [ids.entityMgr, ids.companyOrg, 'owner'],
      [ids.companyAdmin, ids.companyOrg, 'employee'],
      [ids.companyAdminRunsOnly, ids.companyOrg, 'employee'],
      [ids.companyAdminNoGrants, ids.companyOrg, 'employee'],
      [ids.investor, ids.companyOrg, 'investor'],
      [ids.beaconManager, ids.beaconOrg, 'employee'],
      [ids.leadManager, ids.beaconOrg, 'employee'],
      [ids.teamManager, ids.beaconOrg, 'employee'],
      [ids.harborRetention, ids.harborOrg, 'employee'],
    ]) {
      await client.query(
        `INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,$4,'[2020-01-01,)'::daterange,'active',$5)`,
        [randomUUID(), personId, orgId, cap, seq],
      );
    }

    const affiliations = [
      [ids.agentA, '11111111', ids.beaconOrg, 'Sam Seller 1'],
      [ids.agentB, '22222222', ids.beaconOrg, 'Sam Seller 2'],
      [ids.agentEast, '44444444', ids.eastTeamOrg, 'Jamie East'],
      [ids.agentHarbor, '33333333', ids.harborOrg, 'Robin Harbor'],
      [ids.suspendedAgent, '55555555', ids.beaconOrg, 'Chris Suspended'],
    ];
    for (const ag of extraAgents) {
      const pid = ag.id || randomUUID();
      ids[ag.key || ag.npn] = pid;
      await client.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [pid, seq]);
      await client.query(
        `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, npn, status, journal_seq)
         VALUES ($1,$2,$3,$3,$4,'active',$5)`,
        [randomUUID(), pid, ag.name, ag.npn, seq],
      );
      affiliations.push([pid, ag.npn, ag.orgId || ids.companyOrg, ag.name]);
      await client.query(
        `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,$4,true,'self','[2020-01-01,)'::daterange,'active',$5)`,
        [randomUUID(), pid, ids.roleSellingAgent, ag.orgId || ids.companyOrg, seq],
      );
    }
    for (const [personId, npn, orgId, fileName] of affiliations) {
      await client.query(
        `INSERT INTO iam.agent_affiliations (id, person_id, npn, agency_org_id, split_bps, agent_file_name, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,$4,8000,$5,'[2020-01-01,)'::daterange,'active',$6)`,
        [randomUUID(), personId, npn, orgId, fileName, seq],
      );
    }

    for (const [personId, roleId, orgId, mode] of [
      [ids.nusearOwner, ids.roleNusearOwner, ids.rootOrg, 'org_subtree'],
      [ids.nusearAdminNoCoh, ids.roleNusearAdmin, ids.rootOrg, 'org_subtree'],
      [ids.nusearOperator, ids.roleCoherenceOperator, ids.companyOrg, 'org_subtree'],
      [ids.northstarOperator, ids.roleCoherenceOperator, ids.northstarOrg, 'org_subtree'],
      [ids.workerService, ids.roleWorkerService, ids.rootOrg, 'org_subtree'],
      [ids.entityMgr, ids.roleEntityManager, ids.companyOrg, 'org_subtree'],
      [ids.companyAdmin, ids.roleCompanyAdmin, ids.companyOrg, 'org_subtree'],
      [ids.companyAdminRunsOnly, ids.roleCompanyAdminRunsOnly, ids.companyOrg, 'org_subtree'],
      [ids.companyAdminNoGrants, ids.roleCompanyAdminNoGrants, ids.companyOrg, 'org_subtree'],
      [ids.investor, ids.roleInvestor, ids.companyOrg, 'org_subtree'],
      [ids.beaconManager, ids.roleAgencyManager, ids.beaconOrg, 'org_subtree'],
      [ids.harborRetention, ids.roleRetentionAgent, ids.harborOrg, 'org_subtree'],
      [ids.agentA, ids.roleSellingAgent, ids.beaconOrg, 'self'],
      [ids.agentB, ids.roleSellingAgent, ids.beaconOrg, 'self'],
      [ids.agentEast, ids.roleSellingAgent, ids.eastTeamOrg, 'self'],
      [ids.agentHarbor, ids.roleSellingAgent, ids.harborOrg, 'self'],
      [ids.suspendedAgent, ids.roleSellingAgent, ids.beaconOrg, 'self'],
    ]) {
      await client.query(
        `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,$4,true,$5,'[2020-01-01,)'::daterange,'active',$6)`,
        [randomUUID(), personId, roleId, orgId, mode, seq],
      );
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }

  const tokenFor = (actorPersonId, viewAsPersonId = null, opts = {}) => mintSignedToken({
    keyId,
    secretBytes,
    environment: opts.environment ?? environment,
    actorPersonId,
    viewAsPersonId,
    expEpoch: opts.expEpoch,
  });

  const owner = tokenFor(ids.nusearOwner);
  const tampered = owner.slice(0, -1) + (owner.endsWith('0') ? '1' : '0');

  return {
    ids,
    keyId,
    secretBytes,
    environment,
    tokenFor,
    tokens: {
      owner,
      adminNoCoh: tokenFor(ids.nusearAdminNoCoh),
      operator: tokenFor(ids.nusearOperator),
      wrongCoOperator: tokenFor(ids.northstarOperator),
      worker: tokenFor(ids.workerService),
      entityMgr: tokenFor(ids.entityMgr),
      companyAdmin: tokenFor(ids.companyAdmin),
      companyAdminRunsOnly: tokenFor(ids.companyAdminRunsOnly),
      companyAdminNoGrants: tokenFor(ids.companyAdminNoGrants),
      investor: tokenFor(ids.investor),
      agencyMgr: tokenFor(ids.beaconManager),
      leadMgr: tokenFor(ids.leadManager),
      teamMgr: tokenFor(ids.teamManager),
      retentionAgent: tokenFor(ids.harborRetention),
      agentA: tokenFor(ids.agentA),
      agentB: tokenFor(ids.agentB),
      agentEast: tokenFor(ids.agentEast),
      agentHarbor: tokenFor(ids.agentHarbor),
      suspended: tokenFor(ids.suspendedAgent),
      viewAsAgentA: tokenFor(ids.nusearOwner, ids.agentA),
      viewAsAgencyMgr: tokenFor(ids.nusearOwner, ids.beaconManager),
      viewAsEntityMgr: tokenFor(ids.nusearOwner, ids.entityMgr),
      expired: tokenFor(ids.nusearOwner, null, { expEpoch: Math.floor(Date.now() / 1000) - 30 }),
      wrongEnv: tokenFor(ids.nusearOwner, null, { environment: 'prod' }),
      tampered,
    },
  };
}

export async function seedExtraIamSubjects(pool, {
  companyOrgId,
  environment = 'local',
  agencies = [],
  agents = [],
}) {
  const client = await pool.connect();
  const ids = {};
  try {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    const existingOrgs = new Set();
    const orgRes = await client.query(
      `SELECT pg_catalog.lower(pg_catalog.btrim(ov.slug)) AS s, pg_catalog.lower(pg_catalog.btrim(ov.display_name)) AS d
       FROM iam.organization_versions ov WHERE ov.superseded_by_id IS NULL`,
    );
    for (const r of orgRes.rows) {
      if (r.s) existingOrgs.add(r.s);
      if (r.d) existingOrgs.add(r.d);
    }
    const existingNpns = new Set(
      (await client.query('SELECT npn FROM iam.person_versions WHERE superseded_by_id IS NULL AND npn IS NOT NULL')).rows.map((r) => r.npn),
    );
    const missingAgencies = agencies.filter((a) => {
      const k = String(a.displayName || a.slug || '').trim().toLowerCase();
      return k && !existingOrgs.has(k);
    });
    const missingAgents = agents.filter((a) => a.npn && !existingNpns.has(String(a.npn).trim()));
    if (missingAgencies.length > 0 || missingAgents.length > 0) {
      const j = await appendIamAuditEntry(client, {
        environment,
        commandKind: 'iam.seed_extra_subjects',
        commandKey: `extra-subjects-${randomUUID()}`,
        targetOrgId: companyOrgId,
      });
      const seq = j.seq;
      let idx = 0;
      for (const ag of missingAgencies) {
        idx += 1;
        const orgId = ag.id || randomUUID();
        const displayName = ag.displayName || ag.slug;
        let slug = (ag.slug || displayName).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || `ag_${idx}`;
        if (existingOrgs.has(slug)) slug = `${slug}_${idx}`;
        existingOrgs.add(slug);
        existingOrgs.add(displayName.toLowerCase());
        ids[ag.key || displayName] = orgId;
        await client.query('INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,$2,$3)', [orgId, ag.kind || 'agency', seq]);
        await client.query(
          "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,$3,$4,'active',$5)",
          [randomUUID(), orgId, slug, displayName, seq],
        );
        await client.query(
          "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)",
          [randomUUID(), orgId, ag.parentOrgId || companyOrgId, seq],
        );
      }
      for (const ag of missingAgents) {
        const pid = ag.id || randomUUID();
        const npn = String(ag.npn).trim();
        existingNpns.add(npn);
        ids[ag.key || npn] = pid;
        await client.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [pid, seq]);
        await client.query(
          "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, npn, status, journal_seq) VALUES ($1,$2,$3,$3,$4,$5,'active',$6)",
          [randomUUID(), pid, ag.name || `Agent ${npn}`, `extra.${npn.replace(/[^a-zA-Z0-9]/g, '_')}@acme.example`, npn, seq],
        );
        await client.query(
          "INSERT INTO iam.agent_affiliations (id, person_id, npn, agency_org_id, split_bps, agent_file_name, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,8000,$5,'[2020-01-01,)'::daterange,'active',$6)",
          [randomUUID(), pid, npn, ag.orgId || companyOrgId, ag.name || `Agent ${npn}`, seq],
        );
      }
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
  return ids;
}

export async function flipToolSwitch(pool, {
  organizationId,
  toolId = 'coherence',
  switchState,
  replacesId,
  environment = 'local',
}) {
  const newId = randomUUID();
  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    const j = await appendIamAuditEntry(client, {
      environment,
      commandKind: 'iam.flip_tool_switch',
      commandKey: `switch-${newId}`,
      targetOrgId: organizationId,
      body: { toolId, switchState },
    });
    await client.query(
      `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq)
       VALUES ($1,$2,$3,$4,'active',$5,$6)`,
      [newId, organizationId, toolId, switchState, replacesId, j.seq],
    );
    await client.query('COMMIT');
    return newId;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
