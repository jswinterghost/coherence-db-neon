// Test-only IAM seeding, signed token minting, and role-scoped pool harness for Release 1B+ proofs.
// Never imported by runtime code under src/.
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { CANONICAL_TOOLS, seedIamCatalog } from '../../src/iam/catalog.mjs';
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
  const staffKeyId = `k_stf_${randomBytes(4).toString('hex')}`;
  const staffSecretBytes = randomBytes(32);
  const serviceKeyId = `k_svc_${randomBytes(4).toString('hex')}`;
  const serviceSecretBytes = randomBytes(32);

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
    harborZeroDollarReader: randomUUID(),
    agentA: randomUUID(),
    agentB: randomUUID(),
    agentEast: randomUUID(),
    agentHarbor: randomUUID(),
    suspendedAgent: randomUUID(),

    roleCompanyAdminRunsOnly: randomUUID(),
    roleCompanyAdminNoGrants: randomUUID(),
    roleAgencyZeroDollarReader: randomUUID(),
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
      `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, key_scope, active_from, active_until)
       VALUES ($1, $2, $7, 'company_local', pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours'),
              ($3, $4, $7, 'nusear_staff', pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours'),
              ($5, $6, $7, 'service', pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours')`,
      [keyId, secretBytes, staffKeyId, staffSecretBytes, serviceKeyId, serviceSecretBytes, environment],
    );

    const { rolesBySlug } = await seedIamCatalog(client, { environment, journalSeq: seq });
    ids.roleNusearOwner = rolesBySlug.get('nusear_owner');
    ids.roleNusearAdmin = rolesBySlug.get('nusear_admin');
    ids.roleNusearSupport = rolesBySlug.get('nusear_support');
    ids.roleCoherenceOperator = rolesBySlug.get('nusear_support');
    ids.roleWorkerService = rolesBySlug.get('coherence_worker_svc');
    ids.roleOwner = rolesBySlug.get('owner');
    ids.roleEntityManager = rolesBySlug.get('entity_manager');
    ids.roleCompanyAdmin = rolesBySlug.get('company_admin');
    ids.roleInvestor = rolesBySlug.get('investor');
    ids.roleAgencyManager = rolesBySlug.get('agency_manager');
    ids.roleDirectorOfSales = rolesBySlug.get('director_of_sales');
    ids.roleDirectorOfOperations = rolesBySlug.get('director_of_operations');
    ids.roleAccounting = rolesBySlug.get('accounting');
    ids.roleCompliance = rolesBySlug.get('compliance');
    ids.roleSellingAgent = rolesBySlug.get('selling_agent');
    ids.roleRetentionAgent = rolesBySlug.get('retention_agent');

    // Test-only custom company roles for verifying partial workshop grants and agency-wide zero-dollar reads.
    const customRoleSpecs = [
      [ids.roleCompanyAdminRunsOnly, 'company_admin_runs_only', 'Company Admin Runs Only', ['act:coherence.runs.read', 'act:coherence.unpublished.read']],
      [ids.roleCompanyAdminNoGrants, 'company_admin_none', 'Company Admin No Grants', ['act:platform.audit_journal.read']],
      [ids.roleAgencyZeroDollarReader, 'agency_zero_dollar_reader', 'Agency Zero Dollar Reader', ['act:coherence.bob.read', 'col:coherence.member_phi', 'col:coherence.member_contact']],
    ];
    for (const [id, slug, display, rightList] of customRoleSpecs) {
      await client.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,$3,$4)', [id, slug, ids.companyOrg, seq]);
      await client.query(
        `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq)
         VALUES ($1,$2,$3,false,false,true,'active',$4)`,
        [randomUUID(), id, display, seq],
      );
      for (const rightId of rightList) {
        await client.query(
          "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), id, rightId, seq],
        );
      }
    }

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

    for (const tool of CANONICAL_TOOLS) {
      const switchId = tool.id === 'coherence' ? ids.switchAcmeCoherenceId : randomUUID();
      await client.query(
        `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq)
         VALUES ($1,$2,$3,'on','active',$4)`,
        [switchId, ids.companyOrg, tool.id, seq],
      );
      await client.query(
        `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq)
         VALUES ($1,$2,$3,'on','active',$4)`,
        [randomUUID(), ids.northstarOrg, tool.id, seq],
      );
    }

    const humanPeople = [
      [ids.nusearOwner, 'nusear_staff', 'Pat Platform', 'pat.owner@nusear.example', null, 'active'],
      [ids.nusearAdminNoCoh, 'nusear_staff', 'Morgan Admin', 'morgan.admin@nusear.example', null, 'active'],
      [ids.nusearOperator, 'nusear_staff', 'Casey Operator', 'casey.op@nusear.example', null, 'active'],
      [ids.northstarOperator, 'nusear_staff', 'Devon Northstar', 'devon.ns@nusear.example', null, 'active'],
      [ids.entityMgr, 'company_local', 'Dana Entity', 'dana.em@acme.example', null, 'active'],
      [ids.companyAdmin, 'company_local', 'Sloan Admin', 'sloan.admin@acme.example', null, 'active'],
      [ids.companyAdminRunsOnly, 'company_local', 'Skylar Runs', 'skylar.runs@acme.example', null, 'active'],
      [ids.companyAdminNoGrants, 'company_local', 'Quinn None', 'quinn.none@acme.example', null, 'active'],
      [ids.investor, 'company_local', 'Avery Investor', 'avery.inv@acme.example', null, 'active'],
      [ids.beaconManager, 'company_local', 'Taylor Beacon', 'taylor.bm@acme.example', null, 'active'],
      [ids.leadManager, 'company_local', 'Lee Lead', 'lee.lm@acme.example', null, 'active'],
      [ids.teamManager, 'company_local', 'Riley Team', 'riley.tm@acme.example', null, 'active'],
      [ids.harborRetention, 'company_local', 'Jordan Retain', 'jordan.ret@acme.example', '31313131', 'active'],
      [ids.harborZeroDollarReader, 'company_local', 'Morgan Harbor', 'morgan.hv@acme.example', null, 'active'],
      [ids.agentA, 'company_local', 'Sam Seller', 'sam.a@acme.example', '11111111', 'active'],
      [ids.agentB, 'company_local', 'Sam Seller', 'sam.b@acme.example', '22222222', 'active'],
      [ids.agentEast, 'company_local', 'Jamie East', 'jamie.east@acme.example', '44444444', 'active'],
      [ids.agentHarbor, 'company_local', 'Robin Harbor', 'robin.harbor@acme.example', '33333333', 'active'],
      [ids.suspendedAgent, 'company_local', 'Chris Suspended', 'chris.susp@acme.example', '55555555', 'suspended'],
    ];
    for (const [id, origin, name, email, npn, status] of humanPeople) {
      await client.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human',$2,$3)", [id, origin, seq]);
      await client.query(
        `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, npn, status, journal_seq)
         VALUES ($1,$2,$3,$4,$4,$5,$6,$7,$8)`,
        [randomUUID(), id, origin, name, email, npn, status, seq],
      );
    }
    await client.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'service','service',$2)", [ids.workerService, seq]);
    await client.query(
      `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, status, journal_seq)
       VALUES ($1,$2,'service','Coherence Worker','Coherence Worker','active',$3)`,
      [randomUUID(), ids.workerService, seq],
    );

    for (const [personId, orgId, arrangement] of [
      [ids.nusearOwner, ids.rootOrg, 'employee'],
      [ids.nusearAdminNoCoh, ids.rootOrg, 'employee'],
      [ids.nusearOperator, ids.rootOrg, 'employee'],
      [ids.northstarOperator, ids.rootOrg, 'employee'],
      [ids.workerService, ids.rootOrg, null],
      [ids.entityMgr, ids.companyOrg, 'employee'],
      [ids.companyAdmin, ids.companyOrg, 'employee'],
      [ids.companyAdminRunsOnly, ids.companyOrg, 'employee'],
      [ids.companyAdminNoGrants, ids.companyOrg, 'employee'],
      [ids.investor, ids.companyOrg, null],
      [ids.beaconManager, ids.beaconOrg, 'employee'],
      [ids.leadManager, ids.beaconOrg, 'employee'],
      [ids.teamManager, ids.beaconOrg, 'employee'],
      [ids.harborRetention, ids.harborOrg, 'employee'],
      [ids.harborZeroDollarReader, ids.harborOrg, 'employee'],
    ]) {
      await client.query(
        `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,$4,'[2020-01-01,)'::daterange,'active',$5)`,
        [randomUUID(), personId, orgId, arrangement, seq],
      );
    }

    const affiliations = [
      [ids.agentA, '11111111', ids.beaconOrg, 'Sam Seller 1'],
      [ids.agentB, '22222222', ids.beaconOrg, 'Sam Seller 2'],
      [ids.agentEast, '44444444', ids.eastTeamOrg, 'Jamie East'],
      [ids.agentHarbor, '33333333', ids.harborOrg, 'Robin Harbor'],
      [ids.harborRetention, '31313131', ids.harborOrg, 'Jordan Retain'],
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
      [ids.harborRetention, ids.roleRetentionAgent, ids.harborOrg, 'self'],
      [ids.harborZeroDollarReader, ids.roleAgencyZeroDollarReader, ids.harborOrg, 'org_subtree'],
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

  const originByPersonId = new Map([
    [ids.nusearOwner, 'nusear_staff'],
    [ids.nusearAdminNoCoh, 'nusear_staff'],
    [ids.nusearOperator, 'nusear_staff'],
    [ids.northstarOperator, 'nusear_staff'],
    [ids.workerService, 'service'],
  ]);
  const keysByScope = {
    company_local: { keyId, secretBytes },
    nusear_staff: { keyId: staffKeyId, secretBytes: staffSecretBytes },
    service: { keyId: serviceKeyId, secretBytes: serviceSecretBytes },
  };

  const tokenFor = (actorPersonId, viewAsPersonId = null, opts = {}) => {
    const scope = opts.keyScope ?? originByPersonId.get(actorPersonId) ?? 'company_local';
    const key = keysByScope[scope] || keysByScope.company_local;
    return mintSignedToken({
      keyId: opts.keyId ?? key.keyId,
      secretBytes: opts.secretBytes ?? key.secretBytes,
      environment: opts.environment ?? environment,
      actorPersonId,
      viewAsPersonId,
      expEpoch: opts.expEpoch,
    });
  };

  const owner = tokenFor(ids.nusearOwner);
  const tampered = owner.slice(0, -1) + (owner.endsWith('0') ? '1' : '0');

  return {
    ids,
    keyId,
    secretBytes,
    staffKeyId,
    staffSecretBytes,
    serviceKeyId,
    serviceSecretBytes,
    keysByScope,
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
      harborZeroDollarReader: tokenFor(ids.harborZeroDollarReader),
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
      (await client.query("SELECT npn FROM iam.person_versions WHERE superseded_by_id IS NULL AND principal_origin = 'company_local' AND npn IS NOT NULL")).rows.map((r) => r.npn),
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
