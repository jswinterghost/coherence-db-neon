// Layer 7: Release 1A database-only IAM core (migration 008).
import assert from 'node:assert/strict';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';
import { createClient } from '../src/db/pg-client.mjs';
import { canonicalJson, formatTimestampUtcUs, sha256Hex } from '../src/util/crypto.mjs';
import { checkPgAvailable, createEmptyMigratedTestDb, withClusterCatalogLock } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

function mintSignedToken({
  keyId,
  secretBytes,
  environment,
  sessionId = randomUUID(),
  actorPersonId,
  viewAsPersonId = null,
  expEpoch = Math.floor(Date.now() / 1000) + 60,
}) {
  const viewAsPart = viewAsPersonId ?? '-';
  const payload = `v1|${keyId}|${environment}|${sessionId}|${actorPersonId}|${viewAsPart}|${expEpoch}`;
  const sig = createHmac('sha256', secretBytes).update(payload, 'utf8').digest('hex');
  return `${payload}|${sig}`;
}

async function inSerializableTx(pool, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function appendAuditEntry(client, {
  environment = 'local',
  actorPersonId = null,
  recordedAs = 'service',
  targetOrgId = null,
  commandKind = 'iam.test_seed',
  commandKey = `cmd-${randomUUID()}`,
  body = {},
} = {}) {
  const reqHash = sha256Hex(JSON.stringify({ commandKind, commandKey, body }));
  const res = await client.query(
    `INSERT INTO platform.audit_journal (
       environment, actor_person_id, recorded_as, target_org_id,
       command_kind, command_key, request_sha256, body
     ) VALUES ($1, $2::uuid, $3, $4::uuid, $5, $6, $7, $8::jsonb)
     RETURNING seq, recorded_at, prev_hash, entry_hash`,
    [environment, actorPersonId, recordedAs, targetOrgId, commandKind, commandKey, reqHash, JSON.stringify(body)],
  );
  return res.rows[0];
}

async function runAsPlatformApp(pool, { token = null, readOnly = true } = {}, fn) {
  const client = await pool.connect();
  try {
    await client.query(readOnly ? 'BEGIN TRANSACTION READ ONLY' : 'BEGIN TRANSACTION READ WRITE');
    await client.query('SET LOCAL ROLE platform_app');
    if (token !== null) {
      await client.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [token]);
    }
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function seedStandardIamWorld(pool, { environment = 'local' } = {}) {
  const keyId = 'k_test_2026';
  const secretBytes = randomBytes(32);
  const staffKeyId = 'k_staff_2026';
  const staffSecretBytes = randomBytes(32);
  const serviceKeyId = 'k_service_2026';
  const serviceSecretBytes = randomBytes(32);

  const ids = {
    rootOrg: randomUUID(),
    acmeOrg: randomUUID(),
    beaconOrg: randomUUID(),
    harborOrg: randomUUID(),
    eastTeamOrg: randomUUID(),
    northstarOrg: randomUUID(),

    nusearOwner: randomUUID(),
    nusearSupport: randomUUID(),
    acmeOwner: randomUUID(),
    beaconManager: randomUUID(),
    leadManager: randomUUID(),
    teamManager: randomUUID(),
    agentA: randomUUID(),
    agentB: randomUUID(),
    agentC: randomUUID(),
    northstarAdmin: randomUUID(),

    roleNusearOwner: randomUUID(),
    roleNusearSupport: randomUUID(),
    roleSupportCeiling: randomUUID(),
    roleCustomerOwner: randomUUID(),
    roleAgencyManager: randomUUID(),
    roleTeamManager: randomUUID(),
    roleSellingAgent: randomUUID(),
    roleExplicitReader: randomUUID(),

    connOnyx: randomUUID(),
    connEnrollHere: randomUUID(),
  };

  await inSerializableTx(pool, async (c) => {
    const j1 = await appendAuditEntry(c, { environment, commandKind: 'iam.bootstrap', commandKey: 'bootstrap-world' });
    const seq = j1.seq;

    // Organizations
    for (const [id, kind] of [
      [ids.rootOrg, 'platform_root'],
      [ids.acmeOrg, 'company'],
      [ids.beaconOrg, 'agency'],
      [ids.harborOrg, 'agency'],
      [ids.eastTeamOrg, 'team'],
      [ids.northstarOrg, 'company'],
    ]) {
      await c.query('INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1, $2, $3)', [id, kind, seq]);
    }

    // Database context
    await c.query(
      `INSERT INTO iam.database_context (singleton, environment, db_role_kind, tenant_org_id, company_slug, support_external_label, journal_seq)
       VALUES (true, $1, 'company_working', $2, 'acme', 'Nusear support', $3)`,
      [environment, ids.acmeOrg, seq],
    );

    // Signing keys (one per scope)
    await c.query(
      `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, key_scope, active_from, active_until)
       VALUES ($1, $2, $7, 'company_local', pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours'),
              ($3, $4, $7, 'nusear_staff', pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours'),
              ($5, $6, $7, 'service', pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours')`,
      [keyId, secretBytes, staffKeyId, staffSecretBytes, serviceKeyId, serviceSecretBytes, environment],
    );

    // Tools
    for (const [id, display, nusearOnly, switchable] of [
      ['coherence', 'Coherence', false, true],
      ['concurrence', 'Concurrence', false, true],
      ['transmittals', 'Transmittals', false, true],
      ['vault', 'Vault', false, true],
      ['control_center', 'Control Center', true, false],
    ]) {
      await c.query(
        'INSERT INTO iam.tools (id, display_name, is_nusear_only, is_customer_switchable, journal_seq) VALUES ($1, $2, $3, $4, $5)',
        [id, display, nusearOnly, switchable, seq],
      );
    }

    // Rights
    const rights = [
      ['act:coherence.bob.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read Book of Business'],
      ['act:coherence.run.manage', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Manage Coherence runs'],
      ['col:coherence.statement_cash', 'column', 'coherence', 'both', 'money_statement', true, 'coherence', 'bob_policy_financials', 'amount', 'View statement cash'],
      ['act:concurrence.calls.read', 'action', 'concurrence', 'both', 'ordinary', true, null, null, null, 'Read dialer calls'],
      ['act:concurrence.calls.tag', 'action', 'concurrence', 'both', 'ordinary', true, null, null, null, 'Tag dialer calls'],
      ['act:transmittals.read', 'action', 'transmittals', 'both', 'ordinary', true, null, null, null, 'Read transmittals'],
      ['act:transmittals.approve', 'action', 'transmittals', 'both', 'ordinary', true, null, null, null, 'Approve transmittals'],
      ['act:vault.archive.retrieve', 'action', 'vault', 'both', 'ordinary', true, null, null, null, 'Retrieve archive files'],
      ['act:control_center.read', 'action', 'control_center', 'both', 'ordinary', true, null, null, null, 'Read Control Center'],
      ['act:coherence.dev_debug', 'action', 'coherence', 'dev_only', 'ordinary', true, null, null, null, 'Dev-only diagnostics'],
      ['act:coherence.prod_send', 'action', 'coherence', 'prod_only', 'ordinary', true, null, null, null, 'Prod-only send'],
    ];
    for (const r of rights) {
      await c.query(
        `INSERT INTO iam.rights (
           id, right_kind, tool_id, environment_scope, sensitivity_class, is_delegable_power,
           target_schema, target_table, target_column, description, journal_seq
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [...r, seq],
      );
    }

    // Roles + versions
    const roleSpecs = [
      [ids.roleNusearOwner, 'nusear_owner', null, 'Nusear Owner', true, true, true],
      [ids.roleNusearSupport, 'nusear_support', null, 'Nusear Support', false, true, true],
      [ids.roleSupportCeiling, 'nusear_support_contractor', ids.acmeOrg, 'Support Contractor Ceiling', true, false, true],
      [ids.roleCustomerOwner, 'customer_owner', null, 'Customer Owner', true, false, true],
      [ids.roleAgencyManager, 'agency_manager', null, 'Agency Manager', false, false, true],
      [ids.roleTeamManager, 'team_manager', null, 'Team Manager', false, false, false],
      [ids.roleSellingAgent, 'selling_agent', null, 'Selling Agent', false, false, false],
      [ids.roleExplicitReader, 'explicit_reader', null, 'Explicit Reader', false, false, false],
    ];
    for (const [id, slug, ownerOrg, display, pinned, internal, wide] of roleSpecs) {
      await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,$3,$4)', [id, slug, ownerOrg, seq]);
      await c.query(
        `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq)
         VALUES ($1,$2,$3,$4,$5,$6,'active',$7)`,
        [randomUUID(), id, display, pinned, internal, wide, seq],
      );
    }

    const addRoleRights = async (roleId, rightIds) => {
      for (const rightId of rightIds) {
        await c.query(
          "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), roleId, rightId, seq],
        );
      }
    };

    const allRights = rights.map((r) => r[0]);
    await addRoleRights(ids.roleNusearOwner, allRights);
    await addRoleRights(ids.roleNusearSupport, [
      'act:coherence.bob.read', 'act:coherence.run.manage', 'col:coherence.statement_cash',
      'act:concurrence.calls.read', 'act:concurrence.calls.tag',
      'act:transmittals.read', 'act:transmittals.approve', 'act:vault.archive.retrieve',
      'act:control_center.read', 'act:coherence.dev_debug', 'act:coherence.prod_send',
    ]);
    await addRoleRights(ids.roleSupportCeiling, [
      'act:coherence.bob.read', 'act:concurrence.calls.read', 'act:concurrence.calls.tag',
      'act:transmittals.read', 'act:transmittals.approve',
    ]);
    await addRoleRights(ids.roleCustomerOwner, [
      'act:coherence.bob.read', 'col:coherence.statement_cash',
      'act:concurrence.calls.read', 'act:concurrence.calls.tag',
      'act:transmittals.read', 'act:transmittals.approve', 'act:vault.archive.retrieve',
      'act:control_center.read', 'act:coherence.dev_debug', 'act:coherence.prod_send',
    ]);
    await addRoleRights(ids.roleAgencyManager, [
      'act:coherence.bob.read', 'col:coherence.statement_cash',
      'act:concurrence.calls.read', 'act:concurrence.calls.tag',
      'act:transmittals.read', 'act:transmittals.approve',
    ]);
    await addRoleRights(ids.roleTeamManager, [
      'act:coherence.bob.read', 'act:concurrence.calls.read',
      'act:transmittals.read', 'act:transmittals.approve',
    ]);
    await addRoleRights(ids.roleSellingAgent, [
      'act:coherence.bob.read', 'act:concurrence.calls.read', 'act:transmittals.read', 'act:transmittals.approve',
    ]);
    await addRoleRights(ids.roleExplicitReader, [
      'act:coherence.bob.read', 'act:concurrence.calls.read', 'act:transmittals.read', 'act:transmittals.approve',
    ]);

    // Organization versions
    for (const [orgId, slug, name] of [
      [ids.rootOrg, 'nusear', 'Nusear'],
      [ids.acmeOrg, 'acme', 'Acme Holdings'],
      [ids.beaconOrg, 'beacon', 'Beacon Agency'],
      [ids.harborOrg, 'harbor', 'Harbor Agency'],
      [ids.eastTeamOrg, 'east_team', 'East Team'],
      [ids.northstarOrg, 'northstar', 'Northstar Group'],
    ]) {
      await c.query(
        `INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq)
         VALUES ($1,$2,$3,$4,'active',$5)`,
        [randomUUID(), orgId, slug, name, seq],
      );
    }

    // Organization edges: root -> acme -> beacon -> east_team; root -> acme -> harbor; root -> northstar
    for (const [child, parent] of [
      [ids.acmeOrg, ids.rootOrg],
      [ids.beaconOrg, ids.acmeOrg],
      [ids.harborOrg, ids.acmeOrg],
      [ids.eastTeamOrg, ids.beaconOrg],
      [ids.northstarOrg, ids.rootOrg],
    ]) {
      await c.query(
        `INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)`,
        [randomUUID(), child, parent, seq],
      );
    }

    // Tool switches on for Acme and Northstar
    for (const orgId of [ids.acmeOrg, ids.northstarOrg]) {
      for (const toolId of ['coherence', 'concurrence', 'transmittals', 'vault']) {
        await c.query(
          `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq)
           VALUES ($1,$2,$3,'on','active',$4)`,
          [randomUUID(), orgId, toolId, seq],
        );
      }
    }

    // People + versions
    const peopleSpecs = [
      [ids.nusearOwner, 'nusear_staff', 'Pat Platform', 'pat.platform@nusear.example', null],
      [ids.nusearSupport, 'nusear_staff', 'Jordan Support', 'jordan.support@nusear.example', null],
      [ids.acmeOwner, 'company_local', 'Dana Owner', 'dana.owner@acme.example', null],
      [ids.beaconManager, 'company_local', 'Taylor Beacon', 'taylor.beacon@beacon.example', null],
      [ids.leadManager, 'company_local', 'Casey Lead', 'casey.lead@beacon.example', null],
      [ids.teamManager, 'company_local', 'Riley Team', 'riley.team@beacon.example', null],
      [ids.agentA, 'company_local', 'Sam Seller', 'sam.a@beacon.example', '11111111'],
      [ids.agentB, 'company_local', 'Sam Seller', 'sam.b@beacon.example', '22222222'],
      [ids.agentC, 'company_local', 'Morgan Agent', 'morgan.c@beacon.example', '33333333'],
      [ids.northstarAdmin, 'company_local', 'Quinn Northstar', 'quinn@northstar.example', null],
    ];
    for (const [id, origin, name, email, npn] of peopleSpecs) {
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human',$2,$3)", [id, origin, seq]);
      await c.query(
        `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, npn, status, journal_seq)
         VALUES ($1,$2,$3,$4,$4,$5,$6,'active',$7)`,
        [randomUUID(), id, origin, name, email, npn, seq],
      );
    }

    // Seed one active per-company sign-in identity so immutability tests cover person_auth_identities non-vacuously
    await c.query(
      `INSERT INTO iam.person_auth_identities (id, person_id, principal_origin, auth_issuer, auth_subject, status, journal_seq)
       VALUES ($1,$2,'company_local','https://clerk.acme.example','user_acme_owner','active',$3)`,
      [randomUUID(), ids.acmeOwner, seq],
    );

    // Governing memberships (selling agents derive membership SOLELY from iam.agent_affiliations!)
    for (const [personId, orgId, arrangement] of [
      [ids.nusearOwner, ids.rootOrg, 'employee'],
      [ids.nusearSupport, ids.rootOrg, 'employee'],
      [ids.acmeOwner, ids.acmeOrg, 'employee'],
      [ids.beaconManager, ids.beaconOrg, 'employee'],
      [ids.leadManager, ids.beaconOrg, 'employee'],
      [ids.teamManager, ids.beaconOrg, 'employee'],
      [ids.northstarAdmin, ids.northstarOrg, 'employee'],
    ]) {
      await c.query(
        `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,$4,'[2020-01-01,)'::daterange,'active',$5)`,
        [randomUUID(), personId, orgId, arrangement, seq],
      );
    }

    for (const [personId, npn, fileName] of [
      [ids.agentA, '11111111', 'Sam Seller A'],
      [ids.agentB, '22222222', 'Sam Seller B'],
      [ids.agentC, '33333333', 'Morgan Agent'],
    ]) {
      await c.query(
        `INSERT INTO iam.agent_affiliations (id, person_id, npn, agency_org_id, split_bps, agent_file_name, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,$4,8000,$5,'[2020-01-01,)'::daterange,'active',$6)`,
        [randomUUID(), personId, npn, ids.beaconOrg, fileName, seq],
      );
    }

    // Role grants
    const grantSpecs = [
      [ids.nusearOwner, ids.roleNusearOwner, ids.rootOrg, true, 'org_subtree'],
      [ids.nusearSupport, ids.roleNusearSupport, ids.rootOrg, true, 'org_subtree'],
      [ids.acmeOwner, ids.roleCustomerOwner, ids.acmeOrg, true, 'org_subtree'],
      [ids.beaconManager, ids.roleAgencyManager, ids.beaconOrg, true, 'org_subtree'],
      [ids.agentA, ids.roleSellingAgent, ids.beaconOrg, false, 'self'],
      [ids.agentB, ids.roleSellingAgent, ids.beaconOrg, false, 'self'],
      [ids.northstarAdmin, ids.roleCustomerOwner, ids.northstarOrg, true, 'org_subtree'],
    ];
    for (const [personId, roleId, orgId, incDesc, pMode] of grantSpecs) {
      await c.query(
        `INSERT INTO iam.role_grants (
           id, person_id, role_id, organization_id, include_descendants,
           person_scope_mode, valid_range, status, journal_seq
         ) VALUES ($1,$2,$3,$4,$5,$6,'[2020-01-01,)'::daterange,'active',$7)`,
        [randomUUID(), personId, roleId, orgId, incDesc, pMode, seq],
      );
    }
  });

  return { ids, keyId, secretBytes, staffKeyId, staffSecretBytes, serviceKeyId, serviceSecretBytes, environment };
}

test('Layer 7 [Base-Table Lockdown & Catalog Audit]: platform_app gets SQLSTATE 42501 on every iam, iam_secret, and platform base table and internal helper; IAM catalog audit passes', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const db = await createEmptyMigratedTestDb();
  t.after(() => db.cleanup());

  const tblRes = await db.pool.query(
    `SELECT table_schema, table_name
     FROM information_schema.tables
     WHERE table_schema IN ('iam', 'iam_secret', 'platform')
       AND table_type = 'BASE TABLE'
     ORDER BY table_schema, table_name`,
  );
  const iamTables = tblRes.rows.filter((r) => r.table_schema === 'iam');
  const secretTables = tblRes.rows.filter((r) => r.table_schema === 'iam_secret');
  const platformTables = tblRes.rows.filter((r) => r.table_schema === 'platform');
  assert.equal(iamTables.length, 18, `expected 18 iam base tables, found ${iamTables.length}`);
  assert.ok(secretTables.some((r) => r.table_name === 'signing_keys'), 'expected iam_secret.signing_keys');
  assert.ok(platformTables.some((r) => r.table_name === 'audit_journal'), 'expected platform.audit_journal');

  // Every base table across iam, iam_secret, and platform MUST return SQLSTATE 42501 for platform_app.
  for (const row of tblRes.rows) {
    const fq = `"${row.table_schema}"."${row.table_name}"`;
    const colRes = await db.pool.query(
      `SELECT column_name FROM information_schema.columns
       WHERE table_schema = $1 AND table_name = $2 AND is_generated = 'NEVER'
       ORDER BY ordinal_position LIMIT 1`,
      [row.table_schema, row.table_name],
    );
    const firstCol = colRes.rows[0].column_name;
    for (const [label, sql, readOnly] of [
      ['SELECT', `SELECT * FROM ${fq} LIMIT 1`, true],
      ['INSERT', `INSERT INTO ${fq} DEFAULT VALUES`, false],
      ['UPDATE', `UPDATE ${fq} SET "${firstCol}" = "${firstCol}" WHERE false`, false],
      ['DELETE', `DELETE FROM ${fq} WHERE false`, false],
      ['TRUNCATE', `TRUNCATE TABLE ${fq}`, false],
      ['LOCK', `LOCK TABLE ${fq} IN EXCLUSIVE MODE`, false],
    ]) {
      await assert.rejects(
        () => runAsPlatformApp(db.pool, { readOnly }, (c) => c.query(sql)),
        (err) => err?.code === '42501',
        `platform_app must get SQLSTATE 42501 on ${label} ${fq}`,
      );
    }
  }

  // Internal views and internal per-person/secret functions MUST also return 42501 for platform_app.
  for (const sql of [
    'SELECT * FROM iam.v_all_memberships_live LIMIT 1',
    'SELECT * FROM iam.v_organization_closure LIMIT 1',
    'SELECT * FROM iam.v_organization_closure_live LIMIT 1',
    "SELECT iam_secret.hmac_sha256_hex('\\x01'::bytea, 'msg')",
    `SELECT * FROM iam.person_effective_grants('${randomUUID()}'::uuid, 'act:coherence.bob.read')`,
  ]) {
    await assert.rejects(
      () => runAsPlatformApp(db.pool, { readOnly: true }, (c) => c.query(sql)),
      (err) => err?.code === '42501',
      `platform_app must get SQLSTATE 42501 on internal object: ${sql}`,
    );
  }

  const policyChecks = await import('../src/config/policy-checks.mjs');
  assert.equal(typeof policyChecks.verifyIamConfigInvariants, 'function', 'verifyIamConfigInvariants must be exported');
  const audit = await withClusterCatalogLock(() => policyChecks.verifyIamConfigInvariants(db.pool));
  assert.equal(audit.passed, true, `IAM catalog audit failed:\n${audit.problems.join('\n')}`);

  // Negative catalog audit probes (Item 14): prove verifyIamConfigInvariants fails non-vacuously on
  // (a) extra EXECUTE granted to platform_app outside whitelist, (b) unexpected pg_auth_members membership,
  // and (c) an iam base table missing from the immutability lists.
  await t.test('Catalog audit fails when platform_app gets EXECUTE outside its whitelist', async () => {
    await db.pool.query('GRANT EXECUTE ON FUNCTION iam.person_effective_grants(UUID, TEXT, DATE) TO platform_app');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(db.pool);
      assert.equal(bad.passed, false, 'expected catalog audit to fail when platform_app holds EXECUTE on non-whitelisted function');
      assert.ok(bad.problems.some((p) => /person_effective_grants/i.test(p)), `expected problem citing person_effective_grants, got: ${bad.problems.join('; ')}`);
    } finally {
      await db.pool.query('REVOKE EXECUTE ON FUNCTION iam.person_effective_grants(UUID, TEXT, DATE) FROM platform_app');
    }
  });

  await t.test('Catalog audit fails on unexpected pg_auth_members grant involving platform roles', async () => {
    await withClusterCatalogLock(async () => {
      await db.pool.query('GRANT platform_readonly TO platform_app');
      try {
        const bad = await policyChecks.verifyIamConfigInvariants(db.pool);
        assert.equal(bad.passed, false, 'expected catalog audit to fail when platform_app is granted membership in platform_readonly');
        assert.ok(bad.problems.some((p) => /pg_auth_members|platform_readonly|platform_app/i.test(p)), `expected pg_auth_members problem, got: ${bad.problems.join('; ')}`);
      } finally {
        await db.pool.query('REVOKE platform_readonly FROM platform_app');
      }
    });
  });

  await t.test('Catalog audit fails when an iam base table is not covered by immutability lists', async () => {
    await db.pool.query('CREATE TABLE iam._audit_uncovered_probe (id INT PRIMARY KEY)');
    await db.pool.query('REVOKE ALL ON TABLE iam._audit_uncovered_probe FROM PUBLIC');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(db.pool);
      assert.equal(bad.passed, false, 'expected catalog audit to fail on uncovered iam base table');
      assert.ok(bad.problems.some((p) => /_audit_uncovered_probe/i.test(p)), `expected problem citing _audit_uncovered_probe, got: ${bad.problems.join('; ')}`);
    } finally {
      await db.pool.query('DROP TABLE IF EXISTS iam._audit_uncovered_probe');
    }
  });

  await t.test('Round 2 Item 2: catalog audit fails when a non-superuser holds a platform role WITH ADMIN OPTION (INHERIT and SET false)', async () => {
    await withClusterCatalogLock(async () => {
      const probeRole = `iam_audit_admin_probe_${randomUUID().replace(/-/g, '').slice(0, 8)}`;
      await db.pool.query(`CREATE ROLE ${probeRole} NOLOGIN NOSUPERUSER NOINHERIT NOBYPASSRLS`);
      try {
        await db.pool.query(`GRANT platform_readonly TO ${probeRole} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE`);
        const bad = await policyChecks.verifyIamConfigInvariants(db.pool);
        assert.equal(bad.passed, false, 'expected catalog audit to fail when non-superuser holds platform role WITH ADMIN OPTION');
        assert.ok(
          bad.problems.some((p) => p.includes(probeRole) && /platform_readonly/i.test(p) && /admin/i.test(p)),
          `expected problem citing ${probeRole}, platform_readonly, and admin, got: ${bad.problems.join('; ')}`,
        );

        // Even with CREATEROLE, a non-Cloud-SQL non-superuser holding WITH ADMIN OPTION must still fail
        await db.pool.query(`ALTER ROLE ${probeRole} CREATEROLE`);
        const badCreaterole = await policyChecks.verifyIamConfigInvariants(db.pool);
        assert.equal(badCreaterole.passed, false, 'expected catalog audit to fail for non-Cloud-SQL CREATEROLE holder with ADMIN OPTION');
        assert.ok(
          badCreaterole.problems.some((p) => p.includes(probeRole) && /platform_readonly/i.test(p) && /admin=true/i.test(p)),
          `expected problem citing ${probeRole}, platform_readonly, and admin=true, got: ${badCreaterole.problems.join('; ')}`,
        );

        // Even ADMIN FALSE, INHERIT FALSE, SET FALSE for a non-bootstrap non-superuser must fail
        await db.pool.query(`GRANT platform_readonly TO ${probeRole} WITH ADMIN FALSE, INHERIT FALSE, SET FALSE`);
        const badEmpty = await policyChecks.verifyIamConfigInvariants(db.pool);
        assert.equal(badEmpty.passed, false, 'expected catalog audit to fail for stray non-superuser pg_auth_members row on platform role');
        assert.ok(
          badEmpty.problems.some((p) => p.includes(probeRole) && /platform_readonly/i.test(p)),
          `expected problem citing ${probeRole} and platform_readonly, got: ${badEmpty.problems.join('; ')}`,
        );
      } finally {
        await db.pool.query(`REVOKE platform_readonly FROM ${probeRole}`).catch(() => {});
        await db.pool.query(`DROP ROLE IF EXISTS ${probeRole}`).catch(() => {});
      }
    });
  });

  await t.test('Round 2 Item 3: catalog audit discovers every view in iam, iam_secret, and platform and refuses any platform_app or PUBLIC privilege and any platform_app schema CREATE', async () => {
    await db.pool.query('CREATE VIEW iam._audit_iam_view_probe AS SELECT 1 AS ok');
    await db.pool.query('CREATE VIEW platform._audit_platform_view_probe AS SELECT 1 AS ok');
    await db.pool.query('CREATE VIEW iam_secret._audit_secret_view_probe AS SELECT 1 AS ok');
    await db.pool.query('REVOKE ALL ON iam._audit_iam_view_probe, platform._audit_platform_view_probe, iam_secret._audit_secret_view_probe FROM PUBLIC');
    try {
      // Newly created views with no grants pass audit
      const cleanWithViews = await policyChecks.verifyIamConfigInvariants(db.pool);
      assert.equal(cleanWithViews.passed, true, `clean views must pass audit: ${cleanWithViews.problems.join('; ')}`);

      // (a) SELECT on newly discovered iam view for platform_app fails
      await db.pool.query('GRANT SELECT ON iam._audit_iam_view_probe TO platform_app');
      try {
        const bad = await policyChecks.verifyIamConfigInvariants(db.pool);
        assert.equal(bad.passed, false, 'audit must fail when platform_app holds SELECT on any discovered iam view');
        assert.ok(bad.problems.some((p) => /_audit_iam_view_probe/i.test(p) && /platform_app/i.test(p)), `got: ${bad.problems.join('; ')}`);
      } finally {
        await db.pool.query('REVOKE ALL ON iam._audit_iam_view_probe FROM platform_app');
      }

      // (b) Non-SELECT privilege (INSERT) on existing internal iam view for platform_app fails
      await db.pool.query('GRANT INSERT ON iam.v_all_memberships_live TO platform_app');
      try {
        const bad = await policyChecks.verifyIamConfigInvariants(db.pool);
        assert.equal(bad.passed, false, 'audit must fail when platform_app holds INSERT on an iam view');
        assert.ok(bad.problems.some((p) => /v_all_memberships_live/i.test(p) && /INSERT/i.test(p)), `got: ${bad.problems.join('; ')}`);
      } finally {
        await db.pool.query('REVOKE INSERT ON iam.v_all_memberships_live FROM platform_app');
      }

      // (c) PUBLIC privilege on discovered platform view fails
      await db.pool.query('GRANT SELECT ON platform._audit_platform_view_probe TO PUBLIC');
      try {
        const bad = await policyChecks.verifyIamConfigInvariants(db.pool);
        assert.equal(bad.passed, false, 'audit must fail when PUBLIC holds SELECT on a platform view');
        assert.ok(bad.problems.some((p) => /_audit_platform_view_probe/i.test(p) && /public/i.test(p)), `got: ${bad.problems.join('; ')}`);
      } finally {
        await db.pool.query('REVOKE ALL ON platform._audit_platform_view_probe FROM PUBLIC');
      }

      // (d) platform_app privilege (including column-level SELECT) on discovered iam_secret view fails
      await db.pool.query('GRANT SELECT (ok) ON iam_secret._audit_secret_view_probe TO platform_app');
      try {
        const bad = await policyChecks.verifyIamConfigInvariants(db.pool);
        assert.equal(bad.passed, false, 'audit must fail when platform_app holds column-level SELECT on an iam_secret view');
        assert.ok(bad.problems.some((p) => /_audit_secret_view_probe/i.test(p) && /platform_app/i.test(p)), `got: ${bad.problems.join('; ')}`);
      } finally {
        await db.pool.query('REVOKE ALL ON iam_secret._audit_secret_view_probe FROM platform_app');
      }

      // (e) CREATE on iam, iam_secret, or platform schema for platform_app fails
      for (const schema of ['iam', 'iam_secret', 'platform']) {
        await db.pool.query(`GRANT CREATE ON SCHEMA ${schema} TO platform_app`);
        try {
          const bad = await policyChecks.verifyIamConfigInvariants(db.pool);
          assert.equal(bad.passed, false, `audit must fail when platform_app holds CREATE on schema ${schema}`);
          assert.ok(
            bad.problems.some((p) => p.includes('platform_app') && /CREATE/i.test(p) && p.includes(schema)),
            `expected CREATE problem on ${schema}, got: ${bad.problems.join('; ')}`,
          );
        } finally {
          await db.pool.query(`REVOKE CREATE ON SCHEMA ${schema} FROM platform_app`);
        }
      }
    } finally {
      await db.pool.query('DROP VIEW IF EXISTS iam._audit_iam_view_probe, platform._audit_platform_view_probe, iam_secret._audit_secret_view_probe');
    }
  });
});

test('Layer 7 [Immutability & Supersession]: UPDATE, DELETE, and TRUNCATE fail on every iam table (normal and replica mode), platform.audit_journal enforces chaining, and BEFORE INSERT platform_versioner supersession works across partial unique and GiST indexes', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const db = await createEmptyMigratedTestDb();
  t.after(() => db.cleanup());

  const { ids } = await seedStandardIamWorld(db.pool);

  let personVersionId;
  let orgVersionId;
  let switchId;
  let agentGrantId;

  await inSerializableTx(db.pool, async (c) => {
    personVersionId = (await c.query('SELECT id FROM iam.person_versions WHERE person_id = $1 AND superseded_by_id IS NULL', [ids.agentA])).rows[0].id;
    orgVersionId = (await c.query('SELECT id FROM iam.organization_versions WHERE organization_id = $1 AND superseded_by_id IS NULL', [ids.beaconOrg])).rows[0].id;
    switchId = (await c.query("SELECT id FROM iam.organization_tool_switches WHERE organization_id = $1 AND tool_id = 'coherence' AND superseded_by_id IS NULL", [ids.acmeOrg])).rows[0].id;
    agentGrantId = (await c.query('SELECT id FROM iam.role_grants WHERE person_id = $1 AND role_id = $2 AND superseded_by_id IS NULL', [ids.agentA, ids.roleSellingAgent])).rows[0].id;
  });

  // 1. platform.audit_journal guards: non-SERIALIZABLE, gapped seq, wrong prev_hash, backdated recorded_at, forged entry_hash, two-row INSERT (Item 14)
  await assert.rejects(
    () => db.pool.query(
      `INSERT INTO platform.audit_journal (environment, actor_person_id, recorded_as, command_kind, command_key, request_sha256, body)
       VALUES ('local', NULL, 'service', 'iam.bad', 'bad-non-ser', $1, '{}'::jsonb)`,
      [sha256Hex('bad')],
    ),
    (err) => err?.code === '25001',
    'audit_journal must refuse non-SERIALIZABLE writes',
  );
  const headJournal = (await db.pool.query('SELECT seq, entry_hash, recorded_at FROM platform.audit_journal ORDER BY seq DESC LIMIT 1')).rows[0];
  const nextSeq = Number(headJournal.seq) + 1;

  // 1a. Gapped seq alone (valid prev_hash, omitted recorded_at and entry_hash)
  await assert.rejects(
    () => inSerializableTx(db.pool, (c) => c.query(
      `INSERT INTO platform.audit_journal (seq, environment, actor_person_id, recorded_as, command_kind, command_key, request_sha256, body, prev_hash)
       VALUES ($1, 'local', NULL, 'service', 'iam.gap', 'bad-gap-only', $2, '{}'::jsonb, $3)`,
      [nextSeq + 1, sha256Hex('gap'), headJournal.entry_hash],
    )),
    (err) => err?.code === '22023' && /seq must be gapless/i.test(err.message),
    'audit_journal must refuse gapped seq on its own',
  );
  // 1b. Wrong prev_hash alone (valid seq, omitted recorded_at and entry_hash)
  await assert.rejects(
    () => inSerializableTx(db.pool, (c) => c.query(
      `INSERT INTO platform.audit_journal (seq, environment, actor_person_id, recorded_as, command_kind, command_key, request_sha256, body, prev_hash)
       VALUES ($1, 'local', NULL, 'service', 'iam.prev', 'bad-prev-only', $2, '{}'::jsonb, $3)`,
      [nextSeq, sha256Hex('prev'), 'f'.repeat(64)],
    )),
    (err) => err?.code === '22023' && /prev_hash mismatch/i.test(err.message),
    'audit_journal must refuse wrong prev_hash on its own',
  );
  // 1c. Backdated recorded_at alone (valid seq and prev_hash, omitted entry_hash)
  await assert.rejects(
    () => inSerializableTx(db.pool, (c) => c.query(
      `INSERT INTO platform.audit_journal (seq, recorded_at, environment, actor_person_id, recorded_as, command_kind, command_key, request_sha256, body, prev_hash)
       VALUES ($1, $2::timestamptz - INTERVAL '1 second', 'local', NULL, 'service', 'iam.backdate', 'bad-backdate-only', $3, '{}'::jsonb, $4)`,
      [nextSeq, headJournal.recorded_at, sha256Hex('backdate'), headJournal.entry_hash],
    )),
    (err) => err?.code === '22023' && /recorded_at.*cannot precede/i.test(err.message),
    'audit_journal must refuse backdated recorded_at on its own',
  );
  // 1d. Forged entry_hash alone (valid seq, prev_hash, and recorded_at)
  await assert.rejects(
    () => inSerializableTx(db.pool, (c) => c.query(
      `INSERT INTO platform.audit_journal (seq, recorded_at, environment, actor_person_id, recorded_as, command_kind, command_key, request_sha256, body, prev_hash, entry_hash)
       VALUES ($1, $2::timestamptz + INTERVAL '1 millisecond', 'local', NULL, 'service', 'iam.forge', 'bad-forge-only', $3, '{}'::jsonb, $4, $5)`,
      [nextSeq, headJournal.recorded_at, sha256Hex('forge'), headJournal.entry_hash, 'e'.repeat(64)],
    )),
    (err) => err?.code === '22023' && /entry_hash mismatch/i.test(err.message),
    'audit_journal must refuse forged entry_hash on its own',
  );
  await assert.rejects(
    () => inSerializableTx(db.pool, (c) => c.query(
      `INSERT INTO platform.audit_journal (environment, actor_person_id, recorded_as, command_kind, command_key, request_sha256, body)
       VALUES ('local', NULL, 'service', 'iam.two', 'two-1', $1, '{}'::jsonb),
              ('local', NULL, 'service', 'iam.two', 'two-2', $1, '{}'::jsonb)`,
      [sha256Hex('two')],
    )),
    (err) => err?.code === '22023',
    'audit_journal must refuse multi-row INSERT',
  );
  // Attaching an iam row to an already-committed journal_seq must be refused
  await assert.rejects(
    () => inSerializableTx(db.pool, (c) => c.query(
      "INSERT INTO iam.tools (id, display_name, journal_seq) VALUES ('stale_tool', 'Stale', 1)",
    )),
    (err) => err?.code === '22023',
    'iam tables must refuse attaching rows to already-committed journal_seq',
  );

  // Seed one live explicit_people grant + iam.role_grant_people row so FOR EACH ROW immutability
  // checks run non-vacuously on iam.role_grant_people in both normal and replica mode.
  await inSerializableTx(db.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment: 'local', commandKind: 'iam.seed_imm_rgp', commandKey: 'seed-imm-rgp-1' });
    const expGrantId = randomUUID();
    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$4,true,'explicit_people','[2020-01-01,)'::daterange,'active',$5)`,
      [expGrantId, ids.teamManager, ids.roleExplicitReader, ids.beaconOrg, j.seq],
    );
    await c.query(
      "INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
      [randomUUID(), expGrantId, ids.agentA, j.seq],
    );
  });

  // 2. UPDATE, DELETE, and TRUNCATE fail with SQLSTATE 55000 on EVERY iam table and platform.audit_journal (normal + replica mode)
  const iamTablesRes = await db.pool.query(
    `SELECT table_schema, table_name
     FROM information_schema.tables
     WHERE table_schema IN ('iam', 'platform') AND table_type = 'BASE TABLE'
     ORDER BY table_schema, table_name`,
  );
  assert.equal(iamTablesRes.rows.length, 19);

  for (const replicaMode of [false, true]) {
    for (const row of iamTablesRes.rows) {
      const fq = `"${row.table_schema}"."${row.table_name}"`;
      const firstColRes = await db.pool.query(
        `SELECT column_name FROM information_schema.columns
         WHERE table_schema = $1 AND table_name = $2 AND is_generated = 'NEVER'
         ORDER BY ordinal_position LIMIT 1`,
        [row.table_schema, row.table_name],
      );
      const col = firstColRes.rows[0].column_name;

      for (const [op, sql] of [
        ['UPDATE', `UPDATE ${fq} SET "${col}" = "${col}"`],
        ['DELETE', `DELETE FROM ${fq}`],
        ['TRUNCATE', `TRUNCATE TABLE ${fq} CASCADE`],
      ]) {
        await assert.rejects(async () => {
          const client = await createClient(db.pgConfig);
          try {
            await client.query('BEGIN');
            if (replicaMode) await client.query("SET LOCAL session_replication_role = 'replica'");
            await client.query(sql);
            await client.query('COMMIT');
          } finally {
            await client.query('ROLLBACK').catch(() => {});
            await client.end();
          }
        }, (err) => err?.code === '55000', `${op} on ${fq} (replica=${replicaMode}) must fail with SQLSTATE 55000`);
      }
    }
  }

  // Direct UPDATE of superseded_by_id by non-platform_versioner must fail with 55000
  await assert.rejects(
    () => db.pool.query(
      'UPDATE iam.person_versions SET superseded_by_id = id, superseded_journal_seq = 1 WHERE id = $1',
      [personVersionId],
    ),
    (err) => err?.code === '55000',
    'direct UPDATE of superseded_by_id outside platform_versioner must fail with 55000',
  );

  // 3. BEFORE INSERT supersession via platform_versioner works cleanly across partial unique and GiST indexes
  let newPersonVersionId;
  await inSerializableTx(db.pool, async (c) => {
    const j = await appendAuditEntry(c, { commandKind: 'iam.supersede_test', commandKey: 'supersede-1' });
    const seq = j.seq;

    // Supersede person_versions (partial unique index person_versions_one_live + unique_live_email + unique_live_npn)
    newPersonVersionId = randomUUID();
    await c.query(
      `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, npn, status, replaces_id, journal_seq)
       VALUES ($1,$2,'Sam Seller','Sam S. Updated','sam.a@beacon.example','11111111','active',$3,$4)`,
      [newPersonVersionId, ids.agentA, personVersionId, seq],
    );

    // Supersede organization_versions keeping same slug across partial unique index org_versions_live_slug_uniq
    await c.query(
      `INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, replaces_id, journal_seq)
       VALUES ($1,$2,'beacon','Beacon Agency Renamed','active',$3,$4)`,
      [randomUUID(), ids.beaconOrg, orgVersionId, seq],
    );

    // Supersede role_grants with overlapping valid_range across GiST exclusion constraint role_grants_no_overlap
    await c.query(
      `INSERT INTO iam.role_grants (
         id, person_id, role_id, organization_id, include_descendants,
         person_scope_mode, valid_range, status, replaces_id, journal_seq
       ) VALUES ($1,$2,$3,$4,false,'self','[2020-01-01,)'::daterange,'active',$5,$6)`,
      [randomUUID(), ids.agentA, ids.roleSellingAgent, ids.beaconOrg, agentGrantId, seq],
    );

    // Supersede tool switch on -> off
    await c.query(
      `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq)
       VALUES ($1,$2,'coherence','off','active',$3,$4)`,
      [randomUUID(), ids.acmeOrg, switchId, seq],
    );
  });

  const oldPv = (await db.pool.query('SELECT superseded_by_id, superseded_journal_seq FROM iam.person_versions WHERE id = $1', [personVersionId])).rows[0];
  assert.equal(oldPv.superseded_by_id, newPersonVersionId);
  assert.ok(Number(oldPv.superseded_journal_seq) >= 2);

  // Double-replacement of already-superseded row fails (23505)
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.double_replace', commandKey: 'double-rep-1' });
      await c.query(
        `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, status, replaces_id, journal_seq)
         VALUES ($1,$2,'Sam Seller','Double Replace','active',$3,$4)`,
        [randomUUID(), ids.agentA, personVersionId, j.seq],
      );
    }),
    (err) => err?.code === '23505',
    'double supersession of same row must fail with 23505',
  );

  // Pre-stamped superseded_by_id on INSERT fails (23514)
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.pre_superseded', commandKey: 'pre-sup-1' });
      const newId = randomUUID();
      await c.query(
        `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, status, superseded_by_id, superseded_journal_seq, journal_seq)
         VALUES ($1,$2,'Other','Other','active',$3,$4,$4)`,
        [newId, ids.agentB, newPersonVersionId, j.seq],
      );
    }),
    (err) => err?.code === '23514',
    'inserting a pre-superseded row must fail with 23514',
  );

  // Cross-entity supersession (Person B replacing Person A's live row) fails
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.cross_replace', commandKey: 'cross-rep-1' });
      await c.query(
        `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, status, replaces_id, journal_seq)
         VALUES ($1,$2,'Hijack','Hijack','active',$3,$4)`,
        [randomUUID(), ids.agentB, newPersonVersionId, j.seq],
      );
    }),
    (err) => err?.code === '23505',
    'cross-entity supersession must be refused',
  );

  // Item 3: INSERT ... ON CONFLICT (id) DO NOTHING must NEVER stamp superseded_by_id without inserting a replacement
  const otherLivePvId = (await db.pool.query(
    'SELECT id FROM iam.person_versions WHERE person_id = $1 AND superseded_by_id IS NULL',
    [ids.agentB],
  )).rows[0].id;
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.on_conflict_id', commandKey: 'on-conflict-id-1' });
      await c.query(
        `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, npn, status, replaces_id, journal_seq)
         VALUES ($1,$2,'Sam Seller','Orphan Attempt','sam.a@beacon.example','11111111','active',$3,$4)
         ON CONFLICT (id) DO NOTHING`,
        [otherLivePvId, ids.agentA, newPersonVersionId, j.seq],
      );
    }),
    (err) => err?.code === '23505',
    'ON CONFLICT (id) DO NOTHING with an existing id must be refused before stamping superseded_by_id',
  );
  const stillLiveAfterIdConflict = (await db.pool.query(
    'SELECT superseded_by_id FROM iam.person_versions WHERE id = $1',
    [newPersonVersionId],
  )).rows[0];
  assert.equal(stillLiveAfterIdConflict.superseded_by_id, null, 'live row must remain unsuperseded after refused ON CONFLICT (id) DO NOTHING');

  // Item 3 (composite deferred FK defense): ON CONFLICT on a partial unique index DO NOTHING must also fail at COMMIT (23503)
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.on_conflict_email', commandKey: 'on-conflict-email-1' });
      await c.query(
        `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, npn, status, replaces_id, journal_seq)
         VALUES ($1,$2,'Sam Seller','Email Conflict','sam.b@beacon.example','11111111','active',$3,$4)
         ON CONFLICT (principal_origin, primary_email) WHERE superseded_by_id IS NULL AND primary_email IS NOT NULL DO NOTHING`,
        [randomUUID(), ids.agentA, newPersonVersionId, j.seq],
      );
    }),
    (err) => err?.code === '23503',
    'ON CONFLICT on partial unique index DO NOTHING must fail deferred composite FK at COMMIT (23503)',
  );
  const stillLiveAfterEmailConflict = (await db.pool.query(
    'SELECT superseded_by_id FROM iam.person_versions WHERE id = $1',
    [newPersonVersionId],
  )).rows[0];
  assert.equal(stillLiveAfterEmailConflict.superseded_by_id, null, 'live row must remain unsuperseded after rolled-back ON CONFLICT (primary_email) DO NOTHING');
});

test('Layer 7 [Signed Tokens Fail-Closed]: unset, blank, malformed, 1-bit tampered, expired, unknown/expired key, wrong-environment, and suspended-person tokens yield 0 rows and 42501 on writes', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const db = await createEmptyMigratedTestDb();
  t.after(() => db.cleanup());

  const { ids, keyId, secretBytes, staffKeyId, staffSecretBytes } = await seedStandardIamWorld(db.pool, { environment: 'prod' });

  // Verify pure-SQL HMAC-SHA256 matches Node crypto (including >64-byte key)
  for (const [k, msg] of [
    [Buffer.from('0b'.repeat(20), 'hex'), 'Hi There'],
    [Buffer.from('Jefe', 'utf8'), 'what do ya want for nothing?'],
    [Buffer.from('aa'.repeat(131), 'hex'), 'Test Using Larger Than Block-Size Key - Hash Key First'],
  ]) {
    const sqlHmac = (await db.pool.query('SELECT iam_secret.hmac_sha256_hex($1::bytea, $2::text) AS h', [k, msg])).rows[0].h;
    const nodeHmac = createHmac('sha256', k).update(msg, 'utf8').digest('hex');
    assert.equal(sqlHmac, nodeHmac);
  }

  // Add an expired key and a dev-environment key
  const expiredKeyId = 'k_expired_2025';
  const expiredSecret = randomBytes(32);
  const devKeyId = 'k_dev_2026';
  const devSecret = randomBytes(32);
  await db.pool.query(
    `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, active_from, active_until)
     VALUES ($1, $2, 'prod', pg_catalog.now() - INTERVAL '2 hours', pg_catalog.now() - INTERVAL '1 hour'),
            ($3, $4, 'dev', pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours')`,
    [expiredKeyId, expiredSecret, devKeyId, devSecret],
  );

  // Valid token works first
  const validToken = mintSignedToken({ keyId, secretBytes, environment: 'prod', actorPersonId: ids.acmeOwner });
  await runAsPlatformApp(db.pool, { token: validToken, readOnly: false }, async (c) => {
    const ctx = (await c.query('SELECT * FROM iam.session_context()')).rows[0];
    assert.equal(ctx.actor_person_id, ids.acmeOwner);
    assert.equal(ctx.view_as_person_id, null);
    assert.equal(ctx.environment, 'prod');
    const wide = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS orgs")).rows[0].orgs;
    assert.ok(wide.includes(ids.acmeOrg));
    const wr = (await c.query(
      "SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, $2::uuid)",
      [ids.beaconOrg, ids.agentA],
    )).rows[0];
    assert.equal(wr.actor_person_id, ids.acmeOwner);
    assert.equal(wr.recorded_as, 'self');
  });

  // Tamper 1 hex char in HMAC
  const lastHex = validToken.slice(-1);
  const flippedHex = lastHex === '0' ? '1' : '0';
  const tamperedToken = `${validToken.slice(0, -1)}${flippedHex}`;

  const badTokens = [
    ['unset', null],
    ['blank', '   '],
    ['malformed_segments', 'v1|only|three'],
    ['wrong_version', validToken.replace(/^v1\|/, 'v2|')],
    ['bad_uuid', `v1|${keyId}|prod|not-a-uuid|${ids.acmeOwner}|-|${Math.floor(Date.now() / 1000) + 60}|${'a'.repeat(64)}`],
    ['tampered_1_char', tamperedToken],
    ['expired_token', mintSignedToken({ keyId, secretBytes, environment: 'prod', actorPersonId: ids.acmeOwner, expEpoch: Math.floor(Date.now() / 1000) - 5 })],
    ['unknown_key', mintSignedToken({ keyId: 'k_unknown', secretBytes, environment: 'prod', actorPersonId: ids.acmeOwner })],
    ['expired_key', mintSignedToken({ keyId: expiredKeyId, secretBytes: expiredSecret, environment: 'prod', actorPersonId: ids.acmeOwner })],
    ['wrong_env_dev_key', mintSignedToken({ keyId: devKeyId, secretBytes: devSecret, environment: 'dev', actorPersonId: ids.acmeOwner })],
    ['wrong_env_prod_key', mintSignedToken({ keyId, secretBytes, environment: 'dev', actorPersonId: ids.acmeOwner })],
  ];

  for (const [label, tok] of badTokens) {
    await runAsPlatformApp(db.pool, { token: tok, readOnly: true }, async (c) => {
      const ctx = (await c.query('SELECT * FROM iam.session_context()')).rows[0];
      assert.equal(ctx.actor_person_id, null, `${label}: session_context.actor_person_id must be NULL`);
      assert.equal((await c.query("SELECT iam.has_right('act:coherence.bob.read') AS ok")).rows[0].ok, false, `${label}: has_right must be false`);
      assert.deepEqual((await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `${label}: wide orgs must be empty`);
      assert.deepEqual((await c.query("SELECT iam.effective_any_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `${label}: any orgs must be empty`);
      assert.deepEqual((await c.query("SELECT * FROM iam.effective_narrow_pairs('act:coherence.bob.read')")).rows, [], `${label}: narrow pairs must be empty`);
      assert.deepEqual((await c.query("SELECT iam.effective_narrow_person_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `${label}: narrow person ids must be empty`);
    });
    await assert.rejects(
      () => runAsPlatformApp(db.pool, { token: tok, readOnly: false }, (c) => c.query(
        "SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, $2::uuid)",
        [ids.beaconOrg, ids.agentA],
      )),
      (err) => err?.code === '42501',
      `${label}: assert_can_write must fail with 42501`,
    );
  }

  // Suspend acmeOwner via supersession -> previously valid token fails closed immediately
  await inSerializableTx(db.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment: 'prod', commandKind: 'iam.suspend_person', commandKey: 'suspend-owner' });
    const prevId = (await c.query('SELECT id FROM iam.person_versions WHERE person_id = $1 AND superseded_by_id IS NULL', [ids.acmeOwner])).rows[0].id;
    await c.query(
      `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, replaces_id, journal_seq)
       VALUES ($1,$2,'Dana Owner','Dana Owner','dana.owner@acme.example','suspended',$3,$4)`,
      [randomUUID(), ids.acmeOwner, prevId, j.seq],
    );
  });

  await runAsPlatformApp(db.pool, { token: validToken, readOnly: true }, async (c) => {
    const ctx = (await c.query('SELECT * FROM iam.session_context()')).rows[0];
    assert.equal(ctx.actor_person_id, null, 'suspended actor must fail closed');
    assert.deepEqual((await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, []);
  });
  await assert.rejects(
    () => runAsPlatformApp(db.pool, { token: validToken, readOnly: false }, (c) => c.query(
      "SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, $2::uuid)",
      [ids.beaconOrg, ids.agentA],
    )),
    (err) => err?.code === '42501',
  );

  // Viewing as a suspended target must also fail closed
  const viewAsSuspendedToken = mintSignedToken({
    keyId: staffKeyId, secretBytes: staffSecretBytes, environment: 'prod', actorPersonId: ids.nusearOwner, viewAsPersonId: ids.acmeOwner,
  });
  await runAsPlatformApp(db.pool, { token: viewAsSuspendedToken, readOnly: true }, async (c) => {
    assert.equal((await c.query('SELECT * FROM iam.session_context()')).rows[0].actor_person_id, null);
  });
});

test('Layer 7 [View-As Enforcement]: View-as refuses every write with 42501 VIEW_AS_READ_ONLY even in a READ WRITE transaction and intersects wide/narrow scopes cleanly', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const db = await createEmptyMigratedTestDb();
  t.after(() => db.cleanup());

  const { ids, keyId, secretBytes, staffKeyId, staffSecretBytes, environment } = await seedStandardIamWorld(db.pool);

  // 1. Nusear Owner (wide org_subtree) viewing as Selling Agent A (narrow self) inside a deliberate READ WRITE tx
  const ownerAsAgent = mintSignedToken({
    keyId: staffKeyId, secretBytes: staffSecretBytes, environment, actorPersonId: ids.nusearOwner, viewAsPersonId: ids.agentA,
  });

  await runAsPlatformApp(db.pool, { token: ownerAsAgent, readOnly: false }, async (c) => {
    assert.equal((await c.query('SELECT iam.is_viewing_as() AS va')).rows[0].va, true);
    assert.deepEqual((await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, []);
    assert.deepEqual((await c.query("SELECT iam.effective_any_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [ids.beaconOrg]);
    const narrowPairs = (await c.query("SELECT org_id, person_id FROM iam.effective_narrow_pairs('act:coherence.bob.read')")).rows;
    assert.deepEqual(narrowPairs, [{ org_id: ids.beaconOrg, person_id: ids.agentA }]);
    assert.deepEqual((await c.query("SELECT iam.effective_narrow_person_ids('act:coherence.bob.read') AS v")).rows[0].v, [ids.agentA]);
    // Cash column right denied because agent lacks it even though Nusear Owner holds it
    assert.equal((await c.query("SELECT iam.has_right('col:coherence.statement_cash') AS ok")).rows[0].ok, false);
    assert.equal((await c.query("SELECT iam.has_right('act:coherence.bob.read') AS ok")).rows[0].ok, true);
  });

  await assert.rejects(
    () => runAsPlatformApp(db.pool, { token: ownerAsAgent, readOnly: false }, (c) => c.query(
      "SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, $2::uuid)",
      [ids.beaconOrg, ids.agentA],
    )),
    (err) => err?.code === '42501' && /VIEW_AS_READ_ONLY/.test(err.message),
    'View-as write in READ WRITE tx must fail with 42501 VIEW_AS_READ_ONLY',
  );

  // 2. Narrow viewer (Selling Agent A, self) viewing as Wide target (Acme Owner, org_subtree): viewer never widens!
  const agentAsOwner = mintSignedToken({
    keyId, secretBytes, environment, actorPersonId: ids.agentA, viewAsPersonId: ids.acmeOwner,
  });
  await runAsPlatformApp(db.pool, { token: agentAsOwner, readOnly: true }, async (c) => {
    assert.deepEqual((await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, []);
    const people = (await c.query("SELECT iam.effective_narrow_person_ids('act:coherence.bob.read') AS v")).rows[0].v;
    assert.deepEqual(people, [ids.agentA]);
    assert.ok(!people.includes(ids.agentB), 'sibling agent B must never leak into narrow viewer viewing as owner');
  });

  // 3. Disjoint companies (Acme Owner viewing as Northstar Admin): empty intersection
  const crossCompany = mintSignedToken({
    keyId, secretBytes, environment, actorPersonId: ids.acmeOwner, viewAsPersonId: ids.northstarAdmin,
  });
  await runAsPlatformApp(db.pool, { token: crossCompany, readOnly: true }, async (c) => {
    assert.equal((await c.query("SELECT iam.has_right('act:coherence.bob.read') AS ok")).rows[0].ok, false);
    assert.deepEqual((await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, []);
  });
});

test('Layer 7 [Eastern Business Day]: iam.business_today() handles America/New_York midnight, EST/EDT, DST spring-forward, DST fall-back, and non-Eastern session timezones', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const db = await createEmptyMigratedTestDb();
  t.after(() => db.cleanup());

  const cases = [
    // Winter EST (UTC-5)
    ['2026-01-15T04:59:59Z', '2026-01-14'],
    ['2026-01-15T05:00:00Z', '2026-01-15'],
    // Summer EDT (UTC-4)
    ['2026-07-15T03:59:59Z', '2026-07-14'],
    ['2026-07-15T04:00:00Z', '2026-07-15'],
    // DST Spring-Forward (2026-03-08 02:00 EST -> 03:00 EDT)
    ['2026-03-08T04:59:59Z', '2026-03-07'],
    ['2026-03-08T05:00:00Z', '2026-03-08'],
    ['2026-03-08T07:00:00Z', '2026-03-08'],
    ['2026-03-09T03:59:59Z', '2026-03-08'],
    ['2026-03-09T04:00:00Z', '2026-03-09'],
    // DST Fall-Back (2026-11-01 02:00 EDT -> 01:00 EST)
    ['2026-11-01T03:59:59Z', '2026-10-31'],
    ['2026-11-01T04:00:00Z', '2026-11-01'],
    ['2026-11-01T05:30:00Z', '2026-11-01'],
    ['2026-11-01T06:30:00Z', '2026-11-01'],
    ['2026-11-02T04:59:59Z', '2026-11-01'],
    ['2026-11-02T05:00:00Z', '2026-11-02'],
  ];

  for (const sessionTz of ['UTC', 'America/Los_Angeles', 'Asia/Tokyo', 'America/New_York']) {
    await runAsPlatformApp(db.pool, { readOnly: true }, async (c) => {
      await c.query(`SET LOCAL TIME ZONE '${sessionTz}'`);
      for (const [instant, expectedDate] of cases) {
        const actual = (await c.query("SELECT pg_catalog.to_char(iam.business_today($1::timestamptz), 'YYYY-MM-DD') AS d", [instant])).rows[0].d;
        assert.equal(actual, expectedDate, `tz=${sessionTz} instant=${instant}`);
      }
      const noArg = (await c.query(
        "SELECT iam.business_today() = (pg_catalog.now() AT TIME ZONE 'America/New_York')::date AS eq",
      )).rows[0].eq;
      assert.equal(noArg, true, `zero-arg iam.business_today() must match America/New_York under session tz=${sessionTz}`);
    });
  }
});

test('Layer 7 [Scope Derivation & Descendant Flow]: org_subtree, self, include_descendants true/false, allows_org_wide_scope, and org-edge cycle rejection', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const db = await createEmptyMigratedTestDb();
  t.after(() => db.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedStandardIamWorld(db.pool);

  const nonDescPerson = randomUUID();
  await inSerializableTx(db.pool, async (c) => {
    const j = await appendAuditEntry(c, { commandKind: 'iam.scope_extras', commandKey: 'scope-extras-1' });
    const seq = j.seq;

    await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [nonDescPerson, seq]);
    await c.query(
      "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'NoDesc Viewer','NoDesc Viewer','nodesc@acme.example','active',$3)",
      [randomUUID(), nonDescPerson, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), nonDescPerson, ids.acmeOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$4,false,'org_subtree','[2020-01-01,)'::daterange,'active',$5)`,
      [randomUUID(), nonDescPerson, ids.roleCustomerOwner, ids.acmeOrg, seq],
    );
  });

  // 1. org_subtree with include_descendants = true flows to all descendants (acme -> beacon -> eastTeam, harbor)
  const ownerTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.acmeOwner });
  await runAsPlatformApp(db.pool, { token: ownerTok, readOnly: true }, async (c) => {
    const orgs = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v.sort();
    assert.deepEqual(orgs, [ids.acmeOrg, ids.beaconOrg, ids.harborOrg, ids.eastTeamOrg].sort());
  });

  // 2. org_subtree with include_descendants = false stays strictly on acme
  const noDescTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: nonDescPerson });
  await runAsPlatformApp(db.pool, { token: noDescTok, readOnly: true }, async (c) => {
    const orgs = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
    assert.deepEqual(orgs, [ids.acmeOrg]);
  });

  // 3. allows_org_wide_scope = false rejects org_subtree grant and narrowing role_versions with live org_subtree grants
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.bad_wide', commandKey: 'bad-wide-grant' });
      await c.query(
        `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)`,
        [randomUUID(), ids.agentC, ids.roleSellingAgent, ids.beaconOrg, j.seq],
      );
    }),
    (err) => err?.code === '23514',
    'selling_agent (allows_org_wide_scope=false) must reject org_subtree grant',
  );
  const ownerRvId = (await db.pool.query('SELECT id FROM iam.role_versions WHERE role_id = $1 AND superseded_by_id IS NULL', [ids.roleCustomerOwner])).rows[0].id;
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.narrow_wide_role', commandKey: 'narrow-wide-role-1' });
      await c.query(
        `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, replaces_id, journal_seq)
         VALUES ($1,$2,'Customer Owner Narrowed',true,false,false,'active',$3,$4)`,
        [randomUUID(), ids.roleCustomerOwner, ownerRvId, j.seq],
      );
    }),
    (err) => err?.code === '23514' && /ORG_WIDE_SCOPE_FORBIDDEN/.test(err.message),
  );

  // 4. self scope (derived strictly from agent_affiliations, zero organization_memberships)
  const agentATok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.agentA });
  await runAsPlatformApp(db.pool, { token: agentATok, readOnly: false }, async (c) => {
    assert.deepEqual((await c.query("SELECT iam.effective_wide_org_ids('act:transmittals.read') AS v")).rows[0].v, []);
    assert.deepEqual((await c.query("SELECT org_id, person_id FROM iam.effective_narrow_pairs('act:transmittals.read')")).rows, [
      { org_id: ids.beaconOrg, person_id: ids.agentA },
    ]);
    const ok = (await c.query("SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, $2::uuid)", [ids.beaconOrg, ids.agentA])).rows[0];
    assert.equal(ok.actor_person_id, ids.agentA);
  });
  await assert.rejects(
    () => runAsPlatformApp(db.pool, { token: agentATok, readOnly: false }, (c) => c.query(
      "SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, $2::uuid)",
      [ids.beaconOrg, ids.agentB],
    )),
    (err) => err?.code === '42501',
    'self-scoped agent must not write for another agent',
  );

  // 5. Cycle rejection on iam.organization_edges (acme -> eastTeam)
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.org_cycle', commandKey: 'org-cycle-1' });
      const acmeEdgeId = (await c.query('SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND superseded_by_id IS NULL', [ids.acmeOrg])).rows[0].id;
      await c.query(
        `INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq)
         VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4,$5)`,
        [randomUUID(), ids.acmeOrg, ids.eastTeamOrg, acmeEdgeId, j.seq],
      );
    }),
    (err) => err?.code === '23514',
    'cycle in organization_edges must be rejected with 23514',
  );
});

test('Layer 7 [Dated Ranges & Environment Scope]: expired/future valid_range across grants, memberships, affiliations, and org edges; data_date_range; prod_only vs dev_only', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const db = await createEmptyMigratedTestDb();
  t.after(() => db.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedStandardIamWorld(db.pool, { environment: 'dev' });

  const pastGrantPerson = randomUUID();
  const futureGrantPerson = randomUUID();
  const expiredAffAgent = randomUUID();
  const expiredMemPerson = randomUUID();
  const datedDataPerson = randomUUID();
  const expiredChildOrg = randomUUID();

  await inSerializableTx(db.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.dated_seed', commandKey: 'dated-seed-1' });
    const seq = j.seq;

    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'agency',$2)", [expiredChildOrg, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'expired_agency','Expired Agency','active',$3)",
      [randomUUID(), expiredChildOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,daterange(iam.business_today() - 30, iam.business_today(), '[)'),'active',$4)`,
      [randomUUID(), expiredChildOrg, ids.acmeOrg, seq],
    );

    for (const [pid, name, email, npn] of [
      [pastGrantPerson, 'Past Grant', 'past@beacon.example', null],
      [futureGrantPerson, 'Future Grant', 'future@beacon.example', null],
      [expiredAffAgent, 'Expired Aff Agent', 'expaff@beacon.example', '44444444'],
      [expiredMemPerson, 'Expired Mem Staff', 'expmem@beacon.example', null],
      [datedDataPerson, 'Dated Data Staff', 'dated@beacon.example', null],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [pid, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, npn, status, journal_seq) VALUES ($1,$2,$3,$3,$4,$5,'active',$6)",
        [randomUUID(), pid, name, email, npn, seq],
      );
    }

    for (const pid of [pastGrantPerson, futureGrantPerson, datedDataPerson]) {
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), pid, ids.beaconOrg, seq],
      );
    }
    await c.query(
      `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,'employee',daterange(iam.business_today() - 30, iam.business_today(), '[)'),'active',$4)`,
      [randomUUID(), expiredMemPerson, ids.beaconOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.agent_affiliations (id, person_id, npn, agency_org_id, split_bps, agent_file_name, valid_range, status, journal_seq)
       VALUES ($1,$2,'44444444',$3,8000,'Expired Aff Agent',daterange(iam.business_today() - 30, iam.business_today(), '[)'),'active',$4)`,
      [randomUUID(), expiredAffAgent, ids.beaconOrg, seq],
    );

    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$4,true,'org_subtree',daterange(iam.business_today() - 30, iam.business_today(), '[)'),'active',$5)`,
      [randomUUID(), pastGrantPerson, ids.roleAgencyManager, ids.beaconOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$4,true,'org_subtree',daterange(iam.business_today() + 1, NULL, '[)'),'active',$5)`,
      [randomUUID(), futureGrantPerson, ids.roleAgencyManager, ids.beaconOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)`,
      [randomUUID(), expiredMemPerson, ids.roleAgencyManager, ids.beaconOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$4,false,'self','[2020-01-01,)'::daterange,'active',$5)`,
      [randomUUID(), expiredAffAgent, ids.roleSellingAgent, ids.beaconOrg, seq],
    );
    await c.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, data_date_range, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$4,true,'org_subtree','[2025-01-01,2026-01-01)'::daterange,'[2020-01-01,)'::daterange,'active',$5)`,
      [randomUUID(), datedDataPerson, ids.roleAgencyManager, ids.beaconOrg, seq],
    );
  });

  const ownerTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.acmeOwner });
  await runAsPlatformApp(db.pool, { token: ownerTok, readOnly: true }, async (c) => {
    const orgs = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
    assert.ok(!orgs.includes(expiredChildOrg), 'expired org edge must not flow down to child org');
    assert.equal((await c.query("SELECT iam.has_right('act:coherence.dev_debug') AS ok")).rows[0].ok, true);
    assert.equal((await c.query("SELECT iam.has_right('act:coherence.prod_send') AS ok")).rows[0].ok, false);
  });

  for (const [label, pid] of [
    ['past_grant', pastGrantPerson],
    ['future_grant', futureGrantPerson],
    ['expired_membership', expiredMemPerson],
    ['expired_affiliation', expiredAffAgent],
  ]) {
    const tok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: pid });
    await runAsPlatformApp(db.pool, { token: tok, readOnly: true }, async (c) => {
      assert.deepEqual((await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `${label} wide must be empty`);
      assert.deepEqual((await c.query("SELECT iam.effective_narrow_person_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `${label} narrow must be empty`);
    });
  }

  const datedTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: datedDataPerson });
  await runAsPlatformApp(db.pool, { token: datedTok, readOnly: false }, async (c) => {
    const inRange = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read', '2025-06-15'::date) AS v")).rows[0].v;
    assert.ok(inRange.includes(ids.beaconOrg));
    const atUpper = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read', '2026-01-01'::date) AS v")).rows[0].v;
    assert.deepEqual(atUpper, []);
    const beforeLower = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read', '2024-12-31'::date) AS v")).rows[0].v;
    assert.deepEqual(beforeLower, []);
    await c.query("SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, NULL, '2025-12-31'::date)", [ids.beaconOrg]);
  });
  await assert.rejects(
    () => runAsPlatformApp(db.pool, { token: datedTok, readOnly: false }, (c) => c.query(
      "SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, NULL, '2026-01-01'::date)",
      [ids.beaconOrg],
    )),
    (err) => err?.code === '42501',
    'write outside data_date_range must fail with 42501',
  );

  await runAsPlatformApp(db.pool, { token: datedTok, readOnly: true }, async (c) => {
    assert.deepEqual(
      (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v,
      [],
      'omitted p_data_date must not match grant with non-NULL data_date_range',
    );
    assert.strictEqual(
      (await c.query("SELECT iam.has_right('act:coherence.bob.read') AS ok")).rows[0].ok,
      false,
      'has_right with omitted p_data_date must fail closed on date-restricted grant',
    );
  });
  await assert.rejects(
    () => runAsPlatformApp(db.pool, { token: datedTok, readOnly: false }, (c) => c.query(
      "SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, NULL, NULL)",
      [ids.beaconOrg],
    )),
    (err) => err?.code === '42501',
    'assert_can_write with omitted p_data_date must fail closed on date-restricted grant',
  );
});

test('Layer 7 [Tool Switches & Nusear Bypass]: off/held/preview block customers, ancestor held/off vetoes child on, Nusear bypasses switches, and is_nusear_only blocks customers', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const db = await createEmptyMigratedTestDb();
  t.after(() => db.cleanup());

  const { ids, keyId, secretBytes, staffKeyId, staffSecretBytes, environment } = await seedStandardIamWorld(db.pool);

  const ownerTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.acmeOwner });
  const supportTok = mintSignedToken({ keyId: staffKeyId, secretBytes: staffSecretBytes, environment, actorPersonId: ids.nusearSupport });
  const supportAsOwnerTok = mintSignedToken({ keyId: staffKeyId, secretBytes: staffSecretBytes, environment, actorPersonId: ids.nusearSupport, viewAsPersonId: ids.acmeOwner });

  // 1. Held without hold_reason must fail CHECK (23514)
  const transSwitchId = (await db.pool.query("SELECT id FROM iam.organization_tool_switches WHERE organization_id = $1 AND tool_id = 'transmittals' AND superseded_by_id IS NULL", [ids.acmeOrg])).rows[0].id;
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.bad_hold', commandKey: 'bad-hold-1' });
      await c.query(
        `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, hold_reason, status, replaces_id, journal_seq)
         VALUES ($1,$2,'transmittals','held',NULL,'active',$3,$4)`,
        [randomUUID(), ids.acmeOrg, transSwitchId, j.seq],
      );
    }),
    (err) => err?.code === '23514',
    'switch_state = held with NULL hold_reason must fail CHECK',
  );

  // 2. Switch transmittals OFF at Acme: customer sees 0 orgs and write fails 42501; Nusear Support bypasses!
  let offSwitchId;
  await inSerializableTx(db.pool, async (c) => {
    const j = await appendAuditEntry(c, { commandKind: 'iam.switch_off', commandKey: 'switch-off-1' });
    offSwitchId = randomUUID();
    await c.query(
      `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq)
       VALUES ($1,$2,'transmittals','off','active',$3,$4)`,
      [offSwitchId, ids.acmeOrg, transSwitchId, j.seq],
    );
  });

  await runAsPlatformApp(db.pool, { token: ownerTok, readOnly: true }, async (c) => {
    assert.deepEqual((await c.query("SELECT iam.effective_wide_org_ids('act:transmittals.read') AS v")).rows[0].v, []);
  });
  await assert.rejects(
    () => runAsPlatformApp(db.pool, { token: ownerTok, readOnly: false }, (c) => c.query(
      "SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, $2::uuid)",
      [ids.beaconOrg, ids.agentA],
    )),
    (err) => err?.code === '42501',
  );

  // Nusear Support bypasses customer switch!
  await runAsPlatformApp(db.pool, { token: supportTok, readOnly: false }, async (c) => {
    const orgs = (await c.query("SELECT iam.effective_wide_org_ids('act:transmittals.read') AS v")).rows[0].v;
    assert.ok(orgs.includes(ids.beaconOrg));
    const wr = (await c.query(
      "SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, $2::uuid)",
      [ids.beaconOrg, ids.agentA],
    )).rows[0];
    assert.equal(wr.actor_person_id, ids.nusearSupport);
    assert.equal(wr.recorded_as, 'nusear_support');
  });

  // Nusear Support viewing as Customer Owner while tool is off gets 0 rows (intersection!)
  await runAsPlatformApp(db.pool, { token: supportAsOwnerTok, readOnly: true }, async (c) => {
    assert.deepEqual((await c.query("SELECT iam.effective_wide_org_ids('act:transmittals.read') AS v")).rows[0].v, []);
  });

  // 3. Switch back ON at Acme, then override Beacon to 'held' -> Harbor accessible, Beacon blocked for customer!
  let acmeOnSwitchId;
  let beaconHeldSwitchId;
  await inSerializableTx(db.pool, async (c) => {
    const j = await appendAuditEntry(c, { commandKind: 'iam.switch_override', commandKey: 'switch-override-1' });
    acmeOnSwitchId = randomUUID();
    beaconHeldSwitchId = randomUUID();
    await c.query(
      `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq)
       VALUES ($1,$2,'transmittals','on','active',$3,$4)`,
      [acmeOnSwitchId, ids.acmeOrg, offSwitchId, j.seq],
    );
    await c.query(
      `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, hold_reason, status, journal_seq)
       VALUES ($1,$2,'transmittals','held','pending compliance review','active',$3)`,
      [beaconHeldSwitchId, ids.beaconOrg, j.seq],
    );
  });

  await runAsPlatformApp(db.pool, { token: ownerTok, readOnly: true }, async (c) => {
    const orgs = (await c.query("SELECT iam.effective_wide_org_ids('act:transmittals.read') AS v")).rows[0].v;
    assert.ok(orgs.includes(ids.acmeOrg));
    assert.ok(orgs.includes(ids.harborOrg));
    assert.ok(!orgs.includes(ids.beaconOrg), 'child held switch must override ancestor on switch');
    assert.ok(!orgs.includes(ids.eastTeamOrg), 'descendant of held agency must also inherit held');
  });

  // 3b. Item 7: Ancestor 'held' or 'off' MUST veto every descendant even when a child sets 'on'!
  await t.test('Item 7: ancestor held or off switch vetoes child on switch', async () => {
    let acmeHeldSwitchId;
    let beaconOnSwitchId;
    await inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.switch_veto_held', commandKey: 'switch-veto-held-1' });
      acmeHeldSwitchId = randomUUID();
      beaconOnSwitchId = randomUUID();
      await c.query(
        `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, hold_reason, status, replaces_id, journal_seq)
         VALUES ($1,$2,'transmittals','held','company compliance hold','active',$3,$4)`,
        [acmeHeldSwitchId, ids.acmeOrg, acmeOnSwitchId, j.seq],
      );
      await c.query(
        `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq)
         VALUES ($1,$2,'transmittals','on','active',$3,$4)`,
        [beaconOnSwitchId, ids.beaconOrg, beaconHeldSwitchId, j.seq],
      );
    });
    await runAsPlatformApp(db.pool, { token: ownerTok, readOnly: true }, async (c) => {
      const orgs = (await c.query("SELECT iam.effective_wide_org_ids('act:transmittals.read') AS v")).rows[0].v;
      assert.deepEqual(orgs, [], 'parent company held switch must veto child agency on switch');
    });
    await assert.rejects(
      () => runAsPlatformApp(db.pool, { token: ownerTok, readOnly: false }, (c) => c.query(
        "SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, $2::uuid)",
        [ids.beaconOrg, ids.agentA],
      )),
      (err) => err?.code === '42501',
      'parent company held switch must veto customer write on child with on switch',
    );

    await inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.switch_veto_off', commandKey: 'switch-veto-off-1' });
      await c.query(
        `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq)
         VALUES ($1,$2,'transmittals','off','active',$3,$4)`,
        [randomUUID(), ids.acmeOrg, acmeHeldSwitchId, j.seq],
      );
    });
    await runAsPlatformApp(db.pool, { token: ownerTok, readOnly: true }, async (c) => {
      const orgs = (await c.query("SELECT iam.effective_wide_org_ids('act:transmittals.read') AS v")).rows[0].v;
      assert.deepEqual(orgs, [], 'parent company off switch must veto child agency on switch');
    });
  });

  // 3c. Item 14: 'preview' switch state blocks customers while Nusear Support bypasses!
  await t.test('Item 14: preview switch state blocks customers while Nusear internal bypasses', async () => {
    const vaultSwitchId = (await db.pool.query(
      "SELECT id FROM iam.organization_tool_switches WHERE organization_id = $1 AND tool_id = 'vault' AND superseded_by_id IS NULL",
      [ids.acmeOrg],
    )).rows[0].id;
    await inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.switch_preview', commandKey: 'switch-preview-1' });
      await c.query(
        `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq)
         VALUES ($1,$2,'vault','preview','active',$3,$4)`,
        [randomUUID(), ids.acmeOrg, vaultSwitchId, j.seq],
      );
    });
    await runAsPlatformApp(db.pool, { token: ownerTok, readOnly: true }, async (c) => {
      assert.deepEqual(
        (await c.query("SELECT iam.effective_wide_org_ids('act:vault.archive.retrieve') AS v")).rows[0].v,
        [],
        'preview switch must block customer reads',
      );
    });
    await assert.rejects(
      () => runAsPlatformApp(db.pool, { token: ownerTok, readOnly: false }, (c) => c.query(
        "SELECT * FROM iam.assert_can_write('act:vault.archive.retrieve', $1::uuid)",
        [ids.beaconOrg],
      )),
      (err) => err?.code === '42501',
      'preview switch must block customer writes',
    );
    await runAsPlatformApp(db.pool, { token: supportTok, readOnly: true }, async (c) => {
      const orgs = (await c.query("SELECT iam.effective_wide_org_ids('act:vault.archive.retrieve') AS v")).rows[0].v;
      assert.ok(orgs.includes(ids.beaconOrg), 'Nusear internal role must bypass preview switch');
    });
    const previewVaultSwitchId = (await db.pool.query(
      "SELECT id FROM iam.organization_tool_switches WHERE organization_id = $1 AND tool_id = 'vault' AND superseded_by_id IS NULL",
      [ids.acmeOrg],
    )).rows[0].id;
    await inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { commandKind: 'iam.switch_vault_on', commandKey: 'switch-vault-on-1' });
      await c.query(
        `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq)
         VALUES ($1,$2,'vault','on','active',$3,$4)`,
        [randomUUID(), ids.acmeOrg, previewVaultSwitchId, j.seq],
      );
    });
  });

  // 4. is_nusear_only tool (control_center): blocked for customer even if a switch is inserted, allowed for Nusear internal
  await inSerializableTx(db.pool, async (c) => {
    const j = await appendAuditEntry(c, { commandKind: 'iam.nusear_only_sw', commandKey: 'nusear-only-sw-1' });
    await c.query(
      `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq)
       VALUES ($1,$2,'control_center','on','active',$3)`,
      [randomUUID(), ids.acmeOrg, j.seq],
    );
  });
  await runAsPlatformApp(db.pool, { token: ownerTok, readOnly: true }, async (c) => {
    assert.equal((await c.query("SELECT iam.has_right('act:control_center.read') AS ok")).rows[0].ok, false);
  });
  await runAsPlatformApp(db.pool, { token: supportTok, readOnly: true }, async (c) => {
    assert.equal((await c.query("SELECT iam.has_right('act:control_center.read') AS ok")).rows[0].ok, true);
  });

  // 5. Nusear internal writes record recorded_as = 'nusear_support'; customer writes record 'self'
  await runAsPlatformApp(db.pool, { token: supportTok, readOnly: false }, async (c) => {
    const wr = (await c.query(
      "SELECT * FROM iam.assert_can_write('act:coherence.run.manage', $1::uuid)",
      [ids.beaconOrg],
    )).rows[0];
    assert.equal(wr.actor_person_id, ids.nusearSupport);
    assert.equal(wr.recorded_as, 'nusear_support');
  });
  await runAsPlatformApp(db.pool, { token: ownerTok, readOnly: false }, async (c) => {
    const wr = (await c.query(
      "SELECT * FROM iam.assert_can_write('act:vault.archive.retrieve', $1::uuid)",
      [ids.beaconOrg],
    )).rows[0];
    assert.equal(wr.actor_person_id, ids.acmeOwner);
    assert.equal(wr.recorded_as, 'self');
  });
});

test('Layer 7 [Service Role Least-Privilege Transactions]: real SET LOCAL ROLE transactions succeed for platform_writer, platform_worker, platform_iam_sync, and platform_readonly while denying forbidden access', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const db = await createEmptyMigratedTestDb();
  t.after(() => db.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedStandardIamWorld(db.pool);
  const ownerTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.acmeOwner });

  // 1. platform_writer: calls iam.assert_can_write + inserts into platform.audit_journal; denied iam.* base tables & iam_secret
  await inSerializableTx(db.pool, async (c) => {
    await c.query('SET LOCAL ROLE platform_writer');
    await c.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [ownerTok]);
    const wr = (await c.query(
      "SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, $2::uuid)",
      [ids.beaconOrg, ids.agentA],
    )).rows[0];
    assert.equal(wr.actor_person_id, ids.acmeOwner);
    const j = await appendAuditEntry(c, {
      environment,
      actorPersonId: wr.actor_person_id,
      recordedAs: wr.recorded_as,
      targetOrgId: ids.beaconOrg,
      commandKind: 'iam.writer_tx',
      commandKey: 'writer-real-tx-1',
    });
    assert.ok(Number(j.seq) >= 2);
  });
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_writer');
      await c.query('SELECT * FROM iam_secret.signing_keys LIMIT 1');
    }),
    (err) => err?.code === '42501',
    'platform_writer must be denied iam_secret.signing_keys',
  );

  // 2. platform_worker: reads closure views (needs iam.business_today) and audit_journal SELECT,
  //    but is DENIED INSERT on platform.audit_journal, DENIED EXECUTE on compute_journal_hash, denied iam writes & iam_secret.
  await inSerializableTx(db.pool, async (c) => {
    await c.query('SET LOCAL ROLE platform_worker');
    const orgClosure = (await c.query('SELECT COUNT(*)::int AS n FROM iam.v_organization_closure_live')).rows[0].n;
    assert.ok(orgClosure > 0, 'platform_worker must be able to read iam.v_organization_closure_live');
    const memView = (await c.query('SELECT COUNT(*)::int AS n FROM iam.v_all_memberships_live')).rows[0].n;
    assert.ok(memView > 0, 'platform_worker must be able to read iam.v_all_memberships_live');
    const jCnt = (await c.query('SELECT COUNT(*)::int AS n FROM platform.audit_journal')).rows[0].n;
    assert.ok(jCnt >= 2, 'platform_worker must be able to read platform.audit_journal');
  });
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_worker');
      await appendAuditEntry(c, {
        environment,
        commandKind: 'iam.worker_tx',
        commandKey: 'worker-real-tx-1',
      });
    }),
    (err) => err?.code === '42501',
    'platform_worker must be denied INSERT on platform.audit_journal (app_cmd writes journals)',
  );
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_worker');
      await c.query(
        "SELECT platform.compute_journal_hash(1, now(), 'local', NULL, 'service', NULL, 'iam.x', 'k', $1, $2, '{}'::jsonb)",
        ['a'.repeat(64), '0'.repeat(64)],
      );
    }),
    (err) => err?.code === '42501',
    'platform_worker must be denied EXECUTE on platform.compute_journal_hash',
  );
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_worker');
      await c.query('SELECT * FROM iam_secret.signing_keys LIMIT 1');
    }),
    (err) => err?.code === '42501',
    'platform_worker must be denied iam_secret.signing_keys',
  );
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_worker');
      await c.query("INSERT INTO iam.tools (id, display_name, journal_seq) VALUES ('worker_nope', 'Nope', 1)");
    }),
    (err) => err?.code === '42501',
    'platform_worker must be denied INSERT on iam tables',
  );

  // 3. platform_iam_sync: inserts journal, iam roles/role_versions/role_rights,
  //    supersedes a versioned row, reads closure views, and manages iam_secret.signing_keys
  await inSerializableTx(db.pool, async (c) => {
    await c.query('SET LOCAL ROLE platform_iam_sync');
    const j = await appendAuditEntry(c, {
      environment,
      commandKind: 'iam.sync_tx',
      commandKey: 'sync-real-tx-1',
    });
    const seq = j.seq;

    const syncedParent = randomUUID();
    const syncedChild = randomUUID();
    await c.query('INSERT INTO iam.roles (id, slug, journal_seq) VALUES ($1,$2,$3),($4,$5,$3)', [
      syncedParent, 'sync_parent_role', seq, syncedChild, 'sync_child_role',
    ]);
    await c.query(
      `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq)
       VALUES ($1,$2,'Sync Parent',false,false,true,'active',$3),
              ($4,$5,'Sync Child',false,false,false,'active',$3)`,
      [randomUUID(), syncedParent, seq, randomUUID(), syncedChild],
    );
    await c.query(
      `INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq)
       VALUES ($1,$2,'act:coherence.bob.read','active',$3),
              ($4,$5,'act:coherence.bob.read','active',$3)`,
      [randomUUID(), syncedParent, seq, randomUUID(), syncedChild],
    );
    await c.query(
      "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,'act:transmittals.read','active',$3)",
      [randomUUID(), syncedParent, seq],
    );
    const prevParentRv = (await c.query(
      'SELECT id FROM iam.role_versions WHERE role_id = $1 AND superseded_by_id IS NULL',
      [syncedParent],
    )).rows[0].id;
    await c.query(
      `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, replaces_id, journal_seq)
       VALUES ($1,$2,'Sync Parent Renamed',false,false,true,'active',$3,$4)`,
      [randomUUID(), syncedParent, prevParentRv, seq],
    );

    // Supersede an existing nusear_staff person_version under platform_iam_sync
    const prevPvId = (await c.query(
      'SELECT id FROM iam.person_versions WHERE person_id = $1 AND superseded_by_id IS NULL',
      [ids.nusearSupport],
    )).rows[0].id;
    await c.query(
      `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, replaces_id, journal_seq)
       VALUES ($1,$2,'nusear_staff','Jordan Support','Jordan Synced','jordan.support@nusear.example','active',$3,$4)`,
      [randomUUID(), ids.nusearSupport, prevPvId, seq],
    );

    // Closure views under platform_iam_sync (calls iam.business_today)
    const orgClosure = (await c.query('SELECT COUNT(*)::int AS n FROM iam.v_organization_closure_live')).rows[0].n;
    assert.ok(orgClosure > 0);

    // Signing key write under platform_iam_sync (nusear_staff scope)
    await c.query(
      `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, key_scope, active_from)
       VALUES ('k_sync_2026', $1, $2, 'nusear_staff', pg_catalog.now())`,
      [randomBytes(32), environment],
    );
  });

  // platform_iam_sync is denied superseding company_local people or inserting company_local signing keys
  const agentAPvId = (await db.pool.query(
    'SELECT id FROM iam.person_versions WHERE person_id = $1 AND superseded_by_id IS NULL',
    [ids.agentA],
  )).rows[0].id;
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_iam_sync');
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.sync_bad_local', commandKey: 'sync-bad-local-1' });
      await c.query(
        `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, npn, status, replaces_id, journal_seq)
         VALUES ($1,$2,'company_local','Sam Seller','Sam Hijack','sam.a@beacon.example','11111111','active',$3,$4)`,
        [randomUUID(), ids.agentA, agentAPvId, j.seq],
      );
    }),
    (err) => err?.code === '42501',
    'platform_iam_sync must be denied superseding company_local person_versions',
  );

  // 4. platform_readonly: reads platform.audit_journal, iam base tables, and closure views; denied writes & iam_secret
  await inSerializableTx(db.pool, async (c) => {
    await c.query('SET LOCAL ROLE platform_readonly');
    const jCnt = (await c.query('SELECT COUNT(*)::int AS n FROM platform.audit_journal')).rows[0].n;
    assert.ok(jCnt >= 3);
    const orgClosure = (await c.query('SELECT COUNT(*)::int AS n FROM iam.v_organization_closure_live')).rows[0].n;
    assert.ok(orgClosure > 0);
    const rolesCnt = (await c.query('SELECT COUNT(*)::int AS n FROM iam.roles')).rows[0].n;
    assert.ok(rolesCnt > 0);
  });
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_readonly');
      await appendAuditEntry(c, { environment, commandKind: 'iam.ro_bad', commandKey: 'ro-bad-1' });
    }),
    (err) => err?.code === '42501',
    'platform_readonly must be denied INSERT on platform.audit_journal',
  );
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      await c.query('SET LOCAL ROLE platform_readonly');
      await c.query('SELECT * FROM iam_secret.signing_keys LIMIT 1');
    }),
    (err) => err?.code === '42501',
    'platform_readonly must be denied iam_secret.signing_keys',
  );
});

test('Layer 7 [Append-Only Right Retirements]: iam.right_retirements replaces retired_journal_seq and disables reads and writes', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const db = await createEmptyMigratedTestDb();
  t.after(() => db.cleanup());

  const { ids, keyId, secretBytes, staffKeyId, staffSecretBytes, environment } = await seedStandardIamWorld(db.pool);

  // Verify retired_journal_seq column is removed from iam.rights and iam.right_retirements table exists
  const oldCol = await db.pool.query(
    "SELECT 1 FROM information_schema.columns WHERE table_schema = 'iam' AND table_name = 'rights' AND column_name = 'retired_journal_seq'",
  );
  assert.equal(oldCol.rows.length, 0, 'iam.rights must no longer have mutable-never-set retired_journal_seq column');

  const ownerTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.acmeOwner });
  const supportTok = mintSignedToken({ keyId: staffKeyId, secretBytes: staffSecretBytes, environment, actorPersonId: ids.nusearSupport });

  // Before retirement, act:transmittals.approve works for Acme Owner and Nusear Support
  await runAsPlatformApp(db.pool, { token: ownerTok, readOnly: false }, async (c) => {
    assert.equal((await c.query("SELECT iam.has_right('act:transmittals.approve') AS ok")).rows[0].ok, true);
    await c.query("SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, $2::uuid)", [ids.beaconOrg, ids.agentA]);
  });

  // Retire act:transmittals.approve append-only under platform_iam_sync!
  await inSerializableTx(db.pool, async (c) => {
    await c.query('SET LOCAL ROLE platform_iam_sync');
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.retire_rights', commandKey: 'retire-rights-1' });
    await c.query(
      "INSERT INTO iam.right_retirements (right_id, reason, journal_seq) VALUES ('act:transmittals.approve', 'superseded workflow', $1)",
      [j.seq],
    );
  });

  // Retired right immediately stops authorizing reads and writes (for both customer and Nusear support)
  for (const tok of [ownerTok, supportTok]) {
    await runAsPlatformApp(db.pool, { token: tok, readOnly: true }, async (c) => {
      assert.strictEqual((await c.query("SELECT iam.has_right('act:transmittals.approve') AS ok")).rows[0].ok, false);
      assert.deepEqual((await c.query("SELECT iam.effective_wide_org_ids('act:transmittals.approve') AS v")).rows[0].v, []);
    });
    await assert.rejects(
      () => runAsPlatformApp(db.pool, { token: tok, readOnly: false }, (c) => c.query(
        "SELECT * FROM iam.assert_can_write('act:transmittals.approve', $1::uuid, $2::uuid)",
        [ids.beaconOrg, ids.agentA],
      )),
      (err) => err?.code === '42501',
      'retired right must fail assert_can_write with 42501',
    );
  }

  // Duplicate retirement fails PK (23505); UPDATE/DELETE/TRUNCATE fail (55000); platform_app gets 42501
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.retire_dup', commandKey: 'retire-dup-1' });
      await c.query(
        "INSERT INTO iam.right_retirements (right_id, reason, journal_seq) VALUES ('act:transmittals.approve', 'again', $1)",
        [j.seq],
      );
    }),
    (err) => err?.code === '23505',
  );
  for (const sql of [
    "UPDATE iam.right_retirements SET reason = 'tamper'",
    'DELETE FROM iam.right_retirements',
    'TRUNCATE TABLE iam.right_retirements',
  ]) {
    await assert.rejects(() => db.pool.query(sql), (err) => err?.code === '55000');
  }
  await assert.rejects(
    () => runAsPlatformApp(db.pool, { readOnly: true }, (c) => c.query('SELECT * FROM iam.right_retirements LIMIT 1')),
    (err) => err?.code === '42501',
  );
});

test('Layer 7 [Release 1A Journal Hash Parity]: platform.compute_journal_hash uses canonical_json, sha256_text, and format_utc_us matching Node canonicalJson byte-for-byte', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const db = await createEmptyMigratedTestDb();
  t.after(() => db.cleanup());

  // Keys of varying lengths in nested objects distinguish canonical_json (COLLATE "C", no spaces)
  // from PostgreSQL jsonb::text (length-first key sort + spaces after colons/commas).
  const body = { z: 1, aa: { b: true, aaa: 'hello', a: null }, arr: [1, 'two', { zz: 2, a: 1 }] };
  const actorId = randomUUID();
  const orgId = randomUUID();
  const reqSha = sha256Hex('r1a-hash-parity');
  const prevHash = '0'.repeat(64);
  const ts = '2026-11-24T15:30:45.123456Z';

  const row = (await db.pool.query(
    `SELECT platform.canonical_json($1::jsonb) AS cj,
            platform.sha256_text('hello') AS sh,
            platform.format_utc_us($2::timestamptz) AS fmt,
            platform.compute_journal_hash(
              7, $2::timestamptz, 'prod', $3::uuid, 'self', $4::uuid,
              'iam.hash_parity', 'key-parity-1', $5, $6, $1::jsonb
            ) AS h`,
    [JSON.stringify(body), ts, actorId, orgId, reqSha, prevHash],
  )).rows[0];

  assert.equal(row.cj, canonicalJson(body));
  assert.equal(row.sh, sha256Hex('hello'));
  assert.equal(row.fmt, formatTimestampUtcUs(ts));

  const expectedHash = sha256Hex(`platform-audit-journal-v1\n${canonicalJson({
    actor_person_id: actorId,
    body,
    command_key: 'key-parity-1',
    command_kind: 'iam.hash_parity',
    environment: 'prod',
    prev_hash: prevHash,
    recorded_as: 'self',
    recorded_at: formatTimestampUtcUs(ts),
    request_sha256: reqSha,
    seq: 7,
    target_org_id: orgId,
  })}`);
  assert.equal(row.h, expectedHash, 'platform.compute_journal_hash must match Release 1A canonical_json serialization byte-for-byte');
});

test('Layer 7 [Control DB Closure]: iam.person_effective_grants reads today live tree in control database for Nusear staff (moved agency follows new upline, archived orgs excluded) and forbids company_local people', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const db = await createEmptyMigratedTestDb();
  t.after(() => db.cleanup());

  const keyId = 'k_ctrl_2026';
  const secretBytes = randomBytes(32);
  const environment = 'local';
  const rootOrg = randomUUID();
  const acmeOrg = randomUUID();
  const northstarOrg = randomUUID();
  const movedAgency = randomUUID();
  const archivedTeam = randomUUID();
  const acmeStaffOp = randomUUID();
  const nsStaffOp = randomUUID();
  const roleCtrlStaff = randomUUID();

  await inSerializableTx(db.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.ctrl_seed', commandKey: 'ctrl-seed' });
    const seq = j.seq;
    for (const [id, kind] of [
      [rootOrg, 'platform_root'], [acmeOrg, 'company'], [northstarOrg, 'company'],
      [movedAgency, 'agency'], [archivedTeam, 'team'],
    ]) {
      await c.query('INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,$2,$3)', [id, kind, seq]);
    }
    await c.query(
      `INSERT INTO iam.database_context (singleton, environment, db_role_kind, tenant_org_id, company_slug, support_external_label, journal_seq)
       VALUES (true, $1, 'control', NULL, NULL, 'Nusear support', $2)`,
      [environment, seq],
    );
    await c.query(
      `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, key_scope, active_from, active_until)
       VALUES ($1, $2, $3, 'nusear_staff', pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours')`,
      [keyId, secretBytes, environment],
    );
    await c.query("INSERT INTO iam.tools (id, display_name, is_nusear_only, is_customer_switchable, journal_seq) VALUES ('coherence','Coherence',false,true,$1)", [seq]);
    await c.query(
      "INSERT INTO iam.rights (id, right_kind, tool_id, environment_scope, sensitivity_class, is_delegable_power, description, journal_seq) VALUES ('act:coherence.bob.read','action','coherence','both','ordinary',true,'Read BoB',$1)",
      [seq],
    );
    for (const [oid, slug, name, status] of [
      [rootOrg, 'nusear', 'Nusear', 'active'],
      [acmeOrg, 'acme', 'Acme', 'active'],
      [northstarOrg, 'northstar', 'Northstar', 'active'],
      [movedAgency, 'moved', 'Moved', 'active'],
      [archivedTeam, 'arch_team', 'Archived Team', 'archived'],
    ]) {
      await c.query(
        'INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,$3,$4,$5,$6)',
        [randomUUID(), oid, slug, name, status, seq],
      );
    }
    for (const [child, parent, rng] of [
      [acmeOrg, rootOrg, '[2020-01-01,)'],
      [northstarOrg, rootOrg, '[2020-01-01,)'],
      [movedAgency, acmeOrg, '[2020-01-01,2025-06-01)'],
      [movedAgency, northstarOrg, '[2025-06-01,)'],
      [archivedTeam, northstarOrg, '[2020-01-01,2026-01-01)'],
    ]) {
      await c.query(
        "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4::daterange,'active',$5)",
        [randomUUID(), child, parent, rng, seq],
      );
    }
    for (const oid of [acmeOrg, northstarOrg]) {
      await c.query(
        "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','on','active',$3)",
        [randomUUID(), oid, seq],
      );
    }
    await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,NULL,$3)', [roleCtrlStaff, 'ctrl_staff', seq]);
    await c.query(
      "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,'Ctrl Staff',false,true,true,'active',$3)",
      [randomUUID(), roleCtrlStaff, seq],
    );
    await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,'act:coherence.bob.read','active',$3)", [randomUUID(), roleCtrlStaff, seq]);
    for (const [pid, name, email, grantOrg] of [
      [acmeStaffOp, 'Acme Staff Op', 'acme.ctrl@nusear.example', acmeOrg],
      [nsStaffOp, 'NS Staff Op', 'ns.ctrl@nusear.example', northstarOrg],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','nusear_staff',$2)", [pid, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'nusear_staff',$3,$3,$4,'active',$5)",
        [randomUUID(), pid, name, email, seq],
      );
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), pid, rootOrg, seq],
      );
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), pid, roleCtrlStaff, grantOrg, seq],
      );
    }
  });

  // Control DB strictly refuses company_local people.
  await assert.rejects(
    () => inSerializableTx(db.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.ctrl_bad_local', commandKey: 'ctrl-bad-local' });
      await c.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','company_local',$2)", [randomUUID(), j.seq]);
    }),
    (err) => err?.code === '23514',
    'control database must refuse company_local people',
  );

  const tok = (pid) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: pid });
  const acmeWide = await runAsPlatformApp(db.pool, { token: tok(acmeStaffOp), readOnly: true }, async (c) => (
    (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v
  ));
  assert.deepEqual(acmeWide, [acmeOrg], 'control DB uses today live tree: grant on acmeOrg excludes movedAgency');

  const nsWide = await runAsPlatformApp(db.pool, { token: tok(nsStaffOp), readOnly: true }, async (c) => (
    (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v
  ));
  assert.deepEqual([...nsWide].sort(), [movedAgency, northstarOrg].sort(), 'control DB uses today live tree: new upline sees moved agency and excludes archived team');
});
