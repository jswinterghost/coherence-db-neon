// Layer 7B: Release 1 migration 009 - Coherence data under database-only IAM rules.
// Exercises strict throwaway test_* databases on real PostgreSQL 17 strictly as platform_app
// (and platform_worker for worker-only commands) using signed app.session_token values.
import assert from 'node:assert/strict';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createCommandLayer } from '../src/commands/command-layer.mjs';
import { verifyChain, verifyCommitments } from '../src/commands/journal-export.mjs';
import * as policyChecks from '../src/config/policy-checks.mjs';
import { runMigrations } from '../src/db/migrate.mjs';
import { createClient, createPool } from '../src/db/pg-client.mjs';
import { createMemoryObjectStore } from '../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../src/storage/stores.mjs';
import { fingerprintBytes, sha256Hex } from '../src/util/crypto.mjs';
import {
  buildSyntheticEmitDataset,
  createDataOnlyMockEngineMaterializer,
  makeCsvFromObjects,
  seedEngineCopyVersion,
  seedStandingInput,
  SYNTHETIC_BOB_COLUMNS,
  SYNTHETIC_LEDGER_COLUMNS,
  SYNTHETIC_RUN_COLUMNS,
} from './helpers/fixtures.mjs';
import { checkPgAvailable, getAdminPgConfig, withClusterCatalogLock } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();
const TEST_DB_RE = /^test_[a-z0-9_]+$/;

function assertStrictTestDbName(dbName) {
  if (typeof dbName !== 'string' || !TEST_DB_RE.test(dbName)) {
    throw new Error(`Migration 009 tests strictly require throwaway test_* databases; got ${dbName}`);
  }
}

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

const ENV_BY_POOL = new WeakMap();

async function createCoherenceIamTestEnv({ companySlug = 'acme', displayName = 'Acme', initCompany = true } = {}) {
  const suffix = randomBytes(5).toString('hex');
  const dbName = `test_r1_009_${suffix}`;
  assertStrictTestDbName(dbName);
  const adminConfig = getAdminPgConfig();

  const admin = await createClient(adminConfig);
  try {
    await admin.query(`CREATE DATABASE "${dbName}" ENCODING 'UTF8'`);
  } finally {
    await admin.end();
  }

  const pgConfig = { ...adminConfig, database: dbName };
  const pool = await createPool(pgConfig);
  await runMigrations(pool);

  const codeStore = createCodeStore({ backend: createMemoryObjectStore({ label: `r1-009-code-${suffix}` }) });
  const dataStore = createDataStore({ backend: createMemoryObjectStore({ label: `r1-009-data-${suffix}` }) });
  const stores = createStorePair({ codeStore, dataStore });
  const commands = createCommandLayer({ pool, companySlug, stores });

  async function cleanup() {
    await pool.end().catch(() => {});
    const dropAdmin = await createClient(adminConfig).catch(() => null);
    if (dropAdmin) {
      try {
        assertStrictTestDbName(dbName);
        await dropAdmin.query(
          'SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()',
          [dbName],
        );
        await dropAdmin.query(`DROP DATABASE IF EXISTS "${dbName}"`);
      } finally {
        await dropAdmin.end().catch(() => {});
      }
    }
  }

  const env = {
    dbName,
    companySlug,
    displayName,
    pgConfig,
    pool,
    codeStore,
    dataStore,
    stores,
    commands,
    ownerToken: null,
    workerToken: null,
    cleanup,
  };
  ENV_BY_POOL.set(pool, { env, initCompany, suffix });
  return env;
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
  commandKind = 'iam.seed_coherence',
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

async function runAsRole(pool, role, { token = null, readOnly = true, serializable = false } = {}, fn) {
  const client = await pool.connect();
  try {
    const iso = serializable ? 'ISOLATION LEVEL SERIALIZABLE ' : '';
    const mode = readOnly ? 'READ ONLY' : 'READ WRITE';
    await client.query(`BEGIN TRANSACTION ${iso}${mode}`);
    await client.query(`SET LOCAL ROLE ${role}`);
    if (token !== null) {
      await client.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [token]);
    }
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

async function runAsPlatformApp(pool, opts, fn) {
  return runAsRole(pool, 'platform_app', opts, fn);
}

async function seedCoherenceIamWorld(pool, { environment = 'local', coherenceToolNusearOnly = false, bobReadEnvScope = 'both' } = {}) {
  const keyId = 'k_coh_2026';
  const secretBytes = randomBytes(32);

  const ids = {
    rootOrg: randomUUID(),
    acmeOrg: randomUUID(),
    beaconOrg: randomUUID(),
    eastTeamOrg: randomUUID(),
    harborOrg: randomUUID(),
    northstarOrg: randomUUID(),

    nusearOwner: randomUUID(),
    nusearAdminNoCoh: randomUUID(),
    nusearOperator: randomUUID(),
    northstarOperator: randomUUID(),
    workerService: randomUUID(),
    acmeEntityMgr: randomUUID(),
    acmeCompanyAdmin: randomUUID(),
    acmeInvestor: randomUUID(),
    beaconManager: randomUUID(),
    leadManager: randomUUID(),
    teamManager: randomUUID(),
    multiAgencyPerson: randomUUID(),
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
    roleInvestor: randomUUID(),
    roleAgencyManager: randomUUID(),
    roleTeamManager: randomUUID(),
    roleSellingAgent: randomUUID(),
    roleRetentionAgent: randomUUID(),
  };

  await inSerializableTx(pool, async (c) => {
    const j1 = await appendAuditEntry(c, { environment, commandKind: 'iam.bootstrap_coherence', commandKey: 'bootstrap-coherence-iam' });
    const seq = j1.seq;

    for (const [id, kind] of [
      [ids.rootOrg, 'platform_root'],
      [ids.acmeOrg, 'company'],
      [ids.beaconOrg, 'agency'],
      [ids.eastTeamOrg, 'team'],
      [ids.harborOrg, 'agency'],
      [ids.northstarOrg, 'company'],
    ]) {
      await c.query('INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,$2,$3)', [id, kind, seq]);
    }

    await c.query(
      `INSERT INTO iam.database_context (singleton, environment, db_role_kind, tenant_org_id, company_slug, support_external_label, journal_seq)
       VALUES (true, $1, 'company_working', $2, 'acme', 'Nusear support', $3)`,
      [environment, ids.acmeOrg, seq],
    );

    await c.query(
      `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, active_from, active_until)
       VALUES ($1, $2, $3, pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours')`,
      [keyId, secretBytes, environment],
    );

    for (const [id, display, nusearOnly, switchable] of [
      ['coherence', 'Coherence', coherenceToolNusearOnly, true],
      ['platform_audit', 'Platform Audit', false, true],
    ]) {
      await c.query(
        'INSERT INTO iam.tools (id, display_name, is_nusear_only, is_customer_switchable, journal_seq) VALUES ($1,$2,$3,$4,$5)',
        [id, display, nusearOnly, switchable, seq],
      );
    }

    const rights = [
      // Read rights
      ['act:coherence.bob.read', 'action', 'coherence', bobReadEnvScope, 'ordinary', true, null, null, null, 'Read Book of Business'],
      ['act:coherence.statements.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read agency statements'],
      ['act:coherence.upline.read', 'action', 'coherence', 'both', 'money_upline', true, null, null, null, 'Read upline statements'],
      ['act:coherence.ledger.read', 'action', 'coherence', 'both', 'money_upline', true, null, null, null, 'Read Coherent Ledger'],
      ['act:coherence.unpublished.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read published unsent runs'],
      ['act:coherence.runs.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read run metadata'],
      ['act:coherence.inputs.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read input versions'],
      ['act:coherence.decisions.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read decision records'],
      ['act:coherence.checks.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read check reports'],
      ['act:coherence.journal.read', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Read Coherence journal'],
      ['act:platform.audit_journal.read', 'action', 'platform_audit', 'both', 'ordinary', true, null, null, null, 'Read platform audit journal'],
      // Column rights
      ['col:coherence.statement_cash', 'column', 'coherence', 'both', 'money_statement', true, 'coherence', 'bob_policy_financials', 'amount', 'View agency statement cash'],
      ['col:coherence.upline_cash', 'column', 'coherence', 'both', 'money_upline', true, 'coherence', 'bob_policy_financials', 'upline_amount', 'View upline and gross cash'],
      ['col:platform.audit_journal.nusear_actor', 'column', 'platform_audit', 'both', 'platform_internal', true, 'platform', 'audit_journal', 'actor_person_id', 'View Nusear actor identity in audit journal'],
      // Operator write rights
      ['act:coherence.run.launch', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Launch Coherence run'],
      ['act:coherence.run.retry', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Retry Coherence step'],
      ['act:coherence.run.cancel', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Cancel Coherence step'],
      ['act:coherence.review.submit', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Submit staged review CSV'],
      ['act:coherence.review.save', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Save review decisions'],
      ['act:coherence.review.draft', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Save review draft'],
      ['act:coherence.inputs.publish', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Publish input version'],
      ['act:coherence.approvals.register', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Register approvals file'],
      // Owner typed/admin write rights
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
      // Worker-or-Owner write rights
      ['act:coherence.checks.record', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Record check report'],
      ['act:coherence.files.register', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Register stored files'],
      ['act:coherence.overlays.record', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Record generated overlay'],
      ['act:coherence.emit.materialize', 'action', 'coherence', 'both', 'ordinary', true, null, null, null, 'Materialize Emit outputs'],
      // Worker-only rights
      ['act:coherence.worker.attempt', 'action', 'coherence', 'both', 'platform_internal', false, null, null, null, 'Worker step attempt lifecycle'],
      ['act:coherence.worker.review', 'action', 'coherence', 'both', 'platform_internal', false, null, null, null, 'Worker review submission resolution'],
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

    const roleSpecs = [
      [ids.roleNusearOwner, 'nusear_owner', null, 'Nusear Owner', true, true, true],
      [ids.roleNusearAdmin, 'nusear_admin', null, 'Nusear Admin', false, true, true],
      [ids.roleCoherenceOperator, 'coherence_operator', null, 'Coherence Operator', false, true, true],
      [ids.roleWorkerService, 'coherence_worker_svc', null, 'Coherence Worker', true, true, true],
      [ids.roleEntityManager, 'entity_manager', null, 'Entity Manager', false, false, true],
      [ids.roleCompanyAdmin, 'company_admin', null, 'Company Admin', false, false, true],
      [ids.roleInvestor, 'investor', null, 'Investor', false, false, true],
      [ids.roleAgencyManager, 'agency_manager', null, 'Agency Manager', false, false, true],
      [ids.roleTeamManager, 'team_manager', null, 'Team Manager', false, false, false],
      [ids.roleSellingAgent, 'selling_agent', null, 'Selling Agent', false, false, false],
      [ids.roleRetentionAgent, 'retention_agent', null, 'Retention Agent', false, false, true],
    ];
    for (const [id, slug, ownerOrg, display, pinned, internal, wide] of roleSpecs) {
      await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,$3,$4)', [id, slug, ownerOrg, seq]);
      await c.query(
        `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq)
         VALUES ($1,$2,$3,$4,$5,$6,'active',$7)`,
        [randomUUID(), id, display, pinned, internal, wide, seq],
      );
    }

    const addRoleRights = async (roleId, list) => {
      for (const rightId of list) {
        await c.query(
          "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), roleId, rightId, seq],
        );
      }
    };

    const allNonWorkerRights = rights.map((r) => r[0]).filter((id) => !id.startsWith('act:coherence.worker.'));
    await addRoleRights(ids.roleNusearOwner, allNonWorkerRights);
    // Nusear Admin intentionally omits run/owner Coherence write rights (additive model; no negative withhold list!)
    await addRoleRights(ids.roleNusearAdmin, [
      'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
      'act:coherence.ledger.read', 'act:coherence.unpublished.read', 'act:coherence.runs.read',
      'act:coherence.inputs.read', 'act:coherence.decisions.read', 'act:coherence.checks.read',
      'act:coherence.journal.read', 'act:platform.audit_journal.read',
      'col:coherence.statement_cash', 'col:coherence.upline_cash', 'col:platform.audit_journal.nusear_actor',
    ]);
    await addRoleRights(ids.roleCoherenceOperator, [
      'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
      'act:coherence.ledger.read', 'act:coherence.unpublished.read', 'act:coherence.runs.read',
      'act:coherence.inputs.read', 'act:coherence.decisions.read', 'act:coherence.checks.read',
      'act:coherence.journal.read', 'act:platform.audit_journal.read',
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
      'act:coherence.runs.read', 'act:coherence.inputs.read', 'act:platform.audit_journal.read',
    ]);
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

    for (const [orgId, slug, name] of [
      [ids.rootOrg, 'nusear', 'Nusear'],
      [ids.acmeOrg, 'acme', 'Acme'],
      [ids.beaconOrg, 'beacon', 'Beacon'],
      [ids.eastTeamOrg, 'east_team', 'East Team'],
      [ids.harborOrg, 'harbor', 'Harbor'],
      [ids.northstarOrg, 'northstar', 'Northstar'],
    ]) {
      await c.query(
        `INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq)
         VALUES ($1,$2,$3,$4,'active',$5)`,
        [randomUUID(), orgId, slug, name, seq],
      );
    }

    // Tree: root -> acme -> beacon -> east_team; root -> acme -> harbor; root -> northstar
    for (const [child, parent] of [
      [ids.acmeOrg, ids.rootOrg],
      [ids.beaconOrg, ids.acmeOrg],
      [ids.eastTeamOrg, ids.beaconOrg],
      [ids.harborOrg, ids.acmeOrg],
      [ids.northstarOrg, ids.rootOrg],
    ]) {
      await c.query(
        `INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)`,
        [randomUUID(), child, parent, seq],
      );
    }

    for (const orgId of [ids.acmeOrg, ids.northstarOrg]) {
      for (const toolId of ['coherence', 'platform_audit']) {
        await c.query(
          `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq)
           VALUES ($1,$2,$3,'on','active',$4)`,
          [randomUUID(), orgId, toolId, seq],
        );
      }
    }

    const humanPeople = [
      [ids.nusearOwner, 'Pat Platform', 'pat.owner@nusear.example', null, 'active'],
      [ids.nusearAdminNoCoh, 'Drew Admin', 'drew.admin@nusear.example', null, 'active'],
      [ids.nusearOperator, 'Morgan Operator', 'morgan.op@nusear.example', null, 'active'],
      [ids.northstarOperator, 'Quinn Northstar', 'quinn.op@nusear.example', null, 'active'],
      [ids.acmeEntityMgr, 'Dana Entity', 'dana.em@acme.example', null, 'active'],
      [ids.acmeCompanyAdmin, 'Jamie Admin', 'jamie.admin@acme.example', null, 'active'],
      [ids.acmeInvestor, 'Avery Investor', 'avery.inv@acme.example', null, 'active'],
      [ids.beaconManager, 'Taylor Beacon', 'taylor.mgr@beacon.example', null, 'active'],
      [ids.leadManager, 'Casey Lead', 'casey.lead@beacon.example', null, 'active'],
      [ids.teamManager, 'Riley Team', 'riley.team@beacon.example', null, 'active'],
      [ids.multiAgencyPerson, 'Skylar Dual', 'skylar.dual@acme.example', null, 'active'],
      [ids.harborRetention, 'Jordan Retain', 'jordan.ret@harbor.example', null, 'active'],
      [ids.agentA, 'Sam Seller', 'sam.a@beacon.example', '11111111', 'active'],
      [ids.agentB, 'Sam Seller', 'sam.b@beacon.example', '22222222', 'active'],
      [ids.agentEast, 'East Producer', 'east.prod@beacon.example', '44444444', 'active'],
      [ids.agentHarbor, 'Robin Harbor', 'robin.h@harbor.example', '33333333', 'active'],
      [ids.suspendedAgent, 'Suspended Producer', 'susp@beacon.example', '55555555', 'suspended'],
    ];
    for (const [id, name, email, npn, status] of humanPeople) {
      await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [id, seq]);
      await c.query(
        `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, npn, status, journal_seq)
         VALUES ($1,$2,$3,$3,$4,$5,$6,$7)`,
        [randomUUID(), id, name, email, npn, status, seq],
      );
    }

    // Worker service principal
    await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'service',$2)", [ids.workerService, seq]);
    await c.query(
      `INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, status, journal_seq)
       VALUES ($1,$2,'Coherence Engine Worker','Coherence Engine Worker','active',$3)`,
      [randomUUID(), ids.workerService, seq],
    );

    // Memberships
    for (const [personId, orgId, cap] of [
      [ids.nusearOwner, ids.rootOrg, 'owner'],
      [ids.nusearAdminNoCoh, ids.rootOrg, 'employee'],
      [ids.nusearOperator, ids.rootOrg, 'employee'],
      [ids.northstarOperator, ids.rootOrg, 'employee'],
      [ids.workerService, ids.rootOrg, 'employee'],
      [ids.acmeEntityMgr, ids.acmeOrg, 'owner'],
      [ids.acmeCompanyAdmin, ids.acmeOrg, 'employee'],
      [ids.acmeInvestor, ids.acmeOrg, 'investor'],
      [ids.beaconManager, ids.beaconOrg, 'employee'],
      [ids.leadManager, ids.beaconOrg, 'employee'],
      [ids.teamManager, ids.beaconOrg, 'employee'],
      [ids.multiAgencyPerson, ids.acmeOrg, 'employee'],
      [ids.harborRetention, ids.harborOrg, 'employee'],
    ]) {
      await c.query(
        `INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,$4,'[2020-01-01,)'::daterange,'active',$5)`,
        [randomUUID(), personId, orgId, cap, seq],
      );
    }

    // Selling agent affiliations
    for (const [personId, npn, orgId, fileName] of [
      [ids.agentA, '11111111', ids.beaconOrg, 'Sam Seller A'],
      [ids.agentB, '22222222', ids.beaconOrg, 'Sam Seller B'],
      [ids.agentEast, '44444444', ids.eastTeamOrg, 'East Producer'],
      [ids.agentHarbor, '33333333', ids.harborOrg, 'Robin Harbor'],
      [ids.suspendedAgent, '55555555', ids.beaconOrg, 'Suspended Producer'],
    ]) {
      await c.query(
        `INSERT INTO iam.agent_affiliations (id, person_id, npn, agency_org_id, split_bps, agent_file_name, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,$4,8000,$5,'[2020-01-01,)'::daterange,'active',$6)`,
        [randomUUID(), personId, npn, orgId, fileName, seq],
      );
    }

    // Role grants
    const grants = [
      [ids.nusearOwner, ids.roleNusearOwner, ids.rootOrg, true, 'org_subtree'],
      [ids.nusearAdminNoCoh, ids.roleNusearAdmin, ids.rootOrg, true, 'org_subtree'],
      [ids.nusearOperator, ids.roleCoherenceOperator, ids.acmeOrg, true, 'org_subtree'],
      [ids.northstarOperator, ids.roleCoherenceOperator, ids.northstarOrg, true, 'org_subtree'],
      [ids.workerService, ids.roleWorkerService, ids.rootOrg, true, 'org_subtree'],
      [ids.acmeEntityMgr, ids.roleEntityManager, ids.acmeOrg, true, 'org_subtree'],
      [ids.acmeCompanyAdmin, ids.roleCompanyAdmin, ids.acmeOrg, true, 'org_subtree'],
      [ids.acmeInvestor, ids.roleInvestor, ids.acmeOrg, true, 'org_subtree'],
      [ids.beaconManager, ids.roleAgencyManager, ids.beaconOrg, true, 'org_subtree'],
      [ids.multiAgencyPerson, ids.roleAgencyManager, ids.beaconOrg, true, 'org_subtree'],
      [ids.multiAgencyPerson, ids.roleRetentionAgent, ids.harborOrg, true, 'org_subtree'],
      [ids.harborRetention, ids.roleRetentionAgent, ids.harborOrg, true, 'org_subtree'],
      [ids.agentA, ids.roleSellingAgent, ids.beaconOrg, false, 'self'],
      [ids.agentB, ids.roleSellingAgent, ids.beaconOrg, false, 'self'],
      [ids.agentEast, ids.roleSellingAgent, ids.eastTeamOrg, false, 'self'],
      [ids.agentHarbor, ids.roleSellingAgent, ids.harborOrg, false, 'self'],
      [ids.suspendedAgent, ids.roleSellingAgent, ids.beaconOrg, false, 'self'],
    ];
    for (const [personId, roleId, orgId, incDesc, pMode] of grants) {
      await c.query(
        `INSERT INTO iam.role_grants (
           id, person_id, role_id, organization_id, include_descendants,
           person_scope_mode, valid_range, status, journal_seq
         ) VALUES ($1,$2,$3,$4,$5,$6,'[2020-01-01,)'::daterange,'active',$7)`,
        [randomUUID(), personId, roleId, orgId, incDesc, pMode, seq],
      );
    }
  });

  const ownerToken = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.nusearOwner });
  const workerToken = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.workerService });
  const meta = ENV_BY_POOL.get(pool);
  if (meta) {
    meta.env.ownerToken = ownerToken;
    meta.env.workerToken = workerToken;
    if (meta.initCompany) {
      await meta.env.commands.initCompany({
        dbToken: ownerToken,
        commandKey: `init-009-${meta.suffix}`,
        slug: meta.env.companySlug,
        displayName: meta.env.displayName,
        defaultEmitMode: 'coherence',
      });
      const baseFile = await meta.env.dataStore.promoteBytes(Buffer.from('k,v\n1,2\n', 'utf8'), { relPath: 'Carrier/seed.csv', checksPassed: true });
      await meta.env.commands.publishInputVersion({
        dbToken: ownerToken,
        commandKey: `standing-seed-009-${meta.suffix}`,
        lineKind: 'standing',
        sourceKind: 'upload',
        reason: 'synthetic standing input root',
        entries: [{ relPath: 'Carrier/seed.csv', fileSha256: baseFile.sha256 }],
        storedFiles: [baseFile],
      });
    }
  }

  return { ids, keyId, secretBytes, environment, ownerToken, workerToken };
}

function buildMultiSubtreeEmitDataset(statementDate, { suffixTag = 'R1', entityAliasForEast = 'East Team' } = {}) {
  const bobRows = [
    {
      external_policy_id: `POL-101-${suffixTag}`, policy_id: '1', carrier_policy_number: 'C-101', crm_policy_number: 'CRM-101',
      enrollment_code: 'ENR-101', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Gold MA', simple_plan_type: 'MA',
      mbi: '1AB2-CD3-EF45', member: 'Pat Sample', dob: '1954-06-15', phone: '555-010-1001', email: 'pat@example.test',
      address: '100 Oak St', county: 'WAKE', state: 'NC',
      submission_date: '2026-09-10', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      min_date: '2026-09-10', anchor_date: '2026-09-10',
      amount: '80.00', upline_amount: '20.00', writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-BEACON', status: 'ACTIVE_PAYING', conflicts: '', spine_source: 'cbob_c', confidence_level: '100',
    },
    {
      external_policy_id: `POL-102-${suffixTag}`, policy_id: '2', carrier_policy_number: 'C-102', crm_policy_number: 'CRM-102',
      enrollment_code: 'ENR-102', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Silver MA', simple_plan_type: 'MA',
      mbi: '2CD3-EF4-GH56', member: 'Morgan Test', dob: '1957-09-20', phone: '555-010-1002', email: 'morgan@example.test',
      address: '200 Elm Ave', county: 'WAKE', state: 'NC',
      submission_date: '2026-09-12', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      min_date: '2026-09-12', anchor_date: '2026-09-12',
      amount: '120.00', upline_amount: '30.00', writing_npn: '22222222', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-BEACON', status: 'ACTIVE_PAYING', conflicts: '', spine_source: 'cbob_c', confidence_level: '100',
    },
    {
      external_policy_id: `POL-103-${suffixTag}`, policy_id: '3', carrier_policy_number: 'C-103', crm_policy_number: 'CRM-103',
      enrollment_code: 'ENR-103', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Bronze MA', simple_plan_type: 'MA',
      mbi: '4GH5-JK6-LM78', member: 'East Member', dob: '1958-03-11', phone: '555-010-1003', email: 'east@example.test',
      address: '400 Maple Dr', county: 'DURHAM', state: 'NC',
      submission_date: '2026-09-14', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      min_date: '2026-09-14', anchor_date: '2026-09-14',
      amount: '90.00', upline_amount: '10.00', writing_npn: '44444444', writing_agent: 'East Producer', entity: entityAliasForEast,
      agency_id: 'AG-EAST', status: 'ACTIVE_PAYING', conflicts: '', spine_source: 'cbob_c', confidence_level: '100',
    },
    {
      external_policy_id: `POL-201-${suffixTag}`, policy_id: '4', carrier_policy_number: 'C-201', crm_policy_number: 'CRM-201',
      enrollment_code: 'ENR-201', carrier: 'carrier_b', plan_type: 'PDP', plan_name: 'Basic PDP', simple_plan_type: 'PDP',
      mbi: '3EF4-GH5-JK67', member: 'Casey Mock', dob: '1960-01-05', phone: '555-010-2001', email: 'casey@example.test',
      address: '300 Pine Rd', county: 'MECKLENBURG', state: 'NC',
      submission_date: '2026-09-18', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      min_date: '2026-09-18', anchor_date: '2026-09-18',
      amount: '200.00', upline_amount: '50.00', writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor',
      agency_id: 'AG-HARBOR', status: 'ACTIVE_PAYING', conflicts: '', spine_source: 'cbob_c', confidence_level: '95',
    },
  ];

  const ledgerRows = [
    {
      record_id: `carrier_a~direct~PAT SAMPLE~100.00~${statementDate.slice(0, 7)}`, external_policy_id: `POL-101-${suffixTag}`, policy_id: '1', tx_id: '1',
      statement_name: 'carrier_a.csv', src_type: 'direct', carrier: 'carrier_a', mbi: '1AB2-CD3-EF45', member: 'Pat Sample',
      state: 'NC', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-10', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      earned_date: statementDate, payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-10',
      gross_comm: '100.00', revenue_type: 'commission', override_amount: '', commission_amount: '100.00', hra_amount: '', fee_amount: '', other_amount: '',
      downline_amount: '80.00', upline_amount: '20.00',
      writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon', payee_npn: '', agency_id: 'AG-BEACON',
      status: 'ACTIVE_PAYING', policy_status: 'active', cbob_c: 'true', cbob_s: 'false', sf: 'true', notes: '', coherent_notes: 'NEW',
    },
    {
      record_id: `carrier_a~direct~MORGAN TEST~150.00~${statementDate.slice(0, 7)}`, external_policy_id: `POL-102-${suffixTag}`, policy_id: '2', tx_id: '2',
      statement_name: 'carrier_a.csv', src_type: 'direct', carrier: 'carrier_a', mbi: '2CD3-EF4-GH56', member: 'Morgan Test',
      state: 'NC', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-12', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      earned_date: statementDate, payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-12',
      gross_comm: '150.00', revenue_type: 'commission', override_amount: '', commission_amount: '150.00', hra_amount: '', fee_amount: '', other_amount: '',
      downline_amount: '120.00', upline_amount: '30.00',
      writing_npn: '22222222', writing_agent: 'Sam Seller', entity: 'Beacon', payee_npn: '', agency_id: 'AG-BEACON',
      status: 'ACTIVE_PAYING', policy_status: 'active', cbob_c: 'true', cbob_s: 'false', sf: 'true', notes: '', coherent_notes: 'NEW',
    },
    {
      record_id: `carrier_a~direct~EAST MEMBER~100.00~${statementDate.slice(0, 7)}`, external_policy_id: `POL-103-${suffixTag}`, policy_id: '3', tx_id: '3',
      statement_name: 'carrier_a.csv', src_type: 'direct', carrier: 'carrier_a', mbi: '4GH5-JK6-LM78', member: 'East Member',
      state: 'NC', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-14', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      earned_date: statementDate, payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-14',
      gross_comm: '100.00', revenue_type: 'commission', override_amount: '', commission_amount: '100.00', hra_amount: '', fee_amount: '', other_amount: '',
      downline_amount: '90.00', upline_amount: '10.00',
      writing_npn: '44444444', writing_agent: 'East Producer', entity: entityAliasForEast, payee_npn: '', agency_id: 'AG-EAST',
      status: 'ACTIVE_PAYING', policy_status: 'active', cbob_c: 'true', cbob_s: 'false', sf: 'true', notes: '', coherent_notes: 'NEW',
    },
    {
      record_id: `carrier_b~direct~CASEY MOCK~250.00~${statementDate.slice(0, 7)}`, external_policy_id: `POL-201-${suffixTag}`, policy_id: '4', tx_id: '4',
      statement_name: 'carrier_b.csv', src_type: 'direct', carrier: 'carrier_b', mbi: '3EF4-GH5-JK67', member: 'Casey Mock',
      state: 'NC', plan_type: 'PDP', simple_plan_type: 'PDP',
      submission_date: '2026-09-18', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      earned_date: statementDate, payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-18',
      gross_comm: '250.00', revenue_type: 'commission', override_amount: '', commission_amount: '250.00', hra_amount: '', fee_amount: '', other_amount: '',
      downline_amount: '200.00', upline_amount: '50.00',
      writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor', payee_npn: '', agency_id: 'AG-HARBOR',
      status: 'ACTIVE_PAYING', policy_status: 'active', cbob_c: 'true', cbob_s: 'false', sf: 'false', notes: '', coherent_notes: 'NEW',
    },
    {
      record_id: `carrier_a~direct~HOUSE FEE~60.00~${statementDate.slice(0, 7)}`, external_policy_id: '', policy_id: '', tx_id: '5',
      statement_name: 'carrier_a.csv', src_type: 'direct', carrier: 'carrier_a', mbi: '', member: '',
      state: 'NC', plan_type: '', simple_plan_type: '',
      submission_date: '', origin_effective: '', effective_date: '', termination_date: '',
      earned_date: statementDate, payment_date: statementDate, statement_date: statementDate, min_date: statementDate,
      gross_comm: '60.00', revenue_type: 'fee', override_amount: '', commission_amount: '', hra_amount: '', fee_amount: '60.00', other_amount: '',
      downline_amount: '0.00', upline_amount: '60.00',
      writing_npn: '', writing_agent: '', entity: 'Acme', payee_npn: '', agency_id: 'AG-ACME',
      status: '', policy_status: '', cbob_c: 'false', cbob_s: 'false', sf: 'false', notes: 'house admin fee', coherent_notes: 'NEW',
    },
  ];

  const runStatementRows = ledgerRows.map((r) => ({
    ...r,
    run_action: 'NEW',
    run_statement_date: statementDate,
    reversal_of: '',
    reason: 'new',
  }));

  const workingTxCsv = [
    'tx_id,filename,sheet_name,source_position',
    '1,carrier_a.xlsx,Commissions,10',
    '2,carrier_a.xlsx,Commissions,11',
    '3,carrier_a.xlsx,Commissions,12',
    '4,carrier_b.xlsx,Detail,20',
    '5,carrier_a.xlsx,Fees,30',
  ].join('\n') + '\n';

  const emitMetadataJson = JSON.stringify({
    statementDate,
    build: '009test',
    corpusTail: statementDate.slice(0, 7),
    agencyStart: '2026-01-01',
    coherentStatus: { '1': 'ACTIVE_PAYING', '2': 'ACTIVE_PAYING', '3': 'ACTIVE_PAYING', '4': 'ACTIVE_PAYING' },
    coherentTrajectory: {
      '1': [[statementDate.slice(0, 7), 'ACTIVE_PAYING']],
      '2': [[statementDate.slice(0, 7), 'ACTIVE_PAYING']],
      '3': [[statementDate.slice(0, 7), 'ACTIVE_PAYING']],
      '4': [[statementDate.slice(0, 7), 'ACTIVE_PAYING']],
    },
  }, null, 2) + '\n';

  return {
    canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, bobRows),
    coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, ledgerRows),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, runStatementRows),
    workingTxCsv,
    emitMetadataJson,
  };
}

async function seedPublishedRun(env, { statementDate, keyPrefix, markSent = true, abandon = false, dataset = null } = {}) {
  const ds = dataset || buildMultiSubtreeEmitDataset(statementDate, { suffixTag: keyPrefix });
  const stamp = statementDate.replace(/-/g, '');
  const bobF = await env.dataStore.promoteBytes(Buffer.from(ds.canonicalBobCsv, 'utf8'), { relPath: 'emits/canonical_bob.csv', checksPassed: true });
  const ledF = await env.dataStore.promoteBytes(Buffer.from(ds.coherentLedgerCsv, 'utf8'), { relPath: 'emits/coherent_ledger.csv', checksPassed: true });
  const stmtF = await env.dataStore.promoteBytes(Buffer.from(ds.statementsCsv, 'utf8'), { relPath: `emits/statements_${stamp}.csv`, checksPassed: true });
  const metaF = await env.dataStore.promoteBytes(Buffer.from(ds.emitMetadataJson, 'utf8'), { relPath: 'emits/emit_metadata.json', checksPassed: true });
  const ovF = await env.dataStore.promoteBytes(Buffer.from('record_id,disposition,agent,agency,policy,book,month,status,note,committed_at,approved_amount,approved_agency,approved_agent,approved_agency_from,approved_agent_from\n', 'utf8'), { relPath: 'emits/overlay.csv', checksPassed: true });

  const emitEvId = randomUUID();
  const runId = randomUUID();
  const imp = await env.commands.importHistoricalRun({
    dbToken: env.ownerToken,
    commandKey: `${keyPrefix}-imp`,
    run: {
      id: runId,
      statementDate,
      folderNumber: 1,
      origin: 'company_import',
      emitMode: 'coherence',
      sourceFolder: `company-runs/${statementDate}-${keyPrefix}`,
    },
    inputVersion: { reason: `seed ${keyPrefix}` },
    inputEntries: [],
    stepAttempts: [
      {
        id: emitEvId,
        step: 'emit',
        attemptNo: 1,
        eventKind: 'finished',
        artifacts: [
          { relPath: 'emits/canonical_bob.csv', artifactKind: 'data', storeKind: 'company_data', fileSha256: bobF.sha256 },
          { relPath: 'emits/coherent_ledger.csv', artifactKind: 'data', storeKind: 'company_data', fileSha256: ledF.sha256 },
          { relPath: `emits/statements_${stamp}.csv`, artifactKind: 'data', storeKind: 'company_data', fileSha256: stmtF.sha256 },
          { relPath: 'emits/emit_metadata.json', artifactKind: 'data', storeKind: 'company_data', fileSha256: metaF.sha256 },
          { relPath: 'emits/overlay.csv', artifactKind: 'data', storeKind: 'company_data', fileSha256: ovF.sha256 },
        ],
      },
    ],
    storedFiles: [bobF, ledF, stmtF, metaF, ovF],
    abandonment: abandon ? { typedPhrase: `abandon ${statementDate}`, reason: 'abandoned synthetic run' } : null,
  });

  const emitEvRes = await env.pool.query(
    `SELECT id FROM coherence.step_attempt_events
     WHERE run_id = $1::uuid AND step = 'emit' AND event_kind = 'finished'
     ORDER BY attempt_no DESC LIMIT 1`,
    [imp.result.runId],
  );
  const actualEmitEvId = emitEvRes.rows[0].id;

  await env.commands.materializeEmit({
    dbToken: env.workerToken,
    commandKey: `${keyPrefix}-mat`,
    runId: imp.result.runId,
    attemptEventId: actualEmitEvId,
    statementDate,
    canonicalBobCsv: ds.canonicalBobCsv,
    coherentLedgerCsv: ds.coherentLedgerCsv,
    statementsCsv: ds.statementsCsv,
    emitMetadataJson: ds.emitMetadataJson,
    workingTxCsv: ds.workingTxCsv,
    statementsFileSha256: stmtF.sha256,
  });

  if (markSent && !abandon) {
    await env.commands.carrySent({
      dbToken: env.ownerToken,
      commandKey: `${keyPrefix}-sent`,
      runId: imp.result.runId,
      typedPhrase: `sent ${statementDate}`,
    });
  }

  return { runId: imp.result.runId, emitEvId: actualEmitEvId, statementDate };
}

test('Layer 7B [Base-Table Lockdown & Catalog Audit]: platform_app gets SQLSTATE 42501 on every Coherence base table, coherence_views, and worker/internal functions; updated catalog audit passes and catches deliberate mutations', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  // 1. Dynamically discover EVERY base table across coherence, iam, iam_secret, platform
  const tblRes = await env.pool.query(
    `SELECT table_schema, table_name
     FROM information_schema.tables
     WHERE table_schema IN ('coherence', 'iam', 'iam_secret', 'platform')
       AND table_type = 'BASE TABLE'
     ORDER BY table_schema, table_name`,
  );
  const cohTables = tblRes.rows.filter((r) => r.table_schema === 'coherence');
  assert.ok(cohTables.length >= 33, `expected >= 33 coherence base tables, got ${cohTables.length}`);

  for (const row of tblRes.rows) {
    const fq = `"${row.table_schema}"."${row.table_name}"`;
    const colRes = await env.pool.query(
      `SELECT column_name
       FROM information_schema.columns
       WHERE table_schema = $1 AND table_name = $2 AND is_generated = 'NEVER'
       ORDER BY ordinal_position
       LIMIT 1`,
      [row.table_schema, row.table_name],
    );
    const firstCol = `"${colRes.rows[0].column_name}"`;
    for (const [label, sql] of [
      ['SELECT', `SELECT * FROM ${fq} LIMIT 1`],
      ['INSERT', `INSERT INTO ${fq} DEFAULT VALUES`],
      ['UPDATE', `UPDATE ${fq} SET ${firstCol} = ${firstCol} WHERE false`],
      ['DELETE', `DELETE FROM ${fq} WHERE false`],
      ['TRUNCATE', `TRUNCATE ${fq}`],
      ['LOCK', `LOCK TABLE ${fq} IN EXCLUSIVE MODE`],
    ]) {
      await assert.rejects(
        () => runAsPlatformApp(env.pool, { readOnly: false }, (c) => c.query(sql)),
        (err) => err?.code === '42501',
        `platform_app must get SQLSTATE 42501 on ${label} ${fq}`,
      );
    }
  }

  // 2. Retired schema coherence_views must not exist, and every coherence.* view must refuse platform_app with 42501.
  const viewsSchema = await env.pool.query(
    "SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname = 'coherence_views'",
  );
  assert.equal(viewsSchema.rows.length, 0, 'retired schema coherence_views must not exist');

  const internalViews = await env.pool.query(
    `SELECT table_schema, table_name
     FROM information_schema.views
     WHERE table_schema = 'coherence'
     ORDER BY table_schema, table_name`,
  );
  assert.ok(internalViews.rows.length >= 2);
  for (const v of internalViews.rows) {
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { readOnly: true }, (c) => c.query(`SELECT * FROM "${v.table_schema}"."${v.table_name}" LIMIT 1`)),
      (err) => err?.code === '42501',
      `platform_app must get 42501 on internal view ${v.table_schema}.${v.table_name}`,
    );
  }

  // 2b. Every internal app_views._read_* helper refuses platform_worker and platform_writer with 42501,
  //     while platform_readonly keeps EXECUTE (like platform_app) so SELECT on app_views.* works.
  const readHelpers = (await env.pool.query(
    `SELECT p.proname, pg_catalog.oidvectortypes(p.proargtypes) AS arg_types
     FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'app_views' AND p.proname LIKE '\\_read\\_%' ESCAPE '\\'
     ORDER BY p.proname`,
  )).rows;
  assert.ok(readHelpers.length >= 20, `expected >= 20 app_views._read_* helpers, got ${readHelpers.length}`);
  const sampleArgsFor = (argTypes) => {
    if (!argTypes) return '';
    return argTypes.split(',').map((t) => {
      const tt = t.trim();
      if (tt === 'text') return "'act:coherence.runs.read'";
      if (tt === 'boolean') return 'false';
      if (tt === 'uuid') return `'${randomUUID()}'::uuid`;
      return 'NULL';
    }).join(', ');
  };
  for (const h of readHelpers) {
    const callSql = `SELECT app_views.${h.proname}(${sampleArgsFor(h.arg_types)})`;
    for (const roleName of ['platform_worker', 'platform_writer']) {
      await assert.rejects(
        () => runAsRole(env.pool, roleName, { readOnly: true }, (c) => c.query(callSql)),
        (err) => err?.code === '42501',
        `${roleName} must get 42501 on internal helper app_views.${h.proname}`,
      );
    }
  }
  for (const viewName of ['coherence_bob', 'coherence_runs']) {
    const res = await runAsRole(env.pool, 'platform_readonly', { readOnly: true }, (c) => (
      c.query(`SELECT COUNT(*)::int AS n FROM app_views.${viewName}`)
    ));
    assert.equal(res.rows[0].n, 0, `platform_readonly smoke SELECT on app_views.${viewName} without token must succeed with 0 rows`);
  }

  // 3. Backfill function and worker-only app_cmd functions must refuse platform_app with 42501
  for (const sql of [
    'SELECT * FROM coherence.backfill_iam_foreign_keys()',
    `SELECT app_cmd.coherence_start_attempt('k', '${'a'.repeat(64)}', '${randomUUID()}'::uuid, 'assign', '${randomUUID()}'::uuid)`,
    `SELECT app_cmd.coherence_reject_review_submission('${randomUUID()}'::uuid)`,
  ]) {
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { readOnly: false, serializable: true }, (c) => c.query(sql)),
      (err) => err?.code === '42501',
      `platform_app must get 42501 on forbidden function: ${sql}`,
    );
  }

  // 4. Updated live IAM + Coherence catalog audit passes
  const audit = await withClusterCatalogLock(() => policyChecks.verifyIamConfigInvariants(env.pool));
  assert.equal(audit.passed, true, `verifyIamConfigInvariants failed:\n${audit.problems.join('\n')}`);
  assert.ok(audit.checkedAppViews >= 15, `expected >= 15 app_views views, got ${audit.checkedAppViews}`);
  assert.ok(audit.checkedAppCmdFunctions >= 31, `expected >= 31 app_cmd functions, got ${audit.checkedAppCmdFunctions}`);

  // 5. Deliberate-breakage mutation checks prove catalog audit is non-vacuous
  await t.test('Mutation: granting SELECT on a coherence base table to platform_app fails audit', async () => {
    await env.pool.query('GRANT SELECT ON coherence.bob_policies TO platform_app');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /coherence\.bob_policies/i.test(p) && /platform_app/i.test(p)));
    } finally {
      await env.pool.query('REVOKE SELECT ON coherence.bob_policies FROM platform_app');
    }
  });

  await t.test('Mutation: removing security_barrier from an app_views view fails audit', async () => {
    await env.pool.query('ALTER VIEW app_views.coherence_bob SET (security_barrier = false)');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /coherence_bob/i.test(p) && /security_barrier/i.test(p)));
    } finally {
      await env.pool.query('ALTER VIEW app_views.coherence_bob SET (security_barrier = true)');
    }
  });

  await t.test('Mutation: granting EXECUTE on worker-only app_cmd function to platform_app fails audit', async () => {
    await env.pool.query('GRANT EXECUTE ON FUNCTION app_cmd.coherence_reject_review_submission(uuid, text, text) TO platform_app');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /coherence_reject_review_submission/i.test(p) && /platform_app/i.test(p)));
    } finally {
      await env.pool.query('REVOKE EXECUTE ON FUNCTION app_cmd.coherence_reject_review_submission(uuid, text, text) FROM platform_app');
    }
  });

  await t.test('Mutation: dropping platform_view_owner RLS policy on coherence.bob_policies fails audit', async () => {
    const defRes = await env.pool.query(
      "SELECT qual FROM pg_catalog.pg_policies WHERE schemaname = 'coherence' AND tablename = 'bob_policies' AND policyname = 'bob_policies_iam_read'",
    );
    assert.equal(defRes.rows.length, 1);
    const qual = defRes.rows[0].qual;
    await env.pool.query('DROP POLICY bob_policies_iam_read ON coherence.bob_policies');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /bob_policies/i.test(p) && /platform_view_owner|policy/i.test(p)));
    } finally {
      await env.pool.query(`CREATE POLICY bob_policies_iam_read ON coherence.bob_policies FOR SELECT TO platform_view_owner USING (${qual})`);
    }
  });

  await t.test('Mutation: placing a copied base table in app_views fails audit', async () => {
    await env.pool.query('CREATE TABLE app_views._copied_table_probe (id integer)');
    await env.pool.query('REVOKE ALL ON app_views._copied_table_probe FROM PUBLIC');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /_copied_table_probe/i.test(p)));
    } finally {
      await env.pool.query('DROP TABLE IF EXISTS app_views._copied_table_probe');
    }
  });

  await t.test('Mutation: changing owner of an app_views view away from platform_view_owner fails audit', async () => {
    await env.pool.query('ALTER VIEW app_views.coherence_bob OWNER TO platform_migrator');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /coherence_bob/i.test(p) && /platform_view_owner/i.test(p)));
    } finally {
      await env.pool.query('ALTER VIEW app_views.coherence_bob OWNER TO platform_view_owner');
    }
  });

  await t.test('Mutation: granting CREATE on app_views or app_cmd to platform_app fails audit', async () => {
    for (const schema of ['app_views', 'app_cmd']) {
      await env.pool.query(`GRANT CREATE ON SCHEMA ${schema} TO platform_app`);
      try {
        const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
        assert.equal(bad.passed, false);
        assert.ok(bad.problems.some((p) => p.includes('platform_app') && /CREATE/i.test(p) && p.includes(schema)));
      } finally {
        await env.pool.query(`REVOKE CREATE ON SCHEMA ${schema} FROM platform_app`);
      }
    }
  });
});

test('Layer 7B [Foreign Keys & Strict Refusal Backfill]: backfill maps entity and writing_npn cleanly, refuses any unmapped or ambiguous row atomically without guessing, is idempotent, and preserves one-time immutability', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids } = await seedCoherenceIamWorld(env.pool);

  // First confirm live token-based materializeEmit refuses an unmapped entity ("Legacy East Unit") immediately at write time (Item 5).
  const dsAlias = buildMultiSubtreeEmitDataset('2026-10-31', { suffixTag: 'BF', entityAliasForEast: 'Legacy East Unit' });
  await assert.rejects(
    () => seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'bf-live-refuse', markSent: false, dataset: dsAlias }),
    /UNMAPPED_ENTITY/i,
    'live materializeEmit must refuse unmapped entity immediately inside PostgreSQL',
  );

  // Simulate a pre-009 database whose legacy financial rows have NULL organization_id / writing_person_id
  // (using superuser direct SQL insert of a single legacy batch & materialization) so we can thoroughly
  // test coherence.backfill_iam_foreign_keys() across all 5 tables.
  const insertLegacyNullBatch = async ({ commandKey, statementDate, agencyLines = [], uplineLines = [], runMat = null }) => {
    await inSerializableTx(env.pool, async (c) => {
      const batchId = randomUUID();
      await c.query('ALTER TABLE coherence.journal_entries DISABLE TRIGGER trg_journal_verify_commitments');
      await c.query('ALTER TABLE coherence.statement_batches DISABLE TRIGGER USER');
      await c.query('ALTER TABLE coherence.statement_agency_lines DISABLE TRIGGER USER');
      await c.query('ALTER TABLE coherence.statement_upline_lines DISABLE TRIGGER USER');
      await c.query('ALTER TABLE coherence.run_materializations DISABLE TRIGGER USER');
      await c.query('ALTER TABLE coherence.bob_policies DISABLE TRIGGER USER');
      await c.query('ALTER TABLE coherence.bob_policy_financials DISABLE TRIGGER USER');
      await c.query('ALTER TABLE coherence.coherent_ledger_rows DISABLE TRIGGER USER');
      const seq = (await c.query(
        `INSERT INTO coherence.journal_entries (actor, acting_for, command_kind, command_key, request_sha256, body)
         VALUES ('pre-009-legacy', NULL, 'record_statement_batch', $1, $2, '{"commitments":{"counts":{},"hashes":{}}}'::jsonb)
         RETURNING seq`,
        [commandKey, sha256Hex(commandKey)],
      )).rows[0].seq;
      const agNet = agencyLines.reduce((acc, r) => acc + Number(r.amount), 0).toFixed(2);
      const upNet = uplineLines.reduce((acc, r) => acc + Number(r.amount), 0).toFixed(2);
      await c.query(
        `INSERT INTO coherence.statement_batches (
           id, batch_kind, statement_date, run_id, attempt_event_id, reason,
           agency_line_count, agency_lines_sha256, agency_net_total,
           upline_line_count, upline_lines_sha256, upline_net_total, journal_seq
         ) VALUES ($1,$2,$3::date,$4,$5,'pre-009 legacy',$6,$7,$8::numeric,$9,$10,$11::numeric,$12)`,
        [batchId, runMat ? 'run_emission' : 'historical_sent', statementDate, runMat?.runId ?? null, runMat?.emitEvId ?? null,
          agencyLines.length, sha256Hex('ag'), agNet, uplineLines.length, sha256Hex('up'), upNet, seq],
      );
      for (let i = 0; i < agencyLines.length; i++) {
        const r = agencyLines[i];
        await c.query(
          `INSERT INTO coherence.statement_agency_lines (
             batch_id, line_no, statement_date, entry_kind, run_action, entity,
             organization_id, writing_npn, writing_person_id, writing_agent,
             record_id, source_file, source_row_no, gross_comm, amount, journal_seq
           ) VALUES ($1,$2,$3::date,$4,'NEW',$5,NULL,$6,NULL,$7,$8,$9,$10,$11::numeric,$12::numeric,$13)`,
          [batchId, i + 1, statementDate, runMat ? 'run_emission' : 'historical_sent', r.entity, r.writingNpn ?? null, r.writingAgent ?? null,
            r.recordId, r.sourceFile || 'legacy.csv', r.sourceRowNo || (i + 1), r.grossComm, r.amount, seq],
        );
      }
      for (let i = 0; i < uplineLines.length; i++) {
        const r = uplineLines[i];
        await c.query(
          `INSERT INTO coherence.statement_upline_lines (
             batch_id, line_no, statement_date, entry_kind, run_action, source_entity, marked_sent,
             organization_id, writing_npn, writing_person_id, writing_agent,
             record_id, source_file, source_row_no, gross_comm, amount, journal_seq
           ) VALUES ($1,$2,$3::date,$4,'NEW',$5,true,NULL,$6,NULL,$7,$8,$9,$10,$11::numeric,$12::numeric,$13)`,
          [batchId, i + 1, statementDate, runMat ? 'run_emission' : 'historical_sent', r.sourceEntity, r.writingNpn ?? null, r.writingAgent ?? null,
            r.recordId, r.sourceFile || 'legacy.csv', r.sourceRowNo || (i + 1), r.grossComm, r.amount, seq],
        );
      }
      if (runMat) {
        await c.query(
          `INSERT INTO coherence.run_materializations (
             attempt_event_id, run_id, statement_date, reconciliation_mode,
             bob_row_count, bob_rows_sha256, bob_downline_total, bob_upline_total,
             ledger_row_count, ledger_rows_sha256, ledger_gross_total, ledger_downline_total, ledger_upline_total,
             statement_batch_id, journal_seq
           ) VALUES ($1,$2,$3::date,'strict_entity_ledger',$4,$5,490.00,140.00,$6,$7,630.00,490.00,140.00,$8,$9)`,
          [runMat.emitEvId, runMat.runId, statementDate, runMat.bobRows.length, sha256Hex('bob'), runMat.ledgerRows.length, sha256Hex('led'), batchId, seq],
        );
        for (const b of runMat.bobRows) {
          await c.query(
            `INSERT INTO coherence.bob_policies (
               attempt_event_id, policy_id, run_id, writing_npn, writing_agent, entity,
               organization_id, writing_person_id, status, journal_seq
             ) VALUES ($1,$2,$3,$4,$5,$6,NULL,NULL,'ACTIVE_PAYING',$7)`,
            [runMat.emitEvId, b.policyId, runMat.runId, b.writingNpn, b.writingAgent, b.entity, seq],
          );
          await c.query(
            `INSERT INTO coherence.bob_policy_financials (
               attempt_event_id, policy_id, entity, writing_npn, organization_id, writing_person_id,
               amount, upline_amount, journal_seq
             ) VALUES ($1,$2,$3,$4,NULL,NULL,$5::numeric,$6::numeric,$7)`,
            [runMat.emitEvId, b.policyId, b.entity, b.writingNpn, b.amount, b.uplineAmount, seq],
          );
        }
        for (const l of runMat.ledgerRows) {
          await c.query(
            `INSERT INTO coherence.coherent_ledger_rows (
               attempt_event_id, tx_id, run_id, record_id, policy_id, src_type,
               gross_comm, commission_amount, downline_amount, upline_amount, writing_npn, writing_agent, entity,
               cbob_c, cbob_s, sf, organization_id, writing_person_id, journal_seq
             ) VALUES ($1,$2,$3,$4,$5,'direct',$6::numeric,$6::numeric,$7::numeric,$8::numeric,$9,$10,$11,true,false,true,NULL,NULL,$12)`,
            [runMat.emitEvId, l.txId, runMat.runId, l.recordId, l.policyId, l.grossComm, l.downlineAmount, l.uplineAmount, l.writingNpn, l.writingAgent, l.entity, seq],
          );
        }
      }
      await c.query('ALTER TABLE coherence.journal_entries ENABLE TRIGGER trg_journal_verify_commitments');
      await c.query('ALTER TABLE coherence.statement_batches ENABLE TRIGGER USER');
      await c.query('ALTER TABLE coherence.statement_agency_lines ENABLE TRIGGER USER');
      await c.query('ALTER TABLE coherence.statement_upline_lines ENABLE TRIGGER USER');
      await c.query('ALTER TABLE coherence.run_materializations ENABLE TRIGGER USER');
      await c.query('ALTER TABLE coherence.bob_policies ENABLE TRIGGER USER');
      await c.query('ALTER TABLE coherence.bob_policy_financials ENABLE TRIGGER USER');
      await c.query('ALTER TABLE coherence.coherent_ledger_rows ENABLE TRIGGER USER');
    });
  };

  // Import a bare Emit run shell (without materialization), then seed pre-009 NULL-FK materialized rows for it.
  const bfRunImp = await env.commands.importHistoricalRun({
    dbToken: env.ownerToken,
    commandKey: 'bf-r1-shell',
    run: { statementDate: '2026-10-31', folderNumber: 1, origin: 'company_import', emitMode: 'coherence', sourceFolder: 'company-runs/2026-10-31-bf-shell' },
    inputVersion: { reason: 'pre-009 backfill shell' },
    inputEntries: [],
    stepAttempts: [{ step: 'emit', attemptNo: 1, eventKind: 'finished', artifacts: [] }],
    storedFiles: [],
  });
  const bfRunId = bfRunImp.result.runId;
  const bfEmitEvId = (await env.pool.query("SELECT id FROM coherence.step_attempt_events WHERE run_id = $1::uuid AND step = 'emit' AND event_kind = 'finished' LIMIT 1", [bfRunId])).rows[0].id;
  await insertLegacyNullBatch({
    commandKey: 'bf-pre009-mat',
    statementDate: '2026-10-31',
    agencyLines: [
      { entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller', recordId: 'bf-r1', grossComm: '100.00', amount: '80.00' },
      { entity: 'Beacon', writingNpn: '22222222', writingAgent: 'Sam Seller', recordId: 'bf-r2', grossComm: '150.00', amount: '120.00' },
      { entity: 'Legacy East Unit', writingNpn: '44444444', writingAgent: 'Jamie East', recordId: 'bf-r3', grossComm: '100.00', amount: '90.00' },
      { entity: 'Harbor', writingNpn: '33333333', writingAgent: 'Robin Harbor', recordId: 'bf-r4', grossComm: '250.00', amount: '200.00' },
    ],
    uplineLines: [
      { sourceEntity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller', recordId: 'bf-r1', grossComm: '100.00', amount: '20.00' },
      { sourceEntity: 'Legacy East Unit', writingNpn: '44444444', writingAgent: 'Jamie East', recordId: 'bf-r3', grossComm: '100.00', amount: '10.00' },
      { sourceEntity: 'Acme', writingNpn: null, writingAgent: null, recordId: 'bf-house', grossComm: '30.00', amount: '30.00' },
    ],
    runMat: {
      runId: bfRunId,
      emitEvId: bfEmitEvId,
      bobRows: [
        { policyId: 1, entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller', amount: '80.00', uplineAmount: '20.00' },
        { policyId: 2, entity: 'Beacon', writingNpn: '22222222', writingAgent: 'Sam Seller', amount: '120.00', uplineAmount: '30.00' },
        { policyId: 3, entity: 'Legacy East Unit', writingNpn: '44444444', writingAgent: 'Jamie East', amount: '90.00', uplineAmount: '10.00' },
        { policyId: 4, entity: 'Harbor', writingNpn: '33333333', writingAgent: 'Robin Harbor', amount: '200.00', uplineAmount: '50.00' },
      ],
      ledgerRows: [
        { txId: 1, recordId: 'bf-r1', policyId: 1, entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller', grossComm: '100.00', downlineAmount: '80.00', uplineAmount: '20.00' },
        { txId: 2, recordId: 'bf-r2', policyId: 2, entity: 'Beacon', writingNpn: '22222222', writingAgent: 'Sam Seller', grossComm: '150.00', downlineAmount: '120.00', uplineAmount: '30.00' },
        { txId: 3, recordId: 'bf-r3', policyId: 3, entity: 'Legacy East Unit', writingNpn: '44444444', writingAgent: 'Jamie East', grossComm: '100.00', downlineAmount: '90.00', uplineAmount: '10.00' },
        { txId: 4, recordId: 'bf-r4', policyId: 4, entity: 'Harbor', writingNpn: '33333333', writingAgent: 'Robin Harbor', grossComm: '250.00', downlineAmount: '200.00', uplineAmount: '50.00' },
        { txId: 5, recordId: 'bf-house', policyId: 1, entity: 'Acme', writingNpn: null, writingAgent: null, grossComm: '30.00', downlineAmount: '0.00', uplineAmount: '30.00' },
      ],
    },
  });

  // Before backfill: all 5 tables have NULL organization_id and writing_person_id
  for (const tbl of ['bob_policies', 'bob_policy_financials', 'statement_agency_lines', 'statement_upline_lines', 'coherent_ledger_rows']) {
    const r = (await env.pool.query(`SELECT COUNT(*) FILTER (WHERE organization_id IS NOT NULL)::int AS mapped FROM coherence.${tbl}`)).rows[0];
    assert.equal(r.mapped, 0, `expected 0 mapped rows before backfill on ${tbl}`);
  }

  // 1. Without p_entity_map, "Legacy East Unit" MUST be refused (never guessed) and leave 0 rows updated across ALL 5 tables
  await assert.rejects(
    () => env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys()'),
    (err) => /UNMAPPED_ENTITY/i.test(err.message),
    'backfill must refuse unmapped entity without guessing',
  );
  for (const tbl of ['bob_policies', 'bob_policy_financials', 'statement_agency_lines', 'statement_upline_lines', 'coherent_ledger_rows']) {
    const r = (await env.pool.query(`SELECT COUNT(*) FILTER (WHERE organization_id IS NOT NULL)::int AS mapped FROM coherence.${tbl}`)).rows[0];
    assert.equal(r.mapped, 0, `failed backfill must roll back atomically on ${tbl}`);
  }

  // 2. Invalid UUID or unknown org UUID in p_entity_map MUST be refused
  await assert.rejects(
    () => env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys($1::jsonb)', [JSON.stringify({ 'Legacy East Unit': randomUUID() })]),
    /iam\.organizations|invalid|unknown/i,
  );
  await assert.rejects(
    () => env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys($1::jsonb)', [JSON.stringify({ 'Legacy East Unit': 'not-a-uuid' })]),
    /invalid|uuid/i,
  );

  // 3. Explicit p_entity_map succeeds cleanly as platform_migrator and maps all 5 tables accurately
  const entityMap = { 'Legacy East Unit': ids.eastTeamOrg };
  const bfRes = await runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
    c.query('SELECT table_name, rows_updated::int, rows_already_mapped::int FROM coherence.backfill_iam_foreign_keys($1::jsonb) ORDER BY table_name', [JSON.stringify(entityMap)])
  ));
  assert.equal(bfRes.rows.length, 5);
  for (const row of bfRes.rows) {
    assert.ok(row.rows_updated > 0, `expected > 0 rows updated for ${row.table_name}`);
    assert.equal(row.rows_already_mapped, 0);
  }

  // Verify exact org and person bindings (including house line with writing_npn NULL -> writing_person_id NULL)
  const bpCheck = (await env.pool.query(
    'SELECT policy_id, entity, organization_id, writing_npn, writing_person_id FROM coherence.bob_policies ORDER BY policy_id',
  )).rows;
  assert.equal(bpCheck[0].organization_id, ids.beaconOrg);
  assert.equal(bpCheck[0].writing_person_id, ids.agentA);
  assert.equal(bpCheck[1].organization_id, ids.beaconOrg);
  assert.equal(bpCheck[1].writing_person_id, ids.agentB);
  assert.equal(bpCheck[2].organization_id, ids.eastTeamOrg);
  assert.equal(bpCheck[2].writing_person_id, ids.agentEast);
  assert.equal(bpCheck[3].organization_id, ids.harborOrg);
  assert.equal(bpCheck[3].writing_person_id, ids.agentHarbor);

  const houseRow = (await env.pool.query(
    "SELECT organization_id, writing_npn, writing_person_id FROM coherence.coherent_ledger_rows WHERE entity = 'Acme'",
  )).rows[0];
  assert.equal(houseRow.organization_id, ids.acmeOrg);
  assert.equal(houseRow.writing_npn, null);
  assert.equal(houseRow.writing_person_id, null);

  // 4. Re-running backfill is idempotent (0 updated, all already mapped)
  const bfAgain = await runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
    c.query('SELECT table_name, rows_updated::int, rows_already_mapped::int FROM coherence.backfill_iam_foreign_keys($1::jsonb) ORDER BY table_name', [JSON.stringify(entityMap)])
  ));
  for (const row of bfAgain.rows) {
    assert.equal(row.rows_updated, 0);
    assert.ok(row.rows_already_mapped > 0);
  }

  // 5. Unmapped writing_npn on a pre-009 legacy batch MUST be refused atomically by backfill
  await insertLegacyNullBatch({
    commandKey: 'unmapped-npn-batch',
    statementDate: '2026-09-30',
    agencyLines: [{
      entity: 'Beacon', writingNpn: '99999999', writingAgent: 'Ghost Agent',
      recordId: 'carrier_a~direct~GHOST~10.00~2026-09', sourceFile: 'hist.csv', sourceRowNo: 1,
      grossComm: '10.00', amount: '10.00',
    }],
  });
  await assert.rejects(
    () => env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys($1::jsonb)', [JSON.stringify(entityMap)]),
    /UNMAPPED_WRITING_NPN/i,
    'backfill must refuse unmapped writing_npn without guessing',
  );

  // Explicit p_npn_map maps a non-standard/house NPN marker cleanly without guessing
  const housePersonId = randomUUID();
  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { commandKind: 'iam.seed_house', commandKey: 'seed-house-acct' });
    await c.query("INSERT INTO iam.people (id, person_kind, house_org_id, journal_seq) VALUES ($1,'house_account',$2,$3)", [housePersonId, ids.beaconOrg, j.seq]);
    await c.query("INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, status, journal_seq) VALUES ($1,$2,'Beacon House','Beacon House','active',$3)", [randomUUID(), housePersonId, j.seq]);
  });
  const bfNpnMap = await runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
    c.query(
      'SELECT table_name, rows_updated::int FROM coherence.backfill_iam_foreign_keys($1::jsonb, $2::jsonb) WHERE table_name = $3',
      [JSON.stringify(entityMap), JSON.stringify({ '99999999': housePersonId }), 'statement_agency_lines'],
    )
  ));
  assert.equal(bfNpnMap.rows[0].rows_updated, 1);

  // Ambiguous entity (two distinct orgs matching 'dup_entity' inside Acme's tree) MUST refuse without guessing
  const dupOrgA = randomUUID();
  const dupOrgB = randomUUID();
  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { commandKind: 'iam.seed_ambig', commandKey: 'seed-ambig-org' });
    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'agency',$3),($2,'agency',$3)", [dupOrgA, dupOrgB, j.seq]);
    await c.query("INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'dup_entity','Alpha Unit','active',$3),($4,$5,'other_slug','dup_entity','active',$3)", [randomUUID(), dupOrgA, j.seq, randomUUID(), dupOrgB]);
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4),($5,$6,$3,'[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), dupOrgA, ids.acmeOrg, j.seq, randomUUID(), dupOrgB],
    );
  });
  await insertLegacyNullBatch({
    commandKey: 'ambig-entity-batch',
    statementDate: '2026-09-29',
    agencyLines: [{
      entity: 'dup_entity', writingNpn: null, writingAgent: null,
      recordId: 'carrier_a~direct~DUP~5.00~2026-09', sourceFile: 'hist2.csv', sourceRowNo: 1,
      grossComm: '5.00', amount: '5.00',
    }],
  });
  await assert.rejects(
    () => env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys($1::jsonb)', [JSON.stringify(entityMap)]),
    /AMBIGUOUS_ENTITY/i,
    'backfill must refuse ambiguous entity without guessing',
  );

  // Blank non-NULL writing_npn ('   ') MUST refuse without guessing
  await insertLegacyNullBatch({
    commandKey: 'blank-npn-batch',
    statementDate: '2026-09-28',
    agencyLines: [{
      entity: 'Beacon', writingNpn: '   ', writingAgent: 'Blank',
      recordId: 'carrier_a~direct~BLANK~5.00~2026-09', sourceFile: 'hist3.csv', sourceRowNo: 1,
      grossComm: '5.00', amount: '5.00',
    }],
  });
  await assert.rejects(
    () => env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys($1::jsonb)', [JSON.stringify({ ...entityMap, dup_entity: dupOrgA })]),
    /MALFORMED_WRITING_NPN/i,
    'backfill must refuse blank non-NULL writing_npn',
  );

  // 6. Immutability: even platform_versioner CANNOT re-stamp an already-populated organization_id or modify any business column
  await assert.rejects(
    () => runAsRole(env.pool, 'platform_versioner', { readOnly: false }, (c) => (
      c.query('UPDATE coherence.bob_policies SET organization_id = $1::uuid WHERE policy_id = 1', [ids.harborOrg])
    )),
    (err) => err?.code === '55000',
    'platform_versioner must not overwrite already-populated organization_id',
  );
  await assert.rejects(
    () => env.pool.query('UPDATE coherence.bob_policies SET entity = entity WHERE false'),
    (err) => err?.code === '55000' && /immutable/i.test(err.message),
    'ordinary UPDATE on bob_policies must still fail with 55000 immutable',
  );
});

test('Layer 7B [Fail-Closed Tokens]: unset, blank, malformed, 1-bit tampered, expired, wrong-environment, and suspended tokens return 0 rows on every app_views.* and 42501 on app_cmd.*', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'tok-r1', markSent: true });
  await env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys()');

  const validOwnerTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.nusearOwner });
  const flippedLast = validOwnerTok.slice(0, -1) + (validOwnerTok.endsWith('0') ? '1' : '0');
  const expiredTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.nusearOwner, expEpoch: Math.floor(Date.now() / 1000) - 30 });
  const wrongEnvTok = mintSignedToken({ keyId, secretBytes, environment: 'prod', actorPersonId: ids.nusearOwner });
  const suspendedTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.suspendedAgent });

  const viewsRes = await env.pool.query(
    "SELECT table_name FROM information_schema.views WHERE table_schema = 'app_views' ORDER BY table_name",
  );
  assert.ok(viewsRes.rows.length >= 15);

  const badTokens = [
    ['unset', null],
    ['blank', '   '],
    ['malformed', 'not|a|valid|token'],
    ['tampered_sig', flippedLast],
    ['expired', expiredTok],
    ['wrong_env', wrongEnvTok],
    ['suspended', suspendedTok],
  ];

  for (const [label, tok] of badTokens) {
    for (const v of viewsRes.rows) {
      const cnt = await runAsPlatformApp(env.pool, { token: tok, readOnly: true }, async (c) => (
        (await c.query(`SELECT COUNT(*)::int AS n FROM app_views."${v.table_name}"`)).rows[0].n
      ));
      assert.equal(cnt, 0, `token=${label} must see 0 rows on app_views.${v.table_name} (saw ${cnt})`);
    }
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: tok, readOnly: false, serializable: true }, (c) => (
        c.query(
          `SELECT app_cmd.coherence_record_check($1, $2, 'chain', true, '{"ok":true}'::jsonb)`,
          [`bad-tok-${label}`, sha256Hex(`bad-tok-${label}`)],
        )
      )),
      (err) => err?.code === '42501',
      `token=${label} must fail app_cmd with 42501`,
    );
  }
});

test('Layer 7B [Audience Row & Column Isolation]: Agent (own NPN + zero dollars + no record_id dollar leak), Retention, Team Manager, Agency Manager (subtree + no upline + no gross_comm), Multi-Agency concurrent role, Investor, Entity Manager (v_current_policy_periods & v_current_commission_ledger), Tool Switches, and retired Migration 006 GUCs', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const r1 = await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'aud-r1', markSent: true });
  const r2 = await seedPublishedRun(env, { statementDate: '2026-11-15', keyPrefix: 'aud-r2', markSent: false });
  const r3 = await seedPublishedRun(env, { statementDate: '2026-11-20', keyPrefix: 'aud-r3', markSent: false, abandon: true });
  await env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys()');

  const tok = (personId, viewAsPersonId = null) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId });

  // 1. Selling Agent A (NPN 11111111, same name "Sam Seller" as Agent B 22222222)
  await runAsPlatformApp(env.pool, { token: tok(ids.agentA), readOnly: true }, async (c) => {
    const bob = (await c.query('SELECT run_id, policy_id, writing_npn, writing_agent, entity, amount, upline_amount, enrollment_code, conflicts FROM app_views.coherence_bob')).rows;
    assert.equal(bob.length, 1, 'Agent A must see strictly 1 sent policy (own NPN only, 0 unsent R2, 0 abandoned R3)');
    assert.equal(bob[0].run_id, r1.runId);
    assert.equal(bob[0].writing_npn, '11111111');
    assert.equal(bob[0].amount, null, 'Agent A must see NULL amount');
    assert.equal(bob[0].upline_amount, null, 'Agent A must see NULL upline_amount');
    assert.equal(bob[0].enrollment_code, null);
    assert.equal(bob[0].conflicts, null);

    // v_current_policy_periods resolves to official sent R1 (not hidden by unsent R2!)
    const curPol = (await c.query('SELECT run_id, writing_npn, amount, upline_amount FROM app_views.v_current_policy_periods')).rows;
    assert.equal(curPol.length, 1);
    assert.equal(curPol[0].run_id, r1.runId);
    assert.equal(curPol[0].writing_npn, '11111111');
    assert.equal(curPol[0].amount, null);
    assert.equal(curPol[0].upline_amount, null);

    const lines = (await c.query('SELECT writing_npn, amount, gross_comm, record_id, reversal_of, corrects_record_id, tx_id FROM app_views.coherence_statement_agency_lines')).rows;
    assert.equal(lines.length, 1);
    assert.equal(lines[0].writing_npn, '11111111');
    assert.equal(lines[0].amount, null, 'Agent A statement amount must be NULL');
    assert.equal(lines[0].gross_comm, null, 'Agent A gross_comm must be NULL');
    assert.equal(lines[0].record_id, null, 'Agent A record_id must be NULL so dollar amounts never leak in record_id');
    assert.equal(lines[0].tx_id, null);

    const totals = (await c.query('SELECT line_count::int, net_amount FROM app_views.coherence_statement_totals')).rows;
    assert.equal(totals.length, 1);
    assert.equal(totals[0].line_count, 1);
    assert.equal(totals[0].net_amount, null, 'Agent A statement totals net_amount must be NULL');

    // Zero upline, zero ledger, zero v_current_commission_ledger, zero runs
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_upline_lines')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.v_current_commission_ledger')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_entity_statement_reconciliation')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_runs')).rows[0].n, 0);

    // Side-channel security_barrier resistance (division by zero on hidden rows or masked columns)
    const sc1 = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE 1 / CASE WHEN writing_npn = '22222222' OR entity = 'Harbor' OR amount IS NOT NULL THEN 0 ELSE 1 END = 1")).rows[0].n;
    assert.equal(sc1, 1);
    const sc2 = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines WHERE 1 / CASE WHEN writing_npn = '22222222' OR amount IS NOT NULL OR gross_comm IS NOT NULL THEN 0 ELSE 1 END = 1")).rows[0].n;
    assert.equal(sc2, 1);
  });

  // 2. Retention Agent (wide on Harbor, zero dollars)
  await runAsPlatformApp(env.pool, { token: tok(ids.harborRetention), readOnly: true }, async (c) => {
    const bob = (await c.query('SELECT entity, amount, upline_amount FROM app_views.coherence_bob')).rows;
    assert.equal(bob.length, 1);
    assert.equal(bob[0].entity, 'Harbor');
    assert.equal(bob[0].amount, null);
    assert.equal(bob[0].upline_amount, null);
    const lines = (await c.query('SELECT entity, amount, gross_comm, record_id FROM app_views.coherence_statement_agency_lines')).rows;
    assert.equal(lines.length, 1);
    assert.equal(lines[0].entity, 'Harbor');
    assert.equal(lines[0].amount, null);
    assert.equal(lines[0].gross_comm, null);
    assert.equal(lines[0].record_id, null);
  });

  // 3. Beacon Agency Manager: sees Beacon + East Team (descendant org subtree!) + agency amount, NO Harbor, NO upline, NO gross_comm, NO ledger
  await runAsPlatformApp(env.pool, { token: tok(ids.beaconManager), readOnly: true }, async (c) => {
    const bob = (await c.query('SELECT entity, writing_npn, amount, upline_amount, conflicts FROM app_views.coherence_bob ORDER BY policy_id')).rows;
    assert.equal(bob.length, 3, 'Beacon Agency Manager must see Beacon (2) + child East Team (1) = 3 policies');
    assert.deepEqual(bob.map((r) => r.entity), ['Beacon', 'Beacon', 'East Team']);
    assert.deepEqual(bob.map((r) => r.amount), ['80.00', '120.00', '90.00']);
    assert.ok(bob.every((r) => r.upline_amount === null), 'Agency Manager must NEVER see upline_amount');
    assert.ok(bob.every((r) => r.conflicts === null), 'Agency Manager must NEVER see internal provenance');

    const curPol = (await c.query('SELECT run_id, entity, amount, upline_amount FROM app_views.v_current_policy_periods ORDER BY policy_id')).rows;
    assert.equal(curPol.length, 3);
    assert.ok(curPol.every((r) => r.run_id === r1.runId && r.upline_amount === null));

    const lines = (await c.query('SELECT account_kind, statement_entity, amount, gross_comm FROM app_views.coherence_entity_statement_lines ORDER BY statement_entity, amount')).rows;
    assert.equal(lines.length, 3);
    assert.ok(lines.every((r) => r.account_kind === 'agency'), 'Agency Manager must see zero upline rows');
    assert.ok(lines.every((r) => r.gross_comm === null), 'Agency Manager must see NULL gross_comm (cannot deduce upline)');
    assert.deepEqual(lines.map((r) => r.amount), ['80.00', '120.00', '90.00']);

    const batches = (await c.query('SELECT agency_net_total, upline_net_total FROM app_views.coherence_statement_batches')).rows;
    assert.equal(batches.length, 1);
    assert.equal(batches[0].agency_net_total, null, 'Company-wide batch agency_net_total must be NULL to prevent subtracting sibling agencies');
    assert.equal(batches[0].upline_net_total, null);

    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_upline_lines')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.v_current_commission_ledger')).rows[0].n, 0);

    // Side-channel resistance against Harbor and upline_amount
    const sc = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE 1 / CASE WHEN entity = 'Harbor' OR upline_amount IS NOT NULL THEN 0 ELSE 1 END = 1")).rows[0].n;
    assert.equal(sc, 3);
  });

  // 5. Concurrent multi-agency person (Agency Manager WITH cash at Beacon + Retention WITHOUT cash at Harbor)
  await runAsPlatformApp(env.pool, { token: tok(ids.multiAgencyPerson), readOnly: true }, async (c) => {
    const bob = (await c.query('SELECT entity, amount FROM app_views.coherence_bob ORDER BY policy_id')).rows;
    assert.equal(bob.length, 4);
    assert.equal(bob[0].amount, '80.00');
    assert.equal(bob[1].amount, '120.00');
    assert.equal(bob[2].amount, '90.00');
    assert.equal(bob[3].entity, 'Harbor');
    assert.equal(bob[3].amount, null, 'cash grant in Beacon must NEVER leak dollars on Harbor rows');
  });

  // 6. Investor: full sent BoB with dollars, 0 statements, 0 upline, 0 ledger
  await runAsPlatformApp(env.pool, { token: tok(ids.acmeInvestor), readOnly: true }, async (c) => {
    const bob = (await c.query('SELECT COUNT(*)::int AS n, SUM(amount)::text AS s FROM app_views.coherence_bob')).rows[0];
    assert.equal(bob.n, 4);
    assert.equal(bob.s, '490.00');
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_upline_lines')).rows[0].n, 0);
    assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger')).rows[0].n, 0);
  });

  // 7. Entity Manager: sees R1 + unsent R2 (NOT abandoned R3!), upline, ledger, v_current_policy_periods & v_current_commission_ledger on R2, and $0.00 reconciliation
  await runAsPlatformApp(env.pool, { token: tok(ids.acmeEntityMgr), readOnly: true }, async (c) => {
    const allBobRuns = (await c.query('SELECT DISTINCT run_id FROM app_views.coherence_bob')).rows.map((r) => r.run_id);
    assert.ok(allBobRuns.includes(r1.runId));
    assert.ok(allBobRuns.includes(r2.runId));
    assert.ok(!allBobRuns.includes(r3.runId), 'abandoned run must stay invisible even to Entity Manager');

    const curPol = (await c.query('SELECT DISTINCT run_id, COUNT(*) OVER ()::int AS cnt FROM app_views.v_current_policy_periods')).rows;
    assert.equal(curPol[0].run_id, r2.runId, 'Entity Manager v_current_policy_periods sees newest published run R2');
    assert.equal(curPol[0].cnt, 4);

    const curLed = (await c.query('SELECT DISTINCT run_id, COUNT(*) OVER ()::int AS cnt, SUM(upline_amount) OVER ()::text AS up FROM app_views.v_current_commission_ledger')).rows;
    assert.equal(curLed[0].run_id, r2.runId);
    assert.equal(curLed[0].cnt, 5);
    assert.equal(curLed[0].up, '170.00');

    const upline = (await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_upline_lines')).rows[0].n;
    assert.equal(upline, 10, 'Entity Manager sees upline lines across R1 and R2 (5 each)');

    const recon = (await c.query('SELECT * FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid', [r1.runId])).rows;
    assert.ok(recon.length >= 4);
    assert.ok(recon.every((r) => r.reconciled === true && r.variance === '0.00'));
  });

  // 8. Tool switch 'off' hides Coherence rows from customers while Nusear internal bypasses
  let switchOffId;
  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.switch_off', commandKey: 'coh-switch-off' });
    const prev = (await c.query(
      "SELECT id FROM iam.organization_tool_switches WHERE organization_id = $1 AND tool_id = 'coherence' AND superseded_by_id IS NULL",
      [ids.acmeOrg],
    )).rows[0].id;
    switchOffId = randomUUID();
    await c.query(
      `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq)
       VALUES ($1,$2,'coherence','off','active',$3,$4)`,
      [switchOffId, ids.acmeOrg, prev, j.seq],
    );
  });

  const emWhenOff = await runAsPlatformApp(env.pool, { token: tok(ids.acmeEntityMgr), readOnly: true }, async (c) => (
    (await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n
  ));
  assert.equal(emWhenOff, 0, 'Coherence tool switch off must return 0 rows to customer Entity Manager');
  const nusearWhenOff = await runAsPlatformApp(env.pool, { token: tok(ids.nusearOwner), readOnly: true }, async (c) => (
    (await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n
  ));
  assert.equal(nusearWhenOff, 8, 'Nusear internal must bypass customer tool switch');
  const viewAsWhenOff = await runAsPlatformApp(env.pool, { token: tok(ids.nusearOwner, ids.acmeEntityMgr), readOnly: true }, async (c) => (
    (await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n
  ));
  assert.equal(viewAsWhenOff, 0, 'Nusear viewing as customer must respect tool switch off (0 rows)');

  // Restore switch to 'on'
  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.switch_on', commandKey: 'coh-switch-on' });
    await c.query(
      `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq)
       VALUES ($1,$2,'coherence','on','active',$3,$4)`,
      [randomUUID(), ids.acmeOrg, switchOffId, j.seq],
    );
  });

  // 9. Any retired pre-IAM roles still present cluster-wide hold zero grants and fail with 42501.
  const retiredRolesPresent = (await env.pool.query(
    `SELECT rolname FROM pg_catalog.pg_roles
     WHERE rolname = ANY($1::text[])
     ORDER BY rolname`,
    [[
      'coherence_app', 'coherence_worker', 'coherence_readonly',
      'coherence_entity_manager_ro', 'coherence_agency_manager_ro',
      'coherence_agent_ro', 'coherence_retention_ro', 'coherence_investor_ro',
    ]],
  )).rows.map((r) => r.rolname);
  for (const role of retiredRolesPresent) {
    await assert.rejects(
      () => runAsRole(env.pool, role, { readOnly: true }, async (c) => {
        await c.query("SELECT pg_catalog.set_config('app.access_tier', 'entity_manager', true)");
        await c.query("SELECT pg_catalog.set_config('app.allowed_entities', 'Beacon', true)");
        return c.query('SELECT COUNT(*)::int AS n FROM coherence.bob_policies');
      }),
      (err) => err?.code === '42501',
      `retired pre-IAM role ${role} must get SQLSTATE 42501 on coherence.bob_policies`,
    );
  }
});

test('Layer 7B [app_cmd.coherence_* Commands, View-As Refusal & Worker Boundary]: every authz.mjs command executes through iam.assert_can_write, enforces additive roles and worker-only isolation, writes hash-verified journals, and refuses View-As even in READ WRITE transactions', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv({ initCompany: false });
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const tok = (personId, viewAsPersonId = null) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId });

  const ownerTok = tok(ids.nusearOwner);
  const adminNoCohTok = tok(ids.nusearAdminNoCoh);
  const operatorTok = tok(ids.nusearOperator);
  const wrongCoOperatorTok = tok(ids.northstarOperator);
  const workerTok = tok(ids.workerService);
  const companyAdminTok = tok(ids.acmeCompanyAdmin);
  const agentATok = tok(ids.agentA);
  const viewAsAgentTok = tok(ids.nusearOwner, ids.agentA);
  const viewAsMgrTok = tok(ids.nusearOwner, ids.beaconManager);

  const reqSha = (label) => sha256Hex(`req:${label}`);

  // 1. Owner initializes company via app_cmd.coherence_init_company
  const initRes = await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_init_company($1, $2, 'acme', 'Acme', 'coherence') AS res`,
      ['cmd-init-1', reqSha('init-1')],
    )
  ));
  assert.equal(initRes.rows[0].res.idempotent, false);
  assert.equal(initRes.rows[0].res.journal_seq, 1);

  // Idempotent replay succeeds with same seq AND full stored result object (Item 8); conflicting payload fails 23505
  const initReplay = await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_init_company($1, $2, 'acme', 'Acme', 'coherence') AS res`,
      ['cmd-init-1', reqSha('init-1')],
    )
  ));
  assert.equal(initReplay.rows[0].res.idempotent, true);
  assert.equal(initReplay.rows[0].res.journal_seq, 1);
  assert.deepEqual(initReplay.rows[0].res.result, { companySlug: 'acme', displayName: 'Acme', defaultEmitMode: 'coherence' });

  await assert.rejects(
    () => runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
      c.query(`SELECT app_cmd.coherence_init_company($1, $2, 'acme', 'Different', 'coherence')`, ['cmd-init-1', reqSha('init-conflict')])
    )),
    (err) => err?.code === '23505',
  );

  // Audit journal masks Nusear actor as 'Nusear support' for customer, shows real UUID to Nusear
  const custAudit = await runAsPlatformApp(env.pool, { token: tok(ids.acmeEntityMgr), readOnly: true }, async (c) => (
    (await c.query("SELECT recorded_as, recorded_by_display, actor_person_id FROM app_views.audit_journal WHERE command_kind = 'coherence.init_company'")).rows[0]
  ));
  assert.equal(custAudit.recorded_as, 'nusear_support');
  assert.equal(custAudit.recorded_by_display, 'Nusear support');
  assert.equal(custAudit.actor_person_id, null);

  const nusearAudit = await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: true }, async (c) => (
    (await c.query("SELECT recorded_as, actor_person_id FROM app_views.audit_journal WHERE command_kind = 'coherence.init_company'")).rows[0]
  ));
  assert.equal(nusearAudit.actor_person_id, ids.nusearOwner);

  // 2. Register stored files and engine version via app_cmd
  const makeFileObj = (storeKind, text) => {
    const fp = fingerprintBytes(Buffer.from(text, 'utf8'));
    return { store_kind: storeKind, sha256: fp.sha256, byte_size: fp.byteSize, md5_b64: fp.md5B64, crc32c_b64: fp.crc32cB64, object_name: `objects/${fp.sha256}` };
  };
  const codeF1 = makeFileObj('nusear_code', 'git-bundle');
  const codeF2 = makeFileObj('nusear_code', 'manifest');
  const codeF3 = makeFileObj('nusear_code', 'py-lock');
  const codeF4 = makeFileObj('nusear_code', 'wheels');
  const codeF5 = makeFileObj('nusear_code', 'wrappers');
  const inputDataF = makeFileObj('company_data', 'col1,col2\n1,2\n');
  const stagedDataF = makeFileObj('company_data', 'staged,val\n1,2\n');

  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query('SELECT app_cmd.coherence_register_stored_files($1, $2, $3::jsonb)', [
      'cmd-files-1', reqSha('files-1'), JSON.stringify([codeF1, codeF2, codeF3, codeF4, codeF5, inputDataF, stagedDataF]),
    ])
  ));

  const engineVersionId = randomUUID();
  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query('SELECT app_cmd.coherence_register_engine_version($1, $2, $3::jsonb)', [
      'cmd-eng-1', reqSha('eng-1'), JSON.stringify({
        id: engineVersionId,
        label: 'engine-009-copy',
        coherence_commit: 'abcdef1',
        engine_kind: 'engine_copy',
        git_bundle_sha256: codeF1.sha256,
        code_manifest_sha256: codeF2.sha256,
        python_lock_sha256: codeF3.sha256,
        python_wheels_sha256: codeF4.sha256,
        wrapper_bundle_sha256: codeF5.sha256,
        nusear_commit: '1234567',
        overlay_check_sha256: sha256Hex('overlay-check'),
        toolchain: { os: 'Linux', os_version: '6', arch: 'x64', python: '3.12', uv: '0.5', tz: 'America/New_York', lang: 'en_US.UTF-8', lc_all: 'en_US.UTF-8', pythonutf8: '1' },
      }),
    ])
  ));

  // 3. Operator (NOT Nusear Admin without coherence_operator, NOT wrong-company operator, NOT Company Admin, NOT Agent) can publish input & launch run
  await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_publish_input_version($1, $2, NULL, 'standing', 'upload', 'initial standing input', $3::jsonb)`,
      ['cmd-iv-1', reqSha('iv-1'), JSON.stringify([{ rel_path: 'Carrier/data.csv', file_sha256: inputDataF.sha256 }])],
    )
  ));

  // Refusals on launch_run: Nusear Admin (lacks coherence_operator), wrong-company operator, company_admin, agent
  for (const [who, badTok] of [
    ['nusear_admin_without_coherence_operator', adminNoCohTok],
    ['wrong_company_operator', wrongCoOperatorTok],
    ['company_admin', companyAdminTok],
    ['selling_agent', agentATok],
  ]) {
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: badTok, readOnly: false, serializable: true }, (c) => (
        c.query(
          `SELECT app_cmd.coherence_launch_run($1, $2, NULL, DATE '2026-11-01', $3::uuid)`,
          [`deny-launch-${who}`, reqSha(`deny-launch-${who}`), engineVersionId],
        )
      )),
      (err) => err?.code === '42501',
      `${who} must receive 42501 on coherence_launch_run`,
    );
  }

  // Operator launches a run -> succeeds!
  const launchRes = await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_launch_run($1, $2, NULL, DATE '2026-11-01', $3::uuid) AS res`,
      ['cmd-launch-1', reqSha('launch-1'), engineVersionId],
    )
  ));
  const runId = launchRes.rows[0].res.run_id;
  const assignReqId = launchRes.rows[0].res.step_request_id;
  assert.ok(runId && assignReqId);

  // Stale expected_seq fails 40001
  await assert.rejects(
    () => runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query(
        `SELECT app_cmd.coherence_request_cancel($1, $2, 1, $3::uuid, 'assign', 1, 'cancel assign', 'test')`,
        ['cmd-stale-1', reqSha('stale-1'), runId],
      )
    )),
    (err) => err?.code === '40001',
    'stale expected_seq must fail with 40001',
  );

  // Operator MUST get 42501 on owner-only typed commands (abandon_run, confirm_emit, carry_sent, carry_decisions, record_statement_batch)
  for (const [label, sql, params] of [
    ['abandon_run', "SELECT app_cmd.coherence_abandon_run($1, $2, NULL, $3::uuid, 'abandon 2026-11-01', 'nope')", ['op-ab', reqSha('op-ab'), runId]],
    ['carry_sent', "SELECT app_cmd.coherence_carry_sent($1, $2, NULL, $3::uuid, 'sent 2026-11-01')", ['op-cs', reqSha('op-cs'), runId]],
    ['carry_decisions', "SELECT app_cmd.coherence_carry_decisions($1, $2, NULL, $3::uuid, 'carry 2026-11-01')", ['op-cd', reqSha('op-cd'), runId]],
    ['confirm_emit', "SELECT app_cmd.coherence_confirm_emit($1, $2, NULL, $3::uuid, $4::uuid, 'create statements for 2026-11-01')", ['op-ce', reqSha('op-ce'), runId, randomUUID()]],
    ['record_statement_batch', "SELECT app_cmd.coherence_record_statement_batch($1, $2, $3::jsonb)", ['op-sb', reqSha('op-sb'), JSON.stringify({ batch_kind: 'historical_sent', statement_date: '2026-08-01', reason: 'test', agency_lines: [], upline_lines: [] })]],
  ]) {
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => c.query(sql, params)),
      (err) => err?.code === '42501',
      `coherence_operator must get 42501 on owner-only command ${label}`,
    );
  }

  // 4. Worker-only command: human Nusear Owner even under platform_worker gets 42501 WORKER_ONLY; real service worker succeeds through assign -> attribute -> bible!
  await assert.rejects(
    () => runAsRole(env.pool, 'platform_worker', { token: ownerTok, readOnly: false, serializable: true }, (c) => (
      c.query(`SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, 'assign', $4::uuid)`, ['w-human-bad', reqSha('w-human-bad'), runId, assignReqId])
    )),
    (err) => err?.code === '42501' && /WORKER_ONLY|FORBIDDEN/i.test(err.message),
    'human owner must never run worker-only command even as platform_worker',
  );

  // Worker holding advisory slot executes assign -> attribute -> bible cleanly
  const slotClient = await env.pool.connect();
  const lockOk = (await slotClient.query('SELECT pg_catalog.pg_try_advisory_lock(coherence.slot_class_id(), coherence.slot_obj_id()) AS ok')).rows[0].ok;
  assert.equal(lockOk, true);
  let nextReqId = assignReqId;
  try {
    for (const step of ['assign', 'attribute', 'bible']) {
      await slotClient.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      await slotClient.query('SET LOCAL ROLE platform_worker');
      await slotClient.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [workerTok]);
      const stRes = await slotClient.query(
        `SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, $4, $5::uuid) AS res`,
        [`w-start-${step}`, reqSha(`w-start-${step}`), runId, step, nextReqId],
      );
      assert.equal(stRes.rows[0].res.attempt_no, 1);
      await slotClient.query('COMMIT');

      await slotClient.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      await slotClient.query('SET LOCAL ROLE platform_worker');
      await slotClient.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [workerTok]);
      const finRes = await slotClient.query(
        `SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb) AS res`,
        [`w-fin-${step}`, reqSha(`w-fin-${step}`), JSON.stringify({
          run_id: runId, step, attempt_no: 1, born: '2026-11-01T12:00:00Z',
          artifacts: [], continue_to_next_step: step !== 'bible',
        })],
      );
      nextReqId = finRes.rows[0].res.next_request_id;
      await slotClient.query('COMMIT');
    }
  } catch (err) {
    await slotClient.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    await slotClient.query('SELECT pg_catalog.pg_advisory_unlock(coherence.slot_class_id(), coherence.slot_obj_id())').catch(() => {});
    slotClient.release();
  }

  // Operator now succeeds on save_review_draft, submit_review (+ worker reject_review_submission), and save_review_decisions for finished bible step!
  await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_save_review_draft($1::uuid, 'bible', 1, 'chk1', '[{"record_id":"k1"}]'::jsonb, '2026-11-01T12:00:00Z')`,
      [runId],
    )
  ));
  const subSeq = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [runId])).rows[0].s);
  const subRes = await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_submit_review($1, $2, $3, $4::uuid, 'bible', $5) AS res`,
      ['cmd-sub-1', reqSha('sub-1'), subSeq, runId, sha256Hex('staged-review-csv')],
    )
  ));
  const submissionId = subRes.rows[0].res.submission_id;
  assert.ok(submissionId);
  {
    const rejSlot = await env.pool.connect();
    try {
      const ok = (await rejSlot.query('SELECT pg_catalog.pg_try_advisory_lock(coherence.slot_class_id(), coherence.slot_obj_id()) AS ok')).rows[0].ok;
      assert.equal(ok, true);
      await rejSlot.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      await rejSlot.query('SET LOCAL ROLE platform_worker');
      await rejSlot.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [workerTok]);
      await rejSlot.query(
        `SELECT app_cmd.coherence_reject_review_submission($1::uuid, 'rejected', 'synthetic reject test')`,
        [submissionId],
      );
      await rejSlot.query('COMMIT');
    } catch (err) {
      await rejSlot.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      await rejSlot.query('SELECT pg_catalog.pg_advisory_unlock(coherence.slot_class_id(), coherence.slot_obj_id())').catch(() => {});
      rejSlot.release();
    }
  }

  const curRunSeq = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [runId])).rows[0].s);
  const saveDecRes = await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_save_review_decisions($1, $2, $3, $4::uuid, 'bible', $5::jsonb) AS res`,
      ['cmd-bible-save-1', reqSha('bible-save-1'), curRunSeq, runId, JSON.stringify([{ record_id: 'policy:carrier_a:C-101#effective:2026-10-01', disposition: 'CONFIRM' }])],
    )
  ));
  assert.ok(saveDecRes.rows[0].res.decision_commit_id);
  assert.ok(saveDecRes.rows[0].res.review_save_id);

  // 5. View-As refuses EVERY write command with 42501 VIEW_AS_READ_ONLY EVEN IN A DELIBERATE READ WRITE TRANSACTION!
  const viewAsCases = [
    ['launch_run', "SELECT app_cmd.coherence_launch_run($1, $2, NULL, DATE '2026-11-02', $3::uuid)", ['va-1', reqSha('va-1'), engineVersionId]],
    ['request_cancel', "SELECT app_cmd.coherence_request_cancel($1, $2, NULL, $3::uuid, 'assign', 1, 'cancel assign', 'va')", ['va-2', reqSha('va-2'), runId]],
    ['request_retry', "SELECT app_cmd.coherence_request_retry($1, $2, NULL, $3::uuid, 'assign')", ['va-3', reqSha('va-3'), runId]],
    ['submit_review', "SELECT app_cmd.coherence_submit_review($1, $2, 100, $3::uuid, 'bible', $4)", ['va-4', reqSha('va-4'), runId, sha256Hex('csv')]],
    ['save_review_decisions', "SELECT app_cmd.coherence_save_review_decisions($1, $2, 100, $3::uuid, 'bible', '[]'::jsonb)", ['va-5', reqSha('va-5'), runId]],
    ['save_review_draft', "SELECT app_cmd.coherence_save_review_draft($1::uuid, 'bible', 1, 'chk', '[]'::jsonb)", [runId]],
    ['publish_input_version', "SELECT app_cmd.coherence_publish_input_version($1, $2, NULL, 'standing', 'upload', 'va', '[]'::jsonb)", ['va-6', reqSha('va-6')]],
    ['confirm_emit', "SELECT app_cmd.coherence_confirm_emit($1, $2, NULL, $3::uuid, $4::uuid, 'create statements for 2026-11-01')", ['va-7', reqSha('va-7'), runId, randomUUID()]],
    ['carry_sent', "SELECT app_cmd.coherence_carry_sent($1, $2, NULL, $3::uuid, 'sent 2026-11-01')", ['va-8', reqSha('va-8'), runId]],
    ['carry_approvals', "SELECT app_cmd.coherence_carry_approvals($1, $2, NULL, $3::uuid, 'carry 2026-11-01')", ['va-9', reqSha('va-9'), runId]],
    ['carry_decisions', "SELECT app_cmd.coherence_carry_decisions($1, $2, NULL, $3::uuid, 'carry 2026-11-01')", ['va-10', reqSha('va-10'), runId]],
    ['abandon_run', "SELECT app_cmd.coherence_abandon_run($1, $2, NULL, $3::uuid, 'abandon 2026-11-01', 'va')", ['va-11', reqSha('va-11'), runId]],
    ['record_check', "SELECT app_cmd.coherence_record_check($1, $2, 'chain', true, '{}'::jsonb)", ['va-12', reqSha('va-12')]],
    ['register_stored_files', "SELECT app_cmd.coherence_register_stored_files($1, $2, '[]'::jsonb)", ['va-13', reqSha('va-13')]],
    ['record_decision_baseline', "SELECT app_cmd.coherence_record_decision_baseline($1, $2, $3::jsonb)", ['va-14', reqSha('va-14'), JSON.stringify({ decisions: [] })]],
    ['record_statement_batch', "SELECT app_cmd.coherence_record_statement_batch($1, $2, $3::jsonb)", ['va-15', reqSha('va-15'), JSON.stringify({ batch_kind: 'historical_sent', statement_date: '2026-08-01', reason: 'va', agency_lines: [], upline_lines: [] })]],
  ];

  for (const [label, sql, params] of viewAsCases) {
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: viewAsAgentTok, readOnly: false, serializable: true }, (c) => c.query(sql, params)),
      (err) => err?.code === '42501' && /VIEW_AS_READ_ONLY/i.test(err.message),
      `View-as in READ WRITE tx MUST refuse app_cmd.coherence_${label} with 42501 VIEW_AS_READ_ONLY`,
    );
  }

  // 6. Exercise record_check, abandon_run, import_standalone_files, include_staging_file, decision baseline, statement batch, and app_views.coherence_runs!
  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_record_check($1, $2, 'chain', true, '{"ok":true}'::jsonb, $3::uuid)`,
      ['cmd-chk-1', reqSha('chk-1'), runId],
    )
  ));

  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_abandon_run($1, $2, NULL, $3::uuid, 'abandon 2026-11-01', 'test abandon')`,
      ['cmd-ab-1', reqSha('ab-1'), runId],
    )
  ));

  // Verify app_views.coherence_runs shows abandoned stage for Company Admin (runs.read) and 0 rows for Agent A
  const adminRuns = await runAsPlatformApp(env.pool, { token: companyAdminTok, readOnly: true }, async (c) => (
    (await c.query('SELECT id, stage, abandoned FROM app_views.coherence_runs WHERE id = $1::uuid', [runId])).rows
  ));
  assert.equal(adminRuns.length, 1);
  assert.equal(adminRuns[0].stage, 'abandoned');
  assert.equal(adminRuns[0].abandoned, true);
  const agentRunsCnt = await runAsPlatformApp(env.pool, { token: agentATok, readOnly: true }, async (c) => (
    (await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_runs')).rows[0].n
  ));
  assert.equal(agentRunsCnt, 0);
  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_import_standalone_files($1, $2, $3::jsonb)`,
      ['cmd-stf-1', reqSha('stf-1'), JSON.stringify({
        files: [{ area: 'staging', rel_path: 'new_carrier.csv', artifact_kind: 'data', store_kind: 'company_data', file_sha256: stagedDataF.sha256 }],
      })],
    )
  ));
  await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_include_staging_file($1, $2, NULL, $3, 'Carrier/new_carrier.csv', 'include staged file')`,
      ['cmd-inc-1', reqSha('inc-1'), stagedDataF.sha256],
    )
  ));
  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_record_decision_baseline($1, $2, $3::jsonb)`,
      ['cmd-base-1', reqSha('base-1'), JSON.stringify({
        commit_kind: 'historical_baseline',
        header_contract: 'v2',
        imported: true,
        decisions: [{ record_id: 'policy:carrier_a:C-101#effective:2026-10-01', disposition: 'CONFIRM' }],
      })],
    )
  ));
  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query(
      `SELECT app_cmd.coherence_record_statement_batch($1, $2, $3::jsonb)`,
      ['cmd-sb-1', reqSha('sb-1'), JSON.stringify({
        batch_kind: 'historical_sent',
        statement_date: '2026-08-31',
        reason: 'historical seed via app_cmd',
        agency_lines: [{
          entity: 'Beacon', organization_id: ids.beaconOrg, writing_npn: '11111111', writing_person_id: ids.agentA,
          writing_agent: 'Sam Seller', record_id: 'carrier_a~direct~PAT~80.00~2026-08',
          source_file: 'hist_202608.csv', source_row_no: 1, gross_comm: '100.00', amount: '80.00',
        }],
        upline_lines: [{
          source_entity: 'Beacon', organization_id: ids.beaconOrg, writing_npn: '11111111', writing_person_id: ids.agentA,
          writing_agent: 'Sam Seller', record_id: 'carrier_a~direct~PAT~80.00~2026-08',
          source_file: 'hist_202608.csv', source_row_no: 1, gross_comm: '100.00', amount: '20.00',
        }],
      })],
    )
  ));

  // View-as read intersection over the statement batch inserted by app_cmd:
  // Owner viewing as Agent A sees 1 row with NULL amount; Owner viewing as Beacon Manager sees 1 row with 80.00 and 0 upline
  const vaAgentLines = await runAsPlatformApp(env.pool, { token: viewAsAgentTok, readOnly: true }, async (c) => (
    (await c.query('SELECT writing_npn, amount, gross_comm, record_id FROM app_views.coherence_statement_agency_lines')).rows
  ));
  assert.equal(vaAgentLines.length, 1);
  assert.equal(vaAgentLines[0].amount, null);
  assert.equal(vaAgentLines[0].gross_comm, null);
  assert.equal(vaAgentLines[0].record_id, null);

  const vaMgrUpline = await runAsPlatformApp(env.pool, { token: viewAsMgrTok, readOnly: true }, async (c) => (
    (await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_upline_lines')).rows[0].n
  ));
  assert.equal(vaMgrUpline, 0);

  // Full Coherence journal chain & commitments remain 100% valid after all app_cmd writes!
  const chain = await verifyChain(env.pool);
  assert.equal(chain.passed, true, `verifyChain failed: ${chain.problems.join('; ')}`);
  const comm = await verifyCommitments(env.pool);
  assert.equal(comm.passed, true, `verifyCommitments failed: ${comm.problems.join('; ')}`);
});

test('Layer 7B [InitPlan Performance Guard]: EXPLAIN on keyed app_views evaluates _read_* helpers once per statement (InitPlan / hashed SubPlan, zero per-row SubPlans) on sent and unsent runs', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const rSent = await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'plan-r1', markSent: true });
  const rUnsent = await seedPublishedRun(env, { statementDate: '2026-11-15', keyPrefix: 'plan-r2', markSent: false });
  await env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys()');

  // Give agentA narrow self unpublished.read + statement_cash so narrow pairs run on both sent and unsent runs.
  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.plan_guard_seed', commandKey: 'plan-guard-seed' });
    const roleId = randomUUID();
    await c.query("INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,'plan_narrow_unpub',NULL,$2)", [roleId, j.seq]);
    await c.query(
      "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,'Plan Narrow Unpub',false,false,false,'active',$3)",
      [randomUUID(), roleId, j.seq],
    );
    for (const rightId of ['act:coherence.bob.read', 'act:coherence.statements.read', 'col:coherence.statement_cash', 'act:coherence.unpublished.read']) {
      await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)", [randomUUID(), roleId, rightId, j.seq]);
    }
    await c.query(
      "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'self','[2020-01-01,)'::daterange,'active',$5)",
      [randomUUID(), ids.agentA, roleId, ids.beaconOrg, j.seq],
    );
  });

  const collectPlanRefStrings = (node, out = []) => {
    for (const [k, v] of Object.entries(node)) {
      if (k === 'Plans' || k === 'Subplan Name') continue;
      if (typeof v === 'string') out.push(v);
      else if (Array.isArray(v)) {
        for (const item of v) if (typeof item === 'string') out.push(item);
      }
    }
    for (const child of node.Plans || []) collectPlanRefStrings(child, out);
    return out;
  };

  const readCallRe = /\b(?:app_views\.)?_read_\w+\s*\(/;
  const fieldStrings = (val) => (
    typeof val === 'string'
      ? [val]
      : (Array.isArray(val) ? val.filter((item) => typeof item === 'string') : [])
  );

  const inspectReadNodes = (planRoot) => {
    const allRefStrings = collectPlanRefStrings(planRoot).join('\n');
    const readInitPlans = [];
    const readHashedSubPlans = [];
    const readPerRowSubPlans = [];
    const readHighLoopNodes = [];
    const readInlineScanCalls = [];

    const walk = (node, enclosingSubplan = null, enclosingRel = null) => {
      const ownSubplan = node['Subplan Name'] || enclosingSubplan;
      const ownRel = node['Subplan Name'] ? (node['Parent Relationship'] || enclosingRel) : enclosingRel;
      const isInitPlanNode = ownRel === 'InitPlan' || Boolean(ownSubplan && (ownSubplan.startsWith('InitPlan ') || ownSubplan.startsWith('CTE ')));
      const nodeType = node['Node Type'] || '';
      const fnName = node['Function Name'] || '';
      const fnSchema = node.Schema || '';

      // Fail on any _read_* call in Filter, Index Cond, Join Filter, or a non-InitPlan-Result Output.
      const forbiddenKeys = nodeType === 'Result' && isInitPlanNode
        ? ['Filter', 'Index Cond', 'Join Filter']
        : ['Filter', 'Index Cond', 'Join Filter', 'Output'];
      for (const key of forbiddenKeys) {
        for (const text of fieldStrings(node[key])) {
          const match = text.match(readCallRe);
          if (match) {
            readInlineScanCalls.push(`${nodeType}[${key}]:${match[0].replace(/\($/, '')}`);
          }
        }
      }

      const ownStrings = Object.entries(node)
        .filter(([k]) => k !== 'Plans')
        .flatMap(([, v]) => (Array.isArray(v) ? v : [v]))
        .filter((v) => typeof v === 'string')
        .join(' ');
      const isReadFnScan = nodeType === 'Function Scan' && fnSchema === 'app_views' && fnName.startsWith('_read_');
      const hasReadExpr = /app_views\._read_\w+/.test(ownStrings);
      if (isReadFnScan || hasReadExpr) {
        const label = isReadFnScan ? `app_views.${fnName}` : (ownStrings.match(/app_views\._read_\w+/) || ['app_views._read_'])[0];
        const loops = Number(node['Actual Loops'] ?? 0);
        if (loops > 1) {
          readHighLoopNodes.push(`${label} in ${ownSubplan || 'main'} (Actual Loops=${loops})`);
        }
        if (isInitPlanNode) {
          readInitPlans.push(`${ownSubplan}:${label}`);
        } else if (ownSubplan && ownSubplan.startsWith('SubPlan ')) {
          const spNum = ownSubplan.match(/^SubPlan (\d+)/)?.[1];
          const unhashedRe = new RegExp(`(?<!hashed )SubPlan ${spNum}\\b`);
          const hashedRe = new RegExp(`hashed SubPlan ${spNum}\\b`);
          const isHashedOnly = spNum && hashedRe.test(allRefStrings) && !unhashedRe.test(allRefStrings);
          if (isHashedOnly) {
            readHashedSubPlans.push(`${ownSubplan}:${label}`);
          } else {
            readPerRowSubPlans.push(`${ownSubplan}:${label} (loops=${loops})`);
          }
        }
      }
      for (const child of node.Plans || []) walk(child, ownSubplan, ownRel);
    };
    walk(planRoot);
    return { readInitPlans, readHashedSubPlans, readPerRowSubPlans, readHighLoopNodes, readInlineScanCalls };
  };

  // Non-vacuity self-test: inspectReadNodes must flag _read_* in Filter, Index Cond, Join Filter, and Output.
  for (const [key, sampleNode] of [
    ['Filter', { 'Node Type': 'Seq Scan', Filter: '(organization_id = ANY (app_views._read_bob_wide_orgs()))', 'Actual Loops': 1 }],
    ['Index Cond', { 'Node Type': 'Index Scan', 'Index Cond': '(organization_id = ANY (app_views._read_bob_wide_orgs()))', 'Actual Loops': 1 }],
    ['Join Filter', { 'Node Type': 'Nested Loop', 'Join Filter': '(bp.organization_id = ANY (app_views._read_bob_wide_orgs()))', 'Actual Loops': 1 }],
    ['Output', { 'Node Type': 'Seq Scan', Output: ['bp.policy_id', 'app_views._read_upline_cash_orgs()'], 'Actual Loops': 1 }],
  ]) {
    const res = inspectReadNodes(sampleNode);
    assert.ok(
      res.readInlineScanCalls.some((s) => s.includes(`[${key}]:`)),
      `InitPlan guard must flag _read_* call in ${key}, got ${JSON.stringify(res.readInlineScanCalls)}`,
    );
  }

  const agentTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.agentA });
  const emTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.acmeEntityMgr });
  const beaconMgrTok = mintSignedToken({ keyId, secretBytes, environment, actorPersonId: ids.beaconManager });

  // Live PG 17 EXPLAIN self-test: direct _read_* in a scan Filter or Output is caught on real EXPLAIN JSON.
  await runAsRole(env.pool, 'platform_view_owner', { readOnly: true }, async (c) => {
    await c.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [emTok]);
    const badFilterPlan = (await c.query(
      'EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT policy_id FROM coherence.bob_policies WHERE organization_id = ANY(app_views._read_bob_wide_orgs())',
    )).rows[0]['QUERY PLAN'][0].Plan;
    assert.ok(
      inspectReadNodes(badFilterPlan).readInlineScanCalls.some((s) => /\[(?:Filter|Index Cond)\]:/.test(s)),
      `InitPlan guard must catch live PG 17 inline _read_* in Filter/Index Cond:\n${JSON.stringify(badFilterPlan, null, 2)}`,
    );
    const badOutputPlan = (await c.query(
      'EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT policy_id, app_views._read_upline_cash_orgs() FROM coherence.bob_policies',
    )).rows[0]['QUERY PLAN'][0].Plan;
    assert.ok(
      inspectReadNodes(badOutputPlan).readInlineScanCalls.some((s) => s.includes('[Output]:')),
      `InitPlan guard must catch live PG 17 inline _read_* in scan Output:\n${JSON.stringify(badOutputPlan, null, 2)}`,
    );
  });

  const checks = [
    // Narrow self caller with both sent and unsent runs (exercises wide InitPlans + narrow hashed SubPlans on both runs).
    { label: 'agentA (sent+unsent)', token: agentTok, viewName: 'coherence_bob', expectBothRuns: true, expectHashedNarrow: true },
    { label: 'agentA (sent+unsent)', token: agentTok, viewName: 'v_current_policy_periods', expectBothRuns: false, expectHashedNarrow: true },
    { label: 'agentA (sent+unsent)', token: agentTok, viewName: 'coherence_statement_agency_lines', expectBothRuns: true, expectHashedNarrow: true },
    // Sent-only wide agency manager (exercises sent-only path without unsent rights).
    { label: 'beaconMgr (sent-only)', token: beaconMgrTok, viewName: 'coherence_bob', expectBothRuns: false, expectHashedNarrow: false },
    { label: 'beaconMgr (sent-only)', token: beaconMgrTok, viewName: 'coherence_statement_agency_lines', expectBothRuns: false, expectHashedNarrow: false },
    // Wide EM caller across all keyed tables, batches, and current ledger on both sent and unsent runs.
    { label: 'acmeEM (sent+unsent)', token: emTok, viewName: 'coherence_bob', expectBothRuns: true, expectHashedNarrow: false },
    { label: 'acmeEM (sent+unsent)', token: emTok, viewName: 'coherence_statement_batches', expectBothRuns: true, expectHashedNarrow: false },
    { label: 'acmeEM (sent+unsent)', token: emTok, viewName: 'coherence_statement_agency_lines', expectBothRuns: true, expectHashedNarrow: false },
    { label: 'acmeEM (sent+unsent)', token: emTok, viewName: 'coherence_statement_upline_lines', expectBothRuns: true, expectHashedNarrow: false },
    { label: 'acmeEM (sent+unsent)', token: emTok, viewName: 'coherence_ledger', expectBothRuns: true, expectHashedNarrow: false },
    { label: 'acmeEM (sent+unsent)', token: emTok, viewName: 'v_current_commission_ledger', expectBothRuns: false, expectHashedNarrow: false },
  ];

  for (const chk of checks) {
    const { planRoot, rowCount, runDates } = await runAsPlatformApp(env.pool, { token: chk.token, readOnly: true }, async (c) => {
      const planRes = await c.query(`EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT * FROM app_views.${chk.viewName}`);
      const root = planRes.rows[0]['QUERY PLAN'][0].Plan;
      let dates = [];
      if (chk.expectBothRuns) {
        if (chk.viewName === 'coherence_bob' || chk.viewName === 'coherence_ledger') {
          dates = (await c.query(`SELECT DISTINCT run_id FROM app_views.${chk.viewName}`)).rows.map((r) => r.run_id);
        } else {
          dates = (await c.query(`SELECT DISTINCT pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS d FROM app_views.${chk.viewName}`)).rows.map((r) => r.d);
        }
      }
      return { planRoot: root, rowCount: Number(root['Actual Rows'] ?? 0), runDates: dates };
    });

    assert.ok(rowCount > 0, `${chk.label} on app_views.${chk.viewName} must return non-zero rows so plan check is non-vacuous`);
    if (chk.expectBothRuns) {
      if (chk.viewName === 'coherence_bob' || chk.viewName === 'coherence_ledger') {
        assert.ok(runDates.includes(rSent.runId) && runDates.includes(rUnsent.runId), `${chk.label} on app_views.${chk.viewName} must match both sent and unsent runs (got ${JSON.stringify(runDates)})`);
      } else {
        assert.ok(runDates.includes('2026-10-31') && runDates.includes('2026-11-15'), `${chk.label} on app_views.${chk.viewName} must match both sent and unsent statement dates (got ${JSON.stringify(runDates)})`);
      }
    }

    const { readInitPlans, readHashedSubPlans, readPerRowSubPlans, readHighLoopNodes, readInlineScanCalls } = inspectReadNodes(planRoot);
    assert.ok(
      readInitPlans.length > 0,
      `${chk.label} on app_views.${chk.viewName} must match non-zero app_views._read_* InitPlans:\n${JSON.stringify(planRoot, null, 2)}`,
    );
    if (chk.expectHashedNarrow) {
      assert.ok(
        readHashedSubPlans.length > 0,
        `${chk.label} on app_views.${chk.viewName} must match non-zero app_views._read_* hashed SubPlans:\n${JSON.stringify(planRoot, null, 2)}`,
      );
    }
    assert.deepEqual(
      readPerRowSubPlans,
      [],
      `${chk.label} on app_views.${chk.viewName} must have ZERO per-row SubPlans on app_views._read_* (found ${JSON.stringify(readPerRowSubPlans)})`,
    );
    assert.deepEqual(
      readHighLoopNodes,
      [],
      `${chk.label} on app_views.${chk.viewName} must evaluate every app_views._read_* node at most once per statement (found ${JSON.stringify(readHighLoopNodes)})`,
    );
    assert.deepEqual(
      readInlineScanCalls,
      [],
      `${chk.label} on app_views.${chk.viewName} must have ZERO inline _read_* calls in scan Filter/Index Cond/Join Filter/Output (found ${JSON.stringify(readInlineScanCalls)})`,
    );
  }
});

test('Layer 7B [Fix1-1, Fix1-2, Fix1-12 - Backfill Role Isolation, platform_worker Lockdown & Catalog Audit Hardening]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  await seedCoherenceIamWorld(env.pool);
  await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'f1-b12', markSent: true });

  await t.test('Fix1-1: only platform_migrator/platform_versioner may execute backfill_iam_foreign_keys (42501 for platform_readonly/writer/worker/app)', async () => {
    for (const role of ['platform_readonly', 'platform_writer', 'platform_worker', 'platform_app']) {
      await assert.rejects(
        () => runAsRole(env.pool, role, { readOnly: false }, (c) => (
          c.query('SELECT * FROM coherence.backfill_iam_foreign_keys()')
        )),
        (err) => err?.code === '42501',
        `${role} must get SQLSTATE 42501 on coherence.backfill_iam_foreign_keys`,
      );
    }
    const bfMig = await runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
      c.query('SELECT table_name, rows_updated::int, rows_already_mapped::int FROM coherence.backfill_iam_foreign_keys() ORDER BY table_name')
    ));
    assert.equal(bfMig.rows.length, 5);
    assert.ok(bfMig.rows.every((r) => r.rows_already_mapped > 0));
  });

  await t.test('Fix1-2: platform_worker gets 42501 on INSERT/UPDATE/DELETE on every Coherence base table & schema_migrations, and holds only FOR SELECT policies', async () => {
    const cohTbls = (await env.pool.query(
      `SELECT table_name
       FROM information_schema.tables
       WHERE table_schema = 'coherence' AND table_type = 'BASE TABLE'
       ORDER BY table_name`,
    )).rows.map((r) => r.table_name);
    assert.ok(cohTbls.includes('schema_migrations'));
    assert.ok(cohTbls.includes('decisions'));
    assert.ok(cohTbls.includes('decision_commits'));
    assert.ok(cohTbls.includes('review_saves'));
    assert.ok(cohTbls.includes('emit_confirmations'));
    assert.ok(cohTbls.includes('carries'));
    assert.ok(cohTbls.includes('abandonments'));

    for (const tbl of cohTbls) {
      await assert.rejects(
        () => runAsRole(env.pool, 'platform_worker', { readOnly: false, serializable: true }, (c) => (
          c.query(`INSERT INTO coherence."${tbl}" DEFAULT VALUES`)
        )),
        (err) => err?.code === '42501',
        `platform_worker must get SQLSTATE 42501 on INSERT into coherence.${tbl}`,
      );
    }
    await assert.rejects(
      () => runAsRole(env.pool, 'platform_worker', { readOnly: false, serializable: true }, (c) => (
        c.query("UPDATE coherence.review_submissions SET status = 'rejected' WHERE false")
      )),
      (err) => err?.code === '42501',
      'platform_worker must get 42501 on direct UPDATE to coherence.review_submissions',
    );
    await assert.rejects(
      () => runAsRole(env.pool, 'platform_worker', { readOnly: false }, (c) => (
        c.query('DELETE FROM coherence.review_drafts WHERE false')
      )),
      (err) => err?.code === '42501',
      'platform_worker must get 42501 on direct DELETE from coherence.review_drafts',
    );
    await assert.rejects(
      () => runAsRole(env.pool, 'platform_worker', { readOnly: true }, (c) => (
        c.query('SELECT * FROM coherence.schema_migrations LIMIT 1')
      )),
      (err) => err?.code === '42501',
      'platform_worker must get 42501 on SELECT from coherence.schema_migrations',
    );

    const workerRead = await runAsRole(env.pool, 'platform_worker', { readOnly: true }, (c) => (
      c.query('SELECT COUNT(*)::int AS n FROM coherence.runs')
    ));
    assert.ok(workerRead.rows[0].n >= 1);
    await assert.rejects(
      () => runAsRole(env.pool, 'platform_worker', { readOnly: false, serializable: true }, (c) => (
        c.query("SELECT app_cmd.coherence_abandon_run('k', $1, NULL, $2::uuid, 'abandon 2026-10-31', 'x')", [sha256Hex('k'), randomUUID()])
      )),
      (err) => err?.code === '42501',
      'platform_worker must get 42501 on human-only app_cmd.coherence_abandon_run',
    );

    const workerPols = (await env.pool.query(
      `SELECT tablename, policyname, cmd
       FROM pg_catalog.pg_policies
       WHERE schemaname = 'coherence' AND 'platform_worker' = ANY(roles)`,
    )).rows;
    assert.ok(workerPols.length >= 33);
    assert.ok(workerPols.every((p) => p.cmd === 'SELECT'), `platform_worker has non-SELECT RLS policies: ${JSON.stringify(workerPols.filter((p) => p.cmd !== 'SELECT'))}`);
  });

  await t.test('Fix1-12 [Audit baseline]: catalog audit passes on clean migration 009', async () => {
    const okAudit = await withClusterCatalogLock(() => policyChecks.verifyIamConfigInvariants(env.pool));
    assert.equal(okAudit.passed, true, `audit failed:\n${okAudit.problems.join('\n')}`);
  });

  await t.test('Fix1-1 [Audit mutation]: granting backfill EXECUTE to platform_readonly fails audit', async () => {
    await env.pool.query('GRANT EXECUTE ON FUNCTION coherence.backfill_iam_foreign_keys(jsonb, jsonb) TO platform_readonly');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /backfill_iam_foreign_keys/i.test(p) && /platform_readonly/i.test(p)));
    } finally {
      await env.pool.query('REVOKE EXECUTE ON FUNCTION coherence.backfill_iam_foreign_keys(jsonb, jsonb) FROM platform_readonly');
    }
  });

  await t.test('Fix1-1 [Audit mutation]: granting backfill EXECUTE to platform_writer fails audit', async () => {
    await env.pool.query('GRANT EXECUTE ON FUNCTION coherence.backfill_iam_foreign_keys(jsonb, jsonb) TO platform_writer');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /backfill_iam_foreign_keys/i.test(p) && /platform_writer/i.test(p)));
    } finally {
      await env.pool.query('REVOKE EXECUTE ON FUNCTION coherence.backfill_iam_foreign_keys(jsonb, jsonb) FROM platform_writer');
    }
  });

  await t.test('Fix1-2 [Audit mutation]: granting INSERT on coherence.decisions to platform_worker fails audit', async () => {
    await env.pool.query('GRANT INSERT ON coherence.decisions TO platform_worker');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /platform_worker/i.test(p) && /decisions/i.test(p)));
    } finally {
      await env.pool.query('REVOKE INSERT ON coherence.decisions FROM platform_worker');
    }
  });

  await t.test('Fix1-12 [Audit mutation]: adding USING (true) policy for platform_view_owner on bob_policies fails audit (every, not some)', async () => {
    await env.pool.query('CREATE POLICY bob_policies_view_backdoor_probe ON coherence.bob_policies FOR SELECT TO platform_view_owner USING (true)');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /bob_policies/i.test(p) && /platform_view_owner|unscoped|effective_wide_org_ids/i.test(p)));
    } finally {
      await env.pool.query('DROP POLICY IF EXISTS bob_policies_view_backdoor_probe ON coherence.bob_policies');
    }
  });

  await t.test('Fix1-12 [Audit mutation]: adding a PUBLIC RLS policy on bob_policies fails audit', async () => {
    await env.pool.query('CREATE POLICY bob_policies_public_probe ON coherence.bob_policies FOR SELECT TO PUBLIC USING (true)');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /public/i.test(p) && /bob_policies|policy/i.test(p)));
    } finally {
      await env.pool.query('DROP POLICY IF EXISTS bob_policies_public_probe ON coherence.bob_policies');
    }
  });

  await t.test('Fix1-12 [Audit mutation]: granting EXECUTE on app_cmd to platform_readonly fails audit', async () => {
    await env.pool.query('GRANT EXECUTE ON FUNCTION app_cmd.coherence_record_check(text, text, text, boolean, jsonb, uuid, uuid, uuid) TO platform_readonly');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /platform_readonly/i.test(p) && /coherence_record_check/i.test(p)));
    } finally {
      await env.pool.query('REVOKE EXECUTE ON FUNCTION app_cmd.coherence_record_check(text, text, text, boolean, jsonb, uuid, uuid, uuid) FROM platform_readonly');
    }
  });

  await t.test('Fix1-12 [Audit mutation]: granting human-only app_cmd to platform_worker fails audit', async () => {
    await env.pool.query('GRANT EXECUTE ON FUNCTION app_cmd.coherence_abandon_run(text, text, bigint, uuid, text, text, uuid) TO platform_worker');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false);
      assert.ok(bad.problems.some((p) => /platform_worker/i.test(p) && /coherence_abandon_run/i.test(p)));
    } finally {
      await env.pool.query('REVOKE EXECUTE ON FUNCTION app_cmd.coherence_abandon_run(text, text, bigint, uuid, text, text, uuid) FROM platform_worker');
    }
  });

  await t.test('Fix1-12 [Note]: .gitignore ignores .pass2.pid', async () => {
    const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
    const gitignore = (await readFile(resolve(repoRoot, '.gitignore'), 'utf8')).split(/\r?\n/).map((l) => l.trim());
    assert.ok(gitignore.includes('.pass2.pid'), '.gitignore must ignore .pass2.pid');
  });
});

test('Layer 7B [Fix1-3, Fix1-4, Fix1-5, Fix1-8 - Decisions Gate, Tenant-Scoped RLS & Mixed-Scope Reader, Single Upline Row, Reconciliation Rights]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const r1 = await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'f1-v-r1', markSent: true });
  await seedPublishedRun(env, { statementDate: '2026-11-15', keyPrefix: 'f1-v-r2', markSent: false });

  const tok = (personId, viewAsPersonId = null) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId });
  const ownerTok = tok(ids.nusearOwner);
  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, async (c) => {
    await c.query(
      'SELECT app_cmd.coherence_record_decision_baseline($1, $2, $3::jsonb)',
      ['f1-dec-base', sha256Hex('f1-dec-base'), JSON.stringify({
        commit_kind: 'historical_baseline',
        header_contract: 'v2',
        imported: true,
        decisions: [{ record_id: 'policy:carrier_a:C-101#effective:2026-10-01', disposition: 'CONFIRM' }],
      })],
    );
    await c.query(
      "SELECT app_cmd.coherence_record_check($1, $2, 'chain', true, '{\"ok\":true}'::jsonb, $3::uuid)",
      ['f1-chk-1', sha256Hex('f1-chk-1'), r1.runId],
    );
  });
  await runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
    c.query('SELECT * FROM coherence.backfill_iam_foreign_keys()')
  ));

  const crossMixedPerson = randomUUID();
  const intraMixedPerson = randomUUID();
  const roleUnpubStmtOnly = randomUUID();
  const roleLedgerNoStmt = randomUUID();
  const roleLedgerNoUpline = randomUUID();
  const ledgerNoStmtPerson = randomUUID();
  const ledgerNoUplinePerson = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.seed_mixed', commandKey: 'f1-mixed-seed' });
    const seq = j.seq;
    for (const [rid, slug, name, rightsList] of [
      [roleUnpubStmtOnly, 'unpub_stmt_only', 'Unpub Stmt Only', ['act:coherence.unpublished.read', 'act:coherence.statements.read']],
      [roleLedgerNoStmt, 'ledger_no_stmt', 'Ledger No Stmt', ['act:coherence.ledger.read', 'act:coherence.upline.read', 'col:coherence.upline_cash']],
      [roleLedgerNoUpline, 'ledger_no_upline', 'Ledger No Upline', ['act:coherence.ledger.read', 'act:coherence.statements.read', 'col:coherence.upline_cash']],
    ]) {
      await c.query('INSERT INTO iam.roles (id, slug, journal_seq) VALUES ($1,$2,$3)', [rid, slug, seq]);
      await c.query(
        "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,$3,false,false,true,'active',$4)",
        [randomUUID(), rid, name, seq],
      );
      for (const rightId of rightsList) {
        await c.query(
          "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), rid, rightId, seq],
        );
      }
    }
    for (const [pid, name, email] of [
      [crossMixedPerson, 'Cross Mixed', 'cross.mix@example.test'],
      [intraMixedPerson, 'Intra Mixed', 'intra.mix@example.test'],
      [ledgerNoStmtPerson, 'Ledger No Stmt', 'lns@acme.example'],
      [ledgerNoUplinePerson, 'Ledger No Upline', 'lnu@acme.example'],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [pid, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,$3,$3,$4,'active',$5)",
        [randomUUID(), pid, name, email, seq],
      );
    }
    for (const [pid, oid] of [
      [crossMixedPerson, ids.rootOrg],
      [crossMixedPerson, ids.beaconOrg],
      [intraMixedPerson, ids.acmeOrg],
      [ledgerNoStmtPerson, ids.acmeOrg],
      [ledgerNoUplinePerson, ids.acmeOrg],
    ]) {
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), pid, oid, seq],
      );
    }
    for (const [pid, rid, oid] of [
      [crossMixedPerson, ids.roleCoherenceOperator, ids.northstarOrg],
      [crossMixedPerson, ids.roleAgencyManager, ids.beaconOrg],
      [intraMixedPerson, ids.roleAgencyManager, ids.beaconOrg],
      [intraMixedPerson, roleUnpubStmtOnly, ids.harborOrg],
      [ledgerNoStmtPerson, roleLedgerNoStmt, ids.acmeOrg],
      [ledgerNoUplinePerson, roleLedgerNoUpline, ids.acmeOrg],
    ]) {
      await c.query(
        `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)`,
        [randomUUID(), pid, rid, oid, seq],
      );
    }
  });

  await t.test('Fix1-3: company administrator (runs.read only) sees 0 rows in decisions, decision_commits, checks, and journal', async () => {
    await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: true }, async (c) => {
      assert.ok((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_decisions')).rows[0].n > 0);
      assert.ok((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_decision_commits')).rows[0].n > 0);
      assert.ok((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_checks')).rows[0].n > 0);
      assert.ok((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_journal')).rows[0].n > 0);
    });
    await runAsPlatformApp(env.pool, { token: tok(ids.acmeCompanyAdmin), readOnly: true }, async (c) => {
      assert.ok((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_runs')).rows[0].n > 0);
      assert.ok((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_input_versions')).rows[0].n > 0);
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_decisions')).rows[0].n, 0, 'company_admin must see 0 coherence_decisions');
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_decision_commits')).rows[0].n, 0, 'company_admin must see 0 coherence_decision_commits');
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_checks')).rows[0].n, 0, 'company_admin must see 0 coherence_checks');
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_journal')).rows[0].n, 0, 'company_admin must see 0 coherence_journal');
    });
  });

  await t.test('Fix1-4a: other company operator (northstarOperator) sees 0 rows in ALL app_views.*', async () => {
    const allAppViews = (await env.pool.query(
      "SELECT table_name FROM information_schema.views WHERE table_schema = 'app_views' ORDER BY table_name",
    )).rows.map((r) => r.table_name);
    assert.ok(allAppViews.length >= 19);
    await runAsPlatformApp(env.pool, { token: tok(ids.northstarOperator), readOnly: true }, async (c) => {
      for (const v of allAppViews) {
        const cnt = (await c.query(`SELECT COUNT(*)::int AS n FROM app_views."${v}"`)).rows[0].n;
        assert.equal(cnt, 0, `northstarOperator must see 0 rows in app_views.${v} (saw ${cnt})`);
      }
    });
  });

  await t.test('Fix1-4b: mixed-scope readers (cross-company and within-tenant) still see latest sent run R1 policies in v_current_policy_periods', async () => {
    await runAsPlatformApp(env.pool, { token: tok(crossMixedPerson), readOnly: true }, async (c) => {
      const curPol = (await c.query('SELECT run_id, entity, amount FROM app_views.v_current_policy_periods ORDER BY policy_id')).rows;
      assert.equal(curPol.length, 3, 'cross-company mixed reader must still see R1 sent policies in v_current_policy_periods');
      assert.ok(curPol.every((r) => r.run_id === r1.runId));
      const batches = (await c.query('SELECT run_id FROM app_views.coherence_statement_batches')).rows;
      assert.equal(batches.length, 1, 'cross-company mixed reader must see only sent batch R1');
      assert.equal(batches[0].run_id, r1.runId);
    });
    await runAsPlatformApp(env.pool, { token: tok(intraMixedPerson), readOnly: true }, async (c) => {
      const curPol = (await c.query('SELECT run_id, entity FROM app_views.v_current_policy_periods ORDER BY policy_id')).rows;
      assert.equal(curPol.length, 3, 'within-tenant mixed reader must still see R1 sent policies in v_current_policy_periods');
      assert.ok(curPol.every((r) => r.run_id === r1.runId));
    });
  });

  await t.test('Fix1-5: upline totals/date-totals/membership report ONE <Company> Upline row at tenant organization with source_organization_id kept apart', async () => {
    await runAsPlatformApp(env.pool, { token: tok(ids.acmeEntityMgr), readOnly: true }, async (c) => {
      const upLines = (await c.query("SELECT organization_id, source_organization_id, statement_entity, source_entity, amount FROM app_views.coherence_statement_upline_lines WHERE statement_date = DATE '2026-10-31' ORDER BY line_no")).rows;
      assert.equal(upLines.length, 5);
      assert.ok(upLines.every((r) => r.organization_id === ids.acmeOrg), 'upline lines must report tenant organization_id');
      assert.ok(upLines.every((r) => r.statement_entity === 'Acme Upline'));
      assert.deepEqual(
        new Set(upLines.map((r) => r.source_organization_id)),
        new Set([ids.beaconOrg, ids.eastTeamOrg, ids.harborOrg, ids.acmeOrg]),
        'source_organization_id must preserve distinct source agencies',
      );

      const stmtTotals = (await c.query("SELECT organization_id, statement_entity, line_count::int, net_amount FROM app_views.coherence_statement_totals WHERE statement_date = DATE '2026-10-31' AND account_kind = 'upline'")).rows;
      assert.equal(stmtTotals.length, 1, 'coherence_statement_totals must have strictly ONE upline row per batch/src_type/month');
      assert.equal(stmtTotals[0].organization_id, ids.acmeOrg);
      assert.equal(stmtTotals[0].statement_entity, 'Acme Upline');
      assert.equal(stmtTotals[0].line_count, 5);
      assert.equal(stmtTotals[0].net_amount, '170.00');

      const dateTotals = (await c.query("SELECT organization_id, statement_entity, line_count::int, net_amount FROM app_views.coherence_statement_date_totals WHERE statement_date = DATE '2026-10-31' AND account_kind = 'upline'")).rows;
      assert.equal(dateTotals.length, 1, 'coherence_statement_date_totals must have strictly ONE upline row per statement_date');
      assert.equal(dateTotals[0].organization_id, ids.acmeOrg);
      assert.equal(dateTotals[0].statement_entity, 'Acme Upline');
      assert.equal(dateTotals[0].line_count, 5);
      assert.equal(dateTotals[0].net_amount, '170.00');

      const membership = (await c.query("SELECT organization_id, statement_entity, appearances::int, net_amount FROM app_views.coherence_statement_membership WHERE statement_date = DATE '2026-10-31' AND account_kind = 'upline'")).rows;
      assert.equal(membership.length, 5);
      assert.ok(membership.every((r) => r.organization_id === ids.acmeOrg && r.statement_entity === 'Acme Upline'));
    });
  });

  await t.test('Fix1-8: coherence_entity_statement_reconciliation requires statements.read and upline.read as well as ledger.read and upline_cash', async () => {
    for (const [label, pid] of [
      ['missing_statements_read', ledgerNoStmtPerson],
      ['missing_upline_read', ledgerNoUplinePerson],
    ]) {
      const recon = await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => (
        (await c.query('SELECT * FROM app_views.coherence_entity_statement_reconciliation')).rows
      ));
      assert.equal(recon.length, 0, `${label} must see 0 rows in reconciliation (never false variances), saw ${JSON.stringify(recon)}`);
    }
  });
});

test('Layer 7B [Fix1-9 & Fix1-12 Note - Active-Only Affiliations, Tenant-Tree Org Kind Filtering, Archived Agency History Visibility, and writing_person_id CHECK]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const r1 = await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'f1-9-r1', markSent: true });
  const r2 = await seedPublishedRun(env, { statementDate: '2026-11-15', keyPrefix: 'f1-9-r2', markSent: false });
  await runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
    c.query('SELECT * FROM coherence.backfill_iam_foreign_keys()')
  ));

  const tok = (personId, viewAsPersonId = null) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId });

  const leadVendorOrg = randomUUID();
  const refFirmOrg = randomUUID();
  const orphanAgencyOrg = randomUUID();
  const revokedAgent = randomUUID();
  const activeAgent88 = randomUUID();
  const acmeNoDescPerson = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.seed_fix9', commandKey: 'f1-9-seed' });
    const seq = j.seq;
    for (const [oid, kind, slug, name, parent] of [
      [leadVendorOrg, 'lead_vendor', 'leadco', 'LeadCo', ids.acmeOrg],
      [refFirmOrg, 'referral_firm', 'refco', 'RefCo', ids.acmeOrg],
      [orphanAgencyOrg, 'agency', 'orphan_ag', 'Orphan Agency', null],
    ]) {
      await c.query('INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,$2,$3)', [oid, kind, seq]);
      await c.query("INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,$3,$4,'active',$5)", [randomUUID(), oid, slug, name, seq]);
      if (parent) {
        await c.query("INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), oid, parent, seq]);
      }
    }
    for (const [pid, name, email] of [
      [revokedAgent, 'Revoked Affil Agent', 'rev.aff@beacon.example'],
      [activeAgent88, 'Active Affil Agent', 'act.aff@beacon.example'],
      [acmeNoDescPerson, 'Acme House Only', 'house.only@acme.example'],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [pid, seq]);
      await c.query("INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,$3,$3,$4,'active',$5)", [randomUUID(), pid, name, email, seq]);
    }
    await c.query(
      "INSERT INTO iam.agent_affiliations (id, person_id, npn, agency_org_id, split_bps, agent_file_name, valid_range, status, journal_seq) VALUES ($1,$2,'88888888',$3,8000,'Revoked File','[2020-01-01,)'::daterange,'revoked',$4)",
      [randomUUID(), revokedAgent, ids.beaconOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), acmeNoDescPerson, ids.acmeOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,false,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
      [randomUUID(), acmeNoDescPerson, ids.roleEntityManager, ids.acmeOrg, seq],
    );
  });

  await t.test('Fix1-12 [Note]: CHECK constraint forbids writing_person_id IS NOT NULL when writing_npn IS NULL on all 5 FK tables', async () => {
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: tok(ids.nusearOwner), readOnly: false, serializable: true }, (c) => (
        c.query('SELECT app_cmd.coherence_record_statement_batch($1, $2, $3::jsonb)', [
          'chk-null-npn-1', sha256Hex('chk-null-npn-1'), JSON.stringify({
            batch_kind: 'historical_sent',
            statement_date: '2026-07-01',
            reason: 'null npn with person check',
            agency_lines: [{
              entity: 'Beacon', organization_id: ids.beaconOrg, writing_npn: null, writing_person_id: ids.agentA,
              writing_agent: null, record_id: 'carrier_a~direct~BAD~10.00~2026-07',
              source_file: 'bad.csv', source_row_no: 1, gross_comm: '10.00', amount: '10.00',
            }],
            upline_lines: [],
          }),
        ])
      )),
      (err) => err?.code === '23514',
      'CHECK must refuse writing_person_id non-NULL when writing_npn IS NULL',
    );
    const chkRes = await env.pool.query(
      `SELECT c.relname, pg_catalog.pg_get_constraintdef(con.oid) AS def
       FROM pg_catalog.pg_constraint con
       JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'coherence'
         AND c.relname IN ('bob_policies', 'bob_policy_financials', 'statement_agency_lines', 'statement_upline_lines', 'coherent_ledger_rows')
         AND con.contype = 'c'
         AND pg_catalog.pg_get_constraintdef(con.oid) ~ 'writing_person_id'`,
    );
    assert.equal(chkRes.rows.length, 5, 'all 5 FK tables must carry CHECK tying writing_person_id NULL to writing_npn NULL');
  });

  await t.test('Fix1-9B: _resolve_writing_person_id uses only status = active agent_affiliations', async () => {
    await assert.rejects(
      () => env.commands.recordStatementBatch({
        dbToken: env.ownerToken,
        commandKey: 'f1-9b-revoked-npn',
        batchKind: 'historical_sent',
        statementDate: '2026-07-15',
        reason: 'revoked affil test',
        agencyLines: [{
          entity: 'Beacon', writingNpn: '88888888', writingAgent: 'Affil Test',
          recordId: 'carrier_a~direct~AFF88~10.00~2026-07', sourceFile: 'aff.csv', sourceRowNo: 1,
          grossComm: '10.00', amount: '10.00',
        }],
        uplineLines: [],
      }),
      /UNMAPPED_WRITING_NPN/i,
      'revoked agent_affiliation must not resolve writing_npn',
    );
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.seed_active_aff', commandKey: 'f1-9b-act-aff' });
      await c.query(
        "INSERT INTO iam.agent_affiliations (id, person_id, npn, agency_org_id, split_bps, agent_file_name, valid_range, status, journal_seq) VALUES ($1,$2,'88888888',$3,8000,'Active File','[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), activeAgent88, ids.beaconOrg, j.seq],
      );
    });
    await env.commands.recordStatementBatch({
      dbToken: env.ownerToken,
      commandKey: 'f1-9b-active-npn',
      batchKind: 'historical_sent',
      statementDate: '2026-07-15',
      reason: 'active affil test',
      agencyLines: [{
        entity: 'Beacon', writingNpn: '88888888', writingAgent: 'Affil Test',
        recordId: 'carrier_a~direct~AFF88~10.00~2026-07', sourceFile: 'aff.csv', sourceRowNo: 1,
        grossComm: '10.00', amount: '10.00',
      }],
      uplineLines: [],
    });
    const resolved88 = (await env.pool.query(
      "SELECT writing_person_id FROM coherence.statement_agency_lines WHERE writing_npn = '88888888'",
    )).rows[0];
    assert.equal(resolved88.writing_person_id, activeAgent88);
  });

  await t.test('Fix1-9A [Resolver]: _resolve_entity_org_id and p_entity_map accept only company/agency/team orgs in tenant tree', async () => {
    for (const [badLabel, badEntity, badOrgId] of [
      ['other_company', 'Northstar', ids.northstarOrg],
      ['lead_vendor', 'LeadCo', leadVendorOrg],
      ['referral_firm', 'RefCo', refFirmOrg],
      ['orphan_agency', 'Orphan Agency', orphanAgencyOrg],
      ['platform_root', 'Nusear', ids.rootOrg],
    ]) {
      await assert.rejects(
        () => runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
          c.query('SELECT * FROM coherence.backfill_iam_foreign_keys($1::jsonb)', [JSON.stringify({ [badEntity]: badOrgId })])
        )),
        /INVALID_ENTITY_MAP/i,
        `p_entity_map must reject ${badLabel}`,
      );
    }
    await assert.rejects(
      () => env.commands.recordStatementBatch({
        dbToken: env.ownerToken,
        commandKey: 'f1-9a-bad-auto',
        batchKind: 'historical_sent',
        statementDate: '2026-07-10',
        reason: 'bad auto entity test',
        agencyLines: [{
          entity: 'LeadCo', writingNpn: null, writingAgent: null,
          recordId: 'carrier_a~direct~LEADCO~10.00~2026-07', sourceFile: 'lead.csv', sourceRowNo: 1,
          grossComm: '10.00', amount: '10.00',
        }],
        uplineLines: [],
      }),
      /UNMAPPED_ENTITY/i,
      'auto-resolve must not match lead_vendor org',
    );
  });

  await t.test('Fix1-9A [Archived agency history]: Entity Manager and Nusear retain full visibility and $0.00 reconciliation for archived agency history while downline/siblings/include_descendants=false see 0 rows', async () => {
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.archive_harbor', commandKey: 'f1-9a-archive-harbor' });
      const prevOv = (await c.query(
        'SELECT id FROM iam.organization_versions WHERE organization_id = $1 AND superseded_by_id IS NULL',
        [ids.harborOrg],
      )).rows[0].id;
      await c.query(
        "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, replaces_id, journal_seq) VALUES ($1,$2,'harbor','Harbor','archived',$3,$4)",
        [randomUUID(), ids.harborOrg, prevOv, j.seq],
      );
      const prevEdge = (await c.query(
        'SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND superseded_by_id IS NULL',
        [ids.harborOrg],
      )).rows[0].id;
      await c.query(
        "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2026-01-01)'::daterange,'active',$4,$5)",
        [randomUUID(), ids.harborOrg, ids.acmeOrg, prevEdge, j.seq],
      );
    });

    for (const [label, pid] of [['entity_manager', ids.acmeEntityMgr], ['nusear_owner', ids.nusearOwner]]) {
      await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
        const bob = (await c.query("SELECT run_id, entity, amount, upline_amount FROM app_views.coherence_bob WHERE entity = 'Harbor' ORDER BY run_id")).rows;
        assert.equal(bob.length, 2, `${label} must still see archived Harbor policies across R1 & R2`);
        assert.ok(bob.every((r) => r.amount === '200.00' && r.upline_amount === '50.00'), `${label} must still see archived Harbor dollars`);

        const curPol = (await c.query("SELECT run_id, amount FROM app_views.v_current_policy_periods WHERE entity = 'Harbor'")).rows;
        assert.equal(curPol.length, 1);
        assert.equal(curPol[0].run_id, r2.runId);
        assert.equal(curPol[0].amount, '200.00');

        const stLines = (await c.query("SELECT amount, gross_comm FROM app_views.coherence_statement_agency_lines WHERE entity = 'Harbor'")).rows;
        assert.equal(stLines.length, 2);
        assert.ok(stLines.every((r) => r.amount === '200.00' && r.gross_comm === '250.00'));

        const upLines = (await c.query("SELECT amount FROM app_views.coherence_statement_upline_lines WHERE source_entity = 'Harbor'")).rows;
        assert.equal(upLines.length, 2);
        assert.ok(upLines.every((r) => r.amount === '50.00'));

        const led = (await c.query("SELECT downline_amount, upline_amount FROM app_views.coherence_ledger WHERE entity = 'Harbor'")).rows;
        assert.equal(led.length, 2);

        const recon = (await c.query('SELECT statement_entity, variance, reconciled FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid', [r1.runId])).rows;
        assert.ok(recon.some((r) => r.statement_entity === 'Harbor' && r.reconciled === true && r.variance === '0.00'));
        assert.ok(recon.every((r) => r.reconciled === true && r.variance === '0.00'));
      });
    }

    for (const [label, pid] of [
      ['archived_harbor_retention', ids.harborRetention],
      ['archived_harbor_agent', ids.agentHarbor],
      ['sibling_beacon_mgr', ids.beaconManager],
      ['northstar_operator', ids.northstarOperator],
      ['acme_no_descendants', acmeNoDescPerson],
    ]) {
      await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
        const cnt = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'Harbor'")).rows[0].n;
        assert.equal(cnt, 0, `${label} must see 0 archived Harbor rows`);
      });
    }
  });
});

test('Layer 7B [Fix1-6, Fix1-7, Fix1-10, Fix1-11, Fix1-12 Note - Service Principal, save_review_decisions, accept/reject_review_submission, finish_attempt & import_historical_run]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv({ initCompany: false });
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const tok = (personId, viewAsPersonId = null) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId });
  const ownerTok = tok(ids.nusearOwner);
  const operatorTok = tok(ids.nusearOperator);
  const workerTok = tok(ids.workerService);
  const reqSha = (label) => sha256Hex(`f1-cmd:${label}`);

  const makeFileObj = (storeKind, text) => {
    const fp = fingerprintBytes(Buffer.from(text, 'utf8'));
    return { store_kind: storeKind, sha256: fp.sha256, byte_size: fp.byteSize, md5_b64: fp.md5B64, crc32c_b64: fp.crc32cB64, object_name: `objects/${fp.sha256}` };
  };

  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query("SELECT app_cmd.coherence_init_company($1, $2, 'acme', 'Acme', 'coherence')", ['f1-init', reqSha('init')])
  ));
  const codeFiles = ['git', 'man', 'lock', 'whl', 'wrap'].map((k) => makeFileObj('nusear_code', `code-${k}`));
  const inFile = makeFileObj('company_data', 'k,v\n1,2\n');
  const ovFile = makeFileObj('company_data', 'record_id,disposition\n');
  const artFile = makeFileObj('company_data', 'col\nval\n');
  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query('SELECT app_cmd.coherence_register_stored_files($1, $2, $3::jsonb)', [
      'f1-sf', reqSha('sf'), JSON.stringify([...codeFiles, inFile, ovFile, artFile]),
    ])
  ));
  const engId = randomUUID();
  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query('SELECT app_cmd.coherence_register_engine_version($1, $2, $3::jsonb)', [
      'f1-eng', reqSha('eng'), JSON.stringify({
        id: engId, label: 'eng-f1', coherence_commit: 'abcdef1', engine_kind: 'engine_copy',
        git_bundle_sha256: codeFiles[0].sha256, code_manifest_sha256: codeFiles[1].sha256,
        python_lock_sha256: codeFiles[2].sha256, python_wheels_sha256: codeFiles[3].sha256,
        wrapper_bundle_sha256: codeFiles[4].sha256, nusear_commit: '1234567',
        overlay_check_sha256: sha256Hex('ovchk'),
        toolchain: { os: 'Linux', os_version: '6', arch: 'x64', python: '3.12', uv: '0.5', tz: 'America/New_York', lang: 'en_US.UTF-8', lc_all: 'en_US.UTF-8', pythonutf8: '1' },
      }),
    ])
  ));
  await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
    c.query("SELECT app_cmd.coherence_publish_input_version($1, $2, NULL, 'standing', 'upload', 'seed', $3::jsonb)", [
      'f1-iv', reqSha('iv'), JSON.stringify([{ rel_path: 'Carrier/in.csv', file_sha256: inFile.sha256 }]),
    ])
  ));
  const baseDcRes = await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query('SELECT app_cmd.coherence_record_decision_baseline($1, $2, $3::jsonb) AS res', [
      'f1-base-dc', reqSha('base-dc'), JSON.stringify({ commit_kind: 'historical_baseline', header_contract: 'v2', imported: true, decisions: [] }),
    ])
  ));
  const baseCommitId = baseDcRes.rows[0].res.decision_commit_id;

  const withWorkerSlot = async (fn) => {
    const slotClient = await env.pool.connect();
    const ok = (await slotClient.query('SELECT pg_catalog.pg_try_advisory_lock(coherence.slot_class_id(), coherence.slot_obj_id()) AS ok')).rows[0].ok;
    assert.equal(ok, true);
    try {
      const execTx = async (sqlFn) => {
        await slotClient.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
        try {
          await slotClient.query('SET LOCAL ROLE platform_worker');
          await slotClient.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [workerTok]);
          const res = await sqlFn(slotClient);
          await slotClient.query('COMMIT');
          return res;
        } catch (err) {
          await slotClient.query('ROLLBACK').catch(() => {});
          throw err;
        }
      };
      return await fn(execTx);
    } finally {
      await slotClient.query('SELECT pg_catalog.pg_advisory_unlock(coherence.slot_class_id(), coherence.slot_obj_id())').catch(() => {});
      slotClient.release();
    }
  };

  await t.test('Fix1-10: service principal records recorded_as = service (never nusear_support) and is refused on human-only commands', async () => {
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.grant_svc_human_test', commandKey: 'f1-10-svc-right' });
      await c.query(
        "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,'act:coherence.run.launch','active',$3)",
        [randomUUID(), ids.roleWorkerService, j.seq],
      );
    });
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: workerTok, readOnly: false, serializable: true }, (c) => (
        c.query("SELECT app_cmd.coherence_launch_run($1, $2, NULL, DATE '2026-10-15', $3::uuid)", ['svc-launch-bad', reqSha('svc-launch-bad'), engId])
      )),
      (err) => err?.code === '42501' && /HUMAN_ONLY/i.test(err.message),
      'service principal must get 42501 HUMAN_ONLY on human-only command even when holding the right',
    );

    await runAsRole(env.pool, 'platform_worker', { token: workerTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_record_check($1, $2, 'chain', true, '{\"ok\":true}'::jsonb)", ['f1-svc-chk', reqSha('svc-chk')])
    ));
    const svcCheckAudit = (await env.pool.query(
      "SELECT recorded_as, actor_person_id FROM platform.audit_journal WHERE command_key = 'coherence:f1-svc-chk'",
    )).rows[0];
    assert.equal(svcCheckAudit.recorded_as, 'service', 'service principal must record recorded_as=service, never nusear_support');
    assert.equal(svcCheckAudit.actor_person_id, ids.workerService);
    const svcCheckJe = (await env.pool.query(
      "SELECT acting_for FROM coherence.journal_entries WHERE command_key = 'f1-svc-chk'",
    )).rows[0];
    assert.equal(svcCheckJe.acting_for, null, 'service principal must record acting_for=NULL in coherence.journal_entries');
  });

  // Launch run 1 for Fix1-7 (finish_attempt) & Fix1-11 (save_review_decisions)
  const l1 = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
    c.query("SELECT app_cmd.coherence_launch_run($1, $2, NULL, DATE '2026-11-01', $3::uuid) AS res", ['f1-l1', reqSha('l1'), engId])
  ))).rows[0].res;
  const run1Id = l1.run_id;
  let reqId = l1.step_request_id;
  await withWorkerSlot(async (execTx) => {
    for (const step of ['assign', 'attribute', 'bible']) {
      await execTx((c) => c.query(
        'SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, $4, $5::uuid)',
        [`f1-st-${step}`, reqSha(`st-${step}`), run1Id, step, reqId],
      ));
      const finPayload = {
        run_id: run1Id, step, attempt_no: 1, born: '2026-11-01T12:00:00Z',
        artifacts: [{ rel_path: `out/${step}.csv`, artifact_kind: 'data', store_kind: 'company_data', file_sha256: artFile.sha256 }],
        continue_to_next_step: step !== 'bible',
      };
      if (step === 'bible') {
        finPayload.review_queue_items = [
          { item_order: 1, surface: 'bible', record_id: 'policy:carrier_a:P1#effective:2026-10-01', case_kind: 'mismatch', entity: 'Beacon', npn: '11111111', amount: '80.00', needs_reconfirm: false },
        ];
        finPayload.generated_overlays = [
          { decision_commit_id: baseCommitId, purpose: 'bible_review', header_contract: 'v2', row_count: 0, file_sha256: ovFile.sha256 },
        ];
      }
      const fin = (await execTx((c) => c.query(
        'SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb) AS res',
        [`f1-fin-${step}`, reqSha(`fin-${step}`), JSON.stringify(finPayload)],
      ))).rows[0].res;
      reqId = fin.next_request_id;
    }
  });

  await t.test('Fix1-7a: finish_attempt writes review_queue_items and generated_overlays atomically in same journal entry', async () => {
    assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.review_queue_items WHERE run_id = $1::uuid', [run1Id])).rows[0].n, 1);
    assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.generated_overlays WHERE run_id = $1::uuid', [run1Id])).rows[0].n, 1);
  });

  await t.test('Fix1-11: save_review_decisions refuses duplicate keys within a save and unchanged re-save', async () => {
    const seqBeforeSave = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [run1Id])).rows[0].s);
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
        c.query("SELECT app_cmd.coherence_save_review_decisions($1, $2, $3, $4::uuid, 'bible', $5::jsonb)", [
          'f1-dup-key', reqSha('dup-key'), seqBeforeSave, run1Id, JSON.stringify([
            { record_id: 'policy:carrier_a:P1#effective:2026-10-01', disposition: 'CONFIRM' },
            { record_id: 'policy:carrier_a:P1#effective:2026-10-01', disposition: 'CONFIRM' },
          ]),
        ])
      )),
      (err) => err?.code === '23505' && /DUPLICATE_DECISION_KEY/i.test(err.message),
      'save_review_decisions must refuse duplicate record_id keys within one save',
    );
    const firstSave = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_save_review_decisions($1, $2, $3, $4::uuid, 'bible', $5::jsonb) AS res", [
        'f1-save-1', reqSha('save-1'), seqBeforeSave, run1Id, JSON.stringify([
          { record_id: 'policy:carrier_a:P1#effective:2026-10-01', disposition: 'CONFIRM', note: 'first' },
        ]),
      ])
    ))).rows[0].res;
    assert.ok(firstSave.decision_commit_id);

    const adjReq1 = (await env.pool.query("SELECT id FROM coherence.step_requests WHERE run_id = $1::uuid AND step = 'adjust' ORDER BY journal_seq DESC LIMIT 1", [run1Id])).rows[0].id;
    await withWorkerSlot(async (execTx) => {
      await execTx((c) => c.query("SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, 'adjust', $4::uuid)", ['f1-st-adj1', reqSha('st-adj1'), run1Id, adjReq1]));
      await execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb)', [
        'f1-fin-adj1', reqSha('fin-adj1'), JSON.stringify({ run_id: run1Id, step: 'adjust', attempt_no: 1, born: '2026-11-01T12:05:00Z', artifacts: [], continue_to_next_step: false }),
      ]));
    });
    const seqAfterAdj1 = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [run1Id])).rows[0].s);
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
        c.query("SELECT app_cmd.coherence_save_review_decisions($1, $2, $3, $4::uuid, 'bible', $5::jsonb)", [
          'f1-unchanged', reqSha('unchanged'), seqAfterAdj1, run1Id, JSON.stringify([
            { record_id: 'policy:carrier_a:P1#effective:2026-10-01', disposition: 'CONFIRM', note: 'first' },
          ]),
        ])
      )),
      (err) => err?.code === '23514' && /DUPLICATE_REVIEW_SAVE/i.test(err.message),
      'save_review_decisions must refuse unchanged re-save',
    );
    await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_save_review_decisions($1, $2, $3, $4::uuid, 'bible', $5::jsonb)", [
        'f1-changed', reqSha('changed'), seqAfterAdj1, run1Id, JSON.stringify([
          { record_id: 'policy:carrier_a:P1#effective:2026-10-01', disposition: 'CORRECT', agency: 'Beacon', note: 'updated' },
        ]),
      ])
    ));
  });

  await t.test('Fix1-7b: finish_attempt on emit materializes all 7 BoB/statement/ledger tables in the same journal entry', async () => {
    const adjReq2 = (await env.pool.query("SELECT id FROM coherence.step_requests WHERE run_id = $1::uuid AND step = 'adjust' ORDER BY journal_seq DESC LIMIT 1", [run1Id])).rows[0].id;
    await withWorkerSlot(async (execTx) => {
      await execTx((c) => c.query("SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, 'adjust', $4::uuid)", ['f1-st-adj2', reqSha('st-adj2'), run1Id, adjReq2]));
      await execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb)', [
        'f1-fin-adj2', reqSha('fin-adj2'), JSON.stringify({ run_id: run1Id, step: 'adjust', attempt_no: 2, born: '2026-11-01T12:10:00Z', artifacts: [], continue_to_next_step: false }),
      ]));
    });
    const seqAfterAdj2 = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [run1Id])).rows[0].s);
    const adjSaveRes = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_save_review_decisions($1, $2, $3, $4::uuid, 'adjust', '[]'::jsonb) AS res", [
        'f1-adj-save', reqSha('adj-save'), seqAfterAdj2, run1Id,
      ])
    ))).rows[0].res;
    const confEmitRes = (await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_confirm_emit($1, $2, NULL, $3::uuid, $4::uuid, 'create statements for 2026-11-01') AS res", [
        'f1-conf-emit', reqSha('conf-emit'), run1Id, adjSaveRes.review_save_id,
      ])
    ))).rows[0].res;

    await withWorkerSlot(async (execTx) => {
      await execTx((c) => c.query("SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, 'emit', $4::uuid)", [
        'f1-st-emit', reqSha('st-emit'), run1Id, confEmitRes.step_request_id,
      ]));
      const finEmitRes = (await execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb) AS res', [
        'f1-fin-emit', reqSha('fin-emit'), JSON.stringify({
          run_id: run1Id, step: 'emit', attempt_no: 1, born: '2026-11-01T12:15:00Z',
          artifacts: [{ rel_path: 'emits/statements_20261101.csv', artifact_kind: 'data', store_kind: 'company_data', file_sha256: artFile.sha256 }],
          continue_to_next_step: false,
          emit_materialization: {
            statement_batch: { batch_kind: 'run_emission', statement_date: '2026-11-01', reason: 'emit via finish_attempt' },
            run_materialization: { statement_date: '2026-11-01', reconciliation_mode: 'strict_entity_ledger', corpus_tail: '2026-11', agency_start: '2026-01-01' },
            agency_lines: [{
              line_no: 1, entry_kind: 'run_emission', run_action: 'NEW', entity: 'Beacon',
              organization_id: ids.beaconOrg, writing_npn: '11111111', writing_person_id: ids.agentA,
              writing_agent: 'Sam Seller', record_id: 'carrier_a~direct~P1~100.00~2026-11',
              source_file: 'carrier_a.csv', source_row_no: 1, src_type: 'direct', carrier: 'carrier_a',
              policy_id: 1, tx_id: 1, payment_date: '2026-11-01', gross_comm: '100.00', amount: '80.00',
            }],
            upline_lines: [{
              line_no: 1, entry_kind: 'run_emission', run_action: 'NEW', source_entity: 'Beacon', marked_sent: true,
              organization_id: ids.beaconOrg, writing_npn: '11111111', writing_person_id: ids.agentA,
              writing_agent: 'Sam Seller', record_id: 'carrier_a~direct~P1~100.00~2026-11',
              source_file: 'carrier_a.csv', source_row_no: 1, src_type: 'direct', carrier: 'carrier_a',
              policy_id: 1, tx_id: 1, payment_date: '2026-11-01', gross_comm: '100.00', amount: '20.00',
            }],
            bob_policies: [{
              policy_id: 1, external_policy_id: 'POL-F1', carrier: 'carrier_a', member: 'Pat Sample',
              writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
              organization_id: ids.beaconOrg, writing_person_id: ids.agentA, status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE_PAYING',
            }],
            bob_financials: [{
              policy_id: 1, entity: 'Beacon', writing_npn: '11111111',
              organization_id: ids.beaconOrg, writing_person_id: ids.agentA,
              amount: '80.00', upline_amount: '20.00',
            }],
            ledger_rows: [{
              tx_id: 1, record_id: 'carrier_a~direct~P1~100.00~2026-11', external_policy_id: 'POL-F1', policy_id: 1,
              src_type: 'direct', carrier: 'carrier_a', member: 'Pat Sample', statement_date: '2026-11-01', payment_date: '2026-11-01',
              gross_comm: '100.00', commission_amount: '100.00', downline_amount: '80.00', upline_amount: '20.00',
              writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
              organization_id: ids.beaconOrg, writing_person_id: ids.agentA, cbob_c: true, cbob_s: false, sf: true,
            }],
          },
        }),
      ]))).rows[0].res;
      assert.ok(finEmitRes.statement_batch_id, 'finish_attempt on emit must materialize and return statement_batch_id');
    });
    assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.run_materializations WHERE run_id = $1::uuid', [run1Id])).rows[0].n, 1);
  });

  await t.test('Fix1-6 & Fix1-12 Note: accept_review_submission records submitting person, supersedes finished Adjust on Bible re-save, refuses stale expected_journal_seq (40001), and reject_review_submission writes audit_journal', async () => {
    const l2 = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_launch_run($1, $2, NULL, DATE '2026-12-01', $3::uuid) AS res", ['f1-l2', reqSha('l2'), engId])
    ))).rows[0].res;
    const run2Id = l2.run_id;
    let req2Id = l2.step_request_id;
    await withWorkerSlot(async (execTx) => {
      for (const step of ['assign', 'attribute', 'bible']) {
        await execTx((c) => c.query('SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, $4, $5::uuid)', [`f1-r2-st-${step}`, reqSha(`r2-st-${step}`), run2Id, step, req2Id]));
        const fin = (await execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb) AS res', [
          `f1-r2-fin-${step}`, reqSha(`r2-fin-${step}`), JSON.stringify({ run_id: run2Id, step, attempt_no: 1, born: '2026-12-01T12:00:00Z', artifacts: [], continue_to_next_step: step !== 'bible' }),
        ]))).rows[0].res;
        req2Id = fin.next_request_id;
      }
    });

    const r2Seq1 = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [run2Id])).rows[0].s);
    const revCsv1 = makeFileObj('company_data', 'record_id,disposition\nk1,CONFIRM\n');
    const sub1 = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_submit_review($1, $2, $3, $4::uuid, 'bible', $5) AS res", ['f1-sub1', reqSha('sub1'), r2Seq1, run2Id, revCsv1.sha256])
    ))).rows[0].res;

    let acc1Res;
    await withWorkerSlot(async (execTx) => {
      acc1Res = (await execTx((c) => c.query('SELECT app_cmd.coherence_accept_review_submission($1, $2, $3::jsonb) AS res', [
        'f1-acc1', reqSha('acc1'), JSON.stringify({
          submission_id: sub1.submission_id,
          stored_file: revCsv1,
          header_kind: 'v2',
          row_count: 1,
          added_rows: [{ row_no: 1, record_id: 'k1', disposition: 'CONFIRM' }],
        }),
      ]))).rows[0].res;
    });
    assert.ok(acc1Res.review_save_id);
    const acc1Je = (await env.pool.query('SELECT actor, acting_for FROM coherence.journal_entries WHERE seq = $1', [acc1Res.journal_seq])).rows[0];
    assert.equal(acc1Je.actor, ids.nusearOperator, 'accept_review_submission must record submitting person in coherence.journal_entries.actor');
    assert.equal(acc1Je.acting_for, 'nusear_support');

    const r2AdjReq1 = (await env.pool.query("SELECT id FROM coherence.step_requests WHERE run_id = $1::uuid AND step = 'adjust' ORDER BY journal_seq DESC LIMIT 1", [run2Id])).rows[0].id;
    await withWorkerSlot(async (execTx) => {
      await execTx((c) => c.query("SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, 'adjust', $4::uuid)", ['f1-r2-st-adj1', reqSha('r2-st-adj1'), run2Id, r2AdjReq1]));
      await execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb)', [
        'f1-r2-fin-adj1', reqSha('r2-fin-adj1'), JSON.stringify({ run_id: run2Id, step: 'adjust', attempt_no: 1, born: '2026-12-01T12:05:00Z', artifacts: [], continue_to_next_step: false }),
      ]));
    });
    const r2Seq2 = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [run2Id])).rows[0].s);
    const revCsv2 = makeFileObj('company_data', 'record_id,disposition\nk1,CONFIRM\nk2,CONFIRM\n');
    const sub2 = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_submit_review($1, $2, $3, $4::uuid, 'bible', $5) AS res", ['f1-sub2', reqSha('sub2'), r2Seq2, run2Id, revCsv2.sha256])
    ))).rows[0].res;
    await withWorkerSlot(async (execTx) => {
      const acc2 = (await execTx((c) => c.query('SELECT app_cmd.coherence_accept_review_submission($1, $2, $3::jsonb) AS res', [
        'f1-acc2', reqSha('acc2'), JSON.stringify({
          submission_id: sub2.submission_id,
          stored_file: revCsv2,
          header_kind: 'v2',
          row_count: 2,
          extends_sha256: revCsv1.sha256,
          shared_row_count: 1,
          added_rows: [{ row_no: 2, record_id: 'k2', disposition: 'CONFIRM' }],
        }),
      ]))).rows[0].res;
      assert.ok(acc2.review_save_id);
    });
    const supAdjCnt = (await env.pool.query(
      "SELECT COUNT(*)::int AS n FROM coherence.step_attempt_events WHERE run_id = $1::uuid AND step = 'adjust' AND attempt_no = 1 AND event_kind = 'superseded'",
      [run2Id],
    )).rows[0].n;
    assert.equal(supAdjCnt, 1, 'Bible re-save via accept_review_submission must supersede finished Adjust attempt');

    const r2AdjReq2 = (await env.pool.query("SELECT id FROM coherence.step_requests WHERE run_id = $1::uuid AND step = 'adjust' ORDER BY journal_seq DESC LIMIT 1", [run2Id])).rows[0].id;
    await withWorkerSlot(async (execTx) => {
      await execTx((c) => c.query("SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, 'adjust', $4::uuid)", ['f1-r2-st-adj2', reqSha('r2-st-adj2'), run2Id, r2AdjReq2]));
      await execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb)', [
        'f1-r2-fin-adj2', reqSha('r2-fin-adj2'), JSON.stringify({ run_id: run2Id, step: 'adjust', attempt_no: 2, born: '2026-12-01T12:10:00Z', artifacts: [], continue_to_next_step: false }),
      ]));
    });
    const r2Seq3 = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [run2Id])).rows[0].s);
    const revCsv3 = makeFileObj('company_data', 'record_id,disposition\nk1,CONFIRM\nk2,CONFIRM\nk3,CONFIRM\n');
    const sub3 = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_submit_review($1, $2, $3, $4::uuid, 'adjust', $5) AS res", ['f1-sub3', reqSha('sub3'), r2Seq3, run2Id, revCsv3.sha256])
    ))).rows[0].res;
    // Advance run2's latest journal_seq (via generated_overlay on run2) so sub3.expected_journal_seq becomes stale!
    await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_record_generated_overlay($1, $2, $3::uuid, $4::uuid, 'adjust_review', 'v2', 0, $5::jsonb)", [
        'f1-r2-ov-advance', reqSha('r2-ov-advance'), baseCommitId, run2Id, JSON.stringify(ovFile),
      ])
    ));
    await withWorkerSlot(async (execTx) => {
      await assert.rejects(
        () => execTx((c) => c.query('SELECT app_cmd.coherence_accept_review_submission($1, $2, $3::jsonb)', [
          'f1-acc3-stale', reqSha('acc3-stale'), JSON.stringify({
            submission_id: sub3.submission_id,
            stored_file: revCsv3,
            header_kind: 'v2',
            row_count: 3,
            extends_sha256: revCsv2.sha256,
            shared_row_count: 2,
            added_rows: [{ row_no: 3, record_id: 'k3', disposition: 'CONFIRM' }],
          }),
        ])),
        (err) => err?.code === '40001',
        'stale expected_journal_seq in accept_review_submission must fail with SQLSTATE 40001',
      );
      await execTx((c) => c.query("SELECT app_cmd.coherence_reject_review_submission($1::uuid, 'rejected', 'stale run')", [sub3.submission_id]));
    });
    const rejAudit = (await env.pool.query(
      "SELECT command_kind, recorded_as, actor_person_id, body FROM platform.audit_journal WHERE command_kind = 'coherence.reject_review_submission'",
    )).rows;
    assert.equal(rejAudit.length, 1, 'reject_review_submission must write platform.audit_journal');
    assert.equal(rejAudit[0].recorded_as, 'service');
    assert.equal(rejAudit[0].actor_person_id, ids.workerService);
    assert.equal(rejAudit[0].body.submission_id, sub3.submission_id);
  });

  await t.test('Fix1-7c: import_historical_run writes attempts, artifacts, queue items, decision commits, decisions, review saves, overlays, approvals, and extra imported files atomically', async () => {
    const impDcId = randomUUID();
    const impSaveId = randomUUID();
    const impRunId = randomUUID();
    const impAfFile = makeFileObj('company_data', 'imp-approvals-csv');
    const impOvFile = makeFileObj('company_data', 'imp-generated-overlay');
    const impExtraFile = makeFileObj('company_data', 'imp-extra-audit');
    const impRes = (await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
      c.query('SELECT app_cmd.coherence_import_historical_run($1, $2, $3::jsonb) AS res', [
        'f1-imp-full', reqSha('imp-full'), JSON.stringify({
          run: { id: impRunId, origin: 'company_import', statement_date: '2026-06-30', folder_number: 1, emit_mode: 'coherence', source_folder: 'company-runs/2026-06-30' },
          input_version: { reason: 'full historical import via app_cmd' },
          input_entries: [{ rel_path: 'Carrier/in.csv', file_sha256: inFile.sha256 }],
          stored_files: [impAfFile, impOvFile, impExtraFile],
          approvals_files: [{
            file_sha256: impAfFile.sha256, header_kind: 'v2', row_count: 1, shared_row_count: 0,
            added_rows: [{ row_no: 1, record_id: 'imp-rec-1', disposition: 'CONFIRM' }],
          }],
          step_attempts: [{
            step: 'bible', attempt_no: 1, born: '2026-06-30T10:00:00Z',
            artifacts: [{ rel_path: 'bible/bible.csv', artifact_kind: 'data', store_kind: 'company_data', file_sha256: artFile.sha256 }],
          }],
          review_queue_items: [{
            item_order: 1, surface: 'bible', record_id: 'imp-rec-1', case_kind: 'review', entity: 'Beacon',
          }],
          decision_commits: [{
            id: impDcId, commit_kind: 'historical_overlay', header_contract: 'v2', cumulative_decision_count: 1,
          }],
          review_saves: [{
            id: impSaveId, surface: 'bible', approvals_file_sha256: impAfFile.sha256, decision_commit_id: impDcId,
          }],
          decisions: [{
            decision_commit_id: impDcId, row_order: 1, review_save_id: impSaveId, surface: 'bible',
            record_id: 'imp-rec-1', disposition: 'CONFIRM', decided_by: 'historical_import',
          }],
          generated_overlays: [{
            decision_commit_id: impDcId, purpose: 'historical_source', attempt_step: 'bible',
            header_contract: 'v2', row_count: 1, file_sha256: impOvFile.sha256,
          }],
          extra_imported_files: [{
            area: 'other', rel_path: 'audit.json', artifact_kind: 'data', store_kind: 'company_data',
            file_sha256: impExtraFile.sha256, metadata: { runId: '__THIS_RUN__' },
          }],
        }),
      ])
    ))).rows[0].res;
    assert.equal(impRes.run_id, impRunId);
    assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.step_attempt_events WHERE run_id = $1::uuid', [impRunId])).rows[0].n, 2);
    assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.artifacts a JOIN coherence.step_attempt_events e ON e.id = a.attempt_event_id WHERE e.run_id = $1::uuid', [impRunId])).rows[0].n, 1);
    assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.review_queue_items WHERE run_id = $1::uuid', [impRunId])).rows[0].n, 1);
    assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.review_saves WHERE run_id = $1::uuid', [impRunId])).rows[0].n, 1);
    assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.decisions WHERE decision_commit_id = $1::uuid', [impDcId])).rows[0].n, 1);
    assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.generated_overlays WHERE run_id = $1::uuid', [impRunId])).rows[0].n, 1);
    assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.approvals_files WHERE file_sha256 = $1', [impAfFile.sha256])).rows[0].n, 1);
    assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.approval_rows WHERE approvals_file_sha256 = $1', [impAfFile.sha256])).rows[0].n, 1);
    assert.equal((await env.pool.query('SELECT COUNT(*)::int AS n FROM coherence.imported_files WHERE file_sha256 = $1', [impExtraFile.sha256])).rows[0].n, 1);
  });

  await t.test('Full journal chain and commitments remain 100% valid', async () => {
    const chain = await verifyChain(env.pool);
    assert.equal(chain.passed, true, `verifyChain failed: ${chain.problems.join('; ')}`);
    const comm = await verifyCommitments(env.pool);
    assert.equal(comm.passed, true, `verifyCommitments failed: ${comm.problems.join('; ')}`);
  });
});

test('Layer 7B [Fix2-Blocker1 - Archived Child Latest Non-Future Edge & Team Move]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'f2-b1-r1', markSent: true });
  await runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
    c.query('SELECT * FROM coherence.backfill_iam_foreign_keys()')
  ));

  const tok = (personId, viewAsPersonId = null) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId });
  const harborManager = randomUUID();
  const movedOutTeam = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.fix2_b1_move', commandKey: 'f2-b1-move' });
    const seq = j.seq;

    // Seed Harbor agency manager (org_subtree, include_descendants = true on Harbor)
    await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [harborManager, seq]);
    await c.query(
      "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'Harbor Mgr','Harbor Mgr','harbor.mgr@acme.example','active',$3)",
      [randomUUID(), harborManager, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), harborManager, ids.harborOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
      [randomUUID(), harborManager, ids.roleAgencyManager, ids.harborOrg, seq],
    );

    // Move East Team from Beacon ([2020-01-01, 2025-06-01)) to Harbor ([2025-06-01, 2026-01-01)),
    // add a future edge back to Beacon ([2028-01-01, )) that MUST be ignored, then archive East Team.
    const prevEastEdge = (await c.query(
      'SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND superseded_by_id IS NULL',
      [ids.eastTeamOrg],
    )).rows[0].id;
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2025-06-01)'::daterange,'active',$4,$5)",
      [randomUUID(), ids.eastTeamOrg, ids.beaconOrg, prevEastEdge, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2025-06-01,2026-01-01)'::daterange,'active',$4)",
      [randomUUID(), ids.eastTeamOrg, ids.harborOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2028-01-01,)'::daterange,'active',$4)",
      [randomUUID(), ids.eastTeamOrg, ids.beaconOrg, seq],
    );
    const prevEastVer = (await c.query(
      'SELECT id FROM iam.organization_versions WHERE organization_id = $1 AND superseded_by_id IS NULL',
      [ids.eastTeamOrg],
    )).rows[0].id;
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, replaces_id, journal_seq) VALUES ($1,$2,'east_team','East Team','archived',$3,$4)",
      [randomUUID(), ids.eastTeamOrg, prevEastVer, seq],
    );

    // Seed a team that moved from Acme -> Northstar and was archived (must NOT be in Acme's tenant tree)
    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'team',$2)", [movedOutTeam, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'moved_out','Moved Out','archived',$3)",
      [randomUUID(), movedOutTeam, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2025-06-01)'::daterange,'active',$4)",
      [randomUUID(), movedOutTeam, ids.acmeOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2025-06-01,2026-01-01)'::daterange,'active',$4)",
      [randomUUID(), movedOutTeam, ids.northstarOrg, seq],
    );
  });

  await t.test('Fix2-B1a: moved-then-archived team is hidden from old Agency A (Beacon) manager and visible under new Agency B (Harbor) and company', async () => {
    await runAsPlatformApp(env.pool, { token: tok(ids.beaconManager), readOnly: true }, async (c) => {
      const bobEast = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'East Team'")).rows[0].n;
      const curEast = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.v_current_policy_periods WHERE entity = 'East Team'")).rows[0].n;
      const stEast = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines WHERE entity = 'East Team'")).rows[0].n;
      assert.equal(bobEast, 0, 'old Agency A (Beacon) manager must see 0 archived East Team rows in coherence_bob');
      assert.equal(curEast, 0, 'old Agency A (Beacon) manager must see 0 archived East Team rows in v_current_policy_periods');
      assert.equal(stEast, 0, 'old Agency A (Beacon) manager must see 0 archived East Team rows in statement_agency_lines');
    });

    await runAsPlatformApp(env.pool, { token: tok(harborManager), readOnly: true }, async (c) => {
      const bobEast = (await c.query("SELECT entity, amount FROM app_views.coherence_bob WHERE entity = 'East Team'")).rows;
      assert.equal(bobEast.length, 1, 'new Agency B (Harbor) manager must see archived East Team row');
      assert.equal(bobEast[0].amount, '90.00');
      const stEast = (await c.query("SELECT entity, amount FROM app_views.coherence_statement_agency_lines WHERE entity = 'East Team'")).rows;
      assert.equal(stEast.length, 1);
      assert.equal(stEast[0].amount, '90.00');
    });

    for (const [label, pid] of [['acme_entity_mgr', ids.acmeEntityMgr], ['nusear_owner', ids.nusearOwner]]) {
      await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
        const bobEast = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'East Team'")).rows[0].n;
        assert.equal(bobEast, 1, `${label} must still see archived East Team`);
      });
    }
  });

  await t.test('Fix2-B1b: org formerly under Acme and later moved to Northstar & archived stays in Acme tree (Item 4), while pure Northstar org is rejected', async () => {
    const pureNorthstarTeam = randomUUID();
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.seed_pure_ns_team', commandKey: 'f2-b1b-pure-ns' });
      await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'team',$2)", [pureNorthstarTeam, j.seq]);
      await c.query("INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'pure_ns','Pure Northstar','archived',$3)", [randomUUID(), pureNorthstarTeam, j.seq]);
      await c.query("INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2026-01-01)'::daterange,'active',$4)", [randomUUID(), pureNorthstarTeam, ids.northstarOrg, j.seq]);
    });

    // Former Acme org moved to Northstar and archived stays resolvable in Acme's working DB!
    await env.commands.recordStatementBatch({
      dbToken: env.ownerToken,
      commandKey: 'f2-b1b-moved-out',
      batchKind: 'historical_sent',
      statementDate: '2026-07-05',
      reason: 'moved-out team retained in Acme working DB',
      agencyLines: [{
        entity: 'Moved Out', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~MOVEDOUT~10.00~2026-07', sourceFile: 'moved.csv', sourceRowNo: 1,
        grossComm: '10.00', amount: '10.00',
      }],
      uplineLines: [],
    });
    const moRow = (await env.pool.query(
      "SELECT organization_id FROM coherence.statement_agency_lines WHERE entity = 'Moved Out'",
    )).rows[0];
    assert.equal(moRow.organization_id, movedOutTeam, 'movedOutTeam must resolve to its organization_id in Acme DB');

    // Pure Northstar org (never under Acme) is rejected by both backfill_iam_foreign_keys and live writes!
    await assert.rejects(
      () => runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
        c.query('SELECT * FROM coherence.backfill_iam_foreign_keys($1::jsonb)', [JSON.stringify({ 'Pure Northstar': pureNorthstarTeam })])
      )),
      /INVALID_ENTITY_MAP/i,
      'p_entity_map must refuse an org that never had an active edge under Acme',
    );
    await assert.rejects(
      () => env.commands.recordStatementBatch({
        dbToken: env.ownerToken,
        commandKey: 'f2-b1b-pure-ns-write',
        batchKind: 'historical_sent',
        statementDate: '2026-07-06',
        reason: 'pure Northstar org must fail',
        agencyLines: [{
          entity: 'Pure Northstar', writingNpn: null, writingAgent: null,
          recordId: 'carrier_a~direct~PURENS~10.00~2026-07', sourceFile: 'ns.csv', sourceRowNo: 1,
          grossComm: '10.00', amount: '10.00',
        }],
        uplineLines: [],
      }),
      /UNMAPPED_ENTITY/i,
      'auto-resolve must refuse an org that never belonged to Acme',
    );
  });
});

test('Layer 7B [Fix2-Blocker2 - Archived Descendants Full IAM Rules: Switches, View-as, Retirements, Env Scope, is_nusear_only, Dead Customer Grant, Active Child Under Archived Parent]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const r1 = await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'f2-b2-r1', markSent: true });
  await runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
    c.query('SELECT * FROM coherence.backfill_iam_foreign_keys()')
  ));

  const tok = (personId, viewAsPersonId = null) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId });

  await t.test('Fix2-B2a: switched-off or held archived agency (and switched-off/held active parent above archived team) blocks customer and View-as while Nusear internal bypasses', async () => {
    // Archive Harbor and East Team
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f2_b2a_arch', commandKey: 'f2-b2a-arch' });
      for (const [oid, slug, name] of [
        [ids.harborOrg, 'harbor', 'Harbor'],
        [ids.eastTeamOrg, 'east_team', 'East Team'],
      ]) {
        const prevOv = (await c.query('SELECT id FROM iam.organization_versions WHERE organization_id = $1 AND superseded_by_id IS NULL', [oid])).rows[0].id;
        await c.query(
          "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, replaces_id, journal_seq) VALUES ($1,$2,$3,$4,'archived',$5,$6)",
          [randomUUID(), oid, slug, name, prevOv, j.seq],
        );
      }
      // Switch archived Harbor OFF, switch active Beacon HELD (even give archived East Team an ON switch!)
      await c.query(
        "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','off','active',$3)",
        [randomUUID(), ids.harborOrg, j.seq],
      );
      await c.query(
        "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, hold_reason, status, journal_seq) VALUES ($1,$2,'coherence','held','compliance hold','active',$3)",
        [randomUUID(), ids.beaconOrg, j.seq],
      );
      await c.query(
        "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','on','active',$3)",
        [randomUUID(), ids.eastTeamOrg, j.seq],
      );
    });

    for (const [label, token] of [
      ['acme_entity_mgr', tok(ids.acmeEntityMgr)],
      ['nusear_view_as_entity_mgr', tok(ids.nusearOwner, ids.acmeEntityMgr)],
    ]) {
      await runAsPlatformApp(env.pool, { token, readOnly: true }, async (c) => {
        for (const [viewName, col, val] of [
          ['coherence_bob', 'entity', 'Harbor'],
          ['v_current_policy_periods', 'entity', 'Harbor'],
          ['coherence_statement_agency_lines', 'entity', 'Harbor'],
          ['coherence_statement_upline_lines', 'source_entity', 'Harbor'],
          ['coherence_ledger', 'entity', 'Harbor'],
          ['coherence_bob', 'entity', 'East Team'],
          ['coherence_statement_agency_lines', 'entity', 'East Team'],
          ['coherence_ledger', 'entity', 'East Team'],
        ]) {
          const n = (await c.query(`SELECT COUNT(*)::int AS n FROM app_views.${viewName} WHERE ${col} = $1`, [val])).rows[0].n;
          assert.equal(n, 0, `${label} must see 0 rows for switched-off/held ${val} in app_views.${viewName}`);
        }
      });
    }

    // Nusear Owner (internal, not viewing as) bypasses tool switches and still sees Harbor and East Team
    await runAsPlatformApp(env.pool, { token: tok(ids.nusearOwner), readOnly: true }, async (c) => {
      assert.equal((await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'Harbor'")).rows[0].n, 1);
      assert.equal((await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'East Team'")).rows[0].n, 1);
    });

    // Also test archived Harbor switched HELD (not just OFF)
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f2_b2a_held', commandKey: 'f2-b2a-held' });
      const prevTs = (await c.query(
        "SELECT id FROM iam.organization_tool_switches WHERE organization_id = $1 AND tool_id = 'coherence' AND superseded_by_id IS NULL",
        [ids.harborOrg],
      )).rows[0].id;
      await c.query(
        "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, hold_reason, status, replaces_id, journal_seq) VALUES ($1,$2,'coherence','held','archived hold','active',$3,$4)",
        [randomUUID(), ids.harborOrg, prevTs, j.seq],
      );
    });
    for (const [label, token] of [
      ['acme_entity_mgr_held', tok(ids.acmeEntityMgr)],
      ['view_as_entity_mgr_held', tok(ids.nusearOwner, ids.acmeEntityMgr)],
    ]) {
      const n = await runAsPlatformApp(env.pool, { token, readOnly: true }, async (c) => (
        (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'Harbor'")).rows[0].n
      ));
      assert.equal(n, 0, `${label} must see 0 rows when archived Harbor is held`);
    }
  });

  await t.test('Fix2-B2b: a dead customer grant with include_descendants=true cannot expand a live Nusear grant with include_descendants=false', async () => {
    const dualPerson = randomUUID();
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f2_b2b_dual', commandKey: 'f2-b2b-dual' });
      const seq = j.seq;
      // Switch Acme OFF (so every customer grant on Acme is DEAD, while Nusear internal grants on Acme stay alive)
      const prevAcmeTs = (await c.query(
        "SELECT id FROM iam.organization_tool_switches WHERE organization_id = $1 AND tool_id = 'coherence' AND superseded_by_id IS NULL",
        [ids.acmeOrg],
      )).rows[0].id;
      await c.query(
        "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq) VALUES ($1,$2,'coherence','off','active',$3,$4)",
        [randomUUID(), ids.acmeOrg, prevAcmeTs, seq],
      );
      await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [dualPerson, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'Dual Principal','Dual Principal','dual@nusear.example','active',$3)",
        [randomUUID(), dualPerson, seq],
      );
      // Both platform_root membership (for Nusear grant) and acmeOrg membership (for customer grant)
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), dualPerson, ids.rootOrg, seq],
      );
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), dualPerson, ids.acmeOrg, seq],
      );
      // Live Nusear grant on Acme with include_descendants = FALSE
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,false,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), dualPerson, ids.roleNusearAdmin, ids.acmeOrg, seq],
      );
      // Dead customer grant on Acme with include_descendants = TRUE (dead because Acme switch is OFF)
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), dualPerson, ids.roleEntityManager, ids.acmeOrg, seq],
      );
    });

    await runAsPlatformApp(env.pool, { token: tok(dualPerson), readOnly: true }, async (c) => {
      // Sees Acme's own house ledger row (via live Nusear grant with include_descendants=false),
      // and ZERO archived Harbor or East Team rows!
      const acmeLed = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger WHERE entity = 'Acme'")).rows[0].n;
      assert.equal(acmeLed, 1, 'live Nusear grant on Acme must still see Acme house row');
      const archBob = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity IN ('Harbor', 'East Team')")).rows[0].n;
      const archLed = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger WHERE entity IN ('Harbor', 'East Team')")).rows[0].n;
      const archUp = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_upline_lines WHERE source_entity IN ('Harbor', 'East Team')")).rows[0].n;
      assert.equal(archBob, 0, 'dead customer grant with descendants must NOT expand Nusear no-descendants grant in coherence_bob');
      assert.equal(archLed, 0, 'dead customer grant with descendants must NOT expand Nusear no-descendants grant in coherence_ledger');
      assert.equal(archUp, 0, 'dead customer grant with descendants must NOT expand Nusear no-descendants grant in statement_upline_lines');
    });
  });

  await t.test('Fix2-B2c: right_retirements, environment_scope, and is_nusear_only are enforced on archived descendants', async () => {
    // 1. Retire col:coherence.statement_cash in this DB -> even Nusear Owner sees NULL amount on archived Harbor!
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.retire_stmt_cash', commandKey: 'f2-b2c-retire' });
      await c.query(
        "INSERT INTO iam.right_retirements (right_id, reason, journal_seq) VALUES ('col:coherence.statement_cash', 'retired in test', $1)",
        [j.seq],
      );
    });
    await runAsPlatformApp(env.pool, { token: tok(ids.nusearOwner), readOnly: true }, async (c) => {
      const harborBob = (await c.query("SELECT amount FROM app_views.coherence_bob WHERE entity = 'Harbor'")).rows;
      assert.equal(harborBob.length, 1);
      assert.equal(harborBob[0].amount, null, 'retired col:coherence.statement_cash must mask amount to NULL on archived Harbor');
      const harborSt = (await c.query("SELECT amount FROM app_views.coherence_statement_agency_lines WHERE entity = 'Harbor'")).rows;
      assert.equal(harborSt.length, 1);
      assert.equal(harborSt[0].amount, null, 'retired col:coherence.statement_cash must mask statement amount to NULL on archived Harbor');
    });

    // 2. is_nusear_only = true tool: customer sees 0 archived Harbor rows (and cannot expand a Nusear no-desc grant!), Nusear Owner still sees them
    const envNusearOnly = await createCoherenceIamTestEnv();
    try {
      const w = await seedCoherenceIamWorld(envNusearOnly.pool, { coherenceToolNusearOnly: true });
      await seedPublishedRun(envNusearOnly, { statementDate: '2026-10-31', keyPrefix: 'f2-no', markSent: true });
      await runAsRole(envNusearOnly.pool, 'platform_migrator', { readOnly: false }, (c) => (
        c.query('SELECT * FROM coherence.backfill_iam_foreign_keys()')
      ));
      const dualNoDesc = randomUUID();
      await inSerializableTx(envNusearOnly.pool, async (c) => {
        const j = await appendAuditEntry(c, { environment: w.environment, commandKind: 'iam.f2_no_arch', commandKey: 'f2-no-arch' });
        const prevOv = (await c.query('SELECT id FROM iam.organization_versions WHERE organization_id = $1 AND superseded_by_id IS NULL', [w.ids.harborOrg])).rows[0].id;
        await c.query(
          "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, replaces_id, journal_seq) VALUES ($1,$2,'harbor','Harbor','archived',$3,$4)",
          [randomUUID(), w.ids.harborOrg, prevOv, j.seq],
        );
        await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [dualNoDesc, j.seq]);
        await c.query("INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'Dual NO','Dual NO','dual.no@nusear.example','active',$3)", [randomUUID(), dualNoDesc, j.seq]);
        await c.query("INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), dualNoDesc, w.ids.rootOrg, j.seq]);
        await c.query("INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), dualNoDesc, w.ids.acmeOrg, j.seq]);
        await c.query("INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,false,'org_subtree','[2020-01-01,)'::daterange,'active',$5)", [randomUUID(), dualNoDesc, w.ids.roleNusearAdmin, w.ids.acmeOrg, j.seq]);
        await c.query("INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)", [randomUUID(), dualNoDesc, w.ids.roleEntityManager, w.ids.acmeOrg, j.seq]);
      });
      const noTok = (pid) => mintSignedToken({ keyId: w.keyId, secretBytes: w.secretBytes, environment: w.environment, actorPersonId: pid });
      const custCnt = await runAsPlatformApp(envNusearOnly.pool, { token: noTok(w.ids.acmeEntityMgr), readOnly: true }, async (c) => (
        (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'Harbor'")).rows[0].n
      ));
      assert.equal(custCnt, 0, 'is_nusear_only tool must block customer access to archived Harbor');
      const dualCnt = await runAsPlatformApp(envNusearOnly.pool, { token: noTok(dualNoDesc), readOnly: true }, async (c) => (
        (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'Harbor'")).rows[0].n
      ));
      assert.equal(dualCnt, 0, 'dead customer grant on is_nusear_only tool must not expand Nusear no-desc grant');
      const ownerCnt = await runAsPlatformApp(envNusearOnly.pool, { token: noTok(w.ids.nusearOwner), readOnly: true }, async (c) => (
        (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'Harbor'")).rows[0].n
      ));
      assert.equal(ownerCnt, 1, 'Nusear internal still sees archived Harbor on is_nusear_only tool');
    } finally {
      await envNusearOnly.cleanup();
    }

    // 3. environment_scope = 'prod_only' on local DB blocks archived Harbor for BOTH customer and Nusear Owner
    const envProdOnly = await createCoherenceIamTestEnv();
    try {
      const w = await seedCoherenceIamWorld(envProdOnly.pool, { environment: 'local', bobReadEnvScope: 'prod_only' });
      await seedPublishedRun(envProdOnly, { statementDate: '2026-10-31', keyPrefix: 'f2-po', markSent: true });
      await runAsRole(envProdOnly.pool, 'platform_migrator', { readOnly: false }, (c) => (
        c.query('SELECT * FROM coherence.backfill_iam_foreign_keys()')
      ));
      await inSerializableTx(envProdOnly.pool, async (c) => {
        const j = await appendAuditEntry(c, { environment: w.environment, commandKind: 'iam.f2_po_arch', commandKey: 'f2-po-arch' });
        const prevOv = (await c.query('SELECT id FROM iam.organization_versions WHERE organization_id = $1 AND superseded_by_id IS NULL', [w.ids.harborOrg])).rows[0].id;
        await c.query(
          "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, replaces_id, journal_seq) VALUES ($1,$2,'harbor','Harbor','archived',$3,$4)",
          [randomUUID(), w.ids.harborOrg, prevOv, j.seq],
        );
      });
      const poTok = (pid) => mintSignedToken({ keyId: w.keyId, secretBytes: w.secretBytes, environment: w.environment, actorPersonId: pid });
      for (const [label, pid] of [['entity_mgr', w.ids.acmeEntityMgr], ['nusear_owner', w.ids.nusearOwner]]) {
        const cnt = await runAsPlatformApp(envProdOnly.pool, { token: poTok(pid), readOnly: true }, async (c) => (
          (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'Harbor'")).rows[0].n
        ));
        assert.equal(cnt, 0, `${label} must see 0 archived Harbor rows when bob.read is prod_only in local env`);
      }
    } finally {
      await envProdOnly.cleanup();
    }
  });

  await t.test('Fix2-B2d: active child (East Team) under archived parent (Beacon) stays visible to active ancestors with full-path switch enforcement, hidden from archived parent grant & siblings, and dropped if detached', async () => {
    const envAct = await createCoherenceIamTestEnv();
    try {
      const w = await seedCoherenceIamWorld(envAct.pool);
      const run = await seedPublishedRun(envAct, { statementDate: '2026-10-31', keyPrefix: 'f2-act', markSent: true });
      await runAsRole(envAct.pool, 'platform_migrator', { readOnly: false }, (c) => (
        c.query('SELECT * FROM coherence.backfill_iam_foreign_keys()')
      ));
      const aTok = (pid, va = null) => mintSignedToken({ keyId: w.keyId, secretBytes: w.secretBytes, environment: w.environment, actorPersonId: pid, viewAsPersonId: va });

      // Archive Beacon while leaving East Team ACTIVE with current edge East Team -> Beacon
      await inSerializableTx(envAct.pool, async (c) => {
        const j = await appendAuditEntry(c, { environment: w.environment, commandKind: 'iam.arch_beacon_only', commandKey: 'f2-arch-beacon-only' });
        const prevOv = (await c.query('SELECT id FROM iam.organization_versions WHERE organization_id = $1 AND superseded_by_id IS NULL', [w.ids.beaconOrg])).rows[0].id;
        await c.query(
          "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, replaces_id, journal_seq) VALUES ($1,$2,'beacon','Beacon','archived',$3,$4)",
          [randomUUID(), w.ids.beaconOrg, prevOv, j.seq],
        );
      });

      // 1. Active ancestor Acme (Entity Manager & Nusear Owner) keeps full visibility and $0.00 reconciliation for active East Team under archived Beacon
      for (const [label, pid] of [['entity_mgr', w.ids.acmeEntityMgr], ['nusear_owner', w.ids.nusearOwner]]) {
        await runAsPlatformApp(envAct.pool, { token: aTok(pid), readOnly: true }, async (c) => {
          const east = (await c.query("SELECT amount FROM app_views.coherence_bob WHERE entity = 'East Team'")).rows;
          assert.equal(east.length, 1, `${label} must keep visibility of active East Team under archived Beacon`);
          assert.equal(east[0].amount, '90.00');
          const recon = (await c.query('SELECT statement_entity, variance, reconciled FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid', [run.runId])).rows;
          assert.ok(recon.some((r) => r.statement_entity === 'East Team' && r.reconciled === true && r.variance === '0.00'));
          assert.ok(recon.every((r) => r.reconciled === true && r.variance === '0.00'));
        });
      }

      // 2. Archived Beacon's own manager and sibling Harbor Retention see 0 rows for East Team
      for (const [label, pid] of [['archived_beacon_mgr', w.ids.beaconManager], ['harbor_retention', w.ids.harborRetention]]) {
        const cnt = await runAsPlatformApp(envAct.pool, { token: aTok(pid), readOnly: true }, async (c) => (
          (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'East Team'")).rows[0].n
        ));
        assert.equal(cnt, 0, `${label} must see 0 East Team rows under archived Beacon`);
      }

      // 3. Switching archived Beacon HELD blocks active child East Team for Entity Manager AND View-as Entity Manager (full path enforced!)
      await inSerializableTx(envAct.pool, async (c) => {
        const j = await appendAuditEntry(c, { environment: w.environment, commandKind: 'iam.hold_arch_beacon', commandKey: 'f2-hold-arch-beacon' });
        await c.query(
          "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, hold_reason, status, journal_seq) VALUES ($1,$2,'coherence','held','archived parent hold','active',$3)",
          [randomUUID(), w.ids.beaconOrg, j.seq],
        );
      });
      for (const [label, token] of [
        ['entity_mgr_beacon_held', aTok(w.ids.acmeEntityMgr)],
        ['view_as_entity_mgr_beacon_held', aTok(w.ids.nusearOwner, w.ids.acmeEntityMgr)],
      ]) {
        const cnt = await runAsPlatformApp(envAct.pool, { token, readOnly: true }, async (c) => (
          (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'East Team'")).rows[0].n
        ));
        assert.equal(cnt, 0, `${label} must see 0 rows for active East Team when archived parent Beacon is held`);
      }

      // 4. Clearing Beacon's hold and switching active East Team OFF blocks East Team while Beacon stays visible
      await inSerializableTx(envAct.pool, async (c) => {
        const j = await appendAuditEntry(c, { environment: w.environment, commandKind: 'iam.east_off', commandKey: 'f2-east-off' });
        const prevBeaconTs = (await c.query(
          "SELECT id FROM iam.organization_tool_switches WHERE organization_id = $1 AND tool_id = 'coherence' AND superseded_by_id IS NULL",
          [w.ids.beaconOrg],
        )).rows[0].id;
        await c.query(
          "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq) VALUES ($1,$2,'coherence','on','active',$3,$4)",
          [randomUUID(), w.ids.beaconOrg, prevBeaconTs, j.seq],
        );
        await c.query(
          "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','off','active',$3)",
          [randomUUID(), w.ids.eastTeamOrg, j.seq],
        );
      });
      await runAsPlatformApp(envAct.pool, { token: aTok(w.ids.acmeEntityMgr), readOnly: true }, async (c) => {
        assert.equal((await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'Beacon'")).rows[0].n, 2);
        assert.equal((await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'East Team'")).rows[0].n, 0);
      });

      // 5. Detaching active East Team (closing its edge in the past while keeping status = 'active') drops it even for Nusear Owner
      await inSerializableTx(envAct.pool, async (c) => {
        const j = await appendAuditEntry(c, { environment: w.environment, commandKind: 'iam.detach_east', commandKey: 'f2-detach-east' });
        const prevEdge = (await c.query('SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND superseded_by_id IS NULL', [w.ids.eastTeamOrg])).rows[0].id;
        await c.query(
          "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2026-01-01)'::daterange,'active',$4,$5)",
          [randomUUID(), w.ids.eastTeamOrg, w.ids.beaconOrg, prevEdge, j.seq],
        );
      });
      const detachedCnt = await runAsPlatformApp(envAct.pool, { token: aTok(w.ids.nusearOwner), readOnly: true }, async (c) => (
        (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'East Team'")).rows[0].n
      ));
      assert.equal(detachedCnt, 0, 'detached active org with only expired edge must not be reachable under archived parent');
    } finally {
      await envAct.cleanup();
    }
  });
});

test('Layer 7B [Fix2-ShouldFix - Current Views No Stale Fallback, Reconciliation statement_cash & Single Scope, latest_journal_seq True Tip]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const tok = (personId, viewAsPersonId = null) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId });

  // R1 (2026-10-31, SENT): Beacon + East Team + Harbor + Acme house fee
  const r1 = await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'f2-sf-r1', markSent: true });

  // R2 (2026-11-30, SENT): ONLY Beacon (ZERO Harbor policies and ZERO Harbor ledger rows!)
  const beaconOnlyBob = [{
    external_policy_id: 'POL-R2-BEACON', policy_id: '1', carrier_policy_number: 'C-R2-1', crm_policy_number: 'CRM-R2-1',
    enrollment_code: 'ENR-R2-1', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Gold MA', simple_plan_type: 'MA',
    mbi: '1AB2-CD3-EF45', member: 'Pat Sample', dob: '1954-06-15', phone: '555-010-1001', email: 'pat@example.test',
    address: '100 Oak St', county: 'WAKE', state: 'NC',
    submission_date: '2026-10-10', origin_effective: '2026-11-01', effective_date: '2026-11-01', termination_date: '',
    min_date: '2026-10-10', anchor_date: '2026-10-10',
    amount: '80.00', upline_amount: '20.00', writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
    agency_id: 'AG-BEACON', status: 'ACTIVE_PAYING', conflicts: '', spine_source: 'cbob_c', confidence_level: '100',
  }];
  const beaconOnlyLedger = [{
    record_id: 'carrier_a~direct~PAT SAMPLE~100.00~2026-11', external_policy_id: 'POL-R2-BEACON', policy_id: '1', tx_id: '1',
    statement_name: 'carrier_a.csv', src_type: 'direct', carrier: 'carrier_a', mbi: '1AB2-CD3-EF45', member: 'Pat Sample',
    state: 'NC', plan_type: 'MA', simple_plan_type: 'MA',
    submission_date: '2026-10-10', origin_effective: '2026-11-01', effective_date: '2026-11-01', termination_date: '',
    earned_date: '2026-11-30', payment_date: '2026-11-30', statement_date: '2026-11-30', min_date: '2026-10-10',
    gross_comm: '100.00', revenue_type: 'commission', override_amount: '', commission_amount: '100.00', hra_amount: '', fee_amount: '', other_amount: '',
    downline_amount: '80.00', upline_amount: '20.00',
    writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon', payee_npn: '', agency_id: 'AG-BEACON',
    status: 'ACTIVE_PAYING', policy_status: 'active', cbob_c: 'true', cbob_s: 'false', sf: 'true', notes: '', coherent_notes: 'NEW',
  }];
  const beaconOnlyDataset = {
    canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, beaconOnlyBob),
    coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, beaconOnlyLedger),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, beaconOnlyLedger.map((r) => ({ ...r, run_action: 'NEW', run_statement_date: '2026-11-30', reversal_of: '', reason: 'new' }))),
    workingTxCsv: 'tx_id,filename,sheet_name,source_position\n1,carrier_a.xlsx,Commissions,10\n',
    emitMetadataJson: JSON.stringify({ statementDate: '2026-11-30', build: '009test', corpusTail: '2026-11', agencyStart: '2026-01-01', coherentStatus: { '1': 'ACTIVE_PAYING' }, coherentTrajectory: { '1': [['2026-11', 'ACTIVE_PAYING']] } }),
  };
  const r2 = await seedPublishedRun(env, { statementDate: '2026-11-30', keyPrefix: 'f2-sf-r2', markSent: true, dataset: beaconOnlyDataset });

  // R3 (2026-12-15, UNSENT): Beacon + East Team + Harbor + Acme
  const r3 = await seedPublishedRun(env, { statementDate: '2026-12-15', keyPrefix: 'f2-sf-r3', markSent: false });

  await runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
    c.query('SELECT * FROM coherence.backfill_iam_foreign_keys()')
  ));

  const harborLedgerReader = randomUUID();
  const noStmtCashPerson = randomUUID();
  const splitScopeReconPerson = randomUUID();
  const splitUnpubReconPerson = randomUUID();
  const roleHarborLedger = randomUUID();
  const roleNoStmtCash = randomUUID();
  const roleLedgerOnlyWide = randomUUID();
  const roleStmtsUplineCash = randomUUID();
  const roleUnpubOnly = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f2_sf_roles', commandKey: 'f2-sf-roles' });
    const seq = j.seq;
    for (const [rid, slug, name, rlist] of [
      [roleHarborLedger, 'harbor_ledger_ro', 'Harbor Ledger RO', ['act:coherence.ledger.read', 'col:coherence.upline_cash']],
      [roleNoStmtCash, 'recon_no_stmt_cash', 'Recon No Stmt Cash', ['act:coherence.ledger.read', 'act:coherence.statements.read', 'act:coherence.upline.read', 'col:coherence.upline_cash']],
      [roleLedgerOnlyWide, 'ledger_only_wide', 'Ledger Only Wide', ['act:coherence.ledger.read', 'col:coherence.upline_cash']],
      [roleStmtsUplineCash, 'stmts_upline_cash', 'Stmts Upline Cash', ['act:coherence.statements.read', 'act:coherence.upline.read', 'col:coherence.statement_cash']],
      [roleUnpubOnly, 'unpub_only', 'Unpub Only', ['act:coherence.unpublished.read']],
    ]) {
      await c.query('INSERT INTO iam.roles (id, slug, journal_seq) VALUES ($1,$2,$3)', [rid, slug, seq]);
      await c.query("INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,$3,false,false,true,'active',$4)", [randomUUID(), rid, name, seq]);
      for (const rightId of rlist) {
        await c.query("INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)", [randomUUID(), rid, rightId, seq]);
      }
    }
    for (const [pid, name, email, memOrg] of [
      [harborLedgerReader, 'Harbor Ledger Reader', 'hlr@acme.example', ids.harborOrg],
      [noStmtCashPerson, 'No Stmt Cash', 'nsc@acme.example', ids.acmeOrg],
      [splitScopeReconPerson, 'Split Scope Recon', 'ssr@acme.example', ids.acmeOrg],
      [splitUnpubReconPerson, 'Split Unpub Recon', 'sur@acme.example', ids.acmeOrg],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [pid, seq]);
      await c.query("INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,$3,$3,$4,'active',$5)", [randomUUID(), pid, name, email, seq]);
      await c.query("INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), pid, memOrg, seq]);
    }
    for (const [pid, rid, oid, incDesc] of [
      [harborLedgerReader, roleHarborLedger, ids.harborOrg, true],
      [noStmtCashPerson, roleNoStmtCash, ids.acmeOrg, true],
      // splitScopeReconPerson: ledger+upline_cash with include_descendants=true; statements+upline.read+statement_cash with include_descendants=false!
      [splitScopeReconPerson, roleLedgerOnlyWide, ids.acmeOrg, true],
      [splitScopeReconPerson, roleStmtsUplineCash, ids.acmeOrg, false],
      // splitUnpubReconPerson: all 5 rights with include_descendants=true; unpublished.read with include_descendants=false!
      [splitUnpubReconPerson, roleLedgerOnlyWide, ids.acmeOrg, true],
      [splitUnpubReconPerson, roleStmtsUplineCash, ids.acmeOrg, true],
      [splitUnpubReconPerson, roleUnpubOnly, ids.acmeOrg, false],
    ]) {
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,$5,'org_subtree','[2020-01-01,)'::daterange,'active',$6)",
        [randomUUID(), pid, rid, oid, incDesc, seq],
      );
    }
  });

  await t.test('Fix2-SF1: v_current_policy_periods and v_current_commission_ledger do NOT fall back to older sent run R1 when newest sent run R2 has no rows for caller', async () => {
    for (const [label, pid] of [['harbor_retention', ids.harborRetention], ['agent_harbor', ids.agentHarbor]]) {
      const curPol = await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => (
        (await c.query('SELECT run_id, entity FROM app_views.v_current_policy_periods')).rows
      ));
      assert.equal(curPol.length, 0, `${label} must see 0 rows in v_current_policy_periods when newest sent run R2 has no Harbor rows (must NOT fall back to stale R1), saw ${JSON.stringify(curPol)}`);
    }
    const curLed = await runAsPlatformApp(env.pool, { token: tok(harborLedgerReader), readOnly: true }, async (c) => (
      (await c.query('SELECT run_id, entity FROM app_views.v_current_commission_ledger')).rows
    ));
    assert.equal(curLed.length, 0, `harborLedgerReader must see 0 rows in v_current_commission_ledger when newest sent run R2 has no Harbor rows (must NOT fall back to stale R1), saw ${JSON.stringify(curLed)}`);

    // Beacon manager still sees R2's Beacon policy (and not unsent R3)
    const beaconCur = await runAsPlatformApp(env.pool, { token: tok(ids.beaconManager), readOnly: true }, async (c) => (
      (await c.query('SELECT run_id, entity FROM app_views.v_current_policy_periods')).rows
    ));
    assert.equal(beaconCur.length, 1);
    assert.equal(beaconCur[0].run_id, r2.runId);
    assert.equal(beaconCur[0].entity, 'Beacon');
  });

  await t.test('Fix2-SF4: reconciliation view requires col:coherence.statement_cash and uses one consistent scope across statement and ledger sides', async () => {
    const noCashRecon = await runAsPlatformApp(env.pool, { token: tok(noStmtCashPerson), readOnly: true }, async (c) => (
      (await c.query('SELECT * FROM app_views.coherence_entity_statement_reconciliation')).rows
    ));
    assert.equal(noCashRecon.length, 0, `caller without col:coherence.statement_cash must see 0 reconciliation rows, saw ${JSON.stringify(noCashRecon)}`);

    const splitRecon = await runAsPlatformApp(env.pool, { token: tok(splitScopeReconPerson), readOnly: true }, async (c) => (
      (await c.query('SELECT run_id, statement_entity, account_kind, statement_total, ledger_total, variance, reconciled FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid', [r1.runId])).rows
    ));
    assert.ok(splitRecon.length > 0, 'split-scope caller holding all 5 rights at Acme must still see Acme reconciliation');
    assert.ok(splitRecon.every((r) => r.reconciled === true && r.variance === '0.00'), `split-scope reconciliation must never produce false variances: ${JSON.stringify(splitRecon)}`);
    assert.ok(!splitRecon.some((r) => ['Beacon', 'East Team', 'Harbor'].includes(r.statement_entity)), `split-scope reconciliation must only cover the intersected scope (Acme), saw ${JSON.stringify(splitRecon)}`);

    const splitUnpubRecon = await runAsPlatformApp(env.pool, { token: tok(splitUnpubReconPerson), readOnly: true }, async (c) => (
      (await c.query('SELECT run_id, statement_entity, account_kind, statement_total, ledger_total, variance, reconciled FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid', [r3.runId])).rows
    ));
    assert.ok(splitUnpubRecon.length > 0);
    assert.ok(splitUnpubRecon.every((r) => r.reconciled === true && r.variance === '0.00'), `split-unpub reconciliation on unsent run R3 must never produce false variances: ${JSON.stringify(splitUnpubRecon)}`);
  });

  await t.test('Fix2-SF5: app_views.coherence_runs.latest_journal_seq returns the true tip via narrow definer helper even for readers lacking decisions.read / statements.read / unpublished.read', async () => {
    // R3 is UNSENT and materialized via a later journal entry than its finish_attempt,
    // AND we also record a decision row attached to R3 at an even higher journal_seq.
    await runAsPlatformApp(env.pool, { token: tok(ids.nusearOwner), readOnly: false, serializable: true }, (c) => (
      c.query('SELECT app_cmd.coherence_record_decision_baseline($1, $2, $3::jsonb)', [
        'f2-sf5-dec', sha256Hex('f2-sf5-dec'), JSON.stringify({
          commit_kind: 'historical_baseline',
          header_contract: 'v2',
          imported: true,
          decisions: [{ run_id: r3.runId, surface: 'bible', record_id: 'policy:carrier_a:TIP#effective:2026-12-01', disposition: 'CONFIRM' }],
        }),
      ])
    ));
    const trueTip = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [r3.runId])).rows[0].s);
    const adminRuns = await runAsPlatformApp(env.pool, { token: tok(ids.acmeCompanyAdmin), readOnly: true }, async (c) => (
      (await c.query('SELECT id, latest_journal_seq FROM app_views.coherence_runs WHERE id = $1::uuid', [r3.runId])).rows
    ));
    assert.equal(adminRuns.length, 1);
    assert.equal(Number(adminRuns[0].latest_journal_seq), trueTip, `company_admin must see true tip ${trueTip} in coherence_runs.latest_journal_seq (got ${adminRuns[0].latest_journal_seq})`);
    // company_admin still sees 0 rows in decisions & statement_batches
    await runAsPlatformApp(env.pool, { token: tok(ids.acmeCompanyAdmin), readOnly: true }, async (c) => {
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_decisions')).rows[0].n, 0);
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_batches')).rows[0].n, 0);
    });
    // platform_app gets 42501 reading the narrow definer helper view directly
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: tok(ids.acmeCompanyAdmin), readOnly: true }, (c) => (
        c.query('SELECT * FROM coherence.v_run_latest_journal_seq WHERE run_id = $1::uuid', [r3.runId])
      )),
      (err) => err?.code === '42501',
      'platform_app must get 42501 reading coherence.v_run_latest_journal_seq directly',
    );
  });
});

test('Layer 7B [Fix2-ShouldFix - Write Org Validation, accept_review_submission SHA-256 Match, JSON Null Arrays, Audit Hardening & Stale Comment]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv({ initCompany: false });
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const tok = (personId, viewAsPersonId = null) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId });
  const ownerTok = tok(ids.nusearOwner);
  const operatorTok = tok(ids.nusearOperator);
  const workerTok = tok(ids.workerService);
  const reqSha = (label) => sha256Hex(`f2-cmd:${label}`);
  const makeFileObj = (storeKind, text) => {
    const fp = fingerprintBytes(Buffer.from(text, 'utf8'));
    return { store_kind: storeKind, sha256: fp.sha256, byte_size: fp.byteSize, md5_b64: fp.md5B64, crc32c_b64: fp.crc32cB64, object_name: `objects/${fp.sha256}` };
  };

  const leadVendorOrg = randomUUID();
  const refFirmOrg = randomUUID();
  const orphanAgencyOrg = randomUUID();
  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f2_bad_orgs', commandKey: 'f2-bad-orgs' });
    for (const [oid, kind, slug, name, parent] of [
      [leadVendorOrg, 'lead_vendor', 'lead_v', 'Lead V', ids.acmeOrg],
      [refFirmOrg, 'referral_firm', 'ref_f', 'Ref F', ids.acmeOrg],
      [orphanAgencyOrg, 'agency', 'orphan_a', 'Orphan A', null],
    ]) {
      await c.query('INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,$2,$3)', [oid, kind, j.seq]);
      await c.query("INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,$3,$4,'active',$5)", [randomUUID(), oid, slug, name, j.seq]);
      if (parent) {
        await c.query("INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)", [randomUUID(), oid, parent, j.seq]);
      }
    }
  });

  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query("SELECT app_cmd.coherence_init_company($1, $2, 'acme', 'Acme', 'coherence')", ['f2-init', reqSha('init')])
  ));
  const codeFiles = ['git', 'man', 'lock', 'whl', 'wrap'].map((k) => makeFileObj('nusear_code', `f2-code-${k}`));
  const inFile = makeFileObj('company_data', 'k,v\n1,2\n');
  const artFile = makeFileObj('company_data', 'a\n1\n');
  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query('SELECT app_cmd.coherence_register_stored_files($1, $2, $3::jsonb)', ['f2-sf', reqSha('sf'), JSON.stringify([...codeFiles, inFile, artFile])])
  ));
  const engId = randomUUID();
  await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
    c.query('SELECT app_cmd.coherence_register_engine_version($1, $2, $3::jsonb)', [
      'f2-eng', reqSha('eng'), JSON.stringify({
        id: engId, label: 'eng-f2', coherence_commit: 'abcdef1', engine_kind: 'engine_copy',
        git_bundle_sha256: codeFiles[0].sha256, code_manifest_sha256: codeFiles[1].sha256,
        python_lock_sha256: codeFiles[2].sha256, python_wheels_sha256: codeFiles[3].sha256,
        wrapper_bundle_sha256: codeFiles[4].sha256, nusear_commit: '1234567',
        overlay_check_sha256: sha256Hex('f2-ovchk'),
        toolchain: { os: 'Linux', os_version: '6', arch: 'x64', python: '3.12', uv: '0.5', tz: 'America/New_York', lang: 'en_US.UTF-8', lc_all: 'en_US.UTF-8', pythonutf8: '1' },
      }),
    ])
  ));
  await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
    c.query("SELECT app_cmd.coherence_publish_input_version($1, $2, NULL, 'standing', 'upload', 'seed', $3::jsonb)", [
      'f2-iv', reqSha('iv'), JSON.stringify([{ rel_path: 'Carrier/in.csv', file_sha256: inFile.sha256 }]),
    ])
  ));

  const withWorkerSlot = async (fn) => {
    const slotClient = await env.pool.connect();
    const ok = (await slotClient.query('SELECT pg_catalog.pg_try_advisory_lock(coherence.slot_class_id(), coherence.slot_obj_id()) AS ok')).rows[0].ok;
    assert.equal(ok, true);
    try {
      const execTx = async (sqlFn) => {
        await slotClient.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
        try {
          await slotClient.query('SET LOCAL ROLE platform_worker');
          await slotClient.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [workerTok]);
          const res = await sqlFn(slotClient);
          await slotClient.query('COMMIT');
          return res;
        } catch (err) {
          await slotClient.query('ROLLBACK').catch(() => {});
          throw err;
        }
      };
      return await fn(execTx);
    } finally {
      await slotClient.query('SELECT pg_catalog.pg_advisory_unlock(coherence.slot_class_id(), coherence.slot_obj_id())').catch(() => {});
      slotClient.release();
    }
  };

  await t.test('Fix2-SF2 & Item 5: coherence_record_statement_batch and _cmd_insert_materialization refuse non-tenant/non-CAT organization_ids and strictly resolve omitted FKs inside PostgreSQL (refusing unmapped/ambiguous entities and unmapped/blank NPNs)', async () => {
    for (const [label, badOrg] of [
      ['other_company', ids.northstarOrg],
      ['lead_vendor', leadVendorOrg],
      ['referral_firm', refFirmOrg],
      ['platform_root', ids.rootOrg],
      ['orphan_agency', orphanAgencyOrg],
    ]) {
      await assert.rejects(
        () => runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
          c.query('SELECT app_cmd.coherence_record_statement_batch($1, $2, $3::jsonb)', [
            `f2-bad-sb-ag-${label}`, reqSha(`bad-sb-ag-${label}`), JSON.stringify({
              batch_kind: 'historical_sent', statement_date: '2026-07-01', reason: 'bad org test',
              agency_lines: [{
                entity: 'Bad', organization_id: badOrg, writing_npn: null, writing_person_id: null,
                record_id: `carrier_a~direct~BADAG_${label}~10.00~2026-07`, source_file: 'bad.csv', source_row_no: 1,
                gross_comm: '10.00', amount: '10.00',
              }],
              upline_lines: [],
            }),
          ])
        )),
        (err) => err?.code === '23503' && /INVALID_ORGANIZATION_ID/i.test(err.message),
        `coherence_record_statement_batch agency_lines must reject ${label}`,
      );
      await assert.rejects(
        () => runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
          c.query('SELECT app_cmd.coherence_record_statement_batch($1, $2, $3::jsonb)', [
            `f2-bad-sb-up-${label}`, reqSha(`bad-sb-up-${label}`), JSON.stringify({
              batch_kind: 'historical_sent', statement_date: '2026-07-01', reason: 'bad org test',
              agency_lines: [],
              upline_lines: [{
                source_entity: 'Bad', organization_id: badOrg, writing_npn: null, writing_person_id: null,
                record_id: `carrier_a~direct~BADUP_${label}~10.00~2026-07`, source_file: 'bad.csv', source_row_no: 1,
                gross_comm: '10.00', amount: '10.00',
              }],
            }),
          ])
        )),
        (err) => err?.code === '23503' && /INVALID_ORGANIZATION_ID/i.test(err.message),
        `coherence_record_statement_batch upline_lines must reject ${label}`,
      );
    }

    // Item 5 strict PG resolution: NULL organization_id with unmapped entity or non-empty unmapped/blank NPN refuses (never silent NULL)
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
        c.query('SELECT app_cmd.coherence_record_statement_batch($1, $2, $3::jsonb)', [
          'f2-bad-sb-unmapped-entity', reqSha('bad-sb-unmapped-entity'), JSON.stringify({
            batch_kind: 'historical_sent', statement_date: '2026-07-01', reason: 'unmapped entity',
            agency_lines: [{ entity: 'Unknown Agency', organization_id: null, record_id: 'r-unmap-ent', source_file: 'bad.csv', source_row_no: 1, gross_comm: '10.00', amount: '10.00' }],
            upline_lines: [],
          }),
        ])
      )),
      (err) => err?.code === '22023' && /UNMAPPED_ENTITY/i.test(err.message),
      'null organization_id with unmapped entity must refuse with UNMAPPED_ENTITY',
    );
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
        c.query('SELECT app_cmd.coherence_record_statement_batch($1, $2, $3::jsonb)', [
          'f2-bad-sb-unmapped-npn', reqSha('bad-sb-unmapped-npn'), JSON.stringify({
            batch_kind: 'historical_sent', statement_date: '2026-07-01', reason: 'unmapped npn',
            agency_lines: [{ entity: 'Beacon', organization_id: null, writing_npn: '99999999', writing_person_id: null, record_id: 'r-unmap-npn', source_file: 'bad.csv', source_row_no: 1, gross_comm: '10.00', amount: '10.00' }],
            upline_lines: [],
          }),
        ])
      )),
      (err) => err?.code === '22023' && /UNMAPPED_WRITING_NPN/i.test(err.message),
      'non-empty unmapped writing_npn must refuse with UNMAPPED_WRITING_NPN (never silent NULL)',
    );
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
        c.query('SELECT app_cmd.coherence_record_statement_batch($1, $2, $3::jsonb)', [
          'f2-bad-sb-blank-npn', reqSha('bad-sb-blank-npn'), JSON.stringify({
            batch_kind: 'historical_sent', statement_date: '2026-07-01', reason: 'blank npn',
            agency_lines: [{ entity: 'Beacon', organization_id: null, writing_npn: '   ', writing_person_id: null, record_id: 'r-blank-npn', source_file: 'bad.csv', source_row_no: 1, gross_comm: '10.00', amount: '10.00' }],
            upline_lines: [],
          }),
        ])
      )),
      (err) => err?.code === '22023' && /MALFORMED_WRITING_NPN/i.test(err.message),
      'blank writing_npn must refuse with MALFORMED_WRITING_NPN',
    );

    // Launch a run to emit and test _cmd_insert_materialization refusing bad organization_id and strictly resolving omitted FKs
    const l1 = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_launch_run($1, $2, NULL, DATE '2026-11-01', $3::uuid) AS res", ['f2-l1', reqSha('l1'), engId])
    ))).rows[0].res;
    const runId = l1.run_id;
    let reqId = l1.step_request_id;
    await withWorkerSlot(async (execTx) => {
      for (const step of ['assign', 'attribute', 'bible']) {
        await execTx((c) => c.query('SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, $4, $5::uuid)', [`f2-st-${step}`, reqSha(`st-${step}`), runId, step, reqId]));
        const fin = (await execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb) AS res', [
          `f2-fin-${step}`, reqSha(`fin-${step}`), JSON.stringify({
            run_id: runId, step, attempt_no: 1, born: '2026-11-01T12:00:00Z',
            artifacts: [], continue_to_next_step: step !== 'bible',
          }),
        ]))).rows[0].res;
        reqId = fin.next_request_id;
      }
    });
    const seqBible = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [runId])).rows[0].s);
    await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_save_review_decisions($1, $2, $3, $4::uuid, 'bible', '[]'::jsonb)", ['f2-bible-save', reqSha('bible-save'), seqBible, runId])
    ));
    const adjReq = (await env.pool.query("SELECT id FROM coherence.step_requests WHERE run_id = $1::uuid AND step = 'adjust' ORDER BY journal_seq DESC LIMIT 1", [runId])).rows[0].id;
    await withWorkerSlot(async (execTx) => {
      await execTx((c) => c.query("SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, 'adjust', $4::uuid)", ['f2-st-adj', reqSha('st-adj'), runId, adjReq]));
      await execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb)', [
        'f2-fin-adj', reqSha('fin-adj'), JSON.stringify({ run_id: runId, step: 'adjust', attempt_no: 1, born: '2026-11-01T12:05:00Z', artifacts: [], continue_to_next_step: false }),
      ]));
    });
    const seqAdj = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [runId])).rows[0].s);
    const adjSave = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_save_review_decisions($1, $2, $3, $4::uuid, 'adjust', '[]'::jsonb) AS res", ['f2-adj-save', reqSha('adj-save'), seqAdj, runId])
    ))).rows[0].res;
    const conf = (await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_confirm_emit($1, $2, NULL, $3::uuid, $4::uuid, 'create statements for 2026-11-01') AS res", ['f2-conf', reqSha('conf'), runId, adjSave.review_save_id])
    ))).rows[0].res;

    await withWorkerSlot(async (execTx) => {
      await execTx((c) => c.query("SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, 'emit', $4::uuid)", ['f2-st-emit', reqSha('st-emit'), runId, conf.step_request_id]));
      for (const [label, badOrg] of [
        ['northstar', ids.northstarOrg],
        ['lead_vendor', leadVendorOrg],
      ]) {
        await assert.rejects(
          () => execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb)', [
            `f2-bad-mat-${label}`, reqSha(`bad-mat-${label}`), JSON.stringify({
              run_id: runId, step: 'emit', attempt_no: 1, born: '2026-11-01T12:10:00Z',
              artifacts: [{ rel_path: 'emits/statements_20261101.csv', artifact_kind: 'data', store_kind: 'company_data', file_sha256: artFile.sha256 }],
              continue_to_next_step: false,
              emit_materialization: {
                statement_batch: { batch_kind: 'run_emission', statement_date: '2026-11-01', reason: 'bad org mat' },
                run_materialization: { statement_date: '2026-11-01', reconciliation_mode: 'strict_entity_ledger' },
                agency_lines: [{ line_no: 1, entry_kind: 'run_emission', run_action: 'NEW', entity: 'Beacon', organization_id: badOrg, record_id: 'r1', source_file: 'c.csv', source_row_no: 1, gross_comm: '100.00', amount: '80.00' }],
                upline_lines: [{ line_no: 1, entry_kind: 'run_emission', run_action: 'NEW', source_entity: 'Beacon', marked_sent: true, organization_id: ids.beaconOrg, record_id: 'r1', source_file: 'c.csv', source_row_no: 1, gross_comm: '100.00', amount: '20.00' }],
                bob_policies: [{ policy_id: 1, entity: 'Beacon', organization_id: ids.beaconOrg }],
                bob_financials: [{ policy_id: 1, entity: 'Beacon', organization_id: ids.beaconOrg, amount: '80.00', upline_amount: '20.00' }],
                ledger_rows: [{ tx_id: 1, record_id: 'r1', policy_id: 1, src_type: 'direct', gross_comm: '100.00', downline_amount: '80.00', upline_amount: '20.00', entity: 'Beacon', organization_id: ids.beaconOrg }],
              },
            }),
          ])),
          (err) => err?.code === '23503' && /INVALID_ORGANIZATION_ID/i.test(err.message),
          `_cmd_insert_materialization must reject ${label}`,
        );
      }
      // Unmapped entity and unmapped writing_npn inside _cmd_insert_materialization must strictly refuse (Item 5)
      await assert.rejects(
        () => execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb)', [
          'f2-bad-mat-unmapped-ent', reqSha('bad-mat-unmapped-ent'), JSON.stringify({
            run_id: runId, step: 'emit', attempt_no: 1, born: '2026-11-01T12:10:00Z',
            artifacts: [{ rel_path: 'emits/statements_20261101.csv', artifact_kind: 'data', store_kind: 'company_data', file_sha256: artFile.sha256 }],
            continue_to_next_step: false,
            emit_materialization: {
              statement_batch: { batch_kind: 'run_emission', statement_date: '2026-11-01', reason: 'unmapped ent' },
              run_materialization: { statement_date: '2026-11-01', reconciliation_mode: 'strict_entity_ledger' },
              agency_lines: [{ line_no: 1, entry_kind: 'run_emission', run_action: 'NEW', entity: 'NoSuchAgency', organization_id: null, record_id: 'r1', source_file: 'c.csv', source_row_no: 1, gross_comm: '100.00', amount: '80.00' }],
              upline_lines: [{ line_no: 1, entry_kind: 'run_emission', run_action: 'NEW', source_entity: 'Beacon', marked_sent: true, organization_id: null, record_id: 'r1', source_file: 'c.csv', source_row_no: 1, gross_comm: '100.00', amount: '20.00' }],
              bob_policies: [{ policy_id: 1, entity: 'Beacon', organization_id: null }],
              bob_financials: [{ policy_id: 1, entity: 'Beacon', organization_id: null, amount: '80.00', upline_amount: '20.00' }],
              ledger_rows: [{ tx_id: 1, record_id: 'r1', policy_id: 1, src_type: 'direct', gross_comm: '100.00', downline_amount: '80.00', upline_amount: '20.00', entity: 'Beacon', organization_id: null }],
            },
          }),
        ])),
        (err) => err?.code === '22023' && /UNMAPPED_ENTITY/i.test(err.message),
        '_cmd_insert_materialization must reject unmapped entity when organization_id is NULL',
      );
      await assert.rejects(
        () => execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb)', [
          'f2-bad-mat-unmapped-npn', reqSha('bad-mat-unmapped-npn'), JSON.stringify({
            run_id: runId, step: 'emit', attempt_no: 1, born: '2026-11-01T12:10:00Z',
            artifacts: [{ rel_path: 'emits/statements_20261101.csv', artifact_kind: 'data', store_kind: 'company_data', file_sha256: artFile.sha256 }],
            continue_to_next_step: false,
            emit_materialization: {
              statement_batch: { batch_kind: 'run_emission', statement_date: '2026-11-01', reason: 'unmapped npn' },
              run_materialization: { statement_date: '2026-11-01', reconciliation_mode: 'strict_entity_ledger' },
              agency_lines: [{ line_no: 1, entry_kind: 'run_emission', run_action: 'NEW', entity: 'Beacon', organization_id: null, writing_npn: '99999999', writing_person_id: null, record_id: 'r1', source_file: 'c.csv', source_row_no: 1, gross_comm: '100.00', amount: '80.00' }],
              upline_lines: [{ line_no: 1, entry_kind: 'run_emission', run_action: 'NEW', source_entity: 'Beacon', marked_sent: true, organization_id: null, record_id: 'r1', source_file: 'c.csv', source_row_no: 1, gross_comm: '100.00', amount: '20.00' }],
              bob_policies: [{ policy_id: 1, entity: 'Beacon', organization_id: null }],
              bob_financials: [{ policy_id: 1, entity: 'Beacon', organization_id: null, amount: '80.00', upline_amount: '20.00' }],
              ledger_rows: [{ tx_id: 1, record_id: 'r1', policy_id: 1, src_type: 'direct', gross_comm: '100.00', downline_amount: '80.00', upline_amount: '20.00', entity: 'Beacon', organization_id: null }],
            },
          }),
        ])),
        (err) => err?.code === '22023' && /UNMAPPED_WRITING_NPN/i.test(err.message),
        '_cmd_insert_materialization must reject unmapped writing_npn (never silent NULL)',
      );
      // Also test bad org on bob_policies / ledger_rows specifically
      await assert.rejects(
        () => execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb)', [
          'f2-bad-mat-led', reqSha('bad-mat-led'), JSON.stringify({
            run_id: runId, step: 'emit', attempt_no: 1, born: '2026-11-01T12:10:00Z',
            artifacts: [{ rel_path: 'emits/statements_20261101.csv', artifact_kind: 'data', store_kind: 'company_data', file_sha256: artFile.sha256 }],
            continue_to_next_step: false,
            emit_materialization: {
              statement_batch: { batch_kind: 'run_emission', statement_date: '2026-11-01', reason: 'bad led org' },
              run_materialization: { statement_date: '2026-11-01', reconciliation_mode: 'strict_entity_ledger' },
              agency_lines: [{ line_no: 1, entry_kind: 'run_emission', run_action: 'NEW', entity: 'Beacon', organization_id: ids.beaconOrg, record_id: 'r1', source_file: 'c.csv', source_row_no: 1, gross_comm: '100.00', amount: '80.00' }],
              upline_lines: [{ line_no: 1, entry_kind: 'run_emission', run_action: 'NEW', source_entity: 'Beacon', marked_sent: true, organization_id: ids.beaconOrg, record_id: 'r1', source_file: 'c.csv', source_row_no: 1, gross_comm: '100.00', amount: '20.00' }],
              bob_policies: [{ policy_id: 1, entity: 'Beacon', organization_id: ids.beaconOrg }],
              bob_financials: [{ policy_id: 1, entity: 'Beacon', organization_id: ids.beaconOrg, amount: '80.00', upline_amount: '20.00' }],
              ledger_rows: [{ tx_id: 1, record_id: 'r1', policy_id: 1, src_type: 'direct', gross_comm: '100.00', downline_amount: '80.00', upline_amount: '20.00', entity: 'Beacon', organization_id: refFirmOrg }],
            },
          }),
        ])),
        (err) => err?.code === '23503' && /INVALID_ORGANIZATION_ID/i.test(err.message),
        '_cmd_insert_materialization must reject referral_firm on ledger_rows',
      );
      // Finish emit attempt 1 with omitted organization_id / writing_person_id and valid entity/NPN to prove PG resolves them strictly!
      const okMat = (await execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb) AS res', [
        'f2-ok-mat', reqSha('ok-mat'), JSON.stringify({
          run_id: runId, step: 'emit', attempt_no: 1, born: '2026-11-01T12:10:00Z',
          artifacts: [{ rel_path: 'emits/statements_20261101.csv', artifact_kind: 'data', store_kind: 'company_data', file_sha256: artFile.sha256 }],
          continue_to_next_step: false,
          emit_materialization: {
            statement_batch: { batch_kind: 'run_emission', statement_date: '2026-11-01', reason: 'valid org mat' },
            run_materialization: { statement_date: '2026-11-01', reconciliation_mode: 'strict_entity_ledger' },
            agency_lines: [{ line_no: 1, entry_kind: 'run_emission', run_action: 'NEW', entity: 'Beacon', writing_npn: '11111111', record_id: 'r1', source_file: 'c.csv', source_row_no: 1, gross_comm: '100.00', amount: '80.00' }],
            upline_lines: [{ line_no: 1, entry_kind: 'run_emission', run_action: 'NEW', source_entity: 'Beacon', marked_sent: true, writing_npn: '11111111', record_id: 'r1', source_file: 'c.csv', source_row_no: 1, gross_comm: '100.00', amount: '20.00' }],
            bob_policies: [{ policy_id: 1, entity: 'Beacon', writing_npn: '11111111' }],
            bob_financials: [{ policy_id: 1, entity: 'Beacon', writing_npn: '11111111', amount: '80.00', upline_amount: '20.00' }],
            ledger_rows: [{ tx_id: 1, record_id: 'r1', policy_id: 1, src_type: 'direct', gross_comm: '100.00', commission_amount: '100.00', downline_amount: '80.00', upline_amount: '20.00', entity: 'Beacon', writing_npn: '11111111', cbob_c: true, cbob_s: false, sf: true }],
          },
        }),
      ]))).rows[0].res;
      assert.ok(okMat.statement_batch_id, 'valid tenant org materialization must succeed');
      const resolvedRow = (await env.pool.query(
        'SELECT organization_id, writing_person_id FROM coherence.bob_policies WHERE run_id = $1::uuid',
        [runId],
      )).rows[0];
      assert.equal(resolvedRow.organization_id, ids.beaconOrg, 'PostgreSQL _cmd_insert_materialization must resolve organization_id');
      assert.equal(resolvedRow.writing_person_id, ids.agentA, 'PostgreSQL _cmd_insert_materialization must resolve writing_person_id');
      // Replay of finish_attempt returns the stored result object whole (Item 8)
      const okReplay = (await execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb) AS res', [
        'f2-ok-mat', reqSha('ok-mat'), JSON.stringify({}),
      ]))).rows[0].res;
      assert.equal(okReplay.idempotent, true);
      assert.equal(okReplay.result.attemptEventId, okMat.attempt_event_id);
      assert.equal(okReplay.result.statementBatchId, okMat.statement_batch_id);
      assert.equal(okReplay.result.materialized, true);
    });
  });

  await t.test('Fix2-SF3: coherence_accept_review_submission refuses a stored_file whose SHA-256 differs from staged_sha256', async () => {
    const l2 = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_launch_run($1, $2, NULL, DATE '2026-12-01', $3::uuid) AS res", ['f2-l2', reqSha('l2'), engId])
    ))).rows[0].res;
    const run2Id = l2.run_id;
    let req2Id = l2.step_request_id;
    await withWorkerSlot(async (execTx) => {
      for (const step of ['assign', 'attribute', 'bible']) {
        await execTx((c) => c.query('SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, $4, $5::uuid)', [`f2-r2-st-${step}`, reqSha(`r2-st-${step}`), run2Id, step, req2Id]));
        const fin = (await execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb) AS res', [
          `f2-r2-fin-${step}`, reqSha(`r2-fin-${step}`), JSON.stringify({ run_id: run2Id, step, attempt_no: 1, born: '2026-12-01T12:00:00Z', artifacts: [], continue_to_next_step: step !== 'bible' }),
        ]))).rows[0].res;
        req2Id = fin.next_request_id;
      }
    });
    const seq2 = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [run2Id])).rows[0].s);
    const revStaged = makeFileObj('company_data', 'record_id,disposition\nk1,CONFIRM\n');
    const revWrong = makeFileObj('company_data', 'record_id,disposition\nk1,CORRECT\n');
    const sub = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_submit_review($1, $2, $3, $4::uuid, 'bible', $5) AS res", ['f2-sub-sha', reqSha('sub-sha'), seq2, run2Id, revStaged.sha256])
    ))).rows[0].res;

    await withWorkerSlot(async (execTx) => {
      await assert.rejects(
        () => execTx((c) => c.query('SELECT app_cmd.coherence_accept_review_submission($1, $2, $3::jsonb)', [
          'f2-acc-wrong', reqSha('acc-wrong'), JSON.stringify({
            submission_id: sub.submission_id, stored_file: revWrong,
            header_kind: 'v2', row_count: 1, added_rows: [{ row_no: 1, record_id: 'k1', disposition: 'CORRECT' }],
          }),
        ])),
        (err) => err?.code === '23514' && /STAGED_SHA256_MISMATCH/i.test(err.message),
        'coherence_accept_review_submission must refuse stored_file with mismatched sha256',
      );
      // Matching sha256 succeeds
      const ok = (await execTx((c) => c.query('SELECT app_cmd.coherence_accept_review_submission($1, $2, $3::jsonb) AS res', [
        'f2-acc-right', reqSha('acc-right'), JSON.stringify({
          submission_id: sub.submission_id, stored_file: revStaged,
          header_kind: 'v2', row_count: 1, added_rows: [{ row_no: 1, record_id: 'k1', disposition: 'CONFIRM' }],
        }),
      ]))).rows[0].res;
      assert.ok(ok.review_save_id);
    });
  });

  await t.test('Fix2-SF7: JSON null arrays are treated as empty across app_cmd commands', async () => {
    await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, async (c) => {
      const ivNull = (await c.query("SELECT app_cmd.coherence_publish_input_version($1, $2, NULL, 'snapshot', 'upload', 'null arrays iv', 'null'::jsonb, 'null'::jsonb, 'null'::jsonb) AS res", [
        'f2-null-iv', reqSha('null-iv'),
      ])).rows[0].res;
      assert.ok(ivNull.input_version_id);
    });
    await runAsPlatformApp(env.pool, { token: ownerTok, readOnly: false, serializable: true }, async (c) => {
      const sb = (await c.query('SELECT app_cmd.coherence_record_statement_batch($1, $2, $3::jsonb) AS res', [
        'f2-null-sb', reqSha('null-sb'), JSON.stringify({
          batch_kind: 'historical_sent', statement_date: '2026-05-01', reason: 'null arrays test',
          agency_lines: null, upline_lines: null, source_file: null,
        }),
      ])).rows[0].res;
      assert.ok(sb.batch_id);

      const dc = (await c.query('SELECT app_cmd.coherence_record_decision_baseline($1, $2, $3::jsonb) AS res', [
        'f2-null-dc', reqSha('null-dc'), JSON.stringify({ commit_kind: 'historical_baseline', header_contract: 'v2', imported: true, decisions: null }),
      ])).rows[0].res;
      assert.ok(dc.decision_commit_id);

      const stf = (await c.query('SELECT app_cmd.coherence_import_standalone_files($1, $2, $3::jsonb) AS res', [
        'f2-null-stf', reqSha('null-stf'), JSON.stringify({ stored_files: null, files: null }),
      ])).rows[0].res;
      assert.equal(stf.imported, 0);

      const afFile = makeFileObj('company_data', 'record_id,disposition\n');
      const af = (await c.query("SELECT app_cmd.coherence_register_approvals_file($1, $2, $3::jsonb, 'v2', 0, NULL, 0, 'null'::jsonb) AS res", [
        'f2-null-af', reqSha('null-af'), JSON.stringify(afFile),
      ])).rows[0].res;
      assert.equal(af.file_sha256, afFile.sha256);

      const imp = (await c.query('SELECT app_cmd.coherence_import_historical_run($1, $2, $3::jsonb) AS res', [
        'f2-null-imp', reqSha('null-imp'), JSON.stringify({
          run: { origin: 'company_import', statement_date: '2026-05-15', folder_number: 1, emit_mode: 'coherence', emit_keep: null, emit_no_manager: null, source_folder: 'company-runs/2026-05-15-nulls' },
          input_version: { reason: 'null arrays import' },
          input_entries: null, stored_files: null, approvals_files: null, step_attempts: null,
          review_saves: null, review_queue_items: null, decisions: null, decision_commits: null,
          generated_overlays: null, extra_imported_files: null, abandonment: null,
        }),
      ])).rows[0].res;
      assert.ok(imp.run_id);
    });
    // Also exercise finish_attempt & save_review_decisions with JSON null arrays
    const l3 = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_launch_run($1, $2, NULL, DATE '2026-12-15', $3::uuid) AS res", ['f2-l3', reqSha('l3'), engId])
    ))).rows[0].res;
    let r3Req = l3.step_request_id;
    await withWorkerSlot(async (execTx) => {
      for (const step of ['assign', 'attribute', 'bible']) {
        await execTx((c) => c.query('SELECT app_cmd.coherence_start_attempt($1, $2, $3::uuid, $4, $5::uuid)', [`f2-l3-st-${step}`, reqSha(`l3-st-${step}`), l3.run_id, step, r3Req]));
        const fin = (await execTx((c) => c.query('SELECT app_cmd.coherence_finish_attempt($1, $2, $3::jsonb) AS res', [
          `f2-l3-fin-${step}`, reqSha(`l3-fin-${step}`), JSON.stringify({
            run_id: l3.run_id, step, attempt_no: 1, born: '2026-12-15T12:00:00Z',
            artifacts: null, stored_files: null, review_queue_items: null, generated_overlays: null,
            continue_to_next_step: step !== 'bible',
          }),
        ]))).rows[0].res;
        r3Req = fin.next_request_id;
      }
    });
    const r3Seq = Number((await env.pool.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS s', [l3.run_id])).rows[0].s);
    const r3Save = (await runAsPlatformApp(env.pool, { token: operatorTok, readOnly: false, serializable: true }, (c) => (
      c.query("SELECT app_cmd.coherence_save_review_decisions($1, $2, $3, $4::uuid, 'bible', 'null'::jsonb) AS res", ['f2-l3-save', reqSha('l3-save'), r3Seq, l3.run_id])
    ))).rows[0].res;
    assert.ok(r3Save.review_save_id);
  });

  await t.test('Fix2-SF6 & SF8: audit checks every platform_view_owner policy in coherence, backfill pinned search_path, escaped LIKE underscores, _view_* helper, and zero stale comments', async () => {
    const cleanAudit = await withClusterCatalogLock(() => policyChecks.verifyIamConfigInvariants(env.pool));
    assert.equal(cleanAudit.passed, true, `clean audit failed:\n${cleanAudit.problems.join('\n')}`);

    // 1. Unscoped platform_view_owner policy on non-FK coherence table (decisions) must fail audit
    await env.pool.query('CREATE POLICY decisions_view_backdoor_probe ON coherence.decisions FOR SELECT TO platform_view_owner USING (true)');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'unscoped platform_view_owner policy on coherence.decisions must fail audit');
      assert.ok(bad.problems.some((p) => /decisions/i.test(p) && /platform_view_owner|unscoped/i.test(p)));
    } finally {
      await env.pool.query('DROP POLICY IF EXISTS decisions_view_backdoor_probe ON coherence.decisions');
    }

    // 2. Bare iam.has_right() policy for platform_view_owner on coherence.runs must fail audit
    await env.pool.query("CREATE POLICY runs_bare_has_right_probe ON coherence.runs FOR SELECT TO platform_view_owner USING (iam.has_right('act:coherence.runs.read'))");
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'bare iam.has_right policy on coherence.runs must fail audit');
      assert.ok(bad.problems.some((p) => /runs/i.test(p) && /has_right|unscoped/i.test(p)));
    } finally {
      await env.pool.query('DROP POLICY IF EXISTS runs_bare_has_right_probe ON coherence.runs');
    }

    // 3. Unpinning search_path on coherence.backfill_iam_foreign_keys must fail audit
    await env.pool.query('ALTER FUNCTION coherence.backfill_iam_foreign_keys(jsonb, jsonb) RESET search_path');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'unpinned search_path on backfill_iam_foreign_keys must fail audit');
      assert.ok(bad.problems.some((p) => /backfill_iam_foreign_keys/i.test(p) && /search_path/i.test(p)));
    } finally {
      await env.pool.query('ALTER FUNCTION coherence.backfill_iam_foreign_keys(jsonb, jsonb) SET search_path = pg_catalog');
    }

    // 4. Escaped LIKE underscores: a non-internal function named coherence.xresolve_probe() must NOT match '_resolve_%'
    await env.pool.query(`
      CREATE OR REPLACE FUNCTION coherence.xresolve_probe() RETURNS INTEGER
      LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS 'SELECT 1';
      REVOKE ALL ON FUNCTION coherence.xresolve_probe() FROM PUBLIC;
    `);
    try {
      const ok = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(ok.passed, true, `escaped LIKE must not false-positive on coherence.xresolve_probe(): ${ok.problems.join('; ')}`);
    } finally {
      await env.pool.query('DROP FUNCTION IF EXISTS coherence.xresolve_probe()');
    }

    // 5. Granting SELECT on narrow definer view coherence.v_run_latest_journal_seq to platform_worker must fail audit
    await env.pool.query('GRANT SELECT ON coherence.v_run_latest_journal_seq TO platform_worker');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'granting SELECT on coherence.v_run_latest_journal_seq to platform_worker must fail audit');
      assert.ok(bad.problems.some((p) => /v_run_latest_journal_seq/i.test(p) && /platform_worker/i.test(p)));
    } finally {
      await env.pool.query('REVOKE SELECT ON coherence.v_run_latest_journal_seq FROM platform_worker');
    }

    // 6. Stale comment check: migration 009 must not reference nonexistent expand_org_ids_with_archived
    const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
    const mig009 = await readFile(resolve(repoRoot, 'migrations', '009_coherence_under_iam.sql'), 'utf8');
    assert.ok(!mig009.includes('expand_org_ids_with_archived'), 'migrations/009_coherence_under_iam.sql must not contain stale expand_org_ids_with_archived comment');
  });
});

test('Layer 7B [Fix3-1A - Dual-Agency Tenant-Tree Bounds: Active Child Under Archived Held/Off Parent, Archived Direct Grant & col_scopes, Detached Child]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const r1 = await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'f3-da-r1', markSent: true });
  const r2 = await seedPublishedRun(env, { statementDate: '2026-11-15', keyPrefix: 'f3-da-r2', markSent: false });
  await runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
    c.query('SELECT * FROM coherence.backfill_iam_foreign_keys()')
  ));

  const tok = (personId, viewAsPersonId = null) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId });

  const roleFullScoped = randomUUID();
  const roleNarrowCash = randomUUID();
  const roleNoDollarBob = randomUUID();
  const roleCashOnly = randomUUID();
  const roleNarrowCashOnly = randomUUID();
  const dualAgencyWide = randomUUID();
  const dualAgencyNarrow = randomUUID();
  const acmePlusEastWide = randomUUID();
  const acmeNoDollarPlusEastCash = randomUUID();
  const acmeNoDollarPlusEastNarrowCash = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f3_da_setup', commandKey: 'f3-da-setup' });
    const seq = j.seq;

    for (const [roleId, slug, name, wide, rightList] of [
      [roleFullScoped, 'f3_full_scoped', 'F3 Full Scoped', true, [
        'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
        'act:coherence.ledger.read', 'act:coherence.unpublished.read',
        'col:coherence.statement_cash', 'col:coherence.upline_cash',
      ]],
      [roleNarrowCash, 'f3_narrow_cash', 'F3 Narrow Cash', false, [
        'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.unpublished.read',
        'col:coherence.statement_cash',
      ]],
      [roleNoDollarBob, 'f3_nodollar_bob', 'F3 NoDollar Bob', true, [
        'act:coherence.bob.read', 'act:coherence.statements.read',
      ]],
      [roleCashOnly, 'f3_cash_only', 'F3 Cash Only', true, [
        'col:coherence.statement_cash', 'col:coherence.upline_cash',
      ]],
      [roleNarrowCashOnly, 'f3_narrow_cash_only', 'F3 Narrow Cash Only', false, [
        'col:coherence.statement_cash',
      ]],
    ]) {
      await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,$3,$4)', [roleId, slug, ids.acmeOrg, seq]);
      await c.query(
        "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,$3,false,false,$4,'active',$5)",
        [randomUUID(), roleId, name, wide, seq],
      );
      for (const rightId of rightList) {
        await c.query(
          "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), roleId, rightId, seq],
        );
      }
    }

    for (const [pid, name, email] of [
      [dualAgencyWide, 'Dual Agency Wide', 'da.wide@acme.example'],
      [dualAgencyNarrow, 'Dual Agency Narrow', 'da.narrow@acme.example'],
      [acmePlusEastWide, 'Acme Plus East', 'acme.east@acme.example'],
      [acmeNoDollarPlusEastCash, 'Acme NoDollar East Cash', 'acme.nd.ec@acme.example'],
      [acmeNoDollarPlusEastNarrowCash, 'Acme NoDollar East Narrow Cash', 'acme.nd.enc@acme.example'],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [pid, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,$3,$3,$4,'active',$5)",
        [randomUUID(), pid, name, email, seq],
      );
    }

    // Memberships
    for (const [pid, orgId, cap] of [
      [dualAgencyWide, ids.harborOrg, 'employee'],
      [dualAgencyWide, ids.eastTeamOrg, 'employee'],
      [dualAgencyNarrow, ids.harborOrg, 'employee'],
      [dualAgencyNarrow, ids.eastTeamOrg, 'employee'],
      [ids.agentEast, ids.harborOrg, 'employee'],
      [acmePlusEastWide, ids.acmeOrg, 'owner'],
      [acmePlusEastWide, ids.eastTeamOrg, 'employee'],
      [acmeNoDollarPlusEastCash, ids.acmeOrg, 'employee'],
      [acmeNoDollarPlusEastCash, ids.eastTeamOrg, 'employee'],
      [acmeNoDollarPlusEastNarrowCash, ids.acmeOrg, 'employee'],
      [acmeNoDollarPlusEastNarrowCash, ids.eastTeamOrg, 'employee'],
    ]) {
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,'[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), pid, orgId, cap, seq],
      );
    }

    // Grants: Harbor + East Team (wide and narrow)
    for (const [pid, roleId, orgId, incDesc, pMode] of [
      [dualAgencyWide, roleFullScoped, ids.harborOrg, true, 'org_subtree'],
      [dualAgencyWide, roleFullScoped, ids.eastTeamOrg, true, 'org_subtree'],
      [dualAgencyNarrow, ids.roleAgencyManager, ids.harborOrg, true, 'org_subtree'],
      [ids.agentEast, ids.roleSellingAgent, ids.harborOrg, false, 'self'],
      [ids.agentEast, roleNarrowCash, ids.eastTeamOrg, false, 'self'],
      [acmePlusEastWide, ids.roleEntityManager, ids.acmeOrg, true, 'org_subtree'],
      [acmePlusEastWide, roleFullScoped, ids.eastTeamOrg, true, 'org_subtree'],
      [acmeNoDollarPlusEastCash, roleNoDollarBob, ids.acmeOrg, true, 'org_subtree'],
      [acmeNoDollarPlusEastCash, roleCashOnly, ids.eastTeamOrg, true, 'org_subtree'],
      [acmeNoDollarPlusEastNarrowCash, roleNoDollarBob, ids.acmeOrg, true, 'org_subtree'],
    ]) {
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,$5,$6,'[2020-01-01,)'::daterange,'active',$7)",
        [randomUUID(), pid, roleId, orgId, incDesc, pMode, seq],
      );
    }

    // Self-scoped narrow grants on East Team for agentEast and dualAgencyNarrow (replaces parked explicit_people)
    await c.query(
      "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,false,'self','[2020-01-01,)'::daterange,'active',$5)",
      [randomUUID(), ids.agentEast, roleNarrowCashOnly, ids.eastTeamOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,false,'self','[2020-01-01,)'::daterange,'active',$5)",
      [randomUUID(), dualAgencyNarrow, roleNarrowCash, ids.eastTeamOrg, seq],
    );

    // Turn East Team's own coherence switch ON, archive Beacon, and set Beacon's coherence switch HELD
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','on','active',$3)",
      [randomUUID(), ids.eastTeamOrg, seq],
    );
    const prevBeaconOv = (await c.query(
      'SELECT id FROM iam.organization_versions WHERE organization_id = $1 AND superseded_by_id IS NULL',
      [ids.beaconOrg],
    )).rows[0].id;
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, replaces_id, journal_seq) VALUES ($1,$2,'beacon','Beacon','archived',$3,$4)",
      [randomUUID(), ids.beaconOrg, prevBeaconOv, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, hold_reason, status, journal_seq) VALUES ($1,$2,'coherence','held','archived beacon hold','active',$3)",
      [randomUUID(), ids.beaconOrg, seq],
    );
  });

  const assertZeroEastEverywhere = async (label, token, { expectHarbor = false } = {}) => {
    await runAsPlatformApp(env.pool, { token, readOnly: true }, async (c) => {
      if (expectHarbor) {
        const harborBob = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'Harbor'")).rows[0].n;
        assert.ok(harborBob > 0, `${label} must still see Harbor rows (proving runs_iam_read passed)`);
      }
      for (const [viewName, col] of [
        ['coherence_bob', 'entity'],
        ['v_current_policy_periods', 'entity'],
        ['coherence_statement_agency_lines', 'entity'],
        ['coherence_statement_upline_lines', 'source_entity'],
        ['coherence_entity_statement_lines', 'source_entity'],
        ['coherence_statement_totals', 'statement_entity'],
        ['coherence_ledger', 'entity'],
        ['v_current_commission_ledger', 'entity'],
        ['coherence_entity_statement_reconciliation', 'statement_entity'],
      ]) {
        const n = (await c.query(`SELECT COUNT(*)::int AS n FROM app_views.${viewName} WHERE ${col} = 'East Team'`)).rows[0].n;
        assert.equal(n, 0, `${label} must see 0 East Team rows in app_views.${viewName} (saw ${n})`);
      }
    });
  };

  await t.test('Fix3-1a: dual-agency callers (wide and narrow, East Team switch on) see 0 East Team rows under archived HELD Beacon', async () => {
    await assertZeroEastEverywhere('dualAgencyWide (Beacon held)', tok(dualAgencyWide), { expectHarbor: true });
    await assertZeroEastEverywhere('View-as dualAgencyWide (Beacon held)', tok(ids.nusearOwner, dualAgencyWide), { expectHarbor: true });
    await assertZeroEastEverywhere('dualAgencyNarrow (Beacon held)', tok(dualAgencyNarrow), { expectHarbor: true });
    await assertZeroEastEverywhere('View-as dualAgencyNarrow (Beacon held)', tok(ids.nusearOwner, dualAgencyNarrow), { expectHarbor: true });
    await assertZeroEastEverywhere('agentEastDual (Beacon held)', tok(ids.agentEast));
    await assertZeroEastEverywhere('acmePlusEastWide (Beacon held)', tok(acmePlusEastWide), { expectHarbor: true });
    await assertZeroEastEverywhere('View-as acmePlusEastWide (Beacon held)', tok(ids.nusearOwner, acmePlusEastWide), { expectHarbor: true });

    // Reconciliation for acmePlusEastWide stays $0.00 across both sent r1 and unsent r2 without East Team
    await runAsPlatformApp(env.pool, { token: tok(acmePlusEastWide), readOnly: true }, async (c) => {
      for (const runId of [r1.runId, r2.runId]) {
        const recon = (await c.query(
          'SELECT statement_entity, variance, reconciled FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid',
          [runId],
        )).rows;
        assert.ok(recon.length > 0);
        assert.ok(!recon.some((r) => r.statement_entity === 'East Team'));
        assert.ok(recon.every((r) => r.reconciled === true && r.variance === '0.00'), `expected $0.00 reconciliation: ${JSON.stringify(recon)}`);
      }
    });
  });

  await t.test('Fix3-1b: dual-agency callers (wide and narrow, East Team switch on) see 0 East Team rows under archived OFF Beacon', async () => {
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f3_beacon_off', commandKey: 'f3-beacon-off' });
      const prevTs = (await c.query(
        "SELECT id FROM iam.organization_tool_switches WHERE organization_id = $1 AND tool_id = 'coherence' AND superseded_by_id IS NULL",
        [ids.beaconOrg],
      )).rows[0].id;
      await c.query(
        "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq) VALUES ($1,$2,'coherence','off','active',$3,$4)",
        [randomUUID(), ids.beaconOrg, prevTs, j.seq],
      );
    });

    await assertZeroEastEverywhere('dualAgencyWide (Beacon off)', tok(dualAgencyWide), { expectHarbor: true });
    await assertZeroEastEverywhere('View-as dualAgencyWide (Beacon off)', tok(ids.nusearOwner, dualAgencyWide), { expectHarbor: true });
    await assertZeroEastEverywhere('dualAgencyNarrow (Beacon off)', tok(dualAgencyNarrow), { expectHarbor: true });
    await assertZeroEastEverywhere('agentEastDual (Beacon off)', tok(ids.agentEast));
    await assertZeroEastEverywhere('acmePlusEastWide (Beacon off)', tok(acmePlusEastWide), { expectHarbor: true });
    await assertZeroEastEverywhere('View-as acmePlusEastWide (Beacon off)', tok(ids.nusearOwner, acmePlusEastWide), { expectHarbor: true });
  });

  await t.test('Fix3-1c: under archived ON Beacon, East Team is reachable ONLY from active ancestors above Beacon (not direct grants, not View-as has_archived=false, not col_scopes)', async () => {
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f3_beacon_on', commandKey: 'f3-beacon-on' });
      const prevTs = (await c.query(
        "SELECT id FROM iam.organization_tool_switches WHERE organization_id = $1 AND tool_id = 'coherence' AND superseded_by_id IS NULL",
        [ids.beaconOrg],
      )).rows[0].id;
      await c.query(
        "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq) VALUES ($1,$2,'coherence','on','active',$3,$4)",
        [randomUUID(), ids.beaconOrg, prevTs, j.seq],
      );
    });

    // Active ancestor Acme Entity Manager still sees East Team (sent & unsent) and $0.00 reconciliation
    await runAsPlatformApp(env.pool, { token: tok(ids.acmeEntityMgr), readOnly: true }, async (c) => {
      const eastBob = (await c.query("SELECT amount, upline_amount FROM app_views.coherence_bob WHERE entity = 'East Team'")).rows;
      assert.equal(eastBob.length, 2, 'Acme Entity Manager must see active East Team under archived ON Beacon (both runs)');
      assert.ok(eastBob.every((r) => r.amount === '90.00' && r.upline_amount === '10.00'));
    });

    // Direct East Team grants (wide & narrow) and View-as still see 0 East Team rows
    await assertZeroEastEverywhere('dualAgencyWide (Beacon archived on)', tok(dualAgencyWide), { expectHarbor: true });
    await assertZeroEastEverywhere('View-as dualAgencyWide (Beacon archived on)', tok(ids.nusearOwner, dualAgencyWide), { expectHarbor: true });
    await assertZeroEastEverywhere('dualAgencyNarrow (Beacon archived on)', tok(dualAgencyNarrow), { expectHarbor: true });
    await assertZeroEastEverywhere('agentEastDual (Beacon archived on)', tok(ids.agentEast));

    // col_scopes check (wide and narrow self): Acme no-dollar bob/statements grant + direct East Team cash grant sees East Team row with ALL dollar/cash columns NULL
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f3_agent_east_acme_nodollar', commandKey: 'f3-agent-east-acme-nodollar' });
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), ids.agentEast, ids.acmeOrg, j.seq],
      );
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), ids.agentEast, roleNoDollarBob, ids.acmeOrg, j.seq],
      );
    });
    for (const [label, pid] of [
      ['wide cash grant', acmeNoDollarPlusEastCash],
      ['narrow self cash grant', ids.agentEast],
    ]) {
      await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
        const bobEast = (await c.query("SELECT amount, upline_amount, enrollment_code, conflicts FROM app_views.coherence_bob WHERE entity = 'East Team'")).rows;
        assert.equal(bobEast.length, 1, `Acme no-dollar grant (${label}) sees sent East Team row via archived-path ancestor`);
        assert.equal(bobEast[0].amount, null, `direct East Team ${label} must not unmask amount in coherence_bob`);
        assert.equal(bobEast[0].upline_amount, null, `direct East Team ${label} must not unmask upline_amount in coherence_bob`);
        assert.equal(bobEast[0].enrollment_code, null);
        assert.equal(bobEast[0].conflicts, null);

        const curEast = (await c.query("SELECT amount, upline_amount FROM app_views.v_current_policy_periods WHERE entity = 'East Team'")).rows;
        assert.equal(curEast.length, 1);
        assert.equal(curEast[0].amount, null, `direct East Team ${label} must not unmask amount in v_current_policy_periods`);
        assert.equal(curEast[0].upline_amount, null, `direct East Team ${label} must not unmask upline_amount in v_current_policy_periods`);

        const salEast = (await c.query("SELECT record_id, tx_id, gross_comm, amount FROM app_views.coherence_statement_agency_lines WHERE entity = 'East Team'")).rows;
        assert.equal(salEast.length, 1);
        assert.equal(salEast[0].record_id, null, `direct East Team ${label} must not unmask record_id in statement_agency_lines`);
        assert.equal(salEast[0].tx_id, null);
        assert.equal(salEast[0].gross_comm, null);
        assert.equal(salEast[0].amount, null);
      });
    }
  });

  await t.test('Fix3-1d: dual-agency callers (wide and narrow, East Team switch on) see 0 rows when East Team is detached', async () => {
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f3_detach_east', commandKey: 'f3-detach-east' });
      const prevEdge = (await c.query(
        'SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND superseded_by_id IS NULL',
        [ids.eastTeamOrg],
      )).rows[0].id;
      await c.query(
        "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2026-01-01)'::daterange,'active',$4,$5)",
        [randomUUID(), ids.eastTeamOrg, ids.beaconOrg, prevEdge, j.seq],
      );
    });

    await assertZeroEastEverywhere('dualAgencyWide (East Team detached)', tok(dualAgencyWide), { expectHarbor: true });
    await assertZeroEastEverywhere('View-as dualAgencyWide (East Team detached)', tok(ids.nusearOwner, dualAgencyWide), { expectHarbor: true });
    await assertZeroEastEverywhere('dualAgencyNarrow (East Team detached)', tok(dualAgencyNarrow), { expectHarbor: true });
    await assertZeroEastEverywhere('agentEastDual (East Team detached)', tok(ids.agentEast));
    await assertZeroEastEverywhere('acmePlusEastWide (East Team detached)', tok(acmePlusEastWide), { expectHarbor: true });
    await assertZeroEastEverywhere('acmeEntityMgr (East Team detached)', tok(ids.acmeEntityMgr), { expectHarbor: true });
    await assertZeroEastEverywhere('nusearOwner (East Team detached)', tok(ids.nusearOwner), { expectHarbor: true });
  });
});

test('Layer 7B [Item 4 - Moved Organizations in Working DB]: live Emit for moved agency in Acme DB, its own manager read, Acme staff & Nusear read with $0.00 reconciliation, and new upline zero rows (both active and archived)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const r1 = await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'morg-r1', markSent: true });
  const r2 = await seedPublishedRun(env, { statementDate: '2026-11-15', keyPrefix: 'morg-r2', markSent: false });

  const tok = (personId, viewAsPersonId = null) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId });

  const roleFullScoped = randomUUID();
  const roleNarrowCash = randomUUID();
  const dualCoWide = randomUUID();
  const dualCoNarrow = randomUUID();
  const northstarOnlyMgr = randomUUID();
  const acmeAndNorthstarEM = randomUUID();
  const movedAgencyOwnMgr = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.moved_org_setup', commandKey: 'morg-setup' });
    const seq = j.seq;

    for (const [roleId, slug, name, wide, rightList] of [
      [roleFullScoped, 'morg_dc_full', 'Morg DC Full', true, [
        'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
        'act:coherence.ledger.read', 'act:coherence.unpublished.read',
        'col:coherence.statement_cash', 'col:coherence.upline_cash',
      ]],
      [roleNarrowCash, 'morg_dc_narrow', 'Morg DC Narrow', false, [
        'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.unpublished.read',
        'col:coherence.statement_cash',
      ]],
    ]) {
      await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,NULL,$3)', [roleId, slug, seq]);
      await c.query(
        "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,$3,false,false,$4,'active',$5)",
        [randomUUID(), roleId, name, wide, seq],
      );
      for (const rightId of rightList) {
        await c.query(
          "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), roleId, rightId, seq],
        );
      }
    }

    for (const [pid, name, email] of [
      [dualCoWide, 'Dual Company Wide', 'dc.wide@example.test'],
      [dualCoNarrow, 'Dual Company Narrow', 'dc.narrow@example.test'],
      [northstarOnlyMgr, 'Northstar Upline Mgr', 'ns.mgr@example.test'],
      [acmeAndNorthstarEM, 'Acme Northstar EM', 'dc.em@example.test'],
      [movedAgencyOwnMgr, 'Moved Agency Manager', 'moved.mgr@example.test'],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [pid, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,$3,$3,$4,'active',$5)",
        [randomUUID(), pid, name, email, seq],
      );
    }

    for (const [pid, orgId, cap] of [
      [dualCoWide, ids.harborOrg, 'employee'],
      [dualCoWide, ids.northstarOrg, 'employee'],
      [dualCoNarrow, ids.harborOrg, 'employee'],
      [dualCoNarrow, ids.northstarOrg, 'employee'],
      [northstarOnlyMgr, ids.northstarOrg, 'owner'],
      [acmeAndNorthstarEM, ids.acmeOrg, 'owner'],
      [acmeAndNorthstarEM, ids.northstarOrg, 'owner'],
      [movedAgencyOwnMgr, ids.eastTeamOrg, 'employee'],
    ]) {
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,'[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), pid, orgId, cap, seq],
      );
    }

    for (const [pid, roleId, orgId, incDesc, pMode] of [
      [dualCoWide, roleFullScoped, ids.harborOrg, true, 'org_subtree'],
      [dualCoWide, roleFullScoped, ids.northstarOrg, true, 'org_subtree'],
      [dualCoNarrow, ids.roleAgencyManager, ids.harborOrg, true, 'org_subtree'],
      [northstarOnlyMgr, ids.roleEntityManager, ids.northstarOrg, true, 'org_subtree'],
      [acmeAndNorthstarEM, ids.roleEntityManager, ids.acmeOrg, true, 'org_subtree'],
      [acmeAndNorthstarEM, ids.roleEntityManager, ids.northstarOrg, true, 'org_subtree'],
      [movedAgencyOwnMgr, ids.roleAgencyManager, ids.eastTeamOrg, true, 'org_subtree'],
    ]) {
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,$5,$6,'[2020-01-01,)'::daterange,'active',$7)",
        [randomUUID(), pid, roleId, orgId, incDesc, pMode, seq],
      );
    }
    await c.query(
      "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'self','[2020-01-01,)'::daterange,'active',$5)",
      [randomUUID(), dualCoNarrow, roleNarrowCash, ids.northstarOrg, seq],
    );

    // Move East Team from Beacon (Acme) -> Northstar while ACTIVE (first real moved-agency case)
    const prevEastEdge = (await c.query(
      'SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND superseded_by_id IS NULL',
      [ids.eastTeamOrg],
    )).rows[0].id;
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2025-06-01)'::daterange,'active',$4,$5)",
      [randomUUID(), ids.eastTeamOrg, ids.beaconOrg, prevEastEdge, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2025-06-01,)'::daterange,'active',$4)",
      [randomUUID(), ids.eastTeamOrg, ids.northstarOrg, seq],
    );
  });

  const assertZeroMovedEast = async (label, token, { expectHarbor = true } = {}) => {
    await runAsPlatformApp(env.pool, { token, readOnly: true }, async (c) => {
      if (expectHarbor) {
        const harborBob = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_bob WHERE entity = 'Harbor'")).rows[0].n;
        assert.ok(harborBob > 0, `${label} must still see Harbor rows in Acme DB`);
      }
      for (const [viewName, col] of [
        ['coherence_bob', 'entity'],
        ['v_current_policy_periods', 'entity'],
        ['coherence_statement_agency_lines', 'entity'],
        ['coherence_statement_upline_lines', 'source_entity'],
        ['coherence_entity_statement_lines', 'source_entity'],
        ['coherence_statement_totals', 'statement_entity'],
        ['coherence_ledger', 'entity'],
        ['v_current_commission_ledger', 'entity'],
        ['coherence_entity_statement_reconciliation', 'statement_entity'],
      ]) {
        const n = (await c.query(`SELECT COUNT(*)::int AS n FROM app_views.${viewName} WHERE ${col} = 'East Team'`)).rows[0].n;
        assert.equal(n, 0, `${label} must see 0 moved East Team rows in app_views.${viewName} (saw ${n})`);
      }
    });
  };

  // 1. Live Emit for the moved agency in Acme's working DB succeeds AFTER the move, resolving East Team -> ids.eastTeamOrg!
  let r3PostMove;
  await t.test('Item 4a: live Emit for moved agency in Acme working DB succeeds and populates non-NULL organization_id', async () => {
    r3PostMove = await seedPublishedRun(env, { statementDate: '2026-11-30', keyPrefix: 'morg-r3-post-move', markSent: true });
    const postMoveEast = (await env.pool.query(
      "SELECT organization_id, writing_person_id FROM coherence.bob_policies WHERE run_id = $1::uuid AND entity = 'East Team'",
      [r3PostMove.runId],
    )).rows;
    assert.equal(postMoveEast.length, 1);
    assert.equal(postMoveEast[0].organization_id, ids.eastTeamOrg);
    assert.equal(postMoveEast[0].writing_person_id, ids.agentEast);
  });

  // 2. Moved agency's own manager reads East Team's rows (and 0 rows for Beacon/Harbor/Acme) in Acme's DB!
  await t.test('Item 4b: grant anchored at moved org itself reads that org rows in Acme working DB', async () => {
    await runAsPlatformApp(env.pool, { token: tok(movedAgencyOwnMgr), readOnly: true }, async (c) => {
      const bob = (await c.query('SELECT DISTINCT entity FROM app_views.coherence_bob ORDER BY entity')).rows.map((r) => r.entity);
      assert.deepEqual(bob, ['East Team'], 'moved agency own manager must see East Team rows only');
      const cur = (await c.query('SELECT entity, amount FROM app_views.v_current_policy_periods')).rows;
      assert.equal(cur.length, 1);
      assert.equal(cur[0].entity, 'East Team');
      assert.equal(cur[0].amount, '90.00');
      const stmts = (await c.query("SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines WHERE entity = 'East Team'")).rows[0].n;
      assert.ok(stmts >= 2, 'moved agency own manager must see East Team statement lines across historical & post-move runs');
    });
  });

  // 3. Grants anchored at or above Acme read moved East Team with $0.00 reconciliation; new upline grants see 0 rows!
  await t.test('Item 4c: Acme staff & Nusear read moved agency with $0.00 reconciliation while new upline grants see 0 rows (active under Northstar)', async () => {
    for (const [label, pid] of [
      ['acmeEntityMgr', ids.acmeEntityMgr],
      ['acmeAndNorthstarEM', acmeAndNorthstarEM],
      ['nusearOwner', ids.nusearOwner],
    ]) {
      await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
        for (const runId of [r1.runId, r2.runId, r3PostMove.runId]) {
          const recon = (await c.query(
            'SELECT statement_entity, variance, reconciled FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid',
            [runId],
          )).rows;
          assert.ok(recon.length > 0, `${label} must see reconciliation rows for run ${runId}`);
          assert.ok(recon.some((r) => r.statement_entity === 'East Team'), `${label} must see moved East Team in reconciliation for run ${runId}`);
          assert.ok(recon.every((r) => r.reconciled === true && r.variance === '0.00'), `${label} reconciliation must tie to $0.00 variance`);
        }
      });
    }

    // New upline grants NEVER reach Acme's working DB!
    await assertZeroMovedEast('northstarOnlyMgr (active under Northstar)', tok(northstarOnlyMgr), { expectHarbor: false });
    await assertZeroMovedEast('dualCoWide (active under Northstar)', tok(dualCoWide));
    await assertZeroMovedEast('View-as dualCoWide (active under Northstar)', tok(ids.nusearOwner, dualCoWide));
    await assertZeroMovedEast('dualCoNarrow (active under Northstar)', tok(dualCoNarrow));
  });

  // 4. After moved org is archived under Northstar, Acme staff & Nusear STILL read it with $0.00 reconciliation,
  //    while new upline grants STILL see 0 rows!
  await t.test('Item 4d: after moved agency is archived under Northstar, Acme staff & Nusear still read with $0.00 reconciliation and new upline sees 0 rows', async () => {
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.morg_arch', commandKey: 'morg-arch' });
      const seq = j.seq;
      const curNsEdge = (await c.query(
        'SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND parent_org_id = $2 AND superseded_by_id IS NULL',
        [ids.eastTeamOrg, ids.northstarOrg],
      )).rows[0].id;
      await c.query(
        "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'[2025-06-01,2026-01-01)'::daterange,'active',$4,$5)",
        [randomUUID(), ids.eastTeamOrg, ids.northstarOrg, curNsEdge, seq],
      );
      const prevOv = (await c.query(
        'SELECT id FROM iam.organization_versions WHERE organization_id = $1 AND superseded_by_id IS NULL',
        [ids.eastTeamOrg],
      )).rows[0].id;
      await c.query(
        "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, replaces_id, journal_seq) VALUES ($1,$2,'east_team','East Team','archived',$3,$4)",
        [randomUUID(), ids.eastTeamOrg, prevOv, seq],
      );
    });

    for (const [label, pid] of [
      ['acmeEntityMgr', ids.acmeEntityMgr],
      ['acmeAndNorthstarEM', acmeAndNorthstarEM],
      ['nusearOwner', ids.nusearOwner],
    ]) {
      await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
        for (const runId of [r1.runId, r2.runId, r3PostMove.runId]) {
          const recon = (await c.query(
            'SELECT statement_entity, variance, reconciled FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid',
            [runId],
          )).rows;
          assert.ok(recon.some((r) => r.statement_entity === 'East Team'), `${label} must still see archived moved East Team in reconciliation`);
          assert.ok(recon.every((r) => r.reconciled === true && r.variance === '0.00'), `${label} archived moved reconciliation must tie to $0.00`);
        }
      });
    }

    await assertZeroMovedEast('northstarOnlyMgr (archived under Northstar)', tok(northstarOnlyMgr), { expectHarbor: false });
    await assertZeroMovedEast('dualCoWide (archived under Northstar)', tok(dualCoWide));
    await assertZeroMovedEast('View-as dualCoWide (archived under Northstar)', tok(ids.nusearOwner, dualCoWide));
    await assertZeroMovedEast('dualCoNarrow (archived under Northstar)', tok(dualCoNarrow));
  });
});

test('Layer 7B [Fix3-2 - Catalog Audit Non-Vacuous _resolve_* and _cmd_* Loop & Keyed-Table Tenant-Tree Bound]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const cleanAudit = await withClusterCatalogLock(() => policyChecks.verifyIamConfigInvariants(env.pool));
  assert.equal(cleanAudit.passed, true, `clean audit failed:\n${cleanAudit.problems.join('\n')}`);

  await t.test('Positive mutation: granting EXECUTE on coherence._resolve_entity_org_id to platform_readonly fails audit', async () => {
    await env.pool.query('GRANT EXECUTE ON FUNCTION coherence._resolve_entity_org_id(text, text, jsonb) TO platform_readonly');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'granting EXECUTE on _resolve_entity_org_id to platform_readonly must fail audit');
      assert.ok(bad.problems.some((p) => /_resolve_entity_org_id/.test(p) && /platform_readonly/.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query('REVOKE EXECUTE ON FUNCTION coherence._resolve_entity_org_id(text, text, jsonb) FROM platform_readonly');
    }
  });

  await t.test('Positive mutation: granting EXECUTE on coherence._cmd_resolve_context to platform_worker fails audit', async () => {
    await env.pool.query('GRANT EXECUTE ON FUNCTION coherence._cmd_resolve_context(text, text) TO platform_worker');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'granting EXECUTE on _cmd_resolve_context to platform_worker must fail audit');
      assert.ok(bad.problems.some((p) => /_cmd_resolve_context/.test(p) && /platform_worker/.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query('REVOKE EXECUTE ON FUNCTION coherence._cmd_resolve_context(text, text) FROM platform_worker');
    }
  });

  await t.test('Positive mutation: audit fails when _resolve_* matches no functions', async () => {
    const fns = (await env.pool.query(
      `SELECT p.proname, pg_catalog.oidvectortypes(p.proargtypes) AS args
       FROM pg_catalog.pg_proc p
       JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'coherence' AND p.proname LIKE '\\_resolve\\_%' ESCAPE '\\'
       ORDER BY p.proname`,
    )).rows;
    assert.ok(fns.length > 0, 'expected _resolve_* functions to exist before mutation');
    for (const fn of fns) {
      await env.pool.query(`ALTER FUNCTION coherence.${fn.proname}(${fn.args}) RENAME TO tmp_m${fn.proname}`);
    }
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'audit must fail when _resolve_* matches no functions');
      assert.ok(bad.problems.some((p) => /_resolve_/i.test(p)), `expected _resolve_* zero-match problem, got: ${bad.problems.join('; ')}`);
    } finally {
      for (const fn of fns) {
        await env.pool.query(`ALTER FUNCTION coherence.tmp_m${fn.proname}(${fn.args}) RENAME TO ${fn.proname}`);
      }
    }
  });

  await t.test('Positive mutation: audit fails when _cmd_* matches no functions', async () => {
    const fns = (await env.pool.query(
      `SELECT p.proname, pg_catalog.oidvectortypes(p.proargtypes) AS args
       FROM pg_catalog.pg_proc p
       JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'coherence' AND p.proname LIKE '\\_cmd\\_%' ESCAPE '\\'
       ORDER BY p.proname`,
    )).rows;
    assert.ok(fns.length > 0, 'expected _cmd_* functions to exist before mutation');
    for (const fn of fns) {
      await env.pool.query(`ALTER FUNCTION coherence.${fn.proname}(${fn.args}) RENAME TO tmp_m${fn.proname}`);
    }
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'audit must fail when _cmd_* matches no functions');
      assert.ok(bad.problems.some((p) => /_cmd_/i.test(p)), `expected _cmd_* zero-match problem, got: ${bad.problems.join('; ')}`);
    } finally {
      for (const fn of fns) {
        await env.pool.query(`ALTER FUNCTION coherence.tmp_m${fn.proname}(${fn.args}) RENAME TO ${fn.proname}`);
      }
    }
  });

  await t.test('Positive mutation: unscoped policy, worker audit_journal INSERT, worker compute_journal_hash EXECUTE, or legacy coherence_app policy fails audit', async () => {
    await env.pool.query(
      'CREATE POLICY bob_policies_unbounded_probe ON coherence.bob_policies FOR SELECT TO platform_view_owner USING (true)',
    );
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'USING (true) policy on coherence.bob_policies must fail audit');
      assert.ok(bad.problems.some((p) => /bob_policies/i.test(p) && /unscoped|USING \(true\)/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query('DROP POLICY IF EXISTS bob_policies_unbounded_probe ON coherence.bob_policies');
    }

    await env.pool.query('GRANT INSERT ON platform.audit_journal TO platform_worker');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'granting INSERT on platform.audit_journal to platform_worker must fail audit');
      assert.ok(bad.problems.some((p) => /platform_worker/i.test(p) && /audit_journal/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query('REVOKE INSERT ON platform.audit_journal FROM platform_worker');
    }

    await env.pool.query('GRANT EXECUTE ON FUNCTION platform.compute_journal_hash(BIGINT, TIMESTAMPTZ, TEXT, UUID, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, JSONB) TO platform_worker');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'granting EXECUTE on platform.compute_journal_hash to platform_worker must fail audit');
      assert.ok(bad.problems.some((p) => /platform_worker/i.test(p) && /compute_journal_hash/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query('REVOKE EXECUTE ON FUNCTION platform.compute_journal_hash(BIGINT, TIMESTAMPTZ, TEXT, UUID, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, JSONB) FROM platform_worker');
    }

    await env.pool.query('GRANT EXECUTE ON FUNCTION app_views._read_bob_wide_orgs() TO platform_worker');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'granting EXECUTE on app_views._read_bob_wide_orgs to platform_worker must fail audit');
      assert.ok(bad.problems.some((p) => /_read_bob_wide_orgs/i.test(p) && /platform_worker/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query('REVOKE EXECUTE ON FUNCTION app_views._read_bob_wide_orgs() FROM platform_worker');
    }

    await env.pool.query('REVOKE EXECUTE ON FUNCTION app_views._read_bob_wide_orgs() FROM platform_readonly');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'revoking EXECUTE on app_views._read_bob_wide_orgs from platform_readonly must fail audit');
      assert.ok(bad.problems.some((p) => /_read_bob_wide_orgs/i.test(p) && /platform_readonly/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query('GRANT EXECUTE ON FUNCTION app_views._read_bob_wide_orgs() TO platform_readonly');
    }

    await env.pool.query('GRANT SELECT (policy_id) ON app_views.coherence_bob TO PUBLIC');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'granting column-level SELECT on app_views.coherence_bob to PUBLIC must fail audit');
      assert.ok(bad.problems.some((p) => /PUBLIC/i.test(p) && /column-level/i.test(p) && /coherence_bob/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query('REVOKE SELECT (policy_id) ON app_views.coherence_bob FROM PUBLIC');
    }

    await env.pool.query("CREATE FUNCTION coherence.upline_entity_label() RETURNS TEXT LANGUAGE sql SET search_path = pg_catalog AS $$ SELECT ''::text $$");
    await env.pool.query('REVOKE ALL ON FUNCTION coherence.upline_entity_label() FROM PUBLIC');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'retired Migration 006 helper coherence.upline_entity_label must fail audit');
      assert.ok(bad.problems.some((p) => /Retired Migration 006 helper/i.test(p) && /upline_entity_label/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query('DROP FUNCTION IF EXISTS coherence.upline_entity_label()');
    }

    await env.pool.query('CREATE SCHEMA coherence_views');
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'creating retired schema coherence_views must fail audit');
      assert.ok(bad.problems.some((p) => /coherence_views/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query('DROP SCHEMA IF EXISTS coherence_views');
    }

    await withClusterCatalogLock(async () => {
      const hasLegacyRole = (await env.pool.query("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'coherence_app'")).rows.length > 0;
      if (!hasLegacyRole) {
        await env.pool.query('CREATE ROLE coherence_app NOLOGIN NOINHERIT NOBYPASSRLS');
      }
      try {
        await env.pool.query('CREATE POLICY bob_policies_legacy_probe ON coherence.bob_policies FOR ALL TO coherence_app USING (true) WITH CHECK (true)');
        try {
          const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
          assert.equal(bad.passed, false, 'legacy coherence_app USING (true) policy must fail audit');
          assert.ok(bad.problems.some((p) => /coherence_app/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
        } finally {
          await env.pool.query('DROP POLICY IF EXISTS bob_policies_legacy_probe ON coherence.bob_policies');
        }

        await env.pool.query('GRANT SELECT ON coherence.runs TO coherence_app');
        try {
          const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
          assert.equal(bad.passed, false, 'granting SELECT on coherence.runs to retired coherence_app must fail audit');
          assert.ok(bad.problems.some((p) => /coherence_app/i.test(p) && /runs/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
        } finally {
          await env.pool.query('REVOKE SELECT ON coherence.runs FROM coherence_app');
        }

        await env.pool.query('GRANT SELECT (policy_id) ON app_views.coherence_bob TO coherence_app');
        try {
          const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
          assert.equal(bad.passed, false, 'granting column-level SELECT on app_views.coherence_bob to retired coherence_app must fail audit');
          assert.ok(bad.problems.some((p) => /coherence_app/i.test(p) && /column-level/i.test(p) && /coherence_bob/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
        } finally {
          await env.pool.query('REVOKE SELECT (policy_id) ON app_views.coherence_bob FROM coherence_app');
        }
      } finally {
        if (!hasLegacyRole) {
          await env.pool.query('DROP ROLE IF EXISTS coherence_app');
        }
      }
    });
  });
});

test('Layer 7B [Fix4 - Narrow unpublished.read Stays Narrow Across Keyed Tables & Reconciliation, and platform.audit_journal Tenant-Bound Audit]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const r1 = await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'f4-unpub-r1', markSent: true });
  const r2 = await seedPublishedRun(env, { statementDate: '2026-11-15', keyPrefix: 'f4-unpub-r2', markSent: false });
  await runAsRole(env.pool, 'platform_migrator', { readOnly: false }, (c) => (
    c.query('SELECT * FROM coherence.backfill_iam_foreign_keys()')
  ));

  const tok = (personId, viewAsPersonId = null) => mintSignedToken({ keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId });

  const roleUnpubNarrow = randomUUID();
  const roleUnpubWide = randomUUID();
  const roleSentEntityMgr = randomUUID();
  const sentAgencyPlusExplicitUnpub = randomUUID();
  const sentEmPlusExplicitUnpub = randomUUID();
  const sentEmAcmeWideBeaconNarrowUnpub = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f4_unpub_setup', commandKey: 'f4-unpub-setup' });
    const seq = j.seq;

    for (const [roleId, slug, name, wide, rightList] of [
      [roleUnpubNarrow, 'f4_unpub_narrow', 'F4 Unpub Narrow', false, ['act:coherence.unpublished.read']],
      [roleUnpubWide, 'f4_unpub_wide', 'F4 Unpub Wide', true, ['act:coherence.unpublished.read']],
      [roleSentEntityMgr, 'f4_sent_em', 'F4 Sent Entity Manager', true, [
        'act:coherence.bob.read', 'act:coherence.statements.read', 'act:coherence.upline.read',
        'act:coherence.ledger.read', 'col:coherence.statement_cash', 'col:coherence.upline_cash',
      ]],
    ]) {
      await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,$3,$4)', [roleId, slug, ids.acmeOrg, seq]);
      await c.query(
        "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,$3,false,false,$4,'active',$5)",
        [randomUUID(), roleId, name, wide, seq],
      );
      for (const rightId of rightList) {
        await c.query(
          "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
          [randomUUID(), roleId, rightId, seq],
        );
      }
    }

    for (const [pid, name, email] of [
      [sentAgencyPlusExplicitUnpub, 'Sent Agency Narrow Unpub', 'f4.sa.nu@acme.example'],
      [sentEmPlusExplicitUnpub, 'Sent EM Narrow Unpub', 'f4.em.nu@acme.example'],
      [sentEmAcmeWideBeaconNarrowUnpub, 'Sent EM AcmeWide BeaconNarrow Unpub', 'f4.em.awbn@acme.example'],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [pid, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,$3,$3,$4,'active',$5)",
        [randomUUID(), pid, name, email, seq],
      );
    }

    for (const [pid, orgId, cap] of [
      [ids.agentA, ids.beaconOrg, 'employee'],
      [sentAgencyPlusExplicitUnpub, ids.beaconOrg, 'employee'],
      [sentEmPlusExplicitUnpub, ids.acmeOrg, 'owner'],
      [sentEmAcmeWideBeaconNarrowUnpub, ids.acmeOrg, 'owner'],
    ]) {
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,'[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), pid, orgId, cap, seq],
      );
    }

    // 1. agentA: wide sent-only Agency Manager on Beacon + narrow self unpublished.read on Beacon
    await c.query(
      "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), ids.agentA, ids.acmeOrg, seq],
    );
    for (const [pid, roleId, orgId, incDesc, pMode] of [
      [ids.agentA, ids.roleAgencyManager, ids.beaconOrg, true, 'org_subtree'],
      [ids.agentA, roleUnpubNarrow, ids.beaconOrg, false, 'self'],
    ]) {
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,$5,$6,'[2020-01-01,)'::daterange,'active',$7)",
        [randomUUID(), pid, roleId, orgId, incDesc, pMode, seq],
      );
    }
  });

  await t.test('Fix4-1: wide sent-only agency role + narrow self unpublished.read on Beacon sees ONLY agentA unsent rows in bob, financials, and agency statements (direct and View-as)', async () => {
    for (const [label, token] of [
      ['self (agentA)', tok(ids.agentA)],
      ['View-as self (agentA)', tok(ids.nusearOwner, ids.agentA)],
    ]) {
      await runAsPlatformApp(env.pool, { token, readOnly: true }, async (c) => {
        const sentBob = (await c.query(
          'SELECT policy_id, writing_person_id, entity, amount FROM app_views.coherence_bob WHERE run_id = $1::uuid ORDER BY policy_id',
          [r1.runId],
        )).rows;
        assert.equal(sentBob.length, 3, `${label}: sent r1 coherence_bob must include all 3 Beacon-subtree policies`);
        assert.deepEqual(sentBob.map((r) => r.amount), ['80.00', '120.00', '90.00']);

        const unsentBob = (await c.query(
          'SELECT policy_id, writing_person_id, entity, amount FROM app_views.coherence_bob WHERE run_id = $1::uuid ORDER BY policy_id',
          [r2.runId],
        )).rows;
        assert.equal(unsentBob.length, 1, `${label}: unsent r2 coherence_bob must include ONLY agentA, got ${JSON.stringify(unsentBob)}`);
        assert.equal(unsentBob[0].policy_id, 1);
        assert.equal(unsentBob[0].writing_person_id, ids.agentA);
        assert.equal(unsentBob[0].amount, '80.00', `${label}: bob_policy_financials must stay visible for narrow person's unsent row`);

        const curPol = (await c.query(
          'SELECT run_id, policy_id, writing_person_id, amount FROM app_views.v_current_policy_periods ORDER BY policy_id',
        )).rows;
        assert.equal(curPol.length, 1, `${label}: v_current_policy_periods on r2 must show ONLY agentA, got ${JSON.stringify(curPol)}`);
        assert.equal(curPol[0].run_id, r2.runId);
        assert.equal(curPol[0].writing_person_id, ids.agentA);
        assert.equal(curPol[0].amount, '80.00');

        const sentSal = (await c.query(
          "SELECT policy_id, writing_person_id, entity, amount FROM app_views.coherence_statement_agency_lines WHERE statement_date = DATE '2026-10-31' ORDER BY policy_id",
        )).rows;
        assert.equal(sentSal.length, 3, `${label}: sent r1 statement_agency_lines must include all 3 Beacon-subtree rows`);

        const unsentSal = (await c.query(
          "SELECT policy_id, writing_person_id, entity, amount FROM app_views.coherence_statement_agency_lines WHERE statement_date = DATE '2026-11-15' ORDER BY policy_id",
        )).rows;
        assert.equal(unsentSal.length, 1, `${label}: unsent r2 statement_agency_lines must include ONLY agentA, got ${JSON.stringify(unsentSal)}`);
        assert.equal(unsentSal[0].policy_id, 1);
        assert.equal(unsentSal[0].writing_person_id, ids.agentA);
        assert.equal(unsentSal[0].amount, '80.00');

        const unsentTotals = (await c.query(
          "SELECT statement_entity, line_count::int, net_amount FROM app_views.coherence_statement_totals WHERE statement_date = DATE '2026-11-15'",
        )).rows;
        assert.equal(unsentTotals.length, 1, `${label}: unsent r2 statement_totals must only contain Beacon (agentA)`);
        assert.equal(unsentTotals[0].statement_entity, 'Beacon');
        assert.equal(unsentTotals[0].line_count, 1);
        assert.equal(unsentTotals[0].net_amount, '80.00');

        // Run/batch metadata tables still keep effective_any_org_ids so narrow unpublished.read callers see the unsent batch metadata.
        const batches = (await c.query('SELECT run_id FROM app_views.coherence_statement_batches ORDER BY statement_date')).rows;
        assert.deepEqual(batches.map((r) => r.run_id), [r1.runId, r2.runId], `${label}: statement_batches metadata must remain visible for unsent run`);
      });
    }
  });

  await t.test('Fix4-2: wide sent-only Entity Manager + narrow self unpublished.read on Beacon sees ONLY agentA unsent bob/agency rows and 0 unsent upline, ledger, and reconciliation rows', async () => {
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f4_em_self', commandKey: 'f4-em-self' });
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), ids.agentA, roleSentEntityMgr, ids.acmeOrg, j.seq],
      );
    });
    for (const [label, token] of [
      ['agentA (sentEM + self unpub)', tok(ids.agentA)],
      ['View-as agentA (sentEM + self unpub)', tok(ids.nusearOwner, ids.agentA)],
    ]) {
      await runAsPlatformApp(env.pool, { token, readOnly: true }, async (c) => {
        const unsentBob = (await c.query(
          'SELECT policy_id, writing_person_id, amount, upline_amount FROM app_views.coherence_bob WHERE run_id = $1::uuid ORDER BY policy_id',
          [r2.runId],
        )).rows;
        assert.equal(unsentBob.length, 1, `${label}: unsent r2 coherence_bob must include ONLY agentA, got ${JSON.stringify(unsentBob)}`);
        assert.equal(unsentBob[0].writing_person_id, ids.agentA);
        assert.equal(unsentBob[0].amount, '80.00');
        assert.equal(unsentBob[0].upline_amount, '20.00');

        const unsentSal = (await c.query(
          "SELECT policy_id, writing_person_id, amount FROM app_views.coherence_statement_agency_lines WHERE statement_date = DATE '2026-11-15' ORDER BY policy_id",
        )).rows;
        assert.equal(unsentSal.length, 1, `${label}: unsent r2 statement_agency_lines must include ONLY agentA, got ${JSON.stringify(unsentSal)}`);
        assert.equal(unsentSal[0].writing_person_id, ids.agentA);

        const sentUpline = (await c.query(
          "SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_upline_lines WHERE statement_date = DATE '2026-10-31'",
        )).rows[0].n;
        assert.equal(sentUpline, 5);
        const unsentUpline = (await c.query(
          "SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_upline_lines WHERE statement_date = DATE '2026-11-15'",
        )).rows[0].n;
        assert.equal(unsentUpline, 0, `${label}: narrow unpublished.read must NOT open unsent statement_upline_lines`);

        const sentLedger = (await c.query(
          'SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger WHERE run_id = $1::uuid',
          [r1.runId],
        )).rows[0].n;
        assert.equal(sentLedger, 5);
        const unsentLedger = (await c.query(
          'SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger WHERE run_id = $1::uuid',
          [r2.runId],
        )).rows[0].n;
        assert.equal(unsentLedger, 0, `${label}: narrow unpublished.read must NOT open unsent coherent_ledger_rows`);

        const curLedger = (await c.query('SELECT DISTINCT run_id FROM app_views.v_current_commission_ledger')).rows;
        assert.deepEqual(curLedger.map((r) => r.run_id), [r1.runId], `${label}: v_current_commission_ledger must stay on sent r1`);

        const sentRecon = (await c.query(
          'SELECT statement_entity, variance, reconciled FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid',
          [r1.runId],
        )).rows;
        assert.ok(sentRecon.length > 0 && sentRecon.every((r) => r.reconciled === true && r.variance === '0.00'));

        const unsentRecon = (await c.query(
          'SELECT statement_entity, account_kind, statement_total, ledger_total, variance FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid',
          [r2.runId],
        )).rows;
        assert.equal(unsentRecon.length, 0, `${label}: narrow unpublished.read must produce 0 unsent reconciliation rows, got ${JSON.stringify(unsentRecon)}`);

        const batches = (await c.query(
          `SELECT run_id, agency_line_count, agency_lines_sha256, agency_net_total,
                  upline_line_count, upline_lines_sha256, upline_net_total
           FROM app_views.coherence_statement_batches
           ORDER BY statement_date`,
        )).rows;
        assert.deepEqual(batches.map((r) => r.run_id), [r1.runId, r2.runId], `${label}: expected sent r1 and unsent r2 batches`);
        const [sentBatch, unsentBatch] = batches;
        for (const col of ['agency_line_count', 'agency_lines_sha256', 'agency_net_total', 'upline_line_count', 'upline_lines_sha256', 'upline_net_total']) {
          assert.notEqual(sentBatch[col], null, `${label}: sent r1 batch ${col} must be filled`);
          assert.equal(unsentBatch[col], null, `${label}: unsent r2 batch ${col} must be NULL`);
        }
        assert.equal(sentBatch.agency_net_total, '490.00');
        assert.equal(sentBatch.upline_net_total, '170.00');
      });
    }
  });

  await t.test('Fix4-3: wide unpublished.read on Acme (no descendants) + narrow self unpublished.read on Beacon keeps r2 reconciliation clean (Acme $0.00, Beacon absent) and upline/ledger wide-only', async () => {
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.f4_acme_wide_unpub', commandKey: 'f4-acme-wide-unpub' });
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,false,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), ids.agentA, roleUnpubWide, ids.acmeOrg, j.seq],
      );
    });
    await runAsPlatformApp(env.pool, { token: tok(ids.agentA), readOnly: true }, async (c) => {
      const unsentBob = (await c.query(
        'SELECT policy_id, writing_person_id, entity FROM app_views.coherence_bob WHERE run_id = $1::uuid ORDER BY policy_id',
        [r2.runId],
      )).rows;
      assert.equal(unsentBob.length, 1);
      assert.equal(unsentBob[0].writing_person_id, ids.agentA);

      const unsentUpline = (await c.query(
        "SELECT source_entity, amount FROM app_views.coherence_statement_upline_lines WHERE statement_date = DATE '2026-11-15'",
      )).rows;
      assert.equal(unsentUpline.length, 1, `expected only Acme house upline row in r2, got ${JSON.stringify(unsentUpline)}`);
      assert.equal(unsentUpline[0].source_entity, 'Acme');

      const unsentLedger = (await c.query(
        'SELECT entity, upline_amount FROM app_views.coherence_ledger WHERE run_id = $1::uuid',
        [r2.runId],
      )).rows;
      assert.equal(unsentLedger.length, 1, `expected only Acme house ledger row in r2, got ${JSON.stringify(unsentLedger)}`);
      assert.equal(unsentLedger[0].entity, 'Acme');

      const unsentRecon = (await c.query(
        'SELECT statement_entity, account_kind, statement_total, ledger_total, variance, reconciled FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid ORDER BY account_kind, statement_entity',
        [r2.runId],
      )).rows;
      assert.equal(unsentRecon.length, 2, `r2 reconciliation must include only wide-unpublished Acme agency + Acme Upline (never narrow Beacon), got ${JSON.stringify(unsentRecon)}`);
      assert.ok(!unsentRecon.some((r) => ['Beacon', 'East Team', 'Harbor'].includes(r.statement_entity)), `narrow Beacon must never appear in r2 reconciliation: ${JSON.stringify(unsentRecon)}`);
      assert.ok(unsentRecon.every((r) => r.reconciled === true && r.variance === '0.00'), `expected $0.00 variance on all r2 reconciliation rows: ${JSON.stringify(unsentRecon)}`);
      const uplineRow = unsentRecon.find((r) => r.account_kind === 'upline');
      assert.equal(uplineRow?.statement_entity, 'Acme Upline');
      assert.equal(uplineRow?.statement_total, '60.00');
      assert.equal(uplineRow?.ledger_total, '60.00');

      const batches = (await c.query(
        `SELECT run_id, agency_line_count, agency_lines_sha256, agency_net_total,
                upline_line_count, upline_lines_sha256, upline_net_total
         FROM app_views.coherence_statement_batches
         ORDER BY statement_date`,
      )).rows;
      assert.deepEqual(batches.map((r) => r.run_id), [r1.runId, r2.runId], 'expected sent r1 and unsent r2 batches');
      const [sentBatch, unsentBatch] = batches;
      for (const col of ['agency_line_count', 'agency_lines_sha256', 'agency_net_total', 'upline_line_count', 'upline_lines_sha256', 'upline_net_total']) {
        assert.notEqual(sentBatch[col], null, `sent r1 batch ${col} must be filled`);
        assert.equal(unsentBatch[col], null, `unsent r2 batch ${col} must be NULL`);
      }
      assert.equal(sentBatch.agency_net_total, '490.00');
      assert.equal(sentBatch.upline_net_total, '170.00');
    });
  });

  await t.test('Fix4-4: catalog audit requires tenant bound (database_context + v_organization_closure_live) on platform.audit_journal RLS policy, and none of the five keyed tables or reconciliation view use effective_any_org_ids', async () => {
    const cleanAudit = await withClusterCatalogLock(() => policyChecks.verifyIamConfigInvariants(env.pool));
    assert.equal(cleanAudit.passed, true, `clean audit failed:\n${cleanAudit.problems.join('\n')}`);

    const keyedPols = (await env.pool.query(
      `SELECT tablename, policyname, qual
       FROM pg_catalog.pg_policies
       WHERE schemaname = 'coherence'
         AND tablename IN ('bob_policies', 'bob_policy_financials', 'statement_agency_lines', 'statement_upline_lines', 'coherent_ledger_rows')
         AND 'platform_view_owner' = ANY(roles)`,
    )).rows;
    assert.equal(keyedPols.length, 5);
    for (const p of keyedPols) {
      assert.ok(!/effective_any_org_ids/.test(p.qual || ''), `keyed table coherence.${p.tablename} (${p.policyname}) must not use effective_any_org_ids`);
    }
    const reconDef = (await env.pool.query(
      "SELECT definition FROM pg_catalog.pg_views WHERE schemaname = 'app_views' AND viewname = 'coherence_entity_statement_reconciliation'",
    )).rows[0]?.definition || '';
    assert.ok(!/effective_any_org_ids/.test(reconDef), 'app_views.coherence_entity_statement_reconciliation must not use effective_any_org_ids');

    await env.pool.query(
      `CREATE POLICY bob_policies_any_org_probe ON coherence.bob_policies
       FOR SELECT TO platform_view_owner
       USING (
         organization_id = ANY(iam.effective_wide_org_ids('act:coherence.bob.read'))
         AND organization_id = ANY(iam.effective_any_org_ids('act:coherence.unpublished.read'))
         AND organization_id = ANY(COALESCE((
           SELECT pg_catalog.array_agg(c.descendant_org_id)
           FROM iam.database_context dc
           JOIN iam.v_organization_closure_live c ON c.ancestor_org_id = dc.tenant_org_id
           WHERE dc.singleton = true
         ), ARRAY[]::uuid[]))
       )`,
    );
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'keyed table policy referencing effective_any_org_ids must fail audit');
      assert.ok(bad.problems.some((p) => /bob_policies/i.test(p) && /effective_any_org_ids/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query('DROP POLICY IF EXISTS bob_policies_any_org_probe ON coherence.bob_policies');
    }

    const probeClient = await env.pool.connect();
    try {
      await probeClient.query('BEGIN');
      await probeClient.query(
        `CREATE OR REPLACE VIEW app_views.coherence_entity_statement_reconciliation
         WITH (security_barrier = true) AS
         SELECT NULL::uuid AS run_id,
                NULL::uuid AS attempt_event_id,
                NULL::date AS statement_date,
                NULL::text AS statement_entity,
                NULL::text AS account_kind,
                NULL::numeric(14,2) AS statement_total,
                NULL::numeric(14,2) AS ledger_total,
                NULL::numeric(14,2) AS variance,
                NULL::boolean AS reconciled
         WHERE (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
           = ANY(iam.effective_any_org_ids('act:coherence.unpublished.read'))`,
      );
      const bad = await policyChecks.verifyIamConfigInvariants(probeClient);
      assert.equal(bad.passed, false, 'reconciliation view referencing effective_any_org_ids must fail audit');
      assert.ok(
        bad.problems.some((p) => /coherence_entity_statement_reconciliation/i.test(p) && /effective_any_org_ids/i.test(p)),
        `unexpected problems: ${bad.problems.join('; ')}`,
      );

      await probeClient.query(
        `CREATE OR REPLACE VIEW app_views.coherence_entity_statement_reconciliation
         WITH (security_barrier = true) AS
         SELECT NULL::uuid AS run_id,
                NULL::uuid AS attempt_event_id,
                NULL::date AS statement_date,
                NULL::text AS statement_entity,
                NULL::text AS account_kind,
                NULL::numeric(14,2) AS statement_total,
                NULL::numeric(14,2) AS ledger_total,
                NULL::numeric(14,2) AS variance,
                NULL::boolean AS reconciled
         WHERE (SELECT app_views._read_has_run_meta_access())`,
      );
      const badMeta = await policyChecks.verifyIamConfigInvariants(probeClient);
      assert.equal(badMeta.passed, false, 'reconciliation view referencing metadata-only _read_has_run_meta_access must fail audit');
      assert.ok(
        badMeta.problems.some((p) => /coherence_entity_statement_reconciliation/i.test(p)),
        `unexpected problems: ${badMeta.problems.join('; ')}`,
      );
    } finally {
      await probeClient.query('ROLLBACK').catch(() => {});
      probeClient.release();
    }

    await env.pool.query(
      "CREATE POLICY audit_journal_has_right_probe ON platform.audit_journal FOR SELECT TO platform_view_owner USING (iam.has_right('act:platform.audit_journal.read'))",
    );
    try {
      const bad = await policyChecks.verifyIamConfigInvariants(env.pool);
      assert.equal(bad.passed, false, 'unscoped iam.has_right policy on platform.audit_journal must fail audit');
      assert.ok(bad.problems.some((p) => /audit_journal/i.test(p) && /unscoped|effective_wide_org_ids/i.test(p)), `unexpected problems: ${bad.problems.join('; ')}`);
    } finally {
      await env.pool.query('DROP POLICY IF EXISTS audit_journal_has_right_probe ON platform.audit_journal');
    }
  });
});

test('Layer 7B [Release C1 Item 8 - Time-Consistent Chains in iam.v_organization_closure]: post-move team under moved agency is absent from old company tree and its people see nothing there; pre-move old team is absent from new upline tree; v_organization_closure_live stays today tree', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const tok = (personId, viewAsPersonId = null) => mintSignedToken({
    keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId,
  });

  const movedAgency = randomUUID();
  const oldPreMoveTeam = randomUUID();
  const movedActiveTeam = randomUUID();
  const newPostMoveTeam = randomUUID();
  const rejoinAgency = randomUUID();
  const rejoinPreLeaveTeam = randomUUID();
  const rejoinAwayTeam = randomUUID();
  const rejoinStayTeam = randomUUID();
  const rejoinPostTeam = randomUUID();

  const movedAgencyMgr = randomUUID();
  const movedActiveTeamMgr = randomUUID();
  const newTeamMgr = randomUUID();
  const newTeamAgent = randomUUID();
  const northstarEM = randomUUID();
  const nsOnlyMemberMovedGrant = randomUUID();
  const acmeMemberMovedGrant = randomUUID();
  const rejoinAgencyMgr = randomUUID();
  const nsOnlyMemberRejoinGrant = randomUUID();
  const acmeMemberRejoinGrant = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.c1_item8_setup', commandKey: 'c1-item8-setup' });
    const seq = j.seq;

    // 1. Moved Agency: under Acme during [2020-01-01, 2025-06-01), then under Northstar during [2025-06-01, ).
    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'agency',$2)", [movedAgency, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'moved_agency','Moved Agency','active',$3)",
      [randomUUID(), movedAgency, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2025-06-01)'::daterange,'active',$4)",
      [randomUUID(), movedAgency, ids.acmeOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2025-06-01,)'::daterange,'active',$4)",
      [randomUUID(), movedAgency, ids.northstarOrg, seq],
    );

    // 2. Old Pre-Move Team: existed under Moved Agency ONLY before the move [2020-01-01, 2025-01-01) and archived.
    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'team',$2)", [oldPreMoveTeam, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'old_pre_move_team','Old Pre Move Team','archived',$3)",
      [randomUUID(), oldPreMoveTeam, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2025-01-01)'::daterange,'active',$4)",
      [randomUUID(), oldPreMoveTeam, movedAgency, seq],
    );

    // 2b. Moved Active Team: active team under Moved Agency since [2020-01-01, ) that moved WITH Moved Agency.
    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'team',$2)", [movedActiveTeam, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'moved_active_team','Moved Active Team','active',$3)",
      [randomUUID(), movedActiveTeam, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), movedActiveTeam, movedAgency, seq],
    );

    // 3. New Post-Move Team: added under Moved Agency ONLY after the move [2025-07-01, ), active.
    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'team',$2)", [newPostMoveTeam, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'new_post_move_team','New Post Move Team','active',$3)",
      [randomUUID(), newPostMoveTeam, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2025-07-01,)'::daterange,'active',$4)",
      [randomUUID(), newPostMoveTeam, movedAgency, seq],
    );

    // 4. Rejoin Agency: left Acme [2020-01-01, 2024-01-01) -> Northstar [2024-01-01, 2025-06-01) -> re-joined Acme [2025-06-01, ).
    await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'agency',$2)", [rejoinAgency, seq]);
    await c.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'rejoin_agency','Rejoin Agency','active',$3)",
      [randomUUID(), rejoinAgency, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2024-01-01)'::daterange,'active',$4)",
      [randomUUID(), rejoinAgency, ids.acmeOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2024-01-01,2025-06-01)'::daterange,'active',$4)",
      [randomUUID(), rejoinAgency, ids.northstarOrg, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2025-06-01,)'::daterange,'active',$4)",
      [randomUUID(), rejoinAgency, ids.acmeOrg, seq],
    );

    // 4a-d. Teams under Rejoin Agency across its three periods.
    for (const [oid, slug, name, status, rng] of [
      [rejoinPreLeaveTeam, 'rejoin_pre_leave_team', 'Rejoin Pre Leave Team', 'archived', '[2020-01-01,2023-06-01)'],
      [rejoinAwayTeam, 'rejoin_away_team', 'Rejoin Away Team', 'archived', '[2024-06-01,2025-01-01)'],
      [rejoinStayTeam, 'rejoin_stay_team', 'Rejoin Stay Team', 'active', '[2020-01-01,)'],
      [rejoinPostTeam, 'rejoin_post_team', 'Rejoin Post Team', 'active', '[2025-07-01,)'],
    ]) {
      await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'team',$2)", [oid, seq]);
      await c.query(
        "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,$3,$4,$5,$6)",
        [randomUUID(), oid, slug, name, status, seq],
      );
      await c.query(
        "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4::daterange,'active',$5)",
        [randomUUID(), oid, rejoinAgency, rng, seq],
      );
    }

    // Seed people across moved, active-moved, post-move, and rejoined scenarios.
    for (const [pid, name, email, npn] of [
      [movedAgencyMgr, 'Moved Agency Mgr', 'moved.ag.mgr@example.test', null],
      [movedActiveTeamMgr, 'Moved Active Team Mgr', 'moved.act.mgr@example.test', null],
      [newTeamMgr, 'New Team Mgr', 'new.team.mgr@example.test', null],
      [newTeamAgent, 'New Team Agent', 'new.team.agent@example.test', '88888888'],
      [northstarEM, 'Northstar EM', 'ns.em.item8@example.test', null],
      [nsOnlyMemberMovedGrant, 'NS Member Moved Grant', 'ns.mem.moved@example.test', null],
      [acmeMemberMovedGrant, 'Acme Member Moved Grant', 'acme.mem.moved@example.test', null],
      [rejoinAgencyMgr, 'Rejoin Agency Mgr', 'rejoin.ag.mgr@example.test', null],
      [nsOnlyMemberRejoinGrant, 'NS Member Rejoin Grant', 'ns.mem.rejoin@example.test', null],
      [acmeMemberRejoinGrant, 'Acme Member Rejoin Grant', 'acme.mem.rejoin@example.test', null],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [pid, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, npn, status, journal_seq) VALUES ($1,$2,$3,$3,$4,$5,'active',$6)",
        [randomUUID(), pid, name, email, npn, seq],
      );
    }
    for (const [pid, orgId, cap] of [
      [movedAgencyMgr, movedAgency, 'employee'],
      [movedActiveTeamMgr, movedActiveTeam, 'employee'],
      [newTeamMgr, newPostMoveTeam, 'employee'],
      [northstarEM, ids.northstarOrg, 'owner'],
      [nsOnlyMemberMovedGrant, ids.northstarOrg, 'employee'],
      [acmeMemberMovedGrant, ids.acmeOrg, 'employee'],
      [rejoinAgencyMgr, rejoinAgency, 'employee'],
      [nsOnlyMemberRejoinGrant, ids.northstarOrg, 'employee'],
      [acmeMemberRejoinGrant, ids.acmeOrg, 'employee'],
    ]) {
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,'[2020-01-01,)'::daterange,'active',$5)",
        [randomUUID(), pid, orgId, cap, seq],
      );
    }
    await c.query(
      "INSERT INTO iam.agent_affiliations (id, person_id, npn, agency_org_id, split_bps, agent_file_name, valid_range, status, journal_seq) VALUES ($1,$2,'88888888',$3,8000,'New Team Agent','[2025-07-01,)'::daterange,'active',$4)",
      [randomUUID(), newTeamAgent, newPostMoveTeam, seq],
    );
    for (const [pid, roleId, orgId, incDesc, pMode] of [
      [movedAgencyMgr, ids.roleAgencyManager, movedAgency, true, 'org_subtree'],
      [movedActiveTeamMgr, ids.roleAgencyManager, movedActiveTeam, true, 'org_subtree'],
      [newTeamMgr, ids.roleAgencyManager, newPostMoveTeam, true, 'org_subtree'],
      [newTeamAgent, ids.roleSellingAgent, newPostMoveTeam, false, 'self'],
      [northstarEM, ids.roleEntityManager, ids.northstarOrg, true, 'org_subtree'],
      [nsOnlyMemberMovedGrant, ids.roleAgencyManager, movedAgency, true, 'org_subtree'],
      [acmeMemberMovedGrant, ids.roleAgencyManager, movedAgency, true, 'org_subtree'],
      [rejoinAgencyMgr, ids.roleAgencyManager, rejoinAgency, true, 'org_subtree'],
      [nsOnlyMemberRejoinGrant, ids.roleAgencyManager, rejoinAgency, true, 'org_subtree'],
      [acmeMemberRejoinGrant, ids.roleAgencyManager, rejoinAgency, true, 'org_subtree'],
    ]) {
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,$5,$6,'[2020-01-01,)'::daterange,'active',$7)",
        [randomUUID(), pid, roleId, orgId, incDesc, pMode, seq],
      );
    }
  });

  // Seed historical sent statement batch in Acme DB for Moved Agency, Old Pre-Move Team, Moved Active Team, and Rejoin orgs.
  await env.commands.recordStatementBatch({
    dbToken: env.ownerToken,
    commandKey: 'c1-item8-hist-batch',
    batchKind: 'historical_sent',
    statementDate: '2024-12-31',
    reason: 'Historical rows for Moved Agency, Old Pre-Move Team, Moved Active Team, and Rejoin orgs',
    agencyLines: [
      {
        entity: 'Moved Agency', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~MOVEDAG~100.00~2024-12', sourceFile: 'hist.csv', sourceRowNo: 1,
        grossComm: '100.00', amount: '80.00',
      },
      {
        entity: 'Old Pre Move Team', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~OLDPRE~50.00~2024-12', sourceFile: 'hist.csv', sourceRowNo: 2,
        grossComm: '50.00', amount: '40.00',
      },
      {
        entity: 'Moved Active Team', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~MOVEDACT~60.00~2024-12', sourceFile: 'hist.csv', sourceRowNo: 3,
        grossComm: '60.00', amount: '48.00',
      },
      {
        entity: 'Rejoin Agency', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~REJOIN~70.00~2024-12', sourceFile: 'hist.csv', sourceRowNo: 4,
        grossComm: '70.00', amount: '56.00',
      },
      {
        entity: 'Rejoin Pre Leave Team', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~REJOINPRE~30.00~2024-12', sourceFile: 'hist.csv', sourceRowNo: 5,
        grossComm: '30.00', amount: '24.00',
      },
      {
        entity: 'Rejoin Stay Team', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~REJOINSTAY~40.00~2024-12', sourceFile: 'hist.csv', sourceRowNo: 6,
        grossComm: '40.00', amount: '32.00',
      },
      {
        entity: 'Rejoin Post Team', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~REJOINPOST~20.00~2024-12', sourceFile: 'hist.csv', sourceRowNo: 7,
        grossComm: '20.00', amount: '16.00',
      },
    ],
    uplineLines: [
      {
        sourceEntity: 'Moved Agency', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~MOVEDAG~100.00~2024-12', sourceFile: 'hist.csv', sourceRowNo: 1,
        grossComm: '100.00', amount: '20.00',
      },
      {
        sourceEntity: 'Old Pre Move Team', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~OLDPRE~50.00~2024-12', sourceFile: 'hist.csv', sourceRowNo: 2,
        grossComm: '50.00', amount: '10.00',
      },
      {
        sourceEntity: 'Moved Active Team', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~MOVEDACT~60.00~2024-12', sourceFile: 'hist.csv', sourceRowNo: 3,
        grossComm: '60.00', amount: '12.00',
      },
      {
        sourceEntity: 'Rejoin Agency', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~REJOIN~70.00~2024-12', sourceFile: 'hist.csv', sourceRowNo: 4,
        grossComm: '70.00', amount: '14.00',
      },
    ],
  });
  await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'c1-item8-r1', markSent: true });

  await t.test('C1-8a: post-move New Post-Move Team is absent from old company (Acme) closure & tenant tree and its people see nothing in Acme DB', async () => {
    const acmeClosure = (await env.pool.query(
      'SELECT DISTINCT descendant_org_id FROM iam.v_organization_closure WHERE ancestor_org_id = $1::uuid',
      [ids.acmeOrg],
    )).rows.map((r) => r.descendant_org_id);
    assert.ok(acmeClosure.includes(movedAgency), 'Moved Agency history must remain in Acme closure');
    assert.ok(acmeClosure.includes(oldPreMoveTeam), 'Old Pre-Move Team history must remain in Acme closure');
    assert.ok(acmeClosure.includes(movedActiveTeam), 'Moved Active Team that moved with Moved Agency must remain in Acme closure');
    assert.ok(!acmeClosure.includes(newPostMoveTeam), 'New Post-Move Team added after move MUST be absent from Acme closure');
    assert.ok(acmeClosure.includes(rejoinAgency) && acmeClosure.includes(rejoinPreLeaveTeam) && acmeClosure.includes(rejoinStayTeam) && acmeClosure.includes(rejoinPostTeam));
    assert.ok(!acmeClosure.includes(rejoinAwayTeam), 'Rejoin Away Team from Northstar period MUST be absent from Acme closure');

    const tenantTree = (await env.pool.query(
      'SELECT coherence._resolve_tenant_tree_org_ids() AS orgs',
    )).rows[0].orgs;
    assert.ok(tenantTree.includes(movedAgency), 'Moved Agency must remain in Acme tenant tree');
    assert.ok(tenantTree.includes(oldPreMoveTeam), 'Old Pre-Move Team must remain in Acme tenant tree');
    assert.ok(tenantTree.includes(movedActiveTeam), 'Moved Active Team must remain in Acme tenant tree');
    assert.ok(!tenantTree.includes(newPostMoveTeam), 'New Post-Move Team MUST be absent from Acme tenant tree');
    assert.ok(!tenantTree.includes(rejoinAwayTeam), 'Rejoin Away Team MUST be absent from Acme tenant tree');

    // Live write for New Post-Move Team in Acme DB must be refused as UNMAPPED_ENTITY.
    await assert.rejects(
      () => env.commands.recordStatementBatch({
        dbToken: env.ownerToken,
        commandKey: 'c1-item8-reject-new-team',
        batchKind: 'historical_sent',
        statementDate: '2026-07-15',
        reason: 'new post-move team must not resolve in old company DB',
        agencyLines: [{
          entity: 'New Post Move Team', writingNpn: null, writingAgent: null,
          recordId: 'carrier_a~direct~NEWPOST~10.00~2026-07', sourceFile: 'new.csv', sourceRowNo: 1,
          grossComm: '10.00', amount: '10.00',
        }],
        uplineLines: [],
      }),
      /UNMAPPED_ENTITY/i,
      'New Post-Move Team must be refused in old company DB',
    );

    // New Post-Move Team people and new-upline-only members with grants on Moved Agency or Rejoin Agency see ZERO everywhere in Acme DB.
    for (const [label, token] of [
      ['newTeamMgr', tok(newTeamMgr)],
      ['View-as newTeamMgr', tok(ids.nusearOwner, newTeamMgr)],
      ['newTeamAgent', tok(newTeamAgent)],
      ['View-as newTeamAgent', tok(ids.nusearOwner, newTeamAgent)],
      ['northstarEM', tok(northstarEM)],
      ['nsOnlyMemberMovedGrant', tok(nsOnlyMemberMovedGrant)],
      ['View-as nsOnlyMemberMovedGrant', tok(ids.nusearOwner, nsOnlyMemberMovedGrant)],
      ['nsOnlyMemberRejoinGrant', tok(nsOnlyMemberRejoinGrant)],
      ['View-as nsOnlyMemberRejoinGrant', tok(ids.nusearOwner, nsOnlyMemberRejoinGrant)],
    ]) {
      await runAsPlatformApp(env.pool, { token, readOnly: true }, async (c) => {
        const wide = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
        const anyOrgs = (await c.query("SELECT iam.effective_any_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
        assert.deepEqual(wide, [], `${label} must have 0 effective wide orgs in Acme DB`);
        assert.deepEqual(anyOrgs, [], `${label} must have 0 effective any orgs in Acme DB`);
        for (const viewName of [
          'coherence_bob',
          'v_current_policy_periods',
          'coherence_statement_agency_lines',
          'coherence_statement_upline_lines',
          'coherence_entity_statement_lines',
          'coherence_ledger',
          'coherence_published_runs',
        ]) {
          const n = (await c.query(`SELECT COUNT(*)::int AS n FROM app_views.${viewName}`)).rows[0].n;
          assert.equal(n, 0, `${label} must see 0 rows in app_views.${viewName}`);
        }
      });
    }

    // Acme Entity Manager and Nusear Owner retain Moved Agency, Old Pre-Move Team, Moved Active Team, and Rejoin orgs.
    const expectedAllHist = [
      'Moved Active Team', 'Moved Agency', 'Old Pre Move Team',
      'Rejoin Agency', 'Rejoin Post Team', 'Rejoin Pre Leave Team', 'Rejoin Stay Team',
    ];
    for (const [label, pid] of [['acmeEntityMgr', ids.acmeEntityMgr], ['nusearOwner', ids.nusearOwner]]) {
      await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
        const entities = (await c.query(
          "SELECT DISTINCT entity FROM app_views.coherence_statement_agency_lines WHERE statement_date = DATE '2024-12-31' ORDER BY entity",
        )).rows.map((r) => r.entity);
        assert.deepEqual(entities, expectedAllHist, `${label} must keep historical rows for Moved Agency, Old Pre-Move Team, Moved Active Team, and Rejoin orgs`);
      });
    }

    // Moved Agency own manager AND old-company (Acme) member with a grant on Moved Agency both see Moved Agency, Old Pre-Move Team, and Moved Active Team.
    for (const [label, pid] of [
      ['movedAgencyMgr', movedAgencyMgr],
      ['acmeMemberMovedGrant', acmeMemberMovedGrant],
    ]) {
      await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
        const entities = (await c.query(
          "SELECT DISTINCT entity FROM app_views.coherence_statement_agency_lines WHERE statement_date = DATE '2024-12-31' ORDER BY entity",
        )).rows.map((r) => r.entity);
        assert.deepEqual(entities, ['Moved Active Team', 'Moved Agency', 'Old Pre Move Team'], `${label} must see Moved Agency, Moved Active Team, and archived Old Pre-Move Team in Acme DB`);
      });
    }

    // Active team that moved with Moved Agency: its own manager sees Moved Active Team in Acme DB.
    await runAsPlatformApp(env.pool, { token: tok(movedActiveTeamMgr), readOnly: true }, async (c) => {
      const entities = (await c.query(
        "SELECT DISTINCT entity FROM app_views.coherence_statement_agency_lines WHERE statement_date = DATE '2024-12-31' ORDER BY entity",
      )).rows.map((r) => r.entity);
      assert.deepEqual(entities, ['Moved Active Team'], 'Moved Active Team own manager must see Moved Active Team in Acme DB');
    });

    // Rejoin Agency own manager and Acme member with grant on Rejoin Agency see Rejoin Agency, Pre Leave, Stay, and Post teams (never Away).
    for (const [label, pid] of [
      ['rejoinAgencyMgr', rejoinAgencyMgr],
      ['acmeMemberRejoinGrant', acmeMemberRejoinGrant],
    ]) {
      await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
        const entities = (await c.query(
          "SELECT DISTINCT entity FROM app_views.coherence_statement_agency_lines WHERE statement_date = DATE '2024-12-31' ORDER BY entity",
        )).rows.map((r) => r.entity);
        assert.deepEqual(
          entities,
          ['Rejoin Agency', 'Rejoin Post Team', 'Rejoin Pre Leave Team', 'Rejoin Stay Team'],
          `${label} must see all Acme-period teams under Rejoin Agency`,
        );
      });
    }
  });

  await t.test('C1-8b: pre-move Old Pre-Move Team is absent from new upline (Northstar) closure, and v_organization_closure_live stays today tree', async () => {
    const northstarClosure = (await env.pool.query(
      'SELECT DISTINCT descendant_org_id FROM iam.v_organization_closure WHERE ancestor_org_id = $1::uuid',
      [ids.northstarOrg],
    )).rows.map((r) => r.descendant_org_id);
    assert.ok(northstarClosure.includes(movedAgency), 'Moved Agency must be in Northstar closure');
    assert.ok(northstarClosure.includes(movedActiveTeam), 'Moved Active Team must be in Northstar closure');
    assert.ok(northstarClosure.includes(newPostMoveTeam), 'New Post-Move Team must be in Northstar closure');
    assert.ok(!northstarClosure.includes(oldPreMoveTeam), 'Old Pre-Move Team from before the move MUST be absent from Northstar closure');
    assert.ok(northstarClosure.includes(rejoinAgency) && northstarClosure.includes(rejoinAwayTeam) && northstarClosure.includes(rejoinStayTeam));
    assert.ok(!northstarClosure.includes(rejoinPreLeaveTeam) && !northstarClosure.includes(rejoinPostTeam));

    // v_organization_closure_live stays today's live tree only!
    const acmeLive = (await env.pool.query(
      'SELECT DISTINCT descendant_org_id FROM iam.v_organization_closure_live WHERE ancestor_org_id = $1::uuid',
      [ids.acmeOrg],
    )).rows.map((r) => r.descendant_org_id);
    assert.ok(acmeLive.includes(ids.acmeOrg) && acmeLive.includes(ids.beaconOrg) && acmeLive.includes(ids.harborOrg));
    assert.ok(acmeLive.includes(rejoinAgency) && acmeLive.includes(rejoinStayTeam) && acmeLive.includes(rejoinPostTeam));
    assert.ok(!acmeLive.includes(movedAgency), 'Moved Agency (moved away) must not be in Acme today live tree');
    assert.ok(!acmeLive.includes(movedActiveTeam), 'Moved Active Team (moved away) must not be in Acme today live tree');
    assert.ok(!acmeLive.includes(oldPreMoveTeam), 'archived Old Pre-Move Team must not be in Acme today live tree');
    assert.ok(!acmeLive.includes(newPostMoveTeam), 'New Post-Move Team must not be in Acme today live tree');

    const northstarLive = (await env.pool.query(
      'SELECT DISTINCT descendant_org_id FROM iam.v_organization_closure_live WHERE ancestor_org_id = $1::uuid',
      [ids.northstarOrg],
    )).rows.map((r) => r.descendant_org_id);
    assert.ok(northstarLive.includes(ids.northstarOrg), 'Northstar must be in Northstar today live tree');
    assert.ok(northstarLive.includes(movedAgency), 'Moved Agency must be in Northstar today live tree');
    assert.ok(northstarLive.includes(movedActiveTeam), 'Moved Active Team must be in Northstar today live tree');
    assert.ok(northstarLive.includes(newPostMoveTeam), 'New Post-Move Team must be in Northstar today live tree');
    assert.ok(!northstarLive.includes(oldPreMoveTeam), 'Old Pre-Move Team must not be in Northstar today live tree');
    assert.ok(!northstarLive.includes(rejoinAgency), 'Rejoin Agency (back in Acme today) must not be in Northstar today live tree');
  });

  await t.test('C1-8c: tool switch set by new upline (Northstar) never affects Acme DB; switching Moved Agency itself off nulls company totals in coherence_statement_batches for non-internal callers', async () => {
    // 1. Northstar switches coherence OFF (and HELD): must have ZERO effect on Acme DB!
    for (const [state, holdReason, keySuffix] of [
      ['off', null, 'ns-off'],
      ['held', 'new upline hold', 'ns-held'],
    ]) {
      await inSerializableTx(env.pool, async (c) => {
        const j = await appendAuditEntry(c, { environment, commandKind: 'iam.c1_ns_switch', commandKey: `c1-${keySuffix}` });
        const prev = (await c.query(
          "SELECT id FROM iam.organization_tool_switches WHERE organization_id = $1 AND tool_id = 'coherence' AND superseded_by_id IS NULL",
          [ids.northstarOrg],
        )).rows[0]?.id ?? null;
        await c.query(
          "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, hold_reason, status, replaces_id, journal_seq) VALUES ($1,$2,'coherence',$3,$4,'active',$5,$6)",
          [randomUUID(), ids.northstarOrg, state, holdReason, prev, j.seq],
        );
      });

      for (const [label, pid, expected] of [
        ['movedAgencyMgr', movedAgencyMgr, ['Moved Active Team', 'Moved Agency', 'Old Pre Move Team']],
        ['acmeMemberMovedGrant', acmeMemberMovedGrant, ['Moved Active Team', 'Moved Agency', 'Old Pre Move Team']],
        ['movedActiveTeamMgr', movedActiveTeamMgr, ['Moved Active Team']],
        ['rejoinAgencyMgr', rejoinAgencyMgr, ['Rejoin Agency', 'Rejoin Post Team', 'Rejoin Pre Leave Team', 'Rejoin Stay Team']],
      ]) {
        await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
          const entities = (await c.query(
            "SELECT DISTINCT entity FROM app_views.coherence_statement_agency_lines WHERE statement_date = DATE '2024-12-31' ORDER BY entity",
          )).rows.map((r) => r.entity);
          assert.deepEqual(entities, expected, `Northstar switch=${state} must NEVER affect ${label} in Acme DB`);
        });
      }

      // Acme EM still keeps full company totals in coherence_statement_batches!
      await runAsPlatformApp(env.pool, { token: tok(ids.acmeEntityMgr), readOnly: true }, async (c) => {
        const batch = (await c.query(
          "SELECT agency_line_count, agency_net_total, upline_net_total FROM app_views.coherence_statement_batches WHERE statement_date = DATE '2024-12-31'",
        )).rows[0];
        assert.notEqual(batch?.agency_net_total, null, `Northstar switch=${state} must not null Acme EM batch totals`);
        assert.notEqual(batch?.upline_net_total, null, `Northstar switch=${state} must not null Acme EM upline totals`);
      });
    }

    // 2. Switch Moved Agency ITSELF off (Item 3): Moved Agency is outside Acme's live tree today, yet its lines
    //    appear in Acme's batches, so company totals in coherence_statement_batches MUST become NULL for Acme EM
    //    while staying populated for Nusear Owner (who bypasses tool switches).
    await inSerializableTx(env.pool, async (c) => {
      const j = await appendAuditEntry(c, { environment, commandKind: 'iam.c1_moved_off', commandKey: 'c1-moved-off' });
      await c.query(
        "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','off','active',$3)",
        [randomUUID(), movedAgency, j.seq],
      );
    });

    await runAsPlatformApp(env.pool, { token: tok(ids.acmeEntityMgr), readOnly: true }, async (c) => {
      const movedLines = (await c.query(
        "SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines WHERE entity IN ('Moved Agency', 'Old Pre Move Team', 'Moved Active Team')",
      )).rows[0].n;
      assert.equal(movedLines, 0, 'Acme EM must see 0 lines for switched-off Moved Agency and its teams');
      const batches = (await c.query(
        `SELECT statement_date, agency_line_count, agency_lines_sha256, agency_net_total,
                upline_line_count, upline_lines_sha256, upline_net_total
         FROM app_views.coherence_statement_batches`,
      )).rows;
      assert.ok(batches.length >= 2);
      for (const b of batches) {
        for (const col of ['agency_line_count', 'agency_lines_sha256', 'agency_net_total', 'upline_line_count', 'upline_lines_sha256', 'upline_net_total']) {
          assert.equal(b[col], null, `Acme EM must get NULL ${col} in coherence_statement_batches when moved agency is switched off`);
        }
      }
    });

    await runAsPlatformApp(env.pool, { token: tok(ids.nusearOwner), readOnly: true }, async (c) => {
      const histBatch = (await c.query(
        "SELECT agency_line_count, agency_net_total, upline_net_total FROM app_views.coherence_statement_batches WHERE statement_date = DATE '2024-12-31'",
      )).rows[0];
      assert.equal(Number(histBatch.agency_line_count), 7);
      assert.notEqual(histBatch.agency_net_total, null, 'Nusear Owner bypasses tool switches and keeps batch totals');
      assert.notEqual(histBatch.upline_net_total, null);
    });
  });
});

test('Layer 7B [Release C2 - Holding Company Above Tenant]: non-internal org above tenant is followed only through today live chains (live parent and grandparent reach tenant; expired former parent and expired grandparent do not; tool switches follow same rule)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const tok = (personId, viewAsPersonId = null) => mintSignedToken({
    keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId,
  });

  const holdingCo = randomUUID();
  const formerParentCo = randomUUID();
  const grandHoldingCo = randomUUID();
  const expiredGrandHoldingCo = randomUUID();
  const sisterCo = randomUUID();
  const archivedAgency = randomUUID();
  const movedOutAgency = randomUUID();

  const holdingExec = randomUUID();
  const holdingNoDesc = randomUUID();
  const holdingMemTenantGrant = randomUUID();
  const grandHoldingExec = randomUUID();
  const expiredGrandExec = randomUUID();
  const formerParentExec = randomUUID();
  const formerParentMemTenantGrant = randomUUID();
  const sisterExec = randomUUID();
  const roleHoldingWriter = randomUUID();

  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.c2_holding_setup', commandKey: 'c2-holding-setup' });
    const seq = j.seq;

    for (const [oid, kind, slug, name, status] of [
      [grandHoldingCo, 'company', 'grand_holding', 'Grand Holding Co', 'active'],
      [expiredGrandHoldingCo, 'company', 'expired_grand_holding', 'Expired Grand Holding Co', 'active'],
      [holdingCo, 'company', 'holding_co', 'Holding Co', 'active'],
      [formerParentCo, 'company', 'former_parent', 'Former Parent Co', 'active'],
      [sisterCo, 'company', 'sister_co', 'Sister Co', 'active'],
      [archivedAgency, 'agency', 'archived_old_ag', 'Archived Old Agency', 'archived'],
      [movedOutAgency, 'agency', 'moved_out_ag', 'Moved Out Agency', 'active'],
    ]) {
      await c.query('INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,$2,$3)', [oid, kind, seq]);
      await c.query(
        'INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,$3,$4,$5,$6)',
        [randomUUID(), oid, slug, name, status, seq],
      );
    }

    // Reparent acmeOrg: under formerParentCo [2020-01-01, 2025-01-01), then under holdingCo [2025-01-01, ).
    const acmeEdgeId = (await c.query(
      'SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND superseded_by_id IS NULL',
      [ids.acmeOrg],
    )).rows[0].id;
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2025-01-01)'::daterange,'active',$4,$5)",
      [randomUUID(), ids.acmeOrg, formerParentCo, acmeEdgeId, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2025-01-01,)'::daterange,'active',$4)",
      [randomUUID(), ids.acmeOrg, holdingCo, seq],
    );

    // Parent chains above holdingCo and formerParentCo, plus sisterCo and historical agencies under acmeOrg.
    for (const [child, parent, rng] of [
      [grandHoldingCo, ids.rootOrg, '[2020-01-01,)'],
      [expiredGrandHoldingCo, ids.rootOrg, '[2020-01-01,)'],
      [formerParentCo, ids.rootOrg, '[2020-01-01,)'],
      [holdingCo, expiredGrandHoldingCo, '[2020-01-01,2024-01-01)'],
      [holdingCo, grandHoldingCo, '[2024-01-01,)'],
      [sisterCo, holdingCo, '[2025-01-01,)'],
      [archivedAgency, ids.acmeOrg, '[2020-01-01,2024-06-01)'],
      [movedOutAgency, ids.acmeOrg, '[2020-01-01,2024-06-01)'],
      [movedOutAgency, ids.northstarOrg, '[2024-06-01,)'],
    ]) {
      await c.query(
        "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4::daterange,'active',$5)",
        [randomUUID(), child, parent, rng, seq],
      );
    }

    // Non-internal write+read role for testing assert_can_write from holding company vs former parent.
    await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,NULL,$3)', [roleHoldingWriter, 'holding_writer', seq]);
    await c.query(
      "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,'Holding Writer',false,false,true,'active',$3)",
      [randomUUID(), roleHoldingWriter, seq],
    );
    await c.query(
      "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,'act:coherence.inputs.publish','active',$3)",
      [randomUUID(), roleHoldingWriter, seq],
    );

    for (const [pid, name, email, memOrg] of [
      [holdingExec, 'Holding Exec', 'holding.exec@example.test', holdingCo],
      [holdingNoDesc, 'Holding NoDesc', 'holding.nodesc@example.test', holdingCo],
      [holdingMemTenantGrant, 'Holding Mem Tenant Grant', 'holding.mem.tenant@example.test', holdingCo],
      [grandHoldingExec, 'Grand Holding Exec', 'grand.exec@example.test', grandHoldingCo],
      [expiredGrandExec, 'Expired Grand Exec', 'expired.grand@example.test', expiredGrandHoldingCo],
      [formerParentExec, 'Former Parent Exec', 'former.parent@example.test', formerParentCo],
      [formerParentMemTenantGrant, 'Former Parent Mem Tenant', 'former.mem.tenant@example.test', formerParentCo],
      [sisterExec, 'Sister Exec', 'sister.exec@example.test', sisterCo],
    ]) {
      await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [pid, seq]);
      await c.query(
        "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,$3,$3,$4,'active',$5)",
        [randomUUID(), pid, name, email, seq],
      );
      await c.query(
        "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'owner','[2020-01-01,)'::daterange,'active',$4)",
        [randomUUID(), pid, memOrg, seq],
      );
    }

    for (const [pid, roleId, orgId, incDesc] of [
      [holdingExec, ids.roleEntityManager, holdingCo, true],
      [holdingExec, roleHoldingWriter, holdingCo, true],
      [holdingNoDesc, ids.roleEntityManager, holdingCo, false],
      [holdingMemTenantGrant, ids.roleEntityManager, ids.acmeOrg, true],
      [grandHoldingExec, ids.roleEntityManager, grandHoldingCo, true],
      [expiredGrandExec, ids.roleEntityManager, expiredGrandHoldingCo, true],
      [expiredGrandExec, ids.roleEntityManager, holdingCo, true],
      [formerParentExec, ids.roleEntityManager, formerParentCo, true],
      [formerParentExec, roleHoldingWriter, formerParentCo, true],
      [formerParentMemTenantGrant, ids.roleEntityManager, ids.acmeOrg, true],
      [formerParentMemTenantGrant, roleHoldingWriter, ids.acmeOrg, true],
      [sisterExec, ids.roleEntityManager, sisterCo, true],
    ]) {
      await c.query(
        "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,$5,'org_subtree','[2020-01-01,)'::daterange,'active',$6)",
        [randomUUID(), pid, roleId, orgId, incDesc, seq],
      );
    }
  });

  await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'c2-hold-r1', markSent: true });
  await env.commands.recordStatementBatch({
    dbToken: env.ownerToken,
    commandKey: 'c2-hold-hist-batch',
    batchKind: 'historical_sent',
    statementDate: '2024-05-31',
    reason: 'Historical rows for archived and moved-out agencies under Acme',
    agencyLines: [
      {
        entity: 'Archived Old Agency', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~ARCHOLD~50.00~2024-05', sourceFile: 'hist.csv', sourceRowNo: 1,
        grossComm: '50.00', amount: '40.00',
      },
      {
        entity: 'Moved Out Agency', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~MOVEDOUT~60.00~2024-05', sourceFile: 'hist.csv', sourceRowNo: 2,
        grossComm: '60.00', amount: '48.00',
      },
    ],
    uplineLines: [],
  });
  await env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys()');

  const expectedLiveTenantOrgs = [ids.acmeOrg, ids.beaconOrg, ids.harborOrg, ids.eastTeamOrg].sort();

  // 1. Live holding company and live grandparent reach the tenant's live tree (strictly tenant-bounded: no holdingCo/sisterCo/archived/movedOut).
  for (const [label, pid] of [
    ['holdingExec', holdingExec],
    ['grandHoldingExec', grandHoldingExec],
    ['View-as holdingExec', null],
  ]) {
    const token = pid ? tok(pid) : tok(ids.nusearOwner, holdingExec);
    await runAsPlatformApp(env.pool, { token, readOnly: true }, async (c) => {
      const wide = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v.sort();
      assert.deepEqual(wide, expectedLiveTenantOrgs, `${label} must reach Acme live tree only (no holdingCo, sisterCo, archived, or movedOut)`);
      const bobEntities = (await c.query('SELECT DISTINCT entity FROM app_views.coherence_bob ORDER BY entity')).rows.map((r) => r.entity);
      assert.deepEqual(bobEntities, ['Beacon', 'East Team', 'Harbor'], `${label} must read Acme BoB rows`);
      const histCount = (await c.query(
        "SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines WHERE entity IN ('Archived Old Agency', 'Moved Out Agency')",
      )).rows[0].n;
      assert.equal(histCount, 0, `${label} (above tenant, live chains only) must not read pre-acquisition archived/moved-out agency rows`);
    });
  }

  // Holding company member with direct grant on tenant reaches tenant's live AND historical tree (grant anchored at tenant).
  await runAsPlatformApp(env.pool, { token: tok(holdingMemTenantGrant), readOnly: true }, async (c) => {
    const wide = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
    assert.ok(wide.includes(ids.acmeOrg) && wide.includes(ids.beaconOrg) && wide.includes(archivedAgency) && wide.includes(movedOutAgency));
    assert.ok(!wide.includes(holdingCo) && !wide.includes(sisterCo));
  });

  // Holding company executive can authorize writes at tenantOrg via assert_can_write.
  const holdWrite = await runAsPlatformApp(env.pool, { token: tok(holdingExec), readOnly: true }, (c) => (
    c.query("SELECT actor_person_id, recorded_as FROM iam.assert_can_write('act:coherence.inputs.publish', $1::uuid)", [ids.acmeOrg])
  ));
  assert.equal(holdWrite.rows[0].actor_person_id, holdingExec);
  assert.equal(holdWrite.rows[0].recorded_as, 'self');

  // 2. Expired former parent, expired grandparent, non-descending holding grant, and sister company get 0 orgs and 0 rows everywhere.
  for (const [label, token] of [
    ['holdingNoDesc', tok(holdingNoDesc)],
    ['expiredGrandExec', tok(expiredGrandExec)],
    ['formerParentExec', tok(formerParentExec)],
    ['View-as formerParentExec', tok(ids.nusearOwner, formerParentExec)],
    ['formerParentMemTenantGrant', tok(formerParentMemTenantGrant)],
    ['sisterExec', tok(sisterExec)],
  ]) {
    await runAsPlatformApp(env.pool, { token, readOnly: true }, async (c) => {
      assert.deepEqual((await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `${label} must get 0 wide orgs`);
      assert.deepEqual((await c.query("SELECT iam.effective_any_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `${label} must get 0 any orgs`);
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n, 0, `${label} must see 0 BoB rows`);
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n, 0, `${label} must see 0 statement lines`);
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger')).rows[0].n, 0, `${label} must see 0 ledger rows`);
    });
  }

  for (const [label, pid] of [['formerParentExec', formerParentExec], ['formerParentMemTenantGrant', formerParentMemTenantGrant]]) {
    await assert.rejects(
      () => runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, (c) => (
        c.query("SELECT * FROM iam.assert_can_write('act:coherence.inputs.publish', $1::uuid)", [ids.acmeOrg])
      )),
      (err) => err?.code === '42501',
      `${label} must be refused 42501 on iam.assert_can_write`,
    );
  }

  // 3. Tool switches above the tenant: expired former parent switch=off/held has ZERO effect; live holdingCo switch=held vetoes non-internal callers while Nusear internal bypasses.
  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.c2_former_parent_off', commandKey: 'c2-former-parent-off' });
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','off','active',$3)",
      [randomUUID(), formerParentCo, j.seq],
    );
  });
  for (const [label, pid] of [['acmeEntityMgr', ids.acmeEntityMgr], ['holdingExec', holdingExec]]) {
    await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
      assert.ok((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n > 0, `former parent switch=off must not block ${label}`);
    });
  }

  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.c2_holding_held', commandKey: 'c2-holding-held' });
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, hold_reason, status, journal_seq) VALUES ($1,$2,'coherence','held','holding company hold','active',$3)",
      [randomUUID(), holdingCo, j.seq],
    );
  });
  for (const [label, pid] of [['acmeEntityMgr', ids.acmeEntityMgr], ['holdingExec', holdingExec], ['holdingMemTenantGrant', holdingMemTenantGrant]]) {
    await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
      assert.deepEqual((await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [], `live holdingCo switch=held must veto ${label} (including archived/moved orgs)`);
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n, 0, `live holdingCo switch=held must hide all statement lines from ${label}`);
    });
  }
  await runAsPlatformApp(env.pool, { token: tok(ids.nusearOwner), readOnly: true }, async (c) => {
    const wide = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
    assert.ok(wide.includes(ids.acmeOrg) && wide.includes(archivedAgency) && wide.includes(movedOutAgency), 'Nusear Owner must bypass holdingCo switch=held and retain live + historical orgs');
  });
});

test('Layer 7B [Release C2 Fix1 - Unified Tool-Switch Chain]: holdingCo preview with root on blocks live/archived/moved-out orgs, expired direct root edge cannot bypass holdingCo or grandHoldingCo preview, and on-only at holdingCo reaches live/archived/moved-out orgs for Entity Manager', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createCoherenceIamTestEnv();
  t.after(() => env.cleanup());

  const { ids, keyId, secretBytes, environment } = await seedCoherenceIamWorld(env.pool);
  const tok = (personId, viewAsPersonId = null) => mintSignedToken({
    keyId, secretBytes, environment, actorPersonId: personId, viewAsPersonId,
  });

  const grandHoldingCo = randomUUID();
  const holdingCo = randomUUID();
  const archivedAgency = randomUUID();
  const movedOutAgency = randomUUID();
  const holdingExec = randomUUID();

  let acmeSwitchId;
  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.c2_fix1_switch_setup', commandKey: 'c2-fix1-switch-setup' });
    const seq = j.seq;

    for (const [oid, kind, slug, name, status] of [
      [grandHoldingCo, 'company', 'grand_holding_sw', 'Grand Holding SW', 'active'],
      [holdingCo, 'company', 'holding_sw', 'Holding SW', 'active'],
      [archivedAgency, 'agency', 'archived_sw_ag', 'Archived SW Agency', 'archived'],
      [movedOutAgency, 'agency', 'moved_out_sw_ag', 'Moved Out SW Agency', 'active'],
    ]) {
      await c.query('INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,$2,$3)', [oid, kind, seq]);
      await c.query(
        'INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,$3,$4,$5,$6)',
        [randomUUID(), oid, slug, name, status, seq],
      );
    }

    // Tenant acmeOrg moved from DIRECTLY under rootOrg [2020-01-01, 2025-01-01) to under holdingCo [2025-01-01, ),
    // with holdingCo -> grandHoldingCo -> rootOrg live today.
    const acmeEdgeId = (await c.query(
      'SELECT id FROM iam.organization_edges WHERE child_org_id = $1 AND superseded_by_id IS NULL',
      [ids.acmeOrg],
    )).rows[0].id;
    await c.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2025-01-01)'::daterange,'active',$4,$5)",
      [randomUUID(), ids.acmeOrg, ids.rootOrg, acmeEdgeId, seq],
    );
    for (const [child, parent, rng] of [
      [grandHoldingCo, ids.rootOrg, '[2020-01-01,)'],
      [holdingCo, grandHoldingCo, '[2020-01-01,)'],
      [ids.acmeOrg, holdingCo, '[2025-01-01,)'],
      [archivedAgency, ids.acmeOrg, '[2020-01-01,2024-06-01)'],
      [movedOutAgency, ids.acmeOrg, '[2020-01-01,2024-06-01)'],
      [movedOutAgency, ids.northstarOrg, '[2024-06-01,)'],
    ]) {
      await c.query(
        "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4::daterange,'active',$5)",
        [randomUUID(), child, parent, rng, seq],
      );
    }

    await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [holdingExec, seq]);
    await c.query(
      "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'Holding SW Exec','Holding SW Exec','holding.sw.exec@example.test','active',$3)",
      [randomUUID(), holdingExec, seq],
    );
    await c.query(
      "INSERT INTO iam.organization_memberships (id, person_id, organization_id, capacity, valid_range, status, journal_seq) VALUES ($1,$2,$3,'owner','[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), holdingExec, holdingCo, seq],
    );
    await c.query(
      "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
      [randomUUID(), holdingExec, ids.roleEntityManager, holdingCo, seq],
    );

    acmeSwitchId = (await c.query(
      "SELECT id FROM iam.organization_tool_switches WHERE organization_id = $1 AND tool_id = 'coherence' AND superseded_by_id IS NULL",
      [ids.acmeOrg],
    )).rows[0].id;
  });

  await seedPublishedRun(env, { statementDate: '2026-10-31', keyPrefix: 'c2-fix1-sw-r1', markSent: true });
  await env.commands.recordStatementBatch({
    dbToken: env.ownerToken,
    commandKey: 'c2-fix1-sw-hist-batch',
    batchKind: 'historical_sent',
    statementDate: '2024-05-31',
    reason: 'Historical rows for archived and moved-out agencies under Acme',
    agencyLines: [
      {
        entity: 'Archived SW Agency', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~ARCHSW~50.00~2024-05', sourceFile: 'hist_sw.csv', sourceRowNo: 1,
        grossComm: '50.00', amount: '40.00',
      },
      {
        entity: 'Moved Out SW Agency', writingNpn: null, writingAgent: null,
        recordId: 'carrier_a~direct~MOVEDSW~60.00~2024-05', sourceFile: 'hist_sw.csv', sourceRowNo: 2,
        grossComm: '60.00', amount: '48.00',
      },
    ],
    uplineLines: [],
  });
  await env.pool.query('SELECT * FROM coherence.backfill_iam_foreign_keys()');

  const expectedLiveOrgs = [ids.acmeOrg, ids.beaconOrg, ids.harborOrg, ids.eastTeamOrg].sort();
  const expectedAllTenantOrgs = [...expectedLiveOrgs, archivedAgency, movedOutAgency].sort();

  // 1. 'on' ONLY on holdingCo (revoke acmeOrg's own switch; no switch on rootOrg) reaches live, archived, and moved-out orgs for acmeEntityMgr.
  const holdingOnId = randomUUID();
  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.c2_fix1_holding_only_on', commandKey: 'c2-fix1-holding-only-on' });
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq) VALUES ($1,$2,'coherence','on','revoked',$3,$4)",
      [randomUUID(), ids.acmeOrg, acmeSwitchId, j.seq],
    );
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','on','active',$3)",
      [holdingOnId, holdingCo, j.seq],
    );
  });

  await runAsPlatformApp(env.pool, { token: tok(ids.acmeEntityMgr), readOnly: true }, async (c) => {
    const wide = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v.sort();
    assert.deepEqual(wide, expectedAllTenantOrgs, 'on-only at holdingCo must reach live, archived, and moved-out orgs for tenant Entity Manager');
    const bobEntities = (await c.query('SELECT DISTINCT entity FROM app_views.coherence_bob ORDER BY entity')).rows.map((r) => r.entity);
    assert.deepEqual(bobEntities, ['Beacon', 'East Team', 'Harbor'], 'on-only at holdingCo must expose live BoB rows to tenant Entity Manager');
    const histEntities = (await c.query(
      "SELECT DISTINCT entity FROM app_views.coherence_statement_agency_lines WHERE entity IN ('Archived SW Agency', 'Moved Out SW Agency') ORDER BY entity",
    )).rows.map((r) => r.entity);
    assert.deepEqual(histEntities, ['Archived SW Agency', 'Moved Out SW Agency'], 'on-only at holdingCo must expose archived and moved-out statement rows to tenant Entity Manager');
  });

  await runAsPlatformApp(env.pool, { token: tok(holdingExec), readOnly: true }, async (c) => {
    const wide = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v.sort();
    assert.deepEqual(wide, expectedLiveOrgs, 'holdingExec (grant above tenant) still reaches only live tenant orgs');
  });

  // 2. holdingCo 'preview' with rootOrg 'on' (plus expired direct rootOrg -> acmeOrg edge) blocks live, archived, and moved-out orgs alike.
  const rootOnId = randomUUID();
  const holdingPreviewId = randomUUID();
  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.c2_fix1_holding_preview_root_on', commandKey: 'c2-fix1-holding-preview-root-on' });
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','on','active',$3)",
      [rootOnId, ids.rootOrg, j.seq],
    );
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq) VALUES ($1,$2,'coherence','preview','active',$3,$4)",
      [holdingPreviewId, holdingCo, holdingOnId, j.seq],
    );
  });

  for (const [label, pid] of [['acmeEntityMgr', ids.acmeEntityMgr], ['holdingExec', holdingExec]]) {
    await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
      assert.deepEqual(
        (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v,
        [],
        `holdingCo preview with root on must block live, archived, and moved-out orgs for ${label}`,
      );
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n, 0, `holdingCo preview must hide BoB from ${label}`);
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n, 0, `holdingCo preview must hide live, archived, and moved-out statements from ${label}`);
    });
  }
  await runAsPlatformApp(env.pool, { token: tok(ids.nusearOwner), readOnly: true }, async (c) => {
    const wide = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v.sort();
    assert.deepEqual(wide, expectedAllTenantOrgs, 'Nusear Owner must bypass holdingCo preview and retain live, archived, and moved-out orgs');
  });

  // 3. grandHoldingCo 'preview' (depth 2 above tenant) with rootOrg 'on' and expired direct rootOrg -> acmeOrg edge (depth 1):
  //    the expired depth-1 root edge must NOT outrank or bypass live grandHoldingCo 'preview'.
  const grandPreviewId = randomUUID();
  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.c2_fix1_grand_preview_root_on', commandKey: 'c2-fix1-grand-preview-root-on' });
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq) VALUES ($1,$2,'coherence','preview','revoked',$3,$4)",
      [randomUUID(), holdingCo, holdingPreviewId, j.seq],
    );
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','preview','active',$3)",
      [grandPreviewId, grandHoldingCo, j.seq],
    );
  });

  for (const [label, pid] of [['acmeEntityMgr', ids.acmeEntityMgr], ['holdingExec', holdingExec]]) {
    await runAsPlatformApp(env.pool, { token: tok(pid), readOnly: true }, async (c) => {
      assert.deepEqual(
        (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v,
        [],
        `expired direct rootOrg edge must not bypass live grandHoldingCo preview for ${label}`,
      );
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n, 0);
      assert.equal((await c.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n, 0);
    });
  }

  // 4. Once grandHoldingCo preview is revoked, rootOrg 'on' falls through last; rootOrg 'held' vetoes holdingCo 'on'.
  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.c2_fix1_root_fallback', commandKey: 'c2-fix1-root-fallback' });
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq) VALUES ($1,$2,'coherence','preview','revoked',$3,$4)",
      [randomUUID(), grandHoldingCo, grandPreviewId, j.seq],
    );
  });
  await runAsPlatformApp(env.pool, { token: tok(ids.acmeEntityMgr), readOnly: true }, async (c) => {
    const wide = (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v.sort();
    assert.deepEqual(wide, expectedAllTenantOrgs, 'rootOrg on must fall through last when no closer ancestor sets a switch');
  });

  await inSerializableTx(env.pool, async (c) => {
    const j = await appendAuditEntry(c, { environment, commandKind: 'iam.c2_fix1_root_held_veto', commandKey: 'c2-fix1-root-held-veto' });
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,'coherence','on','active',$3)",
      [randomUUID(), holdingCo, j.seq],
    );
    await c.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, hold_reason, status, replaces_id, journal_seq) VALUES ($1,$2,'coherence','held','root hold','active',$3,$4)",
      [randomUUID(), ids.rootOrg, rootOnId, j.seq],
    );
  });
  await runAsPlatformApp(env.pool, { token: tok(ids.acmeEntityMgr), readOnly: true }, async (c) => {
    assert.deepEqual(
      (await c.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v,
      [],
      'rootOrg held switch must still veto holdingCo on across live, archived, and moved-out orgs',
    );
  });
});
