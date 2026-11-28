// Layer 7: Approved Agent Register import into provisioned company databases (migrations 001..012,
// Releases E1..E5 + P1). Uses synthetic people only: verifies --plan (zero DB touches), split
// validation/planning modules, strict scopes & house-agency isolation under live RLS, wrong-company
// refusals, single-SERIALIZABLE-tx atomicity & rollback, website non-granting, date/cycle/org
// lifecycle rules, sha256-keyed re-imports & reactivation refusal, personal-data-free errors & apply
// outputs, org diff checks, vendor-mask Map validation, pool cleanup on partial failure, and
// repository fixture statement batches & history import resolving cleanly after register import.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  buildRegisterImportPoolConfig,
  parseRegisterImportCliArgs,
  runAgentRegisterImportCli,
} from '../scripts/import-agent-register.mjs';
import { buildImportPoolConfig } from '../scripts/import-history.mjs';
import { createAppCommands, createIamCommands } from '../src/commands/app-cmd.mjs';
import { verifyIamConfigInvariants } from '../src/config/policy-checks.mjs';
import {
  buildConnectionConfig,
  createClient,
  createPool,
  inReadTx,
  withRequestTx,
} from '../src/db/pg-client.mjs';
import { provisionCompanyDatabase } from '../src/iam/provision.mjs';
import { withAppAndReadPools } from '../src/iam/provisioned-runtime.mjs';
import { diffRoleGrants, importAgentRegisterIntoDatabase } from '../src/iam/register-import.mjs';
import {
  planAgentRegisterFile,
  planAgentRegisterImport,
  RegisterValidationError,
} from '../src/iam/register-plan.mjs';
import { validateAgentRegisterExport } from '../src/iam/register-validate.mjs';
import { keyFilePath, mintSignedSessionToken } from '../src/iam/tokens.mjs';
import { buildImportManifest, executeHistoryImport } from '../src/importer/history-importer.mjs';
import { importHistoryIntoDatabase } from '../src/importer/provisioned-import.mjs';
import { createFileObjectStore, createMemoryObjectStore } from '../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../src/storage/stores.mjs';
import { sha256Hex } from '../src/util/crypto.mjs';
import {
  createStdlibMockCoherenceRepo,
  makeOverlayCsv,
  sampleApprovalRow,
} from './helpers/fixtures.mjs';
import { createRoleScopedTestPool } from './helpers/iam-harness.mjs';
import { checkPgAvailable, getAdminPgConfig, TEST_DB_PREFIX } from './helpers/test-db.mjs';

const execFileAsync = promisify(execFile);
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI_PATH = join(REPO_ROOT, 'scripts', 'import-agent-register.mjs');
const pgCheck = await checkPgAvailable();

function quoteIdent(ident) {
  return `"${String(ident).replace(/"/g, '""')}"`;
}

async function createScratchDb(prefix = 'regimp') {
  const suffix = randomBytes(5).toString('hex');
  const dbName = `${TEST_DB_PREFIX}${prefix}_${suffix}`;
  const adminConfig = getAdminPgConfig();
  const admin = await createClient(adminConfig);
  try {
    await admin.query(`CREATE DATABASE ${quoteIdent(dbName)} ENCODING 'UTF8'`);
  } finally {
    await admin.end();
  }
  const pgConfig = { ...adminConfig, database: dbName };
  async function drop() {
    const c = await createClient(adminConfig).catch(() => null);
    if (!c) return;
    try {
      await c.query(
        'SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()',
        [dbName],
      );
      await c.query(`DROP DATABASE IF EXISTS ${quoteIdent(dbName)}`);
    } finally {
      await c.end().catch(() => {});
    }
  }
  return { dbName, pgConfig, drop };
}

async function provisionScratchCompany(t, {
  companySlug = 'acme',
  displayName = 'Acme',
  environment = 'dev',
  allowNonDev = false,
} = {}) {
  const db = await createScratchDb(companySlug);
  const workDir = await mkdtemp(join(tmpdir(), `coherence-regimp-${companySlug}-`));
  let pool = null;
  t.after(async () => {
    if (pool) await pool.end().catch(() => {});
    await db.drop().catch(() => {});
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  });
  const keysDir = join(workDir, 'keys');

  const prov = await provisionCompanyDatabase({
    pgConfig: db.pgConfig,
    companySlug,
    displayName,
    environment,
    allowNonDev,
    keysDir,
    staff: [
      { role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Platform' },
      { role: 'nusear_support', email: 'support@nusear.example', legalName: 'Casey Support' },
      { role: 'nusear_admin', email: 'admin@nusear.example', legalName: 'Morgan Admin' },
    ],
  });

  const staffKeyFile = keyFilePath(keysDir, { companySlug, environment, keyScope: 'nusear_staff' });
  const svcKeyFile = keyFilePath(keysDir, { companySlug, environment, keyScope: 'service' });
  pool = await createPool(db.pgConfig);

  const appPool = createRoleScopedTestPool(pool, 'platform_app');
  const readPool = createRoleScopedTestPool(pool, 'platform_readonly');

  return { db, workDir, keysDir, prov, staffKeyFile, svcKeyFile, pool, appPool, readPool };
}

async function seedCompanyLocalKey(pool, environment = 'dev') {
  const keyId = `k_cl_${randomBytes(4).toString('hex')}`;
  const secretBytes = randomBytes(32);
  await pool.query(
    `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, key_scope, active_from, active_until)
     VALUES ($1, $2, $3, 'company_local', pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours')`,
    [keyId, secretBytes, environment],
  );
  return {
    keyId,
    secretBytes,
    tokenFor: (actorPersonId) => mintSignedSessionToken({
      keyId,
      secretBytes,
      environment,
      actorPersonId,
    }),
  };
}

async function mintStaffTokenFromKeyFile(readPool, staffKeyFile, email, environment = 'dev') {
  const res = await readPool.query(
    `SELECT p.id FROM iam.people p
     JOIN iam.person_versions pv ON pv.person_id = p.id AND pv.superseded_by_id IS NULL
     WHERE pv.primary_email = $1 AND p.principal_origin = 'nusear_staff'`,
    [email],
  );
  const keyDoc = JSON.parse(await readFile(staffKeyFile, 'utf8'));
  return mintSignedSessionToken({
    keyId: keyDoc.keyId,
    secretBytes: Buffer.from(keyDoc.secretHex, 'hex'),
    environment,
    actorPersonId: res.rows[0].id,
  });
}

async function snapshotIamAndAuditCounts(pool) {
  const tables = [
    'platform.audit_journal',
    'iam.organizations', 'iam.organization_versions', 'iam.organization_edges',
    'iam.people', 'iam.person_versions',
    'iam.organization_memberships', 'iam.agent_affiliations',
    'iam.role_grants', 'iam.role_grant_people',
  ];
  const out = {};
  for (const tbl of tables) {
    out[tbl] = (await pool.query(`SELECT COUNT(*)::int AS n FROM ${tbl}`)).rows[0].n;
  }
  return out;
}

async function writeTree(baseDir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = join(baseDir, ...rel.split('/'));
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
}

function makeApprovedSyntheticRegister(overrides = {}) {
  return {
    format: 'agent-register',
    schema: 1,
    revision: 12,
    basedOn: 11,
    updatedAt: '2026-11-26T12:00:00Z',
    updatedBy: 'test-approver',
    approval: {
      approvedAt: '2026-11-26T12:05:00Z',
      approvedBy: 'test-approver',
      note: 'Synthetic approved version for automated tests',
      fromRevision: 12,
      warnings: [],
      files: {},
    },
    schedules: {
      AGENT: { label: 'Agent', advanceCents: 5000, finalCents: 5000, qualification: 'THREE_COMPLETE_COVERAGE_MONTHS' },
      RETENTION: { label: 'Retention agent', advanceCents: 0, finalCents: 4000, qualification: 'THREE_COMPLETE_COVERAGE_MONTHS' },
    },
    entities: [
      { name: 'Nusear', kind: 'company' },
      { name: 'Acme', kind: 'agency', house: true },
      { name: 'Beacon', kind: 'agency' },
      { name: 'East Team', kind: 'team', parent: 'Beacon' },
      { name: 'East Pod', kind: 'team', parent: 'East Team' },
      { name: 'Harbor', kind: 'agency' },
      { name: 'SubCo', kind: 'company', parent: 'Acme' },
      { name: 'Cobalt Leads', kind: 'lead_vendor', externalDomain: 'cobalt.example' },
      { name: 'Partner Firm', kind: 'referral_firm', externalDomain: 'partner.example' },
      { name: 'Outside Upline', kind: 'external_upline' },
    ],
    people: [
      { id: 'p-0001', name: 'Pat Owner', assignedName: 'Pat Owner', npn: null, emails: ['pat@acme.example', 'pat.alt@acme.example'], personalEmails: ['pat.home@example.com'], personalPhones: ['5551112222'] },
      { id: 'p-0002', name: 'Dana Entity', assignedName: 'Dana E', npn: null, emails: ['dana@acme.example'] },
      { id: 'p-0003', name: 'Sloan Admin', assignedName: 'Sloan A', npn: null, emails: ['sloan@acme.example'] },
      { id: 'p-0004', name: 'Taylor Beacon', assignedName: 'Taylor B', npn: null, emails: ['taylor@beacon.example'] },
      { id: 'p-0005', name: 'Sam Seller', assignedName: 'Sam Seller', npn: '11111111', emails: ['sam@beacon.example'] },
      { id: 'p-0006', name: 'Robin Harbor', assignedName: 'Robin H', npn: '33333333', emails: ['robin@harbor.example'] },
      { id: 'p-0007', name: 'Jamie East', assignedName: 'Jamie E', npn: '44444444', emails: ['jamie@beacon.example'] },
      { id: 'p-0008', name: 'Jordan Retain', assignedName: 'Jordan R', npn: '31313131', emails: ['jordan@harbor.example'] },
      { id: 'p-0009', name: 'Drew Compliance', assignedName: 'Drew C', npn: null, emails: ['drew@acme.example'] },
      { id: 'p-0010', name: 'Avery Investor', assignedName: 'Avery I', npn: null, emails: ['avery@acme.example'] },
      { id: 'p-0011', name: 'Riley Sales', assignedName: 'Riley S', npn: null, emails: ['riley@acme.example'] },
      { id: 'p-0012', name: 'Morgan Acct', assignedName: 'Morgan A', npn: null, emails: ['morgan@acme.example'] },
      { id: 'p-0013', name: 'Quinn Vendor', assignedName: 'Quinn V', npn: null, emails: ['quinn@cobalt.example'] },
      { id: 'p-0014', name: 'Lee Partner', assignedName: 'Lee P', npn: null, emails: ['lee@partner.example'] },
      { id: 'p-0015', name: 'Casey Consultant', assignedName: 'Casey C', npn: null, emails: ['casey@consult.example'] },
      { id: 'p-0016', name: 'Acme House Account', assignedName: null, npn: '99990001', emails: [], house: true, houseOf: 'Acme' },
      { id: 'p-0017', name: 'Chris Suspended', assignedName: 'Chris S', npn: '55555555', emails: ['chris@beacon.example'] },
      { id: 'p-0018', name: 'Nusear Staff Only', assignedName: 'Nusear Staff', npn: null, emails: ['staffonly@nusear.example'] },
      { id: 'p-0019', name: 'Hayden HouseMgr', assignedName: 'Hayden HM', npn: null, emails: ['hayden@acme.example'] },
      { id: 'p-0020', name: 'Skyler HouseAgent', assignedName: 'Skyler HA', npn: '22222222', emails: ['skyler@acme.example'] },
      { id: 'p-0021', name: 'Rowan HouseRetain', assignedName: 'Rowan HR', npn: '23232323', emails: ['rowan@acme.example'] },
      { id: 'p-0022', name: 'Blair HouseComp', assignedName: 'Blair HC', npn: null, emails: ['blair@acme.example'] },
    ],
    affiliations: [
      { id: 'a-0001', person: 'p-0005', npn: '11111111', entity: 'Beacon', agentName: 'Sam Seller', start: '2024-01-01', end: null, split: '80.00' },
      { id: 'a-0002', person: 'p-0006', npn: '33333333', entity: 'Harbor', agentName: 'Robin Harbor', start: '2024-01-01', end: null, split: '75.00' },
      { id: 'a-0003', person: 'p-0007', npn: '44444444', entity: 'East Team', agentName: 'Jamie East', start: '2024-06-01', end: null, split: '80.00' },
      { id: 'a-0004', person: 'p-0008', npn: '31313131', entity: 'Harbor', agentName: 'Jordan Retain', start: '2024-01-01', end: null, split: '0.00' },
      { id: 'a-0005', person: 'p-0017', npn: '55555555', entity: 'Beacon', agentName: 'Chris Suspended', start: '2024-01-01', end: null, split: '80.00' },
      { id: 'a-0006', person: 'p-0020', npn: '22222222', entity: 'Acme', agentName: 'Skyler HouseAgent', start: '2024-01-01', end: null, split: '100.00' },
      { id: 'a-0007', person: 'p-0021', npn: '23232323', entity: 'Acme', agentName: 'Rowan HouseRetain', start: '2024-01-01', end: null, split: '0.00' },
    ],
    memberships: [
      { id: 'm-0000', person: 'p-0001', entity: 'Nusear', role: 'OWNER', start: '2020-01-01', end: null },
      { id: 'm-0001', person: 'p-0001', entity: 'Acme', role: 'OWNER', start: '2023-01-01', end: null },
      { id: 'm-0002', person: 'p-0002', entity: 'Acme', role: 'EMPLOYEE', taxClassification: 'w2', start: '2023-01-01', end: null },
      { id: 'm-0003', person: 'p-0003', entity: 'Acme', role: 'SYSTEMS_ADMIN', workArrangement: 'employee', start: '2023-01-01', end: null },
      { id: 'm-0004', person: 'p-0004', entity: 'Beacon', role: 'EMPLOYEE', start: '2024-01-01', end: null },
      { id: 'm-0005', person: 'p-0008', entity: 'Harbor', role: 'EMPLOYEE', start: '2024-01-01', end: null },
      { id: 'm-0006', person: 'p-0009', entity: 'Acme', role: 'EMPLOYEE', start: '2024-01-01', end: null },
      { id: 'm-0007', person: 'p-0010', entity: 'Acme', role: 'INVESTOR', start: null, end: null },
      { id: 'm-0008', person: 'p-0011', entity: 'Acme', role: 'EMPLOYEE', start: '2024-01-01', end: null },
      { id: 'm-0009', person: 'p-0012', entity: 'Acme', role: 'EMPLOYEE', start: '2024-01-01', end: null },
      { id: 'm-0010', person: 'p-0013', entity: 'Cobalt Leads', role: 'VENDOR_REP', start: '2024-01-01', end: null },
      { id: 'm-0011', person: 'p-0014', entity: 'Partner Firm', role: 'REFERRAL_PARTNER', start: '2024-01-01', end: null },
      { id: 'm-0012', person: 'p-0015', entity: 'SubCo', role: 'CONSULTANT', workArrangement: 'self_employed_external', taxClassification: '1099', start: '2024-01-01', end: null },
      { id: 'm-0013', person: 'p-0018', entity: 'Nusear', role: 'EMPLOYEE', start: '2022-01-01', end: null },
      { id: 'm-0014', person: 'p-0019', entity: 'Acme', role: 'EMPLOYEE', start: '2024-01-01', end: null },
      { id: 'm-0015', person: 'p-0022', entity: 'Acme', role: 'EMPLOYEE', start: '2024-01-01', end: null },
    ],
    roles: [
      { id: 'r-0000', person: 'p-0001', role: 'OWNER', scope: 'all' },
      { id: 'r-0001', person: 'p-0001', role: 'APPLICATION_MANAGER', scope: 'all' },
      { id: 'r-0002', person: 'p-0001', role: 'ENTITY_MANAGER', scope: 'all' },
      { id: 'r-0003', person: 'p-0002', role: 'ENTITY_MANAGER', scope: 'all' },
      { id: 'r-0004', person: 'p-0003', role: 'COMPANY_ADMIN', scope: 'all' },
      { id: 'r-0005', person: 'p-0004', role: 'AGENCY_MANAGER', scope: { entities: ['Beacon'] } },
      { id: 'r-0006', person: 'p-0005', role: 'SELLING_AGENT', scope: { entities: ['Beacon'], npns: ['11111111'] } },
      { id: 'r-0007', person: 'p-0006', role: 'SELLING_AGENT', scope: { entities: ['Harbor'], npns: ['33333333'] } },
      { id: 'r-0008', person: 'p-0007', role: 'SELLING_AGENT', scope: { npns: ['44444444'] } },
      { id: 'r-0009', person: 'p-0008', role: 'RETENTION_AGENT', scope: { entities: ['Harbor'] } },
      { id: 'r-0010', person: 'p-0009', role: 'COMPLIANCE', scope: { npns: ['11111111', '33333333'] } },
      { id: 'r-0011', person: 'p-0010', role: 'INVESTOR', scope: 'all' },
      { id: 'r-0012', person: 'p-0011', role: 'DIRECTOR_OF_SALES', scope: 'all' },
      { id: 'r-0013', person: 'p-0012', role: 'ACCOUNTING', scope: 'all' },
      { id: 'r-0014', person: 'p-0017', role: 'SELLING_AGENT', scope: { entities: ['Beacon'], npns: ['55555555'] } },
      { id: 'r-0015', person: 'p-0016', role: 'SELLING_AGENT', scope: { npns: ['99990001'] } },
      { id: 'r-0016', person: 'p-0019', role: 'AGENCY_MANAGER', scope: { entities: ['Acme'] } },
      { id: 'r-0017', person: 'p-0020', role: 'SELLING_AGENT', scope: { entities: ['Acme'], npns: ['22222222'] } },
      { id: 'r-0018', person: 'p-0021', role: 'RETENTION_AGENT', scope: { entities: ['Acme'] } },
      { id: 'r-0019', person: 'p-0022', role: 'COMPLIANCE', scope: { entities: ['Acme'], npns: ['11111111', '22222222'] } },
    ],
    website: [
      { email: 'pat@acme.example', person: 'p-0001', role: 'owner', status: 'active' },
      { email: 'sloan@acme.example', person: 'p-0003', role: 'admin', status: 'active' },
      { email: 'chris@beacon.example', person: 'p-0017', role: 'agent', status: 'disabled' },
    ],
    pay: [],
    questions: [],
    sources: [],
    ...overrides,
  };
}

test('Agent Register Import [CLI Parsing, Shared P1 Helpers, Pool Cleanup, Vendor-Mask Map & --plan Mode]: validates approved export and lists creations without touching any database', async (t) => {
  // CLI parsing & Cloud SQL pool config sharing provisioned-runtime with import-history.mjs.
  assert.throws(
    () => parseRegisterImportCliArgs(['--register', 'r.json', '--key-file', 'k.json', '--actor-email', 'a@b.example']),
    (err) => err?.code === 'MISSING_CLI_ARGS',
    'apply mode must require --database',
  );
  const planArgs = parseRegisterImportCliArgs([
    '--register', 'v1.json', '--plan', '--company-slug', 'acme', '--vendor-mask', 'Cobalt Leads=Vendor Alpha',
  ]);
  assert.equal(planArgs.plan, true);
  assert.ok(planArgs.vendorMasks instanceof Map, '--vendor-mask must be stored in a Map');
  assert.equal(planArgs.vendorMasks.get('Cobalt Leads'), 'Vendor Alpha');

  // Duplicate --vendor-mask (exact or case-insensitive) must be refused.
  assert.throws(
    () => parseRegisterImportCliArgs([
      '--register', 'v1.json', '--plan',
      '--vendor-mask', 'Cobalt Leads=Vendor Alpha',
      '--vendor-mask', 'cobalt leads=Vendor Beta',
    ]),
    (err) => err?.code === 'DUPLICATE_VENDOR_MASK',
    'duplicate --vendor-mask must be refused case-insensitively',
  );

  const cloudArgs = parseRegisterImportCliArgs([
    '--register', 'v1.json',
    '--database', 'acme',
    '--key-file', '/tmp/k.key.json',
    '--actor-email', 'owner@nusear.example',
    '--pg-mode', 'cloudsql',
    '--app-socket-path', '/tmp/cloudsql-app/proj:us-east4:dev-db',
    '--app-user', 'app-svc@proj.iam',
    '--readonly-socket-path', '/tmp/cloudsql-ro/proj:us-east4:dev-db',
    '--readonly-user', 'ro-svc@proj.iam',
  ]);
  const appCfg = buildRegisterImportPoolConfig(cloudArgs, 'app');
  const roCfg = buildRegisterImportPoolConfig(cloudArgs, 'readonly');
  const histAppCfg = buildImportPoolConfig(cloudArgs, 'app');
  assert.equal(appCfg.role, 'platform_app');
  assert.equal(roCfg.role, 'platform_readonly');
  assert.equal(appCfg.socketPath, histAppCfg.socketPath);
  assert.equal(appCfg.role, histAppCfg.role);
  const builtApp = buildConnectionConfig({ ...appCfg, env: {} });
  assert.equal(builtApp.port, 5432);
  assert.equal(builtApp.options, '-c role=platform_app');
  assert.throws(
    () => buildConnectionConfig({ ...appCfg, env: { PGPASSWORD: 'nope' } }),
    /PGPASSWORD/,
  );

  // Pool cleanup on partial failure: if readPool creation throws, appPool.end() MUST be called.
  let appEndedDirect = false;
  let callNum = 0;
  await assert.rejects(
    () => withAppAndReadPools(
      { applicationName: 'app' },
      { applicationName: 'ro' },
      async () => {},
      {
        createPoolFn: async () => {
          callNum += 1;
          if (callNum === 1) return { end: async () => { appEndedDirect = true; } };
          throw new Error('simulated read pool failure');
        },
      },
    ),
    /simulated read pool failure/,
  );
  assert.equal(appEndedDirect, true, 'withAppAndReadPools must close appPool if readPool fails');

  let cliAppEnded = false;
  let cliCalls = 0;
  await assert.rejects(
    () => runAgentRegisterImportCli(
      parseRegisterImportCliArgs([
        '--register', 'v1.json',
        '--database', 'test_pool_cleanup',
        '--key-file', '/tmp/k.key.json',
        '--actor-email', 'owner@nusear.example',
      ]),
      {
        createPoolFn: async () => {
          cliCalls += 1;
          if (cliCalls === 1) return { end: async () => { cliAppEnded = true; } };
          throw new Error('simulated cli read pool failure');
        },
      },
    ),
    /simulated cli read pool failure/,
  );
  assert.equal(cliAppEnded, true, 'runAgentRegisterImportCli must close appPool if readPool creation fails');

  const tmpDir = await mkdtemp(join(tmpdir(), 'coherence-regplan-'));
  t.after(() => rm(tmpDir, { recursive: true, force: true }));

  const reg = makeApprovedSyntheticRegister();
  const directPath = join(tmpDir, '0001.json');
  const wrappedPath = join(tmpDir, 'show-v1.json');
  await writeFile(directPath, `${JSON.stringify(reg, null, 2)}\n`, 'utf8');
  await writeFile(wrappedPath, `${JSON.stringify({ register: reg, summary: { revision: 12 } }, null, 2)}\n`, 'utf8');
  const hashBefore = sha256Hex(await readFile(directPath));

  // Direct split-module test: register-validate.mjs validates export independently of register-plan.mjs.
  const validated = validateAgentRegisterExport(reg, {
    companySlug: 'acme',
    companyDisplayName: 'Acme',
    vendorMasks: new Map([['Cobalt Leads', 'Vendor Alpha']]),
  });
  assert.equal(validated.collector.issues.length, 0);
  assert.equal(validated.entState.resolvedCompanySlug, 'acme');

  // Run CLI --plan with unreachable PGHOST and forbidden PGDATABASE to prove zero DB touches.
  const cliRes = await execFileAsync(process.execPath, [
    CLI_PATH,
    '--register', directPath,
    '--plan',
    '--vendor-mask', 'Cobalt Leads=Vendor Alpha',
  ], {
    env: {
      ...process.env,
      PGHOST: '/nonexistent-socket-should-never-be-opened',
      PGPORT: '1',
      PGDATABASE: 'postgres',
    },
  });
  const planOut = JSON.parse(cliRes.stdout);
  assert.equal(planOut.mode, 'plan');
  assert.equal(planOut.valid, true);
  assert.equal(planOut.companySlug, 'acme');
  assert.equal(planOut.counts.organizations, 8); // Beacon, East Team, East Pod, Harbor, SubCo, Cobalt Leads, Partner Firm, Outside Upline
  assert.equal(planOut.counts.people, 21); // 22 minus Nusear Staff Only
  assert.equal(planOut.counts.affiliations, 7);
  assert.equal(planOut.counts.suspendedOrArchivedPeople, 1);
  assert.deepEqual(planOut.skippedOutside.entities, ['Nusear']);
  assert.equal(planOut.skippedOutside.people.length, 1);
  assert.equal(planOut.skippedOutside.memberships.length, 2);
  assert.equal(
    planOut.organizations.find((o) => o.displayName === 'Cobalt Leads').maskedDisplayName,
    'Vendor Alpha',
  );
  // Verify includeDescendants rules in plan output (Item 1):
  // true ONLY for scope "all" and entity-less explicit_people; false for explicit entities & self-scoped agents.
  const grantByRow = (rowId) => planOut.roleGrants.find((g) => g.sourceRowIds.includes(rowId));
  assert.equal(grantByRow('r-0000').includeDescendants, true, 'scope all OWNER descends');
  assert.equal(grantByRow('r-0001').includeDescendants, true, 'scope all ENTITY_MANAGER descends');
  assert.equal(grantByRow('r-0004').includeDescendants, true, 'scope all COMPANY_ADMIN descends');
  assert.equal(grantByRow('r-0010').includeDescendants, true, 'entity-less COMPLIANCE explicit_people descends');
  assert.equal(grantByRow('r-0005').includeDescendants, false, 'explicit-entity Beacon AGENCY_MANAGER does not descend');
  assert.equal(grantByRow('r-0016').includeDescendants, false, 'explicit-entity house-agency Acme AGENCY_MANAGER does not descend');
  assert.equal(grantByRow('r-0017').includeDescendants, false, 'house-agency SELLING_AGENT never descends');
  assert.equal(grantByRow('r-0018').includeDescendants, false, 'house-agency RETENTION_AGENT never descends');
  assert.equal(grantByRow('r-0019').includeDescendants, false, 'explicit-entity house-agency COMPLIANCE does not descend');
  assert.equal(grantByRow('r-0008').includeDescendants, false, 'affiliation-derived SELLING_AGENT never descends');
  assert.equal(grantByRow('r-0015').includeDescendants, false, 'house-account SELLING_AGENT never descends');
  // Website entries NEVER synthesize any role grant (Item 4).
  assert.ok(
    planOut.roleGrants.every((g) => g.sourceRowIds.every((id) => !id.startsWith('website#'))),
    'no role grant may ever be created from doc.website',
  );
  // --plan never leaks personal emails or personal phones.
  assert.ok(!cliRes.stdout.includes('pat.home@example.com'), '--plan output must not contain personal emails');
  assert.ok(!cliRes.stdout.includes('5551112222'), '--plan output must not contain personal phones');
  // Source file completely untouched.
  assert.equal(sha256Hex(await readFile(directPath)), hashBefore);

  // Wrapped `python3 -m register --json show --version N` format also plans cleanly.
  const wrappedPlan = await planAgentRegisterFile(wrappedPath, {
    companySlug: 'acme',
    companyDisplayName: 'Acme',
    vendorMasks: new Map([['Cobalt Leads', 'Vendor Alpha']]),
  });
  assert.equal(wrappedPlan.valid, true);
  assert.deepEqual(wrappedPlan.counts, planOut.counts);
});

test('Agent Register Import [All Refusals & Personal Data Hygiene]: enforces owner rulings, scopes, wrong company, website non-granting, dates/cycles/orgs, vendor masks, and ID-only error messages', async (t) => {
  const base = makeApprovedSyntheticRegister({
    entities: [
      { name: 'Acme', kind: 'agency', house: true },
      { name: 'Beacon', kind: 'agency' },
      { name: 'Harbor', kind: 'agency' },
      { name: 'Cobalt Leads', kind: 'lead_vendor', maskedDisplayName: 'Vendor 01' },
    ],
    people: [
      { id: 'p-1', name: 'Pat Owner', npn: null, emails: ['pat@acme.example'] },
      { id: 'p-2', name: 'Sam Seller', npn: '11111111', emails: ['sam@beacon.example'] },
      { id: 'p-3', name: 'Robin Agent', npn: '22222222', emails: ['robin@harbor.example'] },
      { id: 'p-4', name: 'Skyler House', npn: '44444444', emails: ['skyler@acme.example'] },
      { id: 'p-5', name: 'Acme House Account', npn: '99990001', emails: [], house: true, houseOf: 'Acme' },
    ],
    affiliations: [
      { id: 'a-1', person: 'p-2', npn: '11111111', entity: 'Beacon', start: '2024-01-01', end: null, split: '80.00' },
      { id: 'a-2', person: 'p-3', npn: '22222222', entity: 'Harbor', start: '2024-01-01', end: null, split: '80.00' },
      { id: 'a-3', person: 'p-4', npn: '44444444', entity: 'Acme', start: '2024-01-01', end: null, split: '100.00' },
    ],
    memberships: [
      { id: 'm-1', person: 'p-1', entity: 'Acme', role: 'OWNER', start: '2023-01-01', end: null },
    ],
    roles: [
      { id: 'r-0', person: 'p-1', role: 'OWNER', scope: 'all' },
      { id: 'r-1', person: 'p-1', role: 'ENTITY_MANAGER', scope: 'all' },
      { id: 'r-2', person: 'p-2', role: 'SELLING_AGENT', scope: { entities: ['Beacon'], npns: ['11111111'] } },
      { id: 'r-3', person: 'p-3', role: 'SELLING_AGENT', scope: { entities: ['Harbor'], npns: ['22222222'] } },
      { id: 'r-4', person: 'p-4', role: 'SELLING_AGENT', scope: { entities: ['Acme'], npns: ['44444444'] } },
      { id: 'r-5', person: 'p-5', role: 'SELLING_AGENT', scope: { npns: ['99990001'] } },
    ],
    website: [],
  });
  const baseOpts = { companySlug: 'acme', companyDisplayName: 'Acme', today: '2026-11-27' };
  assert.doesNotThrow(() => planAgentRegisterImport(base, baseOpts));
  // Another company in the register (the owner's holding company, say) is left out with its memberships, like Nusear.
  const withOtherCompany = planAgentRegisterImport({
    ...base,
    entities: [...base.entities, { name: 'Other Corp', kind: 'company' }],
    memberships: [...base.memberships, { id: 'm-oc', person: 'p-1', entity: 'Other Corp', role: 'INVESTOR', start: null, end: null }],
  }, baseOpts);
  assert.ok(withOtherCompany.skippedOutside.entities.includes('Other Corp'));
  assert.ok(withOtherCompany.skippedOutside.memberships.some((m) => m.id === 'm-oc'));
  assert.ok(!withOtherCompany.organizations.some((o) => o.displayName === 'Other Corp'));
  // Someone whose only tie is another company, with no login and no role, is left out with it.
  const onlyOutside = planAgentRegisterImport({
    ...base,
    entities: [...base.entities, { name: 'Other Corp', kind: 'company' }],
    people: [...base.people, { id: 'p-oc', name: 'Olive Outside', npn: null, emails: [] }],
    memberships: [...base.memberships, { id: 'm-oc2', person: 'p-oc', entity: 'Other Corp', role: 'OWNER', start: null, end: null }],
  }, baseOpts);
  assert.ok(onlyOutside.skippedOutside.people.some((p) => p.personId === 'p-oc'));
  assert.ok(!onlyOutside.people.some((p) => p.registerId === 'p-oc'));
  // The agency manager and contractor relationships (the owner, 11/27) carry no invented work arrangement.
  const newRelationships = planAgentRegisterImport({
    ...base,
    memberships: [...base.memberships,
      { id: 'm-am', person: 'p-1', entity: 'Beacon', role: 'AGENCY_MANAGER', start: '2024-01-01', end: null },
      { id: 'm-ct', person: 'p-1', entity: 'Harbor', role: 'CONTRACTOR', start: '2024-01-01', end: null }],
  }, baseOpts);
  for (const entity of ['Beacon', 'Harbor']) {
    const m = newRelationships.memberships.find((one) => one.personRegisterId === 'p-1' && one.entityName === entity && one.validRange.startsWith('[2024-01-01'));
    assert.ok(m, `the ${entity} relationship is planned`);
    assert.equal(m.workArrangement, null);
  }
  // A principal with an NPN and no role (the owner, 11/28: 'a user with zero permissions'): imported, with no grant at all.
  const principalPlan = planAgentRegisterImport({
    ...base,
    people: [...base.people, { id: 'p-pr', name: 'Pia Principal', npn: '55555555', emails: [] }],
    memberships: [...base.memberships, { id: 'm-pr', person: 'p-pr', entity: 'Acme', role: 'PRINCIPAL', start: null, end: null }],
  }, baseOpts);
  assert.ok(principalPlan.people.some((p) => p.registerId === 'p-pr' && p.npn === '55555555'));
  assert.ok(!principalPlan.roleGrants.some((g) => g.personRegisterId === 'p-pr'), 'a principal holds no permission');
  assert.ok(!principalPlan.affiliations.some((a) => a.personRegisterId === 'p-pr'));
  const principalLine = principalPlan.memberships.find((m) => m.personRegisterId === 'p-pr');
  assert.equal(principalLine.entityName, 'Acme');
  assert.equal(principalLine.workArrangement, null);
  assert.equal(principalLine.taxClassification, null);
  assert.equal(principalLine.validRange, '[0001-01-01,)');
  // The Nusear contractor (the owner, 11/27) maps to its catalog role and backs an administrator's website login, as the administrator does.
  const contractorPlan = planAgentRegisterImport({
    ...base,
    people: [...base.people, { id: 'p-nc', name: 'Nico Contractor', npn: null, emails: ['nico@acme.example'] }],
    memberships: [...base.memberships, { id: 'm-nc', person: 'p-nc', entity: 'Acme', role: 'CONSULTANT', start: '2024-01-01', end: null }],
    roles: [...base.roles, { id: 'r-nc', person: 'p-nc', role: 'NUSEAR_CONTRACTOR', scope: 'all' }],
    website: [{ email: 'nico@acme.example', person: 'p-nc', role: 'admin', status: 'active' }],
  }, baseOpts);
  const contractorGrant = contractorPlan.roleGrants.find((g) => g.personRegisterId === 'p-nc');
  assert.equal(contractorGrant.roleSlug, 'nusear_contractor');
  assert.equal(contractorGrant.includeDescendants, true);
  // A website owner backed by a company-wide entity manager line (the owner, 11/27: the entity manager is the control roles' view).
  assert.doesNotThrow(() => planAgentRegisterImport({
    ...base,
    roles: base.roles.filter((r) => r.id !== 'r-0'),
    website: [{ email: 'pat@acme.example', person: 'p-1', role: 'owner', status: 'active' }],
  }, baseOpts));

  // [label, badDoc, optsOverride, expectedCode, msgRe, forbiddenPersonalStrings]
  const cases = [
    ['unapproved_draft', { ...base, approval: undefined }, null, 'UNAPPROVED_REGISTER', /approved/i, []],
    ['open_questions', { ...base, questions: [{ id: 'q-99', person: 'p-1', answer: null }] }, null, 'OPEN_REVIEW_QUESTIONS', /q-99/, []],
    ['role_without_relationship_em', {
      ...base,
      people: [...base.people, { id: 'p-norel', name: 'Unlinked Manager', npn: null, emails: ['unlinked@acme.example'] }],
      roles: [...base.roles, { id: 'r-norel', person: 'p-norel', role: 'ENTITY_MANAGER', scope: 'all' }],
    }, null, 'MISSING_RELATIONSHIP', /r-norel.*p-norel/, ['Unlinked Manager']],
    ['role_without_relationship_agency_mgr', {
      ...base,
      people: [...base.people, { id: 'p-noag', name: 'Unlinked Agency Mgr', npn: null, emails: ['noag@beacon.example'] }],
      roles: [...base.roles, { id: 'r-noag', person: 'p-noag', role: 'AGENCY_MANAGER', scope: { entities: ['Beacon'] } }],
    }, null, 'MISSING_RELATIONSHIP', /r-noag.*p-noag/, ['Unlinked Agency Mgr']],
    ['role_without_relationship_compliance', {
      ...base,
      people: [...base.people, { id: 'p-nocomp', name: 'Unlinked Compliance', npn: null, emails: ['nocomp@acme.example'] }],
      roles: [...base.roles, { id: 'r-nocomp', person: 'p-nocomp', role: 'COMPLIANCE', scope: { npns: ['11111111'] } }],
    }, null, 'MISSING_RELATIONSHIP', /r-nocomp.*p-nocomp/, ['Unlinked Compliance', '11111111']],
    ['role_without_relationship_selling_agent', {
      ...base,
      people: [...base.people, { id: 'p-noaff', name: 'Unlinked Seller', npn: '33333333', emails: [] }],
      roles: [...base.roles, { id: 'r-noaff', person: 'p-noaff', role: 'SELLING_AGENT', scope: { entities: ['Beacon'], npns: ['33333333'] } }],
    }, null, 'MISSING_RELATIONSHIP', /r-noaff.*p-noaff/, ['Unlinked Seller', '33333333']],
    ['dated_role_past_ended_membership', {
      ...base,
      people: [...base.people, { id: 'p-ended', name: 'Ended Staff', npn: null, emails: [] }],
      memberships: [...base.memberships, { id: 'm-ended', person: 'p-ended', entity: 'Beacon', role: 'EMPLOYEE', start: '2024-01-01', end: '2024-12-31' }],
      roles: [...base.roles, { id: 'r-past', person: 'p-ended', role: 'AGENCY_MANAGER', scope: { entities: ['Beacon'] }, start: '2025-01-01', end: null }],
    }, null, 'MISSING_RELATIONSHIP', /r-past.*p-ended/, ['Ended Staff']],
    ['child_agent_holding_parent_company_role', {
      ...base,
      roles: [...base.roles, { id: 'r-upward', person: 'p-2', role: 'ENTITY_MANAGER', scope: 'all' }],
    }, null, 'MISSING_RELATIONSHIP', /r-upward.*p-2/, ['Sam Seller', '11111111']],
    // Item 1: house agency affiliation & house account NEVER cover non-agent roles or other agencies.
    ['house_affiliation_cannot_cover_company_entity_manager', {
      ...base,
      roles: [...base.roles, { id: 'r-ha-em', person: 'p-4', role: 'ENTITY_MANAGER', scope: 'all' }],
    }, null, 'MISSING_RELATIONSHIP', /r-ha-em.*p-4/, ['Skyler House', '44444444']],
    ['house_affiliation_cannot_cover_house_agency_manager', {
      ...base,
      roles: [...base.roles, { id: 'r-ha-am', person: 'p-4', role: 'AGENCY_MANAGER', scope: { entities: ['Acme'] } }],
    }, null, 'MISSING_RELATIONSHIP', /r-ha-am.*p-4/, ['Skyler House', '44444444']],
    ['house_affiliation_cannot_cover_sibling_agency_manager', {
      ...base,
      roles: [...base.roles, { id: 'r-ha-sib', person: 'p-4', role: 'AGENCY_MANAGER', scope: { entities: ['Beacon'] } }],
    }, null, 'MISSING_RELATIONSHIP', /r-ha-sib.*p-4/, ['Skyler House', '44444444']],
    ['house_affiliation_cannot_cover_sibling_agent', {
      ...base,
      roles: [...base.roles, { id: 'r-ha-sibag', person: 'p-4', role: 'SELLING_AGENT', scope: { entities: ['Beacon'], npns: ['44444444'] } }],
    }, null, 'MISSING_RELATIONSHIP', /r-ha-sibag.*p-4/, ['Skyler House', '44444444']],
    ['house_account_cannot_cover_company_entity_manager', {
      ...base,
      roles: [...base.roles, { id: 'r-hacc-em', person: 'p-5', role: 'ENTITY_MANAGER', scope: 'all' }],
    }, null, 'MISSING_RELATIONSHIP', /r-hacc-em.*p-5/, ['Acme House Account', '99990001']],
    ['house_account_cannot_cover_sibling_agency_manager', {
      ...base,
      roles: [...base.roles, { id: 'r-hacc-sib', person: 'p-5', role: 'AGENCY_MANAGER', scope: { entities: ['Beacon'] } }],
    }, null, 'MISSING_RELATIONSHIP', /r-hacc-sib.*p-5/, ['Acme House Account', '99990001']],
    // Item 2: wrong company / duplicate match / archived or ended target company entity.
    ['wrong_company_house_entity', base, { companySlug: 'beta', companyDisplayName: 'Beta', today: '2026-11-27' }, 'AMBIGUOUS_COMPANY_ENTITY', /Acme/, []],
    ['wrong_company_kind_company', {
      ...base,
      entities: [{ name: 'Acme', kind: 'company' }, ...base.entities.slice(1)],
    }, { companySlug: 'beta', companyDisplayName: 'Beta', today: '2026-11-27' }, 'AMBIGUOUS_COMPANY_ENTITY', /No entity matches target company "beta"/, []],
    ['agency_only_register_names_no_company', {
      ...base,
      entities: [{ name: 'Acme', kind: 'agency' }, ...base.entities.slice(1)],
    }, { companySlug: 'beta', companyDisplayName: 'Beta', today: '2026-11-27' }, 'AMBIGUOUS_COMPANY_ENTITY', /No entity matches target company "beta"/, []],
    // A downline agency never passes as the company: a register run against one of its own agencies' databases is refused.
    ['company_register_into_its_downline_agency', {
      ...base,
      entities: [{ name: 'Acme', kind: 'company' }, ...base.entities.slice(1)],
    }, { companySlug: 'beacon', companyDisplayName: 'Beacon', today: '2026-11-27' }, 'AMBIGUOUS_COMPANY_ENTITY', /No entity matches target company "beacon"/, []],
    ['agency_only_register_into_its_downline_agency', {
      ...base,
      entities: [{ name: 'Acme', kind: 'agency' }, ...base.entities.slice(1)],
    }, { companySlug: 'beacon', companyDisplayName: 'Beacon', today: '2026-11-27' }, 'AMBIGUOUS_COMPANY_ENTITY', /No entity matches target company "beacon"/, []],
    // Another company is left out only when the register marks its own company as the house.
    ['two_companies_and_no_house', {
      ...base,
      entities: [{ name: 'Acme', kind: 'company' }, { name: 'Holding Co', kind: 'company' }, ...base.entities.slice(1)],
    }, { companySlug: 'holding_co', companyDisplayName: 'Holding Co', today: '2026-11-27' }, 'AMBIGUOUS_COMPANY_ENTITY', /"Acme".*marks no house/, []],
    ['affiliation_on_another_company', {
      ...base,
      entities: [...base.entities, { name: 'Other Corp', kind: 'company' }],
      affiliations: [...base.affiliations, { id: 'a-oc', person: 'p-2', npn: '11111111', entity: 'Other Corp', start: '2020-01-01', end: '2020-12-31', split: '100.00' }],
    }, null, 'OUTSIDE_COMPANY_ENTITY', /a-oc.*Other Corp/, ['Sam Seller', '11111111']],
    // The real register's shape (a house agency and a holding company) run against the holding company's database.
    ['house_register_into_the_holding_company', {
      ...base,
      entities: [...base.entities, { name: 'Holding Co', kind: 'company' }],
    }, { companySlug: 'holding_co', companyDisplayName: 'Holding Co', today: '2026-11-27' }, 'AMBIGUOUS_COMPANY_ENTITY', /house entity "Acme" does not match/, []],
    ['house_mark_not_boolean', {
      ...base,
      entities: [...base.entities, { name: 'Odd House', kind: 'agency', house: 'false' }],
    }, null, 'INVALID_ENTITY', /Odd House.*not true or false/, []],
    ['house_mark_on_a_lead_vendor', {
      ...base,
      entities: [...base.entities, { name: 'Vendor House', kind: 'lead_vendor', house: true }],
    }, null, 'INVALID_ENTITY', /Vendor House.*cannot be the house/, []],
    ['house_account_of_another_company', {
      ...base,
      entities: [...base.entities, { name: 'Other Corp', kind: 'company' }],
      people: [...base.people, { id: 'p-hoc', name: 'Other Corp house account', npn: null, emails: [], house: true, houseOf: 'Other Corp' }],
    }, null, 'OUTSIDE_COMPANY_ENTITY', /p-hoc.*Other Corp/, ['Other Corp house account']],
    ['website_login_of_someone_only_in_another_company', {
      ...base,
      entities: [...base.entities, { name: 'Other Corp', kind: 'company' }],
      people: [...base.people, { id: 'p-oc', name: 'Olive Outside', npn: null, emails: ['olive@other.example'] }],
      memberships: [...base.memberships, { id: 'm-oc2', person: 'p-oc', entity: 'Other Corp', role: 'OWNER', start: null, end: null }],
      website: [{ email: 'olive@other.example', person: 'p-oc', role: 'agent', status: 'disabled' }],
    }, null, 'MISSING_RELATIONSHIP', /p-oc/, ['Olive Outside']],
    ['multiple_entities_match_target_company', {
      ...base,
      entities: [...base.entities, { name: 'Acme Secondary', kind: 'company', slug: 'acme' }],
    }, null, 'AMBIGUOUS_COMPANY_ENTITY', /Multiple entities/, []],
    ['a_plain_agency_with_the_company_slug_never_matches_it', {
      ...base,
      entities: [...base.entities, { name: 'Acme Secondary', kind: 'agency', slug: 'acme' }],
    }, null, 'DUPLICATE_SLUG', /Acme Secondary.*acme/, []],
    ['matched_company_archived', {
      ...base,
      entities: [{ name: 'Acme', kind: 'agency', house: true, status: 'archived' }, ...base.entities.slice(1)],
    }, null, 'COMPANY_ENTITY_INACTIVE', /archived/, []],
    ['matched_company_ended', {
      ...base,
      entities: [{ name: 'Acme', kind: 'agency', house: true, start: '2020-01-01', end: '2025-12-31' }, ...base.entities.slice(1)],
    }, null, 'COMPANY_ENTITY_INACTIVE', /end date/, []],
    // Item 4: website entries grant nothing; active website owner/admin without matching catalog role refused.
    ['website_owner_without_matching_owner_role', {
      ...base,
      roles: base.roles.filter((r) => r.id !== 'r-0' && r.id !== 'r-1'),
      website: [{ email: 'pat@acme.example', person: 'p-1', role: 'owner', status: 'active' }],
    }, null, 'UNMATCHED_WEBSITE_ROLE', /website#1.*p-1/, ['Pat Owner']],
    ['website_owner_backed_only_by_npn_scoped_owner_role', {
      ...base,
      roles: [{ id: 'r-0', person: 'p-1', role: 'OWNER', scope: { npns: ['11111111'] } }, ...base.roles.filter((r) => r.id !== 'r-0' && r.id !== 'r-1')],
      website: [{ email: 'pat@acme.example', person: 'p-1', role: 'owner', status: 'active' }],
    }, null, 'UNMATCHED_WEBSITE_ROLE', /website#1.*p-1/, ['Pat Owner']],
    ['website_admin_without_matching_admin_role', {
      ...base,
      people: [...base.people, { id: 'p-adm', name: 'Sloan Unroled', npn: null, emails: ['sloan@acme.example'] }],
      memberships: [...base.memberships, { id: 'm-adm', person: 'p-adm', entity: 'Acme', role: 'EMPLOYEE', start: '2024-01-01', end: null }],
      website: [{ email: 'sloan@acme.example', person: 'p-adm', role: 'admin', status: 'active' }],
    }, null, 'UNMATCHED_WEBSITE_ROLE', /website#1.*p-adm/, ['Sloan Unroled']],
    ['website_owner_with_only_ended_owner_role', {
      ...base,
      roles: base.roles.filter((r) => r.id !== 'r-1').map((r) => (r.id === 'r-0' ? { ...r, start: '2023-01-01', end: '2024-12-31' } : r)),
      website: [{ email: 'pat@acme.example', person: 'p-1', role: 'owner', status: 'active' }],
    }, null, 'UNMATCHED_WEBSITE_ROLE', /website#1.*p-1/, ['Pat Owner']],
    // Item 5: dates, external_upline start > today, unresolved cycle, closed-only & future-only orgs.
    ['entity_end_without_start', {
      ...base,
      entities: [...base.entities, { name: 'BadEnd', kind: 'agency', end: '2024-12-31' }],
    }, null, 'INVALID_DATE', /BadEnd.*start date/, []],
    ['membership_end_without_start', {
      ...base,
      memberships: [...base.memberships, { id: 'm-nostart', person: 'p-1', entity: 'Beacon', role: 'EMPLOYEE', start: null, end: '2024-12-31' }],
    }, null, 'INVALID_DATE', /m-nostart.*p-1/, ['Pat Owner']],
    ['role_end_without_start', {
      ...base,
      roles: [...base.roles, { id: 'r-nostart', person: 'p-1', role: 'AGENCY_MANAGER', scope: { entities: ['Beacon'] }, start: null, end: '2024-12-31' }],
    }, null, 'INVALID_DATE', /r-nostart.*p-1/, ['Pat Owner']],
    ['external_upline_start_after_today', {
      ...base,
      entities: [...base.entities, { name: 'Future Upline', kind: 'external_upline', start: '2099-01-01' }],
    }, null, 'INVALID_EXTERNAL_UPLINE', /Future Upline.*after today/, []],
    ['unresolved_non_overlapping_cycle', {
      ...base,
      entities: [
        { name: 'Acme', kind: 'company' },
        {
          name: 'Cycle A',
          kind: 'agency',
          edges: [
            { parent: 'Cycle B', start: '2023-01-01', end: '2023-12-31' },
            { parent: 'Acme', start: '2024-01-01', end: null },
          ],
        },
        {
          name: 'Cycle B',
          kind: 'agency',
          edges: [
            { parent: 'Cycle A', start: '2024-01-01', end: '2024-12-31' },
            { parent: 'Acme', start: '2025-01-01', end: null },
          ],
        },
      ],
      people: [{ id: 'p-1', name: 'Pat Owner', npn: null, emails: [] }],
      affiliations: [],
      memberships: [{ id: 'm-1', person: 'p-1', entity: 'Acme', role: 'OWNER', start: '2023-01-01', end: null }],
      roles: [],
    }, null, 'ORG_HIERARCHY_CYCLE', /Cycle A|Cycle B/, []],
    ['closed_only_active_org', {
      ...base,
      entities: [...base.entities, { name: 'Closed Only', kind: 'agency', start: '2023-01-01', end: '2024-12-31' }],
    }, null, 'UNSUPPORTED_ORG_LIFECYCLE', /Closed Only/, []],
    ['closed_only_archived_org', {
      ...base,
      entities: [...base.entities, { name: 'Closed Archived', kind: 'agency', status: 'archived', start: '2023-01-01', end: '2024-12-31' }],
    }, null, 'UNSUPPORTED_ORG_LIFECYCLE', /Closed Archived/, []],
    ['future_only_org', {
      ...base,
      entities: [...base.entities, { name: 'Future Agency', kind: 'agency', start: '2099-01-01', end: null }],
    }, null, 'UNSUPPORTED_ORG_LIFECYCLE', /Future Agency/, []],
    ['active_child_under_archived_parent', {
      ...base,
      entities: [
        ...base.entities,
        { name: 'Archived Parent', kind: 'agency', status: 'archived', start: '2023-01-01' },
        { name: 'Active Child', kind: 'team', parent: 'Archived Parent', status: 'active', start: '2024-01-01' },
      ],
    }, null, 'UNSUPPORTED_ORG_LIFECYCLE', /Active Child.*Archived Parent/, []],
    // Item 8: --vendor-mask unknown / non-lead-vendor & --plan without --company-slug when unclear.
    ['vendor_mask_unknown_entity', base, { ...baseOpts, vendorMasks: new Map([['Ghost Leads', 'V99']]) }, 'UNKNOWN_VENDOR_MASK', /Ghost Leads/, []],
    ['vendor_mask_non_lead_vendor', base, { ...baseOpts, vendorMasks: new Map([['Beacon', 'V99']]) }, 'INVALID_VENDOR_MASK', /Beacon/, []],
    ['plan_without_company_slug_no_candidates', {
      ...base,
      entities: [{ name: 'Beacon', kind: 'agency' }, { name: 'Harbor', kind: 'agency' }],
      people: [{ id: 'p-2', name: 'Sam Seller', npn: '11111111', emails: [] }],
      affiliations: [{ id: 'a-1', person: 'p-2', npn: '11111111', entity: 'Beacon', start: '2024-01-01', end: null, split: '80.00' }],
      memberships: [],
      roles: [],
    }, { companySlug: null, today: '2026-11-27' }, 'AMBIGUOUS_COMPANY_ENTITY', /--company-slug/, []],
    ['plan_without_company_slug_multiple_candidates', {
      ...base,
      entities: [{ name: 'Acme', kind: 'company' }, { name: 'OtherHouse', kind: 'agency', house: true }],
      people: [{ id: 'p-1', name: 'Pat Owner', npn: null, emails: [] }],
      affiliations: [],
      memberships: [{ id: 'm-1', person: 'p-1', entity: 'Acme', role: 'OWNER', start: '2023-01-01', end: null }],
      roles: [],
    }, { companySlug: null, today: '2026-11-27' }, 'AMBIGUOUS_COMPANY_ENTITY', /multiple/i, []],
    // Core owner-ruling & register refusals (verifying ID-only error messages too).
    ['orphan_person_no_relationship', {
      ...base,
      people: [...base.people, { id: 'p-orphan', name: 'Orphan Person', npn: null, emails: [] }],
    }, null, 'MISSING_RELATIONSHIP', /p-orphan/, ['Orphan Person']],
    ['duplicate_npn', {
      ...base,
      people: [...base.people, { id: 'p-dupnpn', name: 'Twin Agent', npn: '11111111', emails: [] }],
      memberships: [...base.memberships, { id: 'm-dupnpn', person: 'p-dupnpn', entity: 'Beacon', role: 'EMPLOYEE', start: '2024-01-01', end: null }],
    }, null, 'DUPLICATE_NPN', /p-2.*p-dupnpn/, ['Twin Agent', 'Sam Seller', '11111111']],
    ['unknown_entity_parent', {
      ...base,
      entities: [...base.entities, { name: 'Bad Team', kind: 'team', parent: 'Ghost Agency' }],
    }, null, 'UNKNOWN_ENTITY', /Ghost Agency/, []],
    ['unknown_entity_membership', {
      ...base,
      memberships: [...base.memberships, { id: 'm-ghost', person: 'p-1', entity: 'Ghost Agency', role: 'EMPLOYEE', start: '2024-01-01', end: null }],
    }, null, 'UNKNOWN_ENTITY', /m-ghost.*p-1.*Ghost Agency/, ['Pat Owner']],
    ['unknown_entity_affiliation', {
      ...base,
      affiliations: [...base.affiliations, { id: 'a-ghost', person: 'p-2', npn: '11111111', entity: 'Ghost Agency', start: '2023-01-01', end: '2023-12-31', split: '70.00' }],
    }, null, 'UNKNOWN_ENTITY', /a-ghost.*p-2.*Ghost Agency/, ['Sam Seller', '11111111']],
    ['unknown_entity_role_scope', {
      ...base,
      roles: [...base.roles, { id: 'r-ghost', person: 'p-1', role: 'AGENCY_MANAGER', scope: { entities: ['Ghost Agency'] } }],
    }, null, 'UNKNOWN_ENTITY', /r-ghost.*p-1.*Ghost Agency/, ['Pat Owner']],
    ['ambiguous_legacy_manager_role', {
      ...base,
      roles: [...base.roles, { id: 'r-mgr', person: 'p-1', role: 'MANAGER', scope: null }],
    }, null, 'AMBIGUOUS_ROLE', /r-mgr.*p-1.*MANAGER/, ['Pat Owner']],
    ['unknown_role_kind', {
      ...base,
      roles: [...base.roles, { id: 'r-weird', person: 'p-1', role: 'SUPER_BOSS', scope: 'all' }],
    }, null, 'UNKNOWN_ROLE', /r-weird.*p-1.*SUPER_BOSS/, ['Pat Owner']],
    ['compliance_without_npns', {
      ...base,
      roles: [...base.roles, { id: 'r-comp-wide', person: 'p-1', role: 'COMPLIANCE', scope: { entities: ['Beacon'] } }],
    }, null, 'COMPLIANCE_REQUIRES_NPNS', /r-comp-wide.*p-1/, ['Pat Owner']],
    ['selling_agent_non_self_npn', {
      ...base,
      roles: [...base.roles, { id: 'r-self-bad', person: 'p-2', role: 'SELLING_AGENT', scope: { entities: ['Beacon'], npns: ['22222222'] } }],
    }, null, 'AGENT_GRANT_SELF_ONLY', /r-self-bad.*p-2/, ['Sam Seller', '22222222']],
    ['retention_agent_scope_all', {
      ...base,
      roles: [...base.roles, { id: 'r-ret-all', person: 'p-1', role: 'RETENTION_AGENT', scope: 'all' }],
    }, null, 'AGENT_GRANT_SELF_ONLY', /r-ret-all.*p-1/, ['Pat Owner']],
    ['lead_vendor_missing_masked_name', {
      ...base,
      entities: [...base.entities, { name: 'Quartz Leads', kind: 'lead_vendor' }],
    }, null, 'MISSING_VENDOR_MASKED_NAME', /Quartz Leads/, []],
    ['lead_vendor_cannot_have_child', {
      ...base,
      entities: [...base.entities, { name: 'Under Vendor', kind: 'team', parent: 'Cobalt Leads' }],
    }, null, 'LEAD_VENDOR_IS_LEAF', /Under Vendor.*Cobalt Leads/, []],
    ['team_under_another_company', {
      ...base,
      entities: [...base.entities, { name: 'Other Corp', kind: 'company' }, { name: 'Other Team', kind: 'team', parent: 'Other Corp' }],
    }, null, 'OUTSIDE_COMPANY_ENTITY', /Other Team.*Other Corp/, []],
    ['role_on_another_company', {
      ...base,
      entities: [...base.entities, { name: 'Other Corp', kind: 'company' }],
      roles: [...base.roles, { id: 'r-oc', person: 'p-1', role: 'AGENCY_MANAGER', scope: { entities: ['Other Corp'] } }],
    }, null, 'OUTSIDE_COMPANY_ENTITY', /r-oc.*Other Corp/, ['Pat Owner']],
    ['org_hierarchy_cycle', {
      ...base,
      entities: [
        { name: 'Acme', kind: 'company' },
        { name: 'Loop A', kind: 'agency', parent: 'Loop B' },
        { name: 'Loop B', kind: 'agency', parent: 'Loop A' },
      ],
      affiliations: [],
      people: [{ id: 'p-1', name: 'Pat Owner', npn: null, emails: [] }],
      roles: [],
    }, null, 'ORG_HIERARCHY_CYCLE', /Loop A|Loop B/, []],
    ['overlapping_affiliations', {
      ...base,
      affiliations: [
        { id: 'a-ov1', person: 'p-2', npn: '11111111', entity: 'Beacon', start: '2024-01-01', end: '2024-06-30', split: '80.00' },
        { id: 'a-ov2', person: 'p-2', npn: '11111111', entity: 'Harbor', start: '2024-06-30', end: null, split: '80.00' },
      ],
    }, null, 'OVERLAPPING_AFFILIATION', /a-ov1.*a-ov2.*p-2/, ['Sam Seller', '11111111']],
    ['conflicting_membership_arrangement', {
      ...base,
      memberships: [
        { id: 'm-c1', person: 'p-1', entity: 'Acme', role: 'EMPLOYEE', workArrangement: 'employee', start: '2024-01-01', end: null },
        { id: 'm-c2', person: 'p-1', entity: 'Acme', role: 'CONSULTANT', workArrangement: 'self_employed_external', start: '2024-06-01', end: null },
      ],
    }, null, 'CONFLICTING_MEMBERSHIP_ARRANGEMENT', /m-c1.*m-c2.*p-1/, ['Pat Owner']],
    ['year_9999_date', {
      ...base,
      affiliations: [
        { id: 'a-9999', person: 'p-2', npn: '11111111', entity: 'Beacon', start: '2024-01-01', end: '9999-12-31', split: '80.00' },
      ],
    }, null, 'INVALID_DATE', /a-9999.*p-2/, ['Sam Seller', '11111111']],
    ['year_0000_date', {
      ...base,
      memberships: [
        { id: 'm-0000', person: 'p-1', entity: 'Acme', role: 'OWNER', start: '0000-01-01', end: null },
      ],
    }, null, 'INVALID_DATE', /m-0000.*p-1/, ['Pat Owner']],
    ['backwards_date', {
      ...base,
      memberships: [
        { id: 'm-back', person: 'p-1', entity: 'Acme', role: 'OWNER', start: '2025-05-01', end: '2025-04-01' },
      ],
    }, null, 'BACKWARDS_DATE_RANGE', /m-back.*p-1/, ['Pat Owner']],
  ];

  for (const [label, badDoc, optsOverride, expectedCode, msgRe, forbidden] of cases) {
    assert.throws(
      () => planAgentRegisterImport(badDoc, optsOverride || baseOpts),
      (err) => {
        assert.ok(err instanceof RegisterValidationError, `${label}: expected RegisterValidationError`);
        assert.ok(
          err.issues.some((it) => it.code === expectedCode && msgRe.test(it.message)),
          `${label}: expected issue code=${expectedCode} matching ${msgRe}, got ${JSON.stringify(err.issues)}`,
        );
        // Item 7: thrown error messages and issue.message carry ONLY IDs, never names or NPNs.
        for (const secret of forbidden) {
          assert.ok(!err.message.includes(secret), `${label}: thrown err.message must not leak "${secret}": ${err.message}`);
          for (const it of err.issues) {
            assert.ok(!it.message.includes(secret), `${label}: issue.message must not leak "${secret}": ${it.message}`);
          }
        }
        return true;
      },
      `must refuse ${label}`,
    );
  }

  // Multi-issue collection + CLI stderr refusal output (ID-only error text, structured fields in CLI JSON).
  const multiBad = {
    ...base,
    people: [
      ...base.people,
      { id: 'p-bad-a', name: 'Missing Rel One', npn: '11111111', emails: [] },
      { id: 'p-bad-b', name: 'Missing Rel Two', npn: null, emails: [] },
    ],
    roles: [
      ...base.roles,
      { id: 'r-bad-b', person: 'p-bad-b', role: 'AGENCY_MANAGER', scope: { entities: ['Nonexistent Agency'] } },
    ],
  };
  const tmpDir = await mkdtemp(join(tmpdir(), 'coherence-regbad-'));
  t.after(() => rm(tmpDir, { recursive: true, force: true }));
  const badPath = join(tmpDir, 'bad.json');
  await writeFile(badPath, JSON.stringify(multiBad, null, 2), 'utf8');
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI_PATH, '--register', badPath, '--plan', '--company-slug', 'acme']),
    (err) => {
      const body = JSON.parse(err.stderr);
      assert.equal(body.ok, false);
      assert.ok(!body.error.includes('Missing Rel One'), 'stderr top-level error must not contain names');
      assert.ok(!body.error.includes('Missing Rel Two'), 'stderr top-level error must not contain names');
      assert.ok(!body.error.includes('11111111'), 'stderr top-level error must not contain NPNs');
      assert.ok(body.issues.some((i) => i.code === 'DUPLICATE_NPN' && i.npn === '11111111'));
      assert.ok(body.issues.some((i) => i.code === 'UNKNOWN_ENTITY' && i.rowId === 'r-bad-b'));
      assert.ok(body.issues.some((i) => i.code === 'MISSING_RELATIONSHIP' && i.personId === 'p-bad-b'));
      return true;
    },
  );
});

test('Agent Register Import [Fresh Import, Live E1-E5 & House-Agency RLS, Single-Tx Rollback, Re-imports, Org/Person Conflicts & Wrong-Company Refusal]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const ctx = await provisionScratchCompany(t, { companySlug: 'acme', displayName: 'Acme', environment: 'dev' });
  const reg = makeApprovedSyntheticRegister();
  const regPath = join(ctx.workDir, 'approved-v1.json');
  await writeFile(regPath, `${JSON.stringify(reg, null, 2)}\n`, 'utf8');
  const regHashBefore = sha256Hex(await readFile(regPath));

  // P1 guards: refuse forbidden DBs, prod endpoints in dev, wrong key scope, and read-only nusear_admin.
  const countsBeforeAll = await snapshotIamAndAuditCounts(ctx.pool);
  await assert.rejects(
    () => execFileAsync(process.execPath, [
      CLI_PATH, '--register', regPath, '--database', 'nusear_control',
      '--key-file', ctx.staffKeyFile, '--actor-email', 'owner@nusear.example',
    ]),
    (err) => /FORBIDDEN_TARGET_DATABASE/.test(err.stderr),
  );
  await assert.rejects(
    () => execFileAsync(process.execPath, [
      CLI_PATH, '--register', regPath, '--database', ctx.db.dbName,
      '--host', 'prod-db.internal', '--key-file', ctx.staffKeyFile, '--actor-email', 'owner@nusear.example',
    ]),
    (err) => /PRODUCTION_TARGET_REFUSED/.test(err.stderr),
  );
  await assert.rejects(
    () => importAgentRegisterIntoDatabase({
      readPool: ctx.readPool,
      appPool: ctx.appPool,
      registerPath: regPath,
      vendorMasks: new Map([['Cobalt Leads', 'Vendor Alpha']]),
      keyFile: ctx.svcKeyFile,
      actorEmail: 'owner@nusear.example',
    }),
    (err) => err?.code === 'INVALID_KEY_SCOPE',
  );
  await assert.rejects(
    () => importAgentRegisterIntoDatabase({
      readPool: ctx.readPool,
      appPool: ctx.appPool,
      registerPath: regPath,
      vendorMasks: new Map([['Cobalt Leads', 'Vendor Alpha']]),
      keyFile: ctx.staffKeyFile,
      actorEmail: 'admin@nusear.example',
    }),
    (err) => err?.status === 403 && err?.code === 'FORBIDDEN',
    'read-only nusear_admin must be refused before any write',
  );
  assert.deepEqual(await snapshotIamAndAuditCounts(ctx.pool), countsBeforeAll, 'refused imports must write zero rows');

  // Item 3: All-or-nothing single SERIALIZABLE transaction rollback test!
  // Let the first 4 app_cmd.iam_* writes execute inside the tx, then fail inside PG on the 5th.
  let interceptedWrites = 0;
  let writeTxBegins = 0;
  let writeTxRollbacks = 0;
  const failingAppPool = {
    query: (...a) => ctx.appPool.query(...a),
    end: () => Promise.resolve(),
    connect: async () => {
      const inner = await ctx.appPool.connect();
      return {
        release: (...a) => inner.release(...a),
        query: async (sql, params) => {
          const text = String(sql);
          if (/^BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE/i.test(text)) writeTxBegins += 1;
          if (/^ROLLBACK/i.test(text)) writeTxRollbacks += 1;
          if (text.includes('app_cmd.iam_')) {
            interceptedWrites += 1;
            if (interceptedWrites === 5) {
              return inner.query('SELECT 1 / 0');
            }
          }
          return inner.query(sql, params);
        },
      };
    },
  };
  await assert.rejects(
    () => importAgentRegisterIntoDatabase({
      readPool: ctx.readPool,
      appPool: failingAppPool,
      registerPath: regPath,
      vendorMasks: new Map([['Cobalt Leads', 'Vendor Alpha']]),
      keyFile: ctx.staffKeyFile,
      actorEmail: 'owner@nusear.example',
    }),
    (err) => err?.status >= 400,
    'mid-import DB error must reject',
  );
  assert.equal(interceptedWrites, 5, '4 writes executed inside tx before failure on 5th');
  assert.equal(writeTxBegins, 1, 'all writes ran inside one SERIALIZABLE write tx');
  assert.equal(writeTxRollbacks, 1, 'failed write tx rolled back cleanly');
  assert.deepEqual(
    await snapshotIamAndAuditCounts(ctx.pool),
    countsBeforeAll,
    'failed import must leave ZERO rows and ZERO audit_journal entries',
  );

  // 1. Fresh import via CLI after rollback succeeds cleanly (retry meets zero half-made state).
  const auditBefore = countsBeforeAll['platform.audit_journal'];
  const run1 = await execFileAsync(process.execPath, [
    CLI_PATH,
    '--register', regPath,
    '--database', ctx.db.dbName,
    '--key-file', ctx.staffKeyFile,
    '--actor-email', 'owner@nusear.example',
    '--app-role', 'platform_app',
    '--readonly-role', 'platform_readonly',
    '--vendor-mask', 'Cobalt Leads=Vendor Alpha',
  ], { env: { ...process.env } });
  const res1 = JSON.parse(run1.stdout);
  assert.equal(res1.changed, true);
  assert.equal(res1.companySlug, 'acme');
  assert.equal(res1.created.organizations, 8);
  assert.equal(res1.created.people, 21);
  assert.equal(res1.created.affiliations, 7);
  assert.equal(res1.created.personStatusChanges, 1);
  assert.equal(sha256Hex(await readFile(regPath)), regHashBefore, 'source export file must never be modified');

  // Item 7: apply output gives skippedOutside people by ID only and contains ZERO names or NPNs!
  assert.deepEqual(res1.skippedOutside.people, ['p-0018']);
  const applyJson = JSON.stringify(res1);
  for (const personal of ['Pat Owner', 'Sam Seller', 'Nusear Staff Only', 'Skyler HouseAgent', '11111111', '22222222', '99990001']) {
    assert.ok(!applyJson.includes(personal), `apply output must not contain personal data "${personal}"`);
  }

  // Item 6: every audit_journal command_key includes the export's sha256 prefix & runs as nusear_support.
  const expectedShaPrefix = res1.sourceSha256.slice(0, 16);
  const importAuditRows = (await ctx.pool.query(
    `SELECT command_kind, command_key, recorded_as
     FROM platform.audit_journal
     WHERE seq > $1
     ORDER BY seq`,
    [auditBefore],
  )).rows;
  assert.ok(importAuditRows.length > 0);
  for (const row of importAuditRows) {
    assert.ok(row.command_kind.startsWith('iam.'), `unexpected command_kind ${row.command_kind}`);
    assert.equal(row.recorded_as, 'nusear_support', 'every import write must be recorded_as nusear_support');
    assert.ok(
      row.command_key.includes(expectedShaPrefix),
      `command_key "${row.command_key}" must include export sha256 prefix "${expectedShaPrefix}"`,
    );
  }

  // Live PostgreSQL IAM catalog invariants stay 100% green after import.
  const inv = await verifyIamConfigInvariants(ctx.pool);
  assert.equal(inv.passed, true, `IAM invariants failed: ${inv.problems.join('; ')}`);

  // 2. Live RLS & E1..E5 role behavior checks, including real statement lines on Acme vs Beacon!
  const staffOwnerTok = await mintStaffTokenFromKeyFile(ctx.readPool, ctx.staffKeyFile, 'owner@nusear.example', 'dev');
  const memStores = createStorePair({
    codeStore: createCodeStore({ backend: createMemoryObjectStore({ label: 'rls-c' }) }),
    dataStore: createDataStore({ backend: createMemoryObjectStore({ label: 'rls-d' }) }),
  });
  const appCmd = createAppCommands({ pool: ctx.appPool, stores: memStores });
  await appCmd.initCompany({
    dbToken: staffOwnerTok, commandKey: 'rls-init-acme', slug: 'acme', displayName: 'Acme', defaultEmitMode: 'coherence',
  });
  await appCmd.recordStatementBatch({
    dbToken: staffOwnerTok,
    commandKey: 'rls-house-vs-sibling-batch',
    batchKind: 'historical_sent',
    statementDate: '2026-04-30',
    sourceFileName: 'rls_check.csv',
    reason: 'Live RLS isolation check across Acme house agency and Beacon sibling agency',
    agencyLines: [
      { lineNo: 1, entity: 'Acme', writingNpn: '22222222', writingAgent: 'Skyler HouseAgent', recordId: 'ca|direct|NM:h,1|100.00|2026-04', carrier: 'carrier_a', mbi: '1AB2CD3EF41', member: 'House Member', grossComm: '100.00', amount: '100.00' },
      { lineNo: 2, entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller', recordId: 'ca|direct|NM:b,1|100.00|2026-04', carrier: 'carrier_a', mbi: '1AB2CD3EF42', member: 'Beacon Member', grossComm: '100.00', amount: '80.00' },
      { lineNo: 3, entity: 'Harbor', writingNpn: '33333333', writingAgent: 'Robin Harbor', recordId: 'ca|direct|NM:r,1|100.00|2026-04', carrier: 'carrier_a', mbi: '1AB2CD3EF43', member: 'Harbor Member', grossComm: '100.00', amount: '75.00' },
    ],
    uplineLines: [],
  });

  const localKey = await seedCompanyLocalKey(ctx.pool, 'dev');

  // Owner (scope: "all") sees full org tree (including depth-3 East Pod) AND real lead vendor name.
  await withRequestTx(ctx.appPool, localKey.tokenFor(res1.personIds['p-0001']), async (tx) => {
    const wide = (await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
    assert.ok(wide.includes(res1.orgIds['East Pod']), 'owner must reach depth-3 team East Pod');
    assert.ok(wide.includes(res1.orgIds.SubCo), 'owner must reach child company SubCo');
    const stmts = (await tx.query('SELECT entity FROM app_views.coherence_statement_agency_lines ORDER BY entity')).rows.map((r) => r.entity);
    assert.deepEqual(stmts, ['Acme', 'Beacon', 'Harbor']);
    const vendors = (await tx.query("SELECT display_name, masked_display_name, is_vendor_name_masked FROM app_views.iam_organizations WHERE org_kind = 'lead_vendor'")).rows;
    assert.deepEqual(vendors, [{ display_name: 'Cobalt Leads', masked_display_name: 'Vendor Alpha', is_vendor_name_masked: false }]);
  }, { readOnly: true });

  // Item 1 Live RLS: House-agency AGENCY_MANAGER (p-0019, scope: { entities: ['Acme'] }) sees ONLY Acme, NEVER sibling Beacon or Harbor!
  await withRequestTx(ctx.appPool, localKey.tokenFor(res1.personIds['p-0019']), async (tx) => {
    const wide = (await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
    assert.deepEqual(wide, [ctx.prov.iam.companyOrgId], 'house-agency agency_manager must see ONLY Acme, never sibling agencies');
    const stmts = (await tx.query('SELECT entity FROM app_views.coherence_statement_agency_lines')).rows.map((r) => r.entity);
    assert.deepEqual(stmts, ['Acme'], 'house-agency agency_manager must NOT read Beacon or Harbor statement lines');
  }, { readOnly: true });

  // Item 1 Live RLS: House-agency SELLING_AGENT (p-0020, scope: { entities: ['Acme'], npns: ['22222222'] }) sees ONLY (Acme, self), NEVER sibling agencies!
  await withRequestTx(ctx.appPool, localKey.tokenFor(res1.personIds['p-0020']), async (tx) => {
    assert.deepEqual((await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, []);
    const narrow = (await tx.query("SELECT org_id, person_id FROM iam.effective_narrow_pairs('act:coherence.bob.read')")).rows;
    assert.deepEqual(narrow, [{ org_id: ctx.prov.iam.companyOrgId, person_id: res1.personIds['p-0020'] }], 'house-agency selling_agent must NOT descend into sibling agencies');
    assert.equal((await tx.query("SELECT iam.has_right('col:coherence.statement_cash') AS ok")).rows[0].ok, false);
  }, { readOnly: true });

  // Item 1 Live RLS: House-agency RETENTION_AGENT (p-0021) sees ONLY (Acme, self), NEVER sibling agencies!
  await withRequestTx(ctx.appPool, localKey.tokenFor(res1.personIds['p-0021']), async (tx) => {
    assert.deepEqual((await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, []);
    const narrow = (await tx.query("SELECT org_id, person_id FROM iam.effective_narrow_pairs('act:coherence.bob.read')")).rows;
    assert.deepEqual(narrow, [{ org_id: ctx.prov.iam.companyOrgId, person_id: res1.personIds['p-0021'] }]);
  }, { readOnly: true });

  // Item 1 Live RLS: House-agency-scoped COMPLIANCE (p-0022, entities: ['Acme'], npns: ['11111111', '22222222']) sees ONLY Acme, NOT Beacon!
  await withRequestTx(ctx.appPool, localKey.tokenFor(res1.personIds['p-0022']), async (tx) => {
    const narrow = (await tx.query("SELECT DISTINCT org_id FROM iam.effective_narrow_pairs('act:coherence.statements.read')")).rows.map((r) => r.org_id);
    assert.deepEqual(narrow, [ctx.prov.iam.companyOrgId], 'house-agency-scoped compliance must NOT descend into Beacon');
    const stmts = (await tx.query('SELECT entity, writing_npn FROM app_views.coherence_statement_agency_lines')).rows;
    assert.deepEqual(stmts, [{ entity: 'Acme', writing_npn: '22222222' }], 'house-agency-scoped compliance must NOT read Beacon lines for 11111111');
  }, { readOnly: true });

  // Explicit-entity Agency Manager (p-0004, scope: { entities: ['Beacon'] }) sees Beacon ALONE (not East Team, East Pod, or Harbor), masked vendor ONLY.
  await withRequestTx(ctx.appPool, localKey.tokenFor(res1.personIds['p-0004']), async (tx) => {
    const wide = (await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
    assert.deepEqual(wide, [res1.orgIds.Beacon], 'explicit-entity Beacon agency_manager covers Beacon alone');
    assert.equal((await tx.query("SELECT iam.has_right('col:coherence.statement_cash') AS ok")).rows[0].ok, true);
    const vendors = (await tx.query("SELECT slug, display_name, masked_display_name, external_domain, is_vendor_name_masked FROM app_views.iam_organizations WHERE org_kind = 'lead_vendor'")).rows;
    assert.deepEqual(vendors, [{ slug: null, display_name: 'Vendor Alpha', masked_display_name: 'Vendor Alpha', external_domain: null, is_vendor_name_masked: true }]);
  }, { readOnly: true });

  // Selling Agent (11111111) sees strictly (Beacon, self), zero company revenue, own-pay right.
  await withRequestTx(ctx.appPool, localKey.tokenFor(res1.personIds['p-0005']), async (tx) => {
    assert.deepEqual((await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, []);
    const narrow = (await tx.query("SELECT org_id, person_id FROM iam.effective_narrow_pairs('act:coherence.bob.read')")).rows;
    assert.deepEqual(narrow, [{ org_id: res1.orgIds.Beacon, person_id: res1.personIds['p-0005'] }]);
    assert.equal((await tx.query("SELECT iam.has_right('col:coherence.statement_cash') AS ok")).rows[0].ok, false);
    assert.equal((await tx.query("SELECT iam.has_right('act:payroll.agent_pay.read') AS ok")).rows[0].ok, true);
  }, { readOnly: true });

  // Retention Agent (31313131) sees strictly self at Harbor, zero company revenue.
  await withRequestTx(ctx.appPool, localKey.tokenFor(res1.personIds['p-0008']), async (tx) => {
    assert.deepEqual((await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, []);
    assert.deepEqual((await tx.query("SELECT org_id, person_id FROM iam.effective_narrow_pairs('act:coherence.bob.read')")).rows, [
      { org_id: res1.orgIds.Harbor, person_id: res1.personIds['p-0008'] },
    ]);
    assert.equal((await tx.query("SELECT iam.has_right('col:coherence.statement_cash') AS ok")).rows[0].ok, false);
  }, { readOnly: true });

  // Entity-less Compliance (p-0009, scope: { npns: ['11111111', '33333333'] }) sees strictly [11111111, 33333333] across agencies, NOT 44444444 or 22222222.
  await withRequestTx(ctx.appPool, localKey.tokenFor(res1.personIds['p-0009']), async (tx) => {
    assert.deepEqual((await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, []);
    const subjects = (await tx.query("SELECT iam.effective_narrow_person_ids('act:coherence.bob.read') AS v")).rows[0].v.sort();
    assert.deepEqual(subjects, [res1.personIds['p-0005'], res1.personIds['p-0006']].sort());
    const stmts = (await tx.query('SELECT entity, writing_npn FROM app_views.coherence_statement_agency_lines ORDER BY entity')).rows;
    assert.deepEqual(stmts, [
      { entity: 'Beacon', writing_npn: '11111111' },
      { entity: 'Harbor', writing_npn: '33333333' },
    ]);
    assert.equal((await tx.query("SELECT iam.has_right('col:coherence.statement_cash') AS ok")).rows[0].ok, false);
  }, { readOnly: true });

  // Investor holds empty built-in role (zero rights by default).
  await withRequestTx(ctx.appPool, localKey.tokenFor(res1.personIds['p-0010']), async (tx) => {
    assert.equal((await tx.query("SELECT iam.has_right('act:coherence.bob.read') AS ok")).rows[0].ok, false);
  }, { readOnly: true });

  // Suspended agent fails closed.
  await withRequestTx(ctx.appPool, localKey.tokenFor(res1.personIds['p-0017']), async (tx) => {
    assert.equal((await tx.query('SELECT actor_person_id FROM iam.session_context()')).rows[0].actor_person_id, null);
  }, { readOnly: true });

  // House account has person_kind='house_account', house_org_id=companyOrgId, and its NPN preserved.
  const houseRow = (await ctx.pool.query(
    `SELECT p.person_kind, p.house_org_id, pv.npn
     FROM iam.people p
     JOIN iam.person_versions pv ON pv.person_id = p.id AND pv.superseded_by_id IS NULL
     WHERE p.id = $1::uuid`,
    [res1.personIds['p-0016']],
  )).rows[0];
  assert.deepEqual(houseRow, {
    person_kind: 'house_account',
    house_org_id: ctx.prov.iam.companyOrgId,
    npn: '99990001',
  });

  // 3. Idempotent reruns: same actor (CLI) AND different staff actor (API) change NOTHING.
  const countsAfterRun1 = await snapshotIamAndAuditCounts(ctx.pool);
  const run2 = await execFileAsync(process.execPath, [
    CLI_PATH,
    '--register', regPath,
    '--database', ctx.db.dbName,
    '--key-file', ctx.staffKeyFile,
    '--actor-email', 'owner@nusear.example',
    '--app-role', 'platform_app',
    '--readonly-role', 'platform_readonly',
    '--vendor-mask', 'Cobalt Leads=Vendor Alpha',
  ], { env: { ...process.env } });
  const res2 = JSON.parse(run2.stdout);
  assert.equal(res2.changed, false);
  assert.match(res2.message, /no changes needed/i);
  assert.deepEqual(await snapshotIamAndAuditCounts(ctx.pool), countsAfterRun1, 'second CLI run must add zero rows');

  const res3 = await importAgentRegisterIntoDatabase({
    readPool: ctx.readPool,
    appPool: ctx.appPool,
    registerPath: regPath,
    vendorMasks: new Map([['Cobalt Leads', 'Vendor Alpha']]),
    keyFile: ctx.staffKeyFile,
    actorEmail: 'support@nusear.example',
  });
  assert.equal(res3.changed, false);
  assert.deepEqual(await snapshotIamAndAuditCounts(ctx.pool), countsAfterRun1, 'rerun by a different nusear_staff actor must add zero rows');

  // 4. DB conflict refusals (with Item 7 ID-only error checks & Item 8 org slug/external_domain/root checks).
  // 4a. Duplicate NPN against existing DB company_local person -> DUPLICATE_NPN_IN_DB (no name/NPN in message!).
  const collidingReg = {
    ...reg,
    people: [
      ...reg.people.filter((p) => p.id !== 'p-0005'),
      { id: 'p-9999', name: 'Different Id Same NPN', npn: '11111111', emails: ['other@beacon.example'] },
    ],
    affiliations: reg.affiliations.map((a) => (a.person === 'p-0005' ? { ...a, person: 'p-9999' } : a)),
    roles: reg.roles.map((r) => (r.person === 'p-0005' ? { ...r, person: 'p-9999' } : r)),
  };
  await assert.rejects(
    () => importAgentRegisterIntoDatabase({
      readPool: ctx.readPool,
      appPool: ctx.appPool,
      registerDoc: collidingReg,
      vendorMasks: new Map([['Cobalt Leads', 'Vendor Alpha']]),
      keyFile: ctx.staffKeyFile,
      actorEmail: 'owner@nusear.example',
    }),
    (err) => {
      assert.equal(err?.code, 'DUPLICATE_NPN_IN_DB');
      assert.ok(err.message.includes('p-9999'));
      assert.ok(!err.message.includes('Different Id Same NPN'), 'error message must not leak person name');
      assert.ok(!err.message.includes('Sam Seller'), 'error message must not leak existing person name');
      assert.ok(!err.message.includes('11111111'), 'error message must not leak NPN');
      return true;
    },
  );

  // 4b. Item 8: diffOrganizations refuses external_domain mismatch and slug mismatch.
  const changedDomainReg = {
    ...reg,
    entities: reg.entities.map((e) => (e.name === 'Cobalt Leads' ? { ...e, externalDomain: 'different.example' } : e)),
  };
  await assert.rejects(
    () => importAgentRegisterIntoDatabase({
      readPool: ctx.readPool,
      appPool: ctx.appPool,
      registerDoc: changedDomainReg,
      vendorMasks: new Map([['Cobalt Leads', 'Vendor Alpha']]),
      keyFile: ctx.staffKeyFile,
      actorEmail: 'owner@nusear.example',
    }),
    (err) => err?.code === 'ORG_CONFLICT' && /external_domain/.test(err.message),
    'diffOrganizations must refuse external_domain conflict',
  );
  const changedSlugReg = {
    ...reg,
    entities: reg.entities.map((e) => (e.name === 'Beacon' ? { ...e, slug: 'beacon_alt' } : e)),
  };
  await assert.rejects(
    () => importAgentRegisterIntoDatabase({
      readPool: ctx.readPool,
      appPool: ctx.appPool,
      registerDoc: changedSlugReg,
      vendorMasks: new Map([['Cobalt Leads', 'Vendor Alpha']]),
      keyFile: ctx.staffKeyFile,
      actorEmail: 'owner@nusear.example',
    }),
    (err) => err?.code === 'ORG_CONFLICT' && /slug/.test(err.message),
    'diffOrganizations must refuse slug conflict',
  );
  // 4b2. A role removed or downgraded in a newer approved version is refused, never left live (round 2's blocker).
  const removedRoleReg = { ...reg, revision: 13, roles: reg.roles.filter((r) => r.id !== 'r-0005') };
  const downgradedReg = {
    ...reg,
    revision: 13,
    roles: reg.roles.map((r) => (r.id === 'r-0004' ? { ...r, role: 'AGENCY_MANAGER', scope: { entities: ['Beacon'] } } : r)),
    website: reg.website.map((w) => (w.person === 'p-0003' ? { ...w, role: 'manager' } : w)),
  };
  for (const [label, doc] of [['removed', removedRoleReg], ['downgraded', downgradedReg]]) {
    await assert.rejects(
      () => importAgentRegisterIntoDatabase({
        readPool: ctx.readPool,
        appPool: ctx.appPool,
        registerDoc: doc,
        vendorMasks: new Map([['Cobalt Leads', 'Vendor Alpha']]),
        keyFile: ctx.staffKeyFile,
        actorEmail: 'owner@nusear.example',
      }),
      (err) => err?.code === 'ROLE_GRANT_CONFLICT' && /not in this register version/.test(err.message),
      `a ${label} role must be refused while its grant is live`,
    );
  }
  assert.deepEqual(await snapshotIamAndAuditCounts(ctx.pool), countsAfterRun1, 'stale-grant refusals must write zero rows');

  // 4c. Item 8: diffOrganizations never matches the company's own row for a child company named like the root.
  const childNamedLikeRoot = makeApprovedSyntheticRegister({
    entities: [
      { name: 'Acme Home', kind: 'agency', house: true, slug: 'acme' },
      { name: 'Beacon', kind: 'agency' },
      { name: 'Acme', kind: 'company', parent: 'Beacon' },
    ],
    people: [{ id: 'p-1', name: 'Pat Child', npn: null, emails: ['pat.c@acme.example'] }],
    affiliations: [],
    memberships: [{ id: 'm-1', person: 'p-1', entity: 'Beacon', role: 'EMPLOYEE', start: '2024-01-01', end: null }],
    roles: [],
    website: [],
  });
  await assert.rejects(
    () => importAgentRegisterIntoDatabase({
      readPool: ctx.readPool,
      appPool: ctx.appPool,
      registerDoc: childNamedLikeRoot,
      keyFile: ctx.staffKeyFile,
      actorEmail: 'owner@nusear.example',
    }),
    (err) => err?.code === 'ORG_CONFLICT' && /company root/i.test(err.message),
    'diffOrganizations must never match company root row for a child company',
  );
  assert.deepEqual(await snapshotIamAndAuditCounts(ctx.pool), countsAfterRun1, 'org conflict refusals must write zero rows');

  // 4d. Item 6: refuse (PERSON_CONFLICT) re-activating a person who is suspended or archived in DB when register says active.
  const iamCmd = createIamCommands({ pool: ctx.appPool });
  await iamCmd.setPersonStatus({
    dbToken: staffOwnerTok,
    commandKey: 'test-suspend-p0011',
    personId: res1.personIds['p-0011'],
    status: 'suspended',
  });
  await iamCmd.setPersonStatus({
    dbToken: staffOwnerTok,
    commandKey: 'test-archive-p0012',
    personId: res1.personIds['p-0012'],
    status: 'archived',
  });
  const countsAfterSuspensions = await snapshotIamAndAuditCounts(ctx.pool);
  await assert.rejects(
    () => importAgentRegisterIntoDatabase({
      readPool: ctx.readPool,
      appPool: ctx.appPool,
      registerPath: regPath,
      vendorMasks: new Map([['Cobalt Leads', 'Vendor Alpha']]),
      keyFile: ctx.staffKeyFile,
      actorEmail: 'owner@nusear.example',
    }),
    (err) => {
      assert.equal(err?.code, 'PERSON_CONFLICT');
      assert.ok(err.message.includes('p-0011'));
      assert.ok(!err.message.includes('Riley Sales'), 'PERSON_CONFLICT message must not leak person name');
      return true;
    },
    'must refuse re-activating a suspended DB person',
  );
  // Even if p-0011 is updated to suspended in a new export, archived p-0012 still refuses reactivation!
  const regWithP11Suspended = {
    ...reg,
    revision: 13,
    people: reg.people.map((p) => (p.id === 'p-0011' ? { ...p, status: 'suspended' } : p)),
  };
  await assert.rejects(
    () => importAgentRegisterIntoDatabase({
      readPool: ctx.readPool,
      appPool: ctx.appPool,
      registerDoc: regWithP11Suspended,
      vendorMasks: new Map([['Cobalt Leads', 'Vendor Alpha']]),
      keyFile: ctx.staffKeyFile,
      actorEmail: 'owner@nusear.example',
    }),
    (err) => {
      assert.equal(err?.code, 'PERSON_CONFLICT');
      assert.ok(err.message.includes('p-0012'));
      assert.ok(!err.message.includes('Morgan Acct'), 'PERSON_CONFLICT message must not leak person name');
      return true;
    },
    'must refuse re-activating an archived DB person',
  );
  assert.deepEqual(await snapshotIamAndAuditCounts(ctx.pool), countsAfterSuspensions, 'reactivation refusals must write zero rows');

  // 5. Item 2: Company A's register refused against Company B's database, AND separate-company isolation!
  const beta = await provisionScratchCompany(t, { companySlug: 'beta', displayName: 'Beta', environment: 'dev' });
  const betaCountsBefore = await snapshotIamAndAuditCounts(beta.pool);
  await assert.rejects(
    () => importAgentRegisterIntoDatabase({
      readPool: beta.readPool,
      appPool: beta.appPool,
      registerPath: regPath,
      vendorMasks: new Map([['Cobalt Leads', 'Vendor Beta']]),
      keyFile: beta.staffKeyFile,
      actorEmail: 'owner@nusear.example',
    }),
    (err) => err instanceof RegisterValidationError && err.issues.some((i) => i.code === 'AMBIGUOUS_COMPANY_ENTITY' && /Acme/.test(i.message)),
    'company A register (house agency Acme) must be refused against company B database',
  );
  assert.deepEqual(await snapshotIamAndAuditCounts(beta.pool), betaCountsBefore, 'wrong-company refusal must write zero rows in company B DB');

  const betaReg = makeApprovedSyntheticRegister({
    entities: [
      { name: 'Beta', kind: 'company' },
      { name: 'Beacon', kind: 'agency' },
      { name: 'Cobalt Leads', kind: 'lead_vendor' },
    ],
    people: [
      { id: 'p-0001', name: 'Pat Owner', npn: null, emails: ['pat@beta.example'] },
      { id: 'p-0005', name: 'Sam Seller', npn: '11111111', emails: ['sam@beta.example'] },
    ],
    affiliations: [
      { id: 'a-0001', person: 'p-0005', npn: '11111111', entity: 'Beacon', start: '2024-01-01', end: null, split: '80.00' },
    ],
    memberships: [
      { id: 'm-0001', person: 'p-0001', entity: 'Beta', role: 'OWNER', start: '2023-01-01', end: null },
    ],
    roles: [
      { id: 'r-0000', person: 'p-0001', role: 'OWNER', scope: 'all' },
      { id: 'r-0001', person: 'p-0001', role: 'ENTITY_MANAGER', scope: 'all' },
      { id: 'r-0006', person: 'p-0005', role: 'SELLING_AGENT', scope: { entities: ['Beacon'], npns: ['11111111'] } },
    ],
    website: [],
  });
  const betaRes = await importAgentRegisterIntoDatabase({
    readPool: beta.readPool,
    appPool: beta.appPool,
    registerDoc: betaReg,
    vendorMasks: new Map([['Cobalt Leads', 'Vendor Beta']]),
    keyFile: beta.staffKeyFile,
    actorEmail: 'owner@nusear.example',
  });
  assert.equal(betaRes.changed, true);
  assert.notEqual(betaRes.personIds['p-0005'], res1.personIds['p-0005'], 'each company gets its own distinct person UUID');
  assert.notEqual(betaRes.orgIds.Beacon, res1.orgIds.Beacon, 'each company gets its own distinct organization UUID');
  const betaVendorRow = (await beta.pool.query(
    "SELECT ov.masked_display_name FROM iam.organizations o JOIN iam.organization_versions ov ON ov.organization_id = o.id AND ov.superseded_by_id IS NULL WHERE o.org_kind = 'lead_vendor'",
  )).rows[0];
  assert.equal(betaVendorRow.masked_display_name, 'Vendor Beta');
});

test('Agent Register Import [History by Date & Archived Organizations]: preserves dated moves, ended roles, multi-relationship segments, external_upline moves, and atomic archived org hierarchy', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const ctx = await provisionScratchCompany(t, {
    companySlug: 'acme',
    displayName: 'Acme',
    environment: 'local',
    allowNonDev: true,
  });

  const histReg = makeApprovedSyntheticRegister({
    entities: [
      { name: 'Acme', kind: 'company' },
      { name: 'Outside Upline', kind: 'external_upline', start: '2025-07-01' },
      {
        name: 'Moved Agency',
        kind: 'agency',
        edges: [
          { parent: 'Acme', start: '2023-01-01', end: '2025-06-30' },
          { parent: 'Outside Upline', start: '2025-07-01', end: null },
        ],
      },
      { name: 'Beacon', kind: 'agency' },
      { name: 'Harbor', kind: 'agency' },
      { name: 'Retired Agency', kind: 'agency', status: 'archived', start: '2023-01-01' },
      { name: 'Retired Team', kind: 'team', parent: 'Retired Agency', status: 'archived', start: '2023-06-01' },
    ],
    people: [
      { id: 'p-mover', name: 'Sam Mover', npn: '11111111', emails: ['mover@acme.example'] },
      { id: 'p-ended-ag', name: 'Past Seller', npn: '22222222', emails: ['past@beacon.example'] },
      { id: 'p-ended-mgr', name: 'Past Manager', npn: null, emails: ['pastmgr@beacon.example'] },
      { id: 'p-rehire', name: 'Rehired Former Owner', npn: null, emails: ['rehire@acme.example'] },
      { id: 'p-multi-rel', name: 'Multi Rel Owner', npn: null, emails: ['multi@acme.example'] },
      { id: 'p-moved-mgr', name: 'Moved Agency Mgr', npn: null, emails: ['movedmgr@moved.example'] },
      { id: 'p-retired-ag', name: 'Retired Seller', npn: '66666666', emails: ['ret@retired.example'], status: 'archived' },
    ],
    affiliations: [
      { id: 'a-m1', person: 'p-mover', npn: '11111111', entity: 'Harbor', agentName: 'Sam Mover Old', start: '2024-01-01', end: '2024-12-31', split: '75.00' },
      { id: 'a-m2', person: 'p-mover', npn: '11111111', entity: 'Beacon', agentName: 'Sam Mover', start: '2025-01-01', end: null, split: '80.00' },
      { id: 'a-end', person: 'p-ended-ag', npn: '22222222', entity: 'Beacon', start: '2024-01-01', end: '2024-06-30', split: '80.00' },
      { id: 'a-ret', person: 'p-retired-ag', npn: '66666666', entity: 'Retired Team', agentName: 'Retired Seller', start: '2023-06-01', end: '2024-12-31', split: '80.00' },
    ],
    memberships: [
      { id: 'm-endmgr', person: 'p-ended-mgr', entity: 'Beacon', role: 'EMPLOYEE', start: '2024-01-01', end: '2024-12-31' },
      { id: 'm-rehire-1', person: 'p-rehire', entity: 'Acme', role: 'OWNER', start: '2023-01-01', end: '2024-12-31' },
      { id: 'm-rehire-2', person: 'p-rehire', entity: 'Beacon', role: 'EMPLOYEE', start: '2025-06-01', end: null },
      { id: 'm-multi-1', person: 'p-multi-rel', entity: 'Acme', role: 'OWNER', start: '2023-01-01', end: null },
      { id: 'm-multi-2', person: 'p-multi-rel', entity: 'Acme', role: 'EMPLOYEE', taxClassification: 'w2', start: '2024-01-01', end: '2024-12-31' },
      { id: 'm-moved', person: 'p-moved-mgr', entity: 'Moved Agency', role: 'EMPLOYEE', start: '2023-01-01', end: null },
    ],
    roles: [
      { id: 'r-mover', person: 'p-mover', role: 'SELLING_AGENT', scope: { npns: ['11111111'] } },
      { id: 'r-ended-ag', person: 'p-ended-ag', role: 'SELLING_AGENT', scope: { entities: ['Beacon'], npns: ['22222222'] } },
      { id: 'r-ended-mgr', person: 'p-ended-mgr', role: 'AGENCY_MANAGER', scope: { entities: ['Beacon'] } },
      { id: 'r-rehire-old', person: 'p-rehire', role: 'OWNER', scope: 'all', start: '2023-01-01', end: '2024-12-31' },
      { id: 'r-rehire', person: 'p-rehire', role: 'AGENCY_MANAGER', scope: { entities: ['Beacon'] }, start: '2025-06-01', end: null },
      { id: 'r-multi', person: 'p-multi-rel', role: 'ENTITY_MANAGER', scope: 'all' },
      { id: 'r-moved', person: 'p-moved-mgr', role: 'AGENCY_MANAGER', scope: { entities: ['Moved Agency'] } },
    ],
    website: [],
  });

  await assert.rejects(
    () => importAgentRegisterIntoDatabase({
      readPool: ctx.readPool,
      appPool: ctx.appPool,
      registerDoc: histReg,
      keyFile: ctx.staffKeyFile,
      actorEmail: 'owner@nusear.example',
      allowNonDev: false,
    }),
    (err) => err?.code === 'NON_DEV_ENVIRONMENT_REFUSED',
  );

  const imported = await importAgentRegisterIntoDatabase({
    readPool: ctx.readPool,
    appPool: ctx.appPool,
    registerDoc: histReg,
    keyFile: ctx.staffKeyFile,
    actorEmail: 'owner@nusear.example',
    allowNonDev: true,
  });
  assert.equal(imported.changed, true);
  assert.equal(imported.created.archivedOrganizations, 2, 'archived parent + child both archived cleanly in reverse topo order');

  // Idempotent rerun with dated history + archived org hierarchy changes nothing!
  const rerun = await importAgentRegisterIntoDatabase({
    readPool: ctx.readPool,
    appPool: ctx.appPool,
    registerDoc: histReg,
    keyFile: ctx.staffKeyFile,
    actorEmail: 'support@nusear.example',
    allowNonDev: true,
  });
  assert.equal(rerun.changed, false);

  // Attempting to add a new person to an already-archived org on re-import is refused cleanly.
  const addToArchived = {
    ...histReg,
    revision: 13,
    people: [...histReg.people, { id: 'p-late', name: 'Late Arrival', npn: null, emails: ['late@retired.example'] }],
    memberships: [...histReg.memberships, { id: 'm-late', person: 'p-late', entity: 'Retired Agency', role: 'EMPLOYEE', start: '2024-01-01', end: null }],
  };
  await assert.rejects(
    () => importAgentRegisterIntoDatabase({
      readPool: ctx.readPool,
      appPool: ctx.appPool,
      registerDoc: addToArchived,
      keyFile: ctx.staffKeyFile,
      actorEmail: 'owner@nusear.example',
      allowNonDev: true,
    }),
    (err) => err?.code === 'ORG_CONFLICT' && /already-archived/i.test(err.message),
  );

  // Verify Retired Agency & Retired Team both landed as archived.
  const archivedRows = (await ctx.pool.query(
    `SELECT ov.display_name, ov.status
     FROM iam.organization_versions ov
     WHERE ov.superseded_by_id IS NULL AND ov.display_name IN ('Retired Agency', 'Retired Team')
     ORDER BY ov.display_name`,
  )).rows;
  assert.deepEqual(archivedRows, [
    { display_name: 'Retired Agency', status: 'archived' },
    { display_name: 'Retired Team', status: 'archived' },
  ]);

  // Verify moved agent has BOTH historical Harbor (7500) and open Beacon (8000) affiliations.
  const moverAffs = (await ctx.pool.query(
    `SELECT agency_org_id, split_bps, agent_file_name, lower(valid_range)::text AS lo, upper(valid_range)::text AS hi
     FROM iam.agent_affiliations
     WHERE person_id = $1::uuid AND superseded_by_id IS NULL
     ORDER BY lower(valid_range)`,
    [imported.personIds['p-mover']],
  )).rows;
  assert.deepEqual(moverAffs, [
    { agency_org_id: imported.orgIds.Harbor, split_bps: 7500, agent_file_name: 'Sam Mover Old', lo: '2024-01-01', hi: '2025-01-01' },
    { agency_org_id: imported.orgIds.Beacon, split_bps: 8000, agent_file_name: 'Sam Mover', lo: '2025-01-01', hi: null },
  ]);

  // Verify multi-relationship overlap cleanly partitioned into 3 non-overlapping works-for segments.
  const multiSegs = (await ctx.pool.query(
    `SELECT work_arrangement, tax_classification, lower(valid_range)::text AS lo, upper(valid_range)::text AS hi
     FROM iam.organization_memberships
     WHERE person_id = $1::uuid AND superseded_by_id IS NULL
     ORDER BY lower(valid_range)`,
    [imported.personIds['p-multi-rel']],
  )).rows;
  assert.deepEqual(multiSegs, [
    { work_arrangement: null, tax_classification: null, lo: '2023-01-01', hi: '2024-01-01' },
    { work_arrangement: 'employee', tax_classification: 'w2', lo: '2024-01-01', hi: '2025-01-01' },
    { work_arrangement: null, tax_classification: null, lo: '2025-01-01', hi: null },
  ]);

  // Verify Moved Agency has BOTH dated edges (closed Acme edge + open Outside Upline edge).
  const movedEdges = (await ctx.pool.query(
    `SELECT parent_org_id, lower(valid_range)::text AS lo, upper(valid_range)::text AS hi
     FROM iam.organization_edges
     WHERE child_org_id = $1::uuid AND superseded_by_id IS NULL AND status = 'active'
     ORDER BY lower(valid_range)`,
    [imported.orgIds['Moved Agency']],
  )).rows;
  assert.deepEqual(movedEdges, [
    { parent_org_id: ctx.prov.iam.companyOrgId, lo: '2023-01-01', hi: '2025-07-01' },
    { parent_org_id: imported.orgIds['Outside Upline'], lo: '2025-07-01', hi: null },
  ]);

  // Live RLS checks for today:
  const localKey = await seedCompanyLocalKey(ctx.pool, 'local');
  // Company Entity Manager (scope "all") can read archived Retired Agency & Retired Team history!
  await withRequestTx(ctx.appPool, localKey.tokenFor(imported.personIds['p-multi-rel']), async (tx) => {
    const wide = (await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v;
    assert.ok(wide.includes(imported.orgIds['Retired Agency']), 'scope "all" entity manager reads archived agency history');
    assert.ok(wide.includes(imported.orgIds['Retired Team']), 'scope "all" entity manager reads archived team history');
  }, { readOnly: true });
  // Moved agent sees ONLY Beacon today (not Harbor!).
  await withRequestTx(ctx.appPool, localKey.tokenFor(imported.personIds['p-mover']), async (tx) => {
    assert.deepEqual((await tx.query("SELECT org_id, person_id FROM iam.effective_narrow_pairs('act:coherence.bob.read')")).rows, [
      { org_id: imported.orgIds.Beacon, person_id: imported.personIds['p-mover'] },
    ]);
  }, { readOnly: true });
  // Ended agent & ended manager see ZERO rows today!
  await withRequestTx(ctx.appPool, localKey.tokenFor(imported.personIds['p-ended-ag']), async (tx) => {
    assert.deepEqual((await tx.query("SELECT iam.effective_narrow_person_ids('act:coherence.bob.read') AS v")).rows[0].v, []);
  }, { readOnly: true });
  await withRequestTx(ctx.appPool, localKey.tokenFor(imported.personIds['p-ended-mgr']), async (tx) => {
    assert.deepEqual((await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, []);
  }, { readOnly: true });
  // Rehired former owner holds Beacon agency_manager ONLY today (old owner grant capped at 2025-01-01; zero upline_cash).
  await withRequestTx(ctx.appPool, localKey.tokenFor(imported.personIds['p-rehire']), async (tx) => {
    assert.deepEqual((await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [imported.orgIds.Beacon]);
    assert.equal((await tx.query("SELECT iam.has_right('col:coherence.upline_cash') AS ok")).rows[0].ok, false);
  }, { readOnly: true });
  // Moved Agency manager still reads Moved Agency runoff in Acme DB!
  await withRequestTx(ctx.appPool, localKey.tokenFor(imported.personIds['p-moved-mgr']), async (tx) => {
    assert.deepEqual((await tx.query("SELECT iam.effective_wide_org_ids('act:coherence.bob.read') AS v")).rows[0].v, [imported.orgIds['Moved Agency']]);
  }, { readOnly: true });
});

test('Agent Register Import [Repository Fixture Statement Batches & History Import]: unmapped before import, then all fixture agencies and writing NPNs resolve cleanly', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const ctx = await provisionScratchCompany(t, { companySlug: 'acme', displayName: 'Acme', environment: 'dev' });
  const ownerTok = await mintStaffTokenFromKeyFile(ctx.readPool, ctx.staffKeyFile, 'owner@nusear.example', 'dev');

  const codeStore = createCodeStore({ backend: createMemoryObjectStore({ label: 'reg-fix-code' }) });
  const dataStore = createDataStore({ backend: createMemoryObjectStore({ label: 'reg-fix-data' }) });
  const stores = createStorePair({ codeStore, dataStore });
  const commands = createAppCommands({ pool: ctx.appPool, stores });

  await commands.initCompany({
    dbToken: ownerTok,
    commandKey: 'fixture-init-acme',
    slug: 'acme',
    displayName: 'Acme',
    defaultEmitMode: 'coherence',
  });

  // BEFORE importing the Agent Register: recording a statement batch with Beacon + 11111111 MUST fail (UNMAPPED_ENTITY).
  await assert.rejects(
    () => commands.recordStatementBatch({
      dbToken: ownerTok,
      commandKey: 'pre-import-refused',
      batchKind: 'historical_sent',
      statementDate: '2026-03-25',
      sourceFileName: 'BEA20260325.csv',
      reason: 'Before register import',
      agencyLines: [{
        lineNo: 1,
        entity: 'Beacon',
        writingNpn: '11111111',
        writingAgent: 'Sam Seller',
        recordId: 'carrier_a|direct|NM:sample,pat|100.00|2026-03',
        carrier: 'carrier_a',
        mbi: '1AB2CD3EF45',
        member: 'Pat Sample',
        grossComm: '100.00',
        amount: '100.00',
      }],
      uplineLines: [],
    }),
    (err) => err?.code === 'UNMAPPED_ENTITY' || /UNMAPPED_ENTITY/i.test(err?.message || ''),
    'statement batch must fail with UNMAPPED_ENTITY before Agent Register import',
  );

  // Import approved synthetic register matching every agency/team and NPN in the repository's fixtures.
  const fixtureRegister = makeApprovedSyntheticRegister({
    entities: [
      { name: 'Acme', kind: 'agency', house: true },
      { name: 'Beacon', kind: 'agency' },
      { name: 'East Team', kind: 'team', parent: 'Beacon' },
      { name: 'Harbor', kind: 'agency' },
      { name: 'SubAgency', kind: 'agency' },
      { name: 'PartnerAgency', kind: 'agency' },
    ],
    people: [
      { id: 'p-1', name: 'Pat Owner', npn: null, emails: ['pat@acme.example'] },
      { id: 'p-2', name: 'Sam Seller', npn: '11111111', emails: ['sam@beacon.example'] },
      { id: 'p-3', name: 'House Rep', npn: '22222222', emails: ['houserep@acme.example'] },
      { id: 'p-4', name: 'Robin Harbor', npn: '33333333', emails: ['robin@harbor.example'] },
      { id: 'p-5', name: 'Jamie East', npn: '44444444', emails: ['jamie@beacon.example'] },
      { id: 'p-6', name: 'Jordan Retain', npn: '31313131', emails: ['jordan@harbor.example'] },
      { id: 'p-7', name: 'Jane Agent', npn: '12345678', emails: ['jane@acme.example'] },
      { id: 'p-8', name: 'Bob Seller', npn: '87654321', emails: ['bob@sub.example'] },
      { id: 'p-9', name: 'Jordan Manager', npn: '11112222', emails: ['jman@partner.example'] },
    ],
    affiliations: [
      { id: 'a-1', person: 'p-2', npn: '11111111', entity: 'Beacon', start: '2024-01-01', end: null, split: '80.00' },
      { id: 'a-2', person: 'p-3', npn: '22222222', entity: 'Acme', start: '2024-01-01', end: null, split: '100.00' },
      { id: 'a-3', person: 'p-4', npn: '33333333', entity: 'Harbor', start: '2024-01-01', end: null, split: '80.00' },
      { id: 'a-4', person: 'p-5', npn: '44444444', entity: 'East Team', start: '2024-01-01', end: null, split: '80.00' },
      { id: 'a-5', person: 'p-6', npn: '31313131', entity: 'Harbor', start: '2024-01-01', end: null, split: '0.00' },
      { id: 'a-6', person: 'p-7', npn: '12345678', entity: 'Acme', start: '2024-01-01', end: null, split: '80.00' },
      { id: 'a-7', person: 'p-8', npn: '87654321', entity: 'SubAgency', start: '2024-01-01', end: null, split: '80.00' },
      { id: 'a-8', person: 'p-9', npn: '11112222', entity: 'PartnerAgency', start: '2024-01-01', end: null, split: '80.00' },
    ],
    memberships: [
      { id: 'm-1', person: 'p-1', entity: 'Acme', role: 'OWNER', start: '2023-01-01', end: null },
      { id: 'm-2', person: 'p-6', entity: 'Harbor', role: 'EMPLOYEE', start: '2024-01-01', end: null },
    ],
    roles: [
      { id: 'r-1', person: 'p-1', role: 'ENTITY_MANAGER', scope: 'all' },
      { id: 'r-2', person: 'p-2', role: 'SELLING_AGENT', scope: { entities: ['Beacon'], npns: ['11111111'] } },
      { id: 'r-3', person: 'p-3', role: 'SELLING_AGENT', scope: { entities: ['Acme'], npns: ['22222222'] } },
      { id: 'r-4', person: 'p-4', role: 'SELLING_AGENT', scope: { entities: ['Harbor'], npns: ['33333333'] } },
      { id: 'r-5', person: 'p-5', role: 'SELLING_AGENT', scope: { entities: ['East Team'], npns: ['44444444'] } },
      { id: 'r-6', person: 'p-6', role: 'RETENTION_AGENT', scope: { entities: ['Harbor'] } },
      { id: 'r-7', person: 'p-7', role: 'SELLING_AGENT', scope: { entities: ['Acme'], npns: ['12345678'] } },
      { id: 'r-8', person: 'p-8', role: 'SELLING_AGENT', scope: { entities: ['SubAgency'], npns: ['87654321'] } },
      { id: 'r-9', person: 'p-9', role: 'SELLING_AGENT', scope: { entities: ['PartnerAgency'], npns: ['11112222'] } },
    ],
    website: [],
  });

  const imported = await importAgentRegisterIntoDatabase({
    readPool: ctx.readPool,
    appPool: ctx.appPool,
    registerDoc: fixtureRegister,
    keyFile: ctx.staffKeyFile,
    actorEmail: 'owner@nusear.example',
  });
  assert.equal(imported.changed, true);

  // Part A: Import the 5 pre-Coherence historical_sent files + 2 method corrections (exact Layer 4 fixture).
  const mockRepo = join(ctx.workDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
  const stmtDir = join(ctx.workDir, 'pre-coherence-statements');
  const plxCols = 'Statement,WritingAgent,WritingAgentNPN,PolicyHolderName,MBI,State,Carrier,EffectiveDate,PlanType,SimplifiedCoverageType,PolicyNumber,CommissionAmount,Note,RevenueType,EarnedDate,PaymentDate,entity,DLTotal,ULTotal';
  const plxRow = (dt, dl, ul, gross) => `${dt} - CarrierA,Sam Seller,11111111,Pat Sample,1AB2CD3EF45,NC,CarrierA,2026-01-01,MA,MA,POL1,${gross},plx,Commission,${dt},${dt},Beacon,${dl},${ul}`;
  await writeTree(stmtDir, {
    'BEA20260325.csv': 'Statement,Carrier,Revenue Type,Commission Amount,Writing Agent NPN,Writing Agent,Policy Holder Name,MBI,Policy Number,Earned Date,Payment Date,Effective Date,Note,State,Plan Type,Simplified Coverage Type\n2026-03-06,CarrierA,Commission,$ 100.00,11111111,Sam Seller,Pat Sample,1AB2CD3EF45,POL1,2026-03-01,2026-03-06,2026-01-01,mar,NC,MA,MA\n',
    'plxSpark20260429.csv': `${plxCols}\n${plxRow('2026-04-15', '80.00', '20.00', '100.00')}\n`,
    'plxSpark20260531.csv': `${plxCols}\n${plxRow('2026-05-15', '80.00', '20.00', '100.00')}\n`,
    'plxSpark20260630.csv': `${plxCols}\n${plxRow('2026-06-15', '80.00', '20.00', '100.00')}\n`,
    'ALLAGENCY20260731Spark.csv': 'entity,npn,agent,member,mbi,policy_number,carrier,channel,amount,earned,payment,note,state,plan_type,coverage_type,effective,submitted\nBeacon,11111111,Sam Seller,Pat Sample,1AB2CD3EF45,POL1,carriera,spark,100.00,2026-07-01,2026-07-15,jul,NC,MA,MA,2026-01-01,2026-01-01\nAcme,22222222,House Rep,Lee Demo,2CD3EF4GH56,POL2,carriera,spark,50.00,2026-07-01,2026-07-15,jul,NC,MA,MA,2026-01-01,2026-01-01\n',
  });

  const preManifest = await buildImportManifest({
    companySlug: 'acme',
    sources: {
      preCoherenceStatementsDir: stmtDir,
      methodCorrections: [
        {
          kind: 'split_reallocation',
          statementDate: '2026-08-01',
          sourceGrammar: 'all_agency',
          unreversedOnly: false,
          uplineRate: '0.20',
          excludeEntities: ['Acme'],
          expectedAgencyNetCents: -2000,
          expectedUplineNetCents: 2000,
          reason: '2026-08-01 80/20 split correction',
        },
        {
          kind: 'upline_takeback',
          statementDate: '2026-08-31',
          sourceGrammar: 'plx_layout',
          expectedAgencyNetCents: 0,
          expectedUplineNetCents: -6000,
          reason: '2026-08-31 historical ULTotal take-back',
        },
      ],
    },
  });

  const preRep = await executeHistoryImport({
    pool: ctx.readPool,
    stores,
    commands,
    dbToken: ownerTok,
    manifest: preManifest,
    pythonPath: 'python3',
    coherenceRepo: mockRepo,
    verifyRebuild: false,
    tempBaseDir: ctx.workDir,
  });
  assert.equal(preRep.passed, true, preRep.problems.join('; '));
  assert.equal(preRep.preCoherenceBatchesImported, 5);
  assert.equal(preRep.methodCorrectionBatchesImported, 2);

  // Verify every agency & writing_npn FK resolved to the imported organizations and company_local people!
  const resolvedRows = (await ctx.readPool.query(
    `SELECT DISTINCT entity, organization_id, writing_npn, writing_person_id
     FROM coherence.statement_agency_lines
     ORDER BY entity, writing_npn`,
  )).rows;
  assert.deepEqual(resolvedRows, [
    { entity: 'Acme', organization_id: ctx.prov.iam.companyOrgId, writing_npn: '22222222', writing_person_id: imported.personIds['p-3'] },
    { entity: 'Beacon', organization_id: imported.orgIds.Beacon, writing_npn: '11111111', writing_person_id: imported.personIds['p-2'] },
  ]);

  const entTotals = await inReadTx(ctx.appPool, ownerTok, async (tx) => (
    (await tx.query(
      `SELECT statement_entity, SUM(net_amount)::numeric(14,2)::text AS total
       FROM app_views.coherence_statement_date_totals
       GROUP BY statement_entity
       ORDER BY statement_entity COLLATE "C"`,
    )).rows
  ));
  assert.deepEqual(entTotals, [
    { statement_entity: 'Acme', total: '50.00' },
    { statement_entity: 'Acme Upline', total: '20.00' },
    { statement_entity: 'Beacon', total: '420.00' },
  ]);

  // Part B: Record a multi-agency/team statement batch covering East Team, Harbor, SubAgency, PartnerAgency + all fixture NPNs!
  await commands.recordStatementBatch({
    dbToken: ownerTok,
    commandKey: 'fixture-multi-entity-batch',
    batchKind: 'historical_sent',
    statementDate: '2026-09-30',
    sourceFileName: 'fixture_multi.csv',
    reason: 'Multi-entity fixture batch after register import',
    agencyLines: [
      { lineNo: 1, entity: 'East Team', writingNpn: '44444444', writingAgent: 'Jamie East', recordId: 'ca|direct|NM:m,1|100.00|2026-09', carrier: 'carrier_a', mbi: '3AB2CD3EF41', member: 'M One', grossComm: '100.00', amount: '80.00' },
      { lineNo: 2, entity: 'Harbor', writingNpn: '33333333', writingAgent: 'Robin Harbor', recordId: 'ca|direct|NM:m,2|100.00|2026-09', carrier: 'carrier_a', mbi: '3AB2CD3EF42', member: 'M Two', grossComm: '100.00', amount: '80.00' },
      { lineNo: 3, entity: 'Harbor', writingNpn: '31313131', writingAgent: 'Jordan Retain', recordId: 'ca|direct|NM:m,3|50.00|2026-09', carrier: 'carrier_a', mbi: '3AB2CD3EF43', member: 'M Three', grossComm: '50.00', amount: '50.00' },
      { lineNo: 4, entity: 'Acme', writingNpn: '12345678', writingAgent: 'Jane Agent', recordId: 'ca|direct|NM:m,4|100.00|2026-09', carrier: 'carrier_a', mbi: '3AB2CD3EF44', member: 'M Four', grossComm: '100.00', amount: '80.00' },
      { lineNo: 5, entity: 'SubAgency', writingNpn: '87654321', writingAgent: 'Bob Seller', recordId: 'ca|direct|NM:m,5|100.00|2026-09', carrier: 'carrier_a', mbi: '3AB2CD3EF45', member: 'M Five', grossComm: '100.00', amount: '80.00' },
      { lineNo: 6, entity: 'PartnerAgency', writingNpn: '11112222', writingAgent: 'Jordan Manager', recordId: 'ca|direct|NM:m,6|100.00|2026-09', carrier: 'carrier_a', mbi: '3AB2CD3EF46', member: 'M Six', grossComm: '100.00', amount: '80.00' },
    ],
    uplineLines: [],
  });

  const multiResolved = (await ctx.readPool.query(
    `SELECT entity, organization_id, writing_npn, writing_person_id
     FROM coherence.statement_agency_lines
     WHERE statement_date = DATE '2026-09-30'
     ORDER BY line_no`,
  )).rows;
  assert.deepEqual(multiResolved, [
    { entity: 'East Team', organization_id: imported.orgIds['East Team'], writing_npn: '44444444', writing_person_id: imported.personIds['p-5'] },
    { entity: 'Harbor', organization_id: imported.orgIds.Harbor, writing_npn: '33333333', writing_person_id: imported.personIds['p-4'] },
    { entity: 'Harbor', organization_id: imported.orgIds.Harbor, writing_npn: '31313131', writing_person_id: imported.personIds['p-6'] },
    { entity: 'Acme', organization_id: ctx.prov.iam.companyOrgId, writing_npn: '12345678', writing_person_id: imported.personIds['p-7'] },
    { entity: 'SubAgency', organization_id: imported.orgIds.SubAgency, writing_npn: '87654321', writing_person_id: imported.personIds['p-8'] },
    { entity: 'PartnerAgency', organization_id: imported.orgIds.PartnerAgency, writing_npn: '11112222', writing_person_id: imported.personIds['p-9'] },
  ]);

  // Part C: Full P1 importHistoryIntoDatabase (historical runs + overlay + comparator) also passes cleanly on a register-imported DB!
  const ctx2 = await provisionScratchCompany(t, { companySlug: 'acme', displayName: 'Acme', environment: 'dev' });
  await importAgentRegisterIntoDatabase({
    readPool: ctx2.readPool,
    appPool: ctx2.appPool,
    registerDoc: fixtureRegister,
    keyFile: ctx2.staffKeyFile,
    actorEmail: 'owner@nusear.example',
  });

  const plantedMember = 'Zelda Q. Plantedname';
  const mockRepo2 = join(ctx2.workDir, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo2);
  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:P1#effective:2026-01-01', note: 'base' });
  const row1 = sampleApprovalRow({
    record_id: `carrier_a~direct~${plantedMember}~100.00~2026-11`,
    disposition: 'CONFIRM',
    agent: null,
    agency: null,
    status: null,
    note: 'adj',
  });
  const priorCsv = makeOverlayCsv([row0], { version: 'v2' });
  const finalCsv = makeOverlayCsv([row0, row1], { version: 'v2' });
  const runFiles = {
    'input/Agent Data/cleanagentdata.csv': 'agent_name,agent_npn,entity\nSam Seller,11111111,Beacon\n',
    'input/Overlay/overlay.csv': priorCsv,
    'bible.csv': 'record_id,case,subtype,amount\npolicy:carrier_a:P1#effective:2026-01-01,BIBLE,CONFLICT,100.00\n',
    'overlay.csv': finalCsv,
    'emits/overlay.csv': finalCsv,
    'emits/canonical_bob.csv': [
      'policy_id,member,entity,writing_npn,amount,upline_amount',
      `1,${plantedMember},Beacon,11111111,80.00,20.00`,
      '2,House Member,Acme,22222222,100.00,0.00',
      '3,Sibling Row Same NPN,Beacon,22222222,80.00,20.00',
      '',
    ].join('\n'),
    'emits/coherent_ledger.csv': [
      'tx_id,record_id,policy_id,member,entity,src_type,writing_npn,gross_comm,downline_amount,upline_amount,commission_amount',
      `1,carrier_a~direct~${plantedMember}~100.00~2026-11,1,${plantedMember},Beacon,direct,11111111,100.00,80.00,20.00,100.00`,
      '2,carrier_a~direct~House Member~100.00~2026-11,2,House Member,Acme,direct,22222222,100.00,100.00,0.00,100.00',
      '3,carrier_a~direct~Sibling Row Same NPN~100.00~2026-11,3,Sibling Row Same NPN,Beacon,direct,22222222,100.00,80.00,20.00,100.00',
      '',
    ].join('\n'),
    'emits/statements_20261102.csv': [
      'record_id,member,entity,writing_npn,gross_comm,downline_amount,upline_amount,run_action',
      `carrier_a~direct~${plantedMember}~100.00~2026-11,${plantedMember},Beacon,11111111,100.00,80.00,20.00,NEW`,
      'carrier_a~direct~House Member~100.00~2026-11,House Member,Acme,22222222,100.00,100.00,0.00,NEW',
      'carrier_a~direct~Sibling Row Same NPN~100.00~2026-11,Sibling Row Same NPN,Beacon,22222222,100.00,80.00,20.00,NEW',
      '',
    ].join('\n'),
    'run.json': JSON.stringify({
      date: '2026-11-02',
      steps: {
        assign: { at: '2026-11-02T10:00:00' },
        bible: { at: '2026-11-02T10:01:00' },
        emit: { at: '2026-11-02T10:05:00' },
      },
    }),
  };
  const srcDir = join(ctx2.workDir, 'source-ref');
  await writeTree(join(srcDir, 'runs', '2026-10-12'), {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': priorCsv,
    'emits/overlay.csv': priorCsv,
    'run.json': JSON.stringify({
      date: '2026-10-12',
      steps: { assign: { at: '2026-10-12T10:00:00' }, emit: { at: '2026-10-12T10:05:00' } },
    }),
  });
  await writeTree(join(srcDir, 'company-ws', '2026-11-02'), runFiles);
  await writeTree(join(srcDir, 'ref-2026-11-02'), runFiles);
  await writeTree(join(srcDir, 'input'), {
    'Agent Data/cleanagentdata.csv': runFiles['input/Agent Data/cleanagentdata.csv'],
    'Overlay/overlay.csv': finalCsv,
    'Sent/statements_20261102.csv': runFiles['emits/statements_20261102.csv'],
  });
  const manifestPath = join(ctx2.workDir, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    companySlug: 'acme',
    displayName: 'Acme',
    defaultEmitMode: 'coherence',
    coherenceRepo: mockRepo2,
    pythonPath: 'python3',
    sources: {
      legacyRunsRoot: 'source-ref/runs',
      companyWorkspacesDir: 'source-ref/company-ws',
      standingInputDir: 'source-ref/input',
    },
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      currentInputSourceKind: 'mac_import',
      freshOverlayRoots: [{ sourceFolder: '2026-10-12', sha256: sha256Hex(priorCsv) }],
    },
    compareTargets: [{
      label: '2026-11-02 substance parity',
      leftRunSourceFolder: 'company-workspaces/acme/2026-11-02',
      rightDir: 'source-ref/ref-2026-11-02',
      requireStatementsDelta: true,
      requireConservation: true,
    }],
  }, null, 2), 'utf8');

  const codeRoot = join(ctx2.workDir, 'stores', 'code');
  const dataRoot = join(ctx2.workDir, 'stores', 'data');
  await mkdir(codeRoot, { recursive: true, mode: 0o700 });
  await mkdir(dataRoot, { recursive: true, mode: 0o700 });
  const fileStores = createStorePair({
    codeStore: createCodeStore({ backend: createFileObjectStore({ rootDir: codeRoot, label: 'c2' }) }),
    dataStore: createDataStore({ backend: createFileObjectStore({ rootDir: dataRoot, label: 'd2' }) }),
  });

  const histSummary = await importHistoryIntoDatabase({
    readPool: ctx2.readPool,
    appPool: ctx2.appPool,
    stores: fileStores,
    manifestPath,
    keyFile: ctx2.staffKeyFile,
    actorEmail: 'owner@nusear.example',
  });
  assert.equal(histSummary.passed, true, `importHistoryIntoDatabase failed: ${histSummary.problems.join('; ')}`);

  // Materialize Emit for the sent 2026-11-02 company_import run as the provisioned worker service
  // principal, then prove live RLS on app_views.coherence_bob: house-agency selling_agent (p-3)
  // reads ONLY their own Acme row and CANNOT read sibling agency Beacon (even for their own NPN!).
  const svcKeyDoc = JSON.parse(await readFile(ctx2.svcKeyFile, 'utf8'));
  const workerId = (await ctx2.readPool.query(
    "SELECT id FROM iam.people WHERE person_kind = 'service' AND principal_origin = 'service' LIMIT 1",
  )).rows[0].id;
  const workerTok2 = mintSignedSessionToken({
    keyId: svcKeyDoc.keyId,
    secretBytes: Buffer.from(svcKeyDoc.secretHex, 'hex'),
    environment: 'dev',
    actorPersonId: workerId,
  });
  const workerPool2 = createRoleScopedTestPool(ctx2.pool, 'platform_worker');
  const run20261102 = (await ctx2.readPool.query(
    "SELECT r.id, coherence.current_finished_attempt(r.id, 'emit') AS emit_ev FROM coherence.runs r WHERE r.statement_date = DATE '2026-11-02'",
  )).rows[0];
  const workerCmd2 = createAppCommands({ pool: workerPool2, stores: fileStores });
  await workerCmd2.materializeEmit({
    dbToken: workerTok2,
    commandKey: 'materialize-2026-11-02-for-rls',
    runId: run20261102.id,
    attemptEventId: run20261102.emit_ev,
    statementDate: '2026-11-02',
    canonicalBobCsv: runFiles['emits/canonical_bob.csv'],
    coherentLedgerCsv: runFiles['emits/coherent_ledger.csv'],
    statementsCsv: runFiles['emits/statements_20261102.csv'],
  });
  const localKey2 = await seedCompanyLocalKey(ctx2.pool, 'dev');
  const imported2 = await importAgentRegisterIntoDatabase({
    readPool: ctx2.readPool,
    appPool: ctx2.appPool,
    registerDoc: fixtureRegister,
    keyFile: ctx2.staffKeyFile,
    actorEmail: 'owner@nusear.example',
  });
  assert.equal(imported2.changed, false);
  await withRequestTx(ctx2.appPool, localKey2.tokenFor(imported2.personIds['p-3']), async (tx) => {
    const bobRows = (await tx.query('SELECT entity, writing_npn FROM app_views.coherence_bob ORDER BY entity, writing_npn')).rows;
    assert.deepEqual(
      bobRows,
      [{ entity: 'Acme', writing_npn: '22222222' }],
      'house-agency selling_agent must read only their own Acme row and ZERO Beacon rows in coherence_bob',
    );
  }, { readOnly: true });
  await withRequestTx(ctx2.appPool, localKey2.tokenFor(imported2.personIds['p-2']), async (tx) => {
    const bobRows = (await tx.query('SELECT entity, writing_npn FROM app_views.coherence_bob ORDER BY entity, writing_npn')).rows;
    assert.deepEqual(
      bobRows,
      [{ entity: 'Beacon', writing_npn: '11111111' }],
      'Beacon selling_agent sees strictly their own Beacon row in coherence_bob',
    );
  }, { readOnly: true });
});

test('Agent Register Import [Stale grants]: a live grant the register no longer holds is refused; an ended one is history', () => {
  const today = '2026-11-27';
  const snapshotWith = (hi) => ({
    roleIdBySlug: new Map(),
    subjectsByGrantId: new Map(),
    grantsByTuple: new Map([['person|role|org', [{ id: 'g-1', include_descendants: false, person_scope_mode: 'org_subtree', data_date_range: null, lo: '2024-01-01', hi }]]]),
  });
  const run = (hi) => diffRoleGrants({ roleGrants: [] }, snapshotWith(hi), new Map(), new Set(), today);
  for (const hi of ['2026-11-01', today]) assert.doesNotThrow(() => run(hi), `a grant ended before ${hi} is history`);
  for (const hi of [null, '2026-11-28']) {
    assert.throws(() => run(hi), (err) => err?.code === 'ROLE_GRANT_CONFLICT' && /g-1/.test(err.message), `a grant live today (upper bound ${hi}) is refused`);
  }
});

