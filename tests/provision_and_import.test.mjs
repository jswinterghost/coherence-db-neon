// Verification tests for idempotent company database provisioning, non-inherited SET-only
// IAM login role mapping (with startup '-c role=<platform_role>'), withheld administrator
// read-only enforcement, mode-600 signing key hygiene, target-DB/env/context guards, simulated
// non-superuser cloudsqlsuperuser provisioning (creating platform_* roles itself on an ephemeral
// PG 17 cluster), Emit/statement reconciliation and coherence.run_states under FORCE RLS,
// catalog invariant negative probes, and read-only history import via --app-user/--readonly-user.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import pg from 'pg';
import { buildImportPoolConfig, parseImportCliArgs, runHistoryImportCli } from '../scripts/import-history.mjs';
import { parseProvisionCliArgs } from '../scripts/provision-company-db.mjs';
import { createAppCommands, createIamCommands } from '../src/commands/app-cmd.mjs';
import {
  PLATFORM_ROLES,
  validateCloudSqlConfig,
  verifyCloudSqlConfigFile,
  verifyIamConfigInvariants,
} from '../src/config/policy-checks.mjs';
import { buildConnectionConfig, createClient, createPool, inReadTx, resolveLocalUser } from '../src/db/pg-client.mjs';
import { provisionCompanyDatabase } from '../src/iam/provision.mjs';
import {
  assertSafeKeysDir,
  createRenewingTokenProvider,
  mintSignedSessionToken,
  readKeyFile,
} from '../src/iam/tokens.mjs';
import { importHistoryIntoDatabase } from '../src/importer/provisioned-import.mjs';
import { createFileObjectStore } from '../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../src/storage/stores.mjs';
import { sha256Hex } from '../src/util/crypto.mjs';
import {
  createStdlibMockCoherenceRepo,
  makeOverlayCsv,
  sampleApprovalRow,
} from './helpers/fixtures.mjs';
import { checkPgAvailable, getAdminPgConfig, TEST_DB_PREFIX, withClusterCatalogLock } from './helpers/test-db.mjs';

const execFileAsync = promisify(execFile);
const pgCheck = await checkPgAvailable();
const PG_PORT = Number(process.env.PGPORT || 5432);

function quoteIdent(ident) {
  return `"${String(ident).replace(/"/g, '""')}"`;
}

function findPg17BinDir() {
  const candidates = [
    '/opt/homebrew/opt/postgresql@17/bin',
    '/opt/homebrew/bin',
    '/usr/local/opt/postgresql@17/bin',
    '/usr/local/bin',
    '/usr/lib/postgresql/17/bin',
  ];
  for (const dir of candidates) {
    if (existsSync(join(dir, 'initdb')) && existsSync(join(dir, 'pg_ctl'))) {
      return dir;
    }
  }
  return null;
}

async function startEphemeralPg17Cluster({ extraPostgresOpts = [] } = {}) {
  const binDir = findPg17BinDir();
  if (!binDir) {
    throw new Error('Could not locate PostgreSQL 17 initdb and pg_ctl binaries.');
  }
  const suffix = randomBytes(4).toString('hex');
  const dataDir = await mkdtemp(join(tmpdir(), `coherence-pgdata-${suffix}-`));
  const socketDir = join('/tmp', `coh_pgsock_${suffix}`);
  const logFile = join(dataDir, 'postgres.log');
  const osUser = resolveLocalUser();
  const port = 5432;
  await mkdir(socketDir, { mode: 0o700 });

  let started = false;
  try {
    await execFileAsync(join(binDir, 'initdb'), [
      '-D', dataDir,
      '-U', osUser,
      '-E', 'UTF8',
      '--no-locale',
      '--auth-local=peer',
      '--auth-host=scram-sha-256',
    ]);
    // Allow OS superuser via peer and simulated IAM login roles via scram-sha-256 over the local socket.
    const hba = [
      `local all ${osUser} peer`,
      'local all all scram-sha-256',
      'host all all 127.0.0.1/32 scram-sha-256',
      'host all all ::1/128 scram-sha-256',
    ].join('\n') + '\n';
    await writeFile(join(dataDir, 'pg_hba.conf'), hba, { mode: 0o600 });

    const opts = [
      `-k ${socketDir}`,
      '-c listen_addresses=',
      `-p ${port}`,
      ...extraPostgresOpts,
    ].join(' ');
    await execFileAsync(join(binDir, 'pg_ctl'), [
      '-D', dataDir,
      '-l', logFile,
      '-o', opts,
      '-w',
      'start',
    ]);
    started = true;
  } catch (err) {
    await rm(socketDir, { recursive: true, force: true }).catch(() => {});
    await rm(dataDir, { recursive: true, force: true }).catch(() => {});
    throw err;
  }

  const adminConfig = {
    mode: 'local',
    host: socketDir,
    port,
    database: 'postgres',
    user: osUser,
  };

  async function stop() {
    if (started) {
      await execFileAsync(join(binDir, 'pg_ctl'), ['-D', dataDir, '-m', 'immediate', 'stop']).catch(() => {});
      started = false;
    }
    await rm(socketDir, { recursive: true, force: true }).catch(() => {});
    await rm(dataDir, { recursive: true, force: true }).catch(() => {});
  }

  return { socketDir, port, adminConfig, stop };
}

async function createScratchDb(prefix = 'prov', ownerRole = null, customAdminConfig = null) {
  const suffix = randomBytes(5).toString('hex');
  const dbName = `${TEST_DB_PREFIX}${prefix}_${suffix}`;
  const adminConfig = customAdminConfig || getAdminPgConfig();
  const admin = await createClient(adminConfig);
  try {
    const ownerClause = ownerRole ? ` OWNER ${quoteIdent(ownerRole)}` : '';
    await admin.query(`CREATE DATABASE ${quoteIdent(dbName)} ENCODING 'UTF8'${ownerClause}`);
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
  return { dbName, pgConfig, adminConfig, drop };
}

async function createLoginRoles(adminConfig, specs) {
  const admin = await createClient(adminConfig);
  const created = [];
  try {
    for (const s of specs) {
      const password = s.password ?? `pw_${randomBytes(16).toString('hex')}`;
      const attrs = s.attrs || 'LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION INHERIT';
      await admin.query(`CREATE ROLE ${quoteIdent(s.name)} ${attrs} PASSWORD '${password}'`);
      created.push({ name: s.name, password });
    }
  } catch (err) {
    for (const r of created.reverse()) {
      await admin.query(`DROP ROLE IF EXISTS ${quoteIdent(r.name)}`).catch(() => {});
    }
    throw err;
  } finally {
    await admin.end();
  }
  async function cleanup() {
    const c = await createClient(adminConfig).catch(() => null);
    if (!c) return;
    try {
      for (const r of [...created].reverse()) {
        for (const pr of PLATFORM_ROLES) {
          await c.query(`REVOKE ${quoteIdent(pr)} FROM ${quoteIdent(r.name)}`).catch(() => {});
        }
        await c.query(`DROP ROLE IF EXISTS ${quoteIdent(r.name)}`).catch(() => {});
      }
    } finally {
      await c.end().catch(() => {});
    }
  }
  return { roles: created, byName: new Map(created.map((r) => [r.name, r])), cleanup };
}

async function writeTree(baseDir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = join(baseDir, ...rel.split('/'));
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
}

async function snapshotTreeHashes(dir, base = dir, out = {}) {
  const entries = (await readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    const full = join(dir, entry.name);
    const rel = full.slice(base.length + 1).split('\\').join('/');
    if (entry.isDirectory()) {
      await snapshotTreeHashes(full, base, out);
    } else if (entry.isFile()) {
      const bytes = await readFile(full);
      out[rel] = { size: bytes.length, sha256: sha256Hex(bytes) };
    }
  }
  return out;
}

async function buildHistoryFixtures(work, { plantedMember = 'Zelda Q. Plantedname' } = {}) {
  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);
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

  const bobCsv = `policy_id,member,entity,amount,upline_amount\n1,${plantedMember},Beacon,80.00,20.00\n`;
  const ledCsv = `tx_id,record_id,policy_id,member,entity,gross_comm,downline_amount,upline_amount\n1,carrier_a~direct~${plantedMember}~100.00~2026-11,1,${plantedMember},Beacon,100.00,80.00,20.00\n`;
  const stmtCsv = `record_id,member,entity,gross_comm,downline_amount,upline_amount,run_action\ncarrier_a~direct~${plantedMember}~100.00~2026-11,${plantedMember},Beacon,100.00,80.00,20.00,NEW\n`;

  const runFiles = {
    'input/Agent Data/cleanagentdata.csv': 'agent_name,agent_npn,entity\nSam Seller,11111111,Beacon\n',
    'input/Overlay/overlay.csv': priorCsv,
    'bible.csv': 'record_id,case,subtype,amount\npolicy:carrier_a:P1#effective:2026-01-01,BIBLE,CONFLICT,100.00\n',
    'overlay.csv': finalCsv,
    'emits/overlay.csv': finalCsv,
    'emits/canonical_bob.csv': bobCsv,
    'emits/coherent_ledger.csv': ledCsv,
    'emits/statements_20261102.csv': stmtCsv,
    'run.json': JSON.stringify({
      date: '2026-11-02',
      steps: {
        assign: { at: '2026-11-02T10:00:00' },
        bible: { at: '2026-11-02T10:01:00' },
        emit: { at: '2026-11-02T10:05:00' },
      },
    }),
  };

  const srcDir = join(work, 'source-ref');
  await writeTree(join(srcDir, 'runs', '2026-10-12'), {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': priorCsv,
    'emits/overlay.csv': priorCsv,
    'run.json': JSON.stringify({
      date: '2026-10-12',
      steps: { assign: { at: '2026-10-12T10:00:00' }, emit: { at: '2026-10-12T10:05:00' } },
    }),
  });
  await writeTree(join(srcDir, 'runs', '2026-11-02'), runFiles);
  await writeTree(join(srcDir, 'ref-2026-11-02'), runFiles);
  await writeTree(join(srcDir, 'input'), {
    'Agent Data/cleanagentdata.csv': runFiles['input/Agent Data/cleanagentdata.csv'],
    'Overlay/overlay.csv': finalCsv,
  });

  const manifestPath = join(work, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    companySlug: 'acme',
    displayName: 'Acme',
    defaultEmitMode: 'coherence',
    coherenceRepo: mockRepo,
    pythonPath: 'python3',
    sources: {
      legacyRunsRoot: 'source-ref/runs',
      standingInputDir: 'source-ref/input',
    },
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      currentInputSourceKind: 'mac_import',
      freshOverlayRoots: [{ sourceFolder: '2026-10-12', sha256: sha256Hex(priorCsv) }],
    },
    compareTargets: [
      {
        label: '2026-11-02 substance parity',
        leftRunSourceFolder: '2026-11-02',
        rightDir: 'source-ref/ref-2026-11-02',
        requireStatementsDelta: true,
        requireConservation: true,
      },
    ],
  }, null, 2), 'utf8');

  return { srcDir, manifestPath, plantedMember };
}

test('Provisioning [Config, Cloud SQL Socket Driver, CLI Parsing, Token Provider & Key-Dir Safety]: explicit socket port 5432, PG* refusal, CLI guards, short-lived renewing tokens, and key-dir / .gitignore safety', async (t) => {
  const csql = await verifyCloudSqlConfigFile();
  assert.equal(csql.passed, true, `Cloud SQL config failed: ${csql.problems.join('; ')}`);
  assert.equal(csql.config.ipConfiguration.ipv4Enabled, true);
  assert.deepEqual(csql.config.ipConfiguration.authorizedNetworks, []);
  assert.equal(csql.config.ipConfiguration.requireSsl, true);
  assert.equal(csql.config.ipConfiguration.sslMode, 'ENCRYPTED_ONLY');
  assert.equal(csql.config.connectionProtocol.connector, 'cloud-sql-connector');
  assert.equal(csql.config.connectionProtocol.relayMachineAllowed, false);
  assert.equal(csql.config.connectionProtocol.passwordAuthAllowed, false);
  assert.equal(csql.config.connectionProtocol.iamDatabaseAuthRequired, true);
  assert.equal(csql.config.connectionProtocol.runtimeRoleMapping, 'non_inherited_set_with_startup_role');
  assert.equal(csql.config.connectionProtocol.startupRoleOption, '-c role=<platform_role>');
  assert.equal(csql.config.topology.model, 'one_instance_per_environment');
  assert.equal(csql.config.topology.separateEnvironments, true);
  assert.equal(csql.config.topology.databasePerCompany, true);
  assert.equal(csql.config.topology.includesControlDatabase, true);

  const bad = validateCloudSqlConfig({
    ...csql.config,
    topology: { ...csql.config.topology, model: 'one_instance_per_company', separateEnvironments: false },
    ipConfiguration: { ...csql.config.ipConfiguration, ipv4Enabled: false, authorizedNetworks: [{ value: '10.0.0.0/8' }] },
    connectionProtocol: { ...csql.config.connectionProtocol, relayMachineAllowed: true, passwordAuthAllowed: true, runtimeRoleMapping: 'inherit' },
  });
  assert.equal(bad.passed, false);
  assert.ok(bad.problems.some((p) => /topology\.model/i.test(p)));
  assert.ok(bad.problems.some((p) => /separateEnvironments/i.test(p)));
  assert.ok(bad.problems.some((p) => /ipv4Enabled/i.test(p)));
  assert.ok(bad.problems.some((p) => /authorizedNetworks/i.test(p)));
  assert.ok(bad.problems.some((p) => /relayMachineAllowed/i.test(p)));
  assert.ok(bad.problems.some((p) => /passwordAuthAllowed/i.test(p)));
  assert.ok(bad.problems.some((p) => /runtimeRoleMapping/i.test(p)));

  // Item 2: Cloud SQL socket mode explicitly defaults port to 5432 even when PGPORT=5433 is in env,
  // allows explicit port override, and refuses PGPASSWORD + connection-altering PG* env vars.
  const prevPgPort = process.env.PGPORT;
  const prevPgHost = process.env.PGHOST;
  const prevPgPassword = process.env.PGPASSWORD;
  const prevPgOptions = process.env.PGOPTIONS;
  try {
    process.env.PGPORT = '5433';
    process.env.PGHOST = '/tmp';
    delete process.env.PGPASSWORD;
    delete process.env.PGOPTIONS;

    const proxyCfg = buildConnectionConfig({
      mode: 'cloudsql',
      socketPath: '/tmp/cloudsql/proj:us-east4:dev-db',
      database: 'acme',
      user: 'app-svc@proj.iam',
      role: 'platform_app',
    });
    assert.equal(proxyCfg.host, '/tmp/cloudsql/proj:us-east4:dev-db');
    assert.equal(proxyCfg.port, 5432, 'Cloud SQL socket mode must default explicitly to port 5432 regardless of PGPORT');
    assert.equal(proxyCfg.database, 'acme');
    assert.equal(proxyCfg.ssl, false);
    assert.equal(proxyCfg.options, '-c role=platform_app');

    // Confirm pg.Client actually binds port 5432 (never PGPORT=5433) and undefined password.
    const pgClient = new pg.Client(proxyCfg);
    assert.equal(pgClient.port, 5432);
    assert.equal(pgClient.host, '/tmp/cloudsql/proj:us-east4:dev-db');
    assert.equal(pgClient.database, 'acme');
    assert.equal(pgClient.password, null);

    const customPortCfg = buildConnectionConfig({
      mode: 'cloudsql',
      socketPath: '/tmp/cloudsql/proj:us-east4:dev-db',
      port: 5439,
      database: 'acme',
      user: 'app-svc@proj.iam',
    });
    assert.equal(customPortCfg.port, 5439);

    assert.throws(
      () => buildConnectionConfig({ mode: 'cloudsql', socketPath: '/tmp/cloudsql/x', user: 'app@proj.iam' }),
      /explicit database name/i,
    );

    for (const [envKey, envVal] of [
      ['PGPASSWORD', 'leak-pw'],
      ['PGOPTIONS', '-c role=postgres'],
      ['PGREPLICATION', 'database'],
      ['PGCLIENTENCODING', 'LATIN1'],
      ['PGBINARY', 'true'],
      ['PGCONNECT_TIMEOUT', '5'],
      ['PGPASSFILE', '/tmp/pgpass'],
      ['PGSSLMODE', 'disable'],
      ['PGHOSTADDR', '1.2.3.4'],
      ['PGSERVICE', 'prod'],
    ]) {
      assert.throws(
        () => buildConnectionConfig({
          mode: 'cloudsql',
          socketPath: '/tmp/cloudsql/proj:us-east4:dev-db',
          database: 'acme',
          user: 'app-svc@proj.iam',
          env: { [envKey]: envVal },
        }),
        new RegExp(envKey),
        `cloudsql mode must refuse ${envKey} in environment`,
      );
    }
  } finally {
    if (prevPgPort !== undefined) process.env.PGPORT = prevPgPort; else delete process.env.PGPORT;
    if (prevPgHost !== undefined) process.env.PGHOST = prevPgHost; else delete process.env.PGHOST;
    if (prevPgPassword !== undefined) process.env.PGPASSWORD = prevPgPassword; else delete process.env.PGPASSWORD;
    if (prevPgOptions !== undefined) process.env.PGOPTIONS = prevPgOptions; else delete process.env.PGOPTIONS;
  }

  const localCfg = buildConnectionConfig({ mode: 'local', database: 'acme', role: 'platform_readonly' });
  assert.equal(localCfg.options, '-c role=platform_readonly');
  assert.throws(
    () => buildConnectionConfig({ mode: 'local', database: 'acme', role: 'platform_app; DROP TABLE x' }),
    /Invalid PostgreSQL startup role/i,
  );

  // Item 3 & 13: CLI argument parsing for both scripts (requiring --database; --app-user/--readonly-user).
  assert.throws(
    () => parseProvisionCliArgs([
      '--company-slug', 'acme',
      '--keys-dir', '/tmp/k',
      '--staff', 'nusear_owner:owner@nusear.example:Pat Owner',
    ]),
    (err) => err?.code === 'MISSING_CLI_ARGS',
    'provision-company-db.mjs must require --database',
  );
  assert.throws(
    () => parseImportCliArgs([
      '--manifest', 'm.json',
      '--stores-dir', '/tmp/s',
      '--key-file', '/tmp/k.key.json',
      '--actor-email', 'owner@nusear.example',
    ]),
    (err) => err?.code === 'MISSING_CLI_ARGS',
    'import-history.mjs must require --database',
  );
  const planOnly = parseImportCliArgs(['--manifest', 'm.json', '--plan']);
  assert.equal(planOnly.plan, true);
  assert.equal(planOnly.manifestPath, 'm.json');

  const parsedImp = parseImportCliArgs([
    '--manifest', 'm.json',
    '--database', 'acme',
    '--stores-dir', '/tmp/s',
    '--key-file', '/tmp/k.key.json',
    '--actor-email', 'owner@nusear.example',
    '--pg-mode', 'cloudsql',
    '--app-socket-path', '/tmp/cloudsql-app/proj:us-east4:dev-db',
    '--app-user', 'app-svc@proj.iam',
    '--readonly-socket-path', '/tmp/cloudsql-ro/proj:us-east4:dev-db',
    '--readonly-user', 'ro-svc@proj.iam',
  ]);
  assert.equal(parsedImp.database, 'acme');
  assert.equal(parsedImp.appUser, 'app-svc@proj.iam');
  assert.equal(parsedImp.readonlyUser, 'ro-svc@proj.iam');
  const appPoolCfg = buildImportPoolConfig(parsedImp, 'app');
  const roPoolCfg = buildImportPoolConfig(parsedImp, 'readonly');
  assert.equal(appPoolCfg.role, 'platform_app');
  assert.equal(appPoolCfg.user, 'app-svc@proj.iam');
  assert.equal(appPoolCfg.socketPath, '/tmp/cloudsql-app/proj:us-east4:dev-db');
  assert.equal(roPoolCfg.role, 'platform_readonly');
  assert.equal(roPoolCfg.user, 'ro-svc@proj.iam');
  assert.equal(roPoolCfg.socketPath, '/tmp/cloudsql-ro/proj:us-east4:dev-db');

  // Item 8: short-lived renewing token provider renews before expiry and zeroes secret bytes on dispose.
  const secretBuf = randomBytes(32);
  let nowSec = 1_700_000_000;
  const provider = createRenewingTokenProvider({
    keyId: 'k_dev_staff_1234',
    secretBytes: secretBuf,
    environment: 'dev',
    actorPersonId: randomUUID(),
    ttlSeconds: 300,
    renewBeforeSeconds: 60,
    nowMs: () => nowSec * 1000,
  });
  const tok1 = provider.getToken();
  const exp1 = Number(tok1.split('|')[6]);
  assert.equal(exp1, nowSec + 300, 'default token TTL must be short-lived (300s, never 3600s)');
  nowSec += 200;
  assert.equal(provider.getToken(), tok1, 'token stays cached while outside renewal window');
  nowSec += 45; // 245s elapsed -> within 60s of expiry
  const tok2 = provider.getToken();
  const exp2 = Number(tok2.split('|')[6]);
  assert.notEqual(tok2, tok1, 'token must renew automatically before expiry');
  assert.equal(exp2, nowSec + 300);
  provider.dispose();
  assert.equal(secretBuf.every((b) => b === 0), true, 'dispose() must zero all secret bytes');
  assert.throws(() => provider.getToken(), (err) => err?.code === 'TOKEN_PROVIDER_DISPOSED');

  // Item 9: .gitignore ignores *.key.json; keys folder inside repo or any .git tree is refused.
  const gitignore = await readFile(resolve(process.cwd(), '.gitignore'), 'utf8');
  assert.ok(gitignore.split(/\r?\n/).map((l) => l.trim()).includes('*.key.json'), '.gitignore must include *.key.json');

  await assert.rejects(
    () => assertSafeKeysDir(join(process.cwd(), 'tmp-keys')),
    (err) => err?.code === 'UNSAFE_KEYS_DIR',
    'keysDir inside repository must be refused',
  );
  const gitWork = await mkdtemp(join(tmpdir(), 'coherence-git-tree-'));
  t.after(() => rm(gitWork, { recursive: true, force: true }));
  await mkdir(join(gitWork, 'normal-repo', '.git'), { recursive: true });
  await mkdir(join(gitWork, 'wt'), { recursive: true });
  await writeFile(join(gitWork, 'wt', '.git'), 'gitdir: /tmp/x\n');
  await assert.rejects(
    () => assertSafeKeysDir(join(gitWork, 'normal-repo', 'keys')),
    (err) => err?.code === 'UNSAFE_KEYS_DIR',
    'keysDir inside a .git directory tree must be refused',
  );
  await assert.rejects(
    () => assertSafeKeysDir(join(gitWork, 'wt', 'nested', 'keys')),
    (err) => err?.code === 'UNSAFE_KEYS_DIR',
    'keysDir inside a git worktree (.git file) must be refused',
  );
});

test('Provisioning [Fresh, Idempotent, Target/Context/Key Guards & Revoked Switches]: CLI provisions dev DB, refuses wrong/system/prod DBs and insecure key dirs without chmod, preserves revoked switches, validates displayName and worker grants', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-prov-cli-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const keysDir = join(work, 'keys');

  const db = await createScratchDb('cli');
  t.after(() => db.drop());

  const commonArgs = [
    'scripts/provision-company-db.mjs',
    '--pg-mode', 'local',
    '--host', db.pgConfig.host,
    '--port', String(db.pgConfig.port),
    '--database', db.dbName,
    '--user', db.pgConfig.user,
    '--company-slug', 'acme',
    '--display-name', 'Acme Health',
    '--keys-dir', keysDir,
    '--staff', 'nusear_owner:owner@nusear.example:Pat Owner',
    '--staff', 'nusear_admin:admin@nusear.example:Morgan Admin',
  ];

  // Item 3: Refuses system/control DBs, non-slug non-scratch DBs, production socket/host/instance in dev, and non-dev without opt-in.
  for (const forbiddenDb of ['postgres', 'template0', 'template1', 'cloudsqladmin', 'nusear_control']) {
    await assert.rejects(
      () => provisionCompanyDatabase({
        pgConfig: { ...db.pgConfig, database: forbiddenDb },
        companySlug: 'acme',
        keysDir,
        staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
      }),
      (err) => err?.code === 'FORBIDDEN_TARGET_DATABASE',
      `must refuse system/control database ${forbiddenDb}`,
    );
  }
  await assert.rejects(
    () => provisionCompanyDatabase({
      pgConfig: { ...db.pgConfig, database: 'other_company' },
      companySlug: 'acme',
      keysDir,
      staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
    }),
    (err) => err?.code === 'DATABASE_SLUG_MISMATCH',
    'must refuse non-scratch database whose name differs from companySlug',
  );
  await assert.rejects(
    () => provisionCompanyDatabase({
      pgConfig: { mode: 'cloudsql', socketPath: '/tmp/csql/proj:us-east4:dev-db', database: 'test_scratch', user: 'admin@example' },
      companySlug: 'acme',
      keysDir,
      staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
    }),
    (err) => err?.code === 'DATABASE_SLUG_MISMATCH',
    'cloudsql mode must refuse scratch database names differing from companySlug',
  );
  for (const prodCfg of [
    { mode: 'cloudsql', socketPath: '/cloudsql/nusear-control-prod:us-east4:nusear-prod-db', database: 'acme', user: 'admin@example' },
    { mode: 'local', host: 'db.production.nusear.internal', port: 5432, database: 'acme', user: 'admin@example' },
    { mode: 'cloudsql', socketPath: '/tmp/csql/x', instance: 'nusear-prod-db', database: 'acme', user: 'admin@example' },
  ]) {
    await assert.rejects(
      () => provisionCompanyDatabase({
        pgConfig: prodCfg,
        companySlug: 'acme',
        environment: 'dev',
        keysDir,
        staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
      }),
      (err) => err?.code === 'PRODUCTION_TARGET_REFUSED',
      'dev environment must refuse production socket, host, or instance',
    );
  }

  for (const envName of ['prod', 'local']) {
    await assert.rejects(
      () => execFileAsync(process.execPath, [...commonArgs, '--environment', envName], { cwd: process.cwd(), env: process.env }),
      (err) => String(err.stderr || '').includes('NON_DEV_ENVIRONMENT_REFUSED'),
      `provisioning ${envName} without --allow-non-dev must fail closed`,
    );
  }

  // Item 9: Existing insecure keys folder (0755) is refused AND NOT chmod-ed.
  const insecureKeysDir = join(work, 'insecure-keys-dir');
  await mkdir(insecureKeysDir, { mode: 0o755 });
  await chmod(insecureKeysDir, 0o755);
  await assert.rejects(
    () => provisionCompanyDatabase({
      pgConfig: db.pgConfig,
      companySlug: 'acme',
      keysDir: insecureKeysDir,
      staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
    }),
    (err) => err?.code === 'INSECURE_KEYS_DIR',
    'existing non-0700 keys directory must be refused',
  );
  assert.equal((await stat(insecureKeysDir)).mode & 0o777, 0o755, 'must never chmod an existing keys directory');

  // Fresh provision in default environment dev.
  const run1 = await execFileAsync(process.execPath, commonArgs, { cwd: process.cwd(), env: process.env });
  const out1 = JSON.parse(run1.stdout);
  assert.equal(out1.changed, true);
  assert.equal(out1.environment, 'dev');
  assert.equal(out1.companySlug, 'acme');
  assert.equal(out1.displayName, 'Acme Health');
  assert.equal(out1.supportLabel, 'Nusear support');
  assert.equal(out1.migrations.applied.length, out1.migrations.total);
  assert.ok(out1.migrations.total >= 12);
  assert.equal(out1.iam.databaseContextCreated, true);
  assert.equal(out1.keys.length, 2);
  assert.ok(out1.keys.every((k) => k.created === true && k.environment === 'dev'));
  assert.equal(out1.invariants.passed, true);

  // Verify keys directory mode 0700, key files mode 0600, and secrets NEVER appear in stdout/stderr.
  assert.equal((await stat(keysDir)).mode & 0o777, 0o700, 'newly created keys directory must be mode 0700');
  const secrets = [];
  for (const keyMeta of out1.keys) {
    assert.equal('secretHex' in keyMeta, false);
    assert.equal('secretBytes' in keyMeta, false);
    assert.equal((await stat(keyMeta.filePath)).mode & 0o777, 0o600, `key file ${keyMeta.filePath} must be strictly mode 0600`);
    const keyDoc = await readKeyFile(keyMeta.filePath);
    assert.equal(keyDoc.keyId, keyMeta.keyId);
    assert.equal(keyDoc.environment, 'dev');
    assert.equal(keyDoc.companySlug, 'acme');
    assert.equal(keyDoc.secretBytes.length, 32);
    const hex = keyDoc.secretBytes.toString('hex');
    const b64 = keyDoc.secretBytes.toString('base64');
    keyDoc.secretBytes.fill(0);
    secrets.push(hex, b64);
    assert.equal(run1.stdout.includes(hex), false);
    assert.equal(run1.stderr.includes(hex), false);
    assert.equal(run1.stdout.includes(b64), false);
  }

  const pool = await createPool(db.pgConfig);
  try {
    const auditBefore = Number((await pool.query('SELECT pg_catalog.count(*)::int AS n FROM platform.audit_journal')).rows[0].n);
    const peopleBefore = Number((await pool.query('SELECT pg_catalog.count(*)::int AS n FROM iam.people')).rows[0].n);
    const grantsBefore = Number((await pool.query('SELECT pg_catalog.count(*)::int AS n FROM iam.role_grants')).rows[0].n);
    const keyContentsBefore = await Promise.all(out1.keys.map((k) => readFile(k.filePath, 'utf8')));

    // Second run changes NOTHING and says so.
    const run2 = await execFileAsync(process.execPath, commonArgs, { cwd: process.cwd(), env: process.env });
    const out2 = JSON.parse(run2.stdout);
    assert.equal(out2.changed, false);
    assert.match(out2.message, /no changes needed|already provisioned/i);
    assert.deepEqual(out2.migrations.applied, []);
    assert.equal(out2.iam.changed, false);
    assert.equal(out2.iam.auditJournalSeq, null);
    assert.ok(out2.keys.every((k) => k.created === false));
    assert.equal(out2.invariants.passed, true);
    for (const secret of secrets) {
      assert.equal(run2.stdout.includes(secret), false);
      assert.equal(run2.stderr.includes(secret), false);
    }

    assert.equal(Number((await pool.query('SELECT pg_catalog.count(*)::int AS n FROM platform.audit_journal')).rows[0].n), auditBefore);
    assert.equal(Number((await pool.query('SELECT pg_catalog.count(*)::int AS n FROM iam.people')).rows[0].n), peopleBefore);
    assert.equal(Number((await pool.query('SELECT pg_catalog.count(*)::int AS n FROM iam.role_grants')).rows[0].n), grantsBefore);
    assert.deepEqual(await Promise.all(out1.keys.map((k) => readFile(k.filePath, 'utf8'))), keyContentsBefore);

    // Item 10: Omitting displayName on rerun succeeds and reports stored displayName; mismatched displayName fails.
    const omittedNameRes = await provisionCompanyDatabase({
      pgConfig: db.pgConfig,
      companySlug: 'acme',
      environment: 'dev',
      keysDir,
      staff: [
        { role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' },
        { role: 'nusear_admin', email: 'admin@nusear.example', legalName: 'Morgan Admin' },
      ],
    });
    assert.equal(omittedNameRes.changed, false);
    assert.equal(omittedNameRes.displayName, 'Acme Health');

    await assert.rejects(
      () => provisionCompanyDatabase({
        pgConfig: db.pgConfig,
        companySlug: 'acme',
        displayName: 'Wrong Display Name',
        environment: 'dev',
        keysDir,
        staff: [
          { role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' },
          { role: 'nusear_admin', email: 'admin@nusear.example', legalName: 'Morgan Admin' },
        ],
      }),
      (err) => err?.code === 'PROVISION_DISPLAY_NAME_MISMATCH',
    );

    // Item 3: Pre-flight iam.database_context check refuses mismatch BEFORE touching role memberships.
    await withClusterCatalogLock(async () => {
      const probeLogin = `test_preflight_${randomBytes(4).toString('hex')}@nusear-dev.iam`;
      const logins = await createLoginRoles(db.adminConfig, [{ name: probeLogin }]);
      try {
        await assert.rejects(
          () => provisionCompanyDatabase({
            pgConfig: db.pgConfig,
            companySlug: 'other_co',
            environment: 'dev',
            keysDir,
            roleMappings: { app: probeLogin },
            staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
          }),
          (err) => err?.code === 'PROVISION_CONTEXT_MISMATCH',
        );
        const memAfter = await pool.query(
          `SELECT 1 FROM pg_catalog.pg_auth_members am
           JOIN pg_catalog.pg_roles m ON m.oid = am.member
           WHERE m.rolname = $1`,
          [probeLogin],
        );
        assert.equal(memAfter.rows.length, 0, 'pre-flight context mismatch must fail before granting any role membership');
      } finally {
        await logins.cleanup();
      }
    });

    // Item 9: Existing key file with wrong companySlug fails with KEY_FILE_MISMATCH.
    const staffKeyPath = out1.keys.find((k) => k.keyScope === 'nusear_staff').filePath;
    const origStaffKeyText = await readFile(staffKeyPath, 'utf8');
    try {
      const parsedKey = JSON.parse(origStaffKeyText);
      await writeFile(staffKeyPath, JSON.stringify({ ...parsedKey, companySlug: 'wrong_company' }, null, 2), { mode: 0o600 });
      await chmod(staffKeyPath, 0o600);
      await assert.rejects(
        () => provisionCompanyDatabase({
          pgConfig: db.pgConfig,
          companySlug: 'acme',
          displayName: 'Acme Health',
          environment: 'dev',
          keysDir,
          staff: [
            { role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' },
            { role: 'nusear_admin', email: 'admin@nusear.example', legalName: 'Morgan Admin' },
          ],
        }),
        (err) => err?.code === 'KEY_FILE_MISMATCH',
        'key file with wrong companySlug must be refused',
      );
    } finally {
      await writeFile(staffKeyPath, origStaffKeyText, { mode: 0o600 });
      await chmod(staffKeyPath, 0o600);
    }

    // Item 10: Revoking a tool switch leaves it revoked on rerun (does not re-enable or fail).
    const c = await pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const seq = (await c.query(
        `INSERT INTO platform.audit_journal (environment, actor_person_id, recorded_as, target_org_id, command_kind, command_key, request_sha256, body)
         VALUES ('dev', NULL, 'service', $1::uuid, 'test.revoke_switch', $2, $3, '{}'::jsonb) RETURNING seq`,
        [out1.iam.companyOrgId, `revoke-sw-${randomUUID()}`, sha256Hex('revoke-sw')],
      )).rows[0].seq;
      const curSw = (await c.query(
        `SELECT id FROM iam.organization_tool_switches
         WHERE organization_id = $1::uuid AND tool_id = 'coherence' AND superseded_by_id IS NULL`,
        [out1.iam.companyOrgId],
      )).rows[0];
      await c.query(
        `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, replaces_id, journal_seq)
         VALUES ($1, $2, 'coherence', 'off', 'revoked', $3, $4)`,
        [randomUUID(), out1.iam.companyOrgId, curSw.id, seq],
      );
      await c.query('COMMIT');
    } catch (err) {
      await c.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      c.release();
    }

    const afterRevokeRes = await provisionCompanyDatabase({
      pgConfig: db.pgConfig,
      companySlug: 'acme',
      displayName: 'Acme Health',
      environment: 'dev',
      keysDir,
      staff: [
        { role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' },
        { role: 'nusear_admin', email: 'admin@nusear.example', legalName: 'Morgan Admin' },
      ],
    });
    assert.equal(afterRevokeRes.changed, false, 'revoked tool switch must be left alone on rerun');
    const swStatus = (await pool.query(
      `SELECT switch_state, status FROM iam.organization_tool_switches
       WHERE organization_id = $1::uuid AND tool_id = 'coherence' AND superseded_by_id IS NULL`,
      [out1.iam.companyOrgId],
    )).rows[0];
    assert.equal(swStatus.status, 'revoked');
    assert.equal(swStatus.switch_state, 'off');

    // Item 10: Worker with conflicting active role grant must fail with WORKER_ROLE_CONFLICT.
    const c2 = await pool.connect();
    try {
      await c2.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const seq = (await c2.query(
        `INSERT INTO platform.audit_journal (environment, actor_person_id, recorded_as, target_org_id, command_kind, command_key, request_sha256, body)
         VALUES ('dev', NULL, 'service', $1::uuid, 'test.worker_conflict', $2, $3, '{}'::jsonb) RETURNING seq`,
        [out1.iam.rootOrgId, `wrk-conflict-${randomUUID()}`, sha256Hex('wrk-conflict')],
      )).rows[0].seq;
      const adminRoleId = (await c2.query("SELECT id FROM iam.roles WHERE slug = 'nusear_admin'")).rows[0].id;
      await c2.query(
        `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
         VALUES ($1, $2, $3, $4, true, 'org_subtree', '[2020-01-01,)'::daterange, 'active', $5)`,
        [randomUUID(), out1.iam.worker.personId, adminRoleId, out1.iam.rootOrgId, seq],
      );
      await c2.query('COMMIT');
    } catch (err) {
      await c2.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      c2.release();
    }
    await assert.rejects(
      () => provisionCompanyDatabase({
        pgConfig: db.pgConfig,
        companySlug: 'acme',
        displayName: 'Acme Health',
        environment: 'dev',
        keysDir,
        staff: [
          { role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' },
          { role: 'nusear_admin', email: 'admin@nusear.example', legalName: 'Morgan Admin' },
        ],
      }),
      (err) => err?.code === 'WORKER_ROLE_CONFLICT',
    );

    // Item 10: Inactive company organization must fail with PROVISION_ORG_INACTIVE.
    const inactiveDb = await createScratchDb('inactive_org');
    t.after(() => inactiveDb.drop());
    const inactiveKeys = join(work, 'keys-inactive');
    const inactProv = await provisionCompanyDatabase({
      pgConfig: inactiveDb.pgConfig,
      companySlug: 'acme',
      displayName: 'Acme Inactive Test',
      environment: 'dev',
      keysDir: inactiveKeys,
      staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
    });
    const inactPool = await createPool(inactiveDb.pgConfig);
    try {
      const c3 = await inactPool.connect();
      try {
        await c3.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
        const seq = (await c3.query(
          `INSERT INTO platform.audit_journal (environment, actor_person_id, recorded_as, target_org_id, command_kind, command_key, request_sha256, body)
           VALUES ('dev', NULL, 'service', $1::uuid, 'test.archive_co', $2, $3, '{}'::jsonb) RETURNING seq`,
          [inactProv.iam.companyOrgId, `arch-co-${randomUUID()}`, sha256Hex('arch-co')],
        )).rows[0].seq;
        const curOv = (await c3.query(
          `SELECT id FROM iam.organization_versions WHERE organization_id = $1::uuid AND superseded_by_id IS NULL`,
          [inactProv.iam.companyOrgId],
        )).rows[0];
        await c3.query(
          `INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, replaces_id, journal_seq)
           VALUES ($1, $2, 'acme', 'Acme Inactive Test', 'archived', $3, $4)`,
          [randomUUID(), inactProv.iam.companyOrgId, curOv.id, seq],
        );
        await c3.query('COMMIT');
      } catch (err) {
        await c3.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        c3.release();
      }
      await assert.rejects(
        () => provisionCompanyDatabase({
          pgConfig: inactiveDb.pgConfig,
          companySlug: 'acme',
          displayName: 'Acme Inactive Test',
          environment: 'dev',
          keysDir: inactiveKeys,
          staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
        }),
        (err) => err?.code === 'PROVISION_ORG_INACTIVE',
      );
    } finally {
      await inactPool.end();
    }
  } finally {
    await pool.end();
  }

  // Explicit --allow-non-dev succeeds on a separate scratch DB for environment local.
  const localDb = await createScratchDb('local_optin');
  t.after(() => localDb.drop());
  const localKeysDir = join(work, 'keys-local');
  const localRes = await provisionCompanyDatabase({
    pgConfig: localDb.pgConfig,
    companySlug: 'acme',
    displayName: 'Acme Local',
    environment: 'local',
    allowNonDev: true,
    keysDir: localKeysDir,
    staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
  });
  assert.equal(localRes.changed, true);
  assert.equal(localRes.environment, 'local');
  assert.equal(localRes.invariants.passed, true);
});

test('Provisioning [Runtime IAM LOGIN Roles, RESET ROLE / SET ROLE NONE, Withheld Admin & Expanded Catalog Invariants]: runtime user acts strictly as platform_app, RESET ROLE and SET ROLE NONE leave zero privileges, withheld nusear_admin only reads, and catalog audit catches every privilege/setting/ACL/owner/sequence/marker drift', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  await withClusterCatalogLock(async () => {
    const suffix = randomBytes(4).toString('hex');
    const work = await mkdtemp(join(tmpdir(), `coherence-prov-roles-${suffix}-`));
    t.after(() => rm(work, { recursive: true, force: true }));
    const keysDir = join(work, 'keys');

    const db = await createScratchDb('roles');
    const closeables = [];
    const track = (c) => { closeables.push(c); return c; };

    const appUser = `test_app_${suffix}@nusear-dev.iam`;
    const workerUser = `test_wrk_${suffix}@nusear-dev.iam`;
    const roUser = `test_ro_${suffix}@nusear-dev.iam`;
    const replUser = `test_repl_${suffix}@nusear-dev.iam`;
    const logins = await createLoginRoles(db.adminConfig, [
      { name: appUser },
      { name: workerUser },
      { name: roUser },
      { name: replUser, attrs: 'LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS REPLICATION INHERIT' },
    ]);
    const adminClient = track(await createClient(db.adminConfig));
    const createdMarkerRoles = [];
    try {
      const existingMarker = (await adminClient.query("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'cloudsqliamserviceaccount'")).rows.length > 0;
      if (!existingMarker) {
        await adminClient.query('CREATE ROLE cloudsqliamserviceaccount NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION NOINHERIT');
        createdMarkerRoles.push('cloudsqliamserviceaccount');
      }

      // Item 5: ensureRuntimeRoleMappings refuses REPLICATION on mapped runtime login user.
      await assert.rejects(
        () => provisionCompanyDatabase({
          pgConfig: db.pgConfig,
          companySlug: 'acme',
          displayName: 'Acme Health',
          environment: 'dev',
          keysDir,
          staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
          roleMappings: { app: replUser },
        }),
        (err) => err?.code === 'PRIVILEGED_RUNTIME_DB_USER',
        'REPLICATION runtime login user must be refused in ensureRuntimeRoleMappings',
      );

      const prov = await provisionCompanyDatabase({
        pgConfig: db.pgConfig,
        companySlug: 'acme',
        displayName: 'Acme Health',
        environment: 'dev',
        keysDir,
        staff: [
          { role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' },
          { role: 'nusear_admin', email: 'admin@nusear.example', legalName: 'Morgan Admin' },
        ],
        roleMappings: { app: appUser, worker: workerUser, readonly: roUser },
      });
      assert.equal(prov.changed, true);
      assert.equal(prov.invariants.passed, true);
      assert.equal(prov.invariants.mappedRuntimeUsers, 3);

      // Item 5: ensureRuntimeRoleMappings refuses non-compliant platform-role row (inherit/admin/missing set).
      const adminPool = track(await createPool(db.pgConfig));
      await adminPool.query(`GRANT platform_app TO ${quoteIdent(appUser)} WITH ADMIN FALSE, INHERIT TRUE, SET TRUE`);
      try {
        await assert.rejects(
          () => provisionCompanyDatabase({
            pgConfig: db.pgConfig,
            companySlug: 'acme',
            displayName: 'Acme Health',
            environment: 'dev',
            keysDir,
            staff: [
              { role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' },
              { role: 'nusear_admin', email: 'admin@nusear.example', legalName: 'Morgan Admin' },
            ],
            roleMappings: { app: appUser, worker: workerUser, readonly: roUser },
          }),
          (err) => err?.code === 'CONFLICTING_ROLE_MEMBERSHIP',
          'ensureRuntimeRoleMappings must refuse INHERIT TRUE row for target platform role',
        );
      } finally {
        await adminPool.query(`GRANT platform_app TO ${quoteIdent(appUser)} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE`);
      }

      const staffKey = await readKeyFile(prov.keys.find((k) => k.keyScope === 'nusear_staff').filePath);
      const svcKey = await readKeyFile(prov.keys.find((k) => k.keyScope === 'service').filePath);
      const ownerPersonId = prov.iam.staff.find((s) => s.role === 'nusear_owner').personId;
      const adminPersonId = prov.iam.staff.find((s) => s.role === 'nusear_admin').personId;
      const workerPersonId = prov.iam.worker.personId;

      const ownerToken = mintSignedSessionToken({ keyId: staffKey.keyId, secretBytes: staffKey.secretBytes, environment: 'dev', actorPersonId: ownerPersonId });
      const wrongEnvToken = mintSignedSessionToken({ keyId: staffKey.keyId, secretBytes: staffKey.secretBytes, environment: 'prod', actorPersonId: ownerPersonId });
      const withheldAdminToken = mintSignedSessionToken({ keyId: staffKey.keyId, secretBytes: staffKey.secretBytes, environment: 'dev', actorPersonId: adminPersonId });
      const workerToken = mintSignedSessionToken({ keyId: svcKey.keyId, secretBytes: svcKey.secretBytes, environment: 'dev', actorPersonId: workerPersonId });
      staffKey.secretBytes.fill(0);
      svcKey.secretBytes.fill(0);

      // 1. Bare connection without '-c role=platform_app' fails closed; cannot SET ROLE to any other role.
      const appBareClient = track(await createClient({
        mode: 'local', host: '127.0.0.1', port: PG_PORT, database: db.dbName,
        user: appUser, password: logins.byName.get(appUser).password,
      }));
      assert.equal((await appBareClient.query('SELECT current_user')).rows[0].current_user, appUser);
      for (const sql of [
        'SELECT * FROM app_views.iam_my_context',
        'SELECT * FROM coherence.runs LIMIT 1',
        'SELECT * FROM iam.database_context',
        'SELECT * FROM iam_secret.signing_keys',
      ]) {
        await assert.rejects(() => appBareClient.query(sql), (err) => err?.code === '42501');
      }
      for (const forbiddenRole of ['platform_worker', 'platform_readonly', 'platform_writer', 'platform_view_owner', 'platform_migrator']) {
        await assert.rejects(() => appBareClient.query(`SET ROLE ${quoteIdent(forbiddenRole)}`), (err) => err?.code === '42501');
      }

      // Item 13: RESET ROLE and SET ROLE NONE on a startup-role platform_app session leave no extra/elevated privileges:
      // - RESET ROLE resets to the startup parameter value ('platform_app'), leaving zero base-table privileges and
      //   zero unauthenticated view/command access (no escalation to session_user or any other role).
      // - SET ROLE NONE drops current_user to session_user (appUser), leaving zero privileges across ALL managed schemas.
      // - On a bare session that runs SET ROLE platform_app, RESET ROLE drops back to appUser with zero privileges.
      const appSessionClient = track(await createClient({
        mode: 'local', host: '127.0.0.1', port: PG_PORT, database: db.dbName,
        user: appUser, password: logins.byName.get(appUser).password, role: 'platform_app',
      }));
      assert.equal((await appSessionClient.query('SELECT current_user')).rows[0].current_user, 'platform_app');
      await appSessionClient.query('RESET ROLE');
      assert.equal((await appSessionClient.query('SELECT current_user')).rows[0].current_user, 'platform_app');
      for (const sql of [
        'SELECT * FROM coherence.runs LIMIT 1',
        'SELECT * FROM iam.database_context',
        'SELECT * FROM iam_secret.signing_keys',
        'SELECT app_cmd.coherence_authorize_check_run()',
      ]) {
        await assert.rejects(() => appSessionClient.query(sql), (err) => err?.code === '42501', `after RESET ROLE on startup-role session, ${sql} must fail closed`);
      }
      assert.equal((await appSessionClient.query('SELECT * FROM app_views.iam_my_context')).rows.length, 0, 'after RESET ROLE without signed token, app_views returns 0 rows');

      await appSessionClient.query('SET ROLE NONE');
      assert.equal((await appSessionClient.query('SELECT current_user')).rows[0].current_user, appUser);
      for (const sql of [
        'SELECT * FROM app_views.iam_my_context',
        'SELECT * FROM coherence.runs LIMIT 1',
        'SELECT * FROM iam.database_context',
        'SELECT app_cmd.coherence_authorize_check_run()',
      ]) {
        await assert.rejects(() => appSessionClient.query(sql), (err) => err?.code === '42501', `after SET ROLE NONE, ${sql} must fail closed with zero privileges`);
      }

      // On a bare session (no startup role), SET ROLE platform_app then RESET ROLE returns to appUser with zero privileges.
      await appBareClient.query('SET ROLE platform_app');
      assert.equal((await appBareClient.query('SELECT current_user')).rows[0].current_user, 'platform_app');
      await appBareClient.query('RESET ROLE');
      assert.equal((await appBareClient.query('SELECT current_user')).rows[0].current_user, appUser);
      for (const sql of [
        'SELECT * FROM app_views.iam_my_context',
        'SELECT * FROM coherence.runs LIMIT 1',
        'SELECT * FROM iam.database_context',
        'SELECT app_cmd.coherence_authorize_check_run()',
      ]) {
        await assert.rejects(() => appBareClient.query(sql), (err) => err?.code === '42501', `after SET ROLE + RESET ROLE on bare session, ${sql} must fail closed`);
      }

      // 2. Startup-role platform_app: zero base-table reads, owner works, withheld admin only reads.
      const appPool = track(await createPool({
        mode: 'local', host: '127.0.0.1', port: PG_PORT, database: db.dbName,
        user: appUser, password: logins.byName.get(appUser).password, role: 'platform_app',
      }));
      for (const baseSql of [
        'SELECT * FROM coherence.runs LIMIT 1',
        'SELECT * FROM coherence.bob_policies LIMIT 1',
        'SELECT * FROM iam.people LIMIT 1',
        'SELECT * FROM iam_secret.signing_keys LIMIT 1',
        'SELECT * FROM platform.audit_journal LIMIT 1',
      ]) {
        await assert.rejects(() => appPool.query(baseSql), (err) => err?.code === '42501');
      }
      assert.equal((await inReadTx(appPool, wrongEnvToken, (c) => c.query('SELECT * FROM app_views.iam_my_context'))).rows.length, 0);
      const ownerCtx = await inReadTx(appPool, ownerToken, (c) => c.query('SELECT actor_person_id, environment, company_slug FROM app_views.iam_my_context'));
      assert.equal(ownerCtx.rows[0].actor_person_id, ownerPersonId);

      const appCommands = createAppCommands({ pool: appPool });
      const iamCommands = createIamCommands({ pool: appPool });
      const initRes = await appCommands.initCompany({
        dbToken: ownerToken, commandKey: 'prov-test-init-acme', slug: 'acme', displayName: 'Acme Health', defaultEmitMode: 'coherence',
      });
      assert.equal(initRes.idempotent, false);

      // Withheld admin reads work, writes fail with 403.
      const adminCtx = await inReadTx(appPool, withheldAdminToken, async (c) => ({
        me: (await c.query('SELECT actor_person_id FROM app_views.iam_my_context')).rows,
        orgs: (await c.query('SELECT slug FROM app_views.iam_organizations')).rows,
      }));
      assert.equal(adminCtx.me[0].actor_person_id, adminPersonId);
      assert.ok(adminCtx.orgs.some((o) => o.slug === 'acme'));
      await assert.rejects(
        () => iamCommands.createOrganization({
          dbToken: withheldAdminToken, commandKey: 'withheld-admin-org', orgKind: 'agency',
          slug: 'unauthorized_agency', displayName: 'Unauthorized Agency', parentOrgId: prov.iam.companyOrgId,
        }),
        (err) => err?.status === 403,
      );

      // Worker & readonly login roles enter strictly platform_worker / platform_readonly.
      const workerPool = track(await createPool({
        mode: 'local', host: '127.0.0.1', port: PG_PORT, database: db.dbName,
        user: workerUser, password: logins.byName.get(workerUser).password, role: 'platform_worker',
      }));
      assert.equal((await workerPool.query('SELECT current_user AS u')).rows[0].u, 'platform_worker');
      await assert.rejects(
        () => createAppCommands({ pool: workerPool }).initCompany({
          dbToken: workerToken, commandKey: 'worker-forbid-init', slug: 'acme', displayName: 'Acme Health',
        }),
        (err) => err?.status === 403,
      );
      const roPool = track(await createPool({
        mode: 'local', host: '127.0.0.1', port: PG_PORT, database: db.dbName,
        user: roUser, password: logins.byName.get(roUser).password, role: 'platform_readonly',
      }));
      assert.equal((await roPool.query('SELECT current_user AS u')).rows[0].u, 'platform_readonly');
      await assert.rejects(() => roPool.query('SELECT app_cmd.coherence_authorize_check_run()'), (err) => err?.code === '42501');

      // 3. Expanded negative catalog invariant probes (Items 1, 4, 5):
      const probeFail = async (label, setupSql, teardownSql, matcher) => {
        await adminPool.query(setupSql);
        try {
          const bad = await verifyIamConfigInvariants(adminPool);
          assert.equal(bad.passed, false, `verifyIamConfigInvariants must fail for: ${label}`);
          assert.ok(bad.problems.some((p) => matcher.test(p)), `expected problem matching ${matcher} for "${label}", got: ${bad.problems.join('; ')}`);
        } finally {
          await adminPool.query(teardownSql);
        }
      };

      // Item 1: misowned coherence.run_effective_statement_batches & coherence.run_states
      await probeFail(
        'misowned run_effective_statement_batches',
        `ALTER FUNCTION coherence.run_effective_statement_batches(UUID) OWNER TO ${quoteIdent(db.pgConfig.user)}`,
        'ALTER FUNCTION coherence.run_effective_statement_batches(UUID) OWNER TO platform_readonly',
        /run_effective_statement_batches/i,
      );
      await probeFail(
        'misowned coherence.run_states',
        `ALTER VIEW coherence.run_states OWNER TO ${quoteIdent(db.pgConfig.user)}`,
        'ALTER VIEW coherence.run_states OWNER TO platform_readonly',
        /run_states/i,
      );

      // Item 4: non-migrator platform role holding CREATE on managed schema
      for (const roleName of ['platform_readonly', 'platform_worker', 'platform_view_owner', 'platform_writer', 'platform_versioner']) {
        await probeFail(
          `${roleName} CREATE on coherence`,
          `GRANT CREATE ON SCHEMA coherence TO ${roleName}`,
          `REVOKE CREATE ON SCHEMA coherence FROM ${roleName}`,
          new RegExp(`${roleName}.*CREATE.*coherence`, 'i'),
        );
      }

      // Item 5: REPLICATION on mapped runtime user
      await probeFail(
        'REPLICATION on mapped runtime login user',
        `ALTER ROLE ${quoteIdent(appUser)} REPLICATION`,
        `ALTER ROLE ${quoteIdent(appUser)} NOREPLICATION`,
        new RegExp(`${appUser}.*replication=true`, 'i'),
      );

      // Item 5: pg_db_role_setting database-wide (setrole=0) and platform_worker
      await probeFail(
        'database-wide app.session_token (setrole=0)',
        `ALTER DATABASE ${quoteIdent(db.dbName)} SET app.session_token = 'forged'`,
        `ALTER DATABASE ${quoteIdent(db.dbName)} RESET app.session_token`,
        /setrole=0.*app\.session_token/i,
      );
      await probeFail(
        'platform_worker app.session_token in pg_db_role_setting',
        `ALTER ROLE platform_worker IN DATABASE ${quoteIdent(db.dbName)} SET app.session_token = 'forged'`,
        `ALTER ROLE platform_worker IN DATABASE ${quoteIdent(db.dbName)} RESET app.session_token`,
        /platform_worker.*app\.session_token/i,
      );

      // Item 5: pg_default_acl in managed schema
      await probeFail(
        'pg_default_acl in coherence',
        'ALTER DEFAULT PRIVILEGES IN SCHEMA coherence GRANT SELECT ON TABLES TO platform_app',
        'ALTER DEFAULT PRIVILEGES IN SCHEMA coherence REVOKE SELECT ON TABLES FROM platform_app',
        /pg_default_acl/i,
      );

      // Item 5: Database owner, CREATE on database, and CREATE on schema public
      await probeFail(
        'database owned by mapped runtime login user',
        `ALTER DATABASE ${quoteIdent(db.dbName)} OWNER TO ${quoteIdent(appUser)}`,
        `ALTER DATABASE ${quoteIdent(db.dbName)} OWNER TO ${quoteIdent(db.pgConfig.user)}`,
        new RegExp(`Database.*must not be owned by ${appUser}`, 'i'),
      );
      await probeFail(
        'CREATE on database for platform_app',
        `GRANT CREATE ON DATABASE ${quoteIdent(db.dbName)} TO platform_app`,
        `REVOKE CREATE ON DATABASE ${quoteIdent(db.dbName)} FROM platform_app`,
        /platform_app.*CREATE on database/i,
      );
      await probeFail(
        'CREATE on schema public for appUser',
        `GRANT CREATE ON SCHEMA public TO ${quoteIdent(appUser)}`,
        `REVOKE CREATE ON SCHEMA public FROM ${quoteIdent(appUser)}`,
        new RegExp(`${appUser}.*CREATE on schema public`, 'i'),
      );

      // Item 5: sequences in managed schema
      await probeFail(
        'sequence privilege for platform_app',
        'CREATE SEQUENCE coherence._audit_seq_probe; GRANT USAGE ON SEQUENCE coherence._audit_seq_probe TO platform_app;',
        'DROP SEQUENCE IF EXISTS coherence._audit_seq_probe;',
        /_audit_seq_probe/i,
      );

      // Item 5: IAM marker role privilege in managed schema
      await probeFail(
        'IAM marker role privilege on coherence schema',
        'GRANT USAGE ON SCHEMA coherence TO cloudsqliamserviceaccount',
        'REVOKE USAGE ON SCHEMA coherence FROM cloudsqliamserviceaccount',
        /cloudsqliamserviceaccount.*coherence/i,
      );

      const cleanAudit = await verifyIamConfigInvariants(adminPool);
      assert.equal(cleanAudit.passed, true, `expected clean audit after cleanup, got: ${cleanAudit.problems.join('; ')}`);
    } finally {
      for (const c of closeables) {
        await c.end().catch(() => {});
      }
      await db.drop();
      await logins.cleanup();
      if (createdMarkerRoles.length > 0) {
        const dropC = await createClient(db.adminConfig).catch(() => null);
        if (dropC) {
          for (const r of createdMarkerRoles) {
            await dropC.query(`DROP ROLE IF EXISTS ${quoteIdent(r)}`).catch(() => {});
          }
          await dropC.end().catch(() => {});
        }
      }
    }
  });
});

test('Provisioning [Real Cloud SQL Non-Superuser Ephemeral PG17 Cluster]: cloudsqlsuperuser creates all platform_* roles itself under createrole_self_grant=set,inherit, cleans stray grants on 0-migration rerun with zero empty pg_auth_members rows, executes app_cmd writes, history import, Emit materialization/statement reconciliation, and coherence.run_states reads under FORCE RLS', { skip: !findPg17BinDir() && 'PostgreSQL 17 initdb/pg_ctl not found' }, async (t) => {
  const cluster = await startEphemeralPg17Cluster({
    extraPostgresOpts: ["-c createrole_self_grant='set,inherit'"],
  });
  t.after(() => cluster.stop());

  const work = await mkdtemp(join(tmpdir(), 'coherence-ephem-csql-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const keysDir = join(work, 'keys');
  const storesDir = join(work, 'stores');

  const admin = await createClient(cluster.adminConfig);
  const migratorUser = 'admin@nusear.example';
  const migratorPw = `pw_${randomBytes(12).toString('hex')}`;
  const appUser = 'nusear-app-dev@nusear-control-dev.iam';
  const roUser = 'nusear-readonly-dev@nusear-control-dev.iam';
  const workerUser = 'nusear-worker-dev@nusear-control-dev.iam';
  const runtimePw = `pw_${randomBytes(12).toString('hex')}`;

  try {
    // ZERO platform_* roles exist in this brand-new cluster! cloudsqlsuperuser creates them itself!
    await admin.query('CREATE ROLE cloudsqlsuperuser NOLOGIN NOSUPERUSER CREATEROLE CREATEDB NOINHERIT NOBYPASSRLS NOREPLICATION');
    await admin.query('CREATE ROLE cloudsqliamuser NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOINHERIT NOBYPASSRLS NOREPLICATION');
    await admin.query('CREATE ROLE cloudsqliamserviceaccount NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOINHERIT NOBYPASSRLS NOREPLICATION');

    await admin.query(`CREATE ROLE ${quoteIdent(migratorUser)} LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION INHERIT PASSWORD '${migratorPw}'`);
    await admin.query(`GRANT cloudsqliamuser TO ${quoteIdent(migratorUser)} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE`);
    await admin.query(`GRANT cloudsqlsuperuser TO ${quoteIdent(migratorUser)} WITH ADMIN FALSE, INHERIT TRUE, SET TRUE`);

    for (const u of [appUser, roUser, workerUser]) {
      await admin.query(`CREATE ROLE ${quoteIdent(u)} LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION INHERIT PASSWORD '${runtimePw}'`);
      await admin.query(`GRANT cloudsqliamserviceaccount TO ${quoteIdent(u)} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE`);
    }

    // Create company database named 'acme' owned by cloudsqlsuperuser (matches Cloud SQL).
    await admin.query("CREATE DATABASE acme ENCODING 'UTF8' OWNER cloudsqlsuperuser");
  } finally {
    await admin.end();
  }

  const migratorPgConfig = {
    mode: 'local',
    host: cluster.socketDir,
    port: cluster.port,
    database: 'acme',
    user: migratorUser,
    password: migratorPw,
  };

  // Run 1: Fresh provision strictly as non-superuser IAM migrator -> switches to cloudsqlsuperuser,
  // creates all 9 platform_* roles itself with createrole_self_grant='', applies migrations 001..012,
  // maps runtime users, seeds IAM, and passes verifyIamConfigInvariants.
  const r1 = await provisionCompanyDatabase({
    pgConfig: migratorPgConfig,
    companySlug: 'acme',
    displayName: 'Acme Cloud Dev',
    environment: 'dev',
    keysDir,
    staff: [
      { role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' },
      { role: 'nusear_admin', email: 'admin@nusear.example', legalName: 'Morgan Admin' },
    ],
    roleMappings: { app: appUser, readonly: roUser, worker: workerUser },
  });
  assert.equal(r1.changed, true);
  assert.equal(r1.migratorRole, 'cloudsqlsuperuser');
  assert.equal(r1.migrations.applied.length, r1.migrations.total);
  assert.ok(r1.migrations.applied.includes('012_definer_read_owners.sql'));
  assert.equal(r1.invariants.passed, true);

  // Verify ZERO empty or self-granted pg_auth_members rows remain for cloudsqlsuperuser (Item 4).
  const checkAdmin = await createClient({ ...cluster.adminConfig, database: 'acme' });
  try {
    const csqlMem = (await checkAdmin.query(
      `SELECT r.rolname AS role_name, g.rolname AS grantor, am.admin_option, am.inherit_option, am.set_option
       FROM pg_catalog.pg_auth_members am
       JOIN pg_catalog.pg_roles r ON r.oid = am.roleid
       JOIN pg_catalog.pg_roles m ON m.oid = am.member
       JOIN pg_catalog.pg_roles g ON g.oid = am.grantor
       WHERE m.rolname = 'cloudsqlsuperuser' AND r.rolname = ANY($1::text[])
       ORDER BY r.rolname`,
      [PLATFORM_ROLES],
    )).rows;
    assert.equal(csqlMem.length, PLATFORM_ROLES.length, 'exactly one bootstrap pg_auth_members row per platform role');
    for (const row of csqlMem) {
      assert.equal(row.admin_option, true);
      assert.equal(row.inherit_option, false);
      assert.equal(row.set_option, false);
      assert.notEqual(row.grantor, 'cloudsqlsuperuser', 'no self-granted or empty pg_auth_members row may remain');
    }

    // Item 4: Simulate stray temporary migration grants left behind when 0 migrations remain;
    // re-running provisionCompanyDatabase must remove them cleanly and pass invariants.
    const csqlClient = await createClient({ ...migratorPgConfig, role: 'cloudsqlsuperuser' });
    try {
      await csqlClient.query('GRANT platform_readonly TO cloudsqlsuperuser WITH SET TRUE, INHERIT TRUE');
      await csqlClient.query('GRANT CREATE ON SCHEMA coherence TO platform_readonly');
    } finally {
      await csqlClient.end();
    }

    const r2 = await provisionCompanyDatabase({
      pgConfig: migratorPgConfig,
      companySlug: 'acme',
      displayName: 'Acme Cloud Dev',
      environment: 'dev',
      keysDir,
      staff: [
        { role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' },
        { role: 'nusear_admin', email: 'admin@nusear.example', legalName: 'Morgan Admin' },
      ],
      roleMappings: { app: appUser, readonly: roUser, worker: workerUser },
    });
    assert.equal(r2.changed, false);
    assert.equal(r2.invariants.passed, true);

    const selfRowsAfter = (await checkAdmin.query(
      `SELECT 1 FROM pg_catalog.pg_auth_members am
       JOIN pg_catalog.pg_roles m ON m.oid = am.member
       JOIN pg_catalog.pg_roles g ON g.oid = am.grantor
       WHERE m.rolname = 'cloudsqlsuperuser' AND g.rolname = 'cloudsqlsuperuser'`,
    )).rows;
    assert.equal(selfRowsAfter.length, 0, 'stray self-granted pg_auth_members rows must be deleted on 0-migration rerun');

    // Item 3 & 5 on non-superuser DB:
    // (a) Pre-flight iam.database_context guard works under FORCE RLS (via temporary platform_readonly SET + clean revoke)
    //     and refuses context mismatch before touching role memberships or leaving stray rows.
    await assert.rejects(
      () => provisionCompanyDatabase({
        pgConfig: migratorPgConfig,
        companySlug: 'acme',
        displayName: 'Acme Cloud Dev',
        environment: 'dev',
        supportLabel: 'Wrong Support Label',
        keysDir,
        staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
      }),
      (err) => err?.code === 'PROVISION_CONTEXT_MISMATCH',
    );
    const selfRowsAfterGuard = (await checkAdmin.query(
      `SELECT 1 FROM pg_catalog.pg_auth_members am
       JOIN pg_catalog.pg_roles m ON m.oid = am.member
       JOIN pg_catalog.pg_roles g ON g.oid = am.grantor
       WHERE m.rolname = 'cloudsqlsuperuser' AND g.rolname = 'cloudsqlsuperuser'`,
    )).rows;
    assert.equal(selfRowsAfterGuard.length, 0, 'pre-flight context check must revoke temporary platform_readonly row cleanly');

    // (b) Multi-grantor conflict: second grantor adding an INHERIT TRUE row alongside cloudsqlsuperuser's clean row
    //     must fail BOTH ensureRuntimeRoleMappings AND verifyIamConfigInvariants.
    await checkAdmin.query(`GRANT platform_app TO ${quoteIdent(appUser)} WITH ADMIN FALSE, INHERIT TRUE, SET TRUE`);
    try {
      await assert.rejects(
        () => provisionCompanyDatabase({
          pgConfig: migratorPgConfig,
          companySlug: 'acme',
          displayName: 'Acme Cloud Dev',
          environment: 'dev',
          keysDir,
          staff: [
            { role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' },
            { role: 'nusear_admin', email: 'admin@nusear.example', legalName: 'Morgan Admin' },
          ],
          roleMappings: { app: appUser, readonly: roUser, worker: workerUser },
        }),
        (err) => err?.code === 'CONFLICTING_ROLE_MEMBERSHIP',
        'multi-grantor non-compliant row on target platform role must fail ensureRuntimeRoleMappings',
      );
      const multiBad = await verifyIamConfigInvariants(checkAdmin);
      assert.equal(multiBad.passed, false);
      assert.ok(multiBad.problems.some((p) => /pg_auth_members/i.test(p)), 'the audit names the multi-grantor membership row');
    } finally {
      await checkAdmin.query(`REVOKE platform_app FROM ${quoteIdent(appUser)} GRANTED BY ${quoteIdent(cluster.adminConfig.user)}`);
    }
  } finally {
    await checkAdmin.end();
  }

  // Item 1 & 13: Prove app_cmd write, history import, Emit materialization + statement reconciliation,
  // coherence.run_effective_statement_batches(uuid), and coherence.run_states on this real non-superuser DB!
  const appPool = await createPool({
    mode: 'local', host: cluster.socketDir, port: cluster.port, database: 'acme',
    user: appUser, password: runtimePw, role: 'platform_app',
  });
  const roPool = await createPool({
    mode: 'local', host: cluster.socketDir, port: cluster.port, database: 'acme',
    user: roUser, password: runtimePw, role: 'platform_readonly',
  });
  const workerPool = await createPool({
    mode: 'local', host: cluster.socketDir, port: cluster.port, database: 'acme',
    user: workerUser, password: runtimePw, role: 'platform_worker',
  });

  try {
    const staffKeyFile = r1.keys.find((k) => k.keyScope === 'nusear_staff').filePath;
    const svcKeyFile = r1.keys.find((k) => k.keyScope === 'service').filePath;
    const staffKey = await readKeyFile(staffKeyFile);
    const svcKey = await readKeyFile(svcKeyFile);
    const ownerId = r1.iam.staff.find((s) => s.role === 'nusear_owner').personId;
    const workerId = r1.iam.worker.personId;
    const ownerTok = mintSignedSessionToken({ keyId: staffKey.keyId, secretBytes: staffKey.secretBytes, environment: 'dev', actorPersonId: ownerId });
    const workerTok = mintSignedSessionToken({ keyId: svcKey.keyId, secretBytes: svcKey.secretBytes, environment: 'dev', actorPersonId: workerId });
    staffKey.secretBytes.fill(0);
    svcKey.secretBytes.fill(0);

    // 1. app_cmd writes on non-superuser DB (create agency Beacon & agent Sam Seller so Emit resolves FKs).
    const iamCommands = createIamCommands({ pool: appPool });
    const agRes = await iamCommands.createOrganization({
      dbToken: ownerTok,
      commandKey: 'csql-create-beacon',
      orgKind: 'agency',
      slug: 'beacon',
      displayName: 'Beacon',
      parentOrgId: r1.iam.companyOrgId,
    });
    assert.equal(agRes.idempotent, false);
    const personRes = await iamCommands.createPerson({
      dbToken: ownerTok,
      commandKey: 'csql-create-agent',
      organizationId: agRes.result.organizationId,
      legalName: 'Sam Seller',
      preferredName: 'Sam Seller',
      primaryEmail: 'sam.seller@acme.example',
      npn: '11111111',
      workArrangement: 'self_employed_internal',
      validRange: '[2020-01-01,)',
    });
    assert.equal(personRes.idempotent, false);

    // 2. Full read-only history import strictly as platform_app + platform_readonly on non-superuser DB.
    const { manifestPath } = await buildHistoryFixtures(work);
    await mkdir(join(storesDir, 'code'), { recursive: true, mode: 0o700 });
    await mkdir(join(storesDir, 'data'), { recursive: true, mode: 0o700 });
    const stores = createStorePair({
      codeStore: createCodeStore({ backend: createFileObjectStore({ rootDir: join(storesDir, 'code'), label: 'csql-code' }) }),
      dataStore: createDataStore({ backend: createFileObjectStore({ rootDir: join(storesDir, 'data'), label: 'csql-data' }) }),
    });

    const imp = await importHistoryIntoDatabase({
      readPool: roPool,
      appPool,
      stores,
      manifestPath,
      keyFile: staffKeyFile,
      actorEmail: 'owner@nusear.example',
      allowScratchDatabase: false,
    });
    assert.equal(imp.passed, true, `non-superuser history import failed: ${JSON.stringify(imp.problems)}`);
    assert.equal(imp.layer1.importedRunCount, 2);
    assert.equal(imp.comparator.passed, true);

    // 3. Read coherence.run_states as platform_readonly AND platform_worker (proving Migration 012 under FORCE RLS).
    const roRunStates = (await roPool.query('SELECT id, source_folder, stage FROM coherence.run_states ORDER BY source_folder')).rows;
    const wrkRunStates = (await workerPool.query('SELECT id, source_folder, stage FROM coherence.run_states ORDER BY source_folder')).rows;
    assert.equal(roRunStates.length, 2, 'coherence.run_states must return imported runs as platform_readonly on non-superuser DB');
    assert.equal(wrkRunStates.length, 2, 'coherence.run_states must return imported runs as platform_worker on non-superuser DB');
    assert.ok(roRunStates.every((r) => typeof r.stage === 'string' && r.stage.length > 0));

    // 4. Import a company_import run via app_cmd as platform_app, materialize its Emit as platform_worker
    //    (triggers trg_run_materializations_verify_deferred -> coherence.run_effective_statement_batches(uuid)
    //    under FORCE RLS), carry sent, and verify app_views statement reconciliation + run batches!
    const matBobCsv = [
      'policy_id,external_policy_id,carrier,mbi,member,state,plan_type,simple_plan_type,submission_date,origin_effective,effective_date,termination_date,writing_npn,writing_agent,entity,status,coherent_status,amount,upline_amount',
      '1,EXT-1,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,11111111,Sam Seller,Beacon,ACTIVE_PAYING,ACTIVE,80.00,20.00',
    ].join('\n') + '\n';
    const matLedCsv = [
      'tx_id,record_id,external_policy_id,policy_id,statement_name,src_type,carrier,mbi,member,state,plan_type,simple_plan_type,submission_date,origin_effective,effective_date,termination_date,earned_date,payment_date,statement_date,min_date,gross_comm,revenue_type,override_amount,commission_amount,hra_amount,fee_amount,other_amount,downline_amount,upline_amount,writing_npn,writing_agent,entity,payee_npn,agency_id,status,policy_status,cbob_c,cbob_s,sf,notes,coherent_notes,sheet_name,source_row_no',
      '1,carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11,EXT-1,1,stmt_nov,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,2026-11-01,2026-11-09,2026-11-09,2026-10-01,100.00,commission,,100.00,,,,80.00,20.00,11111111,Sam Seller,Beacon,11111111,beacon,ACTIVE_PAYING,active,1,1,1,,,Sheet1,2',
    ].join('\n') + '\n';
    const matStmtCsv = [
      'tx_id,record_id,external_policy_id,policy_id,statement_name,src_type,carrier,mbi,member,state,plan_type,simple_plan_type,submission_date,origin_effective,effective_date,earned_date,payment_date,statement_date,run_statement_date,gross_comm,revenue_type,downline_amount,upline_amount,writing_npn,writing_agent,entity,run_action',
      '1,carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11,EXT-1,1,stmt_nov,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,2026-11-01,2026-11-09,2026-11-09,2026-11-09,100.00,commission,80.00,20.00,11111111,Sam Seller,Beacon,NEW',
    ].join('\n') + '\n';

    const inpFile = await stores.dataStore.promoteBytes(
      Buffer.from('k\ncsql-emit\n', 'utf8'),
      { relPath: 'csql_emit_in.csv', checksPassed: true },
    );
    const stmtArt = await stores.promoteArtifact(
      'emits/statements_20261109.csv',
      Buffer.from(matStmtCsv, 'utf8'),
      { checksPassed: true },
    );
    const appCommands = createAppCommands({ pool: appPool, stores });
    const coRun = await appCommands.importHistoricalRun({
      dbToken: ownerTok,
      commandKey: 'csql-company-run-2026-11-09',
      run: {
        origin: 'company_import',
        statementDate: '2026-11-09',
        sourceFolder: 'company-workspaces/acme/2026-11-09/runs/2026-11-09',
        emitMode: 'coherence',
      },
      inputVersion: { reason: 'csql non-superuser emit test' },
      inputEntries: [{ relPath: 'csql_emit_in.csv', fileSha256: inpFile.sha256 }],
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
    const emitRunId = coRun.result.runId;
    const emitEvId = (await roPool.query(
      "SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev",
      [emitRunId],
    )).rows[0].ev;
    assert.ok(emitEvId, 'expected finished emit attempt for company_import run');

    const workerCommands = createAppCommands({ pool: workerPool, stores });
    const matRes = await workerCommands.materializeEmit({
      dbToken: workerTok,
      commandKey: 'csql-mat-2026-11-09',
      runId: emitRunId,
      attemptEventId: emitEvId,
      statementDate: '2026-11-09',
      canonicalBobCsv: matBobCsv,
      coherentLedgerCsv: matLedCsv,
      statementsCsv: matStmtCsv,
    });
    assert.equal(matRes.idempotent, false);

    // coherence.run_effective_statement_batches(uuid) MUST return the run's batch as platform_readonly!
    const effBatches = (await roPool.query(
      'SELECT batch_id FROM coherence.run_effective_statement_batches($1::uuid)',
      [emitRunId],
    )).rows;
    assert.ok(effBatches.length >= 1, 'coherence.run_effective_statement_batches must return batches on non-superuser DB');

    // app_views.coherence_entity_statement_reconciliation & coherence_statement_run_batches MUST return reconciled rows as platform_app!
    const reconAndBatches = await inReadTx(appPool, ownerTok, async (tx) => ({
      batches: (await tx.query('SELECT batch_id FROM app_views.coherence_statement_run_batches($1::uuid)', [emitRunId])).rows,
      recon: (await tx.query(
        'SELECT statement_entity, account_kind, statement_total, ledger_total, variance, reconciled FROM app_views.coherence_entity_statement_reconciliation WHERE run_id = $1::uuid ORDER BY account_kind, statement_entity',
        [emitRunId],
      )).rows,
    }));
    assert.ok(reconAndBatches.batches.length >= 1, 'app_views.coherence_statement_run_batches must return batches');
    assert.ok(reconAndBatches.recon.length >= 1, 'app_views.coherence_entity_statement_reconciliation must return rows');
    assert.ok(reconAndBatches.recon.every((r) => r.reconciled === true && Number(r.variance) === 0), `expected $0.00 reconciled rows, got: ${JSON.stringify(reconAndBatches.recon)}`);
  } finally {
    await Promise.all([appPool.end().catch(() => {}), roPool.end().catch(() => {}), workerPool.end().catch(() => {})]);
  }
});

test('History Import [CLI --app-user/--readonly-user, Overlapping Store Refusal, Pool DB Mismatch Refusal & Read-Only Source Preservation]: runs CLI strictly via --app-user and --readonly-user, refuses overlapping code/data dirs before mkdir, refuses mismatched app/read DBs, refuses non-dev/prod/withheld admin, and reruns idempotently', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  await withClusterCatalogLock(async () => {
    const suffix = randomBytes(4).toString('hex');
    const work = await mkdtemp(join(tmpdir(), `coherence-imp-prov-${suffix}-`));
    t.after(() => rm(work, { recursive: true, force: true }));
    const keysDir = join(work, 'keys');
    const storesDir = join(work, 'stores');

    const db = await createScratchDb('import');
    const dbOther = await createScratchDb('import_other');
    const sharedPw = `pw_${randomBytes(12).toString('hex')}`;
    const appUser = `test_imp_app_${suffix}@nusear-dev.iam`;
    const roUser = `test_imp_ro_${suffix}@nusear-dev.iam`;
    const logins = await createLoginRoles(db.adminConfig, [
      { name: appUser, password: sharedPw },
      { name: roUser, password: sharedPw },
    ]);
    const closeables = [];
    try {
      const prov = await provisionCompanyDatabase({
        pgConfig: db.pgConfig,
        companySlug: 'acme',
        displayName: 'Acme',
        environment: 'dev',
        keysDir,
        staff: [
          { role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' },
          { role: 'nusear_admin', email: 'admin@nusear.example', legalName: 'Morgan Admin' },
        ],
        roleMappings: { app: appUser, readonly: roUser },
      });
      assert.equal(prov.invariants.passed, true);

      // Provision a second separate DB (also 'acme') to test Item 13 pool-database-mismatch detection.
      const otherKeysDir = join(work, 'keys-other');
      await provisionCompanyDatabase({
        pgConfig: dbOther.pgConfig,
        companySlug: 'acme',
        displayName: 'Acme Other',
        environment: 'dev',
        keysDir: otherKeysDir,
        staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
        roleMappings: { app: appUser, readonly: roUser },
      });

      const { srcDir, manifestPath, plantedMember } = await buildHistoryFixtures(work);
      const srcBefore = await snapshotTreeHashes(srcDir);
      const staffKeyFile = prov.keys.find((k) => k.keyScope === 'nusear_staff').filePath;
      const staffKeyDoc = await readKeyFile(staffKeyFile);
      const staffSecretHex = staffKeyDoc.secretBytes.toString('hex');
      staffKeyDoc.secretBytes.fill(0);

      // Item 7: Refuse code & data stores that are identical or nested inside each other BEFORE mkdir.
      for (const [label, codeDir, dataDir] of [
        ['same dir', join(work, 'overlap-same'), join(work, 'overlap-same')],
        ['code inside data', join(work, 'overlap-cd', 'code'), join(work, 'overlap-cd')],
        ['data inside code', join(work, 'overlap-dc'), join(work, 'overlap-dc', 'data')],
      ]) {
        await assert.rejects(
          () => runHistoryImportCli(parseImportCliArgs([
            '--manifest', manifestPath,
            '--database', db.dbName,
            '--code-store-dir', codeDir,
            '--data-store-dir', dataDir,
            '--key-file', staffKeyFile,
            '--actor-email', 'owner@nusear.example',
          ])),
          (err) => err?.code === 'OVERLAPPING_STORE_DIRS',
          `must refuse overlapping store dirs (${label})`,
        );
        assert.equal(await stat(codeDir).then(() => true, () => false), false, `must not create ${codeDir} on refusal`);
        assert.equal(await stat(dataDir).then(() => true, () => false), false, `must not create ${dataDir} on refusal`);
      }

      // Item 3: Refuse forbidden system/control database and production socket in import-history.mjs.
      for (const badDb of ['postgres', 'nusear_control']) {
        await assert.rejects(
          () => runHistoryImportCli(parseImportCliArgs([
            '--manifest', manifestPath,
            '--database', badDb,
            '--stores-dir', storesDir,
            '--key-file', staffKeyFile,
            '--actor-email', 'owner@nusear.example',
          ])),
          (err) => err?.code === 'FORBIDDEN_TARGET_DATABASE',
        );
      }
      await assert.rejects(
        () => runHistoryImportCli(parseImportCliArgs([
          '--manifest', manifestPath,
          '--database', 'acme',
          '--pg-mode', 'cloudsql',
          '--app-socket-path', '/cloudsql/nusear-control-prod:us-east4:nusear-prod-db',
          '--readonly-socket-path', '/cloudsql/nusear-control-dev:us-east4:nusear-dev-db',
          '--app-user', appUser,
          '--readonly-user', roUser,
          '--stores-dir', storesDir,
          '--key-file', staffKeyFile,
          '--actor-email', 'owner@nusear.example',
        ])),
        (err) => err?.code === 'PRODUCTION_TARGET_REFUSED',
      );

      // Refuse --stores-dir inside source folder before writing anything.
      await assert.rejects(
        () => execFileAsync(process.execPath, [
          'scripts/import-history.mjs',
          '--manifest', manifestPath,
          '--stores-dir', join(srcDir, 'runs', 'bad-stores'),
          '--key-file', staffKeyFile,
          '--actor-email', 'owner@nusear.example',
          '--database', db.dbName,
        ], { cwd: process.cwd(), env: process.env }),
        (err) => String(err.stderr || '').includes('UNSAFE_STORES_DIR'),
      );

      // Refuse insecure key file mode (0644).
      const insecureKey = join(work, 'insecure.key.json');
      await writeFile(insecureKey, await readFile(staffKeyFile, 'utf8'), { mode: 0o644 });
      await chmod(insecureKey, 0o644);
      await assert.rejects(() => readKeyFile(insecureKey), (err) => err?.code === 'INSECURE_KEY_FILE');

      // Item 13: Refuse appPool and readPool connected to two different databases!
      const appPoolOther = await createPool({
        mode: 'local', host: '127.0.0.1', port: PG_PORT, database: dbOther.dbName,
        user: appUser, password: sharedPw, role: 'platform_app',
      });
      const readPool = await createPool({
        mode: 'local', host: '127.0.0.1', port: PG_PORT, database: db.dbName,
        user: roUser, password: sharedPw, role: 'platform_readonly',
      });
      const appPool = await createPool({
        mode: 'local', host: '127.0.0.1', port: PG_PORT, database: db.dbName,
        user: appUser, password: sharedPw, role: 'platform_app',
      });
      closeables.push(appPoolOther, readPool, appPool);

      const probeStores = createStorePair({
        codeStore: createCodeStore({ backend: createFileObjectStore({ rootDir: join(work, 'probe-c'), label: 'p-c' }) }),
        dataStore: createDataStore({ backend: createFileObjectStore({ rootDir: join(work, 'probe-d'), label: 'p-d' }) }),
      });
      await assert.rejects(
        () => importHistoryIntoDatabase({
          readPool,
          appPool: appPoolOther,
          stores: probeStores,
          manifestPath,
          keyFile: staffKeyFile,
          actorEmail: 'owner@nusear.example',
        }),
        (err) => err?.code === 'POOL_DATABASE_MISMATCH',
        'import must refuse appPool and readPool reaching different databases',
      );

      // Withheld admin (nusear_admin) must be refused on history import.
      await assert.rejects(
        () => importHistoryIntoDatabase({
          readPool,
          appPool,
          stores: probeStores,
          manifestPath,
          keyFile: staffKeyFile,
          actorEmail: 'admin@nusear.example',
        }),
        (err) => err?.status === 403,
        'withheld nusear_admin must be refused on history import',
      );

      // Item 13: Run scripts/import-history.mjs end-to-end strictly with --app-user and --readonly-user!
      const cliEnv = { ...process.env, PGPASSWORD: sharedPw };
      const cliRun1 = await execFileAsync(process.execPath, [
        'scripts/import-history.mjs',
        '--manifest', manifestPath,
        '--stores-dir', storesDir,
        '--key-file', staffKeyFile,
        '--actor-email', 'owner@nusear.example',
        '--pg-mode', 'local',
        '--host', '127.0.0.1',
        '--port', String(PG_PORT),
        '--database', db.dbName,
        '--app-user', appUser,
        '--readonly-user', roUser,
      ], { cwd: process.cwd(), env: cliEnv, maxBuffer: 8 * 1024 * 1024 });

      assert.equal(cliRun1.stdout.includes(plantedMember), false, 'import report must never contain member names');
      assert.equal(cliRun1.stdout.includes(staffSecretHex), false, 'import report must never contain signing secret');
      const imp1 = JSON.parse(cliRun1.stdout);
      assert.equal(imp1.passed, true, `history import failed: ${JSON.stringify(imp1.problems)}`);
      assert.equal(imp1.environment, 'dev');
      assert.equal(imp1.companySlug, 'acme');
      assert.equal(imp1.companyInitialized, true);
      assert.equal(imp1.layer0.passed, true);
      assert.equal(imp1.layer0.objects.codeInDataStoreCount, 0);
      assert.equal(imp1.layer1.passed, true);
      assert.equal(imp1.layer1.importedRunCount, 2);
      assert.equal(imp1.layer1.idempotency.passed, true);
      assert.equal(imp1.layer2.passed, true);
      assert.ok(imp1.layer2.checkpointsChecked >= 2);
      assert.equal(imp1.comparator.ran, true);
      assert.equal(imp1.comparator.passed, true);

      // Source reference folder must be 100% untouched byte for byte.
      assert.deepEqual(await snapshotTreeHashes(srcDir), srcBefore, 'read-only history import must never modify source folder');

      // Second CLI run with --app-user and --readonly-user is idempotent.
      const cliRun2 = await execFileAsync(process.execPath, [
        'scripts/import-history.mjs',
        '--manifest', manifestPath,
        '--stores-dir', storesDir,
        '--key-file', staffKeyFile,
        '--actor-email', 'owner@nusear.example',
        '--pg-mode', 'local',
        '--host', '127.0.0.1',
        '--port', String(PG_PORT),
        '--database', db.dbName,
        '--app-user', appUser,
        '--readonly-user', roUser,
      ], { cwd: process.cwd(), env: cliEnv, maxBuffer: 8 * 1024 * 1024 });
      assert.equal(cliRun2.stdout.includes(plantedMember), false);
      assert.equal(cliRun2.stdout.includes(staffSecretHex), false);
      const imp2 = JSON.parse(cliRun2.stdout);
      assert.equal(imp2.passed, true, `second import run failed: ${JSON.stringify(imp2.problems)}`);
      assert.equal(imp2.companyInitialized, false);
      assert.equal(imp2.layer1.importedRunCount, 0);
      assert.equal(imp2.layer1.skippedRunCount, 2);
      assert.equal(imp2.layer0.passed, true);
      assert.equal(imp2.layer2.passed, true);
      assert.equal(imp2.comparator.passed, true);
    } finally {
      for (const c of closeables) {
        await c.end().catch(() => {});
      }
      await db.drop();
      await dbOther.drop();
      await logins.cleanup();
    }
  });
});
