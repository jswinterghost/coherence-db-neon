// Isolated PostgreSQL 17 test harness using throwaway test databases and in-memory stores with zero live-service access.
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { PLATFORM_ROLES } from '../../src/config/policy-checks.mjs';
import { createClient, createPool, resolveLocalUser } from '../../src/db/pg-client.mjs';
import { runMigrations } from '../../src/db/migrate.mjs';
import { createMemoryObjectStore } from '../../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../../src/storage/stores.mjs';
import { seedCoherenceIamFixture } from './iam-harness.mjs';
import { createAppCommands } from '../../src/commands/app-cmd.mjs';

export const TEST_DB_PREFIX = 'coherence_test_';

export function quoteIdent(ident) {
  return `"${String(ident).replace(/"/g, '""')}"`;
}

export async function writeTree(baseDir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = join(baseDir, ...rel.split('/'));
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
}

export function getAdminPgConfig(options = {}) {
  return {
    host: process.env.PGHOST || '/tmp',
    port: Number(process.env.PGPORT || 5432),
    database: process.env.PGADMIN_DATABASE || 'postgres',
    user: options.user ?? resolveLocalUser(options.getUserInfo),
    password: process.env.PGPASSWORD ?? undefined,
  };
}

function assertTestDbName(dbName) {
  if (typeof dbName !== 'string' || !dbName.startsWith(TEST_DB_PREFIX) || !/^[a-z0-9_]+$/.test(dbName)) {
    throw new Error(`Refusing to manage database outside ${TEST_DB_PREFIX}* namespace: ${dbName}`);
  }
}

export async function createScratchDb(prefix = 'scratch', ownerRole = null, customAdminConfig = null) {
  const suffix = randomBytes(5).toString('hex');
  const dbName = `${TEST_DB_PREFIX}${prefix}_${suffix}`;
  assertTestDbName(dbName);
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
      assertTestDbName(dbName);
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

export async function createLoginRoles(adminConfig, specs) {
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

export async function createEmptyMigratedTestDb() {
  const suffix = randomBytes(6).toString('hex');
  const dbName = `${TEST_DB_PREFIX}${suffix}`;
  assertTestDbName(dbName);
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

  async function cleanup() {
    await pool.end().catch(() => {});
    const dropAdmin = await createClient(adminConfig).catch(() => null);
    if (dropAdmin) {
      try {
        assertTestDbName(dbName);
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

  return { dbName, pgConfig, pool, cleanup };
}

export async function withClusterCatalogLock(fn) {
  const admin = await createClient(getAdminPgConfig());
  try {
    await admin.query('SELECT pg_catalog.pg_advisory_lock(88421, 1)');
    try {
      return await fn();
    } finally {
      await admin.query('SELECT pg_catalog.pg_advisory_unlock(88421, 1)').catch(() => {});
    }
  } finally {
    await admin.end().catch(() => {});
  }
}

export async function checkPgAvailable() {
  let client;
  try {
    client = await createClient(getAdminPgConfig());
    const res = await client.query('SHOW server_version_num');
    const ver = Number(res.rows[0]?.server_version_num || 0);
    if (ver < 170000) {
      return { available: false, reason: `PostgreSQL 17+ required (found server_version_num=${ver})` };
    }
    return { available: true, versionNum: ver };
  } catch (err) {
    return { available: false, reason: err.message };
  } finally {
    if (client) await client.end().catch(() => {});
  }
}

/**
 * Creates an isolated migrated PostgreSQL 17 database, in-memory code and data stores, command layer,
 * and temp directory. Cleanup stops all registered workers before closing pools, dropping the test
 * database, and removing temp files.
 */
export async function createTestEnv({
  companySlug = 'acme',
  displayName = 'Acme',
  defaultEmitMode = 'builtin',
  extraAgencies = [],
  extraAgents = [],
} = {}) {
  const suffix = randomBytes(6).toString('hex');
  const dbName = `${TEST_DB_PREFIX}${suffix}`;
  assertTestDbName(dbName);
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

  const codeBackend = createMemoryObjectStore({ label: `test-code-${suffix}` });
  const dataBackend = createMemoryObjectStore({ label: `test-data-${suffix}` });
  const codeStore = createCodeStore({ backend: codeBackend });
  const dataStore = createDataStore({ backend: dataBackend });
  const stores = createStorePair({ codeStore, dataStore });
  const commands = createAppCommands({ pool, stores });
  const tempDir = await mkdtemp(join(tmpdir(), `coherence-test-${suffix}-`));

  const iam = await seedCoherenceIamFixture(pool, {
    companySlug,
    displayName,
    extraAgencies,
    extraAgents,
  });
  const ownerToken = iam.tokens.owner;
  const operatorToken = iam.tokens.operator;
  const workerToken = iam.tokens.worker;

  await commands.initCompany({
    dbToken: ownerToken,
    commandKey: `init-company-${suffix}`,
    slug: companySlug,
    displayName,
    defaultEmitMode,
  });

  const registeredWorkers = [];
  const registeredClients = [];
  const registerWorker = (worker) => {
    registeredWorkers.push(worker);
    return worker;
  };
  const registerClient = (client) => {
    registeredClients.push(client);
    return client;
  };

  async function cleanup() {
    // Stop every worker and wait for child processes to exit before closing connections, dropping the test DB, or removing temp files.
    for (const w of registeredWorkers) {
      await w.stop().catch(() => {});
    }
    for (const c of registeredClients) {
      await c.end().catch(() => {});
    }
    await pool.end().catch(() => {});
    const dropAdmin = await createClient(adminConfig).catch(() => null);
    if (dropAdmin) {
      try {
        assertTestDbName(dbName);
        await dropAdmin.query(
          'SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()',
          [dbName],
        );
        await dropAdmin.query(`DROP DATABASE IF EXISTS "${dbName}"`);
      } finally {
        await dropAdmin.end().catch(() => {});
      }
    }
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }

  return {
    dbName,
    companySlug,
    displayName,
    pgConfig,
    pool,
    codeBackend,
    dataBackend,
    codeStore,
    dataStore,
    stores,
    commands,
    tempDir,
    iam,
    ownerToken,
    operatorToken,
    workerToken,
    registerWorker,
    registerClient,
    cleanup,
  };
}
