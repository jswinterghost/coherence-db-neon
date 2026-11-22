// Isolated PostgreSQL 17 test harness (R3.1: local PG 17 defaults to /tmp:5433; W-9: zero live-service access).
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { createClient, createPool } from '../../src/db/pg-client.mjs';
import { runMigrations } from '../../src/db/migrate.mjs';
import { createMemoryObjectStore } from '../../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../../src/storage/stores.mjs';
import { createCommandLayer } from '../../src/commands/command-layer.mjs';

const TEST_DB_PREFIX = 'neon_test_';

function resolveLocalPgUser() {
  if (process.env.PGUSER) return process.env.PGUSER;
  if (process.env.USER) return process.env.USER;
  try {
    return userInfo().username;
  } catch {
    return 'marcsmac';
  }
}

export function getAdminPgConfig() {
  return {
    host: process.env.PGHOST || '/tmp',
    port: Number(process.env.PGPORT || 5433),
    database: process.env.PGADMIN_DATABASE || 'postgres',
    user: resolveLocalPgUser(),
    password: process.env.PGPASSWORD ?? undefined,
  };
}

function assertTestDbName(dbName) {
  if (typeof dbName !== 'string' || !dbName.startsWith(TEST_DB_PREFIX) || !/^[a-z0-9_]+$/.test(dbName)) {
    throw new Error(`Refusing to manage database outside ${TEST_DB_PREFIX}* namespace: ${dbName}`);
  }
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

/**
 * Checks whether local PostgreSQL 17 is reachable; returns { available, reason }.
 */
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
 * Creates a fresh, isolated, migrated PostgreSQL 17 database + isolated in-memory code & data stores +
 * command layer + isolated temp dir. Cleanup stops any registered workers FIRST (W-9), drops the test DB,
 * and removes the temp directory.
 */
export async function createTestEnv({ companySlug = 'phalanx', displayName = 'Phalanx', defaultEmitMode = 'builtin' } = {}) {
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
  const commands = createCommandLayer({ pool, companySlug, stores });
  const tempDir = await mkdtemp(join(tmpdir(), `coherence-test-${suffix}-`));

  const ownerActor = { id: 'kairon', kind: 'owner', actingFor: null };
  const workerActor = { id: `coherence-worker:${companySlug}`, kind: 'worker' };

  await commands.initCompany({
    actor: ownerActor,
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
    // W-9: ALWAYS stop every worker and wait for all subprocesses to exit BEFORE removing temp tools or DB!
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
    pgConfig,
    pool,
    codeBackend,
    dataBackend,
    codeStore,
    dataStore,
    stores,
    commands,
    tempDir,
    ownerActor,
    workerActor,
    registerWorker,
    registerClient,
    cleanup,
  };
}
