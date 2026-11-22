// PostgreSQL 17 connection adapter (R3.1, R14.4).
// Uses `pg` (node-postgres) when installed, with a built-in zero-dependency PG v3 wire-protocol fallback.
import { WireClient, WirePool } from './wire-pg.mjs';

let loadedPg = undefined;

async function resolveDriver() {
  if (loadedPg !== undefined) return loadedPg;
  try {
    const mod = await import('pg');
    const pkg = mod.default || mod;
    loadedPg = { Pool: pkg.Pool, Client: pkg.Client, driver: 'pg' };
  } catch {
    loadedPg = { Pool: WirePool, Client: WireClient, driver: 'wire-pg' };
  }
  return loadedPg;
}

/**
 * Builds PostgreSQL connection options honoring R3.1 and R14.4:
 * - Local dev: defaults to local PostgreSQL 17 on port 5433 (Mac user on Unix socket or password over TCP).
 * - Production (Cloud SQL): IAM service account authentication + TLS required, never direct unencrypted TCP.
 */
export function buildConnectionConfig(options = {}) {
  if (options.connectionString) {
    return {
      connectionString: options.connectionString,
      ssl: options.ssl,
      max: options.max ?? 10,
      application_name: options.applicationName || 'coherence-db',
    };
  }
  const mode = options.mode || process.env.COHERENCE_PG_MODE || 'local';
  if (mode === 'cloudsql') {
    if (!options.ssl && !options.socketPath) {
      throw new Error('Cloud SQL connections require TLS or the Cloud SQL Auth Proxy Unix socket (R14.4).');
    }
    if (!options.user) {
      throw new Error('Cloud SQL connections require an IAM service account database user (R14.4).');
    }
    return {
      host: options.socketPath || options.host,
      port: options.socketPath ? undefined : Number(options.port || 5432),
      database: options.database,
      user: options.user,
      password: options.iamAccessTokenProvider || options.password,
      ssl: options.socketPath ? false : (options.ssl ?? { rejectUnauthorized: true }),
      max: options.max ?? 10,
      application_name: options.applicationName || 'coherence-db-cloudsql',
    };
  }
  return {
    host: options.host ?? process.env.PGHOST ?? '127.0.0.1',
    port: Number(options.port ?? process.env.PGPORT ?? 5433),
    database: options.database ?? process.env.PGDATABASE ?? 'coherence_dev',
    user: options.user ?? process.env.PGUSER ?? process.env.USER ?? 'postgres',
    password: options.password ?? process.env.PGPASSWORD ?? undefined,
    ssl: options.ssl ?? false,
    max: options.max ?? 10,
    application_name: options.applicationName || 'coherence-db',
  };
}

export async function createPool(options = {}) {
  const { Pool, driver } = await resolveDriver();
  const config = buildConnectionConfig(options);
  const pool = new Pool(config);
  pool.driverName = driver;
  return pool;
}

export async function createClient(options = {}) {
  const { Client, driver } = await resolveDriver();
  const config = buildConnectionConfig(options);
  const client = new Client(config);
  client.driverName = driver;
  await client.connect();
  return client;
}

export async function withSerializableTx(poolOrClient, fn, { maxRetries = 5 } = {}) {
  const isPool = typeof poolOrClient.connect === 'function' && typeof poolOrClient.end === 'function' && !poolOrClient.release;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    const client = isPool ? await poolOrClient.connect() : poolOrClient;
    let destroyOnRelease = false;
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {
        destroyOnRelease = true;
      }
      if (error?.code === '40001' && attempt < maxRetries) {
        continue;
      }
      throw error;
    } finally {
      if (isPool) client.release(destroyOnRelease ? new Error('Rollback failed') : undefined);
    }
  }
}
