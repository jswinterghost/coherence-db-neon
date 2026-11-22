// PostgreSQL 17 connection adapter (R3.1, R14.4).
// Uses the standard `pg` (node-postgres) driver.
import { userInfo } from 'node:os';
import pg from 'pg';

const { Pool, Client, types } = pg;

// Preserve full PostgreSQL microsecond precision on TIMESTAMPTZ (1184) and TIMESTAMP (1114)
// rather than letting JS Date truncate sub-millisecond digits.
types.setTypeParser(1184, (val) => val);
types.setTypeParser(1114, (val) => val);

function resolveLocalUser() {
  if (process.env.PGUSER) return process.env.PGUSER;
  if (process.env.USER) return process.env.USER;
  try {
    return userInfo().username;
  } catch {
    return 'marcsmac';
  }
}

/**
 * Builds PostgreSQL connection options honoring R3.1 and R14.4:
 * - Local dev: defaults to local PostgreSQL 17 on Unix socket /tmp port 5433 (Mac user on socket, password over TCP).
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
    host: options.host ?? process.env.PGHOST ?? '/tmp',
    port: Number(options.port ?? process.env.PGPORT ?? 5433),
    database: options.database ?? process.env.PGDATABASE ?? 'coherence_dev',
    user: options.user ?? resolveLocalUser(),
    password: options.password ?? process.env.PGPASSWORD ?? undefined,
    ssl: options.ssl ?? false,
    max: options.max ?? 10,
    application_name: options.applicationName || 'coherence-db',
  };
}

export async function createPool(options = {}) {
  const config = buildConnectionConfig(options);
  const pool = new Pool(config);
  pool.driverName = 'pg';
  return pool;
}

export async function createClient(options = {}) {
  const config = buildConnectionConfig(options);
  const client = new Client(config);
  client.driverName = 'pg';
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
