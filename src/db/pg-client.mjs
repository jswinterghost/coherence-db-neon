import { userInfo } from 'node:os';
import pg from 'pg';

const { Pool, Client, types } = pg;

// Preserve full PostgreSQL microsecond precision on TIMESTAMPTZ (1184) and TIMESTAMP (1114)
// rather than letting JS Date truncate sub-millisecond digits.
types.setTypeParser(1184, (val) => val);
types.setTypeParser(1114, (val) => val);

export function resolveLocalUser(getUserInfo = userInfo) {
  if (process.env.PGUSER) return process.env.PGUSER;
  if (process.env.USER) return process.env.USER;
  let info;
  try {
    info = getUserInfo();
  } catch {
    info = null;
  }
  if (info && typeof info.username === 'string' && info.username.trim().length > 0) {
    return info.username;
  }
  throw new Error('Could not determine local PostgreSQL user: set PGUSER or USER.');
}

/**
 * Builds PostgreSQL connection options. Local mode connects via configured host or socket and OS user
 * (defaulting to standard port 5432); Cloud SQL mode requires IAM token authentication over TLS or the
 * Cloud SQL Auth Proxy Unix socket and forbids static passwords.
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
      throw new Error('Cloud SQL connections require TLS or the Cloud SQL Auth Proxy Unix socket.');
    }
    if (!options.user) {
      throw new Error('Cloud SQL connections require an IAM service account database user.');
    }
    if (options.password !== undefined && options.password !== null) {
      throw new Error('Cloud SQL connections forbid static passwords; use iamAccessTokenProvider or the Cloud SQL Auth Proxy socket with IAM authentication.');
    }
    if (!options.socketPath && typeof options.iamAccessTokenProvider !== 'function') {
      throw new Error('Cloud SQL TCP/TLS connections require an iamAccessTokenProvider function for IAM authentication.');
    }
    return {
      host: options.socketPath || options.host,
      port: options.socketPath ? undefined : Number(options.port || 5432),
      database: options.database,
      user: options.user,
      password: options.iamAccessTokenProvider,
      ssl: options.socketPath ? false : (options.ssl ?? { rejectUnauthorized: true }),
      max: options.max ?? 10,
      application_name: options.applicationName || 'coherence-db-cloudsql',
    };
  }
  return {
    host: options.host ?? process.env.PGHOST ?? '/tmp',
    port: Number(options.port ?? process.env.PGPORT ?? 5432),
    database: options.database ?? process.env.PGDATABASE ?? 'coherence_dev',
    user: options.user ?? resolveLocalUser(options.getUserInfo),
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
