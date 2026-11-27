import { userInfo } from 'node:os';
import pg from 'pg';
import { AppError, sanitizeErrorMessage } from '../util/redact.mjs';

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

const SAFE_ROLE_RE = /^[a-z_][a-z0-9_]{0,62}$/;
const CLOUDSQL_FORBIDDEN_PG_ENV_VARS = Object.freeze([
  'PGPASSWORD',
  'PGPASSFILE',
  'PGOPTIONS',
  'PGREPLICATION',
  'PGCLIENTENCODING',
  'PGCLIENT_ENCODING',
  'PGBINARY',
  'PGCONNECT_TIMEOUT',
  'PGHOSTADDR',
  'PGSERVICE',
  'PGSERVICEFILE',
  'PGSSLMODE',
  'PGSSLCERT',
  'PGSSLKEY',
  'PGSSLROOTCERT',
  'PGSSLCRL',
  'PGREQUIRESSL',
  'PGSSL',
  'PGCHANNELBINDING',
  'PGTARGETSESSIONATTRS',
]);

function buildRoleStartupOption(role) {
  if (role === undefined || role === null || role === '') return undefined;
  if (typeof role !== 'string' || !SAFE_ROLE_RE.test(role)) {
    throw new Error(`Invalid PostgreSQL startup role identifier: ${String(role)}`);
  }
  return `-c role=${role}`;
}

function assertCleanCloudSqlEnv(env) {
  const forbidden = CLOUDSQL_FORBIDDEN_PG_ENV_VARS.filter(
    (key) => env[key] !== undefined && String(env[key]).length > 0,
  );
  if (forbidden.length > 0) {
    throw new Error(
      `Cloud SQL mode forbids PG* environment variable(s) that alter the connection or pass static credentials: ${forbidden.join(', ')}.`,
    );
  }
}

function parsePort(rawPort, defaultPort = 5432) {
  const port = rawPort !== undefined && rawPort !== null && rawPort !== ''
    ? Number(rawPort)
    : defaultPort;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid PostgreSQL port: ${String(rawPort)}`);
  }
  return port;
}

/**
 * Builds PostgreSQL connection options. Local mode connects via configured host or socket and OS user
 * (defaulting to standard port 5432); Cloud SQL mode requires IAM token authentication over TLS or the
 * Cloud SQL Auth Proxy Unix socket, sets port explicitly (5432 unless told), and forbids static passwords
 * and connection-altering PG* environment variables. When options.role is set, sends PostgreSQL startup
 * parameter options='-c role=<role>' so mapped IAM login users enter the target platform role at
 * connection startup without application-side SET LOCAL ROLE.
 */
export function buildConnectionConfig(options = {}) {
  const startupOptions = buildRoleStartupOption(options.role);
  if (options.connectionString && (options.mode || (options.env || process.env).COHERENCE_PG_MODE) === 'cloudsql') {
    throw new Error('Cloud SQL connections take no connection string; use the Cloud SQL Auth Proxy socket or TLS with IAM authentication.');
  }
  if (options.connectionString) {
    return {
      connectionString: options.connectionString,
      ssl: options.ssl,
      max: options.max ?? 10,
      application_name: options.applicationName || 'coherence-db',
      ...(startupOptions ? { options: startupOptions } : {}),
    };
  }
  const env = options.env || process.env;
  const mode = options.mode || env.COHERENCE_PG_MODE || 'local';
  if (mode === 'cloudsql') {
    assertCleanCloudSqlEnv(env);
    if (!options.ssl && !options.socketPath) {
      throw new Error('Cloud SQL connections require TLS or the Cloud SQL Auth Proxy Unix socket.');
    }
    if (!options.user) {
      throw new Error('Cloud SQL connections require an IAM service account database user.');
    }
    if (options.password !== undefined && options.password !== null) {
      throw new Error('Cloud SQL connections forbid static passwords; use iamAccessTokenProvider or the Cloud SQL Auth Proxy socket with IAM authentication.');
    }
    if (!options.socketPath && !options.host) {
      throw new Error('Cloud SQL connections require an explicit socketPath or host.');
    }
    if (!options.socketPath && typeof options.iamAccessTokenProvider !== 'function') {
      throw new Error('Cloud SQL TCP/TLS connections require an iamAccessTokenProvider function for IAM authentication.');
    }
    if (typeof options.database !== 'string' || !options.database.trim()) {
      throw new Error('Cloud SQL connections require an explicit database name.');
    }
    const port = parsePort(options.port, 5432);
    return {
      host: options.socketPath || options.host,
      port,
      database: options.database.trim(),
      user: options.user,
      password: options.iamAccessTokenProvider,
      ssl: options.socketPath ? false : (options.ssl ?? { rejectUnauthorized: true }),
      max: options.max ?? 10,
      application_name: options.applicationName || 'coherence-db-cloudsql',
      ...(startupOptions ? { options: startupOptions } : {}),
    };
  }
  return {
    host: options.host ?? env.PGHOST ?? '/tmp',
    port: parsePort(options.port ?? env.PGPORT, 5432),
    database: options.database ?? env.PGDATABASE ?? 'coherence_dev',
    user: options.user ?? resolveLocalUser(options.getUserInfo),
    password: options.password ?? env.PGPASSWORD ?? undefined,
    ssl: options.ssl ?? false,
    max: options.max ?? 10,
    application_name: options.applicationName || 'coherence-db',
    ...(startupOptions ? { options: startupOptions } : {}),
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

export function isPgPool(poolOrClient) {
  return typeof poolOrClient.connect === 'function'
    && typeof poolOrClient.end === 'function'
    && !poolOrClient.release
    && !('_connected' in poolOrClient);
}

export async function withSerializableTx(poolOrClient, fn, { maxRetries = 5 } = {}) {
  const isPool = isPgPool(poolOrClient);
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

function tokenHasViewAs(dbToken) {
  if (typeof dbToken !== 'string') return false;
  const parts = dbToken.trim().split('|');
  return parts.length === 8 && parts[0] === 'v1' && parts[5].length > 0 && parts[5] !== '-';
}

/**
 * Runs fn(client) inside one transaction carrying ONLY the signed dbToken via transaction-local
 * app.session_token (never SET LOCAL ROLE). Enforces BEGIN TRANSACTION READ ONLY whenever readOnly
 * is true or the token carries an active View-as subject, and destroys pooled connections on
 * rollback failure so session state can never leak across requests.
 */
export async function withRequestTx(
  poolOrClient,
  dbToken,
  fn,
  { readOnly = true, serializable = false, maxRetries = 5 } = {},
) {
  const iso = serializable ? 'ISOLATION LEVEL SERIALIZABLE ' : '';
  const isPool = isPgPool(poolOrClient);
  const retries = serializable ? Math.max(1, maxRetries) : 1;

  for (let attempt = 1; attempt <= retries; attempt++) {
    const resolved = typeof dbToken === 'function' ? dbToken() : dbToken;
    const token = typeof resolved === 'string' ? resolved : '';
    const effectiveReadOnly = Boolean(readOnly) || tokenHasViewAs(token);
    const mode = effectiveReadOnly ? 'READ ONLY' : 'READ WRITE';
    const beginSql = `BEGIN TRANSACTION ${iso}${mode}`;
    const client = isPool ? await poolOrClient.connect() : poolOrClient;
    let destroyOnRelease = false;
    try {
      await client.query(beginSql);
      await client.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [token]);
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {
        destroyOnRelease = true;
      }
      const isRetryableSerialization = serializable
        && error?.code === '40001'
        && !String(error?.message || '').includes('STALE_JOURNAL_POSITION')
        && attempt < retries;
      if (isRetryableSerialization) {
        continue;
      }
      throw error;
    } finally {
      if (isPool) client.release(destroyOnRelease ? new Error('Rollback failed') : undefined);
    }
  }
}

function extractErrorCodePrefix(rawMessage) {
  const m = /^([A-Z][A-Z0-9_]{2,50}):/.exec(String(rawMessage || '').trim());
  return m ? m[1] : null;
}

export function mapPgError(error) {
  if (error instanceof AppError) return error;
  const pgCode = error?.code;
  const rawMessage = String(error?.message || '');
  const prefix = extractErrorCodePrefix(rawMessage);
  const msg = sanitizeErrorMessage(error, 'Database refused the change.');

  if (pgCode === '42501') {
    if (prefix === 'VIEW_AS_READ_ONLY' || /VIEW_AS_READ_ONLY/i.test(rawMessage)) {
      return new AppError('Cannot make changes while viewing as another user.', 403, 'VIEW_AS_READ_ONLY');
    }
    if (prefix === 'WORKER_ONLY') {
      return new AppError('Only the Coherence engine worker service identity may perform this operation.', 403, 'WORKER_ONLY');
    }
    if (prefix === 'HUMAN_ONLY') {
      return new AppError('The worker service identity cannot execute human decision commands.', 403, 'HUMAN_ONLY');
    }
    if (prefix === 'INVALID_STORE') {
      return new AppError(msg, 403, 'INVALID_STORE');
    }
    return new AppError('Insufficient database privilege for this operation.', 403, 'FORBIDDEN');
  }
  if (pgCode === '25006') {
    return new AppError('Cannot make changes in a read-only transaction.', 403, 'VIEW_AS_READ_ONLY');
  }
  if (pgCode === 'P0002') {
    return new AppError(msg, 404, prefix || 'NOT_FOUND');
  }
  if (pgCode === '40001') {
    if (prefix === 'STALE_JOURNAL_POSITION' || /STALE_JOURNAL_POSITION/i.test(rawMessage)) {
      return new AppError('State changed since the screen loaded; reload and try again.', 409, 'STALE_JOURNAL_POSITION');
    }
    return new AppError('Concurrent change conflicted; retry with current state.', 409, 'SERIALIZATION_FAILURE');
  }
  if (pgCode === '23505') {
    return new AppError(msg, 409, prefix || 'UNIQUE_VIOLATION');
  }
  if (pgCode === '23P01') {
    return new AppError(msg, 409, prefix || 'EXCLUSION_VIOLATION');
  }
  if (pgCode === '22023') {
    const isInputErr = prefix && (prefix.startsWith('MISSING_') || prefix.startsWith('INVALID_'));
    return new AppError(msg, isInputErr ? 400 : 409, prefix || 'INVARIANT_VIOLATION');
  }
  if (pgCode === '23514') {
    return new AppError(msg, 409, prefix || 'INVARIANT_VIOLATION');
  }
  if (pgCode === '23503') {
    return new AppError(msg, 409, prefix || 'REFERENCE_VIOLATION');
  }
  if (pgCode === '55000') {
    return new AppError(msg, 409, prefix || 'STATE_CONFLICT');
  }
  return new AppError(msg, 500, 'DB_ERROR');
}

export async function inReadTx(poolOrClient, dbToken, fn) {
  try {
    return await withRequestTx(poolOrClient, dbToken, fn, { readOnly: true });
  } catch (err) {
    throw mapPgError(err);
  }
}
