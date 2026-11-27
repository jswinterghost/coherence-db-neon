// Target database, environment, production-endpoint, and iam.database_context guards shared by
// provisioning and read-only history import so the wrong database is refused before any change.
import { posix } from 'node:path';
import { AppError } from '../util/redact.mjs';

export const VALID_ENVIRONMENTS = Object.freeze(new Set(['dev', 'prod', 'local']));
export const FORBIDDEN_TARGET_DATABASES = Object.freeze(new Set([
  'postgres',
  'template0',
  'template1',
  'cloudsqladmin',
  'nusear_control',
]));
const SCRATCH_DB_NAME_RE = /^(?:test|coherence_test)_[a-z0-9_]+$/;
const PROD_INDICATOR_RE = /(?:^|[^a-z0-9])(prod|production|prd)(?:[^a-z0-9]|$)/i;
const CLOUDSQL_INSTANCE_SEGMENT_RE = /[^/:]+:[^/:]+:[^/:]+/;

function quoteIdent(ident) {
  return `"${String(ident).replace(/"/g, '""')}"`;
}

export function isForbiddenTargetDatabase(dbName) {
  return typeof dbName !== 'string'
    || !dbName.trim()
    || FORBIDDEN_TARGET_DATABASES.has(dbName.trim().toLowerCase());
}

export function isScratchDatabaseName(dbName) {
  return typeof dbName === 'string' && SCRATCH_DB_NAME_RE.test(dbName.trim());
}

export function isProductionTargetValue(value) {
  return typeof value === 'string' && PROD_INDICATOR_RE.test(value.trim());
}

export function isLocalTargetConfig(pgConfig = {}, env = process.env) {
  if (!pgConfig || typeof pgConfig !== 'object') return false;
  const mode = pgConfig.mode || env.COHERENCE_PG_MODE || 'local';
  if (mode === 'cloudsql') return false;
  if (pgConfig.socketPath) return false;
  if (pgConfig.connectionString) return false;
  const host = String(pgConfig.host ?? env.PGHOST ?? '/tmp').trim();
  if (!host) return false;
  if (host.startsWith('/')) {
    const normalized = posix.resolve(host).toLowerCase();
    if (normalized === '/cloudsql' || normalized.startsWith('/cloudsql/')) return false;
    if (CLOUDSQL_INSTANCE_SEGMENT_RE.test(host)) return false;
    if (isProductionTargetValue(host)) return false;
    return true;
  }
  return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

export function assertNonProdEndpoint({ pgConfig = {}, environment = 'dev', allowNonDev = false, env = process.env } = {}) {
  if (!VALID_ENVIRONMENTS.has(environment)) {
    throw new AppError(`Invalid environment "${String(environment)}"; expected dev, prod, or local.`, 400, 'INVALID_ENVIRONMENT');
  }
  if (environment !== 'dev' && !allowNonDev) {
    throw new AppError(
      `Refusing non-dev environment "${environment}" unless allowNonDev / --allow-non-dev is explicitly specified.`,
      400,
      'NON_DEV_ENVIRONMENT_REFUSED',
    );
  }
  if (environment === 'prod') return;

  for (const [label, value] of [
    ['socketPath', pgConfig.socketPath],
    ['host', pgConfig.host],
    ['instance', pgConfig.instance],
    ['connectionString', pgConfig.connectionString],
    ['PGHOST', env.PGHOST],
    ['PGHOSTADDR', env.PGHOSTADDR],
    ['PGSERVICE', env.PGSERVICE],
  ]) {
    if (isProductionTargetValue(value)) {
      throw new AppError(
        `Refusing production ${label} "${value}" when targeting environment "${environment}".`,
        400,
        'PRODUCTION_TARGET_REFUSED',
      );
    }
  }
}

export function assertDatabaseNameAllowed(dbName, { companySlug = null, allowScratch = false } = {}) {
  if (typeof dbName !== 'string' || !dbName.trim()) {
    throw new AppError('An explicit target database name (--database) is required.', 400, 'MISSING_TARGET_DATABASE');
  }
  const trimmed = dbName.trim();
  if (FORBIDDEN_TARGET_DATABASES.has(trimmed.toLowerCase())) {
    throw new AppError(
      `Refusing to target system or control database "${trimmed}".`,
      400,
      'FORBIDDEN_TARGET_DATABASE',
    );
  }
  if (companySlug && trimmed !== companySlug) {
    if (!(allowScratch && isScratchDatabaseName(trimmed))) {
      throw new AppError(
        `Refusing database "${trimmed}" for company slug "${companySlug}" outside explicit local scratch databases (test_*, coherence_test_*).`,
        400,
        'DATABASE_SLUG_MISMATCH',
      );
    }
  }
}

export function assertSafeTargetConfig({
  pgConfig,
  companySlug = null,
  environment = 'dev',
  allowNonDev = false,
  env = process.env,
}) {
  if (!pgConfig || typeof pgConfig !== 'object') {
    throw new AppError('pgConfig is required.', 400, 'MISSING_PG_CONFIG');
  }
  assertNonProdEndpoint({ pgConfig, environment, allowNonDev });
  const allowScratch = isLocalTargetConfig(pgConfig, env);
  assertDatabaseNameAllowed(pgConfig.database, { companySlug, allowScratch });
}

export function assertSafeConnectedDatabase({
  currentDb,
  pgConfig = null,
  companySlug = null,
  allowScratch = undefined,
  env = process.env,
}) {
  const effectiveAllowScratch = allowScratch !== undefined
    ? Boolean(allowScratch)
    : isLocalTargetConfig(pgConfig || {}, env);
  assertDatabaseNameAllowed(currentDb, { companySlug, allowScratch: effectiveAllowScratch });
}

export function assertDatabaseContextMatches(existingDc, {
  companySlug,
  environment,
  supportLabel,
  expectedRoleKind = 'company_working',
}) {
  if (!existingDc) return;
  if (
    existingDc.environment !== environment
    || existingDc.db_role_kind !== expectedRoleKind
    || existingDc.company_slug !== companySlug
    || existingDc.support_external_label !== supportLabel
  ) {
    throw new AppError(
      `Database context conflict: existing=(${existingDc.environment}, ${existingDc.db_role_kind}, ${existingDc.company_slug}, ${existingDc.support_external_label}) vs requested=(${environment}, ${expectedRoleKind}, ${companySlug}, ${supportLabel}).`,
      409,
      'PROVISION_CONTEXT_MISMATCH',
    );
  }
}

/**
 * Reads any existing iam.database_context row before migrations or role-mapping changes run.
 * On non-superuser databases (FORCE RLS), temporarily acquires SET on platform_readonly in a
 * read-only transaction and revokes the membership row cleanly in finally without swallowing errors.
 */
export async function readExistingDatabaseContext(pool, { isSuperuser, currentUser }) {
  const regRes = await pool.query("SELECT pg_catalog.to_regclass('iam.database_context') AS reg");
  if (!regRes.rows[0]?.reg) return null;

  const querySql = 'SELECT environment, db_role_kind, tenant_org_id, company_slug, support_external_label FROM iam.database_context WHERE singleton = true';
  if (isSuperuser) {
    return (await pool.query(querySql)).rows[0] || null;
  }

  const roExists = (await pool.query("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'platform_readonly'")).rows.length > 0;
  if (!roExists) return null;

  const qUser = quoteIdent(currentUser);
  let primaryErr = null;
  let granted = false;
  try {
    await pool.query(`GRANT platform_readonly TO ${qUser} WITH SET TRUE, INHERIT FALSE`);
    granted = true;
    const client = await pool.connect();
    try {
      await client.query('BEGIN TRANSACTION READ ONLY');
      await client.query('SET LOCAL ROLE platform_readonly');
      const res = await client.query(querySql);
      await client.query('COMMIT');
      return res.rows[0] || null;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    primaryErr = err;
    throw err;
  } finally {
    if (granted) {
      try {
        await pool.query(`REVOKE platform_readonly FROM ${qUser} GRANTED BY ${qUser}`);
      } catch (revokeErr) {
        if (primaryErr) {
          throw new Error(
            `${primaryErr.message}; additionally failed to revoke temporary platform_readonly grant: ${revokeErr.message}`,
            { cause: primaryErr },
          );
        }
        throw revokeErr;
      }
    }
  }
}
