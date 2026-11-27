// Idempotent company database provisioning: validates target DB/environment/context guards first,
// runs migrations 001..012 (with non-superuser privilege bracketing cleaned up idempotently),
// maps IAM login roles to platform_* runtime roles (non-inherited SET-only membership for startup
// '-c role=<role>'), seeds IAM state via provision-seed.mjs, and runs verifyIamConfigInvariants live.
import { readdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CLOUDSQL_IAM_LOGIN_MARKER_ROLES,
  PLATFORM_ROLES,
  verifyIamConfigInvariants,
} from '../config/policy-checks.mjs';
import { runMigrations } from '../db/migrate.mjs';
import { createPool } from '../db/pg-client.mjs';
import { isValidIsoDate } from '../util/csv.mjs';
import { AppError } from '../util/redact.mjs';
import {
  assertDatabaseContextMatches,
  assertSafeConnectedDatabase,
  assertSafeTargetConfig,
  readExistingDatabaseContext,
} from './provision-guards.mjs';
import { seedCompanyIamState } from './provision-seed.mjs';
import { checkExistingPrivateKeyDir } from './tokens.mjs';

const DEFAULT_MIGRATIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'migrations');
const VALID_STAFF_ROLES = new Set(['nusear_owner', 'nusear_admin', 'nusear_support']);
const COMPANY_SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const MANAGED_SCHEMAS = Object.freeze(['coherence', 'platform', 'iam_secret', 'iam', 'app_views', 'app_cmd']);
const MIGRATION_OBJECT_OWNER_ROLES = Object.freeze([
  'platform_versioner',
  'platform_readonly',
  'platform_view_owner',
  'platform_writer',
]);
const PROVISION_ROLE_MAPPING_TARGETS = Object.freeze([
  ['app', 'platform_app'],
  ['worker', 'platform_worker'],
  ['readonly', 'platform_readonly'],
]);

function quoteIdent(ident) {
  return `"${String(ident).replace(/"/g, '""')}"`;
}

export function parseStaffSpec(spec) {
  if (typeof spec !== 'string') {
    throw new AppError('Staff specification must be a string in the form "<role>:<email>:<name>".', 400, 'INVALID_STAFF_SPEC');
  }
  const firstColon = spec.indexOf(':');
  const secondColon = firstColon >= 0 ? spec.indexOf(':', firstColon + 1) : -1;
  if (firstColon <= 0 || secondColon <= firstColon + 1) {
    throw new AppError(
      'Staff specification must have the form "<role>:<email>:<name>" (role in nusear_owner, nusear_admin, nusear_support).',
      400,
      'INVALID_STAFF_SPEC',
    );
  }
  const role = spec.slice(0, firstColon).trim();
  const email = spec.slice(firstColon + 1, secondColon).trim().toLowerCase();
  const legalName = spec.slice(secondColon + 1).trim();
  if (!VALID_STAFF_ROLES.has(role)) {
    throw new AppError(`Invalid Nusear staff role "${role}"; expected one of nusear_owner, nusear_admin, nusear_support.`, 400, 'INVALID_STAFF_ROLE');
  }
  if (!email || !email.includes('@') || /\s/.test(email)) {
    throw new AppError(`Invalid Nusear staff email "${email}".`, 400, 'INVALID_STAFF_EMAIL');
  }
  if (!legalName) {
    throw new AppError(`Missing display/legal name for Nusear staff "${email}".`, 400, 'INVALID_STAFF_NAME');
  }
  return { role, email, legalName, preferredName: legalName };
}

function normalizeStaffList(staffInput) {
  if (!Array.isArray(staffInput) || staffInput.length === 0) {
    throw new AppError('At least one Nusear staff member (including a nusear_owner) is required.', 400, 'MISSING_STAFF');
  }
  const byEmail = new Map();
  const list = [];
  for (const item of staffInput) {
    const parsed = typeof item === 'string'
      ? parseStaffSpec(item)
      : {
        role: String(item?.role || '').trim(),
        email: String(item?.email || '').trim().toLowerCase(),
        legalName: String(item?.legalName ?? item?.name ?? '').trim(),
        preferredName: String(item?.preferredName ?? item?.legalName ?? item?.name ?? '').trim(),
      };
    if (!VALID_STAFF_ROLES.has(parsed.role)) {
      throw new AppError(`Invalid Nusear staff role "${parsed.role}".`, 400, 'INVALID_STAFF_ROLE');
    }
    if (!parsed.email || !parsed.email.includes('@') || /\s/.test(parsed.email)) {
      throw new AppError(`Invalid Nusear staff email "${parsed.email}".`, 400, 'INVALID_STAFF_EMAIL');
    }
    if (!parsed.legalName || !parsed.preferredName) {
      throw new AppError(`Missing name for Nusear staff "${parsed.email}".`, 400, 'INVALID_STAFF_NAME');
    }
    if (byEmail.has(parsed.email)) {
      throw new AppError(`Duplicate Nusear staff email "${parsed.email}" in provisioning arguments.`, 400, 'DUPLICATE_STAFF_EMAIL');
    }
    byEmail.set(parsed.email, parsed);
    list.push(parsed);
  }
  if (!list.some((s) => s.role === 'nusear_owner')) {
    throw new AppError('Provisioning requires at least one staff member with role nusear_owner.', 400, 'MISSING_OWNER');
  }
  return list;
}

function normalizeRoleMappings(roleMappings = {}) {
  if (!roleMappings || typeof roleMappings !== 'object') return [];
  const entries = [];
  const seenUsers = new Map();
  for (const [key, platformRole] of PROVISION_ROLE_MAPPING_TARGETS) {
    const raw = roleMappings[key];
    if (raw === undefined || raw === null || String(raw).trim() === '') continue;
    const dbUser = String(raw).trim();
    if (seenUsers.has(dbUser)) {
      throw new AppError(
        `Runtime DB user "${dbUser}" cannot be mapped to multiple platform roles (${seenUsers.get(dbUser)} and ${platformRole}).`,
        400,
        'DUPLICATE_RUNTIME_DB_USER',
      );
    }
    seenUsers.set(dbUser, platformRole);
    entries.push({ key, dbUser, platformRole });
  }
  return entries;
}

async function hasUnappliedMigrations(pool, migrationsDir) {
  const files = (await readdir(migrationsDir))
    .filter((name) => /^\d+_.+\.sql$/.test(name))
    .sort();
  const regRes = await pool.query("SELECT pg_catalog.to_regclass('coherence.schema_migrations') AS reg");
  if (!regRes.rows[0]?.reg) return true;
  const appliedRes = await pool.query('SELECT version FROM coherence.schema_migrations');
  const applied = new Set(appliedRes.rows.map((r) => r.version));
  return files.some((f) => !applied.has(f));
}

/**
 * Idempotently removes any temporary schema CREATE privileges held by non-migrator platform roles
 * and revokes any self-granted membership rows (REVOKE role FROM user GRANTED BY user) on platform_*
 * roles so zero empty pg_auth_members rows remain. Never swallows revoke errors.
 */
async function cleanupTemporaryMigrationGrants(pool, { currentUser }) {
  const cleanup = await pool.connect();
  const qUser = quoteIdent(currentUser);
  const nonMigratorRoles = PLATFORM_ROLES.filter((r) => r !== 'platform_migrator');
  try {
    const createGrantsRes = await cleanup.query(
      `SELECT n.nspname AS schema_name, r.rolname AS role_name
       FROM pg_catalog.pg_namespace n
       CROSS JOIN pg_catalog.pg_roles r
       WHERE n.nspname = ANY($1::text[])
         AND r.rolname = ANY($2::text[])
         AND pg_catalog.has_schema_privilege(r.oid, n.oid, 'CREATE')
       ORDER BY n.nspname, r.rolname`,
      [MANAGED_SCHEMAS, nonMigratorRoles],
    );
    for (const row of createGrantsRes.rows) {
      await cleanup.query(`REVOKE CREATE ON SCHEMA ${quoteIdent(row.schema_name)} FROM ${quoteIdent(row.role_name)}`);
    }

    const selfGrantsRes = await cleanup.query(
      `SELECT DISTINCT r.rolname AS granted_role
       FROM pg_catalog.pg_auth_members am
       JOIN pg_catalog.pg_roles r ON r.oid = am.roleid
       JOIN pg_catalog.pg_roles m ON m.oid = am.member
       JOIN pg_catalog.pg_roles g ON g.oid = am.grantor
       WHERE r.rolname = ANY($1::text[])
         AND m.rolname = $2
         AND g.rolname = $2
       ORDER BY r.rolname`,
      [PLATFORM_ROLES, currentUser],
    );
    for (const row of selfGrantsRes.rows) {
      await cleanup.query(`REVOKE ${quoteIdent(row.granted_role)} FROM ${qUser} GRANTED BY ${qUser}`);
    }
  } finally {
    cleanup.release();
  }
}

async function runMigrationsWithPrivilegeBracket(pool, { isSuperuser, currentUser, migrationsDir }) {
  if (isSuperuser) {
    return runMigrations(pool, { migrationsDir });
  }

  // On managed non-superuser PostgreSQL 17 (Cloud SQL cloudsqlsuperuser), set createrole_self_grant
  // to '' before creating roles so bootstrap records stay ADMIN-only, run preparation and migrations
  // inside one try/finally, and on every run (even with 0 pending migrations) idempotently remove
  // any stray temporary schema CREATE or self-granted pg_auth_members rows without swallowing errors.
  const needsApply = await hasUnappliedMigrations(pool, migrationsDir);
  const qUser = quoteIdent(currentUser);
  const schemaList = MANAGED_SCHEMAS.map(quoteIdent).join(', ');
  const ownerList = MIGRATION_OBJECT_OWNER_ROLES.map(quoteIdent).join(', ');

  let primaryErr = null;
  try {
    if (needsApply) {
      const prep = await pool.connect();
      try {
        await prep.query("SET createrole_self_grant = ''");
        for (const roleName of PLATFORM_ROLES) {
          const exists = (await prep.query('SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1', [roleName])).rows.length > 0;
          if (!exists) {
            await prep.query(`CREATE ROLE ${quoteIdent(roleName)} NOLOGIN NOINHERIT NOBYPASSRLS`);
          }
        }
        for (const schemaName of MANAGED_SCHEMAS) {
          await prep.query(`CREATE SCHEMA IF NOT EXISTS ${quoteIdent(schemaName)}`);
        }
        for (const ownerRole of MIGRATION_OBJECT_OWNER_ROLES) {
          await prep.query(`GRANT ${quoteIdent(ownerRole)} TO ${qUser} WITH SET TRUE, INHERIT TRUE`);
        }
        await prep.query(`GRANT CREATE ON SCHEMA ${schemaList} TO ${ownerList}`);
      } finally {
        await prep.query('RESET createrole_self_grant').catch(() => {});
        prep.release();
      }
    }
    return await runMigrations(pool, { migrationsDir });
  } catch (err) {
    primaryErr = err;
    throw err;
  } finally {
    try {
      await cleanupTemporaryMigrationGrants(pool, { currentUser });
    } catch (cleanupErr) {
      if (primaryErr) {
        throw new Error(
          `${primaryErr.message}; additionally failed to clean up temporary migration privileges: ${cleanupErr.message}`,
          { cause: primaryErr },
        );
      }
      throw cleanupErr;
    }
  }
}

async function ensureRuntimeRoleMappings(pool, mappings) {
  if (mappings.length === 0) return [];
  const allowedMarkers = new Set(CLOUDSQL_IAM_LOGIN_MARKER_ROLES);
  const results = [];
  for (const { dbUser, platformRole } of mappings) {
    const roleRes = await pool.query(
      `SELECT oid, rolname, rolsuper, rolcanlogin, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication
       FROM pg_catalog.pg_roles
       WHERE rolname = $1`,
      [dbUser],
    );
    const r = roleRes.rows[0];
    if (!r) {
      throw new AppError(
        `Database user "${dbUser}" does not exist; create the IAM database user first before provisioning.`,
        400,
        'MISSING_DB_USER',
      );
    }
    if (!r.rolcanlogin) {
      throw new AppError(`Database user "${dbUser}" must have LOGIN privilege.`, 400, 'INVALID_RUNTIME_DB_USER');
    }
    if (r.rolsuper || r.rolbypassrls || r.rolcreaterole || r.rolcreatedb || r.rolreplication) {
      throw new AppError(
        `Refusing to map privileged role "${dbUser}" to ${platformRole}; runtime login users must be NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION.`,
        400,
        'PRIVILEGED_RUNTIME_DB_USER',
      );
    }

    const memRes = await pool.query(
      `SELECT gr.rolname AS granted_role,
              gr.rolsuper AS granted_is_super,
              gr.rolbypassrls AS granted_bypassrls,
              gr.rolcreaterole AS granted_createrole,
              gr.rolcreatedb AS granted_createdb,
              gr.rolreplication AS granted_replication,
              g.rolname AS grantor_role,
              am.admin_option,
              am.inherit_option,
              am.set_option
       FROM pg_catalog.pg_auth_members am
       JOIN pg_catalog.pg_roles gr ON gr.oid = am.roleid
       JOIN pg_catalog.pg_roles g ON g.oid = am.grantor
       WHERE am.member = $1`,
      [r.oid],
    );
    let exactMatchCount = 0;
    for (const m of memRes.rows) {
      if (m.granted_role === platformRole) {
        if (m.admin_option || m.inherit_option || !m.set_option) {
          throw new AppError(
            `Runtime DB user "${dbUser}" holds non-compliant ${platformRole} membership from grantor "${m.grantor_role}" (admin=${m.admin_option}, inherit=${m.inherit_option}, set=${m.set_option}); expected ADMIN FALSE, INHERIT FALSE, SET TRUE.`,
            409,
            'CONFLICTING_ROLE_MEMBERSHIP',
          );
        }
        exactMatchCount += 1;
        continue;
      }
      const isCleanMarker = allowedMarkers.has(m.granted_role)
        && !m.admin_option
        && !m.granted_is_super
        && !m.granted_bypassrls
        && !m.granted_createrole
        && !m.granted_createdb
        && !m.granted_replication;
      if (!isCleanMarker) {
        throw new AppError(
          `Runtime DB user "${dbUser}" holds conflicting role membership "${m.granted_role}"; refusing to map to ${platformRole}.`,
          409,
          'CONFLICTING_ROLE_MEMBERSHIP',
        );
      }
    }

    if (exactMatchCount > 0) {
      results.push({ dbUser, platformRole, startupOption: `-c role=${platformRole}`, changed: false });
      continue;
    }

    await pool.query(
      `GRANT ${quoteIdent(platformRole)} TO ${quoteIdent(dbUser)} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE`,
    );
    results.push({ dbUser, platformRole, startupOption: `-c role=${platformRole}`, changed: true });
  }
  return results;
}

export async function provisionCompanyDatabase({
  pgConfig,
  companySlug,
  displayName = null,
  environment = 'dev',
  allowNonDev = false,
  supportLabel = 'Nusear support',
  validFrom = '2020-01-01',
  staff = [],
  workerName = 'Coherence Worker',
  roleMappings = {},
  keysDir,
  migrationsDir = DEFAULT_MIGRATIONS_DIR,
} = {}) {
  if (typeof companySlug !== 'string' || !COMPANY_SLUG_RE.test(companySlug)) {
    throw new AppError(`Invalid companySlug "${String(companySlug || '')}".`, 400, 'INVALID_COMPANY_SLUG');
  }
  assertSafeTargetConfig({ pgConfig, companySlug, environment, allowNonDev });

  const requestedDisplayName = displayName === undefined || displayName === null
    ? null
    : String(displayName).trim();
  if (requestedDisplayName !== null && !requestedDisplayName) {
    throw new AppError('displayName must be non-empty when specified.', 400, 'INVALID_DISPLAY_NAME');
  }
  const effectiveSupportLabel = String(supportLabel || '').trim();
  if (!effectiveSupportLabel) {
    throw new AppError('supportLabel must be non-empty.', 400, 'INVALID_SUPPORT_LABEL');
  }
  if (!isValidIsoDate(validFrom)) {
    throw new AppError(`Invalid validFrom date "${String(validFrom)}"; expected YYYY-MM-DD.`, 400, 'INVALID_VALID_FROM');
  }
  if (typeof keysDir !== 'string' || !keysDir.trim()) {
    throw new AppError('keysDir is required so signing key secrets are written only to mode-600 files in an explicit folder.', 400, 'MISSING_KEYS_DIR');
  }
  await checkExistingPrivateKeyDir(keysDir);

  const normalizedStaff = normalizeStaffList(staff);
  const normalizedMappings = normalizeRoleMappings(roleMappings);
  const effectiveWorkerName = String(workerName || '').trim();
  if (!effectiveWorkerName) {
    throw new AppError('workerName must be non-empty.', 400, 'INVALID_WORKER_NAME');
  }

  let pool = await createPool(pgConfig);
  try {
    const infoRes = await pool.query(`
      SELECT current_user AS current_user,
             pg_catalog.current_database() AS current_db,
             pg_catalog.current_setting('is_superuser') = 'on' AS is_super,
             (SELECT rolcreaterole FROM pg_catalog.pg_roles WHERE rolname = current_user) AS has_createrole,
             EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'cloudsqlsuperuser') AS has_csql_super_role,
             CASE WHEN EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'cloudsqlsuperuser')
                  THEN pg_catalog.pg_has_role(current_user, 'cloudsqlsuperuser', 'SET')
                  ELSE false END AS can_set_csql_super
    `);
    let sessionInfo = infoRes.rows[0];

    // On Cloud SQL, an IAM user granted cloudsqlsuperuser via `gcloud sql users assign-roles`
    // switches into cloudsqlsuperuser at startup so CREATEROLE applies and created platform_* roles
    // record cloudsqlsuperuser (not a personal email) as bootstrap creator.
    if (!sessionInfo.is_super && sessionInfo.current_user !== 'cloudsqlsuperuser' && sessionInfo.can_set_csql_super) {
      await pool.end();
      pool = await createPool({ ...pgConfig, role: 'cloudsqlsuperuser' });
      sessionInfo = (await pool.query(`
        SELECT current_user AS current_user,
               pg_catalog.current_database() AS current_db,
               pg_catalog.current_setting('is_superuser') = 'on' AS is_super,
               (SELECT rolcreaterole FROM pg_catalog.pg_roles WHERE rolname = current_user) AS has_createrole
      `)).rows[0];
    }

    assertSafeConnectedDatabase({
      currentDb: sessionInfo.current_db,
      pgConfig,
      companySlug,
    });

    if (!sessionInfo.is_super && !sessionInfo.has_createrole) {
      throw new AppError(
        `Connected user "${sessionInfo.current_user}" lacks SUPERUSER and CREATEROLE privileges needed to migrate and provision.`,
        403,
        'INSUFFICIENT_MIGRATOR_PRIVILEGE',
      );
    }

    // Check any existing iam.database_context BEFORE running migrations or touching role memberships.
    const existingDc = await readExistingDatabaseContext(pool, {
      isSuperuser: Boolean(sessionInfo.is_super),
      currentUser: sessionInfo.current_user,
    });
    assertDatabaseContextMatches(existingDc, {
      companySlug,
      environment,
      supportLabel: effectiveSupportLabel,
    });

    const migrationResult = await runMigrationsWithPrivilegeBracket(pool, {
      isSuperuser: Boolean(sessionInfo.is_super),
      currentUser: sessionInfo.current_user,
      migrationsDir,
    });

    const roleMappingResults = await ensureRuntimeRoleMappings(pool, normalizedMappings);

    const iamResult = await seedCompanyIamState(pool, {
      isSuperuser: Boolean(sessionInfo.is_super),
      currentUser: sessionInfo.current_user,
      companySlug,
      requestedDisplayName,
      environment,
      supportLabel: effectiveSupportLabel,
      validFrom,
      staff: normalizedStaff,
      workerName: effectiveWorkerName,
      keysDir,
    });

    const invariants = await verifyIamConfigInvariants(pool);
    if (!invariants.passed) {
      throw new AppError(
        `Live IAM config invariant audit failed (${invariants.problems.length} problem(s)): ${invariants.problems.join('; ')}`,
        500,
        'IAM_INVARIANTS_FAILED',
      );
    }

    const migrationsChanged = migrationResult.applied.length > 0;
    const mappingsChanged = roleMappingResults.some((m) => m.changed);
    const changed = migrationsChanged || mappingsChanged || iamResult.changed;

    return {
      changed,
      message: changed
        ? 'Provisioned company database.'
        : 'No changes needed; company database is already provisioned.',
      database: sessionInfo.current_db,
      migratorRole: sessionInfo.current_user,
      environment,
      companySlug,
      displayName: iamResult.displayName,
      supportLabel: effectiveSupportLabel,
      migrations: {
        applied: migrationResult.applied,
        total: migrationResult.total,
      },
      roleMappings: roleMappingResults,
      iam: {
        changed: iamResult.changed,
        auditJournalSeq: iamResult.auditJournalSeq,
        databaseContextCreated: iamResult.databaseContextCreated,
        rootOrgId: iamResult.rootOrgId,
        companyOrgId: iamResult.companyOrgId,
        catalog: iamResult.catalog,
        toolSwitchesCreated: iamResult.toolSwitchesCreated,
        staff: iamResult.staff,
        worker: iamResult.worker,
      },
      keys: iamResult.keys,
      invariants: {
        passed: invariants.passed,
        checkedBusinessTables: invariants.checkedBusinessTables,
        checkedIamTables: invariants.checkedIamTables,
        checkedAppViews: invariants.checkedAppViews,
        checkedAppCmdFunctions: invariants.checkedAppCmdFunctions,
        mappedRuntimeUsers: invariants.mappedRuntimeUsers,
      },
    };
  } finally {
    await pool.end().catch(() => {});
  }
}
