// Shared Release P1 runtime helpers for provisioned-database CLIs and importers (history import,
// Agent Register import, and Emit materialization): pool config construction, paired write/readonly
// pool lifecycle with partial-failure cleanup, mode-600 renewing token minting, and same-database checks.
import { createPool, inReadTx } from '../db/pg-client.mjs';
import { AppError } from '../util/redact.mjs';
import { assertDatabaseNameAllowed, assertNonProdEndpoint } from './provision-guards.mjs';
import { createRenewingTokenProvider, readKeyFile } from './tokens.mjs';

export const DB_IDENTITY_SQL = `
  SELECT pg_catalog.current_database() AS database,
         (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()) AS db_oid,
         pg_catalog.pg_postmaster_start_time() AS postmaster_start_time
`;

const WORKER_IDENTITY_SQL = `
  SELECT pg_catalog.current_database() AS database,
         (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()) AS db_oid,
         pg_catalog.pg_postmaster_start_time() AS postmaster_start_time,
         current_user AS current_role,
         (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) AS is_superuser,
         (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = session_user) AS session_is_superuser
`;

const POOL_KIND_SPEC = Object.freeze({
  app: Object.freeze({
    socket: 'appSocketPath',
    host: 'appHost',
    port: 'appPort',
    user: 'appUser',
    role: 'appRole',
    defaultRole: 'platform_app',
  }),
  worker: Object.freeze({
    socket: 'workerSocketPath',
    host: 'workerHost',
    port: 'workerPort',
    user: 'workerUser',
    role: 'workerRole',
    defaultRole: 'platform_worker',
  }),
  readonly: Object.freeze({
    socket: 'readonlySocketPath',
    host: 'readonlyHost',
    port: 'readonlyPort',
    user: 'readonlyUser',
    role: 'readonlyRole',
    defaultRole: 'platform_readonly',
  }),
});

export function buildProvisionedPoolConfig(args, kind, { applicationPrefix = 'coherence-import' } = {}) {
  const spec = Object.prototype.hasOwnProperty.call(POOL_KIND_SPEC, kind) ? POOL_KIND_SPEC[kind] : null;
  if (!spec) {
    throw new AppError(
      `Unknown provisioned pool kind "${String(kind)}"; expected one of: ${Object.keys(POOL_KIND_SPEC).join(', ')}.`,
      400,
      'INVALID_POOL_KIND',
    );
  }
  const socketPath = args[spec.socket] || args.socketPath;
  const host = args[spec.host] || args.host;
  const port = args[spec.port] ?? args.port;
  const explicitUser = args[spec.user];
  const user = explicitUser || args.user;
  const explicitRole = args[spec.role];
  const mode = args.pgMode || (socketPath ? 'cloudsql' : (process.env.COHERENCE_PG_MODE || 'local'));
  const role = explicitRole || ((explicitUser || mode === 'cloudsql') ? spec.defaultRole : null);
  return {
    mode,
    database: args.database,
    ...(socketPath ? { socketPath } : {}),
    ...(host ? { host } : {}),
    ...(port !== null && port !== undefined ? { port } : {}),
    ...(user ? { user } : {}),
    ...(role ? { role } : {}),
    applicationName: `${applicationPrefix}-${kind}`,
  };
}

async function withPairedPools(
  writePoolConfig,
  readPoolConfig,
  fn,
  { createPoolFn = createPool } = {},
) {
  let writePool = null;
  let readPool = null;
  try {
    writePool = await createPoolFn(writePoolConfig);
    readPool = await createPoolFn(readPoolConfig);
    return await fn({ writePool, readPool });
  } finally {
    await Promise.all([
      writePool ? writePool.end().catch(() => {}) : Promise.resolve(),
      readPool ? readPool.end().catch(() => {}) : Promise.resolve(),
    ]);
  }
}

/**
 * Opens both app and readonly pools and guarantees both are closed in finally,
 * including closing appPool if opening readPool throws.
 */
export async function withAppAndReadPools(
  appPoolConfig,
  readPoolConfig,
  fn,
  opts = {},
) {
  return withPairedPools(
    appPoolConfig,
    readPoolConfig,
    ({ writePool, readPool }) => fn({ appPool: writePool, readPool }),
    opts,
  );
}

/**
 * Opens both worker and readonly pools and guarantees both are closed in finally,
 * including closing workerPool if opening readPool throws.
 */
export async function withWorkerAndReadPools(
  workerPoolConfig,
  readPoolConfig,
  fn,
  opts = {},
) {
  return withPairedPools(
    workerPoolConfig,
    readPoolConfig,
    ({ writePool, readPool }) => fn({ workerPool: writePool, readPool }),
    opts,
  );
}

export async function withReadPool(
  readPoolConfig,
  fn,
  { createPoolFn = createPool } = {},
) {
  let readPool = null;
  try {
    readPool = await createPoolFn(readPoolConfig);
    return await fn(readPool);
  } finally {
    if (readPool) await readPool.end().catch(() => {});
  }
}

async function readAndValidateKeyFile(keyFile, {
  expectedKeyScope,
  dbContext,
  operationLabel,
}) {
  if (!keyFile) {
    throw new AppError(
      `${operationLabel} requires --key-file (mode-600 ${expectedKeyScope} signing key) or dbToken.`,
      400,
      'MISSING_KEY_FILE',
    );
  }
  const key = await readKeyFile(keyFile);
  try {
    if (key.keyScope !== expectedKeyScope) {
      throw new AppError(
        `${operationLabel} requires a ${expectedKeyScope} signing key (got keyScope=${key.keyScope}).`,
        400,
        'INVALID_KEY_SCOPE',
      );
    }
    if (key.environment !== dbContext.environment) {
      throw new AppError(
        `Signing key environment "${key.environment}" does not match database environment "${dbContext.environment}".`,
        400,
        'KEY_ENVIRONMENT_MISMATCH',
      );
    }
    if (!key.companySlug || key.companySlug !== dbContext.company_slug) {
      throw new AppError(
        `Signing key companySlug "${String(key.companySlug || '(missing)')}" does not match database company_slug "${dbContext.company_slug}".`,
        400,
        'KEY_COMPANY_MISMATCH',
      );
    }
    return key;
  } catch (err) {
    key.secretBytes.fill(0);
    throw err;
  }
}

export async function createStaffTokenProvider(readPool, {
  keyFile,
  actorEmail,
  actorPersonId,
  dbContext,
  tokenTtlSeconds = 300,
  renewBeforeSeconds = 60,
  operationLabel = 'Provisioned import',
}) {
  const key = await readAndValidateKeyFile(keyFile, {
    expectedKeyScope: 'nusear_staff',
    dbContext,
    operationLabel,
  });
  let handoff = false;
  try {
    let resolvedActorId = actorPersonId ? String(actorPersonId).trim() : null;
    if (resolvedActorId) {
      const res = await readPool.query(
        `SELECT p.id
         FROM iam.people p
         JOIN iam.person_versions pv ON pv.person_id = p.id AND pv.superseded_by_id IS NULL
         WHERE p.id = $1::uuid AND p.person_kind = 'human' AND p.principal_origin = 'nusear_staff' AND pv.status = 'active'`,
        [resolvedActorId],
      );
      if (res.rows.length !== 1) {
        throw new AppError('Specified actorPersonId is not an active nusear_staff human in this database.', 400, 'ACTOR_NOT_FOUND');
      }
    } else if (actorEmail) {
      const normEmail = String(actorEmail).trim().toLowerCase();
      const res = await readPool.query(
        `SELECT p.id
         FROM iam.people p
         JOIN iam.person_versions pv ON pv.person_id = p.id AND pv.superseded_by_id IS NULL
         WHERE p.person_kind = 'human' AND p.principal_origin = 'nusear_staff'
           AND pv.status = 'active' AND pv.primary_email = $1`,
        [normEmail],
      );
      if (res.rows.length !== 1) {
        throw new AppError('Active nusear_staff user not found for specified actor email.', 400, 'ACTOR_NOT_FOUND');
      }
      resolvedActorId = res.rows[0].id;
    } else {
      throw new AppError(
        `${operationLabel} requires --actor-email or --actor-person-id when minting a token from --key-file.`,
        400,
        'MISSING_ACTOR',
      );
    }

    const provider = createRenewingTokenProvider({
      keyId: key.keyId,
      secretBytes: key.secretBytes,
      environment: dbContext.environment,
      actorPersonId: resolvedActorId,
      ttlSeconds: tokenTtlSeconds,
      renewBeforeSeconds,
    });
    handoff = true;
    return provider;
  } finally {
    if (!handoff) {
      key.secretBytes.fill(0);
    }
  }
}

async function queryActiveWorkerPrincipals(readPool) {
  return (await readPool.query(
    `SELECT p.id, pv.legal_name
     FROM iam.people p
     JOIN iam.person_versions pv ON pv.person_id = p.id AND pv.superseded_by_id IS NULL
     WHERE p.person_kind = 'service'
       AND p.principal_origin = 'service'
       AND pv.status = 'active'
       AND EXISTS (
         SELECT 1
         FROM iam.role_grants g
         JOIN iam.roles r ON r.id = g.role_id
         JOIN iam.role_versions rv
           ON rv.role_id = r.id
          AND rv.superseded_by_id IS NULL
          AND rv.status = 'active'
         WHERE g.person_id = p.id
           AND g.superseded_by_id IS NULL
           AND g.status = 'active'
           AND g.valid_range @> iam.business_today()
           AND r.slug = 'coherence_worker_svc'
       )
     ORDER BY pv.journal_seq ASC`,
  )).rows;
}

export async function createWorkerTokenProvider(readPool, {
  keyFile,
  workerPersonId = null,
  workerName = null,
  dbContext,
  tokenTtlSeconds = 300,
  renewBeforeSeconds = 60,
  operationLabel = 'Emit materialization',
}) {
  if (workerPersonId && workerName) {
    throw new AppError(
      'Specify at most one of --worker-person-id or --worker-name, not both.',
      400,
      'INVALID_CLI_ARGS',
    );
  }
  const key = await readAndValidateKeyFile(keyFile, {
    expectedKeyScope: 'service',
    dbContext,
    operationLabel,
  });
  let handoff = false;
  try {
    const workers = await queryActiveWorkerPrincipals(readPool);
    let matches = workers;
    if (workerPersonId) {
      const targetId = String(workerPersonId).trim();
      matches = workers.filter((w) => w.id === targetId);
    } else if (workerName) {
      const targetName = String(workerName).trim();
      matches = workers.filter((w) => w.legal_name === targetName);
    }
    if (matches.length === 0) {
      throw new AppError(
        'No active Coherence worker service principal found in this database.',
        400,
        'WORKER_NOT_FOUND',
      );
    }
    if (matches.length > 1) {
      throw new AppError(
        'Multiple active Coherence worker service principals found; specify --worker-person-id or --worker-name.',
        409,
        'AMBIGUOUS_WORKER_PRINCIPAL',
      );
    }

    const provider = createRenewingTokenProvider({
      keyId: key.keyId,
      secretBytes: key.secretBytes,
      environment: dbContext.environment,
      actorPersonId: matches[0].id,
      ttlSeconds: tokenTtlSeconds,
      renewBeforeSeconds,
    });
    handoff = true;
    return provider;
  } finally {
    if (!handoff) {
      key.secretBytes.fill(0);
    }
  }
}

export async function inspectProvisionedCompanyDatabase(readPool, {
  companySlug = null,
  companyDisplayName = null,
  expectedEnvironment = null,
  allowNonDev = false,
  allowScratchDatabase = true,
  writePoolConfig = null,
  readPoolConfig = null,
  operationLabel = 'Provisioned operation',
} = {}) {
  const [readIdentityRes, dbMetaRes] = await Promise.all([
    readPool.query(DB_IDENTITY_SQL),
    readPool.query(`
      SELECT dc.environment, dc.db_role_kind, dc.company_slug, dc.tenant_org_id, dc.support_external_label,
             ov.display_name AS company_display_name, ov.status AS company_status
      FROM iam.database_context dc
      JOIN iam.organization_versions ov ON ov.organization_id = dc.tenant_org_id AND ov.superseded_by_id IS NULL
      WHERE dc.singleton = true
    `),
  ]);

  const readIdentity = readIdentityRes.rows[0];
  const dbContext = dbMetaRes.rows[0];
  if (!dbContext) {
    throw new AppError('Target database is not provisioned: iam.database_context is empty.', 409, 'DATABASE_NOT_PROVISIONED');
  }
  if (dbContext.db_role_kind !== 'company_working') {
    throw new AppError(
      `Refusing ${operationLabel} on non-company database (db_role_kind=${dbContext.db_role_kind}).`,
      400,
      'INVALID_DB_ROLE_KIND',
    );
  }
  if (dbContext.company_status !== 'active') {
    throw new AppError(
      `Company organization "${dbContext.company_slug}" is not active (status=${dbContext.company_status}).`,
      409,
      'COMPANY_ORG_INACTIVE',
    );
  }
  if (expectedEnvironment && dbContext.environment !== expectedEnvironment) {
    throw new AppError(
      `Database environment "${dbContext.environment}" does not match requested environment "${expectedEnvironment}".`,
      409,
      'ENVIRONMENT_MISMATCH',
    );
  }
  if (dbContext.environment !== 'dev' && !allowNonDev) {
    throw new AppError(
      `Refusing ${operationLabel} in non-dev environment "${dbContext.environment}" unless allowNonDev / --allow-non-dev is explicitly specified.`,
      400,
      'NON_DEV_ENVIRONMENT_REFUSED',
    );
  }
  if (writePoolConfig) {
    assertNonProdEndpoint({ pgConfig: writePoolConfig, environment: dbContext.environment, allowNonDev });
  }
  if (readPoolConfig) {
    assertNonProdEndpoint({ pgConfig: readPoolConfig, environment: dbContext.environment, allowNonDev });
  }
  if (companySlug && companySlug !== dbContext.company_slug) {
    throw new AppError(
      `Requested companySlug "${companySlug}" does not match provisioned database company_slug "${dbContext.company_slug}".`,
      409,
      'COMPANY_SLUG_MISMATCH',
    );
  }
  if (companyDisplayName !== null && companyDisplayName !== undefined) {
    if (String(companyDisplayName) !== dbContext.company_display_name) {
      throw new AppError(
        `Requested company displayName "${companyDisplayName}" does not match provisioned company display_name "${dbContext.company_display_name}".`,
        409,
        'COMPANY_DISPLAY_NAME_MISMATCH',
      );
    }
  }
  assertDatabaseNameAllowed(readIdentity?.database, {
    companySlug: dbContext.company_slug,
    allowScratch: allowScratchDatabase,
  });

  return { readIdentity, dbContext };
}

function assertPoolIdentityMatches(writeIdentity, readIdentity, label) {
  if (
    !writeIdentity
    || writeIdentity.database !== readIdentity.database
    || String(writeIdentity.db_oid) !== String(readIdentity.db_oid)
    || String(writeIdentity.postmaster_start_time) !== String(readIdentity.postmaster_start_time)
  ) {
    throw new AppError(
      `${label} connection (${writeIdentity?.database || 'unknown'}) and readonly connection (${readIdentity.database}) do not reach the same PostgreSQL database.`,
      409,
      'POOL_DATABASE_MISMATCH',
    );
  }
}

function assertPoolContextMatches(writeCtx, dbContext, label) {
  if (
    !writeCtx
    || writeCtx.environment !== dbContext.environment
    || writeCtx.db_role_kind !== dbContext.db_role_kind
    || writeCtx.tenant_org_id !== dbContext.tenant_org_id
    || writeCtx.company_slug !== dbContext.company_slug
  ) {
    throw new AppError(
      `${label} connection iam.database_context does not match readonly connection (${dbContext.company_slug}/${dbContext.environment}/${dbContext.tenant_org_id}).`,
      409,
      'POOL_DATABASE_MISMATCH',
    );
  }
}

/**
 * Verifies that readPool and appPool connect to the exact same PostgreSQL server instance,
 * database OID/name, and iam.database_context tenant before any write runs.
 */
export async function verifySameCompanyDatabase({ appPool, dbToken, readIdentity, dbContext }) {
  const appIdentity = (await appPool.query(DB_IDENTITY_SQL)).rows[0];
  assertPoolIdentityMatches(appIdentity, readIdentity, 'App');

  const appCtxRes = await inReadTx(appPool, dbToken, (tx) => tx.query(
    'SELECT environment, db_role_kind, tenant_org_id, company_slug, support_external_label FROM app_views.iam_my_context',
  ));
  assertPoolContextMatches(appCtxRes.rows[0], dbContext, 'App');
}

/**
 * Verifies that workerPool runs as non-superuser platform_worker on the exact same PostgreSQL server
 * instance, database OID/name, and iam.database_context tenant as readPool, and verifies dbToken
 * inside PostgreSQL as platform_worker (and as an active service principal authorized to materialize)
 * before any work begins.
 */
export async function verifySameCompanyWorkerDatabase({
  workerPool,
  readPool,
  dbToken,
  readIdentity,
  dbContext,
}) {
  const workerIdentity = (await workerPool.query(WORKER_IDENTITY_SQL)).rows[0];
  if (
    workerIdentity?.current_role !== 'platform_worker'
    || workerIdentity?.is_superuser !== false
    || workerIdentity?.session_is_superuser !== false
  ) {
    throw new AppError('Only the Coherence engine worker service identity may perform this operation.', 403, 'WORKER_ONLY');
  }
  assertPoolIdentityMatches(workerIdentity, readIdentity, 'Worker');

  const workerCtxRes = await workerPool.query(
    'SELECT environment, db_role_kind, tenant_org_id, company_slug, support_external_label FROM iam.database_context WHERE singleton = true',
  );
  assertPoolContextMatches(workerCtxRes.rows[0], dbContext, 'Worker');

  await inReadTx(workerPool, dbToken, (tx) => tx.query(
    'SELECT app_cmd.coherence_authorize_check_run() AS ok',
  ));

  const authRes = await inReadTx(readPool, dbToken, (tx) => tx.query(
    `SELECT a.actor_person_id, p.person_kind, p.principal_origin
     FROM iam.assert_can_write('act:coherence.emit.materialize', $1::uuid) a
     JOIN iam.people p ON p.id = a.actor_person_id`,
    [dbContext.tenant_org_id],
  ));
  const authRow = authRes.rows[0];
  if (!authRow || authRow.person_kind !== 'service' || authRow.principal_origin !== 'service') {
    throw new AppError('Only the Coherence engine worker service identity may perform this operation.', 403, 'WORKER_ONLY');
  }
}
