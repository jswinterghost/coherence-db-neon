// Shared Release P1 runtime helpers for provisioned-database CLIs and importers (history import
// and Agent Register import): pool config construction, paired app/readonly pool lifecycle with
// partial-failure cleanup, mode-600 nusear_staff renewing token minting, and same-database checks.
import { createPool, inReadTx } from '../db/pg-client.mjs';
import { AppError } from '../util/redact.mjs';
import { createRenewingTokenProvider, readKeyFile } from './tokens.mjs';

export const DB_IDENTITY_SQL = `
  SELECT pg_catalog.current_database() AS database,
         (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()) AS db_oid,
         pg_catalog.pg_postmaster_start_time() AS postmaster_start_time
`;

export function buildProvisionedPoolConfig(args, kind, { applicationPrefix = 'coherence-import' } = {}) {
  const socketPath = kind === 'app'
    ? (args.appSocketPath || args.socketPath)
    : (args.readonlySocketPath || args.socketPath);
  const host = kind === 'app' ? (args.appHost || args.host) : (args.readonlyHost || args.host);
  const port = kind === 'app' ? (args.appPort ?? args.port) : (args.readonlyPort ?? args.port);
  const explicitUser = kind === 'app' ? args.appUser : args.readonlyUser;
  const user = explicitUser || args.user;
  const explicitRole = kind === 'app' ? args.appRole : args.readonlyRole;
  const mode = args.pgMode || (socketPath ? 'cloudsql' : (process.env.COHERENCE_PG_MODE || 'local'));
  const defaultRole = kind === 'app' ? 'platform_app' : 'platform_readonly';
  const role = explicitRole || ((explicitUser || mode === 'cloudsql') ? defaultRole : null);
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

/**
 * Opens both app and readonly pools and guarantees both are closed in finally,
 * including closing appPool if opening readPool throws.
 */
export async function withAppAndReadPools(
  appPoolConfig,
  readPoolConfig,
  fn,
  { createPoolFn = createPool } = {},
) {
  let appPool = null;
  let readPool = null;
  try {
    appPool = await createPoolFn(appPoolConfig);
    readPool = await createPoolFn(readPoolConfig);
    return await fn({ appPool, readPool });
  } finally {
    await Promise.all([
      appPool ? appPool.end().catch(() => {}) : Promise.resolve(),
      readPool ? readPool.end().catch(() => {}) : Promise.resolve(),
    ]);
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
  if (!keyFile) {
    throw new AppError(
      `${operationLabel} requires --key-file (mode-600 nusear_staff signing key) or dbToken.`,
      400,
      'MISSING_KEY_FILE',
    );
  }
  const key = await readKeyFile(keyFile);
  let handoff = false;
  try {
    if (key.keyScope !== 'nusear_staff') {
      throw new AppError(
        `${operationLabel} requires a nusear_staff signing key (got keyScope=${key.keyScope}).`,
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

/**
 * Verifies that readPool and appPool connect to the exact same PostgreSQL server instance,
 * database OID/name, and iam.database_context tenant before any write runs.
 */
export async function verifySameCompanyDatabase({ appPool, dbToken, readIdentity, dbContext }) {
  const appIdentity = (await appPool.query(DB_IDENTITY_SQL)).rows[0];
  if (
    !appIdentity
    || appIdentity.database !== readIdentity.database
    || String(appIdentity.db_oid) !== String(readIdentity.db_oid)
    || String(appIdentity.postmaster_start_time) !== String(readIdentity.postmaster_start_time)
  ) {
    throw new AppError(
      `App connection (${appIdentity?.database || 'unknown'}) and readonly connection (${readIdentity.database}) do not reach the same PostgreSQL database.`,
      409,
      'POOL_DATABASE_MISMATCH',
    );
  }

  const appCtxRes = await inReadTx(appPool, dbToken, (tx) => tx.query(
    'SELECT environment, db_role_kind, tenant_org_id, company_slug, support_external_label FROM app_views.iam_my_context',
  ));
  const appCtx = appCtxRes.rows[0];
  if (
    !appCtx
    || appCtx.environment !== dbContext.environment
    || appCtx.db_role_kind !== dbContext.db_role_kind
    || appCtx.tenant_org_id !== dbContext.tenant_org_id
    || appCtx.company_slug !== dbContext.company_slug
  ) {
    throw new AppError(
      `App connection iam.database_context does not match readonly connection (${dbContext.company_slug}/${dbContext.environment}/${dbContext.tenant_org_id}).`,
      409,
      'POOL_DATABASE_MISMATCH',
    );
  }
}
