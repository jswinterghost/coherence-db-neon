// Provisioned-database read-only history import runner: validates target database & environment,
// verifies readPool and appPool reach the exact same company database, mints short-lived renewing
// session tokens (zeroing secret bytes in finally), runs executeHistoryImport + idempotency +
// post-import checks, and never modifies source folders.
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAppCommands } from '../commands/app-cmd.mjs';
import { inReadTx } from '../db/pg-client.mjs';
import { assertDatabaseNameAllowed, assertNonProdEndpoint } from '../iam/provision-guards.mjs';
import { createRenewingTokenProvider, readKeyFile } from '../iam/tokens.mjs';
import { AppError, redactPhi } from '../util/redact.mjs';
import { executeHistoryImport, loadImportManifestFile } from './history-importer.mjs';
import { runPostImportChecks, snapshotTableCounts, summarizeImportLayer1 } from './post-import-checks.mjs';

const DB_IDENTITY_SQL = `
  SELECT pg_catalog.current_database() AS database,
         (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()) AS db_oid,
         pg_catalog.pg_postmaster_start_time() AS postmaster_start_time
`;

async function createImportTokenProvider(readPool, {
  keyFile,
  actorEmail,
  actorPersonId,
  dbContext,
  tokenTtlSeconds = 300,
  renewBeforeSeconds = 60,
}) {
  const key = await readKeyFile(keyFile);
  let handoff = false;
  try {
    if (key.keyScope !== 'nusear_staff') {
      throw new AppError(
        `History import requires a nusear_staff signing key (got keyScope=${key.keyScope}).`,
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
        throw new AppError(`Active nusear_staff user not found for email "${normEmail}".`, 400, 'ACTOR_NOT_FOUND');
      }
      resolvedActorId = res.rows[0].id;
    } else {
      throw new AppError('History import requires --actor-email or --actor-person-id when minting a token from --key-file.', 400, 'MISSING_ACTOR');
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
async function verifySameCompanyDatabase({ appPool, dbToken, readIdentity, dbContext }) {
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

/**
 * Runs a read-only historical import into an already-provisioned company database, reusing
 * executeHistoryImport and the Layer 0 / Layer 1 / Layer 2 / Comparator checks.
 * Nothing is ever written to the source folders referenced by manifestPath.
 */
export async function importHistoryIntoDatabase({
  readPool,
  appPool,
  stores,
  manifestPath,
  keyFile = null,
  actorEmail = null,
  actorPersonId = null,
  dbToken = null,
  allowNonDev = false,
  allowScratchDatabase = true,
  appPoolConfig = null,
  readPoolConfig = null,
  skipIdempotency = false,
  tokenTtlSeconds = 300,
  renewBeforeSeconds = 60,
  parseOverlay = undefined,
  readLegacyStatements = undefined,
  tempRoot = tmpdir(),
} = {}) {
  if (!readPool || !appPool) {
    throw new AppError('importHistoryIntoDatabase requires readPool and appPool.', 400, 'MISSING_POOLS');
  }
  if (!stores) {
    throw new AppError('importHistoryIntoDatabase requires separated code and data stores.', 400, 'MISSING_STORES');
  }
  if (!manifestPath) {
    throw new AppError('importHistoryIntoDatabase requires manifestPath.', 400, 'MISSING_MANIFEST');
  }

  const suffix = randomBytes(4).toString('hex');
  const tempBaseDir = await mkdtemp(join(tempRoot, `coherence-import-${suffix}-`));
  let tokenProvider = null;

  try {
    const manifest = await loadImportManifestFile(manifestPath, { tempBaseDir });
    const [readIdentityRes, dbMetaRes] = await Promise.all([
      readPool.query(DB_IDENTITY_SQL),
      readPool.query(`
        SELECT dc.environment, dc.db_role_kind, dc.company_slug, dc.tenant_org_id, dc.support_external_label
        FROM iam.database_context dc
        WHERE dc.singleton = true
      `),
    ]);
    const readIdentity = readIdentityRes.rows[0];
    const dbContext = dbMetaRes.rows[0];
    if (!dbContext) {
      throw new AppError('Target database is not provisioned: iam.database_context is empty.', 409, 'DATABASE_NOT_PROVISIONED');
    }
    assertDatabaseNameAllowed(readIdentity?.database, {
      companySlug: manifest.companySlug,
      allowScratch: allowScratchDatabase,
    });
    if (dbContext.environment !== 'dev' && !allowNonDev) {
      throw new AppError(
        `Refusing history import into non-dev environment "${dbContext.environment}" unless allowNonDev / --allow-non-dev is explicitly specified.`,
        400,
        'NON_DEV_ENVIRONMENT_REFUSED',
      );
    }
    if (appPoolConfig) {
      assertNonProdEndpoint({ pgConfig: appPoolConfig, environment: dbContext.environment, allowNonDev });
    }
    if (readPoolConfig) {
      assertNonProdEndpoint({ pgConfig: readPoolConfig, environment: dbContext.environment, allowNonDev });
    }
    if (dbContext.db_role_kind !== 'company_working') {
      throw new AppError(`Refusing history import into non-company database (db_role_kind=${dbContext.db_role_kind}).`, 400, 'INVALID_DB_ROLE_KIND');
    }
    if (dbContext.company_slug !== manifest.companySlug) {
      throw new AppError(
        `Manifest companySlug "${manifest.companySlug}" does not match provisioned database company_slug "${dbContext.company_slug}".`,
        409,
        'COMPANY_SLUG_MISMATCH',
      );
    }

    let effectiveToken = dbToken;
    if (!effectiveToken) {
      tokenProvider = await createImportTokenProvider(readPool, {
        keyFile,
        actorEmail,
        actorPersonId,
        dbContext,
        tokenTtlSeconds,
        renewBeforeSeconds,
      });
      effectiveToken = () => tokenProvider.getToken();
    }

    await verifySameCompanyDatabase({
      appPool,
      dbToken: effectiveToken,
      readIdentity,
      dbContext,
    });

    const commands = createAppCommands({ pool: appPool, stores });

    // Initialize coherence.company_meta once if not already present (idempotent across reruns).
    const existingMetaRes = await readPool.query(
      'SELECT company_slug, display_name, default_emit_mode FROM coherence.company_meta WHERE singleton = true',
    );
    let companyInitialized = false;
    if (existingMetaRes.rows.length === 0) {
      const initRes = await commands.initCompany({
        dbToken: effectiveToken,
        commandKey: `import-init:${manifest.companySlug}`,
        slug: manifest.companySlug,
        displayName: manifest.displayName || manifest.companySlug,
        defaultEmitMode: manifest.defaultEmitMode || 'coherence',
      });
      companyInitialized = !initRes.idempotent;
    } else if (existingMetaRes.rows[0].company_slug !== manifest.companySlug) {
      throw new AppError(
        `Existing coherence.company_meta company_slug "${existingMetaRes.rows[0].company_slug}" conflicts with manifest "${manifest.companySlug}".`,
        409,
        'COMPANY_SLUG_MISMATCH',
      );
    }

    const problems = [];
    const importOpts = {
      pool: readPool,
      stores,
      commands,
      dbToken: effectiveToken,
      manifest,
      verifyRebuild: true,
      recordCheck: true,
      tempBaseDir,
      ...(parseOverlay ? { parseOverlay } : {}),
      ...(readLegacyStatements ? { readLegacyStatements } : {}),
    };
    const importReport = await executeHistoryImport(importOpts);
    if (!importReport.passed) {
      problems.push(...importReport.problems.map((p) => redactPhi(`Layer 1: ${p}`)));
    }

    let idempotency = { checked: false, passed: true, deltas: {} };
    if (!skipIdempotency) {
      const before = await snapshotTableCounts(readPool);
      const rerunReport = await executeHistoryImport({
        ...importOpts,
        verifyRebuild: false,
        recordCheck: false,
      });
      const after = await snapshotTableCounts(readPool);
      const deltas = {};
      let idemOk = rerunReport.importedRuns.length === 0;
      for (const [tbl, cnt] of Object.entries(before)) {
        const diff = after[tbl] - cnt;
        deltas[tbl] = diff;
        if (diff !== 0) idemOk = false;
      }
      idempotency = { checked: true, passed: idemOk, deltas };
      if (!idemOk) {
        problems.push(`Layer 1 idempotency failed: non-zero deltas ${JSON.stringify(deltas)}`);
      }
    }

    const postChecks = await runPostImportChecks({
      readPool,
      stores,
      commands,
      dbToken: effectiveToken,
      manifest,
      recordChecks: true,
      checkKeyPrefix: 'import-l0',
      tempBaseDir,
      parseOverlay,
    });
    problems.push(...postChecks.problems);

    const layer1 = summarizeImportLayer1(importReport, idempotency);
    const allPassed = postChecks.layer0.passed
      && layer1.passed
      && postChecks.layer2.passed
      && postChecks.comparator.passed;

    return {
      passed: allPassed,
      database: readIdentity.database,
      environment: dbContext.environment,
      companySlug: manifest.companySlug,
      companyInitialized,
      executedAtUtc: new Date().toISOString(),
      layer0: postChecks.layer0,
      layer1,
      layer2: postChecks.layer2,
      comparator: postChecks.comparator,
      problems,
    };
  } finally {
    if (tokenProvider) tokenProvider.dispose();
    await rm(tempBaseDir, { recursive: true, force: true }).catch(() => {});
  }
}
