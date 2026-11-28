// Provisioned-database read-only history import runner: validates target database & environment,
// verifies readPool and appPool reach the exact same company database, mints short-lived renewing
// session tokens (zeroing secret bytes in finally), runs executeHistoryImport + idempotency +
// post-import checks, and never modifies source folders.
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAppCommands } from '../commands/app-cmd.mjs';
import { assertDatabaseNameAllowed, assertNonProdEndpoint } from '../iam/provision-guards.mjs';
import {
  createStaffTokenProvider,
  DB_IDENTITY_SQL,
  verifySameCompanyDatabase,
} from '../iam/provisioned-runtime.mjs';
import { AppError, redactPhi } from '../util/redact.mjs';
import { executeHistoryImport, loadImportManifestFile } from './history-importer.mjs';
import { runPostImportChecks, snapshotTableCounts, summarizeImportLayer1 } from './post-import-checks.mjs';

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
    // the upline statement's own lines name the company, so the manifest must name it exactly as the database does
    const companyNameRes = await readPool.query(
      'SELECT ov.display_name FROM iam.organization_versions ov WHERE ov.organization_id = $1 AND ov.superseded_by_id IS NULL',
      [dbContext.tenant_org_id],
    );
    const companyDisplayName = companyNameRes.rows[0]?.display_name ?? null;
    if (!companyDisplayName || manifest.displayName !== companyDisplayName) {
      throw new AppError(
        `Manifest displayName "${manifest.displayName}" does not match the provisioned company's name "${companyDisplayName}".`,
        409,
        'COMPANY_DISPLAY_NAME_MISMATCH',
      );
    }

    let effectiveToken = dbToken;
    if (!effectiveToken) {
      tokenProvider = await createStaffTokenProvider(readPool, {
        keyFile,
        actorEmail,
        actorPersonId,
        dbContext,
        tokenTtlSeconds,
        renewBeforeSeconds,
        operationLabel: 'History import',
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
