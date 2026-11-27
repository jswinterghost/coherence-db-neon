#!/usr/bin/env node
// Read-only history proof runner: migrates a fresh local throwaway test_* PostgreSQL 17 database,
// imports a company-agnostic JSON manifest read-only (no network), runs Layers 0, 1, 2, 4 and the
// substance comparator (Gates 1-4) where inputs exist, and prints only a strictly PHI-free summary.
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAppCommands } from '../src/commands/app-cmd.mjs';
import {
  compareDatabasesAsOf,
  exportJournalNdjson,
  rebuildFromJournalExport,
} from '../src/commands/journal-export.mjs';
import { runMigrations } from '../src/db/migrate.mjs';
import { createClient, createPool, resolveLocalUser } from '../src/db/pg-client.mjs';
import { CANONICAL_TOOLS, seedIamCatalog } from '../src/iam/catalog.mjs';
import {
  executeHistoryImport,
  loadImportManifestFile,
  planImportManifestFile,
  readLegacyStatementBatches,
} from '../src/importer/history-importer.mjs';
import {
  runComparatorChecks,
  runLayer0AndLayer2Checks,
  snapshotTableCounts,
  summarizeImportLayer1,
} from '../src/importer/post-import-checks.mjs';
import {
  assertSafeStoresDir,
  isSameOrInsidePath,
} from '../src/importer/store-path-safety.mjs';
import { createFileObjectStore } from '../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../src/storage/stores.mjs';
import { sha256Hex } from '../src/util/crypto.mjs';
import { AppError, redactPhi } from '../src/util/redact.mjs';

export { assertSafeStoresDir, isSameOrInsidePath };

const TEST_DB_NAME_RE = /^test_[a-z0-9_]+$/;

export function assertProofDbName(dbName) {
  if (typeof dbName !== 'string' || !TEST_DB_NAME_RE.test(dbName)) {
    throw new AppError(
      `Refusing to manage database outside test_* namespace: ${String(dbName || '(empty)')}`,
      400,
      'INVALID_TEST_DATABASE_NAME',
    );
  }
}

export function assertLocalPgHost(host) {
  const h = String(host ?? '').trim();
  if (h.startsWith('/')) {
    const normalized = posix.resolve(h).toLowerCase();
    if (normalized === '/cloudsql' || normalized.startsWith('/cloudsql/')) {
      throw new AppError(
        `Refusing to run proof runner against Cloud SQL socket PGHOST: ${h}`,
        400,
        'NON_LOCAL_PGHOST',
      );
    }
    return;
  }
  const isLocal = h === 'localhost' || h === '127.0.0.1' || h === '::1';
  if (!isLocal) {
    throw new AppError(
      `Refusing to run proof runner against non-local PGHOST: ${h || '(empty)'}`,
      400,
      'NON_LOCAL_PGHOST',
    );
  }
}

function getAdminPgConfig() {
  return {
    mode: 'local',
    host: process.env.PGHOST || '/tmp',
    port: Number(process.env.PGPORT || 5432),
    database: process.env.PGADMIN_DATABASE || 'postgres',
    user: resolveLocalUser(),
    password: process.env.PGPASSWORD ?? undefined,
  };
}

async function createFreshTestDb(adminConfig, dbName, { recreate = false } = {}) {
  assertProofDbName(dbName);
  const admin = await createClient(adminConfig);
  try {
    if (recreate) {
      await admin.query(
        'SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()',
        [dbName],
      );
      await admin.query(`DROP DATABASE IF EXISTS "${dbName}"`);
    }
    await admin.query(`CREATE DATABASE "${dbName}" ENCODING 'UTF8'`);
  } finally {
    await admin.end();
  }
}

async function dropTestDb(adminConfig, dbName) {
  assertProofDbName(dbName);
  const admin = await createClient(adminConfig).catch(() => null);
  if (!admin) return;
  try {
    await admin.query(
      'SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()',
      [dbName],
    );
    await admin.query(`DROP DATABASE IF EXISTS "${dbName}"`);
  } finally {
    await admin.end().catch(() => {});
  }
}

function mintProofToken({ keyId, secretBytes, environment = 'local', actorPersonId, ttlSeconds = 3600 }) {
  const expEpoch = Math.floor(Date.now() / 1000) + ttlSeconds;
  const payload = `v1|${keyId}|${environment}|${randomUUID()}|${actorPersonId}|-|${expEpoch}`;
  const sig = createHmac('sha256', secretBytes).update(payload, 'utf8').digest('hex');
  return `${payload}|${sig}`;
}

export async function seedProofIamOwner(pool, { companySlug, displayName, environment = 'local' }) {
  const keyId = `k_proof_${randomBytes(4).toString('hex')}`;
  const secretBytes = randomBytes(32);
  const rootOrgId = randomUUID();
  const companyOrgId = randomUUID();
  const ownerPersonId = randomUUID();

  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    const reqHash = sha256Hex(JSON.stringify({ commandKind: 'iam.bootstrap_proof', companySlug }));
    const seq = (await client.query(
      `INSERT INTO platform.audit_journal (
         environment, actor_person_id, recorded_as, target_org_id,
         command_kind, command_key, request_sha256, body
       ) VALUES ($1, NULL, 'service', NULL, 'iam.bootstrap_proof', $2, $3, '{}'::jsonb)
       RETURNING seq`,
      [environment, `proof-iam-bootstrap-${randomUUID()}`, reqHash],
    )).rows[0].seq;

    await client.query(
      "INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'platform_root',$3),($2,'company',$3)",
      [rootOrgId, companyOrgId, seq],
    );
    await client.query(
      `INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq)
       VALUES ($1,$2,'nusear','Nusear','active',$5),($3,$4,$6,$7,'active',$5)`,
      [randomUUID(), rootOrgId, randomUUID(), companyOrgId, seq, companySlug, displayName || companySlug],
    );
    await client.query(
      `INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)`,
      [randomUUID(), companyOrgId, rootOrgId, seq],
    );
    await client.query(
      `INSERT INTO iam.database_context (singleton, environment, db_role_kind, tenant_org_id, company_slug, support_external_label, journal_seq)
       VALUES (true, $1, 'company_working', $2, $3, 'Nusear support', $4)`,
      [environment, companyOrgId, companySlug, seq],
    );
    await client.query(
      `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, key_scope, active_from, active_until)
       VALUES ($1, $2, $3, 'nusear_staff', pg_catalog.now() - INTERVAL '1 hour', pg_catalog.now() + INTERVAL '24 hours')`,
      [keyId, secretBytes, environment],
    );

    const { rolesBySlug } = await seedIamCatalog(client, { environment, journalSeq: seq });
    const roleOwnerId = rolesBySlug.get('nusear_owner');

    for (const tool of CANONICAL_TOOLS) {
      await client.query(
        `INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq)
         VALUES ($1,$2,$3,'on','active',$4)`,
        [randomUUID(), companyOrgId, tool.id, seq],
      );
    }

    await client.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','nusear_staff',$2)", [ownerPersonId, seq]);
    await client.query(
      "INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq) VALUES ($1,$2,'nusear_staff','Proof Importer','Proof Importer','proof.importer@nusear.example','active',$3)",
      [randomUUID(), ownerPersonId, seq],
    );
    await client.query(
      "INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
      [randomUUID(), ownerPersonId, rootOrgId, seq],
    );
    await client.query(
      "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,true,'org_subtree','[2020-01-01,)'::daterange,'active',$5)",
      [randomUUID(), ownerPersonId, roleOwnerId, rootOrgId, seq],
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }

  return {
    companyOrgId,
    environment,
    ownerToken: mintProofToken({ keyId, secretBytes, environment, actorPersonId: ownerPersonId }),
  };
}

export async function ensureProofIamSubjectsForBatches(pool, { companyOrgId, environment, bridgeResult }) {
  const entities = new Map();
  const npns = new Set();
  for (const batch of [...(bridgeResult?.historicalBatches || []), ...(bridgeResult?.methodCorrectionBatches || [])]) {
    for (const line of (batch.agencyLines || [])) {
      const ent = typeof line.entity === 'string' ? line.entity.trim() : '';
      if (ent) entities.set(ent.toLowerCase(), ent);
      const npn = typeof line.writingNpn === 'string' ? line.writingNpn.trim() : '';
      if (npn) npns.add(npn);
    }
    for (const line of (batch.uplineLines || [])) {
      const ent = typeof (line.sourceEntity ?? line.entity) === 'string' ? (line.sourceEntity ?? line.entity).trim() : '';
      if (ent) entities.set(ent.toLowerCase(), ent);
      const npn = typeof line.writingNpn === 'string' ? line.writingNpn.trim() : '';
      if (npn) npns.add(npn);
    }
  }
  if (entities.size === 0 && npns.size === 0) return;

  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    const existingOrgs = new Set();
    const orgRes = await client.query(
      `SELECT pg_catalog.lower(pg_catalog.btrim(ov.slug)) AS s, pg_catalog.lower(pg_catalog.btrim(ov.display_name)) AS d
       FROM iam.organization_versions ov WHERE ov.superseded_by_id IS NULL`,
    );
    for (const r of orgRes.rows) {
      if (r.s) existingOrgs.add(r.s);
      if (r.d) existingOrgs.add(r.d);
    }
    const existingNpns = new Set(
      (await client.query("SELECT npn FROM iam.person_versions WHERE superseded_by_id IS NULL AND principal_origin = 'company_local' AND npn IS NOT NULL")).rows.map((r) => r.npn),
    );
    const missingEntities = [...entities.entries()].filter(([k]) => !existingOrgs.has(k));
    const missingNpns = [...npns].filter((n) => !existingNpns.has(n));
    if (missingEntities.length > 0 || missingNpns.length > 0) {
      const seq = (await client.query(
        `INSERT INTO platform.audit_journal (
           environment, actor_person_id, recorded_as, target_org_id,
           command_kind, command_key, request_sha256, body
         ) VALUES ($1, NULL, 'service', $2::uuid, 'iam.seed_proof_subjects', $3, $4, '{}'::jsonb)
         RETURNING seq`,
        [environment, companyOrgId, `proof-iam-subjects-${randomUUID()}`, sha256Hex(JSON.stringify({ entities: missingEntities.length, npns: missingNpns.length }))],
      )).rows[0].seq;
      let slugIdx = 0;
      for (const [key, display] of missingEntities) {
        slugIdx += 1;
        const orgId = randomUUID();
        const base = key.replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 40).replace(/_+$/, '') || `ag_${slugIdx}`;
        let slug = base;
        while (existingOrgs.has(slug)) {
          slug = `${base}_${slugIdx}`;
          slugIdx += 1;
        }
        existingOrgs.add(slug);
        existingOrgs.add(key);
        await client.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'agency',$2)", [orgId, seq]);
        await client.query(
          "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,$3,$4,'active',$5)",
          [randomUUID(), orgId, slug, display, seq],
        );
        await client.query(
          "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,)'::daterange,'active',$4)",
          [randomUUID(), orgId, companyOrgId, seq],
        );
      }
      for (const npn of missingNpns) {
        const pid = randomUUID();
        await client.query("INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','company_local',$2)", [pid, seq]);
        await client.query(
          "INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, npn, status, journal_seq) VALUES ($1,$2,'company_local',$3,$3,$4,$5,'active',$6)",
          [randomUUID(), pid, `Proof Agent ${npn}`, `proof.npn.${npn.toLowerCase().replace(/[^a-z0-9]/g, '_')}@proof.example`, npn, seq],
        );
      }
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export async function runHistoryProof({
  manifestPath,
  database,
  recreate = false,
  dropDb = false,
  storesDir = null,
  keepStores = false,
  skipIdempotency = false,
  parseOverlay = undefined,
  readLegacyStatements = undefined,
  tempRoot = tmpdir(),
} = {}) {
  assertProofDbName(database);
  const adminConfig = getAdminPgConfig();
  assertLocalPgHost(adminConfig.host);
  await assertSafeStoresDir(storesDir, manifestPath);

  const suffix = randomBytes(4).toString('hex');
  const tempBaseDir = await mkdtemp(join(tempRoot, `coherence-proof-${suffix}-`));
  const ownStoresDir = !storesDir;
  let dbCreated = false;
  let pool = null;

  try {
    const manifest = await loadImportManifestFile(manifestPath, { tempBaseDir });
    const resolvedStoresDir = storesDir ? resolve(storesDir) : join(tempBaseDir, 'stores');
    const codeRoot = join(resolvedStoresDir, 'code');
    const dataRoot = join(resolvedStoresDir, 'data');
    await mkdir(codeRoot, { recursive: true, mode: 0o700 });
    await mkdir(dataRoot, { recursive: true, mode: 0o700 });

    await createFreshTestDb(adminConfig, database, { recreate });
    dbCreated = true;
    const pgConfig = { ...adminConfig, database };
    pool = await createPool(pgConfig);
    await runMigrations(pool);
    const codeStore = createCodeStore({ backend: createFileObjectStore({ rootDir: codeRoot, label: `proof-code-${suffix}` }) });
    const dataStore = createDataStore({ backend: createFileObjectStore({ rootDir: dataRoot, label: `proof-data-${suffix}` }) });
    const stores = createStorePair({ codeStore, dataStore });
    const commands = createAppCommands({ pool, stores });
    const proofIam = await seedProofIamOwner(pool, {
      companySlug: manifest.companySlug,
      displayName: manifest.displayName || manifest.companySlug,
    });
    const dbToken = proofIam.ownerToken;
    const baseReadLegacyStatements = readLegacyStatements || readLegacyStatementBatches;
    const wrappedReadLegacyStatements = async (opts) => {
      const bridgeResult = await baseReadLegacyStatements(opts);
      await ensureProofIamSubjectsForBatches(pool, {
        companyOrgId: proofIam.companyOrgId,
        environment: proofIam.environment,
        bridgeResult,
      });
      return bridgeResult;
    };

    await commands.initCompany({
      dbToken,
      commandKey: `proof-init:${manifest.companySlug}`,
      slug: manifest.companySlug,
      displayName: manifest.displayName || manifest.companySlug,
      defaultEmitMode: manifest.defaultEmitMode || 'coherence',
    });

    const problems = [];

    // Layer 1: Read-only import + full byte-for-byte rebuild proof + idempotency.
    const importOpts = {
      pool,
      stores,
      commands,
      dbToken,
      manifest,
      verifyRebuild: true,
      recordCheck: true,
      tempBaseDir,
      ...(parseOverlay ? { parseOverlay } : {}),
      readLegacyStatements: wrappedReadLegacyStatements,
    };
    const importReport = await executeHistoryImport(importOpts);
    if (!importReport.passed) {
      problems.push(...importReport.problems.map((p) => redactPhi(`Layer 1: ${p}`)));
    }

    let idempotency = { checked: false, passed: true, deltas: {} };
    if (!skipIdempotency) {
      const before = await snapshotTableCounts(pool);
      const rerunReport = await executeHistoryImport({
        ...importOpts,
        verifyRebuild: false,
        recordCheck: false,
      });
      const after = await snapshotTableCounts(pool);
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

    // Layer 0 (chain, commitments, objects) and Layer 2 (overlay reconstruction).
    const l02Checks = await runLayer0AndLayer2Checks({
      readPool: pool,
      stores,
      commands,
      dbToken,
      manifest,
      recordChecks: true,
      checkKeyPrefix: 'proof-l0',
      tempBaseDir,
      parseOverlay,
    });
    problems.push(...l02Checks.problems);

    // Layer 4: Point-in-time database rebuild from its own NDJSON journal (midpoint and tip).
    const tipSeq = Number((await pool.query('SELECT COALESCE(pg_catalog.max(seq), 0)::bigint AS seq FROM coherence.journal_entries')).rows[0]?.seq ?? 0);
    const ndjson = await exportJournalNdjson(pool);
    const momentsToCheck = tipSeq > 2
      ? [
        { label: 'midpoint', cutoffSeq: Math.floor(tipSeq / 2) },
        { label: 'tip', cutoffSeq: tipSeq },
      ]
      : [{ label: 'tip', cutoffSeq: tipSeq }];

    const layer4Moments = [];
    for (const m of momentsToCheck) {
      const rebDbName = `test_l4_${randomBytes(5).toString('hex')}`;
      await createFreshTestDb(adminConfig, rebDbName, { recreate: true });
      const rebPool = await createPool({ ...adminConfig, database: rebDbName });
      try {
        await runMigrations(rebPool);
        const reb = await rebuildFromJournalExport(rebPool, ndjson, { upToSeq: m.cutoffSeq });
        const cmp = await compareDatabasesAsOf(pool, rebPool, m.cutoffSeq);
        const momentPassed = cmp.passed && reb.replayed === m.cutoffSeq;
        layer4Moments.push({
          label: m.label,
          cutoffSeq: m.cutoffSeq,
          replayed: reb.replayed,
          passed: momentPassed,
          journalEntriesChecked: cmp.journalEntriesChecked,
          tablesChecked: cmp.tablesChecked,
          runsChecked: cmp.runsChecked,
          tableDiffCount: cmp.tableDiffs.length,
          stageDiffCount: cmp.stageDiffs.length,
          standingInputMatch: cmp.standingInputMatch,
          standingOverlaySha256Match: cmp.standingOverlaySha256Match,
          sourceOverlaySha256: cmp.sourceOverlaySha256,
          rebuiltOverlaySha256: cmp.rebuiltOverlaySha256,
        });
        if (!momentPassed) {
          problems.push(...cmp.problems.map((p) => redactPhi(`Layer 4 (${m.label}): ${p}`)));
        }
      } finally {
        await rebPool.end().catch(() => {});
        await dropTestDb(adminConfig, rebDbName);
      }
    }
    const layer4Passed = layer4Moments.every((m) => m.passed);
    await commands.recordCheck({
      dbToken,
      commandKey: `proof-l4:${sha256Hex(JSON.stringify(layer4Moments))}`,
      checkKind: 'journal_rebuild',
      passed: layer4Passed,
      report: { layer: 4, checkKind: 'journal_rebuild', passed: layer4Passed, moments: layer4Moments },
    });

    // Substance Comparator (Gates 1 to 4) after Layer 4, preserving exact phase and problem order.
    const comparatorChecks = await runComparatorChecks({
      readPool: pool,
      stores,
      commands,
      dbToken,
      manifest,
      recordChecks: true,
      tempBaseDir,
    });
    problems.push(...comparatorChecks.problems);

    const layer1 = summarizeImportLayer1(importReport, idempotency);
    const allPassed = l02Checks.layer0.passed
      && layer1.passed
      && l02Checks.layer2.passed
      && layer4Passed
      && comparatorChecks.comparator.passed;

    return {
      passed: allPassed,
      database,
      companySlug: manifest.companySlug,
      executedAtUtc: new Date().toISOString(),
      layer0: l02Checks.layer0,
      layer1,
      layer2: l02Checks.layer2,
      layer4: {
        passed: layer4Passed,
        moments: layer4Moments,
      },
      comparator: comparatorChecks.comparator,
      problems,
    };
  } finally {
    if (pool) {
      await pool.end().catch(() => {});
    }
    if (dropDb && dbCreated) {
      await dropTestDb(adminConfig, database);
    }
    if (!ownStoresDir || !keepStores) {
      await rm(tempBaseDir, { recursive: true, force: true }).catch(() => {});
    }
  }
}

export async function runHistoryPlan({ manifestPath } = {}) {
  if (!manifestPath) {
    throw new AppError(
      'Usage: node scripts/prove-history.mjs --manifest <file> --plan',
      400,
      'MISSING_CLI_ARGS',
    );
  }
  return planImportManifestFile(manifestPath);
}

function parseCliArgs(argv) {
  const args = {
    manifestPath: null,
    database: null,
    plan: false,
    recreate: false,
    dropDb: false,
    storesDir: null,
    keepStores: false,
    skipIdempotency: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok === '--manifest') args.manifestPath = argv[++i];
    else if (tok === '--database') args.database = argv[++i];
    else if (tok === '--plan') args.plan = true;
    else if (tok === '--stores-dir') args.storesDir = argv[++i];
    else if (tok === '--recreate') args.recreate = true;
    else if (tok === '--drop-db') args.dropDb = true;
    else if (tok === '--keep-stores') args.keepStores = true;
    else if (tok === '--skip-idempotency') args.skipIdempotency = true;
    else throw new AppError(`Unknown argument: ${tok}`, 400, 'INVALID_CLI_ARGS');
  }
  if (args.plan) {
    if (!args.manifestPath) {
      throw new AppError(
        'Usage: node scripts/prove-history.mjs --manifest <file> --plan',
        400,
        'MISSING_CLI_ARGS',
      );
    }
    return args;
  }
  if (!args.manifestPath || !args.database) {
    throw new AppError(
      'Usage: node scripts/prove-history.mjs --manifest <file> --database test_<name> [--recreate] [--drop-db] [--stores-dir <dir>] | --manifest <file> --plan',
      400,
      'MISSING_CLI_ARGS',
    );
  }
  return args;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const cli = parseCliArgs(process.argv.slice(2));
    const summary = cli.plan
      ? await runHistoryPlan({ manifestPath: cli.manifestPath })
      : await runHistoryProof(cli);
    console.log(JSON.stringify(summary, null, 2));
    process.exitCode = summary.passed ? 0 : 1;
  } catch (err) {
    console.error(JSON.stringify({ passed: false, error: redactPhi(err?.message || 'Proof runner failed.'), code: err?.code || 'ERROR' }));
    process.exitCode = 1;
  }
}
