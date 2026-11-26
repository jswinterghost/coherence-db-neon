#!/usr/bin/env node
// Read-only history proof runner: migrates a fresh local throwaway test_* PostgreSQL 17 database,
// imports a company-agnostic JSON manifest read-only (no network), runs Layers 0, 1, 2, 4 and the
// substance comparator (Gates 1-4) where inputs exist, and prints only a strictly PHI-free summary.
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, posix, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAppCommands } from '../src/commands/app-cmd.mjs';
import {
  compareDatabasesAsOf,
  exportJournalNdjson,
  rebuildFromJournalExport,
  verifyChain,
  verifyCommitments,
  verifyObjects,
} from '../src/commands/journal-export.mjs';
import { verifyOverlayReconstruction } from '../src/compare/overlay-reconstruction.mjs';
import { compareDbRuns, compareRunFolders } from '../src/compare/run-comparator.mjs';
import { runMigrations } from '../src/db/migrate.mjs';
import { createClient, createPool, resolveLocalUser } from '../src/db/pg-client.mjs';
import { CANONICAL_TOOLS, seedIamCatalog } from '../src/iam/catalog.mjs';
import {
  executeHistoryImport,
  loadImportManifestFile,
  planImportManifestFile,
  readLegacyStatementBatches,
} from '../src/importer/history-importer.mjs';
import { createFileObjectStore } from '../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../src/storage/stores.mjs';
import { sha256Hex } from '../src/util/crypto.mjs';
import { AppError, redactPhi } from '../src/util/redact.mjs';

const TEST_DB_NAME_RE = /^test_[a-z0-9_]+$/;

async function isDir(path) {
  return stat(path).then((s) => s.isDirectory(), () => false);
}

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

async function resolveCanonicalPath(targetPath) {
  const abs = resolve(targetPath);
  const trailing = [];
  let cur = abs;
  while (true) {
    try {
      const real = await realpath(cur);
      return trailing.length ? join(real, ...trailing.reverse()) : real;
    } catch {
      const parent = dirname(cur);
      if (parent === cur) return abs;
      trailing.push(basename(cur));
      cur = parent;
    }
  }
}

export function isSameOrInsidePath(candidatePath, protectedPath) {
  const norm = (p) => (process.platform === 'darwin' || process.platform === 'win32' ? p.toLowerCase() : p);
  const rel = relative(norm(protectedPath), norm(candidatePath));
  if (rel === '') return true;
  if (isAbsolute(rel)) return false;
  return rel !== '..' && !rel.startsWith(`..${sep}`);
}

export async function assertSafeStoresDir(storesDir, manifestPath) {
  if (!storesDir) return;
  const absManifest = resolve(manifestPath);
  const baseDir = dirname(absManifest);
  const raw = JSON.parse(await readFile(absManifest, 'utf8'));
  const resolveManifestPath = (val) => (
    typeof val === 'string' && val.trim()
      ? (isAbsolute(val) ? resolve(val) : resolve(baseDir, val))
      : null
  );

  const protectedEntries = [];
  const addProtected = (key, val) => {
    const resolved = resolveManifestPath(val);
    if (resolved) protectedEntries.push({ key, path: resolved });
  };

  addProtected('coherenceRoot', raw?.coherenceRoot);
  addProtected('coherenceRepo', raw?.coherenceRepo);
  addProtected('nusearDataDir', raw?.nusearDataDir);
  addProtected('nusearSqlitePath', raw?.nusearSqlitePath);

  if (raw?.sources && typeof raw.sources === 'object') {
    for (const [key, val] of Object.entries(raw.sources)) {
      if (typeof val === 'string') addProtected(`sources.${key}`, val);
    }
  }
  if (Array.isArray(raw?.overlayCheckpoints)) {
    raw.overlayCheckpoints.forEach((cp, idx) => {
      addProtected(`overlayCheckpoints[${idx}]`, cp?.path || cp?.absPath);
    });
  }
  if (Array.isArray(raw?.compareTargets)) {
    raw.compareTargets.forEach((ct, idx) => {
      addProtected(`compareTargets[${idx}].leftDir`, ct?.leftDir);
      addProtected(`compareTargets[${idx}].rightDir`, ct?.rightDir);
    });
  }

  const candidateResolved = resolve(storesDir);
  const candidateCanonical = await resolveCanonicalPath(storesDir);
  const codeResolved = join(candidateResolved, 'code');
  const dataResolved = join(candidateResolved, 'data');
  const writeTargets = [
    { label: '--stores-dir', resolved: candidateResolved, canonical: candidateCanonical, checkContainsProtected: false },
    { label: '--stores-dir/code', resolved: codeResolved, canonical: await resolveCanonicalPath(codeResolved), checkContainsProtected: true },
    { label: '--stores-dir/data', resolved: dataResolved, canonical: await resolveCanonicalPath(dataResolved), checkContainsProtected: true },
  ];

  for (const entry of protectedEntries) {
    const protectedCanonical = await resolveCanonicalPath(entry.path);
    for (const target of writeTargets) {
      if (
        isSameOrInsidePath(target.resolved, entry.path)
        || isSameOrInsidePath(target.canonical, protectedCanonical)
      ) {
        throw new AppError(
          `Refusing ${target.label} equal to or inside configured source path (${entry.key}).`,
          400,
          'UNSAFE_STORES_DIR',
        );
      }
      if (
        target.checkContainsProtected
        && (
          isSameOrInsidePath(entry.path, target.resolved)
          || isSameOrInsidePath(protectedCanonical, target.canonical)
        )
      ) {
        throw new AppError(
          `Refusing --stores-dir because ${target.label} would contain configured source path (${entry.key}).`,
          400,
          'UNSAFE_STORES_DIR',
        );
      }
    }
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

async function snapshotTableCounts(pool) {
  const tables = [
    'runs',
    'stored_files',
    'decision_commits',
    'decisions',
    'generated_overlays',
    'statement_batches',
    'input_versions',
    'imported_files',
    'carries',
  ];
  const counts = {};
  for (const tbl of tables) {
    counts[tbl] = Number((await pool.query(`SELECT pg_catalog.count(*)::int AS n FROM coherence.${tbl}`)).rows[0]?.n ?? 0);
  }
  return counts;
}

function summarizeComparatorTarget(label, rep) {
  const bob = rep.substance?.bob || null;
  const ledger = rep.substance?.ledger || null;
  const stmtDelta = rep.substance?.statementsDelta || null;
  const entStmts = rep.entityStatements || rep.substance?.entityStatements || null;

  return {
    label,
    passed: Boolean(rep.passed),
    stoppedAtGate: rep.stoppedAtGate ?? null,
    gates: {
      gate1: {
        passed: Boolean(rep.gates?.gate1?.passed),
        fileCount: rep.inputs?.fileCount ?? 0,
        sameCount: rep.inputs?.same ?? 0,
        changedCount: rep.inputs?.changed?.length ?? 0,
        onlyLeftCount: rep.inputs?.onlyLeft?.length ?? 0,
        onlyRightCount: rep.inputs?.onlyRight?.length ?? 0,
      },
      gate2: {
        passed: Boolean(rep.gates?.gate2?.passed),
        skipped: Boolean(rep.gates?.gate2?.skipped),
        leftRowCount: bob?.leftRowCount ?? null,
        rightRowCount: bob?.rightRowCount ?? null,
        differingRowCount: bob?.differingRowCount ?? null,
        leftSha256: bob?.leftSha256 ?? null,
        rightSha256: bob?.rightSha256 ?? null,
        columnMismatchCounts: bob?.columnMismatchCounts ?? {},
        moneyCentDeltas: bob?.moneyCentDeltas ?? {},
      },
      gate3: {
        passed: Boolean(rep.gates?.gate3?.passed),
        skipped: Boolean(rep.gates?.gate3?.skipped),
        leftRowCount: ledger?.leftRowCount ?? null,
        rightRowCount: ledger?.rightRowCount ?? null,
        differingRowCount: ledger?.differingRowCount ?? null,
        leftSha256: ledger?.leftSha256 ?? null,
        rightSha256: ledger?.rightSha256 ?? null,
        columnMismatchCounts: ledger?.columnMismatchCounts ?? {},
        moneyCentDeltas: ledger?.moneyCentDeltas ?? {},
        conservationPassed: ledger?.conservation?.passed ?? null,
        bobDownlineRemainderCents: ledger?.conservation?.bobDownlineRemainderCents ?? null,
        bobUplineRemainderCents: ledger?.conservation?.bobUplineRemainderCents ?? null,
      },
      gate4: {
        passed: Boolean(rep.gates?.gate4?.passed),
        skipped: Boolean(rep.gates?.gate4?.skipped),
        statementsDeltaPassed: stmtDelta ? stmtDelta.passed : null,
        statementsDeltaDifferingRows: stmtDelta?.differingRowCount ?? null,
        statementsDeltaLeftSha256: stmtDelta?.leftSha256 ?? null,
        statementsDeltaRightSha256: stmtDelta?.rightSha256 ?? null,
        statementsDeltaCentDeltas: stmtDelta?.moneyCentDeltas ?? {},
        entityStatementsPassed: entStmts?.passed ?? null,
        datesChecked: entStmts?.datesChecked ?? null,
        filesChecked: entStmts?.filesChecked ?? null,
        totalLines: entStmts?.totalLines ?? null,
        ledgerGrossTotal: entStmts?.ledgerGrossTotal ?? null,
        ledgerRemainderCents: entStmts?.ledgerRemainderCents ?? null,
        entityCentDeltas: entStmts?.entityCentDeltas ?? null,
      },
    },
    problems: (rep.problems || []).map((p) => redactPhi(p)),
  };
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

    // Layer 0: Database chain, 100%-table commitments, and deep object verification.
    const chain = await verifyChain(pool);
    const commitments = await verifyCommitments(pool);
    const objects = await verifyObjects(pool, stores, { deep: true });

    await commands.recordCheck({
      dbToken,
      commandKey: `proof-l0-chain:${chain.headHash}`,
      checkKind: 'chain',
      passed: chain.passed,
      report: chain,
    });
    await commands.recordCheck({
      dbToken,
      commandKey: `proof-l0-commitments:${sha256Hex(JSON.stringify(commitments))}`,
      checkKind: 'commitments',
      passed: commitments.passed,
      report: commitments,
    });
    await commands.recordCheck({
      dbToken,
      commandKey: `proof-l0-objects:${sha256Hex(JSON.stringify(objects))}`,
      checkKind: 'objects',
      passed: objects.passed,
      report: objects,
    });

    const layer0Passed = chain.passed && commitments.passed && objects.passed;
    if (!layer0Passed) {
      for (const p of [...chain.problems, ...commitments.problems, ...objects.problems]) {
        problems.push(redactPhi(`Layer 0: ${p}`));
      }
    }

    // Layer 2: Decision-record overlay reconstruction across every imported checkpoint.
    const layer2Report = await verifyOverlayReconstruction({
      pool,
      stores,
      commands,
      dbToken,
      pythonPath: manifest.pythonPath || null,
      coherenceRepo: manifest.coherenceRepo || null,
      overlayCheckPath: manifest.overlayCheckPath || undefined,
      tempBaseDir,
      ...(parseOverlay ? { parseOverlay } : {}),
    });
    if (!layer2Report.passed) {
      problems.push(...layer2Report.problems.map((p) => redactPhi(`Layer 2: ${p}`)));
    }

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

    // Substance Comparator (Gates 1 to 4) where compareTargets exist in manifest.
    const makeMissingTargetReport = (problem) => ({
      passed: false,
      stoppedAtGate: 1,
      gates: {
        gate1: { passed: false },
        gate2: { passed: false, skipped: true },
        gate3: { passed: false, skipped: true },
        gate4: { passed: false, skipped: true },
      },
      problems: [problem],
    });

    const comparatorResults = [];
    for (const target of (manifest.compareTargets || [])) {
      const label = target.label || `${target.leftRunSourceFolder || target.leftDir} vs ${target.rightRunSourceFolder || target.rightDir}`;
      let rep;
      if (target.leftRunSourceFolder) {
        const leftRow = (await pool.query(
          'SELECT id FROM coherence.runs WHERE source_folder = $1 ORDER BY journal_seq DESC LIMIT 1',
          [target.leftRunSourceFolder],
        )).rows[0];
        if (!leftRow) {
          rep = makeMissingTargetReport(`Left run not found in database: ${target.leftRunSourceFolder}`);
        } else if (target.rightRunSourceFolder) {
          const rightRow = (await pool.query(
            'SELECT id FROM coherence.runs WHERE source_folder = $1 ORDER BY journal_seq DESC LIMIT 1',
            [target.rightRunSourceFolder],
          )).rows[0];
          if (!rightRow) {
            rep = makeMissingTargetReport(`Right run not found in database: ${target.rightRunSourceFolder}`);
          } else {
            rep = await compareDbRuns({
              pool,
              stores,
              leftRunId: leftRow.id,
              rightRunId: rightRow.id,
              rightFolderDir: null,
              mode: 'substance',
              entity: target.entity || null,
              entityMapping: target.entityMapping || null,
              columns: target.columns || {},
              moneyColumns: target.moneyColumns || null,
              uplineAmountColumn: target.uplineAmountColumn || null,
              requireStatementsDelta: Boolean(target.requireStatementsDelta),
              requireConservation: Boolean(target.requireConservation),
              expectedEntityParity: target.expectedEntityParity || null,
              commands,
              dbToken,
              tempBaseDir,
            });
          }
        } else if (target.rightDir) {
          if (!(await isDir(target.rightDir))) {
            rep = makeMissingTargetReport(`Right comparator folder does not exist: ${target.rightDir}`);
          } else {
            rep = await compareDbRuns({
              pool,
              stores,
              leftRunId: leftRow.id,
              rightRunId: null,
              rightFolderDir: target.rightDir,
              mode: 'substance',
              entity: target.entity || null,
              entityMapping: target.entityMapping || null,
              columns: target.columns || {},
              moneyColumns: target.moneyColumns || null,
              uplineAmountColumn: target.uplineAmountColumn || null,
              requireStatementsDelta: Boolean(target.requireStatementsDelta),
              requireConservation: Boolean(target.requireConservation),
              expectedEntityParity: target.expectedEntityParity || null,
              commands,
              dbToken,
              tempBaseDir,
            });
          }
        } else {
          rep = makeMissingTargetReport(`Comparator target ${label} is missing both rightRunSourceFolder and rightDir.`);
        }
      } else if (target.leftDir || target.rightDir) {
        if (!target.leftDir || !(await isDir(target.leftDir))) {
          rep = makeMissingTargetReport(`Left comparator folder does not exist: ${target.leftDir || '(missing)'}`);
        } else if (!target.rightDir || !(await isDir(target.rightDir))) {
          rep = makeMissingTargetReport(`Right comparator folder does not exist: ${target.rightDir || '(missing)'}`);
        } else {
          rep = await compareRunFolders(target.leftDir, target.rightDir, {
            mode: 'substance',
            entity: target.entity || null,
            entityMapping: target.entityMapping || null,
            columns: target.columns || {},
            moneyColumns: target.moneyColumns || null,
            uplineAmountColumn: target.uplineAmountColumn || null,
            requireStatementsDelta: Boolean(target.requireStatementsDelta),
            requireConservation: Boolean(target.requireConservation),
            expectedEntityParity: target.expectedEntityParity || null,
            leftLabel: target.label ? `${target.label}:left` : 'left',
            rightLabel: target.label ? `${target.label}:right` : 'right',
          });
        }
      } else {
        rep = makeMissingTargetReport(`Comparator target ${label} is missing leftRunSourceFolder and leftDir.`);
      }
      const summarized = summarizeComparatorTarget(label, rep);
      comparatorResults.push(summarized);
      if (!summarized.passed) {
        problems.push(...summarized.problems.map((p) => redactPhi(`Comparator (${label}): ${p}`)));
      }
    }

    const comparatorPassed = comparatorResults.every((r) => r.passed);
    const layer1Passed = importReport.passed && idempotency.passed;
    const allPassed = layer0Passed && layer1Passed && layer2Report.passed && layer4Passed && comparatorPassed;

    return {
      passed: allPassed,
      database,
      companySlug: manifest.companySlug,
      executedAtUtc: new Date().toISOString(),
      layer0: {
        passed: layer0Passed,
        chain: { passed: chain.passed, entries: chain.entries, headHash: chain.headHash },
        commitments: { passed: commitments.passed, checkedEntries: commitments.checkedEntries },
        objects: {
          passed: objects.passed,
          checkedObjects: objects.checkedObjects,
          codeInDataStoreCount: objects.codeInDataStoreCount ?? 0,
        },
      },
      layer1: {
        passed: layer1Passed,
        importedRunCount: importReport.importedRuns.length,
        skippedRunCount: importReport.skippedRuns.length,
        companySentCarryCount: importReport.companySentCarries.length,
        preCoherenceBatchCount: importReport.preCoherenceBatchesImported,
        methodCorrectionBatchCount: importReport.methodCorrectionBatchesImported,
        standaloneFileCount: importReport.standaloneFilesImported,
        overlayRootCount: (importReport.overlayRoots || []).length,
        overlayRoots: (importReport.overlayRoots || []).map((r) => ({
          folder: r.folder,
          folders: Array.isArray(r.folders) && r.folders.length ? [...r.folders] : [r.folder],
          commitId: r.commitId,
          sha256: r.sha256,
          rowCount: r.rowCount,
        })),
        carriedPriorCount: (importReport.carriedPriors || []).length,
        carriedPriors: (importReport.carriedPriors || []).map((c) => ({
          folder: c.folder,
          commitId: c.commitId,
          parentCommitId: c.parentCommitId,
          sha256: c.sha256,
          rowsAdded: c.rowsAdded,
        })),
        sqliteParity: importReport.sqliteParity,
        rebuild: {
          runsChecked: importReport.rebuildChecks.length,
          runsPassed: importReport.rebuildChecks.filter((c) => c.passed).length,
          standingInputPassed: importReport.standingInputRebuildCheck ? importReport.standingInputRebuildCheck.passed : null,
          standingInputFiles: importReport.standingInputRebuildCheck?.files ?? 0,
          incidentReportPassed: importReport.incidentReportRebuildCheck ? importReport.incidentReportRebuildCheck.passed : null,
          incidentReportFiles: importReport.incidentReportRebuildCheck?.files ?? 0,
          standalonePassed: importReport.standaloneRebuildCheck ? importReport.standaloneRebuildCheck.passed : null,
          standaloneFiles: importReport.standaloneRebuildCheck?.files ?? 0,
        },
        idempotency,
      },
      layer2: {
        passed: layer2Report.passed,
        checkpointsChecked: layer2Report.checkpointsChecked,
        checkpointsPassed: layer2Report.checkpointsPassed,
        totalRowsChecked: layer2Report.totalRowsChecked,
        replacementChainViolations: layer2Report.replacementChainViolations,
        currentParityMismatches: layer2Report.currentParityMismatches,
        bibleAppliedParityMismatches: layer2Report.bibleAppliedParityMismatches,
        checkpoints: layer2Report.checkpoints.map((cp) => ({
          purpose: cp.purpose,
          statementDate: cp.statementDate,
          origHeaderContract: cp.origHeaderContract,
          genHeaderContract: cp.genHeaderContract,
          origRowCount: cp.origRowCount,
          genRowCount: cp.genRowCount,
          origSha256: cp.origSha256,
          genSha256: cp.genSha256,
          rowsEqual: cp.rowsEqual,
          replacementChainValid: cp.replacementChainValid,
          currentParityOk: cp.currentParity.ok,
          bibleAppliedParityOk: cp.bibleAppliedParity.ok,
          passed: cp.passed,
        })),
      },
      layer4: {
        passed: layer4Passed,
        moments: layer4Moments,
      },
      comparator: {
        ran: comparatorResults.length > 0,
        passed: comparatorPassed,
        targetsChecked: comparatorResults.length,
        targetsPassed: comparatorResults.filter((r) => r.passed).length,
        targets: comparatorResults,
      },
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
