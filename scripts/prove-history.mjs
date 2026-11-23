#!/usr/bin/env node
// Read-only history proof runner: migrates a fresh local throwaway test_* PostgreSQL 17 database,
// imports a company-agnostic JSON manifest read-only (no network), runs Layers 0, 1, 2, 4 and the
// substance comparator (Gates 1-4) where inputs exist, and prints only a strictly PHI-free summary.
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCommandLayer } from '../src/commands/command-layer.mjs';
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
import { executeHistoryImport, loadImportManifestFile } from '../src/importer/history-importer.mjs';
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
  const isLocal = h.startsWith('/') || h === 'localhost' || h === '127.0.0.1' || h === '::1';
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
    const commands = createCommandLayer({ pool, companySlug: manifest.companySlug, stores });
    const actor = { id: 'proof-runner', kind: 'owner', actingFor: null };

    await commands.initCompany({
      actor,
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
      actor,
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
      actor,
      commandKey: `proof-l0-chain:${chain.headHash}`,
      checkKind: 'chain',
      passed: chain.passed,
      report: chain,
    });
    await commands.recordCheck({
      actor,
      commandKey: `proof-l0-commitments:${sha256Hex(JSON.stringify(commitments))}`,
      checkKind: 'commitments',
      passed: commitments.passed,
      report: commitments,
    });
    await commands.recordCheck({
      actor,
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
      actor,
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
      actor,
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
              actor,
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
              actor,
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

function parseCliArgs(argv) {
  const args = {
    manifestPath: null,
    database: null,
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
    else if (tok === '--stores-dir') args.storesDir = argv[++i];
    else if (tok === '--recreate') args.recreate = true;
    else if (tok === '--drop-db') args.dropDb = true;
    else if (tok === '--keep-stores') args.keepStores = true;
    else if (tok === '--skip-idempotency') args.skipIdempotency = true;
    else throw new AppError(`Unknown argument: ${tok}`, 400, 'INVALID_CLI_ARGS');
  }
  if (!args.manifestPath || !args.database) {
    throw new AppError(
      'Usage: node scripts/prove-history.mjs --manifest <file> --database test_<name> [--recreate] [--drop-db] [--stores-dir <dir>]',
      400,
      'MISSING_CLI_ARGS',
    );
  }
  return args;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const cli = parseCliArgs(process.argv.slice(2));
    const summary = await runHistoryProof(cli);
    console.log(JSON.stringify(summary, null, 2));
    process.exitCode = summary.passed ? 0 : 1;
  } catch (err) {
    console.error(JSON.stringify({ passed: false, error: redactPhi(err?.message || 'Proof runner failed.'), code: err?.code || 'ERROR' }));
    process.exitCode = 1;
  }
}
