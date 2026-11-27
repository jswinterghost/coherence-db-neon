// Shared post-import verification checks (Layer 0, Layer 2, and Substance Comparator Gates 1-4)
// and PHI-free report summarizers reused by scripts/prove-history.mjs and provisioned-import.mjs.
import { stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { verifyChain, verifyCommitments, verifyObjects } from '../commands/journal-export.mjs';
import { verifyOverlayReconstruction } from '../compare/overlay-reconstruction.mjs';
import { compareDbRuns, compareRunFolders } from '../compare/run-comparator.mjs';
import { sha256Hex } from '../util/crypto.mjs';
import { redactPhi } from '../util/redact.mjs';

async function isDir(path) {
  return stat(path).then((s) => s.isDirectory(), () => false);
}

export async function snapshotTableCounts(pool) {
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

export function summarizeComparatorTarget(label, rep) {
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

export function summarizeImportLayer1(importReport, idempotency) {
  const layer1Passed = Boolean(importReport.passed) && Boolean(idempotency.passed);
  return {
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
  };
}

export function summarizeLayer2(layer2Report) {
  return {
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
  };
}

function makeMissingTargetReport(problem) {
  return {
    passed: false,
    stoppedAtGate: 1,
    gates: {
      gate1: { passed: false },
      gate2: { passed: false, skipped: true },
      gate3: { passed: false, skipped: true },
      gate4: { passed: false, skipped: true },
    },
    problems: [problem],
  };
}

/**
 * Runs Layer 0 (journal chain, 100%-table commitments, deep object verification) and Layer 2
 * (decision-record overlay reconstruction across every imported checkpoint).
 */
export async function runLayer0AndLayer2Checks({
  readPool,
  stores,
  commands,
  dbToken,
  manifest,
  recordChecks = true,
  checkKeyPrefix = 'import-l0',
  tempBaseDir = tmpdir(),
  parseOverlay = undefined,
}) {
  const problems = [];

  const chain = await verifyChain(readPool);
  const commitments = await verifyCommitments(readPool);
  const objects = await verifyObjects(readPool, stores, { deep: true });

  if (recordChecks) {
    await commands.recordCheck({
      dbToken,
      commandKey: `${checkKeyPrefix}-chain:${chain.headHash}`,
      checkKind: 'chain',
      passed: chain.passed,
      report: chain,
    });
    await commands.recordCheck({
      dbToken,
      commandKey: `${checkKeyPrefix}-commitments:${sha256Hex(JSON.stringify(commitments))}`,
      checkKind: 'commitments',
      passed: commitments.passed,
      report: commitments,
    });
    await commands.recordCheck({
      dbToken,
      commandKey: `${checkKeyPrefix}-objects:${sha256Hex(JSON.stringify(objects))}`,
      checkKind: 'objects',
      passed: objects.passed,
      report: objects,
    });
  }

  const layer0Passed = chain.passed && commitments.passed && objects.passed;
  if (!layer0Passed) {
    for (const p of [...chain.problems, ...commitments.problems, ...objects.problems]) {
      problems.push(redactPhi(`Layer 0: ${p}`));
    }
  }

  const layer2Report = await verifyOverlayReconstruction({
    pool: readPool,
    stores,
    commands: recordChecks ? commands : null,
    dbToken: recordChecks ? dbToken : null,
    pythonPath: manifest.pythonPath || null,
    coherenceRepo: manifest.coherenceRepo || null,
    overlayCheckPath: manifest.overlayCheckPath || undefined,
    tempBaseDir,
    ...(parseOverlay ? { parseOverlay } : {}),
  });
  if (!layer2Report.passed) {
    problems.push(...layer2Report.problems.map((p) => redactPhi(`Layer 2: ${p}`)));
  }

  return {
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
    layer2: summarizeLayer2(layer2Report),
    problems,
  };
}

/**
 * Runs the Substance Comparator (Gates 1 to 4) across manifest compareTargets.
 */
export async function runComparatorChecks({
  readPool,
  stores,
  commands,
  dbToken,
  manifest,
  recordChecks = true,
  tempBaseDir = tmpdir(),
}) {
  const problems = [];
  const comparatorResults = [];
  for (const target of (manifest.compareTargets || [])) {
    const label = target.label || `${target.leftRunSourceFolder || target.leftDir} vs ${target.rightRunSourceFolder || target.rightDir}`;
    let rep;
    if (target.leftRunSourceFolder) {
      const leftRow = (await readPool.query(
        'SELECT id FROM coherence.runs WHERE source_folder = $1 ORDER BY journal_seq DESC LIMIT 1',
        [target.leftRunSourceFolder],
      )).rows[0];
      if (!leftRow) {
        rep = makeMissingTargetReport(`Left run not found in database: ${target.leftRunSourceFolder}`);
      } else if (target.rightRunSourceFolder) {
        const rightRow = (await readPool.query(
          'SELECT id FROM coherence.runs WHERE source_folder = $1 ORDER BY journal_seq DESC LIMIT 1',
          [target.rightRunSourceFolder],
        )).rows[0];
        if (!rightRow) {
          rep = makeMissingTargetReport(`Right run not found in database: ${target.rightRunSourceFolder}`);
        } else {
          rep = await compareDbRuns({
            pool: readPool,
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
            commands: recordChecks ? commands : null,
            dbToken: recordChecks ? dbToken : null,
            tempBaseDir,
          });
        }
      } else if (target.rightDir) {
        if (!(await isDir(target.rightDir))) {
          rep = makeMissingTargetReport(`Right comparator folder does not exist: ${target.rightDir}`);
        } else {
          rep = await compareDbRuns({
            pool: readPool,
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
            commands: recordChecks ? commands : null,
            dbToken: recordChecks ? dbToken : null,
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

  return {
    comparator: {
      ran: comparatorResults.length > 0,
      passed: comparatorResults.every((r) => r.passed),
      targetsChecked: comparatorResults.length,
      targetsPassed: comparatorResults.filter((r) => r.passed).length,
      targets: comparatorResults,
    },
    problems,
  };
}

/**
 * Runs Layer 0, Layer 2, and Substance Comparator (Gates 1-4) in order.
 */
export async function runPostImportChecks(opts) {
  const l02 = await runLayer0AndLayer2Checks(opts);
  const comp = await runComparatorChecks(opts);
  return {
    layer0: l02.layer0,
    layer2: l02.layer2,
    comparator: comp.comparator,
    problems: [...l02.problems, ...comp.problems],
  };
}
