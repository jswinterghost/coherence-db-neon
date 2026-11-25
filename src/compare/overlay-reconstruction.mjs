// Layer 2 check: verifies that every imported historical overlay checkpoint regenerates from
// PostgreSQL decision records identically through Coherence's Python reader (header contract,
// row count, order, all 15 normalized cells), has a 100% valid replaces_decision_id chain, and
// matches overlay.current() and bible.answers() via decisions_current() and decisions_bible_applied().
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateOverlayCsv, OVERLAY_V2_COLUMNS } from '../decisions/overlay-generator.mjs';
import { parseApprovalsFile } from '../importer/history-importer.mjs';
import { sha256Hex } from '../util/crypto.mjs';

function normalizeRowCells(raw) {
  const out = {};
  for (const col of OVERLAY_V2_COLUMNS) {
    const val = raw?.[col];
    out[col] = val == null || val === '' ? null : String(val);
  }
  return out;
}

function compareAnswerMaps(expectedMap, actualMap) {
  const expectedKeys = Object.keys(expectedMap || {});
  const actualKeys = Object.keys(actualMap || {});
  const expectedSet = new Set(expectedKeys);
  const actualSet = new Set(actualKeys);

  let missingInDbCount = 0;
  let extraInDbCount = 0;
  let differingKeyCount = 0;
  const differingCols = new Set();

  for (const key of expectedKeys) {
    if (!actualSet.has(key)) {
      missingInDbCount += 1;
      continue;
    }
    const exp = normalizeRowCells(expectedMap[key]);
    const act = normalizeRowCells(actualMap[key]);
    let rowDiff = false;
    for (const col of OVERLAY_V2_COLUMNS) {
      if (exp[col] !== act[col]) {
        rowDiff = true;
        differingCols.add(col);
      }
    }
    if (rowDiff) differingKeyCount += 1;
  }

  for (const key of actualKeys) {
    if (!expectedSet.has(key)) extraInDbCount += 1;
  }

  return {
    ok: missingInDbCount === 0 && extraInDbCount === 0 && differingKeyCount === 0,
    expectedCount: expectedKeys.length,
    actualCount: actualKeys.length,
    missingInDbCount,
    extraInDbCount,
    differingKeyCount,
    differingColumns: [...differingCols].sort(),
  };
}

function dbDecisionRowToOverlayCells(row) {
  return normalizeRowCells({
    record_id: row.record_id,
    disposition: row.disposition,
    agent: row.agent,
    agency: row.agency,
    policy: row.policy,
    book: row.book,
    month: row.month,
    status: row.status,
    note: row.note,
    committed_at: row.committed_at_raw,
    approved_amount: row.approved_amount,
    approved_agency: row.approved_agency,
    approved_agent: row.approved_agent,
    approved_agency_from: row.approved_agency_from,
    approved_agent_from: row.approved_agent_from,
  });
}

/**
 * Runs Layer 2 overlay reconstruction verification across every imported checkpoint recorded in
 * coherence.generated_overlays and standalone overlay checkpoints in coherence.imported_files.
 * Produces a strictly PHI-free report and optionally records it in coherence.checks ('overlay_reconstruction').
 */
export async function verifyOverlayReconstruction({
  pool,
  stores,
  commands = null,
  dbToken = null,
  parseOverlay = parseApprovalsFile,
  pythonPath = null,
  coherenceRepo = null,
  overlayCheckPath = undefined,
  runIds = null,
  tempBaseDir = tmpdir(),
} = {}) {
  const checkpoints = [];

  const goSql = Array.isArray(runIds) && runIds.length > 0
    ? `SELECT go.id, go.decision_commit_id, go.run_id, go.purpose, go.header_contract, go.row_count,
              go.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64,
              r.source_folder, pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date
       FROM coherence.generated_overlays go
       JOIN coherence.stored_files sf ON sf.store_kind = go.store_kind AND sf.sha256 = go.file_sha256
       JOIN coherence.runs r ON r.id = go.run_id
       WHERE go.run_id = ANY($1::uuid[])
       ORDER BY go.journal_seq ASC, go.id::text COLLATE "C"`
    : `SELECT go.id, go.decision_commit_id, go.run_id, go.purpose, go.header_contract, go.row_count,
              go.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64,
              r.source_folder, pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date
       FROM coherence.generated_overlays go
       JOIN coherence.stored_files sf ON sf.store_kind = go.store_kind AND sf.sha256 = go.file_sha256
       JOIN coherence.runs r ON r.id = go.run_id
       ORDER BY go.journal_seq ASC, go.id::text COLLATE "C"`;
  const goRes = await pool.query(goSql, Array.isArray(runIds) && runIds.length > 0 ? [runIds] : []);
  for (const r of goRes.rows) {
    checkpoints.push({
      checkpointId: r.id,
      decisionCommitId: r.decision_commit_id,
      runId: r.run_id,
      sourceFolder: r.source_folder || null,
      statementDate: r.statement_date || null,
      purpose: r.purpose,
      expectedHeaderContract: r.header_contract,
      expectedRowCount: Number(r.row_count),
      origFileSha256: r.file_sha256,
      byteSize: Number(r.byte_size),
      md5B64: r.md5_b64,
      crc32cB64: r.crc32c_b64,
    });
  }

  if (!Array.isArray(runIds) || runIds.length === 0) {
    const standRes = await pool.query(
      `SELECT i.id, i.rel_path, i.file_sha256, i.metadata,
              sf.byte_size, sf.md5_b64, sf.crc32c_b64
       FROM coherence.imported_files i
       JOIN coherence.stored_files sf ON sf.store_kind = i.store_kind AND sf.sha256 = i.file_sha256
       WHERE i.metadata->>'overlayCheckpoint' = 'true'
         AND i.metadata->>'decisionCommitId' IS NOT NULL
       ORDER BY i.journal_seq ASC, i.id::text COLLATE "C"`,
    );
    for (const r of standRes.rows) {
      checkpoints.push({
        checkpointId: r.id,
        decisionCommitId: r.metadata.decisionCommitId,
        runId: null,
        sourceFolder: r.rel_path,
        statementDate: null,
        purpose: r.metadata.standingHead ? 'standing_baseline' : 'standalone_checkpoint',
        expectedHeaderContract: r.metadata.headerContract || 'v2',
        expectedRowCount: Number(r.metadata.rowCount ?? 0),
        origFileSha256: r.file_sha256,
        byteSize: Number(r.byte_size),
        md5B64: r.md5_b64,
        crc32cB64: r.crc32c_b64,
      });
    }
  }

  const parseOpts = {
    pythonPath,
    coherenceRepo,
    ...(overlayCheckPath ? { overlayCheckPath } : {}),
    tempBaseDir,
  };

  const results = [];
  const problems = [];
  let totalRowsChecked = 0;
  let replacementChainViolations = 0;
  let currentParityMismatches = 0;
  let bibleAppliedParityMismatches = 0;

  const workDir = await mkdtemp(join(tempBaseDir, 'coherence-layer2-'));
  try {
    for (let idx = 0; idx < checkpoints.length; idx++) {
      const cp = checkpoints[idx];
      const cpProblems = [];

      const origBytes = await stores.dataStore.readVerified(cp.origFileSha256, {
        byteSize: cp.byteSize,
        md5B64: cp.md5B64,
        crc32cB64: cp.crc32cB64,
      });
      const gen = await generateOverlayCsv(pool, { decisionCommitId: cp.decisionCommitId });

      const origPath = join(workDir, `orig-${idx}.csv`);
      const genPath = join(workDir, `gen-${idx}.csv`);
      await writeFile(origPath, origBytes);
      await writeFile(genPath, gen.bytes);

      // Collect Bible keys from decisions in this commit plus run's bible review_queue_items.
      const bibleKeySet = new Set();
      const policyKeysRes = await pool.query(
        `SELECT DISTINCT record_id
         FROM coherence.decisions_in_commit($1::uuid)
         WHERE record_id LIKE 'policy:%'`,
        [cp.decisionCommitId],
      );
      for (const row of policyKeysRes.rows) bibleKeySet.add(row.record_id);
      if (cp.runId) {
        const qKeysRes = await pool.query(
          `SELECT DISTINCT record_id
           FROM coherence.review_queue_items
           WHERE run_id = $1::uuid AND surface = 'bible'`,
          [cp.runId],
        );
        for (const row of qKeysRes.rows) bibleKeySet.add(row.record_id);
      }
      const bibleKeys = [...bibleKeySet].sort();

      const origParsed = await parseOverlay(origPath, {
        ...parseOpts,
        parentPath: null,
        includeAnswers: true,
        bibleKeys,
      });
      const genParsed = await parseOverlay(genPath, {
        ...parseOpts,
        parentPath: null,
        includeAnswers: true,
        bibleKeys,
      });

      const headerMatch = origParsed.headerKind === genParsed.headerKind
        && genParsed.headerKind === gen.headerContract;
      const rowCountMatch = origParsed.rowCount === genParsed.rowCount
        && genParsed.rowCount === cp.expectedRowCount;

      let firstDiffRow = null;
      let cellDiffCount = 0;
      const differingCols = new Set();
      const minRows = Math.min(origParsed.addedRows.length, genParsed.addedRows.length);
      for (let i = 0; i < minRows; i++) {
        const oRow = normalizeRowCells(origParsed.addedRows[i]);
        const gRow = normalizeRowCells(genParsed.addedRows[i]);
        for (const col of OVERLAY_V2_COLUMNS) {
          if (oRow[col] !== gRow[col]) {
            if (firstDiffRow === null) firstDiffRow = i + 1;
            cellDiffCount += 1;
            differingCols.add(col);
          }
        }
      }
      if (origParsed.addedRows.length !== genParsed.addedRows.length && firstDiffRow === null) {
        firstDiffRow = minRows + 1;
      }
      const rowsEqual = headerMatch && rowCountMatch && cellDiffCount === 0;
      totalRowsChecked += origParsed.rowCount;

      if (!headerMatch) {
        cpProblems.push(`header contract mismatch (orig=${origParsed.headerKind}, gen=${genParsed.headerKind})`);
      }
      if (!rowCountMatch) {
        cpProblems.push(`row count mismatch (orig=${origParsed.rowCount}, gen=${genParsed.rowCount}, expected=${cp.expectedRowCount})`);
      }
      if (cellDiffCount > 0) {
        cpProblems.push(`cell mismatch: ${cellDiffCount} cell(s) differ starting at row ${firstDiffRow} in columns [${[...differingCols].sort().join(', ')}]`);
      }

      // Verify 100% valid replaces_decision_id chain along commit lineage.
      const chainRes = await pool.query(
        `WITH ordered AS (
           SELECT seq_order, id, record_id, replaces_decision_id,
                  pg_catalog.lag(id) OVER (PARTITION BY record_id ORDER BY seq_order ASC) AS expected_prev_id
           FROM coherence.decisions_in_commit($1::uuid)
         )
         SELECT
           pg_catalog.count(*)::int AS total_rows,
           pg_catalog.count(*) FILTER (WHERE replaces_decision_id IS DISTINCT FROM expected_prev_id)::int AS invalid_links
         FROM ordered`,
        [cp.decisionCommitId],
      );
      const invalidLinks = Number(chainRes.rows[0]?.invalid_links ?? 0);
      const chainTotalRows = Number(chainRes.rows[0]?.total_rows ?? 0);
      const replacementChainValid = invalidLinks === 0 && chainTotalRows === origParsed.rowCount;
      if (!replacementChainValid) {
        replacementChainViolations += Math.max(invalidLinks, 1);
        cpProblems.push(`replacement chain violation (invalidLinks=${invalidLinks}, chainRows=${chainTotalRows}, expectedRows=${origParsed.rowCount})`);
      }

      // Verify PostgreSQL decisions_current() matches Python reader's overlay.current().
      const dbCurRes = await pool.query(
        `SELECT record_id, disposition, agent, agency, policy, book, month, status, note,
                committed_at_raw, approved_amount, approved_agency, approved_agent,
                approved_agency_from, approved_agent_from
         FROM coherence.decisions_current($1::uuid)`,
        [cp.decisionCommitId],
      );
      const dbCurMap = {};
      for (const r of dbCurRes.rows) dbCurMap[r.record_id] = dbDecisionRowToOverlayCells(r);
      const curParity = compareAnswerMaps(origParsed.currentByKey || {}, dbCurMap);
      if (!curParity.ok) {
        currentParityMismatches += 1;
        cpProblems.push(
          `decisions_current parity mismatch (missing=${curParity.missingInDbCount}, extra=${curParity.extraInDbCount}, differing=${curParity.differingKeyCount})`,
        );
      }

      // Verify PostgreSQL decisions_bible_applied() matches Python reader's bible.answers().
      const dbBibleRes = await pool.query(
        `SELECT record_id, disposition, agent, agency, policy, book, month, status, note,
                committed_at_raw, approved_amount, approved_agency, approved_agent,
                approved_agency_from, approved_agent_from
         FROM coherence.decisions_bible_applied($1::uuid, $2::text[])`,
        [cp.decisionCommitId, bibleKeys],
      );
      const dbBibleMap = {};
      for (const r of dbBibleRes.rows) dbBibleMap[r.record_id] = dbDecisionRowToOverlayCells(r);
      const bibleParity = compareAnswerMaps(origParsed.bibleAnswersByKey || {}, dbBibleMap);
      if (!bibleParity.ok) {
        bibleAppliedParityMismatches += 1;
        cpProblems.push(
          `decisions_bible_applied parity mismatch (missing=${bibleParity.missingInDbCount}, extra=${bibleParity.extraInDbCount}, differing=${bibleParity.differingKeyCount})`,
        );
      }

      const cpPassed = cpProblems.length === 0;
      if (!cpPassed) {
        problems.push(
          `checkpoint ${cp.purpose} (${cp.sourceFolder || cp.decisionCommitId}): ${cpProblems.join('; ')}`,
        );
      }

      results.push({
        checkpointId: cp.checkpointId,
        decisionCommitId: cp.decisionCommitId,
        runId: cp.runId,
        sourceFolder: cp.sourceFolder,
        statementDate: cp.statementDate,
        purpose: cp.purpose,
        origHeaderContract: origParsed.headerKind,
        genHeaderContract: genParsed.headerKind,
        origRowCount: origParsed.rowCount,
        genRowCount: genParsed.rowCount,
        origSha256: cp.origFileSha256,
        genSha256: gen.fingerprint.sha256,
        rowsEqual,
        firstDiffRow,
        cellDiffCount,
        differingColumns: [...differingCols].sort(),
        replacementChainValid,
        invalidReplacementLinks: invalidLinks,
        currentParity: curParity,
        bibleAppliedParity: bibleParity,
        passed: cpPassed,
      });
    }
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }

  if (results.length === 0) {
    const popRes = await pool.query(
      `SELECT (
         EXISTS (SELECT 1 FROM coherence.runs WHERE origin IN ('mac_import', 'company_import'))
         OR EXISTS (SELECT 1 FROM coherence.decision_commits)
         OR EXISTS (SELECT 1 FROM coherence.decisions)
         OR EXISTS (SELECT 1 FROM coherence.approvals_files)
         OR EXISTS (SELECT 1 FROM coherence.imported_files)
       ) AS populated`,
    );
    if (popRes.rows[0]?.populated) {
      problems.push('Layer 2 overlay reconstruction checked zero checkpoints on a populated import.');
    }
  }

  const passed = problems.length === 0;
  const report = {
    layer: 2,
    checkKind: 'overlay_reconstruction',
    passed,
    executedAtUtc: new Date().toISOString(),
    checkpointsChecked: results.length,
    checkpointsPassed: results.filter((r) => r.passed).length,
    totalRowsChecked,
    replacementChainViolations,
    currentParityMismatches,
    bibleAppliedParityMismatches,
    checkpoints: results,
    problems,
  };

  if (commands && dbToken) {
    const digest = sha256Hex(JSON.stringify({
      passed: report.passed,
      checkpoints: results.map((r) => [r.decisionCommitId, r.origSha256, r.genSha256, r.passed]),
    }));
    await commands.recordCheck({
      dbToken,
      commandKey: `check-overlay-reconstruction:${digest}`,
      checkKind: 'overlay_reconstruction',
      runId: Array.isArray(runIds) && runIds.length === 1 ? runIds[0] : null,
      passed,
      report,
    });
  }

  return report;
}
