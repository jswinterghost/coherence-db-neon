// Server-side web handlers for all Coherence screens (R16, R4, R14.2, R14.3, R11).
// No front-end HTML or code-bearing files are ever served to clients; bundles serve JSON config + signed-in CSV data.
import { basename } from 'node:path';
import { gzipSync } from 'node:zlib';
import { assertCanRead, assertCanWrite } from '../commands/authz.mjs';
import { verifyChain, verifyCommitments, verifyObjects } from '../commands/journal-export.mjs';
import { createDatabaseCoherenceReader } from '../readers/downstream-reader.mjs';
import { isCodeBearingPath } from '../storage/artifact-policy.mjs';
import { formatTimestampUtcUs } from '../util/crypto.mjs';
import { assertValidRelPath } from '../util/csv.mjs';
import { AppError, redactPhi } from '../util/redact.mjs';
import { checkReviewAppDrift } from './drift-check.mjs';

const ADJUST_STAMP_START = '<script>window.__ADJUST_CONFIG__=';
const ADJUST_STAMP_END = ';</script></head>';

function extractReviewConfigJson(html, surface, expectedDate) {
  const head = html.indexOf('</head>');
  const start = html.lastIndexOf(ADJUST_STAMP_START, head);
  const end = start >= 0 ? html.indexOf(ADJUST_STAMP_END, start) : -1;
  if (start < 0 || end < 0) {
    throw new AppError('The review page does not carry a valid Coherence stamp.', 502, 'INVALID_REVIEW_STAMP');
  }
  const jsonText = html.slice(start + ADJUST_STAMP_START.length, end);
  const config = JSON.parse(jsonText);
  if (!config.stamped || config.surface !== surface || config.statementDate !== expectedDate) {
    throw new AppError('The review stamp does not belong to this run and surface.', 502, 'REVIEW_STAMP_MISMATCH');
  }
  return config;
}

export function createWebHandlers({
  pool,
  companySlug,
  stores,
  commands,
  entity = '',
  display = '',
  driftCheckConfig = null,
}) {
  const reader = createDatabaseCoherenceReader({ pool, stores, entity: entity || display || companySlug, display });

  async function resolveAsOfSeq({ asOfSeq = null, asOf = null } = {}) {
    if (asOfSeq != null && asOfSeq !== '') {
      const n = Number(asOfSeq);
      if (!Number.isInteger(n) || n < 0) throw new AppError('asOfSeq must be a non-negative integer.', 400, 'INVALID_AS_OF');
      return n;
    }
    if (asOf) {
      const parsed = new Date(asOf);
      if (Number.isNaN(parsed.getTime())) throw new AppError('asOf must be a valid ISO-8601 timestamp.', 400, 'INVALID_AS_OF');
      const res = await pool.query(
        'SELECT COALESCE(pg_catalog.max(seq), 0) AS seq FROM coherence.journal_entries WHERE recorded_at <= $1::timestamptz',
        [parsed.toISOString()],
      );
      return Number(res.rows[0].seq);
    }
    return null;
  }

  // ---- R16.1 Inputs ----

  async function listInputVersions(actor, { asOfSeq = null, asOf = null } = {}) {
    assertCanRead(actor, 'inputs', { companySlug });
    const limitSeq = await resolveAsOfSeq({ asOfSeq, asOf });
    const seqCap = limitSeq != null ? String(limitSeq) : '9223372036854775807';
    const res = await pool.query(
      `SELECT iv.id, iv.line_kind, iv.parent_id, iv.source_kind, iv.reason,
              iv.entry_count, iv.entries_sha256, iv.change_count, iv.changes_sha256,
              iv.journal_seq, je.recorded_at, je.actor, je.acting_for
       FROM coherence.input_versions iv
       JOIN coherence.journal_entries je ON je.seq = iv.journal_seq
       WHERE iv.line_kind = 'standing' AND iv.journal_seq <= $1::bigint
       ORDER BY iv.journal_seq DESC`,
      [seqCap],
    );
    const versions = [];
    for (const row of res.rows) {
      const chRes = await pool.query(
        `SELECT rel_path, change_kind, old_rel_path, file_sha256, prev_file_sha256
         FROM coherence.input_changes WHERE input_version_id = $1::uuid
         ORDER BY rel_path COLLATE "C"`,
        [row.id],
      );
      versions.push({
        id: row.id,
        parentId: row.parent_id,
        sourceKind: row.source_kind,
        reason: row.reason,
        entryCount: Number(row.entry_count),
        entriesSha256: row.entries_sha256,
        changeCount: Number(row.change_count),
        changesSha256: row.changes_sha256,
        journalSeq: Number(row.journal_seq),
        recordedAt: formatTimestampUtcUs(row.recorded_at),
        actor: row.actor,
        actingFor: row.acting_for ?? null,
        changes: chRes.rows.map((c) => ({
          relPath: c.rel_path,
          changeKind: c.change_kind,
          oldRelPath: c.old_rel_path,
          fileSha256: c.file_sha256,
          prevFileSha256: c.prev_file_sha256,
        })),
      });
    }
    const maxSeqRes = await pool.query('SELECT COALESCE(pg_catalog.max(seq), 0) AS max_seq FROM coherence.journal_entries');
    return { companySlug, asOfSeq: limitSeq, currentJournalSeq: Number(maxSeqRes.rows[0].max_seq), versions };
  }

  async function getInputVersionDetail(actor, versionId) {
    assertCanRead(actor, 'inputs', { companySlug });
    const ivRes = await pool.query(
      `SELECT iv.*, je.recorded_at, je.actor, je.acting_for
       FROM coherence.input_versions iv
       JOIN coherence.journal_entries je ON je.seq = iv.journal_seq
       WHERE iv.id = $1::uuid`,
      [versionId],
    );
    if (ivRes.rows.length === 0) throw new AppError('Input version not found.', 404, 'NOT_FOUND');
    const iv = ivRes.rows[0];
    const [entriesRes, changesRes] = await Promise.all([
      pool.query(
        `SELECT ie.rel_path, ie.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
         FROM coherence.input_entries ie
         JOIN coherence.stored_files sf ON sf.store_kind = ie.store_kind AND sf.sha256 = ie.file_sha256
         WHERE ie.input_version_id = $1::uuid ORDER BY ie.rel_path COLLATE "C"`,
        [versionId],
      ),
      pool.query(
        `SELECT rel_path, change_kind, old_rel_path, file_sha256, prev_file_sha256
         FROM coherence.input_changes WHERE input_version_id = $1::uuid ORDER BY rel_path COLLATE "C"`,
        [versionId],
      ),
    ]);
    return {
      id: iv.id,
      lineKind: iv.line_kind,
      parentId: iv.parent_id,
      sourceKind: iv.source_kind,
      reason: iv.reason,
      entryCount: Number(iv.entry_count),
      entriesSha256: iv.entries_sha256,
      changeCount: Number(iv.change_count),
      changesSha256: iv.changes_sha256,
      journalSeq: Number(iv.journal_seq),
      recordedAt: formatTimestampUtcUs(iv.recorded_at),
      actor: iv.actor,
      actingFor: iv.acting_for ?? null,
      entries: entriesRes.rows.map((e) => ({
        relPath: e.rel_path,
        fileSha256: e.file_sha256,
        byteSize: Number(e.byte_size),
        md5B64: e.md5_b64,
        crc32cB64: e.crc32c_b64,
      })),
      changes: changesRes.rows.map((c) => ({
        relPath: c.rel_path,
        changeKind: c.change_kind,
        oldRelPath: c.old_rel_path,
        fileSha256: c.file_sha256,
        prevFileSha256: c.prev_file_sha256,
      })),
    };
  }

  async function listStagingFiles(actor) {
    assertCanRead(actor, 'inputs', { companySlug });
    const stagedRes = await pool.query(
      `SELECT f.id, f.rel_path, f.file_sha256, f.original_at, f.metadata, sf.byte_size, sf.md5_b64, f.journal_seq
       FROM coherence.imported_files f
       JOIN coherence.stored_files sf ON sf.store_kind = f.store_kind AND sf.sha256 = f.file_sha256
       WHERE f.area = 'staging'
       ORDER BY f.rel_path COLLATE "C"`,
    );
    const currentStanding = await pool.query('SELECT coherence.standing_input_version_as_of(NULL) AS id');
    const standingId = currentStanding.rows[0]?.id;
    const includedMap = new Map();
    if (standingId) {
      const entriesRes = await pool.query(
        'SELECT rel_path, file_sha256 FROM coherence.input_entries WHERE input_version_id = $1::uuid',
        [standingId],
      );
      for (const e of entriesRes.rows) {
        const list = includedMap.get(e.file_sha256) || [];
        list.push(e.rel_path);
        includedMap.set(e.file_sha256, list);
      }
    }
    return {
      companySlug,
      currentStandingInputVersionId: standingId,
      files: stagedRes.rows.map((r) => ({
        id: r.id,
        relPath: r.rel_path,
        fileSha256: r.file_sha256,
        byteSize: Number(r.byte_size),
        md5B64: r.md5_b64,
        originalAt: r.original_at ? formatTimestampUtcUs(r.original_at) : null,
        includedAt: includedMap.get(r.file_sha256) || [],
      })),
    };
  }

  async function includeStagingFile(actor, { commandKey, expectedJournalSeq, stagingFileSha256, targetRelPath, reason }) {
    assertCanWrite(actor, 'include_staging_file', { companySlug });
    assertValidRelPath(targetRelPath, 'targetRelPath');
    if (!reason || !String(reason).trim()) throw new AppError('A reason is required to include a file in calculations (R16.1).', 400, 'MISSING_REASON');

    const stagedRes = await pool.query(
      `SELECT f.file_sha256 FROM coherence.imported_files f
       WHERE f.area = 'staging' AND f.file_sha256 = $1 LIMIT 1`,
      [stagingFileSha256],
    );
    if (stagedRes.rows.length === 0) throw new AppError('Staged file not found.', 404, 'STAGED_FILE_NOT_FOUND');

    const currentStanding = await pool.query('SELECT coherence.standing_input_version_as_of(NULL) AS id');
    const standingId = currentStanding.rows[0]?.id;
    const prevEntries = standingId
      ? (await pool.query('SELECT rel_path, file_sha256 FROM coherence.input_entries WHERE input_version_id = $1::uuid', [standingId])).rows
      : [];

    const existingSameBytes = prevEntries.find((e) => e.file_sha256 === stagingFileSha256 && e.rel_path !== targetRelPath);
    if (existingSameBytes) {
      throw new AppError('This file is already included in calculations under another path; including it twice would double-count it.', 409, 'DUPLICATE_INPUT_BYTES');
    }
    const existingSamePath = prevEntries.find((e) => e.rel_path === targetRelPath);
    if (existingSamePath) {
      if (existingSamePath.file_sha256 === stagingFileSha256) {
        return { unchanged: true, inputVersionId: standingId, targetRelPath };
      }
      throw new AppError('Another file already exists at that target path.', 409, 'PATH_ALREADY_EXISTS');
    }

    const nextEntries = [
      ...prevEntries.map((e) => ({ relPath: e.rel_path, fileSha256: e.file_sha256 })),
      { relPath: targetRelPath, fileSha256: stagingFileSha256 },
    ];
    return commands.publishInputVersion({
      actor,
      commandKey,
      expectedJournalSeq,
      lineKind: 'standing',
      sourceKind: 'include',
      reason: String(reason).trim(),
      entries: nextEntries,
      detectRenames: false,
    });
  }

  // ---- R16.2 Runs ----

  async function listRuns(actor, { asOfSeq = null, asOf = null } = {}) {
    assertCanRead(actor, 'runs', { companySlug });
    const limitSeq = await resolveAsOfSeq({ asOfSeq, asOf });
    const seqCap = limitSeq != null ? String(limitSeq) : '9223372036854775807';
    const res = await pool.query(
      `SELECT r.id, pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date,
              r.folder_number, r.origin, r.input_version_id, r.engine_version_id,
              r.emit_mode, r.emit_display, r.replays_run_id, r.compared_run_id, r.rerun_reason, r.source_folder,
              r.journal_seq AS created_journal_seq,
              coherence.run_latest_journal_seq(r.id) AS latest_journal_seq,
              coherence.run_stage(r.id, $2::bigint) AS stage,
              iv.entries_sha256 AS input_entries_sha256,
              iv.entry_count AS input_entry_count,
              ev.label AS engine_label,
              ev.coherence_commit AS engine_commit,
              je.recorded_at AS launched_at,
              je.actor AS launched_by,
              je.acting_for AS launched_acting_for
       FROM coherence.runs r
       JOIN coherence.input_versions iv ON iv.id = r.input_version_id
       LEFT JOIN coherence.engine_versions ev ON ev.id = r.engine_version_id
       JOIN coherence.journal_entries je ON je.seq = r.journal_seq
       WHERE r.journal_seq <= $1::bigint
       ORDER BY r.statement_date DESC, r.folder_number DESC, r.journal_seq DESC`,
      [seqCap, limitSeq != null ? String(limitSeq) : null],
    );
    const maxSeqRes = await pool.query('SELECT COALESCE(pg_catalog.max(seq), 0) AS max_seq FROM coherence.journal_entries');
    return {
      companySlug,
      asOfSeq: limitSeq,
      currentJournalSeq: Number(maxSeqRes.rows[0].max_seq),
      runs: res.rows.map((r) => ({
        id: r.id,
        statementDate: r.statement_date,
        folderNumber: Number(r.folder_number),
        origin: r.origin,
        stage: r.stage,
        inputVersion: { id: r.input_version_id, entriesSha256: r.input_entries_sha256, entryCount: Number(r.input_entry_count) },
        engineVersion: r.engine_version_id ? { id: r.engine_version_id, label: r.engine_label, commit: r.engine_commit } : null,
        emitMode: r.emit_mode,
        emitDisplay: r.emit_display,
        replaysRunId: r.replays_run_id,
        comparedRunId: r.compared_run_id,
        rerunReason: r.rerun_reason,
        sourceFolder: r.source_folder,
        createdJournalSeq: Number(r.created_journal_seq),
        latestJournalSeq: Number(r.latest_journal_seq),
        launchedAt: formatTimestampUtcUs(r.launched_at),
        launchedBy: r.launched_by,
        launchedActingFor: r.launched_acting_for ?? null,
      })),
    };
  }

  async function getRunDetail(actor, runId, { asOfSeq = null, asOf = null } = {}) {
    assertCanRead(actor, 'runs', { companySlug });
    const limitSeq = await resolveAsOfSeq({ asOfSeq, asOf });
    const seqCap = limitSeq != null ? String(limitSeq) : '9223372036854775807';
    const runRes = await pool.query(
      `SELECT r.id, pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date,
              r.folder_number, r.origin, r.input_version_id, r.prior_approvals_sha256, r.engine_version_id,
              r.emit_mode, r.emit_display, r.emit_keep, r.emit_no_manager,
              r.replays_run_id, r.compared_run_id, r.rerun_reason, r.source_folder, r.journal_seq,
              coherence.run_stage(r.id, $3::bigint) AS stage,
              coherence.run_latest_journal_seq(r.id) AS latest_journal_seq,
              iv.entries_sha256, iv.entry_count,
              ev.label AS engine_label, ev.coherence_commit, ev.nusear_commit,
              ev.code_manifest_sha256, ev.wrapper_bundle_sha256
       FROM coherence.runs r
       JOIN coherence.input_versions iv ON iv.id = r.input_version_id
       LEFT JOIN coherence.engine_versions ev ON ev.id = r.engine_version_id
       WHERE r.id = $1::uuid AND r.journal_seq <= $2::bigint`,
      [runId, seqCap, limitSeq != null ? String(limitSeq) : null],
    );
    if (runRes.rows.length === 0) throw new AppError('Run not found.', 404, 'RUN_NOT_FOUND');
    const r = runRes.rows[0];

    const [attemptsRes, savesRes, subsRes, confirmsRes, carriesRes, abandonRes] = await Promise.all([
      pool.query(
        `SELECT e.id, e.step, e.attempt_no, e.event_kind, e.census, e.born, e.log_file_sha256,
                e.error_summary, e.artifact_count, e.artifacts_sha256, e.journal_seq, je.recorded_at
         FROM coherence.step_attempt_events e
         JOIN coherence.journal_entries je ON je.seq = e.journal_seq
         WHERE e.run_id = $1::uuid AND e.journal_seq <= $2::bigint
         ORDER BY e.journal_seq ASC, e.attempt_no ASC`,
        [runId, seqCap],
      ),
      pool.query(
        `SELECT rs.id, rs.surface, rs.attempt_event_id, rs.approvals_file_sha256, rs.imported, rs.original_at,
                rs.journal_seq, je.recorded_at, je.actor, je.acting_for, af.row_count, af.header_kind
         FROM coherence.review_saves rs
         JOIN coherence.journal_entries je ON je.seq = rs.journal_seq
         JOIN coherence.approvals_files af ON af.file_sha256 = rs.approvals_file_sha256
         WHERE rs.run_id = $1::uuid AND rs.journal_seq <= $2::bigint
         ORDER BY rs.journal_seq ASC`,
        [runId, seqCap],
      ),
      pool.query(
        `SELECT id, surface, status, staged_sha256, review_save_id, result_journal_seq, result_message, created_at, resolved_at
         FROM coherence.review_submissions WHERE run_id = $1::uuid ORDER BY created_at DESC LIMIT 10`,
        [runId],
      ),
      pool.query(
        `SELECT ec.id, ec.adjust_review_save_id, ec.typed_phrase, ec.journal_seq, je.recorded_at, je.actor
         FROM coherence.emit_confirmations ec
         JOIN coherence.journal_entries je ON je.seq = ec.journal_seq
         WHERE ec.run_id = $1::uuid AND ec.journal_seq <= $2::bigint
         ORDER BY ec.journal_seq ASC`,
        [runId, seqCap],
      ),
      pool.query(
        `SELECT c.id, c.carry_kind, c.file_sha256, c.published_input_version_id, c.nothing_new, c.journal_seq, je.recorded_at, je.actor
         FROM coherence.carries c
         JOIN coherence.journal_entries je ON je.seq = c.journal_seq
         WHERE c.run_id = $1::uuid AND c.journal_seq <= $2::bigint
         ORDER BY c.journal_seq ASC`,
        [runId, seqCap],
      ),
      pool.query(
        `SELECT a.id, a.reason, a.journal_seq, je.recorded_at, je.actor
         FROM coherence.abandonments a
         JOIN coherence.journal_entries je ON je.seq = a.journal_seq
         WHERE a.run_id = $1::uuid AND a.journal_seq <= $2::bigint`,
        [runId, seqCap],
      ),
    ]);

    return {
      id: r.id,
      statementDate: r.statement_date,
      folderNumber: Number(r.folder_number),
      origin: r.origin,
      stage: r.stage,
      createdJournalSeq: Number(r.journal_seq),
      latestJournalSeq: Number(r.latest_journal_seq),
      inputVersion: { id: r.input_version_id, entriesSha256: r.entries_sha256, entryCount: Number(r.entry_count) },
      priorApprovalsSha256: r.prior_approvals_sha256,
      engineVersion: r.engine_version_id ? {
        id: r.engine_version_id,
        label: r.engine_label,
        coherenceCommit: r.coherence_commit,
        nusearCommit: r.nusear_commit,
        codeManifestSha256: r.code_manifest_sha256,
        wrapperBundleSha256: r.wrapper_bundle_sha256,
      } : null,
      emitSettings: { mode: r.emit_mode, display: r.emit_display, keep: r.emit_keep, noManager: r.emit_no_manager },
      replaysRunId: r.replays_run_id,
      comparedRunId: r.compared_run_id,
      rerunReason: r.rerun_reason,
      sourceFolder: r.source_folder,
      attempts: attemptsRes.rows.map((a) => ({
        id: a.id,
        step: a.step,
        attemptNo: Number(a.attempt_no),
        eventKind: a.event_kind,
        census: a.census,
        born: a.born,
        hasLog: Boolean(a.log_file_sha256),
        errorSummary: a.error_summary ? redactPhi(a.error_summary) : null,
        artifactCount: a.artifact_count != null ? Number(a.artifact_count) : null,
        artifactsSha256: a.artifacts_sha256,
        journalSeq: Number(a.journal_seq),
        recordedAt: formatTimestampUtcUs(a.recorded_at),
      })),
      reviewSaves: savesRes.rows.map((s) => ({
        id: s.id,
        surface: s.surface,
        attemptEventId: s.attempt_event_id,
        approvalsFileSha256: s.approvals_file_sha256,
        headerKind: s.header_kind,
        rowCount: Number(s.row_count),
        imported: s.imported,
        originalAt: s.original_at ? formatTimestampUtcUs(s.original_at) : null,
        journalSeq: Number(s.journal_seq),
        recordedAt: formatTimestampUtcUs(s.recorded_at),
        actor: s.actor,
        actingFor: s.acting_for ?? null,
      })),
      reviewSubmissions: subsRes.rows.map((s) => ({
        id: s.id,
        surface: s.surface,
        status: s.status,
        stagedSha256: s.staged_sha256,
        reviewSaveId: s.review_save_id,
        resultJournalSeq: s.result_journal_seq ? Number(s.result_journal_seq) : null,
        resultMessage: s.result_message ? redactPhi(s.result_message) : null,
        createdAt: formatTimestampUtcUs(s.created_at),
        resolvedAt: s.resolved_at ? formatTimestampUtcUs(s.resolved_at) : null,
      })),
      emitConfirmations: confirmsRes.rows.map((c) => ({
        id: c.id,
        adjustReviewSaveId: c.adjust_review_save_id,
        journalSeq: Number(c.journal_seq),
        recordedAt: formatTimestampUtcUs(c.recorded_at),
        actor: c.actor,
      })),
      carries: carriesRes.rows.map((c) => ({
        id: c.id,
        carryKind: c.carry_kind,
        fileSha256: c.file_sha256,
        publishedInputVersionId: c.published_input_version_id,
        nothingNew: c.nothing_new,
        journalSeq: Number(c.journal_seq),
        recordedAt: formatTimestampUtcUs(c.recorded_at),
        actor: c.actor,
      })),
      abandonment: abandonRes.rows[0] ? {
        id: abandonRes.rows[0].id,
        reason: abandonRes.rows[0].reason,
        journalSeq: Number(abandonRes.rows[0].journal_seq),
        recordedAt: formatTimestampUtcUs(abandonRes.rows[0].recorded_at),
        actor: abandonRes.rows[0].actor,
      } : null,
    };
  }

  async function getAttemptLog(actor, runId, step, attemptNo) {
    assertCanRead(actor, 'runs', { companySlug });
    const res = await pool.query(
      `SELECT e.log_file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
       FROM coherence.step_attempt_events e
       JOIN coherence.stored_files sf ON sf.store_kind = 'company_data' AND sf.sha256 = e.log_file_sha256
       WHERE e.run_id = $1::uuid AND e.step = $2 AND e.attempt_no = $3 AND e.log_file_sha256 IS NOT NULL
       ORDER BY e.journal_seq DESC LIMIT 1`,
      [runId, step, Number(attemptNo)],
    );
    if (res.rows.length === 0) throw new AppError('Step log not found.', 404, 'LOG_NOT_FOUND');
    const row = res.rows[0];
    const bytes = await stores.dataStore.readVerified(row.log_file_sha256, {
      byteSize: Number(row.byte_size), md5B64: row.md5_b64, crc32cB64: row.crc32c_b64,
    });
    return { text: redactPhi(bytes.toString('utf8')) };
  }

  /**
   * Extracts ONLY the JSON review configuration from bible.html / adjust.html in Nusear's code store (R14.2, R16.2).
   * Never returns compiled HTML/JS code to clients.
   */
  async function getReviewConfig(actor, runId, surface) {
    assertCanRead(actor, 'approvals', { companySlug });
    if (!['bible', 'adjust'].includes(surface)) throw new AppError('Choose bible or adjust.', 400, 'INVALID_SURFACE');
    const runRes = await pool.query(
      `SELECT pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date,
              coherence.current_finished_attempt(id, $2) AS ev_id
       FROM coherence.runs WHERE id = $1::uuid`,
      [runId, surface],
    );
    if (runRes.rows.length === 0) throw new AppError('Run not found.', 404, 'RUN_NOT_FOUND');
    const { statement_date: statementDate, ev_id: evId } = runRes.rows[0];
    if (!evId) throw new AppError(`The ${surface} step has not finished for this run.`, 404, 'STEP_NOT_FINISHED');

    const attRes = await pool.query('SELECT attempt_no FROM coherence.step_attempt_events WHERE id = $1::uuid', [evId]);
    const attemptNo = Number(attRes.rows[0].attempt_no);

    const artRes = await pool.query(
      `SELECT a.store_kind, a.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
       FROM coherence.artifacts a
       JOIN coherence.stored_files sf ON sf.store_kind = a.store_kind AND sf.sha256 = a.file_sha256
       WHERE a.attempt_event_id = $1::uuid AND a.rel_path = $2`,
      [evId, `${surface}.html`],
    );
    if (artRes.rows.length === 0) throw new AppError(`No ${surface} review config is available.`, 404, 'REVIEW_CONFIG_MISSING');
    const art = artRes.rows[0];
    const htmlBytes = await stores.readVerified(art.store_kind, art.file_sha256, {
      byteSize: Number(art.byte_size), md5B64: art.md5_b64, crc32cB64: art.crc32c_b64,
    });
    const config = extractReviewConfigJson(htmlBytes.toString('utf8'), surface, statementDate);
    return { runId, surface, attemptNo, config };
  }

  async function getReviewSubmission(actor, submissionId) {
    assertCanRead(actor, 'approvals', { companySlug });
    const res = await pool.query(
      `SELECT id, run_id, surface, status, staged_sha256, review_save_id, result_journal_seq, result_message, created_at, resolved_at
       FROM coherence.review_submissions WHERE id = $1::uuid`,
      [submissionId],
    );
    if (res.rows.length === 0) throw new AppError('Review submission not found.', 404, 'NOT_FOUND');
    const row = res.rows[0];
    return {
      id: row.id,
      runId: row.run_id,
      surface: row.surface,
      status: row.status,
      stagedSha256: row.staged_sha256,
      reviewSaveId: row.review_save_id,
      resultJournalSeq: row.result_journal_seq ? Number(row.result_journal_seq) : null,
      resultMessage: row.result_message ? redactPhi(row.result_message) : null,
      createdAt: formatTimestampUtcUs(row.created_at),
      resolvedAt: row.resolved_at ? formatTimestampUtcUs(row.resolved_at) : null,
    };
  }

  async function listRunOutputs(actor, runId) {
    assertCanRead(actor, 'runs', { companySlug });
    const evRes = await pool.query("SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev_id", [runId]);
    const evId = evRes.rows[0]?.ev_id;
    if (!evId) return { available: false, files: [] };
    const artRes = await pool.query(
      `SELECT a.rel_path, a.artifact_kind, a.store_kind, a.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
       FROM coherence.artifacts a
       JOIN coherence.stored_files sf ON sf.store_kind = a.store_kind AND sf.sha256 = a.file_sha256
       WHERE a.attempt_event_id = $1::uuid AND a.artifact_kind = 'data' AND a.store_kind = 'company_data'
       ORDER BY a.rel_path COLLATE "C"`,
      [evId],
    );
    return {
      available: true,
      runId,
      files: artRes.rows.map((r) => ({
        relPath: r.rel_path,
        fileSha256: r.file_sha256,
        byteSize: Number(r.byte_size),
        md5B64: r.md5_b64,
        crc32cB64: r.crc32c_b64,
      })),
    };
  }

  async function getRunOutputFile(actor, runId, relPath, acceptsGzip = false) {
    assertCanRead(actor, 'runs', { companySlug });
    assertValidRelPath(relPath, 'output path');
    if (isCodeBearingPath(relPath)) {
      throw new AppError('Code-bearing files cannot be downloaded from output endpoints (R1.6, R14.2).', 403, 'CODE_FILE_FORBIDDEN');
    }
    const evRes = await pool.query("SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev_id", [runId]);
    const evId = evRes.rows[0]?.ev_id;
    if (!evId) throw new AppError('Run has not finished Emit.', 404, 'EMIT_NOT_FINISHED');
    const artRes = await pool.query(
      `SELECT a.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
       FROM coherence.artifacts a
       JOIN coherence.stored_files sf ON sf.store_kind = 'company_data' AND sf.sha256 = a.file_sha256
       WHERE a.attempt_event_id = $1::uuid AND a.rel_path = $2 AND a.artifact_kind = 'data'`,
      [evId, relPath],
    );
    if (artRes.rows.length === 0) throw new AppError('Output data file not found.', 404, 'FILE_NOT_FOUND');
    const art = artRes.rows[0];
    const bytes = await stores.dataStore.readVerified(art.file_sha256, {
      byteSize: Number(art.byte_size), md5B64: art.md5_b64, crc32cB64: art.crc32c_b64,
    });
    return { name: basename(relPath), body: acceptsGzip ? gzipSync(bytes) : bytes, gzip: Boolean(acceptsGzip) };
  }

  // ---- R16.3 History ("as of", run journal, approval key history) ----

  async function getHistoryAsOf(actor, { asOfSeq = null, asOf = null } = {}) {
    assertCanRead(actor, 'journal', { companySlug });
    const seq = await resolveAsOfSeq({ asOfSeq, asOf });
    if (seq === null) throw new AppError('Provide asOfSeq or asOf timestamp.', 400, 'MISSING_AS_OF');
    const [jeRes, ivRes, runsRes] = await Promise.all([
      pool.query(
        'SELECT seq, recorded_at, actor, acting_for, command_kind, entry_hash FROM coherence.journal_entries WHERE seq = $1',
        [String(seq)],
      ),
      pool.query('SELECT coherence.standing_input_version_as_of($1::bigint) AS id', [String(seq)]),
      listRuns(actor, { asOfSeq: seq }),
    ]);
    return {
      companySlug,
      asOfSeq: seq,
      journalEntry: jeRes.rows[0] ? {
        seq: Number(jeRes.rows[0].seq),
        recordedAt: formatTimestampUtcUs(jeRes.rows[0].recorded_at),
        actor: jeRes.rows[0].actor,
        actingFor: jeRes.rows[0].acting_for ?? null,
        commandKind: jeRes.rows[0].command_kind,
        entryHash: jeRes.rows[0].entry_hash,
      } : null,
      standingInputVersionId: ivRes.rows[0]?.id ?? null,
      runs: runsRes.runs,
    };
  }

  async function getRunJournal(actor, runId) {
    assertCanRead(actor, 'journal', { companySlug });
    const res = await pool.query(
      `SELECT DISTINCT je.seq, je.recorded_at, je.actor, je.acting_for, je.command_kind,
              je.command_key, je.prev_hash, je.entry_hash, je.body
       FROM coherence.journal_entries je
       WHERE je.seq IN (
         SELECT journal_seq FROM coherence.runs WHERE id = $1::uuid
         UNION SELECT journal_seq FROM coherence.step_requests WHERE run_id = $1::uuid
         UNION SELECT journal_seq FROM coherence.cancel_requests WHERE run_id = $1::uuid
         UNION SELECT journal_seq FROM coherence.step_attempt_events WHERE run_id = $1::uuid
         UNION SELECT journal_seq FROM coherence.review_saves WHERE run_id = $1::uuid
         UNION SELECT journal_seq FROM coherence.emit_confirmations WHERE run_id = $1::uuid
         UNION SELECT journal_seq FROM coherence.carries WHERE run_id = $1::uuid
         UNION SELECT journal_seq FROM coherence.abandonments WHERE run_id = $1::uuid
       )
       ORDER BY je.seq ASC`,
      [runId],
    );
    return {
      runId,
      entries: res.rows.map((r) => ({
        seq: Number(r.seq),
        recordedAt: formatTimestampUtcUs(r.recorded_at),
        actor: r.actor,
        actingFor: r.acting_for ?? null,
        commandKind: r.command_kind,
        commandKey: r.command_key,
        prevHash: r.prev_hash,
        entryHash: r.entry_hash,
        body: r.body,
      })),
    };
  }

  async function getApprovalKeyHistory(actor, recordId) {
    assertCanRead(actor, 'approvals', { companySlug });
    if (typeof recordId !== 'string' || !recordId.length) {
      throw new AppError('recordId is required.', 400, 'MISSING_RECORD_ID');
    }
    const res = await pool.query(
      `SELECT ar.approvals_file_sha256, ar.row_no, ar.record_id, ar.disposition, ar.agent, ar.agency,
              ar.policy, ar.book, ar.month, ar.status, ar.note, ar.committed_at,
              ar.approved_amount, ar.approved_agency, ar.approved_agent,
              ar.approved_agency_from, ar.approved_agent_from,
              ar.journal_seq, je.recorded_at, je.actor, je.acting_for,
              rs.run_id, rs.surface
       FROM coherence.approval_rows ar
       JOIN coherence.journal_entries je ON je.seq = ar.journal_seq
       LEFT JOIN coherence.review_saves rs ON rs.approvals_file_sha256 = ar.approvals_file_sha256
       WHERE ar.record_id = $1
       ORDER BY ar.journal_seq ASC, ar.row_no ASC`,
      [recordId],
    );
    return {
      recordId,
      history: res.rows.map((r) => ({
        approvalsFileSha256: r.approvals_file_sha256,
        rowNo: Number(r.row_no),
        disposition: r.disposition,
        agent: r.agent,
        agency: r.agency,
        policy: r.policy,
        book: r.book,
        month: r.month,
        status: r.status,
        note: r.note,
        committedAt: r.committed_at,
        approvedAmount: r.approved_amount,
        approvedAgency: r.approved_agency,
        approvedAgent: r.approved_agent,
        approvedAgencyFrom: r.approved_agency_from,
        approvedAgentFrom: r.approved_agent_from,
        runId: r.run_id,
        surface: r.surface,
        journalSeq: Number(r.journal_seq),
        recordedAt: formatTimestampUtcUs(r.recorded_at),
        actor: r.actor,
        actingFor: r.acting_for ?? null,
      })),
    };
  }

  // ---- R16.4 Checks ----

  async function listChecks(actor, { kind = null, runId = null } = {}) {
    assertCanRead(actor, 'checks', { companySlug });
    const conditions = [];
    const params = [];
    if (kind) { params.push(kind); conditions.push(`c.check_kind = $${params.length}`); }
    if (runId) { params.push(runId); conditions.push(`c.run_id = $${params.length}::uuid`); }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const res = await pool.query(
      `SELECT c.id, c.check_kind, c.run_id, c.compared_run_id, c.passed, c.report, c.journal_seq,
              je.recorded_at, je.actor
       FROM coherence.checks c
       JOIN coherence.journal_entries je ON je.seq = c.journal_seq
       ${where}
       ORDER BY c.journal_seq DESC LIMIT 200`,
      params,
    );
    return {
      companySlug,
      checks: res.rows.map((r) => ({
        id: r.id,
        checkKind: r.check_kind,
        runId: r.run_id,
        comparedRunId: r.compared_run_id,
        passed: r.passed,
        report: r.report,
        journalSeq: Number(r.journal_seq),
        recordedAt: formatTimestampUtcUs(r.recorded_at),
        actor: r.actor,
      })),
    };
  }

  async function getCheckDetail(actor, checkId) {
    assertCanRead(actor, 'checks', { companySlug });
    const res = await pool.query(
      `SELECT c.*, je.recorded_at, je.actor
       FROM coherence.checks c
       JOIN coherence.journal_entries je ON je.seq = c.journal_seq
       WHERE c.id = $1::uuid`,
      [checkId],
    );
    if (res.rows.length === 0) throw new AppError('Check report not found.', 404, 'NOT_FOUND');
    const r = res.rows[0];
    return {
      id: r.id,
      checkKind: r.check_kind,
      runId: r.run_id,
      comparedRunId: r.compared_run_id,
      passed: r.passed,
      report: r.report,
      journalSeq: Number(r.journal_seq),
      recordedAt: formatTimestampUtcUs(r.recorded_at),
      actor: r.actor,
    };
  }

  async function runVerificationCheck(actor, { commandKey, checkKind, deep = false }) {
    assertCanWrite(actor, 'record_check', { companySlug });
    let report;
    if (checkKind === 'chain') report = await verifyChain(pool);
    else if (checkKind === 'commitments') report = await verifyCommitments(pool);
    else if (checkKind === 'objects') report = await verifyObjects(pool, stores, { deep });
    else throw new AppError('Unsupported on-demand checkKind (use chain, commitments, or objects).', 400, 'INVALID_CHECK_KIND');
    const recorded = await commands.recordCheck({
      actor,
      commandKey,
      checkKind,
      passed: report.passed,
      report,
    });
    return { ...recorded, checkKind, passed: report.passed, report };
  }

  // ---- R16.5 Bundles (scope checked on server, no sandboxed viewer) ----

  async function listBundles(actor, { runId = null, asOfSeq = null, asOf = null } = {}) {
    assertCanRead(actor, 'bundles', { companySlug });
    const seq = await resolveAsOfSeq({ asOfSeq, asOf });
    return reader.listAccessibleBundles(actor, { runId, asOfSeq: seq });
  }

  async function getBundleConfig(actor, { output, runId = null, asOfSeq = null, asOf = null } = {}) {
    assertCanRead(actor, 'bundles', { companySlug });
    if (!output) throw new AppError('Bundle output path is required.', 400, 'MISSING_BUNDLE_OUTPUT');
    const seq = await resolveAsOfSeq({ asOfSeq, asOf });
    return reader.getBundleConfig(actor, output, { runId, asOfSeq: seq });
  }

  async function getBundleFile(actor, { output, path, acceptsGzip = false, runId = null, asOfSeq = null, asOf = null } = {}) {
    assertCanRead(actor, 'bundles', { companySlug });
    if (!output || !path) throw new AppError('Bundle output and file path are required.', 400, 'MISSING_PARAMS');
    if (isCodeBearingPath(path)) {
      throw new AppError('Code-bearing files cannot be served from bundle endpoints (R1.6, R14.2).', 403, 'CODE_FILE_FORBIDDEN');
    }
    const seq = await resolveAsOfSeq({ asOfSeq, asOf });
    return reader.getBundleFile(actor, output, path, acceptsGzip, { runId, asOfSeq: seq });
  }

  // ---- R16.2 Review App Drift Check ----

  async function getReviewDriftStatus(actor) {
    assertCanRead(actor, 'journal', { companySlug });
    if (!driftCheckConfig) return { configured: false, passed: true, checkedCopies: 0, problems: [] };
    return { configured: true, ...(await checkReviewAppDrift(driftCheckConfig)) };
  }

  return {
    // Inputs
    listInputVersions,
    getInputVersionDetail,
    listStagingFiles,
    includeStagingFile,
    publishInputVersion: (actor, body) => commands.publishInputVersion({ actor, ...body }),
    // Runs & commands
    listRuns,
    getRunDetail,
    launchRun: (actor, body) => commands.launchRun({ actor, ...body }),
    getAttemptLog,
    getReviewConfig,
    getReviewDraft: async (actor, runId, surface, attemptNo) => {
      assertCanRead(actor, 'approvals', { companySlug });
      return { draft: await commands.getReviewDraft({ runId, surface, attemptNo }) };
    },
    saveReviewDraft: (actor, runId, surface, body) => commands.saveReviewDraft({ actor, runId, surface, ...body }),
    submitReview: (actor, runId, surface, { commandKey, expectedJournalSeq, csvBytes }) =>
      commands.submitReview({ actor, commandKey, expectedJournalSeq, runId, surface, csvBytes }),
    getReviewSubmission,
    confirmEmit: (actor, runId, body) => commands.confirmEmit({ actor, runId, ...body }),
    listRunOutputs,
    getRunOutputFile,
    carrySent: (actor, runId, body) => commands.carrySent({ actor, runId, ...body }),
    carryApprovals: (actor, runId, body) => commands.carryApprovals({ actor, runId, ...body }),
    requestCancel: (actor, runId, body) => commands.requestCancel({ actor, runId, ...body }),
    requestRetry: (actor, runId, body) => commands.requestRetry({ actor, runId, ...body }),
    abandonRun: (actor, runId, body) => commands.abandonRun({ actor, runId, ...body }),
    getReviewDriftStatus,
    // History
    getHistoryAsOf,
    getRunJournal,
    getApprovalKeyHistory,
    // Checks
    listChecks,
    getCheckDetail,
    runVerificationCheck,
    // Bundles
    listBundles,
    getBundleConfig,
    getBundleFile,
  };
}
