// Server-side web handlers for Coherence screens: every read runs inside withRequestTx strictly
// through app_views.* and every write runs inside withRequestTx strictly through app_cmd.*.
// Zero role checks, zero ability checks, zero SET LOCAL ROLE, and zero front-end HTML returned.
import { basename } from 'node:path';
import { gzipSync } from 'node:zlib';
import { verifyChain, verifyCommitments, verifyObjects } from '../commands/journal-export.mjs';
import { createRuntimeCommands } from '../commands/runtime-commands.mjs';
import { inReadTx as runReadTx, mapPgError } from '../db/pg-client.mjs';
import { extractAdjustStamp, isCodeBearingPath } from '../storage/artifact-policy.mjs';
import { formatTimestampUtcUs } from '../util/crypto.mjs';
import { assertValidRelPath } from '../util/csv.mjs';
import { AppError, redactPhi } from '../util/redact.mjs';
import { checkReviewAppDrift } from './drift-check.mjs';
import { createViewHandlers } from './view-handlers.mjs';

const MAX_BIGINT = '9223372036854775807';

function extractReviewConfigJson(html, surface, expectedDate) {
  const stamped = extractAdjustStamp(html);
  if (!stamped) {
    throw new AppError('The review page does not carry a valid Coherence stamp.', 502, 'INVALID_REVIEW_STAMP');
  }
  const { config } = stamped;
  if (!config.stamped || config.surface !== surface || config.statementDate !== expectedDate) {
    throw new AppError('The review stamp does not belong to this run and surface.', 502, 'REVIEW_STAMP_MISMATCH');
  }
  return config;
}

export function createWebHandlers({
  pool,
  readonlyPool = null,
  companySlug,
  stores,
  driftCheckConfig = null,
  maxCsvRows,
}) {
  const appCmd = createRuntimeCommands({ pool, stores });
  const inReadTx = (dbToken, fn) => runReadTx(pool, dbToken, fn);

  async function resolveAsOfSeqTx(tx, { asOfSeq = null, asOf = null } = {}) {
    if (asOfSeq != null && asOfSeq !== '') {
      const n = Number(asOfSeq);
      if (!Number.isInteger(n) || n < 0) throw new AppError('asOfSeq must be a non-negative integer.', 400, 'INVALID_AS_OF');
      return n;
    }
    if (asOf) {
      const parsed = new Date(asOf);
      if (Number.isNaN(parsed.getTime())) throw new AppError('asOf must be a valid ISO-8601 timestamp.', 400, 'INVALID_AS_OF');
      const gateRes = await tx.query('SELECT authorized FROM app_views.coherence_journal_gate LIMIT 1');
      if (gateRes.rows.length === 0 || gateRes.rows[0].authorized !== true) {
        throw new AppError('Resolving an asOf timestamp requires journal read access.', 403, 'FORBIDDEN');
      }
      const res = await tx.query(
        'SELECT COALESCE(pg_catalog.max(seq), 0) AS seq FROM app_views.coherence_journal WHERE recorded_at <= $1::timestamptz',
        [parsed.toISOString()],
      );
      return Number(res.rows[0].seq);
    }
    return null;
  }

  async function listRunsTx(tx, { asOfSeq = null, asOf = null } = {}) {
    const limitSeq = await resolveAsOfSeqTx(tx, { asOfSeq, asOf });
    const seqCap = limitSeq != null ? String(limitSeq) : MAX_BIGINT;
    const asOfArg = limitSeq != null ? String(limitSeq) : null;
    const res = await tx.query(
      `SELECT r.id, pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date,
              r.folder_number, r.origin, r.input_version_id, r.engine_version_id,
              r.emit_mode, r.emit_display, r.replays_run_id, r.compared_run_id, r.rerun_reason, r.source_folder,
              r.created_journal_seq,
              r.latest_journal_seq,
              CASE WHEN $2::bigint IS NOT NULL THEN app_views.coherence_run_stage(r.id, $2::bigint) ELSE r.stage END AS stage,
              iv.entries_sha256 AS input_entries_sha256,
              iv.entry_count AS input_entry_count,
              ev.label AS engine_label,
              ev.coherence_commit AS engine_commit,
              je.recorded_at AS launched_at,
              je.actor AS launched_by,
              je.acting_for AS launched_acting_for
       FROM app_views.coherence_runs r
       LEFT JOIN app_views.coherence_input_versions iv ON iv.id = r.input_version_id
       LEFT JOIN app_views.coherence_engine_versions ev ON ev.id = r.engine_version_id
       LEFT JOIN app_views.coherence_journal je ON je.seq = r.created_journal_seq
       WHERE r.created_journal_seq <= $1::bigint
       ORDER BY r.statement_date DESC, r.folder_number DESC, r.created_journal_seq DESC`,
      [seqCap, asOfArg],
    );
    const runs = res.rows.map((r) => ({
      id: r.id,
      statementDate: r.statement_date,
      folderNumber: Number(r.folder_number),
      origin: r.origin,
      stage: r.stage,
      inputVersion: {
        id: r.input_version_id,
        entriesSha256: r.input_entries_sha256 ?? null,
        entryCount: r.input_entry_count != null ? Number(r.input_entry_count) : null,
      },
      engineVersion: r.engine_version_id ? { id: r.engine_version_id, label: r.engine_label, commit: r.engine_commit } : null,
      emitMode: r.emit_mode,
      emitDisplay: r.emit_display,
      replaysRunId: r.replays_run_id,
      comparedRunId: r.compared_run_id,
      rerunReason: r.rerun_reason,
      sourceFolder: r.source_folder,
      createdJournalSeq: Number(r.created_journal_seq),
      latestJournalSeq: Number(r.latest_journal_seq),
      launchedAt: r.launched_at ? formatTimestampUtcUs(r.launched_at) : null,
      launchedBy: r.launched_by ?? null,
      launchedActingFor: r.launched_acting_for ?? null,
    }));
    const maxSeqRes = await tx.query('SELECT COALESCE(pg_catalog.max(seq), 0) AS max_seq FROM app_views.coherence_journal');
    return {
      companySlug,
      asOfSeq: limitSeq,
      currentJournalSeq: Number(maxSeqRes.rows[0].max_seq),
      runs,
    };
  }

  async function listInputVersions(dbToken, { asOfSeq = null, asOf = null } = {}) {
    return inReadTx(dbToken, async (tx) => {
      const limitSeq = await resolveAsOfSeqTx(tx, { asOfSeq, asOf });
      const seqCap = limitSeq != null ? String(limitSeq) : MAX_BIGINT;
      const res = await tx.query(
        `SELECT iv.id, iv.line_kind, iv.parent_id, iv.source_kind, iv.reason,
                iv.entry_count, iv.entries_sha256, iv.change_count, iv.changes_sha256,
                iv.journal_seq, je.recorded_at, je.actor, je.acting_for
         FROM app_views.coherence_input_versions iv
         LEFT JOIN app_views.coherence_journal je ON je.seq = iv.journal_seq
         WHERE iv.line_kind = 'standing' AND iv.journal_seq <= $1::bigint
         ORDER BY iv.journal_seq DESC`,
        [seqCap],
      );
      const changesByVersion = new Map();
      if (res.rows.length > 0) {
        const chRes = await tx.query(
          `SELECT input_version_id, rel_path, change_kind, old_rel_path, file_sha256, prev_file_sha256
           FROM app_views.coherence_input_changes
           WHERE input_version_id = ANY($1::uuid[])
           ORDER BY rel_path COLLATE "C"`,
          [res.rows.map((r) => r.id)],
        );
        for (const c of chRes.rows) {
          const list = changesByVersion.get(c.input_version_id) || [];
          list.push({
            relPath: c.rel_path,
            changeKind: c.change_kind,
            oldRelPath: c.old_rel_path,
            fileSha256: c.file_sha256,
            prevFileSha256: c.prev_file_sha256,
          });
          changesByVersion.set(c.input_version_id, list);
        }
      }
      const versions = res.rows.map((row) => ({
        id: row.id,
        parentId: row.parent_id,
        sourceKind: row.source_kind,
        reason: row.reason,
        entryCount: Number(row.entry_count),
        entriesSha256: row.entries_sha256,
        changeCount: Number(row.change_count),
        changesSha256: row.changes_sha256,
        journalSeq: Number(row.journal_seq),
        recordedAt: row.recorded_at ? formatTimestampUtcUs(row.recorded_at) : null,
        actor: row.actor ?? null,
        actingFor: row.acting_for ?? null,
        changes: changesByVersion.get(row.id) || [],
      }));
      const maxSeqRes = await tx.query('SELECT COALESCE(pg_catalog.max(seq), 0) AS max_seq FROM app_views.coherence_journal');
      return { companySlug, asOfSeq: limitSeq, currentJournalSeq: Number(maxSeqRes.rows[0].max_seq), versions };
    });
  }

  async function getInputVersionDetail(dbToken, versionId) {
    return inReadTx(dbToken, async (tx) => {
      const ivRes = await tx.query(
        `SELECT iv.*, je.recorded_at, je.actor, je.acting_for
         FROM app_views.coherence_input_versions iv
         LEFT JOIN app_views.coherence_journal je ON je.seq = iv.journal_seq
         WHERE iv.id = $1::uuid`,
        [versionId],
      );
      if (ivRes.rows.length === 0) throw new AppError('Input version not found.', 404, 'NOT_FOUND');
      const iv = ivRes.rows[0];
      const entriesRes = await tx.query(
        `SELECT rel_path, file_sha256, byte_size, md5_b64, crc32c_b64
         FROM app_views.coherence_input_entries
         WHERE input_version_id = $1::uuid
         ORDER BY rel_path COLLATE "C"`,
        [versionId],
      );
      const changesRes = await tx.query(
        `SELECT rel_path, change_kind, old_rel_path, file_sha256, prev_file_sha256
         FROM app_views.coherence_input_changes
         WHERE input_version_id = $1::uuid
         ORDER BY rel_path COLLATE "C"`,
        [versionId],
      );
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
        recordedAt: iv.recorded_at ? formatTimestampUtcUs(iv.recorded_at) : null,
        actor: iv.actor ?? null,
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
    });
  }

  async function listStagingFiles(dbToken) {
    return inReadTx(dbToken, async (tx) => {
      const stagedRes = await tx.query(
        `SELECT id, rel_path, file_sha256, original_at, metadata, byte_size, md5_b64, journal_seq
         FROM app_views.coherence_staging_files
         ORDER BY rel_path COLLATE "C"`,
      );
      const currentStanding = await tx.query(
        `SELECT id FROM app_views.coherence_input_versions
         WHERE line_kind = 'standing'
         ORDER BY journal_seq DESC
         LIMIT 1`,
      );
      const standingId = currentStanding.rows[0]?.id ?? null;
      const includedMap = new Map();
      if (standingId) {
        const entriesRes = await tx.query(
          'SELECT rel_path, file_sha256 FROM app_views.coherence_input_entries WHERE input_version_id = $1::uuid',
          [standingId],
        );
        for (const e of entriesRes.rows) {
          if (!e.file_sha256) continue;
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
          includedAt: r.file_sha256 ? (includedMap.get(r.file_sha256) || []) : [],
        })),
      };
    });
  }

  async function includeStagingFile(dbToken, body = {}) {
    const b = body && typeof body === 'object' ? body : {};
    return appCmd.includeStagingFile({
      commandKey: b.commandKey,
      expectedJournalSeq: b.expectedJournalSeq,
      stagingFileSha256: b.stagingFileSha256,
      targetRelPath: b.targetRelPath,
      reason: b.reason,
      dbToken,
    });
  }

  async function listRuns(dbToken, { asOfSeq = null, asOf = null } = {}) {
    return inReadTx(dbToken, (tx) => listRunsTx(tx, { asOfSeq, asOf }));
  }

  async function getRunDetail(dbToken, runId, { asOfSeq = null, asOf = null } = {}) {
    return inReadTx(dbToken, async (tx) => {
      const limitSeq = await resolveAsOfSeqTx(tx, { asOfSeq, asOf });
      const seqCap = limitSeq != null ? String(limitSeq) : MAX_BIGINT;
      const asOfArg = limitSeq != null ? String(limitSeq) : null;
      const runRes = await tx.query(
        `SELECT r.id, pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date,
                r.folder_number, r.origin, r.input_version_id, r.prior_approvals_sha256,
                r.prior_decision_commit_id, r.engine_version_id,
                r.emit_mode, r.emit_display, r.emit_keep, r.emit_no_manager,
                r.replays_run_id, r.compared_run_id, r.rerun_reason, r.source_folder,
                r.created_journal_seq AS journal_seq,
                CASE WHEN $3::bigint IS NOT NULL THEN app_views.coherence_run_stage(r.id, $3::bigint) ELSE r.stage END AS stage,
                r.latest_journal_seq,
                iv.entries_sha256, iv.entry_count,
                ev.label AS engine_label, ev.coherence_commit, ev.nusear_commit,
                ev.code_manifest_sha256, ev.wrapper_bundle_sha256
         FROM app_views.coherence_runs r
         LEFT JOIN app_views.coherence_input_versions iv ON iv.id = r.input_version_id
         LEFT JOIN app_views.coherence_engine_versions ev ON ev.id = r.engine_version_id
         WHERE r.id = $1::uuid AND r.created_journal_seq <= $2::bigint`,
        [runId, seqCap, asOfArg],
      );
      if (runRes.rows.length === 0) throw new AppError('Run not found.', 404, 'RUN_NOT_FOUND');
      const r = runRes.rows[0];
      const stage = r.stage;

      const attemptsRes = await tx.query(
        `SELECT e.id, e.step, e.attempt_no, e.event_kind, e.census, e.born, e.log_file_sha256,
                e.error_summary, e.artifact_count, e.artifacts_sha256, e.journal_seq, je.recorded_at
         FROM app_views.coherence_step_attempt_events e
         LEFT JOIN app_views.coherence_journal je ON je.seq = e.journal_seq
         WHERE e.run_id = $1::uuid AND e.journal_seq <= $2::bigint
         ORDER BY e.journal_seq ASC, e.attempt_no ASC`,
        [runId, seqCap],
      );
      const savesRes = await tx.query(
        `SELECT rs.id, rs.surface, rs.attempt_event_id, rs.approvals_file_sha256, rs.decision_commit_id,
                rs.imported, rs.original_at, rs.journal_seq, rs.row_count, rs.header_kind,
                je.recorded_at, je.actor, je.acting_for
         FROM app_views.coherence_review_saves rs
         LEFT JOIN app_views.coherence_journal je ON je.seq = rs.journal_seq
         WHERE rs.run_id = $1::uuid AND rs.journal_seq <= $2::bigint
         ORDER BY rs.journal_seq ASC`,
        [runId, seqCap],
      );
      const subsRes = await tx.query(
        `SELECT id, surface, status, staged_sha256, review_save_id, result_journal_seq, result_message, created_at, resolved_at
         FROM app_views.coherence_review_submissions
         WHERE run_id = $1::uuid
         ORDER BY created_at DESC LIMIT 10`,
        [runId],
      );
      const confirmsRes = await tx.query(
        `SELECT ec.id, ec.adjust_review_save_id, ec.typed_phrase, ec.journal_seq, je.recorded_at, je.actor
         FROM app_views.coherence_emit_confirmations ec
         LEFT JOIN app_views.coherence_journal je ON je.seq = ec.journal_seq
         WHERE ec.run_id = $1::uuid AND ec.journal_seq <= $2::bigint
         ORDER BY ec.journal_seq ASC`,
        [runId, seqCap],
      );
      const carriesRes = await tx.query(
        `SELECT c.id, c.carry_kind, c.file_sha256, c.published_input_version_id, c.nothing_new, c.journal_seq, je.recorded_at, je.actor
         FROM app_views.coherence_carries c
         LEFT JOIN app_views.coherence_journal je ON je.seq = c.journal_seq
         WHERE c.run_id = $1::uuid AND c.journal_seq <= $2::bigint
         ORDER BY c.journal_seq ASC`,
        [runId, seqCap],
      );
      const abandonRes = await tx.query(
        `SELECT a.id, a.reason, a.journal_seq, je.recorded_at, je.actor
         FROM app_views.coherence_abandonments a
         LEFT JOIN app_views.coherence_journal je ON je.seq = a.journal_seq
         WHERE a.run_id = $1::uuid AND a.journal_seq <= $2::bigint`,
        [runId, seqCap],
      );

      return {
        id: r.id,
        statementDate: r.statement_date,
        folderNumber: Number(r.folder_number),
        origin: r.origin,
        stage,
        createdJournalSeq: Number(r.journal_seq),
        latestJournalSeq: Number(r.latest_journal_seq),
        inputVersion: {
          id: r.input_version_id,
          entriesSha256: r.entries_sha256 ?? null,
          entryCount: r.entry_count != null ? Number(r.entry_count) : null,
        },
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
          recordedAt: a.recorded_at ? formatTimestampUtcUs(a.recorded_at) : null,
        })),
        reviewSaves: savesRes.rows.map((s) => ({
          id: s.id,
          surface: s.surface,
          attemptEventId: s.attempt_event_id,
          approvalsFileSha256: s.approvals_file_sha256,
          headerKind: s.header_kind,
          rowCount: s.row_count != null ? Number(s.row_count) : null,
          imported: s.imported,
          originalAt: s.original_at ? formatTimestampUtcUs(s.original_at) : null,
          journalSeq: Number(s.journal_seq),
          recordedAt: s.recorded_at ? formatTimestampUtcUs(s.recorded_at) : null,
          actor: s.actor ?? null,
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
          typedPhrase: c.typed_phrase,
          journalSeq: Number(c.journal_seq),
          recordedAt: c.recorded_at ? formatTimestampUtcUs(c.recorded_at) : null,
          actor: c.actor ?? null,
        })),
        carries: carriesRes.rows.map((c) => ({
          id: c.id,
          carryKind: c.carry_kind,
          fileSha256: c.file_sha256,
          publishedInputVersionId: c.published_input_version_id,
          nothingNew: c.nothing_new,
          journalSeq: Number(c.journal_seq),
          recordedAt: c.recorded_at ? formatTimestampUtcUs(c.recorded_at) : null,
          actor: c.actor ?? null,
        })),
        abandonment: abandonRes.rows[0] ? {
          id: abandonRes.rows[0].id,
          reason: abandonRes.rows[0].reason,
          journalSeq: Number(abandonRes.rows[0].journal_seq),
          recordedAt: abandonRes.rows[0].recorded_at ? formatTimestampUtcUs(abandonRes.rows[0].recorded_at) : null,
          actor: abandonRes.rows[0].actor ?? null,
        } : null,
      };
    });
  }

  async function getAttemptLog(dbToken, runId, step, attemptNo) {
    const row = await inReadTx(dbToken, async (tx) => {
      const res = await tx.query(
        `SELECT log_file_sha256, log_byte_size, log_md5_b64, log_crc32c_b64
         FROM app_views.coherence_step_attempt_events
         WHERE run_id = $1::uuid AND step = $2 AND attempt_no = $3 AND log_file_sha256 IS NOT NULL
         ORDER BY journal_seq DESC LIMIT 1`,
        [runId, step, Number(attemptNo)],
      );
      return res.rows[0] || null;
    });
    if (!row) throw new AppError('Step log not found.', 404, 'LOG_NOT_FOUND');
    const bytes = await stores.dataStore.readVerified(row.log_file_sha256, {
      byteSize: Number(row.log_byte_size), md5B64: row.log_md5_b64, crc32cB64: row.log_crc32c_b64,
    });
    return { text: redactPhi(bytes.toString('utf8')) };
  }

  /**
   * Extracts only the JSON review configuration from bible.json/adjust.json (or legacy sealed HTML)
   * after PostgreSQL authorizes the handle via app_views.coherence_review_configs; never returns HTML/JS.
   */
  async function getReviewConfig(dbToken, runId, surface) {
    if (!['bible', 'adjust'].includes(surface)) throw new AppError('Choose bible or adjust.', 400, 'INVALID_SURFACE');
    const art = await inReadTx(dbToken, async (tx) => {
      const res = await tx.query(
        `SELECT statement_date, attempt_no, rel_path, store_kind, file_sha256, byte_size, md5_b64, crc32c_b64
         FROM app_views.coherence_review_configs
         WHERE run_id = $1::uuid AND surface = $2
         ORDER BY CASE WHEN rel_path = $3 THEN 1 ELSE 2 END
         LIMIT 1`,
        [runId, surface, `${surface}.json`],
      );
      return res.rows[0] || null;
    });
    if (!art) throw new AppError(`No ${surface} review config is available.`, 404, 'REVIEW_CONFIG_MISSING');
    const rawBytes = await stores.readVerified(art.store_kind, art.file_sha256, {
      byteSize: Number(art.byte_size), md5B64: art.md5_b64, crc32cB64: art.crc32c_b64,
    });
    const config = art.rel_path.endsWith('.json')
      ? JSON.parse(rawBytes.toString('utf8'))
      : extractReviewConfigJson(rawBytes.toString('utf8'), surface, art.statement_date);
    return { runId, surface, attemptNo: Number(art.attempt_no), config };
  }

  async function getReviewDraft(dbToken, runId, surface, attemptNo) {
    return inReadTx(dbToken, async (tx) => {
      const res = await tx.query(
        `SELECT run_id, surface, attempt_no, born, checksum, rows_json, updated_at, expires_at
         FROM app_views.coherence_review_drafts
         WHERE run_id = $1::uuid AND surface = $2 AND attempt_no = $3`,
        [runId, surface, Number(attemptNo)],
      );
      if (res.rows.length === 0) return { draft: null };
      const row = res.rows[0];
      return {
        draft: {
          runId: row.run_id,
          surface: row.surface,
          attemptNo: Number(row.attempt_no),
          born: row.born,
          checksum: row.checksum,
          rows: row.rows_json,
          updatedAt: formatTimestampUtcUs(row.updated_at),
          expiresAt: formatTimestampUtcUs(row.expires_at),
        },
      };
    });
  }

  async function getReviewSubmission(dbToken, submissionId) {
    return inReadTx(dbToken, async (tx) => {
      const res = await tx.query(
        `SELECT id, run_id, surface, status, staged_sha256, review_save_id, result_journal_seq, result_message, created_at, resolved_at
         FROM app_views.coherence_review_submissions
         WHERE id = $1::uuid`,
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
    });
  }

  async function listRunOutputs(dbToken, runId) {
    return inReadTx(dbToken, async (tx) => {
      const artRes = await tx.query(
        `SELECT rel_path, file_sha256, byte_size, md5_b64, crc32c_b64
         FROM app_views.coherence_run_outputs
         WHERE run_id = $1::uuid
         ORDER BY rel_path COLLATE "C"`,
        [runId],
      );
      if (artRes.rows.length === 0) return { available: false, files: [] };
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
    });
  }

  async function getRunOutputFile(dbToken, runId, relPath, acceptsGzip = false) {
    assertValidRelPath(relPath, 'output path');
    if (isCodeBearingPath(relPath)) {
      throw new AppError('Code-bearing files cannot be downloaded from output endpoints.', 403, 'CODE_FILE_FORBIDDEN');
    }
    const art = await inReadTx(dbToken, async (tx) => {
      const artRes = await tx.query(
        `SELECT file_sha256, byte_size, md5_b64, crc32c_b64
         FROM app_views.coherence_run_outputs
         WHERE run_id = $1::uuid AND rel_path = $2`,
        [runId, relPath],
      );
      return artRes.rows[0] || null;
    });
    if (!art) throw new AppError('Output data file not found.', 404, 'FILE_NOT_FOUND');
    const bytes = await stores.dataStore.readVerified(art.file_sha256, {
      byteSize: Number(art.byte_size), md5B64: art.md5_b64, crc32cB64: art.crc32c_b64,
    });
    return { name: basename(relPath), body: acceptsGzip ? gzipSync(bytes) : bytes, gzip: Boolean(acceptsGzip) };
  }

  async function getHistoryAsOf(dbToken, { asOfSeq = null, asOf = null } = {}) {
    return inReadTx(dbToken, async (tx) => {
      const seq = await resolveAsOfSeqTx(tx, { asOfSeq, asOf });
      if (seq === null) throw new AppError('Provide asOfSeq or asOf timestamp.', 400, 'MISSING_AS_OF');
      const jeRes = await tx.query(
        'SELECT seq, recorded_at, actor, acting_for, command_kind, entry_hash FROM app_views.coherence_journal WHERE seq = $1::bigint',
        [String(seq)],
      );
      const ivRes = await tx.query(
        `SELECT id FROM app_views.coherence_input_versions
         WHERE line_kind = 'standing' AND journal_seq <= $1::bigint
         ORDER BY journal_seq DESC LIMIT 1`,
        [String(seq)],
      );
      const runsRes = await listRunsTx(tx, { asOfSeq: seq });
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
    });
  }

  async function getRunJournal(dbToken, runId) {
    return inReadTx(dbToken, async (tx) => {
      const res = await tx.query(
        `SELECT DISTINCT je.seq, je.recorded_at, je.actor, je.acting_for, je.command_kind,
                je.command_key, je.prev_hash, je.entry_hash, je.body
         FROM app_views.coherence_journal je
         WHERE je.seq IN (
           SELECT created_journal_seq FROM app_views.coherence_runs WHERE id = $1::uuid
           UNION SELECT journal_seq FROM app_views.coherence_step_requests WHERE run_id = $1::uuid
           UNION SELECT journal_seq FROM app_views.coherence_cancel_requests WHERE run_id = $1::uuid
           UNION SELECT journal_seq FROM app_views.coherence_step_attempt_events WHERE run_id = $1::uuid
           UNION SELECT journal_seq FROM app_views.coherence_review_saves WHERE run_id = $1::uuid
           UNION SELECT journal_seq FROM app_views.coherence_emit_confirmations WHERE run_id = $1::uuid
           UNION SELECT journal_seq FROM app_views.coherence_carries WHERE run_id = $1::uuid
           UNION SELECT journal_seq FROM app_views.coherence_abandonments WHERE run_id = $1::uuid
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
    });
  }

  async function getApprovalKeyHistory(dbToken, recordId) {
    if (typeof recordId !== 'string' || !recordId.length) {
      throw new AppError('recordId is required.', 400, 'MISSING_RECORD_ID');
    }
    return inReadTx(dbToken, async (tx) => {
      const res = await tx.query(
        `SELECT ar.approvals_file_sha256, ar.row_no, ar.record_id, ar.disposition, ar.agent, ar.agency,
                ar.policy, ar.book, ar.month, ar.status, ar.note, ar.committed_at,
                ar.approved_amount, ar.approved_agency, ar.approved_agent,
                ar.approved_agency_from, ar.approved_agent_from,
                ar.journal_seq, ar.run_id, ar.surface,
                je.recorded_at, je.actor, je.acting_for
         FROM app_views.coherence_approval_rows ar
         LEFT JOIN app_views.coherence_journal je ON je.seq = ar.journal_seq
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
          recordedAt: r.recorded_at ? formatTimestampUtcUs(r.recorded_at) : null,
          actor: r.actor ?? null,
          actingFor: r.acting_for ?? null,
        })),
      };
    });
  }

  async function getDecisionKeyHistory(dbToken, recordId) {
    if (typeof recordId !== 'string' || !recordId.length) {
      throw new AppError('recordId is required.', 400, 'MISSING_RECORD_ID');
    }
    return inReadTx(dbToken, async (tx) => {
      const res = await tx.query(
        `SELECT d.id, d.decision_commit_id, d.row_order, d.run_id, d.review_save_id, d.surface,
                d.record_id, d.replaces_decision_id, d.disposition, d.agent, d.agency,
                d.policy, d.book, d.month, d.status, d.note,
                d.approved_amount, d.approved_agency, d.approved_agent,
                d.approved_agency_from, d.approved_agent_from,
                d.decided_by, d.acting_for, d.decided_at, d.committed_at_raw, d.imported,
                d.journal_seq, je.recorded_at
         FROM app_views.coherence_decisions d
         LEFT JOIN app_views.coherence_journal je ON je.seq = d.journal_seq
         WHERE d.record_id = $1
         ORDER BY d.journal_seq ASC, d.row_order ASC`,
        [recordId],
      );
      return {
        recordId,
        history: res.rows.map((r) => ({
          id: r.id,
          decisionCommitId: r.decision_commit_id,
          rowOrder: Number(r.row_order),
          replacesDecisionId: r.replaces_decision_id,
          disposition: r.disposition,
          agent: r.agent,
          agency: r.agency,
          policy: r.policy,
          book: r.book,
          month: r.month,
          status: r.status,
          note: r.note,
          approvedAmount: r.approved_amount,
          approvedAgency: r.approved_agency,
          approvedAgent: r.approved_agent,
          approvedAgencyFrom: r.approved_agency_from,
          approvedAgentFrom: r.approved_agent_from,
          decidedBy: r.decided_by,
          actingFor: r.acting_for ?? null,
          decidedAt: formatTimestampUtcUs(r.decided_at),
          committedAt: r.committed_at_raw ?? formatTimestampUtcUs(r.decided_at),
          imported: r.imported,
          runId: r.run_id,
          reviewSaveId: r.review_save_id,
          surface: r.surface,
          journalSeq: Number(r.journal_seq),
          recordedAt: r.recorded_at ? formatTimestampUtcUs(r.recorded_at) : null,
        })),
      };
    });
  }

  async function listChecks(dbToken, { kind = null, runId = null } = {}) {
    return inReadTx(dbToken, async (tx) => {
      const conditions = [];
      const params = [];
      if (kind) { params.push(kind); conditions.push(`c.check_kind = $${params.length}`); }
      if (runId) { params.push(runId); conditions.push(`c.run_id = $${params.length}::uuid`); }
      const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
      const res = await tx.query(
        `SELECT c.id, c.check_kind, c.run_id, c.compared_run_id, c.passed, c.report, c.journal_seq,
                je.recorded_at, je.actor
         FROM app_views.coherence_checks c
         LEFT JOIN app_views.coherence_journal je ON je.seq = c.journal_seq
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
          recordedAt: r.recorded_at ? formatTimestampUtcUs(r.recorded_at) : null,
          actor: r.actor ?? null,
        })),
      };
    });
  }

  async function getCheckDetail(dbToken, checkId) {
    return inReadTx(dbToken, async (tx) => {
      const res = await tx.query(
        `SELECT c.*, je.recorded_at, je.actor
         FROM app_views.coherence_checks c
         LEFT JOIN app_views.coherence_journal je ON je.seq = c.journal_seq
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
        recordedAt: r.recorded_at ? formatTimestampUtcUs(r.recorded_at) : null,
        actor: r.actor ?? null,
      };
    });
  }

  async function runVerificationCheck(dbToken, body = {}) {
    const b = body && typeof body === 'object' ? body : {};
    const { commandKey, checkKind, deep = false } = b;
    // Database-enforced authorization gate runs before touching any verifier reader or object store.
    await appCmd.authorizeCheckRun({ dbToken });
    if (!readonlyPool || readonlyPool === pool) {
      throw new AppError('Read-only check pool is not configured.', 503, 'CHECK_READER_NOT_CONFIGURED');
    }
    let report;
    try {
      if (checkKind === 'chain') report = await verifyChain(readonlyPool);
      else if (checkKind === 'commitments') report = await verifyCommitments(readonlyPool);
      else if (checkKind === 'objects') report = await verifyObjects(readonlyPool, stores, { deep: Boolean(deep) });
      else throw new AppError('Unsupported on-demand checkKind (use chain, commitments, or objects).', 400, 'INVALID_CHECK_KIND');
    } catch (err) {
      throw mapPgError(err);
    }
    const recorded = await appCmd.recordCheck({
      commandKey,
      checkKind,
      passed: report.passed,
      report,
      dbToken,
    });
    const maskedReport = await inReadTx(dbToken, async (tx) => {
      const res = await tx.query(
        'SELECT report FROM app_views.coherence_checks WHERE id = $1::uuid',
        [recorded.result.checkId],
      );
      return res.rows[0]?.report ?? null;
    });
    return { ...recorded, checkKind, passed: report.passed, report: maskedReport };
  }

  async function getReviewDriftStatus(dbToken) {
    const allowed = await inReadTx(dbToken, async (tx) => {
      const res = await tx.query('SELECT authorized FROM app_views.coherence_review_drift_gate LIMIT 1');
      return res.rows.length > 0 && res.rows[0].authorized === true;
    });
    if (!allowed) throw new AppError('Insufficient database privilege for this operation.', 403, 'FORBIDDEN');
    if (!driftCheckConfig) return { configured: false, passed: true, checkedCopies: 0, problems: [] };
    return { configured: true, ...(await checkReviewAppDrift(driftCheckConfig)) };
  }

  const obj = (body) => (body && typeof body === 'object' ? body : {});
  const viewHandlers = createViewHandlers({ pool, companySlug, resolveAsOfSeqTx, maxCsvRows });

  return {
    ...viewHandlers,
    listInputVersions,
    getInputVersionDetail,
    listStagingFiles,
    includeStagingFile,
    publishInputVersion: (dbToken, body) => {
      const b = obj(body);
      return appCmd.publishInputVersion({
        commandKey: b.commandKey,
        expectedJournalSeq: b.expectedJournalSeq,
        lineKind: b.lineKind,
        sourceKind: b.sourceKind,
        reason: b.reason,
        entries: b.entries,
        changes: b.changes,
        storedFiles: b.storedFiles,
        entriesListFileSha256: b.entriesListFileSha256,
        storeCanonicalList: b.storeCanonicalList,
        dbToken,
      });
    },
    listRuns,
    getRunDetail,
    launchRun: (dbToken, body) => {
      const b = obj(body);
      return appCmd.launchRun({
        commandKey: b.commandKey,
        expectedJournalSeq: b.expectedJournalSeq,
        statementDate: b.statementDate,
        engineVersionId: b.engineVersionId,
        origin: b.origin,
        inputVersionId: b.inputVersionId,
        priorDecisionCommitId: b.priorDecisionCommitId,
        emitMode: b.emitMode,
        emitDisplay: b.emitDisplay,
        emitKeep: b.emitKeep,
        emitNoManager: b.emitNoManager,
        replaysRunId: b.replaysRunId,
        comparedRunId: b.comparedRunId,
        rerunReason: b.rerunReason,
        dbToken,
      });
    },
    getAttemptLog,
    getReviewConfig,
    getReviewDraft,
    saveReviewDraft: (dbToken, runId, surface, body) => {
      const b = obj(body);
      return appCmd.saveReviewDraft({
        attemptNo: b.attemptNo,
        born: b.born,
        checksum: b.checksum,
        rows: b.rows,
        runId,
        surface,
        dbToken,
      });
    },
    submitReview: (dbToken, runId, surface, body) => {
      const b = obj(body);
      return appCmd.submitReview({
        commandKey: b.commandKey,
        expectedJournalSeq: b.expectedJournalSeq,
        csvBytes: b.csvBytes,
        runId,
        surface,
        dbToken,
      });
    },
    saveReviewDecisions: (dbToken, runId, surface, body) => {
      const b = obj(body);
      return appCmd.saveReviewDecisions({
        commandKey: b.commandKey,
        expectedJournalSeq: b.expectedJournalSeq,
        decisions: b.decisions,
        runId,
        surface,
        dbToken,
      });
    },
    getReviewSubmission,
    confirmEmit: (dbToken, runId, body) => {
      const b = obj(body);
      return appCmd.confirmEmit({
        commandKey: b.commandKey,
        expectedJournalSeq: b.expectedJournalSeq,
        adjustReviewSaveId: b.adjustReviewSaveId,
        typedPhrase: b.typedPhrase,
        runId,
        dbToken,
      });
    },
    listRunOutputs,
    getRunOutputFile,
    carrySent: (dbToken, runId, body) => {
      const b = obj(body);
      return appCmd.carrySent({
        commandKey: b.commandKey,
        expectedJournalSeq: b.expectedJournalSeq,
        typedPhrase: b.typedPhrase,
        reason: b.reason,
        runId,
        dbToken,
      });
    },
    carryApprovals: (dbToken, runId, body) => {
      const b = obj(body);
      return appCmd.carryApprovals({
        commandKey: b.commandKey,
        expectedJournalSeq: b.expectedJournalSeq,
        typedPhrase: b.typedPhrase,
        runId,
        dbToken,
      });
    },
    carryDecisions: (dbToken, runId, body) => {
      const b = obj(body);
      return appCmd.carryDecisions({
        commandKey: b.commandKey,
        expectedJournalSeq: b.expectedJournalSeq,
        typedPhrase: b.typedPhrase,
        receiptFileSha256: b.receiptFileSha256,
        runId,
        dbToken,
      });
    },
    requestCancel: (dbToken, runId, body) => {
      const b = obj(body);
      return appCmd.requestCancel({
        commandKey: b.commandKey,
        expectedJournalSeq: b.expectedJournalSeq,
        step: b.step,
        attemptNo: b.attemptNo,
        typedPhrase: b.typedPhrase,
        reason: b.reason,
        runId,
        dbToken,
      });
    },
    requestRetry: (dbToken, runId, body) => {
      const b = obj(body);
      return appCmd.requestRetry({
        commandKey: b.commandKey,
        expectedJournalSeq: b.expectedJournalSeq,
        step: b.step,
        runId,
        dbToken,
      });
    },
    abandonRun: (dbToken, runId, body) => {
      const b = obj(body);
      return appCmd.abandonRun({
        commandKey: b.commandKey,
        expectedJournalSeq: b.expectedJournalSeq,
        typedPhrase: b.typedPhrase,
        reason: b.reason,
        runId,
        dbToken,
      });
    },
    getReviewDriftStatus,
    getHistoryAsOf,
    getRunJournal,
    getApprovalKeyHistory,
    getDecisionKeyHistory,
    listChecks,
    getCheckDetail,
    runVerificationCheck,
  };
}
