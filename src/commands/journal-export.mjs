import {
  computeJournalHash,
  formatTimestampUtcUs,
  GENESIS_HASH,
} from '../util/crypto.mjs';
import { isCodeBearingPath } from '../storage/artifact-policy.mjs';
import { buildCommitments, BUSINESS_TABLES, formatIsoDate } from './commitments.mjs';

const EXPORT_TABLE_ORDER = [
  'company_meta',
  'stored_files',
  'engine_versions',
  'approvals_files',
  'approval_rows',
  'decision_commits',
  'input_versions',
  'input_entries',
  'input_changes',
  'runs',
  'step_requests',
  'cancel_requests',
  'step_attempt_events',
  'artifacts',
  'review_queue_items',
  'review_saves',
  'decisions',
  'generated_overlays',
  'emit_confirmations',
  'statement_batches',
  'statement_agency_lines',
  'statement_upline_lines',
  'run_materializations',
  'bob_policies',
  'bob_policy_financials',
  'coherent_ledger_rows',
  'carries',
  'abandonments',
  'imported_files',
  'checks',
];

const DATE_COLS = new Set([
  'statement_date', 'submission_date', 'origin_effective', 'effective_date',
  'termination_date', 'earned_date', 'payment_date', 'posted_statement_date',
  'min_date', 'anchor_date', 'agency_start',
]);

function normalizeExportRow(raw) {
  const clean = { ...raw };
  delete clean.journal_seq;
  delete clean.mac_key;
  if (clean.original_at) clean.original_at = formatTimestampUtcUs(clean.original_at);
  if (clean.decided_at) clean.decided_at = formatTimestampUtcUs(clean.decided_at);
  if (clean.byte_size !== undefined) clean.byte_size = Number(clean.byte_size);
  for (const col of DATE_COLS) {
    if (clean[col] !== undefined && clean[col] !== null) {
      clean[col] = formatIsoDate(clean[col]);
    }
  }
  return clean;
}

function selectQueryForTable(tbl) {
  if (tbl === 'runs') {
    return `SELECT id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date, folder_number, origin,
                   input_version_id, prior_approvals_sha256, prior_decision_commit_id, engine_version_id,
                   emit_mode, emit_display, emit_keep, emit_no_manager, replays_run_id, compared_run_id,
                   rerun_reason, source_folder
            FROM coherence.runs WHERE journal_seq = $1 ORDER BY id::text COLLATE "C"`;
  }
  if (tbl === 'carries') {
    return `SELECT id, run_id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date, carry_kind,
                   store_kind, file_sha256, carried_decision_commit_id, published_input_version_id, nothing_new, typed_phrase
            FROM coherence.carries WHERE journal_seq = $1 ORDER BY id::text COLLATE "C"`;
  }
  if (tbl === 'step_attempt_events') {
    return `SELECT id, run_id, step, attempt_no, event_kind, step_request_id, cancel_request_id,
                   census, born, log_store_kind, log_file_sha256, error_summary,
                   artifact_count, artifacts_sha256, original_at
            FROM coherence.step_attempt_events WHERE journal_seq = $1
            ORDER BY CASE event_kind WHEN 'started' THEN 1 WHEN 'finished' THEN 2 WHEN 'failed' THEN 2 WHEN 'interrupted' THEN 2 WHEN 'cancelled' THEN 2 ELSE 3 END,
                     attempt_no ASC, id::text COLLATE "C"`;
  }
  if (tbl === 'input_entries') {
    return `SELECT input_version_id, rel_path, store_kind, file_sha256
            FROM coherence.input_entries WHERE journal_seq = $1
            ORDER BY input_version_id::text COLLATE "C", rel_path COLLATE "C"`;
  }
  if (tbl === 'approval_rows') {
    return `SELECT approvals_file_sha256, row_no, record_id, disposition, agent, agency, policy, book, month,
                   status, note, committed_at, approved_amount, approved_agency, approved_agent,
                   approved_agency_from, approved_agent_from
            FROM coherence.approval_rows WHERE journal_seq = $1
            ORDER BY approvals_file_sha256 COLLATE "C", row_no ASC`;
  }
  if (tbl === 'decisions') {
    return `SELECT id, decision_commit_id, row_order, run_id, review_save_id, surface, record_id,
                   replaces_decision_id, disposition, agent, agency, policy, book, month, status, note,
                   approved_amount, approved_agency, approved_agent, approved_agency_from, approved_agent_from,
                   decided_by, acting_for, coherence.format_utc_us(decided_at) AS decided_at, committed_at_raw, imported
            FROM coherence.decisions WHERE journal_seq = $1
            ORDER BY decision_commit_id::text COLLATE "C", row_order ASC`;
  }
  if (tbl === 'decision_commits') {
    return `SELECT id, parent_commit_id, commit_kind, header_contract, added_decision_count,
                   cumulative_decision_count, added_decisions_sha256, imported,
                   CASE WHEN original_at IS NULL THEN NULL ELSE coherence.format_utc_us(original_at) END AS original_at
            FROM coherence.decision_commits WHERE journal_seq = $1 ORDER BY id::text COLLATE "C"`;
  }
  if (tbl === 'review_saves') {
    return `SELECT id, run_id, surface, attempt_event_id, approvals_file_sha256, decision_commit_id, imported,
                   CASE WHEN original_at IS NULL THEN NULL ELSE coherence.format_utc_us(original_at) END AS original_at,
                   submission_id
            FROM coherence.review_saves WHERE journal_seq = $1 ORDER BY id::text COLLATE "C"`;
  }
  if (tbl === 'review_queue_items') {
    return `SELECT attempt_event_id, item_order, run_id, surface, record_id, case_kind, subtype,
                   entity, npn, amount, entity_from, npn_from, needs_reconfirm
            FROM coherence.review_queue_items WHERE journal_seq = $1
            ORDER BY attempt_event_id::text COLLATE "C", item_order ASC`;
  }
  if (tbl === 'statement_agency_lines') {
    return `SELECT * FROM coherence.statement_agency_lines WHERE journal_seq = $1
            ORDER BY batch_id::text COLLATE "C", line_no ASC`;
  }
  if (tbl === 'statement_upline_lines') {
    return `SELECT * FROM coherence.statement_upline_lines WHERE journal_seq = $1
            ORDER BY batch_id::text COLLATE "C", line_no ASC`;
  }
  if (tbl === 'bob_policies') {
    return `SELECT * FROM coherence.bob_policies WHERE journal_seq = $1
            ORDER BY attempt_event_id::text COLLATE "C", policy_id ASC`;
  }
  if (tbl === 'bob_policy_financials') {
    return `SELECT * FROM coherence.bob_policy_financials WHERE journal_seq = $1
            ORDER BY attempt_event_id::text COLLATE "C", policy_id ASC`;
  }
  if (tbl === 'coherent_ledger_rows') {
    return `SELECT * FROM coherence.coherent_ledger_rows WHERE journal_seq = $1
            ORDER BY attempt_event_id::text COLLATE "C", tx_id ASC`;
  }
  if (tbl === 'imported_files') {
    return `SELECT id, area, rel_path, artifact_kind, store_kind, file_sha256,
                   CASE WHEN original_at IS NULL THEN NULL ELSE coherence.format_utc_us(original_at) END AS original_at,
                   metadata
            FROM coherence.imported_files WHERE journal_seq = $1 ORDER BY id::text COLLATE "C"`;
  }
  return `SELECT * FROM coherence.${tbl} WHERE journal_seq = $1`;
}

/**
 * Exports the company journal as deterministic NDJSON (one line per seq 1..N, or up to upToSeq)
 * including all child business rows attached to each entry.
 */
export async function exportJournalNdjson(pool, { upToSeq = null } = {}) {
  const cap = upToSeq != null ? String(upToSeq) : '9223372036854775807';
  const entriesRes = await pool.query(
    `SELECT seq, coherence.format_utc_us(recorded_at) AS recorded_at, actor, acting_for, command_kind, command_key, request_sha256, body, prev_hash, entry_hash
     FROM coherence.journal_entries
     WHERE seq <= $1::bigint
     ORDER BY seq ASC`,
    [cap],
  );

  const lines = [];
  for (const je of entriesRes.rows) {
    const seq = Number(je.seq);
    const records = {};
    for (const tbl of EXPORT_TABLE_ORDER) {
      const res = await pool.query(selectQueryForTable(tbl), [String(seq)]);
      if (res.rows.length > 0) {
        records[tbl] = res.rows.map(normalizeExportRow);
      }
    }
    lines.push(JSON.stringify({
      seq,
      recorded_at: formatTimestampUtcUs(je.recorded_at),
      actor: je.actor,
      acting_for: je.acting_for ?? null,
      command_kind: je.command_kind,
      command_key: je.command_key,
      request_sha256: je.request_sha256,
      prev_hash: je.prev_hash,
      entry_hash: je.entry_hash,
      body: je.body,
      records,
    }));
  }
  return `${lines.join('\n')}${lines.length ? '\n' : ''}`;
}

/**
 * Rebuilds an empty migrated database from a journal NDJSON export (optionally up to upToSeq),
 * supplying exact seq, recorded_at, prev_hash, and entry_hash so triggers verify every hash and commitment.
 */
export async function rebuildFromJournalExport(pool, ndjsonText, { upToSeq = null } = {}) {
  const lines = String(ndjsonText || '').split('\n').filter((line) => line.trim().length > 0);
  const client = await pool.connect();
  let slotHeld = false;
  let replayed = 0;

  const acquireSlot = async () => {
    if (slotHeld) return;
    const res = await client.query('SELECT pg_catalog.pg_try_advisory_lock(coherence.slot_class_id(), coherence.slot_obj_id()) AS ok');
    if (!res.rows[0]?.ok) throw new Error('Could not acquire company slot for journal rebuild.');
    slotHeld = true;
  };
  const releaseSlot = async () => {
    if (!slotHeld) return;
    await client.query('SELECT pg_catalog.pg_advisory_unlock(coherence.slot_class_id(), coherence.slot_obj_id())');
    slotHeld = false;
  };

  try {
    for (const line of lines) {
      const entry = JSON.parse(line);
      if (upToSeq != null && Number(entry.seq) > Number(upToSeq)) break;
      const recs = entry.records || {};
      const evs = recs.step_attempt_events || [];
      const needsFreeSlot = evs.some((e) => e.event_kind === 'interrupted');
      const needsSlot = evs.some((e) => ['started', 'finished', 'failed', 'cancelled'].includes(e.event_kind))
        && entry.command_kind !== 'import_historical_run';

      if (needsFreeSlot) await releaseSlot();
      else if (needsSlot) await acquireSlot();

      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      try {
        await client.query(
          `INSERT INTO coherence.journal_entries (
             seq, recorded_at, actor, acting_for, command_kind, command_key, request_sha256, body, prev_hash, entry_hash
           ) VALUES ($1, $2::timestamptz, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)`,
          [
            String(entry.seq), entry.recorded_at, entry.actor, entry.acting_for,
            entry.command_kind, entry.command_key, entry.request_sha256,
            JSON.stringify(entry.body), entry.prev_hash, entry.entry_hash,
          ],
        );

        const seqStr = String(entry.seq);

        for (const r of recs.company_meta || []) {
          await client.query(
            `INSERT INTO coherence.company_meta (
               singleton, company_slug, display_name, default_emit_mode,
               default_emit_display, default_emit_keep, default_emit_no_manager, journal_seq
             ) VALUES (true, $1, $2, $3, $4, $5::text[], $6::text[], $7)`,
            [r.company_slug, r.display_name, r.default_emit_mode, r.default_emit_display, r.default_emit_keep, r.default_emit_no_manager, seqStr],
          );
        }

        for (const r of recs.stored_files || []) {
          await client.query(
            `INSERT INTO coherence.stored_files (store_kind, sha256, byte_size, md5_b64, crc32c_b64, object_name, journal_seq)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [r.store_kind, r.sha256, String(r.byte_size), r.md5_b64, r.crc32c_b64, r.object_name, seqStr],
          );
        }

        for (const r of recs.engine_versions || []) {
          await client.query(
            `INSERT INTO coherence.engine_versions (
               id, label, coherence_commit, engine_kind, upstream_commit, patch_diff_sha256, store_kind,
               git_bundle_sha256, code_manifest_sha256, python_lock_sha256, python_wheels_sha256,
               web_lock_sha256, web_packages_sha256, wrapper_bundle_sha256,
               nusear_commit, company_emit_sha256, pages_law_sha256, overlay_check_sha256,
               toolchain, container_digest, journal_seq
             ) VALUES ($1::uuid, $2, $3, $4, $5, $6, 'nusear_code', $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18::jsonb, $19, $20)`,
            [
              r.id, r.label, r.coherence_commit, r.engine_kind ?? 'legacy_sealed',
              r.upstream_commit ?? null, r.patch_diff_sha256 ?? null,
              r.git_bundle_sha256, r.code_manifest_sha256, r.python_lock_sha256, r.python_wheels_sha256,
              r.web_lock_sha256 ?? null, r.web_packages_sha256 ?? null, r.wrapper_bundle_sha256,
              r.nusear_commit, r.company_emit_sha256 ?? null, r.pages_law_sha256 ?? null, r.overlay_check_sha256,
              JSON.stringify(r.toolchain), r.container_digest ?? null, seqStr,
            ],
          );
        }

        for (const r of recs.approvals_files || []) {
          await client.query(
            `INSERT INTO coherence.approvals_files (
               file_sha256, store_kind, header_kind, row_count, extends_sha256, shared_row_count, added_rows_sha256, journal_seq
             ) VALUES ($1, 'company_data', $2, $3, $4, $5, $6, $7)`,
            [r.file_sha256, r.header_kind, r.row_count, r.extends_sha256, r.shared_row_count, r.added_rows_sha256, seqStr],
          );
        }

        for (const r of recs.approval_rows || []) {
          await client.query(
            `INSERT INTO coherence.approval_rows (
               approvals_file_sha256, row_no, record_id, disposition, agent, agency, policy, book, month, status, note,
               committed_at, approved_amount, approved_agency, approved_agent, approved_agency_from, approved_agent_from, journal_seq
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
            [
              r.approvals_file_sha256, r.row_no, r.record_id, r.disposition, r.agent, r.agency, r.policy, r.book,
              r.month, r.status, r.note, r.committed_at, r.approved_amount, r.approved_agency, r.approved_agent,
              r.approved_agency_from, r.approved_agent_from, seqStr,
            ],
          );
        }

        for (const r of recs.decision_commits || []) {
          await client.query(
            `INSERT INTO coherence.decision_commits (
               id, parent_commit_id, commit_kind, header_contract,
               added_decision_count, cumulative_decision_count, added_decisions_sha256,
               imported, original_at, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10)`,
            [
              r.id, r.parent_commit_id ?? null, r.commit_kind, r.header_contract ?? 'v2',
              r.added_decision_count, r.cumulative_decision_count, r.added_decisions_sha256,
              Boolean(r.imported), r.original_at ?? null, seqStr,
            ],
          );
        }

        for (const r of recs.input_versions || []) {
          await client.query(
            `INSERT INTO coherence.input_versions (
               id, line_kind, parent_id, source_kind, reason,
               entry_count, entries_sha256, entries_list_file_sha256,
               change_count, changes_sha256, store_kind, journal_seq
             ) VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10, 'company_data', $11)`,
            [
              r.id, r.line_kind, r.parent_id, r.source_kind, r.reason,
              r.entry_count, r.entries_sha256, r.entries_list_file_sha256 ?? null,
              r.change_count, r.changes_sha256, seqStr,
            ],
          );
        }

        for (const r of recs.input_entries || []) {
          await client.query(
            `INSERT INTO coherence.input_entries (input_version_id, rel_path, store_kind, file_sha256, journal_seq)
             VALUES ($1::uuid, $2, 'company_data', $3, $4)`,
            [r.input_version_id, r.rel_path, r.file_sha256, seqStr],
          );
        }

        for (const r of recs.input_changes || []) {
          await client.query(
            `INSERT INTO coherence.input_changes (input_version_id, rel_path, change_kind, old_rel_path, store_kind, file_sha256, prev_file_sha256, journal_seq)
             VALUES ($1::uuid, $2, $3, $4, 'company_data', $5, $6, $7)`,
            [r.input_version_id, r.rel_path, r.change_kind, r.old_rel_path, r.file_sha256, r.prev_file_sha256, seqStr],
          );
        }

        for (const r of recs.runs || []) {
          await client.query(
            `INSERT INTO coherence.runs (
               id, statement_date, folder_number, origin, input_version_id, prior_approvals_sha256,
               prior_decision_commit_id, engine_version_id, emit_mode, emit_display, emit_keep, emit_no_manager,
               replays_run_id, compared_run_id, rerun_reason, source_folder, journal_seq
             ) VALUES ($1::uuid, $2::date, $3, $4, $5::uuid, $6, $7::uuid, $8::uuid, $9, $10, $11::text[], $12::text[], $13::uuid, $14::uuid, $15, $16, $17)`,
            [
              r.id, r.statement_date, r.folder_number, r.origin, r.input_version_id, r.prior_approvals_sha256 ?? null,
              r.prior_decision_commit_id ?? null, r.engine_version_id ?? null, r.emit_mode, r.emit_display,
              r.emit_keep, r.emit_no_manager, r.replays_run_id ?? null, r.compared_run_id ?? null,
              r.rerun_reason ?? null, r.source_folder ?? null, seqStr,
            ],
          );
        }

        for (const r of recs.cancel_requests || []) {
          await client.query(
            `INSERT INTO coherence.cancel_requests (id, run_id, step, attempt_no, typed_phrase, reason, journal_seq)
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)`,
            [r.id, r.run_id, r.step, r.attempt_no, r.typed_phrase, r.reason, seqStr],
          );
        }

        const nonSupersededEvs = evs.filter((e) => e.event_kind !== 'superseded');
        const supersededEvs = evs.filter((e) => e.event_kind === 'superseded');

        const insertEv = async (r) => {
          await client.query(
            `INSERT INTO coherence.step_attempt_events (
               id, run_id, step, attempt_no, event_kind, step_request_id, cancel_request_id,
               census, born, log_store_kind, log_file_sha256, error_summary,
               artifact_count, artifacts_sha256, original_at, journal_seq
             ) VALUES (
               $1::uuid, $2::uuid, $3, $4, $5, $6::uuid, $7::uuid,
               $8::jsonb, $9, $10, $11, $12, $13, $14, $15::timestamptz, $16
             )`,
            [
              r.id, r.run_id, r.step, r.attempt_no, r.event_kind, r.step_request_id ?? null, r.cancel_request_id ?? null,
              r.census ? JSON.stringify(r.census) : null, r.born ?? null,
              r.log_store_kind ?? null, r.log_file_sha256 ?? null, r.error_summary ?? null,
              r.artifact_count ?? null, r.artifacts_sha256 ?? null, r.original_at ?? null, seqStr,
            ],
          );
        };

        for (const r of nonSupersededEvs) await insertEv(r);

        for (const r of recs.artifacts || []) {
          await client.query(
            `INSERT INTO coherence.artifacts (attempt_event_id, rel_path, artifact_kind, store_kind, file_sha256, journal_seq)
             VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
            [r.attempt_event_id, r.rel_path, r.artifact_kind, r.store_kind, r.file_sha256, seqStr],
          );
        }

        for (const r of recs.review_queue_items || []) {
          await client.query(
            `INSERT INTO coherence.review_queue_items (
               attempt_event_id, item_order, run_id, surface, record_id,
               case_kind, subtype, entity, npn, amount, entity_from, npn_from, needs_reconfirm, journal_seq
             ) VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
            [
              r.attempt_event_id, r.item_order, r.run_id, r.surface, r.record_id,
              r.case_kind ?? null, r.subtype ?? null, r.entity ?? null, r.npn ?? null, r.amount ?? null,
              r.entity_from ?? null, r.npn_from ?? null, Boolean(r.needs_reconfirm), seqStr,
            ],
          );
        }

        for (const r of recs.review_saves || []) {
          await client.query(
            `INSERT INTO coherence.review_saves (
               id, run_id, surface, attempt_event_id, approvals_file_sha256, decision_commit_id,
               imported, original_at, submission_id, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6::uuid, $7, $8::timestamptz, $9::uuid, $10)`,
            [
              r.id, r.run_id, r.surface, r.attempt_event_id, r.approvals_file_sha256 ?? null,
              r.decision_commit_id ?? null, r.imported, r.original_at ?? null, r.submission_id ?? null, seqStr,
            ],
          );
        }

        for (const r of recs.decisions || []) {
          await client.query(
            `INSERT INTO coherence.decisions (
               id, decision_commit_id, row_order, run_id, review_save_id, surface, record_id,
               replaces_decision_id, disposition, agent, agency, policy, book, month, status, note,
               approved_amount, approved_agency, approved_agent, approved_agency_from, approved_agent_from,
               decided_by, acting_for, decided_at, committed_at_raw, imported, journal_seq
             ) VALUES (
               $1::uuid, $2::uuid, $3, $4::uuid, $5::uuid, $6, $7,
               $8::uuid, $9, $10, $11, $12, $13, $14, $15, $16,
               $17, $18, $19, $20, $21,
               $22, $23, $24::timestamptz, $25, $26, $27
             )`,
            [
              r.id, r.decision_commit_id, r.row_order, r.run_id ?? null, r.review_save_id ?? null, r.surface ?? null,
              r.record_id, r.replaces_decision_id ?? null, r.disposition,
              r.agent ?? null, r.agency ?? null, r.policy ?? null, r.book ?? null, r.month ?? null,
              r.status ?? null, r.note ?? null,
              r.approved_amount ?? null, r.approved_agency ?? null, r.approved_agent ?? null,
              r.approved_agency_from ?? null, r.approved_agent_from ?? null,
              r.decided_by, r.acting_for ?? null, r.decided_at, r.committed_at_raw ?? null, Boolean(r.imported), seqStr,
            ],
          );
        }

        for (const r of recs.generated_overlays || []) {
          await client.query(
            `INSERT INTO coherence.generated_overlays (
               id, decision_commit_id, run_id, purpose, attempt_event_id, header_contract,
               row_count, store_kind, file_sha256, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6, $7, 'company_data', $8, $9)`,
            [
              r.id, r.decision_commit_id, r.run_id, r.purpose, r.attempt_event_id ?? null,
              r.header_contract, r.row_count, r.file_sha256, seqStr,
            ],
          );
        }

        for (const r of recs.emit_confirmations || []) {
          await client.query(
            `INSERT INTO coherence.emit_confirmations (id, run_id, adjust_review_save_id, typed_phrase, journal_seq)
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)`,
            [r.id, r.run_id, r.adjust_review_save_id, r.typed_phrase, seqStr],
          );
        }

        for (const r of supersededEvs) await insertEv(r);

        for (const r of recs.step_requests || []) {
          await client.query(
            `INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
             VALUES ($1::uuid, $2::uuid, $3, $4, $5::uuid, $6)`,
            [r.id, r.run_id, r.step, r.reason, r.emit_confirmation_id ?? null, seqStr],
          );
        }

        for (const r of recs.statement_batches || []) {
          await client.query(
            `INSERT INTO coherence.statement_batches (
               id, batch_kind, statement_date, run_id, attempt_event_id,
               source_file_name, source_store_kind, source_file_sha256, reason,
               agency_line_count, agency_lines_sha256, agency_net_total,
               upline_line_count, upline_lines_sha256, upline_net_total, journal_seq
             ) VALUES (
               $1::uuid, $2, $3::date, $4::uuid, $5::uuid,
               $6, $7, $8, $9,
               $10, $11, $12::numeric(14,2),
               $13, $14, $15::numeric(14,2), $16
             )`,
            [
              r.id, r.batch_kind, r.statement_date, r.run_id ?? null, r.attempt_event_id ?? null,
              r.source_file_name ?? null, r.source_store_kind ?? null, r.source_file_sha256 ?? null, r.reason,
              r.agency_line_count, r.agency_lines_sha256, r.agency_net_total,
              r.upline_line_count, r.upline_lines_sha256, r.upline_net_total, seqStr,
            ],
          );
        }

        for (const r of recs.statement_agency_lines || []) {
          await client.query(
            `INSERT INTO coherence.statement_agency_lines (
               batch_id, line_no, statement_date, entry_kind, run_action, entity,
               writing_npn, writing_agent, record_id, reversal_of, corrects_record_id,
               source_file, sheet_name, source_row_no, src_type, carrier, mbi, member,
               external_policy_id, policy_id, tx_id, plan_type, simple_plan_type, state,
               submission_date, origin_effective, effective_date, termination_date,
               earned_date, payment_date, posted_statement_date, revenue_type,
               gross_comm, amount, reason, notes, journal_seq
             ) VALUES (
               $1::uuid, $2, $3::date, $4, $5, $6,
               $7, $8, $9, $10, $11,
               $12, $13, $14, $15, $16, $17, $18,
               $19, $20, $21, $22, $23, $24,
               $25::date, $26::date, $27::date, $28::date,
               $29::date, $30::date, $31::date, $32,
               $33::numeric(14,2), $34::numeric(14,2), $35, $36, $37
             )`,
            [
              r.batch_id, r.line_no, r.statement_date, r.entry_kind, r.run_action, r.entity,
              r.writing_npn ?? null, r.writing_agent ?? null, r.record_id, r.reversal_of ?? null, r.corrects_record_id ?? null,
              r.source_file, r.sheet_name ?? null, r.source_row_no, r.src_type ?? null, r.carrier ?? null,
              r.mbi ?? null, r.member ?? null, r.external_policy_id ?? null, r.policy_id ?? null, r.tx_id ?? null,
              r.plan_type ?? null, r.simple_plan_type ?? null, r.state ?? null,
              r.submission_date ?? null, r.origin_effective ?? null, r.effective_date ?? null, r.termination_date ?? null,
              r.earned_date ?? null, r.payment_date ?? null, r.posted_statement_date ?? null, r.revenue_type ?? null,
              r.gross_comm, r.amount, r.reason ?? null, r.notes ?? null, seqStr,
            ],
          );
        }

        for (const r of recs.statement_upline_lines || []) {
          await client.query(
            `INSERT INTO coherence.statement_upline_lines (
               batch_id, line_no, statement_date, entry_kind, run_action, source_entity, marked_sent,
               writing_npn, writing_agent, record_id, reversal_of, corrects_record_id,
               source_file, sheet_name, source_row_no, src_type, carrier, mbi, member,
               external_policy_id, policy_id, tx_id, plan_type, simple_plan_type, state,
               submission_date, origin_effective, effective_date, termination_date,
               earned_date, payment_date, posted_statement_date, revenue_type,
               gross_comm, amount, reason, notes, journal_seq
             ) VALUES (
               $1::uuid, $2, $3::date, $4, $5, $6, $7,
               $8, $9, $10, $11, $12,
               $13, $14, $15, $16, $17, $18, $19,
               $20, $21, $22, $23, $24, $25,
               $26::date, $27::date, $28::date, $29::date,
               $30::date, $31::date, $32::date, $33,
               $34::numeric(14,2), $35::numeric(14,2), $36, $37, $38
             )`,
            [
              r.batch_id, r.line_no, r.statement_date, r.entry_kind, r.run_action, r.source_entity, Boolean(r.marked_sent),
              r.writing_npn ?? null, r.writing_agent ?? null, r.record_id, r.reversal_of ?? null, r.corrects_record_id ?? null,
              r.source_file, r.sheet_name ?? null, r.source_row_no, r.src_type ?? null, r.carrier ?? null,
              r.mbi ?? null, r.member ?? null, r.external_policy_id ?? null, r.policy_id ?? null, r.tx_id ?? null,
              r.plan_type ?? null, r.simple_plan_type ?? null, r.state ?? null,
              r.submission_date ?? null, r.origin_effective ?? null, r.effective_date ?? null, r.termination_date ?? null,
              r.earned_date ?? null, r.payment_date ?? null, r.posted_statement_date ?? null, r.revenue_type ?? null,
              r.gross_comm, r.amount, r.reason ?? null, r.notes ?? null, seqStr,
            ],
          );
        }

        for (const r of recs.run_materializations || []) {
          await client.query(
            `INSERT INTO coherence.run_materializations (
               attempt_event_id, run_id, statement_date, reconciliation_mode,
               bob_row_count, bob_rows_sha256, bob_downline_total, bob_upline_total,
               ledger_row_count, ledger_rows_sha256, ledger_gross_total, ledger_downline_total, ledger_upline_total,
               statement_batch_id, corpus_tail, agency_start, journal_seq
             ) VALUES (
               $1::uuid, $2::uuid, $3::date, $4,
               $5, $6, $7::numeric(14,2), $8::numeric(14,2),
               $9, $10, $11::numeric(14,2), $12::numeric(14,2), $13::numeric(14,2),
               $14::uuid, $15, $16::date, $17
             )`,
            [
              r.attempt_event_id, r.run_id, r.statement_date, r.reconciliation_mode ?? 'strict_entity_ledger',
              r.bob_row_count, r.bob_rows_sha256, r.bob_downline_total, r.bob_upline_total,
              r.ledger_row_count, r.ledger_rows_sha256, r.ledger_gross_total, r.ledger_downline_total, r.ledger_upline_total,
              r.statement_batch_id, r.corpus_tail ?? null, r.agency_start ?? null, seqStr,
            ],
          );
        }

        for (const r of recs.bob_policies || []) {
          await client.query(
            `INSERT INTO coherence.bob_policies (
               attempt_event_id, policy_id, run_id, external_policy_id, carrier_policy_number, crm_policy_number,
               carrier, plan_type, plan_name, simple_plan_type, mbi, member, dob, phone, email, address, county, state,
               submission_date, origin_effective, effective_date, termination_date,
               writing_npn, writing_agent, entity, status, coherent_status, journal_seq
             ) VALUES (
               $1::uuid, $2, $3::uuid, $4, $5, $6,
               $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
               $19::date, $20::date, $21::date, $22::date,
               $23, $24, $25, $26, $27, $28
             )`,
            [
              r.attempt_event_id, r.policy_id, r.run_id, r.external_policy_id ?? null,
              r.carrier_policy_number ?? null, r.crm_policy_number ?? null,
              r.carrier ?? null, r.plan_type ?? null, r.plan_name ?? null, r.simple_plan_type ?? null,
              r.mbi ?? null, r.member ?? null, r.dob ?? null, r.phone ?? null, r.email ?? null,
              r.address ?? null, r.county ?? null, r.state ?? null,
              r.submission_date ?? null, r.origin_effective ?? null, r.effective_date ?? null, r.termination_date ?? null,
              r.writing_npn ?? null, r.writing_agent ?? null, r.entity, r.status ?? null, r.coherent_status ?? null, seqStr,
            ],
          );
        }

        for (const r of recs.bob_policy_financials || []) {
          await client.query(
            `INSERT INTO coherence.bob_policy_financials (
               attempt_event_id, policy_id, entity, writing_npn, amount, upline_amount,
               enrollment_code, min_date, anchor_date, agency_id, conflicts,
               spine_source, confidence_level, coherent_trajectory, journal_seq
             ) VALUES (
               $1::uuid, $2, $3, $4, $5::numeric(14,2), $6::numeric(14,2),
               $7, $8::date, $9::date, $10, $11,
               $12, $13, $14::jsonb, $15
             )`,
            [
              r.attempt_event_id, r.policy_id, r.entity, r.writing_npn ?? null,
              r.amount ?? null, r.upline_amount ?? null,
              r.enrollment_code ?? null, r.min_date ?? null, r.anchor_date ?? null,
              r.agency_id ?? null, r.conflicts ?? null, r.spine_source ?? null,
              r.confidence_level ?? null, r.coherent_trajectory != null ? JSON.stringify(r.coherent_trajectory) : null, seqStr,
            ],
          );
        }

        for (const r of recs.coherent_ledger_rows || []) {
          await client.query(
            `INSERT INTO coherence.coherent_ledger_rows (
               attempt_event_id, tx_id, run_id, record_id, external_policy_id, policy_id,
               statement_name, src_type, carrier, mbi, member, state, plan_type, simple_plan_type,
               submission_date, origin_effective, effective_date, termination_date,
               earned_date, payment_date, statement_date, min_date,
               gross_comm, revenue_type, override_amount, commission_amount, hra_amount, fee_amount, other_amount,
               downline_amount, upline_amount, writing_npn, writing_agent, entity, payee_npn, agency_id,
               status, policy_status, cbob_c, cbob_s, sf, notes, coherent_notes, sheet_name, source_row_no, journal_seq
             ) VALUES (
               $1::uuid, $2, $3::uuid, $4, $5, $6,
               $7, $8, $9, $10, $11, $12, $13, $14,
               $15::date, $16::date, $17::date, $18::date,
               $19::date, $20::date, $21::date, $22::date,
               $23::numeric(14,2), $24, $25::numeric(14,2), $26::numeric(14,2), $27::numeric(14,2), $28::numeric(14,2), $29::numeric(14,2),
               $30::numeric(14,2), $31::numeric(14,2), $32, $33, $34, $35, $36,
               $37, $38, $39, $40, $41, $42, $43, $44, $45, $46
             )`,
            [
              r.attempt_event_id, r.tx_id, r.run_id, r.record_id, r.external_policy_id ?? null, r.policy_id ?? null,
              r.statement_name ?? null, r.src_type, r.carrier ?? null, r.mbi ?? null, r.member ?? null,
              r.state ?? null, r.plan_type ?? null, r.simple_plan_type ?? null,
              r.submission_date ?? null, r.origin_effective ?? null, r.effective_date ?? null, r.termination_date ?? null,
              r.earned_date ?? null, r.payment_date ?? null, r.statement_date ?? null, r.min_date ?? null,
              r.gross_comm, r.revenue_type ?? null,
              r.override_amount ?? null, r.commission_amount ?? null, r.hra_amount ?? null,
              r.fee_amount ?? null, r.other_amount ?? null,
              r.downline_amount, r.upline_amount,
              r.writing_npn ?? null, r.writing_agent ?? null, r.entity, r.payee_npn ?? null, r.agency_id ?? null,
              r.status ?? null, r.policy_status ?? null,
              Boolean(r.cbob_c), Boolean(r.cbob_s), Boolean(r.sf),
              r.notes ?? null, r.coherent_notes ?? null, r.sheet_name ?? null, r.source_row_no ?? null, seqStr,
            ],
          );
        }

        for (const r of recs.carries || []) {
          await client.query(
            `INSERT INTO coherence.carries (
               id, run_id, statement_date, carry_kind, store_kind, file_sha256,
               carried_decision_commit_id, published_input_version_id, nothing_new, typed_phrase, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3::date, $4, $5, $6, $7::uuid, $8::uuid, $9, $10, $11)`,
            [
              r.id, r.run_id, r.statement_date, r.carry_kind,
              r.file_sha256 ? 'company_data' : null, r.file_sha256 ?? null,
              r.carried_decision_commit_id ?? null, r.published_input_version_id ?? null,
              Boolean(r.nothing_new), r.typed_phrase, seqStr,
            ],
          );
        }

        for (const r of recs.abandonments || []) {
          await client.query(
            `INSERT INTO coherence.abandonments (id, run_id, typed_phrase, reason, journal_seq)
             VALUES ($1::uuid, $2::uuid, $3, $4, $5)`,
            [r.id, r.run_id, r.typed_phrase, r.reason, seqStr],
          );
        }

        for (const r of recs.imported_files || []) {
          await client.query(
            `INSERT INTO coherence.imported_files (
               id, area, rel_path, artifact_kind, store_kind, file_sha256, original_at, metadata, journal_seq
             ) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::timestamptz, $8::jsonb, $9)`,
            [r.id, r.area, r.rel_path, r.artifact_kind, r.store_kind, r.file_sha256, r.original_at ?? null, JSON.stringify(r.metadata || {}), seqStr],
          );
        }

        for (const r of recs.checks || []) {
          await client.query(
            `INSERT INTO coherence.checks (id, check_kind, run_id, compared_run_id, passed, report, journal_seq)
             VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5, $6::jsonb, $7)`,
            [r.id, r.check_kind, r.run_id ?? null, r.compared_run_id ?? null, r.passed, JSON.stringify(r.report), seqStr],
          );
        }

        await client.query('COMMIT');
        replayed += 1;
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      }
    }
    return { replayed };
  } finally {
    await releaseSlot().catch(() => {});
    client.release();
  }
}

export async function verifyChain(pool) {
  const res = await pool.query(
    `SELECT seq, coherence.format_utc_us(recorded_at) AS recorded_at, actor, acting_for, command_kind, command_key, request_sha256, body, prev_hash, entry_hash
     FROM coherence.journal_entries ORDER BY seq ASC`,
  );
  const problems = [];
  let expectedSeq = 1;
  let expectedPrevHash = GENESIS_HASH;
  let prevTime = null;

  for (const row of res.rows) {
    const seq = Number(row.seq);
    const recordedAt = formatTimestampUtcUs(row.recorded_at);
    if (seq !== expectedSeq) problems.push(`seq gap at ${seq} (expected ${expectedSeq})`);
    if (row.prev_hash !== expectedPrevHash) problems.push(`prev_hash mismatch at seq ${seq}`);
    if (prevTime !== null && recordedAt < prevTime) problems.push(`timestamp regressed at seq ${seq}: ${recordedAt} < ${prevTime}`);
    const recomputed = computeJournalHash({
      seq,
      recordedAt,
      actor: row.actor,
      actingFor: row.acting_for ?? null,
      commandKind: row.command_kind,
      commandKey: row.command_key,
      requestSha256: row.request_sha256,
      prevHash: row.prev_hash,
      body: row.body,
    });
    if (recomputed !== row.entry_hash) problems.push(`entry_hash mismatch at seq ${seq}`);
    expectedSeq = seq + 1;
    expectedPrevHash = row.entry_hash;
    prevTime = recordedAt;
  }

  return { passed: problems.length === 0, entries: res.rows.length, headHash: expectedPrevHash, problems };
}

export async function verifyCommitments(pool) {
  const entriesRes = await pool.query('SELECT seq, body FROM coherence.journal_entries ORDER BY seq ASC');
  const problems = [];

  for (const je of entriesRes.rows) {
    const seq = Number(je.seq);
    const declared = je.body?.commitments;
    if (!declared || typeof declared !== 'object') {
      problems.push(`seq ${seq}: missing commitments object`);
      continue;
    }
    const tables = {};
    for (const tbl of BUSINESS_TABLES) {
      const res = await pool.query(selectQueryForTable(tbl), [String(seq)]);
      if (res.rows.length > 0) tables[tbl] = res.rows;
    }
    const actual = buildCommitments(tables);
    for (const tbl of BUSINESS_TABLES) {
      const decCount = Number(declared.counts?.[tbl] ?? 0);
      const actCount = Number(actual.counts[tbl] ?? 0);
      if (decCount !== actCount) {
        problems.push(`seq ${seq}: ${tbl} count mismatch (declared ${decCount}, actual ${actCount})`);
      }
      if (actCount > 0 && actual.hashes[tbl] && declared.hashes?.[tbl] !== actual.hashes[tbl]) {
        problems.push(`seq ${seq}: ${tbl} hash mismatch`);
      }
    }
  }
  return { passed: problems.length === 0, checkedEntries: entriesRes.rows.length, problems };
}

export async function verifyObjects(pool, stores, { deep = false } = {}) {
  const res = await pool.query(
    'SELECT store_kind, sha256, byte_size, md5_b64, crc32c_b64, object_name FROM coherence.stored_files ORDER BY store_kind, sha256',
  );
  const problems = [];
  for (const row of res.rows) {
    const check = await stores.verifyObject({
      storeKind: row.store_kind,
      sha256: row.sha256,
      byteSize: Number(row.byte_size),
      md5B64: row.md5_b64,
      crc32cB64: row.crc32c_b64,
      objectName: row.object_name,
    }, { deep });
    if (!check.ok) problems.push(`${row.store_kind}/${row.sha256}: ${check.reason}`);
  }

  const badArts = await pool.query(
    `SELECT attempt_event_id, rel_path, artifact_kind, store_kind
     FROM coherence.artifacts
     WHERE store_kind = 'company_data'`,
  );
  for (const art of badArts.rows) {
    if (isCodeBearingPath(art.rel_path) || art.artifact_kind === 'code_bearing') {
      problems.push(`code-bearing artifact ${art.rel_path} stored in company_data`);
    }
  }

  return { passed: problems.length === 0, checkedObjects: res.rows.length, problems };
}
