import {
  computeJournalHash,
  formatTimestampUtcUs,
  GENESIS_HASH,
} from '../util/crypto.mjs';
import { isCodeBearingPath } from '../storage/artifact-policy.mjs';
import { buildCommitments, BUSINESS_TABLES } from './commitments.mjs';

const EXPORT_TABLE_ORDER = [
  'company_meta',
  'stored_files',
  'engine_versions',
  'approvals_files',
  'approval_rows',
  'input_versions',
  'input_entries',
  'input_changes',
  'runs',
  'step_requests',
  'cancel_requests',
  'step_attempt_events',
  'artifacts',
  'review_saves',
  'emit_confirmations',
  'carries',
  'abandonments',
  'imported_files',
  'checks',
];

function formatDateCol(val) {
  if (val instanceof Date) return val.toISOString().slice(0, 10);
  return String(val).slice(0, 10);
}

/**
 * Exports the company journal as deterministic NDJSON (one line per seq 1..N)
 * including all child business rows attached to each entry.
 */
export async function exportJournalNdjson(pool) {
  const entriesRes = await pool.query(
    `SELECT seq, coherence.format_utc_us(recorded_at) AS recorded_at, actor, acting_for, command_kind, command_key, request_sha256, body, prev_hash, entry_hash
     FROM coherence.journal_entries
     ORDER BY seq ASC`,
  );

  const lines = [];
  for (const je of entriesRes.rows) {
    const seq = Number(je.seq);
    const records = {};
    for (const tbl of EXPORT_TABLE_ORDER) {
      let query;
      if (tbl === 'runs') {
        query = `SELECT id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date, folder_number, origin,
                        input_version_id, prior_approvals_sha256, engine_version_id, emit_mode, emit_display,
                        emit_keep, emit_no_manager, replays_run_id, compared_run_id, rerun_reason, source_folder
                 FROM coherence.runs WHERE journal_seq = $1 ORDER BY id::text COLLATE "C"`;
      } else if (tbl === 'carries') {
        query = `SELECT id, run_id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date, carry_kind,
                        store_kind, file_sha256, published_input_version_id, nothing_new, typed_phrase
                 FROM coherence.carries WHERE journal_seq = $1 ORDER BY id::text COLLATE "C"`;
      } else if (tbl === 'step_attempt_events') {
        query = `SELECT id, run_id, step, attempt_no, event_kind, step_request_id, cancel_request_id,
                        census, born, log_store_kind, log_file_sha256, error_summary,
                        artifact_count, artifacts_sha256, original_at
                 FROM coherence.step_attempt_events WHERE journal_seq = $1
                 ORDER BY CASE event_kind WHEN 'started' THEN 1 WHEN 'finished' THEN 2 WHEN 'failed' THEN 2 WHEN 'interrupted' THEN 2 WHEN 'cancelled' THEN 2 ELSE 3 END,
                          attempt_no ASC, id::text COLLATE "C"`;
      } else if (tbl === 'input_entries') {
        query = `SELECT input_version_id, rel_path, store_kind, file_sha256
                 FROM coherence.input_entries WHERE journal_seq = $1
                 ORDER BY input_version_id::text COLLATE "C", rel_path COLLATE "C"`;
      } else if (tbl === 'approval_rows') {
        query = `SELECT approvals_file_sha256, row_no, record_id, disposition, agent, agency, policy, book, month,
                        status, note, committed_at, approved_amount, approved_agency, approved_agent,
                        approved_agency_from, approved_agent_from
                 FROM coherence.approval_rows WHERE journal_seq = $1
                 ORDER BY approvals_file_sha256 COLLATE "C", row_no ASC`;
      } else {
        query = `SELECT * FROM coherence.${tbl} WHERE journal_seq = $1`;
      }
      const res = await pool.query(query, [String(seq)]);
      if (res.rows.length > 0) {
        records[tbl] = res.rows.map((r) => {
          const clean = { ...r };
          delete clean.journal_seq;
          delete clean.mac_key;
          if (clean.original_at) clean.original_at = formatTimestampUtcUs(clean.original_at);
          if (clean.byte_size !== undefined) clean.byte_size = Number(clean.byte_size);
          return clean;
        });
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
 * Rebuilds an empty migrated database from a journal NDJSON export, supplying exact seq, recorded_at,
 * prev_hash, and entry_hash so database triggers verify every hash and commitment.
 */
export async function rebuildFromJournalExport(pool, ndjsonText) {
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
               id, label, coherence_commit, store_kind,
               git_bundle_sha256, code_manifest_sha256, python_lock_sha256, python_wheels_sha256,
               web_lock_sha256, web_packages_sha256, wrapper_bundle_sha256,
               nusear_commit, company_emit_sha256, pages_law_sha256, overlay_check_sha256,
               toolchain, container_digest, journal_seq
             ) VALUES ($1::uuid, $2, $3, 'nusear_code', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb, $16, $17)`,
            [
              r.id, r.label, r.coherence_commit,
              r.git_bundle_sha256, r.code_manifest_sha256, r.python_lock_sha256, r.python_wheels_sha256,
              r.web_lock_sha256, r.web_packages_sha256, r.wrapper_bundle_sha256,
              r.nusear_commit, r.company_emit_sha256, r.pages_law_sha256, r.overlay_check_sha256,
              JSON.stringify(r.toolchain), r.container_digest, seqStr,
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
               engine_version_id, emit_mode, emit_display, emit_keep, emit_no_manager,
               replays_run_id, compared_run_id, rerun_reason, source_folder, journal_seq
             ) VALUES ($1::uuid, $2::date, $3, $4, $5::uuid, $6, $7::uuid, $8, $9, $10::text[], $11::text[], $12::uuid, $13::uuid, $14, $15, $16)`,
            [
              r.id, r.statement_date, r.folder_number, r.origin, r.input_version_id, r.prior_approvals_sha256,
              r.engine_version_id, r.emit_mode, r.emit_display, r.emit_keep, r.emit_no_manager,
              r.replays_run_id, r.compared_run_id, r.rerun_reason, r.source_folder, seqStr,
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

        // Order matters within a tx:
        // 1. Non-superseded step_attempt_events + artifacts (imports create finished attempts before review_saves)
        // 2. review_saves and emit_confirmations (live Bible re-save creates review_save before superseding prior adjust)
        // 3. superseded step_attempt_events (before bible_saved / retry step_requests)
        // 4. step_requests (after finished/superseded/review_saves/emit_confirmations)
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

        for (const r of recs.review_saves || []) {
          await client.query(
            `INSERT INTO coherence.review_saves (
               id, run_id, surface, attempt_event_id, approvals_file_sha256, imported, original_at, submission_id, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6, $7::timestamptz, $8::uuid, $9)`,
            [r.id, r.run_id, r.surface, r.attempt_event_id, r.approvals_file_sha256, r.imported, r.original_at ?? null, r.submission_id ?? null, seqStr],
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

        for (const r of recs.carries || []) {
          await client.query(
            `INSERT INTO coherence.carries (
               id, run_id, statement_date, carry_kind, store_kind, file_sha256,
               published_input_version_id, nothing_new, typed_phrase, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3::date, $4, 'company_data', $5, $6::uuid, $7, $8, $9)`,
            [r.id, r.run_id, r.statement_date, r.carry_kind, r.file_sha256, r.published_input_version_id ?? null, r.nothing_new, r.typed_phrase, seqStr],
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
      let sql = `SELECT * FROM coherence.${tbl} WHERE journal_seq = $1`;
      if (tbl === 'runs') {
        sql = `SELECT id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date, folder_number, origin,
                      input_version_id, prior_approvals_sha256, engine_version_id, emit_mode, emit_display,
                      emit_keep, emit_no_manager, replays_run_id, compared_run_id, rerun_reason, source_folder
               FROM coherence.runs WHERE journal_seq = $1`;
      } else if (tbl === 'carries') {
        sql = `SELECT id, run_id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date, carry_kind,
                      file_sha256, published_input_version_id, nothing_new, typed_phrase
               FROM coherence.carries WHERE journal_seq = $1`;
      } else if (tbl === 'review_saves') {
        sql = `SELECT id, run_id, surface, attempt_event_id, approvals_file_sha256, imported,
                      CASE WHEN original_at IS NULL THEN NULL ELSE coherence.format_utc_us(original_at) END AS original_at,
                      submission_id
               FROM coherence.review_saves WHERE journal_seq = $1`;
      } else if (tbl === 'imported_files') {
        sql = `SELECT id, area, rel_path, artifact_kind, store_kind, file_sha256,
                      CASE WHEN original_at IS NULL THEN NULL ELSE coherence.format_utc_us(original_at) END AS original_at,
                      metadata
               FROM coherence.imported_files WHERE journal_seq = $1`;
      }
      const res = await pool.query(sql, [String(seq)]);
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
