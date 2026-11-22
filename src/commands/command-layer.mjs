// The command layer: every business change passes through here (R4, R8, R9, R10).
// Enforces authorization, View-As refusal, command_key idempotency, expected_journal_seq concurrency,
// SERIALIZABLE isolation, batched inserts, and cryptographic journal commitments.
import { randomUUID } from 'node:crypto';
import {
  canonicalInputEntriesText,
  computeRequestFingerprint,
  formatTimestampUtcUs,
  hashApprovalRows,
  hashArtifacts,
  hashInputChanges,
  hashInputEntries,
} from '../util/crypto.mjs';
import { assertValidRelPath, findPathClashes, isValidIsoDate, normalizeMacKey } from '../util/csv.mjs';
import { AppError, sanitizeErrorMessage } from '../util/redact.mjs';
import { assertCanWrite } from './authz.mjs';
import { buildCommitments } from './commitments.mjs';

const BATCH_SIZE = 2000;

function mapPgError(error) {
  if (error instanceof AppError) return error;
  const code = error?.code;
  const msg = sanitizeErrorMessage(error, 'Database refused the change.');
  if (code === '23505') return new AppError(msg, 409, 'UNIQUE_VIOLATION');
  if (code === '23514' || code === '22023') return new AppError(msg, 409, 'INVARIANT_VIOLATION');
  if (code === '23503') return new AppError(msg, 409, 'REFERENCE_VIOLATION');
  if (code === '40001') return new AppError('Concurrent change conflicted; retry with current state.', 409, 'SERIALIZATION_FAILURE');
  if (code === '55000') return new AppError(msg, 409, 'STATE_CONFLICT');
  if (code === '42501') return new AppError('Insufficient database privilege for this operation.', 403, 'PRIVILEGE_DENIED');
  return new AppError(msg, 500, 'DB_ERROR');
}

async function filterNewStoredFiles(tx, files) {
  if (!files || files.length === 0) return [];
  // Deduplicate by (storeKind, sha256) within batch first
  const byKey = new Map();
  for (const f of files) {
    const storeKind = f.storeKind ?? f.store_kind;
    const key = `${storeKind}:${f.sha256}`;
    if (!byKey.has(key)) {
      byKey.set(key, {
        storeKind,
        sha256: f.sha256,
        byteSize: Number(f.byteSize ?? f.byte_size),
        md5B64: f.md5B64 ?? f.md5_b64,
        crc32cB64: f.crc32cB64 ?? f.crc32c_b64,
        objectName: f.objectName ?? f.object_name ?? `objects/${f.sha256}`,
      });
    }
  }
  const unique = [...byKey.values()];
  const storeKinds = unique.map((f) => f.storeKind);
  const shas = unique.map((f) => f.sha256);
  const existing = await tx.query(
    `SELECT store_kind, sha256, byte_size, md5_b64, crc32c_b64
     FROM coherence.stored_files
     WHERE (store_kind, sha256) IN (SELECT s, h FROM unnest($1::text[], $2::text[]) AS t(s, h))`,
    [storeKinds, shas],
  );
  const existingMap = new Map(existing.rows.map((r) => [`${r.store_kind}:${r.sha256}`, r]));
  const toInsert = [];
  for (const f of unique) {
    const ex = existingMap.get(`${f.storeKind}:${f.sha256}`);
    if (ex) {
      if (Number(ex.byte_size) !== f.byteSize || ex.md5_b64 !== f.md5B64 || ex.crc32c_b64 !== f.crc32cB64) {
        throw new AppError(`Stored file ${f.sha256} metadata conflicts with existing record.`, 409, 'STORED_FILE_CONFLICT');
      }
    } else {
      toInsert.push(f);
    }
  }
  return toInsert;
}

async function insertStoredFilesBatch(tx, files, journalSeq) {
  for (let i = 0; i < files.length; i += BATCH_SIZE) {
    const chunk = files.slice(i, i + BATCH_SIZE);
    await tx.query(
      `INSERT INTO coherence.stored_files (store_kind, sha256, byte_size, md5_b64, crc32c_b64, object_name, journal_seq)
       SELECT s, h, sz, m, c, o, $7
       FROM unnest($1::text[], $2::text[], $3::bigint[], $4::text[], $5::text[], $6::text[]) AS t(s, h, sz, m, c, o)`,
      [
        chunk.map((f) => f.storeKind),
        chunk.map((f) => f.sha256),
        chunk.map((f) => String(f.byteSize)),
        chunk.map((f) => f.md5B64),
        chunk.map((f) => f.crc32cB64),
        chunk.map((f) => f.objectName),
        String(journalSeq),
      ],
    );
  }
}

async function insertInputEntriesBatch(tx, inputVersionId, entries, journalSeq) {
  for (let i = 0; i < entries.length; i += BATCH_SIZE) {
    const chunk = entries.slice(i, i + BATCH_SIZE);
    await tx.query(
      `INSERT INTO coherence.input_entries (input_version_id, rel_path, store_kind, file_sha256, journal_seq)
       SELECT $1::uuid, p, 'company_data', h, $4
       FROM unnest($2::text[], $3::text[]) AS t(p, h)`,
      [
        inputVersionId,
        chunk.map((e) => e.relPath ?? e.rel_path),
        chunk.map((e) => e.fileSha256 ?? e.file_sha256),
        String(journalSeq),
      ],
    );
  }
}

async function insertInputChangesBatch(tx, inputVersionId, changes, journalSeq) {
  for (let i = 0; i < changes.length; i += BATCH_SIZE) {
    const chunk = changes.slice(i, i + BATCH_SIZE);
    await tx.query(
      `INSERT INTO coherence.input_changes (input_version_id, rel_path, change_kind, old_rel_path, store_kind, file_sha256, prev_file_sha256, journal_seq)
       SELECT $1::uuid, p, k, op, 'company_data', h, ph, $7
       FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) AS t(p, k, op, h, ph)`,
      [
        inputVersionId,
        chunk.map((c) => c.relPath ?? c.rel_path),
        chunk.map((c) => c.changeKind ?? c.change_kind),
        chunk.map((c) => c.oldRelPath ?? c.old_rel_path ?? null),
        chunk.map((c) => c.fileSha256 ?? c.file_sha256 ?? null),
        chunk.map((c) => c.prevFileSha256 ?? c.prev_file_sha256 ?? null),
        String(journalSeq),
      ],
    );
  }
}

async function insertArtifactsBatch(tx, artifacts, journalSeq) {
  for (let i = 0; i < artifacts.length; i += BATCH_SIZE) {
    const chunk = artifacts.slice(i, i + BATCH_SIZE);
    await tx.query(
      `INSERT INTO coherence.artifacts (attempt_event_id, rel_path, artifact_kind, store_kind, file_sha256, journal_seq)
       SELECT e, p, ak, sk, h, $6
       FROM unnest($1::uuid[], $2::text[], $3::text[], $4::text[], $5::text[]) AS t(e, p, ak, sk, h)`,
      [
        chunk.map((a) => a.attemptEventId ?? a.attempt_event_id),
        chunk.map((a) => a.relPath ?? a.rel_path),
        chunk.map((a) => a.artifactKind ?? a.artifact_kind),
        chunk.map((a) => a.storeKind ?? a.store_kind),
        chunk.map((a) => a.fileSha256 ?? a.file_sha256),
        String(journalSeq),
      ],
    );
  }
}

async function insertApprovalRowsBatch(tx, rows, journalSeq) {
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE);
    await tx.query(
      `INSERT INTO coherence.approval_rows (
         approvals_file_sha256, row_no, record_id, disposition, agent, agency, policy, book,
         month, status, note, committed_at, approved_amount, approved_agency, approved_agent,
         approved_agency_from, approved_agent_from, journal_seq
       )
       SELECT af, rn, rid, disp, ag, agy, pol, bk, mo, st, nt, ca, aa, aagy, aag, aagyf, aagf, $18
       FROM unnest(
         $1::text[], $2::integer[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[],
         $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], $14::text[], $15::text[],
         $16::text[], $17::text[]
       ) AS t(af, rn, rid, disp, ag, agy, pol, bk, mo, st, nt, ca, aa, aagy, aag, aagyf, aagf)`,
      [
        chunk.map((r) => r.approvalsFileSha256 ?? r.approvals_file_sha256),
        chunk.map((r) => Number(r.rowNo ?? r.row_no)),
        chunk.map((r) => r.record_id ?? r.recordId),
        chunk.map((r) => r.disposition ?? null),
        chunk.map((r) => r.agent ?? null),
        chunk.map((r) => r.agency ?? null),
        chunk.map((r) => r.policy ?? null),
        chunk.map((r) => r.book ?? null),
        chunk.map((r) => r.month ?? null),
        chunk.map((r) => r.status ?? null),
        chunk.map((r) => r.note ?? null),
        chunk.map((r) => r.committed_at ?? r.committedAt ?? null),
        chunk.map((r) => r.approved_amount ?? r.approvedAmount ?? null),
        chunk.map((r) => r.approved_agency ?? r.approvedAgency ?? null),
        chunk.map((r) => r.approved_agent ?? r.approvedAgent ?? null),
        chunk.map((r) => r.approved_agency_from ?? r.approvedAgencyFrom ?? null),
        chunk.map((r) => r.approved_agent_from ?? r.approvedAgentFrom ?? null),
        String(journalSeq),
      ],
    );
  }
}

/**
 * Computes exact input_changes between parent entries and next entries, respecting explicit renames
 * and auto-detecting byte-identical renames when `detectRenames` is true (R6.5, R11 misdated files).
 */
export function diffInputEntries(parentEntries, nextEntries, { explicitRenames = [], detectRenames = true } = {}) {
  const parentMap = new Map(parentEntries.map((e) => [e.relPath ?? e.rel_path, e.fileSha256 ?? e.file_sha256]));
  const nextMap = new Map(nextEntries.map((e) => [e.relPath ?? e.rel_path, e.fileSha256 ?? e.file_sha256]));

  const changes = [];
  const handledOld = new Set();
  const handledNew = new Set();

  for (const ren of explicitRenames) {
    const oldPath = ren.oldRelPath ?? ren.from;
    const newPath = ren.relPath ?? ren.to;
    const oldSha = parentMap.get(oldPath);
    const newSha = nextMap.get(newPath);
    if (!oldSha || !newSha || oldSha !== newSha) {
      throw new AppError(`Rename from ${oldPath} to ${newPath} must move the exact same bytes (R6.5).`, 400, 'INVALID_RENAME');
    }
    changes.push({ changeKind: 'renamed', relPath: newPath, oldRelPath: oldPath, fileSha256: newSha, prevFileSha256: null });
    handledOld.add(oldPath);
    handledNew.add(newPath);
  }

  const removed = [];
  const added = [];

  for (const [relPath, oldSha] of parentMap) {
    if (handledOld.has(relPath)) continue;
    const newSha = nextMap.get(relPath);
    if (newSha === undefined) {
      removed.push({ relPath, sha: oldSha });
    } else if (newSha !== oldSha && !handledNew.has(relPath)) {
      changes.push({ changeKind: 'replaced', relPath, oldRelPath: null, fileSha256: newSha, prevFileSha256: oldSha });
      handledOld.add(relPath);
      handledNew.add(relPath);
    }
  }

  for (const [relPath, newSha] of nextMap) {
    if (handledNew.has(relPath)) continue;
    if (!parentMap.has(relPath)) {
      added.push({ relPath, sha: newSha });
    }
  }

  if (detectRenames) {
    for (const rem of [...removed]) {
      const idx = added.findIndex((a) => a.sha === rem.sha);
      if (idx >= 0) {
        const match = added.splice(idx, 1)[0];
        removed.splice(removed.indexOf(rem), 1);
        changes.push({ changeKind: 'renamed', relPath: match.relPath, oldRelPath: rem.relPath, fileSha256: match.sha, prevFileSha256: null });
      }
    }
  }

  for (const rem of removed) {
    changes.push({ changeKind: 'removed', relPath: rem.relPath, oldRelPath: null, fileSha256: null, prevFileSha256: rem.sha });
  }
  for (const add of added) {
    changes.push({ changeKind: 'added', relPath: add.relPath, oldRelPath: null, fileSha256: add.sha, prevFileSha256: null });
  }
  return changes;
}

export function createCommandLayer({ pool, companySlug, stores = null }) {
  async function executeJournalCommand({
    client = null,
    actor,
    commandKind,
    commandKey,
    payload = {},
    expectedJournalSeq = null,
    scopeRunId = null,
    scopeStandingLine = false,
    strictGlobalSeq = false,
    maxRetries = 8,
    buildAndWrite,
  }) {
    assertCanWrite(actor, commandKind, { companySlug });
    if (typeof commandKey !== 'string' || commandKey.length === 0 || commandKey.length > 200) {
      throw new AppError('Every command must carry a non-empty commandKey (R10.6).', 400, 'MISSING_COMMAND_KEY');
    }

    const actingFor = actor.actingFor ?? null;
    const requestSha256 = computeRequestFingerprint({
      commandKind,
      actor: actor.id,
      actingFor,
      payload,
    });

    const isExternalClient = Boolean(client);
    const retries = Math.max(1, maxRetries);

    for (let attempt = 1; attempt <= retries; attempt++) {
      const tx = isExternalClient ? client : await pool.connect();
      let destroyOnRelease = false;
      try {
        await tx.query('BEGIN ISOLATION LEVEL SERIALIZABLE');

        // 1. R10.6 idempotency check
        const existingRes = await tx.query(
          `SELECT seq, command_kind, actor, acting_for, request_sha256, body, recorded_at, entry_hash
           FROM coherence.journal_entries
           WHERE command_key = $1`,
          [commandKey],
        );
        if (existingRes.rows.length > 0) {
          const ex = existingRes.rows[0];
          await tx.query('COMMIT');
          if (
            ex.command_kind === commandKind
            && ex.actor === actor.id
            && (ex.acting_for ?? null) === actingFor
            && ex.request_sha256 === requestSha256
          ) {
            return {
              idempotent: true,
              journalSeq: Number(ex.seq),
              recordedAt: formatTimestampUtcUs(ex.recorded_at),
              entryHash: ex.entry_hash,
              body: ex.body,
              result: ex.body.result ?? ex.body,
            };
          }
          throw new AppError(
            'This command key was already used for a different request (kind, actor, acting_for, or content) (R10.6).',
            409,
            'COMMAND_KEY_CONFLICT',
          );
        }

        // 2. R10.5 optimistic concurrency check on expected_journal_seq
        if (expectedJournalSeq !== null && expectedJournalSeq !== undefined) {
          const expected = Number(expectedJournalSeq);
          if (!Number.isInteger(expected) || expected < 0) {
            throw new AppError('expectedJournalSeq must be a non-negative integer.', 400, 'INVALID_JOURNAL_SEQ');
          }
          const maxRes = await tx.query('SELECT COALESCE(pg_catalog.max(seq), 0) AS max_seq FROM coherence.journal_entries');
          const currentMax = Number(maxRes.rows[0].max_seq);
          if (expected > currentMax) {
            throw new AppError('Expected journal position is ahead of the database.', 409, 'STALE_JOURNAL_POSITION');
          }
          if (scopeRunId) {
            const runSeqRes = await tx.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS latest', [scopeRunId]);
            const runLatest = Number(runSeqRes.rows[0].latest);
            if (runLatest > expected) {
              throw new AppError('This run changed since the screen loaded; reload and try again (R10.5).', 409, 'STALE_JOURNAL_POSITION');
            }
          }
          if (scopeStandingLine) {
            const standRes = await tx.query(
              `SELECT COALESCE(pg_catalog.max(journal_seq), 0) AS latest
               FROM coherence.input_versions WHERE line_kind = 'standing'`,
            );
            if (Number(standRes.rows[0].latest) > expected) {
              throw new AppError('The standing input changed since the screen loaded; reload and try again (R10.5).', 409, 'STALE_JOURNAL_POSITION');
            }
          }
          if (strictGlobalSeq && currentMax > expected) {
            throw new AppError('Database state changed since the screen loaded; reload and try again (R10.5).', 409, 'STALE_JOURNAL_POSITION');
          }
        }

        // 3. Build plan and insert journal entry + child rows atomically
        const { journalSeq, recordedAt, entryHash, body, result } = await buildAndWrite(tx, async (entryBody) => {
          const jRes = await tx.query(
            `INSERT INTO coherence.journal_entries (actor, acting_for, command_kind, command_key, request_sha256, body)
             VALUES ($1, $2, $3, $4, $5, $6::jsonb)
             RETURNING seq, recorded_at, entry_hash`,
            [actor.id, actingFor, commandKind, commandKey, requestSha256, JSON.stringify(entryBody)],
          );
          return {
            journalSeq: Number(jRes.rows[0].seq),
            recordedAt: formatTimestampUtcUs(jRes.rows[0].recorded_at),
            entryHash: jRes.rows[0].entry_hash,
          };
        });

        await tx.query('COMMIT');
        return { idempotent: false, journalSeq, recordedAt, entryHash, body, result };
      } catch (err) {
        try {
          await tx.query('ROLLBACK');
        } catch {
          destroyOnRelease = true;
        }
        const retryable = err?.code === '40001'
          || (err?.code === '23505' && ['journal_entries_pkey', 'journal_entries_prev_hash_key', 'journal_entries_command_key_key'].includes(err?.constraint));
        if (retryable && !destroyOnRelease && attempt < retries) {
          continue;
        }
        throw mapPgError(err);
      } finally {
        if (!isExternalClient) tx.release(destroyOnRelease ? new Error('Rollback failed') : undefined);
      }
    }
    throw new AppError('Command could not complete due to concurrent updates; retry.', 409, 'SERIALIZATION_FAILURE');
  }

  // ---- Individual Commands ----

  async function initCompany({
    actor,
    commandKey,
    slug = companySlug,
    displayName,
    defaultEmitMode = 'builtin',
    defaultEmitDisplay = null,
    defaultEmitKeep = [],
    defaultEmitNoManager = [],
  }) {
    const payload = { slug, displayName, defaultEmitMode, defaultEmitDisplay, defaultEmitKeep, defaultEmitNoManager };
    return executeJournalCommand({
      actor,
      commandKind: 'init_company',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const commitments = buildCommitments({ company_meta: [payload] });
        const body = { company: payload, result: { companySlug: slug }, commitments };
        const je = await writeJournal(body);
        await tx.query(
          `INSERT INTO coherence.company_meta (
             singleton, company_slug, display_name, default_emit_mode,
             default_emit_display, default_emit_keep, default_emit_no_manager, journal_seq
           ) VALUES (true, $1, $2, $3, $4, $5::text[], $6::text[], $7)`,
          [slug, displayName, defaultEmitMode, defaultEmitDisplay, defaultEmitKeep, defaultEmitNoManager, String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function registerStoredFiles({ actor, commandKey, files }) {
    const payload = { files: files.map((f) => ({ storeKind: f.storeKind, sha256: f.sha256, byteSize: Number(f.byteSize) })) };
    return executeJournalCommand({
      actor,
      commandKind: 'register_stored_files',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const toInsert = await filterNewStoredFiles(tx, files);
        const commitments = buildCommitments({ stored_files: toInsert });
        const body = { registered: toInsert.length, result: { registered: toInsert.length }, commitments };
        const je = await writeJournal(body);
        if (toInsert.length) await insertStoredFilesBatch(tx, toInsert, je.journalSeq);
        return { ...je, body, result: body.result };
      },
    });
  }

  async function registerEngineVersion({
    actor,
    commandKey,
    id = randomUUID(),
    label,
    coherenceCommit,
    gitBundle,
    codeManifest,
    pythonLock,
    pythonWheels,
    webLock,
    webPackages,
    wrapperBundle,
    nusearCommit,
    companyEmitSha256,
    pagesLawSha256,
    overlayCheckSha256,
    toolchain,
    containerDigest = null,
    extraCodeFiles = [],
  }) {
    const allCodeFiles = [gitBundle, codeManifest, pythonLock, pythonWheels, webLock, webPackages, wrapperBundle, ...extraCodeFiles];
    for (const f of allCodeFiles) {
      if ((f.storeKind ?? f.store_kind) !== 'nusear_code') {
        throw new AppError('Engine version files must live solely in Nusear code store (R6.6, R9.7).', 403, 'CODE_IN_DATA_STORE_FORBIDDEN');
      }
    }
    const payload = {
      label, coherenceCommit, gitBundleSha256: gitBundle.sha256, codeManifestSha256: codeManifest.sha256,
      pythonLockSha256: pythonLock.sha256, pythonWheelsSha256: pythonWheels.sha256,
      webLockSha256: webLock.sha256, webPackagesSha256: webPackages.sha256,
      wrapperBundleSha256: wrapperBundle.sha256, nusearCommit,
      companyEmitSha256, pagesLawSha256, overlayCheckSha256, toolchain, containerDigest,
    };
    return executeJournalCommand({
      actor,
      commandKind: 'register_engine_version',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const newFiles = await filterNewStoredFiles(tx, allCodeFiles);
        const engineRow = { id, ...payload };
        const commitments = buildCommitments({ stored_files: newFiles, engine_versions: [engineRow] });
        const body = { engineVersion: engineRow, result: { engineVersionId: id, label }, commitments };
        const je = await writeJournal(body);
        if (newFiles.length) await insertStoredFilesBatch(tx, newFiles, je.journalSeq);
        await tx.query(
          `INSERT INTO coherence.engine_versions (
             id, label, coherence_commit, store_kind,
             git_bundle_sha256, code_manifest_sha256, python_lock_sha256, python_wheels_sha256,
             web_lock_sha256, web_packages_sha256, wrapper_bundle_sha256,
             nusear_commit, company_emit_sha256, pages_law_sha256, overlay_check_sha256,
             toolchain, container_digest, journal_seq
           ) VALUES (
             $1::uuid, $2, $3, 'nusear_code',
             $4, $5, $6, $7, $8, $9, $10,
             $11, $12, $13, $14, $15::jsonb, $16, $17
           )`,
          [
            id, label, coherenceCommit,
            gitBundle.sha256, codeManifest.sha256, pythonLock.sha256, pythonWheels.sha256,
            webLock.sha256, webPackages.sha256, wrapperBundle.sha256,
            nusearCommit, companyEmitSha256, pagesLawSha256, overlayCheckSha256,
            JSON.stringify(toolchain), containerDigest, String(je.journalSeq),
          ],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function registerApprovalsFile({
    actor,
    commandKey,
    storedFile,
    headerKind,
    rowCount,
    extendsSha256 = null,
    sharedRowCount = 0,
    addedRows = [],
  }) {
    const normalizedRows = addedRows.map((r, idx) => ({
      ...r,
      approvalsFileSha256: storedFile.sha256,
      rowNo: r.rowNo ?? r.row_no ?? (sharedRowCount + idx + 1),
    }));
    const addedRowsSha256 = hashApprovalRows(normalizedRows);
    const payload = {
      fileSha256: storedFile.sha256, headerKind, rowCount, extendsSha256, sharedRowCount, addedRowsSha256,
    };
    return executeJournalCommand({
      actor,
      commandKind: 'register_approvals_file',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const exists = await tx.query('SELECT file_sha256, row_count, header_kind FROM coherence.approvals_files WHERE file_sha256 = $1', [storedFile.sha256]);
        if (exists.rows.length > 0) {
          const ex = exists.rows[0];
          const commitments = buildCommitments({});
          const body = {
            approvalsFile: { fileSha256: ex.file_sha256, alreadyRegistered: true, rowCount: ex.row_count, headerKind: ex.header_kind },
            result: { fileSha256: ex.file_sha256, alreadyRegistered: true },
            commitments,
          };
          const je = await writeJournal(body);
          return { ...je, body, result: body.result };
        }
        const newFiles = await filterNewStoredFiles(tx, [storedFile]);
        const afRow = {
          fileSha256: storedFile.sha256, headerKind, rowCount, extendsSha256, sharedRowCount, addedRowsSha256,
        };
        const commitments = buildCommitments({
          stored_files: newFiles,
          approvals_files: [afRow],
          approval_rows: normalizedRows,
        });
        const body = { approvalsFile: afRow, result: { fileSha256: storedFile.sha256, rowCount, added: normalizedRows.length }, commitments };
        const je = await writeJournal(body);
        if (newFiles.length) await insertStoredFilesBatch(tx, newFiles, je.journalSeq);
        await tx.query(
          `INSERT INTO coherence.approvals_files (
             file_sha256, store_kind, header_kind, row_count, extends_sha256, shared_row_count, added_rows_sha256, journal_seq
           ) VALUES ($1, 'company_data', $2, $3, $4, $5, $6, $7)`,
          [storedFile.sha256, headerKind, rowCount, extendsSha256, sharedRowCount, addedRowsSha256, String(je.journalSeq)],
        );
        if (normalizedRows.length) await insertApprovalRowsBatch(tx, normalizedRows, je.journalSeq);
        return { ...je, body, result: body.result };
      },
    });
  }

  async function publishInputVersion({
    actor,
    commandKey,
    expectedJournalSeq = null,
    id = randomUUID(),
    lineKind = 'standing',
    sourceKind,
    reason,
    entries,
    explicitRenames = [],
    detectRenames = true,
    storedFiles = [],
    storeCanonicalList = false,
  }) {
    if (!Array.isArray(entries)) throw new AppError('entries must be an array.', 400, 'INVALID_ENTRIES');
    for (const e of entries) assertValidRelPath(e.relPath ?? e.rel_path, 'input entry path');
    const clashes = findPathClashes(entries.map((e) => e.relPath ?? e.rel_path));
    if (clashes.length > 0) {
      throw new AppError(`Input version contains conflicting paths (${clashes[0].kind}) (R6.4, DS-2).`, 409, 'PATH_CLASH');
    }

    let entriesListStoredFile = null;
    if (storeCanonicalList && stores) {
      const listBytes = Buffer.from(canonicalInputEntriesText(entries), 'utf8');
      entriesListStoredFile = await stores.dataStore.promoteBytes(listBytes, {
        relPath: 'input-entries.canonical.ndjson',
        checksPassed: true,
        contentType: 'application/x-ndjson',
      });
    }

    const entriesSha256 = hashInputEntries(entries);
    const payload = { lineKind, sourceKind, reason, entryCount: entries.length, entriesSha256, explicitRenames };

    return executeJournalCommand({
      actor,
      commandKind: 'publish_input_version',
      commandKey,
      payload,
      expectedJournalSeq,
      scopeStandingLine: lineKind === 'standing',
      buildAndWrite: async (tx, writeJournal) => {
        let parentId = null;
        let changes = [];
        if (lineKind === 'standing') {
          const parentRes = await tx.query(
            `SELECT id FROM coherence.input_versions WHERE line_kind = 'standing' ORDER BY journal_seq DESC LIMIT 1`,
          );
          if (parentRes.rows.length > 0) {
            parentId = parentRes.rows[0].id;
            const prevEntriesRes = await tx.query(
              'SELECT rel_path, file_sha256 FROM coherence.input_entries WHERE input_version_id = $1',
              [parentId],
            );
            changes = diffInputEntries(prevEntriesRes.rows, entries, { explicitRenames, detectRenames });
          }
        }

        const changesSha256 = hashInputChanges(changes);
        const allFiles = entriesListStoredFile ? [...storedFiles, entriesListStoredFile] : storedFiles;
        const newFiles = await filterNewStoredFiles(tx, allFiles);
        const entryRows = entries.map((e) => ({
          inputVersionId: id,
          relPath: e.relPath ?? e.rel_path,
          fileSha256: e.fileSha256 ?? e.file_sha256,
        }));
        const changeRows = changes.map((c) => ({ ...c, inputVersionId: id }));
        const ivMeta = {
          id, lineKind, parentId, sourceKind, reason,
          entryCount: entryRows.length, entriesSha256,
          entriesListFileSha256: entriesListStoredFile?.sha256 ?? null,
          changeCount: changeRows.length, changesSha256,
        };
        const commitments = buildCommitments({
          stored_files: newFiles,
          input_versions: [ivMeta],
          input_entries: entryRows,
          input_changes: changeRows,
        });
        const body = { inputVersion: ivMeta, result: { inputVersionId: id, parentId, entryCount: entryRows.length, changeCount: changeRows.length }, commitments };
        const je = await writeJournal(body);

        if (newFiles.length) await insertStoredFilesBatch(tx, newFiles, je.journalSeq);
        await tx.query(
          `INSERT INTO coherence.input_versions (
             id, line_kind, parent_id, source_kind, reason,
             entry_count, entries_sha256, entries_list_file_sha256,
             change_count, changes_sha256, store_kind, journal_seq
           ) VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10, 'company_data', $11)`,
          [
            id, lineKind, parentId, sourceKind, reason,
            entryRows.length, entriesSha256, entriesListStoredFile?.sha256 ?? null,
            changeRows.length, changesSha256, String(je.journalSeq),
          ],
        );
        if (entryRows.length) await insertInputEntriesBatch(tx, id, entryRows, je.journalSeq);
        if (changeRows.length) await insertInputChangesBatch(tx, id, changeRows, je.journalSeq);
        return { ...je, body, result: body.result };
      },
    });
  }

  async function launchRun({
    actor,
    commandKey,
    expectedJournalSeq = null,
    runId = randomUUID(),
    requestId = randomUUID(),
    statementDate,
    origin = 'app',
    inputVersionId = null,
    engineVersionId,
    emitMode = null,
    emitDisplay = null,
    emitKeep = null,
    emitNoManager = null,
    replaysRunId = null,
    comparedRunId = null,
    rerunReason = null,
  }) {
    if (!isValidIsoDate(statementDate)) {
      throw new AppError('statementDate must be a valid ISO date (YYYY-MM-DD).', 400, 'INVALID_DATE');
    }
    const payload = {
      statementDate, origin, inputVersionId, engineVersionId,
      emitMode, emitDisplay, emitKeep, emitNoManager, replaysRunId, comparedRunId, rerunReason,
    };
    return executeJournalCommand({
      actor,
      commandKind: 'launch_run',
      commandKey,
      payload,
      expectedJournalSeq,
      scopeStandingLine: origin === 'app' || origin === 'trial',
      buildAndWrite: async (tx, writeJournal) => {
        // Resolve inputVersionId (latest standing for app/trial unless specified; replayed run's snapshot for replay)
        let resolvedInputId = inputVersionId;
        if (origin === 'replay' && replaysRunId && !resolvedInputId) {
          const rep = await tx.query('SELECT input_version_id FROM coherence.runs WHERE id = $1::uuid', [replaysRunId]);
          if (rep.rows.length === 0) throw new AppError('Replayed run not found.', 404, 'RUN_NOT_FOUND');
          resolvedInputId = rep.rows[0].input_version_id;
        } else if (!resolvedInputId) {
          const latest = await tx.query(
            `SELECT id FROM coherence.input_versions WHERE line_kind = 'standing' ORDER BY journal_seq DESC LIMIT 1`,
          );
          if (latest.rows.length === 0) throw new AppError('No standing input version exists yet.', 409, 'NO_STANDING_INPUT');
          resolvedInputId = latest.rows[0].id;
        }

        // Resolve Emit defaults from company_meta when omitted
        let mode = emitMode;
        let display = emitDisplay;
        let keep = emitKeep;
        let noManager = emitNoManager;
        if (!mode) {
          const metaRes = await tx.query('SELECT default_emit_mode, default_emit_display, default_emit_keep, default_emit_no_manager FROM coherence.company_meta LIMIT 1');
          if (metaRes.rows.length > 0) {
            mode = metaRes.rows[0].default_emit_mode;
            display = metaRes.rows[0].default_emit_display;
            keep = metaRes.rows[0].default_emit_keep;
            noManager = metaRes.rows[0].default_emit_no_manager;
          } else {
            mode = 'builtin';
          }
        }
        keep = keep || [];
        noManager = noManager || [];
        if (mode !== 'generated') {
          display = null;
          keep = [];
          noManager = [];
        }

        // Look up prior_approvals_sha256 from input_entries
        const ovRes = await tx.query(
          `SELECT file_sha256 FROM coherence.input_entries
           WHERE input_version_id = $1::uuid AND mac_key = 'overlay/overlay.csv'`,
          [resolvedInputId],
        );
        const priorApprovalsSha256 = ovRes.rows[0]?.file_sha256 ?? null;

        // Compute folder_number
        let folderNumber = 1;
        if (origin === 'app' || origin === 'trial') {
          const fnRes = await tx.query(
            'SELECT COALESCE(pg_catalog.max(folder_number), 0) + 1 AS next_no FROM coherence.runs WHERE origin = $1 AND statement_date = $2::date',
            [origin, statementDate],
          );
          folderNumber = Number(fnRes.rows[0].next_no);
        }

        const runRow = {
          id: runId,
          statementDate,
          folderNumber,
          origin,
          inputVersionId: resolvedInputId,
          priorApprovalsSha256,
          engineVersionId,
          emitMode: mode,
          emitDisplay: display,
          emitKeep: keep,
          emitNoManager: noManager,
          replaysRunId,
          comparedRunId,
          rerunReason,
          sourceFolder: null,
        };
        const reqRow = {
          id: requestId,
          runId,
          step: 'assign',
          reason: 'launch',
          emitConfirmationId: null,
        };
        const commitments = buildCommitments({ runs: [runRow], step_requests: [reqRow] });
        const body = {
          run: runRow,
          stepRequest: reqRow,
          result: { runId, stepRequestId: requestId, statementDate, folderNumber, origin },
          commitments,
        };
        const je = await writeJournal(body);

        await tx.query(
          `INSERT INTO coherence.runs (
             id, statement_date, folder_number, origin, input_version_id, prior_approvals_sha256,
             engine_version_id, emit_mode, emit_display, emit_keep, emit_no_manager,
             replays_run_id, compared_run_id, rerun_reason, source_folder, journal_seq
           ) VALUES (
             $1::uuid, $2::date, $3, $4, $5::uuid, $6,
             $7::uuid, $8, $9, $10::text[], $11::text[],
             $12::uuid, $13::uuid, $14, NULL, $15
           )`,
          [
            runId, statementDate, folderNumber, origin, resolvedInputId, priorApprovalsSha256,
            engineVersionId, mode, display, keep, noManager,
            replaysRunId, comparedRunId, rerunReason, String(je.journalSeq),
          ],
        );
        await tx.query(
          `INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
           VALUES ($1::uuid, $2::uuid, 'assign', 'launch', NULL, $3)`,
          [requestId, runId, String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function startStepAttempt({ client, actor, commandKey, eventId = randomUUID(), runId, step, stepRequestId }) {
    if (!client) throw new AppError('startStepAttempt must run on the worker\'s slot connection.', 500, 'SLOT_CONNECTION_REQUIRED');
    const payload = { runId, step, stepRequestId };
    return executeJournalCommand({
      client,
      actor,
      commandKind: 'start_attempt',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const nextRes = await tx.query(
          `SELECT COALESCE(pg_catalog.max(attempt_no), 0) + 1 AS next_no
           FROM coherence.step_attempt_events
           WHERE run_id = $1::uuid AND step = $2 AND event_kind = 'started'`,
          [runId, step],
        );
        const attemptNo = Number(nextRes.rows[0].next_no);
        const evRow = {
          id: eventId, runId, step, attemptNo, eventKind: 'started',
          stepRequestId, cancelRequestId: null, born: null, logFileSha256: null,
          artifactCount: null, artifactsSha256: null,
        };
        const commitments = buildCommitments({ step_attempt_events: [evRow] });
        const body = { attemptEvent: evRow, result: { attemptEventId: eventId, runId, step, attemptNo }, commitments };
        const je = await writeJournal(body);

        await tx.query(
          `INSERT INTO coherence.step_attempt_events (
             id, run_id, step, attempt_no, event_kind, step_request_id, journal_seq
           ) VALUES ($1::uuid, $2::uuid, $3, $4, 'started', $5::uuid, $6)`,
          [eventId, runId, step, attemptNo, stepRequestId, String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function finishStepAttempt({
    client,
    actor,
    commandKey,
    eventId = randomUUID(),
    nextRequestId = randomUUID(),
    runId,
    step,
    attemptNo,
    census = {},
    born = null,
    logFile = null,
    artifacts = [],
    storedFiles = [],
    continueToNextStep = (step === 'assign' || step === 'attribute'),
  }) {
    if (!client) throw new AppError('finishStepAttempt must run on the worker\'s slot connection.', 500, 'SLOT_CONNECTION_REQUIRED');
    const normalizedArtifacts = artifacts.map((a) => ({
      attemptEventId: eventId,
      relPath: a.relPath ?? a.rel_path,
      artifactKind: a.artifactKind ?? a.artifact_kind,
      storeKind: a.storeKind ?? a.store_kind,
      fileSha256: a.fileSha256 ?? a.file_sha256,
    }));
    const artifactsSha256 = hashArtifacts(normalizedArtifacts);
    const nextStep = continueToNextStep
      ? (step === 'assign' ? 'attribute' : step === 'attribute' ? 'bible' : null)
      : null;
    const payload = {
      runId, step, attemptNo, born, logFileSha256: logFile?.sha256 ?? null,
      artifactCount: normalizedArtifacts.length, artifactsSha256, nextStep,
    };

    return executeJournalCommand({
      client,
      actor,
      commandKind: 'finish_attempt',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const allFiles = logFile ? [...storedFiles, logFile] : storedFiles;
        const newFiles = await filterNewStoredFiles(tx, allFiles);
        const evRow = {
          id: eventId, runId, step, attemptNo, eventKind: 'finished',
          stepRequestId: null, cancelRequestId: null, born,
          logFileSha256: logFile?.sha256 ?? null,
          artifactCount: normalizedArtifacts.length, artifactsSha256,
        };
        const nextReqRows = nextStep
          ? [{ id: nextRequestId, runId, step: nextStep, reason: 'continue', emitConfirmationId: null }]
          : [];
        const commitments = buildCommitments({
          stored_files: newFiles,
          step_attempt_events: [evRow],
          artifacts: normalizedArtifacts,
          step_requests: nextReqRows,
        });
        const body = {
          attemptEvent: { ...evRow, census },
          nextRequest: nextReqRows[0] ?? null,
          result: { attemptEventId: eventId, runId, step, attemptNo, nextStep, nextRequestId: nextStep ? nextRequestId : null },
          commitments,
        };
        const je = await writeJournal(body);

        if (newFiles.length) await insertStoredFilesBatch(tx, newFiles, je.journalSeq);
        await tx.query(
          `INSERT INTO coherence.step_attempt_events (
             id, run_id, step, attempt_no, event_kind, census, born,
             log_store_kind, log_file_sha256, artifact_count, artifacts_sha256, journal_seq
           ) VALUES (
             $1::uuid, $2::uuid, $3, $4, 'finished', $5::jsonb, $6,
             $7, $8, $9, $10, $11
           )`,
          [
            eventId, runId, step, attemptNo, JSON.stringify(census), born,
            logFile ? 'company_data' : null, logFile?.sha256 ?? null,
            normalizedArtifacts.length, artifactsSha256, String(je.journalSeq),
          ],
        );
        if (normalizedArtifacts.length) await insertArtifactsBatch(tx, normalizedArtifacts, je.journalSeq);
        if (nextStep) {
          await tx.query(
            `INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
             VALUES ($1::uuid, $2::uuid, $3, 'continue', NULL, $4)`,
            [nextRequestId, runId, nextStep, String(je.journalSeq)],
          );
        }
        return { ...je, body, result: body.result };
      },
    });
  }

  async function failStepAttempt({ client, actor, commandKey, eventId = randomUUID(), runId, step, attemptNo, logFile = null, errorSummary = '', storedFiles = [] }) {
    if (!client) throw new AppError('failStepAttempt must run on the worker\'s slot connection.', 500, 'SLOT_CONNECTION_REQUIRED');
    const safeSummary = sanitizeErrorMessage(errorSummary, 'Step failed.');
    const payload = { runId, step, attemptNo, logFileSha256: logFile?.sha256 ?? null, errorSummary: safeSummary };
    return executeJournalCommand({
      client,
      actor,
      commandKind: 'fail_attempt',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const allFiles = logFile ? [...storedFiles, logFile] : storedFiles;
        const newFiles = await filterNewStoredFiles(tx, allFiles);
        const evRow = {
          id: eventId, runId, step, attemptNo, eventKind: 'failed',
          stepRequestId: null, cancelRequestId: null, born: null,
          logFileSha256: logFile?.sha256 ?? null, artifactCount: null, artifactsSha256: null,
        };
        const commitments = buildCommitments({ stored_files: newFiles, step_attempt_events: [evRow] });
        const body = { attemptEvent: { ...evRow, errorSummary: safeSummary }, result: { attemptEventId: eventId, runId, step, attemptNo, eventKind: 'failed' }, commitments };
        const je = await writeJournal(body);

        if (newFiles.length) await insertStoredFilesBatch(tx, newFiles, je.journalSeq);
        await tx.query(
          `INSERT INTO coherence.step_attempt_events (
             id, run_id, step, attempt_no, event_kind, log_store_kind, log_file_sha256, error_summary, journal_seq
           ) VALUES ($1::uuid, $2::uuid, $3, $4, 'failed', $5, $6, $7, $8)`,
          [eventId, runId, step, attemptNo, logFile ? 'company_data' : null, logFile?.sha256 ?? null, safeSummary, String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function cancelStepAttempt({
    client, actor, commandKey, eventId = randomUUID(), runId, step, attemptNo,
    cancelRequestId = null, logFile = null, errorSummary = 'Cancelled.', storedFiles = [],
  }) {
    if (!client) throw new AppError('cancelStepAttempt must run on the worker\'s slot connection.', 500, 'SLOT_CONNECTION_REQUIRED');
    const safeSummary = sanitizeErrorMessage(errorSummary, 'Cancelled.');
    const payload = { runId, step, attemptNo, cancelRequestId, logFileSha256: logFile?.sha256 ?? null, errorSummary: safeSummary };
    return executeJournalCommand({
      client,
      actor,
      commandKind: 'cancel_attempt',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const allFiles = logFile ? [...storedFiles, logFile] : storedFiles;
        const newFiles = await filterNewStoredFiles(tx, allFiles);
        const evRow = {
          id: eventId, runId, step, attemptNo, eventKind: 'cancelled',
          stepRequestId: null, cancelRequestId, born: null,
          logFileSha256: logFile?.sha256 ?? null, artifactCount: null, artifactsSha256: null,
        };
        const commitments = buildCommitments({ stored_files: newFiles, step_attempt_events: [evRow] });
        const body = { attemptEvent: { ...evRow, errorSummary: safeSummary }, result: { attemptEventId: eventId, runId, step, attemptNo, eventKind: 'cancelled' }, commitments };
        const je = await writeJournal(body);

        if (newFiles.length) await insertStoredFilesBatch(tx, newFiles, je.journalSeq);
        await tx.query(
          `INSERT INTO coherence.step_attempt_events (
             id, run_id, step, attempt_no, event_kind, cancel_request_id,
             log_store_kind, log_file_sha256, error_summary, journal_seq
           ) VALUES ($1::uuid, $2::uuid, $3, $4, 'cancelled', $5::uuid, $6, $7, $8, $9)`,
          [
            eventId, runId, step, attemptNo, cancelRequestId,
            logFile ? 'company_data' : null, logFile?.sha256 ?? null, safeSummary, String(je.journalSeq),
          ],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function interruptStepAttempt({ client = null, actor, commandKey, eventId = randomUUID(), runId, step, attemptNo, errorSummary = 'Worker connection lost before step completed.' }) {
    const safeSummary = sanitizeErrorMessage(errorSummary, 'Interrupted.');
    const payload = { runId, step, attemptNo, errorSummary: safeSummary };
    return executeJournalCommand({
      client,
      actor,
      commandKind: 'interrupt_attempt',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const evRow = {
          id: eventId, runId, step, attemptNo, eventKind: 'interrupted',
          stepRequestId: null, cancelRequestId: null, born: null,
          logFileSha256: null, artifactCount: null, artifactsSha256: null,
        };
        const commitments = buildCommitments({ step_attempt_events: [evRow] });
        const body = { attemptEvent: { ...evRow, errorSummary: safeSummary }, result: { attemptEventId: eventId, runId, step, attemptNo, eventKind: 'interrupted' }, commitments };
        const je = await writeJournal(body);
        await tx.query(
          `INSERT INTO coherence.step_attempt_events (
             id, run_id, step, attempt_no, event_kind, error_summary, journal_seq
           ) VALUES ($1::uuid, $2::uuid, $3, $4, 'interrupted', $5, $6)`,
          [eventId, runId, step, attemptNo, safeSummary, String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function requestCancel({ actor, commandKey, expectedJournalSeq = null, cancelRequestId = randomUUID(), runId, step, attemptNo, typedPhrase, reason = '' }) {
    const payload = { runId, step, attemptNo, typedPhrase, reason };
    return executeJournalCommand({
      actor,
      commandKind: 'request_cancel',
      commandKey,
      payload,
      expectedJournalSeq,
      scopeRunId: runId,
      buildAndWrite: async (tx, writeJournal) => {
        const crRow = { id: cancelRequestId, runId, step, attemptNo, typedPhrase, reason };
        const commitments = buildCommitments({ cancel_requests: [crRow] });
        const body = { cancelRequest: crRow, result: { cancelRequestId, runId, step, attemptNo }, commitments };
        const je = await writeJournal(body);
        await tx.query(
          `INSERT INTO coherence.cancel_requests (id, run_id, step, attempt_no, typed_phrase, reason, journal_seq)
           VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)`,
          [cancelRequestId, runId, step, attemptNo, typedPhrase, reason, String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function requestRetry({ actor, commandKey, expectedJournalSeq = null, requestId = randomUUID(), runId, step }) {
    const payload = { runId, step };
    return executeJournalCommand({
      actor,
      commandKind: 'request_retry',
      commandKey,
      payload,
      expectedJournalSeq,
      scopeRunId: runId,
      buildAndWrite: async (tx, writeJournal) => {
        // Supersede any non-superseded ended attempts of steps strictly after `step`
        const laterRes = await tx.query(
          `SELECT e.step, e.attempt_no
           FROM coherence.step_attempt_events e
           WHERE e.run_id = $1::uuid
             AND coherence.step_rank(e.step) > coherence.step_rank($2)
             AND e.event_kind IN ('finished', 'failed', 'interrupted', 'cancelled')
             AND NOT EXISTS (
               SELECT 1 FROM coherence.step_attempt_events sup
               WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no AND sup.event_kind = 'superseded'
             )
           ORDER BY coherence.step_rank(e.step) ASC, e.attempt_no ASC`,
          [runId, step],
        );
        const supersededRows = laterRes.rows.map((r) => ({
          id: randomUUID(),
          runId,
          step: r.step,
          attemptNo: Number(r.attempt_no),
          eventKind: 'superseded',
          stepRequestId: null,
          cancelRequestId: null,
          born: null,
          logFileSha256: null,
          artifactCount: null,
          artifactsSha256: null,
        }));

        let emitConfirmationId = null;
        if (step === 'emit') {
          const confirmRes = await tx.query(
            `SELECT ec.id
             FROM coherence.emit_confirmations ec
             JOIN coherence.review_saves rs ON rs.id = ec.adjust_review_save_id
             WHERE ec.run_id = $1::uuid
               AND rs.attempt_event_id = coherence.current_finished_attempt($1::uuid, 'adjust')
             ORDER BY ec.journal_seq DESC
             LIMIT 1`,
            [runId],
          );
          if (confirmRes.rows.length === 0) {
            throw new AppError('Emit retry requires an existing Emit confirmation for the current Adjust review (R6.8, R8).', 409, 'MISSING_EMIT_CONFIRMATION');
          }
          emitConfirmationId = confirmRes.rows[0].id;
        }

        const reqRow = { id: requestId, runId, step, reason: 'retry', emitConfirmationId };
        const commitments = buildCommitments({
          step_attempt_events: supersededRows,
          step_requests: [reqRow],
        });
        const body = {
          superseded: supersededRows.map((s) => ({ step: s.step, attemptNo: s.attemptNo })),
          stepRequest: reqRow,
          result: { stepRequestId: requestId, runId, step, emitConfirmationId },
          commitments,
        };
        const je = await writeJournal(body);

        for (const s of supersededRows) {
          await tx.query(
            `INSERT INTO coherence.step_attempt_events (id, run_id, step, attempt_no, event_kind, journal_seq)
             VALUES ($1::uuid, $2::uuid, $3, $4, 'superseded', $5)`,
            [s.id, runId, s.step, s.attemptNo, String(je.journalSeq)],
          );
        }
        await tx.query(
          `INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
           VALUES ($1::uuid, $2::uuid, $3, 'retry', $4::uuid, $5)`,
          [requestId, runId, step, emitConfirmationId, String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  /**
   * R10.7: Non-blocking web submission of a review file.
   * Validates actor, run, and expectedJournalSeq; stages bytes OUTSIDE objects/<sha256>; inserts pending review_submissions row.
   */
  async function submitReview({ actor, commandKey, expectedJournalSeq, runId, surface, csvBytes, submissionId = randomUUID() }) {
    assertCanWrite(actor, 'submit_review', { companySlug });
    if (!['bible', 'adjust'].includes(surface)) {
      throw new AppError('Review surface must be bible or adjust.', 400, 'INVALID_SURFACE');
    }
    if (typeof commandKey !== 'string' || !commandKey.length) {
      throw new AppError('Review submission requires commandKey (R10.6).', 400, 'MISSING_COMMAND_KEY');
    }
    if (!Number.isInteger(Number(expectedJournalSeq)) || Number(expectedJournalSeq) < 0) {
      throw new AppError('Review submission requires expectedJournalSeq (R10.5).', 400, 'MISSING_JOURNAL_SEQ');
    }
    const buf = Buffer.isBuffer(csvBytes) ? csvBytes : Buffer.from(String(csvBytes ?? ''), 'utf8');
    if (buf.length === 0) throw new AppError('Review file cannot be empty.', 400, 'EMPTY_REVIEW');
    if (!stores?.dataStore) throw new AppError('Company data store is required to stage reviews.', 500, 'STORE_NOT_CONFIGURED');

    const actingFor = actor.actingFor ?? null;
    const staged = await stores.dataStore.stageReview({ submissionId, bytes: buf });
    const requestSha256 = computeRequestFingerprint({
      commandKind: 'submit_review',
      actor: actor.id,
      actingFor,
      payload: { runId, surface, stagedSha256: staged.sha256, expectedJournalSeq: Number(expectedJournalSeq) },
    });

    const tx = await pool.connect();
    try {
      await tx.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      // Idempotency check on review_submissions.command_key
      const exRes = await tx.query(
        `SELECT id, run_id, surface, staged_sha256, status, review_save_id, result_journal_seq, result_message,
                actor, acting_for, request_sha256
         FROM coherence.review_submissions WHERE command_key = $1`,
        [commandKey],
      );
      if (exRes.rows.length > 0) {
        const ex = exRes.rows[0];
        await tx.query('COMMIT');
        if (ex.actor === actor.id && (ex.acting_for ?? null) === actingFor && ex.request_sha256 === requestSha256) {
          return {
            idempotent: true,
            submissionId: ex.id,
            status: ex.status,
            reviewSaveId: ex.review_save_id,
            resultJournalSeq: ex.result_journal_seq ? Number(ex.result_journal_seq) : null,
            resultMessage: ex.result_message,
          };
        }
        throw new AppError('Command key already used with a different review submission (R10.6).', 409, 'COMMAND_KEY_CONFLICT');
      }

      // Check expectedJournalSeq against current run position
      const runSeqRes = await tx.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS latest', [runId]);
      if (Number(runSeqRes.rows[0].latest) > Number(expectedJournalSeq)) {
        throw new AppError('This run changed since the review page loaded; reload before saving (R10.5).', 409, 'STALE_JOURNAL_POSITION');
      }

      await tx.query(
        `INSERT INTO coherence.review_submissions (
           id, run_id, surface, staged_sha256, staged_object_name, expected_journal_seq,
           actor, acting_for, command_key, request_sha256, status
         ) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, 'pending')`,
        [
          submissionId, runId, surface, staged.sha256, staged.stagedObjectName, String(expectedJournalSeq),
          actor.id, actingFor, commandKey, requestSha256,
        ],
      );
      await tx.query('COMMIT');
      return { idempotent: false, submissionId, status: 'pending', stagedSha256: staged.sha256 };
    } catch (err) {
      await tx.query('ROLLBACK').catch(() => {});
      throw mapPgError(err);
    } finally {
      tx.release();
    }
  }

  /**
   * Worker-only acceptance of a checked review submission in ONE transaction (R10.7).
   */
  async function acceptReviewSubmission({
    client,
    actor,
    commandKey,
    submissionId,
    reviewSaveId = randomUUID(),
    adjustRequestId = randomUUID(),
    storedFile,
    headerKind,
    rowCount,
    extendsSha256 = null,
    sharedRowCount = 0,
    addedRows = [],
  }) {
    assertCanWrite(actor, 'accept_review_submission', { companySlug });
    if (!client) throw new AppError('acceptReviewSubmission must run on the worker\'s slot connection.', 500, 'SLOT_CONNECTION_REQUIRED');

    const tx = client;
    try {
      await tx.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const subRes = await tx.query('SELECT * FROM coherence.review_submissions WHERE id = $1::uuid', [submissionId]);
      if (subRes.rows.length === 0) throw new AppError('Review submission not found.', 404, 'NOT_FOUND');
      const sub = subRes.rows[0];
      if (sub.status !== 'pending') {
        await tx.query('COMMIT');
        return {
          alreadyResolved: true,
          status: sub.status,
          reviewSaveId: sub.review_save_id,
          journalSeq: sub.result_journal_seq ? Number(sub.result_journal_seq) : null,
        };
      }

      // Re-verify optimistic concurrency (R10.5) inside the serializable acceptance tx
      const runSeqRes = await tx.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS latest', [sub.run_id]);
      if (Number(runSeqRes.rows[0].latest) > Number(sub.expected_journal_seq)) {
        throw new AppError('This run changed while the review submission was waiting (R10.5).', 409, 'STALE_JOURNAL_POSITION');
      }

      const attemptRes = await tx.query(
        'SELECT coherence.current_finished_attempt($1::uuid, $2) AS ev_id',
        [sub.run_id, sub.surface],
      );
      const attemptEventId = attemptRes.rows[0]?.ev_id;
      if (!attemptEventId) {
        throw new AppError(`No current finished ${sub.surface} attempt exists for this run.`, 409, 'NO_FINISHED_ATTEMPT');
      }

      // Check whether approvals_file already exists
      const afExists = await tx.query('SELECT file_sha256 FROM coherence.approvals_files WHERE file_sha256 = $1', [storedFile.sha256]);
      const needAf = afExists.rows.length === 0;
      const newFiles = await filterNewStoredFiles(tx, [storedFile]);
      const normalizedRows = needAf
        ? addedRows.map((r, idx) => ({
          ...r,
          approvalsFileSha256: storedFile.sha256,
          rowNo: r.rowNo ?? r.row_no ?? (sharedRowCount + idx + 1),
        }))
        : [];
      const addedRowsSha256 = needAf ? hashApprovalRows(normalizedRows) : null;

      // If surface === 'bible', check if there is a current finished adjust attempt to supersede
      const supersededRows = [];
      const nextRequests = [];
      if (sub.surface === 'bible') {
        const adjRes = await tx.query(
          `SELECT id, attempt_no FROM coherence.step_attempt_events
           WHERE id = coherence.current_finished_attempt($1::uuid, 'adjust')`,
          [sub.run_id],
        );
        if (adjRes.rows.length > 0) {
          supersededRows.push({
            id: randomUUID(),
            runId: sub.run_id,
            step: 'adjust',
            attemptNo: Number(adjRes.rows[0].attempt_no),
            eventKind: 'superseded',
            stepRequestId: null,
            cancelRequestId: null,
            born: null,
            logFileSha256: null,
            artifactCount: null,
            artifactsSha256: null,
          });
        }
        nextRequests.push({
          id: adjustRequestId,
          runId: sub.run_id,
          step: 'adjust',
          reason: 'bible_saved',
          emitConfirmationId: null,
        });
      }

      const saveRow = {
        id: reviewSaveId,
        runId: sub.run_id,
        surface: sub.surface,
        attemptEventId,
        approvalsFileSha256: storedFile.sha256,
        imported: false,
        originalAt: null,
        submissionId,
      };
      const commitments = buildCommitments({
        stored_files: newFiles,
        approvals_files: needAf ? [{ fileSha256: storedFile.sha256 }] : [],
        approval_rows: normalizedRows,
        review_saves: [saveRow],
        step_attempt_events: supersededRows,
        step_requests: nextRequests,
      });

      const body = {
        reviewSave: saveRow,
        approvalsFileSha256: storedFile.sha256,
        headerKind,
        rowCount,
        addedRowCount: normalizedRows.length,
        adjustRequestId: nextRequests[0]?.id ?? null,
        result: { reviewSaveId, runId: sub.run_id, surface: sub.surface, approvalsFileSha256: storedFile.sha256, adjustRequestId: nextRequests[0]?.id ?? null },
        commitments,
      };

      const finalCommandKey = commandKey || `save-review:${sub.command_key}`;
      const reqSha = computeRequestFingerprint({
        commandKind: 'save_review',
        actor: sub.actor,
        actingFor: sub.acting_for ?? null,
        payload: { submissionId, runId: sub.run_id, surface: sub.surface, approvalsFileSha256: storedFile.sha256 },
      });

      const jRes = await tx.query(
        `INSERT INTO coherence.journal_entries (actor, acting_for, command_kind, command_key, request_sha256, body)
         VALUES ($1, $2, 'save_review', $3, $4, $5::jsonb)
         RETURNING seq, recorded_at, entry_hash`,
        [sub.actor, sub.acting_for ?? null, finalCommandKey, reqSha, JSON.stringify(body)],
      );
      const journalSeq = Number(jRes.rows[0].seq);

      if (newFiles.length) await insertStoredFilesBatch(tx, newFiles, journalSeq);
      if (needAf) {
        await tx.query(
          `INSERT INTO coherence.approvals_files (
             file_sha256, store_kind, header_kind, row_count, extends_sha256, shared_row_count, added_rows_sha256, journal_seq
           ) VALUES ($1, 'company_data', $2, $3, $4, $5, $6, $7)`,
          [storedFile.sha256, headerKind, rowCount, extendsSha256, sharedRowCount, addedRowsSha256, String(journalSeq)],
        );
        if (normalizedRows.length) await insertApprovalRowsBatch(tx, normalizedRows, journalSeq);
      }

      await tx.query(
        `INSERT INTO coherence.review_saves (
           id, run_id, surface, attempt_event_id, approvals_file_sha256, imported, original_at, submission_id, journal_seq
         ) VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, false, NULL, $6::uuid, $7)`,
        [reviewSaveId, sub.run_id, sub.surface, attemptEventId, storedFile.sha256, submissionId, String(journalSeq)],
      );

      for (const s of supersededRows) {
        await tx.query(
          `INSERT INTO coherence.step_attempt_events (id, run_id, step, attempt_no, event_kind, journal_seq)
           VALUES ($1::uuid, $2::uuid, $3, $4, 'superseded', $5)`,
          [s.id, s.runId, s.step, s.attemptNo, String(journalSeq)],
        );
      }

      for (const req of nextRequests) {
        await tx.query(
          `INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
           VALUES ($1::uuid, $2::uuid, $3, $4, NULL, $5)`,
          [req.id, req.runId, req.step, req.reason, String(journalSeq)],
        );
      }

      await tx.query(
        `UPDATE coherence.review_submissions
         SET status = 'accepted', review_save_id = $2::uuid, result_journal_seq = $3,
             result_message = 'Review saved.', resolved_at = pg_catalog.clock_timestamp()
         WHERE id = $1::uuid`,
        [submissionId, reviewSaveId, String(journalSeq)],
      );

      await tx.query('COMMIT');
      return {
        alreadyResolved: false,
        status: 'accepted',
        reviewSaveId,
        journalSeq,
        entryHash: jRes.rows[0].entry_hash,
        recordedAt: formatTimestampUtcUs(jRes.rows[0].recorded_at),
        adjustRequestId: nextRequests[0]?.id ?? null,
      };
    } catch (err) {
      await tx.query('ROLLBACK').catch(() => {});
      throw mapPgError(err);
    }
  }

  async function rejectReviewSubmission({ client, actor, submissionId, status = 'rejected', reason = 'Review file rejected.' }) {
    assertCanWrite(actor, 'reject_review_submission', { companySlug });
    if (!client) throw new AppError('rejectReviewSubmission must run on the worker\'s slot connection.', 500, 'SLOT_CONNECTION_REQUIRED');
    if (!['rejected', 'failed'].includes(status)) throw new AppError('status must be rejected or failed.', 400, 'INVALID_STATUS');
    const safeReason = sanitizeErrorMessage(reason, 'Review submission rejected.');
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      await client.query(
        `UPDATE coherence.review_submissions
         SET status = $2, result_message = $3, resolved_at = pg_catalog.clock_timestamp()
         WHERE id = $1::uuid AND status = 'pending'`,
        [submissionId, status, safeReason],
      );
      await client.query('COMMIT');
      return { submissionId, status, resultMessage: safeReason };
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw mapPgError(err);
    }
  }

  async function saveReviewDraft({ actor, runId, surface, attemptNo, born = null, checksum, rows }) {
    assertCanWrite(actor, 'save_review_draft', { companySlug });
    if (!['bible', 'adjust'].includes(surface)) throw new AppError('Invalid surface.', 400, 'INVALID_SURFACE');
    if (!Array.isArray(rows)) throw new AppError('Draft rows must be an array.', 400, 'INVALID_DRAFT');
    try {
      await pool.query(
        `INSERT INTO coherence.review_drafts (run_id, surface, attempt_no, born, checksum, rows_json, actor, acting_for, updated_at, expires_at)
         VALUES ($1::uuid, $2, $3, $4, $5, $6::jsonb, $7, $8, pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp() + INTERVAL '30 days')
         ON CONFLICT (run_id, surface, attempt_no) DO UPDATE
           SET born = EXCLUDED.born, checksum = EXCLUDED.checksum, rows_json = EXCLUDED.rows_json,
               actor = EXCLUDED.actor, acting_for = EXCLUDED.acting_for,
               updated_at = EXCLUDED.updated_at, expires_at = EXCLUDED.expires_at`,
        [runId, surface, Number(attemptNo), born, checksum, JSON.stringify(rows), actor.id, actor.actingFor ?? null],
      );
      return { saved: rows.length, runId, surface, attemptNo: Number(attemptNo) };
    } catch (err) {
      throw mapPgError(err);
    }
  }

  async function getReviewDraft({ runId, surface, attemptNo }) {
    const res = await pool.query(
      `SELECT run_id, surface, attempt_no, born, checksum, rows_json, updated_at, expires_at
       FROM coherence.review_drafts
       WHERE run_id = $1::uuid AND surface = $2 AND attempt_no = $3 AND expires_at > pg_catalog.clock_timestamp()`,
      [runId, surface, Number(attemptNo)],
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return {
      runId: row.run_id,
      surface: row.surface,
      attemptNo: Number(row.attempt_no),
      born: row.born,
      checksum: row.checksum,
      rows: row.rows_json,
      updatedAt: formatTimestampUtcUs(row.updated_at),
      expiresAt: formatTimestampUtcUs(row.expires_at),
    };
  }

  async function expireOldDrafts() {
    const res = await pool.query('DELETE FROM coherence.review_drafts WHERE expires_at <= pg_catalog.clock_timestamp()');
    return { deleted: res.rowCount ?? 0 };
  }

  async function confirmEmit({
    actor,
    commandKey,
    expectedJournalSeq = null,
    confirmationId = randomUUID(),
    requestId = randomUUID(),
    runId,
    adjustReviewSaveId,
    typedPhrase,
  }) {
    const payload = { runId, adjustReviewSaveId, typedPhrase };
    return executeJournalCommand({
      actor,
      commandKind: 'confirm_emit',
      commandKey,
      payload,
      expectedJournalSeq,
      scopeRunId: runId,
      buildAndWrite: async (tx, writeJournal) => {
        const confirmRow = { id: confirmationId, runId, adjustReviewSaveId, typedPhrase };
        const reqRow = { id: requestId, runId, step: 'emit', reason: 'emit_confirmed', emitConfirmationId: confirmationId };
        const commitments = buildCommitments({ emit_confirmations: [confirmRow], step_requests: [reqRow] });
        const body = {
          emitConfirmation: confirmRow,
          stepRequest: reqRow,
          result: { emitConfirmationId: confirmationId, stepRequestId: requestId, runId },
          commitments,
        };
        const je = await writeJournal(body);

        await tx.query(
          `INSERT INTO coherence.emit_confirmations (id, run_id, adjust_review_save_id, typed_phrase, journal_seq)
           VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)`,
          [confirmationId, runId, adjustReviewSaveId, typedPhrase, String(je.journalSeq)],
        );
        await tx.query(
          `INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
           VALUES ($1::uuid, $2::uuid, 'emit', 'emit_confirmed', $3::uuid, $4)`,
          [requestId, runId, confirmationId, String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function carrySent({
    actor,
    commandKey,
    expectedJournalSeq = null,
    carryId = randomUUID(),
    inputVersionId = randomUUID(),
    runId,
    typedPhrase,
  }) {
    const payload = { runId, typedPhrase };
    return executeJournalCommand({
      actor,
      commandKind: 'carry_sent',
      commandKey,
      payload,
      expectedJournalSeq,
      scopeRunId: runId,
      scopeStandingLine: true,
      buildAndWrite: async (tx, writeJournal) => {
        const runRes = await tx.query(
          `SELECT id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date,
                  pg_catalog.to_char(statement_date, 'YYYYMMDD') AS stamp
           FROM coherence.runs WHERE id = $1::uuid`,
          [runId],
        );
        if (runRes.rows.length === 0) throw new AppError('Run not found.', 404, 'RUN_NOT_FOUND');
        const { statement_date: statementDate, stamp } = runRes.rows[0];
        const emitEvRes = await tx.query("SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev_id", [runId]);
        const emitEvId = emitEvRes.rows[0]?.ev_id;
        if (!emitEvId) throw new AppError('Run has not finished Emit (R8).', 409, 'EMIT_NOT_FINISHED');

        const relArtifact = `emits/statements_${stamp}.csv`;
        const artRes = await tx.query(
          'SELECT file_sha256 FROM coherence.artifacts WHERE attempt_event_id = $1::uuid AND rel_path = $2',
          [emitEvId, relArtifact],
        );
        if (artRes.rows.length === 0) throw new AppError(`Emit artifact ${relArtifact} not found.`, 404, 'ARTIFACT_NOT_FOUND');
        const fileSha256 = artRes.rows[0].file_sha256;

        const parentRes = await tx.query(
          `SELECT id FROM coherence.input_versions WHERE line_kind = 'standing' ORDER BY journal_seq DESC LIMIT 1`,
        );
        const parentId = parentRes.rows[0]?.id ?? null;
        const parentEntries = parentId
          ? (await tx.query('SELECT rel_path, file_sha256 FROM coherence.input_entries WHERE input_version_id = $1::uuid', [parentId])).rows
          : [];

        const sentRelPath = `Sent/statements_${stamp}.csv`;
        const nextEntries = [
          ...parentEntries.map((r) => ({ inputVersionId, relPath: r.rel_path, fileSha256: r.file_sha256 })),
          { inputVersionId, relPath: sentRelPath, fileSha256 },
        ];
        const changes = parentId
          ? [{ inputVersionId, changeKind: 'added', relPath: sentRelPath, oldRelPath: null, fileSha256, prevFileSha256: null }]
          : [];
        const entriesSha256 = hashInputEntries(nextEntries);
        const changesSha256 = hashInputChanges(changes);

        const ivMeta = {
          id: inputVersionId, lineKind: 'standing', parentId, sourceKind: 'record_sent',
          reason: `Record statement ${statementDate} as sent`,
          entryCount: nextEntries.length, entriesSha256, changeCount: changes.length, changesSha256,
        };
        const carryRow = {
          id: carryId, runId, statementDate, carryKind: 'sent', fileSha256,
          publishedInputVersionId: inputVersionId, nothingNew: false, typedPhrase,
        };
        const commitments = buildCommitments({
          input_versions: [ivMeta],
          input_entries: nextEntries,
          input_changes: changes,
          carries: [carryRow],
        });
        const body = {
          carry: carryRow,
          inputVersion: ivMeta,
          result: { carryId, publishedInputVersionId: inputVersionId, statementDate, fileSha256 },
          commitments,
        };
        const je = await writeJournal(body);

        await tx.query(
          `INSERT INTO coherence.input_versions (
             id, line_kind, parent_id, source_kind, reason,
             entry_count, entries_sha256, change_count, changes_sha256, store_kind, journal_seq
           ) VALUES ($1::uuid, 'standing', $2::uuid, 'record_sent', $3, $4, $5, $6, $7, 'company_data', $8)`,
          [inputVersionId, parentId, ivMeta.reason, nextEntries.length, entriesSha256, changes.length, changesSha256, String(je.journalSeq)],
        );
        await insertInputEntriesBatch(tx, inputVersionId, nextEntries, je.journalSeq);
        if (changes.length) await insertInputChangesBatch(tx, inputVersionId, changes, je.journalSeq);
        await tx.query(
          `INSERT INTO coherence.carries (
             id, run_id, statement_date, carry_kind, store_kind, file_sha256,
             published_input_version_id, nothing_new, typed_phrase, journal_seq
           ) VALUES ($1::uuid, $2::uuid, $3::date, 'sent', 'company_data', $4, $5::uuid, false, $6, $7)`,
          [carryId, runId, statementDate, fileSha256, inputVersionId, typedPhrase, String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function carryApprovals({
    actor,
    commandKey,
    expectedJournalSeq = null,
    carryId = randomUUID(),
    inputVersionId = randomUUID(),
    runId,
    typedPhrase,
  }) {
    const payload = { runId, typedPhrase };
    return executeJournalCommand({
      actor,
      commandKind: 'carry_approvals',
      commandKey,
      payload,
      expectedJournalSeq,
      scopeRunId: runId,
      scopeStandingLine: true,
      buildAndWrite: async (tx, writeJournal) => {
        const runRes = await tx.query(
          `SELECT id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date
           FROM coherence.runs WHERE id = $1::uuid`,
          [runId],
        );
        if (runRes.rows.length === 0) throw new AppError('Run not found.', 404, 'RUN_NOT_FOUND');
        const { statement_date: statementDate } = runRes.rows[0];
        const emitEvRes = await tx.query("SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev_id", [runId]);
        const emitEvId = emitEvRes.rows[0]?.ev_id;
        if (!emitEvId) throw new AppError('Run has not finished Emit (R8).', 409, 'EMIT_NOT_FINISHED');

        const artRes = await tx.query(
          "SELECT file_sha256 FROM coherence.artifacts WHERE attempt_event_id = $1::uuid AND rel_path = 'emits/overlay.csv'",
          [emitEvId],
        );
        if (artRes.rows.length === 0) throw new AppError('Emit artifact emits/overlay.csv not found.', 404, 'ARTIFACT_NOT_FOUND');
        const fileSha256 = artRes.rows[0].file_sha256;

        const parentRes = await tx.query(
          `SELECT id FROM coherence.input_versions WHERE line_kind = 'standing' ORDER BY journal_seq DESC LIMIT 1`,
        );
        const parentId = parentRes.rows[0]?.id ?? null;
        const parentEntries = parentId
          ? (await tx.query('SELECT rel_path, file_sha256 FROM coherence.input_entries WHERE input_version_id = $1::uuid', [parentId])).rows
          : [];
        const existingOverlay = parentEntries.find((r) => normalizeMacKey(r.rel_path) === 'overlay/overlay.csv');
        const nothingNew = Boolean(existingOverlay && existingOverlay.file_sha256 === fileSha256);

        if (nothingNew) {
          const carryRow = {
            id: carryId, runId, statementDate, carryKind: 'approvals', fileSha256,
            publishedInputVersionId: null, nothingNew: true, typedPhrase,
          };
          const commitments = buildCommitments({ carries: [carryRow] });
          const body = {
            carry: carryRow,
            result: { carryId, publishedInputVersionId: null, nothingNew: true, statementDate, fileSha256 },
            commitments,
          };
          const je = await writeJournal(body);
          await tx.query(
            `INSERT INTO coherence.carries (
               id, run_id, statement_date, carry_kind, store_kind, file_sha256,
               published_input_version_id, nothing_new, typed_phrase, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3::date, 'approvals', 'company_data', $4, NULL, true, $5, $6)`,
            [carryId, runId, statementDate, fileSha256, typedPhrase, String(je.journalSeq)],
          );
          return { ...je, body, result: body.result };
        }

        const overlayRelPath = 'Overlay/overlay.csv';
        const filteredParent = parentEntries.filter((r) => normalizeMacKey(r.rel_path) !== 'overlay/overlay.csv');
        const nextEntries = [
          ...filteredParent.map((r) => ({ inputVersionId, relPath: r.rel_path, fileSha256: r.file_sha256 })),
          { inputVersionId, relPath: overlayRelPath, fileSha256 },
        ];
        const changes = parentId
          ? [
            existingOverlay
              ? { inputVersionId, changeKind: 'replaced', relPath: overlayRelPath, oldRelPath: null, fileSha256, prevFileSha256: existingOverlay.file_sha256 }
              : { inputVersionId, changeKind: 'added', relPath: overlayRelPath, oldRelPath: null, fileSha256, prevFileSha256: null },
          ]
          : [];
        const entriesSha256 = hashInputEntries(nextEntries);
        const changesSha256 = hashInputChanges(changes);

        const ivMeta = {
          id: inputVersionId, lineKind: 'standing', parentId, sourceKind: 'carry_approvals',
          reason: `Carry approvals from ${statementDate} run`,
          entryCount: nextEntries.length, entriesSha256, changeCount: changes.length, changesSha256,
        };
        const carryRow = {
          id: carryId, runId, statementDate, carryKind: 'approvals', fileSha256,
          publishedInputVersionId: inputVersionId, nothingNew: false, typedPhrase,
        };
        const commitments = buildCommitments({
          input_versions: [ivMeta],
          input_entries: nextEntries,
          input_changes: changes,
          carries: [carryRow],
        });
        const body = {
          carry: carryRow,
          inputVersion: ivMeta,
          result: { carryId, publishedInputVersionId: inputVersionId, nothingNew: false, statementDate, fileSha256 },
          commitments,
        };
        const je = await writeJournal(body);

        await tx.query(
          `INSERT INTO coherence.input_versions (
             id, line_kind, parent_id, source_kind, reason,
             entry_count, entries_sha256, change_count, changes_sha256, store_kind, journal_seq
           ) VALUES ($1::uuid, 'standing', $2::uuid, 'carry_approvals', $3, $4, $5, $6, $7, 'company_data', $8)`,
          [inputVersionId, parentId, ivMeta.reason, nextEntries.length, entriesSha256, changes.length, changesSha256, String(je.journalSeq)],
        );
        await insertInputEntriesBatch(tx, inputVersionId, nextEntries, je.journalSeq);
        if (changes.length) await insertInputChangesBatch(tx, inputVersionId, changes, je.journalSeq);
        await tx.query(
          `INSERT INTO coherence.carries (
             id, run_id, statement_date, carry_kind, store_kind, file_sha256,
             published_input_version_id, nothing_new, typed_phrase, journal_seq
           ) VALUES ($1::uuid, $2::uuid, $3::date, 'approvals', 'company_data', $4, $5::uuid, false, $6, $7)`,
          [carryId, runId, statementDate, fileSha256, inputVersionId, typedPhrase, String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function abandonRun({ actor, commandKey, expectedJournalSeq = null, abandonmentId = randomUUID(), runId, typedPhrase, reason }) {
    const payload = { runId, typedPhrase, reason };
    return executeJournalCommand({
      actor,
      commandKind: 'abandon_run',
      commandKey,
      payload,
      expectedJournalSeq,
      scopeRunId: runId,
      buildAndWrite: async (tx, writeJournal) => {
        const abRow = { id: abandonmentId, runId, typedPhrase, reason };
        const commitments = buildCommitments({ abandonments: [abRow] });
        const body = { abandonment: abRow, result: { abandonmentId, runId, abandoned: true }, commitments };
        const je = await writeJournal(body);
        await tx.query(
          `INSERT INTO coherence.abandonments (id, run_id, typed_phrase, reason, journal_seq)
           VALUES ($1::uuid, $2::uuid, $3, $4, $5)`,
          [abandonmentId, runId, typedPhrase, reason, String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function importHistoricalRun({
    actor,
    commandKey,
    run,
    inputVersion,
    inputEntries = [],
    approvalsFiles = [],
    stepAttempts = [],
    reviewSaves = [],
    storedFiles = [],
  }) {
    const payload = {
      origin: run.origin,
      sourceFolder: run.sourceFolder,
      statementDate: run.statementDate,
      inputEntriesSha256: hashInputEntries(inputEntries),
      steps: stepAttempts.map((s) => s.step),
    };
    return executeJournalCommand({
      actor,
      commandKind: 'import_historical_run',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        // Idempotent check by (origin, source_folder)
        const exRun = await tx.query(
          'SELECT id FROM coherence.runs WHERE origin = $1 AND source_folder = $2',
          [run.origin, run.sourceFolder],
        );
        if (exRun.rows.length > 0) {
          const commitments = buildCommitments({});
          const body = { alreadyImported: true, runId: exRun.rows[0].id, result: { runId: exRun.rows[0].id, alreadyImported: true }, commitments };
          const je = await writeJournal(body);
          return { ...je, body, result: body.result };
        }

        const newFiles = await filterNewStoredFiles(tx, storedFiles);

        // Filter out already-registered approvals_files
        const afToInsert = [];
        const arToInsert = [];
        const seenAf = new Set();
        for (const af of approvalsFiles) {
          if (seenAf.has(af.fileSha256)) continue;
          seenAf.add(af.fileSha256);
          const exAf = await tx.query('SELECT file_sha256 FROM coherence.approvals_files WHERE file_sha256 = $1', [af.fileSha256]);
          if (exAf.rows.length === 0) {
            const rows = (af.addedRows || []).map((r, idx) => ({
              ...r,
              approvalsFileSha256: af.fileSha256,
              rowNo: r.rowNo ?? r.row_no ?? (af.sharedRowCount + idx + 1),
            }));
            afToInsert.push({ ...af, addedRowsSha256: hashApprovalRows(rows) });
            arToInsert.push(...rows);
          }
        }

        const ivId = inputVersion.id || randomUUID();
        const entryRows = inputEntries.map((e) => ({
          inputVersionId: ivId,
          relPath: e.relPath ?? e.rel_path,
          fileSha256: e.fileSha256 ?? e.file_sha256,
        }));
        const entriesSha256 = hashInputEntries(entryRows);
        const changesSha256 = hashInputChanges([]);
        const ivMeta = {
          id: ivId,
          lineKind: 'snapshot',
          parentId: null,
          sourceKind: run.origin === 'mac_import' ? 'mac_import' : 'company_import',
          reason: inputVersion.reason || `Imported frozen input from ${run.sourceFolder}`,
          entryCount: entryRows.length,
          entriesSha256,
          changeCount: 0,
          changesSha256,
        };

        const runId = run.id || randomUUID();
        const overlayEntry = entryRows.find((e) => normalizeMacKey(e.relPath) === 'overlay/overlay.csv');
        const runRow = {
          id: runId,
          statementDate: run.statementDate,
          folderNumber: run.folderNumber ?? 1,
          origin: run.origin,
          inputVersionId: ivId,
          priorApprovalsSha256: overlayEntry?.fileSha256 ?? null,
          engineVersionId: run.engineVersionId ?? null,
          emitMode: run.emitMode || 'coherence',
          emitDisplay: run.emitDisplay ?? null,
          emitKeep: run.emitKeep ?? [],
          emitNoManager: run.emitNoManager ?? [],
          replaysRunId: null,
          comparedRunId: null,
          rerunReason: null,
          sourceFolder: run.sourceFolder,
        };

        const attemptEventRows = [];
        const allArtifacts = [];
        const finishedIdByStep = new Map();
        for (const st of stepAttempts) {
          const startId = st.startEventId || randomUUID();
          const finishId = st.finishEventId || randomUUID();
          const attemptNo = st.attemptNo ?? 1;
          const stepArts = (st.artifacts || []).map((a) => ({
            attemptEventId: finishId,
            relPath: a.relPath,
            artifactKind: a.artifactKind,
            storeKind: a.storeKind,
            fileSha256: a.fileSha256,
          }));
          const artsSha = hashArtifacts(stepArts);
          attemptEventRows.push({
            id: startId, runId, step: st.step, attemptNo, eventKind: 'started',
            stepRequestId: null, cancelRequestId: null, born: null, logFileSha256: null,
            artifactCount: null, artifactsSha256: null, originalAt: st.startedAt ?? st.finishedAt ?? null, census: null,
          });
          attemptEventRows.push({
            id: finishId, runId, step: st.step, attemptNo, eventKind: 'finished',
            stepRequestId: null, cancelRequestId: null, born: st.born ?? null,
            logFileSha256: st.logFileSha256 ?? null,
            artifactCount: stepArts.length, artifactsSha256: artsSha,
            originalAt: st.finishedAt ?? null, census: st.census ?? {},
          });
          allArtifacts.push(...stepArts);
          finishedIdByStep.set(st.step, finishId);
        }

        const saveRows = [];
        for (const rs of reviewSaves) {
          const attemptEventId = finishedIdByStep.get(rs.surface);
          if (!attemptEventId) continue;
          saveRows.push({
            id: rs.id || randomUUID(),
            runId,
            surface: rs.surface,
            attemptEventId,
            approvalsFileSha256: rs.approvalsFileSha256,
            imported: true,
            originalAt: rs.originalAt ?? null,
            submissionId: null,
          });
        }

        const commitments = buildCommitments({
          stored_files: newFiles,
          approvals_files: afToInsert,
          approval_rows: arToInsert,
          input_versions: [ivMeta],
          input_entries: entryRows,
          runs: [runRow],
          step_attempt_events: attemptEventRows,
          artifacts: allArtifacts,
          review_saves: saveRows,
        });
        const body = {
          importedRun: { runId, origin: run.origin, sourceFolder: run.sourceFolder, statementDate: run.statementDate },
          result: { runId, inputVersionId: ivId, alreadyImported: false, steps: stepAttempts.length, reviewSaves: saveRows.length },
          commitments,
        };
        const je = await writeJournal(body);

        if (newFiles.length) await insertStoredFilesBatch(tx, newFiles, je.journalSeq);
        for (const af of afToInsert) {
          await tx.query(
            `INSERT INTO coherence.approvals_files (
               file_sha256, store_kind, header_kind, row_count, extends_sha256, shared_row_count, added_rows_sha256, journal_seq
             ) VALUES ($1, 'company_data', $2, $3, $4, $5, $6, $7)`,
            [af.fileSha256, af.headerKind, af.rowCount, af.extendsSha256 ?? null, af.sharedRowCount ?? 0, af.addedRowsSha256, String(je.journalSeq)],
          );
        }
        if (arToInsert.length) await insertApprovalRowsBatch(tx, arToInsert, je.journalSeq);

        await tx.query(
          `INSERT INTO coherence.input_versions (
             id, line_kind, parent_id, source_kind, reason,
             entry_count, entries_sha256, change_count, changes_sha256, store_kind, journal_seq
           ) VALUES ($1::uuid, 'snapshot', NULL, $2, $3, $4, $5, 0, $6, 'company_data', $7)`,
          [ivId, ivMeta.sourceKind, ivMeta.reason, entryRows.length, entriesSha256, changesSha256, String(je.journalSeq)],
        );
        if (entryRows.length) await insertInputEntriesBatch(tx, ivId, entryRows, je.journalSeq);

        await tx.query(
          `INSERT INTO coherence.runs (
             id, statement_date, folder_number, origin, input_version_id, prior_approvals_sha256,
             engine_version_id, emit_mode, emit_display, emit_keep, emit_no_manager,
             replays_run_id, compared_run_id, rerun_reason, source_folder, journal_seq
           ) VALUES (
             $1::uuid, $2::date, $3, $4, $5::uuid, $6,
             $7::uuid, $8, $9, $10::text[], $11::text[],
             NULL, NULL, NULL, $12, $13
           )`,
          [
            runId, runRow.statementDate, runRow.folderNumber, runRow.origin, ivId, runRow.priorApprovalsSha256,
            runRow.engineVersionId, runRow.emitMode, runRow.emitDisplay, runRow.emitKeep, runRow.emitNoManager,
            runRow.sourceFolder, String(je.journalSeq),
          ],
        );

        for (const ev of attemptEventRows) {
          await tx.query(
            `INSERT INTO coherence.step_attempt_events (
               id, run_id, step, attempt_no, event_kind, census, born,
               log_store_kind, log_file_sha256, artifact_count, artifacts_sha256, original_at, journal_seq
             ) VALUES (
               $1::uuid, $2::uuid, $3, $4, $5, $6::jsonb, $7,
               $8, $9, $10, $11, $12::timestamptz, $13
             )`,
            [
              ev.id, runId, ev.step, ev.attemptNo, ev.eventKind,
              ev.census ? JSON.stringify(ev.census) : null, ev.born,
              ev.logFileSha256 ? 'company_data' : null, ev.logFileSha256,
              ev.artifactCount, ev.artifactsSha256, ev.originalAt, String(je.journalSeq),
            ],
          );
        }
        if (allArtifacts.length) await insertArtifactsBatch(tx, allArtifacts, je.journalSeq);

        for (const rs of saveRows) {
          await tx.query(
            `INSERT INTO coherence.review_saves (
               id, run_id, surface, attempt_event_id, approvals_file_sha256, imported, original_at, submission_id, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, true, $6::timestamptz, NULL, $7)`,
            [rs.id, runId, rs.surface, rs.attemptEventId, rs.approvalsFileSha256, rs.originalAt, String(je.journalSeq)],
          );
        }

        return { ...je, body, result: body.result };
      },
    });
  }

  async function importStandaloneFiles({ actor, commandKey, files = [], storedFiles = [] }) {
    const payload = { files: files.map((f) => ({ area: f.area, relPath: f.relPath, fileSha256: f.fileSha256 })) };
    return executeJournalCommand({
      actor,
      commandKind: 'import_standalone_files',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const newStored = await filterNewStoredFiles(tx, storedFiles);
        const toInsert = [];
        for (const f of files) {
          const ex = await tx.query(
            'SELECT id FROM coherence.imported_files WHERE area = $1 AND rel_path = $2 AND file_sha256 = $3',
            [f.area, f.relPath, f.fileSha256],
          );
          if (ex.rows.length === 0) {
            toInsert.push({ id: f.id || randomUUID(), ...f });
          }
        }
        const commitments = buildCommitments({ stored_files: newStored, imported_files: toInsert });
        const body = { importedCount: toInsert.length, result: { importedCount: toInsert.length }, commitments };
        const je = await writeJournal(body);
        if (newStored.length) await insertStoredFilesBatch(tx, newStored, je.journalSeq);
        for (const f of toInsert) {
          await tx.query(
            `INSERT INTO coherence.imported_files (
               id, area, rel_path, artifact_kind, store_kind, file_sha256, original_at, metadata, journal_seq
             ) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::timestamptz, $8::jsonb, $9)`,
            [
              f.id, f.area, f.relPath, f.artifactKind || 'data', f.storeKind || 'company_data',
              f.fileSha256, f.originalAt ?? null, JSON.stringify(f.metadata || {}), String(je.journalSeq),
            ],
          );
        }
        return { ...je, body, result: body.result };
      },
    });
  }

  async function recordCheck({ actor, commandKey, checkId = randomUUID(), checkKind, runId = null, comparedRunId = null, passed, report }) {
    const payload = { checkKind, runId, comparedRunId, passed: Boolean(passed), report };
    return executeJournalCommand({
      actor,
      commandKind: 'record_check',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const checkRow = { id: checkId, checkKind, runId, comparedRunId, passed: Boolean(passed), report };
        const commitments = buildCommitments({ checks: [checkRow] });
        const body = { check: { id: checkId, checkKind, runId, comparedRunId, passed: Boolean(passed) }, result: { checkId, passed: Boolean(passed) }, commitments };
        const je = await writeJournal(body);
        await tx.query(
          `INSERT INTO coherence.checks (id, check_kind, run_id, compared_run_id, passed, report, journal_seq)
           VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5, $6::jsonb, $7)`,
          [checkId, checkKind, runId, comparedRunId, Boolean(passed), JSON.stringify(report), String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  return {
    initCompany,
    registerStoredFiles,
    registerEngineVersion,
    registerApprovalsFile,
    publishInputVersion,
    launchRun,
    startStepAttempt,
    finishStepAttempt,
    failStepAttempt,
    cancelStepAttempt,
    interruptStepAttempt,
    requestCancel,
    requestRetry,
    submitReview,
    acceptReviewSubmission,
    rejectReviewSubmission,
    saveReviewDraft,
    getReviewDraft,
    expireOldDrafts,
    confirmEmit,
    carrySent,
    carryApprovals,
    abandonRun,
    importHistoricalRun,
    importStandaloneFiles,
    recordCheck,
  };
}
