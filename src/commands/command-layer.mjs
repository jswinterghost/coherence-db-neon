// Single write chokepoint for all business mutations: enforces authorization, View-As refusal,
// command-key idempotency, expected_journal_seq concurrency, SERIALIZABLE isolation, batched inserts,
// and journal commitments.
import { randomUUID } from 'node:crypto';
import { LIVE_DISPOSITIONS, POLICY_STATUSES } from '../decisions/overlay-generator.mjs';
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
import { formatCents, parseCents, prepareEmitMaterialization } from '../worker/emit-materializer.mjs';
import { assertCanWrite } from './authz.mjs';
import {
  buildCommitments,
  hashDecisions,
  hashStatementAgencyLines,
  hashStatementUplineLines,
} from './commitments.mjs';

const BATCH_SIZE = 2000;
const POLICY_STATUS_SET = new Set(POLICY_STATUSES);
const MONEY_RE = /^-?[0-9]+\.[0-9]{2}$/;

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

async function insertDecisionsBatch(tx, rows, journalSeq) {
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE);
    await tx.query(
      `INSERT INTO coherence.decisions (
         id, decision_commit_id, row_order, run_id, review_save_id, surface, record_id,
         replaces_decision_id, disposition, agent, agency, policy, book, month, status, note,
         approved_amount, approved_agency, approved_agent, approved_agency_from, approved_agent_from,
         decided_by, acting_for, decided_at, committed_at_raw, imported, journal_seq
       )
       SELECT id, dcid, ro, rid, rsid, surf, reck,
              rep, disp, ag, agy, pol, bk, mo, st, nt,
              aa, aagy, aag, aagyf, aagf,
              dby, af, dat, craw, imp, $27
       FROM unnest(
         $1::uuid[], $2::uuid[], $3::integer[], $4::uuid[], $5::uuid[], $6::text[], $7::text[],
         $8::uuid[], $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], $14::text[], $15::text[], $16::text[],
         $17::text[], $18::text[], $19::text[], $20::text[], $21::text[],
         $22::text[], $23::text[], $24::timestamptz[], $25::text[], $26::boolean[]
       ) AS t(
         id, dcid, ro, rid, rsid, surf, reck,
         rep, disp, ag, agy, pol, bk, mo, st, nt,
         aa, aagy, aag, aagyf, aagf,
         dby, af, dat, craw, imp
       )`,
      [
        chunk.map((r) => r.id),
        chunk.map((r) => r.decisionCommitId ?? r.decision_commit_id),
        chunk.map((r) => Number(r.rowOrder ?? r.row_order)),
        chunk.map((r) => r.runId ?? r.run_id ?? null),
        chunk.map((r) => r.reviewSaveId ?? r.review_save_id ?? null),
        chunk.map((r) => r.surface ?? null),
        chunk.map((r) => r.recordId ?? r.record_id),
        chunk.map((r) => r.replacesDecisionId ?? r.replaces_decision_id ?? null),
        chunk.map((r) => r.disposition),
        chunk.map((r) => r.agent ?? null),
        chunk.map((r) => r.agency ?? null),
        chunk.map((r) => r.policy ?? null),
        chunk.map((r) => r.book ?? null),
        chunk.map((r) => r.month ?? null),
        chunk.map((r) => r.status ?? null),
        chunk.map((r) => r.note ?? null),
        chunk.map((r) => r.approvedAmount ?? r.approved_amount ?? null),
        chunk.map((r) => r.approvedAgency ?? r.approved_agency ?? null),
        chunk.map((r) => r.approvedAgent ?? r.approved_agent ?? null),
        chunk.map((r) => r.approvedAgencyFrom ?? r.approved_agency_from ?? null),
        chunk.map((r) => r.approvedAgentFrom ?? r.approved_agent_from ?? null),
        chunk.map((r) => r.decidedBy ?? r.decided_by),
        chunk.map((r) => r.actingFor ?? r.acting_for ?? null),
        chunk.map((r) => formatTimestampUtcUs(r.decidedAt ?? r.decided_at)),
        chunk.map((r) => r.committedAtRaw ?? r.committed_at_raw ?? null),
        chunk.map((r) => Boolean(r.imported)),
        String(journalSeq),
      ],
    );
  }
}

async function insertReviewQueueItemsBatch(tx, rows, journalSeq) {
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE);
    await tx.query(
      `INSERT INTO coherence.review_queue_items (
         attempt_event_id, item_order, run_id, surface, record_id,
         case_kind, subtype, entity, npn, amount, entity_from, npn_from, needs_reconfirm, journal_seq
       )
       SELECT ae, io, rid, surf, reck, ck, sub, ent, npn, amt, ef, nf, nr, $14
       FROM unnest(
         $1::uuid[], $2::integer[], $3::uuid[], $4::text[], $5::text[],
         $6::text[], $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::text[], $13::boolean[]
       ) AS t(ae, io, rid, surf, reck, ck, sub, ent, npn, amt, ef, nf, nr)`,
      [
        chunk.map((r) => r.attemptEventId ?? r.attempt_event_id),
        chunk.map((r) => Number(r.itemOrder ?? r.item_order)),
        chunk.map((r) => r.runId ?? r.run_id),
        chunk.map((r) => r.surface),
        chunk.map((r) => r.recordId ?? r.record_id),
        chunk.map((r) => r.caseKind ?? r.case_kind ?? null),
        chunk.map((r) => r.subtype ?? null),
        chunk.map((r) => r.entity ?? null),
        chunk.map((r) => r.npn ?? null),
        chunk.map((r) => r.amount ?? null),
        chunk.map((r) => r.entityFrom ?? r.entity_from ?? null),
        chunk.map((r) => r.npnFrom ?? r.npn_from ?? null),
        chunk.map((r) => Boolean(r.needsReconfirm ?? r.needs_reconfirm)),
        String(journalSeq),
      ],
    );
  }
}

async function insertStatementAgencyLinesBatch(tx, rows, journalSeq) {
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE);
    await tx.query(
      `INSERT INTO coherence.statement_agency_lines (
         batch_id, line_no, statement_date, entry_kind, run_action, entity,
         writing_npn, writing_agent, record_id, reversal_of, corrects_record_id,
         source_file, sheet_name, source_row_no, src_type, carrier, mbi, member,
         external_policy_id, policy_id, tx_id, plan_type, simple_plan_type, state,
         submission_date, origin_effective, effective_date, termination_date,
         earned_date, payment_date, posted_statement_date, revenue_type,
         gross_comm, amount, reason, notes, journal_seq
       )
       SELECT bid, lno, sd, ek, ra, ent, wnpn, wag, rid, rev, cor,
              sf, sh, srn, st, car, mbi, mem,
              epid, pid, tid, pt, spt, ste,
              subd, oeff, effd, termd,
              earnd, payd, psd, revt,
              gc, amt, rsn, nts, $37
       FROM unnest(
         $1::uuid[], $2::integer[], $3::date[], $4::text[], $5::text[], $6::text[],
         $7::text[], $8::text[], $9::text[], $10::text[], $11::text[],
         $12::text[], $13::text[], $14::integer[], $15::text[], $16::text[], $17::text[], $18::text[],
         $19::text[], $20::integer[], $21::integer[], $22::text[], $23::text[], $24::text[],
         $25::date[], $26::date[], $27::date[], $28::date[],
         $29::date[], $30::date[], $31::date[], $32::text[],
         $33::numeric(14,2)[], $34::numeric(14,2)[], $35::text[], $36::text[]
       ) AS t(
         bid, lno, sd, ek, ra, ent, wnpn, wag, rid, rev, cor,
         sf, sh, srn, st, car, mbi, mem,
         epid, pid, tid, pt, spt, ste,
         subd, oeff, effd, termd,
         earnd, payd, psd, revt,
         gc, amt, rsn, nts
       )`,
      [
        chunk.map((r) => r.batchId ?? r.batch_id),
        chunk.map((r) => Number(r.lineNo ?? r.line_no)),
        chunk.map((r) => r.statementDate ?? r.statement_date),
        chunk.map((r) => r.entryKind ?? r.entry_kind),
        chunk.map((r) => r.runAction ?? r.run_action),
        chunk.map((r) => r.entity),
        chunk.map((r) => r.writingNpn ?? r.writing_npn ?? null),
        chunk.map((r) => r.writingAgent ?? r.writing_agent ?? null),
        chunk.map((r) => r.recordId ?? r.record_id),
        chunk.map((r) => r.reversalOf ?? r.reversal_of ?? null),
        chunk.map((r) => r.correctsRecordId ?? r.corrects_record_id ?? null),
        chunk.map((r) => r.sourceFile ?? r.source_file),
        chunk.map((r) => r.sheetName ?? r.sheet_name ?? null),
        chunk.map((r) => Number(r.sourceRowNo ?? r.source_row_no)),
        chunk.map((r) => r.srcType ?? r.src_type ?? null),
        chunk.map((r) => r.carrier ?? null),
        chunk.map((r) => r.mbi ?? null),
        chunk.map((r) => r.member ?? null),
        chunk.map((r) => r.externalPolicyId ?? r.external_policy_id ?? null),
        chunk.map((r) => (r.policyId ?? r.policy_id) ?? null),
        chunk.map((r) => (r.txId ?? r.tx_id) ?? null),
        chunk.map((r) => r.planType ?? r.plan_type ?? null),
        chunk.map((r) => r.simplePlanType ?? r.simple_plan_type ?? null),
        chunk.map((r) => r.state ?? null),
        chunk.map((r) => r.submissionDate ?? r.submission_date ?? null),
        chunk.map((r) => r.originEffective ?? r.origin_effective ?? null),
        chunk.map((r) => r.effectiveDate ?? r.effective_date ?? null),
        chunk.map((r) => r.terminationDate ?? r.termination_date ?? null),
        chunk.map((r) => r.earnedDate ?? r.earned_date ?? null),
        chunk.map((r) => r.paymentDate ?? r.payment_date ?? null),
        chunk.map((r) => r.postedStatementDate ?? r.posted_statement_date ?? null),
        chunk.map((r) => r.revenueType ?? r.revenue_type ?? null),
        chunk.map((r) => r.grossComm ?? r.gross_comm),
        chunk.map((r) => r.amount),
        chunk.map((r) => r.reason ?? null),
        chunk.map((r) => r.notes ?? null),
        String(journalSeq),
      ],
    );
  }
}

async function insertStatementUplineLinesBatch(tx, rows, journalSeq) {
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE);
    await tx.query(
      `INSERT INTO coherence.statement_upline_lines (
         batch_id, line_no, statement_date, entry_kind, run_action, source_entity, marked_sent,
         writing_npn, writing_agent, record_id, reversal_of, corrects_record_id,
         source_file, sheet_name, source_row_no, src_type, carrier, mbi, member,
         external_policy_id, policy_id, tx_id, plan_type, simple_plan_type, state,
         submission_date, origin_effective, effective_date, termination_date,
         earned_date, payment_date, posted_statement_date, revenue_type,
         gross_comm, amount, reason, notes, journal_seq
       )
       SELECT bid, lno, sd, ek, ra, sent, msent, wnpn, wag, rid, rev, cor,
              sf, sh, srn, st, car, mbi, mem,
              epid, pid, tid, pt, spt, ste,
              subd, oeff, effd, termd,
              earnd, payd, psd, revt,
              gc, amt, rsn, nts, $38
       FROM unnest(
         $1::uuid[], $2::integer[], $3::date[], $4::text[], $5::text[], $6::text[], $7::boolean[],
         $8::text[], $9::text[], $10::text[], $11::text[], $12::text[],
         $13::text[], $14::text[], $15::integer[], $16::text[], $17::text[], $18::text[], $19::text[],
         $20::text[], $21::integer[], $22::integer[], $23::text[], $24::text[], $25::text[],
         $26::date[], $27::date[], $28::date[], $29::date[],
         $30::date[], $31::date[], $32::date[], $33::text[],
         $34::numeric(14,2)[], $35::numeric(14,2)[], $36::text[], $37::text[]
       ) AS t(
         bid, lno, sd, ek, ra, sent, msent, wnpn, wag, rid, rev, cor,
         sf, sh, srn, st, car, mbi, mem,
         epid, pid, tid, pt, spt, ste,
         subd, oeff, effd, termd,
         earnd, payd, psd, revt,
         gc, amt, rsn, nts
       )`,
      [
        chunk.map((r) => r.batchId ?? r.batch_id),
        chunk.map((r) => Number(r.lineNo ?? r.line_no)),
        chunk.map((r) => r.statementDate ?? r.statement_date),
        chunk.map((r) => r.entryKind ?? r.entry_kind),
        chunk.map((r) => r.runAction ?? r.run_action),
        chunk.map((r) => r.sourceEntity ?? r.source_entity),
        chunk.map((r) => Boolean(r.markedSent ?? r.marked_sent ?? true)),
        chunk.map((r) => r.writingNpn ?? r.writing_npn ?? null),
        chunk.map((r) => r.writingAgent ?? r.writing_agent ?? null),
        chunk.map((r) => r.recordId ?? r.record_id),
        chunk.map((r) => r.reversalOf ?? r.reversal_of ?? null),
        chunk.map((r) => r.correctsRecordId ?? r.corrects_record_id ?? null),
        chunk.map((r) => r.sourceFile ?? r.source_file),
        chunk.map((r) => r.sheetName ?? r.sheet_name ?? null),
        chunk.map((r) => Number(r.sourceRowNo ?? r.source_row_no)),
        chunk.map((r) => r.srcType ?? r.src_type ?? null),
        chunk.map((r) => r.carrier ?? null),
        chunk.map((r) => r.mbi ?? null),
        chunk.map((r) => r.member ?? null),
        chunk.map((r) => r.externalPolicyId ?? r.external_policy_id ?? null),
        chunk.map((r) => (r.policyId ?? r.policy_id) ?? null),
        chunk.map((r) => (r.txId ?? r.tx_id) ?? null),
        chunk.map((r) => r.planType ?? r.plan_type ?? null),
        chunk.map((r) => r.simplePlanType ?? r.simple_plan_type ?? null),
        chunk.map((r) => r.state ?? null),
        chunk.map((r) => r.submissionDate ?? r.submission_date ?? null),
        chunk.map((r) => r.originEffective ?? r.origin_effective ?? null),
        chunk.map((r) => r.effectiveDate ?? r.effective_date ?? null),
        chunk.map((r) => r.terminationDate ?? r.termination_date ?? null),
        chunk.map((r) => r.earnedDate ?? r.earned_date ?? null),
        chunk.map((r) => r.paymentDate ?? r.payment_date ?? null),
        chunk.map((r) => r.postedStatementDate ?? r.posted_statement_date ?? null),
        chunk.map((r) => r.revenueType ?? r.revenue_type ?? null),
        chunk.map((r) => r.grossComm ?? r.gross_comm),
        chunk.map((r) => r.amount),
        chunk.map((r) => r.reason ?? null),
        chunk.map((r) => r.notes ?? null),
        String(journalSeq),
      ],
    );
  }
}

async function insertBobPoliciesBatch(tx, rows, journalSeq) {
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE);
    await tx.query(
      `INSERT INTO coherence.bob_policies (
         attempt_event_id, policy_id, run_id, external_policy_id, carrier_policy_number, crm_policy_number,
         carrier, plan_type, plan_name, simple_plan_type, mbi, member, dob, phone, email, address, county, state,
         submission_date, origin_effective, effective_date, termination_date,
         writing_npn, writing_agent, entity, status, coherent_status, journal_seq
       )
       SELECT ae, pid, rid, epid, cpn, crm, car, pt, pn, spt, mbi, mem, dob, ph, em, addr, cty, ste,
              subd, oeff, effd, termd, wnpn, wag, ent, st, cst, $28
       FROM unnest(
         $1::uuid[], $2::integer[], $3::uuid[], $4::text[], $5::text[], $6::text[],
         $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], $14::text[], $15::text[], $16::text[], $17::text[], $18::text[],
         $19::date[], $20::date[], $21::date[], $22::date[],
         $23::text[], $24::text[], $25::text[], $26::text[], $27::text[]
       ) AS t(
         ae, pid, rid, epid, cpn, crm, car, pt, pn, spt, mbi, mem, dob, ph, em, addr, cty, ste,
         subd, oeff, effd, termd, wnpn, wag, ent, st, cst
       )`,
      [
        chunk.map((r) => r.attemptEventId ?? r.attempt_event_id),
        chunk.map((r) => Number(r.policyId ?? r.policy_id)),
        chunk.map((r) => r.runId ?? r.run_id),
        chunk.map((r) => r.externalPolicyId ?? r.external_policy_id ?? null),
        chunk.map((r) => r.carrierPolicyNumber ?? r.carrier_policy_number ?? null),
        chunk.map((r) => r.crmPolicyNumber ?? r.crm_policy_number ?? null),
        chunk.map((r) => r.carrier ?? null),
        chunk.map((r) => r.planType ?? r.plan_type ?? null),
        chunk.map((r) => r.planName ?? r.plan_name ?? null),
        chunk.map((r) => r.simplePlanType ?? r.simple_plan_type ?? null),
        chunk.map((r) => r.mbi ?? null),
        chunk.map((r) => r.member ?? null),
        chunk.map((r) => r.dob ?? null),
        chunk.map((r) => r.phone ?? null),
        chunk.map((r) => r.email ?? null),
        chunk.map((r) => r.address ?? null),
        chunk.map((r) => r.county ?? null),
        chunk.map((r) => r.state ?? null),
        chunk.map((r) => r.submissionDate ?? r.submission_date ?? null),
        chunk.map((r) => r.originEffective ?? r.origin_effective ?? null),
        chunk.map((r) => r.effectiveDate ?? r.effective_date ?? null),
        chunk.map((r) => r.terminationDate ?? r.termination_date ?? null),
        chunk.map((r) => r.writingNpn ?? r.writing_npn ?? null),
        chunk.map((r) => r.writingAgent ?? r.writing_agent ?? null),
        chunk.map((r) => r.entity),
        chunk.map((r) => r.status ?? null),
        chunk.map((r) => r.coherentStatus ?? r.coherent_status ?? null),
        String(journalSeq),
      ],
    );
  }
}

async function insertBobPolicyFinancialsBatch(tx, rows, journalSeq) {
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE);
    await tx.query(
      `INSERT INTO coherence.bob_policy_financials (
         attempt_event_id, policy_id, entity, writing_npn, amount, upline_amount,
         enrollment_code, min_date, anchor_date, agency_id, conflicts,
         spine_source, confidence_level, coherent_trajectory, journal_seq
       )
       SELECT ae, pid, ent, wnpn, amt, uamt, ec, md, ad, aid, conf, ss, cl, ct, $15
       FROM unnest(
         $1::uuid[], $2::integer[], $3::text[], $4::text[], $5::numeric(14,2)[], $6::numeric(14,2)[],
         $7::text[], $8::date[], $9::date[], $10::text[], $11::text[],
         $12::text[], $13::smallint[], $14::jsonb[]
       ) AS t(ae, pid, ent, wnpn, amt, uamt, ec, md, ad, aid, conf, ss, cl, ct)`,
      [
        chunk.map((r) => r.attemptEventId ?? r.attempt_event_id),
        chunk.map((r) => Number(r.policyId ?? r.policy_id)),
        chunk.map((r) => r.entity),
        chunk.map((r) => r.writingNpn ?? r.writing_npn ?? null),
        chunk.map((r) => r.amount ?? null),
        chunk.map((r) => r.uplineAmount ?? r.upline_amount ?? null),
        chunk.map((r) => r.enrollmentCode ?? r.enrollment_code ?? null),
        chunk.map((r) => r.minDate ?? r.min_date ?? null),
        chunk.map((r) => r.anchorDate ?? r.anchor_date ?? null),
        chunk.map((r) => r.agencyId ?? r.agency_id ?? null),
        chunk.map((r) => r.conflicts ?? null),
        chunk.map((r) => r.spineSource ?? r.spine_source ?? null),
        chunk.map((r) => (r.confidenceLevel ?? r.confidence_level) ?? null),
        chunk.map((r) => ((r.coherentTrajectory ?? r.coherent_trajectory) != null ? JSON.stringify(r.coherentTrajectory ?? r.coherent_trajectory) : null)),
        String(journalSeq),
      ],
    );
  }
}

async function insertCoherentLedgerRowsBatch(tx, rows, journalSeq) {
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE);
    await tx.query(
      `INSERT INTO coherence.coherent_ledger_rows (
         attempt_event_id, tx_id, run_id, record_id, external_policy_id, policy_id,
         statement_name, src_type, carrier, mbi, member, state, plan_type, simple_plan_type,
         submission_date, origin_effective, effective_date, termination_date,
         earned_date, payment_date, statement_date, min_date,
         gross_comm, revenue_type, override_amount, commission_amount, hra_amount, fee_amount, other_amount,
         downline_amount, upline_amount, writing_npn, writing_agent, entity, payee_npn, agency_id,
         status, policy_status, cbob_c, cbob_s, sf, notes, coherent_notes, sheet_name, source_row_no, journal_seq
       )
       SELECT ae, tid, rid, reck, epid, pid,
              sn, st, car, mbi, mem, ste, pt, spt,
              subd, oeff, effd, termd,
              earnd, payd, std, md,
              gc, revt, oa, ca, ha, fa, otha,
              da, ua, wnpn, wag, ent, pnpn, aid,
              stat, pstat, cc, cs, sff, nts, cnts, sh, srn, $46
       FROM unnest(
         $1::uuid[], $2::integer[], $3::uuid[], $4::text[], $5::text[], $6::integer[],
         $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], $14::text[],
         $15::date[], $16::date[], $17::date[], $18::date[],
         $19::date[], $20::date[], $21::date[], $22::date[],
         $23::numeric(14,2)[], $24::text[], $25::numeric(14,2)[], $26::numeric(14,2)[], $27::numeric(14,2)[], $28::numeric(14,2)[], $29::numeric(14,2)[],
         $30::numeric(14,2)[], $31::numeric(14,2)[], $32::text[], $33::text[], $34::text[], $35::text[], $36::text[],
         $37::text[], $38::text[], $39::boolean[], $40::boolean[], $41::boolean[], $42::text[], $43::text[], $44::text[], $45::integer[]
       ) AS t(
         ae, tid, rid, reck, epid, pid,
         sn, st, car, mbi, mem, ste, pt, spt,
         subd, oeff, effd, termd,
         earnd, payd, std, md,
         gc, revt, oa, ca, ha, fa, otha,
         da, ua, wnpn, wag, ent, pnpn, aid,
         stat, pstat, cc, cs, sff, nts, cnts, sh, srn
       )`,
      [
        chunk.map((r) => r.attemptEventId ?? r.attempt_event_id),
        chunk.map((r) => Number(r.txId ?? r.tx_id)),
        chunk.map((r) => r.runId ?? r.run_id),
        chunk.map((r) => r.recordId ?? r.record_id),
        chunk.map((r) => r.externalPolicyId ?? r.external_policy_id ?? null),
        chunk.map((r) => (r.policyId ?? r.policy_id) ?? null),
        chunk.map((r) => r.statementName ?? r.statement_name ?? null),
        chunk.map((r) => r.srcType ?? r.src_type),
        chunk.map((r) => r.carrier ?? null),
        chunk.map((r) => r.mbi ?? null),
        chunk.map((r) => r.member ?? null),
        chunk.map((r) => r.state ?? null),
        chunk.map((r) => r.planType ?? r.plan_type ?? null),
        chunk.map((r) => r.simplePlanType ?? r.simple_plan_type ?? null),
        chunk.map((r) => r.submissionDate ?? r.submission_date ?? null),
        chunk.map((r) => r.originEffective ?? r.origin_effective ?? null),
        chunk.map((r) => r.effectiveDate ?? r.effective_date ?? null),
        chunk.map((r) => r.terminationDate ?? r.termination_date ?? null),
        chunk.map((r) => r.earnedDate ?? r.earned_date ?? null),
        chunk.map((r) => r.paymentDate ?? r.payment_date ?? null),
        chunk.map((r) => r.statementDate ?? r.statement_date ?? null),
        chunk.map((r) => r.minDate ?? r.min_date ?? null),
        chunk.map((r) => r.grossComm ?? r.gross_comm),
        chunk.map((r) => r.revenueType ?? r.revenue_type ?? null),
        chunk.map((r) => r.overrideAmount ?? r.override_amount ?? null),
        chunk.map((r) => r.commissionAmount ?? r.commission_amount ?? null),
        chunk.map((r) => r.hraAmount ?? r.hra_amount ?? null),
        chunk.map((r) => r.feeAmount ?? r.fee_amount ?? null),
        chunk.map((r) => r.otherAmount ?? r.other_amount ?? null),
        chunk.map((r) => r.downlineAmount ?? r.downline_amount),
        chunk.map((r) => r.uplineAmount ?? r.upline_amount),
        chunk.map((r) => r.writingNpn ?? r.writing_npn ?? null),
        chunk.map((r) => r.writingAgent ?? r.writing_agent ?? null),
        chunk.map((r) => r.entity),
        chunk.map((r) => r.payeeNpn ?? r.payee_npn ?? null),
        chunk.map((r) => r.agencyId ?? r.agency_id ?? null),
        chunk.map((r) => r.status ?? null),
        chunk.map((r) => r.policyStatus ?? r.policy_status ?? null),
        chunk.map((r) => Boolean(r.cbobC ?? r.cbob_c)),
        chunk.map((r) => Boolean(r.cbobS ?? r.cbob_s)),
        chunk.map((r) => Boolean(r.sf)),
        chunk.map((r) => r.notes ?? null),
        chunk.map((r) => r.coherentNotes ?? r.coherent_notes ?? null),
        chunk.map((r) => r.sheetName ?? r.sheet_name ?? null),
        chunk.map((r) => (r.sourceRowNo ?? r.source_row_no) ?? null),
        String(journalSeq),
      ],
    );
  }
}

async function insertMaterializationPayload(tx, mat, journalSeq) {
  const sb = mat.statementBatch;
  await tx.query(
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
      sb.id, sb.batchKind, sb.statementDate, sb.runId ?? null, sb.attemptEventId ?? null,
      sb.sourceFileName ?? null, sb.sourceFileSha256 ? 'company_data' : null, sb.sourceFileSha256 ?? null, sb.reason,
      sb.agencyLineCount, sb.agencyLinesSha256, sb.agencyNetTotal,
      sb.uplineLineCount, sb.uplineLinesSha256, sb.uplineNetTotal, String(journalSeq),
    ],
  );
  if (mat.agencyLines.length) await insertStatementAgencyLinesBatch(tx, mat.agencyLines, journalSeq);
  if (mat.uplineLines.length) await insertStatementUplineLinesBatch(tx, mat.uplineLines, journalSeq);

  const rm = mat.runMaterialization;
  await tx.query(
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
      rm.attemptEventId, rm.runId, rm.statementDate, rm.reconciliationMode,
      rm.bobRowCount, rm.bobRowsSha256, rm.bobDownlineTotal, rm.bobUplineTotal,
      rm.ledgerRowCount, rm.ledgerRowsSha256, rm.ledgerGrossTotal, rm.ledgerDownlineTotal, rm.ledgerUplineTotal,
      rm.statementBatchId, rm.corpusTail ?? null, rm.agencyStart ?? null, String(journalSeq),
    ],
  );
  if (mat.bobPolicies.length) await insertBobPoliciesBatch(tx, mat.bobPolicies, journalSeq);
  if (mat.bobFinancials.length) await insertBobPolicyFinancialsBatch(tx, mat.bobFinancials, journalSeq);
  if (mat.ledgerRows.length) await insertCoherentLedgerRowsBatch(tx, mat.ledgerRows, journalSeq);
}

/**
 * Computes input_changes between parent and next entries, honoring explicit renames
 * and optionally detecting byte-identical renames so file history is preserved across renames.
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
      throw new AppError(`Rename from ${oldPath} to ${newPath} must move the exact same bytes.`, 400, 'INVALID_RENAME');
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
      throw new AppError('Every command must carry a non-empty commandKey.', 400, 'MISSING_COMMAND_KEY');
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
            'This command key was already used for a different request (kind, actor, acting_for, or content).',
            409,
            'COMMAND_KEY_CONFLICT',
          );
        }

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
              throw new AppError('This run changed since the screen loaded; reload and try again.', 409, 'STALE_JOURNAL_POSITION');
            }
          }
          if (scopeStandingLine) {
            const standRes = await tx.query(
              `SELECT COALESCE(pg_catalog.max(journal_seq), 0) AS latest
               FROM coherence.input_versions WHERE line_kind = 'standing'`,
            );
            if (Number(standRes.rows[0].latest) > expected) {
              throw new AppError('The standing input changed since the screen loaded; reload and try again.', 409, 'STALE_JOURNAL_POSITION');
            }
          }
          if (strictGlobalSeq && currentMax > expected) {
            throw new AppError('Database state changed since the screen loaded; reload and try again.', 409, 'STALE_JOURNAL_POSITION');
          }
        }

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
    engineKind = 'legacy_sealed',
    upstreamCommit = null,
    patchDiff = null,
    gitBundle,
    codeManifest,
    pythonLock,
    pythonWheels,
    webLock = null,
    webPackages = null,
    wrapperBundle,
    nusearCommit,
    companyEmitSha256 = null,
    pagesLawSha256 = null,
    overlayCheckSha256,
    toolchain,
    containerDigest = null,
    extraCodeFiles = [],
  }) {
    const allCodeFiles = [
      gitBundle, codeManifest, pythonLock, pythonWheels,
      webLock, webPackages, wrapperBundle, patchDiff,
      ...extraCodeFiles,
    ].filter(Boolean);
    for (const f of allCodeFiles) {
      if ((f.storeKind ?? f.store_kind) !== 'nusear_code') {
        throw new AppError('Engine version files must live solely in Nusear code store.', 403, 'CODE_IN_DATA_STORE_FORBIDDEN');
      }
    }
    const payload = {
      label, coherenceCommit, engineKind, upstreamCommit,
      patchDiffSha256: patchDiff?.sha256 ?? null,
      gitBundleSha256: gitBundle.sha256, codeManifestSha256: codeManifest.sha256,
      pythonLockSha256: pythonLock.sha256, pythonWheelsSha256: pythonWheels.sha256,
      webLockSha256: webLock?.sha256 ?? null, webPackagesSha256: webPackages?.sha256 ?? null,
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
        const body = { engineVersion: engineRow, result: { engineVersionId: id, label, engineKind }, commitments };
        const je = await writeJournal(body);
        if (newFiles.length) await insertStoredFilesBatch(tx, newFiles, je.journalSeq);
        await tx.query(
          `INSERT INTO coherence.engine_versions (
             id, label, coherence_commit, engine_kind, upstream_commit, patch_diff_sha256, store_kind,
             git_bundle_sha256, code_manifest_sha256, python_lock_sha256, python_wheels_sha256,
             web_lock_sha256, web_packages_sha256, wrapper_bundle_sha256,
             nusear_commit, company_emit_sha256, pages_law_sha256, overlay_check_sha256,
             toolchain, container_digest, journal_seq
           ) VALUES (
             $1::uuid, $2, $3, $4, $5, $6, 'nusear_code',
             $7, $8, $9, $10, $11, $12, $13,
             $14, $15, $16, $17, $18::jsonb, $19, $20
           )`,
          [
            id, label, coherenceCommit, engineKind, upstreamCommit, patchDiff?.sha256 ?? null,
            gitBundle.sha256, codeManifest.sha256, pythonLock.sha256, pythonWheels.sha256,
            webLock?.sha256 ?? null, webPackages?.sha256 ?? null, wrapperBundle.sha256,
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
      throw new AppError(`Input version contains conflicting paths (${clashes[0].kind}).`, 409, 'PATH_CLASH');
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
    priorDecisionCommitId = null,
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
      statementDate, origin, inputVersionId, priorDecisionCommitId, engineVersionId,
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

        const ovRes = await tx.query(
          `SELECT file_sha256 FROM coherence.input_entries
           WHERE input_version_id = $1::uuid AND mac_key = 'overlay/overlay.csv'`,
          [resolvedInputId],
        );
        const priorApprovalsSha256 = ovRes.rows[0]?.file_sha256 ?? null;

        let resolvedPriorDecisionCommitId = priorDecisionCommitId;
        if (!resolvedPriorDecisionCommitId && !priorApprovalsSha256 && (origin === 'app' || origin === 'trial')) {
          const headRes = await tx.query('SELECT coherence.standing_decision_head_as_of(NULL) AS id');
          resolvedPriorDecisionCommitId = headRes.rows[0]?.id ?? null;
        }

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
          priorDecisionCommitId: resolvedPriorDecisionCommitId,
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
          result: {
            runId,
            stepRequestId: requestId,
            statementDate,
            folderNumber,
            origin,
            priorDecisionCommitId: resolvedPriorDecisionCommitId,
          },
          commitments,
        };
        const je = await writeJournal(body);

        await tx.query(
          `INSERT INTO coherence.runs (
             id, statement_date, folder_number, origin, input_version_id, prior_approvals_sha256,
             prior_decision_commit_id, engine_version_id, emit_mode, emit_display, emit_keep, emit_no_manager,
             replays_run_id, compared_run_id, rerun_reason, source_folder, journal_seq
           ) VALUES (
             $1::uuid, $2::date, $3, $4, $5::uuid, $6,
             $7::uuid, $8::uuid, $9, $10, $11::text[], $12::text[],
             $13::uuid, $14::uuid, $15, NULL, $16
           )`,
          [
            runId, statementDate, folderNumber, origin, resolvedInputId, priorApprovalsSha256,
            resolvedPriorDecisionCommitId, engineVersionId, mode, display, keep, noManager,
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
    queueItems = [],
    generatedOverlays = [],
    emitMaterializationInput = null,
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
    const normalizedQueueItems = queueItems.map((q, idx) => ({
      attemptEventId: eventId,
      itemOrder: Number(q.itemOrder ?? q.item_order ?? (idx + 1)),
      runId,
      surface: q.surface ?? step,
      recordId: q.recordId ?? q.record_id,
      caseKind: q.caseKind ?? q.case_kind ?? q.case ?? null,
      subtype: q.subtype ?? null,
      entity: q.entity ?? null,
      npn: q.npn ?? null,
      amount: q.amount ?? null,
      entityFrom: q.entityFrom ?? q.entity_from ?? null,
      npnFrom: q.npnFrom ?? q.npn_from ?? null,
      needsReconfirm: Boolean(q.needsReconfirm ?? q.needs_reconfirm),
    }));
    const normalizedGenOverlays = generatedOverlays.map((g) => ({
      id: g.id || randomUUID(),
      decisionCommitId: g.decisionCommitId ?? g.decision_commit_id,
      runId,
      purpose: g.purpose,
      attemptEventId: eventId,
      headerContract: g.headerContract ?? g.header_contract,
      rowCount: Number(g.rowCount ?? g.row_count),
      storeKind: 'company_data',
      fileSha256: g.fileSha256 ?? g.file_sha256,
    }));
    const artifactsSha256 = hashArtifacts(normalizedArtifacts);
    const nextStep = continueToNextStep
      ? (step === 'assign' ? 'attribute' : step === 'attribute' ? 'bible' : null)
      : null;
    const payload = {
      runId, step, attemptNo, born, logFileSha256: logFile?.sha256 ?? null,
      artifactCount: normalizedArtifacts.length, artifactsSha256, nextStep,
      queueItemCount: normalizedQueueItems.length,
      generatedOverlayCount: normalizedGenOverlays.length,
      hasEmitMaterialization: Boolean(emitMaterializationInput),
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
        let mat = null;
        if (emitMaterializationInput && step === 'emit') {
          mat = await prepareEmitMaterialization({
            db: tx,
            runId,
            attemptEventId: eventId,
            ...emitMaterializationInput,
          });
        }
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
          review_queue_items: normalizedQueueItems,
          generated_overlays: normalizedGenOverlays,
          step_requests: nextReqRows,
          ...(mat ? {
            statement_batches: [mat.statementBatch],
            statement_agency_lines: mat.agencyLines,
            statement_upline_lines: mat.uplineLines,
            run_materializations: [mat.runMaterialization],
            bob_policies: mat.bobPolicies,
            bob_policy_financials: mat.bobFinancials,
            coherent_ledger_rows: mat.ledgerRows,
          } : {}),
        });
        const body = {
          attemptEvent: { ...evRow, census },
          nextRequest: nextReqRows[0] ?? null,
          result: {
            attemptEventId: eventId,
            runId,
            step,
            attemptNo,
            nextStep,
            nextRequestId: nextStep ? nextRequestId : null,
            materialized: Boolean(mat),
            statementBatchId: mat ? mat.statementBatch.id : null,
          },
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
        if (normalizedQueueItems.length) await insertReviewQueueItemsBatch(tx, normalizedQueueItems, je.journalSeq);
        for (const g of normalizedGenOverlays) {
          await tx.query(
            `INSERT INTO coherence.generated_overlays (
               id, decision_commit_id, run_id, purpose, attempt_event_id,
               header_contract, row_count, store_kind, file_sha256, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6, $7, 'company_data', $8, $9)`,
            [g.id, g.decisionCommitId, g.runId, g.purpose, g.attemptEventId, g.headerContract, g.rowCount, g.fileSha256, String(je.journalSeq)],
          );
        }
        if (mat) {
          await insertMaterializationPayload(tx, mat, je.journalSeq);
        }
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
            throw new AppError('Emit retry requires an existing Emit confirmation for the current Adjust review.', 409, 'MISSING_EMIT_CONFIRMATION');
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
   * Non-blocking review submission: validates actor, run, and expectedJournalSeq, stages unverified
   * bytes outside objects/<sha256>, and queues a pending review_submissions row for the worker.
   */
  async function submitReview({ actor, commandKey, expectedJournalSeq, runId, surface, csvBytes, submissionId = randomUUID() }) {
    assertCanWrite(actor, 'submit_review', { companySlug });
    if (!['bible', 'adjust'].includes(surface)) {
      throw new AppError('Review surface must be bible or adjust.', 400, 'INVALID_SURFACE');
    }
    if (typeof commandKey !== 'string' || !commandKey.length) {
      throw new AppError('Review submission requires commandKey.', 400, 'MISSING_COMMAND_KEY');
    }
    if (!Number.isInteger(Number(expectedJournalSeq)) || Number(expectedJournalSeq) < 0) {
      throw new AppError('Review submission requires expectedJournalSeq.', 400, 'MISSING_JOURNAL_SEQ');
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
        throw new AppError('Command key already used with a different review submission.', 409, 'COMMAND_KEY_CONFLICT');
      }

      const runSeqRes = await tx.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS latest', [runId]);
      if (Number(runSeqRes.rows[0].latest) > Number(expectedJournalSeq)) {
        throw new AppError('This run changed since the review page loaded; reload before saving.', 409, 'STALE_JOURNAL_POSITION');
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
   * Finalizes a worker-checked review submission atomically in one SERIALIZABLE transaction
   * on the worker's slot connection.
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

      // Re-verify expected_journal_seq inside the acceptance transaction to reject runs modified while queued.
      const runSeqRes = await tx.query('SELECT coherence.run_latest_journal_seq($1::uuid) AS latest', [sub.run_id]);
      if (Number(runSeqRes.rows[0].latest) > Number(sub.expected_journal_seq)) {
        throw new AppError('This run changed while the review submission was waiting.', 409, 'STALE_JOURNAL_POSITION');
      }

      const attemptRes = await tx.query(
        'SELECT coherence.current_finished_attempt($1::uuid, $2) AS ev_id',
        [sub.run_id, sub.surface],
      );
      const attemptEventId = attemptRes.rows[0]?.ev_id;
      if (!attemptEventId) {
        throw new AppError(`No current finished ${sub.surface} attempt exists for this run.`, 409, 'NO_FINISHED_ATTEMPT');
      }

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
        approvals_files: needAf
          ? [{
            fileSha256: storedFile.sha256,
            headerKind,
            rowCount,
            extendsSha256,
            sharedRowCount,
            addedRowsSha256,
          }]
          : [],
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
    reason = null,
    provenance = null,
  }) {
    const payload = provenance != null || reason != null
      ? { runId, typedPhrase, ...(reason != null ? { reason } : {}), ...(provenance != null ? { provenance } : {}) }
      : { runId, typedPhrase };
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
        if (!emitEvId) throw new AppError('Run has not finished Emit.', 409, 'EMIT_NOT_FINISHED');

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
        if (parentEntries.some((r) => normalizeMacKey(r.rel_path) === normalizeMacKey(sentRelPath))) {
          throw new AppError(`Standing input already contains ${sentRelPath}.`, 409, 'SENT_ALREADY_IN_STANDING_INPUT');
        }
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
          reason: reason || `Record statement ${statementDate} as sent`,
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
          ...(provenance != null ? { sentProvenance: provenance } : {}),
          result: { carryId, publishedInputVersionId: inputVersionId, statementDate, fileSha256, ...(provenance != null ? { sentProvenance: provenance } : {}) },
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
        if (!emitEvId) throw new AppError('Run has not finished Emit.', 409, 'EMIT_NOT_FINISHED');

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

  function safeDecisionTimestamp(primary, fallbackA, fallbackB) {
    for (const candidate of [primary, fallbackA, fallbackB]) {
      if (candidate == null || candidate === '') continue;
      try {
        return formatTimestampUtcUs(candidate);
      } catch {}
    }
    return formatTimestampUtcUs(new Date());
  }

  async function importHistoricalRun({
    actor,
    commandKey,
    run,
    inputVersion,
    inputEntries = [],
    approvalsFiles = [],
    decisionCommits = [],
    decisions = [],
    generatedOverlays = [],
    reviewQueueItems = [],
    stepAttempts = [],
    reviewSaves = [],
    storedFiles = [],
    extraImportedFiles = [],
    abandonment = null,
  }) {
    const payload = {
      origin: run.origin,
      sourceFolder: run.sourceFolder,
      statementDate: run.statementDate,
      inputEntriesSha256: hashInputEntries(inputEntries),
      steps: stepAttempts.map((s) => s.step),
      ...(decisionCommits.length ? { decisionCommitCount: decisionCommits.length } : {}),
      ...(extraImportedFiles.length ? { extraImportedFileCount: extraImportedFiles.length } : {}),
      ...(abandonment ? { abandoned: true } : {}),
    };
    return executeJournalCommand({
      actor,
      commandKind: 'import_historical_run',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
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
          priorDecisionCommitId: run.priorDecisionCommitId ?? null,
          engineVersionId: run.engineVersionId ?? null,
          emitMode: run.emitMode || 'coherence',
          emitDisplay: run.emitDisplay ?? null,
          emitKeep: run.emitKeep ?? [],
          emitNoManager: run.emitNoManager ?? [],
          replaysRunId: null,
          comparedRunId: null,
          rerunReason: run.rerunReason ?? null,
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
          const startedOrig = st.startedAt ?? st.finishedAt ?? null;
          const finishedOrig = st.finishedAt ?? null;
          attemptEventRows.push({
            id: startId, runId, step: st.step, attemptNo, eventKind: 'started',
            stepRequestId: null, cancelRequestId: null, born: null, logFileSha256: null,
            artifactCount: null, artifactsSha256: null, originalAt: startedOrig ? formatTimestampUtcUs(startedOrig) : null, census: null,
          });
          attemptEventRows.push({
            id: finishId, runId, step: st.step, attemptNo, eventKind: 'finished',
            stepRequestId: null, cancelRequestId: null, born: st.born ?? null,
            logFileSha256: st.logFileSha256 ?? null,
            artifactCount: stepArts.length, artifactsSha256: artsSha,
            originalAt: finishedOrig ? formatTimestampUtcUs(finishedOrig) : null, census: st.census ?? {},
          });
          allArtifacts.push(...stepArts);
          finishedIdByStep.set(st.step, finishId);
        }

        const saveRows = [];
        for (const rs of reviewSaves) {
          const attemptEventId = rs.attemptEventId || finishedIdByStep.get(rs.surface);
          if (!attemptEventId) continue;
          const rawSaveOrig = rs.originalAt ?? rs.original_at ?? null;
          saveRows.push({
            id: rs.id || randomUUID(),
            runId,
            surface: rs.surface,
            attemptEventId,
            approvalsFileSha256: rs.approvalsFileSha256 ?? null,
            decisionCommitId: rs.decisionCommitId ?? null,
            imported: true,
            originalAt: rawSaveOrig ? formatTimestampUtcUs(rawSaveOrig) : null,
            submissionId: null,
          });
        }
        const insertedSaveIds = new Set(saveRows.map((s) => s.id));

        const queueItemRows = [];
        for (const q of reviewQueueItems) {
          const attemptEventId = q.attemptEventId || finishedIdByStep.get(q.attemptStep || q.surface);
          if (!attemptEventId) continue;
          queueItemRows.push({
            attemptEventId,
            itemOrder: Number(q.itemOrder ?? q.item_order),
            runId,
            surface: q.surface,
            recordId: q.recordId ?? q.record_id,
            caseKind: q.caseKind ?? q.case_kind ?? null,
            subtype: q.subtype ?? null,
            entity: q.entity ?? null,
            npn: q.npn ?? null,
            amount: q.amount ?? null,
            entityFrom: q.entityFrom ?? q.entity_from ?? null,
            npnFrom: q.npnFrom ?? q.npn_from ?? null,
            needsReconfirm: Boolean(q.needsReconfirm ?? q.needs_reconfirm),
          });
        }

        const nowIso = formatTimestampUtcUs(new Date());
        const normOpt = (v) => (v == null || v === '' ? null : String(v));
        const decisionRows = decisions.map((d) => {
          const resolvedSaveId = d.reviewSaveId && insertedSaveIds.has(d.reviewSaveId) ? d.reviewSaveId : null;
          const committedAtRaw = normOpt(d.committedAtRaw ?? d.committed_at_raw ?? d.committed_at ?? d.committedAt);
          return {
            id: d.id || randomUUID(),
            decisionCommitId: d.decisionCommitId ?? d.decision_commit_id,
            rowOrder: Number(d.rowOrder ?? d.row_order),
            runId: d.runId === '__THIS_RUN__' || d.attachToRun ? runId : (d.runId ?? d.run_id ?? runId),
            reviewSaveId: resolvedSaveId,
            surface: resolvedSaveId ? (d.surface ?? null) : (d.surface ?? null),
            recordId: String(d.recordId ?? d.record_id),
            replacesDecisionId: d.replacesDecisionId ?? d.replaces_decision_id ?? null,
            disposition: String(d.disposition ?? 'CONFIRM'),
            agent: normOpt(d.agent),
            agency: normOpt(d.agency),
            policy: normOpt(d.policy),
            book: normOpt(d.book),
            month: normOpt(d.month),
            status: normOpt(d.status),
            note: normOpt(d.note),
            approvedAmount: normOpt(d.approvedAmount ?? d.approved_amount),
            approvedAgency: normOpt(d.approvedAgency ?? d.approved_agency),
            approvedAgent: normOpt(d.approvedAgent ?? d.approved_agent),
            approvedAgencyFrom: normOpt(d.approvedAgencyFrom ?? d.approved_agency_from),
            approvedAgentFrom: normOpt(d.approvedAgentFrom ?? d.approved_agent_from),
            decidedBy: String(d.decidedBy ?? d.decided_by ?? 'historical_import'),
            actingFor: normOpt(d.actingFor ?? d.acting_for ?? null),
            decidedAt: safeDecisionTimestamp(d.decidedAt ?? d.decided_at, committedAtRaw, d.originalAt ?? nowIso),
            committedAtRaw,
            imported: true,
          };
        });

        const decisionsByCommit = new Map();
        for (const d of decisionRows) {
          if (!decisionsByCommit.has(d.decisionCommitId)) decisionsByCommit.set(d.decisionCommitId, []);
          decisionsByCommit.get(d.decisionCommitId).push(d);
        }

        const commitRows = decisionCommits.map((dc) => {
          const rowsForCommit = decisionsByCommit.get(dc.id) || [];
          return {
            id: dc.id,
            parentCommitId: dc.parentCommitId ?? dc.parent_commit_id ?? null,
            commitKind: dc.commitKind ?? dc.commit_kind ?? 'historical_overlay',
            headerContract: dc.headerContract ?? dc.header_contract ?? 'v2',
            addedDecisionCount: rowsForCommit.length,
            cumulativeDecisionCount: Number(dc.cumulativeDecisionCount ?? dc.cumulative_decision_count),
            addedDecisionsSha256: hashDecisions(rowsForCommit),
            imported: true,
            originalAt: (dc.originalAt ?? dc.original_at) ? safeDecisionTimestamp(dc.originalAt ?? dc.original_at, null, nowIso) : null,
          };
        });

        const overlayReceiptRows = generatedOverlays.map((go) => ({
          id: go.id || randomUUID(),
          decisionCommitId: go.decisionCommitId ?? go.decision_commit_id,
          runId,
          purpose: go.purpose,
          attemptEventId: go.attemptEventId || (go.attemptStep ? (finishedIdByStep.get(go.attemptStep) ?? null) : null),
          headerContract: go.headerContract ?? go.header_contract ?? 'v2',
          rowCount: Number(go.rowCount ?? go.row_count),
          storeKind: 'company_data',
          fileSha256: go.fileSha256 ?? go.file_sha256,
        }));

        const extraImportedRows = (extraImportedFiles || []).map((f) => {
          const meta = f.metadata && typeof f.metadata === 'object' ? { ...f.metadata } : {};
          if (meta.runId === '__THIS_RUN__') meta.runId = runId;
          const rawOrig = f.originalAt ?? f.original_at ?? null;
          return {
            id: f.id || randomUUID(),
            area: f.area || 'other',
            relPath: f.relPath,
            artifactKind: f.artifactKind || 'data',
            storeKind: f.storeKind || 'company_data',
            fileSha256: f.fileSha256,
            originalAt: rawOrig ? formatTimestampUtcUs(rawOrig) : null,
            metadata: meta,
          };
        });

        const abandonmentRows = abandonment
          ? [{
            id: abandonment.id || randomUUID(),
            runId,
            typedPhrase: abandonment.typedPhrase || `abandon ${run.statementDate}`,
            reason: abandonment.reason || `Imported abandoned run from ${run.sourceFolder}`,
          }]
          : [];

        const commitments = buildCommitments({
          stored_files: newFiles,
          approvals_files: afToInsert,
          approval_rows: arToInsert,
          decision_commits: commitRows,
          decisions: decisionRows,
          generated_overlays: overlayReceiptRows,
          review_queue_items: queueItemRows,
          input_versions: [ivMeta],
          input_entries: entryRows,
          runs: [runRow],
          step_attempt_events: attemptEventRows,
          artifacts: allArtifacts,
          review_saves: saveRows,
          ...(abandonmentRows.length ? { abandonments: abandonmentRows } : {}),
          ...(extraImportedRows.length ? { imported_files: extraImportedRows } : {}),
        });
        const body = {
          importedRun: {
            runId,
            origin: run.origin,
            sourceFolder: run.sourceFolder,
            statementDate: run.statementDate,
            ...(abandonmentRows.length ? { abandoned: true } : {}),
          },
          result: {
            runId,
            inputVersionId: ivId,
            alreadyImported: false,
            abandoned: abandonmentRows.length > 0,
            steps: stepAttempts.length,
            reviewSaves: saveRows.length,
            decisionCommits: commitRows.length,
            decisions: decisionRows.length,
            generatedOverlays: overlayReceiptRows.length,
          },
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

        for (const dc of commitRows) {
          await tx.query(
            `INSERT INTO coherence.decision_commits (
               id, parent_commit_id, commit_kind, header_contract,
               added_decision_count, cumulative_decision_count, added_decisions_sha256,
               imported, original_at, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, true, $8::timestamptz, $9)`,
            [
              dc.id, dc.parentCommitId, dc.commitKind, dc.headerContract,
              dc.addedDecisionCount, dc.cumulativeDecisionCount, dc.addedDecisionsSha256,
              dc.originalAt, String(je.journalSeq),
            ],
          );
        }

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
             prior_decision_commit_id, engine_version_id, emit_mode, emit_display, emit_keep, emit_no_manager,
             replays_run_id, compared_run_id, rerun_reason, source_folder, journal_seq
           ) VALUES (
             $1::uuid, $2::date, $3, $4, $5::uuid, $6,
             $7::uuid, $8::uuid, $9, $10, $11::text[], $12::text[],
             NULL, NULL, $13, $14, $15
           )`,
          [
            runId, runRow.statementDate, runRow.folderNumber, runRow.origin, ivId, runRow.priorApprovalsSha256,
            runRow.priorDecisionCommitId, runRow.engineVersionId, runRow.emitMode, runRow.emitDisplay,
            runRow.emitKeep, runRow.emitNoManager, runRow.rerunReason, runRow.sourceFolder, String(je.journalSeq),
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
        if (queueItemRows.length) await insertReviewQueueItemsBatch(tx, queueItemRows, je.journalSeq);

        for (const rs of saveRows) {
          await tx.query(
            `INSERT INTO coherence.review_saves (
               id, run_id, surface, attempt_event_id, approvals_file_sha256, decision_commit_id,
               imported, original_at, submission_id, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6::uuid, true, $7::timestamptz, NULL, $8)`,
            [rs.id, runId, rs.surface, rs.attemptEventId, rs.approvalsFileSha256, rs.decisionCommitId, rs.originalAt, String(je.journalSeq)],
          );
        }

        if (decisionRows.length) await insertDecisionsBatch(tx, decisionRows, je.journalSeq);

        for (const go of overlayReceiptRows) {
          await tx.query(
            `INSERT INTO coherence.generated_overlays (
               id, decision_commit_id, run_id, purpose, attempt_event_id,
               header_contract, row_count, store_kind, file_sha256, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6, $7, 'company_data', $8, $9)`,
            [go.id, go.decisionCommitId, go.runId, go.purpose, go.attemptEventId, go.headerContract, go.rowCount, go.fileSha256, String(je.journalSeq)],
          );
        }

        for (const f of extraImportedRows) {
          await tx.query(
            `INSERT INTO coherence.imported_files (
               id, area, rel_path, artifact_kind, store_kind, file_sha256, original_at, metadata, journal_seq
             ) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::timestamptz, $8::jsonb, $9)`,
            [f.id, f.area, f.relPath, f.artifactKind, f.storeKind, f.fileSha256, f.originalAt, JSON.stringify(f.metadata), String(je.journalSeq)],
          );
        }

        for (const ab of abandonmentRows) {
          await tx.query(
            `INSERT INTO coherence.abandonments (id, run_id, typed_phrase, reason, journal_seq)
             VALUES ($1::uuid, $2::uuid, $3, $4, $5)`,
            [ab.id, ab.runId, ab.typedPhrase, ab.reason, String(je.journalSeq)],
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
            const rawOriginalAt = f.originalAt ?? f.original_at ?? null;
            toInsert.push({
              id: f.id || randomUUID(),
              area: f.area,
              relPath: f.relPath,
              artifactKind: f.artifactKind || 'data',
              storeKind: f.storeKind || 'company_data',
              fileSha256: f.fileSha256,
              originalAt: rawOriginalAt ? formatTimestampUtcUs(rawOriginalAt) : null,
              metadata: f.metadata || {},
            });
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

  function normalizeLiveDecisionInput(raw, index) {
    if (!raw || typeof raw !== 'object') {
      throw new AppError(`Decision at position ${index + 1} must be an object.`, 400, 'INVALID_DECISION');
    }
    const recordId = String(raw.recordId ?? raw.record_id ?? '');
    if (!recordId) throw new AppError(`Decision at position ${index + 1} requires a recordId.`, 400, 'INVALID_DECISION');
    const disposition = String(raw.disposition ?? '').trim();
    if (!LIVE_DISPOSITIONS.includes(disposition)) {
      throw new AppError(`Live decision disposition must be CONFIRM or CORRECT.`, 400, 'INVALID_DECISION');
    }
    const normOpt = (v) => (v == null || v === '' ? null : String(v));
    const policy = normOpt(raw.policy);
    const month = normOpt(raw.month);
    if (policy !== null || month !== null) {
      throw new AppError('Live decisions cannot set legacy policy or month columns.', 400, 'INVALID_DECISION');
    }
    const agent = normOpt(raw.agent);
    const agency = normOpt(raw.agency);
    const book = normOpt(raw.book);
    const status = normOpt(raw.status);
    if (status !== null && !POLICY_STATUS_SET.has(status)) {
      throw new AppError(`Invalid policy status value on decision ${index + 1}.`, 400, 'INVALID_DECISION');
    }
    if (disposition === 'CONFIRM' && (agent !== null || agency !== null || book !== null || status !== null)) {
      throw new AppError('CONFIRM decisions cannot carry agent, agency, book, or status edits.', 400, 'INVALID_DECISION');
    }
    if (disposition === 'CORRECT' && agent === null && agency === null && book === null && status === null) {
      throw new AppError('CORRECT decisions must specify at least one of agent, agency, book, or status.', 400, 'INVALID_DECISION');
    }
    const approvedAmount = normOpt(raw.approvedAmount ?? raw.approved_amount);
    if (approvedAmount !== null && !MONEY_RE.test(approvedAmount)) {
      throw new AppError('approvedAmount must be formatted to two decimal places.', 400, 'INVALID_DECISION');
    }
    return {
      id: raw.id || randomUUID(),
      recordId,
      disposition,
      agent,
      agency,
      policy: null,
      book,
      month: null,
      status,
      note: normOpt(raw.note),
      approvedAmount,
      approvedAgency: normOpt(raw.approvedAgency ?? raw.approved_agency),
      approvedAgent: normOpt(raw.approvedAgent ?? raw.approved_agent),
      approvedAgencyFrom: normOpt(raw.approvedAgencyFrom ?? raw.approved_agency_from),
      approvedAgentFrom: normOpt(raw.approvedAgentFrom ?? raw.approved_agent_from),
      committedAtRaw: normOpt(raw.committedAtRaw ?? raw.committed_at_raw ?? raw.committed_at ?? raw.committedAt),
      decidedAt: raw.decidedAt ?? raw.decided_at ?? null,
    };
  }

  async function recordDecisionBaseline({
    actor,
    commandKey,
    decisionCommitId = randomUUID(),
    parentCommitId = null,
    commitKind = 'historical_baseline',
    headerContract = 'v2',
    imported = true,
    originalAt = null,
    decisions = [],
  }) {
    if (!['historical_baseline', 'historical_overlay'].includes(commitKind)) {
      throw new AppError('Baseline commitKind must be historical_baseline or historical_overlay.', 400, 'INVALID_COMMIT_KIND');
    }
    if (!['v1', 'v2'].includes(headerContract)) {
      throw new AppError('headerContract must be v1 or v2.', 400, 'INVALID_HEADER_CONTRACT');
    }
    if (!Array.isArray(decisions)) {
      throw new AppError('decisions must be an array.', 400, 'INVALID_DECISIONS');
    }
    const payload = { parentCommitId, commitKind, headerContract, imported: Boolean(imported), originalAt, decisionCount: decisions.length };
    return executeJournalCommand({
      actor,
      commandKind: 'record_decision_baseline',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        let parentCumulative = 0;
        const headByKey = new Map();
        if (parentCommitId) {
          const pRes = await tx.query(
            'SELECT cumulative_decision_count FROM coherence.decision_commits WHERE id = $1::uuid',
            [parentCommitId],
          );
          if (pRes.rows.length === 0) throw new AppError('Parent decision commit not found.', 404, 'DECISION_COMMIT_NOT_FOUND');
          parentCumulative = Number(pRes.rows[0].cumulative_decision_count);
          const keys = [...new Set(decisions.map((d) => String(d.recordId ?? d.record_id ?? '')).filter(Boolean))];
          if (keys.length > 0) {
            const curRes = await tx.query(
              'SELECT record_id, id FROM coherence.decisions_current($1::uuid) WHERE record_id = ANY($2::text[])',
              [parentCommitId, keys],
            );
            for (const row of curRes.rows) headByKey.set(row.record_id, row.id);
          }
        }

        const nowIso = formatTimestampUtcUs(new Date());
        const normOpt = (v) => (v == null || v === '' ? null : String(v));
        const decisionRows = decisions.map((d, idx) => {
          const id = d.id || randomUUID();
          const recordId = String(d.recordId ?? d.record_id ?? '');
          if (!recordId) throw new AppError(`Baseline decision ${idx + 1} requires recordId.`, 400, 'INVALID_DECISION');
          const replacesDecisionId = headByKey.get(recordId) ?? null;
          headByKey.set(recordId, id);
          const committedAtRaw = normOpt(d.committedAtRaw ?? d.committed_at_raw ?? d.committed_at ?? d.committedAt);
          const decidedAt = safeDecisionTimestamp(d.decidedAt ?? d.decided_at, committedAtRaw, originalAt ?? nowIso);
          return {
            id,
            decisionCommitId,
            rowOrder: idx + 1,
            runId: d.runId ?? d.run_id ?? null,
            reviewSaveId: null,
            surface: d.surface ?? null,
            recordId,
            replacesDecisionId,
            disposition: String(d.disposition ?? 'CONFIRM'),
            agent: normOpt(d.agent),
            agency: normOpt(d.agency),
            policy: normOpt(d.policy),
            book: normOpt(d.book),
            month: normOpt(d.month),
            status: normOpt(d.status),
            note: normOpt(d.note),
            approvedAmount: headerContract === 'v1' ? null : normOpt(d.approvedAmount ?? d.approved_amount),
            approvedAgency: headerContract === 'v1' ? null : normOpt(d.approvedAgency ?? d.approved_agency),
            approvedAgent: headerContract === 'v1' ? null : normOpt(d.approvedAgent ?? d.approved_agent),
            approvedAgencyFrom: headerContract === 'v1' ? null : normOpt(d.approvedAgencyFrom ?? d.approved_agency_from),
            approvedAgentFrom: headerContract === 'v1' ? null : normOpt(d.approvedAgentFrom ?? d.approved_agent_from),
            decidedBy: String(d.decidedBy ?? d.decided_by ?? actor.id),
            actingFor: normOpt(d.actingFor ?? d.acting_for ?? actor.actingFor),
            decidedAt: formatTimestampUtcUs(decidedAt),
            committedAtRaw,
            imported: Boolean(imported),
          };
        });

        const addedDecisionsSha256 = hashDecisions(decisionRows);
        const cumulativeDecisionCount = parentCumulative + decisionRows.length;
        const commitRow = {
          id: decisionCommitId,
          parentCommitId,
          commitKind,
          headerContract,
          addedDecisionCount: decisionRows.length,
          cumulativeDecisionCount,
          addedDecisionsSha256,
          imported: Boolean(imported),
          originalAt: originalAt ? formatTimestampUtcUs(originalAt) : null,
        };
        const commitments = buildCommitments({
          decision_commits: [commitRow],
          decisions: decisionRows,
        });
        const body = {
          decisionCommit: commitRow,
          result: {
            decisionCommitId,
            addedDecisionCount: decisionRows.length,
            cumulativeDecisionCount,
            addedDecisionsSha256,
          },
          commitments,
        };
        const je = await writeJournal(body);

        await tx.query(
          `INSERT INTO coherence.decision_commits (
             id, parent_commit_id, commit_kind, header_contract,
             added_decision_count, cumulative_decision_count, added_decisions_sha256,
             imported, original_at, journal_seq
           ) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10)`,
          [
            decisionCommitId, parentCommitId, commitKind, headerContract,
            decisionRows.length, cumulativeDecisionCount, addedDecisionsSha256,
            Boolean(imported), commitRow.originalAt, String(je.journalSeq),
          ],
        );
        if (decisionRows.length) await insertDecisionsBatch(tx, decisionRows, je.journalSeq);
        return { ...je, body, result: body.result };
      },
    });
  }

  /**
   * Synchronous review save: writes new or changed decisions in one SERIALIZABLE transaction,
   * verifies actor permissions (refusing View-As), rejects stale expectedJournalSeq or duplicate saves,
   * maintains the database-verified replaces_decision_id chain, deletes review drafts, and queues Adjust on Bible save.
   */
  async function saveReviewDecisions({
    actor,
    commandKey,
    expectedJournalSeq,
    runId,
    surface,
    decisions = [],
    decisionCommitId = randomUUID(),
    reviewSaveId = randomUUID(),
    adjustRequestId = randomUUID(),
    headerContract = 'v2',
  }) {
    if (!['bible', 'adjust'].includes(surface)) {
      throw new AppError('Review surface must be bible or adjust.', 400, 'INVALID_SURFACE');
    }
    if (expectedJournalSeq === null || expectedJournalSeq === undefined
        || !Number.isInteger(Number(expectedJournalSeq)) || Number(expectedJournalSeq) < 0) {
      throw new AppError('Saving a review requires a valid expectedJournalSeq.', 400, 'MISSING_JOURNAL_SEQ');
    }
    if (!Array.isArray(decisions)) {
      throw new AppError('decisions must be an array.', 400, 'INVALID_DECISIONS');
    }
    if (headerContract !== 'v2') {
      throw new AppError('Live review saves must use the v2 decision contract.', 400, 'INVALID_HEADER_CONTRACT');
    }

    const normalizedInputs = decisions.map(normalizeLiveDecisionInput);
    const seenKeys = new Set();
    for (const d of normalizedInputs) {
      if (seenKeys.has(d.recordId)) {
        throw new AppError('A live review save cannot include the same decision key more than once.', 409, 'DUPLICATE_DECISION_KEY');
      }
      seenKeys.add(d.recordId);
    }

    const payload = {
      runId,
      surface,
      expectedJournalSeq: Number(expectedJournalSeq),
      decisions: normalizedInputs.map((d) => ({
        recordId: d.recordId,
        disposition: d.disposition,
        agent: d.agent,
        agency: d.agency,
        book: d.book,
        status: d.status,
        note: d.note,
        approvedAmount: d.approvedAmount,
        approvedAgency: d.approvedAgency,
        approvedAgent: d.approvedAgent,
        approvedAgencyFrom: d.approvedAgencyFrom,
        approvedAgentFrom: d.approvedAgentFrom,
      })),
    };

    return executeJournalCommand({
      actor,
      commandKind: 'save_review_decisions',
      commandKey,
      payload,
      expectedJournalSeq: Number(expectedJournalSeq),
      scopeRunId: runId,
      buildAndWrite: async (tx, writeJournal) => {
        const runRes = await tx.query(
          'SELECT id, prior_decision_commit_id FROM coherence.runs WHERE id = $1::uuid',
          [runId],
        );
        if (runRes.rows.length === 0) throw new AppError('Run not found.', 404, 'RUN_NOT_FOUND');
        const runRow = runRes.rows[0];

        const attemptRes = await tx.query(
          'SELECT coherence.current_finished_attempt($1::uuid, $2) AS ev_id',
          [runId, surface],
        );
        const attemptEventId = attemptRes.rows[0]?.ev_id;
        if (!attemptEventId) {
          throw new AppError(`No current finished ${surface} attempt exists for this run.`, 409, 'NO_FINISHED_ATTEMPT');
        }

        const priorSameAttemptRes = await tx.query(
          `SELECT id, decision_commit_id
           FROM coherence.review_saves
           WHERE run_id = $1::uuid AND surface = $2 AND attempt_event_id = $3::uuid
             AND decision_commit_id IS NOT NULL
           ORDER BY journal_seq DESC
           LIMIT 1`,
          [runId, surface, attemptEventId],
        );
        const priorSameAttempt = priorSameAttemptRes.rows[0] || null;

        if (priorSameAttempt && normalizedInputs.length === 0) {
          throw new AppError('Duplicate review save refused: no new or changed decisions for this attempt.', 409, 'DUPLICATE_REVIEW_SAVE');
        }

        let parentCommitId = null;
        if (priorSameAttempt) {
          parentCommitId = priorSameAttempt.decision_commit_id;
        } else if (surface === 'bible') {
          parentCommitId = runRow.prior_decision_commit_id ?? null;
        } else {
          const bibleSaveRes = await tx.query(
            `SELECT decision_commit_id
             FROM coherence.review_saves
             WHERE run_id = $1::uuid AND surface = 'bible'
               AND attempt_event_id = coherence.current_finished_attempt($1::uuid, 'bible')
               AND decision_commit_id IS NOT NULL
             ORDER BY journal_seq DESC
             LIMIT 1`,
            [runId],
          );
          if (bibleSaveRes.rows.length === 0) {
            throw new AppError('Adjust review requires a saved Bible decision commit first.', 409, 'MISSING_BIBLE_SAVE');
          }
          parentCommitId = bibleSaveRes.rows[0].decision_commit_id;
        }

        let parentCumulative = 0;
        const headByKey = new Map();
        if (parentCommitId) {
          const pRes = await tx.query(
            'SELECT cumulative_decision_count FROM coherence.decision_commits WHERE id = $1::uuid',
            [parentCommitId],
          );
          if (pRes.rows.length === 0) throw new AppError('Parent decision commit not found.', 404, 'DECISION_COMMIT_NOT_FOUND');
          parentCumulative = Number(pRes.rows[0].cumulative_decision_count);
          if (normalizedInputs.length > 0) {
            const curRes = await tx.query(
              `SELECT id, record_id, disposition, agent, agency, book, status, note,
                      approved_amount, approved_agency, approved_agent,
                      approved_agency_from, approved_agent_from
               FROM coherence.decisions_current($1::uuid)
               WHERE record_id = ANY($2::text[])`,
              [parentCommitId, normalizedInputs.map((d) => d.recordId)],
            );
            for (const row of curRes.rows) headByKey.set(row.record_id, row);
          }
        }

        if (priorSameAttempt && normalizedInputs.length > 0) {
          const allUnchanged = normalizedInputs.every((d) => {
            const prev = headByKey.get(d.recordId);
            if (!prev) return false;
            return (
              prev.disposition === d.disposition
              && (prev.agent ?? null) === d.agent
              && (prev.agency ?? null) === d.agency
              && (prev.book ?? null) === d.book
              && (prev.status ?? null) === d.status
              && (prev.note ?? null) === d.note
              && (prev.approved_amount ?? null) === d.approvedAmount
              && (prev.approved_agency ?? null) === d.approvedAgency
              && (prev.approved_agent ?? null) === d.approvedAgent
              && (prev.approved_agency_from ?? null) === d.approvedAgencyFrom
              && (prev.approved_agent_from ?? null) === d.approvedAgentFrom
            );
          });
          if (allUnchanged) {
            throw new AppError('Duplicate review save refused: submitted decisions are identical to the current saved review.', 409, 'DUPLICATE_REVIEW_SAVE');
          }
        }

        const decidedNow = formatTimestampUtcUs(new Date());
        const decisionRows = normalizedInputs.map((d, idx) => {
          const prev = headByKey.get(d.recordId);
          const ts = d.decidedAt ? formatTimestampUtcUs(d.decidedAt) : decidedNow;
          return {
            id: d.id,
            decisionCommitId,
            rowOrder: idx + 1,
            runId,
            reviewSaveId,
            surface,
            recordId: d.recordId,
            replacesDecisionId: prev ? prev.id : null,
            disposition: d.disposition,
            agent: d.agent,
            agency: d.agency,
            policy: null,
            book: d.book,
            month: null,
            status: d.status,
            note: d.note,
            approvedAmount: d.approvedAmount,
            approvedAgency: d.approvedAgency,
            approvedAgent: d.approvedAgent,
            approvedAgencyFrom: d.approvedAgencyFrom,
            approvedAgentFrom: d.approvedAgentFrom,
            decidedBy: actor.id,
            actingFor: actor.actingFor ?? null,
            decidedAt: ts,
            committedAtRaw: d.committedAtRaw ?? ts,
            imported: false,
          };
        });

        const supersededRows = [];
        const nextRequests = [];
        if (surface === 'bible') {
          const adjRes = await tx.query(
            `SELECT id, attempt_no FROM coherence.step_attempt_events
             WHERE id = coherence.current_finished_attempt($1::uuid, 'adjust')`,
            [runId],
          );
          if (adjRes.rows.length > 0) {
            supersededRows.push({
              id: randomUUID(),
              runId,
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
            runId,
            step: 'adjust',
            reason: 'bible_saved',
            emitConfirmationId: null,
          });
        }

        const addedDecisionsSha256 = hashDecisions(decisionRows);
        const cumulativeDecisionCount = parentCumulative + decisionRows.length;
        const commitRow = {
          id: decisionCommitId,
          parentCommitId,
          commitKind: 'review_save',
          headerContract,
          addedDecisionCount: decisionRows.length,
          cumulativeDecisionCount,
          addedDecisionsSha256,
          imported: false,
          originalAt: null,
        };
        const saveRow = {
          id: reviewSaveId,
          runId,
          surface,
          attemptEventId,
          approvalsFileSha256: null,
          decisionCommitId,
          imported: false,
          originalAt: null,
          submissionId: null,
        };
        const commitments = buildCommitments({
          decision_commits: [commitRow],
          review_saves: [saveRow],
          decisions: decisionRows,
          step_attempt_events: supersededRows,
          step_requests: nextRequests,
        });
        const body = {
          decisionCommit: commitRow,
          reviewSave: saveRow,
          addedDecisionCount: decisionRows.length,
          adjustRequestId: nextRequests[0]?.id ?? null,
          result: {
            reviewSaveId,
            decisionCommitId,
            runId,
            surface,
            addedDecisionCount: decisionRows.length,
            cumulativeDecisionCount,
            adjustRequestId: nextRequests[0]?.id ?? null,
          },
          commitments,
        };

        const je = await writeJournal(body);

        await tx.query(
          `INSERT INTO coherence.decision_commits (
             id, parent_commit_id, commit_kind, header_contract,
             added_decision_count, cumulative_decision_count, added_decisions_sha256,
             imported, original_at, journal_seq
           ) VALUES ($1::uuid, $2::uuid, 'review_save', $3, $4, $5, $6, false, NULL, $7)`,
          [
            decisionCommitId, parentCommitId, headerContract,
            decisionRows.length, cumulativeDecisionCount, addedDecisionsSha256,
            String(je.journalSeq),
          ],
        );

        await tx.query(
          `INSERT INTO coherence.review_saves (
             id, run_id, surface, attempt_event_id, approvals_file_sha256, decision_commit_id,
             imported, original_at, submission_id, journal_seq
           ) VALUES ($1::uuid, $2::uuid, $3, $4::uuid, NULL, $5::uuid, false, NULL, NULL, $6)`,
          [reviewSaveId, runId, surface, attemptEventId, decisionCommitId, String(je.journalSeq)],
        );

        if (decisionRows.length) await insertDecisionsBatch(tx, decisionRows, je.journalSeq);

        for (const s of supersededRows) {
          await tx.query(
            `INSERT INTO coherence.step_attempt_events (id, run_id, step, attempt_no, event_kind, journal_seq)
             VALUES ($1::uuid, $2::uuid, $3, $4, 'superseded', $5)`,
            [s.id, s.runId, s.step, s.attemptNo, String(je.journalSeq)],
          );
        }

        for (const req of nextRequests) {
          await tx.query(
            `INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
             VALUES ($1::uuid, $2::uuid, $3, $4, NULL, $5)`,
            [req.id, req.runId, req.step, req.reason, String(je.journalSeq)],
          );
        }

        return { ...je, body, result: body.result };
      },
    });
  }

  async function recordGeneratedOverlay({
    actor,
    commandKey,
    overlayId = randomUUID(),
    decisionCommitId,
    runId,
    purpose,
    attemptEventId = null,
    headerContract = 'v2',
    rowCount,
    storedFile,
  }) {
    if (!storedFile || (storedFile.storeKind ?? storedFile.store_kind) !== 'company_data') {
      throw new AppError('Generated overlay must be stored in company_data.', 403, 'INVALID_STORE');
    }
    const payload = { decisionCommitId, runId, purpose, attemptEventId, headerContract, rowCount: Number(rowCount), fileSha256: storedFile.sha256 };
    return executeJournalCommand({
      actor,
      commandKind: 'record_generated_overlay',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const newFiles = await filterNewStoredFiles(tx, [storedFile]);
        const row = {
          id: overlayId,
          decisionCommitId,
          runId,
          purpose,
          attemptEventId,
          headerContract,
          rowCount: Number(rowCount),
          storeKind: 'company_data',
          fileSha256: storedFile.sha256,
        };
        const commitments = buildCommitments({ stored_files: newFiles, generated_overlays: [row] });
        const body = { generatedOverlay: row, result: { overlayId, decisionCommitId, fileSha256: storedFile.sha256 }, commitments };
        const je = await writeJournal(body);
        if (newFiles.length) await insertStoredFilesBatch(tx, newFiles, je.journalSeq);
        await tx.query(
          `INSERT INTO coherence.generated_overlays (
             id, decision_commit_id, run_id, purpose, attempt_event_id,
             header_contract, row_count, store_kind, file_sha256, journal_seq
           ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6, $7, 'company_data', $8, $9)`,
          [overlayId, decisionCommitId, runId, purpose, attemptEventId, headerContract, Number(rowCount), storedFile.sha256, String(je.journalSeq)],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function carryDecisions({
    actor,
    commandKey,
    expectedJournalSeq = null,
    carryId = randomUUID(),
    runId,
    typedPhrase,
    receiptFileSha256 = null,
  }) {
    const payload = { runId, typedPhrase, receiptFileSha256 };
    return executeJournalCommand({
      actor,
      commandKind: 'carry_decisions',
      commandKey,
      payload,
      expectedJournalSeq,
      scopeRunId: runId,
      buildAndWrite: async (tx, writeJournal) => {
        const runRes = await tx.query(
          `SELECT id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date, prior_decision_commit_id
           FROM coherence.runs WHERE id = $1::uuid`,
          [runId],
        );
        if (runRes.rows.length === 0) throw new AppError('Run not found.', 404, 'RUN_NOT_FOUND');
        const { statement_date: statementDate, prior_decision_commit_id: priorCommitId } = runRes.rows[0];

        let carriedCommitId = null;
        for (const surf of ['adjust', 'bible']) {
          const sRes = await tx.query(
            `SELECT decision_commit_id FROM coherence.review_saves
             WHERE run_id = $1::uuid AND surface = $2
               AND attempt_event_id = coherence.current_finished_attempt($1::uuid, $2)
               AND decision_commit_id IS NOT NULL
             ORDER BY journal_seq DESC LIMIT 1`,
            [runId, surf],
          );
          if (sRes.rows.length > 0) {
            carriedCommitId = sRes.rows[0].decision_commit_id;
            break;
          }
        }
        carriedCommitId = carriedCommitId || priorCommitId;
        if (!carriedCommitId) {
          throw new AppError('Run has no decision commit to carry forward.', 409, 'MISSING_DECISION_COMMIT');
        }

        const standingRes = await tx.query('SELECT coherence.standing_decision_head_as_of(NULL) AS head');
        const standingHead = standingRes.rows[0]?.head ?? null;
        const nothingNew = Boolean(standingHead && standingHead === carriedCommitId);

        const carryRow = {
          id: carryId,
          runId,
          statementDate,
          carryKind: 'decisions',
          fileSha256: receiptFileSha256 ?? null,
          carriedDecisionCommitId: carriedCommitId,
          publishedInputVersionId: null,
          nothingNew,
          typedPhrase,
        };
        const commitments = buildCommitments({ carries: [carryRow] });
        const body = {
          carry: carryRow,
          result: { carryId, statementDate, carriedDecisionCommitId: carriedCommitId, nothingNew },
          commitments,
        };
        const je = await writeJournal(body);

        await tx.query(
          `INSERT INTO coherence.carries (
             id, run_id, statement_date, carry_kind, store_kind, file_sha256,
             carried_decision_commit_id, published_input_version_id, nothing_new, typed_phrase, journal_seq
           ) VALUES ($1::uuid, $2::uuid, $3::date, 'decisions', $4, $5, $6::uuid, NULL, $7, $8, $9)`,
          [
            carryId, runId, statementDate,
            receiptFileSha256 ? 'company_data' : null, receiptFileSha256 ?? null,
            carriedCommitId, nothingNew, typedPhrase, String(je.journalSeq),
          ],
        );
        return { ...je, body, result: body.result };
      },
    });
  }

  async function recordStatementBatch({
    actor,
    commandKey,
    batchId = randomUUID(),
    batchKind,
    statementDate,
    sourceFileName = null,
    sourceFile = null,
    reason,
    agencyLines = [],
    uplineLines = [],
  }) {
    if (!['historical_sent', 'method_correction'].includes(batchKind)) {
      throw new AppError('Standalone statement batchKind must be historical_sent or method_correction.', 400, 'INVALID_BATCH_KIND');
    }
    if (!isValidIsoDate(statementDate)) {
      throw new AppError('statementDate must be a valid ISO date.', 400, 'INVALID_DATE');
    }
    let agNet = 0n;
    const normAgency = agencyLines.map((l, idx) => {
      const amtCents = parseCents(l.amount);
      const grossCents = parseCents(l.grossComm ?? l.gross_comm ?? l.amount);
      agNet += amtCents;
      return {
        ...l,
        batchId,
        lineNo: Number(l.lineNo ?? l.line_no ?? (idx + 1)),
        statementDate,
        entryKind: l.entryKind ?? l.entry_kind ?? (batchKind === 'method_correction' ? 'method_correction' : 'historical_sent'),
        runAction: l.runAction ?? l.run_action ?? (batchKind === 'method_correction' ? 'CORRECTION' : 'SENT'),
        sourceFile: l.sourceFile ?? l.source_file ?? sourceFileName ?? `${batchKind}_${statementDate}`,
        sourceRowNo: Number(l.sourceRowNo ?? l.source_row_no ?? (idx + 1)),
        grossComm: formatCents(grossCents),
        amount: formatCents(amtCents),
      };
    });
    let upNet = 0n;
    const normUpline = uplineLines.map((l, idx) => {
      const amtCents = parseCents(l.amount);
      const grossCents = parseCents(l.grossComm ?? l.gross_comm ?? l.amount);
      upNet += amtCents;
      return {
        ...l,
        batchId,
        lineNo: Number(l.lineNo ?? l.line_no ?? (idx + 1)),
        statementDate,
        entryKind: l.entryKind ?? l.entry_kind ?? (batchKind === 'method_correction' ? 'method_correction' : 'historical_upline_derived'),
        runAction: l.runAction ?? l.run_action ?? (batchKind === 'method_correction' ? 'CORRECTION' : 'SENT'),
        sourceEntity: l.sourceEntity ?? l.source_entity ?? l.entity,
        markedSent: l.markedSent ?? l.marked_sent ?? false,
        sourceFile: l.sourceFile ?? l.source_file ?? sourceFileName ?? `${batchKind}_${statementDate}`,
        sourceRowNo: Number(l.sourceRowNo ?? l.source_row_no ?? (idx + 1)),
        grossComm: formatCents(grossCents),
        amount: formatCents(amtCents),
      };
    });
    const agencyLinesSha256 = hashStatementAgencyLines(normAgency);
    const uplineLinesSha256 = hashStatementUplineLines(normUpline);
    const batchRow = {
      id: batchId,
      batchKind,
      statementDate,
      runId: null,
      attemptEventId: null,
      sourceFileName,
      sourceFileSha256: sourceFile?.sha256 ?? null,
      reason,
      agencyLineCount: normAgency.length,
      agencyLinesSha256,
      agencyNetTotal: formatCents(agNet),
      uplineLineCount: normUpline.length,
      uplineLinesSha256,
      uplineNetTotal: formatCents(upNet),
    };
    const payload = { batchKind, statementDate, sourceFileName, sourceFileSha256: sourceFile?.sha256 ?? null, reason, agencyLinesSha256, uplineLinesSha256 };
    return executeJournalCommand({
      actor,
      commandKind: 'record_statement_batch',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const newFiles = sourceFile ? await filterNewStoredFiles(tx, [sourceFile]) : [];
        const commitments = buildCommitments({
          stored_files: newFiles,
          statement_batches: [batchRow],
          statement_agency_lines: normAgency,
          statement_upline_lines: normUpline,
        });
        const body = {
          statementBatch: batchRow,
          result: { batchId, agencyLineCount: normAgency.length, uplineLineCount: normUpline.length },
          commitments,
        };
        const je = await writeJournal(body);
        if (newFiles.length) await insertStoredFilesBatch(tx, newFiles, je.journalSeq);
        await tx.query(
          `INSERT INTO coherence.statement_batches (
             id, batch_kind, statement_date, run_id, attempt_event_id,
             source_file_name, source_store_kind, source_file_sha256, reason,
             agency_line_count, agency_lines_sha256, agency_net_total,
             upline_line_count, upline_lines_sha256, upline_net_total, journal_seq
           ) VALUES (
             $1::uuid, $2, $3::date, NULL, NULL,
             $4, $5, $6, $7,
             $8, $9, $10::numeric(14,2),
             $11, $12, $13::numeric(14,2), $14
           )`,
          [
            batchId, batchKind, statementDate,
            sourceFileName, sourceFile ? 'company_data' : null, sourceFile?.sha256 ?? null, reason,
            normAgency.length, agencyLinesSha256, batchRow.agencyNetTotal,
            normUpline.length, uplineLinesSha256, batchRow.uplineNetTotal, String(je.journalSeq),
          ],
        );
        if (normAgency.length) await insertStatementAgencyLinesBatch(tx, normAgency, je.journalSeq);
        if (normUpline.length) await insertStatementUplineLinesBatch(tx, normUpline, je.journalSeq);
        return { ...je, body, result: body.result };
      },
    });
  }

  /**
   * Loads a finished Emit run's canonical_bob.csv, coherent_ledger.csv, and statements_YYYYMMDD.csv
   * (plus optional emit_metadata.json and working/tx.csv) into the normalized PostgreSQL tables in one
   * SERIALIZABLE transaction, verifying every total ties and refusing any second load of the same run.
   */
  async function materializeEmit({
    actor,
    commandKey,
    runId,
    attemptEventId = null,
    canonicalBobCsv = null,
    coherentLedgerCsv = null,
    statementsCsv = null,
    emitMetadataJson = null,
    workingTxCsv = null,
    statementsFileName = null,
    statementsFileSha256 = null,
    statementBatchId = randomUUID(),
    reconciliationMode = 'strict_entity_ledger',
    columnMap = {},
  }) {
    const payload = {
      runId,
      attemptEventId,
      reconciliationMode,
      statementsFileName,
      statementsFileSha256,
    };
    return executeJournalCommand({
      actor,
      commandKind: 'materialize_emit',
      commandKey,
      payload,
      buildAndWrite: async (tx, writeJournal) => {
        const alreadyRes = await tx.query(
          'SELECT attempt_event_id FROM coherence.run_materializations WHERE run_id = $1::uuid',
          [runId],
        );
        if (alreadyRes.rows.length > 0) {
          throw new AppError('This run has already been materialized; a second load is refused.', 409, 'ALREADY_MATERIALIZED');
        }

        const runRes = await tx.query(
          `SELECT id, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date,
                  pg_catalog.to_char(statement_date, 'YYYYMMDD') AS stamp
           FROM coherence.runs WHERE id = $1::uuid`,
          [runId],
        );
        if (runRes.rows.length === 0) throw new AppError('Run not found.', 404, 'RUN_NOT_FOUND');
        const { statement_date: statementDate, stamp } = runRes.rows[0];

        let resolvedAttemptId = attemptEventId;
        if (!resolvedAttemptId) {
          const evRes = await tx.query("SELECT coherence.current_finished_attempt($1::uuid, 'emit') AS ev_id", [runId]);
          resolvedAttemptId = evRes.rows[0]?.ev_id ?? null;
        }
        if (!resolvedAttemptId) {
          throw new AppError('Cannot materialize Emit: run has no finished emit attempt.', 409, 'EMIT_NOT_FINISHED');
        }

        const readArtifactText = async (relCandidates) => {
          if (!stores?.dataStore) return null;
          for (const rel of relCandidates) {
            const artRes = await tx.query(
              `SELECT a.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
               FROM coherence.artifacts a
               JOIN coherence.stored_files sf ON sf.store_kind = a.store_kind AND sf.sha256 = a.file_sha256
               WHERE a.attempt_event_id = $1::uuid AND a.rel_path = $2 AND a.store_kind = 'company_data'`,
              [resolvedAttemptId, rel],
            );
            if (artRes.rows.length > 0) {
              const row = artRes.rows[0];
              const bytes = await stores.dataStore.readVerified(row.file_sha256, {
                byteSize: Number(row.byte_size), md5B64: row.md5_b64, crc32cB64: row.crc32c_b64,
              });
              return { text: bytes.toString('utf8'), sha256: row.file_sha256, relPath: rel };
            }
          }
          return null;
        };

        const defaultStmtRel = `emits/statements_${stamp}.csv`;
        const bobLoaded = canonicalBobCsv != null ? { text: canonicalBobCsv } : await readArtifactText(['emits/canonical_bob.csv']);
        const ledLoaded = coherentLedgerCsv != null ? { text: coherentLedgerCsv } : await readArtifactText(['emits/coherent_ledger.csv']);
        const stmtLoaded = statementsCsv != null ? { text: statementsCsv, sha256: statementsFileSha256 } : await readArtifactText([defaultStmtRel]);
        const metaLoaded = emitMetadataJson != null ? { text: emitMetadataJson } : await readArtifactText(['emits/emit_metadata.json', 'emits/policy_status_meta.json']);

        if (!bobLoaded || !ledLoaded || !stmtLoaded) {
          throw new AppError('Emit materialization requires canonical_bob.csv, coherent_ledger.csv, and statements file.', 422, 'MISSING_EMIT_FILES');
        }

        let resolvedWorkingTx = workingTxCsv;
        if (resolvedWorkingTx == null && stores?.dataStore) {
          const txArtRes = await tx.query(
            `SELECT a.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
             FROM coherence.artifacts a
             JOIN coherence.stored_files sf ON sf.store_kind = a.store_kind AND sf.sha256 = a.file_sha256
             WHERE a.attempt_event_id IN (
               coherence.current_finished_attempt($1::uuid, 'attribute'),
               coherence.current_finished_attempt($1::uuid, 'assign')
             ) AND a.rel_path = 'working/tx.csv' AND a.store_kind = 'company_data'
             ORDER BY a.journal_seq DESC LIMIT 1`,
            [runId],
          );
          if (txArtRes.rows.length > 0) {
            const row = txArtRes.rows[0];
            const bytes = await stores.dataStore.readVerified(row.file_sha256, {
              byteSize: Number(row.byte_size), md5B64: row.md5_b64, crc32cB64: row.crc32c_b64,
            }).catch(() => null);
            if (bytes) resolvedWorkingTx = bytes.toString('utf8');
          }
        }

        let resolvedStmtSha = stmtLoaded.sha256 ?? statementsFileSha256 ?? null;
        if (!resolvedStmtSha) {
          const stmtArtRes = await tx.query(
            `SELECT file_sha256 FROM coherence.artifacts
             WHERE attempt_event_id = $1::uuid AND rel_path = $2 AND store_kind = 'company_data'`,
            [resolvedAttemptId, defaultStmtRel],
          );
          resolvedStmtSha = stmtArtRes.rows[0]?.file_sha256 ?? null;
        }

        const mat = await prepareEmitMaterialization({
          db: tx,
          runId,
          attemptEventId: resolvedAttemptId,
          statementDate,
          canonicalBobCsv: bobLoaded.text,
          coherentLedgerCsv: ledLoaded.text,
          statementsCsv: stmtLoaded.text,
          emitMetadataJson: metaLoaded?.text ?? null,
          workingTxCsv: resolvedWorkingTx,
          statementsFileName: statementsFileName || `statements_${stamp}.csv`,
          statementsFileSha256: resolvedStmtSha,
          statementBatchId,
          reconciliationMode,
          columnMap,
        });

        const commitments = buildCommitments({
          statement_batches: [mat.statementBatch],
          statement_agency_lines: mat.agencyLines,
          statement_upline_lines: mat.uplineLines,
          run_materializations: [mat.runMaterialization],
          bob_policies: mat.bobPolicies,
          bob_policy_financials: mat.bobFinancials,
          coherent_ledger_rows: mat.ledgerRows,
        });
        const body = {
          runMaterialization: {
            attemptEventId: resolvedAttemptId,
            runId,
            statementDate,
            bobRowCount: mat.runMaterialization.bobRowCount,
            ledgerRowCount: mat.runMaterialization.ledgerRowCount,
            ledgerGrossTotal: mat.runMaterialization.ledgerGrossTotal,
            ledgerDownlineTotal: mat.runMaterialization.ledgerDownlineTotal,
            ledgerUplineTotal: mat.runMaterialization.ledgerUplineTotal,
            statementBatchId: mat.statementBatch.id,
          },
          result: {
            attemptEventId: resolvedAttemptId,
            runId,
            statementDate,
            statementBatchId: mat.statementBatch.id,
            bobRowCount: mat.runMaterialization.bobRowCount,
            ledgerRowCount: mat.runMaterialization.ledgerRowCount,
            agencyLineCount: mat.agencyLines.length,
            uplineLineCount: mat.uplineLines.length,
            ledgerGrossTotal: mat.runMaterialization.ledgerGrossTotal,
            ledgerDownlineTotal: mat.runMaterialization.ledgerDownlineTotal,
            ledgerUplineTotal: mat.runMaterialization.ledgerUplineTotal,
          },
          commitments,
        };

        const je = await writeJournal(body);
        await insertMaterializationPayload(tx, mat, je.journalSeq);
        return { ...je, body, result: body.result };
      },
    });
  }

  return {
    initCompany,
    registerStoredFiles,
    registerEngineVersion,
    registerApprovalsFile,
    recordDecisionBaseline,
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
    saveReviewDecisions,
    recordGeneratedOverlay,
    saveReviewDraft,
    getReviewDraft,
    expireOldDrafts,
    confirmEmit,
    carrySent,
    carryApprovals,
    carryDecisions,
    recordStatementBatch,
    materializeEmit,
    abandonRun,
    importHistoricalRun,
    importStandaloneFiles,
    recordCheck,
  };
}
