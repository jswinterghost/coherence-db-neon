// Read-only server-side handlers for Coherence screens R1 (Canonical Book of Business,
// Coherent Ledger, Statements per Entity, and IAM View-as candidates).
// Every query executes inside inReadTx strictly through PostgreSQL app_views.* under the
// caller's signed dbToken: zero role checks, zero JS dollar/PHI stripping, and zero writes.
import { inReadTx as runReadTx } from '../db/pg-client.mjs';
import { AppError } from '../util/redact.mjs';
import {
  appendSearchFilter,
  assertCsvRowLimit,
  BOB_CSV_SPEC,
  BOB_SORT_COLS,
  buildCsvFile,
  buildSpecCsvFile,
  csvCell,
  escapeLike,
  LEDGER_CSV_SPEC,
  LEDGER_SORT_COLS,
  mapBobRow,
  mapDecisionRow,
  mapLedgerRow,
  mapPublishedRun,
  mapStatementAppearance,
  mapStatementBatch,
  mapStatementLine,
  MAX_CSV_LIMIT,
  parseBoolParam,
  parseDate,
  parseEnum,
  parseFormat,
  parseIntParam,
  parseMonth,
  parsePageOptions,
  parseUuid,
  STATEMENT_LINE_CSV_SPEC,
  STATEMENT_LINE_SORT_COLS,
  trimOpt,
} from './view-formatters.mjs';

const MAX_BIGINT = '9223372036854775807';

const BOB_SELECT_SQL = `
  attempt_event_id, run_id, organization_id, writing_person_id,
  external_policy_id, policy_id, carrier_policy_number, crm_policy_number,
  enrollment_code, carrier, plan_type, plan_name, simple_plan_type,
  mbi, member, dob, phone, email, address, county, state,
  pg_catalog.to_char(submission_date, 'YYYY-MM-DD') AS submission_date,
  pg_catalog.to_char(origin_effective, 'YYYY-MM-DD') AS origin_effective,
  pg_catalog.to_char(effective_date, 'YYYY-MM-DD') AS effective_date,
  pg_catalog.to_char(termination_date, 'YYYY-MM-DD') AS termination_date,
  pg_catalog.to_char(min_date, 'YYYY-MM-DD') AS min_date,
  pg_catalog.to_char(anchor_date, 'YYYY-MM-DD') AS anchor_date,
  amount::text AS amount, upline_amount::text AS upline_amount,
  writing_npn, writing_agent, entity, agency_id, status, coherent_status,
  conflicts, spine_source, confidence_level, coherent_trajectory, journal_seq
`;

const LEDGER_SELECT_SQL = `
  attempt_event_id, tx_id, run_id, organization_id, writing_person_id,
  record_id, external_policy_id, policy_id, statement_name, src_type, carrier,
  mbi, member, state, plan_type, simple_plan_type,
  pg_catalog.to_char(submission_date, 'YYYY-MM-DD') AS submission_date,
  pg_catalog.to_char(origin_effective, 'YYYY-MM-DD') AS origin_effective,
  pg_catalog.to_char(effective_date, 'YYYY-MM-DD') AS effective_date,
  pg_catalog.to_char(termination_date, 'YYYY-MM-DD') AS termination_date,
  pg_catalog.to_char(earned_date, 'YYYY-MM-DD') AS earned_date,
  pg_catalog.to_char(payment_date, 'YYYY-MM-DD') AS payment_date,
  pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date,
  pg_catalog.to_char(min_date, 'YYYY-MM-DD') AS min_date,
  gross_comm::text AS gross_comm, revenue_type,
  override_amount::text AS override_amount, commission_amount::text AS commission_amount,
  hra_amount::text AS hra_amount, fee_amount::text AS fee_amount,
  other_amount::text AS other_amount, downline_amount::text AS downline_amount,
  upline_amount::text AS upline_amount,
  writing_npn, writing_agent, entity, payee_npn, agency_id,
  status, policy_status, cbob_c, cbob_s, sf,
  notes, coherent_notes, sheet_name, source_row_no, journal_seq
`;

const STATEMENT_BATCH_SELECT_SQL = `
  id, batch_kind, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date,
  run_id, attempt_event_id, source_file_name, reason,
  agency_line_count, agency_lines_sha256, agency_net_total::text AS agency_net_total,
  upline_line_count, upline_lines_sha256, upline_net_total::text AS upline_net_total,
  journal_seq, is_sent
`;

const statementLineSelectSql = (batchAlias) => `
  l.batch_id, ${batchAlias}.batch_kind, ${batchAlias}.is_sent, l.line_no,
  pg_catalog.to_char(l.statement_date, 'YYYY-MM-DD') AS statement_date,
  l.entry_kind, l.run_action, l.organization_id, l.source_organization_id,
  l.writing_person_id, l.statement_entity, l.account_kind, l.source_entity,
  l.marked_sent, l.writing_npn, l.writing_agent,
  l.record_id, l.reversal_of, l.corrects_record_id,
  l.source_file, l.sheet_name, l.source_row_no, l.src_type, l.carrier,
  l.mbi, l.member, l.external_policy_id, l.policy_id, l.tx_id,
  l.plan_type, l.simple_plan_type, l.state,
  pg_catalog.to_char(l.submission_date, 'YYYY-MM-DD') AS submission_date,
  pg_catalog.to_char(l.origin_effective, 'YYYY-MM-DD') AS origin_effective,
  pg_catalog.to_char(l.effective_date, 'YYYY-MM-DD') AS effective_date,
  pg_catalog.to_char(l.termination_date, 'YYYY-MM-DD') AS termination_date,
  pg_catalog.to_char(l.earned_date, 'YYYY-MM-DD') AS earned_date,
  pg_catalog.to_char(l.payment_date, 'YYYY-MM-DD') AS payment_date,
  pg_catalog.to_char(l.posted_statement_date, 'YYYY-MM-DD') AS posted_statement_date,
  l.revenue_type, l.gross_comm::text AS gross_comm, l.amount::text AS amount,
  l.reason, l.notes, l.journal_seq
`;

const BOB_SEARCH_EXPRS = [
  'policy_id::text', 'external_policy_id', 'carrier_policy_number', 'crm_policy_number',
  'carrier', 'plan_name', 'plan_type', 'simple_plan_type', 'writing_agent',
  'writing_npn', 'entity', 'state', 'status',
];

const LEDGER_SEARCH_EXPRS = [
  'tx_id::text', 'policy_id::text', 'external_policy_id', 'statement_name', 'src_type',
  'carrier', 'writing_agent', 'writing_npn', 'entity', 'payee_npn', 'agency_id',
  'status', 'policy_status', 'revenue_type', 'sheet_name', 'source_row_no::text',
];

const STATEMENT_LINE_SEARCH_EXPRS = [
  'l.source_file', 'l.sheet_name', 'l.source_row_no::text', 'l.statement_entity',
  'l.source_entity', 'l.carrier', 'l.src_type', 'l.writing_agent', 'l.writing_npn',
  'l.external_policy_id', 'l.policy_id::text', 'l.run_action', 'l.revenue_type',
];

const addEqFilter = (conds, params, col, val, cast = '') => {
  if (val == null) return;
  params.push(val);
  conds.push(`${col} = $${params.length}${cast}`);
};

export function createViewHandlers({ pool, companySlug, resolveAsOfSeqTx, maxCsvRows = MAX_CSV_LIMIT }) {
  const inReadTx = (dbToken, fn) => runReadTx(pool, dbToken, fn);
  const csvRowLimit = Number.isInteger(maxCsvRows) && maxCsvRows >= 1 ? maxCsvRows : MAX_CSV_LIMIT;

  async function listPublishedRunsForViewTx(tx, { tableView, seqCap }) {
    return (await tx.query(
      `SELECT r.id, r.statement_date, r.stamp, r.folder_number, r.origin,
              r.emit_mode, r.emit_display, r.emit_attempt_event_id,
              r.emit_journal_seq, r.journal_seq, r.sent
       FROM app_views.coherence_published_runs r
       WHERE r.journal_seq <= $1::bigint
         AND r.emit_journal_seq <= $1::bigint
         AND EXISTS (SELECT 1 FROM app_views.${tableView} v WHERE v.attempt_event_id = r.emit_attempt_event_id)
       ORDER BY r.statement_date DESC, r.folder_number DESC, r.journal_seq DESC`,
      [seqCap],
    )).rows;
  }

  async function findPublishedRunByIdTx(tx, { runId, seqCap, requireRowsInView = null }) {
    const existsSql = requireRowsInView
      ? ` AND EXISTS (SELECT 1 FROM app_views.${requireRowsInView} v WHERE v.attempt_event_id = r.emit_attempt_event_id)`
      : '';
    return (await tx.query(
      `SELECT r.id, r.statement_date, r.stamp, r.folder_number, r.origin,
              r.emit_mode, r.emit_display, r.emit_attempt_event_id,
              r.emit_journal_seq, r.journal_seq, r.sent
       FROM app_views.coherence_published_runs r
       WHERE r.id = $1::uuid AND r.journal_seq <= $2::bigint AND r.emit_journal_seq <= $2::bigint${existsSql}
       LIMIT 1`,
      [runId, seqCap],
    )).rows[0] || null;
  }

  async function resolveVersionedSourceTx(tx, { runId, limitSeq, tableView, currentView, requireRowsOnRunId = false }) {
    const seqCap = limitSeq != null ? String(limitSeq) : MAX_BIGINT;
    const runRows = await listPublishedRunsForViewTx(tx, { tableView, seqCap });
    const runs = runRows.map((r) => mapPublishedRun(r));

    if (runId) {
      const found = await findPublishedRunByIdTx(tx, {
        runId,
        seqCap,
        requireRowsInView: requireRowsOnRunId ? tableView : null,
      });
      if (!found) throw new AppError('Run not found.', 404, 'RUN_NOT_FOUND');
      return {
        runRows,
        runs,
        selectedRun: mapPublishedRun(found),
        sourceView: `app_views.${tableView}`,
        baseConds: ['attempt_event_id = $1::uuid'],
        baseParams: [found.emit_attempt_event_id],
        isCurrentView: false,
      };
    }
    if (runs.length === 0) {
      return { runRows, runs, selectedRun: null, sourceView: null, baseConds: [], baseParams: [], isCurrentView: false };
    }
    if (limitSeq != null) {
      return {
        runRows,
        runs,
        selectedRun: runs[0],
        sourceView: `app_views.${tableView}`,
        baseConds: ['attempt_event_id = $1::uuid'],
        baseParams: [runs[0].emitAttemptEventId],
        isCurrentView: false,
      };
    }
    return {
      runRows,
      runs,
      selectedRun: null,
      sourceView: `app_views.${currentView}`,
      baseConds: [],
      baseParams: [],
      isCurrentView: true,
    };
  }

  async function fetchLinkedStatementsTx(tx, keyCol, keyVal, runId = null) {
    if (runId) {
      const effIds = (await tx.query(
        'SELECT batch_id FROM app_views.coherence_statement_run_batches($1::uuid)',
        [runId],
      )).rows.map((r) => r.batch_id);
      if (effIds.length === 0) return { statementAppearances: [], statementLines: [] };
      const [appRes, linesRes] = await Promise.all([
        tx.query(
          `SELECT l.policy_id, l.tx_id, l.record_id,
                  pg_catalog.to_char(l.statement_date, 'YYYY-MM-DD') AS statement_date,
                  l.organization_id, l.statement_entity, l.account_kind, l.run_action,
                  pg_catalog.count(*)::bigint AS appearances,
                  CASE WHEN pg_catalog.bool_and(l.amount IS NOT NULL)
                    THEN COALESCE(pg_catalog.sum(l.amount), 0.00)::numeric(14,2)::text ELSE NULL END AS net_amount
           FROM app_views.coherence_entity_statement_lines l
           WHERE l.${keyCol} = $1::int AND l.batch_id = ANY($2::uuid[])
           GROUP BY l.policy_id, l.tx_id, l.record_id, l.statement_date,
                    l.organization_id, l.statement_entity, l.account_kind, l.run_action
           ORDER BY l.statement_date DESC, l.account_kind ASC, l.tx_id ASC NULLS LAST`,
          [keyVal, effIds],
        ),
        tx.query(
          `SELECT ${statementLineSelectSql('sb')}
           FROM app_views.coherence_entity_statement_lines l
           JOIN app_views.coherence_statement_batches sb ON sb.id = l.batch_id
           WHERE l.${keyCol} = $1::int AND l.batch_id = ANY($2::uuid[])
           ORDER BY l.statement_date DESC, l.account_kind ASC, l.line_no ASC`,
          [keyVal, effIds],
        ),
      ]);
      return {
        statementAppearances: appRes.rows.map(mapStatementAppearance),
        statementLines: linesRes.rows.map(mapStatementLine),
      };
    }
    const [appRes, linesRes] = await Promise.all([
      tx.query(
        `SELECT policy_id, tx_id, record_id,
                pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date,
                organization_id, statement_entity, account_kind, run_action,
                appearances, net_amount::text AS net_amount
         FROM app_views.coherence_statement_membership
         WHERE ${keyCol} = $1::int
         ORDER BY statement_date DESC, account_kind ASC, tx_id ASC NULLS LAST`,
        [keyVal],
      ),
      tx.query(
        `SELECT ${statementLineSelectSql('sb')}
         FROM app_views.coherence_entity_statement_lines l
         JOIN app_views.coherence_statement_batches sb ON sb.id = l.batch_id
         WHERE l.${keyCol} = $1::int
         ORDER BY l.statement_date DESC, l.account_kind ASC, l.line_no ASC`,
        [keyVal],
      ),
    ]);
    return {
      statementAppearances: appRes.rows.map(mapStatementAppearance),
      statementLines: linesRes.rows.map(mapStatementLine),
    };
  }

  async function fetchLinkedDecisionsTx(tx, { policyNums = [], recordIds = [] }) {
    const cleanPolicies = [...new Set(policyNums.map(trimOpt).filter(Boolean))];
    const cleanRecords = [...new Set(recordIds.map(trimOpt).filter(Boolean))];
    if (cleanPolicies.length === 0 && cleanRecords.length === 0) return [];
    const clauses = [];
    const params = [];
    if (cleanRecords.length > 0) {
      params.push(cleanRecords);
      clauses.push(`d.record_id = ANY($${params.length}::text[])`);
    }
    if (cleanPolicies.length > 0) {
      params.push(cleanPolicies);
      clauses.push(`d.policy = ANY($${params.length}::text[])`);
      params.push(cleanPolicies.map((p) => `policy:%:${escapeLike(p)}#%`));
      clauses.push(
        `EXISTS (SELECT 1 FROM pg_catalog.unnest($${params.length}::text[]) AS pat WHERE d.record_id LIKE pat ESCAPE '\\')`,
      );
    }
    const res = await tx.query(
      `SELECT d.id, d.decision_commit_id, d.row_order, d.run_id, d.review_save_id, d.surface,
              d.record_id, d.replaces_decision_id, d.disposition, d.agent, d.agency,
              d.policy, d.book, d.month, d.status, d.note,
              d.approved_amount, d.approved_agency, d.approved_agent,
              d.approved_agency_from, d.approved_agent_from,
              d.decided_by, d.decided_by_display, d.acting_for,
              d.decided_at, d.committed_at_raw, d.imported, d.journal_seq
       FROM app_views.coherence_decisions d
       WHERE ${clauses.join(' OR ')}
       ORDER BY d.journal_seq ASC, d.row_order ASC`,
      params,
    );
    return res.rows.map(mapDecisionRow);
  }

  async function resolveStatementBatchesTx(tx, {
    runId = null, batchId = null, statementDate = null, throughDate = null,
    batchKind = null, mode = null, includeUnsent = false,
  }) {
    const queryBatches = (conds, params) => tx.query(
      `SELECT ${STATEMENT_BATCH_SELECT_SQL}
       FROM app_views.coherence_statement_batches
       ${conds.length ? `WHERE ${conds.join(' AND ')}` : ''}
       ORDER BY statement_date DESC, journal_seq DESC`,
      params,
    );

    if (batchId) {
      const res = await queryBatches(['id = $1::uuid'], [batchId]);
      if (res.rows.length === 0) throw new AppError('Statement batch not found.', 404, 'BATCH_NOT_FOUND');
      return {
        batches: res.rows,
        resolvedDate: res.rows[0].statement_date,
        includeUnsent: res.rows.some((b) => !b.is_sent),
      };
    }

    if (runId) {
      const effRes = await tx.query('SELECT batch_id FROM app_views.coherence_statement_run_batches($1::uuid)', [runId]);
      if (effRes.rows.length === 0) throw new AppError('Run not found.', 404, 'RUN_NOT_FOUND');
      const conds = ['id = ANY($1::uuid[])'];
      const params = [effRes.rows.map((r) => r.batch_id)];
      if (mode === 'single') addEqFilter(conds, params, 'run_id', runId, '::uuid');
      addEqFilter(conds, params, 'batch_kind', batchKind);
      addEqFilter(conds, params, 'statement_date', statementDate, '::date');
      if (throughDate) { params.push(throughDate); conds.push(`statement_date <= $${params.length}::date`); }
      const rows = (await queryBatches(conds, params)).rows;
      const targetRow = rows.find((r) => r.run_id === runId) || rows[0] || null;
      return {
        batches: rows,
        resolvedDate: targetRow?.statement_date ?? null,
        includeUnsent: rows.some((b) => !b.is_sent),
      };
    }

    const canSeeUnsent = Boolean((await tx.query('SELECT app_views._read_can_see_unsent_batch_meta() AS ok')).rows[0]?.ok);
    const effectiveIncludeUnsent = Boolean(includeUnsent) && canSeeUnsent;
    const conds = [];
    const params = [];
    if (!effectiveIncludeUnsent) conds.push('is_sent = true');
    addEqFilter(conds, params, 'batch_kind', batchKind);

    let resolvedDate = null;
    if (mode === 'single') {
      resolvedDate = statementDate || throughDate || null;
      if (!resolvedDate) {
        const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
        resolvedDate = (await tx.query(
          `SELECT pg_catalog.to_char(pg_catalog.max(statement_date), 'YYYY-MM-DD') AS d
           FROM app_views.coherence_statement_batches ${where}`,
          params,
        )).rows[0]?.d || null;
        if (!resolvedDate) return { batches: [], resolvedDate: null, includeUnsent: effectiveIncludeUnsent };
      }
      addEqFilter(conds, params, 'statement_date', resolvedDate, '::date');
    } else if (mode === 'cumulative') {
      resolvedDate = throughDate || statementDate || null;
      if (resolvedDate) { params.push(resolvedDate); conds.push(`statement_date <= $${params.length}::date`); }
    } else {
      resolvedDate = statementDate || throughDate || null;
      addEqFilter(conds, params, 'statement_date', statementDate, '::date');
      if (throughDate) { params.push(throughDate); conds.push(`statement_date <= $${params.length}::date`); }
    }

    const rows = (await queryBatches(conds, params)).rows;
    return { batches: rows, resolvedDate: resolvedDate ?? rows[0]?.statement_date ?? null, includeUnsent: effectiveIncludeUnsent };
  }

  async function getBookOfBusiness(dbToken, opts = {}) {
    const runId = parseUuid(opts.runId, 'runId');
    const organizationId = parseUuid(opts.organizationId, 'organizationId');
    const { format, sqlCol, sqlDir, limit, offset, acceptsGzip } = parsePageOptions(opts, BOB_SORT_COLS, 'policyId', 'asc', csvRowLimit);

    return inReadTx(dbToken, async (tx) => {
      const limitSeq = await resolveAsOfSeqTx(tx, { asOfSeq: opts.asOfSeq, asOf: opts.asOf });
      const src = await resolveVersionedSourceTx(tx, {
        runId, limitSeq, tableView: 'coherence_bob', currentView: 'v_current_policy_periods', requireRowsOnRunId: true,
      });
      const empty = () => (format === 'csv'
        ? buildSpecCsvFile('canonical_bob_current.csv', BOB_CSV_SPEC, [], acceptsGzip)
        : {
          companySlug, asOfSeq: limitSeq, run: src.selectedRun, runs: src.runs,
          summary: { policyCount: 0, entityCount: 0, carrierCount: 0, amountTotal: null, uplineAmountTotal: null },
          facets: { entities: [], carriers: [], statuses: [], planTypes: [], states: [] },
          totalCount: 0, limit, offset, rows: [],
        });
      if (!src.sourceView) return empty();

      const filterConds = [];
      const params = [...src.baseParams];
      addEqFilter(filterConds, params, 'organization_id', organizationId, '::uuid');
      addEqFilter(filterConds, params, 'entity', trimOpt(opts.entity));
      addEqFilter(filterConds, params, 'carrier', trimOpt(opts.carrier));
      addEqFilter(filterConds, params, 'status', trimOpt(opts.status));
      addEqFilter(filterConds, params, 'plan_type', trimOpt(opts.planType));
      addEqFilter(filterConds, params, 'simple_plan_type', trimOpt(opts.simplePlanType));
      addEqFilter(filterConds, params, 'state', trimOpt(opts.state));
      addEqFilter(filterConds, params, 'writing_npn', trimOpt(opts.writingNpn));
      appendSearchFilter(filterConds, params, trimOpt(opts.q), BOB_SEARCH_EXPRS);

      const baseWhere = src.baseConds.length ? `WHERE ${src.baseConds.join(' AND ')}` : '';
      const filterWhere = filterConds.length ? `WHERE ${filterConds.join(' AND ')}` : '';
      const metaSql = src.isCurrentView
        ? `(SELECT pg_catalog.jsonb_build_object(
              'run_id', run_id, 'attempt_event_id', attempt_event_id,
              'run_statement_date', pg_catalog.to_char(run_statement_date, 'YYYY-MM-DD'),
              'corpus_tail', corpus_tail,
              'agency_start', pg_catalog.to_char(agency_start, 'YYYY-MM-DD')
            ) FROM base LIMIT 1) AS cur_meta,`
        : 'NULL::jsonb AS cur_meta,';

      const pageParams = [...params, limit, offset];
      const rowsAggSql = format === 'csv'
        ? `(SELECT CASE WHEN (SELECT pg_catalog.count(*) FROM filtered) <= $${pageParams.length - 1}::int
            THEN COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(paged)) FROM paged), '[]'::jsonb)
            ELSE '[]'::jsonb END)`
        : `(SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(paged)), '[]'::jsonb) FROM paged)`;
      const out = (await tx.query(
        `WITH base AS MATERIALIZED (SELECT * FROM ${src.sourceView} ${baseWhere}),
         filtered AS MATERIALIZED (SELECT * FROM base ${filterWhere}),
         paged AS (
           SELECT ${BOB_SELECT_SQL} FROM filtered f
           ORDER BY ${sqlCol} ${sqlDir} NULLS LAST, f.policy_id ASC
           LIMIT $${pageParams.length - 1} OFFSET $${pageParams.length}
         )
         SELECT
           ${metaSql}
           (SELECT pg_catalog.count(*)::int FROM filtered) AS policy_count,
           (SELECT pg_catalog.count(DISTINCT entity)::int FROM filtered) AS entity_count,
           (SELECT pg_catalog.count(DISTINCT carrier)::int FROM filtered) AS carrier_count,
           (SELECT pg_catalog.sum(amount)::numeric(14,2)::text FROM filtered) AS amount_total,
           (SELECT pg_catalog.sum(upline_amount)::numeric(14,2)::text FROM filtered) AS upline_amount_total,
           (SELECT COALESCE(pg_catalog.array_agg(DISTINCT entity ORDER BY entity) FILTER (WHERE entity IS NOT NULL), ARRAY[]::text[]) FROM base) AS entities,
           (SELECT COALESCE(pg_catalog.array_agg(DISTINCT carrier ORDER BY carrier) FILTER (WHERE carrier IS NOT NULL), ARRAY[]::text[]) FROM base) AS carriers,
           (SELECT COALESCE(pg_catalog.array_agg(DISTINCT status ORDER BY status) FILTER (WHERE status IS NOT NULL), ARRAY[]::text[]) FROM base) AS statuses,
           (SELECT COALESCE(pg_catalog.array_agg(DISTINCT plan_type ORDER BY plan_type) FILTER (WHERE plan_type IS NOT NULL), ARRAY[]::text[]) FROM base) AS plan_types,
           (SELECT COALESCE(pg_catalog.array_agg(DISTINCT state ORDER BY state) FILTER (WHERE state IS NOT NULL), ARRAY[]::text[]) FROM base) AS states,
           ${rowsAggSql} AS rows_json`,
        pageParams,
      )).rows[0];

      let selectedRun = src.selectedRun;
      if (src.isCurrentView) {
        if (!out.cur_meta) return empty();
        const matched = src.runRows.find((r) => r.id === out.cur_meta.run_id);
        selectedRun = matched
          ? mapPublishedRun(matched, { corpusTail: out.cur_meta.corpus_tail, agencyStart: out.cur_meta.agency_start })
          : { id: out.cur_meta.run_id, statementDate: out.cur_meta.run_statement_date, emitAttemptEventId: out.cur_meta.attempt_event_id, corpusTail: out.cur_meta.corpus_tail, agencyStart: out.cur_meta.agency_start };
      }

      if (format === 'csv') {
        assertCsvRowLimit(Number(out.policy_count), csvRowLimit);
        const rows = (out.rows_json || []).map(mapBobRow);
        return buildSpecCsvFile(`canonical_bob_${selectedRun.statementDate || 'current'}.csv`, BOB_CSV_SPEC, rows, acceptsGzip);
      }
      const rows = (out.rows_json || []).map(mapBobRow);
      return {
        companySlug, asOfSeq: limitSeq, run: selectedRun, runs: src.runs,
        summary: {
          policyCount: Number(out.policy_count),
          entityCount: Number(out.entity_count),
          carrierCount: Number(out.carrier_count),
          amountTotal: out.amount_total ?? null,
          uplineAmountTotal: out.upline_amount_total ?? null,
        },
        facets: {
          entities: out.entities || [], carriers: out.carriers || [], statuses: out.statuses || [],
          planTypes: out.plan_types || [], states: out.states || [],
        },
        totalCount: Number(out.policy_count), limit, offset, rows,
      };
    });
  }

  async function getPolicyDetail(dbToken, rawPolicyId, opts = {}) {
    const policyId = parseIntParam(rawPolicyId, 'policyId', { min: 0, required: true });
    const runId = parseUuid(opts.runId, 'runId');

    return inReadTx(dbToken, async (tx) => {
      let policyRow;
      if (runId) {
        const found = await findPublishedRunByIdTx(tx, { runId, seqCap: MAX_BIGINT, requireRowsInView: 'coherence_bob' });
        if (!found) throw new AppError('Policy not found.', 404, 'POLICY_NOT_FOUND');
        policyRow = (await tx.query(
          `SELECT ${BOB_SELECT_SQL} FROM app_views.coherence_bob
           WHERE attempt_event_id = $1::uuid AND policy_id = $2::int LIMIT 1`,
          [found.emit_attempt_event_id, policyId],
        )).rows[0] || null;
      } else {
        policyRow = (await tx.query(
          `SELECT ${BOB_SELECT_SQL} FROM app_views.v_current_policy_periods
           WHERE policy_id = $1::int LIMIT 1`,
          [policyId],
        )).rows[0] || null;
      }
      if (!policyRow) throw new AppError('Policy not found.', 404, 'POLICY_NOT_FOUND');

      const [ledgerRes, linkedStmts] = await Promise.all([
        tx.query(
          `SELECT ${LEDGER_SELECT_SQL} FROM app_views.coherence_ledger
           WHERE attempt_event_id = $1::uuid AND policy_id = $2::int ORDER BY tx_id ASC`,
          [policyRow.attempt_event_id, policyId],
        ),
        fetchLinkedStatementsTx(tx, 'policy_id', policyId, runId),
      ]);
      const ledgerRows = ledgerRes.rows.map(mapLedgerRow);
      const decisions = await fetchLinkedDecisionsTx(tx, {
        policyNums: [policyRow.external_policy_id, policyRow.carrier_policy_number, policyRow.crm_policy_number],
        recordIds: [...ledgerRows.map((l) => l.recordId), ...linkedStmts.statementLines.map((l) => l.recordId)],
      });
      return { companySlug, policy: mapBobRow(policyRow), ledgerRows, ...linkedStmts, decisions };
    });
  }

  async function getCoherentLedger(dbToken, opts = {}) {
    const runId = parseUuid(opts.runId, 'runId');
    const organizationId = parseUuid(opts.organizationId, 'organizationId');
    const policyId = parseIntParam(opts.policyId, 'policyId', { min: 0 });
    const paymentMonth = parseMonth(opts.paymentMonth, 'paymentMonth');
    const statementDate = parseDate(opts.statementDate, 'statementDate');
    const { format, sqlCol, sqlDir, limit, offset, acceptsGzip } = parsePageOptions(opts, LEDGER_SORT_COLS, 'txId', 'asc', csvRowLimit);

    return inReadTx(dbToken, async (tx) => {
      const limitSeq = await resolveAsOfSeqTx(tx, { asOfSeq: opts.asOfSeq, asOf: opts.asOf });
      const src = await resolveVersionedSourceTx(tx, {
        runId, limitSeq, tableView: 'coherence_ledger', currentView: 'v_current_commission_ledger', requireRowsOnRunId: true,
      });
      const empty = () => (format === 'csv'
        ? buildSpecCsvFile('coherent_ledger_current.csv', LEDGER_CSV_SPEC, [], acceptsGzip)
        : {
          companySlug, asOfSeq: limitSeq, run: null, runs: src.runs,
          summary: { rowCount: 0, grossTotal: null, downlineTotal: null, uplineTotal: null, variance: null, balanced: null },
          facets: { entities: [], carriers: [], srcTypes: [], revenueTypes: [], statuses: [], states: [] },
          totalCount: 0, limit, offset, rows: [],
        });
      if (!src.sourceView) return empty();

      const filterConds = [];
      const params = [...src.baseParams];
      addEqFilter(filterConds, params, 'organization_id', organizationId, '::uuid');
      addEqFilter(filterConds, params, 'entity', trimOpt(opts.entity));
      addEqFilter(filterConds, params, 'carrier', trimOpt(opts.carrier));
      addEqFilter(filterConds, params, 'src_type', trimOpt(opts.srcType));
      addEqFilter(filterConds, params, 'revenue_type', trimOpt(opts.revenueType));
      addEqFilter(filterConds, params, 'status', trimOpt(opts.status));
      addEqFilter(filterConds, params, 'policy_status', trimOpt(opts.policyStatus));
      addEqFilter(filterConds, params, 'plan_type', trimOpt(opts.planType));
      addEqFilter(filterConds, params, 'simple_plan_type', trimOpt(opts.simplePlanType));
      addEqFilter(filterConds, params, 'state', trimOpt(opts.state));
      addEqFilter(filterConds, params, 'writing_npn', trimOpt(opts.writingNpn));
      addEqFilter(filterConds, params, 'policy_id', policyId, '::int');
      addEqFilter(filterConds, params, 'statement_date', statementDate, '::date');
      if (paymentMonth) {
        params.push(paymentMonth);
        filterConds.push(`pg_catalog.to_char(payment_date, 'YYYY-MM') = $${params.length}`);
      }
      appendSearchFilter(filterConds, params, trimOpt(opts.q), LEDGER_SEARCH_EXPRS);

      const baseWhere = src.baseConds.length ? `WHERE ${src.baseConds.join(' AND ')}` : '';
      const filterWhere = filterConds.length ? `WHERE ${filterConds.join(' AND ')}` : '';
      const metaSql = src.isCurrentView
        ? `(SELECT pg_catalog.jsonb_build_object(
              'run_id', run_id, 'attempt_event_id', attempt_event_id,
              'run_statement_date', pg_catalog.to_char(run_statement_date, 'YYYY-MM-DD')
            ) FROM base LIMIT 1) AS cur_meta,`
        : 'NULL::jsonb AS cur_meta,';

      const pageParams = [...params, limit, offset];
      const rowsAggSql = format === 'csv'
        ? `(SELECT CASE WHEN (SELECT pg_catalog.count(*) FROM filtered) <= $${pageParams.length - 1}::int
            THEN COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(paged)) FROM paged), '[]'::jsonb)
            ELSE '[]'::jsonb END)`
        : `(SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(paged)), '[]'::jsonb) FROM paged)`;
      const out = (await tx.query(
        `WITH base AS MATERIALIZED (SELECT * FROM ${src.sourceView} ${baseWhere}),
         filtered AS MATERIALIZED (SELECT * FROM base ${filterWhere}),
         paged AS (
           SELECT ${LEDGER_SELECT_SQL} FROM filtered f
           ORDER BY ${sqlCol} ${sqlDir} NULLS LAST, f.tx_id ASC
           LIMIT $${pageParams.length - 1} OFFSET $${pageParams.length}
         )
         SELECT
           ${metaSql}
           (SELECT pg_catalog.count(*)::int FROM filtered) AS row_count,
           (SELECT pg_catalog.sum(gross_comm)::numeric(14,2)::text FROM filtered) AS gross_total,
           (SELECT pg_catalog.sum(downline_amount)::numeric(14,2)::text FROM filtered) AS downline_total,
           (SELECT pg_catalog.sum(upline_amount)::numeric(14,2)::text FROM filtered) AS upline_total,
           (SELECT (pg_catalog.sum(downline_amount) + pg_catalog.sum(upline_amount) - pg_catalog.sum(gross_comm))::numeric(14,2)::text FROM filtered) AS variance,
           (SELECT COALESCE(pg_catalog.array_agg(DISTINCT entity ORDER BY entity) FILTER (WHERE entity IS NOT NULL), ARRAY[]::text[]) FROM base) AS entities,
           (SELECT COALESCE(pg_catalog.array_agg(DISTINCT carrier ORDER BY carrier) FILTER (WHERE carrier IS NOT NULL), ARRAY[]::text[]) FROM base) AS carriers,
           (SELECT COALESCE(pg_catalog.array_agg(DISTINCT src_type ORDER BY src_type) FILTER (WHERE src_type IS NOT NULL), ARRAY[]::text[]) FROM base) AS src_types,
           (SELECT COALESCE(pg_catalog.array_agg(DISTINCT revenue_type ORDER BY revenue_type) FILTER (WHERE revenue_type IS NOT NULL), ARRAY[]::text[]) FROM base) AS revenue_types,
           (SELECT COALESCE(pg_catalog.array_agg(DISTINCT status ORDER BY status) FILTER (WHERE status IS NOT NULL), ARRAY[]::text[]) FROM base) AS statuses,
           (SELECT COALESCE(pg_catalog.array_agg(DISTINCT state ORDER BY state) FILTER (WHERE state IS NOT NULL), ARRAY[]::text[]) FROM base) AS states,
           ${rowsAggSql} AS rows_json`,
        pageParams,
      )).rows[0];

      let selectedRun = src.selectedRun;
      if (src.isCurrentView) {
        if (!out.cur_meta) return empty();
        const matched = src.runRows.find((r) => r.id === out.cur_meta.run_id);
        selectedRun = matched
          ? mapPublishedRun(matched)
          : { id: out.cur_meta.run_id, statementDate: out.cur_meta.run_statement_date, emitAttemptEventId: out.cur_meta.attempt_event_id };
      }

      const rowCount = Number(out.row_count);
      if (format === 'csv') {
        assertCsvRowLimit(rowCount, csvRowLimit);
        const rows = (out.rows_json || []).map(mapLedgerRow);
        return buildSpecCsvFile(`coherent_ledger_${selectedRun.statementDate || 'current'}.csv`, LEDGER_CSV_SPEC, rows, acceptsGzip);
      }
      const rows = (out.rows_json || []).map(mapLedgerRow);
      return {
        companySlug, asOfSeq: limitSeq, run: selectedRun, runs: src.runs,
        summary: {
          rowCount,
          grossTotal: rowCount > 0 ? out.gross_total : null,
          downlineTotal: rowCount > 0 ? out.downline_total : null,
          uplineTotal: rowCount > 0 ? out.upline_total : null,
          variance: rowCount > 0 ? out.variance : null,
          balanced: rowCount > 0 ? out.variance === '0.00' : null,
        },
        facets: {
          entities: out.entities || [], carriers: out.carriers || [], srcTypes: out.src_types || [],
          revenueTypes: out.revenue_types || [], statuses: out.statuses || [], states: out.states || [],
        },
        totalCount: rowCount, limit, offset, rows,
      };
    });
  }

  async function getLedgerTransactionDetail(dbToken, rawTxId, opts = {}) {
    const txId = parseIntParam(rawTxId, 'txId', { min: 0, required: true });
    const runId = parseUuid(opts.runId, 'runId');

    return inReadTx(dbToken, async (tx) => {
      let row;
      if (runId) {
        const found = await findPublishedRunByIdTx(tx, { runId, seqCap: MAX_BIGINT, requireRowsInView: 'coherence_ledger' });
        if (!found) throw new AppError('Transaction not found.', 404, 'TRANSACTION_NOT_FOUND');
        row = (await tx.query(
          `SELECT ${LEDGER_SELECT_SQL} FROM app_views.coherence_ledger
           WHERE attempt_event_id = $1::uuid AND tx_id = $2::int LIMIT 1`,
          [found.emit_attempt_event_id, txId],
        )).rows[0] || null;
      } else {
        row = (await tx.query(
          `SELECT ${LEDGER_SELECT_SQL} FROM app_views.v_current_commission_ledger
           WHERE tx_id = $1::int LIMIT 1`,
          [txId],
        )).rows[0] || null;
      }
      if (!row) throw new AppError('Transaction not found.', 404, 'TRANSACTION_NOT_FOUND');

      const [policyRes, linkedStmts] = await Promise.all([
        row.policy_id != null
          ? tx.query(
            `SELECT ${BOB_SELECT_SQL} FROM app_views.coherence_bob
             WHERE attempt_event_id = $1::uuid AND policy_id = $2::int LIMIT 1`,
            [row.attempt_event_id, Number(row.policy_id)],
          )
          : Promise.resolve({ rows: [] }),
        fetchLinkedStatementsTx(tx, 'tx_id', txId, runId),
      ]);
      const parentPolicy = policyRes.rows[0] ? mapBobRow(policyRes.rows[0]) : null;
      const decisions = await fetchLinkedDecisionsTx(tx, {
        policyNums: [row.external_policy_id, parentPolicy?.externalPolicyId, parentPolicy?.carrierPolicyNumber, parentPolicy?.crmPolicyNumber],
        recordIds: [row.record_id, ...linkedStmts.statementLines.map((l) => l.recordId)],
      });
      return { companySlug, transaction: mapLedgerRow(row), policy: parentPolicy, ...linkedStmts, decisions };
    });
  }

  async function listStatementBatches(dbToken, opts = {}) {
    const runId = parseUuid(opts.runId, 'runId');
    const statementDate = parseDate(opts.statementDate, 'statementDate');
    const throughDate = parseDate(opts.throughDate, 'throughDate');
    const batchKind = parseEnum(opts.batchKind, 'batchKind', ['historical_sent', 'method_correction', 'run_emission']);
    const includeUnsent = parseBoolParam(opts.includeUnsent, 'includeUnsent', true);

    return inReadTx(dbToken, async (tx) => {
      const { batches: batchRows, includeUnsent: effectiveIncludeUnsent } = await resolveStatementBatchesTx(tx, {
        runId, statementDate, throughDate, batchKind, includeUnsent,
      });
      if (batchRows.length === 0) return { companySlug, includeUnsent: effectiveIncludeUnsent, batches: [], dateTotals: [] };

      const batchIds = batchRows.map((b) => b.id);
      const unfiltered = !runId && !statementDate && !throughDate && !batchKind && includeUnsent;
      const [entRes, dateTotRes] = await Promise.all([
        tx.query(
          `SELECT batch_id, organization_id, statement_entity, account_kind,
                  pg_catalog.count(*)::int AS line_count,
                  CASE WHEN pg_catalog.bool_and(amount IS NOT NULL)
                    THEN COALESCE(pg_catalog.sum(amount), 0.00)::numeric(14,2)::text ELSE NULL END AS net_amount,
                  pg_catalog.bool_and(marked_sent) AS all_marked_sent,
                  pg_catalog.count(*) FILTER (WHERE NOT marked_sent)::int AS unsent_upline_line_count
           FROM app_views.coherence_entity_statement_lines
           WHERE batch_id = ANY($1::uuid[])
           GROUP BY batch_id, organization_id, statement_entity, account_kind
           ORDER BY CASE WHEN account_kind = 'agency' THEN 0 ELSE 1 END, statement_entity ASC, organization_id ASC NULLS LAST`,
          [batchIds],
        ),
        unfiltered
          ? tx.query(
            `SELECT pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date,
                    organization_id, statement_entity, account_kind,
                    line_count::int AS line_count, net_amount::text AS net_amount
             FROM app_views.coherence_statement_date_totals
             ORDER BY statement_date DESC, CASE WHEN account_kind = 'agency' THEN 0 ELSE 1 END, statement_entity ASC, organization_id ASC NULLS LAST`,
          )
          : tx.query(
            `SELECT pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date,
                    organization_id, statement_entity, account_kind,
                    pg_catalog.sum(line_count)::int AS line_count,
                    CASE WHEN pg_catalog.bool_and(net_amount IS NOT NULL)
                      THEN COALESCE(pg_catalog.sum(net_amount), 0.00)::numeric(14,2)::text ELSE NULL END AS net_amount
             FROM app_views.coherence_statement_totals
             WHERE batch_id = ANY($1::uuid[])
             GROUP BY statement_date, organization_id, statement_entity, account_kind
             ORDER BY statement_date DESC, CASE WHEN account_kind = 'agency' THEN 0 ELSE 1 END, statement_entity ASC, organization_id ASC NULLS LAST`,
            [batchIds],
          ),
      ]);

      const entitiesByBatch = new Map();
      for (const e of entRes.rows) {
        const list = entitiesByBatch.get(e.batch_id) || [];
        list.push({
          organizationId: e.organization_id, statementEntity: e.statement_entity,
          accountKind: e.account_kind, lineCount: Number(e.line_count),
          netAmount: e.net_amount ?? null, allMarkedSent: Boolean(e.all_marked_sent),
          unsentUplineLineCount: Number(e.unsent_upline_line_count),
        });
        entitiesByBatch.set(e.batch_id, list);
      }
      return {
        companySlug,
        includeUnsent: effectiveIncludeUnsent,
        batches: batchRows.map((b) => mapStatementBatch(b, entitiesByBatch.get(b.id) || [])),
        dateTotals: dateTotRes.rows.map((d) => ({
          statementDate: d.statement_date, organizationId: d.organization_id,
          statementEntity: d.statement_entity, accountKind: d.account_kind,
          lineCount: Number(d.line_count), netAmount: d.net_amount ?? null,
        })),
      };
    });
  }

  async function getStatementMatrix(dbToken, opts = {}) {
    const mode = parseEnum(opts.mode, 'mode', ['cumulative', 'single'], 'cumulative');
    const runId = parseUuid(opts.runId, 'runId');
    const batchId = parseUuid(opts.batchId, 'batchId');
    const statementDate = parseDate(opts.statementDate, 'statementDate');
    const throughDate = parseDate(opts.throughDate, 'throughDate');
    const includeUnsent = parseBoolParam(opts.includeUnsent, 'includeUnsent', false);
    const format = parseFormat(opts.format);
    const acceptsGzip = Boolean(opts.acceptsGzip);

    return inReadTx(dbToken, async (tx) => {
      const { batches: batchRows, resolvedDate, includeUnsent: effectiveIncludeUnsent } = await resolveStatementBatchesTx(tx, {
        runId, batchId, statementDate, throughDate, mode, includeUnsent,
      });
      const batchIds = batchRows.map((b) => b.id);
      if (batchIds.length === 0) {
        return format === 'csv'
          ? buildCsvFile('statement_matrix.csv', ['src_type', 'payment_month', 'total'], [], acceptsGzip)
          : {
            companySlug, mode, statementDate: resolvedDate, runId, batchId,
            batchIds: [], includeUnsent: effectiveIncludeUnsent, entities: [], cells: [],
            summary: { lineCount: 0, agencyNetTotal: null, uplineNetTotal: null, grandTotal: null },
          };
      }

      const mat = (await tx.query(
        `WITH base AS MATERIALIZED (
           SELECT src_type, payment_month, organization_id, statement_entity, account_kind, line_count, net_amount
           FROM app_views.coherence_statement_totals WHERE batch_id = ANY($1::uuid[])
         ),
         cells AS (
           SELECT src_type, payment_month, organization_id, statement_entity, account_kind,
                  pg_catalog.sum(line_count)::int AS line_count,
                  CASE WHEN pg_catalog.bool_and(net_amount IS NOT NULL)
                    THEN COALESCE(pg_catalog.sum(net_amount), 0.00)::numeric(14,2)::text ELSE NULL END AS net_amount
           FROM base GROUP BY src_type, payment_month, organization_id, statement_entity, account_kind
           ORDER BY src_type ASC NULLS LAST, payment_month ASC NULLS LAST,
                    CASE WHEN account_kind = 'agency' THEN 0 ELSE 1 END, statement_entity ASC, organization_id ASC NULLS LAST
         ),
         ents AS (
           SELECT organization_id, statement_entity, account_kind,
                  pg_catalog.sum(line_count)::int AS line_count,
                  CASE WHEN pg_catalog.bool_and(net_amount IS NOT NULL)
                    THEN COALESCE(pg_catalog.sum(net_amount), 0.00)::numeric(14,2)::text ELSE NULL END AS net_amount
           FROM base GROUP BY organization_id, statement_entity, account_kind
           ORDER BY CASE WHEN account_kind = 'agency' THEN 0 ELSE 1 END, statement_entity ASC, organization_id ASC NULLS LAST
         ),
         row_tots AS (
           SELECT src_type, payment_month,
                  CASE WHEN pg_catalog.bool_and(net_amount IS NOT NULL)
                    THEN COALESCE(pg_catalog.sum(net_amount), 0.00)::numeric(14,2)::text ELSE NULL END AS row_total
           FROM base GROUP BY src_type, payment_month
           ORDER BY src_type ASC NULLS LAST, payment_month ASC NULLS LAST
         )
         SELECT
           (SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(cells)), '[]'::jsonb) FROM cells) AS cells_json,
           (SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(ents)), '[]'::jsonb) FROM ents) AS ents_json,
           (SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(row_tots)), '[]'::jsonb) FROM row_tots) AS row_tots_json,
           (SELECT COALESCE(pg_catalog.sum(line_count), 0)::int FROM base) AS line_count,
           (SELECT CASE WHEN pg_catalog.count(*) FILTER (WHERE account_kind = 'agency') > 0
                AND pg_catalog.bool_and(net_amount IS NOT NULL) FILTER (WHERE account_kind = 'agency')
             THEN pg_catalog.sum(net_amount) FILTER (WHERE account_kind = 'agency')::numeric(14,2)::text ELSE NULL END FROM base) AS agency_net_total,
           (SELECT CASE WHEN pg_catalog.count(*) FILTER (WHERE account_kind = 'upline') > 0
                AND pg_catalog.bool_and(net_amount IS NOT NULL) FILTER (WHERE account_kind = 'upline')
             THEN pg_catalog.sum(net_amount) FILTER (WHERE account_kind = 'upline')::numeric(14,2)::text ELSE NULL END FROM base) AS upline_net_total,
           (SELECT CASE WHEN pg_catalog.count(*) > 0 AND pg_catalog.bool_and(net_amount IS NOT NULL)
             THEN pg_catalog.sum(net_amount)::numeric(14,2)::text ELSE NULL END FROM base) AS grand_total`,
        [batchIds],
      )).rows[0];

      const entities = (mat.ents_json || []).map((e) => ({
        organizationId: e.organization_id, statementEntity: e.statement_entity,
        accountKind: e.account_kind, lineCount: Number(e.line_count), netAmount: e.net_amount ?? null,
      }));
      const cells = (mat.cells_json || []).map((c) => ({
        srcType: c.src_type ?? null, paymentMonth: c.payment_month ?? null, organizationId: c.organization_id,
        statementEntity: c.statement_entity, accountKind: c.account_kind,
        lineCount: Number(c.line_count), netAmount: c.net_amount ?? null,
      }));
      const rowTots = (mat.row_tots_json || []).map((rt) => ({
        srcType: rt.src_type ?? null, paymentMonth: rt.payment_month ?? null, rowTotal: rt.row_total ?? null,
      }));
      const summary = {
        lineCount: Number(mat.line_count),
        agencyNetTotal: mat.agency_net_total ?? null,
        uplineNetTotal: mat.upline_net_total ?? null,
        grandTotal: mat.grand_total ?? null,
      };

      if (format === 'csv') {
        assertCsvRowLimit(rowTots.length, csvRowLimit);
        const cellKey = (srcType, paymentMonth, e) => JSON.stringify([
          srcType ?? null, paymentMonth ?? null, e.accountKind, e.organizationId ?? null, e.statementEntity,
        ]);
        const cellMap = new Map(cells.map((c) => [cellKey(c.srcType, c.paymentMonth, c), c.netAmount]));
        const headers = ['src_type', 'payment_month', ...entities.map((e) => e.statementEntity), 'total'];
        const csvRows = rowTots.map((rt) => [
          rt.srcType ?? '', rt.paymentMonth ?? '',
          ...entities.map((e) => csvCell(cellMap.get(cellKey(rt.srcType, rt.paymentMonth, e)))),
          csvCell(rt.rowTotal),
        ]);
        if (entities.length > 0) {
          csvRows.push(['TOTAL', '', ...entities.map((e) => csvCell(e.netAmount)), csvCell(summary.grandTotal)]);
        }
        return buildCsvFile(`statement_matrix_${resolvedDate || mode}.csv`, headers, csvRows, acceptsGzip);
      }
      return {
        companySlug, mode, statementDate: resolvedDate, runId, batchId, batchIds,
        includeUnsent: effectiveIncludeUnsent, entities, cells, summary,
      };
    });
  }

  async function listStatementLines(dbToken, opts = {}) {
    const batchId = parseUuid(opts.batchId, 'batchId');
    const runId = parseUuid(opts.runId, 'runId');
    const organizationId = parseUuid(opts.organizationId, 'organizationId');
    const mode = parseEnum(opts.mode, 'mode', ['cumulative', 'single'], 'cumulative');
    const statementDate = parseDate(opts.statementDate, 'statementDate');
    const throughDate = parseDate(opts.throughDate, 'throughDate');
    const includeUnsent = parseBoolParam(opts.includeUnsent, 'includeUnsent', false);
    const accountKind = parseEnum(opts.accountKind, 'accountKind', ['agency', 'upline']);
    const entryKind = parseEnum(opts.entryKind, 'entryKind', ['historical_sent', 'historical_upline_derived', 'method_correction', 'run_emission']);
    const runAction = parseEnum(opts.runAction, 'runAction', ['SENT', 'CORRECTION', 'NEW', 'RESTATED', 'REVERSAL', 'CANCEL']);
    const srcTypeNull = parseBoolParam(opts.srcTypeNull, 'srcTypeNull', false);
    const paymentMonth = parseMonth(opts.paymentMonth, 'paymentMonth');
    const paymentMonthNull = parseBoolParam(opts.paymentMonthNull, 'paymentMonthNull', false);
    const policyId = parseIntParam(opts.policyId, 'policyId', { min: 0 });
    const txId = parseIntParam(opts.txId, 'txId', { min: 0 });
    const markedSent = parseBoolParam(opts.markedSent, 'markedSent', null);
    const { format, sqlCol, sqlDir, limit, offset, acceptsGzip } = parsePageOptions(
      opts, STATEMENT_LINE_SORT_COLS, batchId ? 'lineNo' : 'statementDate', batchId ? 'asc' : 'desc', csvRowLimit,
    );

    return inReadTx(dbToken, async (tx) => {
      const { batches: batchRows, resolvedDate, includeUnsent: effectiveIncludeUnsent } = await resolveStatementBatchesTx(tx, {
        runId, batchId, statementDate, throughDate, mode, includeUnsent,
      });
      const batchIds = batchRows.map((b) => b.id);
      if (batchIds.length === 0) {
        return format === 'csv'
          ? buildSpecCsvFile('statement_lines_empty.csv', STATEMENT_LINE_CSV_SPEC, [], acceptsGzip)
          : {
            companySlug, mode, statementDate: resolvedDate, runId, batchId, batchIds: [],
            includeUnsent: effectiveIncludeUnsent,
            summary: { lineCount: 0, amountTotal: null, grossCommTotal: null },
            totalCount: 0, limit, offset, rows: [],
          };
      }

      const conds = ['l.batch_id = ANY($1::uuid[])'];
      const params = [batchIds];
      addEqFilter(conds, params, 'l.organization_id', organizationId, '::uuid');
      addEqFilter(conds, params, 'l.statement_entity', trimOpt(opts.statementEntity));
      addEqFilter(conds, params, 'l.source_entity', trimOpt(opts.sourceEntity));
      addEqFilter(conds, params, 'l.account_kind', accountKind);
      addEqFilter(conds, params, 'l.entry_kind', entryKind);
      addEqFilter(conds, params, 'l.run_action', runAction);
      if (srcTypeNull) conds.push('l.src_type IS NULL');
      else addEqFilter(conds, params, 'l.src_type', trimOpt(opts.srcType));
      if (paymentMonthNull) conds.push('l.payment_date IS NULL');
      else if (paymentMonth) {
        params.push(paymentMonth);
        conds.push(`pg_catalog.to_char(l.payment_date, 'YYYY-MM') = $${params.length}`);
      }
      addEqFilter(conds, params, 'l.carrier', trimOpt(opts.carrier));
      addEqFilter(conds, params, 'l.writing_npn', trimOpt(opts.writingNpn));
      addEqFilter(conds, params, 'l.policy_id', policyId, '::int');
      addEqFilter(conds, params, 'l.tx_id', txId, '::int');
      if (markedSent !== null) addEqFilter(conds, params, 'l.marked_sent', markedSent, '::boolean');
      appendSearchFilter(conds, params, trimOpt(opts.q), STATEMENT_LINE_SEARCH_EXPRS);

      const pageParams = [...params, limit, offset];
      const rowsAggSql = format === 'csv'
        ? `(SELECT CASE WHEN (SELECT pg_catalog.count(*) FROM filtered) <= $${pageParams.length - 1}::int
            THEN COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(paged)) FROM paged), '[]'::jsonb)
            ELSE '[]'::jsonb END)`
        : `(SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(paged)), '[]'::jsonb) FROM paged)`;
      const out = (await tx.query(
        `WITH filtered AS MATERIALIZED (
           SELECT l.*, sb.batch_kind, sb.is_sent
           FROM app_views.coherence_entity_statement_lines l
           JOIN app_views.coherence_statement_batches sb ON sb.id = l.batch_id
           WHERE ${conds.join(' AND ')}
         ),
         paged AS (
           SELECT ${statementLineSelectSql('l')} FROM filtered l
           ORDER BY ${sqlCol} ${sqlDir} NULLS LAST, l.statement_date DESC, l.account_kind ASC, l.line_no ASC
           LIMIT $${pageParams.length - 1} OFFSET $${pageParams.length}
         )
         SELECT
           (SELECT pg_catalog.count(*)::int FROM filtered) AS line_count,
           (SELECT CASE WHEN pg_catalog.count(*) > 0 AND pg_catalog.bool_and(amount IS NOT NULL)
             THEN pg_catalog.sum(amount)::numeric(14,2)::text ELSE NULL END FROM filtered) AS amount_total,
           (SELECT CASE WHEN pg_catalog.count(*) > 0 AND pg_catalog.bool_and(gross_comm IS NOT NULL)
             THEN pg_catalog.sum(gross_comm)::numeric(14,2)::text ELSE NULL END FROM filtered) AS gross_comm_total,
           ${rowsAggSql} AS rows_json`,
        pageParams,
      )).rows[0];

      const lineCount = Number(out.line_count);
      if (format === 'csv') {
        assertCsvRowLimit(lineCount, csvRowLimit);
        const rows = (out.rows_json || []).map(mapStatementLine);
        return buildSpecCsvFile(`statement_lines_${resolvedDate || 'all'}.csv`, STATEMENT_LINE_CSV_SPEC, rows, acceptsGzip);
      }
      const rows = (out.rows_json || []).map(mapStatementLine);
      return {
        companySlug, mode, statementDate: resolvedDate, runId, batchId, batchIds,
        includeUnsent: effectiveIncludeUnsent,
        summary: {
          lineCount,
          amountTotal: out.amount_total ?? null,
          grossCommTotal: out.gross_comm_total ?? null,
        },
        totalCount: lineCount, limit, offset, rows,
      };
    });
  }

  async function getStatementReconciliation(dbToken, opts = {}) {
    const runId = parseUuid(opts.runId, 'runId');

    return inReadTx(dbToken, async (tx) => {
      const rec = (await tx.query(
        `WITH all_rec AS MATERIALIZED (
           SELECT rec.run_id, rec.attempt_event_id, rec.statement_date,
                  rec.statement_entity, rec.account_kind,
                  rec.statement_total, rec.ledger_total, rec.variance, rec.reconciled,
                  pr.sent, pr.folder_number, pr.journal_seq
           FROM app_views.coherence_entity_statement_reconciliation rec
           LEFT JOIN app_views.coherence_published_runs pr ON pr.id = rec.run_id
         ),
         runs_cte AS (
           SELECT run_id AS id, attempt_event_id,
                  pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date,
                  COALESCE(sent, false) AS sent, pg_catalog.bool_and(reconciled) AS reconciled
           FROM all_rec
           GROUP BY run_id, attempt_event_id, statement_date, sent, folder_number, journal_seq
           ORDER BY statement_date DESC, folder_number DESC NULLS LAST, journal_seq DESC NULLS LAST
         ),
         target_run AS (
           SELECT id, attempt_event_id, statement_date, sent FROM runs_cte
           WHERE ($1::uuid IS NULL OR id = $1::uuid) LIMIT 1
         ),
         target_rows AS (
           SELECT ar.run_id, ar.attempt_event_id,
                  pg_catalog.to_char(ar.statement_date, 'YYYY-MM-DD') AS statement_date,
                  ar.statement_entity, ar.account_kind,
                  ar.statement_total::text AS statement_total,
                  ar.ledger_total::text AS ledger_total,
                  ar.variance::text AS variance, ar.reconciled
           FROM all_rec ar JOIN target_run tr ON tr.id = ar.run_id
           ORDER BY CASE WHEN ar.account_kind = 'agency' THEN 0 ELSE 1 END, ar.statement_entity ASC
         )
         SELECT
           (SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(runs_cte)), '[]'::jsonb) FROM runs_cte) AS runs_json,
           (SELECT pg_catalog.to_jsonb(target_run) FROM target_run LIMIT 1) AS target_run_json,
           (SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(target_rows)), '[]'::jsonb) FROM target_rows) AS rows_json,
           (SELECT pg_catalog.sum(ar.statement_total)::numeric(14,2)::text FROM all_rec ar JOIN target_run tr ON tr.id = ar.run_id) AS statement_total,
           (SELECT pg_catalog.sum(ar.ledger_total)::numeric(14,2)::text FROM all_rec ar JOIN target_run tr ON tr.id = ar.run_id) AS ledger_total,
           (SELECT pg_catalog.sum(ar.variance)::numeric(14,2)::text FROM all_rec ar JOIN target_run tr ON tr.id = ar.run_id) AS variance,
           (SELECT pg_catalog.bool_and(ar.reconciled) FROM all_rec ar JOIN target_run tr ON tr.id = ar.run_id) AS reconciled`,
        [runId],
      )).rows[0];

      const runs = (rec.runs_json || []).map((r) => ({
        id: r.id, attemptEventId: r.attempt_event_id, statementDate: r.statement_date,
        sent: Boolean(r.sent), reconciled: Boolean(r.reconciled),
      }));
      const target = rec.target_run_json;
      if (runId && !target) throw new AppError('Run not found.', 404, 'RUN_NOT_FOUND');
      if (!target) {
        return {
          companySlug, available: false, run: null, runs: [], reconciled: null,
          summary: { statementTotal: null, ledgerTotal: null, variance: null }, rows: [],
        };
      }
      return {
        companySlug, available: true,
        run: { id: target.id, attemptEventId: target.attempt_event_id, statementDate: target.statement_date, sent: Boolean(target.sent) },
        runs, reconciled: Boolean(rec.reconciled),
        summary: { statementTotal: rec.statement_total ?? null, ledgerTotal: rec.ledger_total ?? null, variance: rec.variance ?? null },
        rows: (rec.rows_json || []).map((r) => ({
          runId: r.run_id, attemptEventId: r.attempt_event_id, statementDate: r.statement_date,
          statementEntity: r.statement_entity, accountKind: r.account_kind,
          statementTotal: r.statement_total, ledgerTotal: r.ledger_total,
          variance: r.variance, reconciled: Boolean(r.reconciled),
        })),
      };
    });
  }

  async function listViewAsCandidates(dbToken, opts = {}) {
    const organizationId = parseUuid(opts.organizationId, 'organizationId');
    const roleSlug = trimOpt(opts.roleSlug);
    const search = trimOpt(opts.q)?.toLowerCase() ?? null;

    return inReadTx(dbToken, async (tx) => {
      const [ctxRes, orgsRes, peopleRes] = await Promise.all([
        tx.query(
          `SELECT session_id, actor_person_id, view_as_person_id, effective_person_id,
                  is_viewing_as, environment, db_role_kind, tenant_org_id,
                  company_slug, support_external_label
           FROM app_views.iam_my_context LIMIT 1`,
        ),
        tx.query(
          `SELECT id, org_kind, slug, display_name, masked_display_name, is_vendor_name_masked, status
           FROM app_views.iam_organizations WHERE status = 'active'
           ORDER BY CASE org_kind
             WHEN 'platform_root' THEN 0 WHEN 'company' THEN 1 WHEN 'agency' THEN 2
             WHEN 'team' THEN 3 WHEN 'lead_vendor' THEN 4 ELSE 5 END, display_name ASC`,
        ),
        tx.query(
          `SELECT id, person_kind, principal_origin, house_org_id,
                  legal_name, preferred_name, primary_email, npn, status
           FROM app_views.iam_people
           WHERE person_kind = 'human' AND principal_origin = 'company_local' AND status = 'active'
           ORDER BY preferred_name ASC, npn ASC NULLS LAST, id ASC`,
        ),
      ]);

      const ctxRow = ctxRes.rows[0] || null;
      const context = ctxRow ? {
        sessionId: ctxRow.session_id, actorPersonId: ctxRow.actor_person_id,
        viewAsPersonId: ctxRow.view_as_person_id, effectivePersonId: ctxRow.effective_person_id,
        isViewingAs: Boolean(ctxRow.is_viewing_as), environment: ctxRow.environment,
        dbRoleKind: ctxRow.db_role_kind, tenantOrgId: ctxRow.tenant_org_id,
        companySlug: ctxRow.company_slug, supportExternalLabel: ctxRow.support_external_label,
      } : null;

      const organizations = orgsRes.rows.map((o) => ({
        id: o.id, orgKind: o.org_kind, slug: o.slug, displayName: o.display_name,
        maskedDisplayName: o.masked_display_name, isVendorNameMasked: Boolean(o.is_vendor_name_masked),
        status: o.status,
      }));
      const orgById = new Map(organizations.map((o) => [o.id, o]));
      if (peopleRes.rows.length === 0) return { companySlug, context, organizations, candidates: [] };

      const personIds = peopleRes.rows.map((p) => p.id);
      const [memRes, affRes, grantsRes] = await Promise.all([
        tx.query(
          `SELECT person_id, organization_id FROM app_views.iam_memberships
           WHERE person_id = ANY($1::uuid[]) AND status = 'active' AND valid_range @> iam.business_today()`,
          [personIds],
        ),
        tx.query(
          `SELECT person_id, agency_org_id FROM app_views.iam_agent_affiliations
           WHERE person_id = ANY($1::uuid[]) AND status = 'active' AND valid_range @> iam.business_today()`,
          [personIds],
        ),
        tx.query(
          `SELECT g.id AS grant_id, g.person_id, g.role_id, g.role_slug,
                  r.display_name AS role_display_name, g.organization_id,
                  g.include_descendants, g.person_scope_mode
           FROM app_views.iam_role_grants g
           JOIN app_views.iam_roles r ON r.id = g.role_id
           WHERE g.person_id = ANY($1::uuid[]) AND g.status = 'active' AND g.valid_range @> iam.business_today()
           ORDER BY r.display_name ASC, g.role_slug ASC`,
          [personIds],
        ),
      ]);

      const orgIdsByPerson = new Map();
      const addOrg = (pid, oid) => {
        if (!oid || !orgById.has(oid)) return;
        let set = orgIdsByPerson.get(pid);
        if (!set) { set = new Set(); orgIdsByPerson.set(pid, set); }
        set.add(oid);
      };
      for (const p of peopleRes.rows) addOrg(p.id, p.house_org_id);
      for (const m of memRes.rows) addOrg(m.person_id, m.organization_id);
      for (const a of affRes.rows) addOrg(a.person_id, a.agency_org_id);

      const rolesByPerson = new Map();
      for (const g of grantsRes.rows) {
        addOrg(g.person_id, g.organization_id);
        const org = orgById.get(g.organization_id);
        const list = rolesByPerson.get(g.person_id) || [];
        list.push({
          grantId: g.grant_id, roleId: g.role_id, roleSlug: g.role_slug,
          roleDisplayName: g.role_display_name, organizationId: g.organization_id,
          organizationName: org?.displayName ?? null, orgKind: org?.orgKind ?? null,
          includeDescendants: Boolean(g.include_descendants), personScopeMode: g.person_scope_mode,
        });
        rolesByPerson.set(g.person_id, list);
      }

      let candidates = peopleRes.rows.map((p) => ({
        id: p.id, personKind: p.person_kind, principalOrigin: p.principal_origin,
        legalName: p.legal_name, preferredName: p.preferred_name,
        primaryEmail: p.primary_email, npn: p.npn, status: p.status,
        organizations: [...(orgIdsByPerson.get(p.id) || [])]
          .map((oid) => orgById.get(oid))
          .filter(Boolean)
          .map(({ id, orgKind, slug, displayName, isVendorNameMasked }) => ({ id, orgKind, slug, displayName, isVendorNameMasked })),
        roles: rolesByPerson.get(p.id) || [],
      }));

      if (organizationId) candidates = candidates.filter((c) => c.organizations.some((o) => o.id === organizationId));
      if (roleSlug) candidates = candidates.filter((c) => c.roles.some((r) => r.roleSlug === roleSlug));
      if (search) {
        candidates = candidates.filter((c) => (
          (c.preferredName && c.preferredName.toLowerCase().includes(search))
          || (c.legalName && c.legalName.toLowerCase().includes(search))
          || (c.npn && c.npn.toLowerCase().includes(search))
          || c.organizations.some((o) => o.displayName && o.displayName.toLowerCase().includes(search))
          || c.roles.some((r) => (
            (r.roleSlug && r.roleSlug.toLowerCase().includes(search))
            || (r.roleDisplayName && r.roleDisplayName.toLowerCase().includes(search))
          ))
        ));
      }

      return { companySlug, context, organizations, candidates };
    });
  }

  return {
    getBookOfBusiness,
    getPolicyDetail,
    getCoherentLedger,
    getLedgerTransactionDetail,
    listStatementBatches,
    getStatementMatrix,
    listStatementLines,
    getStatementReconciliation,
    listViewAsCandidates,
  };
}
