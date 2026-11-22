-- Migration 006: entity statement views, security_invoker + security_barrier recipient views,
-- fail-closed FORCE ROW LEVEL SECURITY policies, and five least-privilege read-only roles.
-- All functions pin SET search_path = pg_catalog and schema-qualify all references.

CREATE SCHEMA IF NOT EXISTS coherence_views;

-- 1. RLS and display helper functions (pinned to pg_catalog).
CREATE OR REPLACE FUNCTION coherence.upline_entity_label()
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT COALESCE(
    (SELECT display_name || ' Upline' FROM coherence.company_meta LIMIT 1),
    'Upline'
  );
$$;

CREATE OR REPLACE FUNCTION coherence.rls_allowed_entities()
RETURNS text[]
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT CASE
    WHEN pg_catalog.length(pg_catalog.btrim(COALESCE(pg_catalog.current_setting('app.allowed_entities', true), ''))) = 0
      THEN ARRAY[]::text[]
    ELSE pg_catalog.string_to_array(pg_catalog.current_setting('app.allowed_entities', true), ',')
  END;
$$;

CREATE OR REPLACE FUNCTION coherence.rls_actor_npn()
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT NULLIF(pg_catalog.btrim(COALESCE(pg_catalog.current_setting('app.actor_npn', true), '')), '');
$$;

CREATE OR REPLACE FUNCTION coherence.rls_access_tier()
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT NULLIF(pg_catalog.btrim(COALESCE(pg_catalog.current_setting('app.access_tier', true), '')), '');
$$;

CREATE OR REPLACE FUNCTION coherence.batch_is_official_sent(p_batch_id uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM coherence.statement_batches sb
    WHERE sb.id = p_batch_id
      AND (
        sb.batch_kind IN ('historical_sent', 'method_correction')
        OR (
          sb.batch_kind = 'run_emission'
          AND EXISTS (
            SELECT 1 FROM coherence.carries c
            WHERE c.run_id = sb.run_id AND c.carry_kind = 'sent'
          )
          AND NOT EXISTS (
            SELECT 1 FROM coherence.abandonments a
            WHERE a.run_id = sb.run_id
          )
        )
      )
  );
$$;

CREATE OR REPLACE FUNCTION coherence.attempt_is_published_run(p_attempt_event_id uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM coherence.step_attempt_events e
    JOIN coherence.runs r ON r.id = e.run_id
    WHERE e.id = p_attempt_event_id
      AND e.step = 'emit'
      AND e.event_kind = 'finished'
      AND r.origin IN ('app', 'company_import')
      AND NOT EXISTS (
        SELECT 1 FROM coherence.abandonments a WHERE a.run_id = r.id
      )
      AND NOT EXISTS (
        SELECT 1 FROM coherence.step_attempt_events sup
        WHERE sup.run_id = e.run_id AND sup.step = e.step
          AND sup.attempt_no = e.attempt_no AND sup.event_kind = 'superseded'
      )
  );
$$;

CREATE OR REPLACE FUNCTION coherence.batch_is_published_for_em(p_batch_id uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM coherence.statement_batches sb
    WHERE sb.id = p_batch_id
      AND (
        sb.batch_kind IN ('historical_sent', 'method_correction')
        OR (
          sb.batch_kind = 'run_emission'
          AND coherence.attempt_is_published_run(sb.attempt_event_id)
        )
      )
  );
$$;

-- 2. Views in coherence_views, all defined WITH (security_invoker = true, security_barrier = true).
CREATE OR REPLACE VIEW coherence_views.v_canonical_bob
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  bp.attempt_event_id,
  bp.run_id,
  bp.external_policy_id,
  bp.policy_id,
  bp.carrier_policy_number,
  bp.crm_policy_number,
  bpf.enrollment_code,
  bp.carrier,
  bp.plan_type,
  bp.plan_name,
  bp.simple_plan_type,
  bp.mbi,
  bp.member,
  bp.dob,
  bp.phone,
  bp.email,
  bp.address,
  bp.county,
  bp.state,
  bp.submission_date,
  bp.origin_effective,
  bp.effective_date,
  bp.termination_date,
  bpf.min_date,
  bpf.anchor_date,
  bpf.amount,
  bpf.upline_amount,
  bp.writing_npn,
  bp.writing_agent,
  bp.entity,
  bpf.agency_id,
  bp.status,
  bp.coherent_status,
  bpf.conflicts,
  bpf.spine_source,
  bpf.confidence_level,
  bpf.coherent_trajectory,
  bp.journal_seq
FROM coherence.bob_policies bp
JOIN coherence.bob_policy_financials bpf
  ON bpf.attempt_event_id = bp.attempt_event_id AND bpf.policy_id = bp.policy_id;

CREATE OR REPLACE VIEW coherence_views.v_official_statement_batches
WITH (security_invoker = true, security_barrier = true) AS
SELECT sb.*
FROM coherence.statement_batches sb
WHERE coherence.batch_is_official_sent(sb.id);

CREATE OR REPLACE FUNCTION coherence_views.v_run_effective_batches(p_run_id uuid)
RETURNS SETOF coherence.statement_batches
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT sb.*
  FROM coherence.statement_batches sb
  JOIN coherence.run_effective_statement_batches(p_run_id) eff ON eff.batch_id = sb.id
  ORDER BY sb.statement_date ASC, sb.journal_seq ASC, sb.id ASC;
$$;

CREATE OR REPLACE VIEW coherence_views.v_entity_statement_lines
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  sal.batch_id,
  sal.line_no,
  sal.statement_date,
  sal.entry_kind,
  sal.run_action,
  sal.entity AS statement_entity,
  'agency'::text AS account_kind,
  sal.entity AS source_entity,
  true AS marked_sent,
  sal.writing_npn,
  sal.writing_agent,
  sal.record_id,
  sal.reversal_of,
  sal.corrects_record_id,
  sal.source_file,
  sal.sheet_name,
  sal.source_row_no,
  sal.src_type,
  sal.carrier,
  sal.mbi,
  sal.member,
  sal.external_policy_id,
  sal.policy_id,
  sal.tx_id,
  sal.plan_type,
  sal.simple_plan_type,
  sal.state,
  sal.submission_date,
  sal.origin_effective,
  sal.effective_date,
  sal.termination_date,
  sal.earned_date,
  sal.payment_date,
  sal.posted_statement_date,
  sal.revenue_type,
  sal.gross_comm,
  sal.amount,
  sal.reason,
  sal.notes,
  sal.journal_seq
FROM coherence.statement_agency_lines sal
UNION ALL
SELECT
  sul.batch_id,
  sul.line_no,
  sul.statement_date,
  sul.entry_kind,
  sul.run_action,
  coherence.upline_entity_label() AS statement_entity,
  'upline'::text AS account_kind,
  sul.source_entity,
  sul.marked_sent,
  sul.writing_npn,
  sul.writing_agent,
  sul.record_id,
  sul.reversal_of,
  sul.corrects_record_id,
  sul.source_file,
  sul.sheet_name,
  sul.source_row_no,
  sul.src_type,
  sul.carrier,
  sul.mbi,
  sul.member,
  sul.external_policy_id,
  sul.policy_id,
  sul.tx_id,
  sul.plan_type,
  sul.simple_plan_type,
  sul.state,
  sul.submission_date,
  sul.origin_effective,
  sul.effective_date,
  sul.termination_date,
  sul.earned_date,
  sul.payment_date,
  sul.posted_statement_date,
  sul.revenue_type,
  sul.gross_comm,
  sul.amount,
  sul.reason,
  sul.notes,
  sul.journal_seq
FROM coherence.statement_upline_lines sul;

CREATE OR REPLACE VIEW coherence_views.v_entity_statement_totals
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  batch_id,
  statement_date,
  statement_entity,
  account_kind,
  src_type,
  pg_catalog.to_char(payment_date, 'YYYY-MM') AS payment_month,
  pg_catalog.count(*)::bigint AS line_count,
  COALESCE(pg_catalog.sum(amount), 0.00)::numeric(14,2) AS net_amount
FROM coherence_views.v_entity_statement_lines
GROUP BY batch_id, statement_date, statement_entity, account_kind, src_type, pg_catalog.to_char(payment_date, 'YYYY-MM');

CREATE OR REPLACE VIEW coherence_views.v_entity_statement_date_totals
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  statement_date,
  statement_entity,
  account_kind,
  pg_catalog.count(*)::bigint AS line_count,
  COALESCE(pg_catalog.sum(amount), 0.00)::numeric(14,2) AS net_amount
FROM coherence_views.v_entity_statement_lines
GROUP BY statement_date, statement_entity, account_kind;

CREATE OR REPLACE VIEW coherence_views.v_statement_membership
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  policy_id,
  tx_id,
  record_id,
  statement_date,
  statement_entity,
  account_kind,
  run_action,
  pg_catalog.count(*)::bigint AS appearances,
  COALESCE(pg_catalog.sum(amount), 0.00)::numeric(14,2) AS net_amount
FROM coherence_views.v_entity_statement_lines
GROUP BY policy_id, tx_id, record_id, statement_date, statement_entity, account_kind, run_action;

CREATE OR REPLACE FUNCTION coherence_views.v_entity_statement_reconciliation(p_run_id uuid)
RETURNS TABLE (
  statement_entity text,
  account_kind text,
  statement_total numeric(14,2),
  ledger_total numeric(14,2),
  variance numeric(14,2),
  reconciled boolean
)
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  WITH rm AS (
    SELECT attempt_event_id FROM coherence.run_materializations WHERE run_id = p_run_id
  ),
  eff AS (
    SELECT batch_id FROM coherence.run_effective_statement_batches(p_run_id)
  ),
  stmt_ag AS (
    SELECT sal.entity AS statement_entity, 'agency'::text AS account_kind,
           COALESCE(pg_catalog.sum(sal.amount), 0.00)::numeric(14,2) AS statement_total
    FROM coherence.statement_agency_lines sal
    JOIN eff ON eff.batch_id = sal.batch_id
    GROUP BY sal.entity
  ),
  led_ag AS (
    SELECT clr.entity AS statement_entity, 'agency'::text AS account_kind,
           COALESCE(pg_catalog.sum(clr.downline_amount), 0.00)::numeric(14,2) AS ledger_total
    FROM coherence.coherent_ledger_rows clr
    JOIN rm ON rm.attempt_event_id = clr.attempt_event_id
    GROUP BY clr.entity
  ),
  ag_joined AS (
    SELECT
      COALESCE(s.statement_entity, l.statement_entity) AS statement_entity,
      'agency'::text AS account_kind,
      COALESCE(s.statement_total, 0.00)::numeric(14,2) AS statement_total,
      COALESCE(l.ledger_total, 0.00)::numeric(14,2) AS ledger_total
    FROM stmt_ag s
    FULL OUTER JOIN led_ag l ON l.statement_entity = s.statement_entity
  ),
  up_joined AS (
    SELECT
      coherence.upline_entity_label() AS statement_entity,
      'upline'::text AS account_kind,
      COALESCE((
        SELECT pg_catalog.sum(sul.amount)
        FROM coherence.statement_upline_lines sul
        JOIN eff ON eff.batch_id = sul.batch_id
      ), 0.00)::numeric(14,2) AS statement_total,
      COALESCE((
        SELECT pg_catalog.sum(clr.upline_amount)
        FROM coherence.coherent_ledger_rows clr
        JOIN rm ON rm.attempt_event_id = clr.attempt_event_id
      ), 0.00)::numeric(14,2) AS ledger_total
  ),
  combined AS (
    SELECT * FROM ag_joined
    UNION ALL
    SELECT * FROM up_joined
  )
  SELECT
    statement_entity,
    account_kind,
    statement_total,
    ledger_total,
    (statement_total - ledger_total)::numeric(14,2) AS variance,
    (statement_total = ledger_total) AS reconciled
  FROM combined
  ORDER BY account_kind ASC, statement_entity COLLATE "C" ASC;
$$;

-- Scoped recipient views (all security_invoker = true, security_barrier = true).
CREATE OR REPLACE VIEW coherence_views.agency_bob
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  bp.attempt_event_id,
  bp.run_id,
  bp.policy_id,
  bp.external_policy_id,
  bp.carrier_policy_number,
  bp.crm_policy_number,
  bp.carrier,
  bp.plan_type,
  bp.plan_name,
  bp.simple_plan_type,
  bp.mbi,
  bp.member,
  bp.dob,
  bp.phone,
  bp.email,
  bp.address,
  bp.county,
  bp.state,
  bp.submission_date,
  bp.origin_effective,
  bp.effective_date,
  bp.termination_date,
  bp.writing_npn,
  bp.writing_agent,
  bp.entity,
  bpf.amount
FROM coherence.bob_policies bp
JOIN coherence.bob_policy_financials bpf
  ON bpf.attempt_event_id = bp.attempt_event_id AND bpf.policy_id = bp.policy_id;

CREATE OR REPLACE VIEW coherence_views.agency_statement_lines
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  sal.batch_id,
  sal.line_no,
  sal.statement_date,
  sal.entry_kind,
  sal.run_action,
  sal.entity,
  sal.writing_npn,
  sal.writing_agent,
  sal.record_id,
  sal.reversal_of,
  sal.corrects_record_id,
  sal.source_file,
  sal.sheet_name,
  sal.source_row_no,
  sal.src_type,
  sal.carrier,
  sal.mbi,
  sal.member,
  sal.external_policy_id,
  sal.policy_id,
  sal.tx_id,
  sal.plan_type,
  sal.simple_plan_type,
  sal.state,
  sal.submission_date,
  sal.origin_effective,
  sal.effective_date,
  sal.termination_date,
  sal.earned_date,
  sal.payment_date,
  sal.posted_statement_date,
  sal.revenue_type,
  sal.amount,
  sal.reason,
  sal.notes
FROM coherence.statement_agency_lines sal;

CREATE OR REPLACE VIEW coherence_views.agency_statement_totals
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  batch_id,
  statement_date,
  entity,
  src_type,
  pg_catalog.to_char(payment_date, 'YYYY-MM') AS payment_month,
  pg_catalog.count(*)::bigint AS line_count,
  COALESCE(pg_catalog.sum(amount), 0.00)::numeric(14,2) AS net_amount
FROM coherence_views.agency_statement_lines
GROUP BY batch_id, statement_date, entity, src_type, pg_catalog.to_char(payment_date, 'YYYY-MM');

CREATE OR REPLACE VIEW coherence_views.agent_bob
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  bp.attempt_event_id,
  bp.run_id,
  bp.policy_id,
  bp.external_policy_id,
  bp.carrier_policy_number,
  bp.crm_policy_number,
  bp.carrier,
  bp.plan_type,
  bp.plan_name,
  bp.simple_plan_type,
  bp.mbi,
  bp.member,
  bp.dob,
  bp.phone,
  bp.email,
  bp.address,
  bp.county,
  bp.state,
  bp.submission_date,
  bp.origin_effective,
  bp.effective_date,
  bp.termination_date,
  bp.writing_npn,
  bp.writing_agent,
  bp.entity,
  bp.status
FROM coherence.bob_policies bp;

CREATE OR REPLACE VIEW coherence_views.agent_statement_activity
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  sal.batch_id,
  sal.line_no,
  sal.statement_date,
  sal.entry_kind,
  sal.run_action,
  sal.entity,
  sal.writing_npn,
  sal.writing_agent,
  sal.source_file,
  sal.src_type,
  sal.carrier,
  sal.mbi,
  sal.member,
  sal.external_policy_id,
  sal.policy_id,
  sal.plan_type,
  sal.simple_plan_type,
  sal.state,
  sal.submission_date,
  sal.origin_effective,
  sal.effective_date,
  sal.termination_date,
  sal.earned_date,
  sal.payment_date,
  sal.posted_statement_date,
  sal.revenue_type,
  sal.reason,
  sal.notes
FROM coherence.statement_agency_lines sal;

CREATE OR REPLACE VIEW coherence_views.retention_bob
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  bp.attempt_event_id,
  bp.run_id,
  bp.policy_id,
  bp.external_policy_id,
  bp.carrier_policy_number,
  bp.crm_policy_number,
  bp.carrier,
  bp.plan_type,
  bp.plan_name,
  bp.simple_plan_type,
  bp.mbi,
  bp.member,
  bp.dob,
  bp.phone,
  bp.email,
  bp.address,
  bp.county,
  bp.state,
  bp.submission_date,
  bp.origin_effective,
  bp.effective_date,
  bp.termination_date,
  bp.writing_npn,
  bp.writing_agent,
  bp.entity,
  bp.status
FROM coherence.bob_policies bp;

CREATE OR REPLACE VIEW coherence_views.retention_statement_activity
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  sal.batch_id,
  sal.line_no,
  sal.statement_date,
  sal.entry_kind,
  sal.run_action,
  sal.entity,
  sal.writing_npn,
  sal.writing_agent,
  sal.source_file,
  sal.src_type,
  sal.carrier,
  sal.mbi,
  sal.member,
  sal.external_policy_id,
  sal.policy_id,
  sal.plan_type,
  sal.simple_plan_type,
  sal.state,
  sal.submission_date,
  sal.origin_effective,
  sal.effective_date,
  sal.termination_date,
  sal.earned_date,
  sal.payment_date,
  sal.posted_statement_date,
  sal.revenue_type,
  sal.reason,
  sal.notes
FROM coherence.statement_agency_lines sal;

CREATE OR REPLACE VIEW coherence_views.investor_bob
WITH (security_invoker = true, security_barrier = true) AS
SELECT
  bp.attempt_event_id,
  bp.run_id,
  bp.external_policy_id,
  bp.policy_id,
  bp.carrier_policy_number,
  bp.crm_policy_number,
  bpf.enrollment_code,
  bp.carrier,
  bp.plan_type,
  bp.plan_name,
  bp.simple_plan_type,
  bp.mbi,
  bp.member,
  bp.dob,
  bp.phone,
  bp.email,
  bp.address,
  bp.county,
  bp.state,
  bp.submission_date,
  bp.origin_effective,
  bp.effective_date,
  bp.termination_date,
  bpf.min_date,
  bpf.anchor_date,
  bpf.amount,
  bpf.upline_amount,
  bp.writing_npn,
  bp.writing_agent,
  bp.entity,
  bpf.agency_id,
  bp.status,
  bp.coherent_status,
  bpf.conflicts,
  bpf.spine_source,
  bpf.confidence_level,
  bpf.coherent_trajectory,
  bp.journal_seq
FROM coherence.bob_policies bp
JOIN coherence.bob_policy_financials bpf
  ON bpf.attempt_event_id = bp.attempt_event_id AND bpf.policy_id = bp.policy_id;

-- 3. Create five dedicated NOINHERIT, NOBYPASSRLS read-only roles and enforce FORCE ROW LEVEL SECURITY.
DO $$
DECLARE
  v_role text;
  v_tbl text;
BEGIN
  FOREACH v_role IN ARRAY ARRAY[
    'coherence_entity_manager_ro',
    'coherence_agency_manager_ro',
    'coherence_agent_ro',
    'coherence_retention_ro',
    'coherence_investor_ro'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
      BEGIN
        EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN NOINHERIT NOBYPASSRLS', v_role);
      EXCEPTION WHEN insufficient_privilege THEN
        NULL;
      END;
    END IF;
  END LOOP;

  -- Revoke all PUBLIC privileges on coherence and coherence_views objects added by migrations 004-006.
  REVOKE ALL ON SCHEMA coherence FROM PUBLIC;
  REVOKE ALL ON ALL TABLES IN SCHEMA coherence FROM PUBLIC;
  REVOKE ALL ON ALL FUNCTIONS IN SCHEMA coherence FROM PUBLIC;
  REVOKE ALL ON SCHEMA coherence_views FROM PUBLIC;
  REVOKE ALL ON ALL TABLES IN SCHEMA coherence_views FROM PUBLIC;
  REVOKE ALL ON ALL FUNCTIONS IN SCHEMA coherence_views FROM PUBLIC;

  -- Update grants for core operational roles (coherence_readonly, coherence_app, coherence_worker).
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'coherence_readonly') THEN
    GRANT USAGE ON SCHEMA coherence TO coherence_readonly;
    GRANT SELECT ON ALL TABLES IN SCHEMA coherence TO coherence_readonly;
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA coherence TO coherence_readonly;
    GRANT USAGE ON SCHEMA coherence_views TO coherence_readonly;
    GRANT SELECT ON ALL TABLES IN SCHEMA coherence_views TO coherence_readonly;
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA coherence_views TO coherence_readonly;
  END IF;

  FOREACH v_role IN ARRAY ARRAY['coherence_app', 'coherence_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
      EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA coherence TO %I', v_role);
      EXECUTE pg_catalog.format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA coherence TO %I', v_role);
      EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA coherence_views TO %I', v_role);
      EXECUTE pg_catalog.format('GRANT SELECT ON ALL TABLES IN SCHEMA coherence_views TO %I', v_role);
      EXECUTE pg_catalog.format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA coherence_views TO %I', v_role);
      EXECUTE pg_catalog.format('GRANT SELECT ON coherence.run_states TO %I', v_role);
      FOREACH v_tbl IN ARRAY ARRAY[
        'decision_commits', 'decisions', 'generated_overlays', 'review_queue_items',
        'statement_batches', 'statement_agency_lines', 'statement_upline_lines',
        'run_materializations', 'bob_policies', 'bob_policy_financials', 'coherent_ledger_rows'
      ] LOOP
        EXECUTE pg_catalog.format('GRANT SELECT, INSERT ON coherence.%I TO %I', v_tbl, v_role);
      END LOOP;
    END IF;
  END LOOP;

  -- Scoped read-only grants for the five recipient roles.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'coherence_entity_manager_ro') THEN
    GRANT USAGE ON SCHEMA coherence, coherence_views TO coherence_entity_manager_ro;
    GRANT SELECT ON
      coherence.bob_policies,
      coherence.bob_policy_financials,
      coherence.coherent_ledger_rows,
      coherence.statement_batches,
      coherence.statement_agency_lines,
      coherence.statement_upline_lines,
      coherence.run_materializations,
      coherence.runs,
      coherence.carries
    TO coherence_entity_manager_ro;
    GRANT SELECT ON
      coherence_views.v_canonical_bob,
      coherence_views.v_official_statement_batches,
      coherence_views.v_entity_statement_lines,
      coherence_views.v_entity_statement_totals,
      coherence_views.v_entity_statement_date_totals,
      coherence_views.v_statement_membership
    TO coherence_entity_manager_ro;
    GRANT EXECUTE ON FUNCTION
      coherence.upline_entity_label(),
      coherence.rls_allowed_entities(),
      coherence.rls_actor_npn(),
      coherence.rls_access_tier(),
      coherence.batch_is_official_sent(uuid),
      coherence.batch_is_published_for_em(uuid),
      coherence.attempt_is_published_run(uuid),
      coherence.run_effective_statement_batches(uuid),
      coherence_views.v_run_effective_batches(uuid),
      coherence_views.v_entity_statement_reconciliation(uuid)
    TO coherence_entity_manager_ro;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'coherence_agency_manager_ro') THEN
    GRANT USAGE ON SCHEMA coherence, coherence_views TO coherence_agency_manager_ro;
    GRANT SELECT ON coherence.bob_policies, coherence.statement_batches, coherence.statement_agency_lines
      TO coherence_agency_manager_ro;
    -- Strictly column-scoped grant: agency managers never receive upline_amount or internal provenance columns.
    GRANT SELECT (attempt_event_id, policy_id, entity, writing_npn, amount)
      ON coherence.bob_policy_financials TO coherence_agency_manager_ro;
    GRANT SELECT ON
      coherence_views.agency_bob,
      coherence_views.agency_statement_lines,
      coherence_views.agency_statement_totals
    TO coherence_agency_manager_ro;
    GRANT EXECUTE ON FUNCTION
      coherence.rls_allowed_entities(),
      coherence.rls_actor_npn(),
      coherence.rls_access_tier(),
      coherence.batch_is_official_sent(uuid),
      coherence.attempt_is_published_run(uuid)
    TO coherence_agency_manager_ro;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'coherence_agent_ro') THEN
    GRANT USAGE ON SCHEMA coherence, coherence_views TO coherence_agent_ro;
    GRANT SELECT ON coherence.bob_policies, coherence.statement_batches TO coherence_agent_ro;
    -- Zero-dollar column grant: gross_comm and amount are NOT granted to agents.
    GRANT SELECT (
      batch_id, line_no, statement_date, entry_kind, run_action, entity,
      writing_npn, writing_agent, source_file, sheet_name, source_row_no,
      src_type, carrier, mbi, member, external_policy_id, policy_id, tx_id,
      plan_type, simple_plan_type, state, submission_date, origin_effective,
      effective_date, termination_date, earned_date, payment_date,
      posted_statement_date, revenue_type, reason, notes
    ) ON coherence.statement_agency_lines TO coherence_agent_ro;
    GRANT SELECT ON
      coherence_views.agent_bob,
      coherence_views.agent_statement_activity
    TO coherence_agent_ro;
    GRANT EXECUTE ON FUNCTION
      coherence.rls_allowed_entities(),
      coherence.rls_actor_npn(),
      coherence.rls_access_tier(),
      coherence.batch_is_official_sent(uuid),
      coherence.attempt_is_published_run(uuid)
    TO coherence_agent_ro;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'coherence_retention_ro') THEN
    GRANT USAGE ON SCHEMA coherence, coherence_views TO coherence_retention_ro;
    GRANT SELECT ON coherence.bob_policies, coherence.statement_batches TO coherence_retention_ro;
    GRANT SELECT (
      batch_id, line_no, statement_date, entry_kind, run_action, entity,
      writing_npn, writing_agent, source_file, sheet_name, source_row_no,
      src_type, carrier, mbi, member, external_policy_id, policy_id, tx_id,
      plan_type, simple_plan_type, state, submission_date, origin_effective,
      effective_date, termination_date, earned_date, payment_date,
      posted_statement_date, revenue_type, reason, notes
    ) ON coherence.statement_agency_lines TO coherence_retention_ro;
    GRANT SELECT ON
      coherence_views.retention_bob,
      coherence_views.retention_statement_activity
    TO coherence_retention_ro;
    GRANT EXECUTE ON FUNCTION
      coherence.rls_allowed_entities(),
      coherence.rls_actor_npn(),
      coherence.rls_access_tier(),
      coherence.batch_is_official_sent(uuid),
      coherence.attempt_is_published_run(uuid)
    TO coherence_retention_ro;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'coherence_investor_ro') THEN
    GRANT USAGE ON SCHEMA coherence, coherence_views TO coherence_investor_ro;
    GRANT SELECT ON
      coherence.bob_policies,
      coherence.bob_policy_financials,
      coherence.run_materializations,
      coherence.runs
    TO coherence_investor_ro;
    GRANT SELECT ON coherence_views.investor_bob TO coherence_investor_ro;
    GRANT EXECUTE ON FUNCTION
      coherence.rls_allowed_entities(),
      coherence.rls_actor_npn(),
      coherence.rls_access_tier(),
      coherence.attempt_is_published_run(uuid)
    TO coherence_investor_ro;
  END IF;
END;
$$;

-- 4. Enable and force fail-closed Row-Level Security on policy, financial, ledger, and statement line tables.
ALTER TABLE coherence.bob_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE coherence.bob_policies FORCE ROW LEVEL SECURITY;

ALTER TABLE coherence.bob_policy_financials ENABLE ROW LEVEL SECURITY;
ALTER TABLE coherence.bob_policy_financials FORCE ROW LEVEL SECURITY;

ALTER TABLE coherence.statement_agency_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE coherence.statement_agency_lines FORCE ROW LEVEL SECURITY;

ALTER TABLE coherence.statement_upline_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE coherence.statement_upline_lines FORCE ROW LEVEL SECURITY;

ALTER TABLE coherence.coherent_ledger_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE coherence.coherent_ledger_rows FORCE ROW LEVEL SECURITY;

-- Operational roles (app, worker, readonly) keep full access under FORCE RLS.
CREATE POLICY bob_policies_internal_rw ON coherence.bob_policies
  FOR ALL TO coherence_app, coherence_worker USING (true) WITH CHECK (true);
CREATE POLICY bob_policies_internal_ro ON coherence.bob_policies
  FOR SELECT TO coherence_readonly USING (true);

CREATE POLICY bob_policy_financials_internal_rw ON coherence.bob_policy_financials
  FOR ALL TO coherence_app, coherence_worker USING (true) WITH CHECK (true);
CREATE POLICY bob_policy_financials_internal_ro ON coherence.bob_policy_financials
  FOR SELECT TO coherence_readonly USING (true);

CREATE POLICY statement_agency_lines_internal_rw ON coherence.statement_agency_lines
  FOR ALL TO coherence_app, coherence_worker USING (true) WITH CHECK (true);
CREATE POLICY statement_agency_lines_internal_ro ON coherence.statement_agency_lines
  FOR SELECT TO coherence_readonly USING (true);

CREATE POLICY statement_upline_lines_internal_rw ON coherence.statement_upline_lines
  FOR ALL TO coherence_app, coherence_worker USING (true) WITH CHECK (true);
CREATE POLICY statement_upline_lines_internal_ro ON coherence.statement_upline_lines
  FOR SELECT TO coherence_readonly USING (true);

CREATE POLICY coherent_ledger_rows_internal_rw ON coherence.coherent_ledger_rows
  FOR ALL TO coherence_app, coherence_worker USING (true) WITH CHECK (true);
CREATE POLICY coherent_ledger_rows_internal_ro ON coherence.coherent_ledger_rows
  FOR SELECT TO coherence_readonly USING (true);

-- Fail-closed scoped policies for the five recipient read-only roles (zero rows when session settings are unset).
CREATE POLICY bob_policies_entity_manager ON coherence.bob_policies
  FOR SELECT TO coherence_entity_manager_ro
  USING (coherence.rls_access_tier() = 'entity_manager' AND coherence.attempt_is_published_run(attempt_event_id));

CREATE POLICY bob_policies_agency_manager ON coherence.bob_policies
  FOR SELECT TO coherence_agency_manager_ro
  USING (coherence.attempt_is_published_run(attempt_event_id) AND entity = ANY(coherence.rls_allowed_entities()));

CREATE POLICY bob_policies_agent ON coherence.bob_policies
  FOR SELECT TO coherence_agent_ro
  USING (
    coherence.attempt_is_published_run(attempt_event_id)
    AND writing_npn IS NOT NULL
    AND writing_npn = coherence.rls_actor_npn()
    AND entity = ANY(coherence.rls_allowed_entities())
  );

CREATE POLICY bob_policies_retention ON coherence.bob_policies
  FOR SELECT TO coherence_retention_ro
  USING (coherence.attempt_is_published_run(attempt_event_id) AND entity = ANY(coherence.rls_allowed_entities()));

CREATE POLICY bob_policies_investor ON coherence.bob_policies
  FOR SELECT TO coherence_investor_ro
  USING (coherence.rls_access_tier() = 'investor' AND coherence.attempt_is_published_run(attempt_event_id));

CREATE POLICY bob_policy_financials_entity_manager ON coherence.bob_policy_financials
  FOR SELECT TO coherence_entity_manager_ro
  USING (coherence.rls_access_tier() = 'entity_manager' AND coherence.attempt_is_published_run(attempt_event_id));

CREATE POLICY bob_policy_financials_agency_manager ON coherence.bob_policy_financials
  FOR SELECT TO coherence_agency_manager_ro
  USING (coherence.attempt_is_published_run(attempt_event_id) AND entity = ANY(coherence.rls_allowed_entities()));

CREATE POLICY bob_policy_financials_investor ON coherence.bob_policy_financials
  FOR SELECT TO coherence_investor_ro
  USING (coherence.rls_access_tier() = 'investor' AND coherence.attempt_is_published_run(attempt_event_id));

CREATE POLICY statement_agency_lines_entity_manager ON coherence.statement_agency_lines
  FOR SELECT TO coherence_entity_manager_ro
  USING (coherence.rls_access_tier() = 'entity_manager' AND coherence.batch_is_published_for_em(batch_id));

CREATE POLICY statement_agency_lines_agency_manager ON coherence.statement_agency_lines
  FOR SELECT TO coherence_agency_manager_ro
  USING (coherence.batch_is_official_sent(batch_id) AND entity = ANY(coherence.rls_allowed_entities()));

CREATE POLICY statement_agency_lines_agent ON coherence.statement_agency_lines
  FOR SELECT TO coherence_agent_ro
  USING (
    coherence.batch_is_official_sent(batch_id)
    AND writing_npn IS NOT NULL
    AND writing_npn = coherence.rls_actor_npn()
    AND entity = ANY(coherence.rls_allowed_entities())
  );

CREATE POLICY statement_agency_lines_retention ON coherence.statement_agency_lines
  FOR SELECT TO coherence_retention_ro
  USING (coherence.batch_is_official_sent(batch_id) AND entity = ANY(coherence.rls_allowed_entities()));

CREATE POLICY statement_upline_lines_entity_manager ON coherence.statement_upline_lines
  FOR SELECT TO coherence_entity_manager_ro
  USING (coherence.rls_access_tier() = 'entity_manager' AND coherence.batch_is_published_for_em(batch_id));

CREATE POLICY coherent_ledger_rows_entity_manager ON coherence.coherent_ledger_rows
  FOR SELECT TO coherence_entity_manager_ro
  USING (coherence.rls_access_tier() = 'entity_manager' AND coherence.attempt_is_published_run(attempt_event_id));
