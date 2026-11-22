-- Migration 003: Derived run stage views (R8), "as of" historical query functions (R16.3),
-- approvals derivation functions (R5.5), and least-privilege PostgreSQL roles (R14.4, R11 audits).

-- ============================================================================
-- A. Derived run stage (R8) — never stored, supports "as of" any journal_seq
-- ============================================================================

CREATE OR REPLACE FUNCTION coherence.run_stage(p_run_id uuid, p_as_of_seq bigint DEFAULT NULL)
RETURNS text
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_limit bigint := COALESCE(p_as_of_seq, 9223372036854775807::bigint);
  v_open_step text;
  v_req_step text;
  v_latest_end text;
  v_adjust_finished uuid;
  v_emit_finished uuid;
  v_bible_finished uuid;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM coherence.runs WHERE id = p_run_id AND journal_seq <= v_limit) THEN
    RETURN NULL;
  END IF;

  -- 1. Abandoned
  IF EXISTS (SELECT 1 FROM coherence.abandonments WHERE run_id = p_run_id AND journal_seq <= v_limit) THEN
    RETURN 'abandoned';
  END IF;

  -- 2. Open running attempt
  SELECT s.step INTO v_open_step
  FROM coherence.step_attempt_events s
  WHERE s.run_id = p_run_id
    AND s.event_kind = 'started'
    AND s.journal_seq <= v_limit
    AND NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events e
      WHERE e.run_id = s.run_id AND e.step = s.step AND e.attempt_no = s.attempt_no
        AND e.event_kind IN ('finished', 'failed', 'interrupted', 'cancelled')
        AND e.journal_seq <= v_limit
    )
  ORDER BY s.journal_seq DESC
  LIMIT 1;

  IF v_open_step IS NOT NULL THEN
    IF v_open_step = 'emit' THEN
      RETURN 'emitting';
    END IF;
    RETURN 'running a step';
  END IF;

  -- 3. Open unanswered step request
  SELECT sr.step INTO v_req_step
  FROM coherence.step_requests sr
  WHERE sr.run_id = p_run_id
    AND sr.journal_seq <= v_limit
    AND NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events s
      WHERE s.step_request_id = sr.id AND s.event_kind = 'started' AND s.journal_seq <= v_limit
    )
  ORDER BY sr.journal_seq DESC
  LIMIT 1;

  IF v_req_step IS NOT NULL THEN
    IF v_req_step = 'emit' THEN
      RETURN 'emitting';
    END IF;
    RETURN 'preparing';
  END IF;

  -- 4. Latest non-superseded ended attempt
  SELECT e.event_kind INTO v_latest_end
  FROM coherence.step_attempt_events e
  WHERE e.run_id = p_run_id
    AND e.event_kind IN ('finished', 'failed', 'interrupted', 'cancelled')
    AND e.journal_seq <= v_limit
    AND NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events sup
      WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no
        AND sup.event_kind = 'superseded' AND sup.journal_seq <= v_limit
    )
  ORDER BY coherence.step_rank(e.step) DESC, e.attempt_no DESC
  LIMIT 1;

  IF v_latest_end IN ('failed', 'interrupted', 'cancelled') THEN
    RETURN v_latest_end;
  END IF;

  -- 5. Done (emit finished)
  SELECT e.id INTO v_emit_finished
  FROM coherence.step_attempt_events e
  WHERE e.run_id = p_run_id AND e.step = 'emit' AND e.event_kind = 'finished' AND e.journal_seq <= v_limit
    AND NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events sup
      WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no
        AND sup.event_kind = 'superseded' AND sup.journal_seq <= v_limit
    )
  ORDER BY e.attempt_no DESC LIMIT 1;

  IF v_emit_finished IS NOT NULL THEN
    RETURN 'done';
  END IF;

  -- 6. Adjust finished -> ready to create statements vs waiting for Adjust
  SELECT e.id INTO v_adjust_finished
  FROM coherence.step_attempt_events e
  WHERE e.run_id = p_run_id AND e.step = 'adjust' AND e.event_kind = 'finished' AND e.journal_seq <= v_limit
    AND NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events sup
      WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no
        AND sup.event_kind = 'superseded' AND sup.journal_seq <= v_limit
    )
  ORDER BY e.attempt_no DESC LIMIT 1;

  IF v_adjust_finished IS NOT NULL THEN
    IF EXISTS (
      SELECT 1 FROM coherence.review_saves
      WHERE run_id = p_run_id AND surface = 'adjust' AND attempt_event_id = v_adjust_finished
        AND journal_seq <= v_limit
    ) THEN
      RETURN 'ready to create statements';
    END IF;
    RETURN 'waiting for Adjust';
  END IF;

  -- 7. Bible finished -> waiting for Bible
  SELECT e.id INTO v_bible_finished
  FROM coherence.step_attempt_events e
  WHERE e.run_id = p_run_id AND e.step = 'bible' AND e.event_kind = 'finished' AND e.journal_seq <= v_limit
    AND NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events sup
      WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no
        AND sup.event_kind = 'superseded' AND sup.journal_seq <= v_limit
    )
  ORDER BY e.attempt_no DESC LIMIT 1;

  IF v_bible_finished IS NOT NULL THEN
    RETURN 'waiting for Bible';
  END IF;

  RETURN 'preparing';
END;
$$;

-- Helper: latest journal_seq touching a given run (for R10.5 optimistic concurrency)
CREATE OR REPLACE FUNCTION coherence.run_latest_journal_seq(p_run_id uuid)
RETURNS bigint
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT GREATEST(
    COALESCE((SELECT journal_seq FROM coherence.runs WHERE id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.step_requests WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.cancel_requests WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.step_attempt_events WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.review_saves WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.emit_confirmations WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.carries WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.abandonments WHERE run_id = p_run_id), 0)
  );
$$;

CREATE OR REPLACE VIEW coherence.run_states AS
SELECT
  r.id,
  r.statement_date,
  r.folder_number,
  r.origin,
  r.input_version_id,
  r.prior_approvals_sha256,
  r.engine_version_id,
  r.emit_mode,
  r.emit_display,
  r.emit_keep,
  r.emit_no_manager,
  r.replays_run_id,
  r.compared_run_id,
  r.rerun_reason,
  r.source_folder,
  r.journal_seq AS created_journal_seq,
  coherence.run_latest_journal_seq(r.id) AS latest_journal_seq,
  coherence.run_stage(r.id, NULL) AS stage,
  EXISTS (SELECT 1 FROM coherence.carries c WHERE c.run_id = r.id AND c.carry_kind = 'sent') AS sent_recorded,
  EXISTS (SELECT 1 FROM coherence.carries c WHERE c.run_id = r.id AND c.carry_kind = 'approvals') AS approvals_carried,
  EXISTS (SELECT 1 FROM coherence.abandonments a WHERE a.run_id = r.id) AS abandoned
FROM coherence.runs r;

-- ============================================================================
-- B. Approvals derivation functions (R5.5): full log, current answers, Bible applied
-- ============================================================================

CREATE OR REPLACE FUNCTION coherence.approvals_full_rows(p_file_sha256 text)
RETURNS TABLE (
  row_no integer,
  record_id text,
  disposition text,
  agent text,
  agency text,
  policy text,
  book text,
  month text,
  status text,
  note text,
  committed_at text,
  approved_amount text,
  approved_agency text,
  approved_agent text,
  approved_agency_from text,
  approved_agent_from text
)
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  WITH RECURSIVE lineage(sha, depth) AS (
    SELECT p_file_sha256, 0
    UNION ALL
    SELECT af.extends_sha256, l.depth + 1
    FROM lineage l
    JOIN coherence.approvals_files af ON af.file_sha256 = l.sha
    WHERE af.extends_sha256 IS NOT NULL AND l.depth < 10000
  )
  SELECT
    ar.row_no, ar.record_id, ar.disposition, ar.agent, ar.agency, ar.policy, ar.book,
    ar.month, ar.status, ar.note, ar.committed_at,
    ar.approved_amount, ar.approved_agency, ar.approved_agent,
    ar.approved_agency_from, ar.approved_agent_from
  FROM lineage l
  JOIN coherence.approval_rows ar ON ar.approvals_file_sha256 = l.sha
  ORDER BY ar.row_no ASC;
$$;

-- Current answer per key: last row per record_id (R5.5)
CREATE OR REPLACE FUNCTION coherence.approvals_current(p_file_sha256 text)
RETURNS TABLE (
  row_no integer,
  record_id text,
  disposition text,
  agent text,
  agency text,
  policy text,
  book text,
  month text,
  status text,
  note text,
  committed_at text,
  approved_amount text,
  approved_agency text,
  approved_agent text,
  approved_agency_from text,
  approved_agent_from text
)
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT DISTINCT ON (r.record_id)
    r.row_no, r.record_id, r.disposition, r.agent, r.agency, r.policy, r.book,
    r.month, r.status, r.note, r.committed_at,
    r.approved_amount, r.approved_agency, r.approved_agent,
    r.approved_agency_from, r.approved_agent_from
  FROM coherence.approvals_full_rows(p_file_sha256) r
  ORDER BY r.record_id, r.row_no DESC;
$$;

-- Bible applied answers: last CORRECT row per Bible key (R5.5)
CREATE OR REPLACE FUNCTION coherence.approvals_bible_applied(p_file_sha256 text, p_bible_keys text[])
RETURNS TABLE (
  row_no integer,
  record_id text,
  disposition text,
  agent text,
  agency text,
  policy text,
  book text,
  month text,
  status text,
  note text,
  committed_at text,
  approved_amount text,
  approved_agency text,
  approved_agent text,
  approved_agency_from text,
  approved_agent_from text
)
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT DISTINCT ON (r.record_id)
    r.row_no, r.record_id, r.disposition, r.agent, r.agency, r.policy, r.book,
    r.month, r.status, r.note, r.committed_at,
    r.approved_amount, r.approved_agency, r.approved_agent,
    r.approved_agency_from, r.approved_agent_from
  FROM coherence.approvals_full_rows(p_file_sha256) r
  WHERE r.disposition = 'CORRECT'
    AND r.record_id = ANY(p_bible_keys)
  ORDER BY r.record_id, r.row_no DESC;
$$;

-- Standing input version as of any journal_seq (or current when NULL)
CREATE OR REPLACE FUNCTION coherence.standing_input_version_as_of(p_as_of_seq bigint DEFAULT NULL)
RETURNS uuid
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT id
  FROM coherence.input_versions
  WHERE line_kind = 'standing'
    AND journal_seq <= COALESCE(p_as_of_seq, 9223372036854775807::bigint)
  ORDER BY journal_seq DESC
  LIMIT 1;
$$;

-- ============================================================================
-- C. Least-privilege roles (R14.4, R11 audit: no table locks / no UPDATE/DELETE/TRUNCATE on business tables)
-- ============================================================================

DO $$
DECLARE
  v_role text;
  v_tbl text;
BEGIN
  FOREACH v_role IN ARRAY ARRAY['coherence_app', 'coherence_worker', 'coherence_readonly'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
      BEGIN
        EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN NOINHERIT', v_role);
      EXCEPTION WHEN insufficient_privilege THEN
        NULL;
      END;
    END IF;
  END LOOP;

  REVOKE ALL ON SCHEMA coherence FROM PUBLIC;
  REVOKE ALL ON ALL TABLES IN SCHEMA coherence FROM PUBLIC;
  REVOKE ALL ON ALL FUNCTIONS IN SCHEMA coherence FROM PUBLIC;

  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'coherence_readonly') THEN
    GRANT USAGE ON SCHEMA coherence TO coherence_readonly;
    GRANT SELECT ON ALL TABLES IN SCHEMA coherence TO coherence_readonly;
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA coherence TO coherence_readonly;
  END IF;

  -- coherence_app: SELECT + INSERT ONLY on business tables (NO UPDATE, DELETE, TRUNCATE -> cannot acquire SHARE/EXCLUSIVE/ACCESS EXCLUSIVE table locks!)
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'coherence_app') THEN
    GRANT USAGE ON SCHEMA coherence TO coherence_app;
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA coherence TO coherence_app;
    GRANT SELECT ON coherence.run_states TO coherence_app;
    FOREACH v_tbl IN ARRAY ARRAY[
      'journal_entries', 'company_meta', 'stored_files', 'engine_versions',
      'input_versions', 'input_entries', 'input_changes',
      'approvals_files', 'approval_rows',
      'runs', 'step_requests', 'cancel_requests', 'step_attempt_events', 'artifacts',
      'review_saves', 'emit_confirmations', 'carries', 'abandonments',
      'imported_files', 'checks'
    ] LOOP
      EXECUTE pg_catalog.format('GRANT SELECT, INSERT ON coherence.%I TO coherence_app', v_tbl);
    END LOOP;
    GRANT SELECT, INSERT ON coherence.review_submissions TO coherence_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON coherence.review_drafts TO coherence_app;
  END IF;

  -- coherence_worker: same least privilege on business tables + UPDATE on review_submissions to finalize them
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'coherence_worker') THEN
    GRANT USAGE ON SCHEMA coherence TO coherence_worker;
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA coherence TO coherence_worker;
    GRANT SELECT ON coherence.run_states TO coherence_worker;
    FOREACH v_tbl IN ARRAY ARRAY[
      'journal_entries', 'company_meta', 'stored_files', 'engine_versions',
      'input_versions', 'input_entries', 'input_changes',
      'approvals_files', 'approval_rows',
      'runs', 'step_requests', 'cancel_requests', 'step_attempt_events', 'artifacts',
      'review_saves', 'emit_confirmations', 'carries', 'abandonments',
      'imported_files', 'checks'
    ] LOOP
      EXECUTE pg_catalog.format('GRANT SELECT, INSERT ON coherence.%I TO coherence_worker', v_tbl);
    END LOOP;
    GRANT SELECT, INSERT, UPDATE ON coherence.review_submissions TO coherence_worker;
    GRANT SELECT, INSERT, UPDATE, DELETE ON coherence.review_drafts TO coherence_worker;
  END IF;
END;
$$;
