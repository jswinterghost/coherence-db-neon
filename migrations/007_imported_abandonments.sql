-- Migration 007: allow recording abandonments for imported abandoned company runs
-- atomically inside their own import_historical_run journal entry while continuing
-- to forbid post-import abandonment of normal imported runs.
-- All functions pin SET search_path = pg_catalog and schema-qualify all references.

CREATE OR REPLACE FUNCTION coherence.trg_abandonments_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_run coherence.runs%ROWTYPE;
  v_cmd_kind text;
  v_expected_phrase text;
BEGIN
  SELECT * INTO v_run FROM coherence.runs WHERE id = NEW.run_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'run % does not exist', NEW.run_id;
  END IF;

  IF v_run.origin = 'mac_import' THEN
    RAISE EXCEPTION 'imported historical runs cannot be abandoned';
  ELSIF v_run.origin = 'company_import' THEN
    SELECT command_kind INTO v_cmd_kind
    FROM coherence.journal_entries
    WHERE seq = NEW.journal_seq;
    IF NEW.journal_seq <> v_run.journal_seq OR v_cmd_kind IS DISTINCT FROM 'import_historical_run' THEN
      RAISE EXCEPTION 'imported historical runs cannot be abandoned';
    END IF;
  END IF;

  v_expected_phrase := 'abandon ' || pg_catalog.to_char(v_run.statement_date, 'YYYY-MM-DD');
  IF NEW.typed_phrase <> v_expected_phrase THEN
    RAISE EXCEPTION 'abandon typed_phrase must be "%"', v_expected_phrase
      USING ERRCODE = '23514';
  END IF;
  IF coherence.run_has_open_attempt(NEW.run_id) THEN
    RAISE EXCEPTION 'cannot abandon run % while an attempt is open', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF EXISTS (SELECT 1 FROM coherence.review_submissions WHERE run_id = NEW.run_id AND status = 'pending') THEN
    RAISE EXCEPTION 'cannot abandon run % while a review submission is waiting', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF EXISTS (SELECT 1 FROM coherence.carries WHERE run_id = NEW.run_id) THEN
    RAISE EXCEPTION 'cannot abandon run % because it has carried outputs', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

DO $$
DECLARE
  v_role text;
BEGIN
  REVOKE ALL ON FUNCTION coherence.trg_abandonments_before() FROM PUBLIC;
  FOREACH v_role IN ARRAY ARRAY['coherence_readonly', 'coherence_app', 'coherence_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
      EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION coherence.trg_abandonments_before() TO %I', v_role);
    END IF;
  END LOOP;
END;
$$;
