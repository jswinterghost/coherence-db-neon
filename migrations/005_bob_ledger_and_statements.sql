-- Migration 005: immutable Canonical Book of Business (split vertically into zero-dollar policy core
-- and 1:1 financials), Coherent Ledger, chronological statement batches and lines (agency and upline
-- physically separated), deferred conservation triggers, and full 30-table journal commitment hashing.
-- All functions pin SET search_path = pg_catalog and schema-qualify all references.

-- 1. Statement batches and physically separate agency and upline statement line tables.
CREATE TABLE coherence.statement_batches (
  id UUID PRIMARY KEY,
  batch_kind TEXT NOT NULL CHECK (batch_kind IN ('historical_sent', 'method_correction', 'run_emission')),
  statement_date DATE NOT NULL,
  run_id UUID REFERENCES coherence.runs(id),
  attempt_event_id UUID REFERENCES coherence.step_attempt_events(id),
  source_file_name TEXT,
  source_store_kind TEXT CHECK (source_store_kind IS NULL OR source_store_kind = 'company_data'),
  source_file_sha256 TEXT CHECK (source_file_sha256 IS NULL OR source_file_sha256 ~ '^[0-9a-f]{64}$'),
  reason TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(reason)) > 0),
  agency_line_count INTEGER NOT NULL CHECK (agency_line_count >= 0),
  agency_lines_sha256 TEXT NOT NULL CHECK (agency_lines_sha256 ~ '^[0-9a-f]{64}$'),
  agency_net_total NUMERIC(14,2) NOT NULL,
  upline_line_count INTEGER NOT NULL CHECK (upline_line_count >= 0),
  upline_lines_sha256 TEXT NOT NULL CHECK (upline_lines_sha256 ~ '^[0-9a-f]{64}$'),
  upline_net_total NUMERIC(14,2) NOT NULL,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  CHECK ((source_file_sha256 IS NULL AND source_store_kind IS NULL) OR (source_file_sha256 IS NOT NULL AND source_store_kind = 'company_data')),
  CHECK (
    (batch_kind = 'run_emission' AND run_id IS NOT NULL AND attempt_event_id IS NOT NULL)
    OR (batch_kind <> 'run_emission' AND run_id IS NULL AND attempt_event_id IS NULL)
  ),
  FOREIGN KEY (source_store_kind, source_file_sha256) REFERENCES coherence.stored_files(store_kind, sha256)
);

CREATE UNIQUE INDEX statement_batches_one_per_attempt
  ON coherence.statement_batches (attempt_event_id)
  WHERE attempt_event_id IS NOT NULL;

CREATE UNIQUE INDEX statement_batches_one_per_run
  ON coherence.statement_batches (run_id)
  WHERE run_id IS NOT NULL;

CREATE INDEX statement_batches_date_kind_idx ON coherence.statement_batches (statement_date, batch_kind);
CREATE INDEX statement_batches_source_sha_idx ON coherence.statement_batches (source_file_sha256) WHERE source_file_sha256 IS NOT NULL;
CREATE INDEX statement_batches_journal_seq_idx ON coherence.statement_batches (journal_seq);

CREATE TABLE coherence.statement_agency_lines (
  batch_id UUID NOT NULL REFERENCES coherence.statement_batches(id),
  line_no INTEGER NOT NULL CHECK (line_no >= 1),
  statement_date DATE NOT NULL,
  entry_kind TEXT NOT NULL CHECK (entry_kind IN ('historical_sent', 'method_correction', 'run_emission')),
  run_action TEXT NOT NULL CHECK (run_action IN ('SENT', 'CORRECTION', 'NEW', 'RESTATED', 'REVERSAL', 'CANCEL')),
  entity TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(entity)) > 0),
  writing_npn TEXT,
  writing_agent TEXT,
  record_id TEXT NOT NULL CHECK (pg_catalog.length(record_id) > 0),
  reversal_of TEXT,
  corrects_record_id TEXT,
  source_file TEXT NOT NULL CHECK (pg_catalog.length(source_file) > 0),
  sheet_name TEXT,
  source_row_no INTEGER NOT NULL CHECK (source_row_no >= 1),
  src_type TEXT,
  carrier TEXT,
  mbi TEXT,
  member TEXT,
  external_policy_id TEXT,
  policy_id INTEGER,
  tx_id INTEGER,
  plan_type TEXT,
  simple_plan_type TEXT,
  state TEXT,
  submission_date DATE,
  origin_effective DATE,
  effective_date DATE,
  termination_date DATE,
  earned_date DATE,
  payment_date DATE,
  posted_statement_date DATE,
  revenue_type TEXT,
  gross_comm NUMERIC(14,2) NOT NULL,
  amount NUMERIC(14,2) NOT NULL,
  reason TEXT,
  notes TEXT,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  PRIMARY KEY (batch_id, line_no)
);

CREATE INDEX statement_agency_lines_date_entity_idx ON coherence.statement_agency_lines (statement_date, entity);
CREATE INDEX statement_agency_lines_entity_npn_idx ON coherence.statement_agency_lines (entity, writing_npn, statement_date);
CREATE INDEX statement_agency_lines_record_id_idx ON coherence.statement_agency_lines (record_id);
CREATE INDEX statement_agency_lines_reversal_of_idx ON coherence.statement_agency_lines (reversal_of) WHERE reversal_of IS NOT NULL;
CREATE INDEX statement_agency_lines_journal_seq_idx ON coherence.statement_agency_lines (journal_seq);

-- Physically separate upline table; zero privileges granted to downline agency, agent, retention, or investor roles.
CREATE TABLE coherence.statement_upline_lines (
  batch_id UUID NOT NULL REFERENCES coherence.statement_batches(id),
  line_no INTEGER NOT NULL CHECK (line_no >= 1),
  statement_date DATE NOT NULL,
  entry_kind TEXT NOT NULL CHECK (entry_kind IN ('historical_upline_derived', 'method_correction', 'run_emission')),
  run_action TEXT NOT NULL CHECK (run_action IN ('SENT', 'CORRECTION', 'NEW', 'RESTATED', 'REVERSAL', 'CANCEL')),
  source_entity TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(source_entity)) > 0),
  marked_sent BOOLEAN NOT NULL DEFAULT true,
  writing_npn TEXT,
  writing_agent TEXT,
  record_id TEXT NOT NULL CHECK (pg_catalog.length(record_id) > 0),
  reversal_of TEXT,
  corrects_record_id TEXT,
  source_file TEXT NOT NULL CHECK (pg_catalog.length(source_file) > 0),
  sheet_name TEXT,
  source_row_no INTEGER NOT NULL CHECK (source_row_no >= 1),
  src_type TEXT,
  carrier TEXT,
  mbi TEXT,
  member TEXT,
  external_policy_id TEXT,
  policy_id INTEGER,
  tx_id INTEGER,
  plan_type TEXT,
  simple_plan_type TEXT,
  state TEXT,
  submission_date DATE,
  origin_effective DATE,
  effective_date DATE,
  termination_date DATE,
  earned_date DATE,
  payment_date DATE,
  posted_statement_date DATE,
  revenue_type TEXT,
  gross_comm NUMERIC(14,2) NOT NULL,
  amount NUMERIC(14,2) NOT NULL,
  reason TEXT,
  notes TEXT,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  PRIMARY KEY (batch_id, line_no)
);

CREATE INDEX statement_upline_lines_date_source_idx ON coherence.statement_upline_lines (statement_date, source_entity);
CREATE INDEX statement_upline_lines_record_id_idx ON coherence.statement_upline_lines (record_id);
CREATE INDEX statement_upline_lines_reversal_of_idx ON coherence.statement_upline_lines (reversal_of) WHERE reversal_of IS NOT NULL;
CREATE INDEX statement_upline_lines_journal_seq_idx ON coherence.statement_upline_lines (journal_seq);

-- 2. Run materialization header (one per materialized run; prevents a second load of the same run).
CREATE TABLE coherence.run_materializations (
  attempt_event_id UUID PRIMARY KEY REFERENCES coherence.step_attempt_events(id),
  run_id UUID NOT NULL UNIQUE REFERENCES coherence.runs(id),
  statement_date DATE NOT NULL,
  reconciliation_mode TEXT NOT NULL DEFAULT 'strict_entity_ledger'
    CHECK (reconciliation_mode IN ('strict_entity_ledger', 'legacy_pre_split_archive')),
  bob_row_count INTEGER NOT NULL CHECK (bob_row_count >= 0),
  bob_rows_sha256 TEXT NOT NULL CHECK (bob_rows_sha256 ~ '^[0-9a-f]{64}$'),
  bob_downline_total NUMERIC(14,2) NOT NULL,
  bob_upline_total NUMERIC(14,2) NOT NULL,
  ledger_row_count INTEGER NOT NULL CHECK (ledger_row_count >= 0),
  ledger_rows_sha256 TEXT NOT NULL CHECK (ledger_rows_sha256 ~ '^[0-9a-f]{64}$'),
  ledger_gross_total NUMERIC(14,2) NOT NULL,
  ledger_downline_total NUMERIC(14,2) NOT NULL,
  ledger_upline_total NUMERIC(14,2) NOT NULL,
  statement_batch_id UUID NOT NULL UNIQUE REFERENCES coherence.statement_batches(id),
  corpus_tail TEXT,
  agency_start DATE,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  CHECK (ledger_downline_total + ledger_upline_total = ledger_gross_total)
);

CREATE INDEX run_materializations_date_idx ON coherence.run_materializations (statement_date DESC, journal_seq DESC);
CREATE INDEX run_materializations_journal_seq_idx ON coherence.run_materializations (journal_seq);

-- 3. Canonical Book of Business: zero-dollar policy core (bob_policies) + 1:1 financials (bob_policy_financials).
CREATE TABLE coherence.bob_policies (
  attempt_event_id UUID NOT NULL REFERENCES coherence.run_materializations(attempt_event_id),
  policy_id INTEGER NOT NULL,
  run_id UUID NOT NULL REFERENCES coherence.runs(id),
  external_policy_id TEXT,
  carrier_policy_number TEXT,
  crm_policy_number TEXT,
  carrier TEXT,
  plan_type TEXT,
  plan_name TEXT,
  simple_plan_type TEXT,
  mbi TEXT,
  member TEXT,
  dob TEXT,
  phone TEXT,
  email TEXT,
  address TEXT,
  county TEXT,
  state TEXT,
  submission_date DATE,
  origin_effective DATE,
  effective_date DATE,
  termination_date DATE,
  writing_npn TEXT,
  writing_agent TEXT,
  entity TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(entity)) > 0),
  status TEXT,
  coherent_status TEXT,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  PRIMARY KEY (attempt_event_id, policy_id)
);

CREATE INDEX bob_policies_attempt_entity_idx ON coherence.bob_policies (attempt_event_id, entity);
CREATE INDEX bob_policies_attempt_npn_idx ON coherence.bob_policies (attempt_event_id, writing_npn);
CREATE INDEX bob_policies_attempt_ext_idx ON coherence.bob_policies (attempt_event_id, external_policy_id);
CREATE INDEX bob_policies_journal_seq_idx ON coherence.bob_policies (journal_seq);

CREATE TABLE coherence.bob_policy_financials (
  attempt_event_id UUID NOT NULL,
  policy_id INTEGER NOT NULL,
  entity TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(entity)) > 0),
  writing_npn TEXT,
  amount NUMERIC(14,2),
  upline_amount NUMERIC(14,2),
  enrollment_code TEXT,
  min_date DATE,
  anchor_date DATE,
  agency_id TEXT,
  conflicts TEXT,
  spine_source TEXT,
  confidence_level SMALLINT,
  coherent_trajectory JSONB,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  PRIMARY KEY (attempt_event_id, policy_id),
  FOREIGN KEY (attempt_event_id, policy_id) REFERENCES coherence.bob_policies(attempt_event_id, policy_id)
);

CREATE INDEX bob_policy_financials_attempt_entity_idx ON coherence.bob_policy_financials (attempt_event_id, entity);
CREATE INDEX bob_policy_financials_attempt_npn_idx ON coherence.bob_policy_financials (attempt_event_id, writing_npn);
CREATE INDEX bob_policy_financials_journal_seq_idx ON coherence.bob_policy_financials (journal_seq);

-- 4. Coherent Ledger rows (Entity Manager and Nusear internal only).
CREATE TABLE coherence.coherent_ledger_rows (
  attempt_event_id UUID NOT NULL REFERENCES coherence.run_materializations(attempt_event_id),
  tx_id INTEGER NOT NULL,
  run_id UUID NOT NULL REFERENCES coherence.runs(id),
  record_id TEXT NOT NULL CHECK (pg_catalog.length(record_id) > 0),
  external_policy_id TEXT,
  policy_id INTEGER,
  statement_name TEXT,
  src_type TEXT NOT NULL CHECK (pg_catalog.length(src_type) > 0),
  carrier TEXT,
  mbi TEXT,
  member TEXT,
  state TEXT,
  plan_type TEXT,
  simple_plan_type TEXT,
  submission_date DATE,
  origin_effective DATE,
  effective_date DATE,
  termination_date DATE,
  earned_date DATE,
  payment_date DATE,
  statement_date DATE,
  min_date DATE,
  gross_comm NUMERIC(14,2) NOT NULL,
  revenue_type TEXT,
  override_amount NUMERIC(14,2),
  commission_amount NUMERIC(14,2),
  hra_amount NUMERIC(14,2),
  fee_amount NUMERIC(14,2),
  other_amount NUMERIC(14,2),
  downline_amount NUMERIC(14,2) NOT NULL,
  upline_amount NUMERIC(14,2) NOT NULL,
  writing_npn TEXT,
  writing_agent TEXT,
  entity TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(entity)) > 0),
  payee_npn TEXT,
  agency_id TEXT,
  status TEXT,
  policy_status TEXT,
  cbob_c BOOLEAN NOT NULL,
  cbob_s BOOLEAN NOT NULL,
  sf BOOLEAN NOT NULL,
  notes TEXT,
  coherent_notes TEXT,
  sheet_name TEXT,
  source_row_no INTEGER,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  PRIMARY KEY (attempt_event_id, tx_id),
  CHECK (downline_amount + upline_amount = gross_comm),
  CHECK (
    ((override_amount IS NOT NULL)::int
     + (commission_amount IS NOT NULL)::int
     + (hra_amount IS NOT NULL)::int
     + (fee_amount IS NOT NULL)::int
     + (other_amount IS NOT NULL)::int) = 1
    AND COALESCE(override_amount, commission_amount, hra_amount, fee_amount, other_amount) = gross_comm
  )
);

CREATE INDEX coherent_ledger_rows_attempt_entity_idx ON coherence.coherent_ledger_rows (attempt_event_id, entity);
CREATE INDEX coherent_ledger_rows_attempt_record_idx ON coherence.coherent_ledger_rows (attempt_event_id, record_id);
CREATE INDEX coherent_ledger_rows_attempt_policy_idx ON coherence.coherent_ledger_rows (attempt_event_id, policy_id)
  WHERE policy_id IS NOT NULL;
CREATE INDEX coherent_ledger_rows_journal_seq_idx ON coherence.coherent_ledger_rows (journal_seq);

-- 5. Attach ENABLE ALWAYS immutability and active-journal triggers to all seven new business tables.
DO $$
DECLARE
  v_tbl text;
BEGIN
  FOREACH v_tbl IN ARRAY ARRAY[
    'statement_batches', 'statement_agency_lines', 'statement_upline_lines',
    'run_materializations', 'bob_policies', 'bob_policy_financials', 'coherent_ledger_rows'
  ] LOOP
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER trg_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON coherence.%I FOR EACH STATEMENT EXECUTE FUNCTION coherence.forbid_mutation()',
      v_tbl
    );
    EXECUTE pg_catalog.format(
      'ALTER TABLE coherence.%I ENABLE ALWAYS TRIGGER trg_immutable',
      v_tbl
    );
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER trg_01_require_active_journal BEFORE INSERT ON coherence.%I FOR EACH ROW EXECUTE FUNCTION coherence.trg_require_active_journal()',
      v_tbl
    );
  END LOOP;
END;
$$;

-- 6. Canonical hashing helpers for statement lines, BoB rows, and ledger rows.
CREATE OR REPLACE FUNCTION coherence.fmt_num2(val numeric)
RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT CASE WHEN val IS NULL THEN NULL ELSE (val::numeric(14,2))::text END;
$$;

CREATE OR REPLACE FUNCTION coherence.fmt_date(val date)
RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT CASE WHEN val IS NULL THEN NULL ELSE pg_catalog.to_char(val, 'YYYY-MM-DD') END;
$$;

CREATE OR REPLACE FUNCTION coherence.hash_statement_agency_lines(p_batch_id uuid)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT coherence.sha256_text(
    COALESCE(
      (SELECT pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          line_no, coherence.fmt_date(statement_date), entry_kind, run_action,
          entity, writing_npn, writing_agent, record_id, reversal_of, corrects_record_id,
          source_file, sheet_name, source_row_no, src_type, carrier, mbi, member,
          external_policy_id, policy_id, tx_id, plan_type, simple_plan_type, state,
          coherence.fmt_date(submission_date), coherence.fmt_date(origin_effective),
          coherence.fmt_date(effective_date), coherence.fmt_date(termination_date),
          coherence.fmt_date(earned_date), coherence.fmt_date(payment_date),
          coherence.fmt_date(posted_statement_date), revenue_type,
          coherence.fmt_num2(gross_comm), coherence.fmt_num2(amount), reason, notes
        )) || E'\n',
        '' ORDER BY line_no ASC
      )
      FROM coherence.statement_agency_lines
      WHERE batch_id = p_batch_id),
      ''
    )
  );
$$;

CREATE OR REPLACE FUNCTION coherence.hash_statement_upline_lines(p_batch_id uuid)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT coherence.sha256_text(
    COALESCE(
      (SELECT pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          line_no, coherence.fmt_date(statement_date), entry_kind, run_action,
          source_entity, marked_sent, writing_npn, writing_agent, record_id, reversal_of,
          corrects_record_id, source_file, sheet_name, source_row_no, src_type, carrier,
          mbi, member, external_policy_id, policy_id, tx_id, plan_type, simple_plan_type, state,
          coherence.fmt_date(submission_date), coherence.fmt_date(origin_effective),
          coherence.fmt_date(effective_date), coherence.fmt_date(termination_date),
          coherence.fmt_date(earned_date), coherence.fmt_date(payment_date),
          coherence.fmt_date(posted_statement_date), revenue_type,
          coherence.fmt_num2(gross_comm), coherence.fmt_num2(amount), reason, notes
        )) || E'\n',
        '' ORDER BY line_no ASC
      )
      FROM coherence.statement_upline_lines
      WHERE batch_id = p_batch_id),
      ''
    )
  );
$$;

CREATE OR REPLACE FUNCTION coherence.hash_bob_rows(p_attempt_event_id uuid)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT coherence.sha256_text(
    COALESCE(
      (SELECT pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          bp.policy_id, bp.external_policy_id, bp.carrier_policy_number, bp.crm_policy_number,
          bp.carrier, bp.plan_type, bp.plan_name, bp.simple_plan_type,
          bp.mbi, bp.member, bp.dob, bp.phone, bp.email, bp.address, bp.county, bp.state,
          coherence.fmt_date(bp.submission_date), coherence.fmt_date(bp.origin_effective),
          coherence.fmt_date(bp.effective_date), coherence.fmt_date(bp.termination_date),
          bp.writing_npn, bp.writing_agent, bp.entity, bp.status, bp.coherent_status,
          coherence.fmt_num2(bpf.amount), coherence.fmt_num2(bpf.upline_amount),
          bpf.enrollment_code, coherence.fmt_date(bpf.min_date), coherence.fmt_date(bpf.anchor_date),
          bpf.agency_id, bpf.conflicts, bpf.spine_source, bpf.confidence_level, bpf.coherent_trajectory
        )) || E'\n',
        '' ORDER BY bp.policy_id ASC
      )
      FROM coherence.bob_policies bp
      JOIN coherence.bob_policy_financials bpf
        ON bpf.attempt_event_id = bp.attempt_event_id AND bpf.policy_id = bp.policy_id
      WHERE bp.attempt_event_id = p_attempt_event_id),
      ''
    )
  );
$$;

CREATE OR REPLACE FUNCTION coherence.hash_ledger_rows(p_attempt_event_id uuid)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT coherence.sha256_text(
    COALESCE(
      (SELECT pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          tx_id, record_id, external_policy_id, policy_id, statement_name, src_type,
          carrier, mbi, member, state, plan_type, simple_plan_type,
          coherence.fmt_date(submission_date), coherence.fmt_date(origin_effective),
          coherence.fmt_date(effective_date), coherence.fmt_date(termination_date),
          coherence.fmt_date(earned_date), coherence.fmt_date(payment_date),
          coherence.fmt_date(statement_date), coherence.fmt_date(min_date),
          coherence.fmt_num2(gross_comm), revenue_type,
          coherence.fmt_num2(override_amount), coherence.fmt_num2(commission_amount),
          coherence.fmt_num2(hra_amount), coherence.fmt_num2(fee_amount), coherence.fmt_num2(other_amount),
          coherence.fmt_num2(downline_amount), coherence.fmt_num2(upline_amount),
          writing_npn, writing_agent, entity, payee_npn, agency_id,
          status, policy_status, cbob_c, cbob_s, sf, notes, coherent_notes,
          sheet_name, source_row_no
        )) || E'\n',
        '' ORDER BY tx_id ASC
      )
      FROM coherence.coherent_ledger_rows
      WHERE attempt_event_id = p_attempt_event_id),
      ''
    )
  );
$$;

-- Effective statement batches for a run: prior official batches referenced by the run's frozen input_version
-- (plus applicable prior method corrections), plus the run's own run_emission batch.
CREATE OR REPLACE FUNCTION coherence.run_effective_statement_batches(p_run_id uuid)
RETURNS TABLE (batch_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH run_info AS (
    SELECT r.id, r.input_version_id, r.statement_date
    FROM coherence.runs r
    WHERE r.id = p_run_id
  ),
  matched_historical AS (
    SELECT sb.id AS batch_id
    FROM coherence.statement_batches sb
    CROSS JOIN run_info ri
    WHERE sb.batch_kind = 'historical_sent'
      AND sb.statement_date <= ri.statement_date
      AND (
        (sb.source_file_sha256 IS NOT NULL AND EXISTS (
          SELECT 1 FROM coherence.input_entries ie
          WHERE ie.input_version_id = ri.input_version_id
            AND ie.file_sha256 = sb.source_file_sha256
        ))
        OR (sb.source_file_sha256 IS NULL AND sb.source_file_name IS NOT NULL AND EXISTS (
          SELECT 1 FROM coherence.input_entries ie
          WHERE ie.input_version_id = ri.input_version_id
            AND pg_catalog.lower(pg_catalog.split_part(ie.rel_path, '/', pg_catalog.array_length(pg_catalog.string_to_array(ie.rel_path, '/'), 1)))
                = pg_catalog.lower(sb.source_file_name)
        ))
      )
  ),
  matched_prior_runs AS (
    SELECT sb.id AS batch_id
    FROM coherence.statement_batches sb
    CROSS JOIN run_info ri
    WHERE sb.batch_kind = 'run_emission'
      AND sb.run_id <> ri.id
      AND sb.statement_date < ri.statement_date
      AND EXISTS (
        SELECT 1 FROM coherence.carries c
        WHERE c.run_id = sb.run_id AND c.carry_kind = 'sent'
      )
      AND NOT EXISTS (
        SELECT 1 FROM coherence.abandonments a
        WHERE a.run_id = sb.run_id
      )
      AND (
        (sb.source_file_sha256 IS NOT NULL AND EXISTS (
          SELECT 1 FROM coherence.input_entries ie
          WHERE ie.input_version_id = ri.input_version_id
            AND ie.file_sha256 = sb.source_file_sha256
        ))
        OR EXISTS (
          SELECT 1 FROM coherence.input_entries ie
          WHERE ie.input_version_id = ri.input_version_id
            AND ie.mac_key = 'sent/statements_' || pg_catalog.to_char(sb.statement_date, 'YYYYMMDD') || '.csv'
        )
      )
  ),
  matched_corrections AS (
    SELECT sb.id AS batch_id
    FROM coherence.statement_batches sb
    CROSS JOIN run_info ri
    WHERE sb.batch_kind = 'method_correction'
      AND sb.statement_date <= ri.statement_date
      AND EXISTS (SELECT 1 FROM matched_historical)
  ),
  own_batch AS (
    SELECT sb.id AS batch_id
    FROM coherence.statement_batches sb
    WHERE sb.batch_kind = 'run_emission'
      AND sb.run_id = p_run_id
  )
  SELECT batch_id FROM matched_historical
  UNION
  SELECT batch_id FROM matched_prior_runs
  UNION
  SELECT batch_id FROM matched_corrections
  UNION
  SELECT batch_id FROM own_batch;
$$;

-- 7. Row triggers and deferred conservation triggers on statement batches and run materializations.
CREATE OR REPLACE FUNCTION coherence.trg_statement_batches_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_run coherence.runs%ROWTYPE;
  v_ev coherence.step_attempt_events%ROWTYPE;
BEGIN
  IF NEW.batch_kind = 'run_emission' THEN
    SELECT * INTO v_run FROM coherence.runs WHERE id = NEW.run_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'statement_batch run % does not exist', NEW.run_id
        USING ERRCODE = '23514';
    END IF;
    IF NEW.statement_date <> v_run.statement_date THEN
      RAISE EXCEPTION 'statement_batch statement_date (%) must match run statement_date (%)',
        NEW.statement_date, v_run.statement_date
        USING ERRCODE = '23514';
    END IF;
    SELECT * INTO v_ev FROM coherence.step_attempt_events WHERE id = NEW.attempt_event_id;
    IF NOT FOUND OR v_ev.run_id <> NEW.run_id OR v_ev.step <> 'emit' OR v_ev.event_kind <> 'finished' THEN
      RAISE EXCEPTION 'run_emission statement_batch must reference a finished emit attempt of run %', NEW.run_id
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_statement_batches_before
  BEFORE INSERT ON coherence.statement_batches
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_statement_batches_before();

CREATE OR REPLACE FUNCTION coherence.trg_statement_lines_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_batch coherence.statement_batches%ROWTYPE;
BEGIN
  SELECT * INTO v_batch FROM coherence.statement_batches WHERE id = NEW.batch_id;
  IF NOT FOUND OR v_batch.journal_seq <> NEW.journal_seq THEN
    RAISE EXCEPTION 'statement lines must be inserted in the same journal entry as their statement_batch'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.statement_date <> v_batch.statement_date THEN
    RAISE EXCEPTION 'statement line statement_date (%) must match batch statement_date (%)',
      NEW.statement_date, v_batch.statement_date
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_statement_agency_lines_before
  BEFORE INSERT ON coherence.statement_agency_lines
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_statement_lines_before();

CREATE TRIGGER trg_02_statement_upline_lines_before
  BEFORE INSERT ON coherence.statement_upline_lines
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_statement_lines_before();

CREATE OR REPLACE FUNCTION coherence.trg_statement_batches_verify_deferred()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_ag_cnt integer;
  v_ag_min integer;
  v_ag_max integer;
  v_ag_sum numeric(14,2);
  v_ag_hash text;
  v_up_cnt integer;
  v_up_min integer;
  v_up_max integer;
  v_up_sum numeric(14,2);
  v_up_hash text;
BEGIN
  SELECT pg_catalog.count(*)::integer, pg_catalog.min(line_no), pg_catalog.max(line_no), COALESCE(pg_catalog.sum(amount), 0.00)
  INTO v_ag_cnt, v_ag_min, v_ag_max, v_ag_sum
  FROM coherence.statement_agency_lines
  WHERE batch_id = NEW.id;

  IF v_ag_cnt <> NEW.agency_line_count THEN
    RAISE EXCEPTION 'statement_batch % agency_line_count mismatch: declared %, actual %',
      NEW.id, NEW.agency_line_count, v_ag_cnt
      USING ERRCODE = '23514';
  END IF;
  IF v_ag_cnt > 0 AND (v_ag_min <> 1 OR v_ag_max <> v_ag_cnt) THEN
    RAISE EXCEPTION 'statement_batch % agency line numbers are not contiguous 1..%', NEW.id, v_ag_cnt
      USING ERRCODE = '23514';
  END IF;
  IF v_ag_sum <> NEW.agency_net_total THEN
    RAISE EXCEPTION 'statement_batch % agency_net_total mismatch: declared %, actual %',
      NEW.id, NEW.agency_net_total, v_ag_sum
      USING ERRCODE = '23514';
  END IF;
  v_ag_hash := coherence.hash_statement_agency_lines(NEW.id);
  IF v_ag_hash <> NEW.agency_lines_sha256 THEN
    RAISE EXCEPTION 'statement_batch % agency_lines_sha256 mismatch', NEW.id
      USING ERRCODE = '23514';
  END IF;

  SELECT pg_catalog.count(*)::integer, pg_catalog.min(line_no), pg_catalog.max(line_no), COALESCE(pg_catalog.sum(amount), 0.00)
  INTO v_up_cnt, v_up_min, v_up_max, v_up_sum
  FROM coherence.statement_upline_lines
  WHERE batch_id = NEW.id;

  IF v_up_cnt <> NEW.upline_line_count THEN
    RAISE EXCEPTION 'statement_batch % upline_line_count mismatch: declared %, actual %',
      NEW.id, NEW.upline_line_count, v_up_cnt
      USING ERRCODE = '23514';
  END IF;
  IF v_up_cnt > 0 AND (v_up_min <> 1 OR v_up_max <> v_up_cnt) THEN
    RAISE EXCEPTION 'statement_batch % upline line numbers are not contiguous 1..%', NEW.id, v_up_cnt
      USING ERRCODE = '23514';
  END IF;
  IF v_up_sum <> NEW.upline_net_total THEN
    RAISE EXCEPTION 'statement_batch % upline_net_total mismatch: declared %, actual %',
      NEW.id, NEW.upline_net_total, v_up_sum
      USING ERRCODE = '23514';
  END IF;
  v_up_hash := coherence.hash_statement_upline_lines(NEW.id);
  IF v_up_hash <> NEW.upline_lines_sha256 THEN
    RAISE EXCEPTION 'statement_batch % upline_lines_sha256 mismatch', NEW.id
      USING ERRCODE = '23514';
  END IF;

  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_statement_batches_verify_deferred
  AFTER INSERT ON coherence.statement_batches
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_statement_batches_verify_deferred();

CREATE OR REPLACE FUNCTION coherence.trg_run_materializations_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_run coherence.runs%ROWTYPE;
  v_ev coherence.step_attempt_events%ROWTYPE;
  v_batch coherence.statement_batches%ROWTYPE;
BEGIN
  SELECT * INTO v_run FROM coherence.runs WHERE id = NEW.run_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'run_materialization run % does not exist', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF NEW.statement_date <> v_run.statement_date THEN
    RAISE EXCEPTION 'run_materialization statement_date (%) must match run statement_date (%)',
      NEW.statement_date, v_run.statement_date
      USING ERRCODE = '23514';
  END IF;
  IF NEW.reconciliation_mode = 'legacy_pre_split_archive' THEN
    IF v_run.origin NOT IN ('mac_import', 'company_import') OR v_run.statement_date >= DATE '2026-08-31' THEN
      RAISE EXCEPTION 'legacy_pre_split_archive mode is forbidden for non-import or post-2026-08-31 runs'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  SELECT * INTO v_ev FROM coherence.step_attempt_events WHERE id = NEW.attempt_event_id;
  IF NOT FOUND OR v_ev.run_id <> NEW.run_id OR v_ev.step <> 'emit' OR v_ev.event_kind <> 'finished' THEN
    RAISE EXCEPTION 'run_materialization must reference a finished emit attempt of run %', NEW.run_id
      USING ERRCODE = '23514';
  END IF;

  SELECT * INTO v_batch FROM coherence.statement_batches WHERE id = NEW.statement_batch_id;
  IF NOT FOUND OR v_batch.run_id IS DISTINCT FROM NEW.run_id
     OR v_batch.attempt_event_id IS DISTINCT FROM NEW.attempt_event_id
     OR v_batch.journal_seq <> NEW.journal_seq THEN
    RAISE EXCEPTION 'run_materialization statement_batch_id must match the run_emission batch in the same journal entry'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_run_materializations_before
  BEFORE INSERT ON coherence.run_materializations
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_run_materializations_before();

CREATE OR REPLACE FUNCTION coherence.trg_bob_policies_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_rm coherence.run_materializations%ROWTYPE;
BEGIN
  SELECT * INTO v_rm FROM coherence.run_materializations WHERE attempt_event_id = NEW.attempt_event_id;
  IF NOT FOUND OR v_rm.journal_seq <> NEW.journal_seq OR v_rm.run_id <> NEW.run_id THEN
    RAISE EXCEPTION 'bob_policies rows must be inserted in the same journal entry as their run_materialization'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_bob_policies_before
  BEFORE INSERT ON coherence.bob_policies
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_bob_policies_before();

CREATE OR REPLACE FUNCTION coherence.trg_bob_policy_financials_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_bp coherence.bob_policies%ROWTYPE;
BEGIN
  SELECT * INTO v_bp FROM coherence.bob_policies
  WHERE attempt_event_id = NEW.attempt_event_id AND policy_id = NEW.policy_id;
  IF NOT FOUND OR v_bp.journal_seq <> NEW.journal_seq THEN
    RAISE EXCEPTION 'bob_policy_financials must be inserted in the same journal entry as its bob_policies row'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.entity <> v_bp.entity OR NEW.writing_npn IS DISTINCT FROM v_bp.writing_npn THEN
    RAISE EXCEPTION 'bob_policy_financials entity and writing_npn must match bob_policies exactly'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_bob_policy_financials_before
  BEFORE INSERT ON coherence.bob_policy_financials
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_bob_policy_financials_before();

CREATE OR REPLACE FUNCTION coherence.trg_coherent_ledger_rows_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_rm coherence.run_materializations%ROWTYPE;
BEGIN
  SELECT * INTO v_rm FROM coherence.run_materializations WHERE attempt_event_id = NEW.attempt_event_id;
  IF NOT FOUND OR v_rm.journal_seq <> NEW.journal_seq OR v_rm.run_id <> NEW.run_id THEN
    RAISE EXCEPTION 'coherent_ledger_rows must be inserted in the same journal entry as their run_materialization'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_coherent_ledger_rows_before
  BEFORE INSERT ON coherence.coherent_ledger_rows
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_coherent_ledger_rows_before();

-- Deferred conservation gate at COMMIT: verifies BoB counts/hashes/totals, Ledger counts/hashes/totals,
-- BoB-to-Ledger policy rollup tie-out, and Entity-Statement-to-Ledger cumulative tie-out per entity and record.
CREATE OR REPLACE FUNCTION coherence.trg_run_materializations_verify_deferred()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_bp_cnt integer;
  v_bpf_cnt integer;
  v_bob_downline numeric(14,2);
  v_bob_upline numeric(14,2);
  v_bob_hash text;
  v_led_cnt integer;
  v_led_gross numeric(14,2);
  v_led_downline numeric(14,2);
  v_led_upline numeric(14,2);
  v_led_hash text;
  v_pol_led_downline numeric(14,2);
  v_pol_led_upline numeric(14,2);
  v_entity_mismatch_cnt bigint;
  v_upline_stmt_total numeric(14,2);
  v_record_mismatch_cnt bigint;
BEGIN
  SELECT pg_catalog.count(*)::integer INTO v_bp_cnt
  FROM coherence.bob_policies WHERE attempt_event_id = NEW.attempt_event_id;

  SELECT pg_catalog.count(*)::integer,
         COALESCE(pg_catalog.sum(amount), 0.00),
         COALESCE(pg_catalog.sum(upline_amount), 0.00)
  INTO v_bpf_cnt, v_bob_downline, v_bob_upline
  FROM coherence.bob_policy_financials WHERE attempt_event_id = NEW.attempt_event_id;

  IF v_bp_cnt <> NEW.bob_row_count OR v_bpf_cnt <> NEW.bob_row_count THEN
    RAISE EXCEPTION 'run_materialization BoB row count mismatch: declared %, policies %, financials %',
      NEW.bob_row_count, v_bp_cnt, v_bpf_cnt
      USING ERRCODE = '23514';
  END IF;
  IF v_bob_downline <> NEW.bob_downline_total OR v_bob_upline <> NEW.bob_upline_total THEN
    RAISE EXCEPTION 'run_materialization BoB totals mismatch: declared (% / %), actual (% / %)',
      NEW.bob_downline_total, NEW.bob_upline_total, v_bob_downline, v_bob_upline
      USING ERRCODE = '23514';
  END IF;
  v_bob_hash := coherence.hash_bob_rows(NEW.attempt_event_id);
  IF v_bob_hash <> NEW.bob_rows_sha256 THEN
    RAISE EXCEPTION 'run_materialization bob_rows_sha256 mismatch'
      USING ERRCODE = '23514';
  END IF;

  SELECT pg_catalog.count(*)::integer,
         COALESCE(pg_catalog.sum(gross_comm), 0.00),
         COALESCE(pg_catalog.sum(downline_amount), 0.00),
         COALESCE(pg_catalog.sum(upline_amount), 0.00),
         COALESCE(pg_catalog.sum(downline_amount) FILTER (WHERE policy_id IS NOT NULL), 0.00),
         COALESCE(pg_catalog.sum(upline_amount) FILTER (WHERE policy_id IS NOT NULL), 0.00)
  INTO v_led_cnt, v_led_gross, v_led_downline, v_led_upline, v_pol_led_downline, v_pol_led_upline
  FROM coherence.coherent_ledger_rows
  WHERE attempt_event_id = NEW.attempt_event_id;

  IF v_led_cnt <> NEW.ledger_row_count THEN
    RAISE EXCEPTION 'run_materialization ledger row count mismatch: declared %, actual %',
      NEW.ledger_row_count, v_led_cnt
      USING ERRCODE = '23514';
  END IF;
  IF v_led_gross <> NEW.ledger_gross_total
     OR v_led_downline <> NEW.ledger_downline_total
     OR v_led_upline <> NEW.ledger_upline_total THEN
    RAISE EXCEPTION 'run_materialization ledger totals mismatch: declared (% / % / %), actual (% / % / %)',
      NEW.ledger_gross_total, NEW.ledger_downline_total, NEW.ledger_upline_total,
      v_led_gross, v_led_downline, v_led_upline
      USING ERRCODE = '23514';
  END IF;
  v_led_hash := coherence.hash_ledger_rows(NEW.attempt_event_id);
  IF v_led_hash <> NEW.ledger_rows_sha256 THEN
    RAISE EXCEPTION 'run_materialization ledger_rows_sha256 mismatch'
      USING ERRCODE = '23514';
  END IF;

  -- Conservation law: Book of Business totals must equal policy-linked Coherent Ledger splits to the exact cent.
  IF v_bob_downline <> v_pol_led_downline OR v_bob_upline <> v_pol_led_upline THEN
    RAISE EXCEPTION 'conservation violation: BoB totals (% / %) do not equal policy-linked ledger splits (% / %)',
      v_bob_downline, v_bob_upline, v_pol_led_downline, v_pol_led_upline
      USING ERRCODE = '23514';
  END IF;

  IF NEW.reconciliation_mode = 'strict_entity_ledger' THEN
    -- Conservation law: cumulative agency statements must equal Coherent Ledger downline splits for every entity.
    WITH eff AS (
      SELECT batch_id FROM coherence.run_effective_statement_batches(NEW.run_id)
    ),
    stmt_by_entity AS (
      SELECT sal.entity, COALESCE(pg_catalog.sum(sal.amount), 0.00) AS stmt_total
      FROM coherence.statement_agency_lines sal
      JOIN eff ON eff.batch_id = sal.batch_id
      GROUP BY sal.entity
    ),
    led_by_entity AS (
      SELECT clr.entity, COALESCE(pg_catalog.sum(clr.downline_amount), 0.00) AS led_total
      FROM coherence.coherent_ledger_rows clr
      WHERE clr.attempt_event_id = NEW.attempt_event_id
      GROUP BY clr.entity
    )
    SELECT pg_catalog.count(*) INTO v_entity_mismatch_cnt
    FROM stmt_by_entity s
    FULL OUTER JOIN led_by_entity l ON l.entity = s.entity
    WHERE COALESCE(s.stmt_total, 0.00) <> COALESCE(l.led_total, 0.00);

    IF v_entity_mismatch_cnt > 0 THEN
      RAISE EXCEPTION 'conservation violation: cumulative agency statements disagree with Coherent Ledger on % entity total(s)',
        v_entity_mismatch_cnt
        USING ERRCODE = '23514';
    END IF;

    -- Conservation law: cumulative upline statements must equal Coherent Ledger upline total to the exact cent.
    SELECT COALESCE(pg_catalog.sum(sul.amount), 0.00) INTO v_upline_stmt_total
    FROM coherence.statement_upline_lines sul
    JOIN coherence.run_effective_statement_batches(NEW.run_id) eff ON eff.batch_id = sul.batch_id;

    IF v_upline_stmt_total <> NEW.ledger_upline_total THEN
      RAISE EXCEPTION 'conservation violation: cumulative upline statements (%) disagree with Coherent Ledger upline total (%)',
        v_upline_stmt_total, NEW.ledger_upline_total
        USING ERRCODE = '23514';
    END IF;

    -- Conservation law: cumulative statements reconcile record-by-record to Coherent Ledger (no cross-record cancellation error).
    WITH eff AS (
      SELECT batch_id FROM coherence.run_effective_statement_batches(NEW.run_id)
    ),
    stmt_ag_rec AS (
      SELECT sal.record_id, sal.entity, COALESCE(pg_catalog.sum(sal.amount), 0.00) AS amt
      FROM coherence.statement_agency_lines sal
      JOIN eff ON eff.batch_id = sal.batch_id
      GROUP BY sal.record_id, sal.entity
    ),
    led_ag_rec AS (
      SELECT clr.record_id, clr.entity, COALESCE(pg_catalog.sum(clr.downline_amount), 0.00) AS amt
      FROM coherence.coherent_ledger_rows clr
      WHERE clr.attempt_event_id = NEW.attempt_event_id
      GROUP BY clr.record_id, clr.entity
    ),
    stmt_up_rec AS (
      SELECT sul.record_id, COALESCE(pg_catalog.sum(sul.amount), 0.00) AS amt
      FROM coherence.statement_upline_lines sul
      JOIN eff ON eff.batch_id = sul.batch_id
      GROUP BY sul.record_id
    ),
    led_up_rec AS (
      SELECT clr.record_id, COALESCE(pg_catalog.sum(clr.upline_amount), 0.00) AS amt
      FROM coherence.coherent_ledger_rows clr
      WHERE clr.attempt_event_id = NEW.attempt_event_id
      GROUP BY clr.record_id
    ),
    ag_diff AS (
      SELECT 1 AS bad
      FROM stmt_ag_rec s
      FULL OUTER JOIN led_ag_rec l ON l.record_id = s.record_id AND l.entity = s.entity
      WHERE COALESCE(s.amt, 0.00) <> COALESCE(l.amt, 0.00)
    ),
    up_diff AS (
      SELECT 1 AS bad
      FROM stmt_up_rec s
      FULL OUTER JOIN led_up_rec l ON l.record_id = s.record_id
      WHERE COALESCE(s.amt, 0.00) <> COALESCE(l.amt, 0.00)
    )
    SELECT (SELECT pg_catalog.count(*) FROM ag_diff) + (SELECT pg_catalog.count(*) FROM up_diff)
    INTO v_record_mismatch_cnt;

    IF v_record_mismatch_cnt > 0 THEN
      RAISE EXCEPTION 'conservation violation: cumulative statements disagree with Coherent Ledger on % record balance(s)',
        v_record_mismatch_cnt
        USING ERRCODE = '23514';
    END IF;
  END IF;

  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_run_materializations_verify_deferred
  AFTER INSERT ON coherence.run_materializations
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_run_materializations_verify_deferred();

-- 8. Update run_latest_journal_seq to include run_materializations and statement_batches.
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
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.review_queue_items WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.generated_overlays WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.decisions WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.emit_confirmations WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.statement_batches WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.run_materializations WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.carries WHERE run_id = p_run_id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.abandonments WHERE run_id = p_run_id), 0)
  );
$$;

-- 9. Extend trg_journal_verify_commitments to count-verify and content-hash-verify all 30 child business tables.
CREATE OR REPLACE FUNCTION coherence.trg_journal_verify_commitments()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_counts jsonb := COALESCE(NEW.body->'commitments'->'counts', '{}'::jsonb);
  v_hashes jsonb := COALESCE(NEW.body->'commitments'->'hashes', '{}'::jsonb);
  v_tbl text;
  v_declared bigint;
  v_actual bigint;
  v_hash text;
  v_declared_hash text;
BEGIN
  IF NOT (NEW.body ? 'commitments') OR pg_catalog.jsonb_typeof(NEW.body->'commitments') <> 'object' THEN
    RAISE EXCEPTION 'journal entry % body must include commitments object', NEW.seq
      USING ERRCODE = '22023';
  END IF;

  FOREACH v_tbl IN ARRAY ARRAY[
    'company_meta', 'stored_files', 'engine_versions',
    'input_versions', 'input_entries', 'input_changes',
    'approvals_files', 'approval_rows',
    'decision_commits', 'decisions', 'generated_overlays', 'review_queue_items',
    'runs', 'step_requests', 'cancel_requests', 'step_attempt_events', 'artifacts',
    'review_saves', 'emit_confirmations',
    'statement_batches', 'statement_agency_lines', 'statement_upline_lines',
    'run_materializations', 'bob_policies', 'bob_policy_financials', 'coherent_ledger_rows',
    'carries', 'abandonments', 'imported_files', 'checks'
  ] LOOP
    v_declared := COALESCE((v_counts->>v_tbl)::bigint, 0);
    EXECUTE pg_catalog.format('SELECT pg_catalog.count(*) FROM coherence.%I WHERE journal_seq = $1', v_tbl)
      INTO v_actual USING NEW.seq;
    IF v_actual <> v_declared THEN
      RAISE EXCEPTION 'journal entry % commitment count mismatch for %: declared %, actual %',
        NEW.seq, v_tbl, v_declared, v_actual
        USING ERRCODE = '22023';
    END IF;
  END LOOP;

  IF COALESCE((v_counts->>'company_meta')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'company_meta';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          company_slug, display_name, default_emit_mode, default_emit_display, default_emit_keep, default_emit_no_manager
        )) || E'\n',
        '' ORDER BY company_slug COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.company_meta WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % company_meta commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'stored_files')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'stored_files';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          store_kind, sha256, byte_size, md5_b64, crc32c_b64, object_name
        )) || E'\n',
        '' ORDER BY store_kind COLLATE "C", sha256 COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.stored_files WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % stored_files commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'engine_versions')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'engine_versions';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, label, coherence_commit, engine_kind, upstream_commit, patch_diff_sha256,
          git_bundle_sha256, code_manifest_sha256, python_lock_sha256, python_wheels_sha256,
          web_lock_sha256, web_packages_sha256, wrapper_bundle_sha256,
          nusear_commit, company_emit_sha256, pages_law_sha256, overlay_check_sha256,
          toolchain, container_digest
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.engine_versions WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % engine_versions commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'input_versions')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'input_versions';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, line_kind, parent_id::text, source_kind, reason,
          entry_count, entries_sha256, entries_list_file_sha256,
          change_count, changes_sha256
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.input_versions WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % input_versions commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'input_entries')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'input_entries';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(rel_path, file_sha256)) || E'\n',
        '' ORDER BY input_version_id::text COLLATE "C", rel_path COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.input_entries WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % input_entries commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'input_changes')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'input_changes';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          change_kind, rel_path, old_rel_path, file_sha256, prev_file_sha256
        )) || E'\n',
        '' ORDER BY input_version_id::text COLLATE "C", rel_path COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.input_changes WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % input_changes commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'approvals_files')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'approvals_files';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          file_sha256, header_kind, row_count, extends_sha256, shared_row_count, added_rows_sha256
        )) || E'\n',
        '' ORDER BY file_sha256 COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.approvals_files WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % approvals_files commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'approval_rows')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'approval_rows';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          row_no, record_id, disposition, agent, agency, policy, book, month, status, note,
          committed_at, approved_amount, approved_agency, approved_agent,
          approved_agency_from, approved_agent_from
        )) || E'\n',
        '' ORDER BY approvals_file_sha256 COLLATE "C", row_no ASC
      ), '')
    ) INTO v_hash FROM coherence.approval_rows WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % approval_rows commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'decision_commits')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'decision_commits';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, parent_commit_id::text, commit_kind, header_contract,
          added_decision_count, cumulative_decision_count, added_decisions_sha256,
          imported, CASE WHEN original_at IS NULL THEN NULL ELSE coherence.format_utc_us(original_at) END
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.decision_commits WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % decision_commits commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'decisions')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'decisions';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          decision_commit_id::text, id::text, row_order, run_id::text, review_save_id::text, surface,
          record_id, replaces_decision_id::text, disposition,
          agent, agency, policy, book, month, status, note,
          approved_amount, approved_agency, approved_agent,
          approved_agency_from, approved_agent_from,
          decided_by, acting_for, coherence.format_utc_us(decided_at),
          committed_at_raw, imported
        )) || E'\n',
        '' ORDER BY decision_commit_id::text COLLATE "C", row_order ASC
      ), '')
    ) INTO v_hash FROM coherence.decisions WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % decisions commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'generated_overlays')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'generated_overlays';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, decision_commit_id::text, run_id::text, purpose,
          attempt_event_id::text, header_contract, row_count, store_kind, file_sha256
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.generated_overlays WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % generated_overlays commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'review_queue_items')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'review_queue_items';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          attempt_event_id::text, item_order, run_id::text, surface,
          record_id, case_kind, subtype, entity, npn, amount,
          entity_from, npn_from, needs_reconfirm
        )) || E'\n',
        '' ORDER BY attempt_event_id::text COLLATE "C", item_order ASC
      ), '')
    ) INTO v_hash FROM coherence.review_queue_items WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % review_queue_items commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'runs')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'runs';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, pg_catalog.to_char(statement_date, 'YYYY-MM-DD'), folder_number, origin,
          input_version_id::text, prior_approvals_sha256, prior_decision_commit_id::text, engine_version_id::text,
          emit_mode, emit_display, emit_keep, emit_no_manager,
          replays_run_id::text, compared_run_id::text, rerun_reason, source_folder
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.runs WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % runs commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'step_requests')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'step_requests';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, run_id::text, step, reason, emit_confirmation_id::text
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.step_requests WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % step_requests commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'cancel_requests')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'cancel_requests';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, run_id::text, step, attempt_no, typed_phrase, reason
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.cancel_requests WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % cancel_requests commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'step_attempt_events')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'step_attempt_events';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, run_id::text, step, attempt_no, event_kind,
          step_request_id::text, cancel_request_id::text, born, log_file_sha256,
          artifact_count, artifacts_sha256
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.step_attempt_events WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % step_attempt_events commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'artifacts')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'artifacts';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          rel_path, artifact_kind, store_kind, file_sha256
        )) || E'\n',
        '' ORDER BY attempt_event_id::text COLLATE "C", rel_path COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.artifacts WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % artifacts commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'review_saves')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'review_saves';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, run_id::text, surface, attempt_event_id::text,
          approvals_file_sha256, decision_commit_id::text,
          imported, CASE WHEN original_at IS NULL THEN NULL ELSE coherence.format_utc_us(original_at) END,
          submission_id::text
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.review_saves WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % review_saves commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'emit_confirmations')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'emit_confirmations';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, run_id::text, adjust_review_save_id::text, typed_phrase
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.emit_confirmations WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % emit_confirmations commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'statement_batches')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'statement_batches';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, batch_kind, coherence.fmt_date(statement_date),
          run_id::text, attempt_event_id::text, source_file_name, source_file_sha256, reason,
          agency_line_count, agency_lines_sha256, coherence.fmt_num2(agency_net_total),
          upline_line_count, upline_lines_sha256, coherence.fmt_num2(upline_net_total)
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.statement_batches WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % statement_batches commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'statement_agency_lines')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'statement_agency_lines';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          batch_id::text, line_no, coherence.fmt_date(statement_date), entry_kind, run_action,
          entity, writing_npn, writing_agent, record_id, reversal_of, corrects_record_id,
          source_file, sheet_name, source_row_no, src_type, carrier, mbi, member,
          external_policy_id, policy_id, tx_id, plan_type, simple_plan_type, state,
          coherence.fmt_date(submission_date), coherence.fmt_date(origin_effective),
          coherence.fmt_date(effective_date), coherence.fmt_date(termination_date),
          coherence.fmt_date(earned_date), coherence.fmt_date(payment_date),
          coherence.fmt_date(posted_statement_date), revenue_type,
          coherence.fmt_num2(gross_comm), coherence.fmt_num2(amount), reason, notes
        )) || E'\n',
        '' ORDER BY batch_id::text COLLATE "C", line_no ASC
      ), '')
    ) INTO v_hash FROM coherence.statement_agency_lines WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % statement_agency_lines commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'statement_upline_lines')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'statement_upline_lines';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          batch_id::text, line_no, coherence.fmt_date(statement_date), entry_kind, run_action,
          source_entity, marked_sent, writing_npn, writing_agent, record_id, reversal_of,
          corrects_record_id, source_file, sheet_name, source_row_no, src_type, carrier,
          mbi, member, external_policy_id, policy_id, tx_id, plan_type, simple_plan_type, state,
          coherence.fmt_date(submission_date), coherence.fmt_date(origin_effective),
          coherence.fmt_date(effective_date), coherence.fmt_date(termination_date),
          coherence.fmt_date(earned_date), coherence.fmt_date(payment_date),
          coherence.fmt_date(posted_statement_date), revenue_type,
          coherence.fmt_num2(gross_comm), coherence.fmt_num2(amount), reason, notes
        )) || E'\n',
        '' ORDER BY batch_id::text COLLATE "C", line_no ASC
      ), '')
    ) INTO v_hash FROM coherence.statement_upline_lines WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % statement_upline_lines commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'run_materializations')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'run_materializations';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          attempt_event_id::text, run_id::text, coherence.fmt_date(statement_date), reconciliation_mode,
          bob_row_count, bob_rows_sha256, coherence.fmt_num2(bob_downline_total), coherence.fmt_num2(bob_upline_total),
          ledger_row_count, ledger_rows_sha256,
          coherence.fmt_num2(ledger_gross_total), coherence.fmt_num2(ledger_downline_total), coherence.fmt_num2(ledger_upline_total),
          statement_batch_id::text, corpus_tail, coherence.fmt_date(agency_start)
        )) || E'\n',
        '' ORDER BY attempt_event_id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.run_materializations WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % run_materializations commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'bob_policies')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'bob_policies';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          attempt_event_id::text, policy_id, run_id::text, external_policy_id,
          carrier_policy_number, crm_policy_number, carrier, plan_type, plan_name, simple_plan_type,
          mbi, member, dob, phone, email, address, county, state,
          coherence.fmt_date(submission_date), coherence.fmt_date(origin_effective),
          coherence.fmt_date(effective_date), coherence.fmt_date(termination_date),
          writing_npn, writing_agent, entity, status, coherent_status
        )) || E'\n',
        '' ORDER BY attempt_event_id::text COLLATE "C", policy_id ASC
      ), '')
    ) INTO v_hash FROM coherence.bob_policies WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % bob_policies commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'bob_policy_financials')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'bob_policy_financials';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          attempt_event_id::text, policy_id, entity, writing_npn,
          coherence.fmt_num2(amount), coherence.fmt_num2(upline_amount),
          enrollment_code, coherence.fmt_date(min_date), coherence.fmt_date(anchor_date),
          agency_id, conflicts, spine_source, confidence_level, coherent_trajectory
        )) || E'\n',
        '' ORDER BY attempt_event_id::text COLLATE "C", policy_id ASC
      ), '')
    ) INTO v_hash FROM coherence.bob_policy_financials WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % bob_policy_financials commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'coherent_ledger_rows')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'coherent_ledger_rows';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          attempt_event_id::text, tx_id, run_id::text, record_id, external_policy_id, policy_id,
          statement_name, src_type, carrier, mbi, member, state, plan_type, simple_plan_type,
          coherence.fmt_date(submission_date), coherence.fmt_date(origin_effective),
          coherence.fmt_date(effective_date), coherence.fmt_date(termination_date),
          coherence.fmt_date(earned_date), coherence.fmt_date(payment_date),
          coherence.fmt_date(statement_date), coherence.fmt_date(min_date),
          coherence.fmt_num2(gross_comm), revenue_type,
          coherence.fmt_num2(override_amount), coherence.fmt_num2(commission_amount),
          coherence.fmt_num2(hra_amount), coherence.fmt_num2(fee_amount), coherence.fmt_num2(other_amount),
          coherence.fmt_num2(downline_amount), coherence.fmt_num2(upline_amount),
          writing_npn, writing_agent, entity, payee_npn, agency_id,
          status, policy_status, cbob_c, cbob_s, sf, notes, coherent_notes,
          sheet_name, source_row_no
        )) || E'\n',
        '' ORDER BY attempt_event_id::text COLLATE "C", tx_id ASC
      ), '')
    ) INTO v_hash FROM coherence.coherent_ledger_rows WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % coherent_ledger_rows commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'carries')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'carries';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, run_id::text, pg_catalog.to_char(statement_date, 'YYYY-MM-DD'),
          carry_kind, file_sha256, carried_decision_commit_id::text,
          published_input_version_id::text, nothing_new, typed_phrase
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.carries WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % carries commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'abandonments')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'abandonments';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, run_id::text, typed_phrase, reason
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.abandonments WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % abandonments commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'imported_files')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'imported_files';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, area, rel_path, artifact_kind, store_kind, file_sha256,
          CASE WHEN original_at IS NULL THEN NULL ELSE coherence.format_utc_us(original_at) END,
          metadata
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.imported_files WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % imported_files commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'checks')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'checks';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, check_kind, run_id::text, compared_run_id::text, passed, report
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash FROM coherence.checks WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % checks commitment hash mismatch', NEW.seq USING ERRCODE = '22023';
    END IF;
  END IF;

  RETURN NULL;
END;
$$;
