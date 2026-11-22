-- Migration 002: Database-enforced invariants, journal hash chain, immutability (ENABLE ALWAYS),
-- canonical commitments, slot lock enforcement, and all R8/R9/R11 guards.
-- Every function pins SET search_path = pg_catalog and schema-qualifies every reference.

-- ============================================================================
-- A. Canonical JSON, hashing, slot advisory lock helpers, and approvals chain
-- ============================================================================

CREATE OR REPLACE FUNCTION coherence.slot_class_id()
RETURNS integer
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$ SELECT 1129270853; $$; -- 'COHE'

CREATE OR REPLACE FUNCTION coherence.slot_obj_id()
RETURNS integer
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$ SELECT 1397509972; $$; -- 'SLOT'

CREATE OR REPLACE FUNCTION coherence.this_connection_holds_slot()
RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_locks l
    JOIN pg_catalog.pg_database d ON d.oid = l.database
    WHERE l.locktype = 'advisory'
      AND d.datname = pg_catalog.current_database()
      AND l.classid = coherence.slot_class_id()::oid
      AND l.objid = coherence.slot_obj_id()::oid
      AND l.objsubid = 2
      AND l.pid = pg_catalog.pg_backend_pid()
      AND l.granted = true
  );
$$;

CREATE OR REPLACE FUNCTION coherence.slot_is_free()
RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_locks l
    JOIN pg_catalog.pg_database d ON d.oid = l.database
    WHERE l.locktype = 'advisory'
      AND d.datname = pg_catalog.current_database()
      AND l.classid = coherence.slot_class_id()::oid
      AND l.objid = coherence.slot_obj_id()::oid
      AND l.objsubid = 2
      AND l.granted = true
  );
$$;

CREATE OR REPLACE FUNCTION coherence.own_backend_start()
RETURNS timestamptz
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT backend_start
  FROM pg_catalog.pg_stat_activity
  WHERE pid = pg_catalog.pg_backend_pid();
$$;

CREATE OR REPLACE FUNCTION coherence.canonical_json(val jsonb)
RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT
SET search_path = pg_catalog
AS $$
DECLARE
  v_type text := pg_catalog.jsonb_typeof(val);
  v_res text;
BEGIN
  IF v_type = 'null' THEN
    RETURN 'null';
  ELSIF v_type = 'boolean' THEN
    RETURN val::text;
  ELSIF v_type = 'number' THEN
    RETURN val::text;
  ELSIF v_type = 'string' THEN
    RETURN pg_catalog.to_json(val #>> '{}')::text;
  ELSIF v_type = 'array' THEN
    SELECT '[' || COALESCE(pg_catalog.string_agg(coherence.canonical_json(elem), ',' ORDER BY ord), '') || ']'
    INTO v_res
    FROM pg_catalog.jsonb_array_elements(val) WITH ORDINALITY AS t(elem, ord);
    RETURN v_res;
  ELSIF v_type = 'object' THEN
    SELECT '{' || COALESCE(
      pg_catalog.string_agg(
        pg_catalog.to_json(k)::text || ':' || coherence.canonical_json(v),
        ',' ORDER BY k COLLATE "C"
      ),
      ''
    ) || '}'
    INTO v_res
    FROM pg_catalog.jsonb_each(val) AS t(k, v);
    RETURN v_res;
  ELSE
    RAISE EXCEPTION 'unsupported jsonb type: %', v_type;
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION coherence.sha256_text(input text)
RETURNS text
LANGUAGE sql IMMUTABLE STRICT
SET search_path = pg_catalog
AS $$
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(input, 'UTF8')), 'hex');
$$;

CREATE OR REPLACE FUNCTION coherence.format_utc_us(ts timestamptz)
RETURNS text
LANGUAGE sql IMMUTABLE STRICT
SET search_path = pg_catalog
AS $$
  SELECT pg_catalog.to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
$$;

CREATE OR REPLACE FUNCTION coherence.compute_journal_hash(
  p_seq bigint,
  p_recorded_at timestamptz,
  p_actor text,
  p_acting_for text,
  p_command_kind text,
  p_command_key text,
  p_request_sha256 text,
  p_prev_hash text,
  p_body jsonb
)
RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT coherence.sha256_text(
    'coherence-journal-v1' || E'\n' || coherence.canonical_json(
      pg_catalog.jsonb_build_object(
        'acting_for', p_acting_for,
        'actor', p_actor,
        'body', p_body,
        'command_key', p_command_key,
        'command_kind', p_command_kind,
        'prev_hash', p_prev_hash,
        'recorded_at', coherence.format_utc_us(p_recorded_at),
        'request_sha256', p_request_sha256,
        'seq', p_seq
      )
    )
  );
$$;

CREATE OR REPLACE FUNCTION coherence.approvals_extends(p_child text, p_ancestor text)
RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  WITH RECURSIVE chain(sha, depth) AS (
    SELECT p_child, 0
    UNION ALL
    SELECT af.extends_sha256, c.depth + 1
    FROM chain c
    JOIN coherence.approvals_files af ON af.file_sha256 = c.sha
    WHERE af.extends_sha256 IS NOT NULL AND c.depth < 10000
  )
  SELECT EXISTS (SELECT 1 FROM chain WHERE sha = p_ancestor)
      OR EXISTS (SELECT 1 FROM coherence.approvals_files WHERE file_sha256 = p_ancestor AND row_count = 0);
$$;

CREATE OR REPLACE FUNCTION coherence.is_code_bearing_path(p_rel_path text)
RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT
SET search_path = pg_catalog
AS $$
  SELECT pg_catalog.lower(p_rel_path) ~ '\.(html?|xhtml|js|mjs|cjs|ts|tsx|jsx|py|sh|css|wasm|svg)$';
$$;

CREATE OR REPLACE FUNCTION coherence.step_rank(p_step text)
RETURNS integer
LANGUAGE sql IMMUTABLE STRICT
SET search_path = pg_catalog
AS $$
  SELECT CASE p_step
    WHEN 'assign' THEN 1
    WHEN 'attribute' THEN 2
    WHEN 'bible' THEN 3
    WHEN 'adjust' THEN 4
    WHEN 'emit' THEN 5
    ELSE 0
  END;
$$;

-- Canonical list hashes (exact match with src/util/crypto.mjs)
CREATE OR REPLACE FUNCTION coherence.hash_input_entries(p_input_version_id uuid)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT coherence.sha256_text(
    COALESCE(
      (SELECT pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(rel_path, file_sha256)) || E'\n',
        '' ORDER BY rel_path COLLATE "C"
      )
      FROM coherence.input_entries
      WHERE input_version_id = p_input_version_id),
      ''
    )
  );
$$;

CREATE OR REPLACE FUNCTION coherence.hash_input_changes(p_input_version_id uuid)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT coherence.sha256_text(
    COALESCE(
      (SELECT pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          change_kind, rel_path, old_rel_path, file_sha256, prev_file_sha256
        )) || E'\n',
        '' ORDER BY rel_path COLLATE "C"
      )
      FROM coherence.input_changes
      WHERE input_version_id = p_input_version_id),
      ''
    )
  );
$$;

CREATE OR REPLACE FUNCTION coherence.hash_artifacts(p_attempt_event_id uuid)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT coherence.sha256_text(
    COALESCE(
      (SELECT pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          rel_path, artifact_kind, store_kind, file_sha256
        )) || E'\n',
        '' ORDER BY rel_path COLLATE "C"
      )
      FROM coherence.artifacts
      WHERE attempt_event_id = p_attempt_event_id),
      ''
    )
  );
$$;

CREATE OR REPLACE FUNCTION coherence.hash_approval_rows(p_approvals_file_sha256 text)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT coherence.sha256_text(
    COALESCE(
      (SELECT pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          row_no, record_id, disposition, agent, agency, policy, book, month, status, note,
          committed_at, approved_amount, approved_agency, approved_agent,
          approved_agency_from, approved_agent_from
        )) || E'\n',
        '' ORDER BY row_no ASC
      )
      FROM coherence.approval_rows
      WHERE approvals_file_sha256 = p_approvals_file_sha256),
      ''
    )
  );
$$;

-- ============================================================================
-- B. R9.1 Immutability: forbid UPDATE, DELETE, TRUNCATE under ALL settings
-- ============================================================================

CREATE OR REPLACE FUNCTION coherence.forbid_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'business table %.% is immutable: % is forbidden (R9.1)',
    TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END;
$$;

DO $$
DECLARE
  v_tbl text;
BEGIN
  FOREACH v_tbl IN ARRAY ARRAY[
    'journal_entries', 'company_meta', 'stored_files', 'engine_versions',
    'input_versions', 'input_entries', 'input_changes',
    'approvals_files', 'approval_rows',
    'runs', 'step_requests', 'cancel_requests', 'step_attempt_events', 'artifacts',
    'review_saves', 'emit_confirmations', 'carries', 'abandonments',
    'imported_files', 'checks'
  ] LOOP
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER trg_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON coherence.%I FOR EACH STATEMENT EXECUTE FUNCTION coherence.forbid_mutation()',
      v_tbl
    );
    EXECUTE pg_catalog.format(
      'ALTER TABLE coherence.%I ENABLE ALWAYS TRIGGER trg_immutable',
      v_tbl
    );
  END LOOP;
END;
$$;

-- ============================================================================
-- C. R9.2 Journal chain enforcement & R9.3 active-tx / commitment enforcement
-- ============================================================================

CREATE OR REPLACE FUNCTION coherence.trg_journal_before_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_prev_seq bigint;
  v_prev_hash text;
  v_prev_time timestamptz;
  v_expected_seq bigint;
  v_expected_prev_hash text;
  v_computed_hash text;
BEGIN
  -- R9.2: writes only at SERIALIZABLE isolation
  IF pg_catalog.current_setting('transaction_isolation') <> 'serializable' THEN
    RAISE EXCEPTION 'journal_entries writes require SERIALIZABLE isolation (current: %)',
      pg_catalog.current_setting('transaction_isolation')
      USING ERRCODE = '25001';
  END IF;

  -- Never allow a forged transaction xid
  IF NEW.created_xid IS DISTINCT FROM pg_catalog.pg_current_xact_id() THEN
    RAISE EXCEPTION 'journal_entries.created_xid must match current transaction id'
      USING ERRCODE = '22023';
  END IF;

  SELECT seq, entry_hash, recorded_at
  INTO v_prev_seq, v_prev_hash, v_prev_time
  FROM coherence.journal_entries
  ORDER BY seq DESC
  LIMIT 1;

  IF v_prev_seq IS NULL THEN
    v_expected_seq := 1;
    v_expected_prev_hash := pg_catalog.repeat('0', 64);
  ELSE
    v_expected_seq := v_prev_seq + 1;
    v_expected_prev_hash := v_prev_hash;
  END IF;

  -- R9.2 & R11 audit: verify given seq/prev_hash/recorded_at/entry_hash exactly, NEVER overwrite!
  IF NEW.seq IS NULL THEN
    NEW.seq := v_expected_seq;
  ELSIF NEW.seq <> v_expected_seq THEN
    RAISE EXCEPTION 'journal_entries seq must be gapless: expected %, got %', v_expected_seq, NEW.seq
      USING ERRCODE = '22023';
  END IF;

  IF NEW.prev_hash IS NULL THEN
    NEW.prev_hash := v_expected_prev_hash;
  ELSIF NEW.prev_hash <> v_expected_prev_hash THEN
    RAISE EXCEPTION 'journal_entries prev_hash mismatch: expected %, got %', v_expected_prev_hash, NEW.prev_hash
      USING ERRCODE = '22023';
  END IF;

  IF NEW.recorded_at IS NULL THEN
    NEW.recorded_at := GREATEST(pg_catalog.clock_timestamp(), COALESCE(v_prev_time, '-infinity'::timestamptz));
  ELSIF v_prev_time IS NOT NULL AND NEW.recorded_at < v_prev_time THEN
    RAISE EXCEPTION 'journal_entries recorded_at (%) cannot precede previous entry (%)', NEW.recorded_at, v_prev_time
      USING ERRCODE = '22023';
  END IF;

  v_computed_hash := coherence.compute_journal_hash(
    NEW.seq, NEW.recorded_at, NEW.actor, NEW.acting_for,
    NEW.command_kind, NEW.command_key, NEW.request_sha256, NEW.prev_hash, NEW.body
  );

  IF NEW.entry_hash IS NULL THEN
    NEW.entry_hash := v_computed_hash;
  ELSIF NEW.entry_hash <> v_computed_hash THEN
    RAISE EXCEPTION 'journal_entries entry_hash mismatch: expected %, got %', v_computed_hash, NEW.entry_hash
      USING ERRCODE = '22023';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_journal_before_insert
  BEFORE INSERT ON coherence.journal_entries
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_journal_before_insert();

-- R9.2 & R11 audit: strictly ONE journal entry per INSERT statement (blocks multi-row inserts)
CREATE OR REPLACE FUNCTION coherence.trg_journal_single_row()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_cnt bigint;
BEGIN
  SELECT pg_catalog.count(*) INTO v_cnt FROM new_rows;
  IF v_cnt <> 1 THEN
    RAISE EXCEPTION 'journal_entries allows exactly one entry per INSERT statement (got %)', v_cnt
      USING ERRCODE = '22023';
  END IF;
  RETURN NULL;
END;
$$;

CREATE TRIGGER trg_journal_single_row
  AFTER INSERT ON coherence.journal_entries
  REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION coherence.trg_journal_single_row();

-- R9.3: Every child business row MUST attach to a journal entry created in THIS transaction (never a previously committed one).
CREATE OR REPLACE FUNCTION coherence.trg_require_active_journal()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_xid xid8;
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'serializable' THEN
    RAISE EXCEPTION 'writes to %.% require SERIALIZABLE isolation', TG_TABLE_SCHEMA, TG_TABLE_NAME
      USING ERRCODE = '25001';
  END IF;

  SELECT created_xid INTO v_xid
  FROM coherence.journal_entries
  WHERE seq = NEW.journal_seq;

  IF v_xid IS NULL OR v_xid <> pg_catalog.pg_current_xact_id() THEN
    RAISE EXCEPTION 'cannot attach %.% row to committed or missing journal entry %',
      TG_TABLE_SCHEMA, TG_TABLE_NAME, NEW.journal_seq
      USING ERRCODE = '22023';
  END IF;
  RETURN NEW;
END;
$$;

DO $$
DECLARE
  v_tbl text;
BEGIN
  FOREACH v_tbl IN ARRAY ARRAY[
    'company_meta', 'stored_files', 'engine_versions',
    'input_versions', 'input_entries', 'input_changes',
    'approvals_files', 'approval_rows',
    'runs', 'step_requests', 'cancel_requests', 'step_attempt_events', 'artifacts',
    'review_saves', 'emit_confirmations', 'carries', 'abandonments',
    'imported_files', 'checks'
  ] LOOP
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER trg_01_require_active_journal BEFORE INSERT ON coherence.%I FOR EACH ROW EXECUTE FUNCTION coherence.trg_require_active_journal()',
      v_tbl
    );
  END LOOP;
END;
$$;

-- R9.3 Deferred commitment verifier on journal_entries: verifies every attached table count matches declared body->commitments->counts
-- and verifies canonical hashes for large lists committed in the journal entry.
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
    RAISE EXCEPTION 'journal entry % body must include commitments object (R9.3)', NEW.seq
      USING ERRCODE = '22023';
  END IF;

  FOREACH v_tbl IN ARRAY ARRAY[
    'company_meta', 'stored_files', 'engine_versions',
    'input_versions', 'input_entries', 'input_changes',
    'approvals_files', 'approval_rows',
    'runs', 'step_requests', 'cancel_requests', 'step_attempt_events', 'artifacts',
    'review_saves', 'emit_confirmations', 'carries', 'abandonments',
    'imported_files', 'checks'
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

  -- Verify canonical list hashes for stored_files when inserted
  IF COALESCE((v_counts->>'stored_files')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'stored_files';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          store_kind, sha256, byte_size, md5_b64, crc32c_b64, object_name
        )) || E'\n',
        '' ORDER BY store_kind COLLATE "C", sha256 COLLATE "C"
      ), '')
    ) INTO v_hash
    FROM coherence.stored_files
    WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % stored_files commitment hash mismatch', NEW.seq
        USING ERRCODE = '22023';
    END IF;
  END IF;

  -- Verify input_entries / input_changes hashes against body->commitments->hashes
  IF COALESCE((v_counts->>'input_entries')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'input_entries';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(rel_path, file_sha256)) || E'\n',
        '' ORDER BY input_version_id::text COLLATE "C", rel_path COLLATE "C"
      ), '')
    ) INTO v_hash
    FROM coherence.input_entries
    WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % input_entries commitment hash mismatch', NEW.seq
        USING ERRCODE = '22023';
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
    ) INTO v_hash
    FROM coherence.input_changes
    WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % input_changes commitment hash mismatch', NEW.seq
        USING ERRCODE = '22023';
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
    ) INTO v_hash
    FROM coherence.artifacts
    WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % artifacts commitment hash mismatch', NEW.seq
        USING ERRCODE = '22023';
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
    ) INTO v_hash
    FROM coherence.approval_rows
    WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % approval_rows commitment hash mismatch', NEW.seq
        USING ERRCODE = '22023';
    END IF;
  END IF;

  -- Verify inline small-record commitments when present in body
  IF COALESCE((v_counts->>'runs')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'runs';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, pg_catalog.to_char(statement_date, 'YYYY-MM-DD'), folder_number, origin,
          input_version_id::text, prior_approvals_sha256, engine_version_id::text,
          emit_mode, emit_display, emit_keep, emit_no_manager,
          replays_run_id::text, compared_run_id::text, rerun_reason, source_folder
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash
    FROM coherence.runs
    WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % runs commitment hash mismatch', NEW.seq
        USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'carries')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'carries';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, run_id::text, pg_catalog.to_char(statement_date, 'YYYY-MM-DD'),
          carry_kind, file_sha256, published_input_version_id::text, nothing_new, typed_phrase
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash
    FROM coherence.carries
    WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % carries commitment hash mismatch', NEW.seq
        USING ERRCODE = '22023';
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
    ) INTO v_hash
    FROM coherence.abandonments
    WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % abandonments commitment hash mismatch', NEW.seq
        USING ERRCODE = '22023';
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
    ) INTO v_hash
    FROM coherence.emit_confirmations
    WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % emit_confirmations commitment hash mismatch', NEW.seq
        USING ERRCODE = '22023';
    END IF;
  END IF;

  IF COALESCE((v_counts->>'review_saves')::bigint, 0) > 0 THEN
    v_declared_hash := v_hashes->>'review_saves';
    SELECT coherence.sha256_text(
      COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, run_id::text, surface, attempt_event_id::text, approvals_file_sha256,
          imported, CASE WHEN original_at IS NULL THEN NULL ELSE coherence.format_utc_us(original_at) END,
          submission_id::text
        )) || E'\n',
        '' ORDER BY id::text COLLATE "C"
      ), '')
    ) INTO v_hash
    FROM coherence.review_saves
    WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % review_saves commitment hash mismatch', NEW.seq
        USING ERRCODE = '22023';
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
    ) INTO v_hash
    FROM coherence.step_requests
    WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % step_requests commitment hash mismatch', NEW.seq
        USING ERRCODE = '22023';
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
    ) INTO v_hash
    FROM coherence.step_attempt_events
    WHERE journal_seq = NEW.seq;
    IF v_declared_hash IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'journal entry % step_attempt_events commitment hash mismatch', NEW.seq
        USING ERRCODE = '22023';
    END IF;
  END IF;

  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_journal_verify_commitments
  AFTER INSERT ON coherence.journal_entries
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_journal_verify_commitments();

-- ============================================================================
-- D. Input versions, entries, changes & Sent/Overlay rules (R6.3-6.5, R9.5)
-- ============================================================================

CREATE OR REPLACE FUNCTION coherence.trg_input_versions_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_parent coherence.input_versions%ROWTYPE;
BEGIN
  IF NEW.parent_id IS NOT NULL THEN
    SELECT * INTO v_parent FROM coherence.input_versions WHERE id = NEW.parent_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'parent input version % does not exist', NEW.parent_id;
    END IF;
    IF v_parent.line_kind <> 'standing' THEN
      RAISE EXCEPTION 'input version parent must be on the standing line (R6.3)';
    END IF;
    IF v_parent.journal_seq >= NEW.journal_seq THEN
      RAISE EXCEPTION 'input version parent must be strictly older than child (R6.3)';
    END IF;
  ELSIF NEW.line_kind = 'standing' THEN
    IF EXISTS (SELECT 1 FROM coherence.input_versions WHERE line_kind = 'standing') THEN
      RAISE EXCEPTION 'standing input line already has a root version; parent_id is required (R6.3)';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_input_versions_before
  BEFORE INSERT ON coherence.input_versions
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_input_versions_before();

CREATE OR REPLACE FUNCTION coherence.trg_input_entries_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_iv coherence.input_versions%ROWTYPE;
BEGIN
  SELECT * INTO v_iv FROM coherence.input_versions WHERE id = NEW.input_version_id;
  IF NOT FOUND OR v_iv.journal_seq <> NEW.journal_seq THEN
    RAISE EXCEPTION 'input_entries must be inserted in the same journal entry as their input_version (R9.3)';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_input_entries_before
  BEFORE INSERT ON coherence.input_entries
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_input_entries_before();

CREATE OR REPLACE FUNCTION coherence.trg_input_changes_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_iv coherence.input_versions%ROWTYPE;
BEGIN
  SELECT * INTO v_iv FROM coherence.input_versions WHERE id = NEW.input_version_id;
  IF NOT FOUND OR v_iv.journal_seq <> NEW.journal_seq THEN
    RAISE EXCEPTION 'input_changes must be inserted in the same journal entry as their input_version (R9.3)';
  END IF;
  IF v_iv.parent_id IS NULL THEN
    RAISE EXCEPTION 'input_changes are only valid when input_version has a parent_id';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_input_changes_before
  BEFORE INSERT ON coherence.input_changes
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_input_changes_before();

CREATE OR REPLACE FUNCTION coherence.trg_input_versions_verify_deferred()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_entry_count integer;
  v_entries_hash text;
  v_change_count integer;
  v_changes_hash text;
  v_sent_diff integer;
  v_overlay_diff integer;
  v_other_diff integer;
  v_carry coherence.carries%ROWTYPE;
  v_expected_sent_path text;
  v_bad_diff integer;
  v_bad_sent integer;
BEGIN
  -- 1. Check declared entry count and canonical hash
  SELECT pg_catalog.count(*)::integer INTO v_entry_count
  FROM coherence.input_entries WHERE input_version_id = NEW.id;
  IF v_entry_count <> NEW.entry_count THEN
    RAISE EXCEPTION 'input_version % entry_count mismatch: declared %, actual %', NEW.id, NEW.entry_count, v_entry_count;
  END IF;
  v_entries_hash := coherence.hash_input_entries(NEW.id);
  IF v_entries_hash <> NEW.entries_sha256 THEN
    RAISE EXCEPTION 'input_version % entries_sha256 mismatch', NEW.id;
  END IF;

  -- 2. Check declared change count and canonical hash
  SELECT pg_catalog.count(*)::integer INTO v_change_count
  FROM coherence.input_changes WHERE input_version_id = NEW.id;
  IF v_change_count <> NEW.change_count THEN
    RAISE EXCEPTION 'input_version % change_count mismatch: declared %, actual %', NEW.id, NEW.change_count, v_change_count;
  END IF;
  v_changes_hash := coherence.hash_input_changes(NEW.id);
  IF v_changes_hash <> NEW.changes_sha256 THEN
    RAISE EXCEPTION 'input_version % changes_sha256 mismatch', NEW.id;
  END IF;

  -- 3. R6.4 & DS-2: No path may be both a file and a folder (ignoring case and NFC normalization)
  IF EXISTS (
    WITH paths AS (
      SELECT mac_key, pg_catalog.string_to_array(mac_key, '/') AS parts
      FROM coherence.input_entries
      WHERE input_version_id = NEW.id
    ),
    prefixes AS (
      SELECT pg_catalog.array_to_string(parts[1:i], '/') AS folder_key
      FROM paths, pg_catalog.generate_subscripts(parts, 1) AS i
      WHERE i < pg_catalog.array_length(parts, 1)
    )
    SELECT 1 FROM paths p JOIN prefixes f ON p.mac_key = f.folder_key
  ) THEN
    RAISE EXCEPTION 'input_version % has a file/folder path clash (ignoring case and Unicode normalization) (R6.4)', NEW.id
      USING ERRCODE = '23514';
  END IF;

  -- 4. If parent exists, verify exact 1-to-1 correspondence between (parent vs NEW entries) and input_changes
  IF NEW.parent_id IS NOT NULL THEN
    -- Every parent row that changed or disappeared must match exactly one removed, replaced, or renamed(old_rel_path) change
    IF EXISTS (
      WITH parent_diff AS (
        SELECT p.rel_path, p.file_sha256
        FROM coherence.input_entries p
        LEFT JOIN coherence.input_entries c
          ON c.input_version_id = NEW.id AND c.rel_path = p.rel_path AND c.file_sha256 = p.file_sha256
        WHERE p.input_version_id = NEW.parent_id AND c.rel_path IS NULL
      ),
      change_left AS (
        SELECT CASE WHEN change_kind = 'renamed' THEN old_rel_path ELSE rel_path END AS rel_path,
               CASE WHEN change_kind = 'renamed' THEN file_sha256 ELSE prev_file_sha256 END AS file_sha256
        FROM coherence.input_changes
        WHERE input_version_id = NEW.id AND change_kind IN ('removed', 'replaced', 'renamed')
      )
      SELECT 1 FROM parent_diff pd FULL OUTER JOIN change_left cl
        ON pd.rel_path = cl.rel_path AND pd.file_sha256 = cl.file_sha256
      WHERE pd.rel_path IS NULL OR cl.rel_path IS NULL
    ) THEN
      RAISE EXCEPTION 'input_changes does not match parent-side differences of input_version % (R6.5)', NEW.id
        USING ERRCODE = '23514';
    END IF;

    -- Every child row that is new or changed must match exactly one added, replaced, or renamed(rel_path) change
    IF EXISTS (
      WITH child_diff AS (
        SELECT c.rel_path, c.file_sha256
        FROM coherence.input_entries c
        LEFT JOIN coherence.input_entries p
          ON p.input_version_id = NEW.parent_id AND p.rel_path = c.rel_path AND p.file_sha256 = c.file_sha256
        WHERE c.input_version_id = NEW.id AND p.rel_path IS NULL
      ),
      change_right AS (
        SELECT rel_path, file_sha256
        FROM coherence.input_changes
        WHERE input_version_id = NEW.id AND change_kind IN ('added', 'replaced', 'renamed')
      )
      SELECT 1 FROM child_diff cd FULL OUTER JOIN change_right cr
        ON cd.rel_path = cr.rel_path AND cd.file_sha256 = cr.file_sha256
      WHERE cd.rel_path IS NULL OR cr.rel_path IS NULL
    ) THEN
      RAISE EXCEPTION 'input_changes does not match child-side differences of input_version % (R6.5)', NEW.id
        USING ERRCODE = '23514';
    END IF;

    -- 5. R9.5 & DS-1: Sent and Overlay protection derived directly from input_entries (NOT input_changes!)
    WITH parent_e AS (
      SELECT rel_path, mac_key, file_sha256
      FROM coherence.input_entries
      WHERE input_version_id = NEW.parent_id
    ),
    child_e AS (
      SELECT rel_path, mac_key, file_sha256
      FROM coherence.input_entries
      WHERE input_version_id = NEW.id
    ),
    diff_entries AS (
      SELECT
        COALESCE(c.rel_path, p.rel_path) AS rel_path,
        COALESCE(c.mac_key, p.mac_key) AS mac_key,
        p.file_sha256 AS old_sha,
        c.file_sha256 AS new_sha
      FROM parent_e p
      FULL OUTER JOIN child_e c ON c.rel_path = p.rel_path
      WHERE p.file_sha256 IS DISTINCT FROM c.file_sha256
    )
    SELECT
      pg_catalog.count(*) FILTER (WHERE pg_catalog.split_part(mac_key, '/', 1) = 'sent'),
      pg_catalog.count(*) FILTER (WHERE pg_catalog.split_part(mac_key, '/', 1) IN ('overlay', 'approvals')),
      pg_catalog.count(*) FILTER (WHERE pg_catalog.split_part(mac_key, '/', 1) NOT IN ('sent', 'overlay', 'approvals'))
    INTO v_sent_diff, v_overlay_diff, v_other_diff
    FROM diff_entries;

    IF v_sent_diff > 0 AND NEW.source_kind NOT IN ('record_sent', 'mac_import', 'company_import') THEN
      RAISE EXCEPTION 'Sent/ entries can change only through recording a statement as sent or historical import (R9.5, DS-1)'
        USING ERRCODE = '23514';
    END IF;

    IF v_overlay_diff > 0 AND NEW.source_kind NOT IN ('carry_approvals', 'mac_import', 'company_import') THEN
      RAISE EXCEPTION 'Overlay/ entries can change only through carrying approvals or historical import (R9.5, DS-1)'
        USING ERRCODE = '23514';
    END IF;

    IF NEW.source_kind = 'record_sent' THEN
      SELECT * INTO v_carry
      FROM coherence.carries
      WHERE published_input_version_id = NEW.id AND carry_kind = 'sent' AND journal_seq = NEW.journal_seq;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'record_sent input_version % requires a matching sent carry in the same journal entry (R9.5)', NEW.id
          USING ERRCODE = '23514';
      END IF;
      v_expected_sent_path := 'Sent/statements_' || pg_catalog.to_char(v_carry.statement_date, 'YYYYMMDD') || '.csv';
      IF v_sent_diff <> 1 OR v_overlay_diff <> 0 OR v_other_diff <> 0 THEN
        RAISE EXCEPTION 'record_sent input_version % must change only Sent/statements_<date>.csv (R9.5)', NEW.id
          USING ERRCODE = '23514';
      END IF;
      IF EXISTS (
        SELECT 1 FROM coherence.input_entries
        WHERE input_version_id = NEW.parent_id AND mac_key = pg_catalog.lower(v_expected_sent_path)
      ) OR NOT EXISTS (
        SELECT 1 FROM coherence.input_entries
        WHERE input_version_id = NEW.id AND rel_path = v_expected_sent_path AND file_sha256 = v_carry.file_sha256
      ) THEN
        RAISE EXCEPTION 'record_sent input_version % must add % with the carried statement bytes', NEW.id, v_expected_sent_path
          USING ERRCODE = '23514';
      END IF;
    END IF;

    IF NEW.source_kind = 'carry_approvals' THEN
      SELECT * INTO v_carry
      FROM coherence.carries
      WHERE published_input_version_id = NEW.id AND carry_kind = 'approvals' AND journal_seq = NEW.journal_seq;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'carry_approvals input_version % requires a matching approvals carry in the same journal entry (R9.5)', NEW.id
          USING ERRCODE = '23514';
      END IF;
      IF v_overlay_diff <> 1 OR v_sent_diff <> 0 OR v_other_diff <> 0 THEN
        RAISE EXCEPTION 'carry_approvals input_version % must change only Overlay/overlay.csv (R9.5)', NEW.id
          USING ERRCODE = '23514';
      END IF;
      IF NOT EXISTS (
        SELECT 1 FROM coherence.input_entries
        WHERE input_version_id = NEW.id AND rel_path = 'Overlay/overlay.csv' AND file_sha256 = v_carry.file_sha256
      ) THEN
        RAISE EXCEPTION 'carry_approvals input_version % must set Overlay/overlay.csv to the carried approvals bytes', NEW.id
          USING ERRCODE = '23514';
      END IF;
    END IF;
  ELSE
    -- Root standing version without import cannot inject Sent/Overlay directly
    IF NEW.line_kind = 'standing' AND NEW.source_kind NOT IN ('mac_import', 'company_import') THEN
      IF EXISTS (
        SELECT 1 FROM coherence.input_entries
        WHERE input_version_id = NEW.id
          AND pg_catalog.split_part(mac_key, '/', 1) IN ('sent', 'overlay', 'approvals')
      ) THEN
        RAISE EXCEPTION 'Sent/ and Overlay/ cannot be created outside carry or historical import (R9.5, DS-1)'
          USING ERRCODE = '23514';
      END IF;
    END IF;
  END IF;

  -- For non-import standing versions, enforce strict Sent/ and no approvals/ folder under input/
  IF NEW.line_kind = 'standing' AND NEW.source_kind NOT IN ('mac_import', 'company_import') THEN
    SELECT pg_catalog.count(*)::integer INTO v_bad_sent
    FROM coherence.input_entries
    WHERE input_version_id = NEW.id
      AND (
        pg_catalog.split_part(mac_key, '/', 1) = 'approvals'
        OR (
          pg_catalog.split_part(mac_key, '/', 1) = 'sent'
          AND rel_path !~ '^Sent/(statements_[0-9]{8}\.csv|\.DS_Store)$'
        )
        OR (
          pg_catalog.split_part(mac_key, '/', 1) = 'overlay'
          AND rel_path NOT IN ('Overlay/overlay.csv', 'Overlay/.DS_Store')
        )
      );
    IF v_bad_sent > 0 THEN
      RAISE EXCEPTION 'standing input_version % contains an unauthorized file under Sent/, Overlay/, or approvals/ (DS-1)', NEW.id
        USING ERRCODE = '23514';
    END IF;
  END IF;

  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_input_versions_verify_deferred
  AFTER INSERT ON coherence.input_versions
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_input_versions_verify_deferred();

-- ============================================================================
-- E. Approvals files & rows (R5.5, R6.12, R6.13, R7.5, R9.3)
-- ============================================================================

CREATE OR REPLACE FUNCTION coherence.trg_approvals_files_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_parent coherence.approvals_files%ROWTYPE;
BEGIN
  IF NEW.extends_sha256 IS NOT NULL THEN
    SELECT * INTO v_parent FROM coherence.approvals_files WHERE file_sha256 = NEW.extends_sha256;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'parent approvals_file % does not exist', NEW.extends_sha256;
    END IF;
    IF NEW.shared_row_count <> v_parent.row_count THEN
      RAISE EXCEPTION 'approvals_file shared_row_count (%) must equal parent row_count (%) (R6.12)',
        NEW.shared_row_count, v_parent.row_count
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_approvals_files_before
  BEFORE INSERT ON coherence.approvals_files
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_approvals_files_before();

CREATE OR REPLACE FUNCTION coherence.trg_approval_rows_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_af coherence.approvals_files%ROWTYPE;
BEGIN
  SELECT * INTO v_af FROM coherence.approvals_files WHERE file_sha256 = NEW.approvals_file_sha256;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'approvals_file % does not exist', NEW.approvals_file_sha256;
  END IF;
  -- R9.3 & R18: no row can ever be added to a committed approvals file later
  IF v_af.journal_seq <> NEW.journal_seq THEN
    RAISE EXCEPTION 'cannot add approval_row to previously committed approvals_file % (R9.3)', NEW.approvals_file_sha256
      USING ERRCODE = '23514';
  END IF;
  IF NEW.row_no <= v_af.shared_row_count OR NEW.row_no > v_af.row_count THEN
    RAISE EXCEPTION 'approval_row row_no (%) out of range (%..%) for approvals_file %',
      NEW.row_no, v_af.shared_row_count + 1, v_af.row_count, NEW.approvals_file_sha256
      USING ERRCODE = '23514';
  END IF;
  IF v_af.header_kind = 'v1' AND (
    NEW.approved_amount IS NOT NULL OR NEW.approved_agency IS NOT NULL OR NEW.approved_agent IS NOT NULL
    OR NEW.approved_agency_from IS NOT NULL OR NEW.approved_agent_from IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'v1 approvals_file cannot carry approved_* fact columns (R5.5)'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_approval_rows_before
  BEFORE INSERT ON coherence.approval_rows
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_approval_rows_before();

CREATE OR REPLACE FUNCTION coherence.trg_approvals_files_verify_deferred()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_expected integer := NEW.row_count - NEW.shared_row_count;
  v_actual integer;
  v_min_no integer;
  v_max_no integer;
  v_hash text;
BEGIN
  SELECT pg_catalog.count(*)::integer, pg_catalog.min(row_no), pg_catalog.max(row_no)
  INTO v_actual, v_min_no, v_max_no
  FROM coherence.approval_rows
  WHERE approvals_file_sha256 = NEW.file_sha256;

  IF v_actual <> v_expected THEN
    RAISE EXCEPTION 'approvals_file % row count mismatch: expected % added rows, got % (R9.3)',
      NEW.file_sha256, v_expected, v_actual
      USING ERRCODE = '23514';
  END IF;

  IF v_expected > 0 AND (v_min_no <> NEW.shared_row_count + 1 OR v_max_no <> NEW.row_count) THEN
    RAISE EXCEPTION 'approvals_file % row numbers are not contiguous (%..%)',
      NEW.file_sha256, NEW.shared_row_count + 1, NEW.row_count
      USING ERRCODE = '23514';
  END IF;

  v_hash := coherence.hash_approval_rows(NEW.file_sha256);
  IF v_hash <> NEW.added_rows_sha256 THEN
    RAISE EXCEPTION 'approvals_file % added_rows_sha256 mismatch', NEW.file_sha256
      USING ERRCODE = '23514';
  END IF;

  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_approvals_files_verify_deferred
  AFTER INSERT ON coherence.approvals_files
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_approvals_files_verify_deferred();

-- ============================================================================
-- F. Runs, step requests, attempts, artifacts, cancel, review, emit, carry, abandon (R8, R9.4)
-- ============================================================================

-- Helper: check if a run has an open (un-ended) attempt
CREATE OR REPLACE FUNCTION coherence.run_has_open_attempt(p_run_id uuid)
RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM coherence.step_attempt_events s
    WHERE s.run_id = p_run_id
      AND s.event_kind = 'started'
      AND NOT EXISTS (
        SELECT 1 FROM coherence.step_attempt_events e
        WHERE e.run_id = s.run_id
          AND e.step = s.step
          AND e.attempt_no = s.attempt_no
          AND e.event_kind IN ('finished', 'failed', 'interrupted', 'cancelled')
      )
  );
$$;

-- Helper: check if ANY run in the company DB has an open attempt
CREATE OR REPLACE FUNCTION coherence.company_has_open_attempt()
RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM coherence.step_attempt_events s
    JOIN coherence.runs r ON r.id = s.run_id
    WHERE r.origin NOT IN ('mac_import', 'company_import')
      AND s.event_kind = 'started'
      AND NOT EXISTS (
        SELECT 1 FROM coherence.step_attempt_events e
        WHERE e.run_id = s.run_id
          AND e.step = s.step
          AND e.attempt_no = s.attempt_no
          AND e.event_kind IN ('finished', 'failed', 'interrupted', 'cancelled')
      )
  );
$$;

-- Helper: check if a run has an open (unanswered) step request
CREATE OR REPLACE FUNCTION coherence.run_has_open_request(p_run_id uuid)
RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM coherence.step_requests sr
    WHERE sr.run_id = p_run_id
      AND NOT EXISTS (
        SELECT 1 FROM coherence.step_attempt_events s
        WHERE s.step_request_id = sr.id AND s.event_kind = 'started'
      )
  );
$$;

-- Helper: current non-superseded finished attempt event id for (run, step)
CREATE OR REPLACE FUNCTION coherence.current_finished_attempt(p_run_id uuid, p_step text)
RETURNS uuid
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT e.id
  FROM coherence.step_attempt_events e
  WHERE e.run_id = p_run_id
    AND e.step = p_step
    AND e.event_kind = 'finished'
    AND NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events sup
      WHERE sup.run_id = e.run_id
        AND sup.step = e.step
        AND sup.attempt_no = e.attempt_no
        AND sup.event_kind = 'superseded'
    )
  ORDER BY e.attempt_no DESC
  LIMIT 1;
$$;

-- Runs BEFORE INSERT
CREATE OR REPLACE FUNCTION coherence.trg_runs_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_iv coherence.input_versions%ROWTYPE;
  v_overlay_sha text;
  v_replayed coherence.runs%ROWTYPE;
  v_expected_folder integer;
  v_sent_name text;
BEGIN
  SELECT * INTO v_iv FROM coherence.input_versions WHERE id = NEW.input_version_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'input_version % does not exist', NEW.input_version_id;
  END IF;

  -- R7.2: standing for app and trial; snapshot for imports and their replays
  IF NEW.origin IN ('app', 'trial') AND v_iv.line_kind <> 'standing' THEN
    RAISE EXCEPTION 'app and trial runs must use a standing input_version (R7.2)'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.origin IN ('mac_import', 'company_import', 'replay') AND v_iv.line_kind <> 'snapshot' THEN
    RAISE EXCEPTION 'import and replay runs must use a snapshot input_version (R7.2)'
      USING ERRCODE = '23514';
  END IF;

  -- R7.2: verify prior_approvals_sha256 matches Overlay/overlay.csv inside input_version
  SELECT file_sha256 INTO v_overlay_sha
  FROM coherence.input_entries
  WHERE input_version_id = NEW.input_version_id AND mac_key = 'overlay/overlay.csv';

  IF NEW.prior_approvals_sha256 IS DISTINCT FROM v_overlay_sha THEN
    RAISE EXCEPTION 'run prior_approvals_sha256 must match input_version Overlay/overlay.csv (R7.2)'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.origin = 'replay' THEN
    SELECT * INTO v_replayed FROM coherence.runs WHERE id = NEW.replays_run_id;
    IF NOT FOUND OR v_replayed.origin NOT IN ('mac_import', 'company_import') THEN
      RAISE EXCEPTION 'replay must reference an imported run (R6.7, R7.7)'
        USING ERRCODE = '23514';
    END IF;
    IF NEW.input_version_id <> v_replayed.input_version_id THEN
      RAISE EXCEPTION 'replay must use the replayed run''s frozen input_version'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  IF NEW.origin = 'app' THEN
    -- R8 launch guard: no sent statement for that date
    v_sent_name := 'sent/statements_' || pg_catalog.to_char(NEW.statement_date, 'YYYYMMDD') || '.csv';
    IF EXISTS (
      SELECT 1 FROM coherence.carries
      WHERE carry_kind = 'sent' AND statement_date = NEW.statement_date
    ) OR EXISTS (
      SELECT 1 FROM coherence.input_entries
      WHERE input_version_id = NEW.input_version_id AND mac_key = v_sent_name
    ) THEN
      RAISE EXCEPTION 'cannot launch app run for %: a sent statement already exists for that date (R8)', NEW.statement_date
        USING ERRCODE = '23514';
    END IF;

    -- R8 launch guard: no non-abandoned app run of this date may exist (a finished run with no carries must be abandoned first)
    IF EXISTS (
      SELECT 1 FROM coherence.runs r
      WHERE r.origin = 'app'
        AND r.statement_date = NEW.statement_date
        AND NOT EXISTS (SELECT 1 FROM coherence.abandonments a WHERE a.run_id = r.id)
    ) THEN
      RAISE EXCEPTION 'cannot launch app run for %: a non-abandoned run for that date already exists (R8)', NEW.statement_date
        USING ERRCODE = '23514';
    END IF;

    SELECT COALESCE(pg_catalog.max(folder_number), 0) + 1 INTO v_expected_folder
    FROM coherence.runs
    WHERE origin = 'app' AND statement_date = NEW.statement_date;
    IF NEW.folder_number <> v_expected_folder THEN
      RAISE EXCEPTION 'app run folder_number for % must be % (got %)', NEW.statement_date, v_expected_folder, NEW.folder_number
        USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.origin = 'trial' THEN
    IF EXISTS (
      SELECT 1 FROM coherence.runs r
      WHERE r.origin = 'trial'
        AND r.statement_date = NEW.statement_date
        AND NOT EXISTS (SELECT 1 FROM coherence.abandonments a WHERE a.run_id = r.id)
    ) THEN
      RAISE EXCEPTION 'cannot launch trial run for %: a non-abandoned trial run for that date already exists', NEW.statement_date
        USING ERRCODE = '23514';
    END IF;
    SELECT COALESCE(pg_catalog.max(folder_number), 0) + 1 INTO v_expected_folder
    FROM coherence.runs
    WHERE origin = 'trial' AND statement_date = NEW.statement_date;
    IF NEW.folder_number <> v_expected_folder THEN
      RAISE EXCEPTION 'trial run folder_number for % must be % (got %)', NEW.statement_date, v_expected_folder, NEW.folder_number
        USING ERRCODE = '23514';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_runs_before
  BEFORE INSERT ON coherence.runs
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_runs_before();

-- Runs DEFERRED: non-import runs must create their initial launch assign request in the same tx
CREATE OR REPLACE FUNCTION coherence.trg_runs_verify_deferred()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.origin IN ('app', 'trial', 'replay') THEN
    IF NOT EXISTS (
      SELECT 1 FROM coherence.step_requests
      WHERE run_id = NEW.id AND step = 'assign' AND reason = 'launch' AND journal_seq = NEW.journal_seq
    ) THEN
      RAISE EXCEPTION 'launching run % must request assign in the same journal entry (R8)', NEW.id
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_runs_verify_deferred
  AFTER INSERT ON coherence.runs
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_runs_verify_deferred();

-- Step requests BEFORE INSERT (R8, R9.4)
CREATE OR REPLACE FUNCTION coherence.trg_step_requests_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_run coherence.runs%ROWTYPE;
  v_pred_step text;
  v_pred_finished uuid;
  v_bible_finished uuid;
  v_adjust_finished uuid;
  v_latest_adjust_save uuid;
  v_confirm coherence.emit_confirmations%ROWTYPE;
  v_last_end text;
BEGIN
  SELECT * INTO v_run FROM coherence.runs WHERE id = NEW.run_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'run % does not exist', NEW.run_id;
  END IF;
  IF v_run.origin IN ('mac_import', 'company_import') THEN
    RAISE EXCEPTION 'cannot request steps on an imported run';
  END IF;
  IF EXISTS (SELECT 1 FROM coherence.abandonments WHERE run_id = NEW.run_id) THEN
    RAISE EXCEPTION 'cannot request step on abandoned run % (R9.4)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;

  -- R9.4: one open request per run, and no open attempt
  IF coherence.run_has_open_request(NEW.run_id) THEN
    RAISE EXCEPTION 'run % already has an open step request (R9.4)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF coherence.run_has_open_attempt(NEW.run_id) THEN
    RAISE EXCEPTION 'run % already has an open step attempt (R9.4)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.reason = 'launch' THEN
    IF v_run.journal_seq <> NEW.journal_seq THEN
      RAISE EXCEPTION 'launch step_request must be created in the same journal entry as its run';
    END IF;
    IF EXISTS (SELECT 1 FROM coherence.step_requests WHERE run_id = NEW.run_id) THEN
      RAISE EXCEPTION 'launch request can only be the first request of a run';
    END IF;
  ELSIF NEW.reason = 'continue' THEN
    v_pred_step := CASE NEW.step WHEN 'attribute' THEN 'assign' WHEN 'bible' THEN 'attribute' ELSE NULL END;
    v_pred_finished := coherence.current_finished_attempt(NEW.run_id, v_pred_step);
    IF v_pred_finished IS NULL THEN
      RAISE EXCEPTION 'cannot continue to %: predecessor % is not finished (R8)', NEW.step, v_pred_step
        USING ERRCODE = '23514';
    END IF;
    IF coherence.current_finished_attempt(NEW.run_id, NEW.step) IS NOT NULL THEN
      RAISE EXCEPTION 'cannot continue to %: step is already finished', NEW.step
        USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.reason = 'bible_saved' THEN
    v_bible_finished := coherence.current_finished_attempt(NEW.run_id, 'bible');
    IF v_bible_finished IS NULL THEN
      RAISE EXCEPTION 'bible_saved request requires a finished bible attempt (R8)';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM coherence.review_saves
      WHERE run_id = NEW.run_id AND surface = 'bible' AND attempt_event_id = v_bible_finished
        AND journal_seq = NEW.journal_seq
    ) THEN
      RAISE EXCEPTION 'bible_saved request must accompany a Bible review save in the same journal entry (R8)'
        USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.reason = 'emit_confirmed' THEN
    SELECT * INTO v_confirm FROM coherence.emit_confirmations WHERE id = NEW.emit_confirmation_id;
    IF NOT FOUND OR v_confirm.run_id <> NEW.run_id OR v_confirm.journal_seq <> NEW.journal_seq THEN
      RAISE EXCEPTION 'emit_confirmed request must reference an emit_confirmation created in the same journal entry (R8)'
        USING ERRCODE = '23514';
    END IF;
    IF EXISTS (SELECT 1 FROM coherence.review_submissions WHERE run_id = NEW.run_id AND status = 'pending') THEN
      RAISE EXCEPTION 'cannot request emit while a review submission is waiting (R8)'
        USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.reason = 'retry' THEN
    -- Must be retrying a step that ended in failed, interrupted, or cancelled
    SELECT e.event_kind INTO v_last_end
    FROM coherence.step_attempt_events e
    WHERE e.run_id = NEW.run_id
      AND e.step = NEW.step
      AND e.event_kind IN ('finished', 'failed', 'interrupted', 'cancelled')
      AND NOT EXISTS (
        SELECT 1 FROM coherence.step_attempt_events sup
        WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no AND sup.event_kind = 'superseded'
      )
    ORDER BY e.attempt_no DESC
    LIMIT 1;
    IF v_last_end IS NULL OR v_last_end = 'finished' THEN
      RAISE EXCEPTION 'retry requires a non-superseded failed, interrupted, or cancelled attempt of % (R8)', NEW.step
        USING ERRCODE = '23514';
    END IF;
    -- All attempts of later steps must be superseded first
    IF EXISTS (
      SELECT 1 FROM coherence.step_attempt_events e
      WHERE e.run_id = NEW.run_id
        AND coherence.step_rank(e.step) > coherence.step_rank(NEW.step)
        AND e.event_kind = 'started'
        AND NOT EXISTS (
          SELECT 1 FROM coherence.step_attempt_events sup
          WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no AND sup.event_kind = 'superseded'
        )
    ) THEN
      RAISE EXCEPTION 'cannot retry % while later step attempts are not superseded (R8)', NEW.step
        USING ERRCODE = '23514';
    END IF;
    -- Predecessor must be finished
    IF NEW.step <> 'assign' THEN
      v_pred_step := CASE NEW.step
        WHEN 'attribute' THEN 'assign'
        WHEN 'bible' THEN 'attribute'
        WHEN 'adjust' THEN 'bible'
        WHEN 'emit' THEN 'adjust'
      END;
      IF coherence.current_finished_attempt(NEW.run_id, v_pred_step) IS NULL THEN
        RAISE EXCEPTION 'cannot retry %: predecessor % is not finished', NEW.step, v_pred_step
          USING ERRCODE = '23514';
      END IF;
    END IF;
    IF NEW.step = 'adjust' THEN
      v_bible_finished := coherence.current_finished_attempt(NEW.run_id, 'bible');
      IF NOT EXISTS (
        SELECT 1 FROM coherence.review_saves
        WHERE run_id = NEW.run_id AND surface = 'bible' AND attempt_event_id = v_bible_finished
      ) THEN
        RAISE EXCEPTION 'cannot retry adjust without a Bible review save (R8)';
      END IF;
    END IF;
    IF NEW.step = 'emit' THEN
      v_adjust_finished := coherence.current_finished_attempt(NEW.run_id, 'adjust');
      SELECT id INTO v_latest_adjust_save
      FROM coherence.review_saves
      WHERE run_id = NEW.run_id AND surface = 'adjust' AND attempt_event_id = v_adjust_finished
      ORDER BY journal_seq DESC
      LIMIT 1;
      SELECT * INTO v_confirm FROM coherence.emit_confirmations WHERE id = NEW.emit_confirmation_id;
      IF NOT FOUND OR v_confirm.run_id <> NEW.run_id OR v_confirm.adjust_review_save_id IS DISTINCT FROM v_latest_adjust_save THEN
        RAISE EXCEPTION 'Emit retry must keep the valid confirmation bound to the newest Adjust save (R6.8, R8, R9.4)'
          USING ERRCODE = '23514';
      END IF;
      IF EXISTS (SELECT 1 FROM coherence.review_submissions WHERE run_id = NEW.run_id AND status = 'pending') THEN
        RAISE EXCEPTION 'cannot retry emit while a review submission is waiting (R8)'
          USING ERRCODE = '23514';
      END IF;
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_step_requests_before
  BEFORE INSERT ON coherence.step_requests
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_step_requests_before();

-- Cancel requests BEFORE INSERT (R6.9, R8)
CREATE OR REPLACE FUNCTION coherence.trg_cancel_requests_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_run coherence.runs%ROWTYPE;
  v_expected_phrase text;
BEGIN
  SELECT * INTO v_run FROM coherence.runs WHERE id = NEW.run_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'run % does not exist', NEW.run_id;
  END IF;
  IF EXISTS (SELECT 1 FROM coherence.abandonments WHERE run_id = NEW.run_id) THEN
    RAISE EXCEPTION 'cannot cancel abandoned run %', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  v_expected_phrase := 'cancel ' || pg_catalog.to_char(v_run.statement_date, 'YYYY-MM-DD');
  IF NEW.typed_phrase <> v_expected_phrase THEN
    RAISE EXCEPTION 'cancel typed_phrase must be "%"', v_expected_phrase
      USING ERRCODE = '23514';
  END IF;
  -- Must target an open attempt
  IF NOT EXISTS (
    SELECT 1 FROM coherence.step_attempt_events s
    WHERE s.run_id = NEW.run_id AND s.step = NEW.step AND s.attempt_no = NEW.attempt_no AND s.event_kind = 'started'
      AND NOT EXISTS (
        SELECT 1 FROM coherence.step_attempt_events e
        WHERE e.run_id = s.run_id AND e.step = s.step AND e.attempt_no = s.attempt_no
          AND e.event_kind IN ('finished', 'failed', 'interrupted', 'cancelled')
      )
  ) THEN
    RAISE EXCEPTION 'cancel request requires an open attempt for (%, %, %) (R8)', NEW.run_id, NEW.step, NEW.attempt_no
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_cancel_requests_before
  BEFORE INSERT ON coherence.cancel_requests
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_cancel_requests_before();

-- Step attempt events BEFORE INSERT (R8, R9.4, R9.6, R10.1, R10.2)
CREATE OR REPLACE FUNCTION coherence.trg_step_attempt_events_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_run coherence.runs%ROWTYPE;
  v_req coherence.step_requests%ROWTYPE;
  v_start coherence.step_attempt_events%ROWTYPE;
  v_cancel coherence.cancel_requests%ROWTYPE;
  v_expected_attempt integer;
  v_pred_step text;
  v_own_start timestamptz;
  v_adjust_finished uuid;
  v_latest_adjust_save uuid;
  v_confirm coherence.emit_confirmations%ROWTYPE;
BEGIN
  SELECT * INTO v_run FROM coherence.runs WHERE id = NEW.run_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'run % does not exist', NEW.run_id;
  END IF;

  IF EXISTS (SELECT 1 FROM coherence.abandonments WHERE run_id = NEW.run_id) THEN
    RAISE EXCEPTION 'cannot record step attempt event on abandoned run % (R9.4)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;

  -- Historical imports record started + finished directly in the import journal entry without holding the worker slot.
  IF v_run.origin IN ('mac_import', 'company_import') THEN
    IF NEW.event_kind NOT IN ('started', 'finished') OR NEW.step_request_id IS NOT NULL THEN
      RAISE EXCEPTION 'imported runs only accept started/finished events with no step_request';
    END IF;
    IF NEW.journal_seq <> v_run.journal_seq THEN
      RAISE EXCEPTION 'imported run steps must be recorded in the run''s import journal entry';
    END IF;
    RETURN NEW;
  END IF;

  v_own_start := coherence.own_backend_start();

  IF NEW.event_kind = 'started' THEN
    -- Must hold company running slot (R8, R9.6)
    IF NOT coherence.this_connection_holds_slot() THEN
      RAISE EXCEPTION 'starting a step attempt requires holding the company running slot (R8, R9.6)'
        USING ERRCODE = '55000';
    END IF;
    -- No dead/open attempt may exist anywhere before anything else runs (R10.1)
    IF coherence.company_has_open_attempt() THEN
      RAISE EXCEPTION 'another open attempt exists; reconcile interrupted attempts before starting (R10.1)'
        USING ERRCODE = '23514';
    END IF;
    -- Record/verify exact slot backend identity (prevents PID reuse and lost-slot finishes)
    IF NEW.slot_backend_pid IS NULL THEN
      NEW.slot_backend_pid := pg_catalog.pg_backend_pid();
    ELSIF NEW.slot_backend_pid <> pg_catalog.pg_backend_pid() THEN
      RAISE EXCEPTION 'slot_backend_pid must match current PostgreSQL backend pid';
    END IF;
    IF NEW.slot_backend_start IS NULL THEN
      NEW.slot_backend_start := v_own_start;
    ELSIF NEW.slot_backend_start <> v_own_start THEN
      RAISE EXCEPTION 'slot_backend_start must match current PostgreSQL backend start';
    END IF;

    -- Must answer an open step_request for this run and step
    IF NEW.step_request_id IS NULL THEN
      RAISE EXCEPTION 'started event requires step_request_id (R6.10, R8)';
    END IF;
    SELECT * INTO v_req FROM coherence.step_requests WHERE id = NEW.step_request_id;
    IF NOT FOUND OR v_req.run_id <> NEW.run_id OR v_req.step <> NEW.step THEN
      RAISE EXCEPTION 'step_request % does not match (%, %) (R8)', NEW.step_request_id, NEW.run_id, NEW.step
        USING ERRCODE = '23514';
    END IF;
    IF EXISTS (SELECT 1 FROM coherence.step_attempt_events WHERE step_request_id = NEW.step_request_id) THEN
      RAISE EXCEPTION 'step_request % was already answered (R7.4)', NEW.step_request_id
        USING ERRCODE = '23514';
    END IF;

    -- Attempts numbered strictly in order (R8)
    SELECT COALESCE(pg_catalog.max(attempt_no), 0) + 1 INTO v_expected_attempt
    FROM coherence.step_attempt_events
    WHERE run_id = NEW.run_id AND step = NEW.step AND event_kind = 'started';
    IF NEW.attempt_no <> v_expected_attempt THEN
      RAISE EXCEPTION 'attempt_no for (%, %) must be % (got %) (R8)', NEW.run_id, NEW.step, v_expected_attempt, NEW.attempt_no
        USING ERRCODE = '23514';
    END IF;

    -- Predecessor must be finished (R8)
    IF NEW.step <> 'assign' THEN
      v_pred_step := CASE NEW.step
        WHEN 'attribute' THEN 'assign'
        WHEN 'bible' THEN 'attribute'
        WHEN 'adjust' THEN 'bible'
        WHEN 'emit' THEN 'adjust'
      END;
      IF coherence.current_finished_attempt(NEW.run_id, v_pred_step) IS NULL THEN
        RAISE EXCEPTION 'cannot start %: predecessor % is not finished (R8)', NEW.step, v_pred_step
          USING ERRCODE = '23514';
      END IF;
    END IF;

    -- Emit confirmation binding re-checked at start
    IF NEW.step = 'emit' THEN
      v_adjust_finished := coherence.current_finished_attempt(NEW.run_id, 'adjust');
      SELECT id INTO v_latest_adjust_save
      FROM coherence.review_saves
      WHERE run_id = NEW.run_id AND surface = 'adjust' AND attempt_event_id = v_adjust_finished
      ORDER BY journal_seq DESC
      LIMIT 1;
      SELECT * INTO v_confirm FROM coherence.emit_confirmations WHERE id = v_req.emit_confirmation_id;
      IF NOT FOUND OR v_confirm.adjust_review_save_id IS DISTINCT FROM v_latest_adjust_save THEN
        RAISE EXCEPTION 'cannot start emit: confirmation no longer matches newest Adjust save (R9.4)'
          USING ERRCODE = '23514';
      END IF;
      IF EXISTS (SELECT 1 FROM coherence.review_submissions WHERE run_id = NEW.run_id AND status = 'pending') THEN
        RAISE EXCEPTION 'cannot start emit while a review submission is waiting (R8)'
          USING ERRCODE = '23514';
      END IF;
    END IF;

  ELSIF NEW.event_kind IN ('finished', 'failed', 'cancelled') THEN
    SELECT * INTO v_start
    FROM coherence.step_attempt_events
    WHERE run_id = NEW.run_id AND step = NEW.step AND attempt_no = NEW.attempt_no AND event_kind = 'started';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'cannot end unstarted attempt (%, %, %)', NEW.run_id, NEW.step, NEW.attempt_no
        USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
      SELECT 1 FROM coherence.step_attempt_events
      WHERE run_id = NEW.run_id AND step = NEW.step AND attempt_no = NEW.attempt_no
        AND event_kind IN ('finished', 'failed', 'interrupted', 'cancelled')
    ) THEN
      RAISE EXCEPTION 'attempt (%, %, %) already ended (R8)', NEW.run_id, NEW.step, NEW.attempt_no
        USING ERRCODE = '23514';
    END IF;
    -- R8 & R10.2: must still hold the slot on the SAME connection that started the attempt
    IF NOT coherence.this_connection_holds_slot()
       OR pg_catalog.pg_backend_pid() <> v_start.slot_backend_pid
       OR v_own_start <> v_start.slot_backend_start THEN
      RAISE EXCEPTION 'attempt end (%) must be recorded on the slot connection that started it (R8, R10.2)', NEW.event_kind
        USING ERRCODE = '55000';
    END IF;
    IF NEW.event_kind = 'cancelled' AND NEW.cancel_request_id IS NOT NULL THEN
      SELECT * INTO v_cancel FROM coherence.cancel_requests WHERE id = NEW.cancel_request_id;
      IF NOT FOUND OR v_cancel.run_id <> NEW.run_id OR v_cancel.step <> NEW.step OR v_cancel.attempt_no <> NEW.attempt_no THEN
        RAISE EXCEPTION 'cancel_request % does not match attempt (%, %, %)', NEW.cancel_request_id, NEW.run_id, NEW.step, NEW.attempt_no
          USING ERRCODE = '23514';
      END IF;
    END IF;

  ELSIF NEW.event_kind = 'interrupted' THEN
    SELECT * INTO v_start
    FROM coherence.step_attempt_events
    WHERE run_id = NEW.run_id AND step = NEW.step AND attempt_no = NEW.attempt_no AND event_kind = 'started';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'cannot mark unstarted attempt (%, %, %) interrupted', NEW.run_id, NEW.step, NEW.attempt_no
        USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
      SELECT 1 FROM coherence.step_attempt_events
      WHERE run_id = NEW.run_id AND step = NEW.step AND attempt_no = NEW.attempt_no
        AND event_kind IN ('finished', 'failed', 'interrupted', 'cancelled')
    ) THEN
      RAISE EXCEPTION 'attempt (%, %, %) already ended (R8)', NEW.run_id, NEW.step, NEW.attempt_no
        USING ERRCODE = '23514';
    END IF;
    -- R8 & R10.1: allowed only when slot is free OR held by a different backend than the one that started the attempt
    IF NOT (
      coherence.slot_is_free()
      OR (
        coherence.this_connection_holds_slot()
        AND (pg_catalog.pg_backend_pid() <> v_start.slot_backend_pid OR v_own_start <> v_start.slot_backend_start)
      )
    ) THEN
      RAISE EXCEPTION 'cannot mark attempt interrupted while its owning worker still holds the slot (R8, R10.1)'
        USING ERRCODE = '55000';
    END IF;

  ELSIF NEW.event_kind = 'superseded' THEN
    -- R6.10: superseded only AFTER an end
    IF NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events
      WHERE run_id = NEW.run_id AND step = NEW.step AND attempt_no = NEW.attempt_no
        AND event_kind IN ('finished', 'failed', 'interrupted', 'cancelled')
    ) THEN
      RAISE EXCEPTION 'cannot supersede an attempt before it has ended (R6.10)'
        USING ERRCODE = '23514';
    END IF;
    IF NEW.step = 'emit' AND EXISTS (SELECT 1 FROM coherence.carries WHERE run_id = NEW.run_id) THEN
      RAISE EXCEPTION 'cannot supersede an Emit attempt after its outputs were carried';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_step_attempt_events_before
  BEFORE INSERT ON coherence.step_attempt_events
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_step_attempt_events_before();

-- Artifacts BEFORE INSERT (R6.11, R9.3, R9.7)
CREATE OR REPLACE FUNCTION coherence.trg_artifacts_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_ev coherence.step_attempt_events%ROWTYPE;
BEGIN
  SELECT * INTO v_ev FROM coherence.step_attempt_events WHERE id = NEW.attempt_event_id;
  IF NOT FOUND OR v_ev.event_kind <> 'finished' OR v_ev.journal_seq <> NEW.journal_seq THEN
    RAISE EXCEPTION 'artifacts must belong to a finished step_attempt_event in the same journal entry (R9.3)'
      USING ERRCODE = '23514';
  END IF;
  -- R6.11 & R9.7: code-bearing files MUST be classified code_bearing and stored ONLY in nusear_code
  IF coherence.is_code_bearing_path(NEW.rel_path) AND NEW.artifact_kind <> 'code_bearing' THEN
    RAISE EXCEPTION 'code-bearing artifact % must have artifact_kind = code_bearing and live in nusear_code store (R6.11, R9.7)', NEW.rel_path
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_artifacts_before
  BEFORE INSERT ON coherence.artifacts
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_artifacts_before();

-- Step attempt events DEFERRED: verify artifact count & hash on finished events
CREATE OR REPLACE FUNCTION coherence.trg_step_attempt_events_verify_deferred()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_cnt integer;
  v_hash text;
BEGIN
  IF NEW.event_kind = 'finished' THEN
    SELECT pg_catalog.count(*)::integer INTO v_cnt
    FROM coherence.artifacts
    WHERE attempt_event_id = NEW.id;
    IF v_cnt <> NEW.artifact_count THEN
      RAISE EXCEPTION 'finished attempt % artifact_count mismatch: declared %, actual % (R9.3)', NEW.id, NEW.artifact_count, v_cnt
        USING ERRCODE = '23514';
    END IF;
    v_hash := coherence.hash_artifacts(NEW.id);
    IF v_hash <> NEW.artifacts_sha256 THEN
      RAISE EXCEPTION 'finished attempt % artifacts_sha256 mismatch (R9.3)', NEW.id
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_step_attempt_events_verify_deferred
  AFTER INSERT ON coherence.step_attempt_events
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_step_attempt_events_verify_deferred();

-- Review submissions operational guards (R6.15, R8, R10.7, CR-1)
CREATE OR REPLACE FUNCTION coherence.trg_review_submissions_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_run coherence.runs%ROWTYPE;
  v_surface_attempt uuid;
  v_adjust_attempt uuid;
BEGIN
  IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'review_submissions cannot be deleted or truncated'
      USING ERRCODE = '55000';
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF pg_catalog.current_setting('transaction_isolation') <> 'serializable' THEN
      RAISE EXCEPTION 'review_submissions insert requires SERIALIZABLE isolation'
        USING ERRCODE = '25001';
    END IF;
    IF NEW.status <> 'pending' THEN
      RAISE EXCEPTION 'new review_submission must start in pending status';
    END IF;
    SELECT * INTO v_run FROM coherence.runs WHERE id = NEW.run_id;
    IF NOT FOUND OR v_run.origin IN ('mac_import', 'company_import') THEN
      RAISE EXCEPTION 'cannot submit review for missing or imported run';
    END IF;
    IF EXISTS (SELECT 1 FROM coherence.abandonments WHERE run_id = NEW.run_id) THEN
      RAISE EXCEPTION 'cannot submit review for abandoned run % (R9.4)', NEW.run_id
        USING ERRCODE = '23514';
    END IF;
    IF coherence.run_has_open_attempt(NEW.run_id) OR coherence.run_has_open_request(NEW.run_id) THEN
      RAISE EXCEPTION 'cannot submit review while run % has an open request or running step (R8)', NEW.run_id
        USING ERRCODE = '23514';
    END IF;
    IF coherence.current_finished_attempt(NEW.run_id, 'emit') IS NOT NULL THEN
      RAISE EXCEPTION 'cannot submit review after Emit has finished (R8)'
        USING ERRCODE = '23514';
    END IF;
    v_surface_attempt := coherence.current_finished_attempt(NEW.run_id, NEW.surface);
    IF v_surface_attempt IS NULL THEN
      RAISE EXCEPTION 'cannot submit % review: step % has not finished (R8)', NEW.surface, NEW.surface
        USING ERRCODE = '23514';
    END IF;
    IF NEW.surface = 'bible' THEN
      v_adjust_attempt := coherence.current_finished_attempt(NEW.run_id, 'adjust');
      IF v_adjust_attempt IS NOT NULL AND EXISTS (
        SELECT 1 FROM coherence.review_saves
        WHERE run_id = NEW.run_id AND surface = 'adjust' AND attempt_event_id = v_adjust_attempt
      ) THEN
        RAISE EXCEPTION 'cannot submit Bible review after an Adjust review was saved for Adjust''s current attempt (R8, CR-8)'
          USING ERRCODE = '23514';
      END IF;
    ELSIF NEW.surface = 'adjust' THEN
      IF EXISTS (
        SELECT 1 FROM coherence.emit_confirmations ec
        JOIN coherence.review_saves rs ON rs.id = ec.adjust_review_save_id
        WHERE ec.run_id = NEW.run_id AND rs.attempt_event_id = v_surface_attempt
      ) THEN
        RAISE EXCEPTION 'cannot submit Adjust review after Emit has been confirmed for Adjust''s current attempt (R8, CR-1)'
          USING ERRCODE = '23514';
      END IF;
    END IF;
    RETURN NEW;
  END IF;

  -- TG_OP = 'UPDATE'
  IF pg_catalog.current_setting('transaction_isolation') <> 'serializable' THEN
    RAISE EXCEPTION 'review_submissions resolution requires SERIALIZABLE isolation'
      USING ERRCODE = '25001';
  END IF;
  IF OLD.status <> 'pending' THEN
    RAISE EXCEPTION 'review_submission % is already finalized (%) and cannot change', OLD.id, OLD.status
      USING ERRCODE = '55000';
  END IF;
  IF NEW.status NOT IN ('accepted', 'rejected', 'failed') THEN
    RAISE EXCEPTION 'review_submission must transition from pending to accepted, rejected, or failed';
  END IF;
  IF NEW.id <> OLD.id OR NEW.run_id <> OLD.run_id OR NEW.surface <> OLD.surface
     OR NEW.staged_sha256 <> OLD.staged_sha256 OR NEW.staged_object_name <> OLD.staged_object_name
     OR NEW.expected_journal_seq <> OLD.expected_journal_seq
     OR NEW.actor <> OLD.actor OR NEW.acting_for IS DISTINCT FROM OLD.acting_for
     OR NEW.command_key <> OLD.command_key OR NEW.request_sha256 <> OLD.request_sha256
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'immutable columns of review_submissions cannot be modified'
      USING ERRCODE = '55000';
  END IF;
  IF NOT coherence.this_connection_holds_slot() THEN
    RAISE EXCEPTION 'only the worker holding the company running slot may resolve review_submissions (R4.6, R10.7)'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.status = 'accepted' THEN
    IF NOT EXISTS (
      SELECT 1 FROM coherence.review_saves rs
      JOIN coherence.journal_entries je ON je.seq = rs.journal_seq
      WHERE rs.id = NEW.review_save_id
        AND rs.journal_seq = NEW.result_journal_seq
        AND je.created_xid = pg_catalog.pg_current_xact_id()
    ) THEN
      RAISE EXCEPTION 'accepted review_submission must be resolved in the same transaction as its review_save (R10.7)'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_review_submissions_guard
  BEFORE INSERT OR UPDATE OR DELETE ON coherence.review_submissions
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_review_submissions_guard();
ALTER TABLE coherence.review_submissions ENABLE ALWAYS TRIGGER trg_review_submissions_guard;

CREATE TRIGGER trg_review_submissions_no_trunc
  BEFORE TRUNCATE ON coherence.review_submissions
  FOR EACH STATEMENT EXECUTE FUNCTION coherence.forbid_mutation();
ALTER TABLE coherence.review_submissions ENABLE ALWAYS TRIGGER trg_review_submissions_no_trunc;

-- Review saves BEFORE INSERT (R5.5, R6.14, R8, R9.4, CR-1, CR-8)
CREATE OR REPLACE FUNCTION coherence.trg_review_saves_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_run coherence.runs%ROWTYPE;
  v_ev coherence.step_attempt_events%ROWTYPE;
  v_current_surface uuid;
  v_current_adjust uuid;
  v_current_bible uuid;
  v_bible_save_sha text;
BEGIN
  SELECT * INTO v_run FROM coherence.runs WHERE id = NEW.run_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'run % does not exist', NEW.run_id;
  END IF;

  SELECT * INTO v_ev FROM coherence.step_attempt_events WHERE id = NEW.attempt_event_id;
  IF NOT FOUND OR v_ev.run_id <> NEW.run_id OR v_ev.step <> NEW.surface OR v_ev.event_kind <> 'finished' THEN
    RAISE EXCEPTION 'review_save must reference a finished % attempt of run %', NEW.surface, NEW.run_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.imported THEN
    IF v_run.origin NOT IN ('mac_import', 'company_import') THEN
      RAISE EXCEPTION 'imported review_save is only allowed for imported runs';
    END IF;
    RETURN NEW;
  END IF;

  IF v_run.origin IN ('mac_import', 'company_import') THEN
    RAISE EXCEPTION 'live review_save cannot target an imported run';
  END IF;
  IF EXISTS (SELECT 1 FROM coherence.abandonments WHERE run_id = NEW.run_id) THEN
    RAISE EXCEPTION 'cannot save review on abandoned run % (R9.4)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF coherence.run_has_open_request(NEW.run_id) OR coherence.run_has_open_attempt(NEW.run_id) THEN
    RAISE EXCEPTION 'cannot save review while run % has an open request or running step (R8)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF coherence.current_finished_attempt(NEW.run_id, 'emit') IS NOT NULL THEN
    RAISE EXCEPTION 'cannot save review after Emit finished (R8)'
      USING ERRCODE = '23514';
  END IF;

  v_current_surface := coherence.current_finished_attempt(NEW.run_id, NEW.surface);
  IF v_current_surface IS DISTINCT FROM NEW.attempt_event_id THEN
    RAISE EXCEPTION 'review_save must review the current non-superseded finished % attempt (R8)', NEW.surface
      USING ERRCODE = '23514';
  END IF;

  -- Must extend frozen prior approvals (R5.5)
  IF v_run.prior_approvals_sha256 IS NOT NULL
     AND NOT coherence.approvals_extends(NEW.approvals_file_sha256, v_run.prior_approvals_sha256) THEN
    RAISE EXCEPTION 'saved approvals file does not extend the run''s frozen prior approvals (R5.5)'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.surface = 'bible' THEN
    -- R8 & CR-8: allowed in waiting for Bible, or waiting for Adjust with NO Adjust save for Adjust's current attempt
    v_current_adjust := coherence.current_finished_attempt(NEW.run_id, 'adjust');
    IF v_current_adjust IS NOT NULL AND EXISTS (
      SELECT 1 FROM coherence.review_saves
      WHERE run_id = NEW.run_id AND surface = 'adjust' AND attempt_event_id = v_current_adjust
    ) THEN
      RAISE EXCEPTION 'Bible review cannot be re-saved after an Adjust review was saved for Adjust''s current attempt (R8, CR-8)'
        USING ERRCODE = '23514';
    END IF;
    -- Also refuse if Adjust has a non-superseded failed/interrupted/cancelled attempt (must retry or be waiting for Adjust)
    IF EXISTS (
      SELECT 1 FROM coherence.step_attempt_events e
      WHERE e.run_id = NEW.run_id AND e.step = 'adjust'
        AND e.event_kind IN ('failed', 'interrupted', 'cancelled')
        AND NOT EXISTS (
          SELECT 1 FROM coherence.step_attempt_events sup
          WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no AND sup.event_kind = 'superseded'
        )
    ) THEN
      RAISE EXCEPTION 'cannot save Bible review while Adjust has an un-superseded failed/interrupted/cancelled attempt (R8)'
        USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.surface = 'adjust' THEN
    -- R8 & CR-1: no Emit confirmed for Adjust's current attempt
    IF EXISTS (
      SELECT 1 FROM coherence.emit_confirmations ec
      JOIN coherence.review_saves rs ON rs.id = ec.adjust_review_save_id
      WHERE ec.run_id = NEW.run_id AND rs.attempt_event_id = NEW.attempt_event_id
    ) THEN
      RAISE EXCEPTION 'Adjust review cannot be saved after Emit is confirmed for Adjust''s current attempt (R8, CR-1)'
        USING ERRCODE = '23514';
    END IF;
    -- R5.5 & R8: must begin with this run's Bible review
    v_current_bible := coherence.current_finished_attempt(NEW.run_id, 'bible');
    SELECT approvals_file_sha256 INTO v_bible_save_sha
    FROM coherence.review_saves
    WHERE run_id = NEW.run_id AND surface = 'bible' AND attempt_event_id = v_current_bible
    ORDER BY journal_seq DESC
    LIMIT 1;
    IF v_bible_save_sha IS NULL THEN
      RAISE EXCEPTION 'Adjust review requires a saved Bible review first (R8)'
        USING ERRCODE = '23514';
    END IF;
    IF NOT coherence.approvals_extends(NEW.approvals_file_sha256, v_bible_save_sha) THEN
      RAISE EXCEPTION 'Adjust approvals file must extend this run''s Bible review (R5.5, R8)'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_review_saves_before
  BEFORE INSERT ON coherence.review_saves
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_review_saves_before();

-- Delete review draft automatically on save (R6.16)
CREATE OR REPLACE FUNCTION coherence.trg_review_saves_after_delete_draft()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  DELETE FROM coherence.review_drafts
  WHERE run_id = NEW.run_id AND surface = NEW.surface;
  RETURN NULL;
END;
$$;

CREATE TRIGGER trg_03_review_saves_delete_draft
  AFTER INSERT ON coherence.review_saves
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_review_saves_after_delete_draft();

-- Deferred Bible review save check: prior Adjust attempt must be superseded and Adjust requested
CREATE OR REPLACE FUNCTION coherence.trg_review_saves_verify_deferred()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF NOT NEW.imported AND NEW.surface = 'bible' THEN
    IF coherence.current_finished_attempt(NEW.run_id, 'adjust') IS NOT NULL THEN
      RAISE EXCEPTION 're-saving Bible review must supersede the prior Adjust attempt in the same transaction (R8)'
        USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM coherence.step_requests
      WHERE run_id = NEW.run_id AND step = 'adjust' AND reason = 'bible_saved' AND journal_seq = NEW.journal_seq
    ) THEN
      RAISE EXCEPTION 'saving Bible review must request Adjust in the same transaction (R8)'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_review_saves_verify_deferred
  AFTER INSERT ON coherence.review_saves
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_review_saves_verify_deferred();

-- Review drafts guard (R6.16, CR-9, CR-10): bound to current non-superseded finished attempt
CREATE OR REPLACE FUNCTION coherence.trg_review_drafts_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_finished uuid;
  v_attempt_no integer;
BEGIN
  IF EXISTS (SELECT 1 FROM coherence.abandonments WHERE run_id = NEW.run_id) THEN
    RAISE EXCEPTION 'cannot save draft on abandoned run %', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF coherence.current_finished_attempt(NEW.run_id, 'emit') IS NOT NULL THEN
    RAISE EXCEPTION 'cannot save draft after Emit has finished (CR-10)'
      USING ERRCODE = '23514';
  END IF;
  v_finished := coherence.current_finished_attempt(NEW.run_id, NEW.surface);
  IF v_finished IS NULL THEN
    RAISE EXCEPTION 'cannot save draft: % has no finished attempt', NEW.surface
      USING ERRCODE = '23514';
  END IF;
  SELECT attempt_no INTO v_attempt_no FROM coherence.step_attempt_events WHERE id = v_finished;
  IF NEW.attempt_no <> v_attempt_no THEN
    RAISE EXCEPTION 'draft attempt_no (%) must match current finished % attempt (%) (CR-9)',
      NEW.attempt_no, NEW.surface, v_attempt_no
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_review_drafts_guard
  BEFORE INSERT OR UPDATE ON coherence.review_drafts
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_review_drafts_guard();

-- Emit confirmations BEFORE INSERT (R5.4, R6.17, R8, R9.4, CR-1)
CREATE OR REPLACE FUNCTION coherence.trg_emit_confirmations_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_run coherence.runs%ROWTYPE;
  v_expected_phrase text;
  v_adjust_finished uuid;
  v_newest_save uuid;
BEGIN
  SELECT * INTO v_run FROM coherence.runs WHERE id = NEW.run_id;
  IF NOT FOUND OR v_run.origin IN ('mac_import', 'company_import') THEN
    RAISE EXCEPTION 'cannot confirm Emit on missing or imported run';
  END IF;
  IF EXISTS (SELECT 1 FROM coherence.abandonments WHERE run_id = NEW.run_id) THEN
    RAISE EXCEPTION 'cannot confirm Emit on abandoned run % (R9.4)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF coherence.run_has_open_request(NEW.run_id) OR coherence.run_has_open_attempt(NEW.run_id) THEN
    RAISE EXCEPTION 'cannot confirm Emit while run % has an open request or running step (R8)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  -- R8 & CR-1: no review submission waiting
  IF EXISTS (SELECT 1 FROM coherence.review_submissions WHERE run_id = NEW.run_id AND status = 'pending') THEN
    RAISE EXCEPTION 'cannot confirm Emit while a review submission is waiting (R8, CR-1)'
      USING ERRCODE = '23514';
  END IF;
  IF coherence.current_finished_attempt(NEW.run_id, 'emit') IS NOT NULL THEN
    RAISE EXCEPTION 'Emit has already finished for run %', NEW.run_id
      USING ERRCODE = '23514';
  END IF;

  v_expected_phrase := 'create statements for ' || pg_catalog.to_char(v_run.statement_date, 'YYYY-MM-DD');
  IF NEW.typed_phrase <> v_expected_phrase THEN
    RAISE EXCEPTION 'Emit typed_phrase must be "%" (R5.4, R8)', v_expected_phrase
      USING ERRCODE = '23514';
  END IF;

  v_adjust_finished := coherence.current_finished_attempt(NEW.run_id, 'adjust');
  IF v_adjust_finished IS NULL THEN
    RAISE EXCEPTION 'cannot confirm Emit: Adjust has not finished (R8)'
      USING ERRCODE = '23514';
  END IF;

  SELECT id INTO v_newest_save
  FROM coherence.review_saves
  WHERE run_id = NEW.run_id AND surface = 'adjust' AND attempt_event_id = v_adjust_finished
  ORDER BY journal_seq DESC
  LIMIT 1;
  IF v_newest_save IS NULL OR NEW.adjust_review_save_id <> v_newest_save THEN
    RAISE EXCEPTION 'Emit confirmation must name the run''s newest Adjust review save (R6.17, R8, R9.4)'
      USING ERRCODE = '23514';
  END IF;

  IF EXISTS (
    SELECT 1 FROM coherence.emit_confirmations ec
    JOIN coherence.review_saves rs ON rs.id = ec.adjust_review_save_id
    WHERE ec.run_id = NEW.run_id AND rs.attempt_event_id = v_adjust_finished
  ) THEN
    RAISE EXCEPTION 'Emit is already confirmed for Adjust''s current attempt (R8)'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_emit_confirmations_before
  BEFORE INSERT ON coherence.emit_confirmations
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_emit_confirmations_before();

CREATE OR REPLACE FUNCTION coherence.trg_emit_confirmations_verify_deferred()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM coherence.step_requests
    WHERE run_id = NEW.run_id AND step = 'emit' AND reason = 'emit_confirmed'
      AND emit_confirmation_id = NEW.id AND journal_seq = NEW.journal_seq
  ) THEN
    RAISE EXCEPTION 'emit_confirmation % must create its emit step_request in the same journal entry (R8)', NEW.id
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_emit_confirmations_verify_deferred
  AFTER INSERT ON coherence.emit_confirmations
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_emit_confirmations_verify_deferred();

-- Carries BEFORE INSERT (R6.18, R7.6, R8, R9.4, S-8)
CREATE OR REPLACE FUNCTION coherence.trg_carries_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_run coherence.runs%ROWTYPE;
  v_emit_event uuid;
  v_expected_artifact text;
  v_expected_phrase text;
  v_prev_standing_id uuid;
  v_standing_overlay_sha text;
BEGIN
  SELECT * INTO v_run FROM coherence.runs WHERE id = NEW.run_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'run % does not exist', NEW.run_id;
  END IF;
  IF EXISTS (SELECT 1 FROM coherence.abandonments WHERE run_id = NEW.run_id) THEN
    RAISE EXCEPTION 'cannot carry from abandoned run % (R9.4)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  -- R7.6 & R8: Trial, replay, and mac_import are never carried
  IF v_run.origin NOT IN ('app', 'company_import') THEN
    RAISE EXCEPTION 'only app and company_import runs can be carried (origin: %) (R8)', v_run.origin
      USING ERRCODE = '23514';
  END IF;
  IF NEW.statement_date <> v_run.statement_date THEN
    RAISE EXCEPTION 'carry statement_date (%) must match run statement_date (%)', NEW.statement_date, v_run.statement_date
      USING ERRCODE = '23514';
  END IF;
  IF coherence.run_has_open_request(NEW.run_id) OR coherence.run_has_open_attempt(NEW.run_id) THEN
    RAISE EXCEPTION 'cannot carry while run % has an open request or attempt (R8)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;

  v_emit_event := coherence.current_finished_attempt(NEW.run_id, 'emit');
  IF v_emit_event IS NULL THEN
    RAISE EXCEPTION 'cannot carry from run %: Emit has not finished (R8)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;

  -- Find the previous standing input version (excluding any version created in this same journal_seq)
  SELECT id INTO v_prev_standing_id
  FROM coherence.input_versions
  WHERE line_kind = 'standing' AND journal_seq < NEW.journal_seq
  ORDER BY journal_seq DESC
  LIMIT 1;

  IF NEW.carry_kind = 'sent' THEN
    v_expected_phrase := 'sent ' || pg_catalog.to_char(v_run.statement_date, 'YYYY-MM-DD');
    IF NEW.typed_phrase <> v_expected_phrase THEN
      RAISE EXCEPTION 'record as sent typed_phrase must be "%"', v_expected_phrase
        USING ERRCODE = '23514';
    END IF;
    v_expected_artifact := 'emits/statements_' || pg_catalog.to_char(v_run.statement_date, 'YYYYMMDD') || '.csv';
    IF NOT EXISTS (
      SELECT 1 FROM coherence.artifacts
      WHERE attempt_event_id = v_emit_event
        AND rel_path = v_expected_artifact
        AND file_sha256 = NEW.file_sha256
    ) THEN
      RAISE EXCEPTION 'sent carry file_sha256 must match this run''s finished Emit artifact % (R6.18, R8)', v_expected_artifact
        USING ERRCODE = '23514';
    END IF;
    IF v_prev_standing_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM coherence.input_versions
      WHERE id = NEW.published_input_version_id AND line_kind = 'standing'
        AND source_kind = 'record_sent' AND parent_id = v_prev_standing_id AND journal_seq = NEW.journal_seq
    ) THEN
      RAISE EXCEPTION 'sent carry must publish the next standing input_version in the same journal entry (R8)'
        USING ERRCODE = '23514';
    END IF;

  ELSIF NEW.carry_kind = 'approvals' THEN
    v_expected_phrase := 'carry ' || pg_catalog.to_char(v_run.statement_date, 'YYYY-MM-DD');
    IF NEW.typed_phrase <> v_expected_phrase THEN
      RAISE EXCEPTION 'carry approvals typed_phrase must be "%"', v_expected_phrase
        USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM coherence.artifacts
      WHERE attempt_event_id = v_emit_event
        AND rel_path = 'emits/overlay.csv'
        AND file_sha256 = NEW.file_sha256
    ) THEN
      RAISE EXCEPTION 'approvals carry file_sha256 must match this run''s finished Emit emits/overlay.csv (R6.18, R8)'
        USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM coherence.approvals_files WHERE file_sha256 = NEW.file_sha256) THEN
      RAISE EXCEPTION 'approvals carry file_sha256 must be registered in approvals_files'
        USING ERRCODE = '23514';
    END IF;

    IF v_prev_standing_id IS NOT NULL THEN
      SELECT file_sha256 INTO v_standing_overlay_sha
      FROM coherence.input_entries
      WHERE input_version_id = v_prev_standing_id AND mac_key = 'overlay/overlay.csv';
    END IF;

    IF v_standing_overlay_sha IS NOT NULL THEN
      -- R8, R9.4, S-8: carried approvals MUST extend the current standing approvals file
      IF NOT coherence.approvals_extends(NEW.file_sha256, v_standing_overlay_sha) THEN
        RAISE EXCEPTION 'approvals carry refused: emitted overlay does not extend the standing approvals file (R8, R9.4, S-8)'
          USING ERRCODE = '23514';
      END IF;
      IF NEW.file_sha256 = v_standing_overlay_sha THEN
        IF NOT NEW.nothing_new OR NEW.published_input_version_id IS NOT NULL THEN
          RAISE EXCEPTION 'when emitted approvals are identical to standing approvals, carry must set nothing_new = true and published_input_version_id = NULL (R6.18, R8)'
            USING ERRCODE = '23514';
        END IF;
      ELSE
        IF NEW.nothing_new OR NEW.published_input_version_id IS NULL THEN
          RAISE EXCEPTION 'approvals carry with new rows must publish the next standing input_version (R8)'
            USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
          SELECT 1 FROM coherence.input_versions
          WHERE id = NEW.published_input_version_id AND line_kind = 'standing'
            AND source_kind = 'carry_approvals' AND parent_id = v_prev_standing_id AND journal_seq = NEW.journal_seq
        ) THEN
          RAISE EXCEPTION 'approvals carry must publish the next standing input_version in the same journal entry (R8)'
            USING ERRCODE = '23514';
        END IF;
      END IF;
    ELSE
      IF NEW.nothing_new OR NEW.published_input_version_id IS NULL THEN
        RAISE EXCEPTION 'first approvals carry must publish the next standing input_version (R8)'
          USING ERRCODE = '23514';
      END IF;
      IF v_prev_standing_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM coherence.input_versions
        WHERE id = NEW.published_input_version_id AND line_kind = 'standing'
          AND source_kind = 'carry_approvals' AND parent_id = v_prev_standing_id AND journal_seq = NEW.journal_seq
      ) THEN
        RAISE EXCEPTION 'approvals carry must publish the next standing input_version in the same journal entry (R8)'
          USING ERRCODE = '23514';
      END IF;
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_carries_before
  BEFORE INSERT ON coherence.carries
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_carries_before();

-- Abandonments BEFORE INSERT (R6.19, R8, R9.4)
CREATE OR REPLACE FUNCTION coherence.trg_abandonments_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_run coherence.runs%ROWTYPE;
  v_expected_phrase text;
BEGIN
  SELECT * INTO v_run FROM coherence.runs WHERE id = NEW.run_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'run % does not exist', NEW.run_id;
  END IF;
  IF v_run.origin IN ('mac_import', 'company_import') THEN
    RAISE EXCEPTION 'imported historical runs cannot be abandoned';
  END IF;
  v_expected_phrase := 'abandon ' || pg_catalog.to_char(v_run.statement_date, 'YYYY-MM-DD');
  IF NEW.typed_phrase <> v_expected_phrase THEN
    RAISE EXCEPTION 'abandon typed_phrase must be "%"', v_expected_phrase
      USING ERRCODE = '23514';
  END IF;
  -- R8 & R9.4: no open attempt, no review waiting, nothing carried
  IF coherence.run_has_open_attempt(NEW.run_id) THEN
    RAISE EXCEPTION 'cannot abandon run % while an attempt is open (R8, R9.4)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF EXISTS (SELECT 1 FROM coherence.review_submissions WHERE run_id = NEW.run_id AND status = 'pending') THEN
    RAISE EXCEPTION 'cannot abandon run % while a review submission is waiting (R8, R9.4)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF EXISTS (SELECT 1 FROM coherence.carries WHERE run_id = NEW.run_id) THEN
    RAISE EXCEPTION 'cannot abandon run % because it has carried outputs (R8, R9.4)', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_abandonments_before
  BEFORE INSERT ON coherence.abandonments
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_abandonments_before();

-- Delete review drafts automatically on abandon (R6.16)
CREATE OR REPLACE FUNCTION coherence.trg_abandonments_after_delete_drafts()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  DELETE FROM coherence.review_drafts WHERE run_id = NEW.run_id;
  RETURN NULL;
END;
$$;

CREATE TRIGGER trg_03_abandonments_delete_drafts
  AFTER INSERT ON coherence.abandonments
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_abandonments_after_delete_drafts();
