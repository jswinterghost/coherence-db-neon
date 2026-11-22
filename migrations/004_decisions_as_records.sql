-- Migration 004: decisions as immutable database records, generated overlay receipts,
-- review queue snapshots, and engine-copy provenance on engine_versions.
-- All functions pin SET search_path = pg_catalog and schema-qualify all references.

-- 1. Extend engine_versions to support an engine copy alongside legacy sealed engines.
ALTER TABLE coherence.engine_versions
  ADD COLUMN engine_kind TEXT NOT NULL DEFAULT 'legacy_sealed'
    CHECK (engine_kind IN ('legacy_sealed', 'engine_copy', 'phalanx_copy')),
  ADD COLUMN upstream_commit TEXT
    CHECK (upstream_commit IS NULL OR upstream_commit ~ '^[0-9a-f]{7,40}$'),
  ADD COLUMN patch_diff_sha256 TEXT
    CHECK (patch_diff_sha256 IS NULL OR patch_diff_sha256 ~ '^[0-9a-f]{64}$');

ALTER TABLE coherence.engine_versions
  ADD CONSTRAINT engine_versions_patch_diff_fk
  FOREIGN KEY (store_kind, patch_diff_sha256) REFERENCES coherence.stored_files(store_kind, sha256);

ALTER TABLE coherence.engine_versions
  ALTER COLUMN web_lock_sha256 DROP NOT NULL,
  ALTER COLUMN web_packages_sha256 DROP NOT NULL,
  ALTER COLUMN company_emit_sha256 DROP NOT NULL,
  ALTER COLUMN pages_law_sha256 DROP NOT NULL;

DO $$
DECLARE
  v_con text;
BEGIN
  SELECT con.conname INTO v_con
  FROM pg_catalog.pg_constraint con
  JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'coherence'
    AND c.relname = 'engine_versions'
    AND con.contype = 'c'
    AND pg_catalog.pg_get_constraintdef(con.oid) LIKE '%pnpm%';
  IF v_con IS NOT NULL THEN
    EXECUTE pg_catalog.format('ALTER TABLE coherence.engine_versions DROP CONSTRAINT %I', v_con);
  END IF;
END;
$$;

ALTER TABLE coherence.engine_versions
  ADD CONSTRAINT engine_versions_toolchain_check CHECK (
    pg_catalog.jsonb_typeof(toolchain) = 'object'
    AND toolchain ? 'os'
    AND toolchain ? 'os_version'
    AND toolchain ? 'arch'
    AND toolchain ? 'python'
    AND toolchain ? 'uv'
    AND toolchain ? 'tz'
    AND toolchain ? 'lang'
    AND toolchain ? 'lc_all'
    AND toolchain ? 'pythonutf8'
    AND (
      engine_kind <> 'legacy_sealed'
      OR (toolchain ? 'node' AND toolchain ? 'pnpm')
    )
  ),
  ADD CONSTRAINT engine_versions_kind_requirements_check CHECK (
    engine_kind <> 'legacy_sealed'
    OR (
      web_lock_sha256 IS NOT NULL
      AND web_packages_sha256 IS NOT NULL
      AND company_emit_sha256 IS NOT NULL
      AND pages_law_sha256 IS NOT NULL
    )
  );

-- 2. Expand input_versions.source_kind and checks.check_kind vocabularies.
DO $$
DECLARE
  v_con text;
BEGIN
  SELECT con.conname INTO v_con
  FROM pg_catalog.pg_constraint con
  JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'coherence'
    AND c.relname = 'input_versions'
    AND con.contype = 'c'
    AND pg_catalog.pg_get_constraintdef(con.oid) LIKE '%carry_approvals%';
  IF v_con IS NOT NULL THEN
    EXECUTE pg_catalog.format('ALTER TABLE coherence.input_versions DROP CONSTRAINT %I', v_con);
  END IF;

  SELECT con.conname INTO v_con
  FROM pg_catalog.pg_constraint con
  JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'coherence'
    AND c.relname = 'checks'
    AND con.contype = 'c'
    AND pg_catalog.pg_get_constraintdef(con.oid) LIKE '%trial_comparison%';
  IF v_con IS NOT NULL THEN
    EXECUTE pg_catalog.format('ALTER TABLE coherence.checks DROP CONSTRAINT %I', v_con);
  END IF;
END;
$$;

ALTER TABLE coherence.input_versions
  ADD CONSTRAINT input_versions_source_kind_check CHECK (source_kind IN (
    'upload', 'include', 'remove', 'rename',
    'mac_import', 'company_import', 'google_list_import',
    'record_sent', 'carry_approvals', 'prod_clone', 'dev_override'
  ));

ALTER TABLE coherence.checks
  ADD CONSTRAINT checks_check_kind_check CHECK (check_kind IN (
    'chain', 'commitments', 'objects', 'import', 'replay', 'shadow', 'trial_comparison',
    'overlay_reconstruction', 'entity_statements', 'journal_rebuild', 'non_vacuous_mutation'
  ));

-- 3. Immutable decision commit graph and individual decision records.
CREATE TABLE coherence.decision_commits (
  id UUID PRIMARY KEY,
  parent_commit_id UUID REFERENCES coherence.decision_commits(id),
  commit_kind TEXT NOT NULL CHECK (commit_kind IN ('review_save', 'historical_baseline', 'historical_overlay')),
  header_contract TEXT NOT NULL DEFAULT 'v2' CHECK (header_contract IN ('v1', 'v2')),
  added_decision_count INTEGER NOT NULL CHECK (added_decision_count >= 0),
  cumulative_decision_count INTEGER NOT NULL CHECK (cumulative_decision_count >= added_decision_count),
  added_decisions_sha256 TEXT NOT NULL CHECK (added_decisions_sha256 ~ '^[0-9a-f]{64}$'),
  imported BOOLEAN NOT NULL DEFAULT false,
  original_at TIMESTAMPTZ,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  CHECK (parent_commit_id IS NULL OR parent_commit_id <> id),
  CHECK (imported = true OR original_at IS NULL)
);

CREATE INDEX decision_commits_parent_idx ON coherence.decision_commits (parent_commit_id);
CREATE INDEX decision_commits_journal_seq_idx ON coherence.decision_commits (journal_seq);

CREATE TABLE coherence.decisions (
  id UUID PRIMARY KEY,
  decision_commit_id UUID NOT NULL REFERENCES coherence.decision_commits(id),
  row_order INTEGER NOT NULL CHECK (row_order >= 1),
  run_id UUID REFERENCES coherence.runs(id),
  review_save_id UUID REFERENCES coherence.review_saves(id),
  surface TEXT CHECK (surface IS NULL OR surface IN ('bible', 'adjust')),
  record_id TEXT NOT NULL CHECK (pg_catalog.length(record_id) > 0),
  replaces_decision_id UUID REFERENCES coherence.decisions(id),
  disposition TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(disposition)) > 0),
  agent TEXT,
  agency TEXT,
  policy TEXT,
  book TEXT,
  month TEXT,
  status TEXT,
  note TEXT,
  approved_amount TEXT,
  approved_agency TEXT,
  approved_agent TEXT,
  approved_agency_from TEXT,
  approved_agent_from TEXT,
  decided_by TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(decided_by)) > 0 AND decided_by !~ '[\x01-\x1f\x7f]'),
  acting_for TEXT CHECK (acting_for IS NULL OR (pg_catalog.length(pg_catalog.btrim(acting_for)) > 0 AND acting_for !~ '[\x01-\x1f\x7f]')),
  decided_at TIMESTAMPTZ NOT NULL,
  committed_at_raw TEXT,
  imported BOOLEAN NOT NULL DEFAULT false,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  UNIQUE (decision_commit_id, row_order),
  CHECK (replaces_decision_id IS NULL OR replaces_decision_id <> id),
  CHECK (
    imported = true
    OR (
      disposition IN ('CONFIRM', 'CORRECT')
      AND run_id IS NOT NULL
      AND review_save_id IS NOT NULL
      AND surface IS NOT NULL
      AND policy IS NULL
      AND month IS NULL
      AND (
        (disposition = 'CONFIRM' AND agent IS NULL AND agency IS NULL AND book IS NULL AND status IS NULL)
        OR (disposition = 'CORRECT' AND (agent IS NOT NULL OR agency IS NOT NULL OR book IS NOT NULL OR status IS NOT NULL))
      )
      AND (
        status IS NULL OR status IN (
          'ACTIVE_PAYING', 'ACTIVE_IMPLIED', 'INACTIVE_IMPLIED', 'ACTIVE_RECON',
          'CLAWBACK', 'TERMINATED', 'NEVER_IN_FORCE', 'PENDING',
          'REVERSED', 'INACTIVE', 'UNKNOWN', 'ACTIVE_INTERIM'
        )
      )
      AND (approved_amount IS NULL OR approved_amount ~ '^-?[0-9]+\.[0-9]{2}$')
    )
  )
);

CREATE INDEX decisions_record_id_idx ON coherence.decisions (record_id, journal_seq ASC, row_order ASC);
CREATE INDEX decisions_commit_order_idx ON coherence.decisions (decision_commit_id, row_order ASC);
CREATE INDEX decisions_run_surface_idx ON coherence.decisions (run_id, surface, row_order ASC);
CREATE INDEX decisions_replaces_idx ON coherence.decisions (replaces_decision_id) WHERE replaces_decision_id IS NOT NULL;
CREATE INDEX decisions_journal_seq_idx ON coherence.decisions (journal_seq);

-- Fingerprinted receipt of every overlay.csv generated from decision records for the engine.
CREATE TABLE coherence.generated_overlays (
  id UUID PRIMARY KEY,
  decision_commit_id UUID NOT NULL REFERENCES coherence.decision_commits(id),
  run_id UUID NOT NULL REFERENCES coherence.runs(id),
  purpose TEXT NOT NULL CHECK (purpose IN ('prior_input', 'bible_review', 'adjust_review', 'emit_output', 'historical_source')),
  attempt_event_id UUID REFERENCES coherence.step_attempt_events(id),
  header_contract TEXT NOT NULL CHECK (header_contract IN ('v1', 'v2')),
  row_count INTEGER NOT NULL CHECK (row_count >= 0),
  store_kind TEXT NOT NULL DEFAULT 'company_data' CHECK (store_kind = 'company_data'),
  file_sha256 TEXT NOT NULL CHECK (file_sha256 ~ '^[0-9a-f]{64}$'),
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  FOREIGN KEY (store_kind, file_sha256) REFERENCES coherence.stored_files(store_kind, sha256)
);

CREATE INDEX generated_overlays_run_purpose_idx ON coherence.generated_overlays (run_id, purpose, journal_seq DESC);
CREATE INDEX generated_overlays_commit_idx ON coherence.generated_overlays (decision_commit_id);
CREATE INDEX generated_overlays_journal_seq_idx ON coherence.generated_overlays (journal_seq);

-- Immutable snapshot of bible.csv and adjust.csv queue items loaded when bible or adjust finishes.
CREATE TABLE coherence.review_queue_items (
  attempt_event_id UUID NOT NULL REFERENCES coherence.step_attempt_events(id),
  item_order INTEGER NOT NULL CHECK (item_order >= 1),
  run_id UUID NOT NULL REFERENCES coherence.runs(id),
  surface TEXT NOT NULL CHECK (surface IN ('bible', 'adjust')),
  record_id TEXT NOT NULL CHECK (pg_catalog.length(record_id) > 0),
  case_kind TEXT,
  subtype TEXT,
  entity TEXT,
  npn TEXT,
  amount TEXT,
  entity_from TEXT,
  npn_from TEXT,
  needs_reconfirm BOOLEAN NOT NULL DEFAULT false,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  PRIMARY KEY (attempt_event_id, item_order)
);

CREATE INDEX review_queue_items_run_surface_idx ON coherence.review_queue_items (run_id, surface, attempt_event_id);
CREATE INDEX review_queue_items_attempt_record_idx ON coherence.review_queue_items (attempt_event_id, record_id);
CREATE INDEX review_queue_items_journal_seq_idx ON coherence.review_queue_items (journal_seq);

-- 4. Link runs, review_saves, and carries to decision_commits while keeping legacy columns compatible.
ALTER TABLE coherence.runs
  ADD COLUMN prior_decision_commit_id UUID REFERENCES coherence.decision_commits(id);

ALTER TABLE coherence.review_saves
  ALTER COLUMN approvals_file_sha256 DROP NOT NULL,
  ADD COLUMN decision_commit_id UUID REFERENCES coherence.decision_commits(id),
  ADD CONSTRAINT review_saves_source_check CHECK (
    approvals_file_sha256 IS NOT NULL OR decision_commit_id IS NOT NULL
  );

CREATE INDEX review_saves_decision_commit_idx ON coherence.review_saves (decision_commit_id)
  WHERE decision_commit_id IS NOT NULL;

DO $$
DECLARE
  v_con text;
BEGIN
  FOR v_con IN
    SELECT con.conname
    FROM pg_catalog.pg_constraint con
    JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'coherence'
      AND c.relname = 'carries'
      AND con.contype = 'c'
      AND (
        pg_catalog.pg_get_constraintdef(con.oid) LIKE '%carry_kind%'
        OR pg_catalog.pg_get_constraintdef(con.oid) LIKE '%nothing_new%'
        OR pg_catalog.pg_get_constraintdef(con.oid) LIKE '%store_kind%'
      )
  LOOP
    EXECUTE pg_catalog.format('ALTER TABLE coherence.carries DROP CONSTRAINT %I', v_con);
  END LOOP;
END;
$$;

ALTER TABLE coherence.carries
  ALTER COLUMN store_kind DROP NOT NULL,
  ALTER COLUMN file_sha256 DROP NOT NULL,
  ADD COLUMN carried_decision_commit_id UUID REFERENCES coherence.decision_commits(id);

ALTER TABLE coherence.carries
  ADD CONSTRAINT carries_carry_kind_check CHECK (carry_kind IN ('sent', 'approvals', 'decisions')),
  ADD CONSTRAINT carries_store_file_check CHECK (
    (file_sha256 IS NULL AND store_kind IS NULL)
    OR (file_sha256 IS NOT NULL AND store_kind = 'company_data')
  ),
  ADD CONSTRAINT carries_mode_check CHECK (
    (carry_kind = 'sent' AND nothing_new = false AND published_input_version_id IS NOT NULL AND file_sha256 IS NOT NULL AND carried_decision_commit_id IS NULL)
    OR (carry_kind = 'approvals' AND file_sha256 IS NOT NULL AND carried_decision_commit_id IS NULL AND (
      (nothing_new = false AND published_input_version_id IS NOT NULL)
      OR (nothing_new = true AND published_input_version_id IS NULL)
    ))
    OR (carry_kind = 'decisions' AND carried_decision_commit_id IS NOT NULL AND published_input_version_id IS NULL)
  );

CREATE INDEX carries_decision_commit_idx ON coherence.carries (carried_decision_commit_id)
  WHERE carried_decision_commit_id IS NOT NULL;

-- 5. Attach ENABLE ALWAYS immutability and active-journal triggers to all four new business tables.
DO $$
DECLARE
  v_tbl text;
BEGIN
  FOREACH v_tbl IN ARRAY ARRAY[
    'decision_commits', 'decisions', 'generated_overlays', 'review_queue_items'
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

-- 6. Decision lineage, hashing, and "as of" query functions (all pinned to pg_catalog).
CREATE OR REPLACE FUNCTION coherence.hash_decisions(p_decision_commit_id uuid)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT coherence.sha256_text(
    COALESCE(
      (SELECT pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          id::text, row_order, run_id::text, review_save_id::text, surface,
          record_id, replaces_decision_id::text, disposition,
          agent, agency, policy, book, month, status, note,
          approved_amount, approved_agency, approved_agent,
          approved_agency_from, approved_agent_from,
          decided_by, acting_for, coherence.format_utc_us(decided_at),
          committed_at_raw, imported
        )) || E'\n',
        '' ORDER BY row_order ASC
      )
      FROM coherence.decisions
      WHERE decision_commit_id = p_decision_commit_id),
      ''
    )
  );
$$;

CREATE OR REPLACE FUNCTION coherence.decision_commit_extends(p_child uuid, p_ancestor uuid)
RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  WITH RECURSIVE chain(commit_id, depth) AS (
    SELECT p_child, 0
    WHERE p_child IS NOT NULL
    UNION ALL
    SELECT dc.parent_commit_id, c.depth + 1
    FROM chain c
    JOIN coherence.decision_commits dc ON dc.id = c.commit_id
    WHERE dc.parent_commit_id IS NOT NULL AND c.depth < 10000
  )
  SELECT p_ancestor IS NULL
      OR EXISTS (SELECT 1 FROM chain WHERE commit_id = p_ancestor)
      OR EXISTS (SELECT 1 FROM coherence.decision_commits WHERE id = p_ancestor AND cumulative_decision_count = 0);
$$;

CREATE OR REPLACE FUNCTION coherence.decisions_in_commit(p_commit_id uuid)
RETURNS TABLE (
  seq_order bigint,
  id uuid,
  decision_commit_id uuid,
  row_order integer,
  run_id uuid,
  review_save_id uuid,
  surface text,
  record_id text,
  replaces_decision_id uuid,
  disposition text,
  agent text,
  agency text,
  policy text,
  book text,
  month text,
  status text,
  note text,
  approved_amount text,
  approved_agency text,
  approved_agent text,
  approved_agency_from text,
  approved_agent_from text,
  decided_by text,
  acting_for text,
  decided_at timestamptz,
  committed_at_raw text,
  imported boolean,
  journal_seq bigint
)
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  WITH RECURSIVE lineage(commit_id, depth) AS (
    SELECT p_commit_id, 0
    WHERE p_commit_id IS NOT NULL
    UNION ALL
    SELECT dc.parent_commit_id, l.depth + 1
    FROM lineage l
    JOIN coherence.decision_commits dc ON dc.id = l.commit_id
    WHERE dc.parent_commit_id IS NOT NULL AND l.depth < 10000
  )
  SELECT
    pg_catalog.row_number() OVER (ORDER BY l.depth DESC, d.row_order ASC) AS seq_order,
    d.id, d.decision_commit_id, d.row_order, d.run_id, d.review_save_id, d.surface,
    d.record_id, d.replaces_decision_id, d.disposition, d.agent, d.agency, d.policy,
    d.book, d.month, d.status, d.note,
    d.approved_amount, d.approved_agency, d.approved_agent,
    d.approved_agency_from, d.approved_agent_from,
    d.decided_by, d.acting_for, d.decided_at, d.committed_at_raw, d.imported, d.journal_seq
  FROM lineage l
  JOIN coherence.decisions d ON d.decision_commit_id = l.commit_id
  ORDER BY l.depth DESC, d.row_order ASC;
$$;

CREATE OR REPLACE FUNCTION coherence.decisions_current(p_commit_id uuid)
RETURNS TABLE (
  seq_order bigint,
  id uuid,
  decision_commit_id uuid,
  row_order integer,
  run_id uuid,
  review_save_id uuid,
  surface text,
  record_id text,
  replaces_decision_id uuid,
  disposition text,
  agent text,
  agency text,
  policy text,
  book text,
  month text,
  status text,
  note text,
  approved_amount text,
  approved_agency text,
  approved_agent text,
  approved_agency_from text,
  approved_agent_from text,
  decided_by text,
  acting_for text,
  decided_at timestamptz,
  committed_at_raw text,
  imported boolean,
  journal_seq bigint
)
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT DISTINCT ON (r.record_id)
    r.seq_order, r.id, r.decision_commit_id, r.row_order, r.run_id, r.review_save_id, r.surface,
    r.record_id, r.replaces_decision_id, r.disposition, r.agent, r.agency, r.policy,
    r.book, r.month, r.status, r.note,
    r.approved_amount, r.approved_agency, r.approved_agent,
    r.approved_agency_from, r.approved_agent_from,
    r.decided_by, r.acting_for, r.decided_at, r.committed_at_raw, r.imported, r.journal_seq
  FROM coherence.decisions_in_commit(p_commit_id) r
  ORDER BY r.record_id, r.seq_order DESC;
$$;

CREATE OR REPLACE FUNCTION coherence.decisions_bible_applied(p_commit_id uuid, p_bible_keys text[])
RETURNS TABLE (
  seq_order bigint,
  id uuid,
  decision_commit_id uuid,
  row_order integer,
  run_id uuid,
  review_save_id uuid,
  surface text,
  record_id text,
  replaces_decision_id uuid,
  disposition text,
  agent text,
  agency text,
  policy text,
  book text,
  month text,
  status text,
  note text,
  approved_amount text,
  approved_agency text,
  approved_agent text,
  approved_agency_from text,
  approved_agent_from text,
  decided_by text,
  acting_for text,
  decided_at timestamptz,
  committed_at_raw text,
  imported boolean,
  journal_seq bigint
)
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT DISTINCT ON (r.record_id)
    r.seq_order, r.id, r.decision_commit_id, r.row_order, r.run_id, r.review_save_id, r.surface,
    r.record_id, r.replaces_decision_id, r.disposition, r.agent, r.agency, r.policy,
    r.book, r.month, r.status, r.note,
    r.approved_amount, r.approved_agency, r.approved_agent,
    r.approved_agency_from, r.approved_agent_from,
    r.decided_by, r.acting_for, r.decided_at, r.committed_at_raw, r.imported, r.journal_seq
  FROM coherence.decisions_in_commit(p_commit_id) r
  WHERE r.disposition = 'CORRECT'
    AND r.record_id = ANY(p_bible_keys)
  ORDER BY r.record_id, r.seq_order DESC;
$$;

CREATE OR REPLACE FUNCTION coherence.standing_decision_head_as_of(p_as_of_seq bigint DEFAULT NULL)
RETURNS uuid
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT COALESCE(
    (
      SELECT c.carried_decision_commit_id
      FROM coherence.carries c
      WHERE c.carry_kind = 'decisions'
        AND c.carried_decision_commit_id IS NOT NULL
        AND c.journal_seq <= COALESCE(p_as_of_seq, 9223372036854775807::bigint)
      ORDER BY c.journal_seq DESC
      LIMIT 1
    ),
    (
      SELECT dc.id
      FROM coherence.decision_commits dc
      WHERE dc.commit_kind = 'historical_baseline'
        AND dc.journal_seq <= COALESCE(p_as_of_seq, 9223372036854775807::bigint)
      ORDER BY dc.journal_seq DESC
      LIMIT 1
    )
  );
$$;

-- 7. Triggers for decision_commits, decisions, generated_overlays, and review_queue_items.
CREATE OR REPLACE FUNCTION coherence.trg_decision_commits_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_parent coherence.decision_commits%ROWTYPE;
BEGIN
  IF NEW.parent_commit_id IS NOT NULL THEN
    SELECT * INTO v_parent FROM coherence.decision_commits WHERE id = NEW.parent_commit_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'parent decision_commit % does not exist', NEW.parent_commit_id
        USING ERRCODE = '23514';
    END IF;
    IF v_parent.journal_seq > NEW.journal_seq THEN
      RAISE EXCEPTION 'parent decision_commit must not come from a later journal entry'
        USING ERRCODE = '23514';
    END IF;
    IF NEW.cumulative_decision_count <> v_parent.cumulative_decision_count + NEW.added_decision_count THEN
      RAISE EXCEPTION 'decision_commit cumulative_decision_count (%) must equal parent (%) + added (%)',
        NEW.cumulative_decision_count, v_parent.cumulative_decision_count, NEW.added_decision_count
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF NEW.cumulative_decision_count <> NEW.added_decision_count THEN
      RAISE EXCEPTION 'root decision_commit cumulative_decision_count (%) must equal added_decision_count (%)',
        NEW.cumulative_decision_count, NEW.added_decision_count
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_decision_commits_before
  BEFORE INSERT ON coherence.decision_commits
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_decision_commits_before();

CREATE OR REPLACE FUNCTION coherence.trg_decisions_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_commit coherence.decision_commits%ROWTYPE;
  v_save coherence.review_saves%ROWTYPE;
  v_prev_record_id text;
BEGIN
  SELECT * INTO v_commit FROM coherence.decision_commits WHERE id = NEW.decision_commit_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'decision_commit % does not exist', NEW.decision_commit_id
      USING ERRCODE = '23514';
  END IF;
  IF v_commit.journal_seq <> NEW.journal_seq THEN
    RAISE EXCEPTION 'cannot add decision to previously committed decision_commit %', NEW.decision_commit_id
      USING ERRCODE = '23514';
  END IF;
  IF NEW.row_order < 1 OR NEW.row_order > v_commit.added_decision_count THEN
    RAISE EXCEPTION 'decision row_order (%) out of range (1..%) for decision_commit %',
      NEW.row_order, v_commit.added_decision_count, NEW.decision_commit_id
      USING ERRCODE = '23514';
  END IF;
  IF v_commit.header_contract = 'v1' AND (
    NEW.approved_amount IS NOT NULL OR NEW.approved_agency IS NOT NULL OR NEW.approved_agent IS NOT NULL
    OR NEW.approved_agency_from IS NOT NULL OR NEW.approved_agent_from IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'v1 decision_commit cannot carry approved_* fact columns'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.review_save_id IS NOT NULL THEN
    SELECT * INTO v_save FROM coherence.review_saves WHERE id = NEW.review_save_id;
    IF NOT FOUND
       OR v_save.decision_commit_id IS DISTINCT FROM NEW.decision_commit_id
       OR v_save.run_id IS DISTINCT FROM NEW.run_id
       OR v_save.surface IS DISTINCT FROM NEW.surface
       OR v_save.journal_seq <> NEW.journal_seq THEN
      RAISE EXCEPTION 'decision review_save_id must match the review_save in the same decision_commit and journal entry'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  IF NEW.replaces_decision_id IS NOT NULL THEN
    SELECT record_id INTO v_prev_record_id FROM coherence.decisions WHERE id = NEW.replaces_decision_id;
    IF NOT FOUND OR v_prev_record_id <> NEW.record_id THEN
      RAISE EXCEPTION 'replaces_decision_id must reference a prior decision for the same key'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_decisions_before
  BEFORE INSERT ON coherence.decisions
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_decisions_before();

CREATE OR REPLACE FUNCTION coherence.trg_decision_commits_verify_deferred()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_actual integer;
  v_min_ord integer;
  v_max_ord integer;
  v_hash text;
BEGIN
  SELECT pg_catalog.count(*)::integer, pg_catalog.min(row_order), pg_catalog.max(row_order)
  INTO v_actual, v_min_ord, v_max_ord
  FROM coherence.decisions
  WHERE decision_commit_id = NEW.id;

  IF v_actual <> NEW.added_decision_count THEN
    RAISE EXCEPTION 'decision_commit % decision count mismatch: declared %, actual %',
      NEW.id, NEW.added_decision_count, v_actual
      USING ERRCODE = '23514';
  END IF;

  IF NEW.added_decision_count > 0 AND (v_min_ord <> 1 OR v_max_ord <> NEW.added_decision_count) THEN
    RAISE EXCEPTION 'decision_commit % row_order must be contiguous 1..%',
      NEW.id, NEW.added_decision_count
      USING ERRCODE = '23514';
  END IF;

  v_hash := coherence.hash_decisions(NEW.id);
  IF v_hash <> NEW.added_decisions_sha256 THEN
    RAISE EXCEPTION 'decision_commit % added_decisions_sha256 mismatch', NEW.id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.added_decision_count > 0 THEN
    IF EXISTS (
      WITH RECURSIVE lineage(commit_id, depth) AS (
        SELECT NEW.id, 0
        UNION ALL
        SELECT dc.parent_commit_id, l.depth + 1
        FROM lineage l
        JOIN coherence.decision_commits dc ON dc.id = l.commit_id
        WHERE dc.parent_commit_id IS NOT NULL AND l.depth < 10000
      ),
      touched_keys AS (
        SELECT DISTINCT record_id
        FROM coherence.decisions
        WHERE decision_commit_id = NEW.id
      ),
      scoped_chain AS (
        SELECT
          d.id,
          d.decision_commit_id,
          d.record_id,
          d.replaces_decision_id,
          pg_catalog.lag(d.id) OVER (PARTITION BY d.record_id ORDER BY l.depth DESC, d.row_order ASC) AS expected_prev_id
        FROM lineage l
        JOIN coherence.decisions d ON d.decision_commit_id = l.commit_id
        JOIN touched_keys tk ON tk.record_id = d.record_id
      )
      SELECT 1
      FROM scoped_chain
      WHERE decision_commit_id = NEW.id
        AND replaces_decision_id IS DISTINCT FROM expected_prev_id
    ) THEN
      RAISE EXCEPTION 'decision_commit % contains a decision whose replaces_decision_id does not match the immediately preceding decision on that key', NEW.id
        USING ERRCODE = '23514';
    END IF;
  END IF;

  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_decision_commits_verify_deferred
  AFTER INSERT ON coherence.decision_commits
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_decision_commits_verify_deferred();

CREATE OR REPLACE FUNCTION coherence.trg_generated_overlays_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_commit coherence.decision_commits%ROWTYPE;
BEGIN
  SELECT * INTO v_commit FROM coherence.decision_commits WHERE id = NEW.decision_commit_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'generated_overlay decision_commit % does not exist', NEW.decision_commit_id
      USING ERRCODE = '23514';
  END IF;
  IF NEW.row_count <> v_commit.cumulative_decision_count THEN
    RAISE EXCEPTION 'generated_overlay row_count (%) must equal decision_commit cumulative_decision_count (%)',
      NEW.row_count, v_commit.cumulative_decision_count
      USING ERRCODE = '23514';
  END IF;
  IF NEW.attempt_event_id IS NOT NULL THEN
    IF NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events
      WHERE id = NEW.attempt_event_id AND run_id = NEW.run_id
    ) THEN
      RAISE EXCEPTION 'generated_overlay attempt_event_id must belong to run %', NEW.run_id
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_generated_overlays_before
  BEFORE INSERT ON coherence.generated_overlays
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_generated_overlays_before();

CREATE OR REPLACE FUNCTION coherence.trg_review_queue_items_before()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_ev coherence.step_attempt_events%ROWTYPE;
BEGIN
  SELECT * INTO v_ev FROM coherence.step_attempt_events WHERE id = NEW.attempt_event_id;
  IF NOT FOUND OR v_ev.run_id <> NEW.run_id OR v_ev.step <> NEW.surface
     OR v_ev.event_kind <> 'finished' OR v_ev.journal_seq <> NEW.journal_seq THEN
    RAISE EXCEPTION 'review_queue_items must attach to a finished % attempt of run % in the same journal entry',
      NEW.surface, NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_02_review_queue_items_before
  BEFORE INSERT ON coherence.review_queue_items
  FOR EACH ROW EXECUTE FUNCTION coherence.trg_review_queue_items_before();

-- 8. Update run, review_save, and carry triggers to enforce decision-record lineage alongside legacy compatibility.
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

  IF NEW.origin IN ('app', 'trial') AND v_iv.line_kind <> 'standing' THEN
    RAISE EXCEPTION 'app and trial runs must use a standing input_version'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.origin IN ('mac_import', 'company_import', 'replay') AND v_iv.line_kind <> 'snapshot' THEN
    RAISE EXCEPTION 'import and replay runs must use a snapshot input_version'
      USING ERRCODE = '23514';
  END IF;

  SELECT file_sha256 INTO v_overlay_sha
  FROM coherence.input_entries
  WHERE input_version_id = NEW.input_version_id AND mac_key = 'overlay/overlay.csv';

  IF NEW.prior_decision_commit_id IS NULL AND NEW.prior_approvals_sha256 IS DISTINCT FROM v_overlay_sha THEN
    RAISE EXCEPTION 'run prior_approvals_sha256 must match input_version Overlay/overlay.csv'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.origin = 'replay' THEN
    SELECT * INTO v_replayed FROM coherence.runs WHERE id = NEW.replays_run_id;
    IF NOT FOUND OR v_replayed.origin NOT IN ('mac_import', 'company_import') THEN
      RAISE EXCEPTION 'replay must reference an imported run'
        USING ERRCODE = '23514';
    END IF;
    IF NEW.input_version_id <> v_replayed.input_version_id THEN
      RAISE EXCEPTION 'replay must use the replayed run''s frozen input_version'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  IF NEW.origin = 'app' THEN
    v_sent_name := 'sent/statements_' || pg_catalog.to_char(NEW.statement_date, 'YYYYMMDD') || '.csv';
    IF EXISTS (
      SELECT 1 FROM coherence.carries
      WHERE carry_kind = 'sent' AND statement_date = NEW.statement_date
    ) OR EXISTS (
      SELECT 1 FROM coherence.input_entries
      WHERE input_version_id = NEW.input_version_id AND mac_key = v_sent_name
    ) THEN
      RAISE EXCEPTION 'cannot launch app run for %: a sent statement already exists for that date', NEW.statement_date
        USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
      SELECT 1 FROM coherence.runs r
      WHERE r.origin = 'app'
        AND r.statement_date = NEW.statement_date
        AND NOT EXISTS (SELECT 1 FROM coherence.abandonments a WHERE a.run_id = r.id)
    ) THEN
      RAISE EXCEPTION 'cannot launch app run for %: a non-abandoned run for that date already exists', NEW.statement_date
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
  v_bible_save_commit uuid;
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
    RAISE EXCEPTION 'cannot save review on abandoned run %', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF coherence.run_has_open_request(NEW.run_id) OR coherence.run_has_open_attempt(NEW.run_id) THEN
    RAISE EXCEPTION 'cannot save review while run % has an open request or running step', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF coherence.current_finished_attempt(NEW.run_id, 'emit') IS NOT NULL THEN
    RAISE EXCEPTION 'cannot save review after Emit finished'
      USING ERRCODE = '23514';
  END IF;

  v_current_surface := coherence.current_finished_attempt(NEW.run_id, NEW.surface);
  IF v_current_surface IS DISTINCT FROM NEW.attempt_event_id THEN
    RAISE EXCEPTION 'review_save must review the current non-superseded finished % attempt', NEW.surface
      USING ERRCODE = '23514';
  END IF;

  IF NEW.decision_commit_id IS NOT NULL THEN
    IF v_run.prior_decision_commit_id IS NOT NULL
       AND NOT coherence.decision_commit_extends(NEW.decision_commit_id, v_run.prior_decision_commit_id) THEN
      RAISE EXCEPTION 'saved decision commit does not extend the run''s prior decision commit'
        USING ERRCODE = '23514';
    END IF;
  ELSIF v_run.prior_approvals_sha256 IS NOT NULL
     AND NOT coherence.approvals_extends(NEW.approvals_file_sha256, v_run.prior_approvals_sha256) THEN
    RAISE EXCEPTION 'saved approvals file does not extend the run''s frozen prior approvals'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.surface = 'bible' THEN
    v_current_adjust := coherence.current_finished_attempt(NEW.run_id, 'adjust');
    IF v_current_adjust IS NOT NULL AND EXISTS (
      SELECT 1 FROM coherence.review_saves
      WHERE run_id = NEW.run_id AND surface = 'adjust' AND attempt_event_id = v_current_adjust
    ) THEN
      RAISE EXCEPTION 'Bible review cannot be re-saved after an Adjust review was saved for Adjust''s current attempt'
        USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
      SELECT 1 FROM coherence.step_attempt_events e
      WHERE e.run_id = NEW.run_id AND e.step = 'adjust'
        AND e.event_kind IN ('failed', 'interrupted', 'cancelled')
        AND NOT EXISTS (
          SELECT 1 FROM coherence.step_attempt_events sup
          WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no AND sup.event_kind = 'superseded'
        )
    ) THEN
      RAISE EXCEPTION 'cannot save Bible review while Adjust has an un-superseded failed/interrupted/cancelled attempt'
        USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.surface = 'adjust' THEN
    IF EXISTS (
      SELECT 1 FROM coherence.emit_confirmations ec
      JOIN coherence.review_saves rs ON rs.id = ec.adjust_review_save_id
      WHERE ec.run_id = NEW.run_id AND rs.attempt_event_id = NEW.attempt_event_id
    ) THEN
      RAISE EXCEPTION 'Adjust review cannot be saved after Emit is confirmed for Adjust''s current attempt'
        USING ERRCODE = '23514';
    END IF;
    v_current_bible := coherence.current_finished_attempt(NEW.run_id, 'bible');
    SELECT approvals_file_sha256, decision_commit_id INTO v_bible_save_sha, v_bible_save_commit
    FROM coherence.review_saves
    WHERE run_id = NEW.run_id AND surface = 'bible' AND attempt_event_id = v_current_bible
    ORDER BY journal_seq DESC
    LIMIT 1;
    IF v_bible_save_sha IS NULL AND v_bible_save_commit IS NULL THEN
      RAISE EXCEPTION 'Adjust review requires a saved Bible review first'
        USING ERRCODE = '23514';
    END IF;
    IF NEW.decision_commit_id IS NOT NULL THEN
      IF v_bible_save_commit IS NOT NULL
         AND NOT coherence.decision_commit_extends(NEW.decision_commit_id, v_bible_save_commit) THEN
        RAISE EXCEPTION 'Adjust decision commit must extend this run''s Bible review commit'
          USING ERRCODE = '23514';
      END IF;
    ELSIF v_bible_save_sha IS NOT NULL
       AND NOT coherence.approvals_extends(NEW.approvals_file_sha256, v_bible_save_sha) THEN
      RAISE EXCEPTION 'Adjust approvals file must extend this run''s Bible review'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION coherence.trg_review_saves_verify_deferred()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_missing_count bigint;
  v_reconfirm_missing bigint;
BEGIN
  IF NOT NEW.imported AND NEW.surface = 'bible' THEN
    IF coherence.current_finished_attempt(NEW.run_id, 'adjust') IS NOT NULL THEN
      RAISE EXCEPTION 're-saving Bible review must supersede the prior Adjust attempt in the same transaction'
        USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM coherence.step_requests
      WHERE run_id = NEW.run_id AND step = 'adjust' AND reason = 'bible_saved' AND journal_seq = NEW.journal_seq
    ) THEN
      RAISE EXCEPTION 'saving Bible review must request Adjust in the same transaction'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  -- Enforce 100% queue coverage and Adjust reconfirmation directly in PostgreSQL for record-backed live saves.
  IF NOT NEW.imported AND NEW.decision_commit_id IS NOT NULL THEN
    SELECT pg_catalog.count(DISTINCT q.record_id) INTO v_missing_count
    FROM coherence.review_queue_items q
    WHERE q.attempt_event_id = NEW.attempt_event_id
      AND NOT EXISTS (
        SELECT 1 FROM coherence.decisions_in_commit(NEW.decision_commit_id) d
        WHERE d.record_id = q.record_id
      );
    IF v_missing_count > 0 THEN
      RAISE EXCEPTION 'review_save refused: % queue item(s) have no committed decision', v_missing_count
        USING ERRCODE = '23514';
    END IF;

    IF NEW.surface = 'adjust' THEN
      SELECT pg_catalog.count(DISTINCT q.record_id) INTO v_reconfirm_missing
      FROM coherence.review_queue_items q
      WHERE q.attempt_event_id = NEW.attempt_event_id
        AND q.needs_reconfirm = true
        AND NOT EXISTS (
          SELECT 1 FROM coherence.decisions_in_commit(NEW.decision_commit_id) d
          WHERE d.record_id = q.record_id AND d.run_id = NEW.run_id
        );
      IF v_reconfirm_missing > 0 THEN
        RAISE EXCEPTION 'review_save refused: % reconfirmation item(s) lack a fresh decision in this run', v_reconfirm_missing
          USING ERRCODE = '23514';
      END IF;
    END IF;
  END IF;

  RETURN NULL;
END;
$$;

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
  v_standing_head uuid;
  v_run_decision_commit uuid;
BEGIN
  SELECT * INTO v_run FROM coherence.runs WHERE id = NEW.run_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'run % does not exist', NEW.run_id;
  END IF;
  IF EXISTS (SELECT 1 FROM coherence.abandonments WHERE run_id = NEW.run_id) THEN
    RAISE EXCEPTION 'cannot carry from abandoned run %', NEW.run_id
      USING ERRCODE = '23514';
  END IF;
  IF v_run.origin NOT IN ('app', 'company_import') THEN
    RAISE EXCEPTION 'only app and company_import runs can be carried (origin: %)', v_run.origin
      USING ERRCODE = '23514';
  END IF;
  IF NEW.statement_date <> v_run.statement_date THEN
    RAISE EXCEPTION 'carry statement_date (%) must match run statement_date (%)', NEW.statement_date, v_run.statement_date
      USING ERRCODE = '23514';
  END IF;
  IF coherence.run_has_open_request(NEW.run_id) OR coherence.run_has_open_attempt(NEW.run_id) THEN
    RAISE EXCEPTION 'cannot carry while run % has an open request or attempt', NEW.run_id
      USING ERRCODE = '23514';
  END IF;

  v_emit_event := coherence.current_finished_attempt(NEW.run_id, 'emit');
  IF v_emit_event IS NULL THEN
    RAISE EXCEPTION 'cannot carry from run %: Emit has not finished', NEW.run_id
      USING ERRCODE = '23514';
  END IF;

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
      RAISE EXCEPTION 'sent carry file_sha256 must match this run''s finished Emit artifact %', v_expected_artifact
        USING ERRCODE = '23514';
    END IF;
    IF v_prev_standing_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM coherence.input_versions
      WHERE id = NEW.published_input_version_id AND line_kind = 'standing'
        AND source_kind = 'record_sent' AND parent_id = v_prev_standing_id AND journal_seq = NEW.journal_seq
    ) THEN
      RAISE EXCEPTION 'sent carry must publish the next standing input_version in the same journal entry'
        USING ERRCODE = '23514';
    END IF;

  ELSIF NEW.carry_kind = 'decisions' THEN
    v_expected_phrase := 'carry ' || pg_catalog.to_char(v_run.statement_date, 'YYYY-MM-DD');
    IF NEW.typed_phrase <> v_expected_phrase THEN
      RAISE EXCEPTION 'carry decisions typed_phrase must be "%"', v_expected_phrase
        USING ERRCODE = '23514';
    END IF;

    SELECT rs.decision_commit_id INTO v_run_decision_commit
    FROM coherence.review_saves rs
    WHERE rs.run_id = NEW.run_id
      AND rs.surface = 'adjust'
      AND rs.attempt_event_id = coherence.current_finished_attempt(NEW.run_id, 'adjust')
      AND rs.decision_commit_id IS NOT NULL
    ORDER BY rs.journal_seq DESC
    LIMIT 1;
    IF v_run_decision_commit IS NULL THEN
      SELECT rs.decision_commit_id INTO v_run_decision_commit
      FROM coherence.review_saves rs
      WHERE rs.run_id = NEW.run_id
        AND rs.surface = 'bible'
        AND rs.attempt_event_id = coherence.current_finished_attempt(NEW.run_id, 'bible')
        AND rs.decision_commit_id IS NOT NULL
      ORDER BY rs.journal_seq DESC
      LIMIT 1;
    END IF;
    v_run_decision_commit := COALESCE(v_run_decision_commit, v_run.prior_decision_commit_id);

    IF v_run_decision_commit IS NULL OR NEW.carried_decision_commit_id <> v_run_decision_commit THEN
      RAISE EXCEPTION 'carry decisions must name this run''s newest review decision commit'
        USING ERRCODE = '23514';
    END IF;

    v_standing_head := coherence.standing_decision_head_as_of(NEW.journal_seq - 1);
    IF v_standing_head IS NOT NULL THEN
      IF NOT coherence.decision_commit_extends(NEW.carried_decision_commit_id, v_standing_head) THEN
        RAISE EXCEPTION 'decisions carry refused: run decision commit does not extend the standing decision head'
          USING ERRCODE = '23514';
      END IF;
      IF NEW.carried_decision_commit_id = v_standing_head AND NOT NEW.nothing_new THEN
        RAISE EXCEPTION 'when carried decision commit equals standing head, carry must set nothing_new = true'
          USING ERRCODE = '23514';
      END IF;
      IF NEW.carried_decision_commit_id <> v_standing_head AND NEW.nothing_new THEN
        RAISE EXCEPTION 'decisions carry advancing standing head must set nothing_new = false'
          USING ERRCODE = '23514';
      END IF;
    ELSE
      IF NEW.nothing_new THEN
        RAISE EXCEPTION 'first decisions carry must set nothing_new = false'
          USING ERRCODE = '23514';
      END IF;
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
      RAISE EXCEPTION 'approvals carry file_sha256 must match this run''s finished Emit emits/overlay.csv'
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
      IF NOT coherence.approvals_extends(NEW.file_sha256, v_standing_overlay_sha) THEN
        RAISE EXCEPTION 'approvals carry refused: emitted overlay does not extend the standing approvals file'
          USING ERRCODE = '23514';
      END IF;
      IF NEW.file_sha256 = v_standing_overlay_sha THEN
        IF NOT NEW.nothing_new OR NEW.published_input_version_id IS NOT NULL THEN
          RAISE EXCEPTION 'when emitted approvals are identical to standing approvals, carry must set nothing_new = true and published_input_version_id = NULL'
            USING ERRCODE = '23514';
        END IF;
      ELSE
        IF NEW.nothing_new OR NEW.published_input_version_id IS NULL THEN
          RAISE EXCEPTION 'approvals carry with new rows must publish the next standing input_version'
            USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
          SELECT 1 FROM coherence.input_versions
          WHERE id = NEW.published_input_version_id AND line_kind = 'standing'
            AND source_kind = 'carry_approvals' AND parent_id = v_prev_standing_id AND journal_seq = NEW.journal_seq
        ) THEN
          RAISE EXCEPTION 'approvals carry must publish the next standing input_version in the same journal entry'
            USING ERRCODE = '23514';
        END IF;
      END IF;
    ELSE
      IF NEW.nothing_new OR NEW.published_input_version_id IS NULL THEN
        RAISE EXCEPTION 'first approvals carry must publish the next standing input_version'
          USING ERRCODE = '23514';
      END IF;
      IF v_prev_standing_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM coherence.input_versions
        WHERE id = NEW.published_input_version_id AND line_kind = 'standing'
          AND source_kind = 'carry_approvals' AND parent_id = v_prev_standing_id AND journal_seq = NEW.journal_seq
      ) THEN
        RAISE EXCEPTION 'approvals carry must publish the next standing input_version in the same journal entry'
          USING ERRCODE = '23514';
      END IF;
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

-- 9. Update run_latest_journal_seq and run_states to cover decision records and generated overlays.
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
  EXISTS (SELECT 1 FROM coherence.carries c WHERE c.run_id = r.id AND c.carry_kind IN ('approvals', 'decisions')) AS approvals_carried,
  EXISTS (SELECT 1 FROM coherence.abandonments a WHERE a.run_id = r.id) AS abandoned,
  r.prior_decision_commit_id
FROM coherence.runs r;
