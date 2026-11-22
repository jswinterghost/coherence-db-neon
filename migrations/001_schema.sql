-- Core tables for a company database. Every business table is append-only; immutability triggers live in 002_invariants_and_triggers.sql.

CREATE SCHEMA IF NOT EXISTS coherence;

CREATE TABLE coherence.journal_entries (
  seq BIGINT PRIMARY KEY CHECK (seq >= 1),
  recorded_at TIMESTAMPTZ NOT NULL,
  actor TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(actor)) > 0 AND actor !~ '[\x01-\x1f\x7f]'),
  acting_for TEXT CHECK (acting_for IS NULL OR (pg_catalog.length(pg_catalog.btrim(acting_for)) > 0 AND acting_for !~ '[\x01-\x1f\x7f]')),
  command_kind TEXT NOT NULL CHECK (command_kind ~ '^[a-z][a-z0-9_]{1,63}$'),
  command_key TEXT NOT NULL UNIQUE CHECK (pg_catalog.length(command_key) BETWEEN 1 AND 200 AND command_key !~ '[\x01-\x1f\x7f]'),
  request_sha256 TEXT NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
  body JSONB NOT NULL CHECK (pg_catalog.jsonb_typeof(body) = 'object'),
  prev_hash TEXT NOT NULL UNIQUE CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
  entry_hash TEXT NOT NULL UNIQUE CHECK (entry_hash ~ '^[0-9a-f]{64}$'),
  created_xid xid8 NOT NULL DEFAULT pg_catalog.pg_current_xact_id()
);

CREATE INDEX journal_entries_recorded_at_idx ON coherence.journal_entries (recorded_at, seq);
CREATE INDEX journal_entries_command_kind_idx ON coherence.journal_entries (command_kind, seq);

CREATE TABLE coherence.company_meta (
  singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton = true),
  company_slug TEXT NOT NULL CHECK (company_slug ~ '^[a-z][a-z0-9_-]{1,63}$'),
  display_name TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(display_name)) > 0),
  default_emit_mode TEXT NOT NULL CHECK (default_emit_mode IN ('coherence', 'builtin', 'generated')),
  default_emit_display TEXT,
  default_emit_keep TEXT[] NOT NULL DEFAULT '{}',
  default_emit_no_manager TEXT[] NOT NULL DEFAULT '{}',
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  CHECK (
    (default_emit_mode = 'generated' AND default_emit_display IS NOT NULL AND pg_catalog.length(pg_catalog.btrim(default_emit_display)) > 0)
    OR (default_emit_mode <> 'generated' AND default_emit_display IS NULL AND pg_catalog.cardinality(default_emit_keep) = 0 AND pg_catalog.cardinality(default_emit_no_manager) = 0)
  )
);

CREATE TABLE coherence.stored_files (
  store_kind TEXT NOT NULL CHECK (store_kind IN ('nusear_code', 'company_data')),
  sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  byte_size BIGINT NOT NULL CHECK (byte_size >= 0),
  md5_b64 TEXT NOT NULL CHECK (md5_b64 ~ '^[A-Za-z0-9+/]{22}==$'),
  crc32c_b64 TEXT NOT NULL CHECK (crc32c_b64 ~ '^[A-Za-z0-9+/]{6}==$'),
  object_name TEXT NOT NULL CHECK (object_name = 'objects/' || sha256),
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  PRIMARY KEY (store_kind, sha256)
);

CREATE INDEX stored_files_journal_seq_idx ON coherence.stored_files (journal_seq);

-- Engine versions store fingerprints and metadata only; executable bytes live solely in the nusear_code store.
CREATE TABLE coherence.engine_versions (
  id UUID PRIMARY KEY,
  label TEXT NOT NULL UNIQUE CHECK (pg_catalog.length(pg_catalog.btrim(label)) > 0),
  coherence_commit TEXT NOT NULL CHECK (coherence_commit ~ '^[0-9a-f]{7,40}$'),
  store_kind TEXT NOT NULL DEFAULT 'nusear_code' CHECK (store_kind = 'nusear_code'),
  git_bundle_sha256 TEXT NOT NULL CHECK (git_bundle_sha256 ~ '^[0-9a-f]{64}$'),
  code_manifest_sha256 TEXT NOT NULL CHECK (code_manifest_sha256 ~ '^[0-9a-f]{64}$'),
  python_lock_sha256 TEXT NOT NULL CHECK (python_lock_sha256 ~ '^[0-9a-f]{64}$'),
  python_wheels_sha256 TEXT NOT NULL CHECK (python_wheels_sha256 ~ '^[0-9a-f]{64}$'),
  web_lock_sha256 TEXT NOT NULL CHECK (web_lock_sha256 ~ '^[0-9a-f]{64}$'),
  web_packages_sha256 TEXT NOT NULL CHECK (web_packages_sha256 ~ '^[0-9a-f]{64}$'),
  wrapper_bundle_sha256 TEXT NOT NULL CHECK (wrapper_bundle_sha256 ~ '^[0-9a-f]{64}$'),
  nusear_commit TEXT NOT NULL CHECK (nusear_commit ~ '^[0-9a-f]{7,40}$'),
  company_emit_sha256 TEXT NOT NULL CHECK (company_emit_sha256 ~ '^[0-9a-f]{64}$'),
  pages_law_sha256 TEXT NOT NULL CHECK (pages_law_sha256 ~ '^[0-9a-f]{64}$'),
  overlay_check_sha256 TEXT NOT NULL CHECK (overlay_check_sha256 ~ '^[0-9a-f]{64}$'),
  toolchain JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(toolchain) = 'object'
    AND toolchain ? 'os'
    AND toolchain ? 'os_version'
    AND toolchain ? 'arch'
    AND toolchain ? 'python'
    AND toolchain ? 'uv'
    AND toolchain ? 'node'
    AND toolchain ? 'pnpm'
    AND toolchain ? 'tz'
    AND toolchain ? 'lang'
    AND toolchain ? 'lc_all'
    AND toolchain ? 'pythonutf8'
  ),
  container_digest TEXT,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  FOREIGN KEY (store_kind, git_bundle_sha256) REFERENCES coherence.stored_files(store_kind, sha256),
  FOREIGN KEY (store_kind, code_manifest_sha256) REFERENCES coherence.stored_files(store_kind, sha256),
  FOREIGN KEY (store_kind, python_lock_sha256) REFERENCES coherence.stored_files(store_kind, sha256),
  FOREIGN KEY (store_kind, python_wheels_sha256) REFERENCES coherence.stored_files(store_kind, sha256),
  FOREIGN KEY (store_kind, web_lock_sha256) REFERENCES coherence.stored_files(store_kind, sha256),
  FOREIGN KEY (store_kind, web_packages_sha256) REFERENCES coherence.stored_files(store_kind, sha256),
  FOREIGN KEY (store_kind, wrapper_bundle_sha256) REFERENCES coherence.stored_files(store_kind, sha256)
);

CREATE INDEX engine_versions_journal_seq_idx ON coherence.engine_versions (journal_seq);

-- Input versions belong to either the company's linear standing line or an unchained historical snapshot.
CREATE TABLE coherence.input_versions (
  id UUID PRIMARY KEY,
  line_kind TEXT NOT NULL CHECK (line_kind IN ('standing', 'snapshot')),
  parent_id UUID REFERENCES coherence.input_versions(id),
  source_kind TEXT NOT NULL CHECK (source_kind IN (
    'upload', 'include', 'remove', 'rename',
    'mac_import', 'company_import', 'google_list_import',
    'record_sent', 'carry_approvals'
  )),
  reason TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(reason)) > 0),
  entry_count INTEGER NOT NULL CHECK (entry_count >= 0),
  entries_sha256 TEXT NOT NULL CHECK (entries_sha256 ~ '^[0-9a-f]{64}$'),
  entries_list_file_sha256 TEXT CHECK (entries_list_file_sha256 IS NULL OR entries_list_file_sha256 = entries_sha256),
  change_count INTEGER NOT NULL CHECK (change_count >= 0),
  changes_sha256 TEXT NOT NULL CHECK (changes_sha256 ~ '^[0-9a-f]{64}$'),
  store_kind TEXT NOT NULL DEFAULT 'company_data' CHECK (store_kind = 'company_data'),
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  CHECK (line_kind = 'standing' OR parent_id IS NULL),
  CHECK (parent_id IS NULL OR parent_id <> id),
  FOREIGN KEY (store_kind, entries_list_file_sha256) REFERENCES coherence.stored_files(store_kind, sha256)
);

-- Standing line: at most one root and at most one child per parent (strictly linear chain).
CREATE UNIQUE INDEX input_versions_one_standing_root
  ON coherence.input_versions ((true))
  WHERE line_kind = 'standing' AND parent_id IS NULL;

CREATE UNIQUE INDEX input_versions_one_standing_child
  ON coherence.input_versions (parent_id)
  WHERE parent_id IS NOT NULL;

CREATE INDEX input_versions_standing_seq_idx
  ON coherence.input_versions (journal_seq DESC)
  WHERE line_kind = 'standing';

CREATE INDEX input_versions_journal_seq_idx ON coherence.input_versions (journal_seq);

-- Preserve relative paths verbatim without trimming trailing spaces; mac_key enforces case- and NFC-normalized uniqueness.
CREATE TABLE coherence.input_entries (
  input_version_id UUID NOT NULL REFERENCES coherence.input_versions(id),
  rel_path TEXT NOT NULL CHECK (
    pg_catalog.length(rel_path) > 0
    AND rel_path !~ '^/'
    AND rel_path !~ '/$'
    AND rel_path !~ '//'
    AND pg_catalog.strpos(rel_path, '\') = 0
    AND rel_path !~ '[\x01-\x1f\x7f]'
    AND rel_path !~ '(^|/)\.\.?($|/)'
  ),
  mac_key TEXT GENERATED ALWAYS AS (pg_catalog.lower(pg_catalog.normalize(rel_path, 'NFC'))) STORED,
  store_kind TEXT NOT NULL DEFAULT 'company_data' CHECK (store_kind = 'company_data'),
  file_sha256 TEXT NOT NULL CHECK (file_sha256 ~ '^[0-9a-f]{64}$'),
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  PRIMARY KEY (input_version_id, rel_path),
  UNIQUE (input_version_id, mac_key),
  FOREIGN KEY (store_kind, file_sha256) REFERENCES coherence.stored_files(store_kind, sha256)
);

CREATE INDEX input_entries_journal_seq_idx ON coherence.input_entries (journal_seq);
CREATE INDEX input_entries_file_idx ON coherence.input_entries (file_sha256);

CREATE TABLE coherence.input_changes (
  input_version_id UUID NOT NULL REFERENCES coherence.input_versions(id),
  rel_path TEXT NOT NULL CHECK (pg_catalog.length(rel_path) > 0),
  change_kind TEXT NOT NULL CHECK (change_kind IN ('added', 'removed', 'renamed', 'replaced')),
  old_rel_path TEXT CHECK (old_rel_path IS NULL OR pg_catalog.length(old_rel_path) > 0),
  store_kind TEXT NOT NULL DEFAULT 'company_data' CHECK (store_kind = 'company_data'),
  file_sha256 TEXT CHECK (file_sha256 IS NULL OR file_sha256 ~ '^[0-9a-f]{64}$'),
  prev_file_sha256 TEXT CHECK (prev_file_sha256 IS NULL OR prev_file_sha256 ~ '^[0-9a-f]{64}$'),
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  PRIMARY KEY (input_version_id, rel_path),
  CHECK (
    (change_kind = 'added' AND old_rel_path IS NULL AND file_sha256 IS NOT NULL AND prev_file_sha256 IS NULL)
    OR (change_kind = 'removed' AND old_rel_path IS NULL AND file_sha256 IS NULL AND prev_file_sha256 IS NOT NULL)
    OR (change_kind = 'renamed' AND old_rel_path IS NOT NULL AND old_rel_path <> rel_path AND file_sha256 IS NOT NULL AND prev_file_sha256 IS NULL)
    OR (change_kind = 'replaced' AND old_rel_path IS NULL AND file_sha256 IS NOT NULL AND prev_file_sha256 IS NOT NULL AND file_sha256 <> prev_file_sha256)
  ),
  FOREIGN KEY (store_kind, file_sha256) REFERENCES coherence.stored_files(store_kind, sha256),
  FOREIGN KEY (store_kind, prev_file_sha256) REFERENCES coherence.stored_files(store_kind, sha256)
);

CREATE UNIQUE INDEX input_changes_one_rename_old
  ON coherence.input_changes (input_version_id, old_rel_path)
  WHERE old_rel_path IS NOT NULL;

CREATE INDEX input_changes_journal_seq_idx ON coherence.input_changes (journal_seq);

CREATE TABLE coherence.approvals_files (
  file_sha256 TEXT PRIMARY KEY CHECK (file_sha256 ~ '^[0-9a-f]{64}$'),
  store_kind TEXT NOT NULL DEFAULT 'company_data' CHECK (store_kind = 'company_data'),
  header_kind TEXT NOT NULL CHECK (header_kind IN ('v1', 'v2')),
  row_count INTEGER NOT NULL CHECK (row_count >= 0),
  extends_sha256 TEXT REFERENCES coherence.approvals_files(file_sha256),
  shared_row_count INTEGER NOT NULL CHECK (shared_row_count >= 0 AND shared_row_count <= row_count),
  added_rows_sha256 TEXT NOT NULL CHECK (added_rows_sha256 ~ '^[0-9a-f]{64}$'),
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  CHECK (extends_sha256 IS NULL OR extends_sha256 <> file_sha256),
  CHECK (extends_sha256 IS NOT NULL OR shared_row_count = 0),
  FOREIGN KEY (store_kind, file_sha256) REFERENCES coherence.stored_files(store_kind, sha256)
);

CREATE INDEX approvals_files_journal_seq_idx ON coherence.approvals_files (journal_seq);
CREATE INDEX approvals_files_extends_idx ON coherence.approvals_files (extends_sha256);

-- Stores only the newly added rows for each approvals file (numbered from shared_row_count + 1); inherited rows live on ancestor files.
CREATE TABLE coherence.approval_rows (
  approvals_file_sha256 TEXT NOT NULL REFERENCES coherence.approvals_files(file_sha256),
  row_no INTEGER NOT NULL CHECK (row_no >= 1),
  record_id TEXT NOT NULL CHECK (pg_catalog.length(record_id) > 0),
  disposition TEXT,
  agent TEXT,
  agency TEXT,
  policy TEXT,
  book TEXT,
  month TEXT,
  status TEXT,
  note TEXT,
  committed_at TEXT,
  approved_amount TEXT,
  approved_agency TEXT,
  approved_agent TEXT,
  approved_agency_from TEXT,
  approved_agent_from TEXT,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  PRIMARY KEY (approvals_file_sha256, row_no)
);

CREATE INDEX approval_rows_record_id_idx ON coherence.approval_rows (record_id, approvals_file_sha256, row_no);
CREATE INDEX approval_rows_journal_seq_idx ON coherence.approval_rows (journal_seq);

CREATE TABLE coherence.runs (
  id UUID PRIMARY KEY,
  statement_date DATE NOT NULL,
  folder_number INTEGER NOT NULL CHECK (folder_number >= 1),
  origin TEXT NOT NULL CHECK (origin IN ('app', 'trial', 'replay', 'mac_import', 'company_import')),
  input_version_id UUID NOT NULL REFERENCES coherence.input_versions(id),
  prior_approvals_sha256 TEXT REFERENCES coherence.approvals_files(file_sha256),
  engine_version_id UUID REFERENCES coherence.engine_versions(id),
  emit_mode TEXT NOT NULL CHECK (emit_mode IN ('coherence', 'builtin', 'generated')),
  emit_display TEXT,
  emit_keep TEXT[] NOT NULL DEFAULT '{}',
  emit_no_manager TEXT[] NOT NULL DEFAULT '{}',
  replays_run_id UUID REFERENCES coherence.runs(id),
  compared_run_id UUID REFERENCES coherence.runs(id),
  rerun_reason TEXT,
  source_folder TEXT,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  CHECK (
    (origin IN ('app', 'trial', 'replay') AND engine_version_id IS NOT NULL AND source_folder IS NULL)
    OR (origin IN ('mac_import', 'company_import') AND source_folder IS NOT NULL AND pg_catalog.length(pg_catalog.btrim(source_folder)) > 0)
  ),
  CHECK (
    (origin = 'replay' AND replays_run_id IS NOT NULL AND replays_run_id <> id)
    OR (origin <> 'replay' AND replays_run_id IS NULL)
  ),
  CHECK (compared_run_id IS NULL OR compared_run_id <> id),
  CHECK (
    (emit_mode = 'generated' AND emit_display IS NOT NULL AND pg_catalog.length(pg_catalog.btrim(emit_display)) > 0)
    OR (emit_mode <> 'generated' AND emit_display IS NULL AND pg_catalog.cardinality(emit_keep) = 0 AND pg_catalog.cardinality(emit_no_manager) = 0)
  ),
  CHECK (origin <> 'app' OR folder_number = 1 OR (rerun_reason IS NOT NULL AND pg_catalog.length(pg_catalog.btrim(rerun_reason)) > 0))
);

CREATE UNIQUE INDEX runs_unique_app_folder
  ON coherence.runs (statement_date, folder_number)
  WHERE origin = 'app';

CREATE UNIQUE INDEX runs_unique_trial_folder
  ON coherence.runs (statement_date, folder_number)
  WHERE origin = 'trial';

CREATE UNIQUE INDEX runs_unique_import_source
  ON coherence.runs (origin, source_folder)
  WHERE source_folder IS NOT NULL;

CREATE INDEX runs_date_origin_idx ON coherence.runs (statement_date DESC, origin, journal_seq DESC);
CREATE INDEX runs_journal_seq_idx ON coherence.runs (journal_seq);

-- emit_confirmation_id foreign key is added via ALTER TABLE below after coherence.emit_confirmations is declared.
CREATE TABLE coherence.step_requests (
  id UUID PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES coherence.runs(id),
  step TEXT NOT NULL CHECK (step IN ('assign', 'attribute', 'bible', 'adjust', 'emit')),
  reason TEXT NOT NULL CHECK (reason IN ('launch', 'continue', 'bible_saved', 'emit_confirmed', 'retry')),
  emit_confirmation_id UUID,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  CHECK ((step = 'emit' AND emit_confirmation_id IS NOT NULL) OR (step <> 'emit' AND emit_confirmation_id IS NULL)),
  CHECK (reason <> 'launch' OR step = 'assign'),
  CHECK (reason <> 'continue' OR step IN ('attribute', 'bible')),
  CHECK (reason <> 'bible_saved' OR step = 'adjust'),
  CHECK (reason <> 'emit_confirmed' OR step = 'emit')
);

CREATE INDEX step_requests_run_idx ON coherence.step_requests (run_id, journal_seq);
CREATE INDEX step_requests_journal_seq_idx ON coherence.step_requests (journal_seq);

CREATE TABLE coherence.cancel_requests (
  id UUID PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES coherence.runs(id),
  step TEXT NOT NULL CHECK (step IN ('assign', 'attribute', 'bible', 'adjust', 'emit')),
  attempt_no INTEGER NOT NULL CHECK (attempt_no >= 1),
  typed_phrase TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(typed_phrase)) > 0),
  reason TEXT NOT NULL DEFAULT '',
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq)
);

CREATE INDEX cancel_requests_run_idx ON coherence.cancel_requests (run_id, step, attempt_no, journal_seq);
CREATE INDEX cancel_requests_journal_seq_idx ON coherence.cancel_requests (journal_seq);

CREATE TABLE coherence.step_attempt_events (
  id UUID PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES coherence.runs(id),
  step TEXT NOT NULL CHECK (step IN ('assign', 'attribute', 'bible', 'adjust', 'emit')),
  attempt_no INTEGER NOT NULL CHECK (attempt_no >= 1),
  event_kind TEXT NOT NULL CHECK (event_kind IN ('started', 'finished', 'failed', 'interrupted', 'cancelled', 'superseded')),
  step_request_id UUID REFERENCES coherence.step_requests(id),
  cancel_request_id UUID REFERENCES coherence.cancel_requests(id),
  slot_backend_pid INTEGER,
  slot_backend_start TIMESTAMPTZ,
  census JSONB,
  born TEXT,
  log_store_kind TEXT CHECK (log_store_kind IS NULL OR log_store_kind = 'company_data'),
  log_file_sha256 TEXT CHECK (log_file_sha256 IS NULL OR log_file_sha256 ~ '^[0-9a-f]{64}$'),
  error_summary TEXT,
  artifact_count INTEGER CHECK (artifact_count IS NULL OR artifact_count >= 0),
  artifacts_sha256 TEXT CHECK (artifacts_sha256 IS NULL OR artifacts_sha256 ~ '^[0-9a-f]{64}$'),
  original_at TIMESTAMPTZ,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  CHECK ((log_file_sha256 IS NULL AND log_store_kind IS NULL) OR (log_file_sha256 IS NOT NULL AND log_store_kind = 'company_data')),
  CHECK (event_kind = 'started' OR step_request_id IS NULL),
  CHECK (event_kind = 'cancelled' OR cancel_request_id IS NULL),
  CHECK (
    (event_kind = 'finished' AND artifact_count IS NOT NULL AND artifacts_sha256 IS NOT NULL)
    OR (event_kind <> 'finished' AND artifact_count IS NULL AND artifacts_sha256 IS NULL)
  ),
  FOREIGN KEY (log_store_kind, log_file_sha256) REFERENCES coherence.stored_files(store_kind, sha256)
);

CREATE UNIQUE INDEX sae_one_start
  ON coherence.step_attempt_events (run_id, step, attempt_no)
  WHERE event_kind = 'started';

CREATE UNIQUE INDEX sae_one_start_per_request
  ON coherence.step_attempt_events (step_request_id)
  WHERE step_request_id IS NOT NULL;

CREATE UNIQUE INDEX sae_one_end
  ON coherence.step_attempt_events (run_id, step, attempt_no)
  WHERE event_kind IN ('finished', 'failed', 'interrupted', 'cancelled');

CREATE UNIQUE INDEX sae_one_superseded
  ON coherence.step_attempt_events (run_id, step, attempt_no)
  WHERE event_kind = 'superseded';

CREATE INDEX sae_run_step_idx ON coherence.step_attempt_events (run_id, step, attempt_no, journal_seq);
CREATE INDEX sae_journal_seq_idx ON coherence.step_attempt_events (journal_seq);

CREATE TABLE coherence.artifacts (
  attempt_event_id UUID NOT NULL REFERENCES coherence.step_attempt_events(id),
  rel_path TEXT NOT NULL CHECK (
    pg_catalog.length(rel_path) > 0
    AND rel_path !~ '^/'
    AND rel_path !~ '/$'
    AND rel_path !~ '//'
    AND pg_catalog.strpos(rel_path, '\') = 0
    AND rel_path !~ '[\x01-\x1f\x7f]'
    AND rel_path !~ '(^|/)\.\.?($|/)'
  ),
  artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('data', 'code_bearing')),
  store_kind TEXT NOT NULL CHECK (
    (artifact_kind = 'code_bearing' AND store_kind = 'nusear_code')
    OR (artifact_kind = 'data' AND store_kind = 'company_data')
  ),
  file_sha256 TEXT NOT NULL CHECK (file_sha256 ~ '^[0-9a-f]{64}$'),
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  PRIMARY KEY (attempt_event_id, rel_path),
  FOREIGN KEY (store_kind, file_sha256) REFERENCES coherence.stored_files(store_kind, sha256)
);

CREATE INDEX artifacts_journal_seq_idx ON coherence.artifacts (journal_seq);
CREATE INDEX artifacts_file_idx ON coherence.artifacts (store_kind, file_sha256);

-- Operational queue table (not an append-only business table); updated once by the worker when resolved.
CREATE TABLE coherence.review_submissions (
  id UUID PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES coherence.runs(id),
  surface TEXT NOT NULL CHECK (surface IN ('bible', 'adjust')),
  staged_sha256 TEXT NOT NULL CHECK (staged_sha256 ~ '^[0-9a-f]{64}$'),
  staged_object_name TEXT NOT NULL CHECK (staged_object_name = 'staging/reviews/' || id::text || '/' || staged_sha256),
  expected_journal_seq BIGINT NOT NULL CHECK (expected_journal_seq >= 0),
  actor TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(actor)) > 0 AND actor !~ '[\x01-\x1f\x7f]'),
  acting_for TEXT CHECK (acting_for IS NULL OR (pg_catalog.length(pg_catalog.btrim(acting_for)) > 0 AND acting_for !~ '[\x01-\x1f\x7f]')),
  command_key TEXT NOT NULL UNIQUE CHECK (pg_catalog.length(command_key) BETWEEN 1 AND 200),
  request_sha256 TEXT NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected', 'failed')),
  review_save_id UUID,
  result_journal_seq BIGINT REFERENCES coherence.journal_entries(seq),
  result_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  resolved_at TIMESTAMPTZ,
  CHECK (
    (status = 'pending' AND review_save_id IS NULL AND result_journal_seq IS NULL AND resolved_at IS NULL)
    OR (status = 'accepted' AND review_save_id IS NOT NULL AND result_journal_seq IS NOT NULL AND resolved_at IS NOT NULL)
    OR (status IN ('rejected', 'failed') AND review_save_id IS NULL AND result_journal_seq IS NULL AND resolved_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX rs_one_pending_per_run
  ON coherence.review_submissions (run_id)
  WHERE status = 'pending';

CREATE INDEX rs_pending_queue_idx ON coherence.review_submissions (created_at) WHERE status = 'pending';

CREATE TABLE coherence.review_saves (
  id UUID PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES coherence.runs(id),
  surface TEXT NOT NULL CHECK (surface IN ('bible', 'adjust')),
  attempt_event_id UUID NOT NULL REFERENCES coherence.step_attempt_events(id),
  approvals_file_sha256 TEXT NOT NULL REFERENCES coherence.approvals_files(file_sha256),
  imported BOOLEAN NOT NULL DEFAULT false,
  original_at TIMESTAMPTZ,
  submission_id UUID UNIQUE,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  CHECK ((imported = true AND submission_id IS NULL) OR (imported = false AND original_at IS NULL))
);

ALTER TABLE coherence.review_submissions
  ADD CONSTRAINT review_submissions_save_fk
  FOREIGN KEY (review_save_id) REFERENCES coherence.review_saves(id);

CREATE INDEX review_saves_run_surface_idx ON coherence.review_saves (run_id, surface, journal_seq DESC);
CREATE INDEX review_saves_attempt_idx ON coherence.review_saves (attempt_event_id, surface);
CREATE INDEX review_saves_journal_seq_idx ON coherence.review_saves (journal_seq);

-- Operational scratchpad for in-progress reviews, keyed by (run_id, surface, attempt_no); never read by calculations.
CREATE TABLE coherence.review_drafts (
  run_id UUID NOT NULL REFERENCES coherence.runs(id),
  surface TEXT NOT NULL CHECK (surface IN ('bible', 'adjust')),
  attempt_no INTEGER NOT NULL CHECK (attempt_no >= 1),
  born TEXT,
  checksum TEXT NOT NULL CHECK (pg_catalog.length(checksum) > 0),
  rows_json JSONB NOT NULL CHECK (pg_catalog.jsonb_typeof(rows_json) = 'array'),
  actor TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(actor)) > 0),
  acting_for TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (pg_catalog.clock_timestamp() + INTERVAL '30 days'),
  PRIMARY KEY (run_id, surface, attempt_no)
);

CREATE INDEX review_drafts_expires_idx ON coherence.review_drafts (expires_at);

CREATE TABLE coherence.emit_confirmations (
  id UUID PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES coherence.runs(id),
  adjust_review_save_id UUID NOT NULL UNIQUE REFERENCES coherence.review_saves(id),
  typed_phrase TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(typed_phrase)) > 0),
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq)
);

ALTER TABLE coherence.step_requests
  ADD CONSTRAINT step_requests_emit_confirmation_fk
  FOREIGN KEY (emit_confirmation_id) REFERENCES coherence.emit_confirmations(id);

CREATE INDEX emit_confirmations_run_idx ON coherence.emit_confirmations (run_id, journal_seq);
CREATE INDEX emit_confirmations_journal_seq_idx ON coherence.emit_confirmations (journal_seq);

CREATE TABLE coherence.carries (
  id UUID PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES coherence.runs(id),
  statement_date DATE NOT NULL,
  carry_kind TEXT NOT NULL CHECK (carry_kind IN ('sent', 'approvals')),
  store_kind TEXT NOT NULL DEFAULT 'company_data' CHECK (store_kind = 'company_data'),
  file_sha256 TEXT NOT NULL CHECK (file_sha256 ~ '^[0-9a-f]{64}$'),
  published_input_version_id UUID REFERENCES coherence.input_versions(id),
  nothing_new BOOLEAN NOT NULL DEFAULT false,
  typed_phrase TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(typed_phrase)) > 0),
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  CHECK (
    (nothing_new = false AND published_input_version_id IS NOT NULL)
    OR (nothing_new = true AND carry_kind = 'approvals' AND published_input_version_id IS NULL)
  ),
  FOREIGN KEY (store_kind, file_sha256) REFERENCES coherence.stored_files(store_kind, sha256)
);

CREATE UNIQUE INDEX carries_one_sent_per_date
  ON coherence.carries (statement_date)
  WHERE carry_kind = 'sent';

CREATE INDEX carries_run_idx ON coherence.carries (run_id, carry_kind);
CREATE INDEX carries_journal_seq_idx ON coherence.carries (journal_seq);

CREATE TABLE coherence.abandonments (
  id UUID PRIMARY KEY,
  run_id UUID NOT NULL UNIQUE REFERENCES coherence.runs(id),
  typed_phrase TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(typed_phrase)) > 0),
  reason TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(reason)) > 0),
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq)
);

CREATE INDEX abandonments_journal_seq_idx ON coherence.abandonments (journal_seq);

-- Standalone historical files that do not belong to any run.
CREATE TABLE coherence.imported_files (
  id UUID PRIMARY KEY,
  area TEXT NOT NULL CHECK (area IN ('incident_report', 'staging', 'documents', 'archive_inventory', 'nusear_log', 'nusear_record', 'other')),
  rel_path TEXT NOT NULL CHECK (
    pg_catalog.length(rel_path) > 0
    AND rel_path !~ '^/'
    AND rel_path !~ '/$'
    AND rel_path !~ '//'
    AND pg_catalog.strpos(rel_path, '\') = 0
    AND rel_path !~ '[\x01-\x1f\x7f]'
    AND rel_path !~ '(^|/)\.\.?($|/)'
  ),
  artifact_kind TEXT NOT NULL DEFAULT 'data' CHECK (artifact_kind IN ('data', 'code_bearing')),
  store_kind TEXT NOT NULL CHECK (
    (artifact_kind = 'code_bearing' AND store_kind = 'nusear_code')
    OR (artifact_kind = 'data' AND store_kind = 'company_data')
  ),
  file_sha256 TEXT NOT NULL CHECK (file_sha256 ~ '^[0-9a-f]{64}$'),
  original_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq),
  UNIQUE (area, rel_path, file_sha256),
  FOREIGN KEY (store_kind, file_sha256) REFERENCES coherence.stored_files(store_kind, sha256)
);

CREATE INDEX imported_files_area_idx ON coherence.imported_files (area, rel_path);
CREATE INDEX imported_files_journal_seq_idx ON coherence.imported_files (journal_seq);

CREATE TABLE coherence.checks (
  id UUID PRIMARY KEY,
  check_kind TEXT NOT NULL CHECK (check_kind IN ('chain', 'commitments', 'objects', 'import', 'replay', 'shadow', 'trial_comparison')),
  run_id UUID REFERENCES coherence.runs(id),
  compared_run_id UUID REFERENCES coherence.runs(id),
  passed BOOLEAN NOT NULL,
  report JSONB NOT NULL CHECK (pg_catalog.jsonb_typeof(report) = 'object'),
  journal_seq BIGINT NOT NULL REFERENCES coherence.journal_entries(seq)
);

CREATE INDEX checks_kind_idx ON coherence.checks (check_kind, journal_seq DESC);
CREATE INDEX checks_run_idx ON coherence.checks (run_id, journal_seq DESC);
CREATE INDEX checks_journal_seq_idx ON coherence.checks (journal_seq);
