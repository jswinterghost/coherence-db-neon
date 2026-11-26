-- Migration 008: Database-only IAM core (Release 1A + Release E2).
-- Installs bootstrap least-privilege roles (including platform_auth_lookup), hash-chained platform.audit_journal,
-- BEFORE INSERT platform_versioner supersession triggers and ENABLE ALWAYS immutability triggers,
-- scoped iam_secret.signing_keys, core iam identity/org/role/right/scope/switch/auth-identity tables,
-- origin/role/control-DB/platform_iam_sync isolation triggers, America/New_York business_today(),
-- HMAC-SHA256 scope-checked session_context(), narrow resolve_auth_identity(), unified org closure and
-- tenant-bounded grant evaluator (no cross-company holding-company grant flow), set-theoretic scope helpers,
-- and deterministic iam.assert_can_write().
-- All functions pin SET search_path = pg_catalog and schema-qualify all references.

CREATE EXTENSION IF NOT EXISTS btree_gist;

CREATE SCHEMA IF NOT EXISTS platform;
CREATE SCHEMA IF NOT EXISTS iam_secret;
CREATE SCHEMA IF NOT EXISTS iam;

-- 1. Bootstrap least-privilege NOLOGIN / NOINHERIT / NOBYPASSRLS roles.
-- Cloud SQL IAM login service accounts use the same role names when pre-provisioned externally.
DO $$
DECLARE
  v_role TEXT;
BEGIN
  FOREACH v_role IN ARRAY ARRAY[
    'platform_view_owner',
    'platform_writer',
    'platform_versioner',
    'platform_app',
    'platform_worker',
    'platform_iam_sync',
    'platform_readonly',
    'platform_migrator',
    'platform_auth_lookup'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
      BEGIN
        EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN NOINHERIT NOBYPASSRLS', v_role);
      EXCEPTION WHEN duplicate_object OR unique_violation OR insufficient_privilege THEN
        NULL;
      END;
    END IF;
  END LOOP;

  -- Fail-closed default on every fresh or reset connection from platform_app.
  -- Check rolconfig first so concurrent migrations on separate databases avoid pg_db_role_setting contention.
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'platform_app'
      AND NOT ('app.session_token=' = ANY(COALESCE(rolconfig, ARRAY[]::text[])))
  ) THEN
    BEGIN
      ALTER ROLE platform_app SET app.session_token = '';
    EXCEPTION WHEN insufficient_privilege OR unique_violation OR internal_error THEN
      NULL;
    END;
  END IF;
END;
$$;

REVOKE ALL ON SCHEMA platform, iam_secret, iam FROM PUBLIC;

-- 2. Platform audit journal and SHA-256 hash chain (exact Release 1A canonical_json serialization).
CREATE OR REPLACE FUNCTION platform.canonical_json(val JSONB)
RETURNS TEXT
LANGUAGE plpgsql IMMUTABLE STRICT
SET search_path = pg_catalog
AS $$
DECLARE
  v_type TEXT := pg_catalog.jsonb_typeof(val);
  v_res TEXT;
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
    SELECT '[' || COALESCE(pg_catalog.string_agg(platform.canonical_json(elem), ',' ORDER BY ord), '') || ']'
    INTO v_res
    FROM pg_catalog.jsonb_array_elements(val) WITH ORDINALITY AS t(elem, ord);
    RETURN v_res;
  ELSIF v_type = 'object' THEN
    SELECT '{' || COALESCE(
      pg_catalog.string_agg(
        pg_catalog.to_json(k)::text || ':' || platform.canonical_json(v),
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

CREATE OR REPLACE FUNCTION platform.sha256_text(input TEXT)
RETURNS TEXT
LANGUAGE sql IMMUTABLE STRICT
SET search_path = pg_catalog
AS $$
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(input, 'UTF8')), 'hex');
$$;

CREATE OR REPLACE FUNCTION platform.format_utc_us(ts TIMESTAMPTZ)
RETURNS TEXT
LANGUAGE sql IMMUTABLE STRICT
SET search_path = pg_catalog
AS $$
  SELECT pg_catalog.to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
$$;

CREATE OR REPLACE FUNCTION platform.compute_journal_hash(
  p_seq BIGINT,
  p_recorded_at TIMESTAMPTZ,
  p_environment TEXT,
  p_actor_person_id UUID,
  p_recorded_as TEXT,
  p_target_org_id UUID,
  p_command_kind TEXT,
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_prev_hash TEXT,
  p_body JSONB
)
RETURNS TEXT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT platform.sha256_text(
    'platform-audit-journal-v1' || E'\n' || platform.canonical_json(
      pg_catalog.jsonb_build_object(
        'actor_person_id', p_actor_person_id,
        'body', p_body,
        'command_key', p_command_key,
        'command_kind', p_command_kind,
        'environment', p_environment,
        'prev_hash', p_prev_hash,
        'recorded_as', p_recorded_as,
        'recorded_at', platform.format_utc_us(p_recorded_at),
        'request_sha256', p_request_sha256,
        'seq', p_seq,
        'target_org_id', p_target_org_id
      )
    )
  );
$$;

CREATE TABLE platform.audit_journal (
  seq BIGINT PRIMARY KEY CHECK (seq >= 1),
  recorded_at TIMESTAMPTZ NOT NULL,
  environment TEXT NOT NULL CHECK (environment IN ('prod', 'dev', 'local')),
  actor_person_id UUID,                     -- FK to iam.people(id) added below; NULL only for service/bootstrap
  recorded_as TEXT NOT NULL CHECK (recorded_as IN ('self', 'nusear_support', 'service')),
  target_org_id UUID,                       -- FK to iam.organizations(id) added below
  command_kind TEXT NOT NULL CHECK (command_kind ~ '^[a-z][a-z0-9_.]{1,80}$'),
  command_key TEXT NOT NULL UNIQUE CHECK (pg_catalog.length(command_key) BETWEEN 1 AND 200),
  request_sha256 TEXT NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
  body JSONB NOT NULL CHECK (pg_catalog.jsonb_typeof(body) = 'object'),
  prev_hash TEXT NOT NULL UNIQUE CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
  entry_hash TEXT NOT NULL UNIQUE CHECK (entry_hash ~ '^[0-9a-f]{64}$'),
  created_xid xid8 NOT NULL DEFAULT pg_catalog.pg_current_xact_id(),
  CHECK (recorded_as = 'service' OR actor_person_id IS NOT NULL)
);
CREATE INDEX audit_journal_recorded_at_idx ON platform.audit_journal (recorded_at, seq);

-- Unconditional immutability trigger for append-only tables.
CREATE OR REPLACE FUNCTION platform.forbid_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'immutable table %.% forbids %', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER trg_immutable
  BEFORE UPDATE OR DELETE OR TRUNCATE ON platform.audit_journal
  FOR EACH STATEMENT EXECUTE FUNCTION platform.forbid_mutation();
ALTER TABLE platform.audit_journal ENABLE ALWAYS TRIGGER trg_immutable;

CREATE OR REPLACE FUNCTION platform.trg_audit_journal_before_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_prev_seq BIGINT;
  v_prev_hash TEXT;
  v_prev_time TIMESTAMPTZ;
  v_expected_seq BIGINT;
  v_expected_prev_hash TEXT;
  v_computed_hash TEXT;
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'serializable' THEN
    RAISE EXCEPTION 'audit_journal writes require SERIALIZABLE isolation (current: %)',
      pg_catalog.current_setting('transaction_isolation')
      USING ERRCODE = '25001';
  END IF;

  IF NEW.created_xid IS DISTINCT FROM pg_catalog.pg_current_xact_id() THEN
    RAISE EXCEPTION 'audit_journal.created_xid must match current transaction id'
      USING ERRCODE = '22023';
  END IF;

  SELECT seq, entry_hash, recorded_at
  INTO v_prev_seq, v_prev_hash, v_prev_time
  FROM platform.audit_journal
  ORDER BY seq DESC
  LIMIT 1;

  IF v_prev_seq IS NULL THEN
    v_expected_seq := 1;
    v_expected_prev_hash := pg_catalog.repeat('0', 64);
  ELSE
    v_expected_seq := v_prev_seq + 1;
    v_expected_prev_hash := v_prev_hash;
  END IF;

  IF NEW.seq IS NULL THEN
    NEW.seq := v_expected_seq;
  ELSIF NEW.seq <> v_expected_seq THEN
    RAISE EXCEPTION 'audit_journal seq must be gapless: expected %, got %', v_expected_seq, NEW.seq
      USING ERRCODE = '22023';
  END IF;

  IF NEW.prev_hash IS NULL THEN
    NEW.prev_hash := v_expected_prev_hash;
  ELSIF NEW.prev_hash <> v_expected_prev_hash THEN
    RAISE EXCEPTION 'audit_journal prev_hash mismatch: expected %, got %', v_expected_prev_hash, NEW.prev_hash
      USING ERRCODE = '22023';
  END IF;

  IF NEW.recorded_at IS NULL THEN
    NEW.recorded_at := GREATEST(pg_catalog.clock_timestamp(), COALESCE(v_prev_time, '-infinity'::timestamptz));
  ELSIF v_prev_time IS NOT NULL AND NEW.recorded_at < v_prev_time THEN
    RAISE EXCEPTION 'audit_journal recorded_at (%) cannot precede previous entry (%)', NEW.recorded_at, v_prev_time
      USING ERRCODE = '22023';
  END IF;

  v_computed_hash := platform.compute_journal_hash(
    NEW.seq, NEW.recorded_at, NEW.environment, NEW.actor_person_id, NEW.recorded_as,
    NEW.target_org_id, NEW.command_kind, NEW.command_key, NEW.request_sha256, NEW.prev_hash, NEW.body
  );

  IF NEW.entry_hash IS NULL THEN
    NEW.entry_hash := v_computed_hash;
  ELSIF NEW.entry_hash <> v_computed_hash THEN
    RAISE EXCEPTION 'audit_journal entry_hash mismatch: expected %, got %', v_computed_hash, NEW.entry_hash
      USING ERRCODE = '22023';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_journal_before_insert
  BEFORE INSERT ON platform.audit_journal
  FOR EACH ROW EXECUTE FUNCTION platform.trg_audit_journal_before_insert();

CREATE OR REPLACE FUNCTION platform.trg_audit_journal_single_row()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_cnt BIGINT;
BEGIN
  SELECT pg_catalog.count(*) INTO v_cnt FROM new_rows;
  IF v_cnt <> 1 THEN
    RAISE EXCEPTION 'audit_journal allows exactly one entry per INSERT statement (got %)', v_cnt
      USING ERRCODE = '22023';
  END IF;
  RETURN NULL;
END;
$$;

CREATE TRIGGER trg_audit_journal_single_row
  AFTER INSERT ON platform.audit_journal
  REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION platform.trg_audit_journal_single_row();

-- Every iam child row must attach to a platform.audit_journal entry created in the current SERIALIZABLE transaction.
CREATE OR REPLACE FUNCTION platform.trg_require_active_journal()
RETURNS TRIGGER
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
  FROM platform.audit_journal
  WHERE seq = NEW.journal_seq;

  IF v_xid IS NULL OR v_xid <> pg_catalog.pg_current_xact_id() THEN
    RAISE EXCEPTION 'cannot attach %.% row to committed or missing audit_journal entry %',
      TG_TABLE_SCHEMA, TG_TABLE_NAME, NEW.journal_seq
      USING ERRCODE = '22023';
  END IF;
  RETURN NEW;
END;
$$;

-- Bitemporal immutability trigger for versioned IAM tables: blocks all DELETE and every UPDATE
-- except platform_versioner stamping (superseded_by_id, superseded_journal_seq) once from NULL.
CREATE OR REPLACE FUNCTION platform.guard_versioned_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'versioned table %.% is immutable: % is forbidden',
      TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP USING ERRCODE = '55000';
  END IF;
  IF CURRENT_USER <> 'platform_versioner'
     OR OLD.superseded_by_id IS NOT NULL
     OR NEW.superseded_by_id IS NULL
     OR NEW.superseded_journal_seq IS NULL
     OR (pg_catalog.to_jsonb(NEW) - 'superseded_by_id' - 'superseded_journal_seq')
        IS DISTINCT FROM
        (pg_catalog.to_jsonb(OLD) - 'superseded_by_id' - 'superseded_journal_seq')
  THEN
    RAISE EXCEPTION 'versioned table %.% forbids modifying business facts or re-superseding rows',
      TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

-- BEFORE INSERT trigger owned by platform_versioner: stamps the replaced row BEFORE the new row
-- enters partial UNIQUE indexes (WHERE superseded_by_id IS NULL) and GiST EXCLUDE constraints.
-- Relies on superseded_by_id FK being DEFERRABLE INITIALLY DEFERRED.
-- Optional trigger args list anchor column names that must match between replaced and replacing rows.
CREATE OR REPLACE FUNCTION platform.stamp_superseded_before_insert()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_rows INT;
  v_id_exists BOOLEAN;
  v_sql TEXT;
  v_new_json JSONB;
  v_col TEXT;
  v_val TEXT;
  i INT;
BEGIN
  IF NEW.superseded_by_id IS NOT NULL OR NEW.superseded_journal_seq IS NOT NULL THEN
    RAISE EXCEPTION 'new versioned row in %.% must start unsuperseded',
      TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '23514';
  END IF;
  IF NEW.id IS NULL THEN
    RAISE EXCEPTION 'new versioned row in %.% requires a non-NULL id',
      TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '23502';
  END IF;
  EXECUTE pg_catalog.format(
    'SELECT EXISTS (SELECT 1 FROM %I.%I WHERE id = $1)',
    TG_TABLE_SCHEMA, TG_TABLE_NAME
  ) INTO v_id_exists USING NEW.id;
  IF v_id_exists THEN
    RAISE EXCEPTION 'row id % already exists in %.%',
      NEW.id, TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '23505';
  END IF;
  IF NEW.replaces_id IS NOT NULL THEN
    IF NEW.replaces_id = NEW.id THEN
      RAISE EXCEPTION 'row % on %.% cannot replace itself',
        NEW.id, TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '23514';
    END IF;
    v_sql := pg_catalog.format(
      'UPDATE %I.%I AS t SET superseded_by_id = $1, superseded_journal_seq = $2 WHERE t.id = $3 AND t.superseded_by_id IS NULL',
      TG_TABLE_SCHEMA, TG_TABLE_NAME
    );
    IF TG_NARGS > 0 THEN
      v_new_json := pg_catalog.to_jsonb(NEW);
      FOR i IN 0 .. TG_NARGS - 1 LOOP
        v_col := TG_ARGV[i];
        v_val := v_new_json ->> v_col;
        IF v_val IS NULL THEN
          v_sql := v_sql || pg_catalog.format(' AND (pg_catalog.to_jsonb(t) ->> %L) IS NULL', v_col);
        ELSE
          v_sql := v_sql || pg_catalog.format(' AND (pg_catalog.to_jsonb(t) ->> %L) = %L', v_col, v_val);
        END IF;
      END LOOP;
    END IF;
    EXECUTE v_sql USING NEW.id, NEW.journal_seq, NEW.replaces_id;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows <> 1 THEN
      RAISE EXCEPTION 'replaces_id % on %.% does not exist, belongs to another anchor, or was already superseded',
        NEW.replaces_id, TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '23505';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
ALTER FUNCTION platform.stamp_superseded_before_insert() OWNER TO platform_versioner;

-- 3. Signing keys (unreadable by platform_app; scoped strictly by principal_origin).
CREATE TABLE iam_secret.signing_keys (
  key_id TEXT PRIMARY KEY CHECK (key_id ~ '^[a-z0-9_-]{4,32}$'),
  secret_bytes BYTEA NOT NULL CHECK (pg_catalog.octet_length(secret_bytes) >= 32),
  environment TEXT NOT NULL CHECK (environment IN ('prod', 'dev', 'local')),
  key_scope TEXT NOT NULL DEFAULT 'company_local' CHECK (key_scope IN ('company_local', 'nusear_staff', 'service')),
  active_from TIMESTAMPTZ NOT NULL,
  active_until TIMESTAMPTZ,
  CHECK (active_until IS NULL OR active_until > active_from)
);

CREATE OR REPLACE FUNCTION iam_secret.trg_verify_signing_key_sync()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF CURRENT_USER = 'platform_iam_sync'
     AND (NEW.key_scope = 'company_local' OR (TG_OP = 'UPDATE' AND OLD.key_scope = 'company_local'))
  THEN
    RAISE EXCEPTION 'SYNC_FORBIDDEN_KEY_SCOPE: platform_iam_sync cannot write or modify company_local signing keys.'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_00_verify_signing_key_sync
  BEFORE INSERT OR UPDATE ON iam_secret.signing_keys
  FOR EACH ROW EXECUTE FUNCTION iam_secret.trg_verify_signing_key_sync();

ALTER TABLE iam_secret.signing_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY signing_keys_platform_iam_sync_sel ON iam_secret.signing_keys
  FOR SELECT TO platform_iam_sync
  USING (key_scope IN ('nusear_staff', 'service'));

CREATE POLICY signing_keys_platform_iam_sync_ins ON iam_secret.signing_keys
  FOR INSERT TO platform_iam_sync
  WITH CHECK (key_scope IN ('nusear_staff', 'service'));

CREATE POLICY signing_keys_platform_iam_sync_upd ON iam_secret.signing_keys
  FOR UPDATE TO platform_iam_sync
  USING (key_scope IN ('nusear_staff', 'service'))
  WITH CHECK (key_scope IN ('nusear_staff', 'service'));

-- Pure-SQL RFC 2104 HMAC-SHA256 using built-in pg_catalog.sha256 (zero external C extensions).
CREATE OR REPLACE FUNCTION iam_secret.hmac_sha256_hex(p_key BYTEA, p_msg TEXT)
RETURNS TEXT
LANGUAGE plpgsql IMMUTABLE STRICT
SET search_path = pg_catalog
AS $$
DECLARE
  v_key BYTEA := CASE WHEN pg_catalog.octet_length(p_key) > 64
                      THEN pg_catalog.sha256(p_key) ELSE p_key END;
  v_padded BYTEA := v_key || pg_catalog.decode(pg_catalog.repeat('00', 64 - pg_catalog.octet_length(v_key)), 'hex');
  v_ipad BYTEA := ''::bytea;
  v_opad BYTEA := ''::bytea;
  v_b INT;
  i INT;
BEGIN
  FOR i IN 0..63 LOOP
    v_b := pg_catalog.get_byte(v_padded, i);
    v_ipad := v_ipad || pg_catalog.set_byte('\x00'::bytea, 0, v_b # 54);
    v_opad := v_opad || pg_catalog.set_byte('\x00'::bytea, 0, v_b # 92);
  END LOOP;
  RETURN pg_catalog.encode(
    pg_catalog.sha256(v_opad || pg_catalog.sha256(v_ipad || pg_catalog.convert_to(p_msg, 'UTF8'))),
    'hex'
  );
END;
$$;

-- 4. Core IAM tables (all 17 tables in schema iam are strictly append-only).

-- Immutable one-row identity of this database instance (env never supplied by app code).
CREATE TABLE iam.database_context (
  singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton = true),
  environment TEXT NOT NULL CHECK (environment IN ('prod', 'dev', 'local')),
  db_role_kind TEXT NOT NULL CHECK (db_role_kind IN ('control', 'company_working')),
  tenant_org_id UUID,
  company_slug TEXT CHECK (company_slug IS NULL OR company_slug ~ '^[a-z0-9][a-z0-9_-]{0,47}$'),
  support_external_label TEXT NOT NULL DEFAULT 'Nusear support' CHECK (pg_catalog.length(pg_catalog.btrim(support_external_label)) > 0),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  CHECK ((db_role_kind = 'control' AND tenant_org_id IS NULL AND company_slug IS NULL)
      OR (db_role_kind = 'company_working' AND tenant_org_id IS NOT NULL AND company_slug IS NOT NULL))
);

-- Tools catalog.
CREATE TABLE iam.tools (
  id TEXT PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9_-]{1,48}$'),
  display_name TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(display_name)) > 0),
  is_nusear_only BOOLEAN NOT NULL DEFAULT false,
  is_customer_switchable BOOLEAN NOT NULL DEFAULT true,
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq)
);

-- Organizations: opaque UUID anchor (zero name/slug semantics here so later aliasing never leaks).
CREATE TABLE iam.organizations (
  id UUID PRIMARY KEY,
  org_kind TEXT NOT NULL CHECK (org_kind IN (
    'platform_root', 'company', 'agency', 'team', 'lead_vendor', 'referral_firm'
  )),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq)
);

CREATE TABLE iam.organization_versions (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES iam.organizations(id),
  slug TEXT NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9_-]{0,47}$'),
  display_name TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(display_name)) > 0),
  external_domain TEXT,
  status TEXT NOT NULL CHECK (status IN ('active', 'archived')),
  replaces_id UUID UNIQUE REFERENCES iam.organization_versions(id),
  superseded_by_id UUID UNIQUE,
  superseded_journal_seq BIGINT REFERENCES platform.audit_journal(seq),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  UNIQUE (id, replaces_id),
  FOREIGN KEY (superseded_by_id, id) REFERENCES iam.organization_versions(id, replaces_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK (replaces_id IS NULL OR replaces_id <> id),
  CHECK (superseded_by_id IS NULL OR superseded_by_id <> id),
  CHECK ((superseded_by_id IS NULL) = (superseded_journal_seq IS NULL))
);
CREATE UNIQUE INDEX org_versions_one_live
  ON iam.organization_versions (organization_id) WHERE superseded_by_id IS NULL;
CREATE UNIQUE INDEX org_versions_live_slug_uniq
  ON iam.organization_versions (slug) WHERE superseded_by_id IS NULL AND status = 'active';

-- Dated organization hierarchy (3NF adjacency list; arbitrary depth; one parent per org per day).
CREATE TABLE iam.organization_edges (
  id UUID PRIMARY KEY,
  child_org_id UUID NOT NULL REFERENCES iam.organizations(id),
  parent_org_id UUID NOT NULL REFERENCES iam.organizations(id),
  valid_range DATERANGE NOT NULL CHECK (NOT pg_catalog.isempty(valid_range) AND pg_catalog.lower_inc(valid_range) AND NOT pg_catalog.upper_inc(valid_range)),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  replaces_id UUID UNIQUE REFERENCES iam.organization_edges(id),
  superseded_by_id UUID UNIQUE,
  superseded_journal_seq BIGINT REFERENCES platform.audit_journal(seq),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  UNIQUE (id, replaces_id),
  FOREIGN KEY (superseded_by_id, id) REFERENCES iam.organization_edges(id, replaces_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK (child_org_id <> parent_org_id),
  CHECK (replaces_id IS NULL OR replaces_id <> id),
  CHECK (superseded_by_id IS NULL OR superseded_by_id <> id),
  CHECK ((superseded_by_id IS NULL) = (superseded_journal_seq IS NULL)),
  CONSTRAINT org_edges_one_parent_per_day
    EXCLUDE USING gist (child_org_id WITH =, valid_range WITH &&)
    WHERE (superseded_by_id IS NULL AND status = 'active')
);
CREATE INDEX org_edges_parent_live_idx ON iam.organization_edges (parent_org_id, child_org_id)
  WHERE superseded_by_id IS NULL AND status = 'active';

-- People (company-local humans/house accounts, mirrored Nusear staff, and service principals; zero Medicare member PHI).
CREATE TABLE iam.people (
  id UUID PRIMARY KEY,
  person_kind TEXT NOT NULL CHECK (person_kind IN ('human', 'house_account', 'service')),
  principal_origin TEXT NOT NULL DEFAULT 'company_local' CHECK (principal_origin IN ('company_local', 'nusear_staff', 'service')),
  house_org_id UUID REFERENCES iam.organizations(id),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  UNIQUE (id, principal_origin),
  CHECK ((person_kind = 'house_account' AND house_org_id IS NOT NULL)
      OR (person_kind <> 'house_account' AND house_org_id IS NULL)),
  CHECK ((person_kind = 'service') = (principal_origin = 'service')),
  CHECK (person_kind <> 'house_account' OR principal_origin = 'company_local')
);

CREATE TABLE iam.person_versions (
  id UUID PRIMARY KEY,
  person_id UUID NOT NULL REFERENCES iam.people(id),
  principal_origin TEXT NOT NULL DEFAULT 'company_local' CHECK (principal_origin IN ('company_local', 'nusear_staff', 'service')),
  legal_name TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(legal_name)) > 0),
  preferred_name TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(preferred_name)) > 0),
  primary_email TEXT CHECK (primary_email IS NULL OR primary_email = pg_catalog.lower(pg_catalog.btrim(primary_email))),
  npn TEXT CHECK (npn IS NULL OR npn ~ '^[0-9]{1,10}$'),
  status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'archived')),
  replaces_id UUID UNIQUE REFERENCES iam.person_versions(id),
  superseded_by_id UUID UNIQUE,
  superseded_journal_seq BIGINT REFERENCES platform.audit_journal(seq),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  UNIQUE (id, replaces_id),
  FOREIGN KEY (person_id, principal_origin) REFERENCES iam.people(id, principal_origin),
  FOREIGN KEY (superseded_by_id, id) REFERENCES iam.person_versions(id, replaces_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK (replaces_id IS NULL OR replaces_id <> id),
  CHECK (superseded_by_id IS NULL OR superseded_by_id <> id),
  CHECK ((superseded_by_id IS NULL) = (superseded_journal_seq IS NULL))
);
CREATE UNIQUE INDEX person_versions_one_live
  ON iam.person_versions (person_id) WHERE superseded_by_id IS NULL;
CREATE UNIQUE INDEX person_versions_unique_live_email
  ON iam.person_versions (principal_origin, primary_email) WHERE superseded_by_id IS NULL AND primary_email IS NOT NULL;
CREATE UNIQUE INDEX person_versions_unique_live_npn
  ON iam.person_versions (principal_origin, npn) WHERE superseded_by_id IS NULL AND npn IS NOT NULL;

-- Per-company sign-in identities (e.g., each company's own Clerk issuer + subject mapped to its own people only).
CREATE TABLE iam.person_auth_identities (
  id UUID PRIMARY KEY,
  person_id UUID NOT NULL REFERENCES iam.people(id),
  principal_origin TEXT NOT NULL DEFAULT 'company_local' CHECK (principal_origin IN ('company_local', 'nusear_staff')),
  auth_issuer TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(auth_issuer)) BETWEEN 1 AND 255 AND auth_issuer = pg_catalog.btrim(auth_issuer)),
  auth_subject TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(auth_subject)) BETWEEN 1 AND 255 AND auth_subject = pg_catalog.btrim(auth_subject)),
  status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
  replaces_id UUID UNIQUE REFERENCES iam.person_auth_identities(id),
  superseded_by_id UUID UNIQUE,
  superseded_journal_seq BIGINT REFERENCES platform.audit_journal(seq),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  UNIQUE (id, replaces_id),
  FOREIGN KEY (person_id, principal_origin) REFERENCES iam.people(id, principal_origin),
  FOREIGN KEY (superseded_by_id, id) REFERENCES iam.person_auth_identities(id, replaces_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK (replaces_id IS NULL OR replaces_id <> id),
  CHECK (superseded_by_id IS NULL OR superseded_by_id <> id),
  CHECK ((superseded_by_id IS NULL) = (superseded_journal_seq IS NULL))
);
CREATE UNIQUE INDEX person_auth_identities_live_issuer_sub_uniq
  ON iam.person_auth_identities (auth_issuer, auth_subject)
  WHERE superseded_by_id IS NULL AND status IN ('active', 'suspended');
CREATE INDEX person_auth_identities_person_live_idx
  ON iam.person_auth_identities (person_id)
  WHERE superseded_by_id IS NULL AND status = 'active';

-- Dated non-agent memberships (grants nothing by itself; selling-agent membership derived from agent_affiliations).
CREATE TABLE iam.organization_memberships (
  id UUID PRIMARY KEY,
  person_id UUID NOT NULL REFERENCES iam.people(id),
  organization_id UUID NOT NULL REFERENCES iam.organizations(id),
  capacity TEXT NOT NULL CHECK (capacity IN (
    'owner', 'employee', 'consultant', 'investor', 'vendor_rep', 'referral_partner'
  )),
  valid_range DATERANGE NOT NULL CHECK (NOT pg_catalog.isempty(valid_range) AND pg_catalog.lower_inc(valid_range) AND NOT pg_catalog.upper_inc(valid_range)),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  replaces_id UUID UNIQUE REFERENCES iam.organization_memberships(id),
  superseded_by_id UUID UNIQUE,
  superseded_journal_seq BIGINT REFERENCES platform.audit_journal(seq),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  UNIQUE (id, replaces_id),
  FOREIGN KEY (superseded_by_id, id) REFERENCES iam.organization_memberships(id, replaces_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK (replaces_id IS NULL OR replaces_id <> id),
  CHECK (superseded_by_id IS NULL OR superseded_by_id <> id),
  CHECK ((superseded_by_id IS NULL) = (superseded_journal_seq IS NULL)),
  CONSTRAINT org_memberships_no_overlap
    EXCLUDE USING gist (person_id WITH =, organization_id WITH =, capacity WITH =, valid_range WITH &&)
    WHERE (superseded_by_id IS NULL AND status = 'active')
);
CREATE INDEX org_memberships_person_live_idx ON iam.organization_memberships (person_id, organization_id)
  WHERE superseded_by_id IS NULL AND status = 'active';

-- Dated selling-agent affiliations (one agency per NPN + carrier_scope per day; NULL carrier_id = captive).
CREATE TABLE iam.agent_affiliations (
  id UUID PRIMARY KEY,
  person_id UUID NOT NULL REFERENCES iam.people(id),
  npn TEXT NOT NULL CHECK (npn ~ '^[0-9]{1,10}$'),
  agency_org_id UUID NOT NULL REFERENCES iam.organizations(id),
  carrier_id UUID,                          -- FK to core.carriers(id) added in later release
  carrier_scope_key UUID GENERATED ALWAYS AS (
    COALESCE(carrier_id, '00000000-0000-0000-0000-000000000000'::uuid)
  ) STORED,
  split_bps INTEGER NOT NULL CHECK (split_bps BETWEEN 0 AND 10000),
  agent_file_name TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(agent_file_name)) > 0),
  valid_range DATERANGE NOT NULL CHECK (NOT pg_catalog.isempty(valid_range) AND pg_catalog.lower_inc(valid_range) AND NOT pg_catalog.upper_inc(valid_range)),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  replaces_id UUID UNIQUE REFERENCES iam.agent_affiliations(id),
  superseded_by_id UUID UNIQUE,
  superseded_journal_seq BIGINT REFERENCES platform.audit_journal(seq),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  UNIQUE (id, replaces_id),
  FOREIGN KEY (superseded_by_id, id) REFERENCES iam.agent_affiliations(id, replaces_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK (replaces_id IS NULL OR replaces_id <> id),
  CHECK (superseded_by_id IS NULL OR superseded_by_id <> id),
  CHECK ((superseded_by_id IS NULL) = (superseded_journal_seq IS NULL)),
  CONSTRAINT agent_affiliations_no_overlap
    EXCLUDE USING gist (npn WITH =, carrier_scope_key WITH =, valid_range WITH &&)
    WHERE (superseded_by_id IS NULL AND status = 'active')
);
CREATE INDEX agent_affiliations_person_live_idx ON iam.agent_affiliations (person_id, agency_org_id)
  WHERE superseded_by_id IS NULL AND status = 'active';

-- Rights catalog: atomic action rights and column rights.
CREATE TABLE iam.rights (
  id TEXT PRIMARY KEY CHECK (id ~ '^(act|col):[a-z][a-z0-9_.*-]{1,120}$'),
  right_kind TEXT NOT NULL CHECK (right_kind IN ('action', 'column')),
  tool_id TEXT NOT NULL REFERENCES iam.tools(id),
  environment_scope TEXT NOT NULL DEFAULT 'both' CHECK (environment_scope IN ('both', 'prod_only', 'dev_only')),
  sensitivity_class TEXT NOT NULL CHECK (sensitivity_class IN (
    'ordinary', 'vendor_identity', 'internal_id',
    'money_lead', 'money_pay', 'money_statement', 'money_upline', 'money_operating',
    'recording', 'caller_phone', 'member_contact', 'member_phi', 'staff_free_text', 'platform_internal'
  )),
  is_delegable_power BOOLEAN NOT NULL DEFAULT true,
  target_schema TEXT,
  target_table TEXT,
  target_column TEXT,
  description TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(description)) > 0),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  CHECK ((right_kind = 'column' AND target_schema IS NOT NULL AND target_table IS NOT NULL AND target_column IS NOT NULL)
      OR (right_kind = 'action' AND target_schema IS NULL AND target_table IS NULL AND target_column IS NULL))
);
CREATE UNIQUE INDEX rights_unique_column_target
  ON iam.rights (target_schema, target_table, target_column) WHERE right_kind = 'column';

-- Append-only right retirements (replaces any mutable retirement column on strictly immutable iam.rights).
CREATE TABLE iam.right_retirements (
  right_id TEXT PRIMARY KEY REFERENCES iam.rights(id),
  reason TEXT CHECK (reason IS NULL OR pg_catalog.length(pg_catalog.btrim(reason)) > 0),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq)
);

-- Roles: named strictly-additive bundles of rights.
CREATE TABLE iam.roles (
  id UUID PRIMARY KEY,
  slug TEXT NOT NULL CHECK (slug ~ '^[a-z][a-z0-9_]{1,48}$'),
  owner_org_id UUID REFERENCES iam.organizations(id), -- NULL = platform built-in; non-NULL = company custom role
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq)
);
CREATE UNIQUE INDEX roles_unique_slug_per_owner
  ON iam.roles (COALESCE(owner_org_id, '00000000-0000-0000-0000-000000000000'::uuid), slug);

CREATE TABLE iam.role_versions (
  id UUID PRIMARY KEY,
  role_id UUID NOT NULL REFERENCES iam.roles(id),
  display_name TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(display_name)) BETWEEN 2 AND 40),
  is_pinned BOOLEAN NOT NULL DEFAULT false,
  is_nusear_internal BOOLEAN NOT NULL DEFAULT false,
  allows_org_wide_scope BOOLEAN NOT NULL DEFAULT false,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  replaces_id UUID UNIQUE REFERENCES iam.role_versions(id),
  superseded_by_id UUID UNIQUE,
  superseded_journal_seq BIGINT REFERENCES platform.audit_journal(seq),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  UNIQUE (id, replaces_id),
  FOREIGN KEY (superseded_by_id, id) REFERENCES iam.role_versions(id, replaces_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK (replaces_id IS NULL OR replaces_id <> id),
  CHECK (superseded_by_id IS NULL OR superseded_by_id <> id),
  CHECK ((superseded_by_id IS NULL) = (superseded_journal_seq IS NULL))
);
CREATE UNIQUE INDEX role_versions_one_live
  ON iam.role_versions (role_id) WHERE superseded_by_id IS NULL;

CREATE TABLE iam.role_rights (
  id UUID PRIMARY KEY,
  role_id UUID NOT NULL REFERENCES iam.roles(id),
  right_id TEXT NOT NULL REFERENCES iam.rights(id),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  replaces_id UUID UNIQUE REFERENCES iam.role_rights(id),
  superseded_by_id UUID UNIQUE,
  superseded_journal_seq BIGINT REFERENCES platform.audit_journal(seq),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  UNIQUE (id, replaces_id),
  FOREIGN KEY (superseded_by_id, id) REFERENCES iam.role_rights(id, replaces_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK (replaces_id IS NULL OR replaces_id <> id),
  CHECK (superseded_by_id IS NULL OR superseded_by_id <> id),
  CHECK ((superseded_by_id IS NULL) = (superseded_journal_seq IS NULL))
);
CREATE UNIQUE INDEX role_rights_live_uniq
  ON iam.role_rights (role_id, right_id) WHERE superseded_by_id IS NULL AND status = 'active';
CREATE INDEX role_rights_by_right_live_idx
  ON iam.role_rights (right_id, role_id) WHERE superseded_by_id IS NULL AND status = 'active';

-- Role grants + scopes: binds person to role at an organization node (flowing down to descendants).
CREATE TABLE iam.role_grants (
  id UUID PRIMARY KEY,
  person_id UUID NOT NULL REFERENCES iam.people(id),
  role_id UUID NOT NULL REFERENCES iam.roles(id),
  organization_id UUID NOT NULL REFERENCES iam.organizations(id),
  include_descendants BOOLEAN NOT NULL DEFAULT true,
  person_scope_mode TEXT NOT NULL CHECK (person_scope_mode IN ('org_subtree', 'self')),
  data_date_range DATERANGE,
  valid_range DATERANGE NOT NULL CHECK (NOT pg_catalog.isempty(valid_range) AND pg_catalog.lower_inc(valid_range) AND NOT pg_catalog.upper_inc(valid_range)),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  replaces_id UUID UNIQUE REFERENCES iam.role_grants(id),
  superseded_by_id UUID UNIQUE,
  superseded_journal_seq BIGINT REFERENCES platform.audit_journal(seq),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  UNIQUE (id, replaces_id),
  FOREIGN KEY (superseded_by_id, id) REFERENCES iam.role_grants(id, replaces_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK (data_date_range IS NULL OR NOT pg_catalog.isempty(data_date_range)),
  CHECK (replaces_id IS NULL OR replaces_id <> id),
  CHECK (superseded_by_id IS NULL OR superseded_by_id <> id),
  CHECK ((superseded_by_id IS NULL) = (superseded_journal_seq IS NULL)),
  CONSTRAINT role_grants_no_overlap
    EXCLUDE USING gist (person_id WITH =, role_id WITH =, organization_id WITH =, valid_range WITH &&)
    WHERE (superseded_by_id IS NULL AND status = 'active')
);
CREATE INDEX role_grants_person_live_idx ON iam.role_grants (person_id, organization_id)
  WHERE superseded_by_id IS NULL AND status = 'active';

-- Per-organization tool switches (versioned, append-only).
CREATE TABLE iam.organization_tool_switches (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES iam.organizations(id),
  tool_id TEXT NOT NULL REFERENCES iam.tools(id),
  switch_state TEXT NOT NULL CHECK (switch_state IN ('on', 'off', 'held', 'preview')),
  hold_reason TEXT,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  replaces_id UUID UNIQUE REFERENCES iam.organization_tool_switches(id),
  superseded_by_id UUID UNIQUE,
  superseded_journal_seq BIGINT REFERENCES platform.audit_journal(seq),
  journal_seq BIGINT NOT NULL REFERENCES platform.audit_journal(seq),
  UNIQUE (id, replaces_id),
  FOREIGN KEY (superseded_by_id, id) REFERENCES iam.organization_tool_switches(id, replaces_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK ((switch_state = 'held' AND hold_reason IS NOT NULL AND pg_catalog.length(pg_catalog.btrim(hold_reason)) > 0) OR (switch_state <> 'held')),
  CHECK (replaces_id IS NULL OR replaces_id <> id),
  CHECK (superseded_by_id IS NULL OR superseded_by_id <> id),
  CHECK ((superseded_by_id IS NULL) = (superseded_journal_seq IS NULL))
);
CREATE UNIQUE INDEX org_tool_switches_live_uniq
  ON iam.organization_tool_switches (organization_id, tool_id)
  WHERE superseded_by_id IS NULL AND status = 'active';

-- Cross-table foreign keys.
ALTER TABLE platform.audit_journal
  ADD CONSTRAINT audit_journal_actor_fk FOREIGN KEY (actor_person_id) REFERENCES iam.people(id),
  ADD CONSTRAINT audit_journal_org_fk FOREIGN KEY (target_org_id) REFERENCES iam.organizations(id);
ALTER TABLE iam.database_context
  ADD CONSTRAINT db_context_tenant_org_fk FOREIGN KEY (tenant_org_id) REFERENCES iam.organizations(id);

-- 5. Attach journal coupling, BEFORE INSERT supersession, and ENABLE ALWAYS immutability triggers.
DO $$
DECLARE
  v_tbl TEXT;
  v_spec TEXT[];
BEGIN
  -- Strictly immutable iam tables (7 tables).
  FOREACH v_tbl IN ARRAY ARRAY[
    'database_context', 'tools', 'organizations', 'people',
    'rights', 'right_retirements', 'roles'
  ] LOOP
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER trg_00_require_active_journal BEFORE INSERT ON iam.%I FOR EACH ROW EXECUTE FUNCTION platform.trg_require_active_journal()',
      v_tbl
    );
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER trg_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON iam.%I FOR EACH STATEMENT EXECUTE FUNCTION platform.forbid_mutation()',
      v_tbl
    );
    EXECUTE pg_catalog.format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER trg_immutable', v_tbl);
  END LOOP;

  -- Versioned append-only iam tables (10 tables): table name + comma-separated anchor columns.
  FOREACH v_spec SLICE 1 IN ARRAY ARRAY[
    ARRAY['organization_versions', '''organization_id'''],
    ARRAY['organization_edges', '''child_org_id'''],
    ARRAY['person_versions', '''person_id'''],
    ARRAY['person_auth_identities', '''person_id'', ''auth_issuer'', ''auth_subject'''],
    ARRAY['organization_memberships', '''person_id'''],
    ARRAY['agent_affiliations', '''person_id'''],
    ARRAY['role_versions', '''role_id'''],
    ARRAY['role_rights', '''role_id'', ''right_id'''],
    ARRAY['role_grants', '''person_id'''],
    ARRAY['organization_tool_switches', '''organization_id'', ''tool_id''']
  ] LOOP
    v_tbl := v_spec[1];
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER trg_00_require_active_journal BEFORE INSERT ON iam.%I FOR EACH ROW EXECUTE FUNCTION platform.trg_require_active_journal()',
      v_tbl
    );
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER trg_01_supersede BEFORE INSERT ON iam.%I FOR EACH ROW EXECUTE FUNCTION platform.stamp_superseded_before_insert(%s)',
      v_tbl, v_spec[2]
    );
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER trg_immutable BEFORE UPDATE OR DELETE ON iam.%I FOR EACH ROW EXECUTE FUNCTION platform.guard_versioned_immutability()',
      v_tbl
    );
    EXECUTE pg_catalog.format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER trg_immutable', v_tbl);
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER trg_immutable_truncate BEFORE TRUNCATE ON iam.%I FOR EACH STATEMENT EXECUTE FUNCTION platform.forbid_mutation()',
      v_tbl
    );
    EXECUTE pg_catalog.format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER trg_immutable_truncate', v_tbl);
  END LOOP;
END;
$$;

-- 6. Domain invariant triggers (org-edge cycle detection, origin/role/control-DB/sync isolation, and allows_org_wide_scope).

CREATE OR REPLACE FUNCTION iam.trg_verify_people_origin()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_kind TEXT;
BEGIN
  IF TG_TABLE_NAME IN ('people', 'person_versions') THEN
    IF CURRENT_USER = 'platform_iam_sync' AND NEW.principal_origin = 'company_local' THEN
      RAISE EXCEPTION 'SYNC_FORBIDDEN_ORIGIN: platform_iam_sync cannot write company_local rows in iam.%.', TG_TABLE_NAME
        USING ERRCODE = '42501';
    END IF;
  ELSIF TG_TABLE_NAME = 'person_auth_identities' THEN
    IF CURRENT_USER = 'platform_iam_sync' THEN
      RAISE EXCEPTION 'SYNC_FORBIDDEN_TABLE: platform_iam_sync cannot write iam.person_auth_identities.'
        USING ERRCODE = '42501';
    END IF;
    SELECT p.person_kind INTO v_kind FROM iam.people p WHERE p.id = NEW.person_id;
    IF v_kind IS DISTINCT FROM 'human' THEN
      RAISE EXCEPTION 'AUTH_IDENTITY_KIND_MISMATCH: only human principals may hold sign-in identities (got %).', v_kind
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_00b_verify_origin
  BEFORE INSERT ON iam.people
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_people_origin();
CREATE TRIGGER trg_00b_verify_origin
  BEFORE INSERT ON iam.person_versions
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_people_origin();
CREATE TRIGGER trg_00b_verify_origin
  BEFORE INSERT ON iam.person_auth_identities
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_people_origin();

CREATE OR REPLACE FUNCTION iam.trg_verify_control_db_origin()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_db_role_kind TEXT;
BEGIN
  SELECT dc.db_role_kind INTO v_db_role_kind
  FROM iam.database_context dc
  WHERE dc.singleton = true;

  IF TG_TABLE_NAME = 'people' THEN
    IF v_db_role_kind = 'control' AND NEW.principal_origin = 'company_local' THEN
      RAISE EXCEPTION 'CONTROL_DB_FORBIDS_COMPANY_LOCAL: control database cannot contain company_local people.'
        USING ERRCODE = '23514';
    END IF;
  ELSIF TG_TABLE_NAME = 'database_context' THEN
    IF NEW.db_role_kind = 'control' AND EXISTS (
      SELECT 1 FROM iam.people p WHERE p.principal_origin = 'company_local'
    ) THEN
      RAISE EXCEPTION 'CONTROL_DB_FORBIDS_COMPANY_LOCAL: control database cannot contain company_local people.'
        USING ERRCODE = '23514';
    END IF;
    IF NEW.db_role_kind = 'company_working' AND EXISTS (
      SELECT 1 FROM iam.person_auth_identities ai
      WHERE ai.principal_origin <> 'company_local'
    ) THEN
      RAISE EXCEPTION 'AUTH_IDENTITY_ORIGIN_MISMATCH: company working database auth identities must belong to company_local people.'
        USING ERRCODE = '23514';
    END IF;
    IF NEW.db_role_kind = 'control' AND EXISTS (
      SELECT 1 FROM iam.person_auth_identities ai
      WHERE ai.principal_origin <> 'nusear_staff'
    ) THEN
      RAISE EXCEPTION 'AUTH_IDENTITY_ORIGIN_MISMATCH: control database auth identities must belong to nusear_staff people.'
        USING ERRCODE = '23514';
    END IF;
  ELSIF TG_TABLE_NAME = 'person_auth_identities' THEN
    IF v_db_role_kind = 'company_working' AND NEW.principal_origin <> 'company_local' THEN
      RAISE EXCEPTION 'AUTH_IDENTITY_ORIGIN_MISMATCH: company working database sign-in identities map to company_local people only.'
        USING ERRCODE = '23514';
    END IF;
    IF v_db_role_kind = 'control' AND NEW.principal_origin <> 'nusear_staff' THEN
      RAISE EXCEPTION 'AUTH_IDENTITY_ORIGIN_MISMATCH: control database sign-in identities map to nusear_staff people only.'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NULL;
END;
$$;
ALTER FUNCTION iam.trg_verify_control_db_origin() OWNER TO platform_readonly;

CREATE CONSTRAINT TRIGGER trg_people_verify_db_origin
  AFTER INSERT ON iam.people
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_control_db_origin();
CREATE CONSTRAINT TRIGGER trg_database_context_verify_db_origin
  AFTER INSERT ON iam.database_context
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_control_db_origin();
CREATE CONSTRAINT TRIGGER trg_person_auth_identities_verify_db_origin
  AFTER INSERT ON iam.person_auth_identities
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_control_db_origin();

CREATE OR REPLACE FUNCTION iam.trg_verify_membership_origin()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_origin TEXT;
  v_org_kind TEXT;
BEGIN
  SELECT p.principal_origin INTO v_origin FROM iam.people p WHERE p.id = NEW.person_id;
  IF TG_TABLE_NAME = 'organization_memberships' THEN
    IF CURRENT_USER = 'platform_iam_sync' AND v_origin = 'company_local' THEN
      RAISE EXCEPTION 'SYNC_FORBIDDEN_ORIGIN: platform_iam_sync cannot write memberships for company_local people.'
        USING ERRCODE = '42501';
    END IF;
    SELECT o.org_kind INTO v_org_kind FROM iam.organizations o WHERE o.id = NEW.organization_id;
    IF v_origin IN ('nusear_staff', 'service') AND v_org_kind <> 'platform_root' THEN
      RAISE EXCEPTION 'ORIGIN_MEMBERSHIP_MISMATCH: % principals may only hold memberships at platform_root.', v_origin
        USING ERRCODE = '23514';
    END IF;
    IF v_origin = 'company_local' AND v_org_kind = 'platform_root' THEN
      RAISE EXCEPTION 'ORIGIN_MEMBERSHIP_MISMATCH: company_local principals cannot hold memberships at platform_root.'
        USING ERRCODE = '23514';
    END IF;
  ELSIF TG_TABLE_NAME = 'agent_affiliations' THEN
    IF CURRENT_USER = 'platform_iam_sync' THEN
      RAISE EXCEPTION 'SYNC_FORBIDDEN_TABLE: platform_iam_sync cannot write iam.agent_affiliations.'
        USING ERRCODE = '42501';
    END IF;
    SELECT o.org_kind INTO v_org_kind FROM iam.organizations o WHERE o.id = NEW.agency_org_id;
    IF v_origin <> 'company_local' THEN
      RAISE EXCEPTION 'ORIGIN_AFFILIATION_MISMATCH: only company_local people may hold agent_affiliations (got %).', v_origin
        USING ERRCODE = '23514';
    END IF;
    IF v_org_kind = 'platform_root' THEN
      RAISE EXCEPTION 'ORIGIN_AFFILIATION_MISMATCH: agent_affiliations cannot target platform_root.'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_00b_verify_origin
  BEFORE INSERT ON iam.organization_memberships
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_membership_origin();
CREATE TRIGGER trg_00b_verify_origin
  BEFORE INSERT ON iam.agent_affiliations
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_membership_origin();

CREATE OR REPLACE FUNCTION iam.trg_verify_sync_role_boundary()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF CURRENT_USER <> 'platform_iam_sync' THEN
    RETURN NEW;
  END IF;

  IF TG_TABLE_NAME = 'roles' THEN
    IF NEW.owner_org_id IS NOT NULL THEN
      RAISE EXCEPTION 'SYNC_FORBIDDEN_CUSTOM_ROLE: platform_iam_sync cannot write company custom roles.'
        USING ERRCODE = '42501';
    END IF;
  ELSIF TG_TABLE_NAME IN ('role_versions', 'role_rights') THEN
    IF EXISTS (SELECT 1 FROM iam.roles r WHERE r.id = NEW.role_id AND r.owner_org_id IS NOT NULL) THEN
      RAISE EXCEPTION 'SYNC_FORBIDDEN_CUSTOM_ROLE: platform_iam_sync cannot write versions or rights for company custom roles.'
        USING ERRCODE = '42501';
    END IF;
  ELSIF TG_TABLE_NAME = 'role_grants' THEN
    IF EXISTS (SELECT 1 FROM iam.people p WHERE p.id = NEW.person_id AND p.principal_origin = 'company_local') THEN
      RAISE EXCEPTION 'SYNC_FORBIDDEN_ORIGIN: platform_iam_sync cannot write role grants for company_local people.'
        USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_00b_verify_sync
  BEFORE INSERT ON iam.roles
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_sync_role_boundary();
CREATE TRIGGER trg_00b_verify_sync
  BEFORE INSERT ON iam.role_versions
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_sync_role_boundary();
CREATE TRIGGER trg_00b_verify_sync
  BEFORE INSERT ON iam.role_rights
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_sync_role_boundary();
CREATE TRIGGER trg_00b_verify_sync
  BEFORE INSERT ON iam.role_grants
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_sync_role_boundary();

CREATE OR REPLACE FUNCTION iam.trg_check_org_edge_no_cycle()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_has_cycle BOOLEAN;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM iam.organization_edges cur
    WHERE cur.id = NEW.id AND cur.superseded_by_id IS NULL AND cur.status = 'active'
  ) THEN
    RETURN NULL;
  END IF;

  WITH RECURSIVE walk(node_id, overlap_range, visited, depth) AS (
    SELECT NEW.child_org_id, NEW.valid_range, ARRAY[NEW.parent_org_id, NEW.child_org_id], 1
    UNION ALL
    SELECT e.child_org_id, walk.overlap_range * e.valid_range, walk.visited || e.child_org_id, walk.depth + 1
    FROM walk
    JOIN iam.organization_edges e
      ON e.parent_org_id = walk.node_id
     AND e.superseded_by_id IS NULL
     AND e.status = 'active'
     AND NOT pg_catalog.isempty(walk.overlap_range * e.valid_range)
    WHERE walk.depth < 64
      AND (e.child_org_id = NEW.parent_org_id OR NOT (e.child_org_id = ANY(walk.visited)))
  )
  SELECT EXISTS (SELECT 1 FROM walk WHERE node_id = NEW.parent_org_id) INTO v_has_cycle;

  IF v_has_cycle THEN
    RAISE EXCEPTION 'ORG_HIERARCHY_CYCLE: organization edge % -> % creates an overlapping-date cycle.',
      NEW.parent_org_id, NEW.child_org_id USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_org_edges_no_cycle
  AFTER INSERT ON iam.organization_edges
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION iam.trg_check_org_edge_no_cycle();

-- Enforce allows_org_wide_scope and origin-role parity on iam.role_grants and iam.role_versions.
CREATE OR REPLACE FUNCTION iam.trg_verify_role_grant_scope()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_origin TEXT;
  v_org_kind TEXT;
  v_rv RECORD;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM iam.role_grants cur
    WHERE cur.id = NEW.id AND cur.superseded_by_id IS NULL AND cur.status = 'active'
  ) THEN
    RETURN NULL;
  END IF;

  SELECT p.principal_origin INTO v_origin FROM iam.people p WHERE p.id = NEW.person_id;
  SELECT o.org_kind INTO v_org_kind FROM iam.organizations o WHERE o.id = NEW.organization_id;
  SELECT rv.allows_org_wide_scope, rv.is_nusear_internal
  INTO v_rv
  FROM iam.role_versions rv
  WHERE rv.role_id = NEW.role_id
    AND rv.superseded_by_id IS NULL
    AND rv.status = 'active';

  IF NEW.person_scope_mode = 'org_subtree' AND COALESCE(v_rv.allows_org_wide_scope, false) = false THEN
    RAISE EXCEPTION 'ORG_WIDE_SCOPE_FORBIDDEN: role % does not allow person_scope_mode = org_subtree.',
      NEW.role_id USING ERRCODE = '23514';
  END IF;

  IF v_rv.is_nusear_internal IS NULL THEN
    RAISE EXCEPTION 'ROLE_NOT_ACTIVE: role % has no active live role_version.',
      NEW.role_id USING ERRCODE = '23514';
  END IF;

  IF (v_origin IN ('nusear_staff', 'service') AND v_rv.is_nusear_internal = false)
     OR (v_origin = 'company_local' AND v_rv.is_nusear_internal = true)
  THEN
    RAISE EXCEPTION 'CROSS_ORIGIN_ROLE_GRANT: principal origin % cannot be granted role % (is_nusear_internal = %).',
      v_origin, NEW.role_id, v_rv.is_nusear_internal USING ERRCODE = '23514';
  END IF;

  IF v_origin = 'company_local' AND v_org_kind = 'platform_root' THEN
    RAISE EXCEPTION 'CROSS_ORIGIN_ROLE_GRANT: company_local principal cannot hold a role grant anchored at platform_root.'
      USING ERRCODE = '23514';
  END IF;

  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_role_grants_verify_scope
  AFTER INSERT ON iam.role_grants
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_role_grant_scope();

CREATE OR REPLACE FUNCTION iam.trg_verify_role_version_invariants()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM iam.role_versions cur
    WHERE cur.id = NEW.id AND cur.superseded_by_id IS NULL
  ) THEN
    RETURN NULL;
  END IF;

  IF NEW.is_nusear_internal = true AND EXISTS (
    SELECT 1 FROM iam.roles r WHERE r.id = NEW.role_id AND r.owner_org_id IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'CROSS_ORIGIN_ROLE_VERSION: company-owned role % cannot set is_nusear_internal = true.',
      NEW.role_id USING ERRCODE = '23514';
  END IF;

  IF NEW.status = 'active' AND NEW.allows_org_wide_scope = false AND EXISTS (
    SELECT 1 FROM iam.role_grants g
    WHERE g.role_id = NEW.role_id
      AND g.superseded_by_id IS NULL
      AND g.status = 'active'
      AND g.person_scope_mode = 'org_subtree'
  ) THEN
    RAISE EXCEPTION 'ORG_WIDE_SCOPE_FORBIDDEN: role % still has live org_subtree grants.',
      NEW.role_id USING ERRCODE = '23514';
  END IF;

  IF NEW.status = 'active' AND EXISTS (
    SELECT 1
    FROM iam.role_grants g
    JOIN iam.people p ON p.id = g.person_id
    WHERE g.role_id = NEW.role_id
      AND g.superseded_by_id IS NULL
      AND g.status = 'active'
      AND (
        (NEW.is_nusear_internal = true AND p.principal_origin = 'company_local')
        OR (NEW.is_nusear_internal = false AND p.principal_origin IN ('nusear_staff', 'service'))
      )
  ) THEN
    RAISE EXCEPTION 'CROSS_ORIGIN_ROLE_GRANT: role % has incompatible live role grants for is_nusear_internal = %.',
      NEW.role_id, NEW.is_nusear_internal USING ERRCODE = '23514';
  END IF;

  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_role_versions_verify_invariants
  AFTER INSERT ON iam.role_versions
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION iam.trg_verify_role_version_invariants();

-- 7. Core IAM functions: Eastern business day, signed token verification, unified org closure,
--    set-theoretic InitPlan scope helpers, and central write guard.

-- Eastern business day (America/New_York; optional p_at parameter supports deterministic DST/midnight verification).
CREATE OR REPLACE FUNCTION iam.business_today(p_at TIMESTAMPTZ DEFAULT pg_catalog.now())
RETURNS DATE
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT (COALESCE(p_at, pg_catalog.now()) AT TIME ZONE 'America/New_York')::date;
$$;

CREATE TYPE iam.verified_session AS (
  session_id UUID,
  actor_person_id UUID,
  view_as_person_id UUID,
  environment TEXT
);

-- Verifies transaction-local app.session_token once per statement; fails closed (NULL) on any mismatch
-- including signing-key scope vs principal_origin.
-- Safe inside BEGIN TRANSACTION READ ONLY (never calls pg_current_xact_id()).
CREATE OR REPLACE FUNCTION iam.session_context()
RETURNS iam.verified_session
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_raw TEXT := NULLIF(pg_catalog.btrim(COALESCE(pg_catalog.current_setting('app.session_token', true), '')), '');
  v_parts TEXT[];
  v_payload TEXT;
  v_key_id TEXT;
  v_env TEXT;
  v_session_id UUID;
  v_actor_id UUID;
  v_view_as_id UUID;
  v_exp_epoch BIGINT;
  v_sig TEXT;
  v_secret BYTEA;
  v_key_scope TEXT;
  v_actor_origin TEXT;
  v_view_as_origin TEXT;
  v_expected_sig TEXT;
  v_db_env TEXT;
  v_diff INT := 0;
  i INT;
BEGIN
  IF v_raw IS NULL THEN RETURN NULL; END IF;
  v_parts := pg_catalog.string_to_array(v_raw, '|');
  IF pg_catalog.array_length(v_parts, 1) <> 8 OR v_parts[1] <> 'v1' THEN RETURN NULL; END IF;

  v_key_id := v_parts[2];
  v_env := v_parts[3];
  BEGIN
    v_session_id := v_parts[4]::uuid;
    v_actor_id := v_parts[5]::uuid;
    v_view_as_id := CASE WHEN v_parts[6] = '-' THEN NULL ELSE v_parts[6]::uuid END;
    v_exp_epoch := v_parts[7]::bigint;
  EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN NULL;
  END;
  v_sig := v_parts[8];
  IF v_sig !~ '^[0-9a-f]{64}$' THEN RETURN NULL; END IF;

  SELECT dc.environment INTO v_db_env FROM iam.database_context dc WHERE dc.singleton = true;
  IF v_db_env IS NULL OR v_env <> v_db_env THEN RETURN NULL; END IF;
  IF pg_catalog.date_part('epoch', pg_catalog.now()) > v_exp_epoch THEN RETURN NULL; END IF;

  SELECT sk.secret_bytes, sk.key_scope INTO v_secret, v_key_scope
  FROM iam_secret.signing_keys sk
  WHERE sk.key_id = v_key_id AND sk.environment = v_db_env
    AND sk.active_from <= pg_catalog.now()
    AND (sk.active_until IS NULL OR sk.active_until > pg_catalog.now());
  IF v_secret IS NULL THEN RETURN NULL; END IF;

  v_payload := v_parts[1] || '|' || v_parts[2] || '|' || v_parts[3] || '|'
            || v_parts[4] || '|' || v_parts[5] || '|' || v_parts[6] || '|' || v_parts[7];
  v_expected_sig := iam_secret.hmac_sha256_hex(v_secret, v_payload);

  FOR i IN 1..64 LOOP
    v_diff := v_diff | (pg_catalog.ascii(pg_catalog.substr(v_sig, i, 1))
                      # pg_catalog.ascii(pg_catalog.substr(v_expected_sig, i, 1)));
  END LOOP;
  IF v_diff <> 0 THEN RETURN NULL; END IF;

  SELECT p.principal_origin INTO v_actor_origin
  FROM iam.people p
  JOIN iam.person_versions pv
    ON pv.person_id = p.id AND pv.superseded_by_id IS NULL AND pv.status = 'active'
  WHERE p.id = v_actor_id;
  IF v_actor_origin IS NULL OR v_actor_origin <> v_key_scope THEN RETURN NULL; END IF;

  IF v_view_as_id IS NOT NULL THEN
    IF v_key_scope = 'service' THEN RETURN NULL; END IF;
    SELECT p.principal_origin INTO v_view_as_origin
    FROM iam.people p
    JOIN iam.person_versions pv
      ON pv.person_id = p.id AND pv.superseded_by_id IS NULL AND pv.status = 'active'
    WHERE p.id = v_view_as_id;
    IF v_view_as_origin IS NULL OR v_view_as_origin = 'service' THEN RETURN NULL; END IF;
    IF v_key_scope = 'company_local' AND v_view_as_origin <> 'company_local' THEN RETURN NULL; END IF;
  END IF;

  RETURN ROW(v_session_id, v_actor_id, v_view_as_id, v_env)::iam.verified_session;
END;
$$;

CREATE OR REPLACE FUNCTION iam.is_viewing_as()
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT COALESCE((SELECT view_as_person_id IS NOT NULL FROM iam.session_context()), false);
$$;

-- Narrow per-company sign-in identity resolver (executable strictly by platform_auth_lookup and owner platform_readonly;
-- never granted to platform_app or PUBLIC). Resolves active human identities strictly within this database's origin boundary.
CREATE OR REPLACE FUNCTION iam.resolve_auth_identity(
  p_auth_issuer TEXT,
  p_auth_subject TEXT
)
RETURNS TABLE (
  person_id UUID,
  principal_origin TEXT,
  company_slug TEXT,
  tenant_org_id UUID,
  environment TEXT
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT
    p.id AS person_id,
    p.principal_origin,
    dc.company_slug,
    dc.tenant_org_id,
    dc.environment
  FROM iam.database_context dc
  JOIN iam.person_auth_identities ai
    ON ai.auth_issuer = p_auth_issuer
   AND ai.auth_subject = p_auth_subject
   AND ai.superseded_by_id IS NULL
   AND ai.status = 'active'
  JOIN iam.people p
    ON p.id = ai.person_id
   AND p.person_kind = 'human'
  JOIN iam.person_versions pv
    ON pv.person_id = p.id
   AND pv.superseded_by_id IS NULL
   AND pv.status = 'active'
  WHERE dc.singleton = true
    AND p_auth_issuer IS NOT NULL
    AND p_auth_subject IS NOT NULL
    AND pg_catalog.length(pg_catalog.btrim(p_auth_issuer)) > 0
    AND pg_catalog.length(pg_catalog.btrim(p_auth_subject)) > 0
    AND (
      (dc.db_role_kind = 'company_working' AND p.principal_origin = 'company_local')
      OR (dc.db_role_kind = 'control' AND p.principal_origin = 'nusear_staff')
    );
$$;
ALTER FUNCTION iam.resolve_auth_identity(TEXT, TEXT) OWNER TO platform_readonly;

-- Internal 3NF live derivation views (never directly readable by platform_app or PUBLIC).
CREATE OR REPLACE VIEW iam.v_all_memberships_live AS
SELECT person_id, organization_id, capacity, valid_range
FROM iam.organization_memberships
WHERE superseded_by_id IS NULL AND status = 'active'
UNION ALL
SELECT person_id, agency_org_id AS organization_id, 'agent'::text AS capacity, valid_range
FROM iam.agent_affiliations
WHERE superseded_by_id IS NULL AND status = 'active';

-- Unified time-consistent organization closure (never directly readable by platform_app or PUBLIC).
-- Each active non-future edge carries a valid_range; a chain from an ancestor down to a descendant
-- counts only for the dates every link in it was true at the same time (carrying the intersection
-- eff_range down the recursion and keeping a chain only while eff_range is non-empty).
-- Detached active orgs (active status with no current live edge anywhere) carry no expired edges.
CREATE OR REPLACE VIEW iam.v_organization_closure AS
WITH RECURSIVE valid_edges AS (
  SELECT
    e.child_org_id,
    e.parent_org_id,
    e.valid_range,
    (cov.status = 'archived') AS is_archived_child
  FROM iam.organization_edges e
  JOIN iam.organization_versions cov
    ON cov.organization_id = e.child_org_id
   AND cov.superseded_by_id IS NULL
  WHERE e.superseded_by_id IS NULL
    AND e.status = 'active'
    AND pg_catalog.lower(e.valid_range) <= iam.business_today()
    AND (
      cov.status = 'archived'
      OR e.valid_range @> iam.business_today()
      OR EXISTS (
        SELECT 1 FROM iam.organization_edges live_e
        WHERE live_e.child_org_id = e.child_org_id
          AND live_e.superseded_by_id IS NULL
          AND live_e.status = 'active'
          AND live_e.valid_range @> iam.business_today()
      )
    )
),
chains(ancestor_org_id, descendant_org_id, depth, eff_range, has_archived) AS (
  SELECT
    ov.organization_id,
    ov.organization_id,
    0,
    pg_catalog.daterange('-infinity'::date, 'infinity'::date, '[]'),
    (ov.status = 'archived')
  FROM iam.organization_versions ov
  WHERE ov.superseded_by_id IS NULL
  UNION ALL
  SELECT
    c.ancestor_org_id,
    e.child_org_id,
    c.depth + 1,
    c.eff_range * e.valid_range,
    (c.has_archived OR e.is_archived_child)
  FROM chains c
  JOIN valid_edges e
    ON e.parent_org_id = c.descendant_org_id
   AND c.eff_range && e.valid_range
  WHERE c.depth < 32
) CYCLE descendant_org_id SET is_cycle USING path
SELECT DISTINCT ancestor_org_id, descendant_org_id, depth, eff_range, has_archived
FROM chains
WHERE NOT is_cycle;

CREATE OR REPLACE VIEW iam.v_organization_closure_live AS
SELECT DISTINCT ancestor_org_id, descendant_org_id, depth
FROM iam.v_organization_closure
WHERE NOT has_archived
  AND eff_range @> iam.business_today();

-- Single per-person effective grant evaluator (enforces active person, active role, active grant org,
-- active governing membership, dated valid_range, fail-closed data_date_range, hierarchy flow-down,
-- environment scope, is_nusear_only, company-database tenant bounding, archived-path reachability
-- strictly from active ancestors with include_descendants=true org_subtree grants, and full-path
-- tool switches with ancestor held/off veto and Nusear-internal bypass).
CREATE OR REPLACE FUNCTION iam.person_effective_grants(
  p_person_id UUID,
  p_right_id TEXT,
  p_data_date DATE DEFAULT NULL
)
RETURNS TABLE (
  grant_id UUID,
  target_org_id UUID,
  person_scope_mode TEXT,
  data_date_range DATERANGE,
  is_nusear_internal BOOLEAN,
  is_archived_path BOOLEAN
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH dc AS (
    SELECT db_role_kind, tenant_org_id, environment
    FROM iam.database_context
    WHERE singleton = true
  ),
  raw_closure AS MATERIALIZED (
    SELECT c.ancestor_org_id, c.descendant_org_id, c.depth, c.eff_range, c.has_archived
    FROM dc
    JOIN iam.v_organization_closure c
      ON dc.db_role_kind = 'company_working'
      OR (dc.db_role_kind = 'control' AND NOT c.has_archived AND c.eff_range @> iam.business_today())
  ),
  tc AS (
    SELECT DISTINCT ON (t.descendant_org_id)
      t.descendant_org_id,
      t.eff_range,
      t.has_archived
    FROM dc
    JOIN raw_closure t
      ON dc.db_role_kind = 'company_working'
     AND t.ancestor_org_id = dc.tenant_org_id
    ORDER BY
      t.descendant_org_id,
      (t.eff_range @> iam.business_today()) DESC,
      pg_catalog.lower(t.eff_range) DESC,
      t.depth ASC
  ),
  live_ancestors AS (
    SELECT a.ancestor_org_id AS org_id, pg_catalog.min(a.depth) AS depth, ao.org_kind
    FROM dc
    JOIN raw_closure a
      ON dc.db_role_kind = 'company_working'
     AND a.descendant_org_id = dc.tenant_org_id
     AND a.depth > 0
     AND NOT a.has_archived
     AND a.eff_range @> iam.business_today()
    JOIN iam.organizations ao ON ao.id = a.ancestor_org_id
    GROUP BY a.ancestor_org_id, ao.org_kind
  ),
  scoped_closure AS MATERIALIZED (
    SELECT
      c.ancestor_org_id,
      c.descendant_org_id,
      c.depth,
      c.eff_range,
      c.has_archived,
      COALESCE(tc.has_archived, false) AS tenant_has_archived,
      (dc.db_role_kind = 'company_working' AND anc_tc.descendant_org_id IS NOT NULL) AS ancestor_in_tenant
    FROM dc
    JOIN raw_closure c ON true
    JOIN iam.organizations ao ON ao.id = c.ancestor_org_id
    LEFT JOIN tc ON tc.descendant_org_id = c.descendant_org_id
    LEFT JOIN tc anc_tc ON anc_tc.descendant_org_id = c.ancestor_org_id
    WHERE dc.db_role_kind = 'control'
       OR (
         dc.db_role_kind = 'company_working'
         AND tc.descendant_org_id IS NOT NULL
         AND c.eff_range && tc.eff_range
         AND (
           anc_tc.descendant_org_id IS NOT NULL
           OR (
             ao.org_kind = 'platform_root'
             AND (
               tc.has_archived
               OR NOT (tc.eff_range @> iam.business_today())
               OR (NOT c.has_archived AND c.eff_range @> iam.business_today())
             )
           )
         )
       )
  ),
  switch_chain AS MATERIALIZED (
    SELECT
      swc.descendant_org_id AS target_org_id,
      swc.ancestor_org_id AS switch_org_id,
      0 AS tier,
      swc.depth AS ord
    FROM dc
    JOIN scoped_closure swc ON dc.db_role_kind = 'control'
    UNION ALL
    SELECT
      swc.descendant_org_id AS target_org_id,
      swc.ancestor_org_id AS switch_org_id,
      1 AS tier,
      swc.depth AS ord
    FROM dc
    JOIN scoped_closure swc
      ON dc.db_role_kind = 'company_working'
     AND swc.ancestor_in_tenant
    UNION ALL
    SELECT
      tc.descendant_org_id AS target_org_id,
      la.org_id AS switch_org_id,
      CASE WHEN la.org_kind = 'platform_root' THEN 3 ELSE 2 END AS tier,
      la.depth AS ord
    FROM dc
    JOIN tc ON dc.db_role_kind = 'company_working'
    JOIN live_ancestors la ON true
  )
  SELECT DISTINCT
    g.id,
    c.descendant_org_id,
    g.person_scope_mode,
    g.data_date_range,
    rv.is_nusear_internal,
    c.has_archived
  FROM iam.role_grants g
  JOIN iam.person_versions pv
    ON pv.person_id = g.person_id AND pv.superseded_by_id IS NULL AND pv.status = 'active'
  JOIN iam.role_versions rv
    ON rv.role_id = g.role_id AND rv.superseded_by_id IS NULL AND rv.status = 'active'
  JOIN iam.role_rights rr
    ON rr.role_id = g.role_id AND rr.right_id = p_right_id
   AND rr.superseded_by_id IS NULL AND rr.status = 'active'
  JOIN iam.rights r
    ON r.id = rr.right_id
   AND NOT EXISTS (SELECT 1 FROM iam.right_retirements ret WHERE ret.right_id = r.id)
  JOIN iam.tools t
    ON t.id = r.tool_id
  JOIN dc ON true
  JOIN iam.organization_versions gov
    ON gov.organization_id = g.organization_id
   AND gov.superseded_by_id IS NULL AND gov.status = 'active'
  JOIN scoped_closure c
    ON c.ancestor_org_id = g.organization_id
   AND (g.include_descendants OR c.depth = 0)
  WHERE g.person_id = p_person_id
    AND g.superseded_by_id IS NULL
    AND g.status = 'active'
    AND g.valid_range @> iam.business_today()
    AND (
      (rv.is_nusear_internal AND pv.principal_origin IN ('nusear_staff', 'service'))
      OR (NOT rv.is_nusear_internal AND pv.principal_origin = 'company_local')
    )
    AND (dc.db_role_kind <> 'control' OR pv.principal_origin IN ('nusear_staff', 'service'))
    AND (
      g.data_date_range IS NULL
      OR (p_data_date IS NOT NULL AND g.data_date_range @> p_data_date)
    )
    AND (rv.is_nusear_internal OR NOT t.is_nusear_only)
    AND (
      r.environment_scope = 'both'
      OR (r.environment_scope = 'prod_only' AND dc.environment = 'prod')
      OR (r.environment_scope = 'dev_only' AND dc.environment IN ('dev', 'local'))
    )
    AND (
      (NOT c.tenant_has_archived AND NOT c.has_archived)
      OR (
        dc.db_role_kind = 'company_working'
        AND c.tenant_has_archived
        AND c.has_archived
        AND c.depth > 0
        AND g.include_descendants = true
        AND g.person_scope_mode = 'org_subtree'
        AND EXISTS (
          SELECT 1 FROM scoped_closure lcg
          WHERE NOT lcg.has_archived
            AND (
              (lcg.ancestor_org_id = dc.tenant_org_id AND lcg.descendant_org_id = g.organization_id)
              OR (lcg.ancestor_org_id = g.organization_id AND lcg.descendant_org_id = dc.tenant_org_id)
            )
        )
      )
    )
    AND (
      (rv.is_nusear_internal AND EXISTS (
        SELECT 1 FROM iam.v_all_memberships_live m
        JOIN iam.organizations mo ON mo.id = m.organization_id AND mo.org_kind = 'platform_root'
        WHERE m.person_id = g.person_id AND m.valid_range @> iam.business_today()
      ))
      OR (NOT rv.is_nusear_internal AND EXISTS (
        SELECT 1 FROM iam.v_all_memberships_live m
        JOIN iam.organizations mo ON mo.id = m.organization_id AND mo.org_kind <> 'platform_root'
        JOIN scoped_closure mc
          ON mc.ancestor_org_id = m.organization_id
         AND mc.descendant_org_id = g.organization_id
         AND NOT mc.has_archived
        WHERE m.person_id = g.person_id AND m.valid_range @> iam.business_today()
      ))
    )
    AND (
      rv.is_nusear_internal
      OR (
        (
          SELECT ts.switch_state
          FROM iam.organization_tool_switches ts
          JOIN switch_chain swc
            ON swc.target_org_id = c.descendant_org_id
           AND swc.switch_org_id = ts.organization_id
          WHERE ts.tool_id = r.tool_id
            AND ts.superseded_by_id IS NULL AND ts.status = 'active'
          ORDER BY swc.tier ASC, swc.ord ASC
          LIMIT 1
        ) = 'on'
        AND NOT EXISTS (
          SELECT 1
          FROM iam.organization_tool_switches ts
          JOIN switch_chain swc
            ON swc.target_org_id = c.descendant_org_id
           AND swc.switch_org_id = ts.organization_id
          WHERE ts.tool_id = r.tool_id
            AND ts.superseded_by_id IS NULL AND ts.status = 'active'
            AND ts.switch_state IN ('held', 'off')
        )
      )
    );
$$;

-- Token-bound helper: does effective caller hold a right in an overlapping org (intersected on View-as)?
CREATE OR REPLACE FUNCTION iam.has_right(p_right_id TEXT, p_data_date DATE DEFAULT NULL)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH ctx AS (SELECT * FROM iam.session_context())
  SELECT CASE
    WHEN (SELECT actor_person_id FROM ctx) IS NULL THEN false
    WHEN (SELECT view_as_person_id FROM ctx) IS NULL THEN
      EXISTS (SELECT 1 FROM iam.person_effective_grants((SELECT actor_person_id FROM ctx), p_right_id, p_data_date))
    ELSE
      EXISTS (
        SELECT 1
        FROM iam.person_effective_grants((SELECT actor_person_id FROM ctx), p_right_id, p_data_date) a
        JOIN iam.person_effective_grants((SELECT view_as_person_id FROM ctx), p_right_id, p_data_date) t
          ON t.target_org_id = a.target_org_id
      )
  END;
$$;

-- Set-theoretic InitPlan helper 1: org IDs where caller sees ALL rows (intersected on View-as).
CREATE OR REPLACE FUNCTION iam.effective_wide_org_ids(p_right_id TEXT, p_data_date DATE DEFAULT NULL)
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH ctx AS (SELECT * FROM iam.session_context()),
  actor_orgs AS (
    SELECT DISTINCT g.target_org_id
    FROM ctx
    JOIN LATERAL iam.person_effective_grants(ctx.actor_person_id, p_right_id, p_data_date) g ON true
    WHERE ctx.actor_person_id IS NOT NULL AND g.person_scope_mode = 'org_subtree'
  ),
  target_orgs AS (
    SELECT DISTINCT g.target_org_id
    FROM ctx
    JOIN LATERAL iam.person_effective_grants(ctx.view_as_person_id, p_right_id, p_data_date) g ON true
    WHERE ctx.view_as_person_id IS NOT NULL AND g.person_scope_mode = 'org_subtree'
  )
  SELECT COALESCE(pg_catalog.array_agg(a.target_org_id), ARRAY[]::uuid[])
  FROM actor_orgs a
  WHERE (SELECT view_as_person_id FROM ctx) IS NULL
     OR a.target_org_id IN (SELECT target_org_id FROM target_orgs);
$$;

-- Set-theoretic InitPlan helper 2: org IDs reachable under ANY person_scope_mode (intersected on View-as).
CREATE OR REPLACE FUNCTION iam.effective_any_org_ids(p_right_id TEXT, p_data_date DATE DEFAULT NULL)
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH ctx AS (SELECT * FROM iam.session_context()),
  actor_orgs AS (
    SELECT DISTINCT g.target_org_id
    FROM ctx
    JOIN LATERAL iam.person_effective_grants(ctx.actor_person_id, p_right_id, p_data_date) g ON true
    WHERE ctx.actor_person_id IS NOT NULL
  ),
  target_orgs AS (
    SELECT DISTINCT g.target_org_id
    FROM ctx
    JOIN LATERAL iam.person_effective_grants(ctx.view_as_person_id, p_right_id, p_data_date) g ON true
    WHERE ctx.view_as_person_id IS NOT NULL
  )
  SELECT COALESCE(pg_catalog.array_agg(a.target_org_id), ARRAY[]::uuid[])
  FROM actor_orgs a
  WHERE (SELECT view_as_person_id FROM ctx) IS NULL
     OR a.target_org_id IN (SELECT target_org_id FROM target_orgs);
$$;

-- Set-theoretic InitPlan helper 3: effective narrow (org_id, person_id) pairs for self mode under View-as intersection.
CREATE OR REPLACE FUNCTION iam.effective_narrow_pairs(p_right_id TEXT, p_data_date DATE DEFAULT NULL)
RETURNS TABLE (org_id UUID, person_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH ctx AS (SELECT * FROM iam.session_context()),
  a_wide AS (
    SELECT DISTINCT g.target_org_id AS org_id
    FROM ctx JOIN LATERAL iam.person_effective_grants(ctx.actor_person_id, p_right_id, p_data_date) g ON true
    WHERE ctx.actor_person_id IS NOT NULL AND g.person_scope_mode = 'org_subtree'
  ),
  a_self AS (
    SELECT DISTINCT g.target_org_id AS org_id, ctx.actor_person_id AS person_id
    FROM ctx JOIN LATERAL iam.person_effective_grants(ctx.actor_person_id, p_right_id, p_data_date) g ON true
    WHERE ctx.actor_person_id IS NOT NULL AND g.person_scope_mode = 'self'
  ),
  t_wide AS (
    SELECT DISTINCT g.target_org_id AS org_id
    FROM ctx JOIN LATERAL iam.person_effective_grants(ctx.view_as_person_id, p_right_id, p_data_date) g ON true
    WHERE ctx.view_as_person_id IS NOT NULL AND g.person_scope_mode = 'org_subtree'
  ),
  t_self AS (
    SELECT DISTINCT g.target_org_id AS org_id, ctx.view_as_person_id AS person_id
    FROM ctx JOIN LATERAL iam.person_effective_grants(ctx.view_as_person_id, p_right_id, p_data_date) g ON true
    WHERE ctx.view_as_person_id IS NOT NULL AND g.person_scope_mode = 'self'
  )
  SELECT a.org_id, a.person_id
  FROM a_self a
  WHERE (SELECT view_as_person_id FROM ctx) IS NULL
     OR a.org_id IN (SELECT org_id FROM t_wide)
     OR EXISTS (SELECT 1 FROM t_self t WHERE t.org_id = a.org_id AND t.person_id = a.person_id)
  UNION
  SELECT t.org_id, t.person_id
  FROM t_self t
  WHERE (SELECT view_as_person_id FROM ctx) IS NOT NULL
    AND t.org_id IN (SELECT org_id FROM a_wide);
$$;

CREATE OR REPLACE FUNCTION iam.effective_narrow_person_ids(p_right_id TEXT, p_data_date DATE DEFAULT NULL)
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT COALESCE(pg_catalog.array_agg(DISTINCT person_id), ARRAY[]::uuid[])
  FROM iam.effective_narrow_pairs(p_right_id, p_data_date);
$$;

-- Central write authorization guard called by every app_cmd.* function.
-- Attribution is strictly deterministic from principal_origin: company_local -> 'self',
-- nusear_staff -> 'nusear_support' in company databases ('self' in control), service -> 'service'.
CREATE OR REPLACE FUNCTION iam.assert_can_write(
  p_right_id TEXT,
  p_record_org_id UUID,
  p_subject_person_id UUID DEFAULT NULL,
  p_data_date DATE DEFAULT NULL
)
RETURNS TABLE (actor_person_id UUID, recorded_as TEXT)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx iam.verified_session := iam.session_context();
  v_has_write BOOLEAN := false;
  v_origin TEXT;
  v_db_role_kind TEXT;
BEGIN
  IF v_ctx.actor_person_id IS NULL THEN
    RAISE EXCEPTION 'Authentication required.' USING ERRCODE = '42501';
  END IF;

  -- Unconditional View-as refusal (even in a deliberate READ WRITE transaction).
  IF v_ctx.view_as_person_id IS NOT NULL THEN
    RAISE EXCEPTION 'VIEW_AS_READ_ONLY: writes are forbidden while viewing as another person.'
      USING ERRCODE = '42501';
  END IF;

  -- Column rights and retired rights never authorize writes.
  IF NOT EXISTS (
    SELECT 1 FROM iam.rights r
    WHERE r.id = p_right_id
      AND r.right_kind = 'action'
      AND NOT EXISTS (SELECT 1 FROM iam.right_retirements ret WHERE ret.right_id = r.id)
  ) THEN
    RAISE EXCEPTION 'FORBIDDEN: unknown, retired, or non-action write right %.', p_right_id USING ERRCODE = '42501';
  END IF;

  SELECT EXISTS (
    SELECT 1
    FROM iam.person_effective_grants(v_ctx.actor_person_id, p_right_id, p_data_date) g
    WHERE g.target_org_id = p_record_org_id
      AND NOT g.is_archived_path
      AND (
        g.person_scope_mode = 'org_subtree'
        OR (g.person_scope_mode = 'self' AND p_subject_person_id = v_ctx.actor_person_id)
      )
  ) INTO v_has_write;

  IF NOT v_has_write THEN
    RAISE EXCEPTION 'FORBIDDEN: missing write right % in target scope.', p_right_id USING ERRCODE = '42501';
  END IF;

  SELECT p.principal_origin INTO v_origin
  FROM iam.people p
  WHERE p.id = v_ctx.actor_person_id;

  SELECT dc.db_role_kind INTO v_db_role_kind
  FROM iam.database_context dc
  WHERE dc.singleton = true;

  RETURN QUERY SELECT
    v_ctx.actor_person_id,
    CASE v_origin
      WHEN 'service' THEN 'service'::text
      WHEN 'nusear_staff' THEN
        CASE WHEN v_db_role_kind = 'company_working' THEN 'nusear_support'::text ELSE 'self'::text END
      ELSE 'self'::text
    END;
END;
$$;

-- 8. Least-privilege grants and PUBLIC lockdown.
DO $$
DECLARE
  v_tbl TEXT;
  v_role TEXT;
BEGIN
  REVOKE ALL ON SCHEMA platform, iam_secret, iam FROM PUBLIC;
  REVOKE ALL ON ALL TABLES IN SCHEMA platform, iam_secret, iam FROM PUBLIC;
  REVOKE ALL ON ALL FUNCTIONS IN SCHEMA platform, iam_secret, iam FROM PUBLIC;
  REVOKE ALL ON ALL SEQUENCES IN SCHEMA platform, iam_secret, iam FROM PUBLIC;

  -- platform_versioner: minimum privileges needed for BEFORE INSERT supersession trigger on versioned iam tables.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'platform_versioner') THEN
    GRANT USAGE ON SCHEMA iam TO platform_versioner;
    FOREACH v_tbl IN ARRAY ARRAY[
      'organization_versions', 'organization_edges', 'person_versions', 'person_auth_identities',
      'organization_memberships', 'agent_affiliations',
      'role_versions', 'role_rights', 'role_grants', 'organization_tool_switches'
    ] LOOP
      EXECUTE pg_catalog.format(
        'GRANT SELECT, UPDATE (superseded_by_id, superseded_journal_seq) ON iam.%I TO platform_versioner',
        v_tbl
      );
    END LOOP;
  END IF;

  -- Token-bound IAM read/guard functions callable by platform_app, platform_view_owner, platform_writer, platform_readonly.
  -- Notice: platform_app holds ZERO privileges on any iam, iam_secret, or platform base table or internal view/helper.
  FOREACH v_role IN ARRAY ARRAY['platform_app', 'platform_view_owner', 'platform_writer', 'platform_readonly'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
      EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA iam TO %I', v_role);
      EXECUTE pg_catalog.format(
        'GRANT EXECUTE ON FUNCTION
           iam.business_today(TIMESTAMPTZ),
           iam.session_context(),
           iam.is_viewing_as(),
           iam.has_right(TEXT, DATE),
           iam.effective_wide_org_ids(TEXT, DATE),
           iam.effective_any_org_ids(TEXT, DATE),
           iam.effective_narrow_pairs(TEXT, DATE),
           iam.effective_narrow_person_ids(TEXT, DATE),
           iam.assert_can_write(TEXT, UUID, UUID, DATE)
         TO %I',
        v_role
      );
    END IF;
  END LOOP;

  -- platform_auth_lookup: strictly resolves per-company sign-in identities via iam.resolve_auth_identity()
  -- (zero base-table access anywhere, zero app_views/app_cmd access; never granted to platform_app).
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'platform_auth_lookup') THEN
    GRANT USAGE ON SCHEMA iam TO platform_auth_lookup;
    GRANT EXECUTE ON FUNCTION iam.resolve_auth_identity(TEXT, TEXT) TO platform_auth_lookup;
  END IF;
  REVOKE ALL ON FUNCTION iam.resolve_auth_identity(TEXT, TEXT) FROM PUBLIC, platform_app, platform_worker, platform_writer, platform_iam_sync;

  -- platform_writer: writes to platform.audit_journal inside app_cmd.* commands (zero iam_secret access).
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'platform_writer') THEN
    GRANT USAGE ON SCHEMA platform TO platform_writer;
    GRANT SELECT, INSERT ON platform.audit_journal TO platform_writer;
    GRANT EXECUTE ON FUNCTION
      platform.canonical_json(JSONB),
      platform.sha256_text(TEXT),
      platform.format_utc_us(TIMESTAMPTZ),
      platform.compute_journal_hash(BIGINT, TIMESTAMPTZ, TEXT, UUID, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, JSONB)
    TO platform_writer;
  END IF;

  -- platform_readonly: read-only on platform and iam (zero iam_secret access).
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'platform_readonly') THEN
    GRANT USAGE ON SCHEMA platform TO platform_readonly;
    GRANT SELECT ON ALL TABLES IN SCHEMA platform TO platform_readonly;
    GRANT SELECT ON ALL TABLES IN SCHEMA iam TO platform_readonly;
  END IF;

  -- platform_worker: reads iam (excluding person_auth_identities) and audit_journal SELECT only
  -- (zero INSERT on platform.audit_journal, zero compute_journal_hash execute, zero iam_secret access; app_cmd writes journals).
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'platform_worker') THEN
    GRANT USAGE ON SCHEMA platform, iam TO platform_worker;
    GRANT SELECT ON platform.audit_journal TO platform_worker;
    GRANT SELECT ON ALL TABLES IN SCHEMA iam TO platform_worker;
    REVOKE ALL ON iam.person_auth_identities FROM platform_worker;
    GRANT EXECUTE ON FUNCTION
      iam.business_today(TIMESTAMPTZ)
    TO platform_worker;
  END IF;

  -- platform_iam_sync: mirrors strictly Nusear people, entity tree, platform catalog, tool switches,
  -- and Nusear/service signing keys (zero INSERT on agent_affiliations; zero privileges on person_auth_identities;
  -- triggers enforce refusal of company_local people/memberships/grants, company custom roles, and company_local signing keys).
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'platform_iam_sync') THEN
    GRANT USAGE ON SCHEMA platform, iam, iam_secret TO platform_iam_sync;
    GRANT SELECT, INSERT ON platform.audit_journal TO platform_iam_sync;
    GRANT SELECT ON ALL TABLES IN SCHEMA iam TO platform_iam_sync;
    REVOKE ALL ON iam.person_auth_identities FROM platform_iam_sync;
    FOREACH v_tbl IN ARRAY ARRAY[
      'database_context', 'tools', 'rights', 'right_retirements',
      'organizations', 'organization_versions', 'organization_edges', 'organization_tool_switches',
      'roles', 'role_versions', 'role_rights',
      'people', 'person_versions', 'organization_memberships', 'role_grants'
    ] LOOP
      EXECUTE pg_catalog.format('GRANT INSERT ON iam.%I TO platform_iam_sync', v_tbl);
    END LOOP;
    GRANT SELECT, INSERT, UPDATE ON iam_secret.signing_keys TO platform_iam_sync;
    GRANT EXECUTE ON FUNCTION
      platform.canonical_json(JSONB),
      platform.sha256_text(TEXT),
      platform.format_utc_us(TIMESTAMPTZ),
      platform.compute_journal_hash(BIGINT, TIMESTAMPTZ, TEXT, UUID, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, JSONB),
      iam.business_today(TIMESTAMPTZ)
    TO platform_iam_sync;
  END IF;

  -- platform_migrator: schema usage for DDL migrations.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'platform_migrator') THEN
    GRANT USAGE ON SCHEMA platform, iam, iam_secret TO platform_migrator;
  END IF;
END;
$$;
