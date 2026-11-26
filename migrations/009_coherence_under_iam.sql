-- Migration 009: Coherence data under database-only IAM rules (Release 1).
-- Upgrades Coherence's Book of Business, financials, agency & upline statement lines (kept
-- physically separate), and Coherent Ledger with foreign keys to iam.organizations and iam.people
-- (policy_identity_id waits on the release that builds core.carriers and policies.policy_identities);
-- provides a strict atomic refusal backfill function (coherence.backfill_iam_foreign_keys);
-- replaces Migration 006's app.allowed_entities / app.actor_npn / app.access_tier RLS policies with
-- IAM set-theoretic InitPlan policies under FORCE ROW LEVEL SECURITY across all Coherence tables;
-- exposes app_views.coherence_* (including v_current_policy_periods and v_current_commission_ledger)
-- owned by NOBYPASSRLS platform_view_owner with security_barrier = true;
-- installs app_cmd.coherence_* SECURITY DEFINER write commands owned by platform_writer through
-- iam.assert_can_write(); and revokes every Coherence base-table privilege from platform_app.
-- All functions pin SET search_path = pg_catalog and schema-qualify all references.

CREATE SCHEMA IF NOT EXISTS app_views;
CREATE SCHEMA IF NOT EXISTS app_cmd;

REVOKE ALL ON SCHEMA app_views, app_cmd FROM PUBLIC;

-- 1. Foreign keys to iam.organizations and iam.people on the five core Coherence data tables.
-- Physical vertical split (bob_policies / bob_policy_financials) and physical separation
-- (statement_agency_lines / statement_upline_lines / coherent_ledger_rows) are preserved.
-- Note: policy_identity_id REFERENCES policies.policy_identities(id) is deferred to the release
-- that creates core.carriers and policies.policy_identities.
ALTER TABLE coherence.bob_policies
  ADD COLUMN organization_id UUID REFERENCES iam.organizations(id),
  ADD COLUMN writing_person_id UUID REFERENCES iam.people(id),
  ADD CONSTRAINT bob_policies_writing_person_requires_npn
    CHECK (writing_npn IS NOT NULL OR writing_person_id IS NULL);

ALTER TABLE coherence.bob_policy_financials
  ADD COLUMN organization_id UUID REFERENCES iam.organizations(id),
  ADD COLUMN writing_person_id UUID REFERENCES iam.people(id),
  ADD CONSTRAINT bob_policy_financials_writing_person_requires_npn
    CHECK (writing_npn IS NOT NULL OR writing_person_id IS NULL);

ALTER TABLE coherence.statement_agency_lines
  ADD COLUMN organization_id UUID REFERENCES iam.organizations(id),
  ADD COLUMN writing_person_id UUID REFERENCES iam.people(id),
  ADD CONSTRAINT statement_agency_lines_writing_person_requires_npn
    CHECK (writing_npn IS NOT NULL OR writing_person_id IS NULL);

ALTER TABLE coherence.statement_upline_lines
  ADD COLUMN organization_id UUID REFERENCES iam.organizations(id),
  ADD COLUMN writing_person_id UUID REFERENCES iam.people(id),
  ADD CONSTRAINT statement_upline_lines_writing_person_requires_npn
    CHECK (writing_npn IS NOT NULL OR writing_person_id IS NULL);

ALTER TABLE coherence.coherent_ledger_rows
  ADD COLUMN organization_id UUID REFERENCES iam.organizations(id),
  ADD COLUMN writing_person_id UUID REFERENCES iam.people(id),
  ADD CONSTRAINT coherent_ledger_rows_writing_person_requires_npn
    CHECK (writing_npn IS NOT NULL OR writing_person_id IS NULL);

CREATE INDEX bob_policies_org_person_idx
  ON coherence.bob_policies (organization_id, writing_person_id);
CREATE INDEX bob_policies_attempt_org_idx
  ON coherence.bob_policies (attempt_event_id, organization_id);

CREATE INDEX bob_policy_financials_org_person_idx
  ON coherence.bob_policy_financials (organization_id, writing_person_id);
CREATE INDEX bob_policy_financials_attempt_org_idx
  ON coherence.bob_policy_financials (attempt_event_id, organization_id);

CREATE INDEX statement_agency_lines_org_person_date_idx
  ON coherence.statement_agency_lines (organization_id, writing_person_id, statement_date);
CREATE INDEX statement_agency_lines_batch_org_idx
  ON coherence.statement_agency_lines (batch_id, organization_id);

CREATE INDEX statement_upline_lines_org_date_idx
  ON coherence.statement_upline_lines (organization_id, statement_date);
CREATE INDEX statement_upline_lines_batch_org_idx
  ON coherence.statement_upline_lines (batch_id, organization_id);

CREATE INDEX coherent_ledger_rows_org_person_idx
  ON coherence.coherent_ledger_rows (organization_id, writing_person_id);
CREATE INDEX coherent_ledger_rows_attempt_org_idx
  ON coherence.coherent_ledger_rows (attempt_event_id, organization_id);

-- Keep bob_policy_financials FKs locked in 1:1 parity with bob_policies on insert.
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
  IF NEW.organization_id IS DISTINCT FROM v_bp.organization_id
     OR NEW.writing_person_id IS DISTINCT FROM v_bp.writing_person_id THEN
    RAISE EXCEPTION 'bob_policy_financials organization_id and writing_person_id must match bob_policies exactly'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

-- 2. One-time IAM FK backfill guard and strict refusal backfill function.
-- Preserves ENABLE ALWAYS statement-level immutability for every role and every business fact,
-- permitting strictly platform_versioner one-time NULL -> non-NULL stamping of
-- (organization_id, writing_person_id) on the five FK-upgraded tables via backfill_iam_foreign_keys().
CREATE OR REPLACE FUNCTION coherence.forbid_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND CURRENT_USER = 'platform_versioner'
     AND TG_TABLE_SCHEMA = 'coherence'
     AND TG_TABLE_NAME IN (
       'bob_policies', 'bob_policy_financials',
       'statement_agency_lines', 'statement_upline_lines', 'coherent_ledger_rows'
     )
  THEN
    RETURN NULL;
  END IF;
  RAISE EXCEPTION 'business table %.% is immutable: % is forbidden',
    TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION coherence.guard_iam_fk_backfill()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_bp_org UUID;
  v_bp_person UUID;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.writing_person_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM iam.people p WHERE p.id = NEW.writing_person_id AND p.principal_origin = 'company_local'
    ) THEN
      RAISE EXCEPTION 'business table %.% writing_person_id must reference a company_local person',
        TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF CURRENT_USER <> 'platform_versioner' THEN
    RAISE EXCEPTION 'business table %.% is immutable: UPDATE is forbidden',
      TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '55000';
  END IF;

  IF (pg_catalog.to_jsonb(NEW) - 'organization_id' - 'writing_person_id')
     IS DISTINCT FROM
     (pg_catalog.to_jsonb(OLD) - 'organization_id' - 'writing_person_id')
  THEN
    RAISE EXCEPTION 'business table %.% is immutable: business columns cannot be modified',
      TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '55000';
  END IF;

  IF OLD.organization_id IS NOT NULL AND NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
    RAISE EXCEPTION 'business table %.% is immutable: organization_id cannot be overwritten once stamped',
      TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '55000';
  END IF;

  IF NEW.organization_id IS NULL THEN
    RAISE EXCEPTION 'business table %.% backfill must populate non-NULL organization_id',
      TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '55000';
  END IF;

  IF OLD.writing_person_id IS NOT NULL AND NEW.writing_person_id IS DISTINCT FROM OLD.writing_person_id THEN
    RAISE EXCEPTION 'business table %.% is immutable: writing_person_id cannot be overwritten once stamped',
      TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '55000';
  END IF;

  IF OLD.writing_npn IS NULL AND NEW.writing_person_id IS NOT NULL THEN
    RAISE EXCEPTION 'business table %.% cannot stamp writing_person_id when writing_npn is NULL',
      TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '55000';
  END IF;

  IF OLD.writing_npn IS NOT NULL AND NEW.writing_person_id IS NULL THEN
    RAISE EXCEPTION 'business table %.% backfill must stamp writing_person_id when writing_npn is non-NULL',
      TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '55000';
  END IF;

  IF NEW.writing_person_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM iam.people p WHERE p.id = NEW.writing_person_id AND p.principal_origin = 'company_local'
  ) THEN
    RAISE EXCEPTION 'business table %.% writing_person_id must reference a company_local person',
      TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '55000';
  END IF;

  IF TG_TABLE_NAME = 'bob_policy_financials' THEN
    SELECT bp.organization_id, bp.writing_person_id
    INTO v_bp_org, v_bp_person
    FROM coherence.bob_policies bp
    WHERE bp.attempt_event_id = NEW.attempt_event_id AND bp.policy_id = NEW.policy_id;
    IF NEW.organization_id IS DISTINCT FROM v_bp_org
       OR NEW.writing_person_id IS DISTINCT FROM v_bp_person THEN
      RAISE EXCEPTION 'bob_policy_financials backfilled FKs must match bob_policies exactly'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DO $$
DECLARE
  v_tbl TEXT;
BEGIN
  FOREACH v_tbl IN ARRAY ARRAY[
    'bob_policies', 'bob_policy_financials',
    'statement_agency_lines', 'statement_upline_lines', 'coherent_ledger_rows'
  ] LOOP
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER trg_guard_iam_fk_backfill BEFORE INSERT OR UPDATE ON coherence.%I FOR EACH ROW EXECUTE FUNCTION coherence.guard_iam_fk_backfill()',
      v_tbl
    );
    EXECUTE pg_catalog.format(
      'ALTER TABLE coherence.%I ENABLE ALWAYS TRIGGER trg_guard_iam_fk_backfill',
      v_tbl
    );
  END LOOP;
END;
$$;

-- Deterministic tenant-tree resolver over iam.v_organization_closure: accepts only company,
-- agency, and team organizations inside this tenant's organization tree.
CREATE OR REPLACE FUNCTION coherence._resolve_tenant_tree_org_ids()
RETURNS UUID[]
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT COALESCE(pg_catalog.array_agg(DISTINCT c.descendant_org_id), ARRAY[]::uuid[])
  FROM iam.database_context dc
  JOIN iam.organizations root_o
    ON root_o.id = dc.tenant_org_id
   AND root_o.org_kind IN ('company', 'agency', 'team')
  JOIN iam.v_organization_closure c
    ON c.ancestor_org_id = dc.tenant_org_id
  JOIN iam.organizations co
    ON co.id = c.descendant_org_id
   AND co.org_kind IN ('company', 'agency', 'team')
  WHERE dc.singleton = true
    AND dc.tenant_org_id IS NOT NULL;
$$;

-- Strict deterministic resolver for entity -> iam.organizations(id); accepts only
-- company, agency, and team organizations inside this tenant's organization tree
-- (following each archived child's latest non-future active edge); never guesses.
CREATE OR REPLACE FUNCTION coherence._resolve_entity_org_id(
  p_entity TEXT,
  p_table_name TEXT,
  p_entity_map JSONB DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_trimmed TEXT := pg_catalog.btrim(COALESCE(p_entity, ''));
  v_mapped_text TEXT;
  v_org_id UUID;
  v_cnt BIGINT;
  v_tenant_tree UUID[];
BEGIN
  IF pg_catalog.length(v_trimmed) = 0 THEN
    RAISE EXCEPTION 'UNMAPPED_ENTITY: blank entity value in coherence.%', p_table_name
      USING ERRCODE = '22023';
  END IF;

  v_tenant_tree := coherence._resolve_tenant_tree_org_ids();

  IF p_entity_map IS NOT NULL AND (p_entity_map ? p_entity OR p_entity_map ? v_trimmed) THEN
    v_mapped_text := COALESCE(p_entity_map ->> p_entity, p_entity_map ->> v_trimmed);
    BEGIN
      v_org_id := v_mapped_text::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
      RAISE EXCEPTION 'INVALID_ENTITY_MAP: entity map value for coherence.% is not a valid UUID', p_table_name
        USING ERRCODE = '22023';
    END;
    IF v_org_id IS NULL OR NOT (v_org_id = ANY(v_tenant_tree)) THEN
      RAISE EXCEPTION 'INVALID_ENTITY_MAP: mapped organization_id for coherence.% is not a company/agency/team organization in this tenant tree', p_table_name
        USING ERRCODE = '23503';
    END IF;
    RETURN v_org_id;
  END IF;

  SELECT pg_catalog.count(DISTINCT ov.organization_id), pg_catalog.min(ov.organization_id::text)::uuid
  INTO v_cnt, v_org_id
  FROM iam.organization_versions ov
  JOIN iam.organizations o ON o.id = ov.organization_id
  WHERE ov.superseded_by_id IS NULL
    AND o.org_kind IN ('company', 'agency', 'team')
    AND o.id = ANY(v_tenant_tree)
    AND (
      pg_catalog.lower(pg_catalog.btrim(ov.slug)) = pg_catalog.lower(v_trimmed)
      OR pg_catalog.lower(pg_catalog.btrim(ov.display_name)) = pg_catalog.lower(v_trimmed)
    );

  IF v_cnt = 0 THEN
    RAISE EXCEPTION 'UNMAPPED_ENTITY: cannot map entity "%" in coherence.% to iam.organizations in this tenant tree (provide explicit p_entity_map or seed iam.organizations).',
      v_trimmed, p_table_name USING ERRCODE = '22023';
  ELSIF v_cnt > 1 THEN
    RAISE EXCEPTION 'AMBIGUOUS_ENTITY: entity "%" in coherence.% matches % iam.organizations rows; refusing to guess.',
      v_trimmed, p_table_name, v_cnt USING ERRCODE = '21000';
  END IF;

  RETURN v_org_id;
END;
$$;

-- Strict deterministic resolver for writing_npn -> company_local iam.people(id); ignores nusear_staff/service and never guesses.
CREATE OR REPLACE FUNCTION coherence._resolve_writing_person_id(
  p_writing_npn TEXT,
  p_table_name TEXT,
  p_npn_map JSONB DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_trimmed TEXT;
  v_mapped_text TEXT;
  v_person_id UUID;
  v_cnt BIGINT;
BEGIN
  IF p_writing_npn IS NULL THEN
    RETURN NULL;
  END IF;

  v_trimmed := pg_catalog.btrim(p_writing_npn);
  IF pg_catalog.length(v_trimmed) = 0 THEN
    RAISE EXCEPTION 'MALFORMED_WRITING_NPN: blank non-NULL writing_npn in coherence.%; refusing to guess.',
      p_table_name USING ERRCODE = '22023';
  END IF;

  IF p_npn_map IS NOT NULL AND (p_npn_map ? p_writing_npn OR p_npn_map ? v_trimmed) THEN
    v_mapped_text := COALESCE(p_npn_map ->> p_writing_npn, p_npn_map ->> v_trimmed);
    BEGIN
      v_person_id := v_mapped_text::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
      RAISE EXCEPTION 'INVALID_NPN_MAP: npn map value for coherence.% is not a valid UUID', p_table_name
        USING ERRCODE = '22023';
    END;
    IF v_person_id IS NULL OR NOT EXISTS (
      SELECT 1 FROM iam.people p WHERE p.id = v_person_id AND p.principal_origin = 'company_local'
    ) THEN
      RAISE EXCEPTION 'INVALID_NPN_MAP: mapped person_id for coherence.% is not a company_local person in iam.people', p_table_name
        USING ERRCODE = '23503';
    END IF;
    RETURN v_person_id;
  END IF;

  WITH matched AS (
    SELECT pv.person_id
    FROM iam.person_versions pv
    WHERE pv.superseded_by_id IS NULL
      AND pv.principal_origin = 'company_local'
      AND pv.npn = v_trimmed
    UNION
    SELECT aa.person_id
    FROM iam.agent_affiliations aa
    JOIN iam.people p ON p.id = aa.person_id AND p.principal_origin = 'company_local'
    WHERE aa.superseded_by_id IS NULL AND aa.status = 'active' AND aa.npn = v_trimmed
  )
  SELECT pg_catalog.count(DISTINCT person_id), pg_catalog.min(person_id::text)::uuid
  INTO v_cnt, v_person_id
  FROM matched;

  IF v_cnt = 0 THEN
    RAISE EXCEPTION 'UNMAPPED_WRITING_NPN: cannot map writing_npn "%" in coherence.% to a company_local iam.people row (provide explicit p_npn_map or seed iam.people).',
      v_trimmed, p_table_name USING ERRCODE = '22023';
  ELSIF v_cnt > 1 THEN
    RAISE EXCEPTION 'AMBIGUOUS_WRITING_NPN: writing_npn "%" in coherence.% matches % company_local iam.people rows; refusing to guess.',
      v_trimmed, p_table_name, v_cnt USING ERRCODE = '21000';
  END IF;

  RETURN v_person_id;
END;
$$;

-- Atomic, idempotent backfill function owned by platform_versioner.
-- Maps today's entity (or source_entity on statement_upline_lines) and writing_npn across all five
-- tables; refuses and rolls back atomically on ANY unmapped, blank, out-of-tenant, or ambiguous value.
CREATE OR REPLACE FUNCTION coherence.backfill_iam_foreign_keys(
  p_entity_map JSONB DEFAULT NULL,
  p_npn_map JSONB DEFAULT NULL
)
RETURNS TABLE (
  table_name TEXT,
  rows_updated BIGINT,
  rows_already_mapped BIGINT
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_kv RECORD;
  v_check_uuid UUID;
  v_tenant_tree UUID[];
  v_upd BIGINT;
  v_already BIGINT;
BEGIN
  v_tenant_tree := coherence._resolve_tenant_tree_org_ids();

  IF p_entity_map IS NOT NULL THEN
    IF pg_catalog.jsonb_typeof(p_entity_map) <> 'object' THEN
      RAISE EXCEPTION 'INVALID_ENTITY_MAP: p_entity_map must be a JSON object' USING ERRCODE = '22023';
    END IF;
    FOR v_kv IN SELECT key, value FROM pg_catalog.jsonb_each_text(p_entity_map) LOOP
      BEGIN
        v_check_uuid := v_kv.value::uuid;
      EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'INVALID_ENTITY_MAP: value for entity "%" is not a valid UUID', v_kv.key USING ERRCODE = '22023';
      END;
      IF v_check_uuid IS NULL OR NOT (v_check_uuid = ANY(v_tenant_tree)) THEN
        RAISE EXCEPTION 'INVALID_ENTITY_MAP: organization_id for entity "%" is not a company/agency/team organization in this tenant tree', v_kv.key
          USING ERRCODE = '23503';
      END IF;
    END LOOP;
  END IF;

  IF p_npn_map IS NOT NULL THEN
    IF pg_catalog.jsonb_typeof(p_npn_map) <> 'object' THEN
      RAISE EXCEPTION 'INVALID_NPN_MAP: p_npn_map must be a JSON object' USING ERRCODE = '22023';
    END IF;
    FOR v_kv IN SELECT key, value FROM pg_catalog.jsonb_each_text(p_npn_map) LOOP
      BEGIN
        v_check_uuid := v_kv.value::uuid;
      EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'INVALID_NPN_MAP: value for npn "%" is not a valid UUID', v_kv.key USING ERRCODE = '22023';
      END;
      IF v_check_uuid IS NULL OR NOT EXISTS (
        SELECT 1 FROM iam.people p WHERE p.id = v_check_uuid AND p.principal_origin = 'company_local'
      ) THEN
        RAISE EXCEPTION 'INVALID_NPN_MAP: person_id for npn "%" is not a company_local person in iam.people', v_kv.key
          USING ERRCODE = '23503';
      END IF;
    END LOOP;
  END IF;

  -- 1. coherence.bob_policies (must run before bob_policy_financials so FK parity trigger passes)
  SELECT pg_catalog.count(*) INTO v_already
  FROM coherence.bob_policies
  WHERE organization_id IS NOT NULL AND (writing_npn IS NULL OR writing_person_id IS NOT NULL);

  UPDATE coherence.bob_policies bp
  SET organization_id = COALESCE(bp.organization_id, coherence._resolve_entity_org_id(bp.entity, 'bob_policies', p_entity_map)),
      writing_person_id = COALESCE(bp.writing_person_id, coherence._resolve_writing_person_id(bp.writing_npn, 'bob_policies', p_npn_map))
  WHERE bp.organization_id IS NULL OR (bp.writing_npn IS NOT NULL AND bp.writing_person_id IS NULL);
  GET DIAGNOSTICS v_upd = ROW_COUNT;
  table_name := 'bob_policies'; rows_updated := v_upd; rows_already_mapped := v_already;
  RETURN NEXT;

  -- 2. coherence.bob_policy_financials
  SELECT pg_catalog.count(*) INTO v_already
  FROM coherence.bob_policy_financials
  WHERE organization_id IS NOT NULL AND (writing_npn IS NULL OR writing_person_id IS NOT NULL);

  UPDATE coherence.bob_policy_financials bpf
  SET organization_id = COALESCE(bpf.organization_id, coherence._resolve_entity_org_id(bpf.entity, 'bob_policy_financials', p_entity_map)),
      writing_person_id = COALESCE(bpf.writing_person_id, coherence._resolve_writing_person_id(bpf.writing_npn, 'bob_policy_financials', p_npn_map))
  WHERE bpf.organization_id IS NULL OR (bpf.writing_npn IS NOT NULL AND bpf.writing_person_id IS NULL);
  GET DIAGNOSTICS v_upd = ROW_COUNT;
  table_name := 'bob_policy_financials'; rows_updated := v_upd; rows_already_mapped := v_already;
  RETURN NEXT;

  -- 3. coherence.statement_agency_lines
  SELECT pg_catalog.count(*) INTO v_already
  FROM coherence.statement_agency_lines
  WHERE organization_id IS NOT NULL AND (writing_npn IS NULL OR writing_person_id IS NOT NULL);

  UPDATE coherence.statement_agency_lines sal
  SET organization_id = COALESCE(sal.organization_id, coherence._resolve_entity_org_id(sal.entity, 'statement_agency_lines', p_entity_map)),
      writing_person_id = COALESCE(sal.writing_person_id, coherence._resolve_writing_person_id(sal.writing_npn, 'statement_agency_lines', p_npn_map))
  WHERE sal.organization_id IS NULL OR (sal.writing_npn IS NOT NULL AND sal.writing_person_id IS NULL);
  GET DIAGNOSTICS v_upd = ROW_COUNT;
  table_name := 'statement_agency_lines'; rows_updated := v_upd; rows_already_mapped := v_already;
  RETURN NEXT;

  -- 4. coherence.statement_upline_lines (maps source_entity -> organization_id)
  SELECT pg_catalog.count(*) INTO v_already
  FROM coherence.statement_upline_lines
  WHERE organization_id IS NOT NULL AND (writing_npn IS NULL OR writing_person_id IS NOT NULL);

  UPDATE coherence.statement_upline_lines sul
  SET organization_id = COALESCE(sul.organization_id, coherence._resolve_entity_org_id(sul.source_entity, 'statement_upline_lines', p_entity_map)),
      writing_person_id = COALESCE(sul.writing_person_id, coherence._resolve_writing_person_id(sul.writing_npn, 'statement_upline_lines', p_npn_map))
  WHERE sul.organization_id IS NULL OR (sul.writing_npn IS NOT NULL AND sul.writing_person_id IS NULL);
  GET DIAGNOSTICS v_upd = ROW_COUNT;
  table_name := 'statement_upline_lines'; rows_updated := v_upd; rows_already_mapped := v_already;
  RETURN NEXT;

  -- 5. coherence.coherent_ledger_rows
  SELECT pg_catalog.count(*) INTO v_already
  FROM coherence.coherent_ledger_rows
  WHERE organization_id IS NOT NULL AND (writing_npn IS NULL OR writing_person_id IS NOT NULL);

  UPDATE coherence.coherent_ledger_rows clr
  SET organization_id = COALESCE(clr.organization_id, coherence._resolve_entity_org_id(clr.entity, 'coherent_ledger_rows', p_entity_map)),
      writing_person_id = COALESCE(clr.writing_person_id, coherence._resolve_writing_person_id(clr.writing_npn, 'coherent_ledger_rows', p_npn_map))
  WHERE clr.organization_id IS NULL OR (clr.writing_npn IS NOT NULL AND clr.writing_person_id IS NULL);
  GET DIAGNOSTICS v_upd = ROW_COUNT;
  table_name := 'coherent_ledger_rows'; rows_updated := v_upd; rows_already_mapped := v_already;
  RETURN NEXT;
END;
$$;

ALTER FUNCTION coherence._resolve_tenant_tree_org_ids() OWNER TO platform_versioner;
ALTER FUNCTION coherence._resolve_entity_org_id(TEXT, TEXT, JSONB) OWNER TO platform_versioner;
ALTER FUNCTION coherence._resolve_writing_person_id(TEXT, TEXT, JSONB) OWNER TO platform_versioner;
ALTER FUNCTION coherence.backfill_iam_foreign_keys(JSONB, JSONB) OWNER TO platform_versioner;

-- 3. Enable and force IAM-based Row-Level Security across ALL 31 Coherence business tables +
-- review_submissions + review_drafts (strictly platform_* service roles and platform_view_owner).
DO $$
DECLARE
  v_tbl TEXT;
BEGIN
  FOREACH v_tbl IN ARRAY ARRAY[
    'journal_entries', 'company_meta', 'stored_files', 'engine_versions',
    'input_versions', 'input_entries', 'input_changes',
    'approvals_files', 'approval_rows',
    'decision_commits', 'decisions', 'generated_overlays', 'review_queue_items',
    'runs', 'step_requests', 'cancel_requests', 'step_attempt_events', 'artifacts',
    'review_saves', 'emit_confirmations',
    'statement_batches', 'statement_agency_lines', 'statement_upline_lines',
    'run_materializations', 'bob_policies', 'bob_policy_financials', 'coherent_ledger_rows',
    'carries', 'abandonments', 'imported_files', 'checks',
    'review_submissions', 'review_drafts'
  ] LOOP
    EXECUTE pg_catalog.format('ALTER TABLE coherence.%I ENABLE ROW LEVEL SECURITY', v_tbl);
    EXECUTE pg_catalog.format('ALTER TABLE coherence.%I FORCE ROW LEVEL SECURITY', v_tbl);

    -- Operational policies for platform_worker (FOR SELECT only; writes go strictly through app_cmd.*),
    -- platform_migrator, platform_readonly, platform_writer
    EXECUTE pg_catalog.format(
      'CREATE POLICY %I ON coherence.%I FOR SELECT TO platform_worker USING (true)',
      v_tbl || '_platform_worker_sel', v_tbl
    );
    EXECUTE pg_catalog.format(
      'CREATE POLICY %I ON coherence.%I FOR ALL TO platform_migrator USING (true) WITH CHECK (true)',
      v_tbl || '_platform_migrator_all', v_tbl
    );
    EXECUTE pg_catalog.format(
      'CREATE POLICY %I ON coherence.%I FOR SELECT TO platform_readonly USING (true)',
      v_tbl || '_platform_ro', v_tbl
    );
    IF v_tbl IN ('review_submissions', 'review_drafts') THEN
      EXECUTE pg_catalog.format(
        'CREATE POLICY %I ON coherence.%I FOR ALL TO platform_writer USING (true) WITH CHECK (true)',
        v_tbl || '_platform_writer_all', v_tbl
      );
    ELSE
      EXECUTE pg_catalog.format(
        'CREATE POLICY %I ON coherence.%I FOR SELECT TO platform_writer USING (true)',
        v_tbl || '_platform_writer_sel', v_tbl
      );
      EXECUTE pg_catalog.format(
        'CREATE POLICY %I ON coherence.%I FOR INSERT TO platform_writer WITH CHECK (true)',
        v_tbl || '_platform_writer_ins', v_tbl
      );
    END IF;
  END LOOP;

  -- Narrow platform_versioner policies strictly on the five FK-upgraded tables for one-time backfill
  FOREACH v_tbl IN ARRAY ARRAY[
    'bob_policies', 'bob_policy_financials',
    'statement_agency_lines', 'statement_upline_lines', 'coherent_ledger_rows'
  ] LOOP
    EXECUTE pg_catalog.format(
      'CREATE POLICY %I ON coherence.%I FOR SELECT TO platform_versioner USING (true)',
      v_tbl || '_versioner_sel', v_tbl
    );
    EXECUTE pg_catalog.format(
      'CREATE POLICY %I ON coherence.%I FOR UPDATE TO platform_versioner USING (true) WITH CHECK (true)',
      v_tbl || '_versioner_upd', v_tbl
    );
  END LOOP;
END;
$$;

-- Enable and force RLS on platform.audit_journal so app_views.audit_journal is governed by RLS too.
-- Tenant bounding and archived-path reachability live once in Migration 008's iam.person_effective_grants().
ALTER TABLE platform.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.audit_journal FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_journal_service_all ON platform.audit_journal
  FOR ALL TO platform_writer, platform_iam_sync, platform_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY audit_journal_readonly_sel ON platform.audit_journal
  FOR SELECT TO platform_readonly, platform_worker USING (true);

-- Shared platform_view_owner read-rights and published-emit helpers (one check per data kind).
-- All functions live in app_views.*, are SECURITY DEFINER owned by NOBYPASSRLS platform_view_owner
-- (so FORCE RLS still applies and platform_app keeps zero privileges on schema coherence),
-- and pin SET search_path = pg_catalog.
CREATE OR REPLACE FUNCTION app_views._read_audit_journal_orgs()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam._strip_masked_vendors(iam.effective_wide_org_ids('act:platform.audit_journal.read'));
$$;

CREATE OR REPLACE FUNCTION app_views._read_has_full_tenant_right(p_right_id TEXT)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH tenant_orgs AS (
    SELECT iam._tenant_tree_org_ids(ARRAY['company', 'agency', 'team']) AS orgs
  )
  SELECT pg_catalog.cardinality(t.orgs) > 0
    AND t.orgs <@ ((SELECT iam.effective_wide_org_ids(p_right_id)))::uuid[]
  FROM tenant_orgs t;
$$;

-- Single workshop gate: Coherence's run workshop (runs, inputs, decisions, checks, journal, and unsent
-- outputs) is all-or-nothing, requiring both the workshop right and full-tenant unpublished.read.
CREATE OR REPLACE FUNCTION app_views._read_workshop_right(p_right_id TEXT)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT app_views._read_has_full_tenant_right(p_right_id)
    AND app_views._read_has_full_tenant_right('act:coherence.unpublished.read');
$$;

-- Uncorrelated wide-org array and narrow (org_id, person_id) set helpers per data kind so
-- PostgreSQL evaluates each helper once per statement (InitPlan / hashed SubPlan, never per row).
CREATE OR REPLACE FUNCTION app_views._read_bob_wide_orgs()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam.effective_wide_org_ids('act:coherence.bob.read');
$$;

CREATE OR REPLACE FUNCTION app_views._read_bob_narrow_pairs()
RETURNS TABLE (org_id UUID, person_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT org_id, person_id FROM iam.effective_narrow_pairs('act:coherence.bob.read');
$$;

CREATE OR REPLACE FUNCTION app_views._read_agency_statement_wide_orgs()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam.effective_wide_org_ids('act:coherence.statements.read');
$$;

CREATE OR REPLACE FUNCTION app_views._read_agency_statement_narrow_pairs()
RETURNS TABLE (org_id UUID, person_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT org_id, person_id FROM iam.effective_narrow_pairs('act:coherence.statements.read');
$$;

-- Money in statements (agency amount, record_id, tx_id, bob_policy_financials).
CREATE OR REPLACE FUNCTION app_views._read_statement_cash_wide_orgs()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam.effective_wide_org_ids('col:coherence.statement_cash');
$$;

CREATE OR REPLACE FUNCTION app_views._read_statement_cash_narrow_pairs()
RETURNS TABLE (org_id UUID, person_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT org_id, person_id FROM iam.effective_narrow_pairs('col:coherence.statement_cash');
$$;

-- Member PHI (mbi, member, dob, and member-identifying record_id / reversal_of / corrects_record_id).
CREATE OR REPLACE FUNCTION app_views._read_member_phi_wide_orgs()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam.effective_wide_org_ids('col:coherence.member_phi');
$$;

CREATE OR REPLACE FUNCTION app_views._read_member_phi_narrow_pairs()
RETURNS TABLE (org_id UUID, person_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT org_id, person_id FROM iam.effective_narrow_pairs('col:coherence.member_phi');
$$;

-- Member contact details (phone, email, address, county).
CREATE OR REPLACE FUNCTION app_views._read_member_contact_wide_orgs()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam.effective_wide_org_ids('col:coherence.member_contact');
$$;

CREATE OR REPLACE FUNCTION app_views._read_member_contact_narrow_pairs()
RETURNS TABLE (org_id UUID, person_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT org_id, person_id FROM iam.effective_narrow_pairs('col:coherence.member_contact');
$$;

-- Unsent runs (wide orgs for all tables + narrow pairs for BoB and agency statement lines).
CREATE OR REPLACE FUNCTION app_views._read_unpublished_wide_orgs()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam.effective_wide_org_ids('act:coherence.unpublished.read');
$$;

CREATE OR REPLACE FUNCTION app_views._read_unpublished_narrow_pairs()
RETURNS TABLE (org_id UUID, person_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT org_id, person_id FROM iam.effective_narrow_pairs('act:coherence.unpublished.read');
$$;

-- Upline money (wide-only column right governing upline_amount, gross_comm, and upline metadata).
CREATE OR REPLACE FUNCTION app_views._read_upline_cash_orgs()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT ((SELECT iam.effective_wide_org_ids('col:coherence.upline_cash')))::uuid[];
$$;

-- Upline statements (tenant + org wide col:coherence.upline_cash AND act:coherence.upline.read).
CREATE OR REPLACE FUNCTION app_views._read_upline_statement_orgs()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH s AS (
    SELECT
      (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true) AS tenant_org_id,
      iam.effective_wide_org_ids('col:coherence.upline_cash') AS ucash,
      iam.effective_wide_org_ids('act:coherence.upline.read') AS up
  )
  SELECT CASE
    WHEN s.tenant_org_id = ANY(s.ucash) AND s.tenant_org_id = ANY(s.up)
    THEN COALESCE((
      SELECT pg_catalog.array_agg(DISTINCT u.org_id)
      FROM pg_catalog.unnest(s.ucash) AS u(org_id)
      WHERE u.org_id = ANY(s.up)
    ), ARRAY[]::uuid[])
    ELSE ARRAY[]::uuid[]
  END
  FROM s;
$$;

-- Coherent Ledger (wide col:coherence.upline_cash AND act:coherence.ledger.read).
CREATE OR REPLACE FUNCTION app_views._read_ledger_orgs()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH s AS (
    SELECT
      iam.effective_wide_org_ids('col:coherence.upline_cash') AS ucash,
      iam.effective_wide_org_ids('act:coherence.ledger.read') AS led
  )
  SELECT COALESCE((
    SELECT pg_catalog.array_agg(DISTINCT u.org_id)
    FROM pg_catalog.unnest(s.ucash) AS u(org_id)
    WHERE u.org_id = ANY(s.led)
  ), ARRAY[]::uuid[])
  FROM s;
$$;

-- Entity statement reconciliation (single intersected wide org scope across all 5 reconciliation rights,
-- plus unpublished.read when p_include_unpublished is true; non-empty only when tenant is in scope).
CREATE OR REPLACE FUNCTION app_views._read_reconciliation_orgs(p_include_unpublished BOOLEAN DEFAULT false)
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH s AS (
    SELECT
      (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true) AS tenant_org_id,
      iam.effective_wide_org_ids('act:coherence.ledger.read') AS led,
      iam.effective_wide_org_ids('act:coherence.statements.read') AS stmt,
      iam.effective_wide_org_ids('act:coherence.upline.read') AS up,
      iam.effective_wide_org_ids('col:coherence.statement_cash') AS scash,
      iam.effective_wide_org_ids('col:coherence.upline_cash') AS ucash,
      CASE WHEN p_include_unpublished
        THEN iam.effective_wide_org_ids('act:coherence.unpublished.read')
        ELSE NULL
      END AS unpub
  )
  SELECT CASE
    WHEN s.tenant_org_id = ANY(s.led)
      AND s.tenant_org_id = ANY(s.stmt)
      AND s.tenant_org_id = ANY(s.up)
      AND s.tenant_org_id = ANY(s.scash)
      AND s.tenant_org_id = ANY(s.ucash)
      AND (NOT p_include_unpublished OR s.tenant_org_id = ANY(s.unpub))
    THEN COALESCE((
      SELECT pg_catalog.array_agg(DISTINCT u.org_id)
      FROM pg_catalog.unnest(s.led) AS u(org_id)
      WHERE u.org_id = ANY(s.stmt)
        AND u.org_id = ANY(s.up)
        AND u.org_id = ANY(s.scash)
        AND u.org_id = ANY(s.ucash)
        AND (NOT p_include_unpublished OR u.org_id = ANY(s.unpub))
    ), ARRAY[]::uuid[])
    ELSE ARRAY[]::uuid[]
  END
  FROM s;
$$;

-- Full Entity Manager / Emit outputs & bundle access (all eight tenant-wide rights:
-- BoB, ledger, statements, upline, statement cash, upline cash, member PHI, and member contact).
CREATE OR REPLACE FUNCTION app_views._read_has_full_entity_finance()
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT app_views._read_has_full_tenant_right('act:coherence.bob.read')
    AND app_views._read_has_full_tenant_right('act:coherence.ledger.read')
    AND app_views._read_has_full_tenant_right('act:coherence.statements.read')
    AND app_views._read_has_full_tenant_right('act:coherence.upline.read')
    AND app_views._read_has_full_tenant_right('col:coherence.statement_cash')
    AND app_views._read_has_full_tenant_right('col:coherence.upline_cash')
    AND app_views._read_has_full_tenant_right('col:coherence.member_phi')
    AND app_views._read_has_full_tenant_right('col:coherence.member_contact');
$$;

-- Run/metadata read rights (4 finished-goods rights + workshop runs.read) and overlapping unsent-run visibility (short-circuiting).
CREATE OR REPLACE FUNCTION app_views._read_has_run_meta_access()
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT pg_catalog.cardinality(iam.effective_any_org_ids('act:coherence.bob.read')) > 0
    OR app_views._read_workshop_right('act:coherence.runs.read')
    OR pg_catalog.cardinality(iam.effective_any_org_ids('act:coherence.statements.read')) > 0
    OR pg_catalog.cardinality(iam.effective_any_org_ids('act:coherence.upline.read')) > 0
    OR pg_catalog.cardinality(iam.effective_any_org_ids('act:coherence.ledger.read')) > 0;
$$;

CREATE OR REPLACE FUNCTION app_views._read_can_see_unsent_run_meta()
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH unpub AS (
    SELECT iam.effective_any_org_ids('act:coherence.unpublished.read') AS orgs
  )
  SELECT pg_catalog.cardinality(u.orgs) > 0
    AND (
      u.orgs && iam.effective_any_org_ids('act:coherence.bob.read')
      OR app_views._read_workshop_right('act:coherence.runs.read')
      OR u.orgs && iam.effective_any_org_ids('act:coherence.statements.read')
      OR u.orgs && iam.effective_any_org_ids('act:coherence.upline.read')
      OR u.orgs && iam.effective_any_org_ids('act:coherence.ledger.read')
    )
  FROM unpub u;
$$;

-- Statement-batch metadata read rights (3-right union) and overlapping unsent-batch visibility.
CREATE OR REPLACE FUNCTION app_views._read_has_statement_batch_access()
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT pg_catalog.cardinality(iam.effective_any_org_ids('act:coherence.statements.read')) > 0
    OR pg_catalog.cardinality(iam.effective_any_org_ids('act:coherence.upline.read')) > 0
    OR pg_catalog.cardinality(iam.effective_any_org_ids('act:coherence.ledger.read')) > 0;
$$;

CREATE OR REPLACE FUNCTION app_views._read_can_see_unsent_batch_meta()
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH unpub AS (
    SELECT iam.effective_any_org_ids('act:coherence.unpublished.read') AS orgs
  )
  SELECT pg_catalog.cardinality(u.orgs) > 0
    AND (
      u.orgs && iam.effective_any_org_ids('act:coherence.statements.read')
      OR u.orgs && iam.effective_any_org_ids('act:coherence.upline.read')
      OR u.orgs && iam.effective_any_org_ids('act:coherence.ledger.read')
    )
  FROM unpub u;
$$;

-- Single shared finished, unsuperseded attempt selector across app_views.*
-- (owned by NOBYPASSRLS platform_view_owner so FORCE RLS on step_attempt_events still applies).
CREATE OR REPLACE VIEW coherence.v_current_finished_attempts
WITH (security_barrier = true) AS
SELECT DISTINCT ON (e.run_id, e.step)
  e.id AS attempt_event_id,
  e.run_id,
  e.step,
  e.attempt_no,
  e.journal_seq
FROM coherence.step_attempt_events e
WHERE e.event_kind = 'finished'
  AND NOT EXISTS (
    SELECT 1
    FROM coherence.step_attempt_events sup
    WHERE sup.run_id = e.run_id
      AND sup.step = e.step
      AND sup.attempt_no = e.attempt_no
      AND sup.event_kind = 'superseded'
  )
ORDER BY e.run_id, e.step, e.attempt_no DESC;

ALTER VIEW coherence.v_current_finished_attempts OWNER TO platform_view_owner;
REVOKE ALL ON coherence.v_current_finished_attempts FROM PUBLIC, platform_app;

-- Single shared published-emit attempt definition (replaces all repeated finished/unsuperseded emit subqueries).
-- Runs as NOBYPASSRLS platform_view_owner and gates unsent runs on overlapping unpublished.read.
CREATE OR REPLACE FUNCTION app_views._read_published_emit_attempts()
RETURNS TABLE (
  attempt_event_id UUID,
  run_id UUID,
  attempt_journal_seq BIGINT,
  is_sent BOOLEAN
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT
    ev.attempt_event_id,
    r.id AS run_id,
    ev.journal_seq AS attempt_journal_seq,
    sent_info.is_sent
  FROM coherence.runs r
  JOIN coherence.v_current_finished_attempts ev
    ON ev.run_id = r.id
   AND ev.step = 'emit'
  CROSS JOIN LATERAL (
    SELECT EXISTS (
      SELECT 1 FROM coherence.carries c
      WHERE c.run_id = r.id AND c.carry_kind = 'sent'
    ) AS is_sent
  ) sent_info
  WHERE r.origin IN ('app', 'company_import')
    AND (r.source_folder IS NULL OR r.source_folder NOT LIKE 'company-abandoned/%')
    AND NOT EXISTS (SELECT 1 FROM coherence.abandonments a WHERE a.run_id = r.id)
    AND (sent_info.is_sent OR (SELECT app_views._read_can_see_unsent_run_meta()));
$$;

CREATE OR REPLACE FUNCTION app_views._read_published_emit_attempt_ids(p_is_sent BOOLEAN)
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT COALESCE(pg_catalog.array_agg(pe.attempt_event_id), ARRAY[]::uuid[])
  FROM app_views._read_published_emit_attempts() pe
  WHERE pe.is_sent = p_is_sent;
$$;

DO $$
DECLARE
  v_sig TEXT;
BEGIN
  -- Shared per-data-kind read predicates used in app_views.* views and platform_view_owner RLS policies.
  FOREACH v_sig IN ARRAY ARRAY[
    'app_views._read_audit_journal_orgs()',
    'app_views._read_has_full_tenant_right(text)',
    'app_views._read_workshop_right(text)',
    'app_views._read_bob_wide_orgs()',
    'app_views._read_bob_narrow_pairs()',
    'app_views._read_agency_statement_wide_orgs()',
    'app_views._read_agency_statement_narrow_pairs()',
    'app_views._read_statement_cash_wide_orgs()',
    'app_views._read_statement_cash_narrow_pairs()',
    'app_views._read_member_phi_wide_orgs()',
    'app_views._read_member_phi_narrow_pairs()',
    'app_views._read_member_contact_wide_orgs()',
    'app_views._read_member_contact_narrow_pairs()',
    'app_views._read_unpublished_wide_orgs()',
    'app_views._read_unpublished_narrow_pairs()',
    'app_views._read_upline_cash_orgs()',
    'app_views._read_upline_statement_orgs()',
    'app_views._read_ledger_orgs()',
    'app_views._read_reconciliation_orgs(boolean)',
    'app_views._read_has_full_entity_finance()',
    'app_views._read_has_run_meta_access()',
    'app_views._read_can_see_unsent_run_meta()',
    'app_views._read_has_statement_batch_access()',
    'app_views._read_can_see_unsent_batch_meta()',
    'app_views._read_published_emit_attempts()',
    'app_views._read_published_emit_attempt_ids(boolean)'
  ] LOOP
    EXECUTE 'ALTER FUNCTION ' || v_sig || ' OWNER TO platform_view_owner';
    EXECUTE 'REVOKE ALL ON FUNCTION ' || v_sig || ' FROM PUBLIC';
    -- PostgreSQL checks EXECUTE on functions inside views and RLS policies against current_user,
    -- so both app_views.* readers (platform_app and platform_readonly) require EXECUTE here.
    EXECUTE 'GRANT EXECUTE ON FUNCTION ' || v_sig || ' TO platform_view_owner, platform_app, platform_readonly';
  END LOOP;
END;
$$;

-- IAM-backed row rules for platform_view_owner on platform.audit_journal and leaf metadata tables
-- (strict DAG: zero cross-table references inside leaf policies; every iam.effective_* helper is already tenant-bounded in 008).
CREATE POLICY audit_journal_iam_read ON platform.audit_journal
  FOR SELECT TO platform_view_owner
  USING (
    target_org_id = ANY(((SELECT app_views._read_audit_journal_orgs()))::uuid[])
  );

CREATE POLICY company_meta_iam_read ON coherence.company_meta
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_has_run_meta_access()));

CREATE POLICY runs_iam_read ON coherence.runs
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT app_views._read_has_run_meta_access())
    OR (SELECT app_views._read_has_full_tenant_right('act:coherence.outputs.read'))
    OR (
      (SELECT app_views._read_workshop_right('act:coherence.decisions.read'))
      AND (SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi'))
    )
  );

CREATE POLICY step_attempt_events_iam_read ON coherence.step_attempt_events
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT app_views._read_has_run_meta_access())
    OR (SELECT app_views._read_has_full_tenant_right('act:coherence.outputs.read'))
    OR (
      (SELECT app_views._read_workshop_right('act:coherence.decisions.read'))
      AND (SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi'))
    )
  );

CREATE POLICY carries_iam_read ON coherence.carries
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT app_views._read_has_run_meta_access())
    OR (SELECT app_views._read_has_full_tenant_right('act:coherence.outputs.read'))
  );

CREATE POLICY abandonments_iam_read ON coherence.abandonments
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT app_views._read_has_run_meta_access())
    OR (SELECT app_views._read_has_full_tenant_right('act:coherence.outputs.read'))
  );

CREATE POLICY input_entries_iam_read ON coherence.input_entries
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.inputs.read')));

CREATE POLICY input_versions_iam_read ON coherence.input_versions
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.inputs.read')));

CREATE POLICY decision_commits_iam_read ON coherence.decision_commits
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.decisions.read')));

CREATE POLICY decisions_iam_read ON coherence.decisions
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.decisions.read')));

CREATE POLICY checks_iam_read ON coherence.checks
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.checks.read')));

CREATE POLICY journal_entries_iam_read ON coherence.journal_entries
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.journal.read')));

CREATE POLICY step_requests_iam_read ON coherence.step_requests
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.runs.read')));

CREATE POLICY cancel_requests_iam_read ON coherence.cancel_requests
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.runs.read')));

CREATE POLICY review_saves_iam_read ON coherence.review_saves
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT app_views._read_workshop_right('act:coherence.runs.read'))
    OR (SELECT app_views._read_workshop_right('act:coherence.decisions.read'))
  );

CREATE POLICY review_queue_items_iam_read ON coherence.review_queue_items
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.runs.read')));

CREATE POLICY generated_overlays_iam_read ON coherence.generated_overlays
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.runs.read')));

CREATE POLICY emit_confirmations_iam_read ON coherence.emit_confirmations
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.runs.read')));

-- Level-1 IAM-backed row rules on statement_batches and run_materializations (reference leaf tables only).
CREATE POLICY statement_batches_iam_read ON coherence.statement_batches
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT app_views._read_has_statement_batch_access())
    AND (
      batch_kind IN ('historical_sent', 'method_correction')
      OR (
        batch_kind = 'run_emission'
        AND (
          attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(true)))::uuid[])
          OR (
            attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(false)))::uuid[])
            AND (SELECT app_views._read_can_see_unsent_batch_meta())
          )
        )
      )
    )
  );

CREATE POLICY run_materializations_iam_read ON coherence.run_materializations
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT app_views._read_has_run_meta_access())
    AND (
      attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(true)))::uuid[])
      OR attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(false)))::uuid[])
    )
  );

-- Level-2 IAM-backed row rules for platform_view_owner on the five core Coherence data tables.
-- Tenant bounding and archived-path reachability are enforced once in Migration 008's evaluator;
-- all helpers are uncorrelated (= ANY / IN) so PostgreSQL evaluates each once per statement.
CREATE POLICY bob_policies_iam_read ON coherence.bob_policies
  FOR SELECT TO platform_view_owner
  USING (
    (
      organization_id = ANY(((SELECT app_views._read_bob_wide_orgs()))::uuid[])
      OR (organization_id, writing_person_id) IN (
        SELECT np.org_id, np.person_id FROM app_views._read_bob_narrow_pairs() np
      )
    )
    AND (
      attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(true)))::uuid[])
      OR (
        attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(false)))::uuid[])
        AND (
          organization_id = ANY(((SELECT app_views._read_unpublished_wide_orgs()))::uuid[])
          OR (organization_id, writing_person_id) IN (
            SELECT np.org_id, np.person_id FROM app_views._read_unpublished_narrow_pairs() np
          )
        )
      )
    )
  );

CREATE POLICY bob_policy_financials_iam_read ON coherence.bob_policy_financials
  FOR SELECT TO platform_view_owner
  USING (
    (
      organization_id = ANY(((SELECT app_views._read_bob_wide_orgs()))::uuid[])
      OR (organization_id, writing_person_id) IN (
        SELECT np.org_id, np.person_id FROM app_views._read_bob_narrow_pairs() np
      )
    )
    AND (
      organization_id = ANY(((SELECT app_views._read_statement_cash_wide_orgs()))::uuid[])
      OR (organization_id, writing_person_id) IN (
        SELECT np.org_id, np.person_id FROM app_views._read_statement_cash_narrow_pairs() np
      )
    )
    AND (
      attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(true)))::uuid[])
      OR (
        attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(false)))::uuid[])
        AND (
          organization_id = ANY(((SELECT app_views._read_unpublished_wide_orgs()))::uuid[])
          OR (organization_id, writing_person_id) IN (
            SELECT np.org_id, np.person_id FROM app_views._read_unpublished_narrow_pairs() np
          )
        )
      )
    )
  );

CREATE POLICY statement_agency_lines_iam_read ON coherence.statement_agency_lines
  FOR SELECT TO platform_view_owner
  USING (
    (
      organization_id = ANY(((SELECT app_views._read_agency_statement_wide_orgs()))::uuid[])
      OR (organization_id, writing_person_id) IN (
        SELECT np.org_id, np.person_id FROM app_views._read_agency_statement_narrow_pairs() np
      )
    )
    AND (
      batch_id IN (
        SELECT sb.id
        FROM coherence.statement_batches sb
        WHERE sb.batch_kind IN ('historical_sent', 'method_correction')
           OR (
             sb.batch_kind = 'run_emission'
             AND sb.attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(true)))::uuid[])
           )
      )
      OR (
        batch_id IN (
          SELECT sb.id
          FROM coherence.statement_batches sb
          WHERE sb.batch_kind = 'run_emission'
            AND sb.attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(false)))::uuid[])
        )
        AND (
          organization_id = ANY(((SELECT app_views._read_unpublished_wide_orgs()))::uuid[])
          OR (organization_id, writing_person_id) IN (
            SELECT np.org_id, np.person_id FROM app_views._read_unpublished_narrow_pairs() np
          )
        )
      )
    )
  );

CREATE POLICY statement_upline_lines_iam_read ON coherence.statement_upline_lines
  FOR SELECT TO platform_view_owner
  USING (
    organization_id = ANY(((SELECT app_views._read_upline_statement_orgs()))::uuid[])
    AND (
      batch_id IN (
        SELECT sb.id
        FROM coherence.statement_batches sb
        WHERE sb.batch_kind IN ('historical_sent', 'method_correction')
           OR (
             sb.batch_kind = 'run_emission'
             AND sb.attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(true)))::uuid[])
           )
      )
      OR (
        batch_id IN (
          SELECT sb.id
          FROM coherence.statement_batches sb
          WHERE sb.batch_kind = 'run_emission'
            AND sb.attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(false)))::uuid[])
        )
        AND organization_id = ANY(((SELECT app_views._read_unpublished_wide_orgs()))::uuid[])
      )
    )
  );

CREATE POLICY coherent_ledger_rows_iam_read ON coherence.coherent_ledger_rows
  FOR SELECT TO platform_view_owner
  USING (
    organization_id = ANY(((SELECT app_views._read_ledger_orgs()))::uuid[])
    AND (
      attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(true)))::uuid[])
      OR (
        attempt_event_id = ANY(((SELECT app_views._read_published_emit_attempt_ids(false)))::uuid[])
        AND organization_id = ANY(((SELECT app_views._read_unpublished_wide_orgs()))::uuid[])
      )
    )
  );

-- 4. Grant platform_view_owner the exact base-table SELECT and read-helper privileges it needs under
-- FORCE RLS (zero privileges granted to platform_app or PUBLIC on coherence).
GRANT USAGE ON SCHEMA coherence, iam, platform, app_views TO platform_view_owner;
GRANT SELECT ON
  coherence.company_meta,
  coherence.bob_policies,
  coherence.bob_policy_financials,
  coherence.statement_batches,
  coherence.statement_agency_lines,
  coherence.statement_upline_lines,
  coherence.coherent_ledger_rows,
  coherence.run_materializations,
  coherence.runs,
  coherence.input_versions,
  coherence.input_entries,
  coherence.decision_commits,
  coherence.decisions,
  coherence.checks,
  coherence.journal_entries,
  coherence.carries,
  coherence.abandonments,
  coherence.step_attempt_events,
  coherence.step_requests,
  coherence.cancel_requests,
  coherence.review_saves,
  coherence.review_queue_items,
  coherence.generated_overlays,
  coherence.emit_confirmations,
  platform.audit_journal,
  iam.database_context,
  iam.organizations,
  iam.v_organization_closure,
  iam.person_versions
TO platform_view_owner;
GRANT EXECUTE ON FUNCTION
  coherence.run_effective_statement_batches(UUID)
TO platform_view_owner;

-- 5. Security-barrier views in app_views.*, owned by platform_view_owner (security_invoker = false).
-- Zero copied derived tables: v_current_policy_periods and v_current_commission_ledger are live views.
CREATE OR REPLACE VIEW app_views.coherence_bob
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT
    app_views._read_upline_cash_orgs() AS ucash,
    app_views._read_statement_cash_wide_orgs() AS scash,
    app_views._read_member_phi_wide_orgs() AS mphi,
    app_views._read_member_contact_wide_orgs() AS mcontact
)
SELECT
  bp.attempt_event_id,
  bp.run_id,
  bp.organization_id,
  bp.writing_person_id,
  bp.external_policy_id,
  bp.policy_id,
  bp.carrier_policy_number,
  bp.crm_policy_number,
  CASE WHEN gate.show_upline THEN bpf.enrollment_code ELSE NULL END AS enrollment_code,
  bp.carrier,
  bp.plan_type,
  bp.plan_name,
  bp.simple_plan_type,
  CASE WHEN gate.show_member_phi THEN bp.mbi ELSE NULL END AS mbi,
  CASE WHEN gate.show_member_phi THEN bp.member ELSE NULL END AS member,
  CASE WHEN gate.show_member_phi THEN bp.dob ELSE NULL END AS dob,
  CASE WHEN gate.show_member_contact THEN bp.phone ELSE NULL END AS phone,
  CASE WHEN gate.show_member_contact THEN bp.email ELSE NULL END AS email,
  CASE WHEN gate.show_member_contact THEN bp.address ELSE NULL END AS address,
  CASE WHEN gate.show_member_contact THEN bp.county ELSE NULL END AS county,
  bp.state,
  bp.submission_date,
  bp.origin_effective,
  bp.effective_date,
  bp.termination_date,
  CASE WHEN gate.show_upline THEN bpf.min_date ELSE NULL END AS min_date,
  CASE WHEN gate.show_upline THEN bpf.anchor_date ELSE NULL END AS anchor_date,
  CASE WHEN gate.show_stmt THEN bpf.amount ELSE NULL END AS amount,
  CASE WHEN gate.show_upline THEN bpf.upline_amount ELSE NULL END AS upline_amount,
  bp.writing_npn,
  bp.writing_agent,
  bp.entity,
  CASE WHEN gate.show_upline THEN bpf.agency_id ELSE NULL END AS agency_id,
  bp.status,
  CASE WHEN gate.show_upline THEN bp.coherent_status ELSE NULL END AS coherent_status,
  CASE WHEN gate.show_upline AND gate.show_member_phi THEN bpf.conflicts ELSE NULL END AS conflicts,
  CASE WHEN gate.show_upline THEN bpf.spine_source ELSE NULL END AS spine_source,
  CASE WHEN gate.show_upline THEN bpf.confidence_level ELSE NULL END AS confidence_level,
  CASE WHEN gate.show_upline THEN bpf.coherent_trajectory ELSE NULL END AS coherent_trajectory,
  bp.journal_seq
FROM coherence.bob_policies bp
LEFT JOIN coherence.bob_policy_financials bpf
  ON bpf.attempt_event_id = bp.attempt_event_id AND bpf.policy_id = bp.policy_id
CROSS JOIN scopes s
CROSS JOIN LATERAL (
  SELECT
    (bp.organization_id = ANY(s.ucash)) AS show_upline,
    COALESCE(
      bp.organization_id = ANY(s.scash)
      OR (bp.organization_id, bp.writing_person_id) IN (
        SELECT np.org_id, np.person_id FROM app_views._read_statement_cash_narrow_pairs() np
      ),
      false
    ) AS show_stmt,
    COALESCE(
      bp.organization_id = ANY(s.mphi)
      OR (bp.organization_id, bp.writing_person_id) IN (
        SELECT np.org_id, np.person_id FROM app_views._read_member_phi_narrow_pairs() np
      ),
      false
    ) AS show_member_phi,
    COALESCE(
      bp.organization_id = ANY(s.mcontact)
      OR (bp.organization_id, bp.writing_person_id) IN (
        SELECT np.org_id, np.person_id FROM app_views._read_member_contact_narrow_pairs() np
      ),
      false
    ) AS show_member_contact
) gate;

-- Live view replacing any copied policy_periods table: every sent run stays eligible so a newest
-- sent run with zero rows for the caller never falls back to a stale older run, while unsent runs
-- are eligible only when they contain policies visible to the caller.
CREATE OR REPLACE VIEW app_views.v_current_policy_periods
WITH (security_barrier = true) AS
WITH latest_rm AS (
  SELECT rm.attempt_event_id, rm.run_id, rm.statement_date, rm.corpus_tail, rm.agency_start
  FROM coherence.run_materializations rm
  JOIN coherence.runs r ON r.id = rm.run_id
  JOIN app_views._read_published_emit_attempts() pe ON pe.attempt_event_id = rm.attempt_event_id
  WHERE pe.is_sent
    OR EXISTS (
      SELECT 1 FROM coherence.bob_policies bp_vis
      WHERE bp_vis.attempt_event_id = rm.attempt_event_id
    )
  ORDER BY rm.statement_date DESC, r.folder_number DESC, rm.journal_seq DESC
  LIMIT 1
)
SELECT
  latest_rm.statement_date AS run_statement_date,
  latest_rm.corpus_tail,
  latest_rm.agency_start,
  b.*
FROM latest_rm
JOIN app_views.coherence_bob b ON b.attempt_event_id = latest_rm.attempt_event_id;

CREATE OR REPLACE VIEW app_views.coherence_statement_batches
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT
    app_views._read_has_full_tenant_right('col:coherence.upline_cash') AS full_upline,
    app_views._read_has_full_tenant_right('act:coherence.unpublished.read') AS full_unpub,
    app_views._read_published_emit_attempt_ids(true) AS sent_emits
)
SELECT
  sb.id,
  sb.batch_kind,
  sb.statement_date,
  sb.run_id,
  sb.attempt_event_id,
  sb.source_file_name,
  sb.reason,
  -- Company-wide aggregate totals are hidden from downline agencies so sibling agency totals
  -- can never be deduced by subtraction; agencies read their own totals from coherence_statement_totals.
  CASE WHEN gate.show_company_totals THEN sb.agency_line_count ELSE NULL END AS agency_line_count,
  CASE WHEN gate.show_company_totals THEN sb.agency_lines_sha256 ELSE NULL END AS agency_lines_sha256,
  CASE WHEN gate.show_company_totals THEN sb.agency_net_total ELSE NULL END AS agency_net_total,
  CASE WHEN gate.show_company_totals THEN sb.upline_line_count ELSE NULL END AS upline_line_count,
  CASE WHEN gate.show_company_totals THEN sb.upline_lines_sha256 ELSE NULL END AS upline_lines_sha256,
  CASE WHEN gate.show_company_totals THEN sb.upline_net_total ELSE NULL END AS upline_net_total,
  sb.journal_seq
FROM coherence.statement_batches sb
CROSS JOIN scopes s
CROSS JOIN LATERAL (
  SELECT (
    s.full_upline
    AND (
      s.full_unpub
      OR sb.batch_kind IN ('historical_sent', 'method_correction')
      OR (sb.batch_kind = 'run_emission' AND sb.attempt_event_id = ANY(s.sent_emits))
    )
  ) AS show_company_totals
) gate;

-- Agency statement lines: tx_id and amount require col:coherence.statement_cash; mbi and member
-- require col:coherence.member_phi; record_id / reversal_of / corrects_record_id embed both member
-- names/MBIs and dollar values so they require both statement_cash and member_phi; gross_comm
-- requires col:coherence.upline_cash (preventing agency managers from subtracting amount from gross_comm).
CREATE OR REPLACE VIEW app_views.coherence_statement_agency_lines
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT
    app_views._read_upline_cash_orgs() AS ucash,
    app_views._read_statement_cash_wide_orgs() AS scash,
    app_views._read_member_phi_wide_orgs() AS mphi
)
SELECT
  sal.batch_id,
  sal.line_no,
  sal.statement_date,
  sal.entry_kind,
  sal.run_action,
  sal.organization_id,
  sal.writing_person_id,
  sal.entity,
  sal.writing_npn,
  sal.writing_agent,
  CASE WHEN gate.show_stmt AND gate.show_member_phi THEN sal.record_id ELSE NULL END AS record_id,
  CASE WHEN gate.show_stmt AND gate.show_member_phi THEN sal.reversal_of ELSE NULL END AS reversal_of,
  CASE WHEN gate.show_stmt AND gate.show_member_phi THEN sal.corrects_record_id ELSE NULL END AS corrects_record_id,
  sal.source_file,
  sal.sheet_name,
  sal.source_row_no,
  sal.src_type,
  sal.carrier,
  CASE WHEN gate.show_member_phi THEN sal.mbi ELSE NULL END AS mbi,
  CASE WHEN gate.show_member_phi THEN sal.member ELSE NULL END AS member,
  sal.external_policy_id,
  sal.policy_id,
  CASE WHEN gate.show_stmt THEN sal.tx_id ELSE NULL END AS tx_id,
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
  CASE WHEN gate.show_upline THEN sal.gross_comm ELSE NULL END AS gross_comm,
  CASE WHEN gate.show_stmt THEN sal.amount ELSE NULL END AS amount,
  CASE WHEN gate.show_member_phi THEN sal.reason ELSE NULL END AS reason,
  CASE WHEN gate.show_member_phi THEN sal.notes ELSE NULL END AS notes,
  sal.journal_seq
FROM coherence.statement_agency_lines sal
CROSS JOIN scopes s
CROSS JOIN LATERAL (
  SELECT
    (sal.organization_id = ANY(s.ucash)) AS show_upline,
    COALESCE(
      sal.organization_id = ANY(s.scash)
      OR (sal.organization_id, sal.writing_person_id) IN (
        SELECT np.org_id, np.person_id FROM app_views._read_statement_cash_narrow_pairs() np
      ),
      false
    ) AS show_stmt,
    COALESCE(
      sal.organization_id = ANY(s.mphi)
      OR (sal.organization_id, sal.writing_person_id) IN (
        SELECT np.org_id, np.person_id FROM app_views._read_member_phi_narrow_pairs() np
      ),
      false
    ) AS show_member_phi
) gate;

-- Upline statement lines report organization_id at the tenant company organization (owning
-- '<Company> Upline') while preserving the originating agency in source_organization_id,
-- and gate mbi, member, record_id, reversal_of, and corrects_record_id on wide col:coherence.member_phi.
CREATE OR REPLACE VIEW app_views.coherence_statement_upline_lines
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT
    (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true) AS tenant_org_id,
    COALESCE((SELECT cm.display_name || ' Upline' FROM coherence.company_meta cm LIMIT 1), 'Upline') AS statement_entity,
    app_views._read_member_phi_wide_orgs() AS mphi
)
SELECT
  sul.batch_id,
  sul.line_no,
  sul.statement_date,
  sul.entry_kind,
  sul.run_action,
  s.tenant_org_id AS organization_id,
  sul.organization_id AS source_organization_id,
  sul.writing_person_id,
  s.statement_entity,
  sul.source_entity,
  sul.marked_sent,
  sul.writing_npn,
  sul.writing_agent,
  CASE WHEN gate.show_member_phi THEN sul.record_id ELSE NULL END AS record_id,
  CASE WHEN gate.show_member_phi THEN sul.reversal_of ELSE NULL END AS reversal_of,
  CASE WHEN gate.show_member_phi THEN sul.corrects_record_id ELSE NULL END AS corrects_record_id,
  sul.source_file,
  sul.sheet_name,
  sul.source_row_no,
  sul.src_type,
  sul.carrier,
  CASE WHEN gate.show_member_phi THEN sul.mbi ELSE NULL END AS mbi,
  CASE WHEN gate.show_member_phi THEN sul.member ELSE NULL END AS member,
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
  CASE WHEN gate.show_member_phi THEN sul.reason ELSE NULL END AS reason,
  CASE WHEN gate.show_member_phi THEN sul.notes ELSE NULL END AS notes,
  sul.journal_seq
FROM coherence.statement_upline_lines sul
CROSS JOIN scopes s
CROSS JOIN LATERAL (
  SELECT (sul.organization_id = ANY(s.mphi)) AS show_member_phi
) gate;

CREATE OR REPLACE VIEW app_views.coherence_entity_statement_lines
WITH (security_barrier = true) AS
SELECT
  batch_id,
  line_no,
  statement_date,
  entry_kind,
  run_action,
  organization_id,
  organization_id AS source_organization_id,
  writing_person_id,
  entity AS statement_entity,
  'agency'::text AS account_kind,
  entity AS source_entity,
  true AS marked_sent,
  writing_npn,
  writing_agent,
  record_id,
  reversal_of,
  corrects_record_id,
  source_file,
  sheet_name,
  source_row_no,
  src_type,
  carrier,
  mbi,
  member,
  external_policy_id,
  policy_id,
  tx_id,
  plan_type,
  simple_plan_type,
  state,
  submission_date,
  origin_effective,
  effective_date,
  termination_date,
  earned_date,
  payment_date,
  posted_statement_date,
  revenue_type,
  gross_comm,
  amount,
  reason,
  notes,
  journal_seq
FROM app_views.coherence_statement_agency_lines
UNION ALL
SELECT
  batch_id,
  line_no,
  statement_date,
  entry_kind,
  run_action,
  organization_id,
  source_organization_id,
  writing_person_id,
  statement_entity,
  'upline'::text AS account_kind,
  source_entity,
  marked_sent,
  writing_npn,
  writing_agent,
  record_id,
  reversal_of,
  corrects_record_id,
  source_file,
  sheet_name,
  source_row_no,
  src_type,
  carrier,
  mbi,
  member,
  external_policy_id,
  policy_id,
  tx_id,
  plan_type,
  simple_plan_type,
  state,
  submission_date,
  origin_effective,
  effective_date,
  termination_date,
  earned_date,
  payment_date,
  posted_statement_date,
  revenue_type,
  gross_comm,
  amount,
  reason,
  notes,
  journal_seq
FROM app_views.coherence_statement_upline_lines;

CREATE OR REPLACE VIEW app_views.coherence_statement_totals
WITH (security_barrier = true) AS
SELECT
  batch_id,
  statement_date,
  organization_id,
  statement_entity,
  account_kind,
  src_type,
  pg_catalog.to_char(payment_date, 'YYYY-MM') AS payment_month,
  pg_catalog.count(*)::bigint AS line_count,
  CASE
    WHEN pg_catalog.bool_and(amount IS NOT NULL)
      THEN COALESCE(pg_catalog.sum(amount), 0.00)::numeric(14,2)
    ELSE NULL
  END AS net_amount
FROM app_views.coherence_entity_statement_lines
GROUP BY batch_id, statement_date, organization_id, statement_entity, account_kind, src_type, pg_catalog.to_char(payment_date, 'YYYY-MM');

CREATE OR REPLACE VIEW app_views.coherence_statement_date_totals
WITH (security_barrier = true) AS
SELECT
  statement_date,
  organization_id,
  statement_entity,
  account_kind,
  pg_catalog.count(*)::bigint AS line_count,
  CASE
    WHEN pg_catalog.bool_and(amount IS NOT NULL)
      THEN COALESCE(pg_catalog.sum(amount), 0.00)::numeric(14,2)
    ELSE NULL
  END AS net_amount
FROM app_views.coherence_entity_statement_lines
GROUP BY statement_date, organization_id, statement_entity, account_kind;

CREATE OR REPLACE VIEW app_views.coherence_statement_membership
WITH (security_barrier = true) AS
SELECT
  policy_id,
  tx_id,
  record_id,
  statement_date,
  organization_id,
  statement_entity,
  account_kind,
  run_action,
  pg_catalog.count(*)::bigint AS appearances,
  CASE
    WHEN pg_catalog.bool_and(amount IS NOT NULL)
      THEN COALESCE(pg_catalog.sum(amount), 0.00)::numeric(14,2)
    ELSE NULL
  END AS net_amount
FROM app_views.coherence_entity_statement_lines
GROUP BY policy_id, tx_id, record_id, statement_date, organization_id, statement_entity, account_kind, run_action;

CREATE OR REPLACE VIEW app_views.coherence_ledger
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT
    app_views._read_member_phi_wide_orgs() AS mphi
)
SELECT
  clr.attempt_event_id,
  clr.tx_id,
  clr.run_id,
  clr.organization_id,
  clr.writing_person_id,
  CASE WHEN gate.show_member_phi THEN clr.record_id ELSE NULL END AS record_id,
  clr.external_policy_id,
  clr.policy_id,
  clr.statement_name,
  clr.src_type,
  clr.carrier,
  CASE WHEN gate.show_member_phi THEN clr.mbi ELSE NULL END AS mbi,
  CASE WHEN gate.show_member_phi THEN clr.member ELSE NULL END AS member,
  clr.state,
  clr.plan_type,
  clr.simple_plan_type,
  clr.submission_date,
  clr.origin_effective,
  clr.effective_date,
  clr.termination_date,
  clr.earned_date,
  clr.payment_date,
  clr.statement_date,
  clr.min_date,
  clr.gross_comm,
  clr.revenue_type,
  clr.override_amount,
  clr.commission_amount,
  clr.hra_amount,
  clr.fee_amount,
  clr.other_amount,
  clr.downline_amount,
  clr.upline_amount,
  clr.writing_npn,
  clr.writing_agent,
  clr.entity,
  clr.payee_npn,
  clr.agency_id,
  clr.status,
  clr.policy_status,
  clr.cbob_c,
  clr.cbob_s,
  clr.sf,
  CASE WHEN gate.show_member_phi THEN clr.notes ELSE NULL END AS notes,
  CASE WHEN gate.show_member_phi THEN clr.coherent_notes ELSE NULL END AS coherent_notes,
  clr.sheet_name,
  clr.source_row_no,
  clr.journal_seq
FROM coherence.coherent_ledger_rows clr
CROSS JOIN scopes s
CROSS JOIN LATERAL (
  SELECT (clr.organization_id = ANY(s.mphi)) AS show_member_phi
) gate;

-- Live view replacing any copied commission_ledger_rows table: every sent run stays eligible so a
-- newest sent run with zero rows for the caller never falls back to a stale older run, while unsent
-- runs are eligible only when they contain ledger rows visible to the caller.
CREATE OR REPLACE VIEW app_views.v_current_commission_ledger
WITH (security_barrier = true) AS
WITH latest_rm AS (
  SELECT rm.attempt_event_id, rm.run_id, rm.statement_date
  FROM coherence.run_materializations rm
  JOIN coherence.runs r ON r.id = rm.run_id
  JOIN app_views._read_published_emit_attempts() pe ON pe.attempt_event_id = rm.attempt_event_id
  WHERE pe.is_sent
    OR EXISTS (
      SELECT 1 FROM coherence.coherent_ledger_rows clr_vis
      WHERE clr_vis.attempt_event_id = rm.attempt_event_id
    )
  ORDER BY rm.statement_date DESC, r.folder_number DESC, rm.journal_seq DESC
  LIMIT 1
)
SELECT
  latest_rm.statement_date AS run_statement_date,
  l.*
FROM latest_rm
JOIN app_views.coherence_ledger l
  ON l.attempt_event_id = latest_rm.attempt_event_id;

-- IAM-gated view-owner wrapper over coherence.run_effective_statement_batches() so
-- app_views.coherence_entity_statement_reconciliation shares the single SQL batch selector
-- while platform_app holds zero EXECUTE privileges in schema coherence.
-- Returns batches strictly for a run visible in coherence.run_materializations under its FORCE RLS
-- (sent or unpublished.read, not abandoned, app/company_import, finished unsuperseded Emit)
-- and only when the caller holds the shared reconciliation rights at the tenant.
CREATE OR REPLACE FUNCTION app_views.coherence_effective_statement_batches(p_run_id UUID)
RETURNS TABLE (batch_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT eff.batch_id
  FROM coherence.run_materializations rm
  JOIN app_views._read_published_emit_attempts() pe ON pe.attempt_event_id = rm.attempt_event_id
  CROSS JOIN LATERAL coherence.run_effective_statement_batches(rm.run_id) eff
  WHERE rm.run_id = p_run_id
    AND pg_catalog.cardinality(
      CASE WHEN pe.is_sent
        THEN (SELECT app_views._read_reconciliation_orgs(false))
        ELSE (SELECT app_views._read_reconciliation_orgs(true))
      END
    ) > 0;
$$;

ALTER FUNCTION app_views.coherence_effective_statement_batches(UUID) OWNER TO platform_view_owner;
REVOKE ALL ON FUNCTION app_views.coherence_effective_statement_batches(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_views.coherence_effective_statement_batches(UUID) TO platform_app, platform_readonly;

-- Reconciliation view per materialized run (Entity Manager / Nusear internal only; requires
-- the shared reconciliation rights, applying ONE consistent intersected org scope across both sides).
CREATE OR REPLACE VIEW app_views.coherence_entity_statement_reconciliation
WITH (security_barrier = true) AS
WITH scope_sets AS (
  SELECT
    (SELECT app_views._read_reconciliation_orgs(false)) AS sent_orgs,
    (SELECT app_views._read_reconciliation_orgs(true)) AS unsent_orgs
),
scoped_runs AS (
  SELECT
    rm.run_id,
    rm.attempt_event_id,
    rm.statement_date,
    r.id AS r_id,
    CASE WHEN pe.is_sent THEN sc.sent_orgs ELSE sc.unsent_orgs END AS eff_orgs
  FROM coherence.run_materializations rm
  JOIN coherence.runs r ON r.id = rm.run_id
  JOIN app_views._read_published_emit_attempts() pe ON pe.attempt_event_id = rm.attempt_event_id
  CROSS JOIN scope_sets sc
  WHERE pg_catalog.cardinality(CASE WHEN pe.is_sent THEN sc.sent_orgs ELSE sc.unsent_orgs END) > 0
)
SELECT
  sr.run_id,
  sr.attempt_event_id,
  sr.statement_date,
  rec.statement_entity,
  rec.account_kind,
  rec.statement_total,
  rec.ledger_total,
  (rec.statement_total - rec.ledger_total)::numeric(14,2) AS variance,
  (rec.statement_total = rec.ledger_total) AS reconciled
FROM scoped_runs sr
JOIN LATERAL (
  WITH eff AS (
    SELECT batch_id FROM app_views.coherence_effective_statement_batches(sr.r_id)
  ),
  stmt_ag AS (
    SELECT sal.entity AS statement_entity,
           COALESCE(pg_catalog.sum(sal.amount), 0.00)::numeric(14,2) AS statement_total
    FROM coherence.statement_agency_lines sal
    JOIN eff ON eff.batch_id = sal.batch_id
    WHERE sal.organization_id = ANY(sr.eff_orgs)
    GROUP BY sal.entity
  ),
  led_ag AS (
    SELECT clr.entity AS statement_entity,
           COALESCE(pg_catalog.sum(clr.downline_amount), 0.00)::numeric(14,2) AS ledger_total
    FROM coherence.coherent_ledger_rows clr
    WHERE clr.attempt_event_id = sr.attempt_event_id
      AND clr.organization_id = ANY(sr.eff_orgs)
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
      COALESCE((SELECT cm.display_name || ' Upline' FROM coherence.company_meta cm LIMIT 1), 'Upline') AS statement_entity,
      'upline'::text AS account_kind,
      COALESCE((
        SELECT pg_catalog.sum(sul.amount)
        FROM coherence.statement_upline_lines sul
        JOIN eff ON eff.batch_id = sul.batch_id
        WHERE sul.organization_id = ANY(sr.eff_orgs)
      ), 0.00)::numeric(14,2) AS statement_total,
      COALESCE((
        SELECT pg_catalog.sum(clr.upline_amount)
        FROM coherence.coherent_ledger_rows clr
        WHERE clr.attempt_event_id = sr.attempt_event_id
          AND clr.organization_id = ANY(sr.eff_orgs)
      ), 0.00)::numeric(14,2) AS ledger_total
  )
  SELECT * FROM ag_joined
  UNION ALL
  SELECT * FROM up_joined
) rec ON true;

-- Narrow definer-rights helper view owned by read-only platform_readonly (SELECT strictly for
-- platform_view_owner; zero privileges for platform_app or PUBLIC) so app_views.coherence_runs
-- reports the true latest_journal_seq tip even for workshop readers who lack decisions.read or
-- statements.read, with zero per-run RLS or rights work.
CREATE OR REPLACE VIEW coherence.v_run_latest_journal_seq
WITH (security_barrier = true) AS
SELECT
  r.id AS run_id,
  GREATEST(
    r.journal_seq,
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.step_requests WHERE run_id = r.id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.cancel_requests WHERE run_id = r.id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.step_attempt_events WHERE run_id = r.id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.review_saves WHERE run_id = r.id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.review_queue_items WHERE run_id = r.id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.generated_overlays WHERE run_id = r.id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.decisions WHERE run_id = r.id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.emit_confirmations WHERE run_id = r.id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.statement_batches WHERE run_id = r.id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.run_materializations WHERE run_id = r.id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.carries WHERE run_id = r.id), 0),
    COALESCE((SELECT pg_catalog.max(journal_seq) FROM coherence.abandonments WHERE run_id = r.id), 0)
  ) AS latest_journal_seq
FROM coherence.runs r
WHERE (SELECT app_views._read_workshop_right('act:coherence.runs.read'));

ALTER VIEW coherence.v_run_latest_journal_seq OWNER TO platform_readonly;
REVOKE ALL ON coherence.v_run_latest_journal_seq FROM PUBLIC, platform_app;
GRANT SELECT ON coherence.v_run_latest_journal_seq TO platform_view_owner;

-- Narrow definer-rights wrapper over coherence.run_stage(UUID, BIGINT) owned by read-only
-- platform_readonly (whose RLS policies are USING (true)), executable strictly by
-- platform_view_owner after the view or wrapper's single workshop check. Keeps coherence.run_stage
-- as the single source of truth while performing zero per-run rights or RLS work.
CREATE OR REPLACE FUNCTION coherence._ro_run_stage(p_run_id UUID, p_as_of_seq BIGINT DEFAULT NULL)
RETURNS TEXT
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT coherence.run_stage(p_run_id, p_as_of_seq);
$$;

ALTER FUNCTION coherence._ro_run_stage(UUID, BIGINT) OWNER TO platform_readonly;
REVOKE ALL ON FUNCTION coherence._ro_run_stage(UUID, BIGINT) FROM PUBLIC, platform_app;
GRANT EXECUTE ON FUNCTION coherence._ro_run_stage(UUID, BIGINT) TO platform_view_owner;

-- IAM-gated view-owner wrapper over coherence._ro_run_stage(UUID, BIGINT) for historical as-of queries
-- while platform_app holds zero EXECUTE privileges in schema coherence.
CREATE OR REPLACE FUNCTION app_views.coherence_run_stage(p_run_id UUID, p_as_of_seq BIGINT DEFAULT NULL)
RETURNS TEXT
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT CASE
    WHEN (SELECT app_views._read_workshop_right('act:coherence.runs.read'))
      THEN coherence._ro_run_stage(p_run_id, p_as_of_seq)
    ELSE NULL
  END;
$$;

ALTER FUNCTION app_views.coherence_run_stage(UUID, BIGINT) OWNER TO platform_view_owner;
REVOKE ALL ON FUNCTION app_views.coherence_run_stage(UUID, BIGINT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_views.coherence_run_stage(UUID, BIGINT) TO platform_app, platform_readonly;

-- Single-evaluation workshop stage table for app_views.coherence_runs: runs the workshop gate ONCE as
-- platform_view_owner and delegates stage computation to platform_readonly coherence._ro_run_stage
-- (RLS USING (true), zero per-run rights or RLS work). Needed because PostgreSQL checks function
-- EXECUTE inside views against current_user (platform_app), not the view owner (platform_view_owner).
CREATE OR REPLACE FUNCTION app_views.coherence_run_stages()
RETURNS TABLE (
  run_id UUID,
  stage TEXT
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT r.id AS run_id, coherence._ro_run_stage(r.id, NULL) AS stage
  FROM coherence.runs r
  WHERE (SELECT app_views._read_workshop_right('act:coherence.runs.read'));
$$;

ALTER FUNCTION app_views.coherence_run_stages() OWNER TO platform_view_owner;
REVOKE ALL ON FUNCTION app_views.coherence_run_stages() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_views.coherence_run_stages() TO platform_app, platform_readonly;

CREATE OR REPLACE VIEW app_views.coherence_runs
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT
    app_views._read_workshop_right('act:coherence.runs.read') AS show_runs,
    app_views._read_has_full_tenant_right('col:coherence.member_phi') AS show_member_phi
),
run_stages AS MATERIALIZED (
  SELECT run_id, stage
  FROM app_views.coherence_run_stages()
)
SELECT
  r.id,
  r.statement_date,
  r.folder_number,
  r.origin,
  r.input_version_id,
  CASE WHEN s.show_member_phi THEN r.prior_approvals_sha256 ELSE NULL END AS prior_approvals_sha256,
  r.prior_decision_commit_id,
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
  tip.latest_journal_seq,
  rs.stage,
  EXISTS (SELECT 1 FROM coherence.carries c WHERE c.run_id = r.id AND c.carry_kind = 'sent') AS sent_recorded,
  EXISTS (SELECT 1 FROM coherence.carries c WHERE c.run_id = r.id AND c.carry_kind = 'approvals') AS approvals_carried,
  EXISTS (SELECT 1 FROM coherence.abandonments a WHERE a.run_id = r.id) AS abandoned
FROM coherence.runs r
JOIN run_stages rs ON rs.run_id = r.id
LEFT JOIN coherence.v_run_latest_journal_seq tip ON tip.run_id = r.id
CROSS JOIN scopes s
WHERE s.show_runs;

CREATE OR REPLACE VIEW app_views.coherence_input_versions
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT (
    app_views._read_has_full_tenant_right('col:coherence.member_phi')
    AND app_views._read_has_full_tenant_right('col:coherence.member_contact')
  ) AS show_file_handle
)
SELECT
  iv.id,
  iv.line_kind,
  iv.parent_id,
  iv.source_kind,
  iv.reason,
  iv.entry_count,
  CASE WHEN s.show_file_handle THEN iv.entries_sha256 ELSE NULL END AS entries_sha256,
  CASE WHEN s.show_file_handle THEN iv.entries_list_file_sha256 ELSE NULL END AS entries_list_file_sha256,
  iv.change_count,
  iv.changes_sha256,
  iv.journal_seq
FROM coherence.input_versions iv
CROSS JOIN scopes s;

CREATE OR REPLACE VIEW app_views.coherence_decision_commits
WITH (security_barrier = true) AS
SELECT
  dc.id,
  dc.parent_commit_id,
  dc.commit_kind,
  dc.header_contract,
  dc.added_decision_count,
  dc.cumulative_decision_count,
  dc.added_decisions_sha256,
  dc.imported,
  dc.original_at,
  dc.journal_seq
FROM coherence.decision_commits dc;

CREATE OR REPLACE VIEW app_views.coherence_decisions
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT
    app_views._read_has_full_tenant_right('col:coherence.member_phi') AS show_member_phi,
    app_views._read_has_full_tenant_right('col:platform.audit_journal.nusear_actor') AS show_nusear_actor,
    (SELECT dc.support_external_label FROM iam.database_context dc WHERE dc.singleton = true) AS support_label
)
SELECT
  d.id,
  d.decision_commit_id,
  d.row_order,
  d.run_id,
  d.review_save_id,
  d.surface,
  CASE WHEN s.show_member_phi THEN d.record_id ELSE NULL END AS record_id,
  d.replaces_decision_id,
  d.disposition,
  d.agent,
  d.agency,
  d.policy,
  d.book,
  d.month,
  d.status,
  CASE WHEN s.show_member_phi THEN d.note ELSE NULL END AS note,
  d.approved_amount,
  d.approved_agency,
  d.approved_agent,
  d.approved_agency_from,
  d.approved_agent_from,
  CASE
    WHEN NOT s.show_nusear_actor
      AND (d.acting_for = 'nusear_support' OR pv.principal_origin = 'nusear_staff')
      THEN s.support_label
    ELSE d.decided_by
  END AS decided_by,
  CASE
    WHEN NOT s.show_nusear_actor
      AND (d.acting_for = 'nusear_support' OR pv.principal_origin = 'nusear_staff')
      THEN s.support_label
    ELSE COALESCE(pv.preferred_name, d.decided_by)
  END AS decided_by_display,
  d.acting_for,
  d.decided_at,
  d.committed_at_raw,
  d.imported,
  d.journal_seq
FROM coherence.decisions d
LEFT JOIN iam.v_actor_display_lookup pv
  ON pv.person_id = (
    CASE
      WHEN d.decided_by ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        THEN d.decided_by::uuid
      ELSE NULL
    END
  )
CROSS JOIN scopes s;

CREATE OR REPLACE VIEW app_views.coherence_checks
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi') AS show_member_phi
)
SELECT
  ch.id,
  ch.check_kind,
  ch.run_id,
  ch.compared_run_id,
  ch.passed,
  CASE WHEN s.show_member_phi THEN ch.report ELSE NULL END AS report,
  ch.journal_seq
FROM coherence.checks ch
CROSS JOIN scopes s;

CREATE OR REPLACE VIEW app_views.coherence_journal
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT
    app_views._read_has_full_entity_finance() AS show_full_entity_finance,
    app_views._read_has_full_tenant_right('col:coherence.member_phi') AS show_member_phi,
    app_views._read_has_full_tenant_right('col:platform.audit_journal.nusear_actor') AS show_nusear_actor,
    (SELECT dc.support_external_label FROM iam.database_context dc WHERE dc.singleton = true) AS support_label
)
SELECT
  je.seq,
  je.recorded_at,
  CASE
    WHEN NOT s.show_nusear_actor
      AND (je.acting_for = 'nusear_support' OR pv.principal_origin = 'nusear_staff')
      THEN s.support_label
    ELSE je.actor
  END AS actor,
  CASE
    WHEN NOT s.show_nusear_actor
      AND (je.acting_for = 'nusear_support' OR pv.principal_origin = 'nusear_staff')
      THEN s.support_label
    ELSE COALESCE(pv.preferred_name, je.actor)
  END AS actor_display,
  je.acting_for,
  je.command_kind,
  je.command_key,
  je.request_sha256,
  CASE
    WHEN je.command_kind IN ('carry_sent', 'materialize_emit') AND s.show_full_entity_finance THEN je.body
    WHEN je.command_kind NOT IN ('carry_sent', 'materialize_emit') AND s.show_member_phi THEN je.body
    ELSE NULL
  END AS body,
  je.prev_hash,
  je.entry_hash
FROM coherence.journal_entries je
LEFT JOIN iam.v_actor_display_lookup pv
  ON pv.person_id = (
    CASE
      WHEN je.actor ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        THEN je.actor::uuid
      ELSE NULL
    END
  )
CROSS JOIN scopes s;

-- Platform audit journal view (from DESIGN.md section 2.5): masks Nusear staff identity for customers.
CREATE OR REPLACE VIEW app_views.audit_journal
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT
    iam.effective_wide_org_ids('col:platform.audit_journal.nusear_actor') AS nusear_actor_orgs,
    (SELECT dc.support_external_label FROM iam.database_context dc WHERE dc.singleton = true) AS support_label
)
SELECT
  j.seq,
  j.recorded_at,
  j.environment,
  j.recorded_as,
  j.target_org_id,
  j.command_kind,
  CASE
    WHEN (j.recorded_as = 'nusear_support' OR pv.principal_origin = 'nusear_staff')
      AND NOT (j.target_org_id = ANY(s.nusear_actor_orgs))
      THEN s.support_label
    ELSE pv.preferred_name
  END AS recorded_by_display,
  CASE
    WHEN j.target_org_id = ANY(s.nusear_actor_orgs)
      THEN j.actor_person_id
    ELSE NULL
  END AS actor_person_id
FROM platform.audit_journal j
LEFT JOIN iam.v_actor_display_lookup pv
  ON pv.person_id = j.actor_person_id
CROSS JOIN scopes s;

-- Assign ownership of every app_views.* view to platform_view_owner and grant SELECT strictly to
-- platform_app and platform_readonly.
DO $$
DECLARE
  v_view TEXT;
BEGIN
  FOREACH v_view IN ARRAY ARRAY[
    'coherence_bob',
    'v_current_policy_periods',
    'coherence_statement_batches',
    'coherence_statement_agency_lines',
    'coherence_statement_upline_lines',
    'coherence_entity_statement_lines',
    'coherence_statement_totals',
    'coherence_statement_date_totals',
    'coherence_statement_membership',
    'coherence_ledger',
    'v_current_commission_ledger',
    'coherence_entity_statement_reconciliation',
    'coherence_runs',
    'coherence_input_versions',
    'coherence_decision_commits',
    'coherence_decisions',
    'coherence_checks',
    'coherence_journal',
    'audit_journal'
  ] LOOP
    EXECUTE pg_catalog.format('ALTER VIEW app_views.%I OWNER TO platform_view_owner', v_view);
    EXECUTE pg_catalog.format('REVOKE ALL ON app_views.%I FROM PUBLIC', v_view);
    EXECUTE pg_catalog.format('GRANT SELECT ON app_views.%I TO platform_app, platform_readonly', v_view);
  END LOOP;
END;
$$;

GRANT USAGE ON SCHEMA app_views TO platform_app, platform_readonly;

-- 6. Internal command helpers owned by platform_writer.
-- Every write executes through a real signed app.session_token validated by iam.assert_can_write().
GRANT USAGE ON SCHEMA coherence, iam, platform, app_cmd TO platform_writer;
GRANT SELECT ON
  iam.database_context,
  iam.people,
  iam.person_versions,
  iam.agent_affiliations,
  iam.organizations,
  iam.organization_versions,
  iam.v_organization_closure
TO platform_writer;

DO $$
DECLARE
  v_tbl TEXT;
BEGIN
  FOREACH v_tbl IN ARRAY ARRAY[
    'journal_entries', 'company_meta', 'stored_files', 'engine_versions',
    'input_versions', 'input_entries', 'input_changes',
    'approvals_files', 'approval_rows',
    'decision_commits', 'decisions', 'generated_overlays', 'review_queue_items',
    'runs', 'step_requests', 'cancel_requests', 'step_attempt_events', 'artifacts',
    'review_saves', 'emit_confirmations',
    'statement_batches', 'statement_agency_lines', 'statement_upline_lines',
    'run_materializations', 'bob_policies', 'bob_policy_financials', 'coherent_ledger_rows',
    'carries', 'abandonments', 'imported_files', 'checks'
  ] LOOP
    EXECUTE pg_catalog.format('GRANT SELECT, INSERT ON coherence.%I TO platform_writer', v_tbl);
  END LOOP;
  GRANT SELECT, INSERT, UPDATE ON coherence.review_submissions TO platform_writer;
  GRANT SELECT, INSERT, UPDATE, DELETE ON coherence.review_drafts TO platform_writer;
END;
$$;

CREATE OR REPLACE FUNCTION coherence._cmd_resolve_context(
  p_right_id TEXT,
  p_principal_mode TEXT DEFAULT 'human_only'
)
RETURNS TABLE (
  environment TEXT,
  tenant_org_id UUID,
  company_slug TEXT,
  actor_person_id UUID,
  recorded_as TEXT,
  actor_label TEXT,
  acting_for_label TEXT
)
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_dc RECORD;
  v_auth RECORD;
  v_kind TEXT;
  v_recorded_as TEXT;
BEGIN
  IF p_principal_mode IS NULL OR p_principal_mode NOT IN ('human_only', 'service_only', 'human_or_service') THEN
    RAISE EXCEPTION 'INVALID_PRINCIPAL_MODE: unsupported principal mode %.', p_principal_mode
      USING ERRCODE = '22023';
  END IF;

  SELECT dc.environment, dc.tenant_org_id, dc.company_slug
  INTO v_dc
  FROM iam.database_context dc
  WHERE dc.singleton = true;

  IF v_dc.tenant_org_id IS NULL OR v_dc.environment IS NULL THEN
    RAISE EXCEPTION 'FORBIDDEN: database_context is not configured for a company database.'
      USING ERRCODE = '42501';
  END IF;

  SELECT a.actor_person_id, a.recorded_as
  INTO v_auth
  FROM iam.assert_can_write(p_right_id, v_dc.tenant_org_id) a;

  SELECT p.person_kind INTO v_kind FROM iam.people p WHERE p.id = v_auth.actor_person_id;

  IF p_principal_mode = 'service_only' AND v_kind IS DISTINCT FROM 'service' THEN
    RAISE EXCEPTION 'WORKER_ONLY: only the Coherence engine worker service identity may perform this operation.'
      USING ERRCODE = '42501';
  ELSIF p_principal_mode = 'human_only' AND v_kind IS DISTINCT FROM 'human' THEN
    RAISE EXCEPTION 'HUMAN_ONLY: service principals cannot execute human decision commands.'
      USING ERRCODE = '42501';
  ELSIF p_principal_mode = 'human_or_service' AND v_kind NOT IN ('human', 'service') THEN
    RAISE EXCEPTION 'FORBIDDEN: unsupported principal kind %.', v_kind
      USING ERRCODE = '42501';
  END IF;

  v_recorded_as := v_auth.recorded_as;

  RETURN QUERY SELECT
    v_dc.environment,
    v_dc.tenant_org_id,
    v_dc.company_slug,
    v_auth.actor_person_id,
    v_recorded_as,
    v_auth.actor_person_id::text,
    CASE WHEN v_recorded_as = 'nusear_support' THEN 'nusear_support'::text ELSE NULL::text END;
END;
$$;

CREATE OR REPLACE FUNCTION coherence._cmd_check_idempotency(
  p_command_kind TEXT,
  p_command_key TEXT,
  p_actor_label TEXT,
  p_acting_for_label TEXT,
  p_request_sha256 TEXT
)
RETURNS TABLE (
  existing_seq BIGINT,
  existing_body JSONB
)
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_ex RECORD;
BEGIN
  IF p_command_key IS NULL OR pg_catalog.length(p_command_key) < 1 OR pg_catalog.length(p_command_key) > 200 THEN
    RAISE EXCEPTION 'MISSING_COMMAND_KEY: command_key must be 1..200 characters.' USING ERRCODE = '22023';
  END IF;
  IF p_request_sha256 IS NULL OR p_request_sha256 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'INVALID_REQUEST_SHA256: request_sha256 must be 64 lowercase hex characters.' USING ERRCODE = '22023';
  END IF;

  SELECT je.seq, je.command_kind, je.actor, je.acting_for, je.request_sha256, je.body
  INTO v_ex
  FROM coherence.journal_entries je
  WHERE je.command_key = p_command_key;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  IF v_ex.command_kind = p_command_kind
     AND v_ex.actor = p_actor_label
     AND v_ex.acting_for IS NOT DISTINCT FROM p_acting_for_label
     AND v_ex.request_sha256 = p_request_sha256
  THEN
    RETURN QUERY SELECT v_ex.seq, v_ex.body;
    RETURN;
  END IF;

  RAISE EXCEPTION 'COMMAND_KEY_CONFLICT: command_key already used for a different request.'
    USING ERRCODE = '23505';
END;
$$;

CREATE OR REPLACE FUNCTION coherence._cmd_check_expected_seq(
  p_expected_seq BIGINT,
  p_scope_run_id UUID DEFAULT NULL,
  p_scope_standing_line BOOLEAN DEFAULT false,
  p_strict_global BOOLEAN DEFAULT false
)
RETURNS VOID
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_max_seq BIGINT;
  v_run_latest BIGINT;
  v_standing_latest BIGINT;
BEGIN
  IF p_expected_seq IS NULL THEN
    RETURN;
  END IF;
  IF p_expected_seq < 0 THEN
    RAISE EXCEPTION 'INVALID_JOURNAL_SEQ: expected_seq must be non-negative.' USING ERRCODE = '22023';
  END IF;

  SELECT COALESCE(pg_catalog.max(seq), 0) INTO v_max_seq FROM coherence.journal_entries;
  IF p_expected_seq > v_max_seq THEN
    RAISE EXCEPTION 'STALE_JOURNAL_POSITION: expected_seq % is ahead of database tip %.', p_expected_seq, v_max_seq
      USING ERRCODE = '40001';
  END IF;

  IF p_scope_run_id IS NOT NULL THEN
    v_run_latest := coherence.run_latest_journal_seq(p_scope_run_id);
    IF v_run_latest > p_expected_seq THEN
      RAISE EXCEPTION 'STALE_JOURNAL_POSITION: run changed since journal_seq %.', p_expected_seq
        USING ERRCODE = '40001';
    END IF;
  END IF;

  IF p_scope_standing_line THEN
    SELECT COALESCE(pg_catalog.max(journal_seq), 0) INTO v_standing_latest
    FROM coherence.input_versions WHERE line_kind = 'standing';
    IF v_standing_latest > p_expected_seq THEN
      RAISE EXCEPTION 'STALE_JOURNAL_POSITION: standing input changed since journal_seq %.', p_expected_seq
        USING ERRCODE = '40001';
    END IF;
  END IF;

  IF p_strict_global AND v_max_seq > p_expected_seq THEN
    RAISE EXCEPTION 'STALE_JOURNAL_POSITION: database changed since journal_seq %.', p_expected_seq
      USING ERRCODE = '40001';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION coherence._cmd_write_journals(
  p_env TEXT,
  p_tenant_org_id UUID,
  p_actor_person_id UUID,
  p_recorded_as TEXT,
  p_actor_label TEXT,
  p_acting_for_label TEXT,
  p_command_kind TEXT,
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_coherence_body JSONB,
  p_audit_body JSONB
)
RETURNS BIGINT
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_coh_seq BIGINT;
  v_audit_key TEXT;
BEGIN
  INSERT INTO coherence.journal_entries (
    actor, acting_for, command_kind, command_key, request_sha256, body
  )
  VALUES (
    p_actor_label, p_acting_for_label, p_command_kind, p_command_key, p_request_sha256, p_coherence_body
  )
  RETURNING seq INTO v_coh_seq;

  v_audit_key := CASE
    WHEN pg_catalog.length(p_command_key) <= 190 THEN 'coherence:' || p_command_key
    ELSE 'coh:' || coherence.sha256_text(p_command_key)
  END;

  INSERT INTO platform.audit_journal (
    environment, actor_person_id, recorded_as, target_org_id,
    command_kind, command_key, request_sha256, body
  )
  VALUES (
    p_env, p_actor_person_id, p_recorded_as, p_tenant_org_id,
    'coherence.' || p_command_kind, v_audit_key, p_request_sha256,
    coherence._cmd_jsonb_object(p_audit_body) || pg_catalog.jsonb_build_object('coherence_journal_seq', v_coh_seq)
  );

  RETURN v_coh_seq;
END;
$$;

CREATE OR REPLACE FUNCTION coherence._cmd_jsonb_array(p_val JSONB)
RETURNS JSONB
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT CASE
    WHEN p_val IS NULL OR pg_catalog.jsonb_typeof(p_val) = 'null' THEN '[]'::jsonb
    ELSE p_val
  END;
$$;

CREATE OR REPLACE FUNCTION coherence._cmd_jsonb_object(p_val JSONB)
RETURNS JSONB
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT CASE
    WHEN p_val IS NULL OR pg_catalog.jsonb_typeof(p_val) = 'null' THEN '{}'::jsonb
    ELSE p_val
  END;
$$;

CREATE OR REPLACE FUNCTION coherence._cmd_assert_tenant_orgs(
  p_rows JSONB,
  p_table_name TEXT
)
RETURNS VOID
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_rows JSONB := coherence._cmd_jsonb_array(p_rows);
  v_tenant_tree UUID[];
  v_elem JSONB;
  v_raw TEXT;
  v_org_id UUID;
  v_wp_raw TEXT;
  v_person_id UUID;
BEGIN
  IF pg_catalog.jsonb_typeof(v_rows) <> 'array' THEN
    RAISE EXCEPTION 'INVALID_ROWS: % rows must be a JSON array.', p_table_name USING ERRCODE = '22023';
  END IF;
  IF pg_catalog.jsonb_array_length(v_rows) = 0 THEN
    RETURN;
  END IF;

  v_tenant_tree := coherence._resolve_tenant_tree_org_ids();

  FOR v_elem IN SELECT value FROM pg_catalog.jsonb_array_elements(v_rows) LOOP
    v_raw := v_elem ->> 'organization_id';
    IF v_raw IS NOT NULL AND pg_catalog.length(pg_catalog.btrim(v_raw)) > 0 THEN
      BEGIN
        v_org_id := v_raw::uuid;
      EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'INVALID_ORGANIZATION_ID: coherence.% organization_id "%" is not a valid UUID.', p_table_name, v_raw
          USING ERRCODE = '22023';
      END;
      IF NOT (v_org_id = ANY(v_tenant_tree)) THEN
        RAISE EXCEPTION 'INVALID_ORGANIZATION_ID: organization_id % for coherence.% is not a company/agency/team organization in this tenant tree.',
          v_org_id, p_table_name
          USING ERRCODE = '23503';
      END IF;
    END IF;

    v_wp_raw := v_elem ->> 'writing_person_id';
    IF v_wp_raw IS NOT NULL AND pg_catalog.length(pg_catalog.btrim(v_wp_raw)) > 0 THEN
      BEGIN
        v_person_id := v_wp_raw::uuid;
      EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'INVALID_WRITING_PERSON_ID: coherence.% writing_person_id "%" is not a valid UUID.', p_table_name, v_wp_raw
          USING ERRCODE = '22023';
      END;
      IF NOT EXISTS (
        SELECT 1 FROM iam.people p WHERE p.id = v_person_id AND p.principal_origin = 'company_local'
      ) THEN
        RAISE EXCEPTION 'INVALID_WRITING_PERSON_ID: writing_person_id % for coherence.% is not a company_local person in iam.people.',
          v_person_id, p_table_name
          USING ERRCODE = '23503';
      END IF;
    END IF;
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION coherence._cmd_filter_new_stored_files(
  p_files JSONB,
  p_required_store_kind TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_bad_store TEXT;
  v_conflict_sha TEXT;
  v_out JSONB;
BEGIN
  IF p_required_store_kind IS NOT NULL AND p_required_store_kind NOT IN ('company_data', 'nusear_code') THEN
    RAISE EXCEPTION 'INVALID_STORE: unsupported required store_kind %.', p_required_store_kind
      USING ERRCODE = '22023';
  END IF;

  IF p_files IS NULL OR pg_catalog.jsonb_typeof(p_files) <> 'array' THEN
    RETURN '[]'::jsonb;
  END IF;

  IF p_required_store_kind IS NOT NULL THEN
    SELECT COALESCE(elem ->> 'store_kind', elem ->> 'storeKind', '<null>') INTO v_bad_store
    FROM pg_catalog.jsonb_array_elements(p_files) AS t(elem)
    WHERE COALESCE(elem ->> 'store_kind', elem ->> 'storeKind') IS DISTINCT FROM p_required_store_kind
    LIMIT 1;
    IF v_bad_store IS NOT NULL THEN
      RAISE EXCEPTION 'INVALID_STORE: stored file store_kind "%" is not allowed; expected "%".',
        v_bad_store, p_required_store_kind
        USING ERRCODE = '42501';
    END IF;
  END IF;

  WITH dedup AS (
    SELECT DISTINCT ON (sk, sha)
      ord, sk, sha, sz, md5, crc, obj
    FROM (
      SELECT
        ord,
        COALESCE(elem ->> 'store_kind', elem ->> 'storeKind') AS sk,
        elem ->> 'sha256' AS sha,
        COALESCE(elem ->> 'byte_size', elem ->> 'byteSize')::bigint AS sz,
        COALESCE(elem ->> 'md5_b64', elem ->> 'md5B64') AS md5,
        COALESCE(elem ->> 'crc32c_b64', elem ->> 'crc32cB64') AS crc,
        COALESCE(elem ->> 'object_name', elem ->> 'objectName', 'objects/' || (elem ->> 'sha256')) AS obj
      FROM pg_catalog.jsonb_array_elements(p_files) WITH ORDINALITY AS t(elem, ord)
    ) s
    ORDER BY sk, sha, ord
  )
  SELECT d.sha INTO v_conflict_sha
  FROM dedup d
  JOIN coherence.stored_files sf ON sf.store_kind = d.sk AND sf.sha256 = d.sha
  WHERE sf.byte_size <> d.sz OR sf.md5_b64 <> d.md5 OR sf.crc32c_b64 <> d.crc
  LIMIT 1;

  IF v_conflict_sha IS NOT NULL THEN
    RAISE EXCEPTION 'STORED_FILE_CONFLICT: stored file % metadata conflicts with existing record.', v_conflict_sha
      USING ERRCODE = '23505';
  END IF;

  WITH dedup AS (
    SELECT DISTINCT ON (sk, sha)
      ord, sk, sha, sz, md5, crc, obj
    FROM (
      SELECT
        ord,
        COALESCE(elem ->> 'store_kind', elem ->> 'storeKind') AS sk,
        elem ->> 'sha256' AS sha,
        COALESCE(elem ->> 'byte_size', elem ->> 'byteSize')::bigint AS sz,
        COALESCE(elem ->> 'md5_b64', elem ->> 'md5B64') AS md5,
        COALESCE(elem ->> 'crc32c_b64', elem ->> 'crc32cB64') AS crc,
        COALESCE(elem ->> 'object_name', elem ->> 'objectName', 'objects/' || (elem ->> 'sha256')) AS obj
      FROM pg_catalog.jsonb_array_elements(p_files) WITH ORDINALITY AS t(elem, ord)
    ) s
    ORDER BY sk, sha, ord
  )
  SELECT COALESCE(
    pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object(
        'store_kind', d.sk, 'sha256', d.sha, 'byte_size', d.sz,
        'md5_b64', d.md5, 'crc32c_b64', d.crc, 'object_name', d.obj
      ) ORDER BY d.ord
    ),
    '[]'::jsonb
  ) INTO v_out
  FROM dedup d
  WHERE NOT EXISTS (
    SELECT 1 FROM coherence.stored_files sf
    WHERE sf.store_kind = d.sk AND sf.sha256 = d.sha
  );

  RETURN v_out;
END;
$$;

CREATE OR REPLACE FUNCTION coherence._cmd_hash_stored_files_json(p_files JSONB)
RETURNS TEXT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT coherence.sha256_text(
    COALESCE((
      SELECT pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          elem ->> 'store_kind',
          elem ->> 'sha256',
          (elem ->> 'byte_size')::bigint,
          elem ->> 'md5_b64',
          elem ->> 'crc32c_b64',
          elem ->> 'object_name'
        )) || E'\n',
        '' ORDER BY (elem ->> 'store_kind') COLLATE "C", (elem ->> 'sha256') COLLATE "C"
      )
      FROM pg_catalog.jsonb_array_elements(coherence._cmd_jsonb_array(p_files)) AS t(elem)
    ), '')
  );
$$;

CREATE OR REPLACE FUNCTION coherence._cmd_insert_stored_files_json(p_files JSONB, p_journal_seq BIGINT)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_files JSONB := coherence._cmd_jsonb_array(p_files);
BEGIN
  IF pg_catalog.jsonb_array_length(v_files) = 0 THEN
    RETURN;
  END IF;
  INSERT INTO coherence.stored_files (store_kind, sha256, byte_size, md5_b64, crc32c_b64, object_name, journal_seq)
  SELECT
    elem ->> 'store_kind',
    elem ->> 'sha256',
    (elem ->> 'byte_size')::bigint,
    elem ->> 'md5_b64',
    elem ->> 'crc32c_b64',
    elem ->> 'object_name',
    p_journal_seq
  FROM pg_catalog.jsonb_array_elements(v_files) AS t(elem);
END;
$$;

CREATE OR REPLACE FUNCTION coherence._cmd_prepare_materialization(
  p_mat JSONB,
  p_run_id UUID,
  p_attempt_event_id UUID
)
RETURNS TABLE (
  batch_id UUID,
  stmt_date DATE,
  sb_norm JSONB,
  rm_norm JSONB,
  counts JSONB,
  hashes JSONB
)
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_sb JSONB := coherence._cmd_jsonb_object(p_mat -> 'statement_batch');
  v_rm JSONB := coherence._cmd_jsonb_object(p_mat -> 'run_materialization');
  v_ag JSONB := coherence._cmd_jsonb_array(p_mat -> 'agency_lines');
  v_up JSONB := coherence._cmd_jsonb_array(p_mat -> 'upline_lines');
  v_bp JSONB := coherence._cmd_jsonb_array(p_mat -> 'bob_policies');
  v_bpf JSONB := coherence._cmd_jsonb_array(p_mat -> 'bob_financials');
  v_clr JSONB := coherence._cmd_jsonb_array(p_mat -> 'ledger_rows');
  v_batch_id UUID := COALESCE((v_sb ->> 'id')::uuid, pg_catalog.gen_random_uuid());
  v_stmt_date DATE := COALESCE((v_rm ->> 'statement_date')::date, (v_sb ->> 'statement_date')::date);
  v_ag_cnt INT := pg_catalog.jsonb_array_length(v_ag);
  v_up_cnt INT := pg_catalog.jsonb_array_length(v_up);
  v_bp_cnt INT := pg_catalog.jsonb_array_length(v_bp);
  v_bpf_cnt INT := pg_catalog.jsonb_array_length(v_bpf);
  v_clr_cnt INT := pg_catalog.jsonb_array_length(v_clr);
  v_ag_net NUMERIC(14,2);
  v_up_net NUMERIC(14,2);
  v_ag_lines_hash TEXT;
  v_up_lines_hash TEXT;
  v_ag_tbl_hash TEXT;
  v_up_tbl_hash TEXT;
  v_bob_down NUMERIC(14,2);
  v_bob_up NUMERIC(14,2);
  v_bob_rows_hash TEXT;
  v_bp_tbl_hash TEXT;
  v_bpf_tbl_hash TEXT;
  v_led_gross NUMERIC(14,2);
  v_led_down NUMERIC(14,2);
  v_led_up NUMERIC(14,2);
  v_led_rows_hash TEXT;
  v_clr_tbl_hash TEXT;
  v_sb_norm JSONB;
  v_rm_norm JSONB;
  v_sb_hash TEXT;
  v_rm_hash TEXT;
  v_counts JSONB;
  v_hashes JSONB;
BEGIN
  IF v_stmt_date IS NULL THEN
    SELECT r.statement_date INTO v_stmt_date FROM coherence.runs r WHERE r.id = p_run_id;
  END IF;

  SELECT COALESCE(pg_catalog.sum((e ->> 'amount')::numeric(14,2)), 0.00)::numeric(14,2)
  INTO v_ag_net FROM pg_catalog.jsonb_array_elements(v_ag) AS t(e);
  SELECT COALESCE(pg_catalog.sum((e ->> 'amount')::numeric(14,2)), 0.00)::numeric(14,2)
  INTO v_up_net FROM pg_catalog.jsonb_array_elements(v_up) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      (e ->> 'line_no')::int, coherence.fmt_date(v_stmt_date), e ->> 'entry_kind', e ->> 'run_action',
      e ->> 'entity', e ->> 'writing_npn', e ->> 'writing_agent', e ->> 'record_id',
      e ->> 'reversal_of', e ->> 'corrects_record_id', e ->> 'source_file', e ->> 'sheet_name',
      (e ->> 'source_row_no')::int, e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member',
      e ->> 'external_policy_id', (e ->> 'policy_id')::int, (e ->> 'tx_id')::int,
      e ->> 'plan_type', e ->> 'simple_plan_type', e ->> 'state',
      coherence.fmt_date((e ->> 'submission_date')::date), coherence.fmt_date((e ->> 'origin_effective')::date),
      coherence.fmt_date((e ->> 'effective_date')::date), coherence.fmt_date((e ->> 'termination_date')::date),
      coherence.fmt_date((e ->> 'earned_date')::date), coherence.fmt_date((e ->> 'payment_date')::date),
      coherence.fmt_date((e ->> 'posted_statement_date')::date), e ->> 'revenue_type',
      coherence.fmt_num2((e ->> 'gross_comm')::numeric(14,2)), coherence.fmt_num2((e ->> 'amount')::numeric(14,2)),
      e ->> 'reason', e ->> 'notes'
    )) || E'\n',
    '' ORDER BY (e ->> 'line_no')::int ASC
  ), '')) INTO v_ag_lines_hash FROM pg_catalog.jsonb_array_elements(v_ag) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_batch_id::text, (e ->> 'line_no')::int, coherence.fmt_date(v_stmt_date), e ->> 'entry_kind', e ->> 'run_action',
      e ->> 'entity', e ->> 'writing_npn', e ->> 'writing_agent', e ->> 'record_id',
      e ->> 'reversal_of', e ->> 'corrects_record_id', e ->> 'source_file', e ->> 'sheet_name',
      (e ->> 'source_row_no')::int, e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member',
      e ->> 'external_policy_id', (e ->> 'policy_id')::int, (e ->> 'tx_id')::int,
      e ->> 'plan_type', e ->> 'simple_plan_type', e ->> 'state',
      coherence.fmt_date((e ->> 'submission_date')::date), coherence.fmt_date((e ->> 'origin_effective')::date),
      coherence.fmt_date((e ->> 'effective_date')::date), coherence.fmt_date((e ->> 'termination_date')::date),
      coherence.fmt_date((e ->> 'earned_date')::date), coherence.fmt_date((e ->> 'payment_date')::date),
      coherence.fmt_date((e ->> 'posted_statement_date')::date), e ->> 'revenue_type',
      coherence.fmt_num2((e ->> 'gross_comm')::numeric(14,2)), coherence.fmt_num2((e ->> 'amount')::numeric(14,2)),
      e ->> 'reason', e ->> 'notes'
    )) || E'\n',
    '' ORDER BY (e ->> 'line_no')::int ASC
  ), '')) INTO v_ag_tbl_hash FROM pg_catalog.jsonb_array_elements(v_ag) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      (e ->> 'line_no')::int, coherence.fmt_date(v_stmt_date), e ->> 'entry_kind', e ->> 'run_action',
      e ->> 'source_entity', COALESCE((e ->> 'marked_sent')::boolean, true),
      e ->> 'writing_npn', e ->> 'writing_agent', e ->> 'record_id',
      e ->> 'reversal_of', e ->> 'corrects_record_id', e ->> 'source_file', e ->> 'sheet_name',
      (e ->> 'source_row_no')::int, e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member',
      e ->> 'external_policy_id', (e ->> 'policy_id')::int, (e ->> 'tx_id')::int,
      e ->> 'plan_type', e ->> 'simple_plan_type', e ->> 'state',
      coherence.fmt_date((e ->> 'submission_date')::date), coherence.fmt_date((e ->> 'origin_effective')::date),
      coherence.fmt_date((e ->> 'effective_date')::date), coherence.fmt_date((e ->> 'termination_date')::date),
      coherence.fmt_date((e ->> 'earned_date')::date), coherence.fmt_date((e ->> 'payment_date')::date),
      coherence.fmt_date((e ->> 'posted_statement_date')::date), e ->> 'revenue_type',
      coherence.fmt_num2((e ->> 'gross_comm')::numeric(14,2)), coherence.fmt_num2((e ->> 'amount')::numeric(14,2)),
      e ->> 'reason', e ->> 'notes'
    )) || E'\n',
    '' ORDER BY (e ->> 'line_no')::int ASC
  ), '')) INTO v_up_lines_hash FROM pg_catalog.jsonb_array_elements(v_up) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_batch_id::text, (e ->> 'line_no')::int, coherence.fmt_date(v_stmt_date), e ->> 'entry_kind', e ->> 'run_action',
      e ->> 'source_entity', COALESCE((e ->> 'marked_sent')::boolean, true),
      e ->> 'writing_npn', e ->> 'writing_agent', e ->> 'record_id',
      e ->> 'reversal_of', e ->> 'corrects_record_id', e ->> 'source_file', e ->> 'sheet_name',
      (e ->> 'source_row_no')::int, e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member',
      e ->> 'external_policy_id', (e ->> 'policy_id')::int, (e ->> 'tx_id')::int,
      e ->> 'plan_type', e ->> 'simple_plan_type', e ->> 'state',
      coherence.fmt_date((e ->> 'submission_date')::date), coherence.fmt_date((e ->> 'origin_effective')::date),
      coherence.fmt_date((e ->> 'effective_date')::date), coherence.fmt_date((e ->> 'termination_date')::date),
      coherence.fmt_date((e ->> 'earned_date')::date), coherence.fmt_date((e ->> 'payment_date')::date),
      coherence.fmt_date((e ->> 'posted_statement_date')::date), e ->> 'revenue_type',
      coherence.fmt_num2((e ->> 'gross_comm')::numeric(14,2)), coherence.fmt_num2((e ->> 'amount')::numeric(14,2)),
      e ->> 'reason', e ->> 'notes'
    )) || E'\n',
    '' ORDER BY (e ->> 'line_no')::int ASC
  ), '')) INTO v_up_tbl_hash FROM pg_catalog.jsonb_array_elements(v_up) AS t(e);

  SELECT
    COALESCE(pg_catalog.sum((e ->> 'amount')::numeric(14,2)), 0.00)::numeric(14,2),
    COALESCE(pg_catalog.sum((e ->> 'upline_amount')::numeric(14,2)), 0.00)::numeric(14,2)
  INTO v_bob_down, v_bob_up
  FROM pg_catalog.jsonb_array_elements(v_bpf) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      (bp ->> 'policy_id')::int, bp ->> 'external_policy_id', bp ->> 'carrier_policy_number', bp ->> 'crm_policy_number',
      bp ->> 'carrier', bp ->> 'plan_type', bp ->> 'plan_name', bp ->> 'simple_plan_type',
      bp ->> 'mbi', bp ->> 'member', bp ->> 'dob', bp ->> 'phone', bp ->> 'email', bp ->> 'address', bp ->> 'county', bp ->> 'state',
      coherence.fmt_date((bp ->> 'submission_date')::date), coherence.fmt_date((bp ->> 'origin_effective')::date),
      coherence.fmt_date((bp ->> 'effective_date')::date), coherence.fmt_date((bp ->> 'termination_date')::date),
      bp ->> 'writing_npn', bp ->> 'writing_agent', bp ->> 'entity', bp ->> 'status', bp ->> 'coherent_status',
      coherence.fmt_num2((bpf ->> 'amount')::numeric(14,2)), coherence.fmt_num2((bpf ->> 'upline_amount')::numeric(14,2)),
      bpf ->> 'enrollment_code', coherence.fmt_date((bpf ->> 'min_date')::date), coherence.fmt_date((bpf ->> 'anchor_date')::date),
      bpf ->> 'agency_id', bpf ->> 'conflicts', bpf ->> 'spine_source', (bpf ->> 'confidence_level')::smallint, bpf -> 'coherent_trajectory'
    )) || E'\n',
    '' ORDER BY (bp ->> 'policy_id')::int ASC
  ), '')) INTO v_bob_rows_hash
  FROM pg_catalog.jsonb_array_elements(v_bp) AS tbp(bp)
  JOIN pg_catalog.jsonb_array_elements(v_bpf) AS tbpf(bpf)
    ON (bpf ->> 'policy_id')::int = (bp ->> 'policy_id')::int;

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      p_attempt_event_id::text, (bp ->> 'policy_id')::int, p_run_id::text, bp ->> 'external_policy_id',
      bp ->> 'carrier_policy_number', bp ->> 'crm_policy_number', bp ->> 'carrier', bp ->> 'plan_type', bp ->> 'plan_name', bp ->> 'simple_plan_type',
      bp ->> 'mbi', bp ->> 'member', bp ->> 'dob', bp ->> 'phone', bp ->> 'email', bp ->> 'address', bp ->> 'county', bp ->> 'state',
      coherence.fmt_date((bp ->> 'submission_date')::date), coherence.fmt_date((bp ->> 'origin_effective')::date),
      coherence.fmt_date((bp ->> 'effective_date')::date), coherence.fmt_date((bp ->> 'termination_date')::date),
      bp ->> 'writing_npn', bp ->> 'writing_agent', bp ->> 'entity', bp ->> 'status', bp ->> 'coherent_status'
    )) || E'\n',
    '' ORDER BY (bp ->> 'policy_id')::int ASC
  ), '')) INTO v_bp_tbl_hash FROM pg_catalog.jsonb_array_elements(v_bp) AS t(bp);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      p_attempt_event_id::text, (bpf ->> 'policy_id')::int, bpf ->> 'entity', bpf ->> 'writing_npn',
      coherence.fmt_num2((bpf ->> 'amount')::numeric(14,2)), coherence.fmt_num2((bpf ->> 'upline_amount')::numeric(14,2)),
      bpf ->> 'enrollment_code', coherence.fmt_date((bpf ->> 'min_date')::date), coherence.fmt_date((bpf ->> 'anchor_date')::date),
      bpf ->> 'agency_id', bpf ->> 'conflicts', bpf ->> 'spine_source', (bpf ->> 'confidence_level')::smallint, bpf -> 'coherent_trajectory'
    )) || E'\n',
    '' ORDER BY (bpf ->> 'policy_id')::int ASC
  ), '')) INTO v_bpf_tbl_hash FROM pg_catalog.jsonb_array_elements(v_bpf) AS t(bpf);

  SELECT
    COALESCE(pg_catalog.sum((e ->> 'gross_comm')::numeric(14,2)), 0.00)::numeric(14,2),
    COALESCE(pg_catalog.sum((e ->> 'downline_amount')::numeric(14,2)), 0.00)::numeric(14,2),
    COALESCE(pg_catalog.sum((e ->> 'upline_amount')::numeric(14,2)), 0.00)::numeric(14,2)
  INTO v_led_gross, v_led_down, v_led_up
  FROM pg_catalog.jsonb_array_elements(v_clr) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      (e ->> 'tx_id')::int, e ->> 'record_id', e ->> 'external_policy_id', (e ->> 'policy_id')::int,
      e ->> 'statement_name', e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member', e ->> 'state',
      e ->> 'plan_type', e ->> 'simple_plan_type',
      coherence.fmt_date((e ->> 'submission_date')::date), coherence.fmt_date((e ->> 'origin_effective')::date),
      coherence.fmt_date((e ->> 'effective_date')::date), coherence.fmt_date((e ->> 'termination_date')::date),
      coherence.fmt_date((e ->> 'earned_date')::date), coherence.fmt_date((e ->> 'payment_date')::date),
      coherence.fmt_date((e ->> 'statement_date')::date), coherence.fmt_date((e ->> 'min_date')::date),
      coherence.fmt_num2((e ->> 'gross_comm')::numeric(14,2)), e ->> 'revenue_type',
      coherence.fmt_num2((e ->> 'override_amount')::numeric(14,2)), coherence.fmt_num2((e ->> 'commission_amount')::numeric(14,2)),
      coherence.fmt_num2((e ->> 'hra_amount')::numeric(14,2)), coherence.fmt_num2((e ->> 'fee_amount')::numeric(14,2)),
      coherence.fmt_num2((e ->> 'other_amount')::numeric(14,2)),
      coherence.fmt_num2((e ->> 'downline_amount')::numeric(14,2)), coherence.fmt_num2((e ->> 'upline_amount')::numeric(14,2)),
      e ->> 'writing_npn', e ->> 'writing_agent', e ->> 'entity', e ->> 'payee_npn', e ->> 'agency_id',
      e ->> 'status', e ->> 'policy_status', (e ->> 'cbob_c')::boolean, (e ->> 'cbob_s')::boolean, (e ->> 'sf')::boolean,
      e ->> 'notes', e ->> 'coherent_notes', e ->> 'sheet_name', (e ->> 'source_row_no')::int
    )) || E'\n',
    '' ORDER BY (e ->> 'tx_id')::int ASC
  ), '')) INTO v_led_rows_hash FROM pg_catalog.jsonb_array_elements(v_clr) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      p_attempt_event_id::text, (e ->> 'tx_id')::int, p_run_id::text, e ->> 'record_id', e ->> 'external_policy_id', (e ->> 'policy_id')::int,
      e ->> 'statement_name', e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member', e ->> 'state',
      e ->> 'plan_type', e ->> 'simple_plan_type',
      coherence.fmt_date((e ->> 'submission_date')::date), coherence.fmt_date((e ->> 'origin_effective')::date),
      coherence.fmt_date((e ->> 'effective_date')::date), coherence.fmt_date((e ->> 'termination_date')::date),
      coherence.fmt_date((e ->> 'earned_date')::date), coherence.fmt_date((e ->> 'payment_date')::date),
      coherence.fmt_date((e ->> 'statement_date')::date), coherence.fmt_date((e ->> 'min_date')::date),
      coherence.fmt_num2((e ->> 'gross_comm')::numeric(14,2)), e ->> 'revenue_type',
      coherence.fmt_num2((e ->> 'override_amount')::numeric(14,2)), coherence.fmt_num2((e ->> 'commission_amount')::numeric(14,2)),
      coherence.fmt_num2((e ->> 'hra_amount')::numeric(14,2)), coherence.fmt_num2((e ->> 'fee_amount')::numeric(14,2)),
      coherence.fmt_num2((e ->> 'other_amount')::numeric(14,2)),
      coherence.fmt_num2((e ->> 'downline_amount')::numeric(14,2)), coherence.fmt_num2((e ->> 'upline_amount')::numeric(14,2)),
      e ->> 'writing_npn', e ->> 'writing_agent', e ->> 'entity', e ->> 'payee_npn', e ->> 'agency_id',
      e ->> 'status', e ->> 'policy_status', (e ->> 'cbob_c')::boolean, (e ->> 'cbob_s')::boolean, (e ->> 'sf')::boolean,
      e ->> 'notes', e ->> 'coherent_notes', e ->> 'sheet_name', (e ->> 'source_row_no')::int
    )) || E'\n',
    '' ORDER BY (e ->> 'tx_id')::int ASC
  ), '')) INTO v_clr_tbl_hash FROM pg_catalog.jsonb_array_elements(v_clr) AS t(e);

  v_sb_norm := pg_catalog.jsonb_build_object(
    'id', v_batch_id::text,
    'batch_kind', COALESCE(v_sb ->> 'batch_kind', 'run_emission'),
    'statement_date', coherence.fmt_date(v_stmt_date),
    'source_file_name', v_sb ->> 'source_file_name',
    'source_file_sha256', COALESCE(
      v_sb ->> 'source_file_sha256',
      (
        SELECT a.file_sha256
        FROM coherence.artifacts a
        WHERE a.attempt_event_id = p_attempt_event_id
          AND a.rel_path = 'emits/statements_' || pg_catalog.to_char(v_stmt_date, 'YYYYMMDD') || '.csv'
        LIMIT 1
      )
    ),
    'reason', COALESCE(v_sb ->> 'reason', 'Run emission'),
    'agency_line_count', COALESCE((v_sb ->> 'agency_line_count')::int, v_ag_cnt),
    'agency_lines_sha256', COALESCE(v_sb ->> 'agency_lines_sha256', v_ag_lines_hash),
    'agency_net_total', coherence.fmt_num2(COALESCE((v_sb ->> 'agency_net_total')::numeric(14,2), v_ag_net)),
    'upline_line_count', COALESCE((v_sb ->> 'upline_line_count')::int, v_up_cnt),
    'upline_lines_sha256', COALESCE(v_sb ->> 'upline_lines_sha256', v_up_lines_hash),
    'upline_net_total', coherence.fmt_num2(COALESCE((v_sb ->> 'upline_net_total')::numeric(14,2), v_up_net))
  );

  v_rm_norm := pg_catalog.jsonb_build_object(
    'reconciliation_mode', COALESCE(v_rm ->> 'reconciliation_mode', 'strict_entity_ledger'),
    'bob_row_count', COALESCE((v_rm ->> 'bob_row_count')::int, v_bp_cnt),
    'bob_rows_sha256', COALESCE(v_rm ->> 'bob_rows_sha256', v_bob_rows_hash),
    'bob_downline_total', coherence.fmt_num2(COALESCE((v_rm ->> 'bob_downline_total')::numeric(14,2), v_bob_down)),
    'bob_upline_total', coherence.fmt_num2(COALESCE((v_rm ->> 'bob_upline_total')::numeric(14,2), v_bob_up)),
    'ledger_row_count', COALESCE((v_rm ->> 'ledger_row_count')::int, v_clr_cnt),
    'ledger_rows_sha256', COALESCE(v_rm ->> 'ledger_rows_sha256', v_led_rows_hash),
    'ledger_gross_total', coherence.fmt_num2(COALESCE((v_rm ->> 'ledger_gross_total')::numeric(14,2), v_led_gross)),
    'ledger_downline_total', coherence.fmt_num2(COALESCE((v_rm ->> 'ledger_downline_total')::numeric(14,2), v_led_down)),
    'ledger_upline_total', coherence.fmt_num2(COALESCE((v_rm ->> 'ledger_upline_total')::numeric(14,2), v_led_up)),
    'corpus_tail', v_rm ->> 'corpus_tail',
    'agency_start', coherence.fmt_date((v_rm ->> 'agency_start')::date)
  );

  v_sb_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_batch_id::text, v_sb_norm ->> 'batch_kind', v_sb_norm ->> 'statement_date',
    p_run_id::text, p_attempt_event_id::text, v_sb_norm ->> 'source_file_name', v_sb_norm ->> 'source_file_sha256',
    v_sb_norm ->> 'reason', (v_sb_norm ->> 'agency_line_count')::int, v_sb_norm ->> 'agency_lines_sha256',
    v_sb_norm ->> 'agency_net_total', (v_sb_norm ->> 'upline_line_count')::int, v_sb_norm ->> 'upline_lines_sha256',
    v_sb_norm ->> 'upline_net_total'
  )) || E'\n');

  v_rm_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    p_attempt_event_id::text, p_run_id::text, coherence.fmt_date(v_stmt_date), v_rm_norm ->> 'reconciliation_mode',
    (v_rm_norm ->> 'bob_row_count')::int, v_rm_norm ->> 'bob_rows_sha256',
    v_rm_norm ->> 'bob_downline_total', v_rm_norm ->> 'bob_upline_total',
    (v_rm_norm ->> 'ledger_row_count')::int, v_rm_norm ->> 'ledger_rows_sha256',
    v_rm_norm ->> 'ledger_gross_total', v_rm_norm ->> 'ledger_downline_total', v_rm_norm ->> 'ledger_upline_total',
    v_batch_id::text, v_rm_norm ->> 'corpus_tail', v_rm_norm ->> 'agency_start'
  )) || E'\n');

  v_counts := pg_catalog.jsonb_build_object('statement_batches', 1, 'run_materializations', 1);
  v_hashes := pg_catalog.jsonb_build_object('statement_batches', v_sb_hash, 'run_materializations', v_rm_hash);
  IF v_ag_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('statement_agency_lines', v_ag_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('statement_agency_lines', v_ag_tbl_hash);
  END IF;
  IF v_up_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('statement_upline_lines', v_up_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('statement_upline_lines', v_up_tbl_hash);
  END IF;
  IF v_bp_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('bob_policies', v_bp_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('bob_policies', v_bp_tbl_hash);
  END IF;
  IF v_bpf_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('bob_policy_financials', v_bpf_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('bob_policy_financials', v_bpf_tbl_hash);
  END IF;
  IF v_clr_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('coherent_ledger_rows', v_clr_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('coherent_ledger_rows', v_clr_tbl_hash);
  END IF;

  RETURN QUERY SELECT v_batch_id, v_stmt_date, v_sb_norm, v_rm_norm, v_counts, v_hashes;
END;
$$;

CREATE OR REPLACE FUNCTION coherence._cmd_insert_materialization(
  p_mat JSONB,
  p_sb_norm JSONB,
  p_rm_norm JSONB,
  p_run_id UUID,
  p_attempt_event_id UUID,
  p_journal_seq BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_batch_id UUID := (p_sb_norm ->> 'id')::uuid;
  v_stmt_date DATE := (p_sb_norm ->> 'statement_date')::date;
  v_ag JSONB := coherence._cmd_jsonb_array(p_mat -> 'agency_lines');
  v_up JSONB := coherence._cmd_jsonb_array(p_mat -> 'upline_lines');
  v_bp JSONB := coherence._cmd_jsonb_array(p_mat -> 'bob_policies');
  v_bpf JSONB := coherence._cmd_jsonb_array(p_mat -> 'bob_financials');
  v_clr JSONB := coherence._cmd_jsonb_array(p_mat -> 'ledger_rows');
BEGIN
  PERFORM coherence._cmd_assert_tenant_orgs(v_ag, 'statement_agency_lines');
  PERFORM coherence._cmd_assert_tenant_orgs(v_up, 'statement_upline_lines');
  PERFORM coherence._cmd_assert_tenant_orgs(v_bp, 'bob_policies');
  PERFORM coherence._cmd_assert_tenant_orgs(v_bpf, 'bob_policy_financials');
  PERFORM coherence._cmd_assert_tenant_orgs(v_clr, 'coherent_ledger_rows');

  INSERT INTO coherence.statement_batches (
    id, batch_kind, statement_date, run_id, attempt_event_id,
    source_file_name, source_store_kind, source_file_sha256, reason,
    agency_line_count, agency_lines_sha256, agency_net_total,
    upline_line_count, upline_lines_sha256, upline_net_total, journal_seq
  ) VALUES (
    v_batch_id, p_sb_norm ->> 'batch_kind', v_stmt_date, p_run_id, p_attempt_event_id,
    p_sb_norm ->> 'source_file_name',
    CASE WHEN p_sb_norm ->> 'source_file_sha256' IS NOT NULL THEN 'company_data' ELSE NULL END,
    p_sb_norm ->> 'source_file_sha256', p_sb_norm ->> 'reason',
    (p_sb_norm ->> 'agency_line_count')::int, p_sb_norm ->> 'agency_lines_sha256', (p_sb_norm ->> 'agency_net_total')::numeric(14,2),
    (p_sb_norm ->> 'upline_line_count')::int, p_sb_norm ->> 'upline_lines_sha256', (p_sb_norm ->> 'upline_net_total')::numeric(14,2),
    p_journal_seq
  );

  IF pg_catalog.jsonb_array_length(v_ag) > 0 THEN
    INSERT INTO coherence.statement_agency_lines (
      batch_id, line_no, statement_date, entry_kind, run_action, entity,
      organization_id, writing_npn, writing_person_id, writing_agent,
      record_id, reversal_of, corrects_record_id, source_file, sheet_name, source_row_no,
      src_type, carrier, mbi, member, external_policy_id, policy_id, tx_id,
      plan_type, simple_plan_type, state, submission_date, origin_effective, effective_date, termination_date,
      earned_date, payment_date, posted_statement_date, revenue_type, gross_comm, amount, reason, notes, journal_seq
    )
    SELECT
      v_batch_id, (e ->> 'line_no')::int, v_stmt_date, e ->> 'entry_kind', e ->> 'run_action', e ->> 'entity',
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'organization_id'), '')::uuid, coherence._resolve_entity_org_id(e ->> 'entity', 'statement_agency_lines')),
      e ->> 'writing_npn',
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'writing_person_id'), '')::uuid, coherence._resolve_writing_person_id(e ->> 'writing_npn', 'statement_agency_lines')),
      e ->> 'writing_agent',
      e ->> 'record_id', e ->> 'reversal_of', e ->> 'corrects_record_id', e ->> 'source_file', e ->> 'sheet_name', (e ->> 'source_row_no')::int,
      e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member', e ->> 'external_policy_id', (e ->> 'policy_id')::int, (e ->> 'tx_id')::int,
      e ->> 'plan_type', e ->> 'simple_plan_type', e ->> 'state', (e ->> 'submission_date')::date, (e ->> 'origin_effective')::date,
      (e ->> 'effective_date')::date, (e ->> 'termination_date')::date, (e ->> 'earned_date')::date, (e ->> 'payment_date')::date,
      (e ->> 'posted_statement_date')::date, e ->> 'revenue_type', (e ->> 'gross_comm')::numeric(14,2), (e ->> 'amount')::numeric(14,2),
      e ->> 'reason', e ->> 'notes', p_journal_seq
    FROM pg_catalog.jsonb_array_elements(v_ag) AS t(e);
  END IF;

  IF pg_catalog.jsonb_array_length(v_up) > 0 THEN
    INSERT INTO coherence.statement_upline_lines (
      batch_id, line_no, statement_date, entry_kind, run_action, source_entity, marked_sent,
      organization_id, writing_npn, writing_person_id, writing_agent,
      record_id, reversal_of, corrects_record_id, source_file, sheet_name, source_row_no,
      src_type, carrier, mbi, member, external_policy_id, policy_id, tx_id,
      plan_type, simple_plan_type, state, submission_date, origin_effective, effective_date, termination_date,
      earned_date, payment_date, posted_statement_date, revenue_type, gross_comm, amount, reason, notes, journal_seq
    )
    SELECT
      v_batch_id, (e ->> 'line_no')::int, v_stmt_date, e ->> 'entry_kind', e ->> 'run_action', e ->> 'source_entity', COALESCE((e ->> 'marked_sent')::boolean, true),
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'organization_id'), '')::uuid, coherence._resolve_entity_org_id(e ->> 'source_entity', 'statement_upline_lines')),
      e ->> 'writing_npn',
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'writing_person_id'), '')::uuid, coherence._resolve_writing_person_id(e ->> 'writing_npn', 'statement_upline_lines')),
      e ->> 'writing_agent',
      e ->> 'record_id', e ->> 'reversal_of', e ->> 'corrects_record_id', e ->> 'source_file', e ->> 'sheet_name', (e ->> 'source_row_no')::int,
      e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member', e ->> 'external_policy_id', (e ->> 'policy_id')::int, (e ->> 'tx_id')::int,
      e ->> 'plan_type', e ->> 'simple_plan_type', e ->> 'state', (e ->> 'submission_date')::date, (e ->> 'origin_effective')::date,
      (e ->> 'effective_date')::date, (e ->> 'termination_date')::date, (e ->> 'earned_date')::date, (e ->> 'payment_date')::date,
      (e ->> 'posted_statement_date')::date, e ->> 'revenue_type', (e ->> 'gross_comm')::numeric(14,2), (e ->> 'amount')::numeric(14,2),
      e ->> 'reason', e ->> 'notes', p_journal_seq
    FROM pg_catalog.jsonb_array_elements(v_up) AS t(e);
  END IF;

  INSERT INTO coherence.run_materializations (
    attempt_event_id, run_id, statement_date, reconciliation_mode,
    bob_row_count, bob_rows_sha256, bob_downline_total, bob_upline_total,
    ledger_row_count, ledger_rows_sha256, ledger_gross_total, ledger_downline_total, ledger_upline_total,
    statement_batch_id, corpus_tail, agency_start, journal_seq
  ) VALUES (
    p_attempt_event_id, p_run_id, v_stmt_date, p_rm_norm ->> 'reconciliation_mode',
    (p_rm_norm ->> 'bob_row_count')::int, p_rm_norm ->> 'bob_rows_sha256', (p_rm_norm ->> 'bob_downline_total')::numeric(14,2), (p_rm_norm ->> 'bob_upline_total')::numeric(14,2),
    (p_rm_norm ->> 'ledger_row_count')::int, p_rm_norm ->> 'ledger_rows_sha256', (p_rm_norm ->> 'ledger_gross_total')::numeric(14,2),
    (p_rm_norm ->> 'ledger_downline_total')::numeric(14,2), (p_rm_norm ->> 'ledger_upline_total')::numeric(14,2),
    v_batch_id, p_rm_norm ->> 'corpus_tail', (p_rm_norm ->> 'agency_start')::date, p_journal_seq
  );

  IF pg_catalog.jsonb_array_length(v_bp) > 0 THEN
    INSERT INTO coherence.bob_policies (
      attempt_event_id, policy_id, run_id, external_policy_id, carrier_policy_number, crm_policy_number,
      carrier, plan_type, plan_name, simple_plan_type, mbi, member, dob, phone, email, address, county, state,
      submission_date, origin_effective, effective_date, termination_date,
      writing_npn, writing_agent, entity, organization_id, writing_person_id, status, coherent_status, journal_seq
    )
    SELECT
      p_attempt_event_id, (e ->> 'policy_id')::int, p_run_id, e ->> 'external_policy_id', e ->> 'carrier_policy_number', e ->> 'crm_policy_number',
      e ->> 'carrier', e ->> 'plan_type', e ->> 'plan_name', e ->> 'simple_plan_type', e ->> 'mbi', e ->> 'member',
      e ->> 'dob', e ->> 'phone', e ->> 'email', e ->> 'address', e ->> 'county', e ->> 'state',
      (e ->> 'submission_date')::date, (e ->> 'origin_effective')::date, (e ->> 'effective_date')::date, (e ->> 'termination_date')::date,
      e ->> 'writing_npn', e ->> 'writing_agent', e ->> 'entity',
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'organization_id'), '')::uuid, coherence._resolve_entity_org_id(e ->> 'entity', 'bob_policies')),
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'writing_person_id'), '')::uuid, coherence._resolve_writing_person_id(e ->> 'writing_npn', 'bob_policies')),
      e ->> 'status', e ->> 'coherent_status', p_journal_seq
    FROM pg_catalog.jsonb_array_elements(v_bp) AS t(e);
  END IF;

  IF pg_catalog.jsonb_array_length(v_bpf) > 0 THEN
    INSERT INTO coherence.bob_policy_financials (
      attempt_event_id, policy_id, entity, writing_npn, organization_id, writing_person_id,
      amount, upline_amount, enrollment_code, min_date, anchor_date, agency_id, conflicts,
      spine_source, confidence_level, coherent_trajectory, journal_seq
    )
    SELECT
      p_attempt_event_id, (e ->> 'policy_id')::int, e ->> 'entity', e ->> 'writing_npn',
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'organization_id'), '')::uuid, coherence._resolve_entity_org_id(e ->> 'entity', 'bob_policy_financials')),
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'writing_person_id'), '')::uuid, coherence._resolve_writing_person_id(e ->> 'writing_npn', 'bob_policy_financials')),
      (e ->> 'amount')::numeric(14,2), (e ->> 'upline_amount')::numeric(14,2), e ->> 'enrollment_code',
      (e ->> 'min_date')::date, (e ->> 'anchor_date')::date, e ->> 'agency_id', e ->> 'conflicts',
      e ->> 'spine_source', (e ->> 'confidence_level')::smallint, e -> 'coherent_trajectory', p_journal_seq
    FROM pg_catalog.jsonb_array_elements(v_bpf) AS t(e);
  END IF;

  IF pg_catalog.jsonb_array_length(v_clr) > 0 THEN
    INSERT INTO coherence.coherent_ledger_rows (
      attempt_event_id, tx_id, run_id, record_id, external_policy_id, policy_id,
      statement_name, src_type, carrier, mbi, member, state, plan_type, simple_plan_type,
      submission_date, origin_effective, effective_date, termination_date,
      earned_date, payment_date, statement_date, min_date,
      gross_comm, revenue_type, override_amount, commission_amount, hra_amount, fee_amount, other_amount,
      downline_amount, upline_amount, writing_npn, writing_agent, entity, organization_id, writing_person_id,
      payee_npn, agency_id, status, policy_status, cbob_c, cbob_s, sf, notes, coherent_notes, sheet_name, source_row_no, journal_seq
    )
    SELECT
      p_attempt_event_id, (e ->> 'tx_id')::int, p_run_id, e ->> 'record_id', e ->> 'external_policy_id', (e ->> 'policy_id')::int,
      e ->> 'statement_name', e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member', e ->> 'state', e ->> 'plan_type', e ->> 'simple_plan_type',
      (e ->> 'submission_date')::date, (e ->> 'origin_effective')::date, (e ->> 'effective_date')::date, (e ->> 'termination_date')::date,
      (e ->> 'earned_date')::date, (e ->> 'payment_date')::date, (e ->> 'statement_date')::date, (e ->> 'min_date')::date,
      (e ->> 'gross_comm')::numeric(14,2), e ->> 'revenue_type', (e ->> 'override_amount')::numeric(14,2),
      (e ->> 'commission_amount')::numeric(14,2), (e ->> 'hra_amount')::numeric(14,2), (e ->> 'fee_amount')::numeric(14,2), (e ->> 'other_amount')::numeric(14,2),
      (e ->> 'downline_amount')::numeric(14,2), (e ->> 'upline_amount')::numeric(14,2),
      e ->> 'writing_npn', e ->> 'writing_agent', e ->> 'entity',
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'organization_id'), '')::uuid, coherence._resolve_entity_org_id(e ->> 'entity', 'coherent_ledger_rows')),
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'writing_person_id'), '')::uuid, coherence._resolve_writing_person_id(e ->> 'writing_npn', 'coherent_ledger_rows')),
      e ->> 'payee_npn', e ->> 'agency_id', e ->> 'status', e ->> 'policy_status',
      (e ->> 'cbob_c')::boolean, (e ->> 'cbob_s')::boolean, (e ->> 'sf')::boolean,
      e ->> 'notes', e ->> 'coherent_notes', e ->> 'sheet_name', (e ->> 'source_row_no')::int, p_journal_seq
    FROM pg_catalog.jsonb_array_elements(v_clr) AS t(e);
  END IF;
END;
$$;

ALTER FUNCTION coherence._cmd_resolve_context(TEXT, TEXT) OWNER TO platform_writer;
ALTER FUNCTION coherence._cmd_check_idempotency(TEXT, TEXT, TEXT, TEXT, TEXT) OWNER TO platform_writer;
ALTER FUNCTION coherence._cmd_check_expected_seq(BIGINT, UUID, BOOLEAN, BOOLEAN) OWNER TO platform_writer;
ALTER FUNCTION coherence._cmd_write_journals(TEXT, UUID, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB) OWNER TO platform_writer;
ALTER FUNCTION coherence._cmd_jsonb_array(JSONB) OWNER TO platform_writer;
ALTER FUNCTION coherence._cmd_jsonb_object(JSONB) OWNER TO platform_writer;
ALTER FUNCTION coherence._cmd_assert_tenant_orgs(JSONB, TEXT) OWNER TO platform_writer;
ALTER FUNCTION coherence._cmd_filter_new_stored_files(JSONB, TEXT) OWNER TO platform_writer;
ALTER FUNCTION coherence._cmd_hash_stored_files_json(JSONB) OWNER TO platform_writer;
ALTER FUNCTION coherence._cmd_insert_stored_files_json(JSONB, BIGINT) OWNER TO platform_writer;
ALTER FUNCTION coherence._cmd_prepare_materialization(JSONB, UUID, UUID) OWNER TO platform_writer;
ALTER FUNCTION coherence._cmd_insert_materialization(JSONB, JSONB, JSONB, UUID, UUID, BIGINT) OWNER TO platform_writer;

-- 7. Command functions in app_cmd.coherence_* owned by platform_writer (SECURITY DEFINER).
-- Every command enters through iam.assert_can_write(), checks command_key idempotency and
-- expected_seq concurrency, writes both coherence.journal_entries and platform.audit_journal,
-- and fires deferred commitment verification via SET CONSTRAINTS ALL IMMEDIATE while still
-- executing as platform_writer.

-- 7.1 init_company (Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_init_company(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_slug TEXT,
  p_display_name TEXT,
  p_default_emit_mode TEXT DEFAULT 'builtin',
  p_default_emit_display TEXT DEFAULT NULL,
  p_default_emit_keep TEXT[] DEFAULT '{}',
  p_default_emit_no_manager TEXT[] DEFAULT '{}'
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_keep TEXT[] := COALESCE(p_default_emit_keep, '{}');
  v_nomgr TEXT[] := COALESCE(p_default_emit_no_manager, '{}');
  v_hash TEXT;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.owner.init_company', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('init_company', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  v_hash := coherence.sha256_text(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      p_slug, p_display_name, p_default_emit_mode, p_default_emit_display, v_keep, v_nomgr
    )) || E'\n'
  );
  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('companySlug', p_slug, 'displayName', p_display_name, 'defaultEmitMode', p_default_emit_mode),
    'commitments', pg_catalog.jsonb_build_object(
      'counts', pg_catalog.jsonb_build_object('company_meta', 1),
      'hashes', pg_catalog.jsonb_build_object('company_meta', v_hash)
    )
  );

  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'init_company', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('company_slug', p_slug)
  );

  INSERT INTO coherence.company_meta (
    singleton, company_slug, display_name, default_emit_mode,
    default_emit_display, default_emit_keep, default_emit_no_manager, journal_seq
  ) VALUES (
    true, p_slug, p_display_name, p_default_emit_mode,
    p_default_emit_display, v_keep, v_nomgr, v_seq
  );

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'company_slug', p_slug);
END;
$$;

-- 7.2 register_stored_files (Worker or Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_register_stored_files(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_files JSONB
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_new JSONB;
  v_cnt INT;
  v_counts JSONB := '{}'::jsonb;
  v_hashes JSONB := '{}'::jsonb;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.files.register', 'human_or_service');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('register_stored_files', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  v_new := coherence._cmd_filter_new_stored_files(p_files);
  v_cnt := pg_catalog.jsonb_array_length(v_new);
  IF v_cnt > 0 THEN
    v_counts := pg_catalog.jsonb_build_object('stored_files', v_cnt);
    v_hashes := pg_catalog.jsonb_build_object('stored_files', coherence._cmd_hash_stored_files_json(v_new));
  END IF;
  v_body := pg_catalog.jsonb_build_object(
    'registered', v_cnt,
    'result', pg_catalog.jsonb_build_object('insertedCount', v_cnt, 'registered', v_cnt),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );

  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'register_stored_files', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('registered', v_cnt)
  );
  PERFORM coherence._cmd_insert_stored_files_json(v_new, v_seq);

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'registered', v_cnt, 'inserted_count', v_cnt);
END;
$$;

-- 7.3 register_engine_version (Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_register_engine_version(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_payload JSONB
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_id UUID := COALESCE((p_payload ->> 'id')::uuid, pg_catalog.gen_random_uuid());
  v_label TEXT := p_payload ->> 'label';
  v_coh_commit TEXT := p_payload ->> 'coherence_commit';
  v_eng_kind TEXT := COALESCE(p_payload ->> 'engine_kind', 'legacy_sealed');
  v_upstream TEXT := p_payload ->> 'upstream_commit';
  v_patch TEXT := p_payload ->> 'patch_diff_sha256';
  v_git TEXT := p_payload ->> 'git_bundle_sha256';
  v_manifest TEXT := p_payload ->> 'code_manifest_sha256';
  v_pylock TEXT := p_payload ->> 'python_lock_sha256';
  v_pywheels TEXT := p_payload ->> 'python_wheels_sha256';
  v_weblock TEXT := p_payload ->> 'web_lock_sha256';
  v_webpkg TEXT := p_payload ->> 'web_packages_sha256';
  v_wrap TEXT := p_payload ->> 'wrapper_bundle_sha256';
  v_nus_commit TEXT := p_payload ->> 'nusear_commit';
  v_comp_emit TEXT := p_payload ->> 'company_emit_sha256';
  v_pages TEXT := p_payload ->> 'pages_law_sha256';
  v_ovchk TEXT := p_payload ->> 'overlay_check_sha256';
  v_tc JSONB := p_payload -> 'toolchain';
  v_digest TEXT := p_payload ->> 'container_digest';
  v_new_files JSONB;
  v_file_cnt INT;
  v_counts JSONB;
  v_hashes JSONB;
  v_eng_hash TEXT;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.owner.register_engine', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('register_engine_version', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  v_new_files := coherence._cmd_filter_new_stored_files(coherence._cmd_jsonb_array(p_payload -> 'stored_files'), 'nusear_code');
  v_file_cnt := pg_catalog.jsonb_array_length(v_new_files);

  v_eng_hash := coherence.sha256_text(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_id::text, v_label, v_coh_commit, v_eng_kind, v_upstream, v_patch,
      v_git, v_manifest, v_pylock, v_pywheels,
      v_weblock, v_webpkg, v_wrap,
      v_nus_commit, v_comp_emit, v_pages, v_ovchk, v_tc, v_digest
    )) || E'\n'
  );
  v_counts := pg_catalog.jsonb_build_object('engine_versions', 1);
  v_hashes := pg_catalog.jsonb_build_object('engine_versions', v_eng_hash);
  IF v_file_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('stored_files', v_file_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('stored_files', coherence._cmd_hash_stored_files_json(v_new_files));
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('engineVersionId', v_id, 'label', v_label),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'register_engine_version', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('engine_version_id', v_id, 'label', v_label)
  );
  PERFORM coherence._cmd_insert_stored_files_json(v_new_files, v_seq);

  INSERT INTO coherence.engine_versions (
    id, label, coherence_commit, engine_kind, upstream_commit, patch_diff_sha256, store_kind,
    git_bundle_sha256, code_manifest_sha256, python_lock_sha256, python_wheels_sha256,
    web_lock_sha256, web_packages_sha256, wrapper_bundle_sha256,
    nusear_commit, company_emit_sha256, pages_law_sha256, overlay_check_sha256,
    toolchain, container_digest, journal_seq
  ) VALUES (
    v_id, v_label, v_coh_commit, v_eng_kind, v_upstream, v_patch, 'nusear_code',
    v_git, v_manifest, v_pylock, v_pywheels,
    v_weblock, v_webpkg, v_wrap,
    v_nus_commit, v_comp_emit, v_pages, v_ovchk,
    v_tc, v_digest, v_seq
  );

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'engine_version_id', v_id);
END;
$$;

-- 7.4 register_approvals_file (Operator / Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_register_approvals_file(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_stored_file JSONB,
  p_header_kind TEXT,
  p_row_count INTEGER,
  p_extends_sha256 TEXT DEFAULT NULL,
  p_shared_row_count INTEGER DEFAULT 0,
  p_added_rows JSONB DEFAULT '[]'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_sha TEXT := p_stored_file ->> 'sha256';
  v_new_files JSONB;
  v_file_cnt INT;
  v_rows JSONB := coherence._cmd_jsonb_array(p_added_rows);
  v_row_cnt INT := pg_catalog.jsonb_array_length(v_rows);
  v_rows_hash TEXT;
  v_af_hash TEXT;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.approvals.register', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('register_approvals_file', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  v_new_files := coherence._cmd_filter_new_stored_files(pg_catalog.jsonb_build_array(p_stored_file), 'company_data');

  IF EXISTS (SELECT 1 FROM coherence.approvals_files WHERE file_sha256 = v_sha) THEN
    v_body := pg_catalog.jsonb_build_object(
      'result', pg_catalog.jsonb_build_object('fileSha256', v_sha, 'alreadyRegistered', true),
      'commitments', pg_catalog.jsonb_build_object('counts', '{}'::jsonb, 'hashes', '{}'::jsonb)
    );
    v_seq := coherence._cmd_write_journals(
      v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
      v_ctx.actor_label, v_ctx.acting_for_label,
      'register_approvals_file', p_command_key, p_request_sha256, v_body,
      pg_catalog.jsonb_build_object('file_sha256', v_sha, 'already_registered', true)
    );
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;
    RETURN pg_catalog.jsonb_build_object('idempotent', false, 'already_registered', true, 'journal_seq', v_seq, 'file_sha256', v_sha);
  END IF;

  v_file_cnt := pg_catalog.jsonb_array_length(v_new_files);

  SELECT coherence.sha256_text(
    COALESCE(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        (elem ->> 'row_no')::integer, elem ->> 'record_id', elem ->> 'disposition', elem ->> 'agent',
        elem ->> 'agency', elem ->> 'policy', elem ->> 'book', elem ->> 'month', elem ->> 'status',
        elem ->> 'note', elem ->> 'committed_at', elem ->> 'approved_amount', elem ->> 'approved_agency',
        elem ->> 'approved_agent', elem ->> 'approved_agency_from', elem ->> 'approved_agent_from'
      )) || E'\n',
      '' ORDER BY (elem ->> 'row_no')::integer ASC
    ), '')
  ) INTO v_rows_hash
  FROM pg_catalog.jsonb_array_elements(v_rows) AS t(elem);

  v_af_hash := coherence.sha256_text(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_sha, p_header_kind, p_row_count, p_extends_sha256, p_shared_row_count, v_rows_hash
    )) || E'\n'
  );
  v_counts := pg_catalog.jsonb_build_object('approvals_files', 1);
  v_hashes := pg_catalog.jsonb_build_object('approvals_files', v_af_hash);
  IF v_file_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('stored_files', v_file_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('stored_files', coherence._cmd_hash_stored_files_json(v_new_files));
  END IF;
  IF v_row_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('approval_rows', v_row_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('approval_rows', v_rows_hash);
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('fileSha256', v_sha, 'rowCount', p_row_count, 'alreadyRegistered', false),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'register_approvals_file', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('file_sha256', v_sha, 'row_count', p_row_count)
  );
  PERFORM coherence._cmd_insert_stored_files_json(v_new_files, v_seq);

  INSERT INTO coherence.approvals_files (
    file_sha256, store_kind, header_kind, row_count, extends_sha256, shared_row_count, added_rows_sha256, journal_seq
  ) VALUES (
    v_sha, 'company_data', p_header_kind, p_row_count, p_extends_sha256, p_shared_row_count, v_rows_hash, v_seq
  );

  IF v_row_cnt > 0 THEN
    INSERT INTO coherence.approval_rows (
      approvals_file_sha256, row_no, record_id, disposition, agent, agency, policy, book,
      month, status, note, committed_at, approved_amount, approved_agency, approved_agent,
      approved_agency_from, approved_agent_from, journal_seq
    )
    SELECT
      v_sha, (elem ->> 'row_no')::integer, elem ->> 'record_id', elem ->> 'disposition',
      elem ->> 'agent', elem ->> 'agency', elem ->> 'policy', elem ->> 'book',
      elem ->> 'month', elem ->> 'status', elem ->> 'note', elem ->> 'committed_at',
      elem ->> 'approved_amount', elem ->> 'approved_agency', elem ->> 'approved_agent',
      elem ->> 'approved_agency_from', elem ->> 'approved_agent_from', v_seq
    FROM pg_catalog.jsonb_array_elements(v_rows) AS t(elem);
  END IF;

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'file_sha256', v_sha);
END;
$$;

-- 7.5 publish_input_version (Operator)
CREATE OR REPLACE FUNCTION app_cmd.coherence_publish_input_version(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_expected_seq BIGINT,
  p_line_kind TEXT,
  p_source_kind TEXT,
  p_reason TEXT,
  p_entries JSONB,
  p_changes JSONB DEFAULT '[]'::jsonb,
  p_stored_files JSONB DEFAULT '[]'::jsonb,
  p_entries_list_file_sha256 TEXT DEFAULT NULL,
  p_input_version_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_iv_id UUID := COALESCE(p_input_version_id, pg_catalog.gen_random_uuid());
  v_parent_id UUID := NULL;
  v_entries JSONB := coherence._cmd_jsonb_array(p_entries);
  v_changes JSONB := coherence._cmd_jsonb_array(p_changes);
  v_new_files JSONB;
  v_entry_cnt INT := pg_catalog.jsonb_array_length(v_entries);
  v_change_cnt INT := pg_catalog.jsonb_array_length(v_changes);
  v_file_cnt INT;
  v_entries_hash TEXT;
  v_changes_hash TEXT;
  v_iv_hash TEXT;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.inputs.publish', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('publish_input_version', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;
  PERFORM coherence._cmd_check_expected_seq(p_expected_seq, NULL, p_line_kind = 'standing', false);

  IF p_line_kind = 'standing' THEN
    SELECT id INTO v_parent_id
    FROM coherence.input_versions
    WHERE line_kind = 'standing'
    ORDER BY journal_seq DESC
    LIMIT 1;

    -- Auto-compute standing diff (including byte-identical renames) when caller omitted p_changes.
    IF v_parent_id IS NOT NULL AND (p_changes IS NULL OR pg_catalog.jsonb_typeof(p_changes) = 'null') THEN
      WITH prev_e AS (
        SELECT rel_path, file_sha256
        FROM coherence.input_entries
        WHERE input_version_id = v_parent_id
      ),
      next_e AS (
        SELECT elem ->> 'rel_path' AS rel_path, elem ->> 'file_sha256' AS file_sha256
        FROM pg_catalog.jsonb_array_elements(v_entries) AS t(elem)
      ),
      replaced AS (
        SELECT 'replaced'::text AS change_kind, n.rel_path, NULL::text AS old_rel_path,
               n.file_sha256, p.file_sha256 AS prev_file_sha256
        FROM next_e n
        JOIN prev_e p ON p.rel_path = n.rel_path AND p.file_sha256 <> n.file_sha256
      ),
      raw_rem AS (
        SELECT p.rel_path, p.file_sha256,
               pg_catalog.row_number() OVER (PARTITION BY p.file_sha256 ORDER BY p.rel_path COLLATE "C") AS rn
        FROM prev_e p
        WHERE NOT EXISTS (SELECT 1 FROM next_e n WHERE n.rel_path = p.rel_path)
      ),
      raw_add AS (
        SELECT n.rel_path, n.file_sha256,
               pg_catalog.row_number() OVER (PARTITION BY n.file_sha256 ORDER BY n.rel_path COLLATE "C") AS rn
        FROM next_e n
        WHERE NOT EXISTS (SELECT 1 FROM prev_e p WHERE p.rel_path = n.rel_path)
      ),
      renamed AS (
        SELECT 'renamed'::text AS change_kind, a.rel_path, r.rel_path AS old_rel_path,
               a.file_sha256, NULL::text AS prev_file_sha256
        FROM raw_rem r
        JOIN raw_add a ON a.file_sha256 = r.file_sha256 AND a.rn = r.rn
      ),
      removed AS (
        SELECT 'removed'::text AS change_kind, r.rel_path, NULL::text AS old_rel_path,
               NULL::text AS file_sha256, r.file_sha256 AS prev_file_sha256
        FROM raw_rem r
        WHERE NOT EXISTS (SELECT 1 FROM renamed rn WHERE rn.old_rel_path = r.rel_path)
      ),
      added AS (
        SELECT 'added'::text AS change_kind, a.rel_path, NULL::text AS old_rel_path,
               a.file_sha256, NULL::text AS prev_file_sha256
        FROM raw_add a
        WHERE NOT EXISTS (SELECT 1 FROM renamed rn WHERE rn.rel_path = a.rel_path)
      ),
      all_ch AS (
        SELECT * FROM replaced UNION ALL SELECT * FROM renamed UNION ALL SELECT * FROM removed UNION ALL SELECT * FROM added
      )
      SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'change_kind', change_kind, 'rel_path', rel_path, 'old_rel_path', old_rel_path,
        'file_sha256', file_sha256, 'prev_file_sha256', prev_file_sha256
      )), '[]'::jsonb)
      INTO v_changes
      FROM all_ch;
      v_change_cnt := pg_catalog.jsonb_array_length(v_changes);
    END IF;
  END IF;

  v_new_files := coherence._cmd_filter_new_stored_files(p_stored_files, 'company_data');
  v_file_cnt := pg_catalog.jsonb_array_length(v_new_files);

  SELECT coherence.sha256_text(
    COALESCE(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        elem ->> 'rel_path', elem ->> 'file_sha256'
      )) || E'\n',
      '' ORDER BY (elem ->> 'rel_path') COLLATE "C"
    ), '')
  ) INTO v_entries_hash
  FROM pg_catalog.jsonb_array_elements(v_entries) AS t(elem);

  SELECT coherence.sha256_text(
    COALESCE(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        elem ->> 'change_kind', elem ->> 'rel_path', elem ->> 'old_rel_path',
        elem ->> 'file_sha256', elem ->> 'prev_file_sha256'
      )) || E'\n',
      '' ORDER BY (elem ->> 'rel_path') COLLATE "C"
    ), '')
  ) INTO v_changes_hash
  FROM pg_catalog.jsonb_array_elements(v_changes) AS t(elem);

  v_iv_hash := coherence.sha256_text(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_iv_id::text, p_line_kind, v_parent_id::text, p_source_kind, p_reason,
      v_entry_cnt, v_entries_hash, p_entries_list_file_sha256, v_change_cnt, v_changes_hash
    )) || E'\n'
  );

  v_counts := pg_catalog.jsonb_build_object('input_versions', 1);
  v_hashes := pg_catalog.jsonb_build_object('input_versions', v_iv_hash);
  IF v_file_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('stored_files', v_file_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('stored_files', coherence._cmd_hash_stored_files_json(v_new_files));
  END IF;
  IF v_entry_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('input_entries', v_entry_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('input_entries', v_entries_hash);
  END IF;
  IF v_change_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('input_changes', v_change_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('input_changes', v_changes_hash);
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('inputVersionId', v_iv_id, 'parentId', v_parent_id, 'entryCount', v_entry_cnt, 'changeCount', v_change_cnt),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'publish_input_version', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('input_version_id', v_iv_id, 'line_kind', p_line_kind, 'entry_count', v_entry_cnt)
  );
  PERFORM coherence._cmd_insert_stored_files_json(v_new_files, v_seq);

  INSERT INTO coherence.input_versions (
    id, line_kind, parent_id, source_kind, reason,
    entry_count, entries_sha256, entries_list_file_sha256,
    change_count, changes_sha256, store_kind, journal_seq
  ) VALUES (
    v_iv_id, p_line_kind, v_parent_id, p_source_kind, p_reason,
    v_entry_cnt, v_entries_hash, p_entries_list_file_sha256,
    v_change_cnt, v_changes_hash, 'company_data', v_seq
  );

  IF v_entry_cnt > 0 THEN
    INSERT INTO coherence.input_entries (input_version_id, rel_path, store_kind, file_sha256, journal_seq)
    SELECT v_iv_id, elem ->> 'rel_path', 'company_data', elem ->> 'file_sha256', v_seq
    FROM pg_catalog.jsonb_array_elements(v_entries) AS t(elem);
  END IF;

  IF v_change_cnt > 0 THEN
    INSERT INTO coherence.input_changes (input_version_id, rel_path, change_kind, old_rel_path, store_kind, file_sha256, prev_file_sha256, journal_seq)
    SELECT v_iv_id, elem ->> 'rel_path', elem ->> 'change_kind', elem ->> 'old_rel_path',
           'company_data', elem ->> 'file_sha256', elem ->> 'prev_file_sha256', v_seq
    FROM pg_catalog.jsonb_array_elements(v_changes) AS t(elem);
  END IF;

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'input_version_id', v_iv_id);
END;
$$;

-- 7.6 include_staging_file (Operator)
CREATE OR REPLACE FUNCTION app_cmd.coherence_include_staging_file(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_expected_seq BIGINT,
  p_staging_file_sha256 TEXT,
  p_target_rel_path TEXT,
  p_reason TEXT,
  p_input_version_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_parent_id UUID;
  v_next_entries JSONB;
  v_changes JSONB;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.inputs.publish', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('publish_input_version', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;
  PERFORM coherence._cmd_check_expected_seq(p_expected_seq, NULL, true, false);

  IF NOT EXISTS (
    SELECT 1 FROM coherence.imported_files f
    WHERE f.area = 'staging' AND f.file_sha256 = p_staging_file_sha256
  ) THEN
    RAISE EXCEPTION 'STAGED_FILE_NOT_FOUND: staged file does not exist.' USING ERRCODE = 'P0002';
  END IF;

  v_parent_id := coherence.standing_input_version_as_of(NULL);
  IF v_parent_id IS NOT NULL THEN
    IF EXISTS (
      SELECT 1 FROM coherence.input_entries
      WHERE input_version_id = v_parent_id AND file_sha256 = p_staging_file_sha256 AND rel_path <> p_target_rel_path
    ) THEN
      RAISE EXCEPTION 'DUPLICATE_INPUT_BYTES: file already included under another path.' USING ERRCODE = '23505';
    END IF;
    IF EXISTS (
      SELECT 1 FROM coherence.input_entries
      WHERE input_version_id = v_parent_id AND rel_path = p_target_rel_path AND file_sha256 <> p_staging_file_sha256
    ) THEN
      RAISE EXCEPTION 'PATH_ALREADY_EXISTS: another file already exists at target path.' USING ERRCODE = '23505';
    END IF;
    IF EXISTS (
      SELECT 1 FROM coherence.input_entries
      WHERE input_version_id = v_parent_id AND rel_path = p_target_rel_path AND file_sha256 = p_staging_file_sha256
    ) THEN
      RETURN pg_catalog.jsonb_build_object('unchanged', true, 'input_version_id', v_parent_id);
    END IF;
  END IF;

  SELECT COALESCE(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('rel_path', rel_path, 'file_sha256', file_sha256)),
    '[]'::jsonb
  ) || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object('rel_path', p_target_rel_path, 'file_sha256', p_staging_file_sha256))
  INTO v_next_entries
  FROM coherence.input_entries
  WHERE input_version_id = v_parent_id;

  v_changes := CASE
    WHEN v_parent_id IS NOT NULL THEN pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
      'change_kind', 'added', 'rel_path', p_target_rel_path, 'old_rel_path', NULL,
      'file_sha256', p_staging_file_sha256, 'prev_file_sha256', NULL
    ))
    ELSE '[]'::jsonb
  END;

  RETURN app_cmd.coherence_publish_input_version(
    p_command_key, p_request_sha256, p_expected_seq,
    'standing', 'include', pg_catalog.btrim(p_reason),
    v_next_entries, v_changes, '[]'::jsonb, NULL, p_input_version_id
  );
END;
$$;

-- 7.7 launch_run (Operator)
CREATE OR REPLACE FUNCTION app_cmd.coherence_launch_run(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_expected_seq BIGINT,
  p_statement_date DATE,
  p_engine_version_id UUID,
  p_origin TEXT DEFAULT 'app',
  p_input_version_id UUID DEFAULT NULL,
  p_prior_decision_commit_id UUID DEFAULT NULL,
  p_emit_mode TEXT DEFAULT NULL,
  p_emit_display TEXT DEFAULT NULL,
  p_emit_keep TEXT[] DEFAULT NULL,
  p_emit_no_manager TEXT[] DEFAULT NULL,
  p_replays_run_id UUID DEFAULT NULL,
  p_compared_run_id UUID DEFAULT NULL,
  p_rerun_reason TEXT DEFAULT NULL,
  p_run_id UUID DEFAULT NULL,
  p_request_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_run_id UUID := COALESCE(p_run_id, pg_catalog.gen_random_uuid());
  v_req_id UUID := COALESCE(p_request_id, pg_catalog.gen_random_uuid());
  v_iv_id UUID := p_input_version_id;
  v_mode TEXT := p_emit_mode;
  v_disp TEXT := p_emit_display;
  v_keep TEXT[] := p_emit_keep;
  v_nomgr TEXT[] := p_emit_no_manager;
  v_meta RECORD;
  v_prior_ov TEXT;
  v_prior_dc UUID := p_prior_decision_commit_id;
  v_folder_no INT := 1;
  v_run_hash TEXT;
  v_req_hash TEXT;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.run.launch', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('launch_run', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;
  PERFORM coherence._cmd_check_expected_seq(p_expected_seq, NULL, p_origin IN ('app', 'trial'), false);

  IF p_origin = 'replay' AND p_replays_run_id IS NOT NULL AND v_iv_id IS NULL THEN
    SELECT input_version_id INTO v_iv_id FROM coherence.runs WHERE id = p_replays_run_id;
    IF v_iv_id IS NULL THEN
      RAISE EXCEPTION 'RUN_NOT_FOUND: replayed run does not exist.' USING ERRCODE = 'P0002';
    END IF;
  ELSIF v_iv_id IS NULL THEN
    v_iv_id := coherence.standing_input_version_as_of(NULL);
    IF v_iv_id IS NULL THEN
      RAISE EXCEPTION 'NO_STANDING_INPUT: no standing input version exists yet.' USING ERRCODE = '23514';
    END IF;
  END IF;

  IF v_mode IS NULL THEN
    SELECT default_emit_mode, default_emit_display, default_emit_keep, default_emit_no_manager
    INTO v_meta
    FROM coherence.company_meta LIMIT 1;
    IF FOUND THEN
      v_mode := v_meta.default_emit_mode;
      v_disp := v_meta.default_emit_display;
      v_keep := v_meta.default_emit_keep;
      v_nomgr := v_meta.default_emit_no_manager;
    ELSE
      v_mode := 'builtin';
    END IF;
  END IF;
  v_keep := COALESCE(v_keep, '{}');
  v_nomgr := COALESCE(v_nomgr, '{}');
  IF v_mode <> 'generated' THEN
    v_disp := NULL; v_keep := '{}'; v_nomgr := '{}';
  END IF;

  SELECT file_sha256 INTO v_prior_ov
  FROM coherence.input_entries
  WHERE input_version_id = v_iv_id AND mac_key = 'overlay/overlay.csv';

  IF v_prior_dc IS NULL AND v_prior_ov IS NULL AND p_origin IN ('app', 'trial') THEN
    v_prior_dc := coherence.standing_decision_head_as_of(NULL);
  END IF;

  IF p_origin IN ('app', 'trial') THEN
    SELECT COALESCE(pg_catalog.max(folder_number), 0) + 1 INTO v_folder_no
    FROM coherence.runs WHERE origin = p_origin AND statement_date = p_statement_date;
  END IF;

  v_run_hash := coherence.sha256_text(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_run_id::text, coherence.fmt_date(p_statement_date), v_folder_no, p_origin,
      v_iv_id::text, v_prior_ov, v_prior_dc::text, p_engine_version_id::text,
      v_mode, v_disp, v_keep, v_nomgr,
      p_replays_run_id::text, p_compared_run_id::text, p_rerun_reason, NULL::text
    )) || E'\n'
  );
  v_req_hash := coherence.sha256_text(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_req_id::text, v_run_id::text, 'assign', 'launch', NULL::text
    )) || E'\n'
  );

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object(
      'runId', v_run_id, 'stepRequestId', v_req_id,
      'statementDate', coherence.fmt_date(p_statement_date),
      'folderNumber', v_folder_no, 'origin', p_origin,
      'priorDecisionCommitId', v_prior_dc
    ),
    'commitments', pg_catalog.jsonb_build_object(
      'counts', pg_catalog.jsonb_build_object('runs', 1, 'step_requests', 1),
      'hashes', pg_catalog.jsonb_build_object('runs', v_run_hash, 'step_requests', v_req_hash)
    )
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'launch_run', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('run_id', v_run_id, 'statement_date', coherence.fmt_date(p_statement_date), 'origin', p_origin)
  );

  INSERT INTO coherence.runs (
    id, statement_date, folder_number, origin, input_version_id, prior_approvals_sha256,
    prior_decision_commit_id, engine_version_id, emit_mode, emit_display, emit_keep, emit_no_manager,
    replays_run_id, compared_run_id, rerun_reason, source_folder, journal_seq
  ) VALUES (
    v_run_id, p_statement_date, v_folder_no, p_origin, v_iv_id, v_prior_ov,
    v_prior_dc, p_engine_version_id, v_mode, v_disp, v_keep, v_nomgr,
    p_replays_run_id, p_compared_run_id, p_rerun_reason, NULL, v_seq
  );
  INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
  VALUES (v_req_id, v_run_id, 'assign', 'launch', NULL, v_seq);

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object(
    'idempotent', false, 'journal_seq', v_seq,
    'run_id', v_run_id, 'step_request_id', v_req_id, 'folder_number', v_folder_no,
    'prior_decision_commit_id', v_prior_dc
  );
END;
$$;

-- 7.8 request_cancel (Operator)
CREATE OR REPLACE FUNCTION app_cmd.coherence_request_cancel(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_expected_seq BIGINT,
  p_run_id UUID,
  p_step TEXT,
  p_attempt_no INTEGER,
  p_typed_phrase TEXT,
  p_reason TEXT DEFAULT '',
  p_cancel_request_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_cr_id UUID := COALESCE(p_cancel_request_id, pg_catalog.gen_random_uuid());
  v_reason TEXT := COALESCE(p_reason, '');
  v_hash TEXT;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.run.cancel', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('request_cancel', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;
  PERFORM coherence._cmd_check_expected_seq(p_expected_seq, p_run_id, false, false);

  v_hash := coherence.sha256_text(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_cr_id::text, p_run_id::text, p_step, p_attempt_no, p_typed_phrase, v_reason
    )) || E'\n'
  );
  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('cancelRequestId', v_cr_id, 'runId', p_run_id, 'step', p_step, 'attemptNo', p_attempt_no),
    'commitments', pg_catalog.jsonb_build_object(
      'counts', pg_catalog.jsonb_build_object('cancel_requests', 1),
      'hashes', pg_catalog.jsonb_build_object('cancel_requests', v_hash)
    )
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'request_cancel', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('cancel_request_id', v_cr_id, 'run_id', p_run_id, 'step', p_step)
  );
  INSERT INTO coherence.cancel_requests (id, run_id, step, attempt_no, typed_phrase, reason, journal_seq)
  VALUES (v_cr_id, p_run_id, p_step, p_attempt_no, p_typed_phrase, v_reason, v_seq);

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'cancel_request_id', v_cr_id);
END;
$$;

-- 7.9 request_retry (Operator)
CREATE OR REPLACE FUNCTION app_cmd.coherence_request_retry(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_expected_seq BIGINT,
  p_run_id UUID,
  p_step TEXT,
  p_request_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_req_id UUID := COALESCE(p_request_id, pg_catalog.gen_random_uuid());
  v_emit_conf_id UUID := NULL;
  v_sup JSONB;
  v_sup_cnt INT;
  v_sup_hash TEXT;
  v_req_hash TEXT;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.run.retry', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('request_retry', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;
  PERFORM coherence._cmd_check_expected_seq(p_expected_seq, p_run_id, false, false);

  IF p_step = 'emit' THEN
    SELECT ec.id INTO v_emit_conf_id
    FROM coherence.emit_confirmations ec
    JOIN coherence.review_saves rs ON rs.id = ec.adjust_review_save_id
    WHERE ec.run_id = p_run_id
      AND rs.attempt_event_id = coherence.current_finished_attempt(p_run_id, 'adjust')
    ORDER BY ec.journal_seq DESC
    LIMIT 1;
    IF v_emit_conf_id IS NULL THEN
      RAISE EXCEPTION 'MISSING_EMIT_CONFIRMATION: emit retry requires an existing Emit confirmation.' USING ERRCODE = '23514';
    END IF;
  END IF;

  SELECT COALESCE(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'id', pg_catalog.gen_random_uuid(),
      'step', e.step,
      'attempt_no', e.attempt_no
    ) ORDER BY coherence.step_rank(e.step) ASC, e.attempt_no ASC),
    '[]'::jsonb
  ) INTO v_sup
  FROM coherence.step_attempt_events e
  WHERE e.run_id = p_run_id
    AND coherence.step_rank(e.step) > coherence.step_rank(p_step)
    AND e.event_kind IN ('finished', 'failed', 'interrupted', 'cancelled')
    AND NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events sup
      WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no AND sup.event_kind = 'superseded'
    );

  v_sup_cnt := pg_catalog.jsonb_array_length(v_sup);
  v_req_hash := coherence.sha256_text(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_req_id::text, p_run_id::text, p_step, 'retry', v_emit_conf_id::text
    )) || E'\n'
  );
  v_counts := pg_catalog.jsonb_build_object('step_requests', 1);
  v_hashes := pg_catalog.jsonb_build_object('step_requests', v_req_hash);

  IF v_sup_cnt > 0 THEN
    SELECT coherence.sha256_text(
      pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          elem ->> 'id', p_run_id::text, elem ->> 'step', (elem ->> 'attempt_no')::integer,
          'superseded', NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer, NULL::text
        )) || E'\n',
        '' ORDER BY (elem ->> 'id') COLLATE "C"
      )
    ) INTO v_sup_hash
    FROM pg_catalog.jsonb_array_elements(v_sup) AS t(elem);
    v_counts := v_counts || pg_catalog.jsonb_build_object('step_attempt_events', v_sup_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('step_attempt_events', v_sup_hash);
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('stepRequestId', v_req_id, 'runId', p_run_id, 'step', p_step, 'emitConfirmationId', v_emit_conf_id),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'request_retry', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('step_request_id', v_req_id, 'run_id', p_run_id, 'step', p_step)
  );

  IF v_sup_cnt > 0 THEN
    INSERT INTO coherence.step_attempt_events (id, run_id, step, attempt_no, event_kind, journal_seq)
    SELECT (elem ->> 'id')::uuid, p_run_id, elem ->> 'step', (elem ->> 'attempt_no')::integer, 'superseded', v_seq
    FROM pg_catalog.jsonb_array_elements(v_sup) AS t(elem);
  END IF;
  INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
  VALUES (v_req_id, p_run_id, p_step, 'retry', v_emit_conf_id, v_seq);

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'step_request_id', v_req_id);
END;
$$;

-- 7.10 submit_review (Operator)
CREATE OR REPLACE FUNCTION app_cmd.coherence_submit_review(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_expected_seq BIGINT,
  p_run_id UUID,
  p_surface TEXT,
  p_staged_sha256 TEXT,
  p_submission_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_sub_id UUID := COALESCE(p_submission_id, pg_catalog.gen_random_uuid());
  v_ex RECORD;
  v_audit_key TEXT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.review.submit', 'human_only');
  IF p_command_key IS NULL OR pg_catalog.length(p_command_key) < 1 OR pg_catalog.length(p_command_key) > 200 THEN
    RAISE EXCEPTION 'MISSING_COMMAND_KEY: command_key required.' USING ERRCODE = '22023';
  END IF;
  IF p_request_sha256 IS NULL OR p_request_sha256 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'INVALID_REQUEST_SHA256: valid 64-hex request_sha256 required.' USING ERRCODE = '22023';
  END IF;

  SELECT id, status, review_save_id, result_journal_seq, actor, acting_for, request_sha256
  INTO v_ex
  FROM coherence.review_submissions
  WHERE command_key = p_command_key;

  IF FOUND THEN
    IF v_ex.actor = v_ctx.actor_label
       AND v_ex.acting_for IS NOT DISTINCT FROM v_ctx.acting_for_label
       AND v_ex.request_sha256 = p_request_sha256
    THEN
      RETURN pg_catalog.jsonb_build_object('idempotent', true, 'submission_id', v_ex.id, 'status', v_ex.status);
    END IF;
    RAISE EXCEPTION 'COMMAND_KEY_CONFLICT: command_key already used for a different review submission.' USING ERRCODE = '23505';
  END IF;

  PERFORM coherence._cmd_check_expected_seq(p_expected_seq, p_run_id, false, false);

  INSERT INTO coherence.review_submissions (
    id, run_id, surface, staged_sha256, staged_object_name, expected_journal_seq,
    actor, acting_for, command_key, request_sha256, status
  ) VALUES (
    v_sub_id, p_run_id, p_surface, p_staged_sha256,
    'staging/reviews/' || v_sub_id::text || '/' || p_staged_sha256,
    p_expected_seq, v_ctx.actor_label, v_ctx.acting_for_label, p_command_key, p_request_sha256, 'pending'
  );

  v_audit_key := CASE
    WHEN pg_catalog.length(p_command_key) <= 185 THEN 'coherence:sub:' || p_command_key
    ELSE 'csub:' || coherence.sha256_text(p_command_key)
  END;
  INSERT INTO platform.audit_journal (
    environment, actor_person_id, recorded_as, target_org_id,
    command_kind, command_key, request_sha256, body
  ) VALUES (
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, v_ctx.tenant_org_id,
    'coherence.submit_review', v_audit_key, p_request_sha256,
    pg_catalog.jsonb_build_object('submission_id', v_sub_id, 'run_id', p_run_id, 'surface', p_surface)
  );

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'submission_id', v_sub_id, 'status', 'pending');
END;
$$;

-- 7.11 save_review_draft (Operator)
CREATE OR REPLACE FUNCTION app_cmd.coherence_save_review_draft(
  p_run_id UUID,
  p_surface TEXT,
  p_attempt_no INTEGER,
  p_checksum TEXT,
  p_rows JSONB,
  p_born TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.review.draft', 'human_only');
  IF p_surface NOT IN ('bible', 'adjust') THEN
    RAISE EXCEPTION 'INVALID_SURFACE: review draft surface must be bible or adjust.' USING ERRCODE = '22023';
  END IF;
  IF p_rows IS NULL OR pg_catalog.jsonb_typeof(p_rows) <> 'array' THEN
    RAISE EXCEPTION 'INVALID_DRAFT: draft rows must be a JSON array.' USING ERRCODE = '22023';
  END IF;

  INSERT INTO coherence.review_drafts (
    run_id, surface, attempt_no, born, checksum, rows_json, actor, acting_for, updated_at, expires_at
  ) VALUES (
    p_run_id, p_surface, p_attempt_no, p_born, p_checksum, p_rows,
    v_ctx.actor_label, v_ctx.acting_for_label,
    pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp() + INTERVAL '30 days'
  )
  ON CONFLICT (run_id, surface, attempt_no) DO UPDATE
    SET born = EXCLUDED.born,
        checksum = EXCLUDED.checksum,
        rows_json = EXCLUDED.rows_json,
        actor = EXCLUDED.actor,
        acting_for = EXCLUDED.acting_for,
        updated_at = EXCLUDED.updated_at,
        expires_at = EXCLUDED.expires_at;

  RETURN pg_catalog.jsonb_build_object('saved', pg_catalog.jsonb_array_length(p_rows), 'run_id', p_run_id, 'surface', p_surface, 'attempt_no', p_attempt_no);
END;
$$;

-- 7.12 save_review_decisions (Operator)
CREATE OR REPLACE FUNCTION app_cmd.coherence_save_review_decisions(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_expected_seq BIGINT,
  p_run_id UUID,
  p_surface TEXT,
  p_decisions JSONB,
  p_decision_commit_id UUID DEFAULT NULL,
  p_review_save_id UUID DEFAULT NULL,
  p_adjust_request_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_dc_id UUID := COALESCE(p_decision_commit_id, pg_catalog.gen_random_uuid());
  v_rs_id UUID := COALESCE(p_review_save_id, pg_catalog.gen_random_uuid());
  v_adj_req_id UUID := COALESCE(p_adjust_request_id, pg_catalog.gen_random_uuid());
  v_in JSONB := coherence._cmd_jsonb_array(p_decisions);
  v_in_cnt INT;
  v_input_keys TEXT[];
  v_dup_key TEXT;
  v_run RECORD;
  v_attempt_id UUID;
  v_prior_same RECORD;
  v_prior_same_found BOOLEAN := false;
  v_parent_commit UUID := NULL;
  v_parent_cum INT := 0;
  v_head_map JSONB := '{}'::jsonb;
  v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
  v_dec_rows JSONB := '[]'::jsonb;
  v_elem JSONB;
  v_ord INT := 0;
  v_dec_id UUID;
  v_prev JSONB;
  v_prev_id UUID;
  v_rec_id TEXT;
  v_all_unchanged BOOLEAN := true;
  v_added_hash TEXT;
  v_table_dec_hash TEXT;
  v_dc_hash TEXT;
  v_rs_hash TEXT;
  v_sup_id UUID := NULL;
  v_sup_attempt INT := NULL;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.review.save', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('save_review_decisions', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;
  IF p_surface IS NULL OR p_surface NOT IN ('bible', 'adjust') THEN
    RAISE EXCEPTION 'INVALID_SURFACE: review surface must be bible or adjust.' USING ERRCODE = '22023';
  END IF;
  IF p_expected_seq IS NULL THEN
    RAISE EXCEPTION 'MISSING_JOURNAL_SEQ: saving a review requires expected_seq.' USING ERRCODE = '22023';
  END IF;
  IF pg_catalog.jsonb_typeof(v_in) <> 'array' THEN
    RAISE EXCEPTION 'INVALID_DECISIONS: decisions must be a JSON array.' USING ERRCODE = '22023';
  END IF;

  v_in_cnt := pg_catalog.jsonb_array_length(v_in);
  IF v_in_cnt > 0 THEN
    IF EXISTS (
      SELECT 1 FROM pg_catalog.jsonb_array_elements(v_in) AS t(e)
      WHERE e ->> 'record_id' IS NULL OR pg_catalog.length(pg_catalog.btrim(e ->> 'record_id')) = 0
    ) THEN
      RAISE EXCEPTION 'INVALID_DECISIONS: every decision requires a non-empty record_id.' USING ERRCODE = '22023';
    END IF;
    SELECT e ->> 'record_id' INTO v_dup_key
    FROM pg_catalog.jsonb_array_elements(v_in) AS t(e)
    GROUP BY e ->> 'record_id'
    HAVING pg_catalog.count(*) > 1
    LIMIT 1;
    IF v_dup_key IS NOT NULL THEN
      RAISE EXCEPTION 'DUPLICATE_DECISION_KEY: a live review save cannot include the same decision key (%) more than once.', v_dup_key
        USING ERRCODE = '23505';
    END IF;
    SELECT COALESCE(pg_catalog.array_agg(DISTINCT (e ->> 'record_id')), ARRAY[]::text[])
    INTO v_input_keys
    FROM pg_catalog.jsonb_array_elements(v_in) AS t(e);
  END IF;

  PERFORM coherence._cmd_check_expected_seq(p_expected_seq, p_run_id, false, false);

  SELECT id, prior_decision_commit_id INTO v_run FROM coherence.runs WHERE id = p_run_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RUN_NOT_FOUND: run does not exist.' USING ERRCODE = 'P0002';
  END IF;

  v_attempt_id := coherence.current_finished_attempt(p_run_id, p_surface);
  IF v_attempt_id IS NULL THEN
    RAISE EXCEPTION 'NO_FINISHED_ATTEMPT: no current finished % attempt.', p_surface USING ERRCODE = '23514';
  END IF;

  SELECT id, decision_commit_id INTO v_prior_same
  FROM coherence.review_saves
  WHERE run_id = p_run_id AND surface = p_surface AND attempt_event_id = v_attempt_id
    AND decision_commit_id IS NOT NULL
  ORDER BY journal_seq DESC LIMIT 1;
  v_prior_same_found := FOUND;

  IF v_prior_same_found THEN
    IF v_in_cnt = 0 THEN
      RAISE EXCEPTION 'DUPLICATE_REVIEW_SAVE: no new decisions for this attempt.' USING ERRCODE = '23514';
    END IF;
    v_parent_commit := v_prior_same.decision_commit_id;
  ELSIF p_surface = 'bible' THEN
    v_parent_commit := v_run.prior_decision_commit_id;
  ELSE
    SELECT decision_commit_id INTO v_parent_commit
    FROM coherence.review_saves
    WHERE run_id = p_run_id AND surface = 'bible'
      AND attempt_event_id = coherence.current_finished_attempt(p_run_id, 'bible')
      AND decision_commit_id IS NOT NULL
    ORDER BY journal_seq DESC LIMIT 1;
    IF v_parent_commit IS NULL THEN
      RAISE EXCEPTION 'MISSING_BIBLE_SAVE: adjust review requires a saved Bible commit first.' USING ERRCODE = '23514';
    END IF;
  END IF;

  -- Read current decisions for touched keys ONCE before the loop.
  IF v_parent_commit IS NOT NULL THEN
    SELECT cumulative_decision_count INTO v_parent_cum FROM coherence.decision_commits WHERE id = v_parent_commit;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'DECISION_COMMIT_NOT_FOUND: parent decision commit does not exist.' USING ERRCODE = 'P0002';
    END IF;
    IF v_in_cnt > 0 THEN
      SELECT COALESCE(
        pg_catalog.jsonb_object_agg(
          d.record_id,
          pg_catalog.jsonb_build_object(
            'id', d.id::text,
            'disposition', d.disposition,
            'agent', d.agent,
            'agency', d.agency,
            'book', d.book,
            'status', d.status,
            'note', d.note,
            'approved_amount', d.approved_amount,
            'approved_agency', d.approved_agency,
            'approved_agent', d.approved_agent,
            'approved_agency_from', d.approved_agency_from,
            'approved_agent_from', d.approved_agent_from
          )
        ),
        '{}'::jsonb
      ) INTO v_head_map
      FROM coherence.decisions_current(v_parent_commit) d
      WHERE d.record_id = ANY(v_input_keys);
    END IF;
  END IF;

  v_ord := v_in_cnt;
  SELECT
    COALESCE(pg_catalog.bool_and(
      prev_obj IS NOT NULL
      AND (prev_obj ->> 'disposition') IS NOT DISTINCT FROM (elem ->> 'disposition')
      AND (prev_obj ->> 'agent') IS NOT DISTINCT FROM (elem ->> 'agent')
      AND (prev_obj ->> 'agency') IS NOT DISTINCT FROM (elem ->> 'agency')
      AND (prev_obj ->> 'book') IS NOT DISTINCT FROM (elem ->> 'book')
      AND (prev_obj ->> 'status') IS NOT DISTINCT FROM (elem ->> 'status')
      AND (prev_obj ->> 'note') IS NOT DISTINCT FROM (elem ->> 'note')
      AND (prev_obj ->> 'approved_amount') IS NOT DISTINCT FROM (elem ->> 'approved_amount')
      AND (prev_obj ->> 'approved_agency') IS NOT DISTINCT FROM (elem ->> 'approved_agency')
      AND (prev_obj ->> 'approved_agent') IS NOT DISTINCT FROM (elem ->> 'approved_agent')
      AND (prev_obj ->> 'approved_agency_from') IS NOT DISTINCT FROM (elem ->> 'approved_agency_from')
      AND (prev_obj ->> 'approved_agent_from') IS NOT DISTINCT FROM (elem ->> 'approved_agent_from')
    ), true),
    COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'id', COALESCE((elem ->> 'id')::uuid, pg_catalog.gen_random_uuid()),
      'row_order', ord::int,
      'record_id', elem ->> 'record_id',
      'replaces_decision_id', CASE WHEN prev_obj IS NOT NULL THEN (prev_obj ->> 'id')::uuid ELSE NULL END,
      'disposition', elem ->> 'disposition',
      'agent', elem ->> 'agent', 'agency', elem ->> 'agency', 'book', elem ->> 'book',
      'status', elem ->> 'status', 'note', elem ->> 'note',
      'approved_amount', elem ->> 'approved_amount', 'approved_agency', elem ->> 'approved_agency',
      'approved_agent', elem ->> 'approved_agent',
      'approved_agency_from', elem ->> 'approved_agency_from',
      'approved_agent_from', elem ->> 'approved_agent_from',
      'decided_at', coherence.format_utc_us(v_now),
      'committed_at_raw', COALESCE(elem ->> 'committed_at_raw', coherence.format_utc_us(v_now))
    ) ORDER BY ord), '[]'::jsonb)
  INTO v_all_unchanged, v_dec_rows
  FROM (
    SELECT ord, elem, v_head_map -> (elem ->> 'record_id') AS prev_obj
    FROM pg_catalog.jsonb_array_elements(v_in) WITH ORDINALITY AS t(elem, ord)
  ) s;

  IF v_prior_same_found AND v_in_cnt > 0 AND v_all_unchanged THEN
    RAISE EXCEPTION 'DUPLICATE_REVIEW_SAVE: submitted decisions are identical to the current saved review.'
      USING ERRCODE = '23514';
  END IF;

  SELECT coherence.sha256_text(
    COALESCE(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        e ->> 'id', (e ->> 'row_order')::int, p_run_id::text, v_rs_id::text, p_surface,
        e ->> 'record_id', e ->> 'replaces_decision_id', e ->> 'disposition',
        e ->> 'agent', e ->> 'agency', NULL::text, e ->> 'book', NULL::text, e ->> 'status', e ->> 'note',
        e ->> 'approved_amount', e ->> 'approved_agency', e ->> 'approved_agent',
        e ->> 'approved_agency_from', e ->> 'approved_agent_from',
        v_ctx.actor_label, v_ctx.acting_for_label, e ->> 'decided_at', e ->> 'committed_at_raw', false
      )) || E'\n',
      '' ORDER BY (e ->> 'row_order')::int ASC
    ), '')
  ) INTO v_added_hash
  FROM pg_catalog.jsonb_array_elements(v_dec_rows) AS t(e);

  SELECT coherence.sha256_text(
    COALESCE(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        v_dc_id::text, e ->> 'id', (e ->> 'row_order')::int, p_run_id::text, v_rs_id::text, p_surface,
        e ->> 'record_id', e ->> 'replaces_decision_id', e ->> 'disposition',
        e ->> 'agent', e ->> 'agency', NULL::text, e ->> 'book', NULL::text, e ->> 'status', e ->> 'note',
        e ->> 'approved_amount', e ->> 'approved_agency', e ->> 'approved_agent',
        e ->> 'approved_agency_from', e ->> 'approved_agent_from',
        v_ctx.actor_label, v_ctx.acting_for_label, e ->> 'decided_at', e ->> 'committed_at_raw', false
      )) || E'\n',
      '' ORDER BY (e ->> 'row_order')::int ASC
    ), '')
  ) INTO v_table_dec_hash
  FROM pg_catalog.jsonb_array_elements(v_dec_rows) AS t(e);

  v_dc_hash := coherence.sha256_text(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_dc_id::text, v_parent_commit::text, 'review_save', 'v2',
      v_ord, v_parent_cum + v_ord, v_added_hash, false, NULL::text
    )) || E'\n'
  );
  v_rs_hash := coherence.sha256_text(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_rs_id::text, p_run_id::text, p_surface, v_attempt_id::text,
      NULL::text, v_dc_id::text, false, NULL::text, NULL::text
    )) || E'\n'
  );

  v_counts := pg_catalog.jsonb_build_object('decision_commits', 1, 'review_saves', 1);
  v_hashes := pg_catalog.jsonb_build_object('decision_commits', v_dc_hash, 'review_saves', v_rs_hash);
  IF v_ord > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('decisions', v_ord);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('decisions', v_table_dec_hash);
  END IF;

  IF p_surface = 'bible' THEN
    SELECT attempt_no INTO v_sup_attempt
    FROM coherence.step_attempt_events
    WHERE id = coherence.current_finished_attempt(p_run_id, 'adjust');
    IF v_sup_attempt IS NOT NULL THEN
      v_sup_id := pg_catalog.gen_random_uuid();
      v_counts := v_counts || pg_catalog.jsonb_build_object('step_attempt_events', 1);
      v_hashes := v_hashes || pg_catalog.jsonb_build_object(
        'step_attempt_events',
        coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
          v_sup_id::text, p_run_id::text, 'adjust', v_sup_attempt, 'superseded',
          NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer, NULL::text
        )) || E'\n')
      );
    END IF;
    v_counts := v_counts || pg_catalog.jsonb_build_object('step_requests', 1);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object(
      'step_requests',
      coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
        v_adj_req_id::text, p_run_id::text, 'adjust', 'bible_saved', NULL::text
      )) || E'\n')
    );
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('decisionCommitId', v_dc_id, 'reviewSaveId', v_rs_id, 'runId', p_run_id, 'surface', p_surface, 'addedCount', v_ord),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'save_review_decisions', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('run_id', p_run_id, 'surface', p_surface, 'decision_commit_id', v_dc_id, 'added_count', v_ord)
  );

  INSERT INTO coherence.decision_commits (
    id, parent_commit_id, commit_kind, header_contract,
    added_decision_count, cumulative_decision_count, added_decisions_sha256,
    imported, original_at, journal_seq
  ) VALUES (
    v_dc_id, v_parent_commit, 'review_save', 'v2',
    v_ord, v_parent_cum + v_ord, v_added_hash, false, NULL, v_seq
  );
  INSERT INTO coherence.review_saves (
    id, run_id, surface, attempt_event_id, approvals_file_sha256, decision_commit_id,
    imported, original_at, submission_id, journal_seq
  ) VALUES (
    v_rs_id, p_run_id, p_surface, v_attempt_id, NULL, v_dc_id, false, NULL, NULL, v_seq
  );
  IF v_ord > 0 THEN
    INSERT INTO coherence.decisions (
      id, decision_commit_id, row_order, run_id, review_save_id, surface, record_id,
      replaces_decision_id, disposition, agent, agency, policy, book, month, status, note,
      approved_amount, approved_agency, approved_agent, approved_agency_from, approved_agent_from,
      decided_by, acting_for, decided_at, committed_at_raw, imported, journal_seq
    )
    SELECT
      (e ->> 'id')::uuid, v_dc_id, (e ->> 'row_order')::int, p_run_id, v_rs_id, p_surface, e ->> 'record_id',
      (e ->> 'replaces_decision_id')::uuid, e ->> 'disposition', e ->> 'agent', e ->> 'agency', NULL,
      e ->> 'book', NULL, e ->> 'status', e ->> 'note',
      e ->> 'approved_amount', e ->> 'approved_agency', e ->> 'approved_agent',
      e ->> 'approved_agency_from', e ->> 'approved_agent_from',
      v_ctx.actor_label, v_ctx.acting_for_label, (e ->> 'decided_at')::timestamptz,
      e ->> 'committed_at_raw', false, v_seq
    FROM pg_catalog.jsonb_array_elements(v_dec_rows) AS t(e);
  END IF;
  IF v_sup_id IS NOT NULL THEN
    INSERT INTO coherence.step_attempt_events (id, run_id, step, attempt_no, event_kind, journal_seq)
    VALUES (v_sup_id, p_run_id, 'adjust', v_sup_attempt, 'superseded', v_seq);
  END IF;
  IF p_surface = 'bible' THEN
    INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
    VALUES (v_adj_req_id, p_run_id, 'adjust', 'bible_saved', NULL, v_seq);
  END IF;
  DELETE FROM coherence.review_drafts WHERE run_id = p_run_id AND surface = p_surface;

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'decision_commit_id', v_dc_id, 'review_save_id', v_rs_id);
END;
$$;

-- 7.13 confirm_emit (Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_confirm_emit(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_expected_seq BIGINT,
  p_run_id UUID,
  p_adjust_review_save_id UUID,
  p_typed_phrase TEXT,
  p_confirmation_id UUID DEFAULT NULL,
  p_request_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_conf_id UUID := COALESCE(p_confirmation_id, pg_catalog.gen_random_uuid());
  v_req_id UUID := COALESCE(p_request_id, pg_catalog.gen_random_uuid());
  v_conf_hash TEXT;
  v_req_hash TEXT;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.owner.confirm_emit', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('confirm_emit', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;
  PERFORM coherence._cmd_check_expected_seq(p_expected_seq, p_run_id, false, false);

  v_conf_hash := coherence.sha256_text(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_conf_id::text, p_run_id::text, p_adjust_review_save_id::text, p_typed_phrase
    )) || E'\n'
  );
  v_req_hash := coherence.sha256_text(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_req_id::text, p_run_id::text, 'emit', 'emit_confirmed', v_conf_id::text
    )) || E'\n'
  );
  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('emitConfirmationId', v_conf_id, 'stepRequestId', v_req_id, 'runId', p_run_id),
    'commitments', pg_catalog.jsonb_build_object(
      'counts', pg_catalog.jsonb_build_object('emit_confirmations', 1, 'step_requests', 1),
      'hashes', pg_catalog.jsonb_build_object('emit_confirmations', v_conf_hash, 'step_requests', v_req_hash)
    )
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'confirm_emit', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('emit_confirmation_id', v_conf_id, 'run_id', p_run_id)
  );

  INSERT INTO coherence.emit_confirmations (id, run_id, adjust_review_save_id, typed_phrase, journal_seq)
  VALUES (v_conf_id, p_run_id, p_adjust_review_save_id, p_typed_phrase, v_seq);
  INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
  VALUES (v_req_id, p_run_id, 'emit', 'emit_confirmed', v_conf_id, v_seq);

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'emit_confirmation_id', v_conf_id, 'step_request_id', v_req_id);
END;
$$;

-- 7.14 carry_sent (Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_carry_sent(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_expected_seq BIGINT,
  p_run_id UUID,
  p_typed_phrase TEXT,
  p_reason TEXT DEFAULT NULL,
  p_carry_id UUID DEFAULT NULL,
  p_input_version_id UUID DEFAULT NULL,
  p_sent_provenance JSONB DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_carry_id UUID := COALESCE(p_carry_id, pg_catalog.gen_random_uuid());
  v_iv_id UUID := COALESCE(p_input_version_id, pg_catalog.gen_random_uuid());
  v_stmt_date DATE;
  v_stamp TEXT;
  v_emit_ev UUID;
  v_file_sha TEXT;
  v_parent_id UUID;
  v_sent_rel TEXT;
  v_reason TEXT;
  v_next_entries JSONB;
  v_changes JSONB;
  v_entry_cnt INT;
  v_change_cnt INT;
  v_entries_hash TEXT;
  v_changes_hash TEXT;
  v_iv_hash TEXT;
  v_carry_hash TEXT;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.owner.carry_sent', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('carry_sent', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;
  PERFORM coherence._cmd_check_expected_seq(p_expected_seq, p_run_id, true, false);

  SELECT statement_date, pg_catalog.to_char(statement_date, 'YYYYMMDD')
  INTO v_stmt_date, v_stamp
  FROM coherence.runs WHERE id = p_run_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'RUN_NOT_FOUND: run does not exist.' USING ERRCODE = 'P0002'; END IF;

  v_emit_ev := coherence.current_finished_attempt(p_run_id, 'emit');
  IF v_emit_ev IS NULL THEN RAISE EXCEPTION 'EMIT_NOT_FINISHED: run has not finished Emit.' USING ERRCODE = '23514'; END IF;

  SELECT file_sha256 INTO v_file_sha
  FROM coherence.artifacts WHERE attempt_event_id = v_emit_ev AND rel_path = 'emits/statements_' || v_stamp || '.csv';
  IF v_file_sha IS NULL THEN RAISE EXCEPTION 'ARTIFACT_NOT_FOUND: emit statements artifact not found.' USING ERRCODE = 'P0002'; END IF;

  v_parent_id := coherence.standing_input_version_as_of(NULL);
  v_sent_rel := 'Sent/statements_' || v_stamp || '.csv';
  IF v_parent_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM coherence.input_entries
    WHERE input_version_id = v_parent_id AND mac_key = pg_catalog.lower(pg_catalog.normalize(v_sent_rel, 'NFC'))
  ) THEN
    RAISE EXCEPTION 'SENT_ALREADY_IN_STANDING_INPUT: standing input already contains %.', v_sent_rel USING ERRCODE = '23505';
  END IF;

  SELECT COALESCE(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('rel_path', rel_path, 'file_sha256', file_sha256)),
    '[]'::jsonb
  ) || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object('rel_path', v_sent_rel, 'file_sha256', v_file_sha))
  INTO v_next_entries
  FROM coherence.input_entries WHERE input_version_id = v_parent_id;

  v_changes := CASE
    WHEN v_parent_id IS NOT NULL THEN pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
      'change_kind', 'added', 'rel_path', v_sent_rel, 'old_rel_path', NULL, 'file_sha256', v_file_sha, 'prev_file_sha256', NULL
    ))
    ELSE '[]'::jsonb
  END;
  v_entry_cnt := pg_catalog.jsonb_array_length(v_next_entries);
  v_change_cnt := pg_catalog.jsonb_array_length(v_changes);
  v_reason := COALESCE(p_reason, 'Record statement ' || coherence.fmt_date(v_stmt_date) || ' as sent');

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(e ->> 'rel_path', e ->> 'file_sha256')) || E'\n',
    '' ORDER BY (e ->> 'rel_path') COLLATE "C"
  ), '')) INTO v_entries_hash FROM pg_catalog.jsonb_array_elements(v_next_entries) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      e ->> 'change_kind', e ->> 'rel_path', e ->> 'old_rel_path', e ->> 'file_sha256', e ->> 'prev_file_sha256'
    )) || E'\n',
    '' ORDER BY (e ->> 'rel_path') COLLATE "C"
  ), '')) INTO v_changes_hash FROM pg_catalog.jsonb_array_elements(v_changes) AS t(e);

  v_iv_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_iv_id::text, 'standing', v_parent_id::text, 'record_sent', v_reason,
    v_entry_cnt, v_entries_hash, NULL::text, v_change_cnt, v_changes_hash
  )) || E'\n');
  v_carry_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_carry_id::text, p_run_id::text, coherence.fmt_date(v_stmt_date),
    'sent', v_file_sha, NULL::text, v_iv_id::text, false, p_typed_phrase
  )) || E'\n');

  v_counts := pg_catalog.jsonb_build_object('input_versions', 1, 'input_entries', v_entry_cnt, 'carries', 1);
  v_hashes := pg_catalog.jsonb_build_object('input_versions', v_iv_hash, 'input_entries', v_entries_hash, 'carries', v_carry_hash);
  IF v_change_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('input_changes', v_change_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('input_changes', v_changes_hash);
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('carryId', v_carry_id, 'publishedInputVersionId', v_iv_id, 'statementDate', coherence.fmt_date(v_stmt_date), 'fileSha256', v_file_sha),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  ) || CASE WHEN p_sent_provenance IS NOT NULL THEN pg_catalog.jsonb_build_object('sentProvenance', p_sent_provenance) ELSE '{}'::jsonb END;
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'carry_sent', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('carry_id', v_carry_id, 'run_id', p_run_id, 'statement_date', coherence.fmt_date(v_stmt_date))
  );

  INSERT INTO coherence.input_versions (
    id, line_kind, parent_id, source_kind, reason,
    entry_count, entries_sha256, change_count, changes_sha256, store_kind, journal_seq
  ) VALUES (
    v_iv_id, 'standing', v_parent_id, 'record_sent', v_reason,
    v_entry_cnt, v_entries_hash, v_change_cnt, v_changes_hash, 'company_data', v_seq
  );
  INSERT INTO coherence.input_entries (input_version_id, rel_path, store_kind, file_sha256, journal_seq)
  SELECT v_iv_id, e ->> 'rel_path', 'company_data', e ->> 'file_sha256', v_seq
  FROM pg_catalog.jsonb_array_elements(v_next_entries) AS t(e);
  IF v_change_cnt > 0 THEN
    INSERT INTO coherence.input_changes (input_version_id, rel_path, change_kind, old_rel_path, store_kind, file_sha256, prev_file_sha256, journal_seq)
    SELECT v_iv_id, e ->> 'rel_path', e ->> 'change_kind', e ->> 'old_rel_path', 'company_data', e ->> 'file_sha256', e ->> 'prev_file_sha256', v_seq
    FROM pg_catalog.jsonb_array_elements(v_changes) AS t(e);
  END IF;
  INSERT INTO coherence.carries (
    id, run_id, statement_date, carry_kind, store_kind, file_sha256,
    published_input_version_id, nothing_new, typed_phrase, journal_seq
  ) VALUES (
    v_carry_id, p_run_id, v_stmt_date, 'sent', 'company_data', v_file_sha,
    v_iv_id, false, p_typed_phrase, v_seq
  );

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'carry_id', v_carry_id, 'published_input_version_id', v_iv_id);
END;
$$;

-- 7.15 carry_approvals (Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_carry_approvals(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_expected_seq BIGINT,
  p_run_id UUID,
  p_typed_phrase TEXT,
  p_carry_id UUID DEFAULT NULL,
  p_input_version_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_carry_id UUID := COALESCE(p_carry_id, pg_catalog.gen_random_uuid());
  v_iv_id UUID := COALESCE(p_input_version_id, pg_catalog.gen_random_uuid());
  v_stmt_date DATE;
  v_emit_ev UUID;
  v_file_sha TEXT;
  v_parent_id UUID;
  v_existing_ov_sha TEXT;
  v_nothing_new BOOLEAN;
  v_next_entries JSONB;
  v_changes JSONB;
  v_entry_cnt INT;
  v_change_cnt INT;
  v_entries_hash TEXT;
  v_changes_hash TEXT;
  v_iv_hash TEXT;
  v_carry_hash TEXT;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.owner.carry_approvals', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('carry_approvals', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;
  PERFORM coherence._cmd_check_expected_seq(p_expected_seq, p_run_id, true, false);

  SELECT statement_date INTO v_stmt_date FROM coherence.runs WHERE id = p_run_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'RUN_NOT_FOUND: run does not exist.' USING ERRCODE = 'P0002'; END IF;
  v_emit_ev := coherence.current_finished_attempt(p_run_id, 'emit');
  IF v_emit_ev IS NULL THEN RAISE EXCEPTION 'EMIT_NOT_FINISHED: run has not finished Emit.' USING ERRCODE = '23514'; END IF;
  SELECT file_sha256 INTO v_file_sha FROM coherence.artifacts WHERE attempt_event_id = v_emit_ev AND rel_path = 'emits/overlay.csv';
  IF v_file_sha IS NULL THEN RAISE EXCEPTION 'ARTIFACT_NOT_FOUND: emits/overlay.csv not found.' USING ERRCODE = 'P0002'; END IF;

  v_parent_id := coherence.standing_input_version_as_of(NULL);
  IF v_parent_id IS NOT NULL THEN
    SELECT file_sha256 INTO v_existing_ov_sha
    FROM coherence.input_entries
    WHERE input_version_id = v_parent_id AND mac_key = 'overlay/overlay.csv';
  END IF;
  v_nothing_new := (v_existing_ov_sha IS NOT NULL AND v_existing_ov_sha = v_file_sha);

  IF v_nothing_new THEN
    v_carry_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_carry_id::text, p_run_id::text, coherence.fmt_date(v_stmt_date),
      'approvals', v_file_sha, NULL::text, NULL::text, true, p_typed_phrase
    )) || E'\n');
    v_body := pg_catalog.jsonb_build_object(
      'result', pg_catalog.jsonb_build_object('carryId', v_carry_id, 'publishedInputVersionId', NULL, 'nothingNew', true),
      'commitments', pg_catalog.jsonb_build_object(
        'counts', pg_catalog.jsonb_build_object('carries', 1),
        'hashes', pg_catalog.jsonb_build_object('carries', v_carry_hash)
      )
    );
    v_seq := coherence._cmd_write_journals(
      v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
      v_ctx.actor_label, v_ctx.acting_for_label,
      'carry_approvals', p_command_key, p_request_sha256, v_body,
      pg_catalog.jsonb_build_object('carry_id', v_carry_id, 'run_id', p_run_id, 'nothing_new', true)
    );
    INSERT INTO coherence.carries (
      id, run_id, statement_date, carry_kind, store_kind, file_sha256,
      published_input_version_id, nothing_new, typed_phrase, journal_seq
    ) VALUES (
      v_carry_id, p_run_id, v_stmt_date, 'approvals', 'company_data', v_file_sha,
      NULL, true, p_typed_phrase, v_seq
    );
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;
    RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'carry_id', v_carry_id, 'nothing_new', true);
  END IF;

  SELECT COALESCE(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('rel_path', rel_path, 'file_sha256', file_sha256)),
    '[]'::jsonb
  ) || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object('rel_path', 'Overlay/overlay.csv', 'file_sha256', v_file_sha))
  INTO v_next_entries
  FROM coherence.input_entries
  WHERE input_version_id = v_parent_id AND mac_key <> 'overlay/overlay.csv';

  v_changes := CASE
    WHEN v_parent_id IS NOT NULL AND v_existing_ov_sha IS NOT NULL THEN pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
      'change_kind', 'replaced', 'rel_path', 'Overlay/overlay.csv', 'old_rel_path', NULL, 'file_sha256', v_file_sha, 'prev_file_sha256', v_existing_ov_sha
    ))
    WHEN v_parent_id IS NOT NULL THEN pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
      'change_kind', 'added', 'rel_path', 'Overlay/overlay.csv', 'old_rel_path', NULL, 'file_sha256', v_file_sha, 'prev_file_sha256', NULL
    ))
    ELSE '[]'::jsonb
  END;
  v_entry_cnt := pg_catalog.jsonb_array_length(v_next_entries);
  v_change_cnt := pg_catalog.jsonb_array_length(v_changes);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(e ->> 'rel_path', e ->> 'file_sha256')) || E'\n',
    '' ORDER BY (e ->> 'rel_path') COLLATE "C"
  ), '')) INTO v_entries_hash FROM pg_catalog.jsonb_array_elements(v_next_entries) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      e ->> 'change_kind', e ->> 'rel_path', e ->> 'old_rel_path', e ->> 'file_sha256', e ->> 'prev_file_sha256'
    )) || E'\n',
    '' ORDER BY (e ->> 'rel_path') COLLATE "C"
  ), '')) INTO v_changes_hash FROM pg_catalog.jsonb_array_elements(v_changes) AS t(e);

  v_iv_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_iv_id::text, 'standing', v_parent_id::text, 'carry_approvals',
    'Carry approvals from ' || coherence.fmt_date(v_stmt_date) || ' run',
    v_entry_cnt, v_entries_hash, NULL::text, v_change_cnt, v_changes_hash
  )) || E'\n');
  v_carry_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_carry_id::text, p_run_id::text, coherence.fmt_date(v_stmt_date),
    'approvals', v_file_sha, NULL::text, v_iv_id::text, false, p_typed_phrase
  )) || E'\n');

  v_counts := pg_catalog.jsonb_build_object('input_versions', 1, 'input_entries', v_entry_cnt, 'carries', 1);
  v_hashes := pg_catalog.jsonb_build_object('input_versions', v_iv_hash, 'input_entries', v_entries_hash, 'carries', v_carry_hash);
  IF v_change_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('input_changes', v_change_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('input_changes', v_changes_hash);
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('carryId', v_carry_id, 'publishedInputVersionId', v_iv_id, 'nothingNew', false),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'carry_approvals', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('carry_id', v_carry_id, 'run_id', p_run_id, 'nothing_new', false)
  );
  INSERT INTO coherence.input_versions (
    id, line_kind, parent_id, source_kind, reason,
    entry_count, entries_sha256, change_count, changes_sha256, store_kind, journal_seq
  ) VALUES (
    v_iv_id, 'standing', v_parent_id, 'carry_approvals',
    'Carry approvals from ' || coherence.fmt_date(v_stmt_date) || ' run',
    v_entry_cnt, v_entries_hash, v_change_cnt, v_changes_hash, 'company_data', v_seq
  );
  INSERT INTO coherence.input_entries (input_version_id, rel_path, store_kind, file_sha256, journal_seq)
  SELECT v_iv_id, e ->> 'rel_path', 'company_data', e ->> 'file_sha256', v_seq
  FROM pg_catalog.jsonb_array_elements(v_next_entries) AS t(e);
  IF v_change_cnt > 0 THEN
    INSERT INTO coherence.input_changes (input_version_id, rel_path, change_kind, old_rel_path, store_kind, file_sha256, prev_file_sha256, journal_seq)
    SELECT v_iv_id, e ->> 'rel_path', e ->> 'change_kind', e ->> 'old_rel_path', 'company_data', e ->> 'file_sha256', e ->> 'prev_file_sha256', v_seq
    FROM pg_catalog.jsonb_array_elements(v_changes) AS t(e);
  END IF;
  INSERT INTO coherence.carries (
    id, run_id, statement_date, carry_kind, store_kind, file_sha256,
    published_input_version_id, nothing_new, typed_phrase, journal_seq
  ) VALUES (
    v_carry_id, p_run_id, v_stmt_date, 'approvals', 'company_data', v_file_sha,
    v_iv_id, false, p_typed_phrase, v_seq
  );

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'carry_id', v_carry_id, 'published_input_version_id', v_iv_id, 'nothing_new', false);
END;
$$;

-- 7.16 carry_decisions (Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_carry_decisions(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_expected_seq BIGINT,
  p_run_id UUID,
  p_typed_phrase TEXT,
  p_receipt_file_sha256 TEXT DEFAULT NULL,
  p_carry_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_carry_id UUID := COALESCE(p_carry_id, pg_catalog.gen_random_uuid());
  v_stmt_date DATE;
  v_prior_dc UUID;
  v_carried_dc UUID;
  v_standing_head UUID;
  v_nothing_new BOOLEAN;
  v_carry_hash TEXT;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.owner.carry_decisions', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('carry_decisions', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;
  PERFORM coherence._cmd_check_expected_seq(p_expected_seq, p_run_id, false, false);

  SELECT statement_date, prior_decision_commit_id INTO v_stmt_date, v_prior_dc FROM coherence.runs WHERE id = p_run_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'RUN_NOT_FOUND: run does not exist.' USING ERRCODE = 'P0002'; END IF;

  SELECT decision_commit_id INTO v_carried_dc
  FROM coherence.review_saves
  WHERE run_id = p_run_id AND surface = 'adjust'
    AND attempt_event_id = coherence.current_finished_attempt(p_run_id, 'adjust')
    AND decision_commit_id IS NOT NULL
  ORDER BY journal_seq DESC LIMIT 1;

  IF v_carried_dc IS NULL THEN
    SELECT decision_commit_id INTO v_carried_dc
    FROM coherence.review_saves
    WHERE run_id = p_run_id AND surface = 'bible'
      AND attempt_event_id = coherence.current_finished_attempt(p_run_id, 'bible')
      AND decision_commit_id IS NOT NULL
    ORDER BY journal_seq DESC LIMIT 1;
  END IF;
  v_carried_dc := COALESCE(v_carried_dc, v_prior_dc);
  IF v_carried_dc IS NULL THEN
    RAISE EXCEPTION 'MISSING_DECISION_COMMIT: run has no decision commit to carry.' USING ERRCODE = '23514';
  END IF;

  v_standing_head := coherence.standing_decision_head_as_of(NULL);
  v_nothing_new := (v_standing_head IS NOT NULL AND v_standing_head = v_carried_dc);

  v_carry_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_carry_id::text, p_run_id::text, coherence.fmt_date(v_stmt_date),
    'decisions', p_receipt_file_sha256, v_carried_dc::text, NULL::text, v_nothing_new, p_typed_phrase
  )) || E'\n');
  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('carryId', v_carry_id, 'carriedDecisionCommitId', v_carried_dc, 'nothingNew', v_nothing_new),
    'commitments', pg_catalog.jsonb_build_object(
      'counts', pg_catalog.jsonb_build_object('carries', 1),
      'hashes', pg_catalog.jsonb_build_object('carries', v_carry_hash)
    )
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'carry_decisions', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('carry_id', v_carry_id, 'run_id', p_run_id, 'carried_decision_commit_id', v_carried_dc)
  );
  INSERT INTO coherence.carries (
    id, run_id, statement_date, carry_kind, store_kind, file_sha256,
    carried_decision_commit_id, published_input_version_id, nothing_new, typed_phrase, journal_seq
  ) VALUES (
    v_carry_id, p_run_id, v_stmt_date, 'decisions',
    CASE WHEN p_receipt_file_sha256 IS NOT NULL THEN 'company_data' ELSE NULL END,
    p_receipt_file_sha256, v_carried_dc, NULL, v_nothing_new, p_typed_phrase, v_seq
  );

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'carry_id', v_carry_id, 'carried_decision_commit_id', v_carried_dc, 'nothing_new', v_nothing_new);
END;
$$;

-- 7.17 abandon_run (Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_abandon_run(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_expected_seq BIGINT,
  p_run_id UUID,
  p_typed_phrase TEXT,
  p_reason TEXT,
  p_abandonment_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_ab_id UUID := COALESCE(p_abandonment_id, pg_catalog.gen_random_uuid());
  v_hash TEXT;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.owner.abandon_run', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('abandon_run', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;
  PERFORM coherence._cmd_check_expected_seq(p_expected_seq, p_run_id, false, false);

  v_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_ab_id::text, p_run_id::text, p_typed_phrase, p_reason
  )) || E'\n');
  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('abandonmentId', v_ab_id, 'runId', p_run_id, 'abandoned', true),
    'commitments', pg_catalog.jsonb_build_object(
      'counts', pg_catalog.jsonb_build_object('abandonments', 1),
      'hashes', pg_catalog.jsonb_build_object('abandonments', v_hash)
    )
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'abandon_run', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('abandonment_id', v_ab_id, 'run_id', p_run_id)
  );
  INSERT INTO coherence.abandonments (id, run_id, typed_phrase, reason, journal_seq)
  VALUES (v_ab_id, p_run_id, p_typed_phrase, p_reason, v_seq);

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'abandonment_id', v_ab_id, 'run_id', p_run_id);
END;
$$;

-- 7.18 record_decision_baseline (Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_record_decision_baseline(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_payload JSONB
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_dc_id UUID := COALESCE((p_payload ->> 'decision_commit_id')::uuid, pg_catalog.gen_random_uuid());
  v_parent_id UUID := (p_payload ->> 'parent_commit_id')::uuid;
  v_kind TEXT := COALESCE(p_payload ->> 'commit_kind', 'historical_baseline');
  v_hc TEXT := COALESCE(p_payload ->> 'header_contract', 'v2');
  v_imp BOOLEAN := COALESCE((p_payload ->> 'imported')::boolean, true);
  v_orig TIMESTAMPTZ := (p_payload ->> 'original_at')::timestamptz;
  v_parent_cum INT := 0;
  v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
  v_elem JSONB;
  v_ord INT := 0;
  v_rows JSONB := '[]'::jsonb;
  v_head_map JSONB := '{}'::jsonb;
  v_dec_id UUID;
  v_rec_id TEXT;
  v_prev_id UUID;
  v_dec_at TIMESTAMPTZ;
  v_added_hash TEXT;
  v_table_hash TEXT;
  v_dc_hash TEXT;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.owner.record_baseline', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('record_decision_baseline', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  IF v_parent_id IS NOT NULL THEN
    SELECT cumulative_decision_count INTO v_parent_cum FROM coherence.decision_commits WHERE id = v_parent_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'DECISION_COMMIT_NOT_FOUND: parent commit does not exist.' USING ERRCODE = 'P0002'; END IF;
    SELECT COALESCE(pg_catalog.jsonb_object_agg(record_id, id::text), '{}'::jsonb)
    INTO v_head_map
    FROM coherence.decisions_current(v_parent_id);
  END IF;

  WITH input_rows AS MATERIALIZED (
    SELECT
      ord::int AS row_order,
      COALESCE((elem ->> 'id')::uuid, pg_catalog.gen_random_uuid()) AS dec_id,
      elem ->> 'record_id' AS rec_id,
      COALESCE((elem ->> 'decided_at')::timestamptz, v_orig, v_now) AS dec_at,
      elem
    FROM pg_catalog.jsonb_array_elements(coherence._cmd_jsonb_array(p_payload -> 'decisions'))
         WITH ORDINALITY AS t(elem, ord)
  ),
  chained AS (
    SELECT
      ir.*,
      COALESCE(
        pg_catalog.lag(ir.dec_id) OVER (PARTITION BY ir.rec_id ORDER BY ir.row_order),
        (v_head_map ->> ir.rec_id)::uuid
      ) AS prev_id
    FROM input_rows ir
  )
  SELECT
    pg_catalog.count(*)::int,
    COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'id', c.dec_id, 'row_order', c.row_order,
      'run_id', c.elem ->> 'run_id', 'surface', c.elem ->> 'surface',
      'record_id', c.rec_id, 'replaces_decision_id', c.prev_id,
      'disposition', COALESCE(c.elem ->> 'disposition', 'CONFIRM'),
      'agent', c.elem ->> 'agent', 'agency', c.elem ->> 'agency',
      'policy', c.elem ->> 'policy', 'book', c.elem ->> 'book',
      'month', c.elem ->> 'month', 'status', c.elem ->> 'status', 'note', c.elem ->> 'note',
      'approved_amount', CASE WHEN v_hc = 'v1' THEN NULL ELSE c.elem ->> 'approved_amount' END,
      'approved_agency', CASE WHEN v_hc = 'v1' THEN NULL ELSE c.elem ->> 'approved_agency' END,
      'approved_agent', CASE WHEN v_hc = 'v1' THEN NULL ELSE c.elem ->> 'approved_agent' END,
      'approved_agency_from', CASE WHEN v_hc = 'v1' THEN NULL ELSE c.elem ->> 'approved_agency_from' END,
      'approved_agent_from', CASE WHEN v_hc = 'v1' THEN NULL ELSE c.elem ->> 'approved_agent_from' END,
      'decided_by', CASE
        WHEN v_imp
         AND NULLIF(pg_catalog.btrim(c.elem ->> 'decided_by'), '') IS NOT NULL
         AND pg_catalog.btrim(c.elem ->> 'decided_by') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          THEN pg_catalog.btrim(c.elem ->> 'decided_by')
        ELSE v_ctx.actor_label
      END,
      'acting_for', CASE
        WHEN v_imp
         AND NULLIF(pg_catalog.btrim(c.elem ->> 'decided_by'), '') IS NOT NULL
         AND pg_catalog.btrim(c.elem ->> 'decided_by') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          THEN NULLIF(pg_catalog.btrim(c.elem ->> 'acting_for'), '')
        ELSE v_ctx.acting_for_label
      END,
      'decided_at', coherence.format_utc_us(c.dec_at),
      'committed_at_raw', c.elem ->> 'committed_at_raw',
      'imported', v_imp
    ) ORDER BY c.row_order), '[]'::jsonb)
  INTO v_ord, v_rows
  FROM chained c;

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      e ->> 'id', (e ->> 'row_order')::int, e ->> 'run_id', NULL::text, e ->> 'surface',
      e ->> 'record_id', e ->> 'replaces_decision_id', e ->> 'disposition',
      e ->> 'agent', e ->> 'agency', e ->> 'policy', e ->> 'book', e ->> 'month', e ->> 'status', e ->> 'note',
      e ->> 'approved_amount', e ->> 'approved_agency', e ->> 'approved_agent',
      e ->> 'approved_agency_from', e ->> 'approved_agent_from',
      e ->> 'decided_by', e ->> 'acting_for', e ->> 'decided_at', e ->> 'committed_at_raw', (e ->> 'imported')::boolean
    )) || E'\n',
    '' ORDER BY (e ->> 'row_order')::int ASC
  ), '')) INTO v_added_hash FROM pg_catalog.jsonb_array_elements(v_rows) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_dc_id::text, e ->> 'id', (e ->> 'row_order')::int, e ->> 'run_id', NULL::text, e ->> 'surface',
      e ->> 'record_id', e ->> 'replaces_decision_id', e ->> 'disposition',
      e ->> 'agent', e ->> 'agency', e ->> 'policy', e ->> 'book', e ->> 'month', e ->> 'status', e ->> 'note',
      e ->> 'approved_amount', e ->> 'approved_agency', e ->> 'approved_agent',
      e ->> 'approved_agency_from', e ->> 'approved_agent_from',
      e ->> 'decided_by', e ->> 'acting_for', e ->> 'decided_at', e ->> 'committed_at_raw', (e ->> 'imported')::boolean
    )) || E'\n',
    '' ORDER BY (e ->> 'row_order')::int ASC
  ), '')) INTO v_table_hash FROM pg_catalog.jsonb_array_elements(v_rows) AS t(e);

  v_dc_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_dc_id::text, v_parent_id::text, v_kind, v_hc,
    v_ord, v_parent_cum + v_ord, v_added_hash, v_imp,
    CASE WHEN v_orig IS NULL THEN NULL ELSE coherence.format_utc_us(v_orig) END
  )) || E'\n');

  v_counts := pg_catalog.jsonb_build_object('decision_commits', 1);
  v_hashes := pg_catalog.jsonb_build_object('decision_commits', v_dc_hash);
  IF v_ord > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('decisions', v_ord);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('decisions', v_table_hash);
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('decisionCommitId', v_dc_id, 'addedDecisionCount', v_ord, 'cumulativeDecisionCount', v_parent_cum + v_ord),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'record_decision_baseline', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('decision_commit_id', v_dc_id, 'added_count', v_ord)
  );

  INSERT INTO coherence.decision_commits (
    id, parent_commit_id, commit_kind, header_contract,
    added_decision_count, cumulative_decision_count, added_decisions_sha256,
    imported, original_at, journal_seq
  ) VALUES (
    v_dc_id, v_parent_id, v_kind, v_hc,
    v_ord, v_parent_cum + v_ord, v_added_hash, v_imp, v_orig, v_seq
  );
  IF v_ord > 0 THEN
    INSERT INTO coherence.decisions (
      id, decision_commit_id, row_order, run_id, review_save_id, surface, record_id,
      replaces_decision_id, disposition, agent, agency, policy, book, month, status, note,
      approved_amount, approved_agency, approved_agent, approved_agency_from, approved_agent_from,
      decided_by, acting_for, decided_at, committed_at_raw, imported, journal_seq
    )
    SELECT
      (e ->> 'id')::uuid, v_dc_id, (e ->> 'row_order')::int, (e ->> 'run_id')::uuid, NULL, e ->> 'surface',
      e ->> 'record_id', (e ->> 'replaces_decision_id')::uuid, e ->> 'disposition',
      e ->> 'agent', e ->> 'agency', e ->> 'policy', e ->> 'book', e ->> 'month', e ->> 'status', e ->> 'note',
      e ->> 'approved_amount', e ->> 'approved_agency', e ->> 'approved_agent',
      e ->> 'approved_agency_from', e ->> 'approved_agent_from',
      e ->> 'decided_by', e ->> 'acting_for', (e ->> 'decided_at')::timestamptz,
      e ->> 'committed_at_raw', (e ->> 'imported')::boolean, v_seq
    FROM pg_catalog.jsonb_array_elements(v_rows) AS t(e);
  END IF;

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object(
    'idempotent', false, 'journal_seq', v_seq,
    'decision_commit_id', v_dc_id, 'added_count', v_ord, 'cumulative_count', v_parent_cum + v_ord
  );
END;
$$;

-- 7.19 record_statement_batch (Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_record_statement_batch(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_payload JSONB
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_batch_id UUID := COALESCE((p_payload ->> 'batch_id')::uuid, pg_catalog.gen_random_uuid());
  v_kind TEXT := p_payload ->> 'batch_kind';
  v_stmt_date DATE := (p_payload ->> 'statement_date')::date;
  v_src_name TEXT := p_payload ->> 'source_file_name';
  v_src_file JSONB := p_payload -> 'source_file';
  v_src_sha TEXT := CASE WHEN v_src_file IS NOT NULL AND pg_catalog.jsonb_typeof(v_src_file) = 'object' THEN v_src_file ->> 'sha256' ELSE NULL END;
  v_reason TEXT := p_payload ->> 'reason';
  v_ag_in JSONB := coherence._cmd_jsonb_array(p_payload -> 'agency_lines');
  v_up_in JSONB := coherence._cmd_jsonb_array(p_payload -> 'upline_lines');
  v_ag_norm JSONB := '[]'::jsonb;
  v_up_norm JSONB := '[]'::jsonb;
  v_ag_cnt INT;
  v_up_cnt INT;
  v_ag_net NUMERIC(14,2) := 0.00;
  v_up_net NUMERIC(14,2) := 0.00;
  v_ag_hash TEXT;
  v_up_hash TEXT;
  v_ag_tbl_hash TEXT;
  v_up_tbl_hash TEXT;
  v_batch_hash TEXT;
  v_new_files JSONB;
  v_file_cnt INT;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.owner.record_statement_batch', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('record_statement_batch', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  IF v_kind NOT IN ('historical_sent', 'method_correction') THEN
    RAISE EXCEPTION 'INVALID_BATCH_KIND: standalone statement batch must be historical_sent or method_correction.' USING ERRCODE = '22023';
  END IF;

  PERFORM coherence._cmd_assert_tenant_orgs(v_ag_in, 'statement_agency_lines');
  PERFORM coherence._cmd_assert_tenant_orgs(v_up_in, 'statement_upline_lines');

  SELECT
    COALESCE(pg_catalog.sum((v_elem ->> 'amount')::numeric(14,2)), 0.00)::numeric(14,2),
    COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'line_no', COALESCE((v_elem ->> 'line_no')::int, ord::int),
      'entry_kind', COALESCE(v_elem ->> 'entry_kind', CASE WHEN v_kind = 'method_correction' THEN 'method_correction' ELSE 'historical_sent' END),
      'run_action', COALESCE(v_elem ->> 'run_action', CASE WHEN v_kind = 'method_correction' THEN 'CORRECTION' ELSE 'SENT' END),
      'entity', v_elem ->> 'entity',
      'organization_id', v_elem ->> 'organization_id',
      'writing_npn', v_elem ->> 'writing_npn',
      'writing_person_id', v_elem ->> 'writing_person_id',
      'writing_agent', v_elem ->> 'writing_agent',
      'record_id', v_elem ->> 'record_id',
      'reversal_of', v_elem ->> 'reversal_of',
      'corrects_record_id', v_elem ->> 'corrects_record_id',
      'source_file', COALESCE(v_elem ->> 'source_file', v_src_name, v_kind || '_' || coherence.fmt_date(v_stmt_date)),
      'sheet_name', v_elem ->> 'sheet_name',
      'source_row_no', COALESCE((v_elem ->> 'source_row_no')::int, ord::int),
      'src_type', v_elem ->> 'src_type', 'carrier', v_elem ->> 'carrier',
      'mbi', v_elem ->> 'mbi', 'member', v_elem ->> 'member',
      'external_policy_id', v_elem ->> 'external_policy_id',
      'policy_id', (v_elem ->> 'policy_id')::int, 'tx_id', (v_elem ->> 'tx_id')::int,
      'plan_type', v_elem ->> 'plan_type', 'simple_plan_type', v_elem ->> 'simple_plan_type', 'state', v_elem ->> 'state',
      'submission_date', v_elem ->> 'submission_date', 'origin_effective', v_elem ->> 'origin_effective',
      'effective_date', v_elem ->> 'effective_date', 'termination_date', v_elem ->> 'termination_date',
      'earned_date', v_elem ->> 'earned_date', 'payment_date', v_elem ->> 'payment_date',
      'posted_statement_date', v_elem ->> 'posted_statement_date', 'revenue_type', v_elem ->> 'revenue_type',
      'gross_comm', coherence.fmt_num2(COALESCE((v_elem ->> 'gross_comm')::numeric(14,2), (v_elem ->> 'amount')::numeric(14,2))),
      'amount', coherence.fmt_num2((v_elem ->> 'amount')::numeric(14,2)),
      'reason', v_elem ->> 'reason', 'notes', v_elem ->> 'notes'
    ) ORDER BY ord), '[]'::jsonb)
  INTO v_ag_net, v_ag_norm
  FROM pg_catalog.jsonb_array_elements(v_ag_in) WITH ORDINALITY AS t(v_elem, ord);

  SELECT
    COALESCE(pg_catalog.sum((v_elem ->> 'amount')::numeric(14,2)), 0.00)::numeric(14,2),
    COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'line_no', COALESCE((v_elem ->> 'line_no')::int, ord::int),
      'entry_kind', COALESCE(v_elem ->> 'entry_kind', CASE WHEN v_kind = 'method_correction' THEN 'method_correction' ELSE 'historical_upline_derived' END),
      'run_action', COALESCE(v_elem ->> 'run_action', CASE WHEN v_kind = 'method_correction' THEN 'CORRECTION' ELSE 'SENT' END),
      'source_entity', COALESCE(v_elem ->> 'source_entity', v_elem ->> 'entity'),
      'organization_id', v_elem ->> 'organization_id',
      'marked_sent', COALESCE((v_elem ->> 'marked_sent')::boolean, false),
      'writing_npn', v_elem ->> 'writing_npn',
      'writing_person_id', v_elem ->> 'writing_person_id',
      'writing_agent', v_elem ->> 'writing_agent',
      'record_id', v_elem ->> 'record_id',
      'reversal_of', v_elem ->> 'reversal_of',
      'corrects_record_id', v_elem ->> 'corrects_record_id',
      'source_file', COALESCE(v_elem ->> 'source_file', v_src_name, v_kind || '_' || coherence.fmt_date(v_stmt_date)),
      'sheet_name', v_elem ->> 'sheet_name',
      'source_row_no', COALESCE((v_elem ->> 'source_row_no')::int, ord::int),
      'src_type', v_elem ->> 'src_type', 'carrier', v_elem ->> 'carrier',
      'mbi', v_elem ->> 'mbi', 'member', v_elem ->> 'member',
      'external_policy_id', v_elem ->> 'external_policy_id',
      'policy_id', (v_elem ->> 'policy_id')::int, 'tx_id', (v_elem ->> 'tx_id')::int,
      'plan_type', v_elem ->> 'plan_type', 'simple_plan_type', v_elem ->> 'simple_plan_type', 'state', v_elem ->> 'state',
      'submission_date', v_elem ->> 'submission_date', 'origin_effective', v_elem ->> 'origin_effective',
      'effective_date', v_elem ->> 'effective_date', 'termination_date', v_elem ->> 'termination_date',
      'earned_date', v_elem ->> 'earned_date', 'payment_date', v_elem ->> 'payment_date',
      'posted_statement_date', v_elem ->> 'posted_statement_date', 'revenue_type', v_elem ->> 'revenue_type',
      'gross_comm', coherence.fmt_num2(COALESCE((v_elem ->> 'gross_comm')::numeric(14,2), (v_elem ->> 'amount')::numeric(14,2))),
      'amount', coherence.fmt_num2((v_elem ->> 'amount')::numeric(14,2)),
      'reason', v_elem ->> 'reason', 'notes', v_elem ->> 'notes'
    ) ORDER BY ord), '[]'::jsonb)
  INTO v_up_net, v_up_norm
  FROM pg_catalog.jsonb_array_elements(v_up_in) WITH ORDINALITY AS t(v_elem, ord);

  v_ag_cnt := pg_catalog.jsonb_array_length(v_ag_norm);
  v_up_cnt := pg_catalog.jsonb_array_length(v_up_norm);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      (e ->> 'line_no')::int, coherence.fmt_date(v_stmt_date), e ->> 'entry_kind', e ->> 'run_action',
      e ->> 'entity', e ->> 'writing_npn', e ->> 'writing_agent', e ->> 'record_id', e ->> 'reversal_of', e ->> 'corrects_record_id',
      e ->> 'source_file', e ->> 'sheet_name', (e ->> 'source_row_no')::int, e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member',
      e ->> 'external_policy_id', (e ->> 'policy_id')::int, (e ->> 'tx_id')::int, e ->> 'plan_type', e ->> 'simple_plan_type', e ->> 'state',
      coherence.fmt_date((e ->> 'submission_date')::date), coherence.fmt_date((e ->> 'origin_effective')::date),
      coherence.fmt_date((e ->> 'effective_date')::date), coherence.fmt_date((e ->> 'termination_date')::date),
      coherence.fmt_date((e ->> 'earned_date')::date), coherence.fmt_date((e ->> 'payment_date')::date),
      coherence.fmt_date((e ->> 'posted_statement_date')::date), e ->> 'revenue_type',
      e ->> 'gross_comm', e ->> 'amount', e ->> 'reason', e ->> 'notes'
    )) || E'\n',
    '' ORDER BY (e ->> 'line_no')::int ASC
  ), '')) INTO v_ag_hash FROM pg_catalog.jsonb_array_elements(v_ag_norm) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_batch_id::text, (e ->> 'line_no')::int, coherence.fmt_date(v_stmt_date), e ->> 'entry_kind', e ->> 'run_action',
      e ->> 'entity', e ->> 'writing_npn', e ->> 'writing_agent', e ->> 'record_id', e ->> 'reversal_of', e ->> 'corrects_record_id',
      e ->> 'source_file', e ->> 'sheet_name', (e ->> 'source_row_no')::int, e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member',
      e ->> 'external_policy_id', (e ->> 'policy_id')::int, (e ->> 'tx_id')::int, e ->> 'plan_type', e ->> 'simple_plan_type', e ->> 'state',
      coherence.fmt_date((e ->> 'submission_date')::date), coherence.fmt_date((e ->> 'origin_effective')::date),
      coherence.fmt_date((e ->> 'effective_date')::date), coherence.fmt_date((e ->> 'termination_date')::date),
      coherence.fmt_date((e ->> 'earned_date')::date), coherence.fmt_date((e ->> 'payment_date')::date),
      coherence.fmt_date((e ->> 'posted_statement_date')::date), e ->> 'revenue_type',
      e ->> 'gross_comm', e ->> 'amount', e ->> 'reason', e ->> 'notes'
    )) || E'\n',
    '' ORDER BY (e ->> 'line_no')::int ASC
  ), '')) INTO v_ag_tbl_hash FROM pg_catalog.jsonb_array_elements(v_ag_norm) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      (e ->> 'line_no')::int, coherence.fmt_date(v_stmt_date), e ->> 'entry_kind', e ->> 'run_action',
      e ->> 'source_entity', (e ->> 'marked_sent')::boolean, e ->> 'writing_npn', e ->> 'writing_agent', e ->> 'record_id',
      e ->> 'reversal_of', e ->> 'corrects_record_id', e ->> 'source_file', e ->> 'sheet_name', (e ->> 'source_row_no')::int,
      e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member',
      e ->> 'external_policy_id', (e ->> 'policy_id')::int, (e ->> 'tx_id')::int, e ->> 'plan_type', e ->> 'simple_plan_type', e ->> 'state',
      coherence.fmt_date((e ->> 'submission_date')::date), coherence.fmt_date((e ->> 'origin_effective')::date),
      coherence.fmt_date((e ->> 'effective_date')::date), coherence.fmt_date((e ->> 'termination_date')::date),
      coherence.fmt_date((e ->> 'earned_date')::date), coherence.fmt_date((e ->> 'payment_date')::date),
      coherence.fmt_date((e ->> 'posted_statement_date')::date), e ->> 'revenue_type',
      e ->> 'gross_comm', e ->> 'amount', e ->> 'reason', e ->> 'notes'
    )) || E'\n',
    '' ORDER BY (e ->> 'line_no')::int ASC
  ), '')) INTO v_up_hash FROM pg_catalog.jsonb_array_elements(v_up_norm) AS t(e);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_batch_id::text, (e ->> 'line_no')::int, coherence.fmt_date(v_stmt_date), e ->> 'entry_kind', e ->> 'run_action',
      e ->> 'source_entity', (e ->> 'marked_sent')::boolean, e ->> 'writing_npn', e ->> 'writing_agent', e ->> 'record_id',
      e ->> 'reversal_of', e ->> 'corrects_record_id', e ->> 'source_file', e ->> 'sheet_name', (e ->> 'source_row_no')::int,
      e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member',
      e ->> 'external_policy_id', (e ->> 'policy_id')::int, (e ->> 'tx_id')::int, e ->> 'plan_type', e ->> 'simple_plan_type', e ->> 'state',
      coherence.fmt_date((e ->> 'submission_date')::date), coherence.fmt_date((e ->> 'origin_effective')::date),
      coherence.fmt_date((e ->> 'effective_date')::date), coherence.fmt_date((e ->> 'termination_date')::date),
      coherence.fmt_date((e ->> 'earned_date')::date), coherence.fmt_date((e ->> 'payment_date')::date),
      coherence.fmt_date((e ->> 'posted_statement_date')::date), e ->> 'revenue_type',
      e ->> 'gross_comm', e ->> 'amount', e ->> 'reason', e ->> 'notes'
    )) || E'\n',
    '' ORDER BY (e ->> 'line_no')::int ASC
  ), '')) INTO v_up_tbl_hash FROM pg_catalog.jsonb_array_elements(v_up_norm) AS t(e);

  v_batch_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_batch_id::text, v_kind, coherence.fmt_date(v_stmt_date), NULL::text, NULL::text,
    v_src_name, v_src_sha, v_reason,
    v_ag_cnt, v_ag_hash, coherence.fmt_num2(v_ag_net),
    v_up_cnt, v_up_hash, coherence.fmt_num2(v_up_net)
  )) || E'\n');

  v_new_files := CASE
    WHEN v_src_file IS NOT NULL AND pg_catalog.jsonb_typeof(v_src_file) = 'object'
      THEN coherence._cmd_filter_new_stored_files(pg_catalog.jsonb_build_array(v_src_file), 'company_data')
    ELSE '[]'::jsonb
  END;
  v_file_cnt := pg_catalog.jsonb_array_length(v_new_files);

  v_counts := pg_catalog.jsonb_build_object('statement_batches', 1);
  v_hashes := pg_catalog.jsonb_build_object('statement_batches', v_batch_hash);
  IF v_file_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('stored_files', v_file_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('stored_files', coherence._cmd_hash_stored_files_json(v_new_files));
  END IF;
  IF v_ag_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('statement_agency_lines', v_ag_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('statement_agency_lines', v_ag_tbl_hash);
  END IF;
  IF v_up_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('statement_upline_lines', v_up_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('statement_upline_lines', v_up_tbl_hash);
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('batchId', v_batch_id, 'agencyLineCount', v_ag_cnt, 'uplineLineCount', v_up_cnt),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'record_statement_batch', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('batch_id', v_batch_id, 'batch_kind', v_kind, 'agency_line_count', v_ag_cnt, 'upline_line_count', v_up_cnt)
  );
  PERFORM coherence._cmd_insert_stored_files_json(v_new_files, v_seq);

  INSERT INTO coherence.statement_batches (
    id, batch_kind, statement_date, run_id, attempt_event_id,
    source_file_name, source_store_kind, source_file_sha256, reason,
    agency_line_count, agency_lines_sha256, agency_net_total,
    upline_line_count, upline_lines_sha256, upline_net_total, journal_seq
  ) VALUES (
    v_batch_id, v_kind, v_stmt_date, NULL, NULL,
    v_src_name, CASE WHEN v_src_sha IS NOT NULL THEN 'company_data' ELSE NULL END, v_src_sha, v_reason,
    v_ag_cnt, v_ag_hash, v_ag_net,
    v_up_cnt, v_up_hash, v_up_net, v_seq
  );

  IF v_ag_cnt > 0 THEN
    INSERT INTO coherence.statement_agency_lines (
      batch_id, line_no, statement_date, entry_kind, run_action, entity,
      organization_id, writing_npn, writing_person_id, writing_agent,
      record_id, reversal_of, corrects_record_id, source_file, sheet_name, source_row_no,
      src_type, carrier, mbi, member, external_policy_id, policy_id, tx_id,
      plan_type, simple_plan_type, state, submission_date, origin_effective, effective_date, termination_date,
      earned_date, payment_date, posted_statement_date, revenue_type, gross_comm, amount, reason, notes, journal_seq
    )
    SELECT
      v_batch_id, (e ->> 'line_no')::int, v_stmt_date, e ->> 'entry_kind', e ->> 'run_action', e ->> 'entity',
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'organization_id'), '')::uuid, coherence._resolve_entity_org_id(e ->> 'entity', 'statement_agency_lines')),
      e ->> 'writing_npn',
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'writing_person_id'), '')::uuid, coherence._resolve_writing_person_id(e ->> 'writing_npn', 'statement_agency_lines')),
      e ->> 'writing_agent',
      e ->> 'record_id', e ->> 'reversal_of', e ->> 'corrects_record_id', e ->> 'source_file', e ->> 'sheet_name', (e ->> 'source_row_no')::int,
      e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member', e ->> 'external_policy_id', (e ->> 'policy_id')::int, (e ->> 'tx_id')::int,
      e ->> 'plan_type', e ->> 'simple_plan_type', e ->> 'state', (e ->> 'submission_date')::date, (e ->> 'origin_effective')::date,
      (e ->> 'effective_date')::date, (e ->> 'termination_date')::date, (e ->> 'earned_date')::date, (e ->> 'payment_date')::date,
      (e ->> 'posted_statement_date')::date, e ->> 'revenue_type', (e ->> 'gross_comm')::numeric(14,2), (e ->> 'amount')::numeric(14,2),
      e ->> 'reason', e ->> 'notes', v_seq
    FROM pg_catalog.jsonb_array_elements(v_ag_norm) AS t(e);
  END IF;

  IF v_up_cnt > 0 THEN
    INSERT INTO coherence.statement_upline_lines (
      batch_id, line_no, statement_date, entry_kind, run_action, source_entity, marked_sent,
      organization_id, writing_npn, writing_person_id, writing_agent,
      record_id, reversal_of, corrects_record_id, source_file, sheet_name, source_row_no,
      src_type, carrier, mbi, member, external_policy_id, policy_id, tx_id,
      plan_type, simple_plan_type, state, submission_date, origin_effective, effective_date, termination_date,
      earned_date, payment_date, posted_statement_date, revenue_type, gross_comm, amount, reason, notes, journal_seq
    )
    SELECT
      v_batch_id, (e ->> 'line_no')::int, v_stmt_date, e ->> 'entry_kind', e ->> 'run_action', e ->> 'source_entity', (e ->> 'marked_sent')::boolean,
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'organization_id'), '')::uuid, coherence._resolve_entity_org_id(e ->> 'source_entity', 'statement_upline_lines')),
      e ->> 'writing_npn',
      COALESCE(NULLIF(pg_catalog.btrim(e ->> 'writing_person_id'), '')::uuid, coherence._resolve_writing_person_id(e ->> 'writing_npn', 'statement_upline_lines')),
      e ->> 'writing_agent',
      e ->> 'record_id', e ->> 'reversal_of', e ->> 'corrects_record_id', e ->> 'source_file', e ->> 'sheet_name', (e ->> 'source_row_no')::int,
      e ->> 'src_type', e ->> 'carrier', e ->> 'mbi', e ->> 'member', e ->> 'external_policy_id', (e ->> 'policy_id')::int, (e ->> 'tx_id')::int,
      e ->> 'plan_type', e ->> 'simple_plan_type', e ->> 'state', (e ->> 'submission_date')::date, (e ->> 'origin_effective')::date,
      (e ->> 'effective_date')::date, (e ->> 'termination_date')::date, (e ->> 'earned_date')::date, (e ->> 'payment_date')::date,
      (e ->> 'posted_statement_date')::date, e ->> 'revenue_type', (e ->> 'gross_comm')::numeric(14,2), (e ->> 'amount')::numeric(14,2),
      e ->> 'reason', e ->> 'notes', v_seq
    FROM pg_catalog.jsonb_array_elements(v_up_norm) AS t(e);
  END IF;

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object(
    'idempotent', false, 'journal_seq', v_seq, 'batch_id', v_batch_id,
    'agency_line_count', v_ag_cnt, 'upline_line_count', v_up_cnt
  );
END;
$$;

-- 7.20 import_standalone_files (Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_import_standalone_files(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_payload JSONB
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_new_files JSONB;
  v_file_cnt INT;
  v_imp_rows JSONB := '[]'::jsonb;
  v_elem JSONB;
  v_imp_cnt INT;
  v_imp_hash TEXT;
  v_counts JSONB := '{}'::jsonb;
  v_hashes JSONB := '{}'::jsonb;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.owner.import_history', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('import_standalone_files', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  v_new_files := coherence._cmd_filter_new_stored_files(coherence._cmd_jsonb_array(p_payload -> 'stored_files'));
  v_file_cnt := pg_catalog.jsonb_array_length(v_new_files);

  SELECT COALESCE(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'id', COALESCE((elem ->> 'id')::uuid, pg_catalog.gen_random_uuid()),
      'area', elem ->> 'area',
      'rel_path', elem ->> 'rel_path',
      'artifact_kind', COALESCE(elem ->> 'artifact_kind', 'data'),
      'store_kind', COALESCE(elem ->> 'store_kind', 'company_data'),
      'file_sha256', elem ->> 'file_sha256',
      'original_at', CASE WHEN elem ->> 'original_at' IS NULL THEN NULL ELSE coherence.format_utc_us((elem ->> 'original_at')::timestamptz) END,
      'metadata', coherence._cmd_jsonb_object(elem -> 'metadata')
    ) ORDER BY ord),
    '[]'::jsonb
  ) INTO v_imp_rows
  FROM pg_catalog.jsonb_array_elements(coherence._cmd_jsonb_array(p_payload -> 'files')) WITH ORDINALITY AS t(elem, ord)
  WHERE NOT EXISTS (
    SELECT 1 FROM coherence.imported_files f
    WHERE f.area = (elem ->> 'area') AND f.rel_path = (elem ->> 'rel_path') AND f.file_sha256 = (elem ->> 'file_sha256')
  );
  v_imp_cnt := pg_catalog.jsonb_array_length(v_imp_rows);

  IF v_file_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('stored_files', v_file_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('stored_files', coherence._cmd_hash_stored_files_json(v_new_files));
  END IF;
  IF v_imp_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        e ->> 'id', e ->> 'area', e ->> 'rel_path', e ->> 'artifact_kind', e ->> 'store_kind',
        e ->> 'file_sha256', e ->> 'original_at', e -> 'metadata'
      )) || E'\n',
      '' ORDER BY (e ->> 'id') COLLATE "C"
    )) INTO v_imp_hash FROM pg_catalog.jsonb_array_elements(v_imp_rows) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('imported_files', v_imp_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('imported_files', v_imp_hash);
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('importedCount', v_imp_cnt, 'imported', v_imp_cnt),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'import_standalone_files', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('imported_count', v_imp_cnt)
  );
  PERFORM coherence._cmd_insert_stored_files_json(v_new_files, v_seq);

  IF v_imp_cnt > 0 THEN
    INSERT INTO coherence.imported_files (id, area, rel_path, artifact_kind, store_kind, file_sha256, original_at, metadata, journal_seq)
    SELECT
      (e ->> 'id')::uuid, e ->> 'area', e ->> 'rel_path', e ->> 'artifact_kind', e ->> 'store_kind',
      e ->> 'file_sha256', (e ->> 'original_at')::timestamptz, e -> 'metadata', v_seq
    FROM pg_catalog.jsonb_array_elements(v_imp_rows) AS t(e);
  END IF;

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'imported', v_imp_cnt);
END;
$$;

-- 7.21 import_historical_run (Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_import_historical_run(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_payload JSONB
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_run JSONB := p_payload -> 'run';
  v_existing_run UUID;
  v_run_id UUID := COALESCE((v_run ->> 'id')::uuid, pg_catalog.gen_random_uuid());
  v_iv_id UUID := COALESCE((p_payload -> 'input_version' ->> 'id')::uuid, pg_catalog.gen_random_uuid());
  v_origin TEXT := v_run ->> 'origin';
  v_stmt_date DATE := (v_run ->> 'statement_date')::date;
  v_folder_no INT := COALESCE((v_run ->> 'folder_number')::int, 1);
  v_emit_mode TEXT := COALESCE(v_run ->> 'emit_mode', 'coherence');
  v_emit_display TEXT := v_run ->> 'emit_display';
  v_emit_keep TEXT[] := COALESCE(ARRAY(SELECT pg_catalog.jsonb_array_elements_text(coherence._cmd_jsonb_array(v_run -> 'emit_keep'))), '{}'::text[]);
  v_emit_no_mgr TEXT[] := COALESCE(ARRAY(SELECT pg_catalog.jsonb_array_elements_text(coherence._cmd_jsonb_array(v_run -> 'emit_no_manager'))), '{}'::text[]);
  v_prior_dc UUID := (v_run ->> 'prior_decision_commit_id')::uuid;
  v_eng_id UUID := (v_run ->> 'engine_version_id')::uuid;
  v_rerun_reason TEXT := v_run ->> 'rerun_reason';
  v_src_folder TEXT := v_run ->> 'source_folder';
  v_iv_reason TEXT := COALESCE(p_payload -> 'input_version' ->> 'reason', 'Imported frozen input from ' || v_src_folder);
  v_entries JSONB := coherence._cmd_jsonb_array(p_payload -> 'input_entries');
  v_prior_ov TEXT := NULL;
  v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
  v_new_files JSONB;
  v_file_cnt INT;
  v_entry_cnt INT := pg_catalog.jsonb_array_length(v_entries);
  v_entries_hash TEXT;
  v_changes_hash TEXT := coherence.sha256_text('');
  v_iv_hash TEXT;
  v_run_hash TEXT;
  -- Child collections
  v_elem JSONB;
  v_sub_elem JSONB;
  v_af_rows JSONB := '[]'::jsonb;
  v_ar_rows JSONB := '[]'::jsonb;
  v_seen_af TEXT[] := ARRAY[]::text[];
  v_af_sha TEXT;
  v_af_shared INT;
  v_ar_idx INT;
  v_af_added JSONB;
  v_af_added_hash TEXT;
  v_af_cnt INT;
  v_ar_cnt INT;
  v_ev_rows JSONB := '[]'::jsonb;
  v_art_rows JSONB := '[]'::jsonb;
  v_fin_by_step JSONB := '{}'::jsonb;
  v_st_id UUID;
  v_fn_id UUID;
  v_st_arts JSONB;
  v_st_arts_hash TEXT;
  v_st_no INT;
  v_ev_cnt INT;
  v_art_cnt INT;
  v_rs_rows JSONB := '[]'::jsonb;
  v_rs_ids UUID[] := ARRAY[]::uuid[];
  v_rs_id UUID;
  v_rs_att UUID;
  v_rs_cnt INT;
  v_rqi_rows JSONB := '[]'::jsonb;
  v_rqi_idx INT := 0;
  v_rqi_att UUID;
  v_rqi_cnt INT;
  v_dec_rows JSONB := '[]'::jsonb;
  v_dec_cnt INT;
  v_dc_rows JSONB := '[]'::jsonb;
  v_dc_id UUID;
  v_dc_added_cnt INT;
  v_dc_added_hash TEXT;
  v_dc_cnt INT;
  v_go_rows JSONB := '[]'::jsonb;
  v_go_att UUID;
  v_go_cnt INT;
  v_imp_rows JSONB := '[]'::jsonb;
  v_imp_meta JSONB;
  v_imp_cnt INT;
  v_ab JSONB := p_payload -> 'abandonment';
  v_ab_id UUID;
  v_ab_phrase TEXT;
  v_ab_reason TEXT;
  v_hash TEXT;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.owner.import_history', 'human_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('import_historical_run', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  SELECT id INTO v_existing_run FROM coherence.runs WHERE origin = v_origin AND source_folder = v_src_folder;
  IF FOUND THEN
    v_body := pg_catalog.jsonb_build_object(
      'alreadyImported', true, 'runId', v_existing_run,
      'result', pg_catalog.jsonb_build_object('runId', v_existing_run, 'alreadyImported', true),
      'commitments', pg_catalog.jsonb_build_object('counts', '{}'::jsonb, 'hashes', '{}'::jsonb)
    );
    v_seq := coherence._cmd_write_journals(
      v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
      v_ctx.actor_label, v_ctx.acting_for_label,
      'import_historical_run', p_command_key, p_request_sha256, v_body,
      pg_catalog.jsonb_build_object('run_id', v_existing_run, 'already_imported', true)
    );
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;
    RETURN pg_catalog.jsonb_build_object('idempotent', false, 'already_imported', true, 'journal_seq', v_seq, 'run_id', v_existing_run);
  END IF;

  v_new_files := coherence._cmd_filter_new_stored_files(coherence._cmd_jsonb_array(p_payload -> 'stored_files'));
  v_file_cnt := pg_catalog.jsonb_array_length(v_new_files);

  -- Approvals files + approval_rows (set-based jsonb_agg)
  WITH dedup_af AS MATERIALIZED (
    SELECT DISTINCT ON (elem ->> 'file_sha256')
      ord AS af_ord,
      elem ->> 'file_sha256' AS af_sha,
      elem ->> 'header_kind' AS header_kind,
      (elem ->> 'row_count')::int AS row_count,
      elem ->> 'extends_sha256' AS extends_sha256,
      COALESCE((elem ->> 'shared_row_count')::int, 0) AS shared_row_count,
      coherence._cmd_jsonb_array(elem -> 'added_rows') AS added_rows
    FROM pg_catalog.jsonb_array_elements(coherence._cmd_jsonb_array(p_payload -> 'approvals_files')) WITH ORDINALITY AS t(elem, ord)
    ORDER BY elem ->> 'file_sha256', ord
  ),
  new_af AS MATERIALIZED (
    SELECT * FROM dedup_af d
    WHERE NOT EXISTS (SELECT 1 FROM coherence.approvals_files af WHERE af.file_sha256 = d.af_sha)
  ),
  ar_expanded AS MATERIALIZED (
    SELECT
      n.af_ord,
      ar_ord,
      n.af_sha,
      COALESCE((sub ->> 'row_no')::int, n.shared_row_count + ar_ord::int) AS row_no,
      pg_catalog.jsonb_build_object(
        'approvals_file_sha256', n.af_sha,
        'row_no', COALESCE((sub ->> 'row_no')::int, n.shared_row_count + ar_ord::int),
        'record_id', sub ->> 'record_id',
        'disposition', sub ->> 'disposition',
        'agent', sub ->> 'agent', 'agency', sub ->> 'agency',
        'policy', sub ->> 'policy', 'book', sub ->> 'book',
        'month', sub ->> 'month', 'status', sub ->> 'status',
        'note', sub ->> 'note', 'committed_at', sub ->> 'committed_at',
        'approved_amount', sub ->> 'approved_amount',
        'approved_agency', sub ->> 'approved_agency',
        'approved_agent', sub ->> 'approved_agent',
        'approved_agency_from', sub ->> 'approved_agency_from',
        'approved_agent_from', sub ->> 'approved_agent_from'
      ) AS row_obj,
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        COALESCE((sub ->> 'row_no')::int, n.shared_row_count + ar_ord::int),
        sub ->> 'record_id', sub ->> 'disposition', sub ->> 'agent', sub ->> 'agency',
        sub ->> 'policy', sub ->> 'book', sub ->> 'month', sub ->> 'status', sub ->> 'note', sub ->> 'committed_at',
        sub ->> 'approved_amount', sub ->> 'approved_agency', sub ->> 'approved_agent',
        sub ->> 'approved_agency_from', sub ->> 'approved_agent_from'
      )) || E'\n' AS canon_line
    FROM new_af n
    CROSS JOIN LATERAL pg_catalog.jsonb_array_elements(n.added_rows) WITH ORDINALITY AS s(sub, ar_ord)
  ),
  ar_hashes AS (
    SELECT af_sha, coherence.sha256_text(COALESCE(pg_catalog.string_agg(canon_line, '' ORDER BY row_no ASC), '')) AS added_hash
    FROM ar_expanded
    GROUP BY af_sha
  )
  SELECT
    COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'file_sha256', n.af_sha, 'header_kind', n.header_kind,
        'row_count', n.row_count, 'extends_sha256', n.extends_sha256,
        'shared_row_count', n.shared_row_count,
        'added_rows_sha256', COALESCE(h.added_hash, coherence.sha256_text(''))
      ) ORDER BY n.af_ord)
      FROM new_af n
      LEFT JOIN ar_hashes h ON h.af_sha = n.af_sha
    ), '[]'::jsonb),
    COALESCE((
      SELECT pg_catalog.jsonb_agg(e.row_obj ORDER BY e.af_ord, e.ar_ord)
      FROM ar_expanded e
    ), '[]'::jsonb)
  INTO v_af_rows, v_ar_rows;
  v_af_cnt := pg_catalog.jsonb_array_length(v_af_rows);
  v_ar_cnt := pg_catalog.jsonb_array_length(v_ar_rows);

  -- Input entries + prior overlay auto-detection
  SELECT e ->> 'file_sha256' INTO v_prior_ov
  FROM pg_catalog.jsonb_array_elements(v_entries) AS t(e)
  WHERE pg_catalog.lower(pg_catalog.normalize(e ->> 'rel_path', 'NFC')) = 'overlay/overlay.csv'
  LIMIT 1;

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(e ->> 'rel_path', e ->> 'file_sha256')) || E'\n',
    '' ORDER BY (e ->> 'rel_path') COLLATE "C"
  ), '')) INTO v_entries_hash FROM pg_catalog.jsonb_array_elements(v_entries) AS t(e);

  v_iv_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_iv_id::text, 'snapshot', NULL::text,
    CASE WHEN v_origin = 'mac_import' THEN 'mac_import' ELSE 'company_import' END,
    v_iv_reason, v_entry_cnt, v_entries_hash, NULL::text, 0, v_changes_hash
  )) || E'\n');

  v_run_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_run_id::text, coherence.fmt_date(v_stmt_date), v_folder_no, v_origin,
    v_iv_id::text, v_prior_ov, v_prior_dc::text, v_eng_id::text,
    v_emit_mode, v_emit_display, v_emit_keep, v_emit_no_mgr,
    NULL::text, NULL::text, v_rerun_reason, v_src_folder
  )) || E'\n');

  -- Step attempts (started + finished) and their artifacts (set-based jsonb_agg)
  WITH steps AS MATERIALIZED (
    SELECT
      ord AS st_ord,
      COALESCE((elem ->> 'start_event_id')::uuid, pg_catalog.gen_random_uuid()) AS st_id,
      COALESCE((elem ->> 'finish_event_id')::uuid, (elem ->> 'id')::uuid, pg_catalog.gen_random_uuid()) AS fn_id,
      elem ->> 'step' AS step,
      COALESCE((elem ->> 'attempt_no')::int, 1) AS st_no,
      elem ->> 'born' AS born,
      elem ->> 'log_file_sha256' AS log_file_sha256,
      coherence._cmd_jsonb_object(elem -> 'census') AS census,
      COALESCE(elem ->> 'started_at', elem ->> 'finished_at') AS started_at,
      elem ->> 'finished_at' AS finished_at,
      coherence._cmd_jsonb_array(elem -> 'artifacts') AS artifacts
    FROM pg_catalog.jsonb_array_elements(coherence._cmd_jsonb_array(p_payload -> 'step_attempts')) WITH ORDINALITY AS t(elem, ord)
  ),
  arts_expanded AS MATERIALIZED (
    SELECT
      s.st_ord,
      a_ord,
      s.fn_id,
      pg_catalog.jsonb_build_object(
        'attempt_event_id', s.fn_id::text,
        'rel_path', sub ->> 'rel_path',
        'artifact_kind', sub ->> 'artifact_kind',
        'store_kind', sub ->> 'store_kind',
        'file_sha256', sub ->> 'file_sha256'
      ) AS art_obj,
      sub ->> 'rel_path' AS rel_path,
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        sub ->> 'rel_path', sub ->> 'artifact_kind', sub ->> 'store_kind', sub ->> 'file_sha256'
      )) || E'\n' AS canon_line
    FROM steps s
    CROSS JOIN LATERAL pg_catalog.jsonb_array_elements(s.artifacts) WITH ORDINALITY AS a(sub, a_ord)
  ),
  art_agg AS (
    SELECT
      fn_id,
      pg_catalog.count(*)::int AS art_cnt,
      coherence.sha256_text(COALESCE(pg_catalog.string_agg(canon_line, '' ORDER BY rel_path COLLATE "C"), '')) AS art_hash
    FROM arts_expanded
    GROUP BY fn_id
  ),
  ev_pairs AS (
    SELECT s.st_ord, 1 AS kind_ord, pg_catalog.jsonb_build_object(
      'id', s.st_id::text, 'step', s.step, 'attempt_no', s.st_no, 'event_kind', 'started',
      'born', NULL, 'log_file_sha256', NULL, 'artifact_count', NULL, 'artifacts_sha256', NULL,
      'census', NULL, 'original_at', s.started_at
    ) AS ev_obj
    FROM steps s
    UNION ALL
    SELECT s.st_ord, 2 AS kind_ord, pg_catalog.jsonb_build_object(
      'id', s.fn_id::text, 'step', s.step, 'attempt_no', s.st_no, 'event_kind', 'finished',
      'born', s.born, 'log_file_sha256', s.log_file_sha256,
      'artifact_count', COALESCE(aa.art_cnt, 0), 'artifacts_sha256', COALESCE(aa.art_hash, coherence.sha256_text('')),
      'census', s.census, 'original_at', s.finished_at
    ) AS ev_obj
    FROM steps s
    LEFT JOIN art_agg aa ON aa.fn_id = s.fn_id
  ),
  latest_by_step AS (
    SELECT DISTINCT ON (step) step, fn_id
    FROM steps
    ORDER BY step, st_ord DESC
  )
  SELECT
    COALESCE((SELECT pg_catalog.jsonb_agg(ev_obj ORDER BY st_ord, kind_ord) FROM ev_pairs), '[]'::jsonb),
    COALESCE((SELECT pg_catalog.jsonb_agg(art_obj ORDER BY st_ord, a_ord) FROM arts_expanded), '[]'::jsonb),
    COALESCE((SELECT pg_catalog.jsonb_object_agg(step, fn_id::text) FROM latest_by_step), '{}'::jsonb)
  INTO v_ev_rows, v_art_rows, v_fin_by_step;
  v_ev_cnt := pg_catalog.jsonb_array_length(v_ev_rows);
  v_art_cnt := pg_catalog.jsonb_array_length(v_art_rows);

  -- Review saves (set-based jsonb_agg)
  WITH rs_prep AS MATERIALIZED (
    SELECT
      ord,
      COALESCE((elem ->> 'id')::uuid, pg_catalog.gen_random_uuid()) AS rs_id,
      COALESCE((elem ->> 'attempt_event_id')::uuid, (v_fin_by_step ->> (elem ->> 'surface'))::uuid) AS rs_att,
      elem
    FROM pg_catalog.jsonb_array_elements(coherence._cmd_jsonb_array(p_payload -> 'review_saves')) WITH ORDINALITY AS t(elem, ord)
  )
  SELECT
    COALESCE(pg_catalog.array_agg(rs_id ORDER BY ord), ARRAY[]::uuid[]),
    COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'id', rs_id::text, 'surface', elem ->> 'surface', 'attempt_event_id', rs_att::text,
      'approvals_file_sha256', elem ->> 'approvals_file_sha256',
      'decision_commit_id', elem ->> 'decision_commit_id',
      'original_at', CASE WHEN elem ->> 'original_at' IS NULL THEN NULL ELSE coherence.format_utc_us((elem ->> 'original_at')::timestamptz) END
    ) ORDER BY ord), '[]'::jsonb)
  INTO v_rs_ids, v_rs_rows
  FROM rs_prep
  WHERE rs_att IS NOT NULL;
  v_rs_cnt := pg_catalog.jsonb_array_length(v_rs_rows);

  -- Review queue items (set-based jsonb_agg)
  SELECT COALESCE(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'attempt_event_id', rqi_att::text,
      'item_order', COALESCE((elem ->> 'item_order')::int, ord::int),
      'surface', elem ->> 'surface',
      'record_id', elem ->> 'record_id',
      'case_kind', elem ->> 'case_kind', 'subtype', elem ->> 'subtype',
      'entity', elem ->> 'entity', 'npn', elem ->> 'npn', 'amount', elem ->> 'amount',
      'entity_from', elem ->> 'entity_from', 'npn_from', elem ->> 'npn_from',
      'needs_reconfirm', COALESCE((elem ->> 'needs_reconfirm')::boolean, false)
    ) ORDER BY ord),
    '[]'::jsonb
  ) INTO v_rqi_rows
  FROM (
    SELECT
      ord,
      COALESCE(
        (elem ->> 'attempt_event_id')::uuid,
        (v_fin_by_step ->> COALESCE(elem ->> 'attempt_step', elem ->> 'surface'))::uuid
      ) AS rqi_att,
      elem
    FROM pg_catalog.jsonb_array_elements(coherence._cmd_jsonb_array(p_payload -> 'review_queue_items')) WITH ORDINALITY AS t(elem, ord)
  ) s
  WHERE rqi_att IS NOT NULL;
  v_rqi_cnt := pg_catalog.jsonb_array_length(v_rqi_rows);

  -- Decisions (imported = true, set-based jsonb_agg)
  SELECT COALESCE(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'id', COALESCE((elem ->> 'id')::uuid, pg_catalog.gen_random_uuid())::text,
      'decision_commit_id', elem ->> 'decision_commit_id',
      'row_order', (elem ->> 'row_order')::int,
      'run_id', CASE
        WHEN elem ->> 'run_id' = '__THIS_RUN__' THEN v_run_id::text
        WHEN elem ? 'run_id' THEN elem ->> 'run_id'
        ELSE v_run_id::text
      END,
      'review_save_id', CASE
        WHEN (elem ->> 'review_save_id') IS NOT NULL AND ((elem ->> 'review_save_id')::uuid = ANY(v_rs_ids))
          THEN (elem ->> 'review_save_id')::uuid::text
        ELSE NULL
      END,
      'surface', elem ->> 'surface',
      'record_id', elem ->> 'record_id',
      'replaces_decision_id', elem ->> 'replaces_decision_id',
      'disposition', COALESCE(elem ->> 'disposition', 'CONFIRM'),
      'agent', elem ->> 'agent', 'agency', elem ->> 'agency',
      'policy', elem ->> 'policy', 'book', elem ->> 'book',
      'month', elem ->> 'month', 'status', elem ->> 'status', 'note', elem ->> 'note',
      'approved_amount', elem ->> 'approved_amount',
      'approved_agency', elem ->> 'approved_agency',
      'approved_agent', elem ->> 'approved_agent',
      'approved_agency_from', elem ->> 'approved_agency_from',
      'approved_agent_from', elem ->> 'approved_agent_from',
      'decided_by', CASE
        WHEN NULLIF(pg_catalog.btrim(elem ->> 'decided_by'), '') IS NULL THEN 'historical_import'
        WHEN pg_catalog.btrim(elem ->> 'decided_by') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN v_ctx.actor_label
        ELSE pg_catalog.btrim(elem ->> 'decided_by')
      END,
      'acting_for', CASE
        WHEN pg_catalog.btrim(elem ->> 'decided_by') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN v_ctx.acting_for_label
        ELSE NULLIF(pg_catalog.btrim(elem ->> 'acting_for'), '')
      END,
      'decided_at', coherence.format_utc_us(COALESCE((elem ->> 'decided_at')::timestamptz, v_now)),
      'committed_at_raw', elem ->> 'committed_at_raw'
    ) ORDER BY ord),
    '[]'::jsonb
  ) INTO v_dec_rows
  FROM pg_catalog.jsonb_array_elements(coherence._cmd_jsonb_array(p_payload -> 'decisions')) WITH ORDINALITY AS t(elem, ord);
  v_dec_cnt := pg_catalog.jsonb_array_length(v_dec_rows);

  -- Decision commits (compute added_decision_count and added_decisions_sha256 from matching v_dec_rows, set-based)
  WITH dec_by_dc AS (
    SELECT
      (d ->> 'decision_commit_id')::uuid AS dc_id,
      pg_catalog.count(*)::int AS added_cnt,
      coherence.sha256_text(COALESCE(pg_catalog.string_agg(
        coherence.canonical_json(pg_catalog.jsonb_build_array(
          d ->> 'id', (d ->> 'row_order')::int, d ->> 'run_id', d ->> 'review_save_id', d ->> 'surface',
          d ->> 'record_id', d ->> 'replaces_decision_id', d ->> 'disposition',
          d ->> 'agent', d ->> 'agency', d ->> 'policy', d ->> 'book', d ->> 'month', d ->> 'status', d ->> 'note',
          d ->> 'approved_amount', d ->> 'approved_agency', d ->> 'approved_agent',
          d ->> 'approved_agency_from', d ->> 'approved_agent_from',
          d ->> 'decided_by', d ->> 'acting_for', d ->> 'decided_at', d ->> 'committed_at_raw', true
        )) || E'\n',
        '' ORDER BY (d ->> 'row_order')::int ASC
      ), '')) AS added_hash
    FROM pg_catalog.jsonb_array_elements(v_dec_rows) AS t(d)
    GROUP BY (d ->> 'decision_commit_id')::uuid
  )
  SELECT COALESCE(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'id', (elem ->> 'id')::uuid::text,
      'parent_commit_id', elem ->> 'parent_commit_id',
      'commit_kind', COALESCE(elem ->> 'commit_kind', 'historical_overlay'),
      'header_contract', COALESCE(elem ->> 'header_contract', 'v2'),
      'added_decision_count', COALESCE(agg.added_cnt, 0),
      'cumulative_decision_count', (elem ->> 'cumulative_decision_count')::int,
      'added_decisions_sha256', COALESCE(agg.added_hash, coherence.sha256_text('')),
      'original_at', CASE WHEN elem ->> 'original_at' IS NULL THEN NULL ELSE coherence.format_utc_us((elem ->> 'original_at')::timestamptz) END
    ) ORDER BY ord),
    '[]'::jsonb
  ) INTO v_dc_rows
  FROM pg_catalog.jsonb_array_elements(coherence._cmd_jsonb_array(p_payload -> 'decision_commits')) WITH ORDINALITY AS t(elem, ord)
  LEFT JOIN dec_by_dc agg ON agg.dc_id = (elem ->> 'id')::uuid;
  v_dc_cnt := pg_catalog.jsonb_array_length(v_dc_rows);

  -- Generated overlays (set-based jsonb_agg)
  SELECT COALESCE(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'id', COALESCE((elem ->> 'id')::uuid, pg_catalog.gen_random_uuid())::text,
      'decision_commit_id', elem ->> 'decision_commit_id',
      'purpose', elem ->> 'purpose',
      'attempt_event_id', COALESCE(
        (elem ->> 'attempt_event_id')::uuid,
        CASE WHEN elem ->> 'attempt_step' IS NOT NULL THEN (v_fin_by_step ->> (elem ->> 'attempt_step'))::uuid ELSE NULL END
      )::text,
      'header_contract', COALESCE(elem ->> 'header_contract', 'v2'),
      'row_count', (elem ->> 'row_count')::int,
      'file_sha256', elem ->> 'file_sha256'
    ) ORDER BY ord),
    '[]'::jsonb
  ) INTO v_go_rows
  FROM pg_catalog.jsonb_array_elements(coherence._cmd_jsonb_array(p_payload -> 'generated_overlays')) WITH ORDINALITY AS t(elem, ord);
  v_go_cnt := pg_catalog.jsonb_array_length(v_go_rows);

  -- Extra imported files (set-based jsonb_agg)
  SELECT COALESCE(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'id', COALESCE((elem ->> 'id')::uuid, pg_catalog.gen_random_uuid())::text,
      'area', COALESCE(elem ->> 'area', 'other'),
      'rel_path', elem ->> 'rel_path',
      'artifact_kind', COALESCE(elem ->> 'artifact_kind', 'data'),
      'store_kind', COALESCE(elem ->> 'store_kind', 'company_data'),
      'file_sha256', elem ->> 'file_sha256',
      'original_at', CASE WHEN elem ->> 'original_at' IS NULL THEN NULL ELSE coherence.format_utc_us((elem ->> 'original_at')::timestamptz) END,
      'metadata', CASE
        WHEN coherence._cmd_jsonb_object(elem -> 'metadata') ->> 'runId' = '__THIS_RUN__'
          THEN coherence._cmd_jsonb_object(elem -> 'metadata') || pg_catalog.jsonb_build_object('runId', v_run_id::text)
        ELSE coherence._cmd_jsonb_object(elem -> 'metadata')
      END
    ) ORDER BY ord),
    '[]'::jsonb
  ) INTO v_imp_rows
  FROM pg_catalog.jsonb_array_elements(coherence._cmd_jsonb_array(p_payload -> 'extra_imported_files')) WITH ORDINALITY AS t(elem, ord);
  v_imp_cnt := pg_catalog.jsonb_array_length(v_imp_rows);

  -- Build full commitment counts & hashes across all non-empty child tables
  v_counts := pg_catalog.jsonb_build_object('input_versions', 1, 'runs', 1);
  v_hashes := pg_catalog.jsonb_build_object('input_versions', v_iv_hash, 'runs', v_run_hash);

  IF v_file_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('stored_files', v_file_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('stored_files', coherence._cmd_hash_stored_files_json(v_new_files));
  END IF;
  IF v_entry_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('input_entries', v_entry_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('input_entries', v_entries_hash);
  END IF;
  IF v_af_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        e ->> 'file_sha256', e ->> 'header_kind', (e ->> 'row_count')::int,
        e ->> 'extends_sha256', (e ->> 'shared_row_count')::int, e ->> 'added_rows_sha256'
      )) || E'\n',
      '' ORDER BY (e ->> 'file_sha256') COLLATE "C"
    )) INTO v_hash FROM pg_catalog.jsonb_array_elements(v_af_rows) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('approvals_files', v_af_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('approvals_files', v_hash);
  END IF;
  IF v_ar_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        (e ->> 'row_no')::int, e ->> 'record_id', e ->> 'disposition', e ->> 'agent', e ->> 'agency',
        e ->> 'policy', e ->> 'book', e ->> 'month', e ->> 'status', e ->> 'note', e ->> 'committed_at',
        e ->> 'approved_amount', e ->> 'approved_agency', e ->> 'approved_agent',
        e ->> 'approved_agency_from', e ->> 'approved_agent_from'
      )) || E'\n',
      '' ORDER BY (e ->> 'approvals_file_sha256') COLLATE "C", (e ->> 'row_no')::int ASC
    )) INTO v_hash FROM pg_catalog.jsonb_array_elements(v_ar_rows) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('approval_rows', v_ar_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('approval_rows', v_hash);
  END IF;
  IF v_dc_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        e ->> 'id', e ->> 'parent_commit_id', e ->> 'commit_kind', e ->> 'header_contract',
        (e ->> 'added_decision_count')::int, (e ->> 'cumulative_decision_count')::int,
        e ->> 'added_decisions_sha256', true, e ->> 'original_at'
      )) || E'\n',
      '' ORDER BY (e ->> 'id') COLLATE "C"
    )) INTO v_hash FROM pg_catalog.jsonb_array_elements(v_dc_rows) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('decision_commits', v_dc_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('decision_commits', v_hash);
  END IF;
  IF v_dec_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        e ->> 'decision_commit_id', e ->> 'id', (e ->> 'row_order')::int, e ->> 'run_id', e ->> 'review_save_id',
        e ->> 'surface', e ->> 'record_id', e ->> 'replaces_decision_id', e ->> 'disposition',
        e ->> 'agent', e ->> 'agency', e ->> 'policy', e ->> 'book', e ->> 'month', e ->> 'status', e ->> 'note',
        e ->> 'approved_amount', e ->> 'approved_agency', e ->> 'approved_agent',
        e ->> 'approved_agency_from', e ->> 'approved_agent_from',
        e ->> 'decided_by', e ->> 'acting_for', e ->> 'decided_at', e ->> 'committed_at_raw', true
      )) || E'\n',
      '' ORDER BY (e ->> 'decision_commit_id') COLLATE "C", (e ->> 'row_order')::int ASC
    )) INTO v_hash FROM pg_catalog.jsonb_array_elements(v_dec_rows) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('decisions', v_dec_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('decisions', v_hash);
  END IF;
  IF v_ev_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        e ->> 'id', v_run_id::text, e ->> 'step', (e ->> 'attempt_no')::int, e ->> 'event_kind',
        NULL::text, NULL::text, e ->> 'born', e ->> 'log_file_sha256',
        (e ->> 'artifact_count')::int, e ->> 'artifacts_sha256'
      )) || E'\n',
      '' ORDER BY (e ->> 'id') COLLATE "C"
    )) INTO v_hash FROM pg_catalog.jsonb_array_elements(v_ev_rows) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('step_attempt_events', v_ev_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('step_attempt_events', v_hash);
  END IF;
  IF v_art_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        e ->> 'rel_path', e ->> 'artifact_kind', e ->> 'store_kind', e ->> 'file_sha256'
      )) || E'\n',
      '' ORDER BY (e ->> 'attempt_event_id') COLLATE "C", (e ->> 'rel_path') COLLATE "C"
    )) INTO v_hash FROM pg_catalog.jsonb_array_elements(v_art_rows) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('artifacts', v_art_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('artifacts', v_hash);
  END IF;
  IF v_rqi_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        e ->> 'attempt_event_id', (e ->> 'item_order')::int, v_run_id::text, e ->> 'surface',
        e ->> 'record_id', e ->> 'case_kind', e ->> 'subtype', e ->> 'entity', e ->> 'npn',
        e ->> 'amount', e ->> 'entity_from', e ->> 'npn_from', (e ->> 'needs_reconfirm')::boolean
      )) || E'\n',
      '' ORDER BY (e ->> 'attempt_event_id') COLLATE "C", (e ->> 'item_order')::int ASC
    )) INTO v_hash FROM pg_catalog.jsonb_array_elements(v_rqi_rows) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('review_queue_items', v_rqi_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('review_queue_items', v_hash);
  END IF;
  IF v_rs_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        e ->> 'id', v_run_id::text, e ->> 'surface', e ->> 'attempt_event_id',
        e ->> 'approvals_file_sha256', e ->> 'decision_commit_id',
        true, e ->> 'original_at', NULL::text
      )) || E'\n',
      '' ORDER BY (e ->> 'id') COLLATE "C"
    )) INTO v_hash FROM pg_catalog.jsonb_array_elements(v_rs_rows) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('review_saves', v_rs_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('review_saves', v_hash);
  END IF;
  IF v_go_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        e ->> 'id', e ->> 'decision_commit_id', v_run_id::text, e ->> 'purpose',
        e ->> 'attempt_event_id', e ->> 'header_contract', (e ->> 'row_count')::int, 'company_data', e ->> 'file_sha256'
      )) || E'\n',
      '' ORDER BY (e ->> 'id') COLLATE "C"
    )) INTO v_hash FROM pg_catalog.jsonb_array_elements(v_go_rows) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('generated_overlays', v_go_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('generated_overlays', v_hash);
  END IF;
  IF v_imp_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        e ->> 'id', e ->> 'area', e ->> 'rel_path', e ->> 'artifact_kind', e ->> 'store_kind',
        e ->> 'file_sha256', e ->> 'original_at', e -> 'metadata'
      )) || E'\n',
      '' ORDER BY (e ->> 'id') COLLATE "C"
    )) INTO v_hash FROM pg_catalog.jsonb_array_elements(v_imp_rows) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('imported_files', v_imp_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('imported_files', v_hash);
  END IF;
  IF v_ab IS NOT NULL AND pg_catalog.jsonb_typeof(v_ab) = 'object' THEN
    v_ab_id := COALESCE((v_ab ->> 'id')::uuid, pg_catalog.gen_random_uuid());
    v_ab_phrase := COALESCE(v_ab ->> 'typed_phrase', 'abandon ' || coherence.fmt_date(v_stmt_date));
    v_ab_reason := COALESCE(v_ab ->> 'reason', 'Imported abandoned run from ' || v_src_folder);
    v_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
      v_ab_id::text, v_run_id::text, v_ab_phrase, v_ab_reason
    )) || E'\n');
    v_counts := v_counts || pg_catalog.jsonb_build_object('abandonments', 1);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('abandonments', v_hash);
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object(
      'runId', v_run_id, 'inputVersionId', v_iv_id, 'alreadyImported', false,
      'steps', v_ev_cnt / 2, 'reviewSaves', v_rs_cnt, 'decisionCommits', v_dc_cnt,
      'decisions', v_dec_cnt, 'generatedOverlays', v_go_cnt
    ),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'import_historical_run', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('run_id', v_run_id, 'origin', v_origin, 'statement_date', coherence.fmt_date(v_stmt_date))
  );
  PERFORM coherence._cmd_insert_stored_files_json(v_new_files, v_seq);

  IF v_af_cnt > 0 THEN
    INSERT INTO coherence.approvals_files (
      file_sha256, store_kind, header_kind, row_count, extends_sha256, shared_row_count, added_rows_sha256, journal_seq
    )
    SELECT
      e ->> 'file_sha256', 'company_data', e ->> 'header_kind', (e ->> 'row_count')::int,
      e ->> 'extends_sha256', (e ->> 'shared_row_count')::int, e ->> 'added_rows_sha256', v_seq
    FROM pg_catalog.jsonb_array_elements(v_af_rows) AS t(e);
  END IF;
  IF v_ar_cnt > 0 THEN
    INSERT INTO coherence.approval_rows (
      approvals_file_sha256, row_no, record_id, disposition, agent, agency, policy, book,
      month, status, note, committed_at, approved_amount, approved_agency, approved_agent,
      approved_agency_from, approved_agent_from, journal_seq
    )
    SELECT
      e ->> 'approvals_file_sha256', (e ->> 'row_no')::int, e ->> 'record_id', e ->> 'disposition',
      e ->> 'agent', e ->> 'agency', e ->> 'policy', e ->> 'book', e ->> 'month', e ->> 'status',
      e ->> 'note', e ->> 'committed_at', e ->> 'approved_amount', e ->> 'approved_agency',
      e ->> 'approved_agent', e ->> 'approved_agency_from', e ->> 'approved_agent_from', v_seq
    FROM pg_catalog.jsonb_array_elements(v_ar_rows) AS t(e);
  END IF;

  IF v_dc_cnt > 0 THEN
    INSERT INTO coherence.decision_commits (
      id, parent_commit_id, commit_kind, header_contract,
      added_decision_count, cumulative_decision_count, added_decisions_sha256,
      imported, original_at, journal_seq
    )
    SELECT
      (e ->> 'id')::uuid, (e ->> 'parent_commit_id')::uuid, e ->> 'commit_kind', e ->> 'header_contract',
      (e ->> 'added_decision_count')::int, (e ->> 'cumulative_decision_count')::int,
      e ->> 'added_decisions_sha256', true, (e ->> 'original_at')::timestamptz, v_seq
    FROM pg_catalog.jsonb_array_elements(v_dc_rows) AS t(e);
  END IF;

  INSERT INTO coherence.input_versions (
    id, line_kind, parent_id, source_kind, reason,
    entry_count, entries_sha256, change_count, changes_sha256, store_kind, journal_seq
  ) VALUES (
    v_iv_id, 'snapshot', NULL,
    CASE WHEN v_origin = 'mac_import' THEN 'mac_import' ELSE 'company_import' END,
    v_iv_reason, v_entry_cnt, v_entries_hash, 0, v_changes_hash, 'company_data', v_seq
  );
  IF v_entry_cnt > 0 THEN
    INSERT INTO coherence.input_entries (input_version_id, rel_path, store_kind, file_sha256, journal_seq)
    SELECT v_iv_id, e ->> 'rel_path', 'company_data', e ->> 'file_sha256', v_seq
    FROM pg_catalog.jsonb_array_elements(v_entries) AS t(e);
  END IF;

  INSERT INTO coherence.runs (
    id, statement_date, folder_number, origin, input_version_id, prior_approvals_sha256,
    prior_decision_commit_id, engine_version_id, emit_mode, emit_display, emit_keep, emit_no_manager,
    replays_run_id, compared_run_id, rerun_reason, source_folder, journal_seq
  ) VALUES (
    v_run_id, v_stmt_date, v_folder_no, v_origin, v_iv_id, v_prior_ov,
    v_prior_dc, v_eng_id, v_emit_mode, v_emit_display, v_emit_keep, v_emit_no_mgr,
    NULL, NULL, v_rerun_reason, v_src_folder, v_seq
  );

  IF v_ev_cnt > 0 THEN
    INSERT INTO coherence.step_attempt_events (
      id, run_id, step, attempt_no, event_kind, census, born,
      log_store_kind, log_file_sha256, artifact_count, artifacts_sha256, original_at, journal_seq
    )
    SELECT
      (e ->> 'id')::uuid, v_run_id, e ->> 'step', (e ->> 'attempt_no')::int, e ->> 'event_kind',
      e -> 'census', e ->> 'born',
      CASE WHEN e ->> 'log_file_sha256' IS NOT NULL THEN 'company_data' ELSE NULL END,
      e ->> 'log_file_sha256', (e ->> 'artifact_count')::int, e ->> 'artifacts_sha256',
      (e ->> 'original_at')::timestamptz, v_seq
    FROM pg_catalog.jsonb_array_elements(v_ev_rows) AS t(e);
  END IF;
  IF v_art_cnt > 0 THEN
    INSERT INTO coherence.artifacts (attempt_event_id, rel_path, artifact_kind, store_kind, file_sha256, journal_seq)
    SELECT (e ->> 'attempt_event_id')::uuid, e ->> 'rel_path', e ->> 'artifact_kind', e ->> 'store_kind', e ->> 'file_sha256', v_seq
    FROM pg_catalog.jsonb_array_elements(v_art_rows) AS t(e);
  END IF;
  IF v_rqi_cnt > 0 THEN
    INSERT INTO coherence.review_queue_items (
      attempt_event_id, item_order, run_id, surface, record_id,
      case_kind, subtype, entity, npn, amount, entity_from, npn_from, needs_reconfirm, journal_seq
    )
    SELECT
      (e ->> 'attempt_event_id')::uuid, (e ->> 'item_order')::int, v_run_id, e ->> 'surface', e ->> 'record_id',
      e ->> 'case_kind', e ->> 'subtype', e ->> 'entity', e ->> 'npn', e ->> 'amount',
      e ->> 'entity_from', e ->> 'npn_from', (e ->> 'needs_reconfirm')::boolean, v_seq
    FROM pg_catalog.jsonb_array_elements(v_rqi_rows) AS t(e);
  END IF;
  IF v_rs_cnt > 0 THEN
    INSERT INTO coherence.review_saves (
      id, run_id, surface, attempt_event_id, approvals_file_sha256, decision_commit_id,
      imported, original_at, submission_id, journal_seq
    )
    SELECT
      (e ->> 'id')::uuid, v_run_id, e ->> 'surface', (e ->> 'attempt_event_id')::uuid,
      e ->> 'approvals_file_sha256', (e ->> 'decision_commit_id')::uuid,
      true, (e ->> 'original_at')::timestamptz, NULL, v_seq
    FROM pg_catalog.jsonb_array_elements(v_rs_rows) AS t(e);
  END IF;
  IF v_dec_cnt > 0 THEN
    INSERT INTO coherence.decisions (
      id, decision_commit_id, row_order, run_id, review_save_id, surface, record_id,
      replaces_decision_id, disposition, agent, agency, policy, book, month, status, note,
      approved_amount, approved_agency, approved_agent, approved_agency_from, approved_agent_from,
      decided_by, acting_for, decided_at, committed_at_raw, imported, journal_seq
    )
    SELECT
      (e ->> 'id')::uuid, (e ->> 'decision_commit_id')::uuid, (e ->> 'row_order')::int,
      (e ->> 'run_id')::uuid, (e ->> 'review_save_id')::uuid, e ->> 'surface', e ->> 'record_id',
      (e ->> 'replaces_decision_id')::uuid, e ->> 'disposition', e ->> 'agent', e ->> 'agency',
      e ->> 'policy', e ->> 'book', e ->> 'month', e ->> 'status', e ->> 'note',
      e ->> 'approved_amount', e ->> 'approved_agency', e ->> 'approved_agent',
      e ->> 'approved_agency_from', e ->> 'approved_agent_from',
      e ->> 'decided_by', e ->> 'acting_for', (e ->> 'decided_at')::timestamptz,
      e ->> 'committed_at_raw', true, v_seq
    FROM pg_catalog.jsonb_array_elements(v_dec_rows) AS t(e);
  END IF;
  IF v_go_cnt > 0 THEN
    INSERT INTO coherence.generated_overlays (
      id, decision_commit_id, run_id, purpose, attempt_event_id,
      header_contract, row_count, store_kind, file_sha256, journal_seq
    )
    SELECT
      (e ->> 'id')::uuid, (e ->> 'decision_commit_id')::uuid, v_run_id, e ->> 'purpose',
      (e ->> 'attempt_event_id')::uuid, e ->> 'header_contract', (e ->> 'row_count')::int,
      'company_data', e ->> 'file_sha256', v_seq
    FROM pg_catalog.jsonb_array_elements(v_go_rows) AS t(e);
  END IF;
  IF v_imp_cnt > 0 THEN
    INSERT INTO coherence.imported_files (id, area, rel_path, artifact_kind, store_kind, file_sha256, original_at, metadata, journal_seq)
    SELECT
      (e ->> 'id')::uuid, e ->> 'area', e ->> 'rel_path', e ->> 'artifact_kind', e ->> 'store_kind',
      e ->> 'file_sha256', (e ->> 'original_at')::timestamptz, e -> 'metadata', v_seq
    FROM pg_catalog.jsonb_array_elements(v_imp_rows) AS t(e);
  END IF;
  IF v_ab_id IS NOT NULL THEN
    INSERT INTO coherence.abandonments (id, run_id, typed_phrase, reason, journal_seq)
    VALUES (v_ab_id, v_run_id, v_ab_phrase, v_ab_reason, v_seq);
  END IF;

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'run_id', v_run_id);
END;
$$;

-- 7.22 record_check (Worker or Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_record_check(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_check_kind TEXT,
  p_passed BOOLEAN,
  p_report JSONB,
  p_run_id UUID DEFAULT NULL,
  p_compared_run_id UUID DEFAULT NULL,
  p_check_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_chk_id UUID := COALESCE(p_check_id, pg_catalog.gen_random_uuid());
  v_hash TEXT;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.checks.record', 'human_or_service');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('record_check', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  v_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_chk_id::text, p_check_kind, p_run_id::text, p_compared_run_id::text, p_passed, p_report
  )) || E'\n');
  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('checkId', v_chk_id, 'passed', p_passed),
    'commitments', pg_catalog.jsonb_build_object(
      'counts', pg_catalog.jsonb_build_object('checks', 1),
      'hashes', pg_catalog.jsonb_build_object('checks', v_hash)
    )
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'record_check', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('check_id', v_chk_id, 'check_kind', p_check_kind, 'passed', p_passed)
  );
  INSERT INTO coherence.checks (id, check_kind, run_id, compared_run_id, passed, report, journal_seq)
  VALUES (v_chk_id, p_check_kind, p_run_id, p_compared_run_id, p_passed, p_report, v_seq);

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'check_id', v_chk_id);
END;
$$;

-- 7.23 record_generated_overlay (Worker or Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_record_generated_overlay(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_decision_commit_id UUID,
  p_run_id UUID,
  p_purpose TEXT,
  p_header_contract TEXT,
  p_row_count INTEGER,
  p_stored_file JSONB,
  p_attempt_event_id UUID DEFAULT NULL,
  p_overlay_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_ov_id UUID := COALESCE(p_overlay_id, pg_catalog.gen_random_uuid());
  v_sha TEXT := p_stored_file ->> 'sha256';
  v_new_files JSONB;
  v_file_cnt INT;
  v_ov_hash TEXT;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.overlays.record', 'human_or_service');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('record_generated_overlay', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  v_new_files := coherence._cmd_filter_new_stored_files(pg_catalog.jsonb_build_array(p_stored_file), 'company_data');
  v_file_cnt := pg_catalog.jsonb_array_length(v_new_files);

  v_ov_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_ov_id::text, p_decision_commit_id::text, p_run_id::text, p_purpose,
    p_attempt_event_id::text, p_header_contract, p_row_count, 'company_data', v_sha
  )) || E'\n');
  v_counts := pg_catalog.jsonb_build_object('generated_overlays', 1);
  v_hashes := pg_catalog.jsonb_build_object('generated_overlays', v_ov_hash);
  IF v_file_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('stored_files', v_file_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('stored_files', coherence._cmd_hash_stored_files_json(v_new_files));
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('overlayId', v_ov_id, 'decisionCommitId', p_decision_commit_id, 'fileSha256', v_sha),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'record_generated_overlay', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('overlay_id', v_ov_id, 'run_id', p_run_id, 'purpose', p_purpose)
  );
  PERFORM coherence._cmd_insert_stored_files_json(v_new_files, v_seq);
  INSERT INTO coherence.generated_overlays (
    id, decision_commit_id, run_id, purpose, attempt_event_id,
    header_contract, row_count, store_kind, file_sha256, journal_seq
  ) VALUES (
    v_ov_id, p_decision_commit_id, p_run_id, p_purpose, p_attempt_event_id,
    p_header_contract, p_row_count, 'company_data', v_sha, v_seq
  );

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'overlay_id', v_ov_id);
END;
$$;

-- 7.24 materialize_emit (Worker or Owner)
CREATE OR REPLACE FUNCTION app_cmd.coherence_materialize_emit(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_payload JSONB
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_rm JSONB := p_payload -> 'run_materialization';
  v_att_id UUID := (v_rm ->> 'attempt_event_id')::uuid;
  v_run_id UUID := (v_rm ->> 'run_id')::uuid;
  v_mat RECORD;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.emit.materialize', 'human_or_service');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('materialize_emit', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  IF EXISTS (SELECT 1 FROM coherence.run_materializations WHERE attempt_event_id = v_att_id) THEN
    RAISE EXCEPTION 'ALREADY_MATERIALIZED: Emit attempt has already been materialized.' USING ERRCODE = '23505';
  END IF;

  SELECT * INTO v_mat FROM coherence._cmd_prepare_materialization(p_payload, v_run_id, v_att_id);

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object(
      'attemptEventId', v_att_id, 'runId', v_run_id, 'statementBatchId', v_mat.batch_id,
      'bobRowCount', (v_mat.rm_norm ->> 'bob_row_count')::int,
      'ledgerRowCount', (v_mat.rm_norm ->> 'ledger_row_count')::int,
      'agencyLineCount', (v_mat.sb_norm ->> 'agency_line_count')::int,
      'uplineLineCount', (v_mat.sb_norm ->> 'upline_line_count')::int,
      'ledgerGrossTotal', v_mat.rm_norm ->> 'ledger_gross_total',
      'ledgerDownlineTotal', v_mat.rm_norm ->> 'ledger_downline_total',
      'ledgerUplineTotal', v_mat.rm_norm ->> 'ledger_upline_total'
    ),
    'commitments', pg_catalog.jsonb_build_object('counts', v_mat.counts, 'hashes', v_mat.hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'materialize_emit', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('run_id', v_run_id, 'attempt_event_id', v_att_id, 'statement_batch_id', v_mat.batch_id)
  );
  PERFORM coherence._cmd_insert_materialization(p_payload, v_mat.sb_norm, v_mat.rm_norm, v_run_id, v_att_id, v_seq);

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object(
    'idempotent', false, 'journal_seq', v_seq, 'run_id', v_run_id, 'statement_batch_id', v_mat.batch_id,
    'bob_row_count', (v_mat.rm_norm ->> 'bob_row_count')::int,
    'ledger_row_count', (v_mat.rm_norm ->> 'ledger_row_count')::int,
    'agency_line_count', (v_mat.sb_norm ->> 'agency_line_count')::int,
    'upline_line_count', (v_mat.sb_norm ->> 'upline_line_count')::int,
    'ledger_gross_total', v_mat.rm_norm ->> 'ledger_gross_total',
    'ledger_downline_total', v_mat.rm_norm ->> 'ledger_downline_total',
    'ledger_upline_total', v_mat.rm_norm ->> 'ledger_upline_total'
  );
END;
$$;

-- 7.25 - 7.31 WORKER-ONLY COMMANDS (never granted EXECUTE to platform_app; require person_kind = 'service' + platform_worker).

-- 7.25 start_attempt (Worker only)
CREATE OR REPLACE FUNCTION app_cmd.coherence_start_attempt(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_run_id UUID,
  p_step TEXT,
  p_step_request_id UUID,
  p_event_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_ev_id UUID := COALESCE(p_event_id, pg_catalog.gen_random_uuid());
  v_attempt_no INT;
  v_hash TEXT;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.worker.attempt', 'service_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('start_attempt', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  SELECT COALESCE(pg_catalog.max(attempt_no), 0) + 1 INTO v_attempt_no
  FROM coherence.step_attempt_events
  WHERE run_id = p_run_id AND step = p_step AND event_kind = 'started';

  v_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_ev_id::text, p_run_id::text, p_step, v_attempt_no, 'started',
    p_step_request_id::text, NULL::text, NULL::text, NULL::text, NULL::int, NULL::text
  )) || E'\n');
  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('attemptEventId', v_ev_id, 'runId', p_run_id, 'step', p_step, 'attemptNo', v_attempt_no),
    'commitments', pg_catalog.jsonb_build_object(
      'counts', pg_catalog.jsonb_build_object('step_attempt_events', 1),
      'hashes', pg_catalog.jsonb_build_object('step_attempt_events', v_hash)
    )
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'start_attempt', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('attempt_event_id', v_ev_id, 'run_id', p_run_id, 'step', p_step, 'attempt_no', v_attempt_no)
  );
  INSERT INTO coherence.step_attempt_events (id, run_id, step, attempt_no, event_kind, step_request_id, journal_seq)
  VALUES (v_ev_id, p_run_id, p_step, v_attempt_no, 'started', p_step_request_id, v_seq);

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'attempt_event_id', v_ev_id, 'attempt_no', v_attempt_no);
END;
$$;

-- 7.26 finish_attempt (Worker only)
CREATE OR REPLACE FUNCTION app_cmd.coherence_finish_attempt(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_payload JSONB
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_ev_id UUID := COALESCE((p_payload ->> 'event_id')::uuid, pg_catalog.gen_random_uuid());
  v_run_id UUID := (p_payload ->> 'run_id')::uuid;
  v_step TEXT := p_payload ->> 'step';
  v_attempt_no INT := (p_payload ->> 'attempt_no')::int;
  v_census JSONB := coherence._cmd_jsonb_object(p_payload -> 'census');
  v_born TEXT := p_payload ->> 'born';
  v_log_file JSONB := p_payload -> 'log_file';
  v_log_sha TEXT := COALESCE(
    p_payload ->> 'log_file_sha256',
    CASE WHEN v_log_file IS NOT NULL AND pg_catalog.jsonb_typeof(v_log_file) = 'object' THEN v_log_file ->> 'sha256' ELSE NULL END
  );
  v_all_files JSONB := coherence._cmd_jsonb_array(p_payload -> 'stored_files')
    || CASE WHEN v_log_file IS NOT NULL AND pg_catalog.jsonb_typeof(v_log_file) = 'object' THEN pg_catalog.jsonb_build_array(v_log_file) ELSE '[]'::jsonb END;
  v_arts JSONB := coherence._cmd_jsonb_array(p_payload -> 'artifacts');
  v_art_cnt INT := pg_catalog.jsonb_array_length(v_arts);
  v_arts_hash TEXT;
  v_rqi_in JSONB := coherence._cmd_jsonb_array(p_payload -> 'review_queue_items');
  v_rqi_norm JSONB := '[]'::jsonb;
  v_rqi_cnt INT := 0;
  v_rqi_hash TEXT;
  v_go_in JSONB := coherence._cmd_jsonb_array(p_payload -> 'generated_overlays');
  v_go_norm JSONB := '[]'::jsonb;
  v_go_cnt INT := 0;
  v_go_hash TEXT;
  v_mat_in JSONB := p_payload -> 'emit_materialization';
  v_has_mat BOOLEAN := (v_step = 'emit' AND v_mat_in IS NOT NULL AND pg_catalog.jsonb_typeof(v_mat_in) = 'object');
  v_mat RECORD;
  v_mat_batch_id UUID := NULL;
  v_elem JSONB;
  v_idx INT := 0;
  v_new_files JSONB;
  v_file_cnt INT;
  v_continue BOOLEAN := COALESCE((p_payload ->> 'continue_to_next_step')::boolean, v_step IN ('assign', 'attribute'));
  v_next_step TEXT := CASE v_step WHEN 'assign' THEN 'attribute' WHEN 'attribute' THEN 'bible' ELSE NULL END;
  v_next_req_id UUID := CASE WHEN v_continue AND v_step IN ('assign', 'attribute') THEN COALESCE((p_payload ->> 'next_request_id')::uuid, pg_catalog.gen_random_uuid()) ELSE NULL END;
  v_ev_hash TEXT;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.worker.attempt', 'service_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('finish_attempt', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  IF v_log_file IS NOT NULL AND pg_catalog.jsonb_typeof(v_log_file) = 'object' THEN
    PERFORM coherence._cmd_filter_new_stored_files(pg_catalog.jsonb_build_array(v_log_file), 'company_data');
  END IF;
  v_new_files := coherence._cmd_filter_new_stored_files(v_all_files);
  v_file_cnt := pg_catalog.jsonb_array_length(v_new_files);

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      e ->> 'rel_path', e ->> 'artifact_kind', e ->> 'store_kind', e ->> 'file_sha256'
    )) || E'\n',
    '' ORDER BY (e ->> 'rel_path') COLLATE "C"
  ), '')) INTO v_arts_hash FROM pg_catalog.jsonb_array_elements(v_arts) AS t(e);

  SELECT COALESCE(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'item_order', COALESCE((elem ->> 'item_order')::int, ord::int),
      'surface', COALESCE(elem ->> 'surface', v_step),
      'record_id', elem ->> 'record_id',
      'case_kind', elem ->> 'case_kind', 'subtype', elem ->> 'subtype',
      'entity', elem ->> 'entity', 'npn', elem ->> 'npn', 'amount', elem ->> 'amount',
      'entity_from', elem ->> 'entity_from', 'npn_from', elem ->> 'npn_from',
      'needs_reconfirm', COALESCE((elem ->> 'needs_reconfirm')::boolean, false)
    ) ORDER BY ord),
    '[]'::jsonb
  ) INTO v_rqi_norm
  FROM pg_catalog.jsonb_array_elements(v_rqi_in) WITH ORDINALITY AS t(elem, ord);
  v_rqi_cnt := pg_catalog.jsonb_array_length(v_rqi_norm);

  SELECT COALESCE(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'id', COALESCE((elem ->> 'id')::uuid, pg_catalog.gen_random_uuid())::text,
      'decision_commit_id', elem ->> 'decision_commit_id',
      'purpose', elem ->> 'purpose',
      'header_contract', COALESCE(elem ->> 'header_contract', 'v2'),
      'row_count', (elem ->> 'row_count')::int,
      'file_sha256', elem ->> 'file_sha256'
    ) ORDER BY ord),
    '[]'::jsonb
  ) INTO v_go_norm
  FROM pg_catalog.jsonb_array_elements(v_go_in) WITH ORDINALITY AS t(elem, ord);
  v_go_cnt := pg_catalog.jsonb_array_length(v_go_norm);

  v_ev_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_ev_id::text, v_run_id::text, v_step, v_attempt_no, 'finished',
    NULL::text, NULL::text, v_born, v_log_sha, v_art_cnt, v_arts_hash
  )) || E'\n');

  v_counts := pg_catalog.jsonb_build_object('step_attempt_events', 1);
  v_hashes := pg_catalog.jsonb_build_object('step_attempt_events', v_ev_hash);
  IF v_file_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('stored_files', v_file_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('stored_files', coherence._cmd_hash_stored_files_json(v_new_files));
  END IF;
  IF v_art_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('artifacts', v_art_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('artifacts', v_arts_hash);
  END IF;
  IF v_rqi_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        v_ev_id::text, (e ->> 'item_order')::int, v_run_id::text, e ->> 'surface',
        e ->> 'record_id', e ->> 'case_kind', e ->> 'subtype', e ->> 'entity', e ->> 'npn',
        e ->> 'amount', e ->> 'entity_from', e ->> 'npn_from', (e ->> 'needs_reconfirm')::boolean
      )) || E'\n',
      '' ORDER BY (e ->> 'item_order')::int ASC
    )) INTO v_rqi_hash FROM pg_catalog.jsonb_array_elements(v_rqi_norm) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('review_queue_items', v_rqi_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('review_queue_items', v_rqi_hash);
  END IF;
  IF v_go_cnt > 0 THEN
    SELECT coherence.sha256_text(pg_catalog.string_agg(
      coherence.canonical_json(pg_catalog.jsonb_build_array(
        e ->> 'id', e ->> 'decision_commit_id', v_run_id::text, e ->> 'purpose',
        v_ev_id::text, e ->> 'header_contract', (e ->> 'row_count')::int, 'company_data', e ->> 'file_sha256'
      )) || E'\n',
      '' ORDER BY (e ->> 'id') COLLATE "C"
    )) INTO v_go_hash FROM pg_catalog.jsonb_array_elements(v_go_norm) AS t(e);
    v_counts := v_counts || pg_catalog.jsonb_build_object('generated_overlays', v_go_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('generated_overlays', v_go_hash);
  END IF;
  IF v_has_mat THEN
    SELECT * INTO v_mat FROM coherence._cmd_prepare_materialization(v_mat_in, v_run_id, v_ev_id);
    v_mat_batch_id := v_mat.batch_id;
    v_counts := v_counts || v_mat.counts;
    v_hashes := v_hashes || v_mat.hashes;
  END IF;
  IF v_next_req_id IS NOT NULL THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('step_requests', 1);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object(
      'step_requests',
      coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
        v_next_req_id::text, v_run_id::text, v_next_step, 'continue', NULL::text
      )) || E'\n')
    );
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object(
      'attemptEventId', v_ev_id, 'nextRequestId', v_next_req_id,
      'nextStep', CASE WHEN v_next_req_id IS NOT NULL THEN v_next_step ELSE NULL END,
      'materialized', v_has_mat,
      'statementBatchId', v_mat_batch_id
    ),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'finish_attempt', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('attempt_event_id', v_ev_id, 'run_id', v_run_id, 'step', v_step, 'materialized', v_has_mat)
  );
  PERFORM coherence._cmd_insert_stored_files_json(v_new_files, v_seq);

  INSERT INTO coherence.step_attempt_events (
    id, run_id, step, attempt_no, event_kind, census, born,
    log_store_kind, log_file_sha256, artifact_count, artifacts_sha256, journal_seq
  ) VALUES (
    v_ev_id, v_run_id, v_step, v_attempt_no, 'finished', v_census, v_born,
    CASE WHEN v_log_sha IS NOT NULL THEN 'company_data' ELSE NULL END, v_log_sha,
    v_art_cnt, v_arts_hash, v_seq
  );
  IF v_art_cnt > 0 THEN
    INSERT INTO coherence.artifacts (attempt_event_id, rel_path, artifact_kind, store_kind, file_sha256, journal_seq)
    SELECT v_ev_id, e ->> 'rel_path', e ->> 'artifact_kind', e ->> 'store_kind', e ->> 'file_sha256', v_seq
    FROM pg_catalog.jsonb_array_elements(v_arts) AS t(e);
  END IF;
  IF v_rqi_cnt > 0 THEN
    INSERT INTO coherence.review_queue_items (
      attempt_event_id, item_order, run_id, surface, record_id,
      case_kind, subtype, entity, npn, amount, entity_from, npn_from, needs_reconfirm, journal_seq
    )
    SELECT
      v_ev_id, (e ->> 'item_order')::int, v_run_id, e ->> 'surface', e ->> 'record_id',
      e ->> 'case_kind', e ->> 'subtype', e ->> 'entity', e ->> 'npn', e ->> 'amount',
      e ->> 'entity_from', e ->> 'npn_from', (e ->> 'needs_reconfirm')::boolean, v_seq
    FROM pg_catalog.jsonb_array_elements(v_rqi_norm) AS t(e);
  END IF;
  IF v_go_cnt > 0 THEN
    INSERT INTO coherence.generated_overlays (
      id, decision_commit_id, run_id, purpose, attempt_event_id,
      header_contract, row_count, store_kind, file_sha256, journal_seq
    )
    SELECT
      (e ->> 'id')::uuid, (e ->> 'decision_commit_id')::uuid, v_run_id, e ->> 'purpose', v_ev_id,
      e ->> 'header_contract', (e ->> 'row_count')::int, 'company_data', e ->> 'file_sha256', v_seq
    FROM pg_catalog.jsonb_array_elements(v_go_norm) AS t(e);
  END IF;
  IF v_has_mat THEN
    PERFORM coherence._cmd_insert_materialization(v_mat_in, v_mat.sb_norm, v_mat.rm_norm, v_run_id, v_ev_id, v_seq);
  END IF;
  IF v_next_req_id IS NOT NULL THEN
    INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
    VALUES (v_next_req_id, v_run_id, v_next_step, 'continue', NULL, v_seq);
  END IF;

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object(
    'idempotent', false, 'journal_seq', v_seq,
    'attempt_event_id', v_ev_id, 'next_request_id', v_next_req_id,
    'next_step', CASE WHEN v_next_req_id IS NOT NULL THEN v_next_step ELSE NULL END,
    'statement_batch_id', v_mat_batch_id
  );
END;
$$;

-- 7.27 fail_attempt (Worker only)
CREATE OR REPLACE FUNCTION app_cmd.coherence_fail_attempt(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_run_id UUID,
  p_step TEXT,
  p_attempt_no INTEGER,
  p_error_summary TEXT DEFAULT '',
  p_log_file JSONB DEFAULT NULL,
  p_stored_files JSONB DEFAULT '[]'::jsonb,
  p_event_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_ev_id UUID := COALESCE(p_event_id, pg_catalog.gen_random_uuid());
  v_log_sha TEXT := CASE WHEN p_log_file IS NOT NULL AND pg_catalog.jsonb_typeof(p_log_file) = 'object' THEN p_log_file ->> 'sha256' ELSE NULL END;
  v_all_files JSONB := coherence._cmd_jsonb_array(p_stored_files) || CASE WHEN v_log_sha IS NOT NULL THEN pg_catalog.jsonb_build_array(p_log_file) ELSE '[]'::jsonb END;
  v_new_files JSONB;
  v_file_cnt INT;
  v_ev_hash TEXT;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.worker.attempt', 'service_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('fail_attempt', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  v_new_files := coherence._cmd_filter_new_stored_files(v_all_files, 'company_data');
  v_file_cnt := pg_catalog.jsonb_array_length(v_new_files);
  v_ev_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_ev_id::text, p_run_id::text, p_step, p_attempt_no, 'failed',
    NULL::text, NULL::text, NULL::text, v_log_sha, NULL::int, NULL::text
  )) || E'\n');

  v_counts := pg_catalog.jsonb_build_object('step_attempt_events', 1);
  v_hashes := pg_catalog.jsonb_build_object('step_attempt_events', v_ev_hash);
  IF v_file_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('stored_files', v_file_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('stored_files', coherence._cmd_hash_stored_files_json(v_new_files));
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('attemptEventId', v_ev_id),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'fail_attempt', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('attempt_event_id', v_ev_id, 'run_id', p_run_id, 'step', p_step)
  );
  PERFORM coherence._cmd_insert_stored_files_json(v_new_files, v_seq);
  INSERT INTO coherence.step_attempt_events (
    id, run_id, step, attempt_no, event_kind, log_store_kind, log_file_sha256, error_summary, journal_seq
  ) VALUES (
    v_ev_id, p_run_id, p_step, p_attempt_no, 'failed',
    CASE WHEN v_log_sha IS NOT NULL THEN 'company_data' ELSE NULL END, v_log_sha, p_error_summary, v_seq
  );

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'attempt_event_id', v_ev_id);
END;
$$;

-- 7.28 cancel_attempt (Worker only)
CREATE OR REPLACE FUNCTION app_cmd.coherence_cancel_attempt(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_run_id UUID,
  p_step TEXT,
  p_attempt_no INTEGER,
  p_cancel_request_id UUID,
  p_log_file JSONB DEFAULT NULL,
  p_stored_files JSONB DEFAULT '[]'::jsonb,
  p_event_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_ev_id UUID := COALESCE(p_event_id, pg_catalog.gen_random_uuid());
  v_log_sha TEXT := CASE WHEN p_log_file IS NOT NULL AND pg_catalog.jsonb_typeof(p_log_file) = 'object' THEN p_log_file ->> 'sha256' ELSE NULL END;
  v_all_files JSONB := coherence._cmd_jsonb_array(p_stored_files) || CASE WHEN v_log_sha IS NOT NULL THEN pg_catalog.jsonb_build_array(p_log_file) ELSE '[]'::jsonb END;
  v_new_files JSONB;
  v_file_cnt INT;
  v_ev_hash TEXT;
  v_counts JSONB;
  v_hashes JSONB;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.worker.attempt', 'service_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('cancel_attempt', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  v_new_files := coherence._cmd_filter_new_stored_files(v_all_files, 'company_data');
  v_file_cnt := pg_catalog.jsonb_array_length(v_new_files);
  v_ev_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_ev_id::text, p_run_id::text, p_step, p_attempt_no, 'cancelled',
    NULL::text, p_cancel_request_id::text, NULL::text, v_log_sha, NULL::int, NULL::text
  )) || E'\n');

  v_counts := pg_catalog.jsonb_build_object('step_attempt_events', 1);
  v_hashes := pg_catalog.jsonb_build_object('step_attempt_events', v_ev_hash);
  IF v_file_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('stored_files', v_file_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('stored_files', coherence._cmd_hash_stored_files_json(v_new_files));
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('attemptEventId', v_ev_id),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'cancel_attempt', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('attempt_event_id', v_ev_id, 'run_id', p_run_id, 'step', p_step)
  );
  PERFORM coherence._cmd_insert_stored_files_json(v_new_files, v_seq);
  INSERT INTO coherence.step_attempt_events (
    id, run_id, step, attempt_no, event_kind, cancel_request_id, log_store_kind, log_file_sha256, journal_seq
  ) VALUES (
    v_ev_id, p_run_id, p_step, p_attempt_no, 'cancelled', p_cancel_request_id,
    CASE WHEN v_log_sha IS NOT NULL THEN 'company_data' ELSE NULL END, v_log_sha, v_seq
  );

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'attempt_event_id', v_ev_id);
END;
$$;

-- 7.29 interrupt_attempt (Worker only)
CREATE OR REPLACE FUNCTION app_cmd.coherence_interrupt_attempt(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_run_id UUID,
  p_step TEXT,
  p_attempt_no INTEGER,
  p_error_summary TEXT DEFAULT 'Worker connection lost before step completed.',
  p_event_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_ev_id UUID := COALESCE(p_event_id, pg_catalog.gen_random_uuid());
  v_ev_hash TEXT;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.worker.attempt', 'service_only');
  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('interrupt_attempt', p_command_key, v_ctx.actor_label, v_ctx.acting_for_label, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  v_ev_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_ev_id::text, p_run_id::text, p_step, p_attempt_no, 'interrupted',
    NULL::text, NULL::text, NULL::text, NULL::text, NULL::int, NULL::text
  )) || E'\n');
  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('attemptEventId', v_ev_id),
    'commitments', pg_catalog.jsonb_build_object(
      'counts', pg_catalog.jsonb_build_object('step_attempt_events', 1),
      'hashes', pg_catalog.jsonb_build_object('step_attempt_events', v_ev_hash)
    )
  );
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_ctx.actor_label, v_ctx.acting_for_label,
    'interrupt_attempt', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('attempt_event_id', v_ev_id, 'run_id', p_run_id, 'step', p_step)
  );
  INSERT INTO coherence.step_attempt_events (id, run_id, step, attempt_no, event_kind, error_summary, journal_seq)
  VALUES (v_ev_id, p_run_id, p_step, p_attempt_no, 'interrupted', p_error_summary, v_seq);

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'attempt_event_id', v_ev_id);
END;
$$;

-- 7.30 accept_review_submission (Worker only)
CREATE OR REPLACE FUNCTION app_cmd.coherence_accept_review_submission(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_payload JSONB
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_ex RECORD;
  v_sub_id UUID := (p_payload ->> 'submission_id')::uuid;
  v_sub RECORD;
  v_rs_id UUID := COALESCE((p_payload ->> 'review_save_id')::uuid, pg_catalog.gen_random_uuid());
  v_adj_req_id UUID := COALESCE((p_payload ->> 'adjust_request_id')::uuid, pg_catalog.gen_random_uuid());
  v_attempt_id UUID;
  v_sup_id UUID := NULL;
  v_sup_attempt INT := NULL;
  v_sf JSONB := p_payload -> 'stored_file';
  v_sha TEXT := v_sf ->> 'sha256';
  v_hk TEXT := p_payload ->> 'header_kind';
  v_rc INT := (p_payload ->> 'row_count')::int;
  v_ext TEXT := p_payload ->> 'extends_sha256';
  v_shared INT := COALESCE((p_payload ->> 'shared_row_count')::int, 0);
  v_rows JSONB := coherence._cmd_jsonb_array(p_payload -> 'added_rows');
  v_row_cnt INT := pg_catalog.jsonb_array_length(v_rows);
  v_rows_hash TEXT;
  v_new_files JSONB;
  v_file_cnt INT;
  v_af_exists BOOLEAN;
  v_rs_hash TEXT;
  v_counts JSONB := '{}'::jsonb;
  v_hashes JSONB := '{}'::jsonb;
  v_body JSONB;
  v_seq BIGINT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.worker.review', 'service_only');

  SELECT * INTO v_sub FROM coherence.review_submissions WHERE id = v_sub_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'NOT_FOUND: review submission does not exist.' USING ERRCODE = 'P0002'; END IF;

  SELECT * INTO v_ex FROM coherence._cmd_check_idempotency('save_review', p_command_key, v_sub.actor, v_sub.acting_for, p_request_sha256);
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_ex.existing_seq, 'result', v_ex.existing_body -> 'result');
  END IF;

  IF v_sub.status <> 'pending' THEN RAISE EXCEPTION 'SUBMISSION_ALREADY_RESOLVED: submission is %.', v_sub.status USING ERRCODE = '23514'; END IF;

  IF v_sf IS NULL OR pg_catalog.jsonb_typeof(v_sf) <> 'object' OR v_sha IS DISTINCT FROM v_sub.staged_sha256 THEN
    RAISE EXCEPTION 'STAGED_SHA256_MISMATCH: stored_file sha256 (%) does not match submission staged_sha256 (%).',
      COALESCE(v_sha, '<null>'), v_sub.staged_sha256
      USING ERRCODE = '23514';
  END IF;

  -- Re-check expected_journal_seq inside acceptance transaction (40001 when run changed while queued).
  PERFORM coherence._cmd_check_expected_seq(v_sub.expected_journal_seq, v_sub.run_id, false, false);

  v_attempt_id := coherence.current_finished_attempt(v_sub.run_id, v_sub.surface);
  IF v_attempt_id IS NULL THEN RAISE EXCEPTION 'NO_FINISHED_ATTEMPT: no finished % attempt.', v_sub.surface USING ERRCODE = '23514'; END IF;

  v_new_files := coherence._cmd_filter_new_stored_files(pg_catalog.jsonb_build_array(v_sf), 'company_data');
  v_file_cnt := pg_catalog.jsonb_array_length(v_new_files);
  SELECT EXISTS (SELECT 1 FROM coherence.approvals_files WHERE file_sha256 = v_sha) INTO v_af_exists;

  SELECT coherence.sha256_text(COALESCE(pg_catalog.string_agg(
    coherence.canonical_json(pg_catalog.jsonb_build_array(
      (e ->> 'row_no')::int, e ->> 'record_id', e ->> 'disposition', e ->> 'agent', e ->> 'agency',
      e ->> 'policy', e ->> 'book', e ->> 'month', e ->> 'status', e ->> 'note', e ->> 'committed_at',
      e ->> 'approved_amount', e ->> 'approved_agency', e ->> 'approved_agent',
      e ->> 'approved_agency_from', e ->> 'approved_agent_from'
    )) || E'\n',
    '' ORDER BY (e ->> 'row_no')::int ASC
  ), '')) INTO v_rows_hash FROM pg_catalog.jsonb_array_elements(v_rows) AS t(e);

  v_rs_hash := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
    v_rs_id::text, v_sub.run_id::text, v_sub.surface, v_attempt_id::text,
    v_sha, NULL::text, false, NULL::text, v_sub_id::text
  )) || E'\n');

  v_counts := pg_catalog.jsonb_build_object('review_saves', 1);
  v_hashes := pg_catalog.jsonb_build_object('review_saves', v_rs_hash);
  IF v_file_cnt > 0 THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('stored_files', v_file_cnt);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object('stored_files', coherence._cmd_hash_stored_files_json(v_new_files));
  END IF;
  IF NOT v_af_exists THEN
    v_counts := v_counts || pg_catalog.jsonb_build_object('approvals_files', 1);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object(
      'approvals_files',
      coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
        v_sha, v_hk, v_rc, v_ext, v_shared, v_rows_hash
      )) || E'\n')
    );
    IF v_row_cnt > 0 THEN
      v_counts := v_counts || pg_catalog.jsonb_build_object('approval_rows', v_row_cnt);
      v_hashes := v_hashes || pg_catalog.jsonb_build_object('approval_rows', v_rows_hash);
    END IF;
  END IF;
  IF v_sub.surface = 'bible' THEN
    SELECT attempt_no INTO v_sup_attempt
    FROM coherence.step_attempt_events
    WHERE id = coherence.current_finished_attempt(v_sub.run_id, 'adjust');
    IF v_sup_attempt IS NOT NULL THEN
      v_sup_id := pg_catalog.gen_random_uuid();
      v_counts := v_counts || pg_catalog.jsonb_build_object('step_attempt_events', 1);
      v_hashes := v_hashes || pg_catalog.jsonb_build_object(
        'step_attempt_events',
        coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
          v_sup_id::text, v_sub.run_id::text, 'adjust', v_sup_attempt, 'superseded',
          NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer, NULL::text
        )) || E'\n')
      );
    END IF;
    v_counts := v_counts || pg_catalog.jsonb_build_object('step_requests', 1);
    v_hashes := v_hashes || pg_catalog.jsonb_build_object(
      'step_requests',
      coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_array(
        v_adj_req_id::text, v_sub.run_id::text, 'adjust', 'bible_saved', NULL::text
      )) || E'\n')
    );
  END IF;

  v_body := pg_catalog.jsonb_build_object(
    'result', pg_catalog.jsonb_build_object('reviewSaveId', v_rs_id, 'submissionId', v_sub_id),
    'commitments', pg_catalog.jsonb_build_object('counts', v_counts, 'hashes', v_hashes)
  );
  -- Record the submitting human in coherence.journal_entries while platform.audit_journal records the service principal.
  v_seq := coherence._cmd_write_journals(
    v_ctx.environment, v_ctx.tenant_org_id, v_ctx.actor_person_id, v_ctx.recorded_as,
    v_sub.actor, v_sub.acting_for,
    'save_review', p_command_key, p_request_sha256, v_body,
    pg_catalog.jsonb_build_object('submission_id', v_sub_id, 'review_save_id', v_rs_id, 'submitting_actor', v_sub.actor)
  );
  PERFORM coherence._cmd_insert_stored_files_json(v_new_files, v_seq);

  IF NOT v_af_exists THEN
    INSERT INTO coherence.approvals_files (file_sha256, store_kind, header_kind, row_count, extends_sha256, shared_row_count, added_rows_sha256, journal_seq)
    VALUES (v_sha, 'company_data', v_hk, v_rc, v_ext, v_shared, v_rows_hash, v_seq);
    IF v_row_cnt > 0 THEN
      INSERT INTO coherence.approval_rows (
        approvals_file_sha256, row_no, record_id, disposition, agent, agency, policy, book,
        month, status, note, committed_at, approved_amount, approved_agency, approved_agent,
        approved_agency_from, approved_agent_from, journal_seq
      )
      SELECT
        v_sha, (e ->> 'row_no')::int, e ->> 'record_id', e ->> 'disposition', e ->> 'agent', e ->> 'agency',
        e ->> 'policy', e ->> 'book', e ->> 'month', e ->> 'status', e ->> 'note', e ->> 'committed_at',
        e ->> 'approved_amount', e ->> 'approved_agency', e ->> 'approved_agent',
        e ->> 'approved_agency_from', e ->> 'approved_agent_from', v_seq
      FROM pg_catalog.jsonb_array_elements(v_rows) AS t(e);
    END IF;
  END IF;

  INSERT INTO coherence.review_saves (id, run_id, surface, attempt_event_id, approvals_file_sha256, imported, submission_id, journal_seq)
  VALUES (v_rs_id, v_sub.run_id, v_sub.surface, v_attempt_id, v_sha, false, v_sub_id, v_seq);

  IF v_sup_id IS NOT NULL THEN
    INSERT INTO coherence.step_attempt_events (id, run_id, step, attempt_no, event_kind, journal_seq)
    VALUES (v_sup_id, v_sub.run_id, 'adjust', v_sup_attempt, 'superseded', v_seq);
  END IF;

  IF v_sub.surface = 'bible' THEN
    INSERT INTO coherence.step_requests (id, run_id, step, reason, emit_confirmation_id, journal_seq)
    VALUES (v_adj_req_id, v_sub.run_id, 'adjust', 'bible_saved', NULL, v_seq);
  END IF;

  UPDATE coherence.review_submissions
  SET status = 'accepted', review_save_id = v_rs_id, result_journal_seq = v_seq,
      result_message = 'Review saved.', resolved_at = pg_catalog.clock_timestamp()
  WHERE id = v_sub_id;

  SET CONSTRAINTS ALL IMMEDIATE;
  SET CONSTRAINTS ALL DEFERRED;
  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'review_save_id', v_rs_id);
END;
$$;

-- 7.31 reject_review_submission (Worker only)
CREATE OR REPLACE FUNCTION app_cmd.coherence_reject_review_submission(
  p_submission_id UUID,
  p_status TEXT DEFAULT 'rejected',
  p_reason TEXT DEFAULT 'Review file rejected.'
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_sub RECORD;
  v_audit_key TEXT;
  v_req_sha TEXT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.worker.review', 'service_only');
  IF p_status NOT IN ('rejected', 'failed') THEN
    RAISE EXCEPTION 'INVALID_STATUS: rejection status must be rejected or failed.' USING ERRCODE = '22023';
  END IF;
  UPDATE coherence.review_submissions
  SET status = p_status, result_message = p_reason, resolved_at = pg_catalog.clock_timestamp()
  WHERE id = p_submission_id AND status = 'pending'
  RETURNING id, run_id, surface INTO v_sub;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SUBMISSION_NOT_PENDING: submission % not found or already resolved.', p_submission_id USING ERRCODE = '23514';
  END IF;

  v_audit_key := 'coherence:rej:' || p_submission_id::text;
  v_req_sha := coherence.sha256_text(coherence.canonical_json(pg_catalog.jsonb_build_object(
    'submission_id', p_submission_id::text, 'status', p_status, 'reason', p_reason
  )));
  INSERT INTO platform.audit_journal (
    environment, actor_person_id, recorded_as, target_org_id,
    command_kind, command_key, request_sha256, body
  ) VALUES (
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, v_ctx.tenant_org_id,
    'coherence.reject_review_submission', v_audit_key, v_req_sha,
    pg_catalog.jsonb_build_object('submission_id', p_submission_id, 'run_id', v_sub.run_id, 'surface', v_sub.surface, 'status', p_status, 'reason', p_reason)
  );

  RETURN pg_catalog.jsonb_build_object('submission_id', p_submission_id, 'status', p_status);
END;
$$;

-- 7.32 expire_old_drafts (Worker only)
CREATE OR REPLACE FUNCTION app_cmd.coherence_expire_old_drafts()
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_deleted INT;
BEGIN
  SELECT * INTO v_ctx FROM coherence._cmd_resolve_context('act:coherence.worker.attempt', 'service_only');
  DELETE FROM coherence.review_drafts WHERE expires_at <= pg_catalog.clock_timestamp();
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN pg_catalog.jsonb_build_object('deleted', v_deleted);
END;
$$;

-- Assign ownership of all 32 app_cmd.coherence_* functions to platform_writer and configure exact EXECUTE grants.
DO $$
DECLARE
  v_sig TEXT;
BEGIN
  -- Human-callable operator and owner commands (20 commands): EXECUTE for platform_app only.
  FOREACH v_sig IN ARRAY ARRAY[
    'app_cmd.coherence_init_company(text, text, text, text, text, text, text[], text[])',
    'app_cmd.coherence_register_engine_version(text, text, jsonb)',
    'app_cmd.coherence_register_approvals_file(text, text, jsonb, text, integer, text, integer, jsonb)',
    'app_cmd.coherence_publish_input_version(text, text, bigint, text, text, text, jsonb, jsonb, jsonb, text, uuid)',
    'app_cmd.coherence_include_staging_file(text, text, bigint, text, text, text, uuid)',
    'app_cmd.coherence_launch_run(text, text, bigint, date, uuid, text, uuid, uuid, text, text, text[], text[], uuid, uuid, text, uuid, uuid)',
    'app_cmd.coherence_request_cancel(text, text, bigint, uuid, text, integer, text, text, uuid)',
    'app_cmd.coherence_request_retry(text, text, bigint, uuid, text, uuid)',
    'app_cmd.coherence_submit_review(text, text, bigint, uuid, text, text, uuid)',
    'app_cmd.coherence_save_review_draft(uuid, text, integer, text, jsonb, text)',
    'app_cmd.coherence_save_review_decisions(text, text, bigint, uuid, text, jsonb, uuid, uuid, uuid)',
    'app_cmd.coherence_confirm_emit(text, text, bigint, uuid, uuid, text, uuid, uuid)',
    'app_cmd.coherence_carry_sent(text, text, bigint, uuid, text, text, uuid, uuid, jsonb)',
    'app_cmd.coherence_carry_approvals(text, text, bigint, uuid, text, uuid, uuid)',
    'app_cmd.coherence_carry_decisions(text, text, bigint, uuid, text, text, uuid)',
    'app_cmd.coherence_abandon_run(text, text, bigint, uuid, text, text, uuid)',
    'app_cmd.coherence_record_decision_baseline(text, text, jsonb)',
    'app_cmd.coherence_record_statement_batch(text, text, jsonb)',
    'app_cmd.coherence_import_standalone_files(text, text, jsonb)',
    'app_cmd.coherence_import_historical_run(text, text, jsonb)'
  ] LOOP
    EXECUTE 'ALTER FUNCTION ' || v_sig || ' OWNER TO platform_writer';
    EXECUTE 'REVOKE ALL ON FUNCTION ' || v_sig || ' FROM PUBLIC';
    EXECUTE 'GRANT EXECUTE ON FUNCTION ' || v_sig || ' TO platform_app';
  END LOOP;

  -- Worker-or-Owner commands (4 commands): EXECUTE for platform_app and platform_worker.
  FOREACH v_sig IN ARRAY ARRAY[
    'app_cmd.coherence_register_stored_files(text, text, jsonb)',
    'app_cmd.coherence_record_check(text, text, text, boolean, jsonb, uuid, uuid, uuid)',
    'app_cmd.coherence_record_generated_overlay(text, text, uuid, uuid, text, text, integer, jsonb, uuid, uuid)',
    'app_cmd.coherence_materialize_emit(text, text, jsonb)'
  ] LOOP
    EXECUTE 'ALTER FUNCTION ' || v_sig || ' OWNER TO platform_writer';
    EXECUTE 'REVOKE ALL ON FUNCTION ' || v_sig || ' FROM PUBLIC';
    EXECUTE 'GRANT EXECUTE ON FUNCTION ' || v_sig || ' TO platform_app, platform_worker';
  END LOOP;

  -- Worker-only commands (8 commands): EXECUTE strictly for platform_worker (NEVER platform_app or PUBLIC).
  FOREACH v_sig IN ARRAY ARRAY[
    'app_cmd.coherence_start_attempt(text, text, uuid, text, uuid, uuid)',
    'app_cmd.coherence_finish_attempt(text, text, jsonb)',
    'app_cmd.coherence_fail_attempt(text, text, uuid, text, integer, text, jsonb, jsonb, uuid)',
    'app_cmd.coherence_cancel_attempt(text, text, uuid, text, integer, uuid, jsonb, jsonb, uuid)',
    'app_cmd.coherence_interrupt_attempt(text, text, uuid, text, integer, text, uuid)',
    'app_cmd.coherence_accept_review_submission(text, text, jsonb)',
    'app_cmd.coherence_reject_review_submission(uuid, text, text)',
    'app_cmd.coherence_expire_old_drafts()'
  ] LOOP
    EXECUTE 'ALTER FUNCTION ' || v_sig || ' OWNER TO platform_writer';
    EXECUTE 'REVOKE ALL ON FUNCTION ' || v_sig || ' FROM PUBLIC, platform_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION ' || v_sig || ' TO platform_worker';
  END LOOP;
END;
$$;

-- 8. Final least-privilege grants and complete base-table lockdown for platform_app and PUBLIC.
-- Zero blanket GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA coherence: every platform role holds
-- strictly its explicit function list, only platform_migrator (plus owner platform_versioner)
-- may execute coherence.backfill_iam_foreign_keys, and platform_worker holds SELECT only on
-- Coherence domain tables (zero INSERT/UPDATE/DELETE, zero schema_migrations access).
DO $$
DECLARE
  v_tbl TEXT;
  v_role TEXT;
BEGIN
  GRANT USAGE ON SCHEMA app_cmd TO platform_app, platform_worker, platform_writer;
  GRANT USAGE ON SCHEMA coherence TO platform_versioner, platform_migrator, platform_worker, platform_readonly;

  -- platform_versioner: minimum read/update rights for backfill_iam_foreign_keys()
  GRANT SELECT ON
    iam.database_context,
    iam.organizations, iam.organization_versions, iam.organization_edges, iam.v_organization_closure,
    iam.people, iam.person_versions, iam.agent_affiliations
  TO platform_versioner;
  GRANT EXECUTE ON FUNCTION iam.business_today(TIMESTAMPTZ) TO platform_versioner;

  FOREACH v_tbl IN ARRAY ARRAY[
    'bob_policies', 'bob_policy_financials',
    'statement_agency_lines', 'statement_upline_lines', 'coherent_ledger_rows'
  ] LOOP
    EXECUTE pg_catalog.format(
      'GRANT SELECT, UPDATE (organization_id, writing_person_id) ON coherence.%I TO platform_versioner',
      v_tbl
    );
  END LOOP;

  -- Explicit read-only/hash helper functions + single IAM FK resolvers for platform_writer (NEVER backfill).
  GRANT EXECUTE ON FUNCTION
    coherence._resolve_tenant_tree_org_ids(),
    coherence._resolve_entity_org_id(TEXT, TEXT, JSONB),
    coherence._resolve_writing_person_id(TEXT, TEXT, JSONB),
    coherence.slot_class_id(),
    coherence.slot_obj_id(),
    coherence.this_connection_holds_slot(),
    coherence.slot_is_free(),
    coherence.own_backend_start(),
    coherence.canonical_json(JSONB),
    coherence.sha256_text(TEXT),
    coherence.format_utc_us(TIMESTAMPTZ),
    coherence.compute_journal_hash(BIGINT, TIMESTAMPTZ, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB),
    coherence.approvals_extends(TEXT, TEXT),
    coherence.is_code_bearing_path(TEXT),
    coherence.step_rank(TEXT),
    coherence.hash_input_entries(UUID),
    coherence.hash_input_changes(UUID),
    coherence.hash_artifacts(UUID),
    coherence.hash_approval_rows(TEXT),
    coherence.run_has_open_attempt(UUID),
    coherence.company_has_open_attempt(),
    coherence.run_has_open_request(UUID),
    coherence.current_finished_attempt(UUID, TEXT),
    coherence.run_stage(UUID, BIGINT),
    coherence.run_latest_journal_seq(UUID),
    coherence.approvals_full_rows(TEXT),
    coherence.approvals_current(TEXT),
    coherence.approvals_bible_applied(TEXT, TEXT[]),
    coherence.standing_input_version_as_of(BIGINT),
    coherence.hash_decisions(UUID),
    coherence.decision_commit_extends(UUID, UUID),
    coherence.decisions_in_commit(UUID),
    coherence.decisions_current(UUID),
    coherence.decisions_bible_applied(UUID, TEXT[]),
    coherence.standing_decision_head_as_of(BIGINT),
    coherence.fmt_num2(NUMERIC),
    coherence.fmt_date(DATE),
    coherence.hash_statement_agency_lines(UUID),
    coherence.hash_statement_upline_lines(UUID),
    coherence.hash_bob_rows(UUID),
    coherence.hash_ledger_rows(UUID),
    coherence.run_effective_statement_batches(UUID)
  TO platform_writer;

  -- platform_readonly: SELECT on Coherence tables + explicit read-only helpers.
  GRANT SELECT ON ALL TABLES IN SCHEMA coherence TO platform_readonly;
  GRANT EXECUTE ON FUNCTION
    coherence.slot_class_id(),
    coherence.slot_obj_id(),
    coherence.this_connection_holds_slot(),
    coherence.slot_is_free(),
    coherence.own_backend_start(),
    coherence.canonical_json(JSONB),
    coherence.sha256_text(TEXT),
    coherence.format_utc_us(TIMESTAMPTZ),
    coherence.compute_journal_hash(BIGINT, TIMESTAMPTZ, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB),
    coherence.approvals_extends(TEXT, TEXT),
    coherence.is_code_bearing_path(TEXT),
    coherence.step_rank(TEXT),
    coherence.hash_input_entries(UUID),
    coherence.hash_input_changes(UUID),
    coherence.hash_artifacts(UUID),
    coherence.hash_approval_rows(TEXT),
    coherence.run_has_open_attempt(UUID),
    coherence.company_has_open_attempt(),
    coherence.run_has_open_request(UUID),
    coherence.current_finished_attempt(UUID, TEXT),
    coherence.run_stage(UUID, BIGINT),
    coherence.run_latest_journal_seq(UUID),
    coherence.approvals_full_rows(TEXT),
    coherence.approvals_current(TEXT),
    coherence.approvals_bible_applied(TEXT, TEXT[]),
    coherence.standing_input_version_as_of(BIGINT),
    coherence.hash_decisions(UUID),
    coherence.decision_commit_extends(UUID, UUID),
    coherence.decisions_in_commit(UUID),
    coherence.decisions_current(UUID),
    coherence.decisions_bible_applied(UUID, TEXT[]),
    coherence.standing_decision_head_as_of(BIGINT),
    coherence.fmt_num2(NUMERIC),
    coherence.fmt_date(DATE),
    coherence.hash_statement_agency_lines(UUID),
    coherence.hash_statement_upline_lines(UUID),
    coherence.hash_bob_rows(UUID),
    coherence.hash_ledger_rows(UUID),
    coherence.run_effective_statement_batches(UUID)
  TO platform_readonly;

  -- platform_worker: strictly SELECT on Coherence domain tables + run_states (ZERO INSERT/UPDATE/DELETE,
  -- ZERO schema_migrations access) + explicit read-only/slot helpers. All worker writes go through app_cmd.*.
  FOREACH v_tbl IN ARRAY ARRAY[
    'journal_entries', 'company_meta', 'stored_files', 'engine_versions',
    'input_versions', 'input_entries', 'input_changes',
    'approvals_files', 'approval_rows',
    'decision_commits', 'decisions', 'generated_overlays', 'review_queue_items',
    'runs', 'step_requests', 'cancel_requests', 'step_attempt_events', 'artifacts',
    'review_saves', 'emit_confirmations',
    'statement_batches', 'statement_agency_lines', 'statement_upline_lines',
    'run_materializations', 'bob_policies', 'bob_policy_financials', 'coherent_ledger_rows',
    'carries', 'abandonments', 'imported_files', 'checks',
    'review_submissions', 'review_drafts'
  ] LOOP
    EXECUTE pg_catalog.format('GRANT SELECT ON coherence.%I TO platform_worker', v_tbl);
  END LOOP;
  GRANT SELECT ON coherence.run_states TO platform_worker;
  GRANT EXECUTE ON FUNCTION
    coherence.slot_class_id(),
    coherence.slot_obj_id(),
    coherence.this_connection_holds_slot(),
    coherence.slot_is_free(),
    coherence.own_backend_start(),
    coherence.canonical_json(JSONB),
    coherence.sha256_text(TEXT),
    coherence.format_utc_us(TIMESTAMPTZ),
    coherence.is_code_bearing_path(TEXT),
    coherence.step_rank(TEXT),
    coherence.run_has_open_attempt(UUID),
    coherence.company_has_open_attempt(),
    coherence.run_has_open_request(UUID),
    coherence.current_finished_attempt(UUID, TEXT),
    coherence.run_stage(UUID, BIGINT),
    coherence.run_latest_journal_seq(UUID),
    coherence.approvals_full_rows(TEXT),
    coherence.approvals_current(TEXT),
    coherence.approvals_bible_applied(TEXT, TEXT[]),
    coherence.standing_input_version_as_of(BIGINT),
    coherence.decisions_in_commit(UUID),
    coherence.decisions_current(UUID),
    coherence.decisions_bible_applied(UUID, TEXT[]),
    coherence.standing_decision_head_as_of(BIGINT),
    coherence.fmt_num2(NUMERIC),
    coherence.fmt_date(DATE),
    coherence.run_effective_statement_batches(UUID)
  TO platform_worker;

  -- Strictly platform_migrator (plus function owner platform_versioner) may run backfill_iam_foreign_keys.
  GRANT EXECUTE ON FUNCTION coherence.backfill_iam_foreign_keys(JSONB, JSONB) TO platform_migrator;

  -- Revoke PUBLIC (and non-owning platform roles) from all internal/trigger/backfill functions added in 009.
  REVOKE ALL ON FUNCTION
    coherence.forbid_mutation(),
    coherence.guard_iam_fk_backfill(),
    coherence.trg_bob_policy_financials_before(),
    coherence._resolve_tenant_tree_org_ids(),
    coherence._resolve_entity_org_id(TEXT, TEXT, JSONB),
    coherence._resolve_writing_person_id(TEXT, TEXT, JSONB),
    coherence.backfill_iam_foreign_keys(JSONB, JSONB),
    coherence._cmd_resolve_context(TEXT, TEXT),
    coherence._cmd_check_idempotency(TEXT, TEXT, TEXT, TEXT, TEXT),
    coherence._cmd_check_expected_seq(BIGINT, UUID, BOOLEAN, BOOLEAN),
    coherence._cmd_write_journals(TEXT, UUID, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB),
    coherence._cmd_jsonb_array(JSONB),
    coherence._cmd_jsonb_object(JSONB),
    coherence._cmd_assert_tenant_orgs(JSONB, TEXT),
    coherence._cmd_filter_new_stored_files(JSONB, TEXT),
    coherence._cmd_hash_stored_files_json(JSONB),
    coherence._cmd_insert_stored_files_json(JSONB, BIGINT),
    coherence._cmd_prepare_materialization(JSONB, UUID, UUID),
    coherence._cmd_insert_materialization(JSONB, JSONB, JSONB, UUID, UUID, BIGINT)
  FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION
    coherence._resolve_tenant_tree_org_ids(),
    coherence._resolve_entity_org_id(TEXT, TEXT, JSONB),
    coherence._resolve_writing_person_id(TEXT, TEXT, JSONB)
  TO platform_writer;

  -- Hard lockdown: revoke EVERY Coherence privilege from platform_app and PUBLIC,
  -- and revoke any leftover privileges from retired pre-IAM roles if present cluster-wide.
  REVOKE ALL ON SCHEMA coherence FROM PUBLIC, platform_app;
  REVOKE ALL ON ALL TABLES IN SCHEMA coherence FROM PUBLIC, platform_app;
  REVOKE ALL ON ALL SEQUENCES IN SCHEMA coherence FROM PUBLIC, platform_app;
  REVOKE ALL ON ALL FUNCTIONS IN SCHEMA coherence FROM PUBLIC, platform_app;
  REVOKE CREATE ON SCHEMA app_views, app_cmd FROM PUBLIC, platform_app;
  FOREACH v_role IN ARRAY ARRAY[
    'coherence_app', 'coherence_worker', 'coherence_readonly',
    'coherence_entity_manager_ro', 'coherence_agency_manager_ro',
    'coherence_agent_ro', 'coherence_retention_ro', 'coherence_investor_ro'
  ] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
      EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA coherence, platform, iam, iam_secret, app_views, app_cmd FROM %I', v_role);
      EXECUTE pg_catalog.format('REVOKE ALL ON ALL TABLES IN SCHEMA coherence, platform, iam, iam_secret, app_views, app_cmd FROM %I', v_role);
      EXECUTE pg_catalog.format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA coherence, platform, iam, iam_secret, app_views, app_cmd FROM %I', v_role);
      EXECUTE pg_catalog.format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA coherence, platform, iam, iam_secret, app_views, app_cmd FROM %I', v_role);
    END IF;
  END LOOP;
END;
$$;
