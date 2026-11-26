-- Migration 010: Complete app_views.* runtime read surface (Coherence + Release E5 IAM views)
-- and write command gates (check-run authorization + Release E5 app_cmd.iam_* commands).
-- Ensures src/web/handlers.mjs, src/readers/downstream-reader.mjs, and src/commands/* execute
-- strictly as platform_app via withRequestTx(pool, dbToken, fn), reading ONLY through app_views.*
-- (security_barrier=true, owned by NOBYPASSRLS platform_view_owner) and writing ONLY through
-- app_cmd.* (SECURITY DEFINER, owned by platform_writer), with ZERO base-table privileges for
-- platform_app and ZERO SET LOCAL ROLE.
-- All functions pin SET search_path = pg_catalog and schema-qualify all references.

-- 1. IAM-scoped platform_view_owner FOR SELECT RLS policies on the remaining Coherence tables
--    required by runtime web handlers and downstream readers (sharing app_views._read_* checks).
CREATE POLICY stored_files_iam_read ON coherence.stored_files
  FOR SELECT TO platform_view_owner
  USING (
    (
      store_kind = 'company_data'
      AND (
        (SELECT app_views._read_workshop_right('act:coherence.inputs.read'))
        OR (SELECT app_views._read_workshop_right('act:coherence.runs.read'))
        OR (SELECT app_views._read_has_full_tenant_right('act:coherence.outputs.read'))
        OR (
          (SELECT app_views._read_workshop_right('act:coherence.decisions.read'))
          AND (SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi'))
        )
        OR (SELECT app_views._read_has_full_entity_finance())
      )
    )
    OR (
      store_kind = 'nusear_code'
      AND (
        (
          (SELECT app_views._read_workshop_right('act:coherence.decisions.read'))
          AND (SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi'))
        )
        OR (SELECT app_views._read_has_full_entity_finance())
      )
    )
  );

CREATE POLICY input_changes_iam_read ON coherence.input_changes
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.inputs.read')));

CREATE POLICY imported_files_iam_read ON coherence.imported_files
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.inputs.read')));

CREATE POLICY engine_versions_iam_read ON coherence.engine_versions
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.runs.read')));

CREATE POLICY approvals_files_iam_read ON coherence.approvals_files
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT app_views._read_workshop_right('act:coherence.decisions.read'))
    OR (SELECT app_views._read_workshop_right('act:coherence.runs.read'))
  );

CREATE POLICY approval_rows_iam_read ON coherence.approval_rows
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_workshop_right('act:coherence.decisions.read')));

CREATE POLICY review_submissions_iam_read ON coherence.review_submissions
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT app_views._read_workshop_right('act:coherence.decisions.read'))
    AND (SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi'))
  );

CREATE POLICY review_drafts_iam_read ON coherence.review_drafts
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT app_views._read_workshop_right('act:coherence.decisions.read'))
    AND (SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi'))
  );

CREATE POLICY artifacts_iam_read ON coherence.artifacts
  FOR SELECT TO platform_view_owner
  USING (
    (
      artifact_kind = 'data'
      AND store_kind = 'company_data'
      AND (
        (SELECT app_views._read_has_full_tenant_right('act:coherence.outputs.read'))
        OR (
          (SELECT app_views._read_workshop_right('act:coherence.decisions.read'))
          AND (SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi'))
        )
        OR (SELECT app_views._read_has_full_entity_finance())
      )
    )
    OR (
      rel_path IN ('bible.json', 'bible.html', 'adjust.json', 'adjust.html')
      AND (SELECT app_views._read_workshop_right('act:coherence.decisions.read'))
      AND (SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi'))
    )
    OR (
      rel_path LIKE 'emits/bundles/entity-managers/%/viewer.html'
      AND (SELECT app_views._read_has_full_entity_finance())
    )
  );

GRANT SELECT ON
  coherence.stored_files,
  coherence.input_changes,
  coherence.imported_files,
  coherence.engine_versions,
  coherence.approvals_files,
  coherence.approval_rows,
  coherence.review_submissions,
  coherence.review_drafts,
  coherence.artifacts
TO platform_view_owner;

-- 2. Security-barrier views in app_views.*, owned by NOBYPASSRLS platform_view_owner.
CREATE OR REPLACE VIEW app_views.coherence_input_changes
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT (
    app_views._read_has_full_tenant_right('col:coherence.member_phi')
    AND app_views._read_has_full_tenant_right('col:coherence.member_contact')
  ) AS show_file_handle
)
SELECT
  ic.input_version_id,
  ic.rel_path,
  ic.change_kind,
  ic.old_rel_path,
  ic.store_kind,
  CASE WHEN s.show_file_handle THEN ic.file_sha256 ELSE NULL END AS file_sha256,
  CASE WHEN s.show_file_handle THEN ic.prev_file_sha256 ELSE NULL END AS prev_file_sha256,
  ic.journal_seq
FROM coherence.input_changes ic
CROSS JOIN scopes s;

CREATE OR REPLACE VIEW app_views.coherence_input_entries
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT (
    app_views._read_has_full_tenant_right('col:coherence.member_phi')
    AND app_views._read_has_full_tenant_right('col:coherence.member_contact')
  ) AS show_file_handle
)
SELECT
  ie.input_version_id,
  ie.rel_path,
  ie.mac_key,
  ie.store_kind,
  CASE WHEN s.show_file_handle THEN ie.file_sha256 ELSE NULL END AS file_sha256,
  sf.byte_size,
  CASE WHEN s.show_file_handle THEN sf.md5_b64 ELSE NULL END AS md5_b64,
  CASE WHEN s.show_file_handle THEN sf.crc32c_b64 ELSE NULL END AS crc32c_b64,
  ie.journal_seq
FROM coherence.input_entries ie
JOIN coherence.stored_files sf
  ON sf.store_kind = ie.store_kind
 AND sf.sha256 = ie.file_sha256
CROSS JOIN scopes s
WHERE ie.store_kind = 'company_data';

CREATE OR REPLACE VIEW app_views.coherence_staging_files
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT (
    app_views._read_has_full_tenant_right('col:coherence.member_phi')
    AND app_views._read_has_full_tenant_right('col:coherence.member_contact')
  ) AS show_file_handle
)
SELECT
  f.id,
  f.rel_path,
  CASE WHEN s.show_file_handle THEN f.file_sha256 ELSE NULL END AS file_sha256,
  f.original_at,
  f.metadata,
  sf.byte_size,
  CASE WHEN s.show_file_handle THEN sf.md5_b64 ELSE NULL END AS md5_b64,
  CASE WHEN s.show_file_handle THEN sf.crc32c_b64 ELSE NULL END AS crc32c_b64,
  f.journal_seq
FROM coherence.imported_files f
JOIN coherence.stored_files sf
  ON sf.store_kind = f.store_kind
 AND sf.sha256 = f.file_sha256
CROSS JOIN scopes s
WHERE f.area = 'staging'
  AND f.store_kind = 'company_data';

CREATE OR REPLACE VIEW app_views.coherence_engine_versions
WITH (security_barrier = true) AS
SELECT
  ev.id,
  ev.label,
  ev.coherence_commit,
  ev.nusear_commit,
  ev.engine_kind,
  ev.code_manifest_sha256,
  ev.wrapper_bundle_sha256,
  ev.journal_seq
FROM coherence.engine_versions ev;

CREATE OR REPLACE VIEW app_views.coherence_step_attempt_events
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi') AS show_member_phi
)
SELECT
  e.id,
  e.run_id,
  e.step,
  e.attempt_no,
  e.event_kind,
  e.step_request_id,
  e.cancel_request_id,
  e.census,
  e.born,
  e.log_store_kind,
  CASE WHEN s.show_member_phi THEN e.log_file_sha256 ELSE NULL END AS log_file_sha256,
  sf.byte_size AS log_byte_size,
  CASE WHEN s.show_member_phi THEN sf.md5_b64 ELSE NULL END AS log_md5_b64,
  CASE WHEN s.show_member_phi THEN sf.crc32c_b64 ELSE NULL END AS log_crc32c_b64,
  CASE WHEN s.show_member_phi THEN e.error_summary ELSE NULL END AS error_summary,
  e.artifact_count,
  e.artifacts_sha256,
  e.original_at,
  e.journal_seq
FROM coherence.step_attempt_events e
LEFT JOIN coherence.stored_files sf
  ON sf.store_kind = 'company_data'
 AND sf.sha256 = e.log_file_sha256
CROSS JOIN scopes s
WHERE (SELECT app_views._read_workshop_right('act:coherence.runs.read'));

CREATE OR REPLACE VIEW app_views.coherence_step_requests
WITH (security_barrier = true) AS
SELECT
  sr.id,
  sr.run_id,
  sr.step,
  sr.reason,
  sr.emit_confirmation_id,
  sr.journal_seq
FROM coherence.step_requests sr;

CREATE OR REPLACE VIEW app_views.coherence_cancel_requests
WITH (security_barrier = true) AS
SELECT
  cr.id,
  cr.run_id,
  cr.step,
  cr.attempt_no,
  cr.typed_phrase,
  cr.reason,
  cr.journal_seq
FROM coherence.cancel_requests cr;

CREATE OR REPLACE VIEW app_views.coherence_review_saves
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi') AS show_member_phi
)
SELECT
  rs.id,
  rs.run_id,
  rs.surface,
  rs.attempt_event_id,
  CASE WHEN s.show_member_phi THEN rs.approvals_file_sha256 ELSE NULL END AS approvals_file_sha256,
  rs.decision_commit_id,
  rs.imported,
  rs.original_at,
  rs.submission_id,
  rs.journal_seq,
  COALESCE(dc.cumulative_decision_count, af.row_count) AS row_count,
  COALESCE(dc.header_contract, af.header_kind) AS header_kind
FROM coherence.review_saves rs
LEFT JOIN coherence.approvals_files af ON af.file_sha256 = rs.approvals_file_sha256
LEFT JOIN coherence.decision_commits dc ON dc.id = rs.decision_commit_id
CROSS JOIN scopes s
WHERE (SELECT app_views._read_workshop_right('act:coherence.runs.read'));

CREATE OR REPLACE VIEW app_views.coherence_emit_confirmations
WITH (security_barrier = true) AS
SELECT
  ec.id,
  ec.run_id,
  ec.adjust_review_save_id,
  ec.typed_phrase,
  ec.journal_seq
FROM coherence.emit_confirmations ec;

CREATE OR REPLACE VIEW app_views.coherence_carries
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT
    app_views._read_has_full_entity_finance() AS show_full_entity_finance,
    app_views._read_has_full_tenant_right('col:coherence.member_phi') AS show_member_phi
)
SELECT
  c.id,
  c.run_id,
  c.statement_date,
  c.carry_kind,
  c.store_kind,
  CASE
    WHEN c.carry_kind = 'sent' AND s.show_full_entity_finance THEN c.file_sha256
    WHEN c.carry_kind IN ('approvals', 'decisions') AND s.show_member_phi THEN c.file_sha256
    ELSE NULL
  END AS file_sha256,
  c.carried_decision_commit_id,
  c.published_input_version_id,
  c.nothing_new,
  c.typed_phrase,
  c.journal_seq
FROM coherence.carries c
CROSS JOIN scopes s
WHERE (SELECT app_views._read_workshop_right('act:coherence.runs.read'));

CREATE OR REPLACE VIEW app_views.coherence_abandonments
WITH (security_barrier = true) AS
SELECT
  a.id,
  a.run_id,
  a.typed_phrase,
  a.reason,
  a.journal_seq
FROM coherence.abandonments a
WHERE (SELECT app_views._read_workshop_right('act:coherence.runs.read'));

CREATE OR REPLACE VIEW app_views.coherence_review_submissions
WITH (security_barrier = true) AS
SELECT
  rs.id,
  rs.run_id,
  rs.surface,
  rs.status,
  rs.staged_sha256,
  rs.review_save_id,
  rs.result_journal_seq,
  rs.result_message,
  rs.created_at,
  rs.resolved_at
FROM coherence.review_submissions rs;

CREATE OR REPLACE VIEW app_views.coherence_review_drafts
WITH (security_barrier = true) AS
SELECT
  rd.run_id,
  rd.surface,
  rd.attempt_no,
  rd.born,
  rd.checksum,
  rd.rows_json,
  rd.updated_at,
  rd.expires_at
FROM coherence.review_drafts rd
WHERE rd.expires_at > pg_catalog.clock_timestamp();

CREATE OR REPLACE VIEW app_views.coherence_approval_rows
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi') AS show_member_phi
)
SELECT
  CASE WHEN s.show_member_phi THEN ar.approvals_file_sha256 ELSE NULL END AS approvals_file_sha256,
  ar.row_no,
  CASE WHEN s.show_member_phi THEN ar.record_id ELSE NULL END AS record_id,
  ar.disposition,
  ar.agent,
  ar.agency,
  ar.policy,
  ar.book,
  ar.month,
  ar.status,
  CASE WHEN s.show_member_phi THEN ar.note ELSE NULL END AS note,
  ar.committed_at,
  ar.approved_amount,
  ar.approved_agency,
  ar.approved_agent,
  ar.approved_agency_from,
  ar.approved_agent_from,
  ar.journal_seq,
  rs.run_id,
  rs.surface
FROM coherence.approval_rows ar
CROSS JOIN scopes s
LEFT JOIN coherence.review_saves rs
  ON rs.approvals_file_sha256 = ar.approvals_file_sha256;

CREATE OR REPLACE VIEW app_views.coherence_review_configs
WITH (security_barrier = true) AS
SELECT
  r.id AS run_id,
  pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date,
  e.step AS surface,
  e.attempt_event_id,
  e.attempt_no,
  a.rel_path,
  a.store_kind,
  a.file_sha256,
  sf.byte_size,
  sf.md5_b64,
  sf.crc32c_b64
FROM coherence.runs r
JOIN coherence.v_current_finished_attempts e
  ON e.run_id = r.id
 AND e.step IN ('bible', 'adjust')
JOIN coherence.artifacts a
  ON a.attempt_event_id = e.attempt_event_id
 AND a.rel_path IN (e.step || '.json', e.step || '.html')
JOIN coherence.stored_files sf
  ON sf.store_kind = a.store_kind
 AND sf.sha256 = a.file_sha256
WHERE (SELECT app_views._read_workshop_right('act:coherence.decisions.read'))
  AND (SELECT app_views._read_has_full_tenant_right('col:coherence.member_phi'));

CREATE OR REPLACE VIEW app_views.coherence_run_outputs
WITH (security_barrier = true) AS
WITH pub_emits AS MATERIALIZED (
  SELECT attempt_event_id, is_sent
  FROM app_views._read_published_emit_attempts()
)
SELECT
  r.id AS run_id,
  e.attempt_event_id,
  a.rel_path,
  a.artifact_kind,
  a.store_kind,
  a.file_sha256,
  sf.byte_size,
  sf.md5_b64,
  sf.crc32c_b64
FROM coherence.runs r
JOIN coherence.v_current_finished_attempts e
  ON e.run_id = r.id
 AND e.step = 'emit'
LEFT JOIN pub_emits pe
  ON pe.attempt_event_id = e.attempt_event_id
JOIN coherence.artifacts a
  ON a.attempt_event_id = e.attempt_event_id
 AND a.artifact_kind = 'data'
 AND a.store_kind = 'company_data'
JOIN coherence.stored_files sf
  ON sf.store_kind = 'company_data'
 AND sf.sha256 = a.file_sha256
WHERE (SELECT app_views._read_has_full_tenant_right('act:coherence.outputs.read'))
  AND (
    (pe.attempt_event_id IS NOT NULL AND pe.is_sent)
    OR (SELECT app_views._read_workshop_right('act:coherence.outputs.read'))
  )
  AND (
    a.rel_path IN ('run.json', 'company_manifest.json')
    OR (
      pe.attempt_event_id IS NOT NULL
      AND (SELECT app_views._read_has_full_entity_finance())
    )
  );

CREATE OR REPLACE VIEW app_views.coherence_published_runs
WITH (security_barrier = true) AS
SELECT
  r.id,
  pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date,
  pg_catalog.to_char(r.statement_date, 'YYYYMMDD') AS stamp,
  r.folder_number,
  r.origin,
  r.input_version_id,
  r.emit_mode,
  r.emit_display,
  pe.attempt_event_id AS emit_attempt_event_id,
  pe.attempt_journal_seq AS emit_journal_seq,
  r.journal_seq,
  pe.is_sent AS sent,
  cm.default_emit_display,
  cm.display_name
FROM coherence.runs r
JOIN app_views._read_published_emit_attempts() pe
  ON pe.run_id = r.id
LEFT JOIN coherence.company_meta cm ON cm.singleton = true
WHERE (SELECT app_views._read_has_run_meta_access())
  AND (pe.is_sent OR (SELECT app_views._read_can_see_unsent_run_meta()));

CREATE OR REPLACE VIEW app_views.coherence_entity_bundle_artifacts
WITH (security_barrier = true) AS
SELECT
  r.id AS run_id,
  pe.attempt_event_id,
  a.rel_path,
  a.artifact_kind,
  a.store_kind,
  a.file_sha256,
  sf.byte_size,
  sf.md5_b64,
  sf.crc32c_b64,
  (a.rel_path LIKE 'emits/bundles/entity-managers/%/viewer.html') AS is_viewer_config
FROM coherence.runs r
JOIN app_views._read_published_emit_attempts() pe
  ON pe.run_id = r.id
JOIN coherence.artifacts a
  ON a.attempt_event_id = pe.attempt_event_id
 AND (
   a.rel_path LIKE 'emits/bundles/entity-managers/%/viewer.html'
   OR (
     a.rel_path LIKE 'emits/bundles/entity-managers/%'
     AND a.artifact_kind = 'data'
     AND a.store_kind = 'company_data'
   )
 )
JOIN coherence.stored_files sf
  ON sf.store_kind = a.store_kind
 AND sf.sha256 = a.file_sha256
WHERE (SELECT app_views._read_has_full_entity_finance())
  AND (pe.is_sent OR (SELECT app_views._read_has_full_tenant_right('act:coherence.unpublished.read')));

CREATE OR REPLACE VIEW app_views.coherence_review_drift_gate
WITH (security_barrier = true) AS
SELECT
  dc.company_slug,
  true AS authorized
FROM iam.database_context dc
WHERE dc.singleton = true
  AND (SELECT app_views._read_workshop_right('act:coherence.journal.read'));

CREATE OR REPLACE VIEW app_views.coherence_journal_gate
WITH (security_barrier = true) AS
SELECT
  dc.company_slug,
  true AS authorized
FROM iam.database_context dc
WHERE dc.singleton = true
  AND (SELECT app_views._read_workshop_right('act:coherence.journal.read'));

DO $$
DECLARE
  v_view TEXT;
BEGIN
  FOREACH v_view IN ARRAY ARRAY[
    'coherence_input_changes',
    'coherence_input_entries',
    'coherence_staging_files',
    'coherence_engine_versions',
    'coherence_step_attempt_events',
    'coherence_step_requests',
    'coherence_cancel_requests',
    'coherence_review_saves',
    'coherence_emit_confirmations',
    'coherence_carries',
    'coherence_abandonments',
    'coherence_review_submissions',
    'coherence_review_drafts',
    'coherence_approval_rows',
    'coherence_review_configs',
    'coherence_run_outputs',
    'coherence_published_runs',
    'coherence_entity_bundle_artifacts',
    'coherence_review_drift_gate',
    'coherence_journal_gate'
  ] LOOP
    EXECUTE pg_catalog.format('ALTER VIEW app_views.%I OWNER TO platform_view_owner', v_view);
    EXECUTE pg_catalog.format('REVOKE ALL ON app_views.%I FROM PUBLIC', v_view);
    EXECUTE pg_catalog.format('GRANT SELECT ON app_views.%I TO platform_app, platform_readonly', v_view);
  END LOOP;
END;
$$;

-- 3. Database-enforced authorization gate for on-demand verification check execution (POST /checks/run).
CREATE OR REPLACE FUNCTION app_cmd.coherence_authorize_check_run()
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM coherence._cmd_resolve_context('act:coherence.checks.record', 'human_or_service');
  RETURN true;
END;
$$;

ALTER FUNCTION app_cmd.coherence_authorize_check_run() OWNER TO platform_writer;
REVOKE ALL ON FUNCTION app_cmd.coherence_authorize_check_run() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_cmd.coherence_authorize_check_run() TO platform_app, platform_worker;

-- 4. Release E5: Shared platform_view_owner IAM read helpers, RLS policies on iam.*,
--    and security-barrier app_views.iam_* views (with per-company vendor name masking).
CREATE OR REPLACE FUNCTION app_views._read_iam_has_read()
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam.has_right('act:iam.read');
$$;

CREATE OR REPLACE FUNCTION app_views._read_iam_visible_org_ids()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT COALESCE((
    SELECT pg_catalog.array_agg(DISTINCT u.org_id)
    FROM (
      SELECT org_id FROM pg_catalog.unnest(iam._visible_detail_org_ids()) AS org_id
      UNION
      SELECT org_id
      FROM pg_catalog.unnest(iam._tenant_tree_org_ids(ARRAY['lead_vendor'])) AS org_id
      WHERE iam.has_right('act:iam.read')
    ) u
  ), ARRAY[]::uuid[]);
$$;

CREATE OR REPLACE FUNCTION app_views._read_iam_detail_org_ids()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam._visible_detail_org_ids();
$$;

CREATE OR REPLACE FUNCTION app_views._read_iam_real_vendor_org_ids()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam._real_vendor_org_ids();
$$;

CREATE OR REPLACE FUNCTION app_views._read_iam_visible_person_ids()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam._visible_person_ids();
$$;

CREATE OR REPLACE FUNCTION app_views._read_iam_visible_role_ids()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam._visible_role_ids();
$$;

CREATE OR REPLACE FUNCTION app_views._read_iam_visible_grant_ids()
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT iam._visible_grant_ids();
$$;

DO $$
DECLARE
  v_sig TEXT;
BEGIN
  FOREACH v_sig IN ARRAY ARRAY[
    'app_views._read_iam_has_read()',
    'app_views._read_iam_visible_org_ids()',
    'app_views._read_iam_detail_org_ids()',
    'app_views._read_iam_real_vendor_org_ids()',
    'app_views._read_iam_visible_person_ids()',
    'app_views._read_iam_visible_role_ids()',
    'app_views._read_iam_visible_grant_ids()'
  ] LOOP
    EXECUTE 'ALTER FUNCTION ' || v_sig || ' OWNER TO platform_view_owner';
    EXECUTE 'REVOKE ALL ON FUNCTION ' || v_sig || ' FROM PUBLIC, platform_worker, platform_writer, platform_iam_sync, platform_auth_lookup';
    EXECUTE 'GRANT EXECUTE ON FUNCTION ' || v_sig || ' TO platform_view_owner, platform_app, platform_readonly';
  END LOOP;
END;
$$;

-- IAM-scoped platform_view_owner FOR SELECT RLS policies across the 16 remaining readable iam.* tables
-- (iam.database_context policy lives in 008; iam.person_auth_identities grants ZERO access to platform_view_owner).
-- Masked vendor catalog union stays strictly on organizations / organization_versions (app_views.iam_organizations
-- alone); edges, memberships, affiliations, and tool switches use app_views._read_iam_detail_org_ids().
CREATE POLICY tools_iam_read ON iam.tools
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_iam_has_read()));

CREATE POLICY rights_iam_read ON iam.rights
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_iam_has_read()));

CREATE POLICY right_retirements_iam_read ON iam.right_retirements
  FOR SELECT TO platform_view_owner
  USING ((SELECT app_views._read_iam_has_read()));

CREATE POLICY organizations_iam_read ON iam.organizations
  FOR SELECT TO platform_view_owner
  USING (id = ANY(((SELECT app_views._read_iam_visible_org_ids()))::uuid[]));

CREATE POLICY organization_versions_iam_read ON iam.organization_versions
  FOR SELECT TO platform_view_owner
  USING (organization_id = ANY(((SELECT app_views._read_iam_visible_org_ids()))::uuid[]));

CREATE POLICY organization_edges_iam_read ON iam.organization_edges
  FOR SELECT TO platform_view_owner
  USING (child_org_id = ANY(((SELECT app_views._read_iam_detail_org_ids()))::uuid[]));

CREATE POLICY people_iam_read ON iam.people
  FOR SELECT TO platform_view_owner
  USING (id = ANY(((SELECT app_views._read_iam_visible_person_ids()))::uuid[]));

CREATE POLICY person_versions_iam_read ON iam.person_versions
  FOR SELECT TO platform_view_owner
  USING (person_id = ANY(((SELECT app_views._read_iam_visible_person_ids()))::uuid[]));

CREATE POLICY organization_memberships_iam_read ON iam.organization_memberships
  FOR SELECT TO platform_view_owner
  USING (
    person_id = ANY(((SELECT app_views._read_iam_visible_person_ids()))::uuid[])
    AND organization_id = ANY(((SELECT app_views._read_iam_detail_org_ids()))::uuid[])
  );

CREATE POLICY agent_affiliations_iam_read ON iam.agent_affiliations
  FOR SELECT TO platform_view_owner
  USING (
    person_id = ANY(((SELECT app_views._read_iam_visible_person_ids()))::uuid[])
    AND agency_org_id = ANY(((SELECT app_views._read_iam_detail_org_ids()))::uuid[])
  );

CREATE POLICY roles_iam_read ON iam.roles
  FOR SELECT TO platform_view_owner
  USING (id = ANY(((SELECT app_views._read_iam_visible_role_ids()))::uuid[]));

CREATE POLICY role_versions_iam_read ON iam.role_versions
  FOR SELECT TO platform_view_owner
  USING (role_id = ANY(((SELECT app_views._read_iam_visible_role_ids()))::uuid[]));

CREATE POLICY role_rights_iam_read ON iam.role_rights
  FOR SELECT TO platform_view_owner
  USING (role_id = ANY(((SELECT app_views._read_iam_visible_role_ids()))::uuid[]));

CREATE POLICY role_grants_iam_read ON iam.role_grants
  FOR SELECT TO platform_view_owner
  USING (id = ANY(((SELECT app_views._read_iam_visible_grant_ids()))::uuid[]));

CREATE POLICY role_grant_people_iam_read ON iam.role_grant_people
  FOR SELECT TO platform_view_owner
  USING (
    role_grant_id = ANY(((SELECT app_views._read_iam_visible_grant_ids()))::uuid[])
    AND subject_person_id = ANY(((SELECT app_views._read_iam_visible_person_ids()))::uuid[])
  );

CREATE POLICY organization_tool_switches_iam_read ON iam.organization_tool_switches
  FOR SELECT TO platform_view_owner
  USING (organization_id = ANY(((SELECT app_views._read_iam_detail_org_ids()))::uuid[]));

GRANT SELECT ON
  iam.tools,
  iam.rights,
  iam.right_retirements,
  iam.organizations,
  iam.organization_versions,
  iam.organization_edges,
  iam.people,
  iam.person_versions,
  iam.organization_memberships,
  iam.agent_affiliations,
  iam.roles,
  iam.role_versions,
  iam.role_rights,
  iam.role_grants,
  iam.role_grant_people,
  iam.organization_tool_switches
TO platform_view_owner;
REVOKE ALL ON iam.person_auth_identities FROM platform_view_owner;

-- Security-barrier IAM read views in app_views.*, owned by NOBYPASSRLS platform_view_owner.
CREATE OR REPLACE VIEW app_views.iam_my_context
WITH (security_barrier = true) AS
WITH ctx AS MATERIALIZED (
  SELECT * FROM iam.session_context()
)
SELECT
  ctx.session_id,
  ctx.actor_person_id,
  ctx.view_as_person_id,
  COALESCE(ctx.view_as_person_id, ctx.actor_person_id) AS effective_person_id,
  (ctx.view_as_person_id IS NOT NULL) AS is_viewing_as,
  dc.environment,
  dc.db_role_kind,
  dc.tenant_org_id,
  dc.company_slug,
  dc.support_external_label
FROM ctx
JOIN iam.database_context dc ON dc.singleton = true
WHERE ctx.actor_person_id IS NOT NULL
  AND (SELECT app_views._read_iam_has_read());

-- Per-company vendor name masking (decision 99605efe): everyone but staff (col:vendors.real_name)
-- and the vendor's own active people sees masked_display_name, with slug and external_domain hidden.
CREATE OR REPLACE VIEW app_views.iam_organizations
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT app_views._read_iam_real_vendor_org_ids() AS real_vendor_orgs
)
SELECT
  o.id,
  o.org_kind,
  ov.id AS version_id,
  CASE
    WHEN o.org_kind = 'lead_vendor' AND NOT (o.id = ANY(s.real_vendor_orgs))
      THEN NULL
    ELSE ov.slug
  END AS slug,
  CASE
    WHEN o.org_kind = 'lead_vendor' AND NOT (o.id = ANY(s.real_vendor_orgs))
      THEN ov.masked_display_name
    ELSE ov.display_name
  END AS display_name,
  ov.masked_display_name,
  CASE
    WHEN o.org_kind = 'lead_vendor' AND NOT (o.id = ANY(s.real_vendor_orgs))
      THEN NULL
    ELSE ov.external_domain
  END AS external_domain,
  (o.org_kind = 'lead_vendor' AND NOT (o.id = ANY(s.real_vendor_orgs))) AS is_vendor_name_masked,
  ov.status,
  o.journal_seq AS created_journal_seq,
  ov.journal_seq AS version_journal_seq
FROM iam.organizations o
JOIN iam.organization_versions ov
  ON ov.organization_id = o.id
 AND ov.superseded_by_id IS NULL
CROSS JOIN scopes s;

CREATE OR REPLACE VIEW app_views.iam_organization_edges
WITH (security_barrier = true) AS
SELECT
  e.id,
  e.child_org_id,
  e.parent_org_id,
  e.valid_range,
  e.status,
  e.replaces_id,
  e.journal_seq
FROM iam.organization_edges e
WHERE e.superseded_by_id IS NULL;

CREATE OR REPLACE VIEW app_views.iam_people
WITH (security_barrier = true) AS
WITH scopes AS MATERIALIZED (
  SELECT app_views._read_iam_detail_org_ids() AS detail_orgs
)
SELECT
  p.id,
  p.person_kind,
  p.principal_origin,
  CASE WHEN p.house_org_id = ANY(s.detail_orgs) THEN p.house_org_id ELSE NULL END AS house_org_id,
  pv.id AS version_id,
  pv.legal_name,
  pv.preferred_name,
  pv.primary_email,
  pv.npn,
  pv.status,
  p.journal_seq AS created_journal_seq,
  pv.journal_seq AS version_journal_seq
FROM iam.people p
JOIN iam.person_versions pv
  ON pv.person_id = p.id
 AND pv.superseded_by_id IS NULL
CROSS JOIN scopes s;

CREATE OR REPLACE VIEW app_views.iam_memberships
WITH (security_barrier = true) AS
SELECT
  m.id,
  m.person_id,
  m.organization_id,
  m.work_arrangement,
  m.tax_classification,
  m.valid_range,
  m.status,
  m.replaces_id,
  m.journal_seq
FROM iam.organization_memberships m
WHERE m.superseded_by_id IS NULL;

CREATE OR REPLACE VIEW app_views.iam_agent_affiliations
WITH (security_barrier = true) AS
SELECT
  aa.id,
  aa.person_id,
  aa.npn,
  aa.agency_org_id,
  aa.carrier_id,
  aa.split_bps,
  aa.agent_file_name,
  aa.valid_range,
  aa.status,
  aa.replaces_id,
  aa.journal_seq
FROM iam.agent_affiliations aa
WHERE aa.superseded_by_id IS NULL;

CREATE OR REPLACE VIEW app_views.iam_roles
WITH (security_barrier = true) AS
SELECT
  r.id,
  r.slug,
  r.owner_org_id,
  rv.id AS version_id,
  rv.display_name,
  rv.is_pinned,
  rv.is_nusear_internal,
  rv.allows_org_wide_scope,
  rv.requires_self_scope,
  rv.forbids_company_revenue_rights,
  rv.status,
  r.journal_seq AS created_journal_seq,
  rv.journal_seq AS version_journal_seq
FROM iam.roles r
JOIN iam.role_versions rv
  ON rv.role_id = r.id
 AND rv.superseded_by_id IS NULL;

CREATE OR REPLACE VIEW app_views.iam_role_rights
WITH (security_barrier = true) AS
SELECT
  rr.id,
  rr.role_id,
  r.slug AS role_slug,
  rr.right_id,
  ri.right_kind,
  ri.tool_id,
  ri.sensitivity_class,
  ri.description,
  rr.status,
  rr.replaces_id,
  rr.journal_seq,
  (ret.right_id IS NOT NULL) AS is_retired
FROM iam.role_rights rr
JOIN iam.roles r ON r.id = rr.role_id
JOIN iam.rights ri ON ri.id = rr.right_id
LEFT JOIN iam.right_retirements ret ON ret.right_id = rr.right_id
WHERE rr.superseded_by_id IS NULL;

CREATE OR REPLACE VIEW app_views.iam_role_grants
WITH (security_barrier = true) AS
SELECT
  g.id,
  g.person_id,
  g.role_id,
  r.slug AS role_slug,
  g.organization_id,
  g.include_descendants,
  g.person_scope_mode,
  g.data_date_range,
  g.valid_range,
  g.status,
  g.replaces_id,
  g.journal_seq
FROM iam.role_grants g
JOIN iam.roles r ON r.id = g.role_id
WHERE g.superseded_by_id IS NULL;

CREATE OR REPLACE VIEW app_views.iam_role_grant_people
WITH (security_barrier = true) AS
SELECT
  rgp.id,
  rgp.role_grant_id,
  rgp.subject_person_id,
  rgp.status,
  rgp.replaces_id,
  rgp.journal_seq
FROM iam.role_grant_people rgp
WHERE rgp.superseded_by_id IS NULL;

CREATE OR REPLACE VIEW app_views.iam_tool_switches
WITH (security_barrier = true) AS
SELECT
  ts.id,
  ts.organization_id,
  ts.tool_id,
  t.display_name AS tool_display_name,
  t.is_nusear_only,
  t.is_customer_switchable,
  ts.switch_state,
  ts.hold_reason,
  ts.status,
  ts.replaces_id,
  ts.journal_seq
FROM iam.organization_tool_switches ts
JOIN iam.tools t ON t.id = ts.tool_id
WHERE ts.superseded_by_id IS NULL;

DO $$
DECLARE
  v_view TEXT;
BEGIN
  FOREACH v_view IN ARRAY ARRAY[
    'iam_my_context',
    'iam_organizations',
    'iam_organization_edges',
    'iam_people',
    'iam_memberships',
    'iam_agent_affiliations',
    'iam_roles',
    'iam_role_rights',
    'iam_role_grants',
    'iam_role_grant_people',
    'iam_tool_switches'
  ] LOOP
    EXECUTE pg_catalog.format('ALTER VIEW app_views.%I OWNER TO platform_view_owner', v_view);
    EXECUTE pg_catalog.format('REVOKE ALL ON app_views.%I FROM PUBLIC', v_view);
    EXECUTE pg_catalog.format('GRANT SELECT ON app_views.%I TO platform_app, platform_readonly', v_view);
  END LOOP;
END;
$$;

-- 5. Release E5 (smaller design): Internal IAM command helpers (owned by platform_writer) and
--    SECURITY DEFINER app_cmd.iam_* write commands.
--    In a company database only Nusear staff (origin nusear_staff, holding the command's write right
--    through their Nusear-internal grant, read through iam.assert_can_write / iam.person_effective_grants,
--    and recorded as nusear_support) may execute IAM writes; company_local callers are refused at the
--    top of every app_cmd.iam_* command. Nothing at runtime writes platform_root, built-in roles
--    (owner_org_id IS NULL), or Nusear's own people, memberships, and grants.

-- Early fail-closed session + View-as + human + nusear_staff + write-right guard called FIRST by
-- every app_cmd.iam_* command before any target lookup (zero existence oracle).
CREATE OR REPLACE FUNCTION iam._cmd_require_nusear_staff(p_right_id TEXT)
RETURNS VOID
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx iam.verified_session := iam.session_context();
  v_p RECORD;
BEGIN
  IF v_ctx.actor_person_id IS NULL THEN
    RAISE EXCEPTION 'Authentication required.' USING ERRCODE = '42501';
  END IF;
  IF v_ctx.view_as_person_id IS NOT NULL THEN
    RAISE EXCEPTION 'VIEW_AS_READ_ONLY: writes are forbidden while viewing as another person.'
      USING ERRCODE = '42501';
  END IF;
  SELECT p.person_kind, p.principal_origin INTO v_p FROM iam.people p WHERE p.id = v_ctx.actor_person_id;
  IF v_p.person_kind IS DISTINCT FROM 'human' THEN
    RAISE EXCEPTION 'HUMAN_ONLY: service principals cannot execute IAM administration commands.'
      USING ERRCODE = '42501';
  END IF;
  IF v_p.principal_origin IS DISTINCT FROM 'nusear_staff' THEN
    RAISE EXCEPTION 'FORBIDDEN_ORIGIN: only Nusear staff may execute IAM write commands.'
      USING ERRCODE = '42501';
  END IF;
  IF p_right_id IS NULL OR pg_catalog.cardinality(iam.effective_wide_org_ids(p_right_id, NULL)) = 0 THEN
    RAISE EXCEPTION 'FORBIDDEN: missing write right %.', p_right_id USING ERRCODE = '42501';
  END IF;
END;
$$;

-- Central runtime IAM write authorization through the one existing evaluator (iam.assert_can_write);
-- refuses platform_root and unconfigured / non-company_working databases.
CREATE OR REPLACE FUNCTION iam._cmd_resolve_context(
  p_right_id TEXT,
  p_target_org_id UUID
)
RETURNS TABLE (
  environment TEXT,
  db_role_kind TEXT,
  tenant_org_id UUID,
  actor_person_id UUID,
  recorded_as TEXT
)
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_dc RECORD;
  v_auth RECORD;
BEGIN
  PERFORM iam._cmd_require_nusear_staff(p_right_id);

  SELECT dc.environment, dc.db_role_kind, dc.tenant_org_id
  INTO v_dc
  FROM iam.database_context dc
  WHERE dc.singleton = true;

  IF v_dc.environment IS NULL OR v_dc.db_role_kind <> 'company_working' OR v_dc.tenant_org_id IS NULL THEN
    RAISE EXCEPTION 'FORBIDDEN: runtime IAM commands require a configured company_working database.'
      USING ERRCODE = '42501';
  END IF;

  IF p_target_org_id IS NULL OR EXISTS (
    SELECT 1 FROM iam.organizations o WHERE o.id = p_target_org_id AND o.org_kind = 'platform_root'
  ) THEN
    RAISE EXCEPTION 'FORBIDDEN_PLATFORM_ROOT: platform_root cannot be modified at runtime.'
      USING ERRCODE = '42501';
  END IF;

  SELECT a.actor_person_id, a.recorded_as
  INTO v_auth
  FROM iam.assert_can_write(p_right_id, p_target_org_id, NULL) a;

  RETURN QUERY SELECT
    v_dc.environment,
    v_dc.db_role_kind,
    v_dc.tenant_org_id,
    v_auth.actor_person_id,
    v_auth.recorded_as;
END;
$$;

CREATE OR REPLACE FUNCTION iam._cmd_check_idempotency(
  p_command_kind TEXT,
  p_command_key TEXT,
  p_actor_person_id UUID,
  p_recorded_as TEXT,
  p_request_sha256 TEXT
)
RETURNS TABLE (
  existing_seq BIGINT,
  existing_result JSONB
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

  SELECT j.seq, j.command_kind, j.actor_person_id, j.recorded_as, j.request_sha256, j.body
  INTO v_ex
  FROM platform.audit_journal j
  WHERE j.command_key = p_command_key;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  IF v_ex.command_kind = p_command_kind
     AND v_ex.actor_person_id IS NOT DISTINCT FROM p_actor_person_id
     AND v_ex.recorded_as = p_recorded_as
     AND v_ex.request_sha256 = p_request_sha256
  THEN
    RETURN QUERY SELECT v_ex.seq, v_ex.body -> 'result';
    RETURN;
  END IF;

  RAISE EXCEPTION 'COMMAND_KEY_CONFLICT: command_key already used for a different request.'
    USING ERRCODE = '23505';
END;
$$;

CREATE OR REPLACE FUNCTION iam._cmd_append_audit(
  p_env TEXT,
  p_actor_person_id UUID,
  p_recorded_as TEXT,
  p_target_org_id UUID,
  p_command_kind TEXT,
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_result JSONB
)
RETURNS BIGINT
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_seq BIGINT;
BEGIN
  INSERT INTO platform.audit_journal (
    environment, actor_person_id, recorded_as, target_org_id,
    command_kind, command_key, request_sha256, body
  ) VALUES (
    p_env, p_actor_person_id, p_recorded_as, p_target_org_id,
    p_command_kind, p_command_key, p_request_sha256,
    pg_catalog.jsonb_build_object('result', COALESCE(p_result, '{}'::jsonb))
  )
  RETURNING seq INTO v_seq;
  RETURN v_seq;
END;
$$;

-- Validates a right added to or removed from a company custom role: refuses unknown, retired,
-- non-delegable (act:coherence.owner.*, act:coherence.worker.* and the four worker-or-owner rights), and platform-internal rights.
CREATE OR REPLACE FUNCTION iam._cmd_validate_role_right(
  p_right_id TEXT,
  p_status TEXT
)
RETURNS VOID
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_r RECORD;
BEGIN
  SELECT r.id, r.sensitivity_class, r.is_delegable_power, t.is_nusear_only,
         EXISTS (SELECT 1 FROM iam.right_retirements ret WHERE ret.right_id = r.id) AS is_retired
  INTO v_r
  FROM iam.rights r
  JOIN iam.tools t ON t.id = r.tool_id
  WHERE r.id = p_right_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'RIGHT_NOT_FOUND: unknown right %.', p_right_id USING ERRCODE = 'P0002';
  END IF;
  IF p_status = 'active' THEN
    IF v_r.is_retired THEN
      RAISE EXCEPTION 'RIGHT_RETIRED: right % is retired and cannot be activated on a role.', p_right_id
        USING ERRCODE = '23514';
    END IF;
    IF NOT v_r.is_delegable_power THEN
      RAISE EXCEPTION 'FORBIDDEN_NON_DELEGABLE_RIGHT: non-delegable right % cannot be added to a role.', p_right_id
        USING ERRCODE = '42501';
    END IF;
    IF v_r.sensitivity_class = 'platform_internal' OR v_r.is_nusear_only THEN
      RAISE EXCEPTION 'FORBIDDEN_INTERNAL_RIGHT: non-internal role cannot hold platform-internal right %.', p_right_id
        USING ERRCODE = '42501';
    END IF;
  END IF;
END;
$$;

DO $$
DECLARE
  v_sig TEXT;
BEGIN
  FOREACH v_sig IN ARRAY ARRAY[
    'iam._cmd_require_nusear_staff(TEXT)',
    'iam._cmd_resolve_context(TEXT, UUID)',
    'iam._cmd_check_idempotency(TEXT, TEXT, UUID, TEXT, TEXT)',
    'iam._cmd_append_audit(TEXT, UUID, TEXT, UUID, TEXT, TEXT, TEXT, JSONB)',
    'iam._cmd_validate_role_right(TEXT, TEXT)'
  ] LOOP
    EXECUTE 'ALTER FUNCTION ' || v_sig || ' OWNER TO platform_writer';
    EXECUTE 'REVOKE ALL ON FUNCTION ' || v_sig || ' FROM PUBLIC, platform_app, platform_worker, platform_readonly, platform_iam_sync, platform_auth_lookup, platform_view_owner, platform_versioner';
  END LOOP;
END;
$$;

-- Command 1: Create organization (enforcing external_upline under platform_root open-ended from today,
-- col:vendors.real_name for lead_vendor creation, and auditing against the created organization).
CREATE OR REPLACE FUNCTION app_cmd.iam_create_organization(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_org_kind TEXT,
  p_slug TEXT,
  p_display_name TEXT,
  p_parent_org_id UUID DEFAULT NULL,
  p_valid_from DATE DEFAULT NULL,
  p_masked_display_name TEXT DEFAULT NULL,
  p_external_domain TEXT DEFAULT NULL,
  p_org_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_tenant_org_id UUID;
  v_root_id UUID;
  v_parent_id UUID;
  v_auth_org_id UUID;
  v_org_id UUID;
  v_ver_id UUID;
  v_edge_id UUID;
  v_from DATE;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.entities.write');

  IF p_org_kind IS NULL OR p_org_kind NOT IN ('company', 'agency', 'team', 'lead_vendor', 'referral_firm', 'external_upline') THEN
    RAISE EXCEPTION 'INVALID_ORG_KIND: unsupported org_kind %.', p_org_kind USING ERRCODE = '22023';
  END IF;

  SELECT dc.tenant_org_id INTO v_tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true;
  SELECT o.id INTO v_root_id FROM iam.organizations o WHERE o.org_kind = 'platform_root' LIMIT 1;

  IF p_org_kind = 'external_upline' THEN
    IF v_root_id IS NULL THEN
      RAISE EXCEPTION 'PLATFORM_ROOT_MISSING: platform_root organization not found.' USING ERRCODE = 'P0002';
    END IF;
    v_parent_id := v_root_id;
    v_auth_org_id := v_tenant_org_id;
  ELSE
    IF p_parent_org_id IS NULL THEN
      RAISE EXCEPTION 'MISSING_PARENT_ORG: parent_org_id is required for org_kind %.', p_org_kind USING ERRCODE = '22023';
    END IF;
    v_parent_id := p_parent_org_id;
    v_auth_org_id := p_parent_org_id;
  END IF;

  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.entities.write', v_auth_org_id);

  IF p_org_kind = 'external_upline' AND p_parent_org_id IS NOT NULL AND p_parent_org_id <> v_root_id THEN
    RAISE EXCEPTION 'EXTERNAL_UPLINE_PARENT_MUST_BE_ROOT: external_upline must attach directly under platform_root.'
      USING ERRCODE = '23514';
  END IF;

  IF p_org_kind = 'lead_vendor' AND NOT (v_parent_id = ANY(iam.effective_wide_org_ids('col:vendors.real_name', NULL))) THEN
    RAISE EXCEPTION 'FORBIDDEN_VENDOR_IDENTITY: creating a lead_vendor requires col:vendors.real_name.'
      USING ERRCODE = '42501';
  END IF;

  v_from := COALESCE(p_valid_from, iam.business_today());
  IF p_org_kind = 'external_upline' AND v_from > iam.business_today() THEN
    RAISE EXCEPTION 'EXTERNAL_UPLINE_MUST_STAY_UNDER_ROOT: external_upline edge must stay open-ended from today.'
      USING ERRCODE = '23514';
  END IF;

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.create_organization', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  v_org_id := COALESCE(p_org_id, pg_catalog.gen_random_uuid());
  v_ver_id := pg_catalog.gen_random_uuid();
  v_edge_id := pg_catalog.gen_random_uuid();

  v_result := pg_catalog.jsonb_build_object(
    'organization_id', v_org_id,
    'version_id', v_ver_id,
    'edge_id', v_edge_id,
    'parent_org_id', v_parent_id,
    'org_kind', p_org_kind,
    'slug', p_slug,
    'display_name', p_display_name,
    'masked_display_name', p_masked_display_name,
    'status', 'active'
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, v_org_id,
    'iam.create_organization', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.organizations (id, org_kind, journal_seq)
  VALUES (v_org_id, p_org_kind, v_seq);

  INSERT INTO iam.organization_versions (
    id, organization_id, slug, display_name, masked_display_name, external_domain, status, journal_seq
  ) VALUES (
    v_ver_id, v_org_id, p_slug, p_display_name, p_masked_display_name, p_external_domain, 'active', v_seq
  );

  INSERT INTO iam.organization_edges (
    id, child_org_id, parent_org_id, valid_range, status, journal_seq
  ) VALUES (
    v_edge_id, v_org_id, v_parent_id, pg_catalog.daterange(v_from, NULL, '[)'), 'active', v_seq
  );

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 2: Update organization version (refuses platform_root; never echoes a lead_vendor's
-- real identity on fresh execution or idempotent replay without col:vendors.real_name).
CREATE OR REPLACE FUNCTION app_cmd.iam_update_organization(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_organization_id UUID,
  p_slug TEXT DEFAULT NULL,
  p_display_name TEXT DEFAULT NULL,
  p_masked_display_name TEXT DEFAULT NULL,
  p_external_domain TEXT DEFAULT NULL,
  p_status TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_org RECORD;
  v_tenant_org_id UUID;
  v_auth_org_id UUID;
  v_show_real BOOLEAN;
  v_ver_id UUID;
  v_new_slug TEXT;
  v_new_display TEXT;
  v_new_masked TEXT;
  v_new_domain TEXT;
  v_new_status TEXT;
  v_replay_result JSONB;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.entities.write');

  SELECT o.id, o.org_kind, ov.id AS version_id, ov.slug, ov.display_name, ov.masked_display_name, ov.external_domain, ov.status
  INTO v_org
  FROM iam.organizations o
  JOIN iam.organization_versions ov ON ov.organization_id = o.id AND ov.superseded_by_id IS NULL
  WHERE o.id = p_organization_id;

  IF v_org.org_kind = 'platform_root' THEN
    RAISE EXCEPTION 'FORBIDDEN_PLATFORM_ROOT: platform_root cannot be modified at runtime.'
      USING ERRCODE = '42501';
  END IF;

  IF v_org.org_kind = 'external_upline' THEN
    SELECT dc.tenant_org_id INTO v_tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true;
    v_auth_org_id := v_tenant_org_id;
  ELSE
    v_auth_org_id := p_organization_id;
  END IF;

  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.entities.write', v_auth_org_id);

  IF v_org.id IS NULL THEN
    RAISE EXCEPTION 'ORG_NOT_FOUND: organization % not found.', p_organization_id USING ERRCODE = 'P0002';
  END IF;

  v_show_real := (v_org.org_kind <> 'lead_vendor')
    OR (p_organization_id = ANY(iam.effective_wide_org_ids('col:vendors.real_name', NULL)));

  IF NOT v_show_real AND (p_slug IS NOT NULL OR p_display_name IS NOT NULL OR p_external_domain IS NOT NULL) THEN
    RAISE EXCEPTION 'FORBIDDEN_VENDOR_IDENTITY: updating a lead_vendor real identity requires col:vendors.real_name.'
      USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.update_organization', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    v_replay_result := v_idem.existing_result;
    IF v_org.org_kind = 'lead_vendor' AND NOT v_show_real THEN
      v_replay_result := v_replay_result || pg_catalog.jsonb_build_object(
        'slug', NULL,
        'display_name', v_replay_result ->> 'masked_display_name',
        'external_domain', NULL,
        'is_vendor_name_masked', true
      );
    END IF;
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_replay_result);
  END IF;

  v_ver_id := pg_catalog.gen_random_uuid();
  v_new_slug := COALESCE(p_slug, v_org.slug);
  v_new_display := COALESCE(p_display_name, v_org.display_name);
  v_new_masked := COALESCE(p_masked_display_name, v_org.masked_display_name);
  v_new_domain := COALESCE(p_external_domain, v_org.external_domain);
  v_new_status := COALESCE(p_status, v_org.status);

  v_result := pg_catalog.jsonb_build_object(
    'organization_id', p_organization_id,
    'version_id', v_ver_id,
    'replaces_version_id', v_org.version_id,
    'slug', CASE WHEN v_show_real THEN v_new_slug ELSE NULL END,
    'display_name', CASE WHEN v_show_real THEN v_new_display ELSE v_new_masked END,
    'masked_display_name', v_new_masked,
    'external_domain', CASE WHEN v_show_real THEN v_new_domain ELSE NULL END,
    'is_vendor_name_masked', NOT v_show_real,
    'status', v_new_status
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, p_organization_id,
    'iam.update_organization', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.organization_versions (
    id, organization_id, slug, display_name, masked_display_name, external_domain, status, replaces_id, journal_seq
  ) VALUES (
    v_ver_id, p_organization_id, v_new_slug, v_new_display, v_new_masked, v_new_domain, v_new_status, v_org.version_id, v_seq
  );

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 3: Set/supersede/revoke an organization parent edge (or atomically move an agency to an external_upline).
-- Refuses platform_root edges except the immutable external_upline -> platform_root attachment.
CREATE OR REPLACE FUNCTION app_cmd.iam_set_organization_edge(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_child_org_id UUID,
  p_parent_org_id UUID,
  p_valid_range DATERANGE,
  p_replaces_edge_id UUID DEFAULT NULL,
  p_status TEXT DEFAULT 'active',
  p_close_edge_id UUID DEFAULT NULL,
  p_close_valid_range DATERANGE DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_tenant_org_id UUID;
  v_child_kind TEXT;
  v_parent_kind TEXT;
  v_old_parent_kind TEXT;
  v_rep_edge RECORD;
  v_close_edge RECORD;
  v_auth_org_id UUID;
  v_edge_id UUID;
  v_closed_new_id UUID := NULL;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.entities.write');

  SELECT dc.tenant_org_id INTO v_tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true;
  SELECT o.org_kind INTO v_child_kind FROM iam.organizations o WHERE o.id = p_child_org_id;
  SELECT o.org_kind INTO v_parent_kind FROM iam.organizations o WHERE o.id = p_parent_org_id;

  IF v_child_kind = 'platform_root'
     OR (v_child_kind IS DISTINCT FROM 'external_upline' AND v_parent_kind = 'platform_root')
  THEN
    RAISE EXCEPTION 'FORBIDDEN_PLATFORM_ROOT: platform_root edges cannot be modified at runtime.'
      USING ERRCODE = '42501';
  END IF;

  v_auth_org_id := CASE WHEN v_child_kind = 'external_upline' THEN v_tenant_org_id ELSE p_child_org_id END;
  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.entities.write', v_auth_org_id);

  IF v_child_kind IS NULL THEN
    RAISE EXCEPTION 'ORG_NOT_FOUND: child organization % not found.', p_child_org_id USING ERRCODE = 'P0002';
  END IF;

  IF v_parent_kind IN ('external_upline', 'platform_root') THEN
    PERFORM iam._cmd_resolve_context('act:iam.entities.write', v_ctx.tenant_org_id);
  ELSE
    PERFORM iam._cmd_resolve_context('act:iam.entities.write', p_parent_org_id);
  END IF;

  IF v_parent_kind IS NULL THEN
    RAISE EXCEPTION 'ORG_NOT_FOUND: parent organization % not found.', p_parent_org_id USING ERRCODE = 'P0002';
  END IF;

  IF p_replaces_edge_id IS NOT NULL THEN
    SELECT e.id, e.child_org_id, e.parent_org_id, e.superseded_by_id
    INTO v_rep_edge
    FROM iam.organization_edges e
    WHERE e.id = p_replaces_edge_id;
    IF NOT FOUND OR v_rep_edge.child_org_id <> p_child_org_id THEN
      RAISE EXCEPTION 'EDGE_NOT_FOUND: edge % for child % not found.', p_replaces_edge_id, p_child_org_id
        USING ERRCODE = 'P0002';
    END IF;
    SELECT o.org_kind INTO v_old_parent_kind FROM iam.organizations o WHERE o.id = v_rep_edge.parent_org_id;
    IF v_old_parent_kind = 'platform_root' AND v_child_kind <> 'external_upline' THEN
      RAISE EXCEPTION 'FORBIDDEN_PLATFORM_ROOT: platform_root parent edges cannot be modified at runtime.'
        USING ERRCODE = '42501';
    END IF;
    IF v_old_parent_kind IN ('external_upline', 'platform_root') THEN
      PERFORM iam._cmd_resolve_context('act:iam.entities.write', v_ctx.tenant_org_id);
    ELSE
      PERFORM iam._cmd_resolve_context('act:iam.entities.write', v_rep_edge.parent_org_id);
    END IF;
  END IF;

  IF p_close_edge_id IS NOT NULL THEN
    IF p_close_valid_range IS NULL THEN
      RAISE EXCEPTION 'INVALID_CLOSE_RANGE: close_valid_range is required with close_edge_id.' USING ERRCODE = '22023';
    END IF;
    SELECT e.id, e.child_org_id, e.parent_org_id, e.status, e.superseded_by_id
    INTO v_close_edge
    FROM iam.organization_edges e
    WHERE e.id = p_close_edge_id;
    IF NOT FOUND OR v_close_edge.child_org_id <> p_child_org_id THEN
      RAISE EXCEPTION 'EDGE_NOT_FOUND: active edge % for child % not found.', p_close_edge_id, p_child_org_id
        USING ERRCODE = 'P0002';
    END IF;
    SELECT o.org_kind INTO v_old_parent_kind FROM iam.organizations o WHERE o.id = v_close_edge.parent_org_id;
    IF v_old_parent_kind = 'platform_root' THEN
      RAISE EXCEPTION 'FORBIDDEN_PLATFORM_ROOT: platform_root parent edges cannot be closed at runtime.'
        USING ERRCODE = '42501';
    END IF;
    IF v_old_parent_kind = 'external_upline' THEN
      PERFORM iam._cmd_resolve_context('act:iam.entities.write', v_ctx.tenant_org_id);
    ELSE
      PERFORM iam._cmd_resolve_context('act:iam.entities.write', v_close_edge.parent_org_id);
    END IF;
  END IF;

  IF v_child_kind = 'external_upline' THEN
    IF v_parent_kind <> 'platform_root'
       OR p_status <> 'active'
       OR p_close_edge_id IS NOT NULL
       OR NOT pg_catalog.upper_inf(p_valid_range)
       OR NOT (p_valid_range @> iam.business_today())
    THEN
      RAISE EXCEPTION 'EXTERNAL_UPLINE_MUST_STAY_UNDER_ROOT: external_upline must stay actively attached under platform_root open-ended from today.'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.set_organization_edge', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  IF p_replaces_edge_id IS NOT NULL THEN
    IF v_rep_edge.superseded_by_id IS NOT NULL THEN
      RAISE EXCEPTION 'EDGE_NOT_FOUND: live edge % for child % not found.', p_replaces_edge_id, p_child_org_id
        USING ERRCODE = 'P0002';
    END IF;
  END IF;

  IF p_close_edge_id IS NOT NULL THEN
    IF v_close_edge.superseded_by_id IS NOT NULL OR v_close_edge.status <> 'active' THEN
      RAISE EXCEPTION 'EDGE_NOT_FOUND: active edge % for child % not found.', p_close_edge_id, p_child_org_id
        USING ERRCODE = 'P0002';
    END IF;
  END IF;

  v_edge_id := pg_catalog.gen_random_uuid();
  IF p_close_edge_id IS NOT NULL THEN
    v_closed_new_id := pg_catalog.gen_random_uuid();
  END IF;

  v_result := pg_catalog.jsonb_build_object(
    'edge_id', v_edge_id,
    'closed_edge_id', v_closed_new_id,
    'child_org_id', p_child_org_id,
    'parent_org_id', p_parent_org_id,
    'valid_range', p_valid_range::text,
    'status', p_status
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, p_child_org_id,
    'iam.set_organization_edge', p_command_key, p_request_sha256, v_result
  );

  IF p_close_edge_id IS NOT NULL THEN
    INSERT INTO iam.organization_edges (
      id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq
    ) VALUES (
      v_closed_new_id, v_close_edge.child_org_id, v_close_edge.parent_org_id,
      p_close_valid_range, 'active', p_close_edge_id, v_seq
    );
  END IF;

  INSERT INTO iam.organization_edges (
    id, child_org_id, parent_org_id, valid_range, status, replaces_id, journal_seq
  ) VALUES (
    v_edge_id, p_child_org_id, p_parent_org_id, p_valid_range, p_status, p_replaces_edge_id, v_seq
  );

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 4: Create a company_local person, their initial active person_version, AND their first
-- dated works-for line (iam.organization_memberships) atomically so no person is unseen or unanchored.
CREATE OR REPLACE FUNCTION app_cmd.iam_create_person(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_organization_id UUID,
  p_legal_name TEXT,
  p_preferred_name TEXT,
  p_primary_email TEXT DEFAULT NULL,
  p_npn TEXT DEFAULT NULL,
  p_person_kind TEXT DEFAULT 'human',
  p_principal_origin TEXT DEFAULT 'company_local',
  p_house_org_id UUID DEFAULT NULL,
  p_person_id UUID DEFAULT NULL,
  p_valid_range DATERANGE DEFAULT NULL,
  p_work_arrangement TEXT DEFAULT NULL,
  p_tax_classification TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_person_id UUID;
  v_ver_id UUID;
  v_mem_id UUID;
  v_range DATERANGE;
  v_email TEXT := CASE WHEN p_primary_email IS NULL OR pg_catalog.btrim(p_primary_email) = '' THEN NULL ELSE pg_catalog.lower(pg_catalog.btrim(p_primary_email)) END;
  v_npn TEXT := CASE WHEN p_npn IS NULL OR pg_catalog.btrim(p_npn) = '' THEN NULL ELSE pg_catalog.btrim(p_npn) END;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.people.write');

  IF p_principal_origin IS DISTINCT FROM 'company_local' OR p_person_kind = 'service' THEN
    RAISE EXCEPTION 'FORBIDDEN_ORIGIN: runtime IAM commands create company_local people only; Nusear staff and service principals come from sync.'
      USING ERRCODE = '42501';
  END IF;

  IF p_organization_id IS NULL THEN
    RAISE EXCEPTION 'MISSING_ORGANIZATION_ID: organization_id is required to anchor the person with their first works-for line.'
      USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.people.write', p_organization_id);

  IF p_house_org_id IS NOT NULL AND p_house_org_id IS DISTINCT FROM p_organization_id THEN
    PERFORM iam._cmd_resolve_context('act:iam.people.write', p_house_org_id);
  END IF;

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.create_person', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  v_person_id := COALESCE(p_person_id, pg_catalog.gen_random_uuid());
  v_ver_id := pg_catalog.gen_random_uuid();
  v_mem_id := pg_catalog.gen_random_uuid();
  v_range := COALESCE(p_valid_range, pg_catalog.daterange(iam.business_today(), NULL, '[)'));

  v_result := pg_catalog.jsonb_build_object(
    'person_id', v_person_id,
    'version_id', v_ver_id,
    'membership_id', v_mem_id,
    'organization_id', p_organization_id,
    'work_arrangement', p_work_arrangement,
    'tax_classification', p_tax_classification,
    'valid_range', v_range::text,
    'person_kind', p_person_kind,
    'principal_origin', 'company_local',
    'status', 'active'
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, p_organization_id,
    'iam.create_person', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.people (id, person_kind, principal_origin, house_org_id, journal_seq)
  VALUES (v_person_id, p_person_kind, 'company_local', p_house_org_id, v_seq);

  INSERT INTO iam.person_versions (
    id, person_id, principal_origin, legal_name, preferred_name, primary_email, npn, status, journal_seq
  ) VALUES (
    v_ver_id, v_person_id, 'company_local', p_legal_name, p_preferred_name, v_email, v_npn, 'active', v_seq
  );

  INSERT INTO iam.organization_memberships (
    id, person_id, organization_id, work_arrangement, tax_classification, valid_range, status, journal_seq
  ) VALUES (
    v_mem_id, v_person_id, p_organization_id, p_work_arrangement, p_tax_classification, v_range, 'active', v_seq
  );

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 5: Set person status (active / suspended / archived) for company_local people only.
-- Suspending immediately zeroes reads and blocks writes; audit entry records the person's actual org.
CREATE OR REPLACE FUNCTION app_cmd.iam_set_person_status(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_person_id UUID,
  p_status TEXT,
  p_target_org_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_p RECORD;
  v_person_org_id UUID;
  v_ver_id UUID;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.people.write');

  IF p_status IS NULL OR p_status NOT IN ('active', 'suspended', 'archived') THEN
    RAISE EXCEPTION 'INVALID_PERSON_STATUS: status must be active, suspended, or archived (got %).', p_status
      USING ERRCODE = '22023';
  END IF;

  IF p_target_org_id IS NOT NULL THEN
    PERFORM iam._cmd_resolve_context('act:iam.people.write', p_target_org_id);
  END IF;

  SELECT p.id, p.principal_origin, p.house_org_id,
         pv.id AS version_id, pv.legal_name, pv.preferred_name, pv.primary_email, pv.npn, pv.status
  INTO v_p
  FROM iam.people p
  JOIN iam.person_versions pv ON pv.person_id = p.id AND pv.superseded_by_id IS NULL
  WHERE p.id = p_person_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'FORBIDDEN: target person is outside caller scope.' USING ERRCODE = '42501';
  END IF;

  IF v_p.principal_origin <> 'company_local' THEN
    RAISE EXCEPTION 'FORBIDDEN_ORIGIN: runtime IAM commands cannot modify % principals.', v_p.principal_origin
      USING ERRCODE = '42501';
  END IF;

  IF p_target_org_id IS NOT NULL THEN
    SELECT COALESCE(
      CASE WHEN v_p.house_org_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM iam.v_organization_closure c
        WHERE c.ancestor_org_id = p_target_org_id AND c.descendant_org_id = v_p.house_org_id
      ) THEN v_p.house_org_id END,
      (
        SELECT m.organization_id
        FROM iam.v_all_memberships_live m
        JOIN iam.v_organization_closure c
          ON c.ancestor_org_id = p_target_org_id AND c.descendant_org_id = m.organization_id
        WHERE m.person_id = p_person_id
        ORDER BY (m.valid_range @> iam.business_today()) DESC, pg_catalog.lower(m.valid_range) DESC
        LIMIT 1
      )
    ) INTO v_person_org_id;
    IF v_person_org_id IS NULL THEN
      RAISE EXCEPTION 'FORBIDDEN: person % is outside target organization %.', p_person_id, p_target_org_id
        USING ERRCODE = '42501';
    END IF;
  ELSE
    v_person_org_id := COALESCE(
      v_p.house_org_id,
      (
        SELECT m.organization_id
        FROM iam.v_all_memberships_live m
        WHERE m.person_id = p_person_id
        ORDER BY (m.valid_range @> iam.business_today()) DESC, pg_catalog.lower(m.valid_range) DESC
        LIMIT 1
      ),
      (SELECT m.organization_id FROM iam.organization_memberships m WHERE m.person_id = p_person_id AND m.superseded_by_id IS NULL LIMIT 1),
      (SELECT aa.agency_org_id FROM iam.agent_affiliations aa WHERE aa.person_id = p_person_id AND aa.superseded_by_id IS NULL LIMIT 1)
    );
    IF v_person_org_id IS NULL THEN
      RAISE EXCEPTION 'FORBIDDEN: person % has no organization anchor.', p_person_id USING ERRCODE = '42501';
    END IF;
  END IF;

  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.people.write', v_person_org_id);

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.set_person_status', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  v_ver_id := pg_catalog.gen_random_uuid();
  v_result := pg_catalog.jsonb_build_object(
    'person_id', p_person_id,
    'version_id', v_ver_id,
    'replaces_version_id', v_p.version_id,
    'previous_status', v_p.status,
    'status', p_status
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, v_person_org_id,
    'iam.set_person_status', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.person_versions (
    id, person_id, principal_origin, legal_name, preferred_name, primary_email, npn, status, replaces_id, journal_seq
  ) VALUES (
    v_ver_id, p_person_id, v_p.principal_origin, v_p.legal_name, v_p.preferred_name,
    v_p.primary_email, v_p.npn, p_status, v_p.version_id, v_seq
  );

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 6: Set/supersede/revoke a dated works-for membership line (company_local people only).
CREATE OR REPLACE FUNCTION app_cmd.iam_set_membership(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_person_id UUID,
  p_organization_id UUID,
  p_valid_range DATERANGE,
  p_work_arrangement TEXT DEFAULT NULL,
  p_tax_classification TEXT DEFAULT NULL,
  p_replaces_id UUID DEFAULT NULL,
  p_status TEXT DEFAULT 'active'
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_person_origin TEXT;
  v_old_org_id UUID;
  v_mem_id UUID;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.people.write');

  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.people.write', p_organization_id);

  IF NOT EXISTS (SELECT 1 FROM iam.organizations o WHERE o.id = p_organization_id) THEN
    RAISE EXCEPTION 'ORG_NOT_FOUND: organization % not found.', p_organization_id USING ERRCODE = 'P0002';
  END IF;

  SELECT p.principal_origin INTO v_person_origin FROM iam.people p WHERE p.id = p_person_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PERSON_NOT_FOUND: person % not found.', p_person_id USING ERRCODE = 'P0002';
  END IF;
  IF v_person_origin <> 'company_local' THEN
    RAISE EXCEPTION 'FORBIDDEN_ORIGIN: runtime IAM commands cannot manage memberships of % principals.', v_person_origin
      USING ERRCODE = '42501';
  END IF;

  IF p_replaces_id IS NOT NULL THEN
    SELECT m.organization_id INTO v_old_org_id
    FROM iam.organization_memberships m
    WHERE m.id = p_replaces_id AND m.person_id = p_person_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'MEMBERSHIP_NOT_FOUND: membership % for person % not found.', p_replaces_id, p_person_id
        USING ERRCODE = 'P0002';
    END IF;
    IF v_old_org_id <> p_organization_id THEN
      PERFORM iam._cmd_resolve_context('act:iam.people.write', v_old_org_id);
    END IF;
  END IF;

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.set_membership', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  IF p_replaces_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM iam.organization_memberships m
    WHERE m.id = p_replaces_id AND m.superseded_by_id IS NULL AND m.person_id = p_person_id
  ) THEN
    RAISE EXCEPTION 'MEMBERSHIP_NOT_FOUND: live membership % for person % not found.', p_replaces_id, p_person_id
      USING ERRCODE = 'P0002';
  END IF;

  v_mem_id := pg_catalog.gen_random_uuid();
  v_result := pg_catalog.jsonb_build_object(
    'membership_id', v_mem_id,
    'person_id', p_person_id,
    'organization_id', p_organization_id,
    'work_arrangement', p_work_arrangement,
    'tax_classification', p_tax_classification,
    'valid_range', p_valid_range::text,
    'status', p_status
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, p_organization_id,
    'iam.set_membership', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.organization_memberships (
    id, person_id, organization_id, work_arrangement, tax_classification, valid_range, status, replaces_id, journal_seq
  ) VALUES (
    v_mem_id, p_person_id, p_organization_id, p_work_arrangement, p_tax_classification,
    p_valid_range, p_status, p_replaces_id, v_seq
  );

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 7: Set/supersede/revoke a dated selling-agent affiliation (company_local people only).
CREATE OR REPLACE FUNCTION app_cmd.iam_set_agent_affiliation(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_person_id UUID,
  p_npn TEXT,
  p_agency_org_id UUID,
  p_split_bps INTEGER,
  p_agent_file_name TEXT,
  p_valid_range DATERANGE,
  p_carrier_id UUID DEFAULT NULL,
  p_replaces_id UUID DEFAULT NULL,
  p_status TEXT DEFAULT 'active'
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_person_origin TEXT;
  v_old_org_id UUID;
  v_aff_id UUID;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.people.write');
  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.people.write', p_agency_org_id);

  SELECT p.principal_origin INTO v_person_origin FROM iam.people p WHERE p.id = p_person_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PERSON_NOT_FOUND: person % not found.', p_person_id USING ERRCODE = 'P0002';
  END IF;
  IF v_person_origin <> 'company_local' THEN
    RAISE EXCEPTION 'FORBIDDEN_ORIGIN: runtime IAM commands cannot manage affiliations of % principals.', v_person_origin
      USING ERRCODE = '42501';
  END IF;

  IF p_replaces_id IS NOT NULL THEN
    SELECT aa.agency_org_id INTO v_old_org_id
    FROM iam.agent_affiliations aa
    WHERE aa.id = p_replaces_id AND aa.person_id = p_person_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'AFFILIATION_NOT_FOUND: agent affiliation % for person % not found.', p_replaces_id, p_person_id
        USING ERRCODE = 'P0002';
    END IF;
    IF v_old_org_id <> p_agency_org_id THEN
      PERFORM iam._cmd_resolve_context('act:iam.people.write', v_old_org_id);
    END IF;
  END IF;

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.set_agent_affiliation', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  IF p_replaces_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM iam.agent_affiliations aa
    WHERE aa.id = p_replaces_id AND aa.superseded_by_id IS NULL AND aa.person_id = p_person_id
  ) THEN
    RAISE EXCEPTION 'AFFILIATION_NOT_FOUND: live agent affiliation % for person % not found.', p_replaces_id, p_person_id
      USING ERRCODE = 'P0002';
  END IF;

  v_aff_id := pg_catalog.gen_random_uuid();
  v_result := pg_catalog.jsonb_build_object(
    'agent_affiliation_id', v_aff_id,
    'person_id', p_person_id,
    'npn', p_npn,
    'agency_org_id', p_agency_org_id,
    'split_bps', p_split_bps,
    'valid_range', p_valid_range::text,
    'status', p_status
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, p_agency_org_id,
    'iam.set_agent_affiliation', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.agent_affiliations (
    id, person_id, npn, agency_org_id, carrier_id, split_bps, agent_file_name, valid_range, status, replaces_id, journal_seq
  ) VALUES (
    v_aff_id, p_person_id, p_npn, p_agency_org_id, p_carrier_id, p_split_bps,
    p_agent_file_name, p_valid_range, p_status, p_replaces_id, v_seq
  );

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 8: Create a new empty company custom role (starts with ZERO rights; built-in roles refused).
CREATE OR REPLACE FUNCTION app_cmd.iam_create_role(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_owner_org_id UUID,
  p_slug TEXT,
  p_display_name TEXT,
  p_allows_org_wide_scope BOOLEAN DEFAULT true,
  p_forbids_company_revenue_rights BOOLEAN DEFAULT false,
  p_role_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_role_id UUID;
  v_ver_id UUID;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.roles.write');
  IF p_owner_org_id IS NULL THEN
    RAISE EXCEPTION 'FORBIDDEN_BUILTIN_ROLE: built-in roles (owner_org_id IS NULL) cannot be created at runtime.'
      USING ERRCODE = '42501';
  END IF;
  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.roles.write', p_owner_org_id);

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.create_role', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  v_role_id := COALESCE(p_role_id, pg_catalog.gen_random_uuid());
  v_ver_id := pg_catalog.gen_random_uuid();
  v_result := pg_catalog.jsonb_build_object(
    'role_id', v_role_id,
    'version_id', v_ver_id,
    'owner_org_id', p_owner_org_id,
    'slug', p_slug,
    'display_name', p_display_name,
    'allows_org_wide_scope', COALESCE(p_allows_org_wide_scope, true),
    'requires_self_scope', false,
    'forbids_company_revenue_rights', COALESCE(p_forbids_company_revenue_rights, false),
    'right_ids', '[]'::jsonb
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, p_owner_org_id,
    'iam.create_role', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq)
  VALUES (v_role_id, p_slug, p_owner_org_id, v_seq);

  INSERT INTO iam.role_versions (
    id, role_id, display_name, is_pinned, is_nusear_internal,
    allows_org_wide_scope, requires_self_scope, forbids_company_revenue_rights, status, journal_seq
  ) VALUES (
    v_ver_id, v_role_id, p_display_name, false, false,
    COALESCE(p_allows_org_wide_scope, true), false, COALESCE(p_forbids_company_revenue_rights, false), 'active', v_seq
  );

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 9: Copy a non-internal role's active rights into a new company-owned role with optional adjustments.
-- Preserves forbids_company_revenue_rights, allows_org_wide_scope, and requires_self_scope;
-- refuses built-in target (owner_org_id IS NULL), Nusear-internal sources, and non-delegable rights.
CREATE OR REPLACE FUNCTION app_cmd.iam_copy_role(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_source_role_id UUID,
  p_owner_org_id UUID,
  p_new_slug TEXT,
  p_new_display_name TEXT,
  p_add_right_ids TEXT[] DEFAULT ARRAY[]::text[],
  p_remove_right_ids TEXT[] DEFAULT ARRAY[]::text[],
  p_new_role_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_src RECORD;
  v_new_role_id UUID;
  v_ver_id UUID;
  v_final_rights TEXT[];
  v_rid TEXT;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.roles.write');
  IF p_owner_org_id IS NULL THEN
    RAISE EXCEPTION 'FORBIDDEN_BUILTIN_ROLE: built-in roles (owner_org_id IS NULL) cannot be created at runtime.'
      USING ERRCODE = '42501';
  END IF;
  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.roles.write', p_owner_org_id);

  SELECT r.id, r.owner_org_id, rv.is_nusear_internal, rv.allows_org_wide_scope,
         rv.requires_self_scope, rv.forbids_company_revenue_rights
  INTO v_src
  FROM iam.roles r
  JOIN iam.role_versions rv ON rv.role_id = r.id AND rv.superseded_by_id IS NULL AND rv.status = 'active'
  WHERE r.id = p_source_role_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'ROLE_NOT_FOUND: active source role % not found.', p_source_role_id USING ERRCODE = 'P0002';
  END IF;

  IF v_src.is_nusear_internal THEN
    RAISE EXCEPTION 'FORBIDDEN_INTERNAL_ROLE: Nusear-internal roles cannot be copied at runtime.'
      USING ERRCODE = '42501';
  END IF;
  IF v_src.owner_org_id IS NOT NULL AND v_src.owner_org_id IS DISTINCT FROM p_owner_org_id THEN
    PERFORM iam._cmd_resolve_context('act:iam.roles.write', v_src.owner_org_id);
  END IF;

  SELECT COALESCE(pg_catalog.array_agg(DISTINCT x.right_id ORDER BY x.right_id), ARRAY[]::text[])
  INTO v_final_rights
  FROM (
    SELECT rr.right_id
    FROM iam.role_rights rr
    WHERE rr.role_id = p_source_role_id
      AND rr.superseded_by_id IS NULL
      AND rr.status = 'active'
      AND NOT EXISTS (SELECT 1 FROM iam.right_retirements ret WHERE ret.right_id = rr.right_id)
      AND NOT (rr.right_id = ANY(COALESCE(p_remove_right_ids, ARRAY[]::text[])))
    UNION
    SELECT u.right_id
    FROM pg_catalog.unnest(COALESCE(p_add_right_ids, ARRAY[]::text[])) AS u(right_id)
    WHERE u.right_id IS NOT NULL
  ) x;

  FOREACH v_rid IN ARRAY v_final_rights LOOP
    PERFORM iam._cmd_validate_role_right(v_rid, 'active');
  END LOOP;

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.copy_role', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  v_new_role_id := COALESCE(p_new_role_id, pg_catalog.gen_random_uuid());
  v_ver_id := pg_catalog.gen_random_uuid();
  v_result := pg_catalog.jsonb_build_object(
    'role_id', v_new_role_id,
    'version_id', v_ver_id,
    'source_role_id', p_source_role_id,
    'owner_org_id', p_owner_org_id,
    'slug', p_new_slug,
    'display_name', p_new_display_name,
    'allows_org_wide_scope', v_src.allows_org_wide_scope,
    'requires_self_scope', v_src.requires_self_scope,
    'forbids_company_revenue_rights', v_src.forbids_company_revenue_rights,
    'right_ids', pg_catalog.to_jsonb(v_final_rights)
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, p_owner_org_id,
    'iam.copy_role', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq)
  VALUES (v_new_role_id, p_new_slug, p_owner_org_id, v_seq);

  INSERT INTO iam.role_versions (
    id, role_id, display_name, is_pinned, is_nusear_internal,
    allows_org_wide_scope, requires_self_scope, forbids_company_revenue_rights, status, journal_seq
  ) VALUES (
    v_ver_id, v_new_role_id, p_new_display_name, false, false,
    v_src.allows_org_wide_scope, v_src.requires_self_scope, v_src.forbids_company_revenue_rights, 'active', v_seq
  );

  FOREACH v_rid IN ARRAY v_final_rights LOOP
    INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq)
    VALUES (pg_catalog.gen_random_uuid(), v_new_role_id, v_rid, 'active', v_seq);
  END LOOP;

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 10: Update a company custom role's display_name or status while preserving constraints.
-- Refuses built-in roles (owner_org_id IS NULL), pinned roles, and internal roles.
CREATE OR REPLACE FUNCTION app_cmd.iam_update_role(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_role_id UUID,
  p_display_name TEXT DEFAULT NULL,
  p_status TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_r RECORD;
  v_ver_id UUID;
  v_new_display TEXT;
  v_new_status TEXT;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.roles.write');

  SELECT r.id, r.owner_org_id,
         rv.id AS version_id, rv.display_name, rv.is_pinned, rv.is_nusear_internal,
         rv.allows_org_wide_scope, rv.requires_self_scope, rv.forbids_company_revenue_rights, rv.status
  INTO v_r
  FROM iam.roles r
  JOIN iam.role_versions rv ON rv.role_id = r.id AND rv.superseded_by_id IS NULL
  WHERE r.id = p_role_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'FORBIDDEN: target role is outside caller scope.' USING ERRCODE = '42501';
  END IF;

  IF v_r.owner_org_id IS NULL OR v_r.is_pinned OR v_r.is_nusear_internal THEN
    RAISE EXCEPTION 'FORBIDDEN_BUILTIN_ROLE: built-in roles cannot be modified at runtime.'
      USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.roles.write', v_r.owner_org_id);

  v_new_display := COALESCE(p_display_name, v_r.display_name);
  v_new_status := COALESCE(p_status, v_r.status);

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.update_role', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  v_ver_id := pg_catalog.gen_random_uuid();
  v_result := pg_catalog.jsonb_build_object(
    'role_id', p_role_id,
    'version_id', v_ver_id,
    'replaces_version_id', v_r.version_id,
    'display_name', v_new_display,
    'allows_org_wide_scope', v_r.allows_org_wide_scope,
    'requires_self_scope', v_r.requires_self_scope,
    'forbids_company_revenue_rights', v_r.forbids_company_revenue_rights,
    'status', v_new_status
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, v_r.owner_org_id,
    'iam.update_role', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.role_versions (
    id, role_id, display_name, is_pinned, is_nusear_internal,
    allows_org_wide_scope, requires_self_scope, forbids_company_revenue_rights, status, replaces_id, journal_seq
  ) VALUES (
    v_ver_id, p_role_id, v_new_display, v_r.is_pinned, v_r.is_nusear_internal,
    v_r.allows_org_wide_scope, v_r.requires_self_scope, v_r.forbids_company_revenue_rights, v_new_status, v_r.version_id, v_seq
  );

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 11: Add or revoke a right on a company custom role (refuses built-in roles,
-- non-delegable owner/worker powers, internal rights, and forbidden company-revenue rights).
CREATE OR REPLACE FUNCTION app_cmd.iam_set_role_right(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_role_id UUID,
  p_right_id TEXT,
  p_status TEXT DEFAULT 'active'
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_r RECORD;
  v_cur_rr_id UUID;
  v_new_rr_id UUID;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.roles.write');

  IF p_status IS NULL OR p_status NOT IN ('active', 'revoked') THEN
    RAISE EXCEPTION 'INVALID_STATUS: role_right status must be active or revoked.' USING ERRCODE = '22023';
  END IF;

  SELECT r.id, r.owner_org_id, rv.is_pinned, rv.is_nusear_internal
  INTO v_r
  FROM iam.roles r
  JOIN iam.role_versions rv ON rv.role_id = r.id AND rv.superseded_by_id IS NULL
  WHERE r.id = p_role_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'FORBIDDEN: target role is outside caller scope.' USING ERRCODE = '42501';
  END IF;

  IF v_r.owner_org_id IS NULL OR v_r.is_pinned OR v_r.is_nusear_internal THEN
    RAISE EXCEPTION 'FORBIDDEN_BUILTIN_ROLE: built-in roles cannot be modified at runtime.'
      USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.roles.write', v_r.owner_org_id);

  PERFORM iam._cmd_validate_role_right(p_right_id, p_status);

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.set_role_right', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  SELECT rr.id INTO v_cur_rr_id
  FROM iam.role_rights rr
  WHERE rr.role_id = p_role_id AND rr.right_id = p_right_id AND rr.superseded_by_id IS NULL;

  IF p_status = 'revoked' AND v_cur_rr_id IS NULL THEN
    RAISE EXCEPTION 'ROLE_RIGHT_NOT_FOUND: role % does not hold right %.', p_role_id, p_right_id USING ERRCODE = 'P0002';
  END IF;

  v_new_rr_id := pg_catalog.gen_random_uuid();
  v_result := pg_catalog.jsonb_build_object(
    'role_right_id', v_new_rr_id,
    'role_id', p_role_id,
    'right_id', p_right_id,
    'status', p_status,
    'replaces_id', v_cur_rr_id
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, v_r.owner_org_id,
    'iam.set_role_right', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.role_rights (id, role_id, right_id, status, replaces_id, journal_seq)
  VALUES (v_new_rr_id, p_role_id, p_right_id, p_status, v_cur_rr_id, v_seq);

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 12: Grant or supersede a dated role grant for a company_local person.
-- Refuses platform_root, Nusear-internal roles, and Nusear/service principals; enforces custom role
-- owner tree, self-only agent roles (trg_verify_role_grant_scope), explicit_people company-tree
-- subjects (trg_role_grant_people_verify), and active subject carry-over (trg_02_carry_explicit_people).
CREATE OR REPLACE FUNCTION app_cmd.iam_grant_role(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_person_id UUID,
  p_role_id UUID,
  p_organization_id UUID,
  p_person_scope_mode TEXT,
  p_valid_range DATERANGE,
  p_include_descendants BOOLEAN DEFAULT true,
  p_data_date_range DATERANGE DEFAULT NULL,
  p_replaces_grant_id UUID DEFAULT NULL,
  p_subject_person_ids UUID[] DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_person_origin TEXT;
  v_role RECORD;
  v_old_grant RECORD;
  v_inc BOOLEAN := COALESCE(p_include_descendants, true);
  v_grant_id UUID;
  v_carried UUID[] := ARRAY[]::uuid[];
  v_final_subjects UUID[] := ARRAY[]::uuid[];
  v_sid UUID;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.grants.write');

  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.grants.write', p_organization_id);

  IF NOT EXISTS (SELECT 1 FROM iam.organizations o WHERE o.id = p_organization_id) THEN
    RAISE EXCEPTION 'ORG_NOT_FOUND: organization % not found.', p_organization_id USING ERRCODE = 'P0002';
  END IF;

  SELECT p.principal_origin INTO v_person_origin FROM iam.people p WHERE p.id = p_person_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PERSON_NOT_FOUND: person % not found.', p_person_id USING ERRCODE = 'P0002';
  END IF;
  IF v_person_origin <> 'company_local' THEN
    RAISE EXCEPTION 'FORBIDDEN_ORIGIN: runtime IAM commands cannot manage grants of % principals.', v_person_origin
      USING ERRCODE = '42501';
  END IF;

  SELECT r.id, r.slug, r.owner_org_id, rv.is_nusear_internal, rv.allows_org_wide_scope, rv.requires_self_scope
  INTO v_role
  FROM iam.roles r
  JOIN iam.role_versions rv ON rv.role_id = r.id AND rv.superseded_by_id IS NULL AND rv.status = 'active'
  WHERE r.id = p_role_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ROLE_NOT_FOUND: active role % not found.', p_role_id USING ERRCODE = 'P0002';
  END IF;

  IF v_role.is_nusear_internal THEN
    RAISE EXCEPTION 'FORBIDDEN_INTERNAL_ROLE: Nusear-internal roles cannot be granted at runtime.'
      USING ERRCODE = '42501';
  END IF;

  IF v_role.owner_org_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM iam.v_organization_closure_live c
    WHERE c.ancestor_org_id = v_role.owner_org_id
      AND c.descendant_org_id = p_organization_id
  ) THEN
    RAISE EXCEPTION 'CUSTOM_ROLE_OUTSIDE_OWNER_TREE: custom role % can only be granted inside owner organization % tree.',
      p_role_id, v_role.owner_org_id USING ERRCODE = '42501';
  END IF;

  IF p_subject_person_ids IS NOT NULL
     AND pg_catalog.cardinality(p_subject_person_ids) > 0
     AND p_person_scope_mode IS DISTINCT FROM 'explicit_people'
  THEN
    RAISE EXCEPTION 'EXPLICIT_PEOPLE_SCOPE_REQUIRED: subject_person_ids requires person_scope_mode = explicit_people.'
      USING ERRCODE = '23514';
  END IF;

  IF p_replaces_grant_id IS NOT NULL THEN
    SELECT g.id, g.person_id, g.organization_id, g.superseded_by_id
    INTO v_old_grant
    FROM iam.role_grants g
    WHERE g.id = p_replaces_grant_id;
    IF NOT FOUND OR v_old_grant.person_id <> p_person_id THEN
      RAISE EXCEPTION 'ROLE_GRANT_NOT_FOUND: role_grant % for person % not found.', p_replaces_grant_id, p_person_id
        USING ERRCODE = 'P0002';
    END IF;
    IF v_old_grant.organization_id <> p_organization_id THEN
      PERFORM iam._cmd_resolve_context('act:iam.grants.write', v_old_grant.organization_id);
    END IF;
  END IF;

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.grant_role', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  IF p_replaces_grant_id IS NOT NULL THEN
    IF v_old_grant.superseded_by_id IS NOT NULL THEN
      RAISE EXCEPTION 'ROLE_GRANT_NOT_FOUND: live role_grant % for person % not found.', p_replaces_grant_id, p_person_id
        USING ERRCODE = 'P0002';
    END IF;
  END IF;

  IF p_replaces_grant_id IS NOT NULL AND p_person_scope_mode = 'explicit_people' THEN
    SELECT COALESCE(pg_catalog.array_agg(DISTINCT rgp.subject_person_id ORDER BY rgp.subject_person_id), ARRAY[]::uuid[])
    INTO v_carried
    FROM iam.role_grant_people rgp
    WHERE rgp.role_grant_id = p_replaces_grant_id
      AND rgp.superseded_by_id IS NULL
      AND rgp.status = 'active';
  END IF;

  IF p_person_scope_mode = 'explicit_people' THEN
    SELECT COALESCE(pg_catalog.array_agg(DISTINCT u.sid ORDER BY u.sid), ARRAY[]::uuid[])
    INTO v_final_subjects
    FROM (
      SELECT sid FROM pg_catalog.unnest(v_carried) AS sid
      UNION
      SELECT sid FROM pg_catalog.unnest(COALESCE(p_subject_person_ids, ARRAY[]::uuid[])) AS sid WHERE sid IS NOT NULL
    ) u;
  END IF;

  v_grant_id := pg_catalog.gen_random_uuid();
  v_result := pg_catalog.jsonb_build_object(
    'role_grant_id', v_grant_id,
    'person_id', p_person_id,
    'role_id', p_role_id,
    'organization_id', p_organization_id,
    'person_scope_mode', p_person_scope_mode,
    'include_descendants', v_inc,
    'valid_range', p_valid_range::text,
    'data_date_range', CASE WHEN p_data_date_range IS NULL THEN NULL ELSE p_data_date_range::text END,
    'replaces_grant_id', p_replaces_grant_id,
    'carried_subject_person_ids', pg_catalog.to_jsonb(v_carried),
    'subject_person_ids', pg_catalog.to_jsonb(v_final_subjects),
    'status', 'active'
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, p_organization_id,
    'iam.grant_role', p_command_key, p_request_sha256, v_result
  );

  -- Note: trg_02_carry_explicit_people automatically carries active subjects from p_replaces_grant_id onto v_grant_id.
  INSERT INTO iam.role_grants (
    id, person_id, role_id, organization_id, include_descendants, person_scope_mode,
    data_date_range, valid_range, status, replaces_id, journal_seq
  ) VALUES (
    v_grant_id, p_person_id, p_role_id, p_organization_id, v_inc, p_person_scope_mode,
    p_data_date_range, p_valid_range, 'active', p_replaces_grant_id, v_seq
  );

  IF p_person_scope_mode = 'explicit_people' AND p_subject_person_ids IS NOT NULL THEN
    FOREACH v_sid IN ARRAY p_subject_person_ids LOOP
      IF v_sid IS NOT NULL AND NOT (v_sid = ANY(v_carried)) THEN
        INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, journal_seq)
        SELECT pg_catalog.gen_random_uuid(), v_grant_id, v_sid, 'active', v_seq
        WHERE NOT EXISTS (
          SELECT 1 FROM iam.role_grant_people ex
          WHERE ex.role_grant_id = v_grant_id
            AND ex.subject_person_id = v_sid
            AND ex.superseded_by_id IS NULL
            AND ex.status = 'active'
        );
      END IF;
    END LOOP;
  END IF;

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 13: Revoke a single dated role grant line without touching any sibling role lines.
-- Refuses grants of nusear_staff/service principals and platform_root grants.
CREATE OR REPLACE FUNCTION app_cmd.iam_revoke_role_grant(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_role_grant_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_g RECORD;
  v_person_origin TEXT;
  v_new_id UUID;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.grants.write');

  SELECT g.* INTO v_g
  FROM iam.role_grants g
  WHERE g.id = p_role_grant_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'FORBIDDEN: target role grant is outside caller scope.' USING ERRCODE = '42501';
  END IF;

  SELECT p.principal_origin INTO v_person_origin FROM iam.people p WHERE p.id = v_g.person_id;
  IF v_person_origin <> 'company_local' THEN
    RAISE EXCEPTION 'FORBIDDEN_ORIGIN: runtime IAM commands cannot revoke grants of % principals.', v_person_origin
      USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.grants.write', v_g.organization_id);

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.revoke_role_grant', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  IF v_g.superseded_by_id IS NOT NULL THEN
    RAISE EXCEPTION 'ROLE_GRANT_NOT_FOUND: live role_grant % not found.', p_role_grant_id USING ERRCODE = 'P0002';
  END IF;
  IF v_g.status = 'revoked' THEN
    RAISE EXCEPTION 'ROLE_GRANT_ALREADY_REVOKED: role_grant % is already revoked.', p_role_grant_id USING ERRCODE = '23514';
  END IF;

  v_new_id := pg_catalog.gen_random_uuid();
  v_result := pg_catalog.jsonb_build_object(
    'revoked_grant_id', v_new_id,
    'replaces_grant_id', v_g.id,
    'person_id', v_g.person_id,
    'role_id', v_g.role_id,
    'organization_id', v_g.organization_id,
    'status', 'revoked'
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, v_g.organization_id,
    'iam.revoke_role_grant', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.role_grants (
    id, person_id, role_id, organization_id, include_descendants, person_scope_mode,
    data_date_range, valid_range, status, replaces_id, journal_seq
  ) VALUES (
    v_new_id, v_g.person_id, v_g.role_id, v_g.organization_id, v_g.include_descendants, v_g.person_scope_mode,
    v_g.data_date_range, v_g.valid_range, 'revoked', v_g.id, v_seq
  );

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 14: Add or revoke one permitted person on an active explicit_people role grant.
CREATE OR REPLACE FUNCTION app_cmd.iam_set_role_grant_person(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_role_grant_id UUID,
  p_subject_person_id UUID,
  p_status TEXT DEFAULT 'active'
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_g RECORD;
  v_person_origin TEXT;
  v_cur_id UUID;
  v_new_id UUID;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.grants.write');

  IF p_status IS NULL OR p_status NOT IN ('active', 'revoked') THEN
    RAISE EXCEPTION 'INVALID_STATUS: role_grant_people status must be active or revoked.' USING ERRCODE = '22023';
  END IF;

  SELECT g.id, g.person_id, g.role_id, g.organization_id, g.person_scope_mode, g.status, g.superseded_by_id
  INTO v_g
  FROM iam.role_grants g
  WHERE g.id = p_role_grant_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'FORBIDDEN: target role grant is outside caller scope.' USING ERRCODE = '42501';
  END IF;

  SELECT p.principal_origin INTO v_person_origin FROM iam.people p WHERE p.id = v_g.person_id;
  IF v_person_origin <> 'company_local' THEN
    RAISE EXCEPTION 'FORBIDDEN_ORIGIN: runtime IAM commands cannot modify grants of % principals.', v_person_origin
      USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.grants.write', v_g.organization_id);

  IF v_g.person_scope_mode IS DISTINCT FROM 'explicit_people' THEN
    RAISE EXCEPTION 'EXPLICIT_PEOPLE_SCOPE_REQUIRED: role_grant % has person_scope_mode = % (expected explicit_people).',
      p_role_grant_id, v_g.person_scope_mode USING ERRCODE = '23514';
  END IF;

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.set_role_grant_person', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  IF v_g.superseded_by_id IS NOT NULL OR v_g.status <> 'active' THEN
    RAISE EXCEPTION 'EXPLICIT_PEOPLE_GRANT_INACTIVE: role_grant % must be live and active to modify role_grant_people.',
      p_role_grant_id USING ERRCODE = '23514';
  END IF;

  SELECT rgp.id INTO v_cur_id
  FROM iam.role_grant_people rgp
  WHERE rgp.role_grant_id = p_role_grant_id
    AND rgp.subject_person_id = p_subject_person_id
    AND rgp.superseded_by_id IS NULL;

  IF p_status = 'revoked' AND v_cur_id IS NULL THEN
    RAISE EXCEPTION 'ROLE_GRANT_PERSON_NOT_FOUND: subject % is not attached to role_grant %.',
      p_subject_person_id, p_role_grant_id USING ERRCODE = 'P0002';
  END IF;

  v_new_id := pg_catalog.gen_random_uuid();
  v_result := pg_catalog.jsonb_build_object(
    'role_grant_person_id', v_new_id,
    'role_grant_id', p_role_grant_id,
    'subject_person_id', p_subject_person_id,
    'status', p_status,
    'replaces_id', v_cur_id
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, v_g.organization_id,
    'iam.set_role_grant_person', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, replaces_id, journal_seq)
  VALUES (v_new_id, p_role_grant_id, p_subject_person_id, p_status, v_cur_id, v_seq);

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

-- Command 15: Set or revoke a per-organization tool switch (refuses platform_root).
CREATE OR REPLACE FUNCTION app_cmd.iam_set_tool_switch(
  p_command_key TEXT,
  p_request_sha256 TEXT,
  p_organization_id UUID,
  p_tool_id TEXT,
  p_switch_state TEXT,
  p_hold_reason TEXT DEFAULT NULL,
  p_status TEXT DEFAULT 'active'
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx RECORD;
  v_idem RECORD;
  v_cur_id UUID;
  v_new_id UUID;
  v_result JSONB;
  v_seq BIGINT;
BEGIN
  PERFORM iam._cmd_require_nusear_staff('act:iam.switches.write');

  SELECT * INTO v_ctx FROM iam._cmd_resolve_context('act:iam.switches.write', p_organization_id);

  IF NOT EXISTS (SELECT 1 FROM iam.organizations o WHERE o.id = p_organization_id) THEN
    RAISE EXCEPTION 'ORG_NOT_FOUND: organization % not found.', p_organization_id USING ERRCODE = 'P0002';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM iam.tools t WHERE t.id = p_tool_id) THEN
    RAISE EXCEPTION 'TOOL_NOT_FOUND: tool % not found.', p_tool_id USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO v_idem FROM iam._cmd_check_idempotency(
    'iam.set_tool_switch', p_command_key, v_ctx.actor_person_id, v_ctx.recorded_as, p_request_sha256
  );
  IF v_idem.existing_seq IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('idempotent', true, 'journal_seq', v_idem.existing_seq, 'result', v_idem.existing_result);
  END IF;

  SELECT ts.id INTO v_cur_id
  FROM iam.organization_tool_switches ts
  WHERE ts.organization_id = p_organization_id
    AND ts.tool_id = p_tool_id
    AND ts.superseded_by_id IS NULL;

  v_new_id := pg_catalog.gen_random_uuid();
  v_result := pg_catalog.jsonb_build_object(
    'tool_switch_id', v_new_id,
    'organization_id', p_organization_id,
    'tool_id', p_tool_id,
    'switch_state', p_switch_state,
    'hold_reason', p_hold_reason,
    'status', p_status,
    'replaces_id', v_cur_id
  );

  v_seq := iam._cmd_append_audit(
    v_ctx.environment, v_ctx.actor_person_id, v_ctx.recorded_as, p_organization_id,
    'iam.set_tool_switch', p_command_key, p_request_sha256, v_result
  );

  INSERT INTO iam.organization_tool_switches (
    id, organization_id, tool_id, switch_state, hold_reason, status, replaces_id, journal_seq
  ) VALUES (
    v_new_id, p_organization_id, p_tool_id, p_switch_state, p_hold_reason, p_status, v_cur_id, v_seq
  );

  RETURN pg_catalog.jsonb_build_object('idempotent', false, 'journal_seq', v_seq, 'result', v_result);
END;
$$;

DO $$
DECLARE
  v_sig TEXT;
BEGIN
  FOREACH v_sig IN ARRAY ARRAY[
    'app_cmd.iam_create_organization(TEXT, TEXT, TEXT, TEXT, TEXT, UUID, DATE, TEXT, TEXT, UUID)',
    'app_cmd.iam_update_organization(TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT)',
    'app_cmd.iam_set_organization_edge(TEXT, TEXT, UUID, UUID, DATERANGE, UUID, TEXT, UUID, DATERANGE)',
    'app_cmd.iam_create_person(TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, UUID, UUID, DATERANGE, TEXT, TEXT)',
    'app_cmd.iam_set_person_status(TEXT, TEXT, UUID, TEXT, UUID)',
    'app_cmd.iam_set_membership(TEXT, TEXT, UUID, UUID, DATERANGE, TEXT, TEXT, UUID, TEXT)',
    'app_cmd.iam_set_agent_affiliation(TEXT, TEXT, UUID, TEXT, UUID, INTEGER, TEXT, DATERANGE, UUID, UUID, TEXT)',
    'app_cmd.iam_create_role(TEXT, TEXT, UUID, TEXT, TEXT, BOOLEAN, BOOLEAN, UUID)',
    'app_cmd.iam_copy_role(TEXT, TEXT, UUID, UUID, TEXT, TEXT, TEXT[], TEXT[], UUID)',
    'app_cmd.iam_update_role(TEXT, TEXT, UUID, TEXT, TEXT)',
    'app_cmd.iam_set_role_right(TEXT, TEXT, UUID, TEXT, TEXT)',
    'app_cmd.iam_grant_role(TEXT, TEXT, UUID, UUID, UUID, TEXT, DATERANGE, BOOLEAN, DATERANGE, UUID, UUID[])',
    'app_cmd.iam_revoke_role_grant(TEXT, TEXT, UUID)',
    'app_cmd.iam_set_role_grant_person(TEXT, TEXT, UUID, UUID, TEXT)',
    'app_cmd.iam_set_tool_switch(TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT)'
  ] LOOP
    EXECUTE 'ALTER FUNCTION ' || v_sig || ' OWNER TO platform_writer';
    EXECUTE 'REVOKE ALL ON FUNCTION ' || v_sig || ' FROM PUBLIC, platform_readonly, platform_worker, platform_iam_sync, platform_auth_lookup, platform_view_owner, platform_versioner';
    EXECUTE 'GRANT EXECUTE ON FUNCTION ' || v_sig || ' TO platform_app';
  END LOOP;
END;
$$;

-- Re-assert base-table lockdown for platform_app and PUBLIC across coherence, iam, iam_secret, and platform.
REVOKE ALL ON SCHEMA coherence, iam_secret, platform FROM PUBLIC, platform_app;
REVOKE ALL ON ALL TABLES IN SCHEMA coherence, iam, iam_secret, platform FROM PUBLIC, platform_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA coherence, iam, iam_secret, platform FROM PUBLIC, platform_app;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA coherence, iam_secret, platform FROM PUBLIC, platform_app;
REVOKE CREATE ON SCHEMA iam, app_views, app_cmd FROM PUBLIC, platform_app;
