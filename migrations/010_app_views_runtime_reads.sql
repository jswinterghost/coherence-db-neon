-- Migration 010: Complete app_views.* runtime read surface and check-run authorization gate (Release 1B).
-- Ensures src/web/handlers.mjs and src/readers/downstream-reader.mjs execute strictly as platform_app
-- via withRequestTx(pool, dbToken, fn), reading ONLY through app_views.* (security_barrier=true,
-- owned by NOBYPASSRLS platform_view_owner) and writing ONLY through app_cmd.* (SECURITY DEFINER,
-- owned by platform_writer), with ZERO base-table privileges for platform_app and ZERO SET LOCAL ROLE.
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

-- Re-assert base-table lockdown for platform_app and PUBLIC.
REVOKE ALL ON SCHEMA coherence FROM PUBLIC, platform_app;
REVOKE ALL ON ALL TABLES IN SCHEMA coherence FROM PUBLIC, platform_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA coherence FROM PUBLIC, platform_app;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA coherence FROM PUBLIC, platform_app;
REVOKE CREATE ON SCHEMA app_views, app_cmd FROM PUBLIC, platform_app;
