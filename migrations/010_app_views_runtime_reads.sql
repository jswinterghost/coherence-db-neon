-- Migration 010: Complete app_views.* runtime read surface and check-run authorization gate (Release 1B).
-- Ensures src/web/handlers.mjs and src/readers/downstream-reader.mjs execute strictly as platform_app
-- via withRequestTx(pool, dbToken, fn), reading ONLY through app_views.* (security_barrier=true,
-- owned by NOBYPASSRLS platform_view_owner) and writing ONLY through app_cmd.* (SECURITY DEFINER,
-- owned by platform_writer), with ZERO base-table privileges for platform_app and ZERO SET LOCAL ROLE.
-- All functions pin SET search_path = pg_catalog and schema-qualify all references.

-- 1. IAM-scoped platform_view_owner FOR SELECT RLS policies on the remaining Coherence tables
--    required by runtime web handlers and downstream readers (every policy scoped against iam.database_context).
CREATE POLICY stored_files_iam_read ON coherence.stored_files
  FOR SELECT TO platform_view_owner
  USING (
    (
      store_kind = 'company_data'
      AND (
        (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
          = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.inputs.read')))::uuid[])
        OR (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
          = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.runs.read')))::uuid[])
        OR (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
          = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.outputs.read')))::uuid[])
        OR (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
          = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.decisions.read')))::uuid[])
        OR (
          (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.bob.read')))::uuid[])
          AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.ledger.read')))::uuid[])
          AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('col:coherence.upline_cash')))::uuid[])
        )
      )
    )
    OR (
      store_kind = 'nusear_code'
      AND (
        (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
          = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.decisions.read')))::uuid[])
        OR (
          (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.bob.read')))::uuid[])
          AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.ledger.read')))::uuid[])
          AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('col:coherence.upline_cash')))::uuid[])
        )
      )
    )
  );

CREATE POLICY input_changes_iam_read ON coherence.input_changes
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
      = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.inputs.read')))::uuid[])
  );

CREATE POLICY imported_files_iam_read ON coherence.imported_files
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
      = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.inputs.read')))::uuid[])
  );

CREATE POLICY engine_versions_iam_read ON coherence.engine_versions
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
      = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.runs.read')))::uuid[])
  );

CREATE POLICY approvals_files_iam_read ON coherence.approvals_files
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
      = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.decisions.read')))::uuid[])
    OR (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
      = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.runs.read')))::uuid[])
  );

CREATE POLICY approval_rows_iam_read ON coherence.approval_rows
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
      = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.decisions.read')))::uuid[])
  );

CREATE POLICY review_submissions_iam_read ON coherence.review_submissions
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
      = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.decisions.read')))::uuid[])
  );

CREATE POLICY review_drafts_iam_read ON coherence.review_drafts
  FOR SELECT TO platform_view_owner
  USING (
    (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
      = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.decisions.read')))::uuid[])
  );

CREATE POLICY artifacts_iam_read ON coherence.artifacts
  FOR SELECT TO platform_view_owner
  USING (
    (
      artifact_kind = 'data'
      AND store_kind = 'company_data'
      AND (
        (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
          = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.outputs.read')))::uuid[])
        OR (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
          = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.decisions.read')))::uuid[])
        OR (
          (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.bob.read')))::uuid[])
          AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.ledger.read')))::uuid[])
          AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('col:coherence.upline_cash')))::uuid[])
        )
      )
    )
    OR (
      rel_path IN ('bible.json', 'bible.html', 'adjust.json', 'adjust.html')
      AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.decisions.read')))::uuid[])
    )
    OR (
      rel_path LIKE 'emits/bundles/entity-managers/%/viewer.html'
      AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.bob.read')))::uuid[])
      AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.ledger.read')))::uuid[])
      AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('col:coherence.upline_cash')))::uuid[])
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
SELECT
  ic.input_version_id,
  ic.rel_path,
  ic.change_kind,
  ic.old_rel_path,
  ic.store_kind,
  ic.file_sha256,
  ic.prev_file_sha256,
  ic.journal_seq
FROM coherence.input_changes ic;

CREATE OR REPLACE VIEW app_views.coherence_input_entries
WITH (security_barrier = true) AS
SELECT
  ie.input_version_id,
  ie.rel_path,
  ie.mac_key,
  ie.store_kind,
  ie.file_sha256,
  sf.byte_size,
  sf.md5_b64,
  sf.crc32c_b64,
  ie.journal_seq
FROM coherence.input_entries ie
JOIN coherence.stored_files sf
  ON sf.store_kind = ie.store_kind
 AND sf.sha256 = ie.file_sha256
WHERE ie.store_kind = 'company_data'
  AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.inputs.read')))::uuid[]);

CREATE OR REPLACE VIEW app_views.coherence_staging_files
WITH (security_barrier = true) AS
SELECT
  f.id,
  f.rel_path,
  f.file_sha256,
  f.original_at,
  f.metadata,
  sf.byte_size,
  sf.md5_b64,
  sf.crc32c_b64,
  f.journal_seq
FROM coherence.imported_files f
JOIN coherence.stored_files sf
  ON sf.store_kind = f.store_kind
 AND sf.sha256 = f.file_sha256
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
  e.log_file_sha256,
  sf.byte_size AS log_byte_size,
  sf.md5_b64 AS log_md5_b64,
  sf.crc32c_b64 AS log_crc32c_b64,
  e.error_summary,
  e.artifact_count,
  e.artifacts_sha256,
  e.original_at,
  e.journal_seq
FROM coherence.step_attempt_events e
LEFT JOIN coherence.stored_files sf
  ON sf.store_kind = 'company_data'
 AND sf.sha256 = e.log_file_sha256
WHERE (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.runs.read')))::uuid[]);

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
SELECT
  rs.id,
  rs.run_id,
  rs.surface,
  rs.attempt_event_id,
  rs.approvals_file_sha256,
  rs.decision_commit_id,
  rs.imported,
  rs.original_at,
  rs.submission_id,
  rs.journal_seq,
  COALESCE(dc.cumulative_decision_count, af.row_count) AS row_count,
  COALESCE(dc.header_contract, af.header_kind) AS header_kind
FROM coherence.review_saves rs
LEFT JOIN coherence.approvals_files af ON af.file_sha256 = rs.approvals_file_sha256
LEFT JOIN coherence.decision_commits dc ON dc.id = rs.decision_commit_id;

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
SELECT
  c.id,
  c.run_id,
  c.statement_date,
  c.carry_kind,
  c.store_kind,
  c.file_sha256,
  c.carried_decision_commit_id,
  c.published_input_version_id,
  c.nothing_new,
  c.typed_phrase,
  c.journal_seq
FROM coherence.carries c
WHERE (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.runs.read')))::uuid[]);

CREATE OR REPLACE VIEW app_views.coherence_abandonments
WITH (security_barrier = true) AS
SELECT
  a.id,
  a.run_id,
  a.typed_phrase,
  a.reason,
  a.journal_seq
FROM coherence.abandonments a
WHERE (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.runs.read')))::uuid[]);

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
SELECT
  ar.approvals_file_sha256,
  ar.row_no,
  ar.record_id,
  ar.disposition,
  ar.agent,
  ar.agency,
  ar.policy,
  ar.book,
  ar.month,
  ar.status,
  ar.note,
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
LEFT JOIN coherence.review_saves rs ON rs.approvals_file_sha256 = ar.approvals_file_sha256;

CREATE OR REPLACE VIEW app_views.coherence_review_configs
WITH (security_barrier = true) AS
SELECT
  r.id AS run_id,
  pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date,
  e.step AS surface,
  e.id AS attempt_event_id,
  e.attempt_no,
  a.rel_path,
  a.store_kind,
  a.file_sha256,
  sf.byte_size,
  sf.md5_b64,
  sf.crc32c_b64
FROM coherence.runs r
JOIN LATERAL (
  SELECT DISTINCT ON (s.step)
    s.id, s.step, s.attempt_no
  FROM coherence.step_attempt_events s
  WHERE s.run_id = r.id
    AND s.step IN ('bible', 'adjust')
    AND s.event_kind = 'finished'
    AND NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events sup
      WHERE sup.run_id = s.run_id AND sup.step = s.step AND sup.attempt_no = s.attempt_no
        AND sup.event_kind = 'superseded'
    )
  ORDER BY s.step, s.attempt_no DESC
) e ON true
JOIN coherence.artifacts a
  ON a.attempt_event_id = e.id
 AND a.rel_path IN (e.step || '.json', e.step || '.html')
JOIN coherence.stored_files sf
  ON sf.store_kind = a.store_kind
 AND sf.sha256 = a.file_sha256
WHERE (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.decisions.read')))::uuid[]);

CREATE OR REPLACE VIEW app_views.coherence_run_outputs
WITH (security_barrier = true) AS
SELECT
  r.id AS run_id,
  e.id AS attempt_event_id,
  a.rel_path,
  a.artifact_kind,
  a.store_kind,
  a.file_sha256,
  sf.byte_size,
  sf.md5_b64,
  sf.crc32c_b64
FROM coherence.runs r
JOIN LATERAL (
  SELECT s.id
  FROM coherence.step_attempt_events s
  WHERE s.run_id = r.id
    AND s.step = 'emit'
    AND s.event_kind = 'finished'
    AND NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events sup
      WHERE sup.run_id = s.run_id AND sup.step = s.step AND sup.attempt_no = s.attempt_no
        AND sup.event_kind = 'superseded'
    )
  ORDER BY s.attempt_no DESC
  LIMIT 1
) e ON true
JOIN coherence.artifacts a
  ON a.attempt_event_id = e.id
 AND a.artifact_kind = 'data'
 AND a.store_kind = 'company_data'
JOIN coherence.stored_files sf
  ON sf.store_kind = 'company_data'
 AND sf.sha256 = a.file_sha256
WHERE (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.outputs.read')))::uuid[])
  AND (
    a.rel_path IN ('run.json', 'company_manifest.json')
    OR (
      r.origin IN ('app', 'company_import')
      AND (r.source_folder IS NULL OR r.source_folder NOT LIKE 'company-abandoned/%')
      AND NOT EXISTS (SELECT 1 FROM coherence.abandonments ab WHERE ab.run_id = r.id)
      AND (
        EXISTS (SELECT 1 FROM coherence.carries c WHERE c.run_id = r.id AND c.carry_kind = 'sent')
        OR (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
             = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.unpublished.read')))::uuid[])
      )
      AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('col:coherence.statement_cash')))::uuid[])
      AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('col:coherence.upline_cash')))::uuid[])
      AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.ledger.read')))::uuid[])
      AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.statements.read')))::uuid[])
      AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.upline.read')))::uuid[])
      AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
            = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.bob.read')))::uuid[])
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
  ev.id AS emit_attempt_event_id,
  ev.journal_seq AS emit_journal_seq,
  r.journal_seq,
  sent_info.is_sent AS sent,
  cm.default_emit_display,
  cm.display_name
FROM coherence.runs r
JOIN LATERAL (
  SELECT e.id, e.journal_seq
  FROM coherence.step_attempt_events e
  WHERE e.run_id = r.id
    AND e.step = 'emit'
    AND e.event_kind = 'finished'
    AND NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events sup
      WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no
        AND sup.event_kind = 'superseded'
    )
  ORDER BY e.attempt_no DESC
  LIMIT 1
) ev ON true
LEFT JOIN coherence.company_meta cm ON cm.singleton = true
CROSS JOIN LATERAL (
  SELECT EXISTS (
    SELECT 1 FROM coherence.carries c
    WHERE c.run_id = r.id AND c.carry_kind = 'sent'
  ) AS is_sent
) sent_info
WHERE r.origin IN ('app', 'company_import')
  AND (r.source_folder IS NULL OR r.source_folder NOT LIKE 'company-abandoned/%')
  AND NOT EXISTS (SELECT 1 FROM coherence.abandonments a WHERE a.run_id = r.id)
  AND pg_catalog.cardinality(
    ((SELECT iam.effective_any_org_ids('act:coherence.bob.read')))::uuid[]
    || ((SELECT iam.effective_any_org_ids('act:coherence.statements.read')))::uuid[]
    || ((SELECT iam.effective_any_org_ids('act:coherence.upline.read')))::uuid[]
    || ((SELECT iam.effective_any_org_ids('act:coherence.ledger.read')))::uuid[]
    || ((SELECT iam.effective_any_org_ids('act:coherence.runs.read')))::uuid[]
  ) > 0
  AND (
    sent_info.is_sent
    OR pg_catalog.cardinality(
      ((SELECT iam.effective_any_org_ids('act:coherence.unpublished.read')))::uuid[]
    ) > 0
  );

CREATE OR REPLACE VIEW app_views.coherence_entity_bundle_artifacts
WITH (security_barrier = true) AS
SELECT
  r.id AS run_id,
  ev.id AS attempt_event_id,
  a.rel_path,
  a.artifact_kind,
  a.store_kind,
  a.file_sha256,
  sf.byte_size,
  sf.md5_b64,
  sf.crc32c_b64,
  (a.rel_path LIKE 'emits/bundles/entity-managers/%/viewer.html') AS is_viewer_config
FROM coherence.runs r
JOIN LATERAL (
  SELECT e.id
  FROM coherence.step_attempt_events e
  WHERE e.run_id = r.id
    AND e.step = 'emit'
    AND e.event_kind = 'finished'
    AND NOT EXISTS (
      SELECT 1 FROM coherence.step_attempt_events sup
      WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no
        AND sup.event_kind = 'superseded'
    )
  ORDER BY e.attempt_no DESC
  LIMIT 1
) ev ON true
JOIN coherence.artifacts a
  ON a.attempt_event_id = ev.id
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
WHERE r.origin IN ('app', 'company_import')
  AND (r.source_folder IS NULL OR r.source_folder NOT LIKE 'company-abandoned/%')
  AND NOT EXISTS (SELECT 1 FROM coherence.abandonments ab WHERE ab.run_id = r.id)
  AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.bob.read')))::uuid[])
  AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.ledger.read')))::uuid[])
  AND (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
        = ANY(((SELECT iam.effective_wide_org_ids('col:coherence.upline_cash')))::uuid[])
  AND (
    EXISTS (SELECT 1 FROM coherence.carries c WHERE c.run_id = r.id AND c.carry_kind = 'sent')
    OR (SELECT dc.tenant_org_id FROM iam.database_context dc WHERE dc.singleton = true)
         = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.unpublished.read')))::uuid[])
  );

CREATE OR REPLACE VIEW app_views.coherence_review_drift_gate
WITH (security_barrier = true) AS
SELECT
  dc.company_slug,
  true AS authorized
FROM iam.database_context dc
WHERE dc.singleton = true
  AND dc.tenant_org_id = ANY(((SELECT iam.effective_wide_org_ids('act:coherence.journal.read')))::uuid[]);

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
    'coherence_review_drift_gate'
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

-- Re-assert base-table and legacy-schema lockdown for platform_app and PUBLIC.
REVOKE ALL ON SCHEMA coherence, coherence_views FROM PUBLIC, platform_app;
REVOKE ALL ON ALL TABLES IN SCHEMA coherence, coherence_views FROM PUBLIC, platform_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA coherence, coherence_views FROM PUBLIC, platform_app;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA coherence, coherence_views FROM PUBLIC, platform_app;
REVOKE CREATE ON SCHEMA app_views, app_cmd FROM PUBLIC, platform_app;
