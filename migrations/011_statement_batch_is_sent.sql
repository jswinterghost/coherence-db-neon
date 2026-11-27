-- Migration 011: Expose is_sent on app_views.coherence_statement_batches so screen queries
-- can tag and filter official sent batches vs. unsent run emissions cleanly for every caller.
-- Appends is_sent after journal_seq via CREATE OR REPLACE VIEW, preserving security_barrier = true,
-- platform_view_owner ownership, InitPlan evaluation, and platform_app/platform_readonly SELECT-only grants.

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
  sb.journal_seq,
  gate.is_sent
FROM coherence.statement_batches sb
CROSS JOIN scopes s
CROSS JOIN LATERAL (
  SELECT COALESCE(
    sb.batch_kind IN ('historical_sent', 'method_correction')
    OR (sb.batch_kind = 'run_emission' AND sb.attempt_event_id = ANY(s.sent_emits)),
    false
  ) AS is_sent
) sent_gate
CROSS JOIN LATERAL (
  SELECT
    sent_gate.is_sent,
    (s.full_upline AND (s.full_unpub OR sent_gate.is_sent)) AS show_company_totals
) gate;

ALTER VIEW app_views.coherence_statement_batches OWNER TO platform_view_owner;
REVOKE ALL ON app_views.coherence_statement_batches FROM PUBLIC;
GRANT SELECT ON app_views.coherence_statement_batches TO platform_app, platform_readonly;

-- Single runId effective-batch helper over coherence.run_effective_statement_batches() for every
-- statement-authorized caller (Owner, Entity Manager, Accounting, Agency Manager, Compliance, and View-as)
-- within their own RLS-visible rows: returns 0 rows for callers lacking statement access, abandoned/trial
-- runs, unsent runs invisible to the caller, and zero-row unsent runs for sub-org unpublished readers.
CREATE OR REPLACE FUNCTION app_views.coherence_statement_run_batches(p_run_id UUID)
RETURNS TABLE (batch_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT eff.batch_id
  FROM coherence.run_materializations rm
  JOIN app_views._read_published_emit_attempts() pe
    ON pe.attempt_event_id = rm.attempt_event_id
  JOIN app_views.coherence_statement_batches own_sb
    ON own_sb.run_id = rm.run_id
   AND own_sb.batch_kind = 'run_emission'
  CROSS JOIN LATERAL coherence.run_effective_statement_batches(rm.run_id) eff
  WHERE rm.run_id = p_run_id
    AND (
      pe.is_sent
      OR (SELECT app_views._read_has_full_tenant_right('act:coherence.unpublished.read'))
      OR EXISTS (
        SELECT 1
        FROM app_views.coherence_entity_statement_lines vis
        WHERE vis.batch_id = own_sb.id
      )
    );
$$;

ALTER FUNCTION app_views.coherence_statement_run_batches(UUID) OWNER TO platform_view_owner;
REVOKE ALL ON FUNCTION app_views.coherence_statement_run_batches(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_views.coherence_statement_run_batches(UUID) TO platform_app, platform_readonly;
