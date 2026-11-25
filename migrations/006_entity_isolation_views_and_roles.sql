-- Migration 006 (retired): pre-IAM coherence_views, coherence_*_ro roles, and GUC-based RLS
-- policies were retired in favor of Migrations 008-010 (platform_* roles, IAM FORCE RLS, and app_views.*).
REVOKE ALL ON SCHEMA coherence FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA coherence FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA coherence FROM PUBLIC;
