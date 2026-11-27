-- Migration 012: Transfer ownership of coherence.run_effective_statement_batches(UUID)
-- and coherence.run_states to platform_readonly so both objects execute under an RLS-admitted
-- read-only role when migrations run as a non-superuser migrator (such as Cloud SQL
-- cloudsqlsuperuser under FORCE ROW LEVEL SECURITY).

ALTER FUNCTION coherence.run_effective_statement_batches(UUID) OWNER TO platform_readonly;
REVOKE ALL ON FUNCTION coherence.run_effective_statement_batches(UUID) FROM PUBLIC, platform_app;
GRANT EXECUTE ON FUNCTION coherence.run_effective_statement_batches(UUID)
  TO platform_readonly, platform_writer, platform_worker, platform_view_owner;

ALTER VIEW coherence.run_states OWNER TO platform_readonly;
REVOKE ALL ON coherence.run_states FROM PUBLIC, platform_app;
GRANT SELECT ON coherence.run_states TO platform_readonly, platform_writer, platform_worker;
