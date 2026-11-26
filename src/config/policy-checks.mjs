import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const DEFAULT_CLOUDSQL_CONFIG_PATH = resolve(REPO_ROOT, 'config', 'cloudsql-instance.json');

export const ALL_BUSINESS_TABLES = Object.freeze([
  'journal_entries',
  'company_meta',
  'stored_files',
  'engine_versions',
  'input_versions',
  'input_entries',
  'input_changes',
  'approvals_files',
  'approval_rows',
  'decision_commits',
  'decisions',
  'generated_overlays',
  'review_queue_items',
  'runs',
  'step_requests',
  'cancel_requests',
  'step_attempt_events',
  'artifacts',
  'review_saves',
  'emit_confirmations',
  'statement_batches',
  'statement_agency_lines',
  'statement_upline_lines',
  'run_materializations',
  'bob_policies',
  'bob_policy_financials',
  'coherent_ledger_rows',
  'carries',
  'abandonments',
  'imported_files',
  'checks',
]);

export const RETIRED_COHERENCE_ROLES = Object.freeze([
  'coherence_app',
  'coherence_worker',
  'coherence_readonly',
  'coherence_entity_manager_ro',
  'coherence_agency_manager_ro',
  'coherence_agent_ro',
  'coherence_retention_ro',
  'coherence_investor_ro',
]);

export const RLS_PROTECTED_TABLES = Object.freeze([
  'bob_policies',
  'bob_policy_financials',
  'statement_agency_lines',
  'statement_upline_lines',
  'coherent_ledger_rows',
]);

export const IAM_IMMUTABLE_TABLES = Object.freeze([
  'database_context',
  'tools',
  'organizations',
  'people',
  'rights',
  'right_retirements',
  'roles',
]);

export const IAM_VERSIONED_TABLES = Object.freeze([
  'organization_versions',
  'organization_edges',
  'person_versions',
  'organization_memberships',
  'agent_affiliations',
  'role_versions',
  'role_rights',
  'role_grants',
  'organization_tool_switches',
]);

export const PLATFORM_APP_FUNCTION_WHITELIST = Object.freeze([
  'iam.business_today(timestamp with time zone)',
  'iam.session_context()',
  'iam.is_viewing_as()',
  'iam.has_right(text, date)',
  'iam.effective_wide_org_ids(text, date)',
  'iam.effective_any_org_ids(text, date)',
  'iam.effective_narrow_pairs(text, date)',
  'iam.effective_narrow_person_ids(text, date)',
  'iam.assert_can_write(text, uuid, uuid, date)',
  'app_views.coherence_effective_statement_batches(uuid)',
  'app_views.coherence_run_stage(uuid, bigint)',
  'app_views.coherence_run_stages()',
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
  'app_views._read_published_emit_attempt_ids(boolean)',
]);

export const PLATFORM_APP_CMD_WHITELIST = Object.freeze([
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
  'app_cmd.coherence_import_historical_run(text, text, jsonb)',
  'app_cmd.coherence_register_stored_files(text, text, jsonb)',
  'app_cmd.coherence_record_check(text, text, text, boolean, jsonb, uuid, uuid, uuid)',
  'app_cmd.coherence_record_generated_overlay(text, text, uuid, uuid, text, text, integer, jsonb, uuid, uuid)',
  'app_cmd.coherence_materialize_emit(text, text, jsonb)',
  'app_cmd.coherence_authorize_check_run()',
]);

export const APP_CMD_WORKER_OR_OWNER_FUNCTIONS = Object.freeze([
  'app_cmd.coherence_register_stored_files(text, text, jsonb)',
  'app_cmd.coherence_record_check(text, text, text, boolean, jsonb, uuid, uuid, uuid)',
  'app_cmd.coherence_record_generated_overlay(text, text, uuid, uuid, text, text, integer, jsonb, uuid, uuid)',
  'app_cmd.coherence_materialize_emit(text, text, jsonb)',
  'app_cmd.coherence_authorize_check_run()',
]);

export const APP_CMD_WORKER_ONLY_FUNCTIONS = Object.freeze([
  'app_cmd.coherence_start_attempt(text, text, uuid, text, uuid, uuid)',
  'app_cmd.coherence_finish_attempt(text, text, jsonb)',
  'app_cmd.coherence_fail_attempt(text, text, uuid, text, integer, text, jsonb, jsonb, uuid)',
  'app_cmd.coherence_cancel_attempt(text, text, uuid, text, integer, uuid, jsonb, jsonb, uuid)',
  'app_cmd.coherence_interrupt_attempt(text, text, uuid, text, integer, text, uuid)',
  'app_cmd.coherence_accept_review_submission(text, text, jsonb)',
  'app_cmd.coherence_reject_review_submission(uuid, text, text)',
  'app_cmd.coherence_expire_old_drafts()',
]);

export const PLATFORM_WORKER_CMD_WHITELIST = Object.freeze([
  ...APP_CMD_WORKER_OR_OWNER_FUNCTIONS,
  ...APP_CMD_WORKER_ONLY_FUNCTIONS,
]);

export const BACKFILL_ALLOWED_ROLES = Object.freeze([
  'platform_versioner',
  'platform_migrator',
]);

export const APP_VIEWS_EXPECTED = Object.freeze([
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
  'coherence_journal_gate',
  'coherence_decision_commits',
  'coherence_decisions',
  'coherence_checks',
  'coherence_journal',
  'audit_journal',
]);

export const COHERENCE_IAM_FK_TABLES = Object.freeze([
  'bob_policies',
  'bob_policy_financials',
  'statement_agency_lines',
  'statement_upline_lines',
  'coherent_ledger_rows',
]);

export const PLATFORM_ROLES = Object.freeze([
  'platform_view_owner',
  'platform_writer',
  'platform_versioner',
  'platform_app',
  'platform_worker',
  'platform_iam_sync',
  'platform_readonly',
  'platform_migrator',
]);

export const CLOUDSQL_BOOTSTRAP_CREATOR_ROLES = Object.freeze([
  'cloudsqlsuperuser',
]);

export const CLOUDSQL_IAM_MEMBER_MARKER_ROLES = Object.freeze([
  'cloudsqliamserviceaccount',
]);

const FORBIDDEN_BUSINESS_PRIVS = Object.freeze(['UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']);
const ALL_RELATION_PRIVS = Object.freeze(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN']);
const ALL_COLUMN_PRIVS = Object.freeze(['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']);
const MANAGED_SCHEMAS = Object.freeze(['platform', 'iam_secret', 'iam', 'coherence', 'app_views', 'app_cmd']);

function hasExactPrivileges(value, expected) {
  if (!Array.isArray(value) || value.length !== expected.length) return false;
  const set = new Set(value);
  return set.size === expected.length && expected.every((item) => set.has(item));
}

export function parsePgHbaConf(text) {
  const rules = [];
  const lines = String(text || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const noComment = raw.replace(/#.*$/, '').trim();
    if (!noComment) continue;
    const tokens = noComment.split(/\s+/);
    const type = tokens[0];
    if (type === 'include' || type === 'include_if_exists' || type === 'include_dir') {
      rules.push({ lineNo: i + 1, type, includeTarget: tokens[1] || '', raw: noComment });
      continue;
    }
    if (type === 'local') {
      rules.push({
        lineNo: i + 1,
        type,
        database: tokens[1],
        user: tokens[2],
        address: null,
        method: tokens[3],
        options: tokens.slice(4),
        raw: noComment,
      });
    } else {
      // host / hostssl / hostnossl / hostgssenc / hostnogssenc
      // Address can be CIDR (1 token) or IP + netmask (2 tokens if tokens[4] looks like a netmask)
      const isSeparateNetmask = tokens[4] && /^\d+\.\d+\.\d+\.\d+$/.test(tokens[4]);
      const methodIdx = isSeparateNetmask ? 5 : 4;
      rules.push({
        lineNo: i + 1,
        type,
        database: tokens[1],
        user: tokens[2],
        address: isSeparateNetmask ? `${tokens[3]} ${tokens[4]}` : tokens[3],
        method: tokens[methodIdx],
        options: tokens.slice(methodIdx + 1),
        raw: noComment,
      });
    }
  }
  return rules;
}

export async function verifyPgHbaFile(pathOrOptions = {}) {
  let filePath = null;
  if (typeof pathOrOptions === 'string' && pathOrOptions.length > 0) {
    filePath = pathOrOptions;
  } else if (pathOrOptions && typeof pathOrOptions === 'object') {
    if (pathOrOptions.filePath) {
      filePath = pathOrOptions.filePath;
    } else if (pathOrOptions.pool) {
      const res = await pathOrOptions.pool.query('SHOW hba_file');
      filePath = res.rows[0]?.hba_file || null;
    }
  }
  if (!filePath && process.env.COHERENCE_PG_HBA_PATH) {
    filePath = process.env.COHERENCE_PG_HBA_PATH;
  }
  if (!filePath) {
    throw new Error('verifyPgHbaFile requires an explicit filePath, a PostgreSQL pool (for SHOW hba_file), or COHERENCE_PG_HBA_PATH.');
  }

  const text = await readFile(filePath, 'utf8');
  const rules = parsePgHbaConf(text);
  const problems = [];
  if (rules.length === 0) {
    problems.push(`No active authentication rules found in ${filePath}`);
  }
  for (const r of rules) {
    if (r.type.startsWith('include')) continue;
    if (r.method === 'trust') {
      problems.push(`Line ${r.lineNo}: forbidden 'trust' authentication rule (${r.raw})`);
    }
    if (r.method === 'password' || r.method === 'md5') {
      problems.push(`Line ${r.lineNo}: weak authentication method '${r.method}' (${r.raw})`);
    }
    if (r.type === 'local' && !['peer', 'scram-sha-256', 'cert', 'reject'].includes(r.method)) {
      problems.push(`Line ${r.lineNo}: unexpected local auth method '${r.method}'`);
    }
    if (r.type.startsWith('host') && !['scram-sha-256', 'cert', 'reject'].includes(r.method)) {
      problems.push(`Line ${r.lineNo}: TCP host rule must use scram-sha-256, cert, or reject (got '${r.method}')`);
    }
  }
  return { passed: problems.length === 0, filePath, ruleCount: rules.length, rules, problems };
}

export function validateCloudSqlConfig(config) {
  const problems = [];
  if (!config || typeof config !== 'object') {
    return { passed: false, problems: ['Cloud SQL config must be a JSON object.'] };
  }
  if (config.databaseVersion !== 'POSTGRES_17') {
    problems.push(`databaseVersion must be POSTGRES_17, got ${config.databaseVersion}`);
  }
  const ip = config.ipConfiguration || {};
  if (ip.requireSsl !== true) {
    problems.push('ipConfiguration.requireSsl must be true (TLS required)');
  }
  if (ip.sslMode !== 'ENCRYPTED_ONLY') {
    problems.push(`ipConfiguration.sslMode must be ENCRYPTED_ONLY, got ${ip.sslMode}`);
  }
  if (!Array.isArray(ip.authorizedNetworks) || ip.authorizedNetworks.length !== 0) {
    problems.push('ipConfiguration.authorizedNetworks must be empty (no direct authorized networks)');
  }
  if (ip.ipv4Enabled !== false) {
    problems.push('ipConfiguration.ipv4Enabled must be false (no direct public TCP connections)');
  }

  const proto = config.connectionProtocol || {};
  if (proto.connector !== 'cloud-sql-connector') {
    problems.push(`connectionProtocol.connector must be cloud-sql-connector, got ${proto.connector}`);
  }
  if (proto.dedicatedServiceAccount !== true) {
    problems.push('connectionProtocol.dedicatedServiceAccount must be true');
  }
  if (proto.passwordAuthAllowed !== false) {
    problems.push('connectionProtocol.passwordAuthAllowed must be false (IAM authentication only)');
  }

  const flags = config.databaseFlags || {};
  if (flags['cloudsql.iam_authentication'] !== 'on') {
    problems.push('databaseFlags["cloudsql.iam_authentication"] must be "on"');
  }
  if (flags['cloudsql.enable_pgaudit'] !== 'on') {
    problems.push('databaseFlags["cloudsql.enable_pgaudit"] must be "on"');
  }
  if (flags['pgaudit.log_parameter'] !== 'off') {
    problems.push('databaseFlags["pgaudit.log_parameter"] must be "off" so SQL parameter values are never logged');
  }
  if (flags['log_connections'] !== 'on') {
    problems.push('databaseFlags["log_connections"] must be "on"');
  }
  if (flags['log_disconnections'] !== 'on') {
    problems.push('databaseFlags["log_disconnections"] must be "on"');
  }
  if (flags['log_parameter_max_length'] !== '0') {
    problems.push('databaseFlags["log_parameter_max_length"] must be "0" so bind values never appear in logs');
  }
  if (flags['log_parameter_max_length_on_error'] !== '0') {
    problems.push('databaseFlags["log_parameter_max_length_on_error"] must be "0" so bind values never appear in error logs');
  }
  if (flags['log_statement'] && flags['log_statement'] !== 'none') {
    problems.push('databaseFlags["log_statement"] should be "none" (use pgaudit with log_parameter=off instead)');
  }

  const roles = config.roles && typeof config.roles === 'object' ? config.roles : {};
  for (const retiredRole of RETIRED_COHERENCE_ROLES) {
    if (Object.prototype.hasOwnProperty.call(roles, retiredRole)) {
      problems.push(`roles.${retiredRole} is a retired pre-IAM role and must not be declared`);
    }
  }
  for (const roleName of PLATFORM_ROLES) {
    if (!roles[roleName] || typeof roles[roleName] !== 'object') {
      problems.push(`roles.${roleName} must be declared`);
    }
  }
  if (!hasExactPrivileges(roles.platform_app?.businessTables, [])) {
    problems.push('roles.platform_app.businessTables must be strictly [] (zero base-table access)');
  }
  if (!hasExactPrivileges(roles.platform_app?.appViews, ['SELECT'])) {
    problems.push('roles.platform_app.appViews must be strictly ["SELECT"]');
  }
  if (!hasExactPrivileges(roles.platform_app?.appCmd, ['EXECUTE'])) {
    problems.push('roles.platform_app.appCmd must be strictly ["EXECUTE"]');
  }
  if (!hasExactPrivileges(roles.platform_worker?.businessTables, ['SELECT'])) {
    problems.push('roles.platform_worker.businessTables must be strictly ["SELECT"]');
  }
  if (!hasExactPrivileges(roles.platform_worker?.appCmd, ['EXECUTE'])) {
    problems.push('roles.platform_worker.appCmd must be strictly ["EXECUTE"]');
  }
  if (!hasExactPrivileges(roles.platform_writer?.businessTables, ['SELECT', 'INSERT'])) {
    problems.push('roles.platform_writer.businessTables must be strictly ["SELECT", "INSERT"]');
  }
  if (!hasExactPrivileges(roles.platform_readonly?.businessTables, ['SELECT'])) {
    problems.push('roles.platform_readonly.businessTables must be strictly ["SELECT"]');
  }

  return { passed: problems.length === 0, problems };
}

export async function verifyCloudSqlConfigFile(filePath = DEFAULT_CLOUDSQL_CONFIG_PATH) {
  const raw = await readFile(filePath, 'utf8');
  const parsed = JSON.parse(raw);
  return { filePath, ...validateCloudSqlConfig(parsed), config: parsed };
}

export async function verifyDatabaseConfigInvariants(pool) {
  return verifyIamConfigInvariants(pool);
}

export async function verifyIamConfigInvariants(pool) {
  const problems = [];

  // 1. All platform_* roles must exist and be non-superuser, NOINHERIT, NOBYPASSRLS.
  const rolesRes = await pool.query(
    `SELECT rolname, rolsuper, rolinherit, rolbypassrls, rolconfig
     FROM pg_catalog.pg_roles
     WHERE rolname = ANY($1::text[])`,
    [[...PLATFORM_ROLES, ...RETIRED_COHERENCE_ROLES]],
  );
  const roleByName = new Map(rolesRes.rows.map((r) => [r.rolname, r]));
  const existingRetiredRoles = RETIRED_COHERENCE_ROLES.filter((r) => roleByName.has(r));

  for (const roleName of PLATFORM_ROLES) {
    const r = roleByName.get(roleName);
    if (!r) {
      problems.push(`Missing platform role ${roleName}`);
      continue;
    }
    if (r.rolsuper) problems.push(`Role ${roleName} must not be SUPERUSER`);
    if (r.rolbypassrls) problems.push(`Role ${roleName} must have NOBYPASSRLS`);
    if (r.rolinherit) problems.push(`Role ${roleName} must have NOINHERIT`);
    if (roleName === 'platform_app') {
      const cfg = Array.isArray(r.rolconfig) ? r.rolconfig : [];
      if (!cfg.includes('app.session_token=')) {
        problems.push(`Role platform_app should default app.session_token='' (rolconfig: ${JSON.stringify(cfg)})`);
      }
    }
  }

  // 1b. Audit pg_auth_members: no platform_* role may hold membership in another role (except Cloud SQL's
  //     cloudsqliamserviceaccount login marker without ADMIN OPTION), and no non-superuser may hold ANY
  //     membership (including WITH ADMIN OPTION even when INHERIT and SET are false) in any platform_* role
  //     except Cloud SQL's cloudsqlsuperuser bootstrap CREATEROLE record (INHERIT false, SET false).
  const platformRoleSet = new Set(PLATFORM_ROLES);
  const bootstrapCreatorSet = new Set(CLOUDSQL_BOOTSTRAP_CREATOR_ROLES);
  const iamMarkerSet = new Set(CLOUDSQL_IAM_MEMBER_MARKER_ROLES);
  const authMemRes = await pool.query(
    `SELECT r.rolname AS granted_role,
            r.rolsuper AS granted_is_super,
            r.rolbypassrls AS granted_bypassrls,
            r.rolcreaterole AS granted_createrole,
            m.rolname AS member_role,
            m.rolsuper AS member_is_super,
            m.rolcreaterole AS member_createrole,
            am.admin_option,
            am.inherit_option,
            am.set_option
     FROM pg_catalog.pg_auth_members am
     JOIN pg_catalog.pg_roles r ON r.oid = am.roleid
     JOIN pg_catalog.pg_roles m ON m.oid = am.member
     WHERE r.rolname = ANY($1::text[]) OR m.rolname = ANY($1::text[])
     ORDER BY r.rolname, m.rolname`,
    [PLATFORM_ROLES],
  );
  for (const row of authMemRes.rows) {
    if (platformRoleSet.has(row.member_role)) {
      const allowedCloudSqlIamMarker = iamMarkerSet.has(row.granted_role)
        && !row.admin_option
        && !row.granted_is_super
        && !row.granted_bypassrls
        && !row.granted_createrole;
      if (!allowedCloudSqlIamMarker) {
        problems.push(
          `pg_auth_members violation: platform role ${row.member_role} must not be a member of ${row.granted_role} (admin=${row.admin_option}, inherit=${row.inherit_option}, set=${row.set_option})`,
        );
      }
    } else if (platformRoleSet.has(row.granted_role) && !row.member_is_super) {
      const allowedCloudSqlBootstrap = bootstrapCreatorSet.has(row.member_role)
        && row.member_createrole
        && !row.inherit_option
        && !row.set_option;
      if (!allowedCloudSqlBootstrap) {
        problems.push(
          `pg_auth_members violation: non-superuser ${row.member_role} holds membership in ${row.granted_role} (admin=${row.admin_option}, inherit=${row.inherit_option}, set=${row.set_option})`,
        );
      }
    }
  }

  // 2. Retired schema coherence_views must not exist; PUBLIC and retired roles hold zero privileges
  //    on all managed schemas; platform_app holds USAGE strictly on iam, app_views, app_cmd and zero CREATE.
  const retiredSchemaRes = await pool.query(
    "SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname = 'coherence_views'",
  );
  if (retiredSchemaRes.rows.length > 0) {
    problems.push('Retired schema coherence_views must not exist');
  }

  const schemaPrincipals = ['public', 'platform_app', ...existingRetiredRoles];
  const schemaPrivRes = await pool.query(
    `SELECT p.principal,
            s.schema_name,
            pg_catalog.has_schema_privilege(p.principal, s.schema_name, 'USAGE') AS has_usage,
            pg_catalog.has_schema_privilege(p.principal, s.schema_name, 'CREATE') AS has_create
     FROM pg_catalog.unnest($1::text[]) AS p(principal)
     CROSS JOIN pg_catalog.unnest($2::text[]) AS s(schema_name)`,
    [schemaPrincipals, MANAGED_SCHEMAS],
  );
  const allowedAppUsageSchemas = new Set(['iam', 'app_views', 'app_cmd']);
  for (const row of schemaPrivRes.rows) {
    if (row.principal === 'public') {
      if (row.has_usage || row.has_create) {
        problems.push(`PUBLIC must have zero privileges on schema ${row.schema_name}`);
      }
    } else if (row.principal === 'platform_app') {
      if (!allowedAppUsageSchemas.has(row.schema_name) && row.has_usage) {
        problems.push(`platform_app must not hold USAGE on schema ${row.schema_name}`);
      }
      if (row.has_create) {
        problems.push(`platform_app must not hold CREATE on schema ${row.schema_name}`);
      }
    } else if (row.has_usage || row.has_create) {
      problems.push(`Retired role ${row.principal} must have zero privileges on schema ${row.schema_name}`);
    }
  }

  // 3. Base-table lockdown (batched):
  //    - platform_app, PUBLIC, and any existing retired roles hold ZERO relation/column privileges on all base tables.
  //    - platform_worker holds SELECT on all 31 business tables, ZERO write privileges across coherence.* and platform.audit_journal,
  //      and ZERO privileges on coherence.schema_migrations.
  //    - platform_writer holds strictly SELECT and INSERT on all 31 business tables (no UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER/MAINTAIN)
  //      and ZERO DELETE/TRUNCATE on coherence.review_submissions.
  //    - platform_readonly holds strictly SELECT on all 31 business tables.
  const tblRes = await pool.query(
    `SELECT n.nspname AS table_schema,
            c.relname AS table_name,
            c.oid AS table_oid
     FROM pg_catalog.pg_class c
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('coherence', 'iam', 'iam_secret', 'platform')
       AND c.relkind IN ('r', 'p')
     ORDER BY n.nspname, c.relname`,
  );
  const cohBaseTbls = tblRes.rows.filter((r) => r.table_schema === 'coherence');
  const cohTblSet = new Set(cohBaseTbls.map((r) => r.table_name));
  const businessTblSet = new Set(ALL_BUSINESS_TABLES);
  for (const tbl of [...ALL_BUSINESS_TABLES, 'review_submissions', 'review_drafts']) {
    if (!cohTblSet.has(tbl)) {
      problems.push(`Expected coherence base table coherence.${tbl} is missing`);
    }
  }

  const baseTblOids = tblRes.rows.map((r) => r.table_oid);
  const tblInfoByOid = new Map(tblRes.rows.map((r) => [Number(r.table_oid), r]));
  const lockedPrincipals = ['platform_app', 'public', ...existingRetiredRoles];
  const baseRelPrincipals = [...lockedPrincipals, 'platform_worker', 'platform_writer', 'platform_readonly'];

  const [baseRelPrivRes, baseColPrivRes, pvSelRes] = await Promise.all([
    pool.query(
      `SELECT t.table_oid, p.principal, pr.priv
       FROM pg_catalog.unnest($1::oid[]) AS t(table_oid)
       CROSS JOIN pg_catalog.unnest($2::text[]) AS p(principal)
       CROSS JOIN pg_catalog.unnest($3::text[]) AS pr(priv)
       WHERE pg_catalog.has_table_privilege(p.principal, t.table_oid, pr.priv)`,
      [baseTblOids, baseRelPrincipals, ALL_RELATION_PRIVS],
    ),
    pool.query(
      `SELECT t.table_oid, p.principal, pr.priv
       FROM pg_catalog.unnest($1::oid[]) AS t(table_oid)
       CROSS JOIN pg_catalog.unnest($2::text[]) AS p(principal)
       CROSS JOIN pg_catalog.unnest($3::text[]) AS pr(priv)
       WHERE pg_catalog.has_any_column_privilege(p.principal, t.table_oid, pr.priv)`,
      [baseTblOids, [...lockedPrincipals, 'platform_worker'], ALL_COLUMN_PRIVS],
    ),
    pool.query(
      `SELECT t.table_oid
       FROM pg_catalog.unnest($1::oid[]) AS t(table_oid)
       WHERE pg_catalog.has_table_privilege('platform_view_owner', t.table_oid, 'SELECT')`,
      [cohBaseTbls.map((r) => r.table_oid)],
    ),
  ]);

  const lockedPrincipalSet = new Set(lockedPrincipals);
  const workerForbiddenPrivs = new Set(['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN']);
  const writerForbiddenBizPrivs = new Set(['UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN']);
  const roForbiddenBizPrivs = new Set(['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN']);

  const roleTablePrivs = new Map();
  for (const row of baseRelPrivRes.rows) {
    const tbl = tblInfoByOid.get(Number(row.table_oid));
    const fq = `${tbl.table_schema}.${tbl.table_name}`;
    const key = `${row.principal}:${fq}`;
    let pset = roleTablePrivs.get(key);
    if (!pset) {
      pset = new Set();
      roleTablePrivs.set(key, pset);
    }
    pset.add(row.priv);

    if (lockedPrincipalSet.has(row.principal)) {
      problems.push(`${row.principal} must not hold ${row.priv} on base table ${fq}`);
    } else if (row.principal === 'platform_worker') {
      if (tbl.table_schema === 'coherence') {
        if (tbl.table_name === 'schema_migrations' || workerForbiddenPrivs.has(row.priv)) {
          problems.push(`platform_worker must not hold ${row.priv} on base table ${fq}`);
        }
      } else if (fq === 'platform.audit_journal' && workerForbiddenPrivs.has(row.priv)) {
        problems.push(`platform_worker must not hold ${row.priv} on platform.audit_journal`);
      }
    } else if (row.principal === 'platform_writer' && tbl.table_schema === 'coherence') {
      if (businessTblSet.has(tbl.table_name) && writerForbiddenBizPrivs.has(row.priv)) {
        problems.push(`platform_writer has forbidden privilege ${row.priv} on ${fq}`);
      } else if (tbl.table_name === 'review_submissions' && ['DELETE', 'TRUNCATE'].includes(row.priv)) {
        problems.push(`platform_writer must not have ${row.priv} on coherence.review_submissions`);
      }
    } else if (row.principal === 'platform_readonly' && tbl.table_schema === 'coherence') {
      if (businessTblSet.has(tbl.table_name) && roForbiddenBizPrivs.has(row.priv)) {
        problems.push(`platform_readonly has forbidden privilege ${row.priv} on ${fq}`);
      }
    }
  }

  for (const tbl of ALL_BUSINESS_TABLES) {
    const fq = `coherence.${tbl}`;
    const writerSet = roleTablePrivs.get(`platform_writer:${fq}`);
    if (!writerSet?.has('SELECT') || !writerSet?.has('INSERT')) {
      problems.push(`platform_writer missing SELECT or INSERT on ${fq}`);
    }
    if (!roleTablePrivs.get(`platform_readonly:${fq}`)?.has('SELECT')) {
      problems.push(`platform_readonly missing SELECT on ${fq}`);
    }
    if (!roleTablePrivs.get(`platform_worker:${fq}`)?.has('SELECT')) {
      problems.push(`platform_worker missing SELECT on ${fq}`);
    }
  }

  for (const row of baseColPrivRes.rows) {
    const tbl = tblInfoByOid.get(Number(row.table_oid));
    const fq = `${tbl.table_schema}.${tbl.table_name}`;
    if (lockedPrincipalSet.has(row.principal)) {
      problems.push(`${row.principal} must not hold column-level ${row.priv} on base table ${fq}`);
    } else if (row.principal === 'platform_worker' && tbl.table_schema === 'coherence') {
      if (tbl.table_name === 'schema_migrations' || ['INSERT', 'UPDATE', 'REFERENCES'].includes(row.priv)) {
        problems.push(`platform_worker must not hold column-level ${row.priv} on base table ${fq}`);
      }
    }
  }

  // 4. Views lockdown (batched): ZERO privileges for platform_app, PUBLIC, and retired roles on
  //    every view in coherence, iam, iam_secret, platform.
  const viewRes = await pool.query(
    `SELECT n.nspname AS schema_name,
            c.relname AS view_name,
            c.oid AS view_oid
     FROM pg_catalog.pg_class c
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('coherence', 'iam', 'iam_secret', 'platform')
       AND c.relkind IN ('v', 'm')
     ORDER BY n.nspname, c.relname`,
  );
  if (viewRes.rows.length === 0) {
    problems.push('No views found in schemas coherence / iam / iam_secret / platform');
  }
  const viewOids = viewRes.rows.map((r) => r.view_oid);
  const viewInfoByOid = new Map(viewRes.rows.map((r) => [Number(r.view_oid), r]));
  const [viewRelPrivRes, viewColPrivRes] = await Promise.all([
    pool.query(
      `SELECT v.view_oid, p.principal, pr.priv
       FROM pg_catalog.unnest($1::oid[]) AS v(view_oid)
       CROSS JOIN pg_catalog.unnest($2::text[]) AS p(principal)
       CROSS JOIN pg_catalog.unnest($3::text[]) AS pr(priv)
       WHERE pg_catalog.has_table_privilege(p.principal, v.view_oid, pr.priv)`,
      [viewOids, lockedPrincipals, ALL_RELATION_PRIVS],
    ),
    pool.query(
      `SELECT v.view_oid, p.principal, pr.priv
       FROM pg_catalog.unnest($1::oid[]) AS v(view_oid)
       CROSS JOIN pg_catalog.unnest($2::text[]) AS p(principal)
       CROSS JOIN pg_catalog.unnest($3::text[]) AS pr(priv)
       WHERE pg_catalog.has_any_column_privilege(p.principal, v.view_oid, pr.priv)`,
      [viewOids, lockedPrincipals, ALL_COLUMN_PRIVS],
    ),
  ]);
  for (const row of viewRelPrivRes.rows) {
    const v = viewInfoByOid.get(Number(row.view_oid));
    problems.push(`${row.principal} must not hold ${row.priv} on view ${v.schema_name}.${v.view_name}`);
  }
  for (const row of viewColPrivRes.rows) {
    const v = viewInfoByOid.get(Number(row.view_oid));
    problems.push(`${row.principal} must not hold column-level ${row.priv} on view ${v.schema_name}.${v.view_name}`);
  }

  // 4b. Audit app_views and app_cmd schemas: zero copied base tables, 100% security_barrier + platform_view_owner.
  const badRelRes = await pool.query(
    `SELECT n.nspname AS schema_name, c.relname AS rel_name, c.relkind
     FROM pg_catalog.pg_class c
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE (n.nspname = 'app_views' AND c.relkind IN ('r', 'p', 'm'))
        OR (n.nspname = 'app_cmd' AND c.relkind IN ('r', 'p', 'v', 'm'))
     ORDER BY n.nspname, c.relname`,
  );
  for (const row of badRelRes.rows) {
    problems.push(`Forbidden copied table or relation ${row.schema_name}.${row.rel_name} (relkind=${row.relkind}) in ${row.schema_name}`);
  }

  const appViewsRes = await pool.query(
    `SELECT c.oid AS view_oid,
            c.relname AS view_name,
            r.rolname AS owner_name,
            c.reloptions,
            pg_catalog.pg_get_viewdef(c.oid, true) AS view_def
     FROM pg_catalog.pg_class c
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
     WHERE n.nspname = 'app_views' AND c.relkind = 'v'
     ORDER BY c.relname`,
  );
  const appViewOids = appViewsRes.rows.map((v) => v.view_oid);
  const [appViewPrivRes, appViewColPrivRes] = await Promise.all([
    pool.query(
      `SELECT v.view_oid, p.principal, pr.priv
       FROM pg_catalog.unnest($1::oid[]) AS v(view_oid)
       CROSS JOIN pg_catalog.unnest($2::text[]) AS p(principal)
       CROSS JOIN pg_catalog.unnest($3::text[]) AS pr(priv)
       WHERE pg_catalog.has_table_privilege(p.principal, v.view_oid, pr.priv)`,
      [appViewOids, lockedPrincipals, ALL_RELATION_PRIVS],
    ),
    pool.query(
      `SELECT v.view_oid, p.principal, pr.priv
       FROM pg_catalog.unnest($1::oid[]) AS v(view_oid)
       CROSS JOIN pg_catalog.unnest($2::text[]) AS p(principal)
       CROSS JOIN pg_catalog.unnest($3::text[]) AS pr(priv)
       WHERE pg_catalog.has_any_column_privilege(p.principal, v.view_oid, pr.priv)`,
      [appViewOids, lockedPrincipals, ALL_COLUMN_PRIVS],
    ),
  ]);
  const appViewInfoByOid = new Map(appViewsRes.rows.map((v) => [Number(v.view_oid), v]));
  const appViewSelectOids = new Set();
  for (const row of appViewPrivRes.rows) {
    const v = appViewInfoByOid.get(Number(row.view_oid));
    const fq = `app_views.${v.view_name}`;
    if (row.principal === 'public') {
      problems.push(`PUBLIC must not hold ${row.priv} on ${fq}`);
    } else if (row.principal === 'platform_app') {
      if (row.priv === 'SELECT') appViewSelectOids.add(Number(row.view_oid));
      else problems.push(`platform_app must not hold ${row.priv} on ${fq}`);
    } else {
      problems.push(`Retired role ${row.principal} must not hold ${row.priv} on ${fq}`);
    }
  }
  for (const row of appViewColPrivRes.rows) {
    if (row.principal === 'platform_app' && row.priv === 'SELECT') continue;
    const v = appViewInfoByOid.get(Number(row.view_oid));
    const fq = `app_views.${v.view_name}`;
    if (row.principal === 'public') {
      problems.push(`PUBLIC must not hold column-level ${row.priv} on ${fq}`);
    } else if (row.principal === 'platform_app') {
      problems.push(`platform_app must not hold column-level ${row.priv} on ${fq}`);
    } else {
      problems.push(`Retired role ${row.principal} must not hold column-level ${row.priv} on ${fq}`);
    }
  }

  const keyedHelperRe = /effective_wide_org_ids|_read_(bob_wide_orgs|agency_statement_wide_orgs|statement_cash_wide_orgs|upline_statement_orgs|ledger_orgs)\b/;
  const forbiddenKeyedAnyRe = /\b(effective_any_org_ids|_read_(has_run_meta_access|can_see_unsent_run_meta|has_statement_batch_access|can_see_unsent_batch_meta))\b/i;

  const foundAppViews = new Set();
  for (const v of appViewsRes.rows) {
    foundAppViews.add(v.view_name);
    const fq = `app_views.${v.view_name}`;
    const opts = Array.isArray(v.reloptions) ? v.reloptions : [];
    if (v.owner_name !== 'platform_view_owner') {
      problems.push(`View ${fq} must be owned by platform_view_owner (got ${v.owner_name})`);
    }
    if (!opts.includes('security_barrier=true')) {
      problems.push(`View ${fq} must set security_barrier=true (reloptions: ${JSON.stringify(opts)})`);
    }
    if (opts.includes('security_invoker=true')) {
      problems.push(`View ${fq} must not set security_invoker=true (platform_app has zero base-table SELECT)`);
    }
    if (v.view_name === 'coherence_entity_statement_reconciliation' && forbiddenKeyedAnyRe.test(v.view_def || '')) {
      problems.push(`View ${fq} must not use iam.effective_any_org_ids() or metadata-only _read_* helpers`);
    }
    if (!appViewSelectOids.has(Number(v.view_oid))) {
      problems.push(`platform_app is missing SELECT on ${fq}`);
    }
  }
  for (const expectedView of APP_VIEWS_EXPECTED) {
    if (!foundAppViews.has(expectedView)) {
      problems.push(`Expected app_views.${expectedView} view is missing`);
    }
  }

  // 4c. Coherence under IAM: FORCE RLS, ENABLE ALWAYS immutability triggers, FKs to iam.organizations/iam.people,
  //     platform_view_owner policies, and zero retired pre-IAM policies or helper functions.
  const [cohRlsRes, cohTrigRes, fkRes, npnChkRes] = await Promise.all([
    pool.query(
      `SELECT n.nspname AS schema_name, c.relname AS table_name, c.relrowsecurity, c.relforcerowsecurity,
              (SELECT pg_catalog.count(*)::int FROM pg_catalog.pg_policies p
               WHERE p.schemaname = n.nspname AND p.tablename = c.relname) AS pol_cnt
       FROM pg_catalog.pg_class c
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE (n.nspname = 'coherence' AND c.relkind IN ('r', 'p') AND c.relname <> 'schema_migrations')
          OR (n.nspname = 'platform' AND c.relname = 'audit_journal')`,
    ),
    pool.query(
      `SELECT c.relname AS table_name,
              t.tgname AS trigger_name,
              t.tgenabled,
              pg_catalog.pg_get_triggerdef(t.oid) AS def
       FROM pg_catalog.pg_trigger t
       JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'coherence' AND NOT t.tgisinternal`,
    ),
    pool.query(
      `SELECT c.relname AS table_name, a.attname AS col_name, rn.nspname || '.' || rc.relname AS ref_tbl
       FROM pg_catalog.pg_constraint con
       JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       JOIN pg_catalog.pg_class rc ON rc.oid = con.confrelid
       JOIN pg_catalog.pg_namespace rn ON rn.oid = rc.relnamespace
       JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = con.conkey[1]
       WHERE n.nspname = 'coherence' AND c.relname = ANY($1::text[])
         AND con.contype = 'f' AND pg_catalog.array_length(con.conkey, 1) = 1`,
      [COHERENCE_IAM_FK_TABLES],
    ),
    pool.query(
      `SELECT c.relname AS table_name, con.conname
       FROM pg_catalog.pg_constraint con
       JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'coherence' AND c.relname = ANY($1::text[]) AND con.contype = 'c'
         AND pg_catalog.pg_get_constraintdef(con.oid) ~ 'writing_npn'
         AND pg_catalog.pg_get_constraintdef(con.oid) ~ 'writing_person_id'`,
      [COHERENCE_IAM_FK_TABLES],
    ),
  ]);

  for (const r of cohRlsRes.rows) {
    if (!r.relrowsecurity || !r.relforcerowsecurity) {
      problems.push(`Table ${r.schema_name}.${r.table_name} must have ENABLE + FORCE ROW LEVEL SECURITY`);
    }
    if (r.pol_cnt < 1) {
      problems.push(`Table ${r.schema_name}.${r.table_name} must have at least one RLS policy`);
    }
  }

  const cohTrigByKey = new Map(cohTrigRes.rows.map((r) => [`${r.table_name}:${r.trigger_name}`, r]));
  for (const tbl of ALL_BUSINESS_TABLES) {
    const tr = cohTrigByKey.get(`${tbl}:trg_immutable`);
    if (!tr) {
      problems.push(`Missing append-only trigger trg_immutable on coherence.${tbl}`);
      continue;
    }
    if (tr.tgenabled !== 'A') {
      problems.push(`Trigger trg_immutable on coherence.${tbl} must be ENABLE ALWAYS (tgenabled='A'), got '${tr.tgenabled}'`);
    }
    for (const op of ['BEFORE', 'UPDATE', 'DELETE', 'TRUNCATE', 'coherence.forbid_mutation']) {
      if (!tr.def.includes(op)) {
        problems.push(`Trigger trg_immutable on coherence.${tbl} definition missing ${op}: ${tr.def}`);
      }
    }
  }
  for (const trigName of ['trg_review_submissions_guard', 'trg_review_submissions_no_trunc']) {
    const tr = cohTrigByKey.get(`review_submissions:${trigName}`);
    if (!tr || tr.tgenabled !== 'A') {
      problems.push(`Trigger ${trigName} on coherence.review_submissions must exist and be ENABLE ALWAYS (tgenabled='A')`);
    }
  }

  const fkByTable = new Map();
  for (const f of fkRes.rows) {
    const list = fkByTable.get(f.table_name) || [];
    list.push(f);
    fkByTable.set(f.table_name, list);
  }
  const npnChkTables = new Set(npnChkRes.rows.map((r) => r.table_name));

  // Fetch all policies across managed schemas once and validate every policy rule in memory.
  const allPolRes = await pool.query(
    `SELECT schemaname, tablename, policyname, cmd, roles::text[] AS roles, qual, with_check
     FROM pg_catalog.pg_policies
     WHERE schemaname IN ('coherence', 'platform', 'iam', 'iam_secret')
     ORDER BY schemaname, tablename, policyname`,
  );
  const fkTableSet = new Set(COHERENCE_IAM_FK_TABLES);
  const retiredRoleSet = new Set(RETIRED_COHERENCE_ROLES);
  const cohViewPolTables = new Set();
  const auditViewPols = [];
  const legacyGucRe = /rls_allowed_entities|rls_actor_npn|rls_access_tier|app\.allowed_entities|app\.actor_npn|app\.access_tier/;

  for (const p of allPolRes.rows) {
    const roleList = Array.isArray(p.roles) ? p.roles : [];
    const qual = p.qual || '';
    const withCheck = p.with_check || '';

    if (roleList.includes('public')) {
      problems.push(`Forbidden PUBLIC RLS policy on ${p.schemaname}.${p.tablename}: ${p.policyname}`);
    }
    const matchedRetired = roleList.filter((r) => retiredRoleSet.has(r));
    if (matchedRetired.length > 0) {
      problems.push(`Retired ${matchedRetired.join('/')} RLS policy still active on ${p.schemaname}.${p.tablename}: ${p.policyname}`);
    }
    if (p.schemaname === 'coherence' && legacyGucRe.test(qual)) {
      problems.push(`Retired Migration 006 policy still active on ${p.schemaname}.${p.tablename}: ${p.policyname}`);
    }
    if ((p.schemaname === 'coherence' || p.schemaname === 'platform') && roleList.includes('platform_worker') && p.cmd !== 'SELECT') {
      problems.push(`RLS policy ${p.policyname} on ${p.schemaname}.${p.tablename} grants platform_worker ${p.cmd} (must be SELECT only)`);
    }
    if (p.schemaname === 'coherence' && roleList.includes('platform_view_owner')) {
      cohViewPolTables.add(p.tablename);
      if (p.cmd !== 'SELECT') {
        problems.push(`RLS policy ${p.policyname} on coherence.${p.tablename} grants platform_view_owner ${p.cmd} (must be SELECT only)`);
      }
      if (/\bhas_right\s*\(/i.test(qual)) {
        problems.push(`RLS policy ${p.policyname} on coherence.${p.tablename} uses unscoped iam.has_right()`);
      }
      if (fkTableSet.has(p.tablename)) {
        if (forbiddenKeyedAnyRe.test(qual) || forbiddenKeyedAnyRe.test(withCheck)) {
          problems.push(`RLS policy ${p.policyname} on keyed table coherence.${p.tablename} must not use iam.effective_any_org_ids()`);
        }
        if (!keyedHelperRe.test(qual)) {
          problems.push(`Table coherence.${p.tablename} has an unscoped platform_view_owner RLS policy ${p.policyname} (must reference wide/scoped IAM read helpers)`);
        }
      } else if (!/(effective_(wide|any)_org_ids|app_views\._read_)/.test(qual)) {
        problems.push(`Table coherence.${p.tablename} has an unscoped platform_view_owner RLS policy ${p.policyname} (must scope with IAM org helpers)`);
      }
    }
    if (p.schemaname === 'platform' && p.tablename === 'audit_journal' && roleList.includes('platform_view_owner')) {
      auditViewPols.push(p);
    }
  }

  for (const tbl of COHERENCE_IAM_FK_TABLES) {
    const fks = fkByTable.get(tbl) || [];
    if (!fks.some((f) => f.col_name === 'organization_id' && f.ref_tbl === 'iam.organizations')) {
      problems.push(`Table coherence.${tbl} is missing organization_id FK to iam.organizations`);
    }
    if (!fks.some((f) => f.col_name === 'writing_person_id' && f.ref_tbl === 'iam.people')) {
      problems.push(`Table coherence.${tbl} is missing writing_person_id FK to iam.people`);
    }
    if (!cohViewPolTables.has(tbl)) {
      problems.push(`Table coherence.${tbl} is missing platform_view_owner RLS policy`);
    }
    if (!npnChkTables.has(tbl)) {
      problems.push(`Table coherence.${tbl} is missing CHECK constraint requiring writing_person_id IS NULL when writing_npn IS NULL`);
    }
    const bfTr = cohTrigByKey.get(`${tbl}:trg_guard_iam_fk_backfill`);
    if (!bfTr || bfTr.tgenabled !== 'A' || !bfTr.def.includes('guard_iam_fk_backfill')) {
      problems.push(`Table coherence.${tbl} must carry ENABLE ALWAYS trg_guard_iam_fk_backfill trigger`);
    }
  }

  if (cohViewPolTables.size === 0) {
    problems.push('Schema coherence has no platform_view_owner RLS policies');
  }
  const pvReadableOids = new Set(pvSelRes.rows.map((r) => Number(r.table_oid)));
  for (const row of cohBaseTbls) {
    if (pvReadableOids.has(Number(row.table_oid)) && !cohViewPolTables.has(row.table_name)) {
      problems.push(`Table coherence.${row.table_name} grants SELECT to platform_view_owner without a platform_view_owner RLS policy`);
    }
  }

  if (auditViewPols.length === 0) {
    problems.push('Table platform.audit_journal is missing platform_view_owner RLS policy');
  } else if (!auditViewPols.every((p) => (
    p.cmd === 'SELECT'
    && !/\bhas_right\s*\(/i.test(p.qual || '')
    && /effective_wide_org_ids/.test(p.qual || '')
  ))) {
    problems.push('Table platform.audit_journal has an unscoped platform_view_owner RLS policy (every policy must be FOR SELECT scoped with iam.effective_wide_org_ids)');
  }

  // Confirm removed privileged write bypass objects and Migration 006 helper functions do not exist.
  const [privTblRes, retiredFnRes] = await Promise.all([
    pool.query(
      `SELECT c.relname
       FROM pg_catalog.pg_class c
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'coherence' AND c.relname = 'privileged_write_grants'`,
    ),
    pool.query(
      `SELECT p.proname
       FROM pg_catalog.pg_proc p
       JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'coherence'
         AND p.proname IN (
           'begin_privileged_write', 'end_privileged_write',
           'rls_allowed_entities', 'rls_actor_npn', 'rls_access_tier',
           'upline_entity_label', 'batch_is_official_sent',
           'attempt_is_published_run', 'batch_is_published_for_em'
         )`,
    ),
  ]);
  if (privTblRes.rows.length > 0) {
    problems.push('Removed table coherence.privileged_write_grants must not exist');
  }
  const removedPrivilegedFns = new Set(['begin_privileged_write', 'end_privileged_write']);
  for (const rf of retiredFnRes.rows) {
    if (removedPrivilegedFns.has(rf.proname)) {
      problems.push(`Removed privileged write function coherence.${rf.proname} must not exist`);
    } else {
      problems.push(`Retired Migration 006 helper function still exists: coherence.${rf.proname}`);
    }
  }

  // Audit coherence.backfill_iam_foreign_keys, internal coherence._resolve_* / _cmd_* / _ro_run_stage,
  // narrow helper views (v_run_latest_journal_seq, v_current_finished_attempts), and app_views._read_* / run_stage*.
  const allAuditPrincipals = ['public', ...PLATFORM_ROLES, ...existingRetiredRoles];
  const [bfFnRes, internalCohFnRes, internalViewRes] = await Promise.all([
    pool.query(
      `SELECT p.oid, p.prosecdef, r.rolname AS owner_name, p.proconfig
       FROM pg_catalog.pg_proc p
       JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
       WHERE n.nspname = 'coherence' AND p.proname = 'backfill_iam_foreign_keys'`,
    ),
    pool.query(
      `SELECT p.oid, n.nspname AS schema_name, p.proname, p.proconfig, p.prosecdef, r.rolname AS owner_name,
              pg_catalog.pg_get_functiondef(p.oid) AS fn_def
       FROM pg_catalog.pg_proc p
       JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
       WHERE (n.nspname = 'coherence' AND (
                p.proname LIKE '\\_resolve\\_%' ESCAPE '\\'
                OR p.proname LIKE '\\_cmd\\_%' ESCAPE '\\'
                OR p.proname = '_ro_run_stage'
              ))
          OR (n.nspname = 'app_views' AND (
                p.proname LIKE '\\_read\\_%' ESCAPE '\\'
                OR p.proname IN ('coherence_run_stage', 'coherence_run_stages')
              ))`,
    ),
    pool.query(
      `SELECT c.oid, c.relname AS view_name, r.rolname AS owner_name, c.reloptions
       FROM pg_catalog.pg_class c
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
       WHERE n.nspname = 'coherence'
         AND c.relname IN ('v_run_latest_journal_seq', 'v_current_finished_attempts')
         AND c.relkind = 'v'`,
    ),
  ]);

  const specialFnOids = [
    ...bfFnRes.rows.map((r) => r.oid),
    ...internalCohFnRes.rows.map((r) => r.oid),
  ];
  const specialFnExecRes = specialFnOids.length > 0
    ? await pool.query(
      `SELECT f.fn_oid, p.principal
       FROM pg_catalog.unnest($1::oid[]) AS f(fn_oid)
       CROSS JOIN pg_catalog.unnest($2::text[]) AS p(principal)
       WHERE pg_catalog.has_function_privilege(p.principal, f.fn_oid, 'EXECUTE')`,
      [specialFnOids, allAuditPrincipals],
    )
    : { rows: [] };
  const execByFnOid = new Map();
  for (const row of specialFnExecRes.rows) {
    const oid = Number(row.fn_oid);
    let set = execByFnOid.get(oid);
    if (!set) {
      set = new Set();
      execByFnOid.set(oid, set);
    }
    set.add(row.principal);
  }

  const bfAllowedSet = new Set(BACKFILL_ALLOWED_ROLES);
  if (bfFnRes.rows.length !== 1 || !bfFnRes.rows[0].prosecdef || bfFnRes.rows[0].owner_name !== 'platform_versioner') {
    problems.push('coherence.backfill_iam_foreign_keys must be SECURITY DEFINER owned by platform_versioner');
  } else {
    const bfCfg = Array.isArray(bfFnRes.rows[0].proconfig) ? bfFnRes.rows[0].proconfig : [];
    if (!bfCfg.includes('search_path=pg_catalog')) {
      problems.push(`coherence.backfill_iam_foreign_keys must pin SET search_path = pg_catalog (proconfig: ${JSON.stringify(bfCfg)})`);
    }
    const holders = execByFnOid.get(Number(bfFnRes.rows[0].oid)) || new Set();
    for (const principal of allAuditPrincipals) {
      if (bfAllowedSet.has(principal)) {
        if (!holders.has(principal)) problems.push(`${principal} is missing EXECUTE on coherence.backfill_iam_foreign_keys`);
      } else if (holders.has(principal)) {
        problems.push(`${principal} holds forbidden EXECUTE privilege on coherence.backfill_iam_foreign_keys`);
      }
    }
  }

  const resolveFns = internalCohFnRes.rows.filter((f) => f.schema_name === 'coherence' && f.proname.startsWith('_resolve_'));
  const cmdFns = internalCohFnRes.rows.filter((f) => f.schema_name === 'coherence' && f.proname.startsWith('_cmd_'));
  const readFns = internalCohFnRes.rows.filter((f) => f.schema_name === 'app_views' && f.proname.startsWith('_read_'));
  const roStageFns = internalCohFnRes.rows.filter((f) => f.schema_name === 'coherence' && f.proname === '_ro_run_stage');
  const appStageFns = internalCohFnRes.rows.filter((f) => f.schema_name === 'app_views' && (f.proname === 'coherence_run_stage' || f.proname === 'coherence_run_stages'));
  if (resolveFns.length === 0) problems.push('Expected internal coherence._resolve_* helper functions were not found in pg_proc');
  if (cmdFns.length === 0) problems.push('Expected internal coherence._cmd_* helper functions were not found in pg_proc');
  if (readFns.length === 0) problems.push('Expected shared app_views._read_* rights helper functions were not found in pg_proc');
  if (roStageFns.length !== 1) problems.push('Expected narrow definer helper function coherence._ro_run_stage is missing');
  if (appStageFns.length !== 2) problems.push('Expected app_views.coherence_run_stage and app_views.coherence_run_stages wrapper functions');

  const readWideOnlyFns = new Set([
    '_read_has_full_tenant_right',
    '_read_workshop_right',
    '_read_bob_wide_orgs',
    '_read_bob_narrow_pairs',
    '_read_agency_statement_wide_orgs',
    '_read_agency_statement_narrow_pairs',
    '_read_statement_cash_wide_orgs',
    '_read_statement_cash_narrow_pairs',
    '_read_member_phi_wide_orgs',
    '_read_member_phi_narrow_pairs',
    '_read_member_contact_wide_orgs',
    '_read_member_contact_narrow_pairs',
    '_read_unpublished_wide_orgs',
    '_read_unpublished_narrow_pairs',
    '_read_upline_cash_orgs',
    '_read_upline_statement_orgs',
    '_read_ledger_orgs',
    '_read_reconciliation_orgs',
    '_read_has_full_entity_finance',
  ]);
  const readMetaFns = new Set([
    '_read_has_run_meta_access',
    '_read_can_see_unsent_run_meta',
    '_read_has_statement_batch_access',
    '_read_can_see_unsent_batch_meta',
    '_read_published_emit_attempts',
    '_read_published_emit_attempt_ids',
  ]);
  for (const ifn of internalCohFnRes.rows) {
    const isResolve = ifn.schema_name === 'coherence' && ifn.proname.startsWith('_resolve_');
    const isRoStage = ifn.schema_name === 'coherence' && ifn.proname === '_ro_run_stage';
    const isRead = ifn.schema_name === 'app_views' && ifn.proname.startsWith('_read_');
    const isAppStage = ifn.schema_name === 'app_views' && !isRead;
    const expectedOwner = isResolve ? 'platform_versioner' : (isRoStage ? 'platform_readonly' : ((isRead || isAppStage) ? 'platform_view_owner' : 'platform_writer'));
    const allowedRoles = new Set(
      isResolve
        ? ['platform_versioner', 'platform_writer']
        : (isRoStage
          ? ['platform_readonly', 'platform_view_owner']
          : ((isRead || isAppStage)
            ? ['platform_view_owner', 'platform_app', 'platform_readonly']
            : ['platform_writer'])),
    );
    const fqFn = `${ifn.schema_name}.${ifn.proname}`;
    const cfg = Array.isArray(ifn.proconfig) ? ifn.proconfig : [];
    if (!cfg.includes('search_path=pg_catalog')) {
      problems.push(`Internal function ${fqFn} must pin SET search_path = pg_catalog (proconfig: ${JSON.stringify(cfg)})`);
    }
    if (ifn.owner_name !== expectedOwner) {
      problems.push(`Internal function ${fqFn} must be owned by ${expectedOwner} (got ${ifn.owner_name})`);
    }
    if ((isRead || isRoStage || isAppStage) && !ifn.prosecdef) {
      problems.push(`Helper ${fqFn} must be SECURITY DEFINER owned by ${expectedOwner}`);
    }
    if (isRead && !readWideOnlyFns.has(ifn.proname) && !readMetaFns.has(ifn.proname)) {
      problems.push(`Unclassified shared read helper ${fqFn} must be listed in readWideOnlyFns or readMetaFns`);
    }
    if (isRead && readWideOnlyFns.has(ifn.proname) && forbiddenKeyedAnyRe.test(ifn.fn_def || '')) {
      problems.push(`Wide/scoped read helper ${fqFn} must not use iam.effective_any_org_ids()`);
    }
    if (isRoStage && /\b(app_views|iam)\./i.test(ifn.fn_def || '')) {
      problems.push('coherence._ro_run_stage must not reference app_views.* or iam.* (must delegate purely to coherence.run_stage)');
    }
    if (isAppStage) {
      if (!/\bcoherence\._ro_run_stage\s*\(/.test(ifn.fn_def || '') || /\bcoherence\.run_stage\s*\(/.test(ifn.fn_def || '')) {
        problems.push(`${fqFn} must delegate to coherence._ro_run_stage (never coherence.run_stage directly)`);
      }
      if (!/\bapp_views\._read_workshop_right\s*\(/.test(ifn.fn_def || '')) {
        problems.push(`${fqFn} must enforce app_views._read_workshop_right`);
      }
    }
    const holders = execByFnOid.get(Number(ifn.oid)) || new Set();
    for (const reqRole of allowedRoles) {
      if (!holders.has(reqRole)) {
        problems.push(`${reqRole} is missing EXECUTE on internal function ${fqFn}`);
      }
    }
    for (const principal of allAuditPrincipals) {
      if (!allowedRoles.has(principal) && holders.has(principal)) {
        problems.push(`${principal} holds forbidden EXECUTE privilege on internal function ${fqFn}`);
      }
    }
  }

  // Narrow helper views coherence.v_run_latest_journal_seq (platform_readonly) and
  // coherence.v_current_finished_attempts (platform_view_owner) must set security_barrier=true.
  const internalViewByName = new Map(internalViewRes.rows.map((r) => [r.view_name, r]));
  for (const [viewName, expectedOwner, restrictSelect] of [
    ['v_run_latest_journal_seq', 'platform_readonly', true],
    ['v_current_finished_attempts', 'platform_view_owner', true],
  ]) {
    const iv = internalViewByName.get(viewName);
    if (!iv) {
      problems.push(`Expected narrow helper view coherence.${viewName} is missing`);
      continue;
    }
    const opts = Array.isArray(iv.reloptions) ? iv.reloptions : [];
    if (iv.owner_name !== expectedOwner) {
      problems.push(`View coherence.${viewName} must be owned by ${expectedOwner} (got ${iv.owner_name})`);
    }
    if (!opts.includes('security_barrier=true')) {
      problems.push(`View coherence.${viewName} must set security_barrier=true (reloptions: ${JSON.stringify(opts)})`);
    }
    if (opts.includes('security_invoker=true')) {
      problems.push(`View coherence.${viewName} must not set security_invoker=true`);
    }
    if (restrictSelect) {
      const tipPrivRes = await pool.query(
        `SELECT p.principal
         FROM pg_catalog.unnest($1::text[]) AS p(principal)
         WHERE pg_catalog.has_table_privilege(p.principal, $2::oid, 'SELECT')`,
        [allAuditPrincipals, iv.oid],
      );
      const tipHolders = new Set(tipPrivRes.rows.map((r) => r.principal));
      const allowedTipReaders = new Set(['platform_readonly', 'platform_view_owner']);
      for (const principal of allAuditPrincipals) {
        if (allowedTipReaders.has(principal)) {
          if (!tipHolders.has(principal)) problems.push(`${principal} is missing SELECT on coherence.${viewName}`);
        } else if (tipHolders.has(principal)) {
          problems.push(`${principal} holds forbidden SELECT privilege on coherence.${viewName}`);
        }
      }
    }
  }

  // 5. Verify every iam base table is covered by IAM_IMMUTABLE_TABLES or IAM_VERSIONED_TABLES (disjoint),
  //    all iam tables and platform.audit_journal carry ENABLE ALWAYS immutability triggers, and
  //    all versioned iam tables carry BEFORE INSERT platform_versioner supersession triggers.
  const versionedSet = new Set(IAM_VERSIONED_TABLES);
  const immutableSet = new Set(IAM_IMMUTABLE_TABLES);
  for (const tbl of IAM_IMMUTABLE_TABLES) {
    if (versionedSet.has(tbl)) {
      problems.push(`Table iam.${tbl} appears in both IAM_IMMUTABLE_TABLES and IAM_VERSIONED_TABLES`);
    }
  }
  const actualIamTables = new Set(tblRes.rows.filter((r) => r.table_schema === 'iam').map((r) => r.table_name));
  for (const tbl of actualIamTables) {
    if (!immutableSet.has(tbl) && !versionedSet.has(tbl)) {
      problems.push(`Base table iam.${tbl} is not covered by IAM_IMMUTABLE_TABLES or IAM_VERSIONED_TABLES`);
    }
  }
  for (const tbl of [...IAM_IMMUTABLE_TABLES, ...IAM_VERSIONED_TABLES]) {
    if (!actualIamTables.has(tbl)) {
      problems.push(`Expected iam base table iam.${tbl} is missing`);
    }
  }
  for (const tbl of tblRes.rows.filter((r) => r.table_schema === 'platform').map((r) => r.table_name)) {
    if (tbl !== 'audit_journal') {
      problems.push(`Unexpected base table platform.${tbl} is not covered by platform immutability checks`);
    }
  }

  const [iamTrigRes, supFnRes] = await Promise.all([
    pool.query(
      `SELECT n.nspname AS schema_name,
              c.relname AS table_name,
              t.tgname AS trigger_name,
              t.tgenabled,
              pg_catalog.pg_get_triggerdef(t.oid) AS def
       FROM pg_catalog.pg_trigger t
       JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname IN ('iam', 'platform') AND NOT t.tgisinternal`,
    ),
    pool.query(
      `SELECT p.prosecdef, r.rolname AS owner_name
       FROM pg_catalog.pg_proc p
       JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
       WHERE n.nspname = 'platform' AND p.proname = 'stamp_superseded_before_insert'`,
    ),
  ]);
  const trigByKey = new Map(iamTrigRes.rows.map((r) => [`${r.schema_name}.${r.table_name}:${r.trigger_name}`, r]));

  for (const fq of ['platform.audit_journal', ...IAM_IMMUTABLE_TABLES.map((t) => `iam.${t}`)]) {
    const tr = trigByKey.get(`${fq}:trg_immutable`);
    if (!tr || tr.tgenabled !== 'A') {
      problems.push(`Missing ENABLE ALWAYS trg_immutable on ${fq}`);
    }
  }
  for (const tbl of IAM_VERSIONED_TABLES) {
    const fq = `iam.${tbl}`;
    const trImm = trigByKey.get(`${fq}:trg_immutable`);
    if (!trImm || trImm.tgenabled !== 'A') {
      problems.push(`Missing ENABLE ALWAYS trg_immutable on versioned table ${fq}`);
    }
    const trTrunc = trigByKey.get(`${fq}:trg_immutable_truncate`);
    if (!trTrunc || trTrunc.tgenabled !== 'A') {
      problems.push(`Missing ENABLE ALWAYS trg_immutable_truncate on versioned table ${fq}`);
    }
    const trSup = trigByKey.get(`${fq}:trg_01_supersede`);
    if (!trSup || !trSup.def.includes('BEFORE INSERT') || !trSup.def.includes('platform.stamp_superseded_before_insert')) {
      problems.push(`Missing BEFORE INSERT trg_01_supersede on versioned table ${fq}`);
    }
  }
  if (supFnRes.rows.length !== 1 || !supFnRes.rows[0].prosecdef || supFnRes.rows[0].owner_name !== 'platform_versioner') {
    problems.push('platform.stamp_superseded_before_insert() must be SECURITY DEFINER owned by platform_versioner');
  }

  // 6. All functions across ALL managed schemas (platform, iam_secret, iam, coherence, app_views, app_cmd)
  //    pin SET search_path = pg_catalog and revoke EXECUTE from PUBLIC and retired roles;
  //    every app_cmd.* function is SECURITY DEFINER owned by platform_writer;
  //    platform_app holds EXECUTE strictly on PLATFORM_APP_FUNCTION_WHITELIST + PLATFORM_APP_CMD_WHITELIST;
  //    platform_readonly holds ZERO EXECUTE on app_cmd.*; platform_worker holds EXECUTE strictly on PLATFORM_WORKER_CMD_WHITELIST.
  const fnRes = await pool.query(
    `SELECT p.oid,
            n.nspname,
            p.proname,
            p.prosecdef,
            r.rolname AS owner_name,
            pg_catalog.format('%I.%I(%s)', n.nspname, p.proname, pg_catalog.oidvectortypes(p.proargtypes)) AS sig,
            p.proconfig,
            pg_catalog.has_function_privilege('public', p.oid, 'EXECUTE') AS pub_exec,
            pg_catalog.has_function_privilege('platform_app', p.oid, 'EXECUTE') AS app_exec,
            pg_catalog.has_function_privilege('platform_readonly', p.oid, 'EXECUTE') AS ro_exec,
            pg_catalog.has_function_privilege('platform_worker', p.oid, 'EXECUTE') AS wrk_exec
     FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
     WHERE n.nspname = ANY($1::text[])
     ORDER BY n.nspname, p.proname`,
    [MANAGED_SCHEMAS],
  );
  if (existingRetiredRoles.length > 0 && fnRes.rows.length > 0) {
    const retiredFnExecRes = await pool.query(
      `SELECT f.fn_oid, p.principal
       FROM pg_catalog.unnest($1::oid[]) AS f(fn_oid)
       CROSS JOIN pg_catalog.unnest($2::text[]) AS p(principal)
       WHERE pg_catalog.has_function_privilege(p.principal, f.fn_oid, 'EXECUTE')`,
      [fnRes.rows.map((f) => f.oid), existingRetiredRoles],
    );
    const fnByOid = new Map(fnRes.rows.map((f) => [Number(f.oid), f]));
    for (const row of retiredFnExecRes.rows) {
      const fn = fnByOid.get(Number(row.fn_oid));
      problems.push(`Retired role ${row.principal} holds forbidden EXECUTE privilege on ${fn.sig}`);
    }
  }

  const appCmdFns = fnRes.rows.filter((f) => f.nspname === 'app_cmd');
  if (fnRes.rows.length === 0) {
    problems.push('No functions found in managed schemas');
  }
  const combinedWhitelist = [...PLATFORM_APP_FUNCTION_WHITELIST, ...PLATFORM_APP_CMD_WHITELIST];
  const whitelistSet = new Set(combinedWhitelist);
  const workerOnlySet = new Set(APP_CMD_WORKER_ONLY_FUNCTIONS);
  const workerCmdSet = new Set(PLATFORM_WORKER_CMD_WHITELIST);
  const foundWhitelisted = new Set();
  const foundWorkerOnly = new Set();
  const foundWorkerCmd = new Set();

  for (const fn of fnRes.rows) {
    const cfg = Array.isArray(fn.proconfig) ? fn.proconfig : [];
    if (!cfg.includes('search_path=pg_catalog')) {
      problems.push(`Function ${fn.sig} does not pin SET search_path = pg_catalog (proconfig: ${JSON.stringify(cfg)})`);
    }
    if (fn.pub_exec) {
      problems.push(`PUBLIC has EXECUTE privilege on ${fn.sig}`);
    }
    if (fn.nspname === 'platform' && ['compute_journal_hash', 'canonical_json', 'sha256_text', 'format_utc_us'].includes(fn.proname) && fn.wrk_exec) {
      problems.push(`platform_worker holds forbidden EXECUTE privilege on ${fn.sig}`);
    }
    if (fn.nspname === 'app_cmd') {
      if (!fn.prosecdef) {
        problems.push(`Command function ${fn.sig} must be SECURITY DEFINER`);
      }
      if (fn.owner_name !== 'platform_writer') {
        problems.push(`Command function ${fn.sig} must be owned by platform_writer (got ${fn.owner_name})`);
      }
      if (fn.ro_exec) {
        problems.push(`platform_readonly holds forbidden EXECUTE privilege on app_cmd function ${fn.sig}`);
      }
      if (workerCmdSet.has(fn.sig)) {
        foundWorkerCmd.add(fn.sig);
        if (!fn.wrk_exec) {
          problems.push(`platform_worker is missing EXECUTE on allowed app_cmd function ${fn.sig}`);
        }
      } else if (fn.wrk_exec) {
        problems.push(`platform_worker holds forbidden EXECUTE privilege on non-worker app_cmd function ${fn.sig}`);
      }
      if (workerOnlySet.has(fn.sig)) {
        foundWorkerOnly.add(fn.sig);
      }
    }
    if (whitelistSet.has(fn.sig)) {
      foundWhitelisted.add(fn.sig);
      if (!fn.app_exec) {
        problems.push(`platform_app is missing EXECUTE on whitelisted function ${fn.sig}`);
      }
    } else if (fn.app_exec) {
      problems.push(`platform_app holds forbidden EXECUTE privilege on non-whitelisted function ${fn.sig}`);
    }
  }
  for (const expectedSig of combinedWhitelist) {
    if (!foundWhitelisted.has(expectedSig)) {
      problems.push(`Whitelisted platform_app function ${expectedSig} was not found in pg_proc`);
    }
  }
  for (const expectedWorkerSig of APP_CMD_WORKER_ONLY_FUNCTIONS) {
    if (!foundWorkerOnly.has(expectedWorkerSig)) {
      problems.push(`Expected worker-only app_cmd function ${expectedWorkerSig} was not found in pg_proc`);
    }
  }
  for (const expectedWorkerCmdSig of PLATFORM_WORKER_CMD_WHITELIST) {
    if (!foundWorkerCmd.has(expectedWorkerCmdSig)) {
      problems.push(`Expected platform_worker app_cmd function ${expectedWorkerCmdSig} was not found in pg_proc`);
    }
  }

  return {
    passed: problems.length === 0,
    checkedBusinessTables: ALL_BUSINESS_TABLES.length,
    checkedIamTables: IAM_IMMUTABLE_TABLES.length + IAM_VERSIONED_TABLES.length,
    checkedBaseTables: tblRes.rows.length,
    checkedViews: viewRes.rows.length,
    checkedAppViews: appViewsRes.rows.length,
    checkedFunctions: fnRes.rows.length,
    checkedAppCmdFunctions: appCmdFns.length,
    checkedInternalCoherenceFunctions: internalCohFnRes.rows.length,
    forbiddenBusinessPrivileges: FORBIDDEN_BUSINESS_PRIVS,
    problems,
  };
}
