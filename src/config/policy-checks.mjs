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

export const SCOPED_RECIPIENT_ROLES = Object.freeze([
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
  'app_views._read_tenant_right(text)',
  'app_views._read_has_full_tenant_right(text)',
  'app_views._read_bob_wide_orgs()',
  'app_views._read_bob_narrow_pairs()',
  'app_views._read_agency_statement_wide_orgs()',
  'app_views._read_agency_statement_narrow_pairs()',
  'app_views._read_statement_cash_wide_orgs()',
  'app_views._read_statement_cash_narrow_pairs()',
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
  'app_views._read_current_finished_attempt(uuid, text)',
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

  const roles = config.roles || {};
  const appPrivs = roles.coherence_app?.businessTables;
  if (!Array.isArray(appPrivs) || appPrivs.length !== 2 || !appPrivs.includes('SELECT') || !appPrivs.includes('INSERT')) {
    problems.push('roles.coherence_app.businessTables must be strictly ["SELECT", "INSERT"]');
  }

  return { passed: problems.length === 0, problems };
}

export async function verifyCloudSqlConfigFile(filePath = DEFAULT_CLOUDSQL_CONFIG_PATH) {
  const raw = await readFile(filePath, 'utf8');
  const parsed = JSON.parse(raw);
  return { filePath, ...validateCloudSqlConfig(parsed), config: parsed };
}

export async function verifyDatabaseConfigInvariants(pool) {
  const problems = [];

  for (const tbl of ALL_BUSINESS_TABLES) {
    const fq = `coherence.${tbl}`;

    const appRes = await pool.query(
      `SELECT
         pg_catalog.has_table_privilege('coherence_app', $1, 'SELECT') AS sel,
         pg_catalog.has_table_privilege('coherence_app', $1, 'INSERT') AS ins,
         pg_catalog.has_table_privilege('coherence_app', $1, 'UPDATE') AS upd,
         pg_catalog.has_table_privilege('coherence_app', $1, 'DELETE') AS del,
         pg_catalog.has_table_privilege('coherence_app', $1, 'TRUNCATE') AS trn,
         pg_catalog.has_table_privilege('coherence_app', $1, 'REFERENCES') AS ref,
         pg_catalog.has_table_privilege('coherence_app', $1, 'TRIGGER') AS trg`,
      [fq],
    );
    const a = appRes.rows[0];
    if (!a.sel || !a.ins) problems.push(`coherence_app missing SELECT or INSERT on ${fq}`);
    for (const [k, label] of [['upd', 'UPDATE'], ['del', 'DELETE'], ['trn', 'TRUNCATE'], ['ref', 'REFERENCES'], ['trg', 'TRIGGER']]) {
      if (a[k]) problems.push(`coherence_app has forbidden privilege ${label} on ${fq}`);
    }

    const wrkRes = await pool.query(
      `SELECT
         pg_catalog.has_table_privilege('coherence_worker', $1, 'SELECT') AS sel,
         pg_catalog.has_table_privilege('coherence_worker', $1, 'INSERT') AS ins,
         pg_catalog.has_table_privilege('coherence_worker', $1, 'UPDATE') AS upd,
         pg_catalog.has_table_privilege('coherence_worker', $1, 'DELETE') AS del,
         pg_catalog.has_table_privilege('coherence_worker', $1, 'TRUNCATE') AS trn,
         pg_catalog.has_table_privilege('coherence_worker', $1, 'REFERENCES') AS ref,
         pg_catalog.has_table_privilege('coherence_worker', $1, 'TRIGGER') AS trg`,
      [fq],
    );
    const w = wrkRes.rows[0];
    if (!w.sel || !w.ins) problems.push(`coherence_worker missing SELECT or INSERT on ${fq}`);
    for (const [k, label] of [['upd', 'UPDATE'], ['del', 'DELETE'], ['trn', 'TRUNCATE'], ['ref', 'REFERENCES'], ['trg', 'TRIGGER']]) {
      if (w[k]) problems.push(`coherence_worker has forbidden privilege ${label} on ${fq}`);
    }

    const roRes = await pool.query(
      `SELECT
         pg_catalog.has_table_privilege('coherence_readonly', $1, 'SELECT') AS sel,
         pg_catalog.has_table_privilege('coherence_readonly', $1, 'INSERT') AS ins,
         pg_catalog.has_table_privilege('coherence_readonly', $1, 'UPDATE') AS upd,
         pg_catalog.has_table_privilege('coherence_readonly', $1, 'DELETE') AS del,
         pg_catalog.has_table_privilege('coherence_readonly', $1, 'TRUNCATE') AS trn`,
      [fq],
    );
    const ro = roRes.rows[0];
    if (!ro.sel) problems.push(`coherence_readonly missing SELECT on ${fq}`);
    for (const [k, label] of [['ins', 'INSERT'], ['upd', 'UPDATE'], ['del', 'DELETE'], ['trn', 'TRUNCATE']]) {
      if (ro[k]) problems.push(`coherence_readonly has forbidden privilege ${label} on ${fq}`);
    }

    const pubRes = await pool.query(
      `SELECT
         pg_catalog.has_table_privilege('public', $1, 'SELECT') AS sel,
         pg_catalog.has_table_privilege('public', $1, 'INSERT') AS ins,
         pg_catalog.has_table_privilege('public', $1, 'UPDATE') AS upd,
         pg_catalog.has_table_privilege('public', $1, 'DELETE') AS del,
         pg_catalog.has_table_privilege('public', $1, 'TRUNCATE') AS trn`,
      [fq],
    );
    const pub = pubRes.rows[0];
    for (const [k, label] of [['sel', 'SELECT'], ['ins', 'INSERT'], ['upd', 'UPDATE'], ['del', 'DELETE'], ['trn', 'TRUNCATE']]) {
      if (pub[k]) problems.push(`PUBLIC has forbidden privilege ${label} on ${fq}`);
    }
  }

  const subPrivRes = await pool.query(
    `SELECT
       pg_catalog.has_table_privilege('coherence_app', 'coherence.review_submissions', 'UPDATE') AS app_upd,
       pg_catalog.has_table_privilege('coherence_app', 'coherence.review_submissions', 'DELETE') AS app_del,
       pg_catalog.has_table_privilege('coherence_app', 'coherence.review_submissions', 'TRUNCATE') AS app_trn,
       pg_catalog.has_table_privilege('coherence_worker', 'coherence.review_submissions', 'DELETE') AS wrk_del,
       pg_catalog.has_table_privilege('coherence_worker', 'coherence.review_submissions', 'TRUNCATE') AS wrk_trn`,
  );
  const sp = subPrivRes.rows[0];
  if (sp.app_upd || sp.app_del || sp.app_trn) {
    problems.push('coherence_app must not have UPDATE, DELETE, or TRUNCATE on coherence.review_submissions');
  }
  if (sp.wrk_del || sp.wrk_trn) {
    problems.push('coherence_worker must not have DELETE or TRUNCATE on coherence.review_submissions');
  }

  const schemaPub = await pool.query(
    `SELECT pg_catalog.has_schema_privilege('public', 'coherence', 'USAGE') AS usage,
            pg_catalog.has_schema_privilege('public', 'coherence', 'CREATE') AS create,
            pg_catalog.has_schema_privilege('public', 'coherence_views', 'USAGE') AS views_usage,
            pg_catalog.has_schema_privilege('public', 'coherence_views', 'CREATE') AS views_create`,
  );
  if (schemaPub.rows[0].usage || schemaPub.rows[0].create) {
    problems.push('PUBLIC must have zero privileges on schema coherence');
  }
  if (schemaPub.rows[0].views_usage || schemaPub.rows[0].views_create) {
    problems.push('PUBLIC must have zero privileges on schema coherence_views');
  }

  for (const roleName of SCOPED_RECIPIENT_ROLES) {
    const roleRes = await pool.query(
      'SELECT rolname, rolinherit, rolbypassrls, rolcanlogin FROM pg_catalog.pg_roles WHERE rolname = $1',
      [roleName],
    );
    if (roleRes.rows.length === 0) {
      problems.push(`Missing scoped read-only role ${roleName}`);
      continue;
    }
    const r = roleRes.rows[0];
    if (r.rolbypassrls) problems.push(`Scoped role ${roleName} must have NOBYPASSRLS`);
    if (r.rolinherit) problems.push(`Scoped role ${roleName} must have NOINHERIT`);
    for (const internalTbl of ['journal_entries', 'decision_commits', 'decisions', 'engine_versions', 'stored_files', 'input_versions', 'input_entries']) {
      const privRes = await pool.query(
        "SELECT pg_catalog.has_table_privilege($1, $2, 'SELECT') AS sel, pg_catalog.has_table_privilege($1, $2, 'INSERT') AS ins",
        [roleName, `coherence.${internalTbl}`],
      );
      if (privRes.rows[0].sel || privRes.rows[0].ins) {
        problems.push(`Scoped role ${roleName} must not have access to coherence.${internalTbl}`);
      }
    }
  }

  for (const rlsTbl of [...ALL_BUSINESS_TABLES, 'review_submissions', 'review_drafts']) {
    const rlsRes = await pool.query(
      `SELECT c.relrowsecurity, c.relforcerowsecurity,
              (SELECT pg_catalog.count(*)::int FROM pg_catalog.pg_policies p
               WHERE p.schemaname = 'coherence' AND p.tablename = c.relname) AS pol_cnt
       FROM pg_catalog.pg_class c
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'coherence' AND c.relname = $1`,
      [rlsTbl],
    );
    if (rlsRes.rows.length === 0 || !rlsRes.rows[0].relrowsecurity || !rlsRes.rows[0].relforcerowsecurity) {
      problems.push(`Table coherence.${rlsTbl} must have ENABLE + FORCE ROW LEVEL SECURITY`);
    } else if (rlsRes.rows[0].pol_cnt < 1) {
      problems.push(`Table coherence.${rlsTbl} must have at least one RLS policy`);
    }
  }

  const trigRes = await pool.query(
    `SELECT c.relname AS table_name,
            t.tgname AS trigger_name,
            t.tgenabled,
            pg_catalog.pg_get_triggerdef(t.oid) AS def
     FROM pg_catalog.pg_trigger t
     JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'coherence' AND NOT t.tgisinternal`,
  );
  const trigByKey = new Map(trigRes.rows.map((r) => [`${r.table_name}:${r.trigger_name}`, r]));

  for (const tbl of ALL_BUSINESS_TABLES) {
    const tr = trigByKey.get(`${tbl}:trg_immutable`);
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
    const tr = trigByKey.get(`review_submissions:${trigName}`);
    if (!tr || tr.tgenabled !== 'A') {
      problems.push(`Trigger ${trigName} on coherence.review_submissions must exist and be ENABLE ALWAYS (tgenabled='A')`);
    }
  }

  const fnRes = await pool.query(
    `SELECT p.oid, n.nspname, p.proname, p.proconfig, pg_catalog.has_function_privilege('public', p.oid, 'EXECUTE') AS pub_exec
     FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('coherence', 'coherence_views')
     ORDER BY n.nspname, p.proname`,
  );
  if (fnRes.rows.length === 0) {
    problems.push('No functions found in schemas coherence / coherence_views');
  }
  for (const fn of fnRes.rows) {
    const cfg = Array.isArray(fn.proconfig) ? fn.proconfig : [];
    if (!cfg.includes('search_path=pg_catalog')) {
      problems.push(`Function ${fn.nspname}.${fn.proname} does not pin SET search_path = pg_catalog (proconfig: ${JSON.stringify(cfg)})`);
    }
    if (fn.pub_exec) {
      problems.push(`PUBLIC has EXECUTE privilege on ${fn.nspname}.${fn.proname}`);
    }
  }

  return {
    passed: problems.length === 0,
    checkedBusinessTables: ALL_BUSINESS_TABLES.length,
    checkedFunctions: fnRes.rows.length,
    forbiddenBusinessPrivileges: FORBIDDEN_BUSINESS_PRIVS,
    problems,
  };
}

export async function verifyIamConfigInvariants(pool) {
  const problems = [];

  // 1. All platform_* roles must exist and be non-superuser, NOINHERIT, NOBYPASSRLS.
  for (const roleName of PLATFORM_ROLES) {
    const res = await pool.query(
      'SELECT rolname, rolsuper, rolinherit, rolbypassrls, rolconfig FROM pg_catalog.pg_roles WHERE rolname = $1',
      [roleName],
    );
    if (res.rows.length === 0) {
      problems.push(`Missing platform role ${roleName}`);
      continue;
    }
    const r = res.rows[0];
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

  // 2. PUBLIC must have zero privileges on all platform, IAM, Coherence, app_views, and app_cmd schemas.
  const allManagedSchemas = ['platform', 'iam_secret', 'iam', 'coherence', 'coherence_views', 'app_views', 'app_cmd'];
  for (const schema of allManagedSchemas) {
    const res = await pool.query(
      `SELECT pg_catalog.has_schema_privilege('public', $1, 'USAGE') AS u,
              pg_catalog.has_schema_privilege('public', $1, 'CREATE') AS c`,
      [schema],
    );
    if (res.rows[0].u || res.rows[0].c) {
      problems.push(`PUBLIC must have zero privileges on schema ${schema}`);
    }
  }

  // 3. platform_app and PUBLIC must have ZERO privileges on EVERY base table in coherence, iam, iam_secret, platform.
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
  for (const row of tblRes.rows) {
    const fq = `${row.table_schema}.${row.table_name}`;
    for (const principal of ['platform_app', 'public']) {
      for (const priv of ALL_RELATION_PRIVS) {
        const pRes = await pool.query(
          'SELECT pg_catalog.has_table_privilege($1, $2::oid, $3) AS has_priv',
          [principal, row.table_oid, priv],
        );
        if (pRes.rows[0].has_priv) {
          problems.push(`${principal} must not hold ${priv} on base table ${fq}`);
        }
      }
      for (const priv of ALL_COLUMN_PRIVS) {
        const cRes = await pool.query(
          'SELECT pg_catalog.has_any_column_privilege($1, $2::oid, $3) AS has_priv',
          [principal, row.table_oid, priv],
        );
        if (cRes.rows[0].has_priv) {
          problems.push(`${principal} must not hold column-level ${priv} on base table ${fq}`);
        }
      }
    }
  }

  // 4. platform_app schema lockdown: USAGE only on iam, app_views, app_cmd; ZERO CREATE everywhere;
  //    ZERO privileges for platform_app and PUBLIC on EVERY view in coherence, coherence_views, iam, iam_secret, platform.
  const allowedAppUsageSchemas = new Set(['iam', 'app_views', 'app_cmd']);
  for (const schema of allManagedSchemas) {
    const sRes = await pool.query(
      `SELECT pg_catalog.has_schema_privilege('platform_app', $1, 'USAGE') AS u,
              pg_catalog.has_schema_privilege('platform_app', $1, 'CREATE') AS c`,
      [schema],
    );
    if (!allowedAppUsageSchemas.has(schema) && sRes.rows[0].u) {
      problems.push(`platform_app must not hold USAGE on schema ${schema}`);
    }
    if (sRes.rows[0].c) {
      problems.push(`platform_app must not hold CREATE on schema ${schema}`);
    }
  }
  const viewRes = await pool.query(
    `SELECT n.nspname AS schema_name,
            c.relname AS view_name,
            c.oid AS view_oid
     FROM pg_catalog.pg_class c
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('coherence', 'coherence_views', 'iam', 'iam_secret', 'platform')
       AND c.relkind IN ('v', 'm')
     ORDER BY n.nspname, c.relname`,
  );
  if (viewRes.rows.length === 0) {
    problems.push('No views found in schemas coherence / coherence_views / iam / iam_secret / platform');
  }
  for (const row of viewRes.rows) {
    const fq = `${row.schema_name}.${row.view_name}`;
    for (const principal of ['platform_app', 'public']) {
      for (const priv of ALL_RELATION_PRIVS) {
        const vRes = await pool.query(
          'SELECT pg_catalog.has_table_privilege($1, $2::oid, $3) AS has_priv',
          [principal, row.view_oid, priv],
        );
        if (vRes.rows[0].has_priv) {
          problems.push(`${principal} must not hold ${priv} on view ${fq}`);
        }
      }
      for (const priv of ALL_COLUMN_PRIVS) {
        const cRes = await pool.query(
          'SELECT pg_catalog.has_any_column_privilege($1, $2::oid, $3) AS has_priv',
          [principal, row.view_oid, priv],
        );
        if (cRes.rows[0].has_priv) {
          problems.push(`${principal} must not hold column-level ${priv} on view ${fq}`);
        }
      }
    }
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
    for (const priv of ALL_RELATION_PRIVS) {
      const pubRes = await pool.query('SELECT pg_catalog.has_table_privilege(\'public\', $1::oid, $2) AS hp', [v.view_oid, priv]);
      if (pubRes.rows[0].hp) problems.push(`PUBLIC must not hold ${priv} on ${fq}`);
      const appRes = await pool.query('SELECT pg_catalog.has_table_privilege(\'platform_app\', $1::oid, $2) AS hp', [v.view_oid, priv]);
      if (priv === 'SELECT') {
        if (!appRes.rows[0].hp) problems.push(`platform_app is missing SELECT on ${fq}`);
      } else if (appRes.rows[0].hp) {
        problems.push(`platform_app must not hold ${priv} on ${fq}`);
      }
    }
  }
  for (const expectedView of APP_VIEWS_EXPECTED) {
    if (!foundAppViews.has(expectedView)) {
      problems.push(`Expected app_views.${expectedView} view is missing`);
    }
  }

  // 4c. Coherence under IAM: FORCE RLS on every Coherence business table + platform.audit_journal,
  //     FKs to iam.organizations/iam.people + platform_view_owner policies + zero retired Migration 006 policies/functions.
  const cohRlsRes = await pool.query(
    `SELECT n.nspname AS schema_name, c.relname AS table_name, c.relrowsecurity, c.relforcerowsecurity,
            (SELECT pg_catalog.count(*)::int FROM pg_catalog.pg_policies p
             WHERE p.schemaname = n.nspname AND p.tablename = c.relname) AS pol_cnt
     FROM pg_catalog.pg_class c
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE (n.nspname = 'coherence' AND c.relkind IN ('r', 'p') AND c.relname <> 'schema_migrations')
        OR (n.nspname = 'platform' AND c.relname = 'audit_journal')`,
  );
  for (const r of cohRlsRes.rows) {
    if (!r.relrowsecurity || !r.relforcerowsecurity) {
      problems.push(`Table ${r.schema_name}.${r.table_name} must have ENABLE + FORCE ROW LEVEL SECURITY`);
    }
    if (r.pol_cnt < 1) {
      problems.push(`Table ${r.schema_name}.${r.table_name} must have at least one RLS policy`);
    }
  }

  for (const tbl of COHERENCE_IAM_FK_TABLES) {
    const fkRes = await pool.query(
      `SELECT a.attname AS col_name, rn.nspname || '.' || rc.relname AS ref_tbl
       FROM pg_catalog.pg_constraint con
       JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       JOIN pg_catalog.pg_class rc ON rc.oid = con.confrelid
       JOIN pg_catalog.pg_namespace rn ON rn.oid = rc.relnamespace
       JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = con.conkey[1]
       WHERE n.nspname = 'coherence' AND c.relname = $1 AND con.contype = 'f' AND pg_catalog.array_length(con.conkey, 1) = 1`,
      [tbl],
    );
    const hasOrgFk = fkRes.rows.some((f) => f.col_name === 'organization_id' && f.ref_tbl === 'iam.organizations');
    const hasPerFk = fkRes.rows.some((f) => f.col_name === 'writing_person_id' && f.ref_tbl === 'iam.people');
    if (!hasOrgFk) problems.push(`Table coherence.${tbl} is missing organization_id FK to iam.organizations`);
    if (!hasPerFk) problems.push(`Table coherence.${tbl} is missing writing_person_id FK to iam.people`);

    const viewPolRes = await pool.query(
      `SELECT policyname, cmd, qual, with_check
       FROM pg_catalog.pg_policies
       WHERE schemaname = 'coherence' AND tablename = $1 AND 'platform_view_owner' = ANY(roles)`,
      [tbl],
    );
    if (viewPolRes.rows.length === 0) {
      problems.push(`Table coherence.${tbl} is missing platform_view_owner RLS policy`);
    } else if (!viewPolRes.rows.every((p) => (
      p.cmd === 'SELECT'
      && !forbiddenKeyedAnyRe.test(p.qual || '')
      && !forbiddenKeyedAnyRe.test(p.with_check || '')
      && keyedHelperRe.test(p.qual || '')
    ))) {
      problems.push(`Table coherence.${tbl} has an unscoped platform_view_owner RLS policy (every policy must be FOR SELECT scoped with wide/scoped IAM helpers and must not use iam.effective_any_org_ids)`);
    }

    const npnChkRes = await pool.query(
      `SELECT con.conname
       FROM pg_catalog.pg_constraint con
       JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'coherence' AND c.relname = $1 AND con.contype = 'c'
         AND pg_catalog.pg_get_constraintdef(con.oid) ~ 'writing_npn'
         AND pg_catalog.pg_get_constraintdef(con.oid) ~ 'writing_person_id'`,
      [tbl],
    );
    if (npnChkRes.rows.length === 0) {
      problems.push(`Table coherence.${tbl} is missing CHECK constraint requiring writing_person_id IS NULL when writing_npn IS NULL`);
    }

    const bfTrigRes = await pool.query(
      `SELECT t.tgenabled, pg_catalog.pg_get_triggerdef(t.oid) AS def
       FROM pg_catalog.pg_trigger t
       JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'coherence' AND c.relname = $1 AND t.tgname = 'trg_guard_iam_fk_backfill'`,
      [tbl],
    );
    if (bfTrigRes.rows.length !== 1 || bfTrigRes.rows[0].tgenabled !== 'A' || !bfTrigRes.rows[0].def.includes('guard_iam_fk_backfill')) {
      problems.push(`Table coherence.${tbl} must carry ENABLE ALWAYS trg_guard_iam_fk_backfill trigger`);
    }
  }

  // Every platform_view_owner policy across ALL coherence.* tables must be FOR SELECT and IAM-scoped
  // (never USING (true) and never bare iam.has_right()), and every coherence table readable by
  // platform_view_owner must have at least one platform_view_owner RLS policy.
  const cohBaseTbls = tblRes.rows.filter((r) => r.table_schema === 'coherence');
  const fkTableSet = new Set(COHERENCE_IAM_FK_TABLES);
  const allCohViewPolRes = await pool.query(
    `SELECT tablename, policyname, cmd, qual, with_check
     FROM pg_catalog.pg_policies
     WHERE schemaname = 'coherence' AND 'platform_view_owner' = ANY(roles)
     ORDER BY tablename, policyname`,
  );
  if (allCohViewPolRes.rows.length === 0) {
    problems.push('Schema coherence has no platform_view_owner RLS policies');
  }
  const cohViewPolTables = new Set();
  for (const p of allCohViewPolRes.rows) {
    cohViewPolTables.add(p.tablename);
    const qual = p.qual || '';
    if (p.cmd !== 'SELECT') {
      problems.push(`RLS policy ${p.policyname} on coherence.${p.tablename} grants platform_view_owner ${p.cmd} (must be SELECT only)`);
    }
    if (/\bhas_right\s*\(/i.test(qual)) {
      problems.push(`RLS policy ${p.policyname} on coherence.${p.tablename} uses unscoped iam.has_right()`);
    }
    if (fkTableSet.has(p.tablename)) {
      if (forbiddenKeyedAnyRe.test(qual) || forbiddenKeyedAnyRe.test(p.with_check || '')) {
        problems.push(`RLS policy ${p.policyname} on keyed table coherence.${p.tablename} must not use iam.effective_any_org_ids()`);
      }
      if (!keyedHelperRe.test(qual)) {
        problems.push(`Table coherence.${p.tablename} has an unscoped platform_view_owner RLS policy ${p.policyname} (must reference wide/scoped IAM read helpers)`);
      }
    } else if (!/(effective_(wide|any)_org_ids|app_views\._read_)/.test(qual)) {
      problems.push(`Table coherence.${p.tablename} has an unscoped platform_view_owner RLS policy ${p.policyname} (must scope with IAM org helpers)`);
    }
  }
  for (const row of cohBaseTbls) {
    const pvSelRes = await pool.query(
      'SELECT pg_catalog.has_table_privilege(\'platform_view_owner\', $1::oid, \'SELECT\') AS hp',
      [row.table_oid],
    );
    if (pvSelRes.rows[0].hp && !cohViewPolTables.has(row.table_name)) {
      problems.push(`Table coherence.${row.table_name} grants SELECT to platform_view_owner without a platform_view_owner RLS policy`);
    }
  }

  // Every platform_view_owner policy on platform.audit_journal must be FOR SELECT scoped with effective_wide_org_ids.
  const auditViewPolRes = await pool.query(
    `SELECT policyname, cmd, qual
     FROM pg_catalog.pg_policies
     WHERE schemaname = 'platform' AND tablename = 'audit_journal' AND 'platform_view_owner' = ANY(roles)`,
  );
  if (auditViewPolRes.rows.length === 0) {
    problems.push('Table platform.audit_journal is missing platform_view_owner RLS policy');
  } else if (!auditViewPolRes.rows.every((p) => (
    p.cmd === 'SELECT'
    && !/\bhas_right\s*\(/i.test(p.qual || '')
    && /effective_wide_org_ids/.test(p.qual || '')
  ))) {
    problems.push('Table platform.audit_journal has an unscoped platform_view_owner RLS policy (every policy must be FOR SELECT scoped with iam.effective_wide_org_ids)');
  }

  // Confirm removed privileged write bypass objects do not exist.
  const privTblRes = await pool.query(
    `SELECT c.relname
     FROM pg_catalog.pg_class c
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'coherence' AND c.relname = 'privileged_write_grants'`,
  );
  if (privTblRes.rows.length > 0) {
    problems.push('Removed table coherence.privileged_write_grants must not exist');
  }
  const privFnRes = await pool.query(
    `SELECT p.proname
     FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'coherence' AND p.proname IN ('begin_privileged_write', 'end_privileged_write')`,
  );
  for (const pf of privFnRes.rows) {
    problems.push(`Removed privileged write function coherence.${pf.proname} must not exist`);
  }

  // No PUBLIC RLS policy may exist across managed schemas (a PERMISSIVE PUBLIC policy would bypass role-scoped RLS).
  const publicPolRes = await pool.query(
    `SELECT schemaname, tablename, policyname
     FROM pg_catalog.pg_policies
     WHERE schemaname IN ('coherence', 'platform', 'iam', 'iam_secret')
       AND 'public' = ANY(roles)`,
  );
  for (const pp of publicPolRes.rows) {
    problems.push(`Forbidden PUBLIC RLS policy on ${pp.schemaname}.${pp.tablename}: ${pp.policyname}`);
  }

  // Legacy coherence_app and coherence_worker USING (true) RLS policies must be dropped.
  const legacyRwPolRes = await pool.query(
    `SELECT tablename, policyname
     FROM pg_catalog.pg_policies
     WHERE schemaname = 'coherence'
       AND roles && ARRAY['coherence_app', 'coherence_worker']::name[]`,
  );
  for (const lrp of legacyRwPolRes.rows) {
    problems.push(`Retired coherence_app/coherence_worker RLS policy still active on coherence.${lrp.tablename}: ${lrp.policyname}`);
  }

  // platform_worker must hold zero write privileges on any coherence base table (zero privileges on schema_migrations),
  // zero INSERT/write privileges on platform.audit_journal, zero EXECUTE on platform journal hash functions,
  // and only FOR SELECT RLS policies across coherence.* and platform.audit_journal.
  const workerForbiddenPrivs = ['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN'];
  for (const row of cohBaseTbls) {
    const fq = `coherence.${row.table_name}`;
    const privsToDeny = row.table_name === 'schema_migrations' ? ALL_RELATION_PRIVS : workerForbiddenPrivs;
    for (const priv of privsToDeny) {
      const wpRes = await pool.query(
        'SELECT pg_catalog.has_table_privilege(\'platform_worker\', $1::oid, $2) AS hp',
        [row.table_oid, priv],
      );
      if (wpRes.rows[0].hp) {
        problems.push(`platform_worker must not hold ${priv} on base table ${fq}`);
      }
    }
    const colPrivsToDeny = row.table_name === 'schema_migrations' ? ALL_COLUMN_PRIVS : ['INSERT', 'UPDATE', 'REFERENCES'];
    for (const priv of colPrivsToDeny) {
      const wcRes = await pool.query(
        'SELECT pg_catalog.has_any_column_privilege(\'platform_worker\', $1::oid, $2) AS hp',
        [row.table_oid, priv],
      );
      if (wcRes.rows[0].hp) {
        problems.push(`platform_worker must not hold column-level ${priv} on base table ${fq}`);
      }
    }
  }
  for (const priv of workerForbiddenPrivs) {
    const awRes = await pool.query(
      'SELECT pg_catalog.has_table_privilege(\'platform_worker\', \'platform.audit_journal\', $1) AS hp',
      [priv],
    );
    if (awRes.rows[0].hp) {
      problems.push(`platform_worker must not hold ${priv} on platform.audit_journal`);
    }
  }
  const workerPolRes = await pool.query(
    `SELECT schemaname, tablename, policyname, cmd
     FROM pg_catalog.pg_policies
     WHERE schemaname IN ('coherence', 'platform') AND 'platform_worker' = ANY(roles)`,
  );
  for (const wp of workerPolRes.rows) {
    if (wp.cmd !== 'SELECT') {
      problems.push(`RLS policy ${wp.policyname} on ${wp.schemaname}.${wp.tablename} grants platform_worker ${wp.cmd} (must be SELECT only)`);
    }
  }

  const legacyPolRes = await pool.query(
    `SELECT schemaname, tablename, policyname, roles, qual
     FROM pg_catalog.pg_policies
     WHERE schemaname = 'coherence'
       AND (
         roles && $1::name[]
         OR COALESCE(qual, '') ~ 'rls_allowed_entities|rls_actor_npn|rls_access_tier|app\\.allowed_entities|app\\.actor_npn|app\\.access_tier'
       )`,
    [SCOPED_RECIPIENT_ROLES],
  );
  for (const lp of legacyPolRes.rows) {
    problems.push(`Retired Migration 006 policy still active on ${lp.schemaname}.${lp.tablename}: ${lp.policyname}`);
  }
  const legacyFnRes = await pool.query(
    `SELECT p.proname
     FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'coherence' AND p.proname IN ('rls_allowed_entities', 'rls_actor_npn', 'rls_access_tier')`,
  );
  for (const lf of legacyFnRes.rows) {
    problems.push(`Retired Migration 006 helper function still exists: coherence.${lf.proname}`);
  }

  // Audit coherence.backfill_iam_foreign_keys across EVERY platform role + PUBLIC:
  // strictly platform_versioner (owner) and platform_migrator may hold EXECUTE.
  const bfAllowedSet = new Set(BACKFILL_ALLOWED_ROLES);
  const bfFnRes = await pool.query(
    `SELECT p.oid, p.prosecdef, r.rolname AS owner_name, p.proconfig
     FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
     WHERE n.nspname = 'coherence' AND p.proname = 'backfill_iam_foreign_keys'`,
  );
  if (bfFnRes.rows.length !== 1 || !bfFnRes.rows[0].prosecdef || bfFnRes.rows[0].owner_name !== 'platform_versioner') {
    problems.push('coherence.backfill_iam_foreign_keys must be SECURITY DEFINER owned by platform_versioner');
  } else {
    const bfCfg = Array.isArray(bfFnRes.rows[0].proconfig) ? bfFnRes.rows[0].proconfig : [];
    if (!bfCfg.includes('search_path=pg_catalog')) {
      problems.push(`coherence.backfill_iam_foreign_keys must pin SET search_path = pg_catalog (proconfig: ${JSON.stringify(bfCfg)})`);
    }
    const bfOid = bfFnRes.rows[0].oid;
    for (const principal of ['public', ...PLATFORM_ROLES]) {
      const exRes = await pool.query(
        'SELECT pg_catalog.has_function_privilege($1, $2::oid, \'EXECUTE\') AS hp',
        [principal, bfOid],
      );
      if (bfAllowedSet.has(principal)) {
        if (!exRes.rows[0].hp) {
          problems.push(`${principal} is missing EXECUTE on coherence.backfill_iam_foreign_keys`);
        }
      } else if (exRes.rows[0].hp) {
        problems.push(`${principal} holds forbidden EXECUTE privilege on coherence.backfill_iam_foreign_keys`);
      }
    }
  }

  // Internal coherence._resolve_* / coherence._cmd_* helpers and app_views._read_* shared rights checks
  // must pin SET search_path = pg_catalog and be owned/callable strictly by their respective platform roles.
  const internalCohFnRes = await pool.query(
    `SELECT p.oid, n.nspname AS schema_name, p.proname, p.proconfig, p.prosecdef, r.rolname AS owner_name,
            pg_catalog.pg_get_functiondef(p.oid) AS fn_def
     FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
     WHERE (n.nspname = 'coherence' AND (
              p.proname LIKE '\\_resolve\\_%' ESCAPE '\\'
              OR p.proname LIKE '\\_cmd\\_%' ESCAPE '\\'
            ))
        OR (n.nspname = 'app_views' AND p.proname LIKE '\\_read\\_%' ESCAPE '\\')`,
  );
  const resolveFns = internalCohFnRes.rows.filter((f) => f.schema_name === 'coherence' && f.proname.startsWith('_resolve_'));
  const cmdFns = internalCohFnRes.rows.filter((f) => f.schema_name === 'coherence' && f.proname.startsWith('_cmd_'));
  const readFns = internalCohFnRes.rows.filter((f) => f.schema_name === 'app_views' && f.proname.startsWith('_read_'));
  if (resolveFns.length === 0) {
    problems.push('Expected internal coherence._resolve_* helper functions were not found in pg_proc');
  }
  if (cmdFns.length === 0) {
    problems.push('Expected internal coherence._cmd_* helper functions were not found in pg_proc');
  }
  if (readFns.length === 0) {
    problems.push('Expected shared app_views._read_* rights helper functions were not found in pg_proc');
  }
  const readWideOnlyFns = new Set([
    '_read_tenant_right',
    '_read_has_full_tenant_right',
    '_read_bob_wide_orgs',
    '_read_bob_narrow_pairs',
    '_read_agency_statement_wide_orgs',
    '_read_agency_statement_narrow_pairs',
    '_read_statement_cash_wide_orgs',
    '_read_statement_cash_narrow_pairs',
    '_read_unpublished_wide_orgs',
    '_read_unpublished_narrow_pairs',
    '_read_upline_cash_orgs',
    '_read_upline_statement_orgs',
    '_read_ledger_orgs',
    '_read_reconciliation_orgs',
    '_read_has_full_entity_finance',
  ]);
  for (const ifn of internalCohFnRes.rows) {
    const isResolve = ifn.schema_name === 'coherence' && ifn.proname.startsWith('_resolve_');
    const isRead = ifn.schema_name === 'app_views' && ifn.proname.startsWith('_read_');
    const expectedOwner = isResolve ? 'platform_versioner' : (isRead ? 'platform_view_owner' : 'platform_writer');
    const allowedRoles = new Set(
      isResolve
        ? ['platform_versioner', 'platform_writer']
        : (isRead
          ? ['platform_view_owner', 'platform_app', 'platform_readonly']
          : ['platform_writer']),
    );
    const fqFn = `${ifn.schema_name}.${ifn.proname}`;
    const cfg = Array.isArray(ifn.proconfig) ? ifn.proconfig : [];
    if (!cfg.includes('search_path=pg_catalog')) {
      problems.push(`Internal function ${fqFn} must pin SET search_path = pg_catalog (proconfig: ${JSON.stringify(cfg)})`);
    }
    if (ifn.owner_name !== expectedOwner) {
      problems.push(`Internal function ${fqFn} must be owned by ${expectedOwner} (got ${ifn.owner_name})`);
    }
    if (isRead && !ifn.prosecdef) {
      problems.push(`Shared read helper ${fqFn} must be SECURITY DEFINER owned by platform_view_owner`);
    }
    if (isRead && readWideOnlyFns.has(ifn.proname) && forbiddenKeyedAnyRe.test(ifn.fn_def || '')) {
      problems.push(`Wide/scoped read helper ${fqFn} must not use iam.effective_any_org_ids()`);
    }
    for (const principal of ['public', ...PLATFORM_ROLES]) {
      if (allowedRoles.has(principal)) continue;
      const exRes = await pool.query(
        'SELECT pg_catalog.has_function_privilege($1, $2::oid, \'EXECUTE\') AS hp',
        [principal, ifn.oid],
      );
      if (exRes.rows[0].hp) {
        problems.push(`${principal} holds forbidden EXECUTE privilege on internal function ${fqFn}`);
      }
    }
  }

  // Narrow definer helper view coherence.v_run_latest_journal_seq must be owned by platform_readonly,
  // carry security_barrier=true, and grant SELECT strictly to platform_readonly and platform_view_owner.
  const tipViewRes = await pool.query(
    `SELECT c.oid, r.rolname AS owner_name, c.reloptions
     FROM pg_catalog.pg_class c
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
     WHERE n.nspname = 'coherence' AND c.relname = 'v_run_latest_journal_seq' AND c.relkind = 'v'`,
  );
  if (tipViewRes.rows.length !== 1) {
    problems.push('Expected narrow definer helper view coherence.v_run_latest_journal_seq is missing');
  } else {
    const tv = tipViewRes.rows[0];
    const opts = Array.isArray(tv.reloptions) ? tv.reloptions : [];
    if (tv.owner_name !== 'platform_readonly') {
      problems.push(`View coherence.v_run_latest_journal_seq must be owned by platform_readonly (got ${tv.owner_name})`);
    }
    if (!opts.includes('security_barrier=true')) {
      problems.push(`View coherence.v_run_latest_journal_seq must set security_barrier=true (reloptions: ${JSON.stringify(opts)})`);
    }
    if (opts.includes('security_invoker=true')) {
      problems.push('View coherence.v_run_latest_journal_seq must not set security_invoker=true');
    }
    const allowedTipReaders = new Set(['platform_readonly', 'platform_view_owner']);
    for (const principal of ['public', ...PLATFORM_ROLES]) {
      const selRes = await pool.query(
        'SELECT pg_catalog.has_table_privilege($1, $2::oid, \'SELECT\') AS hp',
        [principal, tv.oid],
      );
      if (allowedTipReaders.has(principal)) {
        if (!selRes.rows[0].hp) {
          problems.push(`${principal} is missing SELECT on coherence.v_run_latest_journal_seq`);
        }
      } else if (selRes.rows[0].hp) {
        problems.push(`${principal} holds forbidden SELECT privilege on coherence.v_run_latest_journal_seq`);
      }
    }
  }

  // 5. Verify every iam base table is covered by IAM_IMMUTABLE_TABLES or IAM_VERSIONED_TABLES (disjoint),
  //    all iam tables and platform.audit_journal carry ENABLE ALWAYS immutability triggers, and
  //    all versioned iam tables carry BEFORE INSERT platform_versioner supersession triggers.
  const immutableSet = new Set(IAM_IMMUTABLE_TABLES);
  const versionedSet = new Set(IAM_VERSIONED_TABLES);
  for (const tbl of IAM_IMMUTABLE_TABLES) {
    if (versionedSet.has(tbl)) {
      problems.push(`Table iam.${tbl} appears in both IAM_IMMUTABLE_TABLES and IAM_VERSIONED_TABLES`);
    }
  }
  const actualIamTables = new Set(
    tblRes.rows.filter((r) => r.table_schema === 'iam').map((r) => r.table_name),
  );
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
  const actualPlatformTables = new Set(
    tblRes.rows.filter((r) => r.table_schema === 'platform').map((r) => r.table_name),
  );
  for (const tbl of actualPlatformTables) {
    if (tbl !== 'audit_journal') {
      problems.push(`Unexpected base table platform.${tbl} is not covered by platform immutability checks`);
    }
  }

  const trigRes = await pool.query(
    `SELECT n.nspname AS schema_name,
            c.relname AS table_name,
            t.tgname AS trigger_name,
            t.tgenabled,
            pg_catalog.pg_get_triggerdef(t.oid) AS def
     FROM pg_catalog.pg_trigger t
     JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('iam', 'platform') AND NOT t.tgisinternal`,
  );
  const trigByKey = new Map(trigRes.rows.map((r) => [`${r.schema_name}.${r.table_name}:${r.trigger_name}`, r]));

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

  // Verify stamp_superseded_before_insert is SECURITY DEFINER owned by platform_versioner.
  const supFnRes = await pool.query(
    `SELECT p.prosecdef, r.rolname AS owner_name
     FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
     WHERE n.nspname = 'platform' AND p.proname = 'stamp_superseded_before_insert'`,
  );
  if (supFnRes.rows.length !== 1 || !supFnRes.rows[0].prosecdef || supFnRes.rows[0].owner_name !== 'platform_versioner') {
    problems.push('platform.stamp_superseded_before_insert() must be SECURITY DEFINER owned by platform_versioner');
  }

  // 6. All functions across platform, iam_secret, iam, app_views, app_cmd pin SET search_path = pg_catalog
  //    and revoke EXECUTE from PUBLIC; every app_cmd.* function is SECURITY DEFINER owned by platform_writer;
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
     WHERE n.nspname IN ('platform', 'iam_secret', 'iam', 'coherence', 'coherence_views', 'app_views', 'app_cmd')
     ORDER BY n.nspname, p.proname`,
  );
  const iamScopeFns = fnRes.rows.filter((f) => ['platform', 'iam_secret', 'iam', 'app_views', 'app_cmd'].includes(f.nspname));
  const appCmdFns = fnRes.rows.filter((f) => f.nspname === 'app_cmd');
  if (iamScopeFns.length === 0) {
    problems.push('No functions found in schemas platform / iam_secret / iam / app_cmd');
  }
  const combinedWhitelist = [...PLATFORM_APP_FUNCTION_WHITELIST, ...PLATFORM_APP_CMD_WHITELIST];
  const whitelistSet = new Set(combinedWhitelist);
  const workerOnlySet = new Set(APP_CMD_WORKER_ONLY_FUNCTIONS);
  const workerCmdSet = new Set(PLATFORM_WORKER_CMD_WHITELIST);
  const foundWhitelisted = new Set();
  const foundWorkerOnly = new Set();
  const foundWorkerCmd = new Set();

  for (const fn of fnRes.rows) {
    if (['platform', 'iam_secret', 'iam', 'app_views', 'app_cmd'].includes(fn.nspname)) {
      const cfg = Array.isArray(fn.proconfig) ? fn.proconfig : [];
      if (!cfg.includes('search_path=pg_catalog')) {
        problems.push(`Function ${fn.sig} does not pin SET search_path = pg_catalog (proconfig: ${JSON.stringify(cfg)})`);
      }
      if (fn.pub_exec) {
        problems.push(`PUBLIC has EXECUTE privilege on ${fn.sig}`);
      }
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
    checkedIamTables: IAM_IMMUTABLE_TABLES.length + IAM_VERSIONED_TABLES.length,
    checkedBaseTables: tblRes.rows.length,
    checkedViews: viewRes.rows.length,
    checkedAppViews: appViewsRes.rows.length,
    checkedFunctions: iamScopeFns.length,
    checkedAppCmdFunctions: appCmdFns.length,
    checkedInternalCoherenceFunctions: internalCohFnRes.rows.length,
    problems,
  };
}
