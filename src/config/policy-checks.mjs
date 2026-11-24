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
  'role_grant_people',
  'role_grant_connections',
]);

export const IAM_VERSIONED_TABLES = Object.freeze([
  'organization_versions',
  'organization_edges',
  'person_versions',
  'person_contacts',
  'person_external_identities',
  'organization_memberships',
  'agent_affiliations',
  'supervision_links',
  'role_versions',
  'role_rights',
  'role_grantable_roles',
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
  'iam.effective_all_connection_org_ids(text, date)',
  'iam.effective_explicit_connection_pairs(text, date)',
  'iam.effective_explicit_connection_ids(text, date)',
  'iam.can_access_connection(text, uuid, uuid, date)',
  'iam.assert_can_write(text, uuid, uuid, text, uuid, date)',
]);

export const PLATFORM_ROLES = Object.freeze([
  'platform_view_owner',
  'platform_writer',
  'platform_versioner',
  'platform_mask_reader',
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

  for (const rlsTbl of RLS_PROTECTED_TABLES) {
    const rlsRes = await pool.query(
      `SELECT c.relrowsecurity, c.relforcerowsecurity
       FROM pg_catalog.pg_class c
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'coherence' AND c.relname = $1`,
      [rlsTbl],
    );
    if (rlsRes.rows.length === 0 || !rlsRes.rows[0].relrowsecurity || !rlsRes.rows[0].relforcerowsecurity) {
      problems.push(`Table coherence.${rlsTbl} must have ENABLE + FORCE ROW LEVEL SECURITY`);
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

  // 2. PUBLIC must have zero privileges on schemas platform, iam_secret, iam.
  for (const schema of ['platform', 'iam_secret', 'iam']) {
    const res = await pool.query(
      `SELECT pg_catalog.has_schema_privilege('public', $1, 'USAGE') AS u,
              pg_catalog.has_schema_privilege('public', $1, 'CREATE') AS c`,
      [schema],
    );
    if (res.rows[0].u || res.rows[0].c) {
      problems.push(`PUBLIC must have zero privileges on schema ${schema}`);
    }
  }

  // 3. platform_app and PUBLIC must have ZERO privileges on EVERY base table in iam, iam_secret, platform.
  const tblRes = await pool.query(
    `SELECT n.nspname AS table_schema,
            c.relname AS table_name,
            c.oid AS table_oid
     FROM pg_catalog.pg_class c
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('iam', 'iam_secret', 'platform')
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

  // 4. platform_app must have zero USAGE on iam_secret/platform, zero CREATE on iam/iam_secret/platform,
  //    and both platform_app and PUBLIC must have ZERO privileges on EVERY view (or materialized view)
  //    discovered from pg_class across iam, iam_secret, and platform.
  for (const schema of ['iam', 'iam_secret', 'platform']) {
    const sRes = await pool.query(
      `SELECT pg_catalog.has_schema_privilege('platform_app', $1, 'USAGE') AS u,
              pg_catalog.has_schema_privilege('platform_app', $1, 'CREATE') AS c`,
      [schema],
    );
    if (schema !== 'iam' && sRes.rows[0].u) {
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
     WHERE n.nspname IN ('iam', 'iam_secret', 'platform')
       AND c.relkind IN ('v', 'm')
     ORDER BY n.nspname, c.relname`,
  );
  if (viewRes.rows.length === 0) {
    problems.push('No views found in schemas iam / iam_secret / platform');
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

  // 6. All functions in platform, iam_secret, iam pin SET search_path = pg_catalog and revoke EXECUTE from PUBLIC;
  //    platform_app holds EXECUTE strictly on PLATFORM_APP_FUNCTION_WHITELIST and nothing else.
  const fnRes = await pool.query(
    `SELECT p.oid,
            n.nspname,
            p.proname,
            pg_catalog.format('%I.%I(%s)', n.nspname, p.proname, pg_catalog.oidvectortypes(p.proargtypes)) AS sig,
            p.proconfig,
            pg_catalog.has_function_privilege('public', p.oid, 'EXECUTE') AS pub_exec,
            pg_catalog.has_function_privilege('platform_app', p.oid, 'EXECUTE') AS app_exec
     FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('platform', 'iam_secret', 'iam', 'coherence', 'coherence_views')
     ORDER BY n.nspname, p.proname`,
  );
  const iamScopeFns = fnRes.rows.filter((f) => f.nspname === 'platform' || f.nspname === 'iam_secret' || f.nspname === 'iam');
  if (iamScopeFns.length === 0) {
    problems.push('No functions found in schemas platform / iam_secret / iam');
  }
  const whitelistSet = new Set(PLATFORM_APP_FUNCTION_WHITELIST);
  const foundWhitelisted = new Set();
  for (const fn of fnRes.rows) {
    if (fn.nspname === 'platform' || fn.nspname === 'iam_secret' || fn.nspname === 'iam') {
      const cfg = Array.isArray(fn.proconfig) ? fn.proconfig : [];
      if (!cfg.includes('search_path=pg_catalog')) {
        problems.push(`Function ${fn.sig} does not pin SET search_path = pg_catalog (proconfig: ${JSON.stringify(cfg)})`);
      }
      if (fn.pub_exec) {
        problems.push(`PUBLIC has EXECUTE privilege on ${fn.sig}`);
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
  for (const expectedSig of PLATFORM_APP_FUNCTION_WHITELIST) {
    if (!foundWhitelisted.has(expectedSig)) {
      problems.push(`Whitelisted platform_app function ${expectedSig} was not found in pg_proc`);
    }
  }

  return {
    passed: problems.length === 0,
    checkedIamTables: IAM_IMMUTABLE_TABLES.length + IAM_VERSIONED_TABLES.length,
    checkedBaseTables: tblRes.rows.length,
    checkedViews: viewRes.rows.length,
    checkedFunctions: iamScopeFns.length,
    problems,
  };
}
