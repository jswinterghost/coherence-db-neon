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

const FORBIDDEN_BUSINESS_PRIVS = Object.freeze(['UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']);

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
