// Configuration assertion checks (R3.1, R9.1, R11 audits, R14.4):
// - PostgreSQL roles & least-privilege grants
// - Every append-only trigger present and ENABLE ALWAYS
// - Fixed search_path = pg_catalog on every function in schema coherence
// - Local pg_hba.conf has zero `trust` (or legacy cleartext/md5) lines
// - Cloud SQL instance configuration matches R3.1 / R14.4 security checklist
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const DEFAULT_CLOUDSQL_CONFIG_PATH = resolve(REPO_ROOT, 'config', 'cloudsql-instance.json');
export const DEFAULT_LOCAL_PG_HBA_PATH = '/opt/homebrew/var/postgresql@17/pg_hba.conf';

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
  'runs',
  'step_requests',
  'cancel_requests',
  'step_attempt_events',
  'artifacts',
  'review_saves',
  'emit_confirmations',
  'carries',
  'abandonments',
  'imported_files',
  'checks',
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

export async function verifyPgHbaFile(filePath = process.env.COHERENCE_PG_HBA_PATH || DEFAULT_LOCAL_PG_HBA_PATH) {
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
    problems.push(`databaseVersion must be POSTGRES_17 (R3.1), got ${config.databaseVersion}`);
  }
  const ip = config.ipConfiguration || {};
  if (ip.requireSsl !== true) {
    problems.push('ipConfiguration.requireSsl must be true (R14.4: TLS required)');
  }
  if (ip.sslMode !== 'ENCRYPTED_ONLY') {
    problems.push(`ipConfiguration.sslMode must be ENCRYPTED_ONLY (R14.4), got ${ip.sslMode}`);
  }
  if (!Array.isArray(ip.authorizedNetworks) || ip.authorizedNetworks.length !== 0) {
    problems.push('ipConfiguration.authorizedNetworks must be empty (R14.4: no direct authorized networks)');
  }
  if (ip.ipv4Enabled !== false) {
    problems.push('ipConfiguration.ipv4Enabled must be false (no direct public TCP connections)');
  }

  const proto = config.connectionProtocol || {};
  if (proto.connector !== 'cloud-sql-connector') {
    problems.push(`connectionProtocol.connector must be cloud-sql-connector (R14.4), got ${proto.connector}`);
  }
  if (proto.dedicatedServiceAccount !== true) {
    problems.push('connectionProtocol.dedicatedServiceAccount must be true (R14.4)');
  }
  if (proto.passwordAuthAllowed !== false) {
    problems.push('connectionProtocol.passwordAuthAllowed must be false (R14.4: IAM auth, no passwords)');
  }

  const flags = config.databaseFlags || {};
  if (flags['cloudsql.iam_authentication'] !== 'on') {
    problems.push('databaseFlags["cloudsql.iam_authentication"] must be "on" (R14.4)');
  }
  if (flags['cloudsql.enable_pgaudit'] !== 'on') {
    problems.push('databaseFlags["cloudsql.enable_pgaudit"] must be "on" (R14.4)');
  }
  if (flags['pgaudit.log_parameter'] !== 'off') {
    problems.push('databaseFlags["pgaudit.log_parameter"] must be "off" so SQL parameter values/PHI are never logged (R14.3, R14.4)');
  }
  if (flags['log_connections'] !== 'on') {
    problems.push('databaseFlags["log_connections"] must be "on" (R14.4)');
  }
  if (flags['log_disconnections'] !== 'on') {
    problems.push('databaseFlags["log_disconnections"] must be "on" (R14.4)');
  }
  if (flags['log_parameter_max_length'] !== '0') {
    problems.push('databaseFlags["log_parameter_max_length"] must be "0" so bind values never appear in logs (R14.3, R14.4)');
  }
  if (flags['log_parameter_max_length_on_error'] !== '0') {
    problems.push('databaseFlags["log_parameter_max_length_on_error"] must be "0" so bind values never appear in error logs (R14.3, R14.4)');
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

/**
 * Verifies live PostgreSQL 17 configuration invariants on a migrated database:
 * 1. Roles & grants (least privilege: coherence_app/worker only SELECT+INSERT on business tables; PUBLIC none).
 * 2. Append-only triggers present and ENABLE ALWAYS (tgenabled = 'A') on all 20 business tables.
 * 3. Every function in schema `coherence` pins `SET search_path = pg_catalog`.
 */
export async function verifyDatabaseConfigInvariants(pool) {
  const problems = [];

  // 1. Roles & grants on all 20 business tables
  for (const tbl of ALL_BUSINESS_TABLES) {
    const fq = `coherence.${tbl}`;

    // coherence_app: SELECT & INSERT only
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

    // coherence_worker: SELECT & INSERT only on business tables
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

    // coherence_readonly: SELECT only
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

    // PUBLIC: ZERO privileges on business tables
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

  // Operational table privileges: coherence_app cannot UPDATE/DELETE/TRUNCATE review_submissions
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

  // PUBLIC must have zero privileges on schema coherence
  const schemaPub = await pool.query(
    `SELECT pg_catalog.has_schema_privilege('public', 'coherence', 'USAGE') AS usage,
            pg_catalog.has_schema_privilege('public', 'coherence', 'CREATE') AS create`,
  );
  if (schemaPub.rows[0].usage || schemaPub.rows[0].create) {
    problems.push('PUBLIC must have zero privileges on schema coherence');
  }

  // 2. Append-only triggers present and ENABLE ALWAYS (tgenabled = 'A') on all 20 business tables
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

  // 3. Fixed search_path = pg_catalog on EVERY function in schema coherence
  const fnRes = await pool.query(
    `SELECT p.oid, p.proname, p.proconfig, pg_catalog.has_function_privilege('public', p.oid, 'EXECUTE') AS pub_exec
     FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'coherence'
     ORDER BY p.proname`,
  );
  if (fnRes.rows.length === 0) {
    problems.push('No functions found in schema coherence');
  }
  for (const fn of fnRes.rows) {
    const cfg = Array.isArray(fn.proconfig) ? fn.proconfig : [];
    if (!cfg.includes('search_path=pg_catalog')) {
      problems.push(`Function coherence.${fn.proname} does not pin SET search_path = pg_catalog (proconfig: ${JSON.stringify(cfg)})`);
    }
    if (fn.pub_exec) {
      problems.push(`PUBLIC has EXECUTE privilege on coherence.${fn.proname}`);
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
