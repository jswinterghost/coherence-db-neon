#!/usr/bin/env node
// Idempotent company database provisioner CLI: verifies target DB/environment/context guards,
// runs migrations 001..012, maps IAM database users to platform_* roles (non-inherited SET-only
// membership for startup '-c role=<role>'), seeds iam.database_context, the canonical IAM catalog,
// platform/company organizations, Nusear staff, the worker service principal, and mode-600 signing
// keys, then verifies verifyIamConfigInvariants live.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseStaffSpec, provisionCompanyDatabase } from '../src/iam/provision.mjs';
import { AppError, redactPhi } from '../src/util/redact.mjs';

function usageText() {
  return [
    'Usage: node scripts/provision-company-db.mjs \\',
    '  --database <db> --company-slug <slug> --keys-dir <dir> \\',
    '  --staff "nusear_owner:<email>:<name>" [--staff "nusear_admin:<email>:<name>"] \\',
    '  [--display-name <name>] \\',
    '  [--app-db-user <iam-user>] [--worker-db-user <iam-user>] [--readonly-db-user <iam-user>] \\',
    '  [--environment dev] [--allow-non-dev] [--support-label "Nusear support"] [--worker-name "Coherence Worker"] \\',
    '  [--pg-mode local|cloudsql] [--socket-path <dir>] [--host <host>] [--port <port>] [--user <user>]',
  ].join('\n');
}

function nextArg(argv, index, flag) {
  if (index + 1 >= argv.length) {
    throw new AppError(`Missing value for ${flag}.\n${usageText()}`, 400, 'MISSING_CLI_ARGS');
  }
  return argv[index + 1];
}

export function parseProvisionCliArgs(argv) {
  const args = {
    companySlug: null,
    displayName: null,
    environment: 'dev',
    allowNonDev: false,
    supportLabel: 'Nusear support',
    validFrom: '2020-01-01',
    keysDir: null,
    workerName: 'Coherence Worker',
    staff: [],
    roleMappings: {},
    pgMode: null,
    socketPath: null,
    host: null,
    port: null,
    database: null,
    user: null,
  };

  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok === '--company-slug') { args.companySlug = nextArg(argv, i++, tok); }
    else if (tok === '--display-name') { args.displayName = nextArg(argv, i++, tok); }
    else if (tok === '--environment') { args.environment = nextArg(argv, i++, tok); }
    else if (tok === '--allow-non-dev') { args.allowNonDev = true; }
    else if (tok === '--support-label') { args.supportLabel = nextArg(argv, i++, tok); }
    else if (tok === '--valid-from') { args.validFrom = nextArg(argv, i++, tok); }
    else if (tok === '--keys-dir') { args.keysDir = nextArg(argv, i++, tok); }
    else if (tok === '--worker-name') { args.workerName = nextArg(argv, i++, tok); }
    else if (tok === '--staff') { args.staff.push(parseStaffSpec(nextArg(argv, i++, tok))); }
    else if (tok === '--app-db-user') { args.roleMappings.app = nextArg(argv, i++, tok); }
    else if (tok === '--worker-db-user') { args.roleMappings.worker = nextArg(argv, i++, tok); }
    else if (tok === '--readonly-db-user') { args.roleMappings.readonly = nextArg(argv, i++, tok); }
    else if (tok === '--pg-mode') { args.pgMode = nextArg(argv, i++, tok); }
    else if (tok === '--socket-path') { args.socketPath = nextArg(argv, i++, tok); }
    else if (tok === '--host') { args.host = nextArg(argv, i++, tok); }
    else if (tok === '--port') { args.port = Number(nextArg(argv, i++, tok)); }
    else if (tok === '--database') { args.database = nextArg(argv, i++, tok); }
    else if (tok === '--user') { args.user = nextArg(argv, i++, tok); }
    else {
      throw new AppError(`Unknown argument: ${tok}\n${usageText()}`, 400, 'INVALID_CLI_ARGS');
    }
  }

  if (!args.database || !args.database.trim() || !args.companySlug || !args.keysDir || args.staff.length === 0) {
    throw new AppError(usageText(), 400, 'MISSING_CLI_ARGS');
  }
  const mode = args.pgMode || (args.socketPath ? 'cloudsql' : (process.env.COHERENCE_PG_MODE || 'local'));
  const pgConfig = {
    mode,
    database: args.database.trim(),
    ...(args.socketPath ? { socketPath: args.socketPath } : {}),
    ...(args.host ? { host: args.host } : {}),
    ...(args.port !== null ? { port: args.port } : {}),
    ...(args.user ? { user: args.user } : {}),
    applicationName: 'coherence-provision',
  };

  return {
    pgConfig,
    companySlug: args.companySlug,
    displayName: args.displayName,
    environment: args.environment,
    allowNonDev: args.allowNonDev,
    supportLabel: args.supportLabel,
    validFrom: args.validFrom,
    keysDir: args.keysDir,
    workerName: args.workerName,
    staff: args.staff,
    roleMappings: args.roleMappings,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const opts = parseProvisionCliArgs(process.argv.slice(2));
    const summary = await provisionCompanyDatabase(opts);
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  } catch (err) {
    const code = err?.code ? `${err.code}: ` : '';
    process.stderr.write(`${redactPhi(`${code}${err?.message || String(err)}`)}\n`);
    process.exitCode = 1;
  }
}
