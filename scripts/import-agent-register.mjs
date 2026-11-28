#!/usr/bin/env node
// Idempotent Agent Register importer CLI into an already-provisioned company database.
// Enforces P1 target-database, environment (dev unless --allow-non-dev), and Cloud SQL Auth Proxy
// connection guards, writes strictly through app_cmd.iam_* commands with short-lived renewing
// nusear_staff tokens from a mode-600 key file, and supports --plan to validate and list what
// would be created without touching any database.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertDatabaseNameAllowed,
  assertNonProdEndpoint,
  isLocalTargetConfig,
} from '../src/iam/provision-guards.mjs';
import { buildProvisionedPoolConfig, withAppAndReadPools } from '../src/iam/provisioned-runtime.mjs';
import { importAgentRegisterIntoDatabase } from '../src/iam/register-import.mjs';
import { planAgentRegisterFile, RegisterValidationError } from '../src/iam/register-plan.mjs';
import { AppError, redactPhi } from '../src/util/redact.mjs';

function usageText() {
  return [
    'Usage: node scripts/import-agent-register.mjs \\',
    '  --register <approved-version.json> --database <db> --key-file <mode-600-key.json> \\',
    '  (--actor-email <staff-email> | --actor-person-id <uuid>) \\',
    '  [--company-slug <slug>] [--company-name <name>] [--vendor-mask "<Vendor>=<Masked Name>"] \\',
    '  [--environment dev] [--allow-non-dev] [--default-valid-from YYYY-MM-DD] \\',
    '  [--pg-mode local|cloudsql] \\',
    '  [--socket-path <dir>] [--app-socket-path <dir>] [--readonly-socket-path <dir>] \\',
    '  [--host <host>] [--app-host <host>] [--readonly-host <host>] \\',
    '  [--port <port>] [--app-port <port>] [--readonly-port <port>] \\',
    '  [--user <user>] [--app-user <iam-user>] [--readonly-user <iam-user>] \\',
    '  [--app-role platform_app] [--readonly-role platform_readonly]',
    '  | node scripts/import-agent-register.mjs --register <approved-version.json> --plan \\',
    '    [--company-slug <slug>] [--company-name <name>] [--vendor-mask "<Vendor>=<Masked Name>"]',
  ].join('\n');
}

function nextArg(argv, index, flag) {
  if (index + 1 >= argv.length) {
    throw new AppError(`Missing value for ${flag}.\n${usageText()}`, 400, 'MISSING_CLI_ARGS');
  }
  return argv[index + 1];
}

function parseVendorMaskFlag(raw) {
  const eq = String(raw || '').indexOf('=');
  if (eq <= 0 || eq === raw.length - 1) {
    throw new AppError(
      `Invalid --vendor-mask "${String(raw || '')}"; expected "<VendorName>=<MaskedDisplayName>".`,
      400,
      'INVALID_VENDOR_MASK',
    );
  }
  const vendor = raw.slice(0, eq).trim();
  const masked = raw.slice(eq + 1).trim();
  if (!vendor || !masked) {
    throw new AppError(
      `Invalid --vendor-mask "${String(raw || '')}"; both vendor name and masked display name must be non-empty.`,
      400,
      'INVALID_VENDOR_MASK',
    );
  }
  return [vendor, masked];
}

export function parseRegisterImportCliArgs(argv) {
  const args = {
    registerPath: null,
    plan: false,
    companySlug: null,
    companyDisplayName: null,
    vendorMasks: new Map(),
    environment: null,
    allowNonDev: false,
    defaultValidFrom: '2020-01-01',
    keyFile: null,
    actorEmail: null,
    actorPersonId: null,
    pgMode: null,
    database: null,
    socketPath: null,
    appSocketPath: null,
    readonlySocketPath: null,
    host: null,
    appHost: null,
    readonlyHost: null,
    port: null,
    appPort: null,
    readonlyPort: null,
    user: null,
    appUser: null,
    readonlyUser: null,
    appRole: null,
    readonlyRole: null,
  };
  const seenVendorMaskKeys = new Set();

  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok === '--register') { args.registerPath = nextArg(argv, i++, tok); }
    else if (tok === '--plan') { args.plan = true; }
    else if (tok === '--company-slug') { args.companySlug = nextArg(argv, i++, tok); }
    else if (tok === '--company-name') { args.companyDisplayName = nextArg(argv, i++, tok); }
    else if (tok === '--vendor-mask') {
      const [vendor, masked] = parseVendorMaskFlag(nextArg(argv, i++, tok));
      const keyLower = vendor.toLowerCase();
      if (seenVendorMaskKeys.has(keyLower)) {
        throw new AppError(`Duplicate --vendor-mask for "${vendor}".`, 400, 'DUPLICATE_VENDOR_MASK');
      }
      seenVendorMaskKeys.add(keyLower);
      args.vendorMasks.set(vendor, masked);
    }
    else if (tok === '--environment') { args.environment = nextArg(argv, i++, tok); }
    else if (tok === '--allow-non-dev') { args.allowNonDev = true; }
    else if (tok === '--default-valid-from') { args.defaultValidFrom = nextArg(argv, i++, tok); }
    else if (tok === '--key-file') { args.keyFile = nextArg(argv, i++, tok); }
    else if (tok === '--actor-email') { args.actorEmail = nextArg(argv, i++, tok); }
    else if (tok === '--actor-person-id') { args.actorPersonId = nextArg(argv, i++, tok); }
    else if (tok === '--pg-mode') { args.pgMode = nextArg(argv, i++, tok); }
    else if (tok === '--database') { args.database = nextArg(argv, i++, tok); }
    else if (tok === '--socket-path') { args.socketPath = nextArg(argv, i++, tok); }
    else if (tok === '--app-socket-path') { args.appSocketPath = nextArg(argv, i++, tok); }
    else if (tok === '--readonly-socket-path') { args.readonlySocketPath = nextArg(argv, i++, tok); }
    else if (tok === '--host') { args.host = nextArg(argv, i++, tok); }
    else if (tok === '--app-host') { args.appHost = nextArg(argv, i++, tok); }
    else if (tok === '--readonly-host') { args.readonlyHost = nextArg(argv, i++, tok); }
    else if (tok === '--port') { args.port = Number(nextArg(argv, i++, tok)); }
    else if (tok === '--app-port') { args.appPort = Number(nextArg(argv, i++, tok)); }
    else if (tok === '--readonly-port') { args.readonlyPort = Number(nextArg(argv, i++, tok)); }
    else if (tok === '--user') { args.user = nextArg(argv, i++, tok); }
    else if (tok === '--app-user') { args.appUser = nextArg(argv, i++, tok); }
    else if (tok === '--readonly-user') { args.readonlyUser = nextArg(argv, i++, tok); }
    else if (tok === '--app-role') { args.appRole = nextArg(argv, i++, tok); }
    else if (tok === '--readonly-role') { args.readonlyRole = nextArg(argv, i++, tok); }
    else {
      throw new AppError(`Unknown argument: ${tok}\n${usageText()}`, 400, 'INVALID_CLI_ARGS');
    }
  }

  if (args.plan) {
    if (!args.registerPath) {
      throw new AppError(usageText(), 400, 'MISSING_CLI_ARGS');
    }
    return args;
  }

  if (
    !args.registerPath
    || !args.database
    || !args.database.trim()
    || !args.keyFile
    || (!args.actorEmail && !args.actorPersonId)
  ) {
    throw new AppError(usageText(), 400, 'MISSING_CLI_ARGS');
  }
  args.database = args.database.trim();
  return args;
}

export function buildRegisterImportPoolConfig(args, kind) {
  return buildProvisionedPoolConfig(args, kind, { applicationPrefix: 'coherence-register-import' });
}

export async function runAgentRegisterImportCli(args, { createPoolFn = undefined } = {}) {
  if (args.plan) {
    return planAgentRegisterFile(resolve(args.registerPath), {
      companySlug: args.companySlug,
      companyDisplayName: args.companyDisplayName,
      vendorMasks: args.vendorMasks,
      defaultValidFrom: args.defaultValidFrom,
    });
  }

  const appPoolConfig = buildRegisterImportPoolConfig(args, 'app');
  const readPoolConfig = buildRegisterImportPoolConfig(args, 'readonly');
  const allowScratchDatabase = isLocalTargetConfig(appPoolConfig) && isLocalTargetConfig(readPoolConfig);

  // Enforce P1 target-database and environment guards BEFORE opening any connection pool.
  assertDatabaseNameAllowed(args.database, {
    companySlug: args.companySlug,
    allowScratch: allowScratchDatabase,
  });
  if (args.environment || !args.allowNonDev) {
    const guardEnv = args.environment || 'dev';
    assertNonProdEndpoint({ pgConfig: appPoolConfig, environment: guardEnv, allowNonDev: args.allowNonDev });
    assertNonProdEndpoint({ pgConfig: readPoolConfig, environment: guardEnv, allowNonDev: args.allowNonDev });
  }

  return withAppAndReadPools(
    appPoolConfig,
    readPoolConfig,
    ({ appPool, readPool }) => importAgentRegisterIntoDatabase({
      readPool,
      appPool,
      registerPath: resolve(args.registerPath),
      companySlug: args.companySlug,
      companyDisplayName: args.companyDisplayName,
      vendorMasks: args.vendorMasks,
      defaultValidFrom: args.defaultValidFrom,
      keyFile: args.keyFile,
      actorEmail: args.actorEmail,
      actorPersonId: args.actorPersonId,
      expectedEnvironment: args.environment,
      allowNonDev: Boolean(args.allowNonDev),
      allowScratchDatabase,
      appPoolConfig,
      readPoolConfig,
    }),
    createPoolFn ? { createPoolFn } : {},
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const cli = parseRegisterImportCliArgs(process.argv.slice(2));
    const result = await runAgentRegisterImportCli(cli);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (err) {
    const payload = {
      ok: false,
      code: err?.code || 'ERROR',
      error: redactPhi(err?.message || 'Agent Register import failed.'),
      ...(err instanceof RegisterValidationError && Array.isArray(err.issues) ? { issues: err.issues } : {}),
    };
    process.stderr.write(`${JSON.stringify(payload, null, 2)}\n`);
    process.exitCode = 1;
  }
}
