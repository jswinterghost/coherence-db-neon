#!/usr/bin/env node
// Production/dev read-only history importer into an already-provisioned company database.
// Reuses executeHistoryImport and the Layer 0 / Layer 1 / Layer 2 / Comparator checks while
// authenticating writes strictly through app_cmd.* as platform_app with short-lived renewing
// nusear_staff tokens from a mode-600 key file, and reads strictly as platform_readonly.
// Never writes to any configured source folder.
import { mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPool } from '../src/db/pg-client.mjs';
import {
  assertDatabaseNameAllowed,
  assertNonProdEndpoint,
  isLocalTargetConfig,
} from '../src/iam/provision-guards.mjs';
import { planImportManifestFile } from '../src/importer/history-importer.mjs';
import { importHistoryIntoDatabase } from '../src/importer/provisioned-import.mjs';
import {
  assertDistinctCodeAndDataStores,
  assertSafeStoresDir,
  assertSafeStoreTargets,
} from '../src/importer/store-path-safety.mjs';
import { createFileObjectStore } from '../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../src/storage/stores.mjs';
import { AppError, redactPhi } from '../src/util/redact.mjs';

function usageText() {
  return [
    'Usage: node scripts/import-history.mjs \\',
    '  --manifest <file> --database <db> --stores-dir <dir> --key-file <mode-600-key.json> \\',
    '  (--actor-email <owner-email> | --actor-person-id <uuid>) \\',
    '  [--pg-mode local|cloudsql] [--allow-non-dev] \\',
    '  [--socket-path <dir>] [--app-socket-path <dir>] [--readonly-socket-path <dir>] \\',
    '  [--host <host>] [--app-host <host>] [--readonly-host <host>] \\',
    '  [--port <port>] [--app-port <port>] [--readonly-port <port>] \\',
    '  [--user <user>] [--app-user <iam-user>] [--readonly-user <iam-user>] \\',
    '  [--app-role platform_app] [--readonly-role platform_readonly] \\',
    '  [--code-store-dir <dir> --data-store-dir <dir>] [--skip-idempotency]',
    '  | node scripts/import-history.mjs --manifest <file> --plan',
  ].join('\n');
}

function nextArg(argv, index, flag) {
  if (index + 1 >= argv.length) {
    throw new AppError(`Missing value for ${flag}.\n${usageText()}`, 400, 'MISSING_CLI_ARGS');
  }
  return argv[index + 1];
}

export function parseImportCliArgs(argv) {
  const args = {
    manifestPath: null,
    plan: false,
    storesDir: null,
    codeStoreDir: null,
    dataStoreDir: null,
    keyFile: null,
    actorEmail: null,
    actorPersonId: null,
    allowNonDev: false,
    skipIdempotency: false,
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

  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok === '--manifest') { args.manifestPath = nextArg(argv, i++, tok); }
    else if (tok === '--plan') { args.plan = true; }
    else if (tok === '--stores-dir') { args.storesDir = nextArg(argv, i++, tok); }
    else if (tok === '--code-store-dir') { args.codeStoreDir = nextArg(argv, i++, tok); }
    else if (tok === '--data-store-dir') { args.dataStoreDir = nextArg(argv, i++, tok); }
    else if (tok === '--key-file') { args.keyFile = nextArg(argv, i++, tok); }
    else if (tok === '--actor-email') { args.actorEmail = nextArg(argv, i++, tok); }
    else if (tok === '--actor-person-id') { args.actorPersonId = nextArg(argv, i++, tok); }
    else if (tok === '--allow-non-dev') { args.allowNonDev = true; }
    else if (tok === '--skip-idempotency') { args.skipIdempotency = true; }
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
    if (!args.manifestPath) throw new AppError(usageText(), 400, 'MISSING_CLI_ARGS');
    return args;
  }

  const hasSplitStores = Boolean(args.codeStoreDir || args.dataStoreDir);
  if (hasSplitStores && (!args.codeStoreDir || !args.dataStoreDir)) {
    throw new AppError('Both --code-store-dir and --data-store-dir must be provided together.', 400, 'MISSING_CLI_ARGS');
  }
  if (
    !args.manifestPath
    || !args.database
    || !args.database.trim()
    || (!args.storesDir && !hasSplitStores)
    || !args.keyFile
    || (!args.actorEmail && !args.actorPersonId)
  ) {
    throw new AppError(usageText(), 400, 'MISSING_CLI_ARGS');
  }
  args.database = args.database.trim();
  return args;
}

export function buildImportPoolConfig(args, kind) {
  const socketPath = kind === 'app'
    ? (args.appSocketPath || args.socketPath)
    : (args.readonlySocketPath || args.socketPath);
  const host = kind === 'app' ? (args.appHost || args.host) : (args.readonlyHost || args.host);
  const port = kind === 'app' ? (args.appPort ?? args.port) : (args.readonlyPort ?? args.port);
  const explicitUser = kind === 'app' ? args.appUser : args.readonlyUser;
  const user = explicitUser || args.user;
  const explicitRole = kind === 'app' ? args.appRole : args.readonlyRole;
  const mode = args.pgMode || (socketPath ? 'cloudsql' : (process.env.COHERENCE_PG_MODE || 'local'));
  const defaultRole = kind === 'app' ? 'platform_app' : 'platform_readonly';
  const role = explicitRole || ((explicitUser || mode === 'cloudsql') ? defaultRole : null);
  return {
    mode,
    database: args.database,
    ...(socketPath ? { socketPath } : {}),
    ...(host ? { host } : {}),
    ...(port !== null && port !== undefined ? { port } : {}),
    ...(user ? { user } : {}),
    ...(role ? { role } : {}),
    applicationName: `coherence-import-${kind}`,
  };
}

export async function runHistoryImportCli(args) {
  if (args.plan) {
    return planImportManifestFile(args.manifestPath);
  }

  const appPoolConfig = buildImportPoolConfig(args, 'app');
  const readPoolConfig = buildImportPoolConfig(args, 'readonly');

  // Validate database name and non-production endpoints before creating any store directory or pool.
  assertDatabaseNameAllowed(args.database);
  if (!args.allowNonDev) {
    assertNonProdEndpoint({ pgConfig: appPoolConfig, environment: 'dev', allowNonDev: false });
    assertNonProdEndpoint({ pgConfig: readPoolConfig, environment: 'dev', allowNonDev: false });
  }

  let codeRoot;
  let dataRoot;
  if (args.codeStoreDir && args.dataStoreDir) {
    codeRoot = resolve(args.codeStoreDir);
    dataRoot = resolve(args.dataStoreDir);
    await assertDistinctCodeAndDataStores(codeRoot, dataRoot);
    await assertSafeStoreTargets([
      { label: '--code-store-dir', path: codeRoot, checkContainsProtected: true },
      { label: '--data-store-dir', path: dataRoot, checkContainsProtected: true },
    ], args.manifestPath);
  } else {
    const resolvedStores = resolve(args.storesDir);
    await assertSafeStoresDir(resolvedStores, args.manifestPath);
    codeRoot = join(resolvedStores, 'code');
    dataRoot = join(resolvedStores, 'data');
    await assertDistinctCodeAndDataStores(codeRoot, dataRoot);
  }

  await mkdir(codeRoot, { recursive: true, mode: 0o700 });
  await mkdir(dataRoot, { recursive: true, mode: 0o700 });

  const codeStore = createCodeStore({ backend: createFileObjectStore({ rootDir: codeRoot, label: `import-code:${codeRoot}` }) });
  const dataStore = createDataStore({ backend: createFileObjectStore({ rootDir: dataRoot, label: `import-data:${dataRoot}` }) });
  const stores = createStorePair({ codeStore, dataStore });

  const allowScratchDatabase = isLocalTargetConfig(appPoolConfig) && isLocalTargetConfig(readPoolConfig);
  const appPool = await createPool(appPoolConfig);
  const readPool = await createPool(readPoolConfig);
  try {
    return await importHistoryIntoDatabase({
      readPool,
      appPool,
      stores,
      manifestPath: args.manifestPath,
      keyFile: args.keyFile,
      actorEmail: args.actorEmail,
      actorPersonId: args.actorPersonId,
      allowNonDev: Boolean(args.allowNonDev),
      allowScratchDatabase,
      appPoolConfig,
      readPoolConfig,
      skipIdempotency: args.skipIdempotency,
    });
  } finally {
    await Promise.all([
      appPool.end().catch(() => {}),
      readPool.end().catch(() => {}),
    ]);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const cli = parseImportCliArgs(process.argv.slice(2));
    const summary = await runHistoryImportCli(cli);
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    if (!cli.plan && !summary.passed) {
      process.exitCode = 1;
    }
  } catch (err) {
    process.stderr.write(`${JSON.stringify({
      passed: false,
      error: redactPhi(err?.message || 'History import failed.'),
      code: err?.code || 'ERROR',
    })}\n`);
    process.exitCode = 1;
  }
}
