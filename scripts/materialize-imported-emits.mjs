#!/usr/bin/env node
// Idempotent worker CLI that materializes every unmaterialized imported run's finished Emit
// outputs from the separated code and data stores into an already-provisioned company database.
// Reads strictly as platform_readonly and writes strictly as platform_worker using a renewing
// service token minted from the worker's mode-600 key file (<company>-<env>-service.key.json).
import { stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertDatabaseNameAllowed,
  assertNonProdEndpoint,
  isLocalTargetConfig,
} from '../src/iam/provision-guards.mjs';
import {
  buildProvisionedPoolConfig,
  withReadPool,
  withWorkerAndReadPools,
} from '../src/iam/provisioned-runtime.mjs';
import {
  materializeImportedEmitsInDatabase,
  planImportedEmitMaterializations,
} from '../src/importer/materialize-imported-emits.mjs';
import { assertDistinctCodeAndDataStores } from '../src/importer/store-path-safety.mjs';
import { createFileObjectStore } from '../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../src/storage/stores.mjs';
import { AppError, redactPhi } from '../src/util/redact.mjs';

function usageText() {
  return [
    'Usage: node scripts/materialize-imported-emits.mjs \\',
    '  --database <db> (--stores-dir <dir> | --code-store-dir <dir> --data-store-dir <dir>) \\',
    '  --key-file <mode-600-service-key.json> \\',
    '  [--company-slug <slug>] [--environment dev] [--allow-non-dev] \\',
    '  [--worker-person-id <uuid> | --worker-name <name>] \\',
    '  [--pg-mode local|cloudsql] \\',
    '  [--socket-path <dir>] [--worker-socket-path <dir>] [--readonly-socket-path <dir>] \\',
    '  [--host <host>] [--worker-host <host>] [--readonly-host <host>] \\',
    '  [--port <port>] [--worker-port <port>] [--readonly-port <port>] \\',
    '  [--user <user>] [--worker-user <iam-user>] [--readonly-user <iam-user>] \\',
    '  [--worker-role platform_worker] [--readonly-role platform_readonly]',
    '  | node scripts/materialize-imported-emits.mjs --database <db> --plan \\',
    '    [--company-slug <slug>] [--environment dev] [--allow-non-dev] \\',
    '    [--pg-mode local|cloudsql] [--socket-path <dir>] [--readonly-socket-path <dir>] \\',
    '    [--host <host>] [--readonly-host <host>] [--port <port>] [--readonly-port <port>] \\',
    '    [--user <user>] [--readonly-user <iam-user>] [--readonly-role platform_readonly]',
  ].join('\n');
}

function nextArg(argv, index, flag) {
  if (index + 1 >= argv.length) {
    throw new AppError(`Missing value for ${flag}.\n${usageText()}`, 400, 'MISSING_CLI_ARGS');
  }
  return argv[index + 1];
}

function parsePortArg(raw, flag) {
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new AppError(`Invalid port for ${flag}: ${raw}`, 400, 'INVALID_CLI_ARGS');
  }
  return port;
}

async function assertExistingStoreDir(dirPath, label) {
  const info = await stat(dirPath).catch(() => null);
  if (!info || !info.isDirectory()) {
    throw new AppError(`Store directory (${label}) does not exist: ${dirPath}`, 400, 'MISSING_STORE_DIR');
  }
}

export function parseMaterializeCliArgs(argv) {
  const args = {
    plan: false,
    database: null,
    companySlug: null,
    environment: null,
    allowNonDev: false,
    storesDir: null,
    codeStoreDir: null,
    dataStoreDir: null,
    keyFile: null,
    workerPersonId: null,
    workerName: null,
    pgMode: null,
    socketPath: null,
    workerSocketPath: null,
    readonlySocketPath: null,
    host: null,
    workerHost: null,
    readonlyHost: null,
    port: null,
    workerPort: null,
    readonlyPort: null,
    user: null,
    workerUser: null,
    readonlyUser: null,
    workerRole: null,
    readonlyRole: null,
  };

  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok === '--plan') { args.plan = true; }
    else if (tok === '--database') { args.database = nextArg(argv, i++, tok); }
    else if (tok === '--company-slug') { args.companySlug = nextArg(argv, i++, tok); }
    else if (tok === '--environment') { args.environment = nextArg(argv, i++, tok); }
    else if (tok === '--allow-non-dev') { args.allowNonDev = true; }
    else if (tok === '--stores-dir') { args.storesDir = nextArg(argv, i++, tok); }
    else if (tok === '--code-store-dir') { args.codeStoreDir = nextArg(argv, i++, tok); }
    else if (tok === '--data-store-dir') { args.dataStoreDir = nextArg(argv, i++, tok); }
    else if (tok === '--key-file') { args.keyFile = nextArg(argv, i++, tok); }
    else if (tok === '--worker-person-id') { args.workerPersonId = nextArg(argv, i++, tok); }
    else if (tok === '--worker-name') { args.workerName = nextArg(argv, i++, tok); }
    else if (tok === '--pg-mode') { args.pgMode = nextArg(argv, i++, tok); }
    else if (tok === '--socket-path') { args.socketPath = nextArg(argv, i++, tok); }
    else if (tok === '--worker-socket-path') { args.workerSocketPath = nextArg(argv, i++, tok); }
    else if (tok === '--readonly-socket-path') { args.readonlySocketPath = nextArg(argv, i++, tok); }
    else if (tok === '--host') { args.host = nextArg(argv, i++, tok); }
    else if (tok === '--worker-host') { args.workerHost = nextArg(argv, i++, tok); }
    else if (tok === '--readonly-host') { args.readonlyHost = nextArg(argv, i++, tok); }
    else if (tok === '--port') { args.port = parsePortArg(nextArg(argv, i++, tok), tok); }
    else if (tok === '--worker-port') { args.workerPort = parsePortArg(nextArg(argv, i++, tok), tok); }
    else if (tok === '--readonly-port') { args.readonlyPort = parsePortArg(nextArg(argv, i++, tok), tok); }
    else if (tok === '--user') { args.user = nextArg(argv, i++, tok); }
    else if (tok === '--worker-user') { args.workerUser = nextArg(argv, i++, tok); }
    else if (tok === '--readonly-user') { args.readonlyUser = nextArg(argv, i++, tok); }
    else if (tok === '--worker-role') { args.workerRole = nextArg(argv, i++, tok); }
    else if (tok === '--readonly-role') { args.readonlyRole = nextArg(argv, i++, tok); }
    else {
      throw new AppError(`Unknown argument: ${tok}\n${usageText()}`, 400, 'INVALID_CLI_ARGS');
    }
  }

  if (!args.database || !args.database.trim()) {
    throw new AppError(usageText(), 400, 'MISSING_CLI_ARGS');
  }
  args.database = args.database.trim();

  if (args.workerPersonId && args.workerName) {
    throw new AppError(
      'Specify at most one of --worker-person-id or --worker-name, not both.',
      400,
      'INVALID_CLI_ARGS',
    );
  }

  if (args.plan) {
    return args;
  }

  const hasSplitStores = Boolean(args.codeStoreDir || args.dataStoreDir);
  if (hasSplitStores && (!args.codeStoreDir || !args.dataStoreDir)) {
    throw new AppError('Both --code-store-dir and --data-store-dir must be provided together.', 400, 'MISSING_CLI_ARGS');
  }
  if ((!args.storesDir && !hasSplitStores) || !args.keyFile) {
    throw new AppError(usageText(), 400, 'MISSING_CLI_ARGS');
  }
  return args;
}

export function buildMaterializePoolConfig(args, kind) {
  return buildProvisionedPoolConfig(args, kind, { applicationPrefix: 'coherence-materialize' });
}

export async function runMaterializeImportedEmitsCli(args, { createPoolFn = undefined } = {}) {
  const readPoolConfig = buildMaterializePoolConfig(args, 'readonly');
  const poolOpts = createPoolFn ? { createPoolFn } : {};

  if (args.plan) {
    const allowScratchDatabase = isLocalTargetConfig(readPoolConfig);
    assertDatabaseNameAllowed(args.database, {
      companySlug: args.companySlug,
      allowScratch: allowScratchDatabase,
    });
    if (args.environment || !args.allowNonDev) {
      assertNonProdEndpoint({
        pgConfig: readPoolConfig,
        environment: args.environment || 'dev',
        allowNonDev: args.allowNonDev,
      });
    }
    return withReadPool(
      readPoolConfig,
      (readPool) => planImportedEmitMaterializations({
        readPool,
        companySlug: args.companySlug,
        expectedEnvironment: args.environment,
        allowNonDev: Boolean(args.allowNonDev),
        allowScratchDatabase,
        readPoolConfig,
      }),
      poolOpts,
    );
  }

  const workerPoolConfig = buildMaterializePoolConfig(args, 'worker');
  const allowScratchDatabase = isLocalTargetConfig(workerPoolConfig) && isLocalTargetConfig(readPoolConfig);

  assertDatabaseNameAllowed(args.database, {
    companySlug: args.companySlug,
    allowScratch: allowScratchDatabase,
  });
  if (args.environment || !args.allowNonDev) {
    const guardEnv = args.environment || 'dev';
    assertNonProdEndpoint({ pgConfig: workerPoolConfig, environment: guardEnv, allowNonDev: args.allowNonDev });
    assertNonProdEndpoint({ pgConfig: readPoolConfig, environment: guardEnv, allowNonDev: args.allowNonDev });
  }

  let codeRoot;
  let dataRoot;
  if (args.codeStoreDir && args.dataStoreDir) {
    codeRoot = resolve(args.codeStoreDir);
    dataRoot = resolve(args.dataStoreDir);
  } else {
    const resolvedStores = resolve(args.storesDir);
    codeRoot = join(resolvedStores, 'code');
    dataRoot = join(resolvedStores, 'data');
  }
  await assertDistinctCodeAndDataStores(codeRoot, dataRoot);
  await assertExistingStoreDir(codeRoot, 'code');
  await assertExistingStoreDir(dataRoot, 'data');

  const codeStore = createCodeStore({ backend: createFileObjectStore({ rootDir: codeRoot, label: `materialize-code:${codeRoot}` }) });
  const dataStore = createDataStore({ backend: createFileObjectStore({ rootDir: dataRoot, label: `materialize-data:${dataRoot}` }) });
  const stores = createStorePair({ codeStore, dataStore });

  return withWorkerAndReadPools(
    workerPoolConfig,
    readPoolConfig,
    ({ workerPool, readPool }) => materializeImportedEmitsInDatabase({
      readPool,
      workerPool,
      stores,
      keyFile: args.keyFile,
      workerPersonId: args.workerPersonId,
      workerName: args.workerName,
      companySlug: args.companySlug,
      expectedEnvironment: args.environment,
      allowNonDev: Boolean(args.allowNonDev),
      allowScratchDatabase,
      workerPoolConfig,
      readPoolConfig,
    }),
    poolOpts,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const cli = parseMaterializeCliArgs(process.argv.slice(2));
    const summary = await runMaterializeImportedEmitsCli(cli);
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    if (!summary.passed) {
      process.exitCode = 1;
    }
  } catch (err) {
    process.stderr.write(`${JSON.stringify({
      passed: false,
      error: redactPhi(err?.message || 'Imported emit materialization failed.'),
      code: err?.code || 'ERROR',
    })}\n`);
    process.exitCode = 1;
  }
}
