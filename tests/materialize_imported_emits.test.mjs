// Live PostgreSQL 17 tests for scripts/materialize-imported-emits.mjs (Release P4):
// CLI parsing & Cloud SQL/safety guards, worker selector exclusivity & unknown pool kind refusal,
// privacy redaction & value-free error mapping (writing_npn, UNMAPPED/AMBIGUOUS_WRITING_NPN, CSV cells),
// --plan read-only listing & prior-sent prerequisite preflight, non-worker & superuser refusals,
// wrong-secret/revoked key refusal even on zero-candidate reruns, company_import-only scope skipping
// legacy mac_import runs, same-date ordering (is_sent ASC so sent is current), bundle display matching
// and viewer.html/policy_status_meta.json merging + conflict refusal, two-run partial failure/fix/rerun,
// store preflight before first write, owner visibility, idempotency, and all-or-nothing refusal.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import pg from 'pg';
import {
  buildMaterializePoolConfig,
  parseMaterializeCliArgs,
  runMaterializeImportedEmitsCli,
} from '../scripts/materialize-imported-emits.mjs';
import { createAppCommands, createIamCommands } from '../src/commands/app-cmd.mjs';
import { buildConnectionConfig, createPool, inReadTx, mapPgError, withSerializableTx } from '../src/db/pg-client.mjs';
import { provisionCompanyDatabase } from '../src/iam/provision.mjs';
import { buildProvisionedPoolConfig, createWorkerTokenProvider } from '../src/iam/provisioned-runtime.mjs';
import { mintSignedSessionToken, readKeyFile } from '../src/iam/tokens.mjs';
import {
  materializeImportedEmitsInDatabase,
  planImportedEmitMaterializations,
} from '../src/importer/materialize-imported-emits.mjs';
import { importHistoryIntoDatabase } from '../src/importer/provisioned-import.mjs';
import { createFileObjectStore } from '../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../src/storage/stores.mjs';
import { sha256Hex } from '../src/util/crypto.mjs';
import { redactPhi } from '../src/util/redact.mjs';
import { createViewHandlers } from '../src/web/view-handlers.mjs';
import { prepareEmitMaterialization } from '../src/worker/emit-materializer.mjs';
import {
  createStdlibMockCoherenceRepo,
  makeOverlayCsv,
  sampleApprovalRow,
} from './helpers/fixtures.mjs';
import { appendIamAuditEntry } from './helpers/iam-harness.mjs';
import {
  checkPgAvailable,
  createLoginRoles,
  createScratchDb,
  withClusterCatalogLock,
  writeTree,
} from './helpers/test-db.mjs';

const execFileAsync = promisify(execFile);
const pgCheck = await checkPgAvailable();
const PG_PORT = Number(process.env.PGPORT || 5432);

const BOB_HDR = 'policy_id,external_policy_id,carrier,mbi,member,state,plan_type,simple_plan_type,submission_date,origin_effective,effective_date,termination_date,writing_npn,writing_agent,entity,status,coherent_status,amount,upline_amount';
const LED_HDR = 'tx_id,record_id,external_policy_id,policy_id,statement_name,src_type,carrier,mbi,member,state,plan_type,simple_plan_type,submission_date,origin_effective,effective_date,termination_date,earned_date,payment_date,statement_date,min_date,gross_comm,revenue_type,override_amount,commission_amount,hra_amount,fee_amount,other_amount,downline_amount,upline_amount,writing_npn,writing_agent,entity,payee_npn,agency_id,status,policy_status,cbob_c,cbob_s,sf,notes,coherent_notes';
const STMT_HDR = 'tx_id,record_id,external_policy_id,policy_id,statement_name,src_type,carrier,mbi,member,state,plan_type,simple_plan_type,submission_date,origin_effective,effective_date,earned_date,payment_date,statement_date,run_statement_date,gross_comm,revenue_type,downline_amount,upline_amount,writing_npn,writing_agent,entity,run_action';

async function snapshotMaterializeState(readPool) {
  const tables = [
    'coherence.journal_entries',
    'platform.audit_journal',
    'coherence.run_materializations',
    'coherence.statement_batches',
    'coherence.statement_agency_lines',
    'coherence.statement_upline_lines',
    'coherence.bob_policies',
    'coherence.bob_policy_financials',
    'coherence.coherent_ledger_rows',
  ];
  const counts = {};
  for (const tbl of tables) {
    counts[tbl] = Number((await readPool.query(`SELECT pg_catalog.count(*)::int AS n FROM ${tbl}`)).rows[0].n);
  }
  const maxCohSeq = Number((await readPool.query('SELECT COALESCE(pg_catalog.max(seq), 0)::bigint AS s FROM coherence.journal_entries')).rows[0].s);
  const maxAuditSeq = Number((await readPool.query('SELECT COALESCE(pg_catalog.max(seq), 0)::bigint AS s FROM platform.audit_journal')).rows[0].s);
  return { counts, maxCohSeq, maxAuditSeq };
}

async function seedAgenciesAndAgents({ appPool, ownerToken, companyOrgId, suffix, includeRobin = true }) {
  const iamCmd = createIamCommands({ pool: appPool });
  const beaconOrg = await iamCmd.createOrganization({
    dbToken: ownerToken,
    commandKey: `mat-org-beacon-${suffix}`,
    orgKind: 'agency',
    slug: 'beacon',
    displayName: 'Beacon',
    parentOrgId: companyOrgId,
    validRange: '[2020-01-01,)',
  });
  const harborOrg = await iamCmd.createOrganization({
    dbToken: ownerToken,
    commandKey: `mat-org-harbor-${suffix}`,
    orgKind: 'agency',
    slug: 'harbor',
    displayName: 'Harbor',
    parentOrgId: companyOrgId,
    validRange: '[2020-01-01,)',
  });
  await iamCmd.createPerson({
    dbToken: ownerToken,
    commandKey: `mat-person-sam-${suffix}`,
    organizationId: beaconOrg.result.organizationId,
    legalName: 'Sam Seller',
    preferredName: 'Sam Seller',
    primaryEmail: 'sam.seller@acme.example',
    npn: '11111111',
    workArrangement: 'self_employed_internal',
    validRange: '[2020-01-01,)',
  });
  if (includeRobin) {
    await iamCmd.createPerson({
      dbToken: ownerToken,
      commandKey: `mat-person-robin-${suffix}`,
      organizationId: harborOrg.result.organizationId,
      legalName: 'Robin Agent',
      preferredName: 'Robin Agent',
      primaryEmail: 'robin.agent@acme.example',
      npn: '22222222',
      workArrangement: 'self_employed_internal',
      validRange: '[2020-01-01,)',
    });
  }
  return {
    beaconOrgId: beaconOrg.result.organizationId,
    harborOrgId: harborOrg.result.organizationId,
  };
}

async function setupProvisionedEnv(prefix, { includeRobin = true } = {}) {
  const suffix = randomBytes(4).toString('hex');
  const work = await mkdtemp(join(tmpdir(), `coherence-${prefix}-${suffix}-`));
  const keysDir = join(work, 'keys');
  const storesDir = join(work, 'stores');
  const db = await createScratchDb(prefix);
  const sharedPw = `pw_${randomBytes(12).toString('hex')}`;
  const appUser = `test_${prefix}_app_${suffix}@nusear-dev.iam`;
  const workerUser = `test_${prefix}_wrk_${suffix}@nusear-dev.iam`;
  const roUser = `test_${prefix}_ro_${suffix}@nusear-dev.iam`;
  const logins = await createLoginRoles(db.adminConfig, [
    { name: appUser, password: sharedPw },
    { name: workerUser, password: sharedPw },
    { name: roUser, password: sharedPw },
  ]);
  const closeables = [];

  try {
    const prov = await provisionCompanyDatabase({
      pgConfig: db.pgConfig,
      companySlug: 'acme',
      displayName: 'Acme',
      environment: 'dev',
      keysDir,
      staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
      roleMappings: { app: appUser, worker: workerUser, readonly: roUser },
    });
    const appPool = await createPool({
      mode: 'local', host: '127.0.0.1', port: PG_PORT, database: db.dbName,
      user: appUser, password: sharedPw, role: 'platform_app',
    });
    const workerPool = await createPool({
      mode: 'local', host: '127.0.0.1', port: PG_PORT, database: db.dbName,
      user: workerUser, password: sharedPw, role: 'platform_worker',
    });
    const readPool = await createPool({
      mode: 'local', host: '127.0.0.1', port: PG_PORT, database: db.dbName,
      user: roUser, password: sharedPw, role: 'platform_readonly',
    });
    closeables.push(appPool, workerPool, readPool);

    const staffKeyFile = prov.keys.find((k) => k.keyScope === 'nusear_staff').filePath;
    const serviceKeyFile = prov.keys.find((k) => k.keyScope === 'service').filePath;
    const staffKey = await readKeyFile(staffKeyFile);
    const ownerId = prov.iam.staff.find((s) => s.role === 'nusear_owner').personId;
    const ownerToken = mintSignedSessionToken({
      keyId: staffKey.keyId,
      secretBytes: staffKey.secretBytes,
      environment: 'dev',
      actorPersonId: ownerId,
    });
    staffKey.secretBytes.fill(0);

    const orgs = await seedAgenciesAndAgents({
      appPool,
      ownerToken,
      companyOrgId: prov.iam.companyOrgId,
      suffix,
      includeRobin,
    });

    await mkdir(join(storesDir, 'code'), { recursive: true, mode: 0o700 });
    await mkdir(join(storesDir, 'data'), { recursive: true, mode: 0o700 });
    const stores = createStorePair({
      codeStore: createCodeStore({ backend: createFileObjectStore({ rootDir: join(storesDir, 'code'), label: `${prefix}-c` }) }),
      dataStore: createDataStore({ backend: createFileObjectStore({ rootDir: join(storesDir, 'data'), label: `${prefix}-d` }) }),
    });
    const appCommands = createAppCommands({ pool: appPool, stores });

    return {
      suffix,
      work,
      keysDir,
      storesDir,
      db,
      sharedPw,
      appUser,
      workerUser,
      roUser,
      prov,
      appPool,
      workerPool,
      readPool,
      staffKeyFile,
      serviceKeyFile,
      ownerToken,
      orgs,
      stores,
      appCommands,
      cliEnv: { ...process.env, PGPASSWORD: sharedPw },
      closeables,
      async cleanup() {
        for (const c of closeables) {
          await c.end().catch(() => {});
        }
        await db.drop();
        await logins.cleanup();
        await rm(work, { recursive: true, force: true }).catch(() => {});
      },
    };
  } catch (err) {
    for (const c of closeables) {
      await c.end().catch(() => {});
    }
    await db.drop().catch(() => {});
    await logins.cleanup().catch(() => {});
    await rm(work, { recursive: true, force: true }).catch(() => {});
    throw err;
  }
}

async function buildProvisionedHistoryFixtures(work, { displayName = 'Acme' } = {}) {
  const plantedMember1 = 'Zelda Q. Plantedname';
  const plantedMember2 = 'Nora V. Fixturemember';
  const plantedMbi1 = '1A2B3C4D5E6';
  const plantedMbi2 = '7F8G9H0J1K2';
  const mockRepo = join(work, 'mock-coherence');
  await createStdlibMockCoherenceRepo(mockRepo);

  const row0 = sampleApprovalRow({ record_id: 'policy:carrier_a:P1#effective:2026-01-01', note: 'base' });
  const row1 = sampleApprovalRow({
    record_id: `carrier_a~direct~${plantedMember1}~100.00~2026-11`,
    disposition: 'CONFIRM',
    agent: null,
    agency: null,
    status: null,
    note: 'run1',
  });
  const row2 = sampleApprovalRow({
    record_id: `carrier_a~direct~${plantedMember2}~200.00~2026-11`,
    disposition: 'CONFIRM',
    agent: null,
    agency: null,
    status: null,
    note: 'run2',
  });
  const priorCsv = makeOverlayCsv([row0], { version: 'v2' });
  const run1OverlayCsv = makeOverlayCsv([row0, row1], { version: 'v2' });
  const run2OverlayCsv = makeOverlayCsv([row0, row1, row2], { version: 'v2' });

  // Run 1 (2026-11-02, sent): direct emits/ files + emit_metadata.json + working/tx.csv.
  const r1BobCsv = [
    BOB_HDR,
    `1,EXT-1,CarrierA,${plantedMbi1},${plantedMember1},FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,11111111,Sam Seller,Beacon,ACTIVE_PAYING,,80.00,20.00`,
    '',
  ].join('\n');
  const r1LedCsv = [
    LED_HDR,
    `101,carrier_a~direct~${plantedMember1}~100.00~2026-11,EXT-1,1,stmt_nov02,direct,CarrierA,${plantedMbi1},${plantedMember1},FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,2026-11-01,2026-11-02,2026-11-02,2026-10-01,100.00,commission,,100.00,,,,80.00,20.00,11111111,Sam Seller,Beacon,11111111,beacon,ACTIVE_PAYING,active,1,1,1,,`,
    '',
  ].join('\n');
  const r1StmtCsv = [
    STMT_HDR,
    `101,carrier_a~direct~${plantedMember1}~100.00~2026-11,EXT-1,1,stmt_nov02,direct,CarrierA,${plantedMbi1},${plantedMember1},FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,2026-11-01,2026-11-02,2026-11-02,2026-11-02,100.00,commission,80.00,20.00,11111111,Sam Seller,Beacon,NEW`,
    '',
  ].join('\n');
  const r1MetaJson = JSON.stringify({
    statementDate: '2026-11-02',
    corpusTail: '2026-11',
    agencyStart: '2026-01-01',
    coherentStatus: { 1: 'ACTIVE_CONFIRMED' },
    coherentTrajectory: { 1: [{ month: '2026-11', amount: '80.00' }] },
  }, null, 2) + '\n';
  const r1WorkingTxCsv = 'tx_id,filename,sheet_name,source_position\n101,stmt_nov02.xlsx,NovDetail,17\n';

  // Run 2 (2026-11-09, unsent, includes Sent/statements_20261102.csv in frozen input):
  // entity-manager viewer.html bundle layout + policy_status_meta.json lacking corpusTail & agencyStart
  // so viewer.html's corpusTail & agencyStart must merge cleanly with policy_status_meta.json!
  const r2BobCsv = [
    BOB_HDR,
    `1,EXT-1,CarrierA,${plantedMbi1},${plantedMember1},FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,11111111,Sam Seller,Beacon,ACTIVE_PAYING,,80.00,20.00`,
    `2,EXT-2,CarrierA,${plantedMbi2},${plantedMember2},NC,MA,MA,2026-10-15,2026-10-15,2026-11-01,,22222222,Robin Agent,Harbor,ACTIVE_PAYING,,160.00,40.00`,
    '',
  ].join('\n');
  const r2LedCsv = [
    LED_HDR,
    `101,carrier_a~direct~${plantedMember1}~100.00~2026-11,EXT-1,1,stmt_nov02,direct,CarrierA,${plantedMbi1},${plantedMember1},FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,2026-11-01,2026-11-02,2026-11-02,2026-10-01,100.00,commission,,100.00,,,,80.00,20.00,11111111,Sam Seller,Beacon,11111111,beacon,ACTIVE_PAYING,active,1,1,1,,`,
    `102,carrier_a~direct~${plantedMember2}~200.00~2026-11,EXT-2,2,stmt_nov09,direct,CarrierA,${plantedMbi2},${plantedMember2},NC,MA,MA,2026-10-15,2026-10-15,2026-11-01,,2026-11-01,2026-11-09,2026-11-09,2026-10-15,200.00,commission,,200.00,,,,160.00,40.00,22222222,Robin Agent,Harbor,22222222,harbor,ACTIVE_PAYING,active,1,1,1,,`,
    '',
  ].join('\n');
  const r2StmtCsv = [
    STMT_HDR,
    `102,carrier_a~direct~${plantedMember2}~200.00~2026-11,EXT-2,2,stmt_nov09,direct,CarrierA,${plantedMbi2},${plantedMember2},NC,MA,MA,2026-10-15,2026-10-15,2026-11-01,2026-11-01,2026-11-09,2026-11-09,2026-11-09,200.00,commission,160.00,40.00,22222222,Robin Agent,Harbor,NEW`,
    '',
  ].join('\n');
  const r2PolicyStatusMetaJson = JSON.stringify({
    statementDate: '2026-11-09',
    coherentStatus: { 1: 'ACTIVE_CONFIRMED', 2: 'ACTIVE_NEW' },
    coherentTrajectory: { 2: [{ month: '2026-11', amount: '160.00' }] },
  }, null, 2) + '\n';
  const r2ViewerCfg = {
    name: 'Entity Manager',
    title: displayName,
    statementDate: '2026-11-09',
    role: 'ENTITY_MANAGER',
    corpusTail: '2026-11',
    agencyStart: '2026-01-01',
    coherentStatus: { 1: 'ACTIVE_CONFIRMED', 2: 'ACTIVE_NEW' },
    features: {
      CANONICAL_BOB: { canonical_bob: 'data/canonical_bob.csv' },
      COHERENT_LEDGER: { coherent_ledger: 'data/coherent_ledger.csv' },
    },
  };
  const r2ViewerHtml = `<!doctype html><html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify(r2ViewerCfg)};</script></head><body>viewer</body></html>`;
  const r2WorkingTxCsv = 'tx_id,filename,sheet_name,source_position\n101,stmt_nov02.xlsx,NovDetail,17\n102,stmt_nov09.xlsx,HarborSheet,42\n';

  const cleanAgentsCsv = 'agent_name,agent_npn,entity\nSam Seller,11111111,Beacon\nRobin Agent,22222222,Harbor\n';
  const srcDir = join(work, 'source-ref');

  // Pre-2026-08-31 legacy mac_import run carrying emit CSVs (including mismatched statements date)
  // that would fail if queued under strict_entity_ledger; must be skipped as skippedLegacyMacImport!
  await writeTree(join(srcDir, 'runs', '2026-08-10'), {
    'input/a.csv': 'k\n0\n',
    'overlay.csv': priorCsv,
    'emits/overlay.csv': priorCsv,
    'emits/canonical_bob.csv': r1BobCsv,
    'emits/coherent_ledger.csv': r1LedCsv,
    'emits/statements_20260899.csv': r1StmtCsv,
    'run.json': JSON.stringify({
      date: '2026-08-10',
      steps: { assign: { at: '2026-08-10T10:00:00' }, emit: { at: '2026-08-10T10:05:00' } },
    }),
  });

  // Legacy mac_import run with only emits/overlay.csv: also skipped as skippedLegacyMacImport.
  await writeTree(join(srcDir, 'runs', '2026-10-12'), {
    'input/a.csv': 'k\n1\n',
    'overlay.csv': priorCsv,
    'emits/overlay.csv': priorCsv,
    'run.json': JSON.stringify({
      date: '2026-10-12',
      steps: { assign: { at: '2026-10-12T10:00:00' }, emit: { at: '2026-10-12T10:05:00' } },
    }),
  });

  // Company run 1 (2026-11-02, sent, direct emits/ files).
  const run1Tree = {
    'input/Agent Data/cleanagentdata.csv': cleanAgentsCsv,
    'input/Overlay/overlay.csv': priorCsv,
    'working/tx.csv': r1WorkingTxCsv,
    'overlay.csv': run1OverlayCsv,
    'emits/overlay.csv': run1OverlayCsv,
    'emits/canonical_bob.csv': r1BobCsv,
    'emits/coherent_ledger.csv': r1LedCsv,
    'emits/statements_20261102.csv': r1StmtCsv,
    'emits/emit_metadata.json': r1MetaJson,
    'run.json': JSON.stringify({
      date: '2026-11-02',
      steps: {
        assign: { at: '2026-11-02T10:00:00' },
        attribute: { at: '2026-11-02T10:01:00' },
        emit: { at: '2026-11-02T10:05:00' },
      },
    }),
  };
  await writeTree(join(srcDir, 'company-ws', '2026-11-02', 'runs', '2026-11-02'), run1Tree);

  // Company run 2 (2026-11-09, unsent, entity-manager viewer.html bundle + policy_status_meta.json merge).
  const run2Tree = {
    'input/Agent Data/cleanagentdata.csv': cleanAgentsCsv,
    'input/Overlay/overlay.csv': run1OverlayCsv,
    'input/Sent/statements_20261102.csv': r1StmtCsv,
    'working/tx.csv': r2WorkingTxCsv,
    'overlay.csv': run2OverlayCsv,
    'emits/overlay.csv': run2OverlayCsv,
    'emits/statements_20261109.csv': r2StmtCsv,
    'emits/policy_status_meta.json': r2PolicyStatusMetaJson,
    [`emits/bundles/entity-managers/${displayName}/viewer.html`]: r2ViewerHtml,
    [`emits/bundles/entity-managers/${displayName}/data/canonical_bob.csv`]: r2BobCsv,
    [`emits/bundles/entity-managers/${displayName}/data/coherent_ledger.csv`]: r2LedCsv,
    'run.json': JSON.stringify({
      date: '2026-11-09',
      steps: {
        assign: { at: '2026-11-09T10:00:00' },
        attribute: { at: '2026-11-09T10:01:00' },
        emit: { at: '2026-11-09T10:05:00' },
      },
    }),
  };
  await writeTree(join(srcDir, 'company-ws', '2026-11-09', 'runs', '2026-11-09'), run2Tree);

  // Abandoned company run (2026-11-05): must be skipped, never materialized or refused.
  await writeTree(join(srcDir, 'company-abandoned', '2026-11-05-abandoned'), {
    'input/Agent Data/cleanagentdata.csv': cleanAgentsCsv,
    'input/Overlay/overlay.csv': run1OverlayCsv,
    'overlay.csv': run1OverlayCsv,
    'emits/overlay.csv': run1OverlayCsv,
    'run.json': JSON.stringify({
      date: '2026-11-05',
      steps: { assign: { at: '2026-11-05T10:00:00' }, emit: { at: '2026-11-05T10:05:00' } },
    }),
  });

  // Standing input marks 2026-11-02 as sent via Sent/statements_20261102.csv.
  await writeTree(join(srcDir, 'input'), {
    'Agent Data/cleanagentdata.csv': cleanAgentsCsv,
    'Overlay/overlay.csv': run2OverlayCsv,
    'Sent/statements_20261102.csv': r1StmtCsv,
  });

  const manifestPath = join(work, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    companySlug: 'acme',
    displayName,
    defaultEmitMode: 'coherence',
    coherenceRepo: mockRepo,
    pythonPath: 'python3',
    sources: {
      legacyRunsRoot: 'source-ref/runs',
      companyWorkspacesDir: 'source-ref/company-ws',
      companyAbandonedDir: 'source-ref/company-abandoned',
      standingInputDir: 'source-ref/input',
    },
    importConfig: {
      includeLegacyHostHistory: true,
      useCompanyIncomingInput: false,
      currentInputSourceKind: 'mac_import',
      freshOverlayRoots: [
        { sourceFolder: '2026-08-10', sha256: sha256Hex(priorCsv) },
        { sourceFolder: '2026-10-12', sha256: sha256Hex(priorCsv) },
      ],
    },
  }, null, 2), 'utf8');

  return {
    manifestPath,
    plantedValues: [plantedMember1, plantedMember2, plantedMbi1, plantedMbi2, '11111111', '22222222', 'Sam Seller', 'Robin Agent'],
    r1BobCsv,
    r1LedCsv,
    r1StmtCsv,
  };
}

test('Materialize Imported Emits [CLI Parsing, Pool Kind Validation, Worker Selector Exclusivity, Cloud SQL Pool Config, PG* & Safety Guards]', async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'coherence-mat-cli-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  assert.throws(
    () => parseMaterializeCliArgs(['--stores-dir', '/tmp/s', '--key-file', '/tmp/k']),
    (err) => err?.code === 'MISSING_CLI_ARGS',
    'must require --database',
  );
  assert.throws(
    () => parseMaterializeCliArgs(['--database', 'acme', '--stores-dir', '/tmp/s']),
    (err) => err?.code === 'MISSING_CLI_ARGS',
    'execute mode must require --key-file',
  );
  assert.throws(
    () => parseMaterializeCliArgs(['--database', 'acme', '--code-store-dir', '/tmp/c', '--key-file', '/tmp/k']),
    (err) => err?.code === 'MISSING_CLI_ARGS',
    'must require both --code-store-dir and --data-store-dir together',
  );
  assert.throws(
    () => parseMaterializeCliArgs(['--database', 'acme', '--plan', '--port', 'notaport']),
    (err) => err?.code === 'INVALID_CLI_ARGS',
    'must refuse non-integer port',
  );
  assert.throws(
    () => parseMaterializeCliArgs([
      '--database', 'acme',
      '--stores-dir', '/tmp/s',
      '--key-file', '/tmp/k',
      '--worker-person-id', randomUUID(),
      '--worker-name', 'Coherence Worker',
    ]),
    (err) => err?.code === 'INVALID_CLI_ARGS',
    '--worker-person-id and --worker-name must be mutually exclusive',
  );
  assert.throws(
    () => buildProvisionedPoolConfig({ database: 'acme' }, 'unknown_kind'),
    (err) => err?.code === 'INVALID_POOL_KIND',
    'unknown pool kind must throw INVALID_POOL_KIND',
  );
  assert.throws(
    () => buildProvisionedPoolConfig({ database: 'acme' }, 'toString'),
    (err) => err?.code === 'INVALID_POOL_KIND',
    'prototype property name must throw INVALID_POOL_KIND',
  );

  // --plan requires only --database and accepts extra flags cleanly.
  const planArgs = parseMaterializeCliArgs([
    '--database', 'acme',
    '--plan',
    '--pg-mode', 'cloudsql',
    '--readonly-socket-path', '/tmp/cloudsql/proj:us-east4:nusear-dev-db',
    '--readonly-user', 'nusear-ro-dev@proj.iam',
  ]);
  assert.equal(planArgs.plan, true);
  assert.equal(planArgs.database, 'acme');

  // Cloud SQL worker + readonly pool configs pin explicit port 5432, startup -c role=platform_worker / platform_readonly, and refuse PG* vars.
  const prevPgPort = process.env.PGPORT;
  const prevPgPassword = process.env.PGPASSWORD;
  const prevPgOptions = process.env.PGOPTIONS;
  try {
    process.env.PGPORT = '5433';
    delete process.env.PGPASSWORD;
    delete process.env.PGOPTIONS;

    const parsed = parseMaterializeCliArgs([
      '--pg-mode', 'cloudsql',
      '--worker-socket-path', '/tmp/cloudsql-worker/proj:us-east4:nusear-dev-db',
      '--readonly-socket-path', '/tmp/cloudsql-ro/proj:us-east4:nusear-dev-db',
      '--database', 'acme',
      '--worker-user', 'nusear-worker-dev@proj.iam',
      '--readonly-user', 'nusear-ro-dev@proj.iam',
      '--stores-dir', '/tmp/stores',
      '--key-file', '/tmp/keys/acme-dev-service.key.json',
    ]);
    const workerPoolCfg = buildMaterializePoolConfig(parsed, 'worker');
    const roPoolCfg = buildMaterializePoolConfig(parsed, 'readonly');
    const workerConn = buildConnectionConfig(workerPoolCfg);
    const roConn = buildConnectionConfig(roPoolCfg);

    assert.equal(workerConn.host, '/tmp/cloudsql-worker/proj:us-east4:nusear-dev-db');
    assert.equal(workerConn.port, 5432);
    assert.equal(workerConn.user, 'nusear-worker-dev@proj.iam');
    assert.equal(workerConn.options, '-c role=platform_worker');
    assert.equal(workerConn.ssl, false);
    assert.equal(new pg.Client(workerConn).port, 5432);

    assert.equal(roConn.host, '/tmp/cloudsql-ro/proj:us-east4:nusear-dev-db');
    assert.equal(roConn.port, 5432);
    assert.equal(roConn.user, 'nusear-ro-dev@proj.iam');
    assert.equal(roConn.options, '-c role=platform_readonly');

    assert.throws(
      () => buildConnectionConfig({ ...workerPoolCfg, env: { PGPASSWORD: 'secret' } }),
      /PGPASSWORD/,
      'cloudsql worker mode must forbid PGPASSWORD',
    );
    assert.throws(
      () => buildConnectionConfig({ ...workerPoolCfg, env: { PGOPTIONS: '-c role=postgres' } }),
      /PGOPTIONS/,
      'cloudsql worker mode must forbid PGOPTIONS',
    );
  } finally {
    if (prevPgPort !== undefined) process.env.PGPORT = prevPgPort; else delete process.env.PGPORT;
    if (prevPgPassword !== undefined) process.env.PGPASSWORD = prevPgPassword; else delete process.env.PGPASSWORD;
    if (prevPgOptions !== undefined) process.env.PGOPTIONS = prevPgOptions; else delete process.env.PGOPTIONS;
  }

  // Refuse forbidden target databases and production sockets BEFORE opening any pool or touching disk.
  for (const badDb of ['postgres', 'nusear_control']) {
    await assert.rejects(
      () => runMaterializeImportedEmitsCli(parseMaterializeCliArgs(['--database', badDb, '--plan'])),
      (err) => err?.code === 'FORBIDDEN_TARGET_DATABASE',
    );
  }
  await assert.rejects(
    () => runMaterializeImportedEmitsCli(parseMaterializeCliArgs([
      '--database', 'acme',
      '--pg-mode', 'cloudsql',
      '--worker-socket-path', '/cloudsql/nusear-prod:us-east4:nusear-prod-db',
      '--readonly-socket-path', '/cloudsql/nusear-dev:us-east4:nusear-dev-db',
      '--worker-user', 'nusear-worker-dev@proj.iam',
      '--readonly-user', 'nusear-ro-dev@proj.iam',
      '--stores-dir', join(work, 'missing-stores'),
      '--key-file', join(work, 'missing.key.json'),
    ])),
    (err) => err?.code === 'PRODUCTION_TARGET_REFUSED',
  );
  await assert.rejects(
    () => runMaterializeImportedEmitsCli(parseMaterializeCliArgs([
      '--database', 'acme',
      '--plan',
      '--pg-mode', 'cloudsql',
      '--readonly-socket-path', '/cloudsql/nusear-prod:us-east4:nusear-prod-db',
      '--readonly-user', 'nusear-ro-dev@proj.iam',
    ])),
    (err) => err?.code === 'PRODUCTION_TARGET_REFUSED',
  );

  // Refuse overlapping code/data store dirs and missing store dirs without creating them.
  const sameDir = join(work, 'overlap');
  await assert.rejects(
    () => runMaterializeImportedEmitsCli(parseMaterializeCliArgs([
      '--database', 'coherence_test_overlap',
      '--code-store-dir', sameDir,
      '--data-store-dir', sameDir,
      '--key-file', join(work, 'k.json'),
    ])),
    (err) => err?.code === 'OVERLAPPING_STORE_DIRS',
  );
  const missingStores = join(work, 'nonexistent-stores');
  await assert.rejects(
    () => runMaterializeImportedEmitsCli(parseMaterializeCliArgs([
      '--database', 'coherence_test_missing_store',
      '--stores-dir', missingStores,
      '--key-file', join(work, 'k.json'),
    ])),
    (err) => err?.code === 'MISSING_STORE_DIR',
  );
  assert.equal(await stat(missingStores).then(() => true, () => false), false, 'refused missing stores dir must never be created');
});

test('Materialize Imported Emits [Privacy Redaction & Value-Free Error Mapping]: writing_npn scrubbing, UNMAPPED/AMBIGUOUS_WRITING_NPN, and CSV cell-parse errors never leak values', async () => {
  const syntheticNpn = '99887766';
  const rawUnmapped = `UNMAPPED_WRITING_NPN: cannot map writing_npn "${syntheticNpn}" in coherence.bob_policies to a company_local iam.people row (provide explicit p_npn_map or seed iam.people).`;
  const rawAmbig = `AMBIGUOUS_WRITING_NPN: writing_npn "${syntheticNpn}" in coherence.coherent_ledger_rows matches 2 company_local iam.people rows; refusing to guess.`;

  const scrubbed = redactPhi(rawUnmapped);
  assert.equal(scrubbed.includes(syntheticNpn), false, 'redactPhi must scrub writing_npn "..."');
  assert.match(scrubbed, /writing_npn "\[redacted-npn\]"/);

  const mappedUnmapped = mapPgError({ code: '22023', message: rawUnmapped });
  assert.equal(mappedUnmapped.code, 'UNMAPPED_WRITING_NPN');
  assert.equal(mappedUnmapped.status, 409);
  assert.equal(mappedUnmapped.message.includes(syntheticNpn), false);
  assert.match(mappedUnmapped.message, /coherence\.bob_policies/);
  assert.match(mappedUnmapped.message, /writing_npn/);

  const mappedAmbig = mapPgError({ code: '21000', message: rawAmbig });
  assert.equal(mappedAmbig.code, 'AMBIGUOUS_WRITING_NPN');
  assert.equal(mappedAmbig.status, 409);
  assert.equal(mappedAmbig.message.includes(syntheticNpn), false);
  assert.match(mappedAmbig.message, /coherence\.coherent_ledger_rows/);
  assert.match(mappedAmbig.message, /writing_npn/);

  const secretCellMoney = 'SECRET_MONEY_CELL_9191';
  const secretCellBool = 'SECRET_BOOL_CELL_8282';
  const secretCellAction = 'SECRET_ACTION_CELL_7373';
  const baseBob = `${BOB_HDR}\n1,EXT-1,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,11111111,Sam Seller,Beacon,ACTIVE_PAYING,ACTIVE,80.00,20.00\n`;
  const baseLed = `${LED_HDR}\n101,carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11,EXT-1,1,stmt_nov,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,2026-11-01,2026-11-02,2026-11-02,2026-10-01,100.00,commission,,100.00,,,,80.00,20.00,11111111,Sam Seller,Beacon,11111111,beacon,ACTIVE_PAYING,active,1,1,1,,\n`;
  const baseStmt = `${STMT_HDR}\n101,carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11,EXT-1,1,stmt_nov,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,2026-11-01,2026-11-02,2026-11-02,2026-11-02,100.00,commission,80.00,20.00,11111111,Sam Seller,Beacon,NEW\n`;

  await assert.rejects(
    () => prepareEmitMaterialization({
      db: null,
      runId: randomUUID(),
      attemptEventId: randomUUID(),
      statementDate: '2026-11-02',
      canonicalBobCsv: baseBob.replace(',80.00,20.00', `,${secretCellMoney},20.00`),
      coherentLedgerCsv: baseLed,
      statementsCsv: baseStmt,
    }),
    (err) => {
      assert.equal(err?.code, 'INVALID_MONEY_AMOUNT');
      assert.equal(err.message.includes(secretCellMoney), false, 'money parse error must never echo cell value');
      assert.match(err.message, /canonical_bob\.csv/);
      assert.match(err.message, /amount/);
      assert.match(err.message, /row 1/);
      return true;
    },
  );

  await assert.rejects(
    () => prepareEmitMaterialization({
      db: null,
      runId: randomUUID(),
      attemptEventId: randomUUID(),
      statementDate: '2026-11-02',
      canonicalBobCsv: baseBob,
      coherentLedgerCsv: baseLed.replace(',active,1,1,1,,', `,active,${secretCellBool},1,1,,`),
      statementsCsv: baseStmt,
    }),
    (err) => {
      assert.equal(err?.code, 'INVALID_BOOLEAN');
      assert.equal(err.message.includes(secretCellBool), false, 'boolean parse error must never echo cell value');
      assert.match(err.message, /coherent_ledger\.csv/);
      assert.match(err.message, /cbob_c/);
      assert.match(err.message, /row 1/);
      return true;
    },
  );

  await assert.rejects(
    () => prepareEmitMaterialization({
      db: null,
      runId: randomUUID(),
      attemptEventId: randomUUID(),
      statementDate: '2026-11-02',
      canonicalBobCsv: baseBob,
      coherentLedgerCsv: baseLed,
      statementsCsv: baseStmt.replace(',NEW', `,${secretCellAction}`),
    }),
    (err) => {
      assert.equal(err?.code, 'INVALID_RUN_ACTION');
      assert.equal(err.message.includes(secretCellAction), false, 'run_action parse error must never echo cell value');
      assert.match(err.message, /statements_20261102\.csv/);
      assert.match(err.message, /run_action/);
      assert.match(err.message, /row 1/);
      return true;
    },
  );
});

test('Materialize Imported Emits [End-to-End Provisioned History -> --plan -> Non-Worker & Superuser Refusals -> Worker CLI -> Owner Views -> Idempotent Rerun -> Wrong-Secret Zero-Candidate Rerun]', { skip: !pgCheck.available && pgCheck.reason }, async () => {
  await withClusterCatalogLock(async () => {
    const env = await setupProvisionedEnv('mat');
    const dbOther = await createScratchDb('mat_other');
    const otherKeysDir = join(env.work, 'keys-other');

    try {
      await provisionCompanyDatabase({
        pgConfig: dbOther.pgConfig,
        companySlug: 'acme',
        displayName: 'Acme',
        environment: 'dev',
        keysDir: otherKeysDir,
        staff: [{ role: 'nusear_owner', email: 'owner@nusear.example', legalName: 'Pat Owner' }],
        roleMappings: { app: env.appUser, worker: env.workerUser, readonly: env.roUser },
      });

      const workerPoolOther = await createPool({
        mode: 'local', host: '127.0.0.1', port: PG_PORT, database: dbOther.dbName,
        user: env.workerUser, password: env.sharedPw, role: 'platform_worker',
      });
      const superuserDirectPool = await createPool(env.db.pgConfig);
      const superuserRolePool = await createPool({ ...env.db.pgConfig, role: 'platform_worker' });
      env.closeables.push(workerPoolOther, superuserDirectPool, superuserRolePool);

      const serviceKey = await readKeyFile(env.serviceKeyFile);
      const serviceSecretHex = serviceKey.secretBytes.toString('hex');
      serviceKey.secretBytes.fill(0);

      const fixtures = await buildProvisionedHistoryFixtures(env.work, { displayName: 'Acme' });
      const imp = await importHistoryIntoDatabase({
        readPool: env.readPool,
        appPool: env.appPool,
        stores: env.stores,
        manifestPath: fixtures.manifestPath,
        keyFile: env.staffKeyFile,
        actorEmail: 'owner@nusear.example',
      });
      assert.equal(imp.passed, true, `history import failed: ${JSON.stringify(imp.problems)}`);
      assert.equal(imp.layer1.importedRunCount, 5);

      // Before materialization: Book, Ledger, and Reconciliation have zero runs and zero rows for the owner.
      const beforeViews = await inReadTx(env.appPool, env.ownerToken, async (tx) => ({
        bobRuns: (await tx.query(
          'SELECT r.id FROM app_views.coherence_published_runs r WHERE EXISTS (SELECT 1 FROM app_views.coherence_bob v WHERE v.attempt_event_id = r.emit_attempt_event_id)',
        )).rows,
        ledgerRuns: (await tx.query(
          'SELECT r.id FROM app_views.coherence_published_runs r WHERE EXISTS (SELECT 1 FROM app_views.coherence_ledger v WHERE v.attempt_event_id = r.emit_attempt_event_id)',
        )).rows,
        bobCount: (await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_bob')).rows[0].n,
        ledgerCount: (await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_ledger')).rows[0].n,
        reconCount: (await tx.query('SELECT COUNT(*)::int AS n FROM app_views.coherence_entity_statement_reconciliation')).rows[0].n,
      }));
      assert.equal(beforeViews.bobRuns.length, 0);
      assert.equal(beforeViews.ledgerRuns.length, 0);
      assert.equal(beforeViews.bobCount, 0);
      assert.equal(beforeViews.ledgerCount, 0);
      assert.equal(beforeViews.reconCount, 0);

      const snapBeforePlan = await snapshotMaterializeState(env.readPool);

      // 1. --plan lists only company_import runs, skips both mac_import runs as skippedLegacyMacImport (never blocking!), and touches nothing.
      const planOut = await execFileAsync(process.execPath, [
        'scripts/materialize-imported-emits.mjs',
        '--plan',
        '--pg-mode', 'local',
        '--host', '127.0.0.1',
        '--port', String(PG_PORT),
        '--database', env.db.dbName,
        '--readonly-user', env.roUser,
      ], { cwd: process.cwd(), env: env.cliEnv, maxBuffer: 4 * 1024 * 1024 });

      for (const secretOrPhi of [...fixtures.plantedValues, serviceSecretHex]) {
        assert.equal(planOut.stdout.includes(secretOrPhi), false, `--plan output must never include "${secretOrPhi}"`);
      }
      const planJson = JSON.parse(planOut.stdout);
      assert.equal(planJson.plan, true);
      assert.equal(planJson.passed, true);
      assert.equal(planJson.database, env.db.dbName);
      assert.equal(planJson.environment, 'dev');
      assert.equal(planJson.companySlug, 'acme');
      assert.deepEqual(planJson.counts, {
        totalImportedRuns: 5,
        toMaterialize: 2,
        skippedAlreadyMaterialized: 0,
        skippedWithoutEmit: 0,
        skippedAbandoned: 1,
        skippedLegacyMacImport: 2,
      });
      assert.deepEqual(planJson.prerequisites, {
        passed: true,
        missingPriorSentDates: [],
        missingPriorSentDateCount: 0,
        affectedRunCount: 0,
        missingReferenceCount: 0,
      });
      assert.deepEqual(
        planJson.runs.map((r) => ({ statementDate: r.statementDate, origin: r.origin, sent: r.sent, hasEmitMetadata: r.hasEmitMetadata, hasWorkingTx: r.hasWorkingTx })),
        [
          { statementDate: '2026-11-02', origin: 'company_import', sent: true, hasEmitMetadata: true, hasWorkingTx: true },
          { statementDate: '2026-11-09', origin: 'company_import', sent: false, hasEmitMetadata: true, hasWorkingTx: true },
        ],
      );
      assert.deepEqual(await snapshotMaterializeState(env.readPool), snapBeforePlan, '--plan must write nothing');

      // 2. Non-worker and superuser identities are refused and write nothing.
      // 2a. nusear_staff key file refused via CLI (INVALID_KEY_SCOPE).
      await assert.rejects(
        () => execFileAsync(process.execPath, [
          'scripts/materialize-imported-emits.mjs',
          '--pg-mode', 'local',
          '--host', '127.0.0.1',
          '--port', String(PG_PORT),
          '--database', env.db.dbName,
          '--worker-user', env.workerUser,
          '--readonly-user', env.roUser,
          '--stores-dir', env.storesDir,
          '--key-file', env.staffKeyFile,
        ], { cwd: process.cwd(), env: env.cliEnv }),
        (err) => String(err.stderr || '').includes('INVALID_KEY_SCOPE'),
        'CLI must refuse nusear_staff key file',
      );

      // 2b. Non-worker IAM login user mapped to platform_app refused via CLI with exact PostgreSQL role-denial message.
      await assert.rejects(
        () => execFileAsync(process.execPath, [
          'scripts/materialize-imported-emits.mjs',
          '--pg-mode', 'local',
          '--host', '127.0.0.1',
          '--port', String(PG_PORT),
          '--database', env.db.dbName,
          '--worker-user', env.appUser,
          '--readonly-user', env.roUser,
          '--stores-dir', env.storesDir,
          '--key-file', env.serviceKeyFile,
        ], { cwd: process.cwd(), env: env.cliEnv }),
        (err) => {
          const parsed = JSON.parse(String(err.stderr || ''));
          assert.equal(parsed.passed, false);
          assert.match(parsed.error, /permission denied to set role "platform_worker"/i);
          return true;
        },
        'CLI must refuse appUser entering platform_worker with PostgreSQL role-denial message',
      );

      // 2c. Explicit --worker-role platform_app refused via CLI (WORKER_ONLY).
      await assert.rejects(
        () => execFileAsync(process.execPath, [
          'scripts/materialize-imported-emits.mjs',
          '--pg-mode', 'local',
          '--host', '127.0.0.1',
          '--port', String(PG_PORT),
          '--database', env.db.dbName,
          '--worker-user', env.appUser,
          '--worker-role', 'platform_app',
          '--readonly-user', env.roUser,
          '--stores-dir', env.storesDir,
          '--key-file', env.serviceKeyFile,
        ], { cwd: process.cwd(), env: env.cliEnv }),
        (err) => String(err.stderr || '').includes('WORKER_ONLY'),
        'CLI must refuse platform_app role with WORKER_ONLY',
      );

      // 2d. Direct library call with platform_app pool refused (403 WORKER_ONLY).
      await assert.rejects(
        () => materializeImportedEmitsInDatabase({
          readPool: env.readPool,
          workerPool: env.appPool,
          stores: env.stores,
          keyFile: env.serviceKeyFile,
        }),
        (err) => err?.status === 403 && err?.code === 'WORKER_ONLY',
      );

      // 2e. Direct library call with workerPool + human owner dbToken refused (403 WORKER_ONLY).
      await assert.rejects(
        () => materializeImportedEmitsInDatabase({
          readPool: env.readPool,
          workerPool: env.workerPool,
          stores: env.stores,
          dbToken: env.ownerToken,
        }),
        (err) => err?.status === 403 && err?.code === 'WORKER_ONLY',
      );

      // 2f. Mismatched workerPool / readPool databases refused (409 POOL_DATABASE_MISMATCH).
      await assert.rejects(
        () => materializeImportedEmitsInDatabase({
          readPool: env.readPool,
          workerPool: workerPoolOther,
          stores: env.stores,
          keyFile: env.serviceKeyFile,
        }),
        (err) => err?.status === 409 && err?.code === 'POOL_DATABASE_MISMATCH',
      );

      // 2g. Superuser worker connection refused (both direct superuser AND superuser entering platform_worker).
      await assert.rejects(
        () => materializeImportedEmitsInDatabase({
          readPool: env.readPool,
          workerPool: superuserDirectPool,
          stores: env.stores,
          keyFile: env.serviceKeyFile,
        }),
        (err) => err?.status === 403 && err?.code === 'WORKER_ONLY',
        'direct superuser worker connection must be refused',
      );
      await assert.rejects(
        () => materializeImportedEmitsInDatabase({
          readPool: env.readPool,
          workerPool: superuserRolePool,
          stores: env.stores,
          keyFile: env.serviceKeyFile,
        }),
        (err) => err?.status === 403 && err?.code === 'WORKER_ONLY',
        'superuser worker connection with -c role=platform_worker must be refused',
      );

      assert.deepEqual(await snapshotMaterializeState(env.readPool), snapBeforePlan, 'refused non-worker/superuser calls must write nothing');

      // 3. Run CLI as the Coherence worker: materializes both company_import runs atomically and reports counts only.
      const matRun1 = await execFileAsync(process.execPath, [
        'scripts/materialize-imported-emits.mjs',
        '--pg-mode', 'local',
        '--host', '127.0.0.1',
        '--port', String(PG_PORT),
        '--database', env.db.dbName,
        '--worker-user', env.workerUser,
        '--readonly-user', env.roUser,
        '--stores-dir', env.storesDir,
        '--key-file', env.serviceKeyFile,
      ], { cwd: process.cwd(), env: env.cliEnv, maxBuffer: 4 * 1024 * 1024 });

      for (const secretOrPhi of [...fixtures.plantedValues, serviceSecretHex]) {
        assert.equal(matRun1.stdout.includes(secretOrPhi), false, `materialize output must never include "${secretOrPhi}"`);
      }
      const res1 = JSON.parse(matRun1.stdout);
      assert.equal(res1.passed, true);
      assert.equal(res1.database, env.db.dbName);
      assert.equal(res1.environment, 'dev');
      assert.equal(res1.companySlug, 'acme');
      assert.equal('runs' in res1, false, 'execute output must report counts only');
      assert.deepEqual(res1.counts, {
        totalImportedRuns: 5,
        materialized: 2,
        skippedAlreadyMaterialized: 0,
        skippedWithoutEmit: 0,
        skippedAbandoned: 1,
        skippedLegacyMacImport: 2,
      });

      // 4. Verify published runs, Book of Business (including merged policy_status_meta + viewer.html metadata!),
      //    Coherent Ledger, Reconciliation, and R1 screen handlers for the owner.
      const afterViews = await inReadTx(env.appPool, env.ownerToken, async (tx) => ({
        pubRuns: (await tx.query(
          `SELECT r.id, r.statement_date, r.sent,
                  EXISTS (SELECT 1 FROM app_views.coherence_bob b WHERE b.attempt_event_id = r.emit_attempt_event_id) AS has_bob,
                  EXISTS (SELECT 1 FROM app_views.coherence_ledger l WHERE l.attempt_event_id = r.emit_attempt_event_id) AS has_ledger
           FROM app_views.coherence_published_runs r
           ORDER BY r.statement_date ASC`,
        )).rows,
        currentBob: (await tx.query(
          `SELECT pg_catalog.to_char(run_statement_date, 'YYYY-MM-DD') AS run_date,
                  policy_id, entity, coherent_status, corpus_tail,
                  pg_catalog.to_char(agency_start, 'YYYY-MM-DD') AS agency_start,
                  amount::text AS amount, upline_amount::text AS upline_amount
           FROM app_views.v_current_policy_periods
           ORDER BY policy_id ASC`,
        )).rows,
        currentLedger: (await tx.query(
          `SELECT pg_catalog.to_char(run_statement_date, 'YYYY-MM-DD') AS run_date,
                  tx_id, entity, gross_comm::text AS gross_comm,
                  downline_amount::text AS downline_amount, upline_amount::text AS upline_amount,
                  sheet_name, source_row_no
           FROM app_views.v_current_commission_ledger
           ORDER BY tx_id ASC`,
        )).rows,
        recon: (await tx.query(
          `SELECT pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS statement_date,
                  statement_entity, account_kind, statement_total::text AS statement_total,
                  ledger_total::text AS ledger_total, variance::text AS variance, reconciled
           FROM app_views.coherence_entity_statement_reconciliation
           ORDER BY statement_date ASC, account_kind ASC, statement_entity ASC`,
        )).rows,
      }));

      assert.equal(afterViews.pubRuns.length, 2);
      assert.deepEqual(
        afterViews.pubRuns.map((r) => ({ statement_date: r.statement_date, sent: r.sent, has_bob: r.has_bob, has_ledger: r.has_ledger })),
        [
          { statement_date: '2026-11-02', sent: true, has_bob: true, has_ledger: true },
          { statement_date: '2026-11-09', sent: false, has_bob: true, has_ledger: true },
        ],
      );
      assert.deepEqual(afterViews.currentBob, [
        { run_date: '2026-11-09', policy_id: 1, entity: 'Beacon', coherent_status: 'ACTIVE_CONFIRMED', corpus_tail: '2026-11', agency_start: '2026-01-01', amount: '80.00', upline_amount: '20.00' },
        { run_date: '2026-11-09', policy_id: 2, entity: 'Harbor', coherent_status: 'ACTIVE_NEW', corpus_tail: '2026-11', agency_start: '2026-01-01', amount: '160.00', upline_amount: '40.00' },
      ]);
      assert.deepEqual(afterViews.currentLedger, [
        { run_date: '2026-11-09', tx_id: 101, entity: 'Beacon', gross_comm: '100.00', downline_amount: '80.00', upline_amount: '20.00', sheet_name: 'NovDetail', source_row_no: 17 },
        { run_date: '2026-11-09', tx_id: 102, entity: 'Harbor', gross_comm: '200.00', downline_amount: '160.00', upline_amount: '40.00', sheet_name: 'HarborSheet', source_row_no: 42 },
      ]);
      assert.ok(afterViews.recon.length >= 5);
      assert.ok(afterViews.recon.every((r) => r.reconciled === true && r.variance === '0.00'), `expected $0.00 reconciled rows, got: ${JSON.stringify(afterViews.recon)}`);

      const viewHandlers = createViewHandlers({ pool: env.appPool, companySlug: 'acme', resolveAsOfSeqTx: async () => null });
      const bobScreen = await viewHandlers.getBookOfBusiness(env.ownerToken, {});
      const ledgerScreen = await viewHandlers.getCoherentLedger(env.ownerToken, {});
      const reconScreen = await viewHandlers.getStatementReconciliation(env.ownerToken, {});
      assert.equal(bobScreen.runs.length, 2);
      assert.equal(bobScreen.rows.length, 2);
      assert.equal(ledgerScreen.runs.length, 2);
      assert.equal(ledgerScreen.rows.length, 2);
      assert.equal(reconScreen.runs.length, 2);
      assert.equal(reconScreen.reconciled, true);

      // 5. Idempotent rerun changes nothing!
      const snapAfterMat1 = await snapshotMaterializeState(env.readPool);
      const matRun2 = await execFileAsync(process.execPath, [
        'scripts/materialize-imported-emits.mjs',
        '--pg-mode', 'local',
        '--host', '127.0.0.1',
        '--port', String(PG_PORT),
        '--database', env.db.dbName,
        '--worker-user', env.workerUser,
        '--readonly-user', env.roUser,
        '--stores-dir', env.storesDir,
        '--key-file', env.serviceKeyFile,
      ], { cwd: process.cwd(), env: env.cliEnv, maxBuffer: 4 * 1024 * 1024 });

      const res2 = JSON.parse(matRun2.stdout);
      assert.equal(res2.passed, true);
      assert.deepEqual(res2.counts, {
        totalImportedRuns: 5,
        materialized: 0,
        skippedAlreadyMaterialized: 2,
        skippedWithoutEmit: 0,
        skippedAbandoned: 1,
        skippedLegacyMacImport: 2,
      });
      assert.deepEqual(await snapshotMaterializeState(env.readPool), snapAfterMat1, 'rerun must change nothing');

      // 6. Wrong-secret key AND revoked key on a zero-candidate rerun MUST still be refused inside PostgreSQL before any work!
      const origKeyDoc = JSON.parse(await readFile(env.serviceKeyFile, 'utf8'));
      const wrongSecretHex = randomBytes(32).toString('hex');
      const wrongKeyFile = join(env.keysDir, 'acme-dev-service-wrong.key.json');
      await writeFile(wrongKeyFile, JSON.stringify({ ...origKeyDoc, secretHex: wrongSecretHex }, null, 2), { mode: 0o600 });
      await assert.rejects(
        () => execFileAsync(process.execPath, [
          'scripts/materialize-imported-emits.mjs',
          '--pg-mode', 'local',
          '--host', '127.0.0.1',
          '--port', String(PG_PORT),
          '--database', env.db.dbName,
          '--worker-user', env.workerUser,
          '--readonly-user', env.roUser,
          '--stores-dir', env.storesDir,
          '--key-file', wrongKeyFile,
        ], { cwd: process.cwd(), env: env.cliEnv }),
        (err) => {
          const stderrText = String(err.stderr || '');
          assert.equal(stderrText.includes(wrongSecretHex), false, 'error must never leak wrong secret');
          const parsed = JSON.parse(stderrText);
          assert.equal(parsed.passed, false);
          assert.equal(parsed.code, 'FORBIDDEN');
          return true;
        },
        'wrong-secret key must be refused even when zero candidate runs remain',
      );

      // 7. --plan after materialization reports 0 runs to materialize, 2 skipped as already done, 2 skippedLegacyMacImport.
      const planAfterOut = await execFileAsync(process.execPath, [
        'scripts/materialize-imported-emits.mjs',
        '--plan',
        '--pg-mode', 'local',
        '--host', '127.0.0.1',
        '--port', String(PG_PORT),
        '--database', env.db.dbName,
        '--readonly-user', env.roUser,
      ], { cwd: process.cwd(), env: env.cliEnv });
      const planAfter = JSON.parse(planAfterOut.stdout);
      assert.equal(planAfter.passed, true);
      assert.equal(planAfter.counts.toMaterialize, 0);
      assert.equal(planAfter.counts.skippedAlreadyMaterialized, 2);
      assert.equal(planAfter.counts.skippedLegacyMacImport, 2);
      assert.deepEqual(planAfter.runs, []);

      // 8. Revoking the service key in iam_secret.signing_keys also refuses a zero-candidate rerun inside PostgreSQL.
      await superuserDirectPool.query(
        "UPDATE iam_secret.signing_keys SET active_until = pg_catalog.now() - INTERVAL '1 minute' WHERE key_id = $1",
        [origKeyDoc.keyId],
      );
      await assert.rejects(
        () => execFileAsync(process.execPath, [
          'scripts/materialize-imported-emits.mjs',
          '--pg-mode', 'local',
          '--host', '127.0.0.1',
          '--port', String(PG_PORT),
          '--database', env.db.dbName,
          '--worker-user', env.workerUser,
          '--readonly-user', env.roUser,
          '--stores-dir', env.storesDir,
          '--key-file', env.serviceKeyFile,
        ], { cwd: process.cwd(), env: env.cliEnv }),
        (err) => {
          const parsed = JSON.parse(String(err.stderr || ''));
          assert.equal(parsed.passed, false);
          assert.equal(parsed.code, 'FORBIDDEN');
          return true;
        },
        'revoked key must be refused even when zero candidate runs remain',
      );
    } finally {
      await env.cleanup();
      await dbOther.drop();
    }
  });
});

test('Materialize Imported Emits [Two-Run Partial Failure + Unmapped NPN Privacy + Fix & Rerun; Missing Prior Sent Date Preflight; Store Preflight Before First Write]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  await withClusterCatalogLock(async () => {
    const r1Bob = `${BOB_HDR}\n1,EXT-1,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,11111111,Sam Seller,Beacon,ACTIVE_PAYING,ACTIVE,80.00,20.00\n`;
    const r1Led = `${LED_HDR}\n101,carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11,EXT-1,1,stmt_nov02,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,2026-11-01,2026-11-02,2026-11-02,2026-10-01,100.00,commission,,100.00,,,,80.00,20.00,11111111,Sam Seller,Beacon,11111111,beacon,ACTIVE_PAYING,active,1,1,1,,\n`;
    const r1Stmt = `${STMT_HDR}\n101,carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11,EXT-1,1,stmt_nov02,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,2026-11-01,2026-11-02,2026-11-02,2026-11-02,100.00,commission,80.00,20.00,11111111,Sam Seller,Beacon,NEW\n`;

    async function seedTwoRuns(env, { run2Npn = '22222222', extraRun2InputEntries = [], carryRun1Sent = true } = {}) {
      await env.appCommands.initCompany({
        dbToken: env.ownerToken,
        commandKey: `init-${env.suffix}`,
        slug: 'acme',
        displayName: 'Acme',
        defaultEmitMode: 'coherence',
      });
      const r2Bob = `${BOB_HDR}\n1,EXT-1,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,11111111,Sam Seller,Beacon,ACTIVE_PAYING,ACTIVE,80.00,20.00\n2,EXT-2,CarrierA,7F8G9H0J1K2,Nora V. Fixturemember,NC,MA,MA,2026-10-15,2026-10-15,2026-11-01,,${run2Npn},Robin Agent,Harbor,ACTIVE_PAYING,ACTIVE,160.00,40.00\n`;
      const r2Led = `${LED_HDR}\n101,carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11,EXT-1,1,stmt_nov02,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,2026-11-01,2026-11-02,2026-11-02,2026-10-01,100.00,commission,,100.00,,,,80.00,20.00,11111111,Sam Seller,Beacon,11111111,beacon,ACTIVE_PAYING,active,1,1,1,,\n102,carrier_a~direct~Nora V. Fixturemember~200.00~2026-11,EXT-2,2,stmt_nov09,direct,CarrierA,7F8G9H0J1K2,Nora V. Fixturemember,NC,MA,MA,2026-10-15,2026-10-15,2026-11-01,,2026-11-01,2026-11-09,2026-11-09,2026-10-15,200.00,commission,,200.00,,,,160.00,40.00,${run2Npn},Robin Agent,Harbor,${run2Npn},harbor,ACTIVE_PAYING,active,1,1,1,,\n`;
      const r2Stmt = `${STMT_HDR}\n102,carrier_a~direct~Nora V. Fixturemember~200.00~2026-11,EXT-2,2,stmt_nov09,direct,CarrierA,7F8G9H0J1K2,Nora V. Fixturemember,NC,MA,MA,2026-10-15,2026-10-15,2026-11-01,2026-11-01,2026-11-09,2026-11-09,2026-11-09,200.00,commission,160.00,40.00,${run2Npn},Robin Agent,Harbor,NEW\n`;

      const inpFile = await env.stores.dataStore.promoteBytes(Buffer.from('k\nv\n', 'utf8'), { relPath: 'in.csv', checksPassed: true });
      const b1 = await env.stores.promoteArtifact('emits/canonical_bob.csv', Buffer.from(r1Bob, 'utf8'), { checksPassed: true });
      const l1 = await env.stores.promoteArtifact('emits/coherent_ledger.csv', Buffer.from(r1Led, 'utf8'), { checksPassed: true });
      const s1 = await env.stores.promoteArtifact('emits/statements_20261102.csv', Buffer.from(r1Stmt, 'utf8'), { checksPassed: true });

      const run1 = await env.appCommands.importHistoricalRun({
        dbToken: env.ownerToken,
        commandKey: `r1-${env.suffix}`,
        run: { origin: 'company_import', statementDate: '2026-11-02', sourceFolder: 'company-ws/2026-11-02/runs/2026-11-02', emitMode: 'coherence' },
        inputVersion: { reason: 'r1' },
        inputEntries: [{ relPath: 'in.csv', fileSha256: inpFile.sha256 }],
        stepAttempts: [{
          step: 'emit',
          attemptNo: 1,
          artifacts: [b1, l1, s1].map((a) => ({ relPath: a.relPath, artifactKind: a.artifactKind, storeKind: a.storeKind, fileSha256: a.sha256 })),
        }],
        storedFiles: [inpFile, b1, l1, s1],
      });

      if (carryRun1Sent) {
        await env.appCommands.publishInputVersion({
          dbToken: env.ownerToken,
          commandKey: `standing-${env.suffix}`,
          lineKind: 'standing',
          sourceKind: 'company_import',
          reason: 'standing seed',
          entries: [{ relPath: 'in.csv', fileSha256: inpFile.sha256 }],
          storedFiles: [inpFile],
        });
        await env.appCommands.carrySent({
          dbToken: env.ownerToken,
          commandKey: `carry-r1-${env.suffix}`,
          runId: run1.result.runId,
          typedPhrase: 'sent 2026-11-02',
          reason: 'seed sent run 1',
        });
      }

      const b2 = await env.stores.promoteArtifact('emits/canonical_bob.csv', Buffer.from(r2Bob, 'utf8'), { checksPassed: true });
      const l2 = await env.stores.promoteArtifact('emits/coherent_ledger.csv', Buffer.from(r2Led, 'utf8'), { checksPassed: true });
      const s2 = await env.stores.promoteArtifact('emits/statements_20261109.csv', Buffer.from(r2Stmt, 'utf8'), { checksPassed: true });

      const extraFiles = [];
      const r2Inputs = [
        { relPath: 'in.csv', fileSha256: inpFile.sha256 },
        { relPath: 'Sent/statements_20261102.csv', fileSha256: s1.sha256 },
      ];
      for (const ex of extraRun2InputEntries) {
        const f = await env.stores.dataStore.promoteBytes(Buffer.from(ex.content, 'utf8'), { relPath: ex.relPath, checksPassed: true });
        extraFiles.push(f);
        r2Inputs.push({ relPath: ex.relPath, fileSha256: f.sha256 });
      }

      const run2 = await env.appCommands.importHistoricalRun({
        dbToken: env.ownerToken,
        commandKey: `r2-${env.suffix}`,
        run: { origin: 'company_import', statementDate: '2026-11-09', sourceFolder: 'company-ws/2026-11-09/runs/2026-11-09', emitMode: 'coherence' },
        inputVersion: { reason: 'r2' },
        inputEntries: r2Inputs,
        stepAttempts: [{
          step: 'emit',
          attemptNo: 1,
          artifacts: [b2, l2, s2].map((a) => ({ relPath: a.relPath, artifactKind: a.artifactKind, storeKind: a.storeKind, fileSha256: a.sha256 })),
        }],
        storedFiles: [inpFile, s1, b2, l2, s2, ...extraFiles],
      });
      return { run1Id: run1.result.runId, run2Id: run2.result.runId, b2 };
    }

    await t.test('two-run partial failure (synthetic unmapped NPN in run 2) leaves run 1 committed, hides NPN from stderr, and rerun after fix materializes only run 2', async () => {
      const syntheticUnmappedNpn = '77776666';
      const env = await setupProvisionedEnv('tworun', { includeRobin: false });
      try {
        await seedTwoRuns(env, { run2Npn: syntheticUnmappedNpn });

        // First attempt: run 1 succeeds and commits; run 2 refuses with UNMAPPED_WRITING_NPN without leaking NPN!
        await assert.rejects(
          () => execFileAsync(process.execPath, [
            'scripts/materialize-imported-emits.mjs',
            '--pg-mode', 'local',
            '--host', '127.0.0.1',
            '--port', String(PG_PORT),
            '--database', env.db.dbName,
            '--worker-user', env.workerUser,
            '--readonly-user', env.roUser,
            '--stores-dir', env.storesDir,
            '--key-file', env.serviceKeyFile,
          ], { cwd: process.cwd(), env: env.cliEnv }),
          (err) => {
            const stderrText = String(err.stderr || '');
            assert.equal(stderrText.includes(syntheticUnmappedNpn), false, 'stderr must NEVER contain the unmapped NPN');
            assert.equal(stderrText.includes('Nora V. Fixturemember'), false, 'stderr must NEVER contain member name');
            assert.equal(stderrText.includes('7F8G9H0J1K2'), false, 'stderr must NEVER contain MBI');
            const parsed = JSON.parse(stderrText);
            assert.equal(parsed.passed, false);
            assert.equal(parsed.code, 'UNMAPPED_WRITING_NPN');
            assert.match(parsed.error, /writing_npn/);
            assert.match(parsed.error, /coherence\./);
            return true;
          },
        );

        // Run 1 stayed materialized while run 2 wrote nothing.
        const midMats = (await env.readPool.query(
          "SELECT pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS d FROM coherence.run_materializations ORDER BY statement_date ASC",
        )).rows;
        assert.deepEqual(midMats, [{ d: '2026-11-02' }]);

        // Fix: seed the missing agent with the synthetic NPN in IAM.
        const iamCmd = createIamCommands({ pool: env.appPool });
        await iamCmd.createPerson({
          dbToken: env.ownerToken,
          commandKey: `fix-robin-${env.suffix}`,
          organizationId: env.orgs.harborOrgId,
          legalName: 'Robin Agent',
          preferredName: 'Robin Agent',
          primaryEmail: 'robin.agent@acme.example',
          npn: syntheticUnmappedNpn,
          workArrangement: 'self_employed_internal',
          validRange: '[2020-01-01,)',
        });

        // Rerun materializes ONLY run 2 (run 1 is skipped as already materialized).
        const rerunOut = await execFileAsync(process.execPath, [
          'scripts/materialize-imported-emits.mjs',
          '--pg-mode', 'local',
          '--host', '127.0.0.1',
          '--port', String(PG_PORT),
          '--database', env.db.dbName,
          '--worker-user', env.workerUser,
          '--readonly-user', env.roUser,
          '--stores-dir', env.storesDir,
          '--key-file', env.serviceKeyFile,
        ], { cwd: process.cwd(), env: env.cliEnv });

        assert.equal(rerunOut.stdout.includes(syntheticUnmappedNpn), false, 'report must never contain NPN');
        const rerunJson = JSON.parse(rerunOut.stdout);
        assert.equal(rerunJson.passed, true);
        assert.deepEqual(rerunJson.counts, {
          totalImportedRuns: 2,
          materialized: 1,
          skippedAlreadyMaterialized: 1,
          skippedWithoutEmit: 0,
          skippedAbandoned: 0,
          skippedLegacyMacImport: 0,
        });

        const finalMats = (await env.readPool.query(
          "SELECT pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS d FROM coherence.run_materializations ORDER BY statement_date ASC",
        )).rows;
        assert.deepEqual(finalMats, [{ d: '2026-11-02' }, { d: '2026-11-09' }]);
      } finally {
        await env.cleanup();
      }
    });

    await t.test('missing prior sent date refused in --plan (passed false, dates & counts only) and execute (MISSING_PRIOR_SENT_BATCHES) before writing anything', async () => {
      const env = await setupProvisionedEnv('missprior');
      try {
        await seedTwoRuns(env, {
          extraRun2InputEntries: [
            { relPath: 'Sent/statements_20260824.csv', content: `${STMT_HDR}\n` },
          ],
        });
        const snapBefore = await snapshotMaterializeState(env.readPool);

        // --plan exits non-zero, reports passed: false naming dates and counts only, and writes nothing.
        await assert.rejects(
          () => execFileAsync(process.execPath, [
            'scripts/materialize-imported-emits.mjs',
            '--plan',
            '--pg-mode', 'local',
            '--host', '127.0.0.1',
            '--port', String(PG_PORT),
            '--database', env.db.dbName,
            '--readonly-user', env.roUser,
          ], { cwd: process.cwd(), env: env.cliEnv }),
          (err) => {
            const planJson = JSON.parse(String(err.stdout || ''));
            assert.equal(planJson.plan, true);
            assert.equal(planJson.passed, false);
            assert.deepEqual(planJson.prerequisites, {
              passed: false,
              missingPriorSentDates: ['2026-08-24'],
              missingPriorSentDateCount: 1,
              affectedRunCount: 1,
              missingReferenceCount: 1,
            });
            assert.equal(String(err.stdout).includes('Zelda'), false);
            return true;
          },
        );
        assert.deepEqual(await snapshotMaterializeState(env.readPool), snapBefore, '--plan failure must write nothing');

        // execute refuses with MISSING_PRIOR_SENT_BATCHES BEFORE writing even run 1!
        await assert.rejects(
          () => execFileAsync(process.execPath, [
            'scripts/materialize-imported-emits.mjs',
            '--pg-mode', 'local',
            '--host', '127.0.0.1',
            '--port', String(PG_PORT),
            '--database', env.db.dbName,
            '--worker-user', env.workerUser,
            '--readonly-user', env.roUser,
            '--stores-dir', env.storesDir,
            '--key-file', env.serviceKeyFile,
          ], { cwd: process.cwd(), env: env.cliEnv }),
          (err) => {
            const parsed = JSON.parse(String(err.stderr || ''));
            assert.equal(parsed.passed, false);
            assert.equal(parsed.code, 'MISSING_PRIOR_SENT_BATCHES');
            assert.match(parsed.error, /2026-08-24/);
            return true;
          },
        );
        assert.deepEqual(await snapshotMaterializeState(env.readPool), snapBefore, 'MISSING_PRIOR_SENT_BATCHES must write nothing for run 1 or run 2');
      } finally {
        await env.cleanup();
      }
    });

    await t.test('store-file preflight refuses corrupted run 2 BEFORE writing valid run 1', async () => {
      const env = await setupProvisionedEnv('storepre');
      try {
        const { b2 } = await seedTwoRuns(env);
        const objPath = join(env.storesDir, 'data', 'objects', b2.sha256);
        await chmod(objPath, 0o600);
        const cur = await readFile(objPath, 'utf8');
        await writeFile(objPath, `${cur}#tampered\n`, 'utf8');

        const snapBefore = await snapshotMaterializeState(env.readPool);
        await assert.rejects(
          () => materializeImportedEmitsInDatabase({
            readPool: env.readPool,
            workerPool: env.workerPool,
            stores: env.stores,
            keyFile: env.serviceKeyFile,
          }),
          (err) => err?.code === 'READ_INTEGRITY_FAILED',
        );
        assert.deepEqual(await snapshotMaterializeState(env.readPool), snapBefore, 'corrupted run 2 store file must refuse BEFORE run 1 is written');
      } finally {
        await env.cleanup();
      }
    });
  });
});

test('Materialize Imported Emits [Same-Date Order (is_sent ASC), Bundle Display Matching & Expired Worker Grant Check]', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  await withClusterCatalogLock(async () => {
    await t.test('same-date order materializes unsent before sent so sent run is current, and matches bundles against run.emit_display and company_meta.default_emit_display', async () => {
      const env = await setupProvisionedEnv('order');
      try {
        await env.appCommands.initCompany({
          dbToken: env.ownerToken,
          commandKey: `ord-init-${env.suffix}`,
          slug: 'acme',
          displayName: 'Acme',
          defaultEmitMode: 'generated',
          defaultEmitDisplay: 'Acme Default Brand',
        });

        const inpFile = await env.stores.dataStore.promoteBytes(Buffer.from('k\nv\n', 'utf8'), { relPath: 'in.csv', checksPassed: true });

        // Run A (2026-11-16, folder_number=1, SENT, imported FIRST so lower run journal_seq): amount 80/20, bundle under run.emit_display "Acme Brand".
        const sentBob = `${BOB_HDR}\n1,EXT-1,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,11111111,Sam Seller,Beacon,ACTIVE_PAYING,SENT_STATUS,80.00,20.00\n`;
        const sentLed = `${LED_HDR}\n101,carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11,EXT-1,1,stmt_nov16_sent,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,2026-11-01,2026-11-16,2026-11-16,2026-10-01,100.00,commission,,100.00,,,,80.00,20.00,11111111,Sam Seller,Beacon,11111111,beacon,ACTIVE_PAYING,active,1,1,1,,\n`;
        const sentStmt = `${STMT_HDR}\n101,carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11,EXT-1,1,stmt_nov16_sent,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,2026-11-01,2026-11-16,2026-11-16,2026-11-16,100.00,commission,80.00,20.00,11111111,Sam Seller,Beacon,NEW\n`;
        const sentViewerCfg = {
          role: 'ENTITY_MANAGER',
          statementDate: '2026-11-16',
          corpusTail: '2026-11',
          agencyStart: '2026-01-01',
          features: {
            CANONICAL_BOB: { canonical_bob: 'data/canonical_bob.csv' },
            COHERENT_LEDGER: { coherent_ledger: 'data/coherent_ledger.csv' },
          },
        };
        const sentViewerHtml = `<!doctype html><html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify(sentViewerCfg)};</script></head><body>v</body></html>`;
        const sentVArt = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme Brand/viewer.html', Buffer.from(sentViewerHtml, 'utf8'), { checksPassed: true });
        const sentBArt = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme Brand/data/canonical_bob.csv', Buffer.from(sentBob, 'utf8'), { checksPassed: true });
        const sentLArt = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme Brand/data/coherent_ledger.csv', Buffer.from(sentLed, 'utf8'), { checksPassed: true });
        const sentSArt = await env.stores.promoteArtifact('emits/statements_20261116.csv', Buffer.from(sentStmt, 'utf8'), { checksPassed: true });

        const sentRun = await env.appCommands.importHistoricalRun({
          dbToken: env.ownerToken,
          commandKey: `ord-sent-${env.suffix}`,
          run: {
            origin: 'company_import',
            statementDate: '2026-11-16',
            folderNumber: 1,
            sourceFolder: 'company-ws/2026-11-16-a/runs/2026-11-16',
            emitMode: 'generated',
            emitDisplay: 'Acme Brand',
          },
          inputVersion: { reason: 'sent same-date run' },
          inputEntries: [{ relPath: 'in.csv', fileSha256: inpFile.sha256 }],
          stepAttempts: [{
            step: 'emit',
            attemptNo: 1,
            artifacts: [sentVArt, sentBArt, sentLArt, sentSArt].map((a) => ({ relPath: a.relPath, artifactKind: a.artifactKind, storeKind: a.storeKind, fileSha256: a.sha256 })),
          }],
          storedFiles: [inpFile, sentVArt, sentBArt, sentLArt, sentSArt],
        });

        await env.appCommands.publishInputVersion({
          dbToken: env.ownerToken,
          commandKey: `ord-stand-${env.suffix}`,
          lineKind: 'standing',
          sourceKind: 'company_import',
          reason: 'standing',
          entries: [{ relPath: 'in.csv', fileSha256: inpFile.sha256 }],
          storedFiles: [inpFile],
        });
        await env.appCommands.carrySent({
          dbToken: env.ownerToken,
          commandKey: `ord-carry-${env.suffix}`,
          runId: sentRun.result.runId,
          typedPhrase: 'sent 2026-11-16',
          reason: 'seed sent same-date run',
        });

        // Run B (2026-11-16, folder_number=1, UNSENT, imported SECOND so higher run journal_seq): amount 40/10,
        // emit_display NULL so its entity-manager bundle matches company_meta.default_emit_display ("Acme Default Brand").
        const unsentBob = `${BOB_HDR}\n1,EXT-1,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,11111111,Sam Seller,Beacon,ACTIVE_PAYING,UNSENT_STATUS,40.00,10.00\n`;
        const unsentLed = `${LED_HDR}\n101,carrier_a~direct~Zelda Q. Plantedname~50.00~2026-11,EXT-1,1,stmt_nov16_unsent,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,2026-11-01,2026-11-16,2026-11-16,2026-10-01,50.00,commission,,50.00,,,,40.00,10.00,11111111,Sam Seller,Beacon,11111111,beacon,ACTIVE_PAYING,active,1,1,1,,\n`;
        const unsentStmt = `${STMT_HDR}\n101,carrier_a~direct~Zelda Q. Plantedname~50.00~2026-11,EXT-1,1,stmt_nov16_unsent,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,2026-11-01,2026-11-16,2026-11-16,2026-11-16,50.00,commission,40.00,10.00,11111111,Sam Seller,Beacon,NEW\n`;
        const unsentViewerHtml = `<!doctype html><html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify({
          role: 'ENTITY_MANAGER',
          statementDate: '2026-11-16',
          features: {
            CANONICAL_BOB: { canonical_bob: 'data/canonical_bob.csv' },
            COHERENT_LEDGER: { coherent_ledger: 'data/coherent_ledger.csv' },
          },
        })};</script></head><body>v</body></html>`;
        const uVArt = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme Default Brand/viewer.html', Buffer.from(unsentViewerHtml, 'utf8'), { checksPassed: true });
        const uBArt = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme Default Brand/data/canonical_bob.csv', Buffer.from(unsentBob, 'utf8'), { checksPassed: true });
        const uLArt = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme Default Brand/data/coherent_ledger.csv', Buffer.from(unsentLed, 'utf8'), { checksPassed: true });
        const uSArt = await env.stores.promoteArtifact('emits/statements_20261116.csv', Buffer.from(unsentStmt, 'utf8'), { checksPassed: true });

        const unsentRun = await env.appCommands.importHistoricalRun({
          dbToken: env.ownerToken,
          commandKey: `ord-unsent-${env.suffix}`,
          run: {
            origin: 'company_import',
            statementDate: '2026-11-16',
            folderNumber: 1,
            sourceFolder: 'company-ws/2026-11-16-b/runs/2026-11-16',
            emitMode: 'coherence',
          },
          inputVersion: { reason: 'unsent same-date run' },
          inputEntries: [{ relPath: 'in.csv', fileSha256: inpFile.sha256 }],
          stepAttempts: [{
            step: 'emit',
            attemptNo: 1,
            artifacts: [uVArt, uBArt, uLArt, uSArt].map((a) => ({ relPath: a.relPath, artifactKind: a.artifactKind, storeKind: a.storeKind, fileSha256: a.sha256 })),
          }],
          storedFiles: [inpFile, uVArt, uBArt, uLArt, uSArt],
        });

        // --plan must list unsent first (is_sent ASC) and sent second!
        const plan = await planImportedEmitMaterializations({ readPool: env.readPool });
        assert.equal(plan.passed, true);
        assert.deepEqual(
          plan.runs.map((r) => ({ runId: r.runId, sent: r.sent })),
          [
            { runId: unsentRun.result.runId, sent: false },
            { runId: sentRun.result.runId, sent: true },
          ],
        );

        const matRes = await materializeImportedEmitsInDatabase({
          readPool: env.readPool,
          workerPool: env.workerPool,
          stores: env.stores,
          keyFile: env.serviceKeyFile,
        });
        assert.equal(matRes.passed, true);
        assert.equal(matRes.counts.materialized, 2);

        // Because sent was materialized AFTER unsent, the SENT run has the higher rm.journal_seq and is current!
        const cur = await inReadTx(env.appPool, env.ownerToken, async (tx) => ({
          bob: (await tx.query('SELECT run_id, coherent_status, amount::text AS amount FROM app_views.v_current_policy_periods')).rows,
          led: (await tx.query('SELECT run_id, gross_comm::text AS gross_comm FROM app_views.v_current_commission_ledger')).rows,
        }));
        assert.deepEqual(cur.bob, [{ run_id: sentRun.result.runId, coherent_status: 'SENT_STATUS', amount: '80.00' }]);
        assert.deepEqual(cur.led, [{ run_id: sentRun.result.runId, gross_comm: '100.00' }]);
      } finally {
        await env.cleanup();
      }
    });

    await t.test('active worker principal lookup respects valid_range and rejects exclusive selector conflict', async () => {
      const env = await setupProvisionedEnv('wkgrant');
      const adminPool = await createPool(env.db.pgConfig);
      env.closeables.push(adminPool);
      try {
        const dbContext = (await env.readPool.query(
          'SELECT environment, db_role_kind, company_slug, tenant_org_id FROM iam.database_context WHERE singleton = true',
        )).rows[0];

        await assert.rejects(
          () => createWorkerTokenProvider(env.readPool, {
            keyFile: env.serviceKeyFile,
            workerPersonId: randomUUID(),
            workerName: 'Coherence Worker',
            dbContext,
          }),
          (err) => err?.code === 'INVALID_CLI_ARGS',
        );

        // Replace the worker's active grant with an expired valid_range grant in the past.
        const grantRow = (await env.readPool.query(
          `SELECT g.id, g.person_id, g.role_id, g.organization_id, g.include_descendants, g.person_scope_mode
           FROM iam.role_grants g
           JOIN iam.roles r ON r.id = g.role_id
           WHERE r.slug = 'coherence_worker_svc' AND g.superseded_by_id IS NULL AND g.status = 'active'`,
        )).rows[0];
        assert.ok(grantRow);
        await withSerializableTx(adminPool, async (c) => {
          const j = await appendIamAuditEntry(c, {
            environment: 'dev',
            commandKind: 'iam.test_expire_worker_grant',
            commandKey: `expire-wk-${env.suffix}`,
          });
          await c.query(
            `INSERT INTO iam.role_grants (
               id, person_id, role_id, organization_id, include_descendants, person_scope_mode,
               valid_range, status, replaces_id, journal_seq
             ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, '[2020-01-01,2020-12-31)'::daterange, 'active', $7::uuid, $8)`,
            [
              randomUUID(),
              grantRow.person_id,
              grantRow.role_id,
              grantRow.organization_id,
              grantRow.include_descendants,
              grantRow.person_scope_mode,
              grantRow.id,
              j.seq,
            ],
          );
        });

        await assert.rejects(
          () => createWorkerTokenProvider(env.readPool, {
            keyFile: env.serviceKeyFile,
            dbContext,
          }),
          (err) => err?.code === 'WORKER_NOT_FOUND',
          'expired valid_range worker grant must not be treated as active',
        );
      } finally {
        await env.cleanup();
      }
    });
  });
});

test('Materialize Imported Emits [Mismatched & Conflicting Files Refuse Run All-or-Nothing]: corrupted store bytes, BoB/Ledger drift, statement tie drift, statements filename date mismatch, conflicting direct/bundle copies, missing artifact, lone unmatched bundle, wrong viewer role, conflicting metadata, and bad CSV cell', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  await withClusterCatalogLock(async () => {
    const cases = [
      {
        name: 'corrupted store bytes on disk',
        expectedCode: 'READ_INTEGRITY_FAILED',
        corruptBobOnDisk: true,
      },
      {
        name: 'BoB-to-Ledger $0.01 conservation mismatch',
        expectedCode: 'CONSERVATION_MISMATCH',
        bobOverride: (csv) => csv.replace(',80.00,20.00', ',80.01,20.00'),
      },
      {
        name: 'Statement-to-Ledger $0.01 mismatch refused at PostgreSQL COMMIT',
        expectedCode: 'INVARIANT_VIOLATION',
        stmtOverride: (csv) => csv.replace(',100.00,commission,80.00,20.00,', ',100.01,commission,80.01,20.00,'),
      },
      {
        name: 'statements filename date disagrees with run statement_date',
        expectedCode: 'STATEMENTS_DATE_MISMATCH',
        stmtRelPath: 'emits/statements_20261199.csv',
      },
      {
        name: 'conflicting direct and entity-manager bundle canonical_bob.csv',
        expectedCode: 'CONFLICTING_EMIT_ARTIFACTS',
        extraBundleBobCsv: 'policy_id,entity,amount,upline_amount\n99,Beacon,1.00,0.00\n',
      },
      {
        name: 'missing required coherent_ledger.csv on company_import run',
        expectedCode: 'MISSING_EMIT_ARTIFACTS',
        omitLedger: true,
      },
      {
        name: 'lone entity-manager bundle matching none of emit_display/default_emit_display/company name',
        expectedCode: 'UNMATCHED_ENTITY_BUNDLE',
        extraBundlePrefix: 'emits/bundles/entity-managers/SomeOtherOrg/',
        extraBundleViewerCfg: { role: 'ENTITY_MANAGER', statementDate: '2026-11-15', features: {} },
      },
      {
        name: 'entity-manager bundle viewer.html with non-ENTITY_MANAGER role',
        expectedCode: 'INVALID_VIEWER_ROLE',
        extraBundlePrefix: 'emits/bundles/entity-managers/Acme/',
        extraBundleViewerCfg: { role: 'AGENCY_MANAGER', statementDate: '2026-11-15', features: {} },
      },
      {
        name: 'conflicting metadata between policy_status_meta.json and viewer.html',
        expectedCode: 'CONFLICTING_EMIT_METADATA',
        extraBundlePrefix: 'emits/bundles/entity-managers/Acme/',
        extraBundleViewerCfg: { role: 'ENTITY_MANAGER', statementDate: '2026-11-15', corpusTail: '2026-10', features: {} },
        policyStatusMeta: { statementDate: '2026-11-15', corpusTail: '2026-11' },
      },
      {
        name: 'invalid money cell in canonical_bob.csv never leaks cell value to stderr',
        expectedCode: 'INVALID_MONEY_AMOUNT',
        bobOverride: (csv) => csv.replace(',80.00,20.00', ',SECRET_CELL_VAL_5544,20.00'),
        forbiddenInStderr: 'SECRET_CELL_VAL_5544',
      },
    ];

    for (const tc of cases) {
      await t.test(tc.name, async () => {
        const env = await setupProvisionedEnv('matbad');
        try {
          await env.appCommands.initCompany({
            dbToken: env.ownerToken,
            commandKey: `mb-init-${env.suffix}`,
            slug: 'acme',
            displayName: 'Acme',
            defaultEmitMode: 'coherence',
          });

          const baseBob = `${BOB_HDR}\n1,EXT-1,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,11111111,Sam Seller,Beacon,ACTIVE_PAYING,ACTIVE,80.00,20.00\n`;
          const baseLed = `${LED_HDR}\n1,carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11,EXT-1,1,stmt_nov,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,,2026-11-01,2026-11-15,2026-11-15,2026-10-01,100.00,commission,,100.00,,,,80.00,20.00,11111111,Sam Seller,Beacon,11111111,beacon,ACTIVE_PAYING,active,1,1,1,,\n`;
          const baseStmt = `${STMT_HDR}\n1,carrier_a~direct~Zelda Q. Plantedname~100.00~2026-11,EXT-1,1,stmt_nov,direct,CarrierA,1A2B3C4D5E6,Zelda Q. Plantedname,FL,MA,MA,2026-10-01,2026-10-01,2026-11-01,2026-11-01,2026-11-15,2026-11-15,2026-11-15,100.00,commission,80.00,20.00,11111111,Sam Seller,Beacon,NEW\n`;

          const bobCsv = tc.bobOverride ? tc.bobOverride(baseBob) : baseBob;
          const stmtCsv = tc.stmtOverride ? tc.stmtOverride(baseStmt) : baseStmt;
          const stmtRel = tc.stmtRelPath || 'emits/statements_20261115.csv';

          const inpFile = await env.stores.dataStore.promoteBytes(Buffer.from('k\nv\n', 'utf8'), { relPath: 'in.csv', checksPassed: true });
          const bobArt = await env.stores.promoteArtifact('emits/canonical_bob.csv', Buffer.from(bobCsv, 'utf8'), { checksPassed: true });
          const stmtArt = await env.stores.promoteArtifact(stmtRel, Buffer.from(stmtCsv, 'utf8'), { checksPassed: true });
          const storedFiles = [inpFile, bobArt, stmtArt];
          const artifacts = [
            { relPath: bobArt.relPath, artifactKind: bobArt.artifactKind, storeKind: bobArt.storeKind, fileSha256: bobArt.sha256 },
            { relPath: stmtArt.relPath, artifactKind: stmtArt.artifactKind, storeKind: stmtArt.storeKind, fileSha256: stmtArt.sha256 },
          ];
          if (!tc.omitLedger) {
            const ledArt = await env.stores.promoteArtifact('emits/coherent_ledger.csv', Buffer.from(baseLed, 'utf8'), { checksPassed: true });
            storedFiles.push(ledArt);
            artifacts.push({ relPath: ledArt.relPath, artifactKind: ledArt.artifactKind, storeKind: ledArt.storeKind, fileSha256: ledArt.sha256 });
          }
          if (tc.extraBundleBobCsv) {
            const extraArt = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme/data/canonical_bob.csv', Buffer.from(tc.extraBundleBobCsv, 'utf8'), { checksPassed: true });
            storedFiles.push(extraArt);
            artifacts.push({ relPath: extraArt.relPath, artifactKind: extraArt.artifactKind, storeKind: extraArt.storeKind, fileSha256: extraArt.sha256 });
          }
          if (tc.extraBundleViewerCfg) {
            const viewerHtml = `<!doctype html><html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify(tc.extraBundleViewerCfg)};</script></head><body>v</body></html>`;
            const vArt = await env.stores.promoteArtifact(`${tc.extraBundlePrefix}viewer.html`, Buffer.from(viewerHtml, 'utf8'), { checksPassed: true });
            storedFiles.push(vArt);
            artifacts.push({ relPath: vArt.relPath, artifactKind: vArt.artifactKind, storeKind: vArt.storeKind, fileSha256: vArt.sha256 });
          }
          if (tc.policyStatusMeta) {
            const mArt = await env.stores.promoteArtifact('emits/policy_status_meta.json', Buffer.from(JSON.stringify(tc.policyStatusMeta), 'utf8'), { checksPassed: true });
            storedFiles.push(mArt);
            artifacts.push({ relPath: mArt.relPath, artifactKind: mArt.artifactKind, storeKind: mArt.storeKind, fileSha256: mArt.sha256 });
          }

          await env.appCommands.importHistoricalRun({
            dbToken: env.ownerToken,
            commandKey: `mb-run-${env.suffix}`,
            run: {
              origin: 'company_import',
              statementDate: '2026-11-15',
              sourceFolder: 'company-workspaces/acme/2026-11-15/runs/2026-11-15',
              emitMode: 'coherence',
            },
            inputVersion: { reason: 'mismatch test' },
            inputEntries: [{ relPath: 'in.csv', fileSha256: inpFile.sha256 }],
            stepAttempts: [{ step: 'emit', attemptNo: 1, artifacts }],
            storedFiles,
          });

          if (tc.corruptBobOnDisk) {
            const objPath = join(env.storesDir, 'data', 'objects', bobArt.sha256);
            await chmod(objPath, 0o600);
            const cur = await readFile(objPath, 'utf8');
            await writeFile(objPath, `${cur}#tampered\n`, 'utf8');
          }

          const snapBefore = await snapshotMaterializeState(env.readPool);

          await assert.rejects(
            () => execFileAsync(process.execPath, [
              'scripts/materialize-imported-emits.mjs',
              '--pg-mode', 'local',
              '--host', '127.0.0.1',
              '--port', String(PG_PORT),
              '--database', env.db.dbName,
              '--worker-user', env.workerUser,
              '--readonly-user', env.roUser,
              '--stores-dir', env.storesDir,
              '--key-file', env.serviceKeyFile,
            ], { cwd: process.cwd(), env: env.cliEnv }),
            (err) => {
              const stderrText = String(err.stderr || '');
              assert.equal(stderrText.includes('Zelda Q. Plantedname'), false, 'error output must never leak member name');
              assert.equal(stderrText.includes('1A2B3C4D5E6'), false, 'error output must never leak MBI');
              if (tc.forbiddenInStderr) {
                assert.equal(stderrText.includes(tc.forbiddenInStderr), false, `error output must never leak ${tc.forbiddenInStderr}`);
              }
              const parsed = JSON.parse(stderrText);
              assert.equal(parsed.passed, false);
              assert.equal(parsed.code, tc.expectedCode, `expected code ${tc.expectedCode}, got ${parsed.code}: ${parsed.error}`);
              return true;
            },
          );

          assert.deepEqual(
            await snapshotMaterializeState(env.readPool),
            snapBefore,
            `${tc.name}: refusal must write nothing for the run`,
          );
        } finally {
          await env.cleanup();
        }
      });
    }
  });
});
