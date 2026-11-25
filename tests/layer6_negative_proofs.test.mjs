// Layer 6: Non-vacuous negative proofs on throwaway test_* databases (PLAN section 5.7).
// Verifies all five mandatory mutations fail at exactly the expected gate without leaking PHI:
//   1. Bible decision mutation (fails Gate 2 BoB, Gate 3 Ledger, Gate 4 statements + exact entity cent shift)
//   2. Adjust decision mutation (fails Gate 3 Ledger, Gate 4 statements + exact entity cent shift)
//   3. Comparator sensitivity ($0.01 perturbation, '100.00' vs '100', entity swap preserving grand total, zero PHI)
//   4. Input gate (1-byte change in input/Agent Data/cleanagentdata.csv fails Gate 1 immediately)
//   5. Journal tamper and cutoff isolation (1-char NDJSON tamper, dropped child row, T1 vs T2 rebuild isolation)
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { createCommandLayer } from '../src/commands/command-layer.mjs';
import {
  compareDatabasesAsOf,
  exportJournalNdjson,
  rebuildFromJournalExport,
} from '../src/commands/journal-export.mjs';
import { compareDbRuns, compareRunFolders } from '../src/compare/run-comparator.mjs';
import { runMigrations } from '../src/db/migrate.mjs';
import { createClient, createPool, resolveLocalUser } from '../src/db/pg-client.mjs';
import { createMemoryObjectStore } from '../src/storage/object-store.mjs';
import { createCodeStore, createDataStore, createStorePair } from '../src/storage/stores.mjs';
import { seedCoherenceIamFixture } from './helpers/iam-harness.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import {
  buildSyntheticEmitDataset,
  makeCsvFromObjects,
  seedEngineCopyVersion,
  seedStandingInput,
  SYNTHETIC_BOB_COLUMNS,
  SYNTHETIC_LEDGER_COLUMNS,
  SYNTHETIC_RUN_COLUMNS,
} from './helpers/fixtures.mjs';
import { checkPgAvailable, getAdminPgConfig } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();
const LAYER6_DB_RE = /^test_[a-z0-9_]+$/;

function assertLayer6TestDbName(dbName) {
  if (typeof dbName !== 'string' || !LAYER6_DB_RE.test(dbName)) {
    throw new Error(`Layer 6 strictly enforces throwaway test_* databases; got ${dbName}`);
  }
}

async function createLayer6TestEnv({ companySlug = 'acme', displayName = 'Acme' } = {}) {
  const suffix = randomBytes(5).toString('hex');
  const dbName = `test_l6_${suffix}`;
  assertLayer6TestDbName(dbName);
  const adminConfig = getAdminPgConfig();

  const admin = await createClient(adminConfig);
  try {
    await admin.query(`CREATE DATABASE "${dbName}" ENCODING 'UTF8'`);
  } finally {
    await admin.end();
  }

  const pgConfig = { ...adminConfig, database: dbName };
  const pool = await createPool(pgConfig);
  await runMigrations(pool);

  const codeStore = createCodeStore({ backend: createMemoryObjectStore({ label: `l6-code-${suffix}` }) });
  const dataStore = createDataStore({ backend: createMemoryObjectStore({ label: `l6-data-${suffix}` }) });
  const stores = createStorePair({ codeStore, dataStore });
  const commands = createCommandLayer({ pool, companySlug, stores });
  const tempDir = await mkdtemp(join(tmpdir(), `coherence-l6-${suffix}-`));
  const iam = await seedCoherenceIamFixture(pool, { companySlug, displayName });
  const ownerToken = iam.tokens.owner;
  const workerToken = iam.tokens.worker;

  await commands.initCompany({
    dbToken: ownerToken,
    commandKey: `l6-init-${suffix}`,
    slug: companySlug,
    displayName,
    defaultEmitMode: 'coherence',
  });

  const workers = [];
  const registerWorker = (w) => {
    workers.push(w);
    return w;
  };

  async function cleanup() {
    for (const w of workers) await w.stop().catch(() => {});
    await pool.end().catch(() => {});
    const dropAdmin = await createClient(adminConfig).catch(() => null);
    if (dropAdmin) {
      try {
        assertLayer6TestDbName(dbName);
        await dropAdmin.query(
          'SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()',
          [dbName],
        );
        await dropAdmin.query(`DROP DATABASE IF EXISTS "${dbName}"`);
      } finally {
        await dropAdmin.end().catch(() => {});
      }
    }
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }

  return { dbName, companySlug, displayName, pgConfig, pool, codeStore, dataStore, stores, commands, tempDir, iam, ownerToken, workerToken, registerWorker, cleanup };
}

async function createEmptyTestDb() {
  const suffix = randomBytes(5).toString('hex');
  const dbName = `test_l6_reb_${suffix}`;
  assertLayer6TestDbName(dbName);
  const adminConfig = getAdminPgConfig();
  const admin = await createClient(adminConfig);
  try {
    await admin.query(`CREATE DATABASE "${dbName}" ENCODING 'UTF8'`);
  } finally {
    await admin.end();
  }
  const pool = await createPool({ ...adminConfig, database: dbName });
  await runMigrations(pool);
  async function cleanup() {
    await pool.end().catch(() => {});
    const dropAdmin = await createClient(adminConfig).catch(() => null);
    if (dropAdmin) {
      try {
        assertLayer6TestDbName(dbName);
        await dropAdmin.query(
          'SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()',
          [dbName],
        );
        await dropAdmin.query(`DROP DATABASE IF EXISTS "${dbName}"`);
      } finally {
        await dropAdmin.end().catch(() => {});
      }
    }
  }
  return { dbName, pool, cleanup };
}

/**
 * Decision-aware synthetic Python engine copy (E1+E2): reads runs/<date>/overlay.csv generated
 * from PostgreSQL decision records and reflects Bible and Adjust CORRECT decisions faithfully
 * into canonical_bob.csv, coherent_ledger.csv, statements_YYYYMMDD.csv, and emit_metadata.json
 * while maintaining exact $0.00 BoB-to-Ledger and Entity-Statement conservation.
 */
function createDecisionAwareMockEngineMaterializer({ fixedCodeHash = 'c0ffee1' } = {}) {
  return async function materializeEngine({ workspaceDir }) {
    const writePy = async (relPath, code) => {
      const full = join(workspaceDir, ...relPath.split('/'));
      await mkdir(dirname(full), { recursive: true });
      await writeFile(full, code, 'utf8');
      return full;
    };
    const pyLit = (v) => (v == null ? 'None' : JSON.stringify(v));

    await writePy('coherence/__init__.py', '');
    await writePy('coherence/phase1/__init__.py', '');
    await writePy('coherence/phase2/__init__.py', '');
    await writePy('coherence/phase3/__init__.py', '');
    await writePy('coherence/phase4/__init__.py', '');

    await writePy('coherence/phase1/assign.py', `
import json, shutil, sys
from pathlib import Path
ROOT = Path(${pyLit(workspaceDir)})
date = sys.argv[1]
run_dir = ROOT / "runs" / date
shutil.rmtree(run_dir, ignore_errors=True)
run_dir.mkdir(parents=True)
shutil.copytree(ROOT / "input", run_dir / "input")
working = run_dir / "working"
working.mkdir()
(working / "tx.csv").write_text(
    "tx_id,filename,sheet_name,source_position\\n"
    "1,carrier_a_202611.xlsx,Commissions,14\\n"
    "2,carrier_b_202611.xlsx,Detail,22\\n"
    "3,carrier_a_202611.xlsx,Variance,31\\n",
    encoding="utf-8",
)
state = {"date": date, "born": "2026-11-02T12:00:00.000000000", "steps": {"assign": {"at": "2026-11-02T12:00:01", "code": ${pyLit(fixedCodeHash)}, "seconds": 0.1}}}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
`);

    await writePy('coherence/phase2/attribute.py', `
import json, sys
from pathlib import Path
ROOT = Path(${pyLit(workspaceDir)})
date = sys.argv[1]
run_dir = ROOT / "runs" / date
state = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
state["steps"]["attribute"] = {"at": "2026-11-02T12:00:02", "code": ${pyLit(fixedCodeHash)}, "seconds": 0.1}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
`);

    await writePy('coherence/phase3/bible.py', `
import csv, json, sys
from pathlib import Path
ROOT = Path(${pyLit(workspaceDir)})
date = sys.argv[1]
run_dir = ROOT / "runs" / date
state = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
items = [
    {"record_id": "policy:carrier_a:C-101#effective:2026-10-01", "case": "BIBLE", "subtype": "CONFLICT", "entity": "Beacon", "npn": "11111111", "amount": "100.00"},
    {"record_id": "policy:carrier_b:C-201#effective:2026-10-01", "case": "BIBLE", "subtype": "CONFLICT", "entity": "Harbor", "npn": "33333333", "amount": "200.00"},
]
with open(run_dir / "bible.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=["record_id", "case", "subtype", "entity", "npn", "amount"])
    w.writeheader()
    w.writerows(items)
cfg = {"statementDate": date, "build": ${pyLit(fixedCodeHash)}, "stamped": True, "surface": "bible", "runBorn": state["born"], "queue": items, "overlay": [], "reconfirm": {}, "checksum": "bible-l6"}
(run_dir / "bible.json").write_text(json.dumps(cfg, indent=2) + "\\n", encoding="utf-8")
state["steps"]["bible"] = {"at": "2026-11-02T12:00:03", "code": ${pyLit(fixedCodeHash)}, "seconds": 0.1, "bible_items": len(items)}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
`);

    await writePy('coherence/phase3/adjust.py', `
import csv, json, sys
from pathlib import Path
ROOT = Path(${pyLit(workspaceDir)})
date = sys.argv[1]
run_dir = ROOT / "runs" / date
if not (run_dir / "overlay.csv").is_file():
    print("adjust requires generated overlay.csv", file=sys.stderr)
    sys.exit(1)
state = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
items = [
    {"record_id": "carrier_a~direct~PAT SAMPLE~100.00~2026-11", "case": "NEW", "subtype": "NEW_BUSINESS", "entity": "Beacon", "npn": "11111111", "amount": "100.00"},
    {"record_id": "carrier_a~direct~VAR ITEM~50.00~2026-11", "case": "VARIANCE", "subtype": "ENTITY_MOVE", "entity": "Beacon", "npn": "11111111", "amount": "50.00"},
]
with open(run_dir / "adjust.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=["record_id", "case", "subtype", "entity", "npn", "amount"])
    w.writeheader()
    w.writerows(items)
cfg = {"statementDate": date, "build": ${pyLit(fixedCodeHash)}, "stamped": True, "surface": "adjust", "runBorn": state["born"], "queue": items, "overlay": [], "reconfirm": {}, "checksum": "adjust-l6"}
(run_dir / "adjust.json").write_text(json.dumps(cfg, indent=2) + "\\n", encoding="utf-8")
state["steps"]["adjust"] = {"at": "2026-11-02T12:00:04", "code": ${pyLit(fixedCodeHash)}, "seconds": 0.1, "queue_items": len(items)}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
`);

    await writePy('coherence/phase4/emit.py', `
import csv, json, shutil, sys
from pathlib import Path
ROOT = Path(${pyLit(workspaceDir)})
date = sys.argv[1]
run_dir = ROOT / "runs" / date
ov_path = run_dir / "overlay.csv"
if not ov_path.is_file():
    print("emit requires generated overlay.csv", file=sys.stderr)
    sys.exit(1)

# Derive current decisions per key (last row wins, matching overlay.current())
current = {}
with open(ov_path, newline="", encoding="utf-8-sig") as fh:
    for row in csv.DictReader(fh):
        if row.get("record_id"):
            current[row["record_id"]] = row

p1_key = "policy:carrier_a:C-101#effective:2026-10-01"
p1_dec = current.get(p1_key)
p1_entity = p1_dec["agency"] if (p1_dec and p1_dec.get("disposition") == "CORRECT" and p1_dec.get("agency")) else "Beacon"
p1_status = p1_dec["status"] if (p1_dec and p1_dec.get("disposition") == "CORRECT" and p1_dec.get("status")) else "ACTIVE_PAYING"

var_key = "carrier_a~direct~VAR ITEM~50.00~2026-11"
var_dec = current.get(var_key)
var_entity = var_dec["agency"] if (var_dec and var_dec.get("disposition") == "CORRECT" and var_dec.get("agency")) else "Beacon"

bob_cols = ${pyLit(SYNTHETIC_BOB_COLUMNS)}
led_cols = ${pyLit(SYNTHETIC_LEDGER_COLUMNS)}
run_cols = ${pyLit(SYNTHETIC_RUN_COLUMNS)}

bob_rows = [
    {
        "external_policy_id": "POL-101", "policy_id": "1", "carrier_policy_number": "C-101", "crm_policy_number": "CRM-101",
        "enrollment_code": "ENR-101", "carrier": "carrier_a", "plan_type": "MA", "plan_name": "Gold MA", "simple_plan_type": "MA",
        "mbi": "1EG4-TE5-MK72", "member": "Zelda Q. Plantedname", "dob": "1955-04-12", "phone": "555-867-5309", "email": "zelda@example.test",
        "address": "742 Evergreen Terrace", "county": "WAKE", "state": "NC",
        "submission_date": "2026-09-15", "origin_effective": "2026-10-01", "effective_date": "2026-10-01", "termination_date": "",
        "min_date": "2026-09-15", "anchor_date": "2026-09-15",
        "amount": "80.00", "upline_amount": "20.00", "writing_npn": "11111111", "writing_agent": "Sam Seller", "entity": p1_entity,
        "agency_id": f"AG-{p1_entity.upper()}", "status": p1_status, "conflicts": "", "spine_source": "cbob_c", "confidence_level": "100",
    },
    {
        "external_policy_id": "POL-201", "policy_id": "2", "carrier_policy_number": "C-201", "crm_policy_number": "CRM-201",
        "enrollment_code": "ENR-201", "carrier": "carrier_b", "plan_type": "PDP", "plan_name": "Basic PDP", "simple_plan_type": "PDP",
        "mbi": "3EF4-GH5-JK67", "member": "Casey Mock", "dob": "1960-01-05", "phone": "555-222-3333", "email": "casey@example.test",
        "address": "300 Pine Rd", "county": "MECKLENBURG", "state": "NC",
        "submission_date": "2026-09-22", "origin_effective": "2026-10-01", "effective_date": "2026-10-01", "termination_date": "",
        "min_date": "2026-09-22", "anchor_date": "2026-09-22",
        "amount": "160.00", "upline_amount": "40.00", "writing_npn": "33333333", "writing_agent": "Robin Harbor", "entity": "Harbor",
        "agency_id": "AG-HARBOR", "status": "ACTIVE_PAYING", "conflicts": "", "spine_source": "cbob_c", "confidence_level": "95",
    },
]

led_rows = [
    {
        "record_id": "carrier_a~direct~PAT SAMPLE~100.00~2026-11", "external_policy_id": "POL-101", "policy_id": "1", "tx_id": "1",
        "statement_name": "carrier_a_202611.csv", "src_type": "direct", "carrier": "carrier_a", "mbi": "1EG4-TE5-MK72", "member": "Zelda Q. Plantedname",
        "state": "NC", "plan_type": "MA", "simple_plan_type": "MA",
        "submission_date": "2026-09-15", "origin_effective": "2026-10-01", "effective_date": "2026-10-01", "termination_date": "",
        "earned_date": "2026-11-01", "payment_date": "2026-11-02", "statement_date": date, "min_date": "2026-09-15",
        "gross_comm": "100.00", "revenue_type": "commission", "override_amount": "", "commission_amount": "100.00", "hra_amount": "", "fee_amount": "", "other_amount": "",
        "downline_amount": "80.00", "upline_amount": "20.00",
        "writing_npn": "11111111", "writing_agent": "Sam Seller", "entity": p1_entity, "payee_npn": "", "agency_id": f"AG-{p1_entity.upper()}",
        "status": p1_status, "policy_status": "active", "cbob_c": "true", "cbob_s": "false", "sf": "true", "notes": "", "coherent_notes": "NEW",
    },
    {
        "record_id": "carrier_b~direct~CASEY MOCK~200.00~2026-11", "external_policy_id": "POL-201", "policy_id": "2", "tx_id": "2",
        "statement_name": "carrier_b_202611.csv", "src_type": "direct", "carrier": "carrier_b", "mbi": "3EF4-GH5-JK67", "member": "Casey Mock",
        "state": "NC", "plan_type": "PDP", "simple_plan_type": "PDP",
        "submission_date": "2026-09-22", "origin_effective": "2026-10-01", "effective_date": "2026-10-01", "termination_date": "",
        "earned_date": "2026-11-01", "payment_date": "2026-11-02", "statement_date": date, "min_date": "2026-09-22",
        "gross_comm": "200.00", "revenue_type": "commission", "override_amount": "", "commission_amount": "200.00", "hra_amount": "", "fee_amount": "", "other_amount": "",
        "downline_amount": "160.00", "upline_amount": "40.00",
        "writing_npn": "33333333", "writing_agent": "Robin Harbor", "entity": "Harbor", "payee_npn": "", "agency_id": "AG-HARBOR",
        "status": "ACTIVE_PAYING", "policy_status": "active", "cbob_c": "true", "cbob_s": "false", "sf": "false", "notes": "", "coherent_notes": "NEW",
    },
    {
        # Non-policy agent variance item (affected by Adjust decision without changing policy BoB)
        "record_id": var_key, "external_policy_id": "", "policy_id": "", "tx_id": "3",
        "statement_name": "carrier_a_202611.csv", "src_type": "direct", "carrier": "carrier_a", "mbi": "", "member": "",
        "state": "NC", "plan_type": "", "simple_plan_type": "",
        "submission_date": "", "origin_effective": "", "effective_date": "", "termination_date": "",
        "earned_date": "2026-11-01", "payment_date": "2026-11-02", "statement_date": date, "min_date": "2026-11-01",
        "gross_comm": "50.00", "revenue_type": "fee", "override_amount": "", "commission_amount": "", "hra_amount": "", "fee_amount": "50.00", "other_amount": "",
        "downline_amount": "40.00", "upline_amount": "10.00",
        "writing_npn": "11111111", "writing_agent": "Sam Seller", "entity": var_entity, "payee_npn": "", "agency_id": f"AG-{var_entity.upper()}",
        "status": "", "policy_status": "", "cbob_c": "false", "cbob_s": "false", "sf": "false", "notes": "variance fee", "coherent_notes": "NEW",
    },
]

stmt_rows = [{**r, "run_action": "NEW", "run_statement_date": date, "reversal_of": "", "reason": "new"} for r in led_rows]

emits = run_dir / "emits"
shutil.rmtree(emits, ignore_errors=True)
emits.mkdir(parents=True)
stamp = date.replace("-", "")

def write_csv(path, cols, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, lineterminator="\\n")
        w.writeheader()
        w.writerows(rows)

write_csv(emits / "canonical_bob.csv", bob_cols, bob_rows)
write_csv(emits / "coherent_ledger.csv", led_cols, led_rows)
write_csv(emits / f"statements_{stamp}.csv", run_cols, stmt_rows)
meta = {
    "statementDate": date, "build": ${pyLit(fixedCodeHash)}, "corpusTail": date[:7], "agencyStart": "2026-01-01",
    "coherentStatus": {"1": p1_status, "2": "ACTIVE_PAYING"},
    "coherentTrajectory": {"1": [["2026-11", p1_status]], "2": [["2026-11", "ACTIVE_PAYING"]]},
}
(emits / "emit_metadata.json").write_text(json.dumps(meta, indent=2) + "\\n", encoding="utf-8")
(emits / "overlay.csv").write_text(ov_path.read_text(encoding="utf-8"), encoding="utf-8")
state = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
state["steps"]["emit"] = {"at": "2026-11-02T12:00:05", "code": ${pyLit(fixedCodeHash)}, "seconds": 0.1, "statements": len(stmt_rows)}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
`);

    return { pythonPath: 'python3', companyEmitPath: null, overlayCheckPath: null };
  };
}

async function runFullDecisionPipeline(env, worker, {
  engineVersionId,
  statementDate = '2026-11-02',
  origin = 'trial',
  keyPrefix,
  bibleDecisions,
  bibleRevisionDecisions = null,
  adjustDecisions,
  adjustRevisionDecisions = null,
}) {
  const launch = await env.commands.launchRun({
    dbToken: env.ownerToken,
    commandKey: `${keyPrefix}-launch`,
    statementDate,
    origin,
    engineVersionId,
    emitMode: 'coherence',
  });
  const runId = launch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');

  let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.saveReviewDecisions({
    dbToken: env.ownerToken,
    commandKey: `${keyPrefix}-bible`,
    expectedJournalSeq: seq,
    runId,
    surface: 'bible',
    decisions: bibleDecisions,
  });
  assert.equal((await worker.runOnce()).action, 'step_finished');

  if (Array.isArray(bibleRevisionDecisions) && bibleRevisionDecisions.length > 0) {
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.saveReviewDecisions({
      dbToken: env.ownerToken,
      commandKey: `${keyPrefix}-bible-rev`,
      expectedJournalSeq: seq,
      runId,
      surface: 'bible',
      decisions: bibleRevisionDecisions,
    });
    assert.equal((await worker.runOnce()).action, 'step_finished');
  }

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  let adjSave = await env.commands.saveReviewDecisions({
    dbToken: env.ownerToken,
    commandKey: `${keyPrefix}-adjust`,
    expectedJournalSeq: seq,
    runId,
    surface: 'adjust',
    decisions: adjustDecisions,
  });

  if (Array.isArray(adjustRevisionDecisions) && adjustRevisionDecisions.length > 0) {
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    adjSave = await env.commands.saveReviewDecisions({
      dbToken: env.ownerToken,
      commandKey: `${keyPrefix}-adjust-rev`,
      expectedJournalSeq: seq,
      runId,
      surface: 'adjust',
      decisions: adjustRevisionDecisions,
    });
  }

  seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
  await env.commands.confirmEmit({
    dbToken: env.ownerToken,
    commandKey: `${keyPrefix}-emit-confirm`,
    expectedJournalSeq: seq,
    runId,
    adjustReviewSaveId: adjSave.result.reviewSaveId,
    typedPhrase: `create statements for ${statementDate}`,
  });
  assert.equal((await worker.runOnce()).action, 'step_finished');
  return runId;
}

const PLANTED_PHI_STRINGS = [
  'Zelda Q. Plantedname',
  'Plantedname',
  '1EG4-TE5-MK72',
  '742 Evergreen Terrace',
  '555-867-5309',
  'zelda@example.test',
  'Casey Mock',
  'carrier_a~direct~PAT SAMPLE~100.00~2026-11',
];

function assertNoPlantedPhi(obj, contextLabel) {
  const json = JSON.stringify(obj);
  for (const token of PLANTED_PHI_STRINGS) {
    assert.equal(json.includes(token), false, `${contextLabel} leaked planted PHI token "${token}"`);
  }
}

test('Layer 6 [Mutations 1 & 2 - Bible & Adjust Decision Perturbations]: each fails at exact expected gate with exact entity cent shifts while still conserving to $0.00', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createLayer6TestEnv();
  t.after(() => env.cleanup());
  assert.ok(env.dbName.startsWith('test_'));

  const { engineVersionId } = await seedEngineCopyVersion(env);
  await seedStandingInput(env, { commandKey: 'l6-standing-input' });

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: env.companySlug,
    stores: env.stores,
    commands: env.commands,
    workerToken: env.workerToken,
    materializeEngine: createDecisionAwareMockEngineMaterializer(),
    tempBaseDir: env.tempDir,
  }));

  const baselineBible = [
    { recordId: 'policy:carrier_a:C-101#effective:2026-10-01', disposition: 'CONFIRM', approvedAmount: '100.00', approvedAgency: 'Beacon', approvedAgent: '11111111' },
    { recordId: 'policy:carrier_b:C-201#effective:2026-10-01', disposition: 'CONFIRM', approvedAmount: '200.00', approvedAgency: 'Harbor', approvedAgent: '33333333' },
  ];
  const baselineAdjust = [
    { recordId: 'carrier_a~direct~PAT SAMPLE~100.00~2026-11', disposition: 'CONFIRM', approvedAmount: '100.00', approvedAgency: 'Beacon', approvedAgent: '11111111' },
    { recordId: 'carrier_a~direct~VAR ITEM~50.00~2026-11', disposition: 'CONFIRM', approvedAmount: '50.00', approvedAgency: 'Beacon', approvedAgent: '11111111' },
  ];

  // Baseline Run A (origin = 'app')
  const runA = await runFullDecisionPipeline(env, worker, {
    engineVersionId,
    statementDate: '2026-11-02',
    origin: 'app',
    keyPrefix: 'run-a',
    bibleDecisions: baselineBible,
    adjustDecisions: baselineAdjust,
  });

  // Sanity check: Run A reconciles to $0.00 across all entities.
  const recA = (await env.pool.query('SELECT * FROM coherence_views.v_entity_statement_reconciliation($1::uuid)', [runA])).rows;
  assert.ok(recA.length >= 3);
  assert.ok(recA.every((r) => r.reconciled === true && r.variance === '0.00'));

  // --- MUTATION 1: Bible decision mutation (append linked CORRECT Bible decision changing Policy 101 Beacon -> Harbor, ACTIVE_RECON) ---
  const runB = await runFullDecisionPipeline(env, worker, {
    engineVersionId,
    statementDate: '2026-11-02',
    origin: 'trial',
    keyPrefix: 'run-b-bible-mut',
    bibleDecisions: baselineBible,
    bibleRevisionDecisions: [{
      recordId: 'policy:carrier_a:C-101#effective:2026-10-01',
      disposition: 'CORRECT',
      agency: 'Harbor',
      status: 'ACTIVE_RECON',
      approvedAmount: '100.00',
      approvedAgency: 'Harbor',
      approvedAgent: '11111111',
    }],
    adjustDecisions: baselineAdjust,
  });

  // Verify the linked Bible decision has a valid replaces_decision_id chain.
  const chainB = (await env.pool.query(
    `SELECT record_id, disposition, replaces_decision_id FROM coherence.decisions
     WHERE run_id = $1::uuid AND record_id = 'policy:carrier_a:C-101#effective:2026-10-01'
     ORDER BY journal_seq ASC, row_order ASC`,
    [runB],
  )).rows;
  assert.equal(chainB.length, 2);
  assert.equal(chainB[0].replaces_decision_id, null);
  assert.ok(chainB[1].replaces_decision_id, 'mutated Bible decision must link replaces_decision_id');

  // Mutated Run B must still reconcile to $0.00 on its own ledger.
  const recB = (await env.pool.query('SELECT * FROM coherence_views.v_entity_statement_reconciliation($1::uuid)', [runB])).rows;
  assert.ok(recB.every((r) => r.reconciled === true && r.variance === '0.00'));

  const cmpBible = await compareDbRuns({
    pool: env.pool,
    stores: env.stores,
    leftRunId: runB,
    rightRunId: runA,
    mode: 'substance',
    columns: { bob: SYNTHETIC_BOB_COLUMNS, ledger: SYNTHETIC_LEDGER_COLUMNS, statements: SYNTHETIC_RUN_COLUMNS },
    requireStatementsDelta: true,
    requireConservation: true,
    tempBaseDir: env.tempDir,
  });
  assert.equal(cmpBible.passed, false);
  assert.equal(cmpBible.gates.gate1.passed, true, 'Mutation 1 inputs must match');
  assert.equal(cmpBible.gates.gate2.passed, false, 'Mutation 1 must FAIL Gate 2 (canonical_bob)');
  assert.equal(cmpBible.gates.gate3.passed, false, 'Mutation 1 must FAIL Gate 3 (coherent_ledger)');
  assert.equal(cmpBible.gates.gate4.passed, false, 'Mutation 1 must FAIL Gate 4 (statements + entity statements)');
  assert.equal(cmpBible.stoppedAtGate, 2);
  assert.equal(cmpBible.entityStatements.dbReconciliation.reconciled, true);
  assert.equal(cmpBible.entityStatements.entityCentDeltas.Beacon, -8000, 'Beacon must shift by -$80.00');
  assert.equal(cmpBible.entityStatements.entityCentDeltas.Harbor, 8000, 'Harbor must shift by +$80.00');
  assert.equal(cmpBible.entityStatements.entityCentDeltas['Acme Upline'], 0, 'Upline must be unaffected ($0.00)');
  assertNoPlantedPhi(cmpBible, 'Mutation 1 report');

  // --- MUTATION 2: Adjust decision mutation (CORRECT variance item agency Beacon -> Harbor, $40.00 downline) ---
  await env.commands.abandonRun({
    dbToken: env.ownerToken,
    commandKey: 'abandon-run-b-for-c',
    runId: runB,
    typedPhrase: 'abandon 2026-11-02',
    reason: 'prepare next layer 6 mutation',
  });
  const runC = await runFullDecisionPipeline(env, worker, {
    engineVersionId,
    statementDate: '2026-11-02',
    origin: 'trial',
    keyPrefix: 'run-c-adjust-mut',
    bibleDecisions: baselineBible,
    adjustDecisions: baselineAdjust,
    adjustRevisionDecisions: [{
      recordId: 'carrier_a~direct~VAR ITEM~50.00~2026-11',
      disposition: 'CORRECT',
      agency: 'Harbor',
      approvedAmount: '50.00',
      approvedAgency: 'Harbor',
      approvedAgent: '11111111',
    }],
  });

  const recC = (await env.pool.query('SELECT * FROM coherence_views.v_entity_statement_reconciliation($1::uuid)', [runC])).rows;
  assert.ok(recC.every((r) => r.reconciled === true && r.variance === '0.00'));

  const cmpAdjust = await compareDbRuns({
    pool: env.pool,
    stores: env.stores,
    leftRunId: runC,
    rightRunId: runA,
    mode: 'substance',
    columns: { bob: SYNTHETIC_BOB_COLUMNS, ledger: SYNTHETIC_LEDGER_COLUMNS, statements: SYNTHETIC_RUN_COLUMNS },
    requireStatementsDelta: true,
    requireConservation: true,
    tempBaseDir: env.tempDir,
  });
  assert.equal(cmpAdjust.passed, false);
  assert.equal(cmpAdjust.gates.gate1.passed, true);
  assert.equal(cmpAdjust.gates.gate2.passed, true, 'Adjust-only non-policy variance leaves policy BoB unchanged');
  assert.equal(cmpAdjust.gates.gate3.passed, false, 'Mutation 2 must FAIL Gate 3 (coherent_ledger)');
  assert.equal(cmpAdjust.gates.gate4.passed, false, 'Mutation 2 must FAIL Gate 4 (statements + entity statements)');
  assert.equal(cmpAdjust.stoppedAtGate, 3);
  assert.equal(cmpAdjust.entityStatements.dbReconciliation.reconciled, true);
  assert.equal(cmpAdjust.entityStatements.entityCentDeltas.Beacon, -4000, 'Beacon must shift by -$40.00');
  assert.equal(cmpAdjust.entityStatements.entityCentDeltas.Harbor, 4000, 'Harbor must shift by +$40.00');
  assert.equal(cmpAdjust.entityStatements.entityCentDeltas['Acme Upline'], 0, 'Upline must be unaffected ($0.00)');
  assertNoPlantedPhi(cmpAdjust, 'Mutation 2 report');

  // Record a non_vacuous_mutation check row proving Mutations 1 & 2 failed at the exact expected gates.
  const chkRes = await env.commands.recordCheck({
    dbToken: env.ownerToken,
    commandKey: 'l6-check-mut-1-2',
    checkKind: 'non_vacuous_mutation',
    passed: true,
    report: {
      layer: 6,
      checkKind: 'non_vacuous_mutation',
      mutations: [
        { name: 'bible_decision_mutation', expectedGate: 2, actualStoppedAtGate: cmpBible.stoppedAtGate, passed: true },
        { name: 'adjust_decision_mutation', expectedGate: 3, actualStoppedAtGate: cmpAdjust.stoppedAtGate, passed: true },
      ],
    },
  });
  assert.equal(chkRes.result.passed, true);
});

test('Layer 6 [Mutations 3 & 4 - Comparator Sensitivity & Input Gate]: $0.01 delta, "100.00" vs "100", entity swap, 1-byte input tamper, and zero planted PHI', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'coherence-l6-cmp-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const writeTree = async (root, files) => {
    for (const [rel, content] of Object.entries(files)) {
      const full = join(root, ...rel.split('/'));
      await mkdir(dirname(full), { recursive: true });
      await writeFile(full, content, 'utf8');
    }
  };

  const baseBobRows = [
    {
      external_policy_id: 'POL-1', policy_id: 1, carrier_policy_number: 'C-1', crm_policy_number: 'CRM-1', enrollment_code: 'E-1',
      carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Gold', simple_plan_type: 'MA',
      mbi: '1EG4-TE5-MK72', member: 'Zelda Q. Plantedname', dob: '1955-04-12', phone: '555-867-5309', email: 'zelda@example.test',
      address: '742 Evergreen Terrace', county: 'WAKE', state: 'NC',
      submission_date: '2026-09-15', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      min_date: '2026-09-15', anchor_date: '2026-09-15',
      amount: '100.00', upline_amount: '25.00', writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-B', status: 'ACTIVE_PAYING', conflicts: '', spine_source: 'cbob_c', confidence_level: 100,
    },
    {
      external_policy_id: 'POL-2', policy_id: 2, carrier_policy_number: 'C-2', crm_policy_number: 'CRM-2', enrollment_code: 'E-2',
      carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Gold', simple_plan_type: 'MA',
      mbi: '3EF4-GH5-JK67', member: 'Casey Mock', dob: '1960-01-05', phone: '555-222-3333', email: 'casey@example.test',
      address: '300 Pine Rd', county: 'WAKE', state: 'NC',
      submission_date: '2026-09-15', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      min_date: '2026-09-15', anchor_date: '2026-09-15',
      amount: '100.00', upline_amount: '25.00', writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor',
      agency_id: 'AG-H', status: 'ACTIVE_PAYING', conflicts: '', spine_source: 'cbob_c', confidence_level: 100,
    },
  ];
  const baseLedgerRows = [
    {
      record_id: 'carrier_a~direct~PAT SAMPLE~100.00~2026-11', external_policy_id: 'POL-1', policy_id: 1, tx_id: 1,
      statement_name: 'c.csv', src_type: 'direct', carrier: 'carrier_a', mbi: '1EG4-TE5-MK72', member: 'Zelda Q. Plantedname',
      state: 'NC', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-15', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      earned_date: '2026-11-01', payment_date: '2026-11-02', statement_date: '2026-11-02', min_date: '2026-09-15',
      gross_comm: '125.00', revenue_type: 'commission', override_amount: '', commission_amount: '125.00', hra_amount: '', fee_amount: '', other_amount: '',
      downline_amount: '100.00', upline_amount: '25.00',
      writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon', payee_npn: '', agency_id: 'AG-B',
      status: 'ACTIVE_PAYING', policy_status: 'active', cbob_c: 'true', cbob_s: 'false', sf: 'true', notes: '', coherent_notes: 'NEW',
    },
    {
      record_id: 'carrier_a~direct~CASEY MOCK~100.00~2026-11', external_policy_id: 'POL-2', policy_id: 2, tx_id: 2,
      statement_name: 'c.csv', src_type: 'direct', carrier: 'carrier_a', mbi: '3EF4-GH5-JK67', member: 'Casey Mock',
      state: 'NC', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-15', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      earned_date: '2026-11-01', payment_date: '2026-11-02', statement_date: '2026-11-02', min_date: '2026-09-15',
      gross_comm: '125.00', revenue_type: 'commission', override_amount: '', commission_amount: '125.00', hra_amount: '', fee_amount: '', other_amount: '',
      downline_amount: '100.00', upline_amount: '25.00',
      writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor', payee_npn: '', agency_id: 'AG-H',
      status: 'ACTIVE_PAYING', policy_status: 'active', cbob_c: 'true', cbob_s: 'false', sf: 'true', notes: '', coherent_notes: 'NEW',
    },
  ];
  const baseStmtRows = baseLedgerRows.map((r) => ({ ...r, run_action: 'NEW', run_statement_date: '2026-11-02', reversal_of: '', reason: 'new' }));

  const makeBaseFiles = (bob, led, stmt, agentCsv = 'agent_name,agent_npn,entity\nSam Seller,11111111,Beacon\n') => ({
    'input/Agent Data/cleanagentdata.csv': agentCsv,
    'emits/canonical_bob.csv': makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, bob),
    'emits/coherent_ledger.csv': makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, led),
    'emits/statements_20261102.csv': makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, stmt),
  });

  const refDir = join(dir, 'ref');
  await writeTree(refDir, makeBaseFiles(baseBobRows, baseLedgerRows, baseStmtRows));
  const opts = {
    mode: 'substance',
    columns: { bob: SYNTHETIC_BOB_COLUMNS, ledger: SYNTHETIC_LEDGER_COLUMNS, statements: SYNTHETIC_RUN_COLUMNS },
    requireStatementsDelta: true,
    requireConservation: true,
  };

  // Sanity baseline passes.
  const ok = await compareRunFolders(refDir, refDir, opts);
  assert.equal(ok.passed, true);

  // Mutation 3a: $0.01 perturbation
  const dirCent = join(dir, 'mut-cent');
  const bobCent = [{ ...baseBobRows[0], amount: '100.01' }, baseBobRows[1]];
  await writeTree(dirCent, makeBaseFiles(bobCent, baseLedgerRows, baseStmtRows));
  const repCent = await compareRunFolders(dirCent, refDir, opts);
  assert.equal(repCent.passed, false);
  assert.equal(repCent.gates.gate2.passed, false);
  assert.equal(repCent.substance.bob.moneyCentDeltas.amount, 1);
  assert.equal(repCent.substance.bob.differingRows[0].rowNumber, 1);
  assert.deepEqual(repCent.substance.bob.differingRows[0].columns, ['amount']);
  assertNoPlantedPhi(repCent, 'Mutation 3a ($0.01)');

  // Mutation 3b: exact text formatting ('100.00' -> '100')
  const dirFmt = join(dir, 'mut-fmt');
  const bobFmt = [{ ...baseBobRows[0], amount: '100' }, baseBobRows[1]];
  await writeTree(dirFmt, makeBaseFiles(bobFmt, baseLedgerRows, baseStmtRows));
  const repFmt = await compareRunFolders(dirFmt, refDir, opts);
  assert.equal(repFmt.passed, false);
  assert.equal(repFmt.gates.gate2.passed, false);
  assert.equal(repFmt.substance.bob.differingRowCount, 1);
  assert.equal(repFmt.substance.bob.columnMismatchCounts.amount, 1);
  assert.equal(repFmt.substance.bob.moneyCentDeltas.amount, 0, 'cent delta is 0 yet exact text mismatch must still fail');
  assertNoPlantedPhi(repFmt, 'Mutation 3b (100.00 vs 100)');

  // Mutation 3c: swap entities across two equal-money rows preserving grand total
  const dirSwap = join(dir, 'mut-swap');
  const bobSwap = [
    { ...baseBobRows[0], entity: 'Harbor' },
    { ...baseBobRows[1], entity: 'Beacon' },
  ];
  await writeTree(dirSwap, makeBaseFiles(bobSwap, baseLedgerRows, baseStmtRows));
  const repSwap = await compareRunFolders(dirSwap, refDir, opts);
  assert.equal(repSwap.passed, false);
  assert.equal(repSwap.gates.gate2.passed, false);
  assert.equal(repSwap.substance.bob.differingRowCount, 2);
  assert.equal(repSwap.substance.bob.columnMismatchCounts.entity, 2);
  assert.deepEqual(repSwap.substance.bob.differingRows.map((r) => r.rowNumber), [1, 2]);
  assertNoPlantedPhi(repSwap, 'Mutation 3c (entity swap)');

  // Mutation 4: 1-byte tamper in input/Agent Data/cleanagentdata.csv -> stops immediately at Gate 1
  const dirInput = join(dir, 'mut-input');
  await writeTree(dirInput, makeBaseFiles(
    baseBobRows,
    baseLedgerRows,
    baseStmtRows,
    'agent_name,agent_npn,entity\nSam Seller,11111112,Beacon\n',
  ));
  const repInput = await compareRunFolders(dirInput, refDir, opts);
  assert.equal(repInput.passed, false);
  assert.equal(repInput.inputs.passed, false);
  assert.equal(repInput.stoppedAtGate, 1);
  assert.equal(repInput.gates.gate1.passed, false);
  assert.equal(repInput.gates.gate2.skipped, true, 'Gate 2 must be skipped after Gate 1 failure');
  assert.equal(repInput.gates.gate3.skipped, true);
  assert.equal(repInput.gates.gate4.skipped, true);
  assert.equal(repInput.substance.passed, false);
  assert.equal(repInput.inputs.changed[0].relPath, 'input/Agent Data/cleanagentdata.csv');
  assertNoPlantedPhi(repInput, 'Mutation 4 (Gate 1 input tamper)');
});

test('Layer 6 [Mutation 5 - Journal Tamper & Cutoff Isolation]: 1-char NDJSON tamper and dropped child row rejected by PostgreSQL; T1 vs T2 cutoff rebuild isolates later decisions', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createLayer6TestEnv();
  t.after(() => env.cleanup());

  const d1 = await env.commands.recordDecisionBaseline({
    dbToken: env.ownerToken,
    commandKey: 'l6-m5-t1',
    commitKind: 'historical_baseline',
    headerContract: 'v2',
    imported: true,
    decisions: [{
      record_id: 'policy:carrier_a:T1-POL#effective:2026-01-01',
      disposition: 'CONFIRM',
      committed_at: '2026-10-01T10:00:00Z',
    }],
  });
  const seqT1 = d1.journalSeq;

  const d2 = await env.commands.recordDecisionBaseline({
    dbToken: env.ownerToken,
    commandKey: 'l6-m5-t2',
    parentCommitId: d1.result.decisionCommitId,
    commitKind: 'historical_baseline',
    headerContract: 'v2',
    imported: true,
    decisions: [{
      record_id: 'policy:carrier_a:T2-POL#effective:2026-02-01',
      disposition: 'CORRECT',
      agency: 'Harbor',
      committed_at: '2026-10-02T10:00:00Z',
    }],
  });
  const seqT2 = d2.journalSeq;
  assert.ok(seqT2 > seqT1);

  const ndjson = await exportJournalNdjson(env.pool);
  const lines = ndjson.trim().split('\n');

  // 5a: Alter 1 character in an exported NDJSON line -> PostgreSQL refuses entry_hash mismatch
  const parsedLast = JSON.parse(lines[lines.length - 1]);
  parsedLast.command_key = `${parsedLast.command_key.slice(0, -1)}X`;
  const tamperedCharNdjson = `${[...lines.slice(0, -1), JSON.stringify(parsedLast)].join('\n')}\n`;
  const dbTamperChar = await createEmptyTestDb();
  t.after(() => dbTamperChar.cleanup());
  await assert.rejects(
    () => rebuildFromJournalExport(dbTamperChar.pool, tamperedCharNdjson),
    /entry_hash|mismatch/i,
  );

  // 5b: Drop 1 child row from an exported NDJSON line -> PostgreSQL refuses commitment count/hash mismatch
  const parsedDrop = JSON.parse(lines[lines.length - 1]);
  assert.ok(Array.isArray(parsedDrop.records.decisions) && parsedDrop.records.decisions.length === 1);
  parsedDrop.records.decisions = [];
  const droppedChildNdjson = `${[...lines.slice(0, -1), JSON.stringify(parsedDrop)].join('\n')}\n`;
  const dbDropped = await createEmptyTestDb();
  t.after(() => dbDropped.cleanup());
  await assert.rejects(
    () => rebuildFromJournalExport(dbDropped.pool, droppedChildNdjson),
    /commitment|count|mismatch/i,
  );

  // 5c: Cutoff isolation at seq = T1 vs seq = T2
  const dbT1 = await createEmptyTestDb();
  t.after(() => dbT1.cleanup());
  const rebT1 = await rebuildFromJournalExport(dbT1.pool, ndjson, { upToSeq: seqT1 });
  assert.equal(rebT1.replayed, seqT1);
  const cmpT1 = await compareDatabasesAsOf(env.pool, dbT1.pool, seqT1);
  assert.equal(cmpT1.passed, true, `T1 compareDatabasesAsOf failed: ${cmpT1.problems.join('; ')}`);
  const t1Keys = (await dbT1.pool.query('SELECT record_id FROM coherence.decisions')).rows.map((r) => r.record_id);
  assert.deepEqual(t1Keys, ['policy:carrier_a:T1-POL#effective:2026-01-01'], 'T2 decision must be absent at T1');

  const dbT2 = await createEmptyTestDb();
  t.after(() => dbT2.cleanup());
  const rebT2 = await rebuildFromJournalExport(dbT2.pool, ndjson, { upToSeq: seqT2 });
  assert.equal(rebT2.replayed, seqT2);
  const cmpT2 = await compareDatabasesAsOf(env.pool, dbT2.pool, seqT2);
  assert.equal(cmpT2.passed, true, `T2 compareDatabasesAsOf failed: ${cmpT2.problems.join('; ')}`);
  const t2Keys = (await dbT2.pool.query('SELECT record_id FROM coherence.decisions ORDER BY journal_seq ASC')).rows.map((r) => r.record_id);
  assert.deepEqual(t2Keys, [
    'policy:carrier_a:T1-POL#effective:2026-01-01',
    'policy:carrier_a:T2-POL#effective:2026-02-01',
  ], 'T2 decision must be present at T2');
});
