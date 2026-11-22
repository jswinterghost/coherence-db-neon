// Synthetic fixtures and mock Python engine for deterministic end-to-end tests with zero access to live data or services.
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { APPROVAL_ROW_COLUMNS, sha256Hex } from '../../src/util/crypto.mjs';
import { parseCsv, toCsv } from '../../src/util/csv.mjs';
import { AppError } from '../../src/util/redact.mjs';

export const V1_COLUMNS = APPROVAL_ROW_COLUMNS.slice(0, 10);
export const V2_COLUMNS = APPROVAL_ROW_COLUMNS;

export function makeOverlayCsv(rows = [], { version = 'v2' } = {}) {
  const cols = version === 'v1' ? V1_COLUMNS : V2_COLUMNS;
  const matrix = [
    cols,
    ...rows.map((r) => cols.map((c) => (r[c] == null ? '' : String(r[c])))),
  ];
  return toCsv(matrix);
}

/**
 * Test-only overlay CSV parser double used by synthetic import tests that do not run the Coherence Python package.
 */
export function createTestOverlayParser() {
  async function parseTestOverlay(filePath, { parentPath = null } = {}) {
    const text = await readFile(filePath, 'utf8');
    const parsedRows = parseCsv(text);
    if (parsedRows.length === 0) throw new AppError('Approvals CSV has no header.', 422, 'INVALID_OVERLAY');
    const header = parsedRows[0];
    let headerKind;
    if (header.length === V2_COLUMNS.length && header.every((c, i) => c === V2_COLUMNS[i])) headerKind = 'v2';
    else if (header.length === V1_COLUMNS.length && header.every((c, i) => c === V1_COLUMNS[i])) headerKind = 'v1';
    else throw new AppError('Approvals CSV header does not match v1 or v2 overlay contract.', 422, 'INVALID_OVERLAY');

    const toObj = (raw) => {
      const obj = {};
      for (let i = 0; i < V2_COLUMNS.length; i++) {
        const val = i < header.length ? raw[i] : '';
        obj[V2_COLUMNS[i]] = val === '' || val === undefined ? null : val;
      }
      return obj;
    };

    const rows = parsedRows.slice(1)
      .filter((r) => r.length > 1 || (r.length === 1 && r[0] !== ''))
      .map(toObj);

    let sharedRowCount = 0;
    if (parentPath) {
      const parentRaw = parseCsv(await readFile(parentPath, 'utf8')).slice(1)
        .filter((r) => r.length > 1 || (r.length === 1 && r[0] !== ''))
        .map(toObj);
      if (rows.length < parentRaw.length) {
        throw new AppError('Approvals file is shorter than its parent.', 422, 'OVERLAY_PREFIX_MISMATCH');
      }
      for (let i = 0; i < parentRaw.length; i++) {
        for (const col of V2_COLUMNS) {
          if ((rows[i][col] ?? null) !== (parentRaw[i][col] ?? null)) {
            throw new AppError('Approvals file does not begin with every row of its parent.', 422, 'OVERLAY_PREFIX_MISMATCH');
          }
        }
      }
      sharedRowCount = parentRaw.length;
    }

    const addedRows = rows.slice(sharedRowCount).map((row, idx) => ({
      row_no: sharedRowCount + idx + 1,
      ...row,
    }));
    return { headerKind, rowCount: rows.length, sharedRowCount, addedRows };
  }
  return parseTestOverlay;
}

export function sampleApprovalRow(overrides = {}) {
  return {
    record_id: 'policy:carrier_a:P10001#effective:2026-01-01',
    disposition: 'CONFIRM',
    agent: '12345678',
    agency: 'Acme',
    policy: null,
    book: null,
    month: null,
    status: 'ACTIVE_PAYING',
    note: 'verified',
    committed_at: '2026-11-21T15:00:00Z',
    approved_amount: '100.00',
    approved_agency: 'Acme',
    approved_agent: '12345678',
    approved_agency_from: null,
    approved_agent_from: null,
    ...overrides,
  };
}

export const DEFAULT_TOOLCHAIN = {
  os: 'Darwin',
  os_version: '24.6.0',
  arch: 'arm64',
  python: '3.12.0',
  uv: '0.5.0',
  node: '22.0.0',
  pnpm: '9.0.0',
  tz: 'America/New_York',
  lang: 'en_US.UTF-8',
  lc_all: 'en_US.UTF-8',
  pythonutf8: '1',
};

export async function seedEngineVersion(env, { label = 'v2.2.5-test', coherenceCommit = '809c6ea', nusearCommit = 'abc1234' } = {}) {
  const promo = async (relPath, content) => env.codeStore.promoteBytes(Buffer.from(content, 'utf8'), { relPath, checksPassed: true });

  const companyEmitPy = '# mock company_emit.py\nimport sys\nprint("mock company_emit")\n';
  const pagesLawPy = '# mock pages_law.py\ndef check(*a, **k): return [], {}\n';
  const overlayCheckPy = '# mock overlay check\n';
  const wrapperPkg = JSON.stringify({
    'company_emit.py': companyEmitPy,
    'pages_law.py': pagesLawPy,
    'coherence_overlay_check.py': overlayCheckPy,
  });

  const gitBundle = await promo('engine/coherence.bundle', '# v2 git bundle\nmock-bundle-bytes\n');
  const codeManifest = await promo('engine/code-manifest.json', JSON.stringify({ 'coherence/__init__.py': sha256Hex('') }));
  const pythonLock = await promo('engine/uv.lock', 'version = 1\n');
  const pythonWheels = await promo('engine/wheels.tar', 'mock-wheels-archive');
  const webLock = await promo('engine/pnpm-lock.yaml', 'lockfileVersion: 9.0\n');
  const webPackages = await promo('engine/web-store.tar', 'mock-pnpm-store');
  const wrapperBundle = await promo('engine/wrappers.json', wrapperPkg);

  const res = await env.commands.registerEngineVersion({
    actor: env.ownerActor,
    commandKey: `register-engine-${label}`,
    label,
    coherenceCommit,
    gitBundle,
    codeManifest,
    pythonLock,
    pythonWheels,
    webLock,
    webPackages,
    wrapperBundle,
    nusearCommit,
    companyEmitSha256: sha256Hex(companyEmitPy),
    pagesLawSha256: sha256Hex(pagesLawPy),
    overlayCheckSha256: sha256Hex(overlayCheckPy),
    toolchain: DEFAULT_TOOLCHAIN,
  });
  return { engineVersionId: res.result.engineVersionId, label, coherenceCommit };
}

/**
 * Seeds a standing input version including a trailing-space folder name and agent data CSV.
 */
export async function seedStandingInput(env, { extraFiles = {}, withPriorOverlay = null, commandKey = 'seed-standing-input' } = {}) {
  const files = {
    'Agent Data/cleanagentdata.csv': 'agent_name,agent_npn,entity,start_date\nJane Agent,12345678,Acme,01/01/2025\nBob Seller,87654321,SubAgency,01/01/2025\nJordan Manager,11112222,PartnerAgency,01/01/2025\n',
    'All Statements/carrier_a_202611.csv': 'member,policy_number,amount\nTest Member,P10001,100.00\n',
    'All BOB/TrailingCarrier /book.csv': 'member,policy_number,status\nTest Member,P10001,ACTIVE\n',
    'EnrollSys/enrollments.csv': 'member,policy_number,npn\nTest Member,P10001,12345678\n',
    ...extraFiles,
  };

  const entries = [];
  const storedFiles = [];
  for (const [relPath, content] of Object.entries(files)) {
    const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
    const promoted = await env.dataStore.promoteBytes(bytes, { relPath, checksPassed: true });
    storedFiles.push(promoted);
    entries.push({ relPath, fileSha256: promoted.sha256 });
  }

  let priorOverlaySha = null;
  if (withPriorOverlay) {
    const ovBytes = Buffer.from(withPriorOverlay.csv, 'utf8');
    const ovPromoted = await env.dataStore.promoteBytes(ovBytes, { relPath: 'Overlay/overlay.csv', checksPassed: true });
    storedFiles.push(ovPromoted);
    priorOverlaySha = ovPromoted.sha256;
    await env.commands.registerApprovalsFile({
      actor: env.ownerActor,
      commandKey: `${commandKey}-prior-overlay`,
      storedFile: ovPromoted,
      headerKind: withPriorOverlay.version || 'v2',
      rowCount: withPriorOverlay.rows.length,
      extendsSha256: null,
      sharedRowCount: 0,
      addedRows: withPriorOverlay.rows.map((r, i) => ({ row_no: i + 1, ...r })),
    });
    entries.push({ relPath: 'Overlay/overlay.csv', fileSha256: ovPromoted.sha256 });
  }

  const res = await env.commands.publishInputVersion({
    actor: env.ownerActor,
    commandKey,
    lineKind: 'standing',
    sourceKind: withPriorOverlay ? 'mac_import' : 'upload',
    reason: 'Initial synthetic input',
    entries,
    storedFiles,
  });
  return { inputVersionId: res.result.inputVersionId, priorOverlaySha, entries, journalSeq: res.journalSeq };
}

/**
 * Creates a standard-library-only Python 3 mock Coherence engine materializer supporting fault injection
 * (sleep, grandchild process, step failure, input tampering, unmarked exit).
 */
export function createMockEngineMaterializer({
  pythonPath = 'python3',
  sleepStep = null,
  sleepSeconds = 0,
  spawnGrandchildPidFile = null,
  failStep = null,
  mutateFrozenInputStep = null,
  unmarkedExitStep = null,
  fixedCodeHash = '809c6ea',
} = {}) {
  return async function materializeEngine({ workspaceDir }) {
    const writePy = async (relPath, code) => {
      const full = join(workspaceDir, ...relPath.split('/'));
      await mkdir(dirname(full), { recursive: true });
      await writeFile(full, code, 'utf8');
      return full;
    };

    const pyLit = (v) => (v == null ? 'None' : JSON.stringify(v));
    const sharedHeader = `
import csv, hashlib, json, os, shutil, subprocess, sys, time
from pathlib import Path

ROOT = Path(${pyLit(workspaceDir)})
CODE_HASH = ${pyLit(fixedCodeHash)}
SLEEP_STEP = ${pyLit(sleepStep)}
SLEEP_SECONDS = ${Number(sleepSeconds)}
GRANDCHILD_PID_FILE = ${pyLit(spawnGrandchildPidFile)}
FAIL_STEP = ${pyLit(failStep)}
MUTATE_STEP = ${pyLit(mutateFrozenInputStep)}
UNMARKED_STEP = ${pyLit(unmarkedExitStep)}

def check_env():
    assert os.environ.get("PYTHONUTF8") == "1", "PYTHONUTF8 must be 1"
    assert os.environ.get("TZ") == "America/New_York", "TZ must be America/New_York"
    assert "UTF-8" in os.environ.get("LANG", "").upper(), "LANG must be UTF-8"

def maybe_hook(step, run_dir):
    if SLEEP_STEP == step and SLEEP_SECONDS > 0:
        if GRANDCHILD_PID_FILE:
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            Path(GRANDCHILD_PID_FILE).write_text(str(child.pid), encoding="utf-8")
        time.sleep(SLEEP_SECONDS)
    if FAIL_STEP == step:
        print(f"simulated failure at {step}", file=sys.stderr)
        sys.exit(2)
    if MUTATE_STEP == step:
        (run_dir / "input" / "tampered.csv").write_text("bad\\n", encoding="utf-8")
`;

    await writePy('coherence/__init__.py', '');
    await writePy('coherence/phase1/__init__.py', '');
    await writePy('coherence/phase2/__init__.py', '');
    await writePy('coherence/phase3/__init__.py', '');
    await writePy('coherence/phase4/__init__.py', '');

    await writePy('coherence/phase1/assign.py', `${sharedHeader}
check_env()
date = sys.argv[1]
run_dir = ROOT / "runs" / date
shutil.rmtree(run_dir, ignore_errors=True)
run_dir.mkdir(parents=True)
shutil.copytree(ROOT / "input", run_dir / "input")
maybe_hook("assign", run_dir)
working = run_dir / "working"
working.mkdir()
trailing = run_dir / "input" / "All BOB" / "TrailingCarrier " / "book.csv"
trailing_hash = hashlib.sha256(trailing.read_bytes()).hexdigest()[:12] if trailing.is_file() else "none"
for name in ("tx", "cbob", "sf", "tx_tx", "tx_cbob", "tx_sf", "cbob_sf", "pbob"):
    (working / f"{name}.csv").write_text(f"id,tag\\n1,{trailing_hash}\\n", encoding="utf-8")
born = time.strftime("%Y-%m-%dT%H:%M:%S") + f".{time.time_ns() % 1_000_000_000:09d}"
state = {"date": date, "born": born, "steps": {}}
if UNMARKED_STEP != "assign":
    state["steps"]["assign"] = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "code": CODE_HASH, "seconds": 0.1}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
print("assign ok")
`);

    await writePy('coherence/phase2/attribute.py', `${sharedHeader}
check_env()
date = sys.argv[1]
run_dir = ROOT / "runs" / date
maybe_hook("attribute", run_dir)
state = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
(run_dir / "working" / "tx.csv").write_text(
    (run_dir / "working" / "tx.csv").read_text(encoding="utf-8").strip() + "\\n2,attributed\\n", encoding="utf-8"
)
if UNMARKED_STEP != "attribute":
    state["steps"]["attribute"] = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "code": CODE_HASH, "seconds": 0.1}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
print("attribute ok")
`);

    await writePy('coherence/phase3/bible.py', `${sharedHeader}
check_env()
date = sys.argv[1]
run_dir = ROOT / "runs" / date
maybe_hook("bible", run_dir)
state = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
unid_hash = hashlib.sha256((state["born"] + ":0").encode()).hexdigest()
items = [
    {"record_id": "policy:carrier_a:P10001#effective:2026-01-01", "case": "BIBLE", "subtype": "CONFLICT", "amount": "100.00"},
    {"record_id": f"policy:carrier_a:unidentified:{unid_hash}", "case": "BIBLE", "subtype": "HOUSE", "amount": "50.00"},
]
with open(run_dir / "bible.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=["record_id", "case", "subtype", "amount"])
    w.writeheader()
    w.writerows(items)
cfg = {"statementDate": date, "build": CODE_HASH, "stamped": True, "surface": "bible", "runBorn": state["born"], "queue": items, "overlay": [], "checksum": unid_hash[:16]}
html = f"<!doctype html><html><head><title>Coherence Bible</title><script>window.__ADJUST_CONFIG__={json.dumps(cfg, separators=(',', ':'))};</script></head><body>bible</body></html>"
(run_dir / "bible.html").write_text(html, encoding="utf-8")
if UNMARKED_STEP != "bible":
    state["steps"]["bible"] = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "code": CODE_HASH, "seconds": 0.1, "bible_items": len(items)}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
print("bible ok")
`);

    await writePy('coherence/phase3/adjust.py', `${sharedHeader}
check_env()
date = sys.argv[1]
run_dir = ROOT / "runs" / date
maybe_hook("adjust", run_dir)
state = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
ov_path = run_dir / "overlay.csv"
if not ov_path.is_file():
    print("adjust requires Bible overlay.csv", file=sys.stderr)
    sys.exit(1)
items = [{"record_id": "carrier_a~direct~P10001~100.00~2026-11", "case": "NEW", "subtype": "NEW_BUSINESS", "amount": "100.00"}]
with open(run_dir / "adjust.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=["record_id", "case", "subtype", "amount"])
    w.writeheader()
    w.writerows(items)
cfg = {"statementDate": date, "build": CODE_HASH, "stamped": True, "surface": "adjust", "runBorn": state["born"], "queue": items, "overlay": [], "checksum": "adj123"}
html = f"<!doctype html><html><head><title>Coherence Adjust</title><script>window.__ADJUST_CONFIG__={json.dumps(cfg, separators=(',', ':'))};</script></head><body>adjust</body></html>"
(run_dir / "adjust.html").write_text(html, encoding="utf-8")
if UNMARKED_STEP != "adjust":
    state["steps"]["adjust"] = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "code": CODE_HASH, "seconds": 0.1, "queue_items": len(items)}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
print("adjust ok")
`);

    await writePy('coherence/phase4/emit.py', `${sharedHeader}
check_env()
date = sys.argv[1]
run_dir = ROOT / "runs" / date
maybe_hook("emit", run_dir)
state = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
emits = run_dir / "emits"
shutil.rmtree(emits, ignore_errors=True)
emits.mkdir(parents=True)
stamp = date.replace("-", "")
(emits / f"statements_{stamp}.csv").write_text(
    "record_id,entity,writing_npn,gross_comm,downline_amount,run_action\\n"
    "carrier_a~direct~P10001~100.00~2026-11,Acme,12345678,100.00,80.00,NEW\\n",
    encoding="utf-8"
)
(emits / "adjustments.csv").write_text((run_dir / "overlay.csv").read_text(encoding="utf-8"), encoding="utf-8")
(emits / "overlay.csv").write_text((run_dir / "overlay.csv").read_text(encoding="utf-8"), encoding="utf-8")

em_dir = emits / "bundles" / "entity-managers" / "Acme"
(em_dir / "data").mkdir(parents=True)
(em_dir / "data" / "canonical_bob.csv").write_text("member,entity,carrier,policy_id,gross_comm\\nTest Member,Acme,carrier_a,1,100.00\\n", encoding="utf-8")
(em_dir / "data" / "coherent_ledger.csv").write_text("member,entity,carrier,gross_comm\\nTest Member,Acme,carrier_a,100.00\\n", encoding="utf-8")
em_cfg = {
    "name": "Entity Manager", "title": "Acme", "statementDate": date, "build": CODE_HASH, "stamped": True,
    "role": "ENTITY_MANAGER",
    "features": {"CANONICAL_BOB": {"canonical_bob": "data/canonical_bob.csv"}, "COHERENT_LEDGER": {"coherent_ledger": "data/coherent_ledger.csv"}},
    "defaultVisible": {"CANONICAL_BOB": {"canonical_bob": ["member", "entity"]}},
    "defaultFilters": {},
}
(em_dir / "viewer.html").write_text(f"<!doctype html><html><head><script>window.__VIEWER_CONFIG__={json.dumps(em_cfg, separators=(',', ':'))};</script></head><body>viewer</body></html>", encoding="utf-8")

# Selling agent bundle intentionally includes a dollar column that the agent feed must strip.
ag_dir = emits / "bundles" / "selling-agents" / "Acme" / "jane-agent"
(ag_dir / "data").mkdir(parents=True)
(ag_dir / "data" / "Acme_jane-agent_12345678_bob.csv").write_text(
    "member,entity,carrier,status,writing_npn,writing_agent,amount,gross_comm\\n"
    "Test Member,Acme,carrier_a,ACTIVE_PAYING,12345678,Jane Agent,100.00,100.00\\n",
    encoding="utf-8"
)
ag_cfg = {
    "name": "Jane Agent", "title": "12345678", "statementDate": date, "build": CODE_HASH, "stamped": True,
    "role": "SELLING_AGENT",
    "features": {"BOB": {"bob": "data/Acme_jane-agent_12345678_bob.csv"}},
    "defaultVisible": {"BOB": {"bob": ["member", "entity", "amount"]}},
    "defaultFilters": {"BOB": {"bob": {"amount": {"positiveOnly": True}, "carrier": {"include": ["carrier_a"]}}}},
}
(ag_dir / "viewer.html").write_text(f"<!doctype html><html><head><script>window.__VIEWER_CONFIG__={json.dumps(ag_cfg, separators=(',', ':'))};</script></head><body>viewer</body></html>", encoding="utf-8")

if UNMARKED_STEP != "emit":
    state["steps"]["emit"] = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "code": CODE_HASH, "seconds": 0.1, "statements": 1}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
print("emit ok")
`);

    const companyEmitPath = await writePy('mock_company_emit.py', `
import argparse, json, subprocess, sys
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument("date")
parser.add_argument("--builtin", action="store_true")
parser.add_argument("--display", default=None)
parser.add_argument("--keep", default="")
parser.add_argument("--no-manager", default="")
args = parser.parse_args()
rc = subprocess.call([sys.executable, "-m", "coherence.phase4.emit", args.date], cwd=str(Path.cwd()))
if rc != 0:
    sys.exit(rc)
if args.display:
    manifest = [
        {"output": f"entity-managers/{args.display}", "role": "ENTITY_MANAGER", "scope": "all", "viewer": {"name": "Entity Manager", "title": args.display}},
        {"output": "selling-agents/Acme/jane-agent", "role": "SELLING_AGENT", "scope": {"npns": ["12345678"], "entities": ["Acme"]}, "viewer": {"name": "Jane Agent", "title": "12345678"}},
    ]
    (Path.cwd() / "runs" / args.date / "company_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
`);

    // Stock-stdlib overlay checker matching python/coherence_overlay_check.py's exact JSON contract
    const overlayCheckPath = await writePy('mock_overlay_check.py', `
import argparse, csv, json, sys
from pathlib import Path

V1 = ("record_id","disposition","agent","agency","policy","book","month","status","note","committed_at")
V2 = V1 + ("approved_amount","approved_agency","approved_agent","approved_agency_from","approved_agent_from")

def read_ov(path: Path):
    if not path.is_file():
        return None, []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.reader(fh))
    if not rows:
        raise ValueError("Empty overlay file.")
    hdr = tuple(rows[0])
    if hdr == V2:
        kind = "v2"
    elif hdr == V1:
        kind = "v1"
    else:
        raise ValueError("The saved file header does not match the v1 or v2 overlay contract.")
    out = []
    for raw in rows[1:]:
        if not any(raw):
            continue
        rec = {}
        for i, c in enumerate(V2):
            v = raw[i] if i < len(raw) else ""
            rec[c] = None if v == "" else v
        if not rec["record_id"]:
            raise ValueError("Approvals row carries no record_id.")
        out.append(rec)
    return kind, out

parser = argparse.ArgumentParser()
parser.add_argument("--parse-only", action="store_true")
parser.add_argument("--extends", default=None)
parser.add_argument("--out", default=None)
parser.add_argument("args", nargs="+")
p = parser.parse_args()
try:
    if p.parse_only:
        kind, rows = read_ov(Path(p.args[0]))
        _, parent = read_ov(Path(p.extends)) if p.extends else (None, [])
        if parent and rows[:len(parent)] != parent:
            raise ValueError("The approvals file does not begin with every row of its parent approvals file.")
        shared = len(parent)
        new_rows = [{"row_no": shared + i + 1, **r} for i, r in enumerate(rows[shared:])]
        summary = {"header_kind": kind, "prior": shared, "current": 0, "shared": shared, "rows": len(rows), "added": len(new_rows)}
    else:
        date, cand, surface = p.args
        root = Path.cwd() / "runs" / date
        kind, rows = read_ov(Path(cand))
        _, prior = read_ov(root / "input" / "Overlay" / "overlay.csv")
        if rows[:len(prior)] != prior:
            raise ValueError("The saved file does not begin with the run's prior approvals.")
        _, current = read_ov(root / "overlay.csv") if surface == "adjust" else (None, [])
        if current and rows[:len(current)] != current:
            raise ValueError("The saved file does not begin with this run's Bible review.")
        shared = max(len(prior), len(current))
        new_rows = [{"row_no": shared + i + 1, **r} for i, r in enumerate(rows[shared:])]
        summary = {"header_kind": kind, "prior": len(prior), "current": len(current), "shared": shared, "rows": len(rows), "added": len(new_rows)}
    if p.out:
        Path(p.out).write_text(json.dumps({**summary, "new_rows": new_rows}), encoding="utf-8")
        print(json.dumps(summary))
    else:
        print(json.dumps({**summary, "new_rows": new_rows}))
except Exception as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)
`);

    await chmod(companyEmitPath, 0o700);
    await chmod(overlayCheckPath, 0o700);
    return { pythonPath, companyEmitPath, overlayCheckPath };
  };
}

export const SYNTHETIC_BOB_COLUMNS = [
  'external_policy_id', 'policy_id', 'carrier_policy_number', 'crm_policy_number', 'enrollment_code',
  'carrier', 'plan_type', 'plan_name', 'simple_plan_type',
  'mbi', 'member', 'dob', 'phone', 'email', 'address', 'county', 'state',
  'submission_date', 'origin_effective', 'effective_date', 'termination_date', 'min_date', 'anchor_date',
  'amount', 'upline_amount', 'writing_npn', 'writing_agent', 'entity', 'agency_id',
  'status', 'conflicts', 'spine_source', 'confidence_level',
];

export const SYNTHETIC_LEDGER_COLUMNS = [
  'record_id', 'external_policy_id', 'policy_id', 'tx_id',
  'statement_name', 'src_type', 'carrier', 'mbi', 'member', 'state', 'plan_type', 'simple_plan_type',
  'submission_date', 'origin_effective', 'effective_date', 'termination_date',
  'earned_date', 'payment_date', 'statement_date', 'min_date',
  'gross_comm', 'revenue_type', 'override_amount', 'commission_amount', 'hra_amount', 'fee_amount', 'other_amount',
  'downline_amount', 'upline_amount',
  'writing_npn', 'writing_agent', 'entity', 'payee_npn', 'agency_id',
  'status', 'policy_status', 'cbob_c', 'cbob_s', 'sf', 'notes', 'coherent_notes',
];

export const SYNTHETIC_RUN_COLUMNS = [
  ...SYNTHETIC_LEDGER_COLUMNS,
  'run_action', 'run_statement_date', 'reversal_of', 'reason',
];

export function makeCsvFromObjects(columns, rows) {
  return toCsv([
    columns,
    ...rows.map((r) => columns.map((c) => (r[c] == null ? '' : String(r[c])))),
  ]);
}

/**
 * Builds a complete, conservation-verified synthetic Emit dataset for Acme, Beacon, and Harbor.
 */
export function buildSyntheticEmitDataset({
  statementDate = '2026-10-31',
  bobRows = null,
  ledgerRows = null,
  statementRows = null,
  metadata = null,
  workingTxRows = null,
} = {}) {
  const defaultBob = bobRows || [
    {
      external_policy_id: 'POL-101', policy_id: 1, carrier_policy_number: 'C-101', crm_policy_number: 'CRM-101',
      enrollment_code: 'ENR-101', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Gold MA', simple_plan_type: 'MA',
      mbi: '1AB2-CD3-EF45', member: 'Pat Sample', dob: '1955-04-12', phone: '5551112222', email: 'pat@example.test',
      address: '100 Main St', county: 'WAKE', state: 'NC',
      submission_date: '2026-09-15', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      min_date: '2026-09-15', anchor_date: '2026-09-15',
      amount: '80.00', upline_amount: '20.00', writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-BEACON', status: 'ACTIVE_PAYING', conflicts: '', spine_source: 'cbob_c', confidence_level: 100,
    },
    {
      external_policy_id: 'POL-102', policy_id: 2, carrier_policy_number: 'C-102', crm_policy_number: 'CRM-102',
      enrollment_code: 'ENR-102', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Silver MA', simple_plan_type: 'MA',
      mbi: '2CD3-EF4-GH56', member: 'Lee Demo', dob: '1958-08-20', phone: '5553334444', email: 'lee@example.test',
      address: '200 Oak Ave', county: 'WAKE', state: 'NC',
      submission_date: '2026-09-20', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      min_date: '2026-09-20', anchor_date: '2026-09-20',
      amount: '120.00', upline_amount: '30.00', writing_npn: '22222222', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-BEACON', status: 'ACTIVE_PAYING', conflicts: '', spine_source: 'cbob_c', confidence_level: 100,
    },
    {
      external_policy_id: 'POL-201', policy_id: 3, carrier_policy_number: 'C-201', crm_policy_number: 'CRM-201',
      enrollment_code: 'ENR-201', carrier: 'carrier_b', plan_type: 'PDP', plan_name: 'Basic PDP', simple_plan_type: 'PDP',
      mbi: '3EF4-GH5-JK67', member: 'Casey Mock', dob: '1960-01-05', phone: '5555556666', email: 'casey@example.test',
      address: '300 Pine Rd', county: 'MECKLENBURG', state: 'NC',
      submission_date: '2026-09-22', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      min_date: '2026-09-22', anchor_date: '2026-09-22',
      amount: '200.00', upline_amount: '50.00', writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor',
      agency_id: 'AG-HARBOR', status: 'ACTIVE_PAYING', conflicts: '', spine_source: 'cbob_c', confidence_level: 95,
    },
  ];

  const defaultLedger = ledgerRows || [
    {
      record_id: 'carrier_a~direct~PAT SAMPLE~100.00~2026-10', external_policy_id: 'POL-101', policy_id: 1, tx_id: 1,
      statement_name: 'carrier_a_202610.csv', src_type: 'direct', carrier: 'carrier_a', mbi: '1AB2-CD3-EF45', member: 'Pat Sample',
      state: 'NC', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-15', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      earned_date: '2026-10-01', payment_date: '2026-10-15', statement_date: statementDate, min_date: '2026-09-15',
      gross_comm: '100.00', revenue_type: 'commission', override_amount: '', commission_amount: '100.00', hra_amount: '', fee_amount: '', other_amount: '',
      downline_amount: '80.00', upline_amount: '20.00',
      writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon', payee_npn: '', agency_id: 'AG-BEACON',
      status: 'ACTIVE_PAYING', policy_status: 'active', cbob_c: 'true', cbob_s: 'false', sf: 'true', notes: '', coherent_notes: 'NEW',
    },
    {
      record_id: 'carrier_a~direct~LEE DEMO~150.00~2026-10', external_policy_id: 'POL-102', policy_id: 2, tx_id: 2,
      statement_name: 'carrier_a_202610.csv', src_type: 'direct', carrier: 'carrier_a', mbi: '2CD3-EF4-GH56', member: 'Lee Demo',
      state: 'NC', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-20', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      earned_date: '2026-10-01', payment_date: '2026-10-15', statement_date: statementDate, min_date: '2026-09-20',
      gross_comm: '150.00', revenue_type: 'commission', override_amount: '', commission_amount: '150.00', hra_amount: '', fee_amount: '', other_amount: '',
      downline_amount: '120.00', upline_amount: '30.00',
      writing_npn: '22222222', writing_agent: 'Sam Seller', entity: 'Beacon', payee_npn: '', agency_id: 'AG-BEACON',
      status: 'ACTIVE_PAYING', policy_status: 'active', cbob_c: 'true', cbob_s: 'false', sf: 'true', notes: '', coherent_notes: 'NEW',
    },
    {
      record_id: 'carrier_b~direct~CASEY MOCK~250.00~2026-10', external_policy_id: 'POL-201', policy_id: 3, tx_id: 3,
      statement_name: 'carrier_b_202610.csv', src_type: 'direct', carrier: 'carrier_b', mbi: '3EF4-GH5-JK67', member: 'Casey Mock',
      state: 'NC', plan_type: 'PDP', simple_plan_type: 'PDP',
      submission_date: '2026-09-22', origin_effective: '2026-10-01', effective_date: '2026-10-01', termination_date: '',
      earned_date: '2026-10-01', payment_date: '2026-10-18', statement_date: statementDate, min_date: '2026-09-22',
      gross_comm: '250.00', revenue_type: 'commission', override_amount: '', commission_amount: '250.00', hra_amount: '', fee_amount: '', other_amount: '',
      downline_amount: '200.00', upline_amount: '50.00',
      writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor', payee_npn: '', agency_id: 'AG-HARBOR',
      status: 'ACTIVE_PAYING', policy_status: 'active', cbob_c: 'true', cbob_s: 'false', sf: 'false', notes: '', coherent_notes: 'NEW',
    },
    {
      // Non-policy house override fee: 0 downline, 25.00 upline
      record_id: 'carrier_a~direct~HOUSE~25.00~2026-10', external_policy_id: '', policy_id: '', tx_id: 4,
      statement_name: 'carrier_a_202610.csv', src_type: 'direct', carrier: 'carrier_a', mbi: '', member: '',
      state: 'NC', plan_type: '', simple_plan_type: '',
      submission_date: '', origin_effective: '', effective_date: '', termination_date: '',
      earned_date: '2026-10-01', payment_date: '2026-10-15', statement_date: statementDate, min_date: '2026-10-01',
      gross_comm: '25.00', revenue_type: 'override', override_amount: '25.00', commission_amount: '', hra_amount: '', fee_amount: '', other_amount: '',
      downline_amount: '0.00', upline_amount: '25.00',
      writing_npn: '', writing_agent: '', entity: 'Acme', payee_npn: '', agency_id: 'AG-ACME',
      status: '', policy_status: '', cbob_c: 'false', cbob_s: 'false', sf: 'false', notes: 'house override', coherent_notes: 'NEW',
    },
  ];

  const defaultStatements = statementRows || defaultLedger.map((r) => ({
    ...r,
    run_action: 'NEW',
    run_statement_date: statementDate,
    reversal_of: '',
    reason: 'new business',
  }));

  const defaultMeta = metadata || {
    statementDate,
    build: 'copy001',
    corpusTail: statementDate.slice(0, 7),
    agencyStart: '2026-01-01',
    coherentStatus: { '1': 'ACTIVE_PAYING', '2': 'ACTIVE_PAYING', '3': 'ACTIVE_PAYING' },
    coherentTrajectory: {
      '1': [['2026-10', 'ACTIVE_PAYING']],
      '2': [['2026-10', 'ACTIVE_PAYING']],
      '3': [['2026-10', 'ACTIVE_PAYING']],
    },
  };

  const defaultWorkingTx = workingTxRows || [
    { tx_id: 1, filename: 'carrier_a_202610.xlsx', sheet_name: 'Commissions', source_position: 14 },
    { tx_id: 2, filename: 'carrier_a_202610.xlsx', sheet_name: 'Commissions', source_position: 15 },
    { tx_id: 3, filename: 'carrier_b_202610.xlsx', sheet_name: 'Detail', source_position: 42 },
    { tx_id: 4, filename: 'carrier_a_202610.xlsx', sheet_name: 'Overrides', source_position: 8 },
  ];

  return {
    canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, defaultBob),
    coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, defaultLedger),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, defaultStatements),
    emitMetadataJson: JSON.stringify(defaultMeta),
    workingTxCsv: makeCsvFromObjects(['tx_id', 'filename', 'sheet_name', 'source_position'], defaultWorkingTx),
  };
}

export async function seedEngineCopyVersion(env, { label = 'acme-copy-2026.11', coherenceCommit = 'c0ffee1', upstreamCommit = '809c6ea', nusearCommit = 'abc1234' } = {}) {
  const promo = async (relPath, content) => env.codeStore.promoteBytes(Buffer.from(content, 'utf8'), { relPath, checksPassed: true });
  const overlayCheckPy = '# mock overlay check\n';
  const wrapperPkg = JSON.stringify({ 'coherence_overlay_check.py': overlayCheckPy });
  const gitBundle = await promo('engine/coherence-copy.bundle', '# v2 git bundle\ncopy-bytes\n');
  const codeManifest = await promo('engine/copy-manifest.json', JSON.stringify({ 'coherence/__init__.py': sha256Hex('') }));
  const pythonLock = await promo('engine/copy-uv.lock', 'version = 1\n');
  const pythonWheels = await promo('engine/copy-wheels.tar', 'mock-copy-wheels');
  const wrapperBundle = await promo('engine/copy-wrappers.json', wrapperPkg);
  const patchDiff = await promo('engine/copy.diff', 'diff --git a/coherence/phase4/emit.py b/coherence/phase4/emit.py\n');

  const copyToolchain = {
    os: 'Darwin',
    os_version: '24.6.0',
    arch: 'arm64',
    python: '3.12.0',
    uv: '0.5.0',
    tz: 'America/New_York',
    lang: 'en_US.UTF-8',
    lc_all: 'en_US.UTF-8',
    pythonutf8: '1',
  };

  const res = await env.commands.registerEngineVersion({
    actor: env.ownerActor,
    commandKey: `register-engine-copy-${label}`,
    label,
    coherenceCommit,
    engineKind: 'engine_copy',
    upstreamCommit,
    patchDiff,
    gitBundle,
    codeManifest,
    pythonLock,
    pythonWheels,
    wrapperBundle,
    nusearCommit,
    overlayCheckSha256: sha256Hex(overlayCheckPy),
    toolchain: copyToolchain,
  });
  return { engineVersionId: res.result.engineVersionId, label, coherenceCommit };
}

/**
 * Data-only engine-copy mock materializer (E1 + E2): writes bible.json, adjust.json,
 * canonical_bob.csv, coherent_ledger.csv, statements_YYYYMMDD.csv, and emit_metadata.json
 * with zero HTML files.
 */
export function createDataOnlyMockEngineMaterializer({
  fixedCodeHash = 'c0ffee1',
  datasetBuilder = buildSyntheticEmitDataset,
  adjustReconfirmRecordId = 'carrier_a~direct~PAT SAMPLE~100.00~2026-10',
} = {}) {
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
import json, shutil, sys, time
from pathlib import Path
ROOT = Path(${pyLit(workspaceDir)})
date = sys.argv[1]
run_dir = ROOT / "runs" / date
shutil.rmtree(run_dir, ignore_errors=True)
run_dir.mkdir(parents=True)
shutil.copytree(ROOT / "input", run_dir / "input")
working = run_dir / "working"
working.mkdir()
(working / "tx.csv").write_text("tx_id,filename,sheet_name,source_position\\n1,carrier_a_202610.xlsx,Commissions,14\\n2,carrier_a_202610.xlsx,Commissions,15\\n3,carrier_b_202610.xlsx,Detail,42\\n4,carrier_a_202610.xlsx,Overrides,8\\n", encoding="utf-8")
state = {"date": date, "born": "2026-10-31T12:00:00.000000000", "steps": {"assign": {"at": "2026-10-31T12:00:01", "code": ${pyLit(fixedCodeHash)}, "seconds": 0.1}}}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
`);

    await writePy('coherence/phase2/attribute.py', `
import json, sys
from pathlib import Path
ROOT = Path(${pyLit(workspaceDir)})
date = sys.argv[1]
run_dir = ROOT / "runs" / date
state = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
state["steps"]["attribute"] = {"at": "2026-10-31T12:00:02", "code": ${pyLit(fixedCodeHash)}, "seconds": 0.1}
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
    {"record_id": "policy:carrier_b:C-201#effective:2026-10-01", "case": "BIBLE", "subtype": "CONFLICT", "entity": "Harbor", "npn": "33333333", "amount": "250.00"},
]
with open(run_dir / "bible.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=["record_id", "case", "subtype", "entity", "npn", "amount"])
    w.writeheader()
    w.writerows(items)
cfg = {"statementDate": date, "build": ${pyLit(fixedCodeHash)}, "stamped": True, "surface": "bible", "runBorn": state["born"], "queue": items, "overlay": [], "reconfirm": {}, "checksum": "bible-json-1"}
(run_dir / "bible.json").write_text(json.dumps(cfg, indent=2) + "\\n", encoding="utf-8")
state["steps"]["bible"] = {"at": "2026-10-31T12:00:03", "code": ${pyLit(fixedCodeHash)}, "seconds": 0.1, "bible_items": len(items)}
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
reconf_id = ${pyLit(adjustReconfirmRecordId)}
items = [
    {"record_id": reconf_id, "case": "CHANGED", "subtype": "ENTITY_MOVE", "entity": "Beacon", "npn": "11111111", "amount": "100.00"},
    {"record_id": "carrier_b~direct~CASEY MOCK~250.00~2026-10", "case": "NEW", "subtype": "NEW_BUSINESS", "entity": "Harbor", "npn": "33333333", "amount": "250.00"},
]
with open(run_dir / "adjust.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=["record_id", "case", "subtype", "entity", "npn", "amount"])
    w.writeheader()
    w.writerows(items)
reconfirm = {reconf_id: {"approved": {"amount": "90.00", "entity": "Beacon"}, "now": {"amount": "100.00", "entity": "Beacon"}}} if reconf_id else {}
cfg = {"statementDate": date, "build": ${pyLit(fixedCodeHash)}, "stamped": True, "surface": "adjust", "runBorn": state["born"], "queue": items, "overlay": [], "reconfirm": reconfirm, "checksum": "adjust-json-1"}
(run_dir / "adjust.json").write_text(json.dumps(cfg, indent=2) + "\\n", encoding="utf-8")
state["steps"]["adjust"] = {"at": "2026-10-31T12:00:04", "code": ${pyLit(fixedCodeHash)}, "seconds": 0.1, "queue_items": len(items)}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
`);

    const ds = datasetBuilder();
    await writePy('coherence/phase4/emit.py', `
import json, shutil, sys
from pathlib import Path
ROOT = Path(${pyLit(workspaceDir)})
date = sys.argv[1]
run_dir = ROOT / "runs" / date
if not (run_dir / "overlay.csv").is_file():
    print("emit requires generated overlay.csv", file=sys.stderr)
    sys.exit(1)
emits = run_dir / "emits"
shutil.rmtree(emits, ignore_errors=True)
emits.mkdir(parents=True)
stamp = date.replace("-", "")
(emits / "canonical_bob.csv").write_text(${pyLit(ds.canonicalBobCsv)}, encoding="utf-8")
(emits / "coherent_ledger.csv").write_text(${pyLit(ds.coherentLedgerCsv)}, encoding="utf-8")
(emits / f"statements_{stamp}.csv").write_text(${pyLit(ds.statementsCsv)}, encoding="utf-8")
(emits / "emit_metadata.json").write_text(${pyLit(ds.emitMetadataJson)}, encoding="utf-8")
(emits / "overlay.csv").write_text((run_dir / "overlay.csv").read_text(encoding="utf-8"), encoding="utf-8")
state = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
state["steps"]["emit"] = {"at": "2026-10-31T12:00:05", "code": ${pyLit(fixedCodeHash)}, "seconds": 0.1, "statements": 4}
(run_dir / "run.json").write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
`);

    return { pythonPath: 'python3', companyEmitPath: null, overlayCheckPath: null };
  };
}
