# Real-History Proof Runbook (Phalanx)

This runbook guides an operator through running the read-only real-history proof for Phalanx using `config/phalanx-history.manifest.json` and `scripts/prove-history.mjs`. "Read-only" means the proof reads source folders and files without changing, creating, or deleting a single byte inside them.

The proof imports Phalanx's complete historical folders and legacy database snapshot into a local throwaway PostgreSQL 17 database (PostgreSQL is a relational database management system; a throwaway `test_*` database is an isolated local database whose name begins with `test_` so production data is never touched), stores copies in a private local content-addressed object store (a storage folder where each file is stored under its SHA-256 fingerprint, a 64-character cryptographic digest computed from the file's exact bytes), verifies storage integrity, decision reconstruction, point-in-time journal rebuild, and substance parity, and prints a summary containing zero Protected Health Information (PHI: identifiable member names, Medicare numbers, policy numbers, addresses, or phone numbers under HIPAA, the United States Health Insurance Portability and Accountability Act).

Follow the steps below in exact order. Do not skip the preconditions, the fingerprints, or the plan check.

---

## 1. Preconditions

Confirm all four preconditions and review the manifest checklist before running any proof command.

### 1.1 Local PostgreSQL 17 at `/tmp` Port `5433`

The proof runner connects only to a local PostgreSQL 17 server over a Unix socket (a local file-based connection endpoint on the same computer, not exposed over a network) or loopback address (this computer's private self-only network address, such as `127.0.0.1`), and refuses any remote host or cloud socket. Verify PostgreSQL 17 is listening at `/tmp` on port `5433`:

```sh
pg_isready -h /tmp -p 5433
psql -h /tmp -p 5433 -U "$USER" -d postgres -c "SHOW server_version;"
```

Confirm the server version starts with `17.`.

### 1.2 Consistent SQLite Copy in the Private Proof Folder (Mode `600`)

Legacy Nusear records live in a SQLite database (SQLite is a lightweight single-file relational database). Never point the manifest at the live `/Users/marcsmac/Code/nusear2.com/data/nusear2.sqlite` file because a running application may hold active changes in Write-Ahead Log (WAL) sidecar files (`-wal` and `-shm`, temporary files that hold recent database writes before they merge into the main file).

Create the private proof folder with file permission mode `700` (only the owning account can open, list, or write inside the folder), take one consistent snapshot with `sqlite3`'s `.backup` command, and lock the snapshot to file permission mode `600` (only the owning account can read or write the file):

```sh
PROOF_DIR="/Users/marcsmac/Code/nusear2.com/private-backups/proof-2026-11-23"
mkdir -p -m 700 "$PROOF_DIR"
chmod 700 "$PROOF_DIR"
sqlite3 -readonly /Users/marcsmac/Code/nusear2.com/data/nusear2.sqlite \
  ".backup '$PROOF_DIR/nusear2.sqlite'"
chmod 600 "$PROOF_DIR/nusear2.sqlite"
ls -la "$PROOF_DIR"
```

Verify that `nusear2.sqlite` shows permissions `-rw-------` (`600`), non-zero size, and no `nusear2.sqlite-wal` or `nusear2.sqlite-shm` sidecar files beside it.

### 1.3 Free Disk Space (At Least Twice the Sources, About `35 GB`)

The proof keeps full copies of imported files in the private object store, writes temporary byte-for-byte rebuild trees, populates PostgreSQL tables, and creates temporary point-in-time rebuild databases during Layer 4. Require at least twice the total size of all source folders, about `35 GB` free on the target volume:

```sh
df -h /Users/marcsmac/Code/nusear2.com/private-backups /tmp
```

Do not start the proof if available space is below `35 GB` (or below twice `totals.bytes` reported by the plan check in Section 3, whichever is larger).

### 1.4 No Company Run in Progress

Confirm that no Coherence calculation phase is running and that no legacy run is marked active in the SQLite snapshot taken in Step 1.2:

```sh
pgrep -fl "coherence\.phase" || echo "No active coherence.phase processes."
sqlite3 -readonly "$PROOF_DIR/nusear2.sqlite" \
  "SELECT date, status FROM coherence_run_records WHERE lower(coalesce(status,'')) = 'running';
   SELECT company, date, status FROM company_run_records WHERE company = 'phalanx' AND lower(coalesce(status,'')) = 'running';"
```

Both checks must return zero active runs before proceeding.

### 1.5 Manifest Source Keys to Verify Before Running

The manifest (`config/phalanx-history.manifest.json`, a JSON [JavaScript Object Notation, a structured plain-text data format] configuration file) was built strictly from a two-level historical folder listing, the importer code, and the implementation plan, without reading any real data file or listing individual filenames.

Most source keys are settled directly from the folder names:
- `sources.legacyRunsRoot` points to `/Users/marcsmac/Code/coherence/runs` (including `archive/provisional`, `archive/v1`, `archive/v2`, and `Historical 2026-08-31/2026-08-31`, while automatically skipping `Incident Report`).
- `sources.incidentReportDir` points to `/Users/marcsmac/Code/coherence/runs/Incident Report`.
- `sources.standingInputDir` points to `/Users/marcsmac/Code/coherence/input` (with `importConfig.useCompanyIncomingInput` set to `false` so standing inputs come from original Coherence rather than Nusear's `incoming/`).
- `sources.legacyReviewSavesDir` points to `/Users/marcsmac/Code/nusear2.com/data/coherence-runs`.
- `sources.companyWorkspacesDir` points to `/Users/marcsmac/Code/nusear2.com/data/company-workspaces/phalanx`.
- `sources.companyReviewSavesDir` points to `/Users/marcsmac/Code/nusear2.com/data/company-runs/phalanx`.
- `sources.companyEnvironmentDir` points to `/Users/marcsmac/Code/nusear2.com/data/company-environments/phalanx`.
- `sources.legacySqlitePath` and `nusearSqlitePath` both point to `/Users/marcsmac/Code/nusear2.com/private-backups/proof-2026-11-23/nusear2.sqlite`.
- `sources.preCoherenceStatementsDir` points to `/Users/marcsmac/Code/coherence/input/Phalanx Statements` (where Coherence's legacy statement reader loads the five pre-Coherence sent dates, `2026-03-25` through `2026-07-31`).
- `sources.preCoherenceSentDir` points to `/Users/marcsmac/Code/coherence/input/Sent` (used by the legacy statement bridge to settle reversals before deriving the `2026-08-01` split correction).
- `sources.preCoherenceAgentsCsv` points to `/Users/marcsmac/Code/coherence/input/Agent Data/cleanagentdata.csv`.

The following items could not be fully settled from two-level folder names alone. Check each one before or during the plan check in Section 3:

| Manifest key | Current value | What to check before running |
|---|---|---|
| `pythonPath` | `/Users/marcsmac/Code/coherence/.venv/bin/python` | The two-level folder listing did not include `.venv`. Confirm this Python executable exists and can import `polars` (the Python data-table library Coherence uses) and `coherence`. Update `pythonPath` if Coherence's virtual environment lives elsewhere. |
| `sources.companyAbandonedDir` | `null` | The two-level folder listing had no `company-abandoned` section. Check whether `/Users/marcsmac/Code/nusear2.com/data/company-abandoned/phalanx` exists. If it exists, set this key explicitly so the plan check enforces its presence (note the importer also checks `nusearDataDir/company-abandoned/phalanx` automatically if present). |
| `sources.cloudMirrorDir` | `null` | The two-level folder listing had no local mirror of Google Cloud Storage lists and objects. Leave `null` for a local-disk-only proof, or point it to a local read-only mirror folder if including cloud archive inventories. |
| `sources.preCoherenceStatementsDir` and `sources.preCoherenceAgentsCsv` | `.../input/Phalanx Statements` and `.../input/Agent Data/cleanagentdata.csv` | Folder names are confirmed, but individual filenames inside them were not listed. Confirm the five pre-Coherence statement CSV (comma-separated values, a plain-text table format) files (`2026-03-25` through `2026-07-31`) sit inside `Phalanx Statements/` and `cleanagentdata.csv` sits inside `Agent Data/`. |
| `sources.methodCorrections` | Two entries: `2026-08-01` (`split_reallocation`, agency `233678` / upline `-233678` cents) and `2026-08-31` (`upline_takeback`, agency `0` / upline `-17764809` cents) | Expected cent totals match Coherence's books, and `unreversedOnly: true` uses `sources.preCoherenceSentDir`. What could not be settled from folder names alone is whether `2026-08-01` needs `useAgentsSplit: true` (per-agent split from `cleanagentdata.csv`) instead of fixed `uplineRate: "0.20"` with `excludeEntities: ["Phalanx"]`, or an explicit `sourceFiles` list. The bridge checks totals to the exact cent and aborts before writing any database batch if off by even one cent. |
| `overlayCheckpoints` | `[]` | Every run's frozen prior `input/Overlay/overlay.csv` (an overlay is Coherence's append-only log of human review decisions), timestamped review saves in `coherence-runs/` and `company-runs/phalanx/`, root `overlay.csv`, `emits/overlay.csv`, and standing `input/Overlay/overlay.csv` are discovered and verified automatically. Folder names alone do not show whether extra standalone pre-`2026-10-21` overlay CSV backups exist outside those locations (for example extra files inside `input/Overlay/` or `company-environments/phalanx/replaced/`). Add any standalone files here if found. |
| `compareTargets` (6 company runs) | `company-workspaces/phalanx/<date>/runs/<date>` for `2026-11-03`, `11-04`, `11-11`, `11-12`, `11-20`, `11-21` | The two-level folder listing stopped at `phalanx/<date>`, so it could not confirm whether each workspace uses the nested `runs/<date>/` layout or a direct `<date>/` layout, or whether every one of the six completed Emit (Coherence's final calculation phase that writes statements, Book of Business, and Coherent Ledger outputs). Section 3's `--plan` check tests every target immediately. |
| `compareTargets` (`expectedEntityParity` on `2026-11-02`) | `null` | `executeHistoryImport` imports files, decision records, and pre-Coherence plus method-correction statement batches, but does not populate `coherence.run_materializations` (the database table holding parsed Emit outputs, created during Layer 3 replay or Emit materialization). Keeping `expectedEntityParity` as `null` prevents a false failure in `prove-history.mjs`; once `2026-11-02` is materialized or replayed in Layer 3, enable the plan's exact 10-date, 70-file, 82,674-line, `$1,063,019.51` parity check. |
| `sources.companyEnvironmentDir` root files | `.../company-environments/phalanx` | Subfolders `finished/`, `incoming/`, and `replaced/` are confirmed; folder names alone do not confirm whether `audit.json` or `answer-key-*.json` sit at the root (the importer reads them automatically if present). |
| `importConfig.allowedMissingCommits`, `allowDisjointOverlayRoots`, `freshOverlayRoots`, `carriedPriors`, `emitRules`, `companySentRecords` | `[]`, `false`, 4 fresh-start roots (each also listed under `archive/v1/`) with pinned SHA-256 digests, 1 carried prior (`archive/provisional/2026-10-01`), `[]`, `{}` | Kept fail-closed by Coherence's own overlay law: both `--plan` and the importer refuse `allowDisjointOverlayRoots: true`. A run with a frozen prior (`input/Overlay/overlay.csv`) must match a known decision commit exactly (as Coherence's `overlay._read` reads it, including v1-to-v2 header transitions) and its `overlay.csv` and `emits/overlay.csv` must extend that prior verbatim; otherwise import fails with `OVERLAY_PREFIX_MISMATCH`. Only runs without a frozen prior (or with an empty 0-row prior) that are explicitly pinned by exact `{ sourceFolder, sha256 }` in `importConfig.freshOverlayRoots` may start a fresh root (checked against `sha256` before any 0-row early return, and recorded as `historical_overlay`, never `historical_baseline`): `2026-07-31` (`4a316f602bc01f1908c96809786073a2d0156045d1921ec51ebd44804852b601`), `2026-08-25` (`26f50cbbf6b10638cecbc1300f4a4c53b29d0b1a705c61c54a641569be9a479a`), `2026-08-31` (`20a4c5f94bac4d49aa564204ec142e637b4fea44a6f68fcdac3f0634a080cb20`), and `Historical 2026-08-31/2026-08-31` (`9bdb4be772aa75308a00fc4fe0980da60a998161e740121bdd08da888b008837`), plus their byte-identical copies under `archive/v1/` (each byte-identical copy resolves to the same commit and creates no new root). A frozen prior that equals no known commit is accepted only when listed in `importConfig.carriedPriors` with exact `{ sourceFolder, sha256, extendsRowCount }` (and, optionally, the `reason` the reference gives) and extending (as `overlay._read` reads it) a known commit of exactly `extendsRowCount` rows; it becomes a `historical_overlay` child commit whose added decisions are recorded as `historical_import_reference_append` with no run, the reason kept in its provenance. Here `archive/provisional/2026-10-01` (`f26f933e2f1d9bb2cc751486bcd28eef0d5d000d2c522b4919f89227a1b66af0`, `extendsRowCount: 22334`) extends `2026-09-30`'s final commit by 220 rows that the reference appended outside any run: 220 `CONFIRM` references re-keying the same saved 9/30 Bible decisions from temporary `#id` keys to dated period keys after the Bible key law changed (the reference's own TODO.md records the measurement in its Replacement 2026-10-11 baseline section: proved references, not new business decisions), and `2026-10-01`'s byte-identical prior then equals that commit. The standing `input/Overlay/overlay.csv` and every company run's prior must equal a known commit exactly (never satisfied by a 0-row commit once any non-empty commit exists) and can never start a root; `standing_decision_head_as_of(NULL)` is verified even when the standing overlay file was already imported. Every root created (`folder`, `folders`, `commitId`, `sha256`, `rowCount`) and every carried prior (`folder`, `commitId`, `parentCommitId`, `sha256`, `rowsAdded`) is reported in the proof summary, never silent. Note that `2026-11-11` was recorded sent in the company environment while original Coherence `input/Sent/` holds only `08/31`, `09/30`, `10/12`, and `11/02`; leaving `companySentRecords: {}` preserves whatever the environment recorded, and setting `"2026-11-11": { "sent": false }` suppresses that sent carry if instructed by the owner. |

---

## 2. Fingerprint of the Original Coherence Folder (Before and After)

Before touching anything with the proof runner, record a read-only fingerprint (a snapshot of repository status plus every file's byte size and last-modified timestamp, used to prove nothing changed) of `/Users/marcsmac/Code/coherence`. Capture both its Git (the version-control system tracking source code history) working-tree status (`git status --porcelain`, which reports any modified, staged, or untracked file) and every file's exact byte size and modified timestamp across `coherence/coherence`, `coherence/input`, and `coherence/runs`.

Use `PYTHONDONTWRITEBYTECODE=1` and `python3 -B` so Python writes no compiled bytecode cache files (`.pyc`) inside the original Coherence folder.

### 2.1 Before the Proof

Run this command right before Step 3:

```sh
PROOF_DIR="/Users/marcsmac/Code/nusear2.com/private-backups/proof-2026-11-23"
COHERENCE_DIR="/Users/marcsmac/Code/coherence"

{
  echo "=== git status --porcelain ==="
  git --no-optional-locks -C "$COHERENCE_DIR" status --porcelain
  echo "=== files (size mtime_ns relpath) ==="
  PYTHONDONTWRITEBYTECODE=1 python3 -B - "$COHERENCE_DIR" <<'PY'
import os, sys
root = sys.argv[1]
rows = []
for sub in ("coherence", "input", "runs"):
    base = os.path.join(root, sub)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            rel = os.path.relpath(full, root)
            rows.append(f"{st.st_size} {st.st_mtime_ns} {rel}")
rows.sort()
sys.stdout.write("\n".join(rows) + ("\n" if rows else ""))
PY
} > "$PROOF_DIR/coherence-before.fingerprint"
chmod 600 "$PROOF_DIR/coherence-before.fingerprint"
wc -l "$PROOF_DIR/coherence-before.fingerprint"
```

### 2.2 After the Proof (Must Match Identically)

Immediately after Step 4 completes (whether the proof passes or fails), run the exact same command writing `coherence-after.fingerprint` and compare the two files with `diff -u`:

```sh
PROOF_DIR="/Users/marcsmac/Code/nusear2.com/private-backups/proof-2026-11-23"
COHERENCE_DIR="/Users/marcsmac/Code/coherence"

{
  echo "=== git status --porcelain ==="
  git --no-optional-locks -C "$COHERENCE_DIR" status --porcelain
  echo "=== files (size mtime_ns relpath) ==="
  PYTHONDONTWRITEBYTECODE=1 python3 -B - "$COHERENCE_DIR" <<'PY'
import os, sys
root = sys.argv[1]
rows = []
for sub in ("coherence", "input", "runs"):
    base = os.path.join(root, sub)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            rel = os.path.relpath(full, root)
            rows.append(f"{st.st_size} {st.st_mtime_ns} {rel}")
rows.sort()
sys.stdout.write("\n".join(rows) + ("\n" if rows else ""))
PY
} > "$PROOF_DIR/coherence-after.fingerprint"
chmod 600 "$PROOF_DIR/coherence-after.fingerprint"
diff -u "$PROOF_DIR/coherence-before.fingerprint" "$PROOF_DIR/coherence-after.fingerprint"
```

`diff -u` must print nothing and return exit code `0` (zero differences). Any difference means a file was created, removed, or modified inside `/Users/marcsmac/Code/coherence` and must be investigated immediately before accepting the proof.

---

## 3. Plan Check (`--plan`)

Before running the full proof, run the metadata-only plan check from this repository root:

```sh
node scripts/prove-history.mjs \
  --manifest config/phalanx-history.manifest.json \
  --plan
```

What `--plan` does:
- Reads only the manifest JSON file plus directory listings (`readdir`) and file-metadata sizes (`stat`).
- Never opens or reads any source file's contents, never opens SQLite, never runs Python or Git, and never connects to PostgreSQL.
- Prints strictly counts and names: per-area `runs`, `files`, and `bytes`; deduplicated `totals` (counting each unique file path once even when folders overlap); per comparison target `found` or `missing` by target name; and `missing`, listing every missing configured folder, file, checkpoint, comparison target, or `importConfig.freshOverlayRoots` / `importConfig.carriedPriors` run folder by its exact manifest key.
- Exits with code `0` (success) when `passed` is `true` and `missing` is empty; exits with code `1` (failure) if anything configured is missing.

Before moving to Step 4:
1. Confirm the plan check exited `0` with `"passed": true` and `"missing": []`.
2. If anything appears in `missing` (for example `pythonPath`, `sources.legacySqlitePath`, or a company workspace `compareTargets[i]` nesting difference), fix the precondition or manifest key and re-run `--plan` until it exits `0`.
3. Check `totals.bytes` against Step 1.3 and confirm free disk space is at least twice `totals.bytes`.

---

## 4. Proof Command

Run the read-only real-history proof against local PostgreSQL 17 at `/tmp` port `5433`, placing the separated `code/` and `data/` object stores under the private proof folder via `--stores-dir`:

```sh
PROOF_DIR="/Users/marcsmac/Code/nusear2.com/private-backups/proof-2026-11-23"

PGHOST=/tmp PGPORT=5433 PGUSER="$USER" \
node scripts/prove-history.mjs \
  --manifest config/phalanx-history.manifest.json \
  --database test_phalanx_history_20261123 \
  --stores-dir "$PROOF_DIR/stores" \
  > "$PROOF_DIR/proof-summary.json"
PROOF_STATUS=$?
chmod 600 "$PROOF_DIR/proof-summary.json"
cat "$PROOF_DIR/proof-summary.json"
echo "proof exit status: $PROOF_STATUS"
node -e 'const fs = require("node:fs"); const s = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); console.log("summary.passed:", s.passed); if (s.passed !== true) process.exit(1);' "$PROOF_DIR/proof-summary.json"
test "$PROOF_STATUS" -eq 0
```

Notes on flags:
- `--database test_phalanx_history_20261123` uses a throwaway `test_*` database name (required by the runner).
- Do **not** pass `--drop-db`; the test database must stay intact until the owner approves clean-up (Section 7).
- Passing an explicit `--stores-dir` keeps `stores/code` and `stores/data` under `$PROOF_DIR/stores` while the runner still cleans its own temporary scratch directory automatically on exit.
- If a prior attempt failed and you corrected a manifest setting before re-running, add `--recreate` to drop and recreate only the named `test_*` database.

When the command exits, immediately run Section 2.2 (`coherence-after.fingerprint` and `diff -u`) to confirm the original Coherence folder stayed completely unchanged.

---

## 5. What the Output Holds

The proof runner writes one strictly PHI-free JSON report to standard output (and `proof-summary.json`). It holds only counts, SHA-256 digests, column names, integer cent deltas, and pass or fail flags per layer and gate. It never prints a member name, Medicare number, policy number, address, phone number, raw CSV row, or `record_id` (Coherence's unique line identifier, which can embed member details).

Key sections in the JSON output:

- **Top-level status:** `passed` (`true` only when every layer and every comparison target passes), `database`, `companySlug`, `executedAtUtc`, and `problems` (redacted list of any failure descriptions, empty on success).
- **`layer0` (Database and object-store integrity):**
  - `chain`: gapless journal sequence count (`entries`), `headHash`, and `passed`.
  - `commitments`: `checkedEntries` and `passed`, verifying exact row counts and canonical content hashes across all 30 child business tables.
  - `objects`: `checkedObjects`, `codeInDataStoreCount` (must be `0`, proving full-buffer scanning kept all code-bearing files out of `company_data`), and `passed`.
- **`layer1` (Historical preservation, byte-for-byte rebuild, and idempotency):**
  - Counts of `importedRunCount`, `skippedRunCount`, `companySentCarryCount`, `preCoherenceBatchCount`, `methodCorrectionBatchCount`, `standaloneFileCount`, `overlayRootCount` plus `overlayRoots` (listing `folder`, `folders` with every folder that resolved to that root, `commitId`, `sha256`, and `rowCount`), and `carriedPriorCount` plus `carriedPriors` (listing `folder`, `commitId`, `parentCommitId`, `sha256`, and `rowsAdded` for every accepted carried prior (a reference append made outside any run; its pinned reason is kept in the database's provenance record, `coherence.imported_files.metadata.reason`, not in this summary)).
  - `sqliteParity`: exact source versus imported row counts across all 8 legacy SQLite tables.
  - `rebuild`: pass or fail and file counts for byte-for-byte reconstruction of every imported run folder, standing `input/`, `Incident Report/`, and all standalone areas (proving every rebuilt file matches the source SHA-256 identically).
  - `idempotency`: `checked`, `passed`, and per-table `deltas` from a second import against the same manifest (every delta must be `0`, meaning re-importing adds nothing).
- **`layer2` (Decision-record overlay reconstruction):**
  - `checkpointsChecked`, `checkpointsPassed`, `totalRowsChecked`, `replacementChainViolations` (must be `0`), `currentParityMismatches` (must be `0`), and `bibleAppliedParityMismatches` (must be `0`).
  - Per-checkpoint entries showing `purpose`, `statementDate`, original versus generated overlay header contract (`v1` or `v2`), row counts, SHA-256 digests, and pass or fail flags after parsing both files strictly through Coherence's Python reader.
- **`layer4` (Point-in-time NDJSON journal rebuild):**
  - NDJSON (newline-delimited JSON, one self-contained JSON record per line) journal replay into fresh throwaway PostgreSQL 17 databases at `midpoint` and `tip` cutoffs.
  - Per-moment counts: `cutoffSeq`, `replayed`, `journalEntriesChecked`, `tablesChecked`, `runsChecked`, `tableDiffCount` (`0`), `stageDiffCount` (`0`), `standingInputMatch` (`true`), and `standingOverlaySha256Match` (`true`).
- **`comparator` (Substance comparison targets, Gates 1 through 4):**
  - `ran`, `passed`, `targetsChecked`, `targetsPassed`, and per-target gate summaries:
    - `gate1` (Inputs first): file count, same count, changed count, only-left and only-right counts (must be zero mismatches; stops immediately on any input difference).
    - `gate2` (Canonical Book of Business, Coherence's authoritative policy table): left and right row counts, differing row count (`0`), SHA-256 digests, column mismatch counts, and cent deltas.
    - `gate3` (Coherent Ledger, Coherence's settled transaction ledger): left and right row counts, differing row count (`0`), SHA-256 digests, conservation pass flag (confirming downline and upline shares sum to gross commission with zero cent remainder), and Book-of-Business-to-Ledger downline and upline remainder cents (`0`).
    - `gate4` (Run delta statements CSV and entity statements): statements delta pass flag, differing row count (`0`), SHA-256 digests, and cent deltas.

---

## 6. How Long It May Take

Based on the expected source size (roughly `15 GB` to `17 GB` across all runs, inputs, and Nusear folders, matching the `35 GB` free-disk rule of at least twice the sources), expect the complete proof to take roughly **15 to 45 minutes** on local solid-state storage. Actual wall-clock time scales directly with `totals.files` and `totals.bytes` from Section 3's `--plan` output:

1. **Initial import and object promotion (~3 to 10 minutes):** Reads every source file once, computes SHA-256, MD5, and CRC32C checksums (integrity digests used to verify stored copies), runs full-buffer code-versus-data scans, writes unique objects once into `--stores-dir` (identical frozen inputs shared across runs deduplicate automatically), archives Git commit bundles, parses every historical overlay checkpoint via Python, and loads pre-Coherence statements and method corrections via the legacy Python bridge.
2. **Layer 1 byte-for-byte rebuild (~3 to 10 minutes):** Materializes every run folder, standing `input/`, `Incident Report/`, and standalone area from the database and object stores into temporary directories and re-hashes every file against disk.
3. **Layer 1 idempotency pass (~1 to 3 minutes):** Re-runs the importer without rebuild verification to prove zero new rows or objects are created.
4. **Layer 0 deep verification (~2 to 6 minutes):** Verifies the journal chain, recomputes 30-table commitment hashes, and re-reads every unique object in `stores/code` and `stores/data` to check byte size, SHA-256, MD5, CRC32C, and code-bearing content rules.
5. **Layer 2 overlay reconstruction (~2 to 6 minutes):** Regenerates every historical overlay checkpoint from PostgreSQL decision records and parses both original and generated CSVs through Coherence's Python reader.
6. **Layer 4 midpoint and tip journal rebuild (~2 to 5 minutes):** Exports the entire journal as NDJSON and replays it into two fresh throwaway PostgreSQL 17 databases, comparing all 31 business tables and derived stages.
7. **Substance comparator across 11 targets (~2 to 5 minutes):** Rebuilds each target run from the database and compares inputs, Canonical Book of Business, Coherent Ledger, conservation rollups, and `statements_YYYYMMDD.csv` cell for cell.

If `--plan` reports significantly more than `17 GB` of unique bytes, budget proportionally more time (roughly `1` to `2.5` minutes per unique gigabyte end to end). Let the command finish uninterrupted.

---

## 7. Clean-Up

**Keep both the throwaway PostgreSQL database (`test_phalanx_history_20261123`) and the private proof folder (`/Users/marcsmac/Code/nusear2.com/private-backups/proof-2026-11-23/`, including `stores/`, `nusear2.sqlite`, fingerprints, and `proof-summary.json`) until the owner explicitly says to remove them.**

Keeping them allows follow-up inspection, Layer 3 engine replay checks, and Layer 6 negative perturbation tests (deliberate single-change tests proving the checks fail when real data or decisions are altered) on a clone of the proven database without repeating the full import.

Confirm restrictive permissions remain set on the private folder (`700`) and files (`600`) while retained, because `stores/data/` and `nusear2.sqlite` contain customer and member records:

```sh
chmod 700 /Users/marcsmac/Code/nusear2.com/private-backups/proof-2026-11-23
chmod 700 /Users/marcsmac/Code/nusear2.com/private-backups/proof-2026-11-23/stores
```

Only **after the owner explicitly approves clean-up**, remove the throwaway database and private proof directory:

```sh
psql -h /tmp -p 5433 -U "$USER" -d postgres -c \
  "DROP DATABASE IF EXISTS test_phalanx_history_20261123;"
rm -rf /Users/marcsmac/Code/nusear2.com/private-backups/proof-2026-11-23
```

Never touch `/Users/marcsmac/Code/coherence` or `/Users/marcsmac/Code/nusear2.com/data` during clean-up.


## The 8/1 correction direction (corrected 2026-11-23)

The first real run stopped at the 8/1 correction: the importer gave the agencies +2,336.78 and the Phalanx upline -2,336.78, while the manifest expected the opposite. The expected values had been taken from a note of 11/20 that compared the old tabs with the ledger (old tab minus ledger: agencies -2,336.78, Phalanx +2,336.78, because the surviving 7/31 ALLAGENCY lines net negative). The correction that moves the old tab to the ledger is the reverse, which is what the importer computes (the 80/20 split is applied the right way for both commissions and chargebacks). The manifest now expects agencies +233678 cents and upline -233678 cents; the owner confirms against the 8/1 correction tab of the 11/20 workbook.


## The reference is the reference computer's Coherence (the owner, 2026-11-23)

The proof reproduces the reference computer's Coherence exactly. Every expected number is taken from Coherence's own outputs (its statements, their corrections and its coherent ledger), never from notes made about them. A difference is this system's to find and fix. An accounting fix, if one is ever needed, is made first in the reference computer's Coherence with the owner's approval, and this system then follows it.

## Known gap (11/23, both reviewers of the last round)

`--plan` accepts a pin whose folder or checkpoint key is shared by two items of different kinds (a legacy run and a company run, a plain and an extending checkpoint, a legacy run and a standalone checkpoint), while the import refuses it before any write (`PIN TARGETS, BEFORE ANY WRITE` in `src/importer/history-importer.mjs`). The import is the stricter side and fails closed, and Phalanx's manifest has no such collisions. The next change to `src/` brings `planImportManifestFile` to the same four sets.
