# Coherence Database Web App: Implementation Report

## Untested Status (Plain Statement)

Commands could not be executed in this session. Every artifact in this repository is currently untested against a live Node runtime, Python interpreter, or PostgreSQL 17 server:

- Untested SQL migrations: `migrations/001_schema.sql`, `migrations/002_invariants_and_triggers.sql`, `migrations/003_views_and_roles.sql`.
- Untested Node modules: all files under `src/` (including both the `pg` adapter and the built-in zero-dependency `src/db/wire-pg.mjs` wire-protocol fallback).
- Untested Python script: `python/coherence_overlay_check.py`.
- Untested test suite: all six `node:test` files under `tests/` and both helpers under `tests/helpers/`.

Everything below describes the code as written and statically reviewed, followed by exact choices, ambiguities, gaps, and what to test first on a real PostgreSQL 17 database.

---

## Requirement-by-Requirement Mapping (R1 to R19)

### R1. Purpose and Non-Negotiables
- **R1.1 (identical fundamental function):** Coherence's five phases (`assign`, `attribute`, `bible`, `adjust`, `emit`) are invoked unchanged by `src/worker/engine-runner.mjs` against an isolated folder built from the database (`src/worker/folder-builder.mjs`). Both human review pauses and Emit's typed confirmation remain mandatory.
- **R1.2 (never overwrite or delete):** All 20 business tables in `migrations/001_schema.sql` are append-only. `migrations/002_invariants_and_triggers.sql` attaches `BEFORE UPDATE OR DELETE OR TRUNCATE ... FOR EACH STATEMENT` triggers with `ENABLE ALWAYS TRIGGER` to every business table. Object storage in `src/storage/object-store.mjs` is create-only (`ifGenerationMatch=0` on GCS, exclusive hard-link on local filesystem).
- **R1.3 (database enforces integrity):** All business state transitions, uniqueness bounds, chain links, canonical commitments, path rules, code-versus-data store bindings, and running-slot checks are enforced inside PostgreSQL 17 constraints and triggers in `migrations/001_schema.sql` and `migrations/002_invariants_and_triggers.sql`.
- **R1.4 (Mac's Coherence untouched):** Nothing in this repository writes to `/Users/marcsmac/Code/coherence` or `/Users/marcsmac/Code/nusear2.com`. The history importer (`src/importer/history-importer.mjs`) opens source directories and SQLite strictly read-only.
- **R1.5 (Phalanx first; Clearpath isolated):** Separate databases per company (`coherence.company_meta` singleton identifies the company). `buildImportManifest` imports Mac history, Incident Report, and Runs Portal records only for `companySlug === 'phalanx'`; for `clearpath` it imports only Clearpath's own company runs and state.
- **R1.6 (customers never see Nusear code):** Strict two-store separation in `src/storage/artifact-policy.mjs`, `src/storage/stores.mjs`, `migrations/001_schema.sql` (composite foreign keys locking `store_kind`), `migrations/002_invariants_and_triggers.sql` (`is_code_bearing_path`), and `src/web/handlers.mjs` (never serving `.html` or code artifacts to clients).
- **R1.7 (separate DB per company; Kairon first):** Each company gets its own PostgreSQL 17 database and data store; `src/commands/authz.mjs` gives `owner` full rights.

### R2. Scope
- All in-scope server components are built: database migrations, two stores, command layer, engine worker, history importer, run folder comparator, downstream database reader, server-side web endpoints, and `node:test` acceptance suite.
- Out-of-scope items (modifying Coherence's code, emailing/sending outputs, moving the worker off the Mac, Coherence .1 entity statements, front-end UI) were left out as required.

### R3. Platform
- **R3.1 (PostgreSQL 17, local port 5433):** `src/db/pg-client.mjs` defaults local connections to `127.0.0.1:5433` (configurable via `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`), and uses only PostgreSQL 17 built-in `pg_catalog` functions (`sha256`, `normalize`, `pg_current_xact_id`, `pg_locks`, `pg_try_advisory_lock`) with zero required extensions.
- **R3.2 (Node ES modules + Coherence Python):** Pure Node 20+ ESM (`"type": "module"`). `src/worker/engine-runner.mjs` spawns Coherence's own Python binary from the verified workspace.
- **R3.3 (content-addressed object storage):** Objects are addressed strictly by `objects/<sha256>` in `src/storage/object-store.mjs` and `coherence.stored_files`.

### R4. Actors and Permissions
Implemented in `src/commands/authz.mjs` and enforced in `src/commands/command-layer.mjs` and `src/web/handlers.mjs`:
- **R4.1 (`owner`):** Permitted all human commands and typed decisions.
- **R4.2 (`nusear_staff`):** Checked against `actor.customers` for the company; refused on run-Coherence commands when `actor.withheld` includes `'run-coherence'`.
- **R4.3 (`company_admin`):** Read-only access to own company's inputs, runs, checks, and bundles; refused writes.
- **R4.4 (`recipient`):** Read-only access strictly to bundles matching `recipientRole` and `recipientScope` (`bundleMatchesRecipientScope` in `src/readers/downstream-reader.mjs`); 403 on journal, inputs, approvals, runs, or any other recipient's bundle.
- **R4.5 ("View as" vs acting for):** Any actor with truthy `viewingAs` is refused on every write command (`403 VIEW_AS_READ_ONLY`). Support staff passing `actingFor` can write and `acting_for` is recorded in `coherence.journal_entries` and included in `request_sha256`.
- **R4.6 (`worker`):** Dedicated `worker` actor kind; the only actor allowed to run worker-only commands (`start_attempt`, `finish_attempt`, `fail_attempt`, `cancel_attempt`, `interrupt_attempt`, `accept_review_submission`, `reject_review_submission`), and prevented from issuing human typed decisions.

### R5. Coherence's Interface
- **R5.1, R5.2, R5.3:** `src/worker/engine-runner.mjs` runs `coherence.phase1.assign`, `phase2.attribute`, `phase3.bible`, `phase3.adjust`, and `phase4.emit`. `src/worker/folder-builder.mjs` builds `input/` for `assign` and `runs/<date>/` (`input/`, `working/`, `overlay.csv`, `run.json`, etc.) for later steps.
- **R5.4:** Human pauses after `bible` and `adjust` are enforced in PostgreSQL triggers (`trg_step_requests_before`, `trg_step_attempt_events_before`, `trg_emit_confirmations_before`). Emit requires the typed phrase `"create statements for <date>"` naming the newest Adjust save.
- **R5.5:** Approvals files enforce v1 (10 columns) and v2 (15 columns) headers, append-only prefix extension (`extends_sha256` + `shared_row_count` + `coherence.approvals_extends()`), and SQL functions `coherence.approvals_current()` and `coherence.approvals_bible_applied()` in `migrations/003_views_and_roles.sql`.
- **R5.6 (determinism):** Clean git checkout verified via `git status --porcelain`; `buildCoherenceEnv` sets `LANG=en_US.UTF-8`, `LC_ALL=en_US.UTF-8`, `PYTHONUTF8=1`, `TZ=America/New_York`; `verifyCaseInsensitiveAllBob` verifies `ALL BOB` resolves when `All BOB` exists; `assertValidRelPath` preserves trailing spaces (`All BOB/Molina `) verbatim without trimming; replay writes back `run.json`'s recorded `born` after `assign`.
- **R5.7 (Emit modes):** `runs.emit_mode` supports `'coherence'`, `'builtin'`, and `'generated'` (with `emit_display`, `emit_keep`, `emit_no_manager`), executing sealed `company_emit.py` and `pages_law.py` for `'builtin'` and `'generated'`.
- **R5.8 (extended overlay check):** `python/coherence_overlay_check.py` runs under Coherence's Python using `coherence.overlay._read()`, verifies prefix rules, detects `header_kind` (`'v1'` or `'v2'`), and writes `new_rows` numbered from `shared + 1` to `--out` JSON so nothing else parses a live review file.

### R6. The 22 Data Shapes
All 22 shapes are modeled in `migrations/001_schema.sql`:
1. `company_meta` (R6.1)
2. `stored_files` (R6.2)
3. `input_versions` (R6.3)
4. `input_entries` (R6.4)
5. `input_changes` (R6.5)
6. `engine_versions` (R6.6)
7. `runs` (R6.7)
8. `step_requests` (R6.8)
9. `cancel_requests` (R6.9)
10. `step_attempt_events` (R6.10)
11. `artifacts` (R6.11)
12. `approvals_files` (R6.12)
13. `approval_rows` (R6.13)
14. `review_saves` (R6.14)
15. `review_submissions` (operational, R6.15)
16. `review_drafts` (operational, R6.16)
17. `emit_confirmations` (R6.17)
18. `carries` (R6.18)
19. `abandonments` (R6.19)
20. `imported_files` (R6.20)
21. `checks` (R6.21)
22. `journal_entries` (R6.22)

### R7. Relationships and Hierarchies
All foreign keys, partial unique indexes (linear standing input chain, one start/end/superseded per attempt, one start per request, one sent carry per date), and trigger checks (`prior_approvals_sha256` matching `Overlay/overlay.csv`, replay referencing an imported run, carries referencing the run's own finished Emit artifact, engine and code-bearing files bound strictly to `nusear_code`) are enforced in `migrations/001_schema.sql` and `migrations/002_invariants_and_triggers.sql`.

### R8. State Machines
- **Derived stages (never stored):** `coherence.run_stage(p_run_id, p_as_of_seq)` and view `coherence.run_states` in `migrations/003_views_and_roles.sql` derive all 11 stages (`preparing`, `running a step`, `waiting for Bible`, `waiting for Adjust`, `ready to create statements`, `emitting`, `done`, `failed`, `interrupted`, `cancelled`, `abandoned`).
- **Every transition and guard of R8:** Enforced both in `src/commands/command-layer.mjs` and independently in PostgreSQL triggers (`trg_runs_before`, `trg_runs_verify_deferred`, `trg_step_requests_before`, `trg_cancel_requests_before`, `trg_step_attempt_events_before`, `trg_review_saves_before`, `trg_review_saves_verify_deferred`, `trg_emit_confirmations_before`, `trg_emit_confirmations_verify_deferred`, `trg_carries_before`, `trg_abandonments_before`).

### R9. Database-Enforced Invariants
- **R9.1:** `forbid_mutation()` attached via `ENABLE ALWAYS TRIGGER` on `UPDATE`, `DELETE`, `TRUNCATE` across all 20 business tables (plus `DELETE`/`TRUNCATE` on `review_submissions`).
- **R9.2:** `trg_journal_before_insert` requires `transaction_isolation = 'serializable'`, checks gapless `seq`, `prev_hash`, monotonic `recorded_at`, and recomputed SHA-256 `entry_hash` over `coherence.canonical_json()` without ever overwriting caller-provided values. `trg_journal_single_row` (`AFTER INSERT ... REFERENCING NEW TABLE FOR EACH STATEMENT`) enforces strictly 1 row per `INSERT`.
- **R9.3:** `trg_require_active_journal` binds every child row to `created_xid = pg_current_xact_id()`, preventing any later transaction from attaching rows to a committed journal entry or committed approvals file. Deferred constraint triggers (`trg_journal_verify_commitments`, `trg_input_versions_verify_deferred`, `trg_approvals_files_verify_deferred`, `trg_step_attempt_events_verify_deferred`) verify declared counts and canonical hashes at `COMMIT`.
- **R9.4:** All R8 guards, re-save rules, one open request per run, Emit confirmation binding to newest Adjust save, one sent carry per date, approvals carry extending standing file, and abandon guards enforced in triggers.
- **R9.5:** `trg_input_versions_verify_deferred` checks exact bidirectional diff matching against `input_changes`, checks file/folder clashes ignoring case and NFC normalization (`UNIQUE(input_version_id, mac_key)` blocks case/NFC twins immediately), and inspects `input_entries` directly (not `input_changes`) to restrict `Sent/`, `Overlay/`, and `approvals/` changes to carries or imports.
- **R9.6:** PostgreSQL session advisory lock (`coherence.slot_class_id()`, `coherence.slot_obj_id()`) checked directly against `pg_catalog.pg_locks` inside triggers (`this_connection_holds_slot()`, `slot_is_free()`), bound to `(pg_backend_pid(), own_backend_start())`.
- **R9.7:** `stored_files.object_name = 'objects/' || sha256` `CHECK` constraint; composite foreign keys and `is_code_bearing_path` trigger prevent engine or code-bearing files from ever referencing `company_data`.

### R10. Failures and Races
- **R10.1, R10.2, R10.3:** `src/worker/slot.mjs` holds a dedicated PG connection with the advisory lock, runs liveness queries strictly between transactions (`inTransaction` guard) with timeout, and aborts all in-flight operations on slot loss. `src/worker/reconciler.mjs` marks dead open attempts `interrupted` before anything else runs. Database triggers refuse recording `finished`/`failed`/`cancelled` unless called on the exact slot connection that started the attempt.
- **R10.4:** `src/worker/engine-runner.mjs` spawns steps `detached: true` in their own process group, kills the entire process group (`process.kill(-pid, ...)`) at the 15-minute step limit, on cancel request, or on slot loss.
- **R10.5, R10.6:** `src/commands/command-layer.mjs` checks `expectedJournalSeq` against `run_latest_journal_seq(runId)` / standing input seq and enforces `command_key` + `request_sha256` idempotency inside `SERIALIZABLE` transactions.
- **R10.7:** `submitReview` stages bytes outside `objects/` and returns `202` immediately; the worker checks staged bytes with `coherence_overlay_check.py`, promotes only after checks pass, and accepts/rejects in one transaction so bad submissions never stall the worker.
- **R10.8:** `src/storage/object-store.mjs` and `src/storage/stores.mjs` enforce `checksPassed === true`, create-only upload, MD5 + CRC32C verification on both fresh uploads and 409/412 existing objects, and safe resume after interrupted promotion.
- **R10.9:** `src/worker/folder-builder.mjs` builds a fresh verified temp folder per attempt, always deletes it in `finally`, and `verifyFrozenInputUnchanged` re-hashes every file under `runs/<date>/input/` after each step.
- **R10.10:** `command-layer.mjs` batches large inserts (`stored_files`, `input_entries`, `input_changes`, `artifacts`, `approval_rows`) in chunks of 2,000 rows via `pg_catalog.unnest(...)`.
- **R10.11:** `src/importer/history-importer.mjs` uses deterministic command keys and DB uniqueness constraints so imports are idempotent and resumable.
- **R10.12:** `src/commands/journal-export.mjs` exports the journal as NDJSON (`exportJournalNdjson`) and rebuilds a fresh database verifying every hash and commitment (`rebuildFromJournalExport`).

### R11. Lessons Learned
Every named lesson (`RP-1`, `RP-2`, `CR-1`, `CR-6`, `CR-7`, `CR-8`, `CR-9`, `W-4`, `W-9`, `S-8`, `DS-1`, `DS-2`, 11/20 agent file EYES, 11/21 renames, post-10/21 Nusear review saves, birth key / `ALL BOB` / UTF-8 / trailing space / Emit modes, and all 7 audit traps: table-lock privilege, trojan `search_path`, non-overwriting triggers, multi-row insert refusal, promotion before checks, out-of-transaction liveness query, and non-sandboxed viewer headers) is both enforced in code and covered by dedicated tests in `tests/01` through `tests/06`.

### R12. History Importer
Implemented in `src/importer/history-importer.mjs`: read-only `buildImportManifest`, `importSingleRunFolder`, `executeHistoryImport` with byte-for-byte rebuild proof (`rebuildRunFolderFromDb`), object check (`verifyObjects`), Nusear SQLite parity counts (including pre-`record-cleared` events), and recorded `checks(check_kind = 'import')` report.

### R13. Proof Against the Mac
Implemented in `src/compare/run-comparator.mjs`: `compareRunFolders` and `compareDbRuns` supporting `storage`, `replay`, `shadow`, `trial`, and `clearpath_vs_mac` modes, always comparing `input/` file by file first, honoring R13's exact allowed differences, mapping non-`InsureItAll` entities to `Clearpath` and verifying `company_manifest.json` bundles for Clearpath-versus-Mac proofs.

### R14. Code Protection, Security, and Member Data
- **R14.1:** Enforced via `createStorePair` (refusing shared backends), `assertDataSafeForCompanyStore` (path + content inspection), and DB foreign keys/triggers.
- **R14.2:** Web handlers never serve `viewer.html` or `bible.html`/`adjust.html` code; bundles serve server-checked JSON config and signed-in CSV endpoints.
- **R14.3:** `src/util/redact.mjs` scrubs `record_id`, `policy:...`, MBI, SSN, email, and phone patterns from error messages and structured logs. Approval key history supports `POST` JSON body so `record_id` stays out of URL access logs.
- **R14.4:** `src/db/pg-client.mjs` enforces TLS or Cloud SQL Auth Proxy socket and IAM service account user in `cloudsql` mode; `migrations/003_views_and_roles.sql` configures least-privilege `coherence_app`, `coherence_worker`, and `coherence_readonly` roles.
- **R14.5, R14.6:** Open operational/compliance decisions documented under R19 below.

### R15. Downstream Readers
Implemented in `src/readers/downstream-reader.mjs`: `createDatabaseCoherenceReader` (matching `lib/coherence.mjs`) and `createDatabaseClearpathFeed` (matching `lib/clearpath-feed.mjs`, including HMAC-SHA256 verification with nonce replay guard, 24-column no-dollar `AGENT_BOOK_COLUMNS` filtering, and 8-feature `HOUSE_FEATURES` filtering), selecting strictly the newest finished, non-abandoned `app` or `company_import` run.

### R16. Screens (Server-Side Handlers)
Implemented in `src/web/handlers.mjs`, `src/web/router.mjs`, and `src/web/drift-check.mjs`:
- **R16.1:** Input versions & changes, Staging listing, "Include in calculations" with reason, general input publish.
- **R16.2:** Run listing/detail/launch, step logs, review config JSON, attempt-keyed drafts, non-blocking review submission + status poll, Emit typed confirmation, data outputs, carry sent/approvals, cancel, retry, abandon, and review app drift check against Coherence's `web/src/adjust`.
- **R16.3:** History `"as of"` any journal sequence or timestamp, per-run full journal, and approval key full history.
- **R16.4:** Verification checks listing, detail, and on-demand `chain`/`commitments`/`objects` check runner.
- **R16.5:** Scope-checked recipient bundle listing, config, and data endpoints without restrictive `sandbox` CSP headers.

### R17. Non-Functional
- **R17.1, R17.2, R17.4:** Large writes batched via `unnest` (2,000 rows/batch); long-running work (Coherence steps and review checks) runs asynchronously in the worker while web requests answer immediately (`202 Accepted`); HTTP responses negotiate gzip.
- **R17.3:** `folder-builder.mjs` supports on-demand working-table rebuild hooks (`rebuildWorkingOnDemand`) if derivable working tables are omitted from object storage, proving rebuilt tables against recorded fingerprints.

### R18. Acceptance Tests
Six `node:test` files under `tests/` cover every named item of R18 and R11, runnable against a local PostgreSQL 17 (`PGPORT=5433` default). Live Mac proof (`2026-11-21` import & rebuild) is included and gated behind `COHERENCE_MAC_PROOF=1` so default runs stay completely isolated from live PHI paths (W-9).

---

## Design Choices Where Requirements Left Room

1. **Explicit UUID primary keys for business entities (and explicit `BIGINT` `seq` for `journal_entries`):** Rather than PostgreSQL `IDENTITY`/`SERIAL` columns on entity tables, entity IDs are UUIDs committed in `journal_entries.body`. During journal export rebuild (`R10.12`), every ID, foreign key, and commitment hash reproduces identically without sequence drift.
2. **Composite primary key `(store_kind, sha256)` on `coherence.stored_files`:** An empty 0-byte file (such as an empty `__init__.py` in Nusear's code store and an empty log file in a company's data store) shares the same SHA-256. Keying by `(store_kind, sha256)` lets both stores coexist cleanly while allowing composite foreign keys (`CHECK (store_kind = 'nusear_code')` vs `CHECK (store_kind = 'company_data')`) to make store mixing structurally impossible in PostgreSQL.
3. **2-argument session advisory lock plus `(pg_backend_pid(), own_backend_start())`:** Using `pg_try_advisory_lock(1129270853, 1397509972)` avoids 64-bit bit-shift signedness quirks in `pg_locks`. Recording the starter's `(pid, backend_start)` (read only for the current session from `pg_stat_activity WHERE pid = pg_backend_pid()`, which requires zero `pg_read_all_stats` or `SECURITY DEFINER` grants) prevents PID reuse (S-1) and guarantees a reconnected worker can never finish an attempt started on an earlier lost connection (R10.2).
4. **Canonical JSON (`coherence.canonical_json` + `src/util/crypto.mjs`) and UTC microsecond timestamps:** PostgreSQL's `jsonb::text` sorts object keys by `(length, lex)` rather than pure codepoint/UTF-8 order. Our `coherence.canonical_json` sorts object keys by `COLLATE "C"` (UTF-8 byte order) with no extra whitespace, and formats timestamps as `YYYY-MM-DDTHH:MM:SS.ffffffZ`, matching `src/util/crypto.mjs` identically across languages.
5. **Unified `body.commitments` structure:** Every journal entry carries `body.commitments = { counts, hashes }` alongside human-readable inline objects (`body.run`, `body.carry`, etc.). A deferred constraint trigger on `journal_entries` verifies all 19 business table counts and canonical hashes at `COMMIT`, while `created_xid = pg_current_xact_id()` blocks attaching rows to any already-committed journal entry.
6. **PostgreSQL driver adapter (`pg` with built-in zero-dependency `wire-pg.mjs` fallback):** `package.json` pins `"pg": "8.13.1"`, which `src/db/pg-client.mjs` loads when installed. If `node_modules` has not been installed, it falls back automatically to `src/db/wire-pg.mjs` (a minimal PG v3.0 wire protocol client supporting Unix socket, TCP, TLS, trust/cleartext/MD5/SCRAM-SHA-256, and Extended Query).
7. **Typed confirmation phrases scoped to the company database:** Since each company has its own separate database (R1.7) and R5.4 explicitly names `"create statements for <date>"`, all typed phrases follow the uniform per-database format: `"create statements for <date>"`, `"sent <date>"`, `"carry <date>"`, `"cancel <date>"`, and `"abandon <date>"`.
8. **Approval key history over `POST` body:** `src/web/router.mjs` accepts `POST /api/coherence/:company/approvals/history` with `{ recordId }` in the JSON body (in addition to `GET`) so member-identifying `record_id` strings do not appear in HTTP URL access logs (R14.3).
9. **Operational `review_submissions` without reverse FK from `review_saves`:** `review_submissions.review_save_id` references `review_saves(id)`, while `review_saves.submission_id` is `UUID UNIQUE` without a foreign key back to the operational table. This lets a business-only journal export rebuild cleanly without requiring operational rows, while `trg_review_submissions_guard` still guarantees accepted submissions bind to a `review_save` created in the same transaction.

---

## Ambiguities, Tensions, and Unmet / Open Items

1. **R8 reconciler guard ("slot free") vs R10.1 worker startup reconciliation:**
   - R8 states the guard for `interrupted` as `slot free; no end`, while R10.1 requires open attempts from a dead worker to be marked `interrupted` before anything else runs. If a new worker acquires the slot first and reconciles before picking up work, the slot is held by the new worker rather than free.
   - Resolution: `trg_02_step_attempt_events_before` allows `interrupted` when EITHER `slot_is_free()` is true OR the current connection holds the slot with a different `(pid, backend_start)` than the attempt's starter, and always refuses while the original starter still holds the slot.
2. **R17.3 ("working tables as fingerprints, rebuilt on demand") vs R12.4 / R13.1 ("every source folder rebuilt identical byte by byte"):**
   - Historical runs executed on uncommitted code (and older runs whose `working/` files were hand-edited or built on older toolchains) cannot be guaranteed to re-derive identical `working/` bytes on demand, so the importer stores `working/` artifacts in `company_data` to guarantee R12.4 byte-for-byte rebuild.
   - For new runs, `worker.mjs` currently promotes all step artifacts including `working/`, while `folder-builder.mjs` includes the `rebuildWorkingOnDemand` hook to support switching new runs to fingerprint-only working tables once storage policy is finalized.
3. **R14.2 / R15 viewer configuration inside `viewer.html`:**
   - Because Coherence currently stamps `window.__VIEWER_CONFIG__` inside `viewer.html` (which is `code_bearing` and therefore stored only in `nusear_code`), `downstream-reader.mjs` reads `viewer.html` from `codeStore` on Nusear's server solely to extract the JSON config, and reads all CSV data exclusively from `company_data`. No HTML or code bytes are ever sent to customers or stored in `company_data`. A future Coherence release that emits a separate data-only `viewer_config.json` would allow the downstream reader to read from `company_data` alone.
4. **R12.1 Google storage import & git bundles for historical commits:**
   - `history-importer.mjs` imports Mac runs, company workspaces/runs/environments, Nusear review saves, Incident Report, Staging/Documents/archive inventories, and Nusear SQLite tables. Live Google Cloud Storage list/bucket ingestion (`lists/*.json`, `approvals/overlay_*.csv`, remote finished buckets) requires service account credentials and network access, so it is left as a clear extension point rather than executed against live buckets.
   - R18 live Mac replay of `2026-10-21`, `2026-11-02`, and `2026-11-21` requires sealing each historical commit's exact Python/web offline dependencies into `nusear_code` (the test suite exercises full replay with birth write-back using the mock engine, and gates live Mac `2026-11-21` storage rebuild behind `COHERENCE_MAC_PROOF=1`).
5. **R19 open items for Kairon:**
   - Post-development retention lock (HIPAA 6-year vs CMS 10-year object lock policy).
   - Fixed egress IP allow-list for Cloud SQL.
   - Stopping legacy `lib/company-storage.mjs` copies of `viewer.html` into companies' finished buckets and removing historical copies already there.
   - Confirming the takeover rule (proposed: three consecutive matching dates, one writing statements).
   - Cloudflare BAA / tunnel decision for carrying member data.

---

## What to Test First on a Real PostgreSQL 17 Database

Run these steps in exact order on the Mac against local PostgreSQL 17 (`PGPORT=5433`):

1. **Install `pg` (and also verify fallback):**
   - Run `PGPORT=5433 node --test tests/03_stores_and_security.test.mjs` first (pure Node, no DB) to verify CRC32C vectors, store separation, promotion-before-checks refusal, and PHI redaction immediately.
   - Next, test `migrations/001_schema.sql`, `002_invariants_and_triggers.sql`, and `003_views_and_roles.sql` directly via `psql -p 5433 -v ON_ERROR_STOP=1` on a fresh throwaway database to catch any PostgreSQL 17 SQL/PLpgSQL syntax, regex, or generated-column (`lower(normalize(rel_path, 'NFC'))`) edge cases immediately.
2. **Verify database invariants and role privileges (`tests/01_schema_invariants.test.mjs`):**
   - Run `npm install` (to use battle-tested `pg` 8.13.1), then `PGPORT=5433 node --test tests/01_schema_invariants.test.mjs`.
   - Specifically verify: `ENABLE ALWAYS TRIGGER` under `session_replication_role = 'replica'`, `SET ROLE coherence_app` denying `LOCK TABLE ... IN EXCLUSIVE MODE`, trojan `search_path`, non-overwriting hash/seq verification, two-row INSERT refusal, NFC/NFD and case-twin refusals, and Sent/Overlay protection.
   - Also run once without `node_modules` (or by invoking `WireClient`/`WirePool` directly) to verify the `src/db/wire-pg.mjs` fallback wire client (especially `SCRAM-SHA-256`, `text[]` array binding in `unnest`, and `pg_terminate_backend` error handling).
3. **Verify command races, state transitions, and journal export rebuild (`tests/02_commands_and_races.test.mjs`):**
   - Confirm concurrent `Promise.allSettled` review submissions serialize cleanly, CR-1 / CR-8 / CR-9 / S-8 guards fire at the DB layer, and `exportJournalNdjson` -> `rebuildFromJournalExport` reproduces an identical `headHash` on an empty database.
4. **Verify engine worker failures, slot loss, cancel, and timeout (`tests/04_worker_and_failures.test.mjs`):**
   - Confirm `pg_terminate_backend` triggers `slot_lost` without recording `finished` (RP-2), out-of-transaction liveness checker records 0 in-transaction queries, grandchild processes die on process-group cancel, and rejected review submissions leave 0 promoted objects and do not stall the worker.
5. **Verify `python/coherence_overlay_check.py` with Coherence's real `.venv`:**
   - Run `python/coherence_overlay_check.py --parse-only` against a small synthetic v1 and v2 CSV using Coherence's `.venv/bin/python` to confirm Polars header detection and `coherence.overlay._read()` behavior match.
6. **Verify synthetic import, replay, downstream readers, and HTTP router (`tests/05` and `tests/06`):**
   - Run `PGPORT=5433 node --test tests/05_import_compare_replay.test.mjs tests/06_readers_and_web.test.mjs`.
7. **Run the read-only live Mac 2026-11-21 storage/rebuild proof:**
   - Run `COHERENCE_MAC_PROOF=1 PGPORT=5433 node --test tests/05_import_compare_replay.test.mjs` (read-only into a throwaway database and temp directory) to prove the real `2026-11-21` Mac run folder imports cleanly and rebuilds byte for byte, with zero code-bearing files in `company_data`.
   - Only after `2026-11-21` storage rebuild passes, seal the exact engine versions for `2026-10-21`, `2026-11-02`, and `2026-11-21` and run full live Coherence replays comparing whole trees per R13.2.
