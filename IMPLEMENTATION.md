# Coherence Database Web App: Implementation Report

## Verification Status (Round 2 — Live PostgreSQL 17 Verified)

All SQL migrations, Node modules, configuration policies, declarative state machines, and all five risk-ranked test suites have been executed and verified against the local Homebrew PostgreSQL 17.12 server (`PGHOST=/tmp PGPORT=5433 PGUSER=marcsmac`, isolated `neon_test_*` databases) on Node `v26.5.0` using the standard `pg` (`8.13.1`) driver:

- **Syntax check (`node --check`):** 35 of 35 `.mjs` files pass (`npm run check`).
- **State machine documentation parity:** `STATE_MACHINE.md` matches the declarative specification in `src/state-machine/coherence-machines.mjs` byte for byte (`npm run docs:state-machine:check`).
- **Raw `psql` migrations:** `migrations/001_schema.sql`, `002_invariants_and_triggers.sql`, and `003_views_and_roles.sql` apply cleanly with `-v ON_ERROR_STOP=1`.
- **Test suites (5 risk-ranked layers):** **23 passed, 0 failed, 1 skipped** (the 1 skipped test is the opt-in live Mac proof gated by `COHERENCE_MAC_PROOF=1` per W-9 and Round 2's isolation rules so tests never open live member data files).
- **Still failing:** **None (0 failures).**

---

## Round 2 Changes and Why

### 1. Review Fixes (Items 1–6)

1. **Syntax check before every test run (Item 1):**
   - Added `scripts/check-syntax.mjs` (`npm run check`), wired directly into `npm test`, running `node --check` on every `.mjs` file in the repository before any test executes. Verified `src/commands/command-layer.mjs` has no remaining SQL doubled-quote strings in JS.
2. **Multi-array `unnest` fixed everywhere (Item 2):**
   - PostgreSQL's multi-argument `unnest(arr1, arr2, ...)` is only valid unqualified in a `FROM` clause (`pg_catalog.unnest(text[], text[])` does not exist). Fixed all 6 multi-array `unnest` queries in `src/commands/command-layer.mjs` (`filterNewStoredFiles`, `insertStoredFilesBatch`, `insertInputEntriesBatch`, `insertInputChangesBatch`, `insertArtifactsBatch`, `insertApprovalRowsBatch`) to use unqualified `FROM unnest(...) AS t(...)`.
   - Proved on live PostgreSQL 17 in Layer 1 with a multi-chunk batched insert of 2,150 `approval_rows` (> `BATCH_SIZE = 2000`) plus batched `stored_files`, `input_entries`, `input_changes`, and `artifacts`.
3. **Local PostgreSQL 17 environment defaults and `neon_test_*` database isolation (Item 3):**
   - Updated `tests/helpers/test-db.mjs` and `src/db/pg-client.mjs` to default local connections to `PGHOST || '/tmp'`, `PGPORT || 5433`, and `PGUSER || USER || os.userInfo().username`, never falling back to `'postgres'`.
   - Switched all test databases (including empty journal-rebuild databases via `createEmptyMigratedTestDb`) strictly to the `neon_test_*` prefix with an `assertTestDbName` guard refusing any create/drop outside `neon_test_*`.
   - Proved by a unit test in Layer 1 that unsets `PGUSER`, `USER`, `PGHOST`, and `PGPORT`.
4. **Root causes fixed to move from 11/24 to 23/23 passing (Item 4 — zero expectations weakened):**
   - **Production code bugs fixed:**
     - Six `pg_catalog.unnest(...)` calls in `src/commands/command-layer.mjs` (blocked nearly every write in Round 1).
     - `TIMESTAMPTZ` microsecond truncation in `pg` + `src/util/crypto.mjs`: `pg` converted `TIMESTAMPTZ` into JS `Date` (millisecond precision), dropping 3 microsecond digits, and `formatTimestampUtcUs` did not match PostgreSQL's 2-digit offset (`+00`, `-05`), causing `verifyChain` and journal export/rebuild to disagree with PostgreSQL's `compute_journal_hash`. Fixed by preserving raw timestamp strings in `src/db/pg-client.mjs` (`types.setTypeParser(1184/1114)`), supporting short offsets (`[+-]\d{2}`) in `src/util/crypto.mjs`, and explicitly selecting `coherence.format_utc_us(recorded_at)` / `original_at` in `src/commands/journal-export.mjs`.
     - PHI and SQL parameter redaction hardening in `src/util/redact.mjs`: fixed tilde `record_id` matching so member names containing spaces (`uhc~direct~SMITH JOHN~100.00~2026-11`) are fully scrubbed; added scrubbing for PostgreSQL `Key (...)= (...)`, `Failing row contains (...)`, `PARAMETERS: ...`, and `$1 = '...'` leaks; scrubbed sensitive keys in `createSafeLogger`.
     - URL `recordId` enforcement in `src/web/router.mjs`: removed `GET /api/coherence/:company/approvals/history` (now returns `405`, requiring `POST` JSON body) and added router-level rejection (`400 RECORD_ID_IN_URL_FORBIDDEN`) whenever any URL query or path carries `recordId`/`record_id` or a member/record identifier.
     - Customer-to-code isolation in `src/web/handlers.mjs`: restricted `getReviewConfig`, `getReviewDraft`, `getReviewSubmission` to `'approvals'` and `getReviewDriftStatus` to `'journal'` (Nusear staff/owner only, refusing `company_admin` and `recipient` with `403`), and added an explicit `isCodeBearingPath(path)` `403` guard at the entry of `getBundleFile`.
   - **Test-harness bugs fixed (no requirement expectation was changed or relaxed):**
     - `tests/helpers/fixtures.mjs`: mock Python engine interpolated JS `JSON.stringify(null)` (`null`) instead of Python `None`, causing `NameError: name 'null' is not defined` on every step; fixed with `pyLit`. Also matched `json.dumps(..., separators=(',', ':'))` in the mock HTML generator so replay byte-for-byte HTML comparisons match JS `JSON.stringify`.
     - `tests/helpers/test-db.mjs`: Node `node:test` runs `t.after` hooks in FIFO order, so `env.cleanup()` terminated backends before test-local `client.end()` ran (`57P01`). Added `env.registerClient(client)` so cleanup closes all clients before `pg_terminate_backend`.
5. **Four requirement clarifications honored (Item 5):**
   - **Reconciler slot rule:** Confirmed and tested in Layer 3 — `trg_02_step_attempt_events_before` allows marking a dead attempt `interrupted` when the slot is free OR held by a different `(pid, backend_start)` than the attempt's starter, and refuses while the original starter still holds the slot.
   - **Working tables storage:** Confirmed and tested in Layer 4 — imported runs keep all `working/` bytes in `company_data` for R12.4 byte-for-byte rebuild; new runs may omit derivable working bytes once replay is proved, using `buildAttemptWorkspace`'s `rebuildWorkingOnDemand` hook to rebuild and verify against recorded fingerprints.
   - **Viewer configuration on Nusear's server only:** Confirmed and tested in Layers 2 & 5 — `viewer.html` lives solely in `nusear_code`, is parsed strictly on Nusear's server to extract JSON config, and never leaves Nusear's server or reaches customers.
   - **Google import:** Kept as a documented extension point in `src/importer/history-importer.mjs`.
6. **Standard `pg` package & retained choices (Item 6):**
   - Installed `pg` `8.13.1` (`npm install`), removed `src/db/wire-pg.mjs`, and simplified `src/db/pg-client.mjs` to use `pg` directly (`driverName === 'pg'`).
   - Kept all five preferred choices: stores separated by composite key `(store_kind, sha256)`, slot starter identity with `(pid, backend_start)`, database-checked per-entry commitments, rebuild-stable explicit UUID identifiers, and record ids strictly excluded from URLs.

### 2. New Testing, Configuration, and State Machine Architecture (Items 7–10)

7. **Risk-ranked test layers (Item 7):**
   - Reorganized all tests into 5 files ordered by worst cost of failure first, each stating what it protects:
     1. `tests/layer1_money_and_history.test.mjs` — Money and immutable history.
     2. `tests/layer2_member_data_code_and_config.test.mjs` — Member data confidentiality, Nusear code protection, and security configuration.
     3. `tests/layer3_state_machine_and_races.test.mjs` — State machine integrity, concurrency races, and worker failure recovery.
     4. `tests/layer4_import_and_proofs.test.mjs` — History import, byte-for-byte rebuild, replay proofs, and run comparison.
     5. `tests/layer5_screens_and_readers.test.mjs` — Downstream readers, Clearpath feed, HTTP screens, recipient scoping, and drift check.
8. **Negative invariants (Item 8):**
   - Layer 1 proves: no `UPDATE`, `DELETE`, or `TRUNCATE` succeeds on any of the 20 business tables (normal and `session_replication_role = 'replica'`); no second sent statement for a date (via command layer, re-launch, or raw SQL).
   - Layer 2 proves: no code-bearing file or engine byte in a company store (storage + DB); no record id, member identifier, or SQL parameter in any log, error, or URL (including real PostgreSQL errors through `command-layer` and HTTP router URL checks); no write while viewing as someone (`viewingAs`); no path from customer roles (`company_admin`, `recipient`) to any code.
9. **Configuration assertions (Item 9):**
   - Added `config/cloudsql-instance.json` (declarative Cloud SQL PostgreSQL 17 security policy) and `src/config/policy-checks.mjs`.
   - Layer 2 asserts on live migrated PostgreSQL 17 and local files:
     - `coherence_app` has strictly `SELECT` and `INSERT` on all 20 business tables (no `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, and cannot acquire `EXCLUSIVE`/`SHARE`/`ACCESS EXCLUSIVE` table locks); `coherence_worker` has strictly `SELECT` and `INSERT` on all 20 business tables; `coherence_readonly` has `SELECT` only; `PUBLIC` has zero schema/table/function privileges.
     - `trg_immutable` is present and `ENABLE ALWAYS` (`tgenabled = 'A'`) on all 20 business tables (and `review_submissions` guards are `ENABLE ALWAYS`).
     - Every function in schema `coherence` (all 55 functions) pins `SET search_path = pg_catalog`.
     - Local `/opt/homebrew/var/postgresql@17/pg_hba.conf` contains zero `trust` (or `password`/`md5`) lines (6 active rules: `peer` on local sockets, `scram-sha-256` on TCP), with a negative test proving a `trust` line is caught.
     - `config/cloudsql-instance.json` passes the R3.1 / R14.4 Cloud SQL checklist (PostgreSQL 17, `requireSsl: true`, `sslMode: "ENCRYPTED_ONLY"`, `authorizedNetworks: []`, `ipv4Enabled: false`, IAM auth on, `pgaudit.log_parameter: "off"`, `log_parameter_max_length: "0"`, `log_parameter_max_length_on_error: "0"`), with a negative test proving misconfigurations fail.
10. **State machine as data (Item 10):**
    - Built a reusable declarative state-machine library in `src/state-machine/declarative-machine.mjs` (`defineStateMachine`, static reachability/dead-end validation, guard evaluation, PostgreSQL catalog verification, and Markdown + Mermaid doc generation) designed for reuse across Nusear's other tools.
    - Declared Coherence's `RUN_STAGE_MACHINE` (11 derived stages, 18 transitions, 16 guards) and `STEP_ATTEMPT_MACHINE` (7 states, 6 transitions, 10 guards) once in `src/state-machine/coherence-machines.mjs`.
    - Generated `STATE_MACHINE.md` via `scripts/generate-state-machine-doc.mjs` (`npm run docs:state-machine` / `--check`).
    - Layer 3 verifies static graph checks (including negative tests rejecting unreachable states, dead-ends, and unknown guards), verifies every declared table/trigger/function/index/`CHECK` constraint enum and `coherence.run_stage()` return literal against PostgreSQL 17 system catalogs, verifies `STATE_MACHINE.md` parity byte for byte, and walks live runs in PostgreSQL 17 through **all 11 declared run stages** and **all 7 step attempt states**, asserting `coherence.run_stage()` matches `deriveRunStage()` at every step.

---

## Round 2 Test Results by Suite

All commands were executed inside `/Users/marcsmac/Code/coherence-db-neon` with `PGHOST=/tmp PGPORT=5433 PGUSER=marcsmac`.

| Suite / Check | Exact Command | Result | Duration |
|---|---|---|---|
| Raw PostgreSQL 17 migrations | `createdb neon_test_migrations_check && psql -d neon_test_migrations_check -v ON_ERROR_STOP=1 -f migrations/001_schema.sql -f migrations/002_invariants_and_triggers.sql -f migrations/003_views_and_roles.sql >/dev/null && dropdb neon_test_migrations_check` | **PASS** (`RAW_PSQL_MIGRATIONS_OK`) | <1 s |
| Syntax check (`node --check`) | `npm run check` (`node scripts/check-syntax.mjs`) | **PASS** (35/35 `.mjs` files) | <1 s |
| `STATE_MACHINE.md` drift check | `npm run docs:state-machine:check` | **PASS** (`STATE_MACHINE.md is up to date.`) | <1 s |
| Layer 1: Money & History | `node --test tests/layer1_money_and_history.test.mjs` | **PASS** (6 pass, 0 fail, 0 skipped) | 2.78 s |
| Layer 2: Member Data, Code & Config | `node --test tests/layer2_member_data_code_and_config.test.mjs` | **PASS** (5 pass, 0 fail, 0 skipped) | 1.21 s |
| Layer 3: State Machine & Races | `node --test tests/layer3_state_machine_and_races.test.mjs` | **PASS** (7 pass, 0 fail, 0 skipped) | 5.03 s |
| Layer 4: Import & Proofs | `node --test tests/layer4_import_and_proofs.test.mjs` | **PASS** (2 pass, 0 fail, 1 skipped\*) | 0.84 s |
| Layer 5: Screens & Readers | `node --test tests/layer5_screens_and_readers.test.mjs` | **PASS** (3 pass, 0 fail, 0 skipped) | 2.56 s |
| Combined full run | `npm test` | **PASS** (23 pass, 0 fail, 1 skipped\*) | ~5.5 s |

\* The single skipped test (`Layer 4 [R18 opt-in COHERENCE_MAC_PROOF=1]`) is intentionally opt-in so default test runs obey W-9 and never touch live member data files under `/Users/marcsmac/Code/coherence/runs` or `/Users/marcsmac/Code/nusear2.com/data`. Zero tests failed.

---

## Requirement-by-Requirement Mapping (R1 to R19)

### R1. Purpose and Non-Negotiables
- **R1.1 (identical fundamental function):** Coherence's five phases (`assign`, `attribute`, `bible`, `adjust`, `emit`) are invoked unchanged by `src/worker/engine-runner.mjs` against an isolated folder built from the database (`src/worker/folder-builder.mjs`). Both human review pauses and Emit's typed confirmation remain mandatory.
- **R1.2 (never overwrite or delete):** All 20 business tables in `migrations/001_schema.sql` are append-only with `BEFORE UPDATE OR DELETE OR TRUNCATE ... ENABLE ALWAYS TRIGGER` (`migrations/002_invariants_and_triggers.sql`), verified across all 20 tables in Layer 1 and catalog-audited in Layer 2. Object storage (`src/storage/object-store.mjs`) is create-only (`ifGenerationMatch=0` on GCS, exclusive hard-link on local filesystem).
- **R1.3 (database enforces integrity):** All business state transitions, uniqueness bounds, chain links, canonical commitments, path rules, code-versus-data store bindings, and running-slot checks are enforced inside PostgreSQL 17 constraints and triggers.
- **R1.4 (Mac's Coherence untouched):** Nothing in this repository writes to `/Users/marcsmac/Code/coherence` or `/Users/marcsmac/Code/nusear2.com`. `src/importer/history-importer.mjs` reads strictly read-only.
- **R1.5 (Phalanx first; Clearpath isolated):** Separate databases per company (`coherence.company_meta` singleton). `buildImportManifest` imports Mac history, Incident Report, and Runs Portal records only for `phalanx`; Clearpath imports only Clearpath's own runs.
- **R1.6 (customers never see Nusear code):** Enforced across storage (`src/storage/artifact-policy.mjs`, `src/storage/stores.mjs`), database composite FKs and triggers, and web handlers (`src/web/handlers.mjs`), proven by Layer 2 negative invariants.
- **R1.7 (separate DB per company; Kairon first):** Each company has its own PostgreSQL 17 database and data store; `src/commands/authz.mjs` gives `owner` full rights.

### R2–R18 Coverage Summary
- **R3 (Platform):** PostgreSQL 17 with standard `pg` 8.13.1 (`src/db/pg-client.mjs`), zero custom wire client, zero required PG extensions; Node ESM; content-addressed `objects/<sha256>` stores.
- **R4 (Actors & Permissions):** `src/commands/authz.mjs` + `src/commands/command-layer.mjs` + `src/web/handlers.mjs` enforce `owner`, `nusear_staff` (`customers`, `withheld`), `company_admin`, `recipient`, `worker`, `viewingAs` read-only refusal, and `actingFor` recording.
- **R5 (Coherence Interface):** `engine-runner.mjs`, `folder-builder.mjs`, `python/coherence_overlay_check.py`, UTF-8 / `America/New_York` env, trailing-space path preservation, `ALL BOB` case-insensitivity check, and `coherence` / `builtin` / `generated` Emit modes.
- **R6 & R7 (Data Shapes & Relationships):** All 22 shapes modeled in `migrations/001_schema.sql` with composite keys, partial unique indexes, and trigger-enforced foreign invariants.
- **R8 (State Machines):** Declared once as data in `src/state-machine/coherence-machines.mjs` using reusable `src/state-machine/declarative-machine.mjs`, verified against PostgreSQL 17 catalogs and live runs across all 11 derived stages and 7 step attempt states, generating `STATE_MACHINE.md`.
- **R9–R11 (DB Invariants, Failures/Races & Lessons Learned):** Every named R9/R10/R11 invariant (`RP-1`, `RP-2`, `CR-1`, `CR-6`, `CR-7`, `CR-8`, `CR-9`, `CR-10`, `W-4`, `W-9`, `S-8`, `DS-1`, `DS-2`, 11/20 EYES, 11/21 renames, all 7 audit traps) is enforced and tested across Layers 1–5.
- **R12 & R13 (Importer & Comparator):** Manifest-first read-only import, byte-for-byte rebuild proof, idempotency, replay with recorded `born` write-back, input-first comparison, trial allowed diffs, and Clearpath-vs-Mac entity mapping.
- **R14 (Security & Configuration):** Two separated stores, server-only `viewer.html` config parsing, PHI/SQL-parameter redaction, URL `recordId` refusal, least-privilege roles, `pg_hba.conf` check, and `config/cloudsql-instance.json` Cloud SQL policy check.
- **R15–R17 (Downstream Readers, Screens & Non-Functional):** Database-backed `coherence.mjs` and `clearpath-feed.mjs` readers, full HTTP router/handlers for all R16 screens, batched 2,000-row `unnest` writes, async worker processing, gzip negotiation, and on-demand working-table rebuild hook (`rebuildWorkingOnDemand`).

---

## Design Choices Kept and Verified

1. **Explicit UUID primary keys for business entities (and explicit `BIGINT` `seq` for `journal_entries`):** Ensures exact NDJSON export rebuild (`R10.12`) with identical IDs, foreign keys, and hashes.
2. **Composite primary key `(store_kind, sha256)` on `coherence.stored_files`:** Allows identical empty/shared files to exist independently in `nusear_code` and `company_data` while locking every foreign key structurally to its store kind.
3. **2-argument session advisory lock plus `(pg_backend_pid(), own_backend_start())`:** Prevents PID reuse and guarantees only the attempt's starting connection can record `finished`/`failed`/`cancelled`, while letting a new worker reconcile dead attempts as `interrupted`.
4. **Canonical JSON (`coherence.canonical_json` + `src/util/crypto.mjs`) and UTC microsecond timestamps:** Matches identically between PostgreSQL 17 and Node (preserving all 6 microsecond digits end to end).
5. **Database-checked per-entry commitments (`body.commitments`):** Deferred constraint trigger on `journal_entries` verifies all 19 business table counts and canonical hashes at `COMMIT`, while `created_xid = pg_current_xact_id()` blocks post-commit row attachment.
6. **Record ids kept out of URLs:** `POST /api/coherence/:company/approvals/history` takes `{ recordId }` in the JSON body; `GET` is refused (`405`), and any URL carrying `recordId` or member patterns is rejected (`400`) before routing.
7. **Standard `pg` package (`8.13.1`):** Replaced the Round 1 custom wire fallback (`wire-pg.mjs` removed).

---

## Remaining Open Items (Operational / Outside This Folder)

1. **R12.1 Google Cloud Storage bucket/list import:** Remains an explicit extension point in `src/importer/history-importer.mjs` (requires GCP service account credentials and live bucket access).
2. **R18 live Mac `2026-11-21` import/rebuild & `2026-10-21` / `2026-11-02` / `2026-11-21` full replays:** Ready to run under Kairon's control with `COHERENCE_MAC_PROOF=1` (and sealed historical engine versions in `nusear_code`); not executed here per the Round 2 rule prohibiting opening live member data files.
3. **R19 open owner decisions (Kairon):** Post-development HIPAA (6-year) vs CMS (10-year) retention lock, fixed egress IP allow-list for Cloud SQL, stopping legacy copies of `viewer.html` to company buckets and deleting existing copies, confirming the takeover rule, and Cloudflare BAA / tunnel policy.
