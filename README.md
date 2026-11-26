# Coherence Database Core

Database-backed engine orchestration, immutable history ledger, separated code and data storage, historical importer, run comparator, downstream readers, and web API handlers for Coherence commission runs.

## What This Repository Provides

Each company runs in its own PostgreSQL 17 database (PostgreSQL is an open-source relational database management system) inside Nusear's cloud organization, paired with two strictly separated content-addressed object stores (storage buckets where each file is named by its SHA-256 cryptographic fingerprint, a 64-character hex digest computed from the file's exact bytes):

- **Nusear code store (`nusear_code`):** Holds sealed engine Git bundles (single-file repository archives), wrapper scripts, offline dependency manifests, and code-bearing HTML (Hypertext Markup Language) review pages and viewers. Customers never have access to this store.
- **Company data store (`company_data`):** Holds customer inputs, commission statements, approvals logs, working tables, and non-code data outputs. Code-bearing files are rejected at both storage and database boundaries.

Every business table is append-only (no `UPDATE`, `DELETE`, or `TRUNCATE`, even under database replication settings). Every change is recorded in a gapless, SHA-256 hash-chained journal whose commitments are checked by PostgreSQL triggers (database rules that run automatically during writes) before a transaction commits.

## Repository Layout

- `migrations/`: Numbered PostgreSQL 17 SQL (Structured Query Language) migrations (`001_schema.sql` through `010_app_views_runtime_reads.sql`, with `006_entity_isolation_views_and_roles.sql` retired) defining all 31 immutable Coherence business tables, triggers, journal chain verification, decision records, Book of Business, Coherent Ledger, entity statement tables, atomic abandonment of imported abandoned company runs, the Release 1A database-only IAM core (`platform`, `iam_secret`, and `iam` schemas with 8 `platform_*` roles, Release 1A `canonical_json` audit journal hashing, 16 append-only `iam.*` tables, and one unified time-consistent organization closure `iam.v_organization_closure` carrying link date-range intersections `eff_range` with `iam.v_organization_closure_live` as today's live tree and tenant-bounded `iam.person_effective_grants` following non-internal holding companies above the tenant strictly through today's live chains), Release 1 Migration 009 Coherence-under-IAM foreign keys, strict refusal backfill and strict PostgreSQL FK resolution inside materialization and batch commands, shared `platform_view_owner` per-data-kind read-rights and published-emit helpers (`app_views._read_*`, executable by `platform_view_owner`, `platform_app`, and `platform_readonly` so `app_views.*` reads work for both readers), IAM `FORCE ROW LEVEL SECURITY` policies (all pre-IAM `coherence_app`, `coherence_worker`, `coherence_readonly`, `coherence_*_ro` roles and `coherence_views.*` retired and revoked), `app_views.*` security-barrier views (including live `v_current_policy_periods` and `v_current_commission_ledger`), and 32 `app_cmd.coherence_*` write commands enforcing required `store_kind` boundaries (`company_data` on data commands, `nusear_code` on engine registration), plus Release 1B Migration 010 completing the runtime `app_views.*` read surface (39 views total including dedicated `app_views.coherence_journal_gate`, with sent status strictly from `coherence.carries`, all-eight-right Entity Manager bundle/output gating, and only `run.json` and `company_manifest.json` exempt by name) and `app_cmd.coherence_authorize_check_run()` gate (33 commands total including `coherence_expire_old_drafts`).
- `config/`: Declarative infrastructure security policy (`cloudsql-instance.json`, naming the 8 `platform_*` IAM roles).
- `python/`: Sealed approvals checker (`coherence_overlay_check.py`) that parses overlays exclusively through Coherence's own Python reader, and legacy pre-Coherence statement bridge (`coherence_legacy_statements.py`) calling Coherence's own legacy reader.
- `src/commands/`: Single database-enforced `app_cmd.coherence_*` write bridge strictly via `withRequestTx` and real signed `dbToken` values (no actor-without-token fallback, no `coherence.*`/`iam.*` queries) (`app-cmd.mjs`), thin `createCommandLayer` alias (`command-layer.mjs`), canonical commitment hashers (`commitments.mjs`), and NDJSON (newline-delimited JSON, one JSON record per line) journal export, rebuild, point-in-time database comparison, and verification (`journal-export.mjs`). Application-side authorization (`authz.mjs`) has been retired.
- `src/compare/`: Parameterized substance and run folder comparator (`run-comparator.mjs`, Gates 1 to 4 with PHI-free reporting reading strictly through `coherence.*` tables/functions readable by `platform_readonly` and `platform_worker`) and Layer 2 overlay reconstruction verifier (`overlay-reconstruction.mjs`).
- `src/config/`: Unified, batched live PostgreSQL catalog audit (`verifyIamConfigInvariants`, with `verifyDatabaseConfigInvariants` delegating to the same single `platform_*` model), `pg_hba.conf` (PostgreSQL host-based authentication file), and Cloud SQL security policy assertions (`policy-checks.mjs`).
- `src/db/`: Standard `pg` driver adapter with canonical `withRequestTx(pool, dbToken, fn)` setting transaction-local `app.session_token` and `BEGIN TRANSACTION READ ONLY` under View-as (`pg-client.mjs`), plus idempotent migration runner (`migrate.mjs`).
- `src/decisions/`: Deterministic `v1`/`v2` overlay CSV generator from immutable database decision records (`overlay-generator.mjs`).
- `src/importer/`: Read-only, manifest-first, config-driven, idempotent history importer (`history-importer.mjs`).
- `src/readers/`: Database-backed downstream readers (`downstream-reader.mjs`) executing strictly through `withRequestTx` and `app_views.*` for published runs, entity bundles (selecting the newest sent run, or a newer unsent run whose entity bundle the caller can open), canonical Book of Business (`v_current_policy_periods`), Coherent Ledger (`v_current_commission_ledger`), entity statements, and HMAC-SHA256 replay-protected feeds with zero JavaScript dollar stripping or role checks.
- `src/state-machine/`: Reusable declarative state-machine library (`declarative-machine.mjs`) and Coherence's run and step-attempt machine specifications (`coherence-machines.mjs`).
- `src/storage/`: Code-versus-data classification policy (`artifact-policy.mjs`), create-only object store backends (`object-store.mjs`), and separated store wrapper (`stores.mjs`).
- `src/util/`: Canonical JSON, SHA-256, MD5, and CRC32C checksums (`crypto.mjs`), RFC 4180 CSV and exact POSIX relative-path validation (`csv.mjs`), and protected health information (PHI) redaction (`redact.mjs`).
- `src/web/`: Review-app provenance drift check (`drift-check.mjs`), server-side screen handlers reading strictly through `app_views.*` (including `app_views.coherence_run_stage`, refusing `?asOf=` via `app_views.coherence_journal_gate` without both `act:coherence.journal.read` and `act:coherence.unpublished.read`, and requiring a distinct `readonlyPool` on `POST /checks/run` with `503 CHECK_READER_NOT_CONFIGURED`, `mapPgError` mapping, and `report` masking through `app_views.coherence_checks` matching `GET /checks`) and writing strictly through `app_cmd.*` via `withRequestTx` with explicit allowlisted body fields and server/URL parameters applied last (`handlers.mjs`), and Node HTTP router passing only signed `dbToken` values (`router.mjs`).
- `src/worker/`: Dedicated session advisory-lock slot holder (`slot.mjs`), isolated workspace builder and verifier (`folder-builder.mjs`), process-group step runner (`engine-runner.mjs`), Emit materializer (`emit-materializer.mjs`), dead-attempt reconciler (`reconciler.mjs`), and worker loop (`worker.mjs`), mandating a signed `workerToken` and executing all worker writes strictly through `app_cmd.*` as `platform_worker`.
- `scripts/`: Pre-test JavaScript syntax verifier (`check-syntax.mjs`), `STATE_MACHINE.md` generator and drift checker (`generate-state-machine-doc.mjs`), and read-only history proof runner (`prove-history.mjs`, seeding a throwaway importing owner and executing through the signed token path).
- `tests/`: Seven risk-ranked verification layers (`layer1` through `layer7`, including Layer 6 non-vacuous negative proofs and Layer 7 Release 1A IAM core + Release 1 Migration 009 Coherence-under-IAM + Release 1B `platform_app` / `platform_worker` end-to-end enforcement + Release E1 member PHI/contact column gates and all-or-nothing workshop vs finished-goods proofs on throwaway `test_*` databases), text hygiene check (`clean-text.test.mjs`), and isolated test helpers (`tests/helpers/`).
- `docs/`: Clean product requirements (`docs/requirements.md`) and implementation mapping (`docs/implementation.md`).
- `STATE_MACHINE.md`: Generated state-machine specification derived directly from `src/state-machine/coherence-machines.mjs`.

Release 1A (`migrations/008_iam_core.sql`), Release 1 Migration 009 (`migrations/009_coherence_under_iam.sql`), Release 1B (`migrations/010_app_views_runtime_reads.sql`, canonical `withRequestTx(pool, dbToken, fn)` wired in `src/web/handlers.mjs`, `src/readers/downstream-reader.mjs`, `src/commands/app-cmd.mjs`, and `src/worker/worker.mjs`, deletion of `src/commands/authz.mjs`, JavaScript dollar stripping, the duplicate raw-SQL command path in `command-layer.mjs`, and the static regex scanner), and Release E1 (in-place in `migrations/009_coherence_under_iam.sql` and `migrations/010_app_views_runtime_reads.sql`) are verified on real PostgreSQL 17. Release E1 separates Coherence reads into two clear areas:

- **The run workshop (all or nothing):** Runs, attempts, step and cancel requests, carries, abandonments, emit confirmations, review saves/configs/drafts/submissions, approval rows, decisions, decision commits, input versions/entries/changes and staging files, engine versions, checks, the journal, run stages, and unsent outputs are opened by one shared check (`app_views._read_workshop_right`), requiring both the matching workshop right (`runs.read`, `inputs.read`, `decisions.read`, `checks.read`, `journal.read`, or `outputs.read` for unsent outputs) and full-tenant `act:coherence.unpublished.read`. `app_views._read_has_run_meta_access()` and `app_views._read_can_see_unsent_run_meta()` count `runs.read` only through `app_views._read_workshop_right('act:coherence.runs.read')`, keeping the four finished-goods rights (`bob`, `statements`, `upline`, `ledger`) unchanged. Whoever passes sees all runs (unfinished included); whoever does not sees none of the workshop. Run stage calculation in `app_views.coherence_runs` delegates through a narrow `platform_readonly` `SECURITY DEFINER` wrapper (`coherence._ro_run_stage`) over `coherence.run_stage` with zero per-run rights or RLS work.
- **Finished goods:** The Book of Business, agency and upline statements, Coherent Ledger, reconciliation, sent outputs, and entity bundles remain scoped to sent runs for finished-goods readers (agency managers, agents, investors, and statements-only roles) through `app_views._read_published_emit_attempts` and `app_views.coherence_published_runs`.
- **Member data gates:** Across both finished goods and the workshop, member PHI (`col:coherence.member_phi`) and member contact details (`col:coherence.member_contact`) gate identifying columns, member-data file handles and checksums, free-text notes/reasons/conflicts/error summaries, `app_views.coherence_journal.body` (requiring full-tenant `member_phi`, and all eight entity-finance and member rights for `carry_sent`), and check `report` JSONB payloads (including run-less `import`, `overlay_reconstruction`, and `objects` reports, as well as `POST /checks/run` masked through `app_views.coherence_checks`), while whole-file Emit outputs, entity bundles, and sent carries require all eight tenant-wide rights via `app_views._read_has_full_entity_finance()`, verified by `tests/layer7_release_e1_member_rights.test.mjs`.
- **Full-tenant scope rule:** The workshop and whole-company outputs require the right over the whole company (every agency in its tree, history included), so an agency whose Coherence switch is `held` or `off` closes them to the company's own people while Nusear's people are unaffected, and a grant above the company through a holding company does not open them once the company has an archived or moved-out agency. In Release E1 each company has its own users and no customer grant reaches across companies (holding-company grants go in Release E2).

The separate Agent Register v1 backfill import remains held pending its owner decision.

## Prerequisites

- Node.js 20 or newer
- Python 3 (for mock engine tests and the overlay checker)
- Local PostgreSQL 17 server configured without `trust`, `md5`, or cleartext `password` authentication rules in `pg_hba.conf`

## Running Tests Against Local PostgreSQL 17

Tests create and drop throwaway databases strictly under the `coherence_test_*` prefix using in-memory object stores and synthetic fixtures. They never connect to cloud services or read member data folders.

1. Set the PostgreSQL connection variables for your local PostgreSQL 17 instance (`PGPORT` defaults to `5432` if omitted):

   ```sh
   PGHOST=/tmp PGPORT=5433 PGUSER="$USER" npm test
   ```

2. `npm test` runs in order:
   - JavaScript syntax check (`node --check` on every `.mjs` file)
   - `STATE_MACHINE.md` parity check against `src/state-machine/coherence-machines.mjs`
   - Layers 1 through 7 against live PostgreSQL 17
   - Repository clean-text hygiene check (`tests/clean-text.test.mjs`)

3. Useful individual commands:

   ```sh
   npm run check
   npm run docs:state-machine
   npm run docs:state-machine:check
   ```

## Read-Only History Proof Runner

To migrate a fresh throwaway local `test_*` database (pinning local PostgreSQL mode, strictly refusing non-local `PGHOST` values including any socket path under `/cloudsql` and non-`test_*` database names, verifying configured manifest folders exist, failing missing comparator targets by name, and cleaning its temporary folder on exit), import a company-agnostic JSON manifest read-only (with zero network calls), run Layers 0, 1, 2, and 4 plus the substance comparator where comparison targets exist, and print a strictly PHI-free summary:

```sh
PGHOST=/tmp PGPORT=5433 PGUSER="$USER" \
node scripts/prove-history.mjs --manifest /path/to/manifest.json --database test_history_proof
```

## Opt-In Live Import Proof

Default test runs never touch live run folders. Operators running a read-only historical import and rebuild proof against an external folder must opt in explicitly via environment variables:

```sh
COHERENCE_LIVE_PROOF=1 \
COHERENCE_REPO=/path/to/coherence \
NUSEAR_DATA_DIR=/path/to/nusear-data \
COHERENCE_PROOF_COMPANY=<company-slug> \
COHERENCE_PYTHON=/path/to/python \
PGHOST=/tmp PGPORT=5433 PGUSER="$USER" \
node --test tests/layer4_import_and_proofs.test.mjs
```
