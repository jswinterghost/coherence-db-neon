# Coherence Database Core

Database-backed engine orchestration, immutable history ledger, separated code and data storage, historical importer, run comparator, downstream readers, and web API handlers for Coherence commission runs.

## What This Repository Provides

Each company runs in its own PostgreSQL 17 database (PostgreSQL is an open-source relational database management system) inside Nusear's cloud organization, paired with two strictly separated content-addressed object stores (storage buckets where each file is named by its SHA-256 cryptographic fingerprint, a 64-character hex digest computed from the file's exact bytes):

- **Nusear code store (`nusear_code`):** Holds sealed engine Git bundles (single-file repository archives), wrapper scripts, offline dependency manifests, and code-bearing HTML (Hypertext Markup Language) review pages and viewers. Customers never have access to this store.
- **Company data store (`company_data`):** Holds customer inputs, commission statements, approvals logs, working tables, and non-code data outputs. Code-bearing files are rejected at both storage and database boundaries.

Every business table is append-only (no `UPDATE`, `DELETE`, or `TRUNCATE`, even under database replication settings). Every change is recorded in a gapless, SHA-256 hash-chained journal whose commitments are checked by PostgreSQL triggers (database rules that run automatically during writes) before a transaction commits.

## Repository Layout

- `migrations/`: Numbered PostgreSQL 17 SQL (Structured Query Language) migrations (`001_schema.sql` through `008_iam_core.sql`) defining all 31 immutable Coherence business tables, triggers, journal chain verification, decision records, Book of Business, Coherent Ledger, entity statement tables and views, Row-Level Security, least-privilege roles, atomic abandonment of imported abandoned company runs, and the Release 1A database-only IAM core (`platform`, `iam_secret`, and `iam` schemas).
- `config/`: Declarative infrastructure security policy (`cloudsql-instance.json`).
- `python/`: Sealed approvals checker (`coherence_overlay_check.py`) that parses overlays exclusively through Coherence's own Python reader, and legacy pre-Coherence statement bridge (`coherence_legacy_statements.py`) calling Coherence's own legacy reader.
- `src/commands/`: Actor authorization (`authz.mjs`), single write chokepoint (`command-layer.mjs`), canonical commitment hashers (`commitments.mjs`), and NDJSON (newline-delimited JSON, one JSON record per line) journal export, rebuild, point-in-time database comparison, and verification (`journal-export.mjs`).
- `src/compare/`: Parameterized substance and run folder comparator (`run-comparator.mjs`, Gates 1 to 4 with PHI-free reporting) and Layer 2 overlay reconstruction verifier (`overlay-reconstruction.mjs`).
- `src/config/`: Live PostgreSQL catalog, `pg_hba.conf` (PostgreSQL host-based authentication file), and Cloud SQL security policy assertions (`policy-checks.mjs`).
- `src/db/`: Standard `pg` driver adapter (`pg-client.mjs`) and idempotent migration runner (`migrate.mjs`).
- `src/decisions/`: Deterministic `v1`/`v2` overlay CSV generator from immutable database decision records (`overlay-generator.mjs`).
- `src/importer/`: Read-only, manifest-first, config-driven, idempotent history importer (`history-importer.mjs`).
- `src/readers/`: Database-backed downstream readers for the canonical Book of Business, Coherent Ledger, and HMAC-SHA256 signed agent feeds (`downstream-reader.mjs`).
- `src/state-machine/`: Reusable declarative state-machine library (`declarative-machine.mjs`) and Coherence's run and step-attempt machine specifications (`coherence-machines.mjs`).
- `src/storage/`: Code-versus-data classification policy (`artifact-policy.mjs`), create-only object store backends (`object-store.mjs`), and separated store wrapper (`stores.mjs`).
- `src/util/`: Canonical JSON, SHA-256, MD5, and CRC32C checksums (`crypto.mjs`), RFC 4180 CSV and exact POSIX relative-path validation (`csv.mjs`), and protected health information (PHI) redaction (`redact.mjs`).
- `src/web/`: Review-app provenance drift check (`drift-check.mjs`), server-side screen handlers (`handlers.mjs`), and Node HTTP router (`router.mjs`).
- `src/worker/`: Dedicated session advisory-lock slot holder (`slot.mjs`), isolated workspace builder and verifier (`folder-builder.mjs`), process-group step runner (`engine-runner.mjs`), Emit materializer (`emit-materializer.mjs`), dead-attempt reconciler (`reconciler.mjs`), and worker loop (`worker.mjs`).
- `scripts/`: Pre-test JavaScript syntax verifier (`check-syntax.mjs`), `STATE_MACHINE.md` generator and drift checker (`generate-state-machine-doc.mjs`), and read-only history proof runner (`prove-history.mjs`).
- `tests/`: Seven risk-ranked verification layers (`layer1` through `layer7`, including Layer 6 non-vacuous negative proofs and Layer 7 Release 1A IAM core proofs on throwaway `test_*` databases), text hygiene check (`clean-text.test.mjs`), and isolated test helpers (`tests/helpers/`).
- `docs/`: Clean product requirements (`docs/requirements.md`) and implementation mapping (`docs/implementation.md`).
- `STATE_MACHINE.md`: Generated state-machine specification derived directly from `src/state-machine/coherence-machines.mjs`.

The Release 1A database-only IAM core (`migrations/008_iam_core.sql`, live IAM catalog audit in `src/config/policy-checks.mjs`, and `tests/layer7_iam_core.test.mjs`) is self-contained and verified independently. The separate Agent Register v1 backfill import is held pending its owner decision on whether roles without an explicit employment record should be refused rather than inferred.

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
