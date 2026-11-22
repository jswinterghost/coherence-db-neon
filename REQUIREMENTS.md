# Coherence as a database web app: the requirements (11/22)

What must be built, stated completely and without implementation. Written 11/22 from Coherence's code and documents, Nusear's
code and STATE_MACHINES.md, the design (`2026-11-21-coherence-database-design.md`, version 3 with sections 19 and 20) and Neon XHigh's
three audits of it, and Kairon's decisions of 11/21 and 11/22. "Must" is a requirement; "should" a strong default; anything not
required is left to the implementer. Nothing here prescribes a table layout, a language or a library beyond the platform named in R3.

## R1. Purpose and the non-negotiables (Kairon's)

1. Move Coherence from a command-line program run over a frozen folder, with approvals files carried by hand, to a web app whose
   database is itself part of the integrity of the data. "The fundamental function needs to be identical."
2. Nothing is ever overwritten or deleted. Every change is a new record that removes, replaces, reverses or extends an earlier one
   and names it, so the complete history is kept and any moment can be rebuilt. "We need 100% data integrity."
3. The database itself handles every failure and race condition; integrity must not depend on the application behaving.
4. The Mac's own Coherence (its folder, code, input and runs) is left alone: isolated, working as it does, a backup and the reference
   ("the Bible") that every result is compared with. Nusear's current company runs also remain for a while as a backup and a Bible.
5. Phalanx first. Its database must migrate from the Mac and match it one to one. Phalanx's and Clearpath's environments are still
   development environments. Clearpath's database holds only Clearpath's own runs.
6. **Customers never have access to Nusear's code,** under any circumstances, whatever the contracts say: assume they would try to
   take it. **Customers own their input and output data.** Code and code-bearing files live only in Nusear's environment.
7. Separate databases per company. Kairon is the only user at first.

## R2. Scope

- **In:** the company databases and data stores; Nusear's code store; the engine worker; the web app's Coherence screens and their
  server endpoints; the import of all history; the proofs against the Mac; the database reader for Nusear's downstream tools.
- **Out (for now):** any change to Coherence's code (its fixes belong to an authorized Coherence release); sending anything to anyone;
  moving the worker off the Mac; the Coherence .1 entity statements (they come later, on top of this).

## R3. Platform

1. Each company's database is PostgreSQL 17 (Cloud SQL in the company's own Google project when it goes to Google; a local
   PostgreSQL 17 on the Mac for development, which today listens on port 5433 because Postgres.app's PostgreSQL 18 holds 5432).
2. The web app is Nusear's existing server (Node). The engine is Coherence's own Python code, run by the worker exactly as its
   command line runs it.
3. Large files live in object storage (Google Cloud Storage buckets) addressed by SHA-256; the database holds their fingerprints and
   facts.

## R4. Actors and permissions

1. **Nusear's owner (Kairon):** everything, including every typed decision.
2. **Nusear's people:** only for the companies they are assigned (`users.customers`), never anyone held back from running Coherence
   (`users.withheld`). Not used at first.
3. **A company's administrators:** may read runs, inputs and outputs of their own company, as granted. Not used at first.
4. **Recipients** (entity manager, agency manager, selling agent, investor, retention agent): only the bundle data in their own scope,
   only through Nusear's screens; never the journal, the inputs, the approvals or anyone else's data.
5. **"View as" never writes.** Every command refuses while a person is viewing as someone else (Nusear's standing law,
   STATE_MACHINES.md section 1, item 8). Nusear support acting for a company is a different thing: it writes, and every such entry
   records that it was done on the company's behalf.
6. **The worker** is a service identity of its own, the only actor that runs Coherence's code, checks review files and stores files.

## R5. The engine: Coherence's interface (unchanged, a black box with known facts)

1. **The five steps,** each its own command keyed by the statement date (ISO): `coherence.phase1.assign`, `phase2.attribute`,
   `phase3.bible`, `phase3.adjust`, `phase4.emit`, run with the engine's own Python environment from the engine's own folder.
2. **The folder it needs:** the code at its commit, with `input/` beside it (the whole input to freeze) and `runs/`. Assign deletes
   `runs/<date>/` and copies `input/` into `runs/<date>/input/`; every later step reads only inside `runs/<date>/`.
3. **What a run folder holds:** `input/` (the frozen copy), `working/` (eight tables: tx, cbob, sf, tx_tx, tx_cbob, tx_sf, cbob_sf, pbob;
   attribute rewrites them in place), `bible.csv` and `bible.html` (after Bible), `overlay.csv` (the reviewer's saved approvals,
   replaced by each save), `adjust.csv` and `adjust.html` (after Adjust), `emits/` (statements_YYYYMMDD.csv, adjustments.csv, overlay.csv,
   bundles/ with each recipient's data and viewer), and `run.json` (the date, the birth time, each step's time, code and census).
4. **The two review pauses are human.** After Bible and after Adjust a person reviews and saves; Adjust never runs before the Bible
   review is saved; Emit never runs before the Adjust review is saved and its typed confirmation given ("create statements for
   <date>"). An earlier approval is never evidence that a person looked at this run.
5. **The approvals file** (`overlay.csv`) is append-only by Coherence's own law: a saved file must begin with every prior row, in order;
   a Bible save must begin with the run's frozen prior (`input/Overlay/overlay.csv`); an Adjust save must also begin with this run's
   Bible review. Its header is exactly one of two contracts: the current (`record_id, disposition, agent, agency, policy, book, month,
   status, note, committed_at, approved_amount, approved_agency, approved_agent, approved_agency_from, approved_agent_from`) or the older
   one without the five `approved_` columns. Two answers derive from it: the current answer per key (the last row) and the Bible's
   applied answers (the last `CORRECT` row per Bible key, the keys being the run's `bible.csv` record ids).
6. **Determinism facts the system must honour:**
   - Each step records `git rev-parse --short HEAD`, with "+" when `git status` shows anything, and stamps it as the build id in the
     review pages and viewers: the engine folder must be a clean checkout at the recorded commit (`input/`, `runs/`, `scratch/`,
     `web/node_modules/`, `web/dist/` are ignored by Coherence's own `.gitignore`).
   - A policy with no number gets a Bible key hashed from `run.json`'s birth time, so a fresh assign gives those policies new keys.
   - The review pages and viewers are built by Vite through pnpm from `web/` during Bible, Adjust and Emit, from its lock file.
   - The clock is read only for `run.json`'s birth and step times.
   - `intake.py` names the folder `ALL BOB` while it is `All BOB`: it works only on a case-insensitive disk (the Mac's).
   - Several files are read and written without a named encoding: the locale must be UTF-8 (`LANG`, `LC_ALL`, `PYTHONUTF8=1`), and the
     time zone America/New_York.
   - A real folder name ends in a space (`All BOB/Molina `): no path may ever be trimmed or normalized silently.
7. **Emit modes:** the Mac runs Coherence's own Emit. Company runs from 11/12 run Nusear's wrapper (`scripts/coherence/company_emit.py`,
   then `pages_law.py`): Phalanx with `--builtin`, Clearpath with `--display Clearpath --keep RETENTION_AGENT,INVESTOR --no-manager
   InsureItAll` (which writes `company_manifest.json`). Clearpath's 11/03, 11/04 and 11/11 ran Coherence's plain Emit. A run's Emit mode
   is part of the run.
8. **Nusear's review check:** `lib/coherence-overlay-check.py`, run from the run's sealed code, applies Coherence's own reader; it must be
   extended (it is Nusear's) to report the header kind and the file's new rows, so nothing else ever parses an approvals file.

## R6. The data shapes

Each shape below is one kind of record. Every record is immutable once written. "Names" means "refers to, and the referent exists".

1. **Company:** the database itself; one per company (Phalanx, Clearpath).
2. **Stored file:** bytes identified by SHA-256, with size, MD5 and CRC32C as the store reports them, and which store holds it:
   **Nusear's code store** or **the company's data store.** A file is stored once; storing it again changes nothing; nothing can
   replace it. Its object name is derived from the fingerprint alone.
3. **Input version:** a complete list of the input folder's files (relative path and stored file), with its line (**standing**: the
   company's own input over time, one line of descent; or **snapshot**: a historical run's frozen input), its parent (standing only,
   older, at most one child), its source (upload, include, remove, rename, Mac import, company import, Google list import, recorded
   sent, carried approvals), its reason, and the count of its entries and changes.
4. **Input entry:** one path in one version and the stored file it holds. Within a version no two paths may be equal ignoring case
   and Unicode normalization, and no path may be both a file and a folder (also ignoring case and normalization).
5. **Input change:** one difference from the parent: added, removed, renamed (with the old path), or replaced (with the previous
   file). At most one change per path and one rename per old path; a rename moves the same bytes; a replacement changes them.
6. **Engine version:** a label (for example v2.2.5), Coherence's commit, and fingerprints of: the commit's git bundle, every code file,
   the Python lock file and offline wheels, the web lock file and offline package store, Nusear's wrapper bundle (company_emit.py,
   pages_law.py, coherence-overlay-check.py and Nusear's commit), and the toolchain (operating system and version, architecture,
   Python, uv, Node, pnpm, time zone, locale settings), plus a container digest for any future Linux worker. **Its bytes live only in
   Nusear's code store;** a company's database holds only the fingerprints and label.
7. **Run:** a statement date, a folder number (1 for `runs/<date>`, 2 for `runs/<date>.2` after an abandoned run of that date), its
   origin (**app**: a real run; **trial**: a parallel run during the takeover period; **replay**: a re-run of an imported run for proof;
   **Mac import**; **company import**), its input version, its engine version (required for app, trial and replay), its Emit settings
   (mode: coherence, builtin or generated with display, keep and no-manager lists), what it replays (replay only), a re-run reason
   where it re-runs a date, and the source folder (imports only).
8. **Step request:** a request for one step of one run, with its reason (launch, continue, Bible saved, Emit confirmed, retry) and,
   for an Emit request, the Emit confirmation it carries out (also on an Emit retry).
9. **Cancel request:** a person's typed request to stop one running attempt.
10. **Step attempt event:** one event of one numbered attempt of one step of one run: started (answering one request), finished
    (with the attempt's census, including assign's birth time, and the complete list of the folder's files), failed (with its log),
    interrupted, cancelled, or superseded (after an end, when a later re-run replaces it).
11. **Artifact:** one file of `runs/<date>/` after a finished attempt: its path and stored file. Every artifact is classified **data**
    (CSV tables, statements, approvals, ledgers, books, logs, `run.json`) or **code-bearing** (the review pages and viewers, which hold the
    compiled apps), and code-bearing files are stored only in Nusear's code store.
12. **Approvals file:** one distinct `overlay.csv` by content: its header kind, its row count, the approvals file it extends (whose
    every row it begins with, in order) and how many rows it shares with it (all of them). Every approvals file ever seen (frozen
    priors, saves, emitted logs) is registered once.
13. **Approval row:** one row of the whole approvals log, numbered within the whole log (a file's own rows are numbered from its shared
    count plus one), with every column of the header (R5.5), exactly as Coherence's reader parsed it.
14. **Review save:** one saved Bible or Adjust review: the run, the surface, the finished attempt reviewed, the approvals file saved,
    whether it was imported, and (imported) its original time.
15. **Review submission (operational):** a posted review waiting for the worker: the run, surface, the staged bytes' fingerprint, the
    journal position the person saw, the person, whom they acted for, the request key and fingerprint, and finally its result.
16. **Review draft (operational):** a review in progress, one per run, surface and attempt; deleted on save and on abandon; expiring
    after 30 days; never read by any calculation.
17. **Emit confirmation:** the typed phrase, naming this run's newest Adjust save.
18. **Carry:** a person's typed decision to record the run's emitted statement as sent, or to carry the run's emitted approvals forward,
    naming the run, its statement date, the stored file (which must be that run's own finished Emit's) and the standing input version
    it publishes (or "nothing new" when the approvals are unchanged).
19. **Abandonment:** a person's typed decision to give up a run, with its reason.
20. **Imported file:** a historical file that belongs to no run (the Incident Report, the Vault's Staging and Documents, an archive
    inventory), with its area and path.
21. **Check:** one verification (chain, commitments, objects, import, replay, shadow, trial comparison), passed or not, with its report.
22. **Journal entry:** one change of any kind above: a gapless number, the time, the actor, whom they acted for, the command key and the
    fingerprint of the request, a body that holds the change's small rows or the fingerprints of its large lists, the previous entry's
    hash and its own hash over a fixed, language-independent text form of all of these.

## R7. Relationships and hierarchies

1. Company → standing input line (one chain of versions, each with at most one successor) → entries and changes.
2. Company → runs; a run → one input version (standing for app and trial runs; a snapshot for imports and their replays) → the prior
   approvals file inside it (`Overlay/overlay.csv`).
3. Run → steps (assign, attribute, bible, adjust, emit, in that order) → numbered attempts → events and, for a finished attempt, its
   artifacts. Assign to bible run as one sequence; Bible and Adjust are each followed by a person.
4. Step request → the attempt that answers it (at most one); Emit request → its confirmation → the Adjust save it names → the finished
   Adjust attempt that save reviewed.
5. Approvals files → a chain by "extends" (no cycles, no self-reference) → the rows each adds; a review save → one approvals file → one
   finished Bible or Adjust attempt.
6. Carry → its run (app or company import only) → the run's own emitted file → the next standing input version.
7. Replay and trial → the run they are compared with.
8. Every record → the journal entry that made it. Engine versions and code-bearing files → Nusear's code store only.

## R8. The state machines

**Run stages** (derived, never stored): preparing, running a step, waiting for Bible, waiting for Adjust, ready to create statements,
emitting, done, failed, interrupted, cancelled, abandoned.

**Step attempt lifecycle:** requested → started → one of finished, failed, interrupted, cancelled; a finished or ended attempt may later
be superseded. Exactly one end per attempt. Attempts are numbered in order. At most one open attempt per run.

**Transitions and their guards** (every guard checked against the state the change will follow):

| From | Action | Guard | Result |
|---|---|---|---|
| no open run of the date | launch | no sent statement for that date (a correction belongs to a later date); a finished run with no carries must be abandoned first | run; assign requested |
| requested | worker starts | it holds the company's running slot; predecessor finished; request open and for this run and step | started |
| running | step ends | still holds the slot; no end yet | finished, or failed; assign to bible continue |
| running | worker lost | slot free; no end | interrupted |
| running | cancel (typed) | an open attempt | the engine stopped; cancelled |
| waiting for Bible, or waiting for Adjust with no Adjust save for Adjust's current attempt | Bible review saved | no open request; not abandoned; Coherence's check passes | review save; Adjust's attempt superseded if any; Adjust requested |
| waiting for Adjust, or ready | Adjust review saved | no open request; no Emit confirmed for Adjust's current attempt; begins with this run's Bible review | review save |
| ready | Emit confirmed | the typed phrase; the newest Adjust save named; no review waiting | confirmation; Emit requested |
| failed, interrupted, cancelled | retry | a person asks; later attempts superseded; an Emit retry keeps its confirmation | request |
| done (app or company import) | record as sent | the run's own statement; one per date | carry; next standing version with `Sent/statements_<date>.csv` |
| done (app or company import) | carry approvals | the run's own emitted log; it extends the standing approvals file (or none exists yet) | carry; next standing version, or "nothing new" |
| not running | abandon | no open attempt; no review waiting; nothing carried | abandonment |

Trial and replay runs are never carried. Imports record their steps as finished attempts holding the files each step is known to have
left in the final folder (assign: the input snapshot; attribute: `working/`; bible and adjust: their files; emit: `emits/` and the final
`run.json`).

## R9. Invariants the database itself must enforce

1. No update, delete or truncate of any business record, for any role, under any replication setting.
2. The journal: gapless numbers; each entry links the previous hash; time never earlier than the previous entry; the hash recomputed
   and checked by the database; one entry per insert statement; writes only at the isolation level the chain needs; a given number,
   time or hash (an export rebuild or a test) verified exactly, never replaced.
3. Every journal entry commits to its records (small ones inline, large lists by the fingerprint of a stored canonical list), and no
   record can be added to a committed list later (each list's count is declared and checked).
4. Every guard of R8, including the review re-save rules, one open request per run, Emit's confirmation binding, one sent statement per
   date, the approvals carry extending the standing file, nothing on an abandoned run, and no abandonment with an open attempt or
   carries.
5. Input rules of R6.3 to R6.5; Sent changes only by recording a statement as sent and Overlay only by carrying approvals (or an import),
   derived from the entries themselves, not from the change list alone.
6. The running slot is held by one worker connection at a time.
7. Every stored file's object name is derived from its fingerprint; engine bytes and code-bearing files never reach a company's store.

## R10. Failures and races: required behaviour

1. A worker, Mac or network that dies at any point leaves no run "running": the slot is released with the worker's connection, and the
   open attempt is marked interrupted before anything else runs.
2. A step is finished only when its end is recorded, on the slot's own connection; a step whose slot was lost is never recorded
   finished; nothing runs after the slot is lost (every operation in flight is aborted).
3. A lost connection is noticed within seconds (a liveness check between operations, never inside a transaction, with its own time
   limit); the engine's whole process group is stopped.
4. A hung step ends at a per-step time limit (15 minutes) or a person's cancel.
5. Two people, tabs or devices: every command carries the journal position its screen showed and is refused if the run changed;
   saving a review and confirming Emit exclude each other.
6. Every command carries a key; a resend returns the first result; the same key with any other request (kind, actor, acting for,
   content) is refused.
7. Review saves run in the worker: the web request validates the person and the run and stages the bytes, then answers at once; the
   worker checks the file with Coherence's own code, stores it only after every guard passes, and records the result with the save in one
   transaction, so a rejected or failed save never stalls the company's worker.
8. Files are promoted to a store only after their checks; storing is create-only and verified by MD5 and CRC32C, also when the object
   already exists; an interrupted promotion is resumed or repeated safely.
9. Each attempt builds its own folder from the database (every fingerprint checked), writable, and removes it afterwards whatever
   happens; the frozen input is re-hashed after every step.
10. Large writes are batched; no single command may exceed the web request's time limit (Cloudflare's 100 seconds).
11. The import is idempotent and resumable: running it again adds nothing; an interrupted import leaves nothing half-recorded.
12. A rebuild from the daily journal export reproduces the database exactly and verifies every hash as it goes.

## R11. Lessons learned (each must have a test that proves it cannot recur)

- **RP-1:** a run between two steps looked interrupted to the other server: state must never be inferred from a process id alone.
- **RP-2:** a death after Coherence marked Emit done but before the run finished: only the recorded end counts.
- **CR-1:** an Emit confirmed while another tab saved a review: confirmations and saves exclude each other.
- **CR-6:** a copy finished whose completion was never written: completion is one transaction.
- **CR-7:** the wrapper's version was unrecorded: every executed file belongs to a fingerprinted engine version.
- **CR-8:** a Bible save after the Adjust review: the re-save rules of R8.
- **CR-9:** an earlier Adjust's draft restored for a later Adjust: drafts are keyed by attempt.
- **W-4:** a dead process's row blocked every restart: no state held by a process outlives it.
- **W-9:** a test's cleanup removed its stand-ins while its watcher ran and reached the live services: tests stop what they start before
  removing its tools, and nothing in a test can reach a live service.
- **S-8:** an older run's approvals carried after a newer one would drop approvals: a carry must extend the standing file.
- **DS-1, DS-2:** Sent and Overlay changed only by their carries; no case twins and no file-folder clashes in any input.
- **The 11/20 agent file (EYES on runs):** two runs are "the same" only by what each recorded using, file by file, never by a label.
- **The misdated files (11/21):** a file renamed is the same file: a rename keeps the file's history and is recorded as a rename.
- **Nusear kept every review save since 10/21:** what an import claims is missing must first be searched for.
- **The birth key, `ALL BOB`, the encodings, the trailing space, Clearpath's Emit modes:** R5.6 and R5.7.
- **The audits:** a privilege the app must never have (table locks); a search path that hides functions; a trigger that overwrote what it
  should verify; multi-row inserts that cannot see each other; promotion before checks; a liveness query inside a transaction; a
  sandboxed viewer that cannot load its data: each a test.

## R12. History to back-load (read only; listed in a manifest before reading)

1. **Phalanx's database:** the Mac's 25 run folders (16 dated, the archive's v1, v2 and provisional, and Historical 2026-08-31), the
   Incident Report, the Mac's current input, a git bundle for every commit any `run.json` names (into Nusear's code store), Nusear's
   records of the Mac's runs (`data/coherence-runs/<date>/`: saves and logs; the Runs Portal's records, all events including those before
   a record-cleared, drafts, settings); then Phalanx's company runs (`data/company-environments/phalanx/`, `data/company-workspaces/phalanx/`,
   `data/company-runs/phalanx/`, the company tables, Google's lists, approvals, Sent, Overlay, finished folders, Staging, Documents, the
   archives' inventory).
2. **Clearpath's database:** Clearpath's own company runs and its current state only.
3. **Rules:** files deduplicate by content and every folder keeps its own record; each of Nusear's saves becomes a review save of its
   surface with its time; a run before 10/21 has only its final approvals file (the root `overlay.csv`, else `emits/overlay.csv`); a
   missing birth stays missing; `.DS_Store` files are kept but left out of comparisons; original times stay with each record.
4. **Proof:** every file re-read and matched; every source folder rebuilt from the database, identical path by path and byte by byte;
   every Nusear record counted on both sides; the report kept.

## R13. Proof against the Mac

1. **Storage:** every imported folder rebuilt identical.
2. **Replay:** every run whose steps all ran on committed code (the Mac's 10/21, 11/02, 11/03, 11/20, 11/21; every such company run)
   re-run from the database with its recorded birth written back after assign, its recorded review files at each pause and its own Emit
   mode, with identical whole trees apart from `run.json`'s step `at` and `seconds` (and the replay's own birth in assign's stored
   `run.json` before the write-back). Runs on uncommitted code are kept whole and proved by storage only.
3. **Shadow:** every new Mac run imported and replayed the same way.
4. **Trial:** during the takeover each company's run is also run in the app and compared with Nusear's current run of the same company
   and date, inputs first, then whole trees; allowed: `run.json`'s times and birth, `runBorn` in the review pages, the reviewers' own
   `committed_at`, and `unidentified:` Bible keys. Clearpath against the Mac: every table and statement identical after mapping every
   entity except InsureItAll to Clearpath; bundles against Clearpath's own manifest.
5. **Takeover:** "prob next week" for Phalanx (Kairon); the rule to confirm (proposed: three consecutive matching dates, one writing
   statements).

## R14. Code protection, security and member data

1. Two stores, never mixed (R6.2, R6.6, R6.11); the engine runs only in Nusear's environment (the Mac now, Nusear's own Google project
   later), reaching the company's database and data store through its service identity; never in a customer's project.
2. No viewer or review page is sent to anyone any more; recipients see bundles only through Nusear's screens (the pattern of
   `workspace-ui/src/workspace/CoherenceScreen.tsx`: the configuration read on the server after a scope check, the files fetched by
   signed-in requests). The viewers keep running on the Mac for now.
3. Member data is never written to application, HTTP or database logs or error messages (record ids name members).
4. The connection is a written protocol in layers: identity (a dedicated service account, IAM database sign-in, no passwords), transport
   (Google's Cloud SQL connector, TLS required), network (no direct connections; an address allow-list if Nusear's addresses are fixed),
   least privilege (insert and read), audit (every sign-in and statement logged without values). The local development database admits
   only the Mac's own user on its socket and a password over TCP.
5. Retention: nothing locked during development; afterwards the period HIPAA and CMS require (six years under HIPAA; CMS's Medicare
   Advantage and Part D record rules are ten years), to confirm.
6. Cloudflare signs business associate agreements only with Enterprise customers; whether Nusear's tunnel may carry member data is to
   be settled before any change.

## R15. Downstream readers

Nusear's Book of business, Ledger, Performance, Policy Reconcile, Canon and the sites' feeds (`lib/coherence.mjs`, and
`lib/clearpath-feed.mjs` for the agent feeds) must read a company's newest finished, non-abandoned app or company-import run through the
database and its data store, with results identical to reading today's workspace folders.

## R16. Screens

1. **Inputs:** every version and its changes; Staging; "include in calculations" publishing a version with a reason.
2. **Runs:** launch (date, input version and engine shown by fingerprint); each step's progress and log; the two reviews (Nusear's
   review app, unchanged in behaviour, with a drift check against Coherence's `web/src/adjust`); Emit's typed confirmation; outputs;
   record as sent; carry approvals; cancel; retry; abandon.
3. **History:** any screen "as of" any moment; a run's full journal; one approval key's full history.
4. **Checks:** every proof's report.
5. **Bundles:** each recipient's data within scope, on Nusear's screens.

## R17. Non-functional

1. Sizes: about 450 input files (48 MB); approvals logs of about 25,000 rows and growing; saves of up to 88,000 new rows; run folders of
   300 to 545 MB on the Mac (working tables 250 to 300 MB, bundles about 170 MB).
2. Steps today: assign about 20 s, attribute 40 s, bible 38 s, adjust 41 s, emit 135 s (11/21).
3. Storage: the database keeps what enters and leaves a run, the decisions and the code version; derivable files (the working tables)
   as fingerprints, rebuilt on demand and proved against them (Kairon: the run folder was a file system's answer to having no database).
4. Every request answers within the web's time limit; long work is queued and followed.

## R18. Acceptance (each a test, written before the code it proves)

Every refused change in R9; a forged, gapped, forked or two-row journal insert; an export rebuilt and verified; a resend acting once and
a reused key refused; two commands racing; a review save racing an Emit confirmation; a rejected review submission not stalling the
worker; a worker killed at each point of a step; a dropped connection mid-step; the reconciler; cancel; every carry and abandon refusal;
an out-of-order approvals carry refused; a later row added to a committed approvals file refused; case twins, file-folder clashes and
NFC/NFD twins refused; Sent or Overlay changed outside a carry refused; the Mac's 11/21 imported and rebuilt byte for byte; 11/21, 10/21
and 11/02 replayed identical; no engine or code-bearing file in a company's store.

## R19. Open (Kairon at the computer)

Retention after development; whether Nusear's addresses are fixed; stopping the copy of code-bearing files into the companies' finished
buckets and removing the copies already there; the takeover rule; Cloudflare.
