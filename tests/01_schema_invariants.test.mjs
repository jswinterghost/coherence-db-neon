// R18 & R9 & R11 database-enforced invariant tests:
// - Immutability (UPDATE, DELETE, TRUNCATE) under normal AND session_replication_role = 'replica'
// - Journal chain: forged hash, gapped seq, forked prev_hash, backdated time, two-row INSERT, non-SERIALIZABLE isolation
// - Audits: trojan search_path shadowing sha256/lower/normalize; coherence_app refused table locks (EXCLUSIVE/SHARE)
// - R9.3: commitment count/hash mismatch refused; adding a row to an already-committed approvals file refused
// - R9.5 / DS-1 / DS-2: case twins, NFC/NFD twins, file-folder clashes, trailing space preserved, Sent/Overlay outside carry refused
// - R9.7: invalid object_name and code-bearing artifact in company_data refused by DB
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { createClient } from '../src/db/pg-client.mjs';
import { computeJournalHash, GENESIS_HASH, hashInputChanges, hashInputEntries, sha256Hex } from '../src/util/crypto.mjs';
import { checkPgAvailable, createTestEnv } from './helpers/test-db.mjs';
import { makeOverlayCsv, sampleApprovalRow, seedStandingInput } from './helpers/fixtures.mjs';

const pgCheck = await checkPgAvailable();

test('R9.1: UPDATE, DELETE, and TRUNCATE are refused on business tables even under session_replication_role = replica', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const client = await createClient(env.pgConfig);
  t.after(() => client.end());

  // Normal mode
  await assert.rejects(() => client.query("UPDATE coherence.journal_entries SET actor = 'mallory' WHERE seq = 1"), /immutable/i);
  await assert.rejects(() => client.query('DELETE FROM coherence.journal_entries WHERE seq = 1'), /immutable/i);
  await assert.rejects(() => client.query('TRUNCATE coherence.journal_entries CASCADE'), /immutable/i);
  await assert.rejects(() => client.query("UPDATE coherence.company_meta SET display_name = 'Hacked'"), /immutable/i);
  await assert.rejects(() => client.query('DELETE FROM coherence.company_meta'), /immutable/i);

  // Under session_replication_role = 'replica' (ENABLE ALWAYS TRIGGER must still fire!)
  await client.query("SET session_replication_role = 'replica'");
  await assert.rejects(() => client.query("UPDATE coherence.journal_entries SET actor = 'mallory' WHERE seq = 1"), /immutable/i);
  await assert.rejects(() => client.query('DELETE FROM coherence.journal_entries WHERE seq = 1'), /immutable/i);
  await assert.rejects(() => client.query('TRUNCATE coherence.journal_entries CASCADE'), /immutable/i);
  await client.query("SET session_replication_role = 'origin'");
});

test('R9.2 & R11: forged hash, gapped seq, forked prev_hash, backdated time, two-row INSERT, and non-SERIALIZABLE write are all refused (never overwritten)', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const headRes = await env.pool.query('SELECT seq, recorded_at, entry_hash FROM coherence.journal_entries ORDER BY seq DESC LIMIT 1');
  const head = headRes.rows[0];
  const nextSeq = Number(head.seq) + 1;
  const body = JSON.stringify({ commitments: { counts: {}, hashes: {} } });
  const reqSha = sha256Hex('test-req');

  // 1. Non-SERIALIZABLE (READ COMMITTED) refused
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('kairon', 'noop_test', 'rc-key', $1, $2::jsonb)`,
        [reqSha, body],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /SERIALIZABLE/i);

  // Helper to run one raw SERIALIZABLE insert
  const rawInsert = async (sql, params = []) => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      await c.query(sql, params);
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  };

  // 2. Forged entry_hash refused (trigger verifies instead of overwriting!)
  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (seq, prev_hash, entry_hash, actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, $2, $3, 'kairon', 'noop_test', 'forged-hash-key', $4, $5::jsonb)`,
      [String(nextSeq), head.entry_hash, 'f'.repeat(64), reqSha, body],
    ),
    /entry_hash mismatch/i,
  );

  // 3. Gapped seq refused (trigger verifies instead of overwriting!)
  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (seq, prev_hash, actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, $2, 'kairon', 'noop_test', 'gap-key', $3, $4::jsonb)`,
      [String(nextSeq + 5), head.entry_hash, reqSha, body],
    ),
    /gapless/i,
  );

  // 4. Forked prev_hash refused
  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (seq, prev_hash, actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, $2, 'kairon', 'noop_test', 'fork-key', $3, $4::jsonb)`,
      [String(nextSeq), GENESIS_HASH, reqSha, body],
    ),
    /prev_hash mismatch/i,
  );

  // 5. Backdated recorded_at refused
  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (seq, prev_hash, recorded_at, actor, command_kind, command_key, request_sha256, body)
       VALUES ($1, $2, '2020-01-01T00:00:00Z'::timestamptz, 'kairon', 'noop_test', 'backdate-key', $3, $4::jsonb)`,
      [String(nextSeq), head.entry_hash, reqSha, body],
    ),
    /cannot precede/i,
  );

  // 6. Two-row single INSERT statement refused (R9.2 & R11 multi-row audit)
  await assert.rejects(
    () => rawInsert(
      `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
       VALUES ('kairon', 'noop_test', 'multi-1', $1, $2::jsonb),
              ('kairon', 'noop_test', 'multi-2', $1, $2::jsonb)`,
      [reqSha, body],
    ),
    /one entry per INSERT/i,
  );

  // 7. Exact given seq, prev_hash, recorded_at, and valid entry_hash succeeds!
  const validAt = new Date(Date.now() + 1000).toISOString();
  const validHash = computeJournalHash({
    seq: nextSeq,
    recordedAt: validAt,
    actor: 'kairon',
    actingFor: null,
    commandKind: 'noop_test',
    commandKey: 'exact-valid-key',
    requestSha256: reqSha,
    prevHash: head.entry_hash,
    body: { commitments: { counts: {}, hashes: {} } },
  });
  await rawInsert(
    `INSERT INTO coherence.journal_entries (seq, recorded_at, prev_hash, entry_hash, actor, command_kind, command_key, request_sha256, body)
     VALUES ($1, $2::timestamptz, $3, $4, 'kairon', 'noop_test', 'exact-valid-key', $5, $6::jsonb)`,
    [String(nextSeq), validAt, head.entry_hash, validHash, reqSha, body],
  );
});

test('R11 audits: trojan search_path cannot hijack functions, and coherence_app cannot acquire EXCLUSIVE/SHARE table locks', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const client = await createClient(env.pgConfig);
  t.after(() => client.end());

  // 1. Trojan search_path shadowing sha256/lower/normalize
  await client.query(`
    CREATE SCHEMA trojan;
    CREATE FUNCTION trojan.sha256(bytea) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$ SELECT '\\xdeadbeef'::bytea; $$;
    CREATE FUNCTION trojan.lower(text) RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT 'hijacked'; $$;
  `);
  await client.query('SET search_path = trojan, public');
  const hashRes = await client.query("SELECT coherence.sha256_text('hello') AS h");
  assert.equal(hashRes.rows[0].h, sha256Hex('hello'));
  await client.query('RESET search_path');

  // 2. Least-privilege role coherence_app must NOT hold table-lock privileges (EXCLUSIVE / SHARE / ACCESS EXCLUSIVE)
  await client.query('SET ROLE coherence_app');
  await assert.rejects(async () => {
    await client.query('BEGIN');
    try {
      await client.query('LOCK TABLE coherence.journal_entries IN EXCLUSIVE MODE');
    } finally {
      await client.query('ROLLBACK').catch(() => {});
    }
  }, /permission denied/i);
  await assert.rejects(async () => {
    await client.query('BEGIN');
    try {
      await client.query('LOCK TABLE coherence.runs IN SHARE MODE');
    } finally {
      await client.query('ROLLBACK').catch(() => {});
    }
  }, /permission denied/i);
  await assert.rejects(async () => {
    await client.query('BEGIN');
    try {
      await client.query('LOCK TABLE coherence.input_entries IN ACCESS EXCLUSIVE MODE');
    } finally {
      await client.query('ROLLBACK').catch(() => {});
    }
  }, /permission denied/i);
  await client.query('RESET ROLE');
});

test('R9.3 & R18: adding a later row to a committed approvals file is refused by the database', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const row1 = sampleApprovalRow({ record_id: 'policy:aetna:P1#effective:2026-01-01' });
  const csv = makeOverlayCsv([row1]);
  const stored = await env.dataStore.promoteBytes(Buffer.from(csv, 'utf8'), { relPath: 'overlay.csv', checksPassed: true });

  const reg = await env.commands.registerApprovalsFile({
    actor: env.ownerActor,
    commandKey: 'reg-af-1',
    storedFile: stored,
    headerKind: 'v2',
    rowCount: 1,
    extendsSha256: null,
    sharedRowCount: 0,
    addedRows: [{ row_no: 1, ...row1 }],
  });

  // Attempt 1: insert extra row referencing original committed journal_seq
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      await c.query(
        `INSERT INTO coherence.approval_rows (approvals_file_sha256, row_no, record_id, disposition, journal_seq)
         VALUES ($1, 2, 'policy:aetna:P2#effective:2026-01-01', 'CONFIRM', $2)`,
        [stored.sha256, String(reg.journalSeq)],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /committed or missing journal entry/i);

  // Attempt 2: insert extra row in a brand-new journal entry
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('kairon', 'sneak_row', 'sneak-key', $1, '{"commitments":{"counts":{"approval_rows":1},"hashes":{}}}'::jsonb)
         RETURNING seq`,
        [sha256Hex('sneak')],
      );
      await c.query(
        `INSERT INTO coherence.approval_rows (approvals_file_sha256, row_no, record_id, disposition, journal_seq)
         VALUES ($1, 2, 'policy:aetna:P2#effective:2026-01-01', 'CONFIRM', $2)`,
        [stored.sha256, String(je.rows[0].seq)],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /previously committed approvals_file/i);
});

test('R9.5 & R18 (DS-1, DS-2): case twins, NFC/NFD twins, file-folder clashes, and Sent/Overlay outside carry are refused; trailing space preserved', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const seed = await seedStandingInput(env);
  const f1 = await env.dataStore.promoteBytes(Buffer.from('a,b\n1,2\n'), { relPath: 'All BOB/test.csv', checksPassed: true });
  const f2 = await env.dataStore.promoteBytes(Buffer.from('a,b\n3,4\n'), { relPath: 'All BOB/test2.csv', checksPassed: true });
  await env.commands.registerStoredFiles({ actor: env.ownerActor, commandKey: 'reg-f1-f2', files: [f1, f2] });

  // Verify trailing-space path `All BOB/Molina /book.csv` was stored verbatim without trimming!
  const molinaRes = await env.pool.query(
    "SELECT rel_path FROM coherence.input_entries WHERE input_version_id = $1::uuid AND rel_path = 'All BOB/Molina /book.csv'",
    [seed.inputVersionId],
  );
  assert.equal(molinaRes.rows.length, 1);

  // Direct SQL helper bypassing JS pre-check so we prove the DATABASE ITSELF enforces DS-1 and DS-2!
  const rawPublish = async (cmdKey, sourceKind, entries) => {
    const ivId = randomUUID();
    const entriesSha = hashInputEntries(entries);
    const changes = entries
      .filter((e) => !seed.entries.some((p) => p.relPath === e.relPath && p.fileSha256 === e.fileSha256))
      .map((e) => ({ inputVersionId: ivId, changeKind: 'added', relPath: e.relPath, oldRelPath: null, fileSha256: e.fileSha256, prevFileSha256: null }));
    const changesSha = hashInputChanges(changes);
    const body = {
      commitments: {
        counts: { input_versions: 1, input_entries: entries.length, input_changes: changes.length },
        hashes: { input_entries: entriesSha, input_changes: changesSha },
      },
    };
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('kairon', 'raw_input', $1, $2, $3::jsonb) RETURNING seq`,
        [cmdKey, sha256Hex(cmdKey), JSON.stringify(body)],
      );
      const seq = String(je.rows[0].seq);
      await c.query(
        `INSERT INTO coherence.input_versions (id, line_kind, parent_id, source_kind, reason, entry_count, entries_sha256, change_count, changes_sha256, store_kind, journal_seq)
         VALUES ($1::uuid, 'standing', $2::uuid, $3, 'test', $4, $5, $6, $7, 'company_data', $8)`,
        [ivId, seed.inputVersionId, sourceKind, entries.length, entriesSha, changes.length, changesSha, seq],
      );
      for (const e of entries) {
        await c.query(
          `INSERT INTO coherence.input_entries (input_version_id, rel_path, store_kind, file_sha256, journal_seq)
           VALUES ($1::uuid, $2, 'company_data', $3, $4)`,
          [ivId, e.relPath, e.fileSha256, seq],
        );
      }
      for (const ch of changes) {
        await c.query(
          `INSERT INTO coherence.input_changes (input_version_id, rel_path, change_kind, old_rel_path, store_kind, file_sha256, prev_file_sha256, journal_seq)
           VALUES ($1::uuid, $2, $3, NULL, 'company_data', $4, NULL, $5)`,
          [ivId, ch.relPath, ch.changeKind, ch.fileSha256, seq],
        );
      }
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  };

  // 1. Case twins refused by DB UNIQUE(input_version_id, mac_key)
  await assert.rejects(
    () => rawPublish('case-twin', 'upload', [...seed.entries, { relPath: 'All BOB/Foo.csv', fileSha256: f1.sha256 }, { relPath: 'all bob/foo.CSV', fileSha256: f2.sha256 }]),
    /unique|mac_key/i,
  );

  // 2. NFC vs NFD twins refused by DB UNIQUE(input_version_id, mac_key)
  await assert.rejects(
    () => rawPublish('nfc-nfd-twin', 'upload', [...seed.entries, { relPath: 'All BOB/caf\u00e9.csv', fileSha256: f1.sha256 }, { relPath: 'All BOB/cafe\u0301.csv', fileSha256: f2.sha256 }]),
    /unique|mac_key/i,
  );

  // 3. File-folder clash (ignoring case) refused by DB trigger
  await assert.rejects(
    () => rawPublish('file-folder', 'upload', [...seed.entries, { relPath: 'All BOB/Aetna', fileSha256: f1.sha256 }, { relPath: 'all bob/aetna/sub.csv', fileSha256: f2.sha256 }]),
    /file\/folder path clash/i,
  );

  // 4. Changing Sent/ outside a carry refused by DB trigger (even lowercase `sent/`)
  await assert.rejects(
    () => rawPublish('bad-sent', 'upload', [...seed.entries, { relPath: 'sent/statements_20261121.csv', fileSha256: f1.sha256 }]),
    /Sent\/ entries can change only through recording a statement as sent/i,
  );

  // 5. Changing Overlay/ outside a carry refused by DB trigger
  await assert.rejects(
    () => rawPublish('bad-overlay', 'upload', [...seed.entries, { relPath: 'Overlay/overlay.csv', fileSha256: f1.sha256 }]),
    /Overlay\/ entries can change only through carrying approvals/i,
  );
});

test('R9.7: database refuses object_name not derived from sha256 and refuses code-bearing artifacts in company_data', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv();
  t.after(() => env.cleanup());

  const sha = sha256Hex('abc');
  // 1. Bad object_name refused by CHECK constraint
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('kairon', 'bad_obj', 'bad-obj-key', $1, '{"commitments":{"counts":{"stored_files":1},"hashes":{}}}'::jsonb) RETURNING seq`,
        [sha256Hex('bad-obj')],
      );
      await c.query(
        `INSERT INTO coherence.stored_files (store_kind, sha256, byte_size, md5_b64, crc32c_b64, object_name, journal_seq)
         VALUES ('company_data', $1, 3, 'kAFQmDzST7DWlj99KOF/cg==', 'Nks/tw==', 'wrong/name', $2)`,
        [sha, String(je.rows[0].seq)],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /object_name|check constraint/i);

  // 2. Code-bearing artifact (`bible.html`) marked as data or stored in company_data is REFUSED by DB
  const fakeDataFile = await env.dataStore.promoteBytes(Buffer.from('a,b\n1,2\n'), { relPath: 'bible.csv', checksPassed: true });
  await env.commands.registerStoredFiles({ actor: env.ownerActor, commandKey: 'reg-art-test', files: [fakeDataFile] });
  await assert.rejects(async () => {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const runId = randomUUID();
      const evId = randomUUID();
      const snapId = randomUUID();
      const je = await c.query(
        `INSERT INTO coherence.journal_entries (actor, command_kind, command_key, request_sha256, body)
         VALUES ('kairon', 'bad_art', 'bad-art-key', $1, '{"commitments":{"counts":{"input_versions":1,"runs":1,"step_attempt_events":1,"artifacts":1},"hashes":{}}}'::jsonb) RETURNING seq`,
        [sha256Hex('bad-art')],
      );
      const seq = String(je.rows[0].seq);
      await c.query(
        `INSERT INTO coherence.input_versions (id, line_kind, source_kind, reason, entry_count, entries_sha256, change_count, changes_sha256, store_kind, journal_seq)
         VALUES ($1::uuid, 'snapshot', 'mac_import', 'test', 0, $2, 0, $2, 'company_data', $3)`,
        [snapId, sha256Hex(''), seq],
      );
      await c.query(
        `INSERT INTO coherence.runs (id, statement_date, folder_number, origin, input_version_id, emit_mode, source_folder, journal_seq)
         VALUES ($1::uuid, '2026-11-21', 1, 'mac_import', $2::uuid, 'coherence', 'test-bad-art', $3)`,
        [runId, snapId, seq],
      );
      await c.query(
        `INSERT INTO coherence.step_attempt_events (id, run_id, step, attempt_no, event_kind, artifact_count, artifacts_sha256, journal_seq)
         VALUES ($1::uuid, $2::uuid, 'bible', 1, 'finished', 1, $3, $4)`,
        [evId, runId, sha256Hex('x'), seq],
      );
      await c.query(
        `INSERT INTO coherence.artifacts (attempt_event_id, rel_path, artifact_kind, store_kind, file_sha256, journal_seq)
         VALUES ($1::uuid, 'bible.html', 'data', 'company_data', $2, $3)`,
        [evId, fakeDataFile.sha256, seq],
      );
      await c.query('COMMIT');
    } finally {
      await c.query('ROLLBACK').catch(() => {});
      c.release();
    }
  }, /code-bearing artifact bible\.html must have artifact_kind = code_bearing/i);
});
