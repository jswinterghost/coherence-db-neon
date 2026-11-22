// Idempotent PostgreSQL 17 migration runner.
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256Hex } from '../util/crypto.mjs';
import { createPool } from './pg-client.mjs';

const DEFAULT_MIGRATIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'migrations');

export async function runMigrations(pool, { migrationsDir = DEFAULT_MIGRATIONS_DIR } = {}) {
  const files = (await readdir(migrationsDir))
    .filter((name) => /^\d+_.+\.sql$/.test(name))
    .sort();

  const client = await pool.connect();
  try {
    await client.query(`
      CREATE SCHEMA IF NOT EXISTS coherence;
      CREATE TABLE IF NOT EXISTS coherence.schema_migrations (
        version TEXT PRIMARY KEY,
        sha256 TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp()
      );
    `);

    const applied = [];
    for (const file of files) {
      const sql = await readFile(join(migrationsDir, file), 'utf8');
      const hash = sha256Hex(sql);
      const existing = await client.query(
        'SELECT sha256 FROM coherence.schema_migrations WHERE version = $1',
        [file],
      );
      if (existing.rows.length > 0) {
        if (existing.rows[0].sha256 !== hash) {
          throw new Error(`Migration ${file} changed after it was applied; migrations are immutable.`);
        }
        continue;
      }
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query(
          'INSERT INTO coherence.schema_migrations (version, sha256) VALUES ($1, $2)',
          [file, hash],
        );
        await client.query('COMMIT');
        applied.push(file);
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      }
    }
    return { applied, total: files.length };
  } finally {
    client.release();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const pool = await createPool();
  try {
    const res = await runMigrations(pool);
    console.log(JSON.stringify(res));
  } finally {
    await pool.end();
  }
}
