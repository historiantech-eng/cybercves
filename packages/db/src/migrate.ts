import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { SqlDriver } from './driver.js';
import { splitStatements } from './driver.js';

/**
 * Node-only migration runner. Imports node:fs, so it is exposed on its own entry
 * point and never pulled into the Worker bundle.
 *
 * In production, Cloudflare applies these same .sql files via
 * `wrangler d1 migrations apply` at deploy time — the Worker never migrates at
 * runtime. This runner serves local development, tests, and backfill machines.
 */

const MIGRATIONS_DIR = fileURLToPath(new URL('../migrations/', import.meta.url));

export interface Migration {
  id: string;
  sql: string;
}

export function loadMigrations(dir = MIGRATIONS_DIR): Migration[] {
  return readdirSync(dir)
    .filter((file) => file.endsWith('.sql'))
    .sort()
    .map((file) => ({ id: file, sql: readFileSync(join(dir, file), 'utf8') }));
}

export async function migrate(driver: SqlDriver, migrations = loadMigrations()): Promise<string[]> {
  await driver.run(
    `CREATE TABLE IF NOT EXISTS schema_migration (
       id         TEXT PRIMARY KEY,
       applied_at TEXT NOT NULL
     )`,
  );

  const applied = new Set(
    (await driver.all<{ id: string }>('SELECT id FROM schema_migration')).map((row) => row.id),
  );

  const ran: string[] = [];
  for (const migration of migrations) {
    if (applied.has(migration.id)) continue;
    for (const statement of splitStatements(migration.sql)) {
      await driver.run(statement);
    }
    await driver.run('INSERT INTO schema_migration (id, applied_at) VALUES (?, ?)', [
      migration.id,
      new Date().toISOString(),
    ]);
    ran.push(migration.id);
  }
  return ran;
}
