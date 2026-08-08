#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { NodeSqliteDriver } from '@cybercves/db/drivers/node';

/**
 * Push the local SQLite snapshot into Cloudflare D1.
 *
 * The Node pipeline owns the canonical database; D1 is the runtime copy the
 * Worker reads. This emits plain INSERT statements and hands them to
 * `wrangler d1 execute`, so nothing here depends on a D1-specific dump format —
 * the same script would target Postgres with a different client.
 *
 *   npm run push:d1 -- --db ./cybercves.sqlite --remote
 */

const { values } = parseArgs({
  options: {
    db: { type: 'string', default: './cybercves.sqlite' },
    remote: { type: 'boolean', default: false },
    'dry-run': { type: 'boolean', default: false },
    database: { type: 'string', default: 'cybercve' },
    /** Rows per statement file. D1 caps how much one execute call accepts. */
    chunk: { type: 'string', default: '400' },
  },
});

const CHUNK = Number.parseInt(values.chunk, 10);

/**
 * Conservative byte budgets for a single `wrangler d1 execute --file` call.
 * D1 rejects oversized input with SQLITE_TOOBIG; empirically ~1 MB files pass and
 * individual statements must stay well under that, so both sit at half.
 */
const MAX_BATCH_BYTES = 500_000;
const MAX_STATEMENT_BYTES = 500_000;

/**
 * Order matters: parents before children, because the schema declares real
 * foreign keys. Taxonomy first, then CVEs, then everything that references them.
 */
const TABLES = [
  'category',
  'vendor',
  'product',
  'cve',
  'cve_affected',
  'cve_product',
  'kev',
  'epss',
  'advisory',
  'advisory_cve',
  'insight',
  'unmapped_product',
  'sync_state',
] as const;

const driver = new NodeSqliteDriver(values.db);

function quote(value: unknown): string {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'NULL';
  if (typeof value === 'bigint') return String(value);
  return `'${String(value).replace(/'/g, "''")}'`;
}

function runWrangler(sqlFile: string) {
  const args = [
    'wrangler',
    'd1',
    'execute',
    values.database,
    values.remote ? '--remote' : '--local',
    '--yes',
    '--file',
    sqlFile,
  ];
  execFileSync('npx', args, {
    cwd: new URL('../../../worker/', import.meta.url).pathname,
    stdio: 'inherit',
  });
}

try {
  const workdir = mkdtempSync(join(tmpdir(), 'cybercve-d1-'));
  let fileIndex = 0;
  let totalRows = 0;

  // Wipe in reverse dependency order so child rows go before their parents.
  const wipe = [...TABLES].reverse().map((t) => `DELETE FROM ${t};`).join('\n');
  const wipeFile = join(workdir, '000-wipe.sql');
  writeFileSync(wipeFile, wipe);
  console.log('wiping remote tables…');
  if (!values['dry-run']) runWrangler(wipeFile);

  for (const table of TABLES) {
    const rows = await driver.all<Record<string, unknown>>(`SELECT * FROM ${table}`);
    if (!rows.length) {
      console.log(`${table}: empty, skipped`);
      continue;
    }

    const columns = Object.keys(rows[0] as Record<string, unknown>);

    // Chunk by serialized bytes, not row count. Row width varies by three orders
    // of magnitude — a CVE with 2,400 CPEs is ~120 KB while a category row is
    // ~200 bytes — so a fixed row count either wastes round-trips on narrow
    // tables or overruns D1's statement limit on wide ones (SQLITE_TOOBIG).
    let batch: string[] = [];
    let batchBytes = 0;

    const flush = () => {
      if (!batch.length) return;
      const file = join(workdir, `${String(++fileIndex).padStart(3, '0')}-${table}.sql`);
      writeFileSync(file, batch.join('\n'));
      if (!values['dry-run']) runWrangler(file);
      batch = [];
      batchBytes = 0;
    };

    for (const row of rows) {
      const statement = `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${columns
        .map((col) => quote(row[col]))
        .join(', ')});`;

      if (statement.length > MAX_STATEMENT_BYTES) {
        // Nothing we can do at this layer — a single row exceeds what D1 accepts.
        // Fail loudly with the offending row rather than truncating data silently.
        throw new Error(
          `${table}: one row serializes to ${statement.length.toLocaleString()} bytes, ` +
            `over the ${MAX_STATEMENT_BYTES.toLocaleString()} limit. ` +
            `Cap the oversized column during normalization. Row starts: ${statement.slice(0, 160)}`,
        );
      }

      if (batch.length >= CHUNK || batchBytes + statement.length > MAX_BATCH_BYTES) flush();
      batch.push(statement);
      batchBytes += statement.length + 1;
    }
    flush();
    totalRows += rows.length;
    console.log(`${table}: ${rows.length.toLocaleString()} row(s)`);
  }

  console.log(
    `\n${values['dry-run'] ? 'DRY RUN — ' : ''}pushed ${totalRows.toLocaleString()} rows ` +
      `to ${values.remote ? 'remote' : 'local'} D1 (${values.database})`,
  );
  console.log(`SQL written to ${workdir}`);
} finally {
  await driver.close();
}
