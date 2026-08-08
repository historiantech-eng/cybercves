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
    /** Skip the regression guard below. Say why in the commit or the PR. */
    force: { type: 'boolean', default: false },
    /** Tolerated shrink in CVE count, as a fraction. */
    'max-shrink': { type: 'string', default: '0.002' },
    /** Tolerated staleness of the local snapshot, in hours. */
    'max-lag-hours': { type: 'string', default: '36' },
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

/**
 * Read the live CVE count and high-water mark straight from D1.
 *
 * Throws if the question cannot be answered. That is deliberate, and it is a
 * correction: this used to swallow the error and return null, which the caller
 * treated as "no baseline, carry on". A transient wrangler failure therefore
 * disabled the guard silently, and the log line it produced read like a benign
 * first-push message rather than "the safety check is off". It happened on the
 * first real push after the guard shipped.
 *
 * An *empty* D1 is not this case — that query succeeds and returns 0, which the
 * caller handles separately. So a genuine first push is never confused with a
 * check that could not run.
 */
async function remoteBaseline(): Promise<{ count: number; newest: string | null }> {
  // Retried: the observed failure was transient, and one flaky subprocess call
  // should not be enough to either halt a deploy or wave one through.
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, 2_000 * attempt));
    try {
    const out = execFileSync(
      'npx',
      [
        'wrangler',
        'd1',
        'execute',
        values.database,
        '--remote',
        '--yes',
        '--json',
        '--command',
        'SELECT COUNT(*) AS n, MAX(date_published) AS newest FROM cve',
      ],
        { cwd: new URL('../../../worker/', import.meta.url).pathname, encoding: 'utf8' },
      );
      // wrangler prefixes human-readable noise before the JSON on some versions.
      const json = out.slice(out.indexOf('['));
      const parsed = JSON.parse(json) as Array<{ results?: Array<{ n?: number; newest?: string }> }>;
      const row = parsed[0]?.results?.[0];
      if (!row || typeof row.n !== 'number') throw new Error('unexpected wrangler output shape');
      return { count: row.n, newest: row.newest ?? null };
    } catch (err) {
      lastError = err;
      console.warn(
        `  baseline query attempt ${attempt + 1}/3 failed: ` +
          `${(err as Error).message.split('\n')[0]}`,
      );
    }
  }
  throw lastError instanceof Error ? lastError : new Error('could not read the D1 baseline');
}

/**
 * Refuse to overwrite production with a worse snapshot.
 *
 * This script truncates every table before reinserting, so the local database
 * wholly replaces D1 — and a stale or half-built local copy silently deletes
 * whatever production learned in the meantime. That is not hypothetical: a push
 * from a three-day-old snapshot took D1 from 1,351 CVEs to 1,342, and nothing
 * complained, because 1,342 rows is a perfectly healthy-looking number.
 *
 * Two checks, because either alone misses real cases:
 *
 *   - **Count.** Catches a failed backfill or an empty database outright. On its
 *     own it is too blunt: the incident above was a 0.7% shrink, well inside any
 *     tolerance loose enough to permit ordinary CVE withdrawals.
 *   - **Freshness.** Compares high-water marks. This is the check that would
 *     have caught it — local topped out three days behind production. The
 *     tolerance is generous because the CVE List clone legitimately lags D1's
 *     15-minute delta cron by a few hours.
 */
async function assertNotARegression(): Promise<void> {
  if (!values.remote || values.force || values['dry-run']) return;

  let remote: { count: number; newest: string | null };
  try {
    remote = await remoteBaseline();
  } catch (err) {
    // Refuse rather than proceed unchecked. The wipe that follows is about to
    // succeed against the very database we just failed to read, so "we could not
    // verify this is safe" is not a reason to overwrite production — it is the
    // reason not to.
    throw new Error(
      `refusing to push — could not read the current state of D1, so this push ` +
        `cannot be checked for regressions:\n  ${(err as Error).message.split('\n')[0]}\n\n` +
        `An empty database is not this error; that reads back as zero and is allowed.\n` +
        `Override with --force if you are certain the local snapshot is good.`,
    );
  }

  if (remote.count === 0) {
    // A real first push. The query worked and production is genuinely empty.
    console.log('D1 is empty — nothing to regress against, proceeding');
    return;
  }

  const local = await driver.first<{ n: number; newest: string | null }>(
    'SELECT COUNT(*) AS n, MAX(date_published) AS newest FROM cve',
  );
  const localCount = local?.n ?? 0;
  const shrink = (remote.count - localCount) / remote.count;
  const maxShrink = Number.parseFloat(values['max-shrink']);

  const problems: string[] = [];
  if (shrink > maxShrink) {
    problems.push(
      `local holds ${localCount.toLocaleString()} CVEs, D1 holds ${remote.count.toLocaleString()} ` +
        `— a ${(shrink * 100).toFixed(1)}% loss, over the ${(maxShrink * 100).toFixed(1)}% tolerance`,
    );
  }

  if (remote.newest && local?.newest) {
    const lagHours = (Date.parse(remote.newest) - Date.parse(local.newest)) / 3_600_000;
    const maxLag = Number.parseFloat(values['max-lag-hours']);
    if (lagHours > maxLag) {
      problems.push(
        `local's newest CVE is ${lagHours.toFixed(1)}h behind D1's ` +
          `(${local.newest} vs ${remote.newest}) — over the ${maxLag}h tolerance`,
      );
    }
  }

  if (problems.length) {
    throw new Error(
      `refusing to push — this would overwrite production with a worse snapshot:\n` +
        problems.map((p) => `  · ${p}`).join('\n') +
        `\n\nBring the local database up to date first:\n` +
        `  npm run backfill -- --clone <absolute path to cvelistV5> --from 2024 --db "$PWD/cybercves.sqlite"\n` +
        `\nThe delta feed carries only very recent changes, so \`npm run sync\` cannot\n` +
        `recover a snapshot that is days behind. Override with --force only when the\n` +
        `shrink is intentional.`,
    );
  }
}

try {
  await assertNotARegression();

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
