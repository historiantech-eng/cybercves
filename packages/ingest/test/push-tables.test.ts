import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { LOCAL_ONLY_TABLES, NEVER_PUSHED_TABLES, PUSHED_TABLES } from '../src/push-tables.js';

/**
 * `push:d1` truncates every table it is given and reinserts from local SQLite.
 * That is safe only for derived data. These tests guard the one mistake that
 * would be both catastrophic and invisible: adding a table with no upstream to
 * the push list, wiping it on the next deploy while the push still reports
 * success and the site still looks fine.
 */
describe('push:d1 table lists', () => {
  it('never pushes a table that cannot be rebuilt from source', () => {
    for (const table of NEVER_PUSHED_TABLES) {
      expect(PUSHED_TABLES).not.toContain(table);
    }
  });

  it('puts every table in exactly one list', () => {
    const all = [...PUSHED_TABLES, ...NEVER_PUSHED_TABLES, ...LOCAL_ONLY_TABLES];
    expect(new Set(all).size).toBe(all.length);
  });

  it('lists parents before children, so foreign keys hold during the wipe', () => {
    // The wipe runs in reverse, so children must be deleted first. If `cve` ever
    // preceded `category`, the reinsert would fail on a foreign key instead.
    const order = (t: string) => PUSHED_TABLES.indexOf(t as (typeof PUSHED_TABLES)[number]);
    expect(order('category')).toBeLessThan(order('product'));
    expect(order('cve')).toBeLessThan(order('cve_affected'));
    expect(order('cve')).toBeLessThan(order('cve_product'));
    expect(order('product')).toBeLessThan(order('cve_product'));
  });

  it('covers every derived table in the schema', () => {
    // Catches the opposite mistake: a new derived table that nobody adds to the
    // push list, so it exists locally and is empty in production forever.
    // Every migration, not a hardcoded list: a table added in a new migration is
    // exactly the case this test exists for, and a fixed list would never see it.
    const dir = fileURLToPath(new URL('../../db/migrations/', import.meta.url));
    const migrations = readdirSync(dir)
      .filter((f) => f.endsWith('.sql'))
      .map((f) => readFileSync(`${dir}${f}`, 'utf8'))
      .join('\n');

    const declared = [...migrations.matchAll(/CREATE TABLE IF NOT EXISTS (\w+)/g)].map((m) => m[1]!);
    const accounted = new Set<string>([
      ...PUSHED_TABLES,
      ...NEVER_PUSHED_TABLES,
      ...LOCAL_ONLY_TABLES,
      'schema_migration',
      'ingest_run', // per-run local log; pushing it would say the Worker ran the backfill
    ]);

    expect(declared.filter((t) => !accounted.has(t))).toEqual([]);
  });
});
