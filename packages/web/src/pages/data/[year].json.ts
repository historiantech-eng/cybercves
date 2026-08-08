import type { APIRoute } from 'astro';
import { db } from '../../lib/data';

/**
 * Year-sharded CVE index, emitted as a static JSON file at build time.
 *
 * This is what makes client-side filtering instant and free: the browser pulls
 * one shard and cross-filters in memory, with no server round-trip and no
 * database read per interaction. Fields are kept to only what the UI filters
 * and sorts on so a decade of history stays inside the ~1-2 MB gzipped budget.
 */

export async function getStaticPaths() {
  const repo = db();
  if (!repo) return [];
  const years = await repo.listYears();
  return years.map((year) => ({ params: { year: String(year) } }));
}

export const GET: APIRoute = async ({ params }) => {
  const repo = db();
  const year = Number.parseInt(params.year ?? '', 10);

  if (!repo || !Number.isFinite(year)) {
    return new Response('[]', { headers: { 'content-type': 'application/json' } });
  }

  const rows = await repo.listCveIndex(year);

  // Short keys, arrays instead of comma strings: at tens of thousands of rows
  // the key names themselves are a meaningful share of the payload.
  const compact = rows.map((row) => ({
    i: row.cve_id,
    d: row.date_published?.slice(0, 10) ?? null,
    s: row.severity ?? null,
    c: row.score ?? null,
    w: row.discovery ?? null,
    k: row.in_kev,
    e: row.epss ?? null,
    v: (row.vendors ?? '').split(',').filter(Boolean),
    p: (row.products ?? '').split(',').filter(Boolean),
    g: (row.categories ?? '').split(',').filter(Boolean),
  }));

  return new Response(JSON.stringify({ year, count: compact.length, rows: compact }), {
    headers: {
      'content-type': 'application/json',
      'cache-control': 'public, max-age=3600',
    },
  });
};
