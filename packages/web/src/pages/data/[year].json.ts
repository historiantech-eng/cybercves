import type { APIRoute } from 'astro';
import { db } from '../../lib/data';
import { toCompactRows } from '../../lib/cve-rows';

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

  // Shape shared with the severity chart via lib/cve-rows, so the chart and the
  // table it sits above cannot aggregate subtly different rows.
  const compact = toCompactRows(rows);

  return new Response(JSON.stringify({ year, count: compact.length, rows: compact }), {
    headers: {
      'content-type': 'application/json',
      'cache-control': 'public, max-age=3600',
    },
  });
};
