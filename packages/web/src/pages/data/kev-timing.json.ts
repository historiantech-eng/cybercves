import type { APIRoute } from 'astro';
import { db } from '../../lib/data';

/**
 * Every known-exploited CVE with its lag from publication to KEV listing.
 *
 * Published for readers who want the underlying numbers, alongside /rss.xml and
 * /data/stats.json. NOT consumed by any page: /kev and /compare render every
 * panel server-side, including the ones the vendor filter hides, because with
 * three vendors and ~30 products the whole set is a few kilobytes of markup and
 * server-rendering removes the possibility of the browser re-aggregating it into
 * different numbers than the build did.
 *
 * Flat and unaggregated on purpose — the same rows answer per-vendor,
 * per-product and per-discovery questions with different counting rules, so any
 * pre-aggregation here would pick one of them for everybody. See
 * lib/kev-timing.ts for what those rules are.
 */

export const GET: APIRoute = async () => {
  const repo = db();
  const rows = repo ? await repo.getKevTiming() : [];
  const vendors = repo ? await repo.listVendors() : [];

  return new Response(
    JSON.stringify({
      rows,
      // Slug to display name, so the client can label a series without a second
      // fetch. Vendors with no exploited CVE are kept: the filter should be able
      // to show an honest empty panel rather than omit the vendor entirely.
      vendorNames: Object.fromEntries(vendors.map((v) => [v.slug, v.name])),
    }),
    {
      headers: {
        'content-type': 'application/json',
        'cache-control': 'public, max-age=3600',
      },
    },
  );
};
