import type { APIRoute } from 'astro';
import { db } from '../../lib/data';

/**
 * Every known-exploited CVE with its lag from publication to KEV listing.
 *
 * Read by /kev, whose year, category and vendor filters re-aggregate in the
 * browser rather than round-tripping. About eighty rows of ten short fields, so
 * the whole set costs less than one request would.
 *
 * Flat and unaggregated on purpose — the same rows answer per-vendor,
 * per-product and per-discovery questions with different counting rules, and
 * the year and category filters cut across all three. Any pre-aggregation here
 * would pick one of those shapes for everybody. See lib/kev-timing.ts for what
 * the rules are.
 *
 * Also the published record behind the charts, alongside /rss.xml and
 * /data/stats.json, so a reader can check the arithmetic.
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
