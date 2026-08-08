import type { APIRoute } from 'astro';
import { db } from '../../lib/data';

/**
 * Every aggregate the site shows, precomputed for every year, in one file.
 *
 * The tables are small — a few vendors, ~15 categories, a handful of fields —
 * so a decade of history is tens of kilobytes. Shipping the whole thing lets the
 * year selector and the year-over-year comparison run instantly in the browser
 * with no server round-trip and no database read per interaction, which is the
 * same reason the CVE index is sharded and shipped.
 *
 * The current year is also rendered server-side on each page so the default view
 * stays indexable; this file only powers switching.
 */

export const GET: APIRoute = async () => {
  const repo = db();
  if (!repo) {
    return new Response(JSON.stringify({ years: [], byYear: {} }), {
      headers: { 'content-type': 'application/json' },
    });
  }

  const years = await repo.listYears();
  const vendors = await repo.listVendors();
  const byYear: Record<string, unknown> = {};

  for (const year of years) {
    const [security, all, categories, discovery] = await Promise.all([
      repo.getVendorRollup(year, true),
      repo.getVendorRollup(year, false),
      repo.getCategoryBreakdown(year),
      repo.getDiscoveryBreakdown(year),
    ]);

    // Per-vendor category and product splits, so a vendor page can switch year
    // without refetching anything.
    const categoriesByVendor: Record<string, unknown> = {};
    const productsByVendor: Record<string, unknown> = {};
    for (const vendor of vendors) {
      categoriesByVendor[vendor.slug] = await repo.getCategoryBreakdown(year, vendor.slug);
      productsByVendor[vendor.slug] = await repo.getProductRollup(vendor.slug, year);
    }

    // The same vendor rollup, recomputed with risk scoped to each product line.
    // Only categories that actually had a CVE that year are emitted — the empty
    // ones would be a rollup of nothing repeated fifteen times per year.
    const vendorsByCategory: Record<string, unknown> = {};
    for (const category of categories) {
      if (category.cve_count === 0) continue;
      vendorsByCategory[category.category_slug] = await repo.getVendorRollup(
        year,
        true,
        category.category_slug,
      );
    }

    byYear[String(year)] = {
      vendors: security,
      vendorsAll: all,
      vendorsByCategory,
      categories,
      categoriesByVendor,
      productsByVendor,
      discovery,
    };
  }

  return new Response(JSON.stringify({ years, byYear }), {
    headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600' },
  });
};
