import type { CveRecord, TaxonomyResolver, UnmappedProduct } from '@cybercves/core';
import { normalizeCve } from '@cybercves/core';
import type { Repository, UpsertResult } from '@cybercves/db';

/**
 * The shared ingest path.
 *
 * Both the Worker's 15-minute delta sync and the Node backfill funnel through
 * this function, so a record is normalized, attributed, and stored identically
 * regardless of which process saw it.
 */

export interface IngestSummary extends UpsertResult {
  processed: number;
  unmappedCount: number;
  /** Queue entries retired because the taxonomy now maps them. */
  retiredUnmapped: number;
  /** Records that matched no tracked vendor. Expected and large — most CVEs are not ours. */
  unmatched: number;
  /** Withdrawn assignments, skipped before normalization. */
  rejected: number;
}

export interface IngestOptions {
  /**
   * Re-apply the taxonomy to records whose upstream content has not changed.
   * Needed after editing data/products/*.yaml — see upsertCves.
   */
  reresolve?: boolean;
  /**
   * Persist records that match no tracked vendor. Off by default: storing all
   * ~40k CVEs published each year, when we track a few thousand, would blow the
   * D1 free-tier storage budget for data the site never shows.
   */
  keepUnmatched?: boolean;
  now?: string;
}

export async function ingestRecords(
  repo: Repository,
  resolver: TaxonomyResolver,
  records: readonly CveRecord[],
  options: IngestOptions = {},
): Promise<IngestSummary> {
  const now = options.now ?? new Date().toISOString();
  const entries: Array<{ cve: ReturnType<typeof normalizeCve>; resolved: never[] | ReturnType<TaxonomyResolver['resolve']>['resolved'] }> = [];
  const unmapped = new Map<string, UnmappedProduct>();
  let unmatched = 0;
  let rejected = 0;

  for (const record of records) {
    if (!record?.cveMetadata?.cveId) continue;

    // REJECTED records are withdrawn assignments — no description, no affected
    // products, no score. Every query already filters them out, so storing them
    // is pure cost: on a 2024-2026 backfill they were 39% of stored rows.
    if (record.cveMetadata.state === 'REJECTED') {
      rejected++;
      continue;
    }

    const cve = normalizeCve(record);
    const { resolved, unmapped: gaps, vendors } = resolver.resolve(cve);

    // A CVE with no resolved product but a matched vendor is still ours — it
    // just names a product we have not mapped yet. Only a CVE matching no vendor
    // at all is genuinely someone else's.
    if (vendors.size === 0) {
      unmatched++;
      if (!options.keepUnmatched) continue;
    }

    for (const gap of gaps) {
      if (gap.vendorSlug) unmapped.set(`${gap.vendorSlug}::${gap.productRaw}`, gap);
    }
    entries.push({ cve, resolved });
  }

  const result = await repo.upsertCves(entries, now, { reresolve: options.reresolve });
  await repo.recordUnmapped([...unmapped.values()], now);

  // Retire gaps the taxonomy now answers. Resolution is a pure function of the
  // config, not of this batch, so the whole pending queue can be re-tested here
  // and a delta sync retires a mapping added since the last full backfill.
  const stale = (await repo.listPendingUnmapped())
    .filter((row) => resolver.resolveProductName(row.vendor_slug, row.product_raw))
    .map((row) => ({ vendorSlug: row.vendor_slug, productKey: row.product_key }));
  const retired = await repo.clearResolvedUnmapped(stale);

  return {
    ...result,
    processed: entries.length,
    unmappedCount: unmapped.size,
    retiredUnmapped: retired,
    unmatched,
    rejected,
  };
}
