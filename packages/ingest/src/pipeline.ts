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

/**
 * The oldest CVE ID year the site tracks.
 *
 * The deploy backfills from a sparse clone of cves/2024 onward and then
 * replaces D1 wholesale, so this is the de facto scope of production. The
 * delta feed has no such limit — it carries any record updated upstream, and
 * old IDs are revised all the time — so the Worker must apply the same cutoff
 * or D1 accumulates rows the next push deletes. Four of those (CVE-2020-26140
 * and friends, republished upstream) were enough to trip push:d1's shrink
 * guard and halt the deploy.
 *
 * Keep in step with `--from` and the sparse checkout in deploy.yml.
 */
export const FIRST_TRACKED_YEAR = 2024;

/** The year embedded in a CVE ID ("CVE-2024-1234" → 2024), or NaN. */
export function cveIdYear(cveId: string): number {
  return Number.parseInt(cveId.slice(4, 8), 10);
}

export interface IngestSummary extends UpsertResult {
  processed: number;
  unmappedCount: number;
  /** Queue entries retired because the taxonomy now maps them. */
  retiredUnmapped: number;
  /** Records that matched no tracked vendor. Expected and large — most CVEs are not ours. */
  unmatched: number;
  /** Withdrawn assignments, skipped before normalization. */
  rejected: number;
  /** Records older than `fromYear`, skipped before normalization. */
  outOfRange: number;
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
  /**
   * Store uncapped version lists in the build-only table. Node bins only —
   * the Worker's cron must not; see Repository.upsertCves.
   */
  fullVersions?: boolean;
  /**
   * Skip CVE IDs from before this year. The delta paths pass FIRST_TRACKED_YEAR;
   * the backfill already limits years by which directories it reads.
   */
  fromYear?: number;
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
  let outOfRange = 0;

  for (const record of records) {
    if (!record?.cveMetadata?.cveId) continue;

    // REJECTED records are withdrawn assignments — no description, no affected
    // products, no score. Every query already filters them out, so storing them
    // is pure cost: on a 2024-2026 backfill they were 39% of stored rows.
    if (record.cveMetadata.state === 'REJECTED') {
      rejected++;
      continue;
    }

    if (options.fromYear !== undefined && !(cveIdYear(record.cveMetadata.cveId) >= options.fromYear)) {
      outOfRange++;
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

  const result = await repo.upsertCves(entries, now, {
    reresolve: options.reresolve,
    fullVersions: options.fullVersions,
  });
  await repo.recordUnmapped([...unmapped.values()], now);

  // Retire gaps the taxonomy now answers. Resolution is a pure function of the
  // config, not of this batch, so the whole pending queue can be re-tested here
  // and a delta sync retires a mapping added since the last full backfill.
  const stale = (await repo.listPendingUnmapped())
    .filter((row) => resolver.resolveProductName(row.vendor_slug, row.product_raw, row.vendor_raw))
    .map((row) => ({ vendorSlug: row.vendor_slug, productKey: row.product_key }));
  const retired = await repo.clearResolvedUnmapped(stale);

  return {
    ...result,
    processed: entries.length,
    unmappedCount: unmapped.size,
    retiredUnmapped: retired,
    unmatched,
    rejected,
    outOfRange,
  };
}
