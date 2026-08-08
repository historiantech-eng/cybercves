import type { CveRecord } from '@cybercves/core';
import { fetchJson, mapLimit } from '../http.js';

/**
 * CVE List adapter — the primary spine.
 *
 * Fortinet, Cisco, and Palo Alto are all CNAs, so their advisory data arrives
 * here as structured JSON with affected products, versions, CVSS, CWE, fixed
 * versions, and a link back to their PSIRT advisory. No scraping required.
 */

export const DELTA_URL =
  'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json';

/** Shape verified live on 2026-07-27. */
export interface DeltaEntry {
  cveId: string;
  cveOrgLink?: string;
  githubLink: string;
  dateUpdated?: string;
}

export interface DeltaFeed {
  fetchTime: string;
  numberOfChanges: number;
  new?: DeltaEntry[];
  updated?: DeltaEntry[];
  error?: DeltaEntry[];
}

export async function fetchDelta(url = DELTA_URL): Promise<DeltaFeed> {
  return fetchJson<DeltaFeed>(url);
}

/**
 * Changed records from the delta feed, newest first, deduped by CVE ID.
 *
 * A record can appear in both `new` and `updated` within one window; fetching it
 * twice would double the request count for no benefit.
 */
export function changedEntries(feed: DeltaFeed): DeltaEntry[] {
  const byId = new Map<string, DeltaEntry>();
  for (const entry of [...(feed.new ?? []), ...(feed.updated ?? [])]) {
    const existing = byId.get(entry.cveId);
    if (!existing || (entry.dateUpdated ?? '') > (existing.dateUpdated ?? '')) {
      byId.set(entry.cveId, entry);
    }
  }
  return [...byId.values()].sort((a, b) => (b.dateUpdated ?? '').localeCompare(a.dateUpdated ?? ''));
}

/**
 * Fetch the full record for each changed entry.
 *
 * Individual failures resolve to null rather than aborting the run: one 404 from
 * a withdrawn record must not cost us the rest of the sync window.
 */
export async function fetchRecords(
  entries: readonly DeltaEntry[],
  concurrency = 6,
): Promise<Array<{ entry: DeltaEntry; record: CveRecord | null; error?: string }>> {
  return mapLimit(entries, concurrency, async (entry) => {
    try {
      return { entry, record: await fetchJson<CveRecord>(entry.githubLink) };
    } catch (err) {
      return { entry, record: null, error: (err as Error).message };
    }
  });
}

/**
 * Path a CVE occupies in the repository tree, e.g.
 * CVE-2025-32756 -> cves/2025/32xxx/CVE-2025-32756.json
 *
 * The bucket is the sequence number with its last three digits replaced by
 * "xxx", so CVE-2024-3400 lands in 3xxx rather than 0xxx.
 */
export function recordPath(cveId: string): string | null {
  const match = /^CVE-(\d{4})-(\d+)$/.exec(cveId);
  if (!match) return null;
  const [, year, sequence] = match as unknown as [string, string, string];
  const bucket = sequence.length <= 3 ? '0xxx' : `${sequence.slice(0, -3)}xxx`;
  return `cves/${year}/${bucket}/${cveId}.json`;
}

export function rawUrlFor(cveId: string): string | null {
  const path = recordPath(cveId);
  return path ? `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/${path}` : null;
}
