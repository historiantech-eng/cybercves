import type { KevEntry } from '@cybercves/core';
import { fetchJson } from '../http.js';

/**
 * CISA Known Exploited Vulnerabilities catalog.
 *
 * The single most valuable enrichment on the site: KEV membership is confirmed
 * exploitation in the wild, which is a far stronger claim about real risk than
 * any CVSS score. Public domain, no auth, no rate limit.
 */

export const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** Shape verified live on 2026-07-27 (catalog of 1,653 entries). */
interface RawKevVulnerability {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  dateAdded?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
}

interface RawKevCatalog {
  catalogVersion?: string;
  dateReleased?: string;
  count?: number;
  vulnerabilities?: RawKevVulnerability[];
}

export interface KevCatalog {
  catalogVersion: string | null;
  dateReleased: string | null;
  entries: KevEntry[];
}

export async function fetchKev(url = KEV_URL): Promise<KevCatalog> {
  const raw = await fetchJson<RawKevCatalog>(url);
  const entries: KevEntry[] = [];

  for (const vuln of raw.vulnerabilities ?? []) {
    // Note the capital "ID" — CISA uses `cveID`, unlike the CVE List's `cveId`.
    if (!vuln.cveID || !vuln.dateAdded) continue;
    entries.push({
      cveId: vuln.cveID,
      dateAdded: vuln.dateAdded,
      dueDate: vuln.dueDate ?? null,
      // A string enum ("Known" | "Unknown"), not a boolean. Anything other than
      // an explicit "Known" is treated as not-known rather than as true.
      ransomwareKnown: vuln.knownRansomwareCampaignUse?.toLowerCase() === 'known',
      vendorProject: vuln.vendorProject ?? null,
      product: vuln.product ?? null,
    });
  }

  return {
    catalogVersion: raw.catalogVersion ?? null,
    dateReleased: raw.dateReleased ?? null,
    entries,
  };
}
