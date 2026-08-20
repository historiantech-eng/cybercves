/** Normalized domain model — what we persist and serve, independent of upstream schemas. */

export type Severity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/** CVSS versions we understand, in descending order of preference. */
export type CvssVersion = '4.0' | '3.1' | '3.0' | '2.0';

export interface CvssResult {
  version: CvssVersion;
  vectorString: string | null;
  baseScore: number;
  severity: Severity;
  /** Which container supplied it — CNA data is preferred over ADP enrichment. */
  source: 'cna' | 'adp';
}

/**
 * How a CVE was attributed to a vendor. Recorded per row so mis-attribution is
 * auditable: not every CVE affecting a vendor is assigned by that vendor's CNA.
 */
export type MatchSignal = 'cna-assigner' | 'affected-vendor' | 'cpe' | 'reference-host';

export interface NormalizedAffected {
  vendorRaw: string | null;
  productRaw: string | null;
  cpes: string[];
  /** Capped at MAX_VERSION_RANGES; see normalize.ts for why. */
  versions: NormalizedVersionRange[];
  /** True when the vendor listed more ranges than we store. */
  versionsTruncated: boolean;
  /** How many the vendor actually listed, before capping. */
  versionCount: number;
  defaultStatus: string | null;
}

export interface NormalizedVersionRange {
  version: string | null;
  status: string | null;
  lessThan: string | null;
  lessThanOrEqual: string | null;
  versionType: string | null;
}

export interface NormalizedReference {
  url: string;
  name: string | null;
  tags: string[];
}

export interface NormalizedCve {
  cveId: string;
  assignerShortName: string | null;
  state: string;
  datePublished: string | null;
  dateUpdated: string | null;
  dateReserved: string | null;
  title: string | null;
  description: string | null;
  cvss: CvssResult | null;
  /** Who found it — vendor's own team vs an outsider. Null when undisclosed. */
  discovery: import('./discovery.js').Discovery | null;
  /** How discovery was determined, so a scraped guess is distinguishable from a published field. */
  discoverySource: import('./discovery.js').DiscoverySource | null;
  /** Raw credit/acknowledgement text, shown so readers can judge the classification. */
  creditText: string | null;
  cweIds: string[];
  solution: string | null;
  affected: NormalizedAffected[];
  references: NormalizedReference[];
  /** Stable hash of the upstream record, used to skip unchanged re-ingests. */
  sourceHash: string;
}

export interface KevEntry {
  cveId: string;
  dateAdded: string;
  dueDate: string | null;
  ransomwareKnown: boolean;
  vendorProject: string | null;
  product: string | null;
}

export interface EpssEntry {
  cveId: string;
  score: number;
  percentile: number;
  asOf: string;
}

export interface Category {
  slug: string;
  name: string;
  description: string;
  sort: number;
}

export interface VendorConfig {
  slug: string;
  name: string;
  /** CVE Program CNA shortNames that assign on this vendor's behalf. */
  cnaShortNames: string[];
  /** Strings seen in `affected[].vendor` and in CPE vendor fields. Lowercased on load. */
  aliases: string[];
  /**
   * Acquired brands still writing their own name in `affected[].vendor`, mapped
   * to every spelling upstream uses for them: Splunk under Cisco, CyberArk under
   * Palo Alto. These count as vendor aliases too — a CVE naming one is still
   * this vendor's — and additionally scope product resolution to the brand, so
   * that a Splunk product cannot be mistaken for a Cisco one. See
   * TaxonomyResolver.resolveProductName.
   */
  brands: Record<string, string[]>;
  /** Hostnames whose presence in a reference URL implies this vendor's advisory. */
  psirtHosts: string[];
  psirtUrl: string | null;
  homepage: string | null;
  /** Which enrichment adapter tier this vendor uses beyond the CVE List. */
  adapter: 'cvelist' | 'json' | 'csaf' | 'rss' | 'scrape';
}

export interface ProductConfig {
  slug: string;
  vendorSlug: string;
  name: string;
  categorySlug: string;
  /** Exact (lowercased) product strings that map here. */
  aliases: string[];
  /** Regex sources tried when no alias matches. Anchored and case-insensitive at compile time. */
  patterns: string[];
  /**
   * The acquired brand this product belongs to, as written in `affected[].vendor`
   * — "Splunk" under Cisco, "CyberArk" under Palo Alto. An entry naming that
   * brand is matched against this brand's products alone, so a Splunk SOAR
   * connector cannot be filed as the Cisco product whose name it borrows.
   */
  brand: string | null;
  /**
   * Catch anything from this brand that no sibling product claimed. Only ever
   * consulted for an entry that names the brand, so it cannot swallow the
   * vendor's own strings. Opt-in per brand: without one, an unrecognised product
   * goes to the review queue instead.
   */
  brandFallback: boolean;
}

/** A resolved link between a CVE and one of our canonical products. */
export interface ResolvedProduct {
  productSlug: string;
  vendorSlug: string;
  categorySlug: string;
  matchSignal: MatchSignal;
}

/** A raw product string we could not map — queued for AI suggestion + human review. */
export interface UnmappedProduct {
  vendorRaw: string | null;
  productRaw: string;
  vendorSlug: string | null;
}
