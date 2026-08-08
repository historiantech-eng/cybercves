import type { CveContainer, CveRecord, LangValue } from './cve-schema.js';
import { extractCvss } from './cvss.js';
import { extractDiscovery } from './discovery.js';
import { fnv1a64 } from './hash.js';
import type {
  NormalizedAffected,
  NormalizedCve,
  NormalizedReference,
  NormalizedVersionRange,
} from './types.js';

/** Prefer an English entry; fall back to the first present so we never drop content. */
function pickText(entries: LangValue[] | undefined): string | null {
  if (!entries?.length) return null;
  const english = entries.find((e) => e.lang?.toLowerCase().startsWith('en') && e.value);
  return (english?.value ?? entries.find((e) => e.value)?.value ?? null)?.trim() || null;
}

/**
 * Cap on stored version ranges per affected product.
 *
 * Some vendors enumerate every patch level individually rather than expressing a
 * range: one Cisco record lists 2,699 version strings for a single product, which
 * serializes to ~866 KB and blows past SQLite's statement-size limit on insert
 * (SQLITE_TOOBIG). Across a 3-year backfill these arrays were 13.5 MB — the bulk
 * of the database — for data no page renders.
 *
 * Fifty preserves the useful signal (the boundaries of the affected range) and
 * discards the enumeration noise. `truncated` records that we capped, so a future
 * "am I affected?" feature knows not to treat the list as exhaustive.
 */
export const MAX_VERSION_RANGES = 50;

/**
 * Cap on stored CPE identifiers per affected product.
 *
 * Vendors that enumerate versions also emit one CPE per version — the same
 * record with 2,699 versions carries ~2,400 CPEs, ~120 KB in a single row.
 *
 * Lossless for our purposes: every CPE within one affected entry shares the same
 * vendor and product components and differs only in version, and matching stops
 * at the first hit. Twenty is far more than the resolver ever reads.
 */
export const MAX_CPES = 20;

function normalizeVersions(container: NonNullable<CveContainer['affected']>[number]) {
  const source = container.versions ?? [];
  const versions: NormalizedVersionRange[] = [];

  for (const v of source.slice(0, MAX_VERSION_RANGES)) {
    versions.push({
      version: v.version ?? null,
      status: v.status ?? null,
      lessThan: v.lessThan ?? null,
      lessThanOrEqual: v.lessThanOrEqual ?? null,
      versionType: v.versionType ?? null,
    });
  }
  return { versions, truncated: source.length > MAX_VERSION_RANGES, total: source.length };
}

/**
 * Collect affected entries from the CNA container and any ADP containers.
 *
 * ADP entries matter: CISA-ADP frequently supplies CPEs for records where the
 * CNA gave only free-text product names, and those CPEs are often the only
 * signal precise enough to resolve a product.
 */
function normalizeAffected(record: CveRecord): NormalizedAffected[] {
  const out: NormalizedAffected[] = [];
  const containers: CveContainer[] = [];
  if (record.containers?.cna) containers.push(record.containers.cna);
  for (const adp of record.containers?.adp ?? []) containers.push(adp);

  for (const container of containers) {
    for (const entry of container.affected ?? []) {
      const vendorRaw = entry.vendor?.trim() || null;
      const productRaw = (entry.product ?? entry.packageName)?.trim() || null;
      if (!vendorRaw && !productRaw && !entry.cpes?.length) continue;
      const { versions, truncated, total } = normalizeVersions(entry);
      out.push({
        vendorRaw,
        productRaw,
        cpes: (entry.cpes ?? [])
          .filter((c): c is string => typeof c === 'string' && c.length > 0)
          .slice(0, MAX_CPES),
        versions,
        versionsTruncated: truncated,
        versionCount: total,
        defaultStatus: entry.defaultStatus ?? null,
      });
    }
  }
  return out;
}

function normalizeReferences(record: CveRecord): NormalizedReference[] {
  const seen = new Set<string>();
  const out: NormalizedReference[] = [];
  const containers: CveContainer[] = [];
  if (record.containers?.cna) containers.push(record.containers.cna);
  for (const adp of record.containers?.adp ?? []) containers.push(adp);

  for (const container of containers) {
    for (const ref of container.references ?? []) {
      const url = ref.url?.trim();
      if (!url || seen.has(url)) continue;
      seen.add(url);
      out.push({ url, name: ref.name?.trim() || null, tags: ref.tags ?? [] });
    }
  }
  return out;
}

function normalizeCwes(record: CveRecord): string[] {
  const seen = new Set<string>();
  for (const problemType of record.containers?.cna?.problemTypes ?? []) {
    for (const desc of problemType.descriptions ?? []) {
      const cweId = desc.cweId?.trim();
      if (cweId && /^CWE-\d+$/i.test(cweId)) seen.add(cweId.toUpperCase());
    }
  }
  return [...seen].sort();
}

/**
 * Convert an upstream CVE 5.x record into our domain model.
 *
 * Pure and synchronous by design: it runs identically in the Cloudflare Worker,
 * in Node during backfill, and inside tests against committed fixtures.
 */
export function normalizeCve(record: CveRecord): NormalizedCve {
  const cna = record.containers?.cna;
  const meta = record.cveMetadata;
  const discovery = extractDiscovery(record);

  return {
    cveId: meta.cveId,
    assignerShortName: meta.assignerShortName?.toLowerCase() ?? null,
    state: meta.state ?? 'PUBLISHED',
    datePublished: meta.datePublished ?? null,
    dateUpdated: meta.dateUpdated ?? null,
    dateReserved: meta.dateReserved ?? null,
    title: cna?.title?.trim() || null,
    description: pickText(cna?.descriptions),
    cvss: extractCvss(record),
    discovery: discovery.discovery,
    discoverySource: discovery.source,
    creditText: discovery.creditText,
    cweIds: normalizeCwes(record),
    solution: pickText(cna?.solutions),
    affected: normalizeAffected(record),
    references: normalizeReferences(record),
    sourceHash: hashRecord(record),
  };
}

/**
 * Fingerprint the fields we persist, not the whole document.
 *
 * `dateUpdated` and provider metadata churn on upstream republishes that change
 * nothing we display; hashing them would force pointless rewrites on every sync.
 */
export function hashRecord(record: CveRecord): string {
  const cna = record.containers?.cna;
  const material = JSON.stringify({
    id: record.cveMetadata.cveId,
    state: record.cveMetadata.state,
    published: record.cveMetadata.datePublished,
    title: cna?.title,
    descriptions: cna?.descriptions,
    affected: cna?.affected,
    metrics: cna?.metrics,
    problemTypes: cna?.problemTypes,
    references: cna?.references,
    solutions: cna?.solutions,
    source: cna?.source,
    credits: cna?.credits,
    adp: record.containers?.adp?.map((a) => ({
      metrics: a.metrics,
      affected: a.affected,
    })),
  });
  return fnv1a64(material);
}

/** Publication year, used for the YTD counter and year-sharded client indexes. */
export function publishedYear(cve: NormalizedCve): number | null {
  if (!cve.datePublished) return null;
  const year = Number.parseInt(cve.datePublished.slice(0, 4), 10);
  return Number.isFinite(year) ? year : null;
}
