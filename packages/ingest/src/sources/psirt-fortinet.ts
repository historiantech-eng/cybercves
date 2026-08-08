import { classifyAcknowledgement, classifyPsirtDiscovered } from '@cybercves/core';
import type { DiscoveryResult } from '@cybercves/core';
import { fetchText, mapLimit } from '../http.js';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Fortinet PSIRT acknowledgement scraper.
 *
 * The tier-4 fallback from the plan, and the only vendor that needs it: Fortinet
 * publishes no `cna.source.discovery` and no `credits` in the CVE List — 357
 * records across 2024-2026 with zero structured discovery signal — but their
 * advisory pages carry an Acknowledgement section naming the finder.
 *
 * Server-rendered, so a plain fetch is enough; no headless browser.
 *
 * This is HTML scraping and therefore brittle by nature. `parseAcknowledgement`
 * is pinned by a committed fixture so a layout change fails a test rather than
 * silently degrading every Fortinet CVE to "undisclosed".
 */

/** Advisory URLs look like https://fortiguard.fortinet.com/psirt/FG-IR-25-254 */
const ADVISORY_URL = /https?:\/\/(?:www\.)?fortiguard\.(?:fortinet\.)?com\/psirt\/(FG-IR-[\w-]+)/i;

/**
 * Canonical page for an advisory.
 *
 * CVE references cite this host three ways — fortiguard.com,
 * www.fortiguard.com, fortiguard.fortinet.com — all of which redirect here. The
 * advisory ID is the identity, so normalising means one cache entry per
 * advisory instead of three, and one request instead of a request plus a
 * redirect, on a pass that is deliberately paced at twenty seconds a page.
 */
export const advisoryUrl = (advisoryId: string): string =>
  `https://www.fortiguard.com/psirt/${advisoryId.toUpperCase()}`;

export function advisoryUrlFromRefs(refsJson: string): string | null {
  let refs: Array<{ url?: string }>;
  try {
    refs = JSON.parse(refsJson) as Array<{ url?: string }>;
  } catch {
    return null;
  }
  for (const ref of refs) {
    const match = ref.url ? ADVISORY_URL.exec(ref.url) : null;
    if (match?.[1]) return advisoryUrl(match[1]);
  }
  return null;
}

function stripTags(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&quot;/gi, '"')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Pull the Acknowledgement text out of an advisory page.
 *
 * Target markup (verified live 2026-08-06):
 *   <div lang="en" class="detail-item">
 *       <h3>Acknowledgement</h3>
 *       Discovered by … of Fortinet Product Security Team …
 *   </div>
 */
export function parseAcknowledgement(html: string): string | null {
  const heading = /<h3[^>]*>\s*Acknowledge?ment\s*<\/h3>/i.exec(html);
  if (!heading) return null;

  const after = html.slice(heading.index + heading[0].length);
  // The section ends at the closing div, or at the next heading if the markup
  // ever flattens — whichever comes first.
  const endDiv = after.search(/<\/div>/i);
  const nextHeading = after.search(/<h[23][^>]*>/i);
  const end = Math.min(...[endDiv, nextHeading].filter((i) => i >= 0));
  const body = Number.isFinite(end) ? after.slice(0, end) : after.slice(0, 1000);

  const text = stripTags(body);
  return text.length ? text : null;
}

/**
 * Pull Fortinet's own "Discovered" value out of an advisory page.
 *
 * Target markup (verified live 2026-08-08):
 *   <tr>
 *       <td>Discovered</td>
 *       <td>Internal</td>
 *   </tr>
 *
 * This is the summary table on every /psirt/FG-IR-* page, and it is a far
 * stronger signal than the Acknowledgement prose below it — a labelled field
 * the vendor publishes rather than a rule applied to a sentence. The same
 * value appears as a column on the paginated /psirt index, which would cost 48
 * requests instead of 336; the index is not used because fortiguard.com's
 * robots.txt disallows `/*?*` and the index only exists behind query params.
 */
export function parseDiscoveredField(html: string): string | null {
  const match = /<td>\s*Discovered\s*<\/td>\s*<td[^>]*>([\s\S]{0,120}?)<\/td>/i.exec(html);
  if (!match) return null;
  const value = stripTags(match[1] ?? '');
  return value.length ? value : null;
}

export interface AcknowledgementResult extends DiscoveryResult {
  cveId: string;
  url: string;
}

export interface AcknowledgementRun {
  results: AcknowledgementResult[];
  /** Pages fetched and parsed, but carrying no usable attribution. */
  missing: number;
  /** Requests that never returned. Counted separately — see below. */
  failed: number;
  /**
   * CVEs whose advisory could not be fetched at all.
   *
   * Exposed, not just counted, because callers must tell "we read it and it said
   * nothing" apart from "we never got the page". Backing the second case off on
   * the same schedule as the first would let one bad afternoon silently suppress
   * a real advisory for a week.
   */
  failedCveIds: string[];
}

/**
 * Read one advisory page into a verdict.
 *
 * Two signals, in strict order of evidential strength:
 *
 *   1. the `Discovered` field — Fortinet's own labelled value;
 *   2. the Acknowledgement prose — a rule applied to a sentence.
 *
 * The field decides, but the prose still supplies `creditText`, because
 * "Discovered by Théo Leleu and David Maciejak of Fortinet Product Security
 * Team" is what a reader needs to audit the verdict, and "Internal" is not.
 * When the field is absent the prose decides on its own, at the weaker
 * `psirt-acknowledgement` source, so the page can still say which it was.
 */
export function classifyAdvisoryPage(
  html: string,
  vendorName: string,
  brandMarkers: readonly string[] = [],
): DiscoveryResult {
  const prose = parseAcknowledgement(html);
  const field = classifyPsirtDiscovered(parseDiscoveredField(html));
  if (!field.discovery) return classifyAcknowledgement(prose, vendorName, brandMarkers);
  return { ...field, creditText: prose ?? field.creditText };
}

export async function fetchAcknowledgements(
  targets: ReadonlyArray<{ cveId: string; url: string }>,
  options: {
    vendorName?: string;
    brandMarkers?: readonly string[];
    concurrency?: number;
    /** Pause between requests, per worker. */
    delayMs?: number;
    /**
     * Page loader. Overridden by the CLI with a disk-caching wrapper so a run
     * that is cut off resumes instead of restarting — at one page every twenty
     * seconds, restarting a 336-page pass is a two-hour penalty. Kept as a hook
     * rather than built in because `ingest/` must not assume a filesystem.
     *
     * `fromCache` is what keeps the delay honest: pacing exists to be polite to
     * the origin, so a page served off disk must not sleep. Without it a resumed
     * run would spend two hours waiting on requests it never makes.
     */
    fetchPage?: (url: string) => Promise<{ html: string; fromCache?: boolean }>;
  } = {},
): Promise<AcknowledgementRun> {
  const {
    vendorName = 'Fortinet',
    brandMarkers = [],
    concurrency = 2,
    delayMs = 1_500,
    fetchPage = async (url: string): Promise<{ html: string; fromCache?: boolean }> => ({
      html: await fetchText(url, { timeoutMs: 30_000, retries: 3 }),
    }),
  } = options;

  let missing = 0;
  let failed = 0;
  const failedCveIds: string[] = [];

  // One fetch per advisory, not per CVE. A Fortinet advisory routinely covers
  // several CVEs, and refetching the same page once per CVE would add ~15
  // needless requests to a run that is already deliberately slow.
  const byUrl = new Map<string, string[]>();
  for (const t of targets) {
    const bucket = byUrl.get(t.url);
    if (bucket) bucket.push(t.cveId);
    else byUrl.set(t.url, [t.cveId]);
  }
  const pages = [...byUrl.entries()].map(([url, cveIds]) => ({ url, cveIds }));

  // Paced deliberately. An unthrottled pass over ~350 advisories got this client
  // blocked at the TLS layer partway through, and the partial result looked like
  // "these CVEs have no acknowledgement" rather than "we were cut off" — which
  // would have produced a false 100%-internal figure for the vendor.
  const settled = await mapLimit(pages, concurrency, async (page) => {
    try {
      const loaded = await fetchPage(page.url);
      // After, not before: this is the gap the next request in this worker
      // waits out, and a cached page owes the origin no gap at all.
      if (!loaded.fromCache) await sleep(delayMs);
      const verdict = classifyAdvisoryPage(loaded.html, vendorName, brandMarkers);
      if (!verdict.discovery) {
        missing += page.cveIds.length;
        return [];
      }
      return page.cveIds.map((cveId) => ({ ...verdict, cveId, url: page.url }));
    } catch {
      // Never conflated with "no acknowledgement": a transport failure tells us
      // nothing about the advisory, and treating it as an answer would bias every
      // aggregate built on top.
      failed += page.cveIds.length;
      failedCveIds.push(...page.cveIds);
      return [];
    }
  });

  return { results: settled.flat(), missing, failed, failedCveIds };
}
