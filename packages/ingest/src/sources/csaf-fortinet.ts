import { classifyAcknowledgement } from '@cybercves/core';
import { fetchText, mapLimit } from '../http.js';
import type { AcknowledgementResult } from './psirt-fortinet.js';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Fortinet discovery attribution from CSAF, instead of from the advisory page.
 *
 * WHY THIS EXISTS ALONGSIDE psirt-fortinet.ts
 *
 * fortiguard.com answers /psirt/* with an ALTCHA proof-of-work interstitial when
 * it does not like the client, and has been refusing CI outright since
 * 2026-09-08. But the same advisories are published as CSAF 2.0 documents on
 * filestore.fortinet.com — the host the PSIRT RSS feed already lives on — and
 * that host serves them without a challenge. The attribution we could not read
 * by scraping has been sitting there in `document.acknowledgments` the whole
 * time.
 *
 * WHAT THIS DOES NOT REPLACE
 *
 * The advisory page carries a labelled `Discovered:` field; the CSAF document
 * does not. Every one of the 363 attributions committed before this was sourced
 * from that field (`psirt-field`), which is the vendor stating the answer
 * outright. CSAF gives prose, which we classify — the weaker `psirt-acknowledgement`
 * tier. So this is a second source, not a successor: it answers when the page
 * cannot be read, and the page remains the better answer when it can.
 *
 * THE FILENAME PROBLEM
 *
 * Fortinet publishes no CSAF index. index.txt, changes.csv and
 * provider-metadata.json are all 404 and the directory does not list, so there
 * is no way to enumerate what exists — the filename has to be derived from the
 * advisory's title, which the RSS feed supplies. That derivation is a guess
 * about someone else's naming convention, so every result is checked against
 * the document's own tracking id before it is believed. See fetchCsafAcknowledgements.
 */

/** Where Fortinet's CSAF documents actually live — not on the blocked host. */
export const CSAF_BASE = 'https://filestore.fortinet.com/fortiguard/psirt/';

/**
 * Advisory id -> title, read from the PSIRT RSS feed.
 *
 * The feed is the only enumeration of recent advisories available without
 * touching fortiguard.com, and the title is the one input the CSAF filename
 * needs. It holds 50 entries, which bounds what this source can ever reach:
 * fine for a refresh job that runs hourly, useless for backfilling history.
 */
export function parseRssAdvisoryTitles(xml: string): Map<string, string> {
  const titles = new Map<string, string>();
  for (const item of xml.matchAll(/<item>([\s\S]*?)<\/item>/g)) {
    const block = item[1] ?? '';
    const title = /<title>([\s\S]*?)<\/title>/.exec(block)?.[1]?.trim();
    const link = /<link>([\s\S]*?)<\/link>/.exec(block)?.[1]?.trim();
    if (!title || !link) continue;
    const advisoryId = link.replace(/\/+$/, '').split('/').pop()?.toUpperCase();
    if (advisoryId) titles.set(advisoryId, title);
  }
  return titles;
}

/**
 * Fortinet's CSAF filename convention, as observed.
 *
 * `csaf_<title slugified>_<advisory id lowercased>.json`. Verified against 21
 * advisories spanning FG-IR-24-* to FG-IR-26-*; every one resolved. It is still
 * a convention we inferred rather than one Fortinet documents, which is why
 * callers must verify the document they get back.
 */
export function csafUrlFor(advisoryId: string, title: string, base = CSAF_BASE): string {
  const slug = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return `${base}csaf_${slug}_${advisoryId.toLowerCase()}.json`;
}

/** Thrown when a CSAF document is not the one we asked for. */
export class CsafMismatchError extends Error {
  constructor(want: string, got: string | undefined) {
    super(`CSAF document is for ${got ?? 'an unknown advisory'}, not ${want}`);
    this.name = 'CsafMismatchError';
  }
}

/**
 * The acknowledgement prose, if the document carries any.
 *
 * Acknowledgments are document-level in Fortinet's CSAF — the per-vulnerability
 * `acknowledgments` array is consistently null — so one credit covers every CVE
 * in the advisory. That matches how the advisory page reads anyway: one
 * Acknowledgement section for the whole page.
 */
export function acknowledgementFromCsaf(doc: unknown, wantAdvisoryId: string): string | null {
  const root = doc as {
    document?: {
      tracking?: { id?: string };
      acknowledgments?: Array<{ summary?: string; names?: string[]; organization?: string }>;
    };
  };

  // Verified before anything is read out of it. The filename was derived from a
  // title, and a wrong guess that happened to hit a real file would attribute
  // one advisory's finder to another CVE — a false statement about a named
  // person, published as fact. An id mismatch is treated as "not readable",
  // never as "no attribution".
  const got = root.document?.tracking?.id;
  if (!got || got.toUpperCase() !== wantAdvisoryId.toUpperCase()) {
    throw new CsafMismatchError(wantAdvisoryId, got);
  }

  const ack = root.document?.acknowledgments?.[0];
  if (!ack) return null;
  // `summary` is what Fortinet populates; names/organization are read as a
  // fallback so a shape change degrades rather than silently returning nothing.
  const summary =
    ack.summary?.trim() ||
    [ack.names?.join(', '), ack.organization].filter(Boolean).join(' of ').trim();
  return summary && summary.length ? summary : null;
}

export interface CsafRun {
  results: AcknowledgementResult[];
  /**
   * Targets CSAF did not answer, for the caller to try another way.
   *
   * Deliberately one bucket covering "no CSAF exists", "the fetch failed" and
   * "the document credits nobody". None of the three is evidence that the
   * *advisory* names no finder — the advisory page carries a `Discovered:` field
   * that CSAF does not reproduce — so none of them may be allowed to reach the
   * unresolved backoff on this source's say-so alone.
   */
  remaining: Array<{ cveId: string; url: string }>;
  /** Documents read successfully. */
  read: number;
  /** Read, valid, but carrying no acknowledgement. */
  missing: number;
  /** Could not be read: no title in the feed, 404, transport error, or id mismatch. */
  failed: number;
}

export async function fetchCsafAcknowledgements(
  targets: ReadonlyArray<{ cveId: string; url: string }>,
  options: {
    /** Advisory id -> title, from parseRssAdvisoryTitles. */
    titles: ReadonlyMap<string, string>;
    vendorName?: string;
    brandMarkers?: readonly string[];
    concurrency?: number;
    delayMs?: number;
    base?: string;
    fetchDoc?: (url: string) => Promise<string>;
  },
): Promise<CsafRun> {
  const {
    titles,
    vendorName = 'Fortinet',
    brandMarkers = [],
    concurrency = 1,
    delayMs = 1_000,
    base = CSAF_BASE,
    fetchDoc = (url: string) => fetchText(url, { timeoutMs: 30_000, retries: 2 }),
  } = options;

  const advisoryId = (url: string) => url.replace(/\/+$/, '').split('/').pop()?.toUpperCase() ?? '';

  // One document per advisory, not per CVE — a Fortinet advisory routinely
  // covers several, and the acknowledgement is document-level regardless.
  const byAdvisory = new Map<string, { url: string; cveIds: string[] }>();
  for (const t of targets) {
    const id = advisoryId(t.url);
    const bucket = byAdvisory.get(id);
    if (bucket) bucket.cveIds.push(t.cveId);
    else byAdvisory.set(id, { url: t.url, cveIds: [t.cveId] });
  }

  let read = 0;
  let missing = 0;
  let failed = 0;
  const resolved = new Set<string>();

  const settled = await mapLimit(
    [...byAdvisory.entries()],
    concurrency,
    async ([id, page]): Promise<AcknowledgementResult[]> => {
      const title = titles.get(id);
      if (!title) {
        // Older than the feed window. Not a failure of Fortinet's, and not
        // evidence of anything — just outside what this source can see.
        failed++;
        return [];
      }
      try {
        const raw = await fetchDoc(csafUrlFor(id, title, base));
        await sleep(delayMs);
        const text = acknowledgementFromCsaf(JSON.parse(raw), id);
        read++;
        if (!text) {
          missing++;
          return [];
        }
        const verdict = classifyAcknowledgement(text, vendorName, brandMarkers);
        if (!verdict.discovery) {
          // Read it, and the prose did not resolve. Still not a null verdict for
          // the advisory: the page's Discovered field may yet answer.
          missing++;
          return [];
        }
        for (const cveId of page.cveIds) resolved.add(cveId);
        return page.cveIds.map((cveId) => ({ ...verdict, cveId, url: page.url }));
      } catch {
        failed++;
        return [];
      }
    },
  );

  return {
    results: settled.flat(),
    remaining: targets.filter((t) => !resolved.has(t.cveId)),
    read,
    missing,
    failed,
  };
}
