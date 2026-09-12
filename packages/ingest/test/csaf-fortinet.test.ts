import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  acknowledgementFromCsaf,
  csafUrlFor,
  CsafMismatchError,
  fetchCsafAcknowledgements,
  parseRssAdvisoryTitles,
} from '../src/sources/csaf-fortinet.js';

const read = (name: string) =>
  readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf8');

/** Real documents, as served by filestore.fortinet.com on 2026-09-12. */
const internalDoc = JSON.parse(read('fortinet-FG-IR-26-166.csaf.json'));
const externalDoc = JSON.parse(read('fortinet-FG-IR-26-165.csaf.json'));
const rss = read('fortinet-ir-rss.xml');

describe('parseRssAdvisoryTitles', () => {
  it('maps advisory ids to titles', () => {
    const titles = parseRssAdvisoryTitles(rss);
    expect(titles.get('FG-IR-26-166')).toBe(
      'Unauthenticated Control of NAT Rules Leading to Exposure of Sensitive Information',
    );
    expect(titles.get('FG-IR-26-165')).toBe(
      'Arbitrary process termination from exposed minifilter communication port',
    );
  });

  it('returns an empty map rather than throwing on junk', () => {
    expect(parseRssAdvisoryTitles('<rss><channel></channel></rss>').size).toBe(0);
  });
});

describe('csafUrlFor', () => {
  it('reproduces the filename Fortinet actually publishes', () => {
    // Pinned against the real URL. There is no CSAF index, so this derivation is
    // the only way to reach a document — if Fortinet changes the convention this
    // test is where it should be noticed.
    expect(
      csafUrlFor(
        'FG-IR-26-166',
        'Unauthenticated Control of NAT Rules Leading to Exposure of Sensitive Information',
      ),
    ).toBe(
      'https://filestore.fortinet.com/fortiguard/psirt/' +
        'csaf_unauthenticated-control-of-nat-rules-leading-to-exposure-of-sensitive-information_fg-ir-26-166.json',
    );
  });

  it('collapses punctuation and trims stray separators', () => {
    expect(csafUrlFor('FG-IR-26-1', 'A "quoted" title: part two!', 'https://x/')).toBe(
      'https://x/csaf_a-quoted-title-part-two_fg-ir-26-1.json',
    );
  });
});

describe('acknowledgementFromCsaf', () => {
  it('reads the credit out of a real document', () => {
    expect(acknowledgementFromCsaf(internalDoc, 'FG-IR-26-166')).toBe(
      'Internally discovered and reported by Adham El karn of Fortinet Product Security team.',
    );
    expect(acknowledgementFromCsaf(externalDoc, 'FG-IR-26-165')).toContain('Robel Campbell');
  });

  it('refuses a document for a different advisory', () => {
    // The guard that makes a derived filename safe to trust. A wrong guess that
    // happened to hit a real file would credit one advisory's finder on another
    // CVE — a false statement about a named person, published as fact.
    expect(() => acknowledgementFromCsaf(internalDoc, 'FG-IR-26-999')).toThrow(CsafMismatchError);
  });

  it('returns null — not a throw — when a valid document credits nobody', () => {
    const doc = { document: { tracking: { id: 'FG-IR-26-1' }, acknowledgments: [] } };
    expect(acknowledgementFromCsaf(doc, 'FG-IR-26-1')).toBeNull();
  });

  it('falls back to names and organization if summary is absent', () => {
    const doc = {
      document: {
        tracking: { id: 'FG-IR-26-1' },
        acknowledgments: [{ names: ['Ada L.', 'Grace H.'], organization: 'Acme Labs' }],
      },
    };
    expect(acknowledgementFromCsaf(doc, 'FG-IR-26-1')).toBe('Ada L., Grace H. of Acme Labs');
  });
});

describe('fetchCsafAcknowledgements', () => {
  const titles = parseRssAdvisoryTitles(rss);
  const targets = [
    { cveId: 'CVE-2026-26084', url: 'https://www.fortiguard.com/psirt/FG-IR-26-166' },
    { cveId: 'CVE-2026-84386', url: 'https://www.fortiguard.com/psirt/FG-IR-26-165' },
  ];

  it('classifies both real documents and leaves nothing behind', async () => {
    const run = await fetchCsafAcknowledgements(targets, {
      titles,
      delayMs: 0,
      brandMarkers: ['FortiGuard'],
      fetchDoc: async (url) =>
        url.includes('fg-ir-26-166') ? JSON.stringify(internalDoc) : JSON.stringify(externalDoc),
    });

    expect(run.results).toHaveLength(2);
    expect(run.remaining).toEqual([]);
    expect(run.results.find((r) => r.cveId === 'CVE-2026-26084')?.discovery).toBe('INTERNAL');
    expect(run.results.find((r) => r.cveId === 'CVE-2026-84386')?.discovery).toBe('EXTERNAL');
    // The prose is kept verbatim so a reader can audit the classification.
    expect(run.results[0]?.creditText).toContain('Adham El karn');
  });

  it('hands an advisory missing from the feed to the caller untouched', async () => {
    // Older than the 50-item RSS window. Not readable by this source, and — the
    // point — not evidence that the advisory credits nobody.
    const run = await fetchCsafAcknowledgements(
      [{ cveId: 'CVE-2025-59921', url: 'https://www.fortiguard.com/psirt/FG-IR-23-434' }],
      { titles, delayMs: 0, fetchDoc: async () => { throw new Error('should not be fetched'); } },
    );

    expect(run.results).toEqual([]);
    expect(run.failed).toBe(1);
    expect(run.remaining.map((t) => t.cveId)).toEqual(['CVE-2025-59921']);
  });

  it('hands a 404 to the caller rather than calling it uncredited', async () => {
    const run = await fetchCsafAcknowledgements(targets, {
      titles,
      delayMs: 0,
      fetchDoc: async () => {
        throw new Error('404');
      },
    });

    expect(run.results).toEqual([]);
    expect(run.failed).toBe(2);
    expect(run.remaining).toHaveLength(2);
  });

  it('hands a document that credits nobody to the caller too', async () => {
    // CSAF omits the advisory page's labelled Discovered field, so "no
    // acknowledgement here" is not "no attribution anywhere". It must stay
    // eligible for the scrape rather than going straight to the backoff.
    const run = await fetchCsafAcknowledgements([targets[0]!], {
      titles,
      delayMs: 0,
      fetchDoc: async () =>
        JSON.stringify({ document: { tracking: { id: 'FG-IR-26-166' }, acknowledgments: [] } }),
    });

    expect(run.results).toEqual([]);
    expect(run.missing).toBe(1);
    expect(run.remaining).toHaveLength(1);
  });

  it('fetches one document per advisory, not one per CVE', async () => {
    const urls: string[] = [];
    const run = await fetchCsafAcknowledgements(
      [
        { cveId: 'CVE-A', url: 'https://www.fortiguard.com/psirt/FG-IR-26-166' },
        { cveId: 'CVE-B', url: 'https://www.fortiguard.com/psirt/FG-IR-26-166' },
      ],
      {
        titles,
        delayMs: 0,
        brandMarkers: ['FortiGuard'],
        fetchDoc: async (url) => {
          urls.push(url);
          return JSON.stringify(internalDoc);
        },
      },
    );

    expect(urls).toHaveLength(1);
    expect(run.results.map((r) => r.cveId).sort()).toEqual(['CVE-A', 'CVE-B']);
  });
});
