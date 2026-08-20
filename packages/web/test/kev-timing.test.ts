import { describe, expect, it } from 'vitest';
import {
  MIN_N,
  aggregateBy,
  bandOf,
  countCves,
  formatLag,
  median,
} from '../src/lib/kev-timing';
import type { KevTimingRow } from '../src/lib/kev-timing';

/**
 * The rules that decide what the runway charts claim.
 *
 * Two of these are the reason the module exists rather than the arithmetic
 * living in the page: the CVE-counted-once invariant, which a widely-scoped CVE
 * would otherwise use to drag a whole vendor's distribution, and the MIN_N
 * withholding, which is what keeps a product with one exploited CVE from
 * publishing a "median" about a named company's product.
 */

const row = (over: Partial<KevTimingRow> = {}): KevTimingRow => ({
  cve_id: 'CVE-2026-0001',
  date_published: '2026-01-01T00:00:00.000Z',
  date_added: '2026-01-01',
  ransomware_known: 0,
  discovery: 'EXTERNAL',
  vendor_slug: 'cisco',
  product_slug: 'cisco-asa',
  product_name: 'Cisco ASA',
  days: 0,
  ...over,
});

describe('bands', () => {
  it('puts each boundary value in the band that names it', () => {
    expect(bandOf(0)).toBe('same-day');
    expect(bandOf(1)).toBe('week');
    expect(bandOf(7)).toBe('week');
    expect(bandOf(8)).toBe('month');
    expect(bandOf(30)).toBe('month');
    expect(bandOf(31)).toBe('quarter');
    expect(bandOf(90)).toBe('quarter');
    expect(bandOf(91)).toBe('year');
    expect(bandOf(365)).toBe('year');
    expect(bandOf(366)).toBe('beyond');
    expect(bandOf(5000)).toBe('beyond');
  });

  it('folds a negative lag into same-day rather than off the scale', () => {
    // CISA can list a CVE before its record publishes. That is the worst case
    // this chart depicts, so it must land in the first bucket, not vanish.
    expect(bandOf(-4)).toBe('same-day');
  });
});

describe('median', () => {
  it('averages the middle pair on an even-length set', () => {
    expect(median([0, 1, 2, 7])).toBe(1.5);
    expect(median([0, 0, 0, 0, 0, 0, 1, 1, 2, 7, 35, 37, 66, 93, 167, 237])).toBe(1.5);
  });

  it('takes the middle value on an odd-length set', () => {
    expect(median([5, 1, 9])).toBe(5);
  });

  it('returns null for nothing rather than zero', () => {
    // Zero is a real and meaningful lag here, so it must never stand in for
    // "no data" — the two would be indistinguishable on the chart.
    expect(median([])).toBeNull();
  });
});

describe('bucket counts', () => {
  it('tallies each observation into exactly one bucket', () => {
    const days = [0, 0, -2, 1, 7, 8, 30, 31, 90, 91, 365, 400];
    const rows = days.map((d, i) => row({ cve_id: `CVE-2026-${i}`, days: d }));
    const [series] = aggregateBy(rows, 'vendor');

    expect(series.counts).toEqual({
      'same-day': 3,
      week: 2,
      month: 2,
      quarter: 2,
      year: 2,
      beyond: 1,
    });
    // The bars must account for every CVE in the row's own n, or the chart is
    // quietly dropping observations the label claims are there.
    const summed = Object.values(series.counts).reduce((a, b) => a + b, 0);
    expect(summed).toBe(series.n);
    expect(summed).toBe(days.length);
  });

  it('reports which bucket the median falls in, and none when it is withheld', () => {
    const many = Array.from({ length: 9 }, (_, i) =>
      row({ cve_id: `CVE-2026-2${i}`, days: i < 5 ? 0 : 200 }),
    );
    const [shown] = aggregateBy(many, 'vendor');
    expect(shown.median).toBe(0);
    expect(shown.medianBand).toBe('same-day');

    const [withheld] = aggregateBy([row({ days: 40 })], 'vendor');
    expect(withheld.median).toBeNull();
    expect(withheld.medianBand).toBeNull();
  });
});

describe('aggregateBy', () => {
  it('counts a multi-product CVE once for its vendor, not once per product', () => {
    // The invariant. getKevTiming emits one row per (CVE, product), so a CVE
    // affecting five SKUs arrives five times; counting them all would let one
    // widely-scoped CVE pull a vendor's whole distribution toward its own lag.
    const rows = ['a', 'b', 'c', 'd', 'e'].map((p) =>
      row({ product_slug: `cisco-${p}`, product_name: `Cisco ${p}`, days: 40 }),
    );
    const [vendor] = aggregateBy(rows, 'vendor');
    expect(vendor.n).toBe(1);
    expect(vendor.days).toEqual([40]);

    const [discovery] = aggregateBy(rows, 'discovery');
    expect(discovery.n).toBe(1);

    // ...but each product genuinely does carry the vulnerability.
    expect(aggregateBy(rows, 'product')).toHaveLength(5);
  });

  it('withholds the median below MIN_N and reports why', () => {
    const under = Array.from({ length: MIN_N - 1 }, (_, i) =>
      row({ cve_id: `CVE-2026-000${i}`, days: i }),
    );
    const [series] = aggregateBy(under, 'vendor');
    expect(series.n).toBe(MIN_N - 1);
    expect(series.median).toBeNull();
    expect(series.suppressed).toBe(true);
    // The observations themselves are still published — each is individually true.
    expect(series.days).toHaveLength(MIN_N - 1);
  });

  it('publishes the median at exactly MIN_N', () => {
    const at = Array.from({ length: MIN_N }, (_, i) => row({ cve_id: `CVE-2026-100${i}`, days: 2 }));
    const [series] = aggregateBy(at, 'vendor');
    expect(series.median).toBe(2);
    expect(series.suppressed).toBe(false);
  });

  it('sorts products alphabetically, not by median or count', () => {
    // Sorting by median would rank the many single-observation products against
    // each other, which is exactly the reading MIN_N exists to prevent.
    const rows = [
      row({ cve_id: 'CVE-2026-1', product_slug: 'z', product_name: 'Zulu', days: 300 }),
      row({ cve_id: 'CVE-2026-2', product_slug: 'a', product_name: 'Alpha', days: 0 }),
      row({ cve_id: 'CVE-2026-3', product_slug: 'a', product_name: 'Alpha', days: 1 }),
      row({ cve_id: 'CVE-2026-4', product_slug: 'm', product_name: 'Mike', days: 5 }),
    ];
    expect(aggregateBy(rows, 'product').map((s) => s.label)).toEqual(['Alpha', 'Mike', 'Zulu']);
  });

  it('scopes the product view to one vendor', () => {
    const rows = [
      row({ vendor_slug: 'cisco', product_slug: 'c1', product_name: 'C One' }),
      row({ cve_id: 'CVE-2026-9', vendor_slug: 'fortinet', product_slug: 'f1', product_name: 'F One' }),
    ];
    const scoped = aggregateBy(rows, 'product', { vendorSlug: 'fortinet' });
    expect(scoped.map((s) => s.label)).toEqual(['F One']);
  });

  it('keeps a product-less CVE in the discovery view but out of vendor and product', () => {
    // CVE-2025-32433 is exactly this today: tracked and exploited, not yet
    // mapped to a product. Dropping it from the discovery panel would make the
    // page disagree with the CVE table about how many exploited CVEs there are.
    const rows = [row({ vendor_slug: null, product_slug: null, product_name: null, days: 8 })];
    expect(aggregateBy(rows, 'discovery')[0]?.n).toBe(1);
    expect(aggregateBy(rows, 'vendor')).toHaveLength(0);
    expect(aggregateBy(rows, 'product')).toHaveLength(0);
  });

  it('files an unattributed CVE as not disclosed, and an unrecognised value as unknown', () => {
    const rows = [
      row({ cve_id: 'CVE-2026-1', discovery: null }),
      row({ cve_id: 'CVE-2026-2', discovery: 'SOMETHING-NEW' }),
    ];
    const keys = aggregateBy(rows, 'discovery').map((s) => s.key);
    expect(keys).toContain('UNDISCLOSED');
    expect(keys).toContain('UNKNOWN');
  });

  it('holds the discovery channels in a fixed order regardless of size', () => {
    const rows = [
      row({ cve_id: 'CVE-2026-1', discovery: 'USER' }),
      row({ cve_id: 'CVE-2026-2', discovery: 'INTERNAL' }),
      row({ cve_id: 'CVE-2026-3', discovery: 'INTERNAL' }),
      row({ cve_id: 'CVE-2026-4', discovery: 'EXTERNAL' }),
    ];
    expect(aggregateBy(rows, 'discovery').map((s) => s.key)).toEqual([
      'INTERNAL',
      'EXTERNAL',
      'USER',
    ]);
  });

  it('counts distinct CVEs for a panel denominator', () => {
    const rows = [
      row({ cve_id: 'CVE-2026-1', product_slug: 'a' }),
      row({ cve_id: 'CVE-2026-1', product_slug: 'b' }),
      row({ cve_id: 'CVE-2026-2', product_slug: 'a' }),
    ];
    expect(countCves(rows)).toBe(2);
  });
});

describe('formatLag', () => {
  it('never renders a bare zero', () => {
    // "0" in a table cell reads as missing data. It is the most severe value here.
    expect(formatLag(0)).toBe('0 — same day');
    expect(formatLag(-3)).toBe('0 — same day');
  });

  it('carries a unit and agrees in number', () => {
    expect(formatLag(1)).toBe('1 day');
    expect(formatLag(237)).toBe('237 days');
  });

  it('distinguishes absent from zero', () => {
    expect(formatLag(null)).toBe('—');
    expect(formatLag(undefined)).toBe('—');
  });
});
