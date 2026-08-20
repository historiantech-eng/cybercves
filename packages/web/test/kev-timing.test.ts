import { describe, expect, it } from 'vitest';
import {
  BANDS,
  MIN_N,
  aggregateBy,
  bandOf,
  bandPosition,
  countCves,
  formatLag,
  layoutDots,
  maxStack,
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

  it('folds a negative lag into same-day rather than off the axis', () => {
    // CISA can list a CVE before its record publishes. That is the worst case
    // this chart depicts, so it must land at the left edge, not vanish.
    expect(bandOf(-4)).toBe('same-day');
    expect(bandPosition(-4)).toBe(bandPosition(0));
  });

  it('keeps positions inside 0-100 and ordered by band', () => {
    const values = [-10, 0, 1, 7, 8, 30, 31, 90, 91, 365, 366, 99999];
    const positions = values.map(bandPosition);
    for (const p of positions) {
      expect(p).toBeGreaterThanOrEqual(0);
      expect(p).toBeLessThanOrEqual(100);
    }
    // Monotonic: a longer runway is never drawn to the left of a shorter one.
    for (let i = 1; i < positions.length; i++) {
      expect(positions[i]).toBeGreaterThanOrEqual(positions[i - 1]);
    }
  });

  it('spreads the whole axis across the declared bands', () => {
    expect(bandPosition(0)).toBeCloseTo(100 / BANDS.length / 2, 5);
    expect(bandPosition(99999)).toBeCloseTo(100, 5);
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

describe('dot layout', () => {
  it('stacks coincident observations instead of drawing them on top of each other', () => {
    const dots = layoutDots([0, 0, 0, 0]);
    expect(dots.map((d) => d.stack)).toEqual([0, 1, 2, 3]);
    expect(new Set(dots.map((d) => d.x)).size).toBe(1);
    expect(maxStack(dots)).toBe(4);
  });

  it('does not stack observations that are far apart', () => {
    const dots = layoutDots([0, 200]);
    expect(dots.every((d) => d.stack === 0)).toBe(true);
  });

  it('returns observations in ascending order', () => {
    expect(layoutDots([200, 0, 30]).map((d) => d.days)).toEqual([0, 30, 200]);
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
    // page disagree with the table above it about how many CVEs there are.
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
