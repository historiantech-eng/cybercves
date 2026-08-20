import { describe, expect, it } from 'vitest';
import { aggregateBy } from '../src/lib/kev-timing';
import type { KevTimingRow } from '../src/lib/kev-timing';
import { renderRunway } from '../src/lib/kev-runway-html';

/**
 * The renderer is a string builder, which makes two things worth pinning: that
 * it escapes what it interpolates, and that the year-over-year comparison keeps
 * every series from BOTH cohorts. The second is the one that matters most --
 * a product that stopped being exploited is what improvement looks like, and an
 * earlier version dropped those rows silently by iterating only the current year.
 */

const row = (over: Partial<KevTimingRow> = {}): KevTimingRow => ({
  cve_id: 'CVE-2026-0001',
  date_published: '2026-01-01T00:00:00.000Z',
  published_year: 2026,
  date_added: '2026-01-01',
  ransomware_known: 0,
  discovery: 'EXTERNAL',
  vendor_slug: 'cisco',
  product_slug: 'p-one',
  product_name: 'Product One',
  category_slug: 'firewall',
  category_name: 'Firewall',
  days: 0,
  ...over,
});

const rows = [
  row({ cve_id: 'a', published_year: 2026, product_slug: 'stayed', product_name: 'Stayed' }),
  row({ cve_id: 'b', published_year: 2026, product_slug: 'arrived', product_name: 'Arrived' }),
  row({ cve_id: 'c', published_year: 2025, product_slug: 'stayed', product_name: 'Stayed' }),
  row({ cve_id: 'd', published_year: 2025, product_slug: 'departed', product_name: 'Departed' }),
];

const compared = () =>
  renderRunway({
    series: aggregateBy(rows, 'product', { year: 2026 }),
    compare: aggregateBy(rows, 'product', { year: 2025 }),
    currentLabel: '2026',
    compareLabel: '2025',
    caption: 'Product',
  });

describe('renderRunway', () => {
  it('renders a series that exists only in the earlier cohort', () => {
    const html = compared();
    expect(html).toContain('Departed');
    expect(html).toContain('Arrived');
    expect(html).toContain('Stayed');
    expect((html.match(/class="runway-row"/g) ?? []).length).toBe(3);
  });

  it('shows the departed series as zero this year rather than as missing data', () => {
    const html = compared();
    const departed = html.slice(html.indexOf('Departed'));
    // Its own count is n=0 while the previous cohort's bar is still drawn.
    expect(departed).toContain('n=0');
    expect(departed).toContain('is-prev');
  });

  it('omits the legend and the previous bars when not comparing', () => {
    const html = renderRunway({
      series: aggregateBy(rows, 'product', { year: 2026 }),
      caption: 'Product',
    });
    expect(html).not.toContain('runway-legend');
    expect(html).not.toContain('is-prev');
  });

  it('keeps bars and axis on one column template', () => {
    // Alignment is structural: if these ever differ, labels drift off their bars.
    const html = compared();
    const cols = html.match(/--runway-cols: repeat\((\d+), 1fr\)/);
    const ticks = (html.match(/class="runway-tick"/g) ?? []).length;
    expect(cols).not.toBeNull();
    expect(Number(cols![1])).toBe(ticks);
  });

  it('escapes a label rather than emitting it as markup', () => {
    const hostile = rows.map((r) => ({ ...r, product_name: '<img src=x onerror=alert(1)>' }));
    const html = renderRunway({
      series: aggregateBy(hostile, 'product', { year: 2026 }),
      caption: 'Product',
    });
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x');
  });

  it('says so plainly when a selection has nothing in it', () => {
    expect(renderRunway({ series: [], caption: 'Product' })).toContain('No exploited CVEs');
  });
});
