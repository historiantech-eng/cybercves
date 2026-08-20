/**
 * Time from a CVE being published to CISA documenting exploitation of it.
 *
 * Aggregated identically at build time and in the browser, for the same reason
 * ./severity.ts is: the server renders the default panel so the page is correct
 * without JS, and the browser re-renders when the vendor filter changes. Two
 * implementations of "count the lags" would eventually disagree, and the
 * disagreement would surface as the chart jumping to different numbers the
 * instant the script loads.
 *
 * WHAT THIS METRIC IS. `kev.date_added` is the day CISA published evidence of
 * exploitation, not the day exploitation began — it lags real attacker activity
 * by an unknown amount and by CISA's own process. Every figure here is therefore
 * an upper bound on the defender's warning and a lower bound on the attacker's
 * head start. The site says so in /methodology; the code says so here because
 * the constant names alone would imply more precision than exists.
 *
 * WHAT IT IS NOT. It cannot separate "the vendor was diligent" from "this
 * product was never a target". A long runway may mean either.
 */

/** One row per (known-exploited CVE, affected product) — Repository.getKevTiming. */
export interface KevTimingRow {
  cve_id: string;
  date_published: string;
  date_added: string;
  ransomware_known: number;
  discovery: string | null;
  vendor_slug: string | null;
  product_slug: string | null;
  product_name: string | null;
  days: number;
}

/**
 * The axis, as bands rather than a linear scale.
 *
 * Lags run 0 to 237 days and cluster hard at zero — 20 of the 51 CVEs we track
 * were exploited on their publication date. A linear axis stacks two thirds of
 * the data on the left edge and spends most of its width on the two outliers. A
 * log axis cannot plot day zero at all, which is the single most important
 * value on the chart.
 *
 * Equal-width bands with linear interpolation inside each one give the crowded
 * region room and keep the tail visible, at the cost of the axis not being
 * proportional — which is why every band is labelled with its own range and the
 * table twin carries the raw numbers.
 */
export const BANDS = [
  { key: 'same-day', label: 'Same day', short: '0', lo: Number.NEGATIVE_INFINITY, hi: 0 },
  { key: 'week', label: '1–7 days', short: '7d', lo: 1, hi: 7 },
  { key: 'month', label: '8–30 days', short: '30d', lo: 8, hi: 30 },
  { key: 'quarter', label: '31–90 days', short: '90d', lo: 31, hi: 90 },
  { key: 'year', label: '91–365 days', short: '1y', lo: 91, hi: 365 },
  { key: 'beyond', label: 'Over a year', short: '1y+', lo: 366, hi: 1095 },
] as const;

export type BandKey = (typeof BANDS)[number]['key'];

/**
 * Minimum observations before a median is shown.
 *
 * Below this the dots are still drawn — each is a real CVE with a real lag, and
 * individually true. The summary is what gets withheld, because a "median" over
 * three points invites being read as this product's typical behaviour when it is
 * three anecdotes. 17 of the 32 products with any KEV entry have exactly one.
 *
 * Same rule and same reasoning as MIN_COVERAGE in DiscoveryBar.astro.
 */
export const MIN_N = 5;

/**
 * Negative lags fold into "same day".
 *
 * CISA occasionally lists a CVE before its record publishes. That is not an
 * error to discard: it means exploitation was documented before disclosure, the
 * worst case this chart can depict, and it belongs at the left edge rather than
 * off the axis.
 */
export function bandOf(days: number): BandKey {
  for (const band of BANDS) {
    if (days <= band.hi) return band.key;
  }
  return 'beyond';
}

/**
 * Horizontal position, 0-100, for a dot on the banded axis.
 *
 * Everything at or below zero sits mid-band: the band represents a single value
 * ("no warning at all"), so spreading it would imply a precision the band does
 * not have. Anything past the last band's ceiling clamps to the right edge.
 */
export function bandPosition(days: number): number {
  const width = 100 / BANDS.length;
  const index = BANDS.findIndex((b) => days <= b.hi);
  const i = index === -1 ? BANDS.length - 1 : index;
  const band = BANDS[i];

  const span = band.hi - band.lo;
  const fraction =
    !Number.isFinite(span) || span <= 0
      ? 0.5
      : Math.min(Math.max((days - band.lo) / span, 0), 1);

  return (i + fraction) * width;
}

export interface DotPlacement {
  days: number;
  /** Horizontal position, 0-100. */
  x: number;
  /** How many dots already occupy this position; the chart stacks upward by it. */
  stack: number;
}

/**
 * Place every observation, stacking coincident ones vertically.
 *
 * Without this the chart lies by omission. 20 of the 51 CVEs we track were
 * exploited on their publication date, so they share an exact position and draw
 * as one dot — a reader sees a single mark where the chart's most important
 * finding is that there are twenty. Stacking is also why the marks are dots and
 * not a density curve: at these counts every observation can simply be shown.
 *
 * Positions are bucketed to the half-percent before stacking, so dots that are
 * merely near each other (and would overlap visually) stack too, rather than
 * smearing into an unreadable clump.
 */
export function layoutDots(days: readonly number[]): DotPlacement[] {
  const occupancy = new Map<number, number>();
  return [...days]
    .sort((a, b) => a - b)
    .map((d) => {
      const x = bandPosition(d);
      const slot = Math.round(x * 2) / 2;
      const stack = occupancy.get(slot) ?? 0;
      occupancy.set(slot, stack + 1);
      return { days: d, x, stack };
    });
}

/** Deepest stack in a set of placements — the chart sizes its rows from this. */
export function maxStack(dots: readonly DotPlacement[]): number {
  return dots.reduce((max, d) => Math.max(max, d.stack + 1), 0);
}

/** Median, or null for an empty set. Even-length sets average the middle pair. */
export function median(days: readonly number[]): number | null {
  if (!days.length) return null;
  const sorted = [...days].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

export interface KevSeries {
  key: string;
  label: string;
  n: number;
  /** Every observation, ascending. The chart plots these directly. */
  days: number[];
  counts: Record<BandKey, number>;
  /** Withheld below MIN_N — see the constant. */
  median: number | null;
  /** True when a median exists but is being withheld, so the UI can say why. */
  suppressed: boolean;
}

export type Dimension = 'vendor' | 'product' | 'discovery';

const DISCOVERY_LABEL: Record<string, string> = {
  INTERNAL: 'Vendor found it',
  EXTERNAL: 'Third party',
  USER: 'Customer reported',
  UNKNOWN: 'Unknown',
  UNDISCLOSED: 'Not disclosed',
};

/** Fixed display order — an ordered scale, not a set, so it never re-sorts. */
const DISCOVERY_ORDER = ['INTERNAL', 'EXTERNAL', 'USER', 'UNKNOWN', 'UNDISCLOSED'];

const emptyCounts = (): Record<BandKey, number> => ({
  'same-day': 0,
  week: 0,
  month: 0,
  quarter: 0,
  year: 0,
  beyond: 0,
});

export interface AggregateOptions {
  /** Restrict to one vendor. Only meaningful for the product dimension. */
  vendorSlug?: string;
  /** Display names by slug, for vendor series. Products carry their own. */
  labels?: Readonly<Record<string, string>>;
}

/**
 * One series per vendor, product, or discovery channel.
 *
 * THE DEDUPE IS THE POINT. getKevTiming returns one row per (CVE, product), so
 * a CVE affecting five SKUs arrives five times. For the vendor and discovery
 * views that CVE is one vulnerability and must be counted once, or a single
 * widely-scoped CVE would drag a vendor's whole distribution toward its own lag.
 * For the product view counting it in each product is correct — it really is a
 * vulnerability in each — which is why per-product counts sum to more than the
 * vendor total, exactly as aggregateSeverityBy's grouped totals do.
 */
export function aggregateBy(
  rows: readonly KevTimingRow[],
  dimension: Dimension,
  options: AggregateOptions = {},
): KevSeries[] {
  const { vendorSlug, labels = {} } = options;
  const groups = new Map<string, { label: string; days: number[] }>();
  // Only consulted for the deduped dimensions; the product view wants every row.
  const seen = new Set<string>();

  for (const row of rows) {
    if (vendorSlug && row.vendor_slug !== vendorSlug) continue;

    let key: string | null;
    let label: string;

    if (dimension === 'vendor') {
      key = row.vendor_slug;
      label = key ? (labels[key] ?? key) : '';
    } else if (dimension === 'product') {
      key = row.product_slug;
      label = row.product_name ?? key ?? '';
    } else {
      key = (row.discovery ?? 'UNDISCLOSED').toUpperCase();
      if (!DISCOVERY_LABEL[key]) key = 'UNKNOWN';
      label = DISCOVERY_LABEL[key];
    }

    // A CVE we track but have not mapped to a product has no vendor and no
    // product; it still counts in the discovery view, which needs no mapping.
    if (!key) continue;

    if (dimension !== 'product') {
      const dedupe = `${key}::${row.cve_id}`;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);
    }

    let group = groups.get(key);
    if (!group) {
      group = { label, days: [] };
      groups.set(key, group);
    }
    group.days.push(row.days);
  }

  const series: KevSeries[] = [...groups.entries()].map(([key, { label, days }]) => {
    const counts = emptyCounts();
    for (const d of days) counts[bandOf(d)]++;
    return {
      key,
      label,
      n: days.length,
      days: [...days].sort((a, b) => a - b),
      counts,
      median: days.length >= MIN_N ? median(days) : null,
      suppressed: days.length > 0 && days.length < MIN_N,
    };
  });

  // Products sort alphabetically: a stable list that does not reshuffle when the
  // data refreshes, and — unlike sorting by median — one that cannot imply a
  // ranking among the many products holding a single observation.
  if (dimension === 'product') {
    return series.sort((a, b) => a.label.localeCompare(b.label));
  }
  if (dimension === 'discovery') {
    return series.sort((a, b) => DISCOVERY_ORDER.indexOf(a.key) - DISCOVERY_ORDER.indexOf(b.key));
  }
  return series.sort((a, b) => b.n - a.n || a.label.localeCompare(b.label));
}

/** Distinct CVEs behind a set of rows, for stating a panel's denominator. */
export function countCves(rows: readonly KevTimingRow[]): number {
  return new Set(rows.map((r) => r.cve_id)).size;
}

/** Bands worth drawing, in fixed order, empty ones dropped. */
export function bandsPresent(series: readonly KevSeries[]) {
  return BANDS.filter((band) => series.some((s) => s.counts[band.key] > 0));
}

/**
 * "0 — same day", "7 days", "237 days". Used in the KEV table, where the number
 * alone reads as a bare integer with no unit and 0 reads as missing data.
 */
export function formatLag(days: number | null | undefined): string {
  if (days == null) return '—';
  if (days <= 0) return '0 — same day';
  return `${days.toLocaleString()} ${days === 1 ? 'day' : 'days'}`;
}
