import type { CveRow } from './cve-rows';

/**
 * Severity distribution, aggregated identically at build time and in the browser.
 *
 * Sharing one function is the point: the server renders the default view so the
 * page is correct without JS, and the browser re-renders on filter changes. Two
 * implementations of "count the severities" would eventually disagree, and the
 * disagreement would show up as the chart flickering to different numbers the
 * moment the script loads.
 */

/** Display order, worst first. Fixed — this is an ordered scale, not a set. */
export const SEVERITY_BUCKETS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNSCORED'] as const;
export type SeverityBucket = (typeof SEVERITY_BUCKETS)[number];

/**
 * Status token per bucket. Matches `severityToken()` in ./data so the chart, the
 * CVE badges and the table all wear the same colour for the same word.
 *
 * These are the reserved status steps and are deliberately NOT re-stepped: the
 * scale is fixed by design, and High↔Medium are close enough in normal vision
 * that the label — never the fill alone — is what identifies a segment.
 */
export const BUCKET_TOKEN: Record<SeverityBucket, string> = {
  CRITICAL: 'critical',
  HIGH: 'serious',
  MEDIUM: 'warning',
  LOW: 'good',
  UNSCORED: 'unknown',
};

export const BUCKET_LABEL: Record<SeverityBucket, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  UNSCORED: 'Unscored',
};

export interface SeverityCounts {
  total: number;
  counts: Record<SeverityBucket, number>;
}

export interface SeverityGroup extends SeverityCounts {
  key: string;
  label: string;
}

/**
 * `NONE` and a missing severity both fold into UNSCORED.
 *
 * Dropping them instead would make the segments sum to less than the result
 * count beside them, which reads as a bug in the chart rather than as a gap in
 * the data. /methodology already explains that unscored records are treated as
 * LOW for risk and are not imputed a severity.
 */
function bucketOf(severity: string | null): SeverityBucket {
  const key = (severity ?? '').toUpperCase();
  return key === 'CRITICAL' || key === 'HIGH' || key === 'MEDIUM' || key === 'LOW'
    ? (key as SeverityBucket)
    : 'UNSCORED';
}

const emptyCounts = (): Record<SeverityBucket, number> => ({
  CRITICAL: 0,
  HIGH: 0,
  MEDIUM: 0,
  LOW: 0,
  UNSCORED: 0,
});

export function aggregateSeverity(rows: readonly CveRow[]): SeverityCounts {
  const counts = emptyCounts();
  for (const row of rows) counts[bucketOf(row.s)]++;
  return { total: rows.length, counts };
}

/**
 * One distribution per vendor or per category.
 *
 * A CVE affecting two vendors counts once under each — the same rule the vendor
 * rollups use, and for the same reason: it is a real vulnerability in each of
 * them. Group totals therefore sum to more than the overall total, which is why
 * the grouped view labels each row with its own total rather than implying a
 * share of one whole.
 */
export function aggregateSeverityBy(
  rows: readonly CveRow[],
  dimension: 'vendor' | 'category',
  labels: Readonly<Record<string, string>> = {},
): SeverityGroup[] {
  const field = dimension === 'vendor' ? 'v' : 'g';
  const groups = new Map<string, Record<SeverityBucket, number>>();
  const totals = new Map<string, number>();

  for (const row of rows) {
    const bucket = bucketOf(row.s);
    // A row can list the same slug twice across products; count the CVE once.
    for (const key of new Set(row[field])) {
      let counts = groups.get(key);
      if (!counts) {
        counts = emptyCounts();
        groups.set(key, counts);
      }
      counts[bucket]++;
      totals.set(key, (totals.get(key) ?? 0) + 1);
    }
  }

  return [...groups.entries()]
    .map(([key, counts]) => ({
      key,
      label: labels[key] ?? key,
      counts,
      total: totals.get(key) ?? 0,
    }))
    .sort((a, b) => b.total - a.total || a.label.localeCompare(b.label));
}

/** Segments worth drawing, in fixed order, zero-count buckets dropped. */
export function segmentsOf(counts: Record<SeverityBucket, number>) {
  return SEVERITY_BUCKETS.filter((b) => counts[b] > 0).map((b) => ({
    bucket: b,
    label: BUCKET_LABEL[b],
    token: BUCKET_TOKEN[b],
    n: counts[b],
  }));
}
