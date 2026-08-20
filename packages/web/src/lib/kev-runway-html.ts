import { BANDS, MIN_N, bandsPresent, formatLag } from './kev-timing';
import type { BandKey, KevSeries } from './kev-timing';

/**
 * Markup for the runway histogram, as a string.
 *
 * ONE implementation, used twice: the Astro component emits it with `set:html`
 * at build time, and the browser assigns it to innerHTML when a filter changes.
 * The alternative — an .astro template for the server and a JS template for the
 * client — is two renderers that must be kept identical by hand, and the way
 * that fails is the chart quietly changing shape the moment the script loads.
 * SeverityChart.astro carries that duplication; this does not.
 *
 * Returned HTML is assembled from data, so every interpolated value is escaped.
 */

const esc = (v: string): string =>
  v.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string,
  );

export interface RunwayView {
  series: KevSeries[];
  /**
   * The same dimension aggregated over the previous cohort, matched by `key`.
   * A series present in one year and absent from the other still renders — a
   * product that stopped appearing in KEV is a result, not a gap to hide.
   */
  compare?: KevSeries[] | null;
  /** Legend labels for the two cohorts, e.g. "2026" and "2025". */
  currentLabel?: string;
  compareLabel?: string;
  /** Heading for the first column of the table twin. */
  caption: string;
  note?: string;
}

/**
 * A zero-count stand-in for a series that exists only in the other cohort, so
 * the row renders with empty bars instead of disappearing.
 */
function emptyLike(s: KevSeries): KevSeries {
  return {
    key: s.key,
    label: s.label,
    n: 0,
    days: [],
    counts: { 'same-day': 0, week: 0, month: 0, quarter: 0, year: 0, beyond: 0 },
    median: null,
    suppressed: false,
  };
}

/** Bars scale against the tallest bar in the panel — see KevRunway.astro. */
function peakOf(series: readonly KevSeries[], compare: readonly KevSeries[], bands: BandKey[]) {
  const all = [...series, ...compare];
  return Math.max(1, ...all.flatMap((s) => bands.map((b) => s.counts[b])));
}

function medianText(s: KevSeries): string {
  if (s.median === null) {
    return `<span class="muted" title="Withheld below ${MIN_N} observations">—</span>`;
  }
  return esc(formatLag(s.median));
}

function ariaFor(s: KevSeries, bands: typeof BANDS[number][]): string {
  const buckets = bands.map((b) => `${b.label}: ${s.counts[b.key]}`).join(', ');
  const med =
    s.median === null
      ? 'Median withheld, too few observations.'
      : s.median <= 0
        ? 'Median zero days: typically exploited on the day of disclosure.'
        : `Median ${s.median} ${s.median === 1 ? 'day' : 'days'}.`;
  return `${s.label}: ${s.n} exploited ${s.n === 1 ? 'CVE' : 'CVEs'} — ${buckets}. ${med}`;
}

export function renderRunway(view: RunwayView): string {
  const { series, compare = null, currentLabel = '', compareLabel = '', caption, note } = view;

  if (!series.length && !(compare && compare.length)) {
    return '<p class="empty">No exploited CVEs on record for this selection.</p>';
  }

  const compareSeries = compare ?? [];
  const byKey = new Map(compareSeries.map((s) => [s.key, s]));

  /**
   * Rows are the UNION of both cohorts, not just the current one.
   *
   * A product that was exploited last year and not this year is the single most
   * useful thing this comparison can show — it is what improvement looks like —
   * and iterating only the current cohort would silently drop it. The missing
   * side renders as an all-zero series so the row still appears with its bars
   * empty, which reads as "none this year" rather than as absent data.
   */
  const rowSeries: KevSeries[] = [
    ...series,
    ...compareSeries.filter((s) => !series.some((c) => c.key === s.key)).map(emptyLike),
  ];
  // Bands are chosen across both cohorts, so a bucket that only the earlier year
  // reaches keeps its column and the two years stay on one shared axis.
  const bands = bandsPresent([...rowSeries, ...compareSeries]);
  const shown = bands.length ? bands : [BANDS[0]];
  const keys = shown.map((b) => b.key);
  const peak = peakOf(rowSeries, compareSeries, keys);
  const columns = `repeat(${shown.length}, 1fr)`;

  const rows = rowSeries
    .map((s) => {
      const prev = byKey.get(s.key) ?? null;
      const cols = shown
        .map((band) => {
          const n = s.counts[band.key];
          const p = prev ? prev.counts[band.key] : null;
          const title =
            p === null
              ? `${band.label}: ${n} of ${s.n}`
              : `${band.label} — ${currentLabel}: ${n}, ${compareLabel}: ${p}`;
          const bars =
            `<span class="runway-bar" style="height: ${(n / peak) * 100}%"${
              n === 0 ? ' data-empty' : ''
            }></span>` +
            (p === null
              ? ''
              : `<span class="runway-bar is-prev" style="height: ${(p / peak) * 100}%"${
                  p === 0 ? ' data-empty' : ''
                }></span>`);
          const label = p === null ? String(n || '') : `${n || 0}<span class="runway-prev">${p}</span>`;
          return (
            `<div class="runway-col${s.medianBand === band.key ? ' is-median' : ''}" title="${esc(title)}">` +
            `<span class="runway-count">${label}</span>` +
            `<span class="runway-pair">${bars}</span>` +
            `</div>`
          );
        })
        .join('');

      return (
        `<div class="runway-row">` +
        `<div class="runway-name">${esc(s.label)}<span class="runway-n"> n=${s.n}</span></div>` +
        `<div class="runway-bars" role="img" aria-label="${esc(ariaFor(s, shown))}">${cols}</div>` +
        `<div class="runway-median-value">${medianText(s)}</div>` +
        `</div>`
      );
    })
    .join('');

  const axis =
    `<div class="runway-axis-row"><div></div><div class="runway-axis">` +
    shown.map((b) => `<span class="runway-tick">${esc(b.label)}</span>`).join('') +
    `</div><div class="runway-axis-caption muted">median</div></div>`;

  const legend =
    compare === null
      ? ''
      : `<ul class="runway-legend"><li><span class="runway-key"></span>${esc(
          currentLabel,
        )}</li><li><span class="runway-key is-prev"></span>${esc(compareLabel)}</li></ul>`;

  const suppressed = series.some((s) => s.suppressed)
    ? `<p class="runway-note muted small">A dash means the median is withheld: fewer than ${MIN_N} exploited CVEs, where a median reads as typical behaviour but is a handful of individual cases. The counts themselves are exact.</p>`
    : '';

  const noteHtml = note ? `<p class="runway-note muted small">${esc(note)}</p>` : '';

  return (
    `<div class="runway" style="--runway-cols: ${columns}">` +
    legend +
    rows +
    axis +
    suppressed +
    noteHtml +
    renderTable(rowSeries, byKey, shown, caption, currentLabel, compareLabel, compare !== null) +
    `</div>`
  );
}

function renderTable(
  series: readonly KevSeries[],
  byKey: ReadonlyMap<string, KevSeries>,
  shown: typeof BANDS[number][],
  caption: string,
  currentLabel: string,
  compareLabel: string,
  comparing: boolean,
): string {
  if (!series.length) return '';
  const total = series.reduce((sum, s) => sum + s.n, 0);

  const head =
    `<tr><th scope="col">${esc(caption)}</th>` +
    (comparing ? '<th scope="col">Cohort</th>' : '') +
    shown.map((b) => `<th scope="col" class="num">${esc(b.label)}</th>`).join('') +
    `<th scope="col" class="num">Total</th><th scope="col" class="num">Median</th></tr>`;

  const bodyRow = (s: KevSeries, label: string, rowspan: number | null) =>
    `<tr>` +
    (rowspan === null
      ? ''
      : `<th scope="row"${rowspan > 1 ? ` rowspan="${rowspan}"` : ''}>${esc(s.label)}</th>`) +
    (comparing ? `<td class="small muted">${esc(label)}</td>` : '') +
    shown.map((b) => `<td class="num">${s.counts[b.key].toLocaleString()}</td>`).join('') +
    `<td class="num">${s.n.toLocaleString()}</td>` +
    `<td class="num">${s.median !== null ? s.median.toLocaleString() : '—'}</td>` +
    `</tr>`;

  const body = series
    .map((s) => {
      const prev = byKey.get(s.key);
      if (!comparing) return bodyRow(s, '', 1);
      return (
        bodyRow(s, currentLabel, prev ? 2 : 1) + (prev ? bodyRow(prev, compareLabel, null) : '')
      );
    })
    .join('');

  return (
    `<details class="runway-table"><summary>Table view</summary>` +
    `<div class="table-scroll"><table><caption class="sr-only">${esc(caption)}</caption>` +
    `<thead>${head}</thead><tbody>${body}</tbody></table></div>` +
    `<p class="muted small">${total.toLocaleString()} observations. Buckets are calendar days ` +
    `from the CVE record publishing to CISA listing it as exploited.</p></details>`
  );
}
