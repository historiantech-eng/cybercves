import { CURRENT_YEAR, db } from './data';

export const SITE = 'https://cybercve.com';

/** Items per feed. Readers poll; fifty covers any sane polling gap. */
export const FEED_LIMIT = 50;

export const escapeXml = (value: string) =>
  value.replace(/[&<>"']/g, (ch) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[ch] as string,
  );

export interface FeedItem {
  title: string;
  link: string;
  guid: string;
  /** Anything `new Date()` accepts; omitted from the item when null. */
  pubDate: string | null;
  description: string;
}

export interface FeedChannel {
  title: string;
  link: string;
  description: string;
  items: FeedItem[];
}

/** Row shape shared by `listCveIndex` and `listKevCves` — what an item needs. */
export interface FeedRow {
  cve_id: string;
  date_published: string | null;
  severity: string | null;
  score: number | null;
  in_kev: number;
  epss: number | null;
  vendors: string | null;
  products: string | null;
}

const list = (value: string | null) => (value ?? '').split(',').filter(Boolean);

/**
 * One CVE as a feed item.
 *
 * `extra` is appended to the description after the exploitation line — the KEV
 * feed uses it to say when CISA listed the CVE, which is that feed's whole news.
 */
export function cveItem(row: FeedRow, options: { pubDate?: string | null; extra?: string } = {}): FeedItem {
  const vendors = list(row.vendors).join(', ');
  return {
    title: `${row.cve_id}${row.severity ? ` — ${row.severity}` : ''}${vendors ? ` (${vendors})` : ''}`,
    link: `${SITE}/cve/${row.cve_id}`,
    guid: `${SITE}/cve/${row.cve_id}`,
    pubDate: options.pubDate === undefined ? row.date_published : options.pubDate,
    description:
      `Severity: ${row.severity ?? 'unscored'}${row.score != null ? ` (${row.score})` : ''}. ` +
      `${row.in_kev === 1 ? 'Listed in CISA KEV. ' : ''}` +
      `${options.extra ?? ''}` +
      `${row.epss != null ? `EPSS ${row.epss.toFixed(3)}. ` : ''}` +
      `Affects: ${list(row.products).join(', ') || 'see advisory'}.`,
  };
}

export function renderFeed(channel: FeedChannel): string {
  const items = channel.items
    .map(
      (item) => `    <item>
      <title>${escapeXml(item.title)}</title>
      <link>${item.link}</link>
      <guid isPermaLink="true">${item.guid}</guid>
      ${item.pubDate ? `<pubDate>${new Date(item.pubDate).toUTCString()}</pubDate>` : ''}
      <description>${escapeXml(item.description)}</description>
    </item>`,
    )
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>${escapeXml(channel.title)}</title>
    <link>${channel.link}</link>
    <description>${escapeXml(channel.description)}</description>
    <language>en-us</language>
    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
${items}
  </channel>
</rss>`;
}

export function feedResponse(channel: FeedChannel): Response {
  return new Response(renderFeed(channel), {
    headers: { 'content-type': 'application/rss+xml; charset=utf-8' },
  });
}

type IndexRow = Awaited<ReturnType<NonNullable<ReturnType<typeof db>>['listCveIndex']>>[number];

let recent: Promise<IndexRow[]> | null = null;

/**
 * This year's and last year's CVEs, newest first, loaded once per build.
 *
 * Two years, not one, so a scoped feed is not empty every January — a product
 * with no CVE yet this year still has a feed worth subscribing to. Memoised
 * because ~200 feed routes each want the same rows.
 */
export function recentRows(): Promise<IndexRow[]> {
  if (!recent) {
    const repo = db();
    recent = repo
      ? Promise.all([repo.listCveIndex(CURRENT_YEAR), repo.listCveIndex(CURRENT_YEAR - 1)]).then(
          ([current, previous]) => [...current, ...previous],
        )
      : Promise.resolve([]);
  }
  return recent;
}

/** Newest rows matching `keep`, as feed items. */
export async function scopedItems(keep: (row: IndexRow) => boolean): Promise<FeedItem[]> {
  return (await recentRows())
    .filter(keep)
    .slice(0, FEED_LIMIT)
    .map((row) => cveItem(row));
}

export { list as splitSlugs };
