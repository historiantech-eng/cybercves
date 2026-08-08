import type { APIRoute } from 'astro';
import { CURRENT_YEAR, db } from '../lib/data';

const SITE = 'https://cybercve.com';

const escapeXml = (value: string) =>
  value.replace(/[&<>"']/g, (ch) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[ch] as string,
  );

/**
 * Free RSS feed of the latest tracked CVEs.
 *
 * Ships from day one: it costs nothing, it is how practitioners actually consume
 * this kind of data, and it seeds the audience the future paid notification tier
 * will be sold to.
 */
export const GET: APIRoute = async () => {
  const repo = db();
  const rows = repo ? (await repo.listCveIndex(CURRENT_YEAR)).slice(0, 50) : [];

  const items = rows
    .map((row) => {
      const vendors = (row.vendors ?? '').split(',').filter(Boolean).join(', ');
      const title = `${row.cve_id}${row.severity ? ` — ${row.severity}` : ''}${vendors ? ` (${vendors})` : ''}`;
      const description =
        `Severity: ${row.severity ?? 'unscored'}${row.score != null ? ` (${row.score})` : ''}. ` +
        `${row.in_kev === 1 ? 'Listed in CISA KEV. ' : ''}` +
        `${row.epss != null ? `EPSS ${row.epss.toFixed(3)}. ` : ''}` +
        `Affects: ${(row.products ?? '').split(',').filter(Boolean).join(', ') || 'see advisory'}.`;

      return `    <item>
      <title>${escapeXml(title)}</title>
      <link>${SITE}/cve/${row.cve_id}</link>
      <guid isPermaLink="true">${SITE}/cve/${row.cve_id}</guid>
      ${row.date_published ? `<pubDate>${new Date(row.date_published).toUTCString()}</pubDate>` : ''}
      <description>${escapeXml(description)}</description>
    </item>`;
    })
    .join('\n');

  const body = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>CyberCVE — latest vendor CVEs</title>
    <link>${SITE}</link>
    <description>New CVEs affecting leading cybersecurity vendors, by product category.</description>
    <language>en-us</language>
    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
${items}
  </channel>
</rss>`;

  return new Response(body, { headers: { 'content-type': 'application/rss+xml; charset=utf-8' } });
};
