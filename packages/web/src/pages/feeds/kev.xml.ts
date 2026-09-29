import type { APIRoute } from 'astro';
import { db, formatDate } from '../../lib/data';
import { FEED_LIMIT, SITE, cveItem, feedResponse } from '../../lib/feed';

/**
 * Tracked CVEs as CISA adds them to the Known Exploited Vulnerabilities catalog.
 *
 * Dated by the KEV listing, not by CVE publication. The news in this feed is
 * "attackers are now using this", which often lands weeks after the CVE itself —
 * dating it by publication would file a fresh exploitation notice under an old
 * date where a reader sorting by date would never see it.
 */
export const GET: APIRoute = async () => {
  const repo = db();
  const rows = repo ? await repo.listKevCves(FEED_LIMIT) : [];

  return feedResponse({
    title: 'CyberCVE — known exploited',
    link: `${SITE}/kev`,
    description:
      'Tracked vendor CVEs as CISA adds them to the Known Exploited Vulnerabilities catalog.',
    items: rows.map((row) =>
      cveItem(row, {
        pubDate: row.date_added,
        extra:
          `Added to KEV ${formatDate(row.date_added)}. ` +
          `${row.ransomware_known === 1 ? 'Known ransomware campaign use. ' : ''}`,
      }),
    ),
  });
};
