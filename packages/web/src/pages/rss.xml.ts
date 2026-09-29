import type { APIRoute } from 'astro';
import { CURRENT_YEAR, db } from '../lib/data';
import { FEED_LIMIT, SITE, cveItem, feedResponse } from '../lib/feed';

/**
 * Free RSS feed of the latest tracked CVEs.
 *
 * Ships from day one: it costs nothing, it is how practitioners actually consume
 * this kind of data, and it seeds the audience the future paid notification tier
 * will be sold to. Narrower feeds — per vendor, category, product, and KEV — are
 * under /feeds and share this one's item format via lib/feed.
 */
export const GET: APIRoute = async () => {
  const repo = db();
  const rows = repo ? (await repo.listCveIndex(CURRENT_YEAR)).slice(0, FEED_LIMIT) : [];

  return feedResponse({
    title: 'CyberCVE — latest vendor CVEs',
    link: SITE,
    description: 'New CVEs affecting leading cybersecurity vendors, by product category.',
    items: rows.map((row) => cveItem(row)),
  });
};
