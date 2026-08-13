import type { APIRoute } from 'astro';
import { db } from '../lib/data';

const SITE = 'https://cybercve.com';

/**
 * Sitemap covering every prerendered route.
 *
 * The per-CVE pages are the bulk of it and the reason the site is indexable at
 * all — they are what organic search has to land on.
 */
export const GET: APIRoute = async () => {
  const repo = db();
  const urls: Array<{ loc: string; priority: string; changefreq: string }> = [
    { loc: '/', priority: '1.0', changefreq: 'hourly' },
    { loc: '/vendors', priority: '0.9', changefreq: 'daily' },
    { loc: '/categories', priority: '0.9', changefreq: 'daily' },
    { loc: '/kev', priority: '0.9', changefreq: 'daily' },
    { loc: '/compare', priority: '0.7', changefreq: 'daily' },
    { loc: '/methodology', priority: '0.5', changefreq: 'monthly' },
    { loc: '/feedback', priority: '0.4', changefreq: 'yearly' },
    // Low priority, but present: a site making claims about named companies
    // should have its terms and privacy findable rather than buried.
    { loc: '/privacy', priority: '0.2', changefreq: 'yearly' },
    { loc: '/terms', priority: '0.2', changefreq: 'yearly' },
  ];

  if (repo) {
    for (const vendor of await repo.listVendors()) {
      urls.push({ loc: `/vendors/${vendor.slug}`, priority: '0.8', changefreq: 'daily' });
    }
    for (const category of await repo.listCategories()) {
      urls.push({ loc: `/categories/${category.slug}`, priority: '0.8', changefreq: 'daily' });
    }
    const years = await repo.listYears();
    for (const year of years) {
      urls.push({ loc: `/years/${year}`, priority: '0.7', changefreq: 'daily' });
    }
    for (const year of years) {
      for (const row of await repo.listCveIndex(year)) {
        urls.push({ loc: `/cve/${row.cve_id}`, priority: '0.6', changefreq: 'monthly' });
      }
    }
  }

  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls
  .map(
    (url) =>
      `  <url><loc>${SITE}${url.loc}</loc><changefreq>${url.changefreq}</changefreq><priority>${url.priority}</priority></url>`,
  )
  .join('\n')}
</urlset>`;

  return new Response(body, { headers: { 'content-type': 'application/xml; charset=utf-8' } });
};
