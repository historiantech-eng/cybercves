import type { APIRoute } from 'astro';
import { db } from '../../../lib/data';
import { SITE, feedResponse, scopedItems, splitSlugs } from '../../../lib/feed';

export async function getStaticPaths() {
  const repo = db();
  if (!repo) return [];
  return (await repo.listVendors()).map((vendor) => ({
    params: { vendor: vendor.slug },
    props: { name: vendor.name },
  }));
}

export const GET: APIRoute = async ({ params, props }) => {
  const slug = params.vendor ?? '';
  return feedResponse({
    title: `CyberCVE — ${props.name} CVEs`,
    link: `${SITE}/vendors/${slug}`,
    description: `New CVEs affecting ${props.name} products, newest first.`,
    items: await scopedItems((row) => splitSlugs(row.vendors).includes(slug)),
  });
};
