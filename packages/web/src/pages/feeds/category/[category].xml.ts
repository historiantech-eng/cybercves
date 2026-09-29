import type { APIRoute } from 'astro';
import { db } from '../../../lib/data';
import { SITE, feedResponse, scopedItems, splitSlugs } from '../../../lib/feed';

export async function getStaticPaths() {
  const repo = db();
  if (!repo) return [];
  return (await repo.listCategories()).map((category) => ({
    params: { category: category.slug },
    props: { name: category.name },
  }));
}

export const GET: APIRoute = async ({ params, props }) => {
  const slug = params.category ?? '';
  return feedResponse({
    title: `CyberCVE — ${props.name} CVEs`,
    link: `${SITE}/categories/${slug}`,
    description: `New CVEs affecting ${props.name} products across every tracked vendor, newest first.`,
    items: await scopedItems((row) => splitSlugs(row.categories).includes(slug)),
  });
};
