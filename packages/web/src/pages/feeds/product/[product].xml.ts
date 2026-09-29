import type { APIRoute } from 'astro';
import { db } from '../../../lib/data';
import { SITE, feedResponse, scopedItems, splitSlugs } from '../../../lib/feed';

/** Only products with at least one CVE — see Repository.listProducts. */
export async function getStaticPaths() {
  const repo = db();
  if (!repo) return [];
  return (await repo.listProducts()).map((product) => ({
    params: { product: product.slug },
    props: { name: product.name, vendor: product.vendor_slug, vendorName: product.vendor_name },
  }));
}

export const GET: APIRoute = async ({ params, props }) => {
  const slug = params.product ?? '';
  return feedResponse({
    title: `CyberCVE — ${props.vendorName} ${props.name} CVEs`,
    link: `${SITE}/vendors/${props.vendor}`,
    description: `New CVEs affecting ${props.vendorName} ${props.name}, newest first.`,
    items: await scopedItems((row) => splitSlugs(row.products).includes(slug)),
  });
};
