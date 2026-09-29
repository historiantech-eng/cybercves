import type { APIRoute } from 'astro';
import {
  TaxonomyResolver,
  VERSION_SCHEMES,
  exposureFromVector,
  type NormalizedVersionRange,
} from '@cybercves/core';
import { db } from '../../../lib/data';
import type { CheckCve, CheckData } from '../../../lib/check';

/**
 * One static file per product /check covers: every CVE linked to the product,
 * with only the affected[] entries that describe THIS product.
 *
 * Entry selection is the whole correctness story here, so it is done at build
 * time, once, with the same resolver ingest uses:
 *
 *   1. Keep entries whose product string resolves to this product. A FortiOS
 *      CVE often lists FortiProxy too, with different ranges.
 *   2. Of those, keep the vendor's own (CNA) entries; fall back to ADP entries
 *      only when the vendor gave none. See migration 0008 — CISA-ADP ranges come
 *      from CPE data, are coarser, and carry defaultStatus "unknown", so mixing
 *      them in turns versions the vendor calls fixed into "could not determine".
 *   3. Rows written before the `source` column existed read as CNA, which is
 *      what every consumer assumed before it existed.
 */
export async function getStaticPaths() {
  const repo = db();
  if (!repo) return [];
  const products = await repo.listProducts();
  return products
    .filter((p) => VERSION_SCHEMES[p.slug])
    .map((p) => ({ params: { product: p.slug }, props: { product: p } }));
}

export const GET: APIRoute = async ({ props }) => {
  const repo = db()!;
  const product = props.product as Awaited<ReturnType<typeof repo.listProducts>>[number];
  const scheme = VERSION_SCHEMES[product.slug]!;

  const { vendors, products } = await repo.loadTaxonomy();
  const resolver = new TaxonomyResolver(vendors, products);
  const psirtHosts = vendors.find((v) => v.slug === product.vendor_slug)?.psirtHosts ?? [];

  const { cves, entries } = await repo.listVersionCheckRows(product.slug);

  const byCve = new Map<string, typeof entries>();
  for (const entry of entries) {
    if (!entry.product_raw) continue;
    const { slugs } = resolver.resolveProductNames(
      product.vendor_slug,
      entry.product_raw,
      entry.vendor_raw,
    );
    if (!slugs.includes(product.slug)) continue;
    const bucket = byCve.get(entry.cve_id);
    if (bucket) bucket.push(entry);
    else byCve.set(entry.cve_id, [entry]);
  }

  const rows: CheckCve[] = cves.map((cve) => {
    const mine = byCve.get(cve.cve_id) ?? [];
    const vendorOwn = mine.filter((e) => e.source !== 'adp');
    const chosen = vendorOwn.length ? vendorOwn : mine;

    const refs = JSON.parse(cve.refs || '[]') as Array<{ url: string }>;
    const advisory =
      refs.find((ref) => {
        try {
          const host = new URL(ref.url).hostname;
          return psirtHosts.some((h) => host === h || host.endsWith(`.${h}`));
        } catch {
          return false;
        }
      })?.url ?? null;

    return {
      i: cve.cve_id,
      t: cve.title,
      d: cve.date_published?.slice(0, 10) ?? null,
      s: cve.severity,
      c: cve.score,
      x: exposureFromVector(cve.vector) === 'remote-unauth' ? 1 : 0,
      k: cve.in_kev,
      r: cve.ransomware_known,
      e: cve.epss,
      fix: cve.solution,
      adv: advisory,
      src: !chosen.length ? 'none' : vendorOwn.length ? 'cna' : 'adp',
      entries: chosen.map((e) => ({
        versions: JSON.parse(e.versions) as NormalizedVersionRange[],
        defaultStatus: e.default_status,
        truncated: e.versions_truncated === 1,
      })),
    };
  });

  const body: CheckData = {
    product: product.slug,
    name: `${product.vendor_name} ${product.name}`,
    scheme,
    generatedAt: new Date().toISOString(),
    cves: rows,
  };

  return new Response(JSON.stringify(body), {
    headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600' },
  });
};
