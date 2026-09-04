#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { NodeSqliteDriver } from '@cybercves/db/drivers/node';
import { Repository } from '@cybercves/db';
import { denyPatterns, sentences, statesApplicability } from '@cybercves/core';
import { loadConfig } from '../node/config-loader.js';

/**
 * Prints the taxonomy review queue: raw product strings we could not map,
 * ranked by how often they appear.
 *
 * The output is meant to be turned into entries in data/products/*.yaml and
 * committed. That keeps the taxonomy version-controlled data rather than model
 * output, so rebuilds stay deterministic.
 *
 *   npm run taxonomy:review -- --db ./cybercves.sqlite
 *
 * `--prose` runs a different search, for a gap the queue above cannot see. The
 * queue is built from product strings in `affected[]`, so it can only report a
 * product the vendor named there. When a vendor states applicability in the
 * description instead, there is no string to be unmapped and the product is
 * simply absent — silently, and from every count on the site.
 *
 * That is what happened to Palo Alto's Panorama: it runs PAN-OS, so its
 * advisories list "PAN-OS" and name Panorama only in a sentence. The product
 * had zero CVEs, Network & Security Management read as empty for the vendor,
 * and nothing anywhere reported a problem. The fix is a `descriptionPatterns`
 * rule in data/products/*.yaml; this flag is how the next one gets found.
 *
 *   npm run taxonomy:review -- --prose
 */

const { values } = parseArgs({
  options: {
    db: { type: 'string', default: './cybercves.sqlite' },
    limit: { type: 'string', default: '100' },
    yaml: { type: 'boolean', default: false },
    prose: { type: 'boolean', default: false },
  },
});

const driver = new NodeSqliteDriver(values.db);
const repo = new Repository(driver);

/**
 * Products a description states applicability for, that the CVE is not linked
 * to. Deliberately broad where ingest is narrow: this writes nothing, so a
 * false positive costs a human one glance, while a miss costs another Panorama.
 */
async function proseReview() {
  const { products } = loadConfig();
  const known = new Map<string, Array<{ slug: string; name: string; re: RegExp }>>();
  for (const p of products) {
    const list = known.get(p.vendorSlug) ?? [];
    for (const re of denyPatterns([p.name, ...p.aliases])) {
      list.push({ slug: p.slug, name: p.name, re });
    }
    known.set(p.vendorSlug, list);
  }

  const rows = await repo.getDescriptionsForProseReview();
  // Keyed by product, because one missing rule shows up on many CVEs at once
  // and the count is what says whether it is worth writing.
  const found = new Map<string, { vendor: string; name: string; cves: string[] }>();

  for (const row of rows) {
    const linked = new Set(row.product_slugs.split(','));
    const claims = sentences(row.description).filter(statesApplicability);
    if (!claims.length) continue;

    for (const vendor of row.vendor_slugs.split(',')) {
      for (const { slug, name, re } of known.get(vendor) ?? []) {
        if (linked.has(slug)) continue;
        if (!claims.some((sentence) => re.test(sentence))) continue;
        const entry = found.get(slug) ?? { vendor, name, cves: [] };
        if (!entry.cves.includes(row.cve_id)) entry.cves.push(row.cve_id);
        found.set(slug, entry);
      }
    }
  }

  if (!found.size) {
    console.log(
      `Scanned ${rows.length.toLocaleString()} descriptions. No product is stated as ` +
        'applicable in prose without also being linked.',
    );
    return;
  }

  console.log(
    `${found.size} product(s) named in an applicability statement but not linked to the CVE.\n` +
      'Each is a candidate for a `descriptionPatterns` rule in data/products/*.yaml —\n' +
      'read the sentences first, and write a pattern narrow enough to exclude denials.\n',
  );
  const ranked = [...found.entries()].sort((a, b) => b[1].cves.length - a[1].cves.length);
  for (const [slug, entry] of ranked) {
    console.log(`  ${entry.cves.length.toString().padStart(4)}  ${entry.vendor}  ${entry.name}  (${slug})`);
    console.log(`        ${entry.cves.slice(0, 8).join(', ')}${entry.cves.length > 8 ? ', …' : ''}`);
  }
}

try {
  // Both branches fall through to the `finally` rather than exiting early — a
  // `process.exit` here would skip it and leave the database handle open.
  if (values.prose) {
    await proseReview();
  } else {
    const queue = await repo.getUnmappedForReview(Number.parseInt(values.limit, 10));

    if (!queue.length) {
      console.log('Review queue is empty — every product string mapped cleanly.');
    } else if (values.yaml) {
      // Emit a YAML skeleton to paste into data/products/<vendor>.yaml, with the
      // category left blank so it cannot be committed without a human choosing one.
      let vendor = '';
      for (const row of queue) {
        if (row.vendor_slug !== vendor) {
          vendor = row.vendor_slug;
          console.log(`\n# --- ${vendor} ---`);
        }
        const slug = `${vendor}-${row.product_raw.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')}`;
        console.log(`  - slug: ${slug}`);
        console.log(`    name: ${row.product_raw}`);
        console.log(`    categorySlug: # TODO (${row.suggested_category ?? 'no suggestion'})`);
        console.log(`    aliases: [${JSON.stringify(row.product_raw)}]`);
      }
    } else {
      console.log(`${queue.length} unmapped product string(s), most frequent first:\n`);
      console.log('  count  vendor        product');
      console.log('  -----  ------------  -------');
      for (const row of queue) {
        const suggestion = row.suggested_category
          ? `  -> ${row.suggested_category} (${((row.confidence ?? 0) * 100).toFixed(0)}%)`
          : '';
        console.log(
          `  ${String(row.seen_count).padStart(5)}  ${row.vendor_slug.padEnd(12)}  ${row.product_raw}${suggestion}`,
        );
      }
      console.log('\nRe-run with --yaml to emit skeleton entries for data/products/*.yaml');
    }
  }
} finally {
  await driver.close();
}
