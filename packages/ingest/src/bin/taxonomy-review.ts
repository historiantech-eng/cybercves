#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { NodeSqliteDriver } from '@cybercves/db/drivers/node';
import { Repository } from '@cybercves/db';

/**
 * Prints the taxonomy review queue: raw product strings we could not map,
 * ranked by how often they appear.
 *
 * The output is meant to be turned into entries in data/products/*.yaml and
 * committed. That keeps the taxonomy version-controlled data rather than model
 * output, so rebuilds stay deterministic.
 *
 *   npm run taxonomy:review -- --db ./cybercves.sqlite
 */

const { values } = parseArgs({
  options: {
    db: { type: 'string', default: './cybercves.sqlite' },
    limit: { type: 'string', default: '100' },
    yaml: { type: 'boolean', default: false },
  },
});

const driver = new NodeSqliteDriver(values.db);
const repo = new Repository(driver);

try {
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
} finally {
  await driver.close();
}
