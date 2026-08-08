#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { NodeSqliteDriver } from '@cybercves/db/drivers/node';
import { Repository } from '@cybercves/db';
import { migrate } from '@cybercves/db/migrate';
import { fetchKev } from '../sources/kev.js';
import { fetchEpss } from '../sources/epss.js';
import { ingestRecords } from '../pipeline.js';
import { loadConfig } from '../node/config-loader.js';
import { inspectClone, streamRecords } from '../node/local-clone.js';

/**
 * Historical backfill, 2016-present by default.
 *
 * Run on a machine with disk and time (the R630 is ideal) against a shallow
 * clone of the CVE List:
 *
 *   git clone --depth 1 https://github.com/CVEProject/cvelistV5.git
 *   npm run backfill -- --clone ../cvelistV5 --db ./cybercves.sqlite
 */

const { values } = parseArgs({
  options: {
    clone: { type: 'string' },
    db: { type: 'string', default: './cybercves.sqlite' },
    from: { type: 'string', default: '2016' },
    to: { type: 'string', default: String(new Date().getUTCFullYear()) },
    'skip-enrich': { type: 'boolean', default: false },
    /**
     * Re-apply the taxonomy to CVEs already stored. Use after editing
     * data/products/*.yaml or data/vendors/*.yaml — without it, mapping changes
     * only reach records that upstream happens to republish afterwards.
     */
    reresolve: { type: 'boolean', default: false },
    help: { type: 'boolean', default: false },
  },
});

if (values.help || !values.clone) {
  console.log(
    'Usage: npm run backfill -- --clone <path-to-cvelistV5> [--db <path>] [--from 2016] [--to 2026] [--skip-enrich]\n\n' +
      'Clone the source first:\n' +
      '  git clone --depth 1 https://github.com/CVEProject/cvelistV5.git',
  );
  // Asking for help is a success; omitting a required flag is not.
  process.exit(values.help ? 0 : 1);
}

const fromYear = Number.parseInt(values.from, 10);
const toYear = Number.parseInt(values.to, 10);

const driver = new NodeSqliteDriver(values.db);
const repo = new Repository(driver);

// Migrate before anything touches a table — startRun() writes to ingest_run,
// which does not exist on a fresh database.
await migrate(driver);
const runId = await repo.startRun('cvelist-backfill');

try {
  const config = loadConfig();
  await repo.syncTaxonomy(config.categories, config.vendors, config.products);

  const stats = inspectClone(values.clone, fromYear, toYear);
  console.log(
    `backfill ${fromYear}-${toYear}: ${stats.fileCount.toLocaleString()} records across ` +
      `${stats.years.length} year(s)`,
  );

  const totals = { inserted: 0, updated: 0, skipped: 0, processed: 0, unmatched: 0, rejected: 0 };
  let seen = 0;

  for (const { year, records } of streamRecords(values.clone, fromYear, toYear)) {
    const summary = await ingestRecords(repo, config.resolver, records, {
      reresolve: values.reresolve,
    });
    totals.inserted += summary.inserted;
    totals.updated += summary.updated;
    totals.skipped += summary.skipped;
    totals.processed += summary.processed;
    totals.unmatched += summary.unmatched;
    totals.rejected += summary.rejected;
    seen += records.length;

    const pct = ((seen / Math.max(stats.fileCount, 1)) * 100).toFixed(1);
    process.stdout.write(
      `\r  ${year} — ${seen.toLocaleString()}/${stats.fileCount.toLocaleString()} (${pct}%) ` +
        `kept ${totals.processed.toLocaleString()}   `,
    );
  }
  process.stdout.write('\n');

  console.log(
    `stored: ${totals.inserted.toLocaleString()} new, ${totals.updated.toLocaleString()} updated, ` +
      `${totals.unmatched.toLocaleString()} skipped as not-ours, ` +
      `${totals.rejected.toLocaleString()} withdrawn`,
  );

  if (!values['skip-enrich']) {
    const kev = await fetchKev();
    console.log(`kev: ${await repo.upsertKev(kev.entries)} entries`);

    const epss = await fetchEpss();
    console.log(`epss: ${await repo.upsertEpssForKnownCves(epss.entries)} scores kept`);
  }

  const queue = await repo.getUnmappedForReview(15);
  if (queue.length) {
    console.log(`\nTop unmapped products (run \`npm run taxonomy:review\` for the full queue):`);
    for (const row of queue) {
      console.log(`  ${String(row.seen_count).padStart(5)}x  ${row.vendor_slug}  ${row.product_raw}`);
    }
  }

  await repo.finishRun(runId, 'ok', totals.processed);
} catch (err) {
  await repo.finishRun(runId, 'error', 0, (err as Error).message);
  console.error(err);
  process.exitCode = 1;
} finally {
  await driver.close();
}
