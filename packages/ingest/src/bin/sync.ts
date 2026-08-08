#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { NodeSqliteDriver } from '@cybercves/db/drivers/node';
import { Repository } from '@cybercves/db';
import { migrate } from '@cybercves/db/migrate';
import { changedEntries, fetchDelta, fetchRecords } from '../sources/cvelist.js';
import { fetchKev } from '../sources/kev.js';
import { fetchEpss } from '../sources/epss.js';
import { ingestRecords } from '../pipeline.js';
import { loadConfig } from '../node/config-loader.js';

/**
 * Incremental sync — the same work the Worker's 15-minute cron does, runnable
 * locally against a SQLite file for development and debugging.
 *
 *   npm run sync -- --db ./cybercves.sqlite
 *   npm run sync -- --db ./cybercves.sqlite --enrich   (also refresh KEV + EPSS)
 */

const { values } = parseArgs({
  options: {
    db: { type: 'string', default: './cybercves.sqlite' },
    enrich: { type: 'boolean', default: false },
    help: { type: 'boolean', default: false },
  },
});

if (values.help) {
  console.log('Usage: npm run sync -- [--db <path>] [--enrich]');
  process.exit(0);
}

const driver = new NodeSqliteDriver(values.db);
const repo = new Repository(driver);

// Migrate before anything touches a table — startRun() writes to ingest_run,
// which does not exist on a fresh database.
await migrate(driver);
const runId = await repo.startRun('cvelist-delta');

try {
  const config = loadConfig();
  await repo.syncTaxonomy(config.categories, config.vendors, config.products);
  console.log(
    `taxonomy: ${config.vendors.length} vendors, ${config.products.length} products, ` +
      `${config.categories.length} categories`,
  );

  const feed = await fetchDelta();
  const changed = changedEntries(feed);
  console.log(`delta @ ${feed.fetchTime}: ${changed.length} changed record(s)`);

  const fetched = await fetchRecords(changed);
  const failures = fetched.filter((f) => f.record === null);
  for (const failure of failures) {
    console.warn(`  ! ${failure.entry.cveId}: ${failure.error}`);
  }

  const records = fetched.flatMap((f) => (f.record ? [f.record] : []));
  const summary = await ingestRecords(repo, config.resolver, records);
  console.log(
    `ingest: ${summary.inserted} new, ${summary.updated} updated, ${summary.skipped} unchanged, ` +
      `${summary.unmatched} not ours, ${summary.rejected} withdrawn, ` +
      `${summary.unmappedCount} unmapped product(s)`,
  );

  if (values.enrich) {
    const kev = await fetchKev();
    console.log(`kev: ${await repo.upsertKev(kev.entries)} entries (catalog ${kev.catalogVersion})`);

    const epss = await fetchEpss();
    const written = await repo.upsertEpssForKnownCves(epss.entries);
    console.log(`epss: ${written} of ${epss.entries.length} scores kept (as of ${epss.asOf})`);
  }

  await repo.setSyncState('cvelist:fetchTime', feed.fetchTime);
  await repo.finishRun(runId, 'ok', summary.processed);
} catch (err) {
  await repo.finishRun(runId, 'error', 0, (err as Error).message);
  console.error(err);
  process.exitCode = 1;
} finally {
  await driver.close();
}
