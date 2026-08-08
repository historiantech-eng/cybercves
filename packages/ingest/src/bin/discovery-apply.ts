#!/usr/bin/env node
import { readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { Repository } from '@cybercves/db';
import { NodeSqliteDriver } from '@cybercves/db/drivers/node';
import { migrate } from '@cybercves/db/migrate';
import { readDiscoveryFile } from '../node/discovery-store.js';
import { discoveryDir } from '../node/paths.js';

/**
 * Apply committed discovery attribution to the database. No network.
 *
 *   npm run discovery:apply -- --db "$PWD/cybercves.sqlite"
 *
 * This is the step CI runs, and the separation from `npm run discovery` is the
 * point rather than an accident. Scraping is a deliberate act a human performs
 * and reviews; a deploy must be a pure function of what is committed. Wiring the
 * scrape into the nightly build would mean every deploy silently depends on a
 * third party's website being up, and a bad night would publish "Fortinet
 * discloses nothing" instead of failing loudly.
 *
 * Runs after the backfill and before the D1 push, because `push:d1` truncates
 * every table — anything not in SQLite by then is destroyed in production.
 */

const { values } = parseArgs({
  options: {
    db: { type: 'string', default: './cybercves.sqlite' },
    dir: { type: 'string' },
    /** Fail instead of warn when the file covers CVEs the database lacks. */
    strict: { type: 'boolean', default: false },
  },
});

const DIR = values.dir ? resolve(values.dir) : discoveryDir();

const driver = new NodeSqliteDriver(values.db);
const repo = new Repository(driver);

await migrate(driver);
const runId = await repo.startRun('discovery:apply');

try {
  let files: string[];
  try {
    files = readdirSync(DIR).filter((f) => f.endsWith('.yaml'));
  } catch {
    files = [];
  }

  if (files.length === 0) {
    // Loud, because the silent version of this is a site that reports every
    // Fortinet CVE as "not disclosed" and looks fine while doing it.
    console.warn(`\n  [cybercve] No discovery data in ${DIR}/ — nothing to apply.\n`);
  }

  let written = 0;
  let missing = 0;

  for (const file of files) {
    const data = readDiscoveryFile(join(DIR, file));
    if (!data) {
      console.warn(`  skipped ${file}: unreadable or empty`);
      continue;
    }

    const rows = Object.entries(data.cves).map(([cveId, record]) => ({
      cveId,
      discovery: record.discovery,
      discoverySource: record.source,
      creditText: record.credit ?? null,
    }));

    if (rows.length === 0) {
      console.warn(`  skipped ${file}: no entries`);
      continue;
    }

    // A CVE in the file but not in the database is drift worth surfacing: either
    // the backfill is short, or an advisory was withdrawn. setDiscovery updates
    // by primary key, so these are no-ops rather than corruption — but a silent
    // no-op is how you find out months later that coverage shrank.
    //
    // Chunked because SQLite caps bound variables at 999 by default. Three years
    // of Fortinet fits in one query; the planned ten-year backfill would not, and
    // this would start failing at exactly the point the dataset got interesting.
    const known = new Set<string>();
    for (let i = 0; i < rows.length; i += 500) {
      const chunk = rows.slice(i, i + 500);
      const found = await repo.driver.all<{ cve_id: string }>(
        `SELECT cve_id FROM cve WHERE cve_id IN (${chunk.map(() => '?').join(',')})`,
        chunk.map((r) => r.cveId),
      );
      for (const row of found) known.add(row.cve_id);
    }
    const absent = rows.filter((r) => !known.has(r.cveId));
    missing += absent.length;

    written += await repo.setDiscovery(rows.filter((r) => known.has(r.cveId)));
    console.log(
      `${file}: applied ${rows.length - absent.length} of ${rows.length}` +
        (absent.length ? ` · ${absent.length} not in this database` : ''),
    );
  }

  if (missing > 0) {
    console.warn(
      `\n  ${missing} committed attribution(s) reference CVEs this database does not hold.\n` +
        '  Usually means the backfill covered fewer years than the scrape did.\n',
    );
    if (values.strict) process.exitCode = 2;
  }

  console.log(`applied ${written} discovery record(s) from ${files.length} file(s)`);
  await repo.finishRun(runId, 'ok', written);
} catch (err) {
  await repo.finishRun(runId, 'error', 0, (err as Error).message);
  console.error(err);
  process.exitCode = 1;
} finally {
  await driver.close();
}
