#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { Repository } from '@cybercves/db';
import { NodeSqliteDriver } from '@cybercves/db/drivers/node';
import { migrate } from '@cybercves/db/migrate';
import { fetchText } from '../http.js';
import { advisoryUrlFromRefs, fetchAcknowledgements } from '../sources/psirt-fortinet.js';
import { loadConfig } from '../node/config-loader.js';
import { mergeDiscoveryFile } from '../node/discovery-store.js';
import { discoveryDir } from '../node/paths.js';

/**
 * Fill in discovery attribution that the CVE List does not carry.
 *
 * Cisco and Palo Alto publish `cna.source.discovery`, so their values arrive with
 * the record and this pass has nothing to do for them. Fortinet publishes none —
 * their attribution lives on each PSIRT advisory page instead, in a labelled
 * `Discovered` field (Internal / External / Third-Party Library) with the
 * Acknowledgement prose underneath it. Both are read here.
 *
 *   npm run discovery -- --db "$PWD/cybercves.sqlite"
 *
 * Pacing is the whole design. fortiguard.com's robots.txt asks for a 2-second
 * crawl delay and disallows `/*?*` outright — which is why this walks 336
 * individual advisory pages rather than the 48-page `/psirt?page=N` index that
 * carries the same column. The default here is 20 seconds, ten times what is
 * asked, because an earlier unthrottled pass got blocked at the TLS layer and a
 * truncated run reads as "Fortinet discloses nothing", not as "we were cut off".
 */

const { values } = parseArgs({
  options: {
    db: { type: 'string', default: './cybercves.sqlite' },
    vendor: { type: 'string', default: 'fortinet' },
    limit: { type: 'string', default: '1000' },
    concurrency: { type: 'string', default: '1' },
    delay: { type: 'string', default: '20000' },
    /** Advisory HTML lands here, so an interrupted run resumes for free. */
    cache: { type: 'string' },
    /** Re-read the DB from an existing cache without touching the network. */
    'cache-only': { type: 'boolean', default: false },
    /** Where the reviewed, committed result is written. */
    out: { type: 'string' },
    /**
     * Re-read every advisory, not just CVEs still lacking attribution.
     * Rebuilds the committed file from scratch — the database being populated
     * says nothing about whether the file on disk is complete.
     */
    refresh: { type: 'boolean', default: false },
  },
});

const OUT_PATH = values.out ? resolve(values.out) : join(discoveryDir(), `${values.vendor}.yaml`);

/**
 * Disk-backed page loader.
 *
 * A cached page never re-hits the origin and never sleeps, so re-running after a
 * block costs only the pages still missing. Filenames are hashed because an
 * advisory URL is not guaranteed to be a safe path component.
 */
function cachingLoader(dir: string, cacheOnly: boolean) {
  mkdirSync(dir, { recursive: true });
  return async (url: string): Promise<{ html: string; fromCache?: boolean }> => {
    const path = join(dir, `${createHash('sha1').update(url).digest('hex')}.html`);
    try {
      return { html: readFileSync(path, 'utf8'), fromCache: true };
    } catch {
      if (cacheOnly) throw new Error(`not cached: ${url}`);
    }
    const html = await fetchText(url, { timeoutMs: 45_000, retries: 3 });
    writeFileSync(path, html);
    return { html };
  };
}

const driver = new NodeSqliteDriver(values.db);
const repo = new Repository(driver);

await migrate(driver);
const runId = await repo.startRun(`discovery:${values.vendor}`);

try {
  const config = loadConfig();
  const vendor = config.vendors.find((v) => v.slug === values.vendor);
  if (!vendor) throw new Error(`unknown vendor "${values.vendor}"`);

  const pending = await repo.listCvesNeedingAcknowledgement(
    vendor.slug,
    Number.parseInt(values.limit, 10),
    values.refresh,
  );

  // Only CVEs that actually reference a PSIRT advisory can be resolved this way.
  const targets = pending.flatMap((row) => {
    const url = advisoryUrlFromRefs(row.refs);
    return url ? [{ cveId: row.cve_id, url }] : [];
  });

  console.log(
    `${vendor.name}: ${pending.length} CVE(s) without discovery, ` +
      `${targets.length} with a PSIRT advisory to read`,
  );

  const run = await fetchAcknowledgements(targets, {
    vendorName: vendor.name,
    brandMarkers: vendor.internalBrandMarkers,
    concurrency: Number.parseInt(values.concurrency, 10),
    delayMs: Number.parseInt(values.delay, 10),
    ...(values.cache ? { fetchPage: cachingLoader(values.cache, values['cache-only']) } : {}),
  });
  const results = run.results;

  const written = await repo.setDiscovery(
    results.map((r) => ({
      cveId: r.cveId,
      discovery: r.discovery as string,
      discoverySource: r.source as string,
      creditText: r.creditText,
    })),
  );

  // Write the reviewed artefact, not just the database. The database is a local
  // build product that CI recreates from nothing; this file is the record, and
  // it is what the nightly deploy actually reads.
  const advisoryId = (url: string) => url.split('/').pop() ?? '';
  const merged = mergeDiscoveryFile(
    OUT_PATH,
    vendor.slug,
    Object.fromEntries(
      results.map((r) => [
        r.cveId,
        {
          discovery: r.discovery as NonNullable<typeof r.discovery>,
          source: r.source as NonNullable<typeof r.source>,
          advisory: advisoryId(r.url),
          ...(r.creditText ? { credit: r.creditText } : {}),
        },
      ]),
    ),
  );
  console.log(
    `${OUT_PATH}: ${merged.total} CVE(s) on record ` +
      `(+${merged.added} new, ${merged.changed} changed, ${merged.unchanged} unchanged) — commit this`,
  );

  const internal = results.filter((r) => r.discovery === 'INTERNAL').length;
  const external = results.filter((r) => r.discovery === 'EXTERNAL').length;
  // Split by source so a run that quietly fell back to prose everywhere — a
  // layout change on the Discovered field — is visible in the output.
  const fromField = results.filter((r) => r.source === 'psirt-field').length;
  console.log(
    `classified ${written}: ${internal} internal, ${external} external · ` +
      `${fromField} from the published Discovered field, ${results.length - fromField} from prose · ` +
      `${run.missing} CVE(s) with no usable attribution · ${run.failed} failed`,
  );

  // A run that mostly failed produced a biased sample, not a finding. Exit
  // non-zero so a scheduled run surfaces it instead of quietly publishing skew.
  if (run.failed > targets.length * 0.1) {
    console.error(
      `\nWARNING: ${run.failed}/${targets.length} requests failed — likely rate limited. ` +
        `Re-run with a longer --delay; treat these totals as incomplete.`,
    );
    process.exitCode = 2;
  }

  await repo.finishRun(runId, 'ok', written);
} catch (err) {
  await repo.finishRun(runId, 'error', 0, (err as Error).message);
  console.error(err);
  process.exitCode = 1;
} finally {
  await driver.close();
}
