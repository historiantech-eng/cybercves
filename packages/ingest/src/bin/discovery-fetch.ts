#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { fetchJson } from '../http.js';
import { fetchAcknowledgements } from '../sources/psirt-fortinet.js';
import { loadConfig } from '../node/config-loader.js';
import { mergeDiscoveryFile } from '../node/discovery-store.js';
import { discoveryDir } from '../node/paths.js';

/**
 * Refresh committed discovery attribution for a handful of new advisories.
 *
 *   npm run discovery:fetch -- --from https://cybercve.com/api/v1/discovery/pending?vendor=fortinet
 *
 * The difference from `npm run discovery` is what it needs to run: nothing but a
 * list of (cveId, url). No CVE List clone, no backfill, no database. That is
 * what makes an hourly refresh job viable — the expensive version takes minutes
 * to reach the point where it can even tell whether there is work to do, and
 * this takes one HTTP request.
 *
 * It writes only the YAML. The database and D1 are updated later by
 * `discovery:apply` during a deploy, which keeps the invariant that production
 * data comes from committed, reviewable files rather than from whatever a job
 * happened to scrape.
 */

const { values } = parseArgs({
  options: {
    /** URL or file holding {pending:[{cveId,url}]} — the Worker's endpoint shape. */
    from: { type: 'string' },
    vendor: { type: 'string', default: 'fortinet' },
    out: { type: 'string' },
    delay: { type: 'string', default: '20000' },
    /**
     * Cap per run. Fortinet publishes in batches, and at 20s a page an
     * unbounded run after a big release would sit there for hours. The
     * remainder is simply picked up by the next run — the job is idempotent.
     */
    max: { type: 'string', default: '40' },
  },
});

interface Pending {
  pending?: Array<{ cveId: string; url: string }>;
}

const source = values.from;
if (!source) {
  console.error('--from <url|file> is required');
  process.exit(1);
}

const payload: Pending = /^https?:\/\//.test(source)
  ? await fetchJson<Pending>(source, { timeoutMs: 30_000, retries: 3 })
  : (JSON.parse(readFileSync(source, 'utf8')) as Pending);

const all = payload.pending ?? [];
const targets = all.slice(0, Number.parseInt(values.max, 10));

if (targets.length === 0) {
  console.log(`${values.vendor}: nothing pending — no requests made`);
  process.exit(0);
}

console.log(
  `${values.vendor}: ${all.length} pending, fetching ${targets.length} ` +
    `at ${Number.parseInt(values.delay, 10) / 1000}s intervals`,
);

const vendor = loadConfig().vendors.find((v) => v.slug === values.vendor);
if (!vendor) throw new Error(`unknown vendor "${values.vendor}"`);

const run = await fetchAcknowledgements(targets, {
  vendorName: vendor.name,
  brandMarkers: vendor.internalBrandMarkers,
  concurrency: 1,
  delayMs: Number.parseInt(values.delay, 10),
});

const advisoryId = (url: string) => url.split('/').pop() ?? '';
const merged = mergeDiscoveryFile(
  values.out ?? join(discoveryDir(), `${values.vendor}.yaml`),
  values.vendor,
  Object.fromEntries(
    run.results.map((r) => [
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
  `resolved ${run.results.length} · ${run.missing} with no usable attribution · ` +
    `${run.failed} failed · file now holds ${merged.total} (+${merged.added} new, ${merged.changed} changed)`,
);

// A run where most requests failed is a blocked scrape, not a finding. Exit
// non-zero so the job surfaces it rather than committing a thin result.
if (run.failed > targets.length * 0.5) {
  console.error(`\n${run.failed}/${targets.length} requests failed — treating this run as invalid.`);
  process.exitCode = 2;
}
