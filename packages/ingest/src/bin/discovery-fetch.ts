#!/usr/bin/env node
import { appendFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { fetchJson, fetchText } from '../http.js';
import { fetchAcknowledgements } from '../sources/psirt-fortinet.js';
import { fetchCsafAcknowledgements, parseRssAdvisoryTitles } from '../sources/csaf-fortinet.js';
import { loadConfig } from '../node/config-loader.js';
import { mergeDiscoveryFile, readDiscoveryFile } from '../node/discovery-store.js';
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
    /**
     * Days before re-reading an advisory that previously carried nothing.
     * Some are withdrawn and will never answer; without a backoff an hourly job
     * re-fetches them every hour forever.
     */
    'retry-after-days': { type: 'string', default: '7' },
    /**
     * Hours before re-asking an origin that refused us.
     *
     * A separate, much shorter clock than --retry-after-days, because it backs
     * off a different fact. That one waits out an advisory that genuinely says
     * nothing; this one waits out fortiguard.com declining to serve us at all.
     * A refusal is worth retesting daily — it usually lifts on its own — but not
     * hourly, which produces twenty-four identical failed runs a day and trains
     * everyone to ignore the one that matters.
     */
    'blocked-retry-hours': { type: 'string', default: '24' },
    /** Escape hatch: scrape advisory pages only, as this job did before CSAF. */
    'no-csaf': { type: 'boolean', default: false },
    /**
     * Pause between CSAF documents. Its own knob, and far shorter than --delay,
     * because it paces a different host: --delay is set to ten times what
     * fortiguard.com's robots.txt asks of a scraper walking advisory pages,
     * while this reads static JSON off filestore.fortinet.com, the same origin
     * the RSS feed is served from.
     */
    'csaf-delay': { type: 'string', default: '1000' },
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

const OUT = values.out ?? join(discoveryDir(), `${values.vendor}.yaml`);

// Drop anything held by either backoff. Both are backoffs, not blocklists — an
// advisory published late, or an origin that stops refusing us, is picked up
// again as soon as the entry ages past its window. They are kept apart because
// they encode different facts: `unresolved` is "it said nothing", `blocked` is
// "we never got to read it".
const retryAfterMs = Number.parseFloat(values['retry-after-days']) * 86_400_000;
const blockedRetryMs = Number.parseFloat(values['blocked-retry-hours']) * 3_600_000;
const priorFile = readDiscoveryFile(OUT);
const suppressed = priorFile?.unresolved ?? {};
const refused = priorFile?.blocked ?? {};
const now = Date.now();

let heldBack = 0;
let heldBlocked = 0;
const all = (payload.pending ?? []).filter((t) => {
  const prior = suppressed[t.cveId];
  if (prior && now - Date.parse(prior.lastChecked) <= retryAfterMs) {
    heldBack++;
    return false;
  }
  const block = refused[t.cveId];
  if (block && now - Date.parse(block.lastBlocked) <= blockedRetryMs) {
    heldBlocked++;
    return false;
  }
  return true;
});
const targets = all.slice(0, Number.parseInt(values.max, 10));

const heldNote =
  (heldBack ? ` · ${heldBack} held back by the retry backoff` : '') +
  (heldBlocked ? ` · ${heldBlocked} waiting out a refused scrape` : '');

if (targets.length === 0) {
  // Said plainly rather than as "nothing to fetch". A run that makes no
  // requests because the origin is refusing us is not the same as a run with no
  // work, and the log is the only place anyone would notice the difference.
  console.log(
    heldBlocked && !all.length
      ? `${values.vendor}: no requests made — ${heldBlocked} advisor${heldBlocked === 1 ? 'y is' : 'ies are'} ` +
          `waiting out a refused scrape, retried after ` +
          `${values['blocked-retry-hours']}h${heldBack ? ` (${heldBack} more on the no-attribution backoff)` : ''}`
      : `${values.vendor}: nothing to fetch — no requests made${heldNote}`,
  );
  process.exit(0);
}

console.log(`${values.vendor}: ${all.length} due, fetching ${targets.length}${heldNote}`);

const vendor = loadConfig().vendors.find((v) => v.slug === values.vendor);
if (!vendor) throw new Error(`unknown vendor "${values.vendor}"`);

/**
 * CSAF first, the advisory page only for what is left.
 *
 * Not a preference for the better data — the page is the better data, because it
 * carries the labelled `Discovered:` field that CSAF omits. It is a preference
 * for the data we can actually get: fortiguard.com has been refusing this job
 * since 2026-09-08, and filestore.fortinet.com serves the same advisories as
 * CSAF without a challenge.
 *
 * The ordering has a second effect worth stating. Every advisory CSAF answers is
 * one the scraper never requests, so a run that resolves everything this way
 * touches the blocked host zero times — no challenge, no refusal record, no
 * alarm. The scrape is reached for only when CSAF genuinely cannot answer.
 */
let titles = new Map<string, string>();
if (!values['no-csaf'] && vendor.rssUrl) {
  try {
    titles = parseRssAdvisoryTitles(await fetchText(vendor.rssUrl, { timeoutMs: 30_000, retries: 2 }));
  } catch (err) {
    // Degrade to the scrape rather than fail. The feed is an optimisation here,
    // and an outage on it should not take the whole refresh down.
    console.warn(`RSS feed unavailable (${(err as Error).message}) — CSAF skipped this run`);
  }
}

const csaf = titles.size
  ? await fetchCsafAcknowledgements(targets, {
      titles,
      vendorName: vendor.name,
      brandMarkers: vendor.internalBrandMarkers,
      concurrency: 1,
      delayMs: Number.parseInt(values['csaf-delay'], 10),
    })
  : { results: [], remaining: [...targets], read: 0, missing: 0, failed: 0 };

if (titles.size) {
  console.log(
    `csaf: read ${csaf.read} of ${csaf.read + csaf.failed} document(s) · ` +
      `resolved ${csaf.results.length} CVE(s) · ${csaf.missing} carried no usable credit · ` +
      `${csaf.remaining.length} left for the advisory page` +
      (csaf.remaining.length
        ? ` at ${Number.parseInt(values.delay, 10) / 1000}s intervals`
        : ' — the blocked host is not touched this run'),
  );
}

// Only what CSAF could not answer reaches the blocked host.
const EMPTY_RUN = {
  results: [],
  missing: 0,
  failed: 0,
  blocked: 0,
  failedCveIds: [],
  blockedCveIds: [],
};
const run = csaf.remaining.length
  ? await fetchAcknowledgements(csaf.remaining, {
      vendorName: vendor.name,
      brandMarkers: vendor.internalBrandMarkers,
      concurrency: 1,
      delayMs: Number.parseInt(values.delay, 10),
    })
  : EMPTY_RUN;

const advisoryId = (url: string) => url.split('/').pop() ?? '';
// Only advisories we actually read count toward the unresolved backoff. A
// request that never returned tells us nothing about the page, and suppressing
// it for a week on that basis would turn one bad afternoon into a silent gap.
const found = [...csaf.results, ...run.results];
const resolved = new Set(found.map((r) => r.cveId));
const unreachable = new Set(run.failedCveIds);
const blockedSet = new Set(run.blockedCveIds);
const merged = mergeDiscoveryFile(
  OUT,
  values.vendor,
  Object.fromEntries(
    found.map((r) => [
      r.cveId,
      {
        discovery: r.discovery as NonNullable<typeof r.discovery>,
        source: r.source as NonNullable<typeof r.source>,
        advisory: advisoryId(r.url),
        ...(r.creditText ? { credit: r.creditText } : {}),
      },
    ]),
  ),
  new Date(),
  targets.filter((t) => !resolved.has(t.cveId) && !unreachable.has(t.cveId)).map((t) => ({
    cveId: t.cveId,
    advisory: t.url.split('/').pop(),
  })),
  // Refusals go to their own bucket, never to `unresolved`. The distinction is
  // load-bearing: one is a statement about the advisory, the other only about
  // our access to it.
  targets.filter((t) => blockedSet.has(t.cveId)).map((t) => ({
    cveId: t.cveId,
    advisory: t.url.split('/').pop(),
  })),
);

console.log(
  `resolved ${found.length} (${csaf.results.length} from csaf, ${run.results.length} from the ` +
    `advisory page) · ${run.missing} with no usable attribution · ` +
    `${run.failed} failed` +
    (run.blocked ? ` (${run.blocked} served a bot challenge, not an advisory)` : '') +
    ` · file now holds ${merged.total} attributed, ` +
    `${merged.unresolved} on backoff (+${merged.added} new, ${merged.changed} changed)` +
    (merged.blocked ? ` · ${merged.blocked} waiting out a refused scrape` : ''),
);

/**
 * Hand the outcome to the calling job.
 *
 * The refresh workflow needs two things this process knows and a shell reading
 * `git diff` cannot tell apart: whether any *attribution* actually changed —
 * which is what justifies a production deploy — and whether the file changed
 * only because a refusal was recorded, which must be committed but is not worth
 * redeploying the site for. Written only under Actions; a local run is
 * unaffected.
 */
const summary = process.env.GITHUB_OUTPUT;
if (summary) {
  appendFileSync(
    summary,
    `attribution-changed=${merged.added + merged.changed > 0}\n` + `blocked=${run.blocked}\n`,
  );
}

// A run where most requests failed is a blocked scrape, not a finding. Exit
// non-zero so the job surfaces it rather than committing a thin result.
//
// Gated on having learned nothing at all, which CSAF changed the meaning of. A
// refused scrape used to mean the run was blind; now it usually means the
// advisory page was unreachable for the handful of CVEs CSAF could not cover,
// while the rest resolved fine. That is a degraded run, not an invalid one, and
// paging someone hourly over it is the noise this job was just fixed to stop.
// The protection that actually matters — never recording a refusal as "credits
// nobody" — lives in the blocked bucket and holds regardless of exit code.
if (found.length === 0 && run.failed > csaf.remaining.length * 0.5) {
  console.error(
    `\n${run.failed}/${csaf.remaining.length} requests failed and nothing resolved — ` +
      `treating this run as invalid.` +
      (run.blocked
        ? `\n${run.blocked} of them were answered with fortiguard.com's bot challenge rather than ` +
          `an advisory. The scrape is being refused, not coming up empty — nothing was written ` +
          `to the no-attribution backoff, so no CVE has been recorded as uncredited on this ` +
          `evidence.\nThey are now on the refusal backoff and will be retried in ` +
          `${values['blocked-retry-hours']}h. If the next attempt is refused too, this job will ` +
          `fail again then: once a day for as long as it lasts, rather than every hour.`
        : ''),
  );
  process.exitCode = 2;
}
