import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { TaxonomyResolver } from '@cybercves/core';
import { Repository } from '@cybercves/db';
import { D1Driver } from '@cybercves/db/drivers/d1';
import type { D1Database as D1Shape } from '@cybercves/db/drivers/d1';
import { changedEntries, fetchDelta, fetchRecords } from '@cybercves/ingest';
import { fetchEpss, fetchKev } from '@cybercves/ingest';
import { ingestRecords } from '@cybercves/ingest';

/**
 * cybercve.com Worker.
 *
 * Two jobs: run the cron ingests, and serve the JSON API.
 *
 * Routing is assets-first, so this code does NOT run for requests that match a
 * prerendered page — those are served at the edge and cost no invocation. The
 * Worker only sees paths with no matching asset: /api/*, CVE pages published
 * since the last rebuild, and genuine 404s.
 *
 * Cloudflare-specific code is confined to this package by design — core, db, and
 * ingest import no platform APIs, so moving to Node or Cloud Run means replacing
 * this file and the driver, not rewriting the pipeline.
 */

export interface Env {
  DB: D1Database;
  /** Small, frequently-rewritten payloads: the live counter snapshot. */
  LIVE: KVNamespace;
  ASSETS: Fetcher;
  ENVIRONMENT?: string;
}

const LIVE_KEY = 'live-snapshot';

/** Cache the counter briefly at the edge; the cron rewrites it every 15 minutes. */
const LIVE_CACHE = 'public, max-age=60, stale-while-revalidate=300';
/** Aggregates change at most daily, so let the edge hold them far longer. */
const API_CACHE = 'public, max-age=600, stale-while-revalidate=3600';

function repoFor(env: Env): Repository {
  return new Repository(new D1Driver(env.DB as unknown as D1Shape));
}

async function resolverFor(repo: Repository): Promise<TaxonomyResolver> {
  // Rebuilt from D1 rather than from YAML: the Worker has no filesystem. Patterns
  // are stored alongside aliases so this resolves identically to the Node pipeline.
  const { vendors, products } = await repo.loadTaxonomy();
  return new TaxonomyResolver(vendors, products);
}

const currentYear = () => new Date().getUTCFullYear();

// ---------------------------------------------------------------------------
// Cron handlers
// ---------------------------------------------------------------------------

/**
 * Poll the CVE List delta feed and store anything that changed.
 *
 * Also rewrites the live snapshot into KV, which is what keeps the hero counter
 * near-real-time without triggering a static rebuild — rebuilding every 15
 * minutes would be ~2,880 builds a month.
 */
async function syncDelta(env: Env): Promise<void> {
  const repo = repoFor(env);
  const runId = await repo.startRun('cvelist-delta');

  try {
    const feed = await fetchDelta();
    const changed = changedEntries(feed);

    let summary = { processed: 0, inserted: 0, updated: 0, skipped: 0, unmatched: 0, unmappedCount: 0 };
    if (changed.length) {
      const resolver = await resolverFor(repo);
      const fetched = await fetchRecords(changed, 4);
      const records = fetched.flatMap((f) => (f.record ? [f.record] : []));
      summary = await ingestRecords(repo, resolver, records);
    }

    await refreshLiveSnapshot(env, repo);
    await repo.setSyncState('cvelist:fetchTime', feed.fetchTime);
    await repo.finishRun(runId, 'ok', summary.processed);
    console.log('delta sync', { changed: changed.length, ...summary });
  } catch (err) {
    await repo.finishRun(runId, 'error', 0, (err as Error).message);
    throw err;
  }
}

/** Daily KEV + EPSS refresh. */
async function syncEnrichment(env: Env): Promise<void> {
  const repo = repoFor(env);
  const runId = await repo.startRun('enrichment');

  try {
    const kev = await fetchKev();
    const kevCount = await repo.upsertKev(kev.entries);

    // EPSS ships ~350k rows daily; only scores for CVEs we actually track are
    // stored, or the enrichment table would dwarf the data the site serves.
    const epss = await fetchEpss();
    const epssCount = await repo.upsertEpssForKnownCves(epss.entries);

    await refreshLiveSnapshot(env, repo);
    await repo.finishRun(runId, 'ok', kevCount + epssCount);
    console.log('enrichment', { kevCount, epssCount, epssAsOf: epss.asOf });
  } catch (err) {
    await repo.finishRun(runId, 'error', 0, (err as Error).message);
    throw err;
  }
}

async function refreshLiveSnapshot(env: Env, repo: Repository): Promise<unknown> {
  const year = currentYear();
  const [snapshot, pace, rollup] = await Promise.all([
    repo.getLiveSnapshot(year),
    repo.getYearOverYearPace(year),
    repo.getVendorRollup(year, true),
  ]);

  const payload = { ...snapshot, pace, rollup };
  await env.LIVE.put(LIVE_KEY, JSON.stringify(payload));
  return payload;
}

// ---------------------------------------------------------------------------
// JSON API
// ---------------------------------------------------------------------------

const api = new Hono<{ Bindings: Env }>();

api.use('/api/*', cors({ origin: '*', allowMethods: ['GET', 'OPTIONS'] }));

api.get('/api/v1/live', async (c) => {
  // Served from KV, not D1: this is the highest-traffic endpoint on the site and
  // must not spend a database read per visitor.
  const cached = await c.env.LIVE.get(LIVE_KEY);
  if (cached) {
    return new Response(cached, {
      headers: { 'content-type': 'application/json', 'cache-control': LIVE_CACHE },
    });
  }
  const payload = await refreshLiveSnapshot(c.env, repoFor(c.env));
  return c.json(payload as object, 200, { 'cache-control': LIVE_CACHE });
});

api.get('/api/v1/vendors', async (c) => {
  const year = Number.parseInt(c.req.query('year') ?? '', 10) || currentYear();
  const securityOnly = c.req.query('all') !== '1';
  // ?category=firewall scopes every figure, risk included, to one product line.
  const category = c.req.query('category') || undefined;
  const rows = await repoFor(c.env).getVendorRollup(year, securityOnly, category);
  return c.json({ year, securityOnly, category: category ?? null, vendors: rows }, 200, {
    'cache-control': API_CACHE,
  });
});

api.get('/api/v1/categories', async (c) => {
  const year = Number.parseInt(c.req.query('year') ?? '', 10) || currentYear();
  const vendor = c.req.query('vendor') ?? undefined;
  const rows = await repoFor(c.env).getCategoryBreakdown(year, vendor);
  return c.json({ year, vendor: vendor ?? null, categories: rows }, 200, {
    'cache-control': API_CACHE,
  });
});

api.get('/api/v1/discovery', async (c) => {
  const yearParam = Number.parseInt(c.req.query('year') ?? '', 10);
  const year = Number.isFinite(yearParam) ? yearParam : undefined;
  const rows = await repoFor(c.env).getDiscoveryBreakdown(year);
  return c.json({ year: year ?? null, vendors: rows }, 200, { 'cache-control': API_CACHE });
});

/**
 * Year-scoped aggregates with an optional previous-year comparison.
 *
 *   /api/v1/stats?year=2025&compare=prev
 */
api.get('/api/v1/stats', async (c) => {
  const year = Number.parseInt(c.req.query('year') ?? '', 10) || currentYear();
  const compare = c.req.query('compare') === 'prev';
  const repo = repoFor(c.env);
  const vendorSlug = c.req.query('vendor') ?? undefined;

  const category = c.req.query('category') || undefined;

  const load = async (y: number) => ({
    year: y,
    vendors: await repo.getVendorRollup(y, c.req.query('all') !== '1', category),
    categories: await repo.getCategoryBreakdown(y, vendorSlug),
    discovery: await repo.getDiscoveryBreakdown(y),
  });

  return c.json(
    {
      current: await load(year),
      previous: compare ? await load(year - 1) : null,
      vendor: vendorSlug ?? null,
      category: category ?? null,
    },
    200,
    { 'cache-control': API_CACHE },
  );
});

api.get('/api/v1/cve/:id', async (c) => {
  const id = c.req.param('id').toUpperCase();
  if (!/^CVE-\d{4}-\d+$/.test(id)) return c.json({ error: 'malformed CVE id' }, 400);

  const repo = repoFor(c.env);
  const cve = await repo.driver.first<Record<string, unknown>>(
    `SELECT c.*, k.date_added AS kev_date_added, k.ransomware_known, e.score AS epss_score
     FROM cve c
     LEFT JOIN kev k  ON k.cve_id = c.cve_id
     LEFT JOIN epss e ON e.cve_id = c.cve_id
     WHERE c.cve_id = ?`,
    [id],
  );
  if (!cve) return c.json({ error: 'not found' }, 404);

  const products = await repo.driver.all(
    `SELECT cp.product_slug, cp.vendor_slug, cp.match_signal, p.name, p.category_slug
     FROM cve_product cp JOIN product p ON p.slug = cp.product_slug
     WHERE cp.cve_id = ?`,
    [id],
  );
  return c.json({ cve, products }, 200, { 'cache-control': API_CACHE });
});

api.get('/api/v1/health', async (c) => {
  const repo = repoFor(c.env);
  const runs = await repo.driver.all(
    `SELECT source, status, started_at, finished_at, records, error
     FROM ingest_run ORDER BY id DESC LIMIT 5`,
  );
  const total = await repo.driver.first<{ n: number }>('SELECT COUNT(*) AS n FROM cve');
  return c.json({ ok: true, cveCount: total?.n ?? 0, recentRuns: runs });
});

/**
 * Constant-time secret comparison.
 *
 * `a !== b` on strings returns as soon as two bytes differ, so how long the
 * comparison took is a function of how many leading bytes the caller got right.
 * Digesting both sides first fixes two things at once: the loop always runs over
 * 32 bytes regardless of input, and the length of the supplied token no longer
 * leaks either.
 *
 * Written against WebCrypto rather than Cloudflare's `crypto.subtle.timingSafeEqual`
 * so this file stays portable to Node and Deno, which is the whole point of
 * keeping platform coupling to the Worker package.
 */
async function secretsMatch(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [da, db] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b)),
  ]);
  const x = new Uint8Array(da);
  const y = new Uint8Array(db);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= (x[i] as number) ^ (y[i] as number);
  return diff === 0;
}

/**
 * Throttle for the admin endpoint.
 *
 * Per-isolate and in-memory, so it is a speed bump rather than a guarantee —
 * Cloudflare may run several isolates, and each starts with an empty map. That
 * is the right trade here: the token is the actual access control, and this
 * exists only so a discovered endpoint cannot be hammered cheaply from one
 * source. A real distributed limiter would mean Durable Objects, which the
 * portability rules rule out for a route the operator hits by hand.
 */
const ADMIN_ATTEMPTS = new Map<string, { count: number; resetAt: number }>();
const ADMIN_WINDOW_MS = 60_000;
const ADMIN_MAX_ATTEMPTS = 10;

function throttled(key: string, now = Date.now()): boolean {
  const seen = ADMIN_ATTEMPTS.get(key);
  if (!seen || now > seen.resetAt) {
    ADMIN_ATTEMPTS.set(key, { count: 1, resetAt: now + ADMIN_WINDOW_MS });
    // Bounded so a spray of forged client IPs cannot grow this without limit.
    if (ADMIN_ATTEMPTS.size > 1_000) {
      for (const [k, v] of ADMIN_ATTEMPTS) if (now > v.resetAt) ADMIN_ATTEMPTS.delete(k);
    }
    return false;
  }
  seen.count++;
  return seen.count > ADMIN_MAX_ATTEMPTS;
}

/**
 * Manual cron trigger, for verifying a fresh deploy without waiting 15 minutes.
 * Guarded by a secret so it cannot be used to run up our egress.
 *
 * The repository is public, so this path is public knowledge and the token is
 * the only control on it. Hence the constant-time compare and the throttle
 * above — neither is load-bearing on its own, but "the path is obscure" stopped
 * being part of the story the moment the source went up.
 */
api.post('/api/v1/admin/run/:job', async (c) => {
  const expected = (c.env as unknown as { ADMIN_TOKEN?: string }).ADMIN_TOKEN;
  const supplied = c.req.header('authorization') ?? '';

  if (throttled(c.req.header('cf-connecting-ip') ?? 'unknown')) {
    return c.json({ error: 'too many requests' }, 429);
  }
  if (!expected || !(await secretsMatch(supplied, `Bearer ${expected}`))) {
    return c.json({ error: 'unauthorized' }, 401);
  }
  const job = c.req.param('job');
  if (job === 'delta') await syncDelta(c.env);
  else if (job === 'enrichment') await syncEnrichment(c.env);
  else return c.json({ error: 'unknown job' }, 400);
  return c.json({ ok: true, job });
});

/**
 * Gap filler.
 *
 * Assets are served before the Worker, so this route only runs when a CVE has no
 * prerendered page — i.e. it was published since the last nightly rebuild. Rather
 * than 404 a record we demonstrably hold, redirect to its API representation.
 */
api.get('/cve/:id', async (c) => {
  const id = c.req.param('id').replace(/\.html$/i, '').toUpperCase();
  if (/^CVE-\d{4}-\d+$/.test(id)) {
    const exists = await repoFor(c.env).driver.first('SELECT 1 AS x FROM cve WHERE cve_id = ?', [
      id,
    ]);
    if (exists) return c.redirect(`/api/v1/cve/${id}`, 302);
  }
  return notFound(c.env);
});

/**
 * Anything else reaching the Worker had no matching asset. Serve the prerendered
 * 404 page with a real 404 status — the edge cannot do this itself without
 * `not_found_handling`, which would stop the gap-filler above from ever running.
 */
api.all('*', (c) => notFound(c.env));

async function notFound(env: Env): Promise<Response> {
  const page = await env.ASSETS.fetch(new Request('https://cybercve.com/404.html'));
  return new Response(page.body, {
    status: 404,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });
}

export default {
  fetch: api.fetch,

  async scheduled(event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    // Cron expressions must match wrangler.jsonc exactly.
    switch (event.cron) {
      case '*/15 * * * *':
        ctx.waitUntil(syncDelta(env));
        break;
      case '0 6 * * *':
        ctx.waitUntil(syncEnrichment(env));
        break;
      default:
        console.warn(`unhandled cron: ${event.cron}`);
    }
  },
};
