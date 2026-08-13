# Deploying cybercve.com

One-time setup, then a repeatable release loop. Everything below runs from the repo root
unless noted.

## Prerequisites

- Node 22+ (`node --version`)
- A Cloudflare account with **cybercve.com** as an active zone
- `npx wrangler login` (opens a browser; run it yourself with `! npx wrangler login`)

---

## One-time setup

### 1. Authenticate

```bash
npx wrangler login
npx wrangler whoami        # confirm the right account
```

### 2. Create the D1 database

```bash
cd packages/worker
npx wrangler d1 create cybercve
```

Copy the printed `database_id` into `packages/worker/wrangler.jsonc`, replacing
`REPLACE_WITH_D1_DATABASE_ID`.

### 3. Create the KV namespace

```bash
npx wrangler kv namespace create LIVE
```

Copy the printed `id` into `wrangler.jsonc`, replacing `REPLACE_WITH_KV_NAMESPACE_ID`.

KV — not D1 — backs the live counter because `/api/v1/live` is the highest-traffic endpoint
on the site and must not spend a database read per visitor.

### 4. Apply migrations to D1

```bash
npx wrangler d1 migrations apply cybercve --remote
```

The deploy workflow now runs this on every deploy too, so a new migration reaches
production without anyone remembering to. This step is only needed for the first
manual bring-up.

### 5. Set the admin token

Lets you trigger a cron job on demand instead of waiting 15 minutes after a deploy,
and guards the feedback triage endpoints.

```bash
npx wrangler secret put ADMIN_TOKEN     # paste any long random string
```

Keep the same value in `~/.cybercve_admin_token` (mode 600) — that is where
`npm run feedback` reads it from.

### 6. Corrections form

The form at `/feedback` needs four secrets and two public values. Set the secrets
with `wrangler secret put`; **never paste any of them into a chat or a shared
terminal.**

```bash
npx wrangler secret put TURNSTILE_SECRET   # Turnstile widget's secret key
npx wrangler secret put FEEDBACK_SALT      # any long random string
npx wrangler secret put ALERT_FROM         # e.g. alerts@cybercve.com
npx wrangler secret put ALERT_TO           # where alerts land; kept secret so
                                           # the address stays out of this repo
```

The two public values are GitHub Actions **repository variables**, because they are
baked into the HTML and are not secret:

| Variable | Where it comes from |
|---|---|
| `PUBLIC_TURNSTILE_SITE_KEY` | Turnstile widget's site key |
| `PUBLIC_CF_ANALYTICS_TOKEN` | Cloudflare Web Analytics site token |

Then, in the Cloudflare dashboard:

1. **Email Routing** on `cybercve.com` — create `contact@` and `security@` forwarding
   to your real inbox, and **verify the destination address**. The Worker's
   `send_email` binding can only deliver to a verified address, which is what makes
   it safe to use without an API key.
2. **Turnstile** — create a widget for `cybercve.com`.
3. **Web Analytics** — enable for the site.

Until these exist the form fails closed: `verifyTurnstile()` returns false without a
secret, so submissions are rejected rather than accepted unverified. Alerts degrade
more gently — a missing `ALERT_EMAIL` binding just means the correction is stored
without emailing anyone, since the triage queue is the system of record.

---

## Loading data

The Node pipeline owns the canonical SQLite database; D1 is the runtime copy the Worker
reads.

### Full backfill (first run, ~10 years)

The CVE Project recommends a shallow clone over per-record HTTP. Sparse-checkout only the
years you need — the full history is far larger:

```bash
cd ..                       # alongside the repo, not inside it
git clone --depth 1 --filter=blob:none --sparse https://github.com/CVEProject/cvelistV5.git
cd cvelistV5
git sparse-checkout set cves/2016 cves/2017 cves/2018 cves/2019 cves/2020 \
                        cves/2021 cves/2022 cves/2023 cves/2024 cves/2025 cves/2026
cd ../cybercves

npm run backfill -- --clone ../cvelistV5 --from 2016 --db "$PWD/cybercves.sqlite"
```

### Incremental sync

```bash
npm run sync -- --db "$PWD/cybercves.sqlite" --enrich
```

> Pass an **absolute** `--db` path. `npm run -w` executes with its cwd inside the package
> directory, so a relative path lands somewhere you did not intend.

### Discovery attribution (optional)

Cisco and Palo Alto publish who found each vulnerability in the CVE record itself, so their
labels arrive with the backfill. Fortinet publishes it only in the Acknowledgement section
of each PSIRT advisory:

```bash
npm run discovery -- --db "$PWD/cybercves.sqlite" --concurrency 2 --delay 2500
```

> **Fortinet rate-limits this.** An unthrottled pass over ~350 advisories got the source IP
> blocked at the TLS layer, and the block persisted well beyond the run. The command exits
> non-zero when more than 10% of requests fail, precisely so a blocked run is never mistaken
> for "these CVEs have no acknowledgement" — a partial sample would produce a false
> self-found percentage. Re-run from a different address or with a much longer `--delay`.
> Until it completes, Fortinet shows as "not disclosed" with an explanatory note.

### Push to D1

```bash
npm run push:d1 -- --db "$PWD/cybercves.sqlite" --remote
```

---

## Building and deploying

```bash
CYBERCVE_DB="$PWD/cybercves.sqlite" npm run build -w @cybercves/web
cd packages/worker && npx wrangler deploy
```

Routing is **assets-first**. A request with a matching static file is served straight from
the edge and never invokes the Worker, so ordinary page views and asset loads cost nothing
against the 100k requests/day limit. Only paths with no matching asset fall through to the
Worker — precisely `/api/*` and CVE pages published since the last rebuild.

This is why `run_worker_first` and `not_found_handling` are both deliberately unset: either
one would put the Worker in front of every request (billing for static files) or short-circuit
404s at the edge (killing the gap-filler). The Worker serves `404.html` itself.

### Verify the deploy

```bash
curl https://cybercve.com/api/v1/health
curl https://cybercve.com/api/v1/live

# Trigger an ingest without waiting for the cron
curl -X POST https://cybercve.com/api/v1/admin/run/delta \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

`wrangler tail` streams live logs while you poke at it.

---

## The release loop

```bash
npm run sync -- --db "$PWD/cybercves.sqlite" --enrich   # 1. refresh local data
npm run push:d1 -- --db "$PWD/cybercves.sqlite" --remote # 2. push to D1
CYBERCVE_DB="$PWD/cybercves.sqlite" npm run build -w @cybercves/web  # 3. prerender
cd packages/worker && npx wrangler deploy                # 4. ship
```

Between deploys the site is **not** stale: the Worker's 15-minute cron writes fresh totals
into KV, and the hero counter reads that client-side. Only new *pages* wait for a rebuild,
and a CVE that exists in D1 without a page yet redirects to its API record rather than 404ing.

---

## Why the build cadence is what it is

Rebuilding the static site on every 15-minute ingest would be ~2,880 builds a month, well
past Cloudflare's 500/month Pages limit. Instead:

| Layer | Cadence | Mechanism |
|---|---|---|
| Live counter | 15 min | Worker cron → KV → fetched client-side. No rebuild. |
| KEV / EPSS | daily | Worker cron → D1 |
| Pages | daily | GitHub Actions → `wrangler deploy` (free for public repos, so the Pages build limit never applies) |

---

## Cost

| Service | Free tier | Expected use |
|---|---|---|
| Workers | 100k req/day | Well under until real traffic |
| D1 | 5 GB, 5M row reads/day | ~50k CVEs is a few hundred MB |
| KV | 100k reads/day | One small key |
| Cron triggers | 5 | 2 used; 1 reserved for the weekly AI narrative |
| GitHub Actions | free on public repos | one daily build |

Expected recurring cost: **the domain only.** The AI narrative layer, when added, is a few
dollars a month because it bills per new CVE, not per visitor.

---

## Not yet verified

- **The Postgres portability drill.** The plan calls for dumping the database to SQL and
  loading it into Postgres to prove the migration path before there is data to lose.
  Postgres is not installed on this machine, so only the SQLite round-trip has been run
  (schema + 9,182 generated rows load clean with matching counts). Run the Postgres half
  before relying on the escape hatch.
- **A live deploy.** Everything below the account boundary is verified — the Worker bundles
  (29 KiB gzipped, no Node-only imports), the site builds (1,369 pages), and the D1 SQL
  round-trips. Nothing has been pushed to Cloudflare; that needs your credentials.

## Known issues

- `npm audit` reports 3 advisories in `undici` via `miniflare`. Miniflare is wrangler's
  **local dev** simulator and is never deployed; npm's suggested "fix" downgrades wrangler
  to an older release. Accepted deliberately — re-check when wrangler bumps its miniflare.
- The site currently has no AI narrative layer and no email capture. Both are scaffolded in
  the schema (`insight`, `subscriber`) but not built.
