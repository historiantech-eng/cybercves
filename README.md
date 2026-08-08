# CyberCVEs

Tracks CVEs across leading cybersecurity vendors, broken down by product category —
firewall vs. endpoint vs. SASE vs. identity — with a live year-to-date counter,
risk-weighted vendor rankings, and AI-written trend commentary.

Mandatory coverage: **Fortinet, Palo Alto Networks, Cisco**. Expanding to ~15–20
category leaders.

Live at **[cybercve.com](https://cybercve.com)** — see [DEPLOY.md](DEPLOY.md).

## Status

End-to-end and deployable. The AI narrative layer and email capture are scaffolded in the
schema but not built.

| Package | What it does | State |
|---|---|---|
| `packages/core` | Types, CVSS extraction, risk scoring, taxonomy resolution. Zero platform deps. | done |
| `packages/db` | Schema, migrations, repository layer. All SQL lives here. | done |
| `packages/ingest` | CVE List, KEV, EPSS adapters + backfill/sync/verify/push CLIs. | done |
| `packages/worker` | Cloudflare Worker: cron ingest, JSON API, asset serving. | done |
| `packages/web` | Astro site: odometer, vendor race, client-side filtering. | done |
| AI insights | Weekly trend narratives (`insight` table exists). | not started |
| Email capture | Double opt-in list (`subscriber` table exists). | not started |

## Quick start

```bash
npm install
npm test           # 86 tests
npm run typecheck
npm run verify     # end-to-end check against live CVE List, KEV, and EPSS
```

`npm run verify` pulls six real advisories from all three mandatory vendors, runs them
through the full pipeline, and prints the rollups the site will render. It is the
fastest way to confirm the whole chain still agrees with reality.

## Commands

```bash
npm run sync -- --db "$PWD/cybercves.sqlite" --enrich    # incremental delta sync
npm run backfill -- --clone ../cvelistV5 --from 2016     # historical backfill
npm run taxonomy:review [-- --yaml]                      # unmapped-product queue
npm run discovery -- --db "$PWD/cybercves.sqlite" --cache .psirt-cache   # scrape attribution
npm run discovery:apply -- --db "$PWD/cybercves.sqlite"                  # apply committed data
npm run push:d1 -- --db "$PWD/cybercves.sqlite" --remote  # local SQLite -> D1
npm run build:web                                        # prerender the site
npm run deploy                                           # wrangler deploy
```

**Pass every path argument as an absolute path** — `--db`, `--clone`, `--cache`, `--out`,
`--dir`. `npm run -w` executes with its cwd inside the package directory, so
`--clone ../cvelistV5` resolves to `packages/cvelistV5` and `--out data/discovery/x.yaml`
writes `packages/ingest/data/discovery/x.yaml`. Two of those fail loudly; the write ones do
not — they create a real file in a directory nothing reads and exit zero. `$PWD/…` is the
habit to build. This has cost four separate debugging sessions, one of them a failed deploy.

`push:d1` **truncates every table** before reinserting, so the local database wholly
replaces D1. It refuses to run when local holds materially fewer CVEs than production, or
when local's newest CVE lags D1's by more than 36 hours — a stale snapshot silently deletes
whatever the 15-minute cron ingested in the meantime, and the resulting row count looks
perfectly healthy. `--force` overrides. Note that `npm run sync` cannot repair a snapshot
that is days behind: the delta feed carries only very recent changes, so the fix is a
`backfill` from a CVE List clone.

The backfill needs a local clone of the CVE List. Sparse-checkout only the years you track:

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/CVEProject/cvelistV5.git
cd cvelistV5 && git sparse-checkout set cves/2024 cves/2025 cves/2026
```

## Architecture

```
CVE List delta ─┐
CISA KEV ───────┼─→ ingest ─→ SQLite (canonical) ─→ push ─→ D1 ─→ Worker API ─┐
FIRST EPSS ─────┘                    │                          ↑             ├─→ browser
                                     └─→ Astro prerender ───────┘  (KV: live) ┘
```

The Worker's 15-minute cron writes fresh totals to **KV**, which the hero counter reads
client-side — so the counter stays live without a rebuild. Rebuilding the static site every
15 minutes would be ~2,880 builds/month, well past Cloudflare's limit; pages rebuild nightly
in GitHub Actions instead, and a CVE that exists in D1 without a page yet redirects to its
API record rather than 404ing.

## How it works

**The CVE List is the spine.** Fortinet, Cisco, and Palo Alto are all CNAs, so their
advisory data arrives as structured JSON — affected products, versions, CVSS, CWE, fixed
versions, and a link back to their PSIRT advisory. No scraping needed for the big three.
Vendor RSS feeds carry no structured fields and are used only as a freshness signal.

**Vendors are matched on three signals**, not just the CNA assigner: researchers routinely
file through MITRE for bugs in a vendor's product, and those CVEs would be silently
undercounted otherwise. The signal that matched is stored per row so attribution is auditable.

1. `cveMetadata.assignerShortName` ∈ the vendor's CNA short names
2. `affected[].vendor` or CPE vendor component matching a known alias
3. A reference URL on the vendor's PSIRT host

**The taxonomy is version-controlled data, not model output.** Product strings map to
categories via `data/products/*.yaml`. Anything unmatched goes to a review queue rather
than being dropped — silently discarding it is how a taxonomy quietly rots. AI proposes
mappings; a human approves them; the result is committed, so rebuilds stay deterministic.

**Who found it matters as much as how many.** Every CVE is labelled internal (the vendor's
own team), third party, customer, or not disclosed — the honest counterweight to raw counts.
Cisco and Palo Alto publish this in the CVE record. Fortinet publishes nothing there, but
every FortiGuard PSIRT advisory page carries a labelled `Discovered` field — Internal,
External, or Third-Party Library — which `npm run discovery` reads, falling back to
classifying the Acknowledgement prose only where the field is missing. `discovery_source`
records which of the three mechanisms supplied each value, and the site says so on the CVE
page, because a field the vendor published is not the same evidence as a rule applied to a
sentence. The percentage divides by *attributed* CVEs only, and is withheld entirely below
40% coverage: a rate computed from a thin slice is not a small error, it is a wrong claim
about a named company.

That pass is deliberately slow. `fortiguard.com/robots.txt` disallows `/*?*` and asks for a
2-second crawl delay, so the 48-page `/psirt?page=N` index — which carries the same column —
is off-limits, and the 336 individual advisory pages are walked instead at 20s each. Pages
are cached to disk (`--cache`), so a run that gets cut off resumes rather than restarting a
two-hour pass. A truncated run is the real hazard here: it reads as "Fortinet discloses
nothing", not as "we were blocked".

**The result is committed, not re-scraped.** `npm run discovery` writes
`data/discovery/*.yaml` — verdict, source mechanism, advisory ID, and the vendor's verbatim
acknowledgement per CVE — on the same principle as the product taxonomy: this is reviewed
data, not something a build step rediscovers from someone else's website. The nightly deploy
runs `npm run discovery:apply`, which reads that file and makes no network requests, so a
rebuild is deterministic and a FortiGuard outage cannot quietly strip Fortinet's attribution
on the way to production. Refreshing it is a deliberate act whose diff shows exactly which
verdicts moved. Writes **merge**: a resumed or year-scoped scrape covers a fraction of the
corpus, and replacing rather than merging would publish "Fortinet stopped disclosing".

**Like-for-like comparison.** `/compare` puts vendors side by side within the same product
category for any year — firewall against firewall, endpoint against endpoint — with optional
year-over-year deltas. Vendors are toggled in and out, and each keeps a fixed colour drawn
from its position in the full vendor list: assigning colour by rank would repaint the
survivors whenever one is switched off. Non-security categories are excluded by default so a
broad-portfolio vendor is not judged on products that are not security.

**Risk beats raw counts.** Raw CVE volume rewards vendors with *worse* disclosure programs.
The default metric weights severity, known exploitation, and exploit probability:

```
cve_risk = severity_weight x kev_multiplier x epss_factor
```

Constants live in `packages/core/src/scoring.ts` and the `/methodology` page renders from
that same module, so the published formula cannot drift from the one that produced the
numbers. Raw counts remain available as a toggle.

**Risk is scoped to a product category, not just filtered.** `/vendors` defaults to
Firewall / NGFW and recomputes the score from the CVEs affecting that line alone; all
security categories is one selection away. The ranking genuinely reorders — in 2026 Cisco
leads on total security risk with Fortinet second, but on firewalls alone Palo Alto is
second. A CVE in two categories scores in full under each, and once per category no matter
how many SKUs the advisory enumerates. The SQL for the formula lives in `RISK_SQL` in the
repository layer and is written once, so the vendor rollup and the category rollup cannot
quietly disagree.

**Broad-portfolio vendors are handled explicitly.** Cisco ships routers, switches, and
collaboration software alongside its security line. Those categories are flagged
`security: false` and excluded from default cross-vendor comparisons — otherwise Cisco's
breadth would swamp any comparison against a pure-play security vendor.

## Portability

Cloudflare is the launch target, not a commitment. The rules that keep migration cheap:

- `core/`, `ingest/`, and `db/` import **no** Cloudflare APIs — only `worker/` will.
- Every query goes through the repository layer, so SQLite → Postgres is mechanical.
- No Durable Objects and no KV-specific semantics. D1 is SQLite; R2 is S3-compatible.
- The same `NodeSqliteDriver` used in tests runs a full backfill on any machine.

## Data sources and attribution

| Source | Licence / terms |
|---|---|
| [CVE List](https://github.com/CVEProject/cvelistV5) | CVE® is a registered trademark of MITRE |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Public domain |
| [FIRST EPSS](https://first.org/epss) | **Attribution required** — must be credited in the footer and on /methodology |

Vendor names and trademarks are used nominatively to identify the products a CVE affects.
