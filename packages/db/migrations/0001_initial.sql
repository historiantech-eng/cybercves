-- CyberCVEs initial schema.
--
-- SQLite dialect, targeting Cloudflare D1. Deliberately avoids D1-specific syntax
-- so `sqlite3 .dump` loads into Postgres with only mechanical edits — the
-- portability drill in the plan depends on that staying true.
--
-- Conventions: dates are ISO-8601 TEXT (sortable as strings, comparable in SQL),
-- booleans are INTEGER 0/1, and JSON blobs are TEXT.

-- ---------------------------------------------------------------------------
-- Taxonomy, synced from /data YAML on every ingest run. YAML is the source of
-- truth; these tables are a queryable projection of it.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS category (
  slug        TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  sort        INTEGER NOT NULL DEFAULT 999,
  -- 0 for portfolio products outside the security line (routing, collaboration).
  -- Excluded from default cross-vendor comparisons so a broad-portfolio vendor
  -- like Cisco is not penalised against a pure-play security vendor.
  is_security INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS vendor (
  slug            TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  cna_short_names TEXT NOT NULL DEFAULT '[]',
  aliases         TEXT NOT NULL DEFAULT '[]',
  psirt_hosts     TEXT NOT NULL DEFAULT '[]',
  psirt_url       TEXT,
  homepage        TEXT,
  adapter         TEXT NOT NULL DEFAULT 'cvelist'
);

CREATE TABLE IF NOT EXISTS product (
  slug          TEXT PRIMARY KEY,
  vendor_slug   TEXT NOT NULL REFERENCES vendor(slug) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  category_slug TEXT NOT NULL REFERENCES category(slug),
  aliases       TEXT NOT NULL DEFAULT '[]',
  -- Regex sources, stored so the Worker resolves products identically to the
  -- Node pipeline. Without these the 15-minute sync and the nightly run would
  -- disagree, and the same CVE would map differently depending on which process
  -- happened to see it first.
  patterns      TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_product_vendor   ON product(vendor_slug);
CREATE INDEX IF NOT EXISTS idx_product_category ON product(category_slug);

-- ---------------------------------------------------------------------------
-- CVE core
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cve (
  cve_id              TEXT PRIMARY KEY,
  assigner_short_name TEXT,
  state               TEXT NOT NULL DEFAULT 'PUBLISHED',
  date_published      TEXT,
  date_updated        TEXT,
  date_reserved       TEXT,
  -- Denormalized publication year: the YTD counter and the year-sharded client
  -- indexes both filter on it, and extracting it in SQL on every query would
  -- prevent index use.
  published_year      INTEGER,
  title               TEXT,
  description         TEXT,
  cvss_version        TEXT,
  cvss_vector         TEXT,
  cvss_base_score     REAL,
  cvss_severity       TEXT,
  cvss_source         TEXT,
  cwe_ids             TEXT NOT NULL DEFAULT '[]',
  solution            TEXT,
  refs                TEXT NOT NULL DEFAULT '[]',
  -- FNV-1a fingerprint of the fields we persist; lets a re-sync skip unchanged
  -- records without rewriting rows.
  source_hash         TEXT NOT NULL,
  first_seen_at       TEXT NOT NULL,
  last_synced_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_year      ON cve(published_year);
CREATE INDEX IF NOT EXISTS idx_cve_published ON cve(date_published);
CREATE INDEX IF NOT EXISTS idx_cve_severity  ON cve(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_cve_assigner  ON cve(assigner_short_name);

CREATE TABLE IF NOT EXISTS cve_affected (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id         TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  vendor_raw     TEXT,
  product_raw    TEXT,
  cpes           TEXT NOT NULL DEFAULT '[]',
  -- Capped at 50 ranges per entry. Some vendors enumerate every patch level
  -- instead of expressing a range (one Cisco record lists 2,699), which exceeds
  -- SQLite's statement-size limit on insert and dwarfs everything else we store.
  versions       TEXT NOT NULL DEFAULT '[]',
  versions_truncated INTEGER NOT NULL DEFAULT 0,
  version_count  INTEGER NOT NULL DEFAULT 0,
  default_status TEXT
);

CREATE INDEX IF NOT EXISTS idx_cve_affected_cve ON cve_affected(cve_id);

-- Resolved link from a CVE to one of our canonical products.
CREATE TABLE IF NOT EXISTS cve_product (
  cve_id       TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  product_slug TEXT NOT NULL REFERENCES product(slug) ON DELETE CASCADE,
  vendor_slug  TEXT NOT NULL,
  -- How the CVE was attributed: cna-assigner | affected-vendor | cpe | reference-host.
  -- Stored so mis-attribution is auditable rather than invisible.
  match_signal TEXT NOT NULL,
  PRIMARY KEY (cve_id, product_slug)
);

CREATE INDEX IF NOT EXISTS idx_cve_product_product ON cve_product(product_slug);
CREATE INDEX IF NOT EXISTS idx_cve_product_vendor  ON cve_product(vendor_slug);

-- ---------------------------------------------------------------------------
-- Enrichment
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS kev (
  cve_id           TEXT PRIMARY KEY,
  date_added       TEXT NOT NULL,
  due_date         TEXT,
  ransomware_known INTEGER NOT NULL DEFAULT 0,
  vendor_project   TEXT,
  product          TEXT
);

CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev(date_added);

CREATE TABLE IF NOT EXISTS epss (
  cve_id     TEXT PRIMARY KEY,
  score      REAL NOT NULL,
  percentile REAL NOT NULL,
  as_of      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_epss_score ON epss(score);

-- ---------------------------------------------------------------------------
-- Vendor advisories (FG-IR-25-254, PAN-SA-2024-0001, cisco-sa-...)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS advisory (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_slug         TEXT NOT NULL REFERENCES vendor(slug) ON DELETE CASCADE,
  vendor_advisory_id  TEXT NOT NULL,
  url                 TEXT NOT NULL,
  title               TEXT,
  published           TEXT,
  severity            TEXT,
  UNIQUE (vendor_slug, vendor_advisory_id)
);

CREATE TABLE IF NOT EXISTS advisory_cve (
  advisory_id INTEGER NOT NULL REFERENCES advisory(id) ON DELETE CASCADE,
  cve_id      TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  PRIMARY KEY (advisory_id, cve_id)
);

-- ---------------------------------------------------------------------------
-- AI insights. Cached by inputs_hash so an unchanged dataset never regenerates
-- (and never re-bills) a narrative.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS insight (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  scope_type   TEXT NOT NULL,           -- 'global' | 'vendor' | 'category' | 'product'
  scope_key    TEXT NOT NULL DEFAULT '',
  period       TEXT NOT NULL,           -- e.g. '2026-W30', '2026-07'
  generated_at TEXT NOT NULL,
  model        TEXT NOT NULL,
  body_md      TEXT NOT NULL,
  inputs_hash  TEXT NOT NULL,
  UNIQUE (scope_type, scope_key, period)
);

-- ---------------------------------------------------------------------------
-- Taxonomy review queue. Unmapped product strings are recorded rather than
-- dropped — silently discarding them is how a taxonomy quietly rots.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS unmapped_product (
  vendor_slug        TEXT NOT NULL,
  product_key        TEXT NOT NULL,     -- normalized form, the dedupe key
  product_raw        TEXT NOT NULL,     -- first raw spelling seen
  vendor_raw         TEXT,
  first_seen         TEXT NOT NULL,
  last_seen          TEXT NOT NULL,
  seen_count         INTEGER NOT NULL DEFAULT 1,
  suggested_category TEXT,
  confidence         REAL,
  -- pending | approved | rejected. Approved entries are written back to YAML and
  -- committed, keeping the taxonomy version-controlled data rather than model output.
  status             TEXT NOT NULL DEFAULT 'pending',
  PRIMARY KEY (vendor_slug, product_key)
);

CREATE INDEX IF NOT EXISTS idx_unmapped_status ON unmapped_product(status, seen_count DESC);

-- ---------------------------------------------------------------------------
-- Operations
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ingest_run (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  source      TEXT NOT NULL,
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  status      TEXT NOT NULL DEFAULT 'running',
  records     INTEGER NOT NULL DEFAULT 0,
  error       TEXT
);

CREATE INDEX IF NOT EXISTS idx_ingest_run_source ON ingest_run(source, started_at DESC);

-- Cursor for incremental syncs, so a restart resumes rather than refetching.
CREATE TABLE IF NOT EXISTS sync_state (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Scaffold for the future paid tier. No auth or billing in v1; the table exists
-- so email capture can start collecting a list from day one.
CREATE TABLE IF NOT EXISTS subscriber (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  email        TEXT NOT NULL UNIQUE,
  created_at   TEXT NOT NULL,
  confirmed_at TEXT,
  -- Double opt-in token; unconfirmed rows are never notified.
  confirm_token TEXT,
  prefs        TEXT NOT NULL DEFAULT '{}',
  tier         TEXT NOT NULL DEFAULT 'free'
);
