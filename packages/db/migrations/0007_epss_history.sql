-- Past EPSS scores for tracked CVEs, so the site can show which are rising.
--
-- A score going from 0.02 to 0.6 in a week is the earliest public signal that
-- attackers have taken an interest — it usually leads a CISA KEV listing.
-- The current score alone cannot show that.
--
-- BUILD-ONLY. Filled at build time from FIRST's dated daily snapshots (the day
-- 7 and 30 days before the current one), read only by the static /priority
-- page, and deliberately NOT pushed to D1 — see LOCAL_ONLY_TABLES in
-- packages/ingest/src/push-tables.ts. The Worker never reads it, and pushing it
-- would spend ~3,200 row-writes a night of the 100,000/day free-plan budget on
-- nothing. The table still exists in D1 because migrations apply everywhere.
--
-- Stateless by design: CI starts every run with an empty database, so history
-- accumulated here would be lost nightly. Re-fetching the two snapshots each
-- build gives the same answer without keeping anything.

CREATE TABLE IF NOT EXISTS epss_history (
  cve_id     TEXT NOT NULL,
  as_of      TEXT NOT NULL,
  score      REAL NOT NULL,
  percentile REAL NOT NULL,
  PRIMARY KEY (cve_id, as_of)
);

CREATE INDEX IF NOT EXISTS idx_epss_history_as_of ON epss_history(as_of);
