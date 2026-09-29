-- The full affected-version list for entries whose cve_affected.versions was
-- capped at MAX_VERSION_RANGES (50).
--
-- Cisco enumerates every affected release instead of writing ranges: 187 ASA
-- versions on CVE-2024-20353, up to 8,138 on one IOS record, ~132,000 across
-- the Cisco CVEs tracked here. 1,093 of Cisco's 3,207 entries exceed the cap,
-- so /check could not tell whether a release was listed or merely cut off.
--
-- BUILD-ONLY, like epss_history: written by the Node pipeline (backfill and
-- sync pass `fullVersions`), read only by the static build, listed in
-- LOCAL_ONLY_TABLES and never pushed to D1. The cap stays on cve_affected
-- because that row DOES reach D1, where one enumerated record would exceed the
-- statement-size limit, and nothing served at runtime needs the full list.
--
-- `versions` is packed (see packVersions in core): one [version, status,
-- lessThan, lessThanOrEqual] tuple per range with trailing nulls dropped,
-- about a tenth of the size of the object form.

CREATE TABLE IF NOT EXISTS affected_versions_full (
  affected_id INTEGER PRIMARY KEY,
  cve_id      TEXT NOT NULL,
  versions    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_affected_versions_full_cve ON affected_versions_full(cve_id);
