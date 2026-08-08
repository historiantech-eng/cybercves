-- Discovery attribution: did the vendor find this itself, or did someone else?
--
-- Sourced from the CVE Record Format's `containers.cna.source.discovery`, which
-- Cisco and Palo Alto populate on most records. Fortinet publishes nothing there,
-- so their values come from scraping the Acknowledgement section of the PSIRT
-- advisory — `discovery_source` records which, because a heuristic over prose is
-- weaker evidence than a field the vendor published, and the site says so.

ALTER TABLE cve ADD COLUMN discovery TEXT;
ALTER TABLE cve ADD COLUMN discovery_source TEXT;
ALTER TABLE cve ADD COLUMN credit_text TEXT;

-- Vendor pages group by discovery within a year, so the counter query hits an index.
CREATE INDEX IF NOT EXISTS idx_cve_discovery ON cve(discovery);

-- Where a vendor publishes attribution, in their own terms.
--
-- Needed for fairness: a vendor showing 100% "not disclosed" looks less
-- transparent than its peers, when the real difference may be that it publishes
-- the same information somewhere we have not read yet. The site says which.
ALTER TABLE vendor ADD COLUMN discovery_note TEXT;
