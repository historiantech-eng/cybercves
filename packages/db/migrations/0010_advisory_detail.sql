-- What a vendor advisory says beyond its title, for the advisories the Cisco
-- openVuln adapter now writes into `advisory` and `advisory_cve` (both existed
-- since 0001 with nothing filling them).
--
-- `severity` already holds the vendor's own rating. For Cisco that is the
-- Security Impact Rating (Critical/High/Medium/Low/Informational), which Cisco
-- sets per advisory and which can differ from the CVSS band of any one CVE in
-- it. Kept apart from cve.cvss_severity for that reason; the CVE page shows
-- both and says which is which.
--
-- `last_updated` and `revision` matter because Cisco revises advisories in
-- place: cisco-sa-asaftdvirtual-dos-MuenGnYR went from 1.0 to 2.1 two years
-- after publication, widening the affected products. A reader who checked the
-- 1.0 advisory needs to see that it moved.
--
-- `status` is Cisco's Interim/Final. An Interim advisory is published while
-- the investigation is still open, and its affected-product list can grow.
--
-- `bug_ids` is a JSON array of Cisco bug IDs (CSCwj10955), the handle TAC and
-- the Bug Search Tool use. Empty array when the vendor gave none.
--
-- These tables ARE pushed to D1 (see PUSHED_TABLES): a few hundred rows, well
-- inside the free plan's daily write budget.
ALTER TABLE advisory ADD COLUMN last_updated TEXT;
ALTER TABLE advisory ADD COLUMN revision TEXT;
ALTER TABLE advisory ADD COLUMN status TEXT;
ALTER TABLE advisory ADD COLUMN cvss_base_score REAL;
ALTER TABLE advisory ADD COLUMN bug_ids TEXT NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_advisory_cve_cve ON advisory_cve(cve_id);
