-- Acquired sub-brands within a vendor.
--
-- A product may belong to a brand the parent vendor bought — Splunk under
-- Cisco, CyberArk under Palo Alto — which is still what upstream writes in
-- `affected[].vendor`. The resolver matches an entry naming that brand against
-- the brand's products alone; without the column the Worker rebuilds the
-- resolver from D1 without brands and resolves differently from the Node
-- pipeline, which is exactly the divergence loadTaxonomy exists to avoid.
--
-- Nullable: the overwhelming majority of products are the vendor's own.
ALTER TABLE product ADD COLUMN brand TEXT;

-- The spellings upstream uses for each brand, as {name: [spelling, ...]}. The
-- resolver reads the entry's raw vendor string through this map to decide which
-- scope to search, so the Worker needs it as much as the Node pipeline does.
ALTER TABLE vendor ADD COLUMN brands TEXT NOT NULL DEFAULT '{}';

-- Catches anything from the brand that no sibling product claimed. Opt-in, and
-- only ever consulted for an entry that names the brand.
ALTER TABLE product ADD COLUMN brand_fallback INTEGER NOT NULL DEFAULT 0;

-- Config order, preserved.
--
-- resolveProductName takes the FIRST pattern that matches, so the order of
-- data/products/*.yaml is load-bearing: Enterprise Security must be tried
-- before Enterprise, and every "ORDER MATTERS" comment in those files says so.
-- loadTaxonomy read the table `ORDER BY slug`, which alphabetised that away, so
-- the Worker's delta sync and the Node pipeline could answer differently and
-- which one a CVE got depended on which process saw it first. Exact aliases are
-- a hash lookup and were never affected, which is why nothing visibly broke;
-- anything reaching the pattern path was. "Splunk Enterprise 9.1.2" resolved to
-- the catch-all `splunk-apps` under the alphabetical order, because that slug
-- sorts ahead of `splunk-enterprise` and its '^splunk\b' matched first.
--
-- Existing rows default to 0 and so keep today's alphabetical order until the
-- next syncTaxonomy writes the real positions; only the config knows them.
ALTER TABLE product ADD COLUMN sort INTEGER NOT NULL DEFAULT 0;
