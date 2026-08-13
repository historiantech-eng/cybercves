import type {
  CategoryConfig,
  EpssEntry,
  KevEntry,
  NormalizedCve,
  ProductConfig,
  ResolvedProduct,
  UnmappedProduct,
  VendorFileConfig,
} from '@cybercves/core';
import { normalizeKey, publishedYear } from '@cybercves/core';
import type { SqlDriver, SqlValue, Statement } from './driver.js';

/**
 * Every SQL statement in the project lives here.
 *
 * Nothing above this layer writes SQL, so swapping D1 for Postgres means editing
 * one file rather than auditing the whole codebase for embedded queries.
 */

const json = (value: unknown): string => JSON.stringify(value);

/**
 * The risk formula, in SQL, written exactly once.
 *
 * It mirrors `cveRisk()` in @cybercves/core — severity weight, escalated 4x for
 * confirmed exploitation, scaled by exploit probability. Two rollups need it, and
 * a second hand-transcribed copy is how the vendor ranking and the category
 * ranking quietly stop agreeing with each other and with /methodology.
 *
 * Expects `c` (cve), `k` (kev) and `e` (epss) in scope, and must only ever be
 * summed over a DISTINCT-ed set of CVE ids — see the CTEs below.
 */
const RISK_SQL = `(CASE c.cvss_severity
                     WHEN 'CRITICAL' THEN 10
                     WHEN 'HIGH'     THEN 5
                     WHEN 'MEDIUM'   THEN 2
                     WHEN 'LOW'      THEN 1
                     WHEN 'NONE'     THEN 0
                     ELSE 1
                   END)
                  * (CASE WHEN k.cve_id IS NOT NULL THEN 4 ELSE 1 END)
                  * (1 + COALESCE(e.score, 0))`;

export interface UpsertResult {
  inserted: number;
  updated: number;
  skipped: number;
}

export class Repository {
  readonly #db: SqlDriver;

  constructor(db: SqlDriver) {
    this.#db = db;
  }

  get driver(): SqlDriver {
    return this.#db;
  }

  // -------------------------------------------------------------------------
  // Taxonomy projection. YAML in /data is the source of truth; these tables are
  // a queryable copy, replaced wholesale on each run.
  // -------------------------------------------------------------------------

  async syncTaxonomy(
    categories: readonly CategoryConfig[],
    vendors: readonly VendorFileConfig[],
    products: readonly ProductConfig[],
  ): Promise<void> {
    const statements: Statement[] = [];

    for (const c of categories) {
      statements.push({
        sql: `INSERT INTO category (slug, name, description, sort, is_security)
              VALUES (?, ?, ?, ?, ?)
              ON CONFLICT(slug) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                sort = excluded.sort,
                is_security = excluded.is_security`,
        params: [c.slug, c.name, c.description, c.sort, c.security ? 1 : 0],
      });
    }

    for (const v of vendors) {
      statements.push({
        sql: `INSERT INTO vendor (slug, name, cna_short_names, aliases, psirt_hosts, psirt_url, homepage, adapter, discovery_note)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(slug) DO UPDATE SET
                name = excluded.name,
                cna_short_names = excluded.cna_short_names,
                aliases = excluded.aliases,
                psirt_hosts = excluded.psirt_hosts,
                psirt_url = excluded.psirt_url,
                homepage = excluded.homepage,
                adapter = excluded.adapter,
                discovery_note = excluded.discovery_note`,
        params: [
          v.slug,
          v.name,
          json(v.cnaShortNames),
          json(v.aliases),
          json(v.psirtHosts),
          v.psirtUrl,
          v.homepage,
          v.adapter,
          v.discoveryNote,
        ],
      });
    }

    for (const p of products) {
      statements.push({
        sql: `INSERT INTO product (slug, vendor_slug, name, category_slug, aliases, patterns)
              VALUES (?, ?, ?, ?, ?, ?)
              ON CONFLICT(slug) DO UPDATE SET
                vendor_slug = excluded.vendor_slug,
                name = excluded.name,
                category_slug = excluded.category_slug,
                aliases = excluded.aliases,
                patterns = excluded.patterns`,
        params: [p.slug, p.vendorSlug, p.name, p.categorySlug, json(p.aliases), json(p.patterns)],
      });
    }

    await this.#db.batch(statements);
  }

  /**
   * Read the taxonomy back out of the database.
   *
   * The Worker has no filesystem, so it rebuilds its TaxonomyResolver from these
   * tables rather than from the YAML. The daily Node run syncs YAML -> tables;
   * the Worker only ever reads.
   */
  async loadTaxonomy(): Promise<{
    categories: CategoryConfig[];
    vendors: VendorFileConfig[];
    products: ProductConfig[];
  }> {
    const categories = (
      await this.#db.all<{
        slug: string;
        name: string;
        description: string;
        sort: number;
        is_security: number;
      }>('SELECT slug, name, description, sort, is_security FROM category ORDER BY sort')
    ).map((row) => ({
      slug: row.slug,
      name: row.name,
      description: row.description,
      sort: row.sort,
      security: row.is_security === 1,
    }));

    const vendors = (
      await this.#db.all<{
        slug: string;
        name: string;
        cna_short_names: string;
        aliases: string;
        psirt_hosts: string;
        psirt_url: string | null;
        homepage: string | null;
        adapter: string;
      }>('SELECT * FROM vendor ORDER BY slug')
    ).map((row) => ({
      slug: row.slug,
      name: row.name,
      cnaShortNames: JSON.parse(row.cna_short_names) as string[],
      aliases: JSON.parse(row.aliases) as string[],
      psirtHosts: JSON.parse(row.psirt_hosts) as string[],
      psirtUrl: row.psirt_url,
      homepage: row.homepage,
      adapter: row.adapter as VendorFileConfig['adapter'],
      rssUrl: null,
      jsonUrlTemplate: null,
      advisoryIdPattern: null,
      internalBrandMarkers: [],
      discoveryNote: null,
    }));

    const products = (
      await this.#db.all<{
        slug: string;
        vendor_slug: string;
        name: string;
        category_slug: string;
        aliases: string;
        patterns: string;
      }>(
        'SELECT slug, vendor_slug, name, category_slug, aliases, patterns FROM product ORDER BY slug',
      )
    ).map((row) => ({
      slug: row.slug,
      vendorSlug: row.vendor_slug,
      name: row.name,
      categorySlug: row.category_slug,
      aliases: JSON.parse(row.aliases) as string[],
      patterns: JSON.parse(row.patterns) as string[],
    }));

    return { categories, vendors, products };
  }

  // -------------------------------------------------------------------------
  // CVE ingest
  // -------------------------------------------------------------------------

  /** Existing fingerprints, so a re-sync can skip records that have not changed. */
  async getSourceHashes(cveIds: readonly string[]): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    if (!cveIds.length) return out;

    // Chunked to stay well inside SQLite's variable limit (999 by default).
    for (let i = 0; i < cveIds.length; i += 400) {
      const chunk = cveIds.slice(i, i + 400);
      const rows = await this.#db.all<{ cve_id: string; source_hash: string }>(
        `SELECT cve_id, source_hash FROM cve WHERE cve_id IN (${chunk.map(() => '?').join(',')})`,
        chunk as SqlValue[],
      );
      for (const row of rows) out.set(row.cve_id, row.source_hash);
    }
    return out;
  }

  /**
   * Persist a batch of normalized CVEs and their resolved product links.
   *
   * Unchanged records are skipped by fingerprint rather than rewritten — upstream
   * republishes touch a large share of records daily, and rewriting them all
   * would burn D1's free-tier write budget for no benefit.
   */
  async upsertCves(
    entries: ReadonlyArray<{ cve: NormalizedCve; resolved: readonly ResolvedProduct[] }>,
    now = new Date().toISOString(),
    options: {
      /**
       * Rewrite even when the upstream record is byte-identical.
       *
       * The fingerprint skip below is keyed on the *source record*, not on our
       * mapping of it — so editing data/products/*.yaml changes nothing for CVEs
       * already stored. That is the documented workflow (propose a mapping,
       * review it, commit it), and without this flag the commit silently applies
       * only to CVEs that happen to be republished afterwards. Adding Splunk to
       * Cisco mapped 41 new records and left 69 existing ones untouched.
       *
       * Off by default: a delta sync must keep skipping republished records, or
       * it burns D1's write budget rewriting rows whose content did not change.
       */
      reresolve?: boolean;
    } = {},
  ): Promise<UpsertResult> {
    const result: UpsertResult = { inserted: 0, updated: 0, skipped: 0 };
    if (!entries.length) return result;

    const existing = await this.getSourceHashes(entries.map((e) => e.cve.cveId));
    const statements: Statement[] = [];

    for (const { cve, resolved } of entries) {
      const known = existing.get(cve.cveId);
      if (known === cve.sourceHash && !options.reresolve) {
        result.skipped++;
        continue;
      }
      known === undefined ? result.inserted++ : result.updated++;

      statements.push({
        sql: `INSERT INTO cve (
                cve_id, assigner_short_name, state, date_published, date_updated, date_reserved,
                published_year, title, description, cvss_version, cvss_vector, cvss_base_score,
                cvss_severity, cvss_source, cwe_ids, solution, refs, source_hash,
                discovery, discovery_source, credit_text,
                first_seen_at, last_synced_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(cve_id) DO UPDATE SET
                assigner_short_name = excluded.assigner_short_name,
                state = excluded.state,
                date_published = excluded.date_published,
                date_updated = excluded.date_updated,
                date_reserved = excluded.date_reserved,
                published_year = excluded.published_year,
                title = excluded.title,
                description = excluded.description,
                cvss_version = excluded.cvss_version,
                cvss_vector = excluded.cvss_vector,
                cvss_base_score = excluded.cvss_base_score,
                cvss_severity = excluded.cvss_severity,
                cvss_source = excluded.cvss_source,
                cwe_ids = excluded.cwe_ids,
                solution = excluded.solution,
                refs = excluded.refs,
                source_hash = excluded.source_hash,
                -- COALESCE keeps a scraped value when the CVE List still has none:
                -- a re-sync must not wipe an acknowledgement the scraper found.
                discovery = COALESCE(excluded.discovery, cve.discovery),
                discovery_source = COALESCE(excluded.discovery_source, cve.discovery_source),
                credit_text = COALESCE(excluded.credit_text, cve.credit_text),
                last_synced_at = excluded.last_synced_at`,
        params: [
          cve.cveId,
          cve.assignerShortName,
          cve.state,
          cve.datePublished,
          cve.dateUpdated,
          cve.dateReserved,
          publishedYear(cve),
          cve.title,
          cve.description,
          cve.cvss?.version ?? null,
          cve.cvss?.vectorString ?? null,
          cve.cvss?.baseScore ?? null,
          cve.cvss?.severity ?? null,
          cve.cvss?.source ?? null,
          json(cve.cweIds),
          cve.solution,
          json(cve.references),
          cve.sourceHash,
          cve.discovery,
          cve.discoverySource,
          cve.creditText,
          now,
          now,
        ],
      });

      // Affected entries and product links are replaced rather than merged: an
      // upstream revision can remove an affected product, and a merge would keep
      // showing a product the vendor has since said is unaffected.
      statements.push({ sql: 'DELETE FROM cve_affected WHERE cve_id = ?', params: [cve.cveId] });
      for (const affected of cve.affected) {
        statements.push({
          sql: `INSERT INTO cve_affected
                  (cve_id, vendor_raw, product_raw, cpes, versions, versions_truncated, version_count, default_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          params: [
            cve.cveId,
            affected.vendorRaw,
            affected.productRaw,
            json(affected.cpes),
            json(affected.versions),
            affected.versionsTruncated ? 1 : 0,
            affected.versionCount,
            affected.defaultStatus,
          ],
        });
      }

      statements.push({ sql: 'DELETE FROM cve_product WHERE cve_id = ?', params: [cve.cveId] });
      for (const link of resolved) {
        statements.push({
          sql: `INSERT INTO cve_product (cve_id, product_slug, vendor_slug, match_signal)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(cve_id, product_slug) DO UPDATE SET
                  vendor_slug = excluded.vendor_slug,
                  match_signal = excluded.match_signal`,
          params: [cve.cveId, link.productSlug, link.vendorSlug, link.matchSignal],
        });
      }
    }

    await this.#db.batch(statements);
    return result;
  }

  // -------------------------------------------------------------------------
  // Enrichment
  // -------------------------------------------------------------------------

  async upsertKev(entries: readonly KevEntry[]): Promise<number> {
    if (!entries.length) return 0;
    await this.#db.batch(
      entries.map((k) => ({
        sql: `INSERT INTO kev (cve_id, date_added, due_date, ransomware_known, vendor_project, product)
              VALUES (?, ?, ?, ?, ?, ?)
              ON CONFLICT(cve_id) DO UPDATE SET
                date_added = excluded.date_added,
                due_date = excluded.due_date,
                ransomware_known = excluded.ransomware_known,
                vendor_project = excluded.vendor_project,
                product = excluded.product`,
        params: [
          k.cveId,
          k.dateAdded,
          k.dueDate,
          k.ransomwareKnown ? 1 : 0,
          k.vendorProject,
          k.product,
        ] as SqlValue[],
      })),
    );
    return entries.length;
  }

  /**
   * EPSS ships a full ~290k-row snapshot daily. Only rows for CVEs we actually
   * track are worth storing — the rest would dwarf our own data and eat the D1
   * free-tier storage budget for nothing.
   */
  async upsertEpssForKnownCves(entries: readonly EpssEntry[]): Promise<number> {
    if (!entries.length) return 0;
    let written = 0;
    for (let i = 0; i < entries.length; i += 400) {
      const chunk = entries.slice(i, i + 400);
      const ids = chunk.map((e) => e.cveId);
      const known = new Set(
        (
          await this.#db.all<{ cve_id: string }>(
            `SELECT cve_id FROM cve WHERE cve_id IN (${ids.map(() => '?').join(',')})`,
            ids as SqlValue[],
          )
        ).map((r) => r.cve_id),
      );
      const relevant = chunk.filter((e) => known.has(e.cveId));
      if (!relevant.length) continue;

      await this.#db.batch(
        relevant.map((e) => ({
          sql: `INSERT INTO epss (cve_id, score, percentile, as_of)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                  score = excluded.score,
                  percentile = excluded.percentile,
                  as_of = excluded.as_of`,
          params: [e.cveId, e.score, e.percentile, e.asOf] as SqlValue[],
        })),
      );
      written += relevant.length;
    }
    return written;
  }

  // -------------------------------------------------------------------------
  // Taxonomy review queue
  // -------------------------------------------------------------------------

  async recordUnmapped(entries: readonly UnmappedProduct[], now = new Date().toISOString()): Promise<void> {
    const rows = entries.filter((e) => e.vendorSlug);
    if (!rows.length) return;

    await this.#db.batch(
      rows.map((e) => ({
        sql: `INSERT INTO unmapped_product
                (vendor_slug, product_key, product_raw, vendor_raw, first_seen, last_seen, seen_count)
              VALUES (?, ?, ?, ?, ?, ?, 1)
              ON CONFLICT(vendor_slug, product_key) DO UPDATE SET
                last_seen = excluded.last_seen,
                seen_count = unmapped_product.seen_count + 1`,
        params: [
          e.vendorSlug,
          normalizeKey(e.productRaw),
          e.productRaw,
          e.vendorRaw,
          now,
          now,
        ] as SqlValue[],
      })),
    );
  }

  /** Every pending gap, for re-testing against the current taxonomy. */
  async listPendingUnmapped() {
    return this.#db.all<{ vendor_slug: string; product_key: string; product_raw: string }>(
      `SELECT vendor_slug, product_key, product_raw
         FROM unmapped_product
        WHERE status = 'pending'`,
    );
  }

  /**
   * Drop gaps that the taxonomy now answers.
   *
   * Without this the queue is append-only: a product mapped today keeps its
   * `pending` row forever, so the list people are meant to act on fills with
   * things already done and stops being read. Deleted rather than marked
   * resolved — if the mapping is later removed, the string simply reappears on
   * the next run, which is the honest state.
   */
  async clearResolvedUnmapped(
    keys: ReadonlyArray<{ vendorSlug: string; productKey: string }>,
  ): Promise<number> {
    if (!keys.length) return 0;
    await this.#db.batch(
      keys.map((k) => ({
        sql: `DELETE FROM unmapped_product WHERE vendor_slug = ? AND product_key = ?`,
        params: [k.vendorSlug, k.productKey] as SqlValue[],
      })),
    );
    return keys.length;
  }

  /** Review queue, most frequently seen first — the highest-leverage gaps. */
  async getUnmappedForReview(limit = 100) {
    return this.#db.all<{
      vendor_slug: string;
      product_raw: string;
      seen_count: number;
      suggested_category: string | null;
      confidence: number | null;
    }>(
      `SELECT vendor_slug, product_raw, seen_count, suggested_category, confidence
       FROM unmapped_product
       WHERE status = 'pending'
       ORDER BY seen_count DESC, product_raw ASC
       LIMIT ?`,
      [limit],
    );
  }

  // -------------------------------------------------------------------------
  // Site queries
  // -------------------------------------------------------------------------

  /**
   * Payload behind the hero odometer.
   *
   * Written to R2/KV on every ingest run and fetched client-side, so the counter
   * stays near-real-time without triggering a static rebuild.
   */
  async getLiveSnapshot(year: number, now = new Date()) {
    const todayStart = `${now.toISOString().slice(0, 10)}T00:00:00.000Z`;

    const total = await this.#db.first<{ n: number }>(
      'SELECT COUNT(*) AS n FROM cve WHERE published_year = ? AND state = ?',
      [year, 'PUBLISHED'],
    );

    const today = await this.#db.first<{ n: number }>(
      'SELECT COUNT(*) AS n FROM cve WHERE date_published >= ? AND state = ?',
      [todayStart, 'PUBLISHED'],
    );

    // DISTINCT because one CVE can affect several products from the same vendor;
    // counting links instead of CVEs would inflate every vendor's total.
    const byVendor = await this.#db.all<{ vendor_slug: string; name: string; n: number }>(
      `SELECT v.slug AS vendor_slug, v.name AS name, COUNT(DISTINCT cp.cve_id) AS n
       FROM cve_product cp
       JOIN cve c    ON c.cve_id = cp.cve_id
       JOIN vendor v ON v.slug = cp.vendor_slug
       WHERE c.published_year = ? AND c.state = 'PUBLISHED'
       GROUP BY v.slug, v.name
       ORDER BY n DESC`,
      [year],
    );

    const latest = await this.#db.all<{
      cve_id: string;
      date_published: string | null;
      cvss_severity: string | null;
      vendor_slug: string | null;
    }>(
      `SELECT c.cve_id, c.date_published, c.cvss_severity,
              (SELECT cp.vendor_slug FROM cve_product cp WHERE cp.cve_id = c.cve_id LIMIT 1) AS vendor_slug
       FROM cve c
       WHERE c.state = 'PUBLISHED' AND c.date_published IS NOT NULL
       ORDER BY c.date_published DESC
       LIMIT 10`,
    );

    return {
      year,
      generatedAt: now.toISOString(),
      total: total?.n ?? 0,
      addedToday: today?.n ?? 0,
      byVendor,
      latest,
    };
  }

  /**
   * Vendor rollup with both metrics.
   *
   * `risk` is the default headline; `cve_count` is the toggle. `securityOnly`
   * drops non-security categories so a broad-portfolio vendor is not penalised
   * for shipping routers and collaboration software.
   *
   * `categorySlug` narrows the whole rollup — risk included — to one product
   * line, which is the only way to ask "how do these vendors compare on firewalls
   * alone". It supersedes `securityOnly`: naming a category already decides the
   * scope, and a CVE that touches both firewall and endpoint products is counted
   * in full under each, because it is a real vulnerability in each of them.
   */
  async getVendorRollup(year: number, securityOnly = true, categorySlug?: string) {
    return this.#db.all<{
      vendor_slug: string;
      name: string;
      cve_count: number;
      kev_count: number;
      critical_count: number;
      risk: number;
    }>(
      // The DISTINCT vendor/CVE pairing in the CTE is load-bearing. Summing risk
      // across the cve_product join directly would multiply a CVE's score by the
      // number of products it touches, so a vendor that enumerates five affected
      // SKUs would score 5x one that lists a single umbrella product for the same
      // flaw. Counts already used COUNT(DISTINCT); the sum needs the same care.
      `WITH vendor_cve AS (
         SELECT DISTINCT cp.vendor_slug AS vendor_slug, cp.cve_id AS cve_id
         FROM cve_product cp
         JOIN product p    ON p.slug = cp.product_slug
         JOIN category cat ON cat.slug = p.category_slug
         JOIN cve c        ON c.cve_id = cp.cve_id
         WHERE c.published_year = ?
           AND c.state = 'PUBLISHED'
           AND (? IS NULL OR cat.slug = ?)
           AND (? IS NOT NULL OR ? = 0 OR cat.is_security = 1)
       )
       SELECT v.slug AS vendor_slug,
              v.name AS name,
              COUNT(*) AS cve_count,
              SUM(CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS kev_count,
              SUM(CASE WHEN c.cvss_severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
              COALESCE(SUM(${RISK_SQL}), 0) AS risk
       FROM vendor_cve vc
       JOIN vendor v   ON v.slug = vc.vendor_slug
       JOIN cve c      ON c.cve_id = vc.cve_id
       LEFT JOIN kev k ON k.cve_id = c.cve_id
       LEFT JOIN epss e ON e.cve_id = c.cve_id
       GROUP BY v.slug, v.name
       ORDER BY risk DESC`,
      [
        year,
        categorySlug ?? null,
        categorySlug ?? null,
        categorySlug ?? null,
        securityOnly ? 1 : 0,
      ],
    );
  }

  /**
   * Per-category breakdown for a vendor — the firewall-vs-endpoint view.
   *
   * Carries `risk` on the same terms as the vendor rollup, so a category can be
   * ranked by weighted exposure rather than raw volume.
   */
  async getCategoryBreakdown(year: number, vendorSlug?: string) {
    return this.#db.all<{
      category_slug: string;
      name: string;
      is_security: number;
      cve_count: number;
      kev_count: number;
      risk: number;
    }>(
      // Same DISTINCT discipline as the vendor rollup: one row per
      // (category, CVE) before anything is summed, so a CVE listing four
      // firewall SKUs does not score four times in the firewall total.
      `WITH category_cve AS (
         SELECT DISTINCT p.category_slug AS category_slug, cp.cve_id AS cve_id
         FROM cve_product cp
         JOIN product p ON p.slug = cp.product_slug
         JOIN cve c     ON c.cve_id = cp.cve_id
         WHERE c.published_year = ?
           AND c.state = 'PUBLISHED'
           AND (? IS NULL OR cp.vendor_slug = ?)
       )
       SELECT cat.slug AS category_slug,
              cat.name AS name,
              cat.is_security AS is_security,
              COUNT(*) AS cve_count,
              SUM(CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS kev_count,
              COALESCE(SUM(${RISK_SQL}), 0) AS risk
       FROM category_cve cc
       JOIN category cat ON cat.slug = cc.category_slug
       JOIN cve c        ON c.cve_id = cc.cve_id
       LEFT JOIN kev k   ON k.cve_id = c.cve_id
       LEFT JOIN epss e  ON e.cve_id = c.cve_id
       GROUP BY cat.slug, cat.name, cat.is_security, cat.sort
       ORDER BY cat.sort`,
      [year, vendorSlug ?? null, vendorSlug ?? null],
    );
  }

  /** YTD pace against the same calendar point last year. */
  async getYearOverYearPace(year: number, now = new Date()) {
    const monthDay = now.toISOString().slice(4, 10); // '-MM-DD'
    const current = await this.#db.first<{ n: number }>(
      `SELECT COUNT(*) AS n FROM cve
       WHERE published_year = ? AND state = 'PUBLISHED' AND substr(date_published, 5, 6) <= ?`,
      [year, monthDay],
    );
    const previous = await this.#db.first<{ n: number }>(
      `SELECT COUNT(*) AS n FROM cve
       WHERE published_year = ? AND state = 'PUBLISHED' AND substr(date_published, 5, 6) <= ?`,
      [year - 1, monthDay],
    );
    return { year, current: current?.n ?? 0, previousYearToDate: previous?.n ?? 0 };
  }

  // -------------------------------------------------------------------------
  // Listing queries — used at build time to prerender pages and emit the
  // year-sharded JSON the browser filters against.
  // -------------------------------------------------------------------------

  async listVendors() {
    return this.#db.all<{
      slug: string;
      name: string;
      psirt_url: string | null;
      homepage: string | null;
      discovery_note: string | null;
    }>('SELECT slug, name, psirt_url, homepage, discovery_note FROM vendor ORDER BY name');
  }

  async listCategories() {
    return this.#db.all<{
      slug: string;
      name: string;
      description: string;
      is_security: number;
      sort: number;
    }>('SELECT slug, name, description, is_security, sort FROM category ORDER BY sort');
  }

  /**
   * Flat CVE index for a year.
   *
   * Deliberately narrow: only the fields the client filters and sorts on, so a
   * decade of history stays inside the ~1-2 MB gzipped budget that lets the whole
   * dataset live in the browser.
   */
  async listCveIndex(year: number) {
    return this.#db.all<{
      cve_id: string;
      date_published: string | null;
      severity: string | null;
      score: number | null;
      discovery: string | null;
      in_kev: number;
      epss: number | null;
      vendors: string | null;
      products: string | null;
      categories: string | null;
    }>(
      `SELECT c.cve_id,
              c.date_published,
              c.cvss_severity AS severity,
              c.cvss_base_score AS score,
              c.discovery,
              CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END AS in_kev,
              e.score AS epss,
              (SELECT GROUP_CONCAT(DISTINCT cp.vendor_slug) FROM cve_product cp WHERE cp.cve_id = c.cve_id) AS vendors,
              (SELECT GROUP_CONCAT(DISTINCT cp.product_slug) FROM cve_product cp WHERE cp.cve_id = c.cve_id) AS products,
              (SELECT GROUP_CONCAT(DISTINCT p.category_slug)
                 FROM cve_product cp JOIN product p ON p.slug = cp.product_slug
                WHERE cp.cve_id = c.cve_id) AS categories
       FROM cve c
       LEFT JOIN kev k  ON k.cve_id = c.cve_id
       LEFT JOIN epss e ON e.cve_id = c.cve_id
       WHERE c.published_year = ? AND c.state = 'PUBLISHED'
       ORDER BY c.date_published DESC`,
      [year],
    );
  }

  /** Years that actually have data, so the build only emits shards that exist. */
  async listYears(): Promise<number[]> {
    const rows = await this.#db.all<{ y: number }>(
      `SELECT DISTINCT published_year AS y FROM cve
       WHERE published_year IS NOT NULL AND state = 'PUBLISHED' ORDER BY y DESC`,
    );
    return rows.map((r) => r.y);
  }

  /** Full detail for one CVE, including its resolved products and enrichment. */
  async getCveDetail(cveId: string) {
    const cve = await this.#db.first<{
      cve_id: string;
      assigner_short_name: string | null;
      date_published: string | null;
      title: string | null;
      description: string | null;
      cvss_version: string | null;
      cvss_vector: string | null;
      cvss_base_score: number | null;
      cvss_severity: string | null;
      cwe_ids: string;
      solution: string | null;
      refs: string;
      discovery: string | null;
      discovery_source: string | null;
      credit_text: string | null;
      kev_date_added: string | null;
      ransomware_known: number | null;
      epss_score: number | null;
      epss_percentile: number | null;
    }>(
      `SELECT c.cve_id, c.assigner_short_name, c.date_published, c.title, c.description,
              c.cvss_version, c.cvss_vector, c.cvss_base_score, c.cvss_severity,
              c.cwe_ids, c.solution, c.refs,
              c.discovery, c.discovery_source, c.credit_text,
              k.date_added AS kev_date_added, k.ransomware_known,
              e.score AS epss_score, e.percentile AS epss_percentile
       FROM cve c
       LEFT JOIN kev k  ON k.cve_id = c.cve_id
       LEFT JOIN epss e ON e.cve_id = c.cve_id
       WHERE c.cve_id = ?`,
      [cveId],
    );
    if (!cve) return null;

    const products = await this.#db.all<{
      product_slug: string;
      product_name: string;
      vendor_slug: string;
      vendor_name: string;
      category_slug: string;
      category_name: string;
      match_signal: string;
    }>(
      `SELECT cp.product_slug, p.name AS product_name, cp.vendor_slug, v.name AS vendor_name,
              p.category_slug, cat.name AS category_name, cp.match_signal
       FROM cve_product cp
       JOIN product p    ON p.slug = cp.product_slug
       JOIN vendor v     ON v.slug = cp.vendor_slug
       JOIN category cat ON cat.slug = p.category_slug
       WHERE cp.cve_id = ?
       ORDER BY v.name, p.name`,
      [cveId],
    );

    const affected = await this.#db.all<{ vendor_raw: string | null; product_raw: string | null; versions: string }>(
      'SELECT vendor_raw, product_raw, versions FROM cve_affected WHERE cve_id = ?',
      [cveId],
    );

    return { ...cve, products, affected };
  }

  /** Product-level rollup for a vendor page. */
  async getProductRollup(vendorSlug: string, year?: number) {
    return this.#db.all<{
      product_slug: string;
      name: string;
      category_slug: string;
      category_name: string;
      cve_count: number;
      kev_count: number;
    }>(
      `SELECT p.slug AS product_slug, p.name, p.category_slug, cat.name AS category_name,
              COUNT(DISTINCT c.cve_id) AS cve_count,
              COUNT(DISTINCT CASE WHEN k.cve_id IS NOT NULL THEN c.cve_id END) AS kev_count
       FROM product p
       JOIN category cat   ON cat.slug = p.category_slug
       JOIN cve_product cp ON cp.product_slug = p.slug
       JOIN cve c          ON c.cve_id = cp.cve_id
       LEFT JOIN kev k     ON k.cve_id = c.cve_id
       WHERE p.vendor_slug = ? AND c.state = 'PUBLISHED'
         AND (? IS NULL OR c.published_year = ?)
       GROUP BY p.slug, p.name, p.category_slug, cat.name
       ORDER BY cve_count DESC`,
      [vendorSlug, year ?? null, year ?? null],
    );
  }

  /**
   * Known-exploited CVEs we track, newest KEV additions first.
   *
   * `in_kev` is selected as a literal 1 rather than omitted: every row here is by
   * definition a KEV entry, and the shared CVE table renders its KEV badge from
   * that field. Leaving it out silently drops the badge from the one view where
   * exploitation is the entire point.
   */
  async listKevCves(limit = 200) {
    return this.#db.all<{
      cve_id: string;
      date_published: string | null;
      date_added: string;
      severity: string | null;
      score: number | null;
      epss: number | null;
      vendors: string | null;
      products: string | null;
      ransomware_known: number;
      in_kev: number;
    }>(
      `SELECT c.cve_id, c.date_published, k.date_added,
              c.cvss_severity AS severity, c.cvss_base_score AS score,
              e.score AS epss, k.ransomware_known, 1 AS in_kev,
              (SELECT GROUP_CONCAT(DISTINCT cp.vendor_slug) FROM cve_product cp WHERE cp.cve_id = c.cve_id) AS vendors,
              (SELECT GROUP_CONCAT(DISTINCT cp.product_slug) FROM cve_product cp WHERE cp.cve_id = c.cve_id) AS products
       FROM kev k
       JOIN cve c      ON c.cve_id = k.cve_id
       LEFT JOIN epss e ON e.cve_id = c.cve_id
       ORDER BY k.date_added DESC, c.cve_id DESC
       LIMIT ?`,
      [limit],
    );
  }

  /**
   * Most recent CVEs regardless of year.
   *
   * The homepage cannot key "latest disclosures" to the current year: for the
   * first days of January that query is legitimately empty, and the site would
   * look broken every New Year even though the data is fine.
   */
  async listRecentCves(limit = 20) {
    return this.#db.all<{
      cve_id: string;
      date_published: string | null;
      severity: string | null;
      score: number | null;
      in_kev: number;
      epss: number | null;
      vendors: string | null;
      products: string | null;
    }>(
      `SELECT c.cve_id, c.date_published, c.cvss_severity AS severity, c.cvss_base_score AS score,
              CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END AS in_kev,
              e.score AS epss,
              (SELECT GROUP_CONCAT(DISTINCT cp.vendor_slug) FROM cve_product cp WHERE cp.cve_id = c.cve_id) AS vendors,
              (SELECT GROUP_CONCAT(DISTINCT cp.product_slug) FROM cve_product cp WHERE cp.cve_id = c.cve_id) AS products
       FROM cve c
       LEFT JOIN kev k  ON k.cve_id = c.cve_id
       LEFT JOIN epss e ON e.cve_id = c.cve_id
       WHERE c.state = 'PUBLISHED' AND c.date_published IS NOT NULL
         AND EXISTS (SELECT 1 FROM cve_product cp WHERE cp.cve_id = c.cve_id)
       ORDER BY c.date_published DESC
       LIMIT ?`,
      [limit],
    );
  }

  /**
   * Discovery attribution per vendor: how many of a vendor's CVEs it found itself.
   *
   * The DISTINCT vendor/CVE pairing matters for the same reason it does in the
   * risk rollup — a CVE touching five products must count once, not five times.
   *
   * `undisclosed` is reported separately and never folded into the denominator.
   * A vendor that does not publish the field would otherwise look like a vendor
   * that finds nothing itself, which is a different and much worse claim.
   */
  async getDiscoveryBreakdown(year?: number) {
    return this.#db.all<{
      vendor_slug: string;
      name: string;
      internal: number;
      external: number;
      user: number;
      unknown: number;
      undisclosed: number;
      total: number;
    }>(
      `WITH vendor_cve AS (
         SELECT DISTINCT cp.vendor_slug AS vendor_slug, cp.cve_id AS cve_id
         FROM cve_product cp
         JOIN cve c ON c.cve_id = cp.cve_id
         WHERE c.state = 'PUBLISHED' AND (? IS NULL OR c.published_year = ?)
       )
       SELECT v.slug AS vendor_slug,
              v.name AS name,
              SUM(CASE WHEN c.discovery = 'INTERNAL' THEN 1 ELSE 0 END) AS internal,
              SUM(CASE WHEN c.discovery = 'EXTERNAL' THEN 1 ELSE 0 END) AS external,
              SUM(CASE WHEN c.discovery = 'USER'     THEN 1 ELSE 0 END) AS user,
              SUM(CASE WHEN c.discovery = 'UNKNOWN'  THEN 1 ELSE 0 END) AS unknown,
              SUM(CASE WHEN c.discovery IS NULL      THEN 1 ELSE 0 END) AS undisclosed,
              COUNT(*) AS total
       FROM vendor_cve vc
       JOIN vendor v ON v.slug = vc.vendor_slug
       JOIN cve c    ON c.cve_id = vc.cve_id
       GROUP BY v.slug, v.name
       ORDER BY internal DESC`,
      [year ?? null, year ?? null],
    );
  }

  /** Which mechanism supplied each discovery value — published field vs scraped prose. */
  async getDiscoverySourceCounts() {
    return this.#db.all<{ discovery_source: string | null; n: number }>(
      `SELECT discovery_source, COUNT(*) AS n
       FROM cve WHERE state = 'PUBLISHED' AND discovery IS NOT NULL
       GROUP BY discovery_source ORDER BY n DESC`,
    );
  }

  /**
   * CVEs for the PSIRT scrape pass to resolve.
   *
   * Defaults to those still missing attribution, which is what an incremental
   * nightly pass wants. `includeAttributed` widens it to every CVE with an
   * advisory — needed to rebuild the committed data file from scratch, because
   * the database is a local artifact and "already in the database" says nothing
   * about whether the reviewed record on disk is complete.
   */
  async listCvesNeedingAcknowledgement(vendorSlug: string, limit = 1000, includeAttributed = false) {
    return this.#db.all<{ cve_id: string; refs: string }>(
      `SELECT DISTINCT c.cve_id, c.refs
       FROM cve c
       JOIN cve_product cp ON cp.cve_id = c.cve_id
       WHERE cp.vendor_slug = ? AND c.state = 'PUBLISHED'
         AND (? = 1 OR c.discovery IS NULL)
       ORDER BY c.date_published DESC
       LIMIT ?`,
      [vendorSlug, includeAttributed ? 1 : 0, limit],
    );
  }

  /** Write a scraped discovery verdict without disturbing anything else on the row. */
  async setDiscovery(
    rows: ReadonlyArray<{
      cveId: string;
      discovery: string;
      discoverySource: string;
      creditText: string | null;
    }>,
  ): Promise<number> {
    if (!rows.length) return 0;
    await this.#db.batch(
      rows.map((r) => ({
        sql: `UPDATE cve SET discovery = ?, discovery_source = ?, credit_text = ? WHERE cve_id = ?`,
        params: [r.discovery, r.discoverySource, r.creditText, r.cveId] as SqlValue[],
      })),
    );
    return rows.length;
  }

  /** Share of tracked CVEs with no CVSS from any source — disclosed on /methodology. */
  async getUnscoredShare(): Promise<{ total: number; unscored: number }> {
    const row = await this.#db.first<{ total: number; unscored: number }>(
      `SELECT COUNT(*) AS total,
              SUM(CASE WHEN cvss_base_score IS NULL THEN 1 ELSE 0 END) AS unscored
       FROM cve WHERE state = 'PUBLISHED'`,
    );
    return { total: row?.total ?? 0, unscored: row?.unscored ?? 0 };
  }

  // -------------------------------------------------------------------------
  // Operations
  // -------------------------------------------------------------------------

  async startRun(source: string, now = new Date().toISOString()): Promise<number> {
    await this.#db.run('INSERT INTO ingest_run (source, started_at, status) VALUES (?, ?, ?)', [
      source,
      now,
      'running',
    ]);
    const row = await this.#db.first<{ id: number }>(
      'SELECT id FROM ingest_run WHERE source = ? ORDER BY id DESC LIMIT 1',
      [source],
    );
    return row?.id ?? 0;
  }

  async finishRun(
    id: number,
    status: 'ok' | 'error',
    records: number,
    error?: string,
  ): Promise<void> {
    await this.#db.run(
      'UPDATE ingest_run SET finished_at = ?, status = ?, records = ?, error = ? WHERE id = ?',
      [new Date().toISOString(), status, records, error ?? null, id],
    );
  }

  async getSyncState(key: string): Promise<string | null> {
    const row = await this.#db.first<{ value: string }>(
      'SELECT value FROM sync_state WHERE key = ?',
      [key],
    );
    return row?.value ?? null;
  }

  async setSyncState(key: string, value: string): Promise<void> {
    await this.#db.run(
      `INSERT INTO sync_state (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
      [key, value, new Date().toISOString()],
    );
  }

  // -------------------------------------------------------------------------
  // Reader-submitted corrections
  //
  // The only rows in this database that cannot be rebuilt from source. See the
  // header of migrations/0003_feedback.sql.
  // -------------------------------------------------------------------------

  async insertFeedback(entry: NewFeedback, now = new Date().toISOString()): Promise<number> {
    await this.#db.run(
      `INSERT INTO feedback
         (created_at, kind, cve_id, page_url, body, evidence_url, reporter_email, ip_hash, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        now,
        entry.kind,
        entry.cveId ?? null,
        entry.pageUrl ?? null,
        entry.body,
        entry.evidenceUrl ?? null,
        entry.reporterEmail ?? null,
        entry.ipHash ?? null,
        entry.userAgent ?? null,
      ],
    );
    const row = await this.#db.first<{ id: number }>(
      'SELECT id FROM feedback ORDER BY id DESC LIMIT 1',
    );
    return row?.id ?? 0;
  }

  /** Submissions from one source since a cutoff — the abuse check the edge limiter cannot do. */
  async countRecentFeedback(ipHash: string, since: string): Promise<number> {
    const row = await this.#db.first<{ n: number }>(
      'SELECT COUNT(*) AS n FROM feedback WHERE ip_hash = ? AND created_at >= ?',
      [ipHash, since],
    );
    return row?.n ?? 0;
  }

  async listFeedback(status = 'new', limit = 50): Promise<FeedbackRow[]> {
    return this.#db.all<FeedbackRow>(
      `SELECT id, created_at, kind, cve_id, page_url, body, evidence_url, reporter_email,
              status, triaged_at, triage_note, github_issue
         FROM feedback
        WHERE (? = 'all' OR status = ?)
        ORDER BY created_at ASC
        LIMIT ?`,
      [status, status, limit],
    );
  }

  async triageFeedback(
    id: number,
    status: 'accepted' | 'rejected' | 'duplicate',
    note: string | null,
    githubIssue: number | null = null,
    now = new Date().toISOString(),
  ): Promise<void> {
    await this.#db.run(
      `UPDATE feedback
          SET status = ?, triage_note = ?, triaged_at = ?,
              github_issue = COALESCE(?, github_issue)
        WHERE id = ?`,
      [status, note, now, githubIssue, id],
    );
  }
}

export interface NewFeedback {
  kind: string;
  body: string;
  cveId?: string | null;
  pageUrl?: string | null;
  evidenceUrl?: string | null;
  reporterEmail?: string | null;
  ipHash?: string | null;
  userAgent?: string | null;
}

export interface FeedbackRow {
  id: number;
  created_at: string;
  kind: string;
  cve_id: string | null;
  page_url: string | null;
  body: string;
  evidence_url: string | null;
  reporter_email: string | null;
  status: string;
  triaged_at: string | null;
  triage_note: string | null;
  github_issue: number | null;
}
