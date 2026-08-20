import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it } from 'vitest';
import type { CveRecord } from '@cybercves/core';
import { TaxonomyResolver, normalizeCve } from '@cybercves/core';
import type { CategoryConfig, ProductConfig, VendorFileConfig } from '@cybercves/core';
import { NodeSqliteDriver } from '../src/drivers/node-sqlite.js';
import { migrate } from '../src/migrate.js';
import { Repository } from '../src/repository.js';

/**
 * Exercises the real schema against real SQLite with real CVE records. This is
 * also the base of the portability drill: the same suite must pass against a
 * Postgres-backed driver before we would trust a migration off D1.
 */

const CATEGORIES: CategoryConfig[] = [
  { slug: 'firewall', name: 'Firewall / NGFW', description: '', sort: 10, security: true },
  { slug: 'email-security', name: 'Email Security', description: '', sort: 50, security: true },
  { slug: 'threat-detection', name: 'Threat Detection', description: '', sort: 80, security: true },
  { slug: 'sase-sse', name: 'SASE / SSE', description: '', sort: 30, security: true },
  { slug: 'routing-switching', name: 'Routing & Switching', description: '', sort: 140, security: false },
  { slug: 'other', name: 'Other', description: '', sort: 999, security: false },
];

const VENDORS: VendorFileConfig[] = [
  {
    slug: 'fortinet',
    name: 'Fortinet',
    cnaShortNames: ['fortinet'],
    aliases: ['Fortinet'],
    psirtHosts: ['fortiguard.fortinet.com'],
    psirtUrl: null,
    homepage: null,
    adapter: 'rss',
    rssUrl: null,
    jsonUrlTemplate: null,
    advisoryIdPattern: null,
    internalBrandMarkers: [],
    discoveryNote: null,
  },
  {
    slug: 'cisco',
    name: 'Cisco',
    cnaShortNames: ['cisco'],
    aliases: ['Cisco'],
    psirtHosts: ['sec.cloudapps.cisco.com'],
    psirtUrl: null,
    homepage: null,
    adapter: 'csaf',
    rssUrl: null,
    jsonUrlTemplate: null,
    advisoryIdPattern: null,
    internalBrandMarkers: [],
    discoveryNote: null,
  },
];

const PRODUCTS: ProductConfig[] = [
  { slug: 'fortinet-fortimail', vendorSlug: 'fortinet', name: 'FortiMail', categorySlug: 'email-security', aliases: ['FortiMail'], patterns: [], brand: null, brandFallback: false },
  { slug: 'fortinet-fortindr', vendorSlug: 'fortinet', name: 'FortiNDR', categorySlug: 'threat-detection', aliases: ['FortiNDR'], patterns: [], brand: null, brandFallback: false },
  { slug: 'fortinet-fortivoice', vendorSlug: 'fortinet', name: 'FortiVoice', categorySlug: 'other', aliases: ['FortiVoice'], patterns: [], brand: null, brandFallback: false },
  { slug: 'fortinet-forticamera', vendorSlug: 'fortinet', name: 'FortiCamera', categorySlug: 'other', aliases: ['FortiCamera'], patterns: [], brand: null, brandFallback: false },
  { slug: 'fortinet-fortirecorder', vendorSlug: 'fortinet', name: 'FortiRecorder', categorySlug: 'other', aliases: ['FortiRecorder'], patterns: [], brand: null, brandFallback: false },
  { slug: 'cisco-ios-xe', vendorSlug: 'cisco', name: 'Cisco IOS XE', categorySlug: 'routing-switching', aliases: [], patterns: ['^cisco ios xe\\b'], brand: null, brandFallback: false },
];

function fixture(id: string) {
  const path = fileURLToPath(
    new URL(`../../core/test/fixtures/${id}.json`, import.meta.url),
  );
  return normalizeCve(JSON.parse(readFileSync(path, 'utf8')) as CveRecord);
}

const resolver = new TaxonomyResolver(VENDORS, PRODUCTS);

let db: NodeSqliteDriver;
let repo: Repository;

beforeEach(async () => {
  db = new NodeSqliteDriver(':memory:');
  repo = new Repository(db);
  await migrate(db);
  await repo.syncTaxonomy(CATEGORIES, VENDORS, PRODUCTS);
});

async function ingest(...ids: string[]) {
  const entries = ids.map((id) => {
    const cve = fixture(id);
    return { cve, resolved: resolver.resolve(cve).resolved };
  });
  return repo.upsertCves(entries);
}

describe('migrations', () => {
  it('apply once and are idempotent on re-run', async () => {
    const second = await migrate(db);
    expect(second).toHaveLength(0);
  });

  it('enforce foreign keys', async () => {
    await expect(
      db.run("INSERT INTO product (slug, vendor_slug, name, category_slug) VALUES ('x','nope','X','firewall')"),
    ).rejects.toThrow();
  });
});

describe('upsertCves', () => {
  it('inserts a CVE with its affected entries and product links', async () => {
    const result = await ingest('CVE-2025-32756');
    expect(result).toEqual({ inserted: 1, updated: 0, skipped: 0 });

    const row = await db.first<{ cvss_base_score: number; published_year: number; cvss_severity: string }>(
      'SELECT cvss_base_score, published_year, cvss_severity FROM cve WHERE cve_id = ?',
      ['CVE-2025-32756'],
    );
    expect(row?.cvss_base_score).toBe(9.6);
    expect(row?.published_year).toBe(2025);
    expect(row?.cvss_severity).toBe('CRITICAL');

    const links = await db.all<{ product_slug: string }>(
      'SELECT product_slug FROM cve_product WHERE cve_id = ? ORDER BY product_slug',
      ['CVE-2025-32756'],
    );
    expect(links.map((l) => l.product_slug)).toContain('fortinet-fortimail');
  });

  it('skips an unchanged record rather than rewriting it', async () => {
    await ingest('CVE-2025-32756');
    // Upstream republishes touch many records daily; rewriting unchanged rows
    // would burn the D1 free-tier write budget for no benefit.
    expect(await ingest('CVE-2025-32756')).toEqual({ inserted: 0, updated: 0, skipped: 1 });
  });

  it('updates when the fingerprint changes', async () => {
    await ingest('CVE-2025-32756');
    const cve = fixture('CVE-2025-32756');
    cve.sourceHash = 'deadbeefdeadbeef';
    cve.description = 'revised description';

    const result = await repo.upsertCves([{ cve, resolved: resolver.resolve(cve).resolved }]);
    expect(result).toEqual({ inserted: 0, updated: 1, skipped: 0 });

    const row = await db.first<{ description: string }>(
      'SELECT description FROM cve WHERE cve_id = ?',
      ['CVE-2025-32756'],
    );
    expect(row?.description).toBe('revised description');
  });

  it('drops products the vendor has removed on revision', async () => {
    await ingest('CVE-2025-32756');
    const cve = fixture('CVE-2025-32756');
    cve.sourceHash = 'changed0000000001';
    // A merge-instead-of-replace bug would keep showing products the vendor has
    // since declared unaffected.
    cve.affected = cve.affected.filter((a) => a.productRaw === 'FortiMail');

    await repo.upsertCves([{ cve, resolved: resolver.resolve(cve).resolved }]);
    const links = await db.all<{ product_slug: string }>(
      'SELECT product_slug FROM cve_product WHERE cve_id = ?',
      ['CVE-2025-32756'],
    );
    expect(links.map((l) => l.product_slug)).toEqual(['fortinet-fortimail']);
  });
});

describe('enrichment', () => {
  it('stores KEV entries', async () => {
    await ingest('CVE-2023-20198');
    await repo.upsertKev([
      {
        cveId: 'CVE-2023-20198',
        dateAdded: '2023-10-16',
        dueDate: '2023-10-20',
        ransomwareKnown: true,
        vendorProject: 'Cisco',
        product: 'IOS XE',
      },
    ]);
    const row = await db.first<{ ransomware_known: number }>(
      'SELECT ransomware_known FROM kev WHERE cve_id = ?',
      ['CVE-2023-20198'],
    );
    expect(row?.ransomware_known).toBe(1);
  });

  it('stores EPSS only for CVEs we track', async () => {
    await ingest('CVE-2023-20198');
    // EPSS ships ~290k rows daily; storing the untracked remainder would dwarf
    // our own data for no benefit.
    const written = await repo.upsertEpssForKnownCves([
      { cveId: 'CVE-2023-20198', score: 0.94, percentile: 0.99, asOf: '2026-07-27' },
      { cveId: 'CVE-1999-0001', score: 0.01, percentile: 0.1, asOf: '2026-07-27' },
    ]);
    expect(written).toBe(1);
    expect(await db.all('SELECT cve_id FROM epss')).toHaveLength(1);
  });
});

describe('getKevTiming', () => {
  it('measures the lag in calendar days, one row per affected product', async () => {
    await ingest('CVE-2023-20198');
    await repo.upsertKev([
      {
        cveId: 'CVE-2023-20198',
        dateAdded: '2023-10-20',
        dueDate: null,
        ransomwareKnown: true,
        vendorProject: 'Cisco',
        product: 'IOS XE',
      },
    ]);

    const rows = await repo.getKevTiming();
    expect(rows.length).toBeGreaterThan(0);

    // The CVE published 2023-10-16T20:00:00Z. Comparing the raw timestamp
    // against a bare date yields a fraction that truncates to 3; the lag has to
    // be a calendar-day difference, which is all `date_added` can support.
    for (const row of rows) {
      expect(row.cve_id).toBe('CVE-2023-20198');
      expect(row.days).toBe(4);
      expect(row.ransomware_known).toBe(1);
    }
  });

  it('keeps a KEV CVE that maps to no product', async () => {
    // Inner-joining cve_product would drop it here while the KEV table above it
    // still listed it, so the page would disagree with itself on the count.
    await db.run(
      `INSERT INTO cve (cve_id, state, date_published, published_year, source_hash,
                        first_seen_at, last_synced_at)
       VALUES ('CVE-2026-9999', 'PUBLISHED', '2026-01-01T00:00:00.000Z', 2026, 'h', 'n', 'n')`,
    );
    await repo.upsertKev([
      {
        cveId: 'CVE-2026-9999',
        dateAdded: '2026-01-09',
        dueDate: null,
        ransomwareKnown: false,
        vendorProject: 'Someone',
        product: 'Something',
      },
    ]);

    const rows = await repo.getKevTiming();
    const orphan = rows.find((r) => r.cve_id === 'CVE-2026-9999');
    expect(orphan).toBeDefined();
    expect(orphan?.product_slug).toBeNull();
    expect(orphan?.vendor_slug).toBeNull();
    expect(orphan?.days).toBe(8);
  });

  it('excludes a CVE with no publication date, having no runway to measure', async () => {
    await db.run(
      `INSERT INTO cve (cve_id, state, date_published, published_year, source_hash,
                        first_seen_at, last_synced_at)
       VALUES ('CVE-2026-8888', 'PUBLISHED', NULL, NULL, 'h', 'n', 'n')`,
    );
    await repo.upsertKev([
      {
        cveId: 'CVE-2026-8888',
        dateAdded: '2026-01-09',
        dueDate: null,
        ransomwareKnown: false,
        vendorProject: null,
        product: null,
      },
    ]);

    const rows = await repo.getKevTiming();
    expect(rows.find((r) => r.cve_id === 'CVE-2026-8888')).toBeUndefined();
  });

  it('reports a negative lag when CISA listed the CVE before it published', async () => {
    await db.run(
      `INSERT INTO cve (cve_id, state, date_published, published_year, source_hash,
                        first_seen_at, last_synced_at)
       VALUES ('CVE-2026-7777', 'PUBLISHED', '2026-03-10T00:00:00.000Z', 2026, 'h', 'n', 'n')`,
    );
    await repo.upsertKev([
      {
        cveId: 'CVE-2026-7777',
        dateAdded: '2026-03-04',
        dueDate: null,
        ransomwareKnown: false,
        vendorProject: null,
        product: null,
      },
    ]);

    const rows = await repo.getKevTiming();
    // Must not be clamped: exploited-before-disclosure is the most severe thing
    // this metric can report, and zeroing it would erase the distinction.
    expect(rows.find((r) => r.cve_id === 'CVE-2026-7777')?.days).toBe(-6);
  });
  it('carries the publication year and category so the page can filter on them', async () => {
    await ingest('CVE-2023-20198');
    await repo.upsertKev([
      { cveId: 'CVE-2023-20198', dateAdded: '2023-10-20', dueDate: null,
        ransomwareKnown: false, vendorProject: 'Cisco', product: 'IOS XE' },
    ]);
    const [first] = await repo.getKevTiming();
    expect(first?.published_year).toBe(2023);
    expect(first?.category_slug).toBeTruthy();
    expect(first?.category_name).toBeTruthy();
  });
});

describe('getKevCohortRate', () => {
  /**
   * The metric exists because year-filtering the runway charts is not a fair
   * comparison: cohorts have not been observed for equal time. These tests pin
   * the two properties that make it fair.
   */
  const publish = (id: string, published: string) =>
    db.run(
      `INSERT INTO cve (cve_id, state, date_published, published_year, source_hash,
                        first_seen_at, last_synced_at)
       VALUES (?, 'PUBLISHED', ?, ?, 'h', 'n', 'n')`,
      [id, published, Number(published.slice(0, 4))],
    );

  const link = (id: string) =>
    db.run(
      `INSERT INTO cve_product (cve_id, product_slug, vendor_slug, match_signal)
       VALUES (?, 'fortinet-fortimail', 'fortinet', 'test')`,
      [id],
    );

  it('excludes CVEs too recent to have been watched for the whole window', async () => {
    // Published 10 days ago: it cannot yet have failed to be exploited within
    // 90, so counting it would dilute the rate with an unfinished observation.
    await publish('CVE-2026-0001', '2026-08-10T00:00:00.000Z');
    await link('CVE-2026-0001');
    // Published 200 days ago: fully observed.
    await publish('CVE-2026-0002', '2026-01-01T00:00:00.000Z');
    await link('CVE-2026-0002');

    const rows = await repo.getKevCohortRate(90, new Date('2026-08-20T00:00:00Z'));
    const y2026 = rows.find((r) => r.published_year === 2026 && r.vendor_slug === 'fortinet');
    expect(y2026?.eligible).toBe(1);
  });

  it('counts exploitation inside the window and ignores it outside', async () => {
    await publish('CVE-2025-0001', '2025-01-01T00:00:00.000Z');
    await link('CVE-2025-0001');
    await publish('CVE-2025-0002', '2025-01-01T00:00:00.000Z');
    await link('CVE-2025-0002');
    await repo.upsertKev([
      // 30 days after publication — inside the window.
      { cveId: 'CVE-2025-0001', dateAdded: '2025-01-31', dueDate: null,
        ransomwareKnown: false, vendorProject: null, product: null },
      // 300 days after — a real exploitation, but outside the ruler, so it must
      // not count or the window would not be a window.
      { cveId: 'CVE-2025-0002', dateAdded: '2025-10-28', dueDate: null,
        ransomwareKnown: false, vendorProject: null, product: null },
    ]);

    const rows = await repo.getKevCohortRate(90, new Date('2026-08-20T00:00:00Z'));
    const y2025 = rows.find((r) => r.published_year === 2025 && r.vendor_slug === 'fortinet');
    expect(y2025?.eligible).toBe(2);
    expect(y2025?.exploited).toBe(1);
  });

  it('counts a CVE once for its vendor however many products it touches', async () => {
    await publish('CVE-2025-0003', '2025-02-01T00:00:00.000Z');
    await db.run(
      `INSERT INTO cve_product (cve_id, product_slug, vendor_slug, match_signal)
       VALUES ('CVE-2025-0003', 'fortinet-fortimail', 'fortinet', 'test'),
              ('CVE-2025-0003', 'fortinet-fortindr', 'fortinet', 'test')`,
    );
    const rows = await repo.getKevCohortRate(90, new Date('2026-08-20T00:00:00Z'));
    const y2025 = rows.find((r) => r.published_year === 2025 && r.vendor_slug === 'fortinet');
    expect(y2025?.eligible).toBe(1);
  });

});

describe('taxonomy review queue', () => {
  it('records unmapped products and counts repeat sightings', async () => {
    const unmapped = [{ vendorRaw: 'Fortinet', productRaw: 'FortiBrandNew', vendorSlug: 'fortinet' }];
    await repo.recordUnmapped(unmapped);
    await repo.recordUnmapped(unmapped);

    const queue = await repo.getUnmappedForReview();
    expect(queue).toHaveLength(1);
    expect(queue[0]?.seen_count).toBe(2);
    expect(queue[0]?.product_raw).toBe('FortiBrandNew');
  });

  it('dedupes spellings that normalize to the same key', async () => {
    await repo.recordUnmapped([{ vendorRaw: 'Fortinet', productRaw: 'FortiThing®', vendorSlug: 'fortinet' }]);
    await repo.recordUnmapped([{ vendorRaw: 'Fortinet', productRaw: 'fortithing', vendorSlug: 'fortinet' }]);
    expect(await repo.getUnmappedForReview()).toHaveLength(1);
  });
});

describe('site queries', () => {
  it('builds the live snapshot the odometer reads', async () => {
    await ingest('CVE-2025-32756');
    const snapshot = await repo.getLiveSnapshot(2025, new Date('2025-06-01T00:00:00Z'));

    expect(snapshot.total).toBe(1);
    expect(snapshot.byVendor).toEqual([
      expect.objectContaining({ vendor_slug: 'fortinet', name: 'Fortinet', n: 1 }),
    ]);
    expect(snapshot.latest[0]?.cve_id).toBe('CVE-2025-32756');
  });

  it('counts a multi-product CVE once per vendor, not once per product', async () => {
    await ingest('CVE-2025-32756');
    const snapshot = await repo.getLiveSnapshot(2025, new Date('2025-06-01T00:00:00Z'));
    // The record affects five Fortinet products; counting links would report 5.
    expect(snapshot.byVendor[0]?.n).toBe(1);
  });

  it('ranks vendors by risk, escalating known-exploited CVEs', async () => {
    await ingest('CVE-2025-32756', 'CVE-2023-20198');
    await repo.upsertKev([
      {
        cveId: 'CVE-2023-20198',
        dateAdded: '2023-10-16',
        dueDate: null,
        ransomwareKnown: true,
        vendorProject: 'Cisco',
        product: 'IOS XE',
      },
    ]);
    await repo.upsertEpssForKnownCves([
      { cveId: 'CVE-2023-20198', score: 0.9, percentile: 0.99, asOf: '2026-07-27' },
    ]);

    const all = await repo.getVendorRollup(2023, false);
    const cisco = all.find((r) => r.vendor_slug === 'cisco');
    // CRITICAL(10) x KEV(4) x (1 + 0.9) = 76
    expect(cisco?.risk).toBeCloseTo(76, 5);
    expect(cisco?.kev_count).toBe(1);
  });

  it('scores a multi-product CVE once, not once per affected product', async () => {
    // CVE-2025-32756 maps to five Fortinet products. Summing risk across the
    // cve_product join would multiply its score by five, making any vendor that
    // enumerates affected SKUs look far riskier than one listing a single
    // umbrella product for the same flaw.
    await ingest('CVE-2025-32756');
    await repo.upsertKev([
      {
        cveId: 'CVE-2025-32756',
        dateAdded: '2025-05-14',
        dueDate: null,
        ransomwareKnown: false,
        vendorProject: 'Fortinet',
        product: 'Multiple',
      },
    ]);
    await repo.upsertEpssForKnownCves([
      { cveId: 'CVE-2025-32756', score: 0.5, percentile: 0.9, asOf: '2026-07-27' },
    ]);

    const links = await db.all('SELECT product_slug FROM cve_product WHERE cve_id = ?', [
      'CVE-2025-32756',
    ]);
    expect(links.length).toBe(5);

    const [fortinet] = await repo.getVendorRollup(2025, false);
    // CRITICAL(10) x KEV(4) x (1 + 0.5) = 60 — not 300.
    expect(fortinet?.risk).toBeCloseTo(60, 5);
    expect(fortinet?.cve_count).toBe(1);
    expect(fortinet?.kev_count).toBe(1);
    expect(fortinet?.critical_count).toBe(1);
  });

  it('excludes non-security categories from the default comparison', async () => {
    await ingest('CVE-2023-20198'); // Cisco IOS XE -> routing-switching, non-security
    expect(await repo.getVendorRollup(2023, true)).toHaveLength(0);
    expect(await repo.getVendorRollup(2023, false)).toHaveLength(1);
  });

  it('scopes the risk calculation to a single product category', async () => {
    // CVE-2025-32756 lands in email-security, threat-detection and other — but
    // never firewall. Scoping to one category must move the risk number, not
    // just filter the rows: this is the whole point of the category filter.
    await ingest('CVE-2025-32756');
    await repo.upsertEpssForKnownCves([
      { cveId: 'CVE-2025-32756', score: 0.5, percentile: 0.9, asOf: '2026-07-27' },
    ]);

    const [all] = await repo.getVendorRollup(2025, true);
    expect(all?.risk).toBeCloseTo(15, 5); // CRITICAL(10) x no-KEV(1) x (1 + 0.5)

    const [email] = await repo.getVendorRollup(2025, true, 'email-security');
    expect(email?.vendor_slug).toBe('fortinet');
    expect(email?.cve_count).toBe(1);
    expect(email?.risk).toBeCloseTo(15, 5);

    expect(await repo.getVendorRollup(2025, true, 'firewall')).toHaveLength(0);
  });

  it('honours a non-security category when one is named explicitly', async () => {
    // Asking for routing & switching is an explicit choice, so securityOnly must
    // not silently empty the result the way it does for the unscoped default.
    await ingest('CVE-2023-20198');
    const rows = await repo.getVendorRollup(2023, true, 'routing-switching');
    expect(rows.map((r) => r.vendor_slug)).toEqual(['cisco']);
  });

  it('scores a category once for a CVE that lists several products in it', async () => {
    // The five affected Fortinet products collapse into three categories; each
    // category must score the CVE once, not once per SKU it names.
    await ingest('CVE-2025-32756');
    await repo.upsertEpssForKnownCves([
      { cveId: 'CVE-2025-32756', score: 0.5, percentile: 0.9, asOf: '2026-07-27' },
    ]);

    const rows = await repo.getCategoryBreakdown(2025, 'fortinet');
    for (const row of rows) {
      expect(row.cve_count).toBe(1);
      expect(row.risk).toBeCloseTo(15, 5);
    }
  });

  it('breaks a vendor down by product category', async () => {
    await ingest('CVE-2025-32756');
    const rows = await repo.getCategoryBreakdown(2025, 'fortinet');
    const byCategory = new Map(rows.map((r) => [r.category_slug, r.cve_count]));

    expect(byCategory.get('email-security')).toBe(1);
    expect(byCategory.get('threat-detection')).toBe(1);
    expect(byCategory.get('other')).toBe(1);
    expect(byCategory.has('firewall')).toBe(false);
  });

  it('compares year-to-date pace against the same calendar point last year', async () => {
    await ingest('CVE-2025-32756'); // published 2025-05-13
    const pace = await repo.getYearOverYearPace(2025, new Date('2025-06-01T00:00:00Z'));
    expect(pace.current).toBe(1);
    expect(pace.previousYearToDate).toBe(0);
  });

  it('excludes a CVE published later in the year from the YTD count', async () => {
    await ingest('CVE-2025-32756'); // 2025-05-13
    const pace = await repo.getYearOverYearPace(2025, new Date('2025-03-01T00:00:00Z'));
    expect(pace.current).toBe(0);
  });
});

describe('operations', () => {
  it('records ingest runs', async () => {
    const id = await repo.startRun('cvelist-delta');
    await repo.finishRun(id, 'ok', 42);
    const row = await db.first<{ status: string; records: number }>(
      'SELECT status, records FROM ingest_run WHERE id = ?',
      [id],
    );
    expect(row).toEqual({ status: 'ok', records: 42 });
  });

  it('persists sync cursors so a restart resumes instead of refetching', async () => {
    expect(await repo.getSyncState('cvelist:cursor')).toBeNull();
    await repo.setSyncState('cvelist:cursor', '2026-07-27T01:06:45Z');
    await repo.setSyncState('cvelist:cursor', '2026-07-27T02:00:00Z');
    expect(await repo.getSyncState('cvelist:cursor')).toBe('2026-07-27T02:00:00Z');
  });
});

describe('discovery attribution', () => {
  async function seed(rows: Array<[string, string | null]>) {
    await ingest('CVE-2025-32756');
    // Reuse one ingested CVE's product links by cloning the row per case.
    for (const [cveId, discovery] of rows) {
      await db.run(
        `INSERT INTO cve (cve_id, state, published_year, source_hash, first_seen_at, last_synced_at, discovery)
         VALUES (?, 'PUBLISHED', 2025, 'h', 'now', 'now', ?)`,
        [cveId, discovery],
      );
      await db.run(
        `INSERT INTO cve_product (cve_id, product_slug, vendor_slug, match_signal)
         VALUES (?, 'fortinet-fortimail', 'fortinet', 'cna-assigner')`,
        [cveId],
      );
    }
  }

  it('counts each discovery value and reports undisclosed separately', async () => {
    await seed([
      ['CVE-2025-9001', 'INTERNAL'],
      ['CVE-2025-9002', 'INTERNAL'],
      ['CVE-2025-9003', 'EXTERNAL'],
      ['CVE-2025-9004', 'USER'],
      ['CVE-2025-9005', 'UNKNOWN'],
      ['CVE-2025-9006', null],
    ]);

    const [fortinet] = await repo.getDiscoveryBreakdown(2025);
    expect(fortinet?.internal).toBe(2);
    expect(fortinet?.external).toBe(1);
    expect(fortinet?.user).toBe(1);
    expect(fortinet?.unknown).toBe(1);
    // The seeded CVE-2025-32756 has no discovery either, so 2 undisclosed.
    expect(fortinet?.undisclosed).toBe(2);
    expect(fortinet?.total).toBe(7);
  });

  it('counts a multi-product CVE once', async () => {
    await ingest('CVE-2025-32756'); // five Fortinet products
    await db.run("UPDATE cve SET discovery='INTERNAL' WHERE cve_id='CVE-2025-32756'");

    const [fortinet] = await repo.getDiscoveryBreakdown(2025);
    // Counting cve_product rows instead of distinct CVEs would report 5.
    expect(fortinet?.internal).toBe(1);
    expect(fortinet?.total).toBe(1);
  });

  it('writes a scraped verdict without disturbing the rest of the row', async () => {
    await ingest('CVE-2025-32756');
    await repo.setDiscovery([
      {
        cveId: 'CVE-2025-32756',
        discovery: 'INTERNAL',
        discoverySource: 'psirt-acknowledgement',
        creditText: 'Discovered by the Fortinet Product Security Team.',
      },
    ]);

    const row = await db.first<{ discovery: string; discovery_source: string; credit_text: string; cvss_base_score: number }>(
      'SELECT discovery, discovery_source, credit_text, cvss_base_score FROM cve WHERE cve_id = ?',
      ['CVE-2025-32756'],
    );
    expect(row?.discovery).toBe('INTERNAL');
    expect(row?.discovery_source).toBe('psirt-acknowledgement');
    expect(row?.credit_text).toContain('Fortinet Product Security');
    expect(row?.cvss_base_score).toBe(9.6);
  });

  it('does not let a re-sync erase a scraped verdict', async () => {
    await ingest('CVE-2025-32756');
    await repo.setDiscovery([
      { cveId: 'CVE-2025-32756', discovery: 'INTERNAL', discoverySource: 'psirt-acknowledgement', creditText: 'x' },
    ]);

    // The CVE List still carries no discovery for this record; re-ingesting it
    // must not wipe what the scraper established.
    const cve = fixture('CVE-2025-32756');
    cve.sourceHash = 'changed-after-scrape';
    await repo.upsertCves([{ cve, resolved: resolver.resolve(cve).resolved }]);

    const row = await db.first<{ discovery: string }>(
      'SELECT discovery FROM cve WHERE cve_id = ?',
      ['CVE-2025-32756'],
    );
    expect(row?.discovery).toBe('INTERNAL');
  });
});
