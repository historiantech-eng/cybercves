import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it } from 'vitest';
import type { CveRecord } from '@cybercves/core';
import { Repository } from '@cybercves/db';
import { NodeSqliteDriver } from '@cybercves/db/drivers/node';
import { migrate } from '@cybercves/db/migrate';
import { ingestRecords } from '../src/pipeline.js';
import { loadConfig } from '../src/node/config-loader.js';

const config = loadConfig();

function fixture(id: string): CveRecord {
  const path = fileURLToPath(
    new URL(`../../core/test/fixtures/${id}.json`, import.meta.url),
  );
  return JSON.parse(readFileSync(path, 'utf8')) as CveRecord;
}

let db: NodeSqliteDriver;
let repo: Repository;

beforeEach(async () => {
  db = new NodeSqliteDriver(':memory:');
  repo = new Repository(db);
  await migrate(db);
  await repo.syncTaxonomy(config.categories, config.vendors, config.products);
});

describe('ingestRecords', () => {
  it('stores a CVE belonging to a tracked vendor', async () => {
    const summary = await ingestRecords(repo, config.resolver, [fixture('CVE-2025-32756')]);
    expect(summary.inserted).toBe(1);
    expect(summary.unmatched).toBe(0);
    expect(summary.rejected).toBe(0);
  });

  it('skips a CVE that matches no tracked vendor', async () => {
    const record = fixture('CVE-2025-32756');
    record.cveMetadata.assignerShortName = 'someone_else';
    record.containers!.cna!.affected = [{ vendor: 'Unrelated Corp', product: 'Widget' }];
    record.containers!.cna!.references = [{ url: 'https://example.test/advisory' }];
    record.containers!.adp = [];

    const summary = await ingestRecords(repo, config.resolver, [record]);
    expect(summary.unmatched).toBe(1);
    expect(summary.inserted).toBe(0);
    expect(await db.all('SELECT cve_id FROM cve')).toHaveLength(0);
  });

  it('drops REJECTED records before they reach the database', async () => {
    // Withdrawn assignments carry no description, products, or score, and every
    // query filters them out — storing them was 39% of rows on a real backfill.
    const record = fixture('CVE-2025-32756');
    record.cveMetadata.state = 'REJECTED';

    const summary = await ingestRecords(repo, config.resolver, [record]);
    expect(summary.rejected).toBe(1);
    expect(summary.inserted).toBe(0);
    expect(await db.all('SELECT cve_id FROM cve')).toHaveLength(0);
  });

  it('keeps a CVE whose vendor matched even when no product could be mapped', async () => {
    // A vendor match with an unmapped product is a taxonomy gap, not someone
    // else's CVE — dropping it would undercount the vendor.
    const record = fixture('CVE-2025-32756');
    record.containers!.cna!.affected = [
      { vendor: 'Fortinet', product: 'FortiSomethingBrandNew' },
    ];
    record.containers!.adp = [];

    const summary = await ingestRecords(repo, config.resolver, [record]);
    expect(summary.inserted).toBe(1);
    expect(summary.unmappedCount).toBe(1);

    const queue = await repo.getUnmappedForReview();
    expect(queue[0]?.product_raw).toBe('FortiSomethingBrandNew');
  });

  it('is idempotent across repeated runs', async () => {
    const records = [fixture('CVE-2025-32756'), fixture('CVE-2024-3400')];
    expect((await ingestRecords(repo, config.resolver, records)).inserted).toBe(2);

    const second = await ingestRecords(repo, config.resolver, records);
    expect(second.inserted).toBe(0);
    expect(second.skipped).toBe(2);
    expect(await db.all('SELECT cve_id FROM cve')).toHaveLength(2);
  });

  it('resolves all three mandatory vendors into categorized products', async () => {
    await ingestRecords(repo, config.resolver, [
      fixture('CVE-2025-32756'),
      fixture('CVE-2024-3400'),
      fixture('CVE-2023-20198'),
    ]);

    const rows = await db.all<{ vendor_slug: string; n: number }>(
      'SELECT vendor_slug, COUNT(*) AS n FROM cve_product GROUP BY vendor_slug ORDER BY vendor_slug',
    );
    expect(rows.map((r) => r.vendor_slug)).toEqual(['cisco', 'fortinet', 'palo-alto']);
  });
});
