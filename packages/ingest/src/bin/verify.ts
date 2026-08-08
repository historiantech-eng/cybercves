#!/usr/bin/env node
import { parseArgs } from 'node:util';
import type { CveRecord } from '@cybercves/core';
import { Repository } from '@cybercves/db';
import { NodeSqliteDriver } from '@cybercves/db/drivers/node';
import { migrate } from '@cybercves/db/migrate';
import { fetchJson } from '../http.js';
import { rawUrlFor } from '../sources/cvelist.js';
import { fetchEpss } from '../sources/epss.js';
import { fetchKev } from '../sources/kev.js';
import { ingestRecords } from '../pipeline.js';
import { loadConfig } from '../node/config-loader.js';

/**
 * End-to-end smoke test against live data.
 *
 * Pulls real, well-known advisories from all three mandatory vendors, runs them
 * through the full pipeline, and prints the rollups the site will render. This
 * is the check that the whole chain — fetch, normalize, attribute, categorize,
 * enrich, score — agrees with reality, not just with our fixtures.
 *
 *   npm run verify
 */

const SAMPLE_CVES = [
  'CVE-2025-32756', // Fortinet FortiVoice et al, CRITICAL 9.6
  'CVE-2024-21762', // Fortinet FortiOS SSL VPN
  'CVE-2024-3400', // Palo Alto PAN-OS GlobalProtect, CRITICAL 10.0
  'CVE-2025-0108', // Palo Alto PAN-OS auth bypass
  'CVE-2023-20198', // Cisco IOS XE web UI, CRITICAL 10.0
  'CVE-2024-20353', // Cisco ASA / FTD
];

const { values } = parseArgs({
  options: {
    db: { type: 'string', default: ':memory:' },
    'skip-enrich': { type: 'boolean', default: false },
  },
});

const driver = new NodeSqliteDriver(values.db);
const repo = new Repository(driver);

try {
  await migrate(driver);

  const config = loadConfig();
  await repo.syncTaxonomy(config.categories, config.vendors, config.products);
  console.log(
    `config: ${config.vendors.length} vendors, ${config.products.length} products, ` +
      `${config.categories.length} categories\n`,
  );

  const records: CveRecord[] = [];
  for (const id of SAMPLE_CVES) {
    const url = rawUrlFor(id);
    if (!url) continue;
    try {
      records.push(await fetchJson<CveRecord>(url));
    } catch (err) {
      console.warn(`  ! ${id}: ${(err as Error).message}`);
    }
  }
  console.log(`fetched ${records.length}/${SAMPLE_CVES.length} live records`);

  const summary = await ingestRecords(repo, config.resolver, records);
  console.log(
    `ingest: ${summary.inserted} new, ${summary.unmatched} not ours, ` +
      `${summary.unmappedCount} unmapped\n`,
  );

  if (!values['skip-enrich']) {
    const kev = await fetchKev();
    await repo.upsertKev(kev.entries);
    const epss = await fetchEpss();
    const kept = await repo.upsertEpssForKnownCves(epss.entries);
    console.log(`enrichment: ${kev.entries.length} KEV entries, ${kept} EPSS scores kept\n`);
  }

  const rows = await repo.driver.all<{
    cve_id: string;
    sev: string | null;
    score: number | null;
    in_kev: number;
    epss: number | null;
    products: string | null;
  }>(
    `SELECT c.cve_id, c.cvss_severity AS sev, c.cvss_base_score AS score,
            CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END AS in_kev,
            ROUND(COALESCE(e.score, 0), 4) AS epss,
            (SELECT GROUP_CONCAT(product_slug, ', ') FROM cve_product WHERE cve_id = c.cve_id) AS products
     FROM cve c
     LEFT JOIN kev k  ON k.cve_id = c.cve_id
     LEFT JOIN epss e ON e.cve_id = c.cve_id
     ORDER BY c.cve_id`,
  );

  console.log('per-CVE resolution:');
  for (const r of rows) {
    console.log(
      `  ${r.cve_id.padEnd(16)} ${String(r.sev ?? '-').padEnd(8)} ${String(r.score ?? '-').padStart(4)}  ` +
        `kev=${r.in_kev} epss=${String(r.epss).padEnd(6)} -> ${r.products ?? '(unresolved)'}`,
    );
  }

  for (const year of [2023, 2024, 2025]) {
    const all = await repo.getVendorRollup(year, false);
    if (!all.length) continue;
    console.log(`\n${year} vendor rollup (all categories):`);
    for (const r of all) {
      console.log(
        `  ${r.name.padEnd(20)} risk=${r.risk.toFixed(1).padStart(7)}  cves=${r.cve_count}  ` +
          `kev=${r.kev_count}  critical=${r.critical_count}`,
      );
    }
    const secure = await repo.getVendorRollup(year, true);
    console.log(`  security-only: ${secure.map((r) => r.name).join(', ') || '(none)'}`);
  }

  console.log('\n2024 category breakdown (all vendors):');
  for (const row of await repo.getCategoryBreakdown(2024)) {
    console.log(
      `  ${row.name.padEnd(26)} cves=${row.cve_count} kev=${row.kev_count} ` +
        `security=${row.is_security === 1}`,
    );
  }

  const unresolved = rows.filter((r) => !r.products);
  if (unresolved.length) {
    console.log(`\nWARNING: ${unresolved.length} sample CVE(s) resolved to no product.`);
    process.exitCode = 1;
  } else {
    console.log('\nOK — every sample CVE resolved to at least one categorized product.');
  }
} finally {
  await driver.close();
}
