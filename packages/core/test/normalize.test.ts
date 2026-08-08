import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { CveRecord } from '../src/cve-schema.js';
import { hashRecord, normalizeCve, publishedYear } from '../src/normalize.js';
import { severityFromScore } from '../src/cvss.js';

/**
 * These run against unmodified records pulled from CVEProject/cvelistV5. They are
 * the regression net for parser changes: any edit to normalization that alters
 * how a real vendor record is read will fail here rather than silently skewing
 * published counts.
 */
function fixture(id: string): CveRecord {
  const path = fileURLToPath(new URL(`./fixtures/${id}.json`, import.meta.url));
  return JSON.parse(readFileSync(path, 'utf8')) as CveRecord;
}

describe('normalizeCve — Fortinet CVE-2025-32756', () => {
  const cve = normalizeCve(fixture('CVE-2025-32756'));

  it('reads CNA identity and publication metadata', () => {
    expect(cve.cveId).toBe('CVE-2025-32756');
    expect(cve.assignerShortName).toBe('fortinet');
    expect(cve.state).toBe('PUBLISHED');
    expect(publishedYear(cve)).toBe(2025);
  });

  it('extracts CVSS v3.1 from the CNA container', () => {
    expect(cve.cvss).not.toBeNull();
    expect(cve.cvss?.version).toBe('3.1');
    expect(cve.cvss?.baseScore).toBe(9.6);
    expect(cve.cvss?.severity).toBe('CRITICAL');
    expect(cve.cvss?.source).toBe('cna');
  });

  it('captures every affected product with its CPE', () => {
    const products = cve.affected.map((a) => a.productRaw);
    expect(products).toEqual(
      expect.arrayContaining(['FortiNDR', 'FortiCamera', 'FortiRecorder', 'FortiVoice', 'FortiMail']),
    );
    const ndr = cve.affected.find((a) => a.productRaw === 'FortiNDR');
    expect(ndr?.vendorRaw).toBe('Fortinet');
    expect(ndr?.cpes[0]).toContain('cpe:2.3:a:fortinet:fortindr');
  });

  it('records the CWE and links back to the Fortinet PSIRT advisory', () => {
    expect(cve.cweIds).toContain('CWE-121');
    expect(cve.references.map((r) => r.url)).toContain(
      'https://fortiguard.fortinet.com/psirt/FG-IR-25-254',
    );
  });
});

describe('normalizeCve — Palo Alto CVE-2024-3400', () => {
  const cve = normalizeCve(fixture('CVE-2024-3400'));

  it('uses the underscored CNA short name Palo Alto actually publishes', () => {
    expect(cve.assignerShortName).toBe('palo_alto');
  });

  it('reads the title and a maximum-severity CVSS v3.1 score', () => {
    expect(cve.title).toContain('PAN-OS');
    expect(cve.cvss?.version).toBe('3.1');
    expect(cve.cvss?.baseScore).toBe(10);
    expect(cve.cvss?.severity).toBe('CRITICAL');
  });

  it('captures the CNA products, which carry no CPEs of their own', () => {
    const products = cve.affected.map((a) => a.productRaw);
    expect(products).toEqual(expect.arrayContaining(['PAN-OS', 'Cloud NGFW', 'Prisma Access']));
    // Palo Alto's own container publishes no CPEs, which is why vendor alias
    // matching rather than CPE matching is load-bearing for this vendor.
    const cnaEntries = cve.affected.filter((a) => a.vendorRaw === 'Palo Alto Networks');
    expect(cnaEntries).not.toHaveLength(0);
    expect(cnaEntries.every((a) => a.cpes.length === 0)).toBe(true);
  });

  it('also absorbs the CPEs CISA-ADP backfills', () => {
    // ADP enrichment is often the only precise product identifier on a record,
    // so normalization reads ADP containers as well as the CNA's.
    const adpEntries = cve.affected.filter((a) => a.cpes.length > 0);
    expect(adpEntries).not.toHaveLength(0);
    expect(adpEntries[0]?.cpes[0]).toContain('cpe:2.3:o:paloaltonetworks:pan-os');
    expect(adpEntries[0]?.vendorRaw).toBe('paloaltonetworks');
  });
});

describe('normalizeCve — Cisco CVE-2023-20198', () => {
  const cve = normalizeCve(fixture('CVE-2023-20198'));

  it('reads Cisco CNA identity and IOS XE as the affected product', () => {
    expect(cve.assignerShortName).toBe('cisco');
    expect(cve.affected.map((a) => a.productRaw)).toContain('Cisco IOS XE Software');
    expect(cve.cvss?.baseScore).toBe(10);
  });

  it('links to the Cisco security advisory host', () => {
    expect(cve.references.some((r) => r.url.includes('sec.cloudapps.cisco.com'))).toBe(true);
  });
});

describe('hashRecord', () => {
  it('is stable across repeated calls', () => {
    const record = fixture('CVE-2025-32756');
    expect(hashRecord(record)).toBe(hashRecord(record));
  });

  it('ignores churn in fields we do not persist', () => {
    const record = fixture('CVE-2025-32756');
    const before = hashRecord(record);
    // Upstream republishes bump dateUpdated without changing anything we display;
    // rehashing on that would rewrite every row on every sync.
    record.cveMetadata.dateUpdated = '2099-01-01T00:00:00.000Z';
    expect(hashRecord(record)).toBe(before);
  });

  it('changes when displayed content changes', () => {
    const record = fixture('CVE-2025-32756');
    const before = hashRecord(record);
    record.containers!.cna!.descriptions = [{ lang: 'en', value: 'different text' }];
    expect(hashRecord(record)).not.toBe(before);
  });

  it('distinguishes different records', () => {
    expect(hashRecord(fixture('CVE-2025-32756'))).not.toBe(hashRecord(fixture('CVE-2024-3400')));
  });
});

describe('severityFromScore', () => {
  it('applies CVSS v3 bands', () => {
    expect(severityFromScore(0, '3.1')).toBe('NONE');
    expect(severityFromScore(3.9, '3.1')).toBe('LOW');
    expect(severityFromScore(4.0, '3.1')).toBe('MEDIUM');
    expect(severityFromScore(7.0, '3.1')).toBe('HIGH');
    expect(severityFromScore(9.0, '3.1')).toBe('CRITICAL');
    expect(severityFromScore(10, '3.1')).toBe('CRITICAL');
  });

  it('never reports CRITICAL for CVSS v2, which has no such band', () => {
    // Treating a v2 9.5 as CRITICAL would silently inflate historical risk scores.
    expect(severityFromScore(9.5, '2.0')).toBe('HIGH');
    expect(severityFromScore(7.0, '2.0')).toBe('HIGH');
    expect(severityFromScore(3.9, '2.0')).toBe('LOW');
  });
});

describe('version range capping', () => {
  it('caps stored ranges and records what was dropped', () => {
    // Some vendors enumerate every patch level rather than expressing a range —
    // one real Cisco record lists 2,699, which serializes past SQLite's
    // statement-size limit and fails the insert outright (SQLITE_TOOBIG).
    const record = fixture('CVE-2025-32756');
    record.containers!.cna!.affected = [
      {
        vendor: 'Cisco',
        product: 'Cisco BroadWorks',
        versions: Array.from({ length: 2699 }, (_, i) => ({
          version: `1.0.${i}`,
          status: 'affected' as const,
        })),
      },
    ];
    record.containers!.adp = [];

    const cve = normalizeCve(record);
    const entry = cve.affected[0]!;
    expect(entry.versions).toHaveLength(50);
    expect(entry.versionsTruncated).toBe(true);
    expect(entry.versionCount).toBe(2699);

    // The serialized row must stay far below the ~1MB statement ceiling.
    expect(JSON.stringify(entry.versions).length).toBeLessThan(10_000);
  });

  it('leaves normal version lists untouched', () => {
    const cve = normalizeCve(fixture('CVE-2024-3400'));
    for (const entry of cve.affected) {
      expect(entry.versionsTruncated).toBe(false);
      expect(entry.versionCount).toBe(entry.versions.length);
    }
  });
});

describe('CPE capping', () => {
  it('caps CPEs without losing the vendor/product signal', () => {
    // Vendors that enumerate versions emit one CPE per version — ~2,400 on a real
    // Cisco record, ~120KB in one row, which fails the insert.
    const record = fixture('CVE-2025-32756');
    record.containers!.cna!.affected = [
      {
        vendor: 'cisco',
        product: 'ios_xe',
        cpes: Array.from({ length: 2434 }, (_, i) => `cpe:2.3:o:cisco:ios_xe:17.${i}:*:*:*:*:*:*:*`),
      },
    ];
    record.containers!.adp = [];

    const entry = normalizeCve(record).affected[0]!;
    expect(entry.cpes).toHaveLength(20);
    // Every CPE in one entry shares vendor and product, so capping loses nothing
    // the resolver uses.
    expect(entry.cpes[0]).toContain('cpe:2.3:o:cisco:ios_xe');
    expect(JSON.stringify(entry.cpes).length).toBeLessThan(5_000);
  });
});
