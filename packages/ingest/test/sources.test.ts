import { describe, expect, it } from 'vitest';
import { changedEntries, rawUrlFor, recordPath } from '../src/sources/cvelist.js';
import type { DeltaFeed } from '../src/sources/cvelist.js';
import { parseEpssCsv } from '../src/sources/epss.js';
import { loadConfig } from '../src/node/config-loader.js';

describe('cvelist record paths', () => {
  it('buckets by the sequence number, not by padding', () => {
    // CVE-2024-3400 lives in 3xxx, not 0xxx — getting this wrong 404s every
    // four-digit CVE, which is most of them.
    expect(recordPath('CVE-2024-3400')).toBe('cves/2024/3xxx/CVE-2024-3400.json');
    expect(recordPath('CVE-2025-32756')).toBe('cves/2025/32xxx/CVE-2025-32756.json');
    expect(recordPath('CVE-2023-20198')).toBe('cves/2023/20xxx/CVE-2023-20198.json');
  });

  it('handles short sequence numbers', () => {
    expect(recordPath('CVE-1999-0001')).toBe('cves/1999/0xxx/CVE-1999-0001.json');
    expect(recordPath('CVE-2015-999')).toBe('cves/2015/0xxx/CVE-2015-999.json');
  });

  it('rejects malformed ids rather than building a bad URL', () => {
    expect(recordPath('not-a-cve')).toBeNull();
    expect(recordPath('CVE-2024-ABCD')).toBeNull();
    expect(rawUrlFor('nonsense')).toBeNull();
  });

  it('builds a raw GitHub URL', () => {
    expect(rawUrlFor('CVE-2025-32756')).toBe(
      'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/32xxx/CVE-2025-32756.json',
    );
  });
});

describe('changedEntries', () => {
  const entry = (cveId: string, dateUpdated: string) => ({
    cveId,
    githubLink: `https://example.test/${cveId}.json`,
    dateUpdated,
  });

  it('merges new and updated, newest first', () => {
    const feed: DeltaFeed = {
      fetchTime: '2026-07-27T01:36:23.631Z',
      numberOfChanges: 3,
      new: [entry('CVE-2026-1000', '2026-07-27T01:00:00Z')],
      updated: [
        entry('CVE-2026-2000', '2026-07-27T01:30:00Z'),
        entry('CVE-2026-3000', '2026-07-27T00:30:00Z'),
      ],
    };
    expect(changedEntries(feed).map((e) => e.cveId)).toEqual([
      'CVE-2026-2000',
      'CVE-2026-1000',
      'CVE-2026-3000',
    ]);
  });

  it('dedupes a record appearing in both lists, keeping the later revision', () => {
    const feed: DeltaFeed = {
      fetchTime: '2026-07-27T01:36:23.631Z',
      numberOfChanges: 2,
      new: [entry('CVE-2026-1000', '2026-07-27T01:00:00Z')],
      updated: [entry('CVE-2026-1000', '2026-07-27T01:30:00Z')],
    };
    const result = changedEntries(feed);
    expect(result).toHaveLength(1);
    expect(result[0]?.dateUpdated).toBe('2026-07-27T01:30:00Z');
  });

  it('tolerates a feed with no changes', () => {
    expect(changedEntries({ fetchTime: 'now', numberOfChanges: 0 })).toEqual([]);
  });
});

describe('parseEpssCsv', () => {
  // Format verified live on 2026-07-27.
  const csv = [
    '#model_version:v2026.06.15,score_date:2026-07-26T12:04:59Z',
    'cve,epss,percentile',
    'CVE-1999-0001,0.03351,0.87423',
    'CVE-2024-3400,0.99999,1.00000',
    '',
  ].join('\n');

  it('reads the score date out of the comment header', () => {
    expect(parseEpssCsv(csv).asOf).toBe('2026-07-26');
  });

  it('parses scores and skips the header row', () => {
    const { entries } = parseEpssCsv(csv);
    expect(entries).toHaveLength(2);
    expect(entries[1]).toEqual({
      cveId: 'CVE-2024-3400',
      score: 0.99999,
      percentile: 1,
      asOf: '2026-07-26',
    });
  });

  it('skips malformed rows instead of poisoning scores with NaN', () => {
    const { entries } = parseEpssCsv('cve,epss,percentile\nCVE-2024-1,abc,def\nCVE-2024-2,0.5,0.6');
    expect(entries).toHaveLength(1);
    expect(entries[0]?.cveId).toBe('CVE-2024-2');
  });
});

describe('committed config loads through the Node loader', () => {
  it('produces a working resolver from /data', () => {
    const config = loadConfig();
    expect(config.vendors.map((v) => v.slug).sort()).toEqual(['cisco', 'fortinet', 'palo-alto']);
    expect(config.resolver.resolveProductName('fortinet', 'FortiGate')).toBe('fortinet-fortigate');
    expect(config.resolver.getProduct('palo-alto-pan-os')?.categorySlug).toBe('firewall');
  });
});
