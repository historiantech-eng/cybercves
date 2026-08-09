import { describe, expect, it } from 'vitest';
import type { CveRow } from '../src/lib/cve-rows';
import { aggregateSeverity, aggregateSeverityBy, segmentsOf } from '../src/lib/severity';

const row = (s: string | null, v: string[] = ['cisco'], g: string[] = ['firewall']): CveRow => ({
  i: `CVE-2026-${Math.random().toString().slice(2, 7)}`,
  d: '2026-01-01',
  s,
  c: null,
  w: null,
  k: 0,
  e: null,
  v,
  p: [],
  g,
});

describe('aggregateSeverity', () => {
  it('counts each band', () => {
    const { total, counts } = aggregateSeverity([
      row('CRITICAL'),
      row('HIGH'),
      row('HIGH'),
      row('MEDIUM'),
      row('LOW'),
    ]);
    expect(total).toBe(5);
    expect(counts).toMatchObject({ CRITICAL: 1, HIGH: 2, MEDIUM: 1, LOW: 1, UNSCORED: 0 });
  });

  it('folds NONE and null into Unscored rather than dropping them', () => {
    // Dropping these would make the segments sum to less than the result count
    // shown beside them, which reads as a broken chart rather than a data gap.
    const { total, counts } = aggregateSeverity([row(null), row('NONE'), row('HIGH')]);
    expect(total).toBe(3);
    expect(counts.UNSCORED).toBe(2);
    expect(counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW + counts.UNSCORED).toBe(total);
  });

  it('is case-insensitive about the band', () => {
    expect(aggregateSeverity([row('critical')]).counts.CRITICAL).toBe(1);
  });

  it('handles an empty slice without dividing by anything', () => {
    const { total, counts } = aggregateSeverity([]);
    expect(total).toBe(0);
    expect(Object.values(counts).every((n) => n === 0)).toBe(true);
  });
});

describe('aggregateSeverityBy', () => {
  it('counts a multi-vendor CVE once under each vendor', () => {
    // Same rule as the vendor rollups: it is a real vulnerability in each. Group
    // totals therefore exceed the overall total, which is why the grouped view
    // labels each row with its own total instead of implying one whole.
    const groups = aggregateSeverityBy([row('HIGH', ['cisco', 'fortinet'])], 'vendor');
    expect(groups.map((g) => g.key).sort()).toEqual(['cisco', 'fortinet']);
    expect(groups.every((g) => g.total === 1 && g.counts.HIGH === 1)).toBe(true);
  });

  it('counts a CVE once per group even if a slug repeats', () => {
    const dupe = row('HIGH');
    dupe.v = ['cisco', 'cisco'];
    expect(aggregateSeverityBy([dupe], 'vendor')[0]?.total).toBe(1);
  });

  it('orders by total descending, then by label', () => {
    const groups = aggregateSeverityBy(
      [
        row('HIGH', ['fortinet']),
        row('LOW', ['cisco']),
        row('LOW', ['cisco']),
        row('MEDIUM', ['cisco']),
      ],
      'vendor',
    );
    expect(groups.map((g) => g.key)).toEqual(['cisco', 'fortinet']);
    expect(groups[0]?.total).toBe(3);
  });

  it('groups by category and resolves display labels', () => {
    const groups = aggregateSeverityBy(
      [row('CRITICAL', ['cisco'], ['firewall', 'endpoint'])],
      'category',
      { firewall: 'Firewall / NGFW', endpoint: 'Endpoint / EDR' },
    );
    expect(groups.map((g) => g.label).sort()).toEqual(['Endpoint / EDR', 'Firewall / NGFW']);
  });

  it('falls back to the slug when no label is supplied', () => {
    expect(aggregateSeverityBy([row('LOW')], 'vendor')[0]?.label).toBe('cisco');
  });

  it('drops rows that belong to no group rather than inventing one', () => {
    expect(aggregateSeverityBy([row('HIGH', [])], 'vendor')).toEqual([]);
  });
});

describe('segmentsOf', () => {
  it('keeps the fixed worst-first order and drops empty buckets', () => {
    const { counts } = aggregateSeverity([row('LOW'), row('CRITICAL'), row('MEDIUM')]);
    expect(segmentsOf(counts).map((s) => s.bucket)).toEqual(['CRITICAL', 'MEDIUM', 'LOW']);
  });

  it('pairs every segment with a label and a status token', () => {
    // Colour alone cannot identify these — High and Medium are ΔE 13.6 apart in
    // normal vision — so a segment without a label is not renderable.
    const { counts } = aggregateSeverity([row('HIGH'), row('MEDIUM')]);
    expect(segmentsOf(counts)).toEqual([
      { bucket: 'HIGH', label: 'High', token: 'serious', n: 1 },
      { bucket: 'MEDIUM', label: 'Medium', token: 'warning', n: 1 },
    ]);
  });
});
