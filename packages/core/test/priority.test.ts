import { describe, expect, it } from 'vitest';
import { PRIORITY, comparePriority, priorityTier, type PriorityInput } from '../src/priority.js';

const NOW = new Date('2026-09-29T00:00:00Z');

const base: PriorityInput = {
  inKev: false,
  ransomware: false,
  epss: 0.01,
  epssPrior: 0.01,
  severity: 'MEDIUM',
  exposure: 'other',
  published: '2026-09-01',
};

describe('priorityTier', () => {
  it('puts anything in KEV in tier 1, whatever else is true', () => {
    expect(priorityTier({ ...base, inKev: true }, NOW)).toEqual({ tier: 1, reasons: ['In CISA KEV'] });
    expect(priorityTier({ ...base, inKev: true, ransomware: true }, NOW).reasons).toContain(
      'Known ransomware use',
    );
  });

  it('puts a high EPSS in tier 2', () => {
    const result = priorityTier({ ...base, epss: PRIORITY.epssHigh, epssPrior: 0.09 }, NOW);
    expect(result.tier).toBe(2);
    expect(result.reasons).toEqual(['EPSS 0.10']);
  });

  it('puts a sharp EPSS rise in tier 2 even when the score is still low', () => {
    const result = priorityTier({ ...base, epss: 0.07, epssPrior: 0.01 }, NOW);
    expect(result.tier).toBe(2);
    expect(result.reasons).toEqual(['EPSS up 0.06 in 30 days']);
  });

  it('does not invent a rise when there is no earlier score', () => {
    expect(priorityTier({ ...base, epss: 0.07, epssPrior: null }, NOW).tier).toBeNull();
  });

  it('puts fresh, serious, remote-unauth CVEs in tier 3', () => {
    const result = priorityTier(
      { ...base, severity: 'CRITICAL', exposure: 'remote-unauth', published: '2026-09-19' },
      NOW,
    );
    expect(result).toEqual({ tier: 3, reasons: ['Remote, no auth', 'Critical, 10 days old'] });
  });

  it('leaves tier 3 when any one of its conditions fails', () => {
    const t3 = { ...base, severity: 'HIGH', exposure: 'remote-unauth' as const, published: '2026-09-19' };
    expect(priorityTier(t3, NOW).tier).toBe(3);
    expect(priorityTier({ ...t3, severity: 'MEDIUM' }, NOW).tier).toBeNull();
    expect(priorityTier({ ...t3, exposure: 'remote' }, NOW).tier).toBeNull();
    expect(priorityTier({ ...t3, published: '2026-05-01' }, NOW).tier).toBeNull();
    expect(priorityTier({ ...t3, published: null }, NOW).tier).toBeNull();
  });
});

describe('comparePriority', () => {
  it('orders by tier, then ransomware within KEV, then EPSS', () => {
    const rows = [
      { tier: 2 as const, reasons: [], ransomware: false, epss: 0.9 },
      { tier: 1 as const, reasons: [], ransomware: false, epss: 0.8 },
      { tier: 1 as const, reasons: [], ransomware: true, epss: 0.1 },
      { tier: 1 as const, reasons: [], ransomware: false, epss: 0.95 },
      { tier: null, reasons: [], ransomware: false, epss: 0.99 },
    ];
    expect(rows.sort(comparePriority).map((r) => [r.tier, r.ransomware, r.epss])).toEqual([
      [1, true, 0.1],
      [1, false, 0.95],
      [1, false, 0.8],
      [2, false, 0.9],
      [null, false, 0.99],
    ]);
  });
});
