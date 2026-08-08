import { describe, expect, it } from 'vitest';
import {
  KEV_MULTIPLIER,
  SEVERITY_WEIGHTS,
  UNSCORED_WEIGHT,
  aggregateRisk,
  cveRisk,
  epssFactor,
  methodology,
  severityWeight,
} from '../src/scoring.js';

describe('epssFactor', () => {
  it('returns 1.0 when FIRST has no estimate, so absence neither helps nor hurts', () => {
    expect(epssFactor(null)).toBe(1);
    expect(epssFactor(Number.NaN)).toBe(1);
  });

  it('scales linearly across [0,1] to at most a doubling', () => {
    expect(epssFactor(0)).toBe(1);
    expect(epssFactor(0.5)).toBe(1.5);
    expect(epssFactor(1)).toBe(2);
  });

  it('clamps out-of-range input rather than trusting it', () => {
    expect(epssFactor(-3)).toBe(1);
    expect(epssFactor(42)).toBe(2);
  });
});

describe('severityWeight', () => {
  it('treats an unscored CVE as LOW rather than imputing a median', () => {
    expect(severityWeight(null)).toBe(UNSCORED_WEIGHT);
    expect(UNSCORED_WEIGHT).toBe(SEVERITY_WEIGHTS.LOW);
  });

  it('scores NONE as zero risk', () => {
    expect(severityWeight('NONE')).toBe(0);
  });
});

describe('cveRisk', () => {
  it('matches hand-computed values', () => {
    // CRITICAL(10) x no KEV(1) x epss 0.0(1.0) = 10
    expect(cveRisk({ severity: 'CRITICAL', inKev: false, epssScore: 0 })).toBe(10);
    // HIGH(5) x no KEV(1) x epss 0.5(1.5) = 7.5
    expect(cveRisk({ severity: 'HIGH', inKev: false, epssScore: 0.5 })).toBe(7.5);
    // MEDIUM(2) x KEV(4) x epss 0.25(1.25) = 10
    expect(cveRisk({ severity: 'MEDIUM', inKev: true, epssScore: 0.25 })).toBe(10);
  });

  it('applies the full KEV multiplier to a maximally exploited critical', () => {
    // CRITICAL(10) x KEV(4) x epss 1.0(2.0) = 80 — the ceiling for a single CVE.
    expect(cveRisk({ severity: 'CRITICAL', inKev: true, epssScore: 1 })).toBe(80);
  });

  it('handles a null EPSS score without discarding severity or KEV', () => {
    expect(cveRisk({ severity: 'CRITICAL', inKev: false, epssScore: null })).toBe(10);
    expect(cveRisk({ severity: 'CRITICAL', inKev: true, epssScore: null })).toBe(
      10 * KEV_MULTIPLIER,
    );
  });

  it('scores an unscored non-KEV CVE as the minimum non-zero risk', () => {
    expect(cveRisk({ severity: null, inKev: false, epssScore: null })).toBe(1);
  });

  it('still escalates an unscored CVE that is known-exploited', () => {
    // A CVE with no CVSS but a KEV listing is a real, common case — it must not
    // score the same as an unscored CVE nobody is exploiting.
    expect(cveRisk({ severity: null, inKev: true, epssScore: null })).toBe(4);
  });

  it('ranks a known-exploited medium above an unexploited critical', () => {
    const exploitedMedium = cveRisk({ severity: 'MEDIUM', inKev: true, epssScore: 0.9 });
    const quietCritical = cveRisk({ severity: 'CRITICAL', inKev: false, epssScore: 0.01 });
    expect(exploitedMedium).toBeGreaterThan(quietCritical);
  });
});

describe('aggregateRisk', () => {
  it('sums per-CVE risk', () => {
    expect(
      aggregateRisk([
        { severity: 'CRITICAL', inKev: false, epssScore: 0 },
        { severity: 'HIGH', inKev: false, epssScore: 0 },
        { severity: 'LOW', inKev: false, epssScore: 0 },
      ]),
    ).toBe(16);
  });

  it('is zero for an empty set', () => {
    expect(aggregateRisk([])).toBe(0);
  });
});

describe('methodology', () => {
  it('publishes the same constants the scorer uses', () => {
    // /methodology renders from this object, so the documented formula cannot
    // drift from the one that produced the numbers.
    const m = methodology();
    expect(m.severityWeights).toBe(SEVERITY_WEIGHTS);
    expect(m.kevMultiplier).toBe(KEV_MULTIPLIER);
    expect(m.unscoredWeight).toBe(UNSCORED_WEIGHT);
    expect(m.caveat).toMatch(/disclosure diligence/i);
  });
});
