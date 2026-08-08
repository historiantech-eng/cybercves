import type { Severity } from './types.js';

/**
 * Risk scoring. Every constant here is exported so the public /methodology page
 * renders from this exact source — the published formula can never drift from
 * the one that produced the numbers.
 *
 *   cve_risk = severity_weight x kev_multiplier x epss_factor
 *
 * Rationale: raw CVE counts reward vendors with *worse* disclosure programs.
 * A vendor that publishes diligently accumulates CVEs; one that quietly patches
 * does not. Weighting by severity, known exploitation, and exploit probability
 * measures something closer to real-world exposure.
 */

export const SEVERITY_WEIGHTS: Readonly<Record<Severity, number>> = {
  CRITICAL: 10,
  HIGH: 5,
  MEDIUM: 2,
  LOW: 1,
  NONE: 0,
};

/** Presence in the CISA KEV catalog — confirmed exploitation in the wild. */
export const KEV_MULTIPLIER = 4;

/**
 * Weight applied when a CVE has no CVSS score from any source. Common in
 * pre-2020 records. Deliberately the LOW weight rather than an imputed median:
 * we do not invent severity we were not given. The share of unscored CVEs is
 * disclosed on /methodology so the reader can judge the effect.
 */
export const UNSCORED_WEIGHT = SEVERITY_WEIGHTS.LOW;

export interface RiskInput {
  severity: Severity | null;
  inKev: boolean;
  /** EPSS probability in [0,1], or null when FIRST has no estimate for this CVE. */
  epssScore: number | null;
}

/**
 * EPSS contributes a factor in [1.0, 2.0] — at most doubling the score. A missing
 * EPSS estimate yields 1.0 (no effect), so absence never penalises or rewards.
 */
export function epssFactor(epssScore: number | null): number {
  if (epssScore === null || Number.isNaN(epssScore)) return 1;
  const clamped = Math.min(Math.max(epssScore, 0), 1);
  return 1 + clamped;
}

export function severityWeight(severity: Severity | null): number {
  if (severity === null) return UNSCORED_WEIGHT;
  return SEVERITY_WEIGHTS[severity];
}

export function cveRisk(input: RiskInput): number {
  const weight = severityWeight(input.severity);
  const kev = input.inKev ? KEV_MULTIPLIER : 1;
  return weight * kev * epssFactor(input.epssScore);
}

/** Sum of per-CVE risk. Used for vendor-year, product-year, and category-year rollups. */
export function aggregateRisk(inputs: readonly RiskInput[]): number {
  let total = 0;
  for (const input of inputs) total += cveRisk(input);
  return total;
}

/** Machine-readable description of the model, rendered directly onto /methodology. */
export function methodology() {
  return {
    formula: 'cve_risk = severity_weight x kev_multiplier x epss_factor',
    severityWeights: SEVERITY_WEIGHTS,
    kevMultiplier: KEV_MULTIPLIER,
    unscoredWeight: UNSCORED_WEIGHT,
    epssFactorRange: [1, 2] as const,
    cvssPreference: ['4.0', '3.1', '3.0', '2.0'] as const,
    caveat:
      'CVE volume reflects disclosure diligence as much as product quality. A vendor ' +
      'that publishes thoroughly will accumulate more CVEs than one that patches ' +
      'silently. These scores measure disclosed, weighted exposure — not engineering quality.',
  };
}
