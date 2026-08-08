import type { CveMetric, CveRecord, CvssPayload } from './cve-schema.js';
import type { CvssResult, CvssVersion, Severity } from './types.js';

/** Preference order per the plan: v4 > v3.1 > v3.0 > v2. */
const VERSION_PRIORITY: ReadonlyArray<{ key: keyof CveMetric; version: CvssVersion }> = [
  { key: 'cvssV4_0', version: '4.0' },
  { key: 'cvssV3_1', version: '3.1' },
  { key: 'cvssV3_0', version: '3.0' },
  { key: 'cvssV2_0', version: '2.0' },
];

const SEVERITIES: ReadonlySet<string> = new Set(['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

/**
 * Derive severity from a base score. CVSS v2 has no CRITICAL band and no
 * publisher-supplied baseSeverity, so it gets its own thresholds — treating a
 * v2 score of 9.5 as CRITICAL would silently inflate historical risk scores.
 */
export function severityFromScore(score: number, version: CvssVersion): Severity {
  if (score <= 0) return 'NONE';
  if (version === '2.0') {
    if (score < 4.0) return 'LOW';
    if (score < 7.0) return 'MEDIUM';
    return 'HIGH';
  }
  if (score < 4.0) return 'LOW';
  if (score < 7.0) return 'MEDIUM';
  if (score < 9.0) return 'HIGH';
  return 'CRITICAL';
}

function readPayload(
  payload: CvssPayload | undefined,
  version: CvssVersion,
  source: 'cna' | 'adp',
): CvssResult | null {
  if (!payload || typeof payload.baseScore !== 'number' || Number.isNaN(payload.baseScore)) {
    return null;
  }
  const declared = payload.baseSeverity?.toUpperCase();
  return {
    version,
    vectorString: payload.vectorString ?? null,
    baseScore: payload.baseScore,
    severity:
      declared && SEVERITIES.has(declared)
        ? (declared as Severity)
        : severityFromScore(payload.baseScore, version),
    source,
  };
}

function bestFromMetrics(
  metrics: CveMetric[] | undefined,
  source: 'cna' | 'adp',
): CvssResult | null {
  if (!metrics?.length) return null;
  for (const { key, version } of VERSION_PRIORITY) {
    for (const metric of metrics) {
      const result = readPayload(metric[key] as CvssPayload | undefined, version, source);
      if (result) return result;
    }
  }
  return null;
}

/**
 * Pick the best available CVSS for a record.
 *
 * CNA-supplied metrics win over ADP enrichment even when the ADP offers a newer
 * CVSS version — the vendor's own scoring is the authoritative claim about their
 * product, and mixing sources across vendors would make scores incomparable.
 * Falls back to ADP (typically CISA-ADP) when the CNA published no metrics at all,
 * which is common for older records.
 */
export function extractCvss(record: CveRecord): CvssResult | null {
  const cna = bestFromMetrics(record.containers?.cna?.metrics, 'cna');
  if (cna) return cna;

  for (const adp of record.containers?.adp ?? []) {
    const found = bestFromMetrics(adp.metrics, 'adp');
    if (found) return found;
  }
  return null;
}
