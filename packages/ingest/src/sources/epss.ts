import type { EpssEntry } from '@cybercves/core';
import { fetchWithRetry } from '../http.js';

/**
 * FIRST EPSS — the probability a CVE will be exploited in the next 30 days.
 *
 * ATTRIBUTION: FIRST requires visible attribution for EPSS data. The site footer
 * and /methodology must credit "EPSS data courtesy of FIRST — https://first.org/epss".
 * Do not remove that without checking the current terms.
 *
 * The bulk CSV is preferred over the per-CVE API: one ~2.5 MB gzipped request
 * covers every CVE, versus tens of thousands of individual lookups.
 */

export const EPSS_CSV_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';

export const EPSS_ATTRIBUTION = 'EPSS data courtesy of FIRST — https://first.org/epss';

/**
 * Parse the EPSS CSV.
 *
 * Format verified live on 2026-07-27:
 *   #model_version:v2026.06.15,score_date:2026-07-26T12:04:59Z
 *   cve,epss,percentile
 *   CVE-1999-0001,0.03351,0.87423
 */
export function parseEpssCsv(csv: string): { asOf: string; entries: EpssEntry[] } {
  const lines = csv.split('\n');
  let asOf = new Date().toISOString().slice(0, 10);
  const entries: EpssEntry[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    if (trimmed.startsWith('#')) {
      const match = /score_date:([0-9T:\-.]+Z?)/.exec(trimmed);
      if (match?.[1]) asOf = match[1].slice(0, 10);
      continue;
    }
    if (trimmed.startsWith('cve,')) continue; // header row

    const [cveId, score, percentile] = trimmed.split(',');
    if (!cveId?.startsWith('CVE-')) continue;

    const scoreNum = Number.parseFloat(score ?? '');
    const percentileNum = Number.parseFloat(percentile ?? '');
    if (!Number.isFinite(scoreNum) || !Number.isFinite(percentileNum)) continue;

    entries.push({ cveId, score: scoreNum, percentile: percentileNum, asOf });
  }

  return { asOf, entries };
}

/**
 * Fetch and decompress the current EPSS snapshot.
 *
 * DecompressionStream is a web standard available in both Node 18+ and Workers,
 * so this needs no zlib import and no platform branch.
 */
export async function fetchEpss(url = EPSS_CSV_URL): Promise<{ asOf: string; entries: EpssEntry[] }> {
  const response = await fetchWithRetry(url, { timeoutMs: 120_000 });
  if (!response.body) throw new Error('EPSS response had no body');

  const stream = response.body.pipeThrough(new DecompressionStream('gzip'));
  const csv = await new Response(stream).text();
  return parseEpssCsv(csv);
}
