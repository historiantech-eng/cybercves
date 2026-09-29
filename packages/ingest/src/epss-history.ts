import { EPSS_HISTORY_DAYS, epssDayBefore } from '@cybercves/core';
import type { Repository } from '@cybercves/db';
import { epssUrlForDate, fetchEpss } from './sources/epss.js';

/**
 * Store the EPSS snapshots from 7 and 30 days before `asOf`.
 *
 * Never throws. A missing archive day or a FIRST outage must not fail a deploy:
 * the only consequence is that /priority hides its "rising" section and says the
 * history is unavailable, which is true. Each day is independent, so one
 * failure still keeps the other.
 */
export async function refreshEpssHistory(
  repo: Repository,
  asOf: string,
  log: (line: string) => void = console.log,
): Promise<{ day: string; kept: number | null }[]> {
  const results: { day: string; kept: number | null }[] = [];
  for (const days of EPSS_HISTORY_DAYS) {
    const day = epssDayBefore(asOf, days);
    try {
      const snapshot = await fetchEpss(epssUrlForDate(day));
      const kept = await repo.upsertEpssHistoryForKnownCves(snapshot.entries);
      log(`epss history: ${day} (${days}d) — ${kept} scores kept`);
      results.push({ day, kept });
    } catch (err) {
      log(`epss history: ${day} (${days}d) unavailable — ${(err as Error).message}`);
      results.push({ day, kept: null });
    }
  }
  return results;
}
