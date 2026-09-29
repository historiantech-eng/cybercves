import type { Exposure } from './cvss.js';

/**
 * Patch priority, as three plain tiers rather than a blended score.
 *
 * A score would rank everything, and in doing so imply a precision the inputs do
 * not have. Tiers say something a reader can check: "this one is on CISA's list,
 * this one is being scored as likely to be exploited, this one is new and open
 * to anyone on the network". Every CVE that lands in a tier carries the reasons
 * that put it there, and /methodology renders these same constants, so the page
 * cannot describe a rule the code does not apply.
 *
 * What this is NOT: a statement that the reader is affected. That depends on the
 * version they run, which is what /check answers.
 */
export const PRIORITY = {
  /** EPSS at or above this puts a CVE in tier 2 on its own. */
  epssHigh: 0.1,
  /** An absolute EPSS rise at least this large over `riseWindowDays` also does. */
  epssRise: 0.05,
  riseWindowDays: 30,
  /** Tier 3 only considers CVEs published within this many days. */
  freshDays: 90,
} as const;

/**
 * Which archived EPSS days the build fetches, counted back from the current
 * snapshot. The longer one is the rise window tier 2 uses.
 */
export const EPSS_HISTORY_DAYS = [7, PRIORITY.riseWindowDays] as const;

/** The scoring day `days` before `asOf` (YYYY-MM-DD or ISO in, YYYY-MM-DD out, UTC). */
export function epssDayBefore(asOf: string, days: number): string {
  const date = new Date(`${asOf.slice(0, 10)}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() - days);
  return date.toISOString().slice(0, 10);
}

export type PriorityTier = 1 | 2 | 3;

export const PRIORITY_TIERS: ReadonlyArray<{ tier: PriorityTier; label: string; rule: string }> = [
  {
    tier: 1,
    label: 'Exploited now',
    rule: 'Listed in the CISA Known Exploited Vulnerabilities catalog. Those linked to ransomware campaigns sort first.',
  },
  {
    tier: 2,
    label: 'Likely next',
    rule:
      `Not yet in KEV, but EPSS is at least ${PRIORITY.epssHigh} or has risen by at least ` +
      `${PRIORITY.epssRise} over the last ${PRIORITY.riseWindowDays} days.`,
  },
  {
    tier: 3,
    label: 'Open to the network',
    rule:
      `Critical or High, reachable remotely with no authentication and no user interaction, ` +
      `and published in the last ${PRIORITY.freshDays} days.`,
  },
];

export interface PriorityInput {
  inKev: boolean;
  ransomware: boolean;
  epss: number | null;
  /** EPSS `riseWindowDays` ago; null when there was no score then or no history. */
  epssPrior: number | null;
  severity: string | null;
  exposure: Exposure | null;
  /** ISO date or datetime. */
  published: string | null;
}

export interface PriorityResult {
  tier: PriorityTier | null;
  reasons: string[];
}

const DAY_MS = 86_400_000;

export function epssRise(input: Pick<PriorityInput, 'epss' | 'epssPrior'>): number | null {
  if (input.epss == null || input.epssPrior == null) return null;
  return input.epss - input.epssPrior;
}

export function priorityTier(input: PriorityInput, now: Date = new Date()): PriorityResult {
  const reasons: string[] = [];
  const rise = epssRise(input);

  if (input.inKev) {
    reasons.push('In CISA KEV');
    if (input.ransomware) reasons.push('Known ransomware use');
    return { tier: 1, reasons };
  }

  const high = input.epss != null && input.epss >= PRIORITY.epssHigh;
  const rising = rise != null && rise >= PRIORITY.epssRise;
  if (high || rising) {
    if (high) reasons.push(`EPSS ${input.epss!.toFixed(2)}`);
    if (rising) reasons.push(`EPSS up ${rise!.toFixed(2)} in ${PRIORITY.riseWindowDays} days`);
    return { tier: 2, reasons };
  }

  const serious = input.severity === 'CRITICAL' || input.severity === 'HIGH';
  const published = input.published ? Date.parse(input.published) : Number.NaN;
  const ageDays = Number.isNaN(published) ? null : Math.floor((now.getTime() - published) / DAY_MS);
  const fresh = ageDays != null && ageDays >= 0 && ageDays <= PRIORITY.freshDays;
  if (serious && input.exposure === 'remote-unauth' && fresh) {
    const severity = input.severity!.charAt(0) + input.severity!.slice(1).toLowerCase();
    reasons.push('Remote, no auth', `${severity}, ${ageDays} days old`);
    return { tier: 3, reasons };
  }

  return { tier: null, reasons };
}

/** Sort order within the priority list: tier, then ransomware (tier 1), then EPSS. */
export function comparePriority(
  a: PriorityResult & Pick<PriorityInput, 'ransomware' | 'epss'>,
  b: PriorityResult & Pick<PriorityInput, 'ransomware' | 'epss'>,
): number {
  const tierA = a.tier ?? 4;
  const tierB = b.tier ?? 4;
  if (tierA !== tierB) return tierA - tierB;
  if (tierA === 1 && a.ransomware !== b.ransomware) return a.ransomware ? -1 : 1;
  return (b.epss ?? -1) - (a.epss ?? -1);
}
