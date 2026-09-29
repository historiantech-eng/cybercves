/**
 * /check: evaluate one version against one product's prebuilt CVE data.
 *
 * Pure, so it is tested directly (test/check.test.ts) and runs unchanged in the
 * browser. All version semantics live in @cybercves/core/versions; this file
 * only groups and orders the answers.
 */
import {
  branchOf,
  cveStatus,
  formatVersion,
  parseVersion,
  upgradeTarget,
  type AffectedEntryInput,
  type UpgradeTarget,
  type VersionScheme,
} from '@cybercves/core';

/** One CVE in /data/versions/<product>.json. Short keys match lib/cve-rows. */
export interface CheckCve {
  i: string;
  t: string | null;
  d: string | null;
  s: string | null;
  c: number | null;
  /** 1 when remote, no auth, no user interaction. */
  x: 0 | 1;
  k: number;
  /** Known ransomware use (KEV). */
  r: number;
  e: number | null;
  /** The vendor's fix text. */
  fix: string | null;
  /** Vendor advisory URL, when one of the record's references is on their PSIRT host. */
  adv: string | null;
  /** Whose ranges `entries` are: the vendor's, CISA-ADP's, or nobody's. */
  src: 'cna' | 'adp' | 'none';
  entries: AffectedEntryInput[];
}

export interface CheckData {
  product: string;
  name: string;
  scheme: VersionScheme;
  generatedAt: string;
  cves: CheckCve[];
}

export interface CheckResult {
  version: string;
  branch: string;
  affected: CheckCve[];
  unknown: Array<CheckCve & { reason: string }>;
  notAffected: number;
  /** Lowest release on the reader's branch clearing every affected CVE. */
  targetAll: UpgradeTarget | null;
  /** Same, for known-exploited CVEs only — the ones to act on today. */
  targetKev: UpgradeTarget | null;
}

export type CheckError = { error: 'unreadable' | 'incomplete' };

const byUrgency = (a: CheckCve, b: CheckCve) =>
  b.k - a.k || b.r - a.r || (b.e ?? -1) - (a.e ?? -1) || (b.c ?? -1) - (a.c ?? -1);

export function evaluate(data: CheckData, raw: string): CheckResult | CheckError {
  const version = parseVersion(raw, data.scheme);
  if (!version) return { error: 'unreadable' };
  // "7.2" is a branch, not a version: every answer would depend on which 7.2.x.
  if (version.depth < 3) return { error: 'incomplete' };

  const affected: CheckCve[] = [];
  const unknown: Array<CheckCve & { reason: string }> = [];
  let notAffected = 0;

  for (const cve of data.cves) {
    const verdict = cveStatus(cve.entries, version, data.scheme);
    if (verdict.status === 'affected') affected.push(cve);
    else if (verdict.status === 'unknown') {
      unknown.push({ ...cve, reason: verdict.reason ?? 'the vendor data does not say' });
    } else notAffected++;
  }

  affected.sort(byUrgency);
  unknown.sort(byUrgency);

  const target = (list: CheckCve[]) =>
    list.length
      ? upgradeTarget(
          list.map((c) => ({ id: c.i, entries: c.entries })),
          version,
          data.scheme,
        )
      : null;

  return {
    version: formatVersion(version),
    branch: branchOf(version),
    affected,
    unknown,
    notAffected,
    targetAll: target(affected),
    targetKev: target(affected.filter((c) => c.k === 1)),
  };
}
