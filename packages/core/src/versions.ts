import type { NormalizedVersionRange } from './types.js';

/**
 * "Is my version affected?" — evaluated against the vendor's own affected[] data.
 *
 * The one rule everything here serves: NEVER answer "not affected" without
 * evidence that covers the reader's version. A wrong "affected" costs someone an
 * unnecessary upgrade; a wrong "not affected" leaves a box exposed while its
 * owner believes it is safe. So every input this code cannot read — a version
 * string it does not understand, a range list we truncated, a status of
 * "unknown" — resolves to `unknown`, and `unknown` is shown as "could not
 * determine", never folded into the safe count.
 *
 * Shapes handled, all observed in the stored data (see the tests for each):
 *
 *   Fortinet  { version: "7.2.0", lessThanOrEqual: "7.2.8" }       range, inclusive end
 *             { version: "7.4.0" }                                 one listed version
 *   Palo Alto { version: "10.1", lessThan: "10.1.6-h1" }            branch start, hotfix end
 *             { version: "11.1.0",
 *               lessThan: "11.1.13, 11.1.10-h9, 11.1.6-h23" }      one fix per maintenance line
 *             { version: "11.0", status: "unaffected" }            whole branch
 *   Both      defaultStatus: "unaffected"                          baseline when nothing matches
 */

export type VersionScheme = 'fortinet' | 'panos';

/**
 * Products /check covers, and how to read their version strings.
 *
 * Deliberately short. A product joins only once its published version data has
 * been read end to end and the scheme below parses all of it. GlobalProtect is
 * absent on purpose: its ranges use build suffixes (`6.2.6-c857`, `6.3.2-566`)
 * whose ordering against hotfixes is not published, and guessing it is how this
 * page would produce a confident wrong answer. Cisco is absent because 1,093 of
 * its 3,207 stored range lists are truncated at MAX_VERSION_RANGES.
 */
export const VERSION_SCHEMES: Readonly<Record<string, VersionScheme>> = {
  'fortinet-fortios': 'fortinet',
  'fortinet-fortiproxy': 'fortinet',
  'fortinet-fortimanager': 'fortinet',
  'fortinet-fortianalyzer': 'fortinet',
  'fortinet-fortiweb': 'fortinet',
  'palo-alto-pan-os': 'panos',
};

export const VERSION_EXAMPLES: Readonly<Record<VersionScheme, string>> = {
  fortinet: '7.2.8',
  panos: '10.2.9-h1',
};

export interface Version {
  major: number;
  minor: number;
  patch: number;
  /** PAN-OS `-hN`; 0 for a base release and for every Fortinet version. */
  hotfix: number;
  /** How many numeric components were written: `10.2` is 2, `10.2.0` is 3. */
  depth: 1 | 2 | 3;
}

const FORTINET = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[\s,]+build\s*\d+.*)?$/i;
const PANOS = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-h(\d+))?$/i;

/**
 * Parse one version string, or return null when it is not one we can order.
 *
 * Accepts what a reader is likely to paste: a leading `v`, and on Fortinet the
 * build suffix the GUI shows (`v7.2.8 build1639 (GA.M)`). A trailing parenthetical
 * is dropped — Palo Alto writes `6.3.3-h9 (6.3.3-999)`, the second form being
 * an alias. Anything else unrecognised is null, not a best guess.
 */
export function parseVersion(raw: string | null | undefined, scheme: VersionScheme): Version | null {
  if (raw == null) return null;
  let text = raw.trim().replace(/\s*\([^)]*\)\s*$/, '').trim();
  if (scheme === 'fortinet') text = text.replace(/^forti\w*\s+/i, '');
  if (scheme === 'panos') text = text.replace(/^pan-?os\s+/i, '');
  const match = (scheme === 'fortinet' ? FORTINET : PANOS).exec(text);
  if (!match) return null;
  const depth = (match[3] !== undefined ? 3 : match[2] !== undefined ? 2 : 1) as Version['depth'];
  return {
    major: Number(match[1]),
    minor: Number(match[2] ?? 0),
    patch: Number(match[3] ?? 0),
    hotfix: scheme === 'panos' && match[4] !== undefined ? Number(match[4]) : 0,
    depth,
  };
}

export function compareVersions(a: Version, b: Version): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch || a.hotfix - b.hotfix;
}

const sameRelease = (a: Version, b: Version) =>
  a.major === b.major && a.minor === b.minor && a.patch === b.patch;

const sameBranch = (a: Version, b: Version) => a.major === b.major && a.minor === b.minor;

export function formatVersion(v: Version): string {
  return `${v.major}.${v.minor}.${v.patch}${v.hotfix ? `-h${v.hotfix}` : ''}`;
}

export function branchOf(v: Version): string {
  return `${v.major}.${v.minor}`;
}

/**
 * Words vendors use for "every version". Not `0`: as a range start it parses to
 * 0.0.0, which already covers everything, and as a bare listed version it means
 * version 0 — reading it as "all" would widen an unaffected statement.
 */
const EVERYTHING = /^(all|\*|any)$/i;

type Point = { kind: 'all' } | { kind: 'version'; v: Version } | { kind: 'unreadable' };

function readPoint(raw: string | null, scheme: VersionScheme): Point {
  if (raw == null) return { kind: 'unreadable' };
  if (EVERYTHING.test(raw.trim())) return { kind: 'all' };
  const v = parseVersion(raw, scheme);
  return v ? { kind: 'version', v } : { kind: 'unreadable' };
}

/**
 * What one versions[] item says about `target`, or `null` when it cannot be read.
 *
 * - `covered` — inside the item's span.
 * - `fixed` — on the same branch as one of the item's fix boundaries and at or
 *   past it. This is evidence, not an absence of it: the vendor named the
 *   release that fixes this branch and the reader is beyond it. It matters on
 *   records whose `defaultStatus` is "affected" (CVE-2026-0227), where reading
 *   "outside every range" literally would call 11.1.13 affected even though the
 *   same record names 11.1.13 as the fix.
 * - `outside` — the item says nothing about this version.
 *
 * A range is `version <= target < lessThan` (or `<= lessThanOrEqual`). Palo
 * Alto's comma list in `lessThan` names one fix per maintenance release: the
 * range ends at the highest, and a release that has its own fix listed is
 * covered only below that fix's hotfix. So with `11.1.13, 11.1.6-h23`,
 * 11.1.6-h22 is affected, 11.1.6-h23 is not, 11.1.7 is (no fix of its own)
 * and 11.1.13 is not.
 *
 * Palo Alto also splits one branch's fixes across separate items —
 * CVE-2024-0007 has `8.1 < 8.1.24-h1` AND `8.1 < 8.1.25`, meaning 8.1.24-h1 is
 * fixed — so `siblingFixes` carries every fix named anywhere in the same entry.
 * A sibling fix only counts when it lies above this item's start: CVE-2024-9472
 * has `11.1.2-h9 < 11.1.2-h14`, a range that begins at a hotfix, and an earlier
 * fix on that release must not carve 11.1.2-h10 out of it.
 *
 * A single version with no range covers its whole branch when written as a
 * branch (`11.0`), and otherwise that release including its hotfixes — a
 * vendor listing `10.1.0` has said nothing about 10.1.0-h3 specifically, and
 * reading it as "not 10.1.0-h3" would narrow an affected statement.
 */
export type Coverage = 'covered' | 'fixed' | 'outside';

export function rangeCovers(
  item: NormalizedVersionRange,
  target: Version,
  scheme: VersionScheme,
  siblingFixes: readonly Version[] = [],
): Coverage | null {
  const start = readPoint(item.version, scheme);
  if (start.kind === 'unreadable') return null;

  if (item.lessThan != null || item.lessThanOrEqual != null) {
    if (start.kind === 'version' && compareVersions(target, start.v) < 0) return 'outside';

    if (item.lessThanOrEqual != null) {
      const end = readPoint(item.lessThanOrEqual, scheme);
      if (end.kind === 'unreadable') return null;
      if (end.kind === 'all' || compareVersions(target, end.v) <= 0) return 'covered';
      return sameBranch(target, end.v) ? 'fixed' : 'outside';
    }

    const parts = item.lessThan!.split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length === 1 && EVERYTHING.test(parts[0]!)) return 'covered';
    const fixes: Version[] = [];
    for (const part of parts) {
      const v = parseVersion(part, scheme);
      if (!v) return null;
      fixes.push(v);
    }
    if (!fixes.length) return null;
    const highest = fixes.reduce((a, b) => (compareVersions(a, b) >= 0 ? a : b));
    if (compareVersions(target, highest) >= 0) {
      return fixes.some((fix) => sameBranch(fix, target)) ? 'fixed' : 'outside';
    }
    // Below the last fix: covered unless this exact release has its own fix
    // listed — here or in a sibling item above this one's start — and the
    // reader is at or past it.
    const releaseFixes = [
      ...fixes,
      ...siblingFixes.filter((fix) => start.kind === 'all' || compareVersions(fix, start.v) > 0),
    ];
    return releaseFixes.some((fix) => sameRelease(fix, target) && target.hotfix >= fix.hotfix)
      ? 'fixed'
      : 'covered';
  }

  const hit =
    start.kind === 'all' ||
    (start.v.depth < 3
      ? start.v.major === target.major && (start.v.depth < 2 || start.v.minor === target.minor)
      : sameRelease(start.v, target) && (start.v.hotfix === 0 || start.v.hotfix === target.hotfix));
  return hit ? 'covered' : 'outside';
}

export type VersionStatus = 'affected' | 'not-affected' | 'unknown';

export interface AffectedEntryInput {
  versions: readonly NormalizedVersionRange[];
  defaultStatus: string | null;
  truncated: boolean;
}

export interface EntryVerdict {
  status: VersionStatus;
  /** Why the answer is `unknown`, in words a reader can act on. */
  reason?: string;
}

const statusOf = (s: string | null) => s?.trim().toLowerCase() ?? null;

/** Every readable `lessThan` fix named by the entry's affected items. */
function lessThanFixes(entry: AffectedEntryInput, scheme: VersionScheme): Version[] {
  const out: Version[] = [];
  for (const item of entry.versions) {
    if (statusOf(item.status) !== 'affected' || item.lessThan == null) continue;
    for (const part of item.lessThan.split(',')) {
      const v = parseVersion(part, scheme);
      if (v && v.depth === 3) out.push(v);
    }
  }
  return out;
}

/**
 * One affected[] entry's answer for one version.
 *
 * Order matters. A range that says `affected` and covers the version decides
 * it outright. Only when none does may the entry conclude anything else, and
 * then only if nothing unreadable could have been the affected range we missed.
 */
export function entryStatus(entry: AffectedEntryInput, target: Version, scheme: VersionScheme): EntryVerdict {
  let unreadable = false;
  let unaffectedMatch = false;
  let unknownMatch = false;
  let pastFix = false;
  const siblingFixes = lessThanFixes(entry, scheme);

  for (const item of entry.versions) {
    const status = statusOf(item.status);
    const covers = rangeCovers(item, target, scheme, siblingFixes);
    if (covers === null) {
      if (status !== 'unaffected') unreadable = true;
      continue;
    }
    if (covers === 'outside') continue;
    if (covers === 'fixed') {
      // Past a fix only speaks for affected items; an unaffected item's
      // boundary is not a fix.
      if (status === 'affected') pastFix = true;
      continue;
    }
    if (status === 'affected') return { status: 'affected' };
    if (status === 'unaffected') unaffectedMatch = true;
    else unknownMatch = true;
  }

  if (unreadable) {
    return { status: 'unknown', reason: 'the vendor wrote a version range this page cannot read' };
  }
  if (entry.truncated) {
    return { status: 'unknown', reason: 'the vendor listed more versions than are stored here' };
  }
  if (unknownMatch) return { status: 'unknown', reason: 'the vendor marks this version as unknown' };
  if (unaffectedMatch || pastFix) return { status: 'not-affected' };

  const baseline = statusOf(entry.defaultStatus);
  if (baseline === 'unaffected') return { status: 'not-affected' };
  if (baseline === 'affected') return { status: 'affected' };
  return { status: 'unknown', reason: 'the vendor does not say whether this version is affected' };
}

/**
 * Combine every entry a CVE has for one product.
 *
 * Any entry saying affected wins, then any unknown; "not affected" needs every
 * entry to agree. No entries at all is unknown — the CVE is attributed to this
 * product (perhaps from its description) but states no versions for it.
 */
export function cveStatus(
  entries: readonly AffectedEntryInput[],
  target: Version,
  scheme: VersionScheme,
): EntryVerdict {
  if (!entries.length) {
    return { status: 'unknown', reason: 'the vendor published no version data for this product' };
  }
  const verdicts = entries.map((entry) => entryStatus(entry, target, scheme));
  return (
    verdicts.find((v) => v.status === 'affected') ??
    verdicts.find((v) => v.status === 'unknown') ?? { status: 'not-affected' }
  );
}

/**
 * Every version these entries name as a boundary, as candidate upgrade targets.
 *
 * `lessThan X` contributes X itself: the vendor's fixed release.
 * `lessThanOrEqual X`, or a single listed affected version X, contributes the
 * release after X, flagged `after` because the vendor never named it and the
 * next release number is not guaranteed.
 */
export function fixPoints(
  entries: readonly AffectedEntryInput[],
  scheme: VersionScheme,
): Array<{ v: Version; after: boolean }> {
  const out: Array<{ v: Version; after: boolean }> = [];
  for (const entry of entries) {
    for (const item of entry.versions) {
      if (statusOf(item.status) !== 'affected') continue;
      if (item.lessThan != null) {
        for (const part of item.lessThan.split(',')) {
          const v = parseVersion(part, scheme);
          if (v && v.depth === 3) out.push({ v, after: false });
        }
      } else {
        // An inclusive end, or a single listed version (FortiWeb enumerates
        // them): the release after it is the first that might be fixed.
        const v = parseVersion(item.lessThanOrEqual ?? item.version, scheme);
        if (v && v.depth === 3) {
          out.push({ v: { ...v, patch: v.patch + 1, hotfix: 0 }, after: true });
        }
      }
    }
  }
  return out;
}

export interface UpgradeTarget {
  /** Lowest version on the reader's branch that none of the CVEs affect. */
  target: Version | null;
  /** True when the target is "the first release after X" rather than a named one. */
  after: boolean;
  /** CVEs with no fixed release on this branch, which the target cannot clear. */
  unfixed: string[];
}

/**
 * The lowest version on the reader's branch that clears every given CVE.
 *
 * Built only from the vendor's own boundaries, and every candidate is re-checked
 * against every CVE with `cveStatus` — so a target is never offered that the same
 * rules would call affected. CVEs with no boundary above the reader's version on
 * this branch are listed as unfixed here rather than silently dropped; the
 * honest advice for those is a newer branch.
 */
export function upgradeTarget(
  cves: ReadonlyArray<{ id: string; entries: readonly AffectedEntryInput[] }>,
  current: Version,
  scheme: VersionScheme,
): UpgradeTarget {
  const candidates = new Map<string, { v: Version; after: boolean }>();
  const unfixed: string[] = [];

  for (const cve of cves) {
    const points = fixPoints(cve.entries, scheme).filter(
      (p) => sameBranch(p.v, current) && compareVersions(p.v, current) > 0,
    );
    if (!points.length) unfixed.push(cve.id);
    for (const p of points) {
      const key = formatVersion(p.v);
      const existing = candidates.get(key);
      // A named release beats an inferred one at the same number.
      if (!existing || (existing.after && !p.after)) candidates.set(key, p);
    }
  }

  const fixable = cves.filter((c) => !unfixed.includes(c.id));
  const ordered = [...candidates.values()].sort((a, b) => compareVersions(a.v, b.v));
  for (const candidate of ordered) {
    const clears = fixable.every(
      (cve) => cveStatus(cve.entries, candidate.v, scheme).status === 'not-affected',
    );
    if (clears) return { target: candidate.v, after: candidate.after, unfixed };
  }
  // No single release on the branch clears every fixable CVE (their fixes sit on
  // different maintenance lines). Say so rather than offer a partial target.
  return { target: null, after: false, unfixed };
}
