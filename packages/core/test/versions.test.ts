import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  cveStatus,
  entryStatus,
  formatVersion,
  listedCveStatus,
  normalizeListedVersion,
  parseVersion,
  upgradeTarget,
  type AffectedEntryInput,
  type VersionScheme,
} from '../src/versions.js';

/**
 * Real affected[] entries, exactly as stored, for known-exploited and edge-case
 * CVEs. Each expectation below was checked against the vendor's advisory; where
 * the CVE record and the advisory disagree, the test pins what the RECORD says
 * and the comment names the difference.
 */
const FIXTURE = JSON.parse(
  readFileSync(new URL('./fixtures/affected-versions.json', import.meta.url), 'utf8'),
) as Record<string, Array<AffectedEntryInput & { source: 'cna' | 'adp' }>>;

const cna = (id: string) => FIXTURE[id]!.filter((e) => e.source === 'cna');
const adp = (id: string) => FIXTURE[id]!.filter((e) => e.source === 'adp');

function status(id: string, version: string, scheme: VersionScheme, entries = cna(id)) {
  const v = parseVersion(version, scheme);
  if (!v) throw new Error(`test version ${version} did not parse`);
  return cveStatus(entries, v, scheme).status;
}

describe('parseVersion', () => {
  it('reads what readers paste', () => {
    expect(parseVersion('v7.2.8 build1639 (GA.M)', 'fortinet')).toMatchObject({ major: 7, minor: 2, patch: 8 });
    expect(parseVersion('FortiOS 7.4.3', 'fortinet')).toMatchObject({ major: 7, minor: 4, patch: 3 });
    expect(parseVersion('PAN-OS 10.2.9-h1', 'panos')).toMatchObject({ patch: 9, hotfix: 1 });
    expect(parseVersion('6.3.3-h9 (6.3.3-999)', 'panos')).toMatchObject({ patch: 3, hotfix: 9 });
  });

  it('records how much was written, so a bare branch is not mistaken for x.y.0', () => {
    expect(parseVersion('10.2', 'panos')?.depth).toBe(2);
    expect(parseVersion('10.2.0', 'panos')?.depth).toBe(3);
  });

  it('refuses what it cannot order rather than guessing', () => {
    expect(parseVersion('6.2.6-c857', 'panos')).toBeNull(); // GlobalProtect build suffix
    expect(parseVersion('7.2.8-h1', 'fortinet')).toBeNull(); // Fortinet has no hotfixes
    expect(parseVersion('10.2.9 on PAN-OS', 'panos')).toBeNull();
    expect(parseVersion('latest', 'fortinet')).toBeNull();
    expect(parseVersion('', 'panos')).toBeNull();
  });
});

describe('FortiOS', () => {
  it('CVE-2024-21762 (KEV, SSL-VPN): fixed in 7.4.3, 7.2.7, 7.0.14, 6.4.15, 6.2.16', () => {
    expect(status('CVE-2024-21762', '7.4.2', 'fortinet')).toBe('affected');
    expect(status('CVE-2024-21762', '7.4.3', 'fortinet')).toBe('not-affected');
    expect(status('CVE-2024-21762', '7.2.6', 'fortinet')).toBe('affected');
    expect(status('CVE-2024-21762', '7.2.7', 'fortinet')).toBe('not-affected');
    expect(status('CVE-2024-21762', '7.0.13', 'fortinet')).toBe('affected');
    expect(status('CVE-2024-21762', '6.2.16', 'fortinet')).toBe('not-affected');
    expect(status('CVE-2024-21762', '7.6.0', 'fortinet')).toBe('not-affected');
  });

  it('CVE-2024-21754: 7.2.8 is affected and 7.2.9 is not', () => {
    expect(status('CVE-2024-21754', '7.2.8', 'fortinet')).toBe('affected');
    expect(status('CVE-2024-21754', '7.2.9', 'fortinet')).toBe('not-affected');
  });

  it('shows why vendor entries must win: CISA-ADP alone cannot clear a fixed version', () => {
    // The ADP entries carry defaultStatus "unknown" and cover only the ranges
    // they list, so 6.2.16 — fixed per Fortinet — would read as undetermined,
    // and so would every 7.6 release. /check therefore uses CNA entries first.
    expect(status('CVE-2024-21762', '6.2.16', 'fortinet', adp('CVE-2024-21762'))).toBe('unknown');
    expect(status('CVE-2024-21762', '7.2.6', 'fortinet', adp('CVE-2024-21762'))).toBe('affected');
  });
});

describe('FortiManager and FortiWeb', () => {
  it('CVE-2024-47575 (KEV, FortiJump): a single listed 7.6.0 plus per-branch ranges', () => {
    expect(status('CVE-2024-47575', '7.6.0', 'fortinet')).toBe('affected');
    expect(status('CVE-2024-47575', '7.6.1', 'fortinet')).toBe('not-affected');
    expect(status('CVE-2024-47575', '7.4.4', 'fortinet')).toBe('affected');
    expect(status('CVE-2024-47575', '7.4.5', 'fortinet')).toBe('not-affected');
    expect(status('CVE-2024-47575', '7.2.8', 'fortinet')).toBe('not-affected');
  });

  it('CVE-2024-23107: FortiWeb 7.4.0 exactly, not 7.4.1', () => {
    expect(status('CVE-2024-23107', '7.4.0', 'fortinet')).toBe('affected');
    expect(status('CVE-2024-23107', '7.4.1', 'fortinet')).toBe('not-affected');
    expect(status('CVE-2024-23107', '7.2.4', 'fortinet')).toBe('affected');
    expect(status('CVE-2024-23107', '7.2.5', 'fortinet')).toBe('not-affected');
  });
});

describe('PAN-OS', () => {
  it('CVE-2024-3400 (KEV, GlobalProtect): hotfix boundaries', () => {
    expect(status('CVE-2024-3400', '10.2.9', 'panos')).toBe('affected');
    expect(status('CVE-2024-3400', '10.2.9-h1', 'panos')).toBe('not-affected');
    expect(status('CVE-2024-3400', '11.1.2-h2', 'panos')).toBe('affected');
    expect(status('CVE-2024-3400', '11.1.2-h3', 'panos')).toBe('not-affected');
    expect(status('CVE-2024-3400', '10.1.11', 'panos')).toBe('not-affected');
    // Palo Alto's advisory later added fixes such as 10.2.7-h8 that the CVE
    // record does not list. The record is what we read, so this errs toward
    // "affected" — the safe direction — and the page links the advisory.
    expect(status('CVE-2024-3400', '10.2.7-h8', 'panos')).toBe('affected');
  });

  it('CVE-2024-0012 (KEV, management auth bypass)', () => {
    expect(status('CVE-2024-0012', '11.2.4', 'panos')).toBe('affected');
    expect(status('CVE-2024-0012', '11.2.4-h1', 'panos')).toBe('not-affected');
    expect(status('CVE-2024-0012', '10.2.12-h1', 'panos')).toBe('affected');
    expect(status('CVE-2024-0012', '10.1.14', 'panos')).toBe('not-affected');
  });

  it('CVE-2026-0227: one fix per maintenance line in a single lessThan', () => {
    const s = (v: string) => status('CVE-2026-0227', v, 'panos');
    expect(s('11.1.6-h22')).toBe('affected');
    expect(s('11.1.6-h23')).toBe('not-affected');
    expect(s('11.1.7')).toBe('affected'); // no fix of its own on 11.1.7
    expect(s('11.1.10-h9')).toBe('not-affected');
    expect(s('11.1.13')).toBe('not-affected');
    expect(s('11.1.4-h26')).toBe('affected');
    // Past the last fix on a listed branch is fixed, even though this record's
    // defaultStatus is "affected" — the vendor named the fix for this branch.
    expect(s('11.1.14')).toBe('not-affected');
    // A branch no range names falls to that "affected" baseline.
    expect(s('9.1.0')).toBe('affected');
  });

  it('CVE-2024-0007: one branch fixed in two separate items', () => {
    const s = (v: string) => status('CVE-2024-0007', v, 'panos');
    expect(s('8.1.24')).toBe('affected');
    expect(s('8.1.24-h1')).toBe('not-affected');
    expect(s('8.1.25')).toBe('not-affected');
    expect(s('10.1.5')).toBe('affected');
    expect(s('10.1.6')).toBe('not-affected');
    expect(s('10.2.0')).toBe('not-affected'); // "10.2" unaffected covers the branch
  });

  it('CVE-2024-9472: a range that starts at a hotfix is not carved up by an earlier fix', () => {
    const entry: AffectedEntryInput = {
      defaultStatus: 'unaffected',
      truncated: false,
      versions: [
        { version: '11.2.2', status: 'affected', lessThan: '11.2.2-h3', lessThanOrEqual: null, versionType: 'custom' },
        { version: '11.1.2-h9', status: 'affected', lessThan: '11.1.2-h14', lessThanOrEqual: null, versionType: 'custom' },
        { version: '11.1.0', status: 'affected', lessThan: '11.1.2-h3', lessThanOrEqual: null, versionType: 'custom' },
      ],
    };
    const s = (v: string) => entryStatus(entry, parseVersion(v, 'panos')!, 'panos').status;
    expect(s('11.1.2-h10')).toBe('affected');
    expect(s('11.1.2-h14')).toBe('not-affected');
    expect(s('11.1.2-h5')).toBe('not-affected');
    expect(s('11.1.2-h2')).toBe('affected');
  });
});

describe('never "not affected" without evidence', () => {
  const v = parseVersion('7.2.9', 'fortinet')!;

  it('treats a truncated range list as unknown', () => {
    const entry = { ...cna('CVE-2024-21754')[0]!, truncated: true };
    expect(entryStatus(entry, v, 'fortinet').status).toBe('unknown');
  });

  it('treats an unreadable affected range as unknown', () => {
    const entry: AffectedEntryInput = {
      defaultStatus: 'unaffected',
      truncated: false,
      versions: [{ version: '7.2.0', status: 'affected', lessThan: 'next release', lessThanOrEqual: null, versionType: null }],
    };
    expect(entryStatus(entry, v, 'fortinet').status).toBe('unknown');
  });

  it('treats a record with no versions and no baseline as unknown', () => {
    expect(entryStatus({ versions: [], defaultStatus: null, truncated: false }, v, 'fortinet').status).toBe('unknown');
    expect(cveStatus([], v, 'fortinet').status).toBe('unknown');
  });

  it('lets any affected entry outrank an unaffected one', () => {
    const clear: AffectedEntryInput = { versions: [], defaultStatus: 'unaffected', truncated: false };
    const hit: AffectedEntryInput = { versions: [], defaultStatus: 'affected', truncated: false };
    expect(cveStatus([clear, hit], v, 'fortinet').status).toBe('affected');
  });
});

describe('upgradeTarget', () => {
  it('finds the lowest FortiOS 7.2 release that clears two CVEs', () => {
    const result = upgradeTarget(
      [
        { id: 'CVE-2024-21762', entries: cna('CVE-2024-21762') },
        { id: 'CVE-2024-21754', entries: cna('CVE-2024-21754') },
      ],
      parseVersion('7.2.5', 'fortinet')!,
      'fortinet',
    );
    // 7.2.7 fixes 21762 but 21754 runs to 7.2.8, so the answer is "after 7.2.8".
    expect(formatVersion(result.target!)).toBe('7.2.9');
    expect(result.after).toBe(true);
    expect(result.unfixed).toEqual([]);
  });

  it('picks the hotfix on the reader\'s own maintenance line for PAN-OS', () => {
    const result = upgradeTarget(
      [{ id: 'CVE-2026-0227', entries: cna('CVE-2026-0227') }],
      parseVersion('11.1.6', 'panos')!,
      'panos',
    );
    expect(formatVersion(result.target!)).toBe('11.1.6-h23');
    expect(result.after).toBe(false);
  });

  it('reports a CVE with no fix on the reader\'s branch instead of dropping it', () => {
    const result = upgradeTarget(
      [{ id: 'CVE-2026-0227', entries: cna('CVE-2026-0227') }],
      parseVersion('9.1.0', 'panos')!,
      'panos',
    );
    expect(result.target).toBeNull();
    expect(result.unfixed).toEqual(['CVE-2026-0227']);
  });
});

describe('Cisco: listed releases', () => {
  it('normalizes the forms readers and records use', () => {
    expect(normalizeListedVersion('9.18(4)24', 'cisco-dotted')).toBe('9.18.4.24');
    expect(normalizeListedVersion('9.18(4)', 'cisco-dotted')).toBe('9.18.4');
    expect(normalizeListedVersion('Cisco Adaptive Security Appliance Software Version 9.16(4)48', 'cisco-dotted')).toBe('9.16.4.48');
    expect(normalizeListedVersion('7.2.5.1 (Build 29)', 'cisco-dotted')).toBe('7.2.5.1');
    expect(normalizeListedVersion('7.2.5-208', 'cisco-dotted')).toBe('7.2.5');
    expect(normalizeListedVersion('9.18', 'cisco-dotted')).toBeNull(); // a train, not a release
    expect(normalizeListedVersion('N/A', 'cisco-dotted')).toBeNull();

    // ISE: two record spellings and the device's, all one release.
    expect(normalizeListedVersion('2.7.0 p1', 'cisco-ise')).toBe('2.7.0 p1');
    expect(normalizeListedVersion('3.3 Patch 2', 'cisco-ise')).toBe('3.3.0 p2');
    expect(normalizeListedVersion('3.2.0.542 patch 4', 'cisco-ise')).toBe('3.2.0 p4');
    expect(normalizeListedVersion('3.2', 'cisco-ise')).toBe('3.2.0');
    expect(normalizeListedVersion('latest', 'cisco-ise')).toBeNull();
  });

  const asa = FIXTURE['CVE-2024-20353']!;
  const ftd = FIXTURE['CVE-2024-20353-ftd']!;
  const s = (entries: AffectedEntryInput[], raw: string) =>
    listedCveStatus(entries, normalizeListedVersion(raw, 'cisco-dotted')!, 'cisco-dotted').status;

  it('CVE-2024-20353 (KEV, ArcaneDoor): listed ASA releases are affected', () => {
    expect(s(asa, '9.18(4)8')).toBe('affected');
    expect(s(asa, '9.18.4')).toBe('affected');
    expect(s(asa, '9.20.2')).toBe('affected');
    expect(s(ftd, '7.4.1')).toBe('affected');
  });

  it('reports a release Cisco did not list as not listed, never as safe', () => {
    // 9.18.4.22 is Cisco's first fixed 9.18 release. The record simply does not
    // list it; it never says it is unaffected.
    expect(s(asa, '9.18.4.22')).toBe('not-listed');
    expect(s(ftd, '7.4.1.1')).toBe('not-listed');
  });

  it('refuses to conclude anything from a list that was cut off', () => {
    const cut = [{ ...asa[0]!, versions: asa[0]!.versions.slice(0, 50), truncated: true }];
    expect(s(cut, '9.20.2')).toBe('unknown');
  });

  it('honours an explicit unaffected baseline when a vendor states one', () => {
    const entry: AffectedEntryInput = {
      defaultStatus: 'unaffected',
      truncated: false,
      versions: [{ version: '3.2.0 p3', status: 'affected', lessThan: null, lessThanOrEqual: null, versionType: null }],
    };
    const ise = (raw: string) =>
      listedCveStatus([entry], normalizeListedVersion(raw, 'cisco-ise')!, 'cisco-ise').status;
    expect(ise('3.2 Patch 3')).toBe('affected');
    expect(ise('3.2 Patch 4')).toBe('not-affected');
  });
});
