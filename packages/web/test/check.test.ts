import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { AffectedEntryInput } from '@cybercves/core';
import { evaluate, type CheckCve, type CheckData } from '../src/lib/check';

const FIXTURE = JSON.parse(
  readFileSync(new URL('../../core/test/fixtures/affected-versions.json', import.meta.url), 'utf8'),
) as Record<string, Array<AffectedEntryInput & { source: string }>>;

function cve(id: string, extra: Partial<CheckCve> = {}): CheckCve {
  return {
    i: id,
    t: null,
    d: null,
    s: 'CRITICAL',
    c: 9.8,
    x: 1,
    k: 0,
    r: 0,
    e: 0.1,
    fix: null,
    adv: null,
    src: 'cna',
    entries: (FIXTURE[id] ?? []).filter((e) => e.source === 'cna'),
    ...extra,
  };
}

const fortios: CheckData = {
  product: 'fortinet-fortios',
  name: 'Fortinet FortiOS',
  scheme: 'fortinet',
  generatedAt: '2026-09-29T00:00:00Z',
  cves: [
    cve('CVE-2024-21754', { s: 'LOW', e: 0.01 }),
    cve('CVE-2024-21762', { k: 1, e: 0.9 }),
    cve('CVE-2099-0001', { src: 'none', entries: [] }),
  ],
};

describe('evaluate', () => {
  it('groups by verdict, puts KEV first, and never counts unknown as safe', () => {
    const result = evaluate(fortios, '7.2.5');
    if ('error' in result) throw new Error(result.error);
    expect(result.affected.map((c) => c.i)).toEqual(['CVE-2024-21762', 'CVE-2024-21754']);
    expect(result.unknown.map((c) => c.i)).toEqual(['CVE-2099-0001']);
    expect(result.notAffected).toBe(0);
    expect(result.branch).toBe('7.2');
  });

  it('gives separate targets for KEV-only and for everything', () => {
    const result = evaluate(fortios, 'v7.2.5 build1517');
    if ('error' in result) throw new Error(result.error);
    // 21762 (KEV) is fixed after 7.2.6; 21754 needs the release after 7.2.8.
    expect(result.targetKev?.target).toMatchObject({ major: 7, minor: 2, patch: 7 });
    expect(result.targetAll?.target).toMatchObject({ major: 7, minor: 2, patch: 9 });
  });

  it('clears a fixed version', () => {
    const result = evaluate(fortios, '7.2.9');
    if ('error' in result) throw new Error(result.error);
    expect(result.affected).toEqual([]);
    expect(result.notAffected).toBe(2);
    expect(result.targetAll).toBeNull();
  });

  it('refuses a branch or an unreadable string rather than guessing', () => {
    expect(evaluate(fortios, '7.2')).toEqual({ error: 'incomplete' });
    expect(evaluate(fortios, 'latest')).toEqual({ error: 'unreadable' });
  });
});
