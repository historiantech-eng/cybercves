import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { affectedStatus, isAffectedEntry, resolvableEntries } from '../src/affected.js';
import type { CveRecord } from '../src/cve-schema.js';
import { normalizeCve } from '../src/normalize.js';
import type { NormalizedAffected } from '../src/types.js';

/**
 * Membership in a CVE record's `affected[]` array is not a claim of
 * vulnerability. Palo Alto publishes their whole product matrix on every
 * advisory and marks most of it `unaffected`, so reading the array as a list of
 * victims credited Cloud NGFW with 82 bugs and Prisma Access with 70 that their
 * own advisories say they do not have.
 */

function entry(over: Partial<NormalizedAffected> = {}): NormalizedAffected {
  return {
    vendorRaw: 'Palo Alto Networks',
    productRaw: 'Some Product',
    cpes: [],
    versions: [],
    versionsTruncated: false,
    versionCount: 0,
    defaultStatus: null,
    ...over,
  };
}

const version = (status: string | null) => ({
  version: 'All',
  status,
  lessThan: null,
  lessThanOrEqual: null,
  versionType: 'custom',
});

describe('affectedStatus', () => {
  it('reads the shape Palo Alto uses to say "not affected"', () => {
    expect(
      affectedStatus(entry({ defaultStatus: 'unaffected', versions: [version('unaffected')] })),
    ).toBe('unaffected');
  });

  it('treats one affected range as overriding an unaffected baseline', () => {
    // This is the normal PAN-OS shape: baseline unaffected, exceptions listed.
    expect(
      affectedStatus(
        entry({ defaultStatus: 'unaffected', versions: [version('affected'), version('unaffected')] }),
      ),
    ).toBe('affected');
  });

  it('returns unknown when the record simply does not say', () => {
    expect(affectedStatus(entry({ defaultStatus: null, versions: [] }))).toBe('unknown');
    expect(affectedStatus(entry({ defaultStatus: 'unknown', versions: [version(null)] }))).toBe(
      'unknown',
    );
  });

  it('counts unknown as affected, because most CNAs never fill these fields in', () => {
    // The asymmetry is the point: absence of a statement is not a statement of
    // absence. Requiring proof of affectedness would delete most of the dataset.
    expect(isAffectedEntry(entry({ defaultStatus: 'unknown' }))).toBe(true);
    expect(isAffectedEntry(entry({ defaultStatus: null }))).toBe(true);
  });

  it('refuses to conclude "unaffected" from a truncated version list', () => {
    // We store only the first MAX_VERSION_RANGES ranges, so the affected
    // exception may be one we never kept. Dropping a real vulnerability is far
    // worse than keeping a spurious product.
    expect(
      affectedStatus(
        entry({
          defaultStatus: 'unaffected',
          versions: [version('unaffected')],
          versionsTruncated: true,
        }),
      ),
    ).toBe('unknown');
  });

  it('is case- and whitespace-insensitive, as upstream data is not clean', () => {
    expect(
      affectedStatus(entry({ defaultStatus: ' UNAFFECTED ', versions: [version('Unaffected')] })),
    ).toBe('unaffected');
  });
});

describe('resolvableEntries', () => {
  const cloudNgfw = entry({
    productRaw: 'Cloud NGFW',
    defaultStatus: 'unaffected',
    versions: [version('unaffected')],
  });
  const panOs = entry({
    productRaw: 'PAN-OS',
    defaultStatus: 'unaffected',
    versions: [version('affected')],
  });

  it('drops the unaffected products when a sibling entry is affected', () => {
    const kept = resolvableEntries([cloudNgfw, panOs]);
    expect(kept.map((e) => e.productRaw)).toEqual(['PAN-OS']);
  });

  it('keeps everything when no entry is affected, because the record contradicts itself', () => {
    // A CVE affecting nothing is impossible; it means the vendor mis-stated the
    // record (CVE-2025-4235 inverted a status field, CVE-2026-20188 listed only
    // a product it then marked unaffected). Believing it literally would strike
    // a real vulnerability off the only product it is attached to.
    const kept = resolvableEntries([cloudNgfw]);
    expect(kept.map((e) => e.productRaw)).toEqual(['Cloud NGFW']);
  });

  it('passes an all-affected list through untouched', () => {
    expect(resolvableEntries([panOs])).toEqual([panOs]);
  });
});

describe('CVE-2026-0281 (the reported miscategorization)', () => {
  const cve = normalizeCve(
    JSON.parse(
      readFileSync(
        fileURLToPath(new URL('./fixtures/CVE-2026-0281.json', import.meta.url)),
        'utf8',
      ),
    ) as CveRecord,
  );

  it('lists the full Palo Alto product matrix upstream, only PAN-OS affected', () => {
    expect(cve.affected.map((e) => e.productRaw).sort()).toEqual([
      'Cloud NGFW',
      'PAN-OS',
      'Prisma Access',
      // Siemens ship this appliance running PAN-OS and file their own ADP
      // container against the same CVE. Status `affected`, so it stays.
      'RUGGEDCOM APE1808',
    ]);
  });

  it('drops Cloud NGFW and Prisma Access, which the advisory says are safe', () => {
    expect(resolvableEntries(cve.affected).map((e) => e.productRaw)).toEqual([
      'PAN-OS',
      'RUGGEDCOM APE1808',
    ]);
  });
});
