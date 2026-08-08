import { describe, expect, it } from 'vitest';
import { looksTruncated } from '../src/index.js';

/**
 * The hero counter reads from KV, and KV is written by a cron that can fire
 * while `push:d1` has D1 truncated. These cases are the difference between
 * "the most prominent number on the site reads 0 for fifteen minutes" and
 * "nobody noticed a deploy happened".
 */
describe('looksTruncated', () => {
  const prev = { year: 2026, total: 404, rollup: [{}, {}, {}] };

  it('rejects a snapshot taken mid-reload', () => {
    expect(looksTruncated(prev, { year: 2026, total: 0, rollup: [] })).toBe(true);
    expect(looksTruncated(prev, { year: 2026, total: 12, rollup: [{}] })).toBe(true);
  });

  it('rejects a plausible total that lost every vendor', () => {
    // Table order means `cve` can be loaded while `cve_product` is not, which
    // reads as a healthy count with nothing attributed to anyone.
    expect(looksTruncated(prev, { year: 2026, total: 404, rollup: [] })).toBe(true);
  });

  it('accepts ordinary movement, including a small withdrawal', () => {
    expect(looksTruncated(prev, { year: 2026, total: 405, rollup: [{}] })).toBe(false);
    expect(looksTruncated(prev, { year: 2026, total: 402, rollup: [{}] })).toBe(false);
  });

  it('accepts the new-year reset', () => {
    // THE case this must not break. On 1 January the counter legitimately falls
    // to near zero and the rollup legitimately empties — that reset is the
    // feature. Comparing across the rollover would freeze the counter at last
    // year's number on the one day it is supposed to move most.
    expect(looksTruncated(prev, { year: 2027, total: 0, rollup: [] })).toBe(false);
    expect(looksTruncated(prev, { year: 2027, total: 3, rollup: [{}] })).toBe(false);
  });

  it('accepts anything when there is no previous snapshot to compare', () => {
    // First deploy, or KV was cleared. Refusing here would mean the counter
    // never populates at all.
    expect(looksTruncated(null, { year: 2026, total: 0, rollup: [] })).toBe(false);
    expect(looksTruncated({ year: 2026, total: 0 }, { year: 2026, total: 0 })).toBe(false);
  });
});
