import { describe, expect, it } from 'vitest';
import { epssDayBefore, epssUrlForDate } from '../src/sources/epss.js';

describe('EPSS archive dates', () => {
  it('counts back in UTC days across month and year boundaries', () => {
    expect(epssDayBefore('2026-09-29', 7)).toBe('2026-09-22');
    expect(epssDayBefore('2026-03-05', 30)).toBe('2026-02-03');
    expect(epssDayBefore('2026-01-03T12:04:59Z', 7)).toBe('2025-12-27');
  });

  it('builds the archive URL and refuses anything that is not a date', () => {
    expect(epssUrlForDate('2026-09-01')).toBe(
      'https://epss.empiricalsecurity.com/epss_scores-2026-09-01.csv.gz',
    );
    expect(() => epssUrlForDate('../etc')).toThrow();
  });
});
