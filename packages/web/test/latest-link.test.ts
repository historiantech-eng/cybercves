import { describe, expect, it } from 'vitest';
import { latestLinkState } from '../src/lib/latest-link';

describe('latestLinkState', () => {
  it('links when the live CVE is the one this build rendered', () => {
    expect(latestLinkState('CVE-2026-20348', 'CVE-2026-20348', 'CVE-2026-20340')).toEqual({
      kind: 'link',
      id: 'CVE-2026-20348',
      href: '/cve/CVE-2026-20348',
    });
  });

  it('does NOT link a CVE this build has no page for', () => {
    // The whole point: the odometer polls KV every 2 minutes and the site
    // rebuilds every 3 hours, so /cve/<unbuilt-id> falls through to the JSON
    // API. A reader clicking "last:" would land on raw JSON.
    expect(latestLinkState('CVE-2026-20349', 'CVE-2026-20348', 'CVE-2026-20348')).toEqual({
      kind: 'text',
      id: 'CVE-2026-20349',
    });
  });

  it('leaves the DOM alone when the shown id already matches', () => {
    expect(latestLinkState('CVE-2026-20348', 'CVE-2026-20348', 'CVE-2026-20348')).toEqual({
      kind: 'unchanged',
    });
  });

  it('tolerates the whitespace the server markup puts around the id', () => {
    expect(latestLinkState('CVE-2026-20348', 'CVE-2026-20348', '\n  CVE-2026-20348 ')).toEqual({
      kind: 'unchanged',
    });
  });

  it('never blanks the line when the poll returns no latest CVE', () => {
    // A failed or empty poll must leave the prerendered value on screen, the
    // same rule the hero number follows.
    for (const empty of [null, undefined, '']) {
      expect(latestLinkState(empty, 'CVE-2026-20348', 'CVE-2026-20348')).toEqual({
        kind: 'unchanged',
      });
    }
  });

  it('still updates when the build rendered no CVE at all', () => {
    expect(latestLinkState('CVE-2026-20349', null, '')).toEqual({
      kind: 'text',
      id: 'CVE-2026-20349',
    });
  });
});
