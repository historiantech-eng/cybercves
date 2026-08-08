import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { classifyAcknowledgement, classifyPsirtDiscovered, selfFoundRate } from '@cybercves/core';
import {
  advisoryUrlFromRefs,
  classifyAdvisoryPage,
  parseAcknowledgement,
  parseDiscoveredField,
} from '../src/sources/psirt-fortinet.js';
import { mergeDiscoveryFile, readDiscoveryFile } from '../src/node/discovery-store.js';

const fixture = readFileSync(
  fileURLToPath(new URL('./fixtures/fortinet-FG-IR-25-254.html', import.meta.url)),
  'utf8',
);

describe('parseAcknowledgement', () => {
  it('extracts the acknowledgement from a real advisory page', () => {
    // Pinned to committed markup so a Fortinet layout change fails here rather
    // than silently degrading every Fortinet CVE to "undisclosed".
    const text = parseAcknowledgement(fixture);
    expect(text).toContain('Fortinet Product Security Team');
    expect(text).toContain('Théo Leleu');
    // Must stop at the section boundary, not run into the Timeline that follows.
    expect(text).not.toContain('Initial publication');
  });

  it('returns null when the page has no acknowledgement section', () => {
    expect(parseAcknowledgement('<div><h3>Summary</h3><p>Nothing here</p></div>')).toBeNull();
    expect(parseAcknowledgement('')).toBeNull();
  });

  it('decodes entities and collapses whitespace', () => {
    const html = '<h3>Acknowledgement</h3>\n  Reported by Alice &amp; Bob\n  of  Acme\n</div>';
    expect(parseAcknowledgement(html)).toBe('Reported by Alice & Bob of Acme');
  });
});

describe('parseDiscoveredField', () => {
  it('reads the labelled field out of the advisory sidebar', () => {
    // The strong signal: Fortinet's own value, not a rule applied to prose.
    // Pinned to committed markup for the same reason as the acknowledgement —
    // a silent parse failure here demotes every Fortinet CVE to a heuristic.
    expect(parseDiscoveredField(fixture)).toBe('Internal');
  });

  it('is not confused by neighbouring rows or missing markup', () => {
    expect(parseDiscoveredField('<tr><td>Component</td><td>OTHERS</td></tr>')).toBeNull();
    expect(parseDiscoveredField('')).toBeNull();
    expect(
      parseDiscoveredField('<tr><td>Discovered</td><td>Third-Party&nbsp;Library</td></tr>'),
    ).toBe('Third-Party Library');
  });
});

describe('classifyPsirtDiscovered', () => {
  it('maps the three values Fortinet publishes', () => {
    expect(classifyPsirtDiscovered('Internal').discovery).toBe('INTERNAL');
    expect(classifyPsirtDiscovered('External').discovery).toBe('EXTERNAL');
    // A flaw in a bundled upstream component reached Fortinet through someone
    // else's advisory — whatever else it is, it is not "our team found this".
    expect(classifyPsirtDiscovered('Third-Party Library').discovery).toBe('EXTERNAL');
  });

  it('marks the verdict as coming from a published field, not prose', () => {
    expect(classifyPsirtDiscovered('External').source).toBe('psirt-field');
  });

  it('refuses to guess at a value it has not been taught', () => {
    // A fourth label must be classified deliberately. Defaulting it to EXTERNAL
    // would publish a claim about a named company that nobody decided to make.
    expect(classifyPsirtDiscovered('Bug Bounty').discovery).toBeNull();
    expect(classifyPsirtDiscovered('').discovery).toBeNull();
    expect(classifyPsirtDiscovered(null).discovery).toBeNull();
  });
});

describe('classifyAdvisoryPage', () => {
  it('takes the verdict from the field and the credit text from the prose', () => {
    const r = classifyAdvisoryPage(fixture, 'Fortinet', ['FortiGuard']);
    expect(r.discovery).toBe('INTERNAL');
    expect(r.source).toBe('psirt-field');
    // "Internal" is not auditable; the names are. The reader gets both.
    expect(r.creditText).toContain('Théo Leleu');
  });

  it('falls back to the prose when the field is gone', () => {
    // A layout change that drops the field must degrade to the weaker signal
    // and *say so* in discovery_source, not silently keep claiming a field.
    const proseOnly = fixture.replace(/<td>\s*Discovered\s*<\/td>\s*<td>[^<]*<\/td>/i, '');
    const r = classifyAdvisoryPage(proseOnly, 'Fortinet', ['FortiGuard']);
    expect(r.discovery).toBe('INTERNAL');
    expect(r.source).toBe('psirt-acknowledgement');
  });

  it('trusts the field over the prose when they disagree', () => {
    // "Reported by X of Acme to Fortinet" reads EXTERNAL to the heuristic; if
    // Fortinet labelled it Internal, Fortinet is the authority on its own team.
    const conflicted = fixture.replace(
      'Discovered by Théo Leleu and David Maciejak of Fortinet Product Security Team based on threat activity.',
      'Reported by Jane Doe of Acme Security Labs to Fortinet PSIRT.',
    );
    const r = classifyAdvisoryPage(conflicted, 'Fortinet', ['FortiGuard']);
    expect(r.discovery).toBe('INTERNAL');
    expect(r.creditText).toContain('Acme Security Labs');
  });
});

describe('classifyAcknowledgement', () => {
  it('reads a vendor-attributed credit as internal', () => {
    const r = classifyAcknowledgement(
      'Discovered by Théo Leleu and David Maciejak of Fortinet Product Security Team based on threat activity.',
      'Fortinet',
    );
    expect(r.discovery).toBe('INTERNAL');
    expect(r.source).toBe('psirt-acknowledgement');
    // The raw text is retained so a reader can disagree with the classification.
    expect(r.creditText).toContain('Fortinet Product Security Team');
  });

  it('reads an outside finder as external', () => {
    const r = classifyAcknowledgement(
      'Reported by Jane Doe of Acme Security Labs to Fortinet PSIRT.',
      'Fortinet',
    );
    // Mentions the vendor only as the recipient, not as the finder's employer.
    expect(r.discovery).toBe('EXTERNAL');
  });

  it('recognises explicit internal phrasing without a team name', () => {
    expect(classifyAcknowledgement('This issue was internally discovered.', 'Fortinet').discovery).toBe(
      'INTERNAL',
    );
  });

  it('does not treat the vendor as the finder when it is only the recipient', () => {
    // The failure mode that would inflate a vendor's self-found rate.
    for (const text of [
      'Reported by Jane Doe of Acme Security Labs to Fortinet PSIRT.',
      'Discovered by an external researcher and reported to Fortinet Product Security Team.',
      'Found by Acme Research, disclosed to Fortinet.',
    ]) {
      expect(classifyAcknowledgement(text, 'Fortinet', ['FortiGuard']).discovery, text).toBe('EXTERNAL');
    }
  });

  it('recognises the vendor brand family as internal', () => {
    for (const text of [
      'Discovered by A. Researcher of FortiGuard Labs.',
      'Reported by the Fortinet Product Security Team.',
      'Discovered by J. Smith of Fortinet.',
    ]) {
      expect(classifyAcknowledgement(text, 'Fortinet', ['FortiGuard']).discovery, text).toBe('INTERNAL');
    }
  });

  it('returns null rather than guessing on unrecognised text', () => {
    expect(classifyAcknowledgement('Thanks to everyone involved.', 'Fortinet').discovery).toBeNull();
    expect(classifyAcknowledgement(null, 'Fortinet').discovery).toBeNull();
    expect(classifyAcknowledgement('   ', 'Fortinet').discovery).toBeNull();
  });
});

describe('advisoryUrlFromRefs', () => {
  it('finds the PSIRT advisory among a CVE reference list', () => {
    const refs = JSON.stringify([
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-32756' },
      { url: 'https://fortiguard.fortinet.com/psirt/FG-IR-25-254' },
    ]);
    expect(advisoryUrlFromRefs(refs)).toBe('https://www.fortiguard.com/psirt/FG-IR-25-254');
  });

  it('canonicalises every host spelling onto one URL', () => {
    // Otherwise the same advisory is fetched up to three times, on a pass that
    // costs twenty seconds a request.
    for (const host of ['fortiguard.com', 'www.fortiguard.com', 'fortiguard.fortinet.com']) {
      expect(advisoryUrlFromRefs(JSON.stringify([{ url: `https://${host}/psirt/fg-ir-25-254` }]))).toBe(
        'https://www.fortiguard.com/psirt/FG-IR-25-254',
      );
    }
  });

  it('returns null when no advisory is referenced, and survives bad JSON', () => {
    expect(advisoryUrlFromRefs('[{"url":"https://example.test/x"}]')).toBeNull();
    expect(advisoryUrlFromRefs('not json')).toBeNull();
  });
});

describe('discovery store', () => {
  const tmp = () => join(mkdtempSync(join(tmpdir(), 'cybercve-')), 'fortinet.yaml');

  it('round-trips through YAML', () => {
    const path = tmp();
    mergeDiscoveryFile(path, 'fortinet', {
      'CVE-2025-32756': {
        discovery: 'INTERNAL',
        source: 'psirt-field',
        advisory: 'FG-IR-25-254',
        credit: 'Discovered by Théo Leleu of Fortinet Product Security Team.',
      },
    });
    const back = readDiscoveryFile(path);
    expect(back?.vendor).toBe('fortinet');
    expect(back?.cves['CVE-2025-32756']?.discovery).toBe('INTERNAL');
    // Non-ASCII survives the round trip — researcher names routinely carry it.
    expect(back?.cves['CVE-2025-32756']?.credit).toContain('Théo');
  });

  it('merges rather than replaces', () => {
    // The property this file exists for. A resumed or year-scoped scrape covers
    // a fraction of the corpus; if writing it dropped everything else, the site
    // would report that Fortinet stopped disclosing — a false claim about a
    // named company, not a visible outage.
    const path = tmp();
    mergeDiscoveryFile(path, 'fortinet', {
      'CVE-2024-0001': { discovery: 'INTERNAL', source: 'psirt-field' },
      'CVE-2024-0002': { discovery: 'EXTERNAL', source: 'psirt-field' },
    });
    const result = mergeDiscoveryFile(path, 'fortinet', {
      'CVE-2026-9999': { discovery: 'EXTERNAL', source: 'psirt-field' },
    });

    const back = readDiscoveryFile(path);
    expect(Object.keys(back?.cves ?? {})).toEqual([
      'CVE-2024-0001',
      'CVE-2024-0002',
      'CVE-2026-9999',
    ]);
    expect(result).toMatchObject({ added: 1, changed: 0, unchanged: 0, total: 3 });
  });

  it('reports a changed verdict instead of swapping it silently', () => {
    // A vendor reclassifying its own advisory is a real event and should show up
    // as a reviewable diff, not slide in unremarked.
    const path = tmp();
    mergeDiscoveryFile(path, 'fortinet', {
      'CVE-2024-0001': { discovery: 'INTERNAL', source: 'psirt-field' },
    });
    const result = mergeDiscoveryFile(path, 'fortinet', {
      'CVE-2024-0001': { discovery: 'EXTERNAL', source: 'psirt-field' },
    });
    expect(result).toMatchObject({ added: 0, changed: 1, unchanged: 0 });
    expect(readDiscoveryFile(path)?.cves['CVE-2024-0001']?.discovery).toBe('EXTERNAL');
  });

  it('sorts entries so a re-scrape diffs cleanly', () => {
    const path = tmp();
    mergeDiscoveryFile(path, 'fortinet', {
      'CVE-2026-0002': { discovery: 'EXTERNAL', source: 'psirt-field' },
      'CVE-2024-0001': { discovery: 'INTERNAL', source: 'psirt-field' },
    });
    expect(Object.keys(readDiscoveryFile(path)?.cves ?? {})).toEqual([
      'CVE-2024-0001',
      'CVE-2026-0002',
    ]);
  });

  it('treats a missing file as empty rather than throwing', () => {
    expect(readDiscoveryFile(join(tmpdir(), 'cybercve-does-not-exist.yaml'))).toBeNull();
  });
});

describe('selfFoundRate', () => {
  it('divides by disclosed CVEs only', () => {
    // Undisclosed records must never enter the denominator — that would turn a
    // vendor's failure to publish the field into a fake quality signal.
    expect(selfFoundRate({ internal: 379, external: 334, user: 0 })).toBeCloseTo(0.5316, 3);
    expect(selfFoundRate({ internal: 54, external: 117, user: 14 })).toBeCloseTo(0.2919, 3);
  });

  it('is null when nothing was disclosed', () => {
    expect(selfFoundRate({ internal: 0, external: 0, user: 0 })).toBeNull();
  });
});
