import { describe, expect, it } from 'vitest';
import {
  denyPatterns,
  isExclusion,
  productsInDescription,
  sentences,
} from '../src/description.js';
import type { DescriptionRule } from '../src/description.js';

/** The real Panorama rule, as data/products/palo-alto.yaml declares it. */
const PANORAMA: DescriptionRule = {
  productSlug: 'palo-alto-panorama',
  affirm: [
    /\bon Panorama\b/i,
    /\bPanorama (?:software|appliances?|server|management server)\b/i,
  ],
  deny: denyPatterns(['Panorama', 'Panorama Interconnect']),
};

describe('sentences', () => {
  it('splits on terminators and hard breaks', () => {
    expect(sentences('One thing. Two things!\nThree things?')).toEqual([
      'One thing',
      'Two things',
      'Three things',
    ]);
  });

  it('does not split inside a version number', () => {
    // "Upgrade to 11.1.16 or later" must stay one sentence, or a negation in
    // its first half stops applying to the product named in its second.
    expect(sentences('Upgrade to 11.1.16 or later.')).toEqual(['Upgrade to 11.1.16 or later']);
  });

  it('splits on <br> because the HTML rendering of a description uses them', () => {
    expect(sentences('Affects Panorama.<br><br>Cloud NGFW is not impacted.')).toEqual([
      'Affects Panorama',
      'Cloud NGFW is not impacted',
    ]);
  });
});

describe('isExclusion', () => {
  for (const s of [
    'Panorama, Cloud NGFW, and Prisma® Access are not impacted by this vulnerability.',
    'Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.',
    'This issue does not affect firewalls that are already deployed.',
    'Panorama is unaffected.',
    'No action needed.',
  ]) {
    it(`reads a denial: ${s.slice(0, 40)}…`, () => expect(isExclusion(s)).toBe(true));
  }

  for (const s of [
    'This issue is applicable to PAN-OS software on PA-Series and VM-Series firewalls and on Panorama (virtual and M-Series).',
    'An improper authorization vulnerability in Palo Alto Networks Panorama software enables an authenticated read-only administrator to upload files.',
  ]) {
    it(`does not read a denial into: ${s.slice(0, 40)}…`, () => expect(isExclusion(s)).toBe(false));
  }
});

describe('productsInDescription', () => {
  it('claims a product the description says the issue applies to', () => {
    const d =
      'An information disclosure vulnerability in Palo Alto Networks PAN-OS® software enables an unauthenticated attacker to obtain web session tokens. ' +
      'This issue is applicable to PAN-OS software on PA-Series and VM-Series firewalls and on Panorama (virtual and M-Series). ' +
      'Cloud NGFW and Prisma® Access are not impacted by this vulnerability.';
    expect([...productsInDescription(d, [PANORAMA])]).toEqual(['palo-alto-panorama']);
  });

  it('refuses a product the description names only to exclude it', () => {
    // The exact shape a reader sees when they filter Palo Alto's PSIRT page on
    // Panorama: the CVE comes back, and it comes back to say "not this one".
    const d =
      'A command injection vulnerability in the GlobalProtect feature of PAN-OS software may enable an unauthenticated attacker to execute arbitrary code. ' +
      'Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.';
    expect([...productsInDescription(d, [PANORAMA])]).toEqual([]);
  });

  it('lets a denial override an affirmation on the same record', () => {
    // A record that both asserts and denies is self-contradictory. Declining to
    // add the product leaves behaviour exactly as it was before this rule; the
    // other choice publishes a bug against a product the vendor calls safe.
    const d = 'The issue applies on Panorama appliances. Panorama is not impacted.';
    expect([...productsInDescription(d, [PANORAMA])]).toEqual([]);
  });

  it('does not mistake the attacker for the affected product', () => {
    // CVE-2024-5920. A Panorama admin is the ACTOR; the vulnerable component is
    // the PAN-OS node they push configuration to.
    const d =
      'A cross-site scripting (XSS) vulnerability in Palo Alto Networks PAN-OS software enables an authenticated read-write Panorama administrator to push a specially crafted configuration to a PAN-OS node.';
    expect([...productsInDescription(d, [PANORAMA])]).toEqual([]);
  });

  it('claims a product the flaw is described as being in', () => {
    // CVE-2024-2433 — the vulnerability is in Panorama, while the vendor's own
    // affected[] lists only PAN-OS, which Panorama runs.
    const d =
      'An improper authorization vulnerability in Palo Alto Networks Panorama software enables an authenticated read-only administrator to fill a disk partition.';
    expect([...productsInDescription(d, [PANORAMA])]).toEqual(['palo-alto-panorama']);
  });

  it('returns nothing for an empty description or an empty ruleset', () => {
    expect([...productsInDescription(null, [PANORAMA])]).toEqual([]);
    expect([...productsInDescription('Affects Panorama software.', [])]).toEqual([]);
  });
});

describe('denyPatterns', () => {
  it('tolerates the spacing and trademark marks upstream actually writes', () => {
    const [re] = denyPatterns(['Prisma Access']);
    for (const spelling of ['Prisma Access', 'Prisma® Access', 'Prisma  Access']) {
      expect(re.test(`${spelling} is not impacted by this vulnerability.`)).toBe(true);
    }
  });

  it('skips spellings too short to match safely', () => {
    // "IDP" and "PAM" are real aliases in the taxonomy and would fire on
    // ordinary English inside an unrelated sentence.
    expect(denyPatterns(['IDP', 'PAM', 'Panorama'])).toHaveLength(1);
  });

  it('still requires a word boundary', () => {
    const [re] = denyPatterns(['Panorama']);
    expect(re.test('Panoramax is not affected.')).toBe(false);
  });
});
