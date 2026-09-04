import { describe, expect, it } from 'vitest';
import { denyPatterns, productsInDescription } from '@cybercves/core';
import { loadConfig } from '../src/node/config-loader.js';

/**
 * Coverage probes for the product-name forms that actually appear upstream.
 *
 * Two distinct spellings reach us for the same product: the CNA's free text
 * ("Cisco Adaptive Security Appliance (ASA) Software") and the CPE component
 * CISA-ADP emits ("asa", "firepower_threat_defense_software"). A rule that only
 * covers the first silently sends the second to the review queue, which reads as
 * "we have no data" rather than "our matcher has a gap".
 */

const { resolver } = loadConfig();

/** CPE product components, as they appear after underscore-to-space folding. */
const CPE_FORMS: Record<string, string[]> = {
  cisco: [
    'asa',
    'ios_xe',
    'ios',
    'nx-os',
    'ios_xr',
    'adaptive_security_appliance',
    'adaptive_security_appliance_software',
    'firepower_threat_defense',
    'firepower_management_center',
    'secure_firewall_management_center',
    'anyconnect_secure_mobility_client',
    'secure_client',
    'identity_services_engine',
    'duo',
    'umbrella',
    'email_security_appliance',
    'web_security_appliance',
    'secure_endpoint',
    'prime_infrastructure',
    'dna_center',
    'catalyst_center',
    'unified_communications_manager',
    'webex_meetings',
    'stealthwatch',
    'unified_computing_system',
  ],
  fortinet: [
    'fortios',
    'fortiproxy',
    'fortigate',
    'forticlient',
    'fortiedr',
    'fortimail',
    'fortiweb',
    'fortiadc',
    'fortianalyzer',
    'fortisiem',
    'fortimanager',
    'fortiauthenticator',
    'fortinac',
    'fortisandbox',
    'fortindr',
    'fortivoice',
    'forticamera',
    'fortirecorder',
    'fortiswitch',
    'fortiap',
    'fortios_6k7k',
    'fortitoken',
    'fortisoar',
    'fortideceptor',
    'fortisase',
  ],
  'palo-alto': [
    'pan-os',
    'pan_os',
    'cloud_ngfw',
    'prisma_access',
    'prisma_cloud',
    'cortex_xdr',
    'cortex_xsoar',
    'cortex_xsiam',
    'globalprotect',
    'globalprotect_app',
    'panorama',
    'expedition',
    'user-id_agent',
    'iot_security',
    'prisma_sd-wan',
  ],
};

describe('CPE-form coverage', () => {
  for (const [vendorSlug, forms] of Object.entries(CPE_FORMS)) {
    it(`resolves every known CPE product form for ${vendorSlug}`, () => {
      const unresolved = forms.filter((form) => !resolver.resolveProductName(vendorSlug, form));
      expect(unresolved).toEqual([]);
    });
  }
});

describe('pattern precedence', () => {
  it('does not let a broad pattern swallow a more specific product', () => {
    // Patterns are tried in file order, so a bare `^unified\b` on the
    // communications manager would capture "unified computing system" first.
    expect(resolver.resolveProductName('cisco', 'unified_computing_system')).toBe('cisco-ucs');
    expect(resolver.resolveProductName('cisco', 'unified_communications_manager')).toBe('cisco-ucm');
  });

  it('distinguishes IOS from IOS XE and IOS XR', () => {
    expect(resolver.resolveProductName('cisco', 'ios_xe')).toBe('cisco-ios-xe');
    expect(resolver.resolveProductName('cisco', 'ios_xr')).toBe('cisco-ios-xr');
    expect(resolver.resolveProductName('cisco', 'ios')).toBe('cisco-ios');
  });

  it('routes ASA and FTD to firewall, not to routing', () => {
    expect(resolver.getProduct(resolver.resolveProductName('cisco', 'asa')!)?.categorySlug).toBe(
      'firewall',
    );
    expect(
      resolver.getProduct(resolver.resolveProductName('cisco', 'firepower_threat_defense')!)
        ?.categorySlug,
    ).toBe('firewall');
  });
});

describe('category assignment sanity', () => {
  it('keeps firewall and endpoint products in security categories', () => {
    const cases: Array<[string, string, string]> = [
      ['fortinet', 'fortios', 'firewall'],
      ['fortinet', 'fortiedr', 'endpoint'],
      ['fortinet', 'fortimail', 'email-security'],
      ['palo-alto', 'pan-os', 'firewall'],
      ['palo-alto', 'cortex_xdr', 'endpoint'],
      ['palo-alto', 'globalprotect', 'vpn-remote-access'],
      ['cisco', 'secure_endpoint', 'endpoint'],
      ['cisco', 'anyconnect_secure_mobility_client', 'vpn-remote-access'],
    ];
    for (const [vendor, form, expected] of cases) {
      const slug = resolver.resolveProductName(vendor, form);
      expect(resolver.getProduct(slug!)?.categorySlug, `${vendor}/${form}`).toBe(expected);
    }
  });

  it('keeps routing and collaboration out of the security comparison', () => {
    const { categories } = loadConfig();
    const nonSecurity = new Set(categories.filter((c) => !c.security).map((c) => c.slug));
    for (const form of ['ios_xe', 'webex_meetings', 'unified_computing_system']) {
      const slug = resolver.resolveProductName('cisco', form);
      expect(nonSecurity.has(resolver.getProduct(slug!)!.categorySlug), form).toBe(true);
    }
  });
});

/**
 * Applicability the vendor states in prose instead of in `affected[]`.
 *
 * These run against the patterns actually shipped in data/products/*.yaml, not
 * against a copy, because the risk being guarded is a well-meant widening of a
 * pattern — 'Panorama' instead of 'on Panorama' — that reads as an improvement
 * and quietly files fourteen CVEs against a product the vendor says is safe.
 *
 * Each sentence below is quoted from a real record. See description.ts.
 */
describe('description-stated applicability', () => {
  const { products } = loadConfig();
  const rulesFor = (vendorSlug: string) =>
    products
      .filter((p) => p.vendorSlug === vendorSlug && p.descriptionPatterns.length)
      .map((p) => ({
        productSlug: p.slug,
        affirm: p.descriptionPatterns.map((source) => new RegExp(source, 'i')),
        deny: denyPatterns([p.name, ...p.aliases]),
      }));

  const panorama = (description: string) =>
    productsInDescription(description, rulesFor('palo-alto')).has('palo-alto-panorama');

  const AFFIRMS: Array<[string, string]> = [
    [
      'CVE-2026-0281 and nine siblings — the formulaic applicability sentence',
      'An information disclosure vulnerability in Palo Alto Networks PAN-OS® software enables an unauthenticated attacker with network access to the management web interface to obtain web session tokens.\n\nThis issue is applicable to PAN-OS software on PA-Series and VM-Series firewalls and on Panorama (virtual and M-Series).\n\nCloud NGFW and Prisma® Access are not impacted by this vulnerability.',
    ],
    [
      'CVE-2024-2433 — the flaw is described as being in Panorama itself',
      'An improper authorization vulnerability in Palo Alto Networks Panorama software enables an authenticated read-only administrator to upload files using the web interface and completely fill one of the disk partitions.',
    ],
    [
      'CVE-2024-0007 — the affected surface is the web interface on Panorama',
      'A cross-site scripting (XSS) vulnerability in Palo Alto Networks PAN-OS software enables a malicious authenticated read-write administrator to store a JavaScript payload using the web interface on Panorama appliances.',
    ],
  ];

  const DENIES: Array<[string, string]> = [
    [
      'CVE-2026-0287 — the bare denial',
      'A vulnerability in PAN-OS software enables a denial of service. Panorama is not impacted by these vulnerabilities.',
    ],
    [
      'CVE-2024-3400 — denied in a list, alongside products that are also denied',
      'A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.\n\nCloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.',
    ],
    [
      'CVE-2026-0300 — denied last in the list',
      'Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.',
    ],
    [
      'CVE-2024-5920 — Panorama is the ATTACKER, the PAN-OS node is the target',
      'A cross-site scripting (XSS) vulnerability in Palo Alto Networks PAN-OS software enables an authenticated read-write Panorama administrator to push a specially crafted configuration to a PAN-OS node.',
    ],
  ];

  for (const [label, description] of AFFIRMS) {
    it(`links Panorama: ${label}`, () => expect(panorama(description)).toBe(true));
  }
  for (const [label, description] of DENIES) {
    it(`leaves Panorama off: ${label}`, () => expect(panorama(description)).toBe(false));
  }

  it('gives Panorama a management category, so the link lands somewhere real', () => {
    // The reported symptom was an empty Network & Security Management column for
    // Palo Alto, not a missing product — the product existed and matched nothing.
    const panoramaProduct = products.find((p) => p.slug === 'palo-alto-panorama');
    expect(panoramaProduct?.categorySlug).toBe('network-management');
    expect(panoramaProduct?.descriptionPatterns.length).toBeGreaterThan(0);
  });
});
