import { describe, expect, it } from 'vitest';
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
