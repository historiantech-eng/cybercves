import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { beforeAll, describe, expect, it } from 'vitest';
import { parseCategories, parseProducts, parseVendor } from '../src/config.js';
import type { CveRecord } from '../src/cve-schema.js';
import { normalizeCve } from '../src/normalize.js';
import { TaxonomyResolver } from '../src/taxonomy.js';
import type { ProductConfig, VendorFileConfig } from '../src/types.js';

/**
 * Acquired brands inside a vendor.
 *
 * Cisco owns Splunk and Palo Alto owns CyberArk, but upstream still writes the
 * acquired name in `affected[].vendor`. Splunk then names each SOAR connector
 * after the system it integrates with — "Cisco Webex app for Splunk SOAR",
 * "CrowdStrike OAuth API app for Splunk SOAR" — so matching a Splunk entry
 * against Cisco's whole catalogue filed a Splunk connector bug as a Cisco Webex
 * vulnerability (CVE-2026-76379), while the fifteen connectors whose names
 * carry no Cisco product at all were counted under nothing.
 */

const DATA_DIR = fileURLToPath(new URL('../../../data/', import.meta.url));

const readYaml = (relative: string): unknown =>
  parseYaml(readFileSync(new URL(relative, `file://${DATA_DIR}`), 'utf8'));

const fixture = (id: string) =>
  normalizeCve(
    JSON.parse(
      readFileSync(fileURLToPath(new URL(`./fixtures/${id}.json`, import.meta.url)), 'utf8'),
    ) as CveRecord,
  );

let resolver: TaxonomyResolver;
let products: ProductConfig[];

beforeAll(() => {
  const categories = parseCategories(readYaml('categories.yaml'));
  const categorySlugs = new Set(categories.map((c) => c.slug));
  const vendors: VendorFileConfig[] = readdirSync(`${DATA_DIR}vendors`)
    .filter((f) => f.endsWith('.yaml'))
    .map((f) => parseVendor(readYaml(`vendors/${f}`), `vendors/${f}`));
  products = readdirSync(`${DATA_DIR}products`)
    .filter((f) => f.endsWith('.yaml'))
    .flatMap((f) => parseProducts(readYaml(`products/${f}`), `products/${f}`, categorySlugs));
  resolver = new TaxonomyResolver(vendors, products);
});

describe('brand spellings', () => {
  it('reaches the brand through every spelling the vendor declares', () => {
    for (const spelling of ['Splunk', 'Splunk Inc.', 'Splunk LLC', 'splunk']) {
      expect(resolver.resolveProductName('cisco', 'FireAMP', spelling), spelling).toBe(
        'splunk-apps',
      );
    }
    // CyberArk writes four of these, including a rename to "Idira". Nothing but
    // the declared list can know that Idira means CyberArk.
    for (const spelling of [
      'CyberArk',
      'CyberArk Software',
      'CyberArk Software, a Palo Alto Networks Company',
      'Idira',
    ]) {
      expect(resolver.resolveProductName('palo-alto', 'Conjur', spelling), spelling).toBe(
        'cyberark-conjur',
      );
    }
  });

  it('treats an unlisted spelling as the vendor\'s own, not the brand\'s', () => {
    // Deliberate: a fuzzy match here would be a silent mis-attribution. An
    // unrecognised spelling shows up in the review queue instead.
    expect(resolver.resolveProductName('palo-alto', 'Conjur', 'Some Other Co')).toBeNull();
  });
});

describe('brand-scoped product resolution', () => {
  it('keeps a Splunk connector out of the Cisco product it is named after', () => {
    // The bug: "Cisco Webex app for Splunk SOAR" matched Cisco's Webex pattern.
    expect(resolver.resolveProductName('cisco', 'Cisco Webex app for Splunk SOAR', 'Splunk')).toBe(
      'splunk-apps',
    );
    // ...while Cisco's own Webex still resolves to Webex.
    expect(resolver.resolveProductName('cisco', 'Cisco Webex App', 'Cisco')).toBe('cisco-webex');
  });

  it('catches the connectors whose names carry no Splunk token at all', () => {
    // SVD-2026-0806. Nothing in "FireAMP" says Splunk; only the entry's vendor
    // does, which is exactly what the brand scope is reading.
    for (const name of ['FireAMP', 'Nmap Scanner', 'AD LDAP app for Splunk SOAR']) {
      expect(resolver.resolveProductName('cisco', name, 'Splunk')).toBe('splunk-apps');
    }
  });

  it('files a Splunk Enterprise Security add-on under Splunk, not Cisco Talos', () => {
    expect(
      resolver.resolveProductName(
        'cisco',
        'Cisco Talos Intelligence for Enterprise Security Cloud',
        'Splunk',
      ),
    ).toBe('splunk-apps');
  });

  it('still tells the Splunk products apart from each other', () => {
    const cases: Array<[string, string]> = [
      ['Splunk Enterprise', 'splunk-enterprise'],
      ['Splunk Enterprise Security', 'splunk-enterprise-security'],
      // Was landing on splunk-enterprise: no exact alias, and the broader
      // '^splunk enterprise\b' pattern was tried first.
      ['Splunk Enterprise Security (ES)', 'splunk-enterprise-security'],
      ['Splunk Enterprise Cloud', 'splunk-cloud-platform'],
      ['Splunk Cloud Platform', 'splunk-cloud-platform'],
      ['Splunk SOAR', 'splunk-soar'],
      ['Splunk Secure Gateway', 'splunk-secure-gateway'],
      // Bare CPE product components; the vendor half of the CPE carries "splunk".
      ['splunk', 'splunk-enterprise'],
      ['cloud', 'splunk-cloud-platform'],
      ['enterprise_security', 'splunk-enterprise-security'],
    ];
    for (const [name, slug] of cases) {
      expect(resolver.resolveProductName('cisco', name, 'Splunk'), name).toBe(slug);
    }
  });

  it('does not let a brand product escape into the vendor it belongs to', () => {
    // '^cloud$' and '^idp$' are deliberately bare, and out of scope they would
    // claim the parent vendor's strings.
    expect(resolver.resolveProductName('cisco', 'cloud', 'Cisco')).not.toBe(
      'splunk-cloud-platform',
    );
    expect(resolver.resolveProductName('palo-alto', 'IDP', 'Palo Alto Networks')).not.toBe(
      'cyberark-identity',
    );
  });

  it('queues an unrecognised brand product for review when the brand has no fallback', () => {
    // CyberArk deliberately has no brandFallback: an unknown product there is a
    // gap a human should name, not something to bury in a catch-all.
    expect(resolver.resolveProductName('palo-alto', 'Idira Something New', 'CyberArk')).toBeNull();
    expect(resolver.resolveProductName('palo-alto', 'Conjur', 'CyberArk')).toBe('cyberark-conjur');
  });

  it('declares exactly one fallback per brand', () => {
    const fallbacks = products.filter((p) => p.brandFallback);
    expect(fallbacks.map((p) => p.slug)).toEqual(['splunk-apps']);
    for (const p of fallbacks) expect(p.brand).toBeTruthy();
  });
});

describe('the reported CVEs', () => {
  it('counts CVE-2026-76390 as a Splunk product under Cisco', () => {
    const { resolved, unmapped } = resolver.resolve(fixture('CVE-2026-76390'));
    expect(unmapped).toHaveLength(0);
    expect(resolved.map((r) => [r.vendorSlug, r.productSlug, r.categorySlug])).toEqual([
      ['cisco', 'splunk-apps', 'siem-logging'],
    ]);
  });

  it('no longer publishes CVE-2026-76379 as a Cisco Webex vulnerability', () => {
    const { resolved } = resolver.resolve(fixture('CVE-2026-76379'));
    expect(resolved.map((r) => r.productSlug)).toEqual(['splunk-apps']);
  });
});
