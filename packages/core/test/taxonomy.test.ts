import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { beforeAll, describe, expect, it } from 'vitest';
import { parseCategories, parseProducts, parseVendor, validateBundle } from '../src/config.js';
import type { CategoryConfig, VendorFileConfig } from '../src/config.js';
import type { CveRecord } from '../src/cve-schema.js';
import { normalizeCve } from '../src/normalize.js';
import { TaxonomyResolver, normalizeKey } from '../src/taxonomy.js';
import type { ProductConfig } from '../src/types.js';

/**
 * End-to-end over the committed /data config and real CVE records. This is what
 * catches a mistyped CNA short name or a category rename — failures here mean the
 * site would have undercounted a vendor, which is invisible in production.
 */

const DATA_DIR = fileURLToPath(new URL('../../../data/', import.meta.url));

function readYaml(relative: string): unknown {
  return parseYaml(readFileSync(new URL(relative, `file://${DATA_DIR}`), 'utf8'));
}

function fixture(id: string) {
  const path = fileURLToPath(new URL(`./fixtures/${id}.json`, import.meta.url));
  return normalizeCve(JSON.parse(readFileSync(path, 'utf8')) as CveRecord);
}

let categories: CategoryConfig[];
let vendors: VendorFileConfig[];
let products: ProductConfig[];
let resolver: TaxonomyResolver;

beforeAll(() => {
  categories = parseCategories(readYaml('categories.yaml'));
  const categorySlugs = new Set(categories.map((c) => c.slug));

  vendors = readdirSync(`${DATA_DIR}vendors`)
    .filter((f) => f.endsWith('.yaml'))
    .map((f) => parseVendor(readYaml(`vendors/${f}`), `vendors/${f}`));

  products = readdirSync(`${DATA_DIR}products`)
    .filter((f) => f.endsWith('.yaml'))
    .flatMap((f) => parseProducts(readYaml(`products/${f}`), `products/${f}`, categorySlugs));

  validateBundle(vendors, products);
  resolver = new TaxonomyResolver(vendors, products);
});

describe('committed config', () => {
  it('loads and cross-validates without error', () => {
    expect(categories.length).toBeGreaterThan(0);
    expect(vendors.map((v) => v.slug).sort()).toEqual(['cisco', 'fortinet', 'palo-alto']);
    expect(products.length).toBeGreaterThan(50);
  });

  it('marks routing and non-security categories as excluded from comparisons', () => {
    const bySlug = new Map(categories.map((c) => [c.slug, c]));
    expect(bySlug.get('firewall')?.security).toBe(true);
    expect(bySlug.get('endpoint')?.security).toBe(true);
    // Without this split, Cisco's routing and collaboration CVEs would swamp any
    // comparison against a pure-play security vendor.
    expect(bySlug.get('routing-switching')?.security).toBe(false);
    expect(bySlug.get('other')?.security).toBe(false);
  });

  it('gives every vendor a way to be matched', () => {
    for (const vendor of vendors) {
      expect(vendor.cnaShortNames.length + vendor.aliases.length).toBeGreaterThan(0);
    }
  });
});

describe('normalizeKey', () => {
  it('folds trademark marks, case, and separators onto one key', () => {
    expect(normalizeKey('FortiOS®')).toBe('fortios');
    expect(normalizeKey('Palo Alto Networks, Inc.')).toBe('palo alto networks inc.');
    expect(normalizeKey('FortiNAC_F')).toBe('fortinac f');
    expect(normalizeKey('  Cisco   IOS  XE  ')).toBe('cisco ios xe');
  });
});

describe('vendor matching', () => {
  it('matches Fortinet via the CNA assigner, the strongest signal', () => {
    expect(resolver.matchVendors(fixture('CVE-2025-32756')).get('fortinet')).toBe('cna-assigner');
  });

  it('matches Palo Alto despite the underscored CNA short name', () => {
    expect(resolver.matchVendors(fixture('CVE-2024-3400')).get('palo-alto')).toBe('cna-assigner');
  });

  it('matches Cisco', () => {
    expect(resolver.matchVendors(fixture('CVE-2023-20198')).get('cisco')).toBe('cna-assigner');
  });

  it('attributes a third-party-filed CVE via affected vendor, not the assigner', () => {
    // The case the CNA-only approach silently loses: a researcher files through
    // MITRE for a bug in a vendor's product.
    const cve = fixture('CVE-2025-32756');
    cve.assignerShortName = 'mitre';
    const matches = resolver.matchVendors(cve);
    expect(matches.get('fortinet')).toBe('affected-vendor');
  });

  it('falls back to the PSIRT reference host when nothing else identifies the vendor', () => {
    const cve = fixture('CVE-2025-32756');
    cve.assignerShortName = 'mitre';
    cve.affected = [];
    expect(resolver.matchVendors(cve).get('fortinet')).toBe('reference-host');
  });

  it('matches via CPE vendor form when the assigner and free-text vendor are absent', () => {
    // CISA-ADP writes PAN's vendor as "paloaltonetworks", not "Palo Alto Networks".
    const cve = fixture('CVE-2024-3400');
    cve.assignerShortName = 'mitre';
    cve.references = [];
    cve.affected = cve.affected.filter((a) => a.cpes.length > 0);
    expect(resolver.matchVendors(cve).get('palo-alto')).toBe('affected-vendor');
  });

  it('does not match an unrelated vendor', () => {
    expect(resolver.matchVendors(fixture('CVE-2025-32756')).has('cisco')).toBe(false);
  });
});

describe('product resolution', () => {
  it('maps Fortinet products to the right categories', () => {
    const { resolved } = resolver.resolve(fixture('CVE-2025-32756'));
    const byProduct = new Map(resolved.map((r) => [r.productSlug, r]));

    expect(byProduct.get('fortinet-fortimail')?.categorySlug).toBe('email-security');
    expect(byProduct.get('fortinet-fortindr')?.categorySlug).toBe('threat-detection');
    expect(byProduct.get('fortinet-fortivoice')?.categorySlug).toBe('other');
    expect(resolved.every((r) => r.vendorSlug === 'fortinet')).toBe(true);
  });

  it('maps PAN-OS to firewall from free text alone', () => {
    const { resolved, unmapped } = resolver.resolve(fixture('CVE-2024-3400'));
    const byProduct = new Map(resolved.map((r) => [r.productSlug, r]));

    expect(byProduct.get('palo-alto-pan-os')?.categorySlug).toBe('firewall');
    expect(unmapped).toHaveLength(0);
  });

  it('honours the advisory when it says a listed product is NOT affected', () => {
    // This assertion used to demand the opposite, and was wrong. CVE-2024-3400
    // names Cloud NGFW and Prisma Access in `affected[]` only to mark them
    // `unaffected` — Palo Alto's advisory states plainly that neither is
    // impacted. Reading array membership as vulnerability put both on the
    // firewall and SASE pages for a bug they never had.
    const { resolved } = resolver.resolve(fixture('CVE-2024-3400'));
    const slugs = resolved.map((r) => r.productSlug);

    expect(slugs).not.toContain('palo-alto-cloud-ngfw');
    expect(slugs).not.toContain('palo-alto-prisma-access');
  });

  it('maps Cisco IOS XE into routing-switching via pattern match', () => {
    const { resolved } = resolver.resolve(fixture('CVE-2023-20198'));
    expect(resolved).toEqual([
      expect.objectContaining({
        productSlug: 'cisco-ios-xe',
        vendorSlug: 'cisco',
        categorySlug: 'routing-switching',
        matchSignal: 'cna-assigner',
      }),
    ]);
  });

  it('resolves product name variants a strict alias list would miss', () => {
    expect(resolver.resolveProductName('fortinet', 'FortiOS 7.4.1')).toBe('fortinet-fortios');
    expect(resolver.resolveProductName('cisco', 'Cisco Adaptive Security Appliance (ASA) Software'))
      .toBe('cisco-asa');
    expect(resolver.resolveProductName('cisco', 'Cisco Firepower Threat Defense Software')).toBe(
      'cisco-ftd',
    );
    expect(resolver.resolveProductName('palo-alto', 'PAN-OS 11.1')).toBe('palo-alto-pan-os');
  });

  it('queues an unknown product for review instead of dropping it', () => {
    const cve = fixture('CVE-2025-32756');
    cve.affected = [
      { vendorRaw: 'Fortinet', productRaw: 'FortiTotallyNewThing', cpes: [], versions: [], versionsTruncated: false, versionCount: 0, defaultStatus: null },
    ];
    const { resolved, unmapped } = resolver.resolve(cve);
    expect(resolved).toHaveLength(0);
    expect(unmapped).toEqual([
      expect.objectContaining({ productRaw: 'FortiTotallyNewThing', vendorSlug: 'fortinet' }),
    ]);
  });

  it('does not assign one vendor products belonging to another', () => {
    // A multi-vendor CVE must not smear every product across every matched vendor.
    const cve = fixture('CVE-2024-3400');
    cve.affected.push({
      vendorRaw: 'Fortinet',
      productRaw: 'FortiOS',
      cpes: [],
      versions: [],
      versionsTruncated: false,
      versionCount: 0,
      defaultStatus: null,
    });
    const { resolved } = resolver.resolve(cve);
    const fortios = resolved.find((r) => r.productSlug === 'fortinet-fortios');
    expect(fortios?.vendorSlug).toBe('fortinet');
    expect(resolved.filter((r) => r.vendorSlug === 'palo-alto').map((r) => r.productSlug)).not.toContain(
      'fortinet-fortios',
    );
  });
});

/**
 * The end-to-end shape of the reported bug: a product stated only in prose.
 *
 * Runs the whole resolver over the committed /data config, so it fails if the
 * patterns move, if the signal is renamed, or if Panorama's category changes.
 */
describe('CVE-2026-0281 — Panorama, named in the description and nowhere else', () => {
  it('has PAN-OS and only PAN-OS in the structured record', () => {
    // The premise. Every product in `affected[]` that survives the unaffected
    // filter is a firewall product; nothing there says "management platform".
    const { resolved } = resolver.resolve(fixture('CVE-2026-0281'));
    const structured = resolved.filter((r) => r.matchSignal !== 'description');
    expect(structured.map((r) => r.productSlug)).toEqual(['palo-alto-pan-os']);
  });

  it('adds Panorama from the description, under the management category', () => {
    const { resolved } = resolver.resolve(fixture('CVE-2026-0281'));
    const panorama = resolved.find((r) => r.productSlug === 'palo-alto-panorama');
    expect(panorama).toMatchObject({
      vendorSlug: 'palo-alto',
      categorySlug: 'network-management',
      matchSignal: 'description',
    });
  });

  it('keeps PAN-OS rather than replacing it', () => {
    // The advisory says the issue applies to PAN-OS software ON Panorama and on
    // PA-Series and VM-Series firewalls. Both are true; the CVE belongs in both
    // categories, and prose must never delete what affected[] established.
    const { resolved } = resolver.resolve(fixture('CVE-2026-0281'));
    const panOs = resolved.find((r) => r.productSlug === 'palo-alto-pan-os');
    expect(panOs?.categorySlug).toBe('firewall');
    expect(panOs?.matchSignal).not.toBe('description');
  });

  it('ignores the description when only a reference URL ties the vendor in', () => {
    // A CVE that merely links to the vendor's site is somebody else writing
    // about their product. The prose is not theirs to make claims with.
    const cve = {
      cveId: 'CVE-2026-99999',
      assignerShortName: 'mitre',
      description: 'This issue is applicable to PAN-OS software on Panorama (virtual and M-Series).',
      affected: [],
      references: [{ url: 'https://security.paloaltonetworks.com/CVE-2026-0281' }],
    } as unknown as Parameters<TaxonomyResolver['resolve']>[0];

    const { resolved, vendors } = resolver.resolve(cve);
    expect(vendors.get('palo-alto')).toBe('reference-host');
    expect(resolved.map((r) => r.productSlug)).not.toContain('palo-alto-panorama');
  });

  it('does not add Panorama to CVE-2024-3400, which says it is not impacted', () => {
    const { resolved } = resolver.resolve(fixture('CVE-2024-3400'));
    expect(resolved.map((r) => r.productSlug)).not.toContain('palo-alto-panorama');
  });
});

describe('unrecognised vendor on a CNA-assigned CVE', () => {
  // Cisco acquired Splunk and began assigning Splunk CVEs under its own CNA
  // while the affected entries still read vendor "Splunk". Every one of those
  // 69 CVEs resolved to nothing and never reached the review queue, because the
  // entry was discarded before the queue was written. The queue existing is the
  // only thing that makes a gap like this visible before someone notices by eye.
  const resolver = new TaxonomyResolver(
    [
      {
        slug: 'cisco',
        name: 'Cisco',
        cnaShortNames: ['cisco'],
        aliases: ['Cisco'],
        psirtHosts: [],
        psirtUrl: null,
        homepage: null,
        adapter: 'cvelist',
        discoveryNote: null,
        internalBrandMarkers: [],
      },
    ],
    [],
  );

  // Same vendor, but with one product defined, so a CVE can actually resolve.
  const resolverWithProducts = new TaxonomyResolver(
    [
      {
        slug: 'cisco',
        name: 'Cisco',
        cnaShortNames: ['cisco'],
        aliases: ['Cisco'],
        psirtHosts: [],
        psirtUrl: null,
        homepage: null,
        adapter: 'cvelist',
        discoveryNote: null,
        internalBrandMarkers: [],
      },
    ],
    [
      {
        slug: 'cisco-secure-firewall',
        name: 'Cisco Secure Firewall',
        vendorSlug: 'cisco',
        categorySlug: 'firewall',
        aliases: ['Cisco Secure Firewall'],
        patterns: [],
        descriptionPatterns: [],
      },
    ],
  );

  const cve = {
    cveId: 'CVE-2026-20298',
    assignerShortName: 'cisco',
    affected: [{ vendorRaw: 'Acquired Co', productRaw: 'Acquired Product', cpes: [], versions: [] }],
    references: [],
  } as unknown as Parameters<TaxonomyResolver['resolve']>[0];

  it('queues the product for review instead of dropping it', () => {
    const { unmapped } = resolver.resolve(cve);
    expect(unmapped).toHaveLength(1);
    expect(unmapped[0]).toMatchObject({
      vendorRaw: 'Acquired Co',
      productRaw: 'Acquired Product',
      vendorSlug: 'cisco',
    });
  });

  it('does not attribute the product to the assigning vendor', () => {
    // A CNA does occasionally assign for a genuine third party, so surfacing the
    // gap must not become a licence to claim the product.
    expect(resolver.resolve(cve).resolved).toHaveLength(0);
  });

  it('stays quiet when another entry already attributed the CVE', () => {
    // Siemens ships RUGGEDCOM APE1808 running FortiOS, so 41 Fortinet CVEs carry
    // a second affected[] entry naming Siemens. All 41 are counted via their
    // FortiOS entry, but "RUGGEDCOM APE1808" still reached the queue at 40 hits
    // — its largest item, and unactionable forever, because Siemens is a real
    // third party rather than an acquisition waiting for an alias. A queue whose
    // top entry can never be resolved is a queue people stop reading.
    const withKnownProduct = {
      ...cve,
      affected: [
        { vendorRaw: 'Cisco', productRaw: 'Cisco Secure Firewall', cpes: [], versions: [] },
        ...cve.affected,
      ],
    } as typeof cve;

    const { resolved, unmapped } = resolverWithProducts.resolve(withKnownProduct);
    expect(resolved.map((r) => r.productSlug)).toEqual(['cisco-secure-firewall']);
    expect(unmapped).toHaveLength(0);
  });
});
