import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { beforeAll, describe, expect, it } from 'vitest';
import { parseCategories, parseProducts, parseVendor } from '../src/config.js';
import { TaxonomyResolver, splitProductList } from '../src/taxonomy.js';

/**
 * One `affected[].product` string naming several products.
 *
 * Check Point files up to seven at once, spanning two categories, so resolving
 * only the first would count six of them nowhere. The risk in fixing that is
 * the opposite error — shredding a single product's name into parts that match
 * other products — and these tests exist to pin the rule that prevents it.
 */

const DATA_DIR = fileURLToPath(new URL('../../../data/', import.meta.url));
const readYaml = (relative: string): unknown =>
  parseYaml(readFileSync(new URL(relative, `file://${DATA_DIR}`), 'utf8'));

let resolver: TaxonomyResolver;

beforeAll(() => {
  const categories = parseCategories(readYaml('categories.yaml'));
  const slugs = new Set(categories.map((c) => c.slug));
  const vendors = readdirSync(`${DATA_DIR}vendors`)
    .filter((f) => f.endsWith('.yaml'))
    .sort()
    .map((f) => parseVendor(readYaml(`vendors/${f}`), `vendors/${f}`, slugs));
  const products = readdirSync(`${DATA_DIR}products`)
    .filter((f) => f.endsWith('.yaml'))
    .sort()
    .flatMap((f) => parseProducts(readYaml(`products/${f}`), `products/${f}`, slugs));
  resolver = new TaxonomyResolver(vendors, products);
});

describe('splitProductList', () => {
  it('splits a comma list, including the trailing "and"', () => {
    expect(splitProductList('A one, B two and C three')).toEqual(['A one', 'B two', 'C three']);
  });

  it('splits a comma list written with no spaces', () => {
    // Check Point writes exactly this.
    expect(splitProductList('AlphaOne,BetaTwo,GammaThree')).toEqual([
      'AlphaOne',
      'BetaTwo',
      'GammaThree',
    ]);
  });

  it('NEVER splits on "and" without a comma', () => {
    // The load-bearing rule. Without the comma gate, "Cisco Secure Email and Web
    // Manager" yields "Web Manager" and "Cisco Enterprise Chat and Email" yields
    // "Email", both of which match other products and would file one CVE against
    // unrelated SKUs. Do not "simplify" this into an unconditional split.
    for (const name of [
      'Cisco Unified Communications Manager IM and Presence Service',
      'Cisco Secure Email and Web Manager',
      'Cisco Small Business Smart and Managed Switches',
      'Cisco Enterprise Chat and Email',
      'WildFire WF-500 and WF-500-B',
    ]) {
      expect(splitProductList(name), name).toEqual([]);
    }
  });

  it('leaves an ordinary single name alone', () => {
    expect(splitProductList('FortiOS')).toEqual([]);
  });
});

describe('splitting adds nothing for the pre-existing vendors', () => {
  /**
   * Every product string in the corpus that contains a comma or " and ".
   * Quoted verbatim from `cve_affected`. If splitting changed any of these, the
   * change would be silently rewriting three vendors' history.
   */
  const CORPUS: Array<[string, string]> = [
    ['palo-alto', 'PAM Self-Hosted, Privilege Cloud'],
    ['palo-alto', 'Privileged Session Manager, Vault'],
    ['palo-alto', 'WildFire WF-500 and WF-500-B'],
    ['cisco', 'Cisco Unified Communications Manager IM and Presence Service'],
    ['cisco', 'Cisco Secure Email and Web Manager'],
    ['cisco', 'Cisco Small Business Smart and Managed Switches'],
    ['cisco', 'Cisco Enterprise Chat and Email'],
  ];

  for (const [vendor, raw] of CORPUS) {
    it(`resolves "${raw}" to exactly what it did before`, () => {
      const single = resolver.resolveProductName(vendor, raw);
      expect(resolver.resolveProductNames(vendor, raw).slugs).toEqual(single ? [single] : []);
    });
  }

  it('holds for every alias declared in every product file', () => {
    // Structural rather than enumerated: catches a future alias containing a
    // comma the moment someone adds one.
    const offenders: string[] = [];
    for (const file of readdirSync(`${DATA_DIR}products`).filter((f) =>
      f.endsWith('.yaml'),
    )) {
      const doc = readYaml(`products/${file}`) as {
        vendorSlug: string;
        products: { aliases?: string[] }[];
      };
      for (const product of doc.products) {
        for (const alias of product.aliases ?? []) {
          if (!alias.includes(',')) continue;
          const single = resolver.resolveProductName(doc.vendorSlug, alias);
          const plural = resolver.resolveProductNames(doc.vendorSlug, alias).slugs;
          // An alias with a comma may legitimately fan out (Check Point), but it
          // must never LOSE the product the whole string resolves to.
          if (single && !plural.includes(single)) offenders.push(`${alias} -> ${plural}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe('brand fallback inside a list', () => {
  /**
   * Splunk (under Cisco) declares a `brandFallback` product that catches
   * anything the brand ships which no sibling rule claims.
   *
   * Applied per part, it would fire on every unrecognised item in a list and
   * attach the catch-all alongside the products that did resolve — so a CVE
   * naming one real product and one unknown one would be filed against both.
   * It must only apply when the entry resolved to nothing at all.
   */
  it('does not attach the catch-all beside products that did resolve', () => {
    const { slugs, unmatchedParts } = resolver.resolveProductNames(
      'cisco',
      'Splunk Enterprise Security, Wholly Unknown Thing',
      'Splunk',
    );
    expect(slugs).toContain('splunk-enterprise-security');
    expect(slugs).not.toContain('splunk-apps');
    expect(unmatchedParts).toEqual(['Wholly Unknown Thing']);
  });

  it('still applies the catch-all when nothing in the list resolved', () => {
    const { slugs, unmatchedParts } = resolver.resolveProductNames(
      'cisco',
      'Wholly Unknown Thing, Another Unknown Thing',
      'Splunk',
    );
    expect(slugs).toEqual(['splunk-apps']);
    // Nothing partially resolved, so the parts are not a gap — the caller
    // queues the whole string instead.
    expect(unmatchedParts).toEqual([]);
  });
});
