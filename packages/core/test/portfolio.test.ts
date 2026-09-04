import { describe, expect, it } from 'vitest';
import { ConfigError, parseVendor, validateBundle } from '../src/config.js';
import type { ProductConfig } from '../src/types.js';

/**
 * The declared-portfolio rules.
 *
 * `portfolio` is the only thing separating "this vendor sells nothing here" from
 * "this vendor sells here and had a clean year", and the site prints a different
 * claim for each. These tests pin the two ways that can go wrong: a declaration
 * that contradicts the products beneath it, and a MISSING declaration being read
 * as "competes in nothing".
 */

const CATEGORIES = new Set(['firewall', 'endpoint', 'web-app-security']);

function vendor(raw: Record<string, unknown>) {
  return parseVendor({ slug: 'acme', name: 'Acme', cnaShortNames: ['acme'], ...raw }, 'vendors/acme.yaml', CATEGORIES);
}

function product(categorySlug: string): ProductConfig {
  return {
    slug: 'acme-thing',
    vendorSlug: 'acme',
    name: 'Thing',
    categorySlug,
    aliases: ['Thing'],
    patterns: [],
    descriptionPatterns: [],
    brand: null,
    brandFallback: false,
  };
}

describe('parseVendor portfolio', () => {
  it('parses a declared list', () => {
    expect(vendor({ portfolio: ['firewall', 'endpoint'] }).portfolio).toEqual([
      'firewall',
      'endpoint',
    ]);
  });

  it('defaults to an empty list when omitted', () => {
    expect(vendor({}).portfolio).toEqual([]);
  });

  it('rejects a category that does not exist', () => {
    // A typo here would silently render N/A over a category that has data.
    expect(() => vendor({ portfolio: ['firewal'] })).toThrow(ConfigError);
  });
});

describe('validateBundle portfolio consistency', () => {
  it('accepts a portfolio that covers every product category', () => {
    expect(() =>
      validateBundle([vendor({ portfolio: ['firewall', 'endpoint'] })], [product('firewall')]),
    ).not.toThrow();
  });

  it('rejects a product in a category the vendor never declared', () => {
    // Without this the site would print "N/A — does not compete here" over a
    // category we hold CVEs for, which is a worse claim than the 0 it replaced.
    expect(() =>
      validateBundle([vendor({ portfolio: ['firewall'] })], [product('endpoint')]),
    ).toThrow(/portfolio/);
  });

  it('names both the product and the vendor file it must be fixed in', () => {
    expect(() =>
      validateBundle([vendor({ portfolio: ['firewall'] })], [product('endpoint')]),
    ).toThrow(/acme-thing[\s\S]*vendors\/acme\.yaml/);
  });

  it('leaves a vendor with NO portfolio alone', () => {
    // The safety property the whole feature rests on: an absent portfolio means
    // "not declared", not "competes in nothing". A vendor added without one must
    // keep behaving exactly as it did before this existed — otherwise adding a
    // fifth vendor silently marks all fifteen categories N/A.
    expect(() => validateBundle([vendor({})], [product('web-app-security')])).not.toThrow();
  });
});
