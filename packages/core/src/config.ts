import type { Category, ProductConfig, VendorConfig } from './types.js';

/**
 * Validation for the YAML config in /data, kept pure so it runs in the Worker,
 * in Node, and in tests. Callers supply already-parsed objects; file reading and
 * YAML parsing live in @cybercves/ingest.
 *
 * Every failure throws with the offending path. A typo in a vendor's CNA short
 * name would otherwise cause silent undercounting that is very hard to notice
 * later — better to refuse to start.
 */

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function requireString(value: unknown, path: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new ConfigError(`${path}: expected a non-empty string`);
  }
  return value.trim();
}

function optionalString(value: unknown, path: string): string | null {
  if (value === undefined || value === null) return null;
  return requireString(value, path);
}

function requireSlug(value: unknown, path: string): string {
  const slug = requireString(value, path);
  if (!SLUG_RE.test(slug)) {
    throw new ConfigError(`${path}: "${slug}" is not a valid slug (lowercase, digits, hyphens)`);
  }
  return slug;
}

function stringArray(value: unknown, path: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new ConfigError(`${path}: expected an array of strings`);
  return value.map((entry, i) => requireString(entry, `${path}[${i}]`));
}

export interface CategoryConfig extends Category {
  /** False for portfolio products outside the security line (routing, collaboration). */
  security: boolean;
}

export function parseCategories(raw: unknown): CategoryConfig[] {
  const list = (raw as { categories?: unknown })?.categories;
  if (!Array.isArray(list)) throw new ConfigError('categories.yaml: missing `categories` array');

  const seen = new Set<string>();
  return list.map((entry, i) => {
    const path = `categories[${i}]`;
    const obj = entry as Record<string, unknown>;
    const slug = requireSlug(obj.slug, `${path}.slug`);
    if (seen.has(slug)) throw new ConfigError(`${path}.slug: duplicate category "${slug}"`);
    seen.add(slug);

    return {
      slug,
      name: requireString(obj.name, `${path}.name`),
      description: optionalString(obj.description, `${path}.description`) ?? '',
      sort: typeof obj.sort === 'number' ? obj.sort : 999,
      security: obj.security !== false,
    };
  });
}

export interface VendorFileConfig extends VendorConfig {
  rssUrl: string | null;
  jsonUrlTemplate: string | null;
  advisoryIdPattern: string | null;
  /** Brands the vendor's own security org publishes under (FortiGuard, Talos, Unit 42). */
  internalBrandMarkers: string[];
  /** Where this vendor publishes discovery attribution, shown when we have none. */
  discoveryNote: string | null;
}

/**
 * `brands:` is a map of canonical brand name -> every spelling upstream uses.
 * Every spelling must be listed: matching is exact, as it is for vendor aliases,
 * because a fuzzy rule cannot know that "Idira" is CyberArk.
 */
function parseBrands(value: unknown, path: string): Record<string, string[]> {
  if (value === undefined || value === null) return {};
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new ConfigError(`${path}: expected a map of brand name to spellings`);
  }
  const out: Record<string, string[]> = {};
  for (const [name, spellings] of Object.entries(value as Record<string, unknown>)) {
    const list = stringArray(spellings, `${path}.${name}`);
    if (!list.length) throw new ConfigError(`${path}.${name}: needs at least one spelling`);
    // The canonical name must itself be matchable, or a product declaring
    // `brand: Splunk` would scope to a key no entry can ever reach.
    out[name] = list.includes(name) ? list : [name, ...list];
  }
  return out;
}

const ADAPTERS = new Set(['cvelist', 'json', 'csaf', 'rss', 'scrape']);

export function parseVendor(raw: unknown, sourcePath: string): VendorFileConfig {
  const obj = raw as Record<string, unknown>;
  const slug = requireSlug(obj.slug, `${sourcePath}.slug`);

  const adapter = optionalString(obj.adapter, `${sourcePath}.adapter`) ?? 'cvelist';
  if (!ADAPTERS.has(adapter)) {
    throw new ConfigError(
      `${sourcePath}.adapter: "${adapter}" is not one of ${[...ADAPTERS].join(', ')}`,
    );
  }

  const cnaShortNames = stringArray(obj.cnaShortNames, `${sourcePath}.cnaShortNames`);
  const aliases = stringArray(obj.aliases, `${sourcePath}.aliases`);
  const brands = parseBrands(obj.brands, `${sourcePath}.brands`);
  // A brand's spellings are vendor aliases as well: a CVE naming "Splunk" is
  // Cisco's. Folding them in here means the two lists cannot drift apart.
  for (const spellings of Object.values(brands)) aliases.push(...spellings);
  if (!cnaShortNames.length && !aliases.length) {
    throw new ConfigError(
      `${sourcePath}: needs at least one cnaShortName or alias, or its CVEs can never be matched`,
    );
  }

  return {
    slug,
    name: requireString(obj.name, `${sourcePath}.name`),
    cnaShortNames: cnaShortNames.map((n) => n.toLowerCase()),
    aliases,
    brands,
    psirtHosts: stringArray(obj.psirtHosts, `${sourcePath}.psirtHosts`).map((h) => h.toLowerCase()),
    psirtUrl: optionalString(obj.psirtUrl, `${sourcePath}.psirtUrl`),
    homepage: optionalString(obj.homepage, `${sourcePath}.homepage`),
    adapter: adapter as VendorConfig['adapter'],
    rssUrl: optionalString(obj.rssUrl, `${sourcePath}.rssUrl`),
    jsonUrlTemplate: optionalString(obj.jsonUrlTemplate, `${sourcePath}.jsonUrlTemplate`),
    advisoryIdPattern: optionalString(obj.advisoryIdPattern, `${sourcePath}.advisoryIdPattern`),
    internalBrandMarkers: stringArray(
      obj.internalBrandMarkers,
      `${sourcePath}.internalBrandMarkers`,
    ),
    discoveryNote: optionalString(obj.discoveryNote, `${sourcePath}.discoveryNote`),
  };
}

export function parseProducts(
  raw: unknown,
  sourcePath: string,
  knownCategories: ReadonlySet<string>,
): ProductConfig[] {
  const obj = raw as Record<string, unknown>;
  const vendorSlug = requireSlug(obj.vendorSlug, `${sourcePath}.vendorSlug`);
  const list = obj.products;
  if (!Array.isArray(list)) throw new ConfigError(`${sourcePath}: missing \`products\` array`);

  return list.map((entry, i) => {
    const path = `${sourcePath}.products[${i}]`;
    const item = entry as Record<string, unknown>;
    const categorySlug = requireSlug(item.categorySlug, `${path}.categorySlug`);
    if (!knownCategories.has(categorySlug)) {
      throw new ConfigError(`${path}.categorySlug: unknown category "${categorySlug}"`);
    }

    const brand = optionalString(item.brand, `${path}.brand`);
    const brandFallback = item.brandFallback === true;
    if (brandFallback && !brand) {
      throw new ConfigError(`${path}.brandFallback: only meaningful alongside a \`brand\``);
    }

    const patterns = stringArray(item.patterns, `${path}.patterns`);
    for (const [j, source] of patterns.entries()) {
      try {
        new RegExp(source, 'i');
      } catch (err) {
        throw new ConfigError(`${path}.patterns[${j}]: invalid regex — ${(err as Error).message}`);
      }
    }

    return {
      slug: requireSlug(item.slug, `${path}.slug`),
      vendorSlug,
      name: requireString(item.name, `${path}.name`),
      categorySlug,
      aliases: stringArray(item.aliases, `${path}.aliases`),
      patterns,
      brand,
      brandFallback,
    };
  });
}

/** Cross-file checks that individual parsers cannot see. */
export function validateBundle(
  vendors: readonly VendorFileConfig[],
  products: readonly ProductConfig[],
): void {
  const vendorSlugs = new Set(vendors.map((v) => v.slug));
  const productSlugs = new Set<string>();
  const cnaOwners = new Map<string, string>();
  const brandsByVendor = new Map(vendors.map((v) => [v.slug, new Set(Object.keys(v.brands))]));

  for (const vendor of vendors) {
    for (const cna of vendor.cnaShortNames) {
      const existing = cnaOwners.get(cna);
      if (existing && existing !== vendor.slug) {
        throw new ConfigError(
          `CNA short name "${cna}" is claimed by both "${existing}" and "${vendor.slug}"`,
        );
      }
      cnaOwners.set(cna, vendor.slug);
    }
  }

  for (const product of products) {
    if (!vendorSlugs.has(product.vendorSlug)) {
      throw new ConfigError(`product "${product.slug}": unknown vendor "${product.vendorSlug}"`);
    }
    if (productSlugs.has(product.slug)) {
      throw new ConfigError(`duplicate product slug "${product.slug}"`);
    }
    productSlugs.add(product.slug);

    // A brand the vendor never declared is a scope no affected-entry can reach,
    // so the product would silently match nothing at all — the exact failure
    // mode this whole mechanism exists to prevent.
    if (product.brand && !brandsByVendor.get(product.vendorSlug)?.has(product.brand)) {
      throw new ConfigError(
        `product "${product.slug}": brand "${product.brand}" is not declared under ` +
          `\`brands\` in vendors/${product.vendorSlug}.yaml`,
      );
    }
  }

  // Two products cannot both catch a brand's long tail; which one won would
  // depend on file order.
  const fallbacks = new Map<string, string>();
  for (const product of products) {
    if (!product.brandFallback || !product.brand) continue;
    const key = `${product.vendorSlug}::${product.brand}`;
    const existing = fallbacks.get(key);
    if (existing) {
      throw new ConfigError(
        `brand "${product.brand}" has two fallbacks: "${existing}" and "${product.slug}"`,
      );
    }
    fallbacks.set(key, product.slug);
  }
}
