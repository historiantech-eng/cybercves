import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import type { CategoryConfig, ProductConfig, VendorFileConfig } from '@cybercves/core';
import { TaxonomyResolver, parseCategories, parseProducts, parseVendor, validateBundle } from '@cybercves/core';

/**
 * Loads the /data YAML. Node-only (uses node:fs), which is why it lives under
 * ./node — the Worker reads the same taxonomy back out of D1 instead.
 */

const DEFAULT_DATA_DIR = fileURLToPath(new URL('../../../../data/', import.meta.url));

export interface LoadedConfig {
  categories: CategoryConfig[];
  vendors: VendorFileConfig[];
  products: ProductConfig[];
  resolver: TaxonomyResolver;
}

export function loadConfig(dataDir = DEFAULT_DATA_DIR): LoadedConfig {
  const read = (relative: string): unknown =>
    parseYaml(readFileSync(join(dataDir, relative), 'utf8'));

  const categories = parseCategories(read('categories.yaml'));
  const categorySlugs = new Set(categories.map((c) => c.slug));

  const vendors = readdirSync(join(dataDir, 'vendors'))
    .filter((file) => file.endsWith('.yaml'))
    .map((file) => parseVendor(read(join('vendors', file)), `vendors/${file}`));

  const products = readdirSync(join(dataDir, 'products'))
    .filter((file) => file.endsWith('.yaml'))
    .flatMap((file) => parseProducts(read(join('products', file)), `products/${file}`, categorySlugs));

  // Cross-file checks: duplicate slugs, a CNA claimed by two vendors, a product
  // pointing at a vendor that does not exist.
  validateBundle(vendors, products);

  return { categories, vendors, products, resolver: new TaxonomyResolver(vendors, products) };
}
