import { resolvableEntries } from './affected.js';
import { parseCpe } from './cpe.js';
import type {
  MatchSignal,
  NormalizedCve,
  ProductConfig,
  ResolvedProduct,
  UnmappedProduct,
  VendorConfig,
} from './types.js';

/**
 * Signal strength, strongest first. When several signals point at the same
 * vendor we keep the strongest, so the stored `match_signal` says how confidently
 * a CVE was attributed rather than which check happened to run last.
 */
const SIGNAL_RANK: Readonly<Record<MatchSignal, number>> = {
  'cna-assigner': 0,
  'affected-vendor': 1,
  cpe: 2,
  'reference-host': 3,
};

/**
 * Fold a raw vendor/product string into a comparable key: lowercase, strip
 * trademark marks and punctuation, collapse whitespace. "FortiOS®" and
 * "fortios" must land on the same key.
 */
export function normalizeKey(value: string): string {
  return value
    .toLowerCase()
    .replace(/[®™℠]/g, '')
    .replace(/[_/]/g, ' ')
    .replace(/[^a-z0-9+.\- ]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export class TaxonomyResolver {
  readonly #vendors = new Map<string, VendorConfig>();
  readonly #byCna = new Map<string, string>();
  readonly #byAlias = new Map<string, string>();
  readonly #byHost = new Map<string, string>();

  readonly #products = new Map<string, ProductConfig>();

  /**
   * Product lookup, indexed three ways by how much we know about the entry:
   *
   *   `cisco`          every Cisco product — used when the entry names no
   *                    vendor at all and its own name is the only evidence
   *   `cisco::`        only the products carrying no brand, i.e. Cisco's own
   *   `cisco::splunk`  only the products of the Splunk brand
   *
   * The narrowest scope the entry supports wins. Keeping them separate is what
   * stops a Cisco entry reaching Splunk's deliberately bare patterns ('^cloud$')
   * and a Splunk entry reaching Cisco's ('\bwebex\b').
   */
  readonly #aliases = new Map<string, Map<string, string>>();
  /** Same keys; compiled patterns, evaluated only when no alias matches. */
  readonly #patterns = new Map<string, Array<{ re: RegExp; slug: string }>>();
  /**
   * `vendorSlug::<normalized spelling>` -> the brand's canonical key, for every
   * spelling the vendor declares. This is what turns the raw vendor string on an
   * affected-entry into the scope its products are looked up in.
   */
  readonly #brandOfSpelling = new Map<string, string>();
  /** `vendorSlug::brandKey` -> the product that catches the brand's long tail. */
  readonly #brandFallback = new Map<string, string>();

  constructor(vendors: readonly VendorConfig[], products: readonly ProductConfig[]) {
    for (const vendor of vendors) {
      this.#vendors.set(vendor.slug, vendor);
      for (const cna of vendor.cnaShortNames) this.#byCna.set(cna.toLowerCase(), vendor.slug);
      for (const alias of vendor.aliases) this.#byAlias.set(normalizeKey(alias), vendor.slug);
      for (const host of vendor.psirtHosts) this.#byHost.set(host.toLowerCase(), vendor.slug);

      for (const [name, spellings] of Object.entries(vendor.brands ?? {})) {
        const key = normalizeKey(name);
        for (const spelling of spellings) {
          this.#brandOfSpelling.set(`${vendor.slug}::${normalizeKey(spelling)}`, key);
        }
      }
    }

    for (const product of products) {
      this.#products.set(product.slug, product);

      const brand = product.brand ? normalizeKey(product.brand) : '';
      // The vendor-wide scope holds everything; the second scope is the brand's,
      // or the vendor's own when the product carries no brand.
      const scopes = [product.vendorSlug, `${product.vendorSlug}::${brand}`];

      for (const scope of scopes) {
        let aliases = this.#aliases.get(scope);
        if (!aliases) {
          aliases = new Map();
          this.#aliases.set(scope, aliases);
        }
        aliases.set(normalizeKey(product.name), product.slug);
        for (const alias of product.aliases) aliases.set(normalizeKey(alias), product.slug);

        if (product.patterns.length) {
          let patterns = this.#patterns.get(scope);
          if (!patterns) {
            patterns = [];
            this.#patterns.set(scope, patterns);
          }
          for (const source of product.patterns) {
            patterns.push({ re: new RegExp(source, 'i'), slug: product.slug });
          }
        }
      }

      if (brand && product.brandFallback) {
        this.#brandFallback.set(`${product.vendorSlug}::${brand}`, product.slug);
      }
    }
  }

  getVendor(slug: string): VendorConfig | undefined {
    return this.#vendors.get(slug);
  }

  getProduct(slug: string): ProductConfig | undefined {
    return this.#products.get(slug);
  }

  /**
   * Attribute a CVE to vendors using all three signals from the plan.
   *
   * The CNA assigner alone is not sufficient: researchers routinely file through
   * MITRE or another CNA for bugs in a vendor's product, and those CVEs would be
   * silently undercounted if we only trusted the assigner field.
   */
  matchVendors(cve: NormalizedCve): Map<string, MatchSignal> {
    const matches = new Map<string, MatchSignal>();
    // A product the vendor says is unaffected is not evidence that the CVE is
    // theirs, so it must not raise the vendor either — otherwise a CVE excluded
    // from every one of our products still counts against the vendor's total.
    const entries = resolvableEntries(cve.affected);

    const record = (slug: string | undefined, signal: MatchSignal) => {
      if (!slug) return;
      const existing = matches.get(slug);
      if (existing === undefined || SIGNAL_RANK[signal] < SIGNAL_RANK[existing]) {
        matches.set(slug, signal);
      }
    };

    if (cve.assignerShortName) {
      record(this.#byCna.get(cve.assignerShortName), 'cna-assigner');
    }

    for (const affected of entries) {
      if (affected.vendorRaw) {
        record(this.#byAlias.get(normalizeKey(affected.vendorRaw)), 'affected-vendor');
      }
      for (const cpe of affected.cpes) {
        const parsed = parseCpe(cpe);
        if (parsed?.vendor) record(this.#byAlias.get(normalizeKey(parsed.vendor)), 'cpe');
      }
    }

    for (const ref of cve.references) {
      const host = hostOf(ref.url);
      if (host) record(this.#byHost.get(host), 'reference-host');
    }

    return matches;
  }

  /**
   * Map one raw product string to a canonical product slug for a known vendor.
   *
   * `vendorRaw` is the vendor string the affected-entry itself carried. When it
   * names a brand we track separately under this vendor — "Splunk" under Cisco —
   * only that brand's products are considered. Splunk ships SOAR connectors
   * named after other companies ("Cisco Webex app for Splunk SOAR"), and the
   * vendor-wide index matched those on the borrowed name, filing a Splunk
   * connector bug as a Cisco Webex vulnerability.
   */
  resolveProductName(
    vendorSlug: string,
    productRaw: string,
    vendorRaw?: string | null,
  ): string | null {
    const key = normalizeKey(productRaw);
    if (!key) return null;

    // With a vendor string in hand the search narrows: to the acquired brand's
    // products when it names one, otherwise to the vendor's own. Only an entry
    // that names no vendor at all searches everything, because there the
    // product name is the only evidence available.
    const brand = vendorRaw
      ? (this.#brandOfSpelling.get(`${vendorSlug}::${normalizeKey(vendorRaw)}`) ?? '')
      : null;
    const scope = brand === null ? vendorSlug : `${vendorSlug}::${brand}`;

    const exact = this.#aliases.get(scope)?.get(key);
    if (exact) return exact;

    for (const { re, slug } of this.#patterns.get(scope) ?? []) {
      if (re.test(key)) return slug;
    }

    // Deliberately no widening on a miss: a string this brand does not
    // recognise is not one of the parent vendor's products either.
    return this.#brandFallback.get(scope) ?? null;
  }

  /**
   * Resolve a CVE into canonical (vendor, product, category) rows.
   *
   * Anything we cannot map is returned separately rather than dropped — unmapped
   * strings are the input to the AI suggestion pass and the human review queue,
   * and silently discarding them is how a taxonomy quietly rots.
   */
  resolve(cve: NormalizedCve): {
    resolved: ResolvedProduct[];
    unmapped: UnmappedProduct[];
    /** Returned so callers need not recompute it — matching parses every reference URL. */
    vendors: Map<string, MatchSignal>;
  } {
    const vendorMatches = this.matchVendors(cve);
    // Entries the vendor's own record marks unaffected are excluded here, so a
    // published product matrix cannot credit a product with a bug the advisory
    // says it does not have. See resolvableEntries for the corroboration rule.
    const entries = resolvableEntries(cve.affected);
    const resolved = new Map<string, ResolvedProduct>();
    const unmapped = new Map<string, UnmappedProduct>();
    // Entries naming a company we do not know, held back until we know whether
    // this CVE was attributed by some other entry — see below.
    const foreign = new Map<string, UnmappedProduct>();

    for (const [vendorSlug, matchSignal] of vendorMatches) {
      for (const affected of entries) {
        // Candidate product names for this affected entry: the free-text product
        // plus any CPE product components, which are often cleaner.
        const candidates: string[] = [];
        if (affected.productRaw) candidates.push(affected.productRaw);
        for (const cpe of affected.cpes) {
          const parsed = parseCpe(cpe);
          if (parsed?.product) candidates.push(parsed.product);
        }
        if (!candidates.length) continue;

        // Only attribute this entry to the vendor if the entry itself points at
        // them; otherwise a multi-vendor CVE would assign every product to every
        // matched vendor.
        if (!this.#entryBelongsTo(vendorSlug, affected, matchSignal)) {
          // An entry naming a vendor we have never heard of, on a CVE the vendor
          // assigned through their own CNA, is what an acquisition looks like
          // before anyone adds the alias — Cisco issued 69 CVEs naming "Splunk"
          // and every one resolved to nothing. Queue it for review rather than
          // dropping it: the entry is deliberately NOT attributed, because a
          // CNA occasionally assigns for a genuine third party, but a gap this
          // shaped must never again be invisible.
          if (
            matchSignal === 'cna-assigner' &&
            affected.vendorRaw &&
            affected.productRaw &&
            !this.#byAlias.has(normalizeKey(affected.vendorRaw))
          ) {
            foreign.set(`${vendorSlug}::${normalizeKey(affected.productRaw)}`, {
              vendorRaw: affected.vendorRaw,
              productRaw: affected.productRaw,
              vendorSlug,
            });
          }
          continue;
        }

        // The brand the entry names, not the vendor it rolls up to — see
        // resolveProductName for why the distinction decides the product.
        const entryVendor = affected.vendorRaw ?? this.#cpeVendorOf(affected);

        let hit = false;
        for (const candidate of candidates) {
          const productSlug = this.resolveProductName(vendorSlug, candidate, entryVendor);
          if (!productSlug) continue;
          const product = this.#products.get(productSlug);
          if (!product) continue;
          resolved.set(productSlug, {
            productSlug,
            vendorSlug,
            categorySlug: product.categorySlug,
            matchSignal,
          });
          hit = true;
          break;
        }

        if (!hit && affected.productRaw) {
          const key = `${vendorSlug}::${normalizeKey(affected.productRaw)}`;
          unmapped.set(key, {
            vendorRaw: affected.vendorRaw,
            productRaw: affected.productRaw,
            vendorSlug,
          });
        }
      }
    }

    // A foreign-vendor entry only matters when nothing else claimed this CVE.
    //
    // If the CVE is already attributed, the foreign entry is a re-listing, not a
    // gap: Siemens ships RUGGEDCOM APE1808 running FortiOS, so 41 Fortinet CVEs
    // carry a second affected[] entry naming Siemens. All 41 are already counted
    // via their FortiOS entry, yet "RUGGEDCOM APE1808" sat at the top of the
    // review queue at 40 hits — the single largest item, and permanently
    // unactionable, because Siemens is a genuine third party rather than an
    // acquisition waiting for an alias.
    //
    // When nothing claimed the CVE the entry still queues, which is what caught
    // Splunk under Cisco and CyberArk under Palo Alto. That is the case worth a
    // human's attention: a CVE we hold and count nowhere.
    if (!resolved.size) for (const [key, entry] of foreign) unmapped.set(key, entry);

    return {
      resolved: [...resolved.values()],
      unmapped: [...unmapped.values()],
      vendors: vendorMatches,
    };
  }

  /**
   * Does this specific affected-entry belong to the given vendor?
   *
   * When the entry names a vendor or carries a CPE, trust that. When it carries
   * neither, fall back to the CVE-level attribution — but only if that came from
   * the CNA assigner, the one signal strong enough to speak for an unlabelled entry.
   */
  #entryBelongsTo(
    vendorSlug: string,
    affected: NormalizedCve['affected'][number],
    matchSignal: MatchSignal,
  ): boolean {
    if (affected.vendorRaw) {
      return this.#byAlias.get(normalizeKey(affected.vendorRaw)) === vendorSlug;
    }
    const cpeVendor = this.#cpeVendorOf(affected);
    if (cpeVendor) return this.#byAlias.get(normalizeKey(cpeVendor)) === vendorSlug;
    return matchSignal === 'cna-assigner';
  }

  /** The vendor component of the entry's first parseable CPE, if it has one. */
  #cpeVendorOf(affected: NormalizedCve['affected'][number]): string | null {
    for (const cpe of affected.cpes) {
      const parsed = parseCpe(cpe);
      if (parsed?.vendor) return parsed.vendor;
    }
    return null;
  }
}
