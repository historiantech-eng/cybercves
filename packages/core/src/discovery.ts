import type { CveRecord } from './cve-schema.js';

/**
 * Who found the vulnerability — the vendor's own team, or someone else.
 *
 * This is the honest counterweight to raw CVE counts. A vendor that finds and
 * discloses its own bugs is doing something materially different from one whose
 * bugs are found by outsiders, and volume alone cannot tell those apart.
 *
 * Values mirror the CVE Record Format's `containers.cna.source.discovery`:
 *   INTERNAL — the vendor's own security team
 *   EXTERNAL — an outside researcher or organization
 *   USER     — a customer using the product
 *   UNKNOWN  — the CNA explicitly recorded that it does not know
 *   null     — the vendor published nothing on the subject
 *
 * UNKNOWN and null are deliberately distinct: "we don't know" is a disclosure,
 * "we said nothing" is not.
 */
export type Discovery = 'INTERNAL' | 'EXTERNAL' | 'USER' | 'UNKNOWN';

/**
 * How we determined the value — stored so the claim is auditable, exactly like
 * vendor match signals. A scraped classification is weaker evidence than a field
 * the vendor published in a machine-readable feed, and the site says which it is.
 */
export type DiscoverySource = 'cna-source' | 'psirt-acknowledgement' | 'psirt-field';

const VALID: ReadonlySet<string> = new Set(['INTERNAL', 'EXTERNAL', 'USER', 'UNKNOWN']);

/**
 * How a discovery source is described to a reader.
 *
 * Lives here rather than in the templates because the CVE page and
 * /methodology both render it, and a source whose strength is described one way
 * on the detail page and another on the methodology page is worse than one that
 * is not described at all. `strength` is deliberately blunt: this is the field
 * that tells someone whether to trust the label above it.
 */
export function discoverySourceLabel(source: DiscoverySource | string | null | undefined): {
  label: string;
  strength: string;
} {
  switch (source) {
    case 'cna-source':
      return {
        label: 'Vendor-published field',
        strength: 'Machine-readable, published by the vendor in the CVE record.',
      };
    case 'psirt-field':
      return {
        label: 'Vendor advisory field',
        strength:
          'The labelled “Discovered” value on the vendor’s own advisory page — published by the vendor, but read from HTML rather than a feed.',
      };
    case 'psirt-acknowledgement':
      return {
        label: 'Vendor advisory acknowledgement',
        strength:
          'Read from the advisory page and classified by rule. Weakest of the three — the raw text is shown on every CVE page so you can judge it yourself.',
      };
    default:
      return { label: 'Unknown source', strength: 'Not recorded.' };
  }
}

export interface DiscoveryResult {
  discovery: Discovery | null;
  source: DiscoverySource | null;
  /** Free-text credit/acknowledgement, shown on the CVE page so readers can judge. */
  creditText: string | null;
}

/**
 * Read the canonical discovery field.
 *
 * Populated by Cisco and Palo Alto on most records. Fortinet publishes nothing
 * here at all, which is why the PSIRT acknowledgement scraper exists — see
 * classifyAcknowledgement.
 */
export function extractDiscovery(record: CveRecord): DiscoveryResult {
  const cna = record.containers?.cna;
  const raw = cna?.source?.discovery?.trim().toUpperCase();
  const discovery = raw && VALID.has(raw) ? (raw as Discovery) : null;

  // Prefer an explicit finder credit; fall back to any credit with text.
  const credits = cna?.credits ?? [];
  const finder = credits.find((c) => c.type?.toLowerCase() === 'finder' && c.value?.trim());
  const anyCredit = credits.find((c) => c.value?.trim());
  const creditText = (finder?.value ?? anyCredit?.value)?.trim() || null;

  return {
    discovery,
    source: discovery ? 'cna-source' : null,
    creditText,
  };
}

/**
 * Read Fortinet's own "Discovered" field.
 *
 * Every FortiGuard PSIRT advisory carries a labelled row —
 * `<td>Discovered</td><td>Internal</td>` — with three observed values:
 * Internal, External, and Third-Party Library. This is a field the vendor
 * publishes, not a heuristic over prose, which is why it outranks
 * `classifyAcknowledgement` and gets its own `psirt-field` source.
 *
 * **Third-Party Library maps to EXTERNAL.** The label describes a flaw in a
 * bundled upstream component, reaching Fortinet through someone else's
 * advisory. It is mutually exclusive with Internal in Fortinet's own taxonomy,
 * so the one thing it certainly is not is "Fortinet's security team found this"
 * — and that is the only question this measure asks. The raw label is kept in
 * `creditText` so the CVE page shows what Fortinet actually published and a
 * reader can disagree with the folding.
 *
 * An unrecognised label returns null. A fourth value appearing later must be
 * classified deliberately, not swept into EXTERNAL by a default branch.
 */
export function classifyPsirtDiscovered(label: string | null | undefined): DiscoveryResult {
  const key = label?.trim().toLowerCase().replace(/[^a-z]+/g, '');
  if (!key) return { discovery: null, source: null, creditText: null };

  const discovery: Discovery | null =
    key === 'internal'
      ? 'INTERNAL'
      : key === 'external' || key === 'thirdpartylibrary'
        ? 'EXTERNAL'
        : null;

  if (!discovery) return { discovery: null, source: null, creditText: null };
  return { discovery, source: 'psirt-field', creditText: label!.trim() };
}

/**
 * Classify a vendor PSIRT acknowledgement string.
 *
 * Used where a vendor publishes credit in prose but not in a structured field.
 * The rule is deliberately simple and conservative: an acknowledgement that
 * attributes the find to the vendor's own security organisation is INTERNAL;
 * anything else that names a finder is EXTERNAL; anything unrecognised returns
 * null rather than a guess.
 *
 * The raw text is always stored alongside the verdict so a reader can disagree
 * with the classification — this is a heuristic over prose, not a published fact,
 * and the site labels it as such.
 */
export function classifyAcknowledgement(
  text: string | null | undefined,
  vendorName: string,
  /**
   * Other names the vendor's own security organisation publishes under —
   * "FortiGuard" for Fortinet, "Talos" for Cisco. Configured per vendor in
   * data/vendors/*.yaml rather than hardcoded, because which brands are
   * in-house is vendor knowledge, not parser logic.
   */
  brandMarkers: readonly string[] = [],
): DiscoveryResult {
  const trimmed = text?.trim();
  if (!trimmed) return { discovery: null, source: null, creditText: null };

  const lower = trimmed.toLowerCase();

  // Explicit statements settle it outright.
  if (/\b(internally\s+(discovered|found|identified|reported)|(discovered|found)\s+internally)\b/i.test(trimmed)) {
    return { discovery: 'INTERNAL', source: 'psirt-acknowledgement', creditText: trimmed };
  }

  // Isolate the finder's own attribution — the text after "discovered/reported by".
  //
  // Only this clause may decide the verdict. Naming the vendor anywhere else in
  // the sentence is not evidence: "Reported by Jane Doe of Acme Labs TO Fortinet
  // PSIRT" credits an outsider, and reading the whole string would score it
  // INTERNAL and inflate the vendor's self-found rate — the worst error this
  // feature can make.
  const byClause = /\b(?:discovered|reported|found|identified|credited)\s+by\s+([\s\S]{0,220})/i.exec(
    trimmed,
  );
  if (!byClause?.[1]) {
    return { discovery: null, source: null, creditText: trimmed };
  }

  // Cut where the sentence stops describing the finder: a hand-off to the vendor
  // ("…to Fortinet PSIRT"), a rationale ("based on threat activity"), or a
  // semicolon.
  //
  // Deliberately NOT split on periods. A full stop is indistinguishable from the
  // period in an initial, and splitting there truncates "A. Researcher of
  // FortiGuard Labs" to "A" — losing the affiliation that decides the verdict.
  // The 220-character window above is what bounds the clause instead.
  const finder = byClause[1]
    .split(/\s+to\s+|\s+based\s+on\s+|\s+in\s+(?:coordination|collaboration)\s+|;/i)[0]
    ?.trim()
    .replace(/\.$/, '');
  if (!finder) return { discovery: null, source: null, creditText: trimmed };

  const finderKey = finder.toLowerCase().replace(/[^a-z0-9]+/g, '');

  // Vendor-employed finder: "… of Fortinet Product Security Team", "… of FortiGuard Labs".
  // Compared on a punctuation-stripped key so "FortiGuard" matches "Fortinet"'s
  // brand family without depending on spacing or hyphenation.
  const brands = [vendorName, ...brandMarkers];
  const affiliated = brands.some((brand) => {
    const key = brand.toLowerCase().replace(/[^a-z0-9]+/g, '');
    return (
      new RegExp(`\\b(?:of|from|at|with)\\s+[^,]{0,60}?${brand}`, 'i').test(finder) ||
      finderKey.includes(`${key}productsecurity`) ||
      finderKey.includes(`${key}psirt`) ||
      finderKey.includes(`${key}securityteam`) ||
      finderKey.includes(`${key}securityresearch`) ||
      finderKey.includes(`${key}labs`)
    );
  });

  if (affiliated) {
    return { discovery: 'INTERNAL', source: 'psirt-acknowledgement', creditText: trimmed };
  }

  // A named finder who is not the vendor.
  return { discovery: 'EXTERNAL', source: 'psirt-acknowledgement', creditText: trimmed };
}

/**
 * Share of disclosed CVEs the vendor found itself.
 *
 * The denominator counts only CVEs where discovery was actually disclosed.
 * Including undisclosed records would silently punish vendors for not publishing
 * the field, turning a transparency gap into a fake quality signal — the exact
 * error this whole feature exists to avoid.
 */
export function selfFoundRate(counts: {
  internal: number;
  external: number;
  user: number;
}): number | null {
  const disclosed = counts.internal + counts.external + counts.user;
  if (disclosed === 0) return null;
  return counts.internal / disclosed;
}
