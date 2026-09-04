/**
 * Reading applicability statements out of a CVE's prose description.
 *
 * Some vendors state which of their products a flaw applies to in the
 * description rather than in `affected[]`. Palo Alto is the clearest case:
 * Panorama runs PAN-OS, so every Panorama advisory lists the product as
 * "PAN-OS" and names Panorama only in a sentence —
 *
 *   "This issue is applicable to PAN-OS software on PA-Series and VM-Series
 *    firewalls and on Panorama (virtual and M-Series)."
 *
 * Read literally, the structured record says "firewall" and nothing else, which
 * is why Palo Alto showed zero CVEs under Network & Security Management while
 * ten 2026 advisories applied to their management platform.
 *
 * The naive fix — search the description for the product name — is wrong, and
 * measurably so. Of the 29 CVEs in this corpus whose description mentions
 * Panorama, 14 mention it only to say it is NOT affected ("Panorama, Cloud NGFW,
 * and Prisma Access are not impacted by this vulnerability"), which is exactly
 * what a reader filtering Palo Alto's PSIRT page on "Panorama" sees. One more,
 * CVE-2024-5920, names a "Panorama administrator" as the *attacker* while the
 * vulnerable component is a PAN-OS node. A substring match gets 15 of 29 wrong.
 *
 * So matching happens per sentence, and a sentence that denies is not evidence
 * that affirms. The patterns themselves are declared per product in
 * data/products/*.yaml (`descriptionPatterns`) rather than derived from the
 * product name, because a name is not a claim: "Cisco IOS Software" appears in
 * 214 descriptions that are really about IOS XE or IOS XR. Opt-in keeps that
 * whole class of false positive impossible for any product that has not had a
 * human write a rule for it.
 */

/**
 * Split prose into sentences for independent judgement.
 *
 * Deliberately blunt: a terminator followed by whitespace or end-of-string,
 * plus hard line breaks and the `<br>` runs that Palo Alto's HTML rendering
 * uses instead of paragraphs. Vendor descriptions are plain declarative prose,
 * and the two failure modes are not symmetric — over-splitting shortens the
 * window and loses a match, while under-splitting carries a negation across a
 * boundary and asserts something the vendor denied. So err toward more splits.
 *
 * The lookbehind spares a period inside a version number, which is the only
 * abbreviation-shaped thing that actually occurs here: without it
 * "Upgrade to 11.1.16 or later" becomes three fragments.
 */
export function sentences(text: string): string[] {
  return text
    .split(/(?<!\d)[.!?]+(?=\s|$)|[\n\r]+|(?:<br\s*\/?>)+/i)
    // A split on `<br>` leaves the terminator attached to the piece before it.
    .map((s) => s.replace(/^[\s.!?]+|[\s.!?]+$/g, ''))
    .filter(Boolean);
}

/**
 * Does this sentence deny that something is affected?
 *
 * Every phrasing here is one the corpus actually uses. "No action needed" is
 * included because Palo Alto's solution tables say only that against the
 * products they consider safe.
 */
const EXCLUSION =
  /\b(?:not\s+(?:impacted|affected|vulnerable)|does\s+not\s+(?:affect|impact|apply)|do\s+not\s+(?:affect|impact|apply)|are\s+unaffected|is\s+unaffected|no\s+action\s+(?:is\s+)?needed|not\s+applicable)\b/i;

export function isExclusion(sentence: string): boolean {
  return EXCLUSION.test(sentence);
}

/**
 * Does this sentence exist to state which products something applies to?
 *
 * Used only by the review tooling, never by ingest. The point is to find the
 * NEXT product with Panorama's problem — stated in prose, absent from
 * `affected[]` — without re-reading every description by hand. Restricting the
 * search to sentences shaped like an applicability statement is what makes the
 * output small enough to read: across this corpus, "applicable to" appears in
 * 13 records, whereas a bare product-name search over all descriptions returns
 * hundreds, nearly all of them "Cisco IOS Software" inside a sentence about
 * IOS XE.
 */
const APPLICABILITY =
  /\b(?:is|are)\s+(?:only\s+)?applicable\s+to\b|\bapplies\s+(?:only\s+)?to\b|\bthis\s+(?:issue|vulnerability|advisory)\s+affects\b/i;

export function statesApplicability(sentence: string): boolean {
  return APPLICABILITY.test(sentence) && !isExclusion(sentence);
}

/** One product's claim on a description. */
export interface DescriptionRule {
  productSlug: string;
  /**
   * Narrow, human-written patterns (`descriptionPatterns` in the YAML) that
   * decide whether a sentence AFFIRMS this product. Narrow because a false
   * affirmation publishes a vulnerability against the wrong product.
   */
  affirm: readonly RegExp[];
  /**
   * Broad patterns that decide whether a sentence DENIES this product, built
   * from its name and aliases by `denyPatterns`. Broad on purpose: the two
   * directions are not symmetric. A denial we miss lets a false claim stand,
   * while a denial we over-read only declines to add a product — which is the
   * behaviour that already existed. So the affirming side is conservative and
   * the denying side is generous.
   */
  deny: readonly RegExp[];
}

/**
 * The denial patterns for a product, from every spelling we know it by.
 *
 * Shared by the resolver and its tests so the two cannot drift. Spellings
 * shorter than four characters are skipped — an alias like "IDP" or "PAM"
 * matches far too much English to be safe even in the generous direction.
 */
export function denyPatterns(spellings: readonly string[]): RegExp[] {
  const out: RegExp[] = [];
  for (const spelling of spellings) {
    if (spelling.trim().length < 4) continue;
    const source = spelling
      .trim()
      .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      // Upstream writes the same name spaced, hyphenated, or with a trademark
      // mark wedged in: "Prisma® Access", "Global Protect", "PAN-OS".
      .replace(/[-\s]+/g, '[-\\s]*(?:[®™℠])?[-\\s]*');
    out.push(new RegExp(`\\b${source}\\b`, 'i'));
  }
  return out;
}

/**
 * Which products a description affirmatively claims.
 *
 * A product is returned when some sentence matches one of its patterns and no
 * sentence that matches it denies it. The denial wins on a contradiction: the
 * result of believing it is that we leave the product off, which is exactly the
 * behaviour before this rule existed, whereas the result of ignoring it is
 * publishing a vulnerability against a product the vendor says is safe.
 *
 * This only ever ADDS products. A description is never allowed to remove a link
 * that `affected[]` established — the structured record is the stronger
 * statement, and CVE-2024-2433 shows why: the flaw is described as being "in
 * Palo Alto Networks Panorama software" while the vendor's own matrix lists
 * PAN-OS. Both are true of an appliance that runs PAN-OS, and dropping either
 * would lose a real result.
 */
export function productsInDescription(
  description: string | null | undefined,
  rules: readonly DescriptionRule[],
): Set<string> {
  const claimed = new Set<string>();
  const denied = new Set<string>();
  if (!description || !rules.length) return claimed;

  for (const sentence of sentences(description)) {
    if (isExclusion(sentence)) {
      for (const rule of rules) {
        if (rule.deny.some((re) => re.test(sentence))) denied.add(rule.productSlug);
      }
      continue;
    }
    for (const rule of rules) {
      if (rule.affirm.some((re) => re.test(sentence))) claimed.add(rule.productSlug);
    }
  }

  for (const slug of denied) claimed.delete(slug);
  return claimed;
}
