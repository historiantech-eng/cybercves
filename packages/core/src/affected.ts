import type { NormalizedAffected, NormalizedVersionRange } from './types.js';

/**
 * Whether the vendor says this product is actually affected.
 *
 * `unknown` is not a hedge between the two — it is the overwhelmingly common
 * case, and it means "the record does not say". See `affectedStatus`.
 */
export type AffectedStatus = 'affected' | 'unaffected' | 'unknown';

/** The shape this rule needs, so DB rows can be tested without a full normalize. */
export interface AffectedStatusInput {
  versions: readonly Pick<NormalizedVersionRange, 'status'>[];
  /** True when more ranges existed upstream than we stored. */
  versionsTruncated?: boolean;
  defaultStatus: string | null;
}

/**
 * Read the CVE 5.x affected-status of one `affected[]` entry.
 *
 * The CVE record format does not list only affected products. An `affected[]`
 * entry is a *statement about* a product, and `defaultStatus: "unaffected"` with
 * `versions: [{ version: "All", status: "unaffected" }]` is the vendor saying,
 * on the record, that this product is NOT vulnerable. Palo Alto publishes a full
 * product matrix on every advisory and uses exactly that shape, so treating
 * membership in `affected[]` as evidence of vulnerability credits them with bugs
 * their own advisory says they do not have.
 *
 * The rule, in the spec's own terms: `defaultStatus` sets the baseline and the
 * `versions[]` entries are the exceptions to it. So a single version marked
 * `affected` makes the product affected no matter what the baseline says, and a
 * baseline of `unaffected` with no such exception means it is not.
 *
 * Absence of a statement is NOT a statement of absence. Most CNAs never populate
 * these fields — 1,972 of 3,062 entries here are `unknown` or missing — so
 * anything short of an explicit "unaffected" returns `unknown`, and callers are
 * expected to treat `unknown` as affected. Requiring proof of affectedness would
 * silently delete most of the dataset.
 */
export function affectedStatus(entry: AffectedStatusInput): AffectedStatus {
  const baseline = entry.defaultStatus?.trim().toLowerCase() ?? null;

  for (const version of entry.versions) {
    const status = version.status?.trim().toLowerCase();
    // An explicit affected range overrides any baseline.
    if (status === 'affected') return 'affected';
  }

  if (baseline === 'affected') return 'affected';

  if (baseline === 'unaffected') {
    // We cap stored ranges (see MAX_VERSION_RANGES), so on a truncated list the
    // affected exception may be one we never stored. Refuse to conclude
    // "unaffected" from evidence we know to be partial — dropping a real
    // vulnerability is far worse than keeping a spurious one.
    return entry.versionsTruncated ? 'unknown' : 'unaffected';
  }

  // No baseline, but every range the vendor did list says unaffected.
  if (
    entry.versions.length > 0 &&
    !entry.versionsTruncated &&
    entry.versions.every((v) => v.status?.trim().toLowerCase() === 'unaffected')
  ) {
    return 'unaffected';
  }

  return 'unknown';
}

/**
 * Should this entry count as evidence that the product is vulnerable?
 *
 * `unknown` counts. See `affectedStatus` for why that asymmetry is deliberate.
 */
export function isAffectedEntry(entry: AffectedStatusInput): boolean {
  return affectedStatus(entry) !== 'unaffected';
}

/**
 * The entries of one CVE that may be attributed to a product.
 *
 * Drops explicitly-unaffected entries, but ONLY when some other entry on the
 * same CVE is affected. That condition is the whole safety argument.
 *
 * A record where every entry is "unaffected" describes a vulnerability in
 * nothing, which is a contradiction — the CVE exists. In practice it means the
 * vendor mis-stated their own record, and two live examples show both shapes:
 *
 *   CVE-2025-4235   Palo Alto's User-ID Credential Agent, whose description
 *                   states the flaw plainly while its one version range is
 *                   marked `unaffected` — an inverted status field.
 *   CVE-2026-20188  Cisco naming only Crosswork Network Change Automation, a
 *                   product the entry then marks unaffected, while the title
 *                   names two others that are never listed at all.
 *
 * Believing those records literally would strike a real vulnerability off the
 * only product it is attached to. So when the CVE offers no affected entry to
 * corroborate the exclusions, nothing is dropped and behaviour is exactly as it
 * was before this rule existed.
 *
 * The converse — at least one entry affected — is the vendor demonstrating on
 * that same record that they use the status fields correctly. Their "unaffected"
 * is then a deliberate statement and is honoured. That is the published product
 * matrix this rule exists to read: Palo Alto lists Cloud NGFW and Prisma Access
 * on nearly every PAN-OS advisory purely to say they are safe.
 */
export function resolvableEntries(
  entries: readonly NormalizedAffected[],
): NormalizedAffected[] {
  const kept = entries.filter((entry) => isAffectedEntry(entry));
  if (kept.length === entries.length) return kept;

  const corroborated = entries.some((entry) => affectedStatus(entry) === 'affected');
  return corroborated ? kept : [...entries];
}
