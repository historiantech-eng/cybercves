/**
 * Which tables `push:d1` replaces, and — just as importantly — which it must not.
 *
 * This lives apart from the bin so it can be asserted on: the bin does work at
 * import time, so a test cannot load it without running a push.
 */

/**
 * Replaced wholesale on every push: truncated, then reinserted from the local
 * SQLite snapshot.
 *
 * Order matters — parents before children, because the schema declares real
 * foreign keys. Taxonomy first, then CVEs, then everything that references them.
 *
 * Every table here is DERIVED. It can be rebuilt at any time from the CVE List,
 * the KEV catalog, EPSS, and the committed taxonomy in /data. That is the only
 * reason destroying and recreating it nightly is safe.
 */
export const PUSHED_TABLES = [
  'category',
  'vendor',
  'product',
  'cve',
  'cve_affected',
  'cve_product',
  'kev',
  'epss',
  'advisory',
  'advisory_cve',
  'insight',
  'unmapped_product',
  'sync_state',
] as const;

/**
 * Tables that exist ONLY in D1 and have no upstream to be rebuilt from.
 *
 * Adding one of these to PUSHED_TABLES would delete every row on the next deploy
 * — silently, because the push would still succeed and the site would still look
 * correct. `feedback` holds reader-submitted corrections; `subscriber` holds
 * addresses people handed us. Neither can be regenerated from anything.
 *
 * A test asserts these two lists never intersect. If you are here because that
 * test failed, the fix is to leave the table out of PUSHED_TABLES, not to
 * shorten this list.
 */
export const NEVER_PUSHED_TABLES = ['feedback', 'subscriber'] as const;
