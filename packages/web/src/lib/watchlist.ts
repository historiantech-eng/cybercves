/**
 * "My stack": the products a reader has chosen to watch.
 *
 * Stored in the reader's own browser and nowhere else. There are no accounts,
 * nothing is sent to the Worker, and /privacy says so — which is also why this
 * costs nothing on the free plan: a watchlist is a filter over the same static
 * year shards every other page reads.
 *
 * Storage can be missing or throw (private windows, blocked site data, some
 * embedded viewers), so every access is guarded and a failure degrades to "no
 * watchlist" rather than a broken page. Storage is injectable so the rules below
 * can be tested without a browser.
 */

export const WATCH_KEY = 'cybercve:watch:v1';
/** Per-tab marker that this session has already rolled the visit clock. */
export const SESSION_KEY = 'cybercve:watch:session';
/** Fired on `window` after any change, so every control on the page can resync. */
export const CHANGE_EVENT = 'watchlist:change';

export interface Watchlist {
  products: string[];
  /** When the reader last started a session here, ISO-8601. */
  lastVisit: string | null;
  /**
   * The visit before that — the "new since" line. Fixed for the whole session,
   * so markers do not vanish as the reader clicks from page to page.
   */
  prevVisit: string | null;
}

type KeyValueStore = Pick<Storage, 'getItem' | 'setItem'>;

const EMPTY: Watchlist = { products: [], lastVisit: null, prevVisit: null };

function browserStore(kind: 'local' | 'session'): KeyValueStore | null {
  try {
    return kind === 'local' ? globalThis.localStorage : globalThis.sessionStorage;
  } catch {
    return null;
  }
}

const isIso = (value: unknown): value is string =>
  typeof value === 'string' && !Number.isNaN(Date.parse(value));

export function load(storage: KeyValueStore | null = browserStore('local')): Watchlist {
  try {
    const raw = storage?.getItem(WATCH_KEY);
    if (!raw) return { ...EMPTY };
    const parsed = JSON.parse(raw) as Partial<Watchlist>;
    // Validate rather than trust: this is whatever the browser kept, possibly
    // from an older version of this code or edited by hand.
    const products = Array.isArray(parsed.products)
      ? [...new Set(parsed.products.filter((p): p is string => typeof p === 'string' && p !== ''))]
      : [];
    return {
      products,
      lastVisit: isIso(parsed.lastVisit) ? parsed.lastVisit : null,
      prevVisit: isIso(parsed.prevVisit) ? parsed.prevVisit : null,
    };
  } catch {
    return { ...EMPTY };
  }
}

/** Returns false when the browser refused the write, so callers can say so. */
export function save(list: Watchlist, storage: KeyValueStore | null = browserStore('local')): boolean {
  try {
    if (!storage) return false;
    storage.setItem(WATCH_KEY, JSON.stringify(list));
    return true;
  } catch {
    return false;
  }
}

/** Flip one product. Returns whether it is now watched, or null if nothing was saved. */
export function toggle(
  slug: string,
  storage: KeyValueStore | null = browserStore('local'),
): boolean | null {
  const list = load(storage);
  const watched = list.products.includes(slug);
  list.products = watched ? list.products.filter((p) => p !== slug) : [...list.products, slug];
  if (!save(list, storage)) return null;
  globalThis.dispatchEvent?.(new CustomEvent(CHANGE_EVENT, { detail: list }));
  return !watched;
}

/**
 * Record a visit, at most once per browser session.
 *
 * The first page view of a session moves `lastVisit` into `prevVisit` and
 * stamps now; every later view in the same session changes nothing. Without the
 * session guard, the second page a reader opened would already count the first
 * as their "last visit" and every New marker would disappear.
 */
export function markVisit(
  now: Date = new Date(),
  local: KeyValueStore | null = browserStore('local'),
  session: KeyValueStore | null = browserStore('session'),
): Watchlist {
  const list = load(local);
  try {
    if (session?.getItem(SESSION_KEY)) return list;
    session?.setItem(SESSION_KEY, '1');
  } catch {
    // No session storage: treat every view as a fresh session. Markers then
    // reset per page, which is the honest degradation — never a wrong count.
  }
  const next = { ...list, prevVisit: list.lastVisit, lastVisit: now.toISOString() };
  // Only persist for readers who watch something — a visit clock for someone
  // with an empty list is data kept for no reason.
  if (next.products.length) save(next, local);
  return next.products.length ? next : list;
}

/**
 * Is a CVE published on `day` (YYYY-MM-DD) new since the previous visit?
 *
 * Compared by calendar day, inclusive: rows carry a date, not a time, so a CVE
 * published later on the same day as the last visit would otherwise never be
 * marked. Over-marking one day's worth is the safe side of that trade.
 */
export function isNewSince(day: string | null, prevVisit: string | null): boolean {
  if (!day || !prevVisit) return false;
  return day >= prevVisit.slice(0, 10);
}
