/**
 * Should "last: CVE-…" be a link?
 *
 * The hero counter polls KV every two minutes; the site rebuilds every three
 * hours. Between those two clocks there is a window where the counter knows
 * about a CVE that has no static page yet, and `/cve/<unbuilt-id>` falls through
 * to the JSON API — so linking it would land a reader on raw JSON.
 *
 * The build records which id it rendered. If the live answer still matches, the
 * page exists and the id links. If it has moved on, show the id as plain text
 * until the next rebuild catches up: naming the right CVE without a link beats
 * naming the wrong one with a working link, and beats a link to JSON.
 *
 * Pure so it can be tested without a DOM — the caller does the element swap.
 */
export type LatestLink =
  | { kind: 'link'; id: string; href: string }
  | { kind: 'text'; id: string }
  | { kind: 'unchanged' };

export function latestLinkState(
  liveId: string | null | undefined,
  serverId: string | null | undefined,
  shownId: string | null | undefined,
): LatestLink {
  // A poll that returns nothing must never blank what is already on screen.
  if (!liveId) return { kind: 'unchanged' };
  if (liveId === shownId?.trim()) return { kind: 'unchanged' };
  return liveId === serverId
    ? { kind: 'link', id: liveId, href: `/cve/${liveId}` }
    : { kind: 'text', id: liveId };
}
