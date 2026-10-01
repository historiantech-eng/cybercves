import type { VendorFileConfig } from '@cybercves/core';
import type { Repository } from '@cybercves/db';
import { fetchCiscoAdvisories, OpenVulnClient, type OpenVulnCredentials } from './sources/cisco-openvuln.js';

export type CiscoEnrichOutcome =
  | { status: 'skipped'; reason: string }
  | { status: 'ok'; fetched: number; advisories: number; links: number; calls: number }
  | { status: 'failed'; error: string };

/**
 * Refresh Cisco's advisories from openVuln, if credentials were supplied.
 *
 * Never throws. This is an enrichment on top of data the CVE List already
 * gives us, and an openVuln outage at build time must not take the deploy down
 * with it — the CVE pages, /check and /priority are all correct without it.
 * The caller decides how loudly to report a failure.
 *
 * A failed pull leaves the table as it was rather than emptying it. In CI the
 * database is fresh, so "as it was" is empty and the site simply shows no
 * advisory panel that night; locally it keeps yesterday's rows.
 */
export async function enrichCiscoAdvisories(
  repo: Repository,
  vendor: VendorFileConfig | undefined,
  credentials: OpenVulnCredentials | null,
  fromYear: number,
  options: { fetchFn?: typeof fetch; minGapMs?: number; now?: Date } = {},
): Promise<CiscoEnrichOutcome> {
  if (!vendor?.openVulnTokenUrl || !vendor.openVulnBaseUrl) {
    return { status: 'skipped', reason: 'no openVuln endpoints in data/vendors/cisco.yaml' };
  }
  if (!credentials) {
    return { status: 'skipped', reason: 'CISCO_CLIENT_ID / CISCO_CLIENT_SECRET not set' };
  }

  const client = new OpenVulnClient({
    tokenUrl: vendor.openVulnTokenUrl,
    baseUrl: vendor.openVulnBaseUrl,
    credentials,
    ...(options.fetchFn ? { fetchFn: options.fetchFn } : {}),
    ...(options.minGapMs !== undefined ? { minGapMs: options.minGapMs } : {}),
  });

  try {
    const advisories = await fetchCiscoAdvisories(client, fromYear, options.now);
    // A successful pull that returned nothing is not plausible for Cisco — it
    // publishes every month — and replacing with it would wipe the table.
    if (!advisories.length) {
      return { status: 'failed', error: 'openVuln answered but returned no advisories' };
    }
    const written = await repo.replaceVendorAdvisories(vendor.slug, advisories);
    return { status: 'ok', fetched: advisories.length, ...written, calls: client.calls };
  } catch (err) {
    return { status: 'failed', error: (err as Error).message };
  }
}

/** Read credentials from an env-like map. Both or nothing. */
export function openVulnCredentialsFrom(env: Record<string, string | undefined>): OpenVulnCredentials | null {
  const clientId = env.CISCO_CLIENT_ID?.trim();
  const clientSecret = env.CISCO_CLIENT_SECRET?.trim();
  return clientId && clientSecret ? { clientId, clientSecret } : null;
}

/** One log line, plus a GitHub annotation when a configured pull fails. */
export function describeCiscoOutcome(outcome: CiscoEnrichOutcome, inActions: boolean): string {
  switch (outcome.status) {
    case 'skipped':
      return `cisco advisories: skipped — ${outcome.reason}`;
    case 'ok':
      return (
        `cisco advisories: ${outcome.advisories} stored of ${outcome.fetched} fetched, ` +
        `${outcome.links} CVE link(s), ${outcome.calls} openVuln call(s)`
      );
    case 'failed':
      // A warning, not an error: the build is still correct, just thinner.
      return (
        (inActions ? '::warning title=Cisco openVuln::' : '') +
        `cisco advisories: NOT refreshed — ${outcome.error}. ` +
        `The build continues without them; CVE data is unaffected.`
      );
  }
}
