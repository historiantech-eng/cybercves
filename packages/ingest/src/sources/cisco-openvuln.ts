import type { VendorAdvisory } from '@cybercves/core';
import { HttpError, USER_AGENT } from '../http.js';

/**
 * Cisco PSIRT openVuln API.
 *
 * The CVE List already carries Cisco's affected releases and discovery field.
 * What it does not carry is the advisory those CVEs were published under: the
 * cisco-sa-* id, Cisco's own Security Impact Rating, the bug IDs that TAC and
 * the Bug Search Tool key on, and whether the advisory has since been revised.
 * One openVuln advisory routinely covers several CVEs, and a reader who has one
 * CVE in hand usually wants the advisory.
 *
 * OAuth2 client credentials, registered at apiconsole.cisco.com. The id and
 * secret come from the environment (CISCO_CLIENT_ID / CISCO_CLIENT_SECRET) and
 * are passed in by the caller — nothing here reads `process.env`, so this runs
 * in the Worker or a test as well as in Node.
 *
 * Shapes below were captured live on 2026-10-01.
 */

/** Cisco's published limits: 5 calls a second, 30 a minute, 5,000 a day. */
export const OPENVULN_MIN_GAP_MS = 2_100;

/** One advisory as openVuln returns it. Absent values come back as the string "NA". */
interface RawAdvisory {
  advisoryId?: string;
  advisoryTitle?: string;
  bugIDs?: string[];
  cves?: string[];
  cvssBaseScore?: string;
  firstPublished?: string;
  lastUpdated?: string;
  publicationUrl?: string;
  sir?: string;
  status?: string;
  version?: string;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** openVuln's placeholder for "no value". Read as absent, never stored. */
const present = (value: string | undefined | null): string | null => {
  const trimmed = value?.trim();
  return trimmed && trimmed.toUpperCase() !== 'NA' ? trimmed : null;
};

export function parseOpenVulnAdvisory(raw: RawAdvisory): VendorAdvisory | null {
  const advisoryId = present(raw.advisoryId);
  const url = present(raw.publicationUrl);
  if (!advisoryId || !url) return null;

  const score = Number.parseFloat(present(raw.cvssBaseScore) ?? '');
  return {
    advisoryId,
    url,
    title: present(raw.advisoryTitle),
    published: present(raw.firstPublished),
    lastUpdated: present(raw.lastUpdated),
    revision: present(raw.version),
    status: present(raw.status),
    severity: present(raw.sir),
    cvssBaseScore: Number.isFinite(score) ? score : null,
    // Filtered by shape, not just for "NA": a malformed id in either list would
    // otherwise become a broken Bug Search link or a link to a CVE that is not one.
    bugIds: (raw.bugIDs ?? []).map((b) => b.trim()).filter((b) => /^CSC[a-z]{2}\d{5}$/i.test(b)),
    cveIds: (raw.cves ?? []).map((c) => c.trim().toUpperCase()).filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c)),
  };
}

export interface OpenVulnCredentials {
  clientId: string;
  clientSecret: string;
}

export interface OpenVulnOptions {
  tokenUrl: string;
  baseUrl: string;
  credentials: OpenVulnCredentials;
  /** Injected by tests. */
  fetchFn?: typeof fetch;
  /** Gap between API calls. Tests pass 0. */
  minGapMs?: number;
  retries?: number;
  timeoutMs?: number;
}

/**
 * A small authenticated client: one token, paced requests, one re-auth on 401.
 *
 * Paced rather than parallel because the limit that bites is 30 a minute, and a
 * nightly build that trips it would lose Cisco's advisories for the day.
 */
export class OpenVulnClient {
  readonly #opts: Required<Omit<OpenVulnOptions, 'credentials'>> & { credentials: OpenVulnCredentials };
  #token: string | null = null;
  #lastCall = 0;
  calls = 0;

  constructor(options: OpenVulnOptions) {
    this.#opts = {
      fetchFn: (input, init) => fetch(input, init),
      minGapMs: OPENVULN_MIN_GAP_MS,
      retries: 3,
      timeoutMs: 60_000,
      ...options,
      baseUrl: options.baseUrl.replace(/\/+$/, ''),
    };
  }

  async #pace(): Promise<void> {
    const wait = this.#lastCall + this.#opts.minGapMs - Date.now();
    if (wait > 0) await sleep(wait);
    this.#lastCall = Date.now();
    this.calls++;
  }

  async #authenticate(): Promise<string> {
    const { tokenUrl, credentials, fetchFn, timeoutMs } = this.#opts;
    const response = await fetchFn(tokenUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
        'user-agent': USER_AGENT,
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: credentials.clientId,
        client_secret: credentials.clientSecret,
      }).toString(),
      signal: AbortSignal.timeout(timeoutMs),
    });
    // The URL only, never the body: an OAuth error body can echo the client id.
    if (!response.ok) throw new HttpError(response.status, tokenUrl);
    const body = (await response.json()) as { access_token?: string };
    if (!body.access_token) throw new Error(`no access_token in response from ${tokenUrl}`);
    this.#token = body.access_token;
    return this.#token;
  }

  /**
   * GET a path under the API root. Returns null for openVuln's "no data" 404,
   * which is how it answers a date range with no advisories in it.
   */
  async get<T>(path: string): Promise<T | null> {
    const { baseUrl, fetchFn, retries, timeoutMs } = this.#opts;
    const url = `${baseUrl}/${path.replace(/^\/+/, '')}`;
    let reauthed = false;
    let lastError: unknown;

    for (let attempt = 0; attempt <= retries; attempt++) {
      if (attempt > 0) await sleep(Math.min(2 ** attempt * 1_000, 15_000));
      const token = this.#token ?? (await this.#authenticate());
      await this.#pace();

      let response: Response;
      try {
        response = await fetchFn(url, {
          headers: { authorization: `Bearer ${token}`, accept: 'application/json', 'user-agent': USER_AGENT },
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch (err) {
        lastError = err;
        continue;
      }

      if (response.ok) return (await response.json()) as T;

      if (response.status === 401 && !reauthed) {
        // Tokens last an hour; a long run can outlive one. Re-auth once, and
        // only once, so bad credentials fail fast instead of looping.
        reauthed = true;
        this.#token = null;
        attempt--;
        continue;
      }
      if (response.status === 404) {
        const body = (await response.text()).toUpperCase();
        if (body.includes('NO_DATA_FOUND')) return null;
        throw new HttpError(404, url);
      }
      if (response.status === 429 || response.status >= 500) {
        lastError = new HttpError(response.status, url);
        continue;
      }
      throw new HttpError(response.status, url);
    }
    throw lastError instanceof Error ? lastError : new Error(`failed to fetch ${url}`);
  }
}

/** YYYY-MM-DD in UTC. */
const isoDay = (d: Date) => d.toISOString().slice(0, 10);

/**
 * Every Cisco advisory first published from `fromYear` to today.
 *
 * One request per calendar year. Any advisory whose CVEs we track was first
 * published no earlier than the CVE List years the build ingests, so the same
 * `--from` bounds both. Notices that carry no CVE (the advance-publication
 * notices, for one) are dropped: an advisory row with nothing to join to is
 * dead weight in a table pushed to D1.
 */
export async function fetchCiscoAdvisories(
  client: OpenVulnClient,
  fromYear: number,
  now = new Date(),
): Promise<VendorAdvisory[]> {
  const byId = new Map<string, VendorAdvisory>();
  const thisYear = now.getUTCFullYear();

  for (let year = fromYear; year <= thisYear; year++) {
    const end = year === thisYear ? isoDay(now) : `${year}-12-31`;
    const body = await client.get<{ advisories?: RawAdvisory[] }>(
      `all/firstpublished?startDate=${year}-01-01&endDate=${end}`,
    );
    for (const raw of body?.advisories ?? []) {
      const advisory = parseOpenVulnAdvisory(raw);
      if (advisory && advisory.cveIds.length) byId.set(advisory.advisoryId, advisory);
    }
  }
  return [...byId.values()];
}
