import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  OpenVulnClient,
  fetchCiscoAdvisories,
  parseOpenVulnAdvisory,
} from '../src/sources/cisco-openvuln.js';
import { describeCiscoOutcome, enrichCiscoAdvisories, openVulnCredentialsFrom } from '../src/cisco-advisories.js';

/** Real openVuln /latest/5 response, captured 2026-10-01, productNames and summary trimmed. */
const latest = JSON.parse(
  readFileSync(fileURLToPath(new URL('./fixtures/cisco-openvuln-latest5.json', import.meta.url)), 'utf8'),
) as { advisories: Array<Record<string, unknown>> };

const byId = (id: string) => latest.advisories.find((a) => a.advisoryId === id)!;

const TOKEN_URL = 'https://id.example/token';
const BASE = 'https://api.example/v2';
const CREDS = { clientId: 'id', clientSecret: 'secret' };

/** A scripted fetch: token endpoint plus a queue of API answers, recording what was asked. */
function scripted(api: Array<() => Response>) {
  const seen: string[] = [];
  let tokens = 0;
  const fetchFn = (async (input: string | URL | Request) => {
    const url = String(input);
    seen.push(url);
    if (url === TOKEN_URL) {
      tokens++;
      return Response.json({ access_token: `tok${tokens}`, token_type: 'Bearer', expires_in: 3600 });
    }
    const next = api.shift();
    if (!next) throw new Error(`unexpected request ${url}`);
    return next();
  }) as typeof fetch;
  return { fetchFn, seen, tokens: () => tokens };
}

const client = (fetchFn: typeof fetch) =>
  new OpenVulnClient({ tokenUrl: TOKEN_URL, baseUrl: BASE, credentials: CREDS, fetchFn, minGapMs: 0, retries: 2 });

describe('parseOpenVulnAdvisory', () => {
  it('reads a real advisory', () => {
    expect(parseOpenVulnAdvisory(byId('cisco-sa-asaftdvirtual-dos-MuenGnYR'))).toEqual({
      advisoryId: 'cisco-sa-asaftdvirtual-dos-MuenGnYR',
      url: 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftdvirtual-dos-MuenGnYR',
      title:
        'Cisco Secure Firewall Adaptive Security Appliance and Secure Firewall Threat Defense Software SSL VPN Denial of Service Vulnerability',
      published: '2024-10-23T16:00:00',
      lastUpdated: '2026-09-23T13:26:33',
      revision: '2.1',
      status: 'Final',
      severity: 'High',
      cvssBaseScore: 8.6,
      bugIds: ['CSCwe44099', 'CSCwk12738', 'CSCwr18877', 'CSCwu02508'],
      cveIds: ['CVE-2024-20260'],
    });
  });

  it('reads "NA" as absent, never as a value', () => {
    // The advance-publication notice: no CVE, no bug, no score.
    const notice = parseOpenVulnAdvisory(byId('cisco-sa-notice-fBn58ELx'))!;
    expect(notice.cveIds).toEqual([]);
    expect(notice.bugIds).toEqual([]);
    expect(notice.cvssBaseScore).toBeNull();
    expect(notice.status).toBe('Interim');
  });

  it('rejects an advisory with no id or no URL', () => {
    expect(parseOpenVulnAdvisory({ advisoryId: 'NA', publicationUrl: 'https://x' })).toBeNull();
    expect(parseOpenVulnAdvisory({ advisoryId: 'cisco-sa-x' })).toBeNull();
  });
});

describe('OpenVulnClient', () => {
  it('authenticates once and sends the bearer token', async () => {
    const auths: string[] = [];
    const { fetchFn, tokens } = scripted([() => Response.json({ advisories: [] }), () => Response.json({ advisories: [] })]);
    const wrapped = (async (input: string | URL | Request, init?: RequestInit) => {
      const h = new Headers(init?.headers);
      if (h.get('authorization')) auths.push(h.get('authorization')!);
      return fetchFn(input, init);
    }) as typeof fetch;
    const c = client(wrapped);
    await c.get('latest/1');
    await c.get('latest/1');
    expect(tokens()).toBe(1);
    expect(auths).toEqual(['Bearer tok1', 'Bearer tok1']);
  });

  it('re-authenticates once on 401, then gives up', async () => {
    const ok = scripted([() => new Response('', { status: 401 }), () => Response.json({ advisories: [1] })]);
    expect(await client(ok.fetchFn).get('latest/1')).toEqual({ advisories: [1] });
    expect(ok.tokens()).toBe(2);

    const bad = scripted([() => new Response('', { status: 401 }), () => new Response('', { status: 401 })]);
    await expect(client(bad.fetchFn).get('latest/1')).rejects.toThrow(/HTTP 401/);
  });

  it('treats openVuln’s NO_DATA_FOUND 404 as an empty answer, and any other 404 as an error', async () => {
    const empty = scripted([
      () => new Response('{"errorCode":"NO_DATA_FOUND","errorMessage":"No data found"}', { status: 404 }),
    ]);
    expect(await client(empty.fetchFn).get('all/firstpublished?x')).toBeNull();

    const missing = scripted([() => new Response('not here', { status: 404 })]);
    await expect(client(missing.fetchFn).get('nope')).rejects.toThrow(/HTTP 404/);
  });

  it('retries a rate limit', async () => {
    const s = scripted([() => new Response('', { status: 429 }), () => Response.json({ advisories: [] })]);
    expect(await client(s.fetchFn).get('latest/1')).toEqual({ advisories: [] });
  });
});

describe('fetchCiscoAdvisories', () => {
  it('asks for one calendar year per request, up to today, and drops CVE-less notices', async () => {
    const s = scripted([
      () => Response.json({ advisories: [byId('cisco-sa-asaftdvirtual-dos-MuenGnYR')] }),
      () => new Response('{"errorCode":"NO_DATA_FOUND"}', { status: 404 }),
      () => Response.json({ advisories: latest.advisories }),
    ]);
    const got = await fetchCiscoAdvisories(client(s.fetchFn), 2024, new Date('2026-10-01T12:00:00Z'));

    expect(s.seen.filter((u) => u.startsWith(BASE))).toEqual([
      `${BASE}/all/firstpublished?startDate=2024-01-01&endDate=2024-12-31`,
      `${BASE}/all/firstpublished?startDate=2025-01-01&endDate=2025-12-31`,
      `${BASE}/all/firstpublished?startDate=2026-01-01&endDate=2026-10-01`,
    ]);
    // Five in the fixture, one is the notice, one appears in two years: four unique.
    expect(got.map((a) => a.advisoryId).sort()).toEqual([
      'cisco-sa-asa-ftd-logging-dos-ZXXNesfN',
      'cisco-sa-asaftdvirtual-dos-MuenGnYR',
      'cisco-sa-ise-multiauth-bypass-sgD2HbL4',
      'cisco-sa-sdwan-webauth-xr8beuuU',
    ]);
  });
});

describe('enrichCiscoAdvisories', () => {
  const vendor = {
    slug: 'cisco',
    openVulnTokenUrl: TOKEN_URL,
    openVulnBaseUrl: BASE,
  } as Parameters<typeof enrichCiscoAdvisories>[1];
  const fakeRepo = (calls: unknown[]) =>
    ({
      replaceVendorAdvisories: async (slug: string, advisories: unknown[]) => {
        calls.push([slug, advisories.length]);
        return { advisories: advisories.length, links: advisories.length };
      },
    }) as unknown as Parameters<typeof enrichCiscoAdvisories>[0];

  it('skips without credentials, touching nothing', async () => {
    const calls: unknown[] = [];
    const out = await enrichCiscoAdvisories(fakeRepo(calls), vendor, null, 2024);
    expect(out.status).toBe('skipped');
    expect(calls).toEqual([]);
  });

  it('reports a failed pull without throwing, and without emptying the table', async () => {
    const calls: unknown[] = [];
    const s = scripted([() => new Response('', { status: 503 }), () => new Response('', { status: 503 }), () => new Response('', { status: 503 }), () => new Response('', { status: 503 })]);
    const out = await enrichCiscoAdvisories(fakeRepo(calls), vendor, CREDS, 2026, {
      fetchFn: s.fetchFn,
      minGapMs: 0,
      now: new Date('2026-10-01T00:00:00Z'),
    });
    expect(out.status).toBe('failed');
    expect(calls).toEqual([]);
    expect(describeCiscoOutcome(out, true)).toMatch(/^::warning title=Cisco openVuln::/);
  }, 20_000);

  it('refuses to replace with an empty pull', async () => {
    const calls: unknown[] = [];
    const s = scripted([() => new Response('{"errorCode":"NO_DATA_FOUND"}', { status: 404 })]);
    const out = await enrichCiscoAdvisories(fakeRepo(calls), vendor, CREDS, 2026, {
      fetchFn: s.fetchFn,
      minGapMs: 0,
      now: new Date('2026-10-01T00:00:00Z'),
    });
    expect(out.status).toBe('failed');
    expect(calls).toEqual([]);
  });

  it('stores a successful pull', async () => {
    const calls: unknown[] = [];
    const s = scripted([() => Response.json({ advisories: latest.advisories })]);
    const out = await enrichCiscoAdvisories(fakeRepo(calls), vendor, CREDS, 2026, {
      fetchFn: s.fetchFn,
      minGapMs: 0,
      now: new Date('2026-10-01T00:00:00Z'),
    });
    expect(out).toMatchObject({ status: 'ok', fetched: 4, calls: 1 });
    expect(calls).toEqual([['cisco', 4]]);
  });
});

describe('openVulnCredentialsFrom', () => {
  it('needs both values', () => {
    expect(openVulnCredentialsFrom({ CISCO_CLIENT_ID: 'a' })).toBeNull();
    expect(openVulnCredentialsFrom({ CISCO_CLIENT_ID: ' ', CISCO_CLIENT_SECRET: 'b' })).toBeNull();
    expect(openVulnCredentialsFrom({ CISCO_CLIENT_ID: 'a', CISCO_CLIENT_SECRET: 'b' })).toEqual({
      clientId: 'a',
      clientSecret: 'b',
    });
  });
});
