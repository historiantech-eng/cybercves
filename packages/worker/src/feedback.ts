/**
 * Validation and abuse checks for reader-submitted corrections.
 *
 * Pure and platform-free so it can be tested without a Worker runtime — the same
 * reason core/ and db/ import no Cloudflare APIs. The route in index.ts does IO;
 * every decision about whether a submission is acceptable is made here.
 */

export const FEEDBACK_KINDS = [
  'wrong-category',
  'wrong-vendor',
  'wrong-discovery',
  'missing-cve',
  'other',
] as const;

export type FeedbackKind = (typeof FEEDBACK_KINDS)[number];

/** Caps chosen to be generous for a human and hostile to a script. */
export const LIMITS = {
  body: { min: 10, max: 4_000 },
  evidenceUrl: 500,
  email: 254,
  pageUrl: 300,
} as const;

export interface FeedbackInput {
  kind?: unknown;
  body?: unknown;
  cveId?: unknown;
  pageUrl?: unknown;
  evidenceUrl?: unknown;
  email?: unknown;
  /** Honeypot. A real browser leaves it empty; most bots fill every field. */
  website?: unknown;
}

export interface CleanFeedback {
  kind: FeedbackKind;
  body: string;
  cveId: string | null;
  pageUrl: string | null;
  evidenceUrl: string | null;
  reporterEmail: string | null;
}

export type Validation =
  | { ok: true; value: CleanFeedback }
  /**
   * `silent` means: answer as though it worked, store nothing. Reserved for the
   * honeypot — telling a bot precisely which check caught it is free tuning
   * information, and a human never trips this one.
   */
  | { ok: false; error: string; silent?: true };

const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

/** Same shape the rest of the codebase uses for CVE ids. */
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

/**
 * Deliberately loose. Email validation by regex is a well-known tar pit, and the
 * address is optional and only ever used to reply — so the cost of accepting a
 * malformed one is that a reply bounces, while the cost of rejecting a valid
 * unusual address is losing a correction.
 */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validateFeedback(input: FeedbackInput): Validation {
  if (str(input.website)) return { ok: false, error: 'rejected', silent: true };

  const kind = str(input.kind) as FeedbackKind;
  if (!FEEDBACK_KINDS.includes(kind)) {
    return { ok: false, error: 'Choose what kind of problem you are reporting.' };
  }

  const body = str(input.body);
  if (body.length < LIMITS.body.min) {
    return { ok: false, error: 'Please describe the problem in a sentence or two.' };
  }
  if (body.length > LIMITS.body.max) {
    return { ok: false, error: `Please keep it under ${LIMITS.body.max} characters.` };
  }

  const rawCve = str(input.cveId);
  if (rawCve && !CVE_RE.test(rawCve)) {
    return { ok: false, error: 'That does not look like a CVE ID (CVE-2026-0259).' };
  }

  const evidenceUrl = str(input.evidenceUrl);
  if (evidenceUrl) {
    if (evidenceUrl.length > LIMITS.evidenceUrl) {
      return { ok: false, error: 'That link is too long.' };
    }
    // Anything but http(s) is either useless as evidence or an attempt to store
    // a javascript:/data: payload for whoever reads the triage queue later.
    let parsed: URL;
    try {
      parsed = new URL(evidenceUrl);
    } catch {
      return { ok: false, error: 'That link is not a valid URL.' };
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return { ok: false, error: 'Links must start with http:// or https://.' };
    }
  }

  const email = str(input.email);
  if (email && (email.length > LIMITS.email || !EMAIL_RE.test(email))) {
    return { ok: false, error: 'That email address does not look right.' };
  }

  return {
    ok: true,
    value: {
      kind,
      body,
      cveId: rawCve ? rawCve.toUpperCase() : null,
      pageUrl: normalizePageUrl(str(input.pageUrl)),
      evidenceUrl: evidenceUrl || null,
      reporterEmail: email || null,
    },
  };
}

/**
 * Keep only the path of a same-site page reference.
 *
 * This is context we captured ourselves, not something a reporter typed, so the
 * only thing it should ever be is a path on this site. Storing whatever arrives
 * would let a submitter plant an arbitrary link in the triage queue.
 */
export function normalizePageUrl(value: string): string | null {
  if (!value) return null;
  const path = value.startsWith('/') ? value : safePath(value);
  if (!path) return null;
  return path.length > LIMITS.pageUrl ? path.slice(0, LIMITS.pageUrl) : path;
}

function safePath(value: string): string | null {
  try {
    const url = new URL(value);
    return url.hostname.endsWith('cybercve.com') ? url.pathname + url.search : null;
  } catch {
    return null;
  }
}

/**
 * Salted hash of the client address.
 *
 * Enough to notice one source flooding the form; not a log of who reads the
 * site. The salt is a Worker secret, so the stored column is useless without it,
 * and rotating the salt retires every existing hash.
 */
export async function hashIp(ip: string, salt: string): Promise<string> {
  const data = new TextEncoder().encode(`${salt}:${ip}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)]
    .slice(0, 16)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Cloudflare Turnstile server-side verification.
 *
 * Returns false when unconfigured rather than true: an unverified form is the
 * failure we are trying to avoid, so a missing secret must close the form, not
 * open it.
 */
export async function verifyTurnstile(
  token: string,
  secret: string | undefined,
  remoteIp?: string,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  if (!secret || !token) return false;
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  if (remoteIp) form.append('remoteip', remoteIp);

  try {
    const res = await fetchImpl('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form,
    });
    if (!res.ok) return false;
    const body = (await res.json()) as { success?: boolean };
    return body.success === true;
  } catch {
    return false;
  }
}

/** Plain-text alert body. Kept here so its content is testable alongside the rules. */
export function alertText(id: number, entry: CleanFeedback): string {
  return [
    `New CyberCVE feedback #${id}`,
    '',
    `Kind:  ${entry.kind}`,
    entry.cveId ? `CVE:   ${entry.cveId}` : null,
    entry.pageUrl ? `Page:  https://cybercve.com${entry.pageUrl}` : null,
    entry.evidenceUrl ? `Link:  ${entry.evidenceUrl}` : null,
    entry.reporterEmail ? `From:  ${entry.reporterEmail}` : 'From:  (anonymous)',
    '',
    entry.body,
    '',
    '-- ',
    'Triage:  npm run feedback -- --status new',
  ]
    .filter((line) => line !== null)
    .join('\n');
}
