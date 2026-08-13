import { describe, expect, it } from 'vitest';
import {
  LIMITS,
  alertText,
  normalizePageUrl,
  validateFeedback,
  verifyTurnstile,
} from '../src/feedback';

const valid = {
  kind: 'wrong-category',
  body: 'WildFire is a malware sandbox, not a firewall product.',
};

describe('validateFeedback', () => {
  it('accepts a well-formed correction', () => {
    const result = validateFeedback({ ...valid, cveId: 'cve-2026-0259' });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.cveId).toBe('CVE-2026-0259'); // normalized
      expect(result.value.reporterEmail).toBeNull();
    }
  });

  it('rejects a kind that is not on the list', () => {
    expect(validateFeedback({ ...valid, kind: 'sql-injection' }).ok).toBe(false);
  });

  it('rejects a body that is too short to act on', () => {
    expect(validateFeedback({ ...valid, body: 'wrong' }).ok).toBe(false);
  });

  it('rejects an oversized body', () => {
    const result = validateFeedback({ ...valid, body: 'x'.repeat(LIMITS.body.max + 1) });
    expect(result.ok).toBe(false);
  });

  it('answers 200-shaped success for the honeypot but stores nothing', () => {
    // Telling a bot which check caught it is free tuning information, and a
    // human never fills a hidden field.
    const result = validateFeedback({ ...valid, website: 'http://spam.example' });
    expect(result).toMatchObject({ ok: false, silent: true });
  });

  it('rejects a javascript: link rather than storing it for the operator to click', () => {
    const result = validateFeedback({ ...valid, evidenceUrl: 'javascript:alert(1)' });
    expect(result.ok).toBe(false);
  });

  it('rejects a malformed CVE id', () => {
    expect(validateFeedback({ ...valid, cveId: 'CVE-BOGUS' }).ok).toBe(false);
  });

  it('accepts an optional email and keeps it', () => {
    const result = validateFeedback({ ...valid, email: 'reporter@example.com' });
    expect(result.ok && result.value.reporterEmail).toBe('reporter@example.com');
  });

  it('rejects a malformed email instead of silently dropping the reply path', () => {
    expect(validateFeedback({ ...valid, email: 'not-an-email' }).ok).toBe(false);
  });
});

describe('normalizePageUrl', () => {
  it('keeps a same-site path', () => {
    expect(normalizePageUrl('/cve/CVE-2026-0259')).toBe('/cve/CVE-2026-0259');
  });

  it('reduces a same-site absolute URL to its path', () => {
    expect(normalizePageUrl('https://cybercve.com/vendors/fortinet')).toBe('/vendors/fortinet');
  });

  it('drops an off-site URL rather than planting a link in the triage queue', () => {
    // This field is context we captured, not something a reporter should be able
    // to aim at whoever reads the queue later.
    expect(normalizePageUrl('https://evil.example/pwn')).toBeNull();
  });
});

describe('verifyTurnstile', () => {
  it('fails closed when no secret is configured', async () => {
    // A misconfigured deploy must close the form, not open it unverified.
    expect(await verifyTurnstile('token', undefined)).toBe(false);
  });

  it('fails closed when the token is missing', async () => {
    expect(await verifyTurnstile('', 'secret')).toBe(false);
  });

  it('fails closed when the verification call itself errors', async () => {
    const boom = (() => Promise.reject(new Error('network'))) as unknown as typeof fetch;
    expect(await verifyTurnstile('token', 'secret', undefined, boom)).toBe(false);
  });

  it('passes only on an explicit success', async () => {
    const ok = (() =>
      Promise.resolve(new Response(JSON.stringify({ success: true })))) as unknown as typeof fetch;
    expect(await verifyTurnstile('token', 'secret', '1.2.3.4', ok)).toBe(true);

    const no = (() =>
      Promise.resolve(new Response(JSON.stringify({ success: false })))) as unknown as typeof fetch;
    expect(await verifyTurnstile('token', 'secret', '1.2.3.4', no)).toBe(false);
  });
});

describe('alertText', () => {
  it('says anonymous rather than leaving the line blank', () => {
    const result = validateFeedback(valid);
    if (!result.ok) throw new Error('fixture should validate');
    expect(alertText(42, result.value)).toContain('From:  (anonymous)');
  });

  it('carries enough context to triage without opening the database', () => {
    const result = validateFeedback({ ...valid, cveId: 'CVE-2026-0259' });
    if (!result.ok) throw new Error('fixture should validate');
    const text = alertText(42, result.value);
    expect(text).toContain('feedback #42');
    expect(text).toContain('CVE-2026-0259');
    expect(text).toContain('npm run feedback');
  });
});
