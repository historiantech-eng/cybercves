import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Every inline script in the built HTML must be allowed by that page's CSP.
 *
 * This exists because the failure it catches is silent. Astro hashes the scripts
 * it processes, but passes `is:inline` scripts through untouched — and Base.astro
 * needs one inline: the pre-paint theme read, which must run synchronously or a
 * dark-mode visitor gets a white flash. Its hash is therefore pinned by hand in
 * astro.config.mjs.
 *
 * Edit that script by one byte and the browser quietly refuses to run it. No
 * error page, no failed build — just light mode for everyone who chose dark, and
 * nothing in the terminal to suggest why. That is precisely the shape of the
 * severity-chart bug that shipped once already, so it gets a test.
 */

const DIST = fileURLToPath(new URL('../dist/', import.meta.url));

// Page types that between them cover every layout and component on the site.
const PAGES = [
  'index.html',
  'feedback.html',
  'privacy.html',
  'methodology.html',
  'vendors/palo-alto.html',
  'categories/threat-detection.html',
];

const INLINE_SCRIPT = /<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/g;

function cspOf(html: string): string {
  const match = html.match(/content-security-policy"\s+content="([^"]*)"/i);
  return match?.[1] ?? '';
}

describe.skipIf(!existsSync(DIST))('Content-Security-Policy', () => {
  for (const page of PAGES) {
    const path = `${DIST}${page}`;

    it.skipIf(!existsSync(path))(`allows every inline script on /${page}`, () => {
      const html = readFileSync(path, 'utf8');
      const csp = cspOf(html);
      expect(csp, `${page} has no CSP meta tag`).not.toBe('');

      const allowed = new Set(
        [...csp.matchAll(/'sha256-([^']+)'/g)].map((m) => m[1] as string),
      );

      const unhashed: string[] = [];
      for (const [, attrs, body] of html.matchAll(INLINE_SCRIPT)) {
        const script = body as string;
        // An empty block executes nothing and needs no hash.
        if (!script.trim()) continue;
        // Data blocks, not code. `script-src` governs script execution, and no
        // browser executes application/ld+json — it is parsed as metadata. They
        // could not be hashed anyway: every CVE page emits a different one, so
        // pinning them would mean a hash list as long as the site.
        if (/type=["']application\/(ld\+json|json)["']/.test(attrs as string)) continue;
        const hash = createHash('sha256').update(script, 'utf8').digest('base64');
        if (!allowed.has(hash)) {
          unhashed.push(
            `\n  sha256-${hash}\n  ${script.trim().slice(0, 90).replace(/\s+/g, ' ')}…`,
          );
        }
      }

      expect(
        unhashed,
        `${page}: inline script(s) not allowed by the CSP. If this is the pre-paint ` +
          `theme script, update experimental.csp.scriptDirective.hashes in ` +
          `astro.config.mjs to the hash printed here.${unhashed.join('')}`,
      ).toEqual([]);
    });
  }

  it('keeps frame-ancestors out of the meta tag, where it would be ignored', () => {
    // It is set as a real header in public/_headers instead. A reader seeing it
    // here would reasonably assume clickjacking was handled when it was not.
    const html = readFileSync(`${DIST}index.html`, 'utf8');
    expect(cspOf(html)).not.toContain('frame-ancestors');
  });

  it('still forbids the escape hatches', () => {
    const csp = cspOf(readFileSync(`${DIST}index.html`, 'utf8'));
    expect(csp).not.toContain("'unsafe-inline'");
    expect(csp).not.toContain("'unsafe-eval'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
  });
});
