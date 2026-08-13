import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://cybercve.com',
  // Fully static: every page is prerendered at build time and served from
  // Cloudflare's edge by the Worker's ASSETS binding. Nothing renders per-request.
  output: 'static',
  build: {
    // Emit /vendors/fortinet.html rather than /vendors/fortinet/index.html so
    // asset routing stays predictable behind the Worker.
    format: 'file',
    // Never inline a <style> block into the HTML.
    //
    // This is load-bearing for the CSP below, not a performance choice. Astro
    // hashes every inline <style> it emits and puts those hashes in `style-src`
    // — and per CSP spec, a directive containing a hash IGNORES 'unsafe-inline'.
    // The site needs 'unsafe-inline' for style *attributes*: every bar width
    // (`style="width:58%"`) and every odometer digit (`style="transform:…"`) is
    // one. With inlined stylesheets there is no way to have both, and the bars
    // and the odometer silently lose their geometry.
    inlineStylesheets: 'never',
  },
  trailingSlash: 'never',
  compressHTML: true,
  devToolbar: { enabled: false },

  // ---------------------------------------------------------------------
  // CSP is OFF. It shipped once and broke every chart on the site.
  //
  // WHAT HAPPENED: Astro emits `style-src 'self' <hashes>`, and per CSP spec a
  // directive containing any hash-source ignores 'unsafe-inline'. This site
  // needs inline STYLE ATTRIBUTES — `style="width:58%"` is how every bar gets
  // its width and `style="transform:translateY(-4em)"` is how every odometer
  // digit gets its offset. All of them were blocked. The pages still rendered,
  // so nothing looked wrong in the build output; the geometry was simply gone.
  //
  // WHY IT IS NOT A ONE-LINE FIX:
  //   - `style-src` cannot be declared in `directives` — Astro rejects it.
  //   - Astro appends at least the empty-string hash even with no inline
  //     <style> left, so 'unsafe-inline' is voided no matter what is configured.
  //   - The hashes come from the four components that still carry a <style>
  //     block (CveTable, Odometer, DiscoveryBar, compare.astro). Moving those
  //     into global.css — the same move already made for .svc-* and .race-* —
  //     should leave style-src hash-free and let 'unsafe-inline' apply.
  //
  // That refactor plus a real browser check is the re-enable path. It is not
  // being done in the same commit as an outage fix. The headers in
  // public/_headers are unaffected and still enforced.
  //
  // experimental: {
  //   csp: { ... see git history for the full block ... }
  // }
  _cspDisabled: {
    // Content-Security-Policy, emitted per page as a <meta> tag with the hashes
    // of that page's own inline scripts and styles.
    //
    // Hand-writing this in public/_headers was the alternative and would not
    // survive contact with reality: Base.astro has two `is:inline` scripts (the
    // pre-paint theme read and the theme toggle) whose hashes change whenever
    // the code does. A stale hash does not fail loudly — it silently kills dark
    // mode, and the severity charts along with it. Letting the build compute
    // them is the only version that stays correct.
    //
    // frame-ancestors is absent here on purpose: it is ignored in a meta tag,
    // so it is set as a real header in public/_headers instead.
    csp: {
      scriptDirective: {
        // The pre-paint theme script in Base.astro is `is:inline`, which means
        // Astro passes it through without hashing it — so its hash is pinned
        // here by hand. It has to be inline and synchronous: a deferred module
        // runs after first paint, which is the light-mode flash it exists to
        // prevent.
        //
        // If you edit that script, this hash goes stale and the browser silently
        // refuses to run it, taking dark mode with it. packages/web/test/csp.test.ts
        // fails when that happens; it prints the replacement hash.
        hashes: ['sha256-TQvc7O8EjB0e9iOaAK3fw+q+uXTZcn9uqs0sqjLBjVI='],
        // Overrides Astro's defaults rather than adding to them, so 'self' must
        // be restated explicitly.
        resources: [
          "'self'",
          // Cloudflare Web Analytics beacon.
          'https://static.cloudflareinsights.com',
          // Turnstile, which guards the corrections form.
          'https://challenges.cloudflare.com',
        ],
      },
      styleDirective: {
        // 'unsafe-inline' is required, and is only honoured because
        // build.inlineStylesheets is 'never' — see the note there. Without it,
        // CSP blocks every `style="width:…"` attribute, which is how each bar
        // gets its width and each odometer digit its offset. Shipping without it
        // broke every chart on the site.
        //
        // The cost is real but small: style injection is the weakest of the CSP
        // protections, and no page here renders user-supplied content — reader
        // corrections are stored and triaged, never displayed. script-src stays
        // strict, which is where the value is.
        resources: ["'self'", "'unsafe-inline'"],
      },
      directives: [
        // MUST stay first, and must contain no hash.
        //
        // Astro appends its own `style-src` after these, and that one always
        // carries at least the empty-string hash even with no inline <style>
        // left to hash. Per CSP, a directive containing any hash-source ignores
        // 'unsafe-inline' — so Astro's copy alone blocks every `style="width:…"`
        // attribute, which is exactly how the bars and the odometer broke.
        //
        // When a policy names the same directive twice the FIRST wins and the
        // rest are ignored, so declaring it here is what actually takes effect.
        // The browser logs a duplicate-directive warning; that is the cost.
        // csp.test.ts asserts the effective (first) style-src still permits
        // inline styles, because the failure mode is silent geometry loss.
        "style-src 'self' 'unsafe-inline'",
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "form-action 'self'",
        // Turnstile renders in an iframe.
        'frame-src https://challenges.cloudflare.com',
        // The analytics beacon posts here; the charts fetch same-origin shards.
        "connect-src 'self' https://static.cloudflareinsights.com https://cloudflareinsights.com",
        "img-src 'self' data:",
        "font-src 'self'",
      ],
    },
  },
});
