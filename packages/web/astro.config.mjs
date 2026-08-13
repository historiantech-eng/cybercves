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
  },
  trailingSlash: 'never',
  compressHTML: true,
  devToolbar: { enabled: false },

  experimental: {
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
      directives: [
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
