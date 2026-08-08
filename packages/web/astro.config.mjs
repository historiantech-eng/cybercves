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
});
