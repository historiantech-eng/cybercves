/** Minimal CPE 2.3 formatted-string parser — only the fields we match on. */

export interface ParsedCpe {
  part: string | null;
  vendor: string | null;
  product: string | null;
  version: string | null;
}

/** CPE escapes literals with a backslash and uses `_` where the name has a space. */
function decodeComponent(raw: string | undefined): string | null {
  if (!raw || raw === '*' || raw === '-') return null;
  return raw.replace(/\\(.)/g, '$1').replace(/_/g, ' ').toLowerCase().trim() || null;
}

/**
 * Parse `cpe:2.3:a:fortinet:fortivoice:7.2.0:*:*:*:*:*:*:*`.
 *
 * Splitting on `:` is safe here because CPE 2.3 requires colons inside components
 * to be backslash-escaped, and we split before unescaping.
 */
export function parseCpe(cpe: string): ParsedCpe | null {
  if (!cpe.startsWith('cpe:2.3:')) return null;
  const parts = cpe.split(/(?<!\\):/);
  if (parts.length < 6) return null;
  return {
    part: decodeComponent(parts[2]),
    vendor: decodeComponent(parts[3]),
    product: decodeComponent(parts[4]),
    version: decodeComponent(parts[5]),
  };
}
