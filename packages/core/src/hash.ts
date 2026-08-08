/**
 * FNV-1a 64-bit, implemented in pure JS.
 *
 * Deliberately not node:crypto (absent on Workers) and not WebCrypto (async, and
 * we need hashing inside synchronous normalization). This is a change-detection
 * fingerprint, not a security primitive — collision resistance beyond "did this
 * record change" is not required.
 */

const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const MASK_64 = 0xffffffffffffffffn;

export function fnv1a64(input: string): string {
  let hash = FNV_OFFSET;
  for (let i = 0; i < input.length; i++) {
    // Hash UTF-16 code units as two bytes so non-ASCII content still contributes.
    const code = input.charCodeAt(i);
    hash = ((hash ^ BigInt(code & 0xff)) * FNV_PRIME) & MASK_64;
    hash = ((hash ^ BigInt((code >> 8) & 0xff)) * FNV_PRIME) & MASK_64;
  }
  return hash.toString(16).padStart(16, '0');
}
