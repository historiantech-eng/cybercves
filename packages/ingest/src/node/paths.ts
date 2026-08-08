import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Repo root, found by walking up for the committed `data/` directory.
 *
 * `npm run -w <pkg>` executes with cwd inside the package, so any CLI default
 * that is a bare relative path resolves against packages/ingest/ rather than the
 * repo. Writing goes to a real file in a directory nothing reads; reading finds
 * nothing. Both exit zero. The README already documents this trap for `--db`,
 * where it merely produces an empty database in an odd place — for the discovery
 * data it is worse, because "no attribution found" is a publishable-looking
 * result that is simply wrong about a named company.
 *
 * Anchored on data/categories.yaml specifically: `data/` alone would also match
 * a package-local one created by an earlier buggy run, which is precisely the
 * state this is meant to detect rather than perpetuate.
 */
export function repoRoot(from = fileURLToPath(new URL('.', import.meta.url))): string {
  for (let dir = from; ; ) {
    if (existsSync(join(dir, 'data', 'categories.yaml'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) return process.cwd();
    dir = parent;
  }
}

/** Where committed discovery attribution lives. */
export const discoveryDir = (): string => join(repoRoot(), 'data', 'discovery');
