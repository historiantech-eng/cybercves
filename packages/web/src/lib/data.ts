import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { Repository } from '@cybercves/db';
import { NodeSqliteDriver } from '@cybercves/db/drivers/node';

/**
 * Build-time data access.
 *
 * The site is fully static, so every page is rendered from a local SQLite
 * snapshot produced by `npm run sync` or `npm run backfill`. At runtime the
 * browser talks to the Worker's JSON API for anything that must stay live —
 * the hero counter — so this file never runs in production.
 */

const DB_PATH = resolve(
  process.env.CYBERCVE_DB ?? resolve(process.cwd(), '../../cybercves.sqlite'),
);

let repo: Repository | null = null;
let missingReported = false;

export function hasDatabase(): boolean {
  return existsSync(DB_PATH);
}

/**
 * A missing database yields empty pages rather than a failed build.
 *
 * CI builds the site before it has run an ingest, and a hard failure there would
 * mean no deploy at all. An empty site that deploys is recoverable; a red build
 * is not. The warning is loud so this never passes unnoticed.
 */
export function db(): Repository | null {
  if (!hasDatabase()) {
    if (!missingReported) {
      missingReported = true;
      console.warn(
        `\n  [cybercve] No database at ${DB_PATH} — building an empty site.\n` +
          '  Populate it first:  npm run sync -- --db ./cybercves.sqlite --enrich\n',
      );
    }
    return null;
  }
  if (!repo) repo = new Repository(new NodeSqliteDriver(DB_PATH));
  return repo;
}

export const CURRENT_YEAR = new Date().getUTCFullYear();

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';

/**
 * Severity always renders as a colored dot PLUS its text label.
 *
 * The status hues for HIGH and MEDIUM sit at ΔE 13.6 in normal vision — close
 * enough that color alone is not a reliable distinction — so the label is the
 * accessible channel, not decoration.
 */
export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];

export function severityToken(severity: string | null): string {
  switch ((severity ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'serious';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
      return 'good';
    default:
      return 'unknown';
  }
}

export function splitList(value: string | null): string[] {
  return value ? value.split(',').filter(Boolean) : [];
}

export function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  });
}

export function compactNumber(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}K`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}
