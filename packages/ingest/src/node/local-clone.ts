import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { CveRecord } from '@cybercves/core';

/**
 * Reads CVE records from a local clone of CVEProject/cvelistV5.
 *
 * The historical backfill covers ~10 years and tens of thousands of records.
 * Fetching those one HTTP request at a time would take hours and hammer a public
 * good; the CVE Project itself recommends a shallow git clone. Clone once:
 *
 *   git clone --depth 1 https://github.com/CVEProject/cvelistV5.git
 *
 * then point the backfill at it. Deliberately no zip dependency — Node has no
 * built-in unzip, and a native one would need a compiler on every backfill host.
 */

export interface CloneStats {
  years: number[];
  fileCount: number;
}

function cvesRoot(clonePath: string): string {
  const nested = join(clonePath, 'cves');
  if (existsSync(nested) && statSync(nested).isDirectory()) return nested;
  // Allow pointing directly at the cves/ directory.
  return clonePath;
}

export function inspectClone(clonePath: string, fromYear: number, toYear: number): CloneStats {
  const root = cvesRoot(clonePath);
  if (!existsSync(root)) {
    throw new Error(
      `No CVE data at ${root}. Clone it first:\n` +
        '  git clone --depth 1 https://github.com/CVEProject/cvelistV5.git',
    );
  }

  const years: number[] = [];
  let fileCount = 0;

  for (const entry of readdirSync(root)) {
    const year = Number.parseInt(entry, 10);
    if (!Number.isFinite(year) || year < fromYear || year > toYear) continue;
    years.push(year);
    for (const bucket of readdirSync(join(root, entry))) {
      fileCount += readdirSync(join(root, entry, bucket)).filter((f) => f.endsWith('.json')).length;
    }
  }

  return { years: years.sort((a, b) => a - b), fileCount };
}

/**
 * Stream records in batches.
 *
 * Yields rather than returning an array: the full corpus is several GB of parsed
 * JSON and would not fit comfortably in memory.
 */
export function* streamRecords(
  clonePath: string,
  fromYear: number,
  toYear: number,
  batchSize = 500,
): Generator<{ year: number; records: CveRecord[] }> {
  const root = cvesRoot(clonePath);

  for (const entry of readdirSync(root).sort()) {
    const year = Number.parseInt(entry, 10);
    if (!Number.isFinite(year) || year < fromYear || year > toYear) continue;

    let batch: CveRecord[] = [];
    for (const bucket of readdirSync(join(root, entry)).sort()) {
      const bucketPath = join(root, entry, bucket);
      if (!statSync(bucketPath).isDirectory()) continue;

      for (const file of readdirSync(bucketPath).sort()) {
        if (!file.endsWith('.json')) continue;
        try {
          batch.push(JSON.parse(readFileSync(join(bucketPath, file), 'utf8')) as CveRecord);
        } catch {
          // A single malformed record must not abort a multi-hour backfill.
          continue;
        }
        if (batch.length >= batchSize) {
          yield { year, records: batch };
          batch = [];
        }
      }
    }
    if (batch.length) yield { year, records: batch };
  }
}
