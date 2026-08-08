/**
 * The single seam between our SQL and whatever engine runs it.
 *
 * Every query in the codebase goes through this interface, which is what makes
 * the D1 -> Postgres migration mechanical rather than a rewrite. Implementations
 * live in ./drivers and are the only files that import engine-specific APIs.
 */

export type SqlValue = string | number | null;

export interface Statement {
  sql: string;
  params?: SqlValue[];
}

export interface SqlDriver {
  /** Run a query and return all rows. */
  all<T = Record<string, unknown>>(sql: string, params?: SqlValue[]): Promise<T[]>;

  /** Run a query and return the first row, or null. */
  first<T = Record<string, unknown>>(sql: string, params?: SqlValue[]): Promise<T | null>;

  /** Execute a write statement. */
  run(sql: string, params?: SqlValue[]): Promise<{ changes: number }>;

  /**
   * Execute many statements as a unit.
   *
   * D1 has no interactive transactions, so this is the strongest atomicity
   * guarantee available on the launch platform. Callers must not assume
   * rollback-on-error beyond what the underlying engine provides.
   */
  batch(statements: Statement[]): Promise<void>;

  close?(): Promise<void>;
}

/**
 * Split a multi-statement SQL file into individual statements.
 *
 * D1 has no reliable multi-statement exec, so migrations are split and issued
 * one at a time. Line comments are stripped first; the schema deliberately
 * contains no semicolons inside string literals, which keeps this safe.
 */
export function splitStatements(sql: string): string[] {
  return sql
    .split('\n')
    .map((line) => {
      const commentAt = line.indexOf('--');
      return commentAt >= 0 ? line.slice(0, commentAt) : line;
    })
    .join('\n')
    .split(';')
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}
