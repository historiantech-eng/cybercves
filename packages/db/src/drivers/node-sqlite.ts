import { DatabaseSync } from 'node:sqlite';
import type { SqlDriver, SqlValue, Statement } from '../driver.js';

/**
 * Node driver, backed by the built-in `node:sqlite` module (Node 22.5+).
 *
 * Deliberately not better-sqlite3: a native module would need a compiler on
 * every machine that runs a backfill, and the built-in has no build step. Used
 * for local development, the historical backfill, and tests.
 */
export class NodeSqliteDriver implements SqlDriver {
  readonly #db: DatabaseSync;

  constructor(path = ':memory:') {
    this.#db = new DatabaseSync(path);
    // Foreign keys are off by default in SQLite; our ON DELETE CASCADE rules
    // silently do nothing without this.
    this.#db.exec('PRAGMA foreign_keys = ON');
  }

  async all<T = Record<string, unknown>>(sql: string, params: SqlValue[] = []): Promise<T[]> {
    return this.#db.prepare(sql).all(...params) as T[];
  }

  async first<T = Record<string, unknown>>(sql: string, params: SqlValue[] = []): Promise<T | null> {
    return (this.#db.prepare(sql).get(...params) as T | undefined) ?? null;
  }

  async run(sql: string, params: SqlValue[] = []): Promise<{ changes: number }> {
    const result = this.#db.prepare(sql).run(...params);
    return { changes: Number(result.changes) };
  }

  async batch(statements: Statement[]): Promise<void> {
    // Unlike D1, SQLite here does give us a real transaction — use it.
    this.#db.exec('BEGIN');
    try {
      for (const { sql, params = [] } of statements) {
        this.#db.prepare(sql).run(...params);
      }
      this.#db.exec('COMMIT');
    } catch (err) {
      this.#db.exec('ROLLBACK');
      throw err;
    }
  }

  async close(): Promise<void> {
    this.#db.close();
  }
}
