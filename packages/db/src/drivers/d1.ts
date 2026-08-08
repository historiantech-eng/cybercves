import type { SqlDriver, SqlValue, Statement } from '../driver.js';

/**
 * Minimal structural type for Cloudflare's D1 binding.
 *
 * Declared locally rather than importing @cloudflare/workers-types so this
 * package stays installable and typecheckable outside a Workers project — the
 * portability rule is that only the worker package depends on Cloudflare.
 */
export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  all<T = unknown>(): Promise<{ results: T[] }>;
  first<T = unknown>(): Promise<T | null>;
  run(): Promise<{ meta?: { changes?: number } }>;
}

export interface D1Database {
  prepare(sql: string): D1PreparedStatement;
  batch(statements: D1PreparedStatement[]): Promise<unknown[]>;
}

/** Cloudflare D1 driver. The only production path in v1. */
export class D1Driver implements SqlDriver {
  readonly #db: D1Database;

  constructor(db: D1Database) {
    this.#db = db;
  }

  #bind(sql: string, params: SqlValue[]): D1PreparedStatement {
    const stmt = this.#db.prepare(sql);
    return params.length ? stmt.bind(...params) : stmt;
  }

  async all<T = Record<string, unknown>>(sql: string, params: SqlValue[] = []): Promise<T[]> {
    const { results } = await this.#bind(sql, params).all<T>();
    return results ?? [];
  }

  async first<T = Record<string, unknown>>(sql: string, params: SqlValue[] = []): Promise<T | null> {
    return await this.#bind(sql, params).first<T>();
  }

  async run(sql: string, params: SqlValue[] = []): Promise<{ changes: number }> {
    const result = await this.#bind(sql, params).run();
    return { changes: result.meta?.changes ?? 0 };
  }

  async batch(statements: Statement[]): Promise<void> {
    if (!statements.length) return;
    // D1's batch is atomic but offers no interactive transaction, so there is no
    // BEGIN/COMMIT to issue here — the batch itself is the unit.
    await this.#db.batch(statements.map(({ sql, params = [] }) => this.#bind(sql, params)));
  }
}
