/**
 * Fetch helpers shared by every source adapter.
 *
 * Uses the global `fetch`, which exists in both Node 18+ and the Workers
 * runtime, so no adapter needs a platform-specific HTTP client.
 */

export const USER_AGENT = 'cybercves/0.1 (+https://github.com/cybercves)';

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly url: string,
  ) {
    super(`HTTP ${status} for ${url}`);
    this.name = 'HttpError';
  }
}

export interface FetchOptions {
  retries?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * GET with bounded retries and exponential backoff.
 *
 * 4xx responses other than 429 are not retried — a 404 on a CVE record means the
 * record moved or was rejected, and hammering it wastes the run's time budget.
 */
export async function fetchWithRetry(url: string, options: FetchOptions = {}): Promise<Response> {
  const { retries = 3, timeoutMs = 30_000 } = options;
  let lastError: unknown;

  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) await sleep(Math.min(2 ** attempt * 250, 8_000));

    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = options.signal
      ? AbortSignal.any([options.signal, timeout])
      : timeout;

    try {
      const response = await fetch(url, { headers: { 'user-agent': USER_AGENT }, signal });
      if (response.ok) return response;

      if (response.status < 500 && response.status !== 429) {
        throw new HttpError(response.status, url);
      }
      lastError = new HttpError(response.status, url);
    } catch (err) {
      if (err instanceof HttpError) throw err;
      lastError = err;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(`Failed to fetch ${url}`);
}

export async function fetchJson<T>(url: string, options?: FetchOptions): Promise<T> {
  const response = await fetchWithRetry(url, options);
  return (await response.json()) as T;
}

export async function fetchText(url: string, options?: FetchOptions): Promise<string> {
  const response = await fetchWithRetry(url, options);
  return await response.text();
}

/**
 * Run tasks with bounded concurrency.
 *
 * Sources like the CVE List are public goods with no published rate limit;
 * unbounded parallel fetching is both rude and a good way to get blocked.
 */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;

  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await worker(items[index] as T, index);
    }
  });

  await Promise.all(runners);
  return results;
}
