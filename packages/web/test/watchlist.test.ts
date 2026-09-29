import { describe, expect, it } from 'vitest';
import { SESSION_KEY, WATCH_KEY, isNewSince, load, markVisit, save, toggle } from '../src/lib/watchlist';

function memory(): Storage {
  const data = new Map<string, string>();
  return {
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, String(v)),
    removeItem: (k) => void data.delete(k),
    clear: () => data.clear(),
    key: (i) => [...data.keys()][i] ?? null,
    get length() {
      return data.size;
    },
  };
}

const throwing = {
  getItem: () => {
    throw new Error('blocked');
  },
  setItem: () => {
    throw new Error('blocked');
  },
};

describe('watchlist storage', () => {
  it('starts empty and round-trips', () => {
    const local = memory();
    expect(load(local)).toEqual({ products: [], lastVisit: null, prevVisit: null });
    expect(toggle('fortinet-fortios', local)).toBe(true);
    expect(load(local).products).toEqual(['fortinet-fortios']);
    expect(toggle('fortinet-fortios', local)).toBe(false);
    expect(load(local).products).toEqual([]);
  });

  it('treats blocked storage as an empty list, never an exception', () => {
    expect(load(throwing).products).toEqual([]);
    expect(save({ products: ['x'], lastVisit: null, prevVisit: null }, throwing)).toBe(false);
    expect(toggle('x', throwing)).toBeNull();
    expect(load(null).products).toEqual([]);
  });

  it('discards malformed stored values instead of trusting them', () => {
    const local = memory();
    local.setItem(WATCH_KEY, JSON.stringify({ products: ['a', 7, '', 'a'], lastVisit: 'nope' }));
    expect(load(local)).toEqual({ products: ['a'], lastVisit: null, prevVisit: null });
    local.setItem(WATCH_KEY, '{not json');
    expect(load(local).products).toEqual([]);
  });
});

describe('markVisit', () => {
  it('rolls the clock once per session so New markers stay put', () => {
    const local = memory();
    toggle('palo-alto-pan-os', local);

    const first = markVisit(new Date('2026-09-01T10:00:00Z'), local, memory());
    expect(first.prevVisit).toBeNull();
    expect(first.lastVisit).toBe('2026-09-01T10:00:00.000Z');

    // A new session a week later: last becomes prev.
    const session = memory();
    const second = markVisit(new Date('2026-09-08T10:00:00Z'), local, session);
    expect(second.prevVisit).toBe('2026-09-01T10:00:00.000Z');
    expect(session.getItem(SESSION_KEY)).toBe('1');

    // Same session, next page: nothing moves.
    const third = markVisit(new Date('2026-09-08T10:05:00Z'), local, session);
    expect(third.prevVisit).toBe('2026-09-01T10:00:00.000Z');
    expect(third.lastVisit).toBe('2026-09-08T10:00:00.000Z');
  });

  it('keeps no visit clock for a reader who watches nothing', () => {
    const local = memory();
    markVisit(new Date('2026-09-01T10:00:00Z'), local, memory());
    expect(local.getItem(WATCH_KEY)).toBeNull();
  });
});

describe('isNewSince', () => {
  it('compares by calendar day, inclusive', () => {
    expect(isNewSince('2026-09-08', '2026-09-08T23:00:00.000Z')).toBe(true);
    expect(isNewSince('2026-09-07', '2026-09-08T00:00:00.000Z')).toBe(false);
    expect(isNewSince('2026-09-09', '2026-09-08T00:00:00.000Z')).toBe(true);
  });

  it('marks nothing without a previous visit or a date', () => {
    expect(isNewSince('2026-09-09', null)).toBe(false);
    expect(isNewSince(null, '2026-09-08T00:00:00.000Z')).toBe(false);
  });
});
