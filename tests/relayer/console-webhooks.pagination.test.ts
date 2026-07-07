import { expect, test } from '@playwright/test';
import {
  encodePaginationCursor,
  normalizePaginationLimit,
  paginateByCursor,
  parsePaginationCursor,
} from '../../packages/console-server-ts/src/webhooks/pagination';

test.describe('console webhook pagination utilities', () => {
  test('cursor encode/parse roundtrip preserves sort key and id', () => {
    const encoded = encodePaginationCursor(1700000000123, 'wh:delivery/abc');
    const parsed = parsePaginationCursor(encoded);
    expect(parsed).toEqual({
      sortMs: 1700000000123,
      id: 'wh:delivery/abc',
    });
  });

  test('parse rejects malformed cursor payloads', () => {
    const invalidValues = [
      'bad',
      '123',
      'abc:def',
      '123:',
      ':abc',
      '123:%E0%A4%A',
      '9007199254740992:abc',
    ];
    for (const value of invalidValues) {
      let caught: any;
      try {
        parsePaginationCursor(value);
      } catch (error: unknown) {
        caught = error;
      }
      expect(caught).toBeTruthy();
      expect(String(caught?.code || '')).toBe('invalid_query');
    }
  });

  test('normalizePaginationLimit applies defaults and max cap', () => {
    expect(normalizePaginationLimit(undefined)).toBe(50);
    expect(normalizePaginationLimit(0)).toBe(50);
    expect(normalizePaginationLimit(-1)).toBe(50);
    expect(normalizePaginationLimit(1.8)).toBe(1);
    expect(normalizePaginationLimit(25)).toBe(25);
    expect(normalizePaginationLimit(999)).toBe(200);
  });

  test('paginateByCursor returns stable nextCursor and slices subsequent pages', () => {
    const items = [
      { id: 'wh_3', sortMs: 3000 },
      { id: 'wh_2', sortMs: 2000 },
      { id: 'wh_1', sortMs: 1000 },
    ];
    const pageOne = paginateByCursor({
      items,
      limit: 2,
      getSortMs: (item) => item.sortMs,
      getId: (item) => item.id,
    });
    expect(pageOne.items.map((entry) => entry.id)).toEqual(['wh_3', 'wh_2']);
    expect(String(pageOne.nextCursor || '')).toBeTruthy();

    const pageTwo = paginateByCursor({
      items,
      limit: 2,
      cursor: pageOne.nextCursor,
      getSortMs: (item) => item.sortMs,
      getId: (item) => item.id,
    });
    expect(pageTwo.items.map((entry) => entry.id)).toEqual(['wh_1']);
    expect(pageTwo.nextCursor).toBeUndefined();
  });

  test('paginateByCursor uses id tie-breaker when sort keys are equal', () => {
    const items = [
      { id: 'wh_b', sortMs: 2000 },
      { id: 'wh_a', sortMs: 2000 },
    ];
    const pageOne = paginateByCursor({
      items,
      limit: 1,
      getSortMs: (item) => item.sortMs,
      getId: (item) => item.id,
    });
    expect(pageOne.items.map((entry) => entry.id)).toEqual(['wh_b']);
    expect(String(pageOne.nextCursor || '')).toBeTruthy();

    const pageTwo = paginateByCursor({
      items,
      limit: 1,
      cursor: pageOne.nextCursor,
      getSortMs: (item) => item.sortMs,
      getId: (item) => item.id,
    });
    expect(pageTwo.items.map((entry) => entry.id)).toEqual(['wh_a']);
    expect(pageTwo.nextCursor).toBeUndefined();
  });

  test('encode rejects invalid sort key values', () => {
    const invalidSortKeys = [Number.NaN, Number.POSITIVE_INFINITY, -1, 9007199254740992];
    for (const sortMs of invalidSortKeys) {
      let caught: any;
      try {
        encodePaginationCursor(sortMs, 'wh_1');
      } catch (error: unknown) {
        caught = error;
      }
      expect(caught).toBeTruthy();
      expect(String(caught?.code || '')).toBe('invalid_query');
    }
  });
});
