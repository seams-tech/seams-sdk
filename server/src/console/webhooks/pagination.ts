import { ConsoleWebhookError } from './errors';

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

export interface PaginationCursor {
  sortMs: number;
  id: string;
}

export function parsePaginationCursor(cursor: string | undefined): PaginationCursor | null {
  const raw = String(cursor || '').trim();
  if (!raw) return null;

  const separatorIndex = raw.indexOf(':');
  if (separatorIndex <= 0 || separatorIndex === raw.length - 1) {
    throw new ConsoleWebhookError('invalid_query', 400, 'Invalid cursor format');
  }

  const sortMsRaw = raw.slice(0, separatorIndex);
  const encodedId = raw.slice(separatorIndex + 1);
  if (!/^\d+$/.test(sortMsRaw)) {
    throw new ConsoleWebhookError('invalid_query', 400, 'Invalid cursor sort key');
  }
  const sortMs = Number.parseInt(sortMsRaw, 10);
  if (!Number.isSafeInteger(sortMs)) {
    throw new ConsoleWebhookError('invalid_query', 400, 'Invalid cursor sort key');
  }

  let id: string;
  try {
    id = decodeURIComponent(encodedId);
  } catch {
    throw new ConsoleWebhookError('invalid_query', 400, 'Invalid cursor value');
  }
  if (!id) {
    throw new ConsoleWebhookError('invalid_query', 400, 'Invalid cursor value');
  }

  return {
    sortMs,
    id,
  };
}

export function normalizePaginationLimit(limit: number | undefined): number {
  if (!Number.isFinite(limit)) return DEFAULT_LIMIT;
  const value = Math.floor(Number(limit));
  if (value <= 0) return DEFAULT_LIMIT;
  return Math.min(value, MAX_LIMIT);
}

export function encodePaginationCursor(sortMs: number, id: string): string {
  if (!Number.isFinite(sortMs) || !Number.isSafeInteger(Math.floor(sortMs)) || sortMs < 0) {
    throw new ConsoleWebhookError('invalid_query', 400, 'Invalid cursor sort key');
  }
  const safeSortMs = Math.floor(sortMs);
  return `${safeSortMs}:${encodeURIComponent(id)}`;
}

export interface CursorPaginateInput<T> {
  items: T[];
  limit?: number;
  cursor?: string;
  getSortMs: (item: T) => number;
  getId: (item: T) => string;
}

export interface CursorPaginateResult<T> {
  items: T[];
  nextCursor?: string;
}

export function paginateByCursor<T>(input: CursorPaginateInput<T>): CursorPaginateResult<T> {
  const limit = normalizePaginationLimit(input.limit);
  const cursor = parsePaginationCursor(input.cursor);

  const filtered = cursor
    ? input.items.filter((item) => {
      const sortMs = input.getSortMs(item);
      const id = input.getId(item);
      if (sortMs < cursor.sortMs) return true;
      if (sortMs > cursor.sortMs) return false;
      return id < cursor.id;
    })
    : input.items;

  const page = filtered.slice(0, limit);
  if (filtered.length <= limit || page.length === 0) {
    return { items: page };
  }

  const last = page[page.length - 1];
  return {
    items: page,
    nextCursor: encodePaginationCursor(input.getSortMs(last), input.getId(last)),
  };
}
