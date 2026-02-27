type ConsoleRequestErrorFactory = (code: string, status: number, message: string) => Error;

export function requireBodyObject(
  body: unknown,
  createError: ConsoleRequestErrorFactory,
): Record<string, unknown> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw createError('invalid_body', 400, 'Expected JSON object request body');
  }
  return body as Record<string, unknown>;
}

export function requireQueryObject(
  query: unknown,
  createError: ConsoleRequestErrorFactory,
): Record<string, unknown> {
  if (query === undefined || query === null) return {};
  if (!query || typeof query !== 'object' || Array.isArray(query)) {
    throw createError('invalid_query', 400, 'Expected query params object');
  }
  return query as Record<string, unknown>;
}

export function readRequiredStringField(
  source: Record<string, unknown>,
  key: string,
  createError: ConsoleRequestErrorFactory,
): string {
  const value = String(source[key] ?? '').trim();
  if (!value) {
    throw createError('invalid_body', 400, `Missing required field: ${key}`);
  }
  return value;
}

export function readOptionalStringField(
  source: Record<string, unknown>,
  key: string,
): string | undefined {
  const raw = source[key];
  if (raw === undefined || raw === null) return undefined;
  const value = String(raw).trim();
  return value || undefined;
}

export function readRequiredIntegerField(
  source: Record<string, unknown>,
  key: string,
  createError: ConsoleRequestErrorFactory,
): number {
  const raw = source[key];
  const n = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isInteger(n)) {
    throw createError('invalid_body', 400, `Field ${key} must be an integer`);
  }
  return n;
}

export function readOptionalQueryStringField(
  query: Record<string, unknown>,
  key: string,
): string | undefined {
  const raw = query[key];
  if (raw === undefined || raw === null) return undefined;
  const first = Array.isArray(raw) ? raw[0] : raw;
  const value = String(first).trim();
  return value || undefined;
}

export function readOptionalQueryBooleanField(
  query: Record<string, unknown>,
  key: string,
  createError: ConsoleRequestErrorFactory,
): boolean | undefined {
  const raw = query[key];
  if (raw === undefined || raw === null) return undefined;
  const first = Array.isArray(raw) ? raw[0] : raw;
  if (typeof first === 'boolean') return first;

  const value = String(first).trim().toLowerCase();
  if (!value) return undefined;
  if (value === 'true' || value === '1') return true;
  if (value === 'false' || value === '0') return false;
  throw createError('invalid_query', 400, `Query parameter ${key} must be true/false`);
}

export function readOptionalQueryPositiveIntegerField(
  query: Record<string, unknown>,
  key: string,
  createError: ConsoleRequestErrorFactory,
): number | undefined {
  const raw = query[key];
  if (raw === undefined || raw === null) return undefined;
  const first = Array.isArray(raw) ? raw[0] : raw;
  const text = String(first).trim();
  if (!text) return undefined;
  if (!/^\d+$/.test(text)) {
    throw createError('invalid_query', 400, `Query parameter ${key} must be a positive integer`);
  }
  const value = Number.parseInt(text, 10);
  if (!Number.isFinite(value) || value <= 0) {
    throw createError('invalid_query', 400, `Query parameter ${key} must be a positive integer`);
  }
  return value;
}
