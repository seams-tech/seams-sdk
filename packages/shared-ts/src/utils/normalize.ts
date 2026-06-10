/**
 * Generic normalization helpers shared across client/server.
 *
 * Keep domain-specific normalizers in their domain modules.
 */

/** Strict string coercion: returns the value only when it's already a string. */
export function normalizeOptionalString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/** Strict string coercion + trimming. */
export function normalizeOptionalTrimmedString(value: unknown): string {
  return normalizeOptionalString(value).trim();
}

/** String coercion + trimming (useful at IO boundaries). */
export function normalizeTrimmedString(value: unknown): string {
  return String(value ?? '').trim();
}

/** String coercion + trimming + lowercase. */
export function normalizeLowercaseString(value: unknown): string {
  return normalizeTrimmedString(value).toLowerCase();
}

/** String coercion + trimming + uppercase. */
export function normalizeUppercaseString(value: unknown): string {
  return normalizeTrimmedString(value).toUpperCase();
}

/** Normalize session kind into the canonical `'jwt' | 'cookie'` token. */
export function normalizeJwtCookieSessionKind(value: unknown): 'jwt' | 'cookie' {
  return normalizeLowercaseString(value) === 'cookie' ? 'cookie' : 'jwt';
}

/** String coercion + trimming; empty => undefined. */
export function normalizeOptionalNonEmptyString(value: unknown): string | undefined {
  const normalized = normalizeTrimmedString(value);
  return normalized || undefined;
}

/** Convert unknown to finite number; non-finite => null. */
export function normalizeFiniteNumber(value: unknown): number | null {
  const normalized = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(normalized)) return null;
  return normalized;
}

/** Convert unknown to integer; non-finite => null. */
export function normalizeInteger(value: unknown): number | null {
  const normalized = normalizeFiniteNumber(value);
  if (normalized == null) return null;
  return Math.trunc(normalized);
}

/** Convert unknown to positive integer; invalid/non-positive => null. */
export function normalizePositiveInteger(value: unknown): number | null {
  const normalized = normalizeInteger(value);
  if (normalized == null || normalized <= 0) return null;
  return normalized;
}

/** Convert unknown to non-negative integer; invalid/negative => null. */
export function normalizeNonNegativeInteger(value: unknown): number | null {
  const normalized = normalizeInteger(value);
  if (normalized == null || normalized < 0) return null;
  return normalized;
}

/**
 * Normalize unknown input to a positive integer with fallback and optional upper bound.
 * - invalid / non-positive values resolve to `fallback`
 * - values above `max` are clamped to `max`
 */
export function normalizeBoundedPositiveInteger(
  value: unknown,
  options: {
    fallback: number;
    min?: number;
    max?: number;
  },
): number {
  const min = normalizePositiveInteger(options.min) ?? 1;
  const fallbackRaw = normalizePositiveInteger(options.fallback) ?? min;
  const fallback = Math.max(min, fallbackRaw);
  const max = normalizePositiveInteger(options.max);
  const parsed = normalizeInteger(value);
  if (parsed == null || parsed < min) return fallback;
  if (max != null) return Math.min(parsed, max);
  return parsed;
}

/** Remove trailing `/` characters (e.g. base URL normalization). */
export function stripTrailingSlashes(value: string): string {
  return String(value ?? '').replace(/\/+$/, '');
}

/** Ensure a non-empty string starts with `/` (path normalization). */
export function ensureLeadingSlash(value: string): string {
  const trimmed = normalizeTrimmedString(value);
  if (!trimmed) return '';
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

/** Join a base URL and path after canonical slash normalization. */
export function joinNormalizedUrl(baseUrlRaw: string, pathRaw: string): string {
  const baseUrl = stripTrailingSlashes(normalizeTrimmedString(baseUrlRaw));
  const path = ensureLeadingSlash(normalizeTrimmedString(pathRaw));
  if (!baseUrl) throw new Error('Missing base URL');
  return `${baseUrl}${path}`;
}

/** Normalize an app base path like `/sdk` (leading slash, no trailing slashes except `/`). */
export function toBasePath(value?: string, fallback = '/sdk'): string {
  const base =
    ensureLeadingSlash(typeof value === 'string' ? value : fallback) ||
    ensureLeadingSlash(fallback) ||
    '/';
  if (base === '/') return '/';
  return base.replace(/\/+$/, '');
}

/** Best-effort origin normalization (used by CSP/Permissions-Policy helpers). */
export function toOriginOrUndefined(input?: string): string | undefined {
  try {
    const v = normalizeTrimmedString(input);
    if (!v) return undefined;
    return new URL(v, 'http://dummy').origin === 'http://dummy' ? new URL(v).origin : v;
  } catch {
    return normalizeTrimmedString(input) || undefined;
  }
}

/**
 * Strict origin sanitizer for Related Origin Requests (ROR).
 * - Allows `https://<host>[:port]` and `http://localhost[:port]` only.
 * - Rejects paths (except `/`), queries, and hashes.
 * - Normalizes hostname casing.
 */
export function toRorOriginOrNull(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const raw = normalizeTrimmedString(value);
  if (!raw) return null;
  try {
    const u = new URL(raw);
    const scheme = u.protocol;
    const host = u.hostname.toLowerCase();
    const port = u.port ? `:${u.port}` : '';
    const isHttps = scheme === 'https:';
    const isLocalhostHttp = scheme === 'http:' && host === 'localhost';
    if (!isHttps && !isLocalhostHttp) return null;
    if ((u.pathname && u.pathname !== '/') || u.search || u.hash) return null;
    return `${scheme}//${host}${port}`;
  } catch {
    return null;
  }
}

/** Collapse a string into a single line by normalizing whitespace. */
export function toSingleLine(value: unknown): string {
  return String(value ?? '')
    .replace(/[\r\n]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}
