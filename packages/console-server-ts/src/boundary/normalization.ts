export function normalizeBoundedPositiveInteger(
  value: unknown,
  options: {
    fallback: number;
    min?: number;
    max?: number;
  },
): number {
  const toPositiveInteger = (input: unknown): number | null => {
    const parsed = typeof input === 'number' ? input : Number(input);
    if (!Number.isFinite(parsed)) return null;
    const truncated = Math.trunc(parsed);
    return truncated > 0 ? truncated : null;
  };
  const toInteger = (input: unknown): number | null => {
    const parsed = typeof input === 'number' ? input : Number(input);
    if (!Number.isFinite(parsed)) return null;
    return Math.trunc(parsed);
  };
  const min = toPositiveInteger(options.min) ?? 1;
  const fallbackRaw = toPositiveInteger(options.fallback) ?? min;
  const fallback = Math.max(min, fallbackRaw);
  const max = toPositiveInteger(options.max);
  const parsed = toInteger(value);
  if (parsed == null || parsed < min) return fallback;
  if (max != null) return Math.min(parsed, max);
  return parsed;
}

function normalizeParsedCorsOrigin(url: URL): string {
  const host = url.hostname.toLowerCase();
  const proto = url.protocol === 'http:' || url.protocol === 'https:' ? url.protocol : 'https:';
  const rawPort = String(url.port || '').trim();
  const isDefaultHttpsPort = proto === 'https:' && rawPort === '443';
  const isDefaultHttpPort = proto === 'http:' && rawPort === '80';
  const port = rawPort && !isDefaultHttpsPort && !isDefaultHttpPort ? `:${rawPort}` : '';
  return `${proto}//${host}${port}`;
}

/**
 * Normalize a single origin for CORS comparisons.
 * Returns null when the input is empty or not URL-like.
 */
export function normalizeCorsOrigin(input?: string): string | null {
  const raw = String(input || '').trim();
  if (!raw) return null;
  try {
    return normalizeParsedCorsOrigin(new URL(raw));
  } catch {
    return null;
  }
}

export function normalizeSourceIp(raw: string | undefined): string | null {
  const value = String(raw || '').trim();
  if (!value) return null;
  const maybeForwarded = value.includes(',') ? value.split(',')[0] : value;
  const trimmed = String(maybeForwarded || '').trim();
  return trimmed || null;
}
