type HeaderBag = Headers | Record<string, unknown>;

function readHeader(headers: HeaderBag, name: string): string {
  if (headers instanceof Headers) {
    return String(headers.get(name) || '').trim();
  }
  const direct = (headers as Record<string, unknown>)[name];
  const lower = (headers as Record<string, unknown>)[name.toLowerCase()];
  const upper = (headers as Record<string, unknown>)[name.toUpperCase()];
  const value = direct ?? lower ?? upper;
  if (typeof value === 'string') return value.trim();
  if (Array.isArray(value)) return String(value[0] || '').trim();
  return '';
}

export function extractBearerCredential(headers: HeaderBag): string | null {
  const authHeader = readHeader(headers, 'authorization');
  if (authHeader) {
    const bearerPrefix = 'bearer ';
    if (authHeader.toLowerCase().startsWith(bearerPrefix)) {
      const bearerValue = authHeader.slice(bearerPrefix.length).trim();
      if (bearerValue) return bearerValue;
    }
  }
  return null;
}

export function normalizeSourceIp(raw: string | undefined): string | null {
  const value = String(raw || '').trim();
  if (!value) return null;
  const maybeForwarded = value.includes(',') ? value.split(',')[0] : value;
  const trimmed = String(maybeForwarded || '').trim();
  return trimmed || null;
}

export function extractRouterApiEnvironmentId(headers: HeaderBag): string | null {
  const preferred = readHeader(headers, 'x-seams-environment-id');
  if (preferred) return preferred;
  const fallback = readHeader(headers, 'x-environment-id');
  if (fallback) return fallback;
  return null;
}

export function resolveSourceIpFromExpressRequest(input: {
  headers: Record<string, unknown>;
  ip?: string | null;
}): string | null {
  const forwarded = readHeader(input.headers, 'x-forwarded-for');
  const realIp = readHeader(input.headers, 'x-real-ip');
  return normalizeSourceIp(forwarded || realIp || String(input.ip || ''));
}

export function resolveSourceIpFromFetchHeaders(headers: HeaderBag): string | null {
  const cfConnecting = readHeader(headers, 'cf-connecting-ip');
  const forwarded = readHeader(headers, 'x-forwarded-for');
  const realIp = readHeader(headers, 'x-real-ip');
  return normalizeSourceIp(cfConnecting || forwarded || realIp);
}

export function resolveRequestOriginRateLimitKeyFromExpressRequest(input: {
  headers: Record<string, unknown>;
  ip?: string | null;
}): string {
  const sourceIp = resolveSourceIpFromExpressRequest(input);
  if (sourceIp) return `ip:${sourceIp}`;
  const origin = readHeader(input.headers, 'origin');
  if (origin) return `origin:${origin}`;
  return 'origin:unknown-express';
}

export function resolveRequestOriginRateLimitKeyFromFetchHeaders(headers: HeaderBag): string {
  const sourceIp = resolveSourceIpFromFetchHeaders(headers);
  if (sourceIp) return `ip:${sourceIp}`;
  const origin = readHeader(headers, 'origin');
  if (origin) return `origin:${origin}`;
  return 'origin:unknown-fetch';
}
