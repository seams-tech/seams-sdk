import { toOptionalTrimmedString, toRorOriginOrNull } from '@shared/utils/validation';

export function sanitizeRorOrigins(origins: unknown): string[] {
  const list = Array.isArray(origins) ? origins : [];
  const out = new Set<string>();
  for (const raw of list) {
    const normalized = toRorOriginOrNull(raw);
    if (normalized) out.add(normalized);
  }
  return Array.from(out);
}

export function normalizeRorHost(hostRaw: unknown): string | null {
  const host = toOptionalTrimmedString(hostRaw);
  if (!host) return null;
  try {
    return new URL(`https://${host}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}
