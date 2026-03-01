import { toOptionalTrimmedString, toRorOriginOrNull } from '@shared/utils/validation';

export function normalizeCsv(valuesRaw: unknown): string[] {
  const values = String(valuesRaw ?? '').trim();
  if (!values) return [];
  return values
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

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

export type WellKnownSigningSessionSealCapabilities =
  | { mode: 'none' }
  | {
      mode: 'sealed_refresh_v1';
      keyVersion?: string;
      shamirPrimeB64u: string;
    };

export function normalizeWellKnownSigningSessionSealCapabilities(
  value: unknown,
): WellKnownSigningSessionSealCapabilities | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const obj = value as Record<string, unknown>;
  const mode = String(obj.mode || '')
    .trim()
    .toLowerCase();
  if (mode === 'none') return { mode: 'none' };
  if (mode !== 'sealed_refresh_v1') return null;

  const shamirPrimeB64u = toOptionalTrimmedString(obj.shamirPrimeB64u);
  if (!shamirPrimeB64u) return null;

  const keyVersion = toOptionalTrimmedString(obj.keyVersion);
  return {
    mode: 'sealed_refresh_v1',
    shamirPrimeB64u,
    ...(keyVersion ? { keyVersion } : {}),
  };
}

export function resolveWellKnownSigningSessionSealCapabilities(
  prfSessionSealOptionsRaw: unknown,
): WellKnownSigningSessionSealCapabilities {
  if (!prfSessionSealOptionsRaw || typeof prfSessionSealOptionsRaw !== 'object') {
    return { mode: 'none' };
  }
  const options = prfSessionSealOptionsRaw as { capabilities?: unknown };
  const normalized = normalizeWellKnownSigningSessionSealCapabilities(options.capabilities);
  return normalized || { mode: 'none' };
}
