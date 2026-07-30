import {
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_GROUP_ID,
  type SigningSessionSealProtocol,
} from '@shared/utils/signingSessionSeal';
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
      protocol: SigningSessionSealProtocol;
      currentKeyVersion: string;
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

  const protocolRaw = obj.protocol;
  if (!protocolRaw || typeof protocolRaw !== 'object' || Array.isArray(protocolRaw)) return null;
  const protocol = protocolRaw as Record<string, unknown>;
  const algorithm = toOptionalTrimmedString(protocol.algorithm);
  const groupId = toOptionalTrimmedString(protocol.groupId);
  const currentKeyVersion = toOptionalTrimmedString(obj.currentKeyVersion);
  if (
    algorithm !== SIGNING_SESSION_SEAL_ALG ||
    groupId !== SIGNING_SESSION_SEAL_GROUP_ID ||
    !currentKeyVersion
  ) {
    return null;
  }
  return {
    mode: 'sealed_refresh_v1',
    protocol: {
      algorithm: SIGNING_SESSION_SEAL_ALG,
      groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    },
    currentKeyVersion,
  };
}

export function resolveWellKnownSigningSessionSealCapabilities(
  signingSessionSealOptionsRaw: unknown,
): WellKnownSigningSessionSealCapabilities {
  if (!signingSessionSealOptionsRaw || typeof signingSessionSealOptionsRaw !== 'object') {
    return { mode: 'none' };
  }
  const options = signingSessionSealOptionsRaw as { capabilities?: unknown };
  const normalized = normalizeWellKnownSigningSessionSealCapabilities(options.capabilities);
  return normalized || { mode: 'none' };
}
