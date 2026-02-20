import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';
import type { EcdsaSessionPolicy } from './sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';

export type EcdsaSessionKind = 'jwt' | 'cookie';

export type EcdsaAuthSession = {
  sessionKind: EcdsaSessionKind;
  policy: EcdsaSessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
  jwt?: string;
  expiresAtMs?: number;
};

type EcdsaAuthSessionCacheEntry = EcdsaAuthSession;

const authSessionCache = new Map<string, EcdsaAuthSessionCacheEntry>();

export function makeEcdsaAuthSessionCacheKey(args: {
  userId: string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds?: number[];
}): string {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(args.relayerUrl));
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  return [
    String(args.userId || '').trim(),
    String(args.rpId || '').trim(),
    relayerUrl,
    String(args.relayerKeyId || '').trim(),
    ...(participantIds ? [participantIds.join(',')] : []),
  ].join('|');
}

export function getCachedEcdsaAuthSession(cacheKey: string): EcdsaAuthSession | null {
  const entry = authSessionCache.get(cacheKey);
  if (!entry) return null;

  if (typeof entry.expiresAtMs === 'number' && Number.isFinite(entry.expiresAtMs) && Date.now() >= entry.expiresAtMs) {
    authSessionCache.delete(cacheKey);
    return null;
  }

  return entry;
}

export function putCachedEcdsaAuthSession(cacheKey: string, entry: EcdsaAuthSession): void {
  authSessionCache.set(cacheKey, entry);
}

export function clearCachedEcdsaAuthSession(cacheKey: string): void {
  authSessionCache.delete(cacheKey);
}

export function clearAllCachedEcdsaAuthSessions(): void {
  authSessionCache.clear();
}

export function getCachedEcdsaAuthSessionJwt(cacheKey: string): string | undefined {
  const cached = getCachedEcdsaAuthSession(cacheKey);
  const jwt = cached?.jwt;
  if (typeof jwt === 'string') {
    const trimmed = jwt.trim();
    if (trimmed) return trimmed;
  }
  if (cached) clearCachedEcdsaAuthSession(cacheKey);
  return undefined;
}
