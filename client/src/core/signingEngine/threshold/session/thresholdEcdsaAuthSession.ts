import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';
import type { ThresholdEcdsaSessionPolicy } from './thresholdSessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';

export type ThresholdEcdsaSessionKind = 'jwt' | 'cookie';

export type ThresholdEcdsaAuthSession = {
  sessionKind: ThresholdEcdsaSessionKind;
  policy: ThresholdEcdsaSessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
  jwt?: string;
  expiresAtMs?: number;
};

type ThresholdEcdsaAuthSessionCacheEntry = ThresholdEcdsaAuthSession;

const authSessionCache = new Map<string, ThresholdEcdsaAuthSessionCacheEntry>();

export function makeThresholdEcdsaAuthSessionCacheKey(args: {
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

export function getCachedThresholdEcdsaAuthSession(cacheKey: string): ThresholdEcdsaAuthSession | null {
  const entry = authSessionCache.get(cacheKey);
  if (!entry) return null;

  if (typeof entry.expiresAtMs === 'number' && Number.isFinite(entry.expiresAtMs) && Date.now() >= entry.expiresAtMs) {
    authSessionCache.delete(cacheKey);
    return null;
  }

  return entry;
}

export function putCachedThresholdEcdsaAuthSession(cacheKey: string, entry: ThresholdEcdsaAuthSession): void {
  authSessionCache.set(cacheKey, entry);
}

export function clearCachedThresholdEcdsaAuthSession(cacheKey: string): void {
  authSessionCache.delete(cacheKey);
}

export function clearAllCachedThresholdEcdsaAuthSessions(): void {
  authSessionCache.clear();
}

export function getCachedThresholdEcdsaAuthSessionJwt(cacheKey: string): string | undefined {
  const cached = getCachedThresholdEcdsaAuthSession(cacheKey);
  const jwt = cached?.jwt;
  if (typeof jwt === 'string') {
    const trimmed = jwt.trim();
    if (trimmed) return trimmed;
  }
  if (cached) clearCachedThresholdEcdsaAuthSession(cacheKey);
  return undefined;
}
