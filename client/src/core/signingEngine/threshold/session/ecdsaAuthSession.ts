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
const authSessionCacheKeyBySessionId = new Map<string, string>();
const authSessionSessionIdByCacheKey = new Map<string, string>();

function toSessionId(value: unknown): string {
  return String(value || '').trim();
}

function clearSessionIndexesForCacheKey(cacheKey: string): void {
  const indexedSessionId = authSessionSessionIdByCacheKey.get(cacheKey);
  if (!indexedSessionId) return;

  authSessionSessionIdByCacheKey.delete(cacheKey);
  const indexedCacheKey = authSessionCacheKeyBySessionId.get(indexedSessionId);
  if (indexedCacheKey === cacheKey) {
    authSessionCacheKeyBySessionId.delete(indexedSessionId);
  }
}

function setSessionIndexes(cacheKey: string, sessionId: string): void {
  const existingCacheKey = authSessionCacheKeyBySessionId.get(sessionId);
  if (existingCacheKey && existingCacheKey !== cacheKey) {
    authSessionCache.delete(existingCacheKey);
    authSessionSessionIdByCacheKey.delete(existingCacheKey);
  }

  authSessionCacheKeyBySessionId.set(sessionId, cacheKey);
  authSessionSessionIdByCacheKey.set(cacheKey, sessionId);
}

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
    clearCachedEcdsaAuthSession(cacheKey);
    return null;
  }

  return entry;
}

export function putCachedEcdsaAuthSession(cacheKey: string, entry: EcdsaAuthSession): void {
  clearSessionIndexesForCacheKey(cacheKey);
  authSessionCache.set(cacheKey, entry);

  const sessionId = toSessionId(entry?.policy?.sessionId);
  if (!sessionId) return;
  setSessionIndexes(cacheKey, sessionId);
}

export function clearCachedEcdsaAuthSession(cacheKey: string): void {
  authSessionCache.delete(cacheKey);
  clearSessionIndexesForCacheKey(cacheKey);
}

export function clearAllCachedEcdsaAuthSessions(): void {
  authSessionCache.clear();
  authSessionCacheKeyBySessionId.clear();
  authSessionSessionIdByCacheKey.clear();
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

export function getCachedEcdsaAuthSessionBySessionId(sessionIdRaw: string): EcdsaAuthSession | null {
  const sessionId = toSessionId(sessionIdRaw);
  if (!sessionId) return null;

  const cacheKey = authSessionCacheKeyBySessionId.get(sessionId);
  if (!cacheKey) return null;

  const entry = getCachedEcdsaAuthSession(cacheKey);
  if (!entry) return null;

  const indexedSessionId = authSessionSessionIdByCacheKey.get(cacheKey);
  if (indexedSessionId !== sessionId) {
    // Defensive self-heal in case an external mutation changed session id without re-indexing.
    authSessionCacheKeyBySessionId.delete(sessionId);
    if (indexedSessionId) authSessionCacheKeyBySessionId.set(indexedSessionId, cacheKey);
    return null;
  }

  return entry;
}

export function getCachedEcdsaAuthSessionJwtBySessionId(sessionIdRaw: string): string | undefined {
  const cached = getCachedEcdsaAuthSessionBySessionId(sessionIdRaw);
  const jwt = cached?.jwt;
  if (typeof jwt !== 'string') return undefined;
  const trimmed = jwt.trim();
  if (!trimmed) return undefined;
  return trimmed;
}
