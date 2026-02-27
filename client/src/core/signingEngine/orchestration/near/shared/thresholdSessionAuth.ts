import {
  getCachedEd25519AuthSessionJwt,
  getCachedEd25519AuthSessionJwtBySessionId,
} from '@/core/signingEngine/threshold/session/ed25519AuthSession';

export function resolveThresholdSessionJwt(args: {
  thresholdSessionCacheKey: string;
  thresholdSessionId: string;
}): string | undefined {
  const fromCacheKey = getCachedEd25519AuthSessionJwt(args.thresholdSessionCacheKey);
  if (fromCacheKey) return fromCacheKey;

  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return undefined;

  return getCachedEd25519AuthSessionJwtBySessionId(thresholdSessionId);
}
