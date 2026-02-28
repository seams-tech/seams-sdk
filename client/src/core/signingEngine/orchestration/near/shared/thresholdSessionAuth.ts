import {
  getCachedEd25519AuthSessionJwt,
  getCachedEd25519AuthSessionJwtBySessionId,
} from '@/core/signingEngine/threshold/session/ed25519AuthSession';

export async function resolveThresholdSessionJwt(args: {
  thresholdSessionCacheKey: string;
  thresholdSessionId: string;
}): Promise<string | undefined> {
  const fromCacheKey = getCachedEd25519AuthSessionJwt(args.thresholdSessionCacheKey);
  if (fromCacheKey) return fromCacheKey;

  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return undefined;

  return await getCachedEd25519AuthSessionJwtBySessionId(thresholdSessionId);
}
