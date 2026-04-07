import {
  getCachedEd25519AuthSession,
  resolveEd25519AuthSessionBySessionId,
} from '@/core/signingEngine/threshold/session/ed25519AuthSession';
import { normalizeOptionalNonEmptyString } from '@shared/utils/normalize';

export type ResolvedThresholdSessionAuth = {
  sessionKind: 'jwt' | 'cookie';
  thresholdSessionJwt?: string;
};

export async function resolveThresholdSessionJwt(args: {
  thresholdSessionCacheKey: string;
  thresholdSessionId: string;
}): Promise<string | undefined> {
  const resolved = await resolveThresholdSessionAuth(args);
  if (!resolved || resolved.sessionKind !== 'jwt') return undefined;
  return resolved.thresholdSessionJwt;
}

export async function resolveThresholdSessionAuth(args: {
  thresholdSessionCacheKey: string;
  thresholdSessionId: string;
}): Promise<ResolvedThresholdSessionAuth | undefined> {
  const cachedAuthSession = getCachedEd25519AuthSession(args.thresholdSessionCacheKey);
  if (cachedAuthSession) {
    if (cachedAuthSession.sessionKind === 'cookie') {
      return { sessionKind: 'cookie' };
    }
    const jwtFromCache = normalizeOptionalNonEmptyString(cachedAuthSession.jwt);
    if (jwtFromCache) {
      return {
        sessionKind: 'jwt',
        thresholdSessionJwt: jwtFromCache,
      };
    }
  }
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return undefined;

  const bySessionId = await resolveEd25519AuthSessionBySessionId(thresholdSessionId);
  if (!bySessionId) return undefined;
  if (bySessionId.sessionKind === 'cookie') {
    return { sessionKind: 'cookie' };
  }
  const jwt = normalizeOptionalNonEmptyString(bySessionId.jwt);
  if (!jwt) return undefined;
  return {
    sessionKind: 'jwt',
    thresholdSessionJwt: jwt,
  };
}

export function resolveCanonicalThresholdSessionId(args: {
  thresholdSessionCacheKey: string;
  fallbackSessionId: string;
}): string {
  const cachedSessionId = String(
    getCachedEd25519AuthSession(args.thresholdSessionCacheKey)?.policy?.sessionId || '',
  ).trim();
  const fallbackSessionId = String(args.fallbackSessionId || '').trim();
  return cachedSessionId || fallbackSessionId;
}
