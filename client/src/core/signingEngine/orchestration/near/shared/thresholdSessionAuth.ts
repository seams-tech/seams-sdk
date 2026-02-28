import {
  clearCachedEd25519AuthSession,
  getCachedEd25519AuthSession,
  resolveEd25519AuthSessionBySessionId,
} from '@/core/signingEngine/threshold/session/ed25519AuthSession';
import { normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import { emitThresholdSessionMetric } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionMetrics';

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
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const cachedAuthSession = getCachedEd25519AuthSession(args.thresholdSessionCacheKey);
  if (cachedAuthSession) {
    const cachedSessionId = String(cachedAuthSession.policy?.sessionId || '').trim();
    if (thresholdSessionId && cachedSessionId && cachedSessionId !== thresholdSessionId) {
      emitThresholdSessionMetric({
        metric: 'session_mismatch',
        curve: 'ed25519',
        source: 'auth-session-cache',
        sessionId: thresholdSessionId,
        reason: 'cache_key_session_id_mismatch',
      });
      clearCachedEd25519AuthSession(args.thresholdSessionCacheKey);
    } else if (cachedAuthSession.sessionKind === 'cookie') {
      return { sessionKind: 'cookie' };
    } else {
      const jwtFromCache = normalizeOptionalNonEmptyString(cachedAuthSession.jwt);
      if (jwtFromCache) {
        return {
          sessionKind: 'jwt',
          thresholdSessionJwt: jwtFromCache,
        };
      }
    }
  }
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
