import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import type { WarmSessionCapabilityReader } from '@/core/signingEngine/session/WarmSessionServiceTypes';
import { THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR } from './thresholdAuthMode';

export type ResolvedThresholdEd25519SessionState = {
  record: ThresholdEd25519SessionRecord;
  sessionKind: 'jwt' | 'cookie';
  thresholdSessionJwt?: string;
  xClientBaseB64u?: string;
  relayerUrl: string;
};

export function requireResolvedThresholdEd25519SessionState(args: {
  signingSessionCoordinator: WarmSessionCapabilityReader;
  thresholdSessionId: string;
}): ResolvedThresholdEd25519SessionState {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) {
    throw new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
  }
  const record = args.signingSessionCoordinator.resolveEd25519RecordByThresholdSessionId(
    thresholdSessionId,
  );
  if (!record) {
    throw new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
  }
  const sessionKind: 'jwt' | 'cookie' =
    record.thresholdSessionKind === 'cookie' ? 'cookie' : 'jwt';
  const thresholdSessionJwt = String(record.thresholdSessionJwt || '').trim() || undefined;
  if (sessionKind === 'jwt' && !thresholdSessionJwt) {
    throw new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
  }
  return {
    record,
    sessionKind,
    thresholdSessionJwt,
    xClientBaseB64u: String(record.xClientBaseB64u || '').trim() || undefined,
    relayerUrl: String(record.relayerUrl || '').trim(),
  };
}
