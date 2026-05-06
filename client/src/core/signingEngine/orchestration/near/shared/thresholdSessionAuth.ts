import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import type { WarmSessionCapabilityReader } from '@/core/signingEngine/session/warmSigning/types';
import { THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR } from './thresholdAuthMode';

export type ResolvedThresholdEd25519SessionState = {
  record: ThresholdEd25519SessionRecord;
  sessionKind: 'jwt' | 'cookie';
  thresholdSessionAuthToken?: string;
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
  const thresholdSessionAuthToken = String(record.thresholdSessionAuthToken || '').trim() || undefined;
  if (sessionKind === 'jwt' && !thresholdSessionAuthToken) {
    throw new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
  }
  return {
    record,
    sessionKind,
    thresholdSessionAuthToken,
    xClientBaseB64u: String(record.xClientBaseB64u || '').trim() || undefined,
    relayerUrl: String(record.relayerUrl || '').trim(),
  };
}
