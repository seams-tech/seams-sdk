import {
  persistStoredThresholdEd25519SessionClientBase,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEd25519SessionStoreSource } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  buildNearTransactionSigningLane,
} from '@/core/signingEngine/session/signingSession/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/signingSession/types';
import type { WarmSessionCapabilityReader } from '@/core/signingEngine/session/warmSigning/types';
import type { NearResolvedEd25519SigningSessionState } from '@/core/signingEngine/interfaces/near';
import { THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR } from './thresholdAuthMode';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';

export type ResolvedThresholdEd25519SessionState = NearResolvedEd25519SigningSessionState;

function resolveEd25519PasskeyStorageSource(
  source: ThresholdEd25519SessionStoreSource | undefined,
): Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'> {
  return source && source !== 'email_otp' ? source : 'login';
}

export function resolveThresholdEd25519SessionStateFromRecord(
  record: ThresholdEd25519SessionRecord | undefined,
): ResolvedThresholdEd25519SessionState | null {
  if (!record) return null;
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(record.walletSigningSessionId || '').trim();
  if (!thresholdSessionId || !walletSigningSessionId) return null;
  const sessionKind: 'jwt' | 'cookie' =
    record.thresholdSessionKind === 'cookie' ? 'cookie' : 'jwt';
  const thresholdSessionAuthToken = String(record.thresholdSessionAuthToken || '').trim();
  if (sessionKind === 'jwt' && !thresholdSessionAuthToken) return null;
  const signingLane =
    record.source === 'email_otp'
      ? buildNearTransactionSigningLane({
          accountId: record.nearAccountId,
          authMethod: 'email_otp',
          walletSigningSessionId:
            SigningSessionIds.walletSigningSession(walletSigningSessionId),
          thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
          retention: record.emailOtpAuthContext?.retention || 'session',
          sessionOrigin:
            record.emailOtpAuthContext?.reason === 'login' ? 'login' : 'per_operation',
        })
      : buildNearTransactionSigningLane({
          accountId: record.nearAccountId,
          authMethod: 'passkey',
          walletSigningSessionId:
            SigningSessionIds.walletSigningSession(walletSigningSessionId),
          thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
          storageSource: resolveEd25519PasskeyStorageSource(record.source),
        });
  const xClientBaseB64u = String(record.xClientBaseB64u || '').trim();
  const common = {
    thresholdSessionId,
    walletSigningSessionId,
    signingLane,
    remainingUses: Math.max(0, Math.floor(Number(record.remainingUses) || 0)),
    ...(xClientBaseB64u ? { xClientBaseB64u } : {}),
    signingRootId: record.runtimePolicyScope
      ? signingRootScopeFromRuntimePolicyScope(record.runtimePolicyScope).signingRootId
      : '',
    relayerUrl: String(record.relayerUrl || '').trim(),
    persistClientBase: (xClientBaseB64u: string) =>
      Boolean(
        persistStoredThresholdEd25519SessionClientBase({
          thresholdSessionId,
          xClientBaseB64u,
        }),
      ),
  };
  return sessionKind === 'jwt'
    ? {
        ...common,
        sessionKind,
        thresholdSessionAuthToken,
      }
    : {
        ...common,
        sessionKind,
      };
}

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
  const state = resolveThresholdEd25519SessionStateFromRecord(record);
  if (!state) {
    throw new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
  }
  return state;
}
