import {
  thresholdEd25519LaneCandidateFromSessionRecord,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  emailOtpAuthContextReason,
  emailOtpAuthContextRetention,
  type ThresholdEd25519SessionStoreSource,
} from '@/core/signingEngine/session/identity/laneIdentity';
import { buildNearTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import type { NearResolvedEd25519SigningSessionState } from '@/core/signingEngine/interfaces/near';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  parseRouterAbEd25519SigningWalletSessionFromRecord,
  type RouterAbEd25519SigningWalletSession,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';

export type ResolvedRouterAbEd25519WalletSessionState =
  NearResolvedEd25519SigningSessionState & {
    signingWalletSession: RouterAbEd25519SigningWalletSession;
  };

function resolveEd25519PasskeyStorageSource(
  source: ThresholdEd25519SessionStoreSource | undefined,
): Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'> {
  return source && source !== 'email_otp' ? source : 'login';
}

export function resolveRouterAbEd25519WalletSessionStateFromRecord(
  record: ThresholdEd25519SessionRecord | undefined,
): ResolvedRouterAbEd25519WalletSessionState | null {
  if (!record) return null;
  const signingWalletSession = classifyRouterAbEd25519PersistedSigningRecord(record);
  if (signingWalletSession.kind !== 'ready') return null;
  return resolveRouterAbEd25519WalletSessionStateFromParsedSession({
    record,
    signingWalletSession: signingWalletSession.value,
  });
}

export function resolveRouterAbEd25519WalletSessionStateForOperation(args: {
  record: ThresholdEd25519SessionRecord;
  nowMs: number;
}): ResolvedRouterAbEd25519WalletSessionState | null {
  const signingWalletSession = classifyRouterAbEd25519PersistedSigningRecord(
    args.record,
    args.nowMs,
  );
  if (signingWalletSession.kind !== 'ready') return null;
  return resolveRouterAbEd25519WalletSessionStateFromParsedSession({
    record: args.record,
    signingWalletSession: signingWalletSession.value,
  });
}

export function resolveRouterAbEd25519WalletSessionStateFromCurrentRecord(
  record: ThresholdEd25519SessionRecord | undefined,
): ResolvedRouterAbEd25519WalletSessionState | null {
  if (!record) return null;
  const signingWalletSession = parseRouterAbEd25519SigningWalletSessionFromRecord(record);
  if (!signingWalletSession.ok) return null;
  return resolveRouterAbEd25519WalletSessionStateFromParsedSession({
    record,
    signingWalletSession: signingWalletSession.value,
  });
}

function resolveRouterAbEd25519WalletSessionStateFromParsedSession(args: {
  record: ThresholdEd25519SessionRecord;
  signingWalletSession: RouterAbEd25519SigningWalletSession;
}): ResolvedRouterAbEd25519WalletSessionState | null {
  const record = args.record;
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  const signingGrantId = String(record.signingGrantId || '').trim();
  const relayerUrl = String(record.relayerUrl || '').trim();
  if (!thresholdSessionId || !signingGrantId || !relayerUrl) return null;

  const recordCandidate = thresholdEd25519LaneCandidateFromSessionRecord({ record });
  if (!recordCandidate) return null;
  const emailOtpAuthContext =
    record.source === 'email_otp' ? record.emailOtpAuthContext : null;
  const signingLane =
    record.source === 'email_otp'
      ? recordCandidate.auth.kind === 'email_otp' && emailOtpAuthContext
        ? buildNearTransactionSigningLane({
            walletId: record.walletId,
            nearAccountId: record.nearAccountId,
            nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
            signerSlot: recordCandidate.signerSlot,
            auth: recordCandidate.auth,
            signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
            thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
            retention: emailOtpAuthContextRetention(emailOtpAuthContext),
            sessionOrigin:
              emailOtpAuthContextReason(emailOtpAuthContext) === 'login'
                ? 'login'
                : 'per_operation',
          })
        : null
      : recordCandidate.auth.kind === 'passkey'
        ? buildNearTransactionSigningLane({
            walletId: record.walletId,
            nearAccountId: record.nearAccountId,
            nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
            signerSlot: recordCandidate.signerSlot,
            auth: recordCandidate.auth,
            signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
            thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
            storageSource: resolveEd25519PasskeyStorageSource(record.source),
          })
        : null;
  if (!signingLane) return null;

  return {
    walletSessionAuth: args.signingWalletSession.auth,
    thresholdSessionId,
    signingGrantId,
    signingLane,
    remainingUses: args.signingWalletSession.remainingUses,
    signingRootId: args.signingWalletSession.signingRootId,
    signingRootVersion: args.signingWalletSession.signingRootVersion,
    routerAbNormalSigning: args.signingWalletSession.routerAbNormalSigning,
    runtimePolicyScope: args.signingWalletSession.runtimePolicyScope,
    relayerUrl,
    signingWalletSession: args.signingWalletSession,
  };
}
