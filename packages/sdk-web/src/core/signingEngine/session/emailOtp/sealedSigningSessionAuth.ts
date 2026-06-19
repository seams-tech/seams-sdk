import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningSessionSealedStoreRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  normalizeSealedRecoveryRecord,
  sealedRecoveryWalletSessionJwt,
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import {
  resolveEmailOtpAuthLane,
  type EmailOtpSigningSessionAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';

export type SealedEmailOtpEcdsaSigningSessionAuthInput = {
  thresholdSessionId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  sealedRecord: SigningSessionSealedStoreRecord;
};

export function emailOtpEcdsaSigningSessionAuthLaneFromSealedRecord(
  input: SealedEmailOtpEcdsaSigningSessionAuthInput,
): EmailOtpSigningSessionAuthLane | null {
  const thresholdSessionId = String(input.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;
  const normalized = normalizeSealedRecoveryRecord(input.sealedRecord, {
    allowExhausted: true,
  });
  if (
    normalized.kind !== 'accepted' ||
    normalized.record.authMethod !== 'email_otp' ||
    normalized.record.curve !== 'ecdsa'
  ) {
    return null;
  }
  const record = normalized.record;
  if (record.authMethod !== 'email_otp') return null;
  if (String(record.thresholdSessionId || '').trim() !== thresholdSessionId) return null;
  if (
    thresholdEcdsaChainTargetKey(record.chainTarget) !==
    thresholdEcdsaChainTargetKey(input.chainTarget)
  ) {
    return null;
  }
  if (Math.floor(Number(record.expiresAtMs) || 0) <= Date.now()) return null;
  const jwt = sealedRecoveryWalletSessionJwt(record.walletSessionAuth);
  if (!jwt) return null;
  const lane = resolveEmailOtpAuthLane({
    routeAuth: { kind: 'wallet_session', jwt },
    thresholdSessionId,
    authorizingSigningGrantId: record.signingGrantId,
    curve: 'ecdsa',
    chainTarget: record.chainTarget,
  });
  return lane?.kind === 'signing_session' && lane.curve === 'ecdsa' ? lane : null;
}
