import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningSessionSealedStoreRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
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
  const record = input.sealedRecord;
  if (record.authMethod !== 'email_otp') return null;
  if (String(record.thresholdSessionIds.ecdsa || '').trim() !== thresholdSessionId) return null;
  const ecdsaRestore = record.ecdsaRestore;
  if (!ecdsaRestore) return null;
  if (
    thresholdEcdsaChainTargetKey(ecdsaRestore.chainTarget) !==
    thresholdEcdsaChainTargetKey(input.chainTarget)
  ) {
    return null;
  }
  if (Math.floor(Number(record.expiresAtMs) || 0) <= Date.now()) return null;
  if (ecdsaRestore.sessionKind !== 'jwt') return null;
  const jwt = String(ecdsaRestore.thresholdSessionAuthToken || '').trim();
  if (!jwt) return null;
  const lane = resolveEmailOtpAuthLane({
    routeAuth: { kind: 'threshold_session', jwt },
    thresholdSessionId,
    authorizingWalletSigningSessionId: record.walletSigningSessionId,
    curve: 'ecdsa',
    chainTarget: ecdsaRestore.chainTarget,
  });
  return lane?.kind === 'signing_session' && lane.curve === 'ecdsa' ? lane : null;
}
