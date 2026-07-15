import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  CurrentSealedSessionRecord,
  SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { ExactEcdsaSigningLaneIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  normalizeSealedRecoveryRecord,
  sealedRecoveryWalletSessionJwt,
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import {
  resolveEmailOtpAuthLane,
  type EmailOtpSigningSessionAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import {
  buildEmailOtpEcdsaSigningSessionAuthority,
  type EmailOtpEcdsaSigningSessionAuthority,
} from './ecdsaSigningSessionAuthority';

export type SealedEmailOtpEcdsaSigningSessionAuthInput = {
  lane: ExactEcdsaSigningLaneIdentity;
  sealedRecord: SigningSessionSealedStoreRecord;
};

export function emailOtpEcdsaSigningSessionAuthLaneFromSealedRecord(
  input: SealedEmailOtpEcdsaSigningSessionAuthInput,
): EmailOtpSigningSessionAuthLane | null {
  return emailOtpEcdsaSigningSessionAuthorityFromSealedRecord(input)?.authLane || null;
}

export function emailOtpEcdsaSigningSessionAuthorityFromSealedRecord(
  input: SealedEmailOtpEcdsaSigningSessionAuthInput,
): EmailOtpEcdsaSigningSessionAuthority | null {
  const thresholdSessionId = String(input.lane.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;
  if (input.lane.auth.kind !== 'email_otp') return null;
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
  const signer = input.lane.signer;
  if (record.authMethod !== 'email_otp') return null;
  if (String(record.walletId || '').trim() !== String(signer.walletId)) return null;
  if (String(record.thresholdSessionId || '').trim() !== thresholdSessionId) return null;
  if (String(record.signingGrantId || '').trim() !== String(input.lane.signingGrantId)) return null;
  if (String(record.keyHandle || '').trim() !== String(signer.keyHandle)) return null;
  if (String(record.ecdsaThresholdKeyId || '').trim() !== String(signer.key.ecdsaThresholdKeyId)) {
    return null;
  }
  if (
    String(record.authority.factor.providerUserId || '').trim() !==
    String(input.lane.auth.providerSubjectId)
  ) {
    return null;
  }
  if (
    thresholdEcdsaChainTargetKey(record.chainTarget) !==
    thresholdEcdsaChainTargetKey(signer.chainTarget)
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
  return buildEmailOtpEcdsaSigningSessionAuthority({
    authLane: lane,
    authority: record.authority,
  });
}

export function exactEmailOtpEcdsaSigningSessionAuthorityFromSealedRecords(args: {
  lane: ExactEcdsaSigningLaneIdentity;
  sealedRecords: readonly CurrentSealedSessionRecord[];
}): EmailOtpEcdsaSigningSessionAuthority | null {
  const exactAuthorities: EmailOtpEcdsaSigningSessionAuthority[] = [];
  for (const sealedRecord of args.sealedRecords) {
    const authority = emailOtpEcdsaSigningSessionAuthorityFromSealedRecord({
      lane: args.lane,
      sealedRecord,
    });
    if (authority) exactAuthorities.push(authority);
  }
  if (exactAuthorities.length > 1) {
    throw new Error(
      '[SigningEngine][ecdsa] multiple durable Email OTP authorities matched one exact lane',
    );
  }
  return exactAuthorities[0] ?? null;
}
