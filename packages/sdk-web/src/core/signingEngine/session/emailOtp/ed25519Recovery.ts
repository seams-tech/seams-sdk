import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  upsertThresholdEd25519SessionFact,
} from '@/core/signingEngine/session/persistence/records';
import type {
  RestorePersistedEd25519SessionPurpose,
  RestoreSealedRecordResult,
} from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import {
  recordAndVerifyRestoredWarmSessions,
  type RestoredWarmSessionStatus,
} from '@/core/signingEngine/session/sealedRecovery/readback';
import {
  sealedRecoverySessionKind,
  sealedRecoveryWalletSessionJwt,
  type EmailOtpEd25519SealedRecoveryRecord,
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EmailOtpEcdsaSealedRecoveryRecordInput,
  EmailOtpThresholdEcdsaRehydrateResult,
} from './ecdsaRecovery';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextRetention,
} from '../identity/laneIdentity';

export type EmailOtpEd25519RestorePurpose = RestorePersistedEd25519SessionPurpose & {
  authMethod: 'email_otp';
};

export function buildEmailOtpEd25519RecordFromSealedRestoreMetadata(args: {
  walletId: string;
  rpId: string;
  record: EmailOtpEd25519SealedRecoveryRecord;
  purpose: EmailOtpEd25519RestorePurpose;
}): ThresholdEd25519SessionRecord | null {
  const existing = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
    args.purpose.thresholdSessionId,
  );
  if (String(args.walletId || '').trim() !== String(args.record.walletId || '').trim()) {
    return null;
  }
  if (
    existing?.source === 'email_otp' &&
    existing.emailOtpAuthContext &&
    emailOtpAuthContextRetention(existing.emailOtpAuthContext) === 'session' &&
    existing.signingGrantId === args.purpose.signingGrantId
  ) {
    return existing;
  }
  const sealedSessionKeyVersion = String(args.record.keyVersion || '').trim();
  if (!sealedSessionKeyVersion) return null;
  const rpId = String(args.rpId || '').trim();
  if (!rpId) return null;
  const routerAbNormalSigning = args.record.routerAbNormalSigning;
  if (!routerAbNormalSigning) return null;
  return upsertThresholdEd25519SessionFact({
    walletId: args.record.walletId,
    nearAccountId: args.record.nearAccountId,
    nearEd25519SigningKeyId: args.record.nearEd25519SigningKeyId,
    rpId,
    relayerUrl: args.record.relayerUrl,
    relayerKeyId: args.record.relayerKeyId,
    ...(args.record.runtimePolicyScope ? { runtimePolicyScope: args.record.runtimePolicyScope } : {}),
    routerAbNormalSigning,
    participantIds: [...args.record.participantIds],
    signerSlot: args.record.signerSlot,
    thresholdSessionKind: sealedRecoverySessionKind(args.record.walletSessionAuth),
    thresholdSessionId: args.purpose.thresholdSessionId,
    signingGrantId: args.purpose.signingGrantId,
    ...(sealedRecoveryWalletSessionJwt(args.record.walletSessionAuth)
      ? {
          walletSessionJwt: sealedRecoveryWalletSessionJwt(
            args.record.walletSessionAuth,
          )!,
        }
      : {}),
    expiresAtMs: args.record.expiresAtMs,
    remainingUses: args.record.remainingUses,
    emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
      policy: 'session',
      walletId: toWalletId(args.record.authority.walletId),
      emailHashHex: args.record.authority.verifier.emailHashHex,
      retention: 'session',
      reason: 'login',
      provider: args.record.authority.factor.provider,
      providerUserId: args.record.authority.factor.providerUserId,
    }),
    source: 'email_otp',
  });
}

export async function restoreEmailOtpEd25519SealedRecordForAccount(args: {
  walletId: string;
  rpId: string;
  record: EmailOtpEd25519SealedRecoveryRecord;
  purpose: EmailOtpEd25519RestorePurpose;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  readWarmSessionStatusFromWorker: (sessionId: string) => Promise<WarmSessionStatusResult>;
  recordSessionMaterialRestored: (
    sessionId: string,
    status: RestoredWarmSessionStatus,
  ) => Promise<void>;
  restoreEcdsaSigningSessionMaterialFromSealedRecord: (
    args: EmailOtpEcdsaSealedRecoveryRecordInput,
  ) => Promise<EmailOtpThresholdEcdsaRehydrateResult | null>;
}): Promise<RestoreSealedRecordResult> {
  const ed25519Record = buildEmailOtpEd25519RecordFromSealedRestoreMetadata(args);
  if (!ed25519Record) return 'deferred';
  const existingStatus = await args
    .readWarmSessionStatusFromWorker(args.purpose.thresholdSessionId)
    .catch(() => null);
  if (existingStatus?.ok) return 'ready';
  const ecdsaSealedRecord = args.record.companionEcdsaRecovery;
  if (!ecdsaSealedRecord) return 'deferred';
  const ecdsaThresholdSessionId = ecdsaSealedRecord.thresholdSessionId;
  const ecdsaRecord = args.getThresholdEcdsaSessionRecordByThresholdSessionId(
    ecdsaThresholdSessionId,
  );
  const restored = await args
    .restoreEcdsaSigningSessionMaterialFromSealedRecord({
      sealedRecord: ecdsaSealedRecord,
      ecdsaRecord,
      ed25519Record,
    })
    .catch((error) => {
      console.warn('[EmailOtpSession] exact-purpose Ed25519 sealed restore failed', {
        walletId: args.walletId,
        nearAccountId: args.record.nearAccountId,
        thresholdSessionId: args.purpose.thresholdSessionId,
        ecdsaThresholdSessionId,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
      return null;
    });
  if (!restored?.ed25519RestoreSeedB64u) return 'deferred';
  return await recordAndVerifyRestoredWarmSessions({
    sessionIds: [ecdsaThresholdSessionId, args.purpose.thresholdSessionId],
    restoredStatus: {
      ok: true,
      remainingUses: restored.remainingUses,
      expiresAtMs: restored.expiresAtMs,
    },
    recordSessionMaterialRestored: args.recordSessionMaterialRestored,
    verifySessionId: args.purpose.thresholdSessionId,
    readWarmSessionStatus: args.readWarmSessionStatusFromWorker,
  });
}
