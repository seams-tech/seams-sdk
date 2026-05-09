import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { normalizeThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  RestorePersistedEd25519SessionPurpose,
  RestoreSealedRecordForAccountResult,
} from '@/core/signingEngine/session/sealedRecovery/types';
import {
  recordAndVerifyRestoredWarmSessions,
  type RestoredWarmSessionStatus,
} from '@/core/signingEngine/session/sealedRecovery/readback';
import type { SigningSessionSealedStoreRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/types';
import type {
  EmailOtpEcdsaSealedRecoveryRecordInput,
  EmailOtpThresholdEcdsaRehydrateResult,
} from './ecdsaRecovery';

export type EmailOtpEd25519RestorePurpose = RestorePersistedEd25519SessionPurpose & {
  authMethod: 'email_otp';
};

export function buildEmailOtpEd25519RecordFromSealedRestoreMetadata(args: {
  accountId: string;
  record: SigningSessionSealedStoreRecord;
  purpose: EmailOtpEd25519RestorePurpose;
}): ThresholdEd25519SessionRecord | null {
  const existing = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
    args.purpose.thresholdSessionId,
  );
  if (
    existing?.source === 'email_otp' &&
    existing.emailOtpAuthContext?.retention === 'session' &&
    existing.walletSigningSessionId === args.purpose.walletSigningSessionId
  ) {
    return existing;
  }
  const metadata = args.record.ed25519Restore;
  if (!metadata) return null;
  const relayerUrl = String(args.record.relayerUrl || '').trim();
  const signingRootId = String(args.record.signingRootId || '').trim();
  if (!relayerUrl || !signingRootId) return null;
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(metadata.runtimePolicyScope);
  return upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: args.accountId,
    rpId: metadata.rpId,
    relayerUrl,
    relayerKeyId: metadata.relayerKeyId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(metadata.xClientBaseB64u ? { xClientBaseB64u: metadata.xClientBaseB64u } : {}),
    participantIds: metadata.participantIds,
    thresholdSessionKind: metadata.sessionKind,
    thresholdSessionId: args.purpose.thresholdSessionId,
    walletSigningSessionId: args.purpose.walletSigningSessionId,
    ...(metadata.thresholdSessionAuthToken
      ? { thresholdSessionAuthToken: metadata.thresholdSessionAuthToken }
      : {}),
    expiresAtMs: args.record.expiresAtMs,
    remainingUses: args.record.remainingUses,
    emailOtpAuthContext: {
      policy: 'session',
      retention: 'session',
      reason: 'login',
      authMethod: 'email_otp',
    },
    source: 'email_otp',
  });
}

export async function restoreEmailOtpEd25519SealedRecordForAccount(args: {
  accountId: string;
  record: SigningSessionSealedStoreRecord;
  purpose: EmailOtpEd25519RestorePurpose;
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (
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
}): Promise<RestoreSealedRecordForAccountResult> {
  const ecdsaThresholdSessionId = String(args.record.thresholdSessionIds.ecdsa || '').trim();
  if (!ecdsaThresholdSessionId) return 'deferred';
  const ed25519Record = buildEmailOtpEd25519RecordFromSealedRestoreMetadata(args);
  if (!ed25519Record) return 'deferred';
  const existingStatus = await args
    .readWarmSessionStatusFromWorker(args.purpose.thresholdSessionId)
    .catch(() => null);
  if (existingStatus?.ok) return 'ready';
  const ecdsaRecord =
    args.getThresholdEcdsaSessionRecordByThresholdSessionId?.(ecdsaThresholdSessionId) ||
    getStoredThresholdEcdsaSessionRecordByThresholdSessionId(ecdsaThresholdSessionId);
  const restored = await args
    .restoreEcdsaSigningSessionMaterialFromSealedRecord({
      sealedRecord: args.record,
      ecdsaRecord,
      ed25519Record,
    })
    .catch((error) => {
      console.warn('[EmailOtpSession] exact-purpose Ed25519 sealed restore failed', {
        accountId: args.accountId,
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
