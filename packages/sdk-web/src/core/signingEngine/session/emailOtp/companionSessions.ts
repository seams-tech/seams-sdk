import {
  listStoredThresholdEcdsaSessionRecordsForWallet,
} from '@/core/signingEngine/session/persistence/records';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  thresholdEcdsaChainTargetKey,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  BuildCurrentSealedSessionRecordInput,
  SigningSessionSealedRecordFilter,
  SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';

export function selectEmailOtpEcdsaRecordForEd25519Signing(args: {
  walletId: WalletId;
  walletSigningSessionFilter?: string | null;
  listThresholdEcdsaSessionRecordsForWallet?: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
}): ThresholdEcdsaSessionRecord | null {
  const walletSigningSessionFilter = String(args.walletSigningSessionFilter || '').trim();
  const records = (
    args.listThresholdEcdsaSessionRecordsForWallet?.(args.walletId) ??
    listStoredThresholdEcdsaSessionRecordsForWallet(args.walletId)
  ).filter(
    (record) =>
      record.source === 'email_otp' &&
      String(record.keyHandle || '').trim() &&
      Array.isArray(record.participantIds) &&
      record.participantIds.length > 0,
  );
  if (!records.length) return null;

  const walletScopedRecords = walletSigningSessionFilter
    ? records.filter((record) => record.walletSigningSessionId === walletSigningSessionFilter)
    : [];
  const candidates = walletScopedRecords.length ? walletScopedRecords : records;

  return [...candidates].sort(
    (left, right) =>
      Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0) ||
      thresholdEcdsaChainTargetKey(left.chainTarget).localeCompare(
        thresholdEcdsaChainTargetKey(right.chainTarget),
      ) ||
      String(left.thresholdSessionId).localeCompare(String(right.thresholdSessionId)),
  )[0];
}

type EmailOtpEcdsaCompanionSealCandidate = {
  existingRecord: SigningSessionSealedStoreRecord;
  ecdsaRecord: ThresholdEcdsaSessionRecord;
};

async function readEmailOtpEcdsaCompanionSealCandidate(args: {
  ecdsaThresholdSessionId: string;
  readExactSealedSession: (
    thresholdSessionId: string,
    filter: SigningSessionSealedRecordFilter,
  ) => Promise<SigningSessionSealedStoreRecord | null>;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
}): Promise<EmailOtpEcdsaCompanionSealCandidate | null> {
  const ecdsaRecord = args.getThresholdEcdsaSessionRecordByThresholdSessionId(
    args.ecdsaThresholdSessionId,
  );
  if (!ecdsaRecord || ecdsaRecord.source !== 'email_otp' || !ecdsaRecord.chainTarget) return null;
  const existingRecord = await args
    .readExactSealedSession(args.ecdsaThresholdSessionId, {
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: ecdsaRecord.chainTarget,
    })
    .catch(() => null);
  if (!existingRecord || existingRecord.authMethod !== 'email_otp') return null;
  return { existingRecord, ecdsaRecord };
}

export async function attachEd25519SessionToEmailOtpSigningSessionSealBestEffort(args: {
  sessionPersistenceMode?: string | null;
  ecdsaThresholdSessionId: string;
  ed25519ThresholdSessionId: string;
  readExactSealedSession: (
    thresholdSessionId: string,
    filter: SigningSessionSealedRecordFilter,
  ) => Promise<SigningSessionSealedStoreRecord | null>;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  getThresholdEd25519SessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
  registerSigningSession: (
    record: BuildCurrentSealedSessionRecordInput,
  ) => Promise<void>;
}): Promise<void> {
  if (args.sessionPersistenceMode !== 'sealed_refresh_v1') return;
  const ecdsaThresholdSessionId = String(args.ecdsaThresholdSessionId || '').trim();
  const ed25519ThresholdSessionId = String(args.ed25519ThresholdSessionId || '').trim();
  if (!ecdsaThresholdSessionId || !ed25519ThresholdSessionId) return;
  const candidate = await readEmailOtpEcdsaCompanionSealCandidate({
    ecdsaThresholdSessionId,
    readExactSealedSession: args.readExactSealedSession,
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      args.getThresholdEcdsaSessionRecordByThresholdSessionId,
  });
  if (!candidate) return;
  const ed25519Record =
    args.getThresholdEd25519SessionRecordByThresholdSessionId(ed25519ThresholdSessionId);
  if (
    !ed25519Record ||
    ed25519Record.source !== 'email_otp' ||
    ed25519Record.emailOtpAuthContext?.retention !== 'session' ||
    ed25519Record.walletSigningSessionId !== candidate.existingRecord.walletSigningSessionId
  ) {
    return;
  }
  // The current sealed companion schema can only carry raw Ed25519 material.
  // Keep this no-op until Phase 15.12 replaces it with handle-backed metadata.
  return;
}
