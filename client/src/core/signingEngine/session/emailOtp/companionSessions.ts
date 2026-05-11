import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
} from '@/core/signingEngine/session/persistence/records';
import {
  thresholdEcdsaChainTargetKey,
  toWalletSubjectId,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  BuildCurrentSealedSessionRecordBaseInput,
  SigningSessionSealedRecordFilter,
  SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';

type SealedSessionCompanionCurve = 'ed25519' | 'ecdsa';

function buildCompanionThresholdSessionIds(args: {
  existingRecord: SigningSessionSealedStoreRecord;
  companionCurve: SealedSessionCompanionCurve;
  companionThresholdSessionId: string;
}): NonNullable<BuildCurrentSealedSessionRecordBaseInput['thresholdSessionIds']> {
  const companionThresholdSessionId = String(args.companionThresholdSessionId || '').trim();
  if (!companionThresholdSessionId) {
    throw new Error('Companion threshold session id is required');
  }
  return {
    ...args.existingRecord.thresholdSessionIds,
    [args.companionCurve]: companionThresholdSessionId,
  };
}

function buildCompanionSealedSessionUpdate(args: {
  existingRecord: SigningSessionSealedStoreRecord;
  companionCurve: SealedSessionCompanionCurve;
  companionThresholdSessionId: string;
  subjectId: string;
  updatedAtMs?: number;
  ecdsaRestore?: BuildCurrentSealedSessionRecordBaseInput['ecdsaRestore'];
  ed25519Restore?: BuildCurrentSealedSessionRecordBaseInput['ed25519Restore'];
}): BuildCurrentSealedSessionRecordBaseInput & { curve: 'ed25519' | 'ecdsa' } {
  const subjectId = String(args.subjectId || '').trim();
  if (!subjectId) {
    throw new Error('Companion sealed-session update requires subjectId');
  }
  return {
    thresholdSessionId:
      args.existingRecord.curve === 'ecdsa'
        ? String(args.existingRecord.thresholdSessionIds.ecdsa || '').trim()
        : String(args.existingRecord.thresholdSessionIds.ed25519 || '').trim(),
    sealedSecretB64u: args.existingRecord.sealedSecretB64u,
    curve: args.existingRecord.curve,
    authMethod: args.existingRecord.authMethod,
    walletSigningSessionId: args.existingRecord.walletSigningSessionId,
    thresholdSessionIds: buildCompanionThresholdSessionIds({
      existingRecord: args.existingRecord,
      companionCurve: args.companionCurve,
      companionThresholdSessionId: args.companionThresholdSessionId,
    }),
    subjectId,
    walletId: args.existingRecord.walletId,
    userId: args.existingRecord.userId,
    signingRootId: args.existingRecord.signingRootId,
    signingRootVersion: args.existingRecord.signingRootVersion,
    relayerUrl: args.existingRecord.relayerUrl,
    keyVersion: args.existingRecord.keyVersion,
    shamirPrimeB64u: args.existingRecord.shamirPrimeB64u,
    ecdsaRestore: args.ecdsaRestore || args.existingRecord.ecdsaRestore,
    ed25519Restore: args.ed25519Restore || args.existingRecord.ed25519Restore,
    issuedAtMs: args.existingRecord.issuedAtMs,
    expiresAtMs: args.existingRecord.expiresAtMs,
    remainingUses: args.existingRecord.remainingUses,
    updatedAtMs: Math.floor(Number(args.updatedAtMs) || Date.now()),
  };
}

export function selectEmailOtpEcdsaRecordForEd25519Signing(args: {
  nearAccountId: AccountId | string;
  walletSigningSessionFilter?: string | null;
  listThresholdEcdsaSessionRecordsForSubject: (args: {
    subjectId: WalletSubjectId;
  }) => ThresholdEcdsaSessionRecord[];
}): ThresholdEcdsaSessionRecord | null {
  const subjectId = toWalletSubjectId(args.nearAccountId);
  const walletSigningSessionFilter = String(args.walletSigningSessionFilter || '').trim();
  const records = args
    .listThresholdEcdsaSessionRecordsForSubject({ subjectId })
    .filter(
      (record) =>
        record.source === 'email_otp' &&
        String(record.ecdsaThresholdKeyId || '').trim() &&
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
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
}): Promise<EmailOtpEcdsaCompanionSealCandidate | null> {
  const ecdsaRecord =
    args.getThresholdEcdsaSessionRecordByThresholdSessionId?.(args.ecdsaThresholdSessionId) ||
    getStoredThresholdEcdsaSessionRecordByThresholdSessionId(args.ecdsaThresholdSessionId);
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
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  registerSigningSession: (
    record: BuildCurrentSealedSessionRecordBaseInput & { curve: 'ed25519' | 'ecdsa' },
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
    getStoredThresholdEd25519SessionRecordByThresholdSessionId(ed25519ThresholdSessionId);
  if (
    !ed25519Record ||
    ed25519Record.source !== 'email_otp' ||
    ed25519Record.emailOtpAuthContext?.retention !== 'session' ||
    ed25519Record.walletSigningSessionId !== candidate.existingRecord.walletSigningSessionId
  ) {
    return;
  }
  const subjectId = String(candidate.existingRecord.subjectId || candidate.ecdsaRecord.subjectId || '').trim();
  if (!subjectId) return;
  await args.registerSigningSession(
    buildCompanionSealedSessionUpdate({
      existingRecord: candidate.existingRecord,
      companionCurve: 'ed25519',
      companionThresholdSessionId: ed25519ThresholdSessionId,
      subjectId,
      ed25519Restore: {
        rpId: ed25519Record.rpId,
        relayerKeyId: ed25519Record.relayerKeyId,
        participantIds: ed25519Record.participantIds,
        ...(ed25519Record.thresholdSessionAuthToken
          ? { thresholdSessionAuthToken: ed25519Record.thresholdSessionAuthToken }
          : {}),
        sessionKind: ed25519Record.thresholdSessionKind || 'jwt',
        ...(ed25519Record.runtimePolicyScope
          ? { runtimePolicyScope: ed25519Record.runtimePolicyScope }
          : {}),
        ...(ed25519Record.xClientBaseB64u
          ? { xClientBaseB64u: ed25519Record.xClientBaseB64u }
          : {}),
      },
    }),
  );
}
