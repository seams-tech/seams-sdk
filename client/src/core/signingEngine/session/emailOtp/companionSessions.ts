import type { AccountId } from '@/core/types/accountIds';
import {
  listStoredThresholdEcdsaSessionRecordsForWallet,
} from '@/core/signingEngine/session/persistence/records';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  BuildCurrentSealedSessionRecordInput,
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
}): BuildCurrentSealedSessionRecordInput {
  const subjectId = String(args.subjectId || '').trim();
  if (!subjectId) {
    throw new Error('Companion sealed-session update requires subjectId');
  }
  const base = {
    thresholdSessionId:
      args.existingRecord.curve === 'ecdsa'
        ? String(args.existingRecord.thresholdSessionIds.ecdsa || '').trim()
        : String(args.existingRecord.thresholdSessionIds.ed25519 || '').trim(),
    sealedSecretB64u: args.existingRecord.sealedSecretB64u,
    authMethod: args.existingRecord.authMethod,
    walletSigningSessionId: args.existingRecord.walletSigningSessionId,
    thresholdSessionIds: buildCompanionThresholdSessionIds({
      existingRecord: args.existingRecord,
      companionCurve: args.companionCurve,
      companionThresholdSessionId: args.companionThresholdSessionId,
    }),
    ...(args.existingRecord.userId ? { userId: args.existingRecord.userId } : {}),
    ...(args.existingRecord.keyVersion ? { keyVersion: args.existingRecord.keyVersion } : {}),
    ...(args.existingRecord.shamirPrimeB64u
      ? { shamirPrimeB64u: args.existingRecord.shamirPrimeB64u }
      : {}),
    issuedAtMs: args.existingRecord.issuedAtMs,
    expiresAtMs: args.existingRecord.expiresAtMs,
    remainingUses: args.existingRecord.remainingUses,
    updatedAtMs: Math.floor(Number(args.updatedAtMs) || Date.now()),
  };
  if (args.existingRecord.curve === 'ecdsa') {
    const walletId = String(args.existingRecord.walletId || '').trim();
    const signingRootId = String(args.existingRecord.signingRootId || '').trim();
    const relayerUrl = String(args.existingRecord.relayerUrl || '').trim();
    const ecdsaRestore = args.ecdsaRestore || args.existingRecord.ecdsaRestore;
    if (!walletId || !signingRootId || !relayerUrl || !ecdsaRestore) {
      throw new Error('ECDSA companion sealed-session update requires exact durable identity');
    }
    return {
      ...base,
      curve: 'ecdsa',
      subjectId,
      walletId,
      signingRootId,
      ...(args.existingRecord.signingRootVersion
        ? { signingRootVersion: args.existingRecord.signingRootVersion }
        : {}),
      relayerUrl,
      ecdsaRestore,
      ...(args.ed25519Restore || args.existingRecord.ed25519Restore
        ? { ed25519Restore: args.ed25519Restore || args.existingRecord.ed25519Restore }
        : {}),
    };
  }
  const relayerUrl = String(args.existingRecord.relayerUrl || '').trim();
  const ed25519Restore = args.ed25519Restore || args.existingRecord.ed25519Restore;
  if (!relayerUrl || !ed25519Restore) {
    throw new Error('Ed25519 companion sealed-session update requires exact durable metadata');
  }
  return {
    ...base,
    curve: 'ed25519',
    relayerUrl,
    ed25519Restore,
    ...(args.existingRecord.walletId ? { walletId: args.existingRecord.walletId } : {}),
    ...(args.existingRecord.signingRootId
      ? { signingRootId: args.existingRecord.signingRootId }
      : {}),
    ...(args.existingRecord.signingRootVersion
      ? { signingRootVersion: args.existingRecord.signingRootVersion }
      : {}),
    ...(args.ecdsaRestore || args.existingRecord.ecdsaRestore
      ? { ecdsaRestore: args.ecdsaRestore || args.existingRecord.ecdsaRestore }
      : {}),
  };
}

export function selectEmailOtpEcdsaRecordForEd25519Signing(args: {
  walletId: AccountId | string;
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
