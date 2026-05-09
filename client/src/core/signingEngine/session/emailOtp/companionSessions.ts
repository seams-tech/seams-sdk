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
import { buildCompanionSealedSessionUpdate } from '../sealedRecovery/companionSessions';
import type {
  SigningSessionSealedRecordFilter,
  SigningSessionSealedStoreRecord,
  WriteExactSealedSessionBaseInput,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';

export function selectEmailOtpEcdsaRecordForEd25519Signing(args: {
  nearAccountId: AccountId | string;
  walletSigningSessionId?: string | null;
  listThresholdEcdsaSessionRecordsForSubject: (args: {
    subjectId: WalletSubjectId;
  }) => ThresholdEcdsaSessionRecord[];
}): ThresholdEcdsaSessionRecord | null {
  const subjectId = toWalletSubjectId(args.nearAccountId);
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
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

  const walletScopedRecords = walletSigningSessionId
    ? records.filter((record) => record.walletSigningSessionId === walletSigningSessionId)
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

export async function attachEd25519SessionToEmailOtpSigningSessionSealBestEffort(args: {
  sessionPersistenceMode?: string | null;
  ecdsaThresholdSessionId?: string;
  ed25519ThresholdSessionId: string;
  readExactSealedSession: (
    thresholdSessionId: string,
    filter: SigningSessionSealedRecordFilter,
  ) => Promise<SigningSessionSealedStoreRecord | null>;
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  registerSigningSession: (
    record: WriteExactSealedSessionBaseInput & { curve: 'ed25519' | 'ecdsa' },
  ) => Promise<void>;
}): Promise<void> {
  if (args.sessionPersistenceMode !== 'sealed_refresh_v1') return;
  const ecdsaThresholdSessionId = String(args.ecdsaThresholdSessionId || '').trim();
  const ed25519ThresholdSessionId = String(args.ed25519ThresholdSessionId || '').trim();
  if (!ecdsaThresholdSessionId || !ed25519ThresholdSessionId) return;
  const ecdsaRecord =
    args.getThresholdEcdsaSessionRecordByThresholdSessionId?.(ecdsaThresholdSessionId) ||
    getStoredThresholdEcdsaSessionRecordByThresholdSessionId(ecdsaThresholdSessionId);
  if (!ecdsaRecord || ecdsaRecord.source !== 'email_otp' || !ecdsaRecord.chainTarget) return;
  const existing = await args
    .readExactSealedSession(ecdsaThresholdSessionId, {
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: ecdsaRecord.chainTarget,
    })
    .catch(() => null);
  if (!existing || existing.authMethod !== 'email_otp') return;
  const ed25519Record =
    getStoredThresholdEd25519SessionRecordByThresholdSessionId(ed25519ThresholdSessionId);
  if (
    !ed25519Record ||
    ed25519Record.source !== 'email_otp' ||
    ed25519Record.emailOtpAuthContext?.retention !== 'session' ||
    ed25519Record.walletSigningSessionId !== existing.walletSigningSessionId
  ) {
    return;
  }
  const subjectId = String(existing.subjectId || ecdsaRecord.subjectId || '').trim();
  if (!subjectId) return;
  await args.registerSigningSession(
    buildCompanionSealedSessionUpdate({
      existingRecord: existing,
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
