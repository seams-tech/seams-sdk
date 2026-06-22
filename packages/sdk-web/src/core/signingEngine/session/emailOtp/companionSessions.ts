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

type EmailOtpEcdsaRecordForEd25519SigningSelection =
  | {
      kind: 'signing_grant_exact';
      walletId: WalletId;
      signingGrantId: string;
      listThresholdEcdsaSessionRecordsForWallet?: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
    }
  | {
      kind: 'latest_wallet_record';
      walletId: WalletId;
      signingGrantId?: never;
      listThresholdEcdsaSessionRecordsForWallet?: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
    };

export type EmailOtpEcdsaRecordForEd25519SigningSelectionResult =
  | {
      kind: 'exact_match';
      record: ThresholdEcdsaSessionRecord;
    }
  | {
      kind: 'ambiguous';
      exactMatchCount: number;
    }
  | {
      kind: 'not_found';
    }
  | {
      kind: 'display_only_fallback';
      record: ThresholdEcdsaSessionRecord;
    };

function sortedEmailOtpEcdsaRecordsForWallet(args: {
  walletId: WalletId;
  listThresholdEcdsaSessionRecordsForWallet?: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
}): ThresholdEcdsaSessionRecord[] {
  return (
    args.listThresholdEcdsaSessionRecordsForWallet?.(args.walletId) ??
    listStoredThresholdEcdsaSessionRecordsForWallet(args.walletId)
  )
    .filter(
      (record) =>
        record.source === 'email_otp' &&
        String(record.keyHandle || '').trim() &&
        Array.isArray(record.participantIds) &&
        record.participantIds.length > 0,
    )
    .sort(
      (left, right) =>
        Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0) ||
        thresholdEcdsaChainTargetKey(left.chainTarget).localeCompare(
          thresholdEcdsaChainTargetKey(right.chainTarget),
        ) ||
        String(left.thresholdSessionId).localeCompare(String(right.thresholdSessionId)),
    );
}

export function selectEmailOtpEcdsaRecordForEd25519Signing(
  args: EmailOtpEcdsaRecordForEd25519SigningSelection,
): EmailOtpEcdsaRecordForEd25519SigningSelectionResult {
  const records = sortedEmailOtpEcdsaRecordsForWallet({
    walletId: args.walletId,
    listThresholdEcdsaSessionRecordsForWallet: args.listThresholdEcdsaSessionRecordsForWallet,
  });
  switch (args.kind) {
    case 'signing_grant_exact': {
      const signingGrantId = String(args.signingGrantId || '').trim();
      if (!signingGrantId) return { kind: 'not_found' };
      const matches = records.filter((record) => record.signingGrantId === signingGrantId);
      const exactRecord = matches[0];
      if (matches.length === 1 && exactRecord) {
        return { kind: 'exact_match', record: exactRecord };
      }
      if (matches.length > 1) {
        return { kind: 'ambiguous', exactMatchCount: matches.length };
      }
      return { kind: 'not_found' };
    }
    case 'latest_wallet_record': {
      const record = records[0];
      return record ? { kind: 'display_only_fallback', record } : { kind: 'not_found' };
    }
    default: {
      const exhaustive: never = args;
      throw new Error(
        `[EmailOtpSession] unsupported ECDSA companion selection: ${String(
          (exhaustive as { kind?: unknown })?.kind || '',
        )}`,
      );
    }
  }
}

type EmailOtpEcdsaCompanionSealCandidate = {
  existingRecord: SigningSessionSealedStoreRecord;
  ecdsaRecord: ThresholdEcdsaSessionRecord;
};

export type EmailOtpCompanionSessionAttachResult =
  | {
      kind: 'attached';
    }
  | {
      kind: 'already_attached';
    }
  | {
      kind: 'not_required';
      reason: 'session_persistence_disabled' | 'handle_backed_companion_not_supported';
    }
  | {
      kind: 'missing_required_material';
      reason:
        | 'missing_threshold_session_id'
        | 'missing_ecdsa_sealed_session'
        | 'missing_email_otp_ed25519_record'
        | 'signing_grant_mismatch';
    }
  | {
      kind: 'failed';
      message: string;
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

export async function attachEd25519SessionToEmailOtpSigningSessionSeal(args: {
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
}): Promise<EmailOtpCompanionSessionAttachResult> {
  if (args.sessionPersistenceMode !== 'sealed_refresh_v1') {
    return { kind: 'not_required', reason: 'session_persistence_disabled' };
  }
  const ecdsaThresholdSessionId = String(args.ecdsaThresholdSessionId || '').trim();
  const ed25519ThresholdSessionId = String(args.ed25519ThresholdSessionId || '').trim();
  if (!ecdsaThresholdSessionId || !ed25519ThresholdSessionId) {
    return { kind: 'missing_required_material', reason: 'missing_threshold_session_id' };
  }
  const candidate = await readEmailOtpEcdsaCompanionSealCandidate({
    ecdsaThresholdSessionId,
    readExactSealedSession: args.readExactSealedSession,
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      args.getThresholdEcdsaSessionRecordByThresholdSessionId,
  });
  if (!candidate) {
    return { kind: 'missing_required_material', reason: 'missing_ecdsa_sealed_session' };
  }
  const ed25519Record =
    args.getThresholdEd25519SessionRecordByThresholdSessionId(ed25519ThresholdSessionId);
  if (!ed25519Record || ed25519Record.source !== 'email_otp') {
    return { kind: 'missing_required_material', reason: 'missing_email_otp_ed25519_record' };
  }
  if (
    ed25519Record.emailOtpAuthContext?.retention !== 'session' ||
    ed25519Record.signingGrantId !== candidate.existingRecord.signingGrantId
  ) {
    return { kind: 'missing_required_material', reason: 'signing_grant_mismatch' };
  }
  // The current sealed companion schema can only carry raw Ed25519 material.
  // Keep this no-op until Phase 15.12 replaces it with handle-backed metadata.
  return { kind: 'not_required', reason: 'handle_backed_companion_not_supported' };
}
