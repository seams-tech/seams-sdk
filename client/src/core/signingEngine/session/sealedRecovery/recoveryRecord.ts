import type {
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  thresholdEcdsaChainTargetFromRequest,
  toWalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type { RawSealedSessionRecordV1 } from '../persistence/sealedSessionStore';

type RawThresholdSessionIds = {
  ed25519?: unknown;
  ecdsa?: unknown;
};

type RawEcdsaRestoreMetadata = {
  chainTarget?: unknown;
  thresholdSessionAuthToken?: unknown;
  sessionKind?: unknown;
  ecdsaThresholdKeyId?: unknown;
  relayerKeyId?: unknown;
  clientVerifyingShareB64u?: unknown;
  participantIds?: unknown;
  runtimePolicyScope?: unknown;
};

type RawEd25519RestoreMetadata = {
  rpId?: unknown;
  relayerKeyId?: unknown;
  participantIds?: unknown;
  thresholdSessionAuthToken?: unknown;
  sessionKind?: unknown;
  runtimePolicyScope?: unknown;
  xClientBaseB64u?: unknown;
};

export type RawSigningSessionSealedStoreRecord = RawSealedSessionRecordV1 & {
  storeKey?: unknown;
  walletId?: unknown;
  userId?: unknown;
  authMethod?: unknown;
  curve?: unknown;
  walletSigningSessionId?: unknown;
  thresholdSessionIds?: RawThresholdSessionIds | unknown;
  sealedSecretB64u?: unknown;
  subjectId?: unknown;
  signingRootId?: unknown;
  signingRootVersion?: unknown;
  relayerUrl?: unknown;
  keyVersion?: unknown;
  shamirPrimeB64u?: unknown;
  ecdsaRestore?: RawEcdsaRestoreMetadata | unknown;
  ed25519Restore?: RawEd25519RestoreMetadata | unknown;
  issuedAtMs?: unknown;
  expiresAtMs?: unknown;
  remainingUses?: unknown;
  updatedAtMs?: unknown;
};

export type SealedRecoveryRejectionReason =
  | 'missing_identity'
  | 'missing_restore_metadata'
  | 'wrong_curve'
  | 'wrong_chain_target'
  | 'expired'
  | 'exhausted'
  | 'unsupported_legacy_record';

export type RejectedSealedRecoveryRecord = {
  kind: 'rejected_sealed_recovery_record';
  storeKey: string | null;
  walletId: string | null;
  reason: SealedRecoveryRejectionReason;
  safeSummary: Record<string, unknown>;
};

type SealedRecoveryRecordBase = {
  storeKey: string;
  walletId: string;
  authMethod: 'passkey' | 'email_otp';
  curve: 'ed25519' | 'ecdsa';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  sealedSecretB64u: string;
  issuedAtMs: number;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs: number;
  keyVersion?: string;
  shamirPrimeB64u?: string;
};

type EcdsaSealedRecoveryRecordBase = SealedRecoveryRecordBase & {
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  subjectId: WalletSubjectId;
  signingRootId: string;
  signingRootVersion: string;
  ecdsaThresholdKeyId: string;
  participantIds: readonly number[];
  relayerUrl: string;
  relayerKeyId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

type Ed25519SealedRecoveryRecordBase = SealedRecoveryRecordBase & {
  curve: 'ed25519';
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

type JwtThresholdSessionAuth = {
  sessionKind: 'jwt';
  thresholdSessionAuthToken: string;
};

type CookieThresholdSessionAuth = {
  sessionKind: 'cookie';
  thresholdSessionAuthToken?: never;
};

type ThresholdSessionAuth = JwtThresholdSessionAuth | CookieThresholdSessionAuth;

export type PasskeyEcdsaSealedRecoveryRecord = EcdsaSealedRecoveryRecordBase &
  ThresholdSessionAuth & {
    authMethod: 'passkey';
    clientVerifyingShareB64u: string;
  };

export type EmailOtpEcdsaSealedRecoveryRecord = EcdsaSealedRecoveryRecordBase &
  ThresholdSessionAuth & {
    authMethod: 'email_otp';
    clientVerifyingShareB64u: string;
    companionEd25519ThresholdSessionId?: string;
  };

export type PasskeyEd25519SealedRecoveryRecord = Ed25519SealedRecoveryRecordBase &
  ThresholdSessionAuth & {
    authMethod: 'passkey';
    rpId: string;
    xClientBaseB64u: string;
  };

export type EmailOtpEd25519SealedRecoveryRecord = Ed25519SealedRecoveryRecordBase &
  ThresholdSessionAuth & {
    authMethod: 'email_otp';
    rpId: string;
    xClientBaseB64u: string;
    companionEcdsaRecovery?: EmailOtpEcdsaSealedRecoveryRecord;
  };

export type SealedRecoveryRecord =
  | PasskeyEd25519SealedRecoveryRecord
  | PasskeyEcdsaSealedRecoveryRecord
  | EmailOtpEd25519SealedRecoveryRecord
  | EmailOtpEcdsaSealedRecoveryRecord;

export type NormalizeSealedRecoveryRecordResult =
  | { kind: 'accepted'; record: SealedRecoveryRecord }
  | { kind: 'rejected'; rejection: RejectedSealedRecoveryRecord };

function normalizeNonEmptyString(value: unknown): string | null {
  const normalized = String(value ?? '').trim();
  return normalized || null;
}

function normalizeParticipantIds(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((participantId) => Math.floor(Number(participantId)))
    .filter((participantId) => Number.isFinite(participantId) && participantId > 0);
}

function normalizeRawObject<TValue extends object>(value: unknown): Partial<TValue> | null {
  return value && typeof value === 'object' ? (value as Partial<TValue>) : null;
}

function normalizeThresholdSessionIds(record: RawSigningSessionSealedStoreRecord): RawThresholdSessionIds {
  return normalizeRawObject<RawThresholdSessionIds>(record.thresholdSessionIds) || {};
}

function normalizeSessionKind(value: unknown): ThresholdSessionKind | null {
  return value === 'jwt' || value === 'cookie' ? value : null;
}

function normalizeThresholdSessionAuthOrReject(args: {
  record: RawSigningSessionSealedStoreRecord;
  sessionKind: ThresholdSessionKind | null;
  thresholdSessionAuthToken: unknown;
}): ThresholdSessionAuth | NormalizeSealedRecoveryRecordResult {
  if (!args.sessionKind) {
    return reject(args.record, 'missing_restore_metadata');
  }
  if (args.sessionKind === 'cookie') {
    return { sessionKind: 'cookie' };
  }
  const thresholdSessionAuthToken = normalizeNonEmptyString(args.thresholdSessionAuthToken);
  if (!thresholdSessionAuthToken) {
    return reject(args.record, 'missing_restore_metadata');
  }
  return {
    sessionKind: 'jwt',
    thresholdSessionAuthToken,
  };
}

function safeSummary(record: RawSigningSessionSealedStoreRecord): Record<string, unknown> {
  const thresholdSessionIds = normalizeThresholdSessionIds(record);
  return {
    authMethod: record.authMethod,
    curve: record.curve,
    storeKey: record.storeKey,
    walletId: record.walletId || null,
    walletSigningSessionId: record.walletSigningSessionId || null,
    thresholdSessionIds,
    issuedAtMs: record.issuedAtMs,
    expiresAtMs: record.expiresAtMs,
    remainingUses: record.remainingUses,
    updatedAtMs: record.updatedAtMs,
    hasEcdsaRestore: Boolean(record.ecdsaRestore),
    hasEd25519Restore: Boolean(record.ed25519Restore),
  };
}

function reject(
  record: RawSigningSessionSealedStoreRecord,
  reason: SealedRecoveryRejectionReason,
): NormalizeSealedRecoveryRecordResult {
  return {
    kind: 'rejected',
    rejection: {
      kind: 'rejected_sealed_recovery_record',
      storeKey: normalizeNonEmptyString(record.storeKey),
      walletId: normalizeNonEmptyString(record.walletId),
      reason,
      safeSummary: safeSummary(record),
    },
  };
}

export function normalizeSealedRecoveryRecord(
  raw: RawSigningSessionSealedStoreRecord,
): NormalizeSealedRecoveryRecordResult {
  const thresholdSessionIds = normalizeThresholdSessionIds(raw);
  const ecdsaRestore = normalizeRawObject<RawEcdsaRestoreMetadata>(raw.ecdsaRestore);
  const ed25519Restore = normalizeRawObject<RawEd25519RestoreMetadata>(raw.ed25519Restore);
  const storeKey = normalizeNonEmptyString(raw.storeKey);
  const walletId = normalizeNonEmptyString(raw.walletId);
  const walletSigningSessionId = normalizeNonEmptyString(raw.walletSigningSessionId);
  const sealedSecretB64u = normalizeNonEmptyString(raw.sealedSecretB64u);
  const issuedAtMs = Math.floor(Number(raw.issuedAtMs) || 0);
  const expiresAtMs = Math.floor(Number(raw.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(raw.remainingUses) || 0);
  const updatedAtMs = Math.floor(Number(raw.updatedAtMs) || 0);

  if (
    (raw.authMethod !== 'passkey' && raw.authMethod !== 'email_otp') ||
    (raw.curve !== 'ed25519' && raw.curve !== 'ecdsa')
  ) {
    return reject(raw, 'unsupported_legacy_record');
  }
  if (!storeKey || !walletId || !walletSigningSessionId || !sealedSecretB64u) {
    return reject(raw, 'missing_identity');
  }
  if (expiresAtMs <= 0 || updatedAtMs <= 0 || issuedAtMs <= 0) {
    return reject(raw, 'missing_restore_metadata');
  }
  if (expiresAtMs <= Date.now()) return reject(raw, 'expired');
  if (raw.authMethod !== 'passkey' && remainingUses <= 0) return reject(raw, 'exhausted');

  if (raw.curve === 'ecdsa') {
    const thresholdSessionId = normalizeNonEmptyString(thresholdSessionIds.ecdsa);
    const restore = ecdsaRestore;
    const subjectId = normalizeNonEmptyString(raw.subjectId);
    const signingRootId = normalizeNonEmptyString(raw.signingRootId);
    const signingRootVersion = normalizeNonEmptyString(raw.signingRootVersion);
    const relayerUrl = normalizeNonEmptyString(raw.relayerUrl);
    const relayerKeyId = normalizeNonEmptyString(restore?.relayerKeyId);
    const ecdsaThresholdKeyId = normalizeNonEmptyString(restore?.ecdsaThresholdKeyId);
    const participantIds = normalizeParticipantIds(restore?.participantIds);
    const clientVerifyingShareB64u = normalizeNonEmptyString(restore?.clientVerifyingShareB64u);
    const sessionKind = normalizeSessionKind(restore?.sessionKind);
    if (!thresholdSessionId || !subjectId || !signingRootId || !signingRootVersion) {
      return reject(raw, 'missing_identity');
    }
    if (!restore?.chainTarget) return reject(raw, 'wrong_chain_target');
    let chainTarget: ThresholdEcdsaChainTarget;
    try {
      chainTarget = thresholdEcdsaChainTargetFromRequest(
        restore.chainTarget as Record<string, unknown>,
      );
    } catch {
      return reject(raw, 'wrong_chain_target');
    }
    if (
      !relayerUrl ||
      !relayerKeyId ||
      !ecdsaThresholdKeyId ||
      !participantIds.length ||
      !clientVerifyingShareB64u
    ) {
      return reject(raw, 'missing_restore_metadata');
    }
    const thresholdSessionAuth = normalizeThresholdSessionAuthOrReject({
      record: raw,
      sessionKind,
      thresholdSessionAuthToken: restore.thresholdSessionAuthToken,
    });
    if ('kind' in thresholdSessionAuth) {
      return thresholdSessionAuth;
    }
    const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(restore.runtimePolicyScope);
    const accepted: SealedRecoveryRecord =
      raw.authMethod === 'passkey'
        ? {
            storeKey,
            walletId,
            authMethod: 'passkey',
            curve: 'ecdsa',
            walletSigningSessionId,
            thresholdSessionId,
            sealedSecretB64u,
            issuedAtMs,
            expiresAtMs,
            remainingUses,
            updatedAtMs,
            ...(normalizeNonEmptyString(raw.keyVersion)
              ? { keyVersion: normalizeNonEmptyString(raw.keyVersion)! }
              : {}),
            ...(normalizeNonEmptyString(raw.shamirPrimeB64u)
              ? { shamirPrimeB64u: normalizeNonEmptyString(raw.shamirPrimeB64u)! }
              : {}),
            chainTarget,
            subjectId: toWalletSubjectId(subjectId),
            signingRootId,
            signingRootVersion,
            ecdsaThresholdKeyId,
            participantIds,
            relayerUrl,
            relayerKeyId,
            ...thresholdSessionAuth,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
            clientVerifyingShareB64u,
          }
        : {
            storeKey,
            walletId,
            authMethod: 'email_otp',
            curve: 'ecdsa',
            walletSigningSessionId,
            thresholdSessionId,
            sealedSecretB64u,
            issuedAtMs,
            expiresAtMs,
            remainingUses,
            updatedAtMs,
            ...(normalizeNonEmptyString(raw.keyVersion)
              ? { keyVersion: normalizeNonEmptyString(raw.keyVersion)! }
              : {}),
            ...(normalizeNonEmptyString(raw.shamirPrimeB64u)
              ? { shamirPrimeB64u: normalizeNonEmptyString(raw.shamirPrimeB64u)! }
              : {}),
            chainTarget,
            subjectId: toWalletSubjectId(subjectId),
            signingRootId,
            signingRootVersion,
            ecdsaThresholdKeyId,
            participantIds,
            relayerUrl,
            relayerKeyId,
            ...thresholdSessionAuth,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
            clientVerifyingShareB64u,
            ...(normalizeNonEmptyString(thresholdSessionIds.ed25519)
              ? {
                  companionEd25519ThresholdSessionId: normalizeNonEmptyString(
                    thresholdSessionIds.ed25519,
                  )!,
                }
              : {}),
          };
    return { kind: 'accepted', record: accepted };
  }

  const thresholdSessionId = normalizeNonEmptyString(thresholdSessionIds.ed25519);
  const restore = ed25519Restore;
  const relayerUrl = normalizeNonEmptyString(raw.relayerUrl);
  const relayerKeyId = normalizeNonEmptyString(restore?.relayerKeyId);
  const rpId = normalizeNonEmptyString(restore?.rpId);
  const participantIds = normalizeParticipantIds(restore?.participantIds);
  const xClientBaseB64u = normalizeNonEmptyString(restore?.xClientBaseB64u);
  const sessionKind = normalizeSessionKind(restore?.sessionKind);
  if (!thresholdSessionId) return reject(raw, 'missing_identity');
  if (
    !restore ||
    !rpId ||
    !relayerUrl ||
    !relayerKeyId ||
    !participantIds.length ||
    !xClientBaseB64u
  ) {
    return reject(raw, 'missing_restore_metadata');
  }
  const thresholdSessionAuth = normalizeThresholdSessionAuthOrReject({
    record: raw,
    sessionKind,
    thresholdSessionAuthToken: restore.thresholdSessionAuthToken,
  });
  if ('kind' in thresholdSessionAuth) {
    return thresholdSessionAuth;
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(restore.runtimePolicyScope);
  let companionEcdsaRecovery: EmailOtpEcdsaSealedRecoveryRecord | undefined;
  if (raw.authMethod === 'email_otp' && (thresholdSessionIds.ecdsa || ecdsaRestore)) {
    if (
      !thresholdSessionIds.ecdsa ||
      !ecdsaRestore ||
      !ecdsaRestore.chainTarget ||
      !normalizeNonEmptyString(raw.subjectId) ||
      !normalizeNonEmptyString(raw.signingRootId) ||
      !normalizeNonEmptyString(raw.signingRootVersion) ||
      !normalizeNonEmptyString(raw.relayerUrl) ||
      !normalizeNonEmptyString(ecdsaRestore.relayerKeyId) ||
      !normalizeNonEmptyString(ecdsaRestore.ecdsaThresholdKeyId) ||
      !normalizeParticipantIds(ecdsaRestore.participantIds).length ||
      !normalizeNonEmptyString(ecdsaRestore.clientVerifyingShareB64u)
    ) {
      return reject(raw, 'missing_restore_metadata');
    }
    let companionChainTarget: ThresholdEcdsaChainTarget;
    try {
      companionChainTarget = thresholdEcdsaChainTargetFromRequest(
        ecdsaRestore.chainTarget as Record<string, unknown>,
      );
    } catch {
      return reject(raw, 'wrong_chain_target');
    }
    const companionThresholdSessionAuth = normalizeThresholdSessionAuthOrReject({
      record: raw,
      sessionKind: normalizeSessionKind(ecdsaRestore.sessionKind),
      thresholdSessionAuthToken: ecdsaRestore.thresholdSessionAuthToken,
    });
    if ('kind' in companionThresholdSessionAuth) {
      return companionThresholdSessionAuth;
    }
    companionEcdsaRecovery = {
      storeKey,
      walletId,
      authMethod: 'email_otp',
      curve: 'ecdsa',
      walletSigningSessionId,
      thresholdSessionId: normalizeNonEmptyString(thresholdSessionIds.ecdsa)!,
      sealedSecretB64u,
      issuedAtMs,
      expiresAtMs,
      remainingUses,
      updatedAtMs,
      ...(normalizeNonEmptyString(raw.keyVersion)
        ? { keyVersion: normalizeNonEmptyString(raw.keyVersion)! }
        : {}),
      ...(normalizeNonEmptyString(raw.shamirPrimeB64u)
        ? { shamirPrimeB64u: normalizeNonEmptyString(raw.shamirPrimeB64u)! }
        : {}),
      chainTarget: companionChainTarget,
      subjectId: toWalletSubjectId(normalizeNonEmptyString(raw.subjectId)!),
      signingRootId: normalizeNonEmptyString(raw.signingRootId)!,
      signingRootVersion: normalizeNonEmptyString(raw.signingRootVersion)!,
      ecdsaThresholdKeyId: normalizeNonEmptyString(ecdsaRestore.ecdsaThresholdKeyId)!,
      participantIds: normalizeParticipantIds(ecdsaRestore.participantIds),
      relayerUrl,
      relayerKeyId: normalizeNonEmptyString(ecdsaRestore.relayerKeyId)!,
      ...companionThresholdSessionAuth,
      ...(normalizeThresholdRuntimePolicyScope(ecdsaRestore.runtimePolicyScope)
        ? {
            runtimePolicyScope: normalizeThresholdRuntimePolicyScope(
              ecdsaRestore.runtimePolicyScope,
            )!,
          }
        : {}),
      clientVerifyingShareB64u: normalizeNonEmptyString(
        ecdsaRestore.clientVerifyingShareB64u,
      )!,
    };
  }
  const accepted: SealedRecoveryRecord =
    raw.authMethod === 'passkey'
      ? {
          storeKey,
          walletId,
          authMethod: 'passkey',
          curve: 'ed25519',
          walletSigningSessionId,
          thresholdSessionId,
          sealedSecretB64u,
          issuedAtMs,
          expiresAtMs,
          remainingUses,
          updatedAtMs,
          ...(normalizeNonEmptyString(raw.keyVersion)
            ? { keyVersion: normalizeNonEmptyString(raw.keyVersion)! }
            : {}),
          ...(normalizeNonEmptyString(raw.shamirPrimeB64u)
            ? { shamirPrimeB64u: normalizeNonEmptyString(raw.shamirPrimeB64u)! }
            : {}),
          relayerUrl,
          rpId,
          relayerKeyId,
          participantIds,
          ...thresholdSessionAuth,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          xClientBaseB64u,
        }
      : {
          storeKey,
          walletId,
          authMethod: 'email_otp',
          curve: 'ed25519',
          walletSigningSessionId,
          thresholdSessionId,
          sealedSecretB64u,
          issuedAtMs,
          expiresAtMs,
          remainingUses,
          updatedAtMs,
          ...(normalizeNonEmptyString(raw.keyVersion)
            ? { keyVersion: normalizeNonEmptyString(raw.keyVersion)! }
            : {}),
          ...(normalizeNonEmptyString(raw.shamirPrimeB64u)
            ? { shamirPrimeB64u: normalizeNonEmptyString(raw.shamirPrimeB64u)! }
            : {}),
          relayerUrl,
          rpId,
          relayerKeyId,
          participantIds,
          ...thresholdSessionAuth,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          xClientBaseB64u,
          ...(companionEcdsaRecovery
            ? {
                companionEcdsaRecovery,
              }
            : {}),
        };
  return { kind: 'accepted', record: accepted };
}
