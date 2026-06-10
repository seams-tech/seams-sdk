import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetFromRequest } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  normalizeThresholdRuntimePolicyScope,
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '@/core/signingEngine/threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { RawSealedSessionRecordV1 } from '../persistence/sealedSessionStore';

type RawThresholdSessionIds = {
  ed25519?: unknown;
  ecdsa?: unknown;
};

type RawEcdsaRestoreMetadata = {
  chainTarget?: unknown;
  rpId?: unknown;
  thresholdSessionAuthToken?: unknown;
  sessionKind?: unknown;
  keyHandle?: unknown;
  ecdsaThresholdKeyId?: unknown;
  ethereumAddress?: unknown;
  relayerKeyId?: unknown;
  clientVerifyingShareB64u?: unknown;
  thresholdEcdsaPublicKeyB64u?: unknown;
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
  | 'invalid_identity'
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
  rpId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  ethereumAddress: `0x${string}`;
  thresholdEcdsaPublicKeyB64u?: string;
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
    clientVerifyingShareB64u?: string;
    companionEd25519ThresholdSessionId?: string;
    companionEd25519Recovery?: EmailOtpEcdsaCompanionEd25519Recovery;
  };

export type EmailOtpEcdsaCompanionEd25519Recovery = Ed25519SealedRecoveryRecordBase &
  ThresholdSessionAuth & {
    authMethod: 'email_otp';
    rpId: string;
    xClientBaseB64u: string;
  };

export type PasskeyEd25519SealedRecoveryRecord = Ed25519SealedRecoveryRecordBase &
  ThresholdSessionAuth & {
    authMethod: 'passkey';
    rpId: string;
    xClientBaseB64u?: string;
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

type NormalizeSealedRecoveryRecordOptions = {
  allowExpired?: boolean;
  allowExhausted?: boolean;
};

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

function normalizeThresholdSessionIds(
  record: RawSigningSessionSealedStoreRecord,
): RawThresholdSessionIds {
  return normalizeRawObject<RawThresholdSessionIds>(record.thresholdSessionIds) || {};
}

function normalizeSessionKind(value: unknown): ThresholdSessionKind | null {
  return value === 'jwt' || value === 'cookie' ? value : null;
}

function normalizeEthereumAddress(value: unknown): `0x${string}` | null {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(normalized) ? (normalized as `0x${string}`) : null;
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

function resolveSigningRootBinding(args: {
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  rawSigningRootId: unknown;
  rawSigningRootVersion: unknown;
}): { signingRootId: string; signingRootVersion: string } | null {
  if (args.runtimePolicyScope) {
    try {
      const scope = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
      const signingRootId = normalizeNonEmptyString(scope.signingRootId);
      const signingRootVersion = normalizeNonEmptyString(scope.signingRootVersion);
      if (signingRootId && signingRootVersion) {
        return { signingRootId, signingRootVersion };
      }
    } catch {}
  }
  const signingRootId = normalizeNonEmptyString(args.rawSigningRootId);
  const signingRootVersion = normalizeNonEmptyString(args.rawSigningRootVersion);
  if (!signingRootId || !signingRootVersion) return null;
  return { signingRootId, signingRootVersion };
}

function resolveRuntimePolicyScope(args: {
  rawRuntimePolicyScope: unknown;
  rawThresholdSessionAuthToken: unknown;
}): ThresholdRuntimePolicyScope | undefined {
  const explicit = normalizeThresholdRuntimePolicyScope(args.rawRuntimePolicyScope);
  if (explicit) return explicit;
  const thresholdSessionAuthToken = normalizeNonEmptyString(args.rawThresholdSessionAuthToken);
  if (!thresholdSessionAuthToken) return undefined;
  return parseThresholdRuntimePolicyScopeFromJwt(thresholdSessionAuthToken);
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
  options: NormalizeSealedRecoveryRecordOptions = {},
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
  if (!options.allowExpired && expiresAtMs <= Date.now()) return reject(raw, 'expired');
  if (!options.allowExhausted && raw.authMethod !== 'passkey' && remainingUses <= 0) {
    return reject(raw, 'exhausted');
  }

  if (raw.curve === 'ecdsa') {
    const thresholdSessionId = normalizeNonEmptyString(thresholdSessionIds.ecdsa);
    const restore = ecdsaRestore;
    const runtimePolicyScope = resolveRuntimePolicyScope({
      rawRuntimePolicyScope: restore?.runtimePolicyScope,
      rawThresholdSessionAuthToken: restore?.thresholdSessionAuthToken,
    });
    const signingRootBinding = resolveSigningRootBinding({
      runtimePolicyScope,
      rawSigningRootId: raw.signingRootId,
      rawSigningRootVersion: raw.signingRootVersion,
    });
    const relayerUrl = normalizeNonEmptyString(raw.relayerUrl);
    const companionRpIdHint = normalizeNonEmptyString(ed25519Restore?.rpId);
    const rpId = normalizeNonEmptyString(restore?.rpId) || companionRpIdHint;
    const relayerKeyId = normalizeNonEmptyString(restore?.relayerKeyId);
    const keyHandle = normalizeNonEmptyString(restore?.keyHandle);
    const ecdsaThresholdKeyId = normalizeNonEmptyString(restore?.ecdsaThresholdKeyId);
    const ethereumAddress = normalizeEthereumAddress(restore?.ethereumAddress);
    const thresholdEcdsaPublicKeyB64u = normalizeNonEmptyString(
      restore?.thresholdEcdsaPublicKeyB64u,
    );
    const participantIds = normalizeParticipantIds(restore?.participantIds);
    const clientVerifyingShareB64u = normalizeNonEmptyString(restore?.clientVerifyingShareB64u);
    const passkeyClientVerifyingShareB64u =
      raw.authMethod === 'passkey' ? clientVerifyingShareB64u : null;
    const sessionKind = normalizeSessionKind(restore?.sessionKind);
    if (normalizeNonEmptyString(raw.subjectId)) {
      return reject(raw, 'invalid_identity');
    }
    if (!thresholdSessionId || !signingRootBinding) {
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
      !rpId ||
      !ecdsaThresholdKeyId ||
      !relayerKeyId ||
      !keyHandle ||
      !ethereumAddress ||
      !participantIds.length ||
      (raw.authMethod === 'passkey' && !passkeyClientVerifyingShareB64u)
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
    const companionEd25519ThresholdSessionId = normalizeNonEmptyString(thresholdSessionIds.ed25519);
    let companionEd25519Recovery: EmailOtpEcdsaCompanionEd25519Recovery | undefined;
    if (
      raw.authMethod === 'email_otp' &&
      companionEd25519ThresholdSessionId &&
      relayerUrl &&
      ed25519Restore
    ) {
      const companionRpId = normalizeNonEmptyString(ed25519Restore.rpId);
      const companionRelayerKeyId = normalizeNonEmptyString(ed25519Restore.relayerKeyId);
      const companionParticipantIds = normalizeParticipantIds(ed25519Restore.participantIds);
      const companionXClientBaseB64u = normalizeNonEmptyString(ed25519Restore.xClientBaseB64u);
      const companionSessionKind = normalizeSessionKind(ed25519Restore.sessionKind);
      const companionThresholdSessionAuthToken = normalizeNonEmptyString(
        ed25519Restore.thresholdSessionAuthToken,
      );
      let companionThresholdSessionAuth: ThresholdSessionAuth | null = null;
      if (companionSessionKind === 'cookie') {
        companionThresholdSessionAuth = { sessionKind: 'cookie' };
      } else if (companionSessionKind === 'jwt' && companionThresholdSessionAuthToken) {
        companionThresholdSessionAuth = {
          sessionKind: 'jwt',
          thresholdSessionAuthToken: companionThresholdSessionAuthToken,
        };
      }
      if (
        companionRpId &&
        companionRelayerKeyId &&
        companionParticipantIds.length &&
        companionXClientBaseB64u &&
        companionThresholdSessionAuth
      ) {
        const companionRuntimePolicyScope = resolveRuntimePolicyScope({
          rawRuntimePolicyScope: ed25519Restore.runtimePolicyScope,
          rawThresholdSessionAuthToken: ed25519Restore.thresholdSessionAuthToken,
        });
        companionEd25519Recovery = {
          storeKey,
          walletId,
          authMethod: 'email_otp',
          curve: 'ed25519',
          walletSigningSessionId,
          thresholdSessionId: companionEd25519ThresholdSessionId,
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
          rpId: companionRpId,
          relayerKeyId: companionRelayerKeyId,
          participantIds: companionParticipantIds,
          ...companionThresholdSessionAuth,
          ...(companionRuntimePolicyScope
            ? { runtimePolicyScope: companionRuntimePolicyScope }
            : {}),
          xClientBaseB64u: companionXClientBaseB64u,
        };
      }
    }
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
            rpId,
            signingRootId: signingRootBinding.signingRootId,
            signingRootVersion: signingRootBinding.signingRootVersion,
            keyHandle,
            ecdsaThresholdKeyId,
            ethereumAddress,
            ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
            participantIds,
            relayerUrl,
            relayerKeyId,
            ...thresholdSessionAuth,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
            clientVerifyingShareB64u: passkeyClientVerifyingShareB64u!,
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
            rpId,
            signingRootId: signingRootBinding.signingRootId,
            signingRootVersion: signingRootBinding.signingRootVersion,
            keyHandle,
            ecdsaThresholdKeyId,
            ethereumAddress,
            ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
            participantIds,
            relayerUrl,
            relayerKeyId,
            ...thresholdSessionAuth,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
            ...(clientVerifyingShareB64u ? { clientVerifyingShareB64u } : {}),
            ...(normalizeNonEmptyString(thresholdSessionIds.ed25519)
              ? {
                  companionEd25519ThresholdSessionId: normalizeNonEmptyString(
                    thresholdSessionIds.ed25519,
                  )!,
                }
              : {}),
            ...(companionEd25519Recovery ? { companionEd25519Recovery } : {}),
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
    (raw.authMethod === 'email_otp' && !xClientBaseB64u)
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
  const runtimePolicyScope = resolveRuntimePolicyScope({
    rawRuntimePolicyScope: restore.runtimePolicyScope,
    rawThresholdSessionAuthToken: restore.thresholdSessionAuthToken,
  });
  let companionEcdsaRecovery: EmailOtpEcdsaSealedRecoveryRecord | undefined;
  if (raw.authMethod === 'email_otp' && (thresholdSessionIds.ecdsa || ecdsaRestore)) {
    const companionRuntimePolicyScope = resolveRuntimePolicyScope({
      rawRuntimePolicyScope: ecdsaRestore?.runtimePolicyScope,
      rawThresholdSessionAuthToken: ecdsaRestore?.thresholdSessionAuthToken,
    });
    const companionSigningRootBinding = resolveSigningRootBinding({
      runtimePolicyScope: companionRuntimePolicyScope,
      rawSigningRootId: raw.signingRootId,
      rawSigningRootVersion: raw.signingRootVersion,
    });
    const companionEcdsaThresholdKeyId = normalizeNonEmptyString(ecdsaRestore?.ecdsaThresholdKeyId);
    if (
      !thresholdSessionIds.ecdsa ||
      !ecdsaRestore ||
      !ecdsaRestore.chainTarget ||
      !companionSigningRootBinding ||
      !companionEcdsaThresholdKeyId ||
      !normalizeNonEmptyString(raw.relayerUrl) ||
      !normalizeNonEmptyString(ecdsaRestore.rpId) ||
      !normalizeNonEmptyString(ecdsaRestore.relayerKeyId) ||
      !normalizeNonEmptyString(ecdsaRestore.keyHandle) ||
      !normalizeEthereumAddress(ecdsaRestore.ethereumAddress) ||
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
      rpId: normalizeNonEmptyString(ecdsaRestore.rpId)!,
      signingRootId: companionSigningRootBinding.signingRootId,
      signingRootVersion: companionSigningRootBinding.signingRootVersion,
      keyHandle: normalizeNonEmptyString(ecdsaRestore.keyHandle)!,
      ecdsaThresholdKeyId: companionEcdsaThresholdKeyId,
      ethereumAddress: normalizeEthereumAddress(ecdsaRestore.ethereumAddress)!,
      ...(normalizeNonEmptyString(ecdsaRestore.thresholdEcdsaPublicKeyB64u)
        ? {
            thresholdEcdsaPublicKeyB64u: normalizeNonEmptyString(
              ecdsaRestore.thresholdEcdsaPublicKeyB64u,
            )!,
          }
        : {}),
      participantIds: normalizeParticipantIds(ecdsaRestore.participantIds),
      relayerUrl,
      relayerKeyId: normalizeNonEmptyString(ecdsaRestore.relayerKeyId)!,
      ...companionThresholdSessionAuth,
      ...(companionRuntimePolicyScope ? { runtimePolicyScope: companionRuntimePolicyScope } : {}),
      clientVerifyingShareB64u: normalizeNonEmptyString(ecdsaRestore.clientVerifyingShareB64u)!,
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
          ...(xClientBaseB64u ? { xClientBaseB64u } : {}),
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
          xClientBaseB64u: xClientBaseB64u!,
          ...(companionEcdsaRecovery
            ? {
                companionEcdsaRecovery,
              }
            : {}),
        };
  return { kind: 'accepted', record: accepted };
}
