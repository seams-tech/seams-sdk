import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetFromRequest } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  normalizeThresholdRuntimePolicyScope,
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '@/core/signingEngine/threshold/sessionPolicy';
import {
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@/core/signingEngine/threshold/ed25519/routerAbNormalSigningState';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { RawSealedSessionRecord } from '../persistence/sealedSessionStore';

type RawThresholdSessionIds = {
  ed25519?: unknown;
  ecdsa?: unknown;
};

type RawEcdsaRestoreMetadata = {
  chainTarget?: unknown;
  walletKeyId?: unknown;
  rpId?: unknown;
  credentialIdB64u?: unknown;
  providerSubjectId?: unknown;
  authSubjectId?: unknown;
  walletSessionJwt?: unknown;
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
  nearAccountId?: unknown;
  nearEd25519SigningKeyId?: unknown;
  rpId?: unknown;
  credentialIdB64u?: unknown;
  providerSubjectId?: unknown;
  authSubjectId?: unknown;
  relayerKeyId?: unknown;
  participantIds?: unknown;
  walletSessionJwt?: unknown;
  sessionKind?: unknown;
  runtimePolicyScope?: unknown;
  xClientBaseB64u?: unknown;
  clientVerifyingShareB64u?: unknown;
  ed25519WorkerMaterialBindingDigest?: unknown;
  sealedWorkerMaterialRef?: unknown;
  sealedWorkerMaterialB64u?: unknown;
  materialFormatVersion?: unknown;
  materialKeyId?: unknown;
  materialCreatedAtMs?: unknown;
  signerSlot?: unknown;
  routerAbNormalSigning?: unknown;
};

export type RawSigningSessionSealedStoreRecord = RawSealedSessionRecord & {
  storeKey?: unknown;
  walletId?: unknown;
  userId?: unknown;
  authMethod?: unknown;
  curve?: unknown;
  thresholdSessionId?: unknown;
  signingGrantId?: unknown;
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
  | 'unsupported_record';

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
  signingGrantId: string;
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
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  clientVerifyingShareB64u?: string;
  ed25519WorkerMaterialBindingDigest?: string;
  sealedWorkerMaterialRef?: string;
  sealedWorkerMaterialB64u?: string;
  materialFormatVersion?: string;
  materialKeyId?: string;
  materialCreatedAtMs?: number;
  signerSlot: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

export type SealedRecoveryWalletSessionAuth =
  {
    kind: 'wallet_session_jwt';
    walletSessionJwt: string;
  };

type SealedRecoveryWalletSessionAuthCarrier = {
  walletSessionAuth: SealedRecoveryWalletSessionAuth;
};

export type PasskeyEcdsaSealedRecoveryRecord = EcdsaSealedRecoveryRecordBase &
  SealedRecoveryWalletSessionAuthCarrier & {
    authMethod: 'passkey';
    rpId: string;
    credentialIdB64u: string;
    clientVerifyingShareB64u: string;
    walletKeyId?: never;
    providerSubjectId?: never;
    authSubjectId?: never;
  };

export type EmailOtpEcdsaSealedRecoveryRecord = EcdsaSealedRecoveryRecordBase &
  SealedRecoveryWalletSessionAuthCarrier & {
    authMethod: 'email_otp';
    walletKeyId: string;
    providerSubjectId: string;
    clientVerifyingShareB64u?: string;
    companionEd25519ThresholdSessionId?: string;
    companionEd25519Recovery?: EmailOtpEcdsaCompanionEd25519Recovery;
    credentialIdB64u?: never;
    authSubjectId?: never;
    rpId?: never;
  };

export type EmailOtpEcdsaCompanionEd25519Recovery = Ed25519SealedRecoveryRecordBase &
  SealedRecoveryWalletSessionAuthCarrier & {
    authMethod: 'email_otp';
    rpId: string;
    providerSubjectId: string;
    routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
    credentialIdB64u?: never;
    authSubjectId?: never;
  };

export type PasskeyEd25519SealedRecoveryRecord = Ed25519SealedRecoveryRecordBase &
  SealedRecoveryWalletSessionAuthCarrier & {
	    authMethod: 'passkey';
	    rpId: string;
	    credentialIdB64u: string;
	    xClientBaseB64u?: never;
	    routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
	    providerSubjectId?: never;
	    authSubjectId?: never;
	  };

export type EmailOtpEd25519SealedRecoveryRecord = Ed25519SealedRecoveryRecordBase &
  SealedRecoveryWalletSessionAuthCarrier & {
    authMethod: 'email_otp';
    rpId: string;
    providerSubjectId: string;
    routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
    companionEcdsaRecovery?: EmailOtpEcdsaSealedRecoveryRecord;
    credentialIdB64u?: never;
    authSubjectId?: never;
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

function normalizedEd25519WorkerMaterialFields(
  restore: RawEd25519RestoreMetadata,
): Pick<
  Ed25519SealedRecoveryRecordBase,
  | 'clientVerifyingShareB64u'
  | 'ed25519WorkerMaterialBindingDigest'
  | 'sealedWorkerMaterialRef'
  | 'sealedWorkerMaterialB64u'
  | 'materialFormatVersion'
  | 'materialKeyId'
  | 'materialCreatedAtMs'
> {
  const clientVerifyingShareB64u = normalizeNonEmptyString(restore.clientVerifyingShareB64u);
  const ed25519WorkerMaterialBindingDigest = normalizeNonEmptyString(
    restore.ed25519WorkerMaterialBindingDigest,
  );
  const sealedWorkerMaterialRef = normalizeNonEmptyString(restore.sealedWorkerMaterialRef);
  const sealedWorkerMaterialB64u = normalizeNonEmptyString(restore.sealedWorkerMaterialB64u);
  const materialFormatVersion = normalizeNonEmptyString(restore.materialFormatVersion);
  const materialKeyId = normalizeNonEmptyString(restore.materialKeyId);
  const materialCreatedAtMs = Math.floor(Number(restore.materialCreatedAtMs) || 0);
  return {
    ...(clientVerifyingShareB64u ? { clientVerifyingShareB64u } : {}),
    ...(ed25519WorkerMaterialBindingDigest ? { ed25519WorkerMaterialBindingDigest } : {}),
    ...(sealedWorkerMaterialRef ? { sealedWorkerMaterialRef } : {}),
    ...(sealedWorkerMaterialB64u ? { sealedWorkerMaterialB64u } : {}),
    ...(materialFormatVersion ? { materialFormatVersion } : {}),
    ...(materialKeyId ? { materialKeyId } : {}),
    ...(materialCreatedAtMs > 0 ? { materialCreatedAtMs } : {}),
  };
}

function normalizeRawObject<TValue extends object>(value: unknown): Partial<TValue> | null {
  return value && typeof value === 'object' ? (value as Partial<TValue>) : null;
}

function normalizeThresholdSessionIds(
  record: RawSigningSessionSealedStoreRecord,
): RawThresholdSessionIds {
  const current = normalizeRawObject<RawThresholdSessionIds>(record.thresholdSessionIds) || {};
  if (normalizeNonEmptyString(current.ed25519) || normalizeNonEmptyString(current.ecdsa)) {
    return current;
  }
  const legacyThresholdSessionId = normalizeNonEmptyString(record.thresholdSessionId);
  if (!legacyThresholdSessionId) return {};
  if (record.curve === 'ed25519') return { ed25519: legacyThresholdSessionId };
  if (record.curve === 'ecdsa') return { ecdsa: legacyThresholdSessionId };
  return {};
}

function legacySigningGrantFieldName(): string {
  return ['wallet', 'SigningSessionId'].join('');
}

function normalizeSigningGrantId(record: RawSigningSessionSealedStoreRecord): string | null {
  return (
    normalizeNonEmptyString(record.signingGrantId) ||
    normalizeNonEmptyString(record[legacySigningGrantFieldName()])
  );
}

function normalizeSessionKind(value: unknown): ThresholdSessionKind | null {
  return value === 'jwt' || value === 'cookie' ? value : null;
}

export function sealedRecoverySessionKind(
  auth: SealedRecoveryWalletSessionAuth,
): ThresholdSessionKind {
  return 'jwt';
}

export function sealedRecoveryWalletSessionJwt(
  auth: SealedRecoveryWalletSessionAuth,
): string | undefined {
  return auth.kind === 'wallet_session_jwt' ? auth.walletSessionJwt : undefined;
}

function normalizeEthereumAddress(value: unknown): `0x${string}` | null {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(normalized) ? (normalized as `0x${string}`) : null;
}

function normalizeWalletSessionAuthFromStoredRestoreOrReject(args: {
  record: RawSigningSessionSealedStoreRecord;
  sessionKind: ThresholdSessionKind | null;
  walletSessionJwt: unknown;
}): SealedRecoveryWalletSessionAuthCarrier | NormalizeSealedRecoveryRecordResult {
  if (!args.sessionKind) {
    return reject(args.record, 'missing_restore_metadata');
  }
  if (args.sessionKind === 'cookie') return reject(args.record, 'missing_restore_metadata');
  const walletSessionJwt = normalizeNonEmptyString(args.walletSessionJwt);
  if (!walletSessionJwt) {
    return reject(args.record, 'missing_restore_metadata');
  }
  return {
    walletSessionAuth: {
      kind: 'wallet_session_jwt',
      walletSessionJwt: walletSessionJwt,
    },
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
  rawWalletSessionJwt: unknown;
}): ThresholdRuntimePolicyScope | undefined {
  const explicit = normalizeThresholdRuntimePolicyScope(args.rawRuntimePolicyScope);
  if (explicit) return explicit;
  const walletSessionJwt = normalizeNonEmptyString(args.rawWalletSessionJwt);
  if (!walletSessionJwt) return undefined;
  return parseThresholdRuntimePolicyScopeFromJwt(walletSessionJwt);
}

function safeSummary(record: RawSigningSessionSealedStoreRecord): Record<string, unknown> {
  const thresholdSessionIds = normalizeThresholdSessionIds(record);
  return {
    authMethod: record.authMethod,
    curve: record.curve,
    storeKey: record.storeKey,
    walletId: record.walletId || null,
    signingGrantId: normalizeSigningGrantId(record),
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
  const signingGrantId = normalizeSigningGrantId(raw);
  const sealedSecretB64u = normalizeNonEmptyString(raw.sealedSecretB64u);
  const issuedAtMs = Math.floor(Number(raw.issuedAtMs) || 0);
  const expiresAtMs = Math.floor(Number(raw.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(raw.remainingUses) || 0);
  const updatedAtMs = Math.floor(Number(raw.updatedAtMs) || 0);

  if (
    (raw.authMethod !== 'passkey' && raw.authMethod !== 'email_otp') ||
    (raw.curve !== 'ed25519' && raw.curve !== 'ecdsa')
  ) {
    return reject(raw, 'unsupported_record');
  }
  if (!storeKey || !walletId || !signingGrantId || !sealedSecretB64u) {
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
      rawWalletSessionJwt: restore?.walletSessionJwt,
    });
    const signingRootBinding = resolveSigningRootBinding({
      runtimePolicyScope,
      rawSigningRootId: raw.signingRootId,
      rawSigningRootVersion: raw.signingRootVersion,
    });
    const relayerUrl = normalizeNonEmptyString(raw.relayerUrl);
	    const companionRpIdHint = normalizeNonEmptyString(ed25519Restore?.rpId);
	    const passkeyRpId = normalizeNonEmptyString(restore?.rpId) || companionRpIdHint;
	    const walletKeyId = normalizeNonEmptyString(restore?.walletKeyId);
    const credentialIdB64u = normalizeNonEmptyString(restore?.credentialIdB64u);
    const providerSubjectId =
      normalizeNonEmptyString(restore?.providerSubjectId) ||
      normalizeNonEmptyString(restore?.authSubjectId);
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
	      (raw.authMethod === 'passkey' && !passkeyRpId) ||
	      (raw.authMethod === 'email_otp' && !walletKeyId) ||
      (raw.authMethod === 'passkey' && !credentialIdB64u) ||
      (raw.authMethod === 'email_otp' && !providerSubjectId) ||
      !ecdsaThresholdKeyId ||
      !relayerKeyId ||
      !keyHandle ||
      !ethereumAddress ||
      !participantIds.length ||
      (raw.authMethod === 'passkey' && !passkeyClientVerifyingShareB64u)
    ) {
      return reject(raw, 'missing_restore_metadata');
    }
    const walletSessionAuth = normalizeWalletSessionAuthFromStoredRestoreOrReject({
      record: raw,
      sessionKind,
      walletSessionJwt: restore.walletSessionJwt,
    });
    if ('kind' in walletSessionAuth) {
      return walletSessionAuth;
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
      const companionProviderSubjectId =
        normalizeNonEmptyString(ed25519Restore.providerSubjectId) ||
        normalizeNonEmptyString(ed25519Restore.authSubjectId);
      const companionNearAccountId = normalizeNonEmptyString(ed25519Restore.nearAccountId);
      const companionNearEd25519SigningKeyId = normalizeNonEmptyString(
        ed25519Restore.nearEd25519SigningKeyId,
      );
      const companionRelayerKeyId = normalizeNonEmptyString(ed25519Restore.relayerKeyId);
      const companionParticipantIds = normalizeParticipantIds(ed25519Restore.participantIds);
      const companionXClientBaseB64u = normalizeNonEmptyString(ed25519Restore.xClientBaseB64u);
	      const companionSignerSlot = Math.floor(Number(ed25519Restore.signerSlot) || 0);
      const companionRouterAbNormalSigning = parseRouterAbEd25519NormalSigningState(
        ed25519Restore.routerAbNormalSigning,
      );
      const companionSessionKind = normalizeSessionKind(ed25519Restore.sessionKind);
      const companionWalletSessionJwt = normalizeNonEmptyString(
        ed25519Restore.walletSessionJwt,
      );
      let companionWalletSessionAuth: SealedRecoveryWalletSessionAuthCarrier | null = null;
      if (companionSessionKind === 'jwt' && companionWalletSessionJwt) {
        companionWalletSessionAuth = {
          walletSessionAuth: {
            kind: 'wallet_session_jwt',
            walletSessionJwt: companionWalletSessionJwt,
          },
        };
      }
      if (
        companionRpId &&
        companionProviderSubjectId &&
        companionNearAccountId &&
        companionNearEd25519SigningKeyId &&
        companionRelayerKeyId &&
        companionParticipantIds.length &&
        companionSignerSlot > 0 &&
	        !companionXClientBaseB64u &&
	        companionWalletSessionAuth
	      ) {
        const companionRuntimePolicyScope = resolveRuntimePolicyScope({
          rawRuntimePolicyScope: ed25519Restore.runtimePolicyScope,
          rawWalletSessionJwt: ed25519Restore.walletSessionJwt,
        });
        companionEd25519Recovery = {
          storeKey,
          walletId,
          authMethod: 'email_otp',
          curve: 'ed25519',
          signingGrantId,
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
	          nearAccountId: companionNearAccountId,
	          nearEd25519SigningKeyId: companionNearEd25519SigningKeyId,
	          ...normalizedEd25519WorkerMaterialFields(ed25519Restore),
	          rpId: companionRpId,
          providerSubjectId: companionProviderSubjectId,
          relayerKeyId: companionRelayerKeyId,
          participantIds: companionParticipantIds,
          signerSlot: companionSignerSlot,
          ...companionWalletSessionAuth,
          ...(companionRuntimePolicyScope
            ? { runtimePolicyScope: companionRuntimePolicyScope }
            : {}),
          ...(companionRouterAbNormalSigning
            ? { routerAbNormalSigning: companionRouterAbNormalSigning }
            : {}),
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
            signingGrantId,
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
	            rpId: passkeyRpId!,
            credentialIdB64u: credentialIdB64u!,
            signingRootId: signingRootBinding.signingRootId,
            signingRootVersion: signingRootBinding.signingRootVersion,
            keyHandle,
            ecdsaThresholdKeyId,
            ethereumAddress,
            ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
            participantIds,
            relayerUrl,
            relayerKeyId,
            ...walletSessionAuth,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
            clientVerifyingShareB64u: passkeyClientVerifyingShareB64u!,
          }
        : {
            storeKey,
            walletId,
            authMethod: 'email_otp',
            curve: 'ecdsa',
            signingGrantId,
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
	            walletKeyId: walletKeyId!,
            providerSubjectId: providerSubjectId!,
            signingRootId: signingRootBinding.signingRootId,
            signingRootVersion: signingRootBinding.signingRootVersion,
            keyHandle,
            ecdsaThresholdKeyId,
            ethereumAddress,
            ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
            participantIds,
            relayerUrl,
            relayerKeyId,
            ...walletSessionAuth,
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
  const nearAccountId = normalizeNonEmptyString(restore?.nearAccountId);
  const nearEd25519SigningKeyId = normalizeNonEmptyString(restore?.nearEd25519SigningKeyId);
  const relayerKeyId = normalizeNonEmptyString(restore?.relayerKeyId);
  const rpId = normalizeNonEmptyString(restore?.rpId);
  const credentialIdB64u = normalizeNonEmptyString(restore?.credentialIdB64u);
  const providerSubjectId =
    normalizeNonEmptyString(restore?.providerSubjectId) ||
    normalizeNonEmptyString(restore?.authSubjectId);
  const participantIds = normalizeParticipantIds(restore?.participantIds);
  const xClientBaseB64u = normalizeNonEmptyString(restore?.xClientBaseB64u);
	  const signerSlot = Math.floor(Number(restore?.signerSlot) || 0);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    restore?.routerAbNormalSigning,
  );
  const sessionKind = normalizeSessionKind(restore?.sessionKind);
  if (!thresholdSessionId) return reject(raw, 'missing_identity');
  if (
    !restore ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !rpId ||
    (raw.authMethod === 'passkey' && !credentialIdB64u) ||
    (raw.authMethod === 'email_otp' && !providerSubjectId) ||
    !relayerUrl ||
    !relayerKeyId ||
	    !participantIds.length ||
	    signerSlot <= 0 ||
	    xClientBaseB64u
	  ) {
    return reject(raw, 'missing_restore_metadata');
  }
  const walletSessionAuth = normalizeWalletSessionAuthFromStoredRestoreOrReject({
    record: raw,
    sessionKind,
    walletSessionJwt: restore.walletSessionJwt,
  });
  if ('kind' in walletSessionAuth) {
    return walletSessionAuth;
  }
  const runtimePolicyScope = resolveRuntimePolicyScope({
    rawRuntimePolicyScope: restore.runtimePolicyScope,
    rawWalletSessionJwt: restore.walletSessionJwt,
  });
  let companionEcdsaRecovery: EmailOtpEcdsaSealedRecoveryRecord | undefined;
  if (raw.authMethod === 'email_otp' && (thresholdSessionIds.ecdsa || ecdsaRestore)) {
    const companionRuntimePolicyScope = resolveRuntimePolicyScope({
      rawRuntimePolicyScope: ecdsaRestore?.runtimePolicyScope,
      rawWalletSessionJwt: ecdsaRestore?.walletSessionJwt,
    });
    const companionSigningRootBinding = resolveSigningRootBinding({
      runtimePolicyScope: companionRuntimePolicyScope,
      rawSigningRootId: raw.signingRootId,
      rawSigningRootVersion: raw.signingRootVersion,
    });
    const companionEcdsaThresholdKeyId = normalizeNonEmptyString(ecdsaRestore?.ecdsaThresholdKeyId);
    const companionProviderSubjectId =
      normalizeNonEmptyString(ecdsaRestore?.providerSubjectId) ||
      normalizeNonEmptyString(ecdsaRestore?.authSubjectId);
    if (
      !thresholdSessionIds.ecdsa ||
      !ecdsaRestore ||
      !ecdsaRestore.chainTarget ||
      !companionSigningRootBinding ||
      !companionEcdsaThresholdKeyId ||
      !normalizeNonEmptyString(raw.relayerUrl) ||
	      !normalizeNonEmptyString(ecdsaRestore.walletKeyId) ||
      !companionProviderSubjectId ||
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
    const companionWalletSessionAuth = normalizeWalletSessionAuthFromStoredRestoreOrReject({
      record: raw,
      sessionKind: normalizeSessionKind(ecdsaRestore.sessionKind),
      walletSessionJwt: ecdsaRestore.walletSessionJwt,
    });
    if ('kind' in companionWalletSessionAuth) {
      return companionWalletSessionAuth;
    }
    companionEcdsaRecovery = {
      storeKey,
      walletId,
      authMethod: 'email_otp',
      curve: 'ecdsa',
      signingGrantId,
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
	      walletKeyId: normalizeNonEmptyString(ecdsaRestore.walletKeyId)!,
      providerSubjectId: companionProviderSubjectId,
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
      ...companionWalletSessionAuth,
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
          signingGrantId,
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
	          nearAccountId,
	          nearEd25519SigningKeyId,
	          ...normalizedEd25519WorkerMaterialFields(restore),
	          rpId,
          credentialIdB64u: credentialIdB64u!,
          relayerKeyId,
          participantIds,
          signerSlot,
          ...walletSessionAuth,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
        }
      : {
          storeKey,
          walletId,
          authMethod: 'email_otp',
          curve: 'ed25519',
          signingGrantId,
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
	          nearAccountId,
	          nearEd25519SigningKeyId,
	          ...normalizedEd25519WorkerMaterialFields(restore),
	          rpId,
          providerSubjectId: providerSubjectId!,
          relayerKeyId,
          participantIds,
          signerSlot,
          ...walletSessionAuth,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
          ...(companionEcdsaRecovery
            ? {
                companionEcdsaRecovery,
              }
            : {}),
        };
  return { kind: 'accepted', record: accepted };
}
