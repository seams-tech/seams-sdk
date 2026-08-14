import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetFromRequest } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import {
  parseRouterAbEcdsaDerivationNormalSigningStateV1,
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  buildPasskeyWalletAuthAuthority,
  parseEmailOtpWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
  type EmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { RawSealedSessionRecord } from '../persistence/sealedSessionStore';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import {
  parseEcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalPersistedMaterialRef,
} from '../keyMaterialBrands';

type RawThresholdSessionIds = {
  ecdsa?: unknown;
};

type RawEcdsaRestoreMetadata = {
  chainTarget?: unknown;
  source?: unknown;
  signingRootId?: unknown;
  signingRootVersion?: unknown;
  rpId?: unknown;
  credentialIdB64u?: unknown;
  providerSubjectId?: unknown;
  provider?: unknown;
  emailHashHex?: unknown;
  authority?: unknown;
  emailOtpAuthority?: unknown;
  sessionKind?: unknown;
  keyHandle?: unknown;
  ecdsaThresholdKeyId?: unknown;
  ethereumAddress?: unknown;
  relayerKeyId?: unknown;
  clientVerifyingShareB64u?: unknown;
  thresholdEcdsaPublicKeyB64u?: unknown;
  participantIds?: unknown;
  runtimePolicyScope?: unknown;
  routerAbEcdsaDerivationNormalSigning?: unknown;
  publicCapability?: unknown;
  roleLocalMaterialRef?: unknown;
};

export type RawSigningSessionSealedStoreRecord = RawSealedSessionRecord & {
  storeKey?: unknown;
  walletId?: unknown;
  userId?: unknown;
  authMethod?: unknown;
  curve?: unknown;
  thresholdSessionIds?: RawThresholdSessionIds | unknown;
  sealedSecretB64u?: unknown;
  subjectId?: unknown;
  signingRootId?: unknown;
  signingRootVersion?: unknown;
  relayerUrl?: unknown;
  keyVersion?: unknown;
  groupId?: unknown;
  ecdsaRestore?: RawEcdsaRestoreMetadata | unknown;
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
  curve: 'ecdsa';
  thresholdSessionId: string;
  sealedSecretB64u: string;
  issuedAtMs: number;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs: number;
  keyVersion?: string;
  groupId?: string;
};

type EcdsaSealedRecoveryRecordBase = SealedRecoveryRecordBase & {
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  signingRootId: string;
  signingRootVersion: string;
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  ethereumAddress: `0x${string}`;
  thresholdEcdsaPublicKeyB64u: string;
  participantIds: readonly number[];
  relayerUrl: string;
  relayerKeyId: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
};

export type PasskeyEcdsaSealedRecoveryRecord = EcdsaSealedRecoveryRecordBase & {
  authMethod: 'passkey';
  source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  authority: PasskeyWalletAuthAuthority;
  clientVerifyingShareB64u: string;
  roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
  rpId?: never;
  credentialIdB64u?: never;
  providerSubjectId?: never;
  emailHashHex?: never;
  authSubjectId?: never;
};

export type EmailOtpEcdsaSealedRecoveryRecord = EcdsaSealedRecoveryRecordBase & {
  authMethod: 'email_otp';
  source: 'email_otp';
  authority: WalletAuthAuthorityRef;
  emailOtpAuthority: EmailOtpWalletAuthAuthority;
  clientVerifyingShareB64u?: string;
  credentialIdB64u?: never;
  providerSubjectId?: never;
  emailHashHex?: never;
  authSubjectId?: never;
  roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
  rpId?: never;
};

export type SealedRecoveryRecord =
  | PasskeyEcdsaSealedRecoveryRecord
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

function normalizeRouterAbEcdsaDerivationNormalSigningState(
  value: unknown,
): RouterAbEcdsaDerivationNormalSigningStateV1 | null {
  try {
    return parseRouterAbEcdsaDerivationNormalSigningStateV1(value);
  } catch {
    return null;
  }
}

function normalizeRouterAbEcdsaDerivationPublicCapability(
  value: unknown,
): RouterAbEcdsaDerivationPublicCapabilityV1 | null {
  try {
    return parseRouterAbEcdsaDerivationPublicCapabilityV1(value);
  } catch {
    return null;
  }
}

function normalizeEcdsaRestoreSource(value: unknown): ThresholdEcdsaSessionStoreSource | null {
  switch (value) {
    case 'login':
    case 'registration':
    case 'manual-bootstrap':
    case 'email_otp':
      return value;
    default:
      return null;
  }
}

function normalizePasskeyEcdsaRestoreSource(
  value: unknown,
): Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'> | null {
  const source = normalizeEcdsaRestoreSource(value);
  return source && source !== 'email_otp' ? source : null;
}

function normalizeRawObject<TValue extends object>(value: unknown): Partial<TValue> | null {
  return value && typeof value === 'object' ? (value as Partial<TValue>) : null;
}

function normalizeThresholdSessionIds(
  record: RawSigningSessionSealedStoreRecord,
): RawThresholdSessionIds {
  const current = normalizeRawObject<RawThresholdSessionIds>(record.thresholdSessionIds) || {};
  return current;
}

function normalizeEthereumAddress(value: unknown): `0x${string}` | null {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(normalized) ? (normalized as `0x${string}`) : null;
}

function buildPasskeyAuthorityForSealedRecord(args: {
  walletId: string;
  rpId: string;
  credentialIdB64u: string;
}): PasskeyWalletAuthAuthority | null {
  try {
    return buildPasskeyWalletAuthAuthority(args);
  } catch {
    return null;
  }
}

function resolveSigningRootBinding(args: {
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  rawSigningRootId?: unknown;
  rawSigningRootVersion?: unknown;
}): { signingRootId: string; signingRootVersion: string } | null {
  const explicitSigningRootId = normalizeNonEmptyString(args.rawSigningRootId);
  const explicitSigningRootVersion = normalizeNonEmptyString(args.rawSigningRootVersion);
  let runtimeSigningRootId: string | null = null;
  let runtimeSigningRootVersion: string | null = null;
  if (args.runtimePolicyScope) {
    try {
      const scope = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
      runtimeSigningRootId = normalizeNonEmptyString(scope.signingRootId);
      runtimeSigningRootVersion = normalizeNonEmptyString(scope.signingRootVersion);
    } catch {}
  }
  if (
    explicitSigningRootId &&
    runtimeSigningRootId &&
    explicitSigningRootId !== runtimeSigningRootId
  ) {
    return null;
  }
  if (
    explicitSigningRootVersion &&
    runtimeSigningRootVersion &&
    explicitSigningRootVersion !== runtimeSigningRootVersion
  ) {
    return null;
  }
  const signingRootId = explicitSigningRootId || runtimeSigningRootId;
  const signingRootVersion = explicitSigningRootVersion || runtimeSigningRootVersion;
  if (signingRootId && signingRootVersion) {
    return { signingRootId, signingRootVersion };
  }
  return null;
}

function hasRawSigningRootBinding(record: RawSigningSessionSealedStoreRecord): boolean {
  return Boolean(
    normalizeNonEmptyString(record.signingRootId) ||
    normalizeNonEmptyString(record.signingRootVersion),
  );
}

function hasRawLegacySealedRecoveryIdentity(record: RawSigningSessionSealedStoreRecord): boolean {
  return Boolean(
    normalizeNonEmptyString(record.subjectId) || normalizeNonEmptyString(record.userId),
  );
}

function safeSummary(record: RawSigningSessionSealedStoreRecord): Record<string, unknown> {
  const thresholdSessionIds = normalizeThresholdSessionIds(record);
  return {
    authMethod: record.authMethod,
    curve: record.curve,
    storeKey: record.storeKey,
    walletId: record.walletId || null,
    thresholdSessionIds,
    issuedAtMs: record.issuedAtMs,
    expiresAtMs: record.expiresAtMs,
    remainingUses: record.remainingUses,
    updatedAtMs: record.updatedAtMs,
    hasEcdsaRestore: Boolean(record.ecdsaRestore),
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
  const storeKey = normalizeNonEmptyString(raw.storeKey);
  const walletId = normalizeNonEmptyString(raw.walletId);
  const sealedSecretB64u = normalizeNonEmptyString(raw.sealedSecretB64u);
  const issuedAtMs = Math.floor(Number(raw.issuedAtMs) || 0);
  const expiresAtMs = Math.floor(Number(raw.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(raw.remainingUses) || 0);
  const updatedAtMs = Math.floor(Number(raw.updatedAtMs) || 0);

  if ((raw.authMethod !== 'passkey' && raw.authMethod !== 'email_otp') || raw.curve !== 'ecdsa') {
    return reject(raw, 'unsupported_record');
  }
  if (!storeKey || !walletId || !sealedSecretB64u) {
    return reject(raw, 'missing_identity');
  }
  if (expiresAtMs <= 0 || updatedAtMs <= 0 || issuedAtMs <= 0) {
    return reject(raw, 'missing_restore_metadata');
  }
  if (hasRawLegacySealedRecoveryIdentity(raw)) {
    return reject(raw, 'invalid_identity');
  }
  if (!options.allowExpired && expiresAtMs <= Date.now()) return reject(raw, 'expired');
  if (!options.allowExhausted && raw.authMethod !== 'passkey' && remainingUses <= 0) {
    return reject(raw, 'exhausted');
  }

  const thresholdSessionId = normalizeNonEmptyString(thresholdSessionIds.ecdsa);
  const restore = ecdsaRestore;
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(restore?.runtimePolicyScope);
  const signingRootBinding = resolveSigningRootBinding({
    runtimePolicyScope,
    rawSigningRootId: restore?.signingRootId,
    rawSigningRootVersion: restore?.signingRootVersion,
  });
  const relayerUrl = normalizeNonEmptyString(raw.relayerUrl);
  const passkeyRpId = raw.authMethod === 'passkey' ? normalizeNonEmptyString(restore?.rpId) : null;
  const passkeySource =
    raw.authMethod === 'passkey' ? normalizePasskeyEcdsaRestoreSource(restore?.source) : null;
  const emailOtpSource =
    raw.authMethod === 'email_otp' && normalizeEcdsaRestoreSource(restore?.source) === 'email_otp'
      ? 'email_otp'
      : null;
  const credentialIdB64u = normalizeNonEmptyString(restore?.credentialIdB64u);
  const providerSubjectId = normalizeNonEmptyString(restore?.providerSubjectId);
  const emailHashHex = normalizeNonEmptyString(restore?.emailHashHex);
  const relayerKeyId = normalizeNonEmptyString(restore?.relayerKeyId);
  const keyHandle = normalizeNonEmptyString(restore?.keyHandle);
  const ecdsaThresholdKeyId = normalizeNonEmptyString(restore?.ecdsaThresholdKeyId);
  const ethereumAddress = normalizeEthereumAddress(restore?.ethereumAddress);
  const thresholdEcdsaPublicKeyB64u = normalizeNonEmptyString(restore?.thresholdEcdsaPublicKeyB64u);
  const participantIds = normalizeParticipantIds(restore?.participantIds);
  const routerAbEcdsaDerivationNormalSigning = normalizeRouterAbEcdsaDerivationNormalSigningState(
    restore?.routerAbEcdsaDerivationNormalSigning,
  );
  const publicCapability = normalizeRouterAbEcdsaDerivationPublicCapability(
    restore?.publicCapability,
  );
  let roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef | null = null;
  try {
    roleLocalMaterialRef = parseEcdsaRoleLocalPersistedMaterialRef(restore?.roleLocalMaterialRef);
  } catch {
    roleLocalMaterialRef = null;
  }
  const clientVerifyingShareB64u = normalizeNonEmptyString(restore?.clientVerifyingShareB64u);
  const passkeyClientVerifyingShareB64u =
    raw.authMethod === 'passkey' ? clientVerifyingShareB64u : null;
  if (restore?.sessionKind != null) {
    return reject(raw, 'invalid_identity');
  }
  if (hasRawSigningRootBinding(raw)) {
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
    (raw.authMethod === 'passkey' && !passkeySource) ||
    (raw.authMethod === 'email_otp' && !emailOtpSource) ||
    (raw.authMethod === 'passkey' && !passkeyRpId) ||
    (raw.authMethod === 'passkey' && !credentialIdB64u) ||
    (raw.authMethod === 'email_otp' && (!providerSubjectId || !emailHashHex)) ||
    !ecdsaThresholdKeyId ||
    !relayerKeyId ||
    !keyHandle ||
    !ethereumAddress ||
    !thresholdEcdsaPublicKeyB64u ||
    !runtimePolicyScope ||
    !routerAbEcdsaDerivationNormalSigning ||
    !publicCapability ||
    !participantIds.length ||
    !roleLocalMaterialRef ||
    (raw.authMethod === 'passkey' && !passkeyClientVerifyingShareB64u)
  ) {
    return reject(raw, 'missing_restore_metadata');
  }
  const passkeyAuthority =
    raw.authMethod === 'passkey'
      ? buildPasskeyAuthorityForSealedRecord({
          walletId,
          rpId: passkeyRpId!,
          credentialIdB64u: credentialIdB64u!,
        })
      : null;
  const authority = parseWalletAuthAuthorityRef(restore.authority);
  const parsedAuthority = parseEmailOtpWalletAuthAuthority(restore.emailOtpAuthority);
  const emailOtpAuthority =
    raw.authMethod === 'email_otp' &&
    authority &&
    parsedAuthority &&
    parsedAuthority.walletId === walletId &&
    parsedAuthority.factor.provider === restore.provider &&
    parsedAuthority.factor.providerUserId === providerSubjectId &&
    parsedAuthority.verifier.emailHashHex === emailHashHex
      ? parsedAuthority
      : null;
  if (
    (raw.authMethod === 'passkey' && !passkeyAuthority) ||
    (raw.authMethod === 'email_otp' && !emailOtpAuthority)
  ) {
    return reject(raw, 'invalid_identity');
  }
  const accepted: SealedRecoveryRecord =
    raw.authMethod === 'passkey'
      ? {
          storeKey,
          walletId,
          authMethod: 'passkey',
          curve: 'ecdsa',
          thresholdSessionId,
          sealedSecretB64u,
          issuedAtMs,
          expiresAtMs,
          remainingUses,
          updatedAtMs,
          ...(normalizeNonEmptyString(raw.keyVersion)
            ? { keyVersion: normalizeNonEmptyString(raw.keyVersion)! }
            : {}),
          ...(normalizeNonEmptyString(raw.groupId)
            ? { groupId: normalizeNonEmptyString(raw.groupId)! }
            : {}),
          chainTarget,
          source: passkeySource!,
          authority: passkeyAuthority!,
          signingRootId: signingRootBinding.signingRootId,
          signingRootVersion: signingRootBinding.signingRootVersion,
          keyHandle,
          ecdsaThresholdKeyId,
          ethereumAddress,
          thresholdEcdsaPublicKeyB64u,
          participantIds,
          relayerUrl,
          relayerKeyId,
          runtimePolicyScope,
          routerAbEcdsaDerivationNormalSigning,
          publicCapability,
          clientVerifyingShareB64u: passkeyClientVerifyingShareB64u!,
          roleLocalMaterialRef: roleLocalMaterialRef!,
        }
      : {
          storeKey,
          walletId,
          authMethod: 'email_otp',
          curve: 'ecdsa',
          thresholdSessionId,
          sealedSecretB64u,
          issuedAtMs,
          expiresAtMs,
          remainingUses,
          updatedAtMs,
          ...(normalizeNonEmptyString(raw.keyVersion)
            ? { keyVersion: normalizeNonEmptyString(raw.keyVersion)! }
            : {}),
          ...(normalizeNonEmptyString(raw.groupId)
            ? { groupId: normalizeNonEmptyString(raw.groupId)! }
            : {}),
          chainTarget,
          source: 'email_otp',
          authority: authority!,
          emailOtpAuthority: emailOtpAuthority!,
          signingRootId: signingRootBinding.signingRootId,
          signingRootVersion: signingRootBinding.signingRootVersion,
          keyHandle,
          ecdsaThresholdKeyId,
          ethereumAddress,
          thresholdEcdsaPublicKeyB64u,
          participantIds,
          relayerUrl,
          relayerKeyId,
          runtimePolicyScope,
          routerAbEcdsaDerivationNormalSigning,
          publicCapability,
          ...(clientVerifyingShareB64u ? { clientVerifyingShareB64u } : {}),
          roleLocalMaterialRef,
        };
  return { kind: 'accepted', record: accepted };
}
