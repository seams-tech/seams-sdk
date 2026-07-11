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
import {
  parseRouterAbEcdsaHssNormalSigningStateV1,
  type RouterAbEcdsaHssNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaHss';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { RawSealedSessionRecord } from '../persistence/sealedSessionStore';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';

type RawThresholdSessionIds = {
  ed25519?: unknown;
  ecdsa?: unknown;
};

type RawEcdsaRestoreMetadata = {
  chainTarget?: unknown;
  source?: unknown;
  evmFamilySigningKeySlotId?: unknown;
  signingRootId?: unknown;
  signingRootVersion?: unknown;
  rpId?: unknown;
  credentialIdB64u?: unknown;
  providerSubjectId?: unknown;
  emailHashHex?: unknown;
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
  routerAbEcdsaHssNormalSigning?: unknown;
};

type RawEd25519RestoreMetadata = {
  nearAccountId?: unknown;
  nearEd25519SigningKeyId?: unknown;
  rpId?: unknown;
  credentialIdB64u?: unknown;
  providerSubjectId?: unknown;
  emailHashHex?: unknown;
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
  routerAbEcdsaHssNormalSigning: RouterAbEcdsaHssNormalSigningStateV1;
};

// The durable record's material fields are a CACHE of the runtime session
// record's material, written at seal time. Material rotates in generations
// (materialCreatedAtMs is baked into materialKeyId), so this cache can be
// generations behind the live record. Grouping the fields under `materialCache`
// keeps that epistemic status visible at every consumer: cache data plans
// restores and feeds lane hints; it must never overwrite newer runtime material
// (see session/ed25519MaterialAdvance.ts) and must never be compared against the
// live record as a hard equality (see session/ed25519MaterialAuthority.ts).
export type Ed25519SealedMaterialCache = {
  clientVerifyingShareB64u: string;
  ed25519WorkerMaterialBindingDigest: string;
  sealedWorkerMaterialRef: string;
  sealedWorkerMaterialB64u?: string;
  materialFormatVersion: string;
  materialKeyId: string;
  /** Material generation (binding createdAtMs); orders this cache vs the runtime record. */
  materialCreatedAtMs: number;
};

type Ed25519SealedRecoveryRecordBase = SealedRecoveryRecordBase & {
  curve: 'ed25519';
  // Identity fields: long-lived truth about the lane this record can restore.
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  signerSlot: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  // Cache fields: refreshable snapshot of the material generation sealed here.
  materialCache: Ed25519SealedMaterialCache;
};

export type SealedRecoveryWalletSessionAuth = {
  kind: 'wallet_session_jwt';
  walletSessionJwt: string;
};

type SealedRecoveryWalletSessionAuthCarrier = {
  walletSessionAuth: SealedRecoveryWalletSessionAuth;
};

export type PasskeyEcdsaSealedRecoveryRecord = EcdsaSealedRecoveryRecordBase &
  SealedRecoveryWalletSessionAuthCarrier & {
    authMethod: 'passkey';
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
    authority: PasskeyWalletAuthAuthority;
    evmFamilySigningKeySlotId: string;
    clientVerifyingShareB64u: string;
    rpId?: never;
    credentialIdB64u?: never;
    providerSubjectId?: never;
    emailHashHex?: never;
    authSubjectId?: never;
  };

export type EmailOtpEcdsaSealedRecoveryRecord = EcdsaSealedRecoveryRecordBase &
  SealedRecoveryWalletSessionAuthCarrier & {
    authMethod: 'email_otp';
    source: 'email_otp';
    authority: EmailOtpWalletAuthAuthority;
    evmFamilySigningKeySlotId: string;
    clientVerifyingShareB64u?: string;
    companionEd25519ThresholdSessionId?: string;
    companionEd25519Recovery?: EmailOtpEcdsaCompanionEd25519Recovery;
    credentialIdB64u?: never;
    providerSubjectId?: never;
    emailHashHex?: never;
    authSubjectId?: never;
    rpId?: never;
  };

export type EmailOtpEcdsaCompanionEd25519Recovery = Ed25519SealedRecoveryRecordBase &
  SealedRecoveryWalletSessionAuthCarrier & {
    authMethod: 'email_otp';
    authority: EmailOtpWalletAuthAuthority;
    rpId?: never;
    routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
    credentialIdB64u?: never;
    providerSubjectId?: never;
    emailHashHex?: never;
    authSubjectId?: never;
  };

export type PasskeyEd25519SealedRecoveryRecord = Ed25519SealedRecoveryRecordBase &
  SealedRecoveryWalletSessionAuthCarrier & {
	    authMethod: 'passkey';
	    authority: PasskeyWalletAuthAuthority;
	    xClientBaseB64u?: never;
	    routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
	    rpId?: never;
	    credentialIdB64u?: never;
	    providerSubjectId?: never;
	    emailHashHex?: never;
	    authSubjectId?: never;
	  };

export type EmailOtpEd25519SealedRecoveryRecord = Ed25519SealedRecoveryRecordBase &
  SealedRecoveryWalletSessionAuthCarrier & {
    authMethod: 'email_otp';
    authority: EmailOtpWalletAuthAuthority;
    rpId?: never;
    routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
    companionEcdsaRecovery?: EmailOtpEcdsaSealedRecoveryRecord;
    credentialIdB64u?: never;
    providerSubjectId?: never;
    emailHashHex?: never;
    authSubjectId?: never;
  };

export type SealedRecoveryRecord =
  | PasskeyEd25519SealedRecoveryRecord
  | PasskeyEcdsaSealedRecoveryRecord
  | EmailOtpEd25519SealedRecoveryRecord
  | EmailOtpEcdsaSealedRecoveryRecord;

export type Ed25519SealedRecoveryMaterialIdentity = {
  bindingDigest: string;
  materialKeyId: string;
};

type Ed25519SealedRecoveryMaterialIdentityRecord = Extract<
  SealedRecoveryRecord,
  { curve: 'ed25519' }
>;

export function ed25519SealedRecoveryMaterialIdentity(
  record: Ed25519SealedRecoveryMaterialIdentityRecord,
): Ed25519SealedRecoveryMaterialIdentity {
  return {
    bindingDigest: record.materialCache.ed25519WorkerMaterialBindingDigest,
    materialKeyId: record.materialCache.materialKeyId,
  };
}

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

function normalizeRouterAbEcdsaHssNormalSigningState(
  value: unknown,
): RouterAbEcdsaHssNormalSigningStateV1 | null {
  try {
    return parseRouterAbEcdsaHssNormalSigningStateV1(value);
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

function normalizedEd25519WorkerMaterialFields(
  restore: RawEd25519RestoreMetadata,
): Ed25519SealedMaterialCache | null {
  const clientVerifyingShareB64u = normalizeNonEmptyString(restore.clientVerifyingShareB64u);
  const ed25519WorkerMaterialBindingDigest = normalizeNonEmptyString(
    restore.ed25519WorkerMaterialBindingDigest,
  );
  const sealedWorkerMaterialRef = normalizeNonEmptyString(restore.sealedWorkerMaterialRef);
  const sealedWorkerMaterialB64u = normalizeNonEmptyString(restore.sealedWorkerMaterialB64u);
  const materialFormatVersion = normalizeNonEmptyString(restore.materialFormatVersion);
  const materialKeyId = normalizeNonEmptyString(restore.materialKeyId);
  const materialCreatedAtMs = Math.floor(Number(restore.materialCreatedAtMs) || 0);
  if (
    !clientVerifyingShareB64u ||
    !ed25519WorkerMaterialBindingDigest ||
    !sealedWorkerMaterialRef ||
    !materialFormatVersion ||
    !materialKeyId ||
    materialCreatedAtMs <= 0
  ) {
    return null;
  }
  return {
    clientVerifyingShareB64u,
    ed25519WorkerMaterialBindingDigest,
    sealedWorkerMaterialRef,
    ...(sealedWorkerMaterialB64u ? { sealedWorkerMaterialB64u } : {}),
    materialFormatVersion,
    materialKeyId,
    materialCreatedAtMs,
  };
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

function normalizeSigningGrantId(record: RawSigningSessionSealedStoreRecord): string | null {
  return normalizeNonEmptyString(record.signingGrantId);
}

function normalizeSessionKind(value: unknown): ThresholdSessionKind | null {
  return value === 'jwt' || value === 'cookie' ? value : null;
}

export function sealedRecoverySessionKind(
  _auth: SealedRecoveryWalletSessionAuth,
): 'jwt' {
  return 'jwt';
}

export function sealedRecoveryWalletSessionJwt(
  auth: SealedRecoveryWalletSessionAuth,
): string {
  return auth.walletSessionJwt;
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

function buildEmailOtpAuthorityForSealedRecord(args: {
  walletId: string;
  providerSubjectId: string;
  emailHashHex: string;
}): EmailOtpWalletAuthAuthority | null {
  try {
    return buildEmailOtpWalletAuthAuthority({
      walletId: args.walletId,
      provider: 'google',
      providerUserId: args.providerSubjectId,
      emailHashHex: args.emailHashHex,
    });
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
  if (hasRawLegacySealedRecoveryIdentity(raw)) {
    return reject(raw, 'invalid_identity');
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
      rawSigningRootId: restore?.signingRootId,
      rawSigningRootVersion: restore?.signingRootVersion,
    });
    const relayerUrl = normalizeNonEmptyString(raw.relayerUrl);
    const passkeyRpId =
      raw.authMethod === 'passkey'
        ? normalizeNonEmptyString(restore?.rpId) ||
          normalizeNonEmptyString(ed25519Restore?.rpId)
        : null;
    const passkeySource =
      raw.authMethod === 'passkey'
        ? normalizePasskeyEcdsaRestoreSource(restore?.source)
        : null;
    const emailOtpSource =
      raw.authMethod === 'email_otp' && normalizeEcdsaRestoreSource(restore?.source) === 'email_otp'
        ? 'email_otp'
        : null;
    const evmFamilySigningKeySlotId = normalizeNonEmptyString(restore?.evmFamilySigningKeySlotId);
    const credentialIdB64u = normalizeNonEmptyString(restore?.credentialIdB64u);
    const providerSubjectId = normalizeNonEmptyString(restore?.providerSubjectId);
    const emailHashHex = normalizeNonEmptyString(restore?.emailHashHex);
    const relayerKeyId = normalizeNonEmptyString(restore?.relayerKeyId);
    const keyHandle = normalizeNonEmptyString(restore?.keyHandle);
    const ecdsaThresholdKeyId = normalizeNonEmptyString(restore?.ecdsaThresholdKeyId);
    const ethereumAddress = normalizeEthereumAddress(restore?.ethereumAddress);
    const thresholdEcdsaPublicKeyB64u = normalizeNonEmptyString(
      restore?.thresholdEcdsaPublicKeyB64u,
    );
    const participantIds = normalizeParticipantIds(restore?.participantIds);
    const routerAbEcdsaHssNormalSigning = normalizeRouterAbEcdsaHssNormalSigningState(
      restore?.routerAbEcdsaHssNormalSigning,
    );
    const clientVerifyingShareB64u = normalizeNonEmptyString(restore?.clientVerifyingShareB64u);
    const passkeyClientVerifyingShareB64u =
      raw.authMethod === 'passkey' ? clientVerifyingShareB64u : null;
    const sessionKind = normalizeSessionKind(restore?.sessionKind);
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
      !evmFamilySigningKeySlotId ||
      (raw.authMethod === 'passkey' && !credentialIdB64u) ||
      (raw.authMethod === 'email_otp' && (!providerSubjectId || !emailHashHex)) ||
      !ecdsaThresholdKeyId ||
      !relayerKeyId ||
      !keyHandle ||
      !ethereumAddress ||
      !routerAbEcdsaHssNormalSigning ||
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
    const passkeyAuthority =
      raw.authMethod === 'passkey'
        ? buildPasskeyAuthorityForSealedRecord({
            walletId,
            rpId: passkeyRpId!,
            credentialIdB64u: credentialIdB64u!,
          })
        : null;
    const emailOtpAuthority =
      raw.authMethod === 'email_otp'
        ? buildEmailOtpAuthorityForSealedRecord({
            walletId,
            providerSubjectId: providerSubjectId!,
            emailHashHex: emailHashHex!,
          })
        : null;
    if (
      (raw.authMethod === 'passkey' && !passkeyAuthority) ||
      (raw.authMethod === 'email_otp' && !emailOtpAuthority)
    ) {
      return reject(raw, 'invalid_identity');
    }
    const companionEd25519ThresholdSessionId = normalizeNonEmptyString(thresholdSessionIds.ed25519);
    let companionEd25519Recovery: EmailOtpEcdsaCompanionEd25519Recovery | undefined;
    if (
      raw.authMethod === 'email_otp' &&
      companionEd25519ThresholdSessionId &&
      relayerUrl &&
      ed25519Restore
    ) {
      const companionProviderSubjectId = normalizeNonEmptyString(
        ed25519Restore.providerSubjectId,
      );
      const companionEmailHashHex = normalizeNonEmptyString(ed25519Restore.emailHashHex);
      const companionCredentialIdB64u = normalizeNonEmptyString(ed25519Restore.credentialIdB64u);
      const companionAuthSubjectId = normalizeNonEmptyString(ed25519Restore.authSubjectId);
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
      const companionEd25519WorkerMaterial =
        normalizedEd25519WorkerMaterialFields(ed25519Restore);
      const companionAuthority =
        companionProviderSubjectId && companionEmailHashHex
          ? buildEmailOtpAuthorityForSealedRecord({
              walletId,
              providerSubjectId: companionProviderSubjectId,
              emailHashHex: companionEmailHashHex,
            })
          : null;
      if (
        companionProviderSubjectId &&
        companionEmailHashHex &&
        companionNearAccountId &&
        companionNearEd25519SigningKeyId &&
        companionRelayerKeyId &&
        companionParticipantIds.length &&
        companionSignerSlot > 0 &&
	        !companionXClientBaseB64u &&
        !companionCredentialIdB64u &&
        !companionAuthSubjectId &&
	        companionWalletSessionAuth &&
        companionEd25519WorkerMaterial &&
        companionAuthority
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
          authority: companionAuthority,
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
	          materialCache: companionEd25519WorkerMaterial,
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
            source: passkeySource!,
            authority: passkeyAuthority!,
            evmFamilySigningKeySlotId: evmFamilySigningKeySlotId!,
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
            routerAbEcdsaHssNormalSigning,
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
            source: 'email_otp',
            authority: emailOtpAuthority!,
	            evmFamilySigningKeySlotId: evmFamilySigningKeySlotId!,
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
            routerAbEcdsaHssNormalSigning,
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
  const passkeyRpId =
    raw.authMethod === 'passkey' ? normalizeNonEmptyString(restore?.rpId) : null;
  const credentialIdB64u = normalizeNonEmptyString(restore?.credentialIdB64u);
  const providerSubjectId = normalizeNonEmptyString(restore?.providerSubjectId);
  const emailHashHex = normalizeNonEmptyString(restore?.emailHashHex);
  const staleAuthSubjectId = normalizeNonEmptyString(restore?.authSubjectId);
  const participantIds = normalizeParticipantIds(restore?.participantIds);
  const xClientBaseB64u = normalizeNonEmptyString(restore?.xClientBaseB64u);
	  const signerSlot = Math.floor(Number(restore?.signerSlot) || 0);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    restore?.routerAbNormalSigning,
  );
  const sessionKind = normalizeSessionKind(restore?.sessionKind);
  if (!thresholdSessionId) return reject(raw, 'missing_identity');
  if (
    staleAuthSubjectId ||
    (raw.authMethod === 'passkey' && providerSubjectId) ||
    (raw.authMethod === 'email_otp' && credentialIdB64u)
  ) {
    return reject(raw, 'invalid_identity');
  }
  if (
    !restore ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    (raw.authMethod === 'passkey' && !passkeyRpId) ||
    (raw.authMethod === 'passkey' && !credentialIdB64u) ||
    (raw.authMethod === 'email_otp' && (!providerSubjectId || !emailHashHex)) ||
    !relayerUrl ||
    !relayerKeyId ||
	    !participantIds.length ||
	    signerSlot <= 0 ||
	    xClientBaseB64u
	  ) {
    return reject(raw, 'missing_restore_metadata');
  }
  const ed25519WorkerMaterial = normalizedEd25519WorkerMaterialFields(restore);
  if (!ed25519WorkerMaterial) {
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
  const passkeyAuthority =
    raw.authMethod === 'passkey'
      ? buildPasskeyAuthorityForSealedRecord({
          walletId,
          rpId: passkeyRpId!,
          credentialIdB64u: credentialIdB64u!,
        })
      : null;
  const emailOtpAuthority =
    raw.authMethod === 'email_otp'
      ? buildEmailOtpAuthorityForSealedRecord({
          walletId,
          providerSubjectId: providerSubjectId!,
          emailHashHex: emailHashHex!,
        })
      : null;
  if (
    (raw.authMethod === 'passkey' && !passkeyAuthority) ||
    (raw.authMethod === 'email_otp' && !emailOtpAuthority)
  ) {
    return reject(raw, 'invalid_identity');
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
      rawSigningRootId: ecdsaRestore?.signingRootId,
      rawSigningRootVersion: ecdsaRestore?.signingRootVersion,
    });
    const companionEcdsaThresholdKeyId = normalizeNonEmptyString(ecdsaRestore?.ecdsaThresholdKeyId);
    const companionProviderSubjectId = normalizeNonEmptyString(
      ecdsaRestore?.providerSubjectId,
    );
    const companionEmailHashHex = normalizeNonEmptyString(ecdsaRestore?.emailHashHex);
    const companionEcdsaSource = normalizeEcdsaRestoreSource(ecdsaRestore?.source);
    const companionRouterAbEcdsaHssNormalSigning =
      normalizeRouterAbEcdsaHssNormalSigningState(ecdsaRestore?.routerAbEcdsaHssNormalSigning);
    if (
      !thresholdSessionIds.ecdsa ||
      !ecdsaRestore ||
      !ecdsaRestore.chainTarget ||
      !companionSigningRootBinding ||
      companionEcdsaSource !== 'email_otp' ||
      !companionEcdsaThresholdKeyId ||
      !companionRouterAbEcdsaHssNormalSigning ||
      !normalizeNonEmptyString(raw.relayerUrl) ||
      !normalizeNonEmptyString(ecdsaRestore.evmFamilySigningKeySlotId) ||
      !companionProviderSubjectId ||
      !companionEmailHashHex ||
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
    const companionAuthority = buildEmailOtpAuthorityForSealedRecord({
      walletId,
      providerSubjectId: companionProviderSubjectId,
      emailHashHex: companionEmailHashHex,
    });
    if (!companionAuthority) {
      return reject(raw, 'invalid_identity');
    }
    companionEcdsaRecovery = {
      storeKey,
      walletId,
      authMethod: 'email_otp',
      curve: 'ecdsa',
      authority: companionAuthority,
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
      source: 'email_otp',
      evmFamilySigningKeySlotId: normalizeNonEmptyString(ecdsaRestore.evmFamilySigningKeySlotId)!,
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
      routerAbEcdsaHssNormalSigning: companionRouterAbEcdsaHssNormalSigning,
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
          authority: passkeyAuthority!,
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
		          materialCache: ed25519WorkerMaterial,
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
          authority: emailOtpAuthority!,
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
		          materialCache: ed25519WorkerMaterial,
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
