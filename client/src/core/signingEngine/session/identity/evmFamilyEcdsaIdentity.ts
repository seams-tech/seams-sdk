import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { base64UrlDecode } from '@shared/utils/base64';
import { alphabetizeStringify } from '@shared/utils/digests';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  deriveThresholdEcdsaKeyHandle,
  type ThresholdEcdsaKeyHandleInput,
} from '@shared/utils/thresholdEcdsaKeyHandle';
import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaClientAdditiveShareHandle,
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../interfaces/signing';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from './laneIdentity';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  toWalletSubjectId,
  walletSubjectIdFromWalletProfile,
  type ThresholdEcdsaChainTarget,
  type WalletId,
  type WalletSubjectId,
} from '../../interfaces/ecdsaChainTarget';
import {
  SigningSessionIds,
  type ThresholdEcdsaSessionId,
  type WalletSigningSessionId,
} from '../operationState/types';
import type {
  ThresholdRuntimePolicyScope,
  ThresholdSessionKind,
} from '../../threshold/sessionPolicy';

export type { WalletId, WalletSubjectId, ThresholdEcdsaSessionId, WalletSigningSessionId };

export type RpId = string & { readonly __brand: 'RpId' };
export type EcdsaThresholdKeyId = string & { readonly __brand: 'EcdsaThresholdKeyId' };
export type SigningRootId = string & { readonly __brand: 'SigningRootId' };
export type SigningRootVersion = string & { readonly __brand: 'SigningRootVersion' };
export type ParticipantId = number & { readonly __brand: 'ParticipantId' };
export type ThresholdOwnerAddress = `0x${string}` & {
  readonly __brand: 'ThresholdOwnerAddress';
};
export type ThresholdEcdsaPublicKeyB64u = string & {
  readonly __brand: 'ThresholdEcdsaPublicKeyB64u';
};
export type EvmFamilyEcdsaKeyHandle = string & {
  readonly __brand: 'EvmFamilyEcdsaKeyHandle';
};
export type EmailOtpAuthSubjectId = string & {
  readonly __brand: 'EmailOtpAuthSubjectId';
};
export type EmailOtpProviderId = string & {
  readonly __brand: 'EmailOtpProviderId';
};
export type VerifiedThresholdSessionAuth = string & {
  readonly __brand: 'VerifiedThresholdSessionAuth';
};
export type EvmFamilyKeyScope = 'evm-family';
export type EvmFamilyKeyFingerprint = string & {
  readonly __brand: 'EvmFamilyKeyFingerprint';
};

export type EvmFamilyEcdsaAuthMethod = 'passkey' | 'email_otp';

export type VerifiedEcdsaPublicFacts = {
  kind: 'verified_ecdsa_public_facts';
  keyHandle: EvmFamilyEcdsaKeyHandle;
  publicKeyB64u: ThresholdEcdsaPublicKeyB64u;
  participantIds: readonly ParticipantId[];
  thresholdOwnerAddress: ThresholdOwnerAddress;
  ecdsaThresholdKeyId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  subjectId?: never;
  rpId?: never;
  thresholdSessionId?: never;
  walletSigningSessionId?: never;
  chainTarget?: never;
  authMethod?: never;
};

export type PasskeyEcdsaAuthBinding = {
  kind: 'passkey_ecdsa_auth_binding';
  authMethod: 'passkey';
  rpId: RpId;
  authSubjectId?: never;
  providerId?: never;
  keyHandle?: never;
  publicKeyB64u?: never;
  participantIds?: never;
  thresholdOwnerAddress?: never;
};

export type EmailOtpEcdsaAuthBinding = {
  kind: 'email_otp_ecdsa_auth_binding';
  authMethod: 'email_otp';
  authSubjectId: EmailOtpAuthSubjectId;
  providerId: EmailOtpProviderId;
  rpId?: never;
  keyHandle?: never;
  publicKeyB64u?: never;
  participantIds?: never;
  thresholdOwnerAddress?: never;
};

export type EvmFamilyEcdsaAuthBinding = PasskeyEcdsaAuthBinding | EmailOtpEcdsaAuthBinding;

export type ResolvedEvmFamilyEcdsaKey<
  TAuthBinding extends EvmFamilyEcdsaAuthBinding = EvmFamilyEcdsaAuthBinding,
> = {
  kind: 'resolved_evm_family_ecdsa_key';
  walletId: WalletId;
  publicFacts: VerifiedEcdsaPublicFacts;
  authBinding: TAuthBinding;
  key?: never;
  ecdsaThresholdKeyId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  subjectId?: never;
  rpId?: never;
};

export type JwtThresholdSessionTransportAuth = {
  kind: 'jwt_threshold_session_auth';
  thresholdSessionAuthToken: VerifiedThresholdSessionAuth;
};

export type CookieThresholdSessionTransportAuth = {
  kind: 'cookie_threshold_session_auth';
  thresholdSessionAuthToken?: never;
};

export type ThresholdEcdsaSessionTransportAuth =
  | JwtThresholdSessionTransportAuth
  | CookieThresholdSessionTransportAuth;

export type ThresholdEcdsaSignerTransport = {
  kind: 'threshold_ecdsa_signer_transport';
  relayerUrl: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  relayerVerifyingShareB64u?: string;
  auth: ThresholdEcdsaSessionTransportAuth;
};

export type ThresholdEcdsaSignerSessionIdentity = {
  kind: 'threshold_ecdsa_signer_session_identity';
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
};

export type KnownReadyThresholdEcdsaSessionPolicy = {
  kind: 'known_threshold_ecdsa_session_policy';
  remainingUses: number;
  expiresAtMs: number;
  source?: never;
};

export type UnavailableReadyThresholdEcdsaSessionPolicy = {
  kind: 'unavailable_threshold_ecdsa_session_policy';
  source: 'key_ref_fallback';
  remainingUses?: never;
  expiresAtMs?: never;
};

export type ReadyThresholdEcdsaSessionPolicy =
  | KnownReadyThresholdEcdsaSessionPolicy
  | UnavailableReadyThresholdEcdsaSessionPolicy;

export type ReadyThresholdEcdsaSession = {
  kind: 'ready_threshold_ecdsa_session';
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  policy: ReadyThresholdEcdsaSessionPolicy;
  thresholdSessionKind?: never;
  thresholdSessionAuthToken?: never;
};

export type EmailOtpWorkerShareHandle = {
  kind: 'email_otp_worker_session';
  sessionId: string;
  laneIdentity: {
    kind: 'email_otp_worker_share_lane_identity';
    keyHandle: EvmFamilyEcdsaKeyHandle;
    chainTarget: ThresholdEcdsaChainTarget;
    walletSigningSessionId: WalletSigningSessionId;
    thresholdSessionId: ThresholdEcdsaSessionId;
  };
};

export type ThresholdEcdsaInlineClientShare = {
  kind: 'inline_client_share';
  clientAdditiveShare32B64u: string;
  handle?: never;
};

export type ThresholdEcdsaEmailOtpWorkerShare = {
  kind: 'email_otp_worker_share';
  handle: EmailOtpWorkerShareHandle;
  clientAdditiveShare32B64u?: never;
};

export type ThresholdEcdsaSignerClientShare =
  | ThresholdEcdsaInlineClientShare
  | ThresholdEcdsaEmailOtpWorkerShare;

export type ReadyEcdsaSignerSession = {
  kind: 'ready_ecdsa_signer_session';
  publicFacts: VerifiedEcdsaPublicFacts;
  chainTarget: ThresholdEcdsaChainTarget;
  session: ReadyThresholdEcdsaSession;
  transport: ThresholdEcdsaSignerTransport;
  clientShare: ThresholdEcdsaSignerClientShare;
  keyRef?: never;
  participantIds?: never;
  thresholdEcdsaPublicKeyB64u?: never;
  thresholdSessionAuthToken?: never;
  clientAdditiveShare32B64u?: never;
  clientAdditiveShareHandle?: never;
};

export type EvmFamilyEcdsaKeyIdentity = {
  walletId: WalletId;
  rpId: RpId;
  keyScope: EvmFamilyKeyScope;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  participantIds: readonly ParticipantId[];
  thresholdOwnerAddress: ThresholdOwnerAddress;
  walletSigningSessionId?: never;
  thresholdSessionId?: never;
  chainTarget?: never;
  authMethod?: never;
};

export type SessionBootstrapKeyContext = {
  walletId: WalletId;
  rpId: RpId;
  participantIds: readonly ParticipantId[];
  keyScope?: never;
  ecdsaThresholdKeyId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  thresholdOwnerAddress?: never;
  walletSigningSessionId?: never;
  thresholdSessionId?: never;
  chainTarget?: never;
  authMethod?: never;
};

export type EvmFamilyEcdsaSessionLane = {
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  thresholdSessionId: ThresholdEcdsaSessionId;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionKind: ThresholdSessionKind;
  thresholdSessionAuthToken: VerifiedThresholdSessionAuth | null;
  remainingUses: number;
  expiresAtMs: number;
  ecdsaThresholdKeyId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  participantIds?: never;
  thresholdOwnerAddress?: never;
};

export type EvmFamilyEcdsaSessionLanePolicy = {
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: ThresholdEcdsaSessionId;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionKind: ThresholdSessionKind;
  ttlMs: number;
  remainingUses: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ecdsaThresholdKeyId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  participantIds?: never;
  thresholdOwnerAddress?: never;
};

export type ReadyEvmFamilyEcdsaSigningKeyContext = {
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  participantIds: readonly ParticipantId[];
};

export type ReadyEvmFamilyEcdsaMaterial = {
  kind: 'ready_evm_family_ecdsa_material';
  key: EvmFamilyEcdsaKeyIdentity;
  lane: EvmFamilyEcdsaSessionLane;
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  signingKeyContext: ReadyEvmFamilyEcdsaSigningKeyContext;
  cachedExportArtifact: ThresholdEcdsaCanonicalExportArtifact | null;
};

type IdentityMismatchDetails = {
  expected: string;
  actual: string;
};

export type EvmFamilyEcdsaIdentityMismatch =
  | ({ kind: 'wallet_mismatch'; field: 'walletId' } & IdentityMismatchDetails)
  | ({ kind: 'chain_family_mismatch'; field: 'chainTarget' } & IdentityMismatchDetails)
  | ({ kind: 'key_id_mismatch'; field: 'ecdsaThresholdKeyId' } & IdentityMismatchDetails)
  | ({ kind: 'signing_root_mismatch'; field: 'signingRoot' } & IdentityMismatchDetails)
  | ({
      kind: 'public_key_mismatch';
      field: 'thresholdEcdsaPublicKeyB64u';
    } & IdentityMismatchDetails)
  | ({ kind: 'participant_ids_mismatch'; field: 'participantIds' } & IdentityMismatchDetails)
  | ({ kind: 'owner_address_mismatch'; field: 'thresholdOwnerAddress' } & IdentityMismatchDetails)
  | ({ kind: 'rp_id_mismatch'; field: 'rpId' } & IdentityMismatchDetails)
  | ({ kind: 'key_scope_mismatch'; field: 'keyScope' } & IdentityMismatchDetails)
  | ({ kind: 'session_identity_mismatch'; field: 'sessionIdentity' } & IdentityMismatchDetails)
  | ({ kind: 'auth_method_mismatch'; field: 'authMethod' } & IdentityMismatchDetails)
  | {
      kind: 'stale_or_unrestorable_material';
      field: 'sessionState';
      reason: 'expired' | 'exhausted' | 'auth_missing' | 'invalid_identity';
      expected?: never;
      actual?: never;
    };

export type EvmFamilyEcdsaMaterialResolution =
  | {
      kind: 'ready';
      material: ReadyEvmFamilyEcdsaMaterial;
      reason?: never;
    }
  | {
      kind: 'record_only';
      reason: EvmFamilyEcdsaIdentityMismatch;
      material?: never;
    }
  | {
      kind: 'key_ref_only';
      reason: EvmFamilyEcdsaIdentityMismatch;
      material?: never;
    }
  | {
      kind: 'missing';
      reason: EvmFamilyEcdsaIdentityMismatch;
      material?: never;
    }
  | {
      kind: 'identity_mismatch';
      reason: EvmFamilyEcdsaIdentityMismatch;
      material?: never;
    }
  | {
      kind: 'stale';
      reason: Extract<EvmFamilyEcdsaIdentityMismatch, { kind: 'stale_or_unrestorable_material' }>;
      material?: never;
    };

export type BuildEvmFamilyEcdsaKeyIdentityInput = {
  walletId: unknown;
  subjectId: unknown;
  rpId: unknown;
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
  participantIds: unknown;
  thresholdOwnerAddress: unknown;
};

export type BuildBaseEvmFamilyEcdsaKeyIdentityInput = Omit<
  BuildEvmFamilyEcdsaKeyIdentityInput,
  'subjectId'
>;

export type BuildEvmFamilyEcdsaKeyHandleInput = ThresholdEcdsaKeyHandleInput;

export type BuildVerifiedEcdsaPublicFactsInput = {
  keyHandle: EvmFamilyEcdsaKeyHandle;
  publicKeyB64u: unknown;
  participantIds: unknown;
  thresholdOwnerAddress: unknown;
};

export type BuildEvmFamilyKeyFingerprintFromPublicFactsInput = {
  walletId: unknown;
  publicFacts: VerifiedEcdsaPublicFacts;
};

export type EvmFamilyEcdsaPublicFactsRecord = BuildEvmFamilyEcdsaKeyHandleInput & {
  thresholdEcdsaPublicKeyB64u: unknown;
  participantIds: unknown;
  ethereumAddress: unknown;
};

export type BuildEmailOtpEcdsaAuthBindingInput = {
  authSubjectId: unknown;
  providerId: unknown;
};

export type BuildResolvedEvmFamilyEcdsaKeyInput<
  TAuthBinding extends EvmFamilyEcdsaAuthBinding = EvmFamilyEcdsaAuthBinding,
> = {
  walletId: unknown;
  publicFacts: VerifiedEcdsaPublicFacts;
  authBinding: TAuthBinding;
};

export type BuildThresholdEcdsaSessionTransportAuthInput = {
  thresholdSessionKind: 'jwt';
  thresholdSessionAuthToken: unknown;
} | {
  thresholdSessionKind: 'cookie';
  thresholdSessionAuthToken?: never;
};

export type BuildReadyEcdsaSignerSessionInput = {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  publicFacts: VerifiedEcdsaPublicFacts;
  sessionPolicy: ReadyThresholdEcdsaSessionPolicy;
} & BuildThresholdEcdsaSessionTransportAuthInput;

export type DurableEvmFamilyEcdsaPublicFactsRecord = {
  ecdsaRestore: {
    keyHandle: unknown;
    thresholdEcdsaPublicKeyB64u: unknown;
    participantIds: unknown;
    ethereumAddress: unknown;
  };
};

export type BuildEvmFamilyEcdsaSessionLaneInput = {
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  thresholdSessionId: unknown;
  walletSigningSessionId: unknown;
  thresholdSessionKind: ThresholdSessionKind;
  thresholdSessionAuthToken?: unknown;
  remainingUses: unknown;
  expiresAtMs: unknown;
};

export type BuildEvmFamilyEcdsaSessionLanePolicyInput = {
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: unknown;
  walletSigningSessionId: unknown;
  thresholdSessionKind: ThresholdSessionKind;
  ttlMs: unknown;
  remainingUses: unknown;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

export type ResolveReadyEvmFamilyEcdsaMaterialInput = {
  record: ThresholdEcdsaSessionRecord | null;
  keyRef: ThresholdEcdsaSecp256k1KeyRef | null;
  rpId: unknown;
  expected: {
    walletId: AccountId | WalletId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
    thresholdSessionId: ThresholdEcdsaSessionId | string;
    walletSigningSessionId: WalletSigningSessionId | string;
  };
  nowMs?: number;
};

function requiredString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`[evm-family-ecdsa] ${field} is required`);
  return normalized;
}

function normalizeRpId(value: unknown): RpId {
  return requiredString(value, 'rpId') as RpId;
}

function normalizeEmailOtpAuthSubjectId(value: unknown): EmailOtpAuthSubjectId {
  return requiredString(value, 'authSubjectId') as EmailOtpAuthSubjectId;
}

function normalizeEmailOtpProviderId(value: unknown): EmailOtpProviderId {
  return requiredString(value, 'providerId') as EmailOtpProviderId;
}

function normalizeEcdsaThresholdKeyId(value: unknown): EcdsaThresholdKeyId {
  return requiredString(value, 'ecdsaThresholdKeyId') as EcdsaThresholdKeyId;
}

function normalizeSigningRootId(value: unknown): SigningRootId {
  return requiredString(value, 'signingRootId') as SigningRootId;
}

function normalizeSigningRootVersion(value: unknown): SigningRootVersion {
  return (String(value ?? '').trim() || 'default') as SigningRootVersion;
}

function normalizeThresholdOwnerAddress(value: unknown): ThresholdOwnerAddress {
  const normalized = String(value ?? '')
    .trim()
    .toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) {
    throw new Error('[evm-family-ecdsa] thresholdOwnerAddress must be an EVM address');
  }
  return normalized as ThresholdOwnerAddress;
}

export function toThresholdOwnerAddress(value: unknown): ThresholdOwnerAddress {
  return normalizeThresholdOwnerAddress(value);
}

export function toRpId(value: unknown): RpId {
  return normalizeRpId(value);
}

export function toEmailOtpAuthSubjectId(value: unknown): EmailOtpAuthSubjectId {
  return normalizeEmailOtpAuthSubjectId(value);
}

export function toEmailOtpProviderId(value: unknown): EmailOtpProviderId {
  return normalizeEmailOtpProviderId(value);
}

export function toEvmFamilyEcdsaKeyHandle(value: unknown): EvmFamilyEcdsaKeyHandle {
  return requiredString(value, 'keyHandle') as EvmFamilyEcdsaKeyHandle;
}

const LEGACY_KEY_HANDLE_THRESHOLD_KEY_ID_PREFIX = 'legacy-key-handle:';

// Compatibility boundary: some persisted records and sealed recovery payloads
// still carry only keyHandle. Adapter paths synthesize a stable key id from it.
function toLegacyThresholdEcdsaKeyIdFromKeyHandle(args: {
  keyHandle: unknown;
}): EcdsaThresholdKeyId {
  const keyHandle = toEvmFamilyEcdsaKeyHandle(args.keyHandle);
  return `${LEGACY_KEY_HANDLE_THRESHOLD_KEY_ID_PREFIX}${String(keyHandle)}` as EcdsaThresholdKeyId;
}

export function resolveThresholdEcdsaKeyIdFromRecord(args: {
  record: Pick<ThresholdEcdsaSessionRecord, 'keyHandle'> & {
    ecdsaThresholdKeyId?: unknown;
  };
}): EcdsaThresholdKeyId {
  const persisted = String(args.record.ecdsaThresholdKeyId ?? '').trim();
  if (persisted) return normalizeEcdsaThresholdKeyId(persisted);
  return toLegacyThresholdEcdsaKeyIdFromKeyHandle({
    keyHandle: args.record.keyHandle,
  });
}

export function resolveThresholdEcdsaKeyIdFromKeyRef(args: {
  keyRef: Pick<ThresholdEcdsaSecp256k1KeyRef, 'keyHandle' | 'ecdsaThresholdKeyId'>;
}): EcdsaThresholdKeyId {
  const explicitKeyId = String(args.keyRef.ecdsaThresholdKeyId || '').trim();
  if (explicitKeyId) {
    return normalizeEcdsaThresholdKeyId(explicitKeyId);
  }
  const keyHandle = String(args.keyRef.keyHandle || '').trim();
  if (keyHandle) {
    return toLegacyThresholdEcdsaKeyIdFromKeyHandle({
      keyHandle,
    });
  }
  return normalizeEcdsaThresholdKeyId(args.keyRef.ecdsaThresholdKeyId);
}

export function resolveThresholdSigningRootBindingFromRecord(args: {
  record: Pick<ThresholdEcdsaSessionRecord, 'runtimePolicyScope' | 'keyHandle'> & {
    signingRootId?: unknown;
    signingRootVersion?: unknown;
  };
}): {
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
} {
  const runtimePolicyScope = args.record.runtimePolicyScope;
  if (runtimePolicyScope) {
    try {
      const scopeBinding = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
      return {
        signingRootId: normalizeSigningRootId(scopeBinding.signingRootId),
        signingRootVersion: normalizeSigningRootVersion(scopeBinding.signingRootVersion),
      };
    } catch {}
  }

  const explicitSigningRootId = String(args.record.signingRootId ?? '').trim();
  const fallbackSigningRootId = explicitSigningRootId
    ? explicitSigningRootId
    : `${LEGACY_KEY_HANDLE_THRESHOLD_KEY_ID_PREFIX}${String(toEvmFamilyEcdsaKeyHandle(args.record.keyHandle))}`;
  const signingRootId = normalizeSigningRootId(fallbackSigningRootId);
  return {
    signingRootId,
    signingRootVersion: normalizeSigningRootVersion(args.record.signingRootVersion),
  };
}

export function toThresholdEcdsaPublicKeyB64u(value: unknown): ThresholdEcdsaPublicKeyB64u {
  const normalized = requiredString(value, 'thresholdEcdsaPublicKeyB64u');
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(normalized);
  } catch {
    throw new Error('[evm-family-ecdsa] thresholdEcdsaPublicKeyB64u must be base64url');
  }
  if (bytes.length !== 33) {
    throw new Error('[evm-family-ecdsa] thresholdEcdsaPublicKeyB64u must decode to 33 bytes');
  }
  return normalized as ThresholdEcdsaPublicKeyB64u;
}

export function toParticipantId(value: unknown): ParticipantId {
  const normalized = Math.floor(Number(value));
  if (!Number.isSafeInteger(normalized) || normalized < 1 || normalized > 65_535) {
    throw new Error('[evm-family-ecdsa] participantId must be a positive safe integer');
  }
  return normalized as ParticipantId;
}

function normalizeParticipantIds(value: unknown): readonly ParticipantId[] {
  const participantIds = normalizeThresholdEd25519ParticipantIds(value);
  if (!participantIds?.length) {
    throw new Error('[evm-family-ecdsa] participantIds are required');
  }
  return participantIds.map(toParticipantId);
}

function participantIdKey(participantIds: readonly ParticipantId[]): string {
  return participantIds.map((id) => String(Number(id))).join(',');
}

function authMethodForRecord(record: ThresholdEcdsaSessionRecord): EvmFamilyEcdsaAuthMethod {
  return record.source === 'email_otp' ? 'email_otp' : 'passkey';
}

function normalizeThresholdSessionAuthToken(args: {
  thresholdSessionKind: ThresholdSessionKind;
  thresholdSessionAuthToken?: unknown;
}): VerifiedThresholdSessionAuth | null {
  if (args.thresholdSessionKind === 'cookie') return null;
  const token = String(args.thresholdSessionAuthToken ?? '').trim();
  if (!token)
    throw new Error('[evm-family-ecdsa] thresholdSessionAuthToken is required for jwt sessions');
  return token as VerifiedThresholdSessionAuth;
}

function mismatch<TKind extends EvmFamilyEcdsaIdentityMismatch['kind']>(
  kind: TKind,
  field: Extract<EvmFamilyEcdsaIdentityMismatch, { kind: TKind }>['field'],
  expected: unknown,
  actual: unknown,
): Extract<EvmFamilyEcdsaIdentityMismatch, { kind: TKind }> {
  return {
    kind,
    field,
    expected: String(expected),
    actual: String(actual),
  } as Extract<EvmFamilyEcdsaIdentityMismatch, { kind: TKind }>;
}

function staleReason(
  reason: Extract<
    EvmFamilyEcdsaIdentityMismatch,
    { kind: 'stale_or_unrestorable_material' }
  >['reason'],
): Extract<EvmFamilyEcdsaIdentityMismatch, { kind: 'stale_or_unrestorable_material' }> {
  return {
    kind: 'stale_or_unrestorable_material',
    field: 'sessionState',
    reason,
  };
}

function firstKeyMismatch(
  left: EvmFamilyEcdsaKeyIdentity,
  right: EvmFamilyEcdsaKeyIdentity,
): EvmFamilyEcdsaIdentityMismatch | null {
  if (String(left.walletId) !== String(right.walletId)) {
    return mismatch('wallet_mismatch', 'walletId', left.walletId, right.walletId);
  }
  if (String(left.rpId) !== String(right.rpId)) {
    return mismatch('rp_id_mismatch', 'rpId', left.rpId, right.rpId);
  }
  if (left.keyScope !== right.keyScope) {
    return mismatch('key_scope_mismatch', 'keyScope', left.keyScope, right.keyScope);
  }
  if (String(left.ecdsaThresholdKeyId) !== String(right.ecdsaThresholdKeyId)) {
    return mismatch(
      'key_id_mismatch',
      'ecdsaThresholdKeyId',
      left.ecdsaThresholdKeyId,
      right.ecdsaThresholdKeyId,
    );
  }
  if (
    String(left.signingRootId) !== String(right.signingRootId) ||
    String(left.signingRootVersion) !== String(right.signingRootVersion)
  ) {
    return mismatch(
      'signing_root_mismatch',
      'signingRoot',
      `${String(left.signingRootId)}:${String(left.signingRootVersion)}`,
      `${String(right.signingRootId)}:${String(right.signingRootVersion)}`,
    );
  }
  if (participantIdKey(left.participantIds) !== participantIdKey(right.participantIds)) {
    return mismatch(
      'participant_ids_mismatch',
      'participantIds',
      participantIdKey(left.participantIds),
      participantIdKey(right.participantIds),
    );
  }
  if (String(left.thresholdOwnerAddress) !== String(right.thresholdOwnerAddress)) {
    return mismatch(
      'owner_address_mismatch',
      'thresholdOwnerAddress',
      left.thresholdOwnerAddress,
      right.thresholdOwnerAddress,
    );
  }
  return null;
}

function fnv1a32Hex(input: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

export function buildEvmFamilyEcdsaKeyIdentity(
  input: BuildEvmFamilyEcdsaKeyIdentityInput,
): EvmFamilyEcdsaKeyIdentity {
  const walletId = toWalletId(input.walletId);
  const subjectId = toWalletSubjectId(input.subjectId);
  const expectedSubjectId = walletSubjectIdFromWalletProfile({ walletId });
  if (subjectId !== expectedSubjectId) {
    throw new Error(
      '[evm-family-ecdsa] subjectId must match the wallet-derived base ECDSA subject',
    );
  }
  return buildNormalizedEvmFamilyEcdsaKeyIdentity({
    walletId,
    rpId: input.rpId,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    participantIds: input.participantIds,
    thresholdOwnerAddress: input.thresholdOwnerAddress,
  });
}

function buildNormalizedEvmFamilyEcdsaKeyIdentity(input: {
  walletId: WalletId;
  rpId: unknown;
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
  participantIds: unknown;
  thresholdOwnerAddress: unknown;
}): EvmFamilyEcdsaKeyIdentity {
  return {
    walletId: input.walletId,
    rpId: normalizeRpId(input.rpId),
    keyScope: 'evm-family',
    ecdsaThresholdKeyId: normalizeEcdsaThresholdKeyId(input.ecdsaThresholdKeyId),
    signingRootId: normalizeSigningRootId(input.signingRootId),
    signingRootVersion: normalizeSigningRootVersion(input.signingRootVersion),
    participantIds: normalizeParticipantIds(input.participantIds),
    thresholdOwnerAddress: normalizeThresholdOwnerAddress(input.thresholdOwnerAddress),
  };
}

export function buildBaseEvmFamilyEcdsaKeyIdentity(
  input: BuildBaseEvmFamilyEcdsaKeyIdentityInput,
): EvmFamilyEcdsaKeyIdentity {
  return buildNormalizedEvmFamilyEcdsaKeyIdentity({
    walletId: toWalletId(input.walletId),
    rpId: input.rpId,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    participantIds: input.participantIds,
    thresholdOwnerAddress: input.thresholdOwnerAddress,
  });
}

export function buildSessionBootstrapKeyContext(input: {
  walletId: unknown;
  rpId: unknown;
  participantIds: unknown;
}): SessionBootstrapKeyContext {
  return {
    walletId: toWalletId(input.walletId),
    rpId: normalizeRpId(input.rpId),
    participantIds: normalizeParticipantIds(input.participantIds),
  };
}

export function deriveBaseEcdsaSubjectIdFromWalletId(walletId: WalletId | string): WalletSubjectId {
  return walletSubjectIdFromWalletProfile({ walletId: toWalletId(walletId) });
}

export function deriveBaseEcdsaSubjectIdFromKey(
  key: Pick<EvmFamilyEcdsaKeyIdentity, 'walletId'>,
): WalletSubjectId {
  return deriveBaseEcdsaSubjectIdFromWalletId(key.walletId);
}

export async function deriveEvmFamilyEcdsaKeyHandle(
  input: BuildEvmFamilyEcdsaKeyHandleInput,
): Promise<EvmFamilyEcdsaKeyHandle> {
  return (await deriveThresholdEcdsaKeyHandle(input)) as string as EvmFamilyEcdsaKeyHandle;
}

export function buildVerifiedEcdsaPublicFacts(
  input: BuildVerifiedEcdsaPublicFactsInput,
): VerifiedEcdsaPublicFacts {
  return {
    kind: 'verified_ecdsa_public_facts',
    keyHandle: input.keyHandle,
    publicKeyB64u: toThresholdEcdsaPublicKeyB64u(input.publicKeyB64u),
    participantIds: normalizeParticipantIds(input.participantIds),
    thresholdOwnerAddress: normalizeThresholdOwnerAddress(input.thresholdOwnerAddress),
  };
}

export function assertMatchingVerifiedEcdsaPublicFacts(args: {
  expected: VerifiedEcdsaPublicFacts;
  actual: VerifiedEcdsaPublicFacts;
  context: string;
}): void {
  const mismatches: string[] = [];
  if (String(args.expected.keyHandle) !== String(args.actual.keyHandle)) {
    mismatches.push('keyHandle');
  }
  if (String(args.expected.publicKeyB64u) !== String(args.actual.publicKeyB64u)) {
    mismatches.push('publicKeyB64u');
  }
  if (
    participantIdKey(args.expected.participantIds) !== participantIdKey(args.actual.participantIds)
  ) {
    mismatches.push('participantIds');
  }
  if (String(args.expected.thresholdOwnerAddress) !== String(args.actual.thresholdOwnerAddress)) {
    mismatches.push('thresholdOwnerAddress');
  }
  if (mismatches.length) {
    throw new Error(
      `[evm-family-ecdsa] ${args.context} public facts mismatch: ${mismatches.join(', ')}`,
    );
  }
}

export function buildPasskeyEcdsaAuthBinding(args: { rpId: unknown }): PasskeyEcdsaAuthBinding {
  return {
    kind: 'passkey_ecdsa_auth_binding',
    authMethod: 'passkey',
    rpId: normalizeRpId(args.rpId),
  };
}

export function buildEmailOtpEcdsaAuthBinding(
  args: BuildEmailOtpEcdsaAuthBindingInput,
): EmailOtpEcdsaAuthBinding {
  return {
    kind: 'email_otp_ecdsa_auth_binding',
    authMethod: 'email_otp',
    authSubjectId: normalizeEmailOtpAuthSubjectId(args.authSubjectId),
    providerId: normalizeEmailOtpProviderId(args.providerId),
  };
}

export function buildResolvedEvmFamilyEcdsaKey<TAuthBinding extends EvmFamilyEcdsaAuthBinding>(
  input: BuildResolvedEvmFamilyEcdsaKeyInput<TAuthBinding>,
): ResolvedEvmFamilyEcdsaKey<TAuthBinding> {
  return {
    kind: 'resolved_evm_family_ecdsa_key',
    walletId: toWalletId(input.walletId),
    publicFacts: input.publicFacts,
    authBinding: input.authBinding,
  };
}

export function buildThresholdEcdsaSessionTransportAuth(
  input: BuildThresholdEcdsaSessionTransportAuthInput,
): ThresholdEcdsaSessionTransportAuth {
  if (input.thresholdSessionKind === 'cookie') {
    return { kind: 'cookie_threshold_session_auth' };
  }
  return {
    kind: 'jwt_threshold_session_auth',
    thresholdSessionAuthToken: requiredString(
      input.thresholdSessionAuthToken,
      'thresholdSessionAuthToken',
    ) as VerifiedThresholdSessionAuth,
  };
}

function buildEmailOtpWorkerShareHandle(args: {
  handle: ThresholdEcdsaClientAdditiveShareHandle;
  publicFacts: VerifiedEcdsaPublicFacts;
  chainTarget: ThresholdEcdsaChainTarget;
  session: ThresholdEcdsaSignerSessionIdentity;
}): EmailOtpWorkerShareHandle {
  const sessionId = requiredString(args.handle.sessionId, 'clientAdditiveShareHandle.sessionId');
  return {
    kind: 'email_otp_worker_session',
    sessionId,
    laneIdentity: {
      kind: 'email_otp_worker_share_lane_identity',
      keyHandle: args.publicFacts.keyHandle,
      chainTarget: args.chainTarget,
      walletSigningSessionId: args.session.walletSigningSessionId,
      thresholdSessionId: args.session.thresholdSessionId,
    },
  };
}

function buildThresholdEcdsaSignerClientShare(args: {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  publicFacts: VerifiedEcdsaPublicFacts;
  chainTarget: ThresholdEcdsaChainTarget;
  session: ThresholdEcdsaSignerSessionIdentity;
}): ThresholdEcdsaSignerClientShare {
  const handle = args.keyRef.backendBinding?.clientAdditiveShareHandle;
  if (handle?.kind === 'email_otp_worker_session') {
    return {
      kind: 'email_otp_worker_share',
      handle: buildEmailOtpWorkerShareHandle({
        handle,
        publicFacts: args.publicFacts,
        chainTarget: args.chainTarget,
        session: args.session,
      }),
    };
  }
  return {
    kind: 'inline_client_share',
    clientAdditiveShare32B64u: requiredString(
      args.keyRef.backendBinding?.clientAdditiveShare32B64u,
      'clientAdditiveShare32B64u',
    ),
  };
}

export function buildKnownReadyThresholdEcdsaSessionPolicy(args: {
  remainingUses: unknown;
  expiresAtMs: unknown;
}): KnownReadyThresholdEcdsaSessionPolicy {
  const remainingUses = Math.floor(Number(args.remainingUses));
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  if (!Number.isFinite(remainingUses)) {
    throw new Error('[evm-family-ecdsa] remainingUses must be finite');
  }
  if (!Number.isFinite(expiresAtMs)) {
    throw new Error('[evm-family-ecdsa] expiresAtMs must be finite');
  }
  return {
    kind: 'known_threshold_ecdsa_session_policy',
    remainingUses,
    expiresAtMs,
  };
}

export function buildUnavailableReadyThresholdEcdsaSessionPolicy(args: {
  source: UnavailableReadyThresholdEcdsaSessionPolicy['source'];
}): UnavailableReadyThresholdEcdsaSessionPolicy {
  return {
    kind: 'unavailable_threshold_ecdsa_session_policy',
    source: args.source,
  };
}

export function buildReadyThresholdEcdsaSession(args: {
  walletSigningSessionId: unknown;
  thresholdSessionId: unknown;
  policy: ReadyThresholdEcdsaSessionPolicy;
}): ReadyThresholdEcdsaSession {
  return {
    kind: 'ready_threshold_ecdsa_session',
    walletSigningSessionId: SigningSessionIds.walletSigningSession(args.walletSigningSessionId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(args.thresholdSessionId),
    policy: args.policy,
  };
}

export function buildReadyEcdsaSignerSession(
  input: BuildReadyEcdsaSignerSessionInput,
): ReadyEcdsaSignerSession {
  const session = buildReadyThresholdEcdsaSession({
    walletSigningSessionId: input.keyRef.walletSigningSessionId,
    thresholdSessionId: input.keyRef.thresholdSessionId,
    policy: input.sessionPolicy,
  });
  const signerIdentity: ThresholdEcdsaSignerSessionIdentity = {
    kind: 'threshold_ecdsa_signer_session_identity',
    walletSigningSessionId: session.walletSigningSessionId,
    thresholdSessionId: session.thresholdSessionId,
  };
  const chainTarget = input.keyRef.chainTarget;
  const transportAuth =
    input.thresholdSessionKind === 'jwt'
      ? buildThresholdEcdsaSessionTransportAuth({
          thresholdSessionKind: 'jwt',
          thresholdSessionAuthToken: input.thresholdSessionAuthToken,
        })
      : buildThresholdEcdsaSessionTransportAuth({
          thresholdSessionKind: 'cookie',
        });
  return {
    kind: 'ready_ecdsa_signer_session',
    publicFacts: input.publicFacts,
    chainTarget,
    session,
    transport: {
      kind: 'threshold_ecdsa_signer_transport',
      relayerUrl: requiredString(input.keyRef.relayerUrl, 'relayerUrl'),
      ecdsaThresholdKeyId: normalizeEcdsaThresholdKeyId(input.keyRef.ecdsaThresholdKeyId),
      relayerKeyId: requiredString(input.keyRef.backendBinding?.relayerKeyId, 'relayerKeyId'),
      clientVerifyingShareB64u: requiredString(
        input.keyRef.backendBinding?.clientVerifyingShareB64u,
        'clientVerifyingShareB64u',
      ),
      ...(String(input.keyRef.relayerVerifyingShareB64u || '').trim()
        ? { relayerVerifyingShareB64u: String(input.keyRef.relayerVerifyingShareB64u).trim() }
        : {}),
      auth: transportAuth,
    },
    clientShare: buildThresholdEcdsaSignerClientShare({
      keyRef: input.keyRef,
      publicFacts: input.publicFacts,
      chainTarget,
      session: signerIdentity,
    }),
  };
}

export function buildReadyEcdsaSignerSessionFromReadyMaterial(args: {
  material: ReadyEvmFamilyEcdsaMaterial;
  publicFacts: VerifiedEcdsaPublicFacts;
}): ReadyEcdsaSignerSession {
  const thresholdSessionTransportAuthInput: BuildThresholdEcdsaSessionTransportAuthInput =
    args.material.lane.thresholdSessionKind === 'jwt'
      ? {
          thresholdSessionKind: 'jwt',
          thresholdSessionAuthToken: args.material.lane.thresholdSessionAuthToken,
        }
      : {
          thresholdSessionKind: 'cookie',
        };
  return buildReadyEcdsaSignerSession({
    keyRef: args.material.keyRef,
    publicFacts: args.publicFacts,
    sessionPolicy: buildKnownReadyThresholdEcdsaSessionPolicy({
      remainingUses: args.material.lane.remainingUses,
      expiresAtMs: args.material.lane.expiresAtMs,
    }),
    ...thresholdSessionTransportAuthInput,
  });
}

export async function toReadyEcdsaSignerSessionFromReadyMaterial(args: {
  material: ReadyEvmFamilyEcdsaMaterial;
}): Promise<ReadyEcdsaSignerSession> {
  return buildReadyEcdsaSignerSessionFromReadyMaterial({
    material: args.material,
    publicFacts: await toVerifiedEcdsaPublicFactsFromReadyMaterial({ material: args.material }),
  });
}

export async function toVerifiedEcdsaPublicFactsFromServerRecord(
  record: EvmFamilyEcdsaPublicFactsRecord,
): Promise<VerifiedEcdsaPublicFacts> {
  return buildVerifiedEcdsaPublicFacts({
    keyHandle: await deriveEvmFamilyEcdsaKeyHandle(record),
    publicKeyB64u: record.thresholdEcdsaPublicKeyB64u,
    participantIds: record.participantIds,
    thresholdOwnerAddress: record.ethereumAddress,
  });
}

export async function toVerifiedEcdsaPublicFactsFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
}): Promise<VerifiedEcdsaPublicFacts> {
  return buildVerifiedEcdsaPublicFacts({
    keyHandle: args.record.keyHandle,
    publicKeyB64u: args.record.thresholdEcdsaPublicKeyB64u,
    participantIds: args.record.participantIds,
    thresholdOwnerAddress: args.record.ethereumAddress,
  });
}

export async function toVerifiedEcdsaPublicFactsFromKeyRef(args: {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
}): Promise<VerifiedEcdsaPublicFacts> {
  const keyHandle = String(args.keyRef.keyHandle || '').trim();
  if (keyHandle) {
    return buildVerifiedEcdsaPublicFacts({
      keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
      publicKeyB64u: args.keyRef.thresholdEcdsaPublicKeyB64u,
      participantIds: args.keyRef.participantIds,
      thresholdOwnerAddress: args.keyRef.ethereumAddress,
    });
  }
  return toVerifiedEcdsaPublicFactsFromServerRecord({
    ecdsaThresholdKeyId: args.keyRef.ecdsaThresholdKeyId,
    signingRootId: args.keyRef.signingRootId,
    signingRootVersion: args.keyRef.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: args.keyRef.thresholdEcdsaPublicKeyB64u,
    participantIds: args.keyRef.participantIds,
    ethereumAddress: args.keyRef.ethereumAddress,
  });
}

export async function toVerifiedEcdsaPublicFactsFromPairedRecordAndKeyRef(args: {
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  context: string;
}): Promise<VerifiedEcdsaPublicFacts> {
  const recordFacts = await toVerifiedEcdsaPublicFactsFromRecord({
    record: args.record,
  });
  const keyRefFacts = await toVerifiedEcdsaPublicFactsFromKeyRef({
    keyRef: args.keyRef,
  });
  assertMatchingVerifiedEcdsaPublicFacts({
    expected: recordFacts,
    actual: keyRefFacts,
    context: args.context,
  });
  return recordFacts;
}

export async function toVerifiedEcdsaPublicFactsFromReadyMaterial(args: {
  material: ReadyEvmFamilyEcdsaMaterial;
}): Promise<VerifiedEcdsaPublicFacts> {
  return toVerifiedEcdsaPublicFactsFromPairedRecordAndKeyRef({
    record: args.material.record,
    keyRef: args.material.keyRef,
    context: 'ready ECDSA material',
  });
}

export async function toVerifiedEcdsaPublicFactsFromDurableRecord(args: {
  record: DurableEvmFamilyEcdsaPublicFactsRecord;
}): Promise<VerifiedEcdsaPublicFacts> {
  return buildVerifiedEcdsaPublicFacts({
    keyHandle: toEvmFamilyEcdsaKeyHandle(args.record.ecdsaRestore.keyHandle),
    publicKeyB64u: args.record.ecdsaRestore.thresholdEcdsaPublicKeyB64u,
    participantIds: args.record.ecdsaRestore.participantIds,
    thresholdOwnerAddress: args.record.ecdsaRestore.ethereumAddress,
  });
}

export function buildEvmFamilyEcdsaKeyIdentityFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  rpId: unknown;
  trustedOwnerAddress?: unknown;
}): EvmFamilyEcdsaKeyIdentity {
  const thresholdOwnerAddress = normalizeThresholdOwnerAddress(args.record.ethereumAddress);
  const trustedOwnerAddress = String(args.trustedOwnerAddress ?? '').trim()
    ? normalizeThresholdOwnerAddress(args.trustedOwnerAddress)
    : null;
  if (trustedOwnerAddress && thresholdOwnerAddress !== trustedOwnerAddress) {
    throw new Error(
      '[evm-family-ecdsa] persisted owner address mismatches trusted EVM-family key material',
    );
  }
  const signingRootBinding = resolveThresholdSigningRootBindingFromRecord({
    record: args.record,
  });
  return buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: args.record.walletId,
    rpId: args.rpId,
    ecdsaThresholdKeyId: resolveThresholdEcdsaKeyIdFromRecord({
      record: args.record,
    }),
    signingRootId: signingRootBinding.signingRootId,
    signingRootVersion: signingRootBinding.signingRootVersion,
    participantIds: args.record.participantIds,
    thresholdOwnerAddress,
  });
}

export function buildEvmFamilyEcdsaKeyIdentityFromKeyRef(args: {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  rpId: unknown;
  trustedOwnerAddress?: unknown;
}): EvmFamilyEcdsaKeyIdentity {
  const thresholdOwnerAddress = normalizeThresholdOwnerAddress(args.keyRef.ethereumAddress);
  const trustedOwnerAddress = String(args.trustedOwnerAddress ?? '').trim()
    ? normalizeThresholdOwnerAddress(args.trustedOwnerAddress)
    : null;
  if (trustedOwnerAddress && thresholdOwnerAddress !== trustedOwnerAddress) {
    throw new Error(
      '[evm-family-ecdsa] key ref owner address mismatches trusted EVM-family key material',
    );
  }
  return buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: args.keyRef.userId,
    rpId: args.rpId,
    ecdsaThresholdKeyId: resolveThresholdEcdsaKeyIdFromKeyRef({
      keyRef: args.keyRef,
    }),
    signingRootId: args.keyRef.signingRootId,
    signingRootVersion: args.keyRef.signingRootVersion,
    participantIds: args.keyRef.participantIds,
    thresholdOwnerAddress,
  });
}

export function buildEvmFamilyEcdsaSessionLane(
  input: BuildEvmFamilyEcdsaSessionLaneInput,
): EvmFamilyEcdsaSessionLane {
  const remainingUses = Math.floor(Number(input.remainingUses));
  const expiresAtMs = Math.floor(Number(input.expiresAtMs));
  if (!Number.isFinite(remainingUses)) {
    throw new Error('[evm-family-ecdsa] remainingUses must be finite');
  }
  if (!Number.isFinite(expiresAtMs)) {
    throw new Error('[evm-family-ecdsa] expiresAtMs must be finite');
  }
  return {
    key: input.key,
    chainTarget: input.chainTarget,
    authMethod: input.authMethod,
    source: input.source,
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(input.thresholdSessionId),
    walletSigningSessionId: SigningSessionIds.walletSigningSession(input.walletSigningSessionId),
    thresholdSessionKind: input.thresholdSessionKind,
    thresholdSessionAuthToken: normalizeThresholdSessionAuthToken({
      thresholdSessionKind: input.thresholdSessionKind,
      thresholdSessionAuthToken: input.thresholdSessionAuthToken,
    }),
    remainingUses,
    expiresAtMs,
  };
}

export function buildEvmFamilyEcdsaSessionLanePolicy(
  input: BuildEvmFamilyEcdsaSessionLanePolicyInput,
): EvmFamilyEcdsaSessionLanePolicy {
  const ttlMs = Math.floor(Number(input.ttlMs));
  const remainingUses = Math.floor(Number(input.remainingUses));
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error('[evm-family-ecdsa] ttlMs must be a positive finite value');
  }
  if (!Number.isFinite(remainingUses) || remainingUses <= 0) {
    throw new Error('[evm-family-ecdsa] remainingUses must be a positive finite value');
  }
  return {
    chainTarget: input.chainTarget,
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(input.thresholdSessionId),
    walletSigningSessionId: SigningSessionIds.walletSigningSession(input.walletSigningSessionId),
    thresholdSessionKind: input.thresholdSessionKind,
    ttlMs,
    remainingUses,
    ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
  };
}

export function deriveEvmFamilyKeyFingerprint(
  key: EvmFamilyEcdsaKeyIdentity,
): EvmFamilyKeyFingerprint {
  const canonical = alphabetizeStringify({
    version: 'evm_family_ecdsa_key_fingerprint_v1',
    walletId: String(key.walletId),
    subjectId: String(deriveBaseEcdsaSubjectIdFromKey(key)),
    rpId: String(key.rpId),
    keyScope: key.keyScope,
    ecdsaThresholdKeyId: String(key.ecdsaThresholdKeyId),
    signingRootId: String(key.signingRootId),
    signingRootVersion: String(key.signingRootVersion),
    participantIds: key.participantIds.map((id) => Number(id)),
    thresholdOwnerAddress: String(key.thresholdOwnerAddress),
  });
  return `evmfam-ecdsa:${fnv1a32Hex(canonical)}` as EvmFamilyKeyFingerprint;
}

export function deriveEvmFamilyKeyFingerprintFromPublicFacts(
  input: BuildEvmFamilyKeyFingerprintFromPublicFactsInput,
): EvmFamilyKeyFingerprint {
  const canonical = alphabetizeStringify({
    version: 'evm_family_ecdsa_public_facts_fingerprint_v1',
    walletId: String(toWalletId(input.walletId)),
    keyHandle: String(input.publicFacts.keyHandle),
    publicKeyB64u: String(input.publicFacts.publicKeyB64u),
    participantIds: input.publicFacts.participantIds.map((id) => Number(id)),
    thresholdOwnerAddress: String(input.publicFacts.thresholdOwnerAddress),
  });
  return `evmfam-ecdsa:${fnv1a32Hex(canonical)}` as EvmFamilyKeyFingerprint;
}

export function deriveEvmFamilyKeyFingerprintFromRecordPublicFacts(args: {
  walletId: unknown;
  record: Pick<
    ThresholdEcdsaSessionRecord,
    'keyHandle' | 'thresholdEcdsaPublicKeyB64u' | 'participantIds' | 'ethereumAddress'
  >;
}): EvmFamilyKeyFingerprint {
  return deriveEvmFamilyKeyFingerprintFromPublicFacts({
    walletId: args.walletId,
    publicFacts: buildVerifiedEcdsaPublicFacts({
      keyHandle: toEvmFamilyEcdsaKeyHandle(args.record.keyHandle),
      publicKeyB64u: args.record.thresholdEcdsaPublicKeyB64u,
      participantIds: args.record.participantIds,
      thresholdOwnerAddress: args.record.ethereumAddress,
    }),
  });
}

export function resolveReadyEvmFamilyEcdsaMaterial(
  input: ResolveReadyEvmFamilyEcdsaMaterialInput,
): EvmFamilyEcdsaMaterialResolution {
  const expectedThresholdSessionId = SigningSessionIds.thresholdEcdsaSession(
    input.expected.thresholdSessionId,
  );
  const expectedWalletSigningSessionId = SigningSessionIds.walletSigningSession(
    input.expected.walletSigningSessionId,
  );
  if (!input.record && !input.keyRef) {
    return { kind: 'missing', reason: staleReason('invalid_identity') };
  }
  if (!input.record) {
    return { kind: 'key_ref_only', reason: staleReason('invalid_identity') };
  }
  if (!input.keyRef) {
    return { kind: 'record_only', reason: staleReason('invalid_identity') };
  }

  let recordKey: EvmFamilyEcdsaKeyIdentity;
  let keyRefKey: EvmFamilyEcdsaKeyIdentity;
  try {
    recordKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: input.record,
      rpId: input.rpId,
    });
    keyRefKey = buildEvmFamilyEcdsaKeyIdentityFromKeyRef({
      keyRef: input.keyRef,
      rpId: input.rpId,
    });
  } catch {
    return { kind: 'identity_mismatch', reason: staleReason('invalid_identity') };
  }

  const keyMismatch = firstKeyMismatch(recordKey, keyRefKey);
  if (keyMismatch) return { kind: 'identity_mismatch', reason: keyMismatch };
  const recordPublicKeyB64u = String(input.record.thresholdEcdsaPublicKeyB64u || '').trim();
  const keyRefPublicKeyB64u = String(input.keyRef.thresholdEcdsaPublicKeyB64u || '').trim();
  if (recordPublicKeyB64u && keyRefPublicKeyB64u && recordPublicKeyB64u !== keyRefPublicKeyB64u) {
    return {
      kind: 'identity_mismatch',
      reason: mismatch(
        'public_key_mismatch',
        'thresholdEcdsaPublicKeyB64u',
        recordPublicKeyB64u,
        keyRefPublicKeyB64u,
      ),
    };
  }

  const expectedWalletId = toWalletId(input.expected.walletId);
  if (String(recordKey.walletId) !== String(expectedWalletId)) {
    return {
      kind: 'identity_mismatch',
      reason: mismatch('wallet_mismatch', 'walletId', expectedWalletId, recordKey.walletId),
    };
  }
  if (!thresholdEcdsaChainTargetsEqual(input.record.chainTarget, input.expected.chainTarget)) {
    return {
      kind: 'identity_mismatch',
      reason: mismatch(
        'chain_family_mismatch',
        'chainTarget',
        thresholdEcdsaChainTargetKey(input.expected.chainTarget),
        thresholdEcdsaChainTargetKey(input.record.chainTarget),
      ),
    };
  }
  if (!thresholdEcdsaChainTargetsEqual(input.keyRef.chainTarget, input.expected.chainTarget)) {
    return {
      kind: 'identity_mismatch',
      reason: mismatch(
        'chain_family_mismatch',
        'chainTarget',
        thresholdEcdsaChainTargetKey(input.expected.chainTarget),
        thresholdEcdsaChainTargetKey(input.keyRef.chainTarget),
      ),
    };
  }
  if (authMethodForRecord(input.record) !== input.expected.authMethod) {
    return {
      kind: 'identity_mismatch',
      reason: mismatch(
        'auth_method_mismatch',
        'authMethod',
        input.expected.authMethod,
        authMethodForRecord(input.record),
      ),
    };
  }
  if (
    String(input.record.thresholdSessionId) !== String(expectedThresholdSessionId) ||
    String(input.keyRef.thresholdSessionId) !== String(expectedThresholdSessionId) ||
    String(input.record.walletSigningSessionId) !== String(expectedWalletSigningSessionId) ||
    String(input.keyRef.walletSigningSessionId) !== String(expectedWalletSigningSessionId)
  ) {
    return {
      kind: 'identity_mismatch',
      reason: mismatch(
        'session_identity_mismatch',
        'sessionIdentity',
        `${String(expectedWalletSigningSessionId)}:${String(expectedThresholdSessionId)}`,
        `${String(input.record.walletSigningSessionId)}:${String(input.record.thresholdSessionId)}/${String(input.keyRef.walletSigningSessionId)}:${String(input.keyRef.thresholdSessionId)}`,
      ),
    };
  }

  const nowMs = Math.floor(Number(input.nowMs) || Date.now());
  if (input.record.remainingUses <= 0) {
    return { kind: 'stale', reason: staleReason('exhausted') };
  }
  if (input.record.expiresAtMs > 0 && input.record.expiresAtMs <= nowMs) {
    return { kind: 'stale', reason: staleReason('expired') };
  }

  let lane: EvmFamilyEcdsaSessionLane;
  try {
    lane = buildEvmFamilyEcdsaSessionLane({
      key: recordKey,
      chainTarget: input.expected.chainTarget,
      authMethod: input.expected.authMethod,
      source: input.expected.source,
      thresholdSessionId: expectedThresholdSessionId,
      walletSigningSessionId: expectedWalletSigningSessionId,
      thresholdSessionKind: input.record.thresholdSessionKind,
      thresholdSessionAuthToken:
        input.record.thresholdSessionAuthToken || input.keyRef.thresholdSessionAuthToken,
      remainingUses: input.record.remainingUses,
      expiresAtMs: input.record.expiresAtMs,
    });
  } catch {
    return { kind: 'stale', reason: staleReason('auth_missing') };
  }

  return {
    kind: 'ready',
    material: {
      kind: 'ready_evm_family_ecdsa_material',
      key: recordKey,
      lane,
      record: input.record,
      keyRef: input.keyRef,
      signingKeyContext: {
        ecdsaThresholdKeyId: recordKey.ecdsaThresholdKeyId,
        signingRootId: recordKey.signingRootId,
        signingRootVersion: recordKey.signingRootVersion,
        participantIds: recordKey.participantIds,
      },
      cachedExportArtifact: input.keyRef.ecdsaHssExportArtifact || null,
    },
  };
}
