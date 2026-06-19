import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { base64UrlDecode } from '@shared/utils/base64';
import { alphabetizeStringify } from '@shared/utils/digests';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  deriveThresholdEcdsaKeyHandle,
  type ThresholdEcdsaKeyHandleInput,
} from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  requireRouterAbEcdsaHssNormalSigningStateV1,
  routerAbEcdsaHssActiveStateSessionId,
  type RouterAbEcdsaHssNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaHss';
import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaBackendBinding,
  ThresholdEcdsaClientAdditiveShareHandle,
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaRoleLocalWorkerShareHandle,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../interfaces/signing';
import type {
  EcdsaRoleLocalReadyRecord,
  EcdsaThresholdKeyId,
  EmailOtpAuthSubjectId,
  RpId,
  SigningRootId,
  SigningRootVersion,
} from '@/core/platform/types';
import { buildEcdsaRoleLocalSigningMaterialHandle } from './ecdsaHssSigningMaterialHandle';
import {
  parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord,
  thresholdEcdsaRecordHasRoleLocalSigningMaterial,
} from '../persistence/ecdsaRoleLocalRecords';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from './laneIdentity';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  walletIdFromWalletProfile,
  type ThresholdEcdsaChainTarget,
  type WalletId,
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

export type {
  EcdsaThresholdKeyId,
  EmailOtpAuthSubjectId,
  RpId,
  SigningRootId,
  SigningRootVersion,
  WalletId,
  ThresholdEcdsaSessionId,
  WalletSigningSessionId,
};
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
export type EmailOtpProviderId = string & {
  readonly __brand: 'EmailOtpProviderId';
};
export type BaseEcdsaSubjectId = WalletId & {
  readonly __baseEcdsaSubjectIdBrand: 'BaseEcdsaSubjectId';
};
export type VerifiedWalletSessionJwt = string & {
  readonly __brand: 'VerifiedWalletSessionJwt';
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

export type EvmFamilyEcdsaWalletKeyFacts = {
  kind: 'evm_family_ecdsa_key_facts';
  keyScope: EvmFamilyKeyScope;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  participantIds: readonly ParticipantId[];
  thresholdOwnerAddress: ThresholdOwnerAddress;
  thresholdEcdsaPublicKeyB64u: ThresholdEcdsaPublicKeyB64u;
  keyHandle?: never;
  chainTarget?: never;
  walletId?: never;
  rpId?: never;
};

export type EcdsaKeyFacts = EvmFamilyEcdsaWalletKeyFacts;

export type EvmFamilyEcdsaWalletKey = {
  kind: 'evm_family_ecdsa_wallet_key';
  walletId: WalletId;
  rpId: RpId;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  chainTarget: ThresholdEcdsaChainTarget;
  keyFacts: EvmFamilyEcdsaWalletKeyFacts;
  key?: never;
  publicFacts?: never;
  ecdsaThresholdKeyId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  participantIds?: never;
  thresholdOwnerAddress?: never;
  thresholdEcdsaPublicKeyB64u?: never;
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

export type EcdsaWalletSignerRecord = {
  kind: 'ecdsa_wallet_signer_record';
  walletKey: EvmFamilyEcdsaWalletKey;
  authBinding: EvmFamilyEcdsaAuthBinding;
  keyHandle?: never;
  keyFacts?: never;
  chainTarget?: never;
  subjectId?: never;
  ecdsaThresholdKeyId?: never;
};

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

export type WalletSessionJwtTransportAuth = {
  kind: 'wallet_session_jwt';
  walletSessionJwt: VerifiedWalletSessionJwt;
};

export type EcdsaWalletSessionTransportAuth = WalletSessionJwtTransportAuth;

export type ThresholdEcdsaSignerTransport = {
  kind: 'threshold_ecdsa_signer_transport';
  relayerUrl: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  relayerVerifyingShareB64u?: string;
  auth: EcdsaWalletSessionTransportAuth;
};

export type ReadyThresholdEcdsaSignerTransport = Omit<ThresholdEcdsaSignerTransport, 'auth'> & {
  auth?: never;
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
};

export type ReadyThresholdEcdsaSessionPolicy = KnownReadyThresholdEcdsaSessionPolicy;

export type ReadyThresholdEcdsaSession = {
  kind: 'ready_threshold_ecdsa_session';
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  policy: ReadyThresholdEcdsaSessionPolicy;
  walletSessionAuth?: never;
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

export type ThresholdEcdsaEmailOtpWorkerShare = {
  kind: 'email_otp_worker_share';
  handle: EmailOtpWorkerShareHandle;
};

export type ThresholdEcdsaRoleLocalWorkerShare = {
  kind: 'role_local_worker_share';
  handle: ThresholdEcdsaRoleLocalWorkerShareHandle;
  stateBlob?: never;
  ecdsaRoleLocalReadyRecord?: never;
};

export type ThresholdEcdsaSignerClientShare =
  | ThresholdEcdsaEmailOtpWorkerShare
  | ThresholdEcdsaRoleLocalWorkerShare;

export type ReadyRouterAbEcdsaHssNormalSigning = {
  kind: 'router_ab_ecdsa_hss_normal_signing_ready_v1';
  state: RouterAbEcdsaHssNormalSigningStateV1;
  credential: {
    kind: 'jwt';
    walletSessionJwt: VerifiedWalletSessionJwt;
  };
  walletSessionSessionId: string;
};

export type ReadyEcdsaSignerSession = {
  kind: 'ready_ecdsa_signer_session';
  publicFacts: VerifiedEcdsaPublicFacts;
  chainTarget: ThresholdEcdsaChainTarget;
  session: ReadyThresholdEcdsaSession;
  transport: ReadyThresholdEcdsaSignerTransport;
  clientShare: ThresholdEcdsaSignerClientShare;
  routerAbEcdsaHssNormalSigning: ReadyRouterAbEcdsaHssNormalSigning;
  keyRef?: never;
  participantIds?: never;
  thresholdEcdsaPublicKeyB64u?: never;
  walletSessionJwt?: never;
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
  walletSessionAuth: EcdsaWalletSessionTransportAuth;
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
  participantIds: readonly ParticipantId[];
  signingRootId?: never;
  signingRootVersion?: never;
};

export type ReadyEvmFamilyEcdsaMaterial = {
  kind: 'ready_evm_family_ecdsa_material';
  key: EvmFamilyEcdsaKeyIdentity;
  lane: EvmFamilyEcdsaSessionLane;
  record: ThresholdEcdsaSessionRecord;
  signingKeyContext: ReadyEvmFamilyEcdsaSigningKeyContext;
  cachedExportArtifact: ThresholdEcdsaCanonicalExportArtifact | null;
  keyRef?: never;
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
  rpId: unknown;
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
  participantIds: unknown;
  thresholdOwnerAddress: unknown;
};

export type BuildBaseEvmFamilyEcdsaKeyIdentityInput = BuildEvmFamilyEcdsaKeyIdentityInput;

export type BuildEvmFamilyEcdsaKeyHandleInput = ThresholdEcdsaKeyHandleInput;

export type BuildVerifiedEcdsaPublicFactsInput = {
  keyHandle: EvmFamilyEcdsaKeyHandle;
  publicKeyB64u: unknown;
  participantIds: unknown;
  thresholdOwnerAddress: unknown;
};

export type BuildEvmFamilyEcdsaWalletKeyInput = BuildBaseEvmFamilyEcdsaKeyIdentityInput & {
  keyHandle: unknown;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdEcdsaPublicKeyB64u: unknown;
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

export type BuildEcdsaWalletSessionTransportAuthInput =
  {
    kind: 'wallet_session_jwt';
    walletSessionJwt: unknown;
  };

export type BuildReadyEcdsaSignerSessionInput = {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  publicFacts: VerifiedEcdsaPublicFacts;
  sessionPolicy: ReadyThresholdEcdsaSessionPolicy;
  walletSessionJwt: unknown;
};

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
  walletSessionAuth: BuildEcdsaWalletSessionTransportAuthInput;
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
  keyRef?: never;
  rpId: unknown;
  expected: {
    walletId: AccountId | WalletId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
    thresholdSessionId: ThresholdEcdsaSessionId | string;
    walletSigningSessionId: WalletSigningSessionId | string;
  };
  cachedExportArtifact?: ThresholdEcdsaCanonicalExportArtifact | null;
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

export function resolveThresholdEcdsaKeyIdFromRecord(args: {
  record: { ecdsaThresholdKeyId: unknown };
}): EcdsaThresholdKeyId {
  const persisted = String(args.record.ecdsaThresholdKeyId ?? '').trim();
  return normalizeEcdsaThresholdKeyId(persisted);
}

export function resolveThresholdEcdsaKeyIdFromKeyRef(args: {
  keyRef: { ecdsaThresholdKeyId: unknown };
}): EcdsaThresholdKeyId {
  const explicitKeyId = String(args.keyRef.ecdsaThresholdKeyId || '').trim();
  return normalizeEcdsaThresholdKeyId(explicitKeyId);
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

  const signingRootId = normalizeSigningRootId(args.record.signingRootId);
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

export function walletSessionAuthInputFromPersistedThresholdSession(args: {
  thresholdSessionKind: ThresholdSessionKind;
  walletSessionJwt?: unknown;
}): BuildEcdsaWalletSessionTransportAuthInput {
  if (args.thresholdSessionKind !== 'jwt') {
    throw new Error('Router A/B ECDSA signing requires Wallet Session JWT auth');
  }
  return {
    kind: 'wallet_session_jwt',
    walletSessionJwt: args.walletSessionJwt,
  };
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

export function deriveBaseEcdsaSubjectIdFromWalletId(
  walletId: WalletId | string,
): BaseEcdsaSubjectId {
  return walletIdFromWalletProfile({
    walletId: toWalletId(walletId),
  }) as BaseEcdsaSubjectId;
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

export function evmFamilyEcdsaWalletKeyToIdentity(
  walletKey: EvmFamilyEcdsaWalletKey,
): EvmFamilyEcdsaKeyIdentity {
  return {
    walletId: walletKey.walletId,
    rpId: walletKey.rpId,
    keyScope: walletKey.keyFacts.keyScope,
    ecdsaThresholdKeyId: walletKey.keyFacts.ecdsaThresholdKeyId,
    signingRootId: walletKey.keyFacts.signingRootId,
    signingRootVersion: walletKey.keyFacts.signingRootVersion,
    participantIds: walletKey.keyFacts.participantIds,
    thresholdOwnerAddress: walletKey.keyFacts.thresholdOwnerAddress,
  };
}

export function evmFamilyEcdsaWalletKeyToPublicFacts(
  walletKey: EvmFamilyEcdsaWalletKey,
): VerifiedEcdsaPublicFacts {
  return {
    kind: 'verified_ecdsa_public_facts',
    keyHandle: walletKey.keyHandle,
    publicKeyB64u: walletKey.keyFacts.thresholdEcdsaPublicKeyB64u,
    participantIds: walletKey.keyFacts.participantIds,
    thresholdOwnerAddress: walletKey.keyFacts.thresholdOwnerAddress,
  };
}

export function buildEvmFamilyEcdsaWalletKey(
  input: BuildEvmFamilyEcdsaWalletKeyInput,
): EvmFamilyEcdsaWalletKey {
  const keyHandle = toEvmFamilyEcdsaKeyHandle(input.keyHandle);
  const keyIdentity = buildBaseEvmFamilyEcdsaKeyIdentity(input);
  const publicFacts = buildVerifiedEcdsaPublicFacts({
    keyHandle,
    publicKeyB64u: input.thresholdEcdsaPublicKeyB64u,
    participantIds: keyIdentity.participantIds,
    thresholdOwnerAddress: keyIdentity.thresholdOwnerAddress,
  });
  return {
    kind: 'evm_family_ecdsa_wallet_key',
    walletId: keyIdentity.walletId,
    rpId: keyIdentity.rpId,
    keyHandle,
    chainTarget: input.chainTarget,
    keyFacts: {
      kind: 'evm_family_ecdsa_key_facts',
      keyScope: keyIdentity.keyScope,
      ecdsaThresholdKeyId: keyIdentity.ecdsaThresholdKeyId,
      signingRootId: keyIdentity.signingRootId,
      signingRootVersion: keyIdentity.signingRootVersion,
      participantIds: publicFacts.participantIds,
      thresholdOwnerAddress: publicFacts.thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u: publicFacts.publicKeyB64u,
    },
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

export function buildEcdsaWalletSessionTransportAuth(input: {
  kind: 'wallet_session_jwt';
  walletSessionJwt: unknown;
}): WalletSessionJwtTransportAuth;
export function buildEcdsaWalletSessionTransportAuth(
  input: BuildEcdsaWalletSessionTransportAuthInput,
): EcdsaWalletSessionTransportAuth;
export function buildEcdsaWalletSessionTransportAuth(
  input: BuildEcdsaWalletSessionTransportAuthInput,
): EcdsaWalletSessionTransportAuth {
  return {
    kind: 'wallet_session_jwt',
    walletSessionJwt: requiredString(
      input.walletSessionJwt,
      'walletSessionJwt',
    ) as VerifiedWalletSessionJwt,
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

function assertNeverThresholdEcdsaBackendBinding(value: never): never {
  throw new Error('[evm-family-ecdsa] unsupported ECDSA backend binding material kind');
}

function requireThresholdEcdsaBackendBinding(
  binding: ThresholdEcdsaSecp256k1KeyRef['backendBinding'],
): ThresholdEcdsaBackendBinding {
  if (!binding) {
    throw new Error('[evm-family-ecdsa] ready ECDSA signer session requires backend binding');
  }
  return binding;
}

function buildThresholdEcdsaSignerClientShare(args: {
  backendBinding: ThresholdEcdsaBackendBinding;
  publicFacts: VerifiedEcdsaPublicFacts;
  chainTarget: ThresholdEcdsaChainTarget;
  session: ThresholdEcdsaSignerSessionIdentity;
  routerAbStateSessionId: string;
}): ThresholdEcdsaSignerClientShare {
  switch (args.backendBinding.materialKind) {
    case 'email_otp_worker_handle':
      return {
        kind: 'email_otp_worker_share',
        handle: buildEmailOtpWorkerShareHandle({
          handle: args.backendBinding.clientAdditiveShareHandle,
          publicFacts: args.publicFacts,
          chainTarget: args.chainTarget,
          session: args.session,
        }),
      };
    case 'role_local_worker_handle':
      return {
        kind: 'role_local_worker_share',
        handle: args.backendBinding.roleLocalMaterialHandle,
      };
    case 'role_local_ready_state_blob':
      return {
        kind: 'role_local_worker_share',
        handle: buildEcdsaRoleLocalSigningMaterialHandle({
          thresholdSessionId: String(args.session.thresholdSessionId),
          walletSigningSessionId: String(args.session.walletSigningSessionId),
          keyHandle: String(args.publicFacts.keyHandle),
          routerAbStateSessionId: args.routerAbStateSessionId,
          chainTarget: args.chainTarget,
          clientVerifyingShareB64u: args.backendBinding.clientVerifyingShareB64u,
          ecdsaThresholdKeyId: String(
            args.backendBinding.ecdsaRoleLocalReadyRecord.publicFacts.ecdsaThresholdKeyId,
          ),
          participantIds: args.publicFacts.participantIds.map((participantId) =>
            Number(participantId),
          ),
          relayerKeyId: args.backendBinding.relayerKeyId,
        }),
      };
    case 'metadata_only':
      throw new Error('[evm-family-ecdsa] ready ECDSA signer session requires signing material');
    default:
      return assertNeverThresholdEcdsaBackendBinding(args.backendBinding);
  }
}

function hasReadyThresholdEcdsaRecordClientShare(record: ThresholdEcdsaSessionRecord): boolean {
  return thresholdEcdsaRecordHasRoleLocalSigningMaterial(record);
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

function buildReadyRouterAbEcdsaHssNormalSigning(args: {
  state: unknown;
  auth: WalletSessionJwtTransportAuth;
}): ReadyRouterAbEcdsaHssNormalSigning {
  const state = requireRouterAbEcdsaHssNormalSigningStateV1(args.state);
  return {
    kind: 'router_ab_ecdsa_hss_normal_signing_ready_v1',
    state,
    credential: {
      kind: 'jwt',
      walletSessionJwt: args.auth.walletSessionJwt,
    },
    walletSessionSessionId: routerAbEcdsaHssActiveStateSessionId(state),
  };
}

export function buildReadyEcdsaSignerSession(
  input: BuildReadyEcdsaSignerSessionInput,
): ReadyEcdsaSignerSession {
  const backendBinding = requireThresholdEcdsaBackendBinding(input.keyRef.backendBinding);
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
  const transportAuth = buildEcdsaWalletSessionTransportAuth({
    kind: 'wallet_session_jwt',
    walletSessionJwt: input.walletSessionJwt,
  });
  const routerAbEcdsaHssNormalSigning = buildReadyRouterAbEcdsaHssNormalSigning({
    state: input.keyRef.routerAbEcdsaHssNormalSigning,
    auth: transportAuth,
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
      relayerKeyId: requiredString(backendBinding.relayerKeyId, 'relayerKeyId'),
      clientVerifyingShareB64u: requiredString(
        backendBinding.clientVerifyingShareB64u,
        'clientVerifyingShareB64u',
      ),
      ...(String(input.keyRef.relayerVerifyingShareB64u || '').trim()
        ? { relayerVerifyingShareB64u: String(input.keyRef.relayerVerifyingShareB64u).trim() }
        : {}),
    },
    clientShare: buildThresholdEcdsaSignerClientShare({
      backendBinding,
      publicFacts: input.publicFacts,
      chainTarget,
      session: signerIdentity,
      routerAbStateSessionId: routerAbEcdsaHssNormalSigning.walletSessionSessionId,
    }),
    routerAbEcdsaHssNormalSigning,
  };
}

export function buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  exportArtifact?: ThresholdEcdsaCanonicalExportArtifact;
}): ThresholdEcdsaSecp256k1KeyRef {
  const record = args.record;
  const ecdsaRoleLocalReadyRecord = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(record);
  const backendBinding = record.clientAdditiveShareHandle
    ? {
        materialKind: 'email_otp_worker_handle' as const,
        relayerKeyId: record.relayerKeyId,
        clientVerifyingShareB64u: record.clientVerifyingShareB64u,
        clientAdditiveShareHandle: record.clientAdditiveShareHandle,
        ecdsaRoleLocalReadyRecord,
      }
    : {
        materialKind: 'role_local_ready_state_blob' as const,
        relayerKeyId: record.relayerKeyId,
        clientVerifyingShareB64u: record.clientVerifyingShareB64u,
        stateBlob: ecdsaRoleLocalReadyRecord.stateBlob,
        ecdsaRoleLocalReadyRecord,
      };
  return {
    type: 'threshold-ecdsa-secp256k1',
    userId: String(record.walletId),
    chainTarget: record.chainTarget,
    relayerUrl: record.relayerUrl,
    keyHandle: record.keyHandle,
    ecdsaThresholdKeyId: resolveThresholdEcdsaKeyIdFromRecord({ record }),
    backendBinding,
    ...(args.exportArtifact ? { ecdsaHssExportArtifact: args.exportArtifact } : {}),
    participantIds: record.participantIds,
    thresholdSessionKind: record.thresholdSessionKind,
    thresholdSessionId: record.thresholdSessionId,
    walletSigningSessionId: record.walletSigningSessionId,
    ...(record.walletSessionJwt
      ? { walletSessionJwt: record.walletSessionJwt }
      : {}),
    ...(record.thresholdEcdsaPublicKeyB64u
      ? { thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u }
      : {}),
    ...(record.ethereumAddress ? { ethereumAddress: record.ethereumAddress } : {}),
    ...(record.relayerVerifyingShareB64u
      ? { relayerVerifyingShareB64u: record.relayerVerifyingShareB64u }
      : {}),
    ...(record.routerAbEcdsaHssNormalSigning
      ? { routerAbEcdsaHssNormalSigning: record.routerAbEcdsaHssNormalSigning }
      : {}),
  };
}

export function buildReadyEcdsaSignerSessionFromReadyMaterial(args: {
  material: ReadyEvmFamilyEcdsaMaterial;
  publicFacts: VerifiedEcdsaPublicFacts;
}): ReadyEcdsaSignerSession {
  const keyRef = buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord({
    record: args.material.record,
    ...(args.material.cachedExportArtifact
      ? { exportArtifact: args.material.cachedExportArtifact }
      : {}),
  });
  if (args.material.lane.walletSessionAuth.kind !== 'wallet_session_jwt') {
    throw new Error(
      '[evm-family-ecdsa] Router A/B ECDSA-HSS signing requires bearer Wallet Session auth',
    );
  }
  return buildReadyEcdsaSignerSession({
    keyRef,
    publicFacts: args.publicFacts,
    sessionPolicy: buildKnownReadyThresholdEcdsaSessionPolicy({
      remainingUses: args.material.lane.remainingUses,
      expiresAtMs: args.material.lane.expiresAtMs,
    }),
    walletSessionJwt: args.material.lane.walletSessionAuth.walletSessionJwt,
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
  if (!keyHandle) {
    throw new Error('[evm-family-ecdsa] key ref public facts require keyHandle');
  }
  return buildVerifiedEcdsaPublicFacts({
    keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
    publicKeyB64u: args.keyRef.thresholdEcdsaPublicKeyB64u,
    participantIds: args.keyRef.participantIds,
    thresholdOwnerAddress: args.keyRef.ethereumAddress,
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
  return toVerifiedEcdsaPublicFactsFromRecord({ record: args.material.record });
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
  runtimePolicyScope: ThresholdRuntimePolicyScope;
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
    ...resolveThresholdSigningRootBindingFromRecord({
      record: {
        keyHandle: toEvmFamilyEcdsaKeyHandle(args.keyRef.keyHandle),
        runtimePolicyScope: args.runtimePolicyScope,
      },
    }),
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
    walletSessionAuth: buildEcdsaWalletSessionTransportAuth(input.walletSessionAuth),
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
    version: 'evm_family_ecdsa_key_fingerprint_v2',
    walletId: String(key.walletId),
    baseEcdsaSubjectId: String(deriveBaseEcdsaSubjectIdFromWalletId(key.walletId)),
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
  if (!input.record) {
    return { kind: 'missing', reason: staleReason('invalid_identity') };
  }

  let recordKey: EvmFamilyEcdsaKeyIdentity;
  try {
    recordKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: input.record,
      rpId: input.rpId,
    });
  } catch {
    return { kind: 'identity_mismatch', reason: staleReason('invalid_identity') };
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
    String(input.record.walletSigningSessionId) !== String(expectedWalletSigningSessionId)
  ) {
    return {
      kind: 'identity_mismatch',
      reason: mismatch(
        'session_identity_mismatch',
        'sessionIdentity',
        `${String(expectedWalletSigningSessionId)}:${String(expectedThresholdSessionId)}`,
        `${String(input.record.walletSigningSessionId)}:${String(input.record.thresholdSessionId)}`,
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
  if (!hasReadyThresholdEcdsaRecordClientShare(input.record)) {
    return { kind: 'stale', reason: staleReason('auth_missing') };
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
      walletSessionAuth: walletSessionAuthInputFromPersistedThresholdSession({
        thresholdSessionKind: input.record.thresholdSessionKind,
        walletSessionJwt: input.record.walletSessionJwt,
      }),
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
      signingKeyContext: {
        ecdsaThresholdKeyId: recordKey.ecdsaThresholdKeyId,
        participantIds: recordKey.participantIds,
      },
      cachedExportArtifact: input.cachedExportArtifact || null,
    },
  };
}
