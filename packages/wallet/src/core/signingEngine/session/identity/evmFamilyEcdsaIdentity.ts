import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { base64UrlDecode } from '@shared/utils/base64';
import { alphabetizeStringify } from '@shared/utils/digests';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  deriveThresholdEcdsaKeyHandle,
  type ThresholdEcdsaKeyHandleInput,
} from '@shared/utils/thresholdEcdsaKeyHandle';
import { type RouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { type EcdsaActiveStateId, type MpcMaterialActivationRef } from '@shared/utils/domainIds';
import {
  deriveEvmFamilySigningKeySlotId as deriveSharedEvmFamilySigningKeySlotId,
  requireEvmFamilySigningKeySlotId,
  type EvmFamilySigningKeySlotId,
} from '@shared/signing-lanes';
import type {
  EcdsaRoleLocalReadyRecord,
  EcdsaRoleLocalReadyStateBlob,
  EcdsaThresholdKeyId,
  EmailOtpAuthSubjectId,
  RpId,
  SigningRootId,
  SigningRootVersion,
} from '@/core/platform/types';
import type { RouterAbEcdsaDerivationSigningMaterialRef } from '../../routerAb/ecdsaDerivation/signingMaterialRef';
import {
  toWalletId,
  walletIdFromWalletProfile,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '../../interfaces/ecdsaChainTarget';
import { SigningSessionIds, type ThresholdEcdsaSessionId } from '../operationState/types';
import {
  type EcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalWorkerHandle,
} from '../keyMaterialBrands';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';

export type {
  EcdsaThresholdKeyId,
  EmailOtpAuthSubjectId,
  RpId,
  SigningRootId,
  SigningRootVersion,
  WalletId,
  ThresholdEcdsaSessionId,
  EvmFamilySigningKeySlotId,
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
export type EvmFamilyKeyScope = 'evm-family';
export type EvmFamilyKeyFingerprint = string & {
  readonly __brand: 'EvmFamilyKeyFingerprint';
};

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

export type EvmFamilyEcdsaWalletKey = {
  kind: 'evm_family_ecdsa_wallet_key';
  walletId: WalletId;
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
  rpId?: never;
};

export type PasskeyEcdsaAuthBinding = {
  kind: 'passkey_ecdsa_auth_binding';
  authMethod: typeof SIGNER_AUTH_METHODS.passkey;
  rpId: RpId;
  credentialIdB64u: string;
  authSubjectId?: never;
  providerId?: never;
  keyHandle?: never;
  publicKeyB64u?: never;
  participantIds?: never;
  thresholdOwnerAddress?: never;
};

export type EmailOtpEcdsaAuthBinding = {
  kind: 'email_otp_ecdsa_auth_binding';
  authMethod: typeof SIGNER_AUTH_METHODS.emailOtp;
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

export type ThresholdEcdsaRoleLocalWorkerMaterial =
  | {
      kind: 'worker_loaded';
      materialRef: EcdsaRoleLocalPersistedMaterialRef;
      stateBlob?: never;
      ecdsaRoleLocalReadyRecord?: never;
    }
  | {
      kind: 'ready_state_blob';
      stateBlob: EcdsaRoleLocalReadyStateBlob;
      ecdsaRoleLocalReadyRecord: EcdsaRoleLocalReadyRecord;
      materialRef?: never;
    };

export type ThresholdEcdsaRoleLocalWorkerShare = {
  kind: 'role_local_worker_share';
  handle: EcdsaRoleLocalWorkerHandle;
  material: ThresholdEcdsaRoleLocalWorkerMaterial;
};

export type ThresholdEcdsaLinkedHolderWorkerShare = {
  readonly kind: 'linked_holder_worker_share';
  readonly holderHandleId: string;
};

export type ThresholdEcdsaSignerClientShare =
  | ThresholdEcdsaRoleLocalWorkerShare
  | ThresholdEcdsaLinkedHolderWorkerShare;

export type HydratedEcdsaSignerTransport = {
  readonly kind: 'threshold_ecdsa_signer_transport';
  readonly relayerUrl: string;
  readonly relayerKeyId: string;
  readonly signingMaterial: RouterAbEcdsaDerivationSigningMaterialRef;
  readonly relayerVerifyingShareB64u: string;
};

export type HydratedRouterAbEcdsaDerivationNormalSigning = {
  readonly kind: 'router_ab_ecdsa_derivation_normal_signing_hydrated_v1';
  readonly state: RouterAbEcdsaDerivationNormalSigningStateV1;
  readonly activeStateId: EcdsaActiveStateId;
  readonly credential?: never;
};

export type HydratedEcdsaSignerMaterial = {
  readonly kind: 'hydrated_ecdsa_signer_material';
  readonly walletId: WalletId;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly publicFacts: VerifiedEcdsaPublicFacts;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly transport: HydratedEcdsaSignerTransport;
  readonly clientShare: ThresholdEcdsaSignerClientShare;
  readonly routerAbEcdsaDerivationNormalSigning: HydratedRouterAbEcdsaDerivationNormalSigning;
  readonly authorization?: never;
  readonly credential?: never;
};

export type EvmFamilyEcdsaKeyIdentity = {
  walletId: WalletId;
  keyScope: EvmFamilyKeyScope;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  participantIds: readonly ParticipantId[];
  thresholdOwnerAddress: ThresholdOwnerAddress;
  thresholdSessionId?: never;
  chainTarget?: never;
  authMethod?: never;
  rpId?: never;
};

export type EvmFamilyEcdsaSessionLanePolicy = {
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: ThresholdEcdsaSessionId;
  ttlMs: number;
  remainingUses: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  ecdsaThresholdKeyId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  participantIds?: never;
  thresholdOwnerAddress?: never;
};

export type EvmFamilyEcdsaRecoveredMaterialLanePolicy = EvmFamilyEcdsaSessionLanePolicy;

export type EvmFamilyEcdsaActivationLanePolicy =
  | EvmFamilyEcdsaSessionLanePolicy
  | EvmFamilyEcdsaRecoveredMaterialLanePolicy;

export type BuildEvmFamilyEcdsaKeyIdentityInput = {
  walletId: unknown;
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
  participantIds: unknown;
  thresholdOwnerAddress: unknown;
};

export type BuildVerifiedEcdsaPublicFactsInput = {
  keyHandle: EvmFamilyEcdsaKeyHandle;
  publicKeyB64u: unknown;
  participantIds: unknown;
  thresholdOwnerAddress: unknown;
};

export type BuildEvmFamilyEcdsaWalletKeyInput = BuildEvmFamilyEcdsaKeyIdentityInput & {
  keyHandle: unknown;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdEcdsaPublicKeyB64u: unknown;
};

export type BuildEvmFamilyKeyFingerprintFromPublicFactsInput = {
  walletId: unknown;
  publicFacts: VerifiedEcdsaPublicFacts;
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

export type BuildHydratedEcdsaSignerMaterialInput = {
  readonly walletId: WalletId;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly publicFacts: VerifiedEcdsaPublicFacts;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly transport: HydratedEcdsaSignerTransport;
  readonly clientShare: ThresholdEcdsaSignerClientShare;
  readonly routerAbEcdsaDerivationNormalSigning: HydratedRouterAbEcdsaDerivationNormalSigning;
  readonly authorization?: never;
  readonly credential?: never;
};

export type BuildEvmFamilyEcdsaSessionLanePolicyInput = {
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: unknown;
  ttlMs: unknown;
  remainingUses: unknown;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

export type BuildEvmFamilyEcdsaRecoveredMaterialLanePolicyInput =
  BuildEvmFamilyEcdsaSessionLanePolicyInput;

function requiredString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`[evm-family-ecdsa] ${field} is required`);
  return normalized;
}

function normalizeRpId(value: unknown): RpId {
  return requiredString(value, 'rpId') as RpId;
}

function normalizeWalletKeyId(value: unknown): EvmFamilySigningKeySlotId {
  try {
    return requireEvmFamilySigningKeySlotId(value);
  } catch (error) {
    throw new Error(`[evm-family-ecdsa] ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function deriveEvmFamilySigningKeySlotId(input: {
  walletId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
}): EvmFamilySigningKeySlotId {
  return deriveSharedEvmFamilySigningKeySlotId({
    walletId: toWalletId(input.walletId),
    signingRootId: normalizeSigningRootId(input.signingRootId),
    signingRootVersion: normalizeSigningRootVersion(input.signingRootVersion),
  });
}

export function deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope(input: {
  walletId: unknown;
  runtimePolicyScope: Parameters<typeof signingRootScopeFromRuntimePolicyScope>[0];
}): EvmFamilySigningKeySlotId {
  const signingRoot = signingRootScopeFromRuntimePolicyScope(input.runtimePolicyScope);
  return deriveEvmFamilySigningKeySlotId({
    walletId: input.walletId,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion || 'default',
  });
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

export function toEvmFamilyEcdsaKeyHandle(value: unknown): EvmFamilyEcdsaKeyHandle {
  return requiredString(value, 'keyHandle') as EvmFamilyEcdsaKeyHandle;
}

export function resolveThresholdEcdsaKeyIdFromRecord(args: {
  record: { ecdsaThresholdKeyId: unknown };
}): EcdsaThresholdKeyId {
  const persisted = String(args.record.ecdsaThresholdKeyId ?? '').trim();
  return normalizeEcdsaThresholdKeyId(persisted);
}

export function parseThresholdSigningRootBinding(input: {
  signingRootId: unknown;
  signingRootVersion: unknown;
}): {
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
} {
  return {
    signingRootId: normalizeSigningRootId(input.signingRootId),
    signingRootVersion: normalizeSigningRootVersion(input.signingRootVersion),
  };
}

export function resolveThresholdSigningRootBindingFromRecord(args: {
  record: { signingRootId: unknown; signingRootVersion: unknown };
}): {
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
} {
  return parseThresholdSigningRootBinding({
    signingRootId: args.record.signingRootId,
    signingRootVersion: args.record.signingRootVersion,
  });
}

export function resolveThresholdSigningRootBindingFromRuntimePolicyScope(args: {
  runtimePolicyScope: Parameters<typeof signingRootScopeFromRuntimePolicyScope>[0];
}): {
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
} {
  const scopeBinding = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
  return parseThresholdSigningRootBinding({
    signingRootId: scopeBinding.signingRootId,
    signingRootVersion: scopeBinding.signingRootVersion,
  });
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
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    participantIds: input.participantIds,
    thresholdOwnerAddress: input.thresholdOwnerAddress,
  });
}

function buildNormalizedEvmFamilyEcdsaKeyIdentity(input: {
  walletId: WalletId;
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
  participantIds: unknown;
  thresholdOwnerAddress: unknown;
}): EvmFamilyEcdsaKeyIdentity {
  return {
    walletId: input.walletId,
    keyScope: 'evm-family',
    ecdsaThresholdKeyId: normalizeEcdsaThresholdKeyId(input.ecdsaThresholdKeyId),
    signingRootId: normalizeSigningRootId(input.signingRootId),
    signingRootVersion: normalizeSigningRootVersion(input.signingRootVersion),
    participantIds: normalizeParticipantIds(input.participantIds),
    thresholdOwnerAddress: normalizeThresholdOwnerAddress(input.thresholdOwnerAddress),
  };
}

export function buildBaseEvmFamilyEcdsaKeyIdentity(
  input: BuildEvmFamilyEcdsaKeyIdentityInput,
): EvmFamilyEcdsaKeyIdentity {
  return buildNormalizedEvmFamilyEcdsaKeyIdentity({
    walletId: toWalletId(input.walletId),
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    participantIds: input.participantIds,
    thresholdOwnerAddress: input.thresholdOwnerAddress,
  });
}

export function deriveBaseEcdsaSubjectIdFromWalletId(
  walletId: WalletId | string,
): BaseEcdsaSubjectId {
  return walletIdFromWalletProfile({
    walletId: toWalletId(walletId),
  }) as BaseEcdsaSubjectId;
}

export async function deriveEvmFamilyEcdsaKeyHandle(
  input: ThresholdEcdsaKeyHandleInput,
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
    keyScope: walletKey.keyFacts.keyScope,
    ecdsaThresholdKeyId: walletKey.keyFacts.ecdsaThresholdKeyId,
    signingRootId: walletKey.keyFacts.signingRootId,
    signingRootVersion: walletKey.keyFacts.signingRootVersion,
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

export function buildPasskeyEcdsaAuthBinding(args: {
  rpId: unknown;
  credentialIdB64u: unknown;
}): PasskeyEcdsaAuthBinding {
  return {
    kind: 'passkey_ecdsa_auth_binding',
    authMethod: SIGNER_AUTH_METHODS.passkey,
    rpId: normalizeRpId(args.rpId),
    credentialIdB64u: requiredString(args.credentialIdB64u, 'credentialIdB64u'),
  };
}

export function buildEmailOtpEcdsaAuthBinding(
  args: BuildEmailOtpEcdsaAuthBindingInput,
): EmailOtpEcdsaAuthBinding {
  return {
    kind: 'email_otp_ecdsa_auth_binding',
    authMethod: SIGNER_AUTH_METHODS.emailOtp,
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

export function buildHydratedEcdsaSignerMaterial(
  input: BuildHydratedEcdsaSignerMaterialInput,
): HydratedEcdsaSignerMaterial {
  return {
    kind: 'hydrated_ecdsa_signer_material',
    walletId: input.walletId,
    materialActivation: input.materialActivation,
    publicFacts: input.publicFacts,
    chainTarget: input.chainTarget,
    transport: input.transport,
    clientShare: input.clientShare,
    routerAbEcdsaDerivationNormalSigning: input.routerAbEcdsaDerivationNormalSigning,
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
    ttlMs,
    remainingUses,
    runtimePolicyScope: input.runtimePolicyScope,
  };
}

export function buildEvmFamilyEcdsaRecoveredMaterialLanePolicy(
  input: BuildEvmFamilyEcdsaRecoveredMaterialLanePolicyInput,
): EvmFamilyEcdsaRecoveredMaterialLanePolicy {
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
    ttlMs,
    remainingUses,
    runtimePolicyScope: input.runtimePolicyScope,
  };
}

export function deriveEvmFamilyKeyFingerprint(
  key: EvmFamilyEcdsaKeyIdentity,
): EvmFamilyKeyFingerprint {
  const canonical = alphabetizeStringify({
    version: 'evm_family_ecdsa_key_fingerprint_v2',
    walletId: String(key.walletId),
    baseEcdsaSubjectId: String(deriveBaseEcdsaSubjectIdFromWalletId(key.walletId)),
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
