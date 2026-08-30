import type { ActiveEcdsaCapabilityManifest } from './ecdsaCapabilityManifest';
import type { PersistedEcdsaRoleLocalMaterial } from './ecdsaRoleLocalMaterialResolver';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking/contracts';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import type {
  ExactEcdsaCapabilityRuntime,
  ExactEcdsaDirectCapabilityRuntime,
  ExactEcdsaSealedRuntimeAuthBinding,
  ExactEcdsaWalletSessionRuntime,
} from './ecdsaSealedRuntime';
import type { ActiveWalletSessionQuotaStatusV1 } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import type { ActiveWalletAuthMethodV2 } from '../identity/ownerLaneScope';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  walletAuthAuthoritiesMatch,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

type ExactEvmFamilyWalletSessionAuthorizationBase = {
  readonly kind: 'exact_evm_family_wallet_session_authorization_v1';
  readonly selectedAuthority: ActiveWalletAuthorityV1;
  readonly session: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
};

type ExactPasskeyWalletSessionRuntime = ExactEcdsaWalletSessionRuntime & {
  readonly authBinding: Extract<ExactEcdsaSealedRuntimeAuthBinding, { readonly kind: 'passkey' }>;
};

type ExactEmailOtpWalletSessionRuntime = ExactEcdsaWalletSessionRuntime & {
  readonly authBinding: Extract<ExactEcdsaSealedRuntimeAuthBinding, { readonly kind: 'email_otp' }>;
};

type ExactPasskeyEvmFamilyWalletSessionAuthorization =
  ExactEvmFamilyWalletSessionAuthorizationBase & {
    readonly selectedAuthMethod: Extract<ActiveWalletAuthMethodV2, { readonly kind: 'passkey' }>;
    readonly runtime: ExactPasskeyWalletSessionRuntime;
  };

type ExactEmailOtpEvmFamilyWalletSessionAuthorization =
  ExactEvmFamilyWalletSessionAuthorizationBase & {
    readonly selectedAuthMethod: Extract<ActiveWalletAuthMethodV2, { readonly kind: 'email_otp' }>;
    readonly runtime: ExactEmailOtpWalletSessionRuntime;
  };

export type ExactEvmFamilyWalletSessionAuthorization =
  | ExactPasskeyEvmFamilyWalletSessionAuthorization
  | ExactEmailOtpEvmFamilyWalletSessionAuthorization;

export type ExactEcdsaWalletSessionAuthorizationLookup = {
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly materialActivation: MpcMaterialActivationRef;
};

export type ExactEcdsaWalletSessionAuthorizationResolver = (
  input: ExactEcdsaWalletSessionAuthorizationLookup,
) => Promise<ExactEvmFamilyWalletSessionAuthorization | null>;

export type CanonicalEvmFamilyEcdsaSigningCapability = {
  readonly kind: 'canonical_evm_family_ecdsa_signing_capability';
  readonly authority: WalletAuthAuthority;
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly material: PersistedEcdsaRoleLocalMaterial;
};

// The canonical capability is durable state: it must resolve from persistence
// alone so hydration can rebind exact material while no reusable Wallet Session
// is active. Authorization is the independent second proof, paired with the
// capability only on the signing path.
export type AuthorizedEvmFamilyEcdsaSigningCapability = {
  readonly kind: 'authorized_evm_family_ecdsa_signing_capability';
  readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
  readonly authorization: ExactEvmFamilyWalletSessionAuthorization;
};

export type EvmFamilyEcdsaSigningCapabilityAvailability =
  | AuthorizedEvmFamilyEcdsaSigningCapability
  | {
      readonly kind: 'authorization_required';
      readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
      readonly authorization?: never;
    };

type ResolvedSelectedWalletAuthorityRecord = Extract<
  ResolveSelectedWalletAuthorityResultV1,
  { readonly kind: 'resolved' }
>;

type ResolvedSelectedWalletAuthority = Omit<
  ResolvedSelectedWalletAuthorityRecord,
  'authMethod' | 'authority'
> & {
  readonly authMethod: ActiveWalletAuthMethodV2;
  readonly authority: ActiveWalletAuthorityV1;
};

export type BuildExactEvmFamilyWalletSessionAuthorizationInput = {
  readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
  readonly selected: ResolvedSelectedWalletAuthority;
  readonly session: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly runtime: ExactEcdsaWalletSessionRuntime;
  readonly nowMs: number;
};

function exactEcdsaSubjectMatches(args: {
  readonly session: ActiveWalletSessionV1;
  readonly materialActivation: CanonicalEvmFamilyEcdsaSigningCapability['manifest']['activation']['materialActivation'];
}): boolean {
  const matches = args.session.capabilitySubjects.filter(
    (subject) =>
      subject.kind === 'sign' &&
      subject.keyFamily === 'ecdsa_secp256k1' &&
      mpcMaterialActivationRefsEqual(subject.materialActivation, args.materialActivation),
  );
  return matches.length === 1;
}

function targetMatchesCapability(args: {
  readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
  readonly chainTarget: ThresholdEcdsaChainTarget;
}): boolean {
  return args.capability.manifest.signer.scope.targetMemberships.some((target) =>
    thresholdEcdsaChainTargetsEqual(target, args.chainTarget),
  );
}

function participantIdsMatch(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function selectedAuthorityComponentsAreExact(args: {
  readonly selectedAuthority: ActiveWalletAuthorityV1;
  readonly selectedAuthMethod: ActiveWalletAuthMethodV2;
  readonly walletId: WalletId;
}): boolean {
  const { selectedAuthority, selectedAuthMethod } = args;
  return (
    selectedAuthMethod.walletId === args.walletId &&
    selectedAuthMethod.status === 'active' &&
    selectedAuthMethod.walletAuthorityId === selectedAuthority.authorityId &&
    selectedAuthority.walletId === args.walletId &&
    selectedAuthority.state === 'active'
  );
}

function capabilityAuthorityMatchesRuntime(args: {
  readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
  readonly runtime: ExactEcdsaWalletSessionRuntime;
}): boolean {
  const capabilityAuthority = args.capability.authority;
  const runtimeBinding = args.runtime.authBinding;
  switch (runtimeBinding.kind) {
    case 'email_otp':
      return (
        isEmailOtpWalletAuthAuthority(capabilityAuthority) &&
        walletAuthAuthoritiesMatch(capabilityAuthority, runtimeBinding.emailOtpAuthority)
      );
    case 'passkey':
      return (
        isPasskeyWalletAuthAuthority(capabilityAuthority) &&
        capabilityAuthority.verifier.rpId === runtimeBinding.rpId &&
        capabilityAuthority.factor.credentialIdB64u === runtimeBinding.credentialIdB64u
      );
    default: {
      const exhaustive: never = runtimeBinding;
      return exhaustive;
    }
  }
}

function selectedAuthMethodMatchesRuntime(args: {
  readonly selectedAuthMethod: ActiveWalletAuthMethodV2;
  readonly runtime: ExactEcdsaWalletSessionRuntime;
}): boolean {
  switch (args.runtime.authBinding.kind) {
    case 'email_otp':
      return (
        args.selectedAuthMethod.kind === 'email_otp' &&
        args.selectedAuthMethod.emailHashHex === args.runtime.authBinding.emailHashHex
      );
    case 'passkey':
      return (
        args.selectedAuthMethod.kind === 'passkey' &&
        String(args.selectedAuthMethod.rpId) === String(args.runtime.authBinding.rpId) &&
        args.selectedAuthMethod.credentialIdB64u === args.runtime.authBinding.credentialIdB64u
      );
    default: {
      const exhaustive: never = args.runtime.authBinding;
      return exhaustive;
    }
  }
}

function exactAuthorizationMatchesCapability(args: {
  readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
  readonly authorization: ExactEvmFamilyWalletSessionAuthorization;
  readonly nowMs: number;
}): boolean {
  const { capability, authorization } = args;
  const session = authorization.session;
  const operationCredential = authorization.operationCredential;
  const runtime = authorization.runtime;
  const signer = capability.manifest.signer;
  const activation = authorization.selectedAuthority.signerActivations.ecdsa;
  if (!activation) return false;
  if (
    !selectedAuthorityComponentsAreExact({
      selectedAuthority: authorization.selectedAuthority,
      selectedAuthMethod: authorization.selectedAuthMethod,
      walletId: session.walletId,
    })
  ) {
    return false;
  }
  if (
    session.walletId !== signer.walletId ||
    session.authorityId !== authorization.selectedAuthority.authorityId ||
    session.authMethodId !== authorization.selectedAuthMethod.walletAuthMethodId ||
    session.authorityDigestB64u !== authorization.selectedAuthority.authorityDigestB64u ||
    session.authorityRevocationEpoch !== authorization.selectedAuthority.revocationEpoch ||
    signer.authority.walletId !== authorization.selectedAuthority.walletId ||
    signer.authority.walletAuthMethodId !== authorization.selectedAuthMethod.walletAuthMethodId ||
    session.authorizationId.trim().length === 0 ||
    session.quotaId.trim().length === 0 ||
    operationCredential.walletSessionId.trim().length === 0 ||
    operationCredential.token.trim().length === 0 ||
    runtime.walletId !== session.walletId ||
    !selectedAuthMethodMatchesRuntime({
      selectedAuthMethod: authorization.selectedAuthMethod,
      runtime,
    }) ||
    !mpcMaterialActivationRefsEqual(
      runtime.materialActivation,
      capability.manifest.activation.materialActivation,
    ) ||
    !mpcMaterialActivationRefsEqual(
      runtime.roleLocalMaterialRef.materialActivation,
      runtime.materialActivation,
    ) ||
    !targetMatchesCapability({ capability, chainTarget: runtime.chainTarget }) ||
    !capabilityAuthorityMatchesRuntime({ capability, runtime }) ||
    !exactEcdsaSubjectMatches({
      session,
      materialActivation: capability.manifest.activation.materialActivation,
    }) ||
    !mpcMaterialActivationRefsEqual(
      activation.materialActivation,
      capability.manifest.activation.materialActivation,
    ) ||
    activation.signer.walletId !== session.walletId ||
    runtime.expiresAtMs <= 0 ||
    runtime.remainingUses <= 0
  ) {
    return false;
  }
  switch (runtime.kind) {
    case 'exact_ecdsa_direct_capability_runtime_v1':
      break;
    case 'exact_ecdsa_sealed_runtime_v1':
      if (
        runtime.sealedRecord.authMethod !== authorization.selectedAuthMethod.kind ||
        runtime.sealedRecord.storeKey.trim().length === 0 ||
        runtime.sealedRecord.thresholdSessionId.trim().length === 0
      ) {
        return false;
      }
      break;
    default: {
      const exhaustive: never = runtime;
      return exhaustive;
    }
  }
  if (session.expiresAtMs <= args.nowMs || runtime.expiresAtMs <= args.nowMs) {
    return false;
  }
  if (
    runtime.keyHandle !== String(capability.material.publicFacts.keyHandle) ||
    runtime.ecdsaThresholdKeyId !== String(capability.material.publicFacts.ecdsaThresholdKeyId) ||
    runtime.thresholdEcdsaPublicKeyB64u !==
      String(capability.material.publicFacts.groupPublicKey33B64u) ||
    !participantIdsMatch(runtime.participantIds, capability.material.publicFacts.participantIds)
  ) {
    return false;
  }
  return true;
}

function isExactPasskeyWalletSessionRuntime(
  runtime: ExactEcdsaWalletSessionRuntime,
): runtime is ExactPasskeyWalletSessionRuntime {
  return runtime.authBinding.kind === 'passkey';
}

function isExactEmailOtpWalletSessionRuntime(
  runtime: ExactEcdsaWalletSessionRuntime,
): runtime is ExactEmailOtpWalletSessionRuntime {
  return runtime.authBinding.kind === 'email_otp';
}

function buildExactAuthorizationObject(
  input: BuildExactEvmFamilyWalletSessionAuthorizationInput,
): ExactEvmFamilyWalletSessionAuthorization {
  if (isExactPasskeyWalletSessionRuntime(input.runtime)) {
    if (input.selected.authMethod.kind !== 'passkey') {
      throw new Error('Exact EVM-family Wallet Session authorization auth method is invalid');
    }
    return {
      kind: 'exact_evm_family_wallet_session_authorization_v1',
      selectedAuthority: input.selected.authority,
      selectedAuthMethod: input.selected.authMethod,
      session: input.session,
      operationCredential: input.operationCredential,
      runtime: input.runtime,
    };
  }
  if (isExactEmailOtpWalletSessionRuntime(input.runtime)) {
    if (input.selected.authMethod.kind !== 'email_otp') {
      throw new Error('Exact EVM-family Wallet Session authorization auth method is invalid');
    }
    return {
      kind: 'exact_evm_family_wallet_session_authorization_v1',
      selectedAuthority: input.selected.authority,
      selectedAuthMethod: input.selected.authMethod,
      session: input.session,
      operationCredential: input.operationCredential,
      runtime: input.runtime,
    };
  }
  throw new Error('Exact EVM-family Wallet Session authorization runtime is invalid');
}

function directRuntimeAuthBinding(
  authority: WalletAuthAuthority,
): ExactEcdsaSealedRuntimeAuthBinding {
  if (isPasskeyWalletAuthAuthority(authority)) {
    return {
      kind: 'passkey',
      rpId: String(authority.verifier.rpId),
      credentialIdB64u: String(authority.factor.credentialIdB64u),
    };
  }
  if (isEmailOtpWalletAuthAuthority(authority)) {
    return {
      kind: 'email_otp',
      providerSubjectId: String(authority.factor.providerUserId),
      emailHashHex: String(authority.verifier.emailHashHex),
      emailOtpAuthority: authority,
    };
  }
  const exhaustive: never = authority;
  return exhaustive;
}

export function buildExactEcdsaDirectCapabilityRuntime(args: {
  readonly runtime: ExactEcdsaCapabilityRuntime;
  readonly authority: WalletAuthAuthority;
  readonly status: ActiveWalletSessionQuotaStatusV1;
}): ExactEcdsaDirectCapabilityRuntime {
  if (
    !Number.isSafeInteger(args.status.expiresAtMs) ||
    args.status.expiresAtMs <= 0 ||
    !Number.isSafeInteger(args.status.remainingUses) ||
    args.status.remainingUses <= 0
  ) {
    throw new Error('Exact ECDSA direct capability requires an active quota');
  }
  return {
    kind: 'exact_ecdsa_direct_capability_runtime_v1',
    walletId: args.runtime.walletId,
    chainTarget: args.runtime.chainTarget,
    materialActivation: args.runtime.materialActivation,
    normalSigning: args.runtime.normalSigning,
    relayerUrl: args.runtime.relayerUrl,
    relayerKeyId: args.runtime.relayerKeyId,
    clientVerifyingPublicKey33B64u: args.runtime.clientVerifyingPublicKey33B64u,
    participantIds: args.runtime.participantIds,
    ecdsaThresholdKeyId: args.runtime.ecdsaThresholdKeyId,
    thresholdEcdsaPublicKeyB64u: args.runtime.thresholdEcdsaPublicKeyB64u,
    keyHandle: args.runtime.keyHandle,
    runtimePolicyScope: args.runtime.runtimePolicyScope,
    roleLocalMaterialRef: args.runtime.roleLocalMaterialRef,
    authBinding: directRuntimeAuthBinding(args.authority),
    expiresAtMs: args.status.expiresAtMs,
    remainingUses: args.status.remainingUses,
  };
}

function exactEcdsaAuthBindingsMatch(
  left: ExactEcdsaSealedRuntimeAuthBinding,
  right: ExactEcdsaSealedRuntimeAuthBinding,
): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'email_otp':
      return (
        right.kind === 'email_otp' &&
        left.providerSubjectId === right.providerSubjectId &&
        left.emailHashHex === right.emailHashHex &&
        walletAuthAuthoritiesMatch(left.emailOtpAuthority, right.emailOtpAuthority)
      );
    case 'passkey':
      return (
        right.kind === 'passkey' &&
        left.rpId === right.rpId &&
        left.credentialIdB64u === right.credentialIdB64u
      );
    default: {
      const exhaustive: never = left;
      return exhaustive;
    }
  }
}

export function exactEcdsaWalletSessionRuntimesMatch(
  left: ExactEcdsaWalletSessionRuntime,
  right: ExactEcdsaWalletSessionRuntime,
): boolean {
  if (
    left.kind !== right.kind ||
    left.walletId !== right.walletId ||
    !thresholdEcdsaChainTargetsEqual(left.chainTarget, right.chainTarget) ||
    !mpcMaterialActivationRefsEqual(left.materialActivation, right.materialActivation) ||
    left.keyHandle !== right.keyHandle ||
    left.ecdsaThresholdKeyId !== right.ecdsaThresholdKeyId ||
    !exactEcdsaAuthBindingsMatch(left.authBinding, right.authBinding)
  ) {
    return false;
  }
  switch (left.kind) {
    case 'exact_ecdsa_direct_capability_runtime_v1':
      return right.kind === 'exact_ecdsa_direct_capability_runtime_v1';
    case 'exact_ecdsa_sealed_runtime_v1':
      return (
        right.kind === 'exact_ecdsa_sealed_runtime_v1' &&
        left.sealedRecord.authMethod === right.sealedRecord.authMethod &&
        left.sealedRecord.storeKey === right.sealedRecord.storeKey &&
        left.sealedRecord.thresholdSessionId === right.sealedRecord.thresholdSessionId
      );
    default: {
      const exhaustive: never = left;
      return exhaustive;
    }
  }
}

export function buildExactEvmFamilyWalletSessionAuthorization(
  input: BuildExactEvmFamilyWalletSessionAuthorizationInput,
): ExactEvmFamilyWalletSessionAuthorization {
  const walletId = input.session.walletId;
  if (!Number.isSafeInteger(input.nowMs) || input.nowMs < 0) {
    throw new Error('Exact EVM-family Wallet Session authorization requires a valid timestamp');
  }
  if (
    !selectedAuthorityComponentsAreExact({
      selectedAuthority: input.selected.authority,
      selectedAuthMethod: input.selected.authMethod,
      walletId,
    }) ||
    input.selected.selection.walletId !== walletId ||
    input.selected.selection.walletAuthMethodId !== input.selected.authMethod.walletAuthMethodId ||
    input.selected.selection.lockState !== 'unlocked'
  ) {
    throw new Error('Exact EVM-family Wallet Session authorization selected authority is invalid');
  }
  const authorization = buildExactAuthorizationObject(input);
  if (
    !exactAuthorizationMatchesCapability({
      capability: input.capability,
      authorization,
      nowMs: input.nowMs,
    })
  ) {
    throw new Error('Exact EVM-family Wallet Session authorization identity is inconsistent');
  }
  return authorization;
}

export function authorizeEvmFamilyEcdsaSigningCapability(input: {
  readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
  readonly authorization: ExactEvmFamilyWalletSessionAuthorization;
  readonly nowMs: number;
}): AuthorizedEvmFamilyEcdsaSigningCapability {
  if (
    !exactAuthorizationMatchesCapability({
      capability: input.capability,
      authorization: input.authorization,
      nowMs: input.nowMs,
    })
  ) {
    throw new Error(
      'Exact Wallet Session authorization does not bind the ECDSA signing capability',
    );
  }
  return {
    kind: 'authorized_evm_family_ecdsa_signing_capability',
    capability: input.capability,
    authorization: input.authorization,
  };
}

export async function buildCanonicalEvmFamilyEcdsaSigningCapability(input: {
  readonly authority: WalletAuthAuthority;
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly material: PersistedEcdsaRoleLocalMaterial;
}): Promise<CanonicalEvmFamilyEcdsaSigningCapability> {
  const signer = input.manifest.signer;
  const registeredPublicFacts = signer.registeredPublicFacts;
  const materialPublicFacts = input.material.publicFacts;
  const authorityRef = await walletAuthAuthorityRef({ authority: input.authority });
  if (
    authorityRef.authorityDigest !== signer.authority.authorityDigest ||
    authorityRef.walletId !== signer.walletId ||
    input.material.authority.walletId !== signer.walletId ||
    input.material.authority.authorityDigest !== signer.authority.authorityDigest ||
    !mpcMaterialActivationRefsEqual(
      input.material.materialActivation,
      input.manifest.activation.materialActivation,
    ) ||
    materialPublicFacts.walletId !== signer.walletId ||
    materialPublicFacts.keyHandle !== registeredPublicFacts.keyHandle ||
    String(materialPublicFacts.groupPublicKey33B64u) !==
      String(registeredPublicFacts.publicKeyB64u) ||
    materialPublicFacts.ethereumAddress !== registeredPublicFacts.thresholdOwnerAddress ||
    materialPublicFacts.participantIds.length !== registeredPublicFacts.participantIds.length ||
    materialPublicFacts.participantIds.some(
      (participantId, index) => participantId !== registeredPublicFacts.participantIds[index],
    )
  ) {
    throw new Error('Canonical EVM-family ECDSA signing capability identity is inconsistent');
  }
  return {
    kind: 'canonical_evm_family_ecdsa_signing_capability',
    authority: input.authority,
    manifest: input.manifest,
    material: input.material,
  };
}
