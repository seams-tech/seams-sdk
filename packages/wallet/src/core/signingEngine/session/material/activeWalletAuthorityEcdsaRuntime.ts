import { IndexedDBManager } from '@/core/indexedDB';
import {
  walletSessionAuthorizations,
  type ActiveWalletSessionV1,
  type WalletSessionOperationCredentialV1,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
  type WalletAuthorityId,
  type WalletAuthMethodId,
  type WalletId,
} from '@shared/utils/domainIds';
import { base64UrlDecode } from '@shared/utils/base64';
import { alphabetizeStringify } from '@shared/utils/digests';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  isActiveEcdsaWalletAuthorityV1,
  isCombinedWalletSignerActivationSetV1,
  type ActiveWalletAuthorityV1,
  type ActiveCombinedWalletAuthorityV1,
  type ActiveEcdsaWalletAuthorityV1,
  type WalletEcdsaSignerActivationV1,
} from '@shared/authorization/walletAuthority';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import type {
  WalletAuthorityLinkedSignerMaterialRecordV1,
  WalletAuthoritySignerMaterialRecordV1,
  WalletSelectionRecordV1,
} from '@/core/indexedDB/passkeyClientDB.types';
import type { WalletCapabilitySubjectV1 } from '@shared/device-linking/contracts';
import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildPasskeyEcdsaAuthBinding,
  buildResolvedEvmFamilyEcdsaKey,
  buildVerifiedEcdsaPublicFacts,
  deriveEvmFamilyEcdsaKeyHandle,
  toRpId,
  toThresholdOwnerAddress,
  type EvmFamilyEcdsaKeyIdentity,
  type PasskeyEcdsaAuthBinding,
  type ResolvedEvmFamilyEcdsaKey,
  type VerifiedEcdsaPublicFacts,
} from '../identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';
import type { ActiveWalletAuthMethodV2 } from '../identity/ownerLaneScope';
import {
  resolveLinkedEcdsaHolderRuntimeV1,
  type LinkedEcdsaHolderRuntimeV1,
} from './linkedEcdsaHolderRuntime';
import { bytesToHex } from '@/core/signingEngine/chains/evm/bytes';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { computeEcdsaDerivationRoleLocalRelayerKeyId } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';

type ActiveWalletAuthorityEcdsaAuth =
  | {
      readonly auth: Extract<SigningLaneAuthBinding, { readonly kind: 'passkey' }>;
      readonly factorAuthority: PasskeyWalletAuthAuthority;
      readonly resolvedKey: ResolvedEvmFamilyEcdsaKey<PasskeyEcdsaAuthBinding>;
    }
  | {
      readonly auth: Extract<SigningLaneAuthBinding, { readonly kind: 'email_otp' }>;
      readonly factorAuthority: EmailOtpWalletAuthAuthority;
      readonly resolvedKey?: never;
    };

type ActiveWalletAuthorityEcdsaProjectionAuth =
  | {
      readonly auth: Extract<SigningLaneAuthBinding, { readonly kind: 'passkey' }>;
      readonly resolvedKey: ResolvedEvmFamilyEcdsaKey<PasskeyEcdsaAuthBinding>;
    }
  | {
      readonly auth: Extract<SigningLaneAuthBinding, { readonly kind: 'email_otp' }>;
      readonly resolvedKey?: never;
    };

export type ActiveWalletAuthorityEcdsaRuntimeV1 = ActiveWalletAuthorityEcdsaAuth & {
  readonly kind: 'active_wallet_authority_ecdsa_runtime_v1';
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authorityDigestB64u: ActiveWalletAuthorityV1['authorityDigestB64u'];
  readonly factorAuthorityRef: WalletAuthAuthorityRef;
  readonly authorityRevocationEpoch: number;
  readonly walletSessionId: WalletSessionOperationCredentialV1['walletSessionId'];
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly session: ActiveWalletSessionV1;
  readonly requiredCapability: Extract<
    WalletCapabilitySubjectV1,
    { readonly kind: 'sign' | 'export_keys' }
  >['kind'];
  readonly materialActivation: MpcMaterialActivationRef;
  readonly ecdsaThresholdKeyId: string;
  readonly relayerKeyId: string;
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: ActiveWalletAuthMethodV2;
  readonly holderRuntime: LinkedEcdsaHolderRuntimeV1;
  readonly normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  readonly key: EvmFamilyEcdsaKeyIdentity;
  readonly publicFacts: VerifiedEcdsaPublicFacts;
};

export type ActiveWalletAuthorityEcdsaSigningAuthPlan = {
  readonly kind: 'active_wallet_authority';
  readonly method: ActiveWalletAuthorityEcdsaRuntimeV1['auth']['kind'];
  readonly accountId: string;
  readonly intent: 'transaction_sign';
  readonly curve: 'ecdsa';
  readonly walletSessionId: WalletSessionOperationCredentialV1['walletSessionId'];
  readonly authorityId: WalletAuthorityId;
  readonly authMethodId: WalletAuthMethodId;
  readonly expiresAtMs: number;
  readonly thresholdSessionId?: never;
  readonly retention?: never;
  readonly remainingUses?: never;
};

export type ActiveWalletAuthorityEcdsaLaneProjectionV1 =
  ActiveWalletAuthorityEcdsaProjectionAuth & {
    readonly kind: 'active_wallet_authority_ecdsa_lane_projection_v1';
    readonly source: 'active_wallet_authority';
    readonly chainTarget: ThresholdEcdsaChainTarget;
    readonly runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
    readonly key: EvmFamilyEcdsaKeyIdentity;
    readonly materialActivation: MpcMaterialActivationRef;
    readonly publicFacts: VerifiedEcdsaPublicFacts;
    readonly state: 'deferred';
    readonly authorizationState: 'authorization_required';
  };

export type ActiveWalletAuthorityEcdsaRuntimeBlockReason =
  | 'missing_selected_authority'
  | 'invalid_selected_authority'
  | 'wallet_locked'
  | 'auth_method_inactive'
  | 'authority_inactive'
  | 'authority_identity_mismatch'
  | 'missing_wallet_session'
  | 'wallet_session_inactive'
  | 'wallet_session_expired'
  | 'wallet_session_identity_mismatch'
  | 'wallet_session_capability_mismatch'
  | 'missing_ecdsa_signer'
  | 'missing_holder_runtime'
  | 'holder_runtime_identity_mismatch'
  | 'normal_signing_identity_mismatch'
  | 'invalid_public_facts'
  | 'persistence_unavailable';

export type ActiveWalletAuthorityEcdsaRuntimeResolution =
  | {
      readonly kind: 'resolved';
      readonly runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
      readonly lane: ActiveWalletAuthorityEcdsaLaneProjectionV1 | null;
      readonly reason?: never;
      readonly message?: never;
    }
  | {
      readonly kind: 'blocked';
      readonly reason: ActiveWalletAuthorityEcdsaRuntimeBlockReason;
      readonly message?: string;
      readonly runtime?: never;
      readonly lane?: never;
    };

export type ResolveActiveWalletAuthorityEcdsaRuntimeV1Input = {
  readonly walletId: WalletId | string;
  readonly chainTarget?: ThresholdEcdsaChainTarget;
  readonly requiredCapability?: 'sign' | 'export_keys';
  readonly materialActivation?: MpcMaterialActivationRef;
  readonly nowMs?: number;
};

type ResolvedSelectedWalletAuthority = {
  readonly selection: WalletSelectionRecordV1;
  readonly authMethod: ActiveWalletAuthMethodV2;
  readonly authority: ActiveWalletAuthorityV1;
  readonly signerMaterials: readonly WalletAuthoritySignerMaterialRecordV1[];
};

type WalletAuthorityLinkedEcdsaSignerMaterialRecord = Extract<
  WalletAuthorityLinkedSignerMaterialRecordV1,
  { readonly keyFamily: 'ecdsa_secp256k1' }
>;

type EcdsaAuthoritySigner = WalletEcdsaSignerActivationV1['signer'];

type ActiveEcdsaSignerActivationSet =
  | ActiveEcdsaWalletAuthorityV1['signerActivations']
  | ActiveCombinedWalletAuthorityV1['signerActivations'];

function blocked(
  reason: ActiveWalletAuthorityEcdsaRuntimeBlockReason,
  message?: string,
): ActiveWalletAuthorityEcdsaRuntimeResolution {
  return message ? { kind: 'blocked', reason, message } : { kind: 'blocked', reason };
}

function activeAuthorityEcdsaActivation(
  authority: ActiveWalletAuthorityV1,
): ActiveEcdsaSignerActivationSet | null {
  if (isActiveEcdsaWalletAuthorityV1(authority)) return authority.signerActivations;
  if (isCombinedWalletSignerActivationSetV1(authority.signerActivations)) {
    return authority.signerActivations;
  }
  return null;
}

function exactAuthorityResolution(
  value: Awaited<ReturnType<typeof IndexedDBManager.resolveSelectedWalletAuthority>>,
): ResolvedSelectedWalletAuthority | ActiveWalletAuthorityEcdsaRuntimeResolution {
  if (value.kind !== 'resolved') {
    switch (value.kind) {
      case 'missing_selection':
        return blocked('missing_selected_authority');
      case 'missing_auth_method':
      case 'missing_authority':
      case 'integrity_error':
        return blocked('invalid_selected_authority');
      default: {
        const exhaustive: never = value;
        return exhaustive;
      }
    }
  }
  if (
    value.selection.walletId !== value.authMethod.walletId ||
    value.selection.walletAuthMethodId !== value.authMethod.walletAuthMethodId ||
    value.authMethod.walletAuthorityId !== value.authority.authorityId ||
    value.authority.walletId !== value.selection.walletId
  ) {
    return blocked('authority_identity_mismatch');
  }
  if (value.selection.lockState !== 'unlocked') return blocked('wallet_locked');
  if (value.authMethod.status !== 'active') return blocked('auth_method_inactive');
  if (value.authority.state !== 'active') return blocked('authority_inactive');
  return {
    selection: value.selection,
    authMethod: value.authMethod,
    authority: value.authority,
    signerMaterials: value.signerMaterials,
  };
}

function exactEcdsaSignerMaterial(args: {
  readonly materials: readonly WalletAuthoritySignerMaterialRecordV1[];
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: ActiveWalletAuthMethodV2;
  readonly materialActivation: MpcMaterialActivationRef;
}): WalletAuthorityLinkedEcdsaSignerMaterialRecord | null {
  const matches = args.materials.filter(
    (material): material is WalletAuthorityLinkedEcdsaSignerMaterialRecord =>
      material.kind === 'wallet_authority_linked_signer_material_v1' &&
      material.keyFamily === 'ecdsa_secp256k1' &&
      material.authorityId === args.authority.authorityId &&
      material.walletAuthMethodId === args.authMethod.walletAuthMethodId &&
      material.activationId === args.materialActivation.activationId &&
      mpcMaterialActivationRefsEqual(material.materialActivation, args.materialActivation),
  );
  const [match] = matches;
  return matches.length === 1 && match ? match : null;
}

function linkedMaterialTargetFactorMatches(args: {
  readonly material: WalletAuthorityLinkedEcdsaSignerMaterialRecord;
  readonly authMethod: ActiveWalletAuthMethodV2;
}): boolean {
  const target = args.material.targetFactor;
  if (target.walletAuthMethodId !== args.authMethod.walletAuthMethodId) return false;
  if (args.authMethod.kind === 'passkey') {
    return (
      target.kind === 'passkey' &&
      target.rpId === args.authMethod.rpId &&
      target.credentialIdB64u === args.authMethod.credentialIdB64u
    );
  }
  return (
    target.kind === 'email_otp' &&
    target.emailHashHex === args.authMethod.emailHashHex &&
    target.registrationAuthorityId === args.authMethod.registrationAuthorityId
  );
}

function exactSessionCapability(args: {
  readonly session: ActiveWalletSessionV1;
  readonly capability: 'sign' | 'export_keys';
  readonly materialActivation: MpcMaterialActivationRef;
}): boolean {
  const matches = args.session.capabilitySubjects.filter(
    (subject) =>
      subject.kind === args.capability &&
      subject.keyFamily === 'ecdsa_secp256k1' &&
      mpcMaterialActivationRefsEqual(subject.materialActivation, args.materialActivation),
  );
  return matches.length === 1;
}

function exactNormalSigningMaterialActivation(
  normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1,
): MpcMaterialActivationRef | null {
  try {
    return routerAbMpcMaterialActivationRefFromWire(normalSigning.scope.material_activation);
  } catch {
    return null;
  }
}

function normalSigningAddress(
  normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1,
): string | null {
  try {
    return bytesToHex(base64UrlDecode(normalSigning.scope.public_identity.ethereum_address20_b64u));
  } catch {
    return null;
  }
}

function exactHolderRuntime(args: {
  readonly walletId: WalletId;
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: ActiveWalletAuthMethodV2;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly ecdsaThresholdKeyId: string;
  readonly material: WalletAuthorityLinkedEcdsaSignerMaterialRecord;
}): LinkedEcdsaHolderRuntimeV1 | null {
  const runtime = resolveLinkedEcdsaHolderRuntimeV1({
    walletId: args.walletId,
    materialActivation: args.materialActivation,
  });
  if (!runtime) return null;
  if (
    runtime.walletId !== args.walletId ||
    runtime.authorityId !== args.authority.authorityId ||
    runtime.walletAuthMethodId !== args.authMethod.walletAuthMethodId ||
    runtime.factorAuthority.walletId !== args.walletId ||
    runtime.factorAuthority.bindingId !== args.authMethod.walletAuthMethodId ||
    runtime.ecdsaThresholdKeyId !== args.ecdsaThresholdKeyId ||
    !mpcMaterialActivationRefsEqual(runtime.materialActivation, args.materialActivation) ||
    !linkedMaterialTargetFactorMatches({ material: args.material, authMethod: args.authMethod }) ||
    alphabetizeStringify(runtime.activationReceipt) !==
      alphabetizeStringify(args.material.publicFacts.activationReceipt)
  ) {
    return null;
  }
  return runtime;
}

async function buildActiveRuntime(args: {
  readonly selected: ResolvedSelectedWalletAuthority;
  readonly session: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly requiredCapability: 'sign' | 'export_keys';
  readonly signer: EcdsaAuthoritySigner;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly holderRuntime: LinkedEcdsaHolderRuntimeV1;
  readonly factorAuthority: WalletAuthAuthority;
}): Promise<ActiveWalletAuthorityEcdsaRuntimeV1 | ActiveWalletAuthorityEcdsaRuntimeResolution> {
  const normalSigning = args.holderRuntime.activationReceipt.normalSigning;
  const normalScope = normalSigning.scope;
  const normalActivation = exactNormalSigningMaterialActivation(normalSigning);
  const normalAddress = normalSigningAddress(normalSigning);
  if (
    !normalActivation ||
    !normalAddress ||
    !mpcMaterialActivationRefsEqual(normalActivation, args.materialActivation) ||
    args.signer.walletId !== args.selected.authority.walletId ||
    normalScope.wallet_id !== String(args.selected.authority.walletId) ||
    normalScope.ecdsa_threshold_key_id !== String(args.holderRuntime.ecdsaThresholdKeyId) ||
    normalScope.public_identity.threshold_public_key33_b64u !==
      String(args.signer.thresholdPublicKey33B64u) ||
    normalAddress.toLowerCase() !== String(args.signer.evmAddress).trim().toLowerCase() ||
    String(args.holderRuntime.activationReceipt.thresholdPublicKey33B64u) !==
      String(normalScope.public_identity.threshold_public_key33_b64u) ||
    String(args.holderRuntime.activationReceipt.thresholdEthereumAddress20B64u) !==
      String(normalScope.public_identity.ethereum_address20_b64u)
  ) {
    return blocked('normal_signing_identity_mismatch');
  }
  let key: EvmFamilyEcdsaKeyIdentity;
  let publicFacts: VerifiedEcdsaPublicFacts;
  let relayerKeyId: string;
  let keyHandle;
  try {
    keyHandle = await deriveEvmFamilyEcdsaKeyHandle({
      ecdsaThresholdKeyId: normalScope.ecdsa_threshold_key_id,
      signingRootId: normalScope.signing_root_id,
      signingRootVersion: normalScope.signing_root_version,
    });
    const thresholdOwnerAddress = toThresholdOwnerAddress(args.signer.evmAddress);
    key = buildBaseEvmFamilyEcdsaKeyIdentity({
      walletId: args.selected.authority.walletId,
      ecdsaThresholdKeyId: normalScope.ecdsa_threshold_key_id,
      signingRootId: normalScope.signing_root_id,
      signingRootVersion: normalScope.signing_root_version,
      participantIds: [1, 2],
      thresholdOwnerAddress,
    });
    publicFacts = buildVerifiedEcdsaPublicFacts({
      keyHandle,
      publicKeyB64u: normalScope.public_identity.threshold_public_key33_b64u,
      participantIds: [1, 2],
      thresholdOwnerAddress,
    });
    relayerKeyId = await computeEcdsaDerivationRoleLocalRelayerKeyId({
      walletId: String(key.walletId),
      signingRootId: String(key.signingRootId),
      signingRootVersion: String(key.signingRootVersion),
    });
  } catch (error: unknown) {
    return blocked('invalid_public_facts', error instanceof Error ? error.message : String(error));
  }
  if (key.ecdsaThresholdKeyId !== args.holderRuntime.ecdsaThresholdKeyId) {
    return blocked('normal_signing_identity_mismatch');
  }
  let factorAuthorityRef: WalletAuthAuthorityRef;
  try {
    factorAuthorityRef = await walletAuthAuthorityRef({ authority: args.factorAuthority });
  } catch (error: unknown) {
    return blocked(
      'authority_identity_mismatch',
      error instanceof Error ? error.message : String(error),
    );
  }
  if (args.selected.authMethod.kind === 'passkey') {
    const auth = {
      kind: 'passkey' as const,
      rpId: toRpId(args.selected.authMethod.rpId),
      credentialIdB64u: args.selected.authMethod.credentialIdB64u,
    };
    if (
      !isPasskeyWalletAuthAuthority(args.factorAuthority) ||
      args.factorAuthority.walletId !== key.walletId ||
      args.factorAuthority.bindingId !== args.selected.authMethod.walletAuthMethodId ||
      args.factorAuthority.factor.credentialIdB64u !== auth.credentialIdB64u ||
      String(args.factorAuthority.verifier.rpId) !== String(auth.rpId)
    ) {
      return blocked('authority_identity_mismatch');
    }
    const resolvedKey = buildResolvedEvmFamilyEcdsaKey({
      walletId: key.walletId,
      publicFacts,
      authBinding: buildPasskeyEcdsaAuthBinding({
        rpId: auth.rpId,
        credentialIdB64u: auth.credentialIdB64u,
      }),
    });
    return {
      kind: 'active_wallet_authority_ecdsa_runtime_v1',
      walletId: args.selected.authority.walletId,
      authorityId: args.selected.authority.authorityId,
      walletAuthMethodId: args.selected.authMethod.walletAuthMethodId,
      authorityDigestB64u: args.selected.authority.authorityDigestB64u,
      factorAuthorityRef,
      authorityRevocationEpoch: args.selected.authority.revocationEpoch,
      walletSessionId: args.operationCredential.walletSessionId,
      operationCredential: args.operationCredential,
      session: args.session,
      requiredCapability: args.requiredCapability,
      materialActivation: args.materialActivation,
      ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
      relayerKeyId,
      authority: args.selected.authority,
      authMethod: args.selected.authMethod,
      holderRuntime: args.holderRuntime,
      normalSigning,
      key,
      publicFacts,
      auth,
      factorAuthority: args.factorAuthority,
      resolvedKey,
    };
  }
  if (
    !isEmailOtpWalletAuthAuthority(args.factorAuthority) ||
    args.factorAuthority.walletId !== key.walletId ||
    args.factorAuthority.bindingId !== args.selected.authMethod.walletAuthMethodId ||
    args.factorAuthority.verifier.emailHashHex !== args.selected.authMethod.emailHashHex
  ) {
    return blocked('authority_identity_mismatch');
  }
  const auth = {
    kind: 'email_otp' as const,
    providerSubjectId: String(args.factorAuthority.factor.providerUserId),
  };
  return {
    kind: 'active_wallet_authority_ecdsa_runtime_v1',
    walletId: args.selected.authority.walletId,
    authorityId: args.selected.authority.authorityId,
    walletAuthMethodId: args.selected.authMethod.walletAuthMethodId,
    authorityDigestB64u: args.selected.authority.authorityDigestB64u,
    factorAuthorityRef,
    authorityRevocationEpoch: args.selected.authority.revocationEpoch,
    walletSessionId: args.operationCredential.walletSessionId,
    operationCredential: args.operationCredential,
    session: args.session,
    requiredCapability: args.requiredCapability,
    materialActivation: args.materialActivation,
    ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
    relayerKeyId,
    authority: args.selected.authority,
    authMethod: args.selected.authMethod,
    holderRuntime: args.holderRuntime,
    normalSigning,
    key,
    publicFacts,
    auth,
    factorAuthority: args.factorAuthority,
  };
}

function projectActiveRuntime(args: {
  readonly runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
  readonly chainTarget?: ThresholdEcdsaChainTarget;
}): ActiveWalletAuthorityEcdsaLaneProjectionV1 | null {
  if (!args.chainTarget) return null;
  if (args.runtime.auth.kind === 'passkey') {
    if (!args.runtime.resolvedKey) return null;
    return {
      kind: 'active_wallet_authority_ecdsa_lane_projection_v1',
      source: 'active_wallet_authority',
      chainTarget: args.chainTarget,
      runtime: args.runtime,
      key: args.runtime.key,
      materialActivation: args.runtime.materialActivation,
      publicFacts: args.runtime.publicFacts,
      state: 'deferred',
      authorizationState: 'authorization_required',
      auth: args.runtime.auth,
      resolvedKey: args.runtime.resolvedKey,
    };
  }
  return {
    kind: 'active_wallet_authority_ecdsa_lane_projection_v1',
    source: 'active_wallet_authority',
    chainTarget: args.chainTarget,
    runtime: args.runtime,
    key: args.runtime.key,
    materialActivation: args.runtime.materialActivation,
    publicFacts: args.runtime.publicFacts,
    state: 'deferred',
    authorizationState: 'authorization_required',
    auth: args.runtime.auth,
  };
}

export async function resolveActiveWalletAuthorityEcdsaRuntimeV1(
  args: ResolveActiveWalletAuthorityEcdsaRuntimeV1Input,
): Promise<ActiveWalletAuthorityEcdsaRuntimeResolution> {
  const requiredCapability = args.requiredCapability || 'sign';
  const nowMs = Math.floor(Number(args.nowMs) || Date.now());
  let walletId: WalletId;
  try {
    walletId = toWalletId(args.walletId);
  } catch (error: unknown) {
    return blocked(
      'invalid_selected_authority',
      error instanceof Error ? error.message : String(error),
    );
  }
  let selectedResult: Awaited<ReturnType<typeof IndexedDBManager.resolveSelectedWalletAuthority>>;
  try {
    selectedResult = await IndexedDBManager.resolveSelectedWalletAuthority(String(walletId));
  } catch (error: unknown) {
    return blocked(
      'persistence_unavailable',
      error instanceof Error ? error.message : String(error),
    );
  }
  const selected = exactAuthorityResolution(selectedResult);
  if ('kind' in selected) return selected;
  const ecdsaActivation = activeAuthorityEcdsaActivation(selected.authority);
  if (!ecdsaActivation) return blocked('missing_ecdsa_signer');
  const signer = ecdsaActivation.ecdsa.signer;
  const materialActivation = ecdsaActivation.ecdsa.materialActivation;
  if (
    args.materialActivation &&
    !mpcMaterialActivationRefsEqual(args.materialActivation, materialActivation)
  ) {
    return blocked('authority_identity_mismatch');
  }
  const linkedMaterial = exactEcdsaSignerMaterial({
    materials: selected.signerMaterials,
    authority: selected.authority,
    authMethod: selected.authMethod,
    materialActivation,
  });
  if (
    !linkedMaterial ||
    !linkedMaterialTargetFactorMatches({
      material: linkedMaterial,
      authMethod: selected.authMethod,
    })
  ) {
    return blocked('missing_holder_runtime');
  }
  if (
    String(linkedMaterial.publicFacts.ecdsaThresholdKeyId) !==
    String(linkedMaterial.ecdsaThresholdKeyId)
  ) {
    return blocked('holder_runtime_identity_mismatch');
  }
  const holderRuntime = exactHolderRuntime({
    walletId,
    authority: selected.authority,
    authMethod: selected.authMethod,
    materialActivation,
    ecdsaThresholdKeyId: String(linkedMaterial.ecdsaThresholdKeyId),
    material: linkedMaterial,
  });
  if (!holderRuntime) return blocked('holder_runtime_identity_mismatch');
  let sessionWithCredential: Awaited<
    ReturnType<typeof walletSessionAuthorizations.readExactWithOperationCredential>
  >;
  try {
    sessionWithCredential = await walletSessionAuthorizations.readExactWithOperationCredential({
      walletId,
      authorityId: selected.authority.authorityId,
      authMethodId: selected.authMethod.walletAuthMethodId,
    });
  } catch (error: unknown) {
    return blocked(
      'persistence_unavailable',
      error instanceof Error ? error.message : String(error),
    );
  }
  if (!sessionWithCredential) return blocked('missing_wallet_session');
  const session = sessionWithCredential.record;
  const operationCredential = sessionWithCredential.operationCredential;
  if (session.expiresAtMs <= nowMs) return blocked('wallet_session_expired');
  if (
    session.walletId !== walletId ||
    session.authorityId !== selected.authority.authorityId ||
    session.authMethodId !== selected.authMethod.walletAuthMethodId ||
    session.authorityDigestB64u !== selected.authority.authorityDigestB64u ||
    session.authorityRevocationEpoch !== selected.authority.revocationEpoch ||
    operationCredential.walletSessionId.length === 0 ||
    operationCredential.token.trim().length === 0
  ) {
    return blocked('wallet_session_identity_mismatch');
  }
  if (!exactSessionCapability({ session, capability: requiredCapability, materialActivation })) {
    return blocked('wallet_session_capability_mismatch');
  }
  const factorAuthority = holderRuntime.factorAuthority;
  const runtime = await buildActiveRuntime({
    selected,
    session,
    operationCredential,
    requiredCapability,
    signer,
    materialActivation,
    holderRuntime,
    factorAuthority,
  });
  if (runtime.kind !== 'active_wallet_authority_ecdsa_runtime_v1') return runtime;
  return {
    kind: 'resolved',
    runtime,
    lane: projectActiveRuntime({ runtime, chainTarget: args.chainTarget }),
  };
}
