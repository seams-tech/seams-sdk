import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
  WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  assertMatchingVerifiedEcdsaPublicFacts,
  deriveEvmFamilyKeyFingerprintFromPublicFacts,
  type EvmFamilyEcdsaKeyIdentity,
  type ThresholdEcdsaSessionId,
  type VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type {
  AvailableEcdsaSigningLane,
  ActiveExecutionBundleEcdsaSigningLane,
  ConcreteAvailableEcdsaSigningLane,
} from '../../session/availability/availableSigningLanes';
import { isConcreteAvailableSigningLane } from '../../session/availability/availableSigningLanes';
import type { DeviceLinkingHolderSigningMaterialHandleV1 } from '../../session/lanes/linkedDevicePorts';
import type { DeviceLinkingHolderSigningMaterialPortV1 } from '../../session/lanes/linkedDevicePorts';
import type { LinkedDeviceWalletSessionTokenReadResultV1 } from '@/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore';
import type { EcdsaAdditiveLaneJobV1 } from '@shared/signing-lanes/rotation';
import type { LinkedDeviceEcdsaNormalSigningScopeV1 } from '@shared/signing-lanes/linkedEcdsaScope';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  buildPersistedEcdsaRoleLocalMaterial,
  type PersistedEcdsaRoleLocalMaterial,
} from '../../session/material/ecdsaRoleLocalMaterialResolver';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { EvmFamilySigningTarget } from '../signEvmFamily/types';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../../session/material/ecdsaSigningCapability';
import type {
  RouterAbEcdsaDerivationNormalSigningStateV1,
  RouterAbEcdsaDerivationPublicCapabilityV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { CanonicalEvmFamilyEcdsaSigningCapability } from '../../session/material/ecdsaSigningCapability';
import { resolveActiveEcdsaCapabilityRuntime } from '../../session/material/activeEcdsaCapabilityRuntime';

export type EcdsaExportMaterialAvailability =
  | { kind: 'loaded_worker_material' }
  | { kind: 'sealed_worker_material' }
  | { kind: 'material_pending'; reason: 'email_otp_route_auth' };

export type ActiveLinkedDeviceEcdsaExportMaterial = {
  kind: 'active_execution_bundle';
  job: EcdsaAdditiveLaneJobV1;
  materialActivation: ActiveExecutionBundleEcdsaSigningLane['materialActivation'];
  laneScope: LinkedDeviceEcdsaNormalSigningScopeV1;
  holderHandle: Extract<
    DeviceLinkingHolderSigningMaterialHandleV1,
    { readonly keyFamily: 'ecdsa_secp256k1' }
  >;
  holderMaterial: DeviceLinkingHolderSigningMaterialPortV1;
  walletSession: Extract<LinkedDeviceWalletSessionTokenReadResultV1, { readonly kind: 'found' }>;
};

/** Internal selection result for an activated linked lane. Public export results remain ordinary. */
export type ActiveLinkedDeviceEcdsaExportLane = {
  curve: 'ecdsa';
  source: 'active_execution_bundle';
  laneIdentity: ExactEcdsaSigningLaneIdentity;
  laneScope: LinkedDeviceEcdsaNormalSigningScopeV1;
  key: EvmFamilyEcdsaKeyIdentity;
  publicFacts: VerifiedEcdsaPublicFacts;
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: 'email_otp' | 'passkey';
  material: ActiveLinkedDeviceEcdsaExportMaterial;
  state: 'ready';
  authorizationState: 'authorized';
  authorization: ActiveWalletSessionAuthorizationProjection;
  capability?: never;
};

type ExactEcdsaExportLaneBase = {
  curve: 'ecdsa';
  laneIdentity: ExactEcdsaSigningLaneIdentity;
  key: EvmFamilyEcdsaKeyIdentity;
  publicFacts: VerifiedEcdsaPublicFacts;
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: 'email_otp' | 'passkey';
  material: EcdsaExportMaterialAvailability;
  state: Exclude<ConcreteAvailableEcdsaSigningLane['state'], 'expired' | 'exhausted'>;
  source: 'canonical_capability';
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  ecdsaThresholdKeyId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  participantIds?: never;
  thresholdOwnerAddress?: never;
  publicReauthAuthority?: never;
};

export type ExactEcdsaExportLane =
  | (ExactEcdsaExportLaneBase & {
      authorizationState: 'authorized';
      authorization: ActiveEvmFamilyWalletSessionAuthorization;
    })
  | (ExactEcdsaExportLaneBase & {
      authorizationState: 'authorization_required';
      authorization?: never;
    });

export type EcdsaExportSessionStoreDeps = {
  exportArtifactsByLane: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
  relayerUrl: string;
};

export type EmailOtpEcdsaExportAuthLane = Extract<
  EmailOtpSigningSessionAuthLane,
  { curve: 'ecdsa' }
>;

type FreshEmailOtpEcdsaOperationExportAuthority = {
  kind: 'fresh_operation_authorization_required';
  authority: EmailOtpWalletAuthAuthority;
};

export type FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready';
  chainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  relayerKeyId: string;
  participantIds: readonly [number, number];
  relayerUrl: string;
  authorization: FreshEmailOtpEcdsaOperationExportAuthority;
  record?: never;
  authLane?: never;
};

export type FreshPasskeyEcdsaExportMaterial = {
  kind: 'fresh_passkey_needs_authorization';
  chainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
  normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  relayerKeyId: string;
  participantIds: readonly [number, number];
  relayerUrl: string;
};

export type EcdsaExportMaterial =
  | ActiveLinkedDeviceEcdsaExportMaterial
  | FreshEmailOtpEcdsaExportMaterial
  | FreshPasskeyEcdsaExportMaterial;

export function ecdsaExportBoundaryChain(
  lane: ExactEcdsaExportLane | ActiveLinkedDeviceEcdsaExportLane,
): 'evm' | 'tempo' {
  return lane.chainTarget.kind;
}

export function ecdsaSigningTargetFromChainTarget(
  chainTarget: ThresholdEcdsaChainTarget,
): EvmFamilySigningTarget {
  return chainTarget;
}

export function isConcreteEcdsaExportLane(
  lane: AvailableEcdsaSigningLane | null | undefined,
): lane is ConcreteAvailableEcdsaSigningLane & {
  source: 'canonical_capability';
} & (
    | {
        authorization: ActiveEvmFamilyWalletSessionAuthorization;
      }
    | {
        authorization?: never;
        auth: ConcreteAvailableEcdsaSigningLane['auth'];
      }
  ) {
  if (
    !lane ||
    lane.curve !== 'ecdsa' ||
    !lane.chainTarget ||
    !isConcreteAvailableSigningLane(lane) ||
    lane.source !== 'canonical_capability' ||
    !String(lane.publicFacts.keyHandle || '').trim()
  ) {
    return false;
  }
  if (lane.authorization) return true;
  return lane.state === 'deferred';
}

export function isConcreteActiveLinkedDeviceEcdsaExportLane(
  lane: AvailableEcdsaSigningLane | null | undefined,
): lane is ActiveExecutionBundleEcdsaSigningLane {
  return (
    lane !== null &&
    lane !== undefined &&
    lane.source === 'active_execution_bundle' &&
    lane.curve === 'ecdsa' &&
    lane.state === 'ready' &&
    lane.authorizationState === 'authorized' &&
    lane.auth.kind !== undefined &&
    lane.materialActivation.activationId === lane.laneIdentity.targetMaterialActivationId &&
    lane.job.targetMaterialActivationId === lane.laneIdentity.targetMaterialActivationId &&
    lane.holderHandle.keyFamily === 'ecdsa_secp256k1'
  );
}

function exactEcdsaParticipantIds(value: readonly number[]): readonly [number, number] {
  if (value.length !== 2) {
    throw new Error('[SigningEngine][ecdsa-export] ECDSA participant set must contain two parties');
  }
  const first = value[0];
  const second = value[1];
  if (
    !Number.isSafeInteger(first) ||
    !Number.isSafeInteger(second) ||
    first <= 0 ||
    second <= 0 ||
    first === second
  ) {
    throw new Error('[SigningEngine][ecdsa-export] ECDSA participant set is invalid');
  }
  return [first, second];
}

export function resolveCanonicalEmailOtpEcdsaExportMaterialForLane(args: {
  deps: EcdsaExportSessionStoreDeps;
  exportLane: ExactEcdsaExportLane;
}): FreshEmailOtpEcdsaExportMaterial {
  const { exportLane } = args;
  const capability = exportLane.capability;
  if (!isEmailOtpWalletAuthAuthority(capability.authority)) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP capability authority mismatch');
  }
  const signer = capability.manifest.signer;
  if (
    signer.walletId !== exportLane.key.walletId ||
    !signer.scope.targetMemberships.some((target) =>
      thresholdEcdsaChainTargetsEqual(target, exportLane.chainTarget),
    )
  ) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP capability target mismatch');
  }
  if (
    exportLane.laneIdentity.auth.kind !== 'email_otp' ||
    exportLane.laneIdentity.auth.providerSubjectId !== capability.authority.factor.providerUserId
  ) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP capability auth mismatch');
  }
  if (
    !mpcMaterialActivationRefsEqual(
      capability.manifest.activation.materialActivation,
      exportLane.laneIdentity.signer.materialActivation,
    )
  ) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP material activation mismatch');
  }
  assertMatchingVerifiedEcdsaPublicFacts({
    expected: exportLane.publicFacts,
    actual: capability.manifest.signer.registeredPublicFacts,
    context: 'canonical Email OTP export lane',
  });
  const materialFacts = capability.material.publicFacts;
  if (
    materialFacts.walletId !== signer.walletId ||
    String(materialFacts.keyHandle) !== String(exportLane.publicFacts.keyHandle) ||
    String(materialFacts.groupPublicKey33B64u) !== String(exportLane.publicFacts.publicKeyB64u) ||
    String(materialFacts.ethereumAddress) !==
      String(exportLane.publicFacts.thresholdOwnerAddress) ||
    materialFacts.participantIds.length !== exportLane.publicFacts.participantIds.length ||
    materialFacts.participantIds.some(
      (participantId, index) => participantId !== exportLane.publicFacts.participantIds[index],
    )
  ) {
    throw new Error('[SigningEngine][ecdsa-export] canonical Email OTP export material mismatch');
  }
  const durable = capability.manifest.durableMaterial;
  const runtimePolicyScope = durable.runtimePolicyScope;
  const relayerUrl = String(args.deps.relayerUrl).trim().replace(/\/+$/g, '');
  if (!runtimePolicyScope) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP runtime policy scope is missing');
  }
  if (!relayerUrl) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP export relayer URL is missing');
  }
  return {
    kind: 'fresh_email_otp_route_auth_ready',
    chainTarget: exportLane.chainTarget,
    publicFacts: exportLane.publicFacts,
    runtimePolicyScope,
    persistedMaterial: capability.material,
    normalSigning: durable.routerAbEcdsaDerivationNormalSigning,
    relayerKeyId: String(durable.roleLocalBinding.relayerKeyId),
    participantIds: exactEcdsaParticipantIds(durable.roleLocalBinding.participantIds),
    relayerUrl,
    authorization: {
      kind: 'fresh_operation_authorization_required',
      authority: capability.authority,
    },
  };
}

export function resolveCanonicalPasskeyEcdsaExportMaterialForLane(args: {
  deps: EcdsaExportSessionStoreDeps;
  exportLane: ExactEcdsaExportLane;
}): FreshPasskeyEcdsaExportMaterial {
  const { exportLane } = args;
  const capability = exportLane.capability;
  if (!isPasskeyWalletAuthAuthority(capability.authority)) {
    throw new Error('[SigningEngine][ecdsa-export] passkey capability authority mismatch');
  }
  const signer = capability.manifest.signer;
  if (
    signer.walletId !== exportLane.key.walletId ||
    !signer.scope.targetMemberships.some((target) =>
      thresholdEcdsaChainTargetsEqual(target, exportLane.chainTarget),
    )
  ) {
    throw new Error('[SigningEngine][ecdsa-export] passkey capability target mismatch');
  }
  if (
    exportLane.laneIdentity.auth.kind !== 'passkey' ||
    exportLane.laneIdentity.auth.credentialIdB64u !== capability.authority.factor.credentialIdB64u
  ) {
    throw new Error('[SigningEngine][ecdsa-export] passkey capability auth mismatch');
  }
  if (
    !mpcMaterialActivationRefsEqual(
      capability.manifest.activation.materialActivation,
      exportLane.laneIdentity.signer.materialActivation,
    )
  ) {
    throw new Error('[SigningEngine][ecdsa-export] passkey material activation mismatch');
  }
  assertMatchingVerifiedEcdsaPublicFacts({
    expected: exportLane.publicFacts,
    actual: signer.registeredPublicFacts,
    context: 'canonical passkey export lane',
  });
  const materialFacts = capability.material.publicFacts;
  if (
    materialFacts.walletId !== signer.walletId ||
    String(materialFacts.keyHandle) !== String(exportLane.publicFacts.keyHandle) ||
    String(materialFacts.groupPublicKey33B64u) !== String(exportLane.publicFacts.publicKeyB64u) ||
    String(materialFacts.ethereumAddress) !==
      String(exportLane.publicFacts.thresholdOwnerAddress) ||
    materialFacts.participantIds.length !== exportLane.publicFacts.participantIds.length ||
    materialFacts.participantIds.some(
      (participantId, index) => participantId !== exportLane.publicFacts.participantIds[index],
    )
  ) {
    throw new Error('[SigningEngine][ecdsa-export] canonical passkey export material mismatch');
  }
  const durable = capability.manifest.durableMaterial;
  const runtimePolicyScope = durable.runtimePolicyScope;
  const relayerUrl = String(args.deps.relayerUrl).trim().replace(/\/+$/g, '');
  if (!runtimePolicyScope) {
    throw new Error('[SigningEngine][ecdsa-export] passkey runtime policy scope is missing');
  }
  if (!relayerUrl) {
    throw new Error('[SigningEngine][ecdsa-export] passkey export relayer URL is missing');
  }
  return {
    kind: 'fresh_passkey_needs_authorization',
    chainTarget: exportLane.chainTarget,
    publicFacts: exportLane.publicFacts,
    runtimePolicyScope,
    publicCapability: durable.roleLocalPublicFacts.publicCapability,
    existingRoleLocalMaterial: capability.material,
    normalSigning: durable.routerAbEcdsaDerivationNormalSigning,
    relayerKeyId: String(durable.roleLocalBinding.relayerKeyId),
    participantIds: exactEcdsaParticipantIds(durable.roleLocalBinding.participantIds),
    relayerUrl,
  };
}

function sealedEmailOtpExportMaterial(args: {
  deps: EcdsaExportSessionStoreDeps;
  exportLane: ExactEcdsaExportLane;
  resolution: Extract<
    Awaited<ReturnType<typeof resolveActiveEcdsaCapabilityRuntime>>,
    { kind: 'resolved' }
  >;
}): FreshEmailOtpEcdsaExportMaterial {
  const { exportLane, resolution } = args;
  if (exportLane.laneIdentity.auth.kind !== 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP runtime auth mismatch');
  }
  if (resolution.runtime.authBinding.kind !== 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP runtime authority mismatch');
  }
  if (
    exportLane.laneIdentity.auth.providerSubjectId !==
    resolution.runtime.authBinding.providerSubjectId
  ) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP runtime auth mismatch');
  }
  if (
    !mpcMaterialActivationRefsEqual(
      resolution.runtime.materialActivation,
      exportLane.laneIdentity.signer.materialActivation,
    )
  ) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP material activation mismatch');
  }
  const runtimePolicyScope = resolution.runtime.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP runtime policy scope is missing');
  }
  const persistedMaterial = buildPersistedEcdsaRoleLocalMaterial({
    authority: resolution.manifest.signer.authority,
    materialActivation: resolution.manifest.activation.materialActivation,
    publicFacts: resolution.manifest.durableMaterial.roleLocalPublicFacts,
  });
  return {
    kind: 'fresh_email_otp_route_auth_ready',
    chainTarget: exportLane.chainTarget,
    publicFacts: exportLane.publicFacts,
    runtimePolicyScope,
    persistedMaterial,
    normalSigning: resolution.runtime.normalSigning,
    relayerKeyId: resolution.runtime.relayerKeyId,
    participantIds: resolution.runtime.participantIds,
    relayerUrl: resolution.runtime.relayerUrl,
    authorization: {
      kind: 'fresh_operation_authorization_required',
      authority: resolution.runtime.authBinding.emailOtpAuthority,
    },
  };
}

export async function resolveFreshEmailOtpEcdsaExportMaterialForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): Promise<FreshEmailOtpEcdsaExportMaterial> {
  if (exportLane.authMethod !== 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] fresh Email OTP export requires Email OTP lane');
  }
  const resolution = await resolveActiveEcdsaCapabilityRuntime({
    walletId: exportLane.key.walletId,
    chainTarget: exportLane.chainTarget,
  });
  if (resolution.kind === 'blocked' && resolution.reason === 'missing_material') {
    return resolveCanonicalEmailOtpEcdsaExportMaterialForLane({ deps, exportLane });
  }
  if (resolution.kind !== 'resolved') {
    throw new Error(
      `[SigningEngine][ecdsa-export] Email OTP capability runtime unavailable: ${resolution.reason}`,
    );
  }
  return sealedEmailOtpExportMaterial({ deps, exportLane, resolution });
}

export async function resolveEcdsaExportMaterialForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane | ActiveLinkedDeviceEcdsaExportLane,
): Promise<EcdsaExportMaterial> {
  if (exportLane.source === 'active_execution_bundle') {
    return exportLane.material;
  }
  if (exportLane.authMethod === 'email_otp') {
    return await resolveFreshEmailOtpEcdsaExportMaterialForLane(deps, exportLane);
  }
  const resolution = await resolveActiveEcdsaCapabilityRuntime({
    walletId: exportLane.key.walletId,
    chainTarget: exportLane.chainTarget,
  });
  if (resolution.kind === 'blocked' && resolution.reason === 'missing_material') {
    return resolveCanonicalPasskeyEcdsaExportMaterialForLane({ deps, exportLane });
  }
  if (resolution.kind !== 'resolved') {
    throw new Error(
      `[SigningEngine][ecdsa-export] passkey capability runtime unavailable: ${resolution.reason}`,
    );
  }
  if (
    !mpcMaterialActivationRefsEqual(
      resolution.runtime.materialActivation,
      exportLane.laneIdentity.signer.materialActivation,
    )
  ) {
    throw new Error('[SigningEngine][ecdsa-export] passkey material activation mismatch');
  }
  if (resolution.runtime.authBinding.kind !== 'passkey') {
    throw new Error('[SigningEngine][ecdsa-export] passkey authority binding mismatch');
  }
  const publicFacts = resolution.manifest.signer.registeredPublicFacts;
  assertMatchingVerifiedEcdsaPublicFacts({
    expected: exportLane.publicFacts,
    actual: publicFacts,
    context: 'canonical passkey export lane',
  });
  const runtimePolicyScope = resolution.runtime.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error(
      '[SigningEngine][ecdsa-export] durable passkey export requires runtimePolicyScope',
    );
  }
  return {
    kind: 'fresh_passkey_needs_authorization',
    chainTarget: exportLane.chainTarget,
    publicFacts,
    runtimePolicyScope,
    publicCapability: resolution.manifest.durableMaterial.roleLocalPublicFacts.publicCapability,
    existingRoleLocalMaterial: buildPersistedEcdsaRoleLocalMaterial({
      authority: resolution.manifest.signer.authority,
      materialActivation: resolution.manifest.durableMaterial.materialActivation,
      publicFacts: resolution.manifest.durableMaterial.roleLocalPublicFacts,
    }),
    normalSigning: resolution.runtime.normalSigning,
    relayerKeyId: resolution.runtime.relayerKeyId,
    participantIds: resolution.runtime.participantIds,
    relayerUrl: resolution.runtime.relayerUrl,
  };
}
import type { ThresholdEcdsaCanonicalExportArtifact } from '../../interfaces/signing';
