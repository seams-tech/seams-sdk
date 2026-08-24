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
  ConcreteAvailableEcdsaSigningLane,
} from '../../session/availability/availableSigningLanes';
import { isConcreteAvailableSigningLane } from '../../session/availability/availableSigningLanes';
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
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { CanonicalEvmFamilyEcdsaSigningCapability } from '../../session/material/ecdsaSigningCapability';
import { resolveActiveEcdsaCapabilityRuntime } from '../../session/material/activeEcdsaCapabilityRuntime';
import type { ActiveWalletAuthorityEcdsaRuntimeV1 } from '../../session/material/activeWalletAuthorityEcdsaRuntime';

export type EcdsaExportMaterialAvailability =
  | { kind: 'loaded_worker_material' }
  | { kind: 'sealed_worker_material' }
  | { kind: 'material_pending'; reason: 'email_otp_route_auth' };

type ExactEcdsaExportLaneBase = {
  curve: 'ecdsa';
  laneIdentity: ExactEcdsaSigningLaneIdentity;
  key: EvmFamilyEcdsaKeyIdentity;
  publicFacts: VerifiedEcdsaPublicFacts;
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: 'email_otp' | 'passkey';
  material: EcdsaExportMaterialAvailability;
  state: Exclude<ConcreteAvailableEcdsaSigningLane['state'], 'expired' | 'exhausted'>;
};

export type ExactEcdsaExportLane =
  | (ExactEcdsaExportLaneBase & {
      source: 'canonical_capability';
      capability: CanonicalEvmFamilyEcdsaSigningCapability;
      runtime?: never;
      authorizationState: 'authorized';
      authorization: ActiveEvmFamilyWalletSessionAuthorization;
    })
  | (ExactEcdsaExportLaneBase & {
      source: 'canonical_capability';
      capability: CanonicalEvmFamilyEcdsaSigningCapability;
      runtime?: never;
      authorizationState: 'authorization_required';
      authorization?: never;
    })
  | (ExactEcdsaExportLaneBase & {
      source: 'active_wallet_authority';
      runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
      capability?: never;
      authorizationState: 'authorization_required';
      authorization?: never;
      state: 'deferred';
      material: { kind: 'loaded_worker_material' };
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
  source: 'canonical_capability';
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
  runtime?: never;
  factorAuthority?: never;
  record?: never;
  authLane?: never;
};

export type FreshPasskeyEcdsaExportMaterial = {
  source: 'canonical_capability';
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
  runtime?: never;
  factorAuthority?: never;
};

export type ActiveWalletAuthorityEcdsaExportMaterial =
  | {
      source: 'active_wallet_authority';
      kind: 'active_wallet_authority_passkey_needs_authorization';
      chainTarget: ThresholdEcdsaChainTarget;
      publicFacts: VerifiedEcdsaPublicFacts;
      normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
      relayerKeyId: string;
      participantIds: readonly [number, number];
      relayerUrl: string;
      runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
      factorAuthority: PasskeyWalletAuthAuthority;
      authMethod: 'passkey';
    }
  | {
      source: 'active_wallet_authority';
      kind: 'active_wallet_authority_email_otp_needs_authorization';
      chainTarget: ThresholdEcdsaChainTarget;
      publicFacts: VerifiedEcdsaPublicFacts;
      normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
      relayerKeyId: string;
      participantIds: readonly [number, number];
      relayerUrl: string;
      runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
      factorAuthority: EmailOtpWalletAuthAuthority;
      authMethod: 'email_otp';
    };

export type EcdsaExportMaterial =
  | FreshEmailOtpEcdsaExportMaterial
  | FreshPasskeyEcdsaExportMaterial
  | ActiveWalletAuthorityEcdsaExportMaterial;

export function ecdsaExportBoundaryChain(lane: ExactEcdsaExportLane): 'evm' | 'tempo' {
  return lane.chainTarget.kind;
}

export function ecdsaSigningTargetFromChainTarget(
  chainTarget: ThresholdEcdsaChainTarget,
): EvmFamilySigningTarget {
  return chainTarget;
}

export function isConcreteEcdsaExportLane(
  lane: AvailableEcdsaSigningLane | null | undefined,
): lane is Extract<
  ConcreteAvailableEcdsaSigningLane,
  { source: 'canonical_capability' | 'active_wallet_authority' }
> {
  if (
    !lane ||
    lane.curve !== 'ecdsa' ||
    !lane.chainTarget ||
    !isConcreteAvailableSigningLane(lane) ||
    !String(lane.publicFacts.keyHandle || '').trim()
  ) {
    return false;
  }
  if (lane.source === 'active_wallet_authority') {
    return (
      lane.runtime.requiredCapability === 'export_keys' &&
      lane.state === 'deferred' &&
      lane.authorizationState === 'authorization_required'
    );
  }
  if (lane.authorization) return true;
  return lane.state === 'deferred';
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
  exportLane: Extract<ExactEcdsaExportLane, { source: 'canonical_capability' }>;
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
    source: 'canonical_capability',
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
  exportLane: Extract<ExactEcdsaExportLane, { source: 'canonical_capability' }>;
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
    source: 'canonical_capability',
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
    source: 'canonical_capability',
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

function resolveActiveWalletAuthorityEcdsaExportMaterialForLane(args: {
  deps: EcdsaExportSessionStoreDeps;
  exportLane: Extract<ExactEcdsaExportLane, { source: 'active_wallet_authority' }>;
}): ActiveWalletAuthorityEcdsaExportMaterial {
  const { exportLane } = args;
  const runtime = exportLane.runtime;
  if (runtime.requiredCapability !== 'export_keys') {
    throw new Error(
      '[SigningEngine][ecdsa-export] active Wallet Authority lane lacks export_keys capability',
    );
  }
  if (runtime.walletId !== exportLane.key.walletId) {
    throw new Error('[SigningEngine][ecdsa-export] active Wallet Authority wallet mismatch');
  }
  if (
    !mpcMaterialActivationRefsEqual(
      runtime.materialActivation,
      exportLane.laneIdentity.signer.materialActivation,
    )
  ) {
    throw new Error(
      '[SigningEngine][ecdsa-export] active Wallet Authority material activation mismatch',
    );
  }
  assertMatchingVerifiedEcdsaPublicFacts({
    expected: exportLane.publicFacts,
    actual: runtime.publicFacts,
    context: 'active Wallet Authority ECDSA export lane',
  });
  const normalSigning = runtime.normalSigning;
  const normalScope = normalSigning.scope;
  if (
    normalScope.wallet_id !== String(runtime.walletId) ||
    normalScope.ecdsa_threshold_key_id !== runtime.ecdsaThresholdKeyId ||
    normalScope.public_identity.threshold_public_key33_b64u !== runtime.publicFacts.publicKeyB64u ||
    !mpcMaterialActivationRefsEqual(
      routerAbMpcMaterialActivationRefFromWire(normalScope.material_activation),
      runtime.materialActivation,
    )
  ) {
    throw new Error(
      '[SigningEngine][ecdsa-export] active Wallet Authority normal-signing identity mismatch',
    );
  }
  const relayerUrl = String(args.deps.relayerUrl).trim().replace(/\/+$/g, '');
  if (!relayerUrl) {
    throw new Error(
      '[SigningEngine][ecdsa-export] active Wallet Authority export relayer URL is missing',
    );
  }
  const participantIds = exactEcdsaParticipantIds(runtime.publicFacts.participantIds);
  if (runtime.auth.kind === 'passkey') {
    if (!isPasskeyWalletAuthAuthority(runtime.factorAuthority)) {
      throw new Error('[SigningEngine][ecdsa-export] active passkey factor authority mismatch');
    }
    if (
      runtime.factorAuthority.factor.credentialIdB64u !== runtime.auth.credentialIdB64u ||
      runtime.factorAuthority.bindingId !== runtime.walletAuthMethodId
    ) {
      throw new Error('[SigningEngine][ecdsa-export] active passkey factor identity mismatch');
    }
    return {
      source: 'active_wallet_authority',
      kind: 'active_wallet_authority_passkey_needs_authorization',
      chainTarget: exportLane.chainTarget,
      publicFacts: runtime.publicFacts,
      normalSigning,
      relayerKeyId: runtime.relayerKeyId,
      participantIds,
      relayerUrl,
      runtime,
      factorAuthority: runtime.factorAuthority,
      authMethod: 'passkey',
    };
  }
  if (!isEmailOtpWalletAuthAuthority(runtime.factorAuthority)) {
    throw new Error('[SigningEngine][ecdsa-export] active Email OTP factor authority mismatch');
  }
  if (
    runtime.factorAuthority.factor.providerUserId !== runtime.auth.providerSubjectId ||
    runtime.factorAuthority.bindingId !== runtime.walletAuthMethodId
  ) {
    throw new Error('[SigningEngine][ecdsa-export] active Email OTP factor identity mismatch');
  }
  return {
    source: 'active_wallet_authority',
    kind: 'active_wallet_authority_email_otp_needs_authorization',
    chainTarget: exportLane.chainTarget,
    publicFacts: runtime.publicFacts,
    normalSigning,
    relayerKeyId: runtime.relayerKeyId,
    participantIds,
    relayerUrl,
    runtime,
    factorAuthority: runtime.factorAuthority,
    authMethod: 'email_otp',
  };
}

export async function resolveFreshEmailOtpEcdsaExportMaterialForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): Promise<FreshEmailOtpEcdsaExportMaterial> {
  if (exportLane.source !== 'canonical_capability') {
    throw new Error(
      '[SigningEngine][ecdsa-export] active Wallet Authority Email OTP material uses its holder runtime',
    );
  }
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
  exportLane: ExactEcdsaExportLane,
): Promise<EcdsaExportMaterial> {
  if (exportLane.source === 'active_wallet_authority') {
    return resolveActiveWalletAuthorityEcdsaExportMaterialForLane({ deps, exportLane });
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
    source: 'canonical_capability',
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
