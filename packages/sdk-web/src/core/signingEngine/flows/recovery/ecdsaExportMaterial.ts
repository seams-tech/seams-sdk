import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
  WalletAuthAuthority,
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
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { EvmFamilySigningTarget } from '../signEvmFamily/types';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../../session/material/ecdsaSigningCapability';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { resolveActiveEcdsaCapabilityRuntime } from '../../session/material/activeEcdsaCapabilityRuntime';
import {
  resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime,
  type EmailOtpEcdsaSigningSessionAuthority,
} from '../../session/emailOtp/ecdsaSigningSessionAuthority';

export type EcdsaExportMaterialAvailability =
  | { kind: 'loaded_worker_material' }
  | { kind: 'sealed_worker_material' }
  | { kind: 'material_pending'; reason: 'email_otp_route_auth' };

export type ExactEcdsaExportLane = {
  curve: 'ecdsa';
  laneIdentity: ExactEcdsaSigningLaneIdentity;
  authorization: ActiveEvmFamilyWalletSessionAuthorization;
  key: EvmFamilyEcdsaKeyIdentity;
  publicFacts: VerifiedEcdsaPublicFacts;
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: 'email_otp' | 'passkey';
  material: EcdsaExportMaterialAvailability;
  state: Exclude<ConcreteAvailableEcdsaSigningLane['state'], 'expired' | 'exhausted'>;
  source: 'canonical_capability';
  ecdsaThresholdKeyId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  participantIds?: never;
  thresholdOwnerAddress?: never;
  publicReauthAuthority?: never;
};

export type EcdsaExportSessionStoreDeps = {
  exportArtifactsByLane: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
};

export type EmailOtpEcdsaExportAuthLane = Extract<
  EmailOtpSigningSessionAuthLane,
  { curve: 'ecdsa' }
>;

type FreshEmailOtpEcdsaWalletSessionExportAuthority = {
  kind: 'wallet_session_authorized';
  signingSessionAuthority: EmailOtpEcdsaSigningSessionAuthority;
};

export type FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready';
  chainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  authorization: FreshEmailOtpEcdsaWalletSessionExportAuthority;
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
  relayerUrl: string;
};

export type EcdsaExportMaterial =
  | FreshEmailOtpEcdsaExportMaterial
  | FreshPasskeyEcdsaExportMaterial;

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
): lane is ConcreteAvailableEcdsaSigningLane & {
  source: 'canonical_capability';
  authorization: NonNullable<ConcreteAvailableEcdsaSigningLane['authorization']>;
} {
  return (
    Boolean(lane) &&
    lane!.curve === 'ecdsa' &&
    Boolean(lane!.chainTarget) &&
    isConcreteAvailableSigningLane(lane!) &&
    lane!.source === 'canonical_capability' &&
    Boolean(lane!.authorization) &&
    Boolean(String(lane!.publicFacts.keyHandle || '').trim())
  );
}

export async function resolveFreshEmailOtpEcdsaExportMaterialForLane(
  _deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): Promise<FreshEmailOtpEcdsaExportMaterial> {
  if (exportLane.authMethod !== 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] fresh Email OTP export requires Email OTP lane');
  }
  const resolution = await resolveActiveEcdsaCapabilityRuntime({
    walletId: exportLane.key.walletId,
    chainTarget: exportLane.chainTarget,
  });
  if (resolution.kind !== 'resolved') {
    throw new Error(
      `[SigningEngine][ecdsa-export] Email OTP capability runtime unavailable: ${resolution.reason}`,
    );
  }
  if (
    !mpcMaterialActivationRefsEqual(
      resolution.runtime.materialActivation,
      exportLane.laneIdentity.signer.materialActivation,
    )
  ) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP material activation mismatch');
  }
  const authority = resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime({
    runtime: resolution.runtime,
    authorization: exportLane.authorization.projection,
  });
  if (authority.kind !== 'ready') {
    throw new Error(
      `[SigningEngine][ecdsa-export] Email OTP signing-session authority unavailable: ${authority.kind}`,
    );
  }
  const runtimePolicyScope = resolution.runtime.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP runtime policy scope is missing');
  }
  return {
    kind: 'fresh_email_otp_route_auth_ready',
    chainTarget: exportLane.chainTarget,
    publicFacts: exportLane.publicFacts,
    runtimePolicyScope,
    authorization: {
      kind: 'wallet_session_authorized',
      signingSessionAuthority: authority.authority,
    },
  };
}

export async function resolveEcdsaExportMaterialForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): Promise<EcdsaExportMaterial> {
  if (exportLane.authMethod === 'email_otp') {
    return await resolveFreshEmailOtpEcdsaExportMaterialForLane(deps, exportLane);
  }
  const resolution = await resolveActiveEcdsaCapabilityRuntime({
    walletId: exportLane.key.walletId,
    chainTarget: exportLane.chainTarget,
  });
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
    relayerUrl: resolution.runtime.relayerUrl,
  };
}
import type { ThresholdEcdsaCanonicalExportArtifact } from '../../interfaces/signing';
