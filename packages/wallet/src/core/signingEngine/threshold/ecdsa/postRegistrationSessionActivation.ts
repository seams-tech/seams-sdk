import type { EcdsaRoleLocalPublicFacts } from '@/core/platform';
import {
  activateRouterAbEcdsaPostRegistrationSession,
  type ThresholdEcdsaDerivationRouteAuth,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  type RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { alphabetizeStringify } from '@shared/utils/digests';
import { base64UrlDecode } from '@shared/utils/base64';
import type { ThresholdEcdsaSessionId } from '@shared/utils/domainIds';
import {
  WALLET_SESSION_CLIENT_CAPABILITY_V1,
  type ReusableWalletSessionMintId,
} from '@shared/authorization/capabilityKinds';
import type {
  EcdsaRoleLocalPersistedMaterialRef,
  EcdsaRoleLocalWorkerHandle,
} from '../../session/keyMaterialBrands';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  ecdsaRoleLocalPersistedMaterialSource,
  resolveEcdsaRoleLocalMaterial,
  type EcdsaRoleLocalMaterialResolution,
  type PersistedEcdsaRoleLocalMaterial,
} from '../../session/material/ecdsaRoleLocalMaterialResolver';
import type { ThresholdRuntimePolicyScope } from '../sessionPolicy';
import { bytesToHex } from '../../chains/evm/bytes';

export type ExistingEcdsaRoleLocalActivation = {
  readonly kind: 'existing_ecdsa_role_local_material_activated_v1';
  readonly roleLocalMaterial: EcdsaRoleLocalWorkerHandle;
  readonly roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
  readonly publicFacts: EcdsaRoleLocalPublicFacts;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
};

export type ActivateStrictEcdsaPostRegistrationSessionInput = {
  readonly relayerUrl: string;
  readonly routeAuth: Extract<
    ThresholdEcdsaDerivationRouteAuth,
    { kind: 'opaque_wallet_session' }
  >;
  readonly workerCtx: WorkerOperationContext;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly persistedRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
  readonly walletId: string;
  readonly thresholdSessionId: ThresholdEcdsaSessionId;
  readonly walletSessionMintId: ReusableWalletSessionMintId;
  readonly ttlMs: number;
  readonly remainingUses: number;
  readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
};

export type ActivateStrictEcdsaPostRegistrationSessionResult = {
  readonly sessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
  readonly roleLocalActivation: ExistingEcdsaRoleLocalActivation;
};

export type AdoptStrictEcdsaPostRegistrationSessionInput = Omit<
  ActivateStrictEcdsaPostRegistrationSessionInput,
  'relayerUrl' | 'routeAuth' | 'walletSessionMintId'
> & {
  readonly sessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
};

function routeFailureMessage(
  result: { readonly code?: string; readonly message?: string; readonly error?: string },
  fallback: string,
): string {
  return result.error || result.message || result.code || fallback;
}

export function buildStrictEcdsaPostRegistrationSessionActivationRequest(input: {
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly thresholdSessionId: ThresholdEcdsaSessionId;
  readonly walletSessionMintId: ReusableWalletSessionMintId;
  readonly ttlMs: number;
  readonly remainingUses: number;
  readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
}): RouterAbEcdsaPostRegistrationSessionActivationRequestV1 {
  return parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1({
    kind: 'router_ab_ecdsa_post_registration_session_activation_v1',
    wallet_session_client_capability: WALLET_SESSION_CLIENT_CAPABILITY_V1,
    public_capability: input.publicCapability,
    session_policy: {
      threshold_session_id: input.thresholdSessionId,
      wallet_session_mint_id: input.walletSessionMintId,
      ttl_ms: input.ttlMs,
      remaining_uses: input.remainingUses,
      runtime_policy_scope: input.runtimePolicyScope,
    },
  });
}

function roleLocalPublicFactsMatchCapability(
  publicFacts: EcdsaRoleLocalPublicFacts,
  capability: RouterAbEcdsaDerivationPublicCapabilityV1,
): boolean {
  const identity = capability.public_identity;
  return (
    publicFacts.applicationBindingDigestB64u ===
      capability.context.application_binding_digest_b64u &&
    publicFacts.contextBinding32B64u === identity.context_binding_b64u &&
    publicFacts.derivationClientSharePublicKey33B64u ===
      identity.derivation_client_share_public_key33_b64u &&
    publicFacts.relayerPublicKey33B64u === identity.server_public_key33_b64u &&
    publicFacts.groupPublicKey33B64u === identity.threshold_public_key33_b64u &&
    publicFacts.ethereumAddress.toLowerCase() ===
      bytesToHex(base64UrlDecode(identity.ethereum_address20_b64u)) &&
    alphabetizeStringify(publicFacts.publicCapability) === alphabetizeStringify(capability)
  );
}

function normalSigningMatchesRoleLocalFacts(
  activation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  publicFacts: EcdsaRoleLocalPublicFacts,
): boolean {
  const scope = activation.normal_signing.scope;
  return (
    scope.wallet_id === String(publicFacts.walletId) &&
    scope.ecdsa_threshold_key_id === String(publicFacts.ecdsaThresholdKeyId) &&
    scope.signing_root_id === String(publicFacts.signingRootId) &&
    scope.signing_root_version === String(publicFacts.signingRootVersion)
  );
}

function validateStrictSessionInput(
  input: Pick<
    ActivateStrictEcdsaPostRegistrationSessionInput,
    | 'publicCapability'
    | 'persistedRoleLocalMaterial'
    | 'walletId'
    | 'thresholdSessionId'
    | 'ttlMs'
    | 'remainingUses'
  >,
): void {
  const publicFacts = input.persistedRoleLocalMaterial.publicFacts;
  if (!input.walletId || !input.thresholdSessionId) {
    throw new Error('Strict ECDSA session activation requires exact wallet and session identity');
  }
  if (!Number.isSafeInteger(input.ttlMs) || input.ttlMs < 1) {
    throw new Error('Strict ECDSA session activation requires a positive ttlMs');
  }
  if (!Number.isSafeInteger(input.remainingUses) || input.remainingUses < 1) {
    throw new Error('Strict ECDSA session activation requires positive remainingUses');
  }
  if (
    String(publicFacts.walletId) !== input.walletId ||
    !roleLocalPublicFactsMatchCapability(publicFacts, input.publicCapability)
  ) {
    throw new Error(
      'Strict ECDSA session activation requires exact registered role-local material',
    );
  }
}

function requireResolvedRegistrationMaterial(
  resolution: EcdsaRoleLocalMaterialResolution,
): Extract<EcdsaRoleLocalMaterialResolution, { kind: 'rehydrated' }> {
  switch (resolution.kind) {
    case 'rehydrated':
      return resolution;
    case 'device_link_required':
      throw new Error(
        'device_link_required: registered ECDSA role-local material is unavailable on this device',
      );
    case 'corrupt':
      throw new Error(
        `Registered ECDSA role-local material is corrupt (${resolution.reason}): ${resolution.message}`,
      );
    default: {
      const exhaustive: never = resolution;
      throw new Error(`Unsupported ECDSA role-local material resolution: ${String(exhaustive)}`);
    }
  }
}

export async function activateStrictEcdsaPostRegistrationSession(
  input: ActivateStrictEcdsaPostRegistrationSessionInput,
): Promise<ActivateStrictEcdsaPostRegistrationSessionResult> {
  validateStrictSessionInput(input);
  const activated = await activateRouterAbEcdsaPostRegistrationSession(input.relayerUrl, {
    auth: input.routeAuth,
    request: buildStrictEcdsaPostRegistrationSessionActivationRequest(input),
  });
  if (!activated.ok) {
    throw new Error(routeFailureMessage(activated, 'Strict ECDSA session activation failed'));
  }
  return await adoptStrictEcdsaPostRegistrationSession({
    workerCtx: input.workerCtx,
    publicCapability: input.publicCapability,
    persistedRoleLocalMaterial: input.persistedRoleLocalMaterial,
    walletId: input.walletId,
    thresholdSessionId: input.thresholdSessionId,
    ttlMs: input.ttlMs,
    remainingUses: input.remainingUses,
    runtimePolicyScope: input.runtimePolicyScope,
    sessionActivation: activated.value,
  });
}

export async function adoptStrictEcdsaPostRegistrationSession(
  input: AdoptStrictEcdsaPostRegistrationSessionInput,
): Promise<ActivateStrictEcdsaPostRegistrationSessionResult> {
  validateStrictSessionInput(input);
  const materialResolution = await resolveEcdsaRoleLocalMaterial({
    purpose: 'registration_activation',
    source: ecdsaRoleLocalPersistedMaterialSource(input.persistedRoleLocalMaterial),
    workerCtx: input.workerCtx,
  });
  const resolvedRoleLocalMaterial = requireResolvedRegistrationMaterial(materialResolution);
  const roleLocalPublicFacts = input.persistedRoleLocalMaterial.publicFacts;
  if (
    alphabetizeStringify(input.sessionActivation.public_capability) !==
      alphabetizeStringify(input.publicCapability) ||
    input.sessionActivation.session.threshold_session_id !== input.thresholdSessionId ||
    !normalSigningMatchesRoleLocalFacts(input.sessionActivation, roleLocalPublicFacts)
  ) {
    throw new Error('Strict ECDSA session activation returned a different registered key identity');
  }
  return {
    sessionActivation: input.sessionActivation,
    roleLocalActivation: {
      kind: 'existing_ecdsa_role_local_material_activated_v1',
      roleLocalMaterial: resolvedRoleLocalMaterial.liveHandle,
      roleLocalMaterialRef: resolvedRoleLocalMaterial.materialRef,
      publicFacts: roleLocalPublicFacts,
      publicCapability: input.publicCapability,
    },
  };
}
