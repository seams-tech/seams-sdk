import type { EcdsaRoleLocalPublicFacts } from '@/core/platform';
import {
  activateRouterAbEcdsaPostRegistrationSession,
  type ThresholdEcdsaDerivationRouteAuth,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import type {
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { alphabetizeStringify } from '@shared/utils/digests';
import { base64UrlDecode } from '@shared/utils/base64';
import type { SigningGrantId, ThresholdEcdsaSessionId } from '@shared/utils/domainIds';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { EcdsaRoleLocalWorkerHandle } from '../../session/keyMaterialBrands';
import {
  persistedEcdsaRoleLocalMaterialSource,
  resolveEcdsaRoleLocalMaterial,
  type EcdsaRoleLocalMaterialResolution,
  type PersistedEcdsaRoleLocalMaterial,
} from '../../session/material/ecdsaRoleLocalMaterialResolver';
import type { ThresholdRuntimePolicyScope } from '../sessionPolicy';
import { bytesToHex } from '../../chains/evm/bytes';

const POST_REGISTRATION_ROUTE_AUTH_KINDS = new Set(['app_session', 'wallet_session']);

export type ExistingEcdsaRoleLocalActivation = {
  readonly kind: 'existing_ecdsa_role_local_material_activated_v1';
  readonly roleLocalMaterial: EcdsaRoleLocalWorkerHandle;
  readonly publicFacts: EcdsaRoleLocalPublicFacts;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
};

export type ActivateStrictEcdsaPostRegistrationSessionInput = {
  readonly relayerUrl: string;
  readonly routeAuth: Extract<
    ThresholdEcdsaDerivationRouteAuth,
    { kind: 'app_session' | 'wallet_session' }
  >;
  readonly workerCtx: WorkerOperationContext;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly persistedRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
  readonly walletId: string;
  readonly thresholdSessionId: ThresholdEcdsaSessionId;
  readonly signingGrantId: SigningGrantId;
  readonly ttlMs: number;
  readonly remainingUses: number;
  readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
};

export type ActivateStrictEcdsaPostRegistrationSessionResult = {
  readonly sessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
  readonly roleLocalActivation: ExistingEcdsaRoleLocalActivation;
};

function routeFailureMessage(
  result: { readonly code?: string; readonly message?: string; readonly error?: string },
  fallback: string,
): string {
  return result.error || result.message || result.code || fallback;
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
    scope.wallet_key_id === String(publicFacts.evmFamilySigningKeySlotId) &&
    scope.ecdsa_threshold_key_id === String(publicFacts.ecdsaThresholdKeyId) &&
    scope.signing_root_id === String(publicFacts.signingRootId) &&
    scope.signing_root_version === String(publicFacts.signingRootVersion)
  );
}

function validateStrictSessionInput(input: ActivateStrictEcdsaPostRegistrationSessionInput): void {
  const publicFacts = input.persistedRoleLocalMaterial.publicFacts;
  if (!POST_REGISTRATION_ROUTE_AUTH_KINDS.has(input.routeAuth.kind)) {
    throw new Error('Strict ECDSA session activation requires app or Wallet Session bearer auth');
  }
  if (!input.walletId || !input.thresholdSessionId || !input.signingGrantId) {
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
    input.persistedRoleLocalMaterial.materialRef.bindingDigest !==
      publicFacts.contextBinding32B64u ||
    !roleLocalPublicFactsMatchCapability(publicFacts, input.publicCapability)
  ) {
    throw new Error(
      'Strict ECDSA session activation requires exact registered role-local material',
    );
  }
}

function requireResolvedRegistrationMaterial(
  resolution: EcdsaRoleLocalMaterialResolution,
): EcdsaRoleLocalWorkerHandle {
  switch (resolution.kind) {
    case 'live':
    case 'rehydrated':
      return resolution.liveHandle;
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
  const materialResolution = await resolveEcdsaRoleLocalMaterial({
    purpose: 'registration_activation',
    source: persistedEcdsaRoleLocalMaterialSource(input.persistedRoleLocalMaterial),
    workerCtx: input.workerCtx,
  });
  const roleLocalMaterial = requireResolvedRegistrationMaterial(materialResolution);
  const roleLocalPublicFacts = input.persistedRoleLocalMaterial.publicFacts;
  const activated = await activateRouterAbEcdsaPostRegistrationSession(input.relayerUrl, {
    auth: input.routeAuth,
    request: {
      kind: 'router_ab_ecdsa_post_registration_session_activation_v1',
      public_capability: input.publicCapability,
      session_policy: {
        threshold_session_id: input.thresholdSessionId,
        signing_grant_id: input.signingGrantId,
        ttl_ms: input.ttlMs,
        remaining_uses: input.remainingUses,
        runtime_policy_scope: input.runtimePolicyScope,
      },
    },
  });
  if (!activated.ok) {
    throw new Error(routeFailureMessage(activated, 'Strict ECDSA session activation failed'));
  }
  if (
    alphabetizeStringify(activated.value.public_capability) !==
      alphabetizeStringify(input.publicCapability) ||
    !normalSigningMatchesRoleLocalFacts(activated.value, roleLocalPublicFacts)
  ) {
    throw new Error('Strict ECDSA session activation returned a different registered key identity');
  }
  return {
    sessionActivation: activated.value,
    roleLocalActivation: {
      kind: 'existing_ecdsa_role_local_material_activated_v1',
      roleLocalMaterial,
      publicFacts: roleLocalPublicFacts,
      publicCapability: input.publicCapability,
    },
  };
}
