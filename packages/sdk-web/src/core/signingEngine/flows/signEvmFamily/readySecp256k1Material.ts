import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  buildHydratedEcdsaSignerMaterial,
  type HydratedEcdsaSignerMaterial,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  ecdsaRoleLocalPersistedMaterialSource,
  resolveEcdsaRoleLocalMaterial,
  type EcdsaRoleLocalMaterialResolution,
  type PersistedEcdsaRoleLocalMaterial,
  type ResolvedEcdsaRoleLocalSigningMaterial,
} from '../../session/material/ecdsaRoleLocalMaterialResolver';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { routerAbEcdsaDerivationActiveStateId } from '@shared/utils/routerAbEcdsaDerivation';
import { buildRouterAbEcdsaDerivationSigningMaterialRef } from '../../routerAb/ecdsaDerivation/signingMaterialRef';
import { laneCandidateStateFromRuntimePolicy } from '../../session/identity/laneIdentity';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { projectEcdsaRoleLocalPublicFactsToChainTarget } from '../../session/persistence/ecdsaRoleLocalRecords';
import type {
  ExactEcdsaCapabilityRuntime,
  ExactEcdsaMaterialRuntime,
  ExactEcdsaSealedRuntime,
} from '../../session/material/ecdsaSealedRuntime';
import {
  buildReadySecp256k1SigningMaterial,
  type ReadySecp256k1SigningMaterial,
} from './signers/secp256k1';
import type {
  ActiveEvmFamilyWalletSessionAuthorization,
  AuthorizedEvmFamilyEcdsaSigningCapability,
  CanonicalEvmFamilyEcdsaSigningCapability,
} from '../../session/material/ecdsaSigningCapability';
import { authorizeEvmFamilyEcdsaSigningCapability } from '../../session/material/ecdsaSigningCapability';
import { walletSessionTokenForCurve } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';

export async function hydrateEcdsaRoleLocalMaterialForSigning(args: {
  persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  workerCtx: WorkerOperationContext;
}): Promise<EcdsaRoleLocalMaterialResolution> {
  return resolveEcdsaRoleLocalMaterial({
    purpose: 'transaction_signing',
    source: ecdsaRoleLocalPersistedMaterialSource(args.persistedMaterial),
    workerCtx: args.workerCtx,
  });
}

export type ReadySecp256k1SigningMaterialResolution =
  | {
      readonly kind: 'ready';
      readonly material: ReadySecp256k1SigningMaterial;
      readonly reason?: never;
    }
  | {
      readonly kind: 'unavailable';
      readonly reason:
        | 'material_activation_mismatch'
        | 'chain_mismatch'
        | 'runtime_correlation_mismatch'
        | 'runtime_policy_scope_missing'
        | 'authorization_expired'
        | 'authorization_exhausted'
        | 'device_link_required'
        | 'material_corrupt';
      readonly material?: never;
    };

export type HydratedSecp256k1SigningMaterialResolution =
  | {
      readonly kind: 'ready';
      readonly material: HydratedEcdsaSignerMaterial;
      readonly reason?: never;
    }
  | {
      readonly kind: 'unavailable';
      readonly reason:
        | 'material_activation_mismatch'
        | 'chain_mismatch'
        | 'runtime_correlation_mismatch'
        | 'runtime_policy_scope_missing'
        | 'device_link_required'
        | 'material_corrupt';
      readonly material?: never;
    };

/** Ready ECDSA signing material, assembled from each fact's canonical owner:
 * the manifest names the material and its public facts, the exact durable
 * runtime supplies normal-signing state, policy scope, and transport, and any
 * reusable Wallet Session remains a separate authorization input.
 *
 * Nothing is decoded out of the Wallet Session JWT. The JWT is a bearer
 * credential here and nothing more: the facts it used to carry are owned by
 * the manifest and durable material record, which are correlated before this
 * function receives the runtime. */
export async function resolveHydratedSecp256k1SigningMaterial(args: {
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  runtime: ExactEcdsaMaterialRuntime | ExactEcdsaCapabilityRuntime;
  chainTarget: ThresholdEcdsaChainTarget;
  materialActivation: MpcMaterialActivationRef;
  workerCtx: WorkerOperationContext;
}): Promise<HydratedSecp256k1SigningMaterialResolution> {
  const capability = args.capability;
  const manifest = capability.manifest;
  const persistedMaterial = capability.material;
  const runtime = args.runtime;
  const sourceRoleLocalFacts = persistedMaterial.publicFacts;

  // 1. Exact activation agreement across all three owners. The runtime is
  //    included because a sealed record for sibling material would otherwise
  //    hydrate a worker handle the manifest never named.
  if (
    !mpcMaterialActivationRefsEqual(args.materialActivation, manifest.activation.materialActivation)
  ) {
    return { kind: 'unavailable', reason: 'material_activation_mismatch' };
  }
  if (
    !mpcMaterialActivationRefsEqual(
      runtime.materialActivation,
      manifest.activation.materialActivation,
    )
  ) {
    return { kind: 'unavailable', reason: 'runtime_correlation_mismatch' };
  }

  // 2. The durable role-local facts are canonical for one published target,
  //    while the same EVM-family material may be published to sibling
  //    targets. Keep the source target inside the manifest scope and project
  //    the verified facts onto the exact target requested by this operation.
  const sourceTargetIsPublished = manifest.signer.scope.targetMemberships.some((target) =>
    thresholdEcdsaChainTargetsEqual(target, sourceRoleLocalFacts.chainTarget),
  );
  const requestedTarget = manifest.signer.scope.targetMemberships.find((target) =>
    thresholdEcdsaChainTargetsEqual(target, args.chainTarget),
  );
  if (!sourceTargetIsPublished || !requestedTarget) {
    return { kind: 'unavailable', reason: 'chain_mismatch' };
  }
  if (!thresholdEcdsaChainTargetsEqual(runtime.chainTarget, requestedTarget)) {
    return { kind: 'unavailable', reason: 'chain_mismatch' };
  }
  const roleLocalFacts = projectEcdsaRoleLocalPublicFactsToChainTarget({
    publicFacts: sourceRoleLocalFacts,
    chainTarget: requestedTarget,
  });

  // The scope is persisted conditionally by the sealed store, but a signing
  // session cannot be built without it.
  const runtimePolicyScope = runtime.runtimePolicyScope;
  if (!runtimePolicyScope) {
    return { kind: 'unavailable', reason: 'runtime_policy_scope_missing' };
  }

  // 4. Persisted material hydration into an exact worker handle.
  const roleLocalMaterialResolution = await hydrateEcdsaRoleLocalMaterialForSigning({
    persistedMaterial,
    workerCtx: args.workerCtx,
  });
  let resolvedRoleLocalMaterial: ResolvedEcdsaRoleLocalSigningMaterial;
  switch (roleLocalMaterialResolution.kind) {
    case 'rehydrated':
      resolvedRoleLocalMaterial = roleLocalMaterialResolution;
      break;
    case 'device_link_required':
      return { kind: 'unavailable', reason: 'device_link_required' };
    case 'corrupt':
      return { kind: 'unavailable', reason: 'material_corrupt' };
    default: {
      const exhaustive: never = roleLocalMaterialResolution;
      return exhaustive;
    }
  }
  // The sealed record owns the normal-signing state. It was cross-checked
  // against this manifest's facts during runtime correlation, which is where
  // that check belongs.
  const normalSigningState = runtime.normalSigning;
  const signingMaterial = buildRouterAbEcdsaDerivationSigningMaterialRef({
    routerAbState: normalSigningState,
  });
  const signerSession = buildHydratedEcdsaSignerMaterial({
    walletId: manifest.signer.walletId,
    materialActivation: manifest.activation.materialActivation,
    publicFacts: manifest.signer.registeredPublicFacts,
    chainTarget: roleLocalFacts.chainTarget,
    transport: {
      kind: 'threshold_ecdsa_signer_transport',
      relayerUrl: runtime.relayerUrl,
      relayerKeyId: manifest.durableMaterial.roleLocalBinding.relayerKeyId,
      signingMaterial,
      relayerVerifyingShareB64u: roleLocalFacts.relayerPublicKey33B64u,
    },
    clientShare: {
      kind: 'role_local_worker_share',
      handle: resolvedRoleLocalMaterial.liveHandle,
      material: {
        kind: 'worker_loaded',
        materialRef: resolvedRoleLocalMaterial.materialRef,
      },
    },
    routerAbEcdsaDerivationNormalSigning: {
      kind: 'router_ab_ecdsa_derivation_normal_signing_hydrated_v1',
      state: normalSigningState,
      activeStateId: routerAbEcdsaDerivationActiveStateId(normalSigningState),
    },
  });

  return {
    kind: 'ready',
    material: signerSession,
  };
}

export async function resolveReadySecp256k1SigningMaterial(args: {
  authorized: AuthorizedEvmFamilyEcdsaSigningCapability;
  runtime: ExactEcdsaSealedRuntime;
  chainTarget: ThresholdEcdsaChainTarget;
  materialActivation: MpcMaterialActivationRef;
  workerCtx: WorkerOperationContext;
}): Promise<ReadySecp256k1SigningMaterialResolution> {
  const runtimeState = laneCandidateStateFromRuntimePolicy({
    remainingUses: args.runtime.remainingUses,
    expiresAtMs: args.runtime.expiresAtMs,
  });
  if (runtimeState === 'expired') {
    return { kind: 'unavailable', reason: 'authorization_expired' };
  }
  if (runtimeState === 'exhausted') {
    return { kind: 'unavailable', reason: 'authorization_exhausted' };
  }
  const hydrated = await resolveHydratedSecp256k1SigningMaterial({
    capability: args.authorized.capability,
    runtime: args.runtime,
    chainTarget: args.chainTarget,
    materialActivation: args.materialActivation,
    workerCtx: args.workerCtx,
  });
  if (hydrated.kind === 'unavailable') return hydrated;
  return {
    kind: 'ready',
    material: attachReusableEcdsaWalletSessionAuthorization({
      material: hydrated.material,
      capability: args.authorized.capability,
      authorization: args.authorized.authorization,
    }),
  };
}

export function attachReusableEcdsaWalletSessionAuthorization(args: {
  material: HydratedEcdsaSignerMaterial;
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  authorization: ActiveEvmFamilyWalletSessionAuthorization;
}): ReadySecp256k1SigningMaterial {
  const authorized = authorizeEvmFamilyEcdsaSigningCapability({
    capability: args.capability,
    authorization: args.authorization,
  });
  const projection = authorized.authorization.projection;
  if (String(projection.walletId) !== String(args.material.walletId)) {
    throw new Error(
      'Reusable Wallet Session authorization wallet does not match hydrated material',
    );
  }
  const walletSessionToken = walletSessionTokenForCurve(projection, 'ecdsa');
  if (!walletSessionToken) {
    throw new Error('Reusable Wallet Session authorization is unavailable');
  }
  return buildReadySecp256k1SigningMaterial({
    walletId: args.material.walletId,
    signerSession: args.material,
    authorization: {
      kind: 'reusable_wallet_session',
      wallet_session_id: projection.walletSessionId,
    },
    credential: {
      kind: 'reusable_wallet_session',
      walletSessionToken,
    },
    expiresAtMs: authorized.authorization.status.expiresAtMs,
    singleUseEmailOtpSession: false,
  });
}
