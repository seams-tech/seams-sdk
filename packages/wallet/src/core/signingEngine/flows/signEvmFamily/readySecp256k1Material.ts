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
  toWalletId,
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
  AuthorizedEvmFamilyEcdsaSigningCapability,
  CanonicalEvmFamilyEcdsaSigningCapability,
  ExactEvmFamilyWalletSessionAuthorization,
} from '../../session/material/ecdsaSigningCapability';
import { authorizeEvmFamilyEcdsaSigningCapability } from '../../session/material/ecdsaSigningCapability';
import type { ActiveWalletSessionV1 } from '@shared/device-linking/contracts';
import type { ActiveWalletAuthorityEcdsaRuntimeV1 } from '../../session/material/activeWalletAuthorityEcdsaRuntime';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';

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
 * runtime supplies normal-signing state, policy scope, and transport, and the
 * exact Wallet Session remains a separate authorization input.
 *
 * Nothing is decoded out of the opaque Wallet Session token. The facts it authorizes are owned by
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
  nowMs: number;
  workerCtx: WorkerOperationContext;
}): Promise<ReadySecp256k1SigningMaterialResolution> {
  const runtimeState = laneCandidateStateFromRuntimePolicy({
    remainingUses: args.runtime.remainingUses,
    expiresAtMs: args.runtime.expiresAtMs,
    nowMs: args.nowMs,
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
    material: attachExactEcdsaWalletSessionAuthorization({
      material: hydrated.material,
      capability: args.authorized.capability,
      authorization: args.authorized.authorization,
      nowMs: args.nowMs,
    }),
  };
}

export function attachExactEcdsaWalletSessionAuthorization(args: {
  material: HydratedEcdsaSignerMaterial;
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  authorization: ExactEvmFamilyWalletSessionAuthorization;
  nowMs: number;
}): ReadySecp256k1SigningMaterial {
  const authorized = authorizeEvmFamilyEcdsaSigningCapability({
    capability: args.capability,
    authorization: args.authorization,
    nowMs: args.nowMs,
  });
  const session = authorized.authorization.session;
  const operationCredential = authorized.authorization.operationCredential;
  if (
    session.walletId !== args.material.walletId ||
    !mpcMaterialActivationRefsEqual(
      args.material.materialActivation,
      args.capability.manifest.activation.materialActivation,
    )
  ) {
    throw new Error('Exact Wallet Session authorization wallet does not match hydrated material');
  }
  if (operationCredential.token.trim().length === 0) {
    throw new Error('Exact Wallet Session authorization is unavailable');
  }
  return buildReadySecp256k1SigningMaterial({
    walletId: args.material.walletId,
    signerSession: args.material,
    authorization: {
      kind: 'reusable_wallet_session',
      wallet_session_id: operationCredential.walletSessionId,
    },
    credential: {
      kind: 'reusable_wallet_session',
      walletSessionToken: operationCredential.token,
    },
    expiresAtMs: session.expiresAtMs,
    singleUseEmailOtpSession: false,
  });
}

function exactSessionAuthorizesEcdsaSigning(args: {
  readonly session: ActiveWalletSessionV1;
  readonly materialActivation: MpcMaterialActivationRef;
}): boolean {
  return args.session.capabilitySubjects.some(
    (subject) =>
      subject.kind === 'sign' &&
      subject.keyFamily === 'ecdsa_secp256k1' &&
      mpcMaterialActivationRefsEqual(subject.materialActivation, args.materialActivation),
  );
}

export function buildActiveWalletAuthorityReadySecp256k1Material(args: {
  readonly authorityRuntime: ActiveWalletAuthorityEcdsaRuntimeV1;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly relayerUrl: string;
}): ReadySecp256k1SigningMaterial {
  const authorityRuntime = args.authorityRuntime;
  const runtime = authorityRuntime.holderRuntime;
  const session = authorityRuntime.session;
  const operationCredential = authorityRuntime.operationCredential;
  const normalSigning = runtime.activationReceipt.normalSigning;
  const normalScope = normalSigning.scope;
  if (
    session.walletId !== runtime.walletId ||
    session.authorityId !== runtime.authorityId ||
    session.authMethodId !== runtime.walletAuthMethodId ||
    operationCredential.walletSessionId !== authorityRuntime.walletSessionId ||
    session.expiresAtMs <= Date.now() ||
    !exactSessionAuthorizesEcdsaSigning({
      session,
      materialActivation: runtime.materialActivation,
    }) ||
    normalScope.wallet_id !== runtime.walletId ||
    normalScope.ecdsa_threshold_key_id !== runtime.ecdsaThresholdKeyId ||
    !mpcMaterialActivationRefsEqual(
      routerAbMpcMaterialActivationRefFromWire(normalScope.material_activation),
      runtime.materialActivation,
    )
  ) {
    throw new Error(
      '[SigningEngine] active Wallet Authority session does not bind the ECDSA holder runtime',
    );
  }
  const relayerUrl = String(args.relayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('[SigningEngine] active Wallet Authority ECDSA signing requires relayerUrl');
  }
  const signerSession = buildHydratedEcdsaSignerMaterial({
    walletId: toWalletId(runtime.walletId),
    materialActivation: runtime.materialActivation,
    publicFacts: authorityRuntime.publicFacts,
    chainTarget: args.chainTarget,
    transport: {
      kind: 'threshold_ecdsa_signer_transport',
      relayerUrl,
      relayerKeyId: authorityRuntime.relayerKeyId,
      signingMaterial: buildRouterAbEcdsaDerivationSigningMaterialRef({
        routerAbState: normalSigning,
      }),
      relayerVerifyingShareB64u: normalScope.public_identity.server_public_key33_b64u,
    },
    clientShare: {
      kind: 'linked_holder_worker_share',
      holderHandleId: runtime.holderHandleId,
    },
    routerAbEcdsaDerivationNormalSigning: {
      kind: 'router_ab_ecdsa_derivation_normal_signing_hydrated_v1',
      state: normalSigning,
      activeStateId: routerAbEcdsaDerivationActiveStateId(normalSigning),
    },
  });
  return buildReadySecp256k1SigningMaterial({
    walletId: runtime.walletId,
    signerSession,
    authorization: {
      kind: 'reusable_wallet_session',
      wallet_session_id: operationCredential.walletSessionId,
    },
    credential: {
      kind: 'reusable_wallet_session',
      walletSessionToken: operationCredential.token,
    },
    expiresAtMs: session.expiresAtMs,
    singleUseEmailOtpSession: false,
  });
}
