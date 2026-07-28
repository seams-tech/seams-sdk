import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  buildEcdsaWalletSessionTransportAuth,
  buildKnownReadyThresholdEcdsaSessionPolicy,
  buildReadyThresholdEcdsaSession,
  type ReadyEcdsaSignerSession,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  ecdsaRoleLocalPersistedMaterialSource,
  resolveEcdsaRoleLocalMaterial,
  type EcdsaRoleLocalMaterialResolution,
  type PersistedEcdsaRoleLocalMaterial,
  type ResolvedEcdsaRoleLocalSigningMaterial,
} from '../../session/material/ecdsaRoleLocalMaterialResolver';
import {
  markResolvedEcdsaRoleLocalMaterialRuntimeValidated,
  type RouterAbEcdsaDerivationSigningWalletSession,
} from '../../session/routerAbSigningWalletSession';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { routerAbEcdsaDerivationActiveStateId } from '@shared/utils/routerAbEcdsaDerivation';
import { buildRouterAbEcdsaDerivationSigningMaterialRef } from '../../routerAb/ecdsaDerivation/signingMaterialRef';
import { laneCandidateStateFromRuntimePolicy } from '../../session/identity/laneIdentity';
import { thresholdEcdsaChainTargetsEqual } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ExactEcdsaSealedRuntime } from '../../session/material/ecdsaSealedRuntime';
import {
  buildReadySecp256k1SigningMaterial,
  type ReadySecp256k1SigningMaterial,
} from './signers/secp256k1';
import type { AuthorizedEvmFamilyEcdsaSigningCapability } from './ecdsaSigningCapability';

type EcdsaSessionChain = 'tempo' | 'evm';

function inferThresholdEcdsaSessionChainFromLabel(labelRaw: unknown): EcdsaSessionChain | null {
  const label = String(labelRaw || '')
    .trim()
    .toLowerCase();
  if (!label) return null;
  if (label === 'tempo' || label.startsWith('tempo:')) return 'tempo';
  if (label === 'evm' || label.startsWith('evm:')) return 'evm';
  return null;
}

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
        | 'material_corrupt'
        | 'worker_binding_failed';
      readonly material?: never;
    };

/** Ready ECDSA signing material, assembled from each fact's canonical owner:
 * the manifest names the material and its public facts, the exact sealed
 * runtime supplies session-scoped state (threshold session, normal-signing
 * state, policy scope, allowance, expiry, transport), and the reusable Wallet
 * Session supplies authorization identity and the bearer credential.
 *
 * Nothing is decoded out of the Wallet Session JWT. The JWT is a bearer
 * credential here and nothing more: the facts it used to carry are owned by
 * the manifest and the sealed record, and correlating those two is what
 * `resolveExactEcdsaSealedRuntime` already did to produce this runtime. */
export async function resolveReadySecp256k1SigningMaterial(args: {
  authorized: AuthorizedEvmFamilyEcdsaSigningCapability;
  runtime: ExactEcdsaSealedRuntime;
  requestLabel: unknown;
  materialActivation: MpcMaterialActivationRef;
  workerCtx: WorkerOperationContext;
}): Promise<ReadySecp256k1SigningMaterialResolution> {
  const capability = args.authorized.capability;
  const manifest = capability.manifest;
  const persistedMaterial = capability.material;
  const projection = args.authorized.authorization.projection;
  const runtime = args.runtime;
  const roleLocalFacts = persistedMaterial.publicFacts;

  // 1. Exact activation agreement across all three owners. The runtime is
  //    included because a sealed record for sibling material would otherwise
  //    hydrate a worker handle the manifest never named.
  if (
    !mpcMaterialActivationRefsEqual(
      args.materialActivation,
      manifest.activation.materialActivation,
    )
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

  // 2. Chain-target agreement between the request, the persisted facts, and
  //    the runtime this session belongs to.
  const requestChain = inferThresholdEcdsaSessionChainFromLabel(args.requestLabel);
  if (requestChain && roleLocalFacts.chainTarget.kind !== requestChain) {
    return { kind: 'unavailable', reason: 'chain_mismatch' };
  }
  if (!thresholdEcdsaChainTargetsEqual(runtime.chainTarget, roleLocalFacts.chainTarget)) {
    return { kind: 'unavailable', reason: 'chain_mismatch' };
  }

  // 3. Authorization classification over the runtime's own allowance, by the
  //    shared Refactor 92 rule: expiry before exhaustion, and neither disturbs
  //    the sealed material or its activation.
  const runtimeState = laneCandidateStateFromRuntimePolicy({
    remainingUses: runtime.remainingUses,
    expiresAtMs: runtime.expiresAtMs,
  });
  if (runtimeState === 'expired') {
    return { kind: 'unavailable', reason: 'authorization_expired' };
  }
  if (runtimeState === 'exhausted') {
    return { kind: 'unavailable', reason: 'authorization_exhausted' };
  }

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
  const walletSessionJwt = projection.walletSessionJwt;
  // The sealed record owns the normal-signing state. It was cross-checked
  // against this manifest's facts during runtime correlation, which is where
  // that check belongs.
  const normalSigningState = runtime.normalSigning;
  const thresholdSessionId = runtime.sealedRecord.thresholdSessionId;
  const signingMaterial = buildRouterAbEcdsaDerivationSigningMaterialRef({
    routerAbState: normalSigningState,
  });
  const signingWalletSession: RouterAbEcdsaDerivationSigningWalletSession = {
    curve: 'ecdsa',
    auth: {
      kind: 'wallet_session_jwt',
      walletSessionJwt,
      credential: {
        kind: 'jwt',
        walletSessionJwt,
      },
    },
    thresholdSessionId,
    remainingUses: runtime.remainingUses,
    expiresAtMs: runtime.expiresAtMs,
    signingMaterial,
    runtimePolicyScope,
    routerAbEcdsaDerivationNormalSigning: normalSigningState,
  };
  // 5. Worker and material-owner binding. This is the last gate before
  //    ready_to_sign: hydrated material that cannot be bound to this exact
  //    session is not signable, and is reported rather than thrown so callers
  //    can plan step-up.
  if (
    !markResolvedEcdsaRoleLocalMaterialRuntimeValidated({
      material: resolvedRoleLocalMaterial,
      session: signingWalletSession,
      keyHandle: roleLocalFacts.keyHandle,
      chainTarget: roleLocalFacts.chainTarget,
      participantIds: roleLocalFacts.participantIds,
    })
  ) {
    return { kind: 'unavailable', reason: 'worker_binding_failed' };
  }

  const transportAuth = buildEcdsaWalletSessionTransportAuth({
    kind: 'wallet_session_jwt',
    walletSessionJwt,
  });
  const signerSession: ReadyEcdsaSignerSession = {
    kind: 'ready_ecdsa_signer_session',
    walletId: manifest.signer.walletId,
    materialActivation: manifest.activation.materialActivation,
    publicFacts: manifest.signer.registeredPublicFacts,
    chainTarget: roleLocalFacts.chainTarget,
    session: buildReadyThresholdEcdsaSession({
      thresholdSessionId,
      policy: buildKnownReadyThresholdEcdsaSessionPolicy({
        remainingUses: runtime.remainingUses,
        expiresAtMs: runtime.expiresAtMs,
      }),
    }),
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
      kind: 'router_ab_ecdsa_derivation_normal_signing_ready_v1',
      state: normalSigningState,
      credential: {
        kind: 'jwt',
        walletSessionJwt: transportAuth.walletSessionJwt,
      },
      activeStateId: routerAbEcdsaDerivationActiveStateId(normalSigningState),
    },
  };

  return {
    kind: 'ready',
    material: buildReadySecp256k1SigningMaterial({
      walletId: manifest.signer.walletId,
      signerSession,
      authorization: {
        kind: 'reusable_wallet_session',
        wallet_session_id: projection.walletSessionId,
      },
      credential: {
        kind: 'jwt',
        walletSessionJwt,
      },
      expiresAtMs: runtime.expiresAtMs,
      singleUseEmailOtpSession: false,
    }),
  };
}
