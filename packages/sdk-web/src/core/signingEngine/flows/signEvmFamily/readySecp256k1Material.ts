import {
  mpcMaterialActivationRefsEqual,
  parseSigningGrantId,
  parseThresholdEcdsaSessionId,
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
import {
  parseRouterAbEcdsaDerivationNormalSigningFromWalletRegistrationJwtV1,
  routerAbEcdsaDerivationActiveStateId,
} from '@shared/utils/routerAbEcdsaDerivation';
import { decodeJwtPayloadRecord } from '@shared/utils/sessionTokens';
import { buildRouterAbEcdsaDerivationSigningMaterialRef } from '../../routerAb/ecdsaDerivation/signingMaterialRef';
import { parseThresholdRuntimePolicyScopeFromJwt } from '../../threshold/sessionPolicy';
import {
  buildReadySecp256k1SigningMaterial,
  type ReadySecp256k1SigningMaterial,
} from './signers/secp256k1';
import type { CanonicalEvmFamilyEcdsaSigningCapability } from './ecdsaSigningCapability';

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

function requireResolvedRoleLocalWorkerHandle(
  resolution: EcdsaRoleLocalMaterialResolution,
): ResolvedEcdsaRoleLocalSigningMaterial {
  switch (resolution.kind) {
    case 'rehydrated':
      return resolution;
    case 'device_link_required':
      throw new Error(
        '[multichain] device_link_required: local threshold ECDSA material is unavailable',
      );
    case 'corrupt':
      throw new Error(
        `[multichain] threshold-ecdsa role-local material is corrupt (${resolution.reason}): ${resolution.message}`,
      );
    default: {
      const exhaustive: never = resolution;
      throw new Error(`Unsupported ECDSA role-local material resolution: ${String(exhaustive)}`);
    }
  }
}

export async function hydrateEcdsaRoleLocalMaterialForSigning(args: {
  persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  workerCtx: WorkerOperationContext;
}): Promise<ResolvedEcdsaRoleLocalSigningMaterial> {
  const resolution = await resolveEcdsaRoleLocalMaterial({
    purpose: 'transaction_signing',
    source: ecdsaRoleLocalPersistedMaterialSource(args.persistedMaterial),
    workerCtx: args.workerCtx,
  });
  return requireResolvedRoleLocalWorkerHandle(resolution);
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
        | 'chain_mismatch';
      readonly material?: never;
    };

function parseCanonicalEcdsaSessionIdentity(walletSessionJwt: string): {
  readonly thresholdSessionId: ReturnType<typeof parseThresholdEcdsaSessionId> & {
    readonly ok: true;
  };
  readonly signingGrantId: ReturnType<typeof parseSigningGrantId> & {
    readonly ok: true;
  };
} {
  const payload = decodeJwtPayloadRecord(walletSessionJwt);
  const thresholdSessionId = parseThresholdEcdsaSessionId(payload?.thresholdSessionId);
  const signingGrantId = parseSigningGrantId(payload?.signingGrantId);
  if (!thresholdSessionId.ok || !signingGrantId.ok) {
    throw new Error('[multichain] ECDSA Wallet Session identity is invalid');
  }
  return { thresholdSessionId, signingGrantId };
}

export async function resolveReadySecp256k1SigningMaterial(args: {
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  relayerUrl: string;
  requestLabel: unknown;
  materialActivation: MpcMaterialActivationRef;
  workerCtx: WorkerOperationContext;
}): Promise<ReadySecp256k1SigningMaterialResolution> {
  const capability = args.capability;
  const manifest = capability.manifest;
  const persistedMaterial = capability.material;
  const projection = capability.authorization.projection;
  const status = capability.authorization.status;
  if (
    !mpcMaterialActivationRefsEqual(
      args.materialActivation,
      manifest.activation.materialActivation,
    )
  ) {
    return {
      kind: 'unavailable',
      reason: 'material_activation_mismatch',
    };
  }
  const requestChain = inferThresholdEcdsaSessionChainFromLabel(args.requestLabel);
  if (requestChain && persistedMaterial.publicFacts.chainTarget.kind !== requestChain) {
    return {
      kind: 'unavailable',
      reason: 'chain_mismatch',
    };
  }
  if (status.expiresAtMs <= Date.now()) {
    throw new Error(
      '[multichain] threshold-ecdsa role-local session requires expired reauthorization',
    );
  }

  const resolvedRoleLocalMaterial = await hydrateEcdsaRoleLocalMaterialForSigning({
    persistedMaterial,
    workerCtx: args.workerCtx,
  });
  const walletSessionJwt = projection.walletSessionJwt;
  const identity = parseCanonicalEcdsaSessionIdentity(walletSessionJwt);
  const roleLocalFacts = persistedMaterial.publicFacts;
  const normalSigningState =
    parseRouterAbEcdsaDerivationNormalSigningFromWalletRegistrationJwtV1({
      walletSessionJwt,
      expected: {
        walletId: String(manifest.signer.walletId),
        evmFamilySigningKeySlotId: String(roleLocalFacts.evmFamilySigningKeySlotId),
        keyHandle: String(roleLocalFacts.keyHandle),
        relayerKeyId: String(manifest.durableMaterial.roleLocalBinding.relayerKeyId),
        ecdsaThresholdKeyId: String(roleLocalFacts.ecdsaThresholdKeyId),
        signingRootId: String(manifest.signer.signingRootId),
        signingRootVersion: String(manifest.signer.signingRootVersion),
        thresholdSessionId: identity.thresholdSessionId.value,
        activationEpoch: roleLocalFacts.publicCapability.activation_epoch,
        signingGrantId: identity.signingGrantId.value,
        expiresAtMs: status.expiresAtMs,
        participantIds: roleLocalFacts.participantIds,
        applicationBindingDigestB64u: roleLocalFacts.applicationBindingDigestB64u,
        contextBinding32B64u: roleLocalFacts.contextBinding32B64u,
        clientPublicKey33B64u: roleLocalFacts.derivationClientSharePublicKey33B64u,
        serverPublicKey33B64u: roleLocalFacts.relayerPublicKey33B64u,
        thresholdPublicKey33B64u: roleLocalFacts.groupPublicKey33B64u,
        ethereumAddress: roleLocalFacts.ethereumAddress,
        clientShareRetryCounter:
          roleLocalFacts.publicCapability.public_identity.client_share_retry_counter,
        serverShareRetryCounter:
          roleLocalFacts.publicCapability.public_identity.server_share_retry_counter,
      },
    });
  const runtimePolicyScope = parseThresholdRuntimePolicyScopeFromJwt(walletSessionJwt);
  if (!runtimePolicyScope) {
    throw new Error('[multichain] ECDSA Wallet Session runtime policy scope is invalid');
  }
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
    thresholdSessionId: identity.thresholdSessionId.value,
    signingGrantId: identity.signingGrantId.value,
    remainingUses: status.remainingUses,
    expiresAtMs: status.expiresAtMs,
    signingMaterial,
    runtimePolicyScope,
    routerAbEcdsaDerivationNormalSigning: normalSigningState,
  };
  if (
    !markResolvedEcdsaRoleLocalMaterialRuntimeValidated({
      material: resolvedRoleLocalMaterial,
      session: signingWalletSession,
      keyHandle: roleLocalFacts.keyHandle,
      chainTarget: roleLocalFacts.chainTarget,
      participantIds: roleLocalFacts.participantIds,
    })
  ) {
    throw new Error(
      '[multichain] threshold-ecdsa hydrated material could not be bound to its signing session',
    );
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
      thresholdSessionId: identity.thresholdSessionId.value,
      signingGrantId: identity.signingGrantId.value,
      policy: buildKnownReadyThresholdEcdsaSessionPolicy({
        remainingUses: status.remainingUses,
        expiresAtMs: status.expiresAtMs,
      }),
    }),
    transport: {
      kind: 'threshold_ecdsa_signer_transport',
      relayerUrl: args.relayerUrl,
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
      expiresAtMs: status.expiresAtMs,
      singleUseEmailOtpSession: false,
    }),
  };
}
