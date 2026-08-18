import type { ActiveEcdsaCapabilityRuntimeResolution } from '../material/activeEcdsaCapabilityRuntime';
import {
  resolveActiveEcdsaCapabilityRuntime,
  resolveActiveEcdsaCapabilityRuntimeForChain,
} from '../material/activeEcdsaCapabilityRuntime';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toRpId,
} from '../identity/evmFamilyEcdsaIdentity';
import { selectedEcdsaLane } from '../identity/laneIdentity';
import type { EcdsaSealTransportAuthMaterial } from '../persistence/sealedSessionTransportAuth';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';
import {
  deriveEcdsaCapabilityState,
  deriveEd25519CapabilityState,
  resolveEcdsaSealTransport,
} from './readModel';
import { assertWarmSessionEnvelopeInvariant } from './types';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { warmClaimFromRecordPolicy } from '../availability/readiness';
import type {
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519CapabilityState,
  WarmSessionEnvelope,
  WarmSessionPrfClaim,
} from './types';
import type { WarmSigningStatusReader } from './statusReader';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  resolveExactEd25519SealedSessionRuntimeForWallet,
  type Ed25519WalletSealedSessionRuntimeResolution,
} from './ed25519SealedSessionRuntime';
import type { ExactEcdsaSealedRuntimeAuthBinding } from '../material/ecdsaSealedRuntime';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';

function signingLaneAuthBindingFromEcdsaRuntime(
  authBinding: ExactEcdsaSealedRuntimeAuthBinding,
): SigningLaneAuthBinding {
  switch (authBinding.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        rpId: toRpId(authBinding.rpId),
        credentialIdB64u: authBinding.credentialIdB64u,
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        providerSubjectId: authBinding.providerSubjectId,
      };
    default:
      authBinding satisfies never;
      throw new Error('[WarmSessionStore] unsupported ECDSA runtime auth binding');
  }
}

export type WarmSessionCapabilityReaderSealConfigured = {
  seal: 'configured';
  groupId: string;
};

export type WarmSessionCapabilityReaderSealUnavailable = {
  seal: 'unconfigured';
  groupId?: never;
};

export type WarmSessionCapabilityReaderSeal =
  | WarmSessionCapabilityReaderSealConfigured
  | WarmSessionCapabilityReaderSealUnavailable;

export type WarmSessionCapabilityReaderCoreDeps = {
  statusReader: Pick<
    WarmSigningStatusReader,
    'readEd25519WarmSessionClaim'
  >;
  signingSessionSeal: WarmSessionCapabilityReaderSeal;
  // Resolves the active reusable Wallet Session authorization for a wallet.
  // Absent or failing resolution degrades ECDSA capabilities to
  // `authorization_required`; it never fabricates an authorization.
  resolveActiveEcdsaWalletSessionAuthorization?: (
    walletId: WalletId,
  ) => Promise<ActiveEvmFamilyWalletSessionAuthorization | null>;
  resolveActiveEd25519WalletSessionAuthorization?: (
    walletId: WalletId,
  ) => Promise<ActiveWalletSessionAuthorizationProjection | null>;
};

export type WarmSessionCapabilityReaderCore = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionEnvelope>;
  getEcdsaCapabilityForLane: (
    args: {
      lane: ExactEcdsaSigningLaneIdentity;
      authorization: ActiveEvmFamilyWalletSessionAuthorization;
    },
  ) => Promise<WarmSessionEcdsaCapabilityState | null>;
  // Lane-qualified, and async because canonical resolution reads persistence.
  // There is deliberately no threshold-session-id entry point: that id indexes
  // runtime state and must never select material.
  resolveEcdsaSealTransportForLane: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
    authorization: ActiveEvmFamilyWalletSessionAuthorization;
  }) => Promise<EcdsaSealTransportAuthMaterial | null>;
};

/** The PRF claim for a resolved ECDSA capability. Correlation has already proved
 * the material, so the claim is the sealed runtime's own allowance and expiry --
 * the same facts the shared Refactor 92 rule classifies. A blocked resolution
 * has no runtime and so no claim to report.
 *
 * The wallet-scoped relayer claim is not consulted here. It is read by lane, and
 * no lane was ever built for an ECDSA capability from the composite store, so
 * this reaches strictly more state than the path it replaces rather than less. */
function ecdsaClaimForResolution(
  resolution: ActiveEcdsaCapabilityRuntimeResolution,
): WarmSessionPrfClaim | null {
  if (resolution.kind !== 'resolved') return null;
  return warmClaimFromRecordPolicy({
    thresholdSessionId: resolution.runtime.sealedRecord.thresholdSessionId,
    remainingUses: resolution.runtime.remainingUses,
    expiresAtMs: resolution.runtime.expiresAtMs,
  });
}

export function createWarmSessionCapabilityReaderCore(
  deps: WarmSessionCapabilityReaderCoreDeps,
): WarmSessionCapabilityReaderCore {
  async function resolveEcdsaAuthorizationForWallet(
    walletId: WalletId | string,
  ): Promise<ActiveEvmFamilyWalletSessionAuthorization | null> {
    const resolve = deps.resolveActiveEcdsaWalletSessionAuthorization;
    if (!resolve) return null;
    try {
      return await resolve(toWalletId(walletId));
    } catch {
      return null;
    }
  }

  async function resolveEd25519AuthorizationForWallet(
    walletId: WalletId,
  ): Promise<ActiveWalletSessionAuthorizationProjection | null> {
    const resolve = deps.resolveActiveEd25519WalletSessionAuthorization;
    if (!resolve) return null;
    try {
      return await resolve(walletId);
    } catch {
      return null;
    }
  }

  function buildEd25519CapabilityState(args: {
    resolution: Ed25519WalletSealedSessionRuntimeResolution;
    auth: ActiveWalletSessionAuthorizationProjection | null;
    prfClaim: WarmSessionEd25519CapabilityState['prfClaim'];
  }): WarmSessionEd25519CapabilityState {
    if (args.resolution.kind === 'missing') {
      return {
        capability: 'ed25519',
        runtime: null,
        auth: null,
        prfClaim: null,
        state: 'missing',
      };
    }
    if (args.resolution.kind === 'conflict' || args.resolution.kind === 'corrupt') {
      return {
        capability: 'ed25519',
        runtime: null,
        auth: null,
        prfClaim: null,
        invalidReason:
          args.resolution.kind === 'conflict' ? 'exact_record_conflict' : 'corrupt',
        state: 'invalid',
      };
    }
    const runtime = args.resolution.runtime;
    const state = deriveEd25519CapabilityState({
      runtime,
      auth: args.auth,
      prfClaim: args.prfClaim,
    });
    if (state === 'authorization_required') {
      return {
        capability: 'ed25519',
        runtime,
        auth: null,
        prfClaim: args.prfClaim,
        state,
      };
    }
    if (state === 'missing' || state === 'invalid') {
      throw new Error(
        `[WarmSessionStore] Ed25519 capability state=${state} with resolved material`,
      );
    }
    if (!args.auth) {
      throw new Error(
        `[WarmSessionStore] Ed25519 capability state=${state} requires active authorization`,
      );
    }
    return {
      capability: 'ed25519',
      runtime,
      auth: args.auth,
      prfClaim: args.prfClaim,
      state,
    };
  }

  /** Canonical ECDSA warm state. The manifest and sealed runtime prove exact
   * material; the active reusable Wallet Session is the independent second
   * proof. Absent authorization over resolved material is authorization_required
   * with no lane, because a SelectedEcdsaLane embeds that authorization. */
  function buildEcdsaCapabilityState(args: {
    resolution: ActiveEcdsaCapabilityRuntimeResolution;
    authorization: ActiveEvmFamilyWalletSessionAuthorization | null;
    prfClaim: WarmSessionEcdsaCapabilityState['prfClaim'];
  }): WarmSessionEcdsaCapabilityState {
    if (args.resolution.kind === 'blocked') {
      const reason = args.resolution.reason;
      // Absence and disagreement are different situations: only the first is
      // 'missing'. A store that holds a manifest and a sealed record which do
      // not correlate is reported with its typed reason.
      if (reason === 'missing_capability' || reason === 'missing_material') {
        return {
          capability: 'ecdsa',
          manifest: null,
          runtime: null,
          key: null,
          lane: null,
          auth: null,
          prfClaim: null,
          state: 'missing',
        };
      }
      return {
        capability: 'ecdsa',
        manifest: null,
        runtime: null,
        key: null,
        lane: null,
        auth: null,
        prfClaim: null,
        invalidReason: reason,
        state: 'invalid',
      };
    }
    const { manifest, runtime } = args.resolution;
    const publicFacts = manifest.durableMaterial.roleLocalPublicFacts;
    const key = buildBaseEvmFamilyEcdsaKeyIdentity({
      walletId: runtime.walletId,
      ecdsaThresholdKeyId: runtime.ecdsaThresholdKeyId,
      signingRootId: String(publicFacts.signingRootId),
      signingRootVersion: String(publicFacts.signingRootVersion),
      participantIds: [...runtime.participantIds],
      thresholdOwnerAddress: String(publicFacts.ethereumAddress),
    });
    const authBinding = runtime.authBinding;
    const state = deriveEcdsaCapabilityState({
      runtime,
      auth: args.authorization,
      prfClaim: args.prfClaim,
      emailOtpAuthContext: null,
    });
    // Derived before the lane, because a SelectedEcdsaLane embeds the
    // authorization it signs under. An absent Wallet Session and a spent one
    // both land here, and neither can produce a lane.
    if (state === 'authorization_required') {
      return {
        capability: 'ecdsa',
        manifest,
        runtime,
        key,
        lane: null,
        auth: null,
        prfClaim: args.prfClaim,
        emailOtpAuthContext: null,
        state,
      };
    }
    if (!args.authorization) {
      throw new Error(
        '[WarmSessionStore] ECDSA capability without authorization must be authorization_required',
      );
    }
    if (state === 'missing' || state === 'invalid') {
      // Both are resolution outcomes, returned above. Reaching them here would
      // mean a resolved manifest and runtime describing an absent capability.
      throw new Error(`[WarmSessionStore] ECDSA capability state=${state} with resolved material`);
    }
    const lane = selectedEcdsaLane({
      key,
      materialActivation: runtime.materialActivation,
      keyHandle: runtime.keyHandle,
      walletId: runtime.walletId,
      auth: signingLaneAuthBindingFromEcdsaRuntime(authBinding),
      authorization: args.authorization,
      chainTarget: runtime.chainTarget,
    });
    if (state === 'ready' || state === 'material_pending') {
      if (!args.prfClaim || args.prfClaim.state !== 'warm') {
        throw new Error(
          `[WarmSessionStore] ECDSA capability state=${state} requires a warm PRF claim`,
        );
      }
      return {
        capability: 'ecdsa',
        manifest,
        runtime,
        key,
        lane,
        auth: args.authorization,
        prfClaim: args.prfClaim,
        state,
      };
    }
    if (state === 'auth_missing') {
      return {
        capability: 'ecdsa',
        manifest,
        runtime,
        key,
        lane,
        auth: null,
        prfClaim: args.prfClaim,
        state,
      };
    }
    return {
      capability: 'ecdsa',
      manifest,
      runtime,
      key,
      lane,
      auth: args.authorization,
      prfClaim: args.prfClaim,
      state,
    };
  }

  async function getWarmSession(walletId: WalletId): Promise<WarmSessionEnvelope> {
    const normalizedWalletId = toWalletId(walletId);
    // Material and authorization are resolved independently: authorization is
    // read unconditionally, so a wallet with durable material and no active
    // Wallet Session reaches authorization_required instead of being gated out
    // by a material precondition.
    const [
      ed25519Resolution,
      ed25519Authorization,
      ecdsaAuthorization,
      evmResolution,
      tempoResolution,
    ] = await Promise.all([
      resolveExactEd25519SealedSessionRuntimeForWallet(normalizedWalletId),
      resolveEd25519AuthorizationForWallet(normalizedWalletId),
      resolveEcdsaAuthorizationForWallet(normalizedWalletId),
      resolveActiveEcdsaCapabilityRuntimeForChain({
        walletId: normalizedWalletId,
        chain: 'evm',
      }),
      resolveActiveEcdsaCapabilityRuntimeForChain({
        walletId: normalizedWalletId,
        chain: 'tempo',
      }),
    ]);
    const ed25519Claim =
      ed25519Resolution.kind === 'resolved'
        ? await deps.statusReader.readEd25519WarmSessionClaim(ed25519Resolution.runtime)
        : null;
    return assertWarmSessionEnvelopeInvariant({
      walletId: normalizedWalletId,
      capabilities: {
        ed25519: buildEd25519CapabilityState({
          resolution: ed25519Resolution,
          auth: ed25519Authorization,
          prfClaim: ed25519Claim,
        }),
        ecdsa: {
          evm: buildEcdsaCapabilityState({
            resolution: evmResolution,
            prfClaim: ecdsaClaimForResolution(evmResolution),
            authorization: ecdsaAuthorization,
          }),
          tempo: buildEcdsaCapabilityState({
            resolution: tempoResolution,
            prfClaim: ecdsaClaimForResolution(tempoResolution),
            authorization: ecdsaAuthorization,
          }),
        },
      },
      updatedAtMs: Date.now(),
    });
  }

  /** The lane names its own wallet and chain target, so material is selected by
   * the capability it belongs to. The authorization the lane already carries is
   * the one this capability is read under -- re-resolving it for the wallet
   * could answer with a different Wallet Session than the caller holds. */
  async function getEcdsaCapabilityForLane(
    args: {
      lane: ExactEcdsaSigningLaneIdentity;
      authorization: ActiveEvmFamilyWalletSessionAuthorization;
    },
  ): Promise<WarmSessionEcdsaCapabilityState | null> {
    const resolution = await resolveActiveEcdsaCapabilityRuntime({
      walletId: args.lane.signer.walletId,
      chainTarget: args.lane.signer.chainTarget,
    });
    return buildEcdsaCapabilityState({
      resolution,
      prfClaim: ecdsaClaimForResolution(resolution),
      authorization: args.authorization,
    });
  }

  function ecdsaSealConfig(): {
    groupId: string;
  } {
    if (deps.signingSessionSeal.seal !== 'configured') return { groupId: '' };
    return {
      groupId: String(deps.signingSessionSeal.groupId || '').trim(),
    };
  }

  /** Seal parameters come from configuration alone. The sealed record's own
   * `keyVersion` seals that record's secret at rest and is not the signing
   * session's transport seal; the two must not be interchanged. */
  async function resolveEcdsaSealTransportForLane(args: {
    lane: ExactEcdsaSigningLaneIdentity;
    authorization: ActiveEvmFamilyWalletSessionAuthorization;
  }): Promise<EcdsaSealTransportAuthMaterial | null> {
    const resolution = await resolveActiveEcdsaCapabilityRuntime({
      walletId: args.lane.signer.walletId,
      chainTarget: args.lane.signer.chainTarget,
    });
    if (resolution.kind !== 'resolved') return null;
    const seal = ecdsaSealConfig();
    return resolveEcdsaSealTransport({
      runtime: resolution.runtime,
      auth: args.authorization,
      groupId: seal.groupId,
    });
  }

  return {
    getWarmSession,
    getEcdsaCapabilityForLane,
    resolveEcdsaSealTransportForLane,
  };
}
