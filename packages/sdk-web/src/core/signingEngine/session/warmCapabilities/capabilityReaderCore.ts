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
import type { ThresholdSessionSealTransportAuthMaterial } from '../persistence/records';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../../flows/signEvmFamily/ecdsaSigningCapability';
import {
  readWarmSessionCapabilityRecordsForWallet,
} from './store';
import {
  deriveEcdsaCapabilityState,
  deriveEd25519CapabilityState,
  resolveEcdsaSealTransport,
  resolveEd25519AuthMaterial,
  type WarmSessionReadPorts,
} from './readModel';
import { assertWarmSessionEnvelopeInvariant } from './types';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { warmClaimFromRecordPolicy } from '../availability/readiness';
import type {
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519AuthMaterial,
  WarmSessionEd25519CapabilityState,
  WarmSessionEnvelope,
  WarmSessionPrfClaim,
} from './types';
import type { WarmSigningStatusReader } from './statusReader';

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
  touchConfirm: WarmSessionReadPorts | null;
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
  }) => Promise<ThresholdSessionSealTransportAuthMaterial | null>;
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
    sessionId: resolution.runtime.sealedRecord.thresholdSessionId,
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

  function buildEd25519CapabilityState(args: {
    record: WarmSessionEd25519CapabilityState['record'];
    auth: WarmSessionEd25519AuthMaterial | null;
    prfClaim: WarmSessionEd25519CapabilityState['prfClaim'];
  }): WarmSessionEd25519CapabilityState {
    const state = deriveEd25519CapabilityState(args);
    if (!args.record) {
      return {
        capability: 'ed25519',
        record: null,
        auth: null,
        prfClaim: null,
        state: 'missing',
      };
    }
    if (state === 'missing') {
      throw new Error(
        '[WarmSessionStore] Ed25519 capability state cannot be missing with a record',
      );
    }
    if (args.record.source === 'email_otp') {
      if (!args.record.emailOtpAuthContext) {
        throw new Error(
          '[WarmSessionStore] Email OTP Ed25519 capability requires emailOtpAuthContext',
        );
      }
      if (state === 'auth_missing') {
        return {
          capability: 'ed25519',
          record: args.record,
          auth: args.auth?.walletSessionJwtSource === 'none' ? args.auth : null,
          prfClaim: args.prfClaim,
          emailOtpAuthContext: args.record.emailOtpAuthContext,
          state,
        };
      }
      if (!args.auth || args.auth.walletSessionJwtSource !== 'ed25519_record') {
        throw new Error(
          `[WarmSessionStore] Ed25519 capability state=${state} requires Wallet Session JWT auth`,
        );
      }
      return {
        capability: 'ed25519',
        record: args.record,
        auth: args.auth,
        prfClaim: args.prfClaim,
        emailOtpAuthContext: args.record.emailOtpAuthContext,
        state,
      };
    }
    if (state === 'auth_missing') {
      return {
        capability: 'ed25519',
        record: args.record,
        auth: args.auth?.walletSessionJwtSource === 'none' ? args.auth : null,
        prfClaim: args.prfClaim,
        state,
      };
    }
    if (!args.auth || args.auth.walletSessionJwtSource !== 'ed25519_record') {
      throw new Error(
        `[WarmSessionStore] Ed25519 capability state=${state} requires Wallet Session JWT auth`,
      );
    }
    return {
      capability: 'ed25519',
      record: args.record,
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
      auth:
        authBinding.kind === 'email_otp'
          ? { kind: 'email_otp', providerSubjectId: authBinding.providerSubjectId }
          : {
              kind: 'passkey',
              rpId: toRpId(authBinding.rpId),
              credentialIdB64u: authBinding.credentialIdB64u,
            },
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
    const records = readWarmSessionCapabilityRecordsForWallet(normalizedWalletId);

    const ed25519Auth = resolveEd25519AuthMaterial(records.ed25519);
    // Material and authorization are resolved independently: authorization is
    // read unconditionally, so a wallet with durable material and no active
    // Wallet Session reaches authorization_required instead of being gated out
    // by a material precondition.
    const [ed25519Claim, ecdsaAuthorization, evmResolution, tempoResolution] = await Promise.all([
      deps.statusReader.readEd25519WarmSessionClaim(records.ed25519),
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
    return assertWarmSessionEnvelopeInvariant({
      walletId: normalizedWalletId,
      capabilities: {
        ed25519: buildEd25519CapabilityState({
          record: records.ed25519,
          auth: ed25519Auth,
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
  }): Promise<ThresholdSessionSealTransportAuthMaterial | null> {
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
