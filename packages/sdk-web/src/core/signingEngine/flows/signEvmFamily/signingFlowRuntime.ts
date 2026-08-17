import type {
  SigningSessionPlan,
  SigningOperationContext,
} from '../../session/operationState/types';
import type { SigningOperationTransitionObserver } from '../shared/signingStateMachine';
import type { EvmFamilySigningDeps } from '../../interfaces/operationDeps';
import type { EvmFamilyLifecycleEventCallback, EvmFamilySenderSignatureAlgorithm } from './types';
import { loadSecp256k1EngineCtor, loadWebAuthnP256EngineCtor } from './signerLoader';
import type { EcdsaSigningMaterialPlan, SupersededEcdsaSigningMaterial } from './signingFlow';
import type { EvmFamilyThresholdEcdsaStepUpRuntime } from './requireEvmFamilyStepUpAuth';
import type { EvmFamilySigningAuthSideEffect } from './freshAuthRetryPolicy';
import {
  attachReusableEcdsaWalletSessionAuthorization,
  resolveHydratedSecp256k1SigningMaterial,
} from './readySecp256k1Material';
import { resolveExactEcdsaCapabilityRuntime } from '../../session/material/activeEcdsaCapabilityRuntime';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { SignerAuthMethod } from '@shared/utils/signerDomain';
import {
  walletSessionAuthorizations,
  walletSessionAuthorizationIdForCurve,
  walletSessionTokenForCurve,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EvmSigningRequest } from '../../chains/evm/evmSigning.types';
import type { TempoSigningRequest } from '../../chains/tempo/tempoSigning.types';
import { requireEvmFamilyEcdsaSigner } from '../../session/identity/exactSigningLaneIdentity';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';

/** The exact material activation the signer binding names. Signing serializes
 * per activation, so this is the only identity the runtime needs — no selected
 * lane, and therefore no authorization. */
type EvmFamilyEcdsaMaterialActivation = ReturnType<
  typeof requireEvmFamilyEcdsaSigner
>['materialActivation'];
import {
  authorizeEvmFamilyEcdsaOperationStepUp,
  prepareEvmFamilyEcdsaOperationStepUp,
} from './thresholdAdmission';
import { emitEvmFamilySigningOperationTrace } from './events';
import { resolveThresholdEcdsaSigningQueueKey } from '../../threshold/ecdsa/signingQueue';
import type {
  ActiveEvmFamilyWalletSessionAuthorization,
  CanonicalEvmFamilyEcdsaSigningCapability,
} from '../../session/material/ecdsaSigningCapability';
import type { ActiveEcdsaCapabilityManifest } from '../../session/material/ecdsaCapabilityManifest';

function signerAuthMethodForWalletAuthority(authority: WalletAuthAuthority): SignerAuthMethod {
  switch (authority.factor.kind) {
    case 'passkey':
      return 'passkey';
    case 'email_otp':
      return 'email_otp';
    default:
      authority.factor satisfies never;
      throw new Error('[SigningEngine] unsupported wallet authorization factor');
  }
}

async function runSerializedEcdsaMaterialUse<T>(
  args: {
    deps: EvmFamilySigningDeps;
    walletId: WalletId;
    materialActivation: EvmFamilyEcdsaMaterialActivation;
    shouldAbort?: () => boolean;
  },
  task: () => Promise<T>,
): Promise<T> {
  return await args.deps.withThresholdEcdsaSigningQueue({
    queueKey: resolveThresholdEcdsaSigningQueueKey({
      materialActivation: args.materialActivation,
    }),
    walletId: args.walletId,
    enabled: true,
    ...(args.shouldAbort ? { shouldAbort: args.shouldAbort } : {}),
    task,
  });
}

function requireEvmFamilyRelayerUrl(deps: EvmFamilySigningDeps): string {
  const relayerUrl = String(deps.seamsWebConfigs.network.relayer?.url || '').trim();
  if (!relayerUrl) {
    throw new Error('[SigningEngine] EVM-family signing requires relayerUrl');
  }
  return relayerUrl;
}

async function readPersistedOwnerWalletSessionToken(walletId: WalletId): Promise<string | null> {
  const read = await walletSessionAuthorizations.readActiveForWallet(walletId);
  if (read.kind !== 'found') return null;
  return (
    walletSessionTokenForCurve(read.projection, 'ecdsa') ??
    walletSessionTokenForCurve(read.projection, 'ed25519')
  );
}

/** R90-INV-010. The wallet's active manifest names the material that may be
 * used right now. When it has moved on from the one this operation was prepared
 * against, the preparation is superseded -- material activation is advance-only,
 * so the prepared side is always the stale one. That is a re-resolution, not a
 * failure and not a request for the wrong material. */
export function ecdsaSigningMaterialSupersession(args: {
  preparedMaterialActivation: EvmFamilyEcdsaMaterialActivation;
  currentMaterialActivation: EvmFamilyEcdsaMaterialActivation;
}): SupersededEcdsaSigningMaterial | null {
  if (
    mpcMaterialActivationRefsEqual(args.currentMaterialActivation, args.preparedMaterialActivation)
  ) {
    return null;
  }
  return {
    kind: 'superseded',
    supersessionKind: 'material_activation_replaced',
    preparedMaterialActivation: args.preparedMaterialActivation,
    currentMaterialActivation: args.currentMaterialActivation,
  };
}

export function ecdsaSigningCapabilitySupersession(args: {
  preparedCapability: CanonicalEvmFamilyEcdsaSigningCapability;
  currentManifest: ActiveEcdsaCapabilityManifest;
}): SupersededEcdsaSigningMaterial | null {
  const preparedManifest = args.preparedCapability.manifest;
  const preparedActivation = preparedManifest.activation.materialActivation;
  const currentActivation = args.currentManifest.activation.materialActivation;
  const activationSupersession = ecdsaSigningMaterialSupersession({
    preparedMaterialActivation: preparedActivation,
    currentMaterialActivation: currentActivation,
  });
  if (activationSupersession) return activationSupersession;
  const preparedSigner = preparedManifest.signer;
  const currentSigner = args.currentManifest.signer;
  if (
    String(preparedManifest.identity.manifestId) ===
      String(args.currentManifest.identity.manifestId) &&
    Number(preparedManifest.identity.manifestRevision) ===
      Number(args.currentManifest.identity.manifestRevision) &&
    String(preparedSigner.capability) === String(currentSigner.capability) &&
    String(preparedSigner.authority.walletId) === String(currentSigner.authority.walletId) &&
    String(preparedSigner.authority.authorityDigest) ===
      String(currentSigner.authority.authorityDigest)
  ) {
    return null;
  }
  return {
    kind: 'superseded',
    supersessionKind: 'capability_authority_replaced',
    preparedMaterialActivation: preparedActivation,
    currentMaterialActivation: currentActivation,
  };
}

export function ecdsaSigningAuthorizationSupersession(args: {
  preparedAuthorization: ActiveEvmFamilyWalletSessionAuthorization;
  currentAuthorization: ActiveEvmFamilyWalletSessionAuthorization | null;
  materialActivation: EvmFamilyEcdsaMaterialActivation;
}): SupersededEcdsaSigningMaterial | null {
  const prepared = args.preparedAuthorization.projection;
  const currentAuthorization = args.currentAuthorization;
  const current = currentAuthorization?.projection;
  const preparedAuthorizationId = walletSessionAuthorizationIdForCurve(prepared, 'ecdsa');
  const currentAuthorizationId = current
    ? walletSessionAuthorizationIdForCurve(current, 'ecdsa')
    : null;
  if (
    currentAuthorization &&
    current &&
    String(current.walletId) === String(prepared.walletId) &&
    String(current.walletSessionId) === String(prepared.walletSessionId) &&
    currentAuthorizationId !== null &&
    currentAuthorizationId === preparedAuthorizationId &&
    String(current.quotaId) === String(prepared.quotaId) &&
    String(currentAuthorization.status.walletSessionId) ===
      String(args.preparedAuthorization.status.walletSessionId) &&
    String(currentAuthorization.status.quotaId) ===
      String(args.preparedAuthorization.status.quotaId) &&
    String(current.authority.authorityDigest) === String(prepared.authority.authorityDigest)
  ) {
    return null;
  }
  return {
    kind: 'superseded',
    supersessionKind: 'reusable_authorization_replaced',
    preparedMaterialActivation: args.materialActivation,
    currentMaterialActivation: args.materialActivation,
  };
}

async function resolveEcdsaSigningMaterialHydrationPlan(args: {
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  preparedAuthorization: ActiveEvmFamilyWalletSessionAuthorization | null;
  currentAuthorization: ActiveEvmFamilyWalletSessionAuthorization | null;
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  materialActivation: EvmFamilyEcdsaMaterialActivation;
  relayerUrl: string;
  workerCtx: ReturnType<EvmFamilySigningDeps['getSignerWorkerContext']>;
}): Promise<EcdsaSigningMaterialPlan> {
  // Resolve the active capability material first. Reusable authorization is
  // checked separately; without it, the hydrated material requires operation
  // step-up authorization.
  const activeRuntimeResolution = await resolveExactEcdsaCapabilityRuntime({
    manifest: args.capability.manifest,
    chainTarget: args.chainTarget,
    relayerUrl: args.relayerUrl,
  });
  if (activeRuntimeResolution.kind !== 'resolved') {
    return {
      kind: 'failed',
      failure: { kind: 'unavailable', reason: 'runtime_correlation_mismatch' },
    };
  }
  const superseded = ecdsaSigningCapabilitySupersession({
    preparedCapability: args.capability,
    currentManifest: activeRuntimeResolution.manifest,
  });
  if (superseded) return { kind: 'superseded', replacement: superseded };
  if (args.preparedAuthorization) {
    const authorizationSupersession = ecdsaSigningAuthorizationSupersession({
      preparedAuthorization: args.preparedAuthorization,
      currentAuthorization: args.currentAuthorization,
      materialActivation: args.materialActivation,
    });
    if (authorizationSupersession) {
      return { kind: 'superseded', replacement: authorizationSupersession };
    }
  }
  const resolution = await resolveHydratedSecp256k1SigningMaterial({
    capability: args.capability,
    runtime: activeRuntimeResolution.runtime,
    chainTarget: args.chainTarget,
    materialActivation: args.materialActivation,
    workerCtx: args.workerCtx,
  });
  if (resolution.kind === 'unavailable') {
    return { kind: 'failed', failure: resolution };
  }
  if (!args.preparedAuthorization) {
    return {
      kind: 'authorization_required',
      requirement: {
        kind: 'material_for_step_up',
        material: resolution.material,
      },
    };
  }
  if (!args.currentAuthorization) {
    return {
      kind: 'superseded',
      replacement: {
        kind: 'superseded',
        supersessionKind: 'reusable_authorization_replaced',
        preparedMaterialActivation: args.materialActivation,
        currentMaterialActivation: args.materialActivation,
      },
    };
  }
  return {
    kind: 'ready',
    value: {
      kind: 'material_from_canonical_capability',
      material: attachReusableEcdsaWalletSessionAuthorization({
        material: resolution.material,
        capability: args.capability,
        authorization: args.currentAuthorization,
      }),
    },
  };
}

export async function createEvmFamilySigningFlowRuntime(args: {
  deps: EvmFamilySigningDeps;
  walletSession: WalletSessionRef;
  request: TempoSigningRequest | EvmSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  signingSessionPlan?: SigningSessionPlan;
  emailOtpSigningForFlow?: EvmFamilyThresholdEcdsaStepUpRuntime['emailOtpSigning'];
  confirmationConfigOverride?: unknown;
  shouldAbort?: () => boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
  onAuthSideEffectStarted?: (sideEffect: EvmFamilySigningAuthSideEffect) => void;
  signingOperation?: SigningOperationContext;
  onSigningOperationTransition?: SigningOperationTransitionObserver;
  // The exact material identity, whether or not a reusable Wallet Session
  // authorizes it. Everything below is resolved from wallet, chain target and
  // material activation.
  getEcdsaSigningLaneIdentity: () => ExactEcdsaSigningLaneIdentity;
}) {
  const [Secp256k1Engine, WebAuthnP256Engine] = await Promise.all([
    loadSecp256k1EngineCtor(),
    loadWebAuthnP256EngineCtor(),
  ]);
  const workerCtx = args.deps.getSignerWorkerContext();
  const ctx = args.deps.touchConfirm.getContext();
  const walletId = toWalletId(args.walletSession.walletId);
  const relayerUrl = requireEvmFamilyRelayerUrl(args.deps);

  const resolvedSigner =
    args.senderSignatureAlgorithm === 'secp256k1'
      ? requireEvmFamilyEcdsaSigner(
          args.getEcdsaSigningLaneIdentity(),
          'ECDSA signing material hydration',
        )
      : undefined;
  const capability = resolvedSigner
    ? await args.deps.resolveCanonicalEcdsaSigningCapability({
        walletId: resolvedSigner.walletId,
        chainTarget: resolvedSigner.chainTarget,
        materialActivation: resolvedSigner.materialActivation,
      })
    : undefined;
  const activeAuthorization = resolvedSigner
    ? await args.deps.resolveActiveEcdsaWalletSessionAuthorization(resolvedSigner.walletId)
    : null;
  const persistedOwnerWalletSessionToken = resolvedSigner
    ? readPersistedOwnerWalletSessionToken(resolvedSigner.walletId)
    : Promise.resolve(null);
  const thresholdEcdsaStepUpRuntime: EvmFamilyThresholdEcdsaStepUpRuntime | undefined = capability
    ? {
        ...(args.emailOtpSigningForFlow ? { emailOtpSigning: args.emailOtpSigningForFlow } : {}),
        // Without an active reusable Wallet Session the candidate is
        // auth-neutral, so the operation must be authorized by a step-up on
        // the capability's own factor rather than a warm session.
        reusableAuthorization: activeAuthorization
          ? { kind: 'active' }
          : {
              kind: 'absent',
              requiredFactor: signerAuthMethodForWalletAuthority(capability.authority),
            },
        operationStepUp: {
          prepare: async ({ operation, operationDigests, material }) =>
            await prepareEvmFamilyEcdsaOperationStepUp({
              operation,
              operationDigests,
              material,
            }),
          authorize: async ({ authorization, prepared, material }) => {
            args.onAuthSideEffectStarted?.(
              authorization.kind === 'passkey' ? 'passkey_reauth' : 'email_otp_challenge',
            );
            const walletSessionToken = await persistedOwnerWalletSessionToken;
            if (!walletSessionToken) {
              throw new Error(
                '[SigningEngine] ECDSA operation step-up requires an opaque owner Wallet Session',
              );
            }
            return await authorizeEvmFamilyEcdsaOperationStepUp({
              relayerUrl,
              authority: capability.authority,
              authorization,
              prepared,
              material,
              walletSessionToken,
            });
          },
        },
        ...(args.onAuthSideEffectStarted
          ? { onAuthSideEffectStarted: args.onAuthSideEffectStarted }
          : {}),
      }
    : undefined;

  const flowArgs = {
    ctx,
    touchConfirm: args.deps.touchConfirm,
    workerCtx,
    walletId,
    onEvent: args.onEvent,
    engines: {
      secp256k1: new Secp256k1Engine({
        getRpId: () => ctx.touchIdPrompt.getRpId(),
        workerCtx,
        shouldAbort: args.shouldAbort,
      }),
      webauthnP256: new WebAuthnP256Engine(workerCtx),
    },
    ...(resolvedSigner && capability
      ? {
          runEcdsaMaterialUse: runSerializedEcdsaMaterialUse.bind(null, {
            deps: args.deps,
            walletId: resolvedSigner.walletId,
            materialActivation: resolvedSigner.materialActivation,
            ...(args.shouldAbort ? { shouldAbort: args.shouldAbort } : {}),
          }),
          resolveEcdsaSigningMaterialPlan: async () =>
            await resolveEcdsaSigningMaterialHydrationPlan({
              capability,
              preparedAuthorization: activeAuthorization,
              currentAuthorization: activeAuthorization
                ? await args.deps.resolveActiveEcdsaWalletSessionAuthorization(
                    resolvedSigner.walletId,
                  )
                : null,
              walletId: resolvedSigner.walletId,
              chainTarget: resolvedSigner.chainTarget,
              materialActivation: resolvedSigner.materialActivation,
              relayerUrl,
              workerCtx,
            }),
        }
      : {}),
    ...(args.signingSessionPlan ? { signingSessionPlan: args.signingSessionPlan } : {}),
    ...(args.signingOperation ? { signingOperation: args.signingOperation } : {}),
    onSigningOperationTransition:
      args.onSigningOperationTransition || emitEvmFamilySigningOperationTrace,
    ...(thresholdEcdsaStepUpRuntime ? { thresholdEcdsaStepUpRuntime } : {}),
    confirmationConfigOverride: args.confirmationConfigOverride,
  };

  return { flowArgs };
}
