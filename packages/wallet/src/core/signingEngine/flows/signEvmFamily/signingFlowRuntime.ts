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
  attachExactEcdsaWalletSessionAuthorization,
  buildActiveWalletAuthorityReadySecp256k1Material,
  resolveHydratedSecp256k1SigningMaterial,
} from './readySecp256k1Material';
import { resolveExactEcdsaCapabilityRuntime } from '../../session/material/activeEcdsaCapabilityRuntime';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import {
  walletAuthAuthoritiesMatch,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { SignerAuthMethod } from '@shared/utils/signerDomain';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetsEqual } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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
  ExactEvmFamilyWalletSessionAuthorization,
  CanonicalEvmFamilyEcdsaSigningCapability,
} from '../../session/material/ecdsaSigningCapability';
import { authorizeEvmFamilyEcdsaSigningCapability } from '../../session/material/ecdsaSigningCapability';
import type { ActiveEcdsaCapabilityManifest } from '../../session/material/ecdsaCapabilityManifest';
import type { OperationDigestSet } from '@shared/authorization/operationFingerprint';
import {
  resolveActiveWalletAuthorityEcdsaRuntimeV1,
  type ActiveWalletAuthorityEcdsaSigningAuthPlan,
  type ActiveWalletAuthorityEcdsaRuntimeV1,
} from '../../session/material/activeWalletAuthorityEcdsaRuntime';
import type { TransactionSigningIntent } from '../../session/operationState/transactionState';

export type ActiveWalletAuthorityEvmFamilyFlowRuntime = {
  readonly runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
  readonly intent: TransactionSigningIntent;
  readonly confirmationAuthPlan: ActiveWalletAuthorityEcdsaSigningAuthPlan;
};

export function buildActiveWalletAuthorityConfirmationAuthPlan(
  runtime: ActiveWalletAuthorityEcdsaRuntimeV1,
): ActiveWalletAuthorityEcdsaSigningAuthPlan {
  return {
    kind: 'active_wallet_authority',
    method: runtime.auth.kind,
    accountId: String(runtime.walletId),
    intent: 'transaction_sign',
    curve: 'ecdsa',
    walletSessionId: runtime.operationCredential.walletSessionId,
    authorityId: runtime.authorityId,
    authMethodId: runtime.walletAuthMethodId,
    expiresAtMs: runtime.session.expiresAtMs,
  };
}

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

async function resolveCurrentActiveWalletAuthorityRuntime(args: {
  readonly prepared: ActiveWalletAuthorityEcdsaRuntimeV1;
  readonly signer: ReturnType<typeof requireEvmFamilyEcdsaSigner>;
}): Promise<ActiveWalletAuthorityEcdsaRuntimeV1> {
  const current = await resolveActiveWalletAuthorityEcdsaRuntimeV1({
    walletId: args.signer.walletId,
    chainTarget: args.signer.chainTarget,
    requiredCapability: 'sign',
    materialActivation: args.signer.materialActivation,
    nowMs: Date.now(),
  });
  if (current.kind !== 'resolved') {
    throw new Error(`[SigningEngine] active Wallet Authority ECDSA runtime is ${current.reason}`);
  }
  const runtime = current.runtime;
  if (
    runtime.authorityId !== args.prepared.authorityId ||
    runtime.walletAuthMethodId !== args.prepared.walletAuthMethodId ||
    runtime.authorityDigestB64u !== args.prepared.authorityDigestB64u ||
    runtime.authorityRevocationEpoch !== args.prepared.authorityRevocationEpoch ||
    runtime.walletSessionId !== args.prepared.walletSessionId ||
    runtime.publicFacts.keyHandle !== args.signer.keyHandle
  ) {
    throw new Error('[SigningEngine] active Wallet Authority ECDSA runtime was replaced');
  }
  return runtime;
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
  preparedAuthorization: ExactEvmFamilyWalletSessionAuthorization;
  currentAuthorization: ExactEvmFamilyWalletSessionAuthorization | null;
  materialActivation: EvmFamilyEcdsaMaterialActivation;
}): SupersededEcdsaSigningMaterial | null {
  const prepared = args.preparedAuthorization;
  const current = args.currentAuthorization;
  if (
    current &&
    prepared.selectedAuthority.authorityId === current.selectedAuthority.authorityId &&
    prepared.selectedAuthMethod.kind === current.selectedAuthMethod.kind &&
    prepared.selectedAuthMethod.walletAuthMethodId ===
      current.selectedAuthMethod.walletAuthMethodId &&
    prepared.session.walletId === current.session.walletId &&
    prepared.session.authorityId === current.session.authorityId &&
    prepared.session.authMethodId === current.session.authMethodId &&
    prepared.session.authorizationId === current.session.authorizationId &&
    prepared.session.quotaId === current.session.quotaId &&
    prepared.session.authorityDigestB64u === current.session.authorityDigestB64u &&
    prepared.session.authorityRevocationEpoch === current.session.authorityRevocationEpoch &&
    prepared.operationCredential.walletSessionId === current.operationCredential.walletSessionId &&
    prepared.operationCredential.token === current.operationCredential.token &&
    thresholdEcdsaChainTargetsEqual(prepared.runtime.chainTarget, current.runtime.chainTarget) &&
    mpcMaterialActivationRefsEqual(
      prepared.runtime.materialActivation,
      current.runtime.materialActivation,
    ) &&
    prepared.runtime.sealedRecord.authMethod === current.runtime.sealedRecord.authMethod &&
    prepared.runtime.sealedRecord.storeKey === current.runtime.sealedRecord.storeKey &&
    prepared.runtime.sealedRecord.thresholdSessionId ===
      current.runtime.sealedRecord.thresholdSessionId &&
    prepared.runtime.authBinding.kind === current.runtime.authBinding.kind &&
    ((prepared.runtime.authBinding.kind === 'email_otp' &&
      current.runtime.authBinding.kind === 'email_otp' &&
      walletAuthAuthoritiesMatch(
        prepared.runtime.authBinding.emailOtpAuthority,
        current.runtime.authBinding.emailOtpAuthority,
      )) ||
      (prepared.runtime.authBinding.kind === 'passkey' &&
        current.runtime.authBinding.kind === 'passkey' &&
        prepared.runtime.authBinding.rpId === current.runtime.authBinding.rpId &&
        prepared.runtime.authBinding.credentialIdB64u ===
          current.runtime.authBinding.credentialIdB64u)) &&
    mpcMaterialActivationRefsEqual(current.runtime.materialActivation, args.materialActivation)
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
  preparedAuthorization: ExactEvmFamilyWalletSessionAuthorization | null;
  currentAuthorization: ExactEvmFamilyWalletSessionAuthorization | null;
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
      material: attachExactEcdsaWalletSessionAuthorization({
        material: resolution.material,
        capability: args.capability,
        authorization: args.currentAuthorization,
        nowMs: Date.now(),
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
  // The exact material identity, whether or not an exact Wallet Session
  // authorizes it. Everything below is resolved from wallet, chain target and
  // material activation.
  getEcdsaSigningLaneIdentity: () => ExactEcdsaSigningLaneIdentity;
  activeWalletAuthority?: ActiveWalletAuthorityEvmFamilyFlowRuntime;
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
  if (args.activeWalletAuthority && !resolvedSigner) {
    throw new Error(
      '[SigningEngine] active Wallet Authority runtime requires a threshold ECDSA signer',
    );
  }
  const capability =
    resolvedSigner && !args.activeWalletAuthority
      ? await args.deps.resolveCanonicalEcdsaSigningCapability({
          walletId: resolvedSigner.walletId,
          chainTarget: resolvedSigner.chainTarget,
          materialActivation: resolvedSigner.materialActivation,
        })
      : undefined;
  const activeAuthorization =
    resolvedSigner && !args.activeWalletAuthority
      ? await args.deps.resolveActiveEcdsaWalletSessionAuthorization({
          walletId: resolvedSigner.walletId,
          chainTarget: resolvedSigner.chainTarget,
          materialActivation: resolvedSigner.materialActivation,
        })
      : null;
  const exactOperationCredentialScope =
    resolvedSigner && capability && !args.activeWalletAuthority
      ? {
          walletId: resolvedSigner.walletId,
          chainTarget: resolvedSigner.chainTarget,
          materialActivation: resolvedSigner.materialActivation,
        }
      : undefined;
  const thresholdEcdsaStepUpRuntime: EvmFamilyThresholdEcdsaStepUpRuntime | undefined =
    !args.activeWalletAuthority && capability && exactOperationCredentialScope
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
              const nowMs = Date.now();
              const currentAuthorization =
                await args.deps.resolveActiveEcdsaWalletSessionAuthorization(
                  exactOperationCredentialScope,
                );
              if (!currentAuthorization) {
                throw new Error('[SigningEngine] exact ECDSA Wallet Session is unavailable');
              }
              if (
                !mpcMaterialActivationRefsEqual(
                  currentAuthorization.runtime.materialActivation,
                  exactOperationCredentialScope.materialActivation,
                )
              ) {
                throw new Error('[SigningEngine] exact ECDSA Wallet Session material changed');
              }
              const authorized = authorizeEvmFamilyEcdsaSigningCapability({
                capability,
                authorization: currentAuthorization,
                nowMs,
              });
              return await authorizeEvmFamilyEcdsaOperationStepUp({
                relayerUrl,
                authority: capability.authority,
                authorization,
                prepared,
                material,
                walletSessionToken: authorized.authorization.operationCredential.token,
              });
            },
          },
          ...(args.onAuthSideEffectStarted
            ? { onAuthSideEffectStarted: args.onAuthSideEffectStarted }
            : {}),
        }
      : undefined;

  const secp256k1Engine = new Secp256k1Engine({
    getRpId: () => ctx.touchIdPrompt.getRpId(),
    workerCtx,
    shouldAbort: args.shouldAbort,
  });
  const activeWalletAuthority = args.activeWalletAuthority;
  const activeWalletAuthorityAuthorization =
    activeWalletAuthority && resolvedSigner
      ? {
          kind: 'active_wallet_authority' as const,
          confirmationAuthPlan: activeWalletAuthority.confirmationAuthPlan,
          sign: async (input: {
            readonly requestId: string;
            readonly operationId: string;
            readonly operationDigests: OperationDigestSet;
            readonly signingDigest32: Uint8Array;
          }) => {
            if (String(activeWalletAuthority.intent.operationId) !== input.operationId) {
              throw new Error(
                '[SigningEngine] active Wallet Authority signing operation identity changed',
              );
            }
            return await runSerializedEcdsaMaterialUse(
              {
                deps: args.deps,
                walletId: resolvedSigner.walletId,
                materialActivation: resolvedSigner.materialActivation,
                ...(args.shouldAbort ? { shouldAbort: args.shouldAbort } : {}),
              },
              async () => {
                const runtime = await resolveCurrentActiveWalletAuthorityRuntime({
                  prepared: activeWalletAuthority.runtime,
                  signer: resolvedSigner,
                });
                const readyMaterial = buildActiveWalletAuthorityReadySecp256k1Material({
                  authorityRuntime: runtime,
                  chainTarget: resolvedSigner.chainTarget,
                  relayerUrl,
                });
                return await secp256k1Engine.signReady(
                  {
                    kind: 'digest',
                    algorithm: 'secp256k1',
                    digest32: input.signingDigest32,
                  },
                  readyMaterial,
                  {
                    intent: activeWalletAuthority.intent,
                    authPlan: activeWalletAuthority.confirmationAuthPlan,
                  },
                  input.operationDigests,
                );
              },
            );
          },
        }
      : undefined;

  const flowArgs = {
    ctx,
    touchConfirm: args.deps.touchConfirm,
    workerCtx,
    walletId,
    onEvent: args.onEvent,
    engines: {
      secp256k1: secp256k1Engine,
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
                ? await args.deps.resolveActiveEcdsaWalletSessionAuthorization({
                    walletId: resolvedSigner.walletId,
                    chainTarget: resolvedSigner.chainTarget,
                    materialActivation: resolvedSigner.materialActivation,
                  })
                : null,
              walletId: resolvedSigner.walletId,
              chainTarget: resolvedSigner.chainTarget,
              materialActivation: resolvedSigner.materialActivation,
              relayerUrl,
              workerCtx,
            }),
        }
      : {}),
    ...(activeWalletAuthorityAuthorization
      ? { authorization: activeWalletAuthorityAuthorization }
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
