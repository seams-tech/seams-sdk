import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import type { NonceCoordinator, PreparedNonceOperationContext } from '../../nonce/NonceCoordinator';
import type { EvmSigningRequest } from '../../chains/evm/evmSigning.types';
import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import { buildEvmDisplayModel } from '../../chains/evm/display/evmTx';
import type { TempoSigningRequest } from '../../chains/tempo/tempoSigning.types';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import { buildTempoDisplayModel } from '../../chains/tempo/display';
import type { TxDisplayModel } from '../../interfaces/display';
import type {
  ReadAvailableSigningLanesForSigningInput,
  AvailableSigningLanes,
} from '../../session/availability/availableSigningLanes';
import type { RestorePersistedSessionForSigningInput } from '../../session/sealedRecovery/sealedRecovery.types';
import { type ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import {
  exactEcdsaSigningLaneIdentityFromSelectedLane,
  requireEvmFamilyEcdsaSigner,
  type ExactEcdsaSigningLaneIdentity,
} from '../../session/identity/exactSigningLaneIdentity';
import { isEvmFamilyEcdsaMaterialSupersededError } from './signingFlow';
import type {
  UiConfirmContextPort,
  UiConfirmSigningPort,
  UiConfirmRequestConfirmationPort,
  WarmSessionStatusResult,
  WarmSessionStatusReader,
} from '../../uiConfirm/uiConfirm.types';
import type { SignerWorkerManagerContext } from '../../workerManager/SignerWorkerManager';
import {
  assertSameSigningLaneIdentity,
  SigningOperationIntent,
  type SigningOperationFingerprint,
  type SigningOperationId,
} from '../../session/operationState/types';
import {
  emitSigningSessionFlowFailure,
  emitSigningSessionFlowTrace,
} from '../../session/operationState/trace';
import {
  computeSigningOperationFingerprint,
  parseSigningOperationFingerprintDigest,
} from '../../session/planning/operationFingerprint';
import {
  buildOperationAuthorizationQueueKey,
  type OperationAuthorizationQueueKey,
} from '../../session/operationState/authorizationAdmission';
import { signingLaneAuthBindingKey } from '../../session/identity/signingLaneAuthBinding';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import { ensureSealedRefreshStartupParityForTransactionSigning } from '../../session/warmCapabilities/sealedRefreshParity';
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';
import { walletSessionAuthorizationIdForCurve } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  evmFamilySigningTargetFromExplicitTarget,
  type EvmFamilyBroadcastAcceptedArgs,
  type EvmFamilyBroadcastRejectedArgs,
  type EvmFamilyChain,
  type EvmFamilyDroppedOrReplacedArgs,
  type EvmFamilyFinalizedArgs,
  type EvmFamilyLifecycleEventCallback,
  type EvmFamilyNonceLaneStatus,
  type EvmFamilyReconcileLaneArgs,
} from './types';
import type {
  EcdsaSigningListLookupArgs,
  EcdsaSigningLookupArgs,
  EvmFamilySigningDeps,
  PasskeyEcdsaSigningLookupArgs,
} from '../../interfaces/operationDeps';
import {
  toWalletId,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { throwIfEvmFamilySigningCancelled } from './errors';
import {
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaLane,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { resolveEvmFamilyTransactionWalletAuth } from './accountAuth';
import {
  resolveEvmFamilyTransactionStepUp,
  type EvmFamilyConfirmedEmailOtpDeps,
} from './authPlanning';
import {
  prepareEvmFamilyEcdsaSigningSession,
  type AuthorizedEvmFamilyEcdsaSigningSession,
  type PreparedEvmFamilyEcdsaSigningSession,
} from './preparedSigning';
import {
  isEmailOtpSigningAuthPlan,
  isPasskeySigningAuthPlan,
} from '../../stepUpConfirmation/types';
import type { EvmFamilyThresholdEcdsaStepUp } from './requireEvmFamilyStepUpAuth';
import {
  executeEvmFamilyTransactionSigning,
  type EvmFamilyExecutorThresholdEcdsaState,
} from './transactionExecutor';

type EvmFamilyTransactionSigningOperationContext = {
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  intent: typeof SigningOperationIntent.TransactionSign;
};
import {
  buildActiveWalletAuthorityConfirmationAuthPlan,
  createEvmFamilySigningFlowRuntime,
  type ActiveWalletAuthorityEvmFamilyFlowRuntime,
} from './signingFlowRuntime';
import {
  resolveEvmFamilyWalletSessionExpiryContext,
  retryEvmFamilyWithFreshWalletSessionAuthWhenRequired,
  type EvmFamilyWalletSessionExpiryCandidate,
} from './freshWalletSessionRetry';
import {
  classifyEvmFamilyFreshAuthRetry,
  nextEvmFamilyFreshAuthRetrySideEffectState,
  runEvmFamilyFreshAuthRetry,
  type EvmFamilyAdmissionRetryState,
  type EvmFamilyFreshAuthRetryDecision,
  type EvmFamilyFreshAuthRetrySideEffectState,
  type EvmFamilySigningAuthSideEffect,
} from './freshAuthRetryPolicy';
import { emitEvmFamilySigningEvent, emitEvmFamilySigningOperationTrace } from './events';
import { requiredEvmFamilyRequestSignatureUses } from './signatureUses';
import {
  bindEvmFamilyCallerProvidedOperationIdToFingerprint,
  createEvmFamilySigningOperationIds,
  ensureEvmFamilyConfirmationOperationId,
  type EvmFamilySigningOperationIds,
} from './operationIds';
import {
  deriveEvmFamilyKeyFingerprintFromPublicFacts,
  type VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  buildPreparedEvmFamilyExecutorThresholdEcdsaState,
  type PreparedEvmFamilyPublicIdentityContinuity,
} from './executorThresholdState';
import {
  reconcileEvmFamilyNonceLane,
  reportEvmFamilyBroadcastAccepted,
  reportEvmFamilyBroadcastRejected,
  reportEvmFamilyDroppedOrReplaced,
  reportEvmFamilyFinalized,
} from './nonceLifecycleAdapter';

// Wallet Session expiry is the authorization's own fact. It used to be read
// off the composite record, which is a different clock from the one that
// actually expires.
function evmFamilyWalletSessionExpiryCandidate(args: {
  readonly prepared: PreparedEvmFamilyEcdsaSigningSession | undefined;
}): EvmFamilyWalletSessionExpiryCandidate {
  // Only a reusable Wallet Session can expire. Auth-neutral material is
  // authorized per operation, so there is no session clock to attribute a
  // failure to.
  if (!args.prepared || args.prepared.kind !== 'authorized') return { kind: 'unavailable' };
  return {
    kind: 'exact_ecdsa_lane',
    identity: exactEcdsaSigningLaneIdentityFromSelectedLane(args.prepared.signingLane),
    authorization: args.prepared.signingLane.authorization,
    expiresAtMs: args.prepared.signingLane.authorization.status.expiresAtMs,
  };
}

export type {
  EvmFamilyBroadcastAcceptedArgs,
  EvmFamilyBroadcastRejectedArgs,
  EvmFamilyDroppedOrReplacedArgs,
  EvmFamilyFinalizedArgs,
  EvmFamilyNonceLaneStatus,
  EvmFamilyReconcileLaneArgs,
} from './types';

function ecdsaOperationAuthorizationQueueKey(args: {
  walletId: string;
  prepared: AuthorizedEvmFamilyEcdsaSigningSession;
}): OperationAuthorizationQueueKey {
  const authorization = args.prepared.signingLane.authorization;
  const authorizationId = walletSessionAuthorizationIdForCurve(authorization.projection, 'ecdsa');
  if (!authorizationId) {
    throw new Error('ECDSA signing authorization has no curve-local authorization id');
  }
  return buildOperationAuthorizationQueueKey({
    walletId: args.walletId,
    materialActivationId: args.prepared.signingLane.materialActivation.activationId,
    authorizationId,
    authorityKey: signingLaneAuthBindingKey(args.prepared.signingLane.auth),
    targetKey: thresholdEcdsaChainTargetKey(args.prepared.signingLane.chainTarget),
  });
}

function activeWalletAuthorityFlowRuntimeFromPrepared(
  prepared: PreparedEvmFamilyEcdsaSigningSession,
): ActiveWalletAuthorityEvmFamilyFlowRuntime | null {
  if (
    prepared.kind !== 'authorization_required' ||
    prepared.candidate.source !== 'active_wallet_authority'
  ) {
    return null;
  }
  const confirmationAuthPlan = buildActiveWalletAuthorityConfirmationAuthPlan(
    prepared.candidate.runtime,
  );
  return {
    runtime: prepared.candidate.runtime,
    intent: prepared.intent,
    confirmationAuthPlan,
  };
}

export {
  reconcileEvmFamilyNonceLane,
  reportEvmFamilyBroadcastAccepted,
  reportEvmFamilyBroadcastRejected,
  reportEvmFamilyDroppedOrReplaced,
  reportEvmFamilyFinalized,
};

type SignEvmFamilyArgs = {
  walletSession: WalletSessionRef;
  request: TempoSigningRequest | EvmSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  shouldAbort?: () => boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
  signingOperationId?: SigningOperationId;
};

type SignEvmFamilyAttemptOptions = {
  admissionRetryState: EvmFamilyAdmissionRetryState;
  forceFreshAuth?: boolean;
  operationIds?: EvmFamilySigningOperationIds;
  retryingFreshAuth?: boolean;
  signingSessionCoordinator?: SigningSessionCoordinator;
  // Set once a supersession has already been re-resolved. Material activation
  // is advance-only, so one re-resolution reaches current state; a second
  // would mean the store is changing under every attempt.
  reResolvedAfterSupersession?: boolean;
};

function buildEvmFamilyPreparationDisplayModel(args: SignEvmFamilyArgs): TxDisplayModel {
  const title =
    args.chainTarget.kind === 'tempo' ? 'Sign Tempo Transaction' : 'Sign EVM Transaction';
  const displayArgs = {
    request: args.request,
    signerAccount: String(args.walletSession.walletId),
    title,
    subtitle: '',
  };

  if (args.request.kind === 'eip1559') {
    return buildEvmDisplayModel({ ...displayArgs, request: args.request });
  }
  return buildTempoDisplayModel({ ...displayArgs, request: args.request });
}

async function executeEvmFamilyFreshAuthRetry(args: {
  deps: EvmFamilySigningDeps;
  signingArgs: SignEvmFamilyArgs;
  decision: Extract<EvmFamilyFreshAuthRetryDecision, { kind: 'retry' }>;
  queueKey: OperationAuthorizationQueueKey;
  operationIds: EvmFamilySigningOperationIds;
  retryingFreshAuth: boolean;
  signingSessionCoordinator: SigningSessionCoordinator;
}): Promise<TempoSignedResult | EvmSignedResult> {
  const rereadAuthoritativeReadiness = signEvmFamilyAttempt.bind(
    null,
    args.deps,
    args.signingArgs,
    {
      admissionRetryState: { kind: 'authoritative_readiness_reread' },
      forceFreshAuth: false,
      operationIds: args.operationIds,
      retryingFreshAuth: args.retryingFreshAuth,
      signingSessionCoordinator: args.signingSessionCoordinator,
    },
  );
  const performFreshAuth = signEvmFamilyAttempt.bind(null, args.deps, args.signingArgs, {
    admissionRetryState: { kind: 'initial_admission' },
    forceFreshAuth: true,
    operationIds: args.operationIds,
    retryingFreshAuth: true,
    signingSessionCoordinator: args.signingSessionCoordinator,
  });
  return await runEvmFamilyFreshAuthRetry({
    decision: args.decision,
    queueKey: args.queueKey,
    signingSessionCoordinator: args.signingSessionCoordinator,
    rereadAuthoritativeReadiness,
    performFreshAuth,
  });
}

function emitEvmFamilyFreshAuthRetryEvent(args: {
  walletId: string;
  chain: EvmFamilyChain;
  accountAuth: AccountAuthMetadata;
  onEvent?: EvmFamilyLifecycleEventCallback;
}): void {
  const isEmailOtp = args.accountAuth.primaryAuthMethod === SIGNER_AUTH_METHODS.emailOtp;
  emitEvmFamilySigningEvent(args.onEvent, {
    phase: isEmailOtp
      ? SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED
      : SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
    status: 'running',
    walletId: args.walletId,
    message: isEmailOtp
      ? 'Signing session needs reauthorization; requesting Email OTP'
      : 'Signing session needs reauthorization; requesting passkey',
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: args.chain, reason: 'wallet_signing_budget_reserved' },
  });
}

export async function signEvmFamily(
  deps: EvmFamilySigningDeps,
  args: SignEvmFamilyArgs,
): Promise<TempoSignedResult | EvmSignedResult> {
  const attempt: SignEvmFamilyAttemptOptions = {
    admissionRetryState: { kind: 'initial_admission' },
    operationIds: createEvmFamilySigningOperationIds(args.signingOperationId),
  };
  await deps.touchConfirm.openTransactionPreparationModal({
    walletLabel: String(args.walletSession.walletId),
    model: buildEvmFamilyPreparationDisplayModel(args),
    confirmationConfigOverride: args.confirmationConfigOverride,
  });
  try {
    return await signEvmFamilyAttempt(deps, args, attempt);
  } finally {
    deps.touchConfirm.closeTransactionPreparationModal();
  }
}

async function signEvmFamilyAttempt(
  deps: EvmFamilySigningDeps,
  args: SignEvmFamilyArgs,
  attempt: SignEvmFamilyAttemptOptions,
): Promise<TempoSignedResult | EvmSignedResult> {
  throwIfEvmFamilySigningCancelled(args.shouldAbort);
  const walletId = toWalletId(args.walletSession.walletId);

  const signingTarget = evmFamilySigningTargetFromExplicitTarget({
    request: args.request,
    chainTarget: args.chainTarget,
  });
  const requiredSignatureUses = requiredEvmFamilyRequestSignatureUses(args.request);
  await ensureSealedRefreshStartupParityForTransactionSigning(
    deps.ensureSealedRefreshStartupParity,
    {
      walletId,
      chainTarget: signingTarget,
    },
  );
  const requestChain = signingTarget.kind;
  const requestChainTarget = signingTarget;

  let accountAuth: AccountAuthMetadata;
  let ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane | undefined;
  let selectedEcdsaAuthMethod: WalletAuthAuthority['factor']['kind'] | undefined;
  let preparedEcdsaSigningSession: PreparedEvmFamilyEcdsaSigningSession | undefined;
  let activeWalletAuthorityFlowRuntime: ActiveWalletAuthorityEvmFamilyFlowRuntime | undefined;
  const ecdsaAttemptDiagnostics: Record<string, unknown> = {
    walletId,
    chain: requestChain,
    chainTarget: requestChainTarget,
    senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
  };
  const signingSessionCoordinator =
    attempt.signingSessionCoordinator || deps.signingSessionCoordinator;
  if (!signingSessionCoordinator) {
    throw new Error('[SigningEngine][ecdsa] production signing session coordinator is required');
  }
  const operationIds =
    attempt.operationIds || createEvmFamilySigningOperationIds(args.signingOperationId);
  const operationFingerprint: SigningOperationFingerprint =
    await computeSigningOperationFingerprint({
      kind: `evm-family:${requestChain}`,
      payload: {
        walletId,
        chainTarget: requestChainTarget,
        request: args.request,
      },
    });
  const operationFingerprintDigest = parseSigningOperationFingerprintDigest(operationFingerprint);
  bindEvmFamilyCallerProvidedOperationIdToFingerprint(
    operationIds,
    operationFingerprint,
    signingSessionCoordinator,
  );
  const ensureConfirmationOperationId = (): SigningOperationId =>
    ensureEvmFamilyConfirmationOperationId(operationIds);
  const createTransactionSigningOperation = (): EvmFamilyTransactionSigningOperationContext => ({
    operationId: ensureConfirmationOperationId(),
    operationFingerprint,
    intent: SigningOperationIntent.TransactionSign,
  });
  // The key fingerprint is a property of hydrated material, which no longer
  // exists at prepare time; it is derived after canonical hydration.
  const derivePreparedEvmFamilyKeyFingerprint = (
    _prepared: PreparedEvmFamilyEcdsaSigningSession | undefined,
  ): string | undefined => undefined;
  const safePreparedPublicFactsFingerprint = (args: {
    walletId: string;
    publicFacts: VerifiedEcdsaPublicFacts;
  }): string | undefined => {
    try {
      return deriveEvmFamilyKeyFingerprintFromPublicFacts({
        walletId: args.walletId,
        publicFacts: args.publicFacts,
      });
    } catch {
      return undefined;
    }
  };
  let freshAuthRetrySideEffectState: EvmFamilyFreshAuthRetrySideEffectState =
    'no_auth_side_effect_started';
  const markFreshAuthRetrySideEffect = (sideEffect: EvmFamilySigningAuthSideEffect): void => {
    freshAuthRetrySideEffectState = nextEvmFamilyFreshAuthRetrySideEffectState({
      current: freshAuthRetrySideEffectState,
      sideEffect,
    });
  };
  const recordFreshAuthRetryDecision = (
    decision: EvmFamilyFreshAuthRetryDecision,
    error: unknown,
  ): void => {
    const errorMessage = error instanceof Error ? error.message : String(error || 'unknown error');
    ecdsaAttemptDiagnostics.freshAuthRetry = {
      decision,
      sideEffectState: freshAuthRetrySideEffectState,
      errorMessage,
    };
    emitSigningSessionFlowTrace('evm-family', {
      stage: 'fresh_auth_retry.decision',
      walletId,
      chain: requestChain,
      chainTarget: requestChainTarget,
      decision,
      sideEffectState: freshAuthRetrySideEffectState,
      errorMessage,
    });
  };
  let confirmationDisplayed = false;
  const markConfirmationDisplayed = (): SigningOperationId => {
    confirmationDisplayed = true;
    markFreshAuthRetrySideEffect('auth_prompt_shown');
    return ensureConfirmationOperationId();
  };
  if (args.request.senderSignatureAlgorithm === 'secp256k1') {
    preparedEcdsaSigningSession = await prepareEvmFamilyEcdsaSigningSession({
      deps,
      walletSession: args.walletSession,
      signingTarget,
      signingOperation: createTransactionSigningOperation(),
      diagnostics: ecdsaAttemptDiagnostics,
      signingSessionCoordinator,
      forceFreshAuth: attempt.forceFreshAuth === true,
    });
    activeWalletAuthorityFlowRuntime =
      activeWalletAuthorityFlowRuntimeFromPrepared(preparedEcdsaSigningSession) ?? undefined;
    ecdsaSigningLane =
      preparedEcdsaSigningSession.kind === 'authorized'
        ? preparedEcdsaSigningSession.signingLane
        : undefined;
    selectedEcdsaAuthMethod = preparedEcdsaSigningSession.authMethod;
    accountAuth =
      preparedEcdsaSigningSession.kind === 'authorized'
        ? preparedEcdsaSigningSession.accountAuth
        : await resolveEvmFamilyTransactionWalletAuth({
            senderSignatureAlgorithm: 'secp256k1',
            signerAuthMethod: preparedEcdsaSigningSession.authMethod,
          });
    emitSigningSessionFlowTrace('evm-family', {
      stage: 'ecdsa_attempt.prepared',
      walletId,
      chain: requestChain,
      chainTarget: requestChainTarget,
      ...(derivePreparedEvmFamilyKeyFingerprint(preparedEcdsaSigningSession)
        ? {
            evmFamilyKeyFingerprint: derivePreparedEvmFamilyKeyFingerprint(
              preparedEcdsaSigningSession,
            ),
          }
        : {}),
      authorizationState: preparedEcdsaSigningSession.kind,
      authMethod: selectedEcdsaAuthMethod,
      lane: summarizeEvmFamilyEcdsaLane(ecdsaSigningLane),
    });
  } else {
    accountAuth = await resolveEvmFamilyTransactionWalletAuth({
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
    });
  }
  const resolvedAccountAuth = accountAuth;

  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  const requestEmailOtpTransactionSigningChallenge =
    deps.requestEmailOtpTransactionSigningChallenge;
  const confirmedSigningDeps: EvmFamilyConfirmedEmailOtpDeps = {
    ...deps,
    requestEmailOtpTransactionSigningChallenge,
  };
  const authPlanningArgsBase = {
    confirmedDeps: confirmedSigningDeps,
    walletSession: args.walletSession,
    chain: requestChain,
    accountAuth: resolvedAccountAuth,
    operationFingerprintDigest,
    onEvent: args.onEvent,
  };
  const getPreparedEcdsaSigningSession = (): PreparedEvmFamilyEcdsaSigningSession => {
    if (preparedEcdsaSigningSession) return preparedEcdsaSigningSession;
    throw new Error('[SigningEngine][ecdsa] prepared signing session is required');
  };
  // The signing runtime needs the exact material identity, not a selected
  // lane: an auth-neutral candidate has the former and never the latter.
  const getEcdsaSigningLaneIdentity = (): ExactEcdsaSigningLaneIdentity => {
    const prepared = getPreparedEcdsaSigningSession();
    return prepared.kind === 'authorized' ? prepared.signingLane.identity : prepared.identity;
  };
  const getPreparedEcdsaSigningSessionIfEcdsa = ():
    | PreparedEvmFamilyEcdsaSigningSession
    | undefined =>
    args.request.senderSignatureAlgorithm === 'secp256k1'
      ? getPreparedEcdsaSigningSession()
      : undefined;
  // R90-INV-010: a superseded preparation is discarded whole and current
  // canonical state resolved again — once. Shared by the execute-phase retry
  // ladder below and the pre-execute wrap, because capability resolution
  // during auth planning and runtime creation can hit the replacement race
  // before the executor's catch exists.
  const reResolveSupersededPreparation = async (
    error: unknown,
  ): Promise<TempoSignedResult | EvmSignedResult | null> => {
    if (!isEvmFamilyEcdsaMaterialSupersededError(error)) return null;
    if (attempt.reResolvedAfterSupersession) return null;
    emitSigningSessionFlowTrace('evm-family', {
      stage: 'ecdsa_attempt.material_superseded',
      walletId,
      chain: requestChain,
      chainTarget: requestChainTarget,
      supersessionKind: error.superseded.supersessionKind,
      preparedMaterialActivationId: String(
        error.superseded.preparedMaterialActivation.activationId,
      ),
      currentMaterialActivationId: String(error.superseded.currentMaterialActivation.activationId),
    });
    return await signEvmFamilyAttempt(deps, args, {
      admissionRetryState: { kind: 'initial_admission' },
      operationIds,
      signingSessionCoordinator,
      reResolvedAfterSupersession: true,
      ...(attempt.retryingFreshAuth ? { retryingFreshAuth: true } : {}),
    });
  };
  const resolveAuthPlanningResult = async () =>
    args.request.senderSignatureAlgorithm === 'secp256k1'
      ? await (async () => {
          const prepared = getPreparedEcdsaSigningSession();
          if (activeWalletAuthorityFlowRuntime) {
            return {
              signingAuthPlan: activeWalletAuthorityFlowRuntime.confirmationAuthPlan,
            };
          }
          // Auth-neutral material has no threshold operation to plan a warm
          // session from; its plan comes from the wallet's own factor.
          return prepared.kind === 'authorized'
            ? await resolveEvmFamilyTransactionStepUp({
                ...authPlanningArgsBase,
                chainTarget: signingTarget,
                senderSignatureAlgorithm: 'secp256k1',
                ecdsaAuthorization: 'reusable_wallet_session',
                preparedOperation: prepared.preparedOperation,
              })
            : await (async () => {
                // The capability is the authority an auth-neutral step-up
                // proves against, so it is resolved before the plan rather
                // than after it. Resolution is a read of the same manifest the
                // signing runtime hydrates from.
                const signer = requireEvmFamilyEcdsaSigner(
                  prepared.identity,
                  'auth-neutral ECDSA step-up planning',
                );
                const capability = await deps.resolveCanonicalEcdsaSigningCapability({
                  walletId: signer.walletId,
                  chainTarget: signer.chainTarget,
                  materialActivation: signer.materialActivation,
                });
                return await resolveEvmFamilyTransactionStepUp({
                  ...authPlanningArgsBase,
                  chainTarget: signingTarget,
                  senderSignatureAlgorithm: 'secp256k1',
                  ecdsaAuthorization: 'operation_step_up',
                  capability,
                  materialActivation: signer.materialActivation,
                  operationFingerprint,
                });
              })();
        })()
      : await resolveEvmFamilyTransactionStepUp({
          ...authPlanningArgsBase,
          chainTarget: signingTarget,
          senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
        });
  // Auth planning and runtime creation both resolve the canonical capability,
  // so the replacement race can surface here — before the executor's retry
  // ladder exists. Route the typed superseded error to the same bounded
  // re-resolution instead of letting it escape as a terminal failure.
  const prepareFlowForExecution = async () => {
    const authPlanningResult = await resolveAuthPlanningResult();
    const { signingAuthPlan, signingSessionPlan, emailOtpSigning } = authPlanningResult;
    const emailOtpSigningForFlow = emailOtpSigning
      ? {
          prepare: emailOtpSigning.prepare,
          ...(emailOtpSigning.resend ? { resend: emailOtpSigning.resend } : {}),
        }
      : undefined;
    const { flowArgs } = await createEvmFamilySigningFlowRuntime({
      deps,
      walletSession: args.walletSession,
      request: args.request,
      chainTarget: requestChainTarget,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      ...(signingSessionPlan ? { signingSessionPlan } : {}),
      signingOperation: createTransactionSigningOperation(),
      onSigningOperationTransition: emitEvmFamilySigningOperationTrace,
      ...(emailOtpSigningForFlow ? { emailOtpSigningForFlow } : {}),
      confirmationConfigOverride: args.confirmationConfigOverride,
      shouldAbort: args.shouldAbort,
      onEvent: args.onEvent,
      onAuthSideEffectStarted: markFreshAuthRetrySideEffect,
      getEcdsaSigningLaneIdentity,
      ...(activeWalletAuthorityFlowRuntime
        ? { activeWalletAuthority: activeWalletAuthorityFlowRuntime }
        : {}),
    });
    return { signingAuthPlan, signingSessionPlan, emailOtpSigning, flowArgs };
  };
  let preparedFlow: Awaited<ReturnType<typeof prepareFlowForExecution>>;
  try {
    preparedFlow = await prepareFlowForExecution();
  } catch (error) {
    const reResolved = await reResolveSupersededPreparation(error);
    if (reResolved) return reResolved;
    throw error;
  }
  const { signingAuthPlan, signingSessionPlan, emailOtpSigning, flowArgs } = preparedFlow;

  let freshAuthRetryHandledFinalization = false;
  const retryWithFreshWalletSessionAuth = async (
    error: unknown,
  ): Promise<TempoSignedResult | EvmSignedResult | null> => {
    return await retryEvmFamilyWithFreshWalletSessionAuthWhenRequired({
      error,
      walletId,
      chain: args.request.chain,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      accountAuth: resolvedAccountAuth,
      alreadyRetryingFreshEmailOtpAuth: attempt.retryingFreshAuth,
      hasEmailOtpSigningPlan: !!emailOtpSigning,
      sideEffectState: freshAuthRetrySideEffectState,
      signingSessionCoordinator,
      expiryContext: resolveEvmFamilyWalletSessionExpiryContext({
        error,
        candidate: evmFamilyWalletSessionExpiryCandidate({
          prepared: preparedEcdsaSigningSession,
        }),
        detectedAtMs: Date.now(),
      }),
      onDecision: (decision) => recordFreshAuthRetryDecision(decision, error),
      onEvent: args.onEvent,
      retry: async () => {
        const result = await signEvmFamilyAttempt(deps, args, {
          admissionRetryState: { kind: 'initial_admission' },
          forceFreshAuth: true,
          operationIds,
          retryingFreshAuth: true,
          signingSessionCoordinator,
        });
        freshAuthRetryHandledFinalization = true;
        return result;
      },
    });
  };
  const retryWithFreshAuth = async (
    error: unknown,
  ): Promise<TempoSignedResult | EvmSignedResult | null> => {
    // R90-INV-010: a superseded preparation is discarded whole and current
    // canonical state resolved again. Nothing about it is an auth problem, so
    // it is handled before the fresh-auth ladder and prompts the user for
    // nothing.
    if (isEvmFamilyEcdsaMaterialSupersededError(error)) {
      const reResolved = await reResolveSupersededPreparation(error);
      if (reResolved) {
        freshAuthRetryHandledFinalization = true;
        return reResolved;
      }
      return null;
    }
    const walletSessionRetry = await retryWithFreshWalletSessionAuth(error);
    if (walletSessionRetry) return walletSessionRetry;
    const decision = classifyEvmFamilyFreshAuthRetry({
      trigger: 'wallet_signing_budget_exhausted',
      error,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      accountAuth: resolvedAccountAuth,
      activeSigningAuthMethod: getPreparedEcdsaSigningSession().authMethod,
      admissionRetryState: attempt.admissionRetryState,
      alreadyRetryingFreshAuth: attempt.retryingFreshAuth,
      hasStepUpAuthPlan:
        isEmailOtpSigningAuthPlan(signingAuthPlan) || isPasskeySigningAuthPlan(signingAuthPlan),
      sideEffectState: freshAuthRetrySideEffectState,
    });
    recordFreshAuthRetryDecision(decision, error);
    if (decision.kind !== 'retry') return null;
    const preparedForRetry = getPreparedEcdsaSigningSession();
    if (preparedForRetry.kind !== 'authorized') {
      // The budget being refreshed is a reusable Wallet Session's. An
      // operation authorized by its own step-up has none, and nothing to
      // serialize the refresh against.
      return null;
    }
    if (decision.retryMode !== 'await_admission_owner_completion') {
      emitEvmFamilyFreshAuthRetryEvent({
        walletId,
        chain: args.request.chain,
        accountAuth: resolvedAccountAuth,
        onEvent: args.onEvent,
      });
    }
    const queueKey = ecdsaOperationAuthorizationQueueKey({
      walletId,
      prepared: preparedForRetry,
    });
    const result = await executeEvmFamilyFreshAuthRetry({
      deps,
      signingArgs: args,
      decision,
      queueKey,
      operationIds,
      retryingFreshAuth: attempt.retryingFreshAuth === true,
      signingSessionCoordinator,
    });
    freshAuthRetryHandledFinalization = true;
    return result;
  };
  const preparedNonceSession = getPreparedEcdsaSigningSessionIfEcdsa();
  const nonceOperation: PreparedNonceOperationContext = {
    ...createTransactionSigningOperation(),
    accountId: String(walletId),
  };
  if (preparedNonceSession) {
    const nonceFingerprint = derivePreparedEvmFamilyKeyFingerprint(preparedNonceSession);
    emitSigningSessionFlowTrace('evm-family', {
      stage: 'ecdsa_attempt.nonce_operation_prepared',
      walletId,
      chain: requestChain,
      chainTarget: requestChainTarget,
      ...(nonceFingerprint ? { evmFamilyKeyFingerprint: nonceFingerprint } : {}),
      ...(preparedNonceSession.kind === 'authorized'
        ? {
            walletSessionId:
              preparedNonceSession.signingLane.authorization.projection.walletSessionId,
          }
        : {}),
      materialActivationId:
        preparedNonceSession.kind === 'authorized'
          ? preparedNonceSession.signingLane.materialActivation.activationId
          : preparedNonceSession.candidate.materialActivation.activationId,
    });
  }
  const preparedExecutorSession = getPreparedEcdsaSigningSessionIfEcdsa();
  // Ready material is produced by `resolveReadySecp256k1SigningMaterial`
  // immediately before worker use, so the prepared session carries none.
  const preparedExecutorReadyMaterial = null;
  const requireThresholdEcdsaStepUpRuntime = () => {
    const runtime = flowArgs.thresholdEcdsaStepUpRuntime;
    if (!runtime) {
      throw new Error(
        '[SigningEngine][ecdsa] prepared executor requires threshold step-up runtime',
      );
    }
    return runtime;
  };
  const thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp =
    preparedExecutorSession && !activeWalletAuthorityFlowRuntime
      ? {
          kind: 'required',
          authPlan: {
            kind: 'planned',
            signingAuthPlan,
          },
          operation: {
            intent:
              preparedExecutorSession.kind === 'authorized'
                ? preparedExecutorSession.transactionOperation.intent
                : preparedExecutorSession.intent,
            authPlan: signingAuthPlan,
          },
          runtime: requireThresholdEcdsaStepUpRuntime(),
        }
      : {
          kind: 'not_required',
        };
  let thresholdEcdsaState: EvmFamilyExecutorThresholdEcdsaState;
  if (!preparedExecutorSession) {
    thresholdEcdsaState = { kind: 'not_required' };
  } else {
    // Public identity continuity is established from hydrated material, which
    // the canonical resolver produces after this point.
    // Lane identity only at prepare time: material public facts are verified by
    // the canonical hydration boundary, after this point.
    const publicIdentityContinuity: PreparedEvmFamilyPublicIdentityContinuity = {
      kind: 'lane_identity_only',
    };
    thresholdEcdsaState = buildPreparedEvmFamilyExecutorThresholdEcdsaState({
      laneThresholdOwnerAddress:
        preparedExecutorSession.kind === 'authorized'
          ? preparedExecutorSession.signingLane.key.thresholdOwnerAddress
          : preparedExecutorSession.candidate.key.thresholdOwnerAddress,
      publicIdentityContinuity,
    });
  }

  const executePayload = {
    deps,
    walletId,
    request: args.request,
    chainTarget: requestChainTarget,
    flowArgs,
    nonceOperation,
    thresholdEcdsaState,
    onConfirmationDisplayed: markConfirmationDisplayed,
    thresholdEcdsaStepUp,
    retryWithFreshEmailOtpAuth: retryWithFreshAuth,
  };
  if (preparedExecutorSession) {
    const result = await executeEvmFamilyTransactionSigning(executePayload);
    if (freshAuthRetryHandledFinalization) {
      return result;
    }
    return result;
  }
  return await executeEvmFamilyTransactionSigning(executePayload);
}

export type TempoSigningDeps = EvmFamilySigningDeps;
export type ReportTempoBroadcastAcceptedArgs = EvmFamilyBroadcastAcceptedArgs;
export type ReportTempoBroadcastRejectedArgs = EvmFamilyBroadcastRejectedArgs;
export type ReportTempoFinalizedArgs = EvmFamilyFinalizedArgs;
export type ReportTempoDroppedOrReplacedArgs = EvmFamilyDroppedOrReplacedArgs;
export type ReconcileTempoNonceLaneArgs = EvmFamilyReconcileLaneArgs;
export type TempoNonceLaneStatus = EvmFamilyNonceLaneStatus;

export async function reportTempoBroadcastAccepted(
  deps: TempoSigningDeps,
  args: ReportTempoBroadcastAcceptedArgs,
): Promise<void> {
  await reportEvmFamilyBroadcastAccepted(deps, args);
}

export async function reportTempoBroadcastRejected(
  deps: TempoSigningDeps,
  args: ReportTempoBroadcastRejectedArgs,
): Promise<void> {
  await reportEvmFamilyBroadcastRejected(deps, args);
}

export async function reportTempoFinalized(
  deps: TempoSigningDeps,
  args: ReportTempoFinalizedArgs,
): Promise<void> {
  await reportEvmFamilyFinalized(deps, args);
}

export async function reportTempoDroppedOrReplaced(
  deps: TempoSigningDeps,
  args: ReportTempoDroppedOrReplacedArgs,
): Promise<void> {
  await reportEvmFamilyDroppedOrReplaced(deps, args);
}

export async function reconcileTempoNonceLane(
  deps: TempoSigningDeps,
  args: ReconcileTempoNonceLaneArgs,
): Promise<TempoNonceLaneStatus> {
  return await reconcileEvmFamilyNonceLane(deps, args);
}
