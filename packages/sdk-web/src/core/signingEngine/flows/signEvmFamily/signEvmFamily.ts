import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import type { NonceCoordinator, PreparedNonceOperationContext } from '../../nonce/NonceCoordinator';
import type { EvmSigningRequest } from '../../chains/evm/evmSigning.types';
import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { TempoSigningRequest } from '../../chains/tempo/tempoSigning.types';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import type {
  ReadAvailableSigningLanesForSigningInput,
  AvailableSigningLanes,
} from '../../session/availability/availableSigningLanes';
import type { RestorePersistedSessionForSigningInput } from '../../session/sealedRecovery/sealedRecovery.types';
import type {
  ThresholdEcdsaKeyRefLookupResult,
  ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import {
  type ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import {
  exactEcdsaSigningLaneIdentityFromSelectedLane,
} from '../../session/identity/exactSigningLaneIdentity';
import type {
  UiConfirmContextPort,
  UiConfirmSigningPort,
  UiConfirmSecureConfirmationPort,
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
import { computeSigningOperationFingerprint } from '../../session/planning/operationFingerprint';
import {
  buildOperationAuthorizationQueueKey,
  signingGrantAdmissionAuthorityKeyFromAuth,
  type OperationAuthorizationQueueKey,
} from '../../session/budget/admission';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import { ensureSealedRefreshStartupParityForTransactionSigning } from '../../session/warmCapabilities/sealedRefreshParity';
import {
  SIGNER_AUTH_METHODS,
  type SignerAuthMethod,
} from '@shared/utils/signerDomain';
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
  EvmFamilyEcdsaSessionReaderDeps,
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
  selectedEvmFamilyEcdsaLaneForMaterialIdentity,
  isEmailOtpThresholdEcdsaSigningContext,
  summarizeEvmFamilyEcdsaLane,
  summarizeEvmFamilyEcdsaSessionRecord,
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import { getEcdsaMaterialRecord } from './ecdsaMaterialState';
import type { EmailOtpEcdsaCommittedLane } from './ecdsaSelection';
import { resolveEvmFamilyTransactionWalletAuth } from './accountAuth';
import {
  resolveEvmFamilyTransactionStepUp,
  type EvmFamilyConfirmedSigningDeps,
} from './authPlanning';
import {
  prepareEvmFamilyEcdsaSigningSession,
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
  finalizeSignedTransactionOperation,
  signPreparedTransactionOperation,
} from '../../session/operationState/transactionState';
import { createEvmFamilySigningFlowRuntime } from './signingFlowRuntime';
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
  deriveEvmFamilyKeyFingerprintFromRecordPublicFacts,
  toVerifiedEcdsaPublicFactsFromRecord,
  type ReadyEcdsaSignerSession,
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
import { resolveThresholdEcdsaSigningQueueKey } from '../../threshold/ecdsa/signingQueue';

function evmFamilyWalletSessionExpiryCandidate(args: {
  readonly prepared: PreparedEvmFamilyEcdsaSigningSession | undefined;
  readonly record: ThresholdEcdsaSessionRecord | undefined;
}): EvmFamilyWalletSessionExpiryCandidate {
  if (!args.prepared || !args.record) return { kind: 'unavailable' };
  return {
    kind: 'exact_ecdsa_lane',
    identity: exactEcdsaSigningLaneIdentityFromSelectedLane(args.prepared.signingLane),
    expiresAtMs: args.record.expiresAtMs,
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
  prepared: PreparedEvmFamilyEcdsaSigningSession;
}): OperationAuthorizationQueueKey {
  const authorization = args.prepared.signingLane.authorization;
  return buildOperationAuthorizationQueueKey({
    walletId: args.walletId,
    materialActivationId: args.prepared.signingLane.materialActivation.activationId,
    authorizationId: authorization.projection.walletSessionId,
    authorityKey: signingGrantAdmissionAuthorityKeyFromAuth(args.prepared.signingLane.auth),
    targetKey: thresholdEcdsaChainTargetKey(args.prepared.signingLane.chainTarget),
  });
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
};

async function executeEvmFamilyFreshAuthRetry(args: {
  deps: EvmFamilySigningDeps;
  signingArgs: SignEvmFamilyArgs;
  decision: Extract<EvmFamilyFreshAuthRetryDecision, { kind: 'retry' }>;
  queueKey: OperationAuthorizationQueueKey;
  operationIds: EvmFamilySigningOperationIds;
  retryingFreshAuth: boolean;
  signingSessionCoordinator: SigningSessionCoordinator;
}): Promise<TempoSignedResult | EvmSignedResult> {
  const rereadAuthoritativeReadiness = signEvmFamilyAttempt.bind(null, args.deps, args.signingArgs, {
    admissionRetryState: { kind: 'authoritative_readiness_reread' },
    forceFreshAuth: false,
    operationIds: args.operationIds,
    retryingFreshAuth: args.retryingFreshAuth,
    signingSessionCoordinator: args.signingSessionCoordinator,
  });
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

function signerAuthMethodForThresholdEcdsaSource(
  source: ThresholdEcdsaSessionStoreSource,
): SignerAuthMethod {
  switch (source) {
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
    case 'login':
    case 'registration':
    case 'manual-bootstrap':
      return SIGNER_AUTH_METHODS.passkey;
    default:
      source satisfies never;
      throw new Error(`[SigningEngine][ecdsa] unsupported session source: ${String(source)}`);
  }
}

export async function signEvmFamily(
  deps: EvmFamilySigningDeps,
  args: SignEvmFamilyArgs,
): Promise<TempoSignedResult | EvmSignedResult> {
  const attempt: SignEvmFamilyAttemptOptions = {
    admissionRetryState: { kind: 'initial_admission' },
    operationIds: createEvmFamilySigningOperationIds(args.signingOperationId),
  };
  if (args.request.senderSignatureAlgorithm !== 'secp256k1') {
    return await signEvmFamilyAttempt(deps, args, attempt);
  }
  const walletId = toWalletId(args.walletSession.walletId);
  const queueKey = resolveThresholdEcdsaSigningQueueKey({ walletId });
  const task = signEvmFamilyAttempt.bind(null, deps, args, attempt);
  return await deps.withThresholdEcdsaSigningQueue({
    queueKey,
    walletId,
    enabled: true,
    shouldAbort: args.shouldAbort,
    task,
  });
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

  let thresholdEcdsaRecord: ThresholdEcdsaSessionRecord | undefined;
  let accountAuth: AccountAuthMetadata | undefined;
  let ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane | undefined;
  let selectedEcdsaAuthMethod: EvmFamilyEcdsaAuthMethod | undefined;
  let preparedEcdsaSigningSession: PreparedEvmFamilyEcdsaSigningSession | undefined;
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
  const derivePreparedEvmFamilyKeyFingerprint = (
    prepared: PreparedEvmFamilyEcdsaSigningSession | undefined,
  ): string | undefined =>
    prepared && prepared.material.kind === 'ready_to_sign'
      ? safeDerivePreparedRecordFingerprint({
          walletId: prepared.material.readyMaterial.key.walletId,
          record: prepared.material.readyMaterial.record,
        })
      : undefined;
  const safeDerivePreparedRecordFingerprint = (args: {
    walletId: string;
    record: ThresholdEcdsaSessionRecord;
  }): string | undefined => {
    try {
      return deriveEvmFamilyKeyFingerprintFromRecordPublicFacts({
        walletId: args.walletId,
        record: args.record,
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
    ecdsaSigningLane = preparedEcdsaSigningSession.signingLane;
    selectedEcdsaAuthMethod = preparedEcdsaSigningSession.authMethod;
    accountAuth = preparedEcdsaSigningSession.accountAuth;
    thresholdEcdsaRecord = getEcdsaMaterialRecord(preparedEcdsaSigningSession.material);
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
      authMethod: selectedEcdsaAuthMethod,
      lane: summarizeEvmFamilyEcdsaLane(ecdsaSigningLane),
      warmRecord: summarizeEvmFamilyEcdsaSessionRecord(thresholdEcdsaRecord),
    });
  } else {
    accountAuth = await resolveEvmFamilyTransactionWalletAuth({
      deps,
      walletId,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      chainTarget: requestChainTarget,
    });
  }
  const isEmailOtpThresholdContext = thresholdEcdsaRecord
    ? isEmailOtpThresholdEcdsaSigningContext({ record: thresholdEcdsaRecord })
    : false;
  accountAuth =
    accountAuth ||
    (await resolveEvmFamilyTransactionWalletAuth({
      deps,
      walletId,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      chainTarget: requestChainTarget,
      ...(thresholdEcdsaRecord
        ? {
            sessionAuthMethod: signerAuthMethodForThresholdEcdsaSource(
              thresholdEcdsaRecord.source,
            ),
          }
        : {}),
      isEmailOtpThresholdContext,
    }));
  const resolvedAccountAuth = accountAuth;

  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  const requestEmailOtpTransactionSigningChallenge =
    deps.requestEmailOtpTransactionSigningChallenge;
  const confirmedSigningDeps: EvmFamilyConfirmedSigningDeps = {
    ...deps,
    requestEmailOtpTransactionSigningChallenge,
  };
  const authPlanningArgsBase = {
    deps: {
      ...deps,
      signingSessionCoordinator,
    },
    confirmedDeps: confirmedSigningDeps,
    walletSession: args.walletSession,
    chain: requestChain,
    accountAuth: resolvedAccountAuth,
    onEvent: args.onEvent,
  };
  const getPreparedEcdsaSigningSession = (): PreparedEvmFamilyEcdsaSigningSession => {
    if (preparedEcdsaSigningSession) return preparedEcdsaSigningSession;
    throw new Error('[SigningEngine][ecdsa] prepared signing session is required');
  };
  const assertPreparedEcdsaOperationLane = (
    prepared: PreparedEvmFamilyEcdsaSigningSession,
    context: string,
  ): void => {
    assertSameSigningLaneIdentity({
      expected: prepared.preparedOperation.lane,
      actual: prepared.signingLane,
      context,
    });
  };
  const getResolvedEcdsaSigningLane = (): ResolvedEvmFamilyEcdsaSigningLane =>
    getPreparedEcdsaSigningSession().signingLane;
  const getPreparedEcdsaSigningSessionIfEcdsa = ():
    | PreparedEvmFamilyEcdsaSigningSession
    | undefined =>
    args.request.senderSignatureAlgorithm === 'secp256k1'
      ? getPreparedEcdsaSigningSession()
      : undefined;
  const authPlanningResult =
    args.request.senderSignatureAlgorithm === 'secp256k1'
      ? await (async () => {
          const prepared = getPreparedEcdsaSigningSession();
          return await resolveEvmFamilyTransactionStepUp({
            ...authPlanningArgsBase,
            chainTarget: signingTarget,
            senderSignatureAlgorithm: 'secp256k1',
            preparedOperation: prepared.preparedOperation,
          });
        })()
      : await resolveEvmFamilyTransactionStepUp({
          ...authPlanningArgsBase,
          chainTarget: signingTarget,
          senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
        });
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
    getResolvedEcdsaSigningLane,
  });

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
          record: thresholdEcdsaRecord,
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
      prepared: getPreparedEcdsaSigningSession(),
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
      walletSessionId:
        preparedNonceSession.signingLane.authorization.projection.walletSessionId,
      materialActivationId:
        preparedNonceSession.signingLane.materialActivation.activationId,
    });
  }
  const preparedExecutorSession = getPreparedEcdsaSigningSessionIfEcdsa();
  const preparedExecutorReadyMaterial =
    preparedExecutorSession?.material.kind === 'ready_to_sign'
      ? preparedExecutorSession.material
      : null;
  const requireThresholdEcdsaStepUpRuntime = () => {
    const runtime = flowArgs.thresholdEcdsaStepUpRuntime;
    if (!runtime) {
      throw new Error(
        '[SigningEngine][ecdsa] prepared executor requires threshold step-up runtime',
      );
    }
    return runtime;
  };
  const thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp = preparedExecutorSession
    ? {
        kind: 'required',
        authPlan: {
          kind: 'planned',
          signingAuthPlan,
        },
        operation: {
          ...preparedExecutorSession.transactionOperation,
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
    if (!signingSessionPlan) {
      throw new Error('[SigningEngine][ecdsa] prepared executor requires a signing session plan');
    }
    let verifiedMaterialPublicFacts: VerifiedEcdsaPublicFacts | null = null;
    if (preparedExecutorReadyMaterial) {
      verifiedMaterialPublicFacts = preparedExecutorReadyMaterial.publicFacts;
    } else if (thresholdEcdsaRecord) {
      verifiedMaterialPublicFacts = await toVerifiedEcdsaPublicFactsFromRecord({
        record: thresholdEcdsaRecord,
      });
    }
    const publicIdentityContinuity: PreparedEvmFamilyPublicIdentityContinuity =
      verifiedMaterialPublicFacts
        ? {
            kind: 'verified_material_identity',
            verifiedMaterialThresholdOwnerAddress:
              verifiedMaterialPublicFacts.thresholdOwnerAddress,
          }
        : { kind: 'lane_identity_only' };
    thresholdEcdsaState = buildPreparedEvmFamilyExecutorThresholdEcdsaState({
      transactionLane: preparedExecutorSession.transactionOperation.lane,
      signingSessionPlan,
      laneThresholdOwnerAddress: preparedExecutorSession.signingLane.key.thresholdOwnerAddress,
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
