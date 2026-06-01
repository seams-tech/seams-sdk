import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import type { NonceCoordinator, NonceOperationContext } from '../../nonce/NonceCoordinator';
import type { EvmSigningRequest } from '../../chains/evm/types';
import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { TempoSigningRequest } from '../../chains/tempo/types';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import type {
  ReadAvailableSigningLanesForSigningInput,
  AvailableSigningLanes,
} from '../../session/availability/availableSigningLanes';
import type { RestorePersistedSessionForSigningInput } from '../../session/sealedRecovery/types';
import type {
  ThresholdEcdsaKeyRefLookupResult,
  ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import type {
  UiConfirmContextPort,
  UiConfirmSigningPort,
  UiConfirmSecureConfirmationPort,
  WarmSessionStatusResult,
  WarmSessionStatusReader,
} from '../../uiConfirm/types';
import type { SignerWorkerManagerContext } from '../../workerManager/SignerWorkerManager';
import {
  assertSameSigningLaneIdentity,
  SigningOperationIntent,
  SigningSessionPlanKind,
  type SigningOperationFingerprint,
  type SigningOperationId,
} from '../../session/operationState/types';
import {
  emitSigningSessionFlowFailure,
  emitSigningSessionFlowTrace,
} from '../../session/operationState/trace';
import { computeSigningOperationFingerprint } from '../../session/planning/operationFingerprint';
import {
  type SigningSessionBudgetStatusAuth,
  type SigningSessionPreparedBudgetIdentity,
  isSigningSessionBudgetReservation,
  type SigningSessionBudgetReserveResult,
} from '../../session/budget/budget';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import { ensureSealedRefreshStartupParityForTransactionSigning } from '../../session/warmCapabilities/sealedRefreshParity';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
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
  readSelectedEcdsaRecordForLane,
  summarizeEvmFamilyEcdsaLane,
  summarizeEvmFamilyEcdsaSessionRecord,
  updateResolvedEvmFamilyEcdsaSigningLaneIdentity,
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import {
  buildEcdsaMaterialStateForResolvedLane,
  getEcdsaMaterialRecord,
  requireReadyEcdsaMaterial,
  requireReadyEcdsaMaterialForResolvedLane,
  resolvedEcdsaMaterialInputFromOptionalRecord,
  summarizeEcdsaMaterialState,
} from './ecdsaMaterialState';
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
  recordFailedEvmFamilyWalletSigningSessionSpend,
  recordSuccessfulEvmFamilyWalletSigningSessionSpend,
  reserveEvmFamilyWalletSigningSessionBudget,
  type EvmFamilyTransactionSigningOperationContext,
} from './budgetSpending';
import {
  isEmailOtpSigningAuthPlan,
  isPasskeySigningAuthPlan,
  isWarmSessionSigningAuthPlan,
} from '../../stepUpConfirmation/types';
import type { EvmFamilyThresholdEcdsaStepUp } from './requireEvmFamilyStepUpAuth';
import type { SelectedEcdsaLane } from '../../session/identity/laneIdentity';
import { applySuccessfulEvmFamilyEcdsaPostSignPolicy } from './postSignPolicy';
import {
  executeEvmFamilyTransactionSigning,
  type EvmFamilyExecutorThresholdEcdsaState,
} from './transactionExecutor';
import {
  admitTransactionBudget,
  finalizeSignedTransactionOperation,
  prepareTransactionSigningOperation,
  recordPreparedTransactionBudgetAdmission,
  recordPreparedTransactionNoBudget,
  replacePreparedTransactionLane,
  signPreparedTransactionOperation,
  type BudgetAdmittedOperation,
} from '../../session/operationState/transactionState';
import { completeEvmFamilyEmailOtpSigningRefresh } from './emailOtpRefresh';
import type { EvmFamilyEcdsaEmailOtpStepUpAuthorization } from './stepUpAuthorization';
import { createEvmFamilySigningFlowRuntime } from './signingFlowRuntime';
import { retryEvmFamilyWithFreshEmailOtpAuthWhenRequired } from './freshEmailOtpRetry';
import { buildEvmFamilyThresholdEcdsaReauthResult } from './thresholdAdmission';
import {
  classifyEvmFamilyFreshAuthRetry,
  nextEvmFamilyFreshAuthRetrySideEffectState,
  type EvmFamilyFreshAuthRetryDecision,
  type EvmFamilyFreshAuthRetrySideEffectState,
  type EvmFamilySigningAuthSideEffect,
} from './freshAuthRetryPolicy';
import { emitEvmFamilySigningEvent, emitEvmFamilySigningOperationTrace } from './events';
import { requiredEvmFamilyRequestSignatureUses } from './signatureUses';
import { toOptionalEvmAddress } from './addresses';
import {
  bindEvmFamilyCallerProvidedOperationIdToFingerprint,
  createEvmFamilySigningOperationIds,
  ensureEvmFamilyConfirmationOperationId,
  type EvmFamilySigningOperationIds,
} from './operationIds';
import {
  deriveEvmFamilyKeyFingerprintFromRecordPublicFacts,
  toReadyEcdsaSignerSessionFromReadyMaterial,
  toVerifiedEcdsaPublicFactsFromRecord,
  type ReadyEcdsaSignerSession,
  type ReadyEvmFamilyEcdsaMaterial,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  reconcileEvmFamilyNonceLane,
  reportEvmFamilyBroadcastAccepted,
  reportEvmFamilyBroadcastRejected,
  reportEvmFamilyDroppedOrReplaced,
  reportEvmFamilyFinalized,
} from './nonceLifecycleAdapter';

export type {
  EvmFamilyBroadcastAcceptedArgs,
  EvmFamilyBroadcastRejectedArgs,
  EvmFamilyDroppedOrReplacedArgs,
  EvmFamilyFinalizedArgs,
  EvmFamilyNonceLaneStatus,
  EvmFamilyReconcileLaneArgs,
} from './types';

function ecdsaTransactionReadinessFromBudgetIdentity(
  budgetIdentity: SigningSessionPreparedBudgetIdentity,
) {
  return {
    status: 'ready' as const,
    remainingUses: Math.max(0, Math.floor(Number(budgetIdentity.status.remainingUses) || 0)),
    expiresAtMs: Math.max(0, Math.floor(Number(budgetIdentity.status.expiresAtMs) || 0)),
  };
}

function getAdmittedEcdsaBudgetIdentity(
  prepared: PreparedEvmFamilyEcdsaSigningSession,
): SigningSessionPreparedBudgetIdentity | null {
  return prepared.budget.kind === 'BudgetAdmitted'
    ? prepared.budget.operation.budgetAdmission.budgetIdentity
    : null;
}

function trustedBudgetStatusAuthFromReadySignerSession(
  signerSession: ReadyEcdsaSignerSession,
): SigningSessionBudgetStatusAuth {
  const thresholdSessionAuthToken =
    signerSession.transport.auth.kind === 'jwt_threshold_session_auth'
      ? signerSession.transport.auth.thresholdSessionAuthToken
      : undefined;
  return {
    relayerUrl: signerSession.transport.relayerUrl,
    thresholdSessionId: String(signerSession.session.thresholdSessionId),
    ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
  };
}

async function trustedBudgetStatusAuthFromReadyMaterial(
  readyMaterial: ReadyEvmFamilyEcdsaMaterial,
): Promise<SigningSessionBudgetStatusAuth> {
  return trustedBudgetStatusAuthFromReadySignerSession(
    await toReadyEcdsaSignerSessionFromReadyMaterial({ material: readyMaterial }),
  );
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
  forceFreshAuth?: boolean;
  operationIds?: EvmFamilySigningOperationIds;
  retryingFreshAuth?: boolean;
  signingSessionCoordinator?: SigningSessionCoordinator;
};

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
    accountId: args.walletId,
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
  return await signEvmFamilyAttempt(deps, args, {
    operationIds: createEvmFamilySigningOperationIds(args.signingOperationId),
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
  const buildBudgetFailureDiagnostics = (
    prepared: PreparedEvmFamilyEcdsaSigningSession | undefined,
  ): Record<string, unknown> => {
    const admittedBudgetIdentity = prepared ? getAdmittedEcdsaBudgetIdentity(prepared) : null;
    const material = prepared?.material;
    const keyFingerprint = derivePreparedEvmFamilyKeyFingerprint(prepared);
    return {
      ...(operationIds.confirmationOperationId
        ? { operationId: String(operationIds.confirmationOperationId) }
        : {}),
      authMethod: prepared?.authMethod || selectedEcdsaAuthMethod,
      ...(keyFingerprint ? { evmFamilyKeyFingerprint: keyFingerprint } : {}),
      chainTargetKey: thresholdEcdsaChainTargetKey(
        prepared?.signingLane.chainTarget || requestChainTarget,
      ),
      ecdsaThresholdKeyId:
        prepared?.signingLane.key.ecdsaThresholdKeyId ||
        (material && material.kind === 'ready_to_sign'
          ? material.signingKeyContext.ecdsaThresholdKeyId
          : undefined),
      walletSigningSessionId: prepared
        ? String(prepared.signingLane.walletSigningSessionId)
        : material
          ? material.identity.walletSigningSessionId
          : undefined,
      thresholdSessionId: prepared
        ? String(prepared.signingLane.thresholdSessionId)
        : material
          ? material.identity.thresholdSessionId
          : undefined,
      budgetProjectionVersion: admittedBudgetIdentity?.projectionVersion,
      freshAuthRetrySideEffectState,
    };
  };

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
      accountId: walletId,
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
    thresholdEcdsaRecord =
      getEcdsaMaterialRecord(preparedEcdsaSigningSession.material) ||
      readSelectedEcdsaRecordForLane({
        deps,
        lane: preparedEcdsaSigningSession.signingLane,
      });
    emitSigningSessionFlowTrace('evm-family', {
      stage: 'ecdsa_attempt.prepared',
      accountId: walletId,
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
      budgetKind: preparedEcdsaSigningSession.budget.kind,
    });
  } else {
    accountAuth = await resolveEvmFamilyTransactionWalletAuth({
      deps,
      walletId,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      chainTarget: requestChainTarget,
    });
  }
  const isEmailOtpThresholdContext =
    thresholdEcdsaRecord
      ? isEmailOtpThresholdEcdsaSigningContext({ record: thresholdEcdsaRecord })
      : false;
  accountAuth =
    accountAuth ||
    (await resolveEvmFamilyTransactionWalletAuth({
      deps,
      walletId,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      chainTarget: requestChainTarget,
      ...(thresholdEcdsaRecord ? { sessionSource: thresholdEcdsaRecord.source } : {}),
      isEmailOtpThresholdContext,
    }));
  const resolvedAccountAuth = accountAuth;

  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  const requestEmailOtpTransactionSigningChallenge =
    deps.requestEmailOtpTransactionSigningChallenge;
  const loginWithEmailOtpEcdsaCapabilityForSigning =
    deps.loginWithEmailOtpEcdsaCapabilityForSigning;
  const confirmedSigningDeps: EvmFamilyConfirmedSigningDeps = {
    ...deps,
    requestEmailOtpTransactionSigningChallenge: requestEmailOtpTransactionSigningChallenge
      ? async (challengeArgs: {
          walletSession: WalletSessionRef;
          chain: EvmFamilyChain;
          authLane?: EmailOtpAuthLane;
        }) =>
          await requestEmailOtpTransactionSigningChallenge({
            walletSession: challengeArgs.walletSession,
            chain: challengeArgs.chain,
            ...(challengeArgs.authLane ? { authLane: challengeArgs.authLane } : {}),
          })
      : undefined,
    loginWithEmailOtpEcdsaCapabilityForSigning: loginWithEmailOtpEcdsaCapabilityForSigning
      ? async (loginArgs: {
          walletSession: WalletSessionRef;
          subjectId?: never;
          chainTarget: ThresholdEcdsaChainTarget;
          challengeId: string;
          otpCode: string;
          record?: ThresholdEcdsaSessionRecord;
          authLane?: EmailOtpAuthLane;
          remainingUses?: number;
        }) =>
          await loginWithEmailOtpEcdsaCapabilityForSigning({
            walletSession: loginArgs.walletSession,
            chainTarget: loginArgs.chainTarget,
            challengeId: loginArgs.challengeId,
            otpCode: loginArgs.otpCode,
            ...(loginArgs.record ? { record: loginArgs.record } : {}),
            ...(loginArgs.authLane ? { authLane: loginArgs.authLane } : {}),
            ...(typeof loginArgs.remainingUses === 'number'
              ? { remainingUses: loginArgs.remainingUses }
              : {}),
          })
      : undefined,
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
  const admitPreparedEcdsaBudgetIdentity = (
    prepared: PreparedEvmFamilyEcdsaSigningSession,
    budgetIdentity: SigningSessionPreparedBudgetIdentity,
    trustedStatusAuth?: SigningSessionBudgetStatusAuth,
  ): PreparedEvmFamilyEcdsaSigningSession => {
    if (
      budgetIdentity.walletSigningSessionId !== String(prepared.signingLane.walletSigningSessionId)
    ) {
      throw new Error('[SigningEngine][ecdsa] budget identity does not match prepared wallet lane');
    }
    const transactionOperation = replacePreparedTransactionLane(prepared.transactionOperation, {
      lane: prepared.transactionOperation.lane,
      readiness: ecdsaTransactionReadinessFromBudgetIdentity(budgetIdentity),
    });
    const budgetAdmittedOperation = admitTransactionBudget(transactionOperation, {
      budgetIdentity,
    });
    const admittedPrepared = {
      ...prepared,
      transactionOperation,
      budget: recordPreparedTransactionBudgetAdmission(budgetAdmittedOperation),
      ...(trustedStatusAuth || prepared.budgetStatusAuth
        ? { budgetStatusAuth: trustedStatusAuth || prepared.budgetStatusAuth }
        : {}),
    };
    assertPreparedEcdsaOperationLane(admittedPrepared, 'budget identity admission');
    return admittedPrepared;
  };
  const updatePreparedEcdsaSigningSessionForSameOperation = (argsForRefresh: {
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
    context: string;
    diagnostics: Record<string, unknown>;
    signingSessionIdentity?: {
      thresholdSessionId: string;
      walletSigningSessionId: string;
    };
    forceRefreshBudgetIdentity?: boolean;
  }): PreparedEvmFamilyEcdsaSigningSession => {
    const prepared = getPreparedEcdsaSigningSession();
    const { budget: _budget, ...preparedWithoutBudget } = prepared;
    const currentLane = requireResolvedEvmFamilyEcdsaSigningLane({
      lane: prepared.signingLane || ecdsaSigningLane,
      chain: requestChain,
      context: argsForRefresh.context,
      diagnostics: argsForRefresh.diagnostics,
    });
    const signingLane = updateResolvedEvmFamilyEcdsaSigningLaneIdentity({
      lane: currentLane,
      chain: requestChain,
      thresholdSessionId:
        argsForRefresh.signingSessionIdentity?.thresholdSessionId ||
        String(currentLane.thresholdSessionId),
      walletSigningSessionId:
        argsForRefresh.signingSessionIdentity?.walletSigningSessionId ||
        String(currentLane.walletSigningSessionId),
      context: argsForRefresh.context,
      diagnostics: argsForRefresh.diagnostics,
    });
    if (prepared.selection.authMethod !== argsForRefresh.authMethod) {
      throw new Error(
        '[SigningEngine][ecdsa] refreshed signing session auth method changed within one operation',
      );
    }
    const refreshedMaterial = buildEcdsaMaterialStateForResolvedLane({
      lane: signingLane,
      authMethod: argsForRefresh.authMethod,
      source: argsForRefresh.source,
      material: resolvedEcdsaMaterialInputFromOptionalRecord({
        record: thresholdEcdsaRecord,
        context: argsForRefresh.context,
      }),
    });
    const refreshedSelection =
      prepared.selection.kind === 'ready'
        ? {
            ...prepared.selection,
            source: argsForRefresh.source,
            lane: signingLane,
            material: requireReadyEcdsaMaterialForResolvedLane({
              lane: signingLane,
              authMethod: argsForRefresh.authMethod,
              source: argsForRefresh.source,
              record: prepared.selection.material.record,
              context: argsForRefresh.context,
            }),
          }
        : prepared.selection.authMethod === SIGNER_AUTH_METHODS.emailOtp
          ? {
              ...prepared.selection,
              authMethod: SIGNER_AUTH_METHODS.emailOtp,
              lane: signingLane,
              material: refreshedMaterial,
              reauthAuthority: {
                ...prepared.selection.reauthAuthority,
                thresholdSessionId: String(signingLane.thresholdSessionId),
              },
            }
          : {
              ...prepared.selection,
              authMethod: SIGNER_AUTH_METHODS.passkey,
              lane: signingLane,
              material: refreshedMaterial,
            };
    const updatedPrepared = {
      ...preparedWithoutBudget,
      accountAuth: resolvedAccountAuth,
      authMethod: argsForRefresh.authMethod,
      source: argsForRefresh.source,
      material: refreshedMaterial,
      selection: refreshedSelection,
      signingLane,
      budget: recordPreparedTransactionNoBudget(
        prepared.transactionOperation,
        'budget_identity_not_prepared',
      ),
    };
    assertPreparedEcdsaOperationLane(updatedPrepared, argsForRefresh.context);
    const admittedBudgetIdentity = getAdmittedEcdsaBudgetIdentity(prepared);
    const preservedBudgetIdentity =
      !argsForRefresh.forceRefreshBudgetIdentity &&
      admittedBudgetIdentity &&
      admittedBudgetIdentity.walletSigningSessionId ===
        String(signingLane.walletSigningSessionId) &&
      String(prepared.transactionOperation.lane.thresholdSessionId) ===
        String(signingLane.thresholdSessionId)
        ? admittedBudgetIdentity
        : undefined;
    preparedEcdsaSigningSession = preservedBudgetIdentity
      ? admitPreparedEcdsaBudgetIdentity(
          updatedPrepared,
          preservedBudgetIdentity,
          prepared.budgetStatusAuth,
        )
      : updatedPrepared;
    ecdsaSigningLane = signingLane;
    selectedEcdsaAuthMethod = argsForRefresh.authMethod;
    return preparedEcdsaSigningSession!;
  };
  const replacePreparedEcdsaSigningOperationAfterReauth = async (argsForRefresh: {
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
    signingLane: ResolvedEvmFamilyEcdsaSigningLane;
    record: ThresholdEcdsaSessionRecord;
    diagnostics: Record<string, unknown>;
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  }): Promise<PreparedEvmFamilyEcdsaSigningSession> => {
    const resolvedLane = requireResolvedEvmFamilyEcdsaSigningLane({
      lane: argsForRefresh.signingLane,
      chain: requestChain,
      context: 'EVM-family signing reauth refresh',
      diagnostics: argsForRefresh.diagnostics,
    });
    if (resolvedLane.authMethod !== argsForRefresh.authMethod) {
      throw new Error(
        `[SigningEngine][ecdsa] reauth lane auth method ${resolvedLane.authMethod} did not match ${argsForRefresh.authMethod}`,
      );
    }
    const transactionLane = selectedEvmFamilyEcdsaLaneForMaterialIdentity({
      lane: resolvedLane,
      chain: requestChain,
      chainTarget: requestChainTarget,
      identity: argsForRefresh.record,
      context: 'reauth refresh',
    });
    const preparedTransaction = await prepareTransactionSigningOperation({
      intent:
        signingTarget.kind === 'tempo'
          ? {
              walletId,
              curve: 'ecdsa',
              chain: 'tempo',
              chainTarget: signingTarget,
              authSelectionPolicy: { kind: 'explicit', authMethod: resolvedLane.authMethod },
              operationUsesNeeded: requiredSignatureUses,
            }
          : {
              walletId,
              curve: 'ecdsa',
              chain: 'evm',
              chainTarget: signingTarget,
              authSelectionPolicy: { kind: 'explicit', authMethod: resolvedLane.authMethod },
              operationUsesNeeded: requiredSignatureUses,
            },
      coordinator: signingSessionCoordinator,
      missingWhenExpiresAtMissing: true,
      prepareBudgetIdentity: true,
      lifecycleAdapter: {
        prepare: async () => {
          const expiresAtMs = Math.floor(
            Number(argsForRefresh.record.expiresAtMs) || Date.now() + 120_000,
          );
          const remainingUses = Math.max(
            1,
            Math.floor(Number(argsForRefresh.record.remainingUses) || 1),
          );
          return {
            lane: resolvedLane,
            transactionLane,
            readiness: {
              readiness: {
                status: 'ready',
                thresholdSessionId: resolvedLane.thresholdSessionId,
                expiresAtMs,
                remainingUses,
              },
              expiresAtMs,
              remainingUses,
            },
            availableLanesGeneration: Date.now(),
            metadata: {},
          };
        },
      },
    });
    const preparedOperation = preparedTransaction.thresholdOperation;
    const readyMaterial = requireReadyEcdsaMaterialForResolvedLane({
      lane: preparedOperation.lane,
      authMethod: argsForRefresh.authMethod,
      source: argsForRefresh.source,
      record: argsForRefresh.record,
      context: 'EVM-family signing reauth refresh',
    });
    const prepared: PreparedEvmFamilyEcdsaSigningSession = {
      accountAuth: resolvedAccountAuth,
      authMethod: argsForRefresh.authMethod,
      source: argsForRefresh.source,
      selection: {
        kind: 'ready',
        accountAuth: resolvedAccountAuth,
        authMethod: argsForRefresh.authMethod,
        source: argsForRefresh.source,
        lane: preparedOperation.lane,
        material: readyMaterial,
        diagnostics: {
          selectedLaneCandidate: {
            authMethod: argsForRefresh.authMethod,
            chain: requestChain,
            chainTarget: requestChainTarget,
            state: 'ready',
            source: 'runtime_session_record',
            walletSigningSessionId: String(preparedOperation.lane.walletSigningSessionId),
            thresholdSessionId: String(preparedOperation.lane.thresholdSessionId),
            remainingUses: null,
            expiresAtMs: null,
            updatedAtMs: null,
          },
          exactCandidateMaterial: summarizeEcdsaMaterialState(readyMaterial),
          visibleEmailOtpMaterial: { present: false },
          visiblePasskeyMaterials: [],
          selectedPasskeyMaterial: { present: false },
        },
      },
      material: readyMaterial,
      availableLanesGeneration: preparedOperation.availableLanesGeneration,
      signingLane: preparedOperation.lane,
      preparedOperation,
      transactionOperation: preparedTransaction.transactionOperation,
      budget: preparedTransaction.budget,
      ...(argsForRefresh.trustedStatusAuth
        ? { budgetStatusAuth: argsForRefresh.trustedStatusAuth }
        : {}),
    };
    assertPreparedEcdsaOperationLane(prepared, 'EVM-family signing reauth refresh');
    preparedEcdsaSigningSession = prepared;
    ecdsaSigningLane = prepared.signingLane;
    selectedEcdsaAuthMethod = prepared.authMethod;
    return prepared;
  };
  const admitPreparedEcdsaTransactionBudget = async (
    prepared: PreparedEvmFamilyEcdsaSigningSession,
    trustedStatusAuth?: SigningSessionBudgetStatusAuth,
  ): Promise<PreparedEvmFamilyEcdsaSigningSession> => {
    assertPreparedEcdsaOperationLane(prepared, 'budget identity preparation');
    const admittedBudgetIdentity = getAdmittedEcdsaBudgetIdentity(prepared);
    if (
      admittedBudgetIdentity &&
      admittedBudgetIdentity.walletSigningSessionId ===
        String(prepared.signingLane.walletSigningSessionId) &&
      String(prepared.transactionOperation.lane.thresholdSessionId) ===
        String(prepared.signingLane.thresholdSessionId)
    ) {
      emitSigningSessionFlowTrace('evm-family', {
        stage: 'ecdsa_attempt.budget_admission_reused',
        accountId: walletId,
        chain: args.request.chain,
        chainTarget: requestChainTarget,
        lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
        budgetKind: prepared.budget.kind,
        ...buildBudgetFailureDiagnostics(prepared),
      });
      return prepared;
    }
    const budgetIdentity = await signingSessionCoordinator.prepareBudgetIdentity({
      lane: prepared.signingLane,
      operationUsesNeeded: requiredSignatureUses,
      ...(trustedStatusAuth || prepared.budgetStatusAuth
        ? { trustedStatusAuth: trustedStatusAuth || prepared.budgetStatusAuth }
        : {}),
    });
    const updatedPrepared = admitPreparedEcdsaBudgetIdentity(
      prepared,
      budgetIdentity,
      trustedStatusAuth || prepared.budgetStatusAuth,
    );
    assertPreparedEcdsaOperationLane(updatedPrepared, 'budget identity preparation');
    emitSigningSessionFlowTrace('evm-family', {
      stage: 'ecdsa_attempt.budget_admitted',
      accountId: walletId,
      chain: args.request.chain,
      chainTarget: requestChainTarget,
      lane: summarizeEvmFamilyEcdsaLane(updatedPrepared.signingLane),
      budgetKind: updatedPrepared.budget.kind,
      ...buildBudgetFailureDiagnostics(updatedPrepared),
    });
    return updatedPrepared;
  };
  function assertPreparedEcdsaBudgetAdmitted(
    prepared: PreparedEvmFamilyEcdsaSigningSession,
    context: string,
  ): asserts prepared is PreparedEvmFamilyEcdsaSigningSession & {
    budget: Extract<PreparedEvmFamilyEcdsaSigningSession['budget'], { kind: 'BudgetAdmitted' }>;
  } {
    if (prepared.budget.kind === 'BudgetAdmitted') {
      return;
    }
    emitSigningSessionFlowFailure('evm-family', {
      stage: 'ecdsa_attempt.admitted_state_required',
      accountId: walletId,
      chain: args.request.chain,
      context,
      lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
      budgetKind: prepared.budget.kind,
      ...buildBudgetFailureDiagnostics(prepared),
    });
    throw new Error(`[SigningEngine][ecdsa] ${context} requires admitted budget state`);
  }
  const requireBudgetAdmittedPreparedEcdsaSession = (
    expectedPrepared: PreparedEvmFamilyEcdsaSigningSession | undefined,
    context: string,
  ): PreparedEvmFamilyEcdsaSigningSession & {
    budget: Extract<PreparedEvmFamilyEcdsaSigningSession['budget'], { kind: 'BudgetAdmitted' }>;
  } => {
    const prepared = expectedPrepared || getPreparedEcdsaSigningSession();
    assertPreparedEcdsaOperationLane(prepared, context);
    assertPreparedEcdsaBudgetAdmitted(prepared, context);
    return prepared;
  };
  const requirePreparedEcdsaBudgetKey = (
    prepared: PreparedEvmFamilyEcdsaSigningSession,
    context: string,
  ) => requireReadyEcdsaMaterial(prepared.material, context).readyMaterial.key;
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
  if (
    args.request.senderSignatureAlgorithm === 'secp256k1' &&
    preparedEcdsaSigningSession &&
    signingSessionPlan?.kind === SigningSessionPlanKind.WarmSession &&
    isWarmSessionSigningAuthPlan(signingAuthPlan) &&
    preparedEcdsaSigningSession.material.kind === 'ready_to_sign' &&
    preparedEcdsaSigningSession.budget.kind !== 'BudgetAdmitted'
  ) {
    try {
      const admittedWarmSession = await admitPreparedEcdsaTransactionBudget(
        preparedEcdsaSigningSession,
        preparedEcdsaSigningSession.budgetStatusAuth,
      );
      if (admittedWarmSession.budget.kind === 'BudgetAdmitted') {
        preparedEcdsaSigningSession = admittedWarmSession;
        ecdsaSigningLane = admittedWarmSession.signingLane;
        selectedEcdsaAuthMethod = admittedWarmSession.authMethod;
        thresholdEcdsaRecord = getEcdsaMaterialRecord(admittedWarmSession.material);
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_attempt.warm_session_budget_admitted',
          accountId: walletId,
          chain: args.request.chain,
          chainTarget: requestChainTarget,
          lane: summarizeEvmFamilyEcdsaLane(admittedWarmSession.signingLane),
          authMethod: admittedWarmSession.authMethod,
          budgetKind: admittedWarmSession.budget.kind,
        });
      }
    } catch (error: unknown) {
      emitSigningSessionFlowFailure('evm-family', {
        stage: 'ecdsa_attempt.warm_session_budget_admission_failed',
        accountId: walletId,
        chain: args.request.chain,
        chainTarget: requestChainTarget,
        lane: summarizeEvmFamilyEcdsaLane(preparedEcdsaSigningSession.signingLane),
        authMethod: preparedEcdsaSigningSession.authMethod,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
      if (
        preparedEcdsaSigningSession.authMethod === SIGNER_AUTH_METHODS.emailOtp &&
        resolvedAccountAuth.primaryAuthMethod === SIGNER_AUTH_METHODS.emailOtp &&
        !attempt.retryingFreshAuth
      ) {
        emitEvmFamilyFreshAuthRetryEvent({
          walletId,
          chain: args.request.chain,
          accountAuth: resolvedAccountAuth,
          onEvent: args.onEvent,
        });
        return await signEvmFamilyAttempt(deps, args, {
          forceFreshAuth: true,
          operationIds,
          retryingFreshAuth: true,
          signingSessionCoordinator,
        });
      }
    }
  }
  const emailOtpSigningForFlow = emailOtpSigning
    ? {
        ...emailOtpSigning,
        complete: async (authorization: EvmFamilyEcdsaEmailOtpStepUpAuthorization) => {
          const refreshed = await completeEvmFamilyEmailOtpSigningRefresh({
            walletSession: args.walletSession,
            chain: requestChain,
            chainTarget: signingTarget,
            emailOtpSigning,
            authorization,
          });
          ecdsaSigningLane = refreshed.lane;
          thresholdEcdsaRecord = refreshed.record;
          selectedEcdsaAuthMethod = SIGNER_AUTH_METHODS.emailOtp;
          emitSigningSessionFlowTrace('evm-family', {
            stage: 'ecdsa_attempt.email_otp_reauth_refreshed',
            accountId: walletId,
            chain: args.request.chain,
            refreshedLane: summarizeEvmFamilyEcdsaLane(refreshed.lane),
            refreshedRecord: summarizeEvmFamilyEcdsaSessionRecord(refreshed.record),
          });
          const refreshedTrustedBudgetStatusAuth = await trustedBudgetStatusAuthFromReadyMaterial(
            refreshed.readyMaterial,
          );
          const preparedAfterReauth = await replacePreparedEcdsaSigningOperationAfterReauth({
            authMethod: SIGNER_AUTH_METHODS.emailOtp,
            source: SIGNER_AUTH_METHODS.emailOtp,
            signingLane: refreshed.lane,
            record: refreshed.record,
            trustedStatusAuth: refreshedTrustedBudgetStatusAuth,
            diagnostics: {
              ...ecdsaAttemptDiagnostics,
              refreshedLane: summarizeEvmFamilyEcdsaLane(refreshed.lane),
              refreshedRecord: summarizeEvmFamilyEcdsaSessionRecord(refreshed.record),
            },
          });
          const admittedAfterReauth = await admitPreparedEcdsaTransactionBudget(
            preparedAfterReauth,
            refreshedTrustedBudgetStatusAuth,
          );
          if (admittedAfterReauth.budget.kind !== 'BudgetAdmitted') {
            emitSigningSessionFlowFailure('evm-family', {
              stage: 'ecdsa_attempt.email_otp_reauth_not_admitted',
              accountId: walletId,
              chain: args.request.chain,
              lane: summarizeEvmFamilyEcdsaLane(admittedAfterReauth.signingLane),
              budgetKind: admittedAfterReauth.budget.kind,
              ...buildBudgetFailureDiagnostics(admittedAfterReauth),
            });
            throw new Error(
              '[SigningEngine][ecdsa] Email OTP reauth did not produce budget-admitted operation',
            );
          }
          emitSigningSessionFlowTrace('evm-family', {
            stage: 'ecdsa_attempt.email_otp_reauth_admitted',
            accountId: walletId,
            chain: args.request.chain,
            ...(derivePreparedEvmFamilyKeyFingerprint(admittedAfterReauth)
              ? {
                  evmFamilyKeyFingerprint:
                    derivePreparedEvmFamilyKeyFingerprint(admittedAfterReauth),
                }
              : {}),
            lane: summarizeEvmFamilyEcdsaLane(admittedAfterReauth.signingLane),
            budgetKind: admittedAfterReauth.budget.kind,
          });
          preparedEcdsaSigningSession = admittedAfterReauth;
          ecdsaSigningLane = admittedAfterReauth.signingLane;
          selectedEcdsaAuthMethod = admittedAfterReauth.authMethod;
          const readyToSignMaterial = requireReadyEcdsaMaterial(
            admittedAfterReauth.material,
            'Email OTP ECDSA reauth completion',
          );
          return await buildEvmFamilyThresholdEcdsaReauthResult({
            readyToSignMaterial,
            operation: {
              ...admittedAfterReauth.budget.operation,
              authPlan: signingAuthPlan,
            },
          });
        },
      }
    : undefined;
  const { flowArgs, warmSessionServices } = await createEvmFamilySigningFlowRuntime({
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
    getThresholdEcdsaRecord: () => thresholdEcdsaRecord,
    setThresholdEcdsaRecord: async ({ record }) => {
      thresholdEcdsaRecord = record;
      if (args.request.senderSignatureAlgorithm === 'secp256k1' && preparedEcdsaSigningSession) {
        const currentPrepared = preparedEcdsaSigningSession;
        const refreshedThresholdSessionId = String(record.thresholdSessionId || '').trim();
        const refreshedWalletSigningSessionId = String(record.walletSigningSessionId || '').trim();
        if (!refreshedThresholdSessionId || !refreshedWalletSigningSessionId) {
          throw new Error(
            '[SigningEngine][ecdsa] record update requires explicit session identity',
          );
        }
        const replacedLaneIdentity =
          refreshedThresholdSessionId !== String(currentPrepared.signingLane.thresholdSessionId) ||
          refreshedWalletSigningSessionId !==
            String(currentPrepared.signingLane.walletSigningSessionId);
        let updatedPrepared: PreparedEvmFamilyEcdsaSigningSession;
        if (replacedLaneIdentity) {
          const refreshedLane = updateResolvedEvmFamilyEcdsaSigningLaneIdentity({
            lane: currentPrepared.signingLane,
            chain: requestChain,
            thresholdSessionId: refreshedThresholdSessionId,
            walletSigningSessionId: refreshedWalletSigningSessionId,
            context: 'EVM-family signing record refresh',
            diagnostics: {
              ...ecdsaAttemptDiagnostics,
              updatedRecord: summarizeEvmFamilyEcdsaSessionRecord(record),
            },
          });
          updatedPrepared = await replacePreparedEcdsaSigningOperationAfterReauth({
            authMethod: currentPrepared.authMethod,
            source: currentPrepared.source,
            signingLane: refreshedLane,
            record,
            diagnostics: {
              ...ecdsaAttemptDiagnostics,
              updatedRecord: summarizeEvmFamilyEcdsaSessionRecord(record),
            },
          });
        } else {
          updatedPrepared = updatePreparedEcdsaSigningSessionForSameOperation({
            authMethod: currentPrepared.authMethod,
            source: currentPrepared.source,
            context: 'EVM-family signing record update',
            diagnostics: {
              ...ecdsaAttemptDiagnostics,
              updatedRecord: summarizeEvmFamilyEcdsaSessionRecord(record),
            },
            signingSessionIdentity: {
              thresholdSessionId: refreshedThresholdSessionId,
              walletSigningSessionId: refreshedWalletSigningSessionId,
            },
            forceRefreshBudgetIdentity: !walletSigningSessionBudgetReserved,
          });
        }
        const refreshedReadyToSignMaterial = requireReadyEcdsaMaterial(
          updatedPrepared.material,
          'EVM-family signing record refresh',
        );
        const admittedPrepared = await admitPreparedEcdsaTransactionBudget(
          updatedPrepared,
          trustedBudgetStatusAuthFromReadySignerSession(
            refreshedReadyToSignMaterial.signerSession,
          ),
        );
        if (admittedPrepared.budget.kind !== 'BudgetAdmitted') {
          throw new Error(
            '[SigningEngine][ecdsa] record refresh did not produce budget-admitted operation',
          );
        }
        preparedEcdsaSigningSession = admittedPrepared;
        ecdsaSigningLane = admittedPrepared.signingLane;
        selectedEcdsaAuthMethod = admittedPrepared.authMethod;
        thresholdEcdsaRecord = getEcdsaMaterialRecord(admittedPrepared.material);
        const readyToSignMaterial = requireReadyEcdsaMaterial(
          admittedPrepared.material,
          'EVM-family signing record refresh',
        );
        return await buildEvmFamilyThresholdEcdsaReauthResult({
          readyToSignMaterial,
          operation: {
            ...admittedPrepared.budget.operation,
            authPlan: signingAuthPlan,
          },
        });
      }
      throw new Error('[SigningEngine][ecdsa] record refresh requires prepared ECDSA session');
    },
    getResolvedEcdsaSigningLane,
  });

  let freshAuthRetryHandledFinalization = false;
  const retryWithFreshEmailOtpAuth = async (
    error: unknown,
  ): Promise<TempoSignedResult | EvmSignedResult | null> => {
    return await retryEvmFamilyWithFreshEmailOtpAuthWhenRequired({
      error,
      walletId,
      chain: args.request.chain,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      accountAuth: resolvedAccountAuth,
      alreadyRetryingFreshEmailOtpAuth: attempt.retryingFreshAuth,
      hasEmailOtpSigningPlan: !!emailOtpSigning,
      sideEffectState: freshAuthRetrySideEffectState,
      onDecision: (decision) => recordFreshAuthRetryDecision(decision, error),
      onEvent: args.onEvent,
      retry: async () => {
        const result = await signEvmFamilyAttempt(deps, args, {
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
    const emailOtpRetry = await retryWithFreshEmailOtpAuth(error);
    if (emailOtpRetry) return emailOtpRetry;
    const decision = classifyEvmFamilyFreshAuthRetry({
      trigger: 'wallet_signing_budget_exhausted',
      error,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      accountAuth: resolvedAccountAuth,
      alreadyRetryingFreshAuth: attempt.retryingFreshAuth,
      hasStepUpAuthPlan:
        isEmailOtpSigningAuthPlan(signingAuthPlan) || isPasskeySigningAuthPlan(signingAuthPlan),
      sideEffectState: freshAuthRetrySideEffectState,
    });
    recordFreshAuthRetryDecision(decision, error);
    if (decision.kind !== 'retry') return null;
    emitEvmFamilyFreshAuthRetryEvent({
      walletId,
      chain: args.request.chain,
      accountAuth: resolvedAccountAuth,
      onEvent: args.onEvent,
    });
    const result = await signEvmFamilyAttempt(deps, args, {
      forceFreshAuth: true,
      operationIds,
      retryingFreshAuth: true,
      signingSessionCoordinator,
    });
    freshAuthRetryHandledFinalization = true;
    return result;
  };
  const recordSuccessfulWalletSigningSessionSpend = async (
    expectedPrepared?: PreparedEvmFamilyEcdsaSigningSession,
  ): Promise<void> => {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return;
    const prepared = requireBudgetAdmittedPreparedEcdsaSession(
      expectedPrepared,
      'successful wallet signing-session spend',
    );
    const budgetDiagnostics = buildBudgetFailureDiagnostics(prepared);
    emitSigningSessionFlowTrace('evm-family', {
      stage: 'ecdsa_attempt.budget_finalization_started',
      accountId: walletId,
      chain: args.request.chain,
      chainTarget: requestChainTarget,
      lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
      reserved: walletSigningSessionBudgetReserved,
      ...budgetDiagnostics,
    });
    try {
      await recordSuccessfulEvmFamilyWalletSigningSessionSpend({
        signingSessionCoordinator,
        walletSession: args.walletSession,
        operation: createTransactionSigningOperation(),
        admittedTransaction: prepared.budget.operation,
        finalizedSigningLane: prepared.signingLane,
        key: requirePreparedEcdsaBudgetKey(prepared, 'successful wallet signing-session spend'),
        reserved: walletSigningSessionBudgetReserved,
        ...(prepared.budgetStatusAuth ? { trustedStatusAuth: prepared.budgetStatusAuth } : {}),
      });
      emitSigningSessionFlowTrace('evm-family', {
        stage: 'ecdsa_attempt.budget_finalized',
        accountId: walletId,
        chain: args.request.chain,
        chainTarget: requestChainTarget,
        lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
        reserved: walletSigningSessionBudgetReserved,
        ...budgetDiagnostics,
      });
    } catch (error: unknown) {
      emitSigningSessionFlowFailure('evm-family', {
        stage: 'ecdsa_attempt.budget_finalization_failed',
        accountId: walletId,
        chain: args.request.chain,
        chainTarget: requestChainTarget,
        lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
        reserved: walletSigningSessionBudgetReserved,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
        ...budgetDiagnostics,
      });
      throw error;
    }
  };
  let walletSigningSessionBudgetReserved = false;
  const reserveWalletSigningSessionBudget = async (
    operation: BudgetAdmittedOperation<SelectedEcdsaLane>,
  ): Promise<SigningSessionBudgetReserveResult> => {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return null;
    const prepared = requireBudgetAdmittedPreparedEcdsaSession(
      undefined,
      'wallet signing-session reservation',
    );
    if (
      String(operation.lane.walletSigningSessionId) !==
        String(prepared.transactionOperation.lane.walletSigningSessionId) ||
      String(operation.lane.thresholdSessionId) !==
        String(prepared.transactionOperation.lane.thresholdSessionId)
    ) {
      throw new Error(
        '[SigningEngine][ecdsa] budget reservation operation does not match prepared transaction lane',
      );
    }
    const reservation = await reserveEvmFamilyWalletSigningSessionBudget({
      signingSessionCoordinator,
      walletSession: args.walletSession,
      operation: createTransactionSigningOperation(),
      admittedTransaction: operation,
      finalizedSigningLane: prepared.signingLane,
      key: requirePreparedEcdsaBudgetKey(prepared, 'wallet signing-session reservation'),
      ...(prepared.budgetStatusAuth ? { trustedStatusAuth: prepared.budgetStatusAuth } : {}),
    });
    walletSigningSessionBudgetReserved = isSigningSessionBudgetReservation(reservation);
    return reservation;
  };
  const recordFailedWalletSigningSessionSpend = (
    error: unknown,
    expectedPrepared?: PreparedEvmFamilyEcdsaSigningSession,
  ): void => {
    if (!confirmationDisplayed) return;
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return;
    const prepared = expectedPrepared || getPreparedEcdsaSigningSession();
    assertPreparedEcdsaOperationLane(prepared, 'failed spend finalization');
    if (prepared.budget.kind !== 'BudgetAdmitted') return;
    emitSigningSessionFlowTrace('evm-family', {
      stage: 'ecdsa_attempt.budget_zero_spend_recorded',
      accountId: walletId,
      chain: args.request.chain,
      chainTarget: requestChainTarget,
      lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
      error: error instanceof Error ? error.message : String(error || 'unknown error'),
      ...buildBudgetFailureDiagnostics(prepared),
    });
    recordFailedEvmFamilyWalletSigningSessionSpend({
      signingSessionCoordinator,
      walletSession: args.walletSession,
      operation: createTransactionSigningOperation(),
      error,
      admittedTransaction: prepared.budget.operation,
      finalizedSigningLane: prepared.signingLane,
      key: requirePreparedEcdsaBudgetKey(prepared, 'failed wallet signing-session spend'),
      ...(prepared.budgetStatusAuth ? { trustedStatusAuth: prepared.budgetStatusAuth } : {}),
    });
  };
  const applySuccessfulEcdsaPostSignPolicy = async (
    expectedPrepared?: PreparedEvmFamilyEcdsaSigningSession,
  ): Promise<void> => {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return;
    const prepared = expectedPrepared || getPreparedEcdsaSigningSession();
    assertPreparedEcdsaOperationLane(prepared, 'post-sign policy');
    const selectedRecord =
      (prepared.selection.kind === 'reauth_required'
        ? getEcdsaMaterialRecord(prepared.selection.material)
        : undefined) || getEcdsaMaterialRecord(prepared.material);
    if (!selectedRecord) {
      // A fresh OTP/passkey reconnect can carry exact keyRef material before the
      // runtime record index catches up. There is no safe global rediscovery
      // here, so finalization follows the admitted lane and skips local cleanup.
      return;
    }
    await applySuccessfulEvmFamilyEcdsaPostSignPolicy({
      postSignPolicy: warmSessionServices,
      walletId,
      chainTarget: prepared.transactionOperation.lane.chainTarget,
      ecdsaSigningLane: prepared.signingLane,
      selectedRecord,
    });
  };
  const preparedNonceSession = getPreparedEcdsaSigningSessionIfEcdsa();
  const nonceOperation: NonceOperationContext = {
    ...createTransactionSigningOperation(),
    accountId: walletId,
  };
  if (preparedNonceSession) {
    const nonceFingerprint = derivePreparedEvmFamilyKeyFingerprint(preparedNonceSession);
    emitSigningSessionFlowTrace('evm-family', {
      stage: 'ecdsa_attempt.nonce_operation_prepared',
      accountId: walletId,
      chain: requestChain,
      chainTarget: requestChainTarget,
      ...(nonceFingerprint ? { evmFamilyKeyFingerprint: nonceFingerprint } : {}),
      walletSigningSessionId: String(preparedNonceSession.signingLane.walletSigningSessionId),
      thresholdSessionId: String(preparedNonceSession.signingLane.thresholdSessionId),
    });
  }
  const preparedExecutorSession = getPreparedEcdsaSigningSessionIfEcdsa();
  const preparedExecutorReadyMaterial =
    preparedExecutorSession?.material.kind === 'ready_to_sign'
      ? preparedExecutorSession.material
      : null;
  const preparedExecutorSignerSession = preparedExecutorReadyMaterial?.signerSession || null;
  const preparedExecutorSingleUseEmailOtpSession =
    preparedExecutorReadyMaterial?.readyMaterial.record.source === 'email_otp' &&
    preparedExecutorReadyMaterial.readyMaterial.record.emailOtpAuthContext?.retention ===
      'single_use';
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
    ? preparedExecutorSession.budget.kind === 'BudgetAdmitted' && preparedExecutorSignerSession
      ? {
          kind: 'required_admitted',
          authPlan: {
            kind: 'planned',
            signingAuthPlan,
          },
          operation: {
            ...preparedExecutorSession.budget.operation,
            authPlan: signingAuthPlan,
          },
          signerSession: preparedExecutorSignerSession,
          singleUseEmailOtpSession: preparedExecutorSingleUseEmailOtpSession,
          runtime: requireThresholdEcdsaStepUpRuntime(),
        }
      : {
          kind: 'required_not_admitted',
          authPlan: {
            kind: 'planned',
            signingAuthPlan,
          },
          runtime: requireThresholdEcdsaStepUpRuntime(),
        }
    : {
        kind: 'not_required',
      };
  const thresholdEcdsaState: EvmFamilyExecutorThresholdEcdsaState = await (async () => {
    if (!preparedExecutorSession) {
      return {
        kind: 'not_required',
      };
    }
    if (!signingSessionPlan) {
      throw new Error('[SigningEngine][ecdsa] prepared executor requires a signing session plan');
    }
    const readyMaterial = preparedExecutorReadyMaterial?.readyMaterial || null;
    const publicFacts = preparedExecutorReadyMaterial
      ? preparedExecutorReadyMaterial.publicFacts
      : thresholdEcdsaRecord
        ? await toVerifiedEcdsaPublicFactsFromRecord({
            record: thresholdEcdsaRecord,
          })
        : null;
    const thresholdOwnerAddress = toOptionalEvmAddress(
      publicFacts?.thresholdOwnerAddress,
    );
    if (!thresholdOwnerAddress) {
      if (signingSessionPlan.kind === SigningSessionPlanKind.EmailOtpReauth) {
        return {
          kind: 'not_required',
        };
      }
      throw new Error(
        '[SigningEngine][ecdsa] prepared EVM-family signing requires threshold owner address',
      );
    }
    return {
      kind: 'prepared',
      lane: preparedExecutorSession.transactionOperation.lane,
      signingSessionPlan,
      thresholdOwnerAddress,
    };
  })();

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
    reserveWalletSigningSessionBudget,
    recordSuccessfulWalletSigningSessionSpend,
    recordFailedWalletSigningSessionSpend,
    applySuccessfulEcdsaPostSignPolicy,
    deferSuccessfulSigningSessionFinalization: Boolean(preparedExecutorSession),
    deferFailedSigningSessionFinalization: Boolean(preparedExecutorSession),
    retryWithFreshEmailOtpAuth: retryWithFreshAuth,
  };
  if (preparedExecutorSession) {
    let result: EvmSignedResult | TempoSignedResult;
    try {
      if (preparedExecutorSession.budget.kind === 'BudgetAdmitted') {
        const signedOperation = await signPreparedTransactionOperation(
          preparedExecutorSession.budget.operation,
          executePayload,
          {
            sign: async (_operation, payload) => await executeEvmFamilyTransactionSigning(payload),
          },
        );
        result = signedOperation.result;
      } else {
        // Exhausted lanes become budget-admitted only after the confirmed
        // step-up reconnect publishes the fresh exact lane.
        result = await executeEvmFamilyTransactionSigning(executePayload);
      }
    } catch (error: unknown) {
      const failedPreparedSession = preparedEcdsaSigningSession || preparedExecutorSession;
      assertPreparedEcdsaOperationLane(failedPreparedSession, 'failed prepared finalization');
      recordFailedWalletSigningSessionSpend(error, failedPreparedSession);
      throw error;
    }
    if (freshAuthRetryHandledFinalization) {
      return result;
    }
    const finalPreparedSession = requireBudgetAdmittedPreparedEcdsaSession(
      preparedEcdsaSigningSession || preparedExecutorSession,
      'threshold transaction finalization',
    );
    assertPreparedEcdsaOperationLane(finalPreparedSession, 'successful prepared finalization');
    await finalizeSignedTransactionOperation(
      {
        ...finalPreparedSession.budget.operation,
        result,
      },
      {
        recordSuccess: async () => {
          await recordSuccessfulWalletSigningSessionSpend(finalPreparedSession);
        },
        cleanup: async () => {
          await applySuccessfulEcdsaPostSignPolicy(finalPreparedSession);
        },
      },
    );
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

export async function signTempo(
  deps: TempoSigningDeps,
  args: SignEvmFamilyArgs,
): Promise<TempoSignedResult | EvmSignedResult> {
  return await signEvmFamily(deps, args);
}

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
