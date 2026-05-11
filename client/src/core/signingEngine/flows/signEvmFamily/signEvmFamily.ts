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
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
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
  WarmSessionMaterialClearer,
  WarmSessionStatusResult,
  WarmSessionStatusReader,
} from '../../uiConfirm/types';
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
  isSigningSessionBudgetExhaustedError,
  type SigningSessionBudgetStatusAuth,
  type SigningSessionPreparedBudgetIdentity,
  type SigningSessionBudgetReservation,
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
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { throwIfEvmFamilySigningCancelled } from './errors';
import {
  requireResolvedEvmFamilyEcdsaSigningLane,
  selectedEvmFamilyEcdsaLaneForMaterialIdentity,
  isEmailOtpThresholdEcdsaSigningContext,
  summarizeEvmFamilyEcdsaKeyRef,
  summarizeEvmFamilyEcdsaLane,
  summarizeEvmFamilyEcdsaSessionRecord,
  updateResolvedEvmFamilyEcdsaSigningLaneIdentity,
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import {
  buildEcdsaMaterialStateForCandidate,
  getEcdsaMaterialKeyRef,
  getEcdsaMaterialRecord,
  requireReadyEcdsaMaterial,
  type ReadyEcdsaMaterial,
  type EcdsaMaterialState,
} from './ecdsaMaterialState';
import { resolveEvmFamilyTransactionAccountAuth } from './accountAuth';
import { resolveEvmFamilyTransactionStepUp } from './authPlanning';
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
import { isPasskeySigningAuthPlan } from '../../stepUpConfirmation/types';
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
  replacePreparedTransactionLane,
  signPreparedTransactionOperation,
  type BudgetAdmittedOperation,
} from '../../session/operationState/transactionState';
import { completeEvmFamilyEmailOtpSigningRefresh } from './emailOtpRefresh';
import type { EvmFamilyEcdsaEmailOtpStepUpAuthorization } from './stepUpAuthorization';
import { createEvmFamilySigningFlowRuntime } from './signingFlowRuntime';
import { retryEvmFamilyWithFreshEmailOtpAuthWhenRequired } from './freshEmailOtpRetry';
import { emitEvmFamilySigningEvent, emitEvmFamilySigningOperationTrace } from './events';
import { toOptionalEvmAddress } from './addresses';
import {
  bindEvmFamilyCallerProvidedOperationIdToFingerprint,
  createEvmFamilySigningOperationIds,
  ensureEvmFamilyConfirmationOperationId,
  type EvmFamilySigningOperationIds,
} from './operationIds';
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
  return prepared.budget.kind === 'admitted'
    ? prepared.budget.operation.budgetAdmission.budgetIdentity
    : null;
}

function trustedBudgetStatusAuthFromEcdsaKeyRef(
  keyRef: ThresholdEcdsaSecp256k1KeyRef | undefined,
): SigningSessionBudgetStatusAuth | undefined {
  const relayerUrl = String(keyRef?.relayerUrl || '').trim();
  const thresholdSessionId = String(keyRef?.thresholdSessionId || '').trim();
  if (!relayerUrl || !thresholdSessionId) return undefined;
  const thresholdSessionAuthToken = String(keyRef?.thresholdSessionAuthToken || '').trim();
  return {
    relayerUrl,
    thresholdSessionId,
    ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
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
  nearAccountId: string;
  subjectId: WalletSubjectId;
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
  nearAccountId: string;
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
    accountId: args.nearAccountId,
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

  const signingTarget = evmFamilySigningTargetFromExplicitTarget({
    request: args.request,
    chainTarget: args.chainTarget,
  });
  await ensureSealedRefreshStartupParityForTransactionSigning(
    deps.ensureSealedRefreshStartupParity,
    {
      nearAccountId: args.nearAccountId,
      chainTarget: signingTarget,
    },
  );
  const requestChain = signingTarget.kind;
  const requestChainTarget = signingTarget;

  let thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  let thresholdEcdsaRecord: ThresholdEcdsaSessionRecord | undefined;
  let accountAuth: AccountAuthMetadata | undefined;
  let ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane | undefined;
  let selectedEcdsaAuthMethod: EvmFamilyEcdsaAuthMethod | undefined;
  let emailOtpReauthRecord: ThresholdEcdsaSessionRecord | undefined;
  let preparedEcdsaSigningSession: PreparedEvmFamilyEcdsaSigningSession | undefined;
  const ecdsaAttemptDiagnostics: Record<string, unknown> = {
    nearAccountId: args.nearAccountId,
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
        nearAccountId: args.nearAccountId,
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
  let confirmationDisplayed = false;
  const markConfirmationDisplayed = (): SigningOperationId => {
    confirmationDisplayed = true;
    return ensureConfirmationOperationId();
  };
  if (args.request.senderSignatureAlgorithm === 'secp256k1') {
    preparedEcdsaSigningSession = await prepareEvmFamilyEcdsaSigningSession({
      deps,
      nearAccountId: args.nearAccountId,
      subjectId: args.subjectId,
      signingTarget,
      diagnostics: ecdsaAttemptDiagnostics,
      signingSessionCoordinator,
      forceFreshAuth: attempt.forceFreshAuth === true,
    });
    ecdsaSigningLane = preparedEcdsaSigningSession.signingLane;
    selectedEcdsaAuthMethod = preparedEcdsaSigningSession.authMethod;
    emailOtpReauthRecord =
      preparedEcdsaSigningSession.selection.kind === 'reauth_required' &&
      preparedEcdsaSigningSession.authMethod === SIGNER_AUTH_METHODS.emailOtp
        ? getEcdsaMaterialRecord(preparedEcdsaSigningSession.selection.material)
        : undefined;
    accountAuth = preparedEcdsaSigningSession.accountAuth;
    thresholdEcdsaRecord = getEcdsaMaterialRecord(preparedEcdsaSigningSession.material);
    thresholdEcdsaKeyRef = getEcdsaMaterialKeyRef(preparedEcdsaSigningSession.material);
    emitSigningSessionFlowTrace('evm-family', {
      stage: 'ecdsa_attempt.prepared',
      accountId: args.nearAccountId,
      chain: requestChain,
      chainTarget: requestChainTarget,
      authMethod: selectedEcdsaAuthMethod,
      lane: summarizeEvmFamilyEcdsaLane(ecdsaSigningLane),
      warmRecord: summarizeEvmFamilyEcdsaSessionRecord(thresholdEcdsaRecord),
      warmKeyRef: summarizeEvmFamilyEcdsaKeyRef(thresholdEcdsaKeyRef),
      budgetKind: preparedEcdsaSigningSession.budget.kind,
    });
  } else {
    accountAuth = await resolveEvmFamilyTransactionAccountAuth({
      deps,
      nearAccountId: args.nearAccountId,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
    });
  }
  accountAuth =
    accountAuth ||
    (await resolveEvmFamilyTransactionAccountAuth({
      deps,
      nearAccountId: args.nearAccountId,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      ...(thresholdEcdsaRecord ? { sessionSource: thresholdEcdsaRecord.source } : {}),
      isEmailOtpThresholdContext: isEmailOtpThresholdEcdsaSigningContext({
        ...(thresholdEcdsaRecord ? { record: thresholdEcdsaRecord } : {}),
        ...(thresholdEcdsaKeyRef ? { keyRef: thresholdEcdsaKeyRef } : {}),
      }),
    }));
  const resolvedAccountAuth = accountAuth;

  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  const resolvePreparedWarmRecord = (
    prepared: PreparedEvmFamilyEcdsaSigningSession | undefined,
  ): ThresholdEcdsaSessionRecord | undefined =>
    prepared ? getEcdsaMaterialRecord(prepared.material) : undefined;
  const resolvePreparedWarmKeyRef = (
    prepared: PreparedEvmFamilyEcdsaSigningSession | undefined,
  ): ThresholdEcdsaSecp256k1KeyRef | undefined =>
    prepared ? getEcdsaMaterialKeyRef(prepared.material) : undefined;
  const buildPreparedMaterialForLane = (argsForMaterial: {
    lane: ResolvedEvmFamilyEcdsaSigningLane;
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
    record?: ThresholdEcdsaSessionRecord;
    keyRef?: ThresholdEcdsaSecp256k1KeyRef;
  }): EcdsaMaterialState =>
    buildEcdsaMaterialStateForCandidate({
      candidate: {
        kind: 'lane_candidate',
        accountId: argsForMaterial.lane.accountId,
        authMethod: argsForMaterial.authMethod,
        curve: 'ecdsa',
        chain: requestChain,
        walletSigningSessionId: String(argsForMaterial.lane.walletSigningSessionId),
        thresholdSessionId: String(argsForMaterial.lane.thresholdSessionId),
        state: 'ready',
        remainingUses: null,
        expiresAtMs: null,
        updatedAtMs: null,
        source: 'runtime_session_record',
        subjectId: argsForMaterial.lane.subjectId,
        chainTarget: argsForMaterial.lane.chainTarget,
        ecdsaThresholdKeyId: argsForMaterial.lane.ecdsaThresholdKeyId,
        signingRootId: argsForMaterial.lane.signingRootId,
        signingRootVersion: argsForMaterial.lane.signingRootVersion,
      },
      record: argsForMaterial.record,
      keyRef: argsForMaterial.keyRef,
      authMethod: argsForMaterial.authMethod,
      source: argsForMaterial.source,
      chainTarget: argsForMaterial.lane.chainTarget,
    });
  const requirePreparedReadyMaterialForLane = (argsForMaterial: {
    lane: ResolvedEvmFamilyEcdsaSigningLane;
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
    record?: ThresholdEcdsaSessionRecord;
    keyRef?: ThresholdEcdsaSecp256k1KeyRef;
    context: string;
  }): ReadyEcdsaMaterial =>
    requireReadyEcdsaMaterial(
      buildPreparedMaterialForLane({
        lane: argsForMaterial.lane,
        authMethod: argsForMaterial.authMethod,
        source: argsForMaterial.source,
        record: argsForMaterial.record,
        keyRef: argsForMaterial.keyRef,
      }),
      argsForMaterial.context,
    );
  const resolveEmailOtpReauthRecord = (): ThresholdEcdsaSessionRecord | undefined =>
    (preparedEcdsaSigningSession?.selection.kind === 'reauth_required' &&
    preparedEcdsaSigningSession.authMethod === SIGNER_AUTH_METHODS.emailOtp
      ? getEcdsaMaterialRecord(preparedEcdsaSigningSession.selection.material)
      : undefined) ||
    (selectedEcdsaAuthMethod === SIGNER_AUTH_METHODS.emailOtp ? emailOtpReauthRecord : undefined);
  const authPlanningArgsBase = {
    deps: {
      ...deps,
      signingSessionCoordinator,
    },
    confirmedDeps: deps,
    nearAccountId: args.nearAccountId,
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
    const updatedPrepared = {
      ...preparedWithoutBudget,
      accountAuth: resolvedAccountAuth,
      authMethod: argsForRefresh.authMethod,
      source: argsForRefresh.source,
      material: buildPreparedMaterialForLane({
        lane: signingLane,
        authMethod: argsForRefresh.authMethod,
        source: argsForRefresh.source,
        record: thresholdEcdsaRecord,
        keyRef: thresholdEcdsaKeyRef,
      }),
      selection:
        prepared.selection.kind === 'ready'
          ? {
              ...prepared.selection,
              authMethod: argsForRefresh.authMethod,
              source: argsForRefresh.source,
              lane: signingLane,
              material: requirePreparedReadyMaterialForLane({
                lane: signingLane,
                authMethod: argsForRefresh.authMethod,
                source: argsForRefresh.source,
                record: thresholdEcdsaRecord,
                keyRef: thresholdEcdsaKeyRef,
                context: argsForRefresh.context,
              }),
            }
          : {
              ...prepared.selection,
              authMethod: argsForRefresh.authMethod,
              lane: signingLane,
              material: buildPreparedMaterialForLane({
                lane: signingLane,
                authMethod: argsForRefresh.authMethod,
                source: argsForRefresh.source,
                record: thresholdEcdsaRecord,
                keyRef: thresholdEcdsaKeyRef,
              }),
            },
      signingLane,
      budget: { kind: 'not_admitted' as const, reason: 'budget_identity_not_prepared' as const },
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
    record?: ThresholdEcdsaSessionRecord;
    keyRef?: ThresholdEcdsaSecp256k1KeyRef;
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
    const identitySource = argsForRefresh.keyRef || argsForRefresh.record;
    if (!identitySource) {
      throw new Error(
        '[SigningEngine][ecdsa] reauth refresh requires exact ECDSA material identity',
      );
    }
    const transactionLane = selectedEvmFamilyEcdsaLaneForMaterialIdentity({
      lane: resolvedLane,
      chain: requestChain,
      chainTarget: requestChainTarget,
      identity: identitySource,
      context: 'reauth refresh',
    });
    const preparedTransaction = await prepareTransactionSigningOperation({
      intent:
        signingTarget.kind === 'tempo'
          ? {
              walletId: args.nearAccountId,
              curve: 'ecdsa',
              chain: 'tempo',
              chainTarget: signingTarget,
              authSelectionPolicy: { kind: 'explicit', authMethod: resolvedLane.authMethod },
              operationUsesNeeded: 1,
            }
          : {
              walletId: args.nearAccountId,
              curve: 'ecdsa',
              chain: 'evm',
              chainTarget: signingTarget,
              authSelectionPolicy: { kind: 'explicit', authMethod: resolvedLane.authMethod },
              operationUsesNeeded: 1,
            },
      coordinator: signingSessionCoordinator,
      missingWhenExpiresAtMissing: true,
      prepareBudgetIdentity: true,
      lifecycleAdapter: {
        prepare: async () => ({
          lane: resolvedLane,
          transactionLane,
          readiness: {
            readiness: {
              status: 'ready',
              thresholdSessionId: resolvedLane.thresholdSessionId,
            },
            expiresAtMs: Math.floor(
              Number(argsForRefresh.record?.expiresAtMs) || Date.now() + 120_000,
            ),
            remainingUses: Math.max(
              1,
              Math.floor(Number(argsForRefresh.record?.remainingUses) || 1),
            ),
          },
          availableLanesGeneration: Date.now(),
          metadata: {},
        }),
      },
    });
    const preparedOperation = preparedTransaction.thresholdOperation;
    const readyMaterial = requirePreparedReadyMaterialForLane({
      lane: preparedOperation.lane,
      authMethod: argsForRefresh.authMethod,
      source: argsForRefresh.source,
      record: argsForRefresh.record,
      keyRef: argsForRefresh.keyRef,
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
          exactCandidateMaterial: {
            present: true,
            kind: argsForRefresh.record && argsForRefresh.keyRef ? 'ready_material' : argsForRefresh.record ? 'record_only' : 'key_ref_only',
            authMethod: argsForRefresh.authMethod,
            source: argsForRefresh.source,
            chainTarget: requestChainTarget,
            thresholdSessionId: String(preparedOperation.lane.thresholdSessionId),
            walletSigningSessionId: String(preparedOperation.lane.walletSigningSessionId),
            signingRootId: preparedOperation.lane.signingRootId,
            signingRootVersion: preparedOperation.lane.signingRootVersion,
            ecdsaThresholdKeyId: preparedOperation.lane.ecdsaThresholdKeyId,
            hasRecord: Boolean(argsForRefresh.record),
            hasKeyRef: Boolean(argsForRefresh.keyRef),
          },
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
      return prepared;
    }
    const budgetIdentity = await signingSessionCoordinator.prepareBudgetIdentity({
      nearAccountId: args.nearAccountId,
      lane: prepared.signingLane,
      operationUsesNeeded: 1,
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
    return updatedPrepared;
  };
  function assertPreparedEcdsaBudgetAdmitted(
    prepared: PreparedEvmFamilyEcdsaSigningSession,
    context: string,
  ): asserts prepared is PreparedEvmFamilyEcdsaSigningSession & {
    budget: Extract<PreparedEvmFamilyEcdsaSigningSession['budget'], { kind: 'admitted' }>;
  } {
    if (prepared.budget.kind === 'admitted') {
      return;
    }
    emitSigningSessionFlowFailure('evm-family', {
      stage: 'ecdsa_attempt.admitted_state_required',
      accountId: args.nearAccountId,
      chain: args.request.chain,
      context,
      lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
      budgetKind: prepared.budget.kind,
    });
    throw new Error(`[SigningEngine][ecdsa] ${context} requires admitted budget state`);
  }
  const requireBudgetAdmittedPreparedEcdsaSession = (
    expectedPrepared: PreparedEvmFamilyEcdsaSigningSession | undefined,
    context: string,
  ): PreparedEvmFamilyEcdsaSigningSession & {
    budget: Extract<PreparedEvmFamilyEcdsaSigningSession['budget'], { kind: 'admitted' }>;
  } => {
    const prepared = expectedPrepared || getPreparedEcdsaSigningSession();
    assertPreparedEcdsaOperationLane(prepared, context);
    assertPreparedEcdsaBudgetAdmitted(prepared, context);
    return prepared;
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
        ...emailOtpSigning,
        complete: async (authorization: EvmFamilyEcdsaEmailOtpStepUpAuthorization) => {
          const refreshed = await completeEvmFamilyEmailOtpSigningRefresh({
            nearAccountId: args.nearAccountId,
            chain: requestChain,
            chainTarget: signingTarget,
            emailOtpSigning,
            authorization,
          });
          thresholdEcdsaKeyRef = refreshed.keyRef;
          ecdsaSigningLane = refreshed.lane;
          thresholdEcdsaRecord = refreshed.record;
          selectedEcdsaAuthMethod = SIGNER_AUTH_METHODS.emailOtp;
          emailOtpReauthRecord = thresholdEcdsaRecord;
          emitSigningSessionFlowTrace('evm-family', {
            stage: 'ecdsa_attempt.email_otp_reauth_refreshed',
            accountId: args.nearAccountId,
            chain: args.request.chain,
            refreshedLane: summarizeEvmFamilyEcdsaLane(refreshed.lane),
            refreshedRecord: summarizeEvmFamilyEcdsaSessionRecord(refreshed.record),
            refreshedKeyRef: summarizeEvmFamilyEcdsaKeyRef(refreshed.keyRef),
          });
          const preparedAfterReauth = await replacePreparedEcdsaSigningOperationAfterReauth({
            authMethod: SIGNER_AUTH_METHODS.emailOtp,
            source: SIGNER_AUTH_METHODS.emailOtp,
            signingLane: refreshed.lane,
            record: refreshed.record,
            ...(refreshed.keyRef ? { keyRef: refreshed.keyRef } : {}),
            ...(trustedBudgetStatusAuthFromEcdsaKeyRef(refreshed.keyRef)
              ? { trustedStatusAuth: trustedBudgetStatusAuthFromEcdsaKeyRef(refreshed.keyRef) }
              : {}),
            diagnostics: {
              ...ecdsaAttemptDiagnostics,
              refreshedLane: summarizeEvmFamilyEcdsaLane(refreshed.lane),
              refreshedRecord: summarizeEvmFamilyEcdsaSessionRecord(refreshed.record),
              refreshedKeyRef: summarizeEvmFamilyEcdsaKeyRef(refreshed.keyRef),
            },
          });
          const admittedAfterReauth = await admitPreparedEcdsaTransactionBudget(
            preparedAfterReauth,
            trustedBudgetStatusAuthFromEcdsaKeyRef(refreshed.keyRef),
          );
          if (admittedAfterReauth.budget.kind !== 'admitted') {
            emitSigningSessionFlowFailure('evm-family', {
              stage: 'ecdsa_attempt.email_otp_reauth_not_admitted',
              accountId: args.nearAccountId,
              chain: args.request.chain,
              lane: summarizeEvmFamilyEcdsaLane(admittedAfterReauth.signingLane),
              budgetKind: admittedAfterReauth.budget.kind,
            });
            throw new Error(
              '[SigningEngine][ecdsa] Email OTP reauth did not produce budget-admitted operation',
            );
          }
          emitSigningSessionFlowTrace('evm-family', {
            stage: 'ecdsa_attempt.email_otp_reauth_admitted',
            accountId: args.nearAccountId,
            chain: args.request.chain,
            lane: summarizeEvmFamilyEcdsaLane(admittedAfterReauth.signingLane),
            budgetKind: admittedAfterReauth.budget.kind,
          });
          preparedEcdsaSigningSession = admittedAfterReauth;
          ecdsaSigningLane = admittedAfterReauth.signingLane;
          selectedEcdsaAuthMethod = admittedAfterReauth.authMethod;
          return {
            keyRef: refreshed.keyRef,
            operation: {
              ...admittedAfterReauth.budget.operation,
              authPlan: signingAuthPlan,
            },
          };
        },
      }
    : undefined;
  const { flowArgs, warmSessionServices } = await createEvmFamilySigningFlowRuntime({
    deps,
    nearAccountId: args.nearAccountId,
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
    getThresholdEcdsaKeyRef: () => thresholdEcdsaKeyRef,
    setThresholdEcdsaKeyRef: async ({ keyRef, signingSessionIdentity }) => {
      thresholdEcdsaKeyRef = keyRef;
      if (args.request.senderSignatureAlgorithm === 'secp256k1' && preparedEcdsaSigningSession) {
        const currentPrepared = preparedEcdsaSigningSession;
        const refreshedThresholdSessionId = String(signingSessionIdentity.thresholdSessionId || '').trim();
        const refreshedWalletSigningSessionId = String(
          signingSessionIdentity.walletSigningSessionId || '',
        ).trim();
        if (!refreshedThresholdSessionId || !refreshedWalletSigningSessionId) {
          throw new Error('[SigningEngine][ecdsa] keyRef update requires explicit session identity');
        }
        const replacedLaneIdentity =
          refreshedThresholdSessionId !== String(currentPrepared.signingLane.thresholdSessionId) ||
          refreshedWalletSigningSessionId !==
            String(currentPrepared.signingLane.walletSigningSessionId);
        const updatedPrepared = replacedLaneIdentity
          ? await replacePreparedEcdsaSigningOperationAfterReauth({
              authMethod: currentPrepared.authMethod,
              source: currentPrepared.source,
              signingLane: updateResolvedEvmFamilyEcdsaSigningLaneIdentity({
                lane: currentPrepared.signingLane,
                chain: requestChain,
                thresholdSessionId: refreshedThresholdSessionId,
                walletSigningSessionId: refreshedWalletSigningSessionId,
                context: 'EVM-family signing keyRef refresh',
                diagnostics: {
                  ...ecdsaAttemptDiagnostics,
                  updatedKeyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
                },
              }),
              keyRef,
              ...(trustedBudgetStatusAuthFromEcdsaKeyRef(keyRef)
                ? { trustedStatusAuth: trustedBudgetStatusAuthFromEcdsaKeyRef(keyRef) }
                : {}),
              diagnostics: {
                ...ecdsaAttemptDiagnostics,
                updatedKeyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
              },
            })
          : updatePreparedEcdsaSigningSessionForSameOperation({
              authMethod: currentPrepared.authMethod,
              source: currentPrepared.source,
              context: 'EVM-family signing keyRef update',
              diagnostics: {
                ...ecdsaAttemptDiagnostics,
                updatedKeyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
              },
              signingSessionIdentity: {
                thresholdSessionId: refreshedThresholdSessionId,
                walletSigningSessionId: refreshedWalletSigningSessionId,
              },
              forceRefreshBudgetIdentity: true,
            });
        const admittedPrepared = await admitPreparedEcdsaTransactionBudget(
          updatedPrepared,
          trustedBudgetStatusAuthFromEcdsaKeyRef(keyRef),
        );
        if (admittedPrepared.budget.kind !== 'admitted') {
          throw new Error(
            '[SigningEngine][ecdsa] keyRef refresh did not produce budget-admitted operation',
          );
        }
        preparedEcdsaSigningSession = admittedPrepared;
        ecdsaSigningLane = admittedPrepared.signingLane;
        selectedEcdsaAuthMethod = admittedPrepared.authMethod;
        return {
          ...admittedPrepared.budget.operation,
          authPlan: signingAuthPlan,
        };
      }
      throw new Error('[SigningEngine][ecdsa] keyRef refresh requires prepared ECDSA session');
    },
    getResolvedEcdsaSigningLane,
  });

  let freshAuthRetryHandledFinalization = false;
  const retryWithFreshEmailOtpAuth = async (
    error: unknown,
  ): Promise<TempoSignedResult | EvmSignedResult | null> => {
    return await retryEvmFamilyWithFreshEmailOtpAuthWhenRequired({
      error,
      nearAccountId: args.nearAccountId,
      chain: args.request.chain,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      accountAuth: resolvedAccountAuth,
      alreadyRetryingFreshEmailOtpAuth: attempt.retryingFreshAuth,
      hasEmailOtpSigningPlan: !!emailOtpSigning,
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
    if (
      attempt.retryingFreshAuth ||
      args.request.senderSignatureAlgorithm !== 'secp256k1' ||
      // If this attempt already performed passkey reauth, retrying would show a
      // second Touch ID prompt for the same user operation instead of surfacing
      // the budget-lane bug that made the fresh session unusable.
      isPasskeySigningAuthPlan(signingAuthPlan) ||
      !isSigningSessionBudgetExhaustedError(error)
    ) {
      return null;
    }
    emitEvmFamilyFreshAuthRetryEvent({
      nearAccountId: args.nearAccountId,
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
    await recordSuccessfulEvmFamilyWalletSigningSessionSpend({
      signingSessionCoordinator,
      nearAccountId: args.nearAccountId,
      operation: createTransactionSigningOperation(),
      admittedTransaction: prepared.budget.operation,
      finalizedSigningLane: prepared.signingLane,
      reserved: walletSigningSessionBudgetReserved,
      ...(prepared.budgetStatusAuth ? { trustedStatusAuth: prepared.budgetStatusAuth } : {}),
    });
  };
  let walletSigningSessionBudgetReserved = false;
  const reserveWalletSigningSessionBudget = async (
    operation: BudgetAdmittedOperation<SelectedEcdsaLane>,
  ): Promise<SigningSessionBudgetReservation | null> => {
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
      nearAccountId: args.nearAccountId,
      operation: createTransactionSigningOperation(),
      admittedTransaction: operation,
      finalizedSigningLane: prepared.signingLane,
      ...(prepared.budgetStatusAuth ? { trustedStatusAuth: prepared.budgetStatusAuth } : {}),
    });
    walletSigningSessionBudgetReserved = Boolean(reservation);
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
    if (prepared.budget.kind !== 'admitted') return;
    recordFailedEvmFamilyWalletSigningSessionSpend({
      signingSessionCoordinator,
      nearAccountId: args.nearAccountId,
      operation: createTransactionSigningOperation(),
      error,
      admittedTransaction: prepared.budget.operation,
      finalizedSigningLane: prepared.signingLane,
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
      nearAccountId: args.nearAccountId,
      chainTarget: prepared.transactionOperation.lane.chainTarget,
      ecdsaSigningLane: prepared.signingLane,
      selectedRecord,
    });
  };
  const preparedNonceSession = getPreparedEcdsaSigningSessionIfEcdsa();
  const nonceOperation: NonceOperationContext = {
    ...createTransactionSigningOperation(),
    accountId: args.nearAccountId,
    chainFamily: requestChain,
    ...(preparedNonceSession?.signingLane.walletSigningSessionId
      ? { walletSigningSessionId: String(preparedNonceSession.signingLane.walletSigningSessionId) }
      : {}),
  };
  const preparedExecutorSession = getPreparedEcdsaSigningSessionIfEcdsa();
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
    ? preparedExecutorSession.budget.kind === 'admitted'
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
  const thresholdEcdsaState: EvmFamilyExecutorThresholdEcdsaState = (() => {
    if (!preparedExecutorSession) {
      return {
        kind: 'not_required',
      };
    }
    if (!signingSessionPlan) {
      throw new Error('[SigningEngine][ecdsa] prepared executor requires a signing session plan');
    }
    const preparedEmailOtpReauthRecord = resolveEmailOtpReauthRecord();
    const signerAddress =
      toOptionalEvmAddress(resolvePreparedWarmKeyRef(preparedExecutorSession)?.ethereumAddress) ||
      toOptionalEvmAddress(resolvePreparedWarmRecord(preparedExecutorSession)?.ethereumAddress) ||
      toOptionalEvmAddress(preparedEmailOtpReauthRecord?.ethereumAddress) ||
      null;
    return {
      kind: 'prepared',
      lane: preparedExecutorSession.transactionOperation.lane,
      signingSessionPlan,
      signerAddress,
    };
  })();

  const executePayload = {
    deps,
    nearAccountId: args.nearAccountId,
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
      if (preparedExecutorSession.budget.kind === 'admitted') {
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
