import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { AccountAuthMetadata } from '@/core/signingEngine/auth';
import type { NonceCoordinator, NonceOperationContext } from '../nonce/NonceCoordinator';
import type { EvmSigningRequest } from '../chainAdaptors/evm/types';
import type { EvmSignedResult } from '../chainAdaptors/evm/evmAdapter';
import type { TempoSigningRequest } from '../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import type { SigningSessionSnapshot } from '../session/snapshotReader';
import type { RestorePersistedSessionForSigningInput } from '../session/restoreCoordinator';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from './thresholdLifecycle/thresholdSessionStore';
import type {
  TouchConfirmContextPort,
  TouchConfirmSigningPort,
  TouchConfirmSecureConfirmationPort,
  WarmSessionMaterialClearer,
  WarmSessionStatusResult,
  WarmSessionStatusReader,
} from '../touchConfirm';
import type { SignerWorkerManagerContext } from '../workerManager';
import {
  assertSameSigningLaneIdentity,
  SigningOperationIntent,
  type SigningLaneContext,
  type SigningOperationFingerprint,
  type SigningOperationId,
} from '../session/signingSession/types';
import { computeSigningOperationFingerprint } from '../session/signingSession/operationFingerprint';
import {
  isSigningSessionBudgetExhaustedError,
  type SigningSessionBudgetReservation,
} from '../session/signingSession/budget';
import type { SigningSessionCoordinator } from '../session/SigningSessionCoordinator';
import type { BootstrapEcdsaSessionArgs } from './thresholdLifecycle/thresholdSessionActivation';
import type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/thresholdActivation';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EmailOtpAuthLane } from '../emailOtp/authLane';
import type { EvmFamilyChain, EvmFamilyLifecycleEventCallback } from './evmFamily/types';
import { throwIfEvmFamilySigningCancelled } from './evmFamily/errors';
import {
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaKeyRef,
  summarizeEvmFamilyEcdsaLane,
  summarizeEvmFamilyEcdsaSessionRecord,
  updateResolvedEvmFamilyEcdsaSigningLaneIdentity,
  type EcdsaSigningLookupArgs,
  type EvmFamilyEcdsaAuthMethod,
  type PasskeyEcdsaSigningLookupArgs,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './evmFamily/ecdsaLanes';
import { resolveEvmFamilyTransactionAccountAuth } from './evmFamily/accountAuth';
import { resolveEvmFamilyTransactionWalletAuth } from './evmFamily/authPlanning';
import {
  prepareEvmFamilyEcdsaSigningSession,
  type PreparedEvmFamilyEcdsaSigningSession,
} from './evmFamily/preparedSigning';
import {
  recordFailedEvmFamilyWalletSigningSessionSpend,
  recordSuccessfulEvmFamilyWalletSigningSessionSpend,
  reserveEvmFamilyWalletSigningSessionBudget,
  type EvmFamilyTransactionSigningOperationContext,
} from './evmFamily/budgetSpending';
import { SigningAuthPlanKind } from '../touchConfirm/shared/confirmTypes';
import { applySuccessfulEvmFamilyEcdsaPostSignPolicy } from './evmFamily/postSignPolicy';
import { executeEvmFamilyTransactionSigning } from './evmFamily/transactionExecutor';
import {
  executePreparedThresholdSigning,
  finalizePreparedThresholdSigning,
} from '../session/signingSession/preparedOperation';
import {
  admitTransactionBudget,
  prepareTransactionSigningOperation,
  recordTransactionBudgetAdmission,
  replacePreparedTransactionLane,
  type BudgetAdmittedOperation,
  type EvmFamilyEcdsaTransactionLane,
} from '../session/signingSession/transactionState';
import { completeEvmFamilyEmailOtpSigningRefresh } from './evmFamily/emailOtpRefresh';
import { createEvmFamilySigningFlowRuntime } from './evmFamily/signingFlowRuntime';
import { maybeRetryEvmFamilyWithFreshEmailOtpAuth } from './evmFamily/freshEmailOtpRetry';
import { emitEvmFamilySigningEvent } from './evmFamily/events';
import {
  bindEvmFamilyCallerProvidedOperationIdToFingerprint,
  createEvmFamilySigningOperationIds,
  ensureEvmFamilyConfirmationOperationId,
  type EvmFamilySigningOperationIds,
} from './evmFamily/operationIds';

export type {
  EvmFamilyBroadcastAcceptedArgs,
  EvmFamilyBroadcastRejectedArgs,
  EvmFamilyDroppedOrReplacedArgs,
  EvmFamilyFinalizedArgs,
  EvmFamilyNonceLaneStatus,
  EvmFamilyReconcileLaneArgs,
} from './evmFamily/types';

function ecdsaTransactionReadinessFromBudgetIdentity(
  budgetIdentity: NonNullable<PreparedEvmFamilyEcdsaSigningSession['budgetIdentity']>,
) {
  return {
    status: 'ready' as const,
    remainingUses: Math.max(0, Math.floor(Number(budgetIdentity.status.remainingUses) || 0)),
    expiresAtMs: Math.max(0, Math.floor(Number(budgetIdentity.status.expiresAtMs) || 0)),
  };
}

export {
  reconcileEvmFamilyNonceLane,
  reportEvmFamilyBroadcastAccepted,
  reportEvmFamilyBroadcastRejected,
  reportEvmFamilyDroppedOrReplaced,
  reportEvmFamilyFinalized,
} from './evmFamily/nonceLifecycleAdapter';

export type EvmFamilySigningDeps = {
  indexedDB: UnifiedIndexedDBManager;
  seamsPasskeyConfigs: SeamsConfigsReadonly;
  nonceCoordinator: NonceCoordinator;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  withThresholdEcdsaCommitQueue: <T>(args: {
    queueKey: string;
    nearAccountId: string;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }) => Promise<T>;
  getEmailOtpThresholdEcdsaKeyRefForSigning: (
    args: EcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSecp256k1KeyRef;
  getEmailOtpThresholdEcdsaSessionRecordForSigning: (
    args: EcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSessionRecord;
  getPasskeyThresholdEcdsaKeyRefForSigning: (
    args: PasskeyEcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSecp256k1KeyRef;
  getPasskeyThresholdEcdsaSessionRecordForSigning: (
    args: PasskeyEcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSessionRecord;
  requestEmailOtpTransactionSigningChallenge?: (args: {
    nearAccountId: string;
    chain: EvmFamilyChain;
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ challengeId: string; emailHint?: string }>;
  resolveEmailOtpSigningSessionAuthLane?: (args: {
    thresholdSessionId: string;
    curve: 'ecdsa';
    chain: EvmFamilyChain;
  }) => EmailOtpAuthLane | null;
  loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
    nearAccountId: string;
    chain: EvmFamilyChain;
    challengeId: string;
    otpCode: string;
    record?: ThresholdEcdsaSessionRecord;
    authLane?: EmailOtpAuthLane;
  }) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  restorePersistedSessionForSigning: (
    args: Extract<RestorePersistedSessionForSigningInput, { curve: 'ecdsa' }>,
  ) => Promise<unknown>;
  readSigningSessionSnapshotForSigning: (args: {
    walletId: string;
    authMethod?: 'email_otp' | 'passkey';
  }) => Promise<SigningSessionSnapshot>;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  markThresholdEcdsaEmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: string;
    chain: EvmFamilyChain;
    uses?: number;
  }) => void;
  signingSessionCoordinator: SigningSessionCoordinator;
  provisionThresholdEcdsaSession: (
    args: BootstrapEcdsaSessionArgs,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  touchConfirm: TouchConfirmContextPort &
    TouchConfirmSigningPort &
    TouchConfirmSecureConfirmationPort &
    WarmSessionStatusReader &
    Partial<WarmSessionMaterialClearer>;
};

type SignEvmFamilyArgs = {
  nearAccountId: string;
  request: TempoSigningRequest | EvmSigningRequest;
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

  if (args.request.chain !== 'tempo' && args.request.chain !== 'evm') {
    throw new Error('[SigningEngine] invalid request: chain must be tempo or evm');
  }

  let thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  let thresholdEcdsaRecord: ThresholdEcdsaSessionRecord | undefined;
  let accountAuth: AccountAuthMetadata | undefined;
  let ecdsaSigningLane: SigningLaneContext | undefined;
  let selectedEcdsaAuthMethod: EvmFamilyEcdsaAuthMethod | undefined;
  let emailOtpReauthRecord: ThresholdEcdsaSessionRecord | undefined;
  let preparedEcdsaSigningSession: PreparedEvmFamilyEcdsaSigningSession | undefined;
  const ecdsaAttemptDiagnostics: Record<string, unknown> = {
    nearAccountId: args.nearAccountId,
    chain: args.request.chain,
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
      kind: `evm-family:${args.request.chain}`,
      payload: {
        nearAccountId: args.nearAccountId,
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
      chain: args.request.chain,
      diagnostics: ecdsaAttemptDiagnostics,
      signingSessionCoordinator,
      forceFreshAuth: attempt.forceFreshAuth === true,
    });
    ecdsaSigningLane = preparedEcdsaSigningSession.signingLane;
    selectedEcdsaAuthMethod = preparedEcdsaSigningSession.authMethod;
    emailOtpReauthRecord = preparedEcdsaSigningSession.emailOtpReauthRecord;
    accountAuth = preparedEcdsaSigningSession.accountAuth;
    thresholdEcdsaRecord = preparedEcdsaSigningSession.warmRecord;
    thresholdEcdsaKeyRef = preparedEcdsaSigningSession.warmKeyRef;
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
      ...(thresholdEcdsaRecord ? { record: thresholdEcdsaRecord } : {}),
      ...(thresholdEcdsaKeyRef ? { keyRef: thresholdEcdsaKeyRef } : {}),
    }));
  const resolvedAccountAuth = accountAuth;

  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  const resolveEmailOtpReauthRecord = (): ThresholdEcdsaSessionRecord | undefined =>
    preparedEcdsaSigningSession?.emailOtpReauthRecord ||
    (selectedEcdsaAuthMethod === SIGNER_AUTH_METHODS.emailOtp ? emailOtpReauthRecord : undefined);
  const walletAuthArgsBase = {
    deps: {
      ...deps,
      signingSessionCoordinator,
    },
    confirmedDeps: deps,
    nearAccountId: args.nearAccountId,
    chain: args.request.chain,
    accountAuth: resolvedAccountAuth,
    forceFreshAuth: attempt.forceFreshAuth === true,
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
  const updatePreparedEcdsaSigningSessionForSameOperation = (argsForRefresh: {
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
    context: string;
    diagnostics: Record<string, unknown>;
    forceRefreshBudgetIdentity?: boolean;
  }): PreparedEvmFamilyEcdsaSigningSession => {
    const prepared = getPreparedEcdsaSigningSession();
    const currentLane = requireResolvedEvmFamilyEcdsaSigningLane({
      lane: prepared.signingLane || ecdsaSigningLane,
      chain: args.request.chain,
      context: argsForRefresh.context,
      diagnostics: argsForRefresh.diagnostics,
    });
    const signingLane = updateResolvedEvmFamilyEcdsaSigningLaneIdentity({
      lane: currentLane,
      chain: args.request.chain,
      thresholdSessionId:
        thresholdEcdsaKeyRef?.thresholdSessionId ||
        thresholdEcdsaRecord?.thresholdSessionId ||
        String(currentLane.thresholdSessionId),
      walletSigningSessionId:
        thresholdEcdsaKeyRef?.walletSigningSessionId ||
        thresholdEcdsaRecord?.walletSigningSessionId ||
        String(currentLane.walletSigningSessionId),
      context: argsForRefresh.context,
      diagnostics: argsForRefresh.diagnostics,
    });
    const updatedPrepared = {
      ...prepared,
      accountAuth: resolvedAccountAuth,
      authMethod: argsForRefresh.authMethod,
      source: argsForRefresh.source,
      signingLane,
      ...(thresholdEcdsaRecord ? { warmRecord: thresholdEcdsaRecord } : {}),
      ...(thresholdEcdsaKeyRef ? { warmKeyRef: thresholdEcdsaKeyRef } : {}),
      ...(thresholdEcdsaRecord && argsForRefresh.authMethod === SIGNER_AUTH_METHODS.emailOtp
        ? { emailOtpReauthRecord: thresholdEcdsaRecord }
        : {}),
    };
    assertPreparedEcdsaOperationLane(updatedPrepared, argsForRefresh.context);
    const preservedBudgetIdentity =
      !argsForRefresh.forceRefreshBudgetIdentity &&
      prepared.budgetIdentity &&
      prepared.budgetIdentity.walletSigningSessionId ===
        String(signingLane.walletSigningSessionId) &&
      prepared.budgetIdentityThresholdSessionId ===
        String(signingLane.thresholdSessionId)
        ? prepared.budgetIdentity
        : undefined;
    preparedEcdsaSigningSession = {
      ...updatedPrepared,
      ...(preservedBudgetIdentity
        ? {
            budgetIdentity: preservedBudgetIdentity,
            budgetProjectionVersion: preservedBudgetIdentity.projectionVersion,
            budgetIdentityThresholdSessionId: String(signingLane.thresholdSessionId),
          }
        : {}),
    };
    ecdsaSigningLane = signingLane;
    selectedEcdsaAuthMethod = argsForRefresh.authMethod;
    return preparedEcdsaSigningSession!;
  };
  const replacePreparedEcdsaSigningOperationAfterReauth = async (argsForRefresh: {
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
    signingLane?: SigningLaneContext;
    record?: ThresholdEcdsaSessionRecord;
    keyRef?: ThresholdEcdsaSecp256k1KeyRef;
    diagnostics: Record<string, unknown>;
  }): Promise<PreparedEvmFamilyEcdsaSigningSession> => {
    if (argsForRefresh.signingLane) {
      const resolvedLane = requireResolvedEvmFamilyEcdsaSigningLane({
        lane: argsForRefresh.signingLane,
        chain: args.request.chain,
        context: 'EVM-family signing reauth refresh',
        diagnostics: argsForRefresh.diagnostics,
      });
      if (resolvedLane.authMethod !== argsForRefresh.authMethod) {
        throw new Error(
          `[SigningEngine][ecdsa] reauth lane auth method ${resolvedLane.authMethod} did not match ${argsForRefresh.authMethod}`,
        );
      }
      const transactionLane: EvmFamilyEcdsaTransactionLane = {
        accountId: resolvedLane.accountId,
        authMethod: resolvedLane.authMethod,
        curve: 'ecdsa',
        chain: args.request.chain,
        walletSigningSessionId: resolvedLane.walletSigningSessionId,
        thresholdSessionId: resolvedLane.thresholdSessionId,
      };
      const preparedTransaction = await prepareTransactionSigningOperation({
        intent: {
          walletId: args.nearAccountId,
          curve: 'ecdsa',
          chain: args.request.chain,
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
                ...(resolvedLane.backingMaterialSessionId
                  ? { backingMaterialSessionId: resolvedLane.backingMaterialSessionId }
                  : {}),
              },
              expiresAtMs: Math.floor(
                Number(argsForRefresh.record?.expiresAtMs) || Date.now() + 120_000,
              ),
              remainingUses: Math.max(
                1,
                Math.floor(Number(argsForRefresh.record?.remainingUses) || 1),
              ),
            },
            snapshotGeneration: Date.now(),
            metadata: {},
          }),
        },
      });
      const preparedOperation = preparedTransaction.thresholdOperation;
      const prepared: PreparedEvmFamilyEcdsaSigningSession = {
        accountAuth: resolvedAccountAuth,
        authMethod: argsForRefresh.authMethod,
        source: argsForRefresh.source,
        snapshotGeneration: preparedOperation.snapshotGeneration,
        signingLane: preparedOperation.lane,
        preparedOperation,
        transactionOperation: preparedTransaction.transactionOperation,
        ...(preparedTransaction.budgetAdmittedOperation
          ? { budgetAdmittedOperation: preparedTransaction.budgetAdmittedOperation }
          : {}),
        ...(preparedTransaction.budgetAdmittedState
          ? { budgetAdmittedState: preparedTransaction.budgetAdmittedState }
          : {}),
        ...(preparedOperation.budgetIdentity
          ? {
              budgetIdentity: preparedOperation.budgetIdentity,
              budgetProjectionVersion: preparedOperation.budgetIdentity.projectionVersion,
              budgetIdentityThresholdSessionId: String(preparedOperation.lane.thresholdSessionId),
            }
          : {}),
        ...(argsForRefresh.record ? { warmRecord: argsForRefresh.record } : {}),
        ...(argsForRefresh.keyRef ? { warmKeyRef: argsForRefresh.keyRef } : {}),
        ...(argsForRefresh.record && argsForRefresh.authMethod === SIGNER_AUTH_METHODS.emailOtp
          ? { emailOtpReauthRecord: argsForRefresh.record }
          : {}),
      };
      assertPreparedEcdsaOperationLane(prepared, 'EVM-family signing reauth refresh');
      preparedEcdsaSigningSession = prepared;
      ecdsaSigningLane = prepared.signingLane;
      selectedEcdsaAuthMethod = prepared.authMethod;
      return prepared;
    }
    const prepared = await prepareEvmFamilyEcdsaSigningSession({
      deps,
      nearAccountId: args.nearAccountId,
      chain: args.request.chain,
      diagnostics: argsForRefresh.diagnostics,
      signingSessionCoordinator,
      forceFreshAuth: attempt.forceFreshAuth === true,
    });
    if (prepared.authMethod !== argsForRefresh.authMethod) {
      throw new Error(
        `[SigningEngine][ecdsa] reauth prepared ${prepared.authMethod} but expected ${argsForRefresh.authMethod}`,
      );
    }
    assertPreparedEcdsaOperationLane(prepared, 'EVM-family signing reauth refresh');
    preparedEcdsaSigningSession = prepared;
    ecdsaSigningLane = prepared.signingLane;
    selectedEcdsaAuthMethod = prepared.authMethod;
    thresholdEcdsaRecord = prepared.warmRecord || thresholdEcdsaRecord;
    thresholdEcdsaKeyRef = prepared.warmKeyRef || thresholdEcdsaKeyRef;
    if (prepared.emailOtpReauthRecord) {
      emailOtpReauthRecord = prepared.emailOtpReauthRecord;
    }
    return prepared;
  };
  const ensurePreparedEcdsaBudgetIdentity =
    async (
      expectedPrepared?: PreparedEvmFamilyEcdsaSigningSession,
    ): Promise<PreparedEvmFamilyEcdsaSigningSession> => {
      const prepared = expectedPrepared || getPreparedEcdsaSigningSession();
      assertPreparedEcdsaOperationLane(prepared, 'budget identity preparation');
      if (
        prepared.budgetIdentity &&
        prepared.budgetIdentity.walletSigningSessionId ===
          String(prepared.signingLane.walletSigningSessionId) &&
        prepared.budgetIdentityThresholdSessionId === String(prepared.signingLane.thresholdSessionId)
      ) {
        return prepared;
      }
      const budgetIdentity = await signingSessionCoordinator.prepareBudgetIdentity({
        nearAccountId: args.nearAccountId,
        lane: prepared.transactionOperation.lane,
        operationUsesNeeded: 1,
      });
      const transactionOperation = replacePreparedTransactionLane(prepared.transactionOperation, {
        lane: prepared.transactionOperation.lane,
        readiness: ecdsaTransactionReadinessFromBudgetIdentity(budgetIdentity),
      });
      const budgetAdmittedOperation = admitTransactionBudget(transactionOperation, {
        budgetIdentity,
      });
      const updatedPrepared = {
        ...prepared,
        budgetIdentity,
        budgetProjectionVersion: budgetIdentity.projectionVersion,
        budgetIdentityThresholdSessionId: String(prepared.signingLane.thresholdSessionId),
        transactionOperation,
        budgetAdmittedOperation,
        budgetAdmittedState: recordTransactionBudgetAdmission(budgetAdmittedOperation),
      };
      assertPreparedEcdsaOperationLane(updatedPrepared, 'budget identity preparation');
      if (preparedEcdsaSigningSession?.preparedOperation === prepared.preparedOperation) {
        preparedEcdsaSigningSession = updatedPrepared;
      }
      return updatedPrepared;
    };
  const getResolvedEcdsaSigningLane = (): ResolvedEvmFamilyEcdsaSigningLane =>
    getPreparedEcdsaSigningSession().signingLane;
  const getPreparedEcdsaSigningSessionIfEcdsa = ():
    | PreparedEvmFamilyEcdsaSigningSession
    | undefined =>
    args.request.senderSignatureAlgorithm === 'secp256k1'
      ? getPreparedEcdsaSigningSession()
      : undefined;
  const walletAuthResult =
    args.request.senderSignatureAlgorithm === 'secp256k1'
      ? await (async () => {
          const prepared = getPreparedEcdsaSigningSession();
          return await resolveEvmFamilyTransactionWalletAuth({
            ...walletAuthArgsBase,
            senderSignatureAlgorithm: 'secp256k1',
            preparedOperation: prepared.preparedOperation,
          });
        })()
      : await resolveEvmFamilyTransactionWalletAuth({
          ...walletAuthArgsBase,
          senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
        });
  const { signingAuthPlan, signingSessionPlan, emailOtpSigning, budgetIdentity } = walletAuthResult;
  if (
    budgetIdentity &&
    preparedEcdsaSigningSession &&
    budgetIdentity.walletSigningSessionId ===
      String(preparedEcdsaSigningSession.signingLane.walletSigningSessionId)
  ) {
    preparedEcdsaSigningSession = {
      ...preparedEcdsaSigningSession,
      budgetIdentity,
      budgetProjectionVersion: budgetIdentity.projectionVersion,
      budgetIdentityThresholdSessionId: String(
        preparedEcdsaSigningSession.signingLane.thresholdSessionId,
      ),
    };
  }
  const emailOtpSigningForFlow = emailOtpSigning
    ? {
        ...emailOtpSigning,
        complete: async (otpCode: string, challengeId?: string) => {
          const refreshed = await completeEvmFamilyEmailOtpSigningRefresh({
            deps,
            nearAccountId: args.nearAccountId,
            chain: args.request.chain,
            emailOtpSigning,
            otpCode,
            ...(challengeId ? { challengeId } : {}),
          });
          thresholdEcdsaKeyRef = refreshed.keyRef;
          if (refreshed.lane) {
            ecdsaSigningLane = refreshed.lane;
          }
          if (refreshed.record) {
            thresholdEcdsaRecord = refreshed.record;
            selectedEcdsaAuthMethod = SIGNER_AUTH_METHODS.emailOtp;
            emailOtpReauthRecord = thresholdEcdsaRecord;
          } else {
            thresholdEcdsaRecord = undefined;
          }
          if (refreshed.lane || refreshed.record) {
            selectedEcdsaAuthMethod = SIGNER_AUTH_METHODS.emailOtp;
          }
          await replacePreparedEcdsaSigningOperationAfterReauth({
            authMethod: SIGNER_AUTH_METHODS.emailOtp,
            source: SIGNER_AUTH_METHODS.emailOtp,
            ...(refreshed.lane ? { signingLane: refreshed.lane } : {}),
            ...(refreshed.record ? { record: refreshed.record } : {}),
            ...(refreshed.keyRef ? { keyRef: refreshed.keyRef } : {}),
            diagnostics: {
              ...ecdsaAttemptDiagnostics,
              refreshedLane: summarizeEvmFamilyEcdsaLane(refreshed.lane),
              refreshedRecord: summarizeEvmFamilyEcdsaSessionRecord(refreshed.record),
              refreshedKeyRef: summarizeEvmFamilyEcdsaKeyRef(refreshed.keyRef),
            },
          });
          return refreshed.keyRef;
        },
      }
    : undefined;
  const { flowArgs, warmSessionServices } = await createEvmFamilySigningFlowRuntime({
    deps,
    nearAccountId: args.nearAccountId,
    request: args.request,
    senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
    ...(signingSessionPlan ? { signingSessionPlan } : {}),
    ...(emailOtpSigningForFlow ? { emailOtpSigningForFlow } : {}),
    confirmationConfigOverride: args.confirmationConfigOverride,
    shouldAbort: args.shouldAbort,
    onEvent: args.onEvent,
    getThresholdEcdsaKeyRef: () => thresholdEcdsaKeyRef,
    setThresholdEcdsaKeyRef: (keyRef) => {
      thresholdEcdsaKeyRef = keyRef;
      if (args.request.senderSignatureAlgorithm === 'secp256k1' && preparedEcdsaSigningSession) {
        updatePreparedEcdsaSigningSessionForSameOperation({
          authMethod: preparedEcdsaSigningSession.authMethod,
          source: preparedEcdsaSigningSession.source,
          context: 'EVM-family signing keyRef update',
          diagnostics: {
            ...ecdsaAttemptDiagnostics,
            updatedKeyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
          },
          forceRefreshBudgetIdentity: true,
        });
      }
    },
    getResolvedEcdsaSigningLane,
  });

  let freshAuthRetryHandledFinalization = false;
  const retryWithFreshEmailOtpAuth = async (
    error: unknown,
  ): Promise<TempoSignedResult | EvmSignedResult | null> => {
    return await maybeRetryEvmFamilyWithFreshEmailOtpAuth({
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
      signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth ||
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
    const prepared = await ensurePreparedEcdsaBudgetIdentity(expectedPrepared);
    await recordSuccessfulEvmFamilyWalletSigningSessionSpend({
      signingSessionCoordinator,
      nearAccountId: args.nearAccountId,
      chain: args.request.chain,
      operation: createTransactionSigningOperation(),
      ecdsaSigningLane: prepared.signingLane,
      budgetIdentity: prepared.budgetIdentity!,
    });
  };
  const reserveWalletSigningSessionBudget =
    async (
      operation: BudgetAdmittedOperation<EvmFamilyEcdsaTransactionLane>,
    ): Promise<SigningSessionBudgetReservation | null> => {
      if (args.request.senderSignatureAlgorithm !== 'secp256k1') return null;
      const prepared = await ensurePreparedEcdsaBudgetIdentity();
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
      return await reserveEvmFamilyWalletSigningSessionBudget({
        signingSessionCoordinator,
        nearAccountId: args.nearAccountId,
        chain: args.request.chain,
        operation: createTransactionSigningOperation(),
        ecdsaSigningLane: prepared.signingLane,
        budgetIdentity: prepared.budgetIdentity!,
      });
    };
  const recordFailedWalletSigningSessionSpend = (
    error: unknown,
    expectedPrepared?: PreparedEvmFamilyEcdsaSigningSession,
  ): void => {
    if (!confirmationDisplayed) return;
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return;
    const prepared = expectedPrepared || getPreparedEcdsaSigningSession();
    assertPreparedEcdsaOperationLane(prepared, 'failed spend finalization');
    if (!prepared.budgetIdentity) return;
    recordFailedEvmFamilyWalletSigningSessionSpend({
      signingSessionCoordinator,
      nearAccountId: args.nearAccountId,
      chain: args.request.chain,
      operation: createTransactionSigningOperation(),
      error,
      ecdsaSigningLane: prepared.signingLane,
      budgetIdentity: prepared.budgetIdentity,
    });
  };
  const applySuccessfulEcdsaPostSignPolicy = async (
    chain: EvmFamilyChain,
    expectedPrepared?: PreparedEvmFamilyEcdsaSigningSession,
  ): Promise<void> => {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return;
    const prepared = expectedPrepared || getPreparedEcdsaSigningSession();
    assertPreparedEcdsaOperationLane(prepared, 'post-sign policy');
    await applySuccessfulEvmFamilyEcdsaPostSignPolicy({
      postSignPolicy: warmSessionServices,
      nearAccountId: args.nearAccountId,
      chain,
      ecdsaSigningLane: prepared.signingLane,
      selectedEcdsaSource: prepared.source,
      ...(prepared.emailOtpReauthRecord || prepared.warmRecord
        ? { selectedRecord: prepared.emailOtpReauthRecord || prepared.warmRecord }
        : {}),
    });
  };
  const preparedNonceSession = getPreparedEcdsaSigningSessionIfEcdsa();
  const nonceOperation: NonceOperationContext = {
    ...createTransactionSigningOperation(),
    accountId: args.nearAccountId,
    chainFamily: args.request.chain,
    ...(preparedNonceSession?.signingLane.walletSigningSessionId
      ? { walletSigningSessionId: String(preparedNonceSession.signingLane.walletSigningSessionId) }
      : {}),
  };
  const preparedExecutorSession = getPreparedEcdsaSigningSessionIfEcdsa();
  const thresholdEcdsaOperation = preparedExecutorSession?.budgetAdmittedOperation
    ? {
        ...preparedExecutorSession.budgetAdmittedOperation,
        authPlan: signingAuthPlan,
      }
    : undefined;

  const executePayload = {
    deps,
    nearAccountId: args.nearAccountId,
    request: args.request,
    flowArgs,
    nonceOperation,
    onConfirmationDisplayed: markConfirmationDisplayed,
    ...(thresholdEcdsaOperation ? { thresholdEcdsaOperation } : {}),
    reserveWalletSigningSessionBudget,
    recordSuccessfulWalletSigningSessionSpend,
    recordFailedWalletSigningSessionSpend,
    applySuccessfulEcdsaPostSignPolicy,
    deferSuccessfulSigningSessionFinalization: Boolean(preparedExecutorSession),
    deferFailedSigningSessionFinalization: Boolean(preparedExecutorSession),
    retryWithFreshEmailOtpAuth: retryWithFreshAuth,
    ...(signingSessionPlan ? { signingSessionPlan } : {}),
    ...(preparedExecutorSession?.warmRecord
      ? { thresholdEcdsaRecord: preparedExecutorSession.warmRecord }
      : {}),
    ...(resolveEmailOtpReauthRecord()
      ? { emailOtpReauthRecord: resolveEmailOtpReauthRecord() }
      : {}),
    ...(preparedExecutorSession?.warmKeyRef
      ? { thresholdEcdsaKeyRef: preparedExecutorSession.warmKeyRef }
      : {}),
  };
  if (preparedExecutorSession) {
    let result: EvmSignedResult | TempoSignedResult;
    try {
      result = await executePreparedThresholdSigning(
        preparedExecutorSession.preparedOperation,
        executePayload,
        { execute: async (_prepared, payload) => await executeEvmFamilyTransactionSigning(payload) },
      );
    } catch (error: unknown) {
      const failedPreparedSession = preparedEcdsaSigningSession || preparedExecutorSession;
      assertPreparedEcdsaOperationLane(failedPreparedSession, 'failed prepared finalization');
      await finalizePreparedThresholdSigning(failedPreparedSession.preparedOperation, null, {
        recordZeroSpend: async () => {
          recordFailedWalletSigningSessionSpend(error, failedPreparedSession);
        },
      });
      throw error;
    }
    if (freshAuthRetryHandledFinalization) {
      return result;
    }
    const finalPreparedSession = preparedEcdsaSigningSession || preparedExecutorSession;
    assertPreparedEcdsaOperationLane(finalPreparedSession, 'successful prepared finalization');
    await finalizePreparedThresholdSigning(
      finalPreparedSession.preparedOperation,
      result,
      {
        recordSuccess: async () => {
          await recordSuccessfulWalletSigningSessionSpend(finalPreparedSession);
        },
        cleanup: async () => {
          await applySuccessfulEcdsaPostSignPolicy(args.request.chain, finalPreparedSession);
        },
      },
    );
    return result;
  }
  return await executeEvmFamilyTransactionSigning(executePayload);
}
