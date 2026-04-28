import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { TatchiConfigsReadonly } from '@/core/types/tatchi';
import type { AccountAuthMetadata } from '@/core/signingEngine/auth';
import type { NonceCoordinator, NonceOperationContext } from '../nonce/NonceCoordinator';
import type { EvmSigningRequest } from '../chainAdaptors/evm/types';
import type { EvmSignedResult } from '../chainAdaptors/evm/evmAdapter';
import type { TempoSigningRequest } from '../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import type { SigningSessionSnapshot } from '../session/snapshotReader';
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
import { SigningSessionCoordinator } from '../session/SigningSessionCoordinator';
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

export {
  reconcileEvmFamilyNonceLane,
  reportEvmFamilyBroadcastAccepted,
  reportEvmFamilyBroadcastRejected,
  reportEvmFamilyDroppedOrReplaced,
  reportEvmFamilyFinalized,
} from './evmFamily/nonceLifecycleAdapter';

export type EvmFamilySigningDeps = {
  indexedDB: UnifiedIndexedDBManager;
  tatchiPasskeyConfigs: TatchiConfigsReadonly;
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
  restorePersistedSessionForSigning: (args: {
    walletId: string;
    authMethod: 'email_otp';
    curve: 'ecdsa';
    chain: EvmFamilyChain;
    reason: 'transaction' | 'export' | 'session_status';
  }) => Promise<unknown>;
  readSigningSessionSnapshotForSigning: (args: {
    walletId: string;
    authMethod?: 'email_otp' | 'passkey';
  }) => Promise<SigningSessionSnapshot>;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  markThresholdEcdsaEmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: string;
    chain: EvmFamilyChain;
  }) => void;
  signingSessionCoordinator?: SigningSessionCoordinator;
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
    attempt.signingSessionCoordinator ||
    deps.signingSessionCoordinator ||
    new SigningSessionCoordinator();
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
  const refreshPreparedEcdsaSigningSession = (argsForRefresh: {
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
    context: string;
    diagnostics: Record<string, unknown>;
  }): PreparedEvmFamilyEcdsaSigningSession => {
    if (!preparedEcdsaSigningSession) {
      throw new Error('[SigningEngine][ecdsa] prepared signing session is required before refresh');
    }
    const currentLane = requireResolvedEvmFamilyEcdsaSigningLane({
      lane: preparedEcdsaSigningSession.signingLane || ecdsaSigningLane,
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
    preparedEcdsaSigningSession = {
      accountAuth: resolvedAccountAuth,
      authMethod: argsForRefresh.authMethod,
      source: argsForRefresh.source,
      snapshotGeneration: preparedEcdsaSigningSession.snapshotGeneration,
      signingLane,
      ...(thresholdEcdsaRecord ? { warmRecord: thresholdEcdsaRecord } : {}),
      ...(thresholdEcdsaKeyRef ? { warmKeyRef: thresholdEcdsaKeyRef } : {}),
      ...(thresholdEcdsaRecord && argsForRefresh.authMethod === SIGNER_AUTH_METHODS.emailOtp
        ? { emailOtpReauthRecord: thresholdEcdsaRecord }
        : {}),
    };
    ecdsaSigningLane = signingLane;
    selectedEcdsaAuthMethod = argsForRefresh.authMethod;
    return preparedEcdsaSigningSession;
  };
  const getPreparedEcdsaSigningSession = (): PreparedEvmFamilyEcdsaSigningSession => {
    if (preparedEcdsaSigningSession) return preparedEcdsaSigningSession;
    throw new Error('[SigningEngine][ecdsa] prepared signing session is required');
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
            ecdsaSigningLane: prepared.signingLane,
            ecdsaAuthMethod: prepared.authMethod,
            ...(prepared.warmRecord ? { ecdsaWarmRecord: prepared.warmRecord } : {}),
            ...(prepared.warmKeyRef ? { ecdsaWarmKeyRef: prepared.warmKeyRef } : {}),
            ...(prepared.emailOtpReauthRecord
              ? { emailOtpReauthRecord: prepared.emailOtpReauthRecord }
              : {}),
          });
        })()
      : await resolveEvmFamilyTransactionWalletAuth({
          ...walletAuthArgsBase,
          senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
        });
  const { signingAuthPlan, signingSessionPlan, emailOtpSigning } = walletAuthResult;
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
          refreshPreparedEcdsaSigningSession({
            authMethod: SIGNER_AUTH_METHODS.emailOtp,
            source: SIGNER_AUTH_METHODS.emailOtp,
            context: 'EVM-family signing refresh',
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
    signingAuthPlan,
    ...(signingSessionPlan ? { signingSessionPlan } : {}),
    ...(emailOtpSigningForFlow ? { emailOtpSigningForFlow } : {}),
    confirmationConfigOverride: args.confirmationConfigOverride,
    shouldAbort: args.shouldAbort,
    onEvent: args.onEvent,
    getThresholdEcdsaKeyRef: () => thresholdEcdsaKeyRef,
    setThresholdEcdsaKeyRef: (keyRef) => {
      thresholdEcdsaKeyRef = keyRef;
      if (args.request.senderSignatureAlgorithm === 'secp256k1' && preparedEcdsaSigningSession) {
        refreshPreparedEcdsaSigningSession({
          authMethod: preparedEcdsaSigningSession.authMethod,
          source: preparedEcdsaSigningSession.source,
          context: 'EVM-family signing keyRef update',
          diagnostics: {
            ...ecdsaAttemptDiagnostics,
            updatedKeyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
          },
        });
      }
    },
    getResolvedEcdsaSigningLane,
  });

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
      retry: async () =>
        await signEvmFamilyAttempt(deps, args, {
          forceFreshAuth: true,
          operationIds,
          retryingFreshAuth: true,
          signingSessionCoordinator,
        }),
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
    return await signEvmFamilyAttempt(deps, args, {
      forceFreshAuth: true,
      operationIds,
      retryingFreshAuth: true,
      signingSessionCoordinator,
    });
  };
  const recordSuccessfulWalletSigningSessionSpend = async (): Promise<void> => {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return;
    const prepared = getPreparedEcdsaSigningSession();
    await recordSuccessfulEvmFamilyWalletSigningSessionSpend({
      signingSessionCoordinator,
      nearAccountId: args.nearAccountId,
      chain: args.request.chain,
      operation: createTransactionSigningOperation(),
      ecdsaSigningLane: prepared.signingLane,
    });
  };
  const reserveWalletSigningSessionBudget =
    async (): Promise<SigningSessionBudgetReservation | null> => {
      if (args.request.senderSignatureAlgorithm !== 'secp256k1') return null;
      const prepared = getPreparedEcdsaSigningSession();
      return await reserveEvmFamilyWalletSigningSessionBudget({
        signingSessionCoordinator,
        nearAccountId: args.nearAccountId,
        chain: args.request.chain,
        operation: createTransactionSigningOperation(),
        ecdsaSigningLane: prepared.signingLane,
      });
    };
  const recordFailedWalletSigningSessionSpend = (error: unknown): void => {
    if (!confirmationDisplayed) return;
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return;
    const prepared = getPreparedEcdsaSigningSession();
    recordFailedEvmFamilyWalletSigningSessionSpend({
      signingSessionCoordinator,
      nearAccountId: args.nearAccountId,
      chain: args.request.chain,
      operation: createTransactionSigningOperation(),
      error,
      ecdsaSigningLane: prepared.signingLane,
    });
  };
  const applySuccessfulEcdsaPostSignPolicy = async (chain: EvmFamilyChain): Promise<void> => {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return;
    const prepared = getPreparedEcdsaSigningSession();
    await applySuccessfulEvmFamilyEcdsaPostSignPolicy({
      postSignPolicy: warmSessionServices,
      nearAccountId: args.nearAccountId,
      chain,
      ecdsaSigningLane: prepared.signingLane,
      selectedEcdsaSource: prepared.source,
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

  return await executeEvmFamilyTransactionSigning({
    deps,
    nearAccountId: args.nearAccountId,
    request: args.request,
    flowArgs,
    nonceOperation,
    onConfirmationDisplayed: markConfirmationDisplayed,
    reserveWalletSigningSessionBudget,
    recordSuccessfulWalletSigningSessionSpend,
    recordFailedWalletSigningSessionSpend,
    applySuccessfulEcdsaPostSignPolicy,
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
  });
}
