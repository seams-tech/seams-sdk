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
import type {
  ReadSigningSessionSnapshotForSigningInput,
  SigningSessionSnapshot,
} from '../session/snapshotReader';
import type { RestorePersistedSessionForSigningInput } from '../session/restoreCoordinator';
import type {
  ThresholdEcdsaKeyRefLookupResult,
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
import {
  emitSigningSessionFlowFailure,
  emitSigningSessionFlowTrace,
} from '../session/signingSession/trace';
import { computeSigningOperationFingerprint } from '../session/signingSession/operationFingerprint';
import {
  isSigningSessionBudgetExhaustedError,
  type SigningSessionBudgetStatusAuth,
  type SigningSessionPreparedBudgetIdentity,
  type SigningSessionBudgetReservation,
} from '../session/signingSession/budget';
import type { SigningSessionCoordinator } from '../session/SigningSessionCoordinator';
import type { BootstrapEcdsaSessionArgs } from './thresholdLifecycle/thresholdSessionActivation';
import type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/thresholdActivation';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EmailOtpAuthLane } from '../emailOtp/authLane';
import {
  evmFamilySigningTargetFromExplicitTarget,
  type EvmFamilyChain,
  type EvmFamilyLifecycleEventCallback,
} from './evmFamily/types';
import {
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '../session/signingSession/ecdsaChainTarget';
import { throwIfEvmFamilySigningCancelled } from './evmFamily/errors';
import {
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaKeyRef,
  summarizeEvmFamilyEcdsaLane,
  summarizeEvmFamilyEcdsaSessionRecord,
  updateResolvedEvmFamilyEcdsaSigningLaneIdentity,
  type EcdsaSigningListLookupArgs,
  type EcdsaSigningLookupArgs,
  type EvmFamilyEcdsaSessionReaderDeps,
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
  admitTransactionBudget,
  finalizeSignedTransactionOperation,
  prepareTransactionSigningOperation,
  recordPreparedTransactionBudgetAdmission,
  replacePreparedTransactionLane,
  signPreparedTransactionOperation,
  type BudgetAdmittedOperation,
  type EvmFamilyEcdsaTransactionLane,
} from '../session/signingSession/transactionState';
import { completeEvmFamilyEmailOtpSigningRefresh } from './evmFamily/emailOtpRefresh';
import { createEvmFamilySigningFlowRuntime } from './evmFamily/signingFlowRuntime';
import { retryEvmFamilyWithFreshEmailOtpAuthWhenRequired } from './evmFamily/freshEmailOtpRetry';
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
  const thresholdSessionJwt = String(keyRef?.thresholdSessionJwt || '').trim();
  return {
    relayerUrl,
    thresholdSessionId,
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
  };
}

export {
  reconcileEvmFamilyNonceLane,
  reportEvmFamilyBroadcastAccepted,
  reportEvmFamilyBroadcastRejected,
  reportEvmFamilyDroppedOrReplaced,
  reportEvmFamilyFinalized,
} from './evmFamily/nonceLifecycleAdapter';

export type EvmFamilySigningDeps = EvmFamilyEcdsaSessionReaderDeps & {
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
  listThresholdEcdsaSessionRecordsForSigning: (
    args: EcdsaSigningListLookupArgs,
  ) => ThresholdEcdsaSessionRecord[];
  listThresholdEcdsaKeyRefsForSigning: (
    args: EcdsaSigningListLookupArgs,
  ) => ThresholdEcdsaKeyRefLookupResult[];
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
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    record?: ThresholdEcdsaSessionRecord;
    authLane?: EmailOtpAuthLane;
    remainingUses?: number;
  }) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  restorePersistedSessionForSigning: (
    args: Extract<RestorePersistedSessionForSigningInput, { curve: 'ecdsa' }>,
  ) => Promise<unknown>;
  readSigningSessionSnapshotForSigning: (
    args: Extract<ReadSigningSessionSnapshotForSigningInput, { curve: 'ecdsa' }>,
  ) => Promise<SigningSessionSnapshot>;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  markThresholdEcdsaEmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: string;
    chainTarget: ThresholdEcdsaChainTarget;
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
  const requestChain = signingTarget.chain;
  const requestChainTarget = signingTarget.chainTarget;

  let thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  let thresholdEcdsaRecord: ThresholdEcdsaSessionRecord | undefined;
  let accountAuth: AccountAuthMetadata | undefined;
  let ecdsaSigningLane: SigningLaneContext | undefined;
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
    emailOtpReauthRecord = preparedEcdsaSigningSession.emailOtpReauthRecord;
    accountAuth = preparedEcdsaSigningSession.accountAuth;
    thresholdEcdsaRecord = preparedEcdsaSigningSession.warmRecord;
    thresholdEcdsaKeyRef = preparedEcdsaSigningSession.warmKeyRef;
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
    chain: requestChain,
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
  const admitPreparedEcdsaBudgetIdentity = (
    prepared: PreparedEvmFamilyEcdsaSigningSession,
    budgetIdentity: SigningSessionPreparedBudgetIdentity,
    trustedStatusAuth?: SigningSessionBudgetStatusAuth,
  ): PreparedEvmFamilyEcdsaSigningSession => {
    if (
      budgetIdentity.walletSigningSessionId !==
      String(prepared.signingLane.walletSigningSessionId)
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
      ...preparedWithoutBudget,
      accountAuth: resolvedAccountAuth,
      authMethod: argsForRefresh.authMethod,
      source: argsForRefresh.source,
      signingLane,
      budget: { kind: 'not_admitted' as const, reason: 'budget_identity_not_prepared' as const },
      ...(thresholdEcdsaRecord ? { warmRecord: thresholdEcdsaRecord } : {}),
      ...(thresholdEcdsaKeyRef ? { warmKeyRef: thresholdEcdsaKeyRef } : {}),
      ...(thresholdEcdsaRecord && argsForRefresh.authMethod === SIGNER_AUTH_METHODS.emailOtp
        ? { emailOtpReauthRecord: thresholdEcdsaRecord }
        : {}),
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
    signingLane: SigningLaneContext;
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
    const subjectId = String(identitySource.subjectId || '').trim();
    const ecdsaThresholdKeyId = String(identitySource.ecdsaThresholdKeyId || '').trim();
    const signingRootId = String(identitySource.signingRootId || '').trim();
    const signingRootVersion = String(identitySource.signingRootVersion || 'default').trim();
    if (!subjectId || !ecdsaThresholdKeyId || !signingRootId || !signingRootVersion) {
      throw new Error(
        '[SigningEngine][ecdsa] reauth refresh received incomplete ECDSA material identity',
      );
    }
    const transactionLane: EvmFamilyEcdsaTransactionLane = {
      accountId: resolvedLane.accountId,
      subjectId: toWalletSubjectId(subjectId),
      authMethod: resolvedLane.authMethod,
      curve: 'ecdsa',
      chainTarget: requestChainTarget,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      walletSigningSessionId: resolvedLane.walletSigningSessionId,
      thresholdSessionId: resolvedLane.thresholdSessionId,
    };
    const preparedTransaction = await prepareTransactionSigningOperation({
      intent:
        signingTarget.chain === 'tempo'
          ? {
              walletId: args.nearAccountId,
              curve: 'ecdsa',
              chain: 'tempo',
              chainTarget: signingTarget.chainTarget,
              authSelectionPolicy: { kind: 'explicit', authMethod: resolvedLane.authMethod },
              operationUsesNeeded: 1,
            }
          : {
              walletId: args.nearAccountId,
              curve: 'ecdsa',
              chain: 'evm',
              chainTarget: signingTarget.chainTarget,
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
      budget: preparedTransaction.budget,
      ...(argsForRefresh.trustedStatusAuth
        ? { budgetStatusAuth: argsForRefresh.trustedStatusAuth }
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
        lane: prepared.transactionOperation.lane,
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
  const requireBudgetAdmittedPreparedEcdsaSession = (
    expectedPrepared: PreparedEvmFamilyEcdsaSigningSession | undefined,
    context: string,
  ): PreparedEvmFamilyEcdsaSigningSession & {
    budget: Extract<PreparedEvmFamilyEcdsaSigningSession['budget'], { kind: 'admitted' }>;
  } => {
    const prepared = expectedPrepared || getPreparedEcdsaSigningSession();
    assertPreparedEcdsaOperationLane(prepared, context);
    if (prepared.budget.kind !== 'admitted') {
      emitSigningSessionFlowFailure('evm-family', {
        stage: 'ecdsa_attempt.admitted_state_required',
        accountId: args.nearAccountId,
        chain: args.request.chain,
        context,
        lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
        budgetKind: prepared.budget.kind,
      });
      throw new Error(
        `[SigningEngine][ecdsa] ${context} requires admitted budget state`,
      );
    }
    return prepared as PreparedEvmFamilyEcdsaSigningSession & {
      budget: Extract<PreparedEvmFamilyEcdsaSigningSession['budget'], { kind: 'admitted' }>;
    };
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
            chainId: args.request.tx.chainId,
            chainTarget: signingTarget.chainTarget,
            senderSignatureAlgorithm: 'secp256k1',
            preparedOperation: prepared.preparedOperation,
          });
        })()
      : await resolveEvmFamilyTransactionWalletAuth({
          ...walletAuthArgsBase,
          chainId: args.request.tx.chainId,
          chainTarget: signingTarget.chainTarget,
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
            chainTarget: signingTarget.chainTarget,
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
          if (!refreshed.lane) {
            emitSigningSessionFlowFailure('evm-family', {
              stage: 'ecdsa_attempt.email_otp_reauth_missing_lane',
              accountId: args.nearAccountId,
              chain: args.request.chain,
              refreshedRecord: summarizeEvmFamilyEcdsaSessionRecord(refreshed.record),
              refreshedKeyRef: summarizeEvmFamilyEcdsaKeyRef(refreshed.keyRef),
            });
            throw new Error('[SigningEngine][ecdsa] Email OTP reauth did not return exact ECDSA lane');
          }
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
            ...(refreshed.record ? { record: refreshed.record } : {}),
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
    ...(emailOtpSigningForFlow ? { emailOtpSigningForFlow } : {}),
    confirmationConfigOverride: args.confirmationConfigOverride,
    shouldAbort: args.shouldAbort,
    onEvent: args.onEvent,
    getThresholdEcdsaKeyRef: () => thresholdEcdsaKeyRef,
    setThresholdEcdsaKeyRef: async (keyRef) => {
      thresholdEcdsaKeyRef = keyRef;
      if (args.request.senderSignatureAlgorithm === 'secp256k1' && preparedEcdsaSigningSession) {
        const currentPrepared = preparedEcdsaSigningSession;
        const keyRefThresholdSessionId = String(keyRef.thresholdSessionId || '').trim();
        const keyRefWalletSigningSessionId = String(keyRef.walletSigningSessionId || '').trim();
        const keyRefReplacedLaneIdentity =
          keyRefThresholdSessionId &&
          keyRefWalletSigningSessionId &&
          (keyRefThresholdSessionId !== String(currentPrepared.signingLane.thresholdSessionId) ||
            keyRefWalletSigningSessionId !==
              String(currentPrepared.signingLane.walletSigningSessionId));
        const updatedPrepared = keyRefReplacedLaneIdentity
          ? await replacePreparedEcdsaSigningOperationAfterReauth({
              authMethod: currentPrepared.authMethod,
              source: currentPrepared.source,
              signingLane: updateResolvedEvmFamilyEcdsaSigningLaneIdentity({
                lane: currentPrepared.signingLane,
                chain: args.request.chain,
                thresholdSessionId: keyRefThresholdSessionId,
                walletSigningSessionId: keyRefWalletSigningSessionId,
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
    const prepared = requireBudgetAdmittedPreparedEcdsaSession(
      expectedPrepared,
      'successful wallet signing-session spend',
    );
    await recordSuccessfulEvmFamilyWalletSigningSessionSpend({
      signingSessionCoordinator,
      nearAccountId: args.nearAccountId,
      operation: createTransactionSigningOperation(),
      transactionLane: prepared.budget.operation.lane,
      budgetIdentity: prepared.budget.operation.budgetAdmission.budgetIdentity,
      ...(prepared.budgetStatusAuth ? { trustedStatusAuth: prepared.budgetStatusAuth } : {}),
    });
  };
  const reserveWalletSigningSessionBudget =
    async (
      operation: BudgetAdmittedOperation<EvmFamilyEcdsaTransactionLane>,
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
      return await reserveEvmFamilyWalletSigningSessionBudget({
        signingSessionCoordinator,
        nearAccountId: args.nearAccountId,
        operation: createTransactionSigningOperation(),
        transactionLane: operation.lane,
        budgetIdentity: operation.budgetAdmission.budgetIdentity,
        ...(prepared.budgetStatusAuth ? { trustedStatusAuth: prepared.budgetStatusAuth } : {}),
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
    if (prepared.budget.kind !== 'admitted') return;
    recordFailedEvmFamilyWalletSigningSessionSpend({
      signingSessionCoordinator,
      nearAccountId: args.nearAccountId,
      operation: createTransactionSigningOperation(),
      error,
      transactionLane: prepared.budget.operation.lane,
      budgetIdentity: prepared.budget.operation.budgetAdmission.budgetIdentity,
      ...(prepared.budgetStatusAuth ? { trustedStatusAuth: prepared.budgetStatusAuth } : {}),
    });
  };
  const applySuccessfulEcdsaPostSignPolicy = async (
    expectedPrepared?: PreparedEvmFamilyEcdsaSigningSession,
  ): Promise<void> => {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return;
    const prepared = expectedPrepared || getPreparedEcdsaSigningSession();
    assertPreparedEcdsaOperationLane(prepared, 'post-sign policy');
    const selectedRecord = prepared.emailOtpReauthRecord || prepared.warmRecord;
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
      selectedEcdsaSource: prepared.source,
      selectedRecord,
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
  const thresholdEcdsaBoundary = preparedExecutorSession
    ? preparedExecutorSession.budget.kind === 'admitted'
      ? ({
          kind: 'admitted' as const,
          operation: {
            ...preparedExecutorSession.budget.operation,
            authPlan: signingAuthPlan,
          },
        })
      : ({
          kind: 'not_required' as const,
        })
    : ({
        kind: 'not_required' as const,
      });
  const thresholdEcdsaAuthPlan = preparedExecutorSession
    ? ({
        kind: 'planned' as const,
        signingAuthPlan,
      })
    : ({
        kind: 'not_required' as const,
      });

  const executePayload = {
    deps,
    nearAccountId: args.nearAccountId,
    request: args.request,
    flowArgs,
    nonceOperation,
    onConfirmationDisplayed: markConfirmationDisplayed,
    thresholdEcdsaBoundary,
    thresholdEcdsaAuthPlan,
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
      if (preparedExecutorSession.budget.kind === 'admitted') {
        const signedOperation = await signPreparedTransactionOperation(
          preparedExecutorSession.budget.operation,
          executePayload,
          { sign: async (_operation, payload) => await executeEvmFamilyTransactionSigning(payload) },
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
