import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { TatchiConfigsReadonly } from '@/core/types/tatchi';
import type { AccountAuthMetadata } from '@/core/signingEngine/auth';
import type { EvmNonceManager } from '@/core/rpcClients/evm/nonceManager';
import type { EvmSigningRequest } from '../chainAdaptors/evm/types';
import type { EvmSignedResult } from '../chainAdaptors/evm/evmAdapter';
import type { TempoSigningRequest } from '../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from './thresholdLifecycle/thresholdSessionStore';
import type { SigningSessionSealedStoreRecord } from './session/signingSessionSealedStore';
import type {
  TouchConfirmContextPort,
  TouchConfirmSigningPort,
  TouchConfirmSecureConfirmationPort,
  WarmSessionMaterialClearer,
  WarmSessionStatusResult,
  WarmSessionStatusReader,
} from '../touchConfirm';
import type { SignerWorkerManagerContext } from '../workerManager';
import type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/thresholdActivation';
import {
  type SigningLaneContext,
  type SigningOperationId,
} from '../session/signingSessionTypes';
import {
  createWalletSigningBudgetLedger,
  type WalletSigningBudgetLedger,
} from '../session/WalletSigningBudgetLedger';
import { emitSigningLaneResolutionTrace } from '../session/SigningSessionTrace';
import type { BootstrapEcdsaSessionArgs } from './thresholdLifecycle/thresholdSessionActivation';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EmailOtpAuthLane } from '../emailOtp/authLane';
import type {
  EvmFamilyChain,
  EvmFamilyLifecycleEventCallback,
} from './evmFamily/types';
import {
  throwIfEvmFamilySigningCancelled,
} from './evmFamily/errors';
import {
  requireEvmFamilyEcdsaAuthMethod,
  requireEvmFamilyEcdsaSigningLane,
  type EcdsaSigningLookupArgs,
  type EvmFamilyEcdsaAuthMethod,
  type PasskeyEcdsaSigningLookupArgs,
} from './evmFamily/ecdsaLanes';
import { resolveEvmFamilyEcdsaSigningSelection } from './evmFamily/ecdsaSelection';
import { resolveEvmFamilyTransactionAccountAuth } from './evmFamily/accountAuth';
import { resolveEvmFamilyTransactionWalletAuth } from './evmFamily/authPlanning';
import {
  recordFailedEvmFamilyWalletSigningSessionSpend,
  recordSuccessfulEvmFamilyWalletSigningSessionSpend,
  reserveEvmFamilyWalletSigningSessionBudget,
} from './evmFamily/budgetSpending';
import { applySuccessfulEvmFamilyEcdsaPostSignPolicy } from './evmFamily/postSignPolicy';
import { executeEvmFamilyTransactionSigning } from './evmFamily/transactionExecutor';
import { completeEvmFamilyEmailOtpSigningRefresh } from './evmFamily/emailOtpRefresh';
import { createEvmFamilySigningFlowRuntime } from './evmFamily/signingFlowRuntime';
import { maybeRetryEvmFamilyWithFreshEmailOtpAuth } from './evmFamily/freshEmailOtpRetry';
import {
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
} from './evmFamily/nonceLifecycle';

export type EvmFamilySigningDeps = {
  indexedDB: UnifiedIndexedDBManager;
  tatchiPasskeyConfigs: TatchiConfigsReadonly;
  evmNonceManager: EvmNonceManager;
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
    record: ThresholdEcdsaSessionRecord;
    authLane?: EmailOtpAuthLane;
  }) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord?: (args: {
    sealedRecord: SigningSessionSealedStoreRecord;
    ecdsaRecord: ThresholdEcdsaSessionRecord;
    ed25519Record?: ThresholdEd25519SessionRecord | null;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    remainingUses: number;
    expiresAtMs: number;
  } | null>;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  markThresholdEcdsaEmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: string;
    chain: EvmFamilyChain;
  }) => void;
  walletSigningBudgetLedger?: WalletSigningBudgetLedger;
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
  forceFreshEmailOtpAuth?: boolean;
  operationIds?: EvmFamilySigningOperationIds;
  retryingFreshEmailOtpAuth?: boolean;
  walletSigningBudgetLedger?: WalletSigningBudgetLedger;
};

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
  let selectedEcdsaSource: ThresholdEcdsaSessionStoreSource | undefined;
  let emailOtpReauthRecord: ThresholdEcdsaSessionRecord | undefined;
  const operationIds =
    attempt.operationIds || createEvmFamilySigningOperationIds(args.signingOperationId);
  const ensureConfirmationOperationId = (): SigningOperationId =>
    ensureEvmFamilyConfirmationOperationId(operationIds);
  let confirmationDisplayed = false;
  const markConfirmationDisplayed = (): SigningOperationId => {
    confirmationDisplayed = true;
    return ensureConfirmationOperationId();
  };
  const walletSigningBudgetLedger =
    attempt.walletSigningBudgetLedger ||
    deps.walletSigningBudgetLedger ||
    createWalletSigningBudgetLedger({});
  if (args.request.senderSignatureAlgorithm === 'secp256k1') {
    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps,
      nearAccountId: args.nearAccountId,
      chain: args.request.chain,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
    });
    ecdsaSigningLane = selection.lane;
    emitSigningLaneResolutionTrace('evm-family', ecdsaSigningLane, {
      reason: 'evm_family_ecdsa_selection',
    });
    selectedEcdsaAuthMethod = selection.authMethod;
    selectedEcdsaSource = selection.source;
    emailOtpReauthRecord = selection.reauthRecord;
    accountAuth = selection.accountAuth;
    thresholdEcdsaRecord = selection.warmRecord;
    thresholdEcdsaKeyRef = selection.warmKeyRef;
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

  const resolveSelectedEcdsaSource = (): ThresholdEcdsaSessionStoreSource | undefined =>
    selectedEcdsaSource ||
    thresholdEcdsaRecord?.source ||
    (resolvedAccountAuth.primaryAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? SIGNER_AUTH_METHODS.emailOtp
      : undefined);
  const resolveEmailOtpReauthRecord = (): ThresholdEcdsaSessionRecord | undefined =>
    selectedEcdsaAuthMethod === SIGNER_AUTH_METHODS.emailOtp ? emailOtpReauthRecord : undefined;
  const walletAuthArgsBase = {
    deps,
    confirmedDeps: deps,
    nearAccountId: args.nearAccountId,
    chain: args.request.chain,
    accountAuth: resolvedAccountAuth,
    forceFreshAuth: attempt.forceFreshEmailOtpAuth === true,
    onEvent: args.onEvent,
  };
  const { signingAuthPlan, signingSessionPlan, emailOtpSigning } =
    args.request.senderSignatureAlgorithm === 'secp256k1'
      ? await resolveEvmFamilyTransactionWalletAuth({
          ...walletAuthArgsBase,
          senderSignatureAlgorithm: 'secp256k1',
          ecdsaSigningLane: requireEvmFamilyEcdsaSigningLane(ecdsaSigningLane),
          ecdsaAuthMethod: requireEvmFamilyEcdsaAuthMethod(selectedEcdsaAuthMethod),
          ...(thresholdEcdsaRecord ? { ecdsaWarmRecord: thresholdEcdsaRecord } : {}),
          ...(thresholdEcdsaKeyRef ? { ecdsaWarmKeyRef: thresholdEcdsaKeyRef } : {}),
          ...(emailOtpReauthRecord ? { emailOtpReauthRecord } : {}),
        })
      : await resolveEvmFamilyTransactionWalletAuth({
          ...walletAuthArgsBase,
          senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
        });
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
          if (refreshed.record) {
            thresholdEcdsaRecord = refreshed.record;
            selectedEcdsaAuthMethod = SIGNER_AUTH_METHODS.emailOtp;
            selectedEcdsaSource = SIGNER_AUTH_METHODS.emailOtp;
            emailOtpReauthRecord = thresholdEcdsaRecord;
            ecdsaSigningLane = refreshed.lane;
          } else {
            thresholdEcdsaRecord = undefined;
          }
          return refreshed.keyRef;
        },
      }
    : undefined;
  const { flowArgs, signingSessionCoordinator } = await createEvmFamilySigningFlowRuntime({
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
    },
    getEcdsaSigningLane: () => requireEvmFamilyEcdsaSigningLane(ecdsaSigningLane),
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
      alreadyRetryingFreshEmailOtpAuth: attempt.retryingFreshEmailOtpAuth,
      hasEmailOtpSigningPlan: !!emailOtpSigning,
      onEvent: args.onEvent,
      retry: async () =>
        await signEvmFamilyAttempt(deps, args, {
          forceFreshEmailOtpAuth: true,
          operationIds,
          retryingFreshEmailOtpAuth: true,
          walletSigningBudgetLedger,
        }),
    });
  };
  const recordSuccessfulWalletSigningSessionSpend = async (): Promise<void> => {
    await recordSuccessfulEvmFamilyWalletSigningSessionSpend({
      deps,
      walletSigningBudgetLedger,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      nearAccountId: args.nearAccountId,
      chain: args.request.chain,
      confirmationOperationId: ensureConfirmationOperationId(),
      ...(ecdsaSigningLane ? { ecdsaSigningLane } : {}),
      ...(thresholdEcdsaRecord ? { thresholdEcdsaRecord } : {}),
      ...(thresholdEcdsaKeyRef ? { thresholdEcdsaKeyRef } : {}),
    });
  };
  const reserveWalletSigningSessionBudget = async (): Promise<void> => {
    await reserveEvmFamilyWalletSigningSessionBudget({
      deps,
      walletSigningBudgetLedger,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      nearAccountId: args.nearAccountId,
      chain: args.request.chain,
      confirmationOperationId: ensureConfirmationOperationId(),
      ...(ecdsaSigningLane ? { ecdsaSigningLane } : {}),
      ...(thresholdEcdsaRecord ? { thresholdEcdsaRecord } : {}),
      ...(thresholdEcdsaKeyRef ? { thresholdEcdsaKeyRef } : {}),
    });
  };
  const recordFailedWalletSigningSessionSpend = (error: unknown): void => {
    if (!confirmationDisplayed) return;
    recordFailedEvmFamilyWalletSigningSessionSpend({
      deps,
      walletSigningBudgetLedger,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      nearAccountId: args.nearAccountId,
      chain: args.request.chain,
      confirmationOperationId: ensureConfirmationOperationId(),
      error,
      ...(ecdsaSigningLane ? { ecdsaSigningLane } : {}),
      ...(thresholdEcdsaRecord ? { thresholdEcdsaRecord } : {}),
      ...(thresholdEcdsaKeyRef ? { thresholdEcdsaKeyRef } : {}),
    });
  };
  const applySuccessfulEcdsaPostSignPolicy = async (chain: EvmFamilyChain): Promise<void> => {
    const selectedSource = resolveSelectedEcdsaSource();
    if (args.request.senderSignatureAlgorithm === 'secp256k1' && !selectedSource) {
      throw new Error('[SigningEngine] ECDSA signing source is required for post-sign cleanup');
    }
    await applySuccessfulEvmFamilyEcdsaPostSignPolicy({
      deps,
      postSignPolicy: signingSessionCoordinator,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      nearAccountId: args.nearAccountId,
      chain,
      ...(ecdsaSigningLane ? { ecdsaSigningLane } : {}),
      ...(selectedSource ? { selectedEcdsaSource: selectedSource } : {}),
      ...(thresholdEcdsaRecord ? { thresholdEcdsaRecord } : {}),
      ...(thresholdEcdsaKeyRef ? { thresholdEcdsaKeyRef } : {}),
    });
  };

  return await executeEvmFamilyTransactionSigning({
    deps,
    nearAccountId: args.nearAccountId,
    request: args.request,
    flowArgs,
    onConfirmationDisplayed: markConfirmationDisplayed,
    reserveWalletSigningSessionBudget,
    recordSuccessfulWalletSigningSessionSpend,
    recordFailedWalletSigningSessionSpend,
    applySuccessfulEcdsaPostSignPolicy,
    retryWithFreshEmailOtpAuth,
    ...(signingSessionPlan ? { signingSessionPlan } : {}),
    ...(thresholdEcdsaRecord ? { thresholdEcdsaRecord } : {}),
    ...(resolveEmailOtpReauthRecord()
      ? { emailOtpReauthRecord: resolveEmailOtpReauthRecord() }
      : {}),
    ...(thresholdEcdsaKeyRef ? { thresholdEcdsaKeyRef } : {}),
  });
}
