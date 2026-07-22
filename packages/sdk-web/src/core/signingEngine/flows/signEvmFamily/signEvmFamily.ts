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
  emailOtpAuthContextRetention,
  type SelectedEcdsaLane,
  type ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import { signingLaneAuthMethod } from '../../session/identity/signingLaneAuthBinding';
import { requireEvmFamilyEcdsaSigner } from '../../session/identity/exactSigningLaneIdentity';
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
  type SigningBudgetFinalizationResult,
  type SigningSessionPreparedBudgetIdentity,
  isSigningSessionBudgetReservation,
  type SigningSessionBudgetReserveResult,
} from '../../session/budget/budget';
import {
  buildSigningGrantAdmissionQueueKey,
  SigningGrantAdmissionError,
  signingGrantAdmissionAuthorityKeyFromAuth,
  waitForSigningGrantAdmissionRetry,
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
import {
  commitReadyEmailOtpEcdsaLaneFromRecord,
  commitReadyPasskeyEcdsaLaneFromRecord,
  type EmailOtpEcdsaCommittedLane,
} from './ecdsaSelection';
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
  recordFailedEvmFamilySigningGrantSpend,
  recordSuccessfulEvmFamilySigningGrantSpend,
  reserveEvmFamilySigningGrantBudget,
  type EvmFamilyTransactionSigningOperationContext,
} from './budgetSpending';
import {
  isEmailOtpSigningAuthPlan,
  isPasskeySigningAuthPlan,
  isWarmSessionSigningAuthPlan,
} from '../../stepUpConfirmation/types';
import type { EvmFamilyThresholdEcdsaStepUp } from './requireEvmFamilyStepUpAuth';
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

type EcdsaBudgetAdmissionAuthority =
  | {
      kind: 'fresh_signer_session';
      signerSession: ReadyEcdsaSignerSession;
    }
  | {
      kind: 'status_reader';
      trustedStatusAuth: SigningSessionBudgetStatusAuth | null;
    };

function walletBudgetProjectionVersion(args: {
  signingGrantId: string;
  expiresAtMs: number;
  committedRemainingUses: number;
  reservedUses: number;
  availableUses: number;
}): string {
  return [
    'wallet-budget',
    args.signingGrantId,
    args.expiresAtMs,
    args.committedRemainingUses,
    args.reservedUses,
    args.availableUses,
  ].join(':');
}

function buildFreshEcdsaBudgetIdentityFromReadySignerSession(args: {
  prepared: PreparedEvmFamilyEcdsaSigningSession;
  signerSession: ReadyEcdsaSignerSession;
  usesNeeded: number;
}): SigningSessionPreparedBudgetIdentity {
  const session = args.signerSession.session;
  const signingGrantId = String(session.signingGrantId);
  const thresholdSessionId = String(session.thresholdSessionId);
  if (
    signingGrantId !== String(args.prepared.signingLane.signingGrantId) ||
    thresholdSessionId !== String(args.prepared.signingLane.thresholdSessionId)
  ) {
    throw new Error(
      '[SigningSessionBudget] fresh ECDSA signer session does not match prepared lane',
    );
  }
  const remainingUses = Math.max(0, Math.floor(Number(session.policy.remainingUses) || 0));
  const usesNeeded = Math.max(1, Math.floor(Number(args.usesNeeded) || 1));
  if (remainingUses < usesNeeded) {
    throw new SigningGrantAdmissionError({
      kind: 'exhausted',
      source: 'trusted_status',
      detail: `fresh ECDSA signer session remaining uses ${remainingUses} is below required uses ${usesNeeded}`,
    });
  }
  const expiresAtMs = Math.max(0, Math.floor(Number(session.policy.expiresAtMs) || 0));
  const projectionVersion = walletBudgetProjectionVersion({
    signingGrantId,
    expiresAtMs,
    committedRemainingUses: remainingUses,
    reservedUses: 0,
    availableUses: remainingUses,
  });
  return {
    signingGrantId,
    projectionVersion,
    status: {
      sessionId: signingGrantId,
      status: 'active',
      committedRemainingUses: remainingUses,
      inFlightReservedUses: 0,
      availableUses: remainingUses,
      remainingUses,
      expiresAtMs,
      projectionVersion,
    },
  };
}

function trustedBudgetStatusAuthFromBudgetAdmissionAuthority(
  authority: EcdsaBudgetAdmissionAuthority,
): SigningSessionBudgetStatusAuth | null {
  switch (authority.kind) {
    case 'fresh_signer_session':
      return trustedBudgetStatusAuthFromReadySignerSession(authority.signerSession);
    case 'status_reader':
      return authority.trustedStatusAuth;
  }
}

function ecdsaBudgetOperationMatchesPreparedSession(args: {
  operation: BudgetAdmittedOperation<SelectedEcdsaLane>;
  prepared: PreparedEvmFamilyEcdsaSigningSession | undefined;
}): boolean {
  const prepared = args.prepared;
  if (!prepared) return false;
  return (
    String(args.operation.lane.signingGrantId) === String(prepared.signingLane.signingGrantId) &&
    String(args.operation.lane.thresholdSessionId) ===
      String(prepared.signingLane.thresholdSessionId)
  );
}

function resolvedEcdsaBudgetSpendLaneForOperation(args: {
  operation: BudgetAdmittedOperation<SelectedEcdsaLane>;
  planningLane: ResolvedEvmFamilyEcdsaSigningLane;
  chain: EvmFamilyChain;
  context: string;
  diagnostics?: Record<string, unknown>;
}): ResolvedEvmFamilyEcdsaSigningLane {
  const operationSigner = requireEvmFamilyEcdsaSigner(
    args.operation.lane.identity,
    `${args.context} admitted operation`,
  );
  const planningSigner = requireEvmFamilyEcdsaSigner(
    args.planningLane.identity,
    `${args.context} planning lane`,
  );
  const sameSigner =
    String(operationSigner.walletId) === String(planningSigner.walletId) &&
    String(operationSigner.keyHandle) === String(planningSigner.keyHandle) &&
    thresholdEcdsaChainTargetKey(operationSigner.chainTarget) ===
      thresholdEcdsaChainTargetKey(planningSigner.chainTarget);
  if (!sameSigner) {
    emitSigningSessionFlowFailure('evm-family', {
      stage: 'ecdsa_attempt.budget_operation_signer_mismatch',
      lane: summarizeEvmFamilyEcdsaLane(args.planningLane),
      admittedLane: summarizeEvmFamilyEcdsaLane(args.operation.lane),
      ...args.diagnostics,
    });
    throw new Error('[SigningEngine][ecdsa] budget operation signer did not match planning lane');
  }
  const updatedLane = updateResolvedEvmFamilyEcdsaSigningLaneIdentity({
    lane: args.planningLane,
    chain: args.chain,
    thresholdSessionId: String(args.operation.lane.thresholdSessionId),
    signingGrantId: String(args.operation.lane.signingGrantId),
    context: args.context,
    diagnostics: args.diagnostics,
  });
  return {
    ...updatedLane,
    ...args.operation.lane,
    key: operationSigner.key,
    keyHandle: operationSigner.keyHandle,
    chainTarget: operationSigner.chainTarget,
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: operationSigner.chainTarget.kind,
  };
}

function trustedBudgetStatusAuthFromReadySignerSession(
  signerSession: ReadyEcdsaSignerSession,
): SigningSessionBudgetStatusAuth {
  const walletSessionJwt = signerSession.routerAbEcdsaDerivationNormalSigning.credential.walletSessionJwt;
  return {
    relayerUrl: signerSession.transport.relayerUrl,
    thresholdSessionId: String(signerSession.session.thresholdSessionId),
    walletSessionJwt,
  };
}

function trustedBudgetStatusAuthForEcdsaBudgetOperation(args: {
  operation: BudgetAdmittedOperation<SelectedEcdsaLane>;
  signerSession: ReadyEcdsaSignerSession;
}): SigningSessionBudgetStatusAuth {
  const session = args.signerSession.session;
  if (
    String(session.thresholdSessionId) !== String(args.operation.lane.thresholdSessionId) ||
    String(session.signingGrantId) !== String(args.operation.lane.signingGrantId)
  ) {
    throw new Error(
      '[SigningSessionBudget] ECDSA budget auth session does not match admitted operation',
    );
  }
  return trustedBudgetStatusAuthFromReadySignerSession(args.signerSession);
}

function ecdsaSigningGrantAdmissionQueueKey(args: {
  walletId: string;
  prepared: PreparedEvmFamilyEcdsaSigningSession;
}): ReturnType<typeof buildSigningGrantAdmissionQueueKey> {
  const signingGrantId = args.prepared.signingLane.signingGrantId;
  const projectionVersion =
    args.prepared.budget.kind === 'BudgetAdmitted'
      ? args.prepared.budget.operation.budgetAdmission.budgetIdentity.projectionVersion
      : 'projection-unadmitted';
  return buildSigningGrantAdmissionQueueKey({
    walletId: args.walletId,
    curve: 'ecdsa',
    signingGrantId,
    projectionVersion,
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
    walletId: args.walletId,
    message: isEmailOtp
      ? 'Signing session needs reauthorization; requesting Email OTP'
      : 'Signing session needs reauthorization; requesting passkey',
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: args.chain, reason: 'wallet_signing_budget_reserved' },
  });
}

function remainingUsesFromBudgetFinalization(
  result: SigningBudgetFinalizationResult | null,
): number | null {
  if (!result) return null;
  switch (result.kind) {
    case 'finalized':
    case 'already_finalized':
      return Math.max(0, Math.floor(Number(result.remainingUses) || 0));
    case 'projection_mismatch':
    case 'missing_reservation':
    case 'reservation_identity_mismatch':
    case 'budget_status_unavailable':
      return null;
    default:
      return assertNeverSigningBudgetFinalization(result);
  }
}

function assertNeverSigningBudgetFinalization(result: never): never {
  throw new Error(`[SigningSessionBudget] unhandled finalization result: ${String(result)}`);
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
      signingGrantId: prepared
        ? String(prepared.signingLane.signingGrantId)
        : material
          ? material.identity.signingGrantId
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
    thresholdEcdsaRecord =
      getEcdsaMaterialRecord(preparedEcdsaSigningSession.material) ||
      readSelectedEcdsaRecordForLane({
        deps,
        lane: preparedEcdsaSigningSession.signingLane,
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
  const loginWithEmailOtpEcdsaCapabilityForSigning =
    deps.loginWithEmailOtpEcdsaCapabilityForSigning;
  const confirmedSigningDeps: EvmFamilyConfirmedSigningDeps = {
    ...deps,
    requestEmailOtpTransactionSigningChallenge,
    loginWithEmailOtpEcdsaCapabilityForSigning,
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
    if (budgetIdentity.signingGrantId !== String(prepared.signingLane.signingGrantId)) {
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
      signingGrantId: string;
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
      signingGrantId:
        argsForRefresh.signingSessionIdentity?.signingGrantId || String(currentLane.signingGrantId),
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
    let refreshedSelection: PreparedEvmFamilyEcdsaSigningSession['selection'];
    if (prepared.selection.kind === 'ready') {
      const refreshedRecord =
        getEcdsaMaterialRecord(refreshedMaterial) || prepared.selection.material.record;
      const readyMaterial = requireReadyEcdsaMaterialForResolvedLane({
        lane: signingLane,
        authMethod: argsForRefresh.authMethod,
        source: argsForRefresh.source,
        record: refreshedRecord,
        context: argsForRefresh.context,
      });
      refreshedSelection =
        argsForRefresh.authMethod === SIGNER_AUTH_METHODS.emailOtp
          ? {
              kind: 'ready',
              accountAuth: prepared.selection.accountAuth,
              authMethod: SIGNER_AUTH_METHODS.emailOtp,
              source: argsForRefresh.source,
              lane: signingLane,
              material: readyMaterial,
              committedLane: commitReadyEmailOtpEcdsaLaneFromRecord({
                lane: signingLane,
                record: readyMaterial.record,
                material: readyMaterial,
              }),
              diagnostics: prepared.selection.diagnostics,
            }
          : {
              kind: 'ready',
              accountAuth: prepared.selection.accountAuth,
              authMethod: SIGNER_AUTH_METHODS.passkey,
              source: argsForRefresh.source,
              lane: signingLane,
              material: readyMaterial,
              committedLane: commitReadyPasskeyEcdsaLaneFromRecord({
                lane: signingLane,
                record: readyMaterial.record,
                material: readyMaterial,
                source: argsForRefresh.source,
              }),
              diagnostics: prepared.selection.diagnostics,
            };
    } else if (prepared.selection.reason === 'missing_hot_material') {
      refreshedSelection =
        prepared.selection.authMethod === SIGNER_AUTH_METHODS.emailOtp
          ? {
              ...prepared.selection,
              authMethod: SIGNER_AUTH_METHODS.emailOtp,
              lane: signingLane,
              material: refreshedMaterial,
              committedLane: {
                ...prepared.selection.committedLane,
                lane: signingLane,
                material: refreshedMaterial,
              },
            }
          : {
              ...prepared.selection,
              authMethod: SIGNER_AUTH_METHODS.passkey,
              lane: signingLane,
              material: refreshedMaterial,
              committedLane: {
                ...prepared.selection.committedLane,
                lane: signingLane,
                material: refreshedMaterial,
              },
            };
    } else {
      refreshedSelection =
        prepared.selection.authMethod === SIGNER_AUTH_METHODS.emailOtp
          ? {
              kind: 'reauth_required',
              accountAuth: prepared.selection.accountAuth,
              authMethod: SIGNER_AUTH_METHODS.emailOtp,
              lane: signingLane,
              material: refreshedMaterial,
              reason: prepared.selection.reason,
              reauthLane: {
                kind: 'public_reauth_lane',
                lane: signingLane,
                authority: prepared.selection.reauthLane.authority,
                publicRestore: prepared.selection.reauthLane.publicRestore,
                reauthAnchor: prepared.selection.reauthLane.reauthAnchor,
                material: refreshedMaterial,
              },
              diagnostics: prepared.selection.diagnostics,
            }
          : {
              kind: 'reauth_required',
              accountAuth: prepared.selection.accountAuth,
              authMethod: SIGNER_AUTH_METHODS.passkey,
              lane: signingLane,
              material: refreshedMaterial,
              reason: prepared.selection.reason,
              reauthLane: {
                kind: 'public_reauth_lane',
                lane: signingLane,
                authority: prepared.selection.reauthLane.authority,
                publicRestore: prepared.selection.reauthLane.publicRestore,
                reauthAnchor: prepared.selection.reauthLane.reauthAnchor,
                material: refreshedMaterial,
              },
              diagnostics: prepared.selection.diagnostics,
            };
    }
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
      admittedBudgetIdentity.signingGrantId === String(signingLane.signingGrantId) &&
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
    const resolvedLaneAuthMethod = signingLaneAuthMethod(resolvedLane.auth);
    if (resolvedLaneAuthMethod !== argsForRefresh.authMethod) {
      throw new Error(
        `[SigningEngine][ecdsa] reauth lane auth method ${resolvedLaneAuthMethod} did not match ${argsForRefresh.authMethod}`,
      );
    }
    const transactionLane = selectedEvmFamilyEcdsaLaneForMaterialIdentity({
      lane: resolvedLane,
      chain: requestChain,
      chainTarget: requestChainTarget,
      identity: argsForRefresh.record,
      context: 'reauth refresh',
    });
    const readyMaterial = requireReadyEcdsaMaterialForResolvedLane({
      lane: resolvedLane,
      authMethod: argsForRefresh.authMethod,
      source: argsForRefresh.source,
      record: argsForRefresh.record,
      context: 'EVM-family signing reauth refresh',
    });
    const refreshedTrustedStatusAuth =
      argsForRefresh.trustedStatusAuth ||
      trustedBudgetStatusAuthFromReadySignerSession(readyMaterial.signerSession);
    const preparedTransaction = await prepareTransactionSigningOperation({
      intent:
        signingTarget.kind === 'tempo'
          ? {
              walletId,
              curve: 'ecdsa',
              chain: 'tempo',
              chainTarget: signingTarget,
              authSelectionPolicy: { kind: 'explicit', authMethod: resolvedLaneAuthMethod },
              operationUsesNeeded: requiredSignatureUses,
            }
          : {
              walletId,
              curve: 'ecdsa',
              chain: 'evm',
              chainTarget: signingTarget,
              authSelectionPolicy: { kind: 'explicit', authMethod: resolvedLaneAuthMethod },
              operationUsesNeeded: requiredSignatureUses,
            },
      coordinator: signingSessionCoordinator,
      missingWhenExpiresAtMissing: true,
      prepareBudgetIdentity: false,
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
              trustedStatusAuth: refreshedTrustedStatusAuth,
            },
            availableLanesGeneration: Date.now(),
            metadata: {},
          };
        },
      },
    });
    const preparedOperation = preparedTransaction.thresholdOperation;
    const refreshedSelection: PreparedEvmFamilyEcdsaSigningSession['selection'] =
      argsForRefresh.authMethod === SIGNER_AUTH_METHODS.emailOtp
        ? {
            kind: 'ready',
            accountAuth: resolvedAccountAuth,
            authMethod: SIGNER_AUTH_METHODS.emailOtp,
            source: argsForRefresh.source,
            lane: preparedOperation.lane,
            material: readyMaterial,
            committedLane: commitReadyEmailOtpEcdsaLaneFromRecord({
              lane: preparedOperation.lane,
              record: readyMaterial.record,
              material: readyMaterial,
            }),
            diagnostics: {
              selectedLaneCandidate: {
                authMethod: argsForRefresh.authMethod,
                chain: requestChain,
                chainTarget: requestChainTarget,
                state: 'ready',
                source: 'runtime_session_record',
                signingGrantId: String(preparedOperation.lane.signingGrantId),
                thresholdSessionId: String(preparedOperation.lane.thresholdSessionId),
                remainingUses: null,
                expiresAtMs: null,
                updatedAtMs: null,
              },
              exactCandidateMaterial: summarizeEcdsaMaterialState(readyMaterial),
              visibleEmailOtpMaterial: summarizeEcdsaMaterialState(readyMaterial),
              visiblePasskeyMaterials: [],
              selectedPasskeyMaterial: { present: false },
            },
          }
        : {
            kind: 'ready',
            accountAuth: resolvedAccountAuth,
            authMethod: SIGNER_AUTH_METHODS.passkey,
            source: argsForRefresh.source,
            lane: preparedOperation.lane,
            material: readyMaterial,
            committedLane: commitReadyPasskeyEcdsaLaneFromRecord({
              lane: preparedOperation.lane,
              record: readyMaterial.record,
              material: readyMaterial,
              source: argsForRefresh.source,
            }),
            diagnostics: {
              selectedLaneCandidate: {
                authMethod: argsForRefresh.authMethod,
                chain: requestChain,
                chainTarget: requestChainTarget,
                state: 'ready',
                source: 'runtime_session_record',
                signingGrantId: String(preparedOperation.lane.signingGrantId),
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
          };
    const prepared: PreparedEvmFamilyEcdsaSigningSession = {
      accountAuth: resolvedAccountAuth,
      authMethod: argsForRefresh.authMethod,
      source: argsForRefresh.source,
      selection: refreshedSelection,
      material: readyMaterial,
      availableLanesGeneration: preparedOperation.availableLanesGeneration,
      signingLane: preparedOperation.lane,
      preparedOperation,
      transactionOperation: preparedTransaction.transactionOperation,
      budget: preparedTransaction.budget,
      budgetStatusAuth: refreshedTrustedStatusAuth,
    };
    assertPreparedEcdsaOperationLane(prepared, 'EVM-family signing reauth refresh');
    preparedEcdsaSigningSession = prepared;
    ecdsaSigningLane = prepared.signingLane;
    selectedEcdsaAuthMethod = prepared.authMethod;
    return prepared;
  };
  const admitPreparedEcdsaTransactionBudget = async (
    prepared: PreparedEvmFamilyEcdsaSigningSession,
    authority: EcdsaBudgetAdmissionAuthority,
  ): Promise<PreparedEvmFamilyEcdsaSigningSession> => {
    assertPreparedEcdsaOperationLane(prepared, 'budget identity preparation');
    const admittedBudgetIdentity = getAdmittedEcdsaBudgetIdentity(prepared);
    if (
      admittedBudgetIdentity &&
      admittedBudgetIdentity.signingGrantId === String(prepared.signingLane.signingGrantId) &&
      String(prepared.transactionOperation.lane.thresholdSessionId) ===
        String(prepared.signingLane.thresholdSessionId)
    ) {
      emitSigningSessionFlowTrace('evm-family', {
        stage: 'ecdsa_attempt.budget_admission_reused',
        walletId,
        chain: args.request.chain,
        chainTarget: requestChainTarget,
        lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
        budgetKind: prepared.budget.kind,
        ...buildBudgetFailureDiagnostics(prepared),
      });
      return prepared;
    }
    const trustedStatusAuth = trustedBudgetStatusAuthFromBudgetAdmissionAuthority(authority);
    const budgetIdentity =
      authority.kind === 'fresh_signer_session'
        ? buildFreshEcdsaBudgetIdentityFromReadySignerSession({
            prepared,
            signerSession: authority.signerSession,
            usesNeeded: requiredSignatureUses,
          })
        : await signingSessionCoordinator.prepareBudgetIdentity({
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
      walletId,
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
      walletId,
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
        {
          kind: 'status_reader',
          trustedStatusAuth: preparedEcdsaSigningSession.budgetStatusAuth || null,
        },
      );
      if (admittedWarmSession.budget.kind === 'BudgetAdmitted') {
        preparedEcdsaSigningSession = admittedWarmSession;
        ecdsaSigningLane = admittedWarmSession.signingLane;
        selectedEcdsaAuthMethod = admittedWarmSession.authMethod;
        thresholdEcdsaRecord = getEcdsaMaterialRecord(admittedWarmSession.material);
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_attempt.warm_session_budget_admitted',
          walletId,
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
        walletId,
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
            walletId,
            chain: args.request.chain,
            refreshedLane: summarizeEvmFamilyEcdsaLane(refreshed.lane),
            refreshedRecord: summarizeEvmFamilyEcdsaSessionRecord(refreshed.record),
          });
          const refreshedSignerSession = await toReadyEcdsaSignerSessionFromReadyMaterial({
            material: refreshed.readyMaterial,
          });
          const refreshedTrustedBudgetStatusAuth =
            trustedBudgetStatusAuthFromReadySignerSession(refreshedSignerSession);
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
            {
              kind: 'fresh_signer_session',
              signerSession: refreshedSignerSession,
            },
          );
          if (admittedAfterReauth.budget.kind !== 'BudgetAdmitted') {
            emitSigningSessionFlowFailure('evm-family', {
              stage: 'ecdsa_attempt.email_otp_reauth_not_admitted',
              walletId,
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
            walletId,
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
        const refreshedSigningGrantId = String(record.signingGrantId || '').trim();
        if (!refreshedThresholdSessionId || !refreshedSigningGrantId) {
          throw new Error(
            '[SigningEngine][ecdsa] record update requires explicit session identity',
          );
        }
        const replacedLaneIdentity =
          refreshedThresholdSessionId !== String(currentPrepared.signingLane.thresholdSessionId) ||
          refreshedSigningGrantId !== String(currentPrepared.signingLane.signingGrantId);
        let updatedPrepared: PreparedEvmFamilyEcdsaSigningSession;
        if (replacedLaneIdentity) {
          const refreshedLane = updateResolvedEvmFamilyEcdsaSigningLaneIdentity({
            lane: currentPrepared.signingLane,
            chain: requestChain,
            thresholdSessionId: refreshedThresholdSessionId,
            signingGrantId: refreshedSigningGrantId,
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
              signingGrantId: refreshedSigningGrantId,
            },
            forceRefreshBudgetIdentity: !signingGrantBudgetReserved,
          });
        }
        const refreshedReadyToSignMaterial = requireReadyEcdsaMaterial(
          updatedPrepared.material,
          'EVM-family signing record refresh',
        );
        const admittedPrepared = await admitPreparedEcdsaTransactionBudget(updatedPrepared, {
          kind: 'fresh_signer_session',
          signerSession: refreshedReadyToSignMaterial.signerSession,
        });
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
    if (decision.retryMode === 'wait_and_retry_admission') {
      await waitForSigningGrantAdmissionRetry(decision.retryAfterMs);
      const result = await signEvmFamilyAttempt(deps, args, {
        forceFreshAuth: false,
        operationIds,
        retryingFreshAuth: attempt.retryingFreshAuth,
        signingSessionCoordinator,
      });
      freshAuthRetryHandledFinalization = true;
      return result;
    }
    emitEvmFamilyFreshAuthRetryEvent({
      walletId,
      chain: args.request.chain,
      accountAuth: resolvedAccountAuth,
      onEvent: args.onEvent,
    });
    const queueKey = ecdsaSigningGrantAdmissionQueueKey({
      walletId,
      prepared: getPreparedEcdsaSigningSession(),
    });
    const result = await signingSessionCoordinator.runSigningGrantAdmissionRetry({
      queueKey,
      refresh: async () =>
        await signEvmFamilyAttempt(deps, args, {
          forceFreshAuth: true,
          operationIds,
          retryingFreshAuth: true,
          signingSessionCoordinator,
        }),
      retryAfterRefresh: async () =>
        await signEvmFamilyAttempt(deps, args, {
          forceFreshAuth: false,
          operationIds,
          retryingFreshAuth: attempt.retryingFreshAuth,
          signingSessionCoordinator,
        }),
    });
    freshAuthRetryHandledFinalization = true;
    return result;
  };
  const recordSuccessfulSigningGrantSpend = async (
    expectedPrepared?: PreparedEvmFamilyEcdsaSigningSession,
  ): Promise<void> => {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return;
    const prepared = requireBudgetAdmittedPreparedEcdsaSession(
      expectedPrepared,
      'successful signing grant spend',
    );
    const budgetDiagnostics = buildBudgetFailureDiagnostics(prepared);
    emitSigningSessionFlowTrace('evm-family', {
      stage: 'ecdsa_attempt.budget_finalization_started',
      walletId,
      chain: args.request.chain,
      chainTarget: requestChainTarget,
      lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
      reserved: signingGrantBudgetReserved,
      ...budgetDiagnostics,
    });
    try {
      const result = await recordSuccessfulEvmFamilySigningGrantSpend({
        signingSessionCoordinator,
        walletSession: args.walletSession,
        operation: createTransactionSigningOperation(),
        admittedTransaction: prepared.budget.operation,
        finalizedSigningLane: prepared.signingLane,
        ...(prepared.budgetStatusAuth ? { trustedStatusAuth: prepared.budgetStatusAuth } : {}),
      });
      const remainingUses = remainingUsesFromBudgetFinalization(result);
      if (remainingUses !== null) {
        emitEvmFamilySigningEvent(args.onEvent, {
          phase: SigningEventPhase.STEP_11_REMAINING_SPEND_UPDATED,
          status: 'succeeded',
          walletId,
          interaction: { kind: 'none', overlay: 'none' },
          data: {
            chain: args.request.chain,
            remainingUses,
            signingGrantId: String(prepared.signingLane.signingGrantId),
            thresholdSessionId: String(prepared.signingLane.thresholdSessionId),
          },
        });
      }
      emitSigningSessionFlowTrace('evm-family', {
        stage: 'ecdsa_attempt.budget_finalized',
        walletId,
        chain: args.request.chain,
        chainTarget: requestChainTarget,
        lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
        reserved: signingGrantBudgetReserved,
        ...budgetDiagnostics,
      });
    } catch (error: unknown) {
      emitSigningSessionFlowFailure('evm-family', {
        stage: 'ecdsa_attempt.budget_finalization_failed',
        walletId,
        chain: args.request.chain,
        chainTarget: requestChainTarget,
        lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
        reserved: signingGrantBudgetReserved,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
        ...budgetDiagnostics,
      });
      throw error;
    }
  };
  let signingGrantBudgetReserved = false;
  const reserveSigningGrantBudget = async (input: {
    operation: BudgetAdmittedOperation<SelectedEcdsaLane>;
    signerSession: ReadyEcdsaSignerSession;
  }): Promise<SigningSessionBudgetReserveResult> => {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return null;
    const { operation } = input;
    const operationBudgetStatusAuth = trustedBudgetStatusAuthForEcdsaBudgetOperation(input);
    const prepared = preparedEcdsaSigningSession;
    const operationLane = resolvedEcdsaBudgetSpendLaneForOperation({
      operation,
      planningLane: getResolvedEcdsaSigningLane(),
      chain: requestChain,
      context: 'signing grant reservation',
      diagnostics: ecdsaAttemptDiagnostics,
    });
    const preparedMatchesOperation = ecdsaBudgetOperationMatchesPreparedSession({
      operation,
      prepared,
    });
    if (!preparedMatchesOperation) {
      emitSigningSessionFlowTrace('evm-family', {
        stage: 'ecdsa_attempt.budget_reservation_uses_admitted_operation',
        walletId,
        chain: args.request.chain,
        chainTarget: requestChainTarget,
        admittedLane: summarizeEvmFamilyEcdsaLane(operationLane),
        preparedLane: prepared
          ? summarizeEvmFamilyEcdsaLane(prepared.signingLane)
          : { present: false },
      });
    }
    const reservation = await reserveEvmFamilySigningGrantBudget({
      signingSessionCoordinator,
      walletSession: args.walletSession,
      operation: createTransactionSigningOperation(),
      admittedTransaction: operation,
      finalizedSigningLane: operationLane,
      trustedStatusAuth: operationBudgetStatusAuth,
    });
    signingGrantBudgetReserved = isSigningSessionBudgetReservation(reservation);
    return reservation;
  };
  const recordFailedSigningGrantSpend = (
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
      walletId,
      chain: args.request.chain,
      chainTarget: requestChainTarget,
      lane: summarizeEvmFamilyEcdsaLane(prepared.signingLane),
      error: error instanceof Error ? error.message : String(error || 'unknown error'),
      ...buildBudgetFailureDiagnostics(prepared),
    });
    recordFailedEvmFamilySigningGrantSpend({
      signingSessionCoordinator,
      walletSession: args.walletSession,
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
    const transactionSigner = requireEvmFamilyEcdsaSigner(
      prepared.transactionOperation.lane.identity,
      'ECDSA post-sign policy',
    );
    await applySuccessfulEvmFamilyEcdsaPostSignPolicy({
      postSignPolicy: warmSessionServices,
      walletId,
      chainTarget: transactionSigner.chainTarget,
      ecdsaSigningLane: prepared.signingLane,
      selectedRecord,
    });
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
      signingGrantId: String(preparedNonceSession.signingLane.signingGrantId),
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
    preparedExecutorReadyMaterial.readyMaterial.record.emailOtpAuthContext &&
    emailOtpAuthContextRetention(
      preparedExecutorReadyMaterial.readyMaterial.record.emailOtpAuthContext,
    ) === 'single_use';
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
    reserveSigningGrantBudget,
    recordSuccessfulSigningGrantSpend,
    recordFailedSigningGrantSpend,
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
      recordFailedSigningGrantSpend(error, failedPreparedSession);
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
          await recordSuccessfulSigningGrantSpend(finalPreparedSession);
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
