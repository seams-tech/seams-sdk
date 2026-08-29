import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { parseSignerSlot } from '@shared/utils/signerSlot';
import {
  parsePasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { DelegateActionInput } from '@/core/types/delegate';
import {
  createSigningFlowEvent,
  SIGNING_SESSION_EXPIRY_DETECTION_SOURCES,
  SigningEventPhase,
  type CreateSigningFlowEventInput,
  type SigningFlowEvent,
} from '@/core/types/sdkSentEvents';
import type {
  ConfirmationConfig,
  RpcCallPayload,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type {
  NearEd25519YaoMaterialExecutor,
  NearEd25519YaoOperationMaterialFacts,
  NearEmailOtpEd25519StepUpHook,
  NearPasskeyEd25519OperationStepUpHook,
  NearTransactionWithActionsPayload,
} from '../../interfaces/near';
import type { NearEd25519YaoSigningPreparation } from '../../session/material/nearEd25519YaoSigningPreparation';
import type { SignTransactionResult } from '@/core/types/seams';
import type { TransactionInputWasm } from '@/core/types/actions';
import {
  SENSITIVE_OPERATION_POLICIES,
  SIGNER_AUTH_METHODS,
  type SensitiveOperationPolicy,
  type SignerAuthMethod,
} from '@shared/utils/signerDomain';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type {
  NearEd25519MaterialIdentity,
  NearSigningApiDeps,
} from '../../interfaces/operationDeps';
import { signNearWithUiConfirm } from './nearSigningFlow';
import { resolveThresholdEd25519CommitQueueKey } from '../../threshold/ed25519/commitQueue';
import type { MpcMaterialActivationRef, ThresholdEd25519SessionId } from '@shared/utils/domainIds';
import {
  emailOtpAuthContextReason,
  emailOtpAuthContextRetention,
  type Ed25519LaneCandidate,
  type SelectedEd25519Lane,
} from '../../session/identity/laneIdentity';
import {
  signingLaneAuthBindingKey,
  signingLaneAuthMethod,
} from '../../session/identity/signingLaneAuthBinding';
import {
  exactEd25519SigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityKey,
  nearEd25519SignerBindingFromBoundaryFields,
} from '../../session/identity/exactSigningLaneIdentity';
import type { NearEd25519SignerBinding } from '@shared/utils/walletCapabilityBindings';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  AvailableSigningLanes,
  AvailableEd25519SigningLane,
} from '../../session/availability/availableSigningLanes';
import type { EmailOtpTransactionSigningChallenge } from '../../session/emailOtp/publicTypes';
import { demoEmailOtpCodeFromDelivery } from '../../session/emailOtp/challengeDelivery';
import {
  walletSessionFailureFromError,
  type WalletSessionFailure,
} from '../../session/lifecycle/walletSessionFailure';
import { requireAuthoritativeExpiredWalletSessionAuthorizationBoundary } from '../../session/identity/clientSessionPersistenceState';
import {
  SigningOperationIntent,
  SigningSessionPlanKind,
  SigningSessionIds,
  type ResolvedEd25519SigningSessionIdentity,
  type SigningOperationId,
} from '../../session/operationState/types';
import {
  buildNearTransactionSigningLane,
  type NearTransactionSigningLane,
} from '../../session/operationState/lanes';
import {
  toWalletId,
  type NearCommandSubject,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  buildWalletSessionQuotaAdmissionQueueKey,
  WalletSessionQuotaAdmissionError,
  classifyWalletSessionQuotaAdmissionFailure,
  decideWalletSessionQuotaAdmissionFailure,
  waitForWalletSessionQuotaAdmissionRetry,
} from '../../session/operationState/authorizationAdmission';
import type { RouterAbEd25519OwnerOperationAuthorizationDecisionV1Wire } from '@shared/utils/routerAbNormalSigningIdentity';

function nearOwnerOperationAuthorizationDecisionFromError(
  error: unknown,
): RouterAbEd25519OwnerOperationAuthorizationDecisionV1Wire | undefined {
  if (!(error instanceof WalletSessionQuotaAdmissionError)) return undefined;
  const decision = error.authorizationDecision;
  if (!decision || decision.kind !== 'step_up_required' || !('request_id' in decision.step_up)) {
    return undefined;
  }
  return {
    kind: 'step_up_required',
    reason: decision.reason,
    step_up: decision.step_up,
  };
}

function nearWalletSessionQuotaAdmissionDecisionFromError(error: unknown) {
  const ownerDecision = nearOwnerOperationAuthorizationDecisionFromError(error);
  const failure = classifyWalletSessionQuotaAdmissionFailure(error);
  if (ownerDecision) {
    return decideWalletSessionQuotaAdmissionFailure(
      failure ?? {
        kind: 'exhausted',
        source: 'server_prepare',
        detail: 'Server requires owner operation step-up',
      },
    );
  }
  return failure?.kind === 'in_flight' ? decideWalletSessionQuotaAdmissionFailure(failure) : null;
}
import type { WalletSessionStatusIdentity } from '../../session/lifecycle/walletSessionStatus';
import {} from '../../threshold/sessionPolicy';
import { signingAuthPlanFromSigningSessionPlan } from '../shared/signingConfirmation';
import { resolveNearSigningSessionAuthContext } from './shared/signingSessionAuthMode';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningLaneResolutionTrace,
  emitSigningPlannerDecisionTrace,
} from '../../session/operationState/trace';
import {
  type PreparedThresholdSigningOperation,
  type ThresholdSigningReadinessInput,
} from '../../session/operationState/preparedOperation';
import type { ResolvedRouterAbEd25519WalletSessionState } from '../../session/warmCapabilities/routerAbEd25519WalletSessionState';
import {
  receiveTransactionIntent,
  recordAvailableSigningLanesRead,
  selectNearEd25519MaterialCandidate,
  selectTransactionLaneFromAvailableLanes,
  type AuthorizationRequiredEd25519LaneCandidate,
  type NearEd25519TransactionSelectableAvailableLane,
  type NearEd25519TransactionSelectableLane,
  type TransactionLaneSelectedState,
} from '../../session/identity/selectLane';
import {
  classifyTransactionReadiness,
  prepareTransactionOperationFromReadiness,
  prepareTransactionSigningOperation,
  type NearEd25519TransactionSigningIntent,
  type NearEd25519TransactionSignerSelection,
  type PreparedTransactionOperation,
  type TransactionAuthSelectionPolicy,
  type TransactionSigningIntent,
  type TransactionReadiness,
  type TransactionReadinessClassifiedState,
} from '../../session/operationState/transactionState';
import { requiredNearTransactionSignatureUses } from './signatureUses';

async function invalidateAuthoritativeNearWalletSessionExpiry(args: {
  readonly failure: WalletSessionFailure | null;
  readonly coordinator: SigningSessionCoordinator;
  readonly lane: SelectedEd25519Lane;
  readonly expiresAtMs: unknown;
}): Promise<void> {
  if (args.failure?.kind !== 'expired') return;
  const state = requireAuthoritativeExpiredWalletSessionAuthorizationBoundary({
    source: {
      kind: 'ed25519',
      laneIdentity: exactEd25519SigningLaneIdentityFromSelectedLane(args.lane),
    },
    expiresAtMs: args.expiresAtMs,
    detectedAtMs: Date.now(),
  });
  const result = await args.coordinator.invalidateExpiredWalletSession({
    state,
    source: SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.serverRejection,
  });
  if (result.kind === 'unavailable') {
    throw new Error('[SigningEngine][near] expired Wallet Session cleanup failed');
  }
}

export type SignDelegateActionResult = {
  signedDelegate: WasmSignedDelegate;
  hash: string;
  nearAccountId: AccountId;
  logs?: string[];
};

export type SignNep413MessagePayload = {
  message: string;
  recipient: string;
  nonce: string;
  state: string | null;
  commandSubject: NearCommandSubject;
  signerSlot?: number;
  title?: string;
  body?: string;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
};

export type SignNep413MessageResult =
  | {
      success: true;
      accountId: string;
      publicKey: string;
      signature: string;
      state?: string;
      error?: never;
    }
  | {
      success: false;
      error: string;
      accountId?: never;
      publicKey?: never;
      signature?: never;
      state?: never;
    };

export type SignTransactionWithActionsInput = {
  commandSubject: NearCommandSubject;
  transaction: TransactionInputWasm;
  rpcCall: RpcCallPayload;
  signerSlot?: number;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  onEvent?: (update: SigningFlowEvent) => void;
  thresholdSessionId?: string;
  sensitivePolicy?: SensitiveOperationPolicy;
};

type NearTransactionPublicSigningOptions = Pick<
  SignTransactionWithActionsInput,
  'confirmationConfigOverride' | 'title' | 'body' | 'onEvent' | 'signerSlot'
>;

export type SignDelegateActionInput = {
  commandSubject: NearCommandSubject;
  delegate: DelegateActionInput;
  rpcCall: RpcCallPayload;
  signerSlot?: number;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  onEvent?: (update: SigningFlowEvent) => void;
};

export type NearSignIntentRequest =
  | {
      chain: 'near';
      kind: 'transactionWithActions';
      args: SignTransactionWithActionsInput;
    }
  | {
      chain: 'near';
      kind: 'delegateAction';
      args: SignDelegateActionInput;
    }
  | {
      chain: 'near';
      kind: 'nep413';
      args: SignNep413MessagePayload;
    };

export type NearSignIntentResultByKind = {
  transactionWithActions: SignTransactionResult;
  delegateAction: SignDelegateActionResult;
  nep413: SignNep413MessageResult;
};

export type NearSignIntentResult<TRequest extends NearSignIntentRequest> = TRequest extends {
  kind: infer TKind;
}
  ? TKind extends keyof NearSignIntentResultByKind
    ? NearSignIntentResultByKind[TKind]
    : never
  : never;

export async function signNear<TRequest extends NearSignIntentRequest>(
  deps: NearSigningApiDeps,
  request: TRequest,
): Promise<NearSignIntentResult<TRequest>> {
  if (request.kind === 'transactionWithActions') {
    return (await signTransactionWithActions(deps, request.args)) as NearSignIntentResult<TRequest>;
  }
  if (request.kind === 'delegateAction') {
    return (await signDelegateAction(deps, request.args)) as NearSignIntentResult<TRequest>;
  }
  if (request.kind === 'nep413') {
    return (await signNEP413Message(deps, request.args)) as NearSignIntentResult<TRequest>;
  }
  throw new Error(
    `[SigningEngine] unsupported near signing intent: ${String((request as { kind?: unknown }).kind || '')}`,
  );
}

type NearEd25519SelectedTransactionLane = TransactionLaneSelectedState<
  SelectedEd25519Lane,
  NearEd25519TransactionSelectableAvailableLane,
  Ed25519LaneCandidate,
  NearEd25519TransactionSelectableLane
>;

type PreparedNearEd25519TransactionSigningSession = {
  preparation: NearEd25519YaoSigningPreparation;
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
  transactionLane: SelectedEd25519Lane;
  identity: ResolvedEd25519SigningSessionIdentity;
  thresholdSessionId: ThresholdEd25519SessionId;
  availableLanesGeneration: number;
  preparedOperation: PreparedNearEd25519Operation;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
};

type PreparedNearTransactionExecutionState = {
  kind: 'prepared_near_transaction_execution';
  thresholdSessionId: ThresholdEd25519SessionId;
  signingSessionPlan: PreparedNearEd25519Operation['signingSessionPlan'];
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
  signingSessionCoordinator: SigningSessionCoordinator;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  passkeyEd25519OperationStepUp: NearPasskeyEd25519OperationStepUpHook | null;
  emailOtpEd25519StepUp: NearEmailOtpEd25519StepUpHook | null;
};

type NearEd25519LifecycleMetadata = {
  transactionLane: SelectedEd25519Lane;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  transactionReadinessState: TransactionReadinessClassifiedState;
  identity: ResolvedEd25519SigningSessionIdentity;
  availableLanesGeneration: number;
  readiness: ThresholdSigningReadinessInput;
};

type PreparedNearEd25519Operation = PreparedThresholdSigningOperation<
  NearTransactionSigningLane,
  NearEd25519LifecycleMetadata
>;

type NearEd25519TransactionOperationPrepareResult = {
  lane: NearTransactionSigningLane;
  transactionLane: SelectedEd25519Lane;
  transactionIntent: TransactionSigningIntent;
  readiness: ThresholdSigningReadinessInput;
  availableLanesGeneration: number;
  metadata: NearEd25519LifecycleMetadata;
};

function createNearTransactionSigningOperationId(): SigningOperationId {
  const randomId = secureRandomBase64Url(32, 'NEAR transaction signing operation IDs');
  return SigningSessionIds.signingOperation(`near-transaction-sign:${randomId}`);
}

function summarizeNearEd25519Lane(lane: AvailableEd25519SigningLane): Record<string, unknown> {
  if (lane.state === 'missing') {
    return {
      state: lane.state,
      curve: lane.curve,
      chain: lane.chain,
    };
  }
  return {
    authMethod: signingLaneAuthMethod(lane.auth),
    walletId: lane.walletId,
    nearAccountId: lane.nearAccountId,
    nearEd25519SigningKeyId: lane.nearEd25519SigningKeyId,
    signerSlot: lane.signerSlot,
    state: lane.state,
    source: lane.source || 'unknown',
    ...(lane.authorizationState === 'authorized'
      ? {
          walletSessionId: lane.authorization.operationCredential.walletSessionId,
          quotaId: lane.authorization.session.quotaId,
        }
      : {}),
    thresholdSessionId: lane.thresholdSessionId,
    remainingUses: lane.remainingUses,
    expiresAtMs: lane.expiresAtMs,
  };
}

function summarizeNearEd25519AvailableLanes(
  availableLanes: AvailableSigningLanes | null,
): Record<string, unknown> {
  const candidates = availableLanes?.candidates.ed25519.near || [];
  return {
    generation: availableLanes?.generation || 0,
    candidateCount: candidates.length,
    candidates: candidates.map(summarizeNearEd25519Lane),
  };
}

function emitNearSigningEvent(
  onEvent: ((event: SigningFlowEvent) => void) | undefined,
  accountId: AccountId | string,
  event: Omit<CreateSigningFlowEventInput, 'flowId' | 'accountId'>,
): void {
  try {
    onEvent?.(
      createSigningFlowEvent({
        ...event,
        flowId: `signing:near:${String(accountId)}:${event.phase}`,
        accountId: String(accountId),
      }),
    );
  } catch {}
}

function assertSigningLaneMatchesSelectedTransactionLane(args: {
  signingLane: NearTransactionSigningLane;
  transactionLane: SelectedEd25519Lane;
}): void {
  if (
    exactSigningLaneIdentityKey(args.signingLane.identity) !==
    exactSigningLaneIdentityKey(args.transactionLane.identity)
  ) {
    throw new Error(
      '[SigningEngine][near] prepared signing lane drifted from selected transaction lane',
    );
  }
}

function selectedEd25519LanesHaveSameSignerAndAuth(
  left: SelectedEd25519Lane,
  right: SelectedEd25519Lane,
): boolean {
  const leftSigner = left.identity.signer;
  const rightSigner = right.identity.signer;
  return (
    String(leftSigner.account.wallet.walletId) === String(rightSigner.account.wallet.walletId) &&
    String(leftSigner.account.nearAccountId) === String(rightSigner.account.nearAccountId) &&
    String(leftSigner.nearEd25519SigningKeyId) === String(rightSigner.nearEd25519SigningKeyId) &&
    leftSigner.signerSlot === rightSigner.signerSlot &&
    signingLaneAuthBindingKey(left.auth) === signingLaneAuthBindingKey(right.auth)
  );
}

function transactionReadinessFromPlannerInput(
  readiness: ThresholdSigningReadinessInput,
): TransactionReadiness {
  const status = readiness.readiness.status;
  if (status === 'ready') {
    return {
      status: 'ready',
      remainingUses: Math.max(0, Math.floor(Number(readiness.readiness.remainingUses) || 0)),
      expiresAtMs: Math.max(0, Math.floor(Number(readiness.readiness.expiresAtMs) || 0)),
    };
  }
  if (status === 'expired' || status === 'exhausted' || status === 'status_unknown') {
    return status === 'status_unknown'
      ? { status, reason: 'trusted wallet budget status is unavailable' }
      : { status };
  }
  if (status === 'auth_unavailable' || status === 'status_unavailable') {
    return { status, reason: status };
  }
  return { status: 'status_unavailable', reason: status };
}

function requireResolvedNearEd25519SigningLane(
  lane: NearTransactionSigningLane,
): ResolvedEd25519SigningSessionIdentity {
  if (lane.curve !== 'ed25519' || lane.keyKind !== 'threshold_ed25519') {
    throw new Error('[SigningEngine][near] prepared signing lane is not Ed25519');
  }
  if (lane.chainFamily !== 'near') {
    throw new Error('[SigningEngine][near] prepared Ed25519 lane must target NEAR');
  }
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  const walletSessionId = String(lane.walletSessionId || '').trim();
  const quotaId = String(lane.quotaId || '').trim();
  if (!thresholdSessionId || !walletSessionId || !quotaId) {
    throw new Error('[SigningEngine][near] prepared Ed25519 lane is missing session identity');
  }
  // Resolved lane metadata is copied from the executable lane so challenge, budget,
  // signing, and cleanup cannot rediscover or disagree about session metadata.
  return {
    ...lane,
    curve: 'ed25519',
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    walletSessionId: SigningSessionIds.walletSession(walletSessionId),
    quotaId: SigningSessionIds.walletSessionQuota(quotaId),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
  };
}

function walletSessionStatusIdentityFromNearPreparation(
  preparation: NearEd25519YaoSigningPreparation,
): WalletSessionStatusIdentity | null {
  if (preparation.authorization.kind !== 'authorized') return null;
  const authorization = preparation.authorization.authorization;
  return {
    walletSessionId: authorization.operationCredential.walletSessionId,
    quotaId: authorization.session.quotaId,
  };
}

async function resolveNearTransactionWalletAuth(args: {
  commandSubject: NearCommandSubject;
  preparedOperation: PreparedNearEd25519Operation;
}): Promise<{
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
}> {
  const preparedOperation = args.preparedOperation;
  const lane = preparedOperation.lane;
  emitSigningLaneResolutionTrace('near', lane, {
    reason: 'near_transaction_auth_planning',
  });

  const nearAccountId = args.commandSubject.nearAccount.accountId;
  const authInput = {
    accountId: nearAccountId,
    intent: SigningOperationIntent.TransactionSign,
    curve: 'ed25519' as const,
  };
  const plan = preparedOperation.signingSessionPlan;
  if (plan.kind === SigningSessionPlanKind.NotReady) {
    console.warn('[SigningEngine][near][ed25519] transaction auth planning not ready', {
      nearAccountId,
      authMethod: signingLaneAuthMethod(lane.auth),
      reason: plan.reason,
      readiness: preparedOperation.readiness.status,
      walletSessionId: lane.walletSessionId,
      quotaId: lane.quotaId,
      thresholdSessionId: lane.thresholdSessionId,
      retention: lane.retention,
      remainingUses: preparedOperation.remainingUses,
      expiresAtMs: preparedOperation.expiresAtMs,
    });
    if (plan.reason === 'policy_blocked') {
      throw new Error(
        '[SigningEngine] NEAR operation requires passkey authentication after Email OTP login',
      );
    }
    throw new Error(`[SigningEngine][near] signing session is not ready: ${plan.reason}`);
  }
  const signingAuthPlan = signingAuthPlanFromSigningSessionPlan({
    plan,
    accountId: authInput.accountId,
    intent: authInput.intent,
    curve: authInput.curve,
    expiresAtMs: preparedOperation.expiresAtMs,
    remainingUses: preparedOperation.remainingUses,
  });
  return {
    signingAuthPlan,
    signingLane: lane,
  };
}

function resolvePreparedSigningRequestSessionId(args: {
  providedThresholdSessionId?: string;
  identity: ResolvedEd25519SigningSessionIdentity;
}): string {
  const provided = String(args.providedThresholdSessionId || '').trim();
  const prepared = String(args.identity.thresholdSessionId || '').trim();
  if (provided && provided !== prepared) {
    throw new Error(
      '[SigningEngine][near] transaction thresholdSessionId must match prepared Ed25519 identity',
    );
  }
  return prepared;
}

function nearEd25519PreparationRequiresAuthorization(
  preparation: NearEd25519YaoSigningPreparation,
): boolean {
  switch (preparation.authorization.kind) {
    case 'authorized':
      return false;
    case 'authorization_required':
      return true;
    default:
      preparation.authorization satisfies never;
      throw new Error('[SigningEngine][near] unsupported material authorization state');
  }
}

function requireNearReusableAuthorizationExpiry(
  preparation: NearEd25519YaoSigningPreparation,
): number {
  if (preparation.authorization.kind !== 'authorized') {
    throw new Error('[SigningEngine][near] reusable Wallet Session authorization is unavailable');
  }
  return preparation.authorization.authorization.status.expiresAtMs;
}

async function prepareNearEd25519YaoMaterialBoundary(
  args:
    | {
        deps: NearSigningApiDeps;
        commandSubject: NearCommandSubject;
        selectedLane: SelectedEd25519Lane;
        materialIdentity?: never;
      }
    | {
        deps: NearSigningApiDeps;
        commandSubject: NearCommandSubject;
        selectedLane?: never;
        materialIdentity: NearEd25519MaterialIdentity;
      },
) {
  const base = {
    walletId: toWalletId(args.commandSubject.walletSession.walletId),
    nearAccountId: toAccountId(args.commandSubject.nearAccount.accountId),
  };
  if (args.materialIdentity) {
    return await args.deps.prepareNearEd25519YaoMaterialBoundary({
      ...base,
      materialIdentity: args.materialIdentity,
    });
  }
  return await args.deps.prepareNearEd25519YaoMaterialBoundary({
    ...base,
    laneIdentity: args.selectedLane.identity,
    auth: args.selectedLane.auth,
  });
}

function createAdHocNearSigningOperationId(
  deps: NearSigningApiDeps,
  kind: 'delegate' | 'nep413',
): SigningOperationId {
  return SigningSessionIds.signingOperation(deps.createSigningSessionId(`near-${kind}-operation`));
}

type NearAdHocSigningAttempt =
  | {
      kind: 'initial';
      forceFreshAuth: false;
    }
  | {
      kind: 'fresh_auth_retry';
      forceFreshAuth: true;
    };

type PreparedNearAdHocSigningSession =
  | {
      kind: 'authorized';
      selectedLane: SelectedEd25519Lane;
      candidate?: never;
      materialIdentity?: never;
      forceFreshAuth: boolean;
      passkeyEd25519OperationStepUp: NearPasskeyEd25519OperationStepUpHook | null;
      emailOtpEd25519StepUp: NearEmailOtpEd25519StepUpHook | null;
      yaoSigningPreparation: NearEd25519YaoSigningPreparation;
      yaoMaterialExecutor: NearEd25519YaoMaterialExecutor;
    }
  | {
      kind: 'authorization_required';
      selectedLane?: never;
      candidate: AuthorizationRequiredEd25519LaneCandidate;
      materialIdentity: NearEd25519MaterialIdentity;
      forceFreshAuth: true;
      passkeyEd25519OperationStepUp: NearPasskeyEd25519OperationStepUpHook | null;
      emailOtpEd25519StepUp: NearEmailOtpEd25519StepUpHook | null;
      yaoSigningPreparation: NearEd25519YaoSigningPreparation;
      yaoMaterialExecutor: NearEd25519YaoMaterialExecutor;
    };

function buildPreparedNearTransactionExecutionState(args: {
  preparedSigningSession: PreparedNearEd25519TransactionSigningSession;
  thresholdSessionId: ThresholdEd25519SessionId;
  signingSessionCoordinator: SigningSessionCoordinator;
  passkeyEd25519OperationStepUp: NearPasskeyEd25519OperationStepUpHook | null;
  emailOtpEd25519StepUp: NearEmailOtpEd25519StepUpHook | null;
}): PreparedNearTransactionExecutionState {
  return {
    kind: 'prepared_near_transaction_execution',
    thresholdSessionId: args.thresholdSessionId,
    signingSessionPlan: args.preparedSigningSession.preparedOperation.signingSessionPlan,
    signingAuthPlan: args.preparedSigningSession.signingAuthPlan,
    signingLane: args.preparedSigningSession.signingLane,
    signingSessionCoordinator: args.signingSessionCoordinator,
    transactionOperation: args.preparedSigningSession.transactionOperation,
    passkeyEd25519OperationStepUp: args.passkeyEd25519OperationStepUp,
    emailOtpEd25519StepUp: args.emailOtpEd25519StepUp,
  };
}

function nearEd25519WalletSessionQuotaAdmissionQueueKey(args: {
  walletId: WalletId | string;
  nearAccountId: AccountId | string;
  prepared: PreparedNearEd25519TransactionSigningSession;
}): ReturnType<typeof buildWalletSessionQuotaAdmissionQueueKey> {
  return buildWalletSessionQuotaAdmissionQueueKey({
    walletId: String(args.walletId),
    curve: 'ed25519',
    walletSessionId: String(args.prepared.signingLane.walletSessionId),
    quotaId: String(args.prepared.signingLane.quotaId),
    projectionVersion: 'server-owned',
    authorityKey: signingLaneAuthBindingKey(args.prepared.signingLane.auth),
    targetKey: `near:${String(args.nearAccountId)}`,
  });
}

function nearAdHocEd25519WalletSessionQuotaAdmissionQueueKey(args: {
  walletId: WalletId | string;
  nearAccountId: AccountId | string;
  prepared: PreparedNearAdHocSigningSession;
}): ReturnType<typeof buildWalletSessionQuotaAdmissionQueueKey> {
  if (args.prepared.kind !== 'authorized') {
    throw new Error('[SigningEngine][near] deferred Ed25519 material has no reusable session');
  }
  return buildWalletSessionQuotaAdmissionQueueKey({
    walletId: String(args.walletId),
    curve: 'ed25519',
    walletSessionId: String(args.prepared.selectedLane.walletSessionId),
    quotaId: String(args.prepared.selectedLane.quotaId),
    projectionVersion: 'projection-unadmitted',
    authorityKey: signingLaneAuthBindingKey(args.prepared.selectedLane.auth),
    targetKey: `near:${String(args.nearAccountId)}`,
  });
}

function buildNearPasskeyEd25519OperationStepUp(args: {
  auth: Ed25519LaneCandidate['auth'];
  signer: NearEd25519SignerBinding;
  preparation: NearEd25519YaoSigningPreparation;
  materialExecutor: NearEd25519YaoMaterialExecutor;
}): NearPasskeyEd25519OperationStepUpHook | undefined {
  if (args.auth.kind !== 'passkey') return undefined;
  const auth = args.auth;
  return {
    prepare: async () => {
      const materialFacts = await resolveNearPasskeyStepUpMaterialFacts({
        preparation: args.preparation,
        executor: args.materialExecutor,
      });
      const signer = args.signer;
      const thresholdSessionId = materialFacts.thresholdSessionId;
      const authority = await exactPasskeyStepUpAuthority({
        authorityRef: nearPasskeyPreparationAuthority(args.preparation),
        walletId: signer.account.wallet.walletId,
        rpId: auth.rpId,
        credentialIdB64u: auth.credentialIdB64u,
      });
      return {
        thresholdSessionId,
        authority,
      };
    },
  };
}

function nearPasskeyPreparationAuthority(
  preparation: NearEd25519YaoSigningPreparation,
): WalletAuthAuthorityRef {
  switch (preparation.hydration.kind) {
    case 'use_live_runtime':
    case 'rehydrate_material_activation':
    case 'reauthorize_public_anchor':
      return preparation.hydration.authority;
    case 'blocked':
      throw new Error('[SigningEngine][near] blocked Passkey material has no authority');
    default:
      preparation.hydration satisfies never;
      throw new Error('[SigningEngine][near] unsupported Passkey material authority');
  }
}

async function exactPasskeyStepUpAuthority(args: {
  authorityRef: WalletAuthAuthorityRef;
  walletId: unknown;
  rpId: unknown;
  credentialIdB64u: unknown;
}): Promise<PasskeyWalletAuthAuthority> {
  const authority = parsePasskeyWalletAuthAuthority({
    walletId: args.walletId,
    factor: {
      kind: 'passkey',
      credentialIdB64u: args.credentialIdB64u,
    },
    verifier: {
      kind: 'webauthn',
      rpId: args.rpId,
    },
    bindingId: args.authorityRef.walletAuthMethodId,
  });
  if (!authority) {
    throw new Error('[SigningEngine][near] exact Passkey step-up authority is invalid');
  }
  const resolvedRef = await walletAuthAuthorityRef({ authority });
  if (
    resolvedRef.walletId !== args.authorityRef.walletId ||
    resolvedRef.walletAuthMethodId !== args.authorityRef.walletAuthMethodId ||
    resolvedRef.authorityDigest !== args.authorityRef.authorityDigest
  ) {
    throw new Error('[SigningEngine][near] exact Passkey step-up authority changed');
  }
  return authority;
}

async function resolveNearPasskeyStepUpMaterialFacts(args: {
  preparation: NearEd25519YaoSigningPreparation;
  executor: NearEd25519YaoMaterialExecutor;
}): Promise<NearEd25519YaoOperationMaterialFacts> {
  switch (args.preparation.hydration.kind) {
    case 'use_live_runtime': {
      const material = await args.executor.resolve(args.preparation);
      return material.facts;
    }
    case 'rehydrate_material_activation': {
      const prepared = await args.executor.preparePasskeyOperationStepUp(args.preparation);
      return prepared.facts;
    }
    case 'reauthorize_public_anchor':
      throw new Error('[SigningEngine][near] retired material cannot prepare Passkey step-up');
    case 'blocked':
      throw new Error(
        `[SigningEngine][near] Passkey step-up material is blocked: ${args.preparation.hydration.reason}`,
      );
    default:
      args.preparation.hydration satisfies never;
      throw new Error('[SigningEngine][near] unsupported Passkey step-up material source');
  }
}

function buildNearEmailOtpEd25519StepUp(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  auth: Ed25519LaneCandidate['auth'];
  signer: NearEd25519SignerBinding;
  preparation: NearEd25519YaoSigningPreparation;
  onEvent: SignTransactionWithActionsInput['onEvent'];
}): NearEmailOtpEd25519StepUpHook | undefined {
  if (
    args.auth.kind !== SIGNER_AUTH_METHODS.emailOtp ||
    typeof args.deps.requestEmailOtpEd25519SigningChallenge !== 'function'
  ) {
    return undefined;
  }
  const expectedActivation = args.preparation.hydration.materialActivation;
  if (!expectedActivation) {
    return undefined;
  }
  if (
    String(args.signer.account.wallet.walletId) !==
      String(args.commandSubject.walletSession.walletId) ||
    String(args.signer.account.nearAccountId) !== String(args.commandSubject.nearAccount.accountId)
  ) {
    throw new Error('[SigningEngine][near] Email OTP step-up lane changed subject');
  }
  const requestChallenge = async (challengeArgs: {
    operationFingerprintDigest: DigestB64u;
  }): Promise<EmailOtpTransactionSigningChallenge> => {
    const challenge = await args.deps.requestEmailOtpEd25519SigningChallenge!({
      walletSession: args.commandSubject.walletSession,
      operationFingerprintDigest: challengeArgs.operationFingerprintDigest,
    });
    emitNearSigningEvent(args.onEvent, args.commandSubject.nearAccount.accountId, {
      phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED,
      status: 'waiting_for_user',
      interaction: { kind: 'otp_input', overlay: 'show' },
      data: {
        emailHint: challenge.emailHint,
        demoOtpCode: demoEmailOtpCodeFromDelivery(challenge.delivery),
      },
    });
    return challenge;
  };
  return {
    prepare: requestChallenge,
    resend: requestChallenge,
  };
}

async function prepareNearAdHocSigningSession(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  signerSlot: number | undefined;
  operationId: SigningOperationId;
  onEvent: SignTransactionWithActionsInput['onEvent'];
  attempt: NearAdHocSigningAttempt;
}): Promise<PreparedNearAdHocSigningSession> {
  const availableLanes = await readNearEd25519AvailableSigningLanes({
    deps: args.deps,
    commandSubject: args.commandSubject,
    authMethod: null,
  });
  const materialSelection = selectNearEd25519MaterialCandidate({
    availableLanes,
    intent: nearEd25519TransactionSigningIntent({
      commandSubject: args.commandSubject,
      signerSlot: args.signerSlot,
      authSelectionPolicy: { kind: 'any' },
      operationUsesNeeded: 1,
    }),
  });
  if (!materialSelection.ok) {
    throw new Error('[SigningEngine][near] signature-only signing requires exact Ed25519 material');
  }
  if (materialSelection.kind === 'authorization_required') {
    const candidate = materialSelection.candidate;
    const signer = nearEd25519SignerBindingFromBoundaryFields({
      walletId: candidate.walletId,
      nearAccountId: candidate.nearAccountId,
      nearEd25519SigningKeyId: candidate.nearEd25519SigningKeyId,
      signerSlot: candidate.signerSlot,
    });
    const materialIdentity: NearEd25519MaterialIdentity = {
      kind: 'near_ed25519_material_identity',
      signer,
      auth: candidate.auth,
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(candidate.thresholdSessionId),
    };
    const materialBoundary = await prepareNearEd25519YaoMaterialBoundary({
      deps: args.deps,
      commandSubject: args.commandSubject,
      materialIdentity,
    });
    const passkeyEd25519OperationStepUp =
      buildNearPasskeyEd25519OperationStepUp({
        auth: candidate.auth,
        signer,
        preparation: materialBoundary.preparation,
        materialExecutor: materialBoundary.executor,
      }) || null;
    const emailOtpEd25519StepUp =
      buildNearEmailOtpEd25519StepUp({
        deps: args.deps,
        commandSubject: args.commandSubject,
        auth: candidate.auth,
        signer,
        preparation: materialBoundary.preparation,
        onEvent: args.onEvent,
      }) || null;
    return {
      kind: 'authorization_required',
      candidate,
      materialIdentity,
      forceFreshAuth: true,
      passkeyEd25519OperationStepUp,
      emailOtpEd25519StepUp,
      yaoSigningPreparation: materialBoundary.preparation,
      yaoMaterialExecutor: materialBoundary.executor,
    };
  }
  const selectedLane = materialSelection.lane;
  const materialBoundary = await prepareNearEd25519YaoMaterialBoundary({
    deps: args.deps,
    commandSubject: args.commandSubject,
    selectedLane,
  });
  const forceFreshAuth =
    args.attempt.forceFreshAuth ||
    nearEd25519PreparationRequiresAuthorization(materialBoundary.preparation);
  const passkeyEd25519OperationStepUp =
    buildNearPasskeyEd25519OperationStepUp({
      auth: selectedLane.auth,
      signer: selectedLane.identity.signer,
      preparation: materialBoundary.preparation,
      materialExecutor: materialBoundary.executor,
    }) || null;
  const emailOtpEd25519StepUp =
    buildNearEmailOtpEd25519StepUp({
      deps: args.deps,
      commandSubject: args.commandSubject,
      auth: selectedLane.auth,
      signer: selectedLane.identity.signer,
      preparation: materialBoundary.preparation,
      onEvent: args.onEvent,
    }) || null;
  return {
    kind: 'authorized' as const,
    selectedLane,
    forceFreshAuth,
    passkeyEd25519OperationStepUp,
    emailOtpEd25519StepUp,
    yaoSigningPreparation: materialBoundary.preparation,
    yaoMaterialExecutor: materialBoundary.executor,
  };
}

async function withThresholdEd25519CommitQueue<T>(args: {
  deps: NearSigningApiDeps;
  nearAccountId: AccountId;
  materialActivation: MpcMaterialActivationRef;
  task: () => Promise<T>;
}): Promise<T> {
  const queueKey = resolveThresholdEd25519CommitQueueKey({
    materialActivation: args.materialActivation,
  });
  return await args.deps.withThresholdEd25519CommitQueue({
    queueKey,
    nearAccountId: args.nearAccountId,
    enabled: true,
    task: args.task,
  });
}

async function prepareNearAuthorizationRequiredTransaction(args: {
  deps: NearSigningApiDeps;
  input: SignTransactionWithActionsInput;
  commandSubject: NearCommandSubject;
  operationId: SigningOperationId;
}): Promise<{
  candidate: AuthorizationRequiredEd25519LaneCandidate;
  preparation: NearEd25519YaoSigningPreparation;
  executor: NearEd25519YaoMaterialExecutor;
  passkeyEd25519OperationStepUp: NearPasskeyEd25519OperationStepUpHook | null;
  emailOtpEd25519StepUp: NearEmailOtpEd25519StepUpHook | null;
} | null> {
  const availableLanes = await readNearEd25519AvailableSigningLanes({
    deps: args.deps,
    commandSubject: args.commandSubject,
    authMethod: null,
  });
  const materialSelection = selectNearEd25519MaterialCandidate({
    availableLanes,
    intent: nearEd25519TransactionSigningIntent({
      commandSubject: args.commandSubject,
      signerSlot: args.input.signerSlot,
      authSelectionPolicy: { kind: 'any' },
      operationUsesNeeded: requiredNearTransactionSignatureUses(args.input.transaction),
    }),
  });
  if (!materialSelection.ok || materialSelection.kind !== 'authorization_required') {
    return null;
  }
  const candidate = materialSelection.candidate;
  const signer = nearEd25519SignerBindingFromBoundaryFields({
    walletId: candidate.walletId,
    nearAccountId: candidate.nearAccountId,
    nearEd25519SigningKeyId: candidate.nearEd25519SigningKeyId,
    signerSlot: candidate.signerSlot,
  });
  const materialIdentity: NearEd25519MaterialIdentity = {
    kind: 'near_ed25519_material_identity',
    signer,
    auth: candidate.auth,
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(candidate.thresholdSessionId),
  };
  const materialBoundary = await prepareNearEd25519YaoMaterialBoundary({
    deps: args.deps,
    commandSubject: args.commandSubject,
    materialIdentity,
  });
  return {
    candidate,
    preparation: materialBoundary.preparation,
    executor: materialBoundary.executor,
    passkeyEd25519OperationStepUp:
      buildNearPasskeyEd25519OperationStepUp({
        auth: candidate.auth,
        signer,
        preparation: materialBoundary.preparation,
        materialExecutor: materialBoundary.executor,
      }) || null,
    emailOtpEd25519StepUp:
      buildNearEmailOtpEd25519StepUp({
        deps: args.deps,
        commandSubject: args.commandSubject,
        auth: candidate.auth,
        signer,
        preparation: materialBoundary.preparation,
        onEvent: args.input.onEvent,
      }) || null,
  };
}

function requireNearEd25519CommitMaterialActivation(
  preparation: NearEd25519YaoSigningPreparation,
): MpcMaterialActivationRef {
  switch (preparation.hydration.kind) {
    case 'use_live_runtime':
    case 'rehydrate_material_activation':
      return preparation.hydration.materialActivation;
    case 'reauthorize_public_anchor':
      throw new Error(
        '[SigningEngine][near] retired public material cannot enter the material commit queue',
      );
    case 'blocked':
      throw new Error(
        `[SigningEngine][near] blocked material cannot enter the material commit queue: ${preparation.hydration.reason}`,
      );
  }
  preparation.hydration satisfies never;
  throw new Error('[SigningEngine][near] unsupported material hydration plan');
}

function selectNearEd25519TransactionCandidate(args: {
  availableLanes: AvailableSigningLanes | null;
  authSelectionPolicy: TransactionAuthSelectionPolicy | null;
  commandSubject: NearCommandSubject;
  signerSlot: number | undefined;
  operationUsesNeeded: number;
}): NearEd25519SelectedTransactionLane | null {
  const authSelectionPolicy = args.authSelectionPolicy || null;
  if (!authSelectionPolicy) return null;

  const intentState = receiveTransactionIntent(
    nearEd25519TransactionSigningIntent({
      commandSubject: args.commandSubject,
      signerSlot: args.signerSlot,
      authSelectionPolicy,
      operationUsesNeeded: args.operationUsesNeeded,
    }),
  );
  const availableLanesState = recordAvailableSigningLanesRead(intentState, {
    availableLanes: args.availableLanes,
  });
  const selectionState = selectTransactionLaneFromAvailableLanes(availableLanesState);
  if (selectionState.tag === 'LaneSelected') {
    if (
      selectionState.lane.curve !== 'ed25519' ||
      selectionState.availableLane.curve !== 'ed25519'
    ) {
      throw new Error('[SigningEngine][near] Ed25519 selector returned a non-Ed25519 lane');
    }
    return selectionState as NearEd25519SelectedTransactionLane;
  }
  if (selectionState.failure.kind === 'no_candidate') return null;
  throw new Error(
    `[SigningEngine][near] Ed25519 transaction lane selection failed: ${selectionState.failure.kind}`,
  );
}

function nearEd25519TransactionSigningIntent(args: {
  commandSubject: NearCommandSubject;
  signerSlot: number | undefined;
  authSelectionPolicy: TransactionAuthSelectionPolicy;
  operationUsesNeeded: number;
}): NearEd25519TransactionSigningIntent {
  return {
    walletId: toWalletId(args.commandSubject.walletSession.walletId),
    curve: 'ed25519',
    chain: 'near',
    signerSelection: nearEd25519TransactionSignerSelection({
      nearAccountId: args.commandSubject.nearAccount.accountId,
      signerSlot: args.signerSlot,
    }),
    authSelectionPolicy: args.authSelectionPolicy,
    operationUsesNeeded: args.operationUsesNeeded,
  };
}

function nearEd25519TransactionSignerSelection(args: {
  nearAccountId: AccountId;
  signerSlot: number | undefined;
}): NearEd25519TransactionSignerSelection {
  if (args.signerSlot === undefined) {
    return {
      kind: 'near_account',
      nearAccountId: args.nearAccountId,
    };
  }
  const signerSlot = parseSignerSlot(args.signerSlot);
  if (signerSlot === null) {
    throw new Error('[SigningEngine][near] signerSlot must be a positive safe integer');
  }
  return {
    kind: 'signer_slot',
    nearAccountId: args.nearAccountId,
    signerSlot,
  };
}

function selectSelectedEd25519LaneFromAvailableLanes(args: {
  commandSubject: NearCommandSubject;
  availableLanes: AvailableSigningLanes | null;
  signerSlot: number | undefined;
  operationUsesNeeded: number;
}): NearEd25519SelectedTransactionLane | null {
  return selectNearEd25519TransactionCandidate({
    availableLanes: args.availableLanes,
    authSelectionPolicy: { kind: 'any' },
    commandSubject: args.commandSubject,
    signerSlot: args.signerSlot,
    operationUsesNeeded: args.operationUsesNeeded,
  });
}

async function readNearEd25519AvailableSigningLanes(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  authMethod: SignerAuthMethod | null;
}): Promise<AvailableSigningLanes | null> {
  const nearAccountId = args.commandSubject.nearAccount.accountId;
  const walletId = args.commandSubject.walletSession.walletId;
  if (typeof args.deps.readAvailableSigningLanesForSigning !== 'function') {
    throw new Error(
      '[SigningEngine][near] transaction signing requires available signing lanes reader',
    );
  }
  const ownerScope = await args.deps.resolveOwnerLaneScope(walletId);
  return await args.deps
    .readAvailableSigningLanesForSigning({
      walletId,
      curve: 'ed25519',
      ownerScope,
      ...(args.authMethod ? { authMethod: args.authMethod } : {}),
    })
    .catch((error) => {
      console.warn('[SigningEngine][near] available signing lanes read failed', {
        nearAccountId,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
      return null;
    });
}

async function prepareNearEd25519TransactionOperation(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  signingSessionCoordinator: SigningSessionCoordinator;
  availableLanes?: AvailableSigningLanes | null;
  selectedLane: NearEd25519SelectedTransactionLane;
  preparation: NearEd25519YaoSigningPreparation;
  forceFreshAuth: boolean;
  operationUsesNeeded: number;
}): Promise<NearEd25519TransactionOperationPrepareResult> {
  const nearAccountId = args.commandSubject.nearAccount.accountId;
  const operationUsesNeeded = Math.max(1, Math.floor(Number(args.operationUsesNeeded) || 1));
  const selectedSessionLane = args.selectedLane.lane;
  const authContext = resolveNearSigningSessionAuthContext({
    commandSubject: args.commandSubject,
    selectedLane: selectedSessionLane,
    preparation: args.preparation,
    forceFreshAuth: args.forceFreshAuth,
    requiredSignatureUses: operationUsesNeeded,
  });
  const lane = authContext.lane;
  assertSigningLaneMatchesSelectedTransactionLane({
    signingLane: lane,
    transactionLane: args.selectedLane.lane,
  });
  const readiness = {
    readiness: authContext.coordinatorInput.readiness,
    expiresAtMs: authContext.coordinatorInput.expiresAtMs,
    remainingUses: authContext.coordinatorInput.remainingUses,
  };
  if (selectedSessionLane.auth.kind === 'email_otp' && readiness.readiness.status !== 'ready') {
    console.warn('[SigningEngine][near][email-otp] Ed25519 pre-confirm readiness is not ready', {
      nearAccountId,
      readiness: readiness.readiness.status,
      thresholdSessionId: selectedSessionLane.thresholdSessionId,
      walletSessionId: selectedSessionLane.walletSessionId,
      quotaId: selectedSessionLane.quotaId,
      retention: lane.retention,
      remainingUses: readiness.remainingUses,
      expiresAtMs: readiness.expiresAtMs,
      requiredSignatureUses: operationUsesNeeded,
    });
  }
  emitSigningBoundaryTrace(
    'near',
    createSigningBoundaryTraceEvent({
      event: 'pre_confirm_readiness_checked',
      lane,
      readinessStatus: readiness.readiness.status,
      phase: 'pre_confirm',
    }),
  );
  const transactionReadinessState = classifyTransactionReadiness(
    args.selectedLane,
    transactionReadinessFromPlannerInput({
      readiness: readiness.readiness,
      expiresAtMs: readiness.expiresAtMs,
      remainingUses: readiness.remainingUses,
      usesNeeded: operationUsesNeeded,
    }),
  );
  const transactionOperation = prepareTransactionOperationFromReadiness(transactionReadinessState);
  const identity = requireResolvedNearEd25519SigningLane(lane);
  const trustedStatusAuth = walletSessionStatusIdentityFromNearPreparation(args.preparation);
  const readinessInput = {
    readiness: readiness.readiness,
    expiresAtMs: readiness.expiresAtMs,
    remainingUses: readiness.remainingUses,
    usesNeeded: operationUsesNeeded,
    ...(trustedStatusAuth ? { trustedStatusAuth } : {}),
  };
  return {
    lane,
    transactionLane: args.selectedLane.lane,
    transactionIntent: args.selectedLane.intent,
    readiness: readinessInput,
    availableLanesGeneration: args.availableLanes?.generation || 0,
    metadata: {
      transactionLane: args.selectedLane.lane,
      transactionOperation,
      transactionReadinessState,
      identity,
      availableLanesGeneration: args.availableLanes?.generation || 0,
      readiness: readinessInput,
    },
  };
}

async function prepareNearEd25519TransactionSigningSession(args: {
  deps: NearSigningApiDeps;
  input: SignTransactionWithActionsInput;
  commandSubject: NearCommandSubject;
  signingSessionCoordinator: SigningSessionCoordinator;
  operationId: SigningOperationId;
  forceFreshAuth?: boolean;
}): Promise<PreparedNearEd25519TransactionSigningSession> {
  const nearAccountId = args.commandSubject.nearAccount.accountId;
  const operationUsesNeeded = requiredNearTransactionSignatureUses(args.input.transaction);
  let availableLanes = await readNearEd25519AvailableSigningLanes({
    deps: args.deps,
    commandSubject: args.commandSubject,
    authMethod: null,
  });
  let selectedLane = selectSelectedEd25519LaneFromAvailableLanes({
    commandSubject: args.commandSubject,
    availableLanes,
    signerSlot: args.input.signerSlot,
    operationUsesNeeded,
  });
  if (!selectedLane) {
    console.warn(
      `[SigningEngine][near][ed25519] exact transaction lane selection failed ${JSON.stringify({
        nearAccountId,
        signerSlot: args.input.signerSlot ?? null,
        requiredSignatureUses: operationUsesNeeded,
        availableLanes: summarizeNearEd25519AvailableLanes(availableLanes),
      })}`,
    );
    throw new Error(
      '[SigningEngine][near] Ed25519 transaction signing requires an exact selected lane',
    );
  }
  const initialAuthSelectionPolicy: TransactionAuthSelectionPolicy = {
    kind: 'account_class',
    authMethod: signingLaneAuthMethod(selectedLane.lane.auth),
  };
  const initialMaterialBoundary = await prepareNearEd25519YaoMaterialBoundary({
    deps: args.deps,
    commandSubject: args.commandSubject,
    selectedLane: selectedLane.lane,
  });
  if (initialMaterialBoundary.preparation.authorization.kind === 'authorized') {
    const authorization = initialMaterialBoundary.preparation.authorization.authorization;
    if (
      selectedLane.lane.walletSessionId !== authorization.operationCredential.walletSessionId ||
      selectedLane.lane.quotaId !== authorization.session.quotaId
    ) {
      availableLanes = await readNearEd25519AvailableSigningLanes({
        deps: args.deps,
        commandSubject: args.commandSubject,
        authMethod: signingLaneAuthMethod(selectedLane.lane.auth),
      });
      const refreshedLane = selectSelectedEd25519LaneFromAvailableLanes({
        commandSubject: args.commandSubject,
        availableLanes,
        signerSlot: args.input.signerSlot,
        operationUsesNeeded,
      });
      if (
        !refreshedLane ||
        !selectedEd25519LanesHaveSameSignerAndAuth(selectedLane.lane, refreshedLane.lane) ||
        refreshedLane.lane.walletSessionId !== authorization.operationCredential.walletSessionId ||
        refreshedLane.lane.quotaId !== authorization.session.quotaId
      ) {
        throw new Error(
          '[SigningEngine][near] material restoration changed the Wallet Session without an exact refreshed lane',
        );
      }
      selectedLane = refreshedLane;
    }
  }
  const forceFreshAuth =
    args.forceFreshAuth === true ||
    nearEd25519PreparationRequiresAuthorization(initialMaterialBoundary.preparation);

  const preparedTransaction = await prepareTransactionSigningOperation({
    intent: nearEd25519TransactionSigningIntent({
      commandSubject: args.commandSubject,
      signerSlot: args.input.signerSlot,
      authSelectionPolicy: initialAuthSelectionPolicy,
      operationUsesNeeded,
    }),
    coordinator: args.signingSessionCoordinator,
    forceFreshAuth,
    sensitiveOperationPolicy:
      args.input.sensitivePolicy || SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy,
    onPlannerTrace: (event) => emitSigningPlannerDecisionTrace('near', event),
    lifecycleAdapter: {
      prepare: async () => {
        const lifecycle = await prepareNearEd25519TransactionOperation({
          deps: args.deps,
          commandSubject: args.commandSubject,
          signingSessionCoordinator: args.signingSessionCoordinator,
          availableLanes,
          selectedLane,
          preparation: initialMaterialBoundary.preparation,
          forceFreshAuth,
          operationUsesNeeded,
        });
        return {
          ...lifecycle,
          metadata: lifecycle.metadata,
        };
      },
    },
  });
  const preparedOperation = preparedTransaction.thresholdOperation as PreparedNearEd25519Operation;
  const transactionOperation = preparedTransaction.transactionOperation;
  const signingLane = preparedOperation.lane;
  const transactionLane = transactionOperation.lane;
  const identity = preparedOperation.metadata.identity;

  const { signingAuthPlan } = await resolveNearTransactionWalletAuth({
    commandSubject: args.commandSubject,
    preparedOperation,
  });
  return {
    preparation: initialMaterialBoundary.preparation,
    signingAuthPlan,
    signingLane,
    transactionLane,
    identity,
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
      resolvePreparedSigningRequestSessionId({
        providedThresholdSessionId: args.input.thresholdSessionId,
        identity,
      }),
    ),
    availableLanesGeneration: preparedOperation.availableLanesGeneration,
    preparedOperation,
    transactionOperation,
  };
}

export async function signTransactionWithActions(
  deps: NearSigningApiDeps,
  args: SignTransactionWithActionsInput,
  attempt: {
    forceFreshAuth?: boolean;
    operationId?: SigningOperationId;
    retryingFreshAuth?: boolean;
    signingSessionCoordinator?: SigningSessionCoordinator;
  } = {},
): Promise<SignTransactionResult> {
  const nearAccount = args.commandSubject.nearAccount;
  const nearAccountId = toAccountId(nearAccount.accountId);
  const publicOptions: NearTransactionPublicSigningOptions = {
    signerSlot: args.signerSlot,
    confirmationConfigOverride: args.confirmationConfigOverride,
    title: args.title,
    body: args.body,
    onEvent: args.onEvent,
  };
  let operationId = attempt.operationId;
  const ensureOperationId = (): SigningOperationId => {
    operationId = operationId || createNearTransactionSigningOperationId();
    return operationId;
  };
  const confirmationOperationId = ensureOperationId();
  const signingSessionCoordinator =
    attempt.signingSessionCoordinator || deps.signingSessionCoordinator;
  const authorizationRequired = await prepareNearAuthorizationRequiredTransaction({
    deps,
    input: args,
    commandSubject: args.commandSubject,
    operationId: confirmationOperationId,
  });
  if (authorizationRequired) {
    const ctx = deps.getSignerWorkerContext();
    return await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      materialActivation: requireNearEd25519CommitMaterialActivation(
        authorizationRequired.preparation,
      ),
      task: async () =>
        (await signNearWithUiConfirm({
          chain: 'near',
          kind: 'transactionWithActions',
          payload: {
            ctx,
            commandSubject: args.commandSubject,
            nearAccount,
            transaction: args.transaction,
            rpcCall: args.rpcCall,
            signerSlot: publicOptions.signerSlot,
            confirmationConfigOverride: publicOptions.confirmationConfigOverride,
            title: publicOptions.title,
            body: publicOptions.body,
            onEvent: publicOptions.onEvent,
            signingOperationId: confirmationOperationId,
            signingSessionCoordinator,
            selection: {
              kind: 'authorization_required',
              candidate: authorizationRequired.candidate,
            },
            passkeyEd25519OperationStepUp:
              authorizationRequired.passkeyEd25519OperationStepUp || undefined,
            emailOtpEd25519StepUp: authorizationRequired.emailOtpEd25519StepUp || undefined,
            sensitivePolicy: args.sensitivePolicy,
            yaoSigningPreparation: authorizationRequired.preparation,
            yaoMaterialExecutor: authorizationRequired.executor,
          },
        })) as SignTransactionResult,
    });
  }
  const preparedSigningSession = await prepareNearEd25519TransactionSigningSession({
    deps,
    input: args,
    commandSubject: args.commandSubject,
    signingSessionCoordinator,
    operationId: confirmationOperationId,
    forceFreshAuth: attempt.forceFreshAuth === true,
  });
  const preparationAuthorization = preparedSigningSession.preparation.authorization;
  const signingAuthPlan = preparedSigningSession.signingAuthPlan;
  const signingLane = preparedSigningSession.signingLane;
  const transactionLane = preparedSigningSession.transactionLane;
  const thresholdSessionId = preparedSigningSession.thresholdSessionId;
  assertSigningLaneMatchesSelectedTransactionLane({
    signingLane,
    transactionLane,
  });
  try {
    return await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      materialActivation: requireNearEd25519CommitMaterialActivation(
        preparedSigningSession.preparation,
      ),
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
        const materialBoundary = await prepareNearEd25519YaoMaterialBoundary({
          deps,
          commandSubject: args.commandSubject,
          selectedLane: transactionLane,
        });
        const passkeyEd25519OperationStepUp = buildNearPasskeyEd25519OperationStepUp({
          auth: transactionLane.auth,
          signer: transactionLane.identity.signer,
          preparation: materialBoundary.preparation,
          materialExecutor: materialBoundary.executor,
        });
        const emailOtpEd25519StepUp = buildNearEmailOtpEd25519StepUp({
          deps,
          commandSubject: args.commandSubject,
          auth: transactionLane.auth,
          signer: transactionLane.identity.signer,
          preparation: materialBoundary.preparation,
          onEvent: publicOptions.onEvent,
        });
        const executionState = buildPreparedNearTransactionExecutionState({
          preparedSigningSession,
          thresholdSessionId,
          signingSessionCoordinator,
          passkeyEd25519OperationStepUp: passkeyEd25519OperationStepUp || null,
          emailOtpEd25519StepUp: emailOtpEd25519StepUp || null,
        });
        const ed25519SigningBoundary = {
          thresholdSessionId: executionState.thresholdSessionId,
          signingSessionPlan: executionState.signingSessionPlan,
          signingAuthPlan: executionState.signingAuthPlan,
          signingLane: executionState.signingLane,
        };
        const payload: NearTransactionWithActionsPayload = {
          ctx,
          commandSubject: args.commandSubject,
          nearAccount,
          transaction: args.transaction,
          rpcCall: args.rpcCall,
          signerSlot: publicOptions.signerSlot,
          confirmationConfigOverride: publicOptions.confirmationConfigOverride,
          title: publicOptions.title,
          body: publicOptions.body,
          onEvent: publicOptions.onEvent,
          signingOperationId: confirmationOperationId,
          signingSessionCoordinator: executionState.signingSessionCoordinator,
          selection: { kind: 'authorized', selectedLane: transactionLane },
          transactionOperation: executionState.transactionOperation,
          ed25519SigningBoundary,
          yaoSigningPreparation: materialBoundary.preparation,
          yaoMaterialExecutor: materialBoundary.executor,
          ...(executionState.passkeyEd25519OperationStepUp
            ? {
                passkeyEd25519OperationStepUp: executionState.passkeyEd25519OperationStepUp,
              }
            : {}),
          ...(executionState.emailOtpEd25519StepUp
            ? {
                emailOtpEd25519StepUp: executionState.emailOtpEd25519StepUp,
              }
            : {}),
        };
        const result = (await signNearWithUiConfirm({
          chain: 'near',
          kind: 'transactionWithActions',
          payload,
        })) as unknown as SignTransactionResult;
        return result;
      },
    });
  } catch (error: unknown) {
    const alreadyAttemptedFreshAuth =
      signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth ||
      signingAuthPlan.kind === SigningAuthPlanKind.EmailOtpReauth;
    const ownerDecision = nearOwnerOperationAuthorizationDecisionFromError(error);
    const admissionDecision = nearWalletSessionQuotaAdmissionDecisionFromError(error);
    const walletSessionFailure = walletSessionFailureFromError(error);
    const walletSessionRequiresStepUp = ownerDecision?.kind === 'step_up_required';
    if (
      !attempt.retryingFreshAuth &&
      !alreadyAttemptedFreshAuth &&
      preparationAuthorization.kind === 'authorized' &&
      (walletSessionRequiresStepUp || admissionDecision)
    ) {
      const nextOperationId = operationId || createNearTransactionSigningOperationId();
      if (admissionDecision?.kind === 'wait_and_retry_admission') {
        await waitForWalletSessionQuotaAdmissionRetry(admissionDecision.retryAfterMs);
        return await signTransactionWithActions(deps, args, {
          forceFreshAuth: false,
          operationId: nextOperationId,
          retryingFreshAuth: attempt.retryingFreshAuth,
          signingSessionCoordinator,
        });
      }
      await invalidateAuthoritativeNearWalletSessionExpiry({
        failure: walletSessionFailure,
        coordinator: signingSessionCoordinator,
        lane: preparedSigningSession.transactionLane,
        expiresAtMs: preparationAuthorization.authorization.status.expiresAtMs,
      });
      const isEmailOtpSession = transactionLane.auth.kind === 'email_otp';
      const ownerStepUpReason =
        ownerDecision?.kind === 'step_up_required' ? ownerDecision.reason : undefined;
      const reason = admissionDecision
        ? admissionDecision.reason === 'stale_projection'
          ? 'wallet_signing_budget_stale_projection'
          : 'wallet_signing_budget_exhausted'
        : ownerStepUpReason === 'wallet_session_missing'
          ? 'threshold_session_missing'
          : 'threshold_session_expired';
      emitNearSigningEvent(publicOptions.onEvent, nearAccountId, {
        phase: isEmailOtpSession
          ? SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED
          : SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
        status: 'running',
        message: isEmailOtpSession
          ? 'Signing session needs reauthorization; requesting Email OTP'
          : 'Signing session needs reauthorization; requesting passkey',
        interaction: { kind: 'none', overlay: 'none' },
        data: {
          chain: 'near',
          reason,
        },
      });
      if (admissionDecision?.kind === 'request_fresh_step_up') {
        const queueKey = nearEd25519WalletSessionQuotaAdmissionQueueKey({
          walletId: args.commandSubject.walletSession.walletId,
          nearAccountId,
          prepared: preparedSigningSession,
        });
        return await signingSessionCoordinator.runWalletSessionQuotaAdmissionRetry({
          queueKey,
          refresh: async () =>
            await signTransactionWithActions(deps, args, {
              forceFreshAuth: true,
              operationId: nextOperationId,
              retryingFreshAuth: true,
              signingSessionCoordinator,
            }),
          retryAfterRefresh: async () =>
            await signTransactionWithActions(deps, args, {
              forceFreshAuth: false,
              operationId: nextOperationId,
              retryingFreshAuth: attempt.retryingFreshAuth,
              signingSessionCoordinator,
            }),
        });
      }
      return await signTransactionWithActions(deps, args, {
        forceFreshAuth: true,
        operationId: nextOperationId,
        retryingFreshAuth: true,
        signingSessionCoordinator,
      });
    }
    throw error;
  }
}

type NearDelegateSigningAttemptArgs = {
  deps: NearSigningApiDeps;
  input: SignDelegateActionInput;
  operationId: SigningOperationId;
  attempt: NearAdHocSigningAttempt;
};

async function runPreparedNearDelegateSigning(args: {
  deps: NearSigningApiDeps;
  input: SignDelegateActionInput;
  operationId: SigningOperationId;
  prepared: PreparedNearAdHocSigningSession;
  normalizedRpcCall: RpcCallPayload;
}): Promise<SignDelegateActionResult> {
  return (await signNearWithUiConfirm({
    chain: 'near',
    kind: 'delegateAction',
    payload: {
      ctx: args.deps.getSignerWorkerContext(),
      commandSubject: args.input.commandSubject,
      nearAccount: args.input.commandSubject.nearAccount,
      delegate: args.input.delegate,
      rpcCall: args.normalizedRpcCall,
      signingSessionCoordinator: args.deps.signingSessionCoordinator,
      signerSlot: args.input.signerSlot,
      confirmationConfigOverride: args.input.confirmationConfigOverride,
      title: args.input.title,
      body: args.input.body,
      onEvent: args.input.onEvent,
      operationId: args.operationId,
      forceFreshAuth: args.prepared.forceFreshAuth,
      selection:
        args.prepared.kind === 'authorized'
          ? { kind: 'authorized', selectedLane: args.prepared.selectedLane }
          : { kind: 'authorization_required', candidate: args.prepared.candidate },
      passkeyEd25519OperationStepUp: args.prepared.passkeyEd25519OperationStepUp,
      emailOtpEd25519StepUp: args.prepared.emailOtpEd25519StepUp,
      yaoSigningPreparation: args.prepared.yaoSigningPreparation,
      yaoMaterialExecutor: args.prepared.yaoMaterialExecutor,
    },
  })) as unknown as SignDelegateActionResult;
}

async function executeNearDelegateSigningAttempt(
  args: NearDelegateSigningAttemptArgs,
): Promise<SignDelegateActionResult> {
  const nearAccountId = toAccountId(args.input.commandSubject.nearAccount.accountId);
  const prepared = await prepareNearAdHocSigningSession({
    deps: args.deps,
    commandSubject: args.input.commandSubject,
    signerSlot: args.input.signerSlot,
    operationId: args.operationId,
    onEvent: args.input.onEvent,
    attempt: args.attempt,
  });
  const normalizedRpcCall: RpcCallPayload = {
    nearRpcUrl: args.input.rpcCall.nearRpcUrl || args.deps.nearRpcUrl,
    nearAccountId,
  };
  try {
    return await withThresholdEd25519CommitQueue({
      deps: args.deps,
      nearAccountId,
      materialActivation: requireNearEd25519CommitMaterialActivation(
        prepared.yaoSigningPreparation,
      ),
      task: runPreparedNearDelegateSigning.bind(undefined, {
        deps: args.deps,
        input: args.input,
        operationId: args.operationId,
        prepared,
        normalizedRpcCall,
      }),
    });
  } catch (error: unknown) {
    const ownerDecision = nearOwnerOperationAuthorizationDecisionFromError(error);
    const admissionDecision = nearWalletSessionQuotaAdmissionDecisionFromError(error);
    if (args.attempt.kind === 'initial' && admissionDecision) {
      if (admissionDecision.kind === 'wait_and_retry_admission') {
        await waitForWalletSessionQuotaAdmissionRetry(admissionDecision.retryAfterMs);
        return await executeNearDelegateSigningAttempt(args);
      }
      const queueKey = nearAdHocEd25519WalletSessionQuotaAdmissionQueueKey({
        walletId: args.input.commandSubject.walletSession.walletId,
        nearAccountId,
        prepared,
      });
      return await args.deps.signingSessionCoordinator.runWalletSessionQuotaAdmissionRetry({
        queueKey,
        refresh: async () =>
          await executeNearDelegateSigningAttempt({
            ...args,
            attempt: { kind: 'fresh_auth_retry', forceFreshAuth: true },
          }),
        retryAfterRefresh: async () =>
          await executeNearDelegateSigningAttempt({
            ...args,
            attempt: { kind: 'initial', forceFreshAuth: false },
          }),
      });
    }
    const failure = walletSessionFailureFromError(error);
    if (args.attempt.kind === 'initial' && !prepared.forceFreshAuth && ownerDecision) {
      await invalidateAuthoritativeNearWalletSessionExpiry({
        failure,
        coordinator: args.deps.signingSessionCoordinator,
        lane: prepared.selectedLane,
        expiresAtMs: requireNearReusableAuthorizationExpiry(prepared.yaoSigningPreparation),
      });
      return await executeNearDelegateSigningAttempt({
        deps: args.deps,
        input: args.input,
        operationId: args.operationId,
        attempt: { kind: 'fresh_auth_retry', forceFreshAuth: true },
      });
    }
    throw error;
  }
}

export async function signDelegateAction(
  deps: NearSigningApiDeps,
  args: SignDelegateActionInput,
): Promise<SignDelegateActionResult> {
  try {
    return await executeNearDelegateSigningAttempt({
      deps,
      input: args,
      operationId: createAdHocNearSigningOperationId(deps, 'delegate'),
      attempt: { kind: 'initial', forceFreshAuth: false },
    });
  } catch (error: unknown) {
    console.error('[SigningEngine][delegate] failed', error);
    throw error;
  }
}

type NearNep413SigningAttemptArgs = {
  deps: NearSigningApiDeps;
  input: SignNep413MessagePayload;
  operationId: SigningOperationId;
  attempt: NearAdHocSigningAttempt;
};

async function runPreparedNearNep413Signing(args: {
  deps: NearSigningApiDeps;
  input: SignNep413MessagePayload;
  operationId: SigningOperationId;
  prepared: PreparedNearAdHocSigningSession;
}): Promise<SignNep413MessageResult> {
  const nearAccount = args.input.commandSubject.nearAccount;
  return (await signNearWithUiConfirm({
    chain: 'near',
    kind: 'nep413',
    payload: {
      ctx: args.deps.getSignerWorkerContext(),
      commandSubject: args.input.commandSubject,
      nearAccount,
      signingSessionCoordinator: args.deps.signingSessionCoordinator,
      forceFreshAuth: args.prepared.forceFreshAuth,
      selection:
        args.prepared.kind === 'authorized'
          ? { kind: 'authorized', selectedLane: args.prepared.selectedLane }
          : { kind: 'authorization_required', candidate: args.prepared.candidate },
      passkeyEd25519OperationStepUp: args.prepared.passkeyEd25519OperationStepUp,
      emailOtpEd25519StepUp: args.prepared.emailOtpEd25519StepUp,
      yaoSigningPreparation: args.prepared.yaoSigningPreparation,
      yaoMaterialExecutor: args.prepared.yaoMaterialExecutor,
      payload: {
        message: args.input.message,
        recipient: args.input.recipient,
        nonce: args.input.nonce,
        state: args.input.state,
        accountId: nearAccount.accountId,
        signerSlot: args.input.signerSlot,
        title: args.input.title,
        body: args.input.body,
        confirmationConfigOverride: args.input.confirmationConfigOverride,
        operationId: args.operationId,
      },
    },
  })) as unknown as SignNep413MessageResult;
}

async function executeNearNep413SigningAttempt(
  args: NearNep413SigningAttemptArgs,
): Promise<SignNep413MessageResult> {
  const nearAccountId = toAccountId(args.input.commandSubject.nearAccount.accountId);
  const prepared = await prepareNearAdHocSigningSession({
    deps: args.deps,
    commandSubject: args.input.commandSubject,
    signerSlot: args.input.signerSlot,
    operationId: args.operationId,
    onEvent: undefined,
    attempt: args.attempt,
  });
  try {
    return await withThresholdEd25519CommitQueue({
      deps: args.deps,
      nearAccountId,
      materialActivation: requireNearEd25519CommitMaterialActivation(
        prepared.yaoSigningPreparation,
      ),
      task: runPreparedNearNep413Signing.bind(undefined, {
        deps: args.deps,
        input: args.input,
        operationId: args.operationId,
        prepared,
      }),
    });
  } catch (error: unknown) {
    const ownerDecision = nearOwnerOperationAuthorizationDecisionFromError(error);
    const failure = walletSessionFailureFromError(error);
    if (
      args.attempt.kind === 'initial' &&
      !prepared.forceFreshAuth &&
      ownerDecision !== undefined
    ) {
      await invalidateAuthoritativeNearWalletSessionExpiry({
        failure,
        coordinator: args.deps.signingSessionCoordinator,
        lane: prepared.selectedLane,
        expiresAtMs: requireNearReusableAuthorizationExpiry(prepared.yaoSigningPreparation),
      });
      return await executeNearNep413SigningAttempt({
        deps: args.deps,
        input: args.input,
        operationId: args.operationId,
        attempt: { kind: 'fresh_auth_retry', forceFreshAuth: true },
      });
    }
    throw error;
  }
}

export async function signNEP413Message(
  deps: NearSigningApiDeps,
  payload: SignNep413MessagePayload,
): Promise<SignNep413MessageResult> {
  try {
    return await executeNearNep413SigningAttempt({
      deps,
      input: payload,
      operationId: createAdHocNearSigningOperationId(deps, 'nep413'),
      attempt: { kind: 'initial', forceFreshAuth: false },
    });
  } catch (error: unknown) {
    console.error('SigningEngine: NEP-413 signing error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error || 'Unknown error'),
    };
  }
}
