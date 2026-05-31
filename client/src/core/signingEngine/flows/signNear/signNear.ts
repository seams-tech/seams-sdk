import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import type { DelegateActionInput } from '@/core/types/delegate';
import {
  createSigningFlowEvent,
  SigningEventPhase,
  type CreateSigningFlowEventInput,
  type SigningFlowEvent,
} from '@/core/types/sdkSentEvents';
import type {
  ConfirmationConfig,
  RpcCallPayload,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { NearTransactionsWithActionsPayload } from '../../interfaces/near';
import type { SignTransactionResult } from '@/core/types/seams';
import type { TransactionInputWasm } from '@/core/types/actions';
import {
  SENSITIVE_OPERATION_POLICIES,
  type SensitiveOperationPolicy,
} from '@shared/utils/signerDomain';
import {
  toAuthorizingWalletSigningSessionId,
  type EmailOtpAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type { NearSigningApiDeps } from '../../interfaces/operationDeps';
import { signNearWithUiConfirm } from './nearSigningFlow';
import { resolveThresholdEd25519CommitQueueKey } from '../../threshold/ed25519/commitQueue';
import {
  getStoredThresholdEd25519SessionRecordForLane,
  upsertStoredThresholdEd25519SessionRecord,
  type ThresholdEd25519SessionRecord,
} from '../../session/persistence/records';
import {
  type Ed25519LaneCandidate,
  type SelectedEd25519Lane,
  type ThresholdEd25519SessionStoreSource,
} from '../../session/identity/laneIdentity';
import type {
  AvailableSigningLanes,
  AvailableEd25519SigningLane,
} from '../../session/availability/availableSigningLanes';
import { publishResolvedIdentity } from '../../session/persistence/sealedSessionStore';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  buildEd25519SessionPolicy,
  isThresholdSessionAuthUnavailableError,
} from '../../threshold/sessionPolicy';
import { buildThresholdEd25519WebAuthnPrfSecretSource } from '../../threshold/ed25519/authSession';
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
import { type NearAccountRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  isSigningSessionBudgetExhaustedError,
  SigningSessionCoordinator,
  type SigningSessionReadiness,
} from '../../session/SigningSessionCoordinator';
import type { SigningSessionBudgetStatusAuth } from '../../session/budget/budget';
import {
  normalizeStepUpOperationId,
  resolvePostExhaustionStepUpBudgetPolicy,
  resolveSigningBudgetPolicyRemainingUses,
} from '../../session/budget/policy';
import { signingAuthPlanFromSigningSessionPlan } from '../shared/signingConfirmation';
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
import {
  resolveThresholdEd25519SessionStateFromRecord,
  type ResolvedThresholdEd25519SessionState,
} from './shared/thresholdSessionAuth';
import {
  receiveTransactionIntent,
  recordAvailableSigningLanesRead,
  selectTransactionLaneFromAvailableLanes,
  type NearEd25519AvailableLane,
  type TransactionLaneSelectedState,
} from '../../session/identity/selectLane';
import {
  classifyTransactionReadiness,
  prepareTransactionOperationFromReadiness,
  prepareTransactionSigningOperation,
  recordExactRestoreAttempt,
  replacePreparedTransactionLane,
  type BudgetAdmittedOperation,
  type PreparedTransactionBudgetState,
  type PreparedTransactionOperation,
  type TransactionAuthSelectionPolicy,
  type TransactionSigningIntent,
  type TransactionReadiness,
  type TransactionReadinessClassifiedState,
} from '../../session/operationState/transactionState';
import type {
  NearEd25519EmailOtpStepUpAuthorization,
  NearEd25519PasskeyStepUpAuthorization,
} from './stepUpAuthorization';
import { requiredNearTransactionSignatureUses } from './signatureUses';

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
  nearAccount: NearAccountRef;
  signerSlot?: number;
  title?: string;
  body?: string;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
};

export type SignNep413MessageResult = {
  success: boolean;
  accountId: string;
  publicKey: string;
  signature: string;
  state?: string;
  error?: string;
};

export type SignTransactionsWithActionsInput = {
  nearAccount: NearAccountRef;
  transactions: TransactionInputWasm[];
  rpcCall: RpcCallPayload;
  signerSlot?: number;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  onEvent?: (update: SigningFlowEvent) => void;
  sessionId?: string;
  sensitivePolicy?: SensitiveOperationPolicy;
};

type NearTransactionPublicSigningOptions = Pick<
  SignTransactionsWithActionsInput,
  'confirmationConfigOverride' | 'title' | 'body' | 'onEvent' | 'signerSlot'
>;

export type SignDelegateActionInput = {
  nearAccount: NearAccountRef;
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
      kind: 'transactionsWithActions';
      args: SignTransactionsWithActionsInput;
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
  transactionsWithActions: SignTransactionResult[];
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

function resolveTransactionStepUpSessionUses(args: {
  operationId: SigningOperationId;
  requiredSignatureUses: number;
}): number {
  const budgetPolicy = resolvePostExhaustionStepUpBudgetPolicy({
    operationId: normalizeStepUpOperationId(args.operationId),
  });
  return Math.max(
    Math.max(1, Math.floor(Number(args.requiredSignatureUses) || 1)),
    resolveSigningBudgetPolicyRemainingUses(budgetPolicy),
  );
}

export async function signNear<TRequest extends NearSignIntentRequest>(
  deps: NearSigningApiDeps,
  request: TRequest,
): Promise<NearSignIntentResult<TRequest>> {
  if (request.kind === 'transactionsWithActions') {
    return (await signTransactionsWithActions(
      deps,
      request.args,
    )) as NearSignIntentResult<TRequest>;
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

type NearTransactionPreConfirmSigningDeps = {
  getWarmThresholdEd25519SessionStatusForSession?: NearSigningApiDeps['getWarmThresholdEd25519SessionStatusForSession'];
  signingSessionCoordinator: SigningSessionCoordinator;
  hasUiConfirm: () => boolean;
};

type NearTransactionConfirmedSigningDeps = {
  requestEmailOtpTransactionSigningChallenge?: NearSigningApiDeps['requestEmailOtpTransactionSigningChallenge'];
  resolveEmailOtpSigningSessionAuthLane?: NearSigningApiDeps['resolveEmailOtpSigningSessionAuthLane'];
  loginWithEmailOtpEd25519CapabilityForSigning?: NearSigningApiDeps['loginWithEmailOtpEd25519CapabilityForSigning'];
};

type NearEd25519EmailOtpSigning = {
  prepare: (args: { requiredSignatureUses: number }) => Promise<{
    challengeId: string;
    emailHint?: string;
  }>;
  resend?: (args: { requiredSignatureUses: number }) => Promise<{
    challengeId: string;
    emailHint?: string;
  }>;
  complete: (
    authorization: NearEd25519EmailOtpStepUpAuthorization,
  ) => Promise<{ sessionId: string; sessionState?: ResolvedThresholdEd25519SessionState }>;
};

type NearEd25519PasskeyReconnect = {
  prepare: (args: { requiredSignatureUses: number }) => Promise<{
    sessionId: string;
    walletSigningSessionId: string;
    sessionPolicyDigest32: string;
  }>;
  reconnect: (args: {
    authorization: NearEd25519PasskeyStepUpAuthorization;
    requiredSignatureUses: number;
  }) => Promise<{ sessionId: string; sessionState?: ResolvedThresholdEd25519SessionState }>;
};

type NearEd25519SelectedTransactionLane = TransactionLaneSelectedState<
  SelectedEd25519Lane,
  NearEd25519AvailableLane,
  Ed25519LaneCandidate
>;

type NearEd25519Warmup = {
  isPending: () => boolean;
  waitForReady: () => Promise<boolean>;
};

type PreparedNearEd25519TransactionSigningSession = {
  thresholdSessionRecord: ThresholdEd25519SessionRecord | null;
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
  transactionLane: SelectedEd25519Lane;
  identity: ResolvedEd25519SigningSessionIdentity;
  resolvedSessionId: string;
  availableLanesGeneration: number;
  preparedOperation: PreparedNearEd25519Operation;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  budget: PreparedTransactionBudgetState<SelectedEd25519Lane>;
  ed25519Warmup?: NearEd25519Warmup;
  emailOtpSigning?: NearEd25519EmailOtpSigning;
};

type PreparedNearTransactionExecutionState = {
  kind: 'prepared_near_transaction_execution';
  sessionId: string;
  signingSessionPlan: PreparedNearEd25519Operation['signingSessionPlan'];
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
  initialBudgetAdmittedOperation: BudgetAdmittedOperation<SelectedEd25519Lane> | null;
  signingSessionCoordinator: SigningSessionCoordinator;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  emailOtpSigning: NearEd25519EmailOtpSigning | null;
  ed25519Warmup: NearEd25519Warmup | null;
  passkeyEd25519Reconnect: NearEd25519PasskeyReconnect | null;
};

type NearEd25519LifecycleMetadata = {
  thresholdSessionRecord: ThresholdEd25519SessionRecord;
  transactionLane: SelectedEd25519Lane;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  transactionReadinessState: TransactionReadinessClassifiedState;
  identity: ResolvedEd25519SigningSessionIdentity;
  availableLanesGeneration: number;
  readiness: ThresholdSigningReadinessInput;
  ed25519Warmup?: NearEd25519Warmup;
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
    authMethod: lane.authMethod,
    state: lane.state,
    source: lane.source || 'unknown',
    walletSigningSessionId: lane.walletSigningSessionId,
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

function buildNearTransactionSigningLaneForSelectedLane(args: {
  nearAccount: NearAccountRef;
  record: ThresholdEd25519SessionRecord;
  selectedLane: SelectedEd25519Lane;
}) {
  const nearAccountId = args.nearAccount.accountId;
  const sessionId = String(args.selectedLane.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(args.selectedLane.walletSigningSessionId || '').trim();
  if (!sessionId) {
    throw new Error(
      '[SigningEngine][near] missing threshold session id for transaction auth planning',
    );
  }
  if (!walletSigningSessionId) {
    throw new Error(
      '[SigningEngine][near] missing wallet signing session id for transaction auth planning',
    );
  }
  if (args.record.source === 'email_otp') {
    return buildNearTransactionSigningLane({
      accountId: nearAccountId,
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
      retention: args.record.emailOtpAuthContext?.retention || 'session',
      sessionOrigin:
        args.record.emailOtpAuthContext?.reason === 'login' ? 'login' : 'per_operation',
    });
  }
  return buildNearTransactionSigningLane({
    accountId: nearAccountId,
    authMethod: 'passkey',
    walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
    storageSource: resolveEd25519PasskeyStorageSource(args.record.source),
  });
}

function assertSigningLaneMatchesSelectedTransactionLane(args: {
  signingLane: NearTransactionSigningLane;
  transactionLane: SelectedEd25519Lane;
}): void {
  const signingThresholdSessionId = String(args.signingLane.thresholdSessionId || '').trim();
  const transactionThresholdSessionId = String(
    args.transactionLane.thresholdSessionId || '',
  ).trim();
  if (
    String(args.signingLane.accountId || '').trim() !==
      String(args.transactionLane.accountId || '').trim() ||
    args.signingLane.authMethod !== args.transactionLane.authMethod ||
    args.signingLane.curve !== args.transactionLane.curve ||
    args.signingLane.chainFamily !== args.transactionLane.chain ||
    String(args.signingLane.walletSigningSessionId || '').trim() !==
      String(args.transactionLane.walletSigningSessionId || '').trim() ||
    signingThresholdSessionId !== transactionThresholdSessionId
  ) {
    throw new Error(
      '[SigningEngine][near] prepared signing lane drifted from selected transaction lane',
    );
  }
}

function transactionReadinessFromPlannerInput(
  readiness: ThresholdSigningReadinessInput,
): TransactionReadiness {
  const status = readiness.readiness.status;
  if (status === 'ready') {
    return {
      status: 'ready',
      remainingUses: Math.max(
        0,
        Math.floor(Number(readiness.readiness.remainingUses) || 0),
      ),
      expiresAtMs: Math.max(0, Math.floor(Number(readiness.readiness.expiresAtMs) || 0)),
    };
  }
  if (status === 'expired' || status === 'exhausted' || status === 'budget_unknown') {
    return status === 'budget_unknown'
      ? { status, reason: 'trusted wallet budget status is unavailable' }
      : { status };
  }
  if (status === 'auth_unavailable' || status === 'status_unavailable') {
    return { status, reason: status };
  }
  return { status: 'missing_hot_material' };
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
  const walletSigningSessionId = String(lane.walletSigningSessionId || '').trim();
  if (!thresholdSessionId || !walletSigningSessionId) {
    throw new Error('[SigningEngine][near] prepared Ed25519 lane is missing session identity');
  }
  // Resolved lane metadata is copied from the executable lane so challenge, budget,
  // signing, and cleanup cannot rediscover or disagree about session metadata.
  return {
    ...lane,
    curve: 'ed25519',
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
  };
}

function resolveEd25519PasskeyStorageSource(
  source: ThresholdEd25519SessionStoreSource | undefined,
): Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'> {
  return source && source !== 'email_otp' ? source : 'login';
}

async function resolveNearTransactionPlannerReadiness(args: {
  preConfirmDeps: NearTransactionPreConfirmSigningDeps;
  nearAccount: NearAccountRef;
  record: ThresholdEd25519SessionRecord;
  requiredSignatureUses?: number;
}): Promise<{
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
}> {
  const sessionId = String(args.record.thresholdSessionId || '').trim();
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(sessionId);
  const requiredSignatureUses = Math.max(1, Math.floor(Number(args.requiredSignatureUses) || 1));
  const resolveExpiresAtMs = (): number => args.record.expiresAtMs;
  const resolveRemainingUses = (): number => args.record.remainingUses;
  const buildReadiness = (
    status: SigningSessionReadiness['status'],
    remainingUses = resolveRemainingUses(),
    expiresAtMs = resolveExpiresAtMs(),
  ): {
    readiness: SigningSessionReadiness;
    expiresAtMs: number;
    remainingUses: number;
  } => {
    const normalizedRemainingUses = Math.max(0, Math.floor(Number(remainingUses) || 0));
    const normalizedExpiresAtMs = Math.max(0, Math.floor(Number(expiresAtMs) || 0));
    const readiness: SigningSessionReadiness =
      status === 'ready' || status === 'exhausted'
        ? {
            status,
            thresholdSessionId,
            remainingUses: normalizedRemainingUses,
            expiresAtMs: normalizedExpiresAtMs,
          }
        : status === 'expired'
          ? { status, thresholdSessionId, expiresAtMs: normalizedExpiresAtMs }
          : { status, thresholdSessionId };
    return {
      readiness,
      expiresAtMs: normalizedExpiresAtMs,
      remainingUses: normalizedRemainingUses,
    };
  };

  const isSingleUseEmailOtpRecord =
    args.record.source === 'email_otp' &&
    args.record.emailOtpAuthContext?.retention === 'single_use';
  const isSessionEmailOtpRecord =
    args.record.source === 'email_otp' &&
    args.record.emailOtpAuthContext?.retention === 'session';
  const hasCachedEmailOtpClientBase =
    isSessionEmailOtpRecord && Boolean(String(args.record.xClientBaseB64u || '').trim());
  if (!sessionId || isSingleUseEmailOtpRecord || !hasThresholdEd25519RouteAuth(args.record)) {
    return buildReadiness('missing_session', 0);
  }

  const liveStatus =
    (await args.preConfirmDeps
      .getWarmThresholdEd25519SessionStatusForSession?.({
        nearAccountId: args.nearAccount.accountId,
        thresholdSessionId: sessionId,
      })
      .catch(() => null)) || null;
  if (liveStatus?.sessionId === sessionId) {
    if (liveStatus.status === 'expired') return buildReadiness('expired', 0);
    if (liveStatus.status === 'exhausted') return buildReadiness('exhausted', 0);
    if (liveStatus.status !== 'active') return buildReadiness('missing_session', 0);
    const remainingUses = Math.floor(Number(liveStatus.remainingUses) || 0);
    if (remainingUses < requiredSignatureUses) return buildReadiness('exhausted', remainingUses);
    return buildReadiness(
      'ready',
      remainingUses,
      Math.floor(Number(liveStatus.expiresAtMs) || args.record.expiresAtMs),
    );
  }

  const remainingUses = resolveRemainingUses();
  const expiresAtMs = resolveExpiresAtMs();
  if (hasCachedEmailOtpClientBase) {
    if (remainingUses < requiredSignatureUses) {
      return buildReadiness('exhausted', remainingUses, expiresAtMs);
    }
    console.info('[SigningEngine][near][email-otp] using record-backed Ed25519 readiness', {
      nearAccountId: args.nearAccount.accountId,
      thresholdSessionId: sessionId,
      walletSigningSessionId: args.record.walletSigningSessionId,
      liveStatus: liveStatus?.status || 'not_found',
      remainingUses,
      expiresAtMs,
      requiredSignatureUses,
    });
    return buildReadiness('ready', remainingUses, expiresAtMs);
  }
  if (args.preConfirmDeps.hasUiConfirm()) return buildReadiness('missing_session', 0);
  if (remainingUses < requiredSignatureUses) return buildReadiness('exhausted', remainingUses, expiresAtMs);
  return buildReadiness('ready', remainingUses, expiresAtMs);
}

function hasThresholdEd25519RouteAuth(record: ThresholdEd25519SessionRecord): boolean {
  if (record.thresholdSessionKind === 'cookie') return true;
  return Boolean(String(record.thresholdSessionAuthToken || '').trim());
}

function emailOtpEd25519AuthLaneFromRecord(
  record: ThresholdEd25519SessionRecord | null | undefined,
): EmailOtpAuthLane | undefined {
  const jwt = String(record?.thresholdSessionAuthToken || '').trim();
  const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(record?.walletSigningSessionId || '').trim();
  if (record?.source !== 'email_otp' || !jwt || !thresholdSessionId || !walletSigningSessionId) {
    return undefined;
  }
  return {
    kind: 'signing_session',
    jwt,
    thresholdSessionId,
    authorizingWalletSigningSessionId: toAuthorizingWalletSigningSessionId(walletSigningSessionId),
    curve: 'ed25519',
  };
}

async function resolveNearTransactionWalletAuth(args: {
  deps: NearSigningApiDeps;
  confirmedDeps: NearTransactionConfirmedSigningDeps;
  nearAccount: NearAccountRef;
  preparedOperation: PreparedNearEd25519Operation;
  operationId: SigningOperationId;
  onEvent?: (update: SigningFlowEvent) => void;
}): Promise<{
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
  emailOtpSigning?: NearEd25519EmailOtpSigning;
}> {
  const preparedOperation = args.preparedOperation;
  const record = preparedOperation.metadata.thresholdSessionRecord;
  if (!record) {
    throw new Error('[SigningEngine][near] signing session is not ready: missing_session');
  }
  const lane = preparedOperation.lane;
  emitSigningLaneResolutionTrace('near', lane, {
    reason: 'near_transaction_auth_planning',
  });

  const authInput = {
    accountId: args.nearAccount.accountId,
    intent: SigningOperationIntent.TransactionSign,
    curve: 'ed25519' as const,
  };
  const plan = preparedOperation.signingSessionPlan;
  if (plan.kind === SigningSessionPlanKind.NotReady) {
    console.warn('[SigningEngine][near][ed25519] transaction auth planning not ready', {
      nearAccountId: args.nearAccount.accountId,
      authMethod: lane.authMethod,
      reason: plan.reason,
      readiness: preparedOperation.readiness.status,
      walletSigningSessionId: lane.walletSigningSessionId,
      thresholdSessionId: lane.thresholdSessionId,
      recordSource: record.source,
      retention: record.emailOtpAuthContext?.retention,
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
    ...(record.runtimePolicyScope
      ? {
          signingRootId: signingRootScopeFromRuntimePolicyScope(record.runtimePolicyScope)
            .signingRootId,
        }
      : {}),
    expiresAtMs: preparedOperation.expiresAtMs,
    remainingUses: preparedOperation.remainingUses,
  });
  if (signingAuthPlan.kind !== SigningAuthPlanKind.EmailOtpReauth) {
    return {
      signingAuthPlan,
      signingLane: lane,
    };
  }

  let activeChallenge: { challengeId: string; email?: string } | null = null;
  let activeEmailOtpRequiredSignatureUses = 1;
  const prepareEmailOtpChallenge = async (prepareArgs: { requiredSignatureUses: number }) => {
    activeEmailOtpRequiredSignatureUses = Math.max(
      1,
      Math.floor(Number(prepareArgs.requiredSignatureUses) || 1),
    );
    if (typeof args.confirmedDeps.requestEmailOtpTransactionSigningChallenge !== 'function') {
      throw new Error('[SigningEngine] Email OTP per-operation NEAR signing is not configured');
    }
    emitNearSigningEvent(args.onEvent, args.nearAccount.accountId, {
      phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED,
      status: 'running',
      message: 'Sending Email OTP for transaction authorization',
      interaction: { kind: 'none', overlay: 'none' },
    });
    emitSigningBoundaryTrace(
      'near',
      createSigningBoundaryTraceEvent({
        event: 'auth_side_effect_started',
        lane,
        sideEffect: 'email_otp_challenge',
        phase: 'confirmed',
      }),
    );
    const authLane = record
      ? args.confirmedDeps.resolveEmailOtpSigningSessionAuthLane?.({
          thresholdSessionId: record.thresholdSessionId,
          curve: 'ed25519',
        }) || emailOtpEd25519AuthLaneFromRecord(record)
      : undefined;
    const challenge = await args.confirmedDeps.requestEmailOtpTransactionSigningChallenge({
      nearAccountId: args.nearAccount.accountId,
      chain: 'near',
      ...(authLane ? { authLane } : {}),
    });
    const challengeId = String(challenge.challengeId || '').trim();
    if (!challengeId) {
      throw new Error('[SigningEngine] Email OTP challenge response did not include challengeId');
    }
    emitNearSigningEvent(args.onEvent, args.nearAccount.accountId, {
      phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED,
      status: 'waiting_for_user',
      message: 'Email OTP challenge ready',
      interaction: { kind: 'otp_input', overlay: 'show' },
      ...(challenge.emailHint ? { data: { emailHint: challenge.emailHint } } : {}),
    });
    activeChallenge = {
      challengeId,
      email: String(challenge.emailHint || '').trim(),
    };
    return {
      challengeId: activeChallenge.challengeId,
      ...(activeChallenge.email ? { emailHint: activeChallenge.email } : {}),
    };
  };
  return {
    signingAuthPlan,
    signingLane: lane,
    emailOtpSigning: {
      prepare: prepareEmailOtpChallenge,
      resend: prepareEmailOtpChallenge,
      complete: async (authorization: NearEd25519EmailOtpStepUpAuthorization) => {
        const resolvedChallengeId = String(
          authorization.challengeId || activeChallenge?.challengeId || '',
        ).trim();
        if (!resolvedChallengeId) {
          throw new Error('[SigningEngine] Email OTP challenge must be prepared before completion');
        }
        if (
          typeof args.confirmedDeps.loginWithEmailOtpEd25519CapabilityForSigning !== 'function' ||
          !record
        ) {
          throw new Error('[SigningEngine] Email OTP per-operation NEAR signing is not configured');
        }
        const sessionBudgetUses = resolveTransactionStepUpSessionUses({
          operationId: args.operationId,
          requiredSignatureUses: activeEmailOtpRequiredSignatureUses,
        });
        const authLane =
          args.confirmedDeps.resolveEmailOtpSigningSessionAuthLane?.({
            thresholdSessionId: record.thresholdSessionId,
            curve: 'ed25519',
          }) || emailOtpEd25519AuthLaneFromRecord(record);
        const emailOtpAuthentication =
          await args.confirmedDeps.loginWithEmailOtpEd25519CapabilityForSigning({
            nearAccountId: args.nearAccount.accountId,
            challengeId: resolvedChallengeId,
            otpCode: authorization.otpCode,
            record,
            ...(authLane ? { authLane } : {}),
            remainingUses: sessionBudgetUses,
          });
        if (emailOtpAuthentication.record) {
          // OTP step-up mints the replacement Ed25519 runtime lane. Publish it
          // before signing/finalization so budget sync targets the same lane.
          upsertStoredThresholdEd25519SessionRecord(emailOtpAuthentication.record);
        }
        const sessionState = resolveThresholdEd25519SessionStateFromRecord(
          emailOtpAuthentication.record,
        );
        return {
          sessionId: emailOtpAuthentication.sessionId,
          ...(sessionState ? { sessionState } : {}),
        };
      },
    },
  };
}

function resolvePreparedSigningRequestSessionId(args: {
  providedSessionId?: string;
  identity: ResolvedEd25519SigningSessionIdentity;
}): string {
  const provided = String(args.providedSessionId || '').trim();
  const prepared = String(args.identity.thresholdSessionId || '').trim();
  if (provided && provided !== prepared) {
    throw new Error(
      '[SigningEngine][near] transaction sessionId must match prepared Ed25519 identity',
    );
  }
  return prepared;
}

function resolveAdHocSigningRequestSessionId(args: {
  deps: NearSigningApiDeps;
  nearAccount: NearAccountRef;
}): string {
  const nearAccountId = args.nearAccount.accountId;
  if (typeof args.deps.resolveThresholdEd25519SessionId === 'function') {
    const canonical = String(
      args.deps.resolveThresholdEd25519SessionId(nearAccountId) || '',
    ).trim();
    if (canonical) return canonical;
  }
  return args.deps.createSigningSessionId('threshold-ed25519');
}

function buildPreparedNearTransactionExecutionState(args: {
  preparedSigningSession: PreparedNearEd25519TransactionSigningSession;
  resolvedSessionId: string;
  signingSessionCoordinator: SigningSessionCoordinator;
  passkeyEd25519Reconnect: NearEd25519PasskeyReconnect | null;
}): PreparedNearTransactionExecutionState {
  const budget = args.preparedSigningSession.budget;
  return {
    kind: 'prepared_near_transaction_execution',
    sessionId: args.resolvedSessionId,
    signingSessionPlan: args.preparedSigningSession.preparedOperation.signingSessionPlan,
    signingAuthPlan: args.preparedSigningSession.signingAuthPlan,
    signingLane: args.preparedSigningSession.signingLane,
    initialBudgetAdmittedOperation: budget.kind === 'BudgetAdmitted' ? budget.operation : null,
    signingSessionCoordinator: args.signingSessionCoordinator,
    transactionOperation: args.preparedSigningSession.transactionOperation,
    emailOtpSigning: args.preparedSigningSession.emailOtpSigning || null,
    ed25519Warmup: args.preparedSigningSession.ed25519Warmup || null,
    passkeyEd25519Reconnect: args.passkeyEd25519Reconnect,
  };
}

function buildNearPasskeyEd25519Reconnect(args: {
  deps: NearSigningApiDeps;
  nearAccount: NearAccountRef;
  ctx: ReturnType<NearSigningApiDeps['getSignerWorkerContext']>;
  thresholdSessionRecord: ThresholdEd25519SessionRecord | null;
  operationId: SigningOperationId;
}): NearEd25519PasskeyReconnect | undefined {
  if (
    !args.thresholdSessionRecord ||
    typeof args.deps.reconnectPasskeyEd25519CapabilityForSigning !== 'function'
  ) {
    return undefined;
  }
  const thresholdSessionRecord = args.thresholdSessionRecord;
  return {
    prepare: async ({ requiredSignatureUses }: { requiredSignatureUses: number }) => {
      const sessionBudgetUses = resolveTransactionStepUpSessionUses({
        operationId: args.operationId,
        requiredSignatureUses,
      });
      const rpId = String(args.ctx.touchIdPrompt.getRpId() || '').trim();
      const walletSigningSessionId = String(
        thresholdSessionRecord.walletSigningSessionId || '',
      ).trim();
      if (!rpId) {
        throw new Error('[SigningEngine] missing rpId for passkey Ed25519 reauth');
      }
      if (!walletSigningSessionId) {
        throw new Error(
          '[SigningEngine] missing wallet signing session id for passkey Ed25519 reauth',
        );
      }
      const { policy, sessionPolicyDigest32 } = await buildEd25519SessionPolicy({
        nearAccountId: args.nearAccount.accountId,
        rpId,
        relayerKeyId: thresholdSessionRecord.relayerKeyId,
        ...(thresholdSessionRecord.runtimePolicyScope
          ? { runtimePolicyScope: thresholdSessionRecord.runtimePolicyScope }
          : {}),
        participantIds: thresholdSessionRecord.participantIds,
        walletSigningSessionId,
        remainingUses: sessionBudgetUses,
      });
      return {
        sessionId: policy.sessionId,
        walletSigningSessionId: policy.walletSigningSessionId,
        sessionPolicyDigest32,
      };
    },
    reconnect: async ({ authorization, requiredSignatureUses }) => {
      const refreshed = await args.deps.reconnectPasskeyEd25519CapabilityForSigning!({
        nearAccountId: args.nearAccount.accountId,
        record: thresholdSessionRecord,
        policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
          credential: authorization.credential,
          rpId: thresholdSessionRecord.rpId,
        }),
        usesNeeded: requiredSignatureUses,
        remainingUses: resolveTransactionStepUpSessionUses({
          operationId: args.operationId,
          requiredSignatureUses,
        }),
        sessionId: authorization.plannedPasskeyReconnect.sessionId,
        walletSigningSessionId: authorization.plannedPasskeyReconnect.walletSigningSessionId,
      });
      const sessionState = resolveThresholdEd25519SessionStateFromRecord(refreshed.record);
      return {
        sessionId: refreshed.sessionId,
        ...(sessionState ? { sessionState } : {}),
      };
    },
  };
}

async function withThresholdEd25519CommitQueue<T>(args: {
  deps: NearSigningApiDeps;
  nearAccountId: AccountId;
  thresholdSessionId: string;
  task: () => Promise<T>;
}): Promise<T> {
  const queueKey = resolveThresholdEd25519CommitQueueKey({
    thresholdSessionId: args.thresholdSessionId,
  });
  return await args.deps.withThresholdEd25519CommitQueue({
    queueKey,
    nearAccountId: args.nearAccountId,
    enabled: true,
    task: args.task,
  });
}

function authMethodForThresholdEd25519Record(
  record: ThresholdEd25519SessionRecord,
): 'email_otp' | 'passkey' {
  return record.source === 'email_otp' ? 'email_otp' : 'passkey';
}

function thresholdEd25519RecordMatchesSelectedLane(args: {
  record: ThresholdEd25519SessionRecord;
  selectedLane: SelectedEd25519Lane;
  nearAccountId: AccountId;
}): boolean {
  return (
    String(args.record.nearAccountId || '').trim() === String(args.nearAccountId || '').trim() &&
    authMethodForThresholdEd25519Record(args.record) === args.selectedLane.authMethod &&
    String(args.record.thresholdSessionId || '').trim() ===
      String(args.selectedLane.thresholdSessionId || '').trim() &&
    String(args.record.walletSigningSessionId || '').trim() ===
      String(args.selectedLane.walletSigningSessionId || '').trim()
  );
}

function selectNearEd25519TransactionCandidate(args: {
  availableLanes: AvailableSigningLanes | null;
  authSelectionPolicy: TransactionAuthSelectionPolicy | null;
  nearAccountId: AccountId;
  currentRuntimeLane?: AvailableEd25519SigningLane | null;
}): NearEd25519SelectedTransactionLane | null {
  const authSelectionPolicy = args.authSelectionPolicy || null;
  if (!authSelectionPolicy) return null;

  const intentState = receiveTransactionIntent({
    walletId: args.nearAccountId,
    curve: 'ed25519',
    chain: 'near',
    authSelectionPolicy,
    operationUsesNeeded: 1,
  });
  const availableLanesState = recordAvailableSigningLanesRead(intentState, {
    availableLanes: args.availableLanes,
    currentRuntimeLane: args.currentRuntimeLane || null,
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

function concreteNearEd25519AvailableAuthMethods(
  availableLanes: AvailableSigningLanes | null,
): Array<'email_otp' | 'passkey'> {
  const methods = new Set<'email_otp' | 'passkey'>();
  for (const lane of availableLanes?.candidates.ed25519.near || []) {
    if (lane.authMethod !== 'email_otp' && lane.authMethod !== 'passkey') continue;
    if (!String(lane.walletSigningSessionId || '').trim()) continue;
    if (!String(lane.thresholdSessionId || '').trim()) continue;
    methods.add(lane.authMethod);
  }
  return [...methods].sort();
}

function hasSharedEmailOtpAndPasskeyEd25519LaneIdentity(
  availableLanes: AvailableSigningLanes | null,
): boolean {
  const authMethodsByIdentity = new Map<string, Set<'email_otp' | 'passkey'>>();
  for (const lane of availableLanes?.candidates.ed25519.near || []) {
    if (lane.authMethod !== 'email_otp' && lane.authMethod !== 'passkey') continue;
    const walletSigningSessionId = String(lane.walletSigningSessionId || '').trim();
    const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
    if (!walletSigningSessionId || !thresholdSessionId) continue;
    const identityKey = `${walletSigningSessionId}:${thresholdSessionId}`;
    const authMethods =
      authMethodsByIdentity.get(identityKey) || new Set<'email_otp' | 'passkey'>();
    authMethods.add(lane.authMethod);
    authMethodsByIdentity.set(identityKey, authMethods);
  }
  for (const authMethods of authMethodsByIdentity.values()) {
    if (authMethods.has('email_otp') && authMethods.has('passkey')) return true;
  }
  return false;
}

function verifiedRuntimeNearEd25519AvailableLanes(args: {
  availableLanes: AvailableSigningLanes | null;
  nearAccountId: AccountId;
}): NearEd25519AvailableLane[] {
  const runtimeLanes: NearEd25519AvailableLane[] = [];
  for (const lane of args.availableLanes?.candidates.ed25519.near || []) {
    if (lane.authMethod !== 'email_otp' && lane.authMethod !== 'passkey') continue;
    if (lane.source !== 'runtime_session_record' && lane.source !== 'runtime_and_durable') continue;
    if (lane.source === 'runtime_session_record' && lane.state !== 'ready') continue;
    const walletSigningSessionId = String(lane.walletSigningSessionId || '').trim();
    const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
    if (!walletSigningSessionId || !thresholdSessionId) continue;
    const runtimeRecord = getStoredThresholdEd25519SessionRecordForLane({
      nearAccountId: args.nearAccountId,
      authMethod: lane.authMethod,
      walletSigningSessionId,
      thresholdSessionId,
    });
    if (!runtimeRecord) continue;
    runtimeLanes.push(lane as NearEd25519AvailableLane);
  }
  return runtimeLanes;
}

async function selectSelectedEd25519LaneFromAvailableLanes(args: {
  deps: NearSigningApiDeps;
  nearAccount: NearAccountRef;
  availableLanes: AvailableSigningLanes | null;
}): Promise<NearEd25519SelectedTransactionLane | null> {
  const nearAccountId = args.nearAccount.accountId;
  const selectByAuthMethod = (
    authMethod: 'email_otp' | 'passkey',
    currentRuntimeLane?: NearEd25519AvailableLane | null,
  ) =>
    selectNearEd25519TransactionCandidate({
      availableLanes: args.availableLanes,
      authSelectionPolicy: { kind: 'account_class', authMethod },
      nearAccountId,
      ...(currentRuntimeLane ? { currentRuntimeLane } : {}),
    });

  const runtimeLanes = verifiedRuntimeNearEd25519AvailableLanes({
    availableLanes: args.availableLanes,
    nearAccountId,
  });
  if (runtimeLanes.length === 1) {
    const runtimeLane = runtimeLanes[0]!;
    return selectByAuthMethod(runtimeLane.authMethod, runtimeLane);
  }
  if (hasSharedEmailOtpAndPasskeyEd25519LaneIdentity(args.availableLanes)) {
    const emailOtpSelection = selectByAuthMethod('email_otp');
    if (emailOtpSelection) return emailOtpSelection;
  }

  const accountSelectedAuthMethod = await args.deps
    .resolveAccountAuthMethodForSigning?.({
      nearAccountId,
      curve: 'ed25519',
      chain: 'near',
    })
    .catch((error) => {
      console.warn('[SigningEngine][near] Ed25519 auth-method selection failed', {
        nearAccountId,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
      return null;
    });
  const accountAuthMethod =
    accountSelectedAuthMethod === 'email_otp' || accountSelectedAuthMethod === 'passkey'
      ? accountSelectedAuthMethod
      : null;

  if (runtimeLanes.length > 1) {
    if (accountAuthMethod) {
      const matchingRuntimeLanes = runtimeLanes.filter(
        (lane) => lane.authMethod === accountAuthMethod,
      );
      if (matchingRuntimeLanes.length === 1) {
        return selectByAuthMethod(accountAuthMethod, matchingRuntimeLanes[0]!);
      }
    }
    throw new Error('[SigningEngine][near] Ed25519 transaction has ambiguous runtime lanes');
  }

  const authMethods = concreteNearEd25519AvailableAuthMethods(args.availableLanes);
  if (authMethods.length === 1) return selectByAuthMethod(authMethods[0]!);

  if (accountAuthMethod && (!authMethods.length || authMethods.includes(accountAuthMethod))) {
    return selectByAuthMethod(accountAuthMethod);
  }
  return null;
}

function assertNearEd25519SelectedLaneMatchesRecord(args: {
  selectedLane: SelectedEd25519Lane | null;
  record: ThresholdEd25519SessionRecord | null;
  nearAccountId: AccountId;
}): void {
  if (!args.selectedLane || !args.record) return;
  if (
    thresholdEd25519RecordMatchesSelectedLane({
      record: args.record,
      selectedLane: args.selectedLane,
      nearAccountId: args.nearAccountId,
    })
  ) {
    return;
  }
  throw new Error(
    `[SigningEngine][near] available Ed25519 lane identity does not match runtime session record for ${String(args.nearAccountId)}`,
  );
}

function readNearEd25519RuntimeRecordForSelectedLane(args: {
  selectedLane: SelectedEd25519Lane | null;
  nearAccountId: AccountId;
}): ThresholdEd25519SessionRecord | null {
  if (!args.selectedLane) return null;
  const record = getStoredThresholdEd25519SessionRecordForLane({
    nearAccountId: args.nearAccountId,
    authMethod: args.selectedLane.authMethod,
    walletSigningSessionId: args.selectedLane.walletSigningSessionId,
    thresholdSessionId: args.selectedLane.thresholdSessionId,
  });
  if (!record) return null;
  return thresholdEd25519RecordMatchesSelectedLane({
    record,
    selectedLane: args.selectedLane,
    nearAccountId: args.nearAccountId,
  })
    ? record
    : null;
}

function publishNearEd25519RuntimeIdentityForRecord(
  record: ThresholdEd25519SessionRecord | null,
): void {
  const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(record?.walletSigningSessionId || '').trim();
  if (!record || !thresholdSessionId || !walletSigningSessionId) return;
  // This is a command-boundary write: durable seal cleanup can remove restore
  // material while the current tab still has a runtime lane that must be
  // selectable for step-up auth after exhaustion.
  publishResolvedIdentity({
    walletId: String(record.nearAccountId),
    authMethod: record.source === 'email_otp' ? 'email_otp' : 'passkey',
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId,
    thresholdSessionId,
  });
}

async function readNearEd25519AvailableSigningLanes(args: {
  deps: NearSigningApiDeps;
  nearAccount: NearAccountRef;
  authMethod: 'email_otp' | 'passkey' | null;
}): Promise<AvailableSigningLanes | null> {
  const nearAccountId = args.nearAccount.accountId;
  if (typeof args.deps.readAvailableSigningLanesForSigning !== 'function') {
    throw new Error(
      '[SigningEngine][near] transaction signing requires available signing lanes reader',
    );
  }
  return await args.deps
    .readAvailableSigningLanesForSigning({
      walletId: nearAccountId,
      curve: 'ed25519',
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

async function restoreNearEd25519SelectedSigningSession(args: {
  deps: NearSigningApiDeps;
  nearAccount: NearAccountRef;
  selectedLane: SelectedEd25519Lane | null;
  candidate: Ed25519LaneCandidate | null;
}): Promise<void> {
  const nearAccountId = args.nearAccount.accountId;
  if (typeof args.deps.restorePersistedSessionForSigning !== 'function') return;
  const selectedLane = args.selectedLane;
  if (!selectedLane) {
    console.debug('[SigningEngine][near] Ed25519 restore skipped without selected available lane', {
      nearAccountId,
    });
    return;
  }
  if (args.candidate?.source === 'runtime_session_record' && args.candidate.state === 'ready') {
    const thresholdSessionId = String(selectedLane.thresholdSessionId || '').trim();
    const liveStatus =
      thresholdSessionId &&
      typeof args.deps.getWarmThresholdEd25519SessionStatusForSession === 'function'
        ? await args.deps
            .getWarmThresholdEd25519SessionStatusForSession({
              nearAccountId,
              thresholdSessionId,
            })
            .catch(() => null)
        : null;
    const liveSessionId = String(liveStatus?.sessionId || '')
      .replace(/^threshold-ed25519:/, '')
      .trim();
    const liveRemainingUses = Math.floor(Number(liveStatus?.remainingUses) || 0);
    if (
      liveStatus?.status === 'active' &&
      (!liveSessionId || liveSessionId === thresholdSessionId) &&
      liveRemainingUses >= 1
    ) {
      return;
    }
  }
  await args.deps.restorePersistedSessionForSigning({
    walletId: nearAccountId,
    authMethod: selectedLane.authMethod,
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId: selectedLane.walletSigningSessionId,
    thresholdSessionId: selectedLane.thresholdSessionId,
    reason: 'transaction',
  });
}

async function prepareNearEd25519TransactionOperation(args: {
  deps: NearSigningApiDeps;
  nearAccount: NearAccountRef;
  signingSessionCoordinator: SigningSessionCoordinator;
  ed25519Warmup?: NearEd25519Warmup;
  availableLanes?: AvailableSigningLanes | null;
  selectedLane: NearEd25519SelectedTransactionLane;
  operationUsesNeeded: number;
}): Promise<NearEd25519TransactionOperationPrepareResult> {
  const nearAccountId = args.nearAccount.accountId;
  const operationUsesNeeded = Math.max(1, Math.floor(Number(args.operationUsesNeeded) || 1));
  const selectedSessionLane = args.selectedLane.lane;
  await restoreNearEd25519SelectedSigningSession({
    deps: args.deps,
    nearAccount: args.nearAccount,
    selectedLane: selectedSessionLane,
    candidate: args.selectedLane.candidate,
  });
  const restoreState = recordExactRestoreAttempt(args.selectedLane, {
    restored: Boolean(selectedSessionLane),
  });
  const recordForLifecycle = readNearEd25519RuntimeRecordForSelectedLane({
    selectedLane: selectedSessionLane,
    nearAccountId,
  });
  publishNearEd25519RuntimeIdentityForRecord(recordForLifecycle);
  assertNearEd25519SelectedLaneMatchesRecord({
    selectedLane: selectedSessionLane,
    record: recordForLifecycle,
    nearAccountId,
  });
  if (!selectedSessionLane || !recordForLifecycle) {
    throw new Error('[SigningEngine][near] signing session is not ready: missing_session');
  }
  const lane = buildNearTransactionSigningLaneForSelectedLane({
    nearAccount: args.nearAccount,
    record: recordForLifecycle,
    selectedLane: selectedSessionLane,
  });
  assertSigningLaneMatchesSelectedTransactionLane({
    signingLane: lane,
    transactionLane: args.selectedLane.lane,
  });
  const readiness = await resolveNearTransactionPlannerReadiness({
    preConfirmDeps: {
      getWarmThresholdEd25519SessionStatusForSession:
        args.deps.getWarmThresholdEd25519SessionStatusForSession,
      signingSessionCoordinator: args.signingSessionCoordinator,
      hasUiConfirm: () => Boolean(args.deps.getSignerWorkerContext().touchConfirm),
    },
    nearAccount: args.nearAccount,
    record: recordForLifecycle,
    requiredSignatureUses: operationUsesNeeded,
  });
  if (recordForLifecycle.source === 'email_otp' && readiness.readiness.status !== 'ready') {
    console.warn('[SigningEngine][near][email-otp] Ed25519 pre-confirm readiness is not ready', {
      nearAccountId,
      readiness: readiness.readiness.status,
      thresholdSessionId: recordForLifecycle.thresholdSessionId,
      walletSigningSessionId: recordForLifecycle.walletSigningSessionId,
      retention: recordForLifecycle.emailOtpAuthContext?.retention,
      remainingUses: readiness.remainingUses,
      expiresAtMs: readiness.expiresAtMs,
      requiredSignatureUses: operationUsesNeeded,
      hasRouteAuth: hasThresholdEd25519RouteAuth(recordForLifecycle),
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
    restoreState,
    transactionReadinessFromPlannerInput({
      readiness: readiness.readiness,
      expiresAtMs: readiness.expiresAtMs,
      remainingUses: readiness.remainingUses,
      usesNeeded: operationUsesNeeded,
    }),
  );
  const transactionOperation = prepareTransactionOperationFromReadiness(transactionReadinessState);
  const identity = requireResolvedNearEd25519SigningLane(lane);
  const readinessInput = {
    readiness: readiness.readiness,
    expiresAtMs: readiness.expiresAtMs,
    remainingUses: readiness.remainingUses,
    usesNeeded: operationUsesNeeded,
  };
  return {
    lane,
    transactionLane: args.selectedLane.lane,
    transactionIntent: args.selectedLane.intent,
    readiness: readinessInput,
    availableLanesGeneration: args.availableLanes?.generation || 0,
    metadata: {
      thresholdSessionRecord: recordForLifecycle,
      transactionLane: args.selectedLane.lane,
      transactionOperation,
      transactionReadinessState,
      identity,
      availableLanesGeneration: args.availableLanes?.generation || 0,
      readiness: readinessInput,
      ...(args.ed25519Warmup ? { ed25519Warmup: args.ed25519Warmup } : {}),
    },
  };
}

async function prepareNearEd25519TransactionSigningSession(args: {
  deps: NearSigningApiDeps;
  input: SignTransactionsWithActionsInput;
  nearAccount: NearAccountRef;
  signingSessionCoordinator: SigningSessionCoordinator;
  operationId: SigningOperationId;
  forceFreshAuth?: boolean;
}): Promise<PreparedNearEd25519TransactionSigningSession> {
  const nearAccountId = args.nearAccount.accountId;
  const operationUsesNeeded = requiredNearTransactionSignatureUses(args.input.transactions);
  const hasPendingEmailOtpEd25519Warmup = (): boolean =>
    args.deps.isEmailOtpEd25519WarmupPending?.({ nearAccountId }) === true;
  if (hasPendingEmailOtpEd25519Warmup()) {
    emitNearSigningEvent(args.input.onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
      status: 'running',
      message: 'Finalizing NEAR signing session',
      interaction: { kind: 'none', overlay: 'none' },
    });
    await args.deps.waitForPendingEmailOtpEd25519Warmup?.({ nearAccountId });
  }
  const ed25519Warmup =
    hasPendingEmailOtpEd25519Warmup() &&
    typeof args.deps.waitForPendingEmailOtpEd25519Warmup === 'function'
      ? {
          isPending: hasPendingEmailOtpEd25519Warmup,
          waitForReady: () =>
            args.deps.waitForPendingEmailOtpEd25519Warmup!({
              nearAccountId,
            }),
        }
      : undefined;
  const availableLanes = await readNearEd25519AvailableSigningLanes({
    deps: args.deps,
    nearAccount: args.nearAccount,
    authMethod: null,
  });
  const selectedLane = await selectSelectedEd25519LaneFromAvailableLanes({
    deps: args.deps,
    nearAccount: args.nearAccount,
    availableLanes,
  });
  if (!selectedLane) {
    console.warn('[SigningEngine][near][ed25519] exact transaction lane selection failed', {
      nearAccountId,
      requiredSignatureUses: operationUsesNeeded,
      pendingEmailOtpEd25519Warmup: hasPendingEmailOtpEd25519Warmup(),
      availableLanes: summarizeNearEd25519AvailableLanes(availableLanes),
    });
    throw new Error(
      '[SigningEngine][near] Ed25519 transaction signing requires an exact selected lane',
    );
  }
  const initialAuthSelectionPolicy: TransactionAuthSelectionPolicy = {
    kind: 'account_class',
    authMethod: selectedLane.lane.authMethod,
  };

  const preparedTransaction = await prepareTransactionSigningOperation({
    intent: {
      walletId: String(nearAccountId),
      curve: 'ed25519',
      chain: 'near',
      authSelectionPolicy: initialAuthSelectionPolicy,
      operationUsesNeeded,
    },
    coordinator: args.signingSessionCoordinator,
    forceFreshAuth: args.forceFreshAuth === true,
    sensitiveOperationPolicy:
      args.input.sensitivePolicy || SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy,
    prepareBudgetIdentity: true,
    onPlannerTrace: (event) => emitSigningPlannerDecisionTrace('near', event),
    lifecycleAdapter: {
      prepare: async () => {
        const lifecycle = await prepareNearEd25519TransactionOperation({
          deps: args.deps,
          nearAccount: args.nearAccount,
          signingSessionCoordinator: args.signingSessionCoordinator,
          availableLanes,
          selectedLane,
          operationUsesNeeded,
          ...(ed25519Warmup ? { ed25519Warmup } : {}),
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
  const thresholdSessionRecord = preparedOperation.metadata.thresholdSessionRecord;
  const signingLane = preparedOperation.lane;
  const transactionLane = transactionOperation.lane;
  const identity = preparedOperation.metadata.identity;

  const { signingAuthPlan, emailOtpSigning } = await resolveNearTransactionWalletAuth({
    deps: args.deps,
    confirmedDeps: {
      requestEmailOtpTransactionSigningChallenge:
        args.deps.requestEmailOtpTransactionSigningChallenge,
      resolveEmailOtpSigningSessionAuthLane: args.deps.resolveEmailOtpSigningSessionAuthLane,
      loginWithEmailOtpEd25519CapabilityForSigning:
        args.deps.loginWithEmailOtpEd25519CapabilityForSigning,
    },
    nearAccount: args.nearAccount,
    preparedOperation,
    operationId: args.operationId,
    onEvent: args.input.onEvent,
  });
  const budget = preparedTransaction.budget;
  return {
    thresholdSessionRecord,
    signingAuthPlan,
    signingLane,
    transactionLane,
    identity,
    resolvedSessionId: resolvePreparedSigningRequestSessionId({
      providedSessionId: args.input.sessionId,
      identity,
    }),
    availableLanesGeneration: preparedOperation.availableLanesGeneration,
    preparedOperation,
    transactionOperation,
    budget,
    ...(preparedOperation.metadata.ed25519Warmup
      ? { ed25519Warmup: preparedOperation.metadata.ed25519Warmup }
      : {}),
    ...(emailOtpSigning ? { emailOtpSigning } : {}),
  };
}

export async function signTransactionsWithActions(
  deps: NearSigningApiDeps,
  args: SignTransactionsWithActionsInput,
  attempt: {
    forceFreshAuth?: boolean;
    operationId?: SigningOperationId;
    retryingFreshAuth?: boolean;
    signingSessionCoordinator?: SigningSessionCoordinator;
  } = {},
): Promise<SignTransactionResult[]> {
  const nearAccountId = toAccountId(args.nearAccount.accountId);
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
  const preparedSigningSession = await prepareNearEd25519TransactionSigningSession({
    deps,
    input: args,
    nearAccount: args.nearAccount,
    signingSessionCoordinator,
    operationId: confirmationOperationId,
    forceFreshAuth: attempt.forceFreshAuth === true,
  });
  const thresholdSessionRecord = preparedSigningSession.thresholdSessionRecord;
  const signingAuthPlan = preparedSigningSession.signingAuthPlan;
  const signingLane = preparedSigningSession.signingLane;
  const transactionLane = preparedSigningSession.transactionLane;
  const resolvedSessionId = preparedSigningSession.resolvedSessionId;
  assertSigningLaneMatchesSelectedTransactionLane({
    signingLane,
    transactionLane,
  });
  try {
    return await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      thresholdSessionId: resolvedSessionId,
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
        const passkeyEd25519Reconnect = buildNearPasskeyEd25519Reconnect({
          deps,
          nearAccount: args.nearAccount,
          ctx,
          thresholdSessionRecord,
          operationId: confirmationOperationId,
        });
        const executionState = buildPreparedNearTransactionExecutionState({
          preparedSigningSession,
          resolvedSessionId,
          signingSessionCoordinator,
          passkeyEd25519Reconnect: passkeyEd25519Reconnect || null,
        });
        const ed25519SigningBoundary = {
          sessionId: executionState.sessionId,
          signingSessionPlan: executionState.signingSessionPlan,
          signingAuthPlan: executionState.signingAuthPlan,
          signingLane: executionState.signingLane,
          initialBudgetAdmittedOperation: executionState.initialBudgetAdmittedOperation,
        };
        const payload: NearTransactionsWithActionsPayload = {
          ctx,
          nearAccount: args.nearAccount,
          transactions: args.transactions,
          rpcCall: args.rpcCall,
          signerSlot: publicOptions.signerSlot,
          confirmationConfigOverride: publicOptions.confirmationConfigOverride,
          title: publicOptions.title,
          body: publicOptions.body,
          onEvent: publicOptions.onEvent,
          ...(executionState.emailOtpSigning
            ? { emailOtpSigning: executionState.emailOtpSigning }
            : {}),
          signingOperationId: confirmationOperationId,
          signingSessionCoordinator: executionState.signingSessionCoordinator,
          transactionOperation: executionState.transactionOperation,
          ed25519SigningBoundary,
          ...(executionState.ed25519Warmup
            ? { ed25519Warmup: executionState.ed25519Warmup }
            : {}),
          ...(executionState.passkeyEd25519Reconnect
            ? { passkeyEd25519Reconnect: executionState.passkeyEd25519Reconnect }
            : {}),
        };
        const result = (await signNearWithUiConfirm({
          chain: 'near',
          kind: 'transactionsWithActions',
          payload,
        })) as unknown as SignTransactionResult[];
        return result;
      },
    });
  } catch (error: unknown) {
    const alreadyAttemptedFreshAuth =
      signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth ||
      signingAuthPlan.kind === SigningAuthPlanKind.EmailOtpReauth ||
      Boolean(preparedSigningSession.emailOtpSigning);
    if (
      !attempt.retryingFreshAuth &&
      !alreadyAttemptedFreshAuth &&
      thresholdSessionRecord &&
      (isThresholdSessionAuthUnavailableError(error) || isSigningSessionBudgetExhaustedError(error))
    ) {
      const isEmailOtpSession = thresholdSessionRecord.source === 'email_otp';
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
          reason: isSigningSessionBudgetExhaustedError(error)
            ? 'wallet_signing_budget_reserved'
            : 'threshold_session_expired',
        },
      });
      return await signTransactionsWithActions(deps, args, {
        forceFreshAuth: true,
        operationId: operationId || createNearTransactionSigningOperationId(),
        retryingFreshAuth: true,
        signingSessionCoordinator,
      });
    }
    throw error;
  }
}

export async function signDelegateAction(
  deps: NearSigningApiDeps,
  args: SignDelegateActionInput,
): Promise<SignDelegateActionResult> {
  const nearAccountId = toAccountId(args.nearAccount.accountId);
  const normalizedRpcCall: RpcCallPayload = {
    nearRpcUrl: args.rpcCall.nearRpcUrl || deps.nearRpcUrl,
    nearAccountId,
  };

  try {
    const activeSessionId = resolveAdHocSigningRequestSessionId({
      deps,
      nearAccount: args.nearAccount,
    });
    console.debug('[SigningEngine][delegate] session created', { sessionId: activeSessionId });
    return await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      thresholdSessionId: activeSessionId,
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
        return (await signNearWithUiConfirm({
          chain: 'near',
          kind: 'delegateAction',
          payload: {
            ctx,
            nearAccount: args.nearAccount,
            delegate: args.delegate,
            rpcCall: normalizedRpcCall,
            signerSlot: args.signerSlot,
            confirmationConfigOverride: args.confirmationConfigOverride,
            title: args.title,
            body: args.body,
            onEvent: args.onEvent,
            sessionId: activeSessionId,
          },
        })) as unknown as SignDelegateActionResult;
      },
    });
  } catch (err) {
    console.error('[SigningEngine][delegate] failed', err);
    throw err;
  }
}

export async function signNEP413Message(
  deps: NearSigningApiDeps,
  payload: SignNep413MessagePayload,
): Promise<SignNep413MessageResult> {
  try {
    const nearAccountId = toAccountId(payload.nearAccount.accountId);
    const activeSessionId = resolveAdHocSigningRequestSessionId({
      deps,
      nearAccount: payload.nearAccount,
    });
    const result = await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      thresholdSessionId: activeSessionId,
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
        return (await signNearWithUiConfirm({
          chain: 'near',
          kind: 'nep413',
          payload: {
            ctx,
            nearAccount: payload.nearAccount,
            payload: {
              message: payload.message,
              recipient: payload.recipient,
              nonce: payload.nonce,
              state: payload.state,
              accountId: nearAccountId,
              signerSlot: payload.signerSlot,
              title: payload.title,
              body: payload.body,
              confirmationConfigOverride: payload.confirmationConfigOverride,
              sessionId: activeSessionId,
            },
          },
        })) as unknown as SignNep413MessageResult;
      },
    });
    if (result.success) {
      return result;
    }
    throw new Error(`NEP-413 signing failed: ${result.error || 'Unknown error'}`);
  } catch (error: unknown) {
    console.error('SigningEngine: NEP-413 signing error:', error);
    const message = error instanceof Error ? error.message : String(error || 'Unknown error');
    return {
      success: false,
      accountId: '',
      publicKey: '',
      signature: '',
      error: message,
    };
  }
}
