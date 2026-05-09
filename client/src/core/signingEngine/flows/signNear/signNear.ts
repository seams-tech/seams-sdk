import { toAccountId, type AccountId } from '@/core/types/accountIds';
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
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
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
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import {
  buildEd25519SessionPolicy,
  isThresholdSessionAuthUnavailableError,
} from '../../threshold/sessionPolicy';
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
  toWalletSubjectId,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  isSigningSessionBudgetExhaustedError,
  SigningSessionCoordinator,
  type SigningSessionReadiness,
} from '../../session/SigningSessionCoordinator';
import type { SigningSessionBudgetStatusAuth } from '../../session/budget/budget';
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
  accountId: AccountId;
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

export type SignDelegateActionInput = {
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

function normalizePositiveUses(value: unknown, fallback = 1): number {
  const normalized = Math.floor(Number(value) || 0);
  return normalized > 0 ? normalized : Math.max(1, Math.floor(Number(fallback) || 1));
}

function resolveTransactionStepUpSessionUses(operationUsesNeeded?: number): number {
  return normalizePositiveUses(operationUsesNeeded, 1);
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
  prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
  resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
  complete: (
    otpCode: string,
    challengeId?: string,
  ) => Promise<{ sessionId: string; sessionState?: ResolvedThresholdEd25519SessionState }>;
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
  const cryptoObj = globalThis as { crypto?: { randomUUID?: () => string } };
  const randomId =
    typeof cryptoObj.crypto?.randomUUID === 'function'
      ? cryptoObj.crypto.randomUUID()
      : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  return SigningSessionIds.signingOperation(`near-transaction-sign:${randomId}`);
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
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord;
  selectedLane: SelectedEd25519Lane;
}) {
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
      accountId: args.nearAccountId,
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
      retention: args.record.emailOtpAuthContext?.retention || 'session',
      sessionOrigin:
        args.record.emailOtpAuthContext?.reason === 'login' ? 'login' : 'per_operation',
    });
  }
  return buildNearTransactionSigningLane({
    accountId: args.nearAccountId,
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
      remainingUses: Math.max(0, Math.floor(Number(readiness.remainingUses) || 0)),
      expiresAtMs: Math.max(0, Math.floor(Number(readiness.expiresAtMs) || 0)),
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
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord;
  usesNeeded?: number;
}): Promise<{
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
}> {
  const sessionId = String(args.record.thresholdSessionId || '').trim();
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(sessionId);
  const usesNeeded = Math.max(1, Math.floor(Number(args.usesNeeded) || 1));
  const resolveExpiresAtMs = (): number => args.record.expiresAtMs;
  const resolveRemainingUses = (): number => args.record.remainingUses;
  const buildReadiness = (
    status: SigningSessionReadiness['status'],
    remainingUses = resolveRemainingUses(),
    expiresAtMs = resolveExpiresAtMs(),
  ) => ({
    readiness: {
      status,
      thresholdSessionId,
    },
    expiresAtMs,
    remainingUses,
  });

  const isSingleUseEmailOtpRecord =
    args.record.source === 'email_otp' &&
    args.record.emailOtpAuthContext?.retention === 'single_use';
  if (!sessionId || isSingleUseEmailOtpRecord || !hasThresholdEd25519RouteAuth(args.record)) {
    return buildReadiness('missing_session', 0);
  }

  const liveStatus =
    (await args.preConfirmDeps
      .getWarmThresholdEd25519SessionStatusForSession?.({
        nearAccountId: args.nearAccountId,
        thresholdSessionId: sessionId,
      })
      .catch(() => null)) || null;
  if (liveStatus?.sessionId === sessionId) {
    if (liveStatus.status === 'expired') return buildReadiness('expired', 0);
    if (liveStatus.status === 'exhausted') return buildReadiness('exhausted', 0);
    if (liveStatus.status !== 'active') return buildReadiness('missing_session', 0);
    const remainingUses = Math.floor(Number(liveStatus.remainingUses) || 0);
    if (remainingUses < usesNeeded) return buildReadiness('exhausted', remainingUses);
    return buildReadiness(
      'ready',
      remainingUses,
      Math.floor(Number(liveStatus.expiresAtMs) || args.record.expiresAtMs),
    );
  }

  if (args.preConfirmDeps.hasUiConfirm()) return buildReadiness('missing_session', 0);
  const remainingUses = resolveRemainingUses();
  const expiresAtMs = resolveExpiresAtMs();
  if (remainingUses < usesNeeded) return buildReadiness('exhausted', remainingUses, expiresAtMs);
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
    walletSigningSessionId,
    curve: 'ed25519',
  };
}

async function resolveNearTransactionWalletAuth(args: {
  deps: NearSigningApiDeps;
  confirmedDeps: NearTransactionConfirmedSigningDeps;
  nearAccountId: AccountId;
  preparedOperation: PreparedNearEd25519Operation;
  onEvent?: (update: SigningFlowEvent) => void;
  usesNeeded?: number;
}): Promise<{
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
  emailOtpSigning?: {
    prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
    resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
    complete: (
      otpCode: string,
      challengeId?: string,
    ) => Promise<{ sessionId: string; sessionState?: ResolvedThresholdEd25519SessionState }>;
  };
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
    accountId: args.nearAccountId,
    intent: SigningOperationIntent.TransactionSign,
    curve: 'ed25519' as const,
  };
  const plan = preparedOperation.signingSessionPlan;
  if (plan.kind === SigningSessionPlanKind.NotReady) {
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
  const prepareEmailOtpChallenge = async () => {
    if (typeof args.confirmedDeps.requestEmailOtpTransactionSigningChallenge !== 'function') {
      throw new Error('[SigningEngine] Email OTP per-operation NEAR signing is not configured');
    }
    emitNearSigningEvent(args.onEvent, args.nearAccountId, {
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
      nearAccountId: args.nearAccountId,
      chain: 'near',
      ...(authLane ? { authLane } : {}),
    });
    const challengeId = String(challenge.challengeId || '').trim();
    if (!challengeId) {
      throw new Error('[SigningEngine] Email OTP challenge response did not include challengeId');
    }
    emitNearSigningEvent(args.onEvent, args.nearAccountId, {
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
      complete: async (otpCode: string, challengeId?: string) => {
        const resolvedChallengeId = String(
          challengeId || activeChallenge?.challengeId || '',
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
        const sessionBudgetUses = resolveTransactionStepUpSessionUses(args.usesNeeded);
        const authLane =
          args.confirmedDeps.resolveEmailOtpSigningSessionAuthLane?.({
            thresholdSessionId: record.thresholdSessionId,
            curve: 'ed25519',
          }) || emailOtpEd25519AuthLaneFromRecord(record);
        const emailOtpAuthentication =
          await args.confirmedDeps.loginWithEmailOtpEd25519CapabilityForSigning({
            nearAccountId: args.nearAccountId,
            challengeId: resolvedChallengeId,
            otpCode,
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
  nearAccountId: AccountId;
}): string {
  if (typeof args.deps.resolveThresholdEd25519SessionId === 'function') {
    const canonical = String(
      args.deps.resolveThresholdEd25519SessionId(args.nearAccountId) || '',
    ).trim();
    if (canonical) return canonical;
  }
  return args.deps.createSigningSessionId('threshold-ed25519');
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

function verifiedRuntimeNearEd25519AvailableLanes(args: {
  availableLanes: AvailableSigningLanes | null;
  nearAccountId: AccountId;
}): NearEd25519AvailableLane[] {
  const runtimeLanes: NearEd25519AvailableLane[] = [];
  for (const lane of args.availableLanes?.candidates.ed25519.near || []) {
    if (lane.authMethod !== 'email_otp' && lane.authMethod !== 'passkey') continue;
    if (lane.source !== 'runtime_session_record' && lane.source !== 'runtime_and_durable') continue;
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
  nearAccountId: AccountId;
  availableLanes: AvailableSigningLanes | null;
}): Promise<NearEd25519SelectedTransactionLane | null> {
  const selectByAuthMethod = (
    authMethod: 'email_otp' | 'passkey',
    currentRuntimeLane?: NearEd25519AvailableLane | null,
  ) =>
    selectNearEd25519TransactionCandidate({
      availableLanes: args.availableLanes,
      authSelectionPolicy: { kind: 'account_class', authMethod },
      nearAccountId: args.nearAccountId,
      ...(currentRuntimeLane ? { currentRuntimeLane } : {}),
    });

  const runtimeLanes = verifiedRuntimeNearEd25519AvailableLanes({
    availableLanes: args.availableLanes,
    nearAccountId: args.nearAccountId,
  });
  if (runtimeLanes.length === 1) {
    const runtimeLane = runtimeLanes[0]!;
    return selectByAuthMethod(runtimeLane.authMethod, runtimeLane);
  }

  const accountSelectedAuthMethod = await args.deps
    .resolveAccountAuthMethodForSigning?.({
      nearAccountId: args.nearAccountId,
      curve: 'ed25519',
      chain: 'near',
    })
    .catch((error) => {
      console.warn('[SigningEngine][near] Ed25519 auth-method selection failed', {
        nearAccountId: args.nearAccountId,
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
  nearAccountId: AccountId;
  authMethod: 'email_otp' | 'passkey' | null;
}): Promise<AvailableSigningLanes | null> {
  if (typeof args.deps.readAvailableSigningLanesForSigning !== 'function') {
    throw new Error('[SigningEngine][near] transaction signing requires available signing lanes reader');
  }
  return await args.deps
    .readAvailableSigningLanesForSigning({
      walletId: args.nearAccountId,
      subjectId: toWalletSubjectId(args.nearAccountId),
      curve: 'ed25519',
      ...(args.authMethod ? { authMethod: args.authMethod } : {}),
    })
    .catch((error) => {
      console.warn('[SigningEngine][near] available signing lanes read failed', {
        nearAccountId: args.nearAccountId,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
      return null;
    });
}

async function restoreNearEd25519SelectedSigningSession(args: {
  deps: NearSigningApiDeps;
  nearAccountId: AccountId;
  selectedLane: SelectedEd25519Lane | null;
  candidate: Ed25519LaneCandidate | null;
}): Promise<void> {
  if (typeof args.deps.restorePersistedSessionForSigning !== 'function') return;
  const selectedLane = args.selectedLane;
  if (!selectedLane) {
    console.debug(
      '[SigningEngine][near] Ed25519 restore skipped without selected available lane',
      {
        nearAccountId: args.nearAccountId,
      },
    );
    return;
  }
  if (args.candidate?.source === 'runtime_session_record' && args.candidate.state === 'ready') {
    return;
  }
  await args.deps.restorePersistedSessionForSigning({
    walletId: args.nearAccountId,
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
  nearAccountId: AccountId;
  signingSessionCoordinator: SigningSessionCoordinator;
  ed25519Warmup?: NearEd25519Warmup;
  availableLanes?: AvailableSigningLanes | null;
  selectedLane: NearEd25519SelectedTransactionLane;
}): Promise<NearEd25519TransactionOperationPrepareResult> {
  const selectedSessionLane = args.selectedLane.lane;
  await restoreNearEd25519SelectedSigningSession({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    selectedLane: selectedSessionLane,
    candidate: args.selectedLane.candidate,
  });
  const restoreState = recordExactRestoreAttempt(args.selectedLane, {
    restored: Boolean(selectedSessionLane),
  });
  const recordForLifecycle = readNearEd25519RuntimeRecordForSelectedLane({
    selectedLane: selectedSessionLane,
    nearAccountId: args.nearAccountId,
  });
  publishNearEd25519RuntimeIdentityForRecord(recordForLifecycle);
  assertNearEd25519SelectedLaneMatchesRecord({
    selectedLane: selectedSessionLane,
    record: recordForLifecycle,
    nearAccountId: args.nearAccountId,
  });
  if (!selectedSessionLane || !recordForLifecycle) {
    console.warn('[SigningEngine][near] Ed25519 signing lane selection missing session', {
      nearAccountId: args.nearAccountId,
      hasSelectedLane: Boolean(selectedSessionLane),
      selectedLane: selectedSessionLane
        ? {
            authMethod: selectedSessionLane.authMethod,
            thresholdSessionId: String(selectedSessionLane.thresholdSessionId || ''),
            walletSigningSessionId: String(selectedSessionLane.walletSigningSessionId || ''),
          }
        : null,
      hasRuntimeRecord: Boolean(recordForLifecycle),
      runtimeRecord: recordForLifecycle
        ? {
            source: recordForLifecycle.source,
            thresholdSessionId: recordForLifecycle.thresholdSessionId,
            walletSigningSessionId: recordForLifecycle.walletSigningSessionId,
            remainingUses: recordForLifecycle.remainingUses,
            expiresAtMs: recordForLifecycle.expiresAtMs,
          }
        : null,
      availableLane: args.availableLanes?.lanes.ed25519.near || null,
      selectedLaneCandidate: args.selectedLane.candidate,
    });
    throw new Error('[SigningEngine][near] signing session is not ready: missing_session');
  }
  const lane = buildNearTransactionSigningLaneForSelectedLane({
    nearAccountId: args.nearAccountId,
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
    nearAccountId: args.nearAccountId,
    record: recordForLifecycle,
    usesNeeded: 1,
  });
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
      usesNeeded: 1,
    }),
  );
  const transactionOperation = prepareTransactionOperationFromReadiness(transactionReadinessState);
  const identity = requireResolvedNearEd25519SigningLane(lane);
  const readinessInput = {
    readiness: readiness.readiness,
    expiresAtMs: readiness.expiresAtMs,
    remainingUses: readiness.remainingUses,
    usesNeeded: 1,
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
  nearAccountId: AccountId;
  signingSessionCoordinator: SigningSessionCoordinator;
  forceFreshAuth?: boolean;
}): Promise<PreparedNearEd25519TransactionSigningSession> {
  const hasPendingEmailOtpEd25519Warmup = (): boolean =>
    args.deps.isEmailOtpEd25519WarmupPending?.({ nearAccountId: args.nearAccountId }) === true;
  if (hasPendingEmailOtpEd25519Warmup()) {
    emitNearSigningEvent(args.input.onEvent, args.nearAccountId, {
      phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
      status: 'running',
      message: 'Finalizing NEAR signing session',
      interaction: { kind: 'none', overlay: 'none' },
    });
    await args.deps.waitForPendingEmailOtpEd25519Warmup?.({ nearAccountId: args.nearAccountId });
  }
  const ed25519Warmup =
    hasPendingEmailOtpEd25519Warmup() &&
    typeof args.deps.waitForPendingEmailOtpEd25519Warmup === 'function'
      ? {
          isPending: hasPendingEmailOtpEd25519Warmup,
          waitForReady: () =>
            args.deps.waitForPendingEmailOtpEd25519Warmup!({
              nearAccountId: args.nearAccountId,
            }),
        }
      : undefined;
  const availableLanes = await readNearEd25519AvailableSigningLanes({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    authMethod: null,
  });
  const selectedLane = await selectSelectedEd25519LaneFromAvailableLanes({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    availableLanes,
  });
  if (!selectedLane) {
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
      walletId: String(args.nearAccountId),
      curve: 'ed25519',
      chain: 'near',
      authSelectionPolicy: initialAuthSelectionPolicy,
      operationUsesNeeded: 1,
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
          nearAccountId: args.nearAccountId,
          signingSessionCoordinator: args.signingSessionCoordinator,
          availableLanes,
          selectedLane,
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
    nearAccountId: args.nearAccountId,
    preparedOperation,
    onEvent: args.input.onEvent,
    usesNeeded: 1,
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
  const nearAccountId = toAccountId(args.rpcCall.nearAccountId);
  const inputWithConfirmationTracking: SignTransactionsWithActionsInput = args;
  let operationId = attempt.operationId;
  const ensureOperationId = (): SigningOperationId => {
    operationId = operationId || createNearTransactionSigningOperationId();
    return operationId;
  };
  const signingSessionCoordinator =
    attempt.signingSessionCoordinator || deps.signingSessionCoordinator;
  const preparedSigningSession = await prepareNearEd25519TransactionSigningSession({
    deps,
    input: inputWithConfirmationTracking,
    nearAccountId,
    signingSessionCoordinator,
    forceFreshAuth: attempt.forceFreshAuth === true,
  });
  const thresholdSessionRecord = preparedSigningSession.thresholdSessionRecord;
  const signingAuthPlan = preparedSigningSession.signingAuthPlan;
  const signingLane = preparedSigningSession.signingLane;
  const transactionLane = preparedSigningSession.transactionLane;
  const emailOtpSigning = preparedSigningSession.emailOtpSigning;
  const ed25519Warmup = preparedSigningSession.ed25519Warmup;
  const resolvedSessionId = preparedSigningSession.resolvedSessionId;
  const budget = preparedSigningSession.budget;
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
        const confirmationOperationId = ensureOperationId();
        const ed25519SigningBoundary = {
          sessionId: resolvedSessionId,
          signingSessionPlan: preparedSigningSession.preparedOperation.signingSessionPlan,
          signingAuthPlan,
          signingLane,
          initialBudgetAdmittedOperation: budget.kind === 'admitted' ? budget.operation : null,
        };
        const payload: NearTransactionsWithActionsPayload = {
          ctx,
          transactions: inputWithConfirmationTracking.transactions,
          rpcCall: inputWithConfirmationTracking.rpcCall,
          signerSlot: inputWithConfirmationTracking.signerSlot,
          confirmationConfigOverride: inputWithConfirmationTracking.confirmationConfigOverride,
          title: inputWithConfirmationTracking.title,
          body: inputWithConfirmationTracking.body,
          onEvent: inputWithConfirmationTracking.onEvent,
          ...(emailOtpSigning ? { emailOtpSigning } : {}),
          signingOperationId: confirmationOperationId,
          signingSessionCoordinator,
          transactionOperation: preparedSigningSession.transactionOperation,
          ed25519SigningBoundary,
          ...(ed25519Warmup ? { ed25519Warmup } : {}),
          ...(signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth &&
          thresholdSessionRecord &&
          typeof deps.reconnectPasskeyEd25519CapabilityForSigning === 'function'
            ? {
                passkeyEd25519Reconnect: {
                  prepare: async ({ usesNeeded }: { usesNeeded: number }) => {
                    const sessionBudgetUses = resolveTransactionStepUpSessionUses(usesNeeded);
                    const rpId = String(ctx.touchIdPrompt.getRpId() || '').trim();
                    if (!rpId) {
                      throw new Error('[SigningEngine] missing rpId for passkey Ed25519 reauth');
                    }
                    const { policy, sessionPolicyDigest32 } = await buildEd25519SessionPolicy({
                      nearAccountId,
                      rpId,
                      relayerKeyId: thresholdSessionRecord.relayerKeyId,
                      ...(thresholdSessionRecord.runtimePolicyScope
                        ? { runtimePolicyScope: thresholdSessionRecord.runtimePolicyScope }
                        : {}),
                      participantIds: thresholdSessionRecord.participantIds,
                      ...(thresholdSessionRecord.walletSigningSessionId
                        ? {
                            walletSigningSessionId: thresholdSessionRecord.walletSigningSessionId,
                          }
                        : {}),
                      remainingUses: sessionBudgetUses,
                    });
                    return {
                      sessionId: policy.sessionId,
                      walletSigningSessionId: policy.walletSigningSessionId,
                      sessionPolicyDigest32,
                    };
                  },
                  reconnect: async ({
                    credential,
                    usesNeeded,
                    sessionId,
                    walletSigningSessionId,
                  }: {
                    credential: WebAuthnAuthenticationCredential;
                    usesNeeded: number;
                    sessionId?: string;
                    walletSigningSessionId?: string;
                  }) => {
                    const refreshed = await deps.reconnectPasskeyEd25519CapabilityForSigning!({
                      nearAccountId,
                      record: thresholdSessionRecord,
                      localPrfCredential: credential,
                      usesNeeded,
                      remainingUses: resolveTransactionStepUpSessionUses(usesNeeded),
                      ...(sessionId ? { sessionId } : {}),
                      ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
                    });
                    const sessionState = resolveThresholdEd25519SessionStateFromRecord(
                      refreshed.record,
                    );
                    return {
                      sessionId: refreshed.sessionId,
                      ...(sessionState ? { sessionState } : {}),
                    };
                  },
                },
              }
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
      Boolean(emailOtpSigning);
    if (
      !attempt.retryingFreshAuth &&
      !alreadyAttemptedFreshAuth &&
      thresholdSessionRecord &&
      (isThresholdSessionAuthUnavailableError(error) || isSigningSessionBudgetExhaustedError(error))
    ) {
      const isEmailOtpSession = thresholdSessionRecord.source === 'email_otp';
      emitNearSigningEvent(inputWithConfirmationTracking.onEvent, nearAccountId, {
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
  const nearAccountId = toAccountId(args.rpcCall.nearAccountId || args.delegate.senderId);
  const normalizedRpcCall: RpcCallPayload = {
    nearRpcUrl: args.rpcCall.nearRpcUrl || deps.nearRpcUrl,
    nearAccountId,
  };

  try {
    const activeSessionId = resolveAdHocSigningRequestSessionId({
      deps,
      nearAccountId,
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
    const nearAccountId = toAccountId(payload.accountId);
    const activeSessionId = resolveAdHocSigningRequestSessionId({
      deps,
      nearAccountId,
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
            payload: {
              ...payload,
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
