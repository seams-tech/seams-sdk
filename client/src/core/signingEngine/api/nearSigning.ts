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
import type { NearTransactionsWithActionsPayload } from '../interfaces/near';
import type { SignTransactionResult } from '@/core/types/seams';
import type { TransactionInputWasm } from '@/core/types/actions';
import {
  SENSITIVE_OPERATION_POLICIES,
  type SensitiveOperationPolicy,
} from '@shared/utils/signerDomain';
import type { EmailOtpAuthLane } from '../emailOtp/authLane';
import {
  createEmailOtpWalletAuthAdapter,
  createPasskeyWalletAuthAdapter,
} from '@/core/signingEngine/auth';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import type { SignerWorkerManagerContext } from '../workerManager';
import { signNearWithTouchConfirm } from '../orchestration/near/nearSigningFlow';
import { resolveThresholdEd25519CommitQueueKey } from './thresholdLifecycle/thresholdEd25519CommitQueue';
import {
  getStoredThresholdEd25519SessionRecordForAccount,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  upsertStoredThresholdEd25519SessionRecord,
  type ThresholdEd25519SessionRecord,
  type ThresholdEd25519SessionStoreSource,
} from './thresholdLifecycle/thresholdSessionStore';
import type {
  SigningSessionSnapshot,
  SigningSessionSnapshotEd25519Lane,
} from '../session/snapshotReader';
import type { RestorePersistedSessionForSigningInput } from '../session/restoreCoordinator';
import {
  listResolvedIdentitiesForAccount,
  publishResolvedIdentity,
} from '../session/sealedSessionStore';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import {
  buildEd25519SessionPolicy,
  isThresholdSessionAuthUnavailableError,
} from '../threshold/session/sessionPolicy';
import {
  SigningOperationIntent,
  SigningSessionPlanKind,
  SigningSessionIds,
  type ResolvedEd25519SigningSessionIdentity,
  type SelectedSigningLaneIdentity,
  type SigningLaneContext,
  type SigningOperationId,
} from '../session/signingSession/types';
import { buildNearTransactionSigningLane } from '../session/signingSession/lanes';
import {
  isSigningSessionBudgetExhaustedError,
  SigningSessionCoordinator,
  type SigningSessionReadiness,
} from '../session/SigningSessionCoordinator';
import type { SigningSessionPreparedBudgetIdentity } from '../session/signingSession/budget';
import { signingAuthPlanFromSigningSessionPlan } from '../orchestration/shared/touchConfirmSigning';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningLaneResolutionTrace,
  emitSigningPlannerDecisionTrace,
} from '../session/signingSession/trace';
import {
  executePreparedThresholdSigning,
  finalizePreparedThresholdSigning,
  prepareThresholdSigningOperation,
  type PreparedThresholdSigningOperation,
  type ThresholdSigningReadinessInput,
} from '../session/signingSession/preparedOperation';
import {
  selectTransactionLane,
  type NearEd25519ConcreteSnapshotLane,
  type TransactionAuthSelectionPolicy,
} from '../session/signingSession/transactionState';

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

type NearEd25519SigningSessionStatus = {
  sessionId?: string | null;
  status?: string | null;
  remainingUses?: number | null;
  expiresAtMs?: number | null;
};

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

export type NearSigningApiDeps = {
  nearRpcUrl: string;
  resolveThresholdEd25519SessionId?: (nearAccountId: AccountId) => string | null;
  requestEmailOtpTransactionSigningChallenge?: (args: {
    nearAccountId: AccountId | string;
    chain: 'near';
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ challengeId: string; emailHint?: string }>;
  resolveEmailOtpSigningSessionAuthLane?: (args: {
    thresholdSessionId: string;
    curve: 'ed25519';
  }) => EmailOtpAuthLane | null;
  isEmailOtpEd25519WarmupPending?: (args: { nearAccountId: AccountId | string }) => boolean;
  waitForPendingEmailOtpEd25519Warmup?: (args: {
    nearAccountId: AccountId | string;
  }) => Promise<boolean>;
  loginWithEmailOtpEd25519CapabilityForSigning?: (args: {
    nearAccountId: AccountId | string;
    challengeId: string;
    otpCode: string;
    record: ThresholdEd25519SessionRecord;
    remainingUses?: number;
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }>;
  restorePersistedSessionForSigning?: (
    args: RestorePersistedSessionForSigningInput,
  ) => Promise<unknown>;
  reconnectPasskeyEd25519CapabilityForSigning?: (args: {
    nearAccountId: AccountId | string;
    record: ThresholdEd25519SessionRecord;
    localPrfCredential: WebAuthnAuthenticationCredential;
    usesNeeded?: number;
    remainingUses?: number;
    sessionId?: string;
    walletSigningSessionId?: string;
  }) => Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }>;
  resolveAccountAuthMethodForSigning?: (args: {
    nearAccountId: AccountId | string;
    curve: 'ed25519';
    chain: 'near';
  }) => Promise<'email_otp' | 'passkey' | null>;
  signingSessionCoordinator: SigningSessionCoordinator;
  readSigningSessionSnapshotForSigning?: (args: {
    walletId: AccountId | string;
    authMethod?: 'email_otp' | 'passkey';
  }) => Promise<SigningSessionSnapshot>;
  getWarmThresholdEd25519SessionStatusForSession?: (args: {
    nearAccountId: AccountId | string;
    thresholdSessionId: string;
  }) => Promise<NearEd25519SigningSessionStatus | null>;
  createSigningSessionId: (prefix: string) => string;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  withThresholdEd25519CommitQueue: <T>(args: {
    queueKey: string;
    nearAccountId: AccountId | string;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }) => Promise<T>;
};

type NearTransactionPreConfirmSigningDeps = {
  getWarmThresholdEd25519SessionStatusForSession?: NearSigningApiDeps['getWarmThresholdEd25519SessionStatusForSession'];
  signingSessionCoordinator: SigningSessionCoordinator;
  hasTouchConfirm: () => boolean;
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
  ) => Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }>;
};

type NearEd25519SelectedIdentity = SelectedSigningLaneIdentity & {
  curve: 'ed25519';
  chainFamily: 'near';
};

type NearEd25519PreparedIdentity = ResolvedEd25519SigningSessionIdentity;

type PreparedNearEd25519TransactionSigningSession = {
  thresholdSessionRecord: ThresholdEd25519SessionRecord | null;
  signingAuthPlan: SigningAuthPlan;
  signingLane: SigningLaneContext;
  identity: NearEd25519PreparedIdentity;
  resolvedSessionId: string;
  snapshotGeneration: number;
  preparedOperation: PreparedNearEd25519Operation;
  budgetIdentity?: SigningSessionPreparedBudgetIdentity;
  budgetProjectionVersion?: string;
  ed25519Warmup?: {
    isPending: () => boolean;
    waitForReady: () => Promise<boolean>;
  };
  emailOtpSigning?: NearEd25519EmailOtpSigning;
};

type NearEd25519LifecycleMetadata = {
  thresholdSessionRecord: ThresholdEd25519SessionRecord;
  identity: NearEd25519PreparedIdentity;
  snapshotGeneration: number;
  readiness: ThresholdSigningReadinessInput;
  ed25519Warmup?: {
    isPending: () => boolean;
    waitForReady: () => Promise<boolean>;
  };
};

type PreparedNearEd25519Operation = PreparedThresholdSigningOperation<
  SigningLaneContext,
  NearEd25519LifecycleMetadata
>;

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

function buildNearTransactionLaneFromPreparedIdentity(args: {
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord;
  identity: NearEd25519SelectedIdentity;
}) {
  const sessionId = String(args.identity.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(args.identity.walletSigningSessionId || '').trim();
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

function requireResolvedNearEd25519SigningLane(
  lane: SigningLaneContext,
): NearEd25519PreparedIdentity {
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
  // Prepared identity is copied from the executable lane so challenge, budget,
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

  if (args.preConfirmDeps.hasTouchConfirm()) return buildReadiness('missing_session', 0);
  const remainingUses = resolveRemainingUses();
  const expiresAtMs = resolveExpiresAtMs();
  if (remainingUses < usesNeeded) return buildReadiness('exhausted', remainingUses, expiresAtMs);
  return buildReadiness('ready', remainingUses, expiresAtMs);
}

function hasThresholdEd25519RouteAuth(record: ThresholdEd25519SessionRecord): boolean {
  if (record.thresholdSessionKind === 'cookie') return true;
  return Boolean(String(record.thresholdSessionJwt || '').trim());
}

function emailOtpEd25519AuthLaneFromRecord(
  record: ThresholdEd25519SessionRecord | null | undefined,
): EmailOtpAuthLane | undefined {
  const jwt = String(record?.thresholdSessionJwt || '').trim();
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
  signingLane: SigningLaneContext;
  budgetIdentity?: SigningSessionPreparedBudgetIdentity;
  emailOtpSigning?: {
    prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
    resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
    complete: (
      otpCode: string,
      challengeId?: string,
    ) => Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }>;
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
    accountAuth: {
      primaryAuthMethod: lane.authMethod,
      linkedAuthMethods: [lane.authMethod],
    },
    intent: SigningOperationIntent.TransactionSign,
    curve: 'ed25519' as const,
  };
  const passkeyAuthAdapter = createPasskeyWalletAuthAdapter({
    challenge: async () => ({}),
    complete: async () => ({
      method: 'passkey',
      webauthnAuthentication: {},
    }),
  });
  const emailOtpAuthAdapter = createEmailOtpWalletAuthAdapter({
    challenge: async () => {
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
      return {
        challengeId,
        email: String(challenge.emailHint || '').trim(),
      };
    },
    complete: async ({ challengeId, code }) => {
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
      const refreshed = await args.confirmedDeps.loginWithEmailOtpEd25519CapabilityForSigning({
        nearAccountId: args.nearAccountId,
        challengeId,
        otpCode: code,
        record,
        ...(authLane ? { authLane } : {}),
        remainingUses: sessionBudgetUses,
      });
      return {
        method: 'email_otp',
        emailOtpAuthentication: refreshed,
      };
    },
  });
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
  if (signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth) {
    await passkeyAuthAdapter.createPasskeyReauthPlan(authInput);
  }
  if (signingAuthPlan.kind !== SigningAuthPlanKind.EmailOtpReauth) {
    return {
      signingAuthPlan,
      signingLane: lane,
      ...(preparedOperation.budgetIdentity
        ? { budgetIdentity: preparedOperation.budgetIdentity }
        : {}),
    };
  }

  const emailOtpAuthBridge = await emailOtpAuthAdapter.createEmailOtpReauthPlan(authInput);

  let activeChallenge: { challengeId: string; email?: string } | null = null;
  const prepareEmailOtpChallenge = async () => {
    activeChallenge = await emailOtpAuthBridge.challenge();
    return {
      challengeId: activeChallenge.challengeId,
      ...(activeChallenge.email ? { emailHint: activeChallenge.email } : {}),
    };
  };
  return {
    signingAuthPlan,
    signingLane: lane,
    ...(preparedOperation.budgetIdentity
      ? { budgetIdentity: preparedOperation.budgetIdentity }
      : {}),
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
        const proof = await emailOtpAuthBridge.complete({
          challengeId: resolvedChallengeId,
          code: otpCode,
        });
        const emailOtpAuthentication = proof.emailOtpAuthentication as {
          sessionId: string;
          record?: ThresholdEd25519SessionRecord;
        };
        if (emailOtpAuthentication.record) {
          // OTP step-up mints the replacement Ed25519 runtime lane. Publish it
          // before signing/finalization so budget sync targets the same lane.
          upsertStoredThresholdEd25519SessionRecord(emailOtpAuthentication.record);
        }
        return emailOtpAuthentication;
      },
    },
  };
}

function resolvePreparedSigningRequestSessionId(args: {
  providedSessionId?: string;
  identity: NearEd25519PreparedIdentity;
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

function concreteEd25519LaneFromRuntimeRecord(args: {
  record: ThresholdEd25519SessionRecord;
  nearAccountId: AccountId;
}): NearEd25519ConcreteSnapshotLane | null {
  const thresholdSessionId = String(args.record.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(args.record.walletSigningSessionId || '').trim();
  if (
    String(args.record.nearAccountId || '').trim() !== String(args.nearAccountId || '').trim() ||
    !thresholdSessionId ||
    !walletSigningSessionId
  ) {
    return null;
  }
  // The current runtime record is already an exact transaction lane identity.
  // Snapshot readers should normally echo it, but a missing snapshot candidate
  // must not turn an OTP/passkey lane into a generic missing-session failure.
  return {
    authMethod: authMethodForThresholdEd25519Record(args.record),
    curve: 'ed25519',
    chain: 'near',
    state: 'ready',
    source: 'runtime_session_record',
    thresholdSessionId,
    walletSigningSessionId,
    remainingUses: Math.max(0, Math.floor(Number(args.record.remainingUses) || 0)),
    expiresAtMs: Math.max(0, Math.floor(Number(args.record.expiresAtMs) || 0)),
    updatedAtMs: Math.max(0, Math.floor(Number(args.record.updatedAtMs) || 0)),
  };
}

function thresholdEd25519RecordMatchesSelectedIdentity(args: {
  record: ThresholdEd25519SessionRecord;
  identity: NearEd25519SelectedIdentity;
  nearAccountId: AccountId;
}): boolean {
  return (
    String(args.record.nearAccountId || '').trim() === String(args.nearAccountId || '').trim() &&
    authMethodForThresholdEd25519Record(args.record) === args.identity.authMethod &&
    String(args.record.thresholdSessionId || '').trim() ===
      String(args.identity.thresholdSessionId || '').trim() &&
    String(args.record.walletSigningSessionId || '').trim() ===
      String(args.identity.walletSigningSessionId || '').trim()
  );
}

function selectNearEd25519TransactionCandidate(args: {
  snapshot: SigningSessionSnapshot | null;
  authSelectionPolicy: TransactionAuthSelectionPolicy | null;
  runtimeRecord: ThresholdEd25519SessionRecord | null;
  nearAccountId: AccountId;
}): NearEd25519ConcreteSnapshotLane | null {
  const runtimeLane = args.runtimeRecord
    ? concreteEd25519LaneFromRuntimeRecord({
        record: args.runtimeRecord,
        nearAccountId: args.nearAccountId,
      })
    : null;
  const authSelectionPolicy =
    args.authSelectionPolicy ||
    (runtimeLane
      ? ({
          kind: 'current_lane',
          authMethod: runtimeLane.authMethod,
        } satisfies TransactionAuthSelectionPolicy)
      : null);
  if (!authSelectionPolicy) return null;

  const selection = selectTransactionLane({
    intent: {
      walletId: args.nearAccountId,
      curve: 'ed25519',
      chain: 'near',
      authSelectionPolicy,
      operationUsesNeeded: 1,
    },
    snapshot: args.snapshot,
    currentRuntimeLane: runtimeLane,
  });
  if (selection.ok) return selection.snapshotLane;
  if (selection.failure.kind === 'no_candidate') return null;
  throw new Error(
    `[SigningEngine][near] Ed25519 transaction lane selection failed: ${selection.failure.kind}`,
  );
}

function resolveNearEd25519SelectedIdentityFromSnapshot(args: {
  nearAccountId: AccountId;
  snapshot: SigningSessionSnapshot | null;
  candidate: NearEd25519ConcreteSnapshotLane | null;
}): NearEd25519SelectedIdentity | null {
  if (!args.candidate) return null;
  return {
    accountId: toAccountId(args.snapshot?.walletId || args.nearAccountId),
    authMethod: args.candidate.authMethod,
    curve: 'ed25519',
    chainFamily: 'near',
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
      args.candidate.thresholdSessionId,
    ),
    walletSigningSessionId: SigningSessionIds.walletSigningSession(
      args.candidate.walletSigningSessionId,
    ),
  };
}

async function resolveNearEd25519AuthSelectionPolicy(args: {
  deps: NearSigningApiDeps;
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord | null;
}): Promise<TransactionAuthSelectionPolicy | null> {
  if (args.record?.source === 'email_otp') {
    return {
      kind: 'current_lane',
      authMethod: 'email_otp',
    };
  }

  const selected = await args.deps
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
  if (selected === 'email_otp' || selected === 'passkey') {
    return {
      kind: 'account_class',
      authMethod: selected,
    };
  }
  if (args.record) {
    return {
      kind: 'current_lane',
      authMethod: authMethodForThresholdEd25519Record(args.record),
    };
  }

  const identities = listResolvedIdentitiesForAccount({
    walletId: args.nearAccountId,
    curve: 'ed25519',
  });
  const authMethods = new Set(identities.map((identity) => identity.authMethod));
  if (authMethods.size === 1) {
    const authMethod = identities[0]?.authMethod || null;
    return authMethod
      ? {
          kind: 'account_class',
          authMethod,
        }
      : null;
  }
  if (authMethods.size > 1) {
    throw new Error(
      '[SigningEngine][near] Ed25519 transaction signing requires an explicit auth-method selector',
    );
  }
  return null;
}

function assertNearEd25519SelectedIdentityMatchesRecord(args: {
  identity: NearEd25519SelectedIdentity | null;
  record: ThresholdEd25519SessionRecord | null;
  nearAccountId: AccountId;
}): void {
  if (!args.identity || !args.record) return;
  if (thresholdEd25519RecordMatchesSelectedIdentity({
    record: args.record,
    identity: args.identity,
    nearAccountId: args.nearAccountId,
  })) {
    return;
  }
  throw new Error(
    `[SigningEngine][near] snapshot Ed25519 identity does not match runtime session record for ${String(args.nearAccountId)}`,
  );
}

function resolveNearEd25519RuntimeRecordForSelectedIdentity(args: {
  identity: NearEd25519SelectedIdentity | null;
  fallback: ThresholdEd25519SessionRecord | null;
  nearAccountId: AccountId;
}): ThresholdEd25519SessionRecord | null {
  if (!args.identity) return args.fallback;
  const thresholdSessionId = String(args.identity.thresholdSessionId || '').trim();
  const exactRecord = thresholdSessionId
    ? getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId)
    : null;
  if (
    exactRecord &&
    thresholdEd25519RecordMatchesSelectedIdentity({
      record: exactRecord,
      identity: args.identity,
      nearAccountId: args.nearAccountId,
    })
  ) {
    return exactRecord;
  }
  if (
    args.fallback &&
    thresholdEd25519RecordMatchesSelectedIdentity({
      record: args.fallback,
      identity: args.identity,
      nearAccountId: args.nearAccountId,
    })
  ) {
    return args.fallback;
  }
  return null;
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

async function readNearEd25519SigningSnapshot(args: {
  deps: NearSigningApiDeps;
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord | null;
  authMethod: 'email_otp' | 'passkey' | null;
}): Promise<SigningSessionSnapshot | null> {
  if (typeof args.deps.readSigningSessionSnapshotForSigning !== 'function') {
    const identities = listResolvedIdentitiesForAccount({
      walletId: args.nearAccountId,
      ...(args.authMethod ? { authMethod: args.authMethod } : {}),
      curve: 'ed25519',
    });
    const identity =
      identities.find((candidate) => {
        if (!args.record) return true;
        return (
          candidate.thresholdSessionId === args.record.thresholdSessionId &&
          candidate.walletSigningSessionId === args.record.walletSigningSessionId
        );
      }) || identities[0];
    if (!identity) return null;
    const lane: SigningSessionSnapshotEd25519Lane = {
      authMethod: identity.authMethod,
      curve: 'ed25519',
      chain: 'near',
      state: 'ready',
      thresholdSessionId: identity.thresholdSessionId,
      walletSigningSessionId: identity.walletSigningSessionId,
      source: 'runtime_session_record',
    };
    return {
      walletId: args.nearAccountId,
      generation: identity.updatedAtMs,
      lanes: {
        ed25519: {
          near: lane,
        },
        ecdsa: {
          tempo: { curve: 'ecdsa', chain: 'tempo', state: 'missing' },
          evm: { curve: 'ecdsa', chain: 'evm', state: 'missing' },
        },
      },
      candidates: {
        ed25519: {
          near: [lane],
        },
        ecdsa: {
          tempo: [],
          evm: [],
        },
      },
    };
  }
  return await args.deps
    .readSigningSessionSnapshotForSigning({
      walletId: args.nearAccountId,
      ...(args.authMethod ? { authMethod: args.authMethod } : {}),
    })
    .catch((error) => {
      console.warn('[SigningEngine][near] signing-session snapshot read failed', {
        nearAccountId: args.nearAccountId,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
      return null;
    });
}

async function restoreNearEd25519SelectedSigningSession(args: {
  deps: NearSigningApiDeps;
  nearAccountId: AccountId;
  identity: NearEd25519SelectedIdentity | null;
  snapshotLane: SigningSessionSnapshotEd25519Lane | null;
}): Promise<void> {
  if (typeof args.deps.restorePersistedSessionForSigning !== 'function') return;
  const identity = args.identity;
  if (!identity) {
    console.debug('[SigningEngine][near] Ed25519 restore skipped without selected snapshot lane', {
      nearAccountId: args.nearAccountId,
    });
    return;
  }
  if (args.snapshotLane?.source === 'runtime_session_record' && args.snapshotLane.state === 'ready') {
    return;
  }
  await args.deps.restorePersistedSessionForSigning({
    walletId: args.nearAccountId,
    authMethod: identity.authMethod,
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId: identity.walletSigningSessionId,
    thresholdSessionId: identity.thresholdSessionId,
    reason: 'transaction',
  });
}

async function prepareNearEd25519TransactionSigningSession(args: {
  deps: NearSigningApiDeps;
  input: SignTransactionsWithActionsInput;
  nearAccountId: AccountId;
  signingSessionCoordinator: SigningSessionCoordinator;
  forceFreshAuth?: boolean;
}): Promise<PreparedNearEd25519TransactionSigningSession> {
  let thresholdSessionRecord = getStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId);
  const hasPendingEmailOtpEd25519Warmup = (): boolean =>
    args.deps.isEmailOtpEd25519WarmupPending?.({ nearAccountId: args.nearAccountId }) === true;
  if (!thresholdSessionRecord && hasPendingEmailOtpEd25519Warmup()) {
    emitNearSigningEvent(args.input.onEvent, args.nearAccountId, {
      phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
      status: 'running',
      message: 'Finalizing NEAR signing session',
      interaction: { kind: 'none', overlay: 'none' },
    });
    await args.deps.waitForPendingEmailOtpEd25519Warmup?.({ nearAccountId: args.nearAccountId });
    thresholdSessionRecord = getStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId);
  }
  const ed25519Warmup =
    thresholdSessionRecord?.source === 'email_otp' &&
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

  const preparedOperation = await prepareThresholdSigningOperation({
    intent: {
      kind: 'transaction_sign',
      chain: 'near',
      curve: 'ed25519',
      walletId: String(args.nearAccountId),
      reason: 'transaction',
    },
    coordinator: args.signingSessionCoordinator,
    forceFreshAuth: args.forceFreshAuth === true,
    sensitiveOperationPolicy:
      args.input.sensitivePolicy || SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy,
    prepareBudgetIdentity: true,
    onPlannerTrace: (event) => emitSigningPlannerDecisionTrace('near', event),
    lifecycleAdapter: {
      prepare: async () => {
        let recordForLifecycle = getStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId);
        const authSelectionPolicy = await resolveNearEd25519AuthSelectionPolicy({
          deps: args.deps,
          nearAccountId: args.nearAccountId,
          record: recordForLifecycle,
        });
        const snapshot = await readNearEd25519SigningSnapshot({
          deps: args.deps,
          nearAccountId: args.nearAccountId,
          record: recordForLifecycle,
          authMethod: authSelectionPolicy?.authMethod || null,
        });
        const selectedAuthRuntimeRecord =
          recordForLifecycle &&
          authSelectionPolicy &&
          authSelectionPolicy.kind === 'current_lane' &&
          authMethodForThresholdEd25519Record(recordForLifecycle) ===
            authSelectionPolicy.authMethod
            ? recordForLifecycle
            : null;
        const selectedSnapshotLane = selectNearEd25519TransactionCandidate({
          snapshot,
          authSelectionPolicy,
          runtimeRecord: selectedAuthRuntimeRecord,
          nearAccountId: args.nearAccountId,
        });
        const selectedIdentity = resolveNearEd25519SelectedIdentityFromSnapshot({
          nearAccountId: args.nearAccountId,
          snapshot,
          candidate: selectedSnapshotLane,
        });
        if (
          authSelectionPolicy &&
          authSelectionPolicy.kind === 'explicit' &&
          selectedIdentity &&
          selectedIdentity.authMethod !== authSelectionPolicy.authMethod
        ) {
          throw new Error(
            `[SigningEngine][near] Ed25519 snapshot selected ${selectedIdentity.authMethod} after ${authSelectionPolicy.authMethod} filter`,
          );
        }
        await restoreNearEd25519SelectedSigningSession({
          deps: args.deps,
          nearAccountId: args.nearAccountId,
          identity: selectedIdentity,
          snapshotLane: selectedSnapshotLane,
        });
        recordForLifecycle = resolveNearEd25519RuntimeRecordForSelectedIdentity({
          identity: selectedIdentity,
          fallback: getStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId),
          nearAccountId: args.nearAccountId,
        });
        publishNearEd25519RuntimeIdentityForRecord(recordForLifecycle);
        assertNearEd25519SelectedIdentityMatchesRecord({
          identity: selectedIdentity,
          record: recordForLifecycle,
          nearAccountId: args.nearAccountId,
        });
        if (!selectedIdentity || !recordForLifecycle) {
          console.warn('[SigningEngine][near] Ed25519 signing lane selection missing session', {
            nearAccountId: args.nearAccountId,
            hasSelectedIdentity: Boolean(selectedIdentity),
            selectedIdentity: selectedIdentity
              ? {
                  authMethod: selectedIdentity.authMethod,
                  thresholdSessionId: String(selectedIdentity.thresholdSessionId || ''),
                  walletSigningSessionId: String(selectedIdentity.walletSigningSessionId || ''),
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
            snapshotLane: snapshot?.lanes.ed25519.near || null,
            snapshotCandidate: selectedSnapshotLane,
          });
          throw new Error('[SigningEngine][near] signing session is not ready: missing_session');
        }
        const lane = buildNearTransactionLaneFromPreparedIdentity({
          nearAccountId: args.nearAccountId,
          record: recordForLifecycle,
          identity: selectedIdentity,
        });
        const readiness = await resolveNearTransactionPlannerReadiness({
          preConfirmDeps: {
            getWarmThresholdEd25519SessionStatusForSession:
              args.deps.getWarmThresholdEd25519SessionStatusForSession,
            signingSessionCoordinator: args.signingSessionCoordinator,
            hasTouchConfirm: () => Boolean(args.deps.getSignerWorkerContext().touchConfirm),
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
        const identity = requireResolvedNearEd25519SigningLane(lane);
        return {
          lane,
          readiness: {
            readiness: readiness.readiness,
            expiresAtMs: readiness.expiresAtMs,
            remainingUses: readiness.remainingUses,
            usesNeeded: 1,
          },
          snapshotGeneration: snapshot?.generation || 0,
          metadata: {
            thresholdSessionRecord: recordForLifecycle,
            identity,
            snapshotGeneration: snapshot?.generation || 0,
            readiness: {
              readiness: readiness.readiness,
              expiresAtMs: readiness.expiresAtMs,
              remainingUses: readiness.remainingUses,
              usesNeeded: 1,
            },
            ...(ed25519Warmup ? { ed25519Warmup } : {}),
          },
        };
      },
    },
  });
  thresholdSessionRecord = preparedOperation.metadata.thresholdSessionRecord;
  const signingLane = preparedOperation.lane;
  const identity = preparedOperation.metadata.identity;

  const { signingAuthPlan, emailOtpSigning, budgetIdentity } = await resolveNearTransactionWalletAuth({
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
  return {
    thresholdSessionRecord,
    signingAuthPlan,
    signingLane,
    identity,
    resolvedSessionId: resolvePreparedSigningRequestSessionId({
      providedSessionId: args.input.sessionId,
      identity,
    }),
    snapshotGeneration: preparedOperation.snapshotGeneration,
    preparedOperation,
    ...(budgetIdentity
      ? {
          budgetIdentity,
          budgetProjectionVersion: budgetIdentity.projectionVersion,
        }
      : {}),
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
  const emailOtpSigning = preparedSigningSession.emailOtpSigning;
  const ed25519Warmup = preparedSigningSession.ed25519Warmup;
  const resolvedSessionId = preparedSigningSession.resolvedSessionId;
  const budgetIdentity = preparedSigningSession.budgetIdentity;
  const preparedOperation = preparedSigningSession.preparedOperation;
  try {
    return await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      thresholdSessionId: resolvedSessionId,
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
        const confirmationOperationId = ensureOperationId();
        const payload: NearTransactionsWithActionsPayload = {
          ctx,
          transactions: inputWithConfirmationTracking.transactions,
          rpcCall: inputWithConfirmationTracking.rpcCall,
          signerSlot: inputWithConfirmationTracking.signerSlot,
          confirmationConfigOverride: inputWithConfirmationTracking.confirmationConfigOverride,
          title: inputWithConfirmationTracking.title,
          body: inputWithConfirmationTracking.body,
          onEvent: inputWithConfirmationTracking.onEvent,
          sessionId: resolvedSessionId,
          signingAuthPlan,
          signingLane,
          ...(emailOtpSigning ? { emailOtpSigning } : {}),
          signingOperationId: confirmationOperationId,
          signingSessionCoordinator,
          ...(budgetIdentity ? { budgetIdentity } : {}),
          finalizePreparedSigningSession: async ({ status, hooks, result, error }) => {
            await finalizePreparedThresholdSigning(preparedOperation, result || null, {
              ...(status === 'success'
                ? {
                    recordSuccess: async () => {
                      await hooks.recordSuccess();
                    },
                  }
                : {
                    recordZeroSpend: async () => {
                      await hooks.recordZeroSpend(error);
                    },
                  }),
            });
          },
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
                    return refreshed;
                  },
                },
              }
            : {}),
        };
        const result = (await executePreparedThresholdSigning(
          preparedOperation,
          payload,
          {
            execute: async (_prepared, preparedPayload) =>
              (await signNearWithTouchConfirm({
                chain: 'near',
                kind: 'transactionsWithActions',
                payload: preparedPayload,
              })) as unknown as SignTransactionResult[],
          },
        )) as SignTransactionResult[];
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
        return (await signNearWithTouchConfirm({
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
        return (await signNearWithTouchConfirm({
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
