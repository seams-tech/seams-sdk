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
import type { SignTransactionResult } from '@/core/types/tatchi';
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
  type ThresholdEd25519SessionRecord,
  type ThresholdEd25519SessionStoreSource,
} from './thresholdLifecycle/thresholdSessionStore';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { WarmSessionSealedRestoreEvent } from '../session/WarmSessionSealedRefreshRestorer';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import {
  buildEd25519SessionPolicy,
  isThresholdSessionAuthUnavailableError,
} from '../threshold/session/sessionPolicy';
import {
  SigningOperationIntent,
  SigningSessionPlanKind,
  SigningSessionIds,
  type SigningLaneContext,
  type SigningOperationId,
} from '../session/signingSessionTypes';
import { buildNearTransactionSigningLane } from '../session/SigningLaneBuilders';
import {
  isWalletSigningBudgetExhaustedError,
  SigningSessionCoordinator,
  type SigningSessionReadiness,
} from '../session/SigningSessionCoordinator';
import { signingAuthPlanFromSigningSessionPlan } from '../orchestration/shared/touchConfirmSigning';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningLaneResolutionTrace,
  emitSigningPlannerDecisionTrace,
} from '../session/SigningSessionTrace';

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
  }) => Promise<{ sessionId: string }>;
  reconnectPasskeyEd25519CapabilityForSigning?: (args: {
    nearAccountId: AccountId | string;
    record: ThresholdEd25519SessionRecord;
    localPrfCredential: WebAuthnAuthenticationCredential;
    usesNeeded?: number;
    sessionId?: string;
    walletSigningSessionId?: string;
  }) => Promise<{ sessionId: string }>;
  signingSessionCoordinator?: SigningSessionCoordinator;
  restoreEmailOtpEcdsaSigningSessionForNearTransaction?: (args: {
    nearAccountId: AccountId | string;
    onSealedRestore?: (event: WarmSessionSealedRestoreEvent) => void;
  }) => Promise<void>;
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
  signingSessionCoordinator?: SigningSessionCoordinator;
  hasTouchConfirm: () => boolean;
};

type NearTransactionConfirmedSigningDeps = {
  requestEmailOtpTransactionSigningChallenge?: NearSigningApiDeps['requestEmailOtpTransactionSigningChallenge'];
  resolveEmailOtpSigningSessionAuthLane?: NearSigningApiDeps['resolveEmailOtpSigningSessionAuthLane'];
  loginWithEmailOtpEd25519CapabilityForSigning?: NearSigningApiDeps['loginWithEmailOtpEd25519CapabilityForSigning'];
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

function buildNearTransactionLaneForRecord(args: {
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord;
}) {
  const sessionId = String(args.record.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(args.record.walletSigningSessionId || '').trim();
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
  if (record?.source !== 'email_otp' || !jwt || !thresholdSessionId) return undefined;
  return {
    kind: 'signing_session',
    jwt,
    thresholdSessionId,
    ...(record.walletSigningSessionId
      ? { walletSigningSessionId: record.walletSigningSessionId }
      : {}),
    curve: 'ed25519',
  };
}

async function tryRestoreEmailOtpSigningSessionForNearTransaction(args: {
  deps: NearSigningApiDeps;
  nearAccountId: AccountId;
  onEvent?: (update: SigningFlowEvent) => void;
}): Promise<void> {
  if (typeof args.deps.restoreEmailOtpEcdsaSigningSessionForNearTransaction !== 'function') {
    return;
  }
  await args.deps
    .restoreEmailOtpEcdsaSigningSessionForNearTransaction({
      nearAccountId: args.nearAccountId,
      onSealedRestore: (event) => {
        if (event.status === 'started') {
          emitNearSigningEvent(args.onEvent, args.nearAccountId, {
            phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
            status: 'waiting_for_user',
            message: 'Restoring signing session...',
            interaction: { kind: 'transaction_confirmation', overlay: 'show' },
            data: {
              chain: event.chain,
              thresholdSessionId: event.thresholdSessionId,
              ...(event.walletSigningSessionId
                ? { walletSigningSessionId: event.walletSigningSessionId }
                : {}),
            },
          });
          return;
        }
        if (event.status === 'restored') {
          emitNearSigningEvent(args.onEvent, args.nearAccountId, {
            phase: SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
            status: 'succeeded',
            message: 'Signing session restored',
            interaction: { kind: 'none', overlay: 'none' },
            data: {
              chain: event.chain,
              thresholdSessionId: event.thresholdSessionId,
              ...(event.walletSigningSessionId
                ? { walletSigningSessionId: event.walletSigningSessionId }
                : {}),
            },
          });
        }
      },
    })
    .catch(() => undefined);
}

async function resolveNearTransactionWalletAuth(args: {
  preConfirmDeps: NearTransactionPreConfirmSigningDeps;
  confirmedDeps: NearTransactionConfirmedSigningDeps;
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord | null;
  onEvent?: (update: SigningFlowEvent) => void;
  sensitivePolicy?: SensitiveOperationPolicy;
  usesNeeded?: number;
  forceFreshAuth?: boolean;
}): Promise<{
  signingAuthPlan: SigningAuthPlan;
  signingLane: SigningLaneContext;
  emailOtpSigning?: {
    prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
    resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
    complete: (otpCode: string, challengeId?: string) => Promise<{ sessionId: string }>;
  };
}> {
  const sensitivePolicy = args.sensitivePolicy || SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy;
  if (!args.record) {
    throw new Error('[SigningEngine][near] signing session is not ready: missing_session');
  }
  const lane = buildNearTransactionLaneForRecord({
    nearAccountId: args.nearAccountId,
    record: args.record,
  });
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
      const authLane = args.record
        ? args.confirmedDeps.resolveEmailOtpSigningSessionAuthLane?.({
            thresholdSessionId: args.record.thresholdSessionId,
            curve: 'ed25519',
          }) || emailOtpEd25519AuthLaneFromRecord(args.record)
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
        !args.record
      ) {
        throw new Error('[SigningEngine] Email OTP per-operation NEAR signing is not configured');
      }
      const authLane =
        args.confirmedDeps.resolveEmailOtpSigningSessionAuthLane?.({
          thresholdSessionId: args.record.thresholdSessionId,
          curve: 'ed25519',
        }) || emailOtpEd25519AuthLaneFromRecord(args.record);
      const refreshed = await args.confirmedDeps.loginWithEmailOtpEd25519CapabilityForSigning({
        nearAccountId: args.nearAccountId,
        challengeId,
        otpCode: code,
        record: args.record,
        ...(authLane ? { authLane } : {}),
        remainingUses: Math.max(1, Math.floor(Number(args.usesNeeded) || 1)),
      });
      return {
        method: 'email_otp',
        emailOtpAuthentication: refreshed,
      };
    },
  });
  const readiness = await resolveNearTransactionPlannerReadiness({
    preConfirmDeps: args.preConfirmDeps,
    nearAccountId: args.nearAccountId,
    record: args.record,
    usesNeeded: args.usesNeeded,
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
  const coordinatorInput = {
    lane,
    readiness: readiness.readiness,
    expiresAtMs: readiness.expiresAtMs,
    remainingUses: readiness.remainingUses,
    usesNeeded: args.usesNeeded,
    forceFreshAuth: args.forceFreshAuth === true,
    sensitiveOperationPolicy: sensitivePolicy,
  };
  const signingSessionCoordinator =
    args.preConfirmDeps.signingSessionCoordinator || new SigningSessionCoordinator();
  const resolvedSigningSession = await signingSessionCoordinator.resolveAuthPlanFromReadiness(
    coordinatorInput,
    (event) => emitSigningPlannerDecisionTrace('near', event),
  );
  const plan = resolvedSigningSession.signingSessionPlan;
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
    ...(args.record.runtimePolicyScope
      ? {
          signingRootId: signingRootScopeFromRuntimePolicyScope(args.record.runtimePolicyScope)
            .signingRootId,
        }
      : {}),
    expiresAtMs: resolvedSigningSession.expiresAtMs,
    remainingUses: resolvedSigningSession.remainingUses,
  });
  if (signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth) {
    await passkeyAuthAdapter.createPasskeyReauthPlan(authInput);
  }
  if (signingAuthPlan.kind !== SigningAuthPlanKind.EmailOtpReauth) {
    return { signingAuthPlan, signingLane: lane };
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
    emailOtpSigning: {
      prepare: prepareEmailOtpChallenge,
      resend: prepareEmailOtpChallenge,
      complete: async (otpCode: string, challengeId?: string) => {
        const resolvedChallengeId = String(challengeId || activeChallenge?.challengeId || '').trim();
        if (!resolvedChallengeId) {
          throw new Error('[SigningEngine] Email OTP challenge must be prepared before completion');
        }
        const proof = await emailOtpAuthBridge.complete({
          challengeId: resolvedChallengeId,
          code: otpCode,
        });
        return proof.emailOtpAuthentication as { sessionId: string };
      },
    },
  };
}

function resolveSigningRequestSessionId(args: {
  deps: NearSigningApiDeps;
  providedSessionId?: string;
  nearAccountId: AccountId;
}): string {
  const provided = String(args.providedSessionId || '').trim();
  if (provided) return provided;
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
  let operationId = attempt.operationId;
  const ensureOperationId = (): SigningOperationId => {
    operationId = operationId || createNearTransactionSigningOperationId();
    return operationId;
  };
  const signingSessionCoordinator =
    attempt.signingSessionCoordinator || deps.signingSessionCoordinator;
  let thresholdSessionRecord = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
  const hasPendingEmailOtpEd25519Warmup = (): boolean =>
    deps.isEmailOtpEd25519WarmupPending?.({ nearAccountId }) === true;
  if (!thresholdSessionRecord && hasPendingEmailOtpEd25519Warmup()) {
    emitNearSigningEvent(args.onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
      status: 'running',
      message: 'Finalizing NEAR signing session',
      interaction: { kind: 'none', overlay: 'none' },
    });
    await deps.waitForPendingEmailOtpEd25519Warmup?.({ nearAccountId });
    thresholdSessionRecord = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
  }
  const ed25519Warmup =
    thresholdSessionRecord?.source === 'email_otp' &&
    hasPendingEmailOtpEd25519Warmup() &&
    typeof deps.waitForPendingEmailOtpEd25519Warmup === 'function'
      ? {
          isPending: hasPendingEmailOtpEd25519Warmup,
          waitForReady: () => deps.waitForPendingEmailOtpEd25519Warmup!({ nearAccountId }),
        }
      : undefined;
  await tryRestoreEmailOtpSigningSessionForNearTransaction({
    deps,
    nearAccountId,
    onEvent: args.onEvent,
  });
  thresholdSessionRecord = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
  const { signingAuthPlan, signingLane, emailOtpSigning } = await resolveNearTransactionWalletAuth({
    preConfirmDeps: {
      getWarmThresholdEd25519SessionStatusForSession:
        deps.getWarmThresholdEd25519SessionStatusForSession,
      signingSessionCoordinator,
      hasTouchConfirm: () => Boolean(deps.getSignerWorkerContext().touchConfirm),
    },
    confirmedDeps: {
      requestEmailOtpTransactionSigningChallenge: deps.requestEmailOtpTransactionSigningChallenge,
      resolveEmailOtpSigningSessionAuthLane: deps.resolveEmailOtpSigningSessionAuthLane,
      loginWithEmailOtpEd25519CapabilityForSigning:
        deps.loginWithEmailOtpEd25519CapabilityForSigning,
    },
    nearAccountId,
    record: thresholdSessionRecord,
    onEvent: args.onEvent,
    sensitivePolicy: args.sensitivePolicy,
    usesNeeded: 1,
    forceFreshAuth: attempt.forceFreshAuth === true,
  });
  const resolvedSessionId = resolveSigningRequestSessionId({
    deps,
    providedSessionId: args.sessionId,
    nearAccountId,
  });
  try {
    return await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      thresholdSessionId: resolvedSessionId,
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
        const confirmationOperationId = ensureOperationId();
        return (await signNearWithTouchConfirm({
          chain: 'near',
          kind: 'transactionsWithActions',
          payload: {
            ctx,
            transactions: args.transactions,
            rpcCall: args.rpcCall,
            signerSlot: args.signerSlot,
            confirmationConfigOverride: args.confirmationConfigOverride,
            title: args.title,
            body: args.body,
            onEvent: args.onEvent,
            sessionId: resolvedSessionId,
            signingAuthPlan,
            signingLane,
            ...(emailOtpSigning ? { emailOtpSigning } : {}),
            signingOperationId: confirmationOperationId,
            signingSessionCoordinator,
            ...(ed25519Warmup ? { ed25519Warmup } : {}),
            ...(signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth &&
            thresholdSessionRecord &&
            typeof deps.reconnectPasskeyEd25519CapabilityForSigning === 'function'
              ? {
                  passkeyEd25519Reconnect: {
                    prepare: async ({ usesNeeded }) => {
                      const rpId = String(ctx.touchIdPrompt.getRpId() || '').trim();
                      if (!rpId) {
                        throw new Error('[SigningEngine] missing rpId for passkey Ed25519 reauth');
                      }
                      const remainingUses = Math.max(1, Math.floor(Number(usesNeeded) || 1));
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
                              walletSigningSessionId:
                                thresholdSessionRecord.walletSigningSessionId,
                            }
                          : {}),
                        remainingUses,
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
                    }) =>
                      await deps.reconnectPasskeyEd25519CapabilityForSigning!({
                        nearAccountId,
                        record: thresholdSessionRecord,
                        localPrfCredential: credential,
                        usesNeeded,
                        ...(sessionId ? { sessionId } : {}),
                        ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
                      }),
                  },
                }
              : {}),
          },
        })) as unknown as SignTransactionResult[];
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
      (isThresholdSessionAuthUnavailableError(error) || isWalletSigningBudgetExhaustedError(error))
    ) {
      const isEmailOtpSession = thresholdSessionRecord.source === 'email_otp';
      emitNearSigningEvent(args.onEvent, nearAccountId, {
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
          reason: isWalletSigningBudgetExhaustedError(error)
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
    const activeSessionId = resolveSigningRequestSessionId({
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
    const activeSessionId = resolveSigningRequestSessionId({
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
