import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { TransactionInputWasm, validateActionArgsWasm } from '@/core/types/actions';
import {
  createSigningFlowEvent,
  SigningEventPhase,
  type CreateSigningFlowEventInput,
  type SigningFlowEvent,
} from '@/core/types/sdkSentEvents';
import {
  WorkerRequestType,
  TransactionPayload,
  type WasmSignTransactionsWithActionsRequest,
  isSignTransactionsWithActionsSuccess,
  isWorkerError,
  type ConfirmationConfig,
  type RpcCallPayload,
  type TransactionResponse,
  type WorkerSuccessResponse,
} from '@/core/types/signer-worker';
import { AccountId, toAccountId } from '@/core/types/accountIds';
import type { SigningRuntimeDeps } from '../../interfaces/runtime';
import type {
  NearEd25519WarmupHook,
  NearEmailOtpSigningHook,
  NearPreparedSigningSessionFinalizer,
  NearPasskeyEd25519ReconnectHook,
} from '../../interfaces/near';
import { formatEmailOtpSentText } from '../shared/touchConfirmSigning';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
  type UserConfirmProgressEvent,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import { WebAuthnAuthenticationCredential } from '@/core/types';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/types';
import type { ThresholdEd25519SessionRecord } from '../../api/thresholdLifecycle/thresholdSessionStore';
import {
  isThresholdSessionAuthUnavailableError,
  isThresholdSignerMissingKeyError,
} from '@/core/signingEngine/threshold/session/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { executeWorkerOperation } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  requirePrfFirstFromCredential,
  resolveNearSigningMaterials,
  toCredentialForRelayJson,
} from './shared/signingMaterials';
import {
  requireResolvedThresholdEd25519SessionState,
  type ResolvedThresholdEd25519SessionState,
} from './shared/thresholdSessionAuth';
import { buildNearWorkerSigningEnvelope } from './shared/workerRequestAssembly';
import {
  createNearSigningSessionCoordinator,
  THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR,
} from './shared/thresholdAuthMode';
import { ensureThresholdEd25519HssClientBase } from './shared/ensureThresholdEd25519HssClientBase';
import { repairThresholdEd25519MissingRelayerKey } from './shared/repairThresholdEd25519MissingRelayerKey';
import { buildNearTransactionSigningLane } from '../../session/signingSession/lanes';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningLaneContext,
  type SelectedSigningLaneContext,
  type SigningOperationId,
} from '../../session/signingSession/types';
import {
  admitTransactionBudget,
  replacePreparedTransactionLane,
  type BudgetAdmittedOperation,
  type NearEd25519TransactionLane,
  type PreparedTransactionOperation,
  type TransactionReadiness,
} from '../../session/signingSession/transactionState';
import type { NonceLeaseRef } from '../../nonce/NonceCoordinator';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
} from '../../session/signingSession/trace';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type {
  SigningSessionBudgetRecordSuccessInput,
  SigningSessionBudgetStatusAuth,
  SigningSessionPreparedBudgetIdentity,
} from '../../session/signingSession/budget';
import { buildWalletSigningSpendPlan } from '../../session/signingSession/budget';
import {
  createSigningSessionBudgetFinalizer,
  inferSigningSessionBudgetZeroSpendReason,
  type SigningSessionBudgetFinalizer,
} from '../../session/signingSession/budgetFinalizer';
import { computeSigningOperationFingerprint } from '../../session/signingSession/operationFingerprint';

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

function requireSelectedNearSigningLane(lane: SigningLaneContext): SelectedSigningLaneContext {
  if (!lane.walletSigningSessionId || !lane.thresholdSessionId) {
    throw new Error('[SigningEngine][near] signing lane is missing resolved session identity');
  }
  return lane as SelectedSigningLaneContext;
}

function nearTransactionLaneFromSelectedSigningLane(
  lane: SelectedSigningLaneContext,
): NearEd25519TransactionLane {
  if (lane.curve !== 'ed25519' || lane.chainFamily !== 'near') {
    throw new Error('[SigningEngine][near] expected selected NEAR Ed25519 signing lane');
  }
  return {
    accountId: lane.accountId,
    authMethod: lane.authMethod,
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId: SigningSessionIds.walletSigningSession(
      String(lane.walletSigningSessionId),
    ),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
      String(lane.thresholdSessionId),
    ),
  };
}

function readinessFromPreparedBudgetIdentity(
  budgetIdentity: SigningSessionPreparedBudgetIdentity,
): TransactionReadiness {
  return {
    status: 'ready',
    remainingUses: Math.max(0, Math.floor(Number(budgetIdentity.status.remainingUses) || 0)),
    expiresAtMs: Math.max(0, Math.floor(Number(budgetIdentity.status.expiresAtMs) || 0)),
  };
}

function resolvedEd25519SessionStateFromRecord(
  record: ThresholdEd25519SessionRecord | undefined,
): ResolvedThresholdEd25519SessionState | null {
  if (!record) return null;
  const sessionKind: 'jwt' | 'cookie' =
    record.thresholdSessionKind === 'cookie' ? 'cookie' : 'jwt';
  const thresholdSessionJwt = String(record.thresholdSessionJwt || '').trim() || undefined;
  if (sessionKind === 'jwt' && !thresholdSessionJwt) return null;
  return {
    record,
    sessionKind,
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    xClientBaseB64u: String(record.xClientBaseB64u || '').trim() || undefined,
    relayerUrl: String(record.relayerUrl || '').trim(),
  };
}

function budgetStatusAuthFromEd25519SessionState(
  state: ResolvedThresholdEd25519SessionState,
): SigningSessionBudgetStatusAuth {
  const thresholdSessionId = String(state.record.thresholdSessionId || '').trim();
  const relayerUrl = String(state.relayerUrl || '').trim();
  if (!thresholdSessionId || !relayerUrl) {
    throw new Error('[SigningEngine][near] refreshed signing session is missing budget auth');
  }
  return {
    thresholdSessionId,
    relayerUrl,
    ...(state.thresholdSessionJwt ? { thresholdSessionJwt: state.thresholdSessionJwt } : {}),
  };
}

function createNearTransactionSigningOperationId(): SigningOperationId {
  const cryptoObj = globalThis as { crypto?: { randomUUID?: () => string } };
  const randomId =
    typeof cryptoObj.crypto?.randomUUID === 'function'
      ? cryptoObj.crypto.randomUUID()
      : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  return SigningSessionIds.signingOperation(`near-transaction-sign:${randomId}`);
}

function normalizeTransactionSigningRequest(args: {
  nearAccountId: string;
  tx: TransactionInputWasm;
  txIndex: number;
}): TransactionPayload {
  const receiverId = String(args.tx?.receiverId || '').trim();
  if (!receiverId) {
    throw new Error(`[SigningEngine] transactions[${args.txIndex}].receiverId is required`);
  }

  const actions = Array.isArray(args.tx?.actions) ? args.tx.actions : [];
  if (actions.length === 0) {
    throw new Error(`[SigningEngine] transactions[${args.txIndex}].actions must be non-empty`);
  }
  for (let i = 0; i < actions.length; i++) {
    validateActionArgsWasm(actions[i]);
  }

  return {
    nearAccountId: args.nearAccountId,
    receiverId,
    actions,
  };
}

/**
 * Sign multiple transactions with a shared WebAuthn credential.
 * Efficiently processes multiple transactions with one PRF-backed signing session.
 */

export async function signTransactionsWithActions({
  ctx,
  sessionId: providedSessionId,
  transactions,
  rpcCall,
  onEvent,
  confirmationConfigOverride,
  title,
  body,
  signerSlot,
  emailOtpSigning,
  signingOperationId: providedSigningOperationId,
  signingSessionCoordinator: sessionCoordinator,
  transactionOperation,
  budgetAdmittedOperation: providedBudgetAdmittedOperation,
  finalizePreparedSigningSession,
  ed25519Warmup,
  passkeyEd25519Reconnect,
  signingAuthPlan: providedSigningAuthPlan,
  signingLane,
}: {
  ctx: SigningRuntimeDeps;
  sessionId?: string;
  transactions: TransactionInputWasm[];
  rpcCall: RpcCallPayload;
  onEvent?: (update: SigningFlowEvent) => void;
  // Allow callers to pass a partial override (e.g., { uiMode: 'drawer' })
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  signerSlot?: number;
  emailOtpSigning?: NearEmailOtpSigningHook;
  signingOperationId?: SigningOperationId;
  signingSessionCoordinator?: SigningSessionCoordinator;
  transactionOperation: PreparedTransactionOperation<NearEd25519TransactionLane>;
  budgetAdmittedOperation?: BudgetAdmittedOperation<NearEd25519TransactionLane>;
  finalizePreparedSigningSession?: NearPreparedSigningSessionFinalizer;
  ed25519Warmup?: NearEd25519WarmupHook;
  passkeyEd25519Reconnect?: NearPasskeyEd25519ReconnectHook;
  signingAuthPlan?: SigningAuthPlan;
  signingLane?: SigningLaneContext;
}): Promise<
  Array<{
    signedTransaction: SignedTransaction;
    nearAccountId: AccountId;
    logs?: string[];
  }>
> {
  const sessionId = String(providedSessionId || '').trim();
  let signingOperationId = providedSigningOperationId;
  const callerProvidedSigningOperationId = Boolean(providedSigningOperationId);
  const ensureSigningOperationId = (): SigningOperationId => {
    signingOperationId = signingOperationId || createNearTransactionSigningOperationId();
    return signingOperationId;
  };
  const nearAccountId = toAccountId(rpcCall.nearAccountId);
  const operationFingerprint = await computeSigningOperationFingerprint({
    kind: 'near:transactions_with_actions',
    payload: {
      nearAccountId,
      transactions,
    },
  });
  const relayerUrl = ctx.relayerUrl;
  const ed25519WarmupPromise =
    ed25519Warmup?.isPending() === true
      ? ed25519Warmup.waitForReady().then(() => undefined)
      : undefined;
  if (ed25519WarmupPromise) {
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
      status: 'running',
      message: 'Finalizing NEAR signing session',
      interaction: { kind: 'none', overlay: 'none' },
    });
    void ed25519WarmupPromise
      .then(() => {
        emitNearSigningEvent(onEvent, nearAccountId, {
          phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED,
          status: 'succeeded',
          message: 'NEAR signing session finalized',
          interaction: { kind: 'none', overlay: 'none' },
        });
      })
      .catch(() => undefined);
  }

  const warnings: string[] = [];
  const signingStartedAt = performance.now();
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_02_REQUEST_PREPARED,
    status: 'running',
    message: 'Loading threshold signing state',
    interaction: { kind: 'none', overlay: 'none' },
  });
  const { thresholdKeyMaterial } = await resolveNearSigningMaterials({
    ctx,
    nearAccountId,
    signerSlot,
    operationLabel: 'signing',
    warnings,
  });
  console.debug('[SigningEngine][near][transactions] signing materials resolved', {
    nearAccountId,
    durationMs: Math.round(performance.now() - signingStartedAt),
  });
  console.debug('[signTransactionsWithActions] threshold signing', {
    nearAccountId,
    warnings,
  });

  const signingContext = validateAndPrepareSigningContext({
    nearAccountId,
    relayerUrl,
    thresholdKeyMaterial,
  });

  // Normalize rpcCall to ensure required fields are present.
  const resolvedRpcCall = {
    nearRpcUrl:
      rpcCall.nearRpcUrl ||
      resolvePrimaryNearRpcUrl(PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains),
    nearAccountId: rpcCall.nearAccountId,
  } as RpcCallPayload;
  const normalizedInputTransactions = Array.isArray(transactions) ? transactions : [];
  if (normalizedInputTransactions.length === 0) {
    throw new Error('[SigningEngine] transactions must be non-empty');
  }
  const txSigningRequests: TransactionPayload[] = normalizedInputTransactions.map((tx, txIndex) =>
    normalizeTransactionSigningRequest({
      nearAccountId: String(resolvedRpcCall.nearAccountId),
      tx,
      txIndex,
    }),
  );
  const normalizedTransactions: TransactionInputWasm[] = txSigningRequests.map((tx) => ({
    receiverId: tx.receiverId,
    actions: tx.actions,
  }));

  // UserConfirm before sending anything to the signer worker.
  // WebAuthn uses a challenge digest (threshold sessions use `sessionPolicyDigest32`).
  if (!ctx.touchConfirm) {
    throw new Error('TouchConfirm bridge not available for signing');
  }
  const touchConfirm = ctx.touchConfirm;
  const signingSessionCoordinator = createNearSigningSessionCoordinator(touchConfirm);
  if (!sessionCoordinator) {
    throw new Error('[SigningEngine][near] production signing session coordinator is required');
  }
  if (callerProvidedSigningOperationId) {
    sessionCoordinator.bindCallerProvidedOperationIdToFingerprint({
      operationId: ensureSigningOperationId(),
      operationFingerprint,
    });
  }
  const usesNeeded = 1;
  if (!providedSessionId || !providedSigningAuthPlan || !signingLane) {
    throw new Error(
      '[SigningEngine][near] threshold transaction signing requires prepared session identity',
    );
  }
  if (!transactionOperation) {
    throw new Error(
      '[SigningEngine][near] threshold transaction signing requires prepared transaction operation',
    );
  }
  if (
    providedSigningAuthPlan.kind === SigningAuthPlanKind.WarmSession &&
    providedSigningAuthPlan.sessionId !== providedSessionId
  ) {
    throw new Error(
      '[SigningEngine][near] warm-session auth plan must match prepared session identity',
    );
  }
  const thresholdAuthPlan = {
    sessionId:
      providedSigningAuthPlan.kind === SigningAuthPlanKind.WarmSession
        ? providedSigningAuthPlan.sessionId
        : providedSessionId,
    lane: signingLane,
    signingAuthPlan: providedSigningAuthPlan,
    touchConfirmAuthPayload: { signingAuthPlan: providedSigningAuthPlan },
    warmSessionReady: providedSigningAuthPlan.kind === SigningAuthPlanKind.WarmSession,
  };
  const activeSigningLane = signingLane;
  type NearAuthSideEffect = 'passkey_reauth' | 'threshold_reconnect';
  const authSideEffectsStarted = new Set<NearAuthSideEffect>();
  const emitConfirmedAuthSideEffectStarted = (sideEffect: NearAuthSideEffect): void => {
    if (authSideEffectsStarted.has(sideEffect)) return;
    authSideEffectsStarted.add(sideEffect);
    emitSigningBoundaryTrace(
      'near',
      createSigningBoundaryTraceEvent({
        event: 'auth_side_effect_started',
        lane: activeSigningLane,
        sideEffect,
        phase: 'confirmed',
      }),
    );
  };
  const emitTouchConfirmProgress = (progress: UserConfirmProgressEvent): void => {
    if (progress.phase === 'auth.passkey.prompt.started') {
      emitConfirmedAuthSideEffectStarted('passkey_reauth');
    }
  };
  if (providedSigningAuthPlan.kind === SigningAuthPlanKind.EmailOtpReauth && !emailOtpSigning) {
    throw new Error('[email-otp] verify Email OTP again before NEAR threshold signing');
  }
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
    status: 'waiting_for_user',
    message: 'Opening confirmation prompt',
    interaction: { kind: 'transaction_confirmation', overlay: 'show' },
  });
  const confirmationOperationId = ensureSigningOperationId();
  const emailOtpChallenge = emailOtpSigning ? await emailOtpSigning.prepare() : undefined;
  const emailOtpPrompt =
    emailOtpSigning && emailOtpChallenge
      ? {
          challengeId: emailOtpChallenge.challengeId,
          ...(emailOtpChallenge.emailHint ? { emailHint: emailOtpChallenge.emailHint } : {}),
          title: 'Enter email code to sign',
          helperText: formatEmailOtpSentText(emailOtpChallenge.emailHint),
          ...(emailOtpSigning.resend ? { onResend: emailOtpSigning.resend } : {}),
        }
      : undefined;
  const signingAuthPlan =
    providedSigningAuthPlan.kind === SigningAuthPlanKind.EmailOtpReauth && emailOtpPrompt
      ? { ...providedSigningAuthPlan, emailOtpPrompt }
      : providedSigningAuthPlan;
  const touchConfirmAuthPayload = { signingAuthPlan };
  const shouldReconnectWithPasskeyEd25519 =
    touchConfirmAuthPayload.signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth &&
    Boolean(passkeyEd25519Reconnect);
  const plannedPasskeyReconnect =
    shouldReconnectWithPasskeyEd25519 && passkeyEd25519Reconnect?.prepare
      ? await passkeyEd25519Reconnect.prepare({ usesNeeded })
      : undefined;
  if (touchConfirmAuthPayload.signingAuthPlan.kind === SigningAuthPlanKind.WarmSession) {
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
      status: 'succeeded',
      interaction: { kind: 'none', overlay: 'none' },
      data: {
        sessionId: touchConfirmAuthPayload.signingAuthPlan.sessionId,
        expiresAtMs: touchConfirmAuthPayload.signingAuthPlan.expiresAtMs,
        remainingUses: touchConfirmAuthPayload.signingAuthPlan.remainingUses,
      },
    });
  }
  const confirmation = await ctx.touchConfirm.orchestrateSigningConfirmation({
    ctx: { touchConfirm },
    sessionId,
    chain: 'near',
    kind: 'transaction',
    ...touchConfirmAuthPayload,
    txSigningRequests: normalizedTransactions,
    rpcCall: resolvedRpcCall,
    nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
    confirmationConfigOverride,
    title,
    body,
    ...(ed25519WarmupPromise
      ? {
          confirmationReadiness: {
            promise: ed25519WarmupPromise,
            body: body
              ? `${body}\n\nFinalizing NEAR signing session...`
              : 'Finalizing NEAR signing session...',
          },
        }
      : {}),
    ...(emailOtpPrompt ? { emailOtpPrompt } : {}),
    // Passkey Ed25519 reauth mints a new threshold session after confirmation. The server
    // verifies the WebAuthn challenge against this session-policy digest, so using the tx
    // intent digest here caused one confirmation plus a second TouchID prompt for session mint.
    ...(plannedPasskeyReconnect?.sessionPolicyDigest32
      ? { sessionPolicyDigest32: plannedPasskeyReconnect.sessionPolicyDigest32 }
      : {}),
    onProgress: emitTouchConfirmProgress,
  });
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
    status: 'succeeded',
    interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
  });

  const intentDigest = confirmation.intentDigest;
  const transactionContext = confirmation.transactionContext;
  const nonceLeaseRefs = confirmation.nonceLeases || [];
  let thresholdSignatureCreated = false;
  let walletSpendRecorded = false;

  const credentialWithPrf: WebAuthnAuthenticationCredential | undefined =
    confirmation.credential as WebAuthnAuthenticationCredential | undefined;

  const credentialForRelayJson = toCredentialForRelayJson(credentialWithPrf);

  // Threshold signer: authorize with relayer and pass threshold config into the signer worker.
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED,
    status: 'running',
    message: 'Preparing NEAR signer',
    interaction: { kind: 'none', overlay: 'none' },
  });
  let canonicalThresholdSessionId = thresholdAuthPlan.sessionId;
  let refreshedThresholdSessionState: ResolvedThresholdEd25519SessionState | null = null;
  let refreshedBudgetIdentityRequired = false;
  if (emailOtpSigning) {
    const otpCode = String(confirmation.otpCode || '').trim();
    if (!/^\d{6}$/.test(otpCode)) {
      throw new Error('[SigningEngine] missing Email OTP code from touchConfirm');
    }
    const refreshed = await emailOtpSigning.complete(otpCode, confirmation.emailOtpChallengeId);
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_VERIFY_SUCCEEDED,
      status: 'succeeded',
      interaction: { kind: 'otp_input', overlay: 'hide' },
    });
    const refreshedSessionId = String(refreshed.sessionId || '').trim();
    if (!refreshedSessionId) {
      throw new Error('[SigningEngine] Email OTP signing did not return a threshold session id');
    }
    // Regression note: after session exhaustion, the old Ed25519 session may
    // authorize the OTP route, but the worker must sign with the freshly minted
    // session. Keeping the stale id here caused OTP success followed by
    // threshold_ed25519_session_not_ready in the NEAR signer.
    canonicalThresholdSessionId = refreshedSessionId;
    refreshedThresholdSessionState = resolvedEd25519SessionStateFromRecord(refreshed.record);
    refreshedBudgetIdentityRequired = true;
  } else if (shouldReconnectWithPasskeyEd25519 && passkeyEd25519Reconnect) {
    if (!credentialWithPrf) {
      throw new Error('[SigningEngine] missing WebAuthn credential for passkey session reconnect');
    }
    emitConfirmedAuthSideEffectStarted('threshold_reconnect');
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
      status: 'running',
      message: 'Reconnecting NEAR signing session',
      interaction: { kind: 'none', overlay: 'none' },
    });
    const refreshed = await passkeyEd25519Reconnect.reconnect({
      credential: credentialWithPrf,
      usesNeeded,
      ...(plannedPasskeyReconnect?.sessionId
        ? { sessionId: plannedPasskeyReconnect.sessionId }
        : {}),
      ...(plannedPasskeyReconnect?.walletSigningSessionId
        ? { walletSigningSessionId: plannedPasskeyReconnect.walletSigningSessionId }
        : {}),
    });
    const refreshedSessionId = String(refreshed.sessionId || '').trim();
    if (!refreshedSessionId) {
      throw new Error('[SigningEngine] passkey signing did not return a threshold session id');
    }
    if (
      plannedPasskeyReconnect?.sessionId &&
      refreshedSessionId !== plannedPasskeyReconnect.sessionId
    ) {
      throw new Error(
        '[SigningEngine] passkey signing returned a different threshold session id than the confirmed session policy',
      );
    }
    canonicalThresholdSessionId = refreshedSessionId;
    refreshedThresholdSessionState = resolvedEd25519SessionStateFromRecord(refreshed.record);
    refreshedBudgetIdentityRequired = true;
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED,
      status: 'succeeded',
      message: 'NEAR signing session reconnected',
      interaction: { kind: 'none', overlay: 'none' },
      data: { sessionId: refreshedSessionId },
    });
  }
  const thresholdSessionState =
    refreshedThresholdSessionState?.record.thresholdSessionId === canonicalThresholdSessionId
      ? refreshedThresholdSessionState
      : requireResolvedThresholdEd25519SessionState({
          signingSessionCoordinator,
          thresholdSessionId: canonicalThresholdSessionId,
        });
  const trustedBudgetStatusAuth = budgetStatusAuthFromEd25519SessionState(thresholdSessionState);
  const provisionedRemainingUses = thresholdSessionState.record.remainingUses;
  if (emailOtpSigning && provisionedRemainingUses < usesNeeded) {
    throw new Error(
      `[SigningEngine] Email OTP NEAR signing session has ${provisionedRemainingUses} remaining use(s), but this operation requires ${usesNeeded}. Retry the Email OTP prompt to provision a fresh signing session.`,
    );
  }
  const cachedXClientBaseB64u = String(thresholdSessionState.xClientBaseB64u || '').trim();
  const prfFirstB64u = signingContext.threshold
    ? cachedXClientBaseB64u
      ? ''
      : thresholdAuthPlan.warmSessionReady
        ? await (async () => {
            const prfFirst = await signingSessionCoordinator.claimPrfFirstByThresholdSessionId({
              thresholdSessionId: thresholdAuthPlan.sessionId,
              uses: usesNeeded,
              errorContext: 'threshold-ed25519 transaction signing',
              walletId: nearAccountId,
              authMethod: thresholdAuthPlan.lane.authMethod,
              curve: 'ed25519',
              chain: 'near',
              walletSigningSessionId: thresholdAuthPlan.lane.walletSigningSessionId,
            });
            return prfFirst;
          })()
        : requirePrfFirstFromCredential(credentialWithPrf)
    : requirePrfFirstFromCredential(credentialWithPrf);

  if (!cachedXClientBaseB64u && !prfFirstB64u) {
    throw new Error('Missing PRF.first output for signing');
  }

  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE,
    status: 'succeeded',
    interaction: { kind: 'none', overlay: 'none' },
    authMethod: emailOtpSigning
      ? 'email_otp'
      : thresholdAuthPlan.warmSessionReady
        ? 'warm_session'
        : thresholdAuthPlan.signingAuthPlan.method,
  });

  const xClientBaseB64u =
    cachedXClientBaseB64u ||
    (await ensureThresholdEd25519HssClientBase({
      ...(onEvent
        ? {
            onProgress: (message: string) => {
              emitConfirmedAuthSideEffectStarted('threshold_reconnect');
              emitNearSigningEvent(onEvent, nearAccountId, {
                phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
                status: 'running',
                message,
                interaction: { kind: 'none', overlay: 'none' },
              });
            },
          }
        : {}),
      ctx,
      thresholdSessionId: canonicalThresholdSessionId,
      thresholdSessionJwt: thresholdSessionState.thresholdSessionJwt,
      relayerUrl: thresholdSessionState.relayerUrl,
      relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
      nearAccountId,
      keyVersion: signingContext.threshold.thresholdKeyMaterial.keyVersion,
      participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map((p) => p.id),
      prfFirstB64u,
    }));
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_08_SIGNER_PREPARE_SUCCEEDED,
    status: 'succeeded',
    message: 'NEAR signer ready',
    interaction: { kind: 'none', overlay: 'none' },
    data: {
      signer: 'threshold-ed25519',
      sessionId: canonicalThresholdSessionId,
      clientBaseSource: cachedXClientBaseB64u ? 'cached' : 'reconstructed',
    },
  });
  console.debug('[SigningEngine][near][transactions] threshold client base ready', {
    nearAccountId,
    thresholdSessionId: canonicalThresholdSessionId,
    durationMs: Math.round(performance.now() - signingStartedAt),
  });
  let activeBudgetAdmittedOperation = providedBudgetAdmittedOperation;
  const buildSelectedBudgetSpendLane = (): SelectedSigningLaneContext => {
    const walletSigningSessionId = String(
      thresholdSessionState.record.walletSigningSessionId || '',
    ).trim();
    if (!walletSigningSessionId) {
      throw new Error(
        '[SigningEngine][near] missing wallet signing session id for transaction budget spend',
      );
    }
    const recordSource = thresholdSessionState.record.source;
    return requireSelectedNearSigningLane(
      recordSource === 'email_otp'
        ? buildNearTransactionSigningLane({
            accountId: nearAccountId,
            authMethod: 'email_otp',
            walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
            thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
              canonicalThresholdSessionId,
            ),
            retention: thresholdSessionState.record.emailOtpAuthContext?.retention || 'session',
            sessionOrigin:
              thresholdSessionState.record.emailOtpAuthContext?.reason === 'login'
                ? 'login'
                : 'per_operation',
          })
        : buildNearTransactionSigningLane({
            accountId: nearAccountId,
            authMethod: 'passkey',
            walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
            thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
              canonicalThresholdSessionId,
            ),
            storageSource: recordSource,
          }),
    );
  };
  const admitBudgetForSelectedSpendLane = async (
    spendLane: SelectedSigningLaneContext,
  ): Promise<BudgetAdmittedOperation<NearEd25519TransactionLane>> => {
    const budgetIdentity = await sessionCoordinator.prepareBudgetIdentity({
      nearAccountId,
      lane: spendLane,
      trustedStatusAuth: trustedBudgetStatusAuth,
      operationUsesNeeded: usesNeeded,
    });
    const refreshedPreparedOperation = replacePreparedTransactionLane(transactionOperation, {
      lane: nearTransactionLaneFromSelectedSigningLane(spendLane),
      readiness: readinessFromPreparedBudgetIdentity(budgetIdentity),
    });
    return admitTransactionBudget(refreshedPreparedOperation, { budgetIdentity });
  };
  if (refreshedBudgetIdentityRequired) {
    activeBudgetAdmittedOperation = await admitBudgetForSelectedSpendLane(
      buildSelectedBudgetSpendLane(),
    );
    refreshedBudgetIdentityRequired = false;
  }
  const createNearBudgetFinalizer = async (): Promise<SigningSessionBudgetFinalizer | undefined> => {
    if (!signingContext.threshold || !sessionCoordinator) return;
    const spendLane = buildSelectedBudgetSpendLane();
    const operation = {
      operationId: confirmationOperationId,
      operationFingerprint,
      intent: SigningOperationIntent.TransactionSign,
    };
    const createAlreadyConsumedFinalizer = (): SigningSessionBudgetFinalizer => {
      const spend = buildWalletSigningSpendPlan(operation, spendLane);
      return {
        spend,
        async reserve() {
          return null;
        },
        async recordSuccess(input: Omit<SigningSessionBudgetRecordSuccessInput, 'spend'> = {}) {
          await sessionCoordinator.recordSuccess({
            ...input,
            spend,
            ...(trustedBudgetStatusAuth ? { trustedStatusAuth: trustedBudgetStatusAuth } : {}),
          }).catch((error) => {
            console.warn(
              '[SigningEngine][near] failed to sync consumed wallet signing-session budget',
              {
                nearAccountId,
                walletSigningSessionId: String(spendLane.walletSigningSessionId),
                thresholdSessionId: canonicalThresholdSessionId,
                error: error instanceof Error ? error.message : String(error || 'unknown error'),
              },
            );
            throw error;
          });
        },
        recordZeroSpend(error) {
          try {
            sessionCoordinator.recordZeroSpend({
              spend,
              reason: inferSigningSessionBudgetZeroSpendReason({
                error,
                authMethod: spend.lane.authMethod,
              }),
              error,
            });
          } catch (ledgerError) {
            console.warn('[SigningEngine][near] failed to record wallet signing-session zero spend', {
              nearAccountId,
              thresholdSessionId: canonicalThresholdSessionId,
              error:
                ledgerError instanceof Error
                  ? ledgerError.message
                  : String(ledgerError || 'unknown error'),
            });
          }
        },
      };
    };
    if (!activeBudgetAdmittedOperation && thresholdSignatureCreated) {
      // Ed25519 server authorization consumes the selected wallet budget during
      // signing. After a single-use step-up, a post-sign active-status check can
      // legitimately read exhausted; finalization should sync that consumed
      // result instead of requiring another active projection.
      return createAlreadyConsumedFinalizer();
    }
    activeBudgetAdmittedOperation =
      activeBudgetAdmittedOperation &&
      activeBudgetAdmittedOperation.budgetAdmission.budgetIdentity.walletSigningSessionId ===
        String(spendLane.walletSigningSessionId)
        ? activeBudgetAdmittedOperation
        : await admitBudgetForSelectedSpendLane(spendLane);
    return createSigningSessionBudgetFinalizer({
      signingSessionBudget: sessionCoordinator,
      budgetIdentity: activeBudgetAdmittedOperation.budgetAdmission.budgetIdentity,
      trustedStatusAuth: trustedBudgetStatusAuth,
      operation,
      lane: spendLane,
      onRecordSuccessError: (error) => {
        console.warn('[SigningEngine][near] failed to update wallet signing-session budget', {
          nearAccountId,
          walletSigningSessionId: String(spendLane.walletSigningSessionId),
          thresholdSessionId: canonicalThresholdSessionId,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
      onRecordZeroSpendError: (ledgerError) => {
        console.warn('[SigningEngine][near] failed to record wallet signing-session zero spend', {
          nearAccountId,
          thresholdSessionId: canonicalThresholdSessionId,
          error:
            ledgerError instanceof Error
              ? ledgerError.message
              : String(ledgerError || 'unknown error'),
        });
      },
    });
  };
  const recordSuccessfulWalletSigningSessionSpend = async (): Promise<void> => {
    if (walletSpendRecorded) return;
    const finalizer = await createNearBudgetFinalizer();
    if (!finalizer) {
      walletSpendRecorded = true;
      return;
    }
    const successArgs = {
      // The threshold Ed25519 signing ceremony is the authoritative spend
      // boundary. Finalization should sync status and local hints, not consume
      // the same selected session again.
      alreadyConsumedThresholdSessionIds: [canonicalThresholdSessionId],
    };
    if (finalizePreparedSigningSession) {
      await finalizePreparedSigningSession({
        status: 'success',
        hooks: {
          recordSuccess: async () => await finalizer.recordSuccess(successArgs),
          recordZeroSpend: (error) => finalizer.recordZeroSpend(error),
        },
      });
    } else {
      await finalizer.recordSuccess(successArgs);
    }
    walletSpendRecorded = true;
  };
  const recordFailedWalletSigningSessionSpend = async (error: unknown): Promise<void> => {
    if (walletSpendRecorded || thresholdSignatureCreated) return;
    const finalizer = await createNearBudgetFinalizer();
    if (!finalizer) return;
    if (finalizePreparedSigningSession) {
      await finalizePreparedSigningSession({
        status: 'zero_spend',
        error,
        hooks: {
          recordSuccess: async (successArgs) => await finalizer.recordSuccess(successArgs),
          recordZeroSpend: (zeroSpendError) => finalizer.recordZeroSpend(zeroSpendError),
        },
      });
    } else {
      finalizer.recordZeroSpend(error);
    }
    walletSpendRecorded = true;
  };
  const releaseUnsignedNonceLeases = async (error: unknown): Promise<void> => {
    if (thresholdSignatureCreated || !nonceLeaseRefs.length) return;
    await releaseNearNonceLeases(ctx, nonceLeaseRefs, 'signing_failed').catch((releaseError) => {
      console.warn('[SigningEngine][near][transactions] failed to release nonce leases', {
        originalError: error instanceof Error ? error.message : String(error || ''),
        releaseError:
          releaseError instanceof Error ? releaseError.message : String(releaseError || ''),
      });
    });
  };
  const finalizeFailedSigningAttempt = async (error: unknown): Promise<void> => {
    if (thresholdSignatureCreated) {
      await recordSuccessfulWalletSigningSessionSpend();
      return;
    }
    await releaseUnsignedNonceLeases(error);
    await recordFailedWalletSigningSessionSpend(error);
  };
  const buildRequestPayload = (
    xClientBaseOverride?: string,
  ): Omit<WasmSignTransactionsWithActionsRequest, 'sessionId'> => {
    return {
      rpcCall: resolvedRpcCall,
      createdAt: Date.now(),
      ...buildNearWorkerSigningEnvelope({
        threshold: {
          relayerUrl: thresholdSessionState.relayerUrl,
          thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
          xClientBaseB64u: xClientBaseOverride || thresholdSessionState.xClientBaseB64u,
          thresholdSessionKind: thresholdSessionState.sessionKind,
          thresholdSessionJwt: thresholdSessionState.thresholdSessionJwt,
        },
      }),
      txSigningRequests,
      intentDigest,
      transactionContext,
      credential: credentialForRelayJson,
    };
  };
  if (!activeBudgetAdmittedOperation) {
    // Non-warm confirmed-auth lanes can only become budget-admitted after the
    // confirmation step has produced fresh auth material. Admit them here, still
    // before the signer worker can consume the threshold session.
    activeBudgetAdmittedOperation = await admitBudgetForSelectedSpendLane(
      buildSelectedBudgetSpendLane(),
    );
  }
  const budgetAdmittedOperationForWorker = activeBudgetAdmittedOperation;
  if (String(budgetAdmittedOperationForWorker.lane.thresholdSessionId) !== canonicalThresholdSessionId) {
    throw new Error(
      '[SigningEngine][near] budget-admitted transaction lane does not match worker session',
    );
  }
  let requestPayload = buildRequestPayload(xClientBaseB64u);

  const executeSignRequest = async (
    admittedOperation: BudgetAdmittedOperation<NearEd25519TransactionLane>,
    payload: Omit<WasmSignTransactionsWithActionsRequest, 'sessionId'>,
  ) => {
    if (String(admittedOperation.lane.thresholdSessionId) !== canonicalThresholdSessionId) {
      throw new Error(
        '[SigningEngine][near] budget-admitted transaction lane does not match worker session',
      );
    }
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_10_COMMIT_STARTED,
      status: 'running',
      interaction: { kind: 'none', overlay: 'none' },
    });
    const response = await executeWorkerOperation({
      ctx,
      kind: 'nearSigner',
      request: {
        sessionId: canonicalThresholdSessionId,
        type: WorkerRequestType.SignTransactionsWithActions,
        payload,
      },
    });
    return requireOkSignTransactionsWithActionsResponse(response);
  };

  try {
    // Ed25519 threshold signing consumes the wallet session on the server as
    // part of the signing ceremony. A local pre-sign reservation would double
    // count in UI projections until finalization reconciles it.
    const okResponse = await executeSignRequest(budgetAdmittedOperationForWorker, requestPayload);
    thresholdSignatureCreated = true;
    await markNearNonceLeasesSigned(ctx, nonceLeaseRefs);
    const signedResults = toSignedTransactionResults({
      okResponse,
      expectedTransactionCount: transactions.length,
      nearAccountId,
      warnings,
      nonceLeases: nonceLeaseRefs,
    });
    await recordSuccessfulWalletSigningSessionSpend();
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_11_TRANSACTION_SIGNED,
      status: 'succeeded',
      interaction: { kind: 'none', overlay: 'hide' },
    });
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_15_COMPLETED,
      status: 'succeeded',
      interaction: { kind: 'none', overlay: 'none' },
      data: { operation: 'sign' },
    });
    return signedResults;
  } catch (e: unknown) {
    const err = e instanceof Error ? e : new Error(String(e));

    if (isThresholdSignerMissingKeyError(err)) {
      try {
        const repairPrfFirstB64u =
          prfFirstB64u ||
          (thresholdAuthPlan.warmSessionReady
            ? await (async () => {
                const prfFirst = await signingSessionCoordinator.claimPrfFirstByThresholdSessionId({
                  thresholdSessionId: thresholdAuthPlan.sessionId,
                  uses: usesNeeded,
                  errorContext: 'threshold-ed25519 transaction signing repair',
                  walletId: nearAccountId,
                  authMethod: thresholdAuthPlan.lane.authMethod,
                  curve: 'ed25519',
                  chain: 'near',
                  walletSigningSessionId: thresholdAuthPlan.lane.walletSigningSessionId,
                });
                return prfFirst;
              })()
            : requirePrfFirstFromCredential(credentialWithPrf));
        const repairedXClientBaseB64u = await repairThresholdEd25519MissingRelayerKey({
          ctx,
          operationLabel: 'transactions',
          thresholdSessionId: canonicalThresholdSessionId,
          thresholdSessionJwt: thresholdSessionState.thresholdSessionJwt,
          relayerUrl: thresholdSessionState.relayerUrl,
          relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
          nearAccountId,
          keyVersion: signingContext.threshold.thresholdKeyMaterial.keyVersion,
          participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map(
            (p) => p.id,
          ),
          prfFirstB64u: repairPrfFirstB64u,
          ...(onEvent
            ? {
                onProgress: (message: string) => {
                  emitConfirmedAuthSideEffectStarted('threshold_reconnect');
                  emitNearSigningEvent(onEvent, nearAccountId, {
                    phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
                    status: 'running',
                    message,
                    interaction: { kind: 'none', overlay: 'none' },
                  });
                },
              }
            : {}),
        });
        requestPayload = buildRequestPayload(repairedXClientBaseB64u);
        const okResponse = await executeSignRequest(
          budgetAdmittedOperationForWorker,
          requestPayload,
        );
        thresholdSignatureCreated = true;
        await markNearNonceLeasesSigned(ctx, nonceLeaseRefs);
        const signedResults = toSignedTransactionResults({
          okResponse,
          expectedTransactionCount: transactions.length,
          nearAccountId,
          warnings,
          nonceLeases: nonceLeaseRefs,
        });
        await recordSuccessfulWalletSigningSessionSpend();
        emitNearSigningEvent(onEvent, nearAccountId, {
          phase: SigningEventPhase.STEP_11_TRANSACTION_SIGNED,
          status: 'succeeded',
          interaction: { kind: 'none', overlay: 'hide' },
        });
        emitNearSigningEvent(onEvent, nearAccountId, {
          phase: SigningEventPhase.STEP_15_COMPLETED,
          status: 'succeeded',
          interaction: { kind: 'none', overlay: 'none' },
          data: { operation: 'sign' },
        });
        return signedResults;
      } catch (repairError: unknown) {
        const repairErr =
          repairError instanceof Error ? repairError : new Error(String(repairError));
        if (isThresholdSignerMissingKeyError(repairErr)) {
          const msg =
            '[SigningEngine] threshold-signer requested but the relayer signing share could not be repaired from the active HSS session';
          console.warn(msg);
          warnings.push(msg);
          const finalError = new Error(msg);
          await finalizeFailedSigningAttempt(finalError);
          throw finalError;
        }
        await finalizeFailedSigningAttempt(repairErr);
        throw repairErr;
      }
    }

    if (isThresholdSessionAuthUnavailableError(err)) {
      const finalError = new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
      await finalizeFailedSigningAttempt(finalError);
      throw finalError;
    }

    await finalizeFailedSigningAttempt(err);
    throw err;
  }
}

async function releaseNearNonceLeases(
  ctx: SigningRuntimeDeps,
  nonceLeases: readonly NonceLeaseRef[],
  reason: 'cancelled' | 'auth_failed' | 'signing_failed' | 'nonce_failed',
): Promise<void> {
  if (!nonceLeases.length) return;
  await Promise.all(
    nonceLeases.map((nonceLease) =>
      ctx.nonceCoordinator.release({
        leaseId: nonceLease.leaseId,
        operationId: nonceLease.operationId,
        reason,
      }),
    ),
  );
}

async function markNearNonceLeasesSigned(
  ctx: SigningRuntimeDeps,
  nonceLeases: readonly NonceLeaseRef[],
): Promise<void> {
  if (!nonceLeases.length) return;
  await Promise.all(
    nonceLeases.map((nonceLease) =>
      ctx.nonceCoordinator.markSigned({
        leaseId: nonceLease.leaseId,
        operationId: nonceLease.operationId,
      }),
    ),
  );
}

function toSignedTransactionResults(args: {
  okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions>;
  expectedTransactionCount: number;
  nearAccountId: string;
  warnings: string[];
  nonceLeases?: readonly NonceLeaseRef[];
}): Array<{
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
  nonceLease?: NonceLeaseRef;
}> {
  const signedTransactions = args.okResponse.payload.signedTransactions || [];
  if (signedTransactions.length !== args.expectedTransactionCount) {
    throw new Error(
      `Expected ${args.expectedTransactionCount} signed transactions but received ${signedTransactions.length}`,
    );
  }

  return signedTransactions.map((signedTx, index) => {
    if (!signedTx || !signedTx.transaction || !signedTx.signature) {
      throw new Error(`Incomplete signed transaction data received for transaction ${index + 1}`);
    }
    const nonceLease = args.nonceLeases?.[index];
    const signedTransaction = new SignedTransaction({
      transaction: signedTx.transaction,
      signature: signedTx.signature,
      borsh_bytes: Array.from(signedTx.borshBytes || []),
      ...(nonceLease ? { nonceLease } : {}),
    });
    return {
      signedTransaction,
      nearAccountId: toAccountId(args.nearAccountId),
      logs: [...(args.okResponse.payload.logs || []), ...args.warnings],
      ...(nonceLease ? { nonceLease } : {}),
    };
  });
}

type ThresholdSigningContext = {
  signingNearPublicKeyStr: string;
  threshold: {
    relayerUrl: string;
    thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  };
};

function validateAndPrepareSigningContext(args: {
  nearAccountId: string;
  relayerUrl: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial | null;
}): ThresholdSigningContext {
  const thresholdKeyMaterial = args.thresholdKeyMaterial;
  if (!thresholdKeyMaterial) {
    throw new Error(`Missing threshold key material for ${args.nearAccountId}`);
  }

  const thresholdPublicKey = String(thresholdKeyMaterial.publicKey || '').trim();
  if (!thresholdPublicKey) {
    throw new Error(`Missing threshold signing public key for ${args.nearAccountId}`);
  }

  const relayerUrl = String(args.relayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('Missing relayerUrl (required for threshold-signer)');
  }

  const participantIds = normalizeThresholdEd25519ParticipantIds(
    thresholdKeyMaterial.participants.map((p) => p.id),
  );
  if (!participantIds || participantIds.length < 2) {
    throw new Error(
      `Invalid threshold signing participantIds (expected >=2 participants, got [${(participantIds || []).join(',')}])`,
    );
  }

  return {
    signingNearPublicKeyStr: thresholdPublicKey,
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
    },
  };
}

function requireOkSignTransactionsWithActionsResponse(
  response: TransactionResponse,
): WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions> {
  if (!isSignTransactionsWithActionsSuccess(response)) {
    if (isWorkerError(response)) {
      throw new Error(response.payload.error || 'Batch transaction signing failed');
    }
    throw new Error('Batch transaction signing failed');
  }

  if (!response.payload.success) {
    throw new Error(response.payload.error || 'Batch transaction signing failed');
  }
  return response;
}
