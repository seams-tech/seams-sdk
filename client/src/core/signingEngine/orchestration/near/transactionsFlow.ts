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
  NearPasskeyEd25519ReconnectHook,
} from '../../interfaces/near';
import {
  emailOtpSigningAuthPlan,
  formatEmailOtpSentText,
  passkeySigningAuthPlan,
} from '../shared/touchConfirmSigning';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
  type UserConfirmProgressEvent,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import { WebAuthnAuthenticationCredential } from '@/core/types';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/types';
import {
  isThresholdSessionAuthUnavailableError,
  isThresholdSignerMissingKeyError,
} from '@/core/signingEngine/threshold/session/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { executeWorkerOperation } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  generateSessionId,
  requirePrfFirstFromCredential,
  resolveNearSigningMaterials,
  toCredentialForRelayJson,
} from './shared/signingMaterials';
import { requireResolvedThresholdEd25519SessionState } from './shared/thresholdSessionAuth';
import { buildNearWorkerSigningEnvelope } from './shared/workerRequestAssembly';
import {
  buildNearThresholdSigningAuthPlan,
  createNearSigningSessionCoordinator,
  resolveNearThresholdSigningAuthContext,
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
import type { NonceLeaseRef } from '../../nonce/NonceCoordinator';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningPlannerDecisionTrace,
} from '../../session/signingSession/trace';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import { createSigningSessionBudgetFinalizer } from '../../session/signingSession/budgetFinalizer';
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
  const sessionId = providedSessionId ?? generateSessionId();
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
  if (callerProvidedSigningOperationId) {
    (sessionCoordinator || new SigningSessionCoordinator()).bindCallerProvidedOperationIdToFingerprint({
      operationId: ensureSigningOperationId(),
      operationFingerprint,
    });
  }
  const usesNeeded = 1;
  const shouldUseEmailOtpReauth =
    providedSigningAuthPlan?.kind === SigningAuthPlanKind.EmailOtpReauth || !!emailOtpSigning;
  const thresholdAuthContext =
    signingContext.threshold && !shouldUseEmailOtpReauth
      ? await resolveNearThresholdSigningAuthContext({
          warmSessionReader: signingSessionCoordinator,
          usesNeeded,
          nearAccountId,
          operationLabel: 'transaction signing',
        })
      : null;
  const resolvedThresholdSigningSession = thresholdAuthContext
    ? await (sessionCoordinator || new SigningSessionCoordinator()).resolveAuthPlanFromReadiness(
        thresholdAuthContext.coordinatorInput,
        (event) =>
          emitSigningPlannerDecisionTrace('near', event),
      )
    : null;
  const thresholdAuthPlan = thresholdAuthContext
    ? buildNearThresholdSigningAuthPlan({
        context: thresholdAuthContext,
        resolvedSigningSession: resolvedThresholdSigningSession!,
      })
    : null;
  const activeSigningLane = signingLane || thresholdAuthPlan?.lane;
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
  if (
    !providedSigningAuthPlan &&
    !emailOtpSigning &&
    thresholdAuthPlan?.signingAuthPlan?.kind === SigningAuthPlanKind.EmailOtpReauth
  ) {
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
  const signingAuthPlan = providedSigningAuthPlan
    ? providedSigningAuthPlan.kind === SigningAuthPlanKind.EmailOtpReauth && emailOtpPrompt
      ? { ...providedSigningAuthPlan, emailOtpPrompt }
      : providedSigningAuthPlan
    : emailOtpPrompt
      ? emailOtpSigningAuthPlan(emailOtpPrompt)
      : thresholdAuthPlan?.signingAuthPlan;
  const touchConfirmAuthPayload = signingAuthPlan
    ? { signingAuthPlan }
    : (thresholdAuthPlan?.touchConfirmAuthPayload ?? { signingAuthPlan: passkeySigningAuthPlan() });
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
  let canonicalThresholdSessionId = thresholdAuthPlan?.sessionId || sessionId;
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
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED,
      status: 'succeeded',
      message: 'NEAR signing session reconnected',
      interaction: { kind: 'none', overlay: 'none' },
      data: { sessionId: refreshedSessionId },
    });
  }
  const thresholdSessionState = requireResolvedThresholdEd25519SessionState({
    signingSessionCoordinator,
    thresholdSessionId: canonicalThresholdSessionId,
  });
  const provisionedRemainingUses = thresholdSessionState.record.remainingUses;
  if (emailOtpSigning && provisionedRemainingUses < usesNeeded) {
    throw new Error(
      `[SigningEngine] Email OTP NEAR signing session has ${provisionedRemainingUses} remaining use(s), but this operation requires ${usesNeeded}. Retry the Email OTP prompt to provision a fresh signing session.`,
    );
  }
  const cachedXClientBaseB64u = String(thresholdSessionState.xClientBaseB64u || '').trim();
  let ed25519WarmSessionBudgetClaimed = false;
  const prfFirstB64u = signingContext.threshold
    ? cachedXClientBaseB64u
      ? ''
      : thresholdAuthPlan?.warmSessionReady
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
            ed25519WarmSessionBudgetClaimed = true;
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
      : thresholdAuthPlan?.warmSessionReady
        ? 'warm_session'
        : (thresholdAuthPlan?.signingAuthPlan?.method ?? 'passkey'),
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
  const createNearBudgetFinalizer = () => {
    if (!signingContext.threshold || !sessionCoordinator) return;
    const walletSigningSessionId = String(
      thresholdSessionState.record.walletSigningSessionId || '',
    ).trim();
    if (!walletSigningSessionId) {
      throw new Error(
        '[SigningEngine][near] missing wallet signing session id for transaction budget spend',
      );
    }
    const recordSource = thresholdSessionState.record.source;
    const spendLane = requireSelectedNearSigningLane(
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
    return createSigningSessionBudgetFinalizer({
      signingSessionBudget: sessionCoordinator,
      operation: {
        operationId: confirmationOperationId,
        operationFingerprint,
        intent: SigningOperationIntent.TransactionSign,
      },
      lane: spendLane,
      onRecordSuccessError: (error) => {
        console.warn('[SigningEngine][near] failed to update wallet signing-session budget', {
          nearAccountId,
          walletSigningSessionId,
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
    const finalizer = createNearBudgetFinalizer();
    if (!finalizer) {
      walletSpendRecorded = true;
      return;
    }
    await finalizer.recordSuccess({
      ...(ed25519WarmSessionBudgetClaimed
        ? { alreadyConsumedThresholdSessionIds: [canonicalThresholdSessionId] }
        : {}),
    });
    walletSpendRecorded = true;
  };
  const reserveWalletSigningSessionBudget = async (): Promise<void> => {
    const finalizer = createNearBudgetFinalizer();
    if (!finalizer) return;
    await finalizer.reserve();
  };
  const recordFailedWalletSigningSessionSpend = (error: unknown): void => {
    if (walletSpendRecorded || thresholdSignatureCreated) return;
    const finalizer = createNearBudgetFinalizer();
    if (!finalizer) return;
    finalizer.recordZeroSpend(error);
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
    recordFailedWalletSigningSessionSpend(error);
  };
  const buildRequestPayload = (
    xClientBaseOverride?: string,
  ): Omit<WasmSignTransactionsWithActionsRequest, 'sessionId'> => {
    const currentThresholdSessionState = requireResolvedThresholdEd25519SessionState({
      signingSessionCoordinator,
      thresholdSessionId: canonicalThresholdSessionId,
    });
    return {
      rpcCall: resolvedRpcCall,
      createdAt: Date.now(),
      ...buildNearWorkerSigningEnvelope({
        threshold: {
          relayerUrl: currentThresholdSessionState.relayerUrl,
          thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
          xClientBaseB64u: xClientBaseOverride || currentThresholdSessionState.xClientBaseB64u,
          thresholdSessionKind: currentThresholdSessionState.sessionKind,
          thresholdSessionJwt: currentThresholdSessionState.thresholdSessionJwt,
        },
      }),
      txSigningRequests,
      intentDigest,
      transactionContext,
      credential: credentialForRelayJson,
    };
  };
  let requestPayload = buildRequestPayload(xClientBaseB64u);

  const executeSignRequest = async (
    payload: Omit<WasmSignTransactionsWithActionsRequest, 'sessionId'>,
  ) => {
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
    await reserveWalletSigningSessionBudget();
    const okResponse = await executeSignRequest(requestPayload);
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
          (thresholdAuthPlan?.warmSessionReady
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
                ed25519WarmSessionBudgetClaimed = true;
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
        const okResponse = await executeSignRequest(requestPayload);
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
