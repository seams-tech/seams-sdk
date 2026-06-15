import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { TransactionInputWasm } from '@/core/types/actions';
import {
  createSigningFlowEvent,
  SigningEventPhase,
  type CreateSigningFlowEventInput,
  type SigningFlowEvent,
} from '@/core/types/sdkSentEvents';
import {
  WorkerRequestType,
  type WasmSignTransactionsWithActionsRequest,
  isSignTransactionsWithActionsSuccess,
  isWorkerError,
  type ConfirmationConfig,
  type RpcCallPayload,
  type TransactionResponse,
  type WorkerSuccessResponse,
} from '@/core/types/signer-worker';
import { AccountId, toAccountId } from '@/core/types/accountIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import type { NearSigningRuntimeDeps } from '../../interfaces/runtime';
import type {
  NearEd25519TransactionSigningBoundary,
  NearEd25519WarmupHook,
  NearEmailOtpSigningHook,
  NearPreparedSigningSessionFinalizer,
  NearPasskeyEd25519ReconnectHook,
} from '../../interfaces/near';
import {
  isWarmSessionSigningAuthPlan,
  type UserConfirmProgressEvent,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { resolveNearNetwork, resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import { WebAuthnAuthenticationCredential } from '@/core/types';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/types';
import {
  isThresholdSessionAuthUnavailableError,
  isThresholdSignerMissingKeyError,
} from '@/core/signingEngine/threshold/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { executeWorkerOperation } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  requirePrfFirstFromCredential,
  resolveNearSigningMaterials,
  toCredentialForRelayJson,
} from './shared/signingMaterials';
import {
  refreshPasskeyEd25519SealedRecordAfterClientBase,
  requireResolvedThresholdEd25519SessionState,
  resolveThresholdEd25519SessionStateFromRecord,
  type ResolvedThresholdEd25519SessionState,
} from './shared/thresholdSessionAuth';
import { buildNearWorkerSigningEnvelope } from '../../chains/near/workerRequest';
import { buildNearTransactionSigningPayloads } from '../../chains/near/payloads';
import {
  createNearSigningSessionCoordinator,
  THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR,
} from './shared/thresholdAuthMode';
import { ensureThresholdEd25519HssClientBase } from '../../threshold/ed25519/hssClientBase';
import { repairThresholdEd25519MissingRelayerKey } from '../../threshold/ed25519/repairMissingRelayerKey';
import type { SelectedEd25519Lane } from '../../session/identity/laneIdentity';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningOperationId,
} from '../../session/operationState/types';
import type { NearTransactionSigningLane } from '../../session/operationState/lanes';
import {
  admitTransactionBudget,
  finalizeSignedTransactionOperation,
  replacePreparedTransactionLane,
  signPreparedTransactionOperation,
  type BudgetAdmittedOperation,
  type PreparedTransactionOperation,
  type SignedTransactionOperation,
  type TransactionReadiness,
} from '../../session/operationState/transactionState';
import type { NonceLeaseRef } from '../../interfaces/nonceLease';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
} from '../../session/operationState/trace';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type {
  BudgetFinalizationSpend,
  SigningSessionBudgetStatusAuth,
  SigningSessionPreparedBudgetIdentity,
} from '../../session/budget/budget';
import {
  createSigningSessionBudgetFinalizer,
  type SigningSessionBudgetFinalizer,
} from '../../session/budget/budgetFinalizer';
import {
  parseThresholdEd25519NearTransaction,
  thresholdEd25519NearTransactionPlanningOperationFingerprint,
} from '@shared/threshold/ed25519OperationFingerprint';
import {
  SigningOperationCommandKind,
  runSigningOperationCommand,
  type SigningOperationCommand,
} from '../shared/signingStateMachine';
import { requireNearStepUpAuth } from './requireNearStepUpAuth';
import { runSigningConfirmationCommand } from '../shared/signingConfirmation';
import { buildNearEd25519StepUpAuthorization } from './stepUpAuthorization';
import type { NearAccountRef } from '../../interfaces/ecdsaChainTarget';
import { requiredNearTransactionSignatureUses } from './signatureUses';
import {
  tryFinalizeRouterAbEd25519NearTransactionNormalSigning,
  tryFinalizeThresholdEd25519NearTransactionPresign,
} from './shared/ed25519PresignFinalize';
import { emitThresholdEd25519PresignMetric } from './shared/ed25519PresignMetrics';

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

function budgetStatusAuthFromEd25519SessionState(
  state: ResolvedThresholdEd25519SessionState,
): SigningSessionBudgetStatusAuth {
  const thresholdSessionId = String(state.thresholdSessionId || '').trim();
  const relayerUrl = String(state.relayerUrl || '').trim();
  if (!thresholdSessionId || !relayerUrl) {
    throw new Error('[SigningEngine][near] refreshed signing session is missing budget auth');
  }
  return {
    thresholdSessionId,
    relayerUrl,
    ...(state.thresholdSessionAuthToken
      ? { thresholdSessionAuthToken: state.thresholdSessionAuthToken }
      : {}),
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

function createNearTransactionSigningOperationId(): SigningOperationId {
  const randomId = secureRandomBase64Url(32, 'NEAR transaction signing operation IDs');
  return SigningSessionIds.signingOperation(`near-transaction-sign:${randomId}`);
}

/**
 * Sign multiple transactions with a shared WebAuthn credential.
 * Efficiently processes multiple transactions with one PRF-backed signing session.
 */

export async function runNearTransactionsWithActionsSigning({
  ctx,
  nearAccount,
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
  ed25519SigningBoundary,
  finalizePreparedSigningSession,
  ed25519Warmup,
  passkeyEd25519Reconnect,
}: {
  ctx: NearSigningRuntimeDeps;
  nearAccount: NearAccountRef;
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
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  ed25519SigningBoundary: NearEd25519TransactionSigningBoundary;
  finalizePreparedSigningSession?: NearPreparedSigningSessionFinalizer;
  ed25519Warmup?: NearEd25519WarmupHook;
  passkeyEd25519Reconnect?: NearPasskeyEd25519ReconnectHook;
}): Promise<
  Array<{
    signedTransaction: SignedTransaction;
    nearAccountId: AccountId;
    logs?: string[];
  }>
> {
  let signingOperationId = providedSigningOperationId;
  const callerProvidedSigningOperationId = Boolean(providedSigningOperationId);
  const ensureSigningOperationId = (): SigningOperationId => {
    signingOperationId = signingOperationId || createNearTransactionSigningOperationId();
    return signingOperationId;
  };
  const nearAccountId = toAccountId(nearAccount.accountId);
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
    nearAccount,
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
    nearAccountId,
  } as RpcCallPayload;
  const { txSigningRequests, confirmationTransactions } = buildNearTransactionSigningPayloads({
    nearAccountId: String(resolvedRpcCall.nearAccountId),
    transactions,
  });
  const presignFingerprintTransactions = txSigningRequests.map((transaction, index) =>
    parseThresholdEd25519NearTransaction(transaction, `txSigningRequests[${index}]`),
  );
  const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
    await thresholdEd25519NearTransactionPlanningOperationFingerprint({
      nearAccountId,
      nearNetworkId: resolveNearNetwork(
        ctx.chains || PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains,
      ),
      relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
      signerPublicKey: signingContext.threshold.thresholdKeyMaterial.publicKey,
      transactions: presignFingerprintTransactions,
    }),
  );

  // UserConfirm before sending anything to the signer worker.
  // WebAuthn uses the typed threshold session policy challenge when passkey reauth is required.
  if (!ctx.touchConfirm) {
    throw new Error('UiConfirm bridge not available for signing');
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
  const requiredSignatureUses = requiredNearTransactionSignatureUses(txSigningRequests);
  const confirmationOperationId = ensureSigningOperationId();
  const signingOperation = {
    operationId: confirmationOperationId,
    operationFingerprint,
    intent: SigningOperationIntent.TransactionSign,
  };
  const runSharedNearTransactionCommand = async <T>(args: {
    commandKind: SigningOperationCommand['kind'];
    execute: () => Promise<T>;
  }): Promise<T> =>
    await runSigningOperationCommand({
      signingSessionPlan: ed25519SigningBoundary.signingSessionPlan,
      signingOperation,
      commandKind: args.commandKind,
      execute: args.execute,
    });
  const providedSessionId = ed25519SigningBoundary.sessionId;
  const sessionId = String(providedSessionId || '').trim();
  const providedSigningAuthPlan = ed25519SigningBoundary.signingAuthPlan;
  const signingLane = ed25519SigningBoundary.signingLane;
  if (!transactionOperation) {
    throw new Error(
      '[SigningEngine][near] threshold transaction signing requires prepared transaction operation',
    );
  }
  if (
    isWarmSessionSigningAuthPlan(providedSigningAuthPlan) &&
    providedSigningAuthPlan.sessionId !== providedSessionId
  ) {
    throw new Error(
      '[SigningEngine][near] warm-session auth plan must match prepared session identity',
    );
  }
  const thresholdAuthPlan = {
    sessionId: isWarmSessionSigningAuthPlan(providedSigningAuthPlan)
      ? providedSigningAuthPlan.sessionId
      : providedSessionId,
    lane: signingLane,
    signingAuthPlan: providedSigningAuthPlan,
    confirmationAuthPayload: { signingAuthPlan: providedSigningAuthPlan },
    warmSessionReady: isWarmSessionSigningAuthPlan(providedSigningAuthPlan),
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
  const emitUiConfirmProgress = (progress: UserConfirmProgressEvent): void => {
    if (progress.phase === 'auth.passkey.prompt.started') {
      emitConfirmedAuthSideEffectStarted('passkey_reauth');
    }
  };
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
    status: 'waiting_for_user',
    message: 'Opening confirmation prompt',
    interaction: { kind: 'transaction_confirmation', overlay: 'show' },
  });
  const preparedStepUp = await requireNearStepUpAuth({
    signingAuthPlan: providedSigningAuthPlan,
    signingLane,
    requiredSignatureUses,
    ...(emailOtpSigning ? { emailOtpSigning } : {}),
    ...(passkeyEd25519Reconnect ? { passkeyEd25519Reconnect } : {}),
  });
  const confirmationAuthPayload = preparedStepUp.confirmationAuthPayload;
  if (isWarmSessionSigningAuthPlan(confirmationAuthPayload.signingAuthPlan)) {
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
      status: 'succeeded',
      interaction: { kind: 'none', overlay: 'none' },
      data: {
        sessionId: confirmationAuthPayload.signingAuthPlan.sessionId,
        expiresAtMs: confirmationAuthPayload.signingAuthPlan.expiresAtMs,
        remainingUses: confirmationAuthPayload.signingAuthPlan.remainingUses,
      },
    });
  }
  const confirmation = await runSigningConfirmationCommand({
    signingSessionPlan: ed25519SigningBoundary.signingSessionPlan,
    signingOperation,
    runtime: touchConfirm,
    request: {
      ctx: { touchConfirm },
      sessionId,
      chain: 'near',
      kind: 'transaction',
      ...confirmationAuthPayload,
      txSigningRequests: confirmationTransactions,
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
      ...(preparedStepUp.kind === 'email_otp'
        ? { emailOtpPrompt: preparedStepUp.emailOtpPrompt }
        : {}),
      ...(preparedStepUp.kind === 'passkey' &&
      preparedStepUp.plannedPasskeyReconnect.sessionPolicyDigest32
        ? {
            webauthnChallenge: {
              kind: 'threshold_session_policy' as const,
              digest32B64u: preparedStepUp.plannedPasskeyReconnect.sessionPolicyDigest32,
            },
          }
        : {}),
      onProgress: emitUiConfirmProgress,
    },
  });
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
    status: 'succeeded',
    interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
  });
  const stepUpAuthorization = buildNearEd25519StepUpAuthorization({
    prepared: preparedStepUp,
    confirmation,
  });

  const intentDigest = confirmation.intentDigest;
  const transactionContext = confirmation.transactionContext;
  const nonceLeaseRefs = confirmation.nonceLeases || [];
  let thresholdSignatureCreated = false;
  let walletSpendRecorded = false;
  let signedTransactionOperation: SignedTransactionOperation<SelectedEd25519Lane> | null = null;

  const credentialWithPrf: WebAuthnAuthenticationCredential | undefined =
    stepUpAuthorization.kind === 'passkey' ? stepUpAuthorization.credential : undefined;

  const credentialForRelayJson = toCredentialForRelayJson(credentialWithPrf);

  const preparedPayload = await runSharedNearTransactionCommand({
    commandKind: SigningOperationCommandKind.PreparePayload,
    execute: async () => {
      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED,
        status: 'running',
        message: 'Preparing NEAR signer',
        interaction: { kind: 'none', overlay: 'none' },
      });
      let canonicalThresholdSessionId = thresholdAuthPlan.sessionId;
      let refreshedThresholdSessionState: ResolvedThresholdEd25519SessionState | null = null;
      let refreshedBudgetIdentityRequired = false;
      if (stepUpAuthorization.kind === 'email_otp') {
        if (!emailOtpSigning) {
          throw new Error('[SigningEngine] Email OTP step-up runtime is unavailable');
        }
        const refreshed = await emailOtpSigning.complete(stepUpAuthorization);
        emitNearSigningEvent(onEvent, nearAccountId, {
          phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
        });
        const refreshedSessionId = String(refreshed.sessionId || '').trim();
        if (!refreshedSessionId) {
          throw new Error(
            '[SigningEngine] Email OTP signing did not return a threshold session id',
          );
        }
        canonicalThresholdSessionId = refreshedSessionId;
        refreshedThresholdSessionState = refreshed.sessionState || null;
        refreshedBudgetIdentityRequired = true;
      } else if (stepUpAuthorization.kind === 'passkey' && passkeyEd25519Reconnect) {
        if (!credentialWithPrf) {
          throw new Error(
            '[SigningEngine] missing WebAuthn credential for passkey session reconnect',
          );
        }
        emitConfirmedAuthSideEffectStarted('threshold_reconnect');
        emitNearSigningEvent(onEvent, nearAccountId, {
          phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
          status: 'running',
          message: 'Reconnecting NEAR signing session',
          interaction: { kind: 'none', overlay: 'none' },
        });
        const refreshed = await passkeyEd25519Reconnect.reconnect({
          authorization: stepUpAuthorization,
          requiredSignatureUses,
        });
        const refreshedSessionId = String(refreshed.sessionId || '').trim();
        if (!refreshedSessionId) {
          throw new Error('[SigningEngine] passkey signing did not return a threshold session id');
        }
        if (refreshedSessionId !== stepUpAuthorization.plannedPasskeyReconnect.sessionId) {
          throw new Error(
            '[SigningEngine] passkey signing returned a different threshold session id than the confirmed session policy',
          );
        }
        canonicalThresholdSessionId = refreshedSessionId;
        refreshedThresholdSessionState = refreshed.sessionState || null;
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
        refreshedThresholdSessionState &&
        refreshedThresholdSessionState.thresholdSessionId === canonicalThresholdSessionId
          ? refreshedThresholdSessionState
          : requireResolvedThresholdEd25519SessionState({
              signingSessionCoordinator,
              thresholdSessionId: canonicalThresholdSessionId,
            });
      const trustedBudgetStatusAuth =
        budgetStatusAuthFromEd25519SessionState(thresholdSessionState);
      const provisionedRemainingUses = thresholdSessionState.remainingUses;
      if (emailOtpSigning && provisionedRemainingUses < requiredSignatureUses) {
        throw new Error(
          `[SigningEngine] Email OTP NEAR signing session has ${provisionedRemainingUses} remaining signature use(s), but this operation requires ${requiredSignatureUses}. Retry the Email OTP prompt to provision a fresh signing session.`,
        );
      }
      const cachedXClientBaseB64u = String(thresholdSessionState.xClientBaseB64u || '').trim();
      const canClaimWarmSessionPrfFirst = thresholdAuthPlan.warmSessionReady;
      const prfFirstB64u = signingContext.threshold
        ? cachedXClientBaseB64u
          ? ''
          : canClaimWarmSessionPrfFirst
            ? await (async () => {
                const prfFirst = await signingSessionCoordinator.claimPrfFirstByThresholdSessionId({
                  kind: 'wallet_scoped_ed25519_claim',
                  thresholdSessionId: thresholdAuthPlan.sessionId,
                  uses: requiredSignatureUses,
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
        console.warn('[SigningEngine][near][ed25519] missing client base and PRF for signing', {
          nearAccountId,
          thresholdSessionId: canonicalThresholdSessionId,
          authMethod: thresholdAuthPlan.lane.authMethod,
          warmSessionReady: thresholdAuthPlan.warmSessionReady,
          hasCredentialWithPrf: Boolean(credentialWithPrf),
        });
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
          existingXClientBaseB64u: thresholdSessionState.xClientBaseB64u,
          thresholdSessionAuthToken: thresholdSessionState.thresholdSessionAuthToken,
          signingRootId: thresholdSessionState.signingRootId,
          relayerUrl: thresholdSessionState.relayerUrl,
          relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
          nearAccountId,
          keyVersion: signingContext.threshold.thresholdKeyMaterial.keyVersion,
          participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map(
            (p) => p.id,
          ),
          prfFirstB64u,
          persistClientBase: thresholdSessionState.persistClientBase,
        }));
      await refreshPasskeyEd25519SealedRecordAfterClientBase({
        touchConfirm,
        nearAccountId,
        thresholdSessionState,
        thresholdSessionId: canonicalThresholdSessionId,
        xClientBaseB64u,
      });
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
      return {
        canonicalThresholdSessionId,
        thresholdSessionState,
        trustedBudgetStatusAuth,
        refreshedBudgetIdentityRequired,
        prfFirstB64u,
        xClientBaseB64u,
      };
    },
  });
  const {
    canonicalThresholdSessionId,
    thresholdSessionState,
    trustedBudgetStatusAuth,
    prfFirstB64u,
    xClientBaseB64u,
  } = preparedPayload;
  let { refreshedBudgetIdentityRequired } = preparedPayload;
  let activeBudgetAdmittedOperation = ed25519SigningBoundary.initialBudgetAdmittedOperation;
  const buildBudgetSigningLane = (): NearTransactionSigningLane => {
    if (String(thresholdSessionState.thresholdSessionId) !== canonicalThresholdSessionId) {
      throw new Error(
        '[SigningEngine][near] budget signing lane session does not match worker session',
      );
    }
    return thresholdSessionState.signingLane;
  };
  const admitSelectedNearTransactionLaneBudget = async (
    lane: NearTransactionSigningLane,
  ): Promise<BudgetAdmittedOperation<SelectedEd25519Lane>> => {
    const budgetIdentity = await sessionCoordinator.prepareBudgetIdentity({
      lane,
      ...(trustedBudgetStatusAuth ? { trustedStatusAuth: trustedBudgetStatusAuth } : {}),
      operationUsesNeeded: requiredSignatureUses,
    });
    const refreshedPreparedOperation = replacePreparedTransactionLane(transactionOperation, {
      lane,
      readiness: readinessFromPreparedBudgetIdentity(budgetIdentity),
    });
    return admitTransactionBudget(refreshedPreparedOperation, { budgetIdentity });
  };
  const createNearBudgetFinalizer = (
    finalization: BudgetFinalizationSpend,
    operationState: BudgetAdmittedOperation<SelectedEd25519Lane>,
  ): SigningSessionBudgetFinalizer | undefined => {
    if (!signingContext.threshold || !sessionCoordinator) return;
    return createSigningSessionBudgetFinalizer({
      budgetMode: 'with_budget',
      signingSessionBudget: sessionCoordinator,
      budgetIdentity: operationState.budgetAdmission.budgetIdentity,
      finalization,
      onRecordSuccessError: (error) => {
        console.warn('[SigningEngine][near] failed to update wallet signing-session budget', {
          nearAccountId,
          walletSigningSessionId: String(operationState.lane.walletSigningSessionId),
          thresholdSessionId: String(operationState.lane.thresholdSessionId),
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
      onRecordZeroSpendError: (ledgerError) => {
        console.warn('[SigningEngine][near] failed to record wallet signing-session zero spend', {
          nearAccountId,
          thresholdSessionId: String(operationState.lane.thresholdSessionId),
          error:
            ledgerError instanceof Error
              ? ledgerError.message
              : String(ledgerError || 'unknown error'),
        });
      },
    });
  };
  const recordSuccessfulWalletSigningSessionSpend = async (
    operationState: SignedTransactionOperation<SelectedEd25519Lane>,
  ): Promise<void> => {
    if (walletSpendRecorded) return;
    const finalizer = createNearBudgetFinalizer(
      {
        kind: 'externally_consumed_success',
        spend: {
          operationId: confirmationOperationId,
          ...(operationFingerprint ? { operationFingerprint } : {}),
          walletId: nearAccountId,
          walletSigningSessionId: buildBudgetSigningLane().walletSigningSessionId,
          lane: buildBudgetSigningLane(),
          thresholdSessionIds: [operationState.lane.thresholdSessionId],
          backingMaterialSessionIds: [],
          uses: requiredSignatureUses,
          reason: SigningOperationIntent.TransactionSign,
        },
        ...(trustedBudgetStatusAuth ? { trustedStatusAuth: trustedBudgetStatusAuth } : {}),
        alreadyConsumedThresholdSessionIds: [operationState.lane.thresholdSessionId],
      },
      operationState,
    );
    if (!finalizer) {
      walletSpendRecorded = true;
      return;
    }
    if (finalizePreparedSigningSession) {
      await finalizePreparedSigningSession({
        status: 'success',
        hooks: {
          recordSuccess: async () => {
            await finalizer.recordSuccess();
          },
          recordZeroSpend: (error) => finalizer.recordZeroSpend(error),
        },
      });
    } else {
      await finalizer.recordSuccess();
    }
    walletSpendRecorded = true;
  };
  const recordFailedWalletSigningSessionSpend = async (error: unknown): Promise<void> => {
    if (walletSpendRecorded || thresholdSignatureCreated) return;
    const admittedOperation = activeBudgetAdmittedOperation;
    if (!admittedOperation) return;
    const finalizer = createNearBudgetFinalizer(
      {
        kind: 'zero_spend',
        operationId: confirmationOperationId,
        operationFingerprint,
        lane: buildBudgetSigningLane(),
        reason: 'signing_failed',
        error,
      },
      admittedOperation,
    );
    if (!finalizer) return;
    if (finalizePreparedSigningSession) {
      await finalizePreparedSigningSession({
        status: 'zero_spend',
        error,
        hooks: {
          recordSuccess: async () => {
            await finalizer.recordSuccess();
          },
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
      if (signedTransactionOperation) {
        await recordSuccessfulWalletSigningSessionSpend(signedTransactionOperation);
      }
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
          thresholdSessionAuthToken: thresholdSessionState.thresholdSessionAuthToken,
        },
      }),
      txSigningRequests,
      intentDigest,
      transactionContext,
      credential: credentialForRelayJson,
    };
  };
  let requestPayload = buildRequestPayload(xClientBaseB64u);
  const budgetAdmittedOperationForWorker = await runSharedNearTransactionCommand({
    commandKind: SigningOperationCommandKind.ReserveBudget,
    execute: async () => {
      if (refreshedBudgetIdentityRequired) {
        activeBudgetAdmittedOperation =
          await admitSelectedNearTransactionLaneBudget(buildBudgetSigningLane());
        refreshedBudgetIdentityRequired = false;
      }
      if (!activeBudgetAdmittedOperation) {
        // Confirmed-auth lanes can only become budget-admitted after confirmation
        // has produced fresh auth material.
        activeBudgetAdmittedOperation =
          await admitSelectedNearTransactionLaneBudget(buildBudgetSigningLane());
      }
      if (
        String(activeBudgetAdmittedOperation.lane.thresholdSessionId) !==
        canonicalThresholdSessionId
      ) {
        throw new Error(
          '[SigningEngine][near] budget-admitted transaction lane does not match worker session',
        );
      }
      return activeBudgetAdmittedOperation;
    },
  });

  const executeSignRequest = async (
    admittedOperation: BudgetAdmittedOperation<SelectedEd25519Lane>,
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
    const presignXClientBaseB64u = payload.threshold.xClientBaseB64u || xClientBaseB64u;
    const routerAbNormalSigningResult = presignXClientBaseB64u
      ? await tryFinalizeRouterAbEd25519NearTransactionNormalSigning({
          ctx,
          thresholdSessionId: canonicalThresholdSessionId,
          thresholdSessionState,
          thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
          nearAccountId,
          xClientBaseB64u: presignXClientBaseB64u,
          operationId: signingOperation.operationId,
          operationFingerprint,
          txSigningRequests,
          transactionContext,
        })
      : null;
    if (routerAbNormalSigningResult) {
      return routerAbNormalSigningResult.okResponse;
    }
    const presignResult = presignXClientBaseB64u
      ? await tryFinalizeThresholdEd25519NearTransactionPresign({
          ctx,
          thresholdSessionId: canonicalThresholdSessionId,
          thresholdSessionState,
          thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
          nearAccountId,
          xClientBaseB64u: presignXClientBaseB64u,
          operationId: signingOperation.operationId,
          operationFingerprint,
          txSigningRequests,
          transactionContext,
        })
      : null;
    if (presignResult) {
      return presignResult.okResponse;
    }
    const fallbackStartedAtMs = Date.now();
    const response = await executeWorkerOperation({
      ctx,
      kind: 'nearSigner',
      request: {
        sessionId: canonicalThresholdSessionId,
        type: WorkerRequestType.SignTransactionsWithActions,
        payload,
      },
    });
    emitThresholdEd25519PresignMetric({
      metric: 'ed25519_two_rtt_fallback_ms',
      nearAccountId,
      nearNetworkId: resolveNearNetwork(
        ctx.chains || PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains,
      ),
      operationId: signingOperation.operationId,
      operationFingerprint,
      durationMs: Date.now() - fallbackStartedAtMs,
    });
    return requireOkSignTransactionsWithActionsResponse(response);
  };

  return await runSharedNearTransactionCommand({
    commandKind: SigningOperationCommandKind.Sign,
    execute: async () => {
      try {
        // Ed25519 threshold signing consumes the wallet session on the server as
        // part of the signing ceremony. Local finalization only reconciles status.
        const signedOperation = await signPreparedTransactionOperation(
          budgetAdmittedOperationForWorker,
          requestPayload,
          { sign: executeSignRequest },
        );
        signedTransactionOperation = signedOperation;
        const okResponse = signedOperation.result;
        thresholdSignatureCreated = true;
        await markNearNonceLeasesSigned(ctx, nonceLeaseRefs);
        const signedResults = toSignedTransactionResults({
          okResponse,
          expectedTransactionCount: txSigningRequests.length,
          nearAccountId,
          warnings,
          nonceLeases: nonceLeaseRefs,
        });
        await finalizeSignedTransactionOperation(signedOperation, {
          recordSuccess: async (operation) =>
            await recordSuccessfulWalletSigningSessionSpend(operation),
        });
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
                    const prfFirst =
                      await signingSessionCoordinator.claimPrfFirstByThresholdSessionId({
                        kind: 'wallet_scoped_ed25519_claim',
                        thresholdSessionId: thresholdAuthPlan.sessionId,
                        uses: requiredSignatureUses,
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
              thresholdSessionAuthToken: thresholdSessionState.thresholdSessionAuthToken,
              signingRootId: thresholdSessionState.signingRootId,
              relayerUrl: thresholdSessionState.relayerUrl,
              relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
              nearAccountId,
              keyVersion: signingContext.threshold.thresholdKeyMaterial.keyVersion,
              participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map(
                (p) => p.id,
              ),
              prfFirstB64u: repairPrfFirstB64u,
              persistClientBase: thresholdSessionState.persistClientBase,
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
            await refreshPasskeyEd25519SealedRecordAfterClientBase({
              touchConfirm,
              nearAccountId,
              thresholdSessionState,
              thresholdSessionId: canonicalThresholdSessionId,
              xClientBaseB64u: repairedXClientBaseB64u,
            });
            requestPayload = buildRequestPayload(repairedXClientBaseB64u);
            const signedOperation = await signPreparedTransactionOperation(
              budgetAdmittedOperationForWorker,
              requestPayload,
              { sign: executeSignRequest },
            );
            signedTransactionOperation = signedOperation;
            const okResponse = signedOperation.result;
            thresholdSignatureCreated = true;
            await markNearNonceLeasesSigned(ctx, nonceLeaseRefs);
            const signedResults = toSignedTransactionResults({
              okResponse,
              expectedTransactionCount: txSigningRequests.length,
              nearAccountId,
              warnings,
              nonceLeases: nonceLeaseRefs,
            });
            await finalizeSignedTransactionOperation(signedOperation, {
              recordSuccess: async (operation) =>
                await recordSuccessfulWalletSigningSessionSpend(operation),
            });
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
          console.warn('[SigningEngine][near][transactions] threshold session auth unavailable', {
            nearAccountId,
            message: err.message,
            requiredSignatureUses,
            thresholdSessionId: thresholdAuthPlan.sessionId,
            authMethod: thresholdAuthPlan.lane.authMethod,
            warmSessionReady: thresholdAuthPlan.warmSessionReady,
          });
          const finalError = new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
          await finalizeFailedSigningAttempt(finalError);
          throw finalError;
        }

        await finalizeFailedSigningAttempt(err);
        throw err;
      }
    },
  });
}

async function releaseNearNonceLeases(
  ctx: NearSigningRuntimeDeps,
  nonceLeases: readonly NonceLeaseRef[],
  reason: 'cancelled' | 'auth_failed' | 'signing_failed' | 'nonce_failed',
): Promise<void> {
  if (!nonceLeases.length) return;
  await Promise.all(
    nonceLeases.map((nonceLease) =>
      ctx.nonceCoordinator.release({
        leaseId: nonceLease.leaseId,
        operationId: nonceLease.operationId,
        operationFingerprint: nonceLease.operationFingerprint,
        reason,
      }),
    ),
  );
}

async function markNearNonceLeasesSigned(
  ctx: NearSigningRuntimeDeps,
  nonceLeases: readonly NonceLeaseRef[],
): Promise<void> {
  if (!nonceLeases.length) return;
  await Promise.all(
    nonceLeases.map((nonceLease) =>
      ctx.nonceCoordinator.markSigned({
        leaseId: nonceLease.leaseId,
        operationId: nonceLease.operationId,
        operationFingerprint: nonceLease.operationFingerprint,
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
    const serverDispatch = (signedTx as { serverDispatch?: SignedTransaction['serverDispatch'] })
      .serverDispatch;
    const signedTransaction = new SignedTransaction({
      transaction: signedTx.transaction,
      signature: signedTx.signature,
      borsh_bytes: Array.from(signedTx.borshBytes || []),
      ...(nonceLease ? { nonceLease } : {}),
      ...(serverDispatch ? { serverDispatch } : {}),
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
