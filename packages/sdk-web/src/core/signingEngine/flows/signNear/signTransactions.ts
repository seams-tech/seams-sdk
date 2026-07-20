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
  type ConfirmationConfig,
  type RpcCallPayload,
  type WorkerSuccessResponse,
} from '@/core/types/signer-worker';
import { AccountId, toAccountId } from '@/core/types/accountIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import type { NearSigningRuntimeDeps } from '../../interfaces/runtime';
import type {
  NearEd25519EmailOtpStepUpAuthorization,
  NearEd25519PasskeyStepUpAuthorization,
  NearEd25519YaoCapabilitySource,
  NearEd25519YaoSigningCapability,
  NearEmailOtpEd25519ReconnectHook,
  NearEd25519TransactionSigningBoundary,
  NearPreparedSigningSessionFinalizer,
  NearPasskeyEd25519ReconnectHook,
} from '../../interfaces/near';
import {
  isWarmSessionSigningAuthPlan,
  type UserConfirmProgressEvent,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { resolveNearNetwork, resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import { isSigningSessionAuthUnavailableError } from '@/core/signingEngine/threshold/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { resolveNearSigningMaterials } from './shared/signingMaterials';
import type { ResolvedRouterAbEd25519WalletSessionState } from '../../session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildNearTransactionSigningPayload } from '../../chains/near/payloads';
import { SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR } from './shared/signingSessionAuthMode';
import type { SelectedEd25519Lane } from '../../session/identity/laneIdentity';
import { signingLaneAuthMethod } from '../../session/identity/signingLaneAuthBinding';
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
  SigningBudgetFinalizationResult,
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
import {
  buildSigningConfirmationAuthParams,
  confirmationConfigForSigningAuthPlan,
  runSigningConfirmationCommand,
} from '../shared/signingConfirmation';
import { buildNearEd25519StepUpAuthorization } from './stepUpAuthorization';
import type { NearAccountRef, NearCommandSubject } from '../../interfaces/ecdsaChainTarget';
import { requiredNearTransactionSignatureUses } from './signatureUses';
import { tryFinalizeRouterAbEd25519NearTransactionNormalSigning } from './shared/ed25519YaoNormalSigning';
import { resolveConfirmedNearTransactionContext } from './implicitAccountFunding';
import type { RouterAbEd25519YaoActiveClientV1 } from '../../threshold/ed25519/yaoClient';

type NearEd25519ReconnectResult = {
  sessionId: string;
  activeClient: RouterAbEd25519YaoActiveClientV1;
  sessionState: ResolvedRouterAbEd25519WalletSessionState;
};

async function resolveNearEd25519YaoCapabilitySource(
  source: NearEd25519YaoCapabilitySource,
): Promise<NearEd25519YaoSigningCapability> {
  switch (source.kind) {
    case 'active_capability':
      return source.capability;
    case 'capability_rehydration':
      return await source.rehydrate();
    case 'email_otp_reconnect':
      throw new Error(
        '[SigningEngine][near] confirmed Email OTP reconnect did not activate an Ed25519 Yao capability',
      );
  }
  source satisfies never;
  throw new Error('[SigningEngine][near] unsupported Ed25519 Yao capability source');
}

function nearEd25519YaoResolutionRequiresBudgetReadmission(
  source: NearEd25519YaoCapabilitySource,
): boolean {
  switch (source.kind) {
    case 'active_capability':
      return false;
    case 'capability_rehydration':
      return true;
    case 'email_otp_reconnect':
      return true;
  }
  source satisfies never;
  throw new Error('[SigningEngine][near] unsupported Ed25519 Yao capability source');
}

async function reconnectNearPasskeyEd25519(args: {
  authorization: NearEd25519PasskeyStepUpAuthorization;
  hook: NearPasskeyEd25519ReconnectHook | undefined;
  requiredSignatureUses: number;
}): Promise<NearEd25519ReconnectResult> {
  if (!args.hook) {
    throw new Error('[SigningEngine] passkey reconnect runner is unavailable');
  }
  if (!args.authorization.credential) {
    throw new Error('[SigningEngine] missing WebAuthn credential for passkey session reconnect');
  }
  return await args.hook.reconnect({
    authorization: args.authorization,
    requiredSignatureUses: args.requiredSignatureUses,
  });
}

async function reconnectNearEmailOtpEd25519(args: {
  authorization: NearEd25519EmailOtpStepUpAuthorization;
  hook: NearEmailOtpEd25519ReconnectHook | undefined;
  requiredSignatureUses: number;
}): Promise<NearEd25519ReconnectResult> {
  if (!args.hook) {
    throw new Error('[SigningEngine] Email OTP reconnect runner is unavailable');
  }
  return await args.hook.reconnect({
    authorization: args.authorization,
    requiredSignatureUses: args.requiredSignatureUses,
  });
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

function remainingUsesFromNearBudgetFinalization(
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
  }
  result satisfies never;
  return null;
}

function budgetStatusAuthFromWalletSessionState(
  state: ResolvedRouterAbEd25519WalletSessionState,
): SigningSessionBudgetStatusAuth {
  const thresholdSessionId = String(state.thresholdSessionId || '').trim();
  const relayerUrl = String(state.relayerUrl || '').trim();
  const walletSessionJwt = String(state.walletSessionAuth.walletSessionJwt || '').trim();
  if (!thresholdSessionId || !relayerUrl || !walletSessionJwt) {
    throw new Error('[SigningEngine][near] refreshed signing session is missing budget auth');
  }
  return {
    thresholdSessionId,
    relayerUrl,
    walletSessionJwt,
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
 * Sign one NEAR transaction. A transaction may contain multiple actions.
 */

export async function runNearTransactionWithActionsSigning({
  ctx,
  commandSubject,
  nearAccount,
  transaction,
  rpcCall,
  onEvent,
  confirmationConfigOverride,
  title,
  body,
  signerSlot,
  signingOperationId: providedSigningOperationId,
  signingSessionCoordinator: sessionCoordinator,
  transactionOperation,
  ed25519SigningBoundary,
  finalizePreparedSigningSession,
  passkeyEd25519Reconnect,
  emailOtpEd25519Reconnect,
  yaoCapabilitySource,
}: {
  ctx: NearSigningRuntimeDeps;
  commandSubject: NearCommandSubject;
  nearAccount: NearAccountRef;
  transaction: TransactionInputWasm;
  rpcCall: RpcCallPayload;
  onEvent?: (update: SigningFlowEvent) => void;
  // Allow callers to pass a partial override (e.g., { uiMode: 'drawer' })
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  signerSlot?: number;
  signingOperationId?: SigningOperationId;
  signingSessionCoordinator: SigningSessionCoordinator;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  ed25519SigningBoundary: NearEd25519TransactionSigningBoundary;
  finalizePreparedSigningSession?: NearPreparedSigningSessionFinalizer;
  passkeyEd25519Reconnect?: NearPasskeyEd25519ReconnectHook;
  emailOtpEd25519Reconnect?: NearEmailOtpEd25519ReconnectHook;
  yaoCapabilitySource: NearEd25519YaoCapabilitySource;
}): Promise<{
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
}> {
  let signingOperationId = providedSigningOperationId;
  const callerProvidedSigningOperationId = Boolean(providedSigningOperationId);
  const ensureSigningOperationId = (): SigningOperationId => {
    signingOperationId = signingOperationId || createNearTransactionSigningOperationId();
    return signingOperationId;
  };
  const nearAccountId = toAccountId(nearAccount.accountId);
  const relayerUrl = ctx.relayerUrl;
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
  console.debug('[SigningEngine][near][transaction] signing materials resolved', {
    nearAccountId,
    durationMs: Math.round(performance.now() - signingStartedAt),
  });
  console.debug('[signTransactionWithActions] threshold signing', {
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
  const { txSigningRequest, confirmationTransaction } = buildNearTransactionSigningPayload({
    nearAccountId: String(resolvedRpcCall.nearAccountId),
    transaction,
  });
  const presignFingerprintTransaction = parseThresholdEd25519NearTransaction(
    txSigningRequest,
    'txSigningRequest',
  );
  const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
    await thresholdEd25519NearTransactionPlanningOperationFingerprint({
      nearAccountId,
      nearNetworkId: resolveNearNetwork(
        ctx.chains || PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains,
      ),
      relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
      signerPublicKey: signingContext.threshold.thresholdKeyMaterial.publicKey,
      transactions: [presignFingerprintTransaction],
    }),
  );

  // UserConfirm before sending anything to the signer worker.
  // WebAuthn uses the typed threshold session policy challenge when passkey reauth is required.
  if (!ctx.touchConfirm) {
    throw new Error('UiConfirm bridge not available for signing');
  }
  const touchConfirm = ctx.touchConfirm;
  if (!sessionCoordinator) {
    throw new Error('[SigningEngine][near] production signing session coordinator is required');
  }
  if (callerProvidedSigningOperationId) {
    sessionCoordinator.bindCallerProvidedOperationIdToFingerprint({
      operationId: ensureSigningOperationId(),
      operationFingerprint,
    });
  }
  const requiredSignatureUses = requiredNearTransactionSignatureUses(transaction);
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
  const signingSessionAuthPlan = {
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
  const preparedStepUp = await requireNearStepUpAuth({
    signingAuthPlan: providedSigningAuthPlan,
    signingLane,
    requiredSignatureUses,
    ...(passkeyEd25519Reconnect ? { passkeyEd25519Reconnect } : {}),
    ...(emailOtpEd25519Reconnect ? { emailOtpEd25519Reconnect } : {}),
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
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
    status: 'waiting_for_user',
    message: 'Opening confirmation prompt',
    interaction: { kind: 'transaction_confirmation', overlay: 'show' },
  });
  const confirmation = await runSigningConfirmationCommand({
    signingSessionPlan: ed25519SigningBoundary.signingSessionPlan,
    signingOperation,
    runtime: touchConfirm,
    request: {
      ctx: { touchConfirm },
      sessionId,
      chain: 'near',
      kind: 'transaction',
      ...buildSigningConfirmationAuthParams({
        signingAuthPlan: confirmationAuthPayload.signingAuthPlan,
        webauthnChallenge:
          preparedStepUp.kind === 'passkey' &&
          preparedStepUp.plannedPasskeyReconnect.sessionPolicyDigest32
            ? {
                kind: 'threshold_session_policy' as const,
                digest32B64u: preparedStepUp.plannedPasskeyReconnect.sessionPolicyDigest32,
              }
            : undefined,
      }),
      walletId: String(signingLane.identity.signer.account.wallet.walletId),
      txSigningRequests: [confirmationTransaction],
      rpcCall: resolvedRpcCall,
      nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
      nearFundingRequest: {
        subject: {
          walletId: signingLane.identity.signer.account.wallet.walletId,
          nearAccountId,
          nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
        },
        operation: {
          ...signingOperation,
          accountId: String(nearAccountId),
        },
        signatureUses: requiredSignatureUses,
      },
      confirmationConfigOverride: confirmationConfigForSigningAuthPlan({
        signingAuthPlan: confirmationAuthPayload.signingAuthPlan,
        override: confirmationConfigOverride,
      }),
      title,
      body,
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
  await ctx.nonceCoordinator.recoverDurableLeases({
    walletId: String(signingLane.identity.signer.account.wallet.walletId),
  });

  let thresholdSignatureCreated = false;
  let walletSpendRecorded = false;
  let signedTransactionOperation: SignedTransactionOperation<SelectedEd25519Lane> | null = null;

  const preparedPayload = await runSharedNearTransactionCommand({
    commandKind: SigningOperationCommandKind.PreparePayload,
    execute: async () => {
      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED,
        status: 'running',
        message: 'Preparing NEAR signer',
        interaction: { kind: 'none', overlay: 'none' },
      });
      let canonicalThresholdSessionId = signingSessionAuthPlan.sessionId;
      let activeCapability: NearEd25519YaoSigningCapability | null = null;
      let refreshedBudgetIdentityRequired = false;
      if (
        (stepUpAuthorization.kind === 'passkey' && passkeyEd25519Reconnect) ||
        (stepUpAuthorization.kind === 'email_otp' && emailOtpEd25519Reconnect)
      ) {
        emitConfirmedAuthSideEffectStarted('threshold_reconnect');
        emitNearSigningEvent(onEvent, nearAccountId, {
          phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
          status: 'running',
          message: 'Reconnecting NEAR signing session',
          interaction: { kind: 'none', overlay: 'none' },
        });
        const refreshed =
          stepUpAuthorization.kind === 'passkey'
            ? await reconnectNearPasskeyEd25519({
                authorization: stepUpAuthorization,
                hook: passkeyEd25519Reconnect,
                requiredSignatureUses,
              })
            : await reconnectNearEmailOtpEd25519({
                authorization: stepUpAuthorization,
                hook: emailOtpEd25519Reconnect,
                requiredSignatureUses,
              });
        const refreshedSessionId = String(refreshed.sessionId || '').trim();
        if (!refreshedSessionId) {
          throw new Error('[SigningEngine] passkey signing did not return a threshold session id');
        }
        if (
          stepUpAuthorization.kind === 'passkey' &&
          refreshedSessionId !== stepUpAuthorization.plannedPasskeyReconnect.sessionId
        ) {
          throw new Error(
            '[SigningEngine] passkey signing returned a different threshold session id than the confirmed session policy',
          );
        }
        canonicalThresholdSessionId = refreshedSessionId;
        activeCapability = {
          activeClient: refreshed.activeClient,
          walletSessionState: refreshed.sessionState,
        };
        refreshedBudgetIdentityRequired = true;
        emitNearSigningEvent(onEvent, nearAccountId, {
          phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED,
          status: 'succeeded',
          message: 'NEAR signing session reconnected',
          interaction: { kind: 'none', overlay: 'none' },
          data: { sessionId: refreshedSessionId },
        });
      }
      activeCapability =
        activeCapability || (await resolveNearEd25519YaoCapabilitySource(yaoCapabilitySource));
      refreshedBudgetIdentityRequired ||=
        nearEd25519YaoResolutionRequiresBudgetReadmission(yaoCapabilitySource);
      const activeYaoClient = activeCapability.activeClient;
      const activeWalletSessionState = activeCapability.walletSessionState;
      if (activeWalletSessionState.thresholdSessionId !== canonicalThresholdSessionId) {
        throw new Error('[SigningEngine][near] active Yao session state mismatch');
      }
      const confirmedNearContext = await resolveConfirmedNearTransactionContext({
        confirmation,
        ctx,
        nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
        walletSessionState: activeWalletSessionState,
        authorization: stepUpAuthorization,
        signingOperation,
        signatureUses: requiredSignatureUses,
      });
      const trustedBudgetStatusAuth =
        budgetStatusAuthFromWalletSessionState(activeWalletSessionState);
      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE,
        status: 'succeeded',
        interaction: { kind: 'none', overlay: 'none' },
        authMethod: signingSessionAuthPlan.warmSessionReady
          ? 'warm_session'
          : signingSessionAuthPlan.signingAuthPlan.method,
      });

      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_08_SIGNER_PREPARE_SUCCEEDED,
        status: 'succeeded',
        message: 'NEAR signer ready',
        interaction: { kind: 'none', overlay: 'none' },
        data: {
          signer: 'threshold-ed25519',
          sessionId: canonicalThresholdSessionId,
          clientBaseSource: 'yao_active_client',
        },
      });
      console.debug('[SigningEngine][near][transaction] threshold client base ready', {
        nearAccountId,
        thresholdSessionId: canonicalThresholdSessionId,
        durationMs: Math.round(performance.now() - signingStartedAt),
      });
      return {
        canonicalThresholdSessionId,
        activeClient: activeYaoClient,
        walletSessionState: activeWalletSessionState,
        trustedBudgetStatusAuth,
        refreshedBudgetIdentityRequired,
        transactionContext: confirmedNearContext.transactionContext,
        nonceLeaseRefs: confirmedNearContext.nonceLeases,
      };
    },
  });
  const {
    canonicalThresholdSessionId,
    activeClient: preparedActiveClient,
    walletSessionState,
    trustedBudgetStatusAuth,
    transactionContext,
    nonceLeaseRefs,
  } = preparedPayload;
  let { refreshedBudgetIdentityRequired } = preparedPayload;
  let activeBudgetAdmittedOperation = ed25519SigningBoundary.initialBudgetAdmittedOperation;
  const buildBudgetSigningLane = (): NearTransactionSigningLane => {
    if (String(walletSessionState.thresholdSessionId) !== canonicalThresholdSessionId) {
      throw new Error(
        '[SigningEngine][near] budget signing lane session does not match worker session',
      );
    }
    return walletSessionState.signingLane;
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
        console.warn('[SigningEngine][near] failed to update signing grant budget', {
          nearAccountId,
          signingGrantId: String(operationState.lane.signingGrantId),
          thresholdSessionId: String(operationState.lane.thresholdSessionId),
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
      onRecordZeroSpendError: (ledgerError) => {
        console.warn('[SigningEngine][near] failed to record signing grant zero spend', {
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
  const recordSuccessfulSigningGrantSpend = async (
    operationState: SignedTransactionOperation<SelectedEd25519Lane>,
  ): Promise<void> => {
    if (walletSpendRecorded) return;
    const spend = {
      operationId: confirmationOperationId,
      ...(operationFingerprint ? { operationFingerprint } : {}),
      lane: buildBudgetSigningLane(),
      backingMaterialSessionIds: [],
      uses: requiredSignatureUses,
      reason: SigningOperationIntent.TransactionSign,
    };
    const finalization: BudgetFinalizationSpend = {
      kind: 'externally_consumed_success',
      spend,
      ...(trustedBudgetStatusAuth ? { trustedStatusAuth: trustedBudgetStatusAuth } : {}),
      alreadyConsumedThresholdSessionIds: [operationState.lane.thresholdSessionId],
    };
    const finalizer = createNearBudgetFinalizer(finalization, operationState);
    if (!finalizer) {
      walletSpendRecorded = true;
      return;
    }
    let finalizationResult: SigningBudgetFinalizationResult | null = null;
    if (finalizePreparedSigningSession) {
      await finalizePreparedSigningSession({
        status: 'success',
        hooks: {
          recordSuccess: async () => {
            finalizationResult = await finalizer.recordSuccess();
          },
          recordZeroSpend: (error) => finalizer.recordZeroSpend(error),
        },
      });
    } else {
      finalizationResult = await finalizer.recordSuccess();
    }
    const remainingUses = remainingUsesFromNearBudgetFinalization(finalizationResult);
    if (remainingUses !== null) {
      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_11_REMAINING_SPEND_UPDATED,
        status: 'succeeded',
        interaction: { kind: 'none', overlay: 'none' },
        data: {
          chain: 'near',
          remainingUses,
          signingGrantId: String(operationState.lane.signingGrantId),
          thresholdSessionId: String(operationState.lane.thresholdSessionId),
        },
      });
    }
    walletSpendRecorded = true;
  };
  const recordFailedSigningGrantSpend = async (error: unknown): Promise<void> => {
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
      console.warn('[SigningEngine][near][transaction] failed to release nonce leases', {
        originalError: error instanceof Error ? error.message : String(error || ''),
        releaseError:
          releaseError instanceof Error ? releaseError.message : String(releaseError || ''),
      });
    });
  };
  const finalizeFailedSigningAttempt = async (error: unknown): Promise<void> => {
    if (thresholdSignatureCreated) {
      if (signedTransactionOperation) {
        await recordSuccessfulSigningGrantSpend(signedTransactionOperation);
      }
      return;
    }
    await releaseUnsignedNonceLeases(error);
    await recordFailedSigningGrantSpend(error);
  };
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
    yaoClient: RouterAbEd25519YaoActiveClientV1,
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
    const routerAbNormalSigningResult =
      await tryFinalizeRouterAbEd25519NearTransactionNormalSigning({
        ctx,
        thresholdSessionId: canonicalThresholdSessionId,
        activeClient: yaoClient,
        walletSessionState,
        thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
        walletId: commandSubject.walletSession.walletId,
        nearAccountId,
        operationId: signingOperation.operationId,
        operationFingerprint,
        txSigningRequest,
        transactionContext,
      });
    if (routerAbNormalSigningResult) {
      return routerAbNormalSigningResult.okResponse;
    }
    throw new Error('[SigningEngine][near] Router A/B Ed25519 signing is unavailable');
  };

  return await runSharedNearTransactionCommand({
    commandKind: SigningOperationCommandKind.Sign,
    execute: async () => {
      try {
        // Ed25519 threshold signing consumes the wallet session on the server as
        // part of the signing ceremony. Local finalization only reconciles status.
        const signedOperation = await signPreparedTransactionOperation(
          budgetAdmittedOperationForWorker,
          preparedActiveClient,
          { sign: executeSignRequest },
        );
        signedTransactionOperation = signedOperation;
        const okResponse = signedOperation.result;
        thresholdSignatureCreated = true;
        await markNearNonceLeasesSigned(ctx, nonceLeaseRefs);
        const signedResult = toSignedTransactionResult({
          okResponse,
          nearAccountId,
          warnings,
          nonceLeases: nonceLeaseRefs,
        });
        await finalizeSignedTransactionOperation(signedOperation, {
          recordSuccess: async (operation) => await recordSuccessfulSigningGrantSpend(operation),
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
        return signedResult;
      } catch (e: unknown) {
        const err = e instanceof Error ? e : new Error(String(e));

        if (isSigningSessionAuthUnavailableError(err)) {
          console.warn('[SigningEngine][near][transaction] Wallet Session auth unavailable', {
            nearAccountId,
            message: err.message,
            requiredSignatureUses,
            thresholdSessionId: signingSessionAuthPlan.sessionId,
            authMethod: signingLaneAuthMethod(signingSessionAuthPlan.lane.auth),
            warmSessionReady: signingSessionAuthPlan.warmSessionReady,
          });
          const finalError = new Error(SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR);
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

function toSignedTransactionResult(args: {
  okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions>;
  nearAccountId: string;
  warnings: string[];
  nonceLeases?: readonly NonceLeaseRef[];
}): {
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
  nonceLease?: NonceLeaseRef;
} {
  const signedTransactions = args.okResponse.payload.signedTransactions || [];
  if (signedTransactions.length !== 1) {
    throw new Error(`Expected one signed transaction but received ${signedTransactions.length}`);
  }

  const signedTx = signedTransactions[0];
  if (!signedTx || !signedTx.transaction || !signedTx.signature) {
    throw new Error('Incomplete signed transaction data received');
  }
  const nonceLease = args.nonceLeases?.[0];
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
