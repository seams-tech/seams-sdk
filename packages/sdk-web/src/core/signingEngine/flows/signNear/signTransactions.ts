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
  NearEd25519YaoMaterialExecutor,
  NearEd25519YaoSigningCapability,
  NearEmailOtpEd25519StepUpHook,
  NearEd25519StepUpAuthorization,
  NearEd25519TransactionSigningBoundary,
  NearPreparedSigningSessionFinalizer,
  NearPasskeyEd25519OperationStepUpHook,
} from '../../interfaces/near';
import type { NearEd25519YaoSigningPreparation } from '../../session/material/nearEd25519YaoSigningPreparation';
import {
  isWarmSessionSigningAuthPlan,
  type UserConfirmProgressEvent,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { resolveNearNetwork, resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { resolveNearSigningMaterials } from './shared/signingMaterials';
import {
  resolveActiveAuthorizedRouterAbEd25519WalletSessionState,
  type AuthorizedRouterAbEd25519WalletSessionState,
  type ResolvedRouterAbEd25519WalletSessionState,
} from '../../session/warmCapabilities/routerAbEd25519WalletSessionState';
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
import {
  buildNearEd25519OperationStepUpProof,
  buildNearEmailOtpEd25519OperationStepUpProof,
  prepareRouterAbEd25519NearTransactionOperationStepUp,
  requireNearEd25519OperationStepUpProof,
  tryFinalizeRouterAbEd25519NearTransactionNormalSigning,
} from './shared/ed25519YaoNormalSigning';
import { resolveConfirmedNearTransactionContext } from './implicitAccountFunding';
import {
  nearOperationStepUpMaterialFacts,
  prepareNearOperationStepUpMaterial,
  resolveNearOperationStepUpMaterial,
  resolvePreparedNearEd25519YaoMaterial,
  type NearOperationStepUpMaterial,
  type ResolvedNearOperationStepUpMaterial,
} from './shared/ed25519YaoCapabilityResolution';
import {
  clearNearOperationStepUpBuilder,
  consumePreparedNearOperationStepUp,
  registerNearOperationStepUpBuilder,
  requireNearOperationStepUpMaterialActivation,
  type PreparedNearOperationStepUp,
} from './shared/operationStepUpPreparation';
import type { NearOperationStepUpPreparationRef } from '../../interfaces/operationStepUpPreparation';
import type { NearTransactionSigningConfirmationResult } from '../../stepUpConfirmation/confirmOperation';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../../session/material/nearEd25519YaoMaterialActivation';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';

function requireNearOperationStepUpPreparation(
  value: NearOperationStepUpPreparationRef | undefined,
): NearOperationStepUpPreparationRef {
  if (!value) {
    throw new Error('[SigningEngine][near] confirmed operation step-up is missing preparation');
  }
  return value;
}

function requirePreparedNearOperationStepUp(
  value: PreparedNearOperationStepUp | null,
): Extract<PreparedNearOperationStepUp, { kind: 'near_transaction' }> {
  if (!value) {
    throw new Error('[SigningEngine][near] prepared operation step-up is missing');
  }
  if (value.kind !== 'near_transaction') {
    throw new Error('[SigningEngine][near] prepared operation step-up is not a transaction');
  }
  return value;
}

function requireNearTransactionOperationStepUpMaterial(
  value: NearOperationStepUpMaterial | null,
): NearOperationStepUpMaterial {
  if (!value) {
    throw new Error('[SigningEngine][near] transaction operation material is unavailable');
  }
  return value;
}

function disposeOwnedNearOperationStepUpMaterial(args: {
  resolved: ResolvedNearOperationStepUpMaterial | null;
  owned: boolean;
}): void {
  if (args.owned) args.resolved?.material.activeClient.dispose();
}

function disposeOwnedNearOperationStepUpMaterialAndRethrow(
  args: {
    resolved: ResolvedNearOperationStepUpMaterial | null;
    owned: boolean;
  },
  error: unknown,
): never {
  disposeOwnedNearOperationStepUpMaterial(args);
  throw error;
}

async function resolveNearTransactionOperationStepUpMaterial(args: {
  material: NearOperationStepUpMaterial;
  prepared: Extract<PreparedNearOperationStepUp, { kind: 'near_transaction' }>;
  displayDigest: string;
  authorization: Exclude<NearEd25519StepUpAuthorization, { kind: 'warm_session' }>;
  proof: ReturnType<typeof buildNearEd25519OperationStepUpProof>;
}): Promise<ResolvedNearOperationStepUpMaterial> {
  if (args.authorization.kind === 'passkey') {
    if (args.material.kind !== 'passkey_live' && args.material.kind !== 'passkey_sealed') {
      throw new Error('[SigningEngine][near] passkey transaction material changed factor');
    }
    return await resolveNearOperationStepUpMaterial({
      kind: 'passkey',
      material: args.material,
      expectedActivation: args.prepared.materialActivation,
      credential: args.authorization.credential,
    });
  }
  if (
    args.material.kind !== 'email_otp_live' &&
    args.material.kind !== 'email_otp_sealed'
  ) {
    throw new Error('[SigningEngine][near] Email OTP transaction material changed factor');
  }
  if (args.proof.kind !== 'email_otp') {
    throw new Error('[SigningEngine][near] Email OTP transaction proof is missing');
  }
  if (args.material.kind === 'email_otp_live') {
    return await resolveNearOperationStepUpMaterial({
      kind: 'email_otp_live',
      material: args.material,
      expectedActivation: args.prepared.materialActivation,
    });
  }
  return await resolveNearOperationStepUpMaterial({
    kind: 'email_otp_sealed',
    material: args.material,
    expectedActivation: args.prepared.materialActivation,
    normalSigningRequest: args.prepared.prepare.request,
    displayDigest: args.displayDigest,
    proof: args.proof,
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

async function requireActiveAuthorizedWalletSessionState(
  state: ResolvedRouterAbEd25519WalletSessionState | null,
) {
  if (!state) {
    throw new Error('[SigningEngine][near] reusable Wallet Session state is unavailable');
  }
  const authorized = await resolveActiveAuthorizedRouterAbEd25519WalletSessionState({
    state,
    nowMs: Date.now(),
  });
  if (!authorized) {
    throw new Error('[SigningEngine][near] reusable Wallet Session authorization is unavailable');
  }
  return authorized;
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
  passkeyEd25519OperationStepUp,
  emailOtpEd25519StepUp,
  yaoSigningPreparation,
  yaoMaterialExecutor,
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
  passkeyEd25519OperationStepUp?: NearPasskeyEd25519OperationStepUpHook;
  emailOtpEd25519StepUp?: NearEmailOtpEd25519StepUpHook;
  yaoSigningPreparation: NearEd25519YaoSigningPreparation;
  yaoMaterialExecutor: NearEd25519YaoMaterialExecutor;
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
    ...(passkeyEd25519OperationStepUp ? { passkeyEd25519OperationStepUp } : {}),
    ...(emailOtpEd25519StepUp ? { emailOtpEd25519StepUp } : {}),
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
  let operationStepUpMaterial: NearOperationStepUpMaterial | null = null;
  if (preparedStepUp.kind !== 'warm_session') {
    operationStepUpMaterial = await prepareNearOperationStepUpMaterial({
      method: preparedStepUp.kind,
      preparation: yaoSigningPreparation,
      executor: yaoMaterialExecutor,
    });
    const material = operationStepUpMaterial;
    const materialFacts = nearOperationStepUpMaterialFacts(material);
    registerNearOperationStepUpBuilder({
      requestId: sessionId,
      build: async (preparation) => {
        if (preparation.kind !== 'near_transaction') {
          throw new Error('[SigningEngine][near] transaction step-up preparation kind changed');
        }
        if (preparation.operationId !== String(signingOperation.operationId)) {
          throw new Error('[SigningEngine][near] operation step-up operation identity changed');
        }
        return await prepareRouterAbEd25519NearTransactionOperationStepUp({
          ctx,
          thresholdSessionId: materialFacts.thresholdSessionId,
          materialFacts,
          thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
          walletId: commandSubject.walletSession.walletId,
          nearAccountId,
          materialActivation: material.materialActivation,
          operationId: signingOperation.operationId,
          grantId:
            preparedStepUp.kind === 'passkey'
              ? preparedStepUp.plannedPasskeyOperationStepUp.signingGrantId
              : `operation-step-up:${signingOperation.operationId}`,
          txSigningRequest,
          transactionContext: preparation.transactionContext,
          displayDigest: preparation.displayDigest,
        });
      },
    });
  }
  let confirmation: NearTransactionSigningConfirmationResult;
  try {
    confirmation = await runSigningConfirmationCommand({
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
            preparedStepUp.plannedPasskeyOperationStepUp.sessionPolicyDigest32
              ? {
                  kind: 'threshold_session_policy' as const,
                  digest32B64u: preparedStepUp.plannedPasskeyOperationStepUp.sessionPolicyDigest32,
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
  } finally {
    clearNearOperationStepUpBuilder(sessionId);
  }
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
    status: 'succeeded',
    interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
  });
  const stepUpAuthorization = buildNearEd25519StepUpAuthorization({
    prepared: preparedStepUp,
    confirmation,
  });
  const operationStepUpProof =
    stepUpAuthorization.kind === 'warm_session'
      ? null
      : buildNearEd25519OperationStepUpProof({
          authorization: stepUpAuthorization,
          preparation: yaoSigningPreparation,
          lane: transactionOperation.lane,
        });
  const preparedOperationStepUp =
    stepUpAuthorization.kind !== 'warm_session'
      ? consumePreparedNearOperationStepUp({
          requestId: sessionId,
          ref: requireNearOperationStepUpPreparation(confirmation.operationStepUpPreparation),
        })
      : null;
  const resolvedOperationStepUpMaterial =
    stepUpAuthorization.kind === 'warm_session'
      ? null
      : await resolveNearTransactionOperationStepUpMaterial({
          material: requireNearTransactionOperationStepUpMaterial(operationStepUpMaterial),
          prepared: requirePreparedNearOperationStepUp(preparedOperationStepUp),
          displayDigest: confirmation.intentDigest,
          authorization: stepUpAuthorization,
          proof: requireNearEd25519OperationStepUpProof(operationStepUpProof),
        });
  const ownsResolvedOperationStepUpMaterial =
    operationStepUpMaterial?.kind === 'passkey_sealed' ||
    operationStepUpMaterial?.kind === 'email_otp_sealed';
  try {
    await ctx.nonceCoordinator.recoverDurableLeases({
      walletId: String(signingLane.identity.signer.account.wallet.walletId),
    });
  } catch (error) {
    disposeOwnedNearOperationStepUpMaterial({
      resolved: resolvedOperationStepUpMaterial,
      owned: ownsResolvedOperationStepUpMaterial,
    });
    throw error;
  }

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
      const resolvedMaterial =
        stepUpAuthorization.kind === 'warm_session'
          ? {
              kind: 'warm_session' as const,
              capability: await resolvePreparedNearEd25519YaoMaterial(
                yaoSigningPreparation,
                yaoMaterialExecutor,
              ),
            }
          : {
              kind: 'operation_step_up' as const,
              resolved: resolvedOperationStepUpMaterial!,
            };
      const canonicalThresholdSessionId =
        resolvedMaterial.kind === 'warm_session'
          ? resolvedMaterial.capability.walletSessionState.thresholdSessionId
          : resolvedMaterial.resolved.material.facts.thresholdSessionId;
      const activeYaoClient =
        resolvedMaterial.kind === 'warm_session'
          ? resolvedMaterial.capability.activeClient
          : resolvedMaterial.resolved.material.activeClient;
      const activeWalletSessionState =
        resolvedMaterial.kind === 'warm_session'
          ? resolvedMaterial.capability.walletSessionState
          : null;
      const confirmedNearContext =
        resolvedMaterial.kind === 'warm_session'
          ? await resolveConfirmedNearTransactionContext({
              confirmation,
              ctx,
              nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
              walletSessionState: activeWalletSessionState!,
              authorization: stepUpAuthorization,
              signingOperation,
              signatureUses: requiredSignatureUses,
            })
          : confirmation.readiness.kind === 'context_ready'
            ? confirmation.readiness
            : (() => {
                throw new Error(
                  '[SigningEngine][near] implicit-account funding requires a reusable Wallet Session',
                );
              })();
      const trustedBudgetStatusAuth =
        activeWalletSessionState
          ? budgetStatusAuthFromWalletSessionState(activeWalletSessionState)
          : null;
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
      return {
        canonicalThresholdSessionId,
        activeClient: activeYaoClient,
        walletSessionState: activeWalletSessionState,
        operationMaterialFacts:
          resolvedMaterial.kind === 'operation_step_up'
            ? resolvedMaterial.resolved.material.facts
            : null,
        issuedGrant:
          resolvedMaterial.kind === 'operation_step_up'
            ? resolvedMaterial.resolved.issuedGrant
            : null,
        trustedBudgetStatusAuth,
        transactionContext: confirmedNearContext.transactionContext,
        nonceLeaseRefs: confirmedNearContext.nonceLeases,
      };
    },
  }).catch(
    disposeOwnedNearOperationStepUpMaterialAndRethrow.bind(undefined, {
      resolved: resolvedOperationStepUpMaterial,
      owned: ownsResolvedOperationStepUpMaterial,
    }),
  );
  const {
    canonicalThresholdSessionId,
    activeClient: preparedActiveClient,
    walletSessionState,
    operationMaterialFacts,
    issuedGrant,
    trustedBudgetStatusAuth,
    transactionContext,
    nonceLeaseRefs,
  } = preparedPayload;
  const usesOperationStepUp = stepUpAuthorization.kind !== 'warm_session';
  let activeBudgetAdmittedOperation = ed25519SigningBoundary.initialBudgetAdmittedOperation;
  const buildBudgetSigningLane = (): NearTransactionSigningLane => {
    if (!walletSessionState) {
      throw new Error('[SigningEngine][near] reusable Wallet Session state is unavailable');
    }
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
  const budgetAdmittedOperationForWorker = usesOperationStepUp
    ? null
    : await runSharedNearTransactionCommand({
        commandKind: SigningOperationCommandKind.ReserveBudget,
        execute: async () => {
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
    admittedOperation: BudgetAdmittedOperation<SelectedEd25519Lane> | null,
    yaoClient: NearEd25519YaoSigningCapability['activeClient'],
  ) => {
    if (
      admittedOperation &&
      String(admittedOperation.lane.thresholdSessionId) !== canonicalThresholdSessionId
    ) {
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
      stepUpAuthorization.kind !== 'warm_session'
        ? await tryFinalizeRouterAbEd25519NearTransactionNormalSigning({
            ctx,
            thresholdSessionId: canonicalThresholdSessionId,
            activeClient: yaoClient,
            materialFacts: operationMaterialFacts!,
            thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
            walletId: commandSubject.walletSession.walletId,
            nearAccountId,
            operationId: signingOperation.operationId,
            operationFingerprint,
            displayDigest: confirmation.intentDigest,
            txSigningRequest,
            transactionContext,
            authorization: {
              kind: 'operation_step_up',
              prepared: requirePreparedNearOperationStepUp(preparedOperationStepUp),
              displayDigest: confirmation.intentDigest,
              proof:
                stepUpAuthorization.kind === 'passkey'
                  ? {
                      kind: 'passkey',
                      authority: stepUpAuthorization.plannedPasskeyOperationStepUp.authority,
                      credential: stepUpAuthorization.credential,
                    }
                  : {
                      ...buildNearEmailOtpEd25519OperationStepUpProof({
                        preparation: yaoSigningPreparation,
                        lane: transactionOperation.lane,
                        challengeId: stepUpAuthorization.challengeId,
                        otpCode: stepUpAuthorization.otpCode,
                      }),
                    },
              issuedGrant,
            },
          })
        : await tryFinalizeRouterAbEd25519NearTransactionNormalSigning({
            ctx,
            thresholdSessionId: canonicalThresholdSessionId,
            activeClient: yaoClient,
            walletSessionState:
              await requireActiveAuthorizedWalletSessionState(walletSessionState),
            thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
            walletId: commandSubject.walletSession.walletId,
            nearAccountId,
            operationId: signingOperation.operationId,
            operationFingerprint,
            displayDigest: confirmation.intentDigest,
            txSigningRequest,
            transactionContext,
            authorization: { kind: 'reusable_wallet_session' },
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
        if (usesOperationStepUp) {
          const okResponse = await executeSignRequest(null, preparedActiveClient);
          thresholdSignatureCreated = true;
          await markNearNonceLeasesSigned(ctx, nonceLeaseRefs);
          const signedResult = toSignedTransactionResult({
            okResponse,
            nearAccountId,
            warnings,
            nonceLeases: nonceLeaseRefs,
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
          disposeOwnedNearOperationStepUpMaterial({
            resolved: resolvedOperationStepUpMaterial,
            owned: ownsResolvedOperationStepUpMaterial,
          });
          return signedResult;
        }
        if (!budgetAdmittedOperationForWorker) {
          throw new Error('[SigningEngine][near] reusable Wallet Session budget is missing');
        }
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

        await finalizeFailedSigningAttempt(err);
        disposeOwnedNearOperationStepUpMaterial({
          resolved: resolvedOperationStepUpMaterial,
          owned: ownsResolvedOperationStepUpMaterial,
        });
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
