import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { resolveNearNetwork } from '@/core/config/chains';
import { AccountId, toAccountId } from '@/core/types/accountIds';
import { DelegateActionInput } from '@/core/types/delegate';
import {
  createSigningFlowEvent,
  SigningEventPhase,
  type CreateSigningFlowEventInput,
  type SigningFlowEvent,
} from '@/core/types/sdkSentEvents';
import {
  ConfirmationConfig,
  RpcCallPayload,
  WorkerRequestType,
  WorkerResponseType,
  type WorkerSuccessResponse,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import { isSigningSessionAuthUnavailableError } from '@/core/signingEngine/threshold/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { NearSigningRuntimeDeps } from '../../interfaces/runtime';
import {
  ensureEd25519Prefix,
  toPublicKeyString,
} from '@/core/signingEngine/workerManager/validation';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import { computeThresholdEd25519DelegateSigningDigestWasm } from '../../chains/near/nearSignerWasm';
import { resolveNearSigningMaterials } from './shared/signingMaterials';
import type { ResolvedRouterAbEd25519WalletSessionState } from '../../session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildNearDelegateSigningPayloads } from '../../chains/near/payloads';
import {
  buildNearSigningSessionAuthPlan,
  createNearSigningSessionCoordinator,
  resolveNearSigningSessionAuthContext,
  SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR,
} from './shared/signingSessionAuthMode';
import { isWarmSessionSigningAuthPlan } from '@/core/signingEngine/stepUpConfirmation/types';
import { planSigningSession } from '../../session/planning/planner';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningOperationContext,
} from '../../session/operationState/types';
import {
  parseThresholdEd25519NearAction,
  thresholdEd25519DelegateActionOperationFingerprint,
} from '@shared/threshold/ed25519OperationFingerprint';
import {
  SigningOperationCommandKind,
  runSigningOperationCommand,
  type SigningOperationCommand,
} from '../shared/signingStateMachine';
import {
  buildSigningConfirmationAuthParams,
  confirmationConfigForSigningAuthPlan,
  runSigningConfirmationCommand,
} from '../shared/signingConfirmation';
import { requireNearStepUpAuth } from './requireNearStepUpAuth';
import type { NearDelegateActionPayload } from '../../interfaces/near';
import {
  finalizeThresholdEd25519DelegateSignatureResult,
  tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning,
} from './shared/ed25519YaoNormalSigning';
import type { RouterAbEd25519YaoActiveClientV1 } from '../../threshold/ed25519/yaoClient';

type NearDelegateActionYaoPayload = NearDelegateActionPayload & {
  activeClient: RouterAbEd25519YaoActiveClientV1;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
};

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

export async function runNearDelegateActionSigning({
  ctx,
  commandSubject,
  nearAccount,
  delegate,
  rpcCall,
  onEvent,
  confirmationConfigOverride,
  title,
  body,
  operationId,
  signerSlot,
  signingSessionCoordinator,
  activeClient,
  walletSessionState,
}: NearDelegateActionYaoPayload): Promise<{
  signedDelegate: WasmSignedDelegate;
  hash: string;
  nearAccountId: AccountId;
  logs?: string[];
}> {
  const nearAccountId = toAccountId(nearAccount.accountId);
  const relayerUrl = ctx.relayerUrl;

  const resolvedRpcCall = {
    nearRpcUrl:
      rpcCall.nearRpcUrl ||
      resolvePrimaryNearRpcUrl(PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains),
    nearAccountId,
  } as RpcCallPayload;

  const warnings: string[] = [];
  const touchConfirm = ctx.touchConfirm;
  if (!touchConfirm) {
    throw new Error('UiConfirm bridge not available for delegate signing');
  }
  const warmSessionReader = createNearSigningSessionCoordinator(touchConfirm);

  const requiredSignatureUses = 1;
  const signingSessionAuthContext = await resolveNearSigningSessionAuthContext({
    warmSessionReader,
    requiredSignatureUses,
    commandSubject,
    operationLabel: 'delegate signing',
  });
  const resolvedSigningSession = {
    signingSessionPlan: planSigningSession({
      lane: signingSessionAuthContext.coordinatorInput.lane,
      readiness: signingSessionAuthContext.coordinatorInput.readiness,
      forceFreshAuth: signingSessionAuthContext.coordinatorInput.forceFreshAuth,
    }),
    readiness: signingSessionAuthContext.coordinatorInput.readiness,
    expiresAtMs: signingSessionAuthContext.coordinatorInput.expiresAtMs || 0,
    remainingUses: signingSessionAuthContext.coordinatorInput.remainingUses || 0,
  };
  const signingSessionAuthPlan = buildNearSigningSessionAuthPlan({
    context: signingSessionAuthContext,
    resolvedSigningSession: resolvedSigningSession,
  });

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
    operationLabel: 'delegate signing',
    warnings,
  });
  console.debug('[SigningEngine][near][delegate] signing materials resolved', {
    nearAccountId,
    durationMs: Math.round(performance.now() - signingStartedAt),
  });
  const signingContext = validateAndPrepareDelegateSigningContext({
    nearAccountId,
    relayerUrl,
    thresholdKeyMaterial,
    providedDelegatePublicKey: delegate.publicKey,
    warnings,
  });
  const delegateSigningPayloads = buildNearDelegateSigningPayloads({
    nearAccountId,
    delegate,
    signingPublicKey: signingContext.delegatePublicKeyStr,
  });
  const delegateIntent = {
    ...delegateSigningPayloads.workerDelegate,
    actions: delegateSigningPayloads.workerDelegate.actions.map((action, index) =>
      parseThresholdEd25519NearAction(action, `delegate.actions[${index}]`),
    ),
  };

  const signingOperation: SigningOperationContext = {
    operationId,
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(
      await thresholdEd25519DelegateActionOperationFingerprint({
        nearAccountId,
        nearNetworkId: resolveNearNetwork(
          ctx.chains || PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains,
        ),
        relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
        signerPublicKey: signingContext.delegatePublicKeyStr,
        delegate: delegateIntent,
      }),
    ),
    intent: SigningOperationIntent.TransactionSign,
  };
  const runSharedNearDelegateCommand = async <T>(args: {
    commandKind: SigningOperationCommand['kind'];
    execute: () => Promise<T>;
  }): Promise<T> =>
    await runSigningOperationCommand({
      signingSessionPlan: resolvedSigningSession.signingSessionPlan,
      signingOperation,
      commandKind: args.commandKind,
      execute: args.execute,
    });
  const preparedStepUp = await requireNearStepUpAuth({
    signingAuthPlan: signingSessionAuthPlan.signingAuthPlan,
    signingLane: signingSessionAuthPlan.lane,
    requiredSignatureUses,
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
  await runSigningConfirmationCommand({
    signingSessionPlan: resolvedSigningSession.signingSessionPlan,
    signingOperation,
    runtime: touchConfirm,
    request: {
      ctx: { touchConfirm },
      sessionId: String(operationId),
      chain: 'near',
      kind: 'delegate',
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
      walletId: String(commandSubject.walletSession.walletId),
      nearAccountId,
      delegate: delegateSigningPayloads.confirmationDelegate,
      rpcCall: resolvedRpcCall,
      nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
      confirmationConfigOverride: confirmationConfigForSigningAuthPlan({
        signingAuthPlan: confirmationAuthPayload.signingAuthPlan,
        override: confirmationConfigOverride,
      }),
      title,
      body,
    },
  });
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
    status: 'succeeded',
    interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
  });
  const preparedPayload = await runSharedNearDelegateCommand({
    commandKind: SigningOperationCommandKind.PreparePayload,
    execute: async () => {
      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED,
        status: 'running',
        message: 'Preparing NEAR signer',
        interaction: { kind: 'none', overlay: 'none' },
      });

      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE,
        status: 'succeeded',
        interaction: { kind: 'none', overlay: 'none' },
        authMethod: preparedStepUp.kind === 'warm_session' ? 'warm_session' : 'passkey',
      });

      const delegatePayload = delegateSigningPayloads.workerDelegate;

      const canonicalThresholdSessionId = signingSessionAuthPlan.sessionId;
      if (walletSessionState.thresholdSessionId !== canonicalThresholdSessionId) {
        throw new Error('[SigningEngine][near] delegate Yao session state mismatch');
      }
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
      console.debug('[SigningEngine][near][delegate] threshold client base ready', {
        nearAccountId,
        thresholdSessionId: canonicalThresholdSessionId,
        durationMs: Math.round(performance.now() - signingStartedAt),
      });
      return {
        canonicalThresholdSessionId,
        delegatePayload,
      };
    },
  });
  const { canonicalThresholdSessionId, delegatePayload } = preparedPayload;

  const executeDelegateRequest = async () => {
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_10_COMMIT_STARTED,
      status: 'running',
      interaction: { kind: 'none', overlay: 'none' },
    });
    const signingDigest = await computeThresholdEd25519DelegateSigningDigestWasm({
      sessionId: canonicalThresholdSessionId,
      delegate: delegatePayload,
      workerCtx: ctx,
    });
    const signatureOnlyIntent = {
      kind: 'near_delegate_action_v1' as const,
      delegate: delegateIntent,
    };
    const routerAbNormalSigningResult = await tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning({
      ctx,
      thresholdSessionId: canonicalThresholdSessionId,
      signingSessionCoordinator,
      activeClient,
      walletSessionState,
      walletId: commandSubject.walletSession.walletId,
      thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
      nearAccountId,
      operationId: signingOperation.operationId,
      operationFingerprint: signingOperation.operationFingerprint!,
      signingDigestB64u: signingDigest.signingDigestB64u,
      intent: signatureOnlyIntent,
    });
    if (routerAbNormalSigningResult) {
      const delegateResult = await finalizeThresholdEd25519DelegateSignatureResult({
        ctx,
        thresholdSessionId: canonicalThresholdSessionId,
        delegate: delegatePayload,
        signingDigestB64u: signingDigest.signingDigestB64u,
        signatureB64u: routerAbNormalSigningResult.signatureB64u,
      });
      return {
        type: WorkerResponseType.SignDelegateActionSuccess,
        payload: {
          success: true,
          hash: delegateResult.hash,
          signedDelegate: delegateResult.signedDelegate,
          logs: ['Delegate action signed through Router A/B normal signing'],
          error: undefined,
        },
      } as WorkerSuccessResponse<typeof WorkerRequestType.SignDelegateAction>;
    }
    throw new Error('[SigningEngine][near] Router A/B Ed25519 delegate signing is unavailable');
  };

  const okResponse = await runSharedNearDelegateCommand({
    commandKind: SigningOperationCommandKind.Sign,
    execute: async () => {
      try {
        return await executeDelegateRequest();
      } catch (e: unknown) {
        const err = e instanceof Error ? e : new Error(String(e));

        if (isSigningSessionAuthUnavailableError(err)) {
          throw new Error(SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR);
        }

        throw err;
      }
    },
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
    data: { operation: 'sign_delegate', hash: okResponse.payload.hash },
  });

  return {
    signedDelegate: okResponse.payload.signedDelegate!,
    hash: okResponse.payload.hash!,
    nearAccountId: toAccountId(nearAccountId),
    logs: [...(okResponse.payload.logs || []), ...warnings],
  };
}

type ThresholdDelegateSigningContext = {
  signingNearPublicKeyStr: string;
  delegatePublicKeyStr: string;
  threshold: {
    relayerUrl: string;
    thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  };
};

function validateAndPrepareDelegateSigningContext(args: {
  nearAccountId: string;
  relayerUrl: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial | null;
  providedDelegatePublicKey: DelegateActionInput['publicKey'];
  warnings: string[];
}): ThresholdDelegateSigningContext {
  const providedDelegatePublicKeyStr = ensureEd25519Prefix(
    toPublicKeyString(args.providedDelegatePublicKey),
  );

  const thresholdKeyMaterial = args.thresholdKeyMaterial;
  if (!thresholdKeyMaterial) {
    throw new Error(`Missing threshold key material for ${args.nearAccountId}`);
  }

  const thresholdPublicKey = ensureEd25519Prefix(thresholdKeyMaterial.publicKey);
  if (!thresholdPublicKey) {
    throw new Error(`Missing threshold signing public key for ${args.nearAccountId}`);
  }

  if (providedDelegatePublicKeyStr && providedDelegatePublicKeyStr !== thresholdPublicKey) {
    args.warnings.push(
      `Delegate public key ${providedDelegatePublicKeyStr} does not match threshold signer key; using ${thresholdPublicKey}`,
    );
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
    delegatePublicKeyStr: thresholdPublicKey,
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
    },
  };
}
