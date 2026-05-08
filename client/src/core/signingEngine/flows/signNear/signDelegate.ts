import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
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
  type DelegateSignResponse,
  type WasmSignDelegateActionRequest,
  isWorkerError,
  isSignDelegateActionSuccess,
  type WorkerSuccessResponse,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/types';
import {
  isThresholdSessionAuthUnavailableError,
  isThresholdSignerMissingKeyError,
} from '@/core/signingEngine/threshold/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { SigningRuntimeDeps } from '../../interfaces/runtime';
import {
  ensureEd25519Prefix,
  toPublicKeyString,
} from '@/core/signingEngine/workerManager/validation';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import { executeWorkerOperation } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  generateNearSigningSessionId,
  requirePrfFirstFromCredential,
  resolveNearSigningMaterials,
  toCredentialForRelayJson,
} from './shared/signingMaterials';
import { requireResolvedThresholdEd25519SessionState } from './shared/thresholdSessionAuth';
import { buildNearWorkerSigningEnvelope } from '../../chains/near/workerRequest';
import { buildNearDelegateSigningPayloads } from '../../chains/near/payloads';
import {
  buildNearThresholdSigningAuthPlan,
  createNearSigningSessionCoordinator,
  resolveNearThresholdSigningAuthContext,
  THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR,
} from './shared/thresholdAuthMode';
import { SigningAuthPlanKind } from '@/core/signingEngine/stepUpConfirmation/types';
import { ensureThresholdEd25519HssClientBase } from '../../threshold/ed25519/hssClientBase';
import { repairThresholdEd25519MissingRelayerKey } from '../../threshold/ed25519/repairMissingRelayerKey';
import { planSigningSession } from '../../session/signingSession/planner';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningOperationContext,
} from '../../session/signingSession/types';
import {
  SigningOperationCommandKind,
  runSigningOperationCommand,
  type SigningOperationCommand,
} from '../shared/signingStateMachine';
import { runSigningConfirmationCommand } from '../shared/signingConfirmation';

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
  delegate,
  rpcCall,
  onEvent,
  confirmationConfigOverride,
  title,
  body,
  sessionId: providedSessionId,
  signerSlot,
}: {
  ctx: SigningRuntimeDeps;
  delegate: DelegateActionInput;
  rpcCall: RpcCallPayload;
  onEvent?: (update: SigningFlowEvent) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  sessionId?: string;
  signerSlot?: number;
}): Promise<{
  signedDelegate: WasmSignedDelegate;
  hash: string;
  nearAccountId: AccountId;
  logs?: string[];
}> {
  const sessionId = providedSessionId ?? generateNearSigningSessionId();
  const nearAccountId = toAccountId(rpcCall.nearAccountId || delegate.senderId);
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
  const signingSessionCoordinator = createNearSigningSessionCoordinator(touchConfirm);

  const usesNeeded = 1;
  const thresholdAuthContext = await resolveNearThresholdSigningAuthContext({
    warmSessionReader: signingSessionCoordinator,
    usesNeeded,
    nearAccountId,
    operationLabel: 'delegate signing',
  });
  const resolvedThresholdSigningSession = {
    signingSessionPlan: planSigningSession({
      lane: thresholdAuthContext.coordinatorInput.lane,
      readiness: thresholdAuthContext.coordinatorInput.readiness,
      forceFreshAuth: thresholdAuthContext.coordinatorInput.forceFreshAuth,
    }),
    readiness: thresholdAuthContext.coordinatorInput.readiness,
    expiresAtMs: thresholdAuthContext.coordinatorInput.expiresAtMs || 0,
    remainingUses: thresholdAuthContext.coordinatorInput.remainingUses || 0,
  };
  const thresholdAuthPlan = buildNearThresholdSigningAuthPlan({
    context: thresholdAuthContext,
    resolvedSigningSession: resolvedThresholdSigningSession,
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
    nearAccountId,
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

  const signingOperation: SigningOperationContext = {
    operationId: SigningSessionIds.signingOperation(`near-delegate:${sessionId}`),
    intent: SigningOperationIntent.TransactionSign,
  };
  const runSharedNearDelegateCommand = async <T>(args: {
    commandKind: SigningOperationCommand['kind'];
    execute: () => Promise<T>;
  }): Promise<T> =>
    await runSigningOperationCommand({
      signingSessionPlan: resolvedThresholdSigningSession.signingSessionPlan,
      signingOperation,
      commandKind: args.commandKind,
      execute: args.execute,
    });
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
    status: 'waiting_for_user',
    message: 'Opening confirmation prompt',
    interaction: { kind: 'transaction_confirmation', overlay: 'show' },
  });
  const confirmationAuthPayload = thresholdAuthPlan.confirmationAuthPayload;
  if (confirmationAuthPayload.signingAuthPlan.kind === SigningAuthPlanKind.WarmSession) {
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
    signingSessionPlan: resolvedThresholdSigningSession.signingSessionPlan,
    signingOperation,
    runtime: touchConfirm,
    request: {
      ctx: { touchConfirm },
      sessionId,
      chain: 'near',
      kind: 'delegate',
      ...confirmationAuthPayload,
      nearAccountId,
      delegate: delegateSigningPayloads.confirmationDelegate,
      rpcCall: resolvedRpcCall,
      nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
      confirmationConfigOverride,
      title,
      body,
    },
  });
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
    status: 'succeeded',
    interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
  });

  const intentDigest = confirmation.intentDigest;
  const transactionContext = confirmation.transactionContext;

  const credentialWithPrf: WebAuthnAuthenticationCredential | undefined =
    confirmation.credential as WebAuthnAuthenticationCredential | undefined;

  const credentialForRelayJson = toCredentialForRelayJson(credentialWithPrf);

  const preparedPayload = await runSharedNearDelegateCommand({
    commandKind: SigningOperationCommandKind.PreparePayload,
    execute: async () => {
      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED,
        status: 'running',
        message: 'Preparing NEAR signer',
        interaction: { kind: 'none', overlay: 'none' },
      });

      const prfFirstB64u = thresholdAuthPlan.warmSessionReady
        ? await signingSessionCoordinator.claimPrfFirstByThresholdSessionId({
            thresholdSessionId: thresholdAuthPlan.sessionId,
            uses: usesNeeded,
            errorContext: 'threshold-ed25519 delegate signing',
            walletId: nearAccountId,
            authMethod: thresholdAuthPlan.lane.authMethod,
            curve: 'ed25519',
            chain: 'near',
            walletSigningSessionId: thresholdAuthPlan.lane.walletSigningSessionId,
          })
        : requirePrfFirstFromCredential(credentialWithPrf);

      if (!prfFirstB64u) {
        throw new Error('Missing PRF.first output for signing');
      }

      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE,
        status: 'succeeded',
        interaction: { kind: 'none', overlay: 'none' },
        authMethod: thresholdAuthPlan.warmSessionReady ? 'warm_session' : 'passkey',
      });

      const delegatePayload = delegateSigningPayloads.workerDelegate;

      const canonicalThresholdSessionId = thresholdAuthPlan.sessionId;
      const thresholdSessionState = requireResolvedThresholdEd25519SessionState({
        signingSessionCoordinator,
        thresholdSessionId: canonicalThresholdSessionId,
      });
      const xClientBaseB64u = await ensureThresholdEd25519HssClientBase({
        ...(onEvent
          ? {
              onProgress: (message: string) => {
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
        participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map((p) => p.id),
        prfFirstB64u,
        persistClientBase: thresholdSessionState.persistClientBase,
      });
      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_08_SIGNER_PREPARE_SUCCEEDED,
        status: 'succeeded',
        message: 'NEAR signer ready',
        interaction: { kind: 'none', overlay: 'none' },
        data: {
          signer: 'threshold-ed25519',
          sessionId: canonicalThresholdSessionId,
          clientBaseSource: 'reconstructed',
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
        thresholdSessionState,
        prfFirstB64u,
        xClientBaseB64u,
      };
    },
  });
  const {
    canonicalThresholdSessionId,
    delegatePayload,
    thresholdSessionState,
    prfFirstB64u,
    xClientBaseB64u,
  } = preparedPayload;

  const buildRequestPayload = (
    xClientBaseOverride?: string,
  ): Omit<WasmSignDelegateActionRequest, 'sessionId'> => {
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
          xClientBaseB64u:
            xClientBaseOverride || currentThresholdSessionState.xClientBaseB64u,
          thresholdSessionKind: currentThresholdSessionState.sessionKind,
          thresholdSessionAuthToken: currentThresholdSessionState.thresholdSessionAuthToken,
        },
      }),
      delegate: delegatePayload,
      intentDigest,
      transactionContext,
      credential: credentialForRelayJson,
    };
  };
  let requestPayload = buildRequestPayload(xClientBaseB64u);

  const executeDelegateRequest = async (
    payload: Omit<WasmSignDelegateActionRequest, 'sessionId'>,
  ) => {
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_10_COMMIT_STARTED,
      status: 'running',
      interaction: { kind: 'none', overlay: 'none' },
    });
    const resp = await executeWorkerOperation({
      ctx,
      kind: 'nearSigner',
      request: {
        sessionId: canonicalThresholdSessionId,
        type: WorkerRequestType.SignDelegateAction,
        payload,
      },
    });
    return requireOkSignDelegateActionResponse(resp);
  };

  const okResponse = await runSharedNearDelegateCommand({
    commandKind: SigningOperationCommandKind.Sign,
    execute: async () => {
      try {
        return await executeDelegateRequest(requestPayload);
      } catch (e: unknown) {
        const err = e instanceof Error ? e : new Error(String(e));

        if (isThresholdSignerMissingKeyError(err)) {
          try {
            const repairedXClientBaseB64u = await repairThresholdEd25519MissingRelayerKey({
              ctx,
              operationLabel: 'delegate',
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
              prfFirstB64u,
              persistClientBase: thresholdSessionState.persistClientBase,
              ...(onEvent
                ? {
                    onProgress: (message: string) => {
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
            return await executeDelegateRequest(requestPayload);
          } catch (repairError: unknown) {
            const repairErr =
              repairError instanceof Error ? repairError : new Error(String(repairError));
            if (isThresholdSignerMissingKeyError(repairErr)) {
              const msg =
                '[SigningEngine] threshold-signer requested but the relayer signing share could not be repaired from the active HSS session';
              console.warn(msg);
              warnings.push(msg);
              throw new Error(msg);
            }
            throw repairErr;
          }
        }

        if (isThresholdSessionAuthUnavailableError(err)) {
          throw new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
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

function requireOkSignDelegateActionResponse(
  response: DelegateSignResponse,
): WorkerSuccessResponse<typeof WorkerRequestType.SignDelegateAction> {
  if (!isSignDelegateActionSuccess(response)) {
    if (isWorkerError(response)) {
      throw new Error(response.payload.error || 'Delegate action signing failed');
    }
    throw new Error('Delegate action signing failed');
  }

  if (!response.payload.success || !response.payload.signedDelegate || !response.payload.hash) {
    throw new Error(response.payload.error || 'Delegate action signing failed');
  }
  return response;
}
