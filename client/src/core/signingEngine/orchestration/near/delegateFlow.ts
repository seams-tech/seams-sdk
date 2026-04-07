import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { AccountId, toAccountId } from '@/core/types/accountIds';
import { toActionArgsWasm, validateActionArgsWasm } from '@/core/types/actions';
import { DelegateActionInput } from '@/core/types/delegate';
import { type onProgressEvents } from '@/core/types/sdkSentEvents';
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
  clearCachedEd25519AuthSession,
  getCachedEd25519AuthSession,
  getCachedEd25519AuthSessionJwt,
  makeEd25519AuthSessionCacheKey,
} from '@/core/signingEngine/threshold/session/ed25519AuthSession';
import {
  isThresholdSessionAuthUnavailableError,
  isThresholdSignerMissingKeyError,
} from '@/core/signingEngine/threshold/session/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { SigningRuntimeDeps } from '../../interfaces/runtime';
import {
  ensureEd25519Prefix,
  toPublicKeyString,
} from '@/core/signingEngine/workerManager/validation';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import { executeWorkerOperation } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { clearSigningSessionPrfFirstBestEffort } from '@/core/signingEngine/api/session/signingSessionState';
import { getStoredThresholdEd25519SessionRecordByThresholdSessionId } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import {
  generateSessionId,
  requirePrfFirstFromCredential,
  resolveNearSigningMaterials,
  toCredentialForRelayJson,
} from './shared/signingMaterials';
import {
  resolveCanonicalThresholdSessionId,
  resolveThresholdSessionAuth,
} from './shared/thresholdSessionAuth';
import { buildNearWorkerSigningEnvelope } from './shared/workerRequestAssembly';
import { resolveNearThresholdSigningAuthPlan } from './shared/thresholdAuthMode';
import { ensureThresholdEd25519HssClientBase } from './shared/ensureThresholdEd25519HssClientBase';
import { repairThresholdEd25519MissingRelayerKey } from './shared/repairThresholdEd25519MissingRelayerKey';
import { ActionPhase, ActionStatus } from '@/core/types/sdkSentEvents';

export async function signDelegateAction({
  ctx,
  delegate,
  rpcCall,
  onEvent,
  confirmationConfigOverride,
  title,
  body,
  sessionId: providedSessionId,
  deviceNumber,
}: {
  ctx: SigningRuntimeDeps;
  delegate: DelegateActionInput;
  rpcCall: RpcCallPayload;
  onEvent?: (update: onProgressEvents) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  sessionId?: string;
  deviceNumber?: number;
}): Promise<{
  signedDelegate: WasmSignedDelegate;
  hash: string;
  nearAccountId: AccountId;
  logs?: string[];
}> {
  const sessionId = providedSessionId ?? generateSessionId();
  const nearAccountId = toAccountId(rpcCall.nearAccountId || delegate.senderId);
  const relayerUrl = ctx.relayerUrl;

  const resolvedRpcCall = {
    nearRpcUrl:
      rpcCall.nearRpcUrl ||
      resolvePrimaryNearRpcUrl(PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains),
    nearAccountId,
  } as RpcCallPayload;

  const actionsWasm = delegate.actions.map(toActionArgsWasm);
  actionsWasm.forEach((action, actionIndex) => {
    try {
      validateActionArgsWasm(action);
    } catch (error) {
      throw new Error(
        `Delegate action ${actionIndex} validation failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  });

  const warnings: string[] = [];
  const touchConfirm = ctx.touchConfirm;
  if (!touchConfirm) {
    throw new Error('TouchConfirm bridge not available for delegate signing');
  }

  const signingStartedAt = performance.now();
  onEvent?.({
    step: 2,
    phase: ActionPhase.STEP_2_USER_CONFIRMATION,
    status: ActionStatus.PROGRESS,
    message: 'Loading threshold signing state...',
  });
  const { thresholdKeyMaterial } = await resolveNearSigningMaterials({
    ctx,
    nearAccountId,
    deviceNumber,
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
    rpId: ctx.touchIdPrompt.getRpId(),
    thresholdKeyMaterial,
    providedDelegatePublicKey: delegate.publicKey,
    warnings,
  });

  // Ensure nonce/block context is fetched for the same access key that will sign.
  // Threshold signing MUST use the threshold/group public key (relayer access key) for:
  // - correct nonce reservation
  // - relayer scope checks (/authorize expects signingPayload.delegate.publicKey == relayer key)
  ctx.nonceManager.initializeUser(
    toAccountId(nearAccountId),
    signingContext.signingNearPublicKeyStr,
  );

  const usesNeeded = 1;
  const thresholdAuthPlan = signingContext.threshold
    ? await resolveNearThresholdSigningAuthPlan({
        touchConfirm,
        sessionId,
        usesNeeded,
        nearAccountId,
        operationLabel: 'delegate signing',
      })
    : null;
  onEvent?.({
    step: 2,
    phase: ActionPhase.STEP_2_USER_CONFIRMATION,
    status: ActionStatus.PROGRESS,
    message: 'Opening confirmation prompt...',
  });
  const signingAuthMode = thresholdAuthPlan?.signingAuthMode;

  const confirmation = await touchConfirm.orchestrateSigningConfirmation({
    ctx: { touchConfirm },
    sessionId,
    chain: 'near',
    kind: 'delegate',
    ...(signingAuthMode ? { signingAuthMode } : {}),
    nearAccountId,
    delegate: {
      senderId: delegate.senderId || nearAccountId,
      receiverId: delegate.receiverId,
      actions: actionsWasm,
      nonce: delegate.nonce,
      maxBlockHeight: delegate.maxBlockHeight,
    },
    rpcCall: resolvedRpcCall,
    confirmationConfigOverride,
    title,
    body,
  });

  const intentDigest = confirmation.intentDigest;
  const transactionContext = confirmation.transactionContext;

  const credentialWithPrf: WebAuthnAuthenticationCredential | undefined =
    confirmation.credential as WebAuthnAuthenticationCredential | undefined;

  const credentialForRelayJson = toCredentialForRelayJson(credentialWithPrf);

  const prfFirstB64u = signingContext.threshold
    ? thresholdAuthPlan?.warmSessionReady
      ? await (async () => {
          const delivered = await touchConfirm.dispensePrfFirstForThresholdSession({
            sessionId,
            uses: usesNeeded,
          });
          if (!delivered.ok) {
            clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
            await clearSigningSessionPrfFirstBestEffort(touchConfirm, sessionId);
            throw new Error(
              `[chains] threshold signingSession is ${delivered.code}; reconnect threshold session before signing`,
            );
          }
          return delivered.prfFirstB64u;
        })()
      : requirePrfFirstFromCredential(credentialWithPrf)
    : requirePrfFirstFromCredential(credentialWithPrf);

  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output for signing');
  }

  const delegatePayload = {
    senderId: delegate.senderId || nearAccountId,
    receiverId: delegate.receiverId,
    actions: actionsWasm,
    nonce: delegate.nonce.toString(),
    maxBlockHeight: delegate.maxBlockHeight.toString(),
    publicKey: signingContext.delegatePublicKeyStr,
  };

  const canonicalThresholdSessionId = resolveCanonicalThresholdSessionId({
    thresholdSessionCacheKey: signingContext.threshold.thresholdSessionCacheKey,
    fallbackSessionId: sessionId,
  });
  if (
    (signingContext.threshold.thresholdSessionKind === 'jwt' &&
      !signingContext.threshold.thresholdSessionJwt) ||
    signingContext.threshold.thresholdSessionKind === 'cookie'
  ) {
    const auth = await resolveThresholdSessionAuth({
      thresholdSessionCacheKey: signingContext.threshold.thresholdSessionCacheKey,
      thresholdSessionId: canonicalThresholdSessionId,
    });
    if (auth) {
      signingContext.threshold.thresholdSessionKind = auth.sessionKind;
      signingContext.threshold.thresholdSessionJwt = auth.thresholdSessionJwt;
    }
  }
  if (
    signingContext.threshold.thresholdSessionKind === 'jwt' &&
    !signingContext.threshold.thresholdSessionJwt
  ) {
    clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
    throw new Error(
      '[chains] threshold signingSession auth is unavailable; reconnect threshold session before signing',
    );
  }
  const xClientBaseB64u = await ensureThresholdEd25519HssClientBase({
    ...(onEvent
      ? {
          onProgress: (message: string) => {
            onEvent({
              step: 4,
              phase: ActionPhase.STEP_4_AUTHENTICATION_COMPLETE,
              status: ActionStatus.PROGRESS,
              message,
            });
          },
        }
      : {}),
    ctx,
    thresholdSessionId: canonicalThresholdSessionId,
    thresholdSessionJwt: signingContext.threshold.thresholdSessionJwt,
    relayerUrl: signingContext.threshold.relayerUrl,
    relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
    nearAccountId,
    keyVersion: signingContext.threshold.thresholdKeyMaterial.keyVersion,
    participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map((p) => p.id),
    prfFirstB64u,
  });
  console.debug('[SigningEngine][near][delegate] threshold client base ready', {
    nearAccountId,
    thresholdSessionId: canonicalThresholdSessionId,
    durationMs: Math.round(performance.now() - signingStartedAt),
  });

  const buildRequestPayload = (
    xClientBaseOverride?: string,
  ): Omit<WasmSignDelegateActionRequest, 'sessionId'> => ({
    rpcCall: resolvedRpcCall,
    createdAt: Date.now(),
    ...buildNearWorkerSigningEnvelope({
      threshold: {
        relayerUrl: signingContext.threshold.relayerUrl,
        thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
        xClientBaseB64u:
          xClientBaseOverride ||
          getStoredThresholdEd25519SessionRecordByThresholdSessionId(canonicalThresholdSessionId)
            ?.xClientBaseB64u,
        thresholdSessionKind: signingContext.threshold.thresholdSessionKind,
        thresholdSessionJwt: signingContext.threshold.thresholdSessionJwt,
      },
    }),
    delegate: delegatePayload,
    intentDigest,
    transactionContext,
    credential: credentialForRelayJson,
  });
  let requestPayload = buildRequestPayload(xClientBaseB64u);

  const executeDelegateRequest = async (
    payload: Omit<WasmSignDelegateActionRequest, 'sessionId'>,
  ) => {
    const resp = await executeWorkerOperation({
      ctx,
      kind: 'nearSigner',
      request: {
        sessionId,
        type: WorkerRequestType.SignDelegateAction,
        payload,
        onEvent,
      },
    });
    return requireOkSignDelegateActionResponse(resp);
  };

  let okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignDelegateAction>;
  try {
    okResponse = await executeDelegateRequest(requestPayload);
  } catch (e: unknown) {
    const err = e instanceof Error ? e : new Error(String(e));

    if (isThresholdSignerMissingKeyError(err)) {
      try {
        const repairedXClientBaseB64u = await repairThresholdEd25519MissingRelayerKey({
          ctx,
          operationLabel: 'delegate',
          thresholdSessionId: canonicalThresholdSessionId,
          thresholdSessionJwt: signingContext.threshold.thresholdSessionJwt,
          relayerUrl: signingContext.threshold.relayerUrl,
          relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
          nearAccountId,
          keyVersion: signingContext.threshold.thresholdKeyMaterial.keyVersion,
          participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map(
            (p) => p.id,
          ),
          prfFirstB64u,
          ...(onEvent
            ? {
                onProgress: (message: string) => {
                  onEvent({
                    step: 4,
                    phase: ActionPhase.STEP_4_AUTHENTICATION_COMPLETE,
                    status: ActionStatus.PROGRESS,
                    message,
                  });
                },
              }
            : {}),
        });
        requestPayload = buildRequestPayload(repairedXClientBaseB64u);
        okResponse = await executeDelegateRequest(requestPayload);
      } catch (repairError: unknown) {
        const repairErr =
          repairError instanceof Error ? repairError : new Error(String(repairError));
        if (isThresholdSignerMissingKeyError(repairErr)) {
          const msg =
            '[SigningEngine] threshold-signer requested but the relayer signing share could not be repaired from the active HSS session';
          console.warn(msg);
          warnings.push(msg);
          clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
          signingContext.threshold.thresholdSessionJwt = undefined;
          throw new Error(msg);
        }
        throw repairErr;
      }
    }

    if (isThresholdSessionAuthUnavailableError(err)) {
      clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
      await clearSigningSessionPrfFirstBestEffort(touchConfirm, sessionId);
      signingContext.threshold.thresholdSessionJwt = undefined;
      throw new Error(
        '[chains] threshold signingSession auth is unavailable; reconnect threshold session before signing',
      );
    }

    throw err;
  }

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
    thresholdSessionCacheKey: string;
    thresholdSessionKind: 'jwt' | 'cookie';
    thresholdSessionJwt: string | undefined;
  };
};

function validateAndPrepareDelegateSigningContext(args: {
  nearAccountId: string;
  relayerUrl: string;
  rpId: string | null;
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

  const rpId = String(args.rpId || '').trim();
  if (!rpId) {
    throw new Error('Missing rpId for threshold signing');
  }

  const participantIds = normalizeThresholdEd25519ParticipantIds(
    thresholdKeyMaterial.participants.map((p) => p.id),
  );
  if (!participantIds || participantIds.length < 2) {
    throw new Error(
      `Invalid threshold signing participantIds (expected >=2 participants, got [${(participantIds || []).join(',')}])`,
    );
  }

  const thresholdSessionCacheKey = makeEd25519AuthSessionCacheKey({
    nearAccountId: args.nearAccountId,
    rpId,
    relayerUrl,
    relayerKeyId: thresholdKeyMaterial.relayerKeyId,
    participantIds,
  });
  const cachedAuthSession = getCachedEd25519AuthSession(thresholdSessionCacheKey);
  const thresholdSessionKind: 'jwt' | 'cookie' =
    cachedAuthSession?.sessionKind === 'cookie' ? 'cookie' : 'jwt';

  return {
    signingNearPublicKeyStr: thresholdPublicKey,
    delegatePublicKeyStr: thresholdPublicKey,
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
      thresholdSessionCacheKey,
      thresholdSessionKind,
      thresholdSessionJwt:
        thresholdSessionKind === 'jwt'
          ? getCachedEd25519AuthSessionJwt(thresholdSessionCacheKey)
          : undefined,
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
