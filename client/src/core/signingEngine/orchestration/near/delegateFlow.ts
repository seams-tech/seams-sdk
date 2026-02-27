import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { AccountId, toAccountId } from '@/core/types/accountIds';
import { toActionArgsWasm, validateActionArgsWasm } from '@/core/types/actions';
import { DelegateActionInput } from '@/core/types/delegate';
import { type onProgressEvents } from '@/core/types/sdkSentEvents';
import {
  ConfirmationConfig,
  RpcCallPayload,
  type SignerMode,
  WorkerRequestType,
  type DelegateSignResponse,
  type WasmSignDelegateActionRequest,
  isWorkerError,
  isSignDelegateActionSuccess,
  type WorkerSuccessResponse,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import {
  LocalNearSkV3Material,
  ThresholdEd25519_2p_V1Material,
} from '@/core/indexedDB/passkeyNearKeysDB.types';
import {
  clearCachedEd25519AuthSession,
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
import {
  generateSessionId,
  requirePrfFirstFromCredential,
  resolveNearSigningMaterials,
  toCredentialForRelayJson,
} from './shared/signingMaterials';
import { resolveThresholdSessionJwt } from './shared/thresholdSessionAuth';
import { assertThresholdSigningSessionReady } from '@/core/signingEngine/orchestration/shared/thresholdSigningSessionPlanner';
import { buildNearWorkerSigningEnvelope } from './shared/workerRequestAssembly';

export async function signDelegateAction({
  ctx,
  delegate,
  rpcCall,
  signerMode,
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
  signerMode: SignerMode;
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

  const {
    resolvedSignerMode,
    localKeyMaterial,
    thresholdKeyMaterial,
    localWrapKeySalt,
    thresholdWrapKeySalt,
  } = await resolveNearSigningMaterials({
    ctx,
    nearAccountId,
    signerMode,
    deviceNumber,
    operationLabel: 'delegate signing',
    warnings,
    allowThresholdOnlyUpgrade: true,
  });

  const signingContext = validateAndPrepareDelegateSigningContext({
    nearAccountId,
    resolvedSignerMode,
    relayerUrl,
    rpId: ctx.touchIdPrompt.getRpId(),
    localKeyMaterial,
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
  const signingAuthMode = signingContext.threshold
    ? await (async () => {
        await assertThresholdSigningSessionReady({
          touchConfirm,
          sessionId,
          usesNeeded,
        });
        return 'warmSession' as const;
      })()
    : undefined;

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

  if (!signingContext.threshold) {
    if (!localKeyMaterial) {
      throw new Error(`No local key material found for account: ${nearAccountId}`);
    }
    const localRequestPayload: Omit<WasmSignDelegateActionRequest, 'sessionId'> = {
      rpcCall: resolvedRpcCall,
      createdAt: Date.now(),
      ...buildNearWorkerSigningEnvelope({
        signerMode: signingContext.resolvedSignerMode,
        prfFirstB64u,
        wrapKeySalt: localWrapKeySalt,
        localKeyMaterial,
      }),
      delegate: delegatePayload,
      intentDigest,
      transactionContext,
      credential: credentialForRelayJson,
    };
    const response = await executeWorkerOperation({
      ctx,
      kind: 'nearSigner',
      request: {
        sessionId,
        type: WorkerRequestType.SignDelegateAction,
        payload: localRequestPayload,
        onEvent,
      },
    });

    const okResponse = requireOkSignDelegateActionResponse(response);
    return {
      signedDelegate: okResponse.payload.signedDelegate!,
      hash: okResponse.payload.hash!,
      nearAccountId: toAccountId(nearAccountId),
      logs: [...(okResponse.payload.logs || []), ...warnings],
    };
  }

  if (!signingContext.threshold.thresholdSessionJwt) {
    signingContext.threshold.thresholdSessionJwt = resolveThresholdSessionJwt({
      thresholdSessionCacheKey: signingContext.threshold.thresholdSessionCacheKey,
      thresholdSessionId: sessionId,
    });
  }
  if (!signingContext.threshold.thresholdSessionJwt) {
    clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
    throw new Error(
      '[chains] threshold signingSession auth is unavailable; reconnect threshold session before signing',
    );
  }

  const requestPayload: Omit<WasmSignDelegateActionRequest, 'sessionId'> = {
    rpcCall: resolvedRpcCall,
    createdAt: Date.now(),
    ...buildNearWorkerSigningEnvelope({
      signerMode: signingContext.resolvedSignerMode,
      prfFirstB64u,
      wrapKeySalt: thresholdWrapKeySalt,
      threshold: {
        relayerUrl: signingContext.threshold.relayerUrl,
        thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
        thresholdSessionJwt: signingContext.threshold.thresholdSessionJwt,
      },
    }),
    delegate: delegatePayload,
    intentDigest,
    transactionContext,
    credential: credentialForRelayJson,
  };

  let okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignDelegateAction>;
  try {
    const resp = await executeWorkerOperation({
      ctx,
      kind: 'nearSigner',
      request: {
        sessionId,
        type: WorkerRequestType.SignDelegateAction,
        payload: requestPayload,
        onEvent,
      },
    });
    okResponse = requireOkSignDelegateActionResponse(resp);
  } catch (e: unknown) {
    const err = e instanceof Error ? e : new Error(String(e));

    if (isThresholdSignerMissingKeyError(err)) {
      const msg =
        '[SigningEngine] threshold-signer requested but the relayer is missing the signing share; local fallback is disabled';
      console.warn(msg);
      warnings.push(msg);
      clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
      signingContext.threshold.thresholdSessionJwt = undefined;
      throw new Error(msg);
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
  resolvedSignerMode: 'threshold-signer';
  signingNearPublicKeyStr: string;
  delegatePublicKeyStr: string;
  threshold: {
    relayerUrl: string;
    thresholdKeyMaterial: ThresholdEd25519_2p_V1Material;
    thresholdSessionCacheKey: string;
    thresholdSessionJwt: string | undefined;
  };
};

type LocalDelegateSigningContext = {
  resolvedSignerMode: 'local-signer';
  signingNearPublicKeyStr: string;
  delegatePublicKeyStr: string;
  threshold: null;
};

type DelegateSigningContext = ThresholdDelegateSigningContext | LocalDelegateSigningContext;

function validateAndPrepareDelegateSigningContext(args: {
  nearAccountId: string;
  resolvedSignerMode: SignerMode['mode'];
  relayerUrl: string;
  rpId: string | null;
  localKeyMaterial: LocalNearSkV3Material | null;
  thresholdKeyMaterial: ThresholdEd25519_2p_V1Material | null;
  providedDelegatePublicKey: DelegateActionInput['publicKey'];
  warnings: string[];
}): DelegateSigningContext {
  const providedDelegatePublicKeyStr = ensureEd25519Prefix(
    toPublicKeyString(args.providedDelegatePublicKey),
  );

  if (args.resolvedSignerMode !== 'threshold-signer') {
    if (!args.localKeyMaterial) {
      throw new Error(`No local key material found for account: ${args.nearAccountId}`);
    }
    const localPublicKey = ensureEd25519Prefix(args.localKeyMaterial.publicKey);
    if (!localPublicKey) {
      throw new Error(`Missing local signing public key for ${args.nearAccountId}`);
    }
    if (providedDelegatePublicKeyStr && providedDelegatePublicKeyStr !== localPublicKey) {
      args.warnings.push(
        `Delegate public key ${providedDelegatePublicKeyStr} does not match local signer key; using ${localPublicKey}`,
      );
    }
    return {
      resolvedSignerMode: 'local-signer',
      signingNearPublicKeyStr: localPublicKey,
      delegatePublicKeyStr: localPublicKey,
      threshold: null,
    };
  }

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

  return {
    resolvedSignerMode: 'threshold-signer',
    signingNearPublicKeyStr: thresholdPublicKey,
    delegatePublicKeyStr: thresholdPublicKey,
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
      thresholdSessionCacheKey,
      thresholdSessionJwt: getCachedEd25519AuthSessionJwt(thresholdSessionCacheKey),
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
