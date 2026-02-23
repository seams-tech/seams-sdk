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
  mintEd25519AuthSession,
  putCachedEd25519AuthSession,
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
import { deriveThresholdEd25519ClientVerifyingShareWasm } from '@/core/signingEngine/signers/wasm/nearSignerWasm';
import { executeWorkerOperation } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  cacheSigningSessionPrfFirstBestEffort,
  clearSigningSessionPrfFirstBestEffort,
} from '@/core/signingEngine/api/session/signingSessionState';
import {
  generateSessionId,
  requirePrfFirstFromCredential,
  resolveNearSigningMaterials,
  toCredentialForRelayJson,
} from './shared/signingMaterials';
import {
  buildEd25519SessionPolicyForNearSigning,
  resolveDesiredSessionOptions,
  resolveInitialThresholdSigningAuthPlan,
} from './shared/thresholdSessionPolicy';
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
  signingSessionTtlMs,
  signingSessionRemainingUses,
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
  signingSessionTtlMs?: number;
  signingSessionRemainingUses?: number;
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
      PASSKEY_MANAGER_DEFAULT_CONFIGS.nearRpcUrl.split(',')[0] ||
      PASSKEY_MANAGER_DEFAULT_CONFIGS.nearRpcUrl,
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
  const { desiredTtlMs, desiredRemainingUses } = resolveDesiredSessionOptions({
    signingSessionTtlMs,
    signingSessionRemainingUses,
  });
  let { signingAuthMode, thresholdSessionPlan } = await resolveInitialThresholdSigningAuthPlan({
    threshold: signingContext.threshold,
    sessionId,
    usesNeeded,
    nearAccountId,
    getRpId: () => ctx.touchIdPrompt.getRpId(),
    touchConfirm,
    desiredTtlMs,
    desiredRemainingUses,
  });

  const confirmation = await touchConfirm.orchestrateSigningConfirmation({
    ctx,
    sessionId,
    chain: 'near',
    kind: 'delegate',
    ...(signingAuthMode ? { signingAuthMode } : {}),
    ...(thresholdSessionPlan
      ? { sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32 }
      : {}),
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

  let intentDigest = confirmation.intentDigest;
  let transactionContext = confirmation.transactionContext;

  let credentialWithPrf: WebAuthnAuthenticationCredential | undefined = confirmation.credential as
    | WebAuthnAuthenticationCredential
    | undefined;

  let credentialForRelayJson = toCredentialForRelayJson(credentialWithPrf);

  let prfFirstB64u: string | undefined;

  if (signingContext.threshold && signingAuthMode === 'warmSession') {
    const delivered = await touchConfirm.dispensePrfFirstForThresholdSession({
      sessionId,
      uses: usesNeeded,
    });
    if (delivered.ok) {
      prfFirstB64u = delivered.prfFirstB64u;
    } else {
      await clearSigningSessionPrfFirstBestEffort(touchConfirm, sessionId);
      signingAuthMode = 'webauthn';

      thresholdSessionPlan = await buildEd25519SessionPolicyForNearSigning({
        nearAccountId,
        getRpId: () => ctx.touchIdPrompt.getRpId(),
        thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
        usesNeeded,
        desiredTtlMs,
        desiredRemainingUses,
      });

      const refreshed = await touchConfirm.orchestrateSigningConfirmation({
        ctx,
        sessionId,
        chain: 'near',
        kind: 'delegate',
        signingAuthMode: 'webauthn',
        sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
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

      intentDigest = refreshed.intentDigest;
      transactionContext = refreshed.transactionContext;
      credentialWithPrf = refreshed.credential as WebAuthnAuthenticationCredential | undefined;
      credentialForRelayJson = toCredentialForRelayJson(credentialWithPrf);
      prfFirstB64u = requirePrfFirstFromCredential(credentialWithPrf);
    }
  } else {
    prfFirstB64u = requirePrfFirstFromCredential(credentialWithPrf);
  }

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

  if (signingContext.threshold && signingAuthMode !== 'warmSession') {
    if (!credentialWithPrf) {
      throw new Error('Missing WebAuthn credential for threshold session mint');
    }
    if (!thresholdSessionPlan) {
      throw new Error('Missing threshold session policy for threshold session mint');
    }

    const derived = await deriveThresholdEd25519ClientVerifyingShareWasm({
      sessionId,
      nearAccountId,
      prfFirstB64u,
      wrapKeySalt: thresholdWrapKeySalt,
      workerCtx: ctx,
    });

    const minted = await mintEd25519AuthSession({
      relayerUrl: signingContext.threshold.relayerUrl,
      sessionKind: 'jwt',
      relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
      clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
      sessionPolicy: thresholdSessionPlan.policy,
      webauthnAuthentication: credentialWithPrf,
    });
    if (!minted.ok || !minted.jwt) {
      throw new Error(minted.message || 'Failed to mint threshold session');
    }

    const expiresAtMs = minted.expiresAtMs ?? Date.now() + thresholdSessionPlan.policy.ttlMs;
    const remainingUses = minted.remainingUses ?? thresholdSessionPlan.policy.remainingUses;

    if (!prfFirstB64u) {
      throw new Error('Missing PRF.first output for threshold session cache');
    }
    await cacheSigningSessionPrfFirstBestEffort(touchConfirm, {
      sessionId,
      prfFirstB64u,
      expiresAtMs,
      remainingUses,
    });

    putCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey, {
      sessionKind: 'jwt',
      policy: thresholdSessionPlan.policy,
      policyJson: thresholdSessionPlan.policyJson,
      sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
      jwt: minted.jwt,
      expiresAtMs,
    });

    signingContext.threshold.thresholdSessionJwt = minted.jwt;
  }

  if (!signingContext.threshold.thresholdSessionJwt) {
    throw new Error('Missing thresholdSessionJwt for threshold delegate signing');
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

  let okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignDelegateAction> | undefined;
  for (let attempt = 0; attempt < 2; attempt++) {
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
      break;
    } catch (e: unknown) {
      const err = e instanceof Error ? e : new Error(String(e));

      if (isThresholdSignerMissingKeyError(err)) {
        const msg =
          '[SigningEngine] threshold-signer requested but the relayer is missing the signing share; local fallback is disabled';
        console.warn(msg);
        warnings.push(msg);

        try {
          clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
        } catch {}
        signingContext.threshold.thresholdSessionJwt = undefined;
        throw new Error(msg);
      }

      if (attempt === 0 && isThresholdSessionAuthUnavailableError(err)) {
        clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
        await clearSigningSessionPrfFirstBestEffort(touchConfirm, sessionId);
        signingContext.threshold.thresholdSessionJwt = undefined;
        requestPayload.threshold!.thresholdSessionJwt = undefined;

        thresholdSessionPlan = await buildEd25519SessionPolicyForNearSigning({
          nearAccountId,
          getRpId: () => ctx.touchIdPrompt.getRpId(),
          thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
          usesNeeded,
          desiredTtlMs,
          desiredRemainingUses,
        });

        const refreshed = await touchConfirm.orchestrateSigningConfirmation({
          ctx,
          sessionId,
          chain: 'near',
          kind: 'delegate',
          signingAuthMode: 'webauthn',
          sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
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

        intentDigest = refreshed.intentDigest;
        transactionContext = refreshed.transactionContext;
        credentialWithPrf = refreshed.credential as WebAuthnAuthenticationCredential | undefined;
        credentialForRelayJson = toCredentialForRelayJson(credentialWithPrf);
        const prfFirst = requirePrfFirstFromCredential(credentialWithPrf);

        const derived = await deriveThresholdEd25519ClientVerifyingShareWasm({
          sessionId,
          nearAccountId,
          prfFirstB64u: prfFirst,
          wrapKeySalt: thresholdWrapKeySalt,
          workerCtx: ctx,
        });

        const minted = await mintEd25519AuthSession({
          relayerUrl: signingContext.threshold.relayerUrl,
          sessionKind: 'jwt',
          relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
          clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
          sessionPolicy: thresholdSessionPlan.policy,
          webauthnAuthentication: credentialWithPrf!,
        });
        if (!minted.ok || !minted.jwt) {
          throw new Error(minted.message || 'Failed to mint threshold session');
        }

        const expiresAtMs = minted.expiresAtMs ?? Date.now() + thresholdSessionPlan.policy.ttlMs;
        const remainingUses = minted.remainingUses ?? thresholdSessionPlan.policy.remainingUses;

        await cacheSigningSessionPrfFirstBestEffort(touchConfirm, {
          sessionId,
          prfFirstB64u: prfFirst,
          expiresAtMs,
          remainingUses,
        });

        putCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey, {
          sessionKind: 'jwt',
          policy: thresholdSessionPlan.policy,
          policyJson: thresholdSessionPlan.policyJson,
          sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
          jwt: minted.jwt,
          expiresAtMs,
        });

        signingContext.threshold.thresholdSessionJwt = minted.jwt;
        requestPayload.threshold!.thresholdSessionJwt = minted.jwt;
        requestPayload.intentDigest = intentDigest;
        requestPayload.transactionContext = transactionContext;
        requestPayload.credential = credentialForRelayJson;
        continue;
      }

      throw err;
    }
  }

  if (!okResponse) {
    throw new Error('No delegate signing response received');
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
