import {
  WorkerRequestType,
  isSignNep413MessageSuccess,
  isWorkerError,
  type ConfirmationConfig,
  type Nep413SigningResponse,
  type SignerMode,
  type WasmSignNep413MessageRequest,
  type WorkerSuccessResponse,
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
import { toAccountId } from '@/core/types/accountIds';
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

/**
 * Sign a NEP-413 message using the user's passkey-derived private key
 *
 * @param payload - NEP-413 signing parameters including message, recipient, nonce, and state
 * @returns Promise resolving to signing result with account ID, public key, and signature
 */
export async function signNep413Message({
  ctx,
  payload,
}: {
  ctx: SigningRuntimeDeps;
  payload: {
    message: string;
    recipient: string;
    nonce: string;
    state: string | null;
    accountId: string;
    signerMode: SignerMode;
    deviceNumber?: number;
    title?: string;
    body?: string;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    signingSessionTtlMs?: number;
    signingSessionRemainingUses?: number;
    sessionId?: string;
    contractId?: string;
    nearRpcUrl?: string;
  };
}): Promise<{
  success: boolean;
  accountId: string;
  publicKey: string;
  signature: string;
  state?: string;
  error?: string;
}> {
  try {
    const sessionId = payload.sessionId ?? generateSessionId();
    const relayerUrl = ctx.relayerUrl;
    const nearAccountId = payload.accountId;
    const {
      resolvedSignerMode,
      localKeyMaterial,
      thresholdKeyMaterial,
      localWrapKeySalt,
      thresholdWrapKeySalt,
    } = await resolveNearSigningMaterials({
      ctx,
      nearAccountId,
      signerMode: payload.signerMode,
      deviceNumber: payload.deviceNumber,
      operationLabel: 'NEP-413 signing',
    });

    const touchConfirmManager = ctx.touchConfirmManager;
    if (!touchConfirmManager) {
      throw new Error('TouchConfirmManager not available for NEP-413 signing');
    }

    const signingContext = validateAndPrepareNep413SigningContext({
      nearAccountId,
      resolvedSignerMode,
      relayerUrl,
      rpId: ctx.touchIdPrompt.getRpId(),
      localKeyMaterial,
      thresholdKeyMaterial,
    });

    // Initialize nonce manager for a better SecureConfirm context (block height + access key lookup).
    // NEP-413 signing itself doesn't require nonces, but SecureConfirm uses Near context for UI.
    ctx.nonceManager.initializeUser(toAccountId(nearAccountId), signingContext.nearPublicKey);

    const usesNeeded = 1;
    const { desiredTtlMs, desiredRemainingUses } = resolveDesiredSessionOptions({
      signingSessionTtlMs: payload.signingSessionTtlMs,
      signingSessionRemainingUses: payload.signingSessionRemainingUses,
    });
    let { signingAuthMode, thresholdSessionPlan } = await resolveInitialThresholdSigningAuthPlan({
      threshold: signingContext.threshold,
      sessionId,
      usesNeeded,
      nearAccountId,
      getRpId: () => ctx.touchIdPrompt.getRpId(),
      touchConfirmManager,
      desiredTtlMs,
      desiredRemainingUses,
    });

    const confirmation = await touchConfirmManager.orchestrateSigningConfirmation({
      ctx,
      sessionId,
      chain: 'near',
      kind: 'nep413',
      ...(signingAuthMode ? { signingAuthMode } : {}),
      ...(thresholdSessionPlan
        ? { sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32 }
        : {}),
      nearAccountId,
      message: payload.message,
      recipient: payload.recipient,
      title: payload.title,
      body: payload.body,
      confirmationConfigOverride: payload.confirmationConfigOverride,
    });

    let credentialWithPrf: WebAuthnAuthenticationCredential | undefined =
      confirmation.credential as WebAuthnAuthenticationCredential | undefined;
    let credentialForRelayJson = toCredentialForRelayJson(credentialWithPrf);

    let prfFirstB64u: string | undefined;

    if (signingContext.threshold && signingAuthMode === 'warmSession') {
      const delivered = await touchConfirmManager.dispensePrfFirstForThresholdSession({
        sessionId,
        uses: usesNeeded,
      });
      if (delivered.ok) {
        prfFirstB64u = delivered.prfFirstB64u;
      } else {
        await clearSigningSessionPrfFirstBestEffort(touchConfirmManager, sessionId);
        signingAuthMode = 'webauthn';

        thresholdSessionPlan = await buildEd25519SessionPolicyForNearSigning({
          nearAccountId,
          getRpId: () => ctx.touchIdPrompt.getRpId(),
          thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
          usesNeeded,
          desiredTtlMs,
          desiredRemainingUses,
        });

        const refreshed = await touchConfirmManager.orchestrateSigningConfirmation({
          ctx,
          sessionId,
          chain: 'near',
          kind: 'nep413',
          signingAuthMode: 'webauthn',
          sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
          nearAccountId,
          message: payload.message,
          recipient: payload.recipient,
          title: payload.title,
          body: payload.body,
          confirmationConfigOverride: payload.confirmationConfigOverride,
        });

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
      await cacheSigningSessionPrfFirstBestEffort(touchConfirmManager, {
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

    if (signingContext.threshold && !signingContext.threshold.thresholdSessionJwt) {
      throw new Error('Missing thresholdSessionJwt for threshold NEP-413 signing');
    }

    const requestPayload: Omit<WasmSignNep413MessageRequest, 'sessionId'> = {
      message: payload.message,
      recipient: payload.recipient,
      nonce: payload.nonce,
      state: payload.state || undefined,
      accountId: nearAccountId,
      nearPublicKey: signingContext.nearPublicKey,
      ...buildNearWorkerSigningEnvelope({
        signerMode: signingContext.resolvedSignerMode,
        prfFirstB64u,
        wrapKeySalt: signingContext.threshold ? thresholdWrapKeySalt : localWrapKeySalt,
        localKeyMaterial: signingContext.threshold ? undefined : localKeyMaterial,
        threshold: signingContext.threshold
          ? {
              relayerUrl: signingContext.threshold.relayerUrl,
              thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
              thresholdSessionJwt: signingContext.threshold.thresholdSessionJwt,
            }
          : undefined,
      }),
      credential: credentialForRelayJson,
    };

    if (!signingContext.threshold) {
      const response = await executeWorkerOperation({
        ctx,
        kind: 'nearSigner',
        request: {
          sessionId,
          type: WorkerRequestType.SignNep413Message,
          payload: requestPayload,
        },
      });
      const okResponse = requireOkSignNep413MessageResponse(response);

      return {
        success: true,
        accountId: okResponse.payload.accountId,
        publicKey: okResponse.payload.publicKey,
        signature: okResponse.payload.signature,
        state: okResponse.payload.state || undefined,
      };
    }

    let okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignNep413Message> | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const response = await executeWorkerOperation({
          ctx,
          kind: 'nearSigner',
          request: {
            sessionId,
            type: WorkerRequestType.SignNep413Message,
            payload: requestPayload,
          },
        });
        okResponse = requireOkSignNep413MessageResponse(response);
        break;
      } catch (e: unknown) {
        const err = e instanceof Error ? e : new Error(String(e));

        if (isThresholdSignerMissingKeyError(err)) {
          const msg =
            '[SigningEngine] threshold-signer requested but the relayer is missing the signing share; local fallback is disabled';
          clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
          signingContext.threshold.thresholdSessionJwt = undefined;
          throw new Error(msg);
        }

        if (attempt === 0 && isThresholdSessionAuthUnavailableError(err)) {
          clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
          await clearSigningSessionPrfFirstBestEffort(touchConfirmManager, sessionId);
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

          const refreshed = await touchConfirmManager.orchestrateSigningConfirmation({
            ctx,
            sessionId,
            chain: 'near',
            kind: 'nep413',
            signingAuthMode: 'webauthn',
            sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
            nearAccountId,
            message: payload.message,
            recipient: payload.recipient,
            title: payload.title,
            body: payload.body,
            confirmationConfigOverride: payload.confirmationConfigOverride,
          });

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

          await cacheSigningSessionPrfFirstBestEffort(touchConfirmManager, {
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
          requestPayload.credential = credentialForRelayJson;
          continue;
        }

        throw err;
      }
    }

    if (!okResponse) {
      throw new Error('No NEP-413 signing response received');
    }

    return {
      success: true,
      accountId: okResponse.payload.accountId,
      publicKey: okResponse.payload.publicKey,
      signature: okResponse.payload.signature,
      state: okResponse.payload.state || undefined,
    };
  } catch (error: unknown) {
    console.error('SignerWorkerManager: NEP-413 signing error:', error);
    return {
      success: false,
      accountId: '',
      publicKey: '',
      signature: '',
      error:
        error && typeof (error as { message?: unknown }).message === 'string'
          ? (error as { message: string }).message
          : 'Unknown error',
    };
  }
}

type ThresholdNep413SigningContext = {
  resolvedSignerMode: 'threshold-signer';
  nearPublicKey: string;
  threshold: {
    relayerUrl: string;
    thresholdKeyMaterial: ThresholdEd25519_2p_V1Material;
    thresholdSessionCacheKey: string;
    thresholdSessionJwt: string | undefined;
  };
};

type LocalNep413SigningContext = {
  resolvedSignerMode: 'local-signer';
  nearPublicKey: string;
  threshold: null;
};

type Nep413SigningContext = ThresholdNep413SigningContext | LocalNep413SigningContext;

function validateAndPrepareNep413SigningContext(args: {
  nearAccountId: string;
  resolvedSignerMode: SignerMode['mode'];
  relayerUrl: string;
  rpId: string | null;
  localKeyMaterial: LocalNearSkV3Material | null;
  thresholdKeyMaterial: ThresholdEd25519_2p_V1Material | null;
}): Nep413SigningContext {
  if (args.resolvedSignerMode !== 'threshold-signer') {
    if (!args.localKeyMaterial) {
      throw new Error(`No local key material found for account: ${args.nearAccountId}`);
    }
    const localPublicKey = String(args.localKeyMaterial.publicKey || '').trim();
    if (!localPublicKey) {
      throw new Error(`Missing local signing public key for ${args.nearAccountId}`);
    }
    return {
      resolvedSignerMode: 'local-signer',
      nearPublicKey: localPublicKey,
      threshold: null,
    };
  }

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
    nearPublicKey: thresholdPublicKey,
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
      thresholdSessionCacheKey,
      thresholdSessionJwt: getCachedEd25519AuthSessionJwt(thresholdSessionCacheKey),
    },
  };
}

function requireOkSignNep413MessageResponse(
  response: Nep413SigningResponse,
): WorkerSuccessResponse<typeof WorkerRequestType.SignNep413Message> {
  if (!isSignNep413MessageSuccess(response)) {
    if (isWorkerError(response)) {
      throw new Error(response.payload.error || 'NEP-413 signing failed');
    }
    throw new Error('NEP-413 signing failed');
  }
  return response;
}
