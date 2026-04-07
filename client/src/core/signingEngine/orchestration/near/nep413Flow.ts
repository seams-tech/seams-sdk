import {
  WorkerRequestType,
  isSignNep413MessageSuccess,
  isWorkerError,
  type ConfirmationConfig,
  type Nep413SigningResponse,
  type WasmSignNep413MessageRequest,
  type WorkerSuccessResponse,
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
import { toAccountId } from '@/core/types/accountIds';
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
    deviceNumber?: number;
    title?: string;
    body?: string;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    sessionId?: string;
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
    const { thresholdKeyMaterial } = await resolveNearSigningMaterials({
      ctx,
      nearAccountId,
      deviceNumber: payload.deviceNumber,
      operationLabel: 'NEP-413 signing',
    });
    const touchConfirm = ctx.touchConfirm;
    if (!touchConfirm) {
      throw new Error('TouchConfirm bridge not available for NEP-413 signing');
    }

    const signingContext = validateAndPrepareNep413SigningContext({
      nearAccountId,
      relayerUrl,
      rpId: ctx.touchIdPrompt.getRpId(),
      thresholdKeyMaterial,
    });

    // Initialize nonce manager for a better UserConfirm context (block height + access key lookup).
    // NEP-413 signing itself doesn't require nonces, but UserConfirm uses Near context for UI.
    ctx.nonceManager.initializeUser(toAccountId(nearAccountId), signingContext.nearPublicKey);

    const usesNeeded = 1;
    const thresholdAuthPlan = signingContext.threshold
      ? await resolveNearThresholdSigningAuthPlan({
          touchConfirm,
          sessionId,
          usesNeeded,
          nearAccountId,
          operationLabel: 'NEP-413 signing',
        })
      : null;
    const signingAuthMode = thresholdAuthPlan?.signingAuthMode;

    const confirmation = await touchConfirm.orchestrateSigningConfirmation({
      ctx: { touchConfirm },
      sessionId,
      chain: 'near',
      kind: 'nep413',
      ...(signingAuthMode ? { signingAuthMode } : {}),
      nearAccountId,
      message: payload.message,
      recipient: payload.recipient,
      title: payload.title,
      body: payload.body,
      confirmationConfigOverride: payload.confirmationConfigOverride,
    });

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

    const canonicalThresholdSessionId = signingContext.threshold
      ? resolveCanonicalThresholdSessionId({
          thresholdSessionCacheKey: signingContext.threshold.thresholdSessionCacheKey,
          fallbackSessionId: sessionId,
        })
      : sessionId;
    if (
      signingContext.threshold &&
      ((signingContext.threshold.thresholdSessionKind === 'jwt' &&
        !signingContext.threshold.thresholdSessionJwt) ||
        signingContext.threshold.thresholdSessionKind === 'cookie')
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
      signingContext.threshold &&
      signingContext.threshold.thresholdSessionKind === 'jwt' &&
      !signingContext.threshold.thresholdSessionJwt
    ) {
      clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
      throw new Error(
        '[chains] threshold signingSession auth is unavailable; reconnect threshold session before signing',
      );
    }
    const xClientBaseB64u = signingContext.threshold
      ? await ensureThresholdEd25519HssClientBase({
          ctx,
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
        })
      : undefined;

    const buildRequestPayload = (
      xClientBaseOverride?: string,
    ): Omit<WasmSignNep413MessageRequest, 'sessionId'> => ({
      message: payload.message,
      recipient: payload.recipient,
      nonce: payload.nonce,
      state: payload.state || undefined,
      accountId: nearAccountId,
      nearPublicKey: signingContext.nearPublicKey,
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
      credential: credentialForRelayJson,
    });
    let requestPayload = buildRequestPayload(xClientBaseB64u);

    const executeNep413Request = async (
      payloadForWorker: Omit<WasmSignNep413MessageRequest, 'sessionId'>,
    ) => {
      const response = await executeWorkerOperation({
        ctx,
        kind: 'nearSigner',
        request: {
          sessionId,
          type: WorkerRequestType.SignNep413Message,
          payload: payloadForWorker,
        },
      });
      return requireOkSignNep413MessageResponse(response);
    };

    let okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignNep413Message>;
    try {
      okResponse = await executeNep413Request(requestPayload);
    } catch (e: unknown) {
      const err = e instanceof Error ? e : new Error(String(e));

      if (isThresholdSignerMissingKeyError(err)) {
        try {
          const repairedXClientBaseB64u = await repairThresholdEd25519MissingRelayerKey({
            ctx,
            operationLabel: 'nep413',
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
          });
          requestPayload = buildRequestPayload(repairedXClientBaseB64u);
          okResponse = await executeNep413Request(requestPayload);
        } catch (repairError: unknown) {
          const repairErr =
            repairError instanceof Error ? repairError : new Error(String(repairError));
          if (isThresholdSignerMissingKeyError(repairErr)) {
            const msg =
              '[SigningEngine] threshold-signer requested but the relayer signing share could not be repaired from the active HSS session';
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
  nearPublicKey: string;
  threshold: {
    relayerUrl: string;
    thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
    thresholdSessionCacheKey: string;
    thresholdSessionKind: 'jwt' | 'cookie';
    thresholdSessionJwt: string | undefined;
  };
};

function validateAndPrepareNep413SigningContext(args: {
  nearAccountId: string;
  relayerUrl: string;
  rpId: string | null;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial | null;
}): ThresholdNep413SigningContext {
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
  const cachedAuthSession = getCachedEd25519AuthSession(thresholdSessionCacheKey);
  const thresholdSessionKind: 'jwt' | 'cookie' =
    cachedAuthSession?.sessionKind === 'cookie' ? 'cookie' : 'jwt';

  return {
    nearPublicKey: thresholdPublicKey,
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
