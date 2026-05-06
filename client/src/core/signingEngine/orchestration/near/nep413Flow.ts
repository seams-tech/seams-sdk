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
  isThresholdSessionAuthUnavailableError,
  isThresholdSignerMissingKeyError,
} from '@/core/signingEngine/threshold/session/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { SigningRuntimeDeps } from '../../interfaces/runtime';
import { executeWorkerOperation } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  generateSessionId,
  requirePrfFirstFromCredential,
  resolveNearSigningMaterials,
  toCredentialForRelayJson,
} from './shared/signingMaterials';
import { requireResolvedThresholdEd25519SessionState } from './shared/thresholdSessionAuth';
import { buildNearWorkerSigningEnvelope } from './shared/workerRequestAssembly';
import {
  buildNearThresholdSigningAuthPlan,
  createNearSigningSessionCoordinator,
  resolveNearThresholdSigningAuthContext,
  THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR,
} from './shared/thresholdAuthMode';
import { ensureThresholdEd25519HssClientBase } from './shared/ensureThresholdEd25519HssClientBase';
import { repairThresholdEd25519MissingRelayerKey } from './shared/repairThresholdEd25519MissingRelayerKey';
import { passkeySigningAuthPlan } from '../shared/touchConfirmSigning';
import { planSigningSession } from '../../session/signingSession/planner';

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
    signerSlot?: number;
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
      signerSlot: payload.signerSlot,
      operationLabel: 'NEP-413 signing',
    });
    const touchConfirm = ctx.touchConfirm;
    if (!touchConfirm) {
      throw new Error('TouchConfirm bridge not available for NEP-413 signing');
    }
    const signingSessionCoordinator = createNearSigningSessionCoordinator(touchConfirm);

    const signingContext = validateAndPrepareNep413SigningContext({
      nearAccountId,
      relayerUrl,
      thresholdKeyMaterial,
    });

    const usesNeeded = 1;
    const thresholdAuthContext = signingContext.threshold
      ? await resolveNearThresholdSigningAuthContext({
          warmSessionReader: signingSessionCoordinator,
          usesNeeded,
          nearAccountId,
          operationLabel: 'NEP-413 signing',
        })
      : null;
    const resolvedThresholdSigningSession = thresholdAuthContext
      ? {
          signingSessionPlan: planSigningSession({
            lane: thresholdAuthContext.coordinatorInput.lane,
            readiness: thresholdAuthContext.coordinatorInput.readiness,
            forceFreshAuth: thresholdAuthContext.coordinatorInput.forceFreshAuth,
          }),
          readiness: thresholdAuthContext.coordinatorInput.readiness,
          expiresAtMs: thresholdAuthContext.coordinatorInput.expiresAtMs || 0,
          remainingUses: thresholdAuthContext.coordinatorInput.remainingUses || 0,
        }
      : null;
    const thresholdAuthPlan = thresholdAuthContext
      ? buildNearThresholdSigningAuthPlan({
          context: thresholdAuthContext,
          resolvedSigningSession: resolvedThresholdSigningSession!,
        })
      : null;
    const confirmation = await touchConfirm.orchestrateSigningConfirmation({
      ctx: { touchConfirm },
      sessionId,
      chain: 'near',
      kind: 'nep413',
      ...(thresholdAuthPlan?.touchConfirmAuthPayload ?? { signingAuthPlan: passkeySigningAuthPlan() }),
      nearAccountId,
      nearPublicKeyStr: signingContext.nearPublicKey,
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
        ? await signingSessionCoordinator.claimPrfFirstByThresholdSessionId({
            thresholdSessionId: thresholdAuthPlan.sessionId,
            uses: usesNeeded,
            errorContext: 'threshold-ed25519 nep413 signing',
            walletId: nearAccountId,
            authMethod: thresholdAuthPlan.lane.authMethod,
            curve: 'ed25519',
            chain: 'near',
            walletSigningSessionId: thresholdAuthPlan.lane.walletSigningSessionId,
          })
        : requirePrfFirstFromCredential(credentialWithPrf)
      : requirePrfFirstFromCredential(credentialWithPrf);

    if (!prfFirstB64u) {
      throw new Error('Missing PRF.first output for signing');
    }

    const canonicalThresholdSessionId = thresholdAuthPlan?.sessionId || sessionId;
    const thresholdSessionState = requireResolvedThresholdEd25519SessionState({
      signingSessionCoordinator,
      thresholdSessionId: canonicalThresholdSessionId,
    });
    const xClientBaseB64u = signingContext.threshold
      ? await ensureThresholdEd25519HssClientBase({
          ctx,
          thresholdSessionId: canonicalThresholdSessionId,
          thresholdSessionAuthToken: thresholdSessionState.thresholdSessionAuthToken,
          relayerUrl: thresholdSessionState.relayerUrl,
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
    ): Omit<WasmSignNep413MessageRequest, 'sessionId'> => {
      const currentThresholdSessionState = requireResolvedThresholdEd25519SessionState({
        signingSessionCoordinator,
        thresholdSessionId: canonicalThresholdSessionId,
      });
      return {
        message: payload.message,
        recipient: payload.recipient,
        nonce: payload.nonce,
        state: payload.state || undefined,
        accountId: nearAccountId,
        nearPublicKey: signingContext.nearPublicKey,
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
        credential: credentialForRelayJson,
      };
    };
    let requestPayload = buildRequestPayload(xClientBaseB64u);

    const executeNep413Request = async (
      payloadForWorker: Omit<WasmSignNep413MessageRequest, 'sessionId'>,
    ) => {
      const response = await executeWorkerOperation({
        ctx,
        kind: 'nearSigner',
        request: {
          sessionId: canonicalThresholdSessionId,
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
            thresholdSessionAuthToken: thresholdSessionState.thresholdSessionAuthToken,
            relayerUrl: thresholdSessionState.relayerUrl,
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
  };
};

function validateAndPrepareNep413SigningContext(args: {
  nearAccountId: string;
  relayerUrl: string;
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

  const participantIds = normalizeThresholdEd25519ParticipantIds(
    thresholdKeyMaterial.participants.map((p) => p.id),
  );
  if (!participantIds || participantIds.length < 2) {
    throw new Error(
      `Invalid threshold signing participantIds (expected >=2 participants, got [${(participantIds || []).join(',')}])`,
    );
  }

  return {
    nearPublicKey: thresholdPublicKey,
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
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
