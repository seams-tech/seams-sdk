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
} from '@/core/signingEngine/threshold/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { SigningRuntimeDeps } from '../../interfaces/runtime';
import { executeWorkerOperation } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  generateNearSigningSessionId,
  requirePrfFirstFromCredential,
  resolveNearSigningMaterials,
  toCredentialForRelayJson,
} from './shared/signingMaterials';
import { requireResolvedThresholdEd25519SessionState } from './shared/thresholdSessionAuth';
import { buildNearWorkerSigningEnvelope } from '../../chains/near/workerRequest';
import {
  buildNearThresholdSigningAuthPlan,
  createNearSigningSessionCoordinator,
  resolveNearThresholdSigningAuthContext,
  THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR,
} from './shared/thresholdAuthMode';
import { ensureThresholdEd25519HssClientBase } from '../../threshold/ed25519/hssClientBase';
import { repairThresholdEd25519MissingRelayerKey } from '../../threshold/ed25519/repairMissingRelayerKey';
import { planSigningSession } from '../../session/planning/planner';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningOperationContext,
} from '../../session/operationState/types';
import {
  SigningOperationCommandKind,
  runSigningOperationCommand,
  type SigningOperationCommand,
} from '../shared/signingStateMachine';
import { runSigningConfirmationCommand } from '../shared/signingConfirmation';
import { requireNearStepUpAuth } from './requireNearStepUpAuth';
import { buildNearEd25519StepUpAuthorization } from './stepUpAuthorization';
import type { NearAccountRef } from '../../interfaces/ecdsaChainTarget';

/**
 * Sign a NEP-413 message using the user's passkey-derived private key
 *
 * @param payload - NEP-413 signing parameters including message, recipient, nonce, and state
 * @returns Promise resolving to signing result with account ID, public key, and signature
 */
export async function signNep413Message({
  ctx,
  nearAccount,
  payload,
}: {
  ctx: SigningRuntimeDeps;
  nearAccount: NearAccountRef;
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
    const sessionId = payload.sessionId ?? generateNearSigningSessionId();
    const relayerUrl = ctx.relayerUrl;
    const nearAccountId = nearAccount.accountId;
    const touchConfirm = ctx.touchConfirm;
    if (!touchConfirm) {
      throw new Error('UiConfirm bridge not available for NEP-413 signing');
    }
    const signingSessionCoordinator = createNearSigningSessionCoordinator(touchConfirm);

    const usesNeeded = 1;
    const thresholdAuthContext = await resolveNearThresholdSigningAuthContext({
      warmSessionReader: signingSessionCoordinator,
      usesNeeded,
      nearAccount,
      operationLabel: 'NEP-413 signing',
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
    const { thresholdKeyMaterial } = await resolveNearSigningMaterials({
      ctx,
      nearAccount,
      signerSlot: payload.signerSlot,
      operationLabel: 'NEP-413 signing',
    });
    const signingContext = validateAndPrepareNep413SigningContext({
      nearAccountId,
      relayerUrl,
      thresholdKeyMaterial,
    });
    const signingOperation: SigningOperationContext = {
      operationId: SigningSessionIds.signingOperation(`near-nep413:${sessionId}`),
      intent: SigningOperationIntent.TransactionSign,
    };
    const runSharedNearNep413Command = async <T>(args: {
      commandKind: SigningOperationCommand['kind'];
      execute: () => Promise<T>;
    }): Promise<T> =>
      await runSigningOperationCommand({
        signingSessionPlan: resolvedThresholdSigningSession.signingSessionPlan,
        signingOperation,
        commandKind: args.commandKind,
        execute: args.execute,
      });
    const preparedStepUp = await requireNearStepUpAuth({
      signingAuthPlan: thresholdAuthPlan.signingAuthPlan,
      signingLane: thresholdAuthPlan.lane,
      usesNeeded,
    });
    const confirmation = await runSigningConfirmationCommand({
      signingSessionPlan: resolvedThresholdSigningSession.signingSessionPlan,
      signingOperation,
      runtime: touchConfirm,
      request: {
        ctx: { touchConfirm },
        sessionId,
        chain: 'near',
        kind: 'nep413',
        ...preparedStepUp.confirmationAuthPayload,
        nearAccountId,
        nearPublicKeyStr: signingContext.nearPublicKey,
        message: payload.message,
        recipient: payload.recipient,
        title: payload.title,
        body: payload.body,
        confirmationConfigOverride: payload.confirmationConfigOverride,
      },
    });
    const stepUpAuthorization = buildNearEd25519StepUpAuthorization({
      prepared: preparedStepUp,
      confirmation,
    });

    const credentialWithPrf: WebAuthnAuthenticationCredential | undefined =
      stepUpAuthorization.kind === 'passkey' ? stepUpAuthorization.credential : undefined;
    const credentialForRelayJson = toCredentialForRelayJson(credentialWithPrf);

    const preparedPayload = await runSharedNearNep413Command({
      commandKind: SigningOperationCommandKind.PreparePayload,
      execute: async () => {
        const prfFirstB64u = stepUpAuthorization.kind === 'warm_session'
          ? await signingSessionCoordinator.claimPrfFirstByThresholdSessionId({
              kind: 'wallet_scoped_ed25519_claim',
              thresholdSessionId: thresholdAuthPlan.sessionId,
              uses: usesNeeded,
              errorContext: 'threshold-ed25519 nep413 signing',
              walletId: nearAccountId,
              authMethod: 'passkey',
              curve: 'ed25519',
              chain: 'near',
              walletSigningSessionId: thresholdAuthPlan.lane.walletSigningSessionId,
            })
          : requirePrfFirstFromCredential(credentialWithPrf);

        if (!prfFirstB64u) {
          throw new Error('Missing PRF.first output for signing');
        }

        const canonicalThresholdSessionId = thresholdAuthPlan.sessionId;
        const thresholdSessionState = requireResolvedThresholdEd25519SessionState({
          signingSessionCoordinator,
          thresholdSessionId: canonicalThresholdSessionId,
        });
        const xClientBaseB64u = await ensureThresholdEd25519HssClientBase({
          ctx,
          thresholdSessionId: canonicalThresholdSessionId,
          existingXClientBaseB64u: thresholdSessionState.xClientBaseB64u,
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
        });
        return {
          canonicalThresholdSessionId,
          thresholdSessionState,
          prfFirstB64u,
          xClientBaseB64u,
        };
      },
    });
    const {
      canonicalThresholdSessionId,
      thresholdSessionState,
      prfFirstB64u,
      xClientBaseB64u,
    } = preparedPayload;

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

    const okResponse = await runSharedNearNep413Command({
      commandKind: SigningOperationCommandKind.Sign,
      execute: async () => {
        try {
          return await executeNep413Request(requestPayload);
        } catch (e: unknown) {
          const err = e instanceof Error ? e : new Error(String(e));

          if (isThresholdSignerMissingKeyError(err)) {
            try {
              const repairedXClientBaseB64u = await repairThresholdEd25519MissingRelayerKey({
                ctx,
                operationLabel: 'nep413',
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
              });
              requestPayload = buildRequestPayload(repairedXClientBaseB64u);
              return await executeNep413Request(requestPayload);
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
      },
    });

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
