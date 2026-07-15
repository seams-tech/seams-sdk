import {
  WorkerRequestType,
  WorkerResponseType,
  type ConfirmationConfig,
  type WorkerSuccessResponse,
} from '@/core/types/signer-worker';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { resolveNearNetwork } from '@/core/config/chains';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import { isSigningSessionAuthUnavailableError } from '@/core/signingEngine/threshold/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { NearSigningRuntimeDeps } from '../../interfaces/runtime';
import { computeThresholdEd25519Nep413SigningDigestWasm } from '../../chains/near/nearSignerWasm';
import type { ResolvedRouterAbEd25519WalletSessionState } from '../../session/warmCapabilities/routerAbEd25519WalletSessionState';
import { resolveNearSigningMaterials } from './shared/signingMaterials';
import {
  buildNearSigningSessionAuthPlan,
  createNearSigningSessionCoordinator,
  resolveNearSigningSessionAuthContext,
  SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR,
} from './shared/signingSessionAuthMode';
import { planSigningSession } from '../../session/planning/planner';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningOperationContext,
} from '../../session/operationState/types';
import { thresholdEd25519Nep413OperationFingerprint } from '@shared/threshold/ed25519OperationFingerprint';
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
import type { NearNep413Payload } from '../../interfaces/near';
import { tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning } from './shared/ed25519YaoNormalSigning';
import { base64Encode, base64UrlDecode } from '@shared/utils/base64';
import type { RouterAbEd25519YaoActiveClientV1 } from '../../threshold/ed25519/yaoClient';

type NearNep413YaoPayload = NearNep413Payload & {
  activeClient: RouterAbEd25519YaoActiveClientV1;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
};

/**
 * Sign a NEP-413 message using the active threshold-controlled NEAR key.
 *
 * @param payload - NEP-413 signing parameters including message, recipient, nonce, and state
 * @returns Promise resolving to signing result with account ID, public key, and signature
 */
type InternalSignNep413MessageResult =
  | {
      success: true;
      accountId: string;
      publicKey: string;
      signature: string;
      state?: string;
      error?: never;
    }
  | {
      success: false;
      error: string;
      accountId?: never;
      publicKey?: never;
      signature?: never;
      state?: never;
    };

export async function signNep413Message({
  ctx,
  commandSubject,
  nearAccount,
  signingSessionCoordinator,
  payload,
  activeClient,
  walletSessionState,
}: NearNep413YaoPayload): Promise<InternalSignNep413MessageResult> {
  try {
    const operationId = payload.operationId;
    const relayerUrl = ctx.relayerUrl;
    const nearAccountId = nearAccount.accountId;
    const touchConfirm = ctx.touchConfirm;
    if (!touchConfirm) {
      throw new Error('UiConfirm bridge not available for NEP-413 signing');
    }
    const warmSessionReader = createNearSigningSessionCoordinator(touchConfirm);

    const requiredSignatureUses = 1;
    const signingSessionAuthContext = await resolveNearSigningSessionAuthContext({
      warmSessionReader,
      requiredSignatureUses,
      commandSubject,
      operationLabel: 'NEP-413 signing',
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
      operationId,
      operationFingerprint: SigningSessionIds.signingOperationFingerprint(
        await thresholdEd25519Nep413OperationFingerprint({
          nearAccountId,
          nearNetworkId: resolveNearNetwork(
            ctx.chains || PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains,
          ),
          relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
          signerPublicKey: signingContext.threshold.thresholdKeyMaterial.publicKey,
          message: payload.message,
          recipient: payload.recipient,
          nonce: payload.nonce,
          state: payload.state || null,
        }),
      ),
      intent: SigningOperationIntent.TransactionSign,
    };
    const runSharedNearNep413Command = async <T>(args: {
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
    await runSigningConfirmationCommand({
      signingSessionPlan: resolvedSigningSession.signingSessionPlan,
      signingOperation,
      runtime: touchConfirm,
      request: {
        ctx: { touchConfirm },
        sessionId: String(operationId),
        chain: 'near',
        kind: 'nep413',
        ...buildSigningConfirmationAuthParams({
          signingAuthPlan: preparedStepUp.confirmationAuthPayload.signingAuthPlan,
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
        nearPublicKeyStr: signingContext.nearPublicKey,
        message: payload.message,
        recipient: payload.recipient,
        title: payload.title,
        body: payload.body,
        confirmationConfigOverride: confirmationConfigForSigningAuthPlan({
          signingAuthPlan: preparedStepUp.confirmationAuthPayload.signingAuthPlan,
          override: payload.confirmationConfigOverride,
        }),
      },
    });

    const canonicalThresholdSessionId = await runSharedNearNep413Command({
      commandKind: SigningOperationCommandKind.PreparePayload,
      execute: async () => {
        const sessionId = signingSessionAuthPlan.sessionId;
        if (walletSessionState.thresholdSessionId !== sessionId) {
          throw new Error('[SigningEngine][near] NEP-413 Yao session state mismatch');
        }
        return sessionId;
      },
    });

    const executeNep413Request = async () => {
      const signingDigest = await computeThresholdEd25519Nep413SigningDigestWasm({
        sessionId: canonicalThresholdSessionId,
        message: payload.message,
        recipient: payload.recipient,
        nonce: payload.nonce,
        ...(payload.state ? { state: payload.state } : {}),
        workerCtx: ctx,
      });
      const signatureOnlyIntent = {
        kind: 'nep413_message_v1' as const,
        message: payload.message,
        recipient: payload.recipient,
        nonce: payload.nonce,
        ...(payload.state ? { state: payload.state } : {}),
      };
      const routerAbNormalSigningResult =
        await tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning({
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
        return {
          type: WorkerResponseType.SignNep413MessageSuccess,
          payload: {
            accountId: nearAccountId,
            publicKey: routerAbNormalSigningResult.signerPublicKey,
            signature: base64Encode(base64UrlDecode(routerAbNormalSigningResult.signatureB64u)),
            state: payload.state || undefined,
          },
        } as WorkerSuccessResponse<typeof WorkerRequestType.SignNep413Message>;
      }
      throw new Error('[SigningEngine][near] Router A/B Ed25519 NEP-413 signing is unavailable');
    };

    const okResponse = await runSharedNearNep413Command({
      commandKind: SigningOperationCommandKind.Sign,
      execute: async () => {
        try {
          return await executeNep413Request();
        } catch (e: unknown) {
          const err = e instanceof Error ? e : new Error(String(e));

          if (isSigningSessionAuthUnavailableError(err)) {
            throw new Error(SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR);
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
