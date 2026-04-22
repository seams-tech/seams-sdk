import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type {
  TouchConfirmSigningPort,
  TouchConfirmSecureConfirmationPort,
  TouchConfirmContext,
  WarmSessionStatusReader,
} from '@/core/signingEngine/touchConfirm';
import type {
  KeyRef,
  SignRequest,
  SignerMap,
  SignatureBytes,
} from '@/core/signingEngine/interfaces/signing';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import type { WalletAuthPlan } from '@/core/signingEngine/auth';
import type { ReserveNonceInput } from '@/core/rpcClients/evm/nonceManager';
import { toManagedNonceReservationSnapshot } from '@/core/rpcClients/evm/nonceManager';
import { base64UrlEncode } from '@shared/utils/base64';
import { bytesToHex } from '../../chainAdaptors/evm/bytes';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { TempoAdapter, type TempoSignedResult } from '../../chainAdaptors/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chainAdaptors/tempo/types';
import { buildTempoDisplayModel } from '@/core/signingEngine/touchConfirm/displayFormat/tempoTx';
import { resolveWebAuthnP256KeyRefForNearAccount } from '@/core/signingEngine/orchestration/walletOrigin/webauthnKeyRef';
import { executeSigningIntent } from '@/core/signingEngine/orchestration/executeSigningIntent';
import { normalizeAuthenticationCredential } from '@/core/signingEngine/signers/webauthn/credentials/helpers';
import {
  createSigningFlowEvent,
  SigningEventPhase,
  type CreateSigningFlowEventInput,
  type SigningFlowEvent,
  type WalletFlowAuthMethod,
  type WalletFlowInteractionKind,
} from '@/core/types/sdkSentEvents';
import {
  PENDING_CHALLENGE_B64U,
  PENDING_INTENT_DIGEST,
  registerIntentDigestPreparation,
} from '@/core/signingEngine/touchConfirm/intentDigestPreparationRegistry';
import {
  asThresholdEcdsaKeyRef,
  formatEmailOtpSentText,
  inferDigest32FromSignRequest,
  makeRequestId,
  resolveKeyRefForSignRequest,
  resolveTouchConfirmSigningAuth,
} from '../shared/touchConfirmSigning';

type ManagedNonceReservation = ReserveNonceInput & { nonce: bigint };

export async function signTempoWithTouchConfirm(args: {
  ctx: TouchConfirmContext;
  touchConfirm: TouchConfirmSigningPort &
    TouchConfirmSecureConfirmationPort &
    WarmSessionStatusReader;
  nearAccountId: string;
  request: TempoSigningRequest;
  engines: SignerMap<SignRequest, KeyRef, SignatureBytes>;
  onEvent?: (event: SigningFlowEvent) => void;
  keyRefsByAlgorithm?: Partial<Record<SignRequest['algorithm'], KeyRef>>;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  workerCtx: WorkerOperationContext;
  ensureThresholdEcdsaKeyRefReady?: () => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  prepareRequestWithManagedNonce?: () => Promise<{
    request: TempoSigningRequest;
    reservation: ManagedNonceReservation;
  }>;
  releaseNonceReservation?: (reservation: ManagedNonceReservation) => void;
  emailOtpSigning?: {
    challengeId: string;
    emailHint?: string;
    resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
    complete: (otpCode: string, challengeId?: string) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  };
  walletAuthPlan?: WalletAuthPlan;
}): Promise<TempoSignedResult> {
  const sessionId = makeRequestId('intent');
  const flowId = `signing:tempo:${args.nearAccountId}:${sessionId}`;
  const authMethod = resolveSigningAuthMethod(args.walletAuthPlan, !!args.emailOtpSigning);
  const emitProgress = (
    event: Omit<CreateSigningFlowEventInput, 'flowId' | 'accountId' | 'authMethod'>,
  ) => {
    try {
      args.onEvent?.(
        createSigningFlowEvent({
          ...event,
          flowId,
          accountId: args.nearAccountId,
          authMethod,
        }),
      );
    } catch {}
  };
  const emitTouchConfirmProgress = (progress: {
    phase: string;
    status: 'running' | 'succeeded' | 'failed';
    message?: string;
    data?: unknown;
  }) => {
    const mapped = mapTouchConfirmSigningProgress(progress, authMethod);
    if (mapped) emitProgress(mapped);
  };

  const title = 'Sign Tempo Transaction';
  const body = 'Review and approve signing the Tempo sender hash.';
  let eagerDisplayModel: ReturnType<typeof buildTempoDisplayModel> | undefined;
  try {
    eagerDisplayModel = buildTempoDisplayModel({
      request: args.request,
      signerAccount: args.nearAccountId,
      title,
      subtitle: body,
    });
  } catch {}
  const needsWebAuthn = args.request.senderSignatureAlgorithm === 'webauthnP256';
  let thresholdEcdsaKeyRef = asThresholdEcdsaKeyRef(args.keyRefsByAlgorithm?.secp256k1);
  const emailOtpPrompt = args.emailOtpSigning
    ? {
        challengeId: args.emailOtpSigning.challengeId,
        ...(args.emailOtpSigning.emailHint ? { emailHint: args.emailOtpSigning.emailHint } : {}),
        title: 'Enter email code to sign',
        helperText: formatEmailOtpSentText(args.emailOtpSigning.emailHint),
        ...(args.emailOtpSigning.resend ? { onResend: args.emailOtpSigning.resend } : {}),
      }
    : undefined;
  const signingAuthPromise = resolveTouchConfirmSigningAuth({
    needsWebAuthn: needsWebAuthn || (!args.walletAuthPlan && !emailOtpPrompt),
    ...(args.walletAuthPlan ? { walletAuthPlan: args.walletAuthPlan } : {}),
    ...(emailOtpPrompt ? { emailOtpPrompt } : {}),
  });
  let preparedRequest = args.request;
  let nonceReservation: ManagedNonceReservation | null = null;
  let reservationReleased = false;
  const releaseNonceReservation = (): void => {
    if (reservationReleased || !nonceReservation || !args.releaseNonceReservation) return;
    reservationReleased = true;
    try {
      args.releaseNonceReservation(nonceReservation);
    } catch {}
  };

  const intentPreparationTask = (async () => {
    if (args.prepareRequestWithManagedNonce) {
      const prepared = await args.prepareRequestWithManagedNonce();
      preparedRequest = prepared.request;
      nonceReservation = prepared.reservation;
    }

    const intent = await new TempoAdapter(args.workerCtx).buildIntent(preparedRequest);
    const webauthnReqs = intent.signRequests.filter((r) => r.kind === 'webauthn');
    if (webauthnReqs.length > 1) {
      throw new Error('[chains] multiple WebAuthn sign requests are not supported yet');
    }
    const firstSignRequest = intent.signRequests[0];
    if (!firstSignRequest) {
      throw new Error('[chains] signing intent has no sign requests');
    }
    const firstDigest = inferDigest32FromSignRequest(firstSignRequest);
    const challengeB64u = base64UrlEncode(firstDigest);
    const intentDigestHex = bytesToHex(firstDigest);
    const displayModel = buildTempoDisplayModel({
      request: preparedRequest,
      intentDigest: intentDigestHex,
      signerAccount: args.nearAccountId,
      title,
      subtitle: body,
    });
    return {
      intent,
      challengeB64u,
      intentDigestHex,
      displayModel,
    };
  })();
  registerIntentDigestPreparation({
    requestId: sessionId,
    preparation: intentPreparationTask.then((prepared) => ({
      intentDigest: prepared.intentDigestHex,
      challengeB64u: prepared.challengeB64u,
      displayModel: prepared.displayModel,
      title,
      body,
    })),
  });

  try {
    emitProgress({
      phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
      status: 'waiting_for_user',
      interaction: { kind: 'transaction_confirmation', overlay: 'show' },
    });
    const { touchConfirmAuthPayload } = await signingAuthPromise;
    if (touchConfirmAuthPayload.signingAuthPlan.kind === 'warmSession') {
      emitProgress({
        phase: SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
        status: 'succeeded',
        interaction: { kind: 'none', overlay: 'none' },
        data: {
          sessionId: touchConfirmAuthPayload.signingAuthPlan.sessionId,
          expiresAtMs: touchConfirmAuthPayload.signingAuthPlan.expiresAtMs,
          remainingUses: touchConfirmAuthPayload.signingAuthPlan.remainingUses,
        },
      });
    }
    const confirmation = await args.touchConfirm.orchestrateSigningConfirmation({
      ctx: { touchConfirm: args.touchConfirm },
      sessionId,
      chain: 'tempo',
      kind: 'intentDigest',
      signerAccountId: args.nearAccountId,
      challengeB64u: PENDING_CHALLENGE_B64U,
      intentDigest: PENDING_INTENT_DIGEST,
      ...(eagerDisplayModel ? { displayModel: eagerDisplayModel } : {}),
      title,
      body,
      ...touchConfirmAuthPayload,
      ...(emailOtpPrompt ? { emailOtpPrompt } : {}),
      onProgress: emitTouchConfirmProgress,
      confirmationConfigOverride: args.confirmationConfigOverride,
    });
    emitProgress({
      phase: SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
      status: 'succeeded',
      interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
    });
    const intentPrepared = await intentPreparationTask;
    const intent = intentPrepared.intent;

    let ensuredThresholdKeyRef: ThresholdEcdsaSecp256k1KeyRef | null = null;
    let ensureThresholdKeyRefTask: Promise<ThresholdEcdsaSecp256k1KeyRef> | null = null;
    const ensureThresholdKeyRef = async (): Promise<ThresholdEcdsaSecp256k1KeyRef> => {
      if (ensuredThresholdKeyRef) return ensuredThresholdKeyRef;
      if (ensureThresholdKeyRefTask) return await ensureThresholdKeyRefTask;
      if (args.ensureThresholdEcdsaKeyRefReady) {
        ensureThresholdKeyRefTask = (async () => {
          const ensured = await args.ensureThresholdEcdsaKeyRefReady!();
          thresholdEcdsaKeyRef = ensured;
          ensuredThresholdKeyRef = ensured;
          return ensured;
        })();
        try {
          return await ensureThresholdKeyRefTask;
        } finally {
          ensureThresholdKeyRefTask = null;
        }
      }
      if (thresholdEcdsaKeyRef) {
        ensuredThresholdKeyRef = thresholdEcdsaKeyRef;
        return thresholdEcdsaKeyRef;
      }
      throw new Error('[chains] missing threshold ECDSA keyRef for secp256k1 signing');
    };
    if (args.emailOtpSigning) {
      const otpCode = String(confirmation.otpCode || '').trim();
      if (!/^\d{6}$/.test(otpCode)) {
        throw new Error('[chains] missing Email OTP code from touchConfirm');
      }
      const refreshed = await args.emailOtpSigning.complete(
        otpCode,
        confirmation.emailOtpChallengeId,
      );
      thresholdEcdsaKeyRef = refreshed;
      ensuredThresholdKeyRef = refreshed;
    }
    const hasSecp256k1Request = intent.signRequests.some(
      (signReq) => signReq.algorithm === 'secp256k1',
    );
    if (hasSecp256k1Request && args.ensureThresholdEcdsaKeyRefReady) {
      await ensureThresholdKeyRef();
    }

    if (hasSecp256k1Request) {
      emitProgress({
        phase: SigningEventPhase.STEP_10_COMMIT_STARTED,
        status: 'running',
        interaction: { kind: 'none', overlay: 'none' },
      });
    }
    const result = await executeSigningIntent({
      intent,
      engines: args.engines,
      resolveSignInput: async (signReq: SignRequest) => {
        if (signReq.kind === 'webauthn') {
          if (!confirmation.credential) {
            throw new Error('[chains] missing WebAuthn credential from touchConfirm');
          }
          const credential = normalizeAuthenticationCredential(confirmation.credential);
          const webauthnKeyRef = await resolveWebAuthnP256KeyRefForNearAccount({
            indexedDB: args.ctx.indexedDB,
            nearAccountId: args.nearAccountId,
            rpId: signReq.rpId,
          });
          return {
            signReq: { ...signReq, credential },
            keyRef: webauthnKeyRef,
          };
        }

        if (signReq.algorithm === 'secp256k1') {
          const keyRef = await ensureThresholdKeyRef();
          return { signReq, keyRef };
        }

        return resolveKeyRefForSignRequest({
          signReq,
          keyRefsByAlgorithm: args.keyRefsByAlgorithm,
        });
      },
    });
    emitProgress({
      phase: SigningEventPhase.STEP_11_TRANSACTION_SIGNED,
      status: 'succeeded',
      interaction: { kind: 'none', overlay: 'hide' },
    });
    emitProgress({
      phase: SigningEventPhase.STEP_15_COMPLETED,
      status: 'succeeded',
      interaction: { kind: 'none', overlay: 'none' },
      data: { operation: 'sign' },
    });
    if (!nonceReservation) {
      return result;
    }
    return {
      ...result,
      managedNonce: toManagedNonceReservationSnapshot(nonceReservation),
    };
  } catch (error: unknown) {
    if (nonceReservation) {
      releaseNonceReservation();
    } else if (args.releaseNonceReservation) {
      void intentPreparationTask
        .then(() => {
          releaseNonceReservation();
        })
        .catch(() => undefined);
    }
    throw error;
  }
}

function resolveSigningAuthMethod(
  walletAuthPlan: WalletAuthPlan | undefined,
  hasEmailOtpPrompt: boolean,
): WalletFlowAuthMethod {
  if (hasEmailOtpPrompt || walletAuthPlan?.kind === 'emailOtpReauth') return 'email_otp';
  if (walletAuthPlan?.kind === 'warmSession') return 'warm_session';
  return 'passkey';
}

function mapTouchConfirmSigningProgress(
  progress: {
    phase: string;
    status: 'running' | 'succeeded' | 'failed';
    message?: string;
    data?: unknown;
  },
  authMethod: WalletFlowAuthMethod,
): Omit<CreateSigningFlowEventInput, 'flowId' | 'accountId' | 'authMethod'> | null {
  const phase = String(progress.phase || '');
  const failed = progress.status === 'failed';
  if (phase === 'intent-confirmation-required') {
    return {
      phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
      status: 'waiting_for_user',
      interaction: { kind: 'transaction_confirmation', overlay: 'show' },
      data: toEventData(progress.data),
    };
  }
  if (phase === 'confirmation.complete') {
    if (failed) {
      return {
        phase: SigningEventPhase.STEP_05_CONFIRMATION_CANCELLED,
        status: 'cancelled',
        interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
        error: { message: progress.message || 'Transaction rejected' },
        data: toEventData(progress.data),
      };
    }
    return {
      phase:
        authMethod === 'email_otp'
          ? SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_VERIFY_SUCCEEDED
          : SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
      status: 'succeeded',
      interaction: {
        kind: authMethod === 'email_otp' ? 'otp_input' : 'transaction_confirmation',
        overlay: 'hide',
      },
      data: toEventData(progress.data),
    };
  }
  if (phase === 'auth.passkey.prompt.started') {
    return {
      phase: SigningEventPhase.STEP_06_AUTH_PASSKEY_PROMPT_STARTED,
      status: 'waiting_for_user',
      interaction: { kind: 'passkey_assert', overlay: 'show' },
      data: toEventData(progress.data),
    };
  }
  if (phase === 'auth.passkey.prompt.succeeded') {
    const interactionKind: WalletFlowInteractionKind = 'passkey_assert';
    if (failed) {
      return {
        phase: SigningEventPhase.FAILED,
        status: 'failed',
        interaction: { kind: interactionKind, overlay: 'hide' },
        error: { message: progress.message || 'Transaction signing failed' },
        data: toEventData(progress.data),
      };
    }
    return {
      phase: SigningEventPhase.STEP_06_AUTH_PASSKEY_PROMPT_SUCCEEDED,
      status: 'succeeded',
      interaction: { kind: interactionKind, overlay: 'hide' },
      data: toEventData(progress.data),
    };
  }
  return null;
}

function toEventData(value: unknown): Record<string, unknown> | undefined {
  if (value == null) return undefined;
  if (typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
  return { value };
}
