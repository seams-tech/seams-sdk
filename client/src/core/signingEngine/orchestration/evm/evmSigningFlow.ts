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
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { base64UrlEncode } from '@shared/utils/base64';
import { bytesToHex } from '@/core/signingEngine/chainAdaptors/evm/bytes';
import {
  EvmAdapter,
  type EvmSignedResult,
} from '@/core/signingEngine/chainAdaptors/evm/evmAdapter';
import type { EvmSigningRequest } from '@/core/signingEngine/chainAdaptors/evm/types';
import type { ReserveNonceInput } from '@/core/rpcClients/evm/nonceManager';
import { toManagedNonceReservationSnapshot } from '@/core/rpcClients/evm/nonceManager';
import { executeSigningIntent } from '@/core/signingEngine/orchestration/executeSigningIntent';
import { buildEvmDisplayModel } from '@/core/signingEngine/touchConfirm/displayFormat/evmTx';
import {
  createSigningFlowEvent,
  SigningEventPhase,
  type CreateSigningFlowEventInput,
  type SigningFlowEvent,
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
  mapTouchConfirmSigningProgress,
  resolveKeyRefForSignRequest,
  resolveTouchConfirmSigningAuth,
  resolveTouchConfirmSigningAuthMethod,
} from '../shared/touchConfirmSigning';

type ManagedNonceReservation = ReserveNonceInput & { nonce: bigint };
type EvmSigningAuthSideEffect = 'passkey_reauth' | 'threshold_reconnect';

export async function signEvmWithTouchConfirm(args: {
  ctx: TouchConfirmContext;
  touchConfirm: TouchConfirmSigningPort &
    TouchConfirmSecureConfirmationPort &
    WarmSessionStatusReader;
  nearAccountId: string;
  request: EvmSigningRequest;
  engines: SignerMap<SignRequest, KeyRef, SignatureBytes>;
  onEvent?: (event: SigningFlowEvent) => void;
  keyRefsByAlgorithm?: Partial<Record<SignRequest['algorithm'], KeyRef>>;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  workerCtx: WorkerOperationContext;
  ensureThresholdEcdsaKeyRefReady?: () => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  prepareRequestWithManagedNonce?: () => Promise<{
    request: EvmSigningRequest;
    reservation: ManagedNonceReservation;
  }>;
  releaseNonceReservation?: (reservation: ManagedNonceReservation) => void;
  onConfirmationDisplayed?: () => void;
  reserveWalletSigningSessionBudget?: () => Promise<void>;
  emailOtpSigning?: {
    prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
    resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
    complete: (otpCode: string, challengeId?: string) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  };
  signingAuthPlan?: SigningAuthPlan;
  onAuthSideEffectStarted?: (sideEffect: EvmSigningAuthSideEffect) => void;
}): Promise<EvmSignedResult> {
  const sessionId = makeRequestId('intent');
  const flowId = `signing:evm:${args.nearAccountId}:${sessionId}`;
  const authMethod = resolveTouchConfirmSigningAuthMethod(
    args.signingAuthPlan,
    !!args.emailOtpSigning,
  );
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
    if (progress.phase === 'auth.passkey.prompt.started') {
      notifyAuthSideEffectStarted('passkey_reauth');
    }
    const mapped = mapTouchConfirmSigningProgress(progress, authMethod);
    if (mapped) emitProgress(mapped);
  };
  const authSideEffectsStarted = new Set<EvmSigningAuthSideEffect>();
  const notifyAuthSideEffectStarted = (sideEffect: EvmSigningAuthSideEffect): void => {
    if (authSideEffectsStarted.has(sideEffect)) return;
    authSideEffectsStarted.add(sideEffect);
    try {
      args.onAuthSideEffectStarted?.(sideEffect);
    } catch {}
  };

  const title = 'Sign EVM Transaction';
  const body = 'Review and approve signing the transaction hash.';
  let eagerDisplayModel: ReturnType<typeof buildEvmDisplayModel> | undefined;
  try {
    eagerDisplayModel = buildEvmDisplayModel({
      request: args.request,
      signerAccount: args.nearAccountId,
      title,
      subtitle: body,
    });
  } catch {}
  let thresholdEcdsaKeyRef = asThresholdEcdsaKeyRef(args.keyRefsByAlgorithm?.secp256k1);
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

    const intent = await new EvmAdapter(args.workerCtx).buildIntent(preparedRequest);
    const firstSignRequest = intent.signRequests[0];
    if (!firstSignRequest) {
      throw new Error('[chains] signing intent has no sign requests');
    }
    const firstDigest = inferDigest32FromSignRequest(firstSignRequest);
    const challengeB64u = base64UrlEncode(firstDigest);
    const intentDigestHex = bytesToHex(firstDigest);
    const displayModel = buildEvmDisplayModel({
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
    args.onConfirmationDisplayed?.();
    const initialEmailOtpChallenge = args.emailOtpSigning
      ? await args.emailOtpSigning.prepare()
      : undefined;
    const emailOtpPrompt = initialEmailOtpChallenge
      ? {
          challengeId: initialEmailOtpChallenge.challengeId,
          ...(initialEmailOtpChallenge.emailHint
            ? { emailHint: initialEmailOtpChallenge.emailHint }
            : {}),
          title: 'Enter email code to sign',
          helperText: formatEmailOtpSentText(initialEmailOtpChallenge.emailHint),
          ...(args.emailOtpSigning?.resend ? { onResend: args.emailOtpSigning.resend } : {}),
        }
      : undefined;
    const { touchConfirmAuthPayload } = await resolveTouchConfirmSigningAuth({
      needsWebAuthn: !args.signingAuthPlan && !emailOtpPrompt,
      ...(args.signingAuthPlan ? { signingAuthPlan: args.signingAuthPlan } : {}),
      ...(emailOtpPrompt ? { emailOtpPrompt } : {}),
    });
    if (touchConfirmAuthPayload.signingAuthPlan.kind === SigningAuthPlanKind.WarmSession) {
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
      chain: 'evm',
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
    if (!args.emailOtpSigning) {
      await args.reserveWalletSigningSessionBudget?.();
    }
    const intentPrepared = await intentPreparationTask;
    const intent = intentPrepared.intent;

    let ensuredThresholdKeyRef: ThresholdEcdsaSecp256k1KeyRef | null = null;
    let ensureThresholdKeyRefTask: Promise<ThresholdEcdsaSecp256k1KeyRef> | null = null;
    const ensureThresholdKeyRef = async (): Promise<ThresholdEcdsaSecp256k1KeyRef> => {
      if (ensuredThresholdKeyRef) return ensuredThresholdKeyRef;
      if (ensureThresholdKeyRefTask) return await ensureThresholdKeyRefTask;
      if (args.ensureThresholdEcdsaKeyRefReady) {
        notifyAuthSideEffectStarted('threshold_reconnect');
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
      await args.reserveWalletSigningSessionBudget?.();
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
    if (!nonceReservation) return result;
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
