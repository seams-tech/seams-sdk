import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
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
import type { SigningSessionBudgetReservation } from '../../session/signingSession/budget';
import type { ManagedNonceReservation } from '@/core/rpcClients/evm/nonceBackend';
import { toManagedNonceReservationSnapshot } from '@/core/rpcClients/evm/nonceBackend';
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

type TempoSigningAuthSideEffect = 'passkey_reauth' | 'threshold_reconnect';
type TempoPasskeyEcdsaReconnect = {
  prepare: (args: { usesNeeded: number }) => Promise<{
    sessionId: string;
    walletSigningSessionId?: string;
    sessionPolicyDigest32: string;
  }>;
  reconnect: (args: {
    credential: WebAuthnAuthenticationCredential;
    usesNeeded: number;
    sessionId?: string;
    walletSigningSessionId?: string;
  }) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
};

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
  passkeyEcdsaReconnect?: TempoPasskeyEcdsaReconnect;
  prepareRequestWithManagedNonce?: () => Promise<{
    request: TempoSigningRequest;
    reservation: ManagedNonceReservation;
  }>;
  releaseNonceReservation?: (reservation: ManagedNonceReservation) => void | Promise<void>;
  onConfirmationDisplayed?: () => void;
  reserveWalletSigningSessionBudget?: () => Promise<SigningSessionBudgetReservation | null>;
  emailOtpSigning?: {
    prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
    resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
    complete: (otpCode: string, challengeId?: string) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  };
  signingAuthPlan?: SigningAuthPlan;
  onAuthSideEffectStarted?: (sideEffect: TempoSigningAuthSideEffect) => void;
}): Promise<TempoSignedResult> {
  const sessionId = makeRequestId('intent');
  const flowId = `signing:tempo:${args.nearAccountId}:${sessionId}`;
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
  const authSideEffectsStarted = new Set<TempoSigningAuthSideEffect>();
  const notifyAuthSideEffectStarted = (sideEffect: TempoSigningAuthSideEffect): void => {
    if (authSideEffectsStarted.has(sideEffect)) return;
    authSideEffectsStarted.add(sideEffect);
    try {
      args.onAuthSideEffectStarted?.(sideEffect);
    } catch {}
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
  let preparedRequest = args.request;
  let nonceReservation: ManagedNonceReservation | null = null;
  let reservationReleased = false;
  let thresholdSignatureCreated = false;
  let walletBudgetReservation: SigningSessionBudgetReservation | null = null;
  let walletBudgetReservationAttempted = false;
  const reserveWalletSigningBudgetOnce = async (): Promise<void> => {
    if (walletBudgetReservationAttempted) return;
    walletBudgetReservationAttempted = true;
    walletBudgetReservation = (await args.reserveWalletSigningSessionBudget?.()) || null;
  };
  const releaseWalletBudgetReservation = (): void => {
    if (!walletBudgetReservation) return;
    walletBudgetReservation.release();
    walletBudgetReservation = null;
  };
  const releaseNonceReservation = async (): Promise<void> => {
    if (reservationReleased || !nonceReservation || !args.releaseNonceReservation) return;
    reservationReleased = true;
    try {
      await args.releaseNonceReservation(nonceReservation);
    } catch {}
  };
  const markNonceReservationSigned = async (): Promise<void> => {
    if (!nonceReservation) return;
    const leaseId = String(nonceReservation.leaseId || '').trim();
    const operationId = String(nonceReservation.operationId || '').trim();
    if (!leaseId || !operationId) {
      throw new Error('[chains] managed Tempo nonce reservation is missing lease metadata');
    }
    await args.ctx.nonceCoordinator.markSigned({
      leaseId,
      operationId,
    });
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
      needsWebAuthn: needsWebAuthn || (!args.signingAuthPlan && !emailOtpPrompt),
      ...(args.signingAuthPlan ? { signingAuthPlan: args.signingAuthPlan } : {}),
      ...(emailOtpPrompt ? { emailOtpPrompt } : {}),
    });
    const usesNeeded = 1;
    const shouldReconnectWithPasskeyEcdsa =
      touchConfirmAuthPayload.signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth &&
      Boolean(args.passkeyEcdsaReconnect);
    const plannedPasskeyReconnect =
      shouldReconnectWithPasskeyEcdsa && args.passkeyEcdsaReconnect?.prepare
        ? await args.passkeyEcdsaReconnect.prepare({ usesNeeded })
        : undefined;
    if (touchConfirmAuthPayload.signingAuthPlan.kind === SigningAuthPlanKind.WarmSession) {
      await reserveWalletSigningBudgetOnce();
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
      ...(plannedPasskeyReconnect?.sessionPolicyDigest32
        ? { sessionPolicyDigest32: plannedPasskeyReconnect.sessionPolicyDigest32 }
        : {}),
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
      await reserveWalletSigningBudgetOnce();
    }
    const hasSecp256k1Request = intent.signRequests.some(
      (signReq) => signReq.algorithm === 'secp256k1',
    );
    if (hasSecp256k1Request && shouldReconnectWithPasskeyEcdsa && args.passkeyEcdsaReconnect) {
      if (!confirmation.credential) {
        throw new Error('[chains] missing WebAuthn credential for threshold ECDSA reconnect');
      }
      notifyAuthSideEffectStarted('threshold_reconnect');
      const refreshed = await args.passkeyEcdsaReconnect.reconnect({
        credential: confirmation.credential as WebAuthnAuthenticationCredential,
        usesNeeded,
        ...(plannedPasskeyReconnect?.sessionId
          ? { sessionId: plannedPasskeyReconnect.sessionId }
          : {}),
        ...(plannedPasskeyReconnect?.walletSigningSessionId
          ? { walletSigningSessionId: plannedPasskeyReconnect.walletSigningSessionId }
          : {}),
      });
      if (
        plannedPasskeyReconnect?.sessionId &&
        String(refreshed.thresholdSessionId || '').trim() !== plannedPasskeyReconnect.sessionId
      ) {
        throw new Error(
          '[chains] threshold ECDSA reconnect returned a different session id than the confirmed session policy',
        );
      }
      thresholdEcdsaKeyRef = refreshed;
      ensuredThresholdKeyRef = refreshed;
    }
    if (hasSecp256k1Request && args.ensureThresholdEcdsaKeyRefReady) {
      await ensureThresholdKeyRef();
    }
    if (!args.emailOtpSigning) {
      await reserveWalletSigningBudgetOnce();
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
    thresholdSignatureCreated = true;
    await markNonceReservationSigned();
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
    if (!thresholdSignatureCreated) {
      releaseWalletBudgetReservation();
      if (nonceReservation) {
        await releaseNonceReservation();
      } else if (args.releaseNonceReservation) {
        await intentPreparationTask
          .then(async () => {
            await releaseNonceReservation();
          })
          .catch(() => undefined);
      }
    }
    throw error;
  }
}
