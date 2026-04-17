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
import { ActionPhase } from '@/core/types/sdkSentEvents';
import {
  PENDING_CHALLENGE_B64U,
  PENDING_INTENT_DIGEST,
  registerIntentDigestPreparation,
} from '@/core/signingEngine/touchConfirm/intentDigestPreparationRegistry';
import {
  asThresholdEcdsaKeyRef,
  inferDigest32FromSignRequest,
  makeRequestId,
  resolveKeyRefForSignRequest,
  resolveSigningAuthMode,
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
  onEvent?: (event: {
    step: number;
    phase: string;
    status: 'progress' | 'success' | 'error';
    message?: string;
    data?: unknown;
  }) => void;
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
    complete: (otpCode: string) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  };
}): Promise<TempoSignedResult> {
  const emitProgress = (event: {
    step: number;
    phase: string;
    status: 'progress' | 'success' | 'error';
    message?: string;
    data?: unknown;
  }) => {
    try {
      args.onEvent?.(event);
    } catch {}
  };

  const title = 'Sign Tempo Transaction';
  const body = 'Review and approve signing the Tempo sender hash.';
  let eagerDisplayModel:
    | ReturnType<typeof buildTempoDisplayModel>
    | undefined;
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
  const signingAuthModePromise = args.emailOtpSigning
    ? Promise.resolve<'emailOtp'>('emailOtp')
    : resolveSigningAuthMode({
        needsWebAuthn,
        thresholdEcdsaKeyRef,
        touchConfirm: args.touchConfirm,
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

  const sessionId = makeRequestId('intent');
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
      step: 2,
      phase: 'user-confirmation',
      status: 'progress',
      message: 'Awaiting transaction confirmation',
    });
    const signingAuthMode = await signingAuthModePromise;
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
      signingAuthMode,
      ...(args.emailOtpSigning
        ? {
            emailOtpPrompt: {
              challengeId: args.emailOtpSigning.challengeId,
              ...(args.emailOtpSigning.emailHint
                ? { emailHint: args.emailOtpSigning.emailHint }
                : {}),
              title: 'Confirm with Email OTP',
              helperText: 'Enter the 6-digit code sent to your email to authorize this transaction.',
            },
          }
        : {}),
      onProgress: args.onEvent,
      confirmationConfigOverride: args.confirmationConfigOverride,
    });
    emitProgress({
      step: 2,
      phase: 'user-confirmation-complete',
      status: 'success',
      message: 'Confirmation complete',
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
      const refreshed = await args.emailOtpSigning.complete(otpCode);
      thresholdEcdsaKeyRef = refreshed;
      ensuredThresholdKeyRef = refreshed;
    }
    const hasSecp256k1Request = intent.signRequests.some(
      (signReq) => signReq.algorithm === 'secp256k1',
    );
    if (hasSecp256k1Request && args.ensureThresholdEcdsaKeyRefReady) {
      await ensureThresholdKeyRef();
    }

    emitProgress({
      step: 5,
      phase: ActionPhase.STEP_5_TRANSACTION_SIGNING_PROGRESS,
      status: 'progress',
      message: 'Signing transaction...',
    });
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
      step: 6,
      phase: ActionPhase.STEP_6_TRANSACTION_SIGNING_COMPLETE,
      status: 'success',
      message: 'Transaction signed',
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
