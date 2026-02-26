import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type {
  TouchConfirmSigningPort,
  TouchConfirmSecureConfirmationPort,
  TouchConfirmContext,
  ThresholdPrfFirstCachePeekPort,
} from '@/core/signingEngine/touchConfirm';
import type {
  KeyRef,
  SignRequest,
  SignerMap,
  SignatureBytes,
} from '@/core/signingEngine/interfaces/signing';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
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

export async function signEvmWithTouchConfirm(args: {
  ctx: TouchConfirmContext;
  touchConfirm: TouchConfirmSigningPort &
    TouchConfirmSecureConfirmationPort &
    ThresholdPrfFirstCachePeekPort;
  nearAccountId: string;
  request: EvmSigningRequest;
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
    request: EvmSigningRequest;
    reservation: ManagedNonceReservation;
  }>;
  releaseNonceReservation?: (reservation: ManagedNonceReservation) => void;
}): Promise<EvmSignedResult> {
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

  const title = 'Sign EVM Transaction';
  const body = 'Review and approve signing the transaction hash.';
  const initialDisplayModel = buildEvmDisplayModel({
    request: args.request,
    signerAccount: args.nearAccountId,
    title,
    subtitle: body,
  });
  let thresholdEcdsaKeyRef = asThresholdEcdsaKeyRef(args.keyRefsByAlgorithm?.secp256k1);
  const signingAuthModePromise = resolveSigningAuthMode({
    needsWebAuthn: false,
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
      step: 2,
      phase: 'user-confirmation',
      status: 'progress',
      message: 'Awaiting transaction confirmation',
    });
    await args.touchConfirm.orchestrateSigningConfirmation({
      ctx: { touchConfirm: args.touchConfirm },
      sessionId,
      chain: 'evm',
      kind: 'intentDigest',
      signerAccountId: args.nearAccountId,
      challengeB64u: PENDING_CHALLENGE_B64U,
      intentDigest: PENDING_INTENT_DIGEST,
      displayModel: initialDisplayModel,
      title,
      body,
      signingAuthMode: await signingAuthModePromise,
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
