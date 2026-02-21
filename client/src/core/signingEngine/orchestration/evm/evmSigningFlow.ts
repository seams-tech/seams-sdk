import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type {
  TouchConfirmSigningPort,
  TouchConfirmContext,
  ThresholdPrfFirstCachePeekPort,
} from '@/core/signingEngine/touchConfirm';
import type {
  KeyRef,
  SignRequest,
  SignerMap,
  SignatureBytes,
} from '@/core/signingEngine/interfaces/signing';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { base64UrlEncode } from '@shared/utils/base64';
import { bytesToHex } from '@/core/signingEngine/chainAdaptors/evm/bytes';
import { EvmAdapter, type EvmSignedResult } from '@/core/signingEngine/chainAdaptors/evm/evmAdapter';
import type { EvmSigningRequest } from '@/core/signingEngine/chainAdaptors/evm/types';
import { executeSigningIntent } from '@/core/signingEngine/orchestration/executeSigningIntent';
import { buildEvmDisplayModel } from '@/core/signingEngine/touchConfirm/displayFormat/evmTx';
import { ActionPhase } from '@/core/types/sdkSentEvents';
import {
  asThresholdEcdsaKeyRef,
  inferDigest32FromSignRequest,
  makeRequestId,
  resolveKeyRefForSignRequest,
  resolveSigningAuthMode,
} from '../shared/touchConfirmSigning';

export async function signEvmWithTouchConfirm(args: {
  ctx: TouchConfirmContext;
  touchConfirmManager: TouchConfirmSigningPort & ThresholdPrfFirstCachePeekPort;
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

  const intent = await new EvmAdapter(args.workerCtx).buildIntent(args.request);

  const firstSignRequest = intent.signRequests[0];
  if (!firstSignRequest) {
    throw new Error('[chains] signing intent has no sign requests');
  }
  const firstDigest = inferDigest32FromSignRequest(firstSignRequest);
  const challengeB64u = base64UrlEncode(firstDigest);
  const intentDigestHex = bytesToHex(firstDigest);
  const title = 'Sign EIP-1559 (0x02)';
  const body = 'Review and approve signing the transaction hash.';
  const displayModel = buildEvmDisplayModel({
    request: args.request,
    intentDigest: intentDigestHex,
    signerAccount: args.nearAccountId,
    title,
    subtitle: body,
  });
  const thresholdEcdsaKeyRef = asThresholdEcdsaKeyRef(args.keyRefsByAlgorithm?.secp256k1);
  const signingAuthMode = await resolveSigningAuthMode({
    needsWebAuthn: false,
    thresholdEcdsaKeyRef,
    touchConfirmManager: args.touchConfirmManager,
  });

  const sessionId = makeRequestId('intent');
  emitProgress({
    step: 2,
    phase: 'user-confirmation',
    status: 'progress',
    message: 'Awaiting transaction confirmation',
  });
  await args.touchConfirmManager.orchestrateSigningConfirmation({
    ctx: args.ctx,
    sessionId,
    chain: 'evm',
    kind: 'intentDigest',
    signerAccountId: args.nearAccountId,
    challengeB64u,
    intentDigest: intentDigestHex,
    displayModel,
    title,
    body,
    signingAuthMode,
    onProgress: args.onEvent,
    confirmationConfigOverride: args.confirmationConfigOverride,
  });
  emitProgress({
    step: 2,
    phase: 'user-confirmation-complete',
    status: 'success',
    message: 'Confirmation complete',
  });

  emitProgress({
    step: 5,
    phase: ActionPhase.STEP_5_TRANSACTION_SIGNING_PROGRESS,
    status: 'progress',
    message: 'Signing transaction...',
  });
  const result = await executeSigningIntent({
    intent,
    engines: args.engines,
    resolveSignInput: async (signReq: SignRequest) =>
      resolveKeyRefForSignRequest({
        signReq,
        keyRefsByAlgorithm: args.keyRefsByAlgorithm,
      }),
  });
  emitProgress({
    step: 6,
    phase: ActionPhase.STEP_6_TRANSACTION_SIGNING_COMPLETE,
    status: 'success',
    message: 'Transaction signed',
  });
  return result;
}
