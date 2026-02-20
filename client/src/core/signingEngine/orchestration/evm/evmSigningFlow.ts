import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type {
  SecureConfirmWorkerManager,
  SecureConfirmWorkerManagerContext,
} from '@/core/signingEngine/secureConfirm';
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
import { buildEvmDisplayModel } from '@/core/signingEngine/touchConfirm/flows/signing/evm/buildDisplayModel';
import {
  asThresholdEcdsaKeyRef,
  inferDigest32FromSignRequest,
  makeRequestId,
  resolveKeyRefForSignRequest,
  resolveSigningAuthMode,
} from '../shared/secureConfirmSigning';

export async function signEvmWithSecureConfirm(args: {
  ctx: SecureConfirmWorkerManagerContext;
  secureConfirmWorkerManager: Pick<
    SecureConfirmWorkerManager,
    'confirmAndPrepareSigningSession' | 'peekPrfFirstForThresholdSession'
  >;
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
    secureConfirmWorkerManager: args.secureConfirmWorkerManager,
  });

  const sessionId = makeRequestId('intent');
  await args.secureConfirmWorkerManager.confirmAndPrepareSigningSession({
    ctx: args.ctx,
    sessionId,
    kind: 'intentDigest',
    nearAccountId: args.nearAccountId,
    challengeB64u,
    intentDigest: intentDigestHex,
    displayModel,
    title,
    body,
    signingAuthMode,
    onProgress: args.onEvent,
    confirmationConfigOverride: args.confirmationConfigOverride,
  });

  return await executeSigningIntent({
    intent,
    engines: args.engines,
    resolveSignInput: async (signReq: SignRequest) =>
      resolveKeyRefForSignRequest({
        signReq,
        keyRefsByAlgorithm: args.keyRefsByAlgorithm,
      }),
  });
}
