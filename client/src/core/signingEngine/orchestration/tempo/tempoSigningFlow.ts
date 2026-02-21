import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type {
  TouchConfirmSigningPort,
  TouchConfirmContext,
  ThresholdPrfFirstCachePeekPort,
} from '@/core/signingEngine/touchConfirm';
import type { KeyRef, SignRequest, SignerMap, SignatureBytes } from '@/core/signingEngine/interfaces/signing';
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
  asThresholdEcdsaKeyRef,
  inferDigest32FromSignRequest,
  makeRequestId,
  resolveKeyRefForSignRequest,
  resolveSigningAuthMode,
} from '../shared/touchConfirmSigning';

export async function signTempoWithTouchConfirm(args: {
  ctx: TouchConfirmContext;
  touchConfirmManager: TouchConfirmSigningPort & ThresholdPrfFirstCachePeekPort;
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

  const intent = await new TempoAdapter(args.workerCtx).buildIntent(args.request);

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
  const title = 'Sign TempoTransaction (0x76)';
  const body = 'Review and approve signing the Tempo sender hash.';
  const displayModel = buildTempoDisplayModel({
    request: args.request,
    intentDigest: intentDigestHex,
    signerAccount: args.nearAccountId,
    title,
    subtitle: body,
  });
  const needsWebAuthn = webauthnReqs.length === 1;
  const thresholdEcdsaKeyRef = asThresholdEcdsaKeyRef(args.keyRefsByAlgorithm?.secp256k1);
  const signingAuthMode = await resolveSigningAuthMode({
    needsWebAuthn,
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
  const confirmation = await args.touchConfirmManager.orchestrateSigningConfirmation({
    ctx: args.ctx,
    sessionId,
    chain: 'tempo',
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
  return result;
}
