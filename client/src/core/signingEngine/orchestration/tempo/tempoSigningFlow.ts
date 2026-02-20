import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type {
  SecureConfirmWorkerManager,
  SecureConfirmWorkerManagerContext,
} from '@/core/signingEngine/secureConfirm';
import type { KeyRef, SignRequest, SignerMap, SignatureBytes } from '@/core/signingEngine/interfaces/signing';
import { base64UrlEncode } from '@shared/utils/base64';
import { bytesToHex } from '../../chainAdaptors/evm/bytes';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { TempoAdapter, type TempoSignedResult } from '../../chainAdaptors/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chainAdaptors/tempo/types';
import { buildTempoDisplayModel } from '@/core/signingEngine/touchConfirm/flows/signing/tempo/buildDisplayModel';
import { resolveWebAuthnP256KeyRefForNearAccount } from '@/core/signingEngine/orchestration/walletOrigin/webauthnKeyRef';
import { executeSigningIntent } from '@/core/signingEngine/orchestration/executeSigningIntent';
import { normalizeAuthenticationCredential } from '@/core/signingEngine/signers/webauthn/credentials/helpers';
import {
  asThresholdEcdsaKeyRef,
  inferDigest32FromSignRequest,
  makeRequestId,
  resolveKeyRefForSignRequest,
  resolveSigningAuthMode,
} from '../shared/secureConfirmSigning';

export async function signTempoWithSecureConfirm(args: {
  ctx: SecureConfirmWorkerManagerContext;
  secureConfirmWorkerManager: Pick<
    SecureConfirmWorkerManager,
    'confirmAndPrepareSigningSession' | 'peekPrfFirstForThresholdSession'
  >;
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
    secureConfirmWorkerManager: args.secureConfirmWorkerManager,
  });

  const sessionId = makeRequestId('intent');
  const confirmation = await args.secureConfirmWorkerManager.confirmAndPrepareSigningSession({
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
    resolveSignInput: async (signReq: SignRequest) => {
      if (signReq.kind === 'webauthn') {
        if (!confirmation.credential) {
          throw new Error('[chains] missing WebAuthn credential from SecureConfirm');
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
}
