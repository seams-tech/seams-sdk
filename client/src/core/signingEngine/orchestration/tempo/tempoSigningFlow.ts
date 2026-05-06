import {
  TempoAdapter,
  type TempoSignedResult,
} from '@/core/signingEngine/chainAdaptors/tempo/tempoAdapter';
import type { TempoSigningRequest } from '@/core/signingEngine/chainAdaptors/tempo/types';
import { buildTempoDisplayModel } from '@/core/signingEngine/touchConfirm/displayFormat/tempoTx';
import { resolveWebAuthnP256KeyRefForNearAccount } from '@/core/signingEngine/orchestration/walletOrigin/webauthnKeyRef';
import type { SignRequest } from '@/core/signingEngine/interfaces/signing';
import {
  signEvmFamilyWithTouchConfirm,
  type SignEvmFamilyWithTouchConfirmArgs,
} from '../shared/evmFamilySigningFlow';

export async function signTempoWithTouchConfirm(
  args: SignEvmFamilyWithTouchConfirmArgs<TempoSigningRequest>,
): Promise<TempoSignedResult> {
  return await signEvmFamilyWithTouchConfirm({
    config: {
      targetKind: 'tempo',
      flowName: 'tempo',
      explicitAuthErrorLabel: 'Tempo',
      nonceErrorLabel: 'Tempo',
      title: 'Sign Tempo Transaction',
      body: 'Review and approve signing the Tempo sender hash.',
      buildIntent: async ({ workerCtx, request }) =>
        await new TempoAdapter(workerCtx).buildIntent(request),
      buildDisplayModel: buildTempoDisplayModel,
      webauthn: {
        kind: 'supported',
        requestNeedsWebAuthn: (request) => request.senderSignatureAlgorithm === 'webauthnP256',
        validateIntent: (intent) => {
          const webauthnReqs = intent.signRequests.filter((request) => request.kind === 'webauthn');
          if (webauthnReqs.length > 1) {
            throw new Error('[chains] multiple WebAuthn sign requests are not supported yet');
          }
        },
        resolveKeyRef: async ({ ctx, nearAccountId, signReq, credential }) => {
          const webauthnKeyRef = await resolveWebAuthnP256KeyRefForNearAccount({
            indexedDB: ctx.indexedDB,
            nearAccountId,
            rpId: signReq.rpId,
          });
          const requestWithCredential: SignRequest = { ...signReq, credential };
          return {
            signReq: requestWithCredential,
            keyRef: webauthnKeyRef,
          };
        },
      },
    },
    input: args,
  });
}
