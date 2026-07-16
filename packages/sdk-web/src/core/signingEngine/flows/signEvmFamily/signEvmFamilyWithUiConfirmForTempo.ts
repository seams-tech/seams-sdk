import {
  TempoAdapter,
  type TempoSignedResult,
} from '@/core/signingEngine/chains/tempo/tempoAdapter';
import { EvmAdapter, type EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/evmSigning.types';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import { buildEvmDisplayModel } from '@/core/signingEngine/chains/evm/display/evmTx';
import { buildTempoDisplayModel } from '@/core/signingEngine/chains/tempo/display';
import type { SignRequest } from '@/core/signingEngine/interfaces/signing';
import { signEvmFamilyWithUiConfirm, type SignEvmFamilyWithUiConfirmArgs } from './signingFlow';
import { requiredEvmFamilyRequestSignatureUses } from './signatureUses';
import { resolveWebAuthnP256KeyRefForWallet } from './webauthnP256KeyRef';

export async function signEvmFamilyWithUiConfirmForTempo(
  args: SignEvmFamilyWithUiConfirmArgs<TempoSigningRequest | EvmSigningRequest>,
): Promise<TempoSignedResult | EvmSignedResult> {
  if (args.request.kind === 'eip1559') {
    return await signEvmFamilyWithUiConfirm({
      config: {
        targetKind: 'tempo',
        flowName: 'tempo',
        explicitAuthErrorLabel: 'Tempo',
        nonceErrorLabel: 'Tempo',
        title: 'Sign Tempo Transaction',
        body: 'Review and approve signing the transaction hash.',
        buildIntent: async ({ workerCtx, request }) =>
          await new EvmAdapter(workerCtx).buildIntent(request),
        buildDisplayModel: buildEvmDisplayModel,
        requiredSignatureUsesForRequest: requiredEvmFamilyRequestSignatureUses,
        webauthn: { kind: 'not_supported' },
      },
      input: args as SignEvmFamilyWithUiConfirmArgs<EvmSigningRequest>,
    });
  }

  return await signEvmFamilyWithUiConfirm({
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
      requiredSignatureUsesForRequest: requiredEvmFamilyRequestSignatureUses,
      webauthn: {
        kind: 'supported',
        requestNeedsWebAuthn: (request) => request.senderSignatureAlgorithm === 'webauthnP256',
        validateIntent: (intent) => {
          const webauthnReqs = intent.signRequests.filter((request) => request.kind === 'webauthn');
          if (webauthnReqs.length > 1) {
            throw new Error('[chains] multiple WebAuthn sign requests are not supported yet');
          }
        },
        resolveKeyRef: async ({ ctx, walletId, workerCtx, signReq, credential }) => {
          const webauthnKeyRef = await resolveWebAuthnP256KeyRefForWallet({
            passkeyAuthenticatorStore: ctx.passkeyAuthenticatorStore,
            walletId,
            workerCtx,
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
    input: args as SignEvmFamilyWithUiConfirmArgs<TempoSigningRequest>,
  });
}
