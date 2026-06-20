import {
  EvmAdapter,
  type EvmSignedResult,
} from '@/core/signingEngine/chains/evm/evmAdapter';
import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/evmSigning.types';
import { buildEvmDisplayModel } from '@/core/signingEngine/chains/evm/display/evmTx';
import {
  signEvmFamilyWithUiConfirm,
  type SignEvmFamilyWithUiConfirmArgs,
} from './signingFlow';

export async function signEvmWithUiConfirm(
  args: SignEvmFamilyWithUiConfirmArgs<EvmSigningRequest>,
): Promise<EvmSignedResult> {
  return await signEvmFamilyWithUiConfirm({
    config: {
      targetKind: 'evm',
      flowName: 'evm',
      explicitAuthErrorLabel: 'EVM',
      nonceErrorLabel: 'EVM',
      title: 'Sign EVM Transaction',
      body: 'Review and approve signing the transaction hash.',
      buildIntent: async ({ workerCtx, request }) =>
        await new EvmAdapter(workerCtx).buildIntent(request),
      buildDisplayModel: buildEvmDisplayModel,
      webauthn: { kind: 'not_supported' },
    },
    input: args,
  });
}
