import {
  EvmAdapter,
  type EvmSignedResult,
} from '@/core/signingEngine/chainAdaptors/evm/evmAdapter';
import type { EvmSigningRequest } from '@/core/signingEngine/chainAdaptors/evm/types';
import { buildEvmDisplayModel } from '@/core/signingEngine/touchConfirm/displayFormat/evmTx';
import {
  signEvmFamilyWithTouchConfirm,
  type SignEvmFamilyWithTouchConfirmArgs,
} from '../shared/evmFamilySigningFlow';

export async function signEvmWithTouchConfirm(
  args: SignEvmFamilyWithTouchConfirmArgs<EvmSigningRequest>,
): Promise<EvmSignedResult> {
  return await signEvmFamilyWithTouchConfirm({
    config: {
      chain: 'evm',
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
