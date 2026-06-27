import type { SponsoredEvmExecutionAdapterResolver } from './evmExecutorTypes';
import { executeSponsoredEvmCall, resolveSponsoredEvmExecutorForChain } from './evmRelay';

export const resolveSponsoredEvmExecutionAdapter: SponsoredEvmExecutionAdapterResolver = (
  input,
) => {
  const executor = resolveSponsoredEvmExecutorForChain(input.config, input.chainId);
  if (!executor) return null;
  return {
    executorKind: 'evm_eoa',
    meta: {
      chainId: executor.chainId,
      sponsorAddress: executor.sponsorAddress,
    },
    execute: async () =>
      await executeSponsoredEvmCall({
        executor,
        call: input.call,
      }),
  };
};
