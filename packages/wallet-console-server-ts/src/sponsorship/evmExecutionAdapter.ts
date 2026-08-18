import type { SponsoredEvmExecutionAdapterResolver } from './evmExecutorTypes';
import type {
  SponsoredEvmCall,
} from './evm';
import type {
  SponsoredEvmChainExecutorConfig,
  SponsoredEvmExecutionAdapter,
  SponsoredEvmExecutionResult,
} from './evmExecutorTypes';
import { executeSponsoredEvmCall, resolveSponsoredEvmExecutorForChain } from './evmRelay';

class NodeSponsoredEvmExecutionAdapter implements SponsoredEvmExecutionAdapter {
  readonly executorKind = 'evm_eoa' as const;

  readonly meta: {
    readonly chainId: number;
    readonly sponsorAddress: `0x${string}`;
  };

  constructor(
    private readonly executor: SponsoredEvmChainExecutorConfig,
    private readonly call: SponsoredEvmCall,
  ) {
    this.meta = {
      chainId: executor.chainId,
      sponsorAddress: executor.sponsorAddress,
    };
  }

  async execute(): Promise<SponsoredEvmExecutionResult> {
    return await executeSponsoredEvmCall({
      executor: this.executor,
      call: this.call,
    });
  }
}

export const resolveSponsoredEvmExecutionAdapter: SponsoredEvmExecutionAdapterResolver = (
  input,
) => {
  const executor = resolveSponsoredEvmExecutorForChain(input.config, input.chainId);
  if (!executor) return null;
  return new NodeSponsoredEvmExecutionAdapter(executor, input.call);
};
