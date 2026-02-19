import type { EvmSignerCapability } from '../capabilities';
import {
  bootstrapThresholdEcdsaSessionForChain,
  type ChainSignerDeps,
} from './shared';

/**
 * EVM signer currently exposes threshold-ECDSA bootstrap only.
 */
export class EvmSigner implements EvmSignerCapability {
  private readonly getContext: ChainSignerDeps['getContext'];
  private readonly walletIframe: ChainSignerDeps['walletIframe'];

  constructor(deps: ChainSignerDeps) {
    this.getContext = deps.getContext;
    this.walletIframe = deps.walletIframe;
  }

  async bootstrapThresholdEcdsaSession(
    args: Parameters<EvmSignerCapability['bootstrapThresholdEcdsaSession']>[0],
  ) {
    return await bootstrapThresholdEcdsaSessionForChain(
      {
        getContext: this.getContext,
        walletIframe: this.walletIframe,
      },
      args,
      'evm',
    );
  }
}
