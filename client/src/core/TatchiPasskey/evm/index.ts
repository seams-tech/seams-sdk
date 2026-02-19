import { toAccountId } from '../../types/accountIds';
import type { EvmSignerCapability } from '..';

type ChainSignerDeps = {
  getContext: () => import('../index').PasskeyManagerContext;
  walletIframe: Pick<
    import('../walletIframeCoordinator').WalletIframeCoordinator,
    'shouldUseWalletIframe' | 'requireRouter'
  >;
};

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
    const options = {
      ...(args.options || {}),
      chain: 'evm' as const,
    };

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.nearAccountId);
      return await router.bootstrapThresholdEcdsaSession({
        nearAccountId: args.nearAccountId,
        options,
      });
    }

    return await this
      .getContext()
      .webAuthnManager
      .thresholdSession
      .bootstrapThresholdEcdsaSessionLite({
        nearAccountId: toAccountId(args.nearAccountId),
        chain: options.chain,
        relayerUrl: options.relayerUrl,
        participantIds: options.participantIds,
        sessionKind: options.sessionKind,
        ttlMs: options.ttlMs,
        remainingUses: options.remainingUses,
        smartAccount: options.smartAccount,
      });
  }
}
