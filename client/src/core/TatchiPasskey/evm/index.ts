import { toAccountId } from '../../types/accountIds';
import type { EvmSignerCapability } from '..';
import { routeWalletIframeOrLocal, type WalletIframeRouteDeps } from '../walletIframeRoute';

type ChainSignerDeps = {
  getContext: () => import('../index').PasskeyManagerContext;
  walletIframe: WalletIframeRouteDeps;
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

  async bootstrapEcdsaSession(args: Parameters<EvmSignerCapability['bootstrapEcdsaSession']>[0]) {
    const options = {
      ...(args.options || {}),
      chain: 'evm' as const,
    };

    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        return await router.bootstrapEcdsaSession({
          nearAccountId: args.nearAccountId,
          options,
        });
      },
      local: async () => {
        const context = this.getContext();
        const managedRegistration =
          context.configs.registration.mode === 'managed' ? context.configs.registration : null;
        return await context.signingEngine.bootstrapEcdsaSession({
          nearAccountId: toAccountId(args.nearAccountId),
          chain: options.chain,
          relayerUrl: options.relayerUrl,
          participantIds: options.participantIds,
          sessionKind: options.sessionKind,
          ...(managedRegistration
            ? {
                runtimeScopeBootstrap: {
                  environmentId: managedRegistration.environmentId,
                  publishableKey: managedRegistration.publishableKey,
                },
              }
            : {}),
          ttlMs: options.ttlMs,
          remainingUses: options.remainingUses,
          smartAccount: options.smartAccount ? { ...options.smartAccount } : undefined,
        });
      },
    });
  }
}
