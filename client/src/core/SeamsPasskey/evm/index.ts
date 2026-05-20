import { toAccountId } from '../../types/accountIds';
import type { EvmSignerCapability } from '..';
import { routeWalletIframeOrLocal, type WalletIframeRouteDeps } from '../walletIframeRoute';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

type ChainSignerDeps = {
  getContext: () => import('../index').PasskeyManagerContext;
  walletIframe: WalletIframeRouteDeps;
};

function toLocalBootstrapRequest(
  args: Parameters<EvmSignerCapability['bootstrapEcdsaSession']>[0],
): EcdsaBootstrapRequest {
  return {
    kind: 'reuse_warm_ecdsa_bootstrap',
    walletId: toAccountId(args.walletSession.walletId),
    chainTarget: args.chainTarget,
    source: args.source,
    relayerUrl: args.relayerUrl,
    runtimeScopeBootstrap: args.runtimeScopeBootstrap,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  };
}

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
    const context = this.getContext();
    const managedRegistration =
      context.configs.registration.mode === 'managed' ? context.configs.registration : null;
    const runtimeScopeBootstrap =
      args.runtimeScopeBootstrap ||
      (managedRegistration
        ? {
            environmentId: managedRegistration.environmentId,
            publishableKey: managedRegistration.publishableKey,
          }
        : undefined);
    const chainTarget = args.chainTarget;
    if (chainTarget.kind !== 'evm') {
      throw new Error('[SeamsPasskey][evm] bootstrapEcdsaSession requires an EVM chainTarget');
    }
    const bootstrapArgs = {
      ...args,
      ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
    };

    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      walletId: toWalletId(args.walletSession.walletId),
      remote: async (router) => {
        return await router.bootstrapEcdsaSession(bootstrapArgs);
      },
      local: async () => {
        return await context.signingEngine.bootstrapEcdsaSession(
          toLocalBootstrapRequest(bootstrapArgs),
        );
      },
    });
  }
}
