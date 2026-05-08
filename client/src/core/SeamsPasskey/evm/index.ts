import { toAccountId } from '../../types/accountIds';
import type { EvmSignerCapability } from '..';
import { routeWalletIframeOrLocal, type WalletIframeRouteDeps } from '../walletIframeRoute';
import { toWalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

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
    const context = this.getContext();
    const managedRegistration =
      context.configs.registration.mode === 'managed' ? context.configs.registration : null;
    const runtimeScopeBootstrap =
      args.options?.runtimeScopeBootstrap ||
      (managedRegistration
        ? {
            environmentId: managedRegistration.environmentId,
            publishableKey: managedRegistration.publishableKey,
          }
        : undefined);
    const chainTarget = args.options.chainTarget;
    if (chainTarget.kind !== 'evm') {
      throw new Error('[SeamsPasskey][evm] bootstrapEcdsaSession requires an EVM chainTarget');
    }
    const options = {
      ...(args.options || {}),
      ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
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
        return await context.signingEngine.bootstrapEcdsaSession({
          nearAccountId: toAccountId(args.nearAccountId),
          subjectId: toWalletSubjectId(args.nearAccountId),
          chainTarget,
          relayerUrl: options.relayerUrl,
          participantIds: options.participantIds,
          sessionKind: options.sessionKind,
          ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
          ttlMs: options.ttlMs,
          remainingUses: options.remainingUses,
          smartAccount: options.smartAccount ? { ...options.smartAccount } : undefined,
        });
      },
    });
  }
}
