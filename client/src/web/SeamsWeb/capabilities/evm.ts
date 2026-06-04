import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toError } from '@shared/utils/errors';
import type { EvmSignerCapability } from '../interfaces';
import { buildEvmBootstrapArgs, buildEvmWalletRegistrationArgs, EvmSigner } from '../evm';
import type { WalletIframeCoordinator } from '../walletIframeCoordinator';

export function createEvmSignerCapability(deps: {
  getContext: () => import('../index').SeamsWebContext;
  getWalletIframe: () => WalletIframeCoordinator;
}): EvmSignerCapability {
  const evmSigner = new EvmSigner({ getContext: deps.getContext });
  return {
    registerEvmWallet: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const context = deps.getContext();
      const registerWalletArgs = buildEvmWalletRegistrationArgs(context, args);
      if (!walletIframe.shouldUseWalletIframe()) {
        return await evmSigner.registerEvmWallet(args);
      }
      try {
        const router = await walletIframe.requireRouter();
        const result = await router.registerWallet(registerWalletArgs);
        await args.options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    bootstrapEcdsaSession: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const context = deps.getContext();
      const bootstrapArgs = buildEvmBootstrapArgs(context, args);
      if (!walletIframe.shouldUseWalletIframe()) {
        return await evmSigner.bootstrapEcdsaSession(bootstrapArgs);
      }
      const router = await walletIframe.requireRouter(toWalletId(args.walletSession.walletId));
      return await router.bootstrapEcdsaSession(bootstrapArgs);
    },
  };
}
