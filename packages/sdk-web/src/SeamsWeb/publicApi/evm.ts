import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toError } from '@shared/utils/errors';
import type {
  EcdsaSessionBootstrapSurface,
  EvmSignerCapability,
  RegistrationSigningSurface,
  RegistrationWebContext,
} from '@/SeamsWeb/signingSurface/types';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { SeamsConfigsReadonly, ThemeMode } from '@/core/types/seams';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import { cloneAuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { registerWallet as registerWalletWithUnifiedCeremony } from '@/SeamsWeb/operations/registration/registration';
import { buildEvmBootstrapArgs, buildEvmWalletRegistrationArgs } from '@/SeamsWeb/operations/evm';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';

function toLocalEvmBootstrapRequest(
  args: Parameters<EvmSignerCapability['bootstrapEcdsaSession']>[0],
): EcdsaBootstrapRequest {
  return {
    kind: 'reuse_warm_ecdsa_bootstrap',
    walletId: toWalletId(args.walletSession.walletId),
    chainTarget: args.chainTarget,
    source: args.source,
    relayerUrl: args.relayerUrl,
    runtimeScopeBootstrap: args.runtimeScopeBootstrap,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  };
}

export function createEvmSignerCapability(deps: {
  signingEngine: RegistrationSigningSurface & EcdsaSessionBootstrapSurface;
  nearClient: NearClient;
  configs: SeamsConfigsReadonly;
  getTheme: () => ThemeMode;
  getWalletIframe: () => WalletIframeCoordinator;
}): EvmSignerCapability {
  return {
    registerEvmWallet: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const registerWalletArgs = buildEvmWalletRegistrationArgs(
        { signingEngine: deps.signingEngine },
        args,
      );
      if (!walletIframe.shouldUseWalletIframe()) {
        const context: RegistrationWebContext = {
          signingEngine: deps.signingEngine,
          nearClient: deps.nearClient,
          configs: deps.configs,
          theme: deps.getTheme(),
        };
        return await registerWalletWithUnifiedCeremony({
          context,
          ...registerWalletArgs,
          authenticatorOptions: cloneAuthenticatorOptions(
            deps.configs.webauthn.authenticatorOptions,
          ),
        });
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
      const bootstrapArgs = buildEvmBootstrapArgs(deps.configs, args);
      if (!walletIframe.shouldUseWalletIframe()) {
        return await deps.signingEngine.bootstrapEcdsaSession(
          toLocalEvmBootstrapRequest(bootstrapArgs),
        );
      }
      const router = await walletIframe.requireRouter(toWalletId(args.walletSession.walletId));
      return await router.bootstrapEcdsaSession(bootstrapArgs);
    },
  };
}
