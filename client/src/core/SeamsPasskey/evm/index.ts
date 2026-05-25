import { toAccountId } from '../../types/accountIds';
import type { EvmSignerCapability, RegistrationCapability } from '..';
import { routeWalletIframeOrLocal, type WalletIframeRouteDeps } from '../walletIframeRoute';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { registerWallet as registerWalletWithUnifiedCeremony } from '../registration';
import { cloneAuthenticatorOptions } from '../../types/authenticatorOptions';
import { toError } from '@shared/utils/errors';

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

  async registerEvmWallet(args: Parameters<EvmSignerCapability['registerEvmWallet']>[0]) {
    const context = this.getContext();
    const rpId = context.signingEngine.getRpId();
    if (!rpId) {
      throw new Error('[SeamsPasskey][evm] registerEvmWallet requires rpId');
    }
    if (!args.chainTargets.length) {
      throw new Error('[SeamsPasskey][evm] registerEvmWallet requires at least one chain target');
    }
    if (!args.participantIds.length) {
      throw new Error('[SeamsPasskey][evm] registerEvmWallet requires participant ids');
    }
    const registerWalletArgs = {
      walletSubject: { kind: 'server_generated' },
      rpId,
      signerSelection: {
        mode: 'ecdsa_only',
        ecdsa: {
          chainTargets: [...args.chainTargets],
          participantIds: [...args.participantIds],
        },
      },
      options: args.options || {},
    } satisfies Parameters<RegistrationCapability['registerWallet']>[0];

    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      remote: async (router) => {
        const result = await router.registerWallet(registerWalletArgs);
        await args.options?.afterCall?.(true, result);
        return result;
      },
      onRemoteError: async (error) => {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      },
      local: async () =>
        await registerWalletWithUnifiedCeremony({
          context,
          ...registerWalletArgs,
          authenticatorOptions: cloneAuthenticatorOptions(
            context.configs.webauthn.authenticatorOptions,
          ),
        }),
    });
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
