import { toAccountId } from '@/core/types/accountIds';
import type { EvmSignerCapability, RegistrationCapability } from '..';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import { registerWallet as registerWalletWithUnifiedCeremony } from '../registration';
import { cloneAuthenticatorOptions } from '@/core/types/authenticatorOptions';

type ChainSignerDeps = {
  getContext: () => import('../index').SeamsWebContext;
};

type EvmWalletRegistrationArgs = Parameters<RegistrationCapability['registerWallet']>[0] & {
  options: NonNullable<Parameters<RegistrationCapability['registerWallet']>[0]['options']>;
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

export function buildEvmWalletRegistrationArgs(
  context: import('../index').SeamsWebContext,
  args: Parameters<EvmSignerCapability['registerEvmWallet']>[0],
): EvmWalletRegistrationArgs {
  const rpId = context.signingEngine.getRpId();
  if (!rpId) {
    throw new Error('[SeamsWeb][evm] registerEvmWallet requires rpId');
  }
  if (!args.chainTargets.length) {
    throw new Error('[SeamsWeb][evm] registerEvmWallet requires at least one chain target');
  }
  if (!args.participantIds.length) {
    throw new Error('[SeamsWeb][evm] registerEvmWallet requires participant ids');
  }
  const authMethod = args.authMethod || { kind: 'passkey' as const };
  return {
    wallet: { kind: 'server_generated' },
    rpId,
    authMethod,
    signerSelection: {
      mode: 'ecdsa_only',
      ecdsa: {
        chainTargets: [...args.chainTargets],
        participantIds: [...args.participantIds],
      },
    },
    options: args.options || {},
  };
}

export function buildEvmBootstrapArgs(
  context: import('../index').SeamsWebContext,
  args: Parameters<EvmSignerCapability['bootstrapEcdsaSession']>[0],
): Parameters<EvmSignerCapability['bootstrapEcdsaSession']>[0] {
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
    throw new Error('[SeamsWeb][evm] bootstrapEcdsaSession requires an EVM chainTarget');
  }
  return {
    ...args,
    ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
  };
}

/**
 * EVM signer currently exposes threshold-ECDSA bootstrap only.
 */
export class EvmSigner implements EvmSignerCapability {
  private readonly getContext: ChainSignerDeps['getContext'];

  constructor(deps: ChainSignerDeps) {
    this.getContext = deps.getContext;
  }

  async registerEvmWallet(args: Parameters<EvmSignerCapability['registerEvmWallet']>[0]) {
    const context = this.getContext();
    const registerWalletArgs = buildEvmWalletRegistrationArgs(context, args);
    return await registerWalletWithUnifiedCeremony({
      context,
      ...registerWalletArgs,
      authenticatorOptions: cloneAuthenticatorOptions(
        context.configs.webauthn.authenticatorOptions,
      ),
    });
  }

  async bootstrapEcdsaSession(args: Parameters<EvmSignerCapability['bootstrapEcdsaSession']>[0]) {
    const context = this.getContext();
    const bootstrapArgs = buildEvmBootstrapArgs(context, args);
    return await context.signingEngine.bootstrapEcdsaSession(toLocalBootstrapRequest(bootstrapArgs));
  }
}
