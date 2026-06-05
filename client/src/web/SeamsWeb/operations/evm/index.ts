import type { EvmSignerCapability, RegistrationCapability } from '@/web/SeamsWeb/signingSurface/types';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { RegistrationSigningSurface } from '@/web/SeamsWeb/signingSurface/types';

type EvmWalletRegistrationArgs = Parameters<RegistrationCapability['registerWallet']>[0] & {
  options: NonNullable<Parameters<RegistrationCapability['registerWallet']>[0]['options']>;
};

export function buildEvmWalletRegistrationArgs(
  deps: {
    signingEngine: Pick<RegistrationSigningSurface, 'getRpId'>;
  },
  args: Parameters<EvmSignerCapability['registerEvmWallet']>[0],
): EvmWalletRegistrationArgs {
  const rpId = deps.signingEngine.getRpId();
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
  configs: SeamsConfigsReadonly,
  args: Parameters<EvmSignerCapability['bootstrapEcdsaSession']>[0],
): Parameters<EvmSignerCapability['bootstrapEcdsaSession']>[0] {
  const managedRegistration = configs.registration.mode === 'managed' ? configs.registration : null;
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
