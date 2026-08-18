import type { EvmSignerCapability, RegistrationCapability } from '@/SeamsWeb/signingSurface/types';
import type { SeamsConfigsReadonly } from '@/core/types/seams';

type EvmWalletRegistrationArgs = Parameters<RegistrationCapability['registerWallet']>[0] & {
  options: NonNullable<Parameters<RegistrationCapability['registerWallet']>[0]['options']>;
};

export function buildEvmWalletRegistrationArgs(
  args: Parameters<EvmSignerCapability['registerEvmWallet']>[0],
): EvmWalletRegistrationArgs {
  if (!args.chainTargets.length) {
    throw new Error('[SeamsWeb][evm] registerEvmWallet requires at least one chain target');
  }
  if (!args.participantIds.length) {
    throw new Error('[SeamsWeb][evm] registerEvmWallet requires participant ids');
  }
  if (!args.authMethod) {
    throw new Error('[SeamsWeb][evm] registerEvmWallet requires an explicit authMethod');
  }
  return {
    wallet: { kind: 'server_allocated' },
    authMethod: args.authMethod,
    signerSelection: {
      kind: 'signer_set',
      signers: [
        {
          kind: 'evm_family_ecdsa',
          chainTargets: [...args.chainTargets],
          participantIds: [...args.participantIds],
        },
      ],
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
          projectEnvironmentId: managedRegistration.projectEnvironmentId,
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
