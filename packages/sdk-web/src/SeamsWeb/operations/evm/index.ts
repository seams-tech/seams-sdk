import type { EvmSignerCapability, RegistrationCapability } from '@/SeamsWeb/signingSurface/types';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { RegistrationSigningSurface } from '@/SeamsWeb/signingSurface/types';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';

type EvmWalletRegistrationArgs = Parameters<RegistrationCapability['registerWallet']>[0] & {
  options: NonNullable<Parameters<RegistrationCapability['registerWallet']>[0]['options']>;
};

function requireEvmRegistrationRpId(value: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

export function buildEvmWalletRegistrationArgs(
  deps: {
    signingEngine: Pick<RegistrationSigningSurface, 'getRpId'>;
  },
  args: Parameters<EvmSignerCapability['registerEvmWallet']>[0],
): EvmWalletRegistrationArgs {
  const rpId = requireEvmRegistrationRpId(deps.signingEngine.getRpId());
  if (!rpId) {
    throw new Error('[SeamsWeb][evm] registerEvmWallet requires rpId');
  }
  if (!args.chainTargets.length) {
    throw new Error('[SeamsWeb][evm] registerEvmWallet requires at least one chain target');
  }
  if (!args.participantIds.length) {
    throw new Error('[SeamsWeb][evm] registerEvmWallet requires participant ids');
  }
  const authMethod = args.authMethod || { kind: 'passkey' as const, rpId };
  return {
    wallet: { kind: 'server_allocated' },
    authMethod,
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
