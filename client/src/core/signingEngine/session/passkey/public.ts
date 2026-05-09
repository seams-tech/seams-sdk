import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { ProvisionWarmEd25519CapabilityArgs } from '../warmCapabilities/types';
import type { ProvisionWarmEd25519CapabilityResult } from '../warmCapabilities/types';
import type { WarmSessionEnvelope } from '../warmCapabilities/types';
import { provisionWarmEd25519Capability } from './ed25519Provisioner';
import type { BootstrapEcdsaSessionArgs } from './ecdsaBootstrap';

export type PasskeyPublicDeps = {
  getWarmSession: (
    nearAccountId: ProvisionWarmEd25519CapabilityArgs['nearAccountId'],
  ) => Promise<WarmSessionEnvelope>;
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  bootstrapEcdsaSession: (
    args: BootstrapEcdsaSessionArgs,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
};

export async function connectEd25519Session(
  deps: PasskeyPublicDeps,
  args: Omit<ProvisionWarmEd25519CapabilityArgs, 'beforeProvision' | 'assertNotCancelled'>,
): Promise<ProvisionWarmEd25519CapabilityResult> {
  return await provisionWarmEd25519Capability(
    {
      getWarmSession: (nearAccountId) => deps.getWarmSession(nearAccountId),
      provisionThresholdEd25519Session: async (provisionArgs) =>
        await deps.provisionThresholdEd25519Session(provisionArgs),
    },
    args,
  );
}

export async function bootstrapEcdsaSession(
  deps: PasskeyPublicDeps,
  args: BootstrapEcdsaSessionArgs,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await deps.bootstrapEcdsaSession(args);
}

export function createPasskeyPublicApi(deps: PasskeyPublicDeps) {
  return {
    connectEd25519Session: (
      args: Omit<ProvisionWarmEd25519CapabilityArgs, 'beforeProvision' | 'assertNotCancelled'>,
    ) => connectEd25519Session(deps, args),
    bootstrapEcdsaSession: (args: BootstrapEcdsaSessionArgs) => bootstrapEcdsaSession(deps, args),
  };
}

export type PasskeyPublicApi = ReturnType<typeof createPasskeyPublicApi>;
