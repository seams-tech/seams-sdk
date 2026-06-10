import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type {
  ExactWarmEd25519CapabilityProvisionArgs,
  FreshWarmEd25519CapabilityProvisionArgs,
  ProvisionWarmEd25519CapabilityArgs,
} from '../warmCapabilities/types';
import type { ProvisionWarmEd25519CapabilityResult } from '../warmCapabilities/types';
import type { WarmSessionEnvelope } from '../warmCapabilities/types';
import { provisionWarmEd25519Capability } from './ed25519Provisioner';
import type { EcdsaBootstrapRequest } from './ecdsaBootstrap';

export type PasskeyPublicDeps = {
  getWarmSession: (
    nearAccountId: ProvisionWarmEd25519CapabilityArgs['nearAccountId'],
  ) => Promise<WarmSessionEnvelope>;
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  bootstrapEcdsaSession: (
    args: EcdsaBootstrapRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
};

export type ConnectEd25519SessionArgs =
  | Omit<FreshWarmEd25519CapabilityProvisionArgs, 'beforeProvision' | 'assertNotCancelled'>
  | Omit<ExactWarmEd25519CapabilityProvisionArgs, 'beforeProvision' | 'assertNotCancelled'>;

export async function connectEd25519Session(
  deps: PasskeyPublicDeps,
  args: ConnectEd25519SessionArgs,
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
  args: EcdsaBootstrapRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await deps.bootstrapEcdsaSession(args);
}
