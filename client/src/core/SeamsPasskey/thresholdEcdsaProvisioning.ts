import type { ThresholdEcdsaActivationChain } from '../signingEngine/SigningEngine';
import type {
  EcdsaSignerProvisioningDefaults,
  EcdsaSignerProvisioningPolicy,
} from '../types/ecdsaSignerProvisioningDefaults';

export type ThresholdEcdsaProvisionTarget = {
  chain: ThresholdEcdsaActivationChain;
  options: EcdsaSignerProvisioningPolicy;
};

export function listThresholdEcdsaProvisionTargets(
  signerOptions: EcdsaSignerProvisioningDefaults,
): ThresholdEcdsaProvisionTarget[] {
  const targets: ThresholdEcdsaProvisionTarget[] = [];
  if (signerOptions.tempo.enabled) {
    targets.push({ chain: 'tempo', options: signerOptions.tempo });
  }
  if (signerOptions.evm.enabled) {
    targets.push({ chain: 'evm', options: signerOptions.evm });
  }
  return targets;
}

export function toSmartAccountBootstrapInput(
  chain: ThresholdEcdsaActivationChain,
  smartAccount: EcdsaSignerProvisioningPolicy['smartAccount'] | undefined,
):
  | {
      chainId: number;
      factory?: string;
      entryPoint?: string;
      salt?: string;
      counterfactualAddress?: string;
    }
  | undefined {
  void chain;
  if (!smartAccount) return undefined;
  return { ...smartAccount };
}

export function toRegistrationSmartAccountTarget(
  chain: ThresholdEcdsaActivationChain,
  smartAccount: EcdsaSignerProvisioningPolicy['smartAccount'] | undefined,
):
  | {
      chain: ThresholdEcdsaActivationChain;
      chain_id: number;
      factory?: string;
      entry_point?: string;
      salt?: string;
      counterfactual_address?: string;
    }
  | undefined {
  if (!smartAccount) return undefined;
  return {
    chain,
    chain_id: smartAccount.chainId,
    ...(smartAccount.factory ? { factory: smartAccount.factory } : {}),
    ...(smartAccount.entryPoint ? { entry_point: smartAccount.entryPoint } : {}),
    ...(smartAccount.salt ? { salt: smartAccount.salt } : {}),
    ...(smartAccount.counterfactualAddress
      ? { counterfactual_address: smartAccount.counterfactualAddress }
      : {}),
  };
}
