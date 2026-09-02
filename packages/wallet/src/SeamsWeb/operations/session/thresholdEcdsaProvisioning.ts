import { chainFamilyFromNetwork } from '@/core/config/chains';
import type { SeamsChainConfig } from '@/core/types/seams';
import {
  thresholdEcdsaChainTargetFromConfig,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaSignerProvisioningDefaults,
  EcdsaSignerProvisioningPolicy,
} from '@/core/types/ecdsaSignerProvisioningDefaults';

export type ThresholdEcdsaProvisionTarget = {
  chainTarget: ThresholdEcdsaChainTarget;
  options: EcdsaSignerProvisioningPolicy;
};

export type EcdsaSessionPublicationTarget = {
  chainTarget: ThresholdEcdsaChainTarget;
};

export function listConfiguredThresholdEcdsaPublicationTargets(
  chains: readonly SeamsChainConfig[],
): EcdsaSessionPublicationTarget[] {
  const targets: EcdsaSessionPublicationTarget[] = [];
  const seen = new Set<string>();
  for (const chainConfig of chains) {
    const family = chainFamilyFromNetwork(chainConfig.network);
    if (family !== 'evm' && family !== 'tempo') continue;
    const chainTarget = thresholdEcdsaChainTargetFromConfig(chainConfig);
    const key = thresholdEcdsaChainTargetKey(chainTarget);
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push({
      chainTarget,
    });
  }
  return targets;
}

export function listThresholdEcdsaProvisionTargets(args: {
  signerOptions: EcdsaSignerProvisioningDefaults;
  chains: readonly SeamsChainConfig[];
}): ThresholdEcdsaProvisionTarget[] {
  const targets: ThresholdEcdsaProvisionTarget[] = [];
  const seen = new Set<string>();
  for (const chainConfig of args.chains) {
    const family = chainFamilyFromNetwork(chainConfig.network);
    if (family !== 'evm' && family !== 'tempo') continue;
    const options = family === 'tempo' ? args.signerOptions.tempo : args.signerOptions.evm;
    if (!options.enabled) continue;
    const chainTarget = thresholdEcdsaChainTargetFromConfig(chainConfig);
    const key = thresholdEcdsaChainTargetKey(chainTarget);
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push({ chainTarget, options });
  }
  return targets;
}
