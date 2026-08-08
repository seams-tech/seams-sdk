import { chainFamilyFromNetwork } from '@/core/config/chains';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  thresholdEcdsaChainTargetFromConfig,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export function configuredEmailOtpEcdsaSnapshotChainTargets(
  configs: SeamsConfigsReadonly,
): ThresholdEcdsaChainTarget[] {
  const targets: ThresholdEcdsaChainTarget[] = [];
  const seen = new Set<string>();
  for (const chain of configs.network.chains) {
    const family = chainFamilyFromNetwork(chain.network);
    if (family !== 'evm' && family !== 'tempo') continue;
    const chainTarget = thresholdEcdsaChainTargetFromConfig(chain);
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    if (seen.has(targetKey)) continue;
    seen.add(targetKey);
    targets.push(chainTarget);
  }
  if (!targets.length) {
    throw new Error('[EmailOtpSession] exact ECDSA snapshot requires configured ECDSA targets');
  }
  return targets;
}
