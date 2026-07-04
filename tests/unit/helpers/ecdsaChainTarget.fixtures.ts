import type { ThresholdEcdsaActivationChain } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export function testEcdsaChainId(chain: ThresholdEcdsaActivationChain): number {
  return chain === 'tempo' ? 42431 : 11155111;
}

export function testEcdsaChainTarget(
  chain: ThresholdEcdsaActivationChain,
): ThresholdEcdsaChainTarget {
  return thresholdEcdsaChainTargetFromChainFamily({
    chain,
    chainId: testEcdsaChainId(chain),
  });
}
