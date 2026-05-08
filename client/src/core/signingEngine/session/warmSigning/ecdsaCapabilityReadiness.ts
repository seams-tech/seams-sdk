import type { AccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionEcdsaCapabilityState, WarmSessionEnvelope } from './types';

export type EcdsaWarmCapabilityReader = {
  getWarmSession: (nearAccountId: AccountId | string) => Promise<WarmSessionEnvelope>;
};

export async function assertWarmThresholdEcdsaCapabilityReady(
  reader: EcdsaWarmCapabilityReader,
  args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
  },
): Promise<WarmSessionEcdsaCapabilityState> {
  const warmSession = await reader.getWarmSession(args.nearAccountId);
  const capability = warmSession.capabilities.ecdsa[args.chainTarget.kind];
  if (capability.state !== 'ready') {
    throw new Error(
      `[SigningEngine] Email OTP bootstrap did not reach warm-session ready state for ${String(
        args.nearAccountId,
      )} (${thresholdEcdsaChainTargetKey(args.chainTarget)}, state=${capability.state})`,
    );
  }
  return capability;
}
