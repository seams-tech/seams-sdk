import type { ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

type EvmFamilyEcdsaPostSignPolicyRunner = {
  applyEcdsaPostSignPolicy: (args: {
    nearAccountId: string;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: string;
    source: ThresholdEcdsaSessionStoreSource;
    selectedRecord: ThresholdEcdsaSessionRecord;
  }) => Promise<void> | void;
};

export async function applySuccessfulEvmFamilyEcdsaPostSignPolicy(args: {
  postSignPolicy: EvmFamilyEcdsaPostSignPolicyRunner;
  nearAccountId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane;
  selectedEcdsaSource: ThresholdEcdsaSessionStoreSource;
  selectedRecord: ThresholdEcdsaSessionRecord;
}): Promise<void> {
  // Post-sign cleanup is security-sensitive: it must operate on the exact
  // lane used after any OTP/passkey reauth, not a generic threshold-session id.
  await args.postSignPolicy.applyEcdsaPostSignPolicy({
    nearAccountId: args.nearAccountId,
    chainTarget: args.chainTarget,
    thresholdSessionId: String(args.ecdsaSigningLane.thresholdSessionId),
    source: args.selectedEcdsaSource,
    selectedRecord: args.selectedRecord,
  });
}
