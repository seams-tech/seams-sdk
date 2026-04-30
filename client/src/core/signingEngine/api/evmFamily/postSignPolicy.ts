import type { ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../thresholdLifecycle/thresholdSessionStore';
import type { EvmFamilyChain } from './types';

type EvmFamilyEcdsaPostSignPolicyRunner = {
  applyEcdsaPostSignPolicy: (args: {
    nearAccountId: string;
    chain: EvmFamilyChain;
    thresholdSessionId: string;
    source: ThresholdEcdsaSessionStoreSource;
    selectedRecord?: ThresholdEcdsaSessionRecord;
  }) => Promise<void> | void;
};

export async function applySuccessfulEvmFamilyEcdsaPostSignPolicy(args: {
  postSignPolicy: EvmFamilyEcdsaPostSignPolicyRunner;
  nearAccountId: string;
  chain: EvmFamilyChain;
  ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane;
  selectedEcdsaSource: ThresholdEcdsaSessionStoreSource;
  selectedRecord?: ThresholdEcdsaSessionRecord;
}): Promise<void> {
  // Post-sign cleanup is security-sensitive: it must operate on the exact
  // lane used after any OTP/passkey reauth, not a generic threshold-session id.
  await args.postSignPolicy.applyEcdsaPostSignPolicy({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    thresholdSessionId: String(args.ecdsaSigningLane.thresholdSessionId),
    source: args.selectedEcdsaSource,
    ...(args.selectedRecord ? { selectedRecord: args.selectedRecord } : {}),
  });
}
