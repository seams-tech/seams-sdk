import type { ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import { exactEcdsaSigningLaneIdentityFromSelectedLane } from '../../session/identity/exactSigningLaneIdentity';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

type EvmFamilyEcdsaPostSignPolicyRunner = {
  applyEcdsaPostSignPolicy: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
    selectedRecord: ThresholdEcdsaSessionRecord;
  }) => Promise<void> | void;
};

export async function applySuccessfulEvmFamilyEcdsaPostSignPolicy(args: {
  postSignPolicy: EvmFamilyEcdsaPostSignPolicyRunner;
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane;
  selectedRecord: ThresholdEcdsaSessionRecord;
}): Promise<void> {
  // Post-sign cleanup is security-sensitive: it must operate on the exact
  // lane used after any OTP/passkey reauth, not a generic threshold-session id.
  await args.postSignPolicy.applyEcdsaPostSignPolicy({
    lane: exactEcdsaSigningLaneIdentityFromSelectedLane(args.ecdsaSigningLane),
    selectedRecord: args.selectedRecord,
  });
}
