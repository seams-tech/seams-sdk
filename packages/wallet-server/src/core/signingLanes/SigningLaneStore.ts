import type {
  SigningLaneId,
  SigningLaneRecord,
  WalletKeyId,
} from '@shared/signing-lanes';
import type { WalletId } from '@shared/utils/domainIds';

export type SigningLaneLookup = {
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
};

export interface SigningLaneStore {
  getSigningLane(lookup: SigningLaneLookup): Promise<SigningLaneRecord | null>;
  listSigningLanes(args: {
    walletId: WalletId;
    walletKeyId: WalletKeyId;
  }): Promise<readonly SigningLaneRecord[]>;
}
