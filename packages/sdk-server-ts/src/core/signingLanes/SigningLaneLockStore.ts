import type { SigningLaneId, WalletKeyId } from '@shared/signing-lanes';

export type SigningLaneLock = {
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  lockId: string;
  expiresAtMs: number;
};

export interface SigningLaneLockStore {
  acquireLaneLock(args: {
    walletKeyId: WalletKeyId;
    laneId: SigningLaneId;
    ttlMs: number;
  }): Promise<SigningLaneLock>;
  releaseLaneLock(lock: SigningLaneLock): Promise<void>;
}
