import {
  getStoredThresholdEd25519SessionRecordForAccount,
  getStoredThresholdEd25519SessionRecordForWallet,
  type ThresholdEd25519SessionRecord,
} from '../persistence/records';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AccountId } from '@/core/types/accountIds';

export type WarmSessionStoredCapabilityRecords = {
  ed25519: ThresholdEd25519SessionRecord | null;
};

export function readWarmSessionCapabilityRecordsForWallet(
  walletId: WalletId,
): WarmSessionStoredCapabilityRecords {
  return {
    ed25519: getStoredThresholdEd25519SessionRecordForWallet(walletId),
  };
}

export function readWarmSessionEd25519RecordForAccount(
  nearAccountId: AccountId | string,
): ThresholdEd25519SessionRecord | null {
  return getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
}
