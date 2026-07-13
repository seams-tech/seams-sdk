import {
  getStoredThresholdEcdsaSessionRecordForWalletChain,
  listStoredThresholdEcdsaSessionRecordsForWallet,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
  getStoredThresholdEd25519SessionRecordForWallet,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEd25519SessionRecord,
} from '../persistence/records';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AccountId } from '@/core/types/accountIds';

export type WarmSessionStoredCapabilityRecords = {
  ed25519: ThresholdEd25519SessionRecord | null;
  ecdsa: {
    evm: ThresholdEcdsaSessionRecord | null;
    tempo: ThresholdEcdsaSessionRecord | null;
  };
};

export function readWarmSessionCapabilityRecordsForWallet(
  walletId: WalletId,
): WarmSessionStoredCapabilityRecords {
  return {
    ed25519: getStoredThresholdEd25519SessionRecordForWallet(walletId),
    ecdsa: {
      evm: getStoredThresholdEcdsaSessionRecordForWalletChain({
        walletId,
        chain: 'evm',
      }),
      tempo: getStoredThresholdEcdsaSessionRecordForWalletChain({
        walletId,
        chain: 'tempo',
      }),
    },
  };
}

export function readWarmSessionEd25519RecordByThresholdSessionId(
  thresholdSessionId: string,
): ThresholdEd25519SessionRecord | null {
  return getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
}

export function readWarmSessionEd25519RecordForAccount(
  nearAccountId: AccountId | string,
): ThresholdEd25519SessionRecord | null {
  return getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
}

export function readWarmSessionEcdsaRecordByThresholdSessionId(
  thresholdSessionId: string,
): ThresholdEcdsaSessionRecord | null {
  return getStoredThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
}

export function readWarmSessionEcdsaRecordByThresholdSessionIdForTarget(args: {
  thresholdSessionId: string;
  chainTarget: ThresholdEcdsaChainTarget;
}): ThresholdEcdsaSessionRecord | null {
  return getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget(args);
}

export function listWarmSessionEcdsaRecordsForWalletTarget(args: {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
}): ThresholdEcdsaSessionRecord[] {
  return listStoredThresholdEcdsaSessionRecordsForWallet(args.walletId, {
    chainTarget: args.chainTarget,
  });
}
