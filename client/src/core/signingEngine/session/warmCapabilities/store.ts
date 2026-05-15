import type { AccountId } from '@/core/types/accountIds';
import {
  getStoredThresholdEcdsaSessionRecordForWalletChain,
  listStoredThresholdEcdsaSessionRecordsForWallet,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEd25519SessionRecord,
} from '../persistence/records';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type WarmSessionStoredCapabilityRecords = {
  ed25519: ThresholdEd25519SessionRecord | null;
  ecdsa: {
    evm: ThresholdEcdsaSessionRecord | null;
    tempo: ThresholdEcdsaSessionRecord | null;
  };
};

export function readWarmSessionCapabilityRecordsForWallet(
  walletId: AccountId | string,
): WarmSessionStoredCapabilityRecords {
  return {
    ed25519: getStoredThresholdEd25519SessionRecordForAccount(walletId),
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
  walletId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
}): ThresholdEcdsaSessionRecord[] {
  return listStoredThresholdEcdsaSessionRecordsForWallet(args.walletId, {
    chainTarget: args.chainTarget,
  });
}
