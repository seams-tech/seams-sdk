import type { AccountId } from '@/core/types/accountIds';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
  listStoredThresholdEcdsaSessionRecordsForAccount,
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

export function readWarmSessionCapabilityRecordsForAccount(
  nearAccountId: AccountId | string,
): WarmSessionStoredCapabilityRecords {
  const ecdsaRecords = listStoredThresholdEcdsaSessionRecordsForAccount(nearAccountId);
  const readEcdsa = (kind: 'evm' | 'tempo'): ThresholdEcdsaSessionRecord | null =>
    ecdsaRecords.find((record) => record.chainTarget.kind === kind) || null;

  return {
    ed25519: getStoredThresholdEd25519SessionRecordForAccount(nearAccountId),
    ecdsa: {
      evm: readEcdsa('evm'),
      tempo: readEcdsa('tempo'),
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
