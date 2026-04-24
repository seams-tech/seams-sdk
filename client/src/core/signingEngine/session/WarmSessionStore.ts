import type { AccountId } from '@/core/types/accountIds';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
  getStoredThresholdSessionRecordForAccount,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEd25519SessionRecord,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaActivationChain } from '../orchestration/thresholdActivation';

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
  const readEcdsa = (chain: ThresholdEcdsaActivationChain): ThresholdEcdsaSessionRecord | null =>
    getStoredThresholdSessionRecordForAccount({
      curve: 'ecdsa',
      nearAccountId,
      chain,
    });

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
