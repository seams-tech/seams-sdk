import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  readSelectedEcdsaRecordForLane,
  type EvmFamilyEcdsaSessionReaderDeps,
} from './ecdsaLanes';
import type { SigningLaneContext } from '../../session/signingSession/types';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../thresholdLifecycle/thresholdSessionStore';
import type {
  EvmFamilyChain,
  EvmFamilySenderSignatureAlgorithm,
} from './types';

type EvmFamilyEcdsaPostSignPolicyRunner = {
  applyEcdsaPostSignPolicy: (args: {
    nearAccountId: string;
    chain: EvmFamilyChain;
    thresholdSessionId?: string;
    source: ThresholdEcdsaSessionStoreSource;
  }) => Promise<void> | void;
};

function resolveCurrentEcdsaThresholdSessionId(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  ecdsaSigningLane: SigningLaneContext;
  thresholdEcdsaRecord?: ThresholdEcdsaSessionRecord;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): string | undefined {
  const selectedSessionId = String(
    args.ecdsaSigningLane.thresholdSessionId ||
      args.thresholdEcdsaRecord?.thresholdSessionId ||
      args.thresholdEcdsaKeyRef?.thresholdSessionId ||
      '',
  ).trim();
  if (selectedSessionId) return selectedSessionId;
  try {
    const currentRecord = readSelectedEcdsaRecordForLane({
      deps: args.deps,
      lane: args.ecdsaSigningLane,
    });
    const recordSessionId = String(currentRecord?.thresholdSessionId || '').trim();
    if (recordSessionId) return recordSessionId;
  } catch {}
  return String(args.thresholdEcdsaKeyRef?.thresholdSessionId || '').trim() || undefined;
}

export async function applySuccessfulEvmFamilyEcdsaPostSignPolicy(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  postSignPolicy: EvmFamilyEcdsaPostSignPolicyRunner;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  nearAccountId: string;
  chain: EvmFamilyChain;
  ecdsaSigningLane?: SigningLaneContext;
  selectedEcdsaSource?: ThresholdEcdsaSessionStoreSource;
  thresholdEcdsaRecord?: ThresholdEcdsaSessionRecord;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): Promise<void> {
  if (args.senderSignatureAlgorithm !== 'secp256k1') return;
  if (!args.ecdsaSigningLane) {
    throw new Error('[SigningEngine] ECDSA signing lane is required for post-sign cleanup');
  }
  if (!args.selectedEcdsaSource) {
    throw new Error('[SigningEngine] ECDSA signing source is required for post-sign cleanup');
  }
  const selectedEcdsaSource = args.selectedEcdsaSource;
  await args.postSignPolicy.applyEcdsaPostSignPolicy({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    thresholdSessionId: resolveCurrentEcdsaThresholdSessionId({
      deps: args.deps,
      ecdsaSigningLane: args.ecdsaSigningLane,
      ...(args.thresholdEcdsaRecord ? { thresholdEcdsaRecord: args.thresholdEcdsaRecord } : {}),
      ...(args.thresholdEcdsaKeyRef ? { thresholdEcdsaKeyRef: args.thresholdEcdsaKeyRef } : {}),
    }),
    source: selectedEcdsaSource,
  });
}
