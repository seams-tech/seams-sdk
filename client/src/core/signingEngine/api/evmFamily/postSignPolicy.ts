import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  logEvmFamilyEcdsaLaneDiagnostic,
  readSelectedEcdsaRecordForLane,
  summarizeEvmFamilyEcdsaKeyRef,
  summarizeEvmFamilyEcdsaSessionRecord,
  type EvmFamilyEcdsaSessionReaderDeps,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../thresholdLifecycle/thresholdSessionStore';
import type { EvmFamilyChain, EvmFamilySenderSignatureAlgorithm } from './types';

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
  ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane;
  thresholdEcdsaRecord?: ThresholdEcdsaSessionRecord;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): string | undefined {
  const selectedSessionId = String(
    args.thresholdEcdsaKeyRef?.thresholdSessionId ||
      args.thresholdEcdsaRecord?.thresholdSessionId ||
      args.ecdsaSigningLane.thresholdSessionId ||
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
  ecdsaSigningLane?: ResolvedEvmFamilyEcdsaSigningLane;
  selectedEcdsaSource?: ThresholdEcdsaSessionStoreSource;
  thresholdEcdsaRecord?: ThresholdEcdsaSessionRecord;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): Promise<void> {
  if (args.senderSignatureAlgorithm !== 'secp256k1') return;
  if (!args.selectedEcdsaSource) {
    throw new Error('[SigningEngine] ECDSA signing source is required for post-sign cleanup');
  }
  // Post-sign cleanup is security-sensitive: it must operate on the exact
  // lane used after any OTP/passkey reauth, not a generic threshold-session id.
  const resolvedLane = args.ecdsaSigningLane;
  if (!resolvedLane) {
    logEvmFamilyEcdsaLaneDiagnostic('missing resolved signing lane for post-sign cleanup', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      selectedEcdsaSource: args.selectedEcdsaSource,
      thresholdEcdsaRecord: summarizeEvmFamilyEcdsaSessionRecord(args.thresholdEcdsaRecord),
      thresholdEcdsaKeyRef: summarizeEvmFamilyEcdsaKeyRef(args.thresholdEcdsaKeyRef),
    });
    throw new Error('[SigningEngine][ecdsa] missing resolved signing lane for post-sign cleanup');
  }
  const selectedEcdsaSource = args.selectedEcdsaSource;
  await args.postSignPolicy.applyEcdsaPostSignPolicy({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    thresholdSessionId: resolveCurrentEcdsaThresholdSessionId({
      deps: args.deps,
      ecdsaSigningLane: resolvedLane,
      ...(args.thresholdEcdsaRecord ? { thresholdEcdsaRecord: args.thresholdEcdsaRecord } : {}),
      ...(args.thresholdEcdsaKeyRef ? { thresholdEcdsaKeyRef: args.thresholdEcdsaKeyRef } : {}),
    }),
    source: selectedEcdsaSource,
  });
}
