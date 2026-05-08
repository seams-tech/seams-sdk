import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  buildEvmFamilyEcdsaSigningLaneContext,
  readSelectedEcdsaRecordForLane,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type { EvmFamilyEcdsaSessionReaderDeps } from '../../interfaces/operationDeps';
import type { EvmFamilyChain } from './types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';

export type EvmFamilyEmailOtpSigningRefreshDeps = EvmFamilyEcdsaSessionReaderDeps;

export type EvmFamilyEmailOtpSigningCompleter = {
  complete: (otpCode: string, challengeId?: string) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
};

export type EvmFamilyEmailOtpSigningRefreshResult = {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  record?: ThresholdEcdsaSessionRecord;
  lane?: ResolvedEvmFamilyEcdsaSigningLane;
};

export async function completeEvmFamilyEmailOtpSigningRefresh(args: {
  deps: EvmFamilyEmailOtpSigningRefreshDeps;
  nearAccountId: string;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  emailOtpSigning: EvmFamilyEmailOtpSigningCompleter;
  otpCode: string;
  challengeId?: string;
}): Promise<EvmFamilyEmailOtpSigningRefreshResult> {
  const keyRef = await args.emailOtpSigning.complete(args.otpCode, args.challengeId);
  const completedLane = buildEvmFamilyEcdsaSigningLaneContext({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    chainTarget: args.chainTarget,
    authMethod: SIGNER_AUTH_METHODS.emailOtp,
    source: SIGNER_AUTH_METHODS.emailOtp,
    material: 'key_ref',
    keyRef,
  });
  try {
    const record = readSelectedEcdsaRecordForLane({
      deps: args.deps,
      lane: completedLane,
    });
    if (!record) return { keyRef, ...(completedLane ? { lane: completedLane } : {}) };
    const lane = buildEvmFamilyEcdsaSigningLaneContext({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      chainTarget: args.chainTarget,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      source: SIGNER_AUTH_METHODS.emailOtp,
      material: 'record_and_key_ref',
      record,
      keyRef,
    });
    return {
      keyRef,
      record,
      ...(lane ? { lane } : {}),
    };
  } catch {
    return { keyRef, ...(completedLane ? { lane: completedLane } : {}) };
  }
}
