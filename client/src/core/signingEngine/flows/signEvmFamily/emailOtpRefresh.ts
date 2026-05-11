import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EmailOtpEcdsaSigningBootstrapResult } from '../../interfaces/operationDeps';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  buildEcdsaSessionIdentity,
  ecdsaSessionIdentitiesEqual,
  type EmailOtpEcdsaSessionProvision,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import {
  buildEvmFamilyEcdsaSigningLaneContext,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type { EvmFamilyChain } from './types';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { EvmFamilyEcdsaEmailOtpStepUpAuthorization } from './stepUpAuthorization';
import { buildEvmFamilyEmailOtpEcdsaProvisionPlan } from './provisionPlan';

export type EvmFamilyEmailOtpSigningCompleter = {
  complete: (otpCode: string, challengeId?: string) => Promise<EmailOtpEcdsaSigningBootstrapResult>;
};

export type EvmFamilyEmailOtpSigningRefreshResult = {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  record: ThresholdEcdsaSessionRecord;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  provisionPlan: EmailOtpEcdsaSessionProvision;
};

export async function completeEvmFamilyEmailOtpSigningRefresh(args: {
  nearAccountId: string;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  emailOtpSigning: EvmFamilyEmailOtpSigningCompleter;
  authorization: EvmFamilyEcdsaEmailOtpStepUpAuthorization;
}): Promise<EvmFamilyEmailOtpSigningRefreshResult> {
  const completed = await args.emailOtpSigning.complete(
    args.authorization.otpCode,
    args.authorization.challengeId,
  );
  const keyRef = completed.bootstrap.thresholdEcdsaKeyRef;
  const record = completed.warmCapability.record;
  if (!record) {
    throw new Error('[SigningEngine][ecdsa] Email OTP refresh did not persist the ECDSA record');
  }
  if (record.source !== 'email_otp' || !record.emailOtpAuthContext) {
    throw new Error(
      '[SigningEngine][ecdsa] Email OTP refresh did not return email OTP-authenticated ECDSA state',
    );
  }
  if (
    !thresholdEcdsaChainTargetsEqual(record.chainTarget, args.chainTarget) ||
    !thresholdEcdsaChainTargetsEqual(keyRef.chainTarget, args.chainTarget)
  ) {
    throw new Error('[SigningEngine][ecdsa] Email OTP refresh returned the wrong ECDSA chain target');
  }
  const recordIdentity = buildEcdsaSessionIdentity(record);
  const keyRefIdentity = buildEcdsaSessionIdentity(keyRef);
  if (!ecdsaSessionIdentitiesEqual(recordIdentity, keyRefIdentity)) {
    throw new Error('[SigningEngine][ecdsa] Email OTP refresh returned mismatched ECDSA identity');
  }
  const provisionPlan = buildEvmFamilyEmailOtpEcdsaProvisionPlan({
    authorization: args.authorization,
    keyRef,
    record,
    chainTarget: args.chainTarget,
    clientRootShare32B64u: completed.clientRootShare32B64u,
    sessionBudgetUses: 1,
  });
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
  if (!lane) {
    throw new Error('[SigningEngine][ecdsa] Email OTP refresh did not return exact ECDSA lane');
  }
  return { keyRef, record, lane, provisionPlan };
}
