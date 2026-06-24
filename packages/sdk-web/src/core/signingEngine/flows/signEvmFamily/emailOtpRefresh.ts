import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EmailOtpEcdsaSigningBootstrapResult } from '../../interfaces/operationDeps';
import {
  buildEcdsaSessionIdentity,
  ecdsaSessionIdentitiesEqual,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import {
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  resolveReadyEvmFamilyEcdsaMaterial,
  type ReadyEvmFamilyEcdsaMaterial,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  buildEvmFamilyEcdsaSigningLaneContext,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type { EvmFamilyChain } from './types';
import {
  toWalletId,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { EvmFamilyEcdsaEmailOtpStepUpAuthorization } from './stepUpAuthorization';

export type EvmFamilyEmailOtpSigningCompleter = {
  complete: (otpCode: string, challengeId?: string) => Promise<EmailOtpEcdsaSigningBootstrapResult>;
};

export type EvmFamilyEmailOtpSigningRefreshResult = {
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
  record: ThresholdEcdsaSessionRecord;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
};

export async function completeEvmFamilyEmailOtpSigningRefresh(args: {
  walletSession: WalletSessionRef;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  emailOtpSigning: EvmFamilyEmailOtpSigningCompleter;
  authorization: EvmFamilyEcdsaEmailOtpStepUpAuthorization;
}): Promise<EvmFamilyEmailOtpSigningRefreshResult> {
  const walletId = toWalletId(args.walletSession.walletId);
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
  const recordKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({ record });
  const materialResolution = resolveReadyEvmFamilyEcdsaMaterial({
    record,
    cachedExportArtifact: keyRef.ecdsaHssExportArtifact || null,
    expected: {
      walletId: record.walletId,
      walletKeyId: recordKey.walletKeyId,
      chainTarget: args.chainTarget,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      source: SIGNER_AUTH_METHODS.emailOtp,
      thresholdSessionId: recordIdentity.thresholdSessionId,
      signingGrantId: recordIdentity.signingGrantId,
    },
  });
  if (materialResolution.kind !== 'ready') {
    throw new Error(
      `[SigningEngine][ecdsa] Email OTP refresh did not return ready ECDSA material: ${materialResolution.kind}`,
    );
  }
  const lane = buildEvmFamilyEcdsaSigningLaneContext({
    walletId,
    chain: args.chain,
    chainTarget: args.chainTarget,
    authMethod: SIGNER_AUTH_METHODS.emailOtp,
    source: SIGNER_AUTH_METHODS.emailOtp,
    material: materialResolution.material,
  });
  if (!lane) {
    throw new Error('[SigningEngine][ecdsa] Email OTP refresh did not return exact ECDSA lane');
  }
  return {
    readyMaterial: materialResolution.material,
    record,
    lane,
  };
}
