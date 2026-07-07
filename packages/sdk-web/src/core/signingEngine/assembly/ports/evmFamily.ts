import type { EvmFamilySigningDeps } from '../../interfaces/operationDeps';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import { readExactSealedSession } from '../../session/persistence/sealedSessionStore';
import { emailOtpEcdsaSigningSessionAuthorityFromSealedRecord } from '../../session/emailOtp/sealedSigningSessionAuth';
import { createWarmSessionCapabilityReader } from '../../session/warmCapabilities/capabilityReader';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type { CreateSigningEnginePortsArgs } from './shared';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export function createEvmFamilySigningDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  walletSignerStore: EvmFamilySigningDeps['walletSignerStore'];
  passkeyAuthenticatorStore: EvmFamilySigningDeps['passkeyAuthenticatorStore'];
  signingSessionCoordinator: SigningSessionCoordinator;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
}): EvmFamilySigningDeps {
  const { createArgs, signingSessionCoordinator, getEmailOtpWarmSessionStatus } = args;
  return {
    walletSignerStore: args.walletSignerStore,
    passkeyAuthenticatorStore: args.passkeyAuthenticatorStore,
    seamsWebConfigs: createArgs.seamsWebConfigs,
    nonceCoordinator: createArgs.nonceCoordinator,
    ensureSealedRefreshStartupParity: createArgs.ensureSealedRefreshStartupParity,
    getSignerWorkerContext: () => createArgs.signerWorkerManager.getContext(),
    getPasskeyThresholdEcdsaSessionRecordForSigning: ({ walletId, chainTarget, source }) =>
      createArgs.getPasskeyThresholdEcdsaSessionRecordForSigning({
        walletId,
        chainTarget,
        source,
      }),
    listThresholdEcdsaSessionRecordsForSigning: ({ walletId, chainTarget, source }) =>
      createArgs.listThresholdEcdsaSessionRecordsForWalletTarget({
        walletId: toWalletId(walletId),
        chainTarget,
        ...(source ? { source } : {}),
      }),
    listThresholdEcdsaKeyRefsForSigning: ({ walletId, chainTarget, source }) =>
      createArgs.listThresholdEcdsaKeyRefsForWalletTarget({
        walletId: toWalletId(walletId),
        chainTarget,
        ...(source ? { source } : {}),
      }),
    getThresholdEcdsaSessionRecordByKey: (identity) =>
      createArgs.getThresholdEcdsaSessionRecordByKey(identity),
    requestEmailOtpTransactionSigningChallenge: ({ walletSession, chain, authLane }) =>
      createArgs.requestEmailOtpTransactionSigningChallenge?.({
        walletSession,
        chain,
        authLane,
      }) || Promise.reject(new Error('Email OTP signing challenge is not configured')),
    resolveEmailOtpEcdsaSigningSessionAuthority: async ({ lane }) => {
      const runtimeAuthority = createWarmSessionCapabilityReader({
        touchConfirm: createArgs.touchConfirm,
        signingSessionSeal: null,
        getEmailOtpWarmSessionStatus,
      }).resolveEmailOtpEcdsaSigningSessionAuthority({ lane });
      if (runtimeAuthority) return runtimeAuthority;
      const sealedRecord = await readExactSealedSession(String(lane.thresholdSessionId), {
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chainTarget: lane.signer.chainTarget,
      }).catch(() => null);
      const exactAuthority = sealedRecord
        ? emailOtpEcdsaSigningSessionAuthorityFromSealedRecord({
            lane,
            sealedRecord,
          })
        : null;
      return exactAuthority;
    },
    loginWithEmailOtpEcdsaCapabilityForSigning: ({
      walletSession,
      chainTarget,
      challengeId,
      otpCode,
      committedLane,
      remainingUses,
    }) =>
      createArgs.loginWithEmailOtpEcdsaCapabilityForSigning?.({
        walletSession,
        chainTarget,
        challengeId,
        otpCode,
        committedLane,
        remainingUses,
      }) || Promise.reject(new Error('Email OTP signing bootstrap is not configured')),
    restorePersistedSessionForSigning: (restoreArgs) =>
      createArgs.restorePersistedSessionForSigning(restoreArgs),
    readAvailableSigningLanesForSigning: (snapshotArgs) =>
      createArgs.readAvailableSigningLanesForSigning(snapshotArgs),
    consumeSingleUseEmailOtpEcdsaLane: (command) =>
      createArgs.consumeSingleUseEmailOtpEcdsaLane?.(command) || {
        kind: 'missing_lane',
        laneKey: command.lane.laneRef.laneKey,
      },
    signingSessionCoordinator,
    getEmailOtpWarmSessionStatus,
    provisionThresholdEcdsaSession: (provisionArgs) =>
      createArgs.provisionThresholdEcdsaSession(provisionArgs),
    withThresholdEcdsaCommitQueue: (queueArgs) =>
      createArgs.withThresholdEcdsaCommitQueue(queueArgs),
    touchConfirm: createArgs.touchConfirm,
  };
}
