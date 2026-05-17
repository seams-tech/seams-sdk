import { IndexedDBManager } from '@/core/indexedDB';
import type { EvmFamilySigningDeps } from '../../interfaces/operationDeps';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import { readExactSealedSession } from '../../session/persistence/sealedSessionStore';
import { emailOtpEcdsaSigningSessionAuthLaneFromSealedRecord } from '../../session/emailOtp/sealedSigningSessionAuth';
import { createWarmSessionCapabilityReader } from '../../session/warmCapabilities/capabilityReader';
import type { WarmSessionStatusResult } from '../../uiConfirm/types';
import type { CreateSigningEnginePortsArgs } from './shared';

export function createEvmFamilySigningDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  signingSessionCoordinator: SigningSessionCoordinator;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
}): EvmFamilySigningDeps {
  const { createArgs, signingSessionCoordinator, getEmailOtpWarmSessionStatus } = args;
  return {
    indexedDB: IndexedDBManager,
    seamsPasskeyConfigs: createArgs.seamsPasskeyConfigs,
    nonceCoordinator: createArgs.nonceCoordinator,
    ensureSealedRefreshStartupParity: createArgs.ensureSealedRefreshStartupParity,
    getSignerWorkerContext: () => createArgs.signerWorkerManager.getContext(),
    getEmailOtpThresholdEcdsaKeyRefForSigning: ({ subjectId, chainTarget }) =>
      createArgs.getEmailOtpThresholdEcdsaKeyRefForSigning({
        subjectId,
        chainTarget,
      }),
    getEmailOtpThresholdEcdsaSessionRecordForSigning: ({ subjectId, chainTarget }) =>
      createArgs.getEmailOtpThresholdEcdsaSessionRecordForSigning({
        subjectId,
        chainTarget,
      }),
    getPasskeyThresholdEcdsaKeyRefForSigning: ({ subjectId, chainTarget, source }) =>
      createArgs.getPasskeyThresholdEcdsaKeyRefForSigning({
        subjectId,
        chainTarget,
        source,
      }),
    getPasskeyThresholdEcdsaSessionRecordForSigning: ({ subjectId, chainTarget, source }) =>
      createArgs.getPasskeyThresholdEcdsaSessionRecordForSigning({
        subjectId,
        chainTarget,
        source,
      }),
    listThresholdEcdsaSessionRecordsForSigning: ({ subjectId, chainTarget, source }) =>
      createArgs.listThresholdEcdsaSessionRecordsForTarget({
        subjectId,
        chainTarget,
        ...(source ? { source } : {}),
      }),
    listThresholdEcdsaKeyRefsForSigning: ({ subjectId, chainTarget, source }) =>
      createArgs.listThresholdEcdsaKeyRefsForTarget({
        subjectId,
        chainTarget,
        ...(source ? { source } : {}),
      }),
    getThresholdEcdsaSessionRecordByKey: (identity) =>
      createArgs.getThresholdEcdsaSessionRecordByKey(identity),
    getThresholdEcdsaKeyRefByKey: (identity) => createArgs.getThresholdEcdsaKeyRefByKey(identity),
    requestEmailOtpTransactionSigningChallenge: ({ walletSession, chain, authLane }) =>
      createArgs.requestEmailOtpTransactionSigningChallenge?.({
        kind: 'wallet_session_challenge',
        walletSession,
        chain,
        ...(authLane ? { authLane } : {}),
      }) || Promise.reject(new Error('Email OTP signing challenge is not configured')),
    resolveEmailOtpSigningSessionAuthLane: async ({ thresholdSessionId, curve, chainTarget }) => {
      const runtimeLane = createWarmSessionCapabilityReader({
        touchConfirm: createArgs.touchConfirm,
        getEmailOtpWarmSessionStatus,
      }).resolveEmailOtpSigningSessionAuthLane({ thresholdSessionId, curve });
      if (runtimeLane) return runtimeLane;
      const sealedRecord = await readExactSealedSession(thresholdSessionId, {
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chainTarget,
      }).catch(() => null);
      return sealedRecord
        ? emailOtpEcdsaSigningSessionAuthLaneFromSealedRecord({
            thresholdSessionId,
            chainTarget,
            sealedRecord,
          })
        : null;
    },
    loginWithEmailOtpEcdsaCapabilityForSigning: ({
      walletSession,
      subjectId,
      chainTarget,
      challengeId,
      otpCode,
      record,
      authLane,
    }) =>
      createArgs.loginWithEmailOtpEcdsaCapabilityForSigning?.({
        walletSession,
        subjectId,
        chainTarget,
        challengeId,
        otpCode,
        record,
        ...(authLane ? { authLane } : {}),
      }) || Promise.reject(new Error('Email OTP signing bootstrap is not configured')),
    restorePersistedSessionForSigning: (restoreArgs) =>
      createArgs.restorePersistedSessionForSigning(restoreArgs),
    readAvailableSigningLanesForSigning: (snapshotArgs) =>
      createArgs.readAvailableSigningLanesForSigning(snapshotArgs),
    markThresholdEcdsaEmailOtpSessionConsumedForSubjectTarget: ({ subjectId, chainTarget, uses }) =>
      createArgs.markThresholdEcdsaEmailOtpSessionConsumedForSubjectTarget?.({
        subjectId,
        chainTarget,
        uses,
      }),
    signingSessionCoordinator,
    getEmailOtpWarmSessionStatus,
    provisionThresholdEcdsaSession: (provisionArgs) =>
      createArgs.provisionThresholdEcdsaSession(provisionArgs),
    withThresholdEcdsaCommitQueue: (queueArgs) =>
      createArgs.withThresholdEcdsaCommitQueue(queueArgs),
    touchConfirm: createArgs.touchConfirm,
  };
}
