import { IndexedDBManager } from '@/core/indexedDB';
import type { EvmFamilySigningDeps } from '../../interfaces/operationDeps';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  listEcdsaSealedSessionsForWallet,
  readExactSealedSession,
} from '../../session/persistence/sealedSessionStore';
import { emailOtpEcdsaSigningSessionAuthLaneFromSealedRecord } from '../../session/emailOtp/sealedSigningSessionAuth';
import { createWarmSessionCapabilityReader } from '../../session/warmCapabilities/capabilityReader';
import type { WarmSessionStatusResult } from '../../uiConfirm/types';
import type { CreateSigningEnginePortsArgs } from './shared';
import { thresholdEcdsaChainTargetsEqual } from '../../interfaces/ecdsaChainTarget';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

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
    getEmailOtpThresholdEcdsaKeyRefForSigning: ({ walletId, chainTarget }) =>
      createArgs.getEmailOtpThresholdEcdsaKeyRefForSigning({
        walletId,
        chainTarget,
      }),
    getEmailOtpThresholdEcdsaSessionRecordForSigning: ({ walletId, chainTarget }) =>
      createArgs.getEmailOtpThresholdEcdsaSessionRecordForSigning({
        walletId,
        chainTarget,
      }),
    getPasskeyThresholdEcdsaKeyRefForSigning: ({ walletId, chainTarget, source }) =>
      createArgs.getPasskeyThresholdEcdsaKeyRefForSigning({
        walletId,
        chainTarget,
        source,
      }),
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
    getThresholdEcdsaKeyRefByKey: (identity) => createArgs.getThresholdEcdsaKeyRefByKey(identity),
    requestEmailOtpTransactionSigningChallenge: ({ walletSession, chain, authLane }) =>
      createArgs.requestEmailOtpTransactionSigningChallenge?.({
        walletSession,
        chain,
        ...(authLane ? { authLane } : {}),
      }) || Promise.reject(new Error('Email OTP signing challenge is not configured')),
    resolveEmailOtpSigningSessionAuthLane: async ({
      walletId,
      thresholdSessionId,
      curve,
      chainTarget,
    }) => {
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
      const exactLane = sealedRecord
        ? emailOtpEcdsaSigningSessionAuthLaneFromSealedRecord({
            thresholdSessionId,
            chainTarget,
            sealedRecord,
          })
        : null;
      if (exactLane) return exactLane;
      const walletRecords = await listEcdsaSealedSessionsForWallet({
        walletId: String(walletId),
        filter: { authMethod: 'email_otp', curve: 'ecdsa' },
      }).catch(() => []);
      for (const record of walletRecords) {
        if (String(record.thresholdSessionIds.ecdsa || '').trim() !== thresholdSessionId) continue;
        if (
          !record.ecdsaRestore?.chainTarget ||
          !thresholdEcdsaChainTargetsEqual(record.ecdsaRestore.chainTarget, chainTarget)
        ) {
          continue;
        }
        const lane = emailOtpEcdsaSigningSessionAuthLaneFromSealedRecord({
          thresholdSessionId,
          chainTarget,
          sealedRecord: record,
        });
        if (lane) return lane;
      }
      return null;
    },
    loginWithEmailOtpEcdsaCapabilityForSigning: ({
      walletSession,
      chainTarget,
      challengeId,
      otpCode,
      record,
      authLane,
    }) =>
      createArgs.loginWithEmailOtpEcdsaCapabilityForSigning?.({
        walletSession,
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
