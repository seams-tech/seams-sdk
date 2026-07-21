import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { DurableRecordStore } from '@/core/platform';
import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
import { ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap } from '../../session/warmCapabilities/sealedRefreshParity';
import {
  commitEvmFamilyThresholdEcdsaSessions,
  type CommitEvmFamilyThresholdEcdsaSessionsDeps,
} from '../../session/emailOtp/ecdsaBootstrapCommit';
import { listStoredThresholdEcdsaSessionRecordsForWallet } from '../../session/persistence/records';
import { createWarmSessionAwareUiConfirm } from '../../uiConfirm/warmSessionUiConfirm';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/uiConfirm.types';
import {
  EmailOtpWalletSessionCoordinator,
  type EmailOtpWalletSessionCoordinatorDeps,
  type EmailOtpSealedSessionStorePorts,
} from '../../session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { TouchIdPrompt } from '../../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManager } from '../../workerManager/SignerWorkerManager';
import type { WarmSigningPorts } from './warmSigning';

export type StepUpRuntime = {
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  touchConfirm: UiConfirmRuntimeBridgePort;
};

export function createStepUpRuntime(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  touchIdPrompt: TouchIdPrompt;
  signerWorkerManager: SignerWorkerManager;
  ecdsaBootstrapStore: CommitEvmFamilyThresholdEcdsaSessionsDeps['bootstrapStore'];
  sealedSessionStore: EmailOtpSealedSessionStorePorts;
  baseTouchConfirm: UiConfirmRuntimeBridgePort;
  getSignerWorkerContext: EmailOtpWalletSessionCoordinatorDeps['getSignerWorkerContext'];
  provisionThresholdEcdsaSession: EmailOtpWalletSessionCoordinatorDeps['provisionThresholdEcdsaSession'];
  provisionEmailOtpEcdsaExplicitExportSession: EmailOtpWalletSessionCoordinatorDeps['provisionEmailOtpEcdsaExplicitExportSession'];
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  persistEcdsaRoleLocalReadyRecord: DurableRecordStore['persistEcdsaRoleLocalReadyRecord'];
  listActiveEcdsaSignersForWallet: (args: {
    walletId: string;
  }) => Promise<readonly AccountSignerRecord[]>;
  getEcdsaSessions: () => WarmSigningPorts['ecdsaSessions'];
  getWarmCapabilityReader: () => WarmSigningPorts['capabilityReader'];
  getThresholdEcdsaSessionRecordByThresholdSessionId: WarmSigningPorts['getThresholdEcdsaSessionRecordByThresholdSessionId'];
  ensureSealedRefreshStartupParity: () => Promise<void>;
}): StepUpRuntime {
  const emailOtpSessions = new EmailOtpWalletSessionCoordinator({
    configs: args.seamsWebConfigs,
    signerWorkerManager: args.signerWorkerManager,
    getRpId: () => args.touchIdPrompt.getRpId(),
    getSignerWorkerContext: args.getSignerWorkerContext,
    provisionThresholdEcdsaSession: args.provisionThresholdEcdsaSession,
    provisionEmailOtpEcdsaExplicitExportSession:
      args.provisionEmailOtpEcdsaExplicitExportSession,
    commitEvmFamilyThresholdEcdsaSessions: (commitArgs) =>
      commitEvmFamilyThresholdEcdsaSessions(
        {
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          bootstrapStore: args.ecdsaBootstrapStore,
          ecdsaSessions: args.getEcdsaSessions(),
          persistEcdsaRoleLocalReadyRecord: args.persistEcdsaRoleLocalReadyRecord,
          warmCapabilityReader: args.getWarmCapabilityReader(),
          ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap: (parityArgs) =>
            ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(
              args.ensureSealedRefreshStartupParity,
              parityArgs,
            ),
        },
        commitArgs,
      ),
    listThresholdEcdsaSessionRecordsForWallet: (walletId) =>
      listStoredThresholdEcdsaSessionRecordsForWallet(walletId),
    listActiveEcdsaSignersForWallet: ({ walletId }) =>
      args.listActiveEcdsaSignersForWallet({ walletId: String(walletId) }),
    getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId) =>
      args.getThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId),
    writeExactSealedSession: args.sealedSessionStore.writeExactSealedSession,
    readExactSealedSession: args.sealedSessionStore.readExactSealedSession,
    listExactSealedSessionsForWallet: args.sealedSessionStore.listExactSealedSessionsForWallet,
    acquireSigningSessionRestoreLease: args.sealedSessionStore.acquireSigningSessionRestoreLease,
    releaseSigningSessionRestoreLease: args.sealedSessionStore.releaseSigningSessionRestoreLease,
    deleteDurableSealedSessionRecord: args.sealedSessionStore.deleteDurableSealedSessionRecord,
    updateExactSealedSessionPolicy: args.sealedSessionStore.updateExactSealedSessionPolicy,
  });

  const touchConfirm = createWarmSessionAwareUiConfirm({
    base: args.baseTouchConfirm,
    secondary: {
      readWarmSessionStatusOnly: (sessionId) =>
        emailOtpSessions.readWarmSessionStatusOnly(sessionId),
      claimWarmSessionMaterial: (claimArgs) => emailOtpSessions.claimWarmSessionMaterial(claimArgs),
      clearVolatileWarmSessionMaterial: (command) =>
        emailOtpSessions.clearVolatileWarmSessionMaterial(command.scope.sessionId),
    },
  });

  return {
    emailOtpSessions,
    touchConfirm,
  };
}
