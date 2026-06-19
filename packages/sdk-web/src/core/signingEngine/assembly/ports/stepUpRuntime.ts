import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap } from '../../session/warmCapabilities/sealedRefreshParity';
import {
  commitEvmFamilyThresholdEcdsaSessions,
  type CommitEvmFamilyThresholdEcdsaSessionsDeps,
} from '../../session/emailOtp/ecdsaBootstrapCommit';
import { persistWarmSessionEd25519Capability } from '../../session/warmCapabilities/persistence';
import { cacheSigningSessionPrfFirst } from '../../session/passkey/prfCache';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  listStoredThresholdEcdsaSessionRecordsForWallet,
} from '../../session/persistence/records';
import { createWarmSessionAwareUiConfirm } from '../../uiConfirm/warmSessionUiConfirm';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import {
  EmailOtpWalletSessionCoordinator,
  type EmailOtpWalletSessionCoordinatorDeps,
  type EmailOtpSealedSessionStorePorts,
} from '../../session/emailOtp/EmailOtpWalletSessionCoordinator';
import {
  persistEmailOtpThresholdEd25519LocalMetadata,
  type PersistEmailOtpThresholdEd25519LocalMetadataDeps,
} from '../../session/emailOtp/ed25519LocalMetadata';
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
  ed25519MetadataStore: PersistEmailOtpThresholdEd25519LocalMetadataDeps;
  sealedSessionStore: EmailOtpSealedSessionStorePorts;
  baseTouchConfirm: UiConfirmRuntimeBridgePort;
  getSignerWorkerContext: EmailOtpWalletSessionCoordinatorDeps['getSignerWorkerContext'];
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  getEcdsaSessions: () => WarmSigningPorts['ecdsaSessions'];
  getWarmCapabilityReader: () => WarmSigningPorts['capabilityReader'];
  getThresholdEcdsaSessionRecordByThresholdSessionId:
    WarmSigningPorts['getThresholdEcdsaSessionRecordByThresholdSessionId'];
  ensureSealedRefreshStartupParity: () => Promise<void>;
}): StepUpRuntime {
  const emailOtpSessions = new EmailOtpWalletSessionCoordinator({
    configs: args.seamsWebConfigs,
    signerWorkerManager: args.signerWorkerManager,
    getRpId: () => args.touchIdPrompt.getRpId(),
    getSignerWorkerContext: args.getSignerWorkerContext,
    commitEvmFamilyThresholdEcdsaSessions: (commitArgs) =>
      commitEvmFamilyThresholdEcdsaSessions(
        {
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          bootstrapStore: args.ecdsaBootstrapStore,
          ecdsaSessions: args.getEcdsaSessions(),
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
    getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId) =>
      args.getThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId),
    getThresholdEd25519SessionRecordByThresholdSessionId: (thresholdSessionId) =>
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId),
    persistEmailOtpThresholdEd25519LocalMetadata: (persistArgs) =>
      persistEmailOtpThresholdEd25519LocalMetadata(args.ed25519MetadataStore, persistArgs),
    persistWarmSessionEd25519Capability: (persistArgs) =>
      persistWarmSessionEd25519Capability(persistArgs),
    hydrateSigningSession: (hydrateArgs) =>
      cacheSigningSessionPrfFirst(args.baseTouchConfirm, hydrateArgs),
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
      claimWarmSessionMaterial: (claimArgs) =>
        emailOtpSessions.claimWarmSessionMaterial(claimArgs),
      clearVolatileWarmSessionMaterial: (command) =>
        emailOtpSessions.clearVolatileWarmSessionMaterial(command.scope.sessionId),
    },
  });

  return {
    emailOtpSessions,
    touchConfirm,
  };
}
