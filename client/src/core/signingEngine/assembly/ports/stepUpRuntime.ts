import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap } from '../../session/warmCapabilities/sealedRefreshParity';
import { commitEvmFamilyThresholdEcdsaSessions } from '../../session/emailOtp/ecdsaBootstrapCommit';
import { persistWarmSessionEd25519Capability } from '../../session/warmCapabilities/persistence';
import { cacheSigningSessionPrfFirst } from '../../session/passkey/prfCache';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  listStoredThresholdEcdsaSessionRecordsForWallet,
} from '../../session/persistence/records';
import { createWarmSessionAwareUiConfirm } from '../../uiConfirm/warmSessionUiConfirm';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import {
  EmailOtpThresholdSessionCoordinator,
  type EmailOtpThresholdSessionCoordinatorDeps,
} from '../../session/emailOtp/EmailOtpThresholdSessionCoordinator';
import { persistEmailOtpThresholdEd25519LocalMetadata } from '../../session/emailOtp/ed25519LocalMetadata';
import {
  acquireSigningSessionRestoreLease,
  deleteDurableSealedSessionRecord,
  listExactSealedSessionsForWallet,
  releaseSigningSessionRestoreLease,
  readExactSealedSession,
  updateExactSealedSessionPolicy,
  writeExactSealedSession,
} from '../../session/persistence/sealedSessionStore';
import type { TouchIdPrompt } from '../../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManager } from '../../workerManager/SignerWorkerManager';
import type { WarmSigningPorts } from './warmSigning';
import type { SigningEnginePorts } from './shared';

export type StepUpRuntime = {
  emailOtpSessions: EmailOtpThresholdSessionCoordinator;
  touchConfirm: UiConfirmRuntimeBridgePort;
};

export function createStepUpRuntime(args: {
  seamsPasskeyConfigs: SeamsConfigsReadonly;
  touchIdPrompt: TouchIdPrompt;
  signerWorkerManager: SignerWorkerManager;
  indexedDB: SigningEnginePorts['indexedDB'];
  baseTouchConfirm: UiConfirmRuntimeBridgePort;
  getSignerWorkerContext: EmailOtpThresholdSessionCoordinatorDeps['getSignerWorkerContext'];
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  getEcdsaSessions: () => WarmSigningPorts['ecdsaSessions'];
  getWarmCapabilityReader: () => WarmSigningPorts['capabilityReader'];
  getThresholdEcdsaSessionRecordByThresholdSessionId:
    WarmSigningPorts['getThresholdEcdsaSessionRecordByThresholdSessionId'];
  ensureSealedRefreshStartupParity: () => Promise<void>;
}): StepUpRuntime {
  const emailOtpSessions = new EmailOtpThresholdSessionCoordinator({
    configs: args.seamsPasskeyConfigs,
    signerWorkerManager: args.signerWorkerManager,
    getRpId: () => args.touchIdPrompt.getRpId(),
    getSignerWorkerContext: args.getSignerWorkerContext,
    commitEvmFamilyThresholdEcdsaSessions: (commitArgs) =>
      commitEvmFamilyThresholdEcdsaSessions(
        {
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          indexedDB: args.indexedDB,
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
      persistEmailOtpThresholdEd25519LocalMetadata(args.indexedDB, persistArgs),
    persistWarmSessionEd25519Capability: (persistArgs) =>
      persistWarmSessionEd25519Capability(persistArgs),
    hydrateSigningSession: (hydrateArgs) =>
      cacheSigningSessionPrfFirst(args.baseTouchConfirm, hydrateArgs),
    writeExactSealedSession,
    readExactSealedSession,
    listExactSealedSessionsForWallet,
    acquireSigningSessionRestoreLease,
    releaseSigningSessionRestoreLease,
    deleteDurableSealedSessionRecord,
    updateExactSealedSessionPolicy,
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
