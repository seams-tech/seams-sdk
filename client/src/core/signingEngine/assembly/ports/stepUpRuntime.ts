import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap } from '../../session/warmSigning/sealedRefreshParity';
import { commitEvmFamilyThresholdEcdsaSessions } from '../../session/warmSigning/ecdsaBootstrapCommit';
import { persistWarmSessionEd25519Capability } from '../../session/warmSigning/persistence';
import { cacheSigningSessionPrfFirst } from '../../session/warmSigning/prfCache';
import { createWarmSessionAwareUiConfirm } from '../../uiConfirm/warmSessionUiConfirm';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import {
  EmailOtpThresholdSessionCoordinator,
  type EmailOtpThresholdSessionCoordinatorDeps,
} from '../../sessionEmailOtp/EmailOtpThresholdSessionCoordinator';
import { persistEmailOtpThresholdEd25519LocalMetadata } from '../../sessionEmailOtp/ed25519LocalMetadata';
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
  thresholdEcdsaBootstrapQueueByAccount: Map<string, Promise<void>>;
  getEcdsaSessions: () => WarmSigningPorts['ecdsaSessions'];
  getWarmCapabilityReader: () => WarmSigningPorts['capabilityReader'];
  listThresholdEcdsaSessionRecordsForSubject: WarmSigningPorts['listThresholdEcdsaSessionRecordsForSubject'];
  getThresholdEcdsaSessionRecordByThresholdSessionId:
    WarmSigningPorts['getThresholdEcdsaSessionRecordByThresholdSessionId'];
  ensureSealedRefreshStartupParity: () => Promise<void>;
}): StepUpRuntime {
  const emailOtpSessions = new EmailOtpThresholdSessionCoordinator({
    configs: args.seamsPasskeyConfigs,
    signerWorkerManager: args.signerWorkerManager,
    touchIdPrompt: args.touchIdPrompt,
    getSignerWorkerContext: args.getSignerWorkerContext,
    commitEvmFamilyThresholdEcdsaSessions: (commitArgs) =>
      commitEvmFamilyThresholdEcdsaSessions(
        {
          queueByAccount: args.thresholdEcdsaBootstrapQueueByAccount,
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
    listThresholdEcdsaSessionRecordsForSubject: (subjectArgs) =>
      args.listThresholdEcdsaSessionRecordsForSubject(subjectArgs),
    getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId) =>
      args.getThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId),
    persistEmailOtpThresholdEd25519LocalMetadata: (persistArgs) =>
      persistEmailOtpThresholdEd25519LocalMetadata(args.indexedDB, persistArgs),
    persistWarmSessionEd25519Capability: (persistArgs) =>
      persistWarmSessionEd25519Capability(persistArgs),
    hydrateSigningSession: (hydrateArgs) =>
      cacheSigningSessionPrfFirst(args.baseTouchConfirm, hydrateArgs),
  });

  const touchConfirm = createWarmSessionAwareUiConfirm({
    base: args.baseTouchConfirm,
    secondary: {
      readWarmSessionStatusOnly: (sessionId) =>
        emailOtpSessions.readWarmSessionStatusOnly(sessionId),
      claimWarmSessionMaterial: (claimArgs) =>
        emailOtpSessions.claimWarmSessionMaterial(claimArgs),
      clearWarmSessionMaterial: (sessionId) =>
        emailOtpSessions.clearWarmSessionMaterial(sessionId),
    },
  });

  return {
    emailOtpSessions,
    touchConfirm,
  };
}
