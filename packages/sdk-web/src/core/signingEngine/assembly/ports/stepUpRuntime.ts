import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { DurableRecordStore } from '@/core/platform';
import type { ActiveEcdsaCapabilityManifest } from '../../session/material/ecdsaCapabilityManifest';
import { ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap } from '../../session/warmCapabilities/sealedRefreshParity';
import {
  commitEvmFamilyThresholdEcdsaSessions,
  type CommitEvmFamilyThresholdEcdsaSessionsDeps,
} from '../../session/emailOtp/ecdsaBootstrapCommit';
import { createWarmSessionAwarePasskeyMpcSession } from '../../uiConfirm/warmSessionUiConfirm';
import type {
  PasskeyMpcSessionPort,
  UiConfirmRuntimeBridgePort,
} from '../../uiConfirm/uiConfirm.types';
import {
  EmailOtpWalletSessionCoordinator,
  type EmailOtpWalletSessionCoordinatorDeps,
  type EmailOtpSealedSessionStorePorts,
} from '../../session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { TouchIdPrompt } from '../../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManager } from '../../workerManager/SignerWorkerManager';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { resolveActiveEcdsaCapabilityRuntime } from '../../session/material/activeEcdsaCapabilityRuntime';
import {
  withThresholdEcdsaSigningQueue,
  type ThresholdEcdsaSigningQueueByKey,
} from '../../threshold/ecdsa/signingQueue';

export type StepUpRuntime = {
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  touchConfirm: UiConfirmRuntimeBridgePort;
  passkeyMpcSession: PasskeyMpcSessionPort;
};

export function createStepUpRuntime(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  touchIdPrompt: TouchIdPrompt;
  signerWorkerManager: SignerWorkerManager;
  ecdsaBootstrapStore: CommitEvmFamilyThresholdEcdsaSessionsDeps['bootstrapStore'];
  sealedSessionStore: EmailOtpSealedSessionStorePorts;
  baseTouchConfirm: UiConfirmRuntimeBridgePort;
  passkeyMpcSession: PasskeyMpcSessionPort;
  getSignerWorkerContext: EmailOtpWalletSessionCoordinatorDeps['getSignerWorkerContext'];
  provisionThresholdEcdsaSession: EmailOtpWalletSessionCoordinatorDeps['provisionThresholdEcdsaSession'];
  provisionEmailOtpEcdsaExplicitExportSession: EmailOtpWalletSessionCoordinatorDeps['provisionEmailOtpEcdsaExplicitExportSession'];
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  thresholdEcdsaSigningQueueByKey: ThresholdEcdsaSigningQueueByKey;
  loadWalletCustodyEd25519Material: EmailOtpWalletSessionCoordinatorDeps['loadWalletCustodyEd25519Material'];
  restoreWalletCustodyEcdsaContinuity: EmailOtpWalletSessionCoordinatorDeps['restoreWalletCustodyEcdsaContinuity'];
  persistEcdsaRoleLocalReadyRecord: DurableRecordStore['persistEcdsaRoleLocalReadyRecord'];
  listActiveEcdsaCapabilityManifestsForWallet: (
    walletId: string,
  ) => Promise<readonly ActiveEcdsaCapabilityManifest[]>;
  ensureSealedRefreshStartupParity: () => Promise<void>;
}): StepUpRuntime {
  const emailOtpSessions = new EmailOtpWalletSessionCoordinator({
    configs: args.seamsWebConfigs,
    signerWorkerManager: args.signerWorkerManager,
    getRpId: () => args.touchIdPrompt.getRpId(),
    getSignerWorkerContext: args.getSignerWorkerContext,
    loadWalletCustodyEd25519Material: args.loadWalletCustodyEd25519Material,
    restoreWalletCustodyEcdsaContinuity: args.restoreWalletCustodyEcdsaContinuity,
    readActiveWalletSessionAuthorization: walletSessionAuthorizations.readActiveForWallet.bind(
      walletSessionAuthorizations,
    ),
    provisionThresholdEcdsaSession: args.provisionThresholdEcdsaSession,
    withThresholdEcdsaSigningQueue: (queueArgs) =>
      withThresholdEcdsaSigningQueue({
        queueByKey: args.thresholdEcdsaSigningQueueByKey,
        ...queueArgs,
      }),
    provisionEmailOtpEcdsaExplicitExportSession: args.provisionEmailOtpEcdsaExplicitExportSession,
    commitEvmFamilyThresholdEcdsaSessions: (commitArgs) =>
      commitEvmFamilyThresholdEcdsaSessions(
        {
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          bootstrapStore: args.ecdsaBootstrapStore,
          persistEcdsaRoleLocalReadyRecord: args.persistEcdsaRoleLocalReadyRecord,
          ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap: (parityArgs) =>
            ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(
              args.ensureSealedRefreshStartupParity,
              parityArgs,
            ),
        },
        commitArgs,
      ),
    listActiveEcdsaCapabilityManifestsForWallet: (walletId) =>
      args.listActiveEcdsaCapabilityManifestsForWallet(String(walletId)),
    resolveCurrentEcdsaCapabilityRuntime: resolveActiveEcdsaCapabilityRuntime,
    writeExactSealedSession: args.sealedSessionStore.writeExactSealedSession,
    readExactSealedSession: args.sealedSessionStore.readExactSealedSession,
    listExactSealedSessionsForWallet: args.sealedSessionStore.listExactSealedSessionsForWallet,
    acquireSigningSessionRestoreLease: args.sealedSessionStore.acquireSigningSessionRestoreLease,
    releaseSigningSessionRestoreLease: args.sealedSessionStore.releaseSigningSessionRestoreLease,
    deleteDurableSealedSessionRecord: args.sealedSessionStore.deleteDurableSealedSessionRecord,
    updateExactSealedSessionPolicy: args.sealedSessionStore.updateExactSealedSessionPolicy,
  });

  const passkeyMpcSession = createWarmSessionAwarePasskeyMpcSession({
    base: args.passkeyMpcSession,
    secondary: {
      readWarmSessionStatusOnly: (thresholdSessionId) =>
        emailOtpSessions.readWarmSessionStatusOnly({
          kind: 'ecdsa',
          thresholdSessionId: String(thresholdSessionId),
        }),
      clearVolatileWarmSessionMaterial: (command) =>
        emailOtpSessions.clearVolatileWarmSessionMaterial({
          kind: 'ecdsa',
          thresholdSessionId: String(command.scope.thresholdSessionId),
        }),
    },
  });

  return {
    emailOtpSessions,
    touchConfirm: args.baseTouchConfirm,
    passkeyMpcSession,
  };
}
