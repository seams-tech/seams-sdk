import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { RuntimePorts } from '@/core/platform';
import type {
  PasskeyMpcSessionPort,
  UiConfirmRuntimeBridgePort,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { SigningEngineStorePorts } from '@/core/signingEngine/assembly/ports/shared';
import type { EmailOtpSealedSessionStorePorts } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import {
  createStepUpRuntime,
  type StepUpRuntime,
} from '@/core/signingEngine/assembly/ports/stepUpRuntime';
import type { WarmSigningPorts } from '@/core/signingEngine/assembly/ports/warmSigning';
import type { createSigningEnginePorts } from '@/core/signingEngine/assembly/createPorts';
import { provisionEmailOtpEcdsaExplicitExportSession } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import type { ThresholdEcdsaSigningQueueByKey } from '@/core/signingEngine/threshold/ecdsa/signingQueue';

type SigningEnginePorts = ReturnType<typeof createSigningEnginePorts>;

export function createBrowserStepUpRuntime(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  touchIdPrompt: TouchIdPrompt;
  signerWorkerManager: SignerWorkerManager;
  stores: SigningEngineStorePorts;
  runtimePorts: RuntimePorts;
  sealedSigningSessionStore: EmailOtpSealedSessionStorePorts;
  baseTouchConfirm: UiConfirmRuntimeBridgePort;
  passkeyMpcSession: PasskeyMpcSessionPort;
  getEnginePorts: () => SigningEnginePorts;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  thresholdEcdsaSigningQueueByKey: ThresholdEcdsaSigningQueueByKey;
  loadWalletCustodyEd25519Material: Parameters<
    typeof createStepUpRuntime
  >[0]['loadWalletCustodyEd25519Material'];
  restoreWalletCustodyEcdsaContinuity: Parameters<
    typeof createStepUpRuntime
  >[0]['restoreWalletCustodyEcdsaContinuity'];
  getWarmSigning: () => WarmSigningPorts;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  listActiveEcdsaCapabilityManifestsForWallet: (
    walletId: string,
  ) => Promise<readonly ActiveEcdsaCapabilityManifest[]>;
}): StepUpRuntime {
  return createStepUpRuntime({
    seamsWebConfigs: args.seamsWebConfigs,
    touchIdPrompt: args.touchIdPrompt,
    signerWorkerManager: args.signerWorkerManager,
    ecdsaBootstrapStore: args.stores.walletProfileAndSignerRecords.ecdsaBootstrapStore,
    sealedSessionStore: args.sealedSigningSessionStore,
    baseTouchConfirm: args.baseTouchConfirm,
    passkeyMpcSession: args.passkeyMpcSession,
    getSignerWorkerContext: () =>
      args.getEnginePorts().walletSessionActivationDeps.getSignerWorkerContext(),
    provisionThresholdEcdsaSession: (request) =>
      args.getEnginePorts().tempoSigningDeps.provisionThresholdEcdsaSession(request),
    provisionEmailOtpEcdsaExplicitExportSession: (request) =>
      provisionEmailOtpEcdsaExplicitExportSession(
        {
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          activationDeps: args.getEnginePorts().walletSessionActivationDeps,
          sealPersistence: args.passkeyMpcSession,
          persistEcdsaRoleLocalReadyRecord:
            args.runtimePorts.storage.persistEcdsaRoleLocalReadyRecord,
          resolveSealTransport: ({ lane, authorization }) =>
            args.getWarmSigning().capabilityReader.resolveEcdsaSealTransportForLane({
              lane,
              authorization,
            }),
        },
        request,
      ),
    thresholdEcdsaBootstrapQueueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
    thresholdEcdsaSigningQueueByKey: args.thresholdEcdsaSigningQueueByKey,
    loadWalletCustodyEd25519Material: args.loadWalletCustodyEd25519Material,
    restoreWalletCustodyEcdsaContinuity: args.restoreWalletCustodyEcdsaContinuity,
    persistEcdsaRoleLocalReadyRecord: args.runtimePorts.storage.persistEcdsaRoleLocalReadyRecord,
    listActiveEcdsaCapabilityManifestsForWallet:
      args.listActiveEcdsaCapabilityManifestsForWallet,
    ensureSealedRefreshStartupParity: args.ensureSealedRefreshStartupParity,
  });
}
