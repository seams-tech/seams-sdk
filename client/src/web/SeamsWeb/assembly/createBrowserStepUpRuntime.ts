import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/types';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { SigningEngineStorePorts } from '@/core/signingEngine/assembly/ports/shared';
import type {
  EmailOtpSealedSessionStorePorts,
} from '@/core/signingEngine/session/emailOtp/EmailOtpThresholdSessionCoordinator';
import {
  createStepUpRuntime,
  type StepUpRuntime,
} from '@/core/signingEngine/assembly/ports/stepUpRuntime';
import type { WarmSigningPorts } from '@/core/signingEngine/assembly/ports/warmSigning';
import type { createSigningEnginePorts } from '@/core/signingEngine/assembly/createPorts';

type SigningEnginePorts = ReturnType<typeof createSigningEnginePorts>;

export function createBrowserStepUpRuntime(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  touchIdPrompt: TouchIdPrompt;
  signerWorkerManager: SignerWorkerManager;
  stores: SigningEngineStorePorts;
  sealedSigningSessionStore: EmailOtpSealedSessionStorePorts;
  baseTouchConfirm: UiConfirmRuntimeBridgePort;
  getEnginePorts: () => SigningEnginePorts;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  getWarmSigning: () => WarmSigningPorts;
  ensureSealedRefreshStartupParity: () => Promise<void>;
}): StepUpRuntime {
  return createStepUpRuntime({
    seamsWebConfigs: args.seamsWebConfigs,
    touchIdPrompt: args.touchIdPrompt,
    signerWorkerManager: args.signerWorkerManager,
    ecdsaBootstrapStore: args.stores.walletProfileAndSignerRecords.ecdsaBootstrapStore,
    ed25519MetadataStore: args.stores.recoveryAndDeviceLinking.ed25519MetadataStore,
    sealedSessionStore: args.sealedSigningSessionStore,
    baseTouchConfirm: args.baseTouchConfirm,
    getSignerWorkerContext: () =>
      args.getEnginePorts().thresholdSessionActivationDeps.getSignerWorkerContext(),
    thresholdEcdsaBootstrapQueueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
    getEcdsaSessions: () => args.getWarmSigning().ecdsaSessions,
    getWarmCapabilityReader: () => args.getWarmSigning().capabilityReader,
    getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId) =>
      args.getWarmSigning().getThresholdEcdsaSessionRecordByThresholdSessionId(
        thresholdSessionId,
      ),
    ensureSealedRefreshStartupParity: args.ensureSealedRefreshStartupParity,
  });
}
