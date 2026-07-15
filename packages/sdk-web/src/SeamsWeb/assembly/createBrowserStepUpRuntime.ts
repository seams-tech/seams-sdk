import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { RuntimePorts } from '@/core/platform';
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { SigningEngineStorePorts } from '@/core/signingEngine/assembly/ports/shared';
import type {
  EmailOtpSealedSessionStorePorts,
} from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
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
  runtimePorts: RuntimePorts;
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
    sealedSessionStore: args.sealedSigningSessionStore,
    baseTouchConfirm: args.baseTouchConfirm,
    getSignerWorkerContext: () =>
      args.getEnginePorts().walletSessionActivationDeps.getSignerWorkerContext(),
    thresholdEcdsaBootstrapQueueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
    persistEcdsaRoleLocalReadyRecord:
      args.runtimePorts.storage.persistEcdsaRoleLocalReadyRecord,
    getEcdsaSessions: () => args.getWarmSigning().ecdsaSessions,
    getWarmCapabilityReader: () => args.getWarmSigning().capabilityReader,
    getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId) =>
      args.getWarmSigning().getThresholdEcdsaSessionRecordByThresholdSessionId(
        thresholdSessionId,
      ),
    ensureSealedRefreshStartupParity: args.ensureSealedRefreshStartupParity,
  });
}
