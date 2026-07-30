import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { RuntimePorts } from '@/core/platform';
import type {
  PasskeyMpcSessionPort,
  UiConfirmRuntimeBridgePort,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SigningEngineStorePorts } from '@/core/signingEngine/assembly/ports/shared';
import {
  createPasskeyPublicDeps,
  createWarmCapabilitiesPublicDeps,
  type WarmSigningPorts,
} from '@/core/signingEngine/assembly/ports/warmSigning';
import type { PasskeyPublicDeps } from '@/core/signingEngine/session/passkey/public';
import type {
  WarmCapabilitiesPublicDeps,
} from '@/core/signingEngine/session/warmCapabilities/public';
import type { createSigningEnginePorts } from '@/core/signingEngine/assembly/createPorts';

type SigningEnginePorts = ReturnType<typeof createSigningEnginePorts>;

export function createBrowserWarmSessionPublicDeps(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  stores: SigningEngineStorePorts;
  touchIdPrompt: TouchIdPrompt;
  touchConfirm: UiConfirmRuntimeBridgePort;
  passkeyMpcSession: PasskeyMpcSessionPort;
  warmSigning: WarmSigningPorts;
  runtimePorts: RuntimePorts;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  enginePorts: Pick<
    SigningEnginePorts,
    | 'walletSessionActivationDeps'
    | 'signingSessionCoordinator'
  >;
}): {
  passkeyPublicDeps: PasskeyPublicDeps;
  warmCapabilitiesPublicDeps: WarmCapabilitiesPublicDeps;
} {
  return {
    passkeyPublicDeps: createPasskeyPublicDeps({
      seamsWebConfigs: args.seamsWebConfigs,
      credentialStore: args.stores.recoveryAndDeviceLinking.credentialStore,
      touchIdPrompt: args.touchIdPrompt,
      touchConfirm: args.touchConfirm,
      passkeyMpcSession: args.passkeyMpcSession,
      warmSigning: args.warmSigning,
      thresholdEcdsaBootstrapQueueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
      ensureSealedRefreshStartupParity: args.ensureSealedRefreshStartupParity,
      walletSessionActivationDeps: args.enginePorts.walletSessionActivationDeps,
      persistEcdsaRoleLocalReadyRecord:
        args.runtimePorts.storage.persistEcdsaRoleLocalReadyRecord,
    }),
    warmCapabilitiesPublicDeps: createWarmCapabilitiesPublicDeps({
      seamsWebConfigs: args.seamsWebConfigs,
      bootstrapStore: args.stores.walletProfileAndSignerRecords.ecdsaBootstrapStore,
      touchConfirm: args.touchConfirm,
      passkeyMpcSession: args.passkeyMpcSession,
      warmSigning: args.warmSigning,
      walletSessionActivationDeps: args.enginePorts.walletSessionActivationDeps,
      signingSessionCoordinator: args.enginePorts.signingSessionCoordinator,
    }),
  };
}
