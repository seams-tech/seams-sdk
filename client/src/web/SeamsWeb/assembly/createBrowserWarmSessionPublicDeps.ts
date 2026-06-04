import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/types';
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
  warmSigning: WarmSigningPorts;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  enginePorts: Pick<
    SigningEnginePorts,
    | 'thresholdSessionActivationDeps'
    | 'resolveCanonicalThresholdEcdsaSessionIdForWalletTarget'
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
      warmSigning: args.warmSigning,
      thresholdEcdsaBootstrapQueueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
      ensureSealedRefreshStartupParity: args.ensureSealedRefreshStartupParity,
      thresholdSessionActivationDeps: args.enginePorts.thresholdSessionActivationDeps,
    }),
    warmCapabilitiesPublicDeps: createWarmCapabilitiesPublicDeps({
      seamsWebConfigs: args.seamsWebConfigs,
      bootstrapStore: args.stores.walletProfileAndSignerRecords.ecdsaBootstrapStore,
      touchConfirm: args.touchConfirm,
      warmSigning: args.warmSigning,
      thresholdSessionActivationDeps: args.enginePorts.thresholdSessionActivationDeps,
      resolveCanonicalThresholdEcdsaSessionIdForWalletTarget:
        args.enginePorts.resolveCanonicalThresholdEcdsaSessionIdForWalletTarget,
      signingSessionCoordinator: args.enginePorts.signingSessionCoordinator,
    }),
  };
}
