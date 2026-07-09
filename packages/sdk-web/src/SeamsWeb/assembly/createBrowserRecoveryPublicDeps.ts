import type { SeamsConfigsReadonly, ThemeMode } from '@/core/types/seams';
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { WarmSigningPorts } from '@/core/signingEngine/assembly/ports/warmSigning';
import type { SigningEngineStorePorts } from '@/core/signingEngine/assembly/ports/shared';
import {
  createRecoveryPublicDeps,
} from '@/core/signingEngine/assembly/ports/recovery';
import { provisionThresholdEd25519Session } from '@/core/signingEngine/session/passkey/ed25519SessionProvision';
import { provisionThresholdEcdsaSession as provisionThresholdEcdsaSessionOperation } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import type { RuntimePorts } from '@/core/platform';
import type { WalletSessionActivationDeps } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type {
  RecoveryPublicDeps,
} from '@/core/signingEngine/flows/recovery/public';
import { readTrustedWalletSigningBudgetStatus as readTrustedWalletSigningBudgetStatusOperation } from '@/core/signingEngine/session/budget/budgetStatusReader';

export function createBrowserRecoveryPublicDeps(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  runtimePorts: RuntimePorts;
  touchIdPrompt: TouchIdPrompt;
  signerWorkerManager: SignerWorkerManager;
  credentialStore: SigningEngineStorePorts['recoveryAndDeviceLinking']['credentialStore'];
  keyMaterialStore: SigningEngineStorePorts['recoveryAndDeviceLinking']['keyMaterialStore'];
  warmSigning: WarmSigningPorts;
  touchConfirm: UiConfirmRuntimeBridgePort;
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  getWalletSessionActivationDeps: () => WalletSessionActivationDeps;
  getTheme: () => ThemeMode;
}): RecoveryPublicDeps {
  return createRecoveryPublicDeps({
    seamsWebConfigs: args.seamsWebConfigs,
    touchIdPrompt: args.touchIdPrompt,
    signerWorkerManager: args.signerWorkerManager,
    privateKeyExportRecovery: {
      keyMaterialStore: args.keyMaterialStore,
      relayerUrl: args.seamsWebConfigs.network.relayer.url,
      getRpId: () => args.touchIdPrompt.getRpId(),
      requestExportPrivateKeysWithUi: (payload) =>
        args.signerWorkerManager.requestExportPrivateKeysWithUi(payload),
      getTheme: args.getTheme,
    },
    ecdsaSessions: args.warmSigning.ecdsaSessions,
    touchConfirm: args.touchConfirm,
    emailOtpSessions: args.emailOtpSessions,
    keyMaterialStore: args.keyMaterialStore,
    provisionThresholdEd25519Session: (provisionArgs) =>
      provisionThresholdEd25519Session(
        {
          credentialStore: args.credentialStore,
          touchIdPrompt: args.touchIdPrompt,
          touchConfirm: args.touchConfirm,
          defaultRelayerUrl: args.seamsWebConfigs.network.relayer?.url || '',
          getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
        },
        provisionArgs,
      ),
    provisionThresholdEcdsaSession: (provisionArgs) =>
      provisionThresholdEcdsaSessionOperation(
        {
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          activationDeps: args.getWalletSessionActivationDeps(),
          touchConfirm: args.touchConfirm,
          persistEcdsaRoleLocalReadyRecord:
            args.runtimePorts.storage.persistEcdsaRoleLocalReadyRecord,
          resolveSealTransport: ({ lane }) =>
            args.warmSigning.capabilityReader.resolveEcdsaSealTransportByThresholdSessionId({
              lane,
            }),
        },
        provisionArgs,
      ),
    warmSessionPolicy: {
      getWarmSession: (walletId) => args.warmSigning.capabilityReader.getWarmSession(walletId),
      resolveExactEcdsaRecord: (recordArgs) =>
        args.warmSigning.statusReader.resolveExactEcdsaRecord(recordArgs),
    },
    getWalletSigningBudgetStatus: (statusArgs) =>
      readTrustedWalletSigningBudgetStatusOperation(
        {
          ecdsaSessions: args.warmSigning.ecdsaSessions,
        },
        statusArgs,
      ),
  });
}
