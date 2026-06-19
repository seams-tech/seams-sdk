import type { SeamsConfigsReadonly, ThemeName } from '@/core/types/seams';
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/types';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { WarmSigningPorts } from '@/core/signingEngine/assembly/ports/warmSigning';
import type { SigningEngineStorePorts } from '@/core/signingEngine/assembly/ports/shared';
import {
  createRecoveryPublicDeps,
} from '@/core/signingEngine/assembly/ports/recovery';
import type {
  RecoveryPublicDeps,
} from '@/core/signingEngine/flows/recovery/public';
import { readTrustedWalletSigningBudgetStatus as readTrustedWalletSigningBudgetStatusOperation } from '@/core/signingEngine/session/budget/budgetStatusReader';

export function createBrowserRecoveryPublicDeps(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  touchIdPrompt: TouchIdPrompt;
  signerWorkerManager: SignerWorkerManager;
  keyMaterialStore: SigningEngineStorePorts['recoveryAndDeviceLinking']['keyMaterialStore'];
  warmSigning: WarmSigningPorts;
  touchConfirm: UiConfirmRuntimeBridgePort;
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  getTheme: () => ThemeName;
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
    warmSessionPolicy: {
      getWarmSession: (nearAccountId) =>
        args.warmSigning.capabilityReader.getWarmSession(nearAccountId),
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
