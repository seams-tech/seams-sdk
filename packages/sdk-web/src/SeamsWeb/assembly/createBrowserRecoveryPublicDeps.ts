import type { SeamsConfigsReadonly, ThemeMode } from '@/core/types/seams';
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { WarmSigningPorts } from '@/core/signingEngine/assembly/ports/warmSigning';
import { createRecoveryPublicDeps } from '@/core/signingEngine/assembly/ports/recovery';
import { provisionThresholdEcdsaSession as provisionThresholdEcdsaSessionOperation } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import type { RuntimePorts } from '@/core/platform';
import type { WalletSessionActivationDeps } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { RecoveryPublicDeps } from '@/core/signingEngine/flows/recovery/public';
import { readTrustedWalletSigningBudgetStatus as readTrustedWalletSigningBudgetStatusOperation } from '@/core/signingEngine/session/budget/budgetStatusReader';

export function createBrowserRecoveryPublicDeps(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  runtimePorts: RuntimePorts;
  signerWorkerManager: SignerWorkerManager;
  warmSigning: WarmSigningPorts;
  touchConfirm: UiConfirmRuntimeBridgePort;
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  getWalletSessionActivationDeps: () => WalletSessionActivationDeps;
  resolveActiveEd25519YaoCapability: RecoveryPublicDeps['ed25519Yao']['resolveActiveCapability'];
  recoverPasskeyEd25519YaoCapability: RecoveryPublicDeps['ed25519Yao']['recoverPasskeyCapability'];
  resolvePasskeyEd25519YaoExportContext: RecoveryPublicDeps['ed25519Yao']['resolvePasskeyExportContext'];
  resolveEmailOtpEd25519YaoExportContext: RecoveryPublicDeps['ed25519Yao']['emailOtp']['resolveExportContext'];
  getTheme: () => ThemeMode;
}): RecoveryPublicDeps {
  return createRecoveryPublicDeps({
    seamsWebConfigs: args.seamsWebConfigs,
    signerWorkerManager: args.signerWorkerManager,
    getTheme: args.getTheme,
    ecdsaSessions: args.warmSigning.ecdsaSessions,
    touchConfirm: args.touchConfirm,
    emailOtpSessions: args.emailOtpSessions,
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
    resolveActiveEd25519YaoCapability: args.resolveActiveEd25519YaoCapability,
    recoverPasskeyEd25519YaoCapability: args.recoverPasskeyEd25519YaoCapability,
    resolvePasskeyEd25519YaoExportContext: args.resolvePasskeyEd25519YaoExportContext,
    resolveEmailOtpEd25519YaoExportContext: args.resolveEmailOtpEd25519YaoExportContext,
  });
}
