import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { configuredThresholdEcdsaChainTargets } from '../../interfaces/ecdsaChainTarget';
import { readTrustedWalletSigningBudgetStatus } from '../../session/budget/budgetStatusReader';
import type { EmailOtpWalletSessionCoordinator } from '../../session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { SessionPublicDeps } from '../../session/public';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/uiConfirm.types';
import type { WarmSigningPorts } from './warmSigning';

export function createSessionPublicDeps(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  touchConfirm: UiConfirmRuntimeBridgePort;
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  warmSigning: WarmSigningPorts;
}): SessionPublicDeps {
  const readCombinedEmailOtpWarmSessionStatus = (sessionId: string) =>
    args.touchConfirm.getWarmSessionStatus({ sessionId });
  const sessionRestore: SessionPublicDeps['restore'] = {
    emailOtp: (restoreArgs) =>
      args.emailOtpSessions.restorePersistedSessionsForWallet(restoreArgs),
  };
  if (args.touchConfirm.restorePersistedSessionsForWallet) {
    sessionRestore.passkey = (restoreArgs) =>
      args.touchConfirm.restorePersistedSessionsForWallet!(restoreArgs);
  }
  return {
    availableLanes: {
      ecdsaSessions: args.warmSigning.ecdsaSessions,
      statusReader: args.touchConfirm,
      getEmailOtpWarmSessionStatus: readCombinedEmailOtpWarmSessionStatus,
      getWalletSigningBudgetStatus: (statusArgs) =>
        readTrustedWalletSigningBudgetStatus(
          {
            ecdsaSessions: args.warmSigning.ecdsaSessions,
          },
          statusArgs,
        ),
    },
    ecdsaSessions: args.warmSigning.ecdsaSessions,
    signingSessionSeal: args.seamsWebConfigs.signing.sessionSeal,
    getConfiguredEcdsaChainTargets: () =>
      configuredThresholdEcdsaChainTargets(args.seamsWebConfigs.network.chains),
    restore: sessionRestore,
  };
}
