import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { configuredThresholdEcdsaChainTargets } from '../../interfaces/ecdsaChainTarget';
import { readTrustedWalletSigningBudgetStatus } from '../../session/budget/budgetStatusReader';
import type { EmailOtpThresholdSessionCoordinator } from '../../session/emailOtp/EmailOtpThresholdSessionCoordinator';
import type { SessionPublicDeps } from '../../session/public';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import type { WarmSigningPorts } from './warmSigning';

export function createSessionPublicDeps(args: {
  seamsPasskeyConfigs: SeamsConfigsReadonly;
  touchConfirm: UiConfirmRuntimeBridgePort;
  emailOtpSessions: EmailOtpThresholdSessionCoordinator;
  warmSigning: WarmSigningPorts;
}): SessionPublicDeps {
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
      getEmailOtpWarmSessionStatus: (sessionId) =>
        args.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
      getWalletSigningBudgetStatus: (statusArgs) =>
        readTrustedWalletSigningBudgetStatus(
          {
            ecdsaSessions: args.warmSigning.ecdsaSessions,
          },
          statusArgs,
        ),
    },
    ecdsaSessions: args.warmSigning.ecdsaSessions,
    signingSessionSeal: args.seamsPasskeyConfigs.signing.sessionSeal,
    getConfiguredEcdsaChainTargets: () =>
      configuredThresholdEcdsaChainTargets(args.seamsPasskeyConfigs.network.chains),
    restore: sessionRestore,
  };
}
