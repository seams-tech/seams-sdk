import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { configuredThresholdEcdsaChainTargets } from '../../interfaces/ecdsaChainTarget';
import { readTrustedWalletSigningBudgetStatus } from '../../session/budget/budgetStatusReader';
import type { EmailOtpWalletSessionCoordinator } from '../../session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { SessionPublicDeps } from '../../session/public';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/uiConfirm.types';
import type { PersistedAvailableSigningLanesDeps } from '../../session/availability/persistedAvailableSigningLanes';

export function createSessionPublicDeps(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  touchConfirm: UiConfirmRuntimeBridgePort;
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  listEcdsaSigningCapabilitiesForWallet: PersistedAvailableSigningLanesDeps['listEcdsaSigningCapabilitiesForWallet'];
}): SessionPublicDeps {
  const readCombinedEmailOtpWarmSessionStatus = (sessionId: string) =>
    args.touchConfirm.getWarmSessionStatus({ sessionId });
  const sessionDiscovery: SessionPublicDeps['discovery'] = {
    emailOtp: (discoveryArgs) =>
      args.emailOtpSessions.discoverPersistedSessionsForWallet(discoveryArgs),
  };
  if (args.touchConfirm.discoverPersistedSessionsForWallet) {
    sessionDiscovery.passkey = (discoveryArgs) =>
      args.touchConfirm.discoverPersistedSessionsForWallet!(discoveryArgs);
  }
  return {
    availableLanes: {
      listEcdsaSigningCapabilitiesForWallet: args.listEcdsaSigningCapabilitiesForWallet,
      statusReader: args.touchConfirm,
      getEmailOtpWarmSessionStatus: readCombinedEmailOtpWarmSessionStatus,
      getWalletSigningBudgetStatus: (statusArgs) =>
        readTrustedWalletSigningBudgetStatus({}, statusArgs),
    },
    signingSessionSeal: args.seamsWebConfigs.signing.sessionSeal,
    getConfiguredEcdsaChainTargets: () =>
      configuredThresholdEcdsaChainTargets(args.seamsWebConfigs.network.chains),
    discovery: sessionDiscovery,
  };
}
