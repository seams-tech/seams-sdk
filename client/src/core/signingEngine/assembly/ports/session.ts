import { configuredThresholdEcdsaChainTargets } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import type { ThresholdEcdsaSessionStoreDeps } from '../../session/persistence/records';
import type { SessionPublicDeps } from '../../session/public';
import type { WalletSigningBudgetAvailableStatusDeps } from '../../session/budget/budgetStatusReader';
import type { CreateSigningEnginePortsArgs } from './shared';

export function createSessionPublicDeps(args: {
  seamsPasskeyConfigs: CreateSigningEnginePortsArgs['seamsPasskeyConfigs'];
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  touchConfirm: UiConfirmRuntimeBridgePort;
  emailOtpSessions: {
    restorePersistedSessionsForWallet: SessionPublicDeps['restore']['emailOtp'];
  };
  getWalletSigningBudgetStatus: WalletSigningBudgetAvailableStatusDeps['getAvailableStatus'];
}): SessionPublicDeps {
  const passkeyRestore = args.touchConfirm.restorePersistedSessionsForWallet
    ? (restoreArgs: Parameters<NonNullable<SessionPublicDeps['restore']['passkey']>>[0]) =>
        args.touchConfirm.restorePersistedSessionsForWallet!(restoreArgs)
    : undefined;

  return {
    availableLanes: {
      ecdsaSessions: args.ecdsaSessions,
      statusReader: args.touchConfirm,
      getWalletSigningBudgetStatus: args.getWalletSigningBudgetStatus,
    },
    ecdsaSessions: args.ecdsaSessions,
    signingSessionSeal: args.seamsPasskeyConfigs.signing.sessionSeal,
    getConfiguredEcdsaChainTargets: () =>
      configuredThresholdEcdsaChainTargets(args.seamsPasskeyConfigs.network.chains),
    restore: {
      emailOtp: (restoreArgs) => args.emailOtpSessions.restorePersistedSessionsForWallet(restoreArgs),
      ...(passkeyRestore ? { passkey: passkeyRestore } : {}),
    },
  };
}
