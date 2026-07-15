import type { WalletSessionActivationDeps } from '../../session/passkey/ecdsaBootstrap';
import type { RegistrationAccountLifecycleDeps } from '../../interfaces/operationDeps';
import type { CreateSigningEnginePortsArgs } from './shared';

export function createWalletSessionActivationDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  credentialStore: WalletSessionActivationDeps['credentialStore'];
  getOrCreateActiveThresholdEcdsaSessionId: WalletSessionActivationDeps['getOrCreateActiveThresholdEcdsaSessionId'];
}): WalletSessionActivationDeps {
  return {
    credentialStore: args.credentialStore,
    touchIdPrompt: args.createArgs.touchIdPrompt,
    touchConfirm: args.createArgs.touchConfirm,
    getSignerWorkerContext: () => args.createArgs.signerWorkerManager.getContext(),
    routerAbNormalSigning: args.createArgs.seamsWebConfigs.signing.routerAb.normalSigning,
    getOrCreateActiveThresholdEcdsaSessionId: args.getOrCreateActiveThresholdEcdsaSessionId,
    defaultRelayerUrl: args.createArgs.seamsWebConfigs.network.relayer?.url || '',
    persistThresholdEcdsaBootstrapForWalletTarget:
      args.createArgs.persistThresholdEcdsaBootstrapForWalletTarget,
    upsertThresholdEcdsaSessionFromBootstrap:
      args.createArgs.upsertThresholdEcdsaSessionFromBootstrap,
  };
}

export function createRegistrationAccountLifecycleDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  accountStore: RegistrationAccountLifecycleDeps['accountStore'];
}): RegistrationAccountLifecycleDeps {
  return {
    accountStore: args.accountStore,
    userPreferencesManager: args.createArgs.userPreferencesManager,
    nonceCoordinator: args.createArgs.nonceCoordinator,
  };
}
