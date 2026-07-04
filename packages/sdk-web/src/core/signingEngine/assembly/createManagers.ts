import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { createEvmNonceBackend } from '@/core/rpcClients/evm/nonceBackend';
import {
  createNonceCoordinator,
  type NonceCoordinator,
} from '../nonce/NonceCoordinator';
import { resolvePrimaryExplorerUrl } from '@/core/config/chains';
import type {
  ThemeName,
  ThemeTokenOverridesInput,
  SeamsConfigsReadonly,
} from '@/core/types/seams';
import { createUiConfirmManager } from '../uiConfirm/UiConfirmManager';
import type { UiConfirmRuntimeBridgePort } from '../uiConfirm/uiConfirm.types';
import type { UiConfirmContext } from '../uiConfirm/uiConfirm.types';
import { TouchIdPrompt } from '../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import { SignerWorkerManager } from '../workerManager/SignerWorkerManager';
import type { SignerWorkerManagerDeps } from '../workerManager/SignerWorkerManager';
import { getWorkerTransport } from '../workerManager/workerTransport';
import { type UserPreferencesStorePort, UserPreferencesManager } from '../session/userPreferences';
import type { NonceLaneCoordinationStore } from '../nonce/NonceCoordinator';
import type { DurableRecordStore } from '@/core/platform';

export type ManagerAssembly = {
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  touchConfirm: UiConfirmRuntimeBridgePort;
  signerWorkerManager: SignerWorkerManager;
};

export type ManagerAssemblyStores = {
  userPreferencesStore: UserPreferencesStorePort;
  nonceLaneCoordinationStore: NonceLaneCoordinationStore;
  webauthnCredentialStore: UiConfirmContext['webauthnCredentialStore'];
  passkeyAuthenticatorStore: UiConfirmContext['passkeyAuthenticatorStore'];
  nearKeyMaterialStore: SignerWorkerManagerDeps['nearKeyMaterialStore'];
};

export function createManagerAssembly(args: {
  stores: ManagerAssemblyStores;
  seamsWebConfigs: SeamsConfigsReadonly;
  nearClient: NearClient;
  loadEcdsaRoleLocalReadyRecord: DurableRecordStore['loadEcdsaRoleLocalReadyRecord'];
  getTheme: () => ThemeName;
  getAppearanceTokens?: () => ThemeTokenOverridesInput | undefined;
}): ManagerAssembly {
  const touchIdPrompt = new TouchIdPrompt(
    args.seamsWebConfigs.wallet.iframe?.rpIdOverride,
    true,
  );
  const userPreferencesManager = new UserPreferencesManager({
    store: args.stores.userPreferencesStore,
  });
  const chains = args.seamsWebConfigs.network.chains;
  const evmNonceBackend = createEvmNonceBackend({
    chains,
  });
  const nonceCoordinator = createNonceCoordinator({
    evmNonceBackend,
    nearClient: args.nearClient,
    nonceLaneCoordinationStore: args.stores.nonceLaneCoordinationStore,
  });
  void nonceCoordinator.recoverDurableLeases().catch((error) => {
    console.warn('[NonceCoordinator] startup durable lease recovery failed', error);
  });
  const nearExplorerUrl = resolvePrimaryExplorerUrl(chains, 'near');
  const tempoExplorerUrl = resolvePrimaryExplorerUrl(chains, 'tempo');
  const evmExplorerUrl = resolvePrimaryExplorerUrl(chains, 'evm');
  const isSealedRefreshMode =
    args.seamsWebConfigs.signing.sessionPersistenceMode === 'sealed_refresh_v1';

  const touchConfirm: UiConfirmRuntimeBridgePort = createUiConfirmManager(
    {
      signingSessionPersistenceMode: args.seamsWebConfigs.signing.sessionPersistenceMode,
      ...(isSealedRefreshMode
        ? {
            signingSessionSealKeyVersion:
              args.seamsWebConfigs.signing.sessionSeal.signingSessionSealKeyVersion,
            signingSessionSealShamirPrimeB64u:
              args.seamsWebConfigs.signing.sessionSeal.shamirPrimeB64u,
          }
        : {}),
    },
    {
      touchIdPrompt: touchIdPrompt,
      nearClient: args.nearClient,
      webauthnCredentialStore: args.stores.webauthnCredentialStore,
      passkeyAuthenticatorStore: args.stores.passkeyAuthenticatorStore,
      userPreferencesManager: userPreferencesManager,
      nonceCoordinator: nonceCoordinator,
      relayerUrl: args.seamsWebConfigs.network.relayer.url,
      chains,
      rpIdOverride: touchIdPrompt.getRpId(),
      nearExplorerUrl,
      tempoExplorerUrl,
      evmExplorerUrl,
      getTheme: args.getTheme,
      getAppearanceTokens: args.getAppearanceTokens,
      loadEcdsaRoleLocalReadyRecord: args.loadEcdsaRoleLocalReadyRecord,
    },
  );

  const signerWorkerManager = new SignerWorkerManager({
    nearKeyMaterialStore: args.stores.nearKeyMaterialStore,
    touchIdPrompt,
    touchConfirm,
    nearClient: args.nearClient,
    userPreferencesManager,
    nonceCoordinator,
    relayerUrl: args.seamsWebConfigs.network.relayer.url,
    workerTransport: getWorkerTransport(),
    chains,
    nearExplorerUrl,
    tempoExplorerUrl,
    evmExplorerUrl,
    getTheme: args.getTheme,
  });

  return {
    touchIdPrompt,
    userPreferencesManager,
    nonceCoordinator,
    touchConfirm,
    signerWorkerManager,
  };
}
