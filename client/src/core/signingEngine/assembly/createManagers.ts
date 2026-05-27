import { createIndexedDBNonceLaneCoordinationStore } from '@/core/indexedDB';
import { getBrowserPlatformIndexedDB, type BrowserPlatformRuntime } from '@/core/platform';
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
import type { UiConfirmRuntimeBridgePort } from '../uiConfirm/types';
import { TouchIdPrompt } from '../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import { SignerWorkerManager } from '../workerManager/SignerWorkerManager';
import { UserPreferencesManager } from '../session/userPreferences';
import UserPreferencesInstance from '../session/userPreferences';

export type ManagerAssembly = {
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  touchConfirm: UiConfirmRuntimeBridgePort;
  signerWorkerManager: SignerWorkerManager;
};

export function createManagerAssembly(args: {
  platformRuntime: BrowserPlatformRuntime;
  seamsPasskeyConfigs: SeamsConfigsReadonly;
  nearClient: NearClient;
  getTheme: () => ThemeName;
  getAppearanceTokens?: () => ThemeTokenOverridesInput | undefined;
}): ManagerAssembly {
  const indexedDB = getBrowserPlatformIndexedDB(args.platformRuntime);
  const touchIdPrompt = new TouchIdPrompt(
    args.seamsPasskeyConfigs.wallet.iframe?.rpIdOverride,
    true,
  );
  const userPreferencesManager = UserPreferencesInstance;
  const chains = args.seamsPasskeyConfigs.network.chains;
  const evmNonceBackend = createEvmNonceBackend({
    chains,
  });
  const nonceLaneCoordinationStore = createIndexedDBNonceLaneCoordinationStore({
    indexedDB,
  });
  const nonceCoordinator = createNonceCoordinator({
    evmNonceBackend,
    nearClient: args.nearClient,
    nonceLaneCoordinationStore,
  });
  void nonceCoordinator.recoverDurableLeases().catch((error) => {
    console.warn('[NonceCoordinator] startup durable lease recovery failed', error);
  });
  const nearExplorerUrl = resolvePrimaryExplorerUrl(chains, 'near');
  const tempoExplorerUrl = resolvePrimaryExplorerUrl(chains, 'tempo');
  const evmExplorerUrl = resolvePrimaryExplorerUrl(chains, 'evm');
  const isSealedRefreshMode =
    args.seamsPasskeyConfigs.signing.sessionPersistenceMode === 'sealed_refresh_v1';

  const touchConfirm: UiConfirmRuntimeBridgePort = createUiConfirmManager(
    {
      signingSessionPersistenceMode: args.seamsPasskeyConfigs.signing.sessionPersistenceMode,
      ...(isSealedRefreshMode
        ? {
            signingSessionSealKeyVersion: args.seamsPasskeyConfigs.signing.sessionSeal.keyVersion,
            signingSessionSealShamirPrimeB64u:
              args.seamsPasskeyConfigs.signing.sessionSeal.shamirPrimeB64u,
          }
        : {}),
    },
    {
      touchIdPrompt: touchIdPrompt,
      nearClient: args.nearClient,
      indexedDB,
      userPreferencesManager: userPreferencesManager,
      nonceCoordinator: nonceCoordinator,
      chains,
      rpIdOverride: touchIdPrompt.getRpId(),
      nearExplorerUrl,
      tempoExplorerUrl,
      evmExplorerUrl,
      getTheme: args.getTheme,
      getAppearanceTokens: args.getAppearanceTokens,
    },
  );

  const signerWorkerManager = new SignerWorkerManager(
    touchConfirm,
    args.nearClient,
    userPreferencesManager,
    nonceCoordinator,
    args.seamsPasskeyConfigs.network.relayer.url,
    chains,
    args.seamsPasskeyConfigs.wallet.iframe?.rpIdOverride,
    true,
    nearExplorerUrl,
    tempoExplorerUrl,
    evmExplorerUrl,
    args.getTheme,
  );

  return {
    touchIdPrompt,
    userPreferencesManager,
    nonceCoordinator,
    touchConfirm,
    signerWorkerManager,
  };
}
