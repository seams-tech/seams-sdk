import {
  IndexedDBManager,
  createIndexedDBNonceLaneCoordinationStore,
} from '@/core/indexedDB';
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
  TatchiConfigsReadonly,
} from '@/core/types/tatchi';
import { createTouchConfirmManager } from '../touchConfirm/TouchConfirmManager';
import type { TouchConfirmRuntimeBridgePort } from '../touchConfirm/types';
import { TouchIdPrompt } from '../signers/webauthn/prompt/touchIdPrompt';
import { SignerWorkerManager } from '../workerManager';
import { UserPreferencesManager } from '../api/userPreferences';
import UserPreferencesInstance from '../api/userPreferences';

export type ManagerAssembly = {
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  touchConfirm: TouchConfirmRuntimeBridgePort;
  signerWorkerManager: SignerWorkerManager;
};

export function createManagerAssembly(args: {
  tatchiPasskeyConfigs: TatchiConfigsReadonly;
  nearClient: NearClient;
  getTheme: () => ThemeName;
  getAppearanceTokens?: () => ThemeTokenOverridesInput | undefined;
}): ManagerAssembly {
  const touchIdPrompt = new TouchIdPrompt(
    args.tatchiPasskeyConfigs.wallet.iframe?.rpIdOverride,
    true,
  );
  const userPreferencesManager = UserPreferencesInstance;
  const chains = args.tatchiPasskeyConfigs.network.chains;
  const evmNonceBackend = createEvmNonceBackend({
    chains,
  });
  const nonceLaneCoordinationStore = createIndexedDBNonceLaneCoordinationStore({
    indexedDB: IndexedDBManager,
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
    args.tatchiPasskeyConfigs.signing.sessionPersistenceMode === 'sealed_refresh_v1';

  const touchConfirm: TouchConfirmRuntimeBridgePort = createTouchConfirmManager(
    {
      signingSessionPersistenceMode: args.tatchiPasskeyConfigs.signing.sessionPersistenceMode,
      ...(isSealedRefreshMode
        ? {
            signingSessionSealKeyVersion: args.tatchiPasskeyConfigs.signing.sessionSeal.keyVersion,
            signingSessionSealShamirPrimeB64u:
              args.tatchiPasskeyConfigs.signing.sessionSeal.shamirPrimeB64u,
          }
        : {}),
    },
    {
      touchIdPrompt: touchIdPrompt,
      nearClient: args.nearClient,
      indexedDB: IndexedDBManager,
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
    args.tatchiPasskeyConfigs.network.relayer.url,
    chains,
    args.tatchiPasskeyConfigs.wallet.iframe?.rpIdOverride,
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
