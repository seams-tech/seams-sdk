import { IndexedDBManager } from '@/core/indexedDB';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { NonceManager } from '@/core/rpcClients/near/nonceManager';
import NonceManagerInstance from '@/core/rpcClients/near/nonceManager';
import { createEvmNonceManager } from '@/core/rpcClients/evm/nonceManager';
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
  nonceManager: NonceManager;
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
  const nonceManager = NonceManagerInstance;
  const chains = args.tatchiPasskeyConfigs.network.chains;
  const evmNonceManager = createEvmNonceManager({
    chains,
  });
  const nonceCoordinator = createNonceCoordinator({
    evmNonceManager,
    nearNonceManager: nonceManager,
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
      nonceManager: nonceManager,
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
    nonceManager,
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
    nonceManager,
    nonceCoordinator,
    touchConfirm,
    signerWorkerManager,
  };
}
