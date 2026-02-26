import { IndexedDBManager } from '@/core/indexedDB';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { NonceManager } from '@/core/rpcClients/near/nonceManager';
import NonceManagerInstance from '@/core/rpcClients/near/nonceManager';
import { resolvePrimaryExplorerUrl } from '@/core/config/chains';
import type { ThemeName, ThemeTokenOverridesInput, TatchiConfigsReadonly } from '@/core/types/tatchi';
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
  touchConfirm: TouchConfirmRuntimeBridgePort;
  signerWorkerManager: SignerWorkerManager;
};

export function createManagerAssembly(args: {
  tatchiPasskeyConfigs: TatchiConfigsReadonly;
  nearClient: NearClient;
  getTheme: () => ThemeName;
  getAppearanceTokens?: () => ThemeTokenOverridesInput | undefined;
}): ManagerAssembly {
  const touchIdPrompt = new TouchIdPrompt(args.tatchiPasskeyConfigs.wallet.iframe?.rpIdOverride, true);
  const userPreferencesManager = UserPreferencesInstance;
  userPreferencesManager.configureDefaultSignerMode?.(args.tatchiPasskeyConfigs.signing.mode);
  const nonceManager = NonceManagerInstance;
  const nearExplorerUrl = resolvePrimaryExplorerUrl(args.tatchiPasskeyConfigs.network.chains, 'near');
  const tempoExplorerUrl = resolvePrimaryExplorerUrl(args.tatchiPasskeyConfigs.network.chains, 'tempo');
  const evmExplorerUrl = resolvePrimaryExplorerUrl(args.tatchiPasskeyConfigs.network.chains, 'arc');

  const touchConfirm: TouchConfirmRuntimeBridgePort = createTouchConfirmManager(
    {},
    {
      touchIdPrompt: touchIdPrompt,
      nearClient: args.nearClient,
      indexedDB: IndexedDBManager,
      userPreferencesManager: userPreferencesManager,
      nonceManager: nonceManager,
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
    args.tatchiPasskeyConfigs.network.relayer.url,
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
    touchConfirm,
    signerWorkerManager,
  };
}
