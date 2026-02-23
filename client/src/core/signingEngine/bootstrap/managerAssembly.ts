import { IndexedDBManager } from '@/core/indexedDB';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { NonceManager } from '@/core/rpcClients/near/nonceManager';
import NonceManagerInstance from '@/core/rpcClients/near/nonceManager';
import type { ThemeName, ThemeTokenOverridesInput, TatchiConfigs } from '@/core/types/tatchi';
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
  tatchiPasskeyConfigs: TatchiConfigs;
  nearClient: NearClient;
  getTheme: () => ThemeName;
  getAppearanceTokens?: () => ThemeTokenOverridesInput | undefined;
}): ManagerAssembly {
  const touchIdPrompt = new TouchIdPrompt(args.tatchiPasskeyConfigs.iframeWallet?.rpIdOverride, true);
  const userPreferencesManager = UserPreferencesInstance;
  userPreferencesManager.configureDefaultSignerMode?.(args.tatchiPasskeyConfigs.signerMode);
  const nonceManager = NonceManagerInstance;

  const touchConfirm: TouchConfirmRuntimeBridgePort = createTouchConfirmManager(
    {},
    {
      touchIdPrompt: touchIdPrompt,
      nearClient: args.nearClient,
      indexedDB: IndexedDBManager,
      userPreferencesManager: userPreferencesManager,
      nonceManager: nonceManager,
      rpIdOverride: touchIdPrompt.getRpId(),
      nearExplorerUrl: args.tatchiPasskeyConfigs.nearExplorerUrl,
      getTheme: args.getTheme,
      getAppearanceTokens: args.getAppearanceTokens,
    },
  );

  const signerWorkerManager = new SignerWorkerManager(
    touchConfirm,
    args.nearClient,
    userPreferencesManager,
    nonceManager,
    args.tatchiPasskeyConfigs.relayer.url,
    args.tatchiPasskeyConfigs.iframeWallet?.rpIdOverride,
    true,
    args.tatchiPasskeyConfigs.nearExplorerUrl,
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
