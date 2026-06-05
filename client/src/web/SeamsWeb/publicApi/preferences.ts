import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { PreferencesCapability } from '@/web/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/web/SeamsWeb/walletIframe/coordinator';

export function createPreferencesCapability(deps: {
  userPreferences: UserPreferencesManager;
  getWalletIframe: () => WalletIframeCoordinator;
}): PreferencesCapability {
  return {
    setCurrentWallet: (walletId: WalletId): void => {
      deps.userPreferences.setCurrentWallet(walletId);
    },
    getCurrentWalletId: (): WalletId | null => deps.userPreferences.getCurrentWalletId(),
    onConfirmationConfigChange: (callback): (() => void) =>
      deps.userPreferences.onConfirmationConfigChange(callback),
    onCurrentWalletChange: (callback): (() => void) =>
      deps.userPreferences.onCurrentWalletChange(callback),
    setConfirmBehavior: (behavior): void => {
      const walletIframe = deps.getWalletIframe();
      if (walletIframe.shouldUseWalletIframe()) {
        void (async () => {
          try {
            const router = await walletIframe.requireRouter();
            await router.setConfirmBehavior(behavior);
          } catch {}
        })();
        return;
      }
      deps.userPreferences.setConfirmBehavior(behavior);
    },
    setConfirmationConfig: (config: ConfirmationConfig): void => {
      const walletIframe = deps.getWalletIframe();
      if (walletIframe.shouldUseWalletIframe()) {
        void (async () => {
          try {
            const router = await walletIframe.requireRouter();
            await router.setConfirmationConfig(config);
          } catch {}
        })();
        return;
      }
      deps.userPreferences.setConfirmationConfig(config);
    },
    getConfirmationConfig: (): ConfirmationConfig => deps.userPreferences.getConfirmationConfig(),
  };
}
