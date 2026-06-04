import type { PreferencesChangedPayload } from '@/core/WalletIframe/shared/messages';
import type { WalletIframeCoordinator } from '../walletIframeCoordinator';

export interface WalletIframeControlCapability {
  initWalletIframe(walletId?: string): Promise<void>;
  isWalletIframeReady(): boolean;
  onWalletIframeReady(listener: () => void): () => void;
  onWalletIframeLoginStatusChanged(
    listener: (status: { isLoggedIn: boolean; walletId: string | null }) => void,
  ): () => void;
  onWalletIframePreferencesChanged(listener: (payload: PreferencesChangedPayload) => void): () => void;
}

export function createWalletIframeControlCapability(deps: {
  getWalletIframe: () => WalletIframeCoordinator;
}): WalletIframeControlCapability {
  return {
    initWalletIframe: async (walletId?: string): Promise<void> => {
      await deps.getWalletIframe().init(walletId);
    },
    isWalletIframeReady: (): boolean => deps.getWalletIframe().isReady(),
    onWalletIframeReady: (listener): (() => void) => deps.getWalletIframe().onReady(listener),
    onWalletIframeLoginStatusChanged: (listener): (() => void) =>
      deps.getWalletIframe().onLoginStatusChanged(listener),
    onWalletIframePreferencesChanged: (listener): (() => void) =>
      deps.getWalletIframe().onPreferencesChanged(listener),
  };
}
