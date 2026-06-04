import { __isWalletIframeHostMode } from '@/core/WalletIframe/host-mode';
import { configureIndexedDB } from '@/core/indexedDB';
import type { SeamsConfigsReadonly } from '@/core/types/seams';

export function configureBrowserIndexedDB(config: SeamsConfigsReadonly): void {
  const mode = __isWalletIframeHostMode()
    ? 'wallet'
    : config.wallet.mode === 'iframe'
      ? 'disabled'
      : 'app';
  configureIndexedDB({ mode });
}
