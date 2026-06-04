import OverlayController from '@/core/WalletIframe/client/overlay/overlay-controller';
import type { WalletIframeOverlayState } from '@/core/WalletIframe/client/router';

export function createWalletIframeOverlayState(args: {
  ensureIframe: () => HTMLIFrameElement;
}): WalletIframeOverlayState {
  return {
    controller: new OverlayController({
      ensureIframe: args.ensureIframe,
    }),
    forceFullscreen: false,
  };
}
