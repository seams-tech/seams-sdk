import OverlayController from '@/SeamsWeb/walletIframe/client/overlay/overlay-controller';
import type { WalletIframeOverlayState } from '@/SeamsWeb/walletIframe/client/router';

export function createWalletIframeOverlayState(args: {
  ensureIframe: () => HTMLIFrameElement;
}): WalletIframeOverlayState {
  return {
    controller: new OverlayController({
      ensureIframe: args.ensureIframe,
    }),
  };
}
