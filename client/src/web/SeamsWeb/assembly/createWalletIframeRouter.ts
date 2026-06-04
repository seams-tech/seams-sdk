import { cloneAuthenticatorOptions } from '@/core/types/authenticatorOptions';
import type { ThemeName, SeamsConfigsReadonly } from '@/core/types/seams';
import type { WalletIframeRouter } from '@/core/WalletIframe/client/router';
import { createWalletIframeOverlayState } from './createWalletIframeOverlayState';

let warnedAboutSameOriginWallet = false;

function warnIfSameOriginWallet(walletOrigin: string): void {
  if (warnedAboutSameOriginWallet) return;
  try {
    const parsed = new URL(walletOrigin);
    if (typeof window !== 'undefined' && parsed.origin === window.location.origin) {
      warnedAboutSameOriginWallet = true;
      console.warn(
        '[SeamsWeb] wallet.iframe.origin matches the host origin. Consider moving the wallet to a dedicated origin for stronger isolation.',
      );
    }
  } catch {}
}

export async function createWalletIframeRouter(args: {
  configs: SeamsConfigsReadonly;
  walletOrigin: string;
  getTheme: () => ThemeName;
}): Promise<WalletIframeRouter> {
  warnIfSameOriginWallet(args.walletOrigin);

  const { WalletIframeRouter } = await import('@/core/WalletIframe/client/router');
  const signingSessionPersistenceMode = args.configs.signing.sessionPersistenceMode;
  const signingSessionSeal =
    signingSessionPersistenceMode === 'sealed_refresh_v1'
      ? args.configs.signing.sessionSeal
      : undefined;
  return new WalletIframeRouter({
    walletOrigin: args.walletOrigin,
    servicePath: args.configs.wallet.iframe?.servicePath || '/wallet-service',
    connectTimeoutMs: 20_000,
    requestTimeoutMs: 60_000,
    chains: args.configs.network.chains,
    relayerAccount: args.configs.network.relayer.accountId,
    relayer: args.configs.network.relayer,
    registration: args.configs.registration,
    signingSessionDefaults: args.configs.signing.sessionDefaults,
    signingSessionPersistenceMode,
    ...(signingSessionSeal ? { signingSessionSeal } : {}),
    thresholdEcdsaPresignPool: args.configs.signing.thresholdEcdsa.presignPool,
    provisioningDefaults: args.configs.signing.thresholdEcdsa.provisioningDefaults,
    rpIdOverride: args.configs.wallet.iframe?.rpIdOverride,
    authenticatorOptions: cloneAuthenticatorOptions(args.configs.webauthn.authenticatorOptions),
    appearance: {
      theme: args.getTheme(),
      tokens: args.configs.ui.appearance?.tokens,
    },
    sdkBasePath: args.configs.wallet.iframe?.sdkBasePath,
    createOverlayState: createWalletIframeOverlayState,
  });
}
