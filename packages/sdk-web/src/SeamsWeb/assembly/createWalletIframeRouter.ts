import { cloneAuthenticatorOptions } from '@/core/types/authenticatorOptions';
import type { AppearanceConfig, SeamsConfigsReadonly } from '@/core/types/seams';
import type { WalletIframeRouter } from '@/SeamsWeb/walletIframe/client/router';
import { signingSessionSealInputFromReadonly } from '@/SeamsWeb/walletIframe/shared/signingSessionSealConfig';
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
  getAppearance: () => AppearanceConfig;
}): Promise<WalletIframeRouter> {
  warnIfSameOriginWallet(args.walletOrigin);

  const { WalletIframeRouter } = await import('@/SeamsWeb/walletIframe/client/router');
  const signingSessionPersistenceMode = args.configs.signing.sessionPersistenceMode;
  const signingSessionSeal =
    signingSessionPersistenceMode === 'sealed_refresh_v1'
      ? signingSessionSealInputFromReadonly(args.configs.signing.sessionSeal)
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
    routerAb: args.configs.signing.routerAb,
    routerAbEcdsaHssPresignaturePool: args.configs.signing.routerAbEcdsaHss.presignaturePool,
    provisioningDefaults: args.configs.signing.thresholdEcdsa.provisioningDefaults,
    rpIdOverride: args.configs.wallet.iframe?.rpIdOverride,
    authenticatorOptions: cloneAuthenticatorOptions(args.configs.webauthn.authenticatorOptions),
    appearance: args.getAppearance(),
    sdkBasePath: args.configs.wallet.iframe?.sdkBasePath,
    createOverlayState: createWalletIframeOverlayState,
  });
}
