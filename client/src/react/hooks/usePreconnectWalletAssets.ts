import React from 'react';
import type { SeamsContextProviderProps } from '../types';
import {
  normalizeWalletHostVariant,
} from '../../core/WalletIframe/hostVariant';
import { preconnectWalletAssets } from '../../web/SeamsWeb/assembly/preconnectWalletAssets';

// Internal: Add preconnect/prefetch hints for wallet service + relayer and
// expose an absolute embedded asset base for srcdoc iframes.
//
// What this hook does
// - Adds resource hints for the configured wallet origin (dns‑prefetch, preconnect, prefetch)
//   and modulepreload for the wallet host script.
// - Sets `window.__W3A_WALLET_SDK_BASE__` to an absolute `${walletOrigin}${sdkBasePath}/` so
//   any embedded srcdoc iframes created by the SDK load ESM bundles from the wallet origin,
//   not from the host app origin.
//
// Requirements
// - `config.iframeWallet.walletOrigin` points to the wallet site (e.g. https://web3authn.org)
// - `config.iframeWallet.sdkBasePath` (default '/sdk') is served on that wallet site
// - `config.iframeWallet.walletServicePath` (default '/wallet-service') is reachable
//
// Gotchas
// - Always resolve `${sdkBasePath}/...` with a trailing slash; otherwise `new URL('file', '/sdk')`
//   becomes `/file` instead of `/sdk/file`.
// - For cross‑origin module/worker imports, ensure the wallet site sends CORS headers for
//   `/sdk/*` and `/sdk/workers/*` (e.g. `Access-Control-Allow-Origin: *`) and `.wasm` has
//   `Content-Type: application/wasm`.
// - `/wallet-service` may 308 → `/wallet-service/` on Pages; both are fine.
export function usePreconnectWalletAssets(config: SeamsContextProviderProps['config']): void {
  // Derive stable primitives to avoid re-running the effect on object identity changes.
  const walletOrigin = config?.iframeWallet?.walletOrigin as string | undefined;
  const servicePath = config?.iframeWallet?.walletServicePath || '/wallet-service';
  const sdkBasePath = config?.iframeWallet?.sdkBasePath || '/sdk';
  const walletHostVariant = normalizeWalletHostVariant(config?.iframeWallet?.walletHostVariant);
  const relayerUrl = config?.relayer?.url as string | undefined;

  React.useEffect(() => {
    preconnectWalletAssets({
      walletOrigin,
      servicePath,
      sdkBasePath,
      walletHostVariant,
      relayerUrl,
    });
  }, [walletOrigin, servicePath, sdkBasePath, walletHostVariant, relayerUrl]);
}

export default usePreconnectWalletAssets;
