import {
  normalizeWalletHostVariant,
  walletHostScriptFileForVariant,
} from '@/core/browser/walletIframe/hostVariant';
import { setEmbeddedBase } from '@/core/walletRuntimePaths';
import type { SeamsConfigsInput } from '@/core/types/seams';

export type PreconnectWalletAssetsArgs = {
  walletOrigin?: string;
  servicePath: string;
  sdkBasePath: string;
  walletHostVariant: ReturnType<typeof normalizeWalletHostVariant>;
  relayerUrl?: string;
};

function ensureLink(rel: string, href?: string, attrs?: Record<string, string>): void {
  try {
    if (!href) return;
    const head = document.head || document.getElementsByTagName('head')[0];
    if (!head) return;
    const selector = `link[rel="${rel}"][href="${href}"]`;
    if (head.querySelector(selector)) return;
    const link = document.createElement('link');
    link.rel = rel;
    link.href = href;
    if (attrs) {
      for (const [key, value] of Object.entries(attrs)) {
        try {
          link.setAttribute(key, value);
        } catch {}
      }
    }
    head.appendChild(link);
  } catch {}
}

export function preconnectWalletAssets(args: PreconnectWalletAssetsArgs): void {
  try {
    if (typeof document === 'undefined') return;
    let isCrossOrigin = false;
    let walletOriginOrigin: string | undefined;
    try {
      if (args.walletOrigin) {
        walletOriginOrigin = new URL(args.walletOrigin, window.location.href).origin;
        isCrossOrigin = walletOriginOrigin !== window.location.origin;
        if (isCrossOrigin) {
          const withSlash = args.sdkBasePath.endsWith('/')
            ? args.sdkBasePath
            : `${args.sdkBasePath}/`;
          setEmbeddedBase(new URL(withSlash, walletOriginOrigin).toString());
        }
      }
    } catch {}

    if (args.walletOrigin) {
      ensureLink('dns-prefetch', args.walletOrigin);
      ensureLink('preconnect', args.walletOrigin, { crossorigin: '' });

      if (!isCrossOrigin) {
        try {
          ensureLink('prefetch', new URL(args.servicePath, args.walletOrigin).toString(), {
            as: 'document',
          });
        } catch {}
      }

      try {
        const withSlash = args.sdkBasePath.endsWith('/')
          ? args.sdkBasePath
          : `${args.sdkBasePath}/`;
        const base = new URL(withSlash, args.walletOrigin);
        ensureLink(
          'modulepreload',
          new URL(walletHostScriptFileForVariant(args.walletHostVariant), base).toString(),
          { crossorigin: '' },
        );
        ensureLink('prefetch', new URL('workers/wasm_signer_worker_bg.wasm', base).toString(), {
          as: 'fetch',
          crossorigin: '',
          type: 'application/wasm',
        });
      } catch {}
    }

    if (args.relayerUrl) {
      ensureLink('dns-prefetch', args.relayerUrl);
      ensureLink('preconnect', args.relayerUrl, { crossorigin: '' });
    }
  } catch {}
}

export function preconnectWalletAssetsFromConfig(config: SeamsConfigsInput): void {
  preconnectWalletAssets({
    walletOrigin: config?.iframeWallet?.walletOrigin,
    servicePath: config?.iframeWallet?.walletServicePath || '/wallet-service',
    sdkBasePath: config?.iframeWallet?.sdkBasePath || '/sdk',
    walletHostVariant: normalizeWalletHostVariant(config?.iframeWallet?.walletHostVariant),
    relayerUrl: config?.relayer?.url,
  });
}
