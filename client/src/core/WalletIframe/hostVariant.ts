export type WalletHostVariant = 'runtime' | 'full' | 'near' | 'ecdsa';

export function normalizeWalletHostVariant(value: unknown): WalletHostVariant {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  switch (normalized) {
    case '':
    case 'runtime':
      return 'runtime';
    case 'full':
      return 'full';
    case 'near':
      return 'near';
    case 'ecdsa':
      return 'ecdsa';
    default:
      throw new Error(`Unsupported wallet host variant: ${normalized}`);
  }
}

export function walletHostScriptFileForVariant(variant: WalletHostVariant): string {
  switch (variant) {
    case 'runtime':
      return 'wallet-iframe-host-runtime.js';
    case 'full':
      return 'wallet-iframe-host-full.js';
    case 'near':
      return 'wallet-iframe-host-near.js';
    case 'ecdsa':
      return 'wallet-iframe-host-ecdsa.js';
  }
}
