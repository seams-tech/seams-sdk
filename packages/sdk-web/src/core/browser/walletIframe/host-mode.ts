// Internal process-wide flag to mark wallet iframe host mode
let IS_WALLET_IFRAME_HOST = false;

export function __setWalletIframeHostMode(enabled: boolean = true): void {
  IS_WALLET_IFRAME_HOST = !!enabled;
}

function readForcedHostModeFlag(): boolean | undefined {
  try {
    const forced = (globalThis as Record<string, unknown>).__W3A_TEST_WALLET_IFRAME_HOST_MODE__;
    return typeof forced === 'boolean' ? forced : undefined;
  } catch {
    return undefined;
  }
}

export function __isWalletIframeHostMode(): boolean {
  // Test-only escape hatch: allow Playwright/unit tests to force host-mode behavior
  // without importing internal host bootstrap modules (which may be tree-shaken from dist/esm).
  const forced = readForcedHostModeFlag();
  if (forced !== undefined) return forced;
  return IS_WALLET_IFRAME_HOST;
}
