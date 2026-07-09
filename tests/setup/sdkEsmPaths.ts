export const SDK_ESM_BASE_PATH = '/_test-sdk/esm';

export function sdkEsmPath(subpath: string): string {
  const cleaned = String(subpath || '').replace(/^\/+/, '');
  return `${SDK_ESM_BASE_PATH}/${cleaned}`;
}

// Canonical browser-only dynamic imports from Playwright's test ESM route.
export const SDK_ESM_PATHS = {
  index: sdkEsmPath('index.js'),
  advanced: sdkEsmPath('advanced.js'),
  base64: sdkEsmPath('utils/base64.js'),
  accountIds: sdkEsmPath('core/types/accountIds.js'),
  actions: sdkEsmPath('core/types/actions.js'),
  seamsWeb: sdkEsmPath('SeamsWeb/index.js'),
  walletIframeRouter: sdkEsmPath('SeamsWeb/walletIframe/client/router.js'),
  confirmUi: sdkEsmPath('core/signingEngine/uiConfirm/ui/confirm-ui.js'),
  walletEvents: sdkEsmPath('core/browser/walletIframe/events.js'),
} as const;

export type SdkEsmPaths = typeof SDK_ESM_PATHS;
