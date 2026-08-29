import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';
import { SDK_ESM_BASE_PATH } from '../setup/sdkEsmPaths';

const WALLET_HOST_ENTRY = '/_test-sdk/esm/sdk/wallet-iframe-host-runtime.js';

test('full wallet host preloads the lightweight recovery runtime and Lit surface at boot', async ({
  page,
}) => {
  const requestedPaths = new Set<string>();
  page.on('request', (request) => {
    requestedPaths.add(new URL(request.url()).pathname);
  });
  await page.goto('/');
  await injectImportMap(page);
  await page.evaluate((base) => {
    (window as typeof window & { __W3A_WALLET_SDK_BASE__?: string }).__W3A_WALLET_SDK_BASE__ = base;
  }, `${SDK_ESM_BASE_PATH}/sdk/`);

  await page.evaluate(async (entry) => {
    await import(entry);
  }, WALLET_HOST_ENTRY);

  await expect
    .poll(async () => {
      return {
        recoveryElementDefined: await page.evaluate(() =>
          Boolean(customElements.get('w3a-recovery-code-backup-host')),
        ),
        recoveryRuntimeStarted: Array.from(requestedPaths).some((name) =>
          name.includes('/runtime-recovery-codes-'),
        ),
        fullWalletRuntimeStarted: Array.from(requestedPaths).some((name) =>
          name.includes('/runtimeContext-'),
        ),
      };
    })
    .toEqual({
      recoveryElementDefined: true,
      recoveryRuntimeStarted: true,
      fullWalletRuntimeStarted: false,
    });
});
