import { expect, test } from '@playwright/test';

test.describe('export viewer host cleanup', () => {
  test('removeExportViewerHostIfPresent removes a mounted export viewer host', async ({ page }) => {
    await page.goto('/');

    const result = await page.evaluate(async () => {
      const mod = await import(
        new URL(
          '/_test-sdk/esm/react/core/signingEngine/uiConfirm/ui/export-viewer-host.js',
          window.location.origin,
        ).toString()
      );

      const staleHost = document.createElement('w3a-export-viewer-iframe');
      document.body.appendChild(staleHost);

      const before = !!document.querySelector('w3a-export-viewer-iframe');
      mod.removeExportViewerHostIfPresent();
      const after = !!document.querySelector('w3a-export-viewer-iframe');

      return { before, after };
    });

    expect(result.before).toBe(true);
    expect(result.after).toBe(false);
  });

  test('export viewer session state clears after host removal', async ({ page }) => {
    await page.goto('/');

    const result = await page.evaluate(async () => {
      const mod = await import(
        new URL(
          '/_test-sdk/esm/react/core/signingEngine/uiConfirm/ui/export-viewer-host.js',
          window.location.origin,
        ).toString()
      );

      const sessionId = 'near-ed25519-export-session-test';
      await mod.upsertExportViewerHost({
        theme: 'dark',
        variant: 'drawer',
        accountId: 'alice.testnet',
        sessionId,
        publicKey: 'ed25519:test-public-key',
        keys: [
          {
            scheme: 'ed25519',
            label: 'NEAR private key',
            publicKey: 'ed25519:test-public-key',
            privateKey: '',
          },
        ],
        loading: true,
      });

      const before = mod.isExportViewerSessionOpen(sessionId);
      mod.removeExportViewerHostIfPresent();
      const after = mod.isExportViewerSessionOpen(sessionId);
      const hostExists = !!document.querySelector('w3a-export-viewer-iframe');

      return { before, after, hostExists };
    });

    expect(result.before).toBe(true);
    expect(result.after).toBe(false);
    expect(result.hostExists).toBe(false);
  });
});
