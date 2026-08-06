import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

test.describe('export viewer host cleanup', () => {
  test('removeExportViewerHostIfPresent removes a mounted export viewer host', async ({ page }) => {
    await setupBasicPasskeyTest(page);

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
    await setupBasicPasskeyTest(page);

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
        variant: 'modal',
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
        surfaceMeasurementBinding: { kind: 'disabled' },
      });

      const before = mod.isExportViewerSessionOpen(sessionId);
      const host = document.querySelector('w3a-export-viewer-iframe');
      const standaloneSurface = host?.getAttribute('data-w3a-export-surface');
      await mod.upsertExportViewerHost({
        theme: 'dark',
        variant: 'drawer',
        accountId: 'alice.testnet',
        sessionId,
        loading: true,
        surfaceMeasurementBinding: {
          kind: 'wallet_iframe',
          requestId: 'request-a',
          postMeasurement: () => undefined,
        },
      });
      const walletSurface = host?.getAttribute('data-w3a-export-surface');
      mod.removeExportViewerHostIfPresent();
      const after = mod.isExportViewerSessionOpen(sessionId);
      const hostExists = !!document.querySelector('w3a-export-viewer-iframe');

      return { before, after, hostExists, standaloneSurface, walletSurface };
    });

    expect(result.before).toBe(true);
    expect(result.after).toBe(false);
    expect(result.hostExists).toBe(false);
    expect(result.standaloneSurface).toBe('standalone');
    expect(result.walletSurface).toBe('wallet-iframe');
  });
});
