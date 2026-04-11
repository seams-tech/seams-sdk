import { expect, test } from '@playwright/test';

test.describe('export viewer host cleanup', () => {
  test('removeExportViewerHostIfPresent removes a mounted export viewer host', async ({ page }) => {
    await page.goto('/');

    const result = await page.evaluate(async () => {
      const mod = await import(
        new URL(
          '/sdk/esm/react/core/signingEngine/touchConfirm/ui/export-viewer-host.js',
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
});
