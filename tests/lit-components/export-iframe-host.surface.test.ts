import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

/**
 * The wallet-iframe export surface is MEASURED: the parent derives the wallet
 * iframe's height from this element's own height. Any viewport-derived sizing
 * (dvh/vh) is therefore a feedback loop — the element re-measures shorter on
 * every pass and converges to a 0-tall card, which shipped as "the export
 * drawer no longer appears".
 *
 * The invariant is not a particular pixel height; it is that the height is
 * independent of the viewport the element sits in. Assert it directly by
 * resizing the window and requiring the height to hold still.
 */

const IFRAME_HOST_MODULE =
  '/_test-sdk/esm/core/signingEngine/uiConfirm/ui/lit-components/ExportPrivateKey/iframe-host.js';
const EXPORT_IFRAME_HOST_TAG = 'w3a-export-viewer-iframe';

test.describe('export iframe host wallet-iframe surface sizing', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(200);
  });

  test('measured surface height is viewport-independent and non-zero', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });

    const mount = await page.evaluate(
      async ({ modulePath, tagName }) => {
        try {
          await import(modulePath);
          const el = document.createElement(tagName);
          el.setAttribute('data-w3a-export-surface', 'wallet-iframe');
          document.body.appendChild(el);
          await customElements.whenDefined(tagName);
          // Styles are adopted asynchronously by the css loader; wait for a
          // non-auto block-size instead of sleeping.
          const deadline = Date.now() + 4000;
          while (Date.now() < deadline) {
            const height = (el as HTMLElement).offsetHeight;
            if (height > 0) return { success: true, height } as const;
            await new Promise((resolve) => setTimeout(resolve, 50));
          }
          return { success: false, error: 'element never received a height' } as const;
        } catch (error: any) {
          return { success: false, error: error?.message || String(error) } as const;
        }
      },
      { modulePath: IFRAME_HOST_MODULE, tagName: EXPORT_IFRAME_HOST_TAG },
    );

    expect(mount.success, 'error' in mount ? mount.error : '').toBe(true);
    if (!mount.success) return;

    // Sanity: the design height, not a viewport-derived one. 36rem at the
    // default 16px root.
    expect(mount.height).toBe(576);

    // The loop-breaker: shrink the viewport well below the element's height.
    // A dvh-derived height would follow the window down (the first step of the
    // collapse); a constant height holds.
    await page.setViewportSize({ width: 500, height: 300 });
    const shrunkHeight = await page.evaluate(
      ({ tagName }) => (document.querySelector(tagName) as HTMLElement).offsetHeight,
      { tagName: EXPORT_IFRAME_HOST_TAG },
    );
    expect(shrunkHeight).toBe(mount.height);
  });
});
