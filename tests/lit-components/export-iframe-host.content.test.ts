import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

/**
 * The direct-mount export host must actually compose the drawer + viewer —
 * the drawer sheet with an EMPTY body is exactly how the removed nested-iframe
 * layer's regression presented. This drives the host the way export-viewer-host
 * does for the ECDSA loading state and asserts real, visible viewer content.
 */

const IFRAME_HOST_MODULE =
  '/_test-sdk/esm/core/signingEngine/uiConfirm/ui/lit-components/ExportPrivateKey/iframe-host.js';
const HOST_TAG = 'w3a-export-viewer-iframe';

test.describe('export host renders drawer + viewer content directly', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(200);
  });

  test('loading export state shows a non-empty viewer inside the drawer slot', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ modulePath, tagName }) => {
        try {
          await import(modulePath);
          const host = document.createElement(tagName) as HTMLElement & {
            theme?: string;
            variant?: string;
            accountId?: string;
            publicKey?: string;
            keys?: unknown[];
            loading?: boolean;
          };
          host.setAttribute('data-w3a-export-surface', 'wallet-iframe');
          host.theme = 'light';
          host.variant = 'modal';
          host.accountId = 'export-content.testnet';
          host.publicKey = '0x02abcd';
          host.loading = true;
          host.keys = [
            {
              scheme: 'secp256k1',
              label: 'EVM',
              publicKey: '0x02abcd',
              privateKey: '',
              address: '0x1234567890abcdef1234567890abcdef12345678',
            },
          ];
          document.body.appendChild(host);

          const deadline = Date.now() + 6000;
          const snapshot = () => {
            const drawer = host.querySelector('w3a-drawer');
            const viewer = host.querySelector('w3a-export-key-viewer') as HTMLElement | null;
            const aboveFold = drawer?.querySelector('.above-fold') ?? null;
            return {
              hostHeight: host.offsetHeight,
              drawerDefined: !!customElements.get('w3a-drawer'),
              viewerDefined: !!customElements.get('w3a-export-key-viewer'),
              aboveFoldExists: !!aboveFold,
              drawerChildren: drawer
                ? Array.from(drawer.children).map((c) => c.tagName.toLowerCase() + '.' + c.className)
                : [],
              hostChildren: Array.from(host.children).map((c) => c.tagName.toLowerCase()),
              drawerExists: !!drawer,
              drawerOpen: drawer?.hasAttribute('open') ?? false,
              viewerExists: !!viewer,
              viewerInSlot: !!(viewer && aboveFold && aboveFold.contains(viewer)),
              viewerHeight: viewer?.offsetHeight ?? 0,
              sheetHeight: (drawer?.querySelector('.drawer') as HTMLElement | null)?.offsetHeight ?? 0,
            };
          };
          let last = snapshot();
          while (Date.now() < deadline) {
            last = snapshot();
            if (last.viewerInSlot && last.viewerHeight > 100 && last.drawerOpen) break;
            await new Promise((resolve) => setTimeout(resolve, 100));
          }
          return { success: true, ...last } as const;
        } catch (error: any) {
          return { success: false, error: error?.message || String(error) } as const;
        }
      },
      { modulePath: IFRAME_HOST_MODULE, tagName: HOST_TAG },
    );

    expect(result.success, JSON.stringify(result, null, 2)).toBe(true);
    if (!result.success) return;
    expect(result.drawerExists).toBe(true);
    expect(result.viewerExists).toBe(true);
    expect(result.viewerInSlot).toBe(true);
    expect(result.drawerOpen).toBe(true);
    // The loading scaffold renders a real key layout, not an empty sheet.
    expect(result.viewerHeight).toBeGreaterThan(100);
    expect(result.sheetHeight).toBeGreaterThan(150);
  });
});
