import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  overlay: '/_test-sdk/esm/SeamsWeb/walletIframe/client/overlay/overlay-controller.js',
} as const;

test.describe('OverlayController', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('viewport modal rendering is interactive and hidden rendering is inert', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.overlay);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        document.body.appendChild(iframe);
        const overlay = new OverlayController({ ensureIframe: () => iframe });

        overlay.applyViewportModal({ title: 'Confirm transaction' });
        const modal = {
          ...overlay.getState(),
          title: iframe.getAttribute('title'),
          pointerEvents: getComputedStyle(iframe).pointerEvents,
          ariaHidden: iframe.getAttribute('aria-hidden'),
        };
        overlay.applyHidden();
        const hidden = {
          ...overlay.getState(),
          width: getComputedStyle(iframe).width,
          height: getComputedStyle(iframe).height,
        };

        return { modal, hidden };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.modal.visible).toBe(true);
    expect(res.modal.title).toBe('Confirm transaction');
    expect(res.modal.pointerEvents).toBe('auto');
    expect(res.modal.ariaHidden).toBe('false');
    expect(res.hidden.visible).toBe(false);
    expect(res.hidden.width).toBe('0px');
    expect(res.hidden.height).toBe('0px');
  });

  test('surface render writes derive title, focusability, and suspended hit testing', async ({
    page,
  }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.overlay);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        document.body.appendChild(iframe);
        const overlay = new OverlayController({ ensureIframe: () => iframe });
        overlay.applyAnchored(
          { top: 10, left: 12, width: 123, height: 45 },
          { title: 'Create passkey' },
        );
        const interactive = {
          ...overlay.getState(),
          title: iframe.getAttribute('title'),
          ariaHidden: iframe.getAttribute('aria-hidden'),
          pointerEvents: getComputedStyle(iframe).pointerEvents,
        };
        overlay.applyAnchoredSuspended({ title: 'Create passkey' });
        const suspended = {
          ...overlay.getState(),
          title: iframe.getAttribute('title'),
          ariaHidden: iframe.getAttribute('aria-hidden'),
          tabindex: iframe.getAttribute('tabindex'),
          pointerEvents: getComputedStyle(iframe).pointerEvents,
        };
        overlay.applyHidden();
        const hidden = {
          ...overlay.getState(),
          title: iframe.getAttribute('title'),
          ariaHidden: iframe.getAttribute('aria-hidden'),
          pointerEvents: getComputedStyle(iframe).pointerEvents,
        };
        return { interactive, suspended, hidden };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.interactive.visible).toBe(true);
    expect(res.interactive.title).toBe('Create passkey');
    expect(res.interactive.ariaHidden).toBe('false');
    expect(res.interactive.pointerEvents).toBe('auto');
    expect(res.suspended.mode).toBe('anchored');
    expect(res.suspended.suspended).toBe(true);
    expect(res.suspended.title).toBe('Create passkey');
    expect(res.suspended.ariaHidden).toBe('true');
    expect(res.suspended.tabindex).toBe('-1');
    expect(res.suspended.pointerEvents).toBe('none');
    expect(res.hidden.mode).toBe('hidden');
    expect(res.hidden.title).toBeNull();
    expect(res.hidden.ariaHidden).toBe('true');
    expect(res.hidden.pointerEvents).toBe('none');
  });
});
