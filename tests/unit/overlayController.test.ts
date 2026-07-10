import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  overlay: '/_test-sdk/esm/SeamsWeb/walletIframe/client/overlay/overlay-controller.js',
} as const;

test.describe('OverlayController', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('showFullscreen → visible + interactive, hide → invisible + inert', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.overlay);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        document.body.appendChild(iframe);
        const overlay = new OverlayController({ ensureIframe: () => iframe });

        overlay.showFullscreen();
        const afterShow = {
          pointerEvents: getComputedStyle(iframe).pointerEvents,
          ariaHidden: iframe.getAttribute('aria-hidden'),
          opacity: getComputedStyle(iframe).opacity,
        };

        overlay.hide();
        const afterHide = {
          pointerEvents: getComputedStyle(iframe).pointerEvents,
          ariaHidden: iframe.getAttribute('aria-hidden'),
          width: getComputedStyle(iframe).width,
          height: getComputedStyle(iframe).height,
          opacity: getComputedStyle(iframe).opacity,
        };

        return { afterShow, afterHide };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.afterShow.pointerEvents).toBe('auto');
    expect(res.afterShow.ariaHidden).toBe('false');
    expect(res.afterShow.opacity).toBe('1');

    expect(res.afterHide.pointerEvents).toBe('none');
    expect(res.afterHide.ariaHidden).toBe('true');
    expect(res.afterHide.width).toBe('0px');
    expect(res.afterHide.height).toBe('0px');
    expect(res.afterHide.opacity).toBe('0');
  });

  test('anchored positioning and sticky prevents hide', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.overlay);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        document.body.appendChild(iframe);
        const overlay = new OverlayController({ ensureIframe: () => iframe });

        overlay.showAnchored({ top: 10, left: 12, width: 123, height: 45 });
        const anchored = {
          top: getComputedStyle(iframe).top,
          left: getComputedStyle(iframe).left,
          width: getComputedStyle(iframe).width,
          height: getComputedStyle(iframe).height,
          ariaHidden: iframe.getAttribute('aria-hidden'),
          pointerEvents: getComputedStyle(iframe).pointerEvents,
        };

        overlay.setSticky(true);
        overlay.hide(); // should be ignored due to sticky
        const stateAfterHideAttempt = overlay.getState();

        overlay.setAnchoredRect({ top: 20, left: 22, width: 150, height: 60 });
        const afterUpdate = {
          top: getComputedStyle(iframe).top,
          left: getComputedStyle(iframe).left,
          width: getComputedStyle(iframe).width,
          height: getComputedStyle(iframe).height,
        };

        return { anchored, stateAfterHideAttempt, afterUpdate };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.anchored.top).toBe('10px');
    expect(res.anchored.left).toBe('12px');
    expect(res.anchored.width).toBe('123px');
    expect(res.anchored.height).toBe('45px');
    expect(res.anchored.ariaHidden).toBe('false');
    expect(res.anchored.pointerEvents).toBe('auto');

    expect(res.stateAfterHideAttempt.visible).toBe(true); // sticky prevented hide

    expect(res.afterUpdate.top).toBe('20px');
    expect(res.afterUpdate.left).toBe('22px');
    expect(res.afterUpdate.width).toBe('150px');
    expect(res.afterUpdate.height).toBe('60px');
  });

  test('forceHide clears sticky overlay lock and makes iframe inert', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.overlay);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        document.body.appendChild(iframe);
        const overlay = new OverlayController({ ensureIframe: () => iframe });

        overlay.showFullscreen();
        overlay.setSticky(true);
        overlay.hide();
        const afterStickyHide = overlay.getState();

        overlay.forceHide();
        const afterForceHide = {
          ...overlay.getState(),
          pointerEvents: getComputedStyle(iframe).pointerEvents,
          ariaHidden: iframe.getAttribute('aria-hidden'),
          width: getComputedStyle(iframe).width,
          height: getComputedStyle(iframe).height,
        };

        return { afterStickyHide, afterForceHide };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.afterStickyHide.visible).toBe(true);
    expect(res.afterStickyHide.sticky).toBe(true);
    expect(res.afterForceHide.visible).toBe(false);
    expect(res.afterForceHide.sticky).toBe(false);
    expect(res.afterForceHide.pointerEvents).toBe('none');
    expect(res.afterForceHide.ariaHidden).toBe('true');
    expect(res.afterForceHide.width).toBe('0px');
    expect(res.afterForceHide.height).toBe('0px');
  });

  test('anchored lease rejects unrelated fullscreen and hide mutations', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.overlay);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        document.body.appendChild(iframe);
        const overlay = new OverlayController({ ensureIframe: () => iframe });
        const lease = overlay.acquireAnchoredLease();
        if (!lease) throw new Error('Expected anchored overlay lease');
        overlay.showAnchoredForLease(lease, { top: 10, left: 12, width: 123, height: 45 });

        overlay.showFullscreen();
        overlay.forceHide();
        overlay.showAnchored({ top: 0, left: 0, width: 500, height: 500 });
        const whileLeased = {
          ...overlay.getState(),
          top: getComputedStyle(iframe).top,
          left: getComputedStyle(iframe).left,
          width: getComputedStyle(iframe).width,
          height: getComputedStyle(iframe).height,
        };

        const released = overlay.releaseAnchoredLease(lease);
        const afterRelease = overlay.getState();
        return { whileLeased, released, afterRelease };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.whileLeased.mode).toBe('anchored');
    expect(res.whileLeased.visible).toBe(true);
    expect(res.whileLeased.ownership).toBe('anchored_lease');
    expect(res.whileLeased.top).toBe('10px');
    expect(res.whileLeased.left).toBe('12px');
    expect(res.whileLeased.width).toBe('123px');
    expect(res.whileLeased.height).toBe('45px');
    expect(res.released).toBe(true);
    expect(res.afterRelease.visible).toBe(false);
    expect(res.afterRelease.ownership).toBe('unowned');
  });

  test('does not acquire an anchored lease over an existing visible surface', async ({ page }) => {
    const acquired = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.overlay);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        document.body.appendChild(iframe);
        const overlay = new OverlayController({ ensureIframe: () => iframe });
        overlay.showFullscreen();
        return overlay.acquireAnchoredLease() !== null;
      },
      { paths: IMPORT_PATHS },
    );

    expect(acquired).toBe(false);
  });
});
