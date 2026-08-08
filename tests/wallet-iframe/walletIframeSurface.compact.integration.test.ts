import { expect, test, type Page } from '@playwright/test';
import type { HostedAuthMenuOpenRequest } from '@/SeamsWeb/walletIframe/shared/messages';
import { setupBasicPasskeyTest } from '../setup';
import { injectImportMap } from '../setup/bootstrap';
import { buildWalletServiceHtml, registerWalletServiceRoute } from './harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const OWNER_TAG = 'compact-surface-test';

type SurfaceMeasurementPayload = Record<string, unknown>;

/**
 * The wallet-host harness owns the MessagePort, so tests route synthetic
 * measurements through the child window and into that port. Tracking the
 * current/previous open lets replacement assertions use real request IDs.
 */
const SURFACE_MEASUREMENT_HARNESS_SCRIPT = String.raw`
      let currentSurface = null;
      let previousSurface = null;
      let exactSessionReadCount = 0;
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const message = event.data || {};
          if (!message || typeof message !== 'object') return;
          if (message.type === 'PM_GET_EXACT_WALLET_SESSION_STATE') {
            exactSessionReadCount += 1;
            window.parent?.postMessage({
              type: 'TEST_EXACT_SESSION_READ_COUNT',
              count: exactSessionReadCount,
            }, '*');
          }
          if (message.type !== 'PM_OPEN_AUTH_MENU' || typeof message.requestId !== 'string') return;
          previousSurface = currentSurface;
          currentSurface = {
            requestId: message.requestId,
            authMenuSessionId: message.payload?.authMenuSessionId,
          };
          window.parent?.postMessage({ type: 'TEST_SURFACE_OPEN', ...currentSurface }, '*');
        };
      };

      const markerValue = (value, field) => {
        if (value === '__current__') return currentSurface?.[field];
        if (value === '__previous__') return previousSurface?.[field];
        return value;
      };

      window.addEventListener('message', (event) => {
        const data = event.data || {};
        if (!data || typeof data !== 'object') return;
        if (data.type === 'TEST_POST_SURFACE_MEASUREMENT') {
          if (!adoptedPort) return;
          const rawPayload = data.payload;
          const payload = rawPayload && typeof rawPayload === 'object'
            ? { ...rawPayload }
            : rawPayload;
          if (payload && typeof payload === 'object') {
            payload.requestId = markerValue(payload.requestId, 'requestId');
            payload.authMenuSessionId = markerValue(
              payload.authMenuSessionId,
              'authMenuSessionId',
            );
          }
          adoptedPort.postMessage({ type: 'SURFACE_MEASUREMENT', payload });
          return;
        }
        if (data.type === 'TEST_COMPLETE_SURFACE' && adoptedPort && currentSurface) {
          pendingRequests.delete(currentSurface.requestId);
          adoptedPort.postMessage({
            type: 'PM_RESULT',
            requestId: currentSurface.requestId,
            payload: {
              ok: true,
              result: {
                kind: 'cancelled',
                authMenuSessionId: currentSurface.authMenuSessionId,
                reason: 'close_button',
              },
            },
          });
        }
      });
`;

type TestWindow = Window & {
  __compactSurfaceRouter?: {
    init: () => Promise<void>;
    dispose: () => void;
    getOverlayState: () => { visible: boolean };
    getExactSessionState: () => Promise<unknown>;
    openHostedAuthMenu: (
      request: HostedAuthMenuOpenRequest,
      anchorElement?: HTMLElement,
    ) => Promise<unknown>;
  };
  __compactSurfaceOpen?: {
    requestId: string;
    authMenuSessionId: string;
  };
  __compactSurfaceTimeoutDelays?: number[];
  __compactExactSessionReadCount?: number;
  __compactSurfaceMessageListenerInstalled?: boolean;
};

type StartHostedAuthMenuOptions = {
  anchorZoom?: number;
  anchorInFlow?: boolean;
  captureRequestTimeouts?: boolean;
};

async function startHostedAuthMenu(
  page: Page,
  sessionId: string,
  options: StartHostedAuthMenuOptions = {},
) {
  await page.evaluate(
    async ({
      walletOrigin,
      ownerTag,
      sessionId,
      anchorZoom,
      anchorInFlow,
      captureRequestTimeouts,
    }) => {
      const testWindow = window as TestWindow;
      if (!testWindow.__compactSurfaceMessageListenerInstalled) {
        window.addEventListener('message', (event) => {
          if (event.data?.type === 'TEST_EXACT_SESSION_READ_COUNT') {
            testWindow.__compactExactSessionReadCount = Number(event.data.count);
            return;
          }
          if (event.data?.type !== 'TEST_SURFACE_OPEN') return;
          testWindow.__compactSurfaceOpen = {
            requestId: String(event.data.requestId),
            authMenuSessionId: String(event.data.authMenuSessionId),
          };
        });
        testWindow.__compactSurfaceMessageListenerInstalled = true;
      }

      let router = testWindow.__compactSurfaceRouter;
      if (!router) {
        const routerModule = await import('/_test-sdk/esm/SeamsWeb/walletIframe/client/router.js');
        const newRouter = new routerModule.WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          sdkBasePath: '/sdk',
          relayer: { url: window.location.origin },
          registration: {
            projectEnvironmentId: 'proj_local:test',
            publishableKey: 'pk_local',
          },
          requestTimeoutMs: 10_000,
          testOptions: { ownerTag },
        });
        await newRouter.init();
        router = newRouter;
        testWindow.__compactSurfaceRouter = newRouter;
      } else {
        await router.init();
      }

      const messages = await import('/_test-sdk/esm/SeamsWeb/walletIframe/shared/messages.js');
      const request = messages.buildHostedAuthMenuOpenRequest({
        authMenuSessionId: sessionId,
        initialMode: 'login',
        registrationAccountInput: 'implicit_wallet',
        showRegistrationInput: false,
        showProgress: true,
        enabledExternalProviders: [],
      });
      let anchorElement: HTMLElement | undefined;
      if (typeof anchorZoom === 'number') {
        anchorElement = document.createElement('div');
        anchorElement.style.position = 'fixed';
        anchorElement.style.top = '100px';
        anchorElement.style.left = '80px';
        anchorElement.style.width = '420px';
        anchorElement.style.height = '430px';
        anchorElement.style.setProperty('zoom', String(anchorZoom));
        document.body.appendChild(anchorElement);
      } else if (anchorInFlow) {
        const spacer = document.createElement('div');
        spacer.style.height = '1200px';
        document.body.appendChild(spacer);
        anchorElement = document.createElement('div');
        anchorElement.dataset.testAuthMenuAnchor = 'true';
        anchorElement.style.width = '420px';
        anchorElement.style.height = '430px';
        document.body.appendChild(anchorElement);
        const tail = document.createElement('div');
        tail.style.height = '1200px';
        document.body.appendChild(tail);
      }
      const nativeSetTimeout = window.setTimeout;
      const timeoutDelays: number[] = [];
      if (captureRequestTimeouts) {
        window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) => {
          timeoutDelays.push(Number(timeout ?? 0));
          return nativeSetTimeout(handler, timeout, ...args);
        }) as typeof window.setTimeout;
      }
      try {
        void router.openHostedAuthMenu(request, anchorElement).catch(() => undefined);
      } finally {
        window.setTimeout = nativeSetTimeout;
        testWindow.__compactSurfaceTimeoutDelays = timeoutDelays;
      }
    },
    {
      walletOrigin: WALLET_ORIGIN,
      ownerTag: OWNER_TAG,
      sessionId,
      anchorZoom: options.anchorZoom,
      anchorInFlow: options.anchorInFlow,
      captureRequestTimeouts: options.captureRequestTimeouts,
    },
  );

  await page.waitForFunction(
    ({ sessionId }) => {
      const testWindow = window as TestWindow;
      return testWindow.__compactSurfaceOpen?.authMenuSessionId === sessionId;
    },
    { sessionId },
  );
  await page.waitForFunction(() => {
    const testWindow = window as TestWindow;
    return testWindow.__compactSurfaceRouter?.getOverlayState().visible === true;
  });
}

async function readDialogGeometry(page: Page) {
  return page.evaluate(() => {
    const dialog = document.querySelector('dialog.w3a-wallet-overlay-dialog');
    if (!(dialog instanceof HTMLDialogElement)) throw new Error('wallet overlay dialog missing');
    const rect = dialog.getBoundingClientRect();
    return {
      className: dialog.className,
      width: rect.width,
      height: rect.height,
      top: rect.top,
      left: rect.left,
      transitionDuration: getComputedStyle(dialog).transitionDuration,
      transitionTimingFunction: getComputedStyle(dialog).transitionTimingFunction,
    };
  });
}

async function waitForDialogGeometry(
  page: Page,
  expected: { width: number; height: number },
): Promise<void> {
  await page.waitForFunction(
    ({ expected }) => {
      const dialog = document.querySelector('dialog.w3a-wallet-overlay-dialog');
      if (!(dialog instanceof HTMLDialogElement)) return false;
      const rect = dialog.getBoundingClientRect();
      return (
        Math.abs(rect.width - expected.width) < 1 && Math.abs(rect.height - expected.height) < 1
      );
    },
    { expected },
  );
}

async function waitForMeasuredDialog(page: Page): Promise<void> {
  await page.waitForFunction(() => {
    const dialog = document.querySelector('dialog.w3a-wallet-overlay-dialog');
    return dialog instanceof HTMLDialogElement && !dialog.classList.contains('is-provisional');
  });
}

async function postSurfaceMeasurement(
  page: Page,
  payload: SurfaceMeasurementPayload,
): Promise<void> {
  await page.evaluate(
    ({ walletOrigin, ownerTag, payload }) => {
      const iframe = document.querySelector(
        `iframe[data-w3a-owner="${ownerTag}"]`,
      ) as HTMLIFrameElement | null;
      if (!iframe?.contentWindow) throw new Error('wallet iframe missing');
      iframe.contentWindow.postMessage(
        { type: 'TEST_POST_SURFACE_MEASUREMENT', payload },
        walletOrigin,
      );
    },
    { walletOrigin: WALLET_ORIGIN, ownerTag: OWNER_TAG, payload },
  );
}

async function completeCurrentSurface(page: Page): Promise<void> {
  await page.evaluate(
    ({ walletOrigin, ownerTag }) => {
      const iframe = document.querySelector(
        `iframe[data-w3a-owner="${ownerTag}"]`,
      ) as HTMLIFrameElement | null;
      if (!iframe?.contentWindow) throw new Error('wallet iframe missing');
      iframe.contentWindow.postMessage({ type: 'TEST_COMPLETE_SURFACE' }, walletOrigin);
    },
    { walletOrigin: WALLET_ORIGIN, ownerTag: OWNER_TAG },
  );
  await page.waitForFunction(() => {
    const testWindow = window as TestWindow;
    return testWindow.__compactSurfaceRouter?.getOverlayState().visible === false;
  });
}

test.describe('wallet iframe compact surface measurement routing', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, {
      skipSeamsWebInit: true,
      injectWalletServiceImportMap: true,
    });
    await page.goto('about:blank');
    await injectImportMap(page);
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: SURFACE_MEASUREMENT_HARNESS_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );
  });

  test.afterEach(async ({ page }) => {
    await page.evaluate(() => {
      const testWindow = window as TestWindow;
      testWindow.__compactSurfaceRouter?.dispose();
      delete testWindow.__compactSurfaceRouter;
    });
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('keeps an unmeasured surface hidden through its initial paints', async ({ page }) => {
    await startHostedAuthMenu(page, 'compact-initial-paint-session');

    const initialPaint = await page.evaluate(() => {
      const dialog = document.querySelector('dialog.w3a-wallet-overlay-dialog');
      if (!(dialog instanceof HTMLDialogElement)) throw new Error('wallet overlay dialog missing');
      return {
        provisional: dialog.classList.contains('is-provisional'),
        visibility: getComputedStyle(dialog).visibility,
      };
    });
    expect(initialPaint).toEqual({ provisional: true, visibility: 'hidden' });

    await page.waitForTimeout(150);
    const settledPaint = await page.evaluate(() => {
      const dialog = document.querySelector('dialog.w3a-wallet-overlay-dialog');
      if (!(dialog instanceof HTMLDialogElement)) throw new Error('wallet overlay dialog missing');
      return {
        provisional: dialog.classList.contains('is-provisional'),
        visibility: getComputedStyle(dialog).visibility,
      };
    });
    expect(settledPaint).toEqual({ provisional: true, visibility: 'hidden' });
  });

  test('ignores malformed, stale, and mismatched measurements before accepting a newer size', async ({
    page,
  }) => {
    await startHostedAuthMenu(page, 'compact-measurement-session');
    await waitForMeasuredDialog(page);
    const fallbackGeometry = await readDialogGeometry(page);

    await postSurfaceMeasurement(page, {
      kind: 'measured_auth_menu_v1',
      requestId: '__current__',
      authMenuSessionId: '__current__',
      sequence: 1,
      widthCssPx: 360,
      heightCssPx: 400,
      unexpected: true,
    });
    await page.waitForTimeout(40);
    const malformedGeometry = await readDialogGeometry(page);
    expect(malformedGeometry.className).toContain('is-viewport-fallback');
    expect(malformedGeometry.width).toBeCloseTo(fallbackGeometry.width, 0);
    expect(malformedGeometry.height).toBeCloseTo(fallbackGeometry.height, 0);

    await postSurfaceMeasurement(page, {
      kind: 'measured_auth_menu_v1',
      requestId: '__current__',
      authMenuSessionId: '__current__',
      sequence: 10,
      widthCssPx: 360,
      heightCssPx: 400,
    });
    await waitForDialogGeometry(page, { width: 360, height: 400 });

    await postSurfaceMeasurement(page, {
      kind: 'measured_auth_menu_v1',
      requestId: '__current__',
      authMenuSessionId: '__current__',
      sequence: 9,
      widthCssPx: 500,
      heightCssPx: 500,
    });
    await page.waitForTimeout(40);
    const staleGeometry = await readDialogGeometry(page);
    expect(staleGeometry.width).toBeCloseTo(360, 0);
    expect(staleGeometry.height).toBeCloseTo(400, 0);

    await postSurfaceMeasurement(page, {
      kind: 'measured_auth_menu_v1',
      requestId: 'mismatched-request-id',
      authMenuSessionId: '__current__',
      sequence: 11,
      widthCssPx: 500,
      heightCssPx: 500,
    });
    await postSurfaceMeasurement(page, {
      kind: 'measured_auth_menu_v1',
      requestId: '__current__',
      authMenuSessionId: 'mismatched-auth-menu-session',
      sequence: 12,
      widthCssPx: 500,
      heightCssPx: 500,
    });
    await page.waitForTimeout(40);
    const mismatchedGeometry = await readDialogGeometry(page);
    expect(mismatchedGeometry.width).toBeCloseTo(360, 0);
    expect(mismatchedGeometry.height).toBeCloseTo(400, 0);

    await postSurfaceMeasurement(page, {
      kind: 'measured_auth_menu_v1',
      requestId: '__current__',
      authMenuSessionId: '__current__',
      sequence: 13,
      widthCssPx: 420,
      heightCssPx: 430,
    });
    await waitForDialogGeometry(page, { width: 420, height: 430 });
    const acceptedGeometry = await readDialogGeometry(page);
    expect(acceptedGeometry.className).not.toContain('is-viewport-fallback');
  });

  test('tracks measured auth-menu heights instantly rather than easing toward them', async ({
    page,
  }) => {
    await startHostedAuthMenu(page, 'compact-height-animation-session');
    await postSurfaceMeasurement(page, {
      kind: 'measured_auth_menu_v1',
      requestId: '__current__',
      authMenuSessionId: '__current__',
      sequence: 20,
      widthCssPx: 420,
      heightCssPx: 430,
    });
    await waitForDialogGeometry(page, { width: 420, height: 430 });

    await postSurfaceMeasurement(page, {
      kind: 'measured_auth_menu_v1',
      requestId: '__current__',
      authMenuSessionId: '__current__',
      sequence: 21,
      widthCssPx: 420,
      heightCssPx: 255,
    });
    await page.waitForTimeout(60);

    // The in-iframe card animates its own height and a ResizeObserver posts
    // every intermediate frame here. If this dialog eased toward those frames
    // it would trail a still-moving target and the change would read as two
    // steps. It must land on each reported frame immediately, so the card's
    // spring stays the only motion on screen.
    const settledGeometry = await readDialogGeometry(page);
    expect(settledGeometry.height).toBeCloseTo(255, 0);
    expect(settledGeometry.transitionDuration).toBe('0s');
    await waitForDialogGeometry(page, { width: 420, height: 255 });
  });

  test('preserves an anchored menu layout when the host page is zoomed', async ({ page }) => {
    await startHostedAuthMenu(page, 'compact-zoomed-anchor-session', { anchorZoom: 0.9 });
    await postSurfaceMeasurement(page, {
      kind: 'measured_auth_menu_v1',
      requestId: '__current__',
      authMenuSessionId: '__current__',
      sequence: 30,
      widthCssPx: 420,
      heightCssPx: 430,
    });
    await waitForDialogGeometry(page, { width: 378, height: 387 });

    const geometry = await page.evaluate(() => {
      const dialog = document.querySelector('dialog.w3a-wallet-overlay-dialog');
      const iframe = dialog?.querySelector('iframe');
      if (!(dialog instanceof HTMLDialogElement) || !(iframe instanceof HTMLIFrameElement)) {
        throw new Error('wallet auth-menu overlay missing');
      }
      const rect = dialog.getBoundingClientRect();
      return {
        width: rect.width,
        height: rect.height,
        top: rect.top,
        left: rect.left,
        iframeLayoutWidth: iframe.offsetWidth,
        transform: getComputedStyle(dialog).transform,
      };
    });

    expect(geometry.width).toBeCloseTo(378, 0);
    expect(geometry.height).toBeCloseTo(387, 0);
    expect(geometry.top).toBeCloseTo(90, 0);
    expect(geometry.left).toBeCloseTo(72, 0);
    expect(geometry.iframeLayoutWidth).toBe(420);
    expect(geometry.transform).toBe('matrix(0.9, 0, 0, 0.9, 0, 0)');
  });

  test('an anchored menu scrolls with the page content instead of floating over it', async ({
    page,
  }) => {
    await startHostedAuthMenu(page, 'compact-scroll-follow-session', { anchorInFlow: true });
    await postSurfaceMeasurement(page, {
      kind: 'measured_auth_menu_v1',
      requestId: '__current__',
      authMenuSessionId: '__current__',
      sequence: 40,
      widthCssPx: 420,
      heightCssPx: 430,
    });
    await waitForDialogGeometry(page, { width: 420, height: 430 });
    // Let the post-open anchor-settle tracking window expire so the scroll
    // assertion exercises native compositor scrolling, not the rAF tracker.
    await page.waitForTimeout(800);

    const scrolled = await page.evaluate(async () => {
      const dialog = document.querySelector('dialog.w3a-wallet-overlay-dialog');
      const anchor = document.querySelector('[data-test-auth-menu-anchor]');
      if (!(dialog instanceof HTMLDialogElement) || !(anchor instanceof HTMLElement)) {
        throw new Error('wallet auth-menu overlay or anchor missing');
      }
      const before = {
        dialogTop: dialog.getBoundingClientRect().top,
        anchorTop: anchor.getBoundingClientRect().top,
      };
      window.scrollTo(0, 400);
      await new Promise((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => resolve(undefined))),
      );
      const after = {
        dialogTop: dialog.getBoundingClientRect().top,
        anchorTop: anchor.getBoundingClientRect().top,
        scrollY: window.scrollY,
        position: getComputedStyle(dialog).position,
      };
      return { before, after };
    });

    expect(scrolled.after.scrollY).toBe(400);
    expect(scrolled.after.position).toBe('absolute');
    expect(scrolled.before.dialogTop).toBeCloseTo(scrolled.before.anchorTop, 0);
    expect(scrolled.after.dialogTop - scrolled.before.dialogTop).toBeCloseTo(-400, 0);
    expect(scrolled.after.dialogTop).toBeCloseTo(scrolled.after.anchorTop, 0);
  });

  test('keeps the hosted auth menu open without a request deadline', async ({ page }) => {
    await startHostedAuthMenu(page, 'compact-interactive-timeout-session', {
      captureRequestTimeouts: true,
    });

    const timeoutDelays = await page.evaluate(() => {
      const testWindow = window as TestWindow;
      return testWindow.__compactSurfaceTimeoutDelays ?? [];
    });
    expect(timeoutDelays).not.toContain(180_000);
  });

  test('serves exact-session reads from the mirror while hosted authentication is active', async ({
    page,
  }) => {
    await startHostedAuthMenu(page, 'compact-mirrored-session-read');
    const before = await page.evaluate(() => {
      const testWindow = window as TestWindow;
      return testWindow.__compactExactSessionReadCount ?? 0;
    });

    await page.evaluate(async () => {
      const testWindow = window as TestWindow;
      await testWindow.__compactSurfaceRouter?.getExactSessionState();
    });

    const after = await page.evaluate(() => {
      const testWindow = window as TestWindow;
      return testWindow.__compactExactSessionReadCount ?? 0;
    });
    expect(after).toBe(before);
  });

  test('does not let a stale measurement resize a replacement surface', async ({ page }) => {
    await startHostedAuthMenu(page, 'compact-replacement-first');
    await postSurfaceMeasurement(page, {
      kind: 'measured_auth_menu_v1',
      requestId: '__current__',
      authMenuSessionId: '__current__',
      sequence: 50,
      widthCssPx: 360,
      heightCssPx: 380,
    });
    await waitForDialogGeometry(page, { width: 360, height: 380 });
    await completeCurrentSurface(page);

    await startHostedAuthMenu(page, 'compact-replacement-second');
    await waitForMeasuredDialog(page);
    const replacementFallback = await readDialogGeometry(page);

    await postSurfaceMeasurement(page, {
      kind: 'measured_auth_menu_v1',
      requestId: '__previous__',
      authMenuSessionId: '__previous__',
      sequence: 999,
      widthCssPx: 520,
      heightCssPx: 500,
    });
    await page.waitForTimeout(40);
    const staleReplacementGeometry = await readDialogGeometry(page);
    expect(staleReplacementGeometry.className).toContain('is-viewport-fallback');
    expect(staleReplacementGeometry.width).toBeCloseTo(replacementFallback.width, 0);
    expect(staleReplacementGeometry.height).toBeCloseTo(replacementFallback.height, 0);
  });

  test('uses viewport fallback when a compact surface cannot fit a mobile viewport', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 320, height: 240 });
    await startHostedAuthMenu(page, 'compact-mobile-session');
    const geometry = await readDialogGeometry(page);
    expect(geometry.className).toContain('is-viewport-fallback');
    expect(geometry.width).toBeCloseTo(288, 0);
    expect(geometry.height).toBeCloseTo(208, 0);
    expect(geometry.left).toBeCloseTo(16, 0);
    expect(geometry.top).toBeCloseTo(16, 0);
  });
});
