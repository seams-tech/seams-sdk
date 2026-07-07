import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors, SDK_ESM_PATHS } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute, waitFor } from './harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const WAIT_FOR_SOURCE = `(${waitFor.toString()})`;

const REGISTRATION_ACTIVATION_STATE_FILTER_SCRIPT = String.raw`
      const activationRequestIds = new Map();
      const validState = {
        kind: 'registration_activation_button_interaction_state_v1',
        hovered: false,
        focused: true,
        pressed: true,
        busy: false,
        disabled: false
      };
      const earlyState = {
        kind: 'registration_activation_button_interaction_state_v1',
        hovered: true,
        focused: false,
        pressed: false,
        busy: false,
        disabled: false
      };
      const unknownActivationState = {
        kind: 'registration_activation_button_interaction_state_v1',
        hovered: false,
        focused: false,
        pressed: false,
        busy: false,
        disabled: true
      };
      const malformedState = {
        kind: 'registration_activation_button_interaction_state_v1',
        hovered: true,
        focused: true,
        pressed: true,
        busy: 'yes',
        disabled: false
      };

      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;

        const respondOk = (requestId, result) => {
          if (!requestId) return;
          pendingRequests.delete(requestId);
          adoptedPort.postMessage({
            type: 'PM_RESULT',
            requestId,
            payload: { ok: true, result }
          });
        };
        const respondCancelled = (requestId) => {
          if (!requestId) return;
          pendingRequests.delete(requestId);
          adoptedPort.postMessage({
            type: 'ERROR',
            requestId,
            payload: { code: 'cancelled', message: 'Registration activation cancelled by test' }
          });
        };
        const postButtonState = (requestId, activationId, state) => {
          adoptedPort.postMessage({
            type: 'PM_REGISTRATION_ACTIVATION_BUTTON_STATE',
            requestId,
            payload: { activationId, state }
          });
        };

        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object') return;
          const requestId = typeof data.requestId === 'string' ? data.requestId : '';

          if (data.type === 'PM_REGISTRATION_ACTIVATION_PREPARE') {
            const payload = data.payload || {};
            const activationId = payload.activationId;
            activationRequestIds.set(activationId, requestId);
            postButtonState(requestId, activationId, earlyState);
            postButtonState(requestId, activationId + ':forged', unknownActivationState);
            adoptedPort.postMessage({
              type: 'PM_REGISTRATION_ACTIVATION_READY',
              requestId,
              payload: {
                activationId,
                expiresAtMs: payload.expiresAtMs
              }
            });
            postButtonState(requestId, activationId, malformedState);
            postButtonState(requestId, activationId, validState);
            return;
          }

          if (data.type === 'PM_REGISTRATION_ACTIVATION_CANCEL') {
            const activationId = data.payload && data.payload.activationId;
            respondCancelled(activationRequestIds.get(activationId));
            activationRequestIds.delete(activationId);
            respondOk(requestId, undefined);
            return;
          }
        };
      };
`;

const REGISTRATION_ACTIVATION_STARTED_RELEASE_SCRIPT = String.raw`
      const activationRequestIds = new Map();
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;

        const respondOk = (requestId, result) => {
          if (!requestId) return;
          pendingRequests.delete(requestId);
          adoptedPort.postMessage({
            type: 'PM_RESULT',
            requestId,
            payload: { ok: true, result }
          });
        };

        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object') return;
          const requestId = typeof data.requestId === 'string' ? data.requestId : '';

          if (data.type === 'PM_REGISTRATION_ACTIVATION_PREPARE') {
            const payload = data.payload || {};
            const activationId = payload.activationId;
            activationRequestIds.set(activationId, requestId);
            adoptedPort.postMessage({
              type: 'PM_REGISTRATION_ACTIVATION_READY',
              requestId,
              payload: {
                activationId,
                expiresAtMs: payload.expiresAtMs
              }
            });
            setTimeout(() => {
              adoptedPort.postMessage({
                type: 'PM_REGISTRATION_ACTIVATION_STARTED',
                requestId,
                payload: { activationId }
              });
            }, 20);
            return;
          }

          if (data.type === 'PM_REGISTRATION_ACTIVATION_CANCEL') {
            const activationId = data.payload && data.payload.activationId;
            activationRequestIds.delete(activationId);
            respondOk(requestId, undefined);
            return;
          }
        };
      };
`;

const REGISTRATION_ACTIVATION_DELAYED_READY_SCRIPT = String.raw`
      const activationRequestIds = new Map();
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;

        const respondOk = (requestId, result) => {
          if (!requestId) return;
          pendingRequests.delete(requestId);
          adoptedPort.postMessage({
            type: 'PM_RESULT',
            requestId,
            payload: { ok: true, result }
          });
        };

        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object') return;
          const requestId = typeof data.requestId === 'string' ? data.requestId : '';

          if (data.type === 'PM_REGISTRATION_ACTIVATION_PREPARE') {
            const payload = data.payload || {};
            const activationId = payload.activationId;
            activationRequestIds.set(activationId, requestId);
            setTimeout(() => {
              adoptedPort.postMessage({
                type: 'PM_REGISTRATION_ACTIVATION_READY',
                requestId,
                payload: {
                  activationId,
                  expiresAtMs: payload.expiresAtMs
                }
              });
            }, 1000);
            return;
          }

          if (data.type === 'PM_REGISTRATION_ACTIVATION_CANCEL') {
            const activationId = data.payload && data.payload.activationId;
            activationRequestIds.delete(activationId);
            respondOk(requestId, undefined);
            return;
          }
        };
      };
`;

const REGISTRATION_ACTIVATION_CLICK_SCRIPT = String.raw`
      const activationRequestIds = new Map();
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;

        const respondOk = (requestId, result) => {
          if (!requestId) return;
          pendingRequests.delete(requestId);
          adoptedPort.postMessage({
            type: 'PM_RESULT',
            requestId,
            payload: { ok: true, result }
          });
        };

        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object') return;
          const requestId = typeof data.requestId === 'string' ? data.requestId : '';

          if (data.type === 'PM_REGISTRATION_ACTIVATION_PREPARE') {
            const payload = data.payload || {};
            const activationId = payload.activationId;
            activationRequestIds.set(activationId, requestId);
            document.body.style.margin = '0';
            document.body.innerHTML = '';
            const button = document.createElement('button');
            button.id = 'trusted-registration-activation';
            button.type = 'button';
            button.setAttribute('aria-label', 'Create passkey account');
            button.style.cssText = 'position:fixed;inset:0;width:100vw;height:100vh;border:0;margin:0;padding:0;background:transparent;color:transparent;cursor:pointer;';
            button.addEventListener('click', () => {
              window.__trustedActivationClickCount = Number(window.__trustedActivationClickCount || 0) + 1;
              adoptedPort.postMessage({
                type: 'PM_REGISTRATION_ACTIVATION_STARTED',
                requestId,
                payload: { activationId }
              });
              respondOk(requestId, { success: true, walletId: '' });
            }, { once: true });
            document.body.appendChild(button);
            adoptedPort.postMessage({
              type: 'PM_REGISTRATION_ACTIVATION_READY',
              requestId,
              payload: {
                activationId,
                expiresAtMs: payload.expiresAtMs
              }
            });
            return;
          }

          if (data.type === 'PM_REGISTRATION_ACTIVATION_CANCEL') {
            const activationId = data.payload && data.payload.activationId;
            activationRequestIds.delete(activationId);
            respondOk(requestId, undefined);
            return;
          }
        };
      };
`;

test.describe('WalletIframeRouter registration activation surface', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: REGISTRATION_ACTIVATION_STATE_FILTER_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('keeps the anchored iframe hit target disabled until wallet-host activation is ready', async ({
    page,
  }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: REGISTRATION_ACTIVATION_DELAYED_READY_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );

    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, waitForSource }) => {
        try {
          const waitForBrowser = eval(waitForSource) as typeof waitFor;
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');
          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 5000,
            sdkBasePath: '/sdk',
            testOptions: { ownerTag: 'tests' },
          });
          await router.init();

          const target = document.createElement('div');
          target.className = 'seams-passkey-registration-btn';
          target.style.cssText =
            'position:absolute;left:40px;top:80px;width:240px;height:60px;border-radius:30px;';
          document.body.appendChild(target);

          const states: string[] = [];
          const walletId =
            'frost-fjord-rgcmpa' as import('@shared/utils/registrationIntent').WalletId;
          const surface = router.createPasskeyRegistrationActivationSurface({
            wallet: { kind: 'provided', walletId },
            presentation: {
              kind: 'outline_overlay',
              label: 'Create with Passkey',
              busyLabel: 'Creating passkey...',
              accessibleLabel: 'Create passkey account',
            },
          });
          const unsubscribe = surface.onStateChange((state) => states.push(state.kind));
          surface.mount(target);

          const mounting = await waitForBrowser(() => states.includes('mounting'), 1000);
          await new Promise((resolve) => setTimeout(resolve, 80));
          const iframeBeforeReady = document.querySelector(
            'iframe[data-w3a-owner="tests"]',
          ) as HTMLIFrameElement | null;
          const unanchoredBeforeReady = Boolean(
            iframeBeforeReady && !iframeBeforeReady.classList.contains('is-anchored'),
          );
          const targetMountingState = {
            active: target.getAttribute('data-seams-registration-button-active'),
            busy: target.getAttribute('data-seams-registration-button-busy'),
            disabled: target.getAttribute('data-seams-registration-button-disabled'),
          };

          const ready = await waitForBrowser(() => states.includes('ready'), 3000);
          const iframeAfterReady = document.querySelector(
            'iframe.w3a-wallet-overlay.is-anchored[data-w3a-owner="tests"]',
          ) as HTMLIFrameElement | null;
          const afterReadyStyle = iframeAfterReady ? getComputedStyle(iframeAfterReady) : null;
          const anchoredAfterReady = Boolean(
            iframeAfterReady &&
              iframeAfterReady.getAttribute('aria-hidden') !== 'true' &&
              afterReadyStyle?.pointerEvents === 'auto',
          );
          const targetReadyState = {
            active: target.getAttribute('data-seams-registration-button-active'),
            busy: target.getAttribute('data-seams-registration-button-busy'),
            disabled: target.getAttribute('data-seams-registration-button-disabled'),
          };

          unsubscribe();
          surface.dispose();
          target.remove();

          return {
            success: true,
            mounting,
            ready,
            unanchoredBeforeReady,
            anchoredAfterReady,
            targetMountingState,
            targetReadyState,
          };
        } catch (error) {
          return { success: false, error: error instanceof Error ? error.message : String(error) };
        }
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        waitForSource: WAIT_FOR_SOURCE,
      },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.mounting).toBe(true);
    expect(result.ready).toBe(true);
    expect(result.unanchoredBeforeReady).toBe(true);
    expect(result.anchoredAfterReady).toBe(true);
    expect(result.targetMountingState).toEqual({
      active: 'true',
      busy: 'true',
      disabled: 'true',
    });
    expect(result.targetReadyState).toEqual({
      active: 'true',
      busy: 'false',
      disabled: 'false',
    });
  });

  test('waits for registration activation target layout before cancelling', async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: REGISTRATION_ACTIVATION_DELAYED_READY_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );

    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, waitForSource }) => {
        try {
          const waitForBrowser = eval(waitForSource) as typeof waitFor;
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');
          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 5000,
            sdkBasePath: '/sdk',
            testOptions: { ownerTag: 'tests' },
          });
          await router.init();

          const target = document.createElement('div');
          target.className = 'seams-passkey-registration-btn';
          target.style.cssText =
            'display:none;position:absolute;left:40px;top:80px;width:240px;height:60px;border-radius:30px;';
          document.body.appendChild(target);

          const states: Array<{ kind: string; reason?: string }> = [];
          const walletId =
            'frost-fjord-rgcmpa' as import('@shared/utils/registrationIntent').WalletId;
          const surface = router.createPasskeyRegistrationActivationSurface({
            wallet: { kind: 'provided', walletId },
            presentation: {
              kind: 'outline_overlay',
              label: 'Create with Passkey',
              busyLabel: 'Creating passkey...',
              accessibleLabel: 'Create passkey account',
            },
          });
          const unsubscribe = surface.onStateChange((state) => {
            states.push({
              kind: state.kind,
              ...('reason' in state ? { reason: state.reason } : {}),
            });
          });
          surface.mount(target);
          const mounting = await waitForBrowser(
            () => states.some((state) => state.kind === 'mounting'),
            1000,
          );
          await new Promise((resolve) => setTimeout(resolve, 80));
          target.style.display = 'block';
          const ready = await waitForBrowser(() => states.some((state) => state.kind === 'ready'), 3000);
          const targetUnavailable = states.some(
            (state) => state.kind === 'cancelled' && state.reason === 'target_unavailable',
          );

          unsubscribe();
          surface.dispose();
          target.remove();

          return { success: true, mounting, ready, targetUnavailable };
        } catch (error) {
          return { success: false, error: error instanceof Error ? error.message : String(error) };
        }
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        waitForSource: WAIT_FOR_SOURCE,
      },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.mounting).toBe(true);
    expect(result.ready).toBe(true);
    expect(result.targetUnavailable).toBe(false);
  });

  test('routes pointer activation to the wallet-origin registration button', async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: REGISTRATION_ACTIVATION_CLICK_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );

    const setup = await page.evaluate(
      async ({ routerPath, walletOrigin, waitForSource }) => {
        try {
          const waitForBrowser = eval(waitForSource) as typeof waitFor;
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');
          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 5000,
            sdkBasePath: '/sdk',
            testOptions: { ownerTag: 'tests' },
          });
          await router.init();

          const target = document.createElement('div');
          target.id = 'activation-target';
          target.className = 'seams-passkey-registration-btn';
          target.style.cssText =
            'position:absolute;left:40px;top:80px;width:240px;height:60px;border-radius:30px;';
          document.body.appendChild(target);

          const states: string[] = [];
          const walletId =
            'frost-fjord-rgcmpa' as import('@shared/utils/registrationIntent').WalletId;
          const surface = router.createPasskeyRegistrationActivationSurface({
            wallet: { kind: 'provided', walletId },
            presentation: {
              kind: 'outline_overlay',
              label: 'Create with Passkey',
              busyLabel: 'Creating passkey...',
              accessibleLabel: 'Create passkey account',
            },
          });
          const unsubscribe = surface.onStateChange((state) => states.push(state.kind));
          surface.mount(target);
          const ready = await waitForBrowser(() => states.includes('ready'), 3000);
          (window as typeof window & {
            __registrationActivationTest?: {
              states: string[];
              dispose(): void;
            };
          }).__registrationActivationTest = {
            states,
            dispose() {
              unsubscribe();
              surface.dispose();
              target.remove();
            },
          };
          return { success: true, ready };
        } catch (error) {
          return { success: false, error: error instanceof Error ? error.message : String(error) };
        }
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        waitForSource: WAIT_FOR_SOURCE,
      },
    );

    if (!setup.success) {
      if (handleInfrastructureErrors(setup)) return;
      expect(setup.success).toBe(true);
      return;
    }
    expect(setup.ready).toBe(true);

    const box = await page.locator('#activation-target').boundingBox();
    expect(box).not.toBeNull();
    if (!box) return;
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);

    await page.waitForFunction(
      () =>
        Boolean(
          (
            window as typeof window & {
              __registrationActivationTest?: { states: string[] };
            }
          ).__registrationActivationTest?.states.includes('completed'),
        ),
      null,
      { timeout: 3000 },
    );

    const result = await page.evaluate(() => {
      const testState = (
        window as typeof window & {
          __registrationActivationTest?: {
            states: string[];
            dispose(): void;
          };
        }
      ).__registrationActivationTest;
      const states = testState?.states || [];
      testState?.dispose();
      return { states };
    });

    expect(result.states).toEqual(expect.arrayContaining(['mounting', 'ready', 'starting']));
    expect(result.states[result.states.length - 1]).toBe('completed');
  });

  test('ignores forged, malformed, and early activation button state messages', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, waitForSource }) => {
        try {
          const waitForBrowser = eval(waitForSource) as typeof waitFor;
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');
          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 1000,
            sdkBasePath: '/sdk',
            testOptions: { ownerTag: 'tests' },
          });
          await router.init();

          const scrollHost = document.createElement('div');
          scrollHost.style.cssText =
            'position:absolute;left:32px;top:48px;width:360px;height:180px;overflow:auto;padding:24px;';
          const spacer = document.createElement('div');
          spacer.style.cssText = 'height:520px;position:relative;';
          const target = document.createElement('div');
          target.className = 'seams-passkey-registration-btn';
          target.style.cssText =
            'position:absolute;left:40px;top:210px;width:220px;height:56px;border-radius:28px;box-shadow:0 0 0 12px rgba(20,120,140,0.28);';
          spacer.appendChild(target);
          scrollHost.appendChild(spacer);
          document.body.appendChild(scrollHost);

          const states: string[] = [];
          const walletId =
            'frost-fjord-rgcmpa' as import('@shared/utils/registrationIntent').WalletId;
          const surface = router.createPasskeyRegistrationActivationSurface({
            wallet: { kind: 'provided', walletId },
            presentation: {
              kind: 'outline_overlay',
              label: 'Create with Passkey',
              busyLabel: 'Creating passkey...',
              accessibleLabel: 'Create passkey account',
            },
          });
          const unsubscribe = surface.onStateChange((state) => states.push(state.kind));
          surface.mount(target);

          const accepted = await waitForBrowser(() => {
            return (
              target.getAttribute('data-seams-registration-button-focused') === 'true' &&
              target.getAttribute('data-seams-registration-button-pressed') === 'true'
            );
          }, 3000);
          const rectsAligned = await waitForBrowser(() => {
            const iframe = document.querySelector(
              'iframe.w3a-wallet-overlay.is-anchored[data-w3a-owner="tests"]',
            ) as HTMLIFrameElement | null;
            if (!iframe) return false;
            const targetRect = target.getBoundingClientRect();
            const iframeRect = iframe.getBoundingClientRect();
            return (
              Math.abs(targetRect.top - iframeRect.top) <= 1 &&
              Math.abs(targetRect.left - iframeRect.left) <= 1 &&
              Math.abs(targetRect.width - iframeRect.width) <= 1 &&
              Math.abs(targetRect.height - iframeRect.height) <= 1
            );
          }, 3000);
          target.style.width = '268px';
          target.style.height = '64px';
          const resizedRectsAligned = await waitForBrowser(() => {
            const iframe = document.querySelector(
              'iframe.w3a-wallet-overlay.is-anchored[data-w3a-owner="tests"]',
            ) as HTMLIFrameElement | null;
            if (!iframe) return false;
            const targetRect = target.getBoundingClientRect();
            const iframeRect = iframe.getBoundingClientRect();
            return (
              Math.abs(targetRect.width - iframeRect.width) <= 1 &&
              Math.abs(targetRect.height - iframeRect.height) <= 1
            );
          }, 3000);
          scrollHost.scrollTop = 80;
          const scrolledRectsAligned = await waitForBrowser(() => {
            const iframe = document.querySelector(
              'iframe.w3a-wallet-overlay.is-anchored[data-w3a-owner="tests"]',
            ) as HTMLIFrameElement | null;
            if (!iframe) return false;
            const targetRect = target.getBoundingClientRect();
            const iframeRect = iframe.getBoundingClientRect();
            return (
              Math.abs(targetRect.top - iframeRect.top) <= 1 &&
              Math.abs(targetRect.left - iframeRect.left) <= 1 &&
              Math.abs(targetRect.width - iframeRect.width) <= 1 &&
              Math.abs(targetRect.height - iframeRect.height) <= 1
            );
          }, 3000);
          const boxShadow = getComputedStyle(target).boxShadow;
          const transactionConfirmerMounted = Boolean(
            document.querySelector(
              'seams-tx-confirmer,w3a-tx-tree,w3a-modal-tx-confirmer,w3a-drawer-tx-confirmer',
            ),
          );
          const attributes = {
            active: target.getAttribute('data-seams-registration-button-active'),
            hovered: target.getAttribute('data-seams-registration-button-hovered'),
            focused: target.getAttribute('data-seams-registration-button-focused'),
            pressed: target.getAttribute('data-seams-registration-button-pressed'),
            busy: target.getAttribute('data-seams-registration-button-busy'),
            disabled: target.getAttribute('data-seams-registration-button-disabled'),
          };

          unsubscribe();
          surface.dispose();
          const cleared = await waitForBrowser(() => {
            return (
              !target.hasAttribute('data-seams-registration-button-active') &&
              !target.hasAttribute('data-seams-registration-button-hovered') &&
              !target.hasAttribute('data-seams-registration-button-focused') &&
              !target.hasAttribute('data-seams-registration-button-pressed') &&
              !target.hasAttribute('data-seams-registration-button-busy') &&
              !target.hasAttribute('data-seams-registration-button-disabled')
            );
          }, 1000);
          const overlayReleased = await waitForBrowser(() => {
            const iframe = document.querySelector(
              'iframe[data-w3a-owner="tests"]',
            ) as HTMLIFrameElement | null;
            if (!iframe) return true;
            const style = getComputedStyle(iframe);
            return iframe.getAttribute('aria-hidden') === 'true' || style.pointerEvents === 'none';
          }, 1000);
          scrollHost.remove();

          return {
            success: true,
            accepted,
            rectsAligned,
            resizedRectsAligned,
            scrolledRectsAligned,
            boxShadow,
            transactionConfirmerMounted,
            attributes,
            states,
            cleared,
            overlayReleased,
          };
        } catch (error) {
          return { success: false, error: error instanceof Error ? error.message : String(error) };
        }
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        waitForSource: WAIT_FOR_SOURCE,
      },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.accepted).toBe(true);
    expect(result.rectsAligned).toBe(true);
    expect(result.resizedRectsAligned).toBe(true);
    expect(result.scrolledRectsAligned).toBe(true);
    expect(result.boxShadow).not.toBe('none');
    expect(result.transactionConfirmerMounted).toBe(false);
    expect(result.attributes).toEqual({
      active: 'true',
      hovered: 'false',
      focused: 'true',
      pressed: 'true',
      busy: 'false',
      disabled: 'false',
    });
    expect(result.states).toEqual(expect.arrayContaining(['mounting', 'ready']));
    expect(result.cleared).toBe(true);
    expect(result.overlayReleased).toBe(true);
  });

  test('releases the anchored hit target after iframe registration starts', async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: REGISTRATION_ACTIVATION_STARTED_RELEASE_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );

    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, waitForSource }) => {
        try {
          const waitForBrowser = eval(waitForSource) as typeof waitFor;
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');
          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 5000,
            sdkBasePath: '/sdk',
            testOptions: { ownerTag: 'tests' },
          });
          await router.init();

          const target = document.createElement('div');
          target.className = 'seams-passkey-registration-btn';
          target.style.cssText =
            'position:absolute;left:40px;top:80px;width:240px;height:60px;border-radius:30px;';
          document.body.appendChild(target);

          const states: string[] = [];
          const walletId =
            'frost-fjord-rgcmpa' as import('@shared/utils/registrationIntent').WalletId;
          const surface = router.createPasskeyRegistrationActivationSurface({
            wallet: { kind: 'provided', walletId },
            presentation: {
              kind: 'outline_overlay',
              label: 'Create with Passkey',
              busyLabel: 'Creating passkey...',
              accessibleLabel: 'Create passkey account',
            },
          });
          const unsubscribe = surface.onStateChange((state) => states.push(state.kind));
          surface.mount(target);

          const started = await waitForBrowser(() => states.includes('starting'), 3000);
          const clearedAfterStart =
            !target.hasAttribute('data-seams-registration-button-active') &&
            !target.hasAttribute('data-seams-registration-button-hovered') &&
            !target.hasAttribute('data-seams-registration-button-focused') &&
            !target.hasAttribute('data-seams-registration-button-pressed') &&
            !target.hasAttribute('data-seams-registration-button-busy') &&
            !target.hasAttribute('data-seams-registration-button-disabled');
          const overlayReleased = await waitForBrowser(() => {
            const iframe = document.querySelector(
              'iframe[data-w3a-owner="tests"]',
            ) as HTMLIFrameElement | null;
            if (!iframe) return true;
            const style = getComputedStyle(iframe);
            return iframe.getAttribute('aria-hidden') === 'true' || style.pointerEvents === 'none';
          }, 1000);

          target.remove();
          await new Promise((resolve) => setTimeout(resolve, 120));
          const cancelledBeforeDispose = states.includes('cancelled');

          unsubscribe();
          surface.dispose();

          return {
            success: true,
            started,
            states,
            clearedAfterStart,
            overlayReleased,
            cancelledBeforeDispose,
          };
        } catch (error) {
          return { success: false, error: error instanceof Error ? error.message : String(error) };
        }
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        waitForSource: WAIT_FOR_SOURCE,
      },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.started).toBe(true);
    expect(result.states).toEqual(expect.arrayContaining(['mounting', 'ready', 'starting']));
    expect(result.clearedAfterStart).toBe(true);
    expect(result.overlayReleased).toBe(true);
    expect(result.cancelledBeforeDispose).toBe(false);
  });
});
