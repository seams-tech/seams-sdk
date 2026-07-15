import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors, SDK_ESM_PATHS } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute, waitFor } from './harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const WAIT_FOR_SOURCE = `(${waitFor.toString()})`;

function registrationActivationSignerSelection() {
  return {
    kind: 'signer_set' as const,
    signers: [
      {
        kind: 'near_ed25519' as const,
        accountProvisioning: {
          kind: 'implicit_account' as const,
          accountIdSource: 'ed25519_public_key' as const,
        },
        signerSlot: 1,
        participantIds: [1, 2],
        derivationVersion: 1,
      },
    ],
  };
}

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
        const postButtonState = (requestId, identity, state) => {
          adoptedPort.postMessage({
            type: 'PM_REGISTRATION_ACTIVATION_BUTTON_STATE',
            requestId,
            payload: { ...identity, state }
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
            const identity = {
              activationId,
              surfaceId: payload.surfaceId,
              requestId: payload.requestId
            };
            activationRequestIds.set(activationId, requestId);
            postButtonState(requestId, identity, earlyState);
            postButtonState(requestId, { ...identity, activationId: activationId + ':forged' }, unknownActivationState);
            adoptedPort.postMessage({
              type: 'PM_REGISTRATION_ACTIVATION_READY',
              requestId,
              payload: {
                ...identity,
                expiresAtMs: payload.expiresAtMs
              }
            });
            postButtonState(requestId, identity, malformedState);
            postButtonState(requestId, identity, validState);
            postButtonState(
              requestId,
              { ...identity, surfaceId: identity.surfaceId + ':forged' },
              unknownActivationState
            );
            postButtonState(
              requestId,
              { ...identity, requestId: identity.requestId + ':forged' },
              unknownActivationState
            );
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
            const identity = {
              activationId,
              surfaceId: payload.surfaceId,
              requestId: payload.requestId
            };
            activationRequestIds.set(activationId, requestId);
            adoptedPort.postMessage({
              type: 'PM_REGISTRATION_ACTIVATION_READY',
              requestId,
              payload: {
                ...identity,
                expiresAtMs: payload.expiresAtMs
              }
            });
            setTimeout(() => {
              adoptedPort.postMessage({
                type: 'PM_REGISTRATION_ACTIVATION_STARTED',
                requestId,
                payload: identity
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
            const identity = {
              activationId,
              surfaceId: payload.surfaceId,
              requestId: payload.requestId
            };
            activationRequestIds.set(activationId, requestId);
            setTimeout(() => {
              adoptedPort.postMessage({
                type: 'PM_REGISTRATION_ACTIVATION_READY',
                requestId,
                payload: {
                  ...identity,
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
            const identity = {
              activationId,
              surfaceId: payload.surfaceId,
              requestId: payload.requestId
            };
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
                payload: identity
              });
              respondOk(requestId, { success: true, walletId: '' });
            }, { once: true });
            document.body.appendChild(button);
            adoptedPort.postMessage({
              type: 'PM_REGISTRATION_ACTIVATION_READY',
              requestId,
              payload: {
                ...identity,
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

const REGISTRATION_ACTIVATION_TIMEOUT_CANCEL_SCRIPT = String.raw`
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

          if (data.type === 'PM_REGISTRATION_ACTIVATION_CANCEL') {
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
      async ({ routerPath, walletOrigin, waitForSource, signerSelection }) => {
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
            signerSelection,
            presentation: {
              kind: 'outline_overlay',
              label: 'Sign up with Passkey',
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
        signerSelection: registrationActivationSignerSelection(),
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

  test('rejects fullscreen wallet work while the anchored activation surface is ready', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, waitForSource, signerSelection }) => {
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
        target.style.cssText = 'position:absolute;left:40px;top:80px;width:240px;height:60px;';
        document.body.appendChild(target);
        const walletId =
          'frost-fjord-rgcmpa' as import('@shared/utils/registrationIntent').WalletId;
        const surface = router.createPasskeyRegistrationActivationSurface({
          wallet: { kind: 'provided', walletId },
          signerSelection,
          presentation: {
            kind: 'outline_overlay',
            label: 'Create passkey',
            busyLabel: 'Creating passkey...',
            accessibleLabel: 'Create passkey account',
          },
        });
        surface.mount(target);
        await waitForBrowser(() => surface.state().kind === 'ready', 3000);

        let errorCode = '';
        try {
          await router.registerWallet({} as never);
        } catch (error) {
          errorCode = String((error as { code?: unknown }).code || '');
        }
        const overlayState = router.getOverlayState();
        surface.dispose();
        target.remove();
        return { errorCode, overlayState };
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        waitForSource: WAIT_FOR_SOURCE,
        signerSelection: registrationActivationSignerSelection(),
      },
    );

    expect(result.errorCode).toBe('wallet_iframe_surface_busy');
    expect(result.overlayState.mode).toBe('anchored');
    expect(result.overlayState.visible).toBe(true);
  });

  test('waits for registration activation target layout before cancelling', async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: REGISTRATION_ACTIVATION_DELAYED_READY_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );

    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, waitForSource, signerSelection }) => {
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
            signerSelection,
            presentation: {
              kind: 'outline_overlay',
              label: 'Sign up with Passkey',
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
          const ready = await waitForBrowser(
            () => states.some((state) => state.kind === 'ready'),
            3000,
          );
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
        signerSelection: registrationActivationSignerSelection(),
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

  test('maps idle activation prepare timeout to expired cancellation', async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: REGISTRATION_ACTIVATION_TIMEOUT_CANCEL_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );

    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, waitForSource, signerSelection }) => {
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

          const nativeDateNow = Date.now.bind(Date);
          const nativeSetTimeout = window.setTimeout.bind(window);
          let fakeNow = nativeDateNow();
          Date.now = () => fakeNow;
          window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) => {
            const timeoutMs = Number(timeout);
            if (Number.isFinite(timeoutMs) && timeoutMs > 60_000) {
              return nativeSetTimeout(() => {
                fakeNow += timeoutMs + 1;
                if (typeof handler === 'function') {
                  handler(...args);
                }
              }, 30);
            }
            return nativeSetTimeout(handler, timeout, ...args);
          }) as typeof window.setTimeout;

          const target = document.createElement('div');
          target.className = 'seams-passkey-registration-btn';
          target.style.cssText =
            'position:absolute;left:40px;top:80px;width:240px;height:60px;border-radius:30px;';
          document.body.appendChild(target);

          const states: Array<{ kind: string; reason?: string; error?: string }> = [];
          const walletId =
            'frost-fjord-rgcmpa' as import('@shared/utils/registrationIntent').WalletId;
          const surface = router.createPasskeyRegistrationActivationSurface({
            wallet: { kind: 'provided', walletId },
            signerSelection,
            presentation: {
              kind: 'outline_overlay',
              label: 'Sign up with Passkey',
              busyLabel: 'Creating passkey...',
              accessibleLabel: 'Create passkey account',
            },
          });
          const unsubscribe = surface.onStateChange((state) => {
            states.push({
              kind: state.kind,
              ...('reason' in state ? { reason: state.reason } : {}),
              ...('error' in state ? { error: state.error } : {}),
            });
          });
          surface.mount(target);
          const expired = await waitForBrowser(
            () => states.some((state) => state.kind === 'cancelled' && state.reason === 'expired'),
            1000,
          );
          const failedErrors = states
            .filter((state) => state.kind === 'failed')
            .map((state) => state.error || '');

          unsubscribe();
          surface.dispose();
          target.remove();
          Date.now = nativeDateNow;
          window.setTimeout = nativeSetTimeout;

          return { success: true, expired, failedErrors, states };
        } catch (error) {
          return { success: false, error: error instanceof Error ? error.message : String(error) };
        }
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        waitForSource: WAIT_FOR_SOURCE,
        signerSelection: registrationActivationSignerSelection(),
      },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.expired).toBe(true);
    expect(result.failedErrors).toEqual([]);
  });

  test('routes pointer activation to the wallet-origin registration button', async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: REGISTRATION_ACTIVATION_CLICK_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );

    const setup = await page.evaluate(
      async ({ routerPath, walletOrigin, waitForSource, signerSelection }) => {
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
            signerSelection,
            presentation: {
              kind: 'outline_overlay',
              label: 'Sign up with Passkey',
              busyLabel: 'Creating passkey...',
              accessibleLabel: 'Create passkey account',
            },
          });
          const unsubscribe = surface.onStateChange((state) => states.push(state.kind));
          surface.mount(target);
          const ready = await waitForBrowser(() => states.includes('ready'), 3000);
          (
            window as typeof window & {
              __registrationActivationTest?: {
                states: string[];
                dispose(): void;
              };
            }
          ).__registrationActivationTest = {
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
        signerSelection: registrationActivationSignerSelection(),
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
      async ({ routerPath, walletOrigin, waitForSource, signerSelection }) => {
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
            'position:absolute;left:40px;top:40px;width:220px;height:56px;border-radius:28px;box-shadow:0 0 0 12px rgba(20,120,140,0.28);';
          spacer.appendChild(target);
          scrollHost.appendChild(spacer);
          document.body.appendChild(scrollHost);

          const states: string[] = [];
          const walletId =
            'frost-fjord-rgcmpa' as import('@shared/utils/registrationIntent').WalletId;
          const surface = router.createPasskeyRegistrationActivationSurface({
            wallet: { kind: 'provided', walletId },
            signerSelection,
            presentation: {
              kind: 'outline_overlay',
              label: 'Sign up with Passkey',
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
          scrollHost.scrollTop = 20;
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
        signerSelection: registrationActivationSignerSelection(),
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

  test('rejects hidden, detached, undersized, inert, and low-opacity targets', async ({ page }) => {
    const results = await page.evaluate(
      async ({ routerPath, walletOrigin, waitForSource, signerSelection }) => {
        const waitForBrowser = eval(waitForSource) as typeof waitFor;
        const { WalletIframeRouter } = (await import(
          routerPath
        )) as typeof import('@/SeamsWeb/walletIframe/client/router');
        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3000,
          requestTimeoutMs: 1000,
          sdkBasePath: '/sdk',
          testOptions: { ownerTag: 'tests' },
        });
        await router.init();
        const walletId =
          'frost-fjord-rgcmpa' as import('@shared/utils/registrationIntent').WalletId;
        const cases: Array<{ name: string; target: HTMLElement; cleanup(): void }> = [];

        const undersized = document.createElement('div');
        undersized.style.cssText = 'width:40px;height:56px;';
        document.body.appendChild(undersized);
        cases.push({ name: 'undersized', target: undersized, cleanup: () => undersized.remove() });

        const hidden = document.createElement('div');
        hidden.style.cssText = 'width:100px;height:56px;visibility:hidden;';
        document.body.appendChild(hidden);
        cases.push({ name: 'hidden', target: hidden, cleanup: () => hidden.remove() });

        const inertHost = document.createElement('div');
        inertHost.setAttribute('inert', '');
        const inertTarget = document.createElement('div');
        inertTarget.style.cssText = 'width:100px;height:56px;';
        inertHost.appendChild(inertTarget);
        document.body.appendChild(inertHost);
        cases.push({ name: 'inert', target: inertTarget, cleanup: () => inertHost.remove() });

        const opacityHost = document.createElement('div');
        opacityHost.style.opacity = '0.09';
        const opacityTarget = document.createElement('div');
        opacityTarget.style.cssText = 'width:100px;height:56px;';
        opacityHost.appendChild(opacityTarget);
        document.body.appendChild(opacityHost);
        cases.push({
          name: 'low-opacity',
          target: opacityTarget,
          cleanup: () => opacityHost.remove(),
        });

        const detached = document.createElement('div');
        detached.style.cssText = 'width:100px;height:56px;';
        cases.push({ name: 'detached', target: detached, cleanup: () => undefined });

        const outcomes: Array<{ name: string; reason: string }> = [];
        for (const entry of cases) {
          const surface = router.createPasskeyRegistrationActivationSurface({
            wallet: { kind: 'provided', walletId },
            signerSelection,
            presentation: {
              kind: 'outline_overlay',
              label: 'Create passkey',
              busyLabel: 'Creating passkey...',
              accessibleLabel: 'Create passkey account',
            },
          });
          surface.mount(entry.target);
          await waitForBrowser(() => surface.state().kind === 'cancelled', 2500);
          const state = surface.state();
          outcomes.push({
            name: entry.name,
            reason: state.kind === 'cancelled' ? state.reason : state.kind,
          });
          surface.dispose();
          entry.cleanup();
        }
        return outcomes;
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        waitForSource: WAIT_FOR_SOURCE,
        signerSelection: registrationActivationSignerSelection(),
      },
    );

    expect(results).toEqual([
      { name: 'undersized', reason: 'target_unavailable' },
      { name: 'hidden', reason: 'target_unavailable' },
      { name: 'inert', reason: 'target_unavailable' },
      { name: 'low-opacity', reason: 'target_unavailable' },
      { name: 'detached', reason: 'target_unavailable' },
    ]);
  });

  test('suspends and restores the iframe hit target when an ancestor clips the CTA', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, waitForSource, signerSelection }) => {
        const waitForBrowser = eval(waitForSource) as typeof waitFor;
        const { WalletIframeRouter } = (await import(
          routerPath
        )) as typeof import('@/SeamsWeb/walletIframe/client/router');
        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3000,
          requestTimeoutMs: 1000,
          sdkBasePath: '/sdk',
          testOptions: { ownerTag: 'tests' },
        });
        await router.init();

        const clippingHost = document.createElement('div');
        clippingHost.style.cssText =
          'position:absolute;left:40px;top:40px;width:240px;height:100px;overflow:hidden;';
        const target = document.createElement('div');
        target.style.cssText = 'position:absolute;left:20px;top:20px;width:180px;height:56px;';
        clippingHost.appendChild(target);
        document.body.appendChild(clippingHost);

        const walletId =
          'frost-fjord-rgcmpa' as import('@shared/utils/registrationIntent').WalletId;
        const surface = router.createPasskeyRegistrationActivationSurface({
          wallet: { kind: 'provided', walletId },
          signerSelection,
          presentation: {
            kind: 'outline_overlay',
            label: 'Create passkey',
            busyLabel: 'Creating passkey...',
            accessibleLabel: 'Create passkey account',
          },
        });
        surface.mount(target);
        const ready = await waitForBrowser(() => surface.state().kind === 'ready', 3000);
        const visible = await waitForBrowser(() => {
          const iframe = document.querySelector(
            'iframe.w3a-wallet-overlay[data-w3a-owner="tests"]',
          ) as HTMLIFrameElement | null;
          return Boolean(iframe?.classList.contains('is-anchored'));
        }, 2000);

        target.style.top = '72px';
        const suspended = await waitForBrowser(() => {
          const iframe = document.querySelector(
            'iframe.w3a-wallet-overlay[data-w3a-owner="tests"]',
          ) as HTMLIFrameElement | null;
          return Boolean(
            iframe?.classList.contains('is-hidden') &&
            iframe.getAttribute('aria-hidden') === 'true',
          );
        }, 2000);

        target.style.top = '20px';
        const restored = await waitForBrowser(() => {
          const iframe = document.querySelector(
            'iframe.w3a-wallet-overlay[data-w3a-owner="tests"]',
          ) as HTMLIFrameElement | null;
          return Boolean(
            iframe?.classList.contains('is-anchored') &&
            iframe.getAttribute('aria-hidden') === 'false',
          );
        }, 2000);
        surface.dispose();
        clippingHost.remove();
        return { ready, visible, suspended, restored };
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        waitForSource: WAIT_FOR_SOURCE,
        signerSelection: registrationActivationSignerSelection(),
      },
    );

    expect(result).toEqual({ ready: true, visible: true, suspended: true, restored: true });
  });

  test('releases the anchored hit target after iframe registration starts', async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: REGISTRATION_ACTIVATION_STARTED_RELEASE_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );

    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, waitForSource, signerSelection }) => {
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
            signerSelection,
            presentation: {
              kind: 'outline_overlay',
              label: 'Sign up with Passkey',
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
        signerSelection: registrationActivationSignerSelection(),
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
