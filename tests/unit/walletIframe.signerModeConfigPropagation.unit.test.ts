import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute } from '../wallet-iframe/harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';

const WALLET_STUB_CAPTURE_SCRIPT = String.raw`
  const originalAdoptPort = adoptPort;
  adoptPort = function patchedAdoptPort(port) {
    originalAdoptPort(port);
    if (!adoptedPort) return;

    const originalHandler = adoptedPort.onmessage;
    adoptedPort.onmessage = (event) => {
      originalHandler?.(event);
      const data = event.data || {};
      if (!data || typeof data !== 'object') return;

      if (data.type === 'PM_SET_CONFIG') {
        try {
          window.__capturedSigningSessionPersistenceMode = (data.payload && typeof data.payload === 'object')
            ? data.payload.signingSessionPersistenceMode
            : undefined;
          window.__capturedSigningSessionDefaults = (data.payload && typeof data.payload === 'object')
            ? data.payload.signingSessionDefaults
            : undefined;
          window.__capturedSigningSessionSeal = (data.payload && typeof data.payload === 'object')
            ? data.payload.signingSessionSeal
            : undefined;
          window.__capturedThresholdEcdsaPresignPool = (data.payload && typeof data.payload === 'object')
            ? data.payload.thresholdEcdsaPresignPool
            : undefined;
          window.__capturedProvisioningDefaults = (data.payload && typeof data.payload === 'object')
            ? data.payload.provisioningDefaults
            : undefined;
          window.__capturedRegistration = (data.payload && typeof data.payload === 'object')
            ? data.payload.registration
            : undefined;
          window.__capturedAppearance = (data.payload && typeof data.payload === 'object')
            ? data.payload.appearance
            : undefined;
        } catch {}
      }

      const requestId = data.requestId;
      if (typeof requestId !== 'string') return;

      const respond = (result) => {
        try {
          pendingRequests.delete(requestId);
          adoptedPort.postMessage({ type: 'PM_RESULT', requestId, payload: { ok: true, result } });
        } catch (err) {
          console.error('post PM_RESULT failed', err);
        }
      };

      if (data.type === 'PM_SET_CONFIG') {
        respond(null);
      }
      if (data.type === 'PM_PREFETCH_BLOCKHEIGHT') {
        respond(null);
      }
      if (data.type === 'PM_GET_WALLET_SESSION') {
        respond({
          login: {
            isLoggedIn: false,
            nearAccountId: null,
            publicKey: null,
            userData: null,
          },
          signingSession: null,
        });
      }
      if (data.type === 'PM_GET_CONFIRMATION_CONFIG') {
        respond({ behavior: 'requireClick', uiMode: 'modal' });
      }
    };
  };
`;

test.describe('Wallet iframe config propagation', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: WALLET_STUB_CAPTURE_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await page.unroute(WALLET_SERVICE_ROUTE.replace('wallet-service', 'service')).catch(() => {});
  });

  test('forwards signing-session config in PM_SET_CONFIG', async ({ page }) => {
    await page.evaluate(
      async ({ walletOrigin }) => {
        const mod = await import('/sdk/esm/web/SeamsWeb/index.js');
        const { SeamsWeb } = mod as any;

        const pm = new SeamsWeb({
          relayer: { url: 'http://localhost:3000' },
          signingSessionDefaults: {
            ttlMs: 12_345,
            remainingUses: 67,
          },
          signingSessionPersistenceMode: 'sealed_refresh_v1',
          signingSessionSeal: {
            keyVersion: 'kek-s-2026-02',
            shamirPrimeB64u: '_____________________________________v___C8',
          },
          thresholdEcdsaPresignPool: {
            enabled: false,
            targetDepth: 5,
            lowWatermark: 2,
            maxRefillInFlight: 3,
            refillAttemptTimeoutMs: 45_000,
          },
          provisioningDefaults: {
            tempo: {
              enabled: true,
              participantIds: [1, 2],
              signingSession: {
                kind: 'jwt',
                ttlMs: 54_321,
                remainingUses: 9,
              },
            },
            evm: {
              enabled: true,
              participantIds: [1, 2],
              signingSession: {
                kind: 'jwt',
                ttlMs: 65_432,
                remainingUses: 11,
              },
            },
          },
          iframeWallet: {
            walletOrigin,
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
          },
        });

        await pm.initWalletIframe();
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    const walletFrame = page.frames().find((frame) => {
      const url = frame.url();
      return url.startsWith(WALLET_ORIGIN) && url.includes('/wallet-service');
    });
    expect(walletFrame, 'wallet iframe should be mounted').toBeTruthy();

    const capturedSigningSessionPersistenceMode = await walletFrame!.evaluate(() => {
      return (window as any).__capturedSigningSessionPersistenceMode ?? null;
    });
    const capturedSigningSessionDefaults = await walletFrame!.evaluate(() => {
      return (window as any).__capturedSigningSessionDefaults ?? null;
    });
    const capturedSigningSessionSeal = await walletFrame!.evaluate(() => {
      return (window as any).__capturedSigningSessionSeal ?? null;
    });
    const capturedThresholdEcdsaPresignPool = await walletFrame!.evaluate(() => {
      return (window as any).__capturedThresholdEcdsaPresignPool ?? null;
    });
    const capturedProvisioningDefaults = await walletFrame!.evaluate(() => {
      return (window as any).__capturedProvisioningDefaults ?? null;
    });
    expect(capturedSigningSessionPersistenceMode).toBe('sealed_refresh_v1');
    expect(capturedSigningSessionDefaults).toEqual({
      ttlMs: 12_345,
      remainingUses: 67,
    });
    expect(capturedSigningSessionSeal).toEqual({
      keyVersion: 'kek-s-2026-02',
      shamirPrimeB64u: '_____________________________________v___C8',
    });
    expect(capturedThresholdEcdsaPresignPool).toEqual({
      enabled: false,
      targetDepth: 5,
      lowWatermark: 2,
      maxRefillInFlight: 3,
      refillAttemptTimeoutMs: 45_000,
    });
    expect(capturedProvisioningDefaults).toEqual({
      tempo: {
        enabled: true,
        participantIds: [1, 2],
        signingSession: {
          kind: 'jwt',
          ttlMs: 54_321,
          remainingUses: 9,
        },
      },
      evm: {
        enabled: true,
        participantIds: [1, 2],
        signingSession: {
          kind: 'jwt',
          ttlMs: 65_432,
          remainingUses: 11,
        },
      },
    });
  });

  test('does not forward signingSessionSeal when sealed refresh mode is disabled', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ walletOrigin }) => {
        const mod = await import('/sdk/esm/web/SeamsWeb/index.js');
        const { SeamsWeb } = mod as any;

        const pm = new SeamsWeb({
          relayer: { url: 'http://localhost:3000' },
          signingSessionPersistenceMode: 'none',
          signingSessionSeal: {
            keyVersion: 'should-not-forward',
            shamirPrimeB64u: '_____________________________________v___C8',
          },
          iframeWallet: {
            walletOrigin,
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
          },
        });

        await pm.initWalletIframe();
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    const walletFrame = page.frames().find((frame) => {
      const url = frame.url();
      return url.startsWith(WALLET_ORIGIN) && url.includes('/wallet-service');
    });
    expect(walletFrame, 'wallet iframe should be mounted').toBeTruthy();

    const capturedSigningSessionPersistenceMode = await walletFrame!.evaluate(() => {
      return (window as any).__capturedSigningSessionPersistenceMode ?? null;
    });
    const capturedSigningSessionSeal = await walletFrame!.evaluate(() => {
      return (window as any).__capturedSigningSessionSeal ?? null;
    });
    expect(capturedSigningSessionPersistenceMode).toBe('none');
    expect(capturedSigningSessionSeal).toBe(null);
  });

  test('forwards managed registration config in PM_SET_CONFIG', async ({ page }) => {
    await page.evaluate(
      async ({ walletOrigin }) => {
        const mod = await import('/sdk/esm/web/SeamsWeb/index.js');
        const { SeamsWeb } = mod as any;

        const pm = new SeamsWeb({
          relayer: { url: 'https://localhost:9444' },
          registration: {
            mode: 'managed',
            environmentId: 'proj_demo:dev',
            publishableKey: 'pk_demopublishablekeypreview',
          },
          iframeWallet: {
            walletOrigin,
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
          },
        });

        await pm.initWalletIframe();
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    const walletFrame = page.frames().find((frame) => {
      const url = frame.url();
      return url.startsWith(WALLET_ORIGIN) && url.includes('/wallet-service');
    });
    expect(walletFrame, 'wallet iframe should be mounted').toBeTruthy();

    const capturedRegistration = await walletFrame!.evaluate(() => {
      return (window as any).__capturedRegistration ?? null;
    });
    expect(capturedRegistration).toEqual({
      mode: 'managed',
      environmentId: 'proj_demo:dev',
      publishableKey: 'pk_demopublishablekeypreview',
      paymentMode: 'disabled',
    });
  });

  test('fails fast when sealed refresh is enabled without shamirPrimeB64u', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        const mod = await import('/sdk/esm/web/SeamsWeb/index.js');
        const { SeamsWeb } = mod as any;
        new SeamsWeb({
          relayer: { url: 'http://localhost:3000' },
          signingSessionPersistenceMode: 'sealed_refresh_v1',
          signingSessionSeal: {
            keyVersion: 'kek-s-2026-02',
          },
        });
        return { ok: true, error: '' };
      } catch (error: unknown) {
        return {
          ok: false,
          error: String(
            error && typeof error === 'object' && 'message' in error
              ? (error as { message?: unknown }).message
              : error || 'unknown error',
          ),
        };
      }
    });
    expect(result.ok).toBe(false);
    expect(result.error).toContain('signingSessionSeal.shamirPrimeB64u');
  });

  test('forwards appearance theme/tokens in PM_SET_CONFIG for Lit confirmer theming', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ walletOrigin }) => {
        const mod = await import('/sdk/esm/web/SeamsWeb/index.js');
        const { SeamsWeb } = mod as any;

        const pm = new SeamsWeb({
          relayer: { url: 'http://localhost:3000' },
          appearance: {
            theme: 'light',
            tokens: {
              light: {
                colors: {
                  primary: '#abcdef',
                  surface: '#f5f7fb',
                },
              },
              dark: {
                colors: {
                  primary: '#112233',
                },
              },
            },
          },
          iframeWallet: {
            walletOrigin,
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
          },
        });

        await pm.initWalletIframe();
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    const walletFrame = page.frames().find((frame) => {
      const url = frame.url();
      return url.startsWith(WALLET_ORIGIN) && url.includes('/wallet-service');
    });
    expect(walletFrame, 'wallet iframe should be mounted').toBeTruthy();

    const capturedAppearance = await walletFrame!.evaluate(() => {
      return (window as any).__capturedAppearance ?? null;
    });
    expect(capturedAppearance).toEqual({
      theme: 'light',
      tokens: {
        light: {
          colors: {
            primary: '#abcdef',
            surface: '#f5f7fb',
          },
        },
        dark: {
          colors: {
            primary: '#112233',
          },
        },
      },
    });
  });
});
