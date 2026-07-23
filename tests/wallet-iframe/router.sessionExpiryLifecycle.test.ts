import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest, SDK_ESM_PATHS } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute } from './harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const WALLET_ID = 'refactor-92-wallet';
const ACTIVE_SESSION_ID = 'wss_refactor_92_active';
const STALE_SESSION_ID = 'wss_refactor_92_stale';
const EXPIRES_AT_MS = 4_102_444_800_000;

const ACTIVE_SESSION_STATE = {
  kind: 'active_session',
  status: 'active',
  walletId: WALLET_ID,
  walletSessionId: ACTIVE_SESSION_ID,
  authMethod: 'passkey',
  expiresAtMs: EXPIRES_AT_MS,
};

test.describe('WalletIframeRouter signing-session expiry lifecycle', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ exactSessionState: ACTIVE_SESSION_STATE }),
      WALLET_SERVICE_ROUTE,
    );
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('forwards each exact event once and cancels only exact-session requests', async ({ page }) => {
    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, walletId, activeSessionId, staleSessionId, expiresAtMs }) => {
        const module = await import(routerPath);
        const { WalletIframeRouter } =
          module as typeof import('@/SeamsWeb/walletIframe/client/router');

        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3_000,
          requestTimeoutMs: 5_000,
          sdkBasePath: '/sdk',
        });
        const lifecycleEvents: Array<{ walletSessionId: string }> = [];
        router.onSdkLifecycleEvent((event) => lifecycleEvents.push(event));
        await router.init();

        let requestSettled = false;
        const pendingRequest = router
          .executeAction({
            walletId,
            nearAccountId: 'refactor-92.testnet',
            receiverId: 'w3a-v1.testnet',
            actionArgs: { type: 'Transfer', amount: '1' } as any,
            options: {},
          })
          .then(
            () => ({ kind: 'resolved' as const }),
            (error: unknown) => {
              const candidate = error as {
                name?: unknown;
                message?: unknown;
                failure?: { code?: unknown; walletId?: unknown; walletSessionId?: unknown };
              };
              return {
                kind: 'rejected' as const,
                name: String(candidate.name || ''),
                message: String(candidate.message || ''),
                code: String(candidate.failure?.code || ''),
                walletId: String(candidate.failure?.walletId || ''),
                walletSessionId: String(candidate.failure?.walletSessionId || ''),
              };
            },
          )
          .finally(() => {
            requestSettled = true;
          });

        const emitSdkLifecycleEvent = Reflect.get(router, 'emitSdkLifecycleEvent');
        if (typeof emitSdkLifecycleEvent !== 'function') {
          throw new Error('wallet iframe lifecycle consumer is unavailable');
        }
        const staleExpiry = {
          version: 1 as const,
          event: 'signing_session.expired' as const,
          walletId,
          walletSessionId: staleSessionId,
          authMethod: 'passkey' as const,
          expiresAtMs,
          detectedAtMs: Date.now(),
          source: 'server_rejection' as const,
        };
        emitSdkLifecycleEvent.call(router, staleExpiry);
        emitSdkLifecycleEvent.call(router, staleExpiry);
        await new Promise((resolve) => window.setTimeout(resolve, 50));
        const staleEventResult = {
          requestSettled,
          mirroredState: router.getMirroredExactSessionState(),
          lifecycleEventSessionIds: lifecycleEvents.map((event) => event.walletSessionId),
        };

        const activeExpiry = {
          ...staleExpiry,
          walletSessionId: activeSessionId,
          detectedAtMs: Date.now(),
        };
        emitSdkLifecycleEvent.call(router, activeExpiry);
        emitSdkLifecycleEvent.call(router, activeExpiry);
        const requestResult = await pendingRequest;

        return {
          staleEventResult,
          requestResult,
          finalMirroredState: router.getMirroredExactSessionState(),
          lifecycleEventSessionIds: lifecycleEvents.map((event) => event.walletSessionId),
        };
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        walletId: WALLET_ID,
        activeSessionId: ACTIVE_SESSION_ID,
        staleSessionId: STALE_SESSION_ID,
        expiresAtMs: EXPIRES_AT_MS,
      },
    );

    expect(result.staleEventResult.requestSettled).toBe(false);
    expect(result.staleEventResult.mirroredState).toEqual(ACTIVE_SESSION_STATE);
    expect(result.staleEventResult.lifecycleEventSessionIds).toEqual([STALE_SESSION_ID]);
    expect(result.requestResult).toEqual({
      kind: 'rejected',
      name: 'WalletIframeSessionExpiredRequestError',
      message: 'Wallet signing session expired',
      code: 'wallet_session_expired',
      walletId: WALLET_ID,
      walletSessionId: ACTIVE_SESSION_ID,
    });
    expect(result.finalMirroredState).toEqual({
      kind: 'expired_session',
      walletId: WALLET_ID,
      walletSessionId: ACTIVE_SESSION_ID,
      authMethod: 'passkey',
      expiresAtMs: EXPIRES_AT_MS,
    });
    expect(result.lifecycleEventSessionIds).toEqual([STALE_SESSION_ID, ACTIVE_SESSION_ID]);
  });

  test('rejects queued exact requests while admitting requests started after expiry', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, walletId, activeSessionId, expiresAtMs }) => {
        const module = await import(routerPath);
        const { WalletIframeRouter } =
          module as typeof import('@/SeamsWeb/walletIframe/client/router');
        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3_000,
          requestTimeoutMs: 5_000,
          sdkBasePath: '/sdk',
        });
        await router.init();

        const execute = () =>
          router
            .executeAction({
              walletId,
              nearAccountId: 'refactor-92.testnet',
              receiverId: 'w3a-v1.testnet',
              actionArgs: { type: 'Transfer', amount: '1' } as any,
              options: {},
            })
            .then(
              () => ({ kind: 'resolved' as const }),
              (error: unknown) => {
                const candidate = error as {
                  failure?: { code?: unknown; walletSessionId?: unknown };
                };
                return {
                  kind: 'rejected' as const,
                  code: String(candidate.failure?.code || ''),
                  walletSessionId: String(candidate.failure?.walletSessionId || ''),
                };
              },
            );

        const firstRequest = execute();
        await new Promise((resolve) => window.setTimeout(resolve, 30));
        const queuedRequest = execute();
        await new Promise((resolve) => window.setTimeout(resolve, 30));

        const emitSdkLifecycleEvent = Reflect.get(router, 'emitSdkLifecycleEvent');
        if (typeof emitSdkLifecycleEvent !== 'function') {
          throw new Error('wallet iframe lifecycle consumer is unavailable');
        }
        emitSdkLifecycleEvent.call(router, {
          version: 1,
          event: 'signing_session.expired',
          walletId,
          walletSessionId: activeSessionId,
          authMethod: 'passkey',
          expiresAtMs,
          detectedAtMs: Date.now(),
          source: 'server_rejection',
        });

        const [firstResult, queuedResult] = await Promise.all([firstRequest, queuedRequest]);

        let postExpirySettled = false;
        const postExpiryRequest = execute().finally(() => {
          postExpirySettled = true;
        });
        await new Promise((resolve) => window.setTimeout(resolve, 50));
        const postExpirySettledBeforeCancel = postExpirySettled;
        await router.cancelAll();
        const postExpiryResult = await postExpiryRequest;

        return {
          firstResult,
          queuedResult,
          postExpirySettledBeforeCancel,
          postExpiryResult,
        };
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        walletId: WALLET_ID,
        activeSessionId: ACTIVE_SESSION_ID,
        expiresAtMs: EXPIRES_AT_MS,
      },
    );

    expect(result.firstResult).toEqual({
      kind: 'rejected',
      code: 'wallet_session_expired',
      walletSessionId: ACTIVE_SESSION_ID,
    });
    expect(result.queuedResult).toEqual({
      kind: 'rejected',
      code: 'wallet_session_expired',
      walletSessionId: ACTIVE_SESSION_ID,
    });
    expect(result.postExpirySettledBeforeCancel).toBe(false);
    expect(result.postExpiryResult).toEqual({
      kind: 'rejected',
      code: '',
      walletSessionId: '',
    });
  });

  test('locks only the exact session selected by the caller', async ({ page }) => {
    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, expected }) => {
        const module = await import(routerPath);
        const { WalletIframeRouter } =
          module as typeof import('@/SeamsWeb/walletIframe/client/router');
        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3_000,
          requestTimeoutMs: 5_000,
          sdkBasePath: '/sdk',
        });
        await router.init();

        const first = await router.lockExactSession(expected);
        const second = await router.lockExactSession(expected);
        return {
          first,
          second,
          mirroredState: router.getMirroredExactSessionState(),
        };
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        expected: ACTIVE_SESSION_STATE,
      },
    );

    expect(result.first).toEqual({
      kind: 'locked',
      identity: {
        walletId: WALLET_ID,
        walletSessionId: ACTIVE_SESSION_ID,
        authMethod: 'passkey',
        expiresAtMs: EXPIRES_AT_MS,
      },
    });
    expect(result.second).toEqual({
      kind: 'stale_session',
      expected: {
        walletId: WALLET_ID,
        walletSessionId: ACTIVE_SESSION_ID,
        authMethod: 'passkey',
        expiresAtMs: EXPIRES_AT_MS,
      },
      current: { kind: 'wallet_locked' },
    });
    expect(result.mirroredState).toEqual({ kind: 'wallet_locked' });
  });

  test('locks only a wallet that still has no signing session', async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE);
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({
        exactSessionState: {
          kind: 'wallet_unlocked_without_signing_session',
          walletId: WALLET_ID,
          reason: 'not_found',
        },
      }),
      WALLET_SERVICE_ROUTE,
    );

    const result = await page.evaluate(
      async ({ routerPath, walletOrigin, walletId }) => {
        const module = await import(routerPath);
        const { WalletIframeRouter } =
          module as typeof import('@/SeamsWeb/walletIframe/client/router');
        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3_000,
          requestTimeoutMs: 5_000,
          sdkBasePath: '/sdk',
        });
        await router.init();
        return await router.lockMissingSession({ walletId, reason: 'not_found' });
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        walletId: WALLET_ID,
      },
    );

    expect(result).toEqual({
      kind: 'locked',
      identity: { walletId: WALLET_ID, reason: 'not_found' },
    });
  });
});
