import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest, SDK_ESM_PATHS } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute } from './harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const WALLET_ID = 'refactor-92-wallet';
const ACTIVE_SESSION_ID = 'wss_refactor_92_active';
const STALE_SESSION_ID = 'wss_refactor_92_stale';
const AUTHORIZATION_ID = 'wsa_refactor_92_active';
const EXPIRES_AT_MS = 4_102_444_800_000;

const ACTIVE_SESSION_STATE = {
  kind: 'active_session',
  status: 'active',
  walletId: WALLET_ID,
  authorizationId: AUTHORIZATION_ID,
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

  test('forwards each exact event once without cancelling the operation that will step up', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({
        routerPath,
        walletOrigin,
        walletId,
        activeSessionId,
        staleSessionId,
        expiresAtMs,
      }) => {
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
        const loginStatuses: Array<{ isLoggedIn: boolean; walletId: string | null }> = [];
        router.onSdkLifecycleEvent((event) => lifecycleEvents.push(event));
        router.onLoginStatusChanged((status) => loginStatuses.push(status));
        await router.init();

        let requestSettled = false;
        const pendingRequest = router
          .executeAction({
            walletId,
            nearAccountId: 'refactor-92.testnet',
            receiverId: 'seams-v1.testnet',
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
          loginStatuses: [...loginStatuses],
        };

        const activeExpiry = {
          ...staleExpiry,
          walletSessionId: activeSessionId,
          detectedAtMs: Date.now(),
        };
        emitSdkLifecycleEvent.call(router, activeExpiry);
        emitSdkLifecycleEvent.call(router, activeExpiry);
        await new Promise((resolve) => window.setTimeout(resolve, 50));
        const requestSettledAfterExpiry = requestSettled;
        await router.cancelAll();
        const requestResult = await pendingRequest;

        return {
          staleEventResult,
          requestSettledAfterExpiry,
          requestResult,
          finalMirroredState: router.getMirroredExactSessionState(),
          lifecycleEventSessionIds: lifecycleEvents.map((event) => event.walletSessionId),
          loginStatuses,
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
    expect(result.staleEventResult.loginStatuses).toEqual([
      { isLoggedIn: true, walletId: WALLET_ID },
    ]);
    expect(result.requestSettledAfterExpiry).toBe(false);
    expect(result.requestResult.kind).toBe('rejected');
    expect(result.requestResult.code).not.toBe('wallet_session_expired');
    expect(result.finalMirroredState).toEqual({
      kind: 'expired_session',
      walletId: WALLET_ID,
      authorizationId: AUTHORIZATION_ID,
      walletSessionId: ACTIVE_SESSION_ID,
      authMethod: 'passkey',
      expiresAtMs: EXPIRES_AT_MS,
    });
    expect(result.lifecycleEventSessionIds).toEqual([STALE_SESSION_ID, ACTIVE_SESSION_ID]);
    expect(result.loginStatuses).toEqual([
      { isLoggedIn: true, walletId: WALLET_ID },
      { isLoggedIn: true, walletId: WALLET_ID },
    ]);
  });

  test('keeps active and queued operations eligible for step-up after expiry', async ({ page }) => {
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
              receiverId: 'seams-v1.testnet',
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

        let firstSettled = false;
        const firstRequest = execute().finally(() => {
          firstSettled = true;
        });
        await new Promise((resolve) => window.setTimeout(resolve, 30));
        let queuedSettled = false;
        const queuedRequest = execute().finally(() => {
          queuedSettled = true;
        });
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

        await new Promise((resolve) => window.setTimeout(resolve, 50));
        const settledAfterExpiry = { first: firstSettled, queued: queuedSettled };
        await router.cancelAll();
        const [firstResult, queuedResult] = await Promise.all([firstRequest, queuedRequest]);

        return {
          firstResult,
          queuedResult,
          settledAfterExpiry,
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

    expect(result.settledAfterExpiry).toEqual({ first: false, queued: false });
    expect(result.firstResult.code).not.toBe('wallet_session_expired');
    expect(result.queuedResult.code).not.toBe('wallet_session_expired');
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
        authorizationId: AUTHORIZATION_ID,
        walletSessionId: ACTIVE_SESSION_ID,
        authMethod: 'passkey',
        expiresAtMs: EXPIRES_AT_MS,
      },
    });
    expect(result.second).toEqual({
      kind: 'stale_session',
      expected: {
        walletId: WALLET_ID,
        authorizationId: AUTHORIZATION_ID,
        walletSessionId: ACTIVE_SESSION_ID,
        authMethod: 'passkey',
        expiresAtMs: EXPIRES_AT_MS,
      },
      current: { kind: 'wallet_locked' },
    });
    expect(result.mirroredState).toEqual({ kind: 'wallet_locked' });
  });
});
