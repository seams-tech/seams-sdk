import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors, SDK_ESM_PATHS } from '../setup';
import {
  buildWalletServiceHtml,
  registerWalletServiceRoute,
  waitFor,
  captureOverlay,
} from './harness';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const ALICE_EVM_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
  networkSlug: 'sepolia',
});
const ALICE_WALLET_SESSION = {
  walletId: toWalletId('alice.testnet'),
  walletSessionUserId: 'alice.testnet',
};
const WAIT_FOR_SOURCE = `(${waitFor.toString()})`;
const CAPTURE_OVERLAY_SOURCE = `(${captureOverlay.toString()})`;
const HIDE_SIGNING_SURFACE_SCRIPT = String.raw`
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object') return;
          if (data.type !== 'PM_EXECUTE_ACTION' || typeof data.requestId !== 'string') return;
          setTimeout(() => {
            adoptedPort.postMessage({
              type: 'PROGRESS',
              requestId: data.requestId,
              payload: {
                version: 2,
                flow: 'signing',
                step: 5,
                phase: 'signing.confirmation.approved',
                status: 'succeeded',
                message: 'Confirmation approved; signing in progress',
                flowId: 'signing:test:' + data.requestId,
                requestId: data.requestId,
                interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
              },
            });
          }, 20);
        };
      };
`;
const SIGN_TEMPO_SESSION_LOSS_SCRIPT = String.raw`
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object') return;
          if (data.type !== 'PM_SIGN_TEMPO' || typeof data.requestId !== 'string') return;
          const requestId = data.requestId;
          setTimeout(() => {
            pendingRequests.delete(requestId);
            try {
              adoptedPort.postMessage({
                type: 'ERROR',
                requestId,
                payload: {
                  code: 'session_not_ready',
                  message:
                    '[SigningEngine] missing canonical threshold ECDSA session for alice.testnet; reconnect threshold session via bootstrapEcdsaSession',
                },
              });
            } catch (err) {
              console.error('Failed to post ERROR for PM_SIGN_TEMPO session loss test', err);
            }
          }, 20);
        };
      };
`;
const FAILED_UNLOCK_WITH_ACTIVE_EMAIL_OTP_SESSION_SCRIPT = String.raw`
      const accountId = 'crisp-plain-29ph888gzw.w3a-relayer.testnet';
      const activeEmailOtpSession = {
        login: {
          isLoggedIn: true,
          nearAccountId: accountId,
          publicKey: null,
          userData: null,
          authMethod: 'email_otp',
        },
        signingSession: {
          status: 'active',
          sessionId: 'email-otp-session-1',
          authMethod: 'email_otp',
          retention: 'session',
        },
        authMethod: 'email_otp',
        retention: 'session',
      };
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object' || typeof data.requestId !== 'string') return;
          const requestId = data.requestId;
          if (data.type === 'PM_GET_WALLET_SESSION') {
            pendingRequests.delete(requestId);
            postResult(requestId, activeEmailOtpSession);
            return;
          }
          if (data.type === 'PM_UNLOCK') {
            adoptedPort.postMessage({
              type: 'PROGRESS',
              requestId,
              payload: {
                version: 2,
                flow: 'unlock',
                step: 99,
                phase: 'unlock.failed',
                status: 'failed',
                message: 'No authenticators found for account ' + accountId + '. Please register an account.',
                flowId: 'unlock:test:' + requestId,
                requestId,
                accountId,
                authMethod: 'passkey',
                error: {
                  message: 'No authenticators found for account ' + accountId + '. Please register an account.',
                },
              },
            });
            pendingRequests.delete(requestId);
            postResult(requestId, {
              success: false,
              error: 'No authenticators found for account ' + accountId + '. Please register an account.',
            });
          }
        };
      };
`;
const CAPTURE_UNLOCK_PAYLOAD_SCRIPT = String.raw`
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object' || data.type !== 'PM_UNLOCK') return;
          const requestId = data.requestId;
          if (typeof requestId !== 'string') return;
          pendingRequests.delete(requestId);
          window.parent?.postMessage(
            {
              type: 'CAPTURED_PM_UNLOCK_PAYLOAD',
              payload: data.payload,
            },
            '*',
          );
          adoptedPort.postMessage({
            type: 'PM_RESULT',
            requestId,
            payload: {
              ok: true,
              result: { success: false, error: 'captured unlock payload' },
            },
          });
        };
      };
`;
const EMAIL_OTP_REGISTRATION_SESSION_SCRIPT = String.raw`
      const captureEmailOtpRequest = (requestType) => {
        window.parent?.postMessage(
          {
            type: 'CAPTURED_EMAIL_OTP_ROUTER_REQUEST',
            requestType,
          },
          '*',
        );
      };
      const completedSession = {
        appIdentity: {
          kind: 'resolved',
          walletId: 'alice.testnet',
          nearAccountId: null,
          nearOperationalPublicKey: null,
          userData: null,
          authMethods: [{
            kind: 'email_otp',
            wallet: { walletId: 'alice.testnet' },
            emailHashHex: 'email-hash',
            registrationAuthorityId: 'registration-authority',
          }],
          thresholdEcdsaEthereumAddress: null,
          thresholdEcdsaPublicKeyB64u: null,
        },
        authentication: {
          kind: 'authenticated',
          walletId: 'alice.testnet',
          authMethod: 'email_otp',
        },
        reusableWalletSession: {
          kind: 'missing',
          walletId: 'alice.testnet',
          authorizationId: 'wallet-session-authorization-router-fixture',
          walletSessionId: 'wallet-session-router-fixture',
          authMethod: 'email_otp',
        },
        capabilityProjection: { kind: 'not_requested' },
        nonceDiagnostics: null,
      };
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          const data = event.data || {};
          if (!data || typeof data !== 'object' || typeof data.requestId !== 'string') {
            originalHandler?.(event);
            return;
          }
          const requestId = data.requestId;
          if (data.type === 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH') {
            captureEmailOtpRequest(data.type);
            postResult(requestId, {
              ok: true,
              value: {
                flowHandleId: 'registration-handle-1',
                flowId: 'registration-flow-1',
                state: 'registration_ready',
                requestedMode: 'register',
                mode: 'register',
                walletId: 'alice.testnet',
                emailHint: 'alice@example.com',
                prompt: {
                  title: 'Create your Email OTP wallet',
                  description: 'Google verified alice@example.com.',
                  submitLabel: 'Create wallet',
                  helperText: 'Choose this wallet name.',
                },
                expiresAtMs: Date.now() + 60_000,
              },
            });
            return;
          }
          if (data.type === 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION') {
            captureEmailOtpRequest(data.type);
            postResult(requestId, {
              ok: true,
              value: {
                walletId: 'alice.testnet',
                mode: 'register',
                session: completedSession,
              },
            });
            return;
          }
          if (data.type === 'PM_GET_EXACT_WALLET_SESSION_STATE') {
            captureEmailOtpRequest(data.type);
          }
          originalHandler?.(event);
        };
      };
`;

test.describe('WalletIframeRouter – overlay + timeout behavior', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(200);
    // Register wallet service route with default stub which sends READY and PROGRESS but no PM_RESULT
    await registerWalletServiceRoute(page, buildWalletServiceHtml(), WALLET_SERVICE_ROUTE);
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('addEmailOtp shows an interactive wallet surface while awaiting the OTP', async ({
    page,
  }) => {
    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, waitForSource, routerPath }) => {
        const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
        const mod = await import(routerPath);
        const { WalletIframeRouter } =
          mod as typeof import('@/SeamsWeb/walletIframe/client/router');
        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3000,
          requestTimeoutMs: 100,
          sdkBasePath: '/sdk',
        });
        await router.init();

        let settled = false;
        const request = router
          .addEmailOtp({ walletId: 'alice.testnet', emailAddress: 'alice@example.test' })
          .then(
            () => {
              settled = true;
            },
            () => {
              settled = true;
            },
          );
        const shown = await waitFor(() => router.getOverlayState().visible, 3000);
        await new Promise((resolve) => setTimeout(resolve, 350));
        const state = router.getOverlayState();
        const remainedInteractive = !settled && state.visible;

        router.dispose();
        await request;
        return { shown, remainedInteractive, mode: state.mode };
      },
      { walletOrigin: WALLET_ORIGIN, waitForSource: WAIT_FOR_SOURCE, routerPath },
    );

    expect(result.shown).toBe(true);
    expect(result.remainedInteractive).toBe(true);
    expect(result.mode).toBe('compact_modal');
  });

  test('executeAction shows overlay then hides it after request timeout', async ({ page }) => {
    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, waitForSource, captureOverlaySource, routerPath }) => {
        const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
        const capture = eval(captureOverlaySource) as typeof import('./harness').captureOverlay;
        try {
          // Dynamically import the router from built ESM
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');

          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 200, // short timeout to exercise cleanup
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          // Fire-and-forget request that will time out since the stub never replies with PM_RESULT
          const p = router
            .executeAction({
              walletId: 'e2e_router_timeout.testnet',
              nearAccountId: 'e2e_router_timeout.testnet',
              receiverId: 'seams-v1.testnet',
              actionArgs: { type: 'Transfer', amount: '1' } as any,
              options: {},
            })
            .catch((e) => ({ ok: false, error: String(e?.message || e) }));

          // Expect overlay to become visible soon after posting
          const shown = await waitFor(() => {
            const s = capture();
            return s.exists && s.visible;
          }, 3000);

          // Wait for timeout path and cleanup
          await p;
          // Wait for overlay to contract (hide) after timeout cleanup
          const hidden = await waitFor(() => {
            const s = capture();
            if (!s.exists) return true; // entirely removed counts as hidden
            return !s.visible;
          }, 3000);
          const after = capture();

          return { success: true, shown, hidden, after };
        } catch (error: any) {
          return { success: false, error: error?.message || String(error) };
        }
      },
      {
        walletOrigin: WALLET_ORIGIN,
        waitForSource: WAIT_FOR_SOURCE,
        captureOverlaySource: CAPTURE_OVERLAY_SOURCE,
        routerPath,
      },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success, result.error).toBe(true);
      return;
    }

    expect(result.shown).toBe(true);
    // After timeout, overlay should contract and become inert
    if (!result.hidden) {
      console.log('[router.behavior] overlay state after timeout', result.after);
    }
    expect(result.hidden).toBe(true);
  });

  test('executeAction hides the overlay when signing progress releases the surface', async ({
    page,
  }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: HIDE_SIGNING_SURFACE_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, captureOverlaySource, waitForSource, routerPath }) => {
        const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
        const capture = eval(captureOverlaySource) as typeof import('./harness').captureOverlay;
        const mod = await import(routerPath);
        const { WalletIframeRouter } =
          mod as typeof import('@/SeamsWeb/walletIframe/client/router');
        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3000,
          requestTimeoutMs: 1000,
          debug: true,
          sdkBasePath: '/sdk',
        });
        await router.init();

        const pending = router
          .executeAction({
            walletId: 'e2e_router_signing.testnet',
            nearAccountId: 'e2e_router_signing.testnet',
            receiverId: 'seams-v1.testnet',
            actionArgs: { type: 'Transfer', amount: '1' } as any,
            options: {},
          })
          .catch((error: unknown) => String((error as Error)?.message || error));

        const shown = await waitFor(() => {
          const state = capture();
          return !!(state.exists && state.visible);
        }, 3000);
        const hidden = await waitFor(() => {
          const state = capture();
          return !state.exists || !state.visible;
        }, 3000);
        const requestResult = await pending;
        return { shown, hidden, requestResult };
      },
      {
        walletOrigin: WALLET_ORIGIN,
        captureOverlaySource: CAPTURE_OVERLAY_SOURCE,
        waitForSource: WAIT_FOR_SOURCE,
        routerPath,
      },
    );

    expect(result.shown).toBe(true);
    expect(result.hidden).toBe(true);
    expect(result.requestResult).toContain('Wallet request timeout');
  });

  test('executeAction still times out when host keeps sending PROGRESS frames', async ({
    page,
  }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    const spamProgressHtml = buildWalletServiceHtml({
      extraScript: `
        setInterval(() => {
          if (!adoptedPort) return;
          for (const requestId of pendingRequests.keys()) {
            try {
              adoptedPort.postMessage({
                type: 'PROGRESS',
                requestId,
                payload: {
                  version: 2,
                  flow: 'signing',
                  step: 10,
                  phase: 'signing.commit.started',
                  status: 'running',
                  message: 'Creating threshold signature',
                  flowId: 'signing:test:' + requestId,
                  requestId,
                  interaction: { kind: 'none', overlay: 'none' }
                }
              });
            } catch (err) {
              console.error('Failed to spam PROGRESS frame', err);
            }
          }
        }, 40);
      `,
    });
    await registerWalletServiceRoute(page, spamProgressHtml, WALLET_SERVICE_ROUTE);

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, routerPath }) => {
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');

          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 200,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const start = Date.now();
          const outcome = await router
            .executeAction({
              walletId: 'e2e_router_progress_timeout.testnet',
              nearAccountId: 'e2e_router_progress_timeout.testnet',
              receiverId: 'seams-v1.testnet',
              actionArgs: { type: 'Transfer', amount: '1' } as any,
              options: {},
            })
            .then(
              () => ({ ok: true as const }),
              (error: unknown) => ({
                ok: false as const,
                error: String((error as { message?: unknown })?.message || error || ''),
                elapsedMs: Date.now() - start,
              }),
            );

          return { success: true as const, outcome };
        } catch (error: unknown) {
          return {
            success: false as const,
            error: String((error as { message?: unknown })?.message || error || ''),
          };
        }
      },
      { walletOrigin: WALLET_ORIGIN, routerPath },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.outcome.ok).toBe(false);
    if (result.outcome.ok) return;
    expect(result.outcome.error).toContain('Wallet request timeout for PM_EXECUTE_ACTION');
    expect(result.outcome.elapsedMs).toBeGreaterThanOrEqual(500);
    expect(result.outcome.elapsedMs).toBeLessThan(2500);
  });

  test('signTempo session-loss error is surfaced as session_not_ready with canonical guidance', async ({
    page,
  }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: SIGN_TEMPO_SESSION_LOSS_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, routerPath, chainTarget, walletSession }) => {
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');

          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 800,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const outcome = await router
            .signTempo({
              walletSession,
              chainTarget,
              request: {
                chain: 'evm',
                kind: 'eip1559',
                senderSignatureAlgorithm: 'secp256k1',
                tx: {},
              },
            })
            .then(
              () => ({ ok: true as const }),
              (error: any) => ({
                ok: false as const,
                code: String(error?.code || ''),
                message: String(error?.message || ''),
              }),
            );

          return { success: true as const, outcome };
        } catch (error: any) {
          return { success: false as const, error: error?.message || String(error) };
        }
      },
      {
        walletOrigin: WALLET_ORIGIN,
        routerPath,
        chainTarget: ALICE_EVM_CHAIN_TARGET,
        walletSession: ALICE_WALLET_SESSION,
      },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success, result.error).toBe(true);
      return;
    }

    expect(result.outcome.ok).toBe(false);
    if (result.outcome.ok) return;
    expect(result.outcome.code).toBe('session_not_ready');
    expect(result.outcome.message).toContain('Threshold signing session is not ready');
    expect(result.outcome.message).toContain('Refresh the signing session');
    expect(result.outcome.message).not.toContain('missing canonical threshold ECDSA session');
  });

  test('signTempo remains pending until explicit cancellation', async ({ page }) => {
    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, routerPath, chainTarget, walletSession }) => {
        const mod = await import(routerPath);
        const { WalletIframeRouter } =
          mod as typeof import('@/SeamsWeb/walletIframe/client/router');
        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3000,
          requestTimeoutMs: 25,
          debug: true,
          sdkBasePath: '/sdk',
        });
        await router.init();

        // Keep this test focused on the interactive request policy rather than config discovery.
        (router as any).mirroredConfirmationUiMode = 'modal';
        const nativeSetTimeout = window.setTimeout;
        const timeoutDelays: number[] = [];
        window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) => {
          timeoutDelays.push(Number(timeout ?? 0));
          return nativeSetTimeout(handler, timeout, ...args);
        }) as typeof window.setTimeout;

        try {
          const signing = router
            .signTempo({
              walletSession,
              chainTarget,
              request: {
                chain: 'evm',
                kind: 'eip1559',
                senderSignatureAlgorithm: 'secp256k1',
                tx: {},
              },
            })
            .then(
              () => ({ ok: true as const, message: '' }),
              (error: unknown) => ({
                ok: false as const,
                message: String((error as { message?: unknown })?.message || error || ''),
              }),
            );

          const pendingStartedAt = Date.now();
          while ((router as any).state.pending.size === 0 && Date.now() - pendingStartedAt < 1000) {
            await new Promise<void>((resolve) => nativeSetTimeout(resolve, 10));
          }
          const pendingEntries = Array.from((router as any).state.pending.entries()) as Array<
            [string, { requestType?: string }]
          >;
          const requestId = pendingEntries.find(
            ([, pending]) => pending.requestType === 'PM_SIGN_TEMPO',
          )?.[0];
          if (!requestId) throw new Error('PM_SIGN_TEMPO request did not become pending');

          const stillPendingAfterShortWait = await Promise.race([
            signing.then(() => false),
            new Promise<boolean>((resolve) => nativeSetTimeout(() => resolve(true), 100)),
          ]);
          const hasThirtySecondDeadline = timeoutDelays.some(
            (delay) => delay >= 29_000 && delay <= 31_000,
          );

          await router.cancelRequest(requestId);
          const outcome = await signing;
          return { hasThirtySecondDeadline, stillPendingAfterShortWait, outcome };
        } finally {
          window.setTimeout = nativeSetTimeout;
        }
      },
      {
        walletOrigin: WALLET_ORIGIN,
        routerPath,
        chainTarget: ALICE_EVM_CHAIN_TARGET,
        walletSession: ALICE_WALLET_SESSION,
      },
    );

    expect(result.hasThirtySecondDeadline).toBe(false);
    expect(result.stillPendingAfterShortWait).toBe(true);
    expect(result.outcome).toEqual({ ok: false, message: 'Request cancelled.' });
  });

  test('failed passkey unlock does not publish stale Email OTP login status', async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({
        extraScript: FAILED_UNLOCK_WITH_ACTIVE_EMAIL_OTP_SESSION_SCRIPT,
      }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, routerPath }) => {
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');

          const accountId = 'crisp-plain-29ph888gzw.w3a-relayer.testnet';
          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 1000,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const statuses: Array<{ isLoggedIn: boolean; walletId: string | null }> = [];
          router.onLoginStatusChanged((status) => statuses.push(status));

          const unlockResult = await router.unlock({
            kind: 'default_options',
            walletId: accountId,
          });

          return {
            success: true as const,
            unlockResult,
            statuses,
          };
        } catch (error: unknown) {
          return {
            success: false as const,
            error: String((error as { message?: unknown })?.message || error || ''),
          };
        }
      },
      { walletOrigin: WALLET_ORIGIN, routerPath },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success, result.error).toBe(true);
      return;
    }

    expect(result.unlockResult.success).toBe(false);
    expect(result.unlockResult.error).toContain('No authenticators found');
    expect(result.statuses).toEqual([]);
  });

  test('Email OTP registration mirrors its returned session without another iframe request', async ({
    page,
  }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({
        extraScript: EMAIL_OTP_REGISTRATION_SESSION_SCRIPT,
      }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, routerPath }) => {
        const requestTypes: string[] = [];
        const captureRequest = (event: MessageEvent): void => {
          const data = event.data;
          if (!data || typeof data !== 'object') return;
          if ((data as { type?: unknown }).type !== 'CAPTURED_EMAIL_OTP_ROUTER_REQUEST') return;
          const requestType = (data as { requestType?: unknown }).requestType;
          if (typeof requestType === 'string') requestTypes.push(requestType);
        };
        window.addEventListener('message', captureRequest);
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');
          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 1000,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const statuses: Array<{ isLoggedIn: boolean; walletId: string | null }> = [];
          router.onLoginStatusChanged((status) => statuses.push(status));
          const started = await router.beginGoogleEmailOtpWalletAuth({
            idToken: 'google-id-token',
            mode: 'register',
          });
          if (!started.ok || started.value.mode !== 'register') {
            throw new Error('Expected Google Email OTP registration flow');
          }
          const completed = await started.value.completeRegistration();

          return {
            success: true as const,
            completed,
            requestTypes,
            statuses,
            mirroredSession: router.getMirroredExactSessionState(),
          };
        } catch (error: unknown) {
          return {
            success: false as const,
            error: String((error as { message?: unknown })?.message || error || ''),
          };
        } finally {
          window.removeEventListener('message', captureRequest);
        }
      },
      { walletOrigin: WALLET_ORIGIN, routerPath },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success, result.error).toBe(true);
      return;
    }

    expect(result.completed.ok).toBe(true);
    expect(result.requestTypes).toEqual([
      'PM_GET_EXACT_WALLET_SESSION_STATE',
      'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH',
      'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION',
    ]);
    expect(result.statuses).toEqual([{ isLoggedIn: true, walletId: 'alice.testnet' }]);
    expect(result.mirroredSession).toEqual({
      kind: 'wallet_unlocked_without_signing_session',
      walletId: 'alice.testnet',
      authorizationId: 'wallet-session-authorization-router-fixture',
      walletSessionId: 'wallet-session-router-fixture',
      authMethod: 'email_otp',
      reason: 'not_found',
    });
  });

  test('unlock posts strict protocol options for selection and ECDSA inventory', async ({
    page,
  }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({
        extraScript: CAPTURE_UNLOCK_PAYLOAD_SCRIPT,
      }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({ walletOrigin, routerPath }) => {
        const capturedPayload = new Promise((resolve) => {
          const onMessage = (event: MessageEvent) => {
            const data = event.data || {};
            if (!data || typeof data !== 'object') return;
            if ((data as { type?: unknown }).type !== 'CAPTURED_PM_UNLOCK_PAYLOAD') return;
            window.removeEventListener('message', onMessage);
            resolve((data as { payload: unknown }).payload);
          };
          window.addEventListener('message', onMessage);
        });

        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');
          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 1000,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const unlockResult = await router.unlock({
            kind: 'custom_options',
            walletId: 'alice.testnet',
            options: {
              signerSlot: 2,
              signingSession: {
                ttlMs: 60_000,
                remainingUses: 2,
              },
              unlockSelection: {
                mode: 'ecdsa_only',
                ecdsa: true,
              },
              ecdsaKeyFactsInventory: {
                mode: 'webauthn',
              },
            },
          });

          return {
            success: true as const,
            unlockResult,
            capturedPayload: await capturedPayload,
          };
        } catch (error: unknown) {
          return {
            success: false as const,
            error: String((error as { message?: unknown })?.message || error || ''),
          };
        }
      },
      { walletOrigin: WALLET_ORIGIN, routerPath },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.unlockResult).toEqual({
      success: false,
      error: 'captured unlock payload',
    });
    expect(result.capturedPayload).toEqual({
      kind: 'custom_options',
      walletId: 'alice.testnet',
      options: {
        kind: 'pm_unlock_options_v1',
        signerSlot: { kind: 'value', value: 2 },
        signingSession: {
          kind: 'value',
          value: {
            ttlMs: 60_000,
            remainingUses: 2,
          },
        },
        unlockSelection: {
          kind: 'value',
          value: {
            mode: 'ecdsa_only',
            ecdsa: true,
          },
        },
        ecdsaKeyFactsInventory: {
          kind: 'value',
          value: {
            mode: 'webauthn',
          },
        },
      },
    });
  });
});
