import { expect, test } from '@playwright/test';

const IMPORT_PATHS = {
  googleIdentity: '/src/shared/auth/googleIdentity.ts',
} as const;

test.describe('Google Identity One Tap handling', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('requests One Tap without a FedCM prompt moment listener', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        let initializedConfig: Record<string, unknown> | null = null;
        let initializeCount = 0;
        let promptArgumentCount = -1;
        const nativeSetTimeout = window.setTimeout.bind(window);
        const nativeClearTimeout = window.clearTimeout.bind(window);
        window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) =>
          nativeSetTimeout(
            handler,
            timeout === 8_000 || timeout === 60_000 ? 1_000 : timeout,
            ...args,
          )) as typeof window.setTimeout;
        window.clearTimeout = ((handle?: number) =>
          nativeClearTimeout(handle)) as typeof window.clearTimeout;

        (window as any).google = {
          accounts: {
            id: {
              initialize(config: Record<string, unknown>) {
                initializeCount += 1;
                initializedConfig = config;
              },
              prompt(...args: unknown[]) {
                promptArgumentCount = args.length;
                nativeSetTimeout(() => {
                  const callback = initializedConfig?.callback as
                    | ((response: { credential: string }) => void)
                    | undefined;
                  callback?.({ credential: 'google-id-token' });
                }, 20);
              },
              cancel() {},
            },
          },
        };

        try {
          const { requestGoogleIdToken } = await import(paths.googleIdentity);
          const token = await requestGoogleIdToken('google-client-id');
          return { ok: true, token, initializeCount, promptArgumentCount, message: '' };
        } catch (error) {
          return {
            ok: false,
            token: '',
            initializeCount,
            promptArgumentCount,
            message: error instanceof Error ? error.message : String(error),
          };
        } finally {
          window.setTimeout = nativeSetTimeout as typeof window.setTimeout;
          window.clearTimeout = nativeClearTimeout as typeof window.clearTimeout;
          delete (window as any).google;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      ok: true,
      token: 'google-id-token',
      initializeCount: 1,
      promptArgumentCount: 0,
      message: '',
    });
  });

  test('reuses the initialized Google client for repeated requests', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        let initializedConfig: Record<string, unknown> | null = null;
        let initializeCount = 0;
        let promptCount = 0;
        const nativeSetTimeout = window.setTimeout.bind(window);
        const nativeClearTimeout = window.clearTimeout.bind(window);
        window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) =>
          nativeSetTimeout(
            handler,
            timeout === 8_000 || timeout === 60_000 ? 1_000 : timeout,
            ...args,
          )) as typeof window.setTimeout;
        window.clearTimeout = ((handle?: number) =>
          nativeClearTimeout(handle)) as typeof window.clearTimeout;

        (window as any).google = {
          accounts: {
            id: {
              initialize(config: Record<string, unknown>) {
                initializeCount += 1;
                initializedConfig = config;
              },
              prompt(...args: unknown[]) {
                if (args.length !== 0) {
                  throw new Error('prompt listener must not be installed');
                }
                promptCount += 1;
                const credential = `google-id-token-${promptCount}`;
                nativeSetTimeout(() => {
                  const callback = initializedConfig?.callback as
                    | ((response: { credential: string }) => void)
                    | undefined;
                  callback?.({ credential });
                }, 20);
              },
              cancel() {},
            },
          },
        };

        try {
          const { requestGoogleIdToken } = await import(paths.googleIdentity);
          const firstToken = await requestGoogleIdToken('google-client-id');
          const secondToken = await requestGoogleIdToken('google-client-id');
          return { ok: true, firstToken, secondToken, initializeCount, promptCount, message: '' };
        } catch (error) {
          return {
            ok: false,
            firstToken: '',
            secondToken: '',
            initializeCount,
            promptCount,
            message: error instanceof Error ? error.message : String(error),
          };
        } finally {
          window.setTimeout = nativeSetTimeout as typeof window.setTimeout;
          window.clearTimeout = nativeClearTimeout as typeof window.clearTimeout;
          delete (window as any).google;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      ok: true,
      firstToken: 'google-id-token-1',
      secondToken: 'google-id-token-2',
      initializeCount: 1,
      promptCount: 2,
      message: '',
    });
  });

  test('fails promptly when Google never returns a credential callback', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        let initializeCount = 0;
        let promptCount = 0;
        let cancelCount = 0;
        const nativeSetTimeout = window.setTimeout.bind(window);
        const nativeClearTimeout = window.clearTimeout.bind(window);
        window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) =>
          nativeSetTimeout(
            handler,
            timeout === 8_000 || timeout === 60_000 ? 10 : timeout,
            ...args,
          )) as typeof window.setTimeout;
        window.clearTimeout = ((handle?: number) =>
          nativeClearTimeout(handle)) as typeof window.clearTimeout;

        (window as any).google = {
          accounts: {
            id: {
              initialize() {
                initializeCount += 1;
              },
              prompt(...args: unknown[]) {
                if (args.length !== 0) {
                  throw new Error('prompt listener must not be installed');
                }
                promptCount += 1;
              },
              cancel() {
                cancelCount += 1;
              },
            },
          },
        };

        try {
          const { requestGoogleIdToken } = await import(paths.googleIdentity);
          await requestGoogleIdToken('google-client-id');
          return { ok: true, initializeCount, promptCount, cancelCount, message: '' };
        } catch (error) {
          return {
            ok: false,
            initializeCount,
            promptCount,
            cancelCount,
            message: error instanceof Error ? error.message : String(error),
          };
        } finally {
          window.setTimeout = nativeSetTimeout as typeof window.setTimeout;
          window.clearTimeout = nativeClearTimeout as typeof window.clearTimeout;
          delete (window as any).google;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      ok: false,
      initializeCount: 1,
      promptCount: 1,
      cancelCount: 1,
      message:
        'Google sign-in did not return a token. Check browser sign-in settings, OAuth origin configuration, or retry from a fresh Google session.',
    });
  });
});
