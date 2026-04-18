import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  provider: '/sdk/esm/react/context/TatchiPasskeyProvider.js',
  reactIndex: '/sdk/esm/react/index.js',
  passkeyAuthMenu: '/sdk/esm/react/components/PasskeyAuthMenu/passkeyAuthMenuCompat.js',
  passkeyAuthMenuController:
    '/sdk/esm/react/components/PasskeyAuthMenu/controller/usePasskeyAuthMenuController.js',
  authMenuTypes: '/sdk/esm/react/components/PasskeyAuthMenu/authMenuTypes.js',
  reactStyles: '/sdk/esm/react/styles/styles.css',
} as const;

test.describe('PasskeyAuthMenu styles bootstrap', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('renders styled UI when react/styles is loaded before mount', async ({ page }) => {
    await page.evaluate(
      async ({ paths }) => {
        // Simulate app bootstrap: load SDK styles once at the root before mounting any UI.
        await new Promise<void>((resolve, reject) => {
          const link = document.createElement('link');
          link.rel = 'stylesheet';
          link.href = paths.reactStyles;
          link.addEventListener('load', () => resolve());
          link.addEventListener('error', () =>
            reject(new Error(`Failed to load: ${paths.reactStyles}`)),
          );
          document.head.appendChild(link);
        });

        const mount = document.createElement('div');
        mount.id = 'pam2-test-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.passkeyAuthMenu);

        const Provider = providerMod.TatchiPasskeyProvider || providerMod.default;
        const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          // Disable wallet iframe mode for this unit test (no iframe handshake / COEP concerns).
          iframeWallet: { walletOrigin: '' },
        };

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(Provider, { config }, React.createElement(PasskeyAuthMenu, null)),
          );
        });

        // Save refs so the test can unmount/remount and assert no fallback flash after the first load.
        (window as any).__w3a_pam2_root__ = root;
        (window as any).__w3a_pam2_config__ = config;
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#pam2-test-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await expect(mount.locator('.w3a-seg')).toHaveCount(1);
    await expect(mount.locator('.w3a-arrow-btn')).toHaveCount(1);

    const root = mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)');
    const sentinel = await root.evaluate((el) =>
      window.getComputedStyle(el).getPropertyValue('--w3a-pam2-css-ready').trim(),
    );
    expect(sentinel).toBe('1');

    await expect(mount.getByRole('button', { name: 'Register with Google SSO' })).toBeDisabled();

    const radius = await root.evaluate((el) => window.getComputedStyle(el).borderTopLeftRadius);
    expect(radius).not.toBe('0px');

    const remount = await page.evaluate(
      async ({ paths }) => {
        const mount = document.getElementById('pam2-test-mount');
        if (!mount) throw new Error('missing #pam2-test-mount');

        const existingRoot = (window as any).__w3a_pam2_root__;
        if (existingRoot?.unmount) existingRoot.unmount();

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.passkeyAuthMenu);

        const Provider = providerMod.TatchiPasskeyProvider || providerMod.default;
        const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;

        const config = (window as any).__w3a_pam2_config__ || {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        };

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(Provider, { config }, React.createElement(PasskeyAuthMenu, null)),
          );
        });
        (window as any).__w3a_pam2_root__ = root;

        const hadSkeletonAtFirstFrame = await new Promise<boolean>((resolve) => {
          requestAnimationFrame(() => {
            resolve(!!mount.querySelector('.w3a-signup-menu-root.w3a-skeleton'));
          });
        });

        const hasClientMenuAtFirstFrame = !!mount.querySelector(
          '.w3a-signup-menu-root:not(.w3a-skeleton)',
        );

        return { hadSkeletonAtFirstFrame, hasClientMenuAtFirstFrame };
      },
      { paths: IMPORT_PATHS },
    );

    expect(remount.hadSkeletonAtFirstFrame).toBe(false);
    expect(remount.hasClientMenuAtFirstFrame).toBe(true);
  });

  test('login mode shows passkey and Google SSO Email OTP methods without legacy email recovery CTA', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        await new Promise<void>((resolve, reject) => {
          const link = document.createElement('link');
          link.rel = 'stylesheet';
          link.href = paths.reactStyles;
          link.addEventListener('load', () => resolve());
          link.addEventListener('error', () =>
            reject(new Error(`Failed to load: ${paths.reactStyles}`)),
          );
          document.head.appendChild(link);
        });

        const mount = document.createElement('div');
        mount.id = 'pam2-login-methods-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.passkeyAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.TatchiPasskeyProvider || providerMod.default;
        const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        };

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(PasskeyAuthMenu, {
                defaultMode: AuthMenuMode.Login,
                socialLogin: {
                  google: () => ({ username: 'alice' }),
                },
              }),
            ),
          );
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#pam2-login-methods-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Login' }).click();
    await expect(mount.getByRole('button', { name: 'Continue with Passkey' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Continue with Email OTP' })).toHaveCount(0);
    await expect(mount.getByRole('button', { name: 'Sign in with Google SSO' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Scan and Link Device' })).toBeVisible();
    await expect(
      mount.getByText(
        'Google SSO signs you in, then a 6-digit email code unlocks signing for this session. Passkey is recommended for stronger security.',
      ),
    ).toBeVisible();
    await expect(mount.getByText('Recover Account with Email')).toHaveCount(0);

    await mount.getByRole('button', { name: 'Register' }).click();
    await expect(mount.getByRole('button', { name: 'Create with Passkey' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Register with Google SSO' })).toBeVisible();
    await expect(
      mount.getByText(
        'Creates a Google SSO account that uses a 6-digit Email OTP for signing. Passkey is recommended for stronger security.',
      ),
    ).toBeVisible();
  });

  test('Google SSO can hand off to the Email OTP unlock prompt', async ({ page }) => {
    await page.evaluate(
      async ({ paths }) => {
        await new Promise<void>((resolve, reject) => {
          const link = document.createElement('link');
          link.rel = 'stylesheet';
          link.href = paths.reactStyles;
          link.addEventListener('load', () => resolve());
          link.addEventListener('error', () =>
            reject(new Error(`Failed to load: ${paths.reactStyles}`)),
          );
          document.head.appendChild(link);
        });

        const mount = document.createElement('div');
        mount.id = 'pam2-google-otp-prompt-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.passkeyAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.TatchiPasskeyProvider || providerMod.default;
        const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        };

        (window as any).__otpSubmitted = '';
        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(PasskeyAuthMenu, {
                defaultMode: AuthMenuMode.Login,
                socialLogin: {
                  google: () => ({
                    username: 'alice',
                    otpPrompt: {
                      title: 'Check your email to unlock your wallet',
                      description: 'Enter the 6-digit code we sent to alice@example.com.',
                      emailHint: 'alice@example.com',
                      onSubmit: async (otpCode: string) => {
                        (window as any).__otpSubmitted = otpCode;
                      },
                    },
                  }),
                },
              }),
            ),
          );
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#pam2-google-otp-prompt-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Sign in with Google SSO' }).click();
    await expect(mount.getByText('Check your email to unlock your wallet')).toBeVisible();
    await expect(mount.getByText('alice@example.com', { exact: true })).toBeVisible();
    await mount.getByLabel('Email code').fill('123456');
    await mount.getByRole('button', { name: 'Unlock wallet' }).click();
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpSubmitted))
      .toBe('123456');
  });

  test('Email OTP resend preserves input, debounces clicks, and updates prompt metadata', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        await new Promise<void>((resolve, reject) => {
          const link = document.createElement('link');
          link.rel = 'stylesheet';
          link.href = paths.reactStyles;
          link.addEventListener('load', () => resolve());
          link.addEventListener('error', () =>
            reject(new Error(`Failed to load: ${paths.reactStyles}`)),
          );
          document.head.appendChild(link);
        });

        const mount = document.createElement('div');
        mount.id = 'pam2-google-otp-resend-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.passkeyAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.TatchiPasskeyProvider || providerMod.default;
        const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        };

        (window as any).__otpResendCalls = 0;
        (window as any).__otpSubmitted = '';
        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(PasskeyAuthMenu, {
                defaultMode: AuthMenuMode.Login,
                socialLogin: {
                  google: () => ({
                    username: 'alice',
                    otpPrompt: {
                      title: 'Check your email to unlock your wallet',
                      description: 'Enter the 6-digit code we sent to alice@example.com.',
                      emailHint: 'alice@example.com',
                      resendDebounceMs: 10_000,
                      onResend: async () => {
                        (window as any).__otpResendCalls += 1;
                        return {
                          challengeId: `challenge-${(window as any).__otpResendCalls}`,
                          emailHint: 'new-alice@example.com',
                        };
                      },
                      onSubmit: async (otpCode: string) => {
                        (window as any).__otpSubmitted = otpCode;
                      },
                    },
                  }),
                },
              }),
            ),
          );
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#pam2-google-otp-resend-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Sign in with Google SSO' }).click();
    await expect(mount.getByText('alice@example.com', { exact: true })).toBeVisible();

    const input = mount.getByLabel('Email code');
    await input.fill('123');
    await mount.getByRole('button', { name: 'Resend code' }).click();
    await expect(input).toHaveValue('123');
    await expect(mount.getByText('new-alice@example.com', { exact: true })).toBeVisible();
    await expect(mount.getByRole('button', { name: /Resend in \d+s/ })).toBeDisabled();
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpResendCalls))
      .toBe(1);

    await input.fill('123456');
    await mount.getByRole('button', { name: 'Unlock wallet' }).click();
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpSubmitted))
      .toBe('123456');
  });

  test('Email OTP resend rate limits render retry copy', async ({ page }) => {
    await page.evaluate(
      async ({ paths }) => {
        await new Promise<void>((resolve, reject) => {
          const link = document.createElement('link');
          link.rel = 'stylesheet';
          link.href = paths.reactStyles;
          link.addEventListener('load', () => resolve());
          link.addEventListener('error', () =>
            reject(new Error(`Failed to load: ${paths.reactStyles}`)),
          );
          document.head.appendChild(link);
        });

        const mount = document.createElement('div');
        mount.id = 'pam2-google-otp-resend-rate-limit-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.passkeyAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.TatchiPasskeyProvider || providerMod.default;
        const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        };

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(PasskeyAuthMenu, {
                defaultMode: AuthMenuMode.Login,
                socialLogin: {
                  google: () => ({
                    username: 'alice',
                    otpPrompt: {
                      title: 'Check your email to unlock your wallet',
                      description: 'Enter the 6-digit code we sent to alice@example.com.',
                      emailHint: 'alice@example.com',
                      onResend: async () => {
                        const error = new Error('Email OTP rate limit exceeded') as Error & {
                          code?: string;
                          retryAfterMs?: number;
                        };
                        error.code = 'rate_limited';
                        error.retryAfterMs = 12_300;
                        throw error;
                      },
                      onSubmit: async () => undefined,
                    },
                  }),
                },
              }),
            ),
          );
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#pam2-google-otp-resend-rate-limit-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Sign in with Google SSO' }).click();
    await mount.getByRole('button', { name: 'Resend code' }).click();
    await expect(mount.getByRole('alert')).toHaveText('Too many requests. Try again in 13s.');
  });

  test('Google SSO Email OTP refreshes wallet state only after OTP success', async ({ page }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'pam2-google-otp-refresh-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.passkeyAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const usePasskeyAuthMenuController = controllerMod.usePasskeyAuthMenuController;
        const { AuthMenuMode } = typesMod;

        (window as any).__otpRefreshCalls = [];
        (window as any).__otpSubmitted = '';

        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('');
          const runtime = React.useMemo(
            () => ({
              tatchiPasskey: {
                auth: {
                  getRecentUnlocks: async () => ({ lastUsedAccount: null }),
                },
              },
              accountExists: false,
              inputUsername,
              targetAccountId: inputUsername,
              setInputUsername,
              refreshLoginState: async (nearAccountId?: string) => {
                (window as any).__otpRefreshCalls.push(String(nearAccountId || ''));
              },
              sdkFlow: {
                eventsText: '',
                seq: 0,
                awaitNextCompletion: async () => undefined,
              },
              displayPostfix: '.testnet',
              isUsingExistingAccount: false,
            }),
            [inputUsername],
          );

          const controller = usePasskeyAuthMenuController(
            {
              defaultMode: AuthMenuMode.Login,
              socialLogin: {
                google: async () => ({
                  username: 'alice.testnet',
                  otpPrompt: {
                    title: 'Check your email to unlock your wallet',
                    description: 'Enter the 6-digit code we sent to alice@example.com.',
                    emailHint: 'alice@example.com',
                    onSubmit: async (otpCode: string) => {
                      (window as any).__otpSubmitted = otpCode;
                    },
                  },
                }),
              },
            },
            runtime,
          );

          return React.createElement(
            'div',
            null,
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () => controller.onSocialLogin('google', AuthMenuMode.Login),
              },
              'Start Google',
            ),
            controller.otpPrompt
              ? React.createElement(
                  React.Fragment,
                  null,
                  React.createElement('div', { id: 'otp-ready' }, controller.otpPrompt.title),
                  React.createElement('input', {
                    'aria-label': 'Email code',
                    value: controller.otpPrompt.code,
                    onChange: (event: React.ChangeEvent<HTMLInputElement>) =>
                      controller.otpPrompt?.onCodeChange(event.currentTarget.value),
                  }),
                  React.createElement(
                    'button',
                    {
                      type: 'button',
                      onClick: controller.otpPrompt.onSubmit,
                    },
                    'Unlock wallet',
                  ),
                )
              : null,
          );
        }

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(React.createElement(Harness));
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#pam2-google-otp-refresh-mount');
    await mount.getByRole('button', { name: 'Start Google' }).click();
    await expect(mount.locator('#otp-ready')).toHaveText('Check your email to unlock your wallet');
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpRefreshCalls))
      .toEqual([]);

    await mount.getByLabel('Email code').fill('123456');
    await mount.getByRole('button', { name: 'Unlock wallet' }).click();

    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpSubmitted))
      .toBe('123456');
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpRefreshCalls))
      .toEqual(['alice.testnet']);
  });

  test('Google SSO buttons pass explicit register and login modes', async ({ page }) => {
    await page.evaluate(
      async ({ paths }) => {
        await new Promise<void>((resolve, reject) => {
          const link = document.createElement('link');
          link.rel = 'stylesheet';
          link.href = paths.reactStyles;
          link.addEventListener('load', () => resolve());
          link.addEventListener('error', () =>
            reject(new Error(`Failed to load: ${paths.reactStyles}`)),
          );
          document.head.appendChild(link);
        });

        const mount = document.createElement('div');
        mount.id = 'pam2-google-mode-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.passkeyAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.TatchiPasskeyProvider || providerMod.default;
        const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;
        const { AuthMenuMode, AuthMenuModeMap } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        };

        (window as any).__pamGoogleModes = [];
        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(PasskeyAuthMenu, {
                defaultMode: AuthMenuMode.Login,
                socialLogin: {
                  google: (args: { mode: number }) => {
                    (window as any).__pamGoogleModes.push(AuthMenuModeMap[args.mode]);
                  },
                },
              }),
            ),
          );
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#pam2-google-mode-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Sign in with Google SSO' }).click();
    await mount.getByRole('button', { name: 'Register' }).click();
    await mount.getByRole('button', { name: 'Register with Google SSO' }).click();

    await expect
      .poll(async () => await page.evaluate(() => (window as any).__pamGoogleModes))
      .toEqual(['login', 'register']);
  });

  test('Google SSO errors render inline without unhandled promise rejection', async ({ page }) => {
    await page.evaluate(
      async ({ paths }) => {
        await new Promise<void>((resolve, reject) => {
          const link = document.createElement('link');
          link.rel = 'stylesheet';
          link.href = paths.reactStyles;
          link.addEventListener('load', () => resolve());
          link.addEventListener('error', () =>
            reject(new Error(`Failed to load: ${paths.reactStyles}`)),
          );
          document.head.appendChild(link);
        });

        const mount = document.createElement('div');
        mount.id = 'pam2-google-error-mount';
        document.body.appendChild(mount);
        (window as any).__pamUnhandledRejectionCount = 0;
        window.addEventListener('unhandledrejection', () => {
          (window as any).__pamUnhandledRejectionCount += 1;
        });

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.passkeyAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.TatchiPasskeyProvider || providerMod.default;
        const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        };

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(PasskeyAuthMenu, {
                defaultMode: AuthMenuMode.Register,
                socialLogin: {
                  google: async () => {
                    throw new Error('Email OTP rate limit exceeded');
                  },
                },
              }),
            ),
          );
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#pam2-google-error-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Register with Google SSO' }).click();
    await expect(mount.getByRole('alert')).toHaveText('Email OTP rate limit exceeded');
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__pamUnhandledRejectionCount))
      .toBe(0);
  });

  test('React SDK-flow proxy preserves Email OTP auth methods', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'pam2-auth-surface-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const reactMod: any = await import(paths.reactIndex);

        const Provider = providerMod.TatchiPasskeyProvider || providerMod.default;
        const { useTatchi } = reactMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        };

        const methodNames = [
          'requestEmailOtpChallenge',
          'requestEmailOtpEnrollmentChallenge',
          'enrollEmailOtp',
          'loginWithEmailOtpEcdsaCapability',
          'enrollAndLoginWithEmailOtpEcdsaCapability',
        ];

        function Probe() {
          const { tatchi } = useTatchi();
          React.useEffect(() => {
            (window as any).__authSurface__ = Object.fromEntries(
              methodNames.map((name) => [name, typeof (tatchi.auth as any)[name]]),
            );
          }, [tatchi]);
          return React.createElement('div', { id: 'auth-surface-ready' }, 'ready');
        }

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(React.createElement(Provider, { config }, React.createElement(Probe)));
        });

        return await new Promise<Record<string, string>>((resolve, reject) => {
          const startedAt = Date.now();
          const poll = () => {
            const surface = (window as any).__authSurface__;
            if (surface) {
              resolve(surface);
              return;
            }
            if (Date.now() - startedAt > 3000) {
              reject(new Error('auth surface probe timed out'));
              return;
            }
            setTimeout(poll, 25);
          };
          poll();
        });
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      requestEmailOtpChallenge: 'function',
      requestEmailOtpEnrollmentChallenge: 'function',
      enrollEmailOtp: 'function',
      loginWithEmailOtpEcdsaCapability: 'function',
      enrollAndLoginWithEmailOtpEcdsaCapability: 'function',
    });
  });
});
