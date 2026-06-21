import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  provider: '/sdk/esm/react/context/SeamsWebProvider.js',
  reactIndex: '/sdk/esm/react/index.js',
  passkeyAuthMenu: '/sdk/esm/react/components/PasskeyAuthMenu/public.js',
  passkeyAuthMenuController:
    '/sdk/esm/react/components/PasskeyAuthMenu/controller/usePasskeyAuthMenuController.js',
  passkeyInput: '/sdk/esm/react/components/PasskeyAuthMenu/ui/PasskeyInput.js',
  authMenuTypes: '/sdk/esm/react/components/PasskeyAuthMenu/authMenuTypes.js',
  reactStyles: '/sdk/esm/react/styles/styles.css',
} as const;

test.describe('PasskeyAuthMenu styles bootstrap', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
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

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
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
    await expect(mount.locator('.w3a-passkey-row button')).toHaveCount(0);

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

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
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

  test('login mode shows passkey and Google SSO Email OTP methods without email recovery CTA', async ({
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

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
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
    await expect(mount.locator('.w3a-social-helper')).toHaveCount(0);
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

  test('account dropdown groups accounts from auth method metadata', async ({ page }) => {
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
        mount.id = 'pam2-account-groups-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const inputMod: any = await import(paths.passkeyInput);
        const typesMod: any = await import(paths.authMenuTypes);

        const PasskeyInput = inputMod.PasskeyInput || inputMod.default;
        const { AuthMenuMode } = typesMod;

        function Harness() {
          const [value, setValue] = React.useState('sage-shore-3scqvgt7hl.w3a-relayer.testnet');
          return React.createElement(PasskeyInput, {
            value,
            onChange: setValue,
            placeholder: 'Enter your username',
            mode: AuthMenuMode.Login,
            onProceed: () => undefined,
            accountOptions: [
              {
                nearAccountId: 'gorp12.w3a-relayer.testnet',
                signerSlot: 1,
                authMethod: 'passkey',
              },
              {
                nearAccountId: 'gorp13.w3a-relayer.testnet',
                signerSlot: 1,
                authMethod: 'passkey',
              },
              {
                nearAccountId: 'sage-shore-3scqvgt7hl.w3a-relayer.testnet',
                signerSlot: 1,
                authMethod: 'email_otp',
              },
              {
                nearAccountId: 'n6378056-gmail-com-1776502017920.w3a-relayer.testnet',
                signerSlot: 1,
                authMethod: 'email_otp',
              },
            ],
          });
        }

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(React.createElement(Harness));
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#pam2-account-groups-mount');
    await mount.getByRole('button', { name: 'Saved accounts' }).click();

    const passkeyGroup = mount.locator('.w3a-account-menu-group').filter({ hasText: 'PASSKEY' });
    const emailOtpGroup = mount.locator('.w3a-account-menu-group').filter({ hasText: 'EMAIL OTP' });

    await expect(passkeyGroup).toContainText('gorp12.w3a-relayer.testnet');
    await expect(passkeyGroup).toContainText('gorp13.w3a-relayer.testnet');
    await expect(passkeyGroup).not.toContainText('sage-shore-3scqvgt7hl.w3a-relayer.testnet');
    await expect(emailOtpGroup).toContainText('sage-shore-3scqvgt7hl.w3a-relayer.testnet');
    await expect(emailOtpGroup).toContainText(
      'n6378056-gmail-com-1776502017920.w3a-relayer.testnet',
    );
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

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
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
    await expect(mount.locator('.w3a-otp-email')).toHaveCount(0);
    await expect(mount.getByText(/alice@example\.com/)).toBeVisible();
    await mount.getByLabel('Email code').fill('123456');
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpSubmitted))
      .toBe('123456');
  });

  test('Google SSO registration Email OTP prompt can generate another wallet name', async ({
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
        mount.id = 'pam2-google-otp-reroll-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.passkeyAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        };

        (window as any).__otpRerollCalls = 0;
        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(PasskeyAuthMenu, {
                defaultMode: AuthMenuMode.Register,
                socialLogin: {
                  google: () => ({
                    username: 'frost-beacon.testnet',
                    otpPrompt: {
                      title: 'Check your email to unlock your wallet',
                      description: 'Enter the 6-digit code we sent to alice@example.com.',
                      emailHint: 'alice@example.com',
                      accountId: 'frost-beacon.testnet',
                      submitLabel: 'Unlock wallet',
                      helperText:
                        'Google keeps you signed in. The email code unlocks wallet signing for this session.',
                      onRerollAccount: async () => {
                        (window as any).__otpRerollCalls += 1;
                        return {
                          username: 'ember-river.testnet',
                          accountId: 'ember-river.testnet',
                          emailHint: 'alice@example.com',
                          title: 'Check your email to finish registration',
                          description:
                            'Enter the 6-digit setup code we sent to alice@example.com.',
                          submitLabel: 'Create wallet',
                          helperText:
                            'Google started your wallet registration. The email code secures wallet signing for this account.',
                        };
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

    const mount = page.locator('#pam2-google-otp-reroll-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Register with Google SSO' }).click();
    await expect(mount.getByText('frost-beacon.testnet')).toBeVisible();
    await mount.getByRole('button', { name: 'Generate another name' }).click();
    await expect(mount.getByText('ember-river.testnet')).toBeVisible();
    await expect(mount.getByText('Check your email to finish registration')).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Create wallet' })).toBeVisible();
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpRerollCalls))
      .toBe(1);
  });

  test('Google SSO can hand off to an Email OTP device recovery prompt', async ({ page }) => {
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
        mount.id = 'pam2-google-otp-recovery-key-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.passkeyAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        };

        (window as any).__otpRecoverySubmit = null;
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
                      title: 'Recover this device',
                      description: 'Enter the email code and one recovery key.',
                      submitLabel: 'Recover device',
                      recoveryKey: {
                        required: true,
                        scanLabel: 'Scan key',
                        onScan: async () => '008j4ct4ank7f24snaxwsqfezw834n3p',
                      },
                      onSubmit: async (otpCode: string, context?: { recoveryKey?: string }) => {
                        (window as any).__otpRecoverySubmit = {
                          otpCode,
                          recoveryKey: context?.recoveryKey,
                        };
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

    const mount = page.locator('#pam2-google-otp-recovery-key-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Sign in with Google SSO' }).click();
    await expect(mount.getByText('Recover this device')).toBeVisible();

    await mount.getByLabel('Email code').fill('123456');
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpRecoverySubmit))
      .toBeNull();

    const recoveryKeyInput = mount.getByLabel('Recovery key');
    await recoveryKeyInput.fill('008j4ct4ank7f24snaxwsqfezw834n3p');
    await expect(recoveryKeyInput).toHaveValue('008J-4CT4-ANK7-F24S-NAXW-SQFE-ZW83-4N3P');
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpRecoverySubmit))
      .toEqual({
        otpCode: '123456',
        recoveryKey: '008J-4CT4-ANK7-F24S-NAXW-SQFE-ZW83-4N3P',
      });
  });

  test('Email OTP resend preserves input, debounces clicks, and restores resend label', async ({
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

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
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
                      resendDebounceMs: 1_000,
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
    await expect(mount.getByText(/alice@example\.com/)).toBeVisible();

    const input = mount.getByLabel('Email code');
    await input.fill('123');
    await mount.getByRole('button', { name: 'Resend Code' }).click();
    await expect(input).toHaveValue('123');
    await expect(mount.getByRole('button', { name: 'Code sent' })).toBeDisabled();
    await expect(mount.getByRole('button', { name: 'Resend Code' })).toBeEnabled({
      timeout: 2_000,
    });
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpResendCalls))
      .toBe(1);

    await input.fill('123456');
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

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
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
    await mount.getByRole('button', { name: 'Resend Code' }).click();
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
              seamsWeb: {
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

  test('Google SSO headless Email OTP flow does not duplicate wallet refresh', async ({ page }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'pam2-google-headless-otp-refresh-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.passkeyAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const usePasskeyAuthMenuController = controllerMod.usePasskeyAuthMenuController;
        const { AuthMenuMode } = typesMod;

        (window as any).__headlessRefreshCalls = [];
        (window as any).__headlessSubmitted = '';
        (window as any).__headlessCompletions = [];

        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('');
          const runtime = React.useMemo(
            () => ({
              seamsWeb: {
                auth: {
                  getRecentUnlocks: async () => ({ lastUsedAccount: null }),
                },
              },
              accountExists: false,
              inputUsername,
              targetAccountId: inputUsername,
              setInputUsername,
              refreshLoginState: async (nearAccountId?: string) => {
                (window as any).__headlessRefreshCalls.push(String(nearAccountId || ''));
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
                  kind: 'otp_flow',
                  flow: {
                    kind: 'google_email_otp_wallet_auth_flow_v1',
                    state: 'challenge_sent',
                    flowId: 'flow-1',
                    requestedMode: 'login',
                    mode: 'login',
                    walletId: 'alice.testnet',
                    emailHint: 'alice@example.com',
                    prompt: {
                      title: 'Check your email to unlock your wallet',
                      description: 'Enter the 6-digit code we sent to alice@example.com.',
                      submitLabel: 'Unlock wallet',
                      helperText: 'Use the code from your email.',
                    },
                    delivery: 'sent',
                    expiresAtMs: Date.now() + 60_000,
                    resend: async () => ({ ok: false, error: { code: 'email_otp_challenge_failed', message: 'no resend' } }),
                    submit: async (input: { otpCode: string }) => {
                      (window as any).__headlessSubmitted = input.otpCode;
                      return {
                        ok: true,
                        value: {
                          walletId: 'alice.testnet',
                          mode: 'login',
                          session: { login: { isLoggedIn: true } },
                        },
                      };
                    },
                    cancel: async () => undefined,
                  },
                  onComplete: async (result: { walletId: string; mode: string }) => {
                    (window as any).__headlessCompletions.push({
                      walletId: result.walletId,
                      mode: result.mode,
                    });
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
                  React.createElement('div', { id: 'headless-otp-ready' }, controller.otpPrompt.title),
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

    const mount = page.locator('#pam2-google-headless-otp-refresh-mount');
    await mount.getByRole('button', { name: 'Start Google' }).click();
    await expect(mount.locator('#headless-otp-ready')).toHaveText(
      'Check your email to unlock your wallet',
    );

    await mount.getByLabel('Email code').fill('123456');
    await mount.getByRole('button', { name: 'Unlock wallet' }).click();

    await expect
      .poll(async () => await page.evaluate(() => (window as any).__headlessSubmitted))
      .toBe('123456');
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__headlessCompletions))
      .toEqual([{ walletId: 'alice.testnet', mode: 'login' }]);
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__headlessRefreshCalls))
      .toEqual([]);
  });

  test('Google SSO headless registration shows registration prompt with reroll', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'pam2-google-headless-registration-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.passkeyAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const usePasskeyAuthMenuController = controllerMod.usePasskeyAuthMenuController;
        const { AuthMenuMode } = typesMod;

        function registrationFlow(walletId: string) {
          return {
            kind: 'google_email_otp_wallet_auth_flow_v1',
            state: 'registration_ready',
            flowId: `flow-${walletId}`,
            requestedMode: 'register',
            mode: 'register',
            walletId,
            emailHint: 'alice@example.com',
            prompt: {
              title: 'Create your Email OTP wallet',
              description: 'Google verified alice@example.com.',
              submitLabel: 'Create wallet',
              helperText: 'Choose this wallet name or generate another one.',
            },
            expiresAtMs: Date.now() + 60_000,
            rerollWalletId: async () => ({
              ok: true,
              value: registrationFlow('ember-river.testnet'),
            }),
            completeRegistration: async () => ({
              ok: true,
              value: {
                walletId,
                mode: 'register',
                session: { login: { isLoggedIn: true } },
              },
            }),
            cancel: async () => undefined,
          };
        }

        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('');
          const runtime = React.useMemo(
            () => ({
              seamsWeb: { auth: { getRecentUnlocks: async () => ({ lastUsedAccount: null }) } },
              accountExists: false,
              inputUsername,
              targetAccountId: inputUsername,
              setInputUsername,
              refreshLoginState: async () => undefined,
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
              defaultMode: AuthMenuMode.Register,
              socialLogin: {
                google: async () => ({
                  kind: 'registration_flow',
                  flow: registrationFlow('frost-beacon.testnet'),
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
                onClick: () => controller.onSocialLogin('google', AuthMenuMode.Register),
              },
              'Start registration',
            ),
            controller.registrationPrompt
              ? React.createElement(
                  React.Fragment,
                  null,
                  React.createElement('div', { id: 'registration-title' }, controller.registrationPrompt.title),
                  React.createElement('div', { id: 'registration-account' }, controller.registrationPrompt.accountId),
                  React.createElement('button', { type: 'button' }, controller.registrationPrompt.submitLabel),
                  React.createElement(
                    'button',
                    {
                      type: 'button',
                      onClick: controller.registrationPrompt.onRerollAccount,
                    },
                    controller.registrationPrompt.rerollAccountLabel,
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

    const mount = page.locator('#pam2-google-headless-registration-mount');
    await mount.getByRole('button', { name: 'Start registration' }).click();
    await expect(mount.locator('#registration-title')).toHaveText(
      'Create your Email OTP wallet',
    );
    await expect(mount.getByRole('button', { name: 'Create wallet' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Generate another name' })).toBeVisible();
    await expect(mount.getByText('Check your email to unlock your wallet')).toHaveCount(0);
    await mount.getByRole('button', { name: 'Generate another name' }).click();
    await expect(mount.locator('#registration-account')).toHaveText('ember-river.testnet');
  });

  test('Google SSO headless register request for existing wallet shows unlock prompt', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'pam2-google-headless-existing-wallet-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.passkeyAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const usePasskeyAuthMenuController = controllerMod.usePasskeyAuthMenuController;
        const { AuthMenuMode } = typesMod;

        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('');
          const runtime = React.useMemo(
            () => ({
              seamsWeb: { auth: { getRecentUnlocks: async () => ({ lastUsedAccount: null }) } },
              accountExists: false,
              inputUsername,
              targetAccountId: inputUsername,
              setInputUsername,
              refreshLoginState: async () => undefined,
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
              defaultMode: AuthMenuMode.Register,
              socialLogin: {
                google: async () => ({
                  kind: 'otp_flow',
                  flow: {
                    kind: 'google_email_otp_wallet_auth_flow_v1',
                    state: 'challenge_sent',
                    flowId: 'existing-flow',
                    requestedMode: 'register',
                    mode: 'login',
                    walletId: 'frost-beacon.testnet',
                    emailHint: 'alice@example.com',
                    prompt: {
                      title: 'Check your email to unlock your wallet',
                      description: 'Enter the 6-digit code we sent to alice@example.com.',
                      submitLabel: 'Unlock wallet',
                      helperText:
                        'Google keeps you signed in. The email code unlocks wallet signing for this session.',
                    },
                    delivery: 'sent',
                    expiresAtMs: Date.now() + 60_000,
                    resend: async () => ({ ok: false, error: { code: 'email_otp_challenge_failed', message: 'no resend' } }),
                    submit: async () => ({
                      ok: true,
                      value: {
                        walletId: 'frost-beacon.testnet',
                        mode: 'login',
                        session: { login: { isLoggedIn: true } },
                      },
                    }),
                    cancel: async () => undefined,
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
                onClick: () => controller.onSocialLogin('google', AuthMenuMode.Register),
              },
              'Start existing wallet',
            ),
            controller.otpPrompt
              ? React.createElement(
                  React.Fragment,
                  null,
                  React.createElement('div', { id: 'existing-title' }, controller.otpPrompt.title),
                  React.createElement('button', { type: 'button' }, controller.otpPrompt.submitLabel),
                  controller.otpPrompt.onRerollAccount
                    ? React.createElement(
                        'button',
                        { type: 'button', onClick: controller.otpPrompt.onRerollAccount },
                        controller.otpPrompt.rerollAccountLabel,
                      )
                    : null,
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

    const mount = page.locator('#pam2-google-headless-existing-wallet-mount');
    await mount.getByRole('button', { name: 'Start existing wallet' }).click();
    await expect(mount.locator('#existing-title')).toHaveText(
      'Check your email to unlock your wallet',
    );
    await expect(mount.getByRole('button', { name: 'Unlock wallet' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Generate another name' })).toHaveCount(0);
    await expect(mount.getByText('Check your email to finish registration')).toHaveCount(0);
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

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
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

  test('Passkey register button stays enabled before username input', async ({ page }) => {
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
        mount.id = 'pam2-passkey-register-enabled-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.passkeyAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        };

        (window as any).__pamPasskeyRegisterCalls = 0;
        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(PasskeyAuthMenu, {
                defaultMode: AuthMenuMode.Register,
                onRegister: () => {
                  (window as any).__pamPasskeyRegisterCalls += 1;
                },
              }),
            ),
          );
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#pam2-passkey-register-enabled-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    const button = mount.getByRole('button', { name: 'Create with Passkey' });
    await expect(button).toBeEnabled();
    await button.click();
    await expect(mount.getByRole('alert')).toHaveText(
      'Pick a username to create a passkey account.',
    );
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__pamPasskeyRegisterCalls))
      .toBe(0);
  });

  test('iframe passkey registration activation starting shows waiting screen state', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'pam2-registration-activation-waiting-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.passkeyAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const usePasskeyAuthMenuController = controllerMod.usePasskeyAuthMenuController;
        const { AuthMenuMode } = typesMod;

        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('alice');
          const runtime = React.useMemo(
            () => ({
              seamsWeb: { auth: { getRecentUnlocks: async () => ({ lastUsedAccount: null }) } },
              accountExists: false,
              inputUsername,
              targetAccountId: `${inputUsername}.testnet`,
              setInputUsername,
              refreshLoginState: async () => undefined,
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
            { defaultMode: AuthMenuMode.Register },
            runtime,
          );

          const status = controller.waiting
            ? `waiting:${controller.waitingReason}`
            : 'not-waiting';

          return React.createElement(
            'div',
            null,
            React.createElement('div', { id: 'activation-waiting-state' }, status),
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () =>
                  controller.onRegistrationActivationSurfaceStateChange({
                    kind: 'starting',
                    activationId: 'activation-1',
                  }),
              },
              'Start activation',
            ),
          );
        }

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(React.createElement(Harness));
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#pam2-registration-activation-waiting-mount');
    await expect(mount.locator('#activation-waiting-state')).toHaveText('not-waiting');
    await mount.getByRole('button', { name: 'Start activation' }).click();
    await expect(mount.locator('#activation-waiting-state')).toHaveText('waiting:passkey');
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

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
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

  test('React SDK-flow proxy preserves Email OTP namespace methods', async ({ page }) => {
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

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const { useSeams } = reactMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        };

        const authMethodNames = [
          'requestEmailOtpChallenge',
          'loginWithEmailOtpEcdsaCapability',
          'beginGoogleEmailOtpWalletAuth',
        ];
        const registrationMethodNames = [
          'requestEmailOtpEnrollmentChallenge',
          'enrollEmailOtp',
          'enrollAndLoginWithEmailOtpEcdsaCapability',
        ];

        function Probe() {
          const { seams } = useSeams();
          React.useEffect(() => {
            (window as any).__emailOtpSurface__ = {
              auth: Object.fromEntries(
                authMethodNames.map((name) => [name, typeof (seams.auth as any)[name]]),
              ),
              registration: Object.fromEntries(
                registrationMethodNames.map((name) => [
                  name,
                  typeof (seams.registration as any)[name],
                ]),
              ),
            };
          }, [seams]);
          return React.createElement('div', { id: 'auth-surface-ready' }, 'ready');
        }

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(React.createElement(Provider, { config }, React.createElement(Probe)));
        });

        return await new Promise<Record<string, Record<string, string>>>((resolve, reject) => {
          const startedAt = Date.now();
          const poll = () => {
            const surface = (window as any).__emailOtpSurface__;
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
      auth: {
        requestEmailOtpChallenge: 'function',
        loginWithEmailOtpEcdsaCapability: 'function',
        beginGoogleEmailOtpWalletAuth: 'function',
      },
      registration: {
        requestEmailOtpEnrollmentChallenge: 'function',
        enrollEmailOtp: 'function',
        enrollAndLoginWithEmailOtpEcdsaCapability: 'function',
      },
    });
  });
});
