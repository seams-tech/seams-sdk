import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const IMPORT_PATHS = {
  provider: '/_test-sdk/esm/react/context/SeamsWebProvider.js',
  contextIndex: '/_test-sdk/esm/react/context/index.js',
  seamsManagerSingleton: '/_test-sdk/esm/react/context/seamsManagerSingleton.js',
  reactIndex: '/_test-sdk/esm/react/index.js',
  seamsAuthMenu: '/_test-sdk/esm/react/components/SeamsAuthMenu/public.js',
  seamsAuthMenuClient: '/_test-sdk/esm/react/components/SeamsAuthMenu/client.js',
  seamsAuthMenuController:
    '/_test-sdk/esm/react/components/SeamsAuthMenu/controller/useSeamsAuthMenuController.js',
  seamsContextValue: '/_test-sdk/esm/react/context/useSeamsContextValue.js',
  loginStateRefresher: '/_test-sdk/esm/react/context/useLoginStateRefresher.js',
  passkeyInput: '/_test-sdk/esm/react/components/SeamsAuthMenu/ui/PasskeyInput.js',
  authMenuTypes: '/_test-sdk/esm/react/components/SeamsAuthMenu/authMenuTypes.js',
  reactStyles: '/_test-sdk/esm/react/styles/styles.css',
} as const;

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function sourceRangeBetween(source: string, startNeedle: string, endNeedle: string): string {
  const start = source.indexOf(startNeedle);
  expect(start, `missing source range start: ${startNeedle}`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  expect(end, `missing source range end: ${endNeedle}`).toBeGreaterThan(start);
  return source.slice(start, end);
}

test.describe('SeamsAuthMenu styles bootstrap', () => {
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
        mount.id = 'seams-auth-menu-test-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.seamsAuthMenuClient);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const SeamsAuthMenu = menuMod.SeamsAuthMenuClient || menuMod.default;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(Provider, { config }, React.createElement(SeamsAuthMenu, null)),
          );
        });

        // Save refs so the test can unmount/remount and assert no fallback flash after the first load.
        (window as any).__w3a_seams_auth_menu_root__ = root;
        (window as any).__w3a_seams_auth_menu_config__ = config;
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#seams-auth-menu-test-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await expect(mount.locator('.w3a-auth-intent-switch')).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Sign up' })).toBeVisible();

    const root = mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)');

    const sentinel = await root.evaluate((el) =>
      window.getComputedStyle(el).getPropertyValue('--w3a-seams-auth-menu-css-ready').trim(),
    );
    expect(sentinel).toBe('1');

    await expect(mount.getByRole('button', { name: 'Continue with Google SSO' })).toBeDisabled();

    const radius = await root.evaluate((el) => window.getComputedStyle(el).borderTopLeftRadius);
    expect(radius).not.toBe('0px');

    const remount = await page.evaluate(
      async ({ paths }) => {
        const mount = document.getElementById('seams-auth-menu-test-mount');
        if (!mount) throw new Error('missing #seams-auth-menu-test-mount');

        const existingRoot = (window as any).__w3a_seams_auth_menu_root__;
        if (existingRoot?.unmount) existingRoot.unmount();

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.seamsAuthMenuClient);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const SeamsAuthMenu = menuMod.SeamsAuthMenuClient || menuMod.default;

        const config = (window as any).__w3a_seams_auth_menu_config__ || {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(Provider, { config }, React.createElement(SeamsAuthMenu, null)),
          );
        });
        (window as any).__w3a_seams_auth_menu_root__ = root;

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

  test('login mode shows passkey, Google SSO Email OTP, and email recovery methods', async ({
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
        mount.id = 'seams-auth-menu-login-methods-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.seamsAuthMenuClient);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const SeamsAuthMenu = menuMod.SeamsAuthMenuClient || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(SeamsAuthMenu, {
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

    const mount = page.locator('#seams-auth-menu-login-methods-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await expect(mount.getByRole('button', { name: 'Continue with Passkey' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Continue with Email OTP' })).toHaveCount(0);
    await expect(mount.getByRole('button', { name: 'Continue with Google SSO' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Scan and Link Device' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Recover Account with Email' })).toBeVisible();
    await expect(mount.locator('.w3a-social-helper')).toHaveCount(0);

    await mount.getByRole('button', { name: 'Sign up' }).click();
    await expect(mount.getByRole('button', { name: 'Create passkey account' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Continue with Google SSO' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Scan and Link Device' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Recover Account with Email' })).toBeVisible();
    await expect(
      mount.getByText(
        'Creates a Google SSO account that uses a 6-digit Email OTP for signing. Passkey is recommended for stronger security.',
      ),
    ).toHaveCount(0);
    await expect(mount.locator('.w3a-social-helper')).toHaveCount(0);
  });

  test('login and register expose email recovery without synced passkey restore CTA', async ({
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
        mount.id = 'seams-auth-menu-synced-passkey-restore-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.seamsAuthMenuClient);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const SeamsAuthMenu = menuMod.SeamsAuthMenuClient || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        (window as any).__emailRecoveryModes = [];
        (window as any).__emailRecoveryLoginMode = String(AuthMenuMode.Login);
        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(SeamsAuthMenu, {
                defaultMode: AuthMenuMode.Login,
                onSyncAccount: async () => {
                  throw new Error('onSyncAccount should not be exposed as a button');
                },
                socialLogin: {
                  google: async (args: { mode: number | string }) => {
                    (window as any).__emailRecoveryModes.push(String(args.mode));
                  },
                },
              }),
            ),
          );
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#seams-auth-menu-synced-passkey-restore-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await expect(mount.getByRole('button', { name: /^Sync$/ })).toHaveCount(0);
    await expect(mount.getByRole('button', { name: 'Restore from synced passkey' })).toHaveCount(0);
    await expect(mount.getByRole('button', { name: 'Scan and Link Device' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Recover Account with Email' })).toBeVisible();

    await mount.getByRole('button', { name: 'Sign up' }).click();
    await expect(mount.getByRole('button', { name: 'Create passkey account' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Restore from synced passkey' })).toHaveCount(0);
    await expect(mount.getByRole('button', { name: 'Scan and Link Device' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Recover Account with Email' })).toBeVisible();

    await mount.getByRole('button', { name: 'Recover Account with Email' }).click();
    const expectedLoginMode = await page.evaluate(() => (window as any).__emailRecoveryLoginMode);
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__emailRecoveryModes))
      .toEqual([expectedLoginMode]);
  });

  test('login submit auto-restores synced passkey when no local passkey exists', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.seamsAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const useSeamsAuthMenuController =
          controllerMod.useSeamsAuthMenuController || controllerMod.default;
        const { AuthMenuMode } = typesMod;

        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-auto-synced-passkey-restore-mount';
        document.body.appendChild(mount);

        (window as any).__autoSyncedPasskeyRestore = {
          loginCalls: 0,
          syncCalls: 0,
          waitingStates: [] as string[],
        };

        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('alice');
          const runtime = React.useMemo(
            () => ({
              seamsWeb: {
                auth: {
                  getRecentUnlocks: async () => ({ lastUsedAccount: null }),
                },
              },
              accountExists: true,
              passkeyCredentialExists: false,
              inputUsername,
              targetWalletId: 'alice',
              targetAccountId: 'alice.testnet',
              accountOptions: [
                {
                  walletId: 'alice',
                  displayName: 'alice',
                  authMethod: 'email_otp',
                },
              ],
              setInputUsername,
              refreshLoginState: async () => undefined,
              sdkFlow: {
                eventsText: '',
                seq: 0,
                awaitNextCompletion: async () => undefined,
              },
              displayPostfix: '.testnet',
              isUsingExistingAccount: true,
            }),
            [inputUsername],
          );

          const controller = useSeamsAuthMenuController(
            {
              defaultMode: AuthMenuMode.Login,
              onLogin: async () => {
                (window as any).__autoSyncedPasskeyRestore.loginCalls += 1;
              },
              onSyncAccount: async () => {
                (window as any).__autoSyncedPasskeyRestore.syncCalls += 1;
              },
            },
            runtime,
          );

          React.useEffect(() => {
            (window as any).__autoSyncedPasskeyRestore.waitingStates.push(
              controller.waiting ? String(controller.waitingReason) : 'idle',
            );
          }, [controller.waiting, controller.waitingReason]);

          return React.createElement(
            'button',
            {
              type: 'button',
              disabled: !controller.canSubmit,
              onClick: controller.onProceed,
            },
            'Continue with Passkey',
          );
        }

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(React.createElement(Harness));
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#seams-auth-menu-auto-synced-passkey-restore-mount');
    await mount.getByRole('button', { name: 'Continue with Passkey' }).click();
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__autoSyncedPasskeyRestore))
      .toMatchObject({
        loginCalls: 0,
        syncCalls: 1,
      });
  });

  test('synced passkey restore timeout warns without rendering inline method error', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.seamsAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const useSeamsAuthMenuController =
          controllerMod.useSeamsAuthMenuController || controllerMod.default;
        const { AuthMenuMode } = typesMod;

        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-sync-timeout-no-inline-error-mount';
        document.body.appendChild(mount);

        (window as any).__seamsAuthMenuSyncTimeoutWarnings = [];
        const originalWarn = console.warn.bind(console);
        console.warn = (...args: unknown[]) => {
          (window as any).__seamsAuthMenuSyncTimeoutWarnings.push(args.map(String).join(' '));
          originalWarn(...args);
        };

        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('alice');
          const runtime = React.useMemo(
            () => ({
              seamsWeb: {
                auth: {
                  getRecentUnlocks: async () => ({ lastUsedAccount: null }),
                },
              },
              accountExists: true,
              passkeyCredentialExists: false,
              inputUsername,
              targetWalletId: 'alice',
              targetAccountId: 'alice.testnet',
              accountOptions: [
                {
                  walletId: 'alice',
                  displayName: 'alice',
                  authMethod: 'email_otp',
                },
              ],
              setInputUsername,
              refreshLoginState: async () => undefined,
              sdkFlow: {
                eventsText: '',
                seq: 0,
                awaitNextCompletion: async () => undefined,
              },
              displayPostfix: '.testnet',
              isUsingExistingAccount: true,
            }),
            [inputUsername],
          );

          const controller = useSeamsAuthMenuController(
            {
              defaultMode: AuthMenuMode.Login,
              onSyncAccount: async () => {
                throw new Error('Wallet request timeout for PM_SYNC_ACCOUNT_FLOW after 60010ms');
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
                disabled: !controller.canSubmit,
                onClick: controller.onProceed,
              },
              'Continue with Passkey',
            ),
            React.createElement('div', { id: 'sync-method-error' }, controller.methodError || ''),
          );
        }

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(React.createElement(Harness));
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#seams-auth-menu-sync-timeout-no-inline-error-mount');
    await mount.getByRole('button', { name: 'Continue with Passkey' }).click();
    await expect.poll(async () => await mount.locator('#sync-method-error').textContent()).toBe('');
    await expect
      .poll(
        async () => await page.evaluate(() => (window as any).__seamsAuthMenuSyncTimeoutWarnings),
      )
      .toContainEqual(
        expect.stringContaining('Wallet request timeout for PM_SYNC_ACCOUNT_FLOW after 60010ms'),
      );
  });

  test('account dropdown renders auth labels instead of implicit NEAR account IDs', async ({
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
        mount.id = 'seams-auth-menu-account-groups-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const inputMod: any = await import(paths.passkeyInput);
        const typesMod: any = await import(paths.authMenuTypes);

        const PasskeyInput = inputMod.PasskeyInput || inputMod.default;
        const { AuthMenuMode } = typesMod;

        function Harness() {
          const [value, setValue] = React.useState('jade-orchid-2caqh9');
          return React.createElement(PasskeyInput, {
            value,
            onChange: setValue,
            placeholder: 'Enter your username',
            mode: AuthMenuMode.Login,
            onProceed: () => undefined,
            accountOptions: [
              {
                walletId: 'jade-orchid-2caqh9',
                displayName: 'jade-orchid-2caqh9',
                nearAccountId: '13f209913f2d5d9cd8d7ec99a9a93f8c7b00c53326c4dd978a32b9f3b8d25b9b',
                signerSlot: 1,
                authMethod: 'passkey',
              },
              {
                walletId: 'frost-violet-8n1lfz',
                displayName: 'frost-violet-8n1lfz',
                nearAccountId: '654d84f7bf7475554e18f970148c744842288a79aaf7d82010d50d9a3b40d1a2',
                signerSlot: 1,
                authMethod: 'passkey',
              },
              {
                walletId: 'cedar-harvest-r9a4kp',
                displayName: 'n6378056@gmail.com',
                nearAccountId: '82c97f62d2ea8b7033fc24a4b525b3bb3240298f9ed220bd1b7427f2b0229978',
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

    const mount = page.locator('#seams-auth-menu-account-groups-mount');
    await mount.getByRole('button', { name: 'Saved accounts' }).click();

    const passkeyGroup = mount.locator('.w3a-account-menu-group').filter({ hasText: 'PASSKEY' });
    const emailOtpGroup = mount.locator('.w3a-account-menu-group').filter({ hasText: 'EMAIL OTP' });

    await expect(passkeyGroup).toContainText('jade-orchid-2caqh9');
    await expect(passkeyGroup).toContainText('frost-violet-8n1lfz');
    await expect(passkeyGroup).not.toContainText(
      '13f209913f2d5d9cd8d7ec99a9a93f8c7b00c53326c4dd978a32b9f3b8d25b9b',
    );
    await expect(emailOtpGroup).toContainText('n6378056@gmail.com');
    await expect(emailOtpGroup).not.toContainText(
      '82c97f62d2ea8b7033fc24a4b525b3bb3240298f9ed220bd1b7427f2b0229978',
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
        mount.id = 'seams-auth-menu-google-otp-prompt-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.seamsAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const SeamsAuthMenu = menuMod.SeamsAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        (window as any).__otpSubmitted = '';
        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(SeamsAuthMenu, {
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

    const mount = page.locator('#seams-auth-menu-google-otp-prompt-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Continue with Google SSO' }).click();
    await expect(mount.getByText('Check your email to unlock your wallet')).toBeVisible();
    await expect(mount.locator('.w3a-otp-email')).toHaveCount(0);
    await expect(mount.getByText(/alice@example\.com/)).toBeVisible();
    await mount.getByLabel('Email code').fill('123456');
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpSubmitted))
      .toBe('123456');
  });

  test('Google SSO timeout warns without rendering inline method error', async ({ page }) => {
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
        mount.id = 'seams-auth-menu-google-timeout-no-inline-error-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.seamsAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const SeamsAuthMenu = menuMod.SeamsAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        (window as any).__seamsAuthMenuGoogleTimeoutWarnings = [];
        const originalWarn = console.warn.bind(console);
        console.warn = (...args: unknown[]) => {
          (window as any).__seamsAuthMenuGoogleTimeoutWarnings.push(args.map(String).join(' '));
          originalWarn(...args);
        };

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(SeamsAuthMenu, {
                defaultMode: AuthMenuMode.Login,
                socialLogin: {
                  google: async () => {
                    throw new Error(
                      'Wallet request timeout for PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH after 30000ms',
                    );
                  },
                },
              }),
            ),
          );
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#seams-auth-menu-google-timeout-no-inline-error-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Continue with Google SSO' }).click();
    await expect(mount.locator('.w3a-method-error')).toHaveCount(0);
    await expect
      .poll(
        async () => await page.evaluate(() => (window as any).__seamsAuthMenuGoogleTimeoutWarnings),
      )
      .toContainEqual(
        expect.stringContaining(
          'Wallet request timeout for PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH after 30000ms',
        ),
      );
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
        mount.id = 'seams-auth-menu-google-otp-reroll-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.seamsAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const SeamsAuthMenu = menuMod.SeamsAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        (window as any).__otpRerollCalls = 0;
        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(SeamsAuthMenu, {
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
                          description: 'Enter the 6-digit setup code we sent to alice@example.com.',
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

    const mount = page.locator('#seams-auth-menu-google-otp-reroll-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Continue with Google SSO' }).click();
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
        mount.id = 'seams-auth-menu-google-otp-recovery-key-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.seamsAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const SeamsAuthMenu = menuMod.SeamsAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        (window as any).__otpRecoverySubmit = null;
        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(SeamsAuthMenu, {
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

    const mount = page.locator('#seams-auth-menu-google-otp-recovery-key-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Continue with Google SSO' }).click();
    await expect(mount.getByText('Recover this device')).toBeVisible();

    const recoveryKeyInput = mount.getByLabel('Recovery key');
    await expect(recoveryKeyInput).toBeVisible();
    await recoveryKeyInput.fill('008j4ct4ank7f24snaxwsqfezw834n3p');
    await expect(recoveryKeyInput).toHaveValue('008J-4CT4-ANK7-F24S-NAXW-SQFE-ZW83-4N3P');
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__otpRecoverySubmit))
      .toBeNull();

    await mount.getByLabel('Email code').fill('123456');
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
        mount.id = 'seams-auth-menu-google-otp-resend-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.seamsAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const SeamsAuthMenu = menuMod.SeamsAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        (window as any).__otpResendCalls = 0;
        (window as any).__otpSubmitted = '';
        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(SeamsAuthMenu, {
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

    const mount = page.locator('#seams-auth-menu-google-otp-resend-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Continue with Google SSO' }).click();
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
        mount.id = 'seams-auth-menu-google-otp-resend-rate-limit-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.seamsAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const SeamsAuthMenu = menuMod.SeamsAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(SeamsAuthMenu, {
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

    const mount = page.locator('#seams-auth-menu-google-otp-resend-rate-limit-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Continue with Google SSO' }).click();
    await mount.getByRole('button', { name: 'Resend Code' }).click();
    await expect(mount.getByRole('alert')).toHaveText('Too many requests. Try again in 13s.');
  });

  test('Google SSO Email OTP refreshes wallet state only after OTP success', async ({ page }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-google-otp-refresh-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.seamsAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const useSeamsAuthMenuController =
          controllerMod.useSeamsAuthMenuController || controllerMod.default;
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

          const controller = useSeamsAuthMenuController(
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

    const mount = page.locator('#seams-auth-menu-google-otp-refresh-mount');
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
        mount.id = 'seams-auth-menu-google-headless-otp-refresh-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.seamsAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const useSeamsAuthMenuController =
          controllerMod.useSeamsAuthMenuController || controllerMod.default;
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

          const controller = useSeamsAuthMenuController(
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
                    resend: async () => ({
                      ok: false,
                      error: { code: 'email_otp_challenge_failed', message: 'no resend' },
                    }),
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
                  React.createElement(
                    'div',
                    { id: 'headless-otp-ready' },
                    controller.otpPrompt.title,
                  ),
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

    const mount = page.locator('#seams-auth-menu-google-headless-otp-refresh-mount');
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
        mount.id = 'seams-auth-menu-google-headless-registration-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.seamsAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const useSeamsAuthMenuController =
          controllerMod.useSeamsAuthMenuController || controllerMod.default;
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
          const controller = useSeamsAuthMenuController(
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
                  React.createElement(
                    'div',
                    { id: 'registration-title' },
                    controller.registrationPrompt.title,
                  ),
                  React.createElement(
                    'div',
                    { id: 'registration-account' },
                    controller.registrationPrompt.accountId,
                  ),
                  React.createElement(
                    'button',
                    { type: 'button' },
                    controller.registrationPrompt.submitLabel,
                  ),
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

    const mount = page.locator('#seams-auth-menu-google-headless-registration-mount');
    await mount.getByRole('button', { name: 'Start registration' }).click();
    await expect(mount.locator('#registration-title')).toHaveText('Create your Email OTP wallet');
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
        mount.id = 'seams-auth-menu-google-headless-existing-wallet-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.seamsAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const useSeamsAuthMenuController =
          controllerMod.useSeamsAuthMenuController || controllerMod.default;
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
          const controller = useSeamsAuthMenuController(
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
                    resend: async () => ({
                      ok: false,
                      error: { code: 'email_otp_challenge_failed', message: 'no resend' },
                    }),
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
                  React.createElement(
                    'button',
                    { type: 'button' },
                    controller.otpPrompt.submitLabel,
                  ),
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

    const mount = page.locator('#seams-auth-menu-google-headless-existing-wallet-mount');
    await mount.getByRole('button', { name: 'Start existing wallet' }).click();
    await expect(mount.locator('#existing-title')).toHaveText(
      'Check your email to unlock your wallet',
    );
    await expect(mount.getByRole('button', { name: 'Unlock wallet' })).toBeVisible();
    await expect(mount.getByRole('button', { name: 'Generate another name' })).toHaveCount(0);
    await expect(mount.getByText('Check your email to finish registration')).toHaveCount(0);
  });

  test('Google SSO registration does not keep passkey activation surface mounted while social auth waits', () => {
    const source = readRepoSource('packages/sdk-web/src/react/components/SeamsAuthMenu/client.tsx');
    const activationGate = sourceRangeBetween(
      source,
      'const iframeRegistrationButtonEnabled =',
      'React.useEffect(() => {',
    );

    expect(activationGate).toContain("controller.waitingReason !== 'social'");
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
        mount.id = 'seams-auth-menu-google-mode-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.seamsAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const SeamsAuthMenu = menuMod.SeamsAuthMenu || menuMod.default;
        const { AuthMenuMode, AuthMenuModeMap } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        (window as any).__seamsAuthMenuGoogleModes = [];
        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(SeamsAuthMenu, {
                defaultMode: AuthMenuMode.Login,
                socialLogin: {
                  google: (args: { mode: number }) => {
                    (window as any).__seamsAuthMenuGoogleModes.push(AuthMenuModeMap[args.mode]);
                  },
                },
              }),
            ),
          );
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#seams-auth-menu-google-mode-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Continue with Google SSO' }).click();
    await mount.getByRole('button', { name: 'Sign up' }).click();
    await mount.getByRole('button', { name: 'Continue with Google SSO' }).click();

    await expect
      .poll(async () => await page.evaluate(() => (window as any).__seamsAuthMenuGoogleModes))
      .toEqual(['login', 'register']);
  });

  test('Passkey implicit registration keeps generated wallet internal by default', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-passkey-register-controller-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.seamsAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const useSeamsAuthMenuController =
          controllerMod.useSeamsAuthMenuController || controllerMod.default;
        const { AuthMenuMode } = typesMod;

        (window as any).__seamsAuthMenuPasskeyRegisterCalls = 0;
        (window as any).__seamsAuthMenuPasskeyRegisterWallets = [];
        (window as any).__seamsAuthMenuPasskeyRegisterKinds = [];
        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('');
          const runtime = React.useMemo(
            () => ({
              seamsWeb: { auth: { getRecentUnlocks: async () => ({ lastUsedAccount: null }) } },
              accountExists: false,
              passkeyCredentialExists: false,
              inputUsername,
              targetWalletId: '',
              setInputUsername,
              refreshLoginState: async () => undefined,
              sdkFlow: {
                eventsText: '',
                seq: 0,
                awaitNextCompletion: async () => undefined,
              },
            }),
            [inputUsername],
          );
          const controller = useSeamsAuthMenuController(
            {
              defaultMode: AuthMenuMode.Register,
              onRegister: (request: any) => {
                (window as any).__seamsAuthMenuPasskeyRegisterCalls += 1;
                (window as any).__seamsAuthMenuPasskeyRegisterKinds.push(
                  String(request?.kind || ''),
                );
                (window as any).__seamsAuthMenuPasskeyRegisterWallets.push(
                  String(request?.wallet?.walletId || ''),
                );
              },
            },
            runtime,
          );
          return React.createElement(
            'div',
            null,
            React.createElement(
              'div',
              { id: 'implicit-show-input' },
              String(controller.showAccountInput),
            ),
            React.createElement(
              'div',
              { id: 'implicit-readonly' },
              String(controller.accountInputReadOnly),
            ),
            React.createElement(
              'div',
              { id: 'implicit-wallet-id' },
              String(controller.currentValue || ''),
            ),
            React.createElement(
              'div',
              { id: 'implicit-activation-wallet-id' },
              String(controller.registrationActivationWallet?.walletId || ''),
            ),
            React.createElement('div', { id: 'implicit-can-submit' }, String(controller.canSubmit)),
            React.createElement(
              'button',
              {
                type: 'button',
                disabled: controller.accountInputRerollDisabled,
                onClick: controller.onAccountInputReroll,
              },
              'Generate another wallet name',
            ),
            React.createElement(
              'button',
              {
                type: 'button',
                disabled: !controller.canSubmit,
                onClick: controller.onProceed,
              },
              'Create with Passkey',
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

    const mount = page.locator('#seams-auth-menu-passkey-register-controller-mount');
    await expect(mount.locator('#implicit-show-input')).toHaveText('false');
    await expect(mount.locator('#implicit-readonly')).toHaveText('true');
    await expect(mount.locator('#implicit-wallet-id')).toHaveText(/^[a-z]+-[a-z]+-[a-z0-9]{6}$/);
    await expect(mount.locator('#implicit-activation-wallet-id')).toHaveText(
      (await mount.locator('#implicit-wallet-id').textContent()) || '',
    );
    await expect(mount.locator('#implicit-can-submit')).toHaveText('true');
    const initialWalletId = await mount.locator('#implicit-wallet-id').textContent();
    await mount.getByRole('button', { name: 'Generate another wallet name' }).click();
    await expect(mount.locator('#implicit-wallet-id')).not.toHaveText(initialWalletId || '');
    const generatedWalletId = await mount.locator('#implicit-wallet-id').textContent();
    await expect(mount.locator('#implicit-activation-wallet-id')).toHaveText(
      generatedWalletId || '',
    );
    const button = mount.getByRole('button', { name: 'Create with Passkey' });
    await expect(button).toBeEnabled();
    await button.click();
    await expect
      .poll(
        async () => await page.evaluate(() => (window as any).__seamsAuthMenuPasskeyRegisterCalls),
      )
      .toBe(1);
    await expect
      .poll(
        async () =>
          await page.evaluate(() => (window as any).__seamsAuthMenuPasskeyRegisterWallets),
      )
      .toEqual([generatedWalletId]);
    await expect
      .poll(
        async () => await page.evaluate(() => (window as any).__seamsAuthMenuPasskeyRegisterKinds),
      )
      .toEqual(['implicit_wallet']);
  });

  test('Passkey implicit registration can show generated wallet input when requested', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-passkey-register-visible-input-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.seamsAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const useSeamsAuthMenuController =
          controllerMod.useSeamsAuthMenuController || controllerMod.default;
        const { AuthMenuMode } = typesMod;

        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('');
          const runtime = React.useMemo(
            () => ({
              seamsWeb: { auth: { getRecentUnlocks: async () => ({ lastUsedAccount: null }) } },
              accountExists: false,
              passkeyCredentialExists: false,
              inputUsername,
              targetWalletId: '',
              setInputUsername,
              refreshLoginState: async () => undefined,
              sdkFlow: {
                eventsText: '',
                seq: 0,
                awaitNextCompletion: async () => undefined,
              },
            }),
            [inputUsername],
          );
          const controller = useSeamsAuthMenuController(
            {
              defaultMode: AuthMenuMode.Register,
              showRegistrationInput: true,
            },
            runtime,
          );
          return React.createElement(
            'div',
            null,
            React.createElement(
              'div',
              { id: 'visible-implicit-show-input' },
              String(controller.showAccountInput),
            ),
            React.createElement(
              'div',
              { id: 'visible-implicit-readonly' },
              String(controller.accountInputReadOnly),
            ),
            React.createElement(
              'div',
              { id: 'visible-implicit-wallet-id' },
              String(controller.currentValue || ''),
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

    const mount = page.locator('#seams-auth-menu-passkey-register-visible-input-mount');
    await expect(mount.locator('#visible-implicit-show-input')).toHaveText('true');
    await expect(mount.locator('#visible-implicit-readonly')).toHaveText('true');
    await expect(mount.locator('#visible-implicit-wallet-id')).toHaveText(
      /^[a-z]+-[a-z]+-[a-z0-9]{6}$/,
    );
  });

  test('Passkey implicit registration reroll disposes stale activation surface', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-passkey-register-activation-reroll-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const contextMod: any = await import(paths.contextIndex);
        const singletonMod: any = await import(paths.seamsManagerSingleton);
        const menuMod: any = await import(paths.seamsAuthMenuClient);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const useSeams = contextMod.useSeams;
        const SeamsAuthMenu = menuMod.SeamsAuthMenuClient || menuMod.default;
        const { AuthMenuMode } = typesMod;

        type LifecycleEvent = {
          event: 'init' | 'create' | 'mount' | 'dispose' | 'subscribe' | 'unsubscribe';
          walletId: string;
        };
        const lifecycle: LifecycleEvent[] = [];
        (window as any).__seamsAuthMenuActivationSurfaceLifecycle = lifecycle;
        (window as any).__seamsAuthMenuActivationSurfacePatchInstalled = false;

        function installActivationSurfacePatch(seams: any): void {
          if ((window as any).__seamsAuthMenuActivationSurfacePatchInstalled) return;
          (window as any).__seamsAuthMenuActivationSurfacePatchInstalled = true;
          seams.initWalletIframe = async (walletId?: string) => {
            lifecycle.push({ event: 'init', walletId: String(walletId || '') });
          };
          seams.isWalletIframeReady = () => true;
          seams.onWalletIframeReady = () => () => undefined;
          seams.onWalletIframeLoginStatusChanged = () => () => undefined;
          seams.onWalletIframePreferencesChanged = () => () => undefined;
          seams.preferences.getCurrentWalletId = () => '';
          seams.registration.createPasskeyRegistrationActivationSurface = (args: {
            wallet: { walletId: string };
          }) => {
            const walletId = String(args.wallet.walletId || '');
            lifecycle.push({ event: 'create', walletId });
            return {
              kind: 'wallet_iframe_registration_activation_surface_v1',
              mount: (target: HTMLElement) => {
                lifecycle.push({ event: 'mount', walletId });
                target.setAttribute('data-activation-wallet-id', walletId);
              },
              dispose: () => {
                lifecycle.push({ event: 'dispose', walletId });
              },
              state: () => ({ kind: 'idle' }),
              onStateChange: () => {
                lifecycle.push({ event: 'subscribe', walletId });
                return () => {
                  lifecycle.push({ event: 'unsubscribe', walletId });
                };
              },
            };
          };
        }

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        function Harness() {
          useSeams();
          const rawSeams = singletonMod.getOrCreateSeamsManager(config, {});
          installActivationSurfacePatch(rawSeams);
          return React.createElement(SeamsAuthMenu, {
            defaultMode: AuthMenuMode.Register,
            showRegistrationInput: true,
          });
        }

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(React.createElement(Provider, { config }, React.createElement(Harness)));
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#seams-auth-menu-passkey-register-activation-reroll-mount');
    const activationButton = mount.locator('.seams-passkey-registration-btn');
    await activationButton.waitFor({ state: 'attached' });
    await expect
      .poll(
        async () =>
          await page.evaluate(
            () =>
              ((window as any).__seamsAuthMenuActivationSurfaceLifecycle || []).filter(
                (entry: { event: string }) => entry.event === 'mount',
              ).length,
          ),
      )
      .toBe(1);
    const initialWalletId = await activationButton.getAttribute('data-activation-wallet-id');
    if (initialWalletId === null) throw new Error('activation wallet ID was not mounted');
    expect(initialWalletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{6}$/);

    await mount.getByRole('button', { name: 'Generate another wallet name' }).click();

    await expect
      .poll(
        async () =>
          await page.evaluate(() => {
            const lifecycle = ((window as any).__seamsAuthMenuActivationSurfaceLifecycle ||
              []) as Array<{
              event: string;
              walletId: string;
            }>;
            return {
              mountCount: lifecycle.filter((entry) => entry.event === 'mount').length,
              disposeCount: lifecycle.filter((entry) => entry.event === 'dispose').length,
              unsubscribeCount: lifecycle.filter((entry) => entry.event === 'unsubscribe').length,
            };
          }),
      )
      .toEqual({
        mountCount: 2,
        disposeCount: 1,
        unsubscribeCount: 1,
      });
    const lifecycleResult = await page.evaluate(() => {
      const lifecycle = ((window as any).__seamsAuthMenuActivationSurfaceLifecycle || []) as Array<{
        event: string;
        walletId: string;
      }>;
      return {
        mountWalletIds: lifecycle
          .filter((entry) => entry.event === 'mount')
          .map((entry) => entry.walletId),
        disposeWalletIds: lifecycle
          .filter((entry) => entry.event === 'dispose')
          .map((entry) => entry.walletId),
        unsubscribeWalletIds: lifecycle
          .filter((entry) => entry.event === 'unsubscribe')
          .map((entry) => entry.walletId),
      };
    });
    expect(lifecycleResult.mountWalletIds[0]).toBe(initialWalletId);
    expect(lifecycleResult.mountWalletIds[1]).not.toBe(initialWalletId);
    expect(lifecycleResult.disposeWalletIds).toEqual([initialWalletId]);
    expect(lifecycleResult.unsubscribeWalletIds).toEqual([initialWalletId]);
  });

  test('Passkey implicit registration falls back to a clickable button after activation target cancellation', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-passkey-register-activation-cancelled-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const contextMod: any = await import(paths.contextIndex);
        const singletonMod: any = await import(paths.seamsManagerSingleton);
        const menuMod: any = await import(paths.seamsAuthMenuClient);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const useSeams = contextMod.useSeams;
        const SeamsAuthMenu = menuMod.SeamsAuthMenuClient || menuMod.default;
        const { AuthMenuMode } = typesMod;
        const activationId = 'cancelled-before-click';

        (window as any).__seamsAuthMenuActivationCancelledRegisterCalls = 0;
        (window as any).__seamsAuthMenuActivationCancelledEvents = [];
        (window as any).__seamsAuthMenuActivationCancelledPatchInstalled = false;

        function installActivationSurfacePatch(seams: any): void {
          if ((window as any).__seamsAuthMenuActivationCancelledPatchInstalled) return;
          (window as any).__seamsAuthMenuActivationCancelledPatchInstalled = true;
          seams.initWalletIframe = async () => undefined;
          seams.isWalletIframeReady = () => true;
          seams.onWalletIframeReady = () => () => undefined;
          seams.onWalletIframeLoginStatusChanged = () => () => undefined;
          seams.onWalletIframePreferencesChanged = () => () => undefined;
          seams.preferences.getCurrentWalletId = () => '';
          seams.registration.createPasskeyRegistrationActivationSurface = () => {
            let stateListener: ((state: unknown) => void) | null = null;
            return {
              kind: 'wallet_iframe_registration_activation_surface_v1',
              mount: () => {
                (window as any).__seamsAuthMenuActivationCancelledEvents.push('mount');
                stateListener?.({
                  kind: 'cancelled',
                  activationId,
                  reason: 'target_unavailable',
                });
              },
              dispose: () => {
                (window as any).__seamsAuthMenuActivationCancelledEvents.push('dispose');
              },
              state: () => ({ kind: 'cancelled', activationId, reason: 'target_unavailable' }),
              onStateChange: (listener: (state: unknown) => void) => {
                stateListener = listener;
                (window as any).__seamsAuthMenuActivationCancelledEvents.push('subscribe');
                return () => {
                  (window as any).__seamsAuthMenuActivationCancelledEvents.push('unsubscribe');
                };
              },
            };
          };
        }

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        function Harness() {
          useSeams();
          const rawSeams = singletonMod.getOrCreateSeamsManager(config, {});
          installActivationSurfacePatch(rawSeams);
          return React.createElement(SeamsAuthMenu, {
            defaultMode: AuthMenuMode.Register,
            onRegister: () => {
              (window as any).__seamsAuthMenuActivationCancelledRegisterCalls += 1;
            },
          });
        }

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(React.createElement(Provider, { config }, React.createElement(Harness)));
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#seams-auth-menu-passkey-register-activation-cancelled-mount');
    const button = mount.getByRole('button', { name: 'Create with Passkey' });
    await expect(button).toBeVisible();
    await expect.poll(async () => await button.evaluate((node) => node.tagName)).toBe('BUTTON');
    await button.click();
    await expect
      .poll(
        async () =>
          await page.evaluate(
            () => (window as any).__seamsAuthMenuActivationCancelledRegisterCalls,
          ),
      )
      .toBe(1);
  });

  test('Passkey implicit registration refreshes activation surface after expiry', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-passkey-register-activation-expiry-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const contextMod: any = await import(paths.contextIndex);
        const singletonMod: any = await import(paths.seamsManagerSingleton);
        const menuMod: any = await import(paths.seamsAuthMenuClient);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const useSeams = contextMod.useSeams;
        const SeamsAuthMenu = menuMod.SeamsAuthMenuClient || menuMod.default;
        const { AuthMenuMode } = typesMod;
        const activationId = 'expired-before-click';

        type LifecycleEvent = {
          event: 'create' | 'mount' | 'dispose' | 'subscribe' | 'unsubscribe';
          walletId: string;
        };
        const lifecycle: LifecycleEvent[] = [];
        (window as any).__seamsAuthMenuActivationExpiryLifecycle = lifecycle;
        (window as any).__seamsAuthMenuActivationExpiryPatchInstalled = false;

        function installActivationSurfacePatch(seams: any): void {
          if ((window as any).__seamsAuthMenuActivationExpiryPatchInstalled) return;
          (window as any).__seamsAuthMenuActivationExpiryPatchInstalled = true;
          let mountCount = 0;
          seams.initWalletIframe = async () => undefined;
          seams.isWalletIframeReady = () => true;
          seams.onWalletIframeReady = () => () => undefined;
          seams.onWalletIframeLoginStatusChanged = () => () => undefined;
          seams.onWalletIframePreferencesChanged = () => () => undefined;
          seams.preferences.getCurrentWalletId = () => '';
          seams.registration.createPasskeyRegistrationActivationSurface = (args: {
            wallet: { walletId: string };
          }) => {
            const walletId = String(args.wallet.walletId || '');
            let stateListener: ((state: unknown) => void) | null = null;
            lifecycle.push({ event: 'create', walletId });
            return {
              kind: 'wallet_iframe_registration_activation_surface_v1',
              mount: (target: HTMLElement) => {
                mountCount += 1;
                lifecycle.push({ event: 'mount', walletId });
                target.setAttribute('data-activation-expiry-mount-count', String(mountCount));
                if (mountCount === 1) {
                  window.setTimeout(() => {
                    stateListener?.({
                      kind: 'cancelled',
                      activationId,
                      reason: 'expired',
                    });
                  }, 0);
                }
              },
              dispose: () => {
                lifecycle.push({ event: 'dispose', walletId });
              },
              state: () => ({ kind: 'idle' }),
              onStateChange: (listener: (state: unknown) => void) => {
                stateListener = listener;
                lifecycle.push({ event: 'subscribe', walletId });
                return () => {
                  lifecycle.push({ event: 'unsubscribe', walletId });
                };
              },
            };
          };
        }

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        function Harness() {
          useSeams();
          const rawSeams = singletonMod.getOrCreateSeamsManager(config, {});
          installActivationSurfacePatch(rawSeams);
          return React.createElement(SeamsAuthMenu, {
            defaultMode: AuthMenuMode.Register,
          });
        }

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(React.createElement(Provider, { config }, React.createElement(Harness)));
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#seams-auth-menu-passkey-register-activation-expiry-mount');
    const activationButton = mount.locator('.seams-passkey-registration-btn');
    await activationButton.waitFor({ state: 'attached' });
    await expect
      .poll(
        async () =>
          await page.evaluate(() => {
            const lifecycle = ((window as any).__seamsAuthMenuActivationExpiryLifecycle ||
              []) as Array<{
              event: string;
            }>;
            return {
              mountCount: lifecycle.filter((entry) => entry.event === 'mount').length,
              disposeCount: lifecycle.filter((entry) => entry.event === 'dispose').length,
              unsubscribeCount: lifecycle.filter((entry) => entry.event === 'unsubscribe').length,
            };
          }),
      )
      .toEqual({
        mountCount: 2,
        disposeCount: 1,
        unsubscribeCount: 1,
      });
    await expect(activationButton).toHaveAttribute('data-activation-expiry-mount-count', '2');
    await expect(mount.getByRole('alert')).toHaveCount(0);
    await expect(mount.getByRole('button', { name: 'Create passkey account' })).toBeVisible();
  });

  test('Passkey sponsored named registration keeps username input required', async ({ page }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-sponsored-passkey-register-controller-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.seamsAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const useSeamsAuthMenuController =
          controllerMod.useSeamsAuthMenuController || controllerMod.default;
        const { AuthMenuMode } = typesMod;

        (window as any).__seamsAuthMenuSponsoredPasskeyRegisterCalls = 0;
        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('');
          const runtime = React.useMemo(
            () => ({
              seamsWeb: { auth: { getRecentUnlocks: async () => ({ lastUsedAccount: null }) } },
              accountExists: false,
              passkeyCredentialExists: false,
              inputUsername,
              targetWalletId: '',
              setInputUsername,
              refreshLoginState: async () => undefined,
              sdkFlow: {
                eventsText: '',
                seq: 0,
                awaitNextCompletion: async () => undefined,
              },
            }),
            [inputUsername],
          );
          const controller = useSeamsAuthMenuController(
            {
              defaultMode: AuthMenuMode.Register,
              registrationAccountInput: 'sponsored_named_near_account',
              onRegister: () => {
                (window as any).__seamsAuthMenuSponsoredPasskeyRegisterCalls += 1;
              },
            },
            runtime,
          );
          return React.createElement(
            'div',
            null,
            React.createElement(
              'div',
              { id: 'sponsored-show-input' },
              String(controller.showAccountInput),
            ),
            React.createElement(
              'div',
              { id: 'sponsored-can-submit' },
              String(controller.canSubmit),
            ),
            controller.methodError
              ? React.createElement('div', { role: 'alert' }, controller.methodError)
              : null,
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: controller.onProceed,
              },
              'Create with Passkey',
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

    const mount = page.locator('#seams-auth-menu-sponsored-passkey-register-controller-mount');
    await expect(mount.locator('#sponsored-show-input')).toHaveText('true');
    await expect(mount.locator('#sponsored-can-submit')).toHaveText('false');
    const button = mount.getByRole('button', { name: 'Create with Passkey' });
    await expect(button).toBeEnabled();
    await button.click();
    await expect(mount.getByRole('alert')).toHaveText(
      'Pick a username to create a passkey account.',
    );
    await expect
      .poll(
        async () =>
          await page.evaluate(() => (window as any).__seamsAuthMenuSponsoredPasskeyRegisterCalls),
      )
      .toBe(0);
  });

  test('iframe passkey registration activation starting shows waiting screen state', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-registration-activation-waiting-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.seamsAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const useSeamsAuthMenuController =
          controllerMod.useSeamsAuthMenuController || controllerMod.default;
        const { AuthMenuMode } = typesMod;

        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('alice');
          const refreshLoginState = React.useCallback(async () => {
            (window as any).__seamsAuthMenuActivationRefreshCalls =
              ((window as any).__seamsAuthMenuActivationRefreshCalls || 0) + 1;
            await new Promise(() => {});
          }, []);
          const runtime = React.useMemo(
            () => ({
              seamsWeb: { auth: { getRecentUnlocks: async () => ({ lastUsedAccount: null }) } },
              accountExists: false,
              inputUsername,
              targetAccountId: `${inputUsername}.testnet`,
              setInputUsername,
              refreshLoginState,
              sdkFlow: {
                eventsText: '',
                seq: 0,
                awaitNextCompletion: async () => undefined,
              },
              displayPostfix: '.testnet',
              isUsingExistingAccount: false,
            }),
            [inputUsername, refreshLoginState],
          );
          const controller = useSeamsAuthMenuController(
            { defaultMode: AuthMenuMode.Register },
            runtime,
          );

          const status = controller.waiting ? `waiting:${controller.waitingReason}` : 'not-waiting';

          return React.createElement(
            'div',
            null,
            React.createElement('div', { id: 'activation-waiting-state' }, status),
            React.createElement('div', { id: 'activation-mode-state' }, String(controller.mode)),
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
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () =>
                  controller.onRegistrationActivationSurfaceStateChange({
                    kind: 'completed',
                    activationId: 'activation-1',
                    result: {
                      success: true,
                      walletId: 'alice.testnet',
                    },
                  }),
              },
              'Complete activation',
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

    const mount = page.locator('#seams-auth-menu-registration-activation-waiting-mount');
    await expect(mount.locator('#activation-waiting-state')).toHaveText('not-waiting');
    await expect(mount.locator('#activation-mode-state')).toHaveText('0');
    await mount.getByRole('button', { name: 'Start activation' }).click();
    await expect(mount.locator('#activation-waiting-state')).toHaveText('waiting:passkey');
    await mount.getByRole('button', { name: 'Complete activation' }).click();
    await expect(mount.locator('#activation-waiting-state')).toHaveText('waiting:passkey');
    await expect(mount.locator('#activation-mode-state')).toHaveText('0');
    await expect
      .poll(
        async () =>
          await page.evaluate(() => (window as any).__seamsAuthMenuActivationRefreshCalls || 0),
      )
      .toBe(1);
  });

  test('Passkey registration cancellation states do not render inline errors', async ({ page }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-registration-cancellation-silent-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.seamsAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const useSeamsAuthMenuController =
          controllerMod.useSeamsAuthMenuController || controllerMod.default;
        const { AuthMenuMode } = typesMod;
        const registrationCancelledMessage =
          "Registration was cancelled. Please try again when you're ready to set up your passkey.";

        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('alice');
          const runtime = React.useMemo(
            () => ({
              seamsWeb: { auth: { getRecentUnlocks: async () => ({ lastUsedAccount: null }) } },
              accountExists: false,
              passkeyCredentialExists: false,
              inputUsername,
              targetWalletId: inputUsername,
              setInputUsername,
              refreshLoginState: async () => undefined,
              sdkFlow: {
                eventsText: '',
                seq: 0,
                awaitNextCompletion: async () => undefined,
              },
              displayPostfix: '',
              isUsingExistingAccount: false,
            }),
            [inputUsername],
          );
          const controller = useSeamsAuthMenuController(
            { defaultMode: AuthMenuMode.Register },
            runtime,
          );

          return React.createElement(
            'div',
            null,
            React.createElement(
              'div',
              { id: 'registration-cancellation-waiting' },
              controller.waiting ? `waiting:${controller.waitingReason}` : 'not-waiting',
            ),
            controller.methodError
              ? React.createElement('div', { role: 'alert' }, controller.methodError)
              : null,
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () =>
                  controller.onRegistrationActivationSurfaceStateChange({
                    kind: 'cancelled',
                    activationId: 'activation-user-cancelled',
                    reason: 'user_cancelled',
                  }),
              },
              'Cancel activation',
            ),
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () =>
                  controller.onRegistrationActivationSurfaceStateChange({
                    kind: 'cancelled',
                    activationId: 'activation-expired',
                    reason: 'expired',
                  }),
              },
              'Expire activation',
            ),
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () =>
                  controller.onRegistrationActivationSurfaceStateChange({
                    kind: 'cancelled',
                    activationId: 'activation-target-unavailable',
                    reason: 'target_unavailable',
                  }),
              },
              'Lose activation target',
            ),
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () =>
                  controller.onRegistrationActivationSurfaceStateChange({
                    kind: 'completed',
                    activationId: 'activation-completed-cancelled',
                    result: {
                      success: false,
                      error: registrationCancelledMessage,
                    },
                  }),
              },
              'Complete cancellation result',
            ),
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () =>
                  controller.onRegistrationActivationSurfaceStateChange({
                    kind: 'failed',
                    activationId: 'activation-failed-cancelled',
                    error: registrationCancelledMessage,
                  }),
              },
              'Fail cancellation result',
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

    const mount = page.locator('#seams-auth-menu-registration-cancellation-silent-mount');
    await mount.getByRole('button', { name: 'Cancel activation' }).click();
    await expect(mount.getByRole('alert')).toHaveCount(0);
    await expect(mount.locator('#registration-cancellation-waiting')).toHaveText('not-waiting');

    await mount.getByRole('button', { name: 'Expire activation' }).click();
    await expect(mount.getByRole('alert')).toHaveCount(0);
    await expect(mount.locator('#registration-cancellation-waiting')).toHaveText('not-waiting');

    await mount.getByRole('button', { name: 'Lose activation target' }).click();
    await expect(mount.getByRole('alert')).toHaveCount(0);
    await expect(mount.locator('#registration-cancellation-waiting')).toHaveText('not-waiting');

    await mount.getByRole('button', { name: 'Complete cancellation result' }).click();
    await expect(mount.getByRole('alert')).toHaveCount(0);
    await expect(mount.locator('#registration-cancellation-waiting')).toHaveText('not-waiting');

    await mount.getByRole('button', { name: 'Fail cancellation result' }).click();
    await expect(mount.getByRole('alert')).toHaveCount(0);
    await expect(mount.locator('#registration-cancellation-waiting')).toHaveText('not-waiting');
  });

  test('Sign-up intent clears login input and uses generated wallet internally', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-register-segment-clear-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const controllerMod: any = await import(paths.seamsAuthMenuController);
        const typesMod: any = await import(paths.authMenuTypes);

        const useSeamsAuthMenuController =
          controllerMod.useSeamsAuthMenuController || controllerMod.default;
        const { AuthMenuMode } = typesMod;

        function Harness() {
          const [inputUsername, setInputUsername] = React.useState('gorp79');
          const runtime = React.useMemo(
            () => ({
              seamsWeb: {
                auth: {
                  getRecentUnlocks: async () => ({
                    accountIds: ['gorp80.w3a-relayer.testnet'],
                    lastUsedAccount: { nearAccountId: 'gorp80.w3a-relayer.testnet' },
                  }),
                },
              },
              accountExists: true,
              inputUsername,
              targetAccountId: inputUsername ? `${inputUsername}.w3a-relayer.testnet` : '',
              setInputUsername,
              refreshLoginState: async () => undefined,
              sdkFlow: {
                eventsText: '',
                seq: 0,
                awaitNextCompletion: async () => undefined,
              },
              displayPostfix: '.w3a-relayer.testnet',
              isUsingExistingAccount: true,
            }),
            [inputUsername],
          );
          const controller = useSeamsAuthMenuController(
            { defaultMode: AuthMenuMode.Login },
            runtime,
          );

          return React.createElement(
            'div',
            null,
            React.createElement('div', {
              id: 'register-clear-state',
              'data-mode': String(controller.mode),
              'data-input': controller.currentValue,
              'data-show-input': String(controller.showAccountInput),
            }),
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () => controller.onIntentChange(AuthMenuMode.Register),
              },
              'Sign up intent',
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

    const mount = page.locator('#seams-auth-menu-register-segment-clear-mount');
    const state = mount.locator('#register-clear-state');
    await expect(state).toHaveAttribute('data-input', 'gorp79');
    await expect(state).toHaveAttribute('data-show-input', 'true');
    await mount.getByRole('button', { name: 'Sign up intent' }).click();
    await expect(state).toHaveAttribute('data-input', /^[a-z]+-[a-z]+-[a-z0-9]{6}$/);
    await expect(state).toHaveAttribute('data-show-input', 'false');
    await expect(state).toHaveAttribute('data-mode', '0');
  });

  test('successful unlock refresh writes the unlocked account into account input state', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-unlock-input-refresh-mount';
        document.body.appendChild(mount);

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const contextMod: any = await import(paths.seamsContextValue);
        const refresherMod: any = await import(paths.loginStateRefresher);

        const useSeamsContextValue = contextMod.useSeamsContextValue;
        const useLoginStateRefresher = refresherMod.useLoginStateRefresher;

        (window as any).__seamsAuthMenuUnlockInputWrites = [];
        (window as any).__seamsAuthMenuUnlockRefreshAccountCalls = 0;

        const readySessionFor = (walletId: string) => ({
          authMethod: 'passkey',
          login: {
            isLoggedIn: true,
            walletId,
            nearAccountId: `${walletId}.w3a-relayer.testnet`,
            publicKey: 'ed25519:pub',
            authMethod: 'passkey',
            thresholdEcdsaEthereumAddress: null,
            thresholdEcdsaPublicKeyB64u: null,
          },
          signingSession: {
            status: 'active',
            sessionId: 'session-1',
          },
        });

        const emptySession = {
          authMethod: null,
          login: {
            isLoggedIn: false,
            walletId: null,
            nearAccountId: null,
            publicKey: null,
            authMethod: null,
            thresholdEcdsaEthereumAddress: null,
            thresholdEcdsaPublicKeyB64u: null,
          },
          signingSession: {
            status: 'missing',
            sessionId: '',
          },
        };

        function Harness() {
          const [inputUsername, setInputUsernameState] = React.useState('gorp79');
          const [loginState, setLoginState] = React.useState({
            isLoggedIn: false,
            nearAccountId: null,
            nearPublicKey: null,
            authMethod: null,
            thresholdEcdsaEthereumAddress: null,
            thresholdEcdsaPublicKeyB64u: null,
          });

          const setInputUsername = React.useCallback((username: string) => {
            (window as any).__seamsAuthMenuUnlockInputWrites.push(username);
            setInputUsernameState(username);
          }, []);

          const seams = React.useMemo(
            () => ({
              auth: {
                unlock: async (walletId: string, options?: any) => {
                  await options?.onEvent?.({
                    flow: 'unlock',
                    phase: 'unlock.completed',
                    status: 'succeeded',
                    message: 'Wallet unlocked',
                    walletId,
                  });
                  return { success: true };
                },
                lock: async () => undefined,
                getWalletSession: async (walletId?: string) =>
                  walletId ? readySessionFor(walletId) : emptySession,
                hasPasskeyCredential: async () => true,
                getRecentUnlocks: async () => ({
                  walletIds: ['gorp80'],
                  accountIds: ['gorp80.w3a-relayer.testnet'],
                  lastUsedAccount: {
                    walletId: 'gorp80',
                    displayName: 'gorp80',
                    nearAccountId: 'gorp80.w3a-relayer.testnet',
                    signerSlot: 1,
                    authMethod: 'passkey',
                  },
                }),
              },
              registration: {
                registerPasskey: async () => ({ success: true }),
                registerWallet: async () => ({ success: true }),
                registerWithEmailOtp: async () => ({ success: true }),
                addWalletSigner: async () => ({ success: true }),
              },
              recovery: {
                syncAccount: async () => ({ success: true }),
                getRecoveryEmails: async () => [],
                setRecoveryEmails: async () => ({ success: true }),
                startEmailRecovery: async () => ({ success: true }),
                finalizeEmailRecovery: async () => ({ success: true }),
                cancelEmailRecovery: async () => undefined,
                getEmailOtpRecoveryCodeStatus: async () => ({ activeRecoveryCodeCount: 0 }),
                rotateEmailOtpRecoveryCodes: async () => undefined,
              },
              near: {
                executeAction: async () => ({ success: true }),
                signNEP413Message: async () => ({ success: true }),
                signDelegateAction: async () => ({ success: true }),
              },
              devices: {
                startDevice2LinkingFlow: async () => ({ success: true }),
                stopDevice2LinkingFlow: async () => undefined,
                viewAccessKeyList: async () => ({ keys: [] }),
              },
              preferences: {
                setCurrentWallet: () => undefined,
                setConfirmBehavior: () => undefined,
                setConfirmationConfig: () => undefined,
                getConfirmationConfig: () => ({}),
              },
              setTheme: () => undefined,
            }),
            [],
          );

          const refreshLoginState = useLoginStateRefresher({
            seams,
            walletIframeConnected: false,
            setLoginState,
            setInputUsername,
          });

          const contextValue = useSeamsContextValue({
            seams,
            loginState,
            setLoginState,
            walletIframeConnected: false,
            refreshLoginState,
            accountInputState: {
              inputUsername,
              lastLoggedInUsername: '',
              lastLoggedInDomain: '',
              targetAccountId: inputUsername ? `${inputUsername}.w3a-relayer.testnet` : '',
              displayPostfix: inputUsername ? '.w3a-relayer.testnet' : '',
              isUsingExistingAccount: true,
              accountExists: true,
              indexDBAccounts: ['gorp80'],
              indexDBAccountOptions: [
                {
                  walletId: 'gorp80',
                  displayName: 'gorp80',
                  nearAccountId: 'gorp80.w3a-relayer.testnet',
                },
              ],
            },
            setInputUsername,
            refreshAccountData: async () => {
              (window as any).__seamsAuthMenuUnlockRefreshAccountCalls += 1;
            },
          });

          React.useEffect(() => {
            (window as any).__seamsAuthMenuUnlockSnapshot = {
              inputUsername,
              nearAccountId: loginState.nearAccountId,
              isLoggedIn: loginState.isLoggedIn,
            };
          }, [inputUsername, loginState]);

          return React.createElement(
            'button',
            {
              type: 'button',
              onClick: () => contextValue.unlock('gorp80'),
            },
            'Unlock gorp80',
          );
        }

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(React.createElement(Harness));
        });
      },
      { paths: IMPORT_PATHS },
    );

    const mount = page.locator('#seams-auth-menu-unlock-input-refresh-mount');
    await mount.getByRole('button', { name: 'Unlock gorp80' }).click();
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__seamsAuthMenuUnlockSnapshot))
      .toMatchObject({
        inputUsername: 'gorp80',
        nearAccountId: 'gorp80.w3a-relayer.testnet',
        isLoggedIn: true,
      });
    await expect
      .poll(
        async () =>
          await page.evaluate(() => (window as any).__seamsAuthMenuUnlockRefreshAccountCalls),
      )
      .toBeGreaterThan(0);
  });

  test('Google SSO errors warn without inline alert or unhandled promise rejection', async ({
    page,
  }) => {
    const warnings: string[] = [];
    page.on('console', (message) => {
      if (message.type() === 'warning') warnings.push(message.text());
    });

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
        mount.id = 'seams-auth-menu-google-error-mount';
        document.body.appendChild(mount);
        (window as any).__seamsAuthMenuUnhandledRejectionCount = 0;
        window.addEventListener('unhandledrejection', () => {
          (window as any).__seamsAuthMenuUnhandledRejectionCount += 1;
        });

        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const providerMod: any = await import(paths.provider);
        const menuMod: any = await import(paths.seamsAuthMenu);
        const typesMod: any = await import(paths.authMenuTypes);

        const Provider = providerMod.SeamsWebProvider || providerMod.default;
        const SeamsAuthMenu = menuMod.SeamsAuthMenu || menuMod.default;
        const { AuthMenuMode } = typesMod;

        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
        };

        const root = ReactDOMClient.createRoot(mount);
        ReactDOM.flushSync(() => {
          root.render(
            React.createElement(
              Provider,
              { config },
              React.createElement(SeamsAuthMenu, {
                defaultMode: AuthMenuMode.Login,
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

    const mount = page.locator('#seams-auth-menu-google-error-mount');
    await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({ state: 'attached' });
    await mount.getByRole('button', { name: 'Continue with Google SSO' }).click();
    await expect(mount.getByRole('alert')).toHaveCount(0);
    await expect
      .poll(() =>
        warnings.some((warning) =>
          warning.includes('[SeamsAuthMenu] Google SSO failed: Email OTP rate limit exceeded'),
        ),
      )
      .toBe(true);
    await expect
      .poll(
        async () =>
          await page.evaluate(() => (window as any).__seamsAuthMenuUnhandledRejectionCount),
      )
      .toBe(0);
  });

  test('React SDK-flow proxy preserves Email OTP namespace methods', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mount = document.createElement('div');
        mount.id = 'seams-auth-menu-auth-surface-mount';
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
          relayer: { url: 'https://router-api.localhost' },
          iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
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
