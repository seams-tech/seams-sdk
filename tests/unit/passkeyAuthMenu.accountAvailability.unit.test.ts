import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  useAccountInput: '/_test-sdk/esm/react/hooks/useAccountInput.js',
  accountExistsBadge: '/_test-sdk/esm/react/components/PasskeyAuthMenu/ui/AccountExistsBadge.js',
  authMenuTypes: '/_test-sdk/esm/react/components/PasskeyAuthMenu/authMenuTypes.js',
} as const;

test.describe('Passkey auth account availability', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('local saved credentials do not mark an unregistered account as existing', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mountId = 'w3a-account-availability-hook-mount';
      let mount = document.getElementById(mountId);
      if (!mount) {
        mount = document.createElement('div');
        mount.id = mountId;
        document.body.appendChild(mount);
      }

      const React = await import('react');
      const ReactDOMClient = await import('react-dom/client');
      const ReactDOM = await import('react-dom');
      const hooksMod: any = await import(paths.useAccountInput);
      const useAccountInput = hooksMod.useAccountInput;

      if (typeof useAccountInput !== 'function') {
        throw new Error('useAccountInput export missing from SDK ESM bundle');
      }

      let viewAccountCalls = 0;
      let viewAccessKeyListCalls = 0;

      const seams = {
        configs: {
          wallet: { mode: 'popup' },
          network: {
            relayer: {
              accountId: 'w3a-v1.testnet',
              url: 'https://router-api.localhost',
            },
          },
        },
        auth: {
          async getRecentUnlocks() {
            const account = {
              walletId: 'aerp1',
              displayName: 'aerp1',
              nearAccountId: 'aerp1.w3a-v1.testnet',
              signerSlot: 1,
              authMethod: 'passkey',
            };
            return {
              walletIds: ['aerp1'],
              accountIds: ['aerp1.w3a-v1.testnet'],
              accounts: [account],
              lastUsedAccount: account,
            };
          },
          async hasPasskeyCredential(walletId: string) {
            return walletId === 'aerp1';
          },
        },
        getContext() {
          return {
            nearClient: {
              async viewAccount(accountId: string) {
                viewAccountCalls += 1;
                throw new Error(`UNKNOWN_ACCOUNT: ${String(accountId || '')}`);
              },
            },
          };
        },
        async viewAccessKeyList(accountId: string) {
          viewAccessKeyListCalls += 1;
          return { keys: [] };
        },
        isWalletIframeReady() {
          return true;
        },
        async initWalletIframe() {},
        onWalletIframeReady() {
          return () => {};
        },
      };

      function Harness() {
        const hook = useAccountInput({
          seams,
          accountDomain: 'w3a-v1.testnet',
          currentNearAccountId: null,
          isLoggedIn: false,
        });

        React.useEffect(() => {
          (window as any).__w3aAccountAvailabilityHook = hook;
        }, [hook]);

        return React.createElement('div', {
          id: 'w3a-account-availability-state',
          'data-account-exists': String(hook.accountExists),
        });
      }

      const root = ReactDOMClient.createRoot(mount);
      ReactDOM.flushSync(() => {
        root.render(React.createElement(Harness));
      });

      const waitFor = async (predicate: () => boolean, label: string) => {
        const timeoutMs = 3_000;
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
          if (predicate()) return;
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
        throw new Error(`Timed out waiting for ${label}`);
      };

      await waitFor(
        () => {
          const hook = (window as any).__w3aAccountAvailabilityHook;
          return (
            hook?.inputUsername === 'aerp1' &&
            hook?.targetWalletId === 'aerp1' &&
            hook?.targetAccountId === 'aerp1.w3a-v1.testnet' &&
            viewAccountCalls > 0
          );
        },
        'account availability check to complete',
      );

      const hook = (window as any).__w3aAccountAvailabilityHook;
      const snapshot = {
        inputUsername: String(hook?.inputUsername || ''),
        targetWalletId: String(hook?.targetWalletId || ''),
        targetAccountId: String(hook?.targetAccountId || ''),
        isUsingExistingAccount: Boolean(hook?.isUsingExistingAccount),
        accountExists: Boolean(hook?.accountExists),
        passkeyCredentialExists: Boolean(hook?.passkeyCredentialExists),
        viewAccountCalls,
        viewAccessKeyListCalls,
      };

      root.unmount();
      return snapshot;
    }, { paths: IMPORT_PATHS });

    expect(result.inputUsername).toBe('aerp1');
    expect(result.targetWalletId).toBe('aerp1');
    expect(result.targetAccountId).toBe('aerp1.w3a-v1.testnet');
    expect(result.isUsingExistingAccount).toBe(true);
    expect(result.accountExists).toBe(false);
    expect(result.passkeyCredentialExists).toBe(true);
    expect(result.viewAccountCalls).toBeGreaterThan(0);
    expect(result.viewAccessKeyListCalls).toBe(0);
  });

  test('register badge stays neutral for a locally saved account until it exists on-chain', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mountId = 'w3a-account-availability-badge-mount';
      let mount = document.getElementById(mountId);
      if (!mount) {
        mount = document.createElement('div');
        mount.id = mountId;
        document.body.appendChild(mount);
      }

      const React = await import('react');
      const ReactDOMClient = await import('react-dom/client');
      const ReactDOM = await import('react-dom');
      const badgeMod: any = await import(paths.accountExistsBadge);
      const typesMod: any = await import(paths.authMenuTypes);
      const AccountExistsBadge = badgeMod.AccountExistsBadge || badgeMod.default;
      const { AuthMenuMode } = typesMod;

      const root = ReactDOMClient.createRoot(mount);
      ReactDOM.flushSync(() => {
        root.render(
          React.createElement(AccountExistsBadge, {
            isUsingExistingAccount: true,
            targetExists: false,
            mode: AuthMenuMode.Register,
            secure: true,
          }),
        );
      });

      const snapshot = {
        text: String(mount.textContent || '').trim(),
        html: mount.innerHTML,
      };

      root.unmount();
      return snapshot;
    }, { paths: IMPORT_PATHS });

    expect(result.text).toBe('');
    expect(result.html).not.toContain('name taken');
  });
});
