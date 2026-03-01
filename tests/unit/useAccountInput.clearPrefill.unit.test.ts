import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  useAccountInput: '/sdk/esm/react/hooks/useAccountInput.js',
} as const;

test.describe('useAccountInput refresh prefill behavior', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('refreshAccountData does not repopulate input after explicit clear', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mountId = 'w3a-use-account-input-mount';
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

      const tatchi = {
        configs: {
          wallet: { mode: 'popup' },
          network: {
            relayer: {
              accountId: 'w3a-v1.testnet',
              url: 'https://relay-server.localhost',
            },
          },
        },
        auth: {
          async getRecentUnlocks() {
            return {
              accountIds: ['alice.w3a-v1.testnet'],
              lastUsedAccount: { nearAccountId: 'alice.w3a-v1.testnet' },
            };
          },
          async hasPasskeyCredential() {
            return true;
          },
        },
        async viewAccessKeyList() {
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
          tatchi,
          accountDomain: 'w3a-v1.testnet',
          currentNearAccountId: null,
          isLoggedIn: false,
        });

        React.useEffect(() => {
          (window as any).__w3aUseAccountInputHook = hook;
        }, [hook]);

        return React.createElement('div', {
          id: 'w3a-use-account-input-state',
          'data-username': hook.inputUsername,
        });
      }

      const root = ReactDOMClient.createRoot(mount);
      ReactDOM.flushSync(() => {
        root.render(React.createElement(Harness));
      });

      const waitForInput = async (expected: string) => {
        const timeoutMs = 3_000;
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
          const current = String((window as any).__w3aUseAccountInputHook?.inputUsername || '');
          if (current === expected) return current;
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
        throw new Error(`Timed out waiting for inputUsername=${JSON.stringify(expected)}`);
      };

      await waitForInput('alice');
      const initial = String((window as any).__w3aUseAccountInputHook?.inputUsername || '');

      (window as any).__w3aUseAccountInputHook?.setInputUsername('');
      await waitForInput('');
      const afterClear = String((window as any).__w3aUseAccountInputHook?.inputUsername || '');

      await (window as any).__w3aUseAccountInputHook?.refreshAccountData?.();
      await new Promise((resolve) => setTimeout(resolve, 20));
      const afterRefresh = String((window as any).__w3aUseAccountInputHook?.inputUsername || '');

      root.unmount();
      return { initial, afterClear, afterRefresh };
    }, { paths: IMPORT_PATHS });

    expect(result.initial).toBe('alice');
    expect(result.afterClear).toBe('');
    expect(result.afterRefresh).toBe('');
  });
});
