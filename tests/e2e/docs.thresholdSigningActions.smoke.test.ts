import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  demoPage: '/src/components/DemoPage.tsx',
} as const;

test.describe('docs frontend signing actions smoke', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('logged-in demo invokes NEAR action + Tempo/EVM threshold signing actions', async ({
    page,
  }) => {
    await page.evaluate(async ({ paths }) => {
      const viteReactPath = '/node_modules/.vite/deps/react.js' as string;
      const viteReactDomClientPath = '/node_modules/.vite/deps/react-dom_client.js' as string;
      const viteReactDomPath = '/node_modules/.vite/deps/react-dom.js' as string;
      const React =
        ((await import(viteReactPath).catch(() => null)) as any) ||
        (await import('react'));
      const ReactRuntime = (React as any).default || React;
      const ReactDOMClient =
        ((await import(viteReactDomClientPath).catch(() => null)) as any) ||
        (await import('react-dom/client'));
      const ReactDOMClientRuntime = (ReactDOMClient as any).default || ReactDOMClient;
      const ReactDOM =
        ((await import(viteReactDomPath).catch(() => null)) as any) ||
        (await import('react-dom'));
      const ReactDOMRuntime = (ReactDOM as any).default || ReactDOM;
      const demoMod = await import(paths.demoPage);
      const DemoPage = (demoMod as any).DemoPage || (demoMod as any).default;
      if (!DemoPage) {
        throw new Error('Failed to load DemoPage module export');
      }

      const counters = {
        nearActions: 0,
        tempoSigns: 0,
        evmSigns: 0,
      };
      (window as any).__docsSigningSmokeCounters = counters;
      (window as any).__docsSigningSmokeRequests = {
        tempo: null,
        evm: null,
      };

      function useTatchiHook() {
        return {
          loginState: {
            isLoggedIn: true,
            nearAccountId: 'alice.testnet',
          },
          tatchi: {
            auth: {
              getSession: async () => ({
                signingSession: {
                  sessionId: 'session-1',
                  status: 'active',
                  remainingUses: 3,
                  expiresAtMs: Date.now() + 60_000,
                  createdAtMs: Date.now(),
                },
              }),
              login: async () => ({ success: true }),
            },
            near: {
              executeAction: async (args: any) => {
                counters.nearActions += 1;
                args?.options?.afterCall?.(true, {
                  success: true,
                  transactionId: 'mock-near-tx',
                });
                return { success: true };
              },
              signDelegateAction: async () => ({
                hash: 'mock-hash',
                signedDelegate: {},
              }),
              sendDelegateActionViaRelayer: async () => ({
                ok: true,
                relayerTxHash: 'mock-relayer-tx',
              }),
            },
            tempo: {
              signTempo: async (args: any) => {
                const kind = String(args?.request?.kind || '').trim();
                const chain = String(args?.request?.chain || '').trim();

                if (kind === 'eip1559') {
                  counters.evmSigns += 1;
                  (window as any).__docsSigningSmokeRequests.evm = { chain, kind };
                  return {
                    kind: 'eip1559',
                    txHashHex: `0x${'cd'.repeat(32)}`,
                    rawTxHex: `0x${'34'.repeat(32)}`,
                  };
                }

                counters.tempoSigns += 1;
                (window as any).__docsSigningSmokeRequests.tempo = { chain, kind };
                return {
                  kind: 'tempoTransaction',
                  senderHashHex: `0x${'ab'.repeat(32)}`,
                  rawTxHex: `0x${'12'.repeat(32)}`,
                };
              },
            },
            configs: { relayer: { url: 'https://relay.example' } },
          },
        };
      }

      function useSetGreetingHook() {
        return {
          onchainGreeting: 'hello',
          isLoading: false,
          fetchGreeting: async () => undefined,
          error: null,
        };
      }

      const mount = document.createElement('div');
      mount.id = 'demo-page-test-mount';
      document.body.appendChild(mount);

      const root = ReactDOMClientRuntime.createRoot(mount);
      ReactDOMRuntime.flushSync(() => {
        root.render(
          ReactRuntime.createElement(DemoPage, {
            __testOverrides: {
              useTatchiHook,
              useSetGreetingHook,
            },
          }),
        );
      });
    }, { paths: IMPORT_PATHS });

    const scope = page.locator('#demo-page-test-mount');
    const nearActionButton = scope.getByRole('button', { name: 'Set Greeting' });
    const tempoButton = scope.getByRole('button', { name: 'Sign Tempo Threshold Transaction' });
    const evmButton = scope.getByRole('button', { name: 'Sign EVM Threshold EIP-1559 Transaction' });

    await expect(nearActionButton).toBeVisible();
    await expect(tempoButton).toBeVisible();
    await expect(evmButton).toBeVisible();

    await nearActionButton.evaluate((el: HTMLElement) => el.click());
    await tempoButton.evaluate((el: HTMLElement) => el.click());
    await evmButton.evaluate((el: HTMLElement) => el.click());

    await page.waitForFunction(() => {
      const counters = (window as any).__docsSigningSmokeCounters;
      return (
        counters &&
        counters.nearActions === 1 &&
        counters.tempoSigns === 1 &&
        counters.evmSigns === 1
      );
    });

    const counters = await page.evaluate(() => (window as any).__docsSigningSmokeCounters);
    expect(counters).toEqual({
      nearActions: 1,
      tempoSigns: 1,
      evmSigns: 1,
    });

    const requests = await page.evaluate(() => (window as any).__docsSigningSmokeRequests);
    expect(requests).toEqual({
      tempo: { chain: 'tempo', kind: 'tempoTransaction' },
      evm: { chain: 'evm', kind: 'eip1559' },
    });
  });
});
