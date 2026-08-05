import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const AUTH_MENU_PATH = '/_test-sdk/esm/react/components/SeamsAuthMenu/public.js';
const CONTEXT_PATH = '/_test-sdk/esm/react/context/index.js';

test.describe('SeamsAuthMenu StrictMode lifecycle', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('about:blank');
    await injectImportMap(page);
  });

  test('suppresses synthetic cleanup and value-equal config replacements', async ({ page }) => {
    const result = await page.evaluate(
      async ({ authMenuPath, contextPath }) => {
        const React = await import('react');
        const ReactDOMClient = await import('react-dom/client');
        const ReactDOM = await import('react-dom');
        const authMenuModule = await import(authMenuPath);
        const contextModule = await import(contextPath);
        const outcomes: unknown[] = [];
        const mount = document.createElement('div');
        document.body.appendChild(mount);
        const config = {
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://router-api.localhost' },
        };
        const copy = {
          login: { title: 'Sign in' },
          common: { closeLabel: 'Close' },
        };
        const root = ReactDOMClient.createRoot(mount);
        const renderMenu = (
          nextCopy: typeof copy,
          externalAuthBroker: ((request: unknown) => unknown) | null = null,
        ) => {
          ReactDOM.flushSync(() => {
            root.render(
              React.createElement(
                React.StrictMode,
                null,
                React.createElement(
                  contextModule.SeamsContextProvider,
                  { config },
                  React.createElement(authMenuModule.SeamsAuthMenu, {
                    copy: nextCopy,
                    externalAuthBroker,
                    onOutcome: (outcome: unknown) => outcomes.push(outcome),
                  }),
                ),
              ),
            );
          });
        };
        renderMenu(copy);
        await new Promise((resolve) => setTimeout(resolve, 100));
        const afterInitialMount = outcomes.slice();
        renderMenu({
          login: { title: 'Sign in' },
          common: { closeLabel: 'Close' },
        });
        await new Promise((resolve) => setTimeout(resolve, 100));
        const afterValueEqualReplacement = outcomes.slice();
        renderMenu({
          login: { title: 'Sign in to Seams' },
          common: { closeLabel: 'Close' },
        });
        await new Promise((resolve) => setTimeout(resolve, 100));
        const afterChangedReplacement = outcomes.slice();
        const brokerA = () => ({ kind: 'cancelled', reason: 'user_cancelled' });
        const brokerB = () => ({ kind: 'cancelled', reason: 'user_cancelled' });
        renderMenu(copy, brokerA);
        await new Promise((resolve) => setTimeout(resolve, 100));
        const afterBrokerAdded = outcomes.slice();
        renderMenu(copy, brokerB);
        await new Promise((resolve) => setTimeout(resolve, 100));
        const afterBrokerReplaced = outcomes.slice();
        renderMenu(copy, null);
        await new Promise((resolve) => setTimeout(resolve, 100));
        const afterBrokerRemoved = outcomes.slice();
        root.unmount();
        await new Promise((resolve) => setTimeout(resolve, 0));
        return {
          afterInitialMount,
          afterValueEqualReplacement,
          afterChangedReplacement,
          afterBrokerAdded,
          afterBrokerReplaced,
          afterBrokerRemoved,
          afterUnmount: outcomes,
        };
      },
      { authMenuPath: AUTH_MENU_PATH, contextPath: CONTEXT_PATH },
    );

    expect(result.afterInitialMount).toHaveLength(1);
    expect(result.afterInitialMount[0]).toMatchObject({ kind: 'failed' });
    expect(result.afterValueEqualReplacement).toEqual(result.afterInitialMount);
    expect(result.afterChangedReplacement).toHaveLength(2);
    expect(result.afterChangedReplacement.every((outcome) => outcome.kind === 'failed')).toBe(true);
    expect(result.afterBrokerAdded).toHaveLength(3);
    expect(result.afterBrokerAdded.every((outcome) => outcome.kind === 'failed')).toBe(true);
    expect(result.afterBrokerReplaced).toEqual(result.afterBrokerAdded);
    expect(result.afterBrokerRemoved).toHaveLength(4);
    expect(result.afterBrokerRemoved.every((outcome) => outcome.kind === 'failed')).toBe(true);
    expect(result.afterUnmount).toEqual(result.afterBrokerRemoved);
  });
});
