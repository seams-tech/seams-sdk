import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const FLAT_ROOT_SIGNING_METHODS = [
  'executeAction',
  'signAndSendTransactions',
  'signAndSendTransaction',
  'signTransactionsWithActions',
  'sendTransaction',
  'signDelegateAction',
  'sendDelegateActionViaRelayer',
  'signAndSendDelegateAction',
  'signNEP413Message',
  'signTempo',
  'bootstrapEcdsaSession',
] as const;

test.describe('TatchiPasskey namespaced signing surface', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('TatchiPasskey exposes near/tempo/evm namespaces without flat root signing methods', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ flatMethods }) => {
        const mod = await import('/sdk/esm/core/TatchiPasskey/index.js');
        const { TatchiPasskey } = mod as any;

        const tatchi = new TatchiPasskey({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        });

        const hasNear =
          !!tatchi.near &&
          typeof tatchi.near.executeAction === 'function' &&
          typeof tatchi.near.signAndSendTransactions === 'function' &&
          typeof tatchi.near.signTransactionsWithActions === 'function' &&
          typeof tatchi.near.sendTransaction === 'function' &&
          typeof tatchi.near.signDelegateAction === 'function' &&
          typeof tatchi.near.sendDelegateActionViaRelayer === 'function' &&
          typeof tatchi.near.signAndSendDelegateAction === 'function' &&
          typeof tatchi.near.signNEP413Message === 'function';
        const hasTempo =
          !!tatchi.tempo &&
          typeof tatchi.tempo.signTempo === 'function' &&
          typeof tatchi.tempo.reportBroadcastResult === 'function' &&
          typeof tatchi.tempo.bootstrapEcdsaSession === 'function';
        const hasEvm = !!tatchi.evm && typeof tatchi.evm.bootstrapEcdsaSession === 'function';
        const noFlatMethods = flatMethods.every((name: string) => !(name in tatchi));

        return { hasNear, hasTempo, hasEvm, noFlatMethods };
      },
      { flatMethods: [...FLAT_ROOT_SIGNING_METHODS] },
    );

    expect(result.hasNear).toBe(true);
    expect(result.hasTempo).toBe(true);
    expect(result.hasEvm).toBe(true);
    expect(result.noFlatMethods).toBe(true);
  });
});
