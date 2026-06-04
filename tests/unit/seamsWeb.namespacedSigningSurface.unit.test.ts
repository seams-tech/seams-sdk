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

test.describe('SeamsWeb namespaced signing surface', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('SeamsWeb exposes near/tempo/evm namespaces without flat root signing methods', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ flatMethods }) => {
        const mod = await import('/sdk/esm/web/SeamsWeb/index.js');
        const { SeamsWeb } = mod as any;

        const seams = new SeamsWeb({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'https://relay-server.localhost' },
          iframeWallet: { walletOrigin: '' },
        });

        const hasNear =
          !!seams.near &&
          typeof seams.near.executeAction === 'function' &&
          typeof seams.near.signAndSendTransactions === 'function' &&
          typeof seams.near.signTransactionsWithActions === 'function' &&
          typeof seams.near.sendTransaction === 'function' &&
          typeof seams.near.signDelegateAction === 'function' &&
          typeof seams.near.sendDelegateActionViaRelayer === 'function' &&
          typeof seams.near.signAndSendDelegateAction === 'function' &&
          typeof seams.near.signNEP413Message === 'function';
        const hasTempo =
          !!seams.tempo &&
          typeof seams.tempo.signTempo === 'function' &&
          typeof seams.tempo.reportBroadcastAccepted === 'function' &&
          typeof seams.tempo.reportBroadcastRejected === 'function' &&
          typeof seams.tempo.reportFinalized === 'function' &&
          typeof seams.tempo.reconcileNonceLane === 'function' &&
          typeof seams.tempo.bootstrapEcdsaSession === 'function';
        const hasEvm = !!seams.evm && typeof seams.evm.bootstrapEcdsaSession === 'function';
        const noFlatMethods = flatMethods.every((name: string) => !(name in seams));

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
