import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, SDK_ESM_PATHS } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute } from './harness';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const ALICE_SUBJECT_ID = toWalletSubjectId('alice.testnet');
const ALICE_EVM_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
  networkSlug: 'sepolia',
});

const signingProgressForwardingScript = String.raw`
  const originalAdoptPort = adoptPort;
  adoptPort = function patchedAdoptPort(port) {
    originalAdoptPort(port);
    if (!adoptedPort) return;

    const originalHandler = adoptedPort.onmessage;
    adoptedPort.onmessage = (event) => {
      originalHandler?.(event);
      const data = event.data || {};
      if (!data || typeof data !== 'object') return;
      if (data.type !== 'PM_SIGN_TEMPO' || typeof data.requestId !== 'string') return;

      const requestId = data.requestId;
      setTimeout(() => {
        try {
          adoptedPort.postMessage({
            type: 'PROGRESS',
            requestId,
            payload: {
              version: 2,
              flow: 'unlock',
              step: 1,
              phase: 'unlock.started',
              status: 'started',
              message: 'Ignored wrong-flow progress',
              flowId: 'unlock:test',
              interaction: { kind: 'none', overlay: 'none' },
            },
          });
        } catch (err) {
          console.error('Failed to post wrong-flow PROGRESS', err);
        }
      }, 10);

      setTimeout(() => {
        try {
          adoptedPort.postMessage({
            type: 'PROGRESS',
            requestId,
            payload: {
              version: 2,
              flow: 'signing',
              step: 10,
              phase: 'signing.commit.started',
              status: 'running',
              message: 'Creating threshold signature',
              flowId: 'signing:evm:test',
              accountId: 'alice.testnet',
              authMethod: 'warm_session',
              interaction: { kind: 'none', overlay: 'none' },
              data: { chain: 'evm', threshold: true },
            },
          });
        } catch (err) {
          console.error('Failed to post signing PROGRESS', err);
        }
      }, 20);

      setTimeout(() => {
        pendingRequests.delete(requestId);
        try {
          adoptedPort.postMessage({
            type: 'PM_RESULT',
            requestId,
            payload: {
              ok: true,
              result: { chain: 'evm', kind: 'eip1559', txHashHex: '0xabc', rawTxHex: '0xdef' },
            },
          });
        } catch (err) {
          console.error('Failed to post PM_RESULT for PM_SIGN_TEMPO', err);
        }
      }, 40);
    };
  };
`;

test.describe('WalletIframeRouter signing progress forwarding', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: signingProgressForwardingScript }),
      WALLET_SERVICE_ROUTE,
    );
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('forwards v2 EVM threshold signing progress to app onEvent', async ({ page }) => {
    const result = await page.evaluate(
      async ({ routerPath, walletOrigin }) => {
        const mod = await import(routerPath);
        const { WalletIframeRouter } = mod as typeof import('@/core/WalletIframe/client/router');

        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3000,
          requestTimeoutMs: 1200,
          debug: true,
          sdkBasePath: '/sdk',
        });
        await router.init();

        const events: any[] = [];
        const signed = await router.signTempo({
          nearAccountId: 'alice.testnet',
          subjectId: ALICE_SUBJECT_ID,
          chainTarget: ALICE_EVM_CHAIN_TARGET,
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {},
          } as any,
          options: {
            onEvent: (event: any) => events.push(event),
          },
        });

        return {
          signed,
          events,
        };
      },
      { routerPath: SDK_ESM_PATHS.walletIframeRouter, walletOrigin: WALLET_ORIGIN },
    );

    expect(result.signed).toMatchObject({
      chain: 'evm',
      txHashHex: '0xabc',
      rawTxHex: '0xdef',
    });
    expect(result.events).toHaveLength(1);
    expect(result.events[0]).toMatchObject({
      version: 2,
      flow: 'signing',
      step: 10,
      phase: 'signing.commit.started',
      status: 'running',
      flowId: 'signing:evm:test',
      accountId: 'alice.testnet',
      authMethod: 'warm_session',
      interaction: { kind: 'none', overlay: 'none' },
      data: { chain: 'evm', threshold: true },
    });
  });
});
