import { expect, test } from '@playwright/test';
import { createInMemoryConsoleApiKeyService } from '../../packages/sdk-server-ts/src/console/apiKeys';
import { createInMemoryConsoleRuntimeSnapshotService } from '../../packages/sdk-server-ts/src/console/runtimeSnapshots';
import { createInMemoryConsoleSponsoredCallService } from '../../packages/sdk-server-ts/src/console/sponsoredCalls';
import { createCloudflareRouter } from '../../packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter';
import { createRouterApiPublishableKeyAuthAdapter } from '../../packages/sdk-server-ts/src/router/routerApiKeyAuth';
import { callCf, makeFakeAuthService } from '../relayer/helpers';

function makeSponsoredOptions() {
  const apiKeys = createInMemoryConsoleApiKeyService();
  const sponsorAddress = '0x2222222222222222222222222222222222222222' as const;
  const sponsorPrivateKeyHex =
    '0x1111111111111111111111111111111111111111111111111111111111111111' as const;
  return {
    route: '/gas/relay',
    publishableKeyAuth: createRouterApiPublishableKeyAuthAdapter(apiKeys),
    billing: {
      async recordUsageEvent() {
        return {
          accepted: true,
          counted: true,
          monthUtc: '2026-03',
          monthlyActiveWallets: 1,
        };
      },
      async recordSponsoredExecutionDebit() {
        return {
          accepted: true,
          debitAppliedMinor: 0,
          creditBalanceMinor: 0,
          monthUtc: '2026-03',
          statementId: 'inv_202603_001',
        };
      },
    } as any,
    ledger: createInMemoryConsoleSponsoredCallService(),
    runtimeSnapshots: createInMemoryConsoleRuntimeSnapshotService(),
    config: {
      executorsByChain: new Map([
        [
          42_431,
          {
            chainId: 42_431,
            rpcUrl: 'https://rpc.example.test',
            sponsorAddress,
            sponsorPrivateKeyHex,
            maxPriorityFeePerGasFloor: 2_000_000_000n,
            maxFeePerGasFloor: 40_000_000_000n,
          },
        ],
      ]),
    },
  } as const;
}

test.describe('cloudflare sponsored evm call route', () => {
  const requestBody = {
    environmentId: 'proj_test:dev',
    walletId: 'wallet_test_1',
    walletAddress: '0x1111111111111111111111111111111111111111',
    chainId: 42_431,
    call: {
      to: '0x2222222222222222222222222222222222222222',
      data: '0x12345678',
      gasLimit: '21000',
      value: '0',
    },
    idempotencyKey: 'intent_test_1',
  } as const;

  test('returns 404 when sponsorship is not configured', async () => {
    const handler = createCloudflareRouter(makeFakeAuthService(), {
      corsOrigins: ['https://example.localhost'],
    });

    const response = await callCf(handler, {
      method: 'POST',
      path: '/sponsorships/evm/call',
      origin: 'https://example.localhost',
      body: requestBody,
    });

    expect(response.status).toBe(404);
  });

  test('warns and fails closed when sponsored route is mounted without pricing', async () => {
    const warnings: unknown[][] = [];
    const handler = createCloudflareRouter(makeFakeAuthService(), {
      corsOrigins: ['https://example.localhost'],
      sponsoredEvmCall: makeSponsoredOptions(),
      logger: {
        warn: (...args: unknown[]) => {
          warnings.push(args);
        },
      },
    });

    const response = await callCf(handler, {
      method: 'POST',
      path: '/gas/relay',
      origin: 'https://example.localhost',
      body: requestBody,
    });

    expect(response.status).not.toBe(404);
    expect(response.status).toBe(503);
    expect(response.json?.code).toBe('sponsorship_pricing_unavailable');
    expect(warnings[0]?.[0]).toBe('[sponsored-evm-call][pricing-unconfigured]');
  });
});
