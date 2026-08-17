import { expect, test } from '@playwright/test';
import { getNearSpendCapChainId } from '@seams-internal/wallet-console-shared/gasSponsorshipSpendCapTargets';
import {
  createOutlayerSponsoredExecutionPricingService,
  isSponsorshipSpendCapEnforcementError,
  resolveSponsoredExecutionPricingFromEnv,
} from '../../packages/console-server-ts/src/sponsorship';

const NEAR_RPC_URL = 'https://free.rpc.fastnear.com';
const EVM_RPC_URL = 'https://rpc.moderato.tempo.xyz';
const ORACLE_CONTRACT_ID = 'price-oracle.near';
const NEAR_USD_PRICE_ID = 'c415de8d2efa7db216527dff4b60e8f3a5311c740dadb233e13e12547e226750';
const NOW_MS = 1_700_000_100_000;
const PUBLISH_TIME_SECONDS = 1_700_000_050;

type PythPriceFixture = {
  price: number;
  conf: number;
  expo: number;
  publish_time: number;
};

function encodeJsonBytes(value: unknown): number[] {
  return Array.from(new TextEncoder().encode(JSON.stringify(value)));
}

function createPythPrice(overrides: Partial<PythPriceFixture> = {}): PythPriceFixture {
  return {
    price: 725_000_000,
    conf: 0,
    expo: -8,
    publish_time: PUBLISH_TIME_SECONDS,
    ...overrides,
  };
}

function createMockFetch(options?: {
  captures?: { nearRpcCalls: number };
  latest?: unknown;
  ema?: unknown;
}) {
  const latest = options && 'latest' in options ? options.latest : createPythPrice();
  const ema = options && 'ema' in options ? options.ema : createPythPrice({ price: 700_000_000 });
  return async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(typeof input === 'string' || input instanceof URL ? input : input.url);
    const request = JSON.parse(String(init?.body || '{}')) as {
      method?: string;
      params?: {
        account_id?: string;
        method_name?: string;
        args_base64?: string;
      };
    };
    if (url === NEAR_RPC_URL && request.method === 'query') {
      if (options?.captures) options.captures.nearRpcCalls += 1;
      expect(request.params?.account_id).toBe(ORACLE_CONTRACT_ID);
      const methodName = request.params?.method_name;
      const args = JSON.parse(atob(String(request.params?.args_base64 || ''))) as Record<
        string,
        unknown
      >;
      if (methodName === 'get_price') {
        expect(args).toEqual({ price_identifier: NEAR_USD_PRICE_ID });
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            block_height: 209_163_435,
            result: encodeJsonBytes(latest),
          },
        });
      }
      if (methodName === 'get_ema_price') {
        expect(args).toEqual({ price_id: NEAR_USD_PRICE_ID });
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            block_height: 209_163_435,
            result: encodeJsonBytes(ema),
          },
        });
      }
    }
    if (url === EVM_RPC_URL && request.method === 'eth_gasPrice') {
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: '22000000000',
      });
    }
    throw new Error(`Unexpected pricing request ${url} ${String(request.method)}`);
  };
}

function createPricing(options?: { fetch?: typeof fetch; now?: () => number }) {
  return createOutlayerSponsoredExecutionPricingService(
    {
      nearRpcUrl: NEAR_RPC_URL,
      oracleContractId: ORACLE_CONTRACT_ID,
      nearUsdPriceId: NEAR_USD_PRICE_ID,
      maxAgeSeconds: 120,
      maxLatestToEmaDeviationBps: 1_000,
      cacheTtlMs: 60_000,
      evmByChain: new Map([
        [
          42_431,
          {
            chainId: 42_431,
            rpcUrl: EVM_RPC_URL,
            nativeUnitDecimals: 18,
            pricingVersionPrefix: 'outlayer-tempo-testnet',
          },
        ],
      ]),
      nearByChain: new Map([
        [
          getNearSpendCapChainId('TESTNET'),
          {
            networkClass: 'TESTNET',
            nativeUnitDecimals: 24,
            estimateFeeAmountYocto: 2_000n,
            pricingVersionPrefix: 'outlayer-near-testnet',
          },
        ],
      ]),
    },
    {
      fetch: options?.fetch || (createMockFetch() as typeof fetch),
      now: options?.now || (() => NOW_MS),
    },
  );
}

function nearEstimateInput() {
  return {
    chainFamily: 'near' as const,
    intentKind: 'near_delegate' as const,
    executorKind: 'near_delegate' as const,
    environmentId: 'proj_env:dev',
    policyId: 'policy_gs_near',
    accountRef: 'near:alice.testnet',
    targetRef: 'near:guest-book.testnet',
    chainId: getNearSpendCapChainId('TESTNET'),
    requestDetails: { receiverId: 'guest-book.testnet' },
  };
}

async function captureEstimateError(pricing = createPricing()): Promise<unknown> {
  return await pricing
    .estimateSponsoredExecutionSpend(nearEstimateInput())
    .catch((error: unknown) => error);
}

function expectPricingError(error: unknown, code: string): void {
  expect(isSponsorshipSpendCapEnforcementError(error)).toBe(true);
  expect((error as { code?: string }).code).toBe(code);
}

test.describe('Outlayer sponsored execution pricing', () => {
  test('estimates and finalizes NEAR spend from fresh latest and EMA prices', async () => {
    const pricing = createPricing();
    const estimated = await pricing.estimateSponsoredExecutionSpend(nearEstimateInput());
    expect(estimated).toEqual({
      spendMinor: 1,
      pricingVersion:
        'outlayer-near-testnet:outlayer:price-oracle.near:near-usd:1700000050:ema-guard-1000bps',
    });

    const finalized = await pricing.finalizeSponsoredExecutionSpend({
      ...nearEstimateInput(),
      txOrExecutionRef: 'delegate-tx-123',
      receiptStatus: 'success',
      feeUnit: 'yocto_near',
      feeAmount: '1500',
      estimatedSpendMinor: estimated.spendMinor,
      estimatedPricingVersion: estimated.pricingVersion,
    });
    expect(finalized).toEqual({
      spendMinor: 1,
      pricingVersion: estimated.pricingVersion,
    });
  });

  test('combines EVM gas price with the accepted NEAR/USD price', async () => {
    const pricing = createPricing();
    const estimated = await pricing.estimateSponsoredExecutionSpend({
      chainFamily: 'evm',
      intentKind: 'evm_call',
      executorKind: 'evm_eoa',
      environmentId: 'proj_env:dev',
      policyId: 'policy_gs_onboarding',
      accountRef: 'near:alice.testnet',
      targetRef: 'evm:42431:0xbb442b54c85efba2d7b81ea52990ad638cdba483',
      chainId: 42_431,
      requestDetails: { call: { gasLimit: '1000000' } },
    });
    expect(estimated.spendMinor).toBe(16);
    expect(estimated.pricingVersion).toContain(
      'outlayer-tempo-testnet:outlayer:price-oracle.near:near-usd:1700000050',
    );
  });

  test('caches both oracle responses for the configured TTL', async () => {
    const captures = { nearRpcCalls: 0 };
    let nowMs = NOW_MS;
    const pricing = createPricing({
      fetch: createMockFetch({ captures }) as typeof fetch,
      now: () => nowMs,
    });
    await pricing.estimateSponsoredExecutionSpend(nearEstimateInput());
    await pricing.estimateSponsoredExecutionSpend(nearEstimateInput());
    expect(captures.nearRpcCalls).toBe(2);

    nowMs += 60_001;
    await pricing.estimateSponsoredExecutionSpend(nearEstimateInput());
    expect(captures.nearRpcCalls).toBe(4);
  });

  test('never caches a quote beyond its freshness boundary', async () => {
    const captures = { nearRpcCalls: 0 };
    let nowMs = NOW_MS;
    const pricing = createPricing({
      fetch: createMockFetch({
        captures,
        latest: createPythPrice({ publish_time: Math.floor(NOW_MS / 1000) - 100 }),
        ema: createPythPrice({ publish_time: Math.floor(NOW_MS / 1000) - 100 }),
      }) as typeof fetch,
      now: () => nowMs,
    });
    await pricing.estimateSponsoredExecutionSpend(nearEstimateInput());

    nowMs += 20_001;
    const stale = await captureEstimateError(pricing);
    expectPricingError(stale, 'sponsorship_pricing_unavailable');
    expect(captures.nearRpcCalls).toBe(4);
  });

  test('prefers valid Outlayer pricing when static pricing is also configured', async () => {
    const originalFetch = globalThis.fetch;
    const currentPublishTimeSeconds = Math.floor(Date.now() / 1000);
    globalThis.fetch = createMockFetch({
      latest: createPythPrice({ publish_time: currentPublishTimeSeconds }),
      ema: createPythPrice({
        price: 700_000_000,
        publish_time: currentPublishTimeSeconds,
      }),
    }) as typeof fetch;
    try {
      const pricing = resolveSponsoredExecutionPricingFromEnv({
        SPONSORED_EXECUTION_REAL_PRICING_JSON: JSON.stringify({
          provider: 'outlayer',
          nearRpcUrl: NEAR_RPC_URL,
          oracleContractId: ORACLE_CONTRACT_ID,
          nearUsdPriceId: NEAR_USD_PRICE_ID,
          maxAgeSeconds: 120,
          maxLatestToEmaDeviationBps: 1_000,
          cacheTtlMs: 60_000,
          near: {
            TESTNET: {
              nativeUnitDecimals: 24,
              estimateFeeAmountYocto: '2000',
              pricingVersionPrefix: 'outlayer-near-testnet',
            },
          },
        }),
        SPONSORED_EXECUTION_STATIC_PRICING_JSON: JSON.stringify({
          near: {
            TESTNET: {
              estimateFeeAmountYocto: '2000',
              minorPerFeeUnitNumerator: '100',
              minorPerFeeUnitDenominator: '1000000000000000000000000',
              pricingVersion: 'static-near-testnet-v1',
            },
          },
        }),
      });
      expect(pricing).not.toBeNull();
      const estimated = await pricing!.estimateSponsoredExecutionSpend(nearEstimateInput());
      expect(estimated.pricingVersion).toContain('outlayer-near-testnet');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('rejects invalid non-empty real pricing configuration', () => {
    let thrown: unknown;
    try {
      resolveSponsoredExecutionPricingFromEnv({
        SPONSORED_EXECUTION_REAL_PRICING_JSON: JSON.stringify({
          provider: 'outlayer',
          nearRpcUrl: NEAR_RPC_URL,
          oracleContractId: ORACLE_CONTRACT_ID,
          nearUsdPriceId: NEAR_USD_PRICE_ID,
          maxAgeSeconds: 120,
          maxLatestToEmaDeviationBps: 1_000,
          cacheTtlMs: 60_000,
          near: {
            TESTNET: {
              nativeUnitDecimals: 24,
              estimateFeeAmountYocto: '2000',
            },
          },
        }),
        SPONSORED_EXECUTION_STATIC_PRICING_JSON: JSON.stringify({
          near: {
            TESTNET: {
              estimateFeeAmountYocto: '2000',
              minorPerFeeUnitNumerator: '1',
              minorPerFeeUnitDenominator: '1000',
            },
          },
        }),
      });
    } catch (error: unknown) {
      thrown = error;
    }
    expectPricingError(thrown, 'sponsorship_pricing_invalid');
  });

  test('fails closed for unavailable, stale, and excessive-deviation prices', async () => {
    const unavailable = await captureEstimateError(
      createPricing({
        fetch: createMockFetch({ latest: null }) as typeof fetch,
      }),
    );
    expectPricingError(unavailable, 'sponsorship_pricing_unavailable');

    const stale = await captureEstimateError(
      createPricing({
        fetch: createMockFetch({
          latest: createPythPrice({ publish_time: PUBLISH_TIME_SECONDS - 121 }),
        }) as typeof fetch,
      }),
    );
    expectPricingError(stale, 'sponsorship_pricing_unavailable');

    const staleEma = await captureEstimateError(
      createPricing({
        fetch: createMockFetch({
          ema: createPythPrice({ publish_time: PUBLISH_TIME_SECONDS - 121 }),
        }) as typeof fetch,
      }),
    );
    expectPricingError(staleEma, 'sponsorship_pricing_unavailable');

    const excessiveDeviation = await captureEstimateError(
      createPricing({
        fetch: createMockFetch({
          latest: createPythPrice({ price: 800_000_000 }),
          ema: createPythPrice({ price: 700_000_000 }),
        }) as typeof fetch,
      }),
    );
    expectPricingError(excessiveDeviation, 'sponsorship_pricing_unavailable');
  });

  test('rejects malformed price fields at the RPC boundary', async () => {
    const invalidPrices = [
      createPythPrice({ price: 0 }),
      createPythPrice({ expo: -37 }),
      createPythPrice({ publish_time: 0 }),
      createPythPrice({ publish_time: Math.floor(NOW_MS / 1000) + 31 }),
    ];
    for (const latest of invalidPrices) {
      const thrown = await captureEstimateError(
        createPricing({
          fetch: createMockFetch({ latest }) as typeof fetch,
        }),
      );
      expectPricingError(thrown, 'sponsorship_pricing_invalid');
    }
  });

  test('rejects an unconfigured chain', async () => {
    const thrown = await createPricing()
      .estimateSponsoredExecutionSpend({
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: 'evm_eoa',
        environmentId: 'proj_env:dev',
        policyId: 'policy_gs_onboarding',
        accountRef: 'near:alice.testnet',
        targetRef: 'evm:11155111:0x0000000000000000000000000000000000000001',
        chainId: 11_155_111,
        requestDetails: { call: { gasLimit: '1000000' } },
      })
      .catch((error: unknown) => error);
    expectPricingError(thrown, 'sponsorship_pricing_unavailable');
  });
});
