import { expect, test } from '@playwright/test';
import {
  createCoinGeckoSponsoredExecutionPricingService,
  isSponsorshipSpendCapEnforcementError,
  resolveSponsoredExecutionPricingFromEnv,
} from '../../server/src/sponsorship';

function createMockFetch() {
  return async (input: string | URL | Request): Promise<Response> => {
    const url = String(
      typeof input === 'string' || input instanceof URL ? input : input.url,
    );
    if (url.includes('/simple/price')) {
      return new Response(
        JSON.stringify({
          near: {
            usd: 7.25,
            last_updated_at: 1_700_000_000,
          },
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' },
        },
      );
    }
    if (url === 'https://rpc.moderato.tempo.xyz') {
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: '22000000000',
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' },
        },
      );
    }
    throw new Error(`Unexpected fetch URL ${url}`);
  };
}

test.describe('real sponsored execution pricing', () => {
  test('estimates and finalizes EVM spend from CoinGecko market pricing plus RPC gas price', async () => {
    const pricing = createCoinGeckoSponsoredExecutionPricingService(
      {
        apiBaseUrl: 'https://api.coingecko.com/api/v3',
        cacheTtlMs: 60_000,
        evmByChain: new Map([
          [
            42_431,
            {
              chainId: 42_431,
              rpcUrl: 'https://rpc.moderato.tempo.xyz',
              assetId: 'near',
              nativeUnitDecimals: 18,
              pricingVersionPrefix: 'coingecko-tempo-testnet',
            },
          ],
        ]),
      },
      {
        fetch: createMockFetch() as typeof fetch,
        now: () => 1_700_000_100_000,
      },
    );

    const estimated = await pricing.estimateSponsoredExecutionSpend({
      chainFamily: 'evm',
      intentKind: 'evm_call',
      executorKind: 'evm_eoa',
      environmentId: 'proj_env:dev',
      policyId: 'policy_gs_onboarding',
      accountRef: 'near:alice.testnet',
      targetRef: 'evm:42431:0xbb442b54c85efba2d7b81ea52990ad638cdba483',
      chainId: 42_431,
      requestDetails: {
        call: {
          gasLimit: '1000000',
        },
      },
    });
    expect(estimated).toEqual({
      spendMinor: 16,
      pricingVersion: 'coingecko-tempo-testnet:coingecko:near:1700000000',
    });

    const finalized = await pricing.finalizeSponsoredExecutionSpend({
      chainFamily: 'evm',
      intentKind: 'evm_call',
      executorKind: 'evm_eoa',
      environmentId: 'proj_env:dev',
      policyId: 'policy_gs_onboarding',
      accountRef: 'near:alice.testnet',
      targetRef: 'evm:42431:0xbb442b54c85efba2d7b81ea52990ad638cdba483',
      chainId: 42_431,
      txOrExecutionRef: '0x1234',
      receiptStatus: 'success',
      feeUnit: 'wei',
      feeAmount: '15000000000000000',
      requestDetails: {
        call: {
          gasLimit: '1000000',
        },
      },
      estimatedSpendMinor: estimated.spendMinor,
      estimatedPricingVersion: estimated.pricingVersion,
    });
    expect(finalized).toEqual({
      spendMinor: 11,
      pricingVersion: 'coingecko-tempo-testnet:coingecko:near:1700000000',
    });
  });

  test('prefers real pricing over static pricing when both are configured', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = createMockFetch() as typeof fetch;
    try {
      const pricing = resolveSponsoredExecutionPricingFromEnv({
        SPONSORED_EXECUTION_REAL_PRICING_JSON: JSON.stringify({
          provider: 'coingecko',
          evm: {
            42431: {
              rpcUrl: 'https://rpc.moderato.tempo.xyz',
              assetId: 'near',
              pricingVersionPrefix: 'coingecko-tempo-testnet',
            },
          },
        }),
        SPONSORED_EXECUTION_STATIC_PRICING_JSON: JSON.stringify({
          evm: {
            42431: {
              estimateFeePerGas: '22000000000',
              minorPerFeeUnitNumerator: '100',
              minorPerFeeUnitDenominator: '1000000000000000000',
              pricingVersion: 'static-tempo-testnet-v1',
            },
          },
        }),
      } as NodeJS.ProcessEnv);
      expect(pricing).not.toBeNull();

      const estimated = await pricing!.estimateSponsoredExecutionSpend({
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: 'evm_eoa',
        environmentId: 'proj_env:dev',
        policyId: 'policy_gs_onboarding',
        accountRef: 'near:alice.testnet',
        targetRef: 'evm:42431:0xbb442b54c85efba2d7b81ea52990ad638cdba483',
        chainId: 42_431,
        requestDetails: {
          call: {
            gasLimit: '1000000',
          },
        },
      });
      expect(estimated.pricingVersion).toContain('coingecko-tempo-testnet:coingecko:near:1700000000');
      expect(estimated.spendMinor).toBe(16);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('falls back to static pricing when real pricing config is invalid', async () => {
    const pricing = resolveSponsoredExecutionPricingFromEnv({
      SPONSORED_EXECUTION_REAL_PRICING_JSON: '{invalid-json',
      SPONSORED_EXECUTION_STATIC_PRICING_JSON: JSON.stringify({
        evm: {
          42431: {
            estimateFeePerGas: '22000000000',
            minorPerFeeUnitNumerator: '100',
            minorPerFeeUnitDenominator: '1000000000000000000',
            pricingVersion: 'static-tempo-testnet-v1',
          },
        },
      }),
    } as NodeJS.ProcessEnv);
    expect(pricing).not.toBeNull();

    const estimated = await pricing!.estimateSponsoredExecutionSpend({
      chainFamily: 'evm',
      intentKind: 'evm_call',
      executorKind: 'evm_eoa',
      environmentId: 'proj_env:dev',
      policyId: 'policy_gs_onboarding',
      accountRef: 'near:alice.testnet',
      targetRef: 'evm:42431:0xbb442b54c85efba2d7b81ea52990ad638cdba483',
      chainId: 42_431,
      requestDetails: {
        call: {
          gasLimit: '1000000',
        },
      },
    });
    expect(estimated).toEqual({
      spendMinor: 3,
      pricingVersion: 'static-tempo-testnet-v1',
    });
  });

  test('throws sponsorship_pricing_unavailable for real pricing on an unconfigured chain', async () => {
    const pricing = createCoinGeckoSponsoredExecutionPricingService(
      {
        apiBaseUrl: 'https://api.coingecko.com/api/v3',
        cacheTtlMs: 60_000,
        evmByChain: new Map(),
      },
      {
        fetch: createMockFetch() as typeof fetch,
      },
    );

    const thrown = await pricing
      .estimateSponsoredExecutionSpend({
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: 'evm_eoa',
        environmentId: 'proj_env:dev',
        policyId: 'policy_gs_onboarding',
        accountRef: 'near:alice.testnet',
        targetRef: 'evm:11155111:0x0000000000000000000000000000000000000001',
        chainId: 11_155_111,
        requestDetails: {
          call: {
            gasLimit: '1000000',
          },
        },
      })
      .catch((error: unknown) => error);

    expect(isSponsorshipSpendCapEnforcementError(thrown)).toBe(true);
    expect((thrown as { code?: string }).code).toBe('sponsorship_pricing_unavailable');
  });
});
