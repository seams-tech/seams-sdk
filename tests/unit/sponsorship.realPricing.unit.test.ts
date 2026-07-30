import { expect, test } from '@playwright/test';
import { getNearSpendCapChainId } from '@seams-internal/console-shared/gasSponsorshipSpendCapTargets';
import {
  createRefFinanceSponsoredExecutionPricingService,
  isSponsorshipSpendCapEnforcementError,
  resolveSponsoredExecutionPricingFromEnv,
} from '../../packages/console-server-ts/src/sponsorship';

const NEAR_RPC_URL = 'https://free.rpc.fastnear.com';
const EVM_RPC_URL = 'https://rpc.moderato.tempo.xyz';
const DEX_CONTRACT_ID = 'v2.ref-finance.near';
const NEAR_TOKEN_ID = 'wrap.near';
const USDC_TOKEN_ID = 'native-usdc.near';

function encodeJsonBytes(value: unknown): number[] {
  return Array.from(new TextEncoder().encode(JSON.stringify(value)));
}

function createMockFetch(captures?: { nearRpcCalls: number }) {
  return async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(typeof input === 'string' || input instanceof URL ? input : input.url);
    const request = JSON.parse(String(init?.body || '{}')) as {
      method?: string;
      params?: { account_id?: string; method_name?: string };
    };
    if (url === NEAR_RPC_URL && request.method === 'query') {
      if (captures) captures.nearRpcCalls += 1;
      expect(request.params).toMatchObject({
        account_id: DEX_CONTRACT_ID,
        method_name: 'get_pool',
      });
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: {
          block_height: 209_153_568,
          result: encodeJsonBytes({
            pool_kind: 'SIMPLE_POOL',
            token_account_ids: [USDC_TOKEN_ID, NEAR_TOKEN_ID],
            amounts: ['7250000', '1000000000000000000000000'],
          }),
        },
      });
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

function createPricing(options?: {
  fetch?: typeof fetch;
  now?: () => number;
}) {
  return createRefFinanceSponsoredExecutionPricingService(
    {
      nearRpcUrl: NEAR_RPC_URL,
      dexContractId: DEX_CONTRACT_ID,
      poolId: 4512,
      nearTokenId: NEAR_TOKEN_ID,
      usdcTokenId: USDC_TOKEN_ID,
      nearTokenDecimals: 24,
      usdcTokenDecimals: 6,
      cacheTtlMs: 60_000,
      evmByChain: new Map([
        [
          42_431,
          {
            chainId: 42_431,
            rpcUrl: EVM_RPC_URL,
            nativeUnitDecimals: 18,
            pricingVersionPrefix: 'ref-finance-tempo-testnet',
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
            pricingVersionPrefix: 'ref-finance-near-testnet',
          },
        ],
      ]),
    },
    {
      fetch: options?.fetch || (createMockFetch() as typeof fetch),
      now: options?.now || (() => 1_700_000_100_000),
    },
  );
}

test.describe('Ref Finance sponsored execution pricing', () => {
  test('estimates and finalizes NEAR spend from the on-chain NEAR/USDC pool', async () => {
    const pricing = createPricing();
    const estimated = await pricing.estimateSponsoredExecutionSpend({
      chainFamily: 'near',
      intentKind: 'near_delegate',
      executorKind: 'near_delegate',
      environmentId: 'proj_env:dev',
      policyId: 'policy_gs_near',
      accountRef: 'near:alice.testnet',
      targetRef: 'near:guest-book.testnet',
      chainId: getNearSpendCapChainId('TESTNET'),
      requestDetails: { receiverId: 'guest-book.testnet' },
    });
    expect(estimated).toEqual({
      spendMinor: 1,
      pricingVersion:
        'ref-finance-near-testnet:ref-finance:v2.ref-finance.near:pool-4512:block-209153568',
    });

    const finalized = await pricing.finalizeSponsoredExecutionSpend({
      chainFamily: 'near',
      intentKind: 'near_delegate',
      executorKind: 'near_delegate',
      environmentId: 'proj_env:dev',
      policyId: 'policy_gs_near',
      accountRef: 'near:alice.testnet',
      targetRef: 'near:guest-book.testnet',
      chainId: getNearSpendCapChainId('TESTNET'),
      txOrExecutionRef: 'delegate-tx-123',
      receiptStatus: 'success',
      feeUnit: 'yocto_near',
      feeAmount: '1500',
      requestDetails: { receiverId: 'guest-book.testnet' },
      estimatedSpendMinor: estimated.spendMinor,
      estimatedPricingVersion: estimated.pricingVersion,
    });
    expect(finalized).toEqual({
      spendMinor: 1,
      pricingVersion: estimated.pricingVersion,
    });
  });

  test('combines EVM gas price with the on-chain NEAR/USDC price', async () => {
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
      'ref-finance-tempo-testnet:ref-finance:v2.ref-finance.near:pool-4512',
    );
  });

  test('caches the pool quote for the configured TTL', async () => {
    const captures = { nearRpcCalls: 0 };
    const pricing = createPricing({
      fetch: createMockFetch(captures) as typeof fetch,
    });
    const input = {
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
    await pricing.estimateSponsoredExecutionSpend(input);
    await pricing.estimateSponsoredExecutionSpend(input);
    expect(captures.nearRpcCalls).toBe(1);
  });

  test('prefers Ref Finance pricing over static pricing', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = createMockFetch() as typeof fetch;
    try {
      const pricing = resolveSponsoredExecutionPricingFromEnv({
        SPONSORED_EXECUTION_REAL_PRICING_JSON: JSON.stringify({
          provider: 'ref_finance',
          nearRpcUrl: NEAR_RPC_URL,
          dexContractId: DEX_CONTRACT_ID,
          poolId: 4512,
          nearTokenId: NEAR_TOKEN_ID,
          usdcTokenId: USDC_TOKEN_ID,
          nearTokenDecimals: 24,
          usdcTokenDecimals: 6,
          near: {
            TESTNET: {
              nativeUnitDecimals: 24,
              estimateFeeAmountYocto: '2000',
              pricingVersionPrefix: 'ref-finance-near-testnet',
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
      const estimated = await pricing!.estimateSponsoredExecutionSpend({
        chainFamily: 'near',
        intentKind: 'near_delegate',
        executorKind: 'near_delegate',
        environmentId: 'proj_env:dev',
        policyId: 'policy_gs_near',
        accountRef: 'near:alice.testnet',
        targetRef: 'near:guest-book.testnet',
        chainId: getNearSpendCapChainId('TESTNET'),
        requestDetails: { receiverId: 'guest-book.testnet' },
      });
      expect(estimated.pricingVersion).toContain('ref-finance-near-testnet');
    } finally {
      globalThis.fetch = originalFetch;
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
    expect(isSponsorshipSpendCapEnforcementError(thrown)).toBe(true);
    expect((thrown as { code?: string }).code).toBe('sponsorship_pricing_unavailable');
  });
});
