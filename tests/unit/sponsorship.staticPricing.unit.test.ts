import { expect, test } from '@playwright/test';
import {
  isSponsorshipSpendCapEnforcementError,
  resolveStaticSponsoredExecutionPricingFromEnv,
} from '../../server/src/sponsorship';

function makeStaticPricingEnv(): NodeJS.ProcessEnv {
  return {
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
  } as NodeJS.ProcessEnv;
}

test.describe('static sponsored execution pricing', () => {
  test('estimates and finalizes EVM spend from explicit chain pricing config', async () => {
    const pricing = resolveStaticSponsoredExecutionPricingFromEnv(makeStaticPricingEnv());
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

    const finalized = await pricing!.finalizeSponsoredExecutionSpend({
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
      spendMinor: 2,
      pricingVersion: 'static-tempo-testnet-v1',
    });
  });

  test('returns null for invalid JSON or duplicate normalized chains', async () => {
    const invalidJson = resolveStaticSponsoredExecutionPricingFromEnv({
      SPONSORED_EXECUTION_STATIC_PRICING_JSON: '{invalid-json',
    } as NodeJS.ProcessEnv);
    expect(invalidJson).toBeNull();

    const duplicateChains = resolveStaticSponsoredExecutionPricingFromEnv({
      SPONSORED_EXECUTION_STATIC_PRICING_JSON: JSON.stringify({
        evm: {
          tempo_primary: {
            chainId: 42431,
            estimateFeePerGas: '22000000000',
            minorPerFeeUnitNumerator: '100',
            minorPerFeeUnitDenominator: '1000000000000000000',
          },
          tempo_secondary: {
            chainId: 42431,
            estimateFeePerGas: '22000000000',
            minorPerFeeUnitNumerator: '100',
            minorPerFeeUnitDenominator: '1000000000000000000',
          },
        },
      }),
    } as NodeJS.ProcessEnv);
    expect(duplicateChains).toBeNull();
  });

  test('throws sponsorship_pricing_unavailable when the chain has no pricing row', async () => {
    const pricing = resolveStaticSponsoredExecutionPricingFromEnv(makeStaticPricingEnv());
    expect(pricing).not.toBeNull();

    const thrown = await pricing!
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

  test('throws sponsorship_pricing_invalid for malformed request details', async () => {
    const pricing = resolveStaticSponsoredExecutionPricingFromEnv(makeStaticPricingEnv());
    expect(pricing).not.toBeNull();

    const thrown = await pricing!
      .estimateSponsoredExecutionSpend({
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: 'evm_eoa',
        environmentId: 'proj_env:dev',
        policyId: 'policy_gs_onboarding',
        accountRef: 'near:alice.testnet',
        targetRef: 'evm:42431:0xbb442b54c85efba2d7b81ea52990ad638cdba483',
        chainId: 42_431,
        requestDetails: {},
      })
      .catch((error: unknown) => error);

    expect(isSponsorshipSpendCapEnforcementError(thrown)).toBe(true);
    expect((thrown as { code?: string }).code).toBe('sponsorship_pricing_invalid');
  });
});
