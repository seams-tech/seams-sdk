import { parseOptionalPositiveInteger } from './evm';
import type {
  SponsorshipSpendPricingEstimateInput,
  SponsorshipSpendPricingFinalizeInput,
  SponsorshipSpendPricingQuote,
  SponsorshipSpendPricingService,
} from './spendCaps';
import { SponsorshipSpendCapEnforcementError } from './spendCaps';

type StaticSponsoredEvmSpendPricingRule = {
  chainId: number;
  estimateFeePerGas: bigint;
  minorPerFeeUnitNumerator: bigint;
  minorPerFeeUnitDenominator: bigint;
  pricingVersion: string;
};

export interface StaticSponsoredExecutionPricingConfig {
  evmByChain: ReadonlyMap<number, StaticSponsoredEvmSpendPricingRule>;
}

function parseOptionalBigIntLiteral(
  value: unknown,
  options?: { allowZero?: boolean },
): bigint | null {
  if (value === undefined || value === null) return null;
  const normalized = String(value).trim();
  if (!normalized) return null;
  try {
    const parsed = BigInt(normalized);
    if (parsed < 0n) return null;
    if (parsed === 0n && !options?.allowZero) return null;
    return parsed;
  } catch {
    return null;
  }
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${label} must be an object`,
    );
  }
  return value as Record<string, unknown>;
}

function requireNonNegativeBigInt(value: unknown, label: string): bigint {
  const parsed = parseOptionalBigIntLiteral(value, { allowZero: true });
  if (parsed === null) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${label} must be a non-negative integer`,
    );
  }
  return parsed;
}

function ceilDivide(numerator: bigint, denominator: bigint): bigint {
  if (numerator <= 0n) return 0n;
  return (numerator + denominator - 1n) / denominator;
}

function toSafeInteger(value: bigint, label: string): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${label} exceeds Number.MAX_SAFE_INTEGER`,
    );
  }
  return Number(value);
}

function resolveStaticEvmPricingRule(
  config: StaticSponsoredExecutionPricingConfig,
  chainId: number,
): StaticSponsoredEvmSpendPricingRule {
  const rule = config.evmByChain.get(chainId) || null;
  if (rule) return rule;
  throw new SponsorshipSpendCapEnforcementError(
    'sponsorship_pricing_unavailable',
    503,
    `Sponsored spend pricing is not configured for EVM chain ${chainId}`,
  );
}

function computeQuotedSpendMinor(input: {
  feeAmount: bigint;
  numerator: bigint;
  denominator: bigint;
}): number {
  return toSafeInteger(
    ceilDivide(input.feeAmount * input.numerator, input.denominator),
    'quoted spendMinor',
  );
}

function normalizePricingVersion(value: unknown, fallback: string): string {
  const normalized = String(value || '').trim();
  return normalized || fallback;
}

function extractGasLimitForEvmEstimate(requestDetails: Record<string, unknown>): bigint {
  const call = requireRecord(requestDetails.call, 'requestDetails.call');
  return requireNonNegativeBigInt(call.gasLimit, 'requestDetails.call.gasLimit');
}

function quoteFromRule(input: {
  rule: StaticSponsoredEvmSpendPricingRule;
  feeAmount: bigint;
}): SponsorshipSpendPricingQuote {
  return {
    spendMinor: computeQuotedSpendMinor({
      feeAmount: input.feeAmount,
      numerator: input.rule.minorPerFeeUnitNumerator,
      denominator: input.rule.minorPerFeeUnitDenominator,
    }),
    pricingVersion: input.rule.pricingVersion,
  };
}

export function createStaticSponsoredExecutionPricingService(
  config: StaticSponsoredExecutionPricingConfig,
): SponsorshipSpendPricingService {
  return {
    async estimateSponsoredExecutionSpend(
      input: SponsorshipSpendPricingEstimateInput,
    ): Promise<SponsorshipSpendPricingQuote> {
      if (input.chainFamily !== 'evm') {
        throw new SponsorshipSpendCapEnforcementError(
          'sponsorship_pricing_unavailable',
          503,
          `Static sponsored spend pricing does not support ${input.chainFamily}`,
        );
      }
      const rule = resolveStaticEvmPricingRule(config, input.chainId);
      const gasLimit = extractGasLimitForEvmEstimate(input.requestDetails);
      return quoteFromRule({
        rule,
        feeAmount: gasLimit * rule.estimateFeePerGas,
      });
    },

    async finalizeSponsoredExecutionSpend(
      input: SponsorshipSpendPricingFinalizeInput,
    ): Promise<SponsorshipSpendPricingQuote> {
      if (input.chainFamily !== 'evm') {
        throw new SponsorshipSpendCapEnforcementError(
          'sponsorship_pricing_unavailable',
          503,
          `Static sponsored spend pricing does not support ${input.chainFamily}`,
        );
      }
      if (input.feeUnit !== 'wei') {
        throw new SponsorshipSpendCapEnforcementError(
          'sponsorship_pricing_invalid',
          500,
          `Static sponsored spend pricing expected feeUnit wei, received ${input.feeUnit}`,
        );
      }
      const rule = resolveStaticEvmPricingRule(config, input.chainId);
      return quoteFromRule({
        rule,
        feeAmount: requireNonNegativeBigInt(input.feeAmount, 'feeAmount'),
      });
    },
  };
}

export function resolveStaticSponsoredExecutionPricingFromEnv(
  env: NodeJS.ProcessEnv,
): SponsorshipSpendPricingService | null {
  const raw = String(env.SPONSORED_EXECUTION_STATIC_PRICING_JSON || '').trim();
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;

  const evmSection = (parsed as Record<string, unknown>).evm;
  if (!evmSection || typeof evmSection !== 'object' || Array.isArray(evmSection)) return null;

  const evmByChain = new Map<number, StaticSponsoredEvmSpendPricingRule>();
  for (const [chainIdRaw, value] of Object.entries(evmSection as Record<string, unknown>)) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
    const row = value as Record<string, unknown>;
    const chainId =
      parseOptionalPositiveInteger(chainIdRaw) ||
      parseOptionalPositiveInteger(row.chainId) ||
      undefined;
    const estimateFeePerGas = parseOptionalBigIntLiteral(row.estimateFeePerGas, {
      allowZero: true,
    });
    const minorPerFeeUnitNumerator = parseOptionalBigIntLiteral(row.minorPerFeeUnitNumerator);
    const minorPerFeeUnitDenominator = parseOptionalBigIntLiteral(row.minorPerFeeUnitDenominator);
    if (
      !chainId ||
      estimateFeePerGas === null ||
      minorPerFeeUnitNumerator === null ||
      minorPerFeeUnitDenominator === null
    ) {
      continue;
    }
    if (evmByChain.has(chainId)) return null;
    evmByChain.set(chainId, {
      chainId,
      estimateFeePerGas,
      minorPerFeeUnitNumerator,
      minorPerFeeUnitDenominator,
      pricingVersion: normalizePricingVersion(row.pricingVersion, `static-evm-${chainId}-v1`),
    });
  }

  if (evmByChain.size === 0) return null;
  return createStaticSponsoredExecutionPricingService({
    evmByChain,
  });
}
