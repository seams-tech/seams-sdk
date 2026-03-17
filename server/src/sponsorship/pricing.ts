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

type CoinGeckoSponsoredEvmSpendPricingRule = {
  chainId: number;
  rpcUrl: string;
  assetId: string;
  nativeUnitDecimals: number;
  pricingVersionPrefix: string;
};

type CoinGeckoMarketPriceCacheEntry = {
  spendMinorNumerator: bigint;
  spendMinorDenominator: bigint;
  pricingVersion: string;
  expiresAtMs: number;
};

type DecimalRatio = {
  numerator: bigint;
  denominator: bigint;
};

export interface StaticSponsoredExecutionPricingConfig {
  evmByChain: ReadonlyMap<number, StaticSponsoredEvmSpendPricingRule>;
}

export interface CoinGeckoSponsoredExecutionPricingConfig {
  apiBaseUrl: string;
  cacheTtlMs: number;
  evmByChain: ReadonlyMap<number, CoinGeckoSponsoredEvmSpendPricingRule>;
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

function normalizePricingVersion(value: unknown, fallback: string): string {
  const normalized = String(value || '').trim();
  return normalized || fallback;
}

function extractGasLimitForEvmEstimate(requestDetails: Record<string, unknown>): bigint {
  const call = requireRecord(requestDetails.call, 'requestDetails.call');
  return requireNonNegativeBigInt(call.gasLimit, 'requestDetails.call.gasLimit');
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

function normalizeUrlPath(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

function normalizeApiBaseUrl(value: unknown, fallback: string): string {
  const normalized = normalizeUrlPath(String(value || '').trim() || fallback);
  try {
    return normalizeUrlPath(new URL(normalized).toString());
  } catch {
    return normalizeUrlPath(fallback);
  }
}

function readCacheTtlMs(value: unknown, fallback: number): number {
  const parsed = parseOptionalPositiveInteger(value);
  return parsed && parsed > 0 ? parsed : fallback;
}

function readNativeUnitDecimals(value: unknown, fallback: number): number {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 36) return fallback;
  return parsed;
}

function normalizeDecimalString(value: string): string {
  const [wholeRaw, fractionRaw = ''] = value.split('.');
  const whole = wholeRaw.replace(/^(-?)0+(?=\d)/, '$1') || '0';
  const fraction = fractionRaw.replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : whole;
}

function parseDecimalRatio(value: unknown, label: string): DecimalRatio {
  let normalized = '';
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value < 0) {
      throw new SponsorshipSpendCapEnforcementError(
        'sponsorship_pricing_invalid',
        500,
        `${label} must be a non-negative number`,
      );
    }
    normalized = value.toString().includes('e') ? value.toFixed(18) : value.toString();
  } else {
    normalized = String(value || '').trim();
  }
  normalized = normalizeDecimalString(normalized);
  if (!/^\d+(?:\.\d+)?$/.test(normalized)) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${label} must be a non-negative decimal`,
    );
  }
  const [wholeRaw, fractionRaw = ''] = normalized.split('.');
  const fraction = fractionRaw.replace(/0+$/, '');
  const denominator = 10n ** BigInt(fraction.length);
  const numerator = BigInt(wholeRaw) * denominator + BigInt(fraction || '0');
  return {
    numerator,
    denominator,
  };
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

function resolveCoinGeckoEvmPricingRule(
  config: CoinGeckoSponsoredExecutionPricingConfig,
  chainId: number,
): CoinGeckoSponsoredEvmSpendPricingRule {
  const rule = config.evmByChain.get(chainId) || null;
  if (rule) return rule;
  throw new SponsorshipSpendCapEnforcementError(
    'sponsorship_pricing_unavailable',
    503,
    `Real sponsored spend pricing is not configured for EVM chain ${chainId}`,
  );
}

async function fetchJsonRpcResult(
  rpcUrl: string,
  method: string,
  params: unknown[],
  fetchImpl: typeof fetch,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method,
        params,
      }),
    });
  } catch (error: unknown) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      `Failed to query pricing RPC ${rpcUrl}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (!response.ok) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      `Pricing RPC ${rpcUrl} returned ${response.status}`,
    );
  }
  const payload = requireRecord(await response.json(), 'pricing RPC response');
  if (payload.error) {
    const errorRecord = requireRecord(payload.error, 'pricing RPC response.error');
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      String(errorRecord.message || `Pricing RPC ${rpcUrl} rejected ${method}`),
      {
        code: errorRecord.code,
      },
    );
  }
  return payload.result;
}

async function fetchCoinGeckoUsdPrice(input: {
  apiBaseUrl: string;
  assetId: string;
  fetchImpl: typeof fetch;
}): Promise<{ spendMinorRatio: DecimalRatio; pricingVersion: string }> {
  const url = new URL(`${input.apiBaseUrl}/simple/price`);
  url.searchParams.set('ids', input.assetId);
  url.searchParams.set('vs_currencies', 'usd');
  url.searchParams.set('include_last_updated_at', 'true');
  let response: Response;
  try {
    response = await input.fetchImpl(url.toString());
  } catch (error: unknown) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      `Failed to query CoinGecko pricing: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (!response.ok) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      `CoinGecko pricing returned ${response.status}`,
    );
  }
  const payload = requireRecord(await response.json(), 'CoinGecko pricing response');
  const asset = requireRecord(payload[input.assetId], `CoinGecko pricing response.${input.assetId}`);
  const usdRatio = parseDecimalRatio(asset.usd, `CoinGecko usd price for ${input.assetId}`);
  const spendMinorRatio = {
    numerator: usdRatio.numerator * 100n,
    denominator: usdRatio.denominator,
  };
  return {
    spendMinorRatio,
    pricingVersion: `coingecko:${input.assetId}:${String(asset.last_updated_at || 'unknown')}`,
  };
}

function quoteFromCoinGeckoRule(input: {
  feeAmount: bigint;
  nativeUnitDecimals: number;
  spendMinorRatio: DecimalRatio;
  pricingVersion: string;
}): SponsorshipSpendPricingQuote {
  return {
    spendMinor: computeQuotedSpendMinor({
      feeAmount: input.feeAmount,
      numerator: input.spendMinorRatio.numerator,
      denominator: (10n ** BigInt(input.nativeUnitDecimals)) * input.spendMinorRatio.denominator,
    }),
    pricingVersion: input.pricingVersion,
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

export function createCoinGeckoSponsoredExecutionPricingService(
  config: CoinGeckoSponsoredExecutionPricingConfig,
  options?: {
    fetch?: typeof fetch;
    now?: () => number;
  },
): SponsorshipSpendPricingService {
  const fetchImpl = options?.fetch || fetch;
  const now = options?.now || (() => Date.now());
  const marketPriceCache = new Map<string, CoinGeckoMarketPriceCacheEntry>();

  const resolveMarketPrice = async (
    assetId: string,
  ): Promise<{
    spendMinorRatio: DecimalRatio;
    pricingVersion: string;
  }> => {
    const cached = marketPriceCache.get(assetId) || null;
    const currentMs = now();
    if (cached && cached.expiresAtMs > currentMs) {
      return {
        spendMinorRatio: {
          numerator: cached.spendMinorNumerator,
          denominator: cached.spendMinorDenominator,
        },
        pricingVersion: cached.pricingVersion,
      };
    }
    const fetched = await fetchCoinGeckoUsdPrice({
      apiBaseUrl: config.apiBaseUrl,
      assetId,
      fetchImpl,
    });
    marketPriceCache.set(assetId, {
      spendMinorNumerator: fetched.spendMinorRatio.numerator,
      spendMinorDenominator: fetched.spendMinorRatio.denominator,
      pricingVersion: fetched.pricingVersion,
      expiresAtMs: currentMs + config.cacheTtlMs,
    });
    return fetched;
  };

  return {
    async estimateSponsoredExecutionSpend(
      input: SponsorshipSpendPricingEstimateInput,
    ): Promise<SponsorshipSpendPricingQuote> {
      if (input.chainFamily !== 'evm') {
        throw new SponsorshipSpendCapEnforcementError(
          'sponsorship_pricing_unavailable',
          503,
          `Real sponsored spend pricing does not support ${input.chainFamily}`,
        );
      }
      const rule = resolveCoinGeckoEvmPricingRule(config, input.chainId);
      const gasLimit = extractGasLimitForEvmEstimate(input.requestDetails);
      const gasPriceHex = await fetchJsonRpcResult(rule.rpcUrl, 'eth_gasPrice', [], fetchImpl);
      const gasPriceWei = requireNonNegativeBigInt(gasPriceHex, 'pricing RPC eth_gasPrice result');
      const marketPrice = await resolveMarketPrice(rule.assetId);
      return quoteFromCoinGeckoRule({
        feeAmount: gasLimit * gasPriceWei,
        nativeUnitDecimals: rule.nativeUnitDecimals,
        spendMinorRatio: marketPrice.spendMinorRatio,
        pricingVersion: `${rule.pricingVersionPrefix}:${marketPrice.pricingVersion}`,
      });
    },

    async finalizeSponsoredExecutionSpend(
      input: SponsorshipSpendPricingFinalizeInput,
    ): Promise<SponsorshipSpendPricingQuote> {
      if (input.chainFamily !== 'evm') {
        throw new SponsorshipSpendCapEnforcementError(
          'sponsorship_pricing_unavailable',
          503,
          `Real sponsored spend pricing does not support ${input.chainFamily}`,
        );
      }
      if (input.feeUnit !== 'wei') {
        throw new SponsorshipSpendCapEnforcementError(
          'sponsorship_pricing_invalid',
          500,
          `Real sponsored spend pricing expected feeUnit wei, received ${input.feeUnit}`,
        );
      }
      const rule = resolveCoinGeckoEvmPricingRule(config, input.chainId);
      const marketPrice = await resolveMarketPrice(rule.assetId);
      return quoteFromCoinGeckoRule({
        feeAmount: requireNonNegativeBigInt(input.feeAmount, 'feeAmount'),
        nativeUnitDecimals: rule.nativeUnitDecimals,
        spendMinorRatio: marketPrice.spendMinorRatio,
        pricingVersion: `${rule.pricingVersionPrefix}:${marketPrice.pricingVersion}`,
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

export function resolveCoinGeckoSponsoredExecutionPricingFromEnv(
  env: NodeJS.ProcessEnv,
): SponsorshipSpendPricingService | null {
  const raw = String(env.SPONSORED_EXECUTION_REAL_PRICING_JSON || '').trim();
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const root = parsed as Record<string, unknown>;
  const provider = String(root.provider || 'coingecko').trim().toLowerCase();
  if (provider !== 'coingecko') return null;
  const evmSection = root.evm;
  if (!evmSection || typeof evmSection !== 'object' || Array.isArray(evmSection)) return null;

  const evmByChain = new Map<number, CoinGeckoSponsoredEvmSpendPricingRule>();
  for (const [chainIdRaw, value] of Object.entries(evmSection as Record<string, unknown>)) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
    const row = value as Record<string, unknown>;
    const chainId =
      parseOptionalPositiveInteger(chainIdRaw) ||
      parseOptionalPositiveInteger(row.chainId) ||
      undefined;
    const rpcUrl = String(row.rpcUrl || '').trim();
    const assetId = String(row.assetId || '').trim().toLowerCase();
    if (!chainId || !rpcUrl || !assetId) continue;
    if (evmByChain.has(chainId)) return null;
    evmByChain.set(chainId, {
      chainId,
      rpcUrl,
      assetId,
      nativeUnitDecimals: readNativeUnitDecimals(row.nativeUnitDecimals, 18),
      pricingVersionPrefix: normalizePricingVersion(
        row.pricingVersionPrefix,
        `coingecko-evm-${chainId}`,
      ),
    });
  }

  if (evmByChain.size === 0) return null;
  return createCoinGeckoSponsoredExecutionPricingService({
    apiBaseUrl: normalizeApiBaseUrl(root.apiBaseUrl, 'https://api.coingecko.com/api/v3'),
    cacheTtlMs: readCacheTtlMs(root.cacheTtlMs, 5 * 60 * 1000),
    evmByChain,
  });
}

export function resolveSponsoredExecutionPricingFromEnv(
  env: NodeJS.ProcessEnv,
): SponsorshipSpendPricingService | null {
  return (
    resolveCoinGeckoSponsoredExecutionPricingFromEnv(env) ||
    resolveStaticSponsoredExecutionPricingFromEnv(env)
  );
}
