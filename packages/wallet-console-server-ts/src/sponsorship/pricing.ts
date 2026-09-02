import { parseOptionalPositiveInteger } from './evm';
import { getNearSpendCapChainId } from '@seams-internal/wallet-console-shared/gasSponsorshipSpendCapTargets';
import type {
  SponsorshipSpendPricingEstimateInput,
  SponsorshipSpendPricingFinalizeInput,
  SponsorshipSpendPricingQuote,
  SponsorshipSpendPricingService,
} from './spendCaps';
import { SponsorshipSpendCapEnforcementError } from './spendCaps';
import type { ConsoleSponsoredCallChainFamily } from '../sponsoredCalls/types';

type StaticSponsoredEvmSpendPricingRule = {
  chainId: number;
  estimateFeePerGas: bigint;
  minorPerFeeUnitNumerator: bigint;
  minorPerFeeUnitDenominator: bigint;
  pricingVersion: string;
};

type StaticSponsoredNearSpendPricingRule = {
  networkClass: 'TESTNET' | 'MAINNET';
  estimateFeeAmountYocto: bigint;
  minorPerFeeUnitNumerator: bigint;
  minorPerFeeUnitDenominator: bigint;
  pricingVersion: string;
};

type OutlayerSponsoredEvmSpendPricingRule = {
  chainId: number;
  rpcUrl: string;
  nativeUnitDecimals: number;
  pricingVersionPrefix: string;
};

type OutlayerSponsoredNearSpendPricingRule = {
  networkClass: 'TESTNET' | 'MAINNET';
  nativeUnitDecimals: number;
  estimateFeeAmountYocto: bigint;
  pricingVersionPrefix: string;
};

type OutlayerMarketPriceCacheEntry = {
  spendMinorNumerator: bigint;
  spendMinorDenominator: bigint;
  pricingVersion: string;
  expiresAtMs: number;
};

type DecimalRatio = {
  numerator: bigint;
  denominator: bigint;
};

function resolveSponsorshipPricingFetch(input?: typeof fetch): typeof fetch {
  if (input) return input;
  if (typeof globalThis.fetch !== 'function') {
    throw new Error('fetch is not available for sponsored execution pricing');
  }
  return globalThis.fetch.bind(globalThis) as typeof fetch;
}

export interface StaticSponsoredExecutionPricingConfig {
  evmByChain: ReadonlyMap<number, StaticSponsoredEvmSpendPricingRule>;
  nearByChain: ReadonlyMap<number, StaticSponsoredNearSpendPricingRule>;
}

export interface OutlayerSponsoredExecutionPricingConfig {
  nearRpcUrl: string;
  oracleContractId: string;
  nearUsdPriceId: string;
  maxAgeSeconds: number;
  maxLatestToEmaDeviationBps: number;
  cacheTtlMs: number;
  evmByChain: ReadonlyMap<number, OutlayerSponsoredEvmSpendPricingRule>;
  nearByChain: ReadonlyMap<number, OutlayerSponsoredNearSpendPricingRule>;
}

export interface ChainFamilySponsoredExecutionPricingConfig {
  readonly evm: SponsorshipSpendPricingService;
  readonly near: SponsorshipSpendPricingService;
}

export interface SponsoredExecutionPricingEnv {
  readonly SPONSORED_EXECUTION_REAL_PRICING_JSON?: string;
  readonly SPONSORED_EXECUTION_STATIC_PRICING_JSON?: string;
}

const pricingServiceByEnv = new WeakMap<object, SponsorshipSpendPricingService | null>();

function assertNeverChainFamily(chainFamily: never): never {
  throw new Error(`Unsupported sponsored call chain family: ${String(chainFamily)}`);
}

class ChainFamilySponsoredExecutionPricingService implements SponsorshipSpendPricingService {
  constructor(private readonly config: ChainFamilySponsoredExecutionPricingConfig) {}

  async estimateSponsoredExecutionSpend(
    input: SponsorshipSpendPricingEstimateInput,
  ): Promise<SponsorshipSpendPricingQuote> {
    return await this.resolve(input.chainFamily).estimateSponsoredExecutionSpend(input);
  }

  async finalizeSponsoredExecutionSpend(
    input: SponsorshipSpendPricingFinalizeInput,
  ): Promise<SponsorshipSpendPricingQuote> {
    return await this.resolve(input.chainFamily).finalizeSponsoredExecutionSpend(input);
  }

  private resolve(chainFamily: ConsoleSponsoredCallChainFamily): SponsorshipSpendPricingService {
    switch (chainFamily) {
      case 'evm':
        return this.config.evm;
      case 'near':
        return this.config.near;
      default:
        return assertNeverChainFamily(chainFamily);
    }
  }
}

export function createChainFamilySponsoredExecutionPricingService(
  config: ChainFamilySponsoredExecutionPricingConfig,
): SponsorshipSpendPricingService {
  return new ChainFamilySponsoredExecutionPricingService(config);
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

function quoteFromStaticNearRule(input: {
  rule: StaticSponsoredNearSpendPricingRule;
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

function resolveStaticNearPricingRule(
  config: StaticSponsoredExecutionPricingConfig,
  chainId: number,
): StaticSponsoredNearSpendPricingRule {
  const rule = config.nearByChain.get(chainId) || null;
  if (rule) return rule;
  throw new SponsorshipSpendCapEnforcementError(
    'sponsorship_pricing_unavailable',
    503,
    `Sponsored spend pricing is not configured for NEAR target ${chainId}`,
  );
}

function resolveOutlayerEvmPricingRule(
  config: OutlayerSponsoredExecutionPricingConfig,
  chainId: number,
): OutlayerSponsoredEvmSpendPricingRule {
  const rule = config.evmByChain.get(chainId) || null;
  if (rule) return rule;
  throw new SponsorshipSpendCapEnforcementError(
    'sponsorship_pricing_unavailable',
    503,
    `Real sponsored spend pricing is not configured for EVM chain ${chainId}`,
  );
}

function resolveOutlayerNearPricingRule(
  config: OutlayerSponsoredExecutionPricingConfig,
  chainId: number,
): OutlayerSponsoredNearSpendPricingRule {
  const rule = config.nearByChain.get(chainId) || null;
  if (rule) return rule;
  throw new SponsorshipSpendCapEnforcementError(
    'sponsorship_pricing_unavailable',
    503,
    `Real sponsored spend pricing is not configured for NEAR target ${chainId}`,
  );
}

async function fetchJsonRpcResult(
  rpcUrl: string,
  method: string,
  params: unknown,
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

function requireSafeInteger(value: unknown, label: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${label} must be a safe integer`,
    );
  }
  return parsed;
}

function encodeJsonBase64(value: unknown): string {
  return btoa(JSON.stringify(value));
}

function parseNearContractJsonResult(input: { result: unknown; label: string }): unknown {
  const queryResult = requireRecord(input.result, `${input.label} RPC query result`);
  if (queryResult.error) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      `${input.label} contract call failed: ${String(queryResult.error)}`,
    );
  }
  if (!Array.isArray(queryResult.result)) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${input.label} RPC query result.result must be a byte array`,
    );
  }
  const bytes = queryResult.result.map((value, index) => {
    const byte = Number(value);
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new SponsorshipSpendCapEnforcementError(
        'sponsorship_pricing_invalid',
        500,
        `${input.label} RPC query result.result[${index}] must be a byte`,
      );
    }
    return byte;
  });
  try {
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(bytes)));
  } catch (error: unknown) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${input.label} response is invalid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

type ParsedOutlayerPrice = {
  ratio: DecimalRatio;
  publishTimeSeconds: number;
};

function parseOutlayerPrice(input: {
  value: unknown;
  label: string;
  nowMs: number;
  maxAgeSeconds: number;
}): ParsedOutlayerPrice {
  if (input.value === null || input.value === undefined) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      `${input.label} is unavailable`,
    );
  }
  const price = requireRecord(input.value, input.label);
  const priceValue = requireSafeInteger(price.price, `${input.label}.price`);
  if (priceValue <= 0) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${input.label}.price must be positive`,
    );
  }
  const exponent = requireSafeInteger(price.expo, `${input.label}.expo`);
  if (exponent < -36 || exponent > 36) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${input.label}.expo must be between -36 and 36`,
    );
  }
  const publishTimeSeconds = requireSafeInteger(price.publish_time, `${input.label}.publish_time`);
  if (publishTimeSeconds <= 0) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${input.label}.publish_time must be positive`,
    );
  }
  const ageMs = input.nowMs - publishTimeSeconds * 1000;
  if (ageMs < -30_000) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${input.label}.publish_time is in the future`,
    );
  }
  if (ageMs > input.maxAgeSeconds * 1000) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      `${input.label} is stale`,
    );
  }
  const scale = 10n ** BigInt(Math.abs(exponent));
  const unsignedPrice = BigInt(priceValue);
  return {
    ratio:
      exponent >= 0
        ? {
            numerator: unsignedPrice * 100n * scale,
            denominator: 1n,
          }
        : {
            numerator: unsignedPrice * 100n,
            denominator: scale,
          },
    publishTimeSeconds,
  };
}

function assertLatestWithinEmaDeviation(input: {
  latest: DecimalRatio;
  ema: DecimalRatio;
  maxDeviationBps: number;
}): void {
  const latestScaled = input.latest.numerator * input.ema.denominator;
  const emaScaled = input.ema.numerator * input.latest.denominator;
  const difference =
    latestScaled >= emaScaled ? latestScaled - emaScaled : emaScaled - latestScaled;
  if (difference * 10_000n <= emaScaled * BigInt(input.maxDeviationBps)) return;
  throw new SponsorshipSpendCapEnforcementError(
    'sponsorship_pricing_unavailable',
    503,
    `Outlayer NEAR/USD latest price exceeds the ${input.maxDeviationBps} bps EMA deviation limit`,
  );
}

async function fetchOutlayerNearUsdPrice(input: {
  config: OutlayerSponsoredExecutionPricingConfig;
  fetchImpl: typeof fetch;
  nowMs: number;
}): Promise<{
  spendMinorRatio: DecimalRatio;
  pricingVersion: string;
  freshnessExpiresAtMs: number;
}> {
  const [latestResult, emaResult] = await Promise.all([
    fetchOutlayerPriceMethod({
      config: input.config,
      fetchImpl: input.fetchImpl,
      methodName: 'get_price',
      args: { price_identifier: input.config.nearUsdPriceId },
    }),
    fetchOutlayerPriceMethod({
      config: input.config,
      fetchImpl: input.fetchImpl,
      methodName: 'get_ema_price',
      args: { price_id: input.config.nearUsdPriceId },
    }),
  ]);
  const latest = parseOutlayerPrice({
    value: parseNearContractJsonResult({
      result: latestResult,
      label: 'Outlayer NEAR/USD latest price',
    }),
    label: 'Outlayer NEAR/USD latest price',
    nowMs: input.nowMs,
    maxAgeSeconds: input.config.maxAgeSeconds,
  });
  const ema = parseOutlayerPrice({
    value: parseNearContractJsonResult({
      result: emaResult,
      label: 'Outlayer NEAR/USD EMA price',
    }),
    label: 'Outlayer NEAR/USD EMA price',
    nowMs: input.nowMs,
    maxAgeSeconds: input.config.maxAgeSeconds,
  });
  assertLatestWithinEmaDeviation({
    latest: latest.ratio,
    ema: ema.ratio,
    maxDeviationBps: input.config.maxLatestToEmaDeviationBps,
  });
  return {
    spendMinorRatio: latest.ratio,
    pricingVersion:
      `outlayer:${input.config.oracleContractId}:near-usd:${latest.publishTimeSeconds}:` +
      `ema-guard-${input.config.maxLatestToEmaDeviationBps}bps`,
    freshnessExpiresAtMs:
      Math.min(latest.publishTimeSeconds, ema.publishTimeSeconds) * 1000 +
      input.config.maxAgeSeconds * 1000,
  };
}

function fetchOutlayerPriceMethod(input: {
  config: OutlayerSponsoredExecutionPricingConfig;
  fetchImpl: typeof fetch;
  methodName: 'get_price' | 'get_ema_price';
  args: Readonly<Record<string, string>>;
}): Promise<unknown> {
  return fetchJsonRpcResult(
    input.config.nearRpcUrl,
    'query',
    {
      request_type: 'call_function',
      finality: 'final',
      account_id: input.config.oracleContractId,
      method_name: input.methodName,
      args_base64: encodeJsonBase64(input.args),
    },
    input.fetchImpl,
  );
}

function quoteFromMarketPrice(input: {
  feeAmount: bigint;
  nativeUnitDecimals: number;
  spendMinorRatio: DecimalRatio;
  pricingVersion: string;
}): SponsorshipSpendPricingQuote {
  return {
    spendMinor: computeQuotedSpendMinor({
      feeAmount: input.feeAmount,
      numerator: input.spendMinorRatio.numerator,
      denominator: 10n ** BigInt(input.nativeUnitDecimals) * input.spendMinorRatio.denominator,
    }),
    pricingVersion: input.pricingVersion,
  };
}

function parseNearPricingNetworkClass(value: unknown): 'TESTNET' | 'MAINNET' | null {
  const normalized = String(value || '')
    .trim()
    .toUpperCase();
  if (normalized === 'TESTNET' || normalized === 'MAINNET') {
    return normalized;
  }
  return null;
}

export function createStaticSponsoredExecutionPricingService(
  config: StaticSponsoredExecutionPricingConfig,
): SponsorshipSpendPricingService {
  return {
    async estimateSponsoredExecutionSpend(
      input: SponsorshipSpendPricingEstimateInput,
    ): Promise<SponsorshipSpendPricingQuote> {
      if (input.chainFamily === 'near') {
        const rule = resolveStaticNearPricingRule(config, input.chainId);
        return quoteFromStaticNearRule({
          rule,
          feeAmount: rule.estimateFeeAmountYocto,
        });
      }
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
      if (input.chainFamily === 'near') {
        if (input.feeUnit !== 'yocto_near') {
          throw new SponsorshipSpendCapEnforcementError(
            'sponsorship_pricing_invalid',
            500,
            `Static sponsored spend pricing expected feeUnit yocto_near, received ${input.feeUnit}`,
          );
        }
        const rule = resolveStaticNearPricingRule(config, input.chainId);
        return quoteFromStaticNearRule({
          rule,
          feeAmount: requireNonNegativeBigInt(input.feeAmount, 'feeAmount'),
        });
      }
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

export function createOutlayerSponsoredExecutionPricingService(
  config: OutlayerSponsoredExecutionPricingConfig,
  options?: {
    fetch?: typeof fetch;
    now?: () => number;
  },
): SponsorshipSpendPricingService {
  const fetchImpl = resolveSponsorshipPricingFetch(options?.fetch);
  const now = options?.now || (() => Date.now());
  let marketPriceCache: OutlayerMarketPriceCacheEntry | null = null;

  const resolveMarketPrice = async (): Promise<{
    spendMinorRatio: DecimalRatio;
    pricingVersion: string;
  }> => {
    const currentMs = now();
    if (marketPriceCache && marketPriceCache.expiresAtMs > currentMs) {
      return {
        spendMinorRatio: {
          numerator: marketPriceCache.spendMinorNumerator,
          denominator: marketPriceCache.spendMinorDenominator,
        },
        pricingVersion: marketPriceCache.pricingVersion,
      };
    }
    const fetched = await fetchOutlayerNearUsdPrice({
      config,
      fetchImpl,
      nowMs: currentMs,
    });
    marketPriceCache = {
      spendMinorNumerator: fetched.spendMinorRatio.numerator,
      spendMinorDenominator: fetched.spendMinorRatio.denominator,
      pricingVersion: fetched.pricingVersion,
      expiresAtMs: Math.min(currentMs + config.cacheTtlMs, fetched.freshnessExpiresAtMs),
    };
    return fetched;
  };

  return {
    async estimateSponsoredExecutionSpend(
      input: SponsorshipSpendPricingEstimateInput,
    ): Promise<SponsorshipSpendPricingQuote> {
      if (input.chainFamily === 'near') {
        const rule = resolveOutlayerNearPricingRule(config, input.chainId);
        const marketPrice = await resolveMarketPrice();
        return quoteFromMarketPrice({
          feeAmount: rule.estimateFeeAmountYocto,
          nativeUnitDecimals: rule.nativeUnitDecimals,
          spendMinorRatio: marketPrice.spendMinorRatio,
          pricingVersion: `${rule.pricingVersionPrefix}:${marketPrice.pricingVersion}`,
        });
      }
      if (input.chainFamily !== 'evm') {
        throw new SponsorshipSpendCapEnforcementError(
          'sponsorship_pricing_unavailable',
          503,
          `Real sponsored spend pricing does not support ${input.chainFamily}`,
        );
      }
      const rule = resolveOutlayerEvmPricingRule(config, input.chainId);
      const gasLimit = extractGasLimitForEvmEstimate(input.requestDetails);
      const gasPriceHex = await fetchJsonRpcResult(rule.rpcUrl, 'eth_gasPrice', [], fetchImpl);
      const gasPriceWei = requireNonNegativeBigInt(gasPriceHex, 'pricing RPC eth_gasPrice result');
      const marketPrice = await resolveMarketPrice();
      return quoteFromMarketPrice({
        feeAmount: gasLimit * gasPriceWei,
        nativeUnitDecimals: rule.nativeUnitDecimals,
        spendMinorRatio: marketPrice.spendMinorRatio,
        pricingVersion: `${rule.pricingVersionPrefix}:${marketPrice.pricingVersion}`,
      });
    },

    async finalizeSponsoredExecutionSpend(
      input: SponsorshipSpendPricingFinalizeInput,
    ): Promise<SponsorshipSpendPricingQuote> {
      if (input.chainFamily === 'near') {
        if (input.feeUnit !== 'yocto_near') {
          throw new SponsorshipSpendCapEnforcementError(
            'sponsorship_pricing_invalid',
            500,
            `Real sponsored spend pricing expected feeUnit yocto_near, received ${input.feeUnit}`,
          );
        }
        const rule = resolveOutlayerNearPricingRule(config, input.chainId);
        const marketPrice = await resolveMarketPrice();
        return quoteFromMarketPrice({
          feeAmount: requireNonNegativeBigInt(input.feeAmount, 'feeAmount'),
          nativeUnitDecimals: rule.nativeUnitDecimals,
          spendMinorRatio: marketPrice.spendMinorRatio,
          pricingVersion: `${rule.pricingVersionPrefix}:${marketPrice.pricingVersion}`,
        });
      }
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
      const rule = resolveOutlayerEvmPricingRule(config, input.chainId);
      const marketPrice = await resolveMarketPrice();
      return quoteFromMarketPrice({
        feeAmount: requireNonNegativeBigInt(input.feeAmount, 'feeAmount'),
        nativeUnitDecimals: rule.nativeUnitDecimals,
        spendMinorRatio: marketPrice.spendMinorRatio,
        pricingVersion: `${rule.pricingVersionPrefix}:${marketPrice.pricingVersion}`,
      });
    },
  };
}

export function resolveStaticSponsoredExecutionPricingFromEnv(
  env: SponsoredExecutionPricingEnv,
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

  const evmByChain = new Map<number, StaticSponsoredEvmSpendPricingRule>();
  const root = parsed as Record<string, unknown>;
  const evmSection = root.evm;
  if (evmSection && typeof evmSection === 'object' && !Array.isArray(evmSection)) {
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
  }

  const nearByChain = new Map<number, StaticSponsoredNearSpendPricingRule>();
  const nearSection = root.near;
  if (nearSection && typeof nearSection === 'object' && !Array.isArray(nearSection)) {
    for (const [networkClassRaw, value] of Object.entries(nearSection as Record<string, unknown>)) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
      const row = value as Record<string, unknown>;
      const networkClass =
        parseNearPricingNetworkClass(networkClassRaw) ||
        parseNearPricingNetworkClass(row.networkClass);
      const estimateFeeAmountYocto = parseOptionalBigIntLiteral(row.estimateFeeAmountYocto, {
        allowZero: true,
      });
      const minorPerFeeUnitNumerator = parseOptionalBigIntLiteral(row.minorPerFeeUnitNumerator);
      const minorPerFeeUnitDenominator = parseOptionalBigIntLiteral(row.minorPerFeeUnitDenominator);
      if (
        !networkClass ||
        estimateFeeAmountYocto === null ||
        minorPerFeeUnitNumerator === null ||
        minorPerFeeUnitDenominator === null
      ) {
        continue;
      }
      const chainId = getNearSpendCapChainId(networkClass);
      if (nearByChain.has(chainId)) return null;
      nearByChain.set(chainId, {
        networkClass,
        estimateFeeAmountYocto,
        minorPerFeeUnitNumerator,
        minorPerFeeUnitDenominator,
        pricingVersion: normalizePricingVersion(
          row.pricingVersion,
          `static-near-${networkClass.toLowerCase()}-v1`,
        ),
      });
    }
  }

  if (evmByChain.size === 0 && nearByChain.size === 0) return null;
  return createStaticSponsoredExecutionPricingService({
    evmByChain,
    nearByChain,
  });
}

function invalidRealPricingConfig(message: string): never {
  throw new SponsorshipSpendCapEnforcementError(
    'sponsorship_pricing_invalid',
    500,
    `SPONSORED_EXECUTION_REAL_PRICING_JSON ${message}`,
  );
}

function requireRealPricingString(value: unknown, field: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) invalidRealPricingConfig(`requires ${field}`);
  return normalized;
}

function requireRealPricingPositiveInteger(value: unknown, field: string): number {
  const parsed = parseOptionalPositiveInteger(value);
  if (!parsed) invalidRealPricingConfig(`requires positive integer ${field}`);
  return parsed;
}

function requireRealPricingDecimals(value: unknown, field: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 36) {
    return invalidRealPricingConfig(`requires integer ${field} between 0 and 36`);
  }
  return parsed;
}

function requireRealPricingBigInt(
  value: unknown,
  field: string,
  options?: { allowZero?: boolean },
): bigint {
  const parsed = parseOptionalBigIntLiteral(value, options);
  if (parsed === null) invalidRealPricingConfig(`requires integer ${field}`);
  return parsed;
}

function requireRealPricingUrl(value: unknown, field: string): string {
  const normalized = requireRealPricingString(value, field);
  try {
    return normalizeUrlPath(new URL(normalized).toString());
  } catch {
    return invalidRealPricingConfig(`requires valid URL ${field}`);
  }
}

export function resolveOutlayerSponsoredExecutionPricingFromEnv(
  env: SponsoredExecutionPricingEnv,
): SponsorshipSpendPricingService | null {
  const raw = String(env.SPONSORED_EXECUTION_REAL_PRICING_JSON || '').trim();
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return invalidRealPricingConfig('must be valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return invalidRealPricingConfig('must be an object');
  }
  const root = parsed as Record<string, unknown>;
  const provider = String(root.provider || '')
    .trim()
    .toLowerCase();
  if (provider !== 'outlayer') {
    return invalidRealPricingConfig('requires provider "outlayer"');
  }
  const oracleContractId = requireRealPricingString(root.oracleContractId, 'oracleContractId');
  const nearUsdPriceId = requireRealPricingString(root.nearUsdPriceId, 'nearUsdPriceId');
  if (!/^[0-9a-f]{64}$/i.test(nearUsdPriceId)) {
    return invalidRealPricingConfig('requires a 64-character hexadecimal nearUsdPriceId');
  }
  const maxAgeSeconds = requireRealPricingPositiveInteger(root.maxAgeSeconds, 'maxAgeSeconds');
  const maxLatestToEmaDeviationBps = requireRealPricingPositiveInteger(
    root.maxLatestToEmaDeviationBps,
    'maxLatestToEmaDeviationBps',
  );
  if (maxLatestToEmaDeviationBps > 10_000) {
    return invalidRealPricingConfig('maxLatestToEmaDeviationBps must not exceed 10000');
  }
  const cacheTtlMs = requireRealPricingPositiveInteger(root.cacheTtlMs, 'cacheTtlMs');
  if (cacheTtlMs > maxAgeSeconds * 1000) {
    return invalidRealPricingConfig('cacheTtlMs must not exceed maxAgeSeconds');
  }

  const evmByChain = new Map<number, OutlayerSponsoredEvmSpendPricingRule>();
  const evmSection = root.evm;
  if (evmSection !== undefined) {
    if (!evmSection || typeof evmSection !== 'object' || Array.isArray(evmSection)) {
      return invalidRealPricingConfig('requires object evm');
    }
    for (const [chainIdRaw, value] of Object.entries(evmSection as Record<string, unknown>)) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return invalidRealPricingConfig(`requires object evm.${chainIdRaw}`);
      }
      const row = value as Record<string, unknown>;
      const chainId = parseOptionalPositiveInteger(chainIdRaw);
      if (!chainId)
        invalidRealPricingConfig(`requires positive integer EVM chain id ${chainIdRaw}`);
      if (evmByChain.has(chainId)) {
        return invalidRealPricingConfig(`contains duplicate EVM chain id ${chainId}`);
      }
      evmByChain.set(chainId, {
        chainId,
        rpcUrl: requireRealPricingUrl(row.rpcUrl, `evm.${chainId}.rpcUrl`),
        nativeUnitDecimals: requireRealPricingDecimals(
          row.nativeUnitDecimals,
          `evm.${chainId}.nativeUnitDecimals`,
        ),
        pricingVersionPrefix: requireRealPricingString(
          row.pricingVersionPrefix,
          `evm.${chainId}.pricingVersionPrefix`,
        ),
      });
    }
  }

  const nearByChain = new Map<number, OutlayerSponsoredNearSpendPricingRule>();
  const nearSection = root.near;
  if (nearSection !== undefined) {
    if (!nearSection || typeof nearSection !== 'object' || Array.isArray(nearSection)) {
      return invalidRealPricingConfig('requires object near');
    }
    for (const [networkClassRaw, value] of Object.entries(nearSection as Record<string, unknown>)) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return invalidRealPricingConfig(`requires object near.${networkClassRaw}`);
      }
      const row = value as Record<string, unknown>;
      const networkClass = parseNearPricingNetworkClass(networkClassRaw);
      if (!networkClass) {
        return invalidRealPricingConfig(`requires TESTNET or MAINNET key near.${networkClassRaw}`);
      }
      const chainId = getNearSpendCapChainId(networkClass);
      if (nearByChain.has(chainId)) {
        return invalidRealPricingConfig(`contains duplicate NEAR network ${networkClass}`);
      }
      nearByChain.set(chainId, {
        networkClass,
        nativeUnitDecimals: requireRealPricingDecimals(
          row.nativeUnitDecimals,
          `near.${networkClass}.nativeUnitDecimals`,
        ),
        estimateFeeAmountYocto: requireRealPricingBigInt(
          row.estimateFeeAmountYocto,
          `near.${networkClass}.estimateFeeAmountYocto`,
          { allowZero: true },
        ),
        pricingVersionPrefix: requireRealPricingString(
          row.pricingVersionPrefix,
          `near.${networkClass}.pricingVersionPrefix`,
        ),
      });
    }
  }

  if (evmByChain.size === 0 && nearByChain.size === 0) {
    return invalidRealPricingConfig('requires at least one valid EVM or NEAR rule');
  }
  return createOutlayerSponsoredExecutionPricingService({
    nearRpcUrl: requireRealPricingUrl(root.nearRpcUrl, 'nearRpcUrl'),
    oracleContractId,
    nearUsdPriceId: nearUsdPriceId.toLowerCase(),
    maxAgeSeconds,
    maxLatestToEmaDeviationBps,
    cacheTtlMs,
    evmByChain,
    nearByChain,
  });
}

export function resolveSponsoredExecutionPricingFromEnv(
  env: SponsoredExecutionPricingEnv,
): SponsorshipSpendPricingService | null {
  if (pricingServiceByEnv.has(env)) {
    return pricingServiceByEnv.get(env) || null;
  }
  const service =
    resolveOutlayerSponsoredExecutionPricingFromEnv(env) ||
    resolveStaticSponsoredExecutionPricingFromEnv(env);
  pricingServiceByEnv.set(env, service);
  return service;
}
