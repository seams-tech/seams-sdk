import { parseOptionalPositiveInteger } from './evm';
import { getNearSpendCapChainId } from '@seams-internal/console-shared/gasSponsorshipSpendCapTargets';
import type {
  SponsorshipSpendPricingEstimateInput,
  SponsorshipSpendPricingFinalizeInput,
  SponsorshipSpendPricingQuote,
  SponsorshipSpendPricingService,
} from './spendCaps';
import {
  isSponsorshipSpendCapEnforcementError,
  SponsorshipSpendCapEnforcementError,
} from './spendCaps';
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

type RefFinanceSponsoredEvmSpendPricingRule = {
  chainId: number;
  rpcUrl: string;
  nativeUnitDecimals: number;
  pricingVersionPrefix: string;
};

type RefFinanceSponsoredNearSpendPricingRule = {
  networkClass: 'TESTNET' | 'MAINNET';
  nativeUnitDecimals: number;
  estimateFeeAmountYocto: bigint;
  pricingVersionPrefix: string;
};

type RefFinanceMarketPriceCacheEntry = {
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

export interface RefFinanceSponsoredExecutionPricingConfig {
  nearRpcUrl: string;
  dexContractId: string;
  poolId: number;
  nearTokenId: string;
  usdcTokenId: string;
  nearTokenDecimals: number;
  usdcTokenDecimals: number;
  cacheTtlMs: number;
  evmByChain: ReadonlyMap<number, RefFinanceSponsoredEvmSpendPricingRule>;
  nearByChain: ReadonlyMap<number, RefFinanceSponsoredNearSpendPricingRule>;
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

function resolveRefFinanceEvmPricingRule(
  config: RefFinanceSponsoredExecutionPricingConfig,
  chainId: number,
): RefFinanceSponsoredEvmSpendPricingRule {
  const rule = config.evmByChain.get(chainId) || null;
  if (rule) return rule;
  throw new SponsorshipSpendCapEnforcementError(
    'sponsorship_pricing_unavailable',
    503,
    `Real sponsored spend pricing is not configured for EVM chain ${chainId}`,
  );
}

function resolveRefFinanceNearPricingRule(
  config: RefFinanceSponsoredExecutionPricingConfig,
  chainId: number,
): RefFinanceSponsoredNearSpendPricingRule {
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

function requirePositiveInteger(value: unknown, label: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${label} must be a positive integer`,
    );
  }
  return parsed;
}

function encodeJsonBase64(value: unknown): string {
  return btoa(JSON.stringify(value));
}

function parseRefFinancePoolResult(input: {
  result: unknown;
  nearTokenId: string;
  usdcTokenId: string;
}): {
  nearReserve: bigint;
  usdcReserve: bigint;
  blockHeight: number;
} {
  const queryResult = requireRecord(input.result, 'Ref Finance RPC query result');
  const blockHeight = requirePositiveInteger(
    queryResult.block_height,
    'Ref Finance RPC query result.block_height',
  );
  if (!Array.isArray(queryResult.result)) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      'Ref Finance RPC query result.result must be a byte array',
    );
  }
  const bytes = queryResult.result.map((value, index) => {
    const byte = Number(value);
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new SponsorshipSpendCapEnforcementError(
        'sponsorship_pricing_invalid',
        500,
        `Ref Finance RPC query result.result[${index}] must be a byte`,
      );
    }
    return byte;
  });
  let pool: Record<string, unknown>;
  try {
    pool = requireRecord(
      JSON.parse(new TextDecoder().decode(Uint8Array.from(bytes))),
      'Ref Finance pool',
    );
  } catch (error: unknown) {
    if (isSponsorshipSpendCapEnforcementError(error)) throw error;
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `Ref Finance pool response is invalid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (!Array.isArray(pool.token_account_ids) || !Array.isArray(pool.amounts)) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      'Ref Finance pool must contain token_account_ids and amounts arrays',
    );
  }
  const nearIndex = pool.token_account_ids.indexOf(input.nearTokenId);
  const usdcIndex = pool.token_account_ids.indexOf(input.usdcTokenId);
  if (nearIndex < 0 || usdcIndex < 0 || nearIndex === usdcIndex) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      'Configured Ref Finance pool does not contain the expected NEAR and USDC tokens',
    );
  }
  const nearReserve = requireNonNegativeBigInt(
    pool.amounts[nearIndex],
    'Ref Finance NEAR reserve',
  );
  const usdcReserve = requireNonNegativeBigInt(
    pool.amounts[usdcIndex],
    'Ref Finance USDC reserve',
  );
  if (nearReserve === 0n || usdcReserve === 0n) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      'Configured Ref Finance pool has no liquidity',
    );
  }
  return {
    nearReserve,
    usdcReserve,
    blockHeight,
  };
}

async function fetchRefFinanceNearUsdPrice(input: {
  config: RefFinanceSponsoredExecutionPricingConfig;
  fetchImpl: typeof fetch;
}): Promise<{ spendMinorRatio: DecimalRatio; pricingVersion: string }> {
  const result = await fetchJsonRpcResult(
    input.config.nearRpcUrl,
    'query',
    {
      request_type: 'call_function',
      finality: 'final',
      account_id: input.config.dexContractId,
      method_name: 'get_pool',
      args_base64: encodeJsonBase64({ pool_id: input.config.poolId }),
    },
    input.fetchImpl,
  );
  const pool = parseRefFinancePoolResult({
    result,
    nearTokenId: input.config.nearTokenId,
    usdcTokenId: input.config.usdcTokenId,
  });
  return {
    spendMinorRatio: {
      numerator:
        pool.usdcReserve *
        100n *
        10n ** BigInt(input.config.nearTokenDecimals),
      denominator:
        pool.nearReserve * 10n ** BigInt(input.config.usdcTokenDecimals),
    },
    pricingVersion: `ref-finance:${input.config.dexContractId}:pool-${input.config.poolId}:block-${pool.blockHeight}`,
  };
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
      denominator: (10n ** BigInt(input.nativeUnitDecimals)) * input.spendMinorRatio.denominator,
    }),
    pricingVersion: input.pricingVersion,
  };
}

function parseNearPricingNetworkClass(value: unknown): 'TESTNET' | 'MAINNET' | null {
  const normalized = String(value || '').trim().toUpperCase();
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

export function createRefFinanceSponsoredExecutionPricingService(
  config: RefFinanceSponsoredExecutionPricingConfig,
  options?: {
    fetch?: typeof fetch;
    now?: () => number;
  },
): SponsorshipSpendPricingService {
  const fetchImpl = resolveSponsorshipPricingFetch(options?.fetch);
  const now = options?.now || (() => Date.now());
  let marketPriceCache: RefFinanceMarketPriceCacheEntry | null = null;

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
    const fetched = await fetchRefFinanceNearUsdPrice({
      config,
      fetchImpl,
    });
    marketPriceCache = {
      spendMinorNumerator: fetched.spendMinorRatio.numerator,
      spendMinorDenominator: fetched.spendMinorRatio.denominator,
      pricingVersion: fetched.pricingVersion,
      expiresAtMs: currentMs + config.cacheTtlMs,
    };
    return fetched;
  };

  return {
    async estimateSponsoredExecutionSpend(
      input: SponsorshipSpendPricingEstimateInput,
    ): Promise<SponsorshipSpendPricingQuote> {
      if (input.chainFamily === 'near') {
        const rule = resolveRefFinanceNearPricingRule(config, input.chainId);
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
      const rule = resolveRefFinanceEvmPricingRule(config, input.chainId);
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
        const rule = resolveRefFinanceNearPricingRule(config, input.chainId);
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
      const rule = resolveRefFinanceEvmPricingRule(config, input.chainId);
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

export function resolveRefFinanceSponsoredExecutionPricingFromEnv(
  env: SponsoredExecutionPricingEnv,
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
  const provider = String(root.provider || '').trim().toLowerCase();
  if (provider !== 'ref_finance') return null;
  const poolId = parseOptionalPositiveInteger(root.poolId);
  const dexContractId = String(root.dexContractId || '').trim();
  const nearTokenId = String(root.nearTokenId || '').trim();
  const usdcTokenId = String(root.usdcTokenId || '').trim();
  if (!poolId || !dexContractId || !nearTokenId || !usdcTokenId) return null;

  const evmByChain = new Map<number, RefFinanceSponsoredEvmSpendPricingRule>();
  const evmSection = root.evm;
  if (evmSection && typeof evmSection === 'object' && !Array.isArray(evmSection)) {
    for (const [chainIdRaw, value] of Object.entries(evmSection as Record<string, unknown>)) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
      const row = value as Record<string, unknown>;
      const chainId =
        parseOptionalPositiveInteger(chainIdRaw) ||
        parseOptionalPositiveInteger(row.chainId) ||
        undefined;
      const rpcUrl = String(row.rpcUrl || '').trim();
      if (!chainId || !rpcUrl) continue;
      if (evmByChain.has(chainId)) return null;
      evmByChain.set(chainId, {
        chainId,
        rpcUrl,
        nativeUnitDecimals: readNativeUnitDecimals(row.nativeUnitDecimals, 18),
        pricingVersionPrefix: normalizePricingVersion(
          row.pricingVersionPrefix,
          `ref-finance-evm-${chainId}`,
        ),
      });
    }
  }

  const nearByChain = new Map<number, RefFinanceSponsoredNearSpendPricingRule>();
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
      if (!networkClass || estimateFeeAmountYocto === null) continue;
      const chainId = getNearSpendCapChainId(networkClass);
      if (nearByChain.has(chainId)) return null;
      nearByChain.set(chainId, {
        networkClass,
        nativeUnitDecimals: readNativeUnitDecimals(row.nativeUnitDecimals, 24),
        estimateFeeAmountYocto,
        pricingVersionPrefix: normalizePricingVersion(
          row.pricingVersionPrefix,
          `ref-finance-near-${networkClass.toLowerCase()}`,
        ),
      });
    }
  }

  if (evmByChain.size === 0 && nearByChain.size === 0) return null;
  return createRefFinanceSponsoredExecutionPricingService({
    nearRpcUrl: normalizeApiBaseUrl(root.nearRpcUrl, 'https://rpc.mainnet.near.org'),
    dexContractId,
    poolId,
    nearTokenId,
    usdcTokenId,
    nearTokenDecimals: readNativeUnitDecimals(root.nearTokenDecimals, 24),
    usdcTokenDecimals: readNativeUnitDecimals(root.usdcTokenDecimals, 6),
    cacheTtlMs: readCacheTtlMs(root.cacheTtlMs, 5 * 60 * 1000),
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
    resolveRefFinanceSponsoredExecutionPricingFromEnv(env) ||
    resolveStaticSponsoredExecutionPricingFromEnv(env);
  pricingServiceByEnv.set(env, service);
  return service;
}
