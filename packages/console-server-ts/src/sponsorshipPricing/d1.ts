import { formatD1ExecStatement, queryD1One, type D1Row } from '@seams/sdk-server/internal/storage/d1Sql';
import type { D1DatabaseLike } from '@seams/sdk-server/internal/storage/tenantRoute';
import {
  SponsorshipSpendCapEnforcementError,
  type SponsorshipSpendPricingEstimateInput,
  type SponsorshipSpendPricingFinalizeInput,
  type SponsorshipSpendPricingQuote,
  type SponsorshipSpendPricingService,
} from '../sponsorship/spendCaps';

export interface D1ConsoleSponsorshipPricingSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1ConsoleSponsorshipPricingServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

export interface SeedD1ConsoleStaticEvmSponsorshipPricingRuleOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly policyId?: string;
  readonly chainId: number;
  readonly pricingVersion: string;
  readonly estimateFeePerGasWei: string | bigint;
  readonly minorPerWeiNumerator: string | bigint;
  readonly minorPerWeiDenominator: string | bigint;
  readonly minSpendMinor?: number;
  readonly createdBy: string;
  readonly effectiveFromMs?: number;
  readonly now?: () => Date;
}

type D1SponsorshipPricingRule = {
  readonly pricingVersion: string;
  readonly estimateFeePerGasWei: bigint;
  readonly minorPerWeiNumerator: bigint;
  readonly minorPerWeiDenominator: bigint;
  readonly minSpendMinor: number;
};

export const CONSOLE_SPONSORSHIP_PRICING_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS sponsorship_pricing_rules (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      environment_id TEXT NOT NULL,
      policy_id TEXT NOT NULL DEFAULT '',
      chain_family TEXT NOT NULL,
      chain_id INTEGER NOT NULL,
      intent_kind TEXT NOT NULL,
      executor_kind TEXT NOT NULL,
      model_kind TEXT NOT NULL,
      pricing_version TEXT NOT NULL,
      estimate_fee_per_gas_wei TEXT NOT NULL,
      minor_per_wei_numerator TEXT NOT NULL,
      minor_per_wei_denominator TEXT NOT NULL,
      min_spend_minor INTEGER NOT NULL DEFAULT 0,
      rounding_mode TEXT NOT NULL,
      status TEXT NOT NULL,
      effective_from_ms INTEGER NOT NULL,
      effective_until_ms INTEGER,
      created_by TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, pricing_version),
      CHECK (chain_family = 'evm'),
      CHECK (chain_id > 0),
      CHECK (intent_kind = 'evm_call'),
      CHECK (executor_kind = 'evm_eoa'),
      CHECK (model_kind = 'evm_static_gas_v1'),
      CHECK (length(pricing_version) > 0),
      CHECK (length(estimate_fee_per_gas_wei) > 0),
      CHECK (length(minor_per_wei_numerator) > 0),
      CHECK (length(minor_per_wei_denominator) > 0),
      CHECK (min_spend_minor >= 0),
      CHECK (rounding_mode = 'ceil'),
      CHECK (status IN ('active', 'retired')),
      CHECK (effective_from_ms > 0),
      CHECK (effective_until_ms IS NULL OR effective_until_ms > effective_from_ms),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms >= created_at_ms)
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS sponsorship_pricing_active_selector_idx
      ON sponsorship_pricing_rules (
        namespace,
        org_id,
        project_id,
        environment_id,
        policy_id,
        chain_family,
        chain_id,
        intent_kind,
        executor_kind
      )
      WHERE status = 'active'
  `,
  `
    CREATE INDEX IF NOT EXISTS sponsorship_pricing_environment_idx
      ON sponsorship_pricing_rules (
        namespace,
        environment_id,
        policy_id,
        chain_id,
        status,
        effective_from_ms DESC
      )
  `,
] as const);

export async function ensureConsoleSponsorshipPricingD1Schema(
  options: D1ConsoleSponsorshipPricingSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_SPONSORSHIP_PRICING_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

function defaultNow(): Date {
  return new Date();
}

function ensureNamespace(namespace: string | undefined): string {
  const normalized = String(namespace || 'default').trim();
  return normalized || 'default';
}

function requireNonEmptyString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${label} is required`,
    );
  }
  return normalized;
}

function toNowMs(now: () => Date): number {
  return now().getTime();
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
  const normalized = String(value ?? '').trim();
  if (!/^[0-9]+$/.test(normalized)) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${label} must be a non-negative integer`,
    );
  }
  return BigInt(normalized);
}

function requirePositiveBigInt(value: unknown, label: string): bigint {
  const parsed = requireNonNegativeBigInt(value, label);
  if (parsed <= 0n) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${label} must be a positive integer`,
    );
  }
  return parsed;
}

function requireNonNegativeSafeInteger(value: unknown, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${label} must be a non-negative safe integer`,
    );
  }
  return parsed;
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

function ceilDivide(numerator: bigint, denominator: bigint): bigint {
  if (numerator <= 0n) return 0n;
  return (numerator + denominator - 1n) / denominator;
}

function normalizePolicyId(value: unknown): string {
  return String(value || '').trim();
}

function requireEvmPricingInput(input: {
  readonly chainFamily: string;
  readonly intentKind: string;
  readonly executorKind: string;
}): void {
  if (
    input.chainFamily !== 'evm' ||
    input.intentKind !== 'evm_call' ||
    input.executorKind !== 'evm_eoa'
  ) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      'Only evm_static_gas_v1 sponsorship pricing is modeled in the D1 MVP',
    );
  }
}

function requirePositiveChainId(chainId: unknown): number {
  const parsed = Number(chainId);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      'EVM sponsorship pricing requires a positive chainId',
    );
  }
  return parsed;
}

function requirePositiveTimestampMs(value: unknown, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${label} must be a positive safe integer timestamp`,
    );
  }
  return parsed;
}

async function requireEnvironmentScope(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly environmentId: string;
}): Promise<void> {
  const row = await queryD1One(
    input.database,
    `SELECT id
       FROM environments
      WHERE namespace = ?
        AND org_id = ?
        AND project_id = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.projectId, input.environmentId],
  );
  if (row) return;
  throw new SponsorshipSpendCapEnforcementError(
    'sponsorship_pricing_invalid',
    400,
    'Static sponsorship pricing seed requires an existing environment scope',
  );
}

function pricingRuleFromRow(row: D1Row | null): D1SponsorshipPricingRule {
  if (!row) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      'Sponsored EVM static gas pricing is not configured',
    );
  }
  return {
    pricingVersion: String(row.pricing_version || '').trim(),
    estimateFeePerGasWei: requirePositiveBigInt(
      row.estimate_fee_per_gas_wei,
      'estimate_fee_per_gas_wei',
    ),
    minorPerWeiNumerator: requirePositiveBigInt(
      row.minor_per_wei_numerator,
      'minor_per_wei_numerator',
    ),
    minorPerWeiDenominator: requirePositiveBigInt(
      row.minor_per_wei_denominator,
      'minor_per_wei_denominator',
    ),
    minSpendMinor: requireNonNegativeSafeInteger(row.min_spend_minor, 'min_spend_minor'),
  };
}

function quoteFromStaticEvmRule(input: {
  readonly rule: D1SponsorshipPricingRule;
  readonly feeAmountWei: bigint;
}): SponsorshipSpendPricingQuote {
  const rawSpendMinor = toSafeInteger(
    ceilDivide(
      input.feeAmountWei * input.rule.minorPerWeiNumerator,
      input.rule.minorPerWeiDenominator,
    ),
    'quoted spendMinor',
  );
  return {
    spendMinor: Math.max(rawSpendMinor, input.rule.minSpendMinor),
    pricingVersion: input.rule.pricingVersion || 'unknown',
  };
}

function estimateGasLimitFromRequestDetails(requestDetails: Record<string, unknown>): bigint {
  const call = requireRecord(requestDetails.call, 'requestDetails.call');
  return requireNonNegativeBigInt(call.gasLimit, 'requestDetails.call.gasLimit');
}

class D1ConsoleSponsorshipPricingService implements SponsorshipSpendPricingService {
  constructor(
    private readonly database: D1DatabaseLike,
    private readonly namespace: string,
    private readonly now: () => Date,
  ) {}

  async estimateSponsoredExecutionSpend(
    input: SponsorshipSpendPricingEstimateInput,
  ): Promise<SponsorshipSpendPricingQuote> {
    requireEvmPricingInput(input);
    const chainId = requirePositiveChainId(input.chainId);
    const rule = await this.loadActiveStaticEvmRule({
      environmentId: input.environmentId,
      policyId: input.policyId,
      chainId,
      nowMs: toNowMs(this.now),
    });
    const gasLimit = estimateGasLimitFromRequestDetails(input.requestDetails);
    return quoteFromStaticEvmRule({
      rule,
      feeAmountWei: gasLimit * rule.estimateFeePerGasWei,
    });
  }

  async finalizeSponsoredExecutionSpend(
    input: SponsorshipSpendPricingFinalizeInput,
  ): Promise<SponsorshipSpendPricingQuote> {
    requireEvmPricingInput(input);
    if (input.feeUnit !== 'wei') {
      throw new SponsorshipSpendCapEnforcementError(
        'sponsorship_pricing_invalid',
        500,
        `Static EVM sponsorship pricing expected feeUnit wei, received ${input.feeUnit}`,
      );
    }
    const chainId = requirePositiveChainId(input.chainId);
    const rule = await this.loadExactStaticEvmRule({
      environmentId: input.environmentId,
      policyId: input.policyId,
      chainId,
      pricingVersion: input.estimatedPricingVersion,
      nowMs: toNowMs(this.now),
    });
    return quoteFromStaticEvmRule({
      rule,
      feeAmountWei: requireNonNegativeBigInt(input.feeAmount, 'feeAmount'),
    });
  }

  private async loadActiveStaticEvmRule(input: {
    readonly environmentId: string;
    readonly policyId: string;
    readonly chainId: number;
    readonly nowMs: number;
  }): Promise<D1SponsorshipPricingRule> {
    const row = await queryD1One(
      this.database,
      `SELECT r.*
         FROM sponsorship_pricing_rules r
         JOIN environments e
           ON e.namespace = r.namespace
          AND e.id = r.environment_id
          AND e.org_id = r.org_id
          AND e.project_id = r.project_id
        WHERE r.namespace = ?
          AND r.environment_id = ?
          AND r.policy_id = ?
          AND r.chain_family = 'evm'
          AND r.chain_id = ?
          AND r.intent_kind = 'evm_call'
          AND r.executor_kind = 'evm_eoa'
          AND r.model_kind = 'evm_static_gas_v1'
          AND r.rounding_mode = 'ceil'
          AND r.status = 'active'
          AND r.effective_from_ms <= ?
          AND (r.effective_until_ms IS NULL OR r.effective_until_ms > ?)
        ORDER BY r.effective_from_ms DESC
        LIMIT 1`,
      [
        this.namespace,
        String(input.environmentId || '').trim(),
        normalizePolicyId(input.policyId),
        input.chainId,
        input.nowMs,
        input.nowMs,
      ],
    );
    return pricingRuleFromRow(row);
  }

  private async loadExactStaticEvmRule(input: {
    readonly environmentId: string;
    readonly policyId: string;
    readonly chainId: number;
    readonly pricingVersion: string;
    readonly nowMs: number;
  }): Promise<D1SponsorshipPricingRule> {
    const row = await queryD1One(
      this.database,
      `SELECT r.*
         FROM sponsorship_pricing_rules r
         JOIN environments e
           ON e.namespace = r.namespace
          AND e.id = r.environment_id
          AND e.org_id = r.org_id
          AND e.project_id = r.project_id
        WHERE r.namespace = ?
          AND r.environment_id = ?
          AND r.policy_id = ?
          AND r.chain_family = 'evm'
          AND r.chain_id = ?
          AND r.intent_kind = 'evm_call'
          AND r.executor_kind = 'evm_eoa'
          AND r.model_kind = 'evm_static_gas_v1'
          AND r.rounding_mode = 'ceil'
          AND r.status = 'active'
          AND r.pricing_version = ?
          AND r.effective_from_ms <= ?
          AND (r.effective_until_ms IS NULL OR r.effective_until_ms > ?)
        LIMIT 1`,
      [
        this.namespace,
        String(input.environmentId || '').trim(),
        normalizePolicyId(input.policyId),
        input.chainId,
        String(input.pricingVersion || '').trim(),
        input.nowMs,
        input.nowMs,
      ],
    );
    return pricingRuleFromRow(row);
  }
}

export async function createD1ConsoleSponsorshipPricingService(
  options: D1ConsoleSponsorshipPricingServiceOptions,
): Promise<SponsorshipSpendPricingService> {
  if (options.ensureSchema !== false) {
    await ensureConsoleSponsorshipPricingD1Schema({ database: options.database });
  }
  // ponytail: MVP supports static EVM gas only; add model branches when sponsorship resumes.
  return new D1ConsoleSponsorshipPricingService(
    options.database,
    ensureNamespace(options.namespace),
    options.now || defaultNow,
  );
}

export async function seedD1ConsoleStaticEvmSponsorshipPricingRule(
  options: SeedD1ConsoleStaticEvmSponsorshipPricingRuleOptions,
): Promise<{ readonly pricingVersion: string }> {
  await ensureConsoleSponsorshipPricingD1Schema({ database: options.database });
  const namespace = ensureNamespace(options.namespace);
  const orgId = requireNonEmptyString(options.orgId, 'orgId');
  const projectId = requireNonEmptyString(options.projectId, 'projectId');
  const environmentId = requireNonEmptyString(options.environmentId, 'environmentId');
  const policyId = normalizePolicyId(options.policyId);
  const chainId = requirePositiveChainId(options.chainId);
  const pricingVersion = requireNonEmptyString(options.pricingVersion, 'pricingVersion');
  const estimateFeePerGasWei = requirePositiveBigInt(
    options.estimateFeePerGasWei,
    'estimateFeePerGasWei',
  ).toString();
  const minorPerWeiNumerator = requirePositiveBigInt(
    options.minorPerWeiNumerator,
    'minorPerWeiNumerator',
  ).toString();
  const minorPerWeiDenominator = requirePositiveBigInt(
    options.minorPerWeiDenominator,
    'minorPerWeiDenominator',
  ).toString();
  const minSpendMinor = requireNonNegativeSafeInteger(
    options.minSpendMinor || 0,
    'minSpendMinor',
  );
  const createdBy = requireNonEmptyString(options.createdBy, 'createdBy');
  const nowMs = requirePositiveTimestampMs((options.now || defaultNow)().getTime(), 'nowMs');
  const effectiveFromMs = requirePositiveTimestampMs(
    options.effectiveFromMs || nowMs,
    'effectiveFromMs',
  );
  await requireEnvironmentScope({
    database: options.database,
    namespace,
    orgId,
    projectId,
    environmentId,
  });
  // ponytail: explicit setup seed only; platform-admin pricing UI can retire/replace rows later.
  await options.database
    .prepare(
      `INSERT OR IGNORE INTO sponsorship_pricing_rules (
         namespace,
         org_id,
         project_id,
         environment_id,
         policy_id,
         chain_family,
         chain_id,
         intent_kind,
         executor_kind,
         model_kind,
         pricing_version,
         estimate_fee_per_gas_wei,
         minor_per_wei_numerator,
         minor_per_wei_denominator,
         min_spend_minor,
         rounding_mode,
         status,
         effective_from_ms,
         effective_until_ms,
         created_by,
         created_at_ms,
         updated_at_ms
       ) VALUES (?, ?, ?, ?, ?, 'evm', ?, 'evm_call', 'evm_eoa', 'evm_static_gas_v1', ?, ?, ?, ?, ?, 'ceil', 'active', ?, NULL, ?, ?, ?)`,
    )
    .bind(
      namespace,
      orgId,
      projectId,
      environmentId,
      policyId,
      chainId,
      pricingVersion,
      estimateFeePerGasWei,
      minorPerWeiNumerator,
      minorPerWeiDenominator,
      minSpendMinor,
      effectiveFromMs,
      createdBy,
      nowMs,
      nowMs,
    )
    .run();
  return { pricingVersion };
}
