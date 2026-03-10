import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import {
  ensureConsoleNamespace as ensureNamespace,
  toConsoleIso as toIso,
  toConsoleNumber as toNumber,
} from '../shared/postgresNormalize';
import {
  ensureConsoleTenantRlsPolicies,
  withConsoleTenantContextTx,
} from '../shared/postgresTenantContext';
import { ConsoleGasSponsorshipError } from './errors';
import type {
  ConsoleGasSponsorshipAllowedCall,
  ConsoleGasSponsorshipCallMode,
  ConsoleGasSponsorshipConfig,
  ConsoleGasSponsorshipNetworkClass,
  ConsoleGasSponsorshipSpendCap,
  ConsoleGasSponsorshipSpendCapMode,
  ConsoleGasSponsorshipSpendCapPeriod,
  ConsoleGasSponsorshipTelemetry,
  CreateConsoleGasSponsorshipRequest,
  UpdateConsoleGasSponsorshipRequest,
} from './types';
import type { ConsoleGasSponsorshipContext, ConsoleGasSponsorshipService } from './service';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_GAS_SPONSORSHIP_MIGRATION_LOCK_ID = 9452360123591;

function nowMs(now: Date): number {
  return now.getTime();
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function parseJsonArray(raw: unknown): unknown[] {
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

function parseJsonObject(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return {};
    }
  }
  return {};
}

function toNullableString(raw: unknown): string | null {
  const value = String(raw || '').trim();
  return value || null;
}

function normalizeSpendCapMode(value: unknown): ConsoleGasSponsorshipSpendCapMode {
  const normalized = String(value || '')
    .trim()
    .toUpperCase();
  if (normalized === 'CHAIN_TOTAL' || normalized === 'WALLET_CHAIN_TOTAL') {
    return normalized;
  }
  return 'NONE';
}

function normalizeSpendCapPeriod(value: unknown): ConsoleGasSponsorshipSpendCapPeriod {
  const normalized = String(value || '')
    .trim()
    .toUpperCase();
  return normalized === 'WEEKLY' ? 'WEEKLY' : 'MONTHLY';
}

function normalizeSpendCap(input: ConsoleGasSponsorshipSpendCap | undefined): ConsoleGasSponsorshipSpendCap {
  const mode = normalizeSpendCapMode(input?.mode);
  const capsByChain = new Map<number, { chainId: number; capMinor: number }>();
  const source = Array.isArray(input?.capsByChain) ? input?.capsByChain : [];
  source.forEach((entry) => {
    const chainId = Math.max(0, Math.floor(Number(entry.chainId) || 0));
    if (!chainId) return;
    capsByChain.set(chainId, {
      chainId,
      capMinor: Math.max(0, Math.floor(Number(entry.capMinor) || 0)),
    });
  });
  return {
    mode,
    period: normalizeSpendCapPeriod(input?.period),
    capsByChain: mode === 'NONE' ? [] : Array.from(capsByChain.values()),
  };
}

function parseSpendCap(raw: unknown): ConsoleGasSponsorshipSpendCap {
  const row = parseJsonObject(raw);
  const out: ConsoleGasSponsorshipSpendCap = {
    mode: normalizeSpendCapMode(row.mode),
    period: normalizeSpendCapPeriod(row.period),
    capsByChain: [],
  };
  for (const entry of parseJsonArray(row.capsByChain)) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const capRow = entry as Record<string, unknown>;
    const chainId = Math.max(0, Math.floor(toNumber(capRow.chainId, 0)));
    if (!chainId) continue;
    out.capsByChain.push({
      chainId,
      capMinor: Math.max(0, Math.floor(toNumber(capRow.capMinor, 0))),
    });
  }
  return normalizeSpendCap(out);
}

function normalizeAddress(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return /^0x[0-9a-fA-F]{40}$/.test(normalized) ? normalized : null;
}

function normalizeSelector(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return /^0x[0-9a-fA-F]{8}$/.test(normalized) ? normalized.toLowerCase() : null;
}

function normalizeNetworkClass(value: unknown): ConsoleGasSponsorshipNetworkClass {
  const normalized = String(value || '')
    .trim()
    .toUpperCase();
  if (normalized === 'TESTNET' || normalized === 'MAINNET') return normalized;
  return 'ANY';
}

function normalizeCallMode(
  value: unknown,
  inputAllowedCalls: ConsoleGasSponsorshipAllowedCall[] | undefined,
): ConsoleGasSponsorshipCallMode {
  const normalized = String(value || '')
    .trim()
    .toUpperCase();
  if (normalized === 'ALLOW_ALL' || normalized === 'ALLOWLIST') return normalized;
  return Array.isArray(inputAllowedCalls) && inputAllowedCalls.length > 0 ? 'ALLOWLIST' : 'ALLOW_ALL';
}

function normalizeAllowedChainIds(
  input: number[] | undefined,
  inputAllowedCalls: ConsoleGasSponsorshipAllowedCall[] | undefined,
): number[] {
  const source =
    Array.isArray(input) && input.length > 0
      ? input
      : Array.isArray(inputAllowedCalls)
        ? inputAllowedCalls.map((entry) => Number(entry.chainId || 0))
        : [];
  const out: number[] = [];
  const seen = new Set<number>();
  source.forEach((entry) => {
    const chainId = Math.max(0, Math.floor(Number(entry) || 0));
    if (!chainId || seen.has(chainId)) return;
    seen.add(chainId);
    out.push(chainId);
  });
  return out;
}

function normalizeAllowedCalls(
  input: ConsoleGasSponsorshipAllowedCall[] | undefined,
): ConsoleGasSponsorshipAllowedCall[] {
  const source = Array.isArray(input) ? input : [];
  const deduped = new Map<string, ConsoleGasSponsorshipAllowedCall>();
  source.forEach((entry) => {
    const chainId = Math.max(0, Math.floor(Number(entry.chainId) || 0));
    const to = normalizeAddress(entry.to);
    const selector = normalizeSelector(entry.selector);
    if (!chainId || !to || !selector) return;
    deduped.set(`${chainId}:${to.toLowerCase()}:${selector}`, {
      chainId,
      to,
      selector,
    });
  });
  return Array.from(deduped.values());
}

function parseAllowedCalls(raw: unknown): ConsoleGasSponsorshipAllowedCall[] {
  const out: ConsoleGasSponsorshipAllowedCall[] = [];
  for (const entry of parseJsonArray(raw)) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const row = entry as Record<string, unknown>;
    const chainId = Math.max(0, Math.floor(toNumber(row.chainId, 0)));
    const to = normalizeAddress(row.to);
    const selector = normalizeSelector(row.selector);
    if (!chainId || !to || !selector) continue;
    out.push({
      chainId,
      to,
      selector,
    });
  }
  return normalizeAllowedCalls(out);
}

function parseAllowedChainIds(
  raw: unknown,
  allowedCalls: ConsoleGasSponsorshipAllowedCall[],
): number[] {
  const rawValues = parseJsonArray(raw)
    .map((entry) => Math.max(0, Math.floor(toNumber(entry, 0))))
    .filter((entry) => entry > 0);
  return normalizeAllowedChainIds(rawValues, allowedCalls);
}

function parseTelemetry(raw: unknown): ConsoleGasSponsorshipTelemetry {
  const row = parseJsonObject(raw);
  return {
    sponsoredTransactionCount: Math.max(0, Math.floor(toNumber(row.sponsoredTransactionCount, 0))),
    failedTransactionCount: Math.max(0, Math.floor(toNumber(row.failedTransactionCount, 0))),
    spendMinor: Math.max(0, Math.floor(toNumber(row.spendMinor, 0))),
    budgetUtilizationPct: Math.max(0, toNumber(row.budgetUtilizationPct, 0)),
  };
}

function parseConfigRow(row: PgRow): ConsoleGasSponsorshipConfig {
  const allowedCalls = parseAllowedCalls(row.allowed_calls);
  const allowedChainIds = parseAllowedChainIds(row.allowed_chain_ids, allowedCalls);
  const callMode = normalizeCallMode(row.call_mode, allowedCalls);
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    scopeType: String(row.scope_type || 'ORG') as ConsoleGasSponsorshipConfig['scopeType'],
    projectId: toNullableString(row.project_id),
    environmentId: toNullableString(row.environment_id),
    policyId: toNullableString(row.policy_id),
    walletSegmentId: toNullableString(row.wallet_segment_id),
    policyName: String(row.policy_name || 'Gas Sponsorship Policy'),
    templateId: toNullableString(row.template_id),
    networkClass: normalizeNetworkClass(row.network_class),
    enabled: row.enabled !== false,
    allowedChainIds,
    callMode,
    spendCap: parseSpendCap(row.spend_cap),
    allowedCalls: callMode === 'ALLOW_ALL' ? [] : allowedCalls,
    telemetry: parseTelemetry(row.telemetry),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

function validateScope(config: {
  scopeType: ConsoleGasSponsorshipConfig['scopeType'];
  projectId: string | null;
  environmentId: string | null;
  policyId: string | null;
  walletSegmentId: string | null;
}): void {
  if (config.scopeType === 'ORG') return;
  if (config.scopeType === 'PROJECT' && config.projectId) return;
  if (config.scopeType === 'ENVIRONMENT' && config.environmentId) return;
  if (config.scopeType === 'POLICY' && config.policyId) return;
  if (config.scopeType === 'WALLET_SEGMENT' && config.walletSegmentId) return;
  throw new ConsoleGasSponsorshipError(
    'invalid_scope',
    400,
    `Scope ${config.scopeType} is missing a required identifier`,
  );
}

function validatePolicyRules(config: {
  allowedChainIds: number[];
  callMode: ConsoleGasSponsorshipCallMode;
  allowedCalls: ConsoleGasSponsorshipAllowedCall[];
  spendCap: ConsoleGasSponsorshipSpendCap;
}): void {
  if (config.allowedChainIds.length === 0) {
    throw new ConsoleGasSponsorshipError(
      'invalid_allowed_chains',
      400,
      'At least one allowed chain is required.',
    );
  }
  if (config.callMode === 'ALLOWLIST' && config.allowedCalls.length === 0) {
    throw new ConsoleGasSponsorshipError(
      'invalid_allowed_calls',
      400,
      'Allowlist mode requires at least one allowed contract function.',
    );
  }
  const chainIdSet = new Set(config.allowedChainIds);
  if (config.callMode === 'ALLOWLIST') {
    const invalidCall = config.allowedCalls.find((entry) => !chainIdSet.has(entry.chainId));
    if (invalidCall) {
      throw new ConsoleGasSponsorshipError(
        'invalid_allowed_calls',
        400,
        `Allowed call chain ${invalidCall.chainId} is not part of the selected chains.`,
      );
    }
  }
  if (config.spendCap.mode === 'NONE') return;
  const invalidSpendCap = config.spendCap.capsByChain.find((entry) => !chainIdSet.has(entry.chainId));
  if (invalidSpendCap) {
    throw new ConsoleGasSponsorshipError(
      'invalid_spend_cap',
      400,
      `Spend cap chain ${invalidSpendCap.chainId} is not part of the selected chains.`,
    );
  }
}

function isUniqueViolation(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  return (error as { code?: unknown }).code === '23505';
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

export interface PostgresConsoleGasSponsorshipSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleGasSponsorshipPostgresSchema(
  options: PostgresConsoleGasSponsorshipSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_GAS_SPONSORSHIP_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_gas_sponsorship_configs (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        id TEXT NOT NULL,
        scope_type TEXT NOT NULL,
        project_id TEXT,
        environment_id TEXT,
        policy_id TEXT,
        wallet_segment_id TEXT,
        policy_name TEXT NOT NULL,
        template_id TEXT,
        network_class TEXT NOT NULL,
        enabled BOOLEAN NOT NULL,
        allowed_chain_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        call_mode TEXT NOT NULL DEFAULT 'ALLOW_ALL',
        spend_cap JSONB NOT NULL DEFAULT '{"mode":"NONE","period":"MONTHLY","capsByChain":[]}'::jsonb,
        allowed_calls JSONB NOT NULL,
        telemetry JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, id),
        CHECK (scope_type IN ('ORG', 'PROJECT', 'ENVIRONMENT', 'POLICY', 'WALLET_SEGMENT')),
        CHECK (network_class IN ('ANY', 'TESTNET', 'MAINNET')),
        CHECK (call_mode IN ('ALLOW_ALL', 'ALLOWLIST')),
        CHECK (jsonb_typeof(allowed_chain_ids) = 'array'),
        CHECK (jsonb_typeof(spend_cap) = 'object'),
        CHECK (jsonb_typeof(allowed_calls) = 'array'),
        CHECK (jsonb_typeof(telemetry) = 'object')
      )
    `);

    await pool.query(`
      ALTER TABLE console_gas_sponsorship_configs
      ADD COLUMN IF NOT EXISTS policy_name TEXT NOT NULL DEFAULT 'Gas Sponsorship Policy'
    `);
    await pool.query(`
      ALTER TABLE console_gas_sponsorship_configs
      ADD COLUMN IF NOT EXISTS template_id TEXT
    `);
    await pool.query(`
      ALTER TABLE console_gas_sponsorship_configs
      ADD COLUMN IF NOT EXISTS network_class TEXT NOT NULL DEFAULT 'ANY'
    `);
    await pool.query(`
      ALTER TABLE console_gas_sponsorship_configs
      ADD COLUMN IF NOT EXISTS allowed_calls JSONB NOT NULL DEFAULT '[]'::jsonb
    `);
    await pool.query(`
      ALTER TABLE console_gas_sponsorship_configs
      ADD COLUMN IF NOT EXISTS allowed_chain_ids JSONB NOT NULL DEFAULT '[]'::jsonb
    `);
    await pool.query(`
      ALTER TABLE console_gas_sponsorship_configs
      ADD COLUMN IF NOT EXISTS call_mode TEXT NOT NULL DEFAULT 'ALLOW_ALL'
    `);
    await pool.query(`
      ALTER TABLE console_gas_sponsorship_configs
      ADD COLUMN IF NOT EXISTS spend_cap JSONB NOT NULL DEFAULT '{"mode":"NONE","period":"MONTHLY","capsByChain":[]}'::jsonb
    `);
    await pool.query(`
      ALTER TABLE console_gas_sponsorship_configs
      DROP COLUMN IF EXISTS executor
    `);
    await pool.query(`
      ALTER TABLE console_gas_sponsorship_configs
      DROP COLUMN IF EXISTS paymaster_mode
    `);
    await pool.query(`
      ALTER TABLE console_gas_sponsorship_configs
      DROP COLUMN IF EXISTS fallback_behavior
    `);
    await pool.query(`
      ALTER TABLE console_gas_sponsorship_configs
      DROP COLUMN IF EXISTS chain_budgets
    `);
    await pool.query(`
      UPDATE console_gas_sponsorship_configs
         SET allowed_calls = COALESCE(
           (
             SELECT jsonb_agg(
               CASE
                 WHEN jsonb_typeof(entry) = 'object' THEN (entry - 'maxGasLimit') - 'maxValueWei'
                 ELSE entry
               END
             )
             FROM jsonb_array_elements(
               CASE
                 WHEN jsonb_typeof(allowed_calls) = 'array' THEN allowed_calls
                 ELSE '[]'::jsonb
               END
             ) AS entry
           ),
           '[]'::jsonb
         )
       WHERE jsonb_typeof(allowed_calls) = 'array'
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_gas_sponsorship_org_updated_idx
      ON console_gas_sponsorship_configs (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_gas_sponsorship_org_scope_idx
      ON console_gas_sponsorship_configs (namespace, org_id, scope_type)
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_gas_sponsorship_configs',
      policyName: 'console_gas_sponsorship_configs_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_GAS_SPONSORSHIP_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }

  options.logger.info('[console-gas-sponsorship][postgres] Schema ready');
}

export interface PostgresConsoleGasSponsorshipServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleGasSponsorshipService(
  options: PostgresConsoleGasSponsorshipServiceOptions,
): Promise<ConsoleGasSponsorshipService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console gas sponsorship service');
  }

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());

  if (options.ensureSchema !== false) {
    await ensureConsoleGasSponsorshipPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);
  const withTenantTx = <T>(
    ctx: ConsoleGasSponsorshipContext,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, fn);

  async function findConfig(
    q: Queryable,
    input: { orgId: string; id: string },
  ): Promise<ConsoleGasSponsorshipConfig | null> {
    const row = await queryOne(
      q,
      `SELECT *
         FROM console_gas_sponsorship_configs
        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
      [namespace, input.orgId, input.id],
    );
    return row ? parseConfigRow(row) : null;
  }

  return {
    async listConfigs(ctx, request = {}) {
      return withTenantTx(ctx, async (q) => {
        const out = await q.query(
          `SELECT *
             FROM console_gas_sponsorship_configs
            WHERE namespace = $1
              AND org_id = $2
              AND ($3::text IS NULL OR scope_type = $3::text)
              AND ($4::text IS NULL OR project_id = $4::text)
              AND ($5::text IS NULL OR environment_id = $5::text)
              AND ($6::text IS NULL OR policy_id = $6::text)
              AND ($7::text IS NULL OR wallet_segment_id = $7::text)
              AND ($8::text IS NULL OR template_id = $8::text)
            ORDER BY updated_at_ms DESC, created_at_ms DESC`,
          [
            namespace,
            ctx.orgId,
            request.scopeType || null,
            request.projectId || null,
            request.environmentId || null,
            request.policyId || null,
            request.walletSegmentId || null,
            request.templateId || null,
          ],
        );
        return out.rows.map((row) => parseConfigRow(row as PgRow));
      });
    },

    async createConfig(ctx, request: CreateConsoleGasSponsorshipRequest) {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        const spendCap = normalizeSpendCap(request.spendCap);
        const callMode = normalizeCallMode(request.callMode, request.allowedCalls);
        const allowedChainIds = normalizeAllowedChainIds(request.allowedChainIds, request.allowedCalls);
        const allowedCalls = normalizeAllowedCalls(request.allowedCalls);
        const config: ConsoleGasSponsorshipConfig = {
          id: toNullableString(request.id) || makeId('gs', now),
          orgId: ctx.orgId,
          scopeType: request.scopeType,
          projectId: toNullableString(request.projectId),
          environmentId: toNullableString(request.environmentId),
          policyId: toNullableString(request.policyId),
          walletSegmentId: toNullableString(request.walletSegmentId),
          policyName: String(request.policyName || '').trim() || 'Gas Sponsorship Policy',
          templateId: toNullableString(request.templateId),
          networkClass: normalizeNetworkClass(request.networkClass),
          enabled: request.enabled ?? true,
          allowedChainIds,
          callMode,
          spendCap,
          allowedCalls: callMode === 'ALLOW_ALL' ? [] : allowedCalls,
          telemetry: {
            sponsoredTransactionCount: 0,
            failedTransactionCount: 0,
            spendMinor: 0,
            budgetUtilizationPct: 0,
          },
          createdAt: now.toISOString(),
          updatedAt: now.toISOString(),
        };
        validateScope(config);
        validatePolicyRules(config);
        const createdAtMs = nowMs(now);
        try {
          const row = await queryOne(
            q,
            `INSERT INTO console_gas_sponsorship_configs
              (namespace, org_id, id, scope_type, project_id, environment_id, policy_id, wallet_segment_id, policy_name, template_id, network_class, enabled, allowed_chain_ids, call_mode, spend_cap, allowed_calls, telemetry, created_at_ms, updated_at_ms)
             VALUES
              ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15::jsonb, $16::jsonb, $17::jsonb, $18, $18)
             RETURNING *`,
            [
              namespace,
              ctx.orgId,
              config.id,
              config.scopeType,
              config.projectId,
              config.environmentId,
              config.policyId,
              config.walletSegmentId,
              config.policyName,
              config.templateId,
              config.networkClass,
              config.enabled,
              JSON.stringify(config.allowedChainIds),
              config.callMode,
              JSON.stringify(config.spendCap),
              JSON.stringify(config.allowedCalls),
              JSON.stringify(config.telemetry),
              createdAtMs,
            ],
          );
          if (!row) {
            throw new ConsoleGasSponsorshipError('internal', 500, 'Failed to create gas sponsorship config');
          }
          return parseConfigRow(row);
        } catch (error: unknown) {
          if (isUniqueViolation(error)) {
            throw new ConsoleGasSponsorshipError(
              'config_exists',
              409,
              `Gas sponsorship config ${config.id} already exists`,
            );
          }
          throw error;
        }
      });
    },

    async updateConfig(ctx, configId: string, request: UpdateConsoleGasSponsorshipRequest) {
      return withTenantTx(ctx, async (q) => {
        const current = await findConfig(q, { orgId: ctx.orgId, id: configId });
        if (!current) return null;

        const next: ConsoleGasSponsorshipConfig = {
          ...current,
          scopeType: request.scopeType || current.scopeType,
          projectId:
            request.projectId === undefined ? current.projectId : toNullableString(request.projectId),
          environmentId:
            request.environmentId === undefined
              ? current.environmentId
              : toNullableString(request.environmentId),
          policyId: request.policyId === undefined ? current.policyId : toNullableString(request.policyId),
          walletSegmentId:
            request.walletSegmentId === undefined
              ? current.walletSegmentId
              : toNullableString(request.walletSegmentId),
          policyName:
            request.policyName === undefined
              ? current.policyName
              : String(request.policyName || '').trim() || current.policyName,
          templateId:
            request.templateId === undefined ? current.templateId : toNullableString(request.templateId),
          networkClass:
            request.networkClass === undefined
              ? current.networkClass
              : normalizeNetworkClass(request.networkClass),
          enabled: request.enabled === undefined ? current.enabled : request.enabled,
          allowedChainIds:
            request.allowedChainIds === undefined
              ? [...current.allowedChainIds]
              : normalizeAllowedChainIds(request.allowedChainIds, request.allowedCalls),
          callMode:
            request.callMode === undefined
              ? current.callMode
              : normalizeCallMode(request.callMode, request.allowedCalls),
          spendCap:
            request.spendCap === undefined
              ? current.spendCap
              : normalizeSpendCap(request.spendCap),
          allowedCalls:
            request.allowedCalls === undefined
              ? current.allowedCalls
              : normalizeAllowedCalls(request.allowedCalls),
          updatedAt: nowFn().toISOString(),
        };
        validateScope(next);
        next.allowedCalls = next.callMode === 'ALLOW_ALL' ? [] : next.allowedCalls;
        validatePolicyRules(next);

        const updatedAtMs = nowMs(new Date(next.updatedAt));
        const row = await queryOne(
          q,
          `UPDATE console_gas_sponsorship_configs
              SET scope_type = $4,
                  project_id = $5,
                  environment_id = $6,
                  policy_id = $7,
                  wallet_segment_id = $8,
                  policy_name = $9,
                  template_id = $10,
                  network_class = $11,
                  enabled = $12,
                  allowed_chain_ids = $13::jsonb,
                  call_mode = $14,
                  spend_cap = $15::jsonb,
                  allowed_calls = $16::jsonb,
                  updated_at_ms = $17
            WHERE namespace = $1
              AND org_id = $2
              AND id = $3
            RETURNING *`,
          [
            namespace,
            ctx.orgId,
            configId,
            next.scopeType,
            next.projectId,
            next.environmentId,
            next.policyId,
            next.walletSegmentId,
            next.policyName,
            next.templateId,
            next.networkClass,
            next.enabled,
            JSON.stringify(next.allowedChainIds),
            next.callMode,
            JSON.stringify(next.spendCap),
            JSON.stringify(next.allowedCalls),
            updatedAtMs,
          ],
        );
        return row ? parseConfigRow(row) : null;
      });
    },
  };
}
