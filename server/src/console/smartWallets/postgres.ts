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
import { ConsoleSmartWalletError } from './errors';
import type {
  ConsoleSmartWalletConfig,
  CreateConsoleSmartWalletRequest,
  UpdateConsoleSmartWalletRequest,
} from './types';
import type { ConsoleSmartWalletContext, ConsoleSmartWalletService } from './service';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_SMART_WALLETS_MIGRATION_LOCK_ID = 9452360123592;

function nowMs(now: Date): number {
  return now.getTime();
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function parseJsonObject(raw: unknown): Record<string, unknown> | null {
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
      return null;
    }
  }
  return null;
}

function toNullableString(raw: unknown): string | null {
  const value = String(raw || '').trim();
  return value || null;
}

function parseConfigRow(row: PgRow): ConsoleSmartWalletConfig {
  const bundler = parseJsonObject(row.bundler);
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    scopeType: String(row.scope_type || 'ORG') as ConsoleSmartWalletConfig['scopeType'],
    projectId: toNullableString(row.project_id),
    environmentId: toNullableString(row.environment_id),
    policyId: toNullableString(row.policy_id),
    policyName: null,
    walletSegmentId: toNullableString(row.wallet_segment_id),
    enabled: row.enabled !== false,
    mode: String(row.mode || 'OPTIONAL') as ConsoleSmartWalletConfig['mode'],
    accountType: String(row.account_type || 'SMART_ACCOUNT') as ConsoleSmartWalletConfig['accountType'],
    paymasterMode: String(row.paymaster_mode || 'AUTO') as ConsoleSmartWalletConfig['paymasterMode'],
    fallbackBehavior: String(row.fallback_behavior || 'FALLBACK_TO_EOA') as ConsoleSmartWalletConfig['fallbackBehavior'],
    bundler: bundler
      ? {
          provider: String(bundler.provider || '').trim(),
          entryPointVersion: String(bundler.entryPointVersion || 'v0.7') as NonNullable<
            ConsoleSmartWalletConfig['bundler']
          >['entryPointVersion'],
          maxFeePerGasGwei: Math.max(0, toNumber(bundler.maxFeePerGasGwei, 0)),
          maxPriorityFeePerGasGwei: Math.max(0, toNumber(bundler.maxPriorityFeePerGasGwei, 0)),
        }
      : null,
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

function validateScope(config: {
  scopeType: ConsoleSmartWalletConfig['scopeType'];
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
  throw new ConsoleSmartWalletError(
    'invalid_scope',
    400,
    `Scope ${config.scopeType} is missing a required identifier`,
  );
}

function normalizeBundler(
  input: ConsoleSmartWalletConfig['bundler'] | undefined,
): ConsoleSmartWalletConfig['bundler'] | null {
  if (!input) return null;
  return {
    provider: String(input.provider || '').trim(),
    entryPointVersion: input.entryPointVersion,
    maxFeePerGasGwei: Math.max(0, Number(input.maxFeePerGasGwei || 0)),
    maxPriorityFeePerGasGwei: Math.max(0, Number(input.maxPriorityFeePerGasGwei || 0)),
  };
}

function isUniqueViolation(error: unknown): boolean {
  return !!error && typeof error === 'object' && (error as any).code === '23505';
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

async function findPolicyName(
  q: Queryable,
  input: { namespace: string; orgId: string; policyId: string | null },
): Promise<string | null> {
  if (!input.policyId) return null;
  const row = await queryOne(
    q,
    `SELECT name
       FROM console_policies
      WHERE namespace = $1 AND org_id = $2 AND id = $3`,
    [input.namespace, input.orgId, input.policyId],
  );
  if (!row) return null;
  return String(row.name || '').trim() || input.policyId;
}

export interface PostgresConsoleSmartWalletSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleSmartWalletsPostgresSchema(
  options: PostgresConsoleSmartWalletSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_SMART_WALLETS_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_smart_wallet_configs (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        id TEXT NOT NULL,
        scope_type TEXT NOT NULL,
        project_id TEXT,
        environment_id TEXT,
        policy_id TEXT,
        wallet_segment_id TEXT,
        enabled BOOLEAN NOT NULL,
        mode TEXT NOT NULL,
        account_type TEXT NOT NULL,
        paymaster_mode TEXT NOT NULL,
        fallback_behavior TEXT NOT NULL,
        bundler JSONB,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, id),
        CHECK (scope_type IN ('ORG', 'PROJECT', 'ENVIRONMENT', 'POLICY', 'WALLET_SEGMENT')),
        CHECK (mode IN ('DISABLED', 'OPTIONAL', 'REQUIRED')),
        CHECK (account_type IN ('EOA', 'SMART_ACCOUNT')),
        CHECK (paymaster_mode IN ('DISABLED', 'AUTO', 'REQUIRED')),
        CHECK (fallback_behavior IN ('FAIL_CLOSED', 'FALLBACK_TO_EOA')),
        CHECK (bundler IS NULL OR jsonb_typeof(bundler) = 'object')
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_smart_wallet_org_updated_idx
      ON console_smart_wallet_configs (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_smart_wallet_org_scope_idx
      ON console_smart_wallet_configs (namespace, org_id, scope_type)
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_smart_wallet_configs',
      policyName: 'console_smart_wallet_configs_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_SMART_WALLETS_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }

  options.logger.info('[console-smart-wallets][postgres] Schema ready');
}

export interface PostgresConsoleSmartWalletServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleSmartWalletService(
  options: PostgresConsoleSmartWalletServiceOptions,
): Promise<ConsoleSmartWalletService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console smart wallet service');
  }

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());

  if (options.ensureSchema !== false) {
    await ensureConsoleSmartWalletsPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);
  const withTenantTx = <T>(
    ctx: ConsoleSmartWalletContext,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, fn);

  async function findConfig(
    q: Queryable,
    input: { orgId: string; id: string },
  ): Promise<ConsoleSmartWalletConfig | null> {
    const row = await queryOne(
      q,
      `SELECT *
         FROM console_smart_wallet_configs
        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
      [namespace, input.orgId, input.id],
    );
    return row ? parseConfigRow(row) : null;
  }

  async function requirePolicyName(
    q: Queryable,
    ctx: ConsoleSmartWalletContext,
    policyId: string | null,
  ): Promise<string | null> {
    if (!policyId) return null;
    const policyName = await findPolicyName(q, { namespace, orgId: ctx.orgId, policyId });
    if (!policyName) {
      throw new ConsoleSmartWalletError(
        'policy_not_found',
        404,
        `Policy ${policyId} was not found`,
      );
    }
    return policyName;
  }

  async function projectConfig(
    q: Queryable,
    ctx: ConsoleSmartWalletContext,
    config: ConsoleSmartWalletConfig,
  ): Promise<ConsoleSmartWalletConfig> {
    return {
      ...config,
      bundler: config.bundler ? { ...config.bundler } : null,
      policyName: await findPolicyName(q, { namespace, orgId: ctx.orgId, policyId: config.policyId }),
    };
  }

  return {
    async listConfigs(ctx, request = {}) {
      return withTenantTx(ctx, async (q) => {
        const out = await q.query(
          `SELECT *
             FROM console_smart_wallet_configs
            WHERE namespace = $1
              AND org_id = $2
              AND ($3::text IS NULL OR scope_type = $3::text)
              AND ($4::text IS NULL OR project_id = $4::text)
              AND ($5::text IS NULL OR environment_id = $5::text)
              AND ($6::text IS NULL OR policy_id = $6::text)
              AND ($7::text IS NULL OR wallet_segment_id = $7::text)
            ORDER BY updated_at_ms DESC, created_at_ms DESC`,
          [
            namespace,
            ctx.orgId,
            request.scopeType || null,
            request.projectId || null,
            request.environmentId || null,
            request.policyId || null,
            request.walletSegmentId || null,
          ],
        );
        return await Promise.all(
          out.rows.map(async (row) => await projectConfig(q, ctx, parseConfigRow(row as PgRow))),
        );
      });
    },

    async createConfig(ctx, request: CreateConsoleSmartWalletRequest) {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        const config: ConsoleSmartWalletConfig = {
          id: toNullableString(request.id) || makeId('sw', now),
          orgId: ctx.orgId,
          scopeType: request.scopeType,
          projectId: toNullableString(request.projectId),
          environmentId: toNullableString(request.environmentId),
          policyId: toNullableString(request.policyId),
          policyName: null,
          walletSegmentId: toNullableString(request.walletSegmentId),
          enabled: request.enabled ?? true,
          mode: request.mode || 'OPTIONAL',
          accountType: request.accountType || 'SMART_ACCOUNT',
          paymasterMode: request.paymasterMode || 'AUTO',
          fallbackBehavior: request.fallbackBehavior || 'FALLBACK_TO_EOA',
          bundler: normalizeBundler(request.bundler),
          createdAt: now.toISOString(),
          updatedAt: now.toISOString(),
        };
        validateScope(config);
        config.policyName = await requirePolicyName(q, ctx, config.policyId);
        const createdAtMs = nowMs(now);

        try {
          const row = await queryOne(
            q,
            `INSERT INTO console_smart_wallet_configs
              (namespace, org_id, id, scope_type, project_id, environment_id, policy_id, wallet_segment_id, enabled, mode, account_type, paymaster_mode, fallback_behavior, bundler, created_at_ms, updated_at_ms)
             VALUES
              ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15, $15)
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
              config.enabled,
              config.mode,
              config.accountType,
              config.paymasterMode,
              config.fallbackBehavior,
              config.bundler ? JSON.stringify(config.bundler) : null,
              createdAtMs,
            ],
          );
          if (!row) {
            throw new ConsoleSmartWalletError('internal', 500, 'Failed to create smart wallet config');
          }
          return await projectConfig(q, ctx, parseConfigRow(row));
        } catch (error: unknown) {
          if (isUniqueViolation(error)) {
            throw new ConsoleSmartWalletError(
              'config_exists',
              409,
              `Smart-wallet config ${config.id} already exists`,
            );
          }
          throw error;
        }
      });
    },

    async updateConfig(ctx, configId: string, request: UpdateConsoleSmartWalletRequest) {
      return withTenantTx(ctx, async (q) => {
        const current = await findConfig(q, { orgId: ctx.orgId, id: configId });
        if (!current) return null;

        const next: ConsoleSmartWalletConfig = {
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
          enabled: request.enabled === undefined ? current.enabled : request.enabled,
          mode: request.mode || current.mode,
          accountType: request.accountType || current.accountType,
          paymasterMode: request.paymasterMode || current.paymasterMode,
          fallbackBehavior: request.fallbackBehavior || current.fallbackBehavior,
          bundler:
            request.bundler === undefined ? current.bundler : normalizeBundler(request.bundler),
          updatedAt: nowFn().toISOString(),
        };
        validateScope(next);
        next.policyName = await requirePolicyName(q, ctx, next.policyId);

        const updatedAtMs = nowMs(new Date(next.updatedAt));
        const row = await queryOne(
          q,
          `UPDATE console_smart_wallet_configs
              SET scope_type = $4,
                  project_id = $5,
                  environment_id = $6,
                  policy_id = $7,
                  wallet_segment_id = $8,
                  enabled = $9,
                  mode = $10,
                  account_type = $11,
                  paymaster_mode = $12,
                  fallback_behavior = $13,
                  bundler = $14::jsonb,
                  updated_at_ms = $15
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
            next.enabled,
            next.mode,
            next.accountType,
            next.paymasterMode,
            next.fallbackBehavior,
            next.bundler ? JSON.stringify(next.bundler) : null,
            updatedAtMs,
          ],
        );
        return row ? await projectConfig(q, ctx, parseConfigRow(row)) : null;
      });
    },
  };
}
