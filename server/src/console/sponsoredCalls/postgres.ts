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
import type {
  ConsoleSponsoredCallRecord,
  ConsoleSponsoredCallRecordPage,
  ConsoleSponsoredCallOverviewSummary,
  CreateConsoleSponsoredCallRecordRequest,
  ListConsoleSponsoredCallRecordsRequest,
} from './types';
import type {
  ConsoleSponsoredCallContext,
  ConsoleSponsoredCallService,
} from './service';
import { ConsoleSponsoredCallError } from './errors';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_SPONSORED_CALL_MIGRATION_LOCK_ID = 9452360123592;
export const CONSOLE_SPONSORED_CALL_POSTGRES_RUNTIME = Symbol('consoleSponsoredCallPostgresRuntime');

export interface ConsoleSponsoredCallPostgresRuntime {
  pool: PgPool;
  namespace: string;
  now: () => Date;
}

export type ConsoleSponsoredCallPostgresService = ConsoleSponsoredCallService & {
  [CONSOLE_SPONSORED_CALL_POSTGRES_RUNTIME]: ConsoleSponsoredCallPostgresRuntime;
};

export function getConsoleSponsoredCallPostgresRuntime(
  service: ConsoleSponsoredCallService | null | undefined,
): ConsoleSponsoredCallPostgresRuntime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleSponsoredCallPostgresService>)[CONSOLE_SPONSORED_CALL_POSTGRES_RUNTIME] ||
    null
  );
}

function nowMs(now: Date): number {
  return now.getTime();
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function normalizeString(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return normalized || null;
}

function normalizeInteger(value: unknown): number | null {
  if (value == null) return null;
  const parsed = Number(value);
  if (!Number.isInteger(parsed)) return null;
  return parsed;
}

function parseRecord(row: PgRow): ConsoleSponsoredCallRecord {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    environmentId: String(row.environment_id || ''),
    apiKeyId: String(row.api_key_id || ''),
    apiKeyKind: String(row.api_key_kind || 'publishable_key') as ConsoleSponsoredCallRecord['apiKeyKind'],
    route: String(row.route || ''),
    policyId: String(row.policy_id || ''),
    policyNameAtEvent: normalizeString(row.policy_name_at_event),
    templateId: normalizeString(row.template_id),
    chainFamily: String(row.chain_family || 'evm') as ConsoleSponsoredCallRecord['chainFamily'],
    intentKind: String(row.intent_kind || 'evm_call') as ConsoleSponsoredCallRecord['intentKind'],
    executorKind: String(row.executor_kind || 'evm_eoa') as ConsoleSponsoredCallRecord['executorKind'],
    accountRef: String(row.account_ref || ''),
    targetRef: String(row.target_ref || ''),
    sponsorRef: String(row.sponsor_ref || ''),
    txOrExecutionRef: normalizeString(row.tx_or_execution_ref),
    receiptStatus: String(row.receipt_status || 'rpc_rejected') as ConsoleSponsoredCallRecord['receiptStatus'],
    feeUnit: String(row.fee_unit || 'wei') as ConsoleSponsoredCallRecord['feeUnit'],
    feeAmount: String(row.fee_amount || '0'),
    detailsJson: String(row.details_json || '{}'),
    estimatedSpendMinor:
      row.estimated_spend_minor == null ? null : Math.max(0, toNumber(row.estimated_spend_minor)),
    settledSpendMinor:
      row.settled_spend_minor == null ? null : Math.max(0, toNumber(row.settled_spend_minor)),
    pricingVersion: normalizeString(row.pricing_version),
    pricingSource: normalizeString(row.pricing_source),
    billingLedgerEntryId: normalizeString(row.billing_ledger_entry_id),
    prepaidReservationId: normalizeString(row.prepaid_reservation_id),
    charged: Boolean(row.charged),
    chargedReason: normalizeString(row.charged_reason),
    settledAt: normalizeString(row.settled_at_iso),
    errorCode: normalizeString(row.error_code),
    errorMessage: normalizeString(row.error_message),
    idempotencyKey: normalizeString(row.idempotency_key),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const result = await q.query(text, values);
  return (result.rows[0] as PgRow) || null;
}

function isUniqueViolation(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && (error as { code?: unknown }).code === '23505');
}

const DEFAULT_LIST_LIMIT = 25;
const MAX_LIST_LIMIT = 100;
const DEFAULT_LOOKBACK_DAYS = 90;
const MAX_LOOKBACK_DAYS = 365;

function normalizePositiveInteger(value: unknown, fallback: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.max(1, Math.min(max, Math.trunc(parsed)));
}

function parseListCursor(cursor: string | undefined): { createdAtMs: number; id: string } | null {
  const raw = String(cursor || '').trim();
  if (!raw) return null;
  const separator = raw.indexOf(':');
  if (separator <= 0 || separator >= raw.length - 1) {
    throw new ConsoleSponsoredCallError('invalid_query', 400, 'Invalid sponsored call cursor format');
  }
  const createdAtMs = Number.parseInt(raw.slice(0, separator), 10);
  const id = raw.slice(separator + 1).trim();
  if (!Number.isFinite(createdAtMs) || !id) {
    throw new ConsoleSponsoredCallError('invalid_query', 400, 'Invalid sponsored call cursor format');
  }
  return { createdAtMs, id };
}

function buildListCursor(record: ConsoleSponsoredCallRecord): string {
  return `${Date.parse(record.createdAt)}:${record.id}`;
}

interface NormalizedSponsoredCallListRequest {
  environmentId?: string;
  policyId?: string;
  chainFamily?: ListConsoleSponsoredCallRecordsRequest['chainFamily'];
  receiptStatus?: ListConsoleSponsoredCallRecordsRequest['receiptStatus'];
  charged?: boolean;
  limit: number;
  lookbackDays: number;
  cursor: { createdAtMs: number; id: string } | null;
}

function normalizeListRequest(
  request: ListConsoleSponsoredCallRecordsRequest | undefined,
): NormalizedSponsoredCallListRequest {
  return {
    ...(normalizeString(request?.environmentId)
      ? { environmentId: normalizeString(request?.environmentId)! }
      : {}),
    ...(normalizeString(request?.policyId)
      ? { policyId: normalizeString(request?.policyId)! }
      : {}),
    chainFamily: request?.chainFamily,
    receiptStatus: request?.receiptStatus,
    charged: typeof request?.charged === 'boolean' ? request.charged : undefined,
    limit: normalizePositiveInteger(request?.limit, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT),
    lookbackDays: normalizePositiveInteger(
      request?.lookbackDays,
      DEFAULT_LOOKBACK_DAYS,
      MAX_LOOKBACK_DAYS,
    ),
    cursor: parseListCursor(request?.cursor),
  };
}

export interface PostgresConsoleSponsoredCallSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleSponsoredCallPostgresSchema(
  options: PostgresConsoleSponsoredCallSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_SPONSORED_CALL_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      ALTER TABLE IF EXISTS console_tempo_sponsorship_records
      RENAME TO console_sponsored_call_records
    `);
    await pool.query(`
      ALTER INDEX IF EXISTS console_tempo_sponsorship_source_event_idx
      RENAME TO console_sponsored_call_idempotency_key_idx
    `);
    await pool.query(`
      ALTER INDEX IF EXISTS console_tempo_sponsorship_org_created_idx
      RENAME TO console_sponsored_call_org_created_idx
    `);
    await pool.query(`
      ALTER INDEX IF EXISTS console_sponsored_call_source_event_idx
      RENAME TO console_sponsored_call_idempotency_key_idx
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      RENAME COLUMN source_event_id TO idempotency_key
    `).catch(() => {});
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_sponsored_call_records (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        id TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        api_key_id TEXT NOT NULL,
        api_key_kind TEXT NOT NULL,
        route TEXT NOT NULL,
        chain_family TEXT NOT NULL DEFAULT 'evm',
        intent_kind TEXT NOT NULL DEFAULT 'evm_call',
        executor_kind TEXT NOT NULL DEFAULT 'evm_eoa',
        account_ref TEXT NOT NULL DEFAULT '',
        target_ref TEXT NOT NULL DEFAULT '',
        sponsor_ref TEXT NOT NULL DEFAULT '',
        tx_or_execution_ref TEXT,
        policy_id TEXT NOT NULL DEFAULT '',
        policy_name_at_event TEXT,
        template_id TEXT,
        receipt_status TEXT NOT NULL,
        fee_unit TEXT NOT NULL DEFAULT 'wei',
        fee_amount TEXT NOT NULL DEFAULT '0',
        details_json TEXT NOT NULL DEFAULT '{}',
        error_code TEXT,
        error_message TEXT,
        idempotency_key TEXT,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, id),
        CHECK (api_key_kind IN ('secret_key', 'publishable_key')),
        CHECK (receipt_status IN ('success', 'reverted', 'broadcast_failed', 'rpc_rejected')),
        CHECK (chain_family IN ('evm', 'near')),
        CHECK (intent_kind IN ('evm_call', 'near_delegate')),
        CHECK (executor_kind IN ('evm_eoa', 'near_delegate')),
        CHECK (fee_unit IN ('wei', 'yocto_near'))
      )
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS policy_id TEXT NOT NULL DEFAULT ''
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS policy_name_at_event TEXT
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS template_id TEXT
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS chain_family TEXT NOT NULL DEFAULT 'evm'
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS intent_kind TEXT NOT NULL DEFAULT 'evm_call'
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS executor_kind TEXT NOT NULL DEFAULT 'evm_eoa'
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS account_ref TEXT NOT NULL DEFAULT ''
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS target_ref TEXT NOT NULL DEFAULT ''
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS sponsor_ref TEXT NOT NULL DEFAULT ''
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS tx_or_execution_ref TEXT
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS fee_unit TEXT NOT NULL DEFAULT 'wei'
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS fee_amount TEXT NOT NULL DEFAULT '0'
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS details_json TEXT NOT NULL DEFAULT '{}'
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS estimated_spend_minor BIGINT
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS settled_spend_minor BIGINT
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS pricing_version TEXT
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS pricing_source TEXT
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS billing_ledger_entry_id TEXT
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS prepaid_reservation_id TEXT
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS charged BOOLEAN NOT NULL DEFAULT FALSE
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS charged_reason TEXT
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS settled_at_iso TEXT
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS idempotency_key TEXT
    `);
    const idempotencyLegacyColumnsResult = await pool.query(
      `
        SELECT column_name
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'console_sponsored_call_records'
           AND column_name = ANY($1::text[])
      `,
      [['source_event_id', 'idempotency_key']],
    );
    const idempotencyLegacyColumns = new Set(
      idempotencyLegacyColumnsResult.rows.map((row) =>
        String((row as { column_name?: unknown }).column_name || ''),
      ),
    );
    if (idempotencyLegacyColumns.has('source_event_id')) {
      await pool.query(`
        UPDATE console_sponsored_call_records
        SET idempotency_key = CASE
          WHEN coalesce(trim(idempotency_key), '') <> '' THEN idempotency_key
          ELSE nullif(trim(source_event_id), '')
        END
        WHERE source_event_id IS NOT NULL
      `);
      await pool.query(`
        ALTER TABLE console_sponsored_call_records
        DROP COLUMN IF EXISTS source_event_id
      `);
    }
    const legacyColumnsResult = await pool.query(
      `
        SELECT column_name
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'console_sponsored_call_records'
           AND column_name = ANY($1::text[])
      `,
      [
        [
          'wallet_id',
          'wallet_address',
          'token_addresses',
          'contract_address',
          'function_selector',
          'chain_id',
          'sponsor_address',
          'tx_hash',
          'gas_used',
          'effective_gas_price',
          'spend_wei',
          'near_account_id',
          'call_data',
          'call_value_wei',
          'sponsorship_config_id',
        ],
      ],
    );
    const legacyColumns = new Set(
      legacyColumnsResult.rows.map((row) => String((row as { column_name?: unknown }).column_name || '')),
    );
    if (legacyColumns.has('sponsorship_config_id')) {
      await pool.query(`
        UPDATE console_sponsored_call_records
        SET policy_id = CASE
          WHEN coalesce(trim(policy_id), '') <> '' THEN policy_id
          ELSE coalesce(nullif(trim(sponsorship_config_id), ''), policy_id)
        END
        WHERE coalesce(trim(policy_id), '') = ''
      `);
    }
    const legacyEvmShapeColumns = [
      'wallet_address',
      'contract_address',
      'function_selector',
      'chain_id',
      'sponsor_address',
      'tx_hash',
      'gas_used',
      'effective_gas_price',
      'spend_wei',
      'near_account_id',
      'call_data',
      'call_value_wei',
    ];
    if (legacyEvmShapeColumns.every((column) => legacyColumns.has(column))) {
      await pool.query(`
        UPDATE console_sponsored_call_records
        SET
          chain_family = CASE WHEN coalesce(trim(chain_family), '') = '' THEN 'evm' ELSE chain_family END,
          intent_kind = CASE WHEN coalesce(trim(intent_kind), '') = '' THEN 'evm_call' ELSE intent_kind END,
          executor_kind = CASE
            WHEN coalesce(trim(executor_kind), '') <> '' THEN executor_kind
            WHEN coalesce(trim(intent_kind), '') = 'near_delegate' THEN 'near_delegate'
            ELSE 'evm_eoa'
          END,
          account_ref = CASE
            WHEN coalesce(trim(account_ref), '') <> '' THEN account_ref
            WHEN coalesce(trim(near_account_id), '') <> '' THEN 'near:' || trim(near_account_id)
            WHEN coalesce(trim(wallet_address), '') <> '' THEN 'evm_wallet:' || lower(trim(wallet_address))
            ELSE ''
          END,
          target_ref = CASE
            WHEN coalesce(trim(target_ref), '') <> '' THEN target_ref
            WHEN coalesce(trim(contract_address), '') <> '' AND coalesce(chain_id, 0) > 0
              THEN 'evm:' || chain_id::text || ':' || lower(trim(contract_address))
            ELSE ''
          END,
          sponsor_ref = CASE
            WHEN coalesce(trim(sponsor_ref), '') <> '' THEN sponsor_ref
            WHEN coalesce(trim(sponsor_address), '') <> '' AND coalesce(chain_id, 0) > 0
              THEN 'evm:' || chain_id::text || ':' || lower(trim(sponsor_address))
            ELSE ''
          END,
          tx_or_execution_ref = CASE
            WHEN tx_or_execution_ref IS NOT NULL AND trim(tx_or_execution_ref) <> '' THEN tx_or_execution_ref
            WHEN tx_hash IS NOT NULL AND trim(tx_hash) <> '' THEN tx_hash
            ELSE NULL
          END,
          fee_unit = CASE WHEN coalesce(trim(fee_unit), '') = '' THEN 'wei' ELSE fee_unit END,
          fee_amount = CASE
            WHEN coalesce(trim(fee_amount), '') <> '' THEN fee_amount
            WHEN coalesce(trim(spend_wei), '') <> '' THEN spend_wei
            ELSE '0'
          END,
          details_json = CASE
            WHEN coalesce(trim(details_json), '') <> '' AND details_json <> '{}' THEN details_json
            ELSE jsonb_build_object(
              'nearAccountId', near_account_id,
              'walletAddress', wallet_address,
              'chainId', chain_id,
              'call', jsonb_build_object(
                'to', contract_address,
                'data', call_data,
                'valueWei', call_value_wei,
                'selector', function_selector
              ),
              'execution', jsonb_build_object(
                'txHash', tx_hash,
                'gasUsed', gas_used,
                'effectiveGasPrice', effective_gas_price,
                'feeAmount', spend_wei
              )
            )::text
          END
        WHERE
          coalesce(trim(account_ref), '') = ''
          OR coalesce(trim(target_ref), '') = ''
          OR coalesce(trim(sponsor_ref), '') = ''
          OR coalesce(trim(executor_kind), '') = ''
          OR (tx_or_execution_ref IS NULL AND tx_hash IS NOT NULL AND trim(tx_hash) <> '')
          OR coalesce(trim(fee_amount), '') = ''
          OR coalesce(trim(details_json), '') = ''
          OR details_json = '{}'
      `);
    }
    const legacyDropColumns = Array.from(legacyColumns).filter((column) =>
      [
        'wallet_id',
        'wallet_address',
        'token_addresses',
        'contract_address',
        'function_selector',
        'chain_id',
        'sponsor_address',
        'tx_hash',
        'gas_used',
        'effective_gas_price',
        'spend_wei',
        'near_account_id',
        'call_data',
        'call_value_wei',
        'sponsorship_config_id',
      ].includes(column),
    );
    if (legacyDropColumns.length > 0) {
      await pool.query(
        `ALTER TABLE console_sponsored_call_records\n${legacyDropColumns
          .map((column, index) => `${index === 0 ? '' : ','}DROP COLUMN IF EXISTS ${column}`)
          .join('\n')}`,
      );
    }
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS console_sponsored_call_idempotency_key_idx
      ON console_sponsored_call_records (namespace, org_id, idempotency_key)
      WHERE idempotency_key IS NOT NULL
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_sponsored_call_org_created_idx
      ON console_sponsored_call_records (namespace, org_id, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_sponsored_call_org_environment_created_idx
      ON console_sponsored_call_records (namespace, org_id, environment_id, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_sponsored_call_org_policy_created_idx
      ON console_sponsored_call_records (namespace, org_id, policy_id, created_at_ms DESC)
    `);
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_sponsored_call_records',
      policyName: 'console_sponsored_call_records_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_SPONSORED_CALL_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }
  options.logger.info('[console-sponsored-call][postgres] Schema ready');
}

export interface PostgresConsoleSponsoredCallServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleSponsoredCallService(
  options: PostgresConsoleSponsoredCallServiceOptions,
): Promise<ConsoleSponsoredCallService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres sponsored-call service');
  }
  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const now = options.now || (() => new Date());
  if (options.ensureSchema !== false) {
    await ensureConsoleSponsoredCallPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }
  const pool = await getPostgresPool(postgresUrl);

  const runtime: ConsoleSponsoredCallPostgresRuntime = {
    pool,
    namespace,
    now,
  };

  const service: ConsoleSponsoredCallPostgresService = {
    async getOverviewSummary(ctx): Promise<ConsoleSponsoredCallOverviewSummary> {
      return await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (tx: Queryable) => {
        const trailing30MinCreatedAtMs = now().getTime() - 30 * 24 * 60 * 60 * 1000;
        const trailing90MinCreatedAtMs = now().getTime() - 90 * 24 * 60 * 60 * 1000;
        const row = await queryOne(
          tx,
          `
            SELECT
              COALESCE(COUNT(*) FILTER (WHERE charged AND created_at_ms >= $3), 0)::BIGINT AS trailing_30_count,
              COALESCE(SUM(CASE WHEN charged AND created_at_ms >= $3 THEN COALESCE(settled_spend_minor, 0) ELSE 0 END), 0)::BIGINT AS trailing_30_spend_minor,
              COALESCE(COUNT(*) FILTER (WHERE charged AND created_at_ms >= $4), 0)::BIGINT AS trailing_90_count,
              COALESCE(SUM(CASE WHEN charged AND created_at_ms >= $4 THEN COALESCE(settled_spend_minor, 0) ELSE 0 END), 0)::BIGINT AS trailing_90_spend_minor
            FROM console_sponsored_call_records
            WHERE namespace = $1
              AND org_id = $2
              AND created_at_ms >= $4
          `,
          [namespace, ctx.orgId, trailing30MinCreatedAtMs, trailing90MinCreatedAtMs],
        );
        return {
          trailing30Days: {
            lookbackDays: 30,
            chargedExecutionCount: Math.max(0, toNumber(row?.trailing_30_count)),
            chargedSettledSpendMinor: Math.max(0, toNumber(row?.trailing_30_spend_minor)),
          },
          trailing90Days: {
            lookbackDays: 90,
            chargedExecutionCount: Math.max(0, toNumber(row?.trailing_90_count)),
            chargedSettledSpendMinor: Math.max(0, toNumber(row?.trailing_90_spend_minor)),
          },
        };
      });
    },

    async listRecords(ctx, request = {}): Promise<ConsoleSponsoredCallRecordPage> {
      const normalized = normalizeListRequest(request);
      return await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (tx: Queryable) => {
        const values: unknown[] = [namespace, ctx.orgId];
        const whereClauses = ['namespace = $1', 'org_id = $2'];
        const minCreatedAtMs = now().getTime() - normalized.lookbackDays * 24 * 60 * 60 * 1000;
        values.push(minCreatedAtMs);
        whereClauses.push(`created_at_ms >= $${values.length}`);
        if (normalized.environmentId) {
          values.push(normalized.environmentId);
          whereClauses.push(`environment_id = $${values.length}`);
        }
        if (normalized.policyId) {
          values.push(normalized.policyId);
          whereClauses.push(`policy_id = $${values.length}`);
        }
        if (normalized.chainFamily) {
          values.push(normalized.chainFamily);
          whereClauses.push(`chain_family = $${values.length}`);
        }
        if (normalized.receiptStatus) {
          values.push(normalized.receiptStatus);
          whereClauses.push(`receipt_status = $${values.length}`);
        }
        if (normalized.charged !== undefined) {
          values.push(normalized.charged);
          whereClauses.push(`charged = $${values.length}`);
        }
        if (normalized.cursor) {
          values.push(normalized.cursor.createdAtMs, normalized.cursor.id);
          whereClauses.push(
            `(created_at_ms < $${values.length - 1} OR (created_at_ms = $${values.length - 1} AND id < $${values.length}))`,
          );
        }
        values.push(normalized.limit + 1);
        const result = await tx.query(
          `
            SELECT *
            FROM console_sponsored_call_records
            WHERE ${whereClauses.join(' AND ')}
            ORDER BY created_at_ms DESC, id DESC
            LIMIT $${values.length}
          `,
          values,
        );
        const rows = (result.rows as PgRow[]).map(parseRecord);
        const items = rows.slice(0, normalized.limit);
        return {
          items,
          nextCursor:
            rows.length > normalized.limit && items.length > 0
              ? buildListCursor(items[items.length - 1]!)
              : null,
        };
      });
    },

    async getRecordByIdempotencyKey(ctx, idempotencyKey): Promise<ConsoleSponsoredCallRecord | null> {
      const normalized = normalizeString(idempotencyKey);
      if (!normalized) return null;
      return await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (tx: Queryable) => {
        const row = await queryOne(
          tx,
          `
            SELECT *
            FROM console_sponsored_call_records
            WHERE namespace = $1
              AND org_id = $2
              AND idempotency_key = $3
            LIMIT 1
          `,
          [namespace, ctx.orgId, normalized],
        );
        return row ? parseRecord(row) : null;
      });
    },

    async createRecord(ctx, request): Promise<ConsoleSponsoredCallRecord> {
      return await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (tx: Queryable) =>
        createConsoleSponsoredCallRecordTx(tx, {
          namespace,
          ctx,
          now,
          request,
        }),
      );
    },
    [CONSOLE_SPONSORED_CALL_POSTGRES_RUNTIME]: runtime,
  };

  return service;
}

export async function createConsoleSponsoredCallRecordTx(
  tx: Queryable,
  input: {
    namespace: string;
    ctx: ConsoleSponsoredCallContext;
    now: () => Date;
    request: CreateConsoleSponsoredCallRecordRequest;
  },
): Promise<ConsoleSponsoredCallRecord> {
  const createdAt = input.now();
  const createdAtMs = nowMs(createdAt);
  const recordId = normalizeString(input.request.id) || makeId('scr', createdAt);
  const idempotencyKey = normalizeString(input.request.idempotencyKey);
  if (idempotencyKey) {
    const existing = await queryOne(
      tx,
      `
        SELECT *
        FROM console_sponsored_call_records
        WHERE namespace = $1
          AND org_id = $2
          AND idempotency_key = $3
        LIMIT 1
      `,
      [input.namespace, input.ctx.orgId, idempotencyKey],
    );
    if (existing) return parseRecord(existing);
  }
  try {
    const row = await queryOne(
      tx,
      `
        INSERT INTO console_sponsored_call_records (
          namespace,
          org_id,
          id,
          environment_id,
          api_key_id,
          api_key_kind,
          route,
          policy_id,
          policy_name_at_event,
          template_id,
          chain_family,
          intent_kind,
          executor_kind,
          account_ref,
          target_ref,
          sponsor_ref,
          tx_or_execution_ref,
          receipt_status,
          fee_unit,
          fee_amount,
          details_json,
          estimated_spend_minor,
          settled_spend_minor,
          pricing_version,
          pricing_source,
          billing_ledger_entry_id,
          prepaid_reservation_id,
          charged,
          charged_reason,
          settled_at_iso,
          error_code,
          error_message,
          idempotency_key,
          created_at_ms,
          updated_at_ms
        ) VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35
        )
        RETURNING *
      `,
      [
        input.namespace,
        input.ctx.orgId,
        recordId,
        String(input.request.environmentId || '').trim(),
        String(input.request.apiKeyId || '').trim(),
        input.request.apiKeyKind,
        String(input.request.route || '').trim(),
        String(input.request.policyId || '').trim(),
        normalizeString(input.request.policyNameAtEvent),
        normalizeString(input.request.templateId),
        input.request.chainFamily,
        input.request.intentKind,
        input.request.executorKind,
        String(input.request.accountRef || '').trim(),
        String(input.request.targetRef || '').trim(),
        String(input.request.sponsorRef || '').trim(),
        normalizeString(input.request.txOrExecutionRef),
        input.request.receiptStatus,
        input.request.feeUnit,
        String(input.request.feeAmount || '0').trim() || '0',
        String(input.request.detailsJson || '{}').trim() || '{}',
        normalizeInteger(input.request.estimatedSpendMinor),
        normalizeInteger(input.request.settledSpendMinor),
        normalizeString(input.request.pricingVersion),
        normalizeString(input.request.pricingSource),
        normalizeString(input.request.billingLedgerEntryId),
        normalizeString(input.request.prepaidReservationId),
        Boolean(input.request.charged),
        normalizeString(input.request.chargedReason),
        normalizeString(input.request.settledAt),
        normalizeString(input.request.errorCode),
        normalizeString(input.request.errorMessage),
        idempotencyKey,
        createdAtMs,
        createdAtMs,
      ],
    );
    if (!row) throw new Error('Failed to insert sponsored-call record');
    return parseRecord(row);
  } catch (error: unknown) {
    if (!idempotencyKey || !isUniqueViolation(error)) throw error;
    const existing = await queryOne(
      tx,
      `
        SELECT *
        FROM console_sponsored_call_records
        WHERE namespace = $1
          AND org_id = $2
          AND idempotency_key = $3
        LIMIT 1
      `,
      [input.namespace, input.ctx.orgId, idempotencyKey],
    );
    if (!existing) throw error;
    return parseRecord(existing);
  }
}
