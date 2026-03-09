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
  CreateConsoleSponsoredCallRecordRequest,
} from './types';
import type {
  ConsoleSponsoredCallContext,
  ConsoleSponsoredCallService,
} from './service';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_SPONSORED_CALL_MIGRATION_LOCK_ID = 9452360123592;

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

function parseRecord(row: PgRow): ConsoleSponsoredCallRecord {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    environmentId: String(row.environment_id || ''),
    apiKeyId: String(row.api_key_id || ''),
    apiKeyKind: String(row.api_key_kind || 'publishable_key') as ConsoleSponsoredCallRecord['apiKeyKind'],
    route: String(row.route || ''),
    policyId: String(row.policy_id || ''),
    chainFamily: String(row.chain_family || 'evm') as ConsoleSponsoredCallRecord['chainFamily'],
    intentKind: String(row.intent_kind || 'evm_call') as ConsoleSponsoredCallRecord['intentKind'],
    accountRef: String(row.account_ref || ''),
    targetRef: String(row.target_ref || ''),
    sponsorRef: String(row.sponsor_ref || ''),
    txOrExecutionRef: normalizeString(row.tx_or_execution_ref),
    receiptStatus: String(row.receipt_status || 'rpc_rejected') as ConsoleSponsoredCallRecord['receiptStatus'],
    feeUnit: String(row.fee_unit || 'wei') as ConsoleSponsoredCallRecord['feeUnit'],
    feeAmount: String(row.fee_amount || '0'),
    detailsJson: String(row.details_json || '{}'),
    errorCode: normalizeString(row.error_code),
    errorMessage: normalizeString(row.error_message),
    sourceEventId: normalizeString(row.source_event_id),
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
      RENAME TO console_sponsored_call_source_event_idx
    `);
    await pool.query(`
      ALTER INDEX IF EXISTS console_tempo_sponsorship_org_created_idx
      RENAME TO console_sponsored_call_org_created_idx
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_sponsored_call_records (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        id TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        api_key_id TEXT NOT NULL,
        api_key_kind TEXT NOT NULL,
        route TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        chain_family TEXT NOT NULL DEFAULT 'evm',
        intent_kind TEXT NOT NULL DEFAULT 'evm_call',
        account_ref TEXT NOT NULL DEFAULT '',
        target_ref TEXT NOT NULL DEFAULT '',
        sponsor_ref TEXT NOT NULL DEFAULT '',
        tx_or_execution_ref TEXT,
        fee_unit TEXT NOT NULL DEFAULT 'wei',
        fee_amount TEXT NOT NULL DEFAULT '0',
        details_json TEXT NOT NULL DEFAULT '{}',
        near_account_id TEXT,
        wallet_address TEXT NOT NULL,
        call_data TEXT NOT NULL,
        call_value_wei TEXT NOT NULL,
        contract_address TEXT NOT NULL,
        function_selector TEXT NOT NULL,
        chain_id INTEGER NOT NULL,
        sponsor_address TEXT NOT NULL,
        tx_hash TEXT,
        receipt_status TEXT NOT NULL,
        gas_used TEXT,
        effective_gas_price TEXT,
        spend_wei TEXT NOT NULL,
        error_code TEXT,
        error_message TEXT,
        source_event_id TEXT,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, id),
        CHECK (api_key_kind IN ('secret_key', 'publishable_key')),
        CHECK (receipt_status IN ('success', 'reverted', 'broadcast_failed', 'rpc_rejected')),
        CHECK (chain_family IN ('evm', 'near')),
        CHECK (intent_kind IN ('evm_call', 'near_delegate')),
        CHECK (fee_unit IN ('wei', 'yocto_near'))
      )
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS policy_id TEXT NOT NULL DEFAULT ''
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
      ADD COLUMN IF NOT EXISTS near_account_id TEXT
    `);
    await pool.query(`
      UPDATE console_sponsored_call_records
      SET
        chain_family = CASE WHEN coalesce(trim(chain_family), '') = '' THEN 'evm' ELSE chain_family END,
        intent_kind = CASE WHEN coalesce(trim(intent_kind), '') = '' THEN 'evm_call' ELSE intent_kind END,
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
        OR (tx_or_execution_ref IS NULL AND tx_hash IS NOT NULL AND trim(tx_hash) <> '')
        OR coalesce(trim(fee_amount), '') = ''
        OR coalesce(trim(details_json), '') = ''
        OR details_json = '{}'
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS call_data TEXT NOT NULL DEFAULT ''
    `);
    await pool.query(`
      ALTER TABLE console_sponsored_call_records
      ADD COLUMN IF NOT EXISTS call_value_wei TEXT NOT NULL DEFAULT '0'
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS console_sponsored_call_source_event_idx
      ON console_sponsored_call_records (namespace, org_id, source_event_id)
      WHERE source_event_id IS NOT NULL
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_sponsored_call_org_created_idx
      ON console_sponsored_call_records (namespace, org_id, created_at_ms DESC)
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

  return {
    async getRecordBySourceEventId(ctx, sourceEventId): Promise<ConsoleSponsoredCallRecord | null> {
      const normalized = normalizeString(sourceEventId);
      if (!normalized) return null;
      return await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (tx: Queryable) => {
        const row = await queryOne(
          tx,
          `
            SELECT *
            FROM console_sponsored_call_records
            WHERE namespace = $1
              AND org_id = $2
              AND source_event_id = $3
            LIMIT 1
          `,
          [namespace, ctx.orgId, normalized],
        );
        return row ? parseRecord(row) : null;
      });
    },

    async createRecord(ctx, request): Promise<ConsoleSponsoredCallRecord> {
      const createdAt = now();
      const createdAtMs = nowMs(createdAt);
      const recordId = normalizeString(request.id) || makeId('scr', createdAt);
      const sourceEventId = normalizeString(request.sourceEventId);
      return await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (tx: Queryable) => {
        if (sourceEventId) {
          const existing = await queryOne(
            tx,
            `
              SELECT *
              FROM console_sponsored_call_records
              WHERE namespace = $1
                AND org_id = $2
                AND source_event_id = $3
              LIMIT 1
            `,
            [namespace, ctx.orgId, sourceEventId],
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
                chain_family,
                intent_kind,
                account_ref,
                target_ref,
                sponsor_ref,
                tx_or_execution_ref,
                receipt_status,
                fee_unit,
                fee_amount,
                details_json,
                error_code,
                error_message,
                source_event_id,
                created_at_ms,
                updated_at_ms
              ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23
              )
              RETURNING *
            `,
            [
              namespace,
              ctx.orgId,
              recordId,
              String(request.environmentId || '').trim(),
              String(request.apiKeyId || '').trim(),
              request.apiKeyKind,
              String(request.route || '').trim(),
              String(request.policyId || '').trim(),
              request.chainFamily,
              request.intentKind,
              String(request.accountRef || '').trim(),
              String(request.targetRef || '').trim(),
              String(request.sponsorRef || '').trim(),
              normalizeString(request.txOrExecutionRef),
              request.receiptStatus,
              request.feeUnit,
              String(request.feeAmount || '0').trim() || '0',
              String(request.detailsJson || '{}').trim() || '{}',
              normalizeString(request.errorCode),
              normalizeString(request.errorMessage),
              sourceEventId,
              createdAtMs,
              createdAtMs,
            ],
          );
          if (!row) throw new Error('Failed to insert sponsored-call record');
          return parseRecord(row);
        } catch (error: unknown) {
          if (!sourceEventId || !isUniqueViolation(error)) throw error;
          const existing = await queryOne(
            tx,
            `
              SELECT *
              FROM console_sponsored_call_records
              WHERE namespace = $1
                AND org_id = $2
                AND source_event_id = $3
              LIMIT 1
            `,
            [namespace, ctx.orgId, sourceEventId],
          );
          if (!existing) throw error;
          return parseRecord(existing);
        }
      });
    },
  };
}
