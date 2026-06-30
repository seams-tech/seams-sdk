import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import { d1Number as toNumber, queryD1All, queryD1One, type D1Row } from '../../storage/d1Sql';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../storage/tenantRoute';
import { ConsoleSponsoredCallError } from './errors';
import type {
  ConsoleSponsoredCallApiKeyKind,
  ConsoleSponsoredCallChainFamily,
  ConsoleSponsoredCallExecutorKind,
  ConsoleSponsoredCallFeeUnit,
  ConsoleSponsoredCallIntentKind,
  ConsoleSponsoredCallReceiptStatus,
  ConsoleSponsoredCallRecord,
  ConsoleSponsoredCallRecordPage,
  ConsoleSponsoredCallOverviewSummary,
  CreateConsoleSponsoredCallRecordRequest,
  ListConsoleSponsoredCallRecordsRequest,
} from './types';
import type { ConsoleSponsoredCallContext, ConsoleSponsoredCallService } from './service';

export const CONSOLE_SPONSORED_CALL_D1_RUNTIME = Symbol('consoleSponsoredCallD1Runtime');

export interface ConsoleSponsoredCallD1Runtime {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
}

export type ConsoleSponsoredCallD1Service = ConsoleSponsoredCallService & {
  [CONSOLE_SPONSORED_CALL_D1_RUNTIME]: ConsoleSponsoredCallD1Runtime;
};

export interface D1ConsoleSponsoredCallServiceOptions {
  database: D1DatabaseLike;
  namespace?: string;
  now?: () => Date;
}


type D1SponsoredCallInsertGuard = {
  readonly kind: 'previous_statement_changed_one';
};

interface NormalizedSponsoredCallListRequest {
  readonly environmentId?: string;
  readonly policyId?: string;
  readonly chainFamily?: ConsoleSponsoredCallChainFamily;
  readonly receiptStatus?: ConsoleSponsoredCallReceiptStatus;
  readonly charged?: boolean;
  readonly limit: number;
  readonly lookbackDays: number;
  readonly cursor: { readonly createdAtMs: number; readonly id: string } | null;
}

const DEFAULT_LIST_LIMIT = 25;
const MAX_LIST_LIMIT = 100;
const DEFAULT_LOOKBACK_DAYS = 90;
const MAX_LOOKBACK_DAYS = 365;

export function getConsoleSponsoredCallD1Runtime(
  service: ConsoleSponsoredCallService | null | undefined,
): ConsoleSponsoredCallD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleSponsoredCallD1Service>)[CONSOLE_SPONSORED_CALL_D1_RUNTIME] ||
    null
  );
}

function defaultNow(): Date {
  return new Date();
}

function ensureNamespace(namespace: string | undefined): string {
  const normalized = String(namespace || 'default').trim();
  return normalized || 'default';
}

function nowMs(now: Date): number {
  return now.getTime();
}

function toIso(ms: number): string {
  return new Date(ms).toISOString();
}


function normalizeString(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return normalized || null;
}

function normalizeRequiredString(value: unknown): string {
  return String(value || '').trim();
}

function normalizeRequiredIdempotencyKey(value: unknown): string {
  const normalized = normalizeRequiredString(value);
  if (!normalized) {
    throw new ConsoleSponsoredCallError(
      'invalid_request',
      400,
      'idempotencyKey is required',
    );
  }
  return normalized;
}

function normalizeInteger(value: unknown): number | null {
  if (value == null) return null;
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(parsed)) return null;
  return parsed;
}

function normalizePositiveInteger(value: unknown, fallback: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.max(1, Math.min(max, Math.trunc(parsed)));
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = secureRandomBase36(8, 'console IDs');
  return `${prefix}_${ts}_${rand}`;
}

function parseApiKeyKind(value: unknown): ConsoleSponsoredCallApiKeyKind {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'secret_key':
    case 'publishable_key':
      return normalized;
    default:
      throw new Error(`Invalid sponsored call api key kind row: ${normalized || 'empty'}`);
  }
}

function parseChainFamily(value: unknown): ConsoleSponsoredCallChainFamily {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'evm':
    case 'near':
      return normalized;
    default:
      throw new Error(`Invalid sponsored call chain family row: ${normalized || 'empty'}`);
  }
}

function parseIntentKind(value: unknown): ConsoleSponsoredCallIntentKind {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'evm_call':
    case 'near_delegate':
      return normalized;
    default:
      throw new Error(`Invalid sponsored call intent kind row: ${normalized || 'empty'}`);
  }
}

function parseExecutorKind(value: unknown): ConsoleSponsoredCallExecutorKind {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'evm_eoa':
    case 'near_delegate':
      return normalized;
    default:
      throw new Error(`Invalid sponsored call executor kind row: ${normalized || 'empty'}`);
  }
}

function parseReceiptStatus(value: unknown): ConsoleSponsoredCallReceiptStatus {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'success':
    case 'reverted':
    case 'broadcast_failed':
    case 'rpc_rejected':
      return normalized;
    default:
      throw new Error(`Invalid sponsored call receipt status row: ${normalized || 'empty'}`);
  }
}

function parseFeeUnit(value: unknown): ConsoleSponsoredCallFeeUnit {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'wei':
    case 'yocto_near':
      return normalized;
    default:
      throw new Error(`Invalid sponsored call fee unit row: ${normalized || 'empty'}`);
  }
}

function parseRecord(row: D1Row): ConsoleSponsoredCallRecord {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    environmentId: String(row.environment_id || ''),
    apiKeyId: String(row.api_key_id || ''),
    apiKeyKind: parseApiKeyKind(row.api_key_kind),
    route: String(row.route || ''),
    policyId: String(row.policy_id || ''),
    policyNameAtEvent: normalizeString(row.policy_name_at_event),
    templateId: normalizeString(row.template_id),
    chainFamily: parseChainFamily(row.chain_family),
    intentKind: parseIntentKind(row.intent_kind),
    executorKind: parseExecutorKind(row.executor_kind),
    accountRef: String(row.account_ref || ''),
    targetRef: String(row.target_ref || ''),
    sponsorRef: String(row.sponsor_ref || ''),
    txOrExecutionRef: normalizeString(row.tx_or_execution_ref),
    receiptStatus: parseReceiptStatus(row.receipt_status),
    feeUnit: parseFeeUnit(row.fee_unit),
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
    idempotencyKey: normalizeRequiredString(row.idempotency_key),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
  };
}

function parseListCursor(cursor: string | undefined): { createdAtMs: number; id: string } | null {
  const raw = String(cursor || '').trim();
  if (!raw) return null;
  const separator = raw.indexOf(':');
  if (separator <= 0 || separator >= raw.length - 1) {
    throw new ConsoleSponsoredCallError(
      'invalid_query',
      400,
      'Invalid sponsored call cursor format',
    );
  }
  const createdAtMs = Number.parseInt(raw.slice(0, separator), 10);
  const id = raw.slice(separator + 1).trim();
  if (!Number.isFinite(createdAtMs) || !id) {
    throw new ConsoleSponsoredCallError(
      'invalid_query',
      400,
      'Invalid sponsored call cursor format',
    );
  }
  return { createdAtMs, id };
}

function buildListCursor(record: ConsoleSponsoredCallRecord): string {
  return `${Date.parse(record.createdAt)}:${record.id}`;
}

function finalListItem(
  records: readonly ConsoleSponsoredCallRecord[],
): ConsoleSponsoredCallRecord | null {
  return records.length > 0 ? records[records.length - 1] || null : null;
}

function normalizeListRequest(
  request: ListConsoleSponsoredCallRecordsRequest | undefined,
): NormalizedSponsoredCallListRequest {
  const environmentId = normalizeString(request?.environmentId);
  const policyId = normalizeString(request?.policyId);
  return {
    ...(environmentId ? { environmentId } : {}),
    ...(policyId ? { policyId } : {}),
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

async function loadRecordByIdempotencyKey(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  idempotencyKey: string;
}): Promise<ConsoleSponsoredCallRecord | null> {
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM sponsored_call_records
      WHERE namespace = ?
        AND org_id = ?
        AND idempotency_key = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.idempotencyKey],
  );
  return row ? parseRecord(row) : null;
}

export async function loadD1ConsoleSponsoredCallRecordByIdempotencyKey(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  idempotencyKey: string;
}): Promise<ConsoleSponsoredCallRecord | null> {
  const normalized = normalizeString(input.idempotencyKey);
  if (!normalized) return null;
  return await loadRecordByIdempotencyKey({
    database: input.database,
    namespace: input.namespace,
    orgId: input.orgId,
    idempotencyKey: normalized,
  });
}

export async function loadD1ConsoleSponsoredCallRecordById(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  recordId: string;
}): Promise<ConsoleSponsoredCallRecord | null> {
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM sponsored_call_records
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.recordId],
  );
  return row ? parseRecord(row) : null;
}

function appendListFilter(input: {
  values: unknown[];
  clauses: string[];
  clause: string;
  value: unknown;
}): void {
  input.values.push(input.value);
  input.clauses.push(input.clause);
}

function maybeAppendListFilter(input: {
  values: unknown[];
  clauses: string[];
  clause: string;
  value: unknown;
}): void {
  if (input.value === undefined || input.value === null || input.value === '') return;
  appendListFilter(input);
}

function isD1UniqueConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('UNIQUE constraint failed') || message.includes('constraint failed');
}

function buildRecordInsertValues(input: {
  namespace: string;
  ctx: ConsoleSponsoredCallContext;
  recordId: string;
  request: CreateConsoleSponsoredCallRecordRequest;
  idempotencyKey: string;
  createdAtMs: number;
}): readonly unknown[] {
  return [
    input.namespace,
    input.ctx.orgId,
    input.recordId,
    normalizeRequiredString(input.request.environmentId),
    normalizeRequiredString(input.request.apiKeyId),
    input.request.apiKeyKind,
    normalizeRequiredString(input.request.route),
    normalizeRequiredString(input.request.policyId),
    normalizeString(input.request.policyNameAtEvent),
    normalizeString(input.request.templateId),
    input.request.chainFamily,
    input.request.intentKind,
    input.request.executorKind,
    normalizeRequiredString(input.request.accountRef),
    normalizeRequiredString(input.request.targetRef),
    normalizeRequiredString(input.request.sponsorRef),
    normalizeString(input.request.txOrExecutionRef),
    input.request.receiptStatus,
    input.request.feeUnit,
    normalizeRequiredString(input.request.feeAmount) || '0',
    normalizeRequiredString(input.request.detailsJson) || '{}',
    normalizeInteger(input.request.estimatedSpendMinor),
    normalizeInteger(input.request.settledSpendMinor),
    normalizeString(input.request.pricingVersion),
    normalizeString(input.request.pricingSource),
    normalizeString(input.request.billingLedgerEntryId),
    normalizeString(input.request.prepaidReservationId),
    input.request.charged ? 1 : 0,
    normalizeString(input.request.chargedReason),
    normalizeString(input.request.settledAt),
    normalizeString(input.request.errorCode),
    normalizeString(input.request.errorMessage),
    input.idempotencyKey,
    input.createdAtMs,
    input.createdAtMs,
  ];
}

export function createD1ConsoleSponsoredCallRecordInsertStatement(input: {
  database: D1DatabaseLike;
  namespace: string;
  ctx: ConsoleSponsoredCallContext;
  recordId: string;
  request: CreateConsoleSponsoredCallRecordRequest;
  createdAtMs: number;
  insertGuard?: D1SponsoredCallInsertGuard;
}): D1PreparedStatementLike {
  const idempotencyKey = normalizeRequiredIdempotencyKey(input.request.idempotencyKey);
  const sourceSql = d1SponsoredCallRecordInsertSourceSql(input.insertGuard);
  return input.database
    .prepare(
      `INSERT INTO sponsored_call_records (
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
      ) ${sourceSql}`,
    )
    .bind(
      ...buildRecordInsertValues({
        namespace: input.namespace,
        ctx: input.ctx,
        recordId: input.recordId,
        request: input.request,
        idempotencyKey,
        createdAtMs: input.createdAtMs,
      }),
    );
}

function d1SponsoredCallRecordInsertSourceSql(
  insertGuard: D1SponsoredCallInsertGuard | undefined,
): string {
  const sourceSql =
    'SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?';
  if (!insertGuard) return sourceSql;
  return `${sourceSql} WHERE changes() = 1`;
}

export async function createD1ConsoleSponsoredCallRecord(input: {
  database: D1DatabaseLike;
  namespace: string;
  ctx: ConsoleSponsoredCallContext;
  now: () => Date;
  request: CreateConsoleSponsoredCallRecordRequest;
}): Promise<ConsoleSponsoredCallRecord> {
  const createdAt = input.now();
  const createdAtMs = nowMs(createdAt);
  const recordId = normalizeString(input.request.id) || makeId('scr', createdAt);
  const idempotencyKey = normalizeRequiredIdempotencyKey(input.request.idempotencyKey);
  const existing = await loadRecordByIdempotencyKey({
    database: input.database,
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    idempotencyKey,
  });
  if (existing) return existing;
  try {
    await createD1ConsoleSponsoredCallRecordInsertStatement({
      database: input.database,
      namespace: input.namespace,
      ctx: input.ctx,
      recordId,
      request: input.request,
      createdAtMs,
    }).run();
  } catch (error: unknown) {
    if (!isD1UniqueConstraintError(error)) throw error;
    const existing = await loadRecordByIdempotencyKey({
      database: input.database,
      namespace: input.namespace,
      orgId: input.ctx.orgId,
      idempotencyKey,
    });
    if (!existing) throw error;
    return existing;
  }
  const record = await loadD1ConsoleSponsoredCallRecordById({
    database: input.database,
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    recordId,
  });
  if (!record) throw new Error('Failed to insert sponsored-call record');
  return record;
}

export async function createD1ConsoleSponsoredCallService(
  options: D1ConsoleSponsoredCallServiceOptions,
): Promise<ConsoleSponsoredCallService> {
  const database = options.database;
  const namespace = ensureNamespace(options.namespace);
  const now = options.now || defaultNow;
  const runtime: ConsoleSponsoredCallD1Runtime = {
    database,
    namespace,
    now,
  };

  const service: ConsoleSponsoredCallD1Service = {
    async getOverviewSummary(ctx): Promise<ConsoleSponsoredCallOverviewSummary> {
      const currentNowMs = nowMs(now());
      const trailing30MinCreatedAtMs = currentNowMs - 30 * 24 * 60 * 60 * 1000;
      const trailing90MinCreatedAtMs = currentNowMs - 90 * 24 * 60 * 60 * 1000;
      const row = await queryD1One(
        database,
        `SELECT
            COALESCE(SUM(CASE WHEN charged = 1 AND created_at_ms >= ? THEN 1 ELSE 0 END), 0) AS trailing_30_count,
            COALESCE(SUM(CASE WHEN charged = 1 AND created_at_ms >= ? THEN COALESCE(settled_spend_minor, 0) ELSE 0 END), 0) AS trailing_30_spend_minor,
            COALESCE(SUM(CASE WHEN charged = 1 AND created_at_ms >= ? THEN 1 ELSE 0 END), 0) AS trailing_90_count,
            COALESCE(SUM(CASE WHEN charged = 1 AND created_at_ms >= ? THEN COALESCE(settled_spend_minor, 0) ELSE 0 END), 0) AS trailing_90_spend_minor
           FROM sponsored_call_records
          WHERE namespace = ?
            AND org_id = ?
            AND created_at_ms >= ?`,
        [
          trailing30MinCreatedAtMs,
          trailing30MinCreatedAtMs,
          trailing90MinCreatedAtMs,
          trailing90MinCreatedAtMs,
          namespace,
          ctx.orgId,
          trailing90MinCreatedAtMs,
        ],
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
    },

    async listRecords(ctx, request = {}): Promise<ConsoleSponsoredCallRecordPage> {
      const normalized = normalizeListRequest(request);
      const values: unknown[] = [namespace, ctx.orgId];
      const whereClauses = ['namespace = ?', 'org_id = ?'];
      const minCreatedAtMs = nowMs(now()) - normalized.lookbackDays * 24 * 60 * 60 * 1000;
      appendListFilter({
        values,
        clauses: whereClauses,
        clause: 'created_at_ms >= ?',
        value: minCreatedAtMs,
      });
      maybeAppendListFilter({
        values,
        clauses: whereClauses,
        clause: 'environment_id = ?',
        value: normalized.environmentId,
      });
      maybeAppendListFilter({
        values,
        clauses: whereClauses,
        clause: 'policy_id = ?',
        value: normalized.policyId,
      });
      maybeAppendListFilter({
        values,
        clauses: whereClauses,
        clause: 'chain_family = ?',
        value: normalized.chainFamily,
      });
      maybeAppendListFilter({
        values,
        clauses: whereClauses,
        clause: 'receipt_status = ?',
        value: normalized.receiptStatus,
      });
      if (normalized.charged !== undefined) {
        appendListFilter({
          values,
          clauses: whereClauses,
          clause: 'charged = ?',
          value: normalized.charged ? 1 : 0,
        });
      }
      if (normalized.cursor) {
        values.push(normalized.cursor.createdAtMs, normalized.cursor.createdAtMs, normalized.cursor.id);
        whereClauses.push('(created_at_ms < ? OR (created_at_ms = ? AND id < ?))');
      }
      values.push(normalized.limit + 1);
      const rows = await queryD1All(
        database,
        `SELECT *
           FROM sponsored_call_records
          WHERE ${whereClauses.join(' AND ')}
          ORDER BY created_at_ms DESC, id DESC
          LIMIT ?`,
        values,
      );
      const records = rows.map(parseRecord);
      const items = records.slice(0, normalized.limit);
      const finalItem = finalListItem(items);
      return {
        items,
        nextCursor: records.length > normalized.limit && finalItem ? buildListCursor(finalItem) : null,
      };
    },

    async getRecordByIdempotencyKey(
      ctx,
      idempotencyKey,
    ): Promise<ConsoleSponsoredCallRecord | null> {
      const normalized = normalizeString(idempotencyKey);
      if (!normalized) return null;
      return await loadRecordByIdempotencyKey({
        database,
        namespace,
        orgId: ctx.orgId,
        idempotencyKey: normalized,
      });
    },

    async createRecord(ctx, request): Promise<ConsoleSponsoredCallRecord> {
      return await createD1ConsoleSponsoredCallRecord({
        database,
        namespace,
        ctx,
        now,
        request,
      });
    },

    [CONSOLE_SPONSORED_CALL_D1_RUNTIME]: runtime,
  };

  return service;
}
