import { secureRandomBase36 } from '@seams-internal/shared-ts/utils/secureRandomId';
import type {
  ConsoleSponsoredCallRecord,
  ConsoleSponsoredCallRecordPage,
  ConsoleSponsoredCallOverviewSummary,
  CreateConsoleSponsoredCallRecordRequest,
  ListConsoleSponsoredCallRecordsRequest,
} from './types';
import { ConsoleSponsoredCallError } from './errors';

export interface ConsoleSponsoredCallContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface InMemoryConsoleSponsoredCallServiceOptions {
  now?: () => Date;
}

export interface ConsoleSponsoredCallService {
  getOverviewSummary(
    ctx: ConsoleSponsoredCallContext,
  ): Promise<ConsoleSponsoredCallOverviewSummary>;
  listRecords(
    ctx: ConsoleSponsoredCallContext,
    request?: ListConsoleSponsoredCallRecordsRequest,
  ): Promise<ConsoleSponsoredCallRecordPage>;
  getRecordByIdempotencyKey(
    ctx: ConsoleSponsoredCallContext,
    idempotencyKey: string,
  ): Promise<ConsoleSponsoredCallRecord | null>;
  createRecord(
    ctx: ConsoleSponsoredCallContext,
    request: CreateConsoleSponsoredCallRecordRequest,
  ): Promise<ConsoleSponsoredCallRecord>;
}

function toIso(date: Date): string {
  return date.toISOString();
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = secureRandomBase36(8, 'console IDs');
  return `${prefix}_${ts}_${rand}`;
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
  const parsed = Number(value);
  if (!Number.isInteger(parsed)) return null;
  return parsed;
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
  if (separator <= 0 || separator >= raw.length - 1) return null;
  const createdAtMs = Number.parseInt(raw.slice(0, separator), 10);
  const id = raw.slice(separator + 1).trim();
  if (!Number.isFinite(createdAtMs) || !id) return null;
  return { createdAtMs, id };
}

function buildListCursor(record: ConsoleSponsoredCallRecord): string {
  return `${Date.parse(record.createdAt)}:${record.id}`;
}

function cloneRecord(record: ConsoleSponsoredCallRecord): ConsoleSponsoredCallRecord {
  return { ...record };
}

function buildOverviewSummary(
  records: Iterable<ConsoleSponsoredCallRecord>,
  nowMs: number,
): ConsoleSponsoredCallOverviewSummary {
  const trailing30MinCreatedAtMs = nowMs - 30 * 24 * 60 * 60 * 1000;
  const trailing90MinCreatedAtMs = nowMs - 90 * 24 * 60 * 60 * 1000;
  const summary: ConsoleSponsoredCallOverviewSummary = {
    trailing30Days: {
      lookbackDays: 30,
      chargedExecutionCount: 0,
      chargedSettledSpendMinor: 0,
    },
    trailing90Days: {
      lookbackDays: 90,
      chargedExecutionCount: 0,
      chargedSettledSpendMinor: 0,
    },
  };
  for (const record of records) {
    if (!record.charged) continue;
    const createdAtMs = Date.parse(record.createdAt);
    if (!Number.isFinite(createdAtMs)) continue;
    const settledSpendMinor = Math.max(0, Number(record.settledSpendMinor || 0));
    if (createdAtMs >= trailing90MinCreatedAtMs) {
      summary.trailing90Days.chargedExecutionCount += 1;
      summary.trailing90Days.chargedSettledSpendMinor += settledSpendMinor;
    }
    if (createdAtMs >= trailing30MinCreatedAtMs) {
      summary.trailing30Days.chargedExecutionCount += 1;
      summary.trailing30Days.chargedSettledSpendMinor += settledSpendMinor;
    }
  }
  return summary;
}

export function createInMemoryConsoleSponsoredCallService(
  options: InMemoryConsoleSponsoredCallServiceOptions = {},
): ConsoleSponsoredCallService {
  const now = options.now || (() => new Date());
  const stores = new Map<string, Map<string, ConsoleSponsoredCallRecord>>();

  function requireOrgStore(orgId: string): Map<string, ConsoleSponsoredCallRecord> {
    let store = stores.get(orgId);
    if (!store) {
      store = new Map<string, ConsoleSponsoredCallRecord>();
      stores.set(orgId, store);
    }
    return store;
  }

  return {
    async getOverviewSummary(ctx): Promise<ConsoleSponsoredCallOverviewSummary> {
      const store = requireOrgStore(ctx.orgId);
      return buildOverviewSummary(store.values(), now().getTime());
    },

    async listRecords(ctx, request = {}): Promise<ConsoleSponsoredCallRecordPage> {
      const store = requireOrgStore(ctx.orgId);
      const limit = normalizePositiveInteger(request.limit, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT);
      const lookbackDays = normalizePositiveInteger(
        request.lookbackDays,
        DEFAULT_LOOKBACK_DAYS,
        MAX_LOOKBACK_DAYS,
      );
      const nowMs = now().getTime();
      const minCreatedAtMs = nowMs - lookbackDays * 24 * 60 * 60 * 1000;
      const cursor = parseListCursor(request.cursor);
      const filtered = Array.from(store.values())
        .filter((record) => {
          const createdAtMs = Date.parse(record.createdAt);
          if (!Number.isFinite(createdAtMs) || createdAtMs < minCreatedAtMs) return false;
          if (request.environmentId && record.environmentId !== request.environmentId) return false;
          if (request.policyId && record.policyId !== request.policyId) return false;
          if (request.chainFamily && record.chainFamily !== request.chainFamily) return false;
          if (request.receiptStatus && record.receiptStatus !== request.receiptStatus) return false;
          if (request.charged !== undefined && record.charged !== request.charged) return false;
          if (!cursor) return true;
          if (createdAtMs < cursor.createdAtMs) return true;
          if (createdAtMs > cursor.createdAtMs) return false;
          return record.id < cursor.id;
        })
        .sort((a, b) => {
          const aMs = Date.parse(a.createdAt);
          const bMs = Date.parse(b.createdAt);
          if (bMs !== aMs) return bMs - aMs;
          return b.id.localeCompare(a.id);
        });
      const items = filtered.slice(0, limit).map(cloneRecord);
      return {
        items,
        nextCursor:
          filtered.length > limit && items.length > 0
            ? buildListCursor(items[items.length - 1]!)
            : null,
      };
    },

    async getRecordByIdempotencyKey(
      ctx,
      idempotencyKey,
    ): Promise<ConsoleSponsoredCallRecord | null> {
      const normalized = normalizeString(idempotencyKey);
      if (!normalized) return null;
      const store = requireOrgStore(ctx.orgId);
      for (const record of store.values()) {
        if (record.idempotencyKey === normalized) return cloneRecord(record);
      }
      return null;
    },

    async createRecord(ctx, request): Promise<ConsoleSponsoredCallRecord> {
      const createdAt = now();
      const iso = toIso(createdAt);
      const store = requireOrgStore(ctx.orgId);
      const idempotencyKey = normalizeRequiredIdempotencyKey(request.idempotencyKey);
      for (const record of store.values()) {
        if (record.idempotencyKey === idempotencyKey) return cloneRecord(record);
      }
      const record: ConsoleSponsoredCallRecord = {
        id: normalizeString(request.id) || makeId('scr', createdAt),
        orgId: ctx.orgId,
        environmentId: normalizeRequiredString(request.environmentId),
        apiKeyId: normalizeRequiredString(request.apiKeyId),
        apiKeyKind: request.apiKeyKind,
        route: normalizeRequiredString(request.route),
        policyId: normalizeRequiredString(request.policyId),
        policyNameAtEvent: normalizeString(request.policyNameAtEvent),
        templateId: normalizeString(request.templateId),
        chainFamily: request.chainFamily,
        intentKind: request.intentKind,
        executorKind: request.executorKind,
        accountRef: normalizeRequiredString(request.accountRef),
        targetRef: normalizeRequiredString(request.targetRef),
        sponsorRef: normalizeRequiredString(request.sponsorRef),
        txOrExecutionRef: normalizeString(request.txOrExecutionRef),
        receiptStatus: request.receiptStatus,
        feeUnit: request.feeUnit,
        feeAmount: normalizeRequiredString(request.feeAmount) || '0',
        detailsJson: normalizeRequiredString(request.detailsJson) || '{}',
        estimatedSpendMinor: normalizeInteger(request.estimatedSpendMinor),
        settledSpendMinor: normalizeInteger(request.settledSpendMinor),
        pricingVersion: normalizeString(request.pricingVersion),
        pricingSource: normalizeString(request.pricingSource),
        billingLedgerEntryId: normalizeString(request.billingLedgerEntryId),
        prepaidReservationId: normalizeString(request.prepaidReservationId),
        charged: Boolean(request.charged),
        chargedReason: normalizeString(request.chargedReason),
        settledAt: normalizeString(request.settledAt),
        errorCode: normalizeString(request.errorCode),
        errorMessage: normalizeString(request.errorMessage),
        idempotencyKey,
        createdAt: iso,
        updatedAt: iso,
      };
      store.set(record.id, record);
      return cloneRecord(record);
    },
  };
}
