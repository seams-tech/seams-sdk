import type {
  ConsoleSponsoredCallRecord,
  CreateConsoleSponsoredCallRecordRequest,
} from './types';

export interface ConsoleSponsoredCallContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface InMemoryConsoleSponsoredCallServiceOptions {
  now?: () => Date;
}

export interface ConsoleSponsoredCallService {
  getRecordBySourceEventId(
    ctx: ConsoleSponsoredCallContext,
    sourceEventId: string,
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
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function normalizeString(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return normalized || null;
}

function normalizeRequiredString(value: unknown): string {
  return String(value || '').trim();
}

function cloneRecord(record: ConsoleSponsoredCallRecord): ConsoleSponsoredCallRecord {
  return { ...record };
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
    async getRecordBySourceEventId(ctx, sourceEventId): Promise<ConsoleSponsoredCallRecord | null> {
      const normalized = normalizeString(sourceEventId);
      if (!normalized) return null;
      const store = requireOrgStore(ctx.orgId);
      for (const record of store.values()) {
        if (record.sourceEventId === normalized) return cloneRecord(record);
      }
      return null;
    },

    async createRecord(ctx, request): Promise<ConsoleSponsoredCallRecord> {
      const createdAt = now();
      const iso = toIso(createdAt);
      const store = requireOrgStore(ctx.orgId);
      const sourceEventId = normalizeString(request.sourceEventId);
      if (sourceEventId) {
        for (const record of store.values()) {
          if (record.sourceEventId === sourceEventId) return cloneRecord(record);
        }
      }
      const record: ConsoleSponsoredCallRecord = {
        id: normalizeString(request.id) || makeId('scr', createdAt),
        orgId: ctx.orgId,
        environmentId: normalizeRequiredString(request.environmentId),
        apiKeyId: normalizeRequiredString(request.apiKeyId),
        apiKeyKind: request.apiKeyKind,
        route: normalizeRequiredString(request.route),
        sponsorshipConfigId: normalizeRequiredString(request.sponsorshipConfigId),
        sponsorshipConfigNameAtEvent: normalizeString(request.sponsorshipConfigNameAtEvent),
        chainFamily: request.chainFamily,
        intentKind: request.intentKind,
        accountRef: normalizeRequiredString(request.accountRef),
        targetRef: normalizeRequiredString(request.targetRef),
        sponsorRef: normalizeRequiredString(request.sponsorRef),
        txOrExecutionRef: normalizeString(request.txOrExecutionRef),
        receiptStatus: request.receiptStatus,
        feeUnit: request.feeUnit,
        feeAmount: normalizeRequiredString(request.feeAmount) || '0',
        detailsJson: normalizeRequiredString(request.detailsJson) || '{}',
        errorCode: normalizeString(request.errorCode),
        errorMessage: normalizeString(request.errorMessage),
        sourceEventId,
        createdAt: iso,
        updatedAt: iso,
      };
      store.set(record.id, record);
      return cloneRecord(record);
    },
  };
}
