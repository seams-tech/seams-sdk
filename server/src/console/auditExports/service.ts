import { ConsoleAuditExportsError } from './errors';
import type {
  ConsoleAuditExportRecord,
  CreateConsoleAuditExportRequest,
  ListConsoleAuditExportsRequest,
} from './types';

export interface ConsoleAuditExportsContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
  environmentId?: string;
}

export interface ConsoleAuditExportsService {
  listExports(
    ctx: ConsoleAuditExportsContext,
    request?: ListConsoleAuditExportsRequest,
  ): Promise<ConsoleAuditExportRecord[]>;
  getExport(ctx: ConsoleAuditExportsContext, exportId: string): Promise<ConsoleAuditExportRecord | null>;
  createExport(
    ctx: ConsoleAuditExportsContext,
    request: CreateConsoleAuditExportRequest,
  ): Promise<ConsoleAuditExportRecord>;
}

export interface InMemoryConsoleAuditExportsServiceOptions {
  now?: () => Date;
}

function toIso(date: Date): string {
  return date.toISOString();
}

function makeId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeString(value: unknown): string | null {
  const out = String(value || '').trim();
  return out || null;
}

function cloneRecord(input: ConsoleAuditExportRecord): ConsoleAuditExportRecord {
  return {
    id: input.id,
    orgId: input.orgId,
    requestedByUserId: input.requestedByUserId,
    status: input.status,
    format: input.format,
    filters: {
      ...(input.filters.projectId ? { projectId: input.filters.projectId } : {}),
      ...(input.filters.environmentId ? { environmentId: input.filters.environmentId } : {}),
      ...(input.filters.domain ? { domain: input.filters.domain } : {}),
      ...(input.filters.from ? { from: input.filters.from } : {}),
      ...(input.filters.to ? { to: input.filters.to } : {}),
    },
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
    readyAt: input.readyAt,
    expiresAt: input.expiresAt,
    downloadUrl: input.downloadUrl,
    failureCode: input.failureCode,
    failureMessage: input.failureMessage,
  };
}

function sortRecords(rows: ConsoleAuditExportRecord[]): ConsoleAuditExportRecord[] {
  return [...rows].sort((a, b) => {
    const tsDiff = b.createdAt.localeCompare(a.createdAt);
    if (tsDiff !== 0) return tsDiff;
    return b.id.localeCompare(a.id);
  });
}

export function createInMemoryConsoleAuditExportsService(
  opts: InMemoryConsoleAuditExportsServiceOptions = {},
): ConsoleAuditExportsService {
  const now = opts.now || (() => new Date());
  const stores = new Map<string, Map<string, ConsoleAuditExportRecord>>();

  function requireOrgStore(orgId: string): Map<string, ConsoleAuditExportRecord> {
    let store = stores.get(orgId);
    if (!store) {
      store = new Map<string, ConsoleAuditExportRecord>();
      stores.set(orgId, store);
    }
    return store;
  }

  return {
    async listExports(
      ctx: ConsoleAuditExportsContext,
      request: ListConsoleAuditExportsRequest = {},
    ): Promise<ConsoleAuditExportRecord[]> {
      const store = requireOrgStore(ctx.orgId);
      const limit = Number.isFinite(Number(request.limit))
        ? Math.max(1, Math.min(200, Math.floor(Number(request.limit))))
        : 50;
      return sortRecords(Array.from(store.values()))
        .filter((row) => {
          if (request.status && row.status !== request.status) return false;
          if (request.domain && row.filters.domain !== request.domain) return false;
          return true;
        })
        .slice(0, limit)
        .map(cloneRecord);
    },

    async getExport(
      ctx: ConsoleAuditExportsContext,
      exportId: string,
    ): Promise<ConsoleAuditExportRecord | null> {
      const store = requireOrgStore(ctx.orgId);
      const row = store.get(exportId);
      return row ? cloneRecord(row) : null;
    },

    async createExport(
      ctx: ConsoleAuditExportsContext,
      request: CreateConsoleAuditExportRequest,
    ): Promise<ConsoleAuditExportRecord> {
      const createdAt = now();
      const iso = toIso(createdAt);
      const id = normalizeString(request.id) || makeId('aexp', createdAt);
      const store = requireOrgStore(ctx.orgId);
      if (store.has(id)) {
        throw new ConsoleAuditExportsError(
          'audit_export_already_exists',
          409,
          `Audit export ${id} already exists`,
        );
      }

      const record: ConsoleAuditExportRecord = {
        id,
        orgId: ctx.orgId,
        requestedByUserId: ctx.actorUserId,
        status: 'QUEUED',
        format: request.format,
        filters: {
          ...(normalizeString(request.projectId) ? { projectId: normalizeString(request.projectId) || undefined } : {}),
          ...(normalizeString(request.environmentId)
            ? { environmentId: normalizeString(request.environmentId) || undefined }
            : {}),
          ...(request.domain ? { domain: request.domain } : {}),
          ...(request.from ? { from: request.from } : {}),
          ...(request.to ? { to: request.to } : {}),
        },
        createdAt: iso,
        updatedAt: iso,
        readyAt: null,
        expiresAt: null,
        downloadUrl: null,
        failureCode: null,
        failureMessage: null,
      };

      store.set(record.id, record);
      return cloneRecord(record);
    },
  };
}
