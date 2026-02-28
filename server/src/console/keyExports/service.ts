import { ConsoleKeyExportError } from './errors';
import type {
  ApproveConsoleKeyExportRequest,
  ConsoleKeyExportConstraints,
  ConsoleKeyExportRequestRecord,
  CreateConsoleKeyExportRequest,
  ListConsoleKeyExportsRequest,
} from './types';

export interface ConsoleKeyExportsContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface InMemoryConsoleKeyExportServiceOptions {
  now?: () => Date;
}

export interface ConsoleKeyExportService {
  listKeyExports(
    ctx: ConsoleKeyExportsContext,
    request?: ListConsoleKeyExportsRequest,
  ): Promise<ConsoleKeyExportRequestRecord[]>;
  createKeyExport(
    ctx: ConsoleKeyExportsContext,
    request: CreateConsoleKeyExportRequest,
  ): Promise<ConsoleKeyExportRequestRecord>;
  approveKeyExport(
    ctx: ConsoleKeyExportsContext,
    exportId: string,
    request: ApproveConsoleKeyExportRequest,
  ): Promise<ConsoleKeyExportRequestRecord | null>;
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function toIso(date: Date): string {
  return date.toISOString();
}

function normalizeString(value: unknown): string | null {
  const out = String(value || '').trim();
  return out || null;
}

function normalizeStringArray(input: string[] | undefined): string[] {
  if (!Array.isArray(input)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of input) {
    const value = String(raw || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function normalizeConstraints(
  constraints: Partial<ConsoleKeyExportConstraints> | undefined,
): ConsoleKeyExportConstraints {
  return {
    roles: normalizeStringArray(constraints?.roles),
    chains: normalizeStringArray(constraints?.chains),
    walletTypes: normalizeStringArray(constraints?.walletTypes),
    environmentIds: normalizeStringArray(constraints?.environmentIds),
  };
}

function cloneRecord(record: ConsoleKeyExportRequestRecord): ConsoleKeyExportRequestRecord {
  return {
    ...record,
    approvals: record.approvals.map((approval) => ({ ...approval })),
    constraints: {
      roles: [...record.constraints.roles],
      chains: [...record.constraints.chains],
      walletTypes: [...record.constraints.walletTypes],
      environmentIds: [...record.constraints.environmentIds],
    },
  };
}

function sortRecords(records: ConsoleKeyExportRequestRecord[]): ConsoleKeyExportRequestRecord[] {
  return [...records].sort((a, b) => {
    const updatedCompare = b.updatedAt.localeCompare(a.updatedAt);
    if (updatedCompare !== 0) return updatedCompare;
    return b.createdAt.localeCompare(a.createdAt);
  });
}

export function createInMemoryConsoleKeyExportService(
  opts: InMemoryConsoleKeyExportServiceOptions = {},
): ConsoleKeyExportService {
  const now = opts.now || (() => new Date());
  const stores = new Map<string, Map<string, ConsoleKeyExportRequestRecord>>();

  function requireOrgStore(orgId: string): Map<string, ConsoleKeyExportRequestRecord> {
    let store = stores.get(orgId);
    if (!store) {
      store = new Map<string, ConsoleKeyExportRequestRecord>();
      stores.set(orgId, store);
    }
    return store;
  }

  return {
    async listKeyExports(ctx, request = {}): Promise<ConsoleKeyExportRequestRecord[]> {
      const store = requireOrgStore(ctx.orgId);
      return sortRecords(Array.from(store.values()))
        .filter((row) => {
          if (request.environmentId && row.environmentId !== request.environmentId) return false;
          if (request.status && row.status !== request.status) return false;
          return true;
        })
        .map(cloneRecord);
    },

    async createKeyExport(ctx, request): Promise<ConsoleKeyExportRequestRecord> {
      const createdAt = now();
      const iso = toIso(createdAt);
      const record: ConsoleKeyExportRequestRecord = {
        id: normalizeString(request.id) || makeId('ke', createdAt),
        orgId: ctx.orgId,
        environmentId: request.environmentId,
        walletId: normalizeString(request.walletId),
        mode: request.mode || 'APPROVAL_REQUIRED',
        status: 'PENDING_APPROVAL',
        reason: request.reason,
        requestedByUserId: ctx.actorUserId,
        requiredApprovals: Math.max(1, request.requiredApprovals || 2),
        approvals: [],
        constraints: normalizeConstraints(request.constraints),
        createdAt: iso,
        updatedAt: iso,
      };

      const store = requireOrgStore(ctx.orgId);
      if (store.has(record.id)) {
        throw new ConsoleKeyExportError(
          'key_export_exists',
          409,
          `Key export request ${record.id} already exists`,
        );
      }
      store.set(record.id, record);
      return cloneRecord(record);
    },

    async approveKeyExport(ctx, exportId, request): Promise<ConsoleKeyExportRequestRecord | null> {
      const store = requireOrgStore(ctx.orgId);
      const current = store.get(exportId);
      if (!current) return null;

      if (current.status !== 'PENDING_APPROVAL') {
        throw new ConsoleKeyExportError(
          'invalid_state',
          409,
          `Key export request ${exportId} is not pending approval`,
        );
      }
      if (!request.mfaVerified) {
        throw new ConsoleKeyExportError(
          'mfa_required',
          400,
          'MFA is required to approve key export requests',
        );
      }
      if (current.approvals.some((entry) => entry.approverUserId === ctx.actorUserId)) {
        throw new ConsoleKeyExportError(
          'already_approved',
          409,
          `User ${ctx.actorUserId} already approved key export request ${exportId}`,
        );
      }

      current.approvals.push({
        approverUserId: ctx.actorUserId,
        approvedAt: toIso(now()),
        reason: request.reason,
        mfaVerified: request.mfaVerified,
      });
      if (current.approvals.length >= current.requiredApprovals) {
        current.status = 'APPROVED';
      }
      current.updatedAt = toIso(now());
      return cloneRecord(current);
    },
  };
}
