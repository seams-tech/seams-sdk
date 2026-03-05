import { ConsoleApprovalsError } from './errors';
import type {
  ApproveConsoleApprovalRequest,
  ConsoleApprovalDecisionRecord,
  ConsoleApprovalOperationType,
  ConsoleApprovalRequestRecord,
  CreateConsoleApprovalRequest,
  ListConsoleApprovalsRequest,
  RejectConsoleApprovalRequest,
} from './types';

export interface ConsoleApprovalsContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
  environmentId?: string;
}

export interface ConsoleApprovalService {
  listApprovalRequests(
    ctx: ConsoleApprovalsContext,
    request?: ListConsoleApprovalsRequest,
  ): Promise<ConsoleApprovalRequestRecord[]>;
  getApprovalRequest(
    ctx: ConsoleApprovalsContext,
    approvalId: string,
  ): Promise<ConsoleApprovalRequestRecord | null>;
  createApprovalRequest(
    ctx: ConsoleApprovalsContext,
    request: CreateConsoleApprovalRequest,
  ): Promise<ConsoleApprovalRequestRecord>;
  approveApprovalRequest(
    ctx: ConsoleApprovalsContext,
    approvalId: string,
    request: ApproveConsoleApprovalRequest,
  ): Promise<ConsoleApprovalRequestRecord | null>;
  rejectApprovalRequest(
    ctx: ConsoleApprovalsContext,
    approvalId: string,
    request: RejectConsoleApprovalRequest,
  ): Promise<ConsoleApprovalRequestRecord | null>;
}

export interface InMemoryConsoleApprovalServiceOptions {
  now?: () => Date;
}

const OPERATION_DEFAULTS: Record<
  ConsoleApprovalOperationType,
  {
    requiredApprovals: number;
    requireMfa: boolean;
  }
> = {
  POLICY_PUBLISH: { requiredApprovals: 1, requireMfa: false },
  KEY_EXPORT: { requiredApprovals: 2, requireMfa: true },
  SECURITY_SETTINGS_CHANGE: { requiredApprovals: 1, requireMfa: true },
};

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

function cloneDecision(input: ConsoleApprovalDecisionRecord): ConsoleApprovalDecisionRecord {
  return {
    decision: input.decision,
    actorUserId: input.actorUserId,
    reason: input.reason,
    mfaVerified: input.mfaVerified,
    decidedAt: input.decidedAt,
  };
}

function cloneRecord(input: ConsoleApprovalRequestRecord): ConsoleApprovalRequestRecord {
  return {
    id: input.id,
    orgId: input.orgId,
    operationType: input.operationType,
    status: input.status,
    reason: input.reason,
    requestedByUserId: input.requestedByUserId,
    requiredApprovals: input.requiredApprovals,
    requireMfa: input.requireMfa,
    projectId: input.projectId,
    environmentId: input.environmentId,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    metadata: { ...input.metadata },
    decisions: input.decisions.map(cloneDecision),
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
    resolvedAt: input.resolvedAt,
  };
}

function countApprovalDecisions(input: ConsoleApprovalRequestRecord): number {
  return input.decisions.filter((entry) => entry.decision === 'APPROVE').length;
}

function sortRecords(input: ConsoleApprovalRequestRecord[]): ConsoleApprovalRequestRecord[] {
  return [...input].sort((a, b) => {
    const updatedCompare = b.updatedAt.localeCompare(a.updatedAt);
    if (updatedCompare !== 0) return updatedCompare;
    return b.createdAt.localeCompare(a.createdAt);
  });
}

export function createInMemoryConsoleApprovalService(
  opts: InMemoryConsoleApprovalServiceOptions = {},
): ConsoleApprovalService {
  const now = opts.now || (() => new Date());
  const stores = new Map<string, Map<string, ConsoleApprovalRequestRecord>>();

  function requireOrgStore(orgId: string): Map<string, ConsoleApprovalRequestRecord> {
    let store = stores.get(orgId);
    if (!store) {
      store = new Map<string, ConsoleApprovalRequestRecord>();
      stores.set(orgId, store);
    }
    return store;
  }

  return {
    async listApprovalRequests(
      ctx: ConsoleApprovalsContext,
      request: ListConsoleApprovalsRequest = {},
    ): Promise<ConsoleApprovalRequestRecord[]> {
      const store = requireOrgStore(ctx.orgId);
      return sortRecords(Array.from(store.values()))
        .filter((row) => {
          if (request.status && row.status !== request.status) return false;
          if (request.operationType && row.operationType !== request.operationType) return false;
          if (request.projectId && row.projectId !== request.projectId) return false;
          if (request.environmentId && row.environmentId !== request.environmentId) return false;
          return true;
        })
        .map(cloneRecord);
    },

    async getApprovalRequest(
      ctx: ConsoleApprovalsContext,
      approvalId: string,
    ): Promise<ConsoleApprovalRequestRecord | null> {
      const store = requireOrgStore(ctx.orgId);
      const row = store.get(approvalId);
      return row ? cloneRecord(row) : null;
    },

    async createApprovalRequest(
      ctx: ConsoleApprovalsContext,
      request: CreateConsoleApprovalRequest,
    ): Promise<ConsoleApprovalRequestRecord> {
      const createdAt = now();
      const iso = toIso(createdAt);
      const defaults = OPERATION_DEFAULTS[request.operationType];
      const record: ConsoleApprovalRequestRecord = {
        id: normalizeString(request.id) || makeId('apr', createdAt),
        orgId: ctx.orgId,
        operationType: request.operationType,
        status: 'PENDING',
        reason: request.reason,
        requestedByUserId: ctx.actorUserId,
        requiredApprovals: Math.max(1, request.requiredApprovals || defaults.requiredApprovals),
        requireMfa: request.requireMfa === undefined ? defaults.requireMfa : request.requireMfa,
        projectId: normalizeString(request.projectId),
        environmentId: normalizeString(request.environmentId),
        resourceType: normalizeString(request.resourceType),
        resourceId: normalizeString(request.resourceId),
        metadata:
          request.metadata && typeof request.metadata === 'object' && !Array.isArray(request.metadata)
            ? { ...request.metadata }
            : {},
        decisions: [],
        createdAt: iso,
        updatedAt: iso,
        resolvedAt: null,
      };

      const store = requireOrgStore(ctx.orgId);
      if (store.has(record.id)) {
        throw new ConsoleApprovalsError(
          'approval_request_exists',
          409,
          `Approval request ${record.id} already exists`,
        );
      }
      store.set(record.id, record);
      return cloneRecord(record);
    },

    async approveApprovalRequest(
      ctx: ConsoleApprovalsContext,
      approvalId: string,
      request: ApproveConsoleApprovalRequest,
    ): Promise<ConsoleApprovalRequestRecord | null> {
      const store = requireOrgStore(ctx.orgId);
      const row = store.get(approvalId);
      if (!row) return null;

      if (row.status !== 'PENDING') {
        throw new ConsoleApprovalsError(
          'invalid_state',
          409,
          `Approval request ${approvalId} is not pending`,
        );
      }
      if (row.requireMfa && !request.mfaVerified) {
        throw new ConsoleApprovalsError(
          'mfa_required',
          400,
          'MFA is required to approve this request',
        );
      }
      if (row.decisions.some((entry) => entry.actorUserId === ctx.actorUserId)) {
        throw new ConsoleApprovalsError(
          'already_decided',
          409,
          `User ${ctx.actorUserId} has already decided request ${approvalId}`,
        );
      }

      row.decisions.push({
        decision: 'APPROVE',
        actorUserId: ctx.actorUserId,
        reason: request.reason,
        mfaVerified: request.mfaVerified,
        decidedAt: toIso(now()),
      });
      if (countApprovalDecisions(row) >= row.requiredApprovals) {
        row.status = 'APPROVED';
        row.resolvedAt = toIso(now());
      }
      row.updatedAt = toIso(now());
      return cloneRecord(row);
    },

    async rejectApprovalRequest(
      ctx: ConsoleApprovalsContext,
      approvalId: string,
      request: RejectConsoleApprovalRequest,
    ): Promise<ConsoleApprovalRequestRecord | null> {
      const store = requireOrgStore(ctx.orgId);
      const row = store.get(approvalId);
      if (!row) return null;

      if (row.status !== 'PENDING') {
        throw new ConsoleApprovalsError(
          'invalid_state',
          409,
          `Approval request ${approvalId} is not pending`,
        );
      }
      if (row.decisions.some((entry) => entry.actorUserId === ctx.actorUserId)) {
        throw new ConsoleApprovalsError(
          'already_decided',
          409,
          `User ${ctx.actorUserId} has already decided request ${approvalId}`,
        );
      }

      row.decisions.push({
        decision: 'REJECT',
        actorUserId: ctx.actorUserId,
        reason: request.reason,
        mfaVerified: false,
        decidedAt: toIso(now()),
      });
      row.status = 'REJECTED';
      row.updatedAt = toIso(now());
      row.resolvedAt = toIso(now());
      return cloneRecord(row);
    },
  };
}
