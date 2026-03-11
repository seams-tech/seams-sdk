import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  fetchConsoleEndpoint,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export type DashboardConsoleApprovalOperationType = 'POLICY_PUBLISH' | 'KEY_EXPORT';

export type DashboardConsoleApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'CANCELED';

export type DashboardConsoleApprovalDecision = 'APPROVE' | 'REJECT';

export interface DashboardConsoleApprovalDecisionRecord {
  decision: DashboardConsoleApprovalDecision;
  actorUserId: string;
  reason: string;
  mfaVerified: boolean;
  decidedAt: string;
}

export interface DashboardConsoleApprovalRequest {
  id: string;
  orgId: string;
  operationType: DashboardConsoleApprovalOperationType;
  status: DashboardConsoleApprovalStatus;
  reason: string;
  requestedByUserId: string;
  requiredApprovals: number;
  requireMfa: boolean;
  projectId: string | null;
  environmentId: string | null;
  resourceType: string | null;
  resourceId: string | null;
  policyId: string | null;
  policyName: string | null;
  metadata: Record<string, unknown>;
  decisions: DashboardConsoleApprovalDecisionRecord[];
  createdAt: string;
  updatedAt: string;
  resolvedAt: string | null;
}

interface ConsoleApprovalsListResponse {
  ok?: boolean;
  message?: string;
  approvals?: unknown;
}

interface ConsoleApprovalsMutationResponse {
  ok?: boolean;
  message?: string;
  approval?: unknown;
}

const OPERATION_TYPE_SET = new Set<DashboardConsoleApprovalOperationType>([
  'POLICY_PUBLISH',
  'KEY_EXPORT',
]);

const STATUS_SET = new Set<DashboardConsoleApprovalStatus>([
  'PENDING',
  'APPROVED',
  'REJECTED',
  'CANCELED',
]);

function normalizeString(value: unknown): string {
  return String(value || '').trim();
}

function decodeOperationType(raw: unknown): DashboardConsoleApprovalOperationType {
  const value = normalizeString(raw).toUpperCase();
  return OPERATION_TYPE_SET.has(value as DashboardConsoleApprovalOperationType)
    ? (value as DashboardConsoleApprovalOperationType)
    : 'POLICY_PUBLISH';
}

function decodeStatus(raw: unknown): DashboardConsoleApprovalStatus {
  const value = normalizeString(raw).toUpperCase();
  return STATUS_SET.has(value as DashboardConsoleApprovalStatus)
    ? (value as DashboardConsoleApprovalStatus)
    : 'PENDING';
}

function decodeDecision(raw: unknown): DashboardConsoleApprovalDecisionRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const decisionRaw = normalizeString(row.decision).toUpperCase();
  const decision: DashboardConsoleApprovalDecision =
    decisionRaw === 'REJECT' ? 'REJECT' : 'APPROVE';
  const actorUserId = normalizeString(row.actorUserId);
  const reason = normalizeString(row.reason);
  const decidedAt = normalizeString(row.decidedAt);
  if (!actorUserId || !reason || !decidedAt) return null;
  return {
    decision,
    actorUserId,
    reason,
    mfaVerified: row.mfaVerified === true,
    decidedAt,
  };
}

function decodeApproval(raw: unknown): DashboardConsoleApprovalRequest | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = normalizeString(row.id);
  const orgId = normalizeString(row.orgId);
  const reason = normalizeString(row.reason);
  const requestedByUserId = normalizeString(row.requestedByUserId);
  const createdAt = normalizeString(row.createdAt);
  const updatedAt = normalizeString(row.updatedAt);
  if (!id || !orgId || !requestedByUserId || !createdAt || !updatedAt) return null;
  const metadata =
    row.metadata && typeof row.metadata === 'object' && !Array.isArray(row.metadata)
      ? (row.metadata as Record<string, unknown>)
      : {};
  const decisionsRaw = Array.isArray(row.decisions) ? row.decisions : [];
  return {
    id,
    orgId,
    operationType: decodeOperationType(row.operationType),
    status: decodeStatus(row.status),
    reason,
    requestedByUserId,
    requiredApprovals: Math.max(1, Number(row.requiredApprovals || 1)),
    requireMfa: row.requireMfa === true,
    projectId: normalizeString(row.projectId) || null,
    environmentId: normalizeString(row.environmentId) || null,
    resourceType: normalizeString(row.resourceType) || null,
    resourceId: normalizeString(row.resourceId) || null,
    policyId: normalizeString(row.policyId) || null,
    policyName: normalizeString(row.policyName) || null,
    metadata,
    decisions: decisionsRaw
      .map((entry) => decodeDecision(entry))
      .filter((entry): entry is DashboardConsoleApprovalDecisionRecord => entry !== null),
    createdAt,
    updatedAt,
    resolvedAt: normalizeString(row.resolvedAt) || null,
  };
}

export async function listDashboardApprovals(input?: {
  status?: DashboardConsoleApprovalStatus;
  operationType?: DashboardConsoleApprovalOperationType;
  projectId?: string;
  environmentId?: string;
}): Promise<DashboardConsoleApprovalRequest[]> {
  const base = requireConsoleBaseUrl();
  const url = new URL('/console/approvals', base);
  if (input?.status) url.searchParams.set('status', input.status);
  if (input?.operationType) url.searchParams.set('operationType', input.operationType);
  if (input?.projectId) url.searchParams.set('projectId', input.projectId);
  if (input?.environmentId) url.searchParams.set('environmentId', input.environmentId);
  const response = await fetchConsoleEndpoint(
    url.toString(),
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
    {
      baseUrl: base,
      path: `${url.pathname}${url.search}`,
      operation: 'Approvals request',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsoleApprovalsListResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Approvals request failed'));
  }
  const rows = Array.isArray(body?.approvals) ? body.approvals : [];
  return rows
    .map((entry) => decodeApproval(entry))
    .filter((entry): entry is DashboardConsoleApprovalRequest => entry !== null);
}

export async function createDashboardApproval(input: {
  id?: string;
  operationType: DashboardConsoleApprovalOperationType;
  reason: string;
  requiredApprovals?: number;
  requireMfa?: boolean;
  projectId?: string;
  environmentId?: string;
  resourceType?: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
}): Promise<DashboardConsoleApprovalRequest> {
  const base = requireConsoleBaseUrl();
  const response = await fetchConsoleEndpoint(
    `${base}/console/approvals`,
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify(input),
    },
    {
      baseUrl: base,
      path: '/console/approvals',
      operation: 'Create approval request',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsoleApprovalsMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Create approval request failed'));
  }
  const approval = decodeApproval(body?.approval);
  if (!approval) throw new Error('Create approval response was invalid');
  return approval;
}

export async function approveDashboardApproval(input: {
  approvalId: string;
  reason: string;
  mfaVerified: boolean;
}): Promise<DashboardConsoleApprovalRequest> {
  const approvalId = normalizeString(input.approvalId);
  if (!approvalId) throw new Error('Approval request id is required');
  const base = requireConsoleBaseUrl();
  const approvePath = `/console/approvals/${encodeURIComponent(approvalId)}/approve`;
  const response = await fetchConsoleEndpoint(
    `${base}${approvePath}`,
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify({
        reason: input.reason,
        mfaVerified: input.mfaVerified,
      }),
    },
    {
      baseUrl: base,
      path: approvePath,
      operation: 'Approve request',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsoleApprovalsMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Approve request failed'));
  }
  const approval = decodeApproval(body?.approval);
  if (!approval) throw new Error('Approve response was invalid');
  return approval;
}

export async function rejectDashboardApproval(input: {
  approvalId: string;
  reason: string;
}): Promise<DashboardConsoleApprovalRequest> {
  const approvalId = normalizeString(input.approvalId);
  if (!approvalId) throw new Error('Approval request id is required');
  const base = requireConsoleBaseUrl();
  const rejectPath = `/console/approvals/${encodeURIComponent(approvalId)}/reject`;
  const response = await fetchConsoleEndpoint(
    `${base}${rejectPath}`,
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify({
        reason: input.reason,
      }),
    },
    {
      baseUrl: base,
      path: rejectPath,
      operation: 'Reject request',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsoleApprovalsMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Reject request failed'));
  }
  const approval = decodeApproval(body?.approval);
  if (!approval) throw new Error('Reject response was invalid');
  return approval;
}
