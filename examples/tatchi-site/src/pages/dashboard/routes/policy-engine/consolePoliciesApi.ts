import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export interface DashboardConsolePolicy {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  status: 'DRAFT' | 'PUBLISHED' | 'ARCHIVED';
  version: number;
  rules: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
  publishedAt: string | null;
}

export interface DashboardConsolePolicySimulation {
  policyId: string;
  decision: 'ALLOW' | 'DENY';
  reasons: string[];
  evaluatedAt: string;
  policyVersion: number;
}

export interface DashboardConsolePolicyAssignment {
  id: string;
  orgId: string;
  scopeType: 'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'WALLET';
  scopeId: string;
  policyId: string;
  createdAt: string;
  updatedAt: string;
}

interface ConsolePoliciesResponse {
  ok?: boolean;
  message?: string;
  policies?: unknown;
}

interface ConsolePolicyResponse {
  ok?: boolean;
  message?: string;
  policy?: unknown;
}

interface ConsolePolicyPublishResponse {
  ok?: boolean;
  message?: string;
  result?: {
    published?: unknown;
    policy?: unknown;
  };
}

interface ConsolePolicySimulationResponse {
  ok?: boolean;
  message?: string;
  simulation?: unknown;
}

interface ConsolePolicyAssignmentsResponse {
  ok?: boolean;
  message?: string;
  assignments?: unknown;
}

interface ConsolePolicyAssignmentResponse {
  ok?: boolean;
  message?: string;
  assignment?: unknown;
  removed?: unknown;
}

function decodeStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const entry of raw) {
    const value = String(entry || '').trim();
    if (!value) continue;
    out.push(value);
  }
  return out;
}

function decodePolicy(raw: unknown): DashboardConsolePolicy | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const orgId = String(row.orgId || '').trim();
  if (!id || !orgId) return null;
  const statusRaw = String(row.status || '').trim().toUpperCase();
  const status =
    statusRaw === 'ARCHIVED' ? 'ARCHIVED' : statusRaw === 'PUBLISHED' ? 'PUBLISHED' : 'DRAFT';
  const rulesRaw =
    row.rules && typeof row.rules === 'object' && !Array.isArray(row.rules)
      ? (row.rules as Record<string, unknown>)
      : {};
  return {
    id,
    orgId,
    name: String(row.name || '').trim(),
    description: row.description == null ? null : String(row.description || '').trim() || null,
    status,
    version: Number(row.version || 0),
    rules: rulesRaw,
    createdAt: String(row.createdAt || '').trim(),
    updatedAt: String(row.updatedAt || '').trim(),
    publishedAt: row.publishedAt == null ? null : String(row.publishedAt || '').trim() || null,
  };
}

function decodeSimulation(raw: unknown): DashboardConsolePolicySimulation | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const policyId = String(row.policyId || '').trim();
  if (!policyId) return null;
  const decisionRaw = String(row.decision || '').trim().toUpperCase();
  const decision = decisionRaw === 'DENY' ? 'DENY' : 'ALLOW';
  return {
    policyId,
    decision,
    reasons: decodeStringArray(row.reasons),
    evaluatedAt: String(row.evaluatedAt || '').trim(),
    policyVersion: Number(row.policyVersion || 0),
  };
}

function decodeAssignment(raw: unknown): DashboardConsolePolicyAssignment | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const orgId = String(row.orgId || '').trim();
  const scopeTypeRaw = String(row.scopeType || '')
    .trim()
    .toUpperCase();
  const scopeType =
    scopeTypeRaw === 'WALLET'
      ? 'WALLET'
      : scopeTypeRaw === 'ENVIRONMENT'
        ? 'ENVIRONMENT'
        : scopeTypeRaw === 'PROJECT'
          ? 'PROJECT'
          : scopeTypeRaw === 'ORG'
            ? 'ORG'
            : null;
  const scopeId = String(row.scopeId || '').trim();
  const policyId = String(row.policyId || '').trim();
  if (!id || !orgId || !scopeType || !scopeId || !policyId) return null;
  return {
    id,
    orgId,
    scopeType,
    scopeId,
    policyId,
    createdAt: String(row.createdAt || '').trim(),
    updatedAt: String(row.updatedAt || '').trim(),
  };
}

export async function listDashboardPolicies(): Promise<DashboardConsolePolicy[]> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/policies`, {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsolePoliciesResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Policy list request failed'));
  }
  const rows = Array.isArray(body?.policies) ? body.policies : [];
  return rows
    .map((entry) => decodePolicy(entry))
    .filter((entry): entry is DashboardConsolePolicy => entry !== null);
}

export async function createDashboardPolicy(input: {
  id?: string;
  name: string;
  description?: string;
  rules?: Record<string, unknown>;
}): Promise<DashboardConsolePolicy> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/policies`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsolePolicyResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Create policy request failed'));
  }
  const policy = decodePolicy(body?.policy);
  if (!policy) throw new Error('Create policy response missing policy');
  return policy;
}

export async function updateDashboardPolicy(input: {
  policyId: string;
  name?: string;
  description?: string;
  rules?: Record<string, unknown>;
}): Promise<DashboardConsolePolicy> {
  const policyId = String(input.policyId || '').trim();
  if (!policyId) throw new Error('Policy id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/policies/${encodeURIComponent(policyId)}`, {
    method: 'PATCH',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify({
      ...(input.name ? { name: input.name } : {}),
      ...(input.description !== undefined ? { description: input.description } : {}),
      ...(input.rules ? { rules: input.rules } : {}),
    }),
  });
  const body = (await parseConsoleJson(response)) as ConsolePolicyResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Update policy request failed'));
  }
  const policy = decodePolicy(body?.policy);
  if (!policy) throw new Error('Update policy response missing policy');
  return policy;
}

export async function publishDashboardPolicy(input: {
  policyId: string;
}): Promise<DashboardConsolePolicy> {
  const policyId = String(input.policyId || '').trim();
  if (!policyId) throw new Error('Policy id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/policies/${encodeURIComponent(policyId)}/publish`, {
    method: 'POST',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsolePolicyPublishResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Publish policy request failed'));
  }
  const policy = decodePolicy(body?.result?.policy);
  if (!policy) throw new Error('Publish policy response missing policy');
  return policy;
}

export async function simulateDashboardPolicy(input: {
  policyId: string;
  action: string;
  chain?: string;
  amountMinor?: number;
  metadata?: Record<string, unknown>;
}): Promise<DashboardConsolePolicySimulation> {
  const policyId = String(input.policyId || '').trim();
  if (!policyId) throw new Error('Policy id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(
    `${base}/console/policies/${encodeURIComponent(policyId)}/simulate`,
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify({
        action: input.action,
        ...(input.chain ? { chain: input.chain } : {}),
        ...(input.amountMinor !== undefined ? { amountMinor: input.amountMinor } : {}),
        ...(input.metadata ? { metadata: input.metadata } : {}),
      }),
    },
  );
  const body = (await parseConsoleJson(response)) as ConsolePolicySimulationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Policy simulation request failed'));
  }
  const simulation = decodeSimulation(body?.simulation);
  if (!simulation) throw new Error('Policy simulation response missing simulation result');
  return simulation;
}

export async function listDashboardPolicyAssignments(input: {
  scopeType?: 'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'WALLET';
  scopeId?: string;
} = {}): Promise<DashboardConsolePolicyAssignment[]> {
  const params = new URLSearchParams();
  if (input.scopeType) params.set('scopeType', input.scopeType);
  if (input.scopeId) params.set('scopeId', input.scopeId);
  const query = params.toString();
  const base = requireConsoleBaseUrl();
  const response = await fetch(
    `${base}/console/policies/assignments${query ? `?${query}` : ''}`,
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsolePolicyAssignmentsResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Policy assignment list request failed'));
  }
  const rows = Array.isArray(body?.assignments) ? body.assignments : [];
  return rows
    .map((entry) => decodeAssignment(entry))
    .filter((entry): entry is DashboardConsolePolicyAssignment => entry !== null);
}

export async function upsertDashboardPolicyAssignment(input: {
  scopeType: 'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'WALLET';
  scopeId: string;
  policyId: string;
}): Promise<DashboardConsolePolicyAssignment> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/policies/assignments`, {
    method: 'PUT',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsolePolicyAssignmentResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Policy assignment upsert request failed'));
  }
  const assignment = decodeAssignment(body?.assignment);
  if (!assignment) throw new Error('Policy assignment upsert response missing assignment');
  return assignment;
}

export async function deleteDashboardPolicyAssignment(input: {
  assignmentId: string;
}): Promise<{ removed: boolean; assignment: DashboardConsolePolicyAssignment | null }> {
  const assignmentId = String(input.assignmentId || '').trim();
  if (!assignmentId) throw new Error('Assignment id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(
    `${base}/console/policies/assignments/${encodeURIComponent(assignmentId)}`,
    {
      method: 'DELETE',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsolePolicyAssignmentResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Policy assignment delete request failed'));
  }
  return {
    removed: body?.removed === true,
    assignment: decodeAssignment(body?.assignment) || null,
  };
}
