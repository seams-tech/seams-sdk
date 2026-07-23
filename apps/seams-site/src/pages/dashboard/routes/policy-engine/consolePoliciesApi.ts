import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  fetchConsoleEndpoint,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export interface DashboardConsolePolicy {
  id: string;
  orgId: string;
  isSystemDefault: boolean;
  kind: 'TRANSACTION' | 'GAS_SPONSORSHIP';
  name: string;
  description: string | null;
  status: 'DRAFT' | 'PUBLISHED' | 'ARCHIVED';
  version: number;
  rules: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
  publishedAt: string | null;
}

export interface DashboardConsolePolicyVersion {
  policyId: string;
  kind: 'TRANSACTION' | 'GAS_SPONSORSHIP';
  version: number;
  status: 'DRAFT' | 'PUBLISHED' | 'ARCHIVED';
  rules: Record<string, unknown>;
  publishedAt: string | null;
  createdAt: string;
  actorUserId: string;
}

export interface DashboardConsolePolicySimulation {
  policyId: string;
  decision: 'ALLOW' | 'DENY';
  denyReasons: Array<{
    code:
      | 'ACTION_BLOCKED'
      | 'CHAIN_NOT_ALLOWED'
      | 'AMOUNT_LIMIT_EXCEEDED'
      | 'CONTRACT_NOT_ALLOWED'
      | 'FUNCTION_NOT_ALLOWED';
    message: string;
  }>;
  evaluatedAt: string;
  policyVersion: number;
  normalizedRequest: {
    action: string;
    chain: string | null;
    amountMinor: number | null;
    contractAddress: string | null;
    functionSelector: string | null;
  };
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

interface ConsolePolicyVersionsResponse {
  ok?: boolean;
  message?: string;
  versions?: unknown;
}

interface ConsolePolicyResponse {
  ok?: boolean;
  message?: string;
  policy?: unknown;
  removed?: unknown;
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

function decodeSimulationDenyReasons(
  raw: unknown,
): DashboardConsolePolicySimulation['denyReasons'] {
  if (!Array.isArray(raw)) return [];
  const out: DashboardConsolePolicySimulation['denyReasons'] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const row = entry as Record<string, unknown>;
    const code = String(row.code || '').trim().toUpperCase();
    const message = String(row.message || '').trim();
    if (!message) continue;
    if (
      code !== 'ACTION_BLOCKED' &&
      code !== 'CHAIN_NOT_ALLOWED' &&
      code !== 'AMOUNT_LIMIT_EXCEEDED' &&
      code !== 'CONTRACT_NOT_ALLOWED' &&
      code !== 'FUNCTION_NOT_ALLOWED'
    ) {
      continue;
    }
    out.push({ code, message });
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
  const kindRaw = String(row.kind || '').trim().toUpperCase();
  const kind = kindRaw === 'GAS_SPONSORSHIP' ? 'GAS_SPONSORSHIP' : 'TRANSACTION';
  const rulesRaw =
    row.rules && typeof row.rules === 'object' && !Array.isArray(row.rules)
      ? (row.rules as Record<string, unknown>)
      : {};
  return {
    id,
    orgId,
    isSystemDefault: row.isSystemDefault === true,
    kind,
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

function decodePolicyVersion(raw: unknown): DashboardConsolePolicyVersion | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const policyId = String(row.policyId || '').trim();
  if (!policyId) return null;
  const statusRaw = String(row.status || '').trim().toUpperCase();
  const status =
    statusRaw === 'ARCHIVED' ? 'ARCHIVED' : statusRaw === 'PUBLISHED' ? 'PUBLISHED' : 'DRAFT';
  const kindRaw = String(row.kind || '').trim().toUpperCase();
  const kind = kindRaw === 'GAS_SPONSORSHIP' ? 'GAS_SPONSORSHIP' : 'TRANSACTION';
  const rulesRaw =
    row.rules && typeof row.rules === 'object' && !Array.isArray(row.rules)
      ? (row.rules as Record<string, unknown>)
      : {};
  return {
    policyId,
    kind,
    version: Number(row.version || 0),
    status,
    rules: rulesRaw,
    publishedAt: row.publishedAt == null ? null : String(row.publishedAt || '').trim() || null,
    createdAt: String(row.createdAt || '').trim(),
    actorUserId: String(row.actorUserId || '').trim(),
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
    denyReasons: decodeSimulationDenyReasons(row.denyReasons),
    evaluatedAt: String(row.evaluatedAt || '').trim(),
    policyVersion: Number(row.policyVersion || 0),
    normalizedRequest:
      row.normalizedRequest && typeof row.normalizedRequest === 'object' && !Array.isArray(row.normalizedRequest)
        ? {
            action: String((row.normalizedRequest as Record<string, unknown>).action || '')
              .trim()
              .toLowerCase(),
            chain: (() => {
              const rawChain = (row.normalizedRequest as Record<string, unknown>).chain;
              const value = rawChain == null ? '' : String(rawChain || '').trim().toLowerCase();
              return value || null;
            })(),
            amountMinor: (() => {
              const rawAmount = (row.normalizedRequest as Record<string, unknown>).amountMinor;
              const value = Number(rawAmount);
              return Number.isFinite(value) ? value : null;
            })(),
            contractAddress: (() => {
              const rawContract = (row.normalizedRequest as Record<string, unknown>).contractAddress;
              const value = rawContract == null ? '' : String(rawContract || '').trim().toLowerCase();
              return value || null;
            })(),
            functionSelector: (() => {
              const rawSelector = (row.normalizedRequest as Record<string, unknown>).functionSelector;
              const value = rawSelector == null ? '' : String(rawSelector || '').trim().toLowerCase();
              return value || null;
            })(),
          }
        : {
            action: '',
            chain: null,
            amountMinor: null,
            contractAddress: null,
            functionSelector: null,
          },
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

export async function listDashboardPolicies(input: {
  kind?: DashboardConsolePolicy['kind'];
} = {}): Promise<DashboardConsolePolicy[]> {
  const base = requireConsoleBaseUrl();
  const search = new URLSearchParams();
  if (input.kind) search.set('kind', input.kind);
  const listPath = `/console/policies${search.size > 0 ? `?${search.toString()}` : ''}`;
  const response = await fetchConsoleEndpoint(
    `${base}${listPath}`,
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
    {
      baseUrl: base,
      path: listPath,
      operation: 'Policy list request',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsolePoliciesResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Policy list request failed'));
  }
  const rows = Array.isArray(body?.policies) ? body.policies : [];
  return rows
    .map((entry) => decodePolicy(entry))
    .filter((entry): entry is DashboardConsolePolicy => entry !== null);
}

export async function listDashboardPolicyVersions(
  policyId: string,
): Promise<DashboardConsolePolicyVersion[]> {
  const normalizedPolicyId = String(policyId || '').trim();
  if (!normalizedPolicyId) throw new Error('Policy id is required');
  const base = requireConsoleBaseUrl();
  const versionsPath = `/console/policies/${encodeURIComponent(normalizedPolicyId)}/versions`;
  const response = await fetchConsoleEndpoint(
    `${base}${versionsPath}`,
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
    {
      baseUrl: base,
      path: versionsPath,
      operation: 'Policy version list request',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsolePolicyVersionsResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Policy version list request failed'));
  }
  const rows = Array.isArray(body?.versions) ? body.versions : [];
  return rows
    .map((entry) => decodePolicyVersion(entry))
    .filter((entry): entry is DashboardConsolePolicyVersion => entry !== null);
}

export async function createDashboardPolicy(input: {
  kind?: DashboardConsolePolicy['kind'];
  name: string;
  description?: string;
  rules?: Record<string, unknown>;
  assignment?: {
    scopeType: 'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'WALLET';
    scopeId: string;
  };
}): Promise<DashboardConsolePolicy> {
  const base = requireConsoleBaseUrl();
  const response = await fetchConsoleEndpoint(
    `${base}/console/policies`,
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify(input),
    },
    {
      baseUrl: base,
      path: '/console/policies',
      operation: 'Create policy request',
    },
  );
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
  const updatePath = `/console/policies/${encodeURIComponent(policyId)}`;
  const response = await fetchConsoleEndpoint(
    `${base}${updatePath}`,
    {
      method: 'PATCH',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify({
        ...(input.name ? { name: input.name } : {}),
        ...(input.description !== undefined ? { description: input.description } : {}),
        ...(input.rules ? { rules: input.rules } : {}),
      }),
    },
    {
      baseUrl: base,
      path: updatePath,
      operation: 'Update policy request',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsolePolicyResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Update policy request failed'));
  }
  const policy = decodePolicy(body?.policy);
  if (!policy) throw new Error('Update policy response missing policy');
  return policy;
}

export async function deleteDashboardPolicy(input: {
  policyId: string;
}): Promise<{ removed: boolean; policy: DashboardConsolePolicy | null }> {
  const policyId = String(input.policyId || '').trim();
  if (!policyId) throw new Error('Policy id is required');
  const base = requireConsoleBaseUrl();
  const deletePath = `/console/policies/${encodeURIComponent(policyId)}`;
  const response = await fetchConsoleEndpoint(
    `${base}${deletePath}`,
    {
      method: 'DELETE',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
    {
      baseUrl: base,
      path: deletePath,
      operation: 'Delete policy request',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsolePolicyResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Delete policy request failed'));
  }
  return {
    removed: body?.removed === true,
    policy: decodePolicy(body?.policy),
  };
}

export async function publishDashboardPolicy(input: {
  policyId: string;
  approvalId?: string;
}): Promise<DashboardConsolePolicy> {
  const policyId = String(input.policyId || '').trim();
  if (!policyId) throw new Error('Policy id is required');
  const approvalId = String(input.approvalId || '').trim();
  const requestBody = approvalId ? JSON.stringify({ approvalId }) : null;
  const base = requireConsoleBaseUrl();
  const publishPath = `/console/policies/${encodeURIComponent(policyId)}/publish`;
  const response = await fetchConsoleEndpoint(
    `${base}${publishPath}`,
    {
      method: 'POST',
      headers: requestBody ? buildConsoleJsonHeaders() : buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
      ...(requestBody ? { body: requestBody } : {}),
    },
    {
      baseUrl: base,
      path: publishPath,
      operation: 'Publish policy request',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsolePolicyPublishResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Publish policy request failed'));
  }
  const policy = decodePolicy(body?.result?.policy);
  if (!policy) throw new Error('Publish policy response missing policy');
  return policy;
}

/**
 * Republishes the environment's runtime snapshot from its current policies.
 * Publishing a policy version does not refresh the runtime snapshot that the
 * relayer / router API reads, so callers that mutate sponsorship policy must
 * republish the snapshot for the change to take effect.
 */
export async function publishCurrentDashboardRuntimeSnapshot(input: {
  environmentId: string;
  projectId?: string;
}): Promise<void> {
  const environmentId = String(input.environmentId || '').trim();
  if (!environmentId) {
    throw new Error('Environment id is required to publish a runtime snapshot');
  }
  const projectId = String(input.projectId || '').trim();
  const base = requireConsoleBaseUrl();
  const path = '/console/runtime-snapshots/publish-current';
  const response = await fetchConsoleEndpoint(
    `${base}${path}`,
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify({ environmentId, ...(projectId ? { projectId } : {}) }),
    },
    {
      baseUrl: base,
      path,
      operation: 'Publish current runtime snapshot request',
    },
  );
  const body = (await parseConsoleJson(response)) as { ok?: boolean } | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(
      consoleErrorMessage(response, body, 'Publish current runtime snapshot request failed'),
    );
  }
}

export async function simulateDashboardPolicy(input: {
  policyId: string;
  action: string;
  chain?: string;
  amountMinor?: number;
  contractAddress?: string;
  functionSelector?: string;
  metadata?: Record<string, unknown>;
}): Promise<DashboardConsolePolicySimulation> {
  const policyId = String(input.policyId || '').trim();
  if (!policyId) throw new Error('Policy id is required');
  const base = requireConsoleBaseUrl();
  const simulatePath = `/console/policies/${encodeURIComponent(policyId)}/simulate`;
  const response = await fetchConsoleEndpoint(
    `${base}${simulatePath}`,
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify({
        action: input.action,
        ...(input.chain ? { chain: input.chain } : {}),
        ...(input.amountMinor !== undefined ? { amountMinor: input.amountMinor } : {}),
        ...(input.contractAddress ? { contractAddress: input.contractAddress } : {}),
        ...(input.functionSelector ? { functionSelector: input.functionSelector } : {}),
        ...(input.metadata ? { metadata: input.metadata } : {}),
      }),
    },
    {
      baseUrl: base,
      path: simulatePath,
      operation: 'Policy simulation request',
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
  const assignmentsPath = `/console/policies/assignments${query ? `?${query}` : ''}`;
  const response = await fetchConsoleEndpoint(
    `${base}${assignmentsPath}`,
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
    {
      baseUrl: base,
      path: assignmentsPath,
      operation: 'Policy assignment list request',
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
