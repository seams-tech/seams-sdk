import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export interface DashboardConsoleApiKey {
  id: string;
  orgId: string;
  name: string;
  environmentId: string;
  scopes: string[];
  ipAllowlist: string[];
  status: string;
  secretVersion: number;
  secretPreview: string;
  createdAt: string;
  updatedAt: string;
  lastUsedAt: string | null;
  endpointUsageCounts: Record<string, number>;
  anomalyFlags: string[];
}

interface ConsoleApiKeysListResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  apiKeys?: unknown;
}

interface ConsoleApiKeyMutationResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  apiKey?: unknown;
  secret?: unknown;
  revoked?: unknown;
}

function readStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    const value = String(entry || '').trim();
    if (!value) continue;
    const dedupeKey = value.toLowerCase();
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push(value);
  }
  return out;
}

function readEndpointUsageCounts(raw: unknown): Record<string, number> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const row = raw as Record<string, unknown>;
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(row)) {
    const endpoint = String(key || '').trim();
    if (!endpoint) continue;
    const count = Number(value || 0);
    if (!Number.isFinite(count) || count < 0) continue;
    out[endpoint] = Math.floor(count);
  }
  return out;
}

function decodeApiKey(raw: unknown): DashboardConsoleApiKey | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const orgId = String(row.orgId || '').trim();
  if (!id || !orgId) return null;
  return {
    id,
    orgId,
    name: String(row.name || '').trim() || id,
    environmentId: String(row.environmentId || '').trim(),
    scopes: readStringArray(row.scopes),
    ipAllowlist: readStringArray(row.ipAllowlist),
    status: String(row.status || '').trim() || 'ACTIVE',
    secretVersion: Number(row.secretVersion || 0),
    secretPreview: String(row.secretPreview || '').trim(),
    createdAt: String(row.createdAt || '').trim(),
    updatedAt: String(row.updatedAt || '').trim(),
    lastUsedAt: row.lastUsedAt == null ? null : String(row.lastUsedAt || '').trim() || null,
    endpointUsageCounts: readEndpointUsageCounts(row.endpointUsageCounts),
    anomalyFlags: readStringArray(row.anomalyFlags),
  };
}

export async function listDashboardApiKeys(): Promise<DashboardConsoleApiKey[]> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/api-keys`, {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleApiKeysListResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Console API keys request failed'));
  }
  const rows = Array.isArray(body?.apiKeys) ? body.apiKeys : [];
  return rows
    .map((entry) => decodeApiKey(entry))
    .filter((entry): entry is DashboardConsoleApiKey => entry !== null);
}

export async function createDashboardApiKey(input: {
  name: string;
  environmentId: string;
  scopes: string[];
  ipAllowlist?: string[];
}): Promise<{ apiKey: DashboardConsoleApiKey; secret: string }> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/api-keys`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleApiKeyMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Create API key request failed'));
  }
  const apiKey = decodeApiKey(body?.apiKey);
  const secret = String(body?.secret || '').trim();
  if (!apiKey || !secret) {
    throw new Error('Create API key response was missing apiKey or secret');
  }
  return { apiKey, secret };
}

export async function rotateDashboardApiKey(input: {
  apiKeyId: string;
  reason?: string;
}): Promise<{ apiKey: DashboardConsoleApiKey; secret: string }> {
  const apiKeyId = String(input.apiKeyId || '').trim();
  if (!apiKeyId) throw new Error('API key id is required for rotate');
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/api-keys/${encodeURIComponent(apiKeyId)}/rotate`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input.reason ? { reason: input.reason } : {}),
  });
  const body = (await parseConsoleJson(response)) as ConsoleApiKeyMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Rotate API key request failed'));
  }
  const apiKey = decodeApiKey(body?.apiKey);
  const secret = String(body?.secret || '').trim();
  if (!apiKey || !secret) {
    throw new Error('Rotate API key response was missing apiKey or secret');
  }
  return { apiKey, secret };
}

export async function revokeDashboardApiKey(input: {
  apiKeyId: string;
}): Promise<{ revoked: boolean; apiKey: DashboardConsoleApiKey | null }> {
  const apiKeyId = String(input.apiKeyId || '').trim();
  if (!apiKeyId) throw new Error('API key id is required for revoke');
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/api-keys/${encodeURIComponent(apiKeyId)}`, {
    method: 'DELETE',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleApiKeyMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Revoke API key request failed'));
  }
  return {
    revoked: body?.revoked === true,
    apiKey: decodeApiKey(body?.apiKey),
  };
}
