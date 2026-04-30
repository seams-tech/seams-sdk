import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';
import {
  isApiCredentialScope,
  type ApiCredentialScope,
} from '../../../../../../../shared/src/console/apiKeyScopes';

export interface DashboardConsoleApiKey {
  id: string;
  kind: 'secret_key' | 'publishable_key';
  orgId: string;
  name: string;
  environmentId: string;
  scopes: ApiCredentialScope[];
  ipAllowlist: string[];
  allowedOrigins: string[];
  rateLimitBucket: string | null;
  quotaBucket: string | null;
  riskPolicy: Record<string, unknown>;
  paymentPolicy: Record<string, unknown>;
  status: string;
  secretVersion: number;
  credentialPreview: string;
  createdAt: string;
  updatedAt: string;
  lastUsedAt: string | null;
  expiresAt: string | null;
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
  deleted?: unknown;
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

function readApiCredentialScopeArray(raw: unknown): ApiCredentialScope[] {
  return readStringArray(raw).filter((value): value is ApiCredentialScope => isApiCredentialScope(value));
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

function readJsonObject(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  return { ...(raw as Record<string, unknown>) };
}

function decodeApiKey(raw: unknown): DashboardConsoleApiKey | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const orgId = String(row.orgId || '').trim();
  if (!id || !orgId) return null;
  return {
    id,
    kind:
      String(row.kind || '').trim() === 'publishable_key' ? 'publishable_key' : 'secret_key',
    orgId,
    name: String(row.name || '').trim() || id,
    environmentId: String(row.environmentId || '').trim(),
    scopes: readApiCredentialScopeArray(row.scopes),
    ipAllowlist: readStringArray(row.ipAllowlist),
    allowedOrigins: readStringArray(row.allowedOrigins),
    rateLimitBucket: row.rateLimitBucket == null ? null : String(row.rateLimitBucket || '').trim(),
    quotaBucket: row.quotaBucket == null ? null : String(row.quotaBucket || '').trim(),
    riskPolicy: readJsonObject(row.riskPolicy),
    paymentPolicy: readJsonObject(row.paymentPolicy),
    status: String(row.status || '').trim() || 'ACTIVE',
    secretVersion: Number(row.secretVersion || 0),
    credentialPreview: String(row.secretPreview || '').trim(),
    createdAt: String(row.createdAt || '').trim(),
    updatedAt: String(row.updatedAt || '').trim(),
    lastUsedAt: row.lastUsedAt == null ? null : String(row.lastUsedAt || '').trim() || null,
    expiresAt: row.expiresAt == null ? null : String(row.expiresAt || '').trim() || null,
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

export type CreateDashboardApiKeyInput =
  | {
      kind: 'secret_key';
      name: string;
      environmentId: string;
      scopes: ApiCredentialScope[];
      ipAllowlist?: string[];
    }
  | {
      kind: 'publishable_key';
      name: string;
      environmentId: string;
      allowedOrigins: string[];
      rateLimitBucket: string;
      quotaBucket: string;
      riskPolicy?: Record<string, unknown>;
      paymentPolicy?: Record<string, unknown>;
    };

export type UpdateDashboardApiKeyInput =
  | {
      apiKeyId: string;
      name?: string;
      scopes?: ApiCredentialScope[];
      ipAllowlist?: string[];
      expiresAt?: string | null;
    }
  | {
      apiKeyId: string;
      name?: string;
      allowedOrigins?: string[];
      rateLimitBucket?: string;
      quotaBucket?: string;
      riskPolicy?: Record<string, unknown>;
      paymentPolicy?: Record<string, unknown>;
      expiresAt?: string | null;
    };

export async function createDashboardApiKey(
  input: CreateDashboardApiKeyInput,
): Promise<{ apiKey: DashboardConsoleApiKey; credential: string }> {
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
  const credential = String(body?.secret || '').trim();
  if (!apiKey || !credential) {
    throw new Error('Create API key response was missing apiKey or credential');
  }
  return { apiKey, credential };
}

export async function updateDashboardApiKey(
  input: UpdateDashboardApiKeyInput,
): Promise<DashboardConsoleApiKey> {
  const apiKeyId = String(input.apiKeyId || '').trim();
  if (!apiKeyId) throw new Error('API key id is required for update');
  const { apiKeyId: _apiKeyId, ...payload } = input;
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/api-keys/${encodeURIComponent(apiKeyId)}`, {
    method: 'PATCH',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(payload),
  });
  const body = (await parseConsoleJson(response)) as ConsoleApiKeyMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Update API key request failed'));
  }
  const apiKey = decodeApiKey(body?.apiKey);
  if (!apiKey) {
    throw new Error('Update API key response was missing apiKey');
  }
  return apiKey;
}

export async function rotateDashboardApiKey(input: {
  apiKeyId: string;
  reason?: string;
}): Promise<{ apiKey: DashboardConsoleApiKey; credential: string }> {
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
  const credential = String(body?.secret || '').trim();
  if (!apiKey || !credential) {
    throw new Error('Rotate API key response was missing apiKey or credential');
  }
  return { apiKey, credential };
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

export async function deleteRevokedDashboardApiKey(input: {
  apiKeyId: string;
}): Promise<{ deleted: boolean; apiKey: DashboardConsoleApiKey | null }> {
  const apiKeyId = String(input.apiKeyId || '').trim();
  if (!apiKeyId) throw new Error('API key id is required for delete');
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/api-keys/${encodeURIComponent(apiKeyId)}/purge`, {
    method: 'DELETE',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleApiKeyMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Delete API key request failed'));
  }
  return {
    deleted: body?.deleted === true,
    apiKey: decodeApiKey(body?.apiKey),
  };
}
