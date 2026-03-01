import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export interface DashboardRuntimeSnapshotPayload {
  policy: Record<string, unknown>;
  settings: Record<string, unknown>;
  gasSponsorship: Record<string, unknown>;
  smartWallets: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface DashboardRuntimeSnapshot {
  orgId: string;
  projectId: string | null;
  environmentId: string;
  snapshotId: string;
  version: number;
  effectiveAt: string;
  checksum: string;
  payload: DashboardRuntimeSnapshotPayload;
  createdAt: string;
  createdBy: string;
}

interface ConsoleRuntimeSnapshotListResponse {
  ok?: boolean;
  message?: string;
  snapshots?: unknown;
}

interface ConsoleRuntimeSnapshotLatestResponse {
  ok?: boolean;
  message?: string;
  snapshot?: unknown;
}

interface ConsoleRuntimeSnapshotMutationResponse {
  ok?: boolean;
  message?: string;
  snapshot?: unknown;
}

function decodeObject(raw: unknown): Record<string, unknown> | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  return raw as Record<string, unknown>;
}

function decodePayload(raw: unknown): DashboardRuntimeSnapshotPayload | null {
  const row = decodeObject(raw);
  if (!row) return null;
  const policy = decodeObject(row.policy);
  const settings = decodeObject(row.settings);
  const gasSponsorship = decodeObject(row.gasSponsorship);
  const smartWallets = decodeObject(row.smartWallets);
  if (!policy || !settings || !gasSponsorship || !smartWallets) return null;
  const metadata = row.metadata === undefined ? undefined : decodeObject(row.metadata);
  if (row.metadata !== undefined && !metadata) return null;
  return {
    policy,
    settings,
    gasSponsorship,
    smartWallets,
    ...(metadata ? { metadata } : {}),
  };
}

function decodeRuntimeSnapshot(raw: unknown): DashboardRuntimeSnapshot | null {
  const row = decodeObject(raw);
  if (!row) return null;
  const orgId = String(row.orgId || '').trim();
  const environmentId = String(row.environmentId || '').trim();
  const snapshotId = String(row.snapshotId || '').trim();
  const effectiveAt = String(row.effectiveAt || '').trim();
  const checksum = String(row.checksum || '').trim();
  const createdAt = String(row.createdAt || '').trim();
  const createdBy = String(row.createdBy || '').trim();
  if (!orgId || !environmentId || !snapshotId || !effectiveAt || !checksum || !createdAt || !createdBy) {
    return null;
  }
  const version = Number(row.version || 0);
  if (!Number.isFinite(version) || version <= 0) return null;
  const payload = decodePayload(row.payload);
  if (!payload) return null;
  return {
    orgId,
    projectId: row.projectId == null ? null : String(row.projectId || '').trim() || null,
    environmentId,
    snapshotId,
    version,
    effectiveAt,
    checksum,
    payload,
    createdAt,
    createdBy,
  };
}

interface RuntimeSnapshotScope {
  environmentId: string;
  projectId?: string;
}

function buildScopeParams(input: RuntimeSnapshotScope): URLSearchParams {
  const environmentId = String(input.environmentId || '').trim();
  if (!environmentId) throw new Error('Environment id is required');
  const params = new URLSearchParams();
  params.set('environmentId', environmentId);
  const projectId = String(input.projectId || '').trim();
  if (projectId) params.set('projectId', projectId);
  return params;
}

export async function listDashboardRuntimeSnapshots(input: RuntimeSnapshotScope & { limit?: number }): Promise<
  DashboardRuntimeSnapshot[]
> {
  const base = requireConsoleBaseUrl();
  const params = buildScopeParams(input);
  if (input.limit !== undefined) {
    if (!Number.isFinite(input.limit) || Number(input.limit) <= 0) {
      throw new Error('Runtime snapshot limit must be a positive integer');
    }
    params.set('limit', String(Math.floor(Number(input.limit))));
  }
  const response = await fetch(`${base}/console/runtime-snapshots?${params.toString()}`, {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleRuntimeSnapshotListResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Runtime snapshots request failed'));
  }
  const rows = Array.isArray(body?.snapshots) ? body.snapshots : [];
  return rows
    .map((entry) => decodeRuntimeSnapshot(entry))
    .filter((entry): entry is DashboardRuntimeSnapshot => entry !== null);
}

export async function getLatestDashboardRuntimeSnapshot(
  input: RuntimeSnapshotScope,
): Promise<DashboardRuntimeSnapshot | null> {
  const base = requireConsoleBaseUrl();
  const params = buildScopeParams(input);
  const response = await fetch(`${base}/console/runtime-snapshots/latest?${params.toString()}`, {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleRuntimeSnapshotLatestResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Latest runtime snapshot request failed'));
  }
  if (body?.snapshot == null) return null;
  const snapshot = decodeRuntimeSnapshot(body.snapshot);
  if (!snapshot) throw new Error('Latest runtime snapshot response was invalid');
  return snapshot;
}

export async function publishCurrentDashboardRuntimeSnapshot(input: {
  environmentId: string;
  projectId?: string;
  snapshotId?: string;
  effectiveAt?: string;
}): Promise<DashboardRuntimeSnapshot> {
  const environmentId = String(input.environmentId || '').trim();
  if (!environmentId) throw new Error('Environment id is required');
  const projectId = String(input.projectId || '').trim();
  const snapshotId = String(input.snapshotId || '').trim();
  const effectiveAt = String(input.effectiveAt || '').trim();
  const body: Record<string, unknown> = {
    environmentId,
  };
  if (projectId) body.projectId = projectId;
  if (snapshotId) body.snapshotId = snapshotId;
  if (effectiveAt) body.effectiveAt = effectiveAt;

  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/runtime-snapshots/publish-current`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(body),
  });
  const result = (await parseConsoleJson(response)) as ConsoleRuntimeSnapshotMutationResponse | null;
  if (!response.ok || result?.ok !== true) {
    throw new Error(consoleErrorMessage(response, result, 'Publish current runtime snapshot request failed'));
  }
  const snapshot = decodeRuntimeSnapshot(result?.snapshot);
  if (!snapshot) throw new Error('Publish current runtime snapshot response was invalid');
  return snapshot;
}
