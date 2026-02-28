import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export interface DashboardKeyExportRequest {
  id: string;
  environmentId: string;
  walletId: string | null;
  mode: string;
  status: string;
  reason: string;
  requestedByUserId: string;
  requiredApprovals: number;
  approvals: Array<{
    approverUserId: string;
    approvedAt: string;
    reason: string;
    mfaVerified: boolean;
  }>;
  constraints: {
    roles: string[];
    chains: string[];
    walletTypes: string[];
    environmentIds: string[];
  };
  createdAt: string;
  updatedAt: string;
}

interface ConsoleKeyExportListResponse {
  ok?: boolean;
  message?: string;
  exports?: unknown;
}

interface ConsoleKeyExportMutationResponse {
  ok?: boolean;
  message?: string;
  keyExport?: unknown;
}

function decodeStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    const value = String(entry || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function decodeKeyExport(raw: unknown): DashboardKeyExportRequest | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  if (!id) return null;
  const constraints =
    row.constraints && typeof row.constraints === 'object' && !Array.isArray(row.constraints)
      ? (row.constraints as Record<string, unknown>)
      : {};
  const approvalsRaw = Array.isArray(row.approvals) ? row.approvals : [];
  return {
    id,
    environmentId: String(row.environmentId || '').trim(),
    walletId: row.walletId == null ? null : String(row.walletId || '').trim() || null,
    mode: String(row.mode || '').trim() || 'APPROVAL_REQUIRED',
    status: String(row.status || '').trim() || 'PENDING_APPROVAL',
    reason: String(row.reason || '').trim(),
    requestedByUserId: String(row.requestedByUserId || '').trim(),
    requiredApprovals: Number(row.requiredApprovals || 0),
    approvals: approvalsRaw
      .map((entry) => {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
        const approval = entry as Record<string, unknown>;
        return {
          approverUserId: String(approval.approverUserId || '').trim(),
          approvedAt: String(approval.approvedAt || '').trim(),
          reason: String(approval.reason || '').trim(),
          mfaVerified: approval.mfaVerified === true,
        };
      })
      .filter(
        (
          entry,
        ): entry is DashboardKeyExportRequest['approvals'][number] => entry !== null,
      ),
    constraints: {
      roles: decodeStringArray(constraints.roles),
      chains: decodeStringArray(constraints.chains),
      walletTypes: decodeStringArray(constraints.walletTypes),
      environmentIds: decodeStringArray(constraints.environmentIds),
    },
    createdAt: String(row.createdAt || '').trim(),
    updatedAt: String(row.updatedAt || '').trim(),
  };
}

export async function listDashboardKeyExports(input: {
  environmentId?: string;
  status?: string;
} = {}): Promise<DashboardKeyExportRequest[]> {
  const base = requireConsoleBaseUrl();
  const params = new URLSearchParams();
  if (input.environmentId) params.set('environmentId', input.environmentId);
  if (input.status) params.set('status', input.status);
  const suffix = params.toString();
  const response = await fetch(`${base}/console/key-exports${suffix ? `?${suffix}` : ''}`, {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleKeyExportListResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Key exports request failed'));
  }
  const rows = Array.isArray(body?.exports) ? body.exports : [];
  return rows
    .map((entry) => decodeKeyExport(entry))
    .filter((entry): entry is DashboardKeyExportRequest => entry !== null);
}

export async function createDashboardKeyExport(
  input: Record<string, unknown>,
): Promise<DashboardKeyExportRequest> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/key-exports`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleKeyExportMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Create key export request failed'));
  }
  const keyExport = decodeKeyExport(body?.keyExport);
  if (!keyExport) throw new Error('Create key export response was invalid');
  return keyExport;
}

export async function approveDashboardKeyExport(
  exportId: string,
  input: { reason: string; mfaVerified: boolean },
): Promise<DashboardKeyExportRequest> {
  const id = String(exportId || '').trim();
  if (!id) throw new Error('Key export id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/key-exports/${encodeURIComponent(id)}/approve`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleKeyExportMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Approve key export request failed'));
  }
  const keyExport = decodeKeyExport(body?.keyExport);
  if (!keyExport) throw new Error('Approve key export response was invalid');
  return keyExport;
}
