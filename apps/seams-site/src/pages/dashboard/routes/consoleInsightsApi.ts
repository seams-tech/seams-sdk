import {
  buildConsoleAcceptHeaders,
  consoleErrorMessage,
  fetchConsoleEndpoint,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../consoleHttp';

export type DashboardConsolePolicyKind = 'TRANSACTION' | 'GAS_SPONSORSHIP';

export interface DashboardPolicyCoveragePolicy {
  policyId: string;
  policyName: string | null;
  policyKind: DashboardConsolePolicyKind | null;
  walletCount: number;
  activeWalletCount: number;
  archivedWalletCount: number;
  totalBalanceMinor: number;
  lastActivityAt: string | null;
}

export interface DashboardPolicyCoverageWalletSample {
  id: string;
  address: string;
  chain: string;
  status: string;
  balanceMinor: number;
  policyId: string | null;
  policyName: string | null;
  policyKind: DashboardConsolePolicyKind | null;
  userId: string;
  lastActivityAt: string | null;
  updatedAt: string;
}

export interface DashboardPolicyCoverage {
  scope: { projectId: string | null; environmentId: string | null };
  totals: {
    walletCount: number;
    policyCount: number;
    unassignedWalletCount: number;
    activeWalletCount: number;
    archivedWalletCount: number;
  };
  policies: DashboardPolicyCoveragePolicy[];
  unassignedWalletSample: DashboardPolicyCoverageWalletSample[];
  truncated: boolean;
}

export interface DashboardGasReadinessChain {
  chain: string;
  walletCount: number;
  activeWalletCount: number;
  recentActivityCount: number;
  totalBalanceMinor: number;
  avgBalanceMinor: number;
}

export interface DashboardGasReadinessWalletSample {
  id: string;
  chain: string;
  status: string;
  balanceMinor: number;
  policyId: string | null;
  policyName: string | null;
  policyKind: DashboardConsolePolicyKind | null;
  userId: string;
  lastActivityAt: string | null;
  updatedAt: string;
}

export interface DashboardGasReadiness {
  scope: { projectId: string | null; environmentId: string | null };
  totals: {
    walletCount: number;
    chainCount: number;
    recentActiveWalletCount: number;
    totalBalanceMinor: number;
    recentWindowDays: number;
  };
  chains: DashboardGasReadinessChain[];
  recentWalletSample: DashboardGasReadinessWalletSample[];
  truncated: boolean;
}

export interface DashboardExportGovernanceRequest {
  id: string;
  environmentId: string;
  walletId: string | null;
  mode: string;
  status: string;
  reason: string;
  requestedByUserId: string;
  requiredApprovals: number;
  approvalCount: number;
  pendingApprovals: number;
  constraints: {
    roles: string[];
    chains: string[];
    walletTypes: string[];
    environmentIds: string[];
  };
  createdAt: string;
  updatedAt: string;
}

export interface DashboardExportGovernance {
  scope: { environmentId: string | null };
  totals: {
    requestCount: number;
    pendingApprovalCount: number;
    approvedRequestCount: number;
    executedRequestCount: number;
    rejectedRequestCount: number;
    canceledRequestCount: number;
    selectedEnvironmentRequestCount: number;
    selectedEnvironmentPendingApprovalCount: number;
  };
  requests: DashboardExportGovernanceRequest[];
  selectedEnvironmentRequests: DashboardExportGovernanceRequest[];
}

interface ConsolePolicyCoverageResponse {
  ok?: boolean;
  message?: string;
  coverage?: unknown;
}

interface ConsoleGasReadinessResponse {
  ok?: boolean;
  message?: string;
  readiness?: unknown;
}

interface ConsoleExportGovernanceResponse {
  ok?: boolean;
  message?: string;
  governance?: unknown;
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

function decodePolicyKind(raw: unknown): DashboardConsolePolicyKind | null {
  const value = String(raw || '')
    .trim()
    .toUpperCase();
  if (value === 'TRANSACTION' || value === 'GAS_SPONSORSHIP') return value;
  return null;
}

function decodePolicyCoverage(raw: unknown): DashboardPolicyCoverage | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const totalsRaw =
    row.totals && typeof row.totals === 'object' && !Array.isArray(row.totals)
      ? (row.totals as Record<string, unknown>)
      : {};
  const scopeRaw =
    row.scope && typeof row.scope === 'object' && !Array.isArray(row.scope)
      ? (row.scope as Record<string, unknown>)
      : {};
  const policiesRaw = Array.isArray(row.policies) ? row.policies : [];
  const sampleRaw = Array.isArray(row.unassignedWalletSample) ? row.unassignedWalletSample : [];
  const policies: DashboardPolicyCoveragePolicy[] = [];
  for (const entry of policiesRaw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const policy = entry as Record<string, unknown>;
    policies.push({
      policyId: String(policy.policyId || '').trim() || 'unassigned',
      policyName: policy.policyName == null ? null : String(policy.policyName || '').trim() || null,
      policyKind: decodePolicyKind(policy.policyKind),
      walletCount: Number(policy.walletCount || 0),
      activeWalletCount: Number(policy.activeWalletCount || 0),
      archivedWalletCount: Number(policy.archivedWalletCount || 0),
      totalBalanceMinor: Number(policy.totalBalanceMinor || 0),
      lastActivityAt: policy.lastActivityAt == null ? null : String(policy.lastActivityAt || '').trim() || null,
    });
  }
  const unassignedWalletSample: DashboardPolicyCoverageWalletSample[] = [];
  for (const entry of sampleRaw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const wallet = entry as Record<string, unknown>;
    const id = String(wallet.id || '').trim();
    if (!id) continue;
    unassignedWalletSample.push({
      id,
      address: String(wallet.address || '').trim(),
      chain: String(wallet.chain || '').trim(),
      status: String(wallet.status || '').trim(),
      balanceMinor: Number(wallet.balanceMinor || 0),
      policyId: wallet.policyId == null ? null : String(wallet.policyId || '').trim() || null,
      policyName: wallet.policyName == null ? null : String(wallet.policyName || '').trim() || null,
      policyKind: decodePolicyKind(wallet.policyKind),
      userId: String(wallet.userId || '').trim(),
      lastActivityAt: wallet.lastActivityAt == null ? null : String(wallet.lastActivityAt || '').trim() || null,
      updatedAt: String(wallet.updatedAt || '').trim(),
    });
  }
  return {
    scope: {
      projectId: scopeRaw.projectId == null ? null : String(scopeRaw.projectId || '').trim() || null,
      environmentId:
        scopeRaw.environmentId == null ? null : String(scopeRaw.environmentId || '').trim() || null,
    },
    totals: {
      walletCount: Number(totalsRaw.walletCount || 0),
      policyCount: Number(totalsRaw.policyCount || 0),
      unassignedWalletCount: Number(totalsRaw.unassignedWalletCount || 0),
      activeWalletCount: Number(totalsRaw.activeWalletCount || 0),
      archivedWalletCount: Number(totalsRaw.archivedWalletCount || 0),
    },
    policies,
    unassignedWalletSample,
    truncated: row.truncated === true,
  };
}

function decodeGasReadiness(raw: unknown): DashboardGasReadiness | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const totalsRaw =
    row.totals && typeof row.totals === 'object' && !Array.isArray(row.totals)
      ? (row.totals as Record<string, unknown>)
      : {};
  const scopeRaw =
    row.scope && typeof row.scope === 'object' && !Array.isArray(row.scope)
      ? (row.scope as Record<string, unknown>)
      : {};
  const chainsRaw = Array.isArray(row.chains) ? row.chains : [];
  const sampleRaw = Array.isArray(row.recentWalletSample) ? row.recentWalletSample : [];
  const chains: DashboardGasReadinessChain[] = [];
  for (const entry of chainsRaw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const chain = entry as Record<string, unknown>;
    const chainName = String(chain.chain || '').trim();
    if (!chainName) continue;
    chains.push({
      chain: chainName,
      walletCount: Number(chain.walletCount || 0),
      activeWalletCount: Number(chain.activeWalletCount || 0),
      recentActivityCount: Number(chain.recentActivityCount || 0),
      totalBalanceMinor: Number(chain.totalBalanceMinor || 0),
      avgBalanceMinor: Number(chain.avgBalanceMinor || 0),
    });
  }
  const recentWalletSample: DashboardGasReadinessWalletSample[] = [];
  for (const entry of sampleRaw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const wallet = entry as Record<string, unknown>;
    const id = String(wallet.id || '').trim();
    if (!id) continue;
    recentWalletSample.push({
      id,
      chain: String(wallet.chain || '').trim(),
      status: String(wallet.status || '').trim(),
      balanceMinor: Number(wallet.balanceMinor || 0),
      policyId: wallet.policyId == null ? null : String(wallet.policyId || '').trim() || null,
      policyName: wallet.policyName == null ? null : String(wallet.policyName || '').trim() || null,
      policyKind: decodePolicyKind(wallet.policyKind),
      userId: String(wallet.userId || '').trim(),
      lastActivityAt: wallet.lastActivityAt == null ? null : String(wallet.lastActivityAt || '').trim() || null,
      updatedAt: String(wallet.updatedAt || '').trim(),
    });
  }
  return {
    scope: {
      projectId: scopeRaw.projectId == null ? null : String(scopeRaw.projectId || '').trim() || null,
      environmentId:
        scopeRaw.environmentId == null ? null : String(scopeRaw.environmentId || '').trim() || null,
    },
    totals: {
      walletCount: Number(totalsRaw.walletCount || 0),
      chainCount: Number(totalsRaw.chainCount || 0),
      recentActiveWalletCount: Number(totalsRaw.recentActiveWalletCount || 0),
      totalBalanceMinor: Number(totalsRaw.totalBalanceMinor || 0),
      recentWindowDays: Number(totalsRaw.recentWindowDays || 0),
    },
    chains,
    recentWalletSample,
    truncated: row.truncated === true,
  };
}

function decodeExportGovernance(raw: unknown): DashboardExportGovernance | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const totalsRaw =
    row.totals && typeof row.totals === 'object' && !Array.isArray(row.totals)
      ? (row.totals as Record<string, unknown>)
      : {};
  const scopeRaw =
    row.scope && typeof row.scope === 'object' && !Array.isArray(row.scope)
      ? (row.scope as Record<string, unknown>)
      : {};
  const requestRows = Array.isArray(row.requests) ? row.requests : [];
  const selectedRequestRows = Array.isArray(row.selectedEnvironmentRequests)
    ? row.selectedEnvironmentRequests
    : [];
  const decodeRequest = (entry: unknown): DashboardExportGovernanceRequest | null => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
    const request = entry as Record<string, unknown>;
    const id = String(request.id || '').trim();
    if (!id) return null;
    return {
      id,
      environmentId: String(request.environmentId || '').trim(),
      walletId: request.walletId == null ? null : String(request.walletId || '').trim() || null,
      mode: String(request.mode || '').trim(),
      status: String(request.status || '').trim(),
      reason: String(request.reason || '').trim(),
      requestedByUserId: String(request.requestedByUserId || '').trim(),
      requiredApprovals: Number(request.requiredApprovals || 0),
      approvalCount: Number(request.approvalCount || 0),
      pendingApprovals: Number(request.pendingApprovals || 0),
      constraints: {
        roles: decodeStringArray((request.constraints as Record<string, unknown> | undefined)?.roles),
        chains: decodeStringArray((request.constraints as Record<string, unknown> | undefined)?.chains),
        walletTypes: decodeStringArray(
          (request.constraints as Record<string, unknown> | undefined)?.walletTypes,
        ),
        environmentIds: decodeStringArray(
          (request.constraints as Record<string, unknown> | undefined)?.environmentIds,
        ),
      },
      createdAt: String(request.createdAt || '').trim(),
      updatedAt: String(request.updatedAt || '').trim(),
    };
  };
  return {
    scope: {
      environmentId:
        scopeRaw.environmentId == null ? null : String(scopeRaw.environmentId || '').trim() || null,
    },
    totals: {
      requestCount: Number(totalsRaw.requestCount || 0),
      pendingApprovalCount: Number(totalsRaw.pendingApprovalCount || 0),
      approvedRequestCount: Number(totalsRaw.approvedRequestCount || 0),
      executedRequestCount: Number(totalsRaw.executedRequestCount || 0),
      rejectedRequestCount: Number(totalsRaw.rejectedRequestCount || 0),
      canceledRequestCount: Number(totalsRaw.canceledRequestCount || 0),
      selectedEnvironmentRequestCount: Number(totalsRaw.selectedEnvironmentRequestCount || 0),
      selectedEnvironmentPendingApprovalCount: Number(
        totalsRaw.selectedEnvironmentPendingApprovalCount || 0,
      ),
    },
    requests: requestRows
      .map((entry) => decodeRequest(entry))
      .filter((entry): entry is DashboardExportGovernanceRequest => entry !== null),
    selectedEnvironmentRequests: selectedRequestRows
      .map((entry) => decodeRequest(entry))
      .filter((entry): entry is DashboardExportGovernanceRequest => entry !== null),
  };
}

async function fetchJson(path: string): Promise<any> {
  const base = requireConsoleBaseUrl();
  const response = await fetchConsoleEndpoint(
    `${base}${path}`,
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
    {
      baseUrl: base,
      path,
      operation: 'Console insights request',
    },
  );
  const body = await parseConsoleJson(response);
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Console insights request failed'));
  }
  return body;
}

export async function getDashboardPolicyCoverage(input: {
  projectId?: string;
  environmentId?: string;
} = {}): Promise<DashboardPolicyCoverage> {
  const params = new URLSearchParams();
  if (input.projectId) params.set('projectId', input.projectId);
  if (input.environmentId) params.set('environmentId', input.environmentId);
  const suffix = params.toString();
  const body = (await fetchJson(
    `/console/policy/coverage${suffix ? `?${suffix}` : ''}`,
  )) as ConsolePolicyCoverageResponse;
  const coverage = decodePolicyCoverage(body.coverage);
  if (!coverage) throw new Error('Policy coverage response was invalid');
  return coverage;
}

export async function getDashboardGasReadiness(input: {
  projectId?: string;
  environmentId?: string;
} = {}): Promise<DashboardGasReadiness> {
  const params = new URLSearchParams();
  if (input.projectId) params.set('projectId', input.projectId);
  if (input.environmentId) params.set('environmentId', input.environmentId);
  const suffix = params.toString();
  const body = (await fetchJson(
    `/console/gas/readiness${suffix ? `?${suffix}` : ''}`,
  )) as ConsoleGasReadinessResponse;
  const readiness = decodeGasReadiness(body.readiness);
  if (!readiness) throw new Error('Gas readiness response was invalid');
  return readiness;
}

export async function getDashboardExportGovernance(input: {
  environmentId?: string;
} = {}): Promise<DashboardExportGovernance> {
  const params = new URLSearchParams();
  if (input.environmentId) params.set('environmentId', input.environmentId);
  const suffix = params.toString();
  const body = (await fetchJson(
    `/console/export/governance${suffix ? `?${suffix}` : ''}`,
  )) as ConsoleExportGovernanceResponse;
  const governance = decodeExportGovernance(body.governance);
  if (!governance) throw new Error('Export governance response was invalid');
  return governance;
}
