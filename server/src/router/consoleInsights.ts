import type {
  ConsoleKeyExportRequestRecord,
  ConsoleKeyExportService,
  ConsoleKeyExportsContext,
} from '../console/keyExports';
import type { ConsolePolicyKind } from '../console/policies';
import type { ConsoleWallet, ConsoleWalletService, ConsoleWalletsContext } from '../console/wallets';

export interface ConsoleInsightsScope {
  projectId?: string;
  environmentId?: string;
}

export interface ConsolePolicyCoveragePolicy {
  policyId: string;
  policyName: string | null;
  policyKind: ConsolePolicyKind | null;
  walletCount: number;
  activeWalletCount: number;
  archivedWalletCount: number;
  totalBalanceMinor: number;
  lastActivityAt: string | null;
}

export interface ConsolePolicyCoverageWalletSample {
  id: string;
  address: string;
  chain: string;
  status: string;
  balanceMinor: number;
  policyId: string | null;
  policyName: string | null;
  policyKind: ConsolePolicyKind | null;
  userId: string;
  lastActivityAt: string | null;
  updatedAt: string;
}

export interface ConsolePolicyCoverageView {
  scope: { projectId: string | null; environmentId: string | null };
  totals: {
    walletCount: number;
    policyCount: number;
    unassignedWalletCount: number;
    activeWalletCount: number;
    archivedWalletCount: number;
  };
  policies: ConsolePolicyCoveragePolicy[];
  unassignedWalletSample: ConsolePolicyCoverageWalletSample[];
  truncated: boolean;
}

export interface ConsoleGasReadinessChain {
  chain: string;
  walletCount: number;
  activeWalletCount: number;
  recentActivityCount: number;
  totalBalanceMinor: number;
  avgBalanceMinor: number;
}

export interface ConsoleGasReadinessWalletSample {
  id: string;
  chain: string;
  status: string;
  balanceMinor: number;
  policyId: string | null;
  policyName: string | null;
  policyKind: ConsolePolicyKind | null;
  userId: string;
  lastActivityAt: string | null;
  updatedAt: string;
}

export interface ConsoleGasReadinessView {
  scope: { projectId: string | null; environmentId: string | null };
  totals: {
    walletCount: number;
    chainCount: number;
    recentActiveWalletCount: number;
    totalBalanceMinor: number;
    recentWindowDays: number;
  };
  chains: ConsoleGasReadinessChain[];
  recentWalletSample: ConsoleGasReadinessWalletSample[];
  truncated: boolean;
}

export interface ConsoleExportGovernanceRequest {
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

export interface ConsoleExportGovernanceView {
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
  requests: ConsoleExportGovernanceRequest[];
  selectedEnvironmentRequests: ConsoleExportGovernanceRequest[];
}

function normalizeScopeValue(raw: unknown): string | undefined {
  const value = String(raw || '').trim();
  return value || undefined;
}

function toMs(raw: string | null | undefined): number {
  if (!raw) return 0;
  const parsed = Date.parse(raw);
  return Number.isFinite(parsed) ? parsed : 0;
}

function compareIsoDesc(a: string | null | undefined, b: string | null | undefined): number {
  return toMs(b) - toMs(a);
}

function toScopeResponse(scope: ConsoleInsightsScope): {
  projectId: string | null;
  environmentId: string | null;
} {
  return {
    projectId: scope.projectId || null,
    environmentId: scope.environmentId || null,
  };
}

type ResolvedWalletPolicyPresentation = {
  policyId: string | null;
  policyName: string | null;
  policyKind: ConsolePolicyKind | null;
};

function toWalletSample(
  wallet: ConsoleWallet,
  policyOverride?: ResolvedWalletPolicyPresentation | null,
): ConsolePolicyCoverageWalletSample {
  return {
    id: wallet.id,
    address: wallet.address,
    chain: wallet.chain,
    status: wallet.status,
    balanceMinor: wallet.balanceMinor,
    policyId: policyOverride === undefined ? wallet.policyId : policyOverride?.policyId || null,
    policyName: policyOverride?.policyName || null,
    policyKind: policyOverride?.policyKind || null,
    userId: wallet.userId,
    lastActivityAt: wallet.lastActivityAt,
    updatedAt: wallet.updatedAt,
  };
}

function toGasWalletSample(
  wallet: ConsoleWallet,
  policyOverride?: ResolvedWalletPolicyPresentation | null,
): ConsoleGasReadinessWalletSample {
  return {
    id: wallet.id,
    chain: wallet.chain,
    status: wallet.status,
    balanceMinor: wallet.balanceMinor,
    policyId: policyOverride === undefined ? wallet.policyId : policyOverride?.policyId || null,
    policyName: policyOverride?.policyName || null,
    policyKind: policyOverride?.policyKind || null,
    userId: wallet.userId,
    lastActivityAt: wallet.lastActivityAt,
    updatedAt: wallet.updatedAt,
  };
}

function toExportGovernanceRequest(
  record: ConsoleKeyExportRequestRecord,
): ConsoleExportGovernanceRequest {
  const approvalCount = Array.isArray(record.approvals) ? record.approvals.length : 0;
  const requiredApprovals = Math.max(1, Number(record.requiredApprovals || 0));
  return {
    id: record.id,
    environmentId: record.environmentId,
    walletId: record.walletId,
    mode: record.mode,
    status: record.status,
    reason: record.reason,
    requestedByUserId: record.requestedByUserId,
    requiredApprovals,
    approvalCount,
    pendingApprovals: Math.max(requiredApprovals - approvalCount, 0),
    constraints: {
      roles: [...record.constraints.roles],
      chains: [...record.constraints.chains],
      walletTypes: [...record.constraints.walletTypes],
      environmentIds: [...record.constraints.environmentIds],
    },
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  };
}

export function resolveConsoleInsightsScope(input: {
  projectIdRaw?: unknown;
  environmentIdRaw?: unknown;
  claimsProjectId?: string;
  claimsEnvironmentId?: string;
}): ConsoleInsightsScope {
  const projectId = normalizeScopeValue(input.projectIdRaw) || normalizeScopeValue(input.claimsProjectId);
  const environmentId =
    normalizeScopeValue(input.environmentIdRaw) || normalizeScopeValue(input.claimsEnvironmentId);
  return {
    ...(projectId ? { projectId } : {}),
    ...(environmentId ? { environmentId } : {}),
  };
}

async function listAllWalletsForScope(input: {
  wallets: ConsoleWalletService;
  walletCtx: ConsoleWalletsContext;
  scope: ConsoleInsightsScope;
  maxPages?: number;
  pageLimit?: number;
}): Promise<{ wallets: ConsoleWallet[]; truncated: boolean }> {
  const maxPages = Math.max(1, Math.floor(Number(input.maxPages || 100)));
  const pageLimit = Math.max(1, Math.floor(Number(input.pageLimit || 100)));
  let cursor: string | undefined;
  let pages = 0;
  const collected = new Map<string, ConsoleWallet>();

  while (pages < maxPages) {
    const page = await input.wallets.listWallets(input.walletCtx, {
      limit: pageLimit,
      ...(cursor ? { cursor } : {}),
      ...(input.scope.projectId ? { projectId: input.scope.projectId } : {}),
      ...(input.scope.environmentId ? { environmentId: input.scope.environmentId } : {}),
    });
    for (const wallet of page.items) {
      collected.set(wallet.id, wallet);
    }
    pages += 1;
    if (!page.nextCursor) {
      return {
        wallets: Array.from(collected.values()),
        truncated: false,
      };
    }
    cursor = page.nextCursor;
  }

  return {
    wallets: Array.from(collected.values()),
    truncated: true,
  };
}

export async function buildConsolePolicyCoverageView(input: {
  wallets: ConsoleWalletService;
  walletCtx: ConsoleWalletsContext;
  scope: ConsoleInsightsScope;
  resolveWalletPolicies?: (
    wallets: ConsoleWallet[],
  ) => Promise<Record<string, ResolvedWalletPolicyPresentation>>;
}): Promise<ConsolePolicyCoverageView> {
  const collected = await listAllWalletsForScope(input);
  const resolvedWalletPolicies = input.resolveWalletPolicies
    ? await input.resolveWalletPolicies(collected.wallets)
    : {};
  const policies = new Map<string, ConsolePolicyCoveragePolicy>();
  let activeWalletCount = 0;
  let archivedWalletCount = 0;
  const unassigned: Array<{
    wallet: ConsoleWallet;
    policy: ResolvedWalletPolicyPresentation;
  }> = [];

  for (const wallet of collected.wallets) {
    const status = String(wallet.status || '').toUpperCase();
    if (status === 'ACTIVE') activeWalletCount += 1;
    if (status === 'ARCHIVED') archivedWalletCount += 1;

    const effectivePolicy =
      resolvedWalletPolicies[wallet.id] === undefined
        ? { policyId: wallet.policyId, policyName: null, policyKind: null }
        : resolvedWalletPolicies[wallet.id] || { policyId: null, policyName: null, policyKind: null };
    const effectivePolicyId = String(effectivePolicy.policyId || '').trim();
    const policyId = effectivePolicyId || 'unassigned';
    const current = policies.get(policyId) || {
      policyId,
      policyName: effectivePolicy.policyName || null,
      policyKind: effectivePolicy.policyKind || null,
      walletCount: 0,
      activeWalletCount: 0,
      archivedWalletCount: 0,
      totalBalanceMinor: 0,
      lastActivityAt: null,
    };
    if (!current.policyName && effectivePolicy.policyName) {
      current.policyName = effectivePolicy.policyName;
    }
    if (!current.policyKind && effectivePolicy.policyKind) {
      current.policyKind = effectivePolicy.policyKind;
    }
    current.walletCount += 1;
    if (status === 'ACTIVE') current.activeWalletCount += 1;
    if (status === 'ARCHIVED') current.archivedWalletCount += 1;
    current.totalBalanceMinor += Number(wallet.balanceMinor || 0);
    if (compareIsoDesc(current.lastActivityAt, wallet.lastActivityAt) > 0) {
      current.lastActivityAt = wallet.lastActivityAt;
    }
    policies.set(policyId, current);
    if (policyId === 'unassigned') {
      unassigned.push({
        wallet,
        policy: {
          policyId: effectivePolicy.policyId || null,
          policyName: effectivePolicy.policyName || null,
          policyKind: effectivePolicy.policyKind || null,
        },
      });
    }
  }

  const policyRows = Array.from(policies.values()).sort((a, b) => {
    if (b.walletCount !== a.walletCount) return b.walletCount - a.walletCount;
    return a.policyId.localeCompare(b.policyId);
  });

  const unassignedWalletSample = [...unassigned]
    .sort((a, b) => compareIsoDesc(a.wallet.updatedAt, b.wallet.updatedAt))
    .slice(0, 20)
    .map((entry) => toWalletSample(entry.wallet, entry.policy));

  return {
    scope: toScopeResponse(input.scope),
    totals: {
      walletCount: collected.wallets.length,
      policyCount: policyRows.length,
      unassignedWalletCount: unassigned.length,
      activeWalletCount,
      archivedWalletCount,
    },
    policies: policyRows,
    unassignedWalletSample,
    truncated: collected.truncated,
  };
}

export async function buildConsoleGasReadinessView(input: {
  wallets: ConsoleWalletService;
  walletCtx: ConsoleWalletsContext;
  scope: ConsoleInsightsScope;
  recentWindowDays?: number;
  resolveWalletPolicies?: (
    wallets: ConsoleWallet[],
  ) => Promise<Record<string, ResolvedWalletPolicyPresentation>>;
}): Promise<ConsoleGasReadinessView> {
  const recentWindowDays = Math.max(1, Math.floor(Number(input.recentWindowDays || 7)));
  const recentCutoffMs = Date.now() - recentWindowDays * 24 * 60 * 60 * 1000;
  const collected = await listAllWalletsForScope(input);
  const resolvedWalletPolicies = input.resolveWalletPolicies
    ? await input.resolveWalletPolicies(collected.wallets)
    : {};

  let recentActiveWalletCount = 0;
  const chains = new Map<string, ConsoleGasReadinessChain>();
  const recentWallets: ConsoleWallet[] = [];
  let totalBalanceMinor = 0;

  for (const wallet of collected.wallets) {
    const chain = String(wallet.chain || '').trim() || 'unknown';
    const status = String(wallet.status || '').toUpperCase();
    const activityMs = toMs(wallet.lastActivityAt);
    const isRecent = activityMs >= recentCutoffMs;
    const isActive = status === 'ACTIVE';
    const balanceMinor = Number(wallet.balanceMinor || 0);

    if (isRecent) recentWallets.push(wallet);
    if (isRecent && isActive) recentActiveWalletCount += 1;
    totalBalanceMinor += balanceMinor;

    const current = chains.get(chain) || {
      chain,
      walletCount: 0,
      activeWalletCount: 0,
      recentActivityCount: 0,
      totalBalanceMinor: 0,
      avgBalanceMinor: 0,
    };
    current.walletCount += 1;
    if (isActive) current.activeWalletCount += 1;
    if (isRecent) current.recentActivityCount += 1;
    current.totalBalanceMinor += balanceMinor;
    current.avgBalanceMinor =
      current.walletCount > 0 ? Math.floor(current.totalBalanceMinor / current.walletCount) : 0;
    chains.set(chain, current);
  }

  const chainRows = Array.from(chains.values()).sort((a, b) => {
    if (b.walletCount !== a.walletCount) return b.walletCount - a.walletCount;
    return a.chain.localeCompare(b.chain);
  });

  const recentWalletSample = recentWallets
    .sort((a, b) => compareIsoDesc(a.lastActivityAt, b.lastActivityAt))
    .slice(0, 20)
    .map((wallet) =>
      toGasWalletSample(
        wallet,
        resolvedWalletPolicies[wallet.id] === undefined ? undefined : resolvedWalletPolicies[wallet.id],
      ),
    );

  return {
    scope: toScopeResponse(input.scope),
    totals: {
      walletCount: collected.wallets.length,
      chainCount: chainRows.length,
      recentActiveWalletCount,
      totalBalanceMinor,
      recentWindowDays,
    },
    chains: chainRows,
    recentWalletSample,
    truncated: collected.truncated,
  };
}

export async function buildConsoleExportGovernanceView(input: {
  keyExports: ConsoleKeyExportService;
  keyExportCtx: ConsoleKeyExportsContext;
  environmentIdFilter?: string;
}): Promise<ConsoleExportGovernanceView> {
  const rows = await input.keyExports.listKeyExports(input.keyExportCtx);
  const normalizedRequests = [...rows]
    .sort((a, b) => compareIsoDesc(a.updatedAt, b.updatedAt))
    .map((entry) => toExportGovernanceRequest(entry));
  const normalizedSelected = normalizedRequests.filter((entry) =>
    input.environmentIdFilter ? entry.environmentId === input.environmentIdFilter : true,
  );

  return {
    scope: { environmentId: input.environmentIdFilter || null },
    totals: {
      requestCount: normalizedRequests.length,
      pendingApprovalCount: normalizedRequests.filter((entry) => entry.status === 'PENDING_APPROVAL')
        .length,
      approvedRequestCount: normalizedRequests.filter((entry) => entry.status === 'APPROVED').length,
      executedRequestCount: normalizedRequests.filter((entry) => entry.status === 'EXECUTED').length,
      rejectedRequestCount: normalizedRequests.filter((entry) => entry.status === 'REJECTED').length,
      canceledRequestCount: normalizedRequests.filter((entry) => entry.status === 'CANCELED').length,
      selectedEnvironmentRequestCount: normalizedSelected.length,
      selectedEnvironmentPendingApprovalCount: normalizedSelected.filter(
        (entry) => entry.status === 'PENDING_APPROVAL',
      ).length,
    },
    requests: normalizedRequests,
    selectedEnvironmentRequests: normalizedSelected,
  };
}
