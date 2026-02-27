import type { ConsoleApiKeyService, ConsoleApiKeysContext } from '../console/apiKeys';
import type { ConsoleWallet, ConsoleWalletService, ConsoleWalletsContext } from '../console/wallets';

export interface ConsoleInsightsScope {
  projectId?: string;
  environmentId?: string;
}

export interface ConsolePolicyCoveragePolicy {
  policyId: string;
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

export interface ConsoleExportGovernanceKey {
  id: string;
  name: string;
  environmentId: string;
  status: string;
  scopes: string[];
  lastUsedAt: string | null;
  anomalyFlags: string[];
  secretVersion: number;
  createdAt: string;
  updatedAt: string;
}

export interface ConsoleExportGovernanceView {
  scope: { environmentId: string | null };
  totals: {
    apiKeyCount: number;
    exportScopedKeyCount: number;
    activeExportScopedKeyCount: number;
    selectedEnvironmentExportScopedKeyCount: number;
  };
  exportScopedKeys: ConsoleExportGovernanceKey[];
  selectedEnvironmentKeys: ConsoleExportGovernanceKey[];
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

function toWalletSample(
  wallet: ConsoleWallet,
  policyIdOverride?: string | null,
): ConsolePolicyCoverageWalletSample {
  return {
    id: wallet.id,
    address: wallet.address,
    chain: wallet.chain,
    status: wallet.status,
    balanceMinor: wallet.balanceMinor,
    policyId: policyIdOverride === undefined ? wallet.policyId : policyIdOverride,
    userId: wallet.userId,
    lastActivityAt: wallet.lastActivityAt,
    updatedAt: wallet.updatedAt,
  };
}

function toGasWalletSample(wallet: ConsoleWallet): ConsoleGasReadinessWalletSample {
  return {
    id: wallet.id,
    chain: wallet.chain,
    status: wallet.status,
    balanceMinor: wallet.balanceMinor,
    policyId: wallet.policyId,
    userId: wallet.userId,
    lastActivityAt: wallet.lastActivityAt,
    updatedAt: wallet.updatedAt,
  };
}

function hasExportScope(scopes: string[]): boolean {
  return scopes.some((scope) => String(scope || '').toLowerCase().includes('export'));
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
  resolvePolicyIds?: (wallets: ConsoleWallet[]) => Promise<Record<string, string | null>>;
}): Promise<ConsolePolicyCoverageView> {
  const collected = await listAllWalletsForScope(input);
  const resolvedPolicyIds = input.resolvePolicyIds
    ? await input.resolvePolicyIds(collected.wallets)
    : {};
  const policies = new Map<string, ConsolePolicyCoveragePolicy>();
  let activeWalletCount = 0;
  let archivedWalletCount = 0;
  const unassigned: Array<{ wallet: ConsoleWallet; policyId: string | null }> = [];

  for (const wallet of collected.wallets) {
    const status = String(wallet.status || '').toUpperCase();
    if (status === 'ACTIVE') activeWalletCount += 1;
    if (status === 'ARCHIVED') archivedWalletCount += 1;

    const effectivePolicyIdRaw =
      resolvedPolicyIds[wallet.id] === undefined
        ? wallet.policyId
        : resolvedPolicyIds[wallet.id];
    const effectivePolicyId = String(effectivePolicyIdRaw || '').trim();
    const policyId = effectivePolicyId || 'unassigned';
    const current = policies.get(policyId) || {
      policyId,
      walletCount: 0,
      activeWalletCount: 0,
      archivedWalletCount: 0,
      totalBalanceMinor: 0,
      lastActivityAt: null,
    };
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
        policyId: effectivePolicyIdRaw || null,
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
    .map((entry) => toWalletSample(entry.wallet, entry.policyId));

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
}): Promise<ConsoleGasReadinessView> {
  const recentWindowDays = Math.max(1, Math.floor(Number(input.recentWindowDays || 7)));
  const recentCutoffMs = Date.now() - recentWindowDays * 24 * 60 * 60 * 1000;
  const collected = await listAllWalletsForScope(input);

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
    .map((wallet) => toGasWalletSample(wallet));

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
  apiKeys: ConsoleApiKeyService;
  apiKeyCtx: ConsoleApiKeysContext;
  environmentIdFilter?: string;
}): Promise<ConsoleExportGovernanceView> {
  const rows = await input.apiKeys.listApiKeys(input.apiKeyCtx);
  const exportScopedKeys = rows.filter((entry) => hasExportScope(entry.scopes));
  const selectedEnvironmentKeys = input.environmentIdFilter
    ? exportScopedKeys.filter((entry) => entry.environmentId === input.environmentIdFilter)
    : exportScopedKeys;

  const normalizedExportKeys = [...exportScopedKeys]
    .sort((a, b) => compareIsoDesc(a.updatedAt, b.updatedAt))
    .map((entry) => ({
      id: entry.id,
      name: entry.name,
      environmentId: entry.environmentId,
      status: entry.status,
      scopes: [...entry.scopes],
      lastUsedAt: entry.lastUsedAt,
      anomalyFlags: [...entry.anomalyFlags],
      secretVersion: entry.secretVersion,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
    }));

  const normalizedSelected = normalizedExportKeys.filter((entry) =>
    input.environmentIdFilter ? entry.environmentId === input.environmentIdFilter : true,
  );

  return {
    scope: { environmentId: input.environmentIdFilter || null },
    totals: {
      apiKeyCount: rows.length,
      exportScopedKeyCount: normalizedExportKeys.length,
      activeExportScopedKeyCount: normalizedExportKeys.filter(
        (entry) => String(entry.status || '').toUpperCase() === 'ACTIVE',
      ).length,
      selectedEnvironmentExportScopedKeyCount: normalizedSelected.length,
    },
    exportScopedKeys: normalizedExportKeys,
    selectedEnvironmentKeys: normalizedSelected,
  };
}
