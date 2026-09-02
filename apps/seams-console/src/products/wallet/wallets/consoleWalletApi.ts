import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  fetchConsoleEndpoint,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '@core/dashboard/consoleHttp';

export interface DashboardConsoleWallet {
  id: string;
  address: string;
  chain: DashboardConsoleWalletChain;
  walletType: DashboardConsoleWalletType;
  userId: string;
  policyId: string | null;
  balanceMinor: number;
  funded: boolean;
  gasBalances: DashboardWalletGasBalances | null;
  status: string;
  createdAt: string;
  updatedAt: string;
  lastActivityAt: string | null;
}

export interface DashboardWalletGasBalances {
  observedAt: string;
  near: {
    accountId: string;
    balanceYocto: string;
  };
  tempo: {
    address: string;
    alphaUsdRaw: string;
  };
  arc: {
    address: string;
    usdcRaw: string;
  };
}

export type DashboardConsoleWalletChain =
  | 'Multichain'
  | 'Ethereum'
  | 'Base'
  | 'Tempo'
  | 'Arc Circle'
  | 'NEAR';
export type DashboardConsoleWalletType = 'EOA' | 'SMART';
export type DashboardConsoleWalletSortBy = 'createdAt' | 'balance' | 'lastActivity';
export type DashboardConsoleWalletSortOrder = 'asc' | 'desc';

export interface DashboardConsoleWalletListInput {
  limit?: number;
  cursor?: string;
  projectId?: string;
  environmentId?: string;
  chain?: DashboardConsoleWalletChain;
  walletType?: DashboardConsoleWalletType;
  policyId?: string;
  sortBy?: DashboardConsoleWalletSortBy;
  sortOrder?: DashboardConsoleWalletSortOrder;
}

export interface DashboardConsoleWalletPage {
  wallets: DashboardConsoleWallet[];
  nextCursor?: string;
}

interface ConsoleWalletPageResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  wallets?: unknown;
  nextCursor?: unknown;
}

interface ConsoleWalletResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  wallet?: unknown;
}

function asRecord(raw: unknown): Record<string, unknown> | null {
  return raw && typeof raw === 'object' && !Array.isArray(raw)
    ? (raw as Record<string, unknown>)
    : null;
}

function decodeGasBalances(raw: unknown): DashboardWalletGasBalances | null {
  const balances = asRecord(raw);
  const near = asRecord(balances?.near);
  const tempo = asRecord(balances?.tempo);
  const arc = asRecord(balances?.arc);
  const observedAt = String(balances?.observedAt ?? '').trim();
  const nearAccountId = String(near?.accountId ?? '').trim();
  const nearBalanceYocto = String(near?.balanceYocto ?? '').trim();
  const evmAddress = String(tempo?.address ?? '').trim();
  const arcAddress = String(arc?.address ?? '').trim();
  const alphaUsdRaw = String(tempo?.alphaUsdRaw ?? '').trim();
  const usdcRaw = String(arc?.usdcRaw ?? '').trim();
  if (
    !observedAt ||
    !nearAccountId ||
    !nearBalanceYocto ||
    !evmAddress ||
    !arcAddress ||
    !alphaUsdRaw ||
    !usdcRaw
  ) {
    return null;
  }
  return {
    observedAt,
    near: { accountId: nearAccountId, balanceYocto: nearBalanceYocto },
    tempo: { address: evmAddress, alphaUsdRaw },
    arc: { address: arcAddress, usdcRaw },
  };
}

function decodeWalletChain(raw: unknown): DashboardConsoleWalletChain | null {
  const value = String(raw ?? '').trim();
  switch (value) {
    case 'Multichain':
    case 'Ethereum':
    case 'Base':
    case 'Tempo':
    case 'Arc Circle':
    case 'NEAR':
      return value;
    default:
      return null;
  }
}

function decodeWalletType(raw: unknown): DashboardConsoleWalletType | null {
  const value = String(raw ?? '').trim();
  switch (value) {
    case 'EOA':
    case 'SMART':
      return value;
    default:
      return null;
  }
}

function decodeWallet(raw: unknown): DashboardConsoleWallet | null {
  const row = asRecord(raw);
  if (!row) return null;
  const id = String(row.id || '').trim();
  const address = String(row.address || '').trim();
  const chain = decodeWalletChain(row.chain);
  const walletType = decodeWalletType(row.walletType);
  if (!id || !address || !chain || !walletType) return null;
  const balanceMinor = Number(row.balanceMinor || 0);
  return {
    id,
    address,
    chain,
    walletType,
    userId: String(row.userId || '').trim(),
    policyId: row.policyId == null ? null : String(row.policyId || '').trim(),
    balanceMinor,
    funded: row.funded === true || balanceMinor > 0,
    gasBalances: decodeGasBalances(row.gasBalances),
    status: String(row.status || '').trim(),
    createdAt: String(row.createdAt || '').trim(),
    updatedAt: String(row.updatedAt || '').trim(),
    lastActivityAt: row.lastActivityAt == null ? null : String(row.lastActivityAt || '').trim(),
  };
}

function decodeWalletPage(body: ConsoleWalletPageResponse | null): DashboardConsoleWalletPage {
  const items = Array.isArray(body?.wallets) ? body.wallets : [];
  const wallets = items
    .map((entry) => decodeWallet(entry))
    .filter((entry): entry is DashboardConsoleWallet => entry !== null);
  const nextCursorRaw = typeof body?.nextCursor === 'string' ? body.nextCursor.trim() : '';
  return {
    wallets,
    ...(nextCursorRaw ? { nextCursor: nextCursorRaw } : {}),
  };
}

async function fetchWalletPage(pathWithQuery: string): Promise<DashboardConsoleWalletPage> {
  const base = requireConsoleBaseUrl();

  const response = await fetchConsoleEndpoint(
    `${base}${pathWithQuery}`,
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
    {
      baseUrl: base,
      path: pathWithQuery,
      operation: 'Console wallet request',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsoleWalletPageResponse | null;

  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Console wallet request failed'));
  }

  return decodeWalletPage(body);
}

export async function getDashboardWallet(walletId: string): Promise<DashboardConsoleWallet | null> {
  const trimmedId = String(walletId || '').trim();
  if (!trimmedId) throw new Error('Wallet id is required');

  const base = requireConsoleBaseUrl();

  const walletPath = `/console/wallets/${encodeURIComponent(trimmedId)}`;
  const response = await fetchConsoleEndpoint(
    `${base}${walletPath}`,
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
    {
      baseUrl: base,
      path: walletPath,
      operation: 'Console wallet request',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsoleWalletResponse | null;
  if (response.status === 404) return null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Console wallet request failed'));
  }
  return decodeWallet(body.wallet);
}

export async function listDashboardWallets(
  input: DashboardConsoleWalletListInput = {},
): Promise<DashboardConsoleWalletPage> {
  const params = new URLSearchParams();
  params.set('limit', String(input.limit || 25));
  if (input.cursor) params.set('cursor', input.cursor);
  if (input.projectId) params.set('projectId', input.projectId);
  if (input.environmentId) params.set('environmentId', input.environmentId);
  if (input.chain) params.set('chain', input.chain);
  if (input.walletType) params.set('walletType', input.walletType);
  if (input.policyId) params.set('policyId', input.policyId);
  if (input.sortBy) params.set('sortBy', input.sortBy);
  if (input.sortOrder) params.set('sortOrder', input.sortOrder);
  return fetchWalletPage(`/console/wallets?${params.toString()}`);
}

export async function searchDashboardWallets(
  input: DashboardConsoleWalletListInput & { q: string },
): Promise<DashboardConsoleWalletPage> {
  const q = String(input.q || '').trim();
  if (!q) throw new Error('Search query cannot be empty');
  const params = new URLSearchParams();
  params.set('q', q);
  params.set('limit', String(input.limit || 25));
  if (input.cursor) params.set('cursor', input.cursor);
  if (input.projectId) params.set('projectId', input.projectId);
  if (input.environmentId) params.set('environmentId', input.environmentId);
  if (input.chain) params.set('chain', input.chain);
  if (input.walletType) params.set('walletType', input.walletType);
  if (input.policyId) params.set('policyId', input.policyId);
  if (input.sortBy) params.set('sortBy', input.sortBy);
  if (input.sortOrder) params.set('sortOrder', input.sortOrder);
  return fetchWalletPage(`/console/wallets/search?${params.toString()}`);
}

export async function refreshDashboardWalletBalances(
  walletIds: readonly string[],
): Promise<DashboardConsoleWallet[]> {
  const normalizedWalletIds = [
    ...new Set(walletIds.map((walletId) => walletId.trim()).filter(Boolean)),
  ];
  if (normalizedWalletIds.length === 0) return [];
  const base = requireConsoleBaseUrl();
  const path = '/console/wallets/balances/refresh';
  const response = await fetchConsoleEndpoint(
    `${base}${path}`,
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify({ walletIds: normalizedWalletIds.slice(0, 10) }),
    },
    {
      baseUrl: base,
      path,
      operation: 'Console wallet balance refresh',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsoleWalletPageResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Console wallet balance refresh failed'));
  }
  return decodeWalletPage(body).wallets;
}

export function formatWalletBalanceMinor(balanceMinor: number): string {
  const asNumber = Number(balanceMinor || 0);
  return `$${(asNumber / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

export function mergeDashboardWalletsById(
  current: DashboardConsoleWallet[],
  incoming: DashboardConsoleWallet[],
): DashboardConsoleWallet[] {
  const seen = new Set(current.map((wallet) => wallet.id));
  const merged = [...current];
  for (const wallet of incoming) {
    if (seen.has(wallet.id)) continue;
    merged.push(wallet);
    seen.add(wallet.id);
  }
  return merged;
}

export function replaceDashboardWalletsById(
  current: DashboardConsoleWallet[],
  incoming: DashboardConsoleWallet[],
): DashboardConsoleWallet[] {
  const replacements = new Map(incoming.map((wallet) => [wallet.id, wallet]));
  return current.map((wallet) => replacements.get(wallet.id) || wallet);
}
