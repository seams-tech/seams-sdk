import {
  buildConsoleAcceptHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export interface DashboardConsoleWallet {
  id: string;
  address: string;
  chain: string;
  userId: string;
  policyId: string | null;
  balanceMinor: number;
  status: string;
  updatedAt: string;
  lastActivityAt: string | null;
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

function decodeWallet(raw: unknown): DashboardConsoleWallet | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const address = String(row.address || '').trim();
  if (!id || !address) return null;
  return {
    id,
    address,
    chain: String(row.chain || '').trim(),
    userId: String(row.userId || '').trim(),
    policyId: row.policyId == null ? null : String(row.policyId || '').trim(),
    balanceMinor: Number(row.balanceMinor || 0),
    status: String(row.status || '').trim(),
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

  const response = await fetch(`${base}${pathWithQuery}`, {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
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

  const response = await fetch(`${base}/console/wallets/${encodeURIComponent(trimmedId)}`, {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleWalletResponse | null;
  if (response.status === 404) return null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Console wallet request failed'));
  }
  return decodeWallet(body.wallet);
}

export async function listDashboardWallets(
  input: { limit?: number; cursor?: string; projectId?: string; environmentId?: string } = {},
): Promise<DashboardConsoleWalletPage> {
  const params = new URLSearchParams();
  params.set('limit', String(input.limit || 25));
  if (input.cursor) params.set('cursor', input.cursor);
  if (input.projectId) params.set('projectId', input.projectId);
  if (input.environmentId) params.set('environmentId', input.environmentId);
  return fetchWalletPage(`/console/wallets?${params.toString()}`);
}

export async function searchDashboardWallets(
  input: { q: string; limit?: number; cursor?: string; projectId?: string; environmentId?: string },
): Promise<DashboardConsoleWalletPage> {
  const q = String(input.q || '').trim();
  if (!q) throw new Error('Search query cannot be empty');
  const params = new URLSearchParams();
  params.set('q', q);
  params.set('limit', String(input.limit || 25));
  if (input.cursor) params.set('cursor', input.cursor);
  if (input.projectId) params.set('projectId', input.projectId);
  if (input.environmentId) params.set('environmentId', input.environmentId);
  return fetchWalletPage(`/console/wallets/search?${params.toString()}`);
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
