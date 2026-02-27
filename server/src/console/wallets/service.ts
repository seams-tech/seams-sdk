import { ConsoleWalletError } from './errors';
import {
  makeDeterministicWalletAddress as makeDeterministicAddress,
  normalizeWalletLimit as normalizeLimit,
  normalizeWalletSortBy as normalizeSortBy,
  normalizeWalletSortOrder as normalizeSortOrder,
  slugifyWalletToken as slugify,
} from './normalization';
import type {
  ConsoleWallet,
  ConsoleWalletPage,
  ConsoleWalletSortBy,
  ConsoleWalletSortOrder,
  ListConsoleWalletsRequest,
  SearchConsoleWalletsRequest,
} from './types';

export interface ConsoleWalletsContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
  environmentId?: string;
}

export interface ConsoleWalletService {
  listWallets(
    ctx: ConsoleWalletsContext,
    request?: ListConsoleWalletsRequest,
  ): Promise<ConsoleWalletPage>;
  searchWallets(
    ctx: ConsoleWalletsContext,
    request: SearchConsoleWalletsRequest,
  ): Promise<ConsoleWalletPage>;
  getWallet(
    ctx: ConsoleWalletsContext,
    walletId: string,
  ): Promise<ConsoleWallet | null>;
}

export interface InMemoryConsoleWalletServiceOptions {
  now?: () => Date;
}

interface OrgWalletStore {
  wallets: Map<string, ConsoleWallet>;
}

interface WalletCursorPayload {
  sortBy: ConsoleWalletSortBy;
  sortOrder: ConsoleWalletSortOrder;
  sortValue: number;
  id: string;
}

function toIso(date: Date): string {
  return date.toISOString();
}

function toMs(iso: string | null | undefined): number {
  if (!iso) return 0;
  const parsed = Date.parse(iso);
  return Number.isFinite(parsed) ? parsed : 0;
}

function makeBootstrapWallet(ctx: ConsoleWalletsContext, now: Date): ConsoleWallet {
  const projectId = String(ctx.projectId || `${ctx.orgId}:default-project`).trim();
  const environmentId = String(ctx.environmentId || `${projectId}:prod`).trim();
  const seed = `${ctx.orgId}:${projectId}:${environmentId}`;
  const id = `wallet_${slugify(seed).replace(/-/g, '_').slice(0, 40)}`;
  const createdAt = toIso(now);
  return {
    id,
    orgId: ctx.orgId,
    projectId,
    environmentId,
    userId: `user_${slugify(ctx.orgId).replace(/-/g, '_').slice(0, 12)}`,
    externalRefId: `ext_${slugify(seed).replace(/-/g, '_').slice(0, 18)}`,
    address: makeDeterministicAddress(seed),
    chain: 'Ethereum',
    walletType: 'EOA',
    status: 'ACTIVE',
    policyId: 'policy_default',
    balanceMinor: 0,
    lastActivityAt: null,
    createdAt,
    updatedAt: createdAt,
  };
}

function encodeCursor(payload: WalletCursorPayload): string {
  const json = JSON.stringify(payload);
  if (typeof btoa === 'function') {
    return btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }
  const bufferCtor = (globalThis as any).Buffer;
  if (bufferCtor) {
    return bufferCtor.from(json, 'utf8').toString('base64url');
  }
  throw new ConsoleWalletError('internal', 500, 'No base64 encoder available');
}

function decodeCursor(input: string): WalletCursorPayload {
  const value = String(input || '').trim();
  if (!value) {
    throw new ConsoleWalletError('invalid_query', 400, 'Invalid cursor value');
  }

  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);

  let json = '';
  try {
    if (typeof atob === 'function') {
      json = atob(padded);
    } else {
      const bufferCtor = (globalThis as any).Buffer;
      if (!bufferCtor) throw new Error('no_decoder');
      json = bufferCtor.from(value, 'base64url').toString('utf8');
    }
  } catch {
    throw new ConsoleWalletError('invalid_query', 400, 'Invalid cursor value');
  }

  try {
    const parsed = JSON.parse(json);
    const sortBy = String(parsed?.sortBy || '') as ConsoleWalletSortBy;
    const sortOrder = String(parsed?.sortOrder || '') as ConsoleWalletSortOrder;
    const sortValue = Number(parsed?.sortValue);
    const id = String(parsed?.id || '').trim();
    if (
      (sortBy !== 'createdAt' && sortBy !== 'balance' && sortBy !== 'lastActivity') ||
      (sortOrder !== 'asc' && sortOrder !== 'desc') ||
      !Number.isFinite(sortValue) ||
      !id
    ) {
      throw new Error('invalid_payload');
    }
    return { sortBy, sortOrder, sortValue, id };
  } catch {
    throw new ConsoleWalletError('invalid_query', 400, 'Invalid cursor value');
  }
}

function sortValueFor(wallet: ConsoleWallet, sortBy: ConsoleWalletSortBy): number {
  if (sortBy === 'balance') return wallet.balanceMinor;
  if (sortBy === 'lastActivity') return toMs(wallet.lastActivityAt);
  return toMs(wallet.createdAt);
}

function compareWallets(
  a: ConsoleWallet,
  b: ConsoleWallet,
  sortBy: ConsoleWalletSortBy,
  sortOrder: ConsoleWalletSortOrder,
): number {
  const av = sortValueFor(a, sortBy);
  const bv = sortValueFor(b, sortBy);
  if (av !== bv) {
    return sortOrder === 'asc' ? av - bv : bv - av;
  }
  const idCompare = a.id.localeCompare(b.id);
  return sortOrder === 'asc' ? idCompare : -idCompare;
}

function matchesFilters(wallet: ConsoleWallet, request: ListConsoleWalletsRequest): boolean {
  if (request.projectId && wallet.projectId !== request.projectId) return false;
  if (request.environmentId && wallet.environmentId !== request.environmentId) return false;
  if (request.chain && wallet.chain !== request.chain) return false;
  if (request.walletType && wallet.walletType !== request.walletType) return false;
  if (request.status && wallet.status !== request.status) return false;
  if (request.policyId && String(wallet.policyId || '') !== request.policyId) return false;
  if (request.userId && wallet.userId !== request.userId) return false;
  if (request.externalRefId && wallet.externalRefId !== request.externalRefId) return false;
  return true;
}

function matchesSearch(wallet: ConsoleWallet, q: string): boolean {
  const needle = q.toLowerCase();
  return (
    wallet.id.toLowerCase().includes(needle) ||
    wallet.address.toLowerCase().includes(needle) ||
    wallet.userId.toLowerCase().includes(needle) ||
    wallet.externalRefId.toLowerCase().includes(needle)
  );
}

function cloneWallet(wallet: ConsoleWallet): ConsoleWallet {
  return { ...wallet };
}

function applyPage(
  wallets: ConsoleWallet[],
  request: ListConsoleWalletsRequest,
): ConsoleWalletPage {
  const sortBy = normalizeSortBy(request.sortBy);
  const sortOrder = normalizeSortOrder(request.sortOrder);
  const limit = normalizeLimit(request.limit);

  const sorted = [...wallets].sort((a, b) => compareWallets(a, b, sortBy, sortOrder));
  const cursor = request.cursor ? decodeCursor(request.cursor) : null;
  const cursorAware = cursor
    ? sorted.filter((wallet) => {
      if (cursor.sortBy !== sortBy || cursor.sortOrder !== sortOrder) {
        throw new ConsoleWalletError(
          'invalid_query',
          400,
          'Cursor does not match requested sortBy/sortOrder',
        );
      }
      const walletSortValue = sortValueFor(wallet, sortBy);
      if (sortOrder === 'asc') {
        if (walletSortValue > cursor.sortValue) return true;
        if (walletSortValue < cursor.sortValue) return false;
        return wallet.id.localeCompare(cursor.id) > 0;
      }
      if (walletSortValue < cursor.sortValue) return true;
      if (walletSortValue > cursor.sortValue) return false;
      return wallet.id.localeCompare(cursor.id) < 0;
    })
    : sorted;

  const rows = cursorAware.slice(0, limit + 1);
  const hasMore = rows.length > limit;
  const items = rows.slice(0, limit).map(cloneWallet);
  const last = items[items.length - 1];
  const nextCursor = hasMore && last
    ? encodeCursor({
      sortBy,
      sortOrder,
      sortValue: sortValueFor(last, sortBy),
      id: last.id,
    })
    : undefined;
  return { items, ...(nextCursor ? { nextCursor } : {}) };
}

export function createInMemoryConsoleWalletService(
  opts: InMemoryConsoleWalletServiceOptions = {},
): ConsoleWalletService {
  const now = opts.now || (() => new Date());
  const stores = new Map<string, OrgWalletStore>();

  function ensureOrgStore(ctx: ConsoleWalletsContext): OrgWalletStore {
    let store = stores.get(ctx.orgId);
    if (!store) {
      store = { wallets: new Map<string, ConsoleWallet>() };
      stores.set(ctx.orgId, store);
    }
    const bootstrap = makeBootstrapWallet(ctx, now());
    if (!store.wallets.has(bootstrap.id)) {
      store.wallets.set(bootstrap.id, bootstrap);
    }
    return store;
  }

  return {
    async listWallets(
      ctx: ConsoleWalletsContext,
      request: ListConsoleWalletsRequest = {},
    ): Promise<ConsoleWalletPage> {
      const store = ensureOrgStore(ctx);
      const filtered = Array.from(store.wallets.values()).filter((wallet) =>
        matchesFilters(wallet, request),
      );
      return applyPage(filtered, request);
    },

    async searchWallets(
      ctx: ConsoleWalletsContext,
      request: SearchConsoleWalletsRequest,
    ): Promise<ConsoleWalletPage> {
      const store = ensureOrgStore(ctx);
      const filtered = Array.from(store.wallets.values()).filter(
        (wallet) => matchesFilters(wallet, request) && matchesSearch(wallet, request.q),
      );
      return applyPage(filtered, request);
    },

    async getWallet(
      ctx: ConsoleWalletsContext,
      walletId: string,
    ): Promise<ConsoleWallet | null> {
      const store = ensureOrgStore(ctx);
      const wallet = store.wallets.get(walletId);
      return wallet ? cloneWallet(wallet) : null;
    },
  };
}
