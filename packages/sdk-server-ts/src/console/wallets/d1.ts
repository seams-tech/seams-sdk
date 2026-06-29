import { d1Integer as toNumber, formatD1ExecStatement, type D1Row } from '../../storage/d1Sql';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import { ConsoleWalletError } from './errors';
import {
  normalizeWalletLimit as normalizeLimit,
  normalizeWalletSortBy as normalizeSortBy,
  normalizeWalletSortOrder as normalizeSortOrder,
} from './normalization';
import type {
  ConsoleWalletService,
  ConsoleWalletsContext,
  UpsertConsoleWalletRequest,
} from './service';
import type {
  ConsoleWallet,
  ConsoleWalletChain,
  ConsoleWalletPage,
  ConsoleWalletSortBy,
  ConsoleWalletSortOrder,
  ConsoleWalletStatus,
  ConsoleWalletType,
  ListConsoleWalletsRequest,
  SearchConsoleWalletsRequest,
} from './types';


interface D1ConsoleWalletState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

interface WalletCursorPayload {
  readonly sortBy: ConsoleWalletSortBy;
  readonly sortOrder: ConsoleWalletSortOrder;
  readonly sortValue: number;
  readonly id: string;
}

interface WalletQueryParts {
  readonly whereSql: string;
  readonly values: readonly unknown[];
  readonly orderBySql: string;
  readonly limit: number;
  readonly sortBy: ConsoleWalletSortBy;
  readonly sortOrder: ConsoleWalletSortOrder;
}

interface WalletFilterAccumulator {
  readonly clauses: string[];
  readonly values: unknown[];
}

interface NormalizedWalletUpsert {
  readonly id: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly userId: string;
  readonly externalRefId: string;
  readonly address: string;
  readonly chain: ConsoleWalletChain;
  readonly walletType: ConsoleWalletType;
  readonly status: ConsoleWalletStatus;
  readonly policyId: string | null;
  readonly balanceMinor: number;
  readonly lastActivityAtMs: number | null;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}

export const CONSOLE_WALLETS_D1_RUNTIME = Symbol('consoleWalletsD1Runtime');

export interface ConsoleWalletsD1Runtime {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

export type ConsoleWalletsD1Service = ConsoleWalletService & {
  readonly [CONSOLE_WALLETS_D1_RUNTIME]: ConsoleWalletsD1Runtime;
};

export interface D1ConsoleWalletSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1ConsoleWalletServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

export const CONSOLE_WALLETS_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS wallet_index (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      environment_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      external_ref_id TEXT NOT NULL,
      address TEXT NOT NULL,
      chain TEXT NOT NULL,
      wallet_type TEXT NOT NULL,
      status TEXT NOT NULL,
      policy_id TEXT,
      balance_minor INTEGER NOT NULL,
      last_activity_at_ms INTEGER,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      UNIQUE (namespace, org_id, address),
      CHECK (chain IN ('Ethereum', 'Base', 'Tempo', 'Arc Circle', 'NEAR')),
      CHECK (wallet_type IN ('EOA', 'SMART')),
      CHECK (status IN ('ACTIVE', 'FROZEN', 'ARCHIVED'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS wallet_index_org_created_idx
      ON wallet_index (namespace, org_id, created_at_ms DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS wallet_index_org_project_env_idx
      ON wallet_index (namespace, org_id, project_id, environment_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS wallet_index_org_status_type_chain_idx
      ON wallet_index (namespace, org_id, status, wallet_type, chain)
  `,
  `
    CREATE INDEX IF NOT EXISTS wallet_index_org_balance_idx
      ON wallet_index (namespace, org_id, balance_minor DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS wallet_index_org_last_activity_idx
      ON wallet_index (namespace, org_id, COALESCE(last_activity_at_ms, 0) DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS wallet_index_org_user_idx
      ON wallet_index (namespace, org_id, user_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS wallet_index_org_external_ref_idx
      ON wallet_index (namespace, org_id, external_ref_id)
  `,
] as const);

export async function ensureConsoleWalletsD1Schema(
  options: D1ConsoleWalletSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_WALLETS_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleWalletsD1Runtime(
  service: ConsoleWalletService | null | undefined,
): ConsoleWalletsD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (service as Partial<ConsoleWalletsD1Service>)[CONSOLE_WALLETS_D1_RUNTIME] || null;
}

export async function createD1ConsoleWalletService(
  options: D1ConsoleWalletServiceOptions,
): Promise<ConsoleWalletsD1Service> {
  const state: D1ConsoleWalletState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
  };
  if (options.ensureSchema !== false) {
    await ensureConsoleWalletsD1Schema({ database: state.database });
  }
  return new D1ConsoleWalletServiceImpl(state) as ConsoleWalletsD1Service;
}

function defaultNow(): Date {
  return new Date();
}

function ensureNamespace(namespace: string | undefined): string {
  const normalized = String(namespace || 'default').trim();
  return normalized || 'default';
}

function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function toNullableString(raw: unknown): string | null {
  const value = normalizeString(raw);
  return value || null;
}


function toIso(ms: number): string {
  return new Date(ms).toISOString();
}

function toNullableIso(raw: unknown): string | null {
  if (raw === null || raw === undefined || raw === '') return null;
  const parsed = toNumber(raw, NaN);
  return Number.isFinite(parsed) ? toIso(parsed) : null;
}

function toMsFromIso(value: string | null | undefined, fallbackMs: number): number {
  if (!value) return fallbackMs;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : fallbackMs;
}

function parseWalletChain(raw: unknown): ConsoleWalletChain {
  const value = normalizeString(raw);
  switch (value) {
    case 'Ethereum':
    case 'Base':
    case 'Tempo':
    case 'Arc Circle':
    case 'NEAR':
      return value;
    default:
      return 'Ethereum';
  }
}

function parseWalletType(raw: unknown): ConsoleWalletType {
  const value = normalizeString(raw).toUpperCase();
  switch (value) {
    case 'SMART':
      return 'SMART';
    case 'EOA':
    default:
      return 'EOA';
  }
}

function parseWalletStatus(raw: unknown): ConsoleWalletStatus {
  const value = normalizeString(raw).toUpperCase();
  switch (value) {
    case 'FROZEN':
      return 'FROZEN';
    case 'ARCHIVED':
      return 'ARCHIVED';
    case 'ACTIVE':
    default:
      return 'ACTIVE';
  }
}

function normalizeUpsertChain(raw: unknown): ConsoleWalletChain {
  const value = normalizeString(raw);
  switch (value) {
    case 'Ethereum':
    case 'Base':
    case 'Tempo':
    case 'Arc Circle':
    case 'NEAR':
      return value;
    default:
      throw new ConsoleWalletError('invalid_body', 400, `Unsupported chain: ${value}`);
  }
}

function normalizeUpsertWalletType(raw: unknown): ConsoleWalletType {
  const value = normalizeString(raw || 'EOA').toUpperCase();
  switch (value) {
    case 'EOA':
    case 'SMART':
      return value;
    default:
      throw new ConsoleWalletError('invalid_body', 400, `Unsupported walletType: ${value}`);
  }
}

function normalizeUpsertStatus(raw: unknown): ConsoleWalletStatus {
  const value = normalizeString(raw || 'ACTIVE').toUpperCase();
  switch (value) {
    case 'ACTIVE':
    case 'FROZEN':
    case 'ARCHIVED':
      return value;
    default:
      throw new ConsoleWalletError('invalid_body', 400, `Unsupported status: ${value}`);
  }
}

function parseWalletRow(row: D1Row): ConsoleWallet {
  return {
    id: normalizeString(row.id),
    orgId: normalizeString(row.org_id),
    projectId: normalizeString(row.project_id),
    environmentId: normalizeString(row.environment_id),
    userId: normalizeString(row.user_id),
    externalRefId: normalizeString(row.external_ref_id),
    address: normalizeString(row.address),
    chain: parseWalletChain(row.chain),
    walletType: parseWalletType(row.wallet_type),
    status: parseWalletStatus(row.status),
    policyId: toNullableString(row.policy_id),
    balanceMinor: toNumber(row.balance_minor),
    lastActivityAt: toNullableIso(row.last_activity_at_ms),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
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
  const json = decodeCursorJson(value, padded);
  return parseCursorJson(json);
}

function decodeCursorJson(value: string, padded: string): string {
  try {
    if (typeof atob === 'function') return atob(padded);
    const bufferCtor = (globalThis as any).Buffer;
    if (!bufferCtor) throw new Error('no_decoder');
    return bufferCtor.from(value, 'base64url').toString('utf8');
  } catch {
    throw new ConsoleWalletError('invalid_query', 400, 'Invalid cursor value');
  }
}

function parseCursorJson(json: string): WalletCursorPayload {
  try {
    const parsed: unknown = JSON.parse(json);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('invalid_payload');
    }
    const row = parsed as Record<string, unknown>;
    const sortBy = parseCursorSortBy(row.sortBy);
    const sortOrder = parseCursorSortOrder(row.sortOrder);
    const sortValue = Number(row.sortValue);
    const id = normalizeString(row.id);
    if (!Number.isFinite(sortValue) || !id) {
      throw new Error('invalid_payload');
    }
    return {
      sortBy,
      sortOrder,
      sortValue: Math.trunc(sortValue),
      id,
    };
  } catch {
    throw new ConsoleWalletError('invalid_query', 400, 'Invalid cursor value');
  }
}

function parseCursorSortBy(raw: unknown): ConsoleWalletSortBy {
  const value = normalizeString(raw);
  switch (value) {
    case 'createdAt':
    case 'balance':
    case 'lastActivity':
      return value;
    default:
      throw new Error('invalid_payload');
  }
}

function parseCursorSortOrder(raw: unknown): ConsoleWalletSortOrder {
  const value = normalizeString(raw);
  switch (value) {
    case 'asc':
    case 'desc':
      return value;
    default:
      throw new Error('invalid_payload');
  }
}

function sortColumn(sortBy: ConsoleWalletSortBy): string {
  if (sortBy === 'balance') return 'balance_minor';
  if (sortBy === 'lastActivity') return 'COALESCE(last_activity_at_ms, 0)';
  return 'created_at_ms';
}

function directionSql(sortOrder: ConsoleWalletSortOrder): 'ASC' | 'DESC' {
  return sortOrder === 'asc' ? 'ASC' : 'DESC';
}

function walletSortValue(wallet: ConsoleWallet, sortBy: ConsoleWalletSortBy): number {
  if (sortBy === 'balance') return wallet.balanceMinor;
  if (sortBy === 'lastActivity') return wallet.lastActivityAt ? toMsFromIso(wallet.lastActivityAt, 0) : 0;
  return toMsFromIso(wallet.createdAt, 0);
}

function appendEqualsFilter(
  input: WalletFilterAccumulator,
  column: string,
  raw: unknown,
): void {
  const value = normalizeString(raw);
  if (!value) return;
  input.clauses.push(`${column} = ?`);
  input.values.push(value);
}

function appendSearchFilter(input: WalletFilterAccumulator, searchQ: string | undefined): void {
  const q = normalizeString(searchQ).toLowerCase();
  if (!q) return;
  const like = `%${q}%`;
  input.clauses.push(
    `(LOWER(id) LIKE ? OR LOWER(address) LIKE ? OR LOWER(user_id) LIKE ? OR LOWER(external_ref_id) LIKE ?)`,
  );
  input.values.push(like, like, like, like);
}

function appendCursorFilter(input: {
  readonly accumulator: WalletFilterAccumulator;
  readonly cursor: WalletCursorPayload | null;
  readonly sortBy: ConsoleWalletSortBy;
  readonly sortOrder: ConsoleWalletSortOrder;
  readonly column: string;
}): void {
  if (!input.cursor) return;
  if (input.cursor.sortBy !== input.sortBy || input.cursor.sortOrder !== input.sortOrder) {
    throw new ConsoleWalletError(
      'invalid_query',
      400,
      'Cursor does not match requested sortBy/sortOrder',
    );
  }
  const op = input.sortOrder === 'desc' ? '<' : '>';
  input.accumulator.clauses.push(
    `(${input.column} ${op} ? OR (${input.column} = ? AND id ${op} ?))`,
  );
  input.accumulator.values.push(input.cursor.sortValue, input.cursor.sortValue, input.cursor.id);
}

function buildWalletQuery(input: {
  readonly namespace: string;
  readonly orgId: string;
  readonly request: ListConsoleWalletsRequest;
  readonly searchQ?: string;
}): WalletQueryParts {
  const sortBy = normalizeSortBy(input.request.sortBy);
  const sortOrder = normalizeSortOrder(input.request.sortOrder);
  const limit = normalizeLimit(input.request.limit);
  const column = sortColumn(sortBy);
  const accumulator: WalletFilterAccumulator = {
    clauses: ['namespace = ?', 'org_id = ?'],
    values: [input.namespace, input.orgId],
  };
  appendEqualsFilter(accumulator, 'project_id', input.request.projectId);
  appendEqualsFilter(accumulator, 'environment_id', input.request.environmentId);
  appendEqualsFilter(accumulator, 'chain', input.request.chain);
  appendEqualsFilter(accumulator, 'wallet_type', input.request.walletType);
  appendEqualsFilter(accumulator, 'status', input.request.status);
  appendEqualsFilter(accumulator, 'policy_id', input.request.policyId);
  appendEqualsFilter(accumulator, 'user_id', input.request.userId);
  appendEqualsFilter(accumulator, 'external_ref_id', input.request.externalRefId);
  appendSearchFilter(accumulator, input.searchQ);
  appendCursorFilter({
    accumulator,
    cursor: input.request.cursor ? decodeCursor(input.request.cursor) : null,
    sortBy,
    sortOrder,
    column,
  });
  const direction = directionSql(sortOrder);
  return {
    whereSql: accumulator.clauses.join(' AND '),
    values: accumulator.values,
    orderBySql: `${column} ${direction}, id ${direction}`,
    limit,
    sortBy,
    sortOrder,
  };
}

function buildWalletPage(input: {
  readonly wallets: readonly ConsoleWallet[];
  readonly limit: number;
  readonly sortBy: ConsoleWalletSortBy;
  readonly sortOrder: ConsoleWalletSortOrder;
}): ConsoleWalletPage {
  const hasMore = input.wallets.length > input.limit;
  const items = (hasMore ? input.wallets.slice(0, input.limit) : [...input.wallets]).map((wallet) => ({
    ...wallet,
  }));
  const last = items[items.length - 1];
  const nextCursor =
    hasMore && last
      ? encodeCursor({
          sortBy: input.sortBy,
          sortOrder: input.sortOrder,
          sortValue: walletSortValue(last, input.sortBy),
          id: last.id,
        })
      : undefined;
  return {
    items,
    ...(nextCursor ? { nextCursor } : {}),
  };
}

function normalizeRequiredWalletField(raw: unknown, field: string): string {
  const value = normalizeString(raw);
  if (!value) {
    throw new ConsoleWalletError(
      'invalid_body',
      400,
      `Wallet upsert requires ${field}`,
    );
  }
  return value;
}

function normalizeBalanceMinor(raw: unknown): number {
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
}

function normalizeWalletUpsert(
  request: UpsertConsoleWalletRequest,
  nowMsValue: number,
): NormalizedWalletUpsert {
  const updatedAtMs = toMsFromIso(request.updatedAt, nowMsValue);
  return {
    id: normalizeRequiredWalletField(request.id, 'id'),
    projectId: normalizeRequiredWalletField(request.projectId, 'projectId'),
    environmentId: normalizeRequiredWalletField(request.environmentId, 'environmentId'),
    userId: normalizeRequiredWalletField(request.userId, 'userId'),
    externalRefId: normalizeRequiredWalletField(request.externalRefId, 'externalRefId'),
    address: normalizeRequiredWalletField(request.address, 'address'),
    chain: normalizeUpsertChain(request.chain),
    walletType: normalizeUpsertWalletType(request.walletType),
    status: normalizeUpsertStatus(request.status),
    policyId: toNullableString(request.policyId),
    balanceMinor: normalizeBalanceMinor(request.balanceMinor),
    lastActivityAtMs:
      request.lastActivityAt === null ? null : toMsFromIso(request.lastActivityAt, updatedAtMs),
    createdAtMs: toMsFromIso(request.createdAt, nowMsValue),
    updatedAtMs,
  };
}

function isD1ConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('UNIQUE constraint failed') || message.includes('constraint failed');
}

class D1ConsoleWalletServiceImpl implements ConsoleWalletService {
  readonly [CONSOLE_WALLETS_D1_RUNTIME]: ConsoleWalletsD1Runtime;

  private readonly state: D1ConsoleWalletState;

  constructor(state: D1ConsoleWalletState) {
    this.state = state;
    this[CONSOLE_WALLETS_D1_RUNTIME] = {
      database: state.database,
      namespace: state.namespace,
      now: state.now,
    };
    this.listWallets = this.listWallets.bind(this);
    this.searchWallets = this.searchWallets.bind(this);
    this.getWallet = this.getWallet.bind(this);
    this.upsertWallet = this.upsertWallet.bind(this);
  }

  async listWallets(
    ctx: ConsoleWalletsContext,
    request: ListConsoleWalletsRequest = {},
  ): Promise<ConsoleWalletPage> {
    return await this.queryWalletPage(ctx, request);
  }

  async searchWallets(
    ctx: ConsoleWalletsContext,
    request: SearchConsoleWalletsRequest,
  ): Promise<ConsoleWalletPage> {
    return await this.queryWalletPage(ctx, request, request.q);
  }

  async getWallet(
    ctx: ConsoleWalletsContext,
    walletId: string,
  ): Promise<ConsoleWallet | null> {
    const row = await this.state.database
      .prepare(
        `SELECT *
           FROM wallet_index
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?`,
      )
      .bind(this.state.namespace, ctx.orgId, walletId)
      .first<D1Row>();
    return row ? parseWalletRow(row) : null;
  }

  async upsertWallet(
    ctx: ConsoleWalletsContext,
    request: UpsertConsoleWalletRequest,
  ): Promise<ConsoleWallet> {
    const normalized = normalizeWalletUpsert(request, this.state.now().getTime());
    try {
      await this.state.database
        .prepare(
          `INSERT INTO wallet_index (
             namespace,
             org_id,
             id,
             project_id,
             environment_id,
             user_id,
             external_ref_id,
             address,
             chain,
             wallet_type,
             status,
             policy_id,
             balance_minor,
             last_activity_at_ms,
             created_at_ms,
             updated_at_ms
           )
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (namespace, org_id, id)
           DO UPDATE SET
             project_id = EXCLUDED.project_id,
             environment_id = EXCLUDED.environment_id,
             user_id = EXCLUDED.user_id,
             external_ref_id = EXCLUDED.external_ref_id,
             address = EXCLUDED.address,
             chain = EXCLUDED.chain,
             wallet_type = EXCLUDED.wallet_type,
             status = EXCLUDED.status,
             policy_id = EXCLUDED.policy_id,
             balance_minor = EXCLUDED.balance_minor,
             last_activity_at_ms = EXCLUDED.last_activity_at_ms,
             created_at_ms = MIN(wallet_index.created_at_ms, EXCLUDED.created_at_ms),
             updated_at_ms = MAX(wallet_index.updated_at_ms, EXCLUDED.updated_at_ms)`,
        )
        .bind(
          this.state.namespace,
          ctx.orgId,
          normalized.id,
          normalized.projectId,
          normalized.environmentId,
          normalized.userId,
          normalized.externalRefId,
          normalized.address,
          normalized.chain,
          normalized.walletType,
          normalized.status,
          normalized.policyId,
          normalized.balanceMinor,
          normalized.lastActivityAtMs,
          normalized.createdAtMs,
          normalized.updatedAtMs,
        )
        .run();
    } catch (error: unknown) {
      if (isD1ConstraintError(error)) {
        throw new ConsoleWalletError(
          'wallet_address_conflict',
          409,
          `Wallet address ${normalized.address} already exists`,
        );
      }
      throw error;
    }
    const wallet = await this.getWallet(ctx, normalized.id);
    if (!wallet) {
      throw new ConsoleWalletError('internal', 500, 'Failed to upsert wallet');
    }
    return wallet;
  }

  private async queryWalletPage(
    ctx: ConsoleWalletsContext,
    request: ListConsoleWalletsRequest,
    searchQ?: string,
  ): Promise<ConsoleWalletPage> {
    const query = buildWalletQuery({
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      request,
      searchQ,
    });
    const out = await this.state.database
      .prepare(
        `SELECT *
           FROM wallet_index
          WHERE ${query.whereSql}
          ORDER BY ${query.orderBySql}
          LIMIT ?`,
      )
      .bind(...query.values, query.limit + 1)
      .all<D1Row>();
    const wallets = (out.results || []).map((row) => parseWalletRow(row));
    return buildWalletPage({
      wallets,
      limit: query.limit,
      sortBy: query.sortBy,
      sortOrder: query.sortOrder,
    });
  }
}
