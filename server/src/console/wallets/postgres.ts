import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import { ensureConsoleOrgProjectEnvPostgresSchema } from '../orgProjectEnv/postgres';
import {
  ensureConsoleNamespace as ensureNamespace,
  toConsoleIso as toIso,
  toConsoleNumber as toNumber,
} from '../shared/postgresNormalize';
import {
  ensureConsoleTenantRlsPolicies,
  withConsoleTenantContextTx,
} from '../shared/postgresTenantContext';
import { ConsoleWalletError } from './errors';
import {
  makeDeterministicWalletAddress as makeDeterministicAddress,
  normalizeWalletLimit as normalizeLimit,
  normalizeWalletSortBy as normalizeSortBy,
  normalizeWalletSortOrder as normalizeSortOrder,
  slugifyWalletToken as slugify,
} from './normalization';
import type { ConsoleWalletService, ConsoleWalletsContext } from './service';
import type {
  ConsoleWallet,
  ConsoleWalletPage,
  ConsoleWalletSortBy,
  ConsoleWalletSortOrder,
  ListConsoleWalletsRequest,
  SearchConsoleWalletsRequest,
} from './types';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_WALLETS_MIGRATION_LOCK_ID = 9452360123587;

interface WalletCursorPayload {
  sortBy: ConsoleWalletSortBy;
  sortOrder: ConsoleWalletSortOrder;
  sortValue: number;
  id: string;
}

function nowMs(now: Date): number {
  return now.getTime();
}

function humanizeId(value: string, fallback: string): string {
  const trimmed = String(value || '').trim();
  if (!trimmed) return fallback;
  return trimmed
    .replace(/[_:-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function inferEnvironmentKey(
  environmentId: string | undefined,
): 'dev' | 'staging' | 'prod' {
  const value = String(environmentId || '').toLowerCase();
  if (value.includes('stag')) return 'staging';
  if (value.includes('dev') || value.includes('test')) return 'dev';
  return 'prod';
}

function environmentNameFromKey(key: 'dev' | 'staging' | 'prod'): string {
  if (key === 'dev') return 'Development';
  if (key === 'staging') return 'Staging';
  return 'Production';
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

function sortColumn(sortBy: ConsoleWalletSortBy): string {
  if (sortBy === 'balance') return 'balance_minor';
  if (sortBy === 'lastActivity') return 'COALESCE(last_activity_at_ms, 0)';
  return 'created_at_ms';
}

function parseWalletRow(row: PgRow): ConsoleWallet {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    projectId: String(row.project_id || ''),
    environmentId: String(row.environment_id || ''),
    userId: String(row.user_id || ''),
    externalRefId: String(row.external_ref_id || ''),
    address: String(row.address || ''),
    chain: String(row.chain || 'Ethereum') as ConsoleWallet['chain'],
    walletType: String(row.wallet_type || 'EOA') as ConsoleWallet['walletType'],
    status: String(row.status || 'ACTIVE') as ConsoleWallet['status'],
    policyId: row.policy_id == null ? null : String(row.policy_id),
    balanceMinor: toNumber(row.balance_minor),
    lastActivityAt: toIso(row.last_activity_at_ms == null ? null : toNumber(row.last_activity_at_ms)),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

function buildBootstrapWallet(ctx: ConsoleWalletsContext, now: Date): {
  id: string;
  orgId: string;
  projectId: string;
  environmentId: string;
  userId: string;
  externalRefId: string;
  address: string;
  createdAtMs: number;
} {
  const projectId = String(ctx.projectId || `${ctx.orgId}:default-project`).trim();
  const environmentId = String(ctx.environmentId || `${projectId}:prod`).trim();
  const seed = `${ctx.orgId}:${projectId}:${environmentId}`;
  return {
    id: `wallet_${slugify(seed).replace(/-/g, '_').slice(0, 40)}`,
    orgId: ctx.orgId,
    projectId,
    environmentId,
    userId: `user_${slugify(ctx.orgId).replace(/-/g, '_').slice(0, 12)}`,
    externalRefId: `ext_${slugify(seed).replace(/-/g, '_').slice(0, 18)}`,
    address: makeDeterministicAddress(seed),
    createdAtMs: nowMs(now),
  };
}

async function ensureBootstrapWallet(
  q: Queryable,
  input: {
    namespace: string;
    ctx: ConsoleWalletsContext;
    now: Date;
  },
): Promise<void> {
  const bootstrap = buildBootstrapWallet(input.ctx, input.now);
  const envKey = inferEnvironmentKey(bootstrap.environmentId);
  await q.query(
    `INSERT INTO console_organizations
      (namespace, id, name, slug, status, created_at_ms, updated_at_ms)
     VALUES
      ($1, $2, $3, $4, 'ACTIVE', $5, $5)
     ON CONFLICT (namespace, id) DO NOTHING`,
    [
      input.namespace,
      bootstrap.orgId,
      humanizeId(bootstrap.orgId, 'Organization'),
      slugify(bootstrap.orgId),
      bootstrap.createdAtMs,
    ],
  );
  await q.query(
    `INSERT INTO console_projects
      (namespace, id, org_id, name, slug, status, created_at_ms, updated_at_ms)
     VALUES
      ($1, $2, $3, $4, $5, 'ACTIVE', $6, $6)
     ON CONFLICT (namespace, id) DO NOTHING`,
    [
      input.namespace,
      bootstrap.projectId,
      bootstrap.orgId,
      humanizeId(bootstrap.projectId, 'Default Project'),
      slugify(bootstrap.projectId),
      bootstrap.createdAtMs,
    ],
  );
  await q.query(
    `INSERT INTO console_environments
      (namespace, id, org_id, project_id, env_key, name, status, created_at_ms, updated_at_ms)
     VALUES
      ($1, $2, $3, $4, $5, $6, 'ACTIVE', $7, $7)
     ON CONFLICT (namespace, id) DO NOTHING`,
    [
      input.namespace,
      bootstrap.environmentId,
      bootstrap.orgId,
      bootstrap.projectId,
      envKey,
      environmentNameFromKey(envKey),
      bootstrap.createdAtMs,
    ],
  );
  await q.query(
    `INSERT INTO console_wallet_index
      (namespace, id, org_id, project_id, environment_id, user_id, external_ref_id, address, chain, wallet_type, status, policy_id, balance_minor, last_activity_at_ms, created_at_ms, updated_at_ms)
     VALUES
      ($1, $2, $3, $4, $5, $6, $7, $8, 'Ethereum', 'EOA', 'ACTIVE', 'policy_default', 0, NULL, $9, $9)
     ON CONFLICT (namespace, id) DO NOTHING`,
    [
      input.namespace,
      bootstrap.id,
      bootstrap.orgId,
      bootstrap.projectId,
      bootstrap.environmentId,
      bootstrap.userId,
      bootstrap.externalRefId,
      bootstrap.address,
      bootstrap.createdAtMs,
    ],
  );
}

interface WalletQueryResult {
  items: ConsoleWallet[];
  nextCursor?: string;
}

async function queryWalletPage(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    request: ListConsoleWalletsRequest;
    searchQ?: string;
  },
): Promise<WalletQueryResult> {
  const sortBy = normalizeSortBy(input.request.sortBy);
  const sortOrder = normalizeSortOrder(input.request.sortOrder);
  const limit = normalizeLimit(input.request.limit);
  const column = sortColumn(sortBy);
  const direction = sortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

  const clauses: string[] = ['namespace = $1', 'org_id = $2'];
  const params: unknown[] = [input.namespace, input.orgId];

  const pushParam = (value: unknown): string => {
    params.push(value);
    return `$${params.length}`;
  };

  if (input.request.projectId) clauses.push(`project_id = ${pushParam(input.request.projectId)}`);
  if (input.request.environmentId) clauses.push(`environment_id = ${pushParam(input.request.environmentId)}`);
  if (input.request.chain) clauses.push(`chain = ${pushParam(input.request.chain)}`);
  if (input.request.walletType) clauses.push(`wallet_type = ${pushParam(input.request.walletType)}`);
  if (input.request.status) clauses.push(`status = ${pushParam(input.request.status)}`);
  if (input.request.policyId) clauses.push(`policy_id = ${pushParam(input.request.policyId)}`);
  if (input.request.userId) clauses.push(`user_id = ${pushParam(input.request.userId)}`);
  if (input.request.externalRefId) clauses.push(`external_ref_id = ${pushParam(input.request.externalRefId)}`);

  if (input.searchQ) {
    const qLike = `%${input.searchQ.toLowerCase()}%`;
    const param = pushParam(qLike);
    clauses.push(
      `(LOWER(id) LIKE ${param} OR LOWER(address) LIKE ${param} OR LOWER(user_id) LIKE ${param} OR LOWER(external_ref_id) LIKE ${param})`,
    );
  }

  const cursor = input.request.cursor ? decodeCursor(input.request.cursor) : null;
  if (cursor) {
    if (cursor.sortBy !== sortBy || cursor.sortOrder !== sortOrder) {
      throw new ConsoleWalletError(
        'invalid_query',
        400,
        'Cursor does not match requested sortBy/sortOrder',
      );
    }
    const sortParam = pushParam(cursor.sortValue);
    const idParam = pushParam(cursor.id);
    const op = direction === 'DESC' ? '<' : '>';
    clauses.push(`(${column} ${op} ${sortParam} OR (${column} = ${sortParam} AND id ${op} ${idParam}))`);
  }

  const limitParam = pushParam(limit + 1);
  const sql = `
    SELECT *
      FROM console_wallet_index
     WHERE ${clauses.join(' AND ')}
     ORDER BY ${column} ${direction}, id ${direction}
     LIMIT ${limitParam}
  `;

  const out = await q.query(sql, params);
  const wallets = out.rows.map((row) => parseWalletRow(row as PgRow));
  const hasMore = wallets.length > limit;
  const items = hasMore ? wallets.slice(0, limit) : wallets;

  const last = items[items.length - 1];
  const nextCursor = hasMore && last
    ? encodeCursor({
      sortBy,
      sortOrder,
      sortValue:
        sortBy === 'balance'
          ? last.balanceMinor
          : sortBy === 'lastActivity'
            ? toNumber(last.lastActivityAt ? Date.parse(last.lastActivityAt) : 0)
            : toNumber(Date.parse(last.createdAt)),
      id: last.id,
    })
    : undefined;

  return { items, ...(nextCursor ? { nextCursor } : {}) };
}

export interface PostgresConsoleWalletSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleWalletsPostgresSchema(
  options: PostgresConsoleWalletSchemaOptions,
): Promise<void> {
  await ensureConsoleOrgProjectEnvPostgresSchema({
    postgresUrl: options.postgresUrl,
    logger: options.logger,
  });

  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_WALLETS_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_wallet_index (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        external_ref_id TEXT NOT NULL,
        address TEXT NOT NULL,
        chain TEXT NOT NULL,
        wallet_type TEXT NOT NULL,
        status TEXT NOT NULL,
        policy_id TEXT,
        balance_minor BIGINT NOT NULL,
        last_activity_at_ms BIGINT,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        UNIQUE (namespace, org_id, address),
        CHECK (chain IN ('Ethereum', 'Base', 'Tempo', 'Arc Circle', 'NEAR')),
        CHECK (wallet_type IN ('EOA', 'SMART')),
        CHECK (status IN ('ACTIVE', 'FROZEN', 'ARCHIVED'))
      )
    `);
    await pool.query(`
      ALTER TABLE console_wallet_index
      DROP CONSTRAINT IF EXISTS console_wallet_index_namespace_environment_id_project_id_org_id_fkey
    `);
    await pool.query(`
      ALTER TABLE console_wallet_index
      DROP CONSTRAINT IF EXISTS console_wallet_index_environment_fk
    `);
    await pool.query(`
      DO $$
      BEGIN
        ALTER TABLE console_wallet_index
          ADD CONSTRAINT console_wallet_index_environment_fk
          FOREIGN KEY (namespace, environment_id, project_id, org_id)
          REFERENCES console_environments(namespace, id, project_id, org_id)
          NOT VALID;
      EXCEPTION
        WHEN duplicate_object THEN NULL;
      END
      $$;
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_wallet_index_org_created_idx
      ON console_wallet_index (namespace, org_id, created_at_ms DESC, id DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_wallet_index_org_project_env_idx
      ON console_wallet_index (namespace, org_id, project_id, environment_id)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_wallet_index_org_status_type_chain_idx
      ON console_wallet_index (namespace, org_id, status, wallet_type, chain)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_wallet_index_org_balance_idx
      ON console_wallet_index (namespace, org_id, balance_minor DESC, id DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_wallet_index_org_last_activity_idx
      ON console_wallet_index (namespace, org_id, COALESCE(last_activity_at_ms, 0) DESC, id DESC)
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_wallet_index',
      policyName: 'console_wallet_index_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_WALLETS_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }
  options.logger.info('[console-wallets][postgres] Schema ready');
}

export interface PostgresConsoleWalletServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleWalletService(
  options: PostgresConsoleWalletServiceOptions,
): Promise<ConsoleWalletService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) throw new Error('Missing POSTGRES_URL for Postgres console wallet service');

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());
  if (options.ensureSchema !== false) {
    await ensureConsoleWalletsPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);
  const withTenantTx = <T>(
    ctx: ConsoleWalletsContext,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, fn);

  return {
    async listWallets(
      ctx: ConsoleWalletsContext,
      request: ListConsoleWalletsRequest = {},
    ): Promise<ConsoleWalletPage> {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        await ensureBootstrapWallet(q, { namespace, ctx, now });
        return queryWalletPage(q, {
          namespace,
          orgId: ctx.orgId,
          request,
        });
      });
    },

    async searchWallets(
      ctx: ConsoleWalletsContext,
      request: SearchConsoleWalletsRequest,
    ): Promise<ConsoleWalletPage> {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        await ensureBootstrapWallet(q, { namespace, ctx, now });
        return queryWalletPage(q, {
          namespace,
          orgId: ctx.orgId,
          request,
          searchQ: request.q,
        });
      });
    },

    async getWallet(
      ctx: ConsoleWalletsContext,
      walletId: string,
    ): Promise<ConsoleWallet | null> {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        await ensureBootstrapWallet(q, { namespace, ctx, now });
        const row = await queryOne(
          q,
          `SELECT *
             FROM console_wallet_index
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, walletId],
        );
        return row ? parseWalletRow(row) : null;
      });
    },
  };
}
