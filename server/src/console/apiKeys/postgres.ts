import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import {
  ensureConsoleNamespace as ensureNamespace,
  toConsoleIso as toIso,
  toConsoleNumber as toNumber,
} from '../shared/postgresNormalize';
import {
  ensureConsoleTenantRlsPolicies,
  withConsoleTenantContextTx,
} from '../shared/postgresTenantContext';
import { ConsoleApiKeyError } from './errors';
import type {
  ConsoleApiKey,
  CreateConsoleApiKeyRequest,
  CreateConsoleApiKeyResult,
  RotateConsoleApiKeyRequest,
  RotateConsoleApiKeyResult,
} from './types';
import type { ConsoleApiKeyService, ConsoleApiKeysContext } from './service';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_API_KEYS_MIGRATION_LOCK_ID = 9452360123585;

interface StoredApiKey extends ConsoleApiKey {
  secretHash: string;
}

function nowMs(now: Date): number {
  return now.getTime();
}

function parseStringArray(raw: unknown): string[] {
  const source = (() => {
    if (Array.isArray(raw)) return raw;
    if (typeof raw === 'string') {
      try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    }
    return [];
  })();

  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of source) {
    const value = String(entry || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function parseUsageCounts(raw: unknown): Record<string, number> {
  const source = (() => {
    if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw as Record<string, unknown>;
    if (typeof raw === 'string') {
      try {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          return parsed as Record<string, unknown>;
        }
      } catch {
        return {};
      }
    }
    return {};
  })();

  const out: Record<string, number> = {};
  for (const [keyRaw, valueRaw] of Object.entries(source)) {
    const key = String(keyRaw || '').trim();
    if (!key) continue;
    const value = Number(valueRaw);
    if (!Number.isFinite(value) || value < 0) continue;
    out[key] = Math.floor(value);
  }
  return out;
}

function parseApiKeyRow(row: PgRow): StoredApiKey {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    name: String(row.name || ''),
    environmentId: String(row.environment_id || ''),
    scopes: parseStringArray(row.scopes),
    ipAllowlist: parseStringArray(row.ip_allowlist),
    status: String(row.status || 'ACTIVE') as ConsoleApiKey['status'],
    secretVersion: toNumber(row.secret_version, 1),
    secretPreview: String(row.secret_preview || ''),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
    lastUsedAt: toIso(row.last_used_at_ms == null ? null : toNumber(row.last_used_at_ms)),
    endpointUsageCounts: parseUsageCounts(row.endpoint_usage_counts),
    anomalyFlags: parseStringArray(row.anomaly_flags),
    secretHash: String(row.secret_hash || ''),
  };
}

function toPublicApiKey(input: StoredApiKey): ConsoleApiKey {
  return {
    id: input.id,
    orgId: input.orgId,
    name: input.name,
    environmentId: input.environmentId,
    scopes: [...input.scopes],
    ipAllowlist: [...input.ipAllowlist],
    status: input.status,
    secretVersion: input.secretVersion,
    secretPreview: input.secretPreview,
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
    lastUsedAt: input.lastUsedAt,
    endpointUsageCounts: { ...input.endpointUsageCounts },
    anomalyFlags: [...input.anomalyFlags],
  };
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function makeSecret(now: Date): string {
  return `tsk_${makeId('sec', now)}_${Math.random().toString(36).slice(2, 14)}`;
}

function makeSecretPreview(secret: string): string {
  return `${secret.slice(0, 10)}...`;
}

function fnv1a(input: string): string {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

async function hashSecret(secret: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    return `fnv1a:${fnv1a(secret)}`;
  }
  const bytes = await subtle.digest('SHA-256', new TextEncoder().encode(secret));
  const hex = Array.from(new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `sha256:${hex}`;
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

export interface PostgresConsoleApiKeySchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleApiKeysPostgresSchema(
  options: PostgresConsoleApiKeySchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_API_KEYS_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_api_keys (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        name TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        scopes JSONB NOT NULL,
        ip_allowlist JSONB NOT NULL,
        status TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        secret_version INTEGER NOT NULL,
        secret_preview TEXT NOT NULL,
        last_used_at_ms BIGINT,
        endpoint_usage_counts JSONB NOT NULL,
        anomaly_flags JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        CHECK (status IN ('ACTIVE', 'REVOKED')),
        CHECK (jsonb_typeof(scopes) = 'array'),
        CHECK (jsonb_typeof(ip_allowlist) = 'array'),
        CHECK (jsonb_typeof(endpoint_usage_counts) = 'object'),
        CHECK (jsonb_typeof(anomaly_flags) = 'array')
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_api_keys_org_updated_idx
      ON console_api_keys (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_api_keys_org_status_idx
      ON console_api_keys (namespace, org_id, status)
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_api_keys',
      policyName: 'console_api_keys_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_API_KEYS_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }
  options.logger.info('[console-api-keys][postgres] Schema ready');
}

export interface PostgresConsoleApiKeyServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleApiKeyService(
  options: PostgresConsoleApiKeyServiceOptions,
): Promise<ConsoleApiKeyService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) throw new Error('Missing POSTGRES_URL for Postgres console API key service');

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());

  if (options.ensureSchema !== false) {
    await ensureConsoleApiKeysPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }
  const pool = await getPostgresPool(postgresUrl);
  const withTenantTx = <T>(
    ctx: ConsoleApiKeysContext,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, fn);

  async function findApiKey(
    q: Queryable,
    input: { orgId: string; apiKeyId: string },
  ): Promise<StoredApiKey | null> {
    const row = await queryOne(
      q,
      `SELECT *
         FROM console_api_keys
        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
      [namespace, input.orgId, input.apiKeyId],
    );
    return row ? parseApiKeyRow(row) : null;
  }

  return {
    async listApiKeys(ctx: ConsoleApiKeysContext): Promise<ConsoleApiKey[]> {
      return withTenantTx(ctx, async (q) => {
        const out = await q.query(
          `SELECT *
             FROM console_api_keys
            WHERE namespace = $1 AND org_id = $2
            ORDER BY updated_at_ms DESC, created_at_ms DESC`,
          [namespace, ctx.orgId],
        );
        return out.rows.map((row) => toPublicApiKey(parseApiKeyRow(row as PgRow)));
      });
    },

    async createApiKey(
      ctx: ConsoleApiKeysContext,
      request: CreateConsoleApiKeyRequest,
    ): Promise<CreateConsoleApiKeyResult> {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        const secret = makeSecret(now);
        const row = await queryOne(
          q,
          `INSERT INTO console_api_keys
            (namespace, id, org_id, name, environment_id, scopes, ip_allowlist, status, secret_hash, secret_version, secret_preview, last_used_at_ms, endpoint_usage_counts, anomaly_flags, created_at_ms, updated_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, $10, $11, NULL, '{}'::jsonb, '[]'::jsonb, $12, $12)
           RETURNING *`,
          [
            namespace,
            makeId('ak', now),
            ctx.orgId,
            request.name,
            request.environmentId,
            JSON.stringify(request.scopes),
            JSON.stringify(request.ipAllowlist || []),
            'ACTIVE',
            await hashSecret(secret),
            1,
            makeSecretPreview(secret),
            nowMs(now),
          ],
        );
        if (!row) {
          throw new ConsoleApiKeyError('internal', 500, 'Failed to create API key');
        }
        return {
          apiKey: toPublicApiKey(parseApiKeyRow(row)),
          secret,
        };
      });
    },

    async revokeApiKey(
      ctx: ConsoleApiKeysContext,
      apiKeyId: string,
    ): Promise<{ revoked: boolean; apiKey: ConsoleApiKey | null }> {
      return withTenantTx(ctx, async (q) => {
        const current = await findApiKey(q, { orgId: ctx.orgId, apiKeyId });
        if (!current) {
          return { revoked: false, apiKey: null };
        }
        if (current.status === 'REVOKED') {
          return { revoked: true, apiKey: toPublicApiKey(current) };
        }

        const row = await queryOne(
          q,
          `UPDATE console_api_keys
              SET status = 'REVOKED',
                  updated_at_ms = $4
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [namespace, ctx.orgId, apiKeyId, nowMs(nowFn())],
        );
        if (!row) {
          return { revoked: false, apiKey: null };
        }
        return { revoked: true, apiKey: toPublicApiKey(parseApiKeyRow(row)) };
      });
    },

    async rotateApiKey(
      ctx: ConsoleApiKeysContext,
      apiKeyId: string,
      _request?: RotateConsoleApiKeyRequest,
    ): Promise<RotateConsoleApiKeyResult | null> {
      return withTenantTx(ctx, async (q) => {
        const current = await findApiKey(q, { orgId: ctx.orgId, apiKeyId });
        if (!current) return null;
        if (current.status === 'REVOKED') {
          throw new ConsoleApiKeyError(
            'api_key_revoked',
            409,
            `API key ${apiKeyId} is revoked and cannot be rotated`,
          );
        }

        const now = nowFn();
        const secret = makeSecret(now);
        const row = await queryOne(
          q,
          `UPDATE console_api_keys
              SET secret_hash = $4,
                  secret_version = secret_version + 1,
                  secret_preview = $5,
                  updated_at_ms = $6
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [namespace, ctx.orgId, apiKeyId, await hashSecret(secret), makeSecretPreview(secret), nowMs(now)],
        );
        if (!row) return null;
        return {
          apiKey: toPublicApiKey(parseApiKeyRow(row)),
          secret,
        };
      });
    },
  };
}
