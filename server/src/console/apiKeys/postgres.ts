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
import { isIpAllowlistMatch } from './ipAllowlist';
import {
  hashApiKeySecret,
  makeApiKeyLookupPrefix,
  makeApiKeySecret,
  makeId,
  makeSecretPreview,
  parseApiKeySecret,
} from './secret';
import type {
  AuthenticateConsoleApiKeyResult,
  ConsoleApiKey,
  CreateConsoleApiKeyRequest,
  CreateConsoleApiKeyResult,
  RevokeConsoleApiKeyRequest,
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
  keyPrefix: string;
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
    expiresAt: toIso(row.expires_at_ms == null ? null : toNumber(row.expires_at_ms)),
    revokedReason: row.revoked_reason == null ? null : String(row.revoked_reason || ''),
    endpointUsageCounts: parseUsageCounts(row.endpoint_usage_counts),
    anomalyFlags: parseStringArray(row.anomaly_flags),
    secretHash: String(row.secret_hash || ''),
    keyPrefix: String(row.key_prefix || ''),
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
    expiresAt: input.expiresAt,
    revokedReason: input.revokedReason,
    endpointUsageCounts: { ...input.endpointUsageCounts },
    anomalyFlags: [...input.anomalyFlags],
  };
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
        key_prefix TEXT NOT NULL,
        scopes JSONB NOT NULL,
        ip_allowlist JSONB NOT NULL,
        status TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        secret_version INTEGER NOT NULL,
        secret_preview TEXT NOT NULL,
        last_used_at_ms BIGINT,
        expires_at_ms BIGINT,
        revoked_reason TEXT,
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
      ALTER TABLE console_api_keys
      ADD COLUMN IF NOT EXISTS key_prefix TEXT
    `);
    await pool.query(`
      UPDATE console_api_keys
         SET key_prefix = ''
       WHERE key_prefix IS NULL
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN key_prefix SET DEFAULT ''
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN key_prefix SET NOT NULL
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ADD COLUMN IF NOT EXISTS expires_at_ms BIGINT
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ADD COLUMN IF NOT EXISTS revoked_reason TEXT
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_api_keys_org_updated_idx
      ON console_api_keys (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_api_keys_org_status_idx
      ON console_api_keys (namespace, org_id, status)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_api_keys_org_key_prefix_idx
      ON console_api_keys (namespace, org_id, key_prefix, id)
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

  function hasRequiredScopes(scopes: string[], requiredScopes: string[]): boolean {
    if (!requiredScopes.length) return true;
    const available = new Set(
      scopes.map((scope) => String(scope || '').trim().toLowerCase()).filter(Boolean),
    );
    for (const required of requiredScopes) {
      const normalized = String(required || '').trim().toLowerCase();
      if (!normalized) continue;
      if (!available.has(normalized)) return false;
    }
    return true;
  }

  async function appendAnomalyFlag(input: {
    orgId: string;
    apiKeyId: string;
    anomaly: string;
    nowMsValue: number;
  }): Promise<void> {
    await withConsoleTenantContextTx(pool, { namespace, orgId: input.orgId }, async (q) => {
      await q.query(
        `UPDATE console_api_keys
            SET anomaly_flags = CASE
                  WHEN anomaly_flags ? $4 THEN anomaly_flags
                  ELSE anomaly_flags || to_jsonb($4::text)
                END,
                updated_at_ms = $5
          WHERE namespace = $1 AND org_id = $2 AND id = $3`,
        [namespace, input.orgId, input.apiKeyId, input.anomaly, input.nowMsValue],
      );
    });
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
        const apiKeyId = makeId('ak', now);
        const secret = makeApiKeySecret({ orgId: ctx.orgId, apiKeyId });
        const keyPrefix = makeApiKeyLookupPrefix(secret);
        const expiresAtMs = request.expiresAt ? Date.parse(request.expiresAt) : NaN;
        const row = await queryOne(
          q,
          `INSERT INTO console_api_keys
            (namespace, id, org_id, name, environment_id, key_prefix, scopes, ip_allowlist, status, secret_hash, secret_version, secret_preview, last_used_at_ms, expires_at_ms, revoked_reason, endpoint_usage_counts, anomaly_flags, created_at_ms, updated_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, $11, $12, NULL, $13, NULL, '{}'::jsonb, '[]'::jsonb, $14, $14)
           RETURNING *`,
          [
            namespace,
            apiKeyId,
            ctx.orgId,
            request.name,
            request.environmentId,
            keyPrefix,
            JSON.stringify(request.scopes),
            JSON.stringify(request.ipAllowlist || []),
            'ACTIVE',
            await hashApiKeySecret(secret),
            1,
            makeSecretPreview(secret),
            Number.isFinite(expiresAtMs) ? Math.floor(expiresAtMs) : null,
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
      request?: RevokeConsoleApiKeyRequest,
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
                  revoked_reason = $4,
                  updated_at_ms = $5
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [
            namespace,
            ctx.orgId,
            apiKeyId,
            String(request?.reason || '').trim() || null,
            nowMs(nowFn()),
          ],
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
        const secret = makeApiKeySecret({ orgId: ctx.orgId, apiKeyId });
        const keyPrefix = makeApiKeyLookupPrefix(secret);
        const row = await queryOne(
          q,
          `UPDATE console_api_keys
              SET secret_hash = $4,
                  key_prefix = $5,
                  secret_version = secret_version + 1,
                  secret_preview = $6,
                  updated_at_ms = $7
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [
            namespace,
            ctx.orgId,
            apiKeyId,
            await hashApiKeySecret(secret),
            keyPrefix,
            makeSecretPreview(secret),
            nowMs(now),
          ],
        );
        if (!row) return null;
        return {
          apiKey: toPublicApiKey(parseApiKeyRow(row)),
          secret,
        };
      });
    },

    async authenticateApiKey(request): Promise<AuthenticateConsoleApiKeyResult> {
      const secret = String(request.secret || '').trim();
      if (!secret) {
        return {
          ok: false,
          status: 401,
          code: 'api_key_missing',
          message: 'Missing API key secret',
        };
      }

      const parsed = parseApiKeySecret(secret);
      if (!parsed) {
        return {
          ok: false,
          status: 401,
          code: 'api_key_invalid',
          message: 'Invalid API key',
        };
      }

      const hashedSecret = await hashApiKeySecret(secret);
      const keyPrefix = makeApiKeyLookupPrefix(secret);
      const keyRow = await withConsoleTenantContextTx(
        pool,
        { namespace, orgId: parsed.orgId },
        async (q) => {
          const prefixed = await queryOne(
            q,
            `SELECT *
               FROM console_api_keys
              WHERE namespace = $1
                AND org_id = $2
                AND id = $3
                AND key_prefix = $4`,
            [namespace, parsed.orgId, parsed.apiKeyId, keyPrefix],
          );
          if (prefixed) return parseApiKeyRow(prefixed);
          return await findApiKey(q, { orgId: parsed.orgId, apiKeyId: parsed.apiKeyId });
        },
      );
      if (!keyRow || keyRow.secretHash !== hashedSecret) {
        return {
          ok: false,
          status: 401,
          code: 'api_key_invalid',
          message: 'Invalid API key',
        };
      }

      const currentNowMs = nowMs(nowFn());
      const appendAnomaly = async (anomaly: string): Promise<void> => {
        await appendAnomalyFlag({
          orgId: keyRow.orgId,
          apiKeyId: keyRow.id,
          anomaly,
          nowMsValue: currentNowMs,
        });
      };

      if (keyRow.status === 'REVOKED') {
        await appendAnomaly('auth.revoked_attempt');
        return {
          ok: false,
          status: 403,
          code: 'api_key_revoked',
          message: 'API key has been revoked',
        };
      }

      if (keyRow.expiresAt) {
        const expiresAtMs = Date.parse(keyRow.expiresAt);
        if (Number.isFinite(expiresAtMs) && expiresAtMs <= currentNowMs) {
          await appendAnomaly('auth.expired_attempt');
          return {
            ok: false,
            status: 403,
            code: 'api_key_revoked',
            message: 'API key has expired',
          };
        }
      }

      const requestEnvironmentId = String(request.environmentId || '').trim();
      if (requestEnvironmentId && requestEnvironmentId !== keyRow.environmentId) {
        await appendAnomaly('auth.environment_mismatch');
        return {
          ok: false,
          status: 403,
          code: 'api_key_environment_mismatch',
          message: 'API key is not valid for the requested environment',
        };
      }

      if (!hasRequiredScopes(keyRow.scopes, request.requiredScopes || [])) {
        await appendAnomaly('auth.scope_denied');
        return {
          ok: false,
          status: 403,
          code: 'api_key_forbidden_scope',
          message: 'API key does not grant required scope',
        };
      }

      if (!isIpAllowlistMatch({ allowlist: keyRow.ipAllowlist, sourceIp: request.sourceIp })) {
        await appendAnomaly('auth.ip_blocked');
        return {
          ok: false,
          status: 403,
          code: 'api_key_ip_blocked',
          message: 'API key is blocked for this source IP',
        };
      }

      const endpoint = String(request.endpoint || '').trim();
      const refreshed = await withConsoleTenantContextTx(
        pool,
        { namespace, orgId: keyRow.orgId },
        async (q) => {
          const row = await queryOne(
            q,
            `UPDATE console_api_keys
                SET last_used_at_ms = $4,
                    endpoint_usage_counts = CASE
                      WHEN $5 = '' THEN endpoint_usage_counts
                      ELSE jsonb_set(
                        endpoint_usage_counts,
                        ARRAY[$5]::text[],
                        to_jsonb(COALESCE((endpoint_usage_counts ->> $5)::bigint, 0) + 1),
                        true
                      )
                    END,
                    updated_at_ms = $4
              WHERE namespace = $1 AND org_id = $2 AND id = $3
              RETURNING *`,
            [namespace, keyRow.orgId, keyRow.id, currentNowMs, endpoint],
          );
          return row ? parseApiKeyRow(row) : null;
        },
      );

      return {
        ok: true,
        apiKey: toPublicApiKey(refreshed || keyRow),
      };
    },
  };
}
