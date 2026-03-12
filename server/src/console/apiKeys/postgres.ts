import type { NormalizedLogger } from '../../core/logger';
import { normalizeCorsOrigin } from '../../core/SessionService';
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
import { buildPublishableKeyOriginBlockedMessage } from './originMessage';
import {
  hashApiKeySecret,
  makeApiKeyLookupPrefix,
  makeApiKeyId,
  makeApiKeySecret,
  makeSecretPreview,
  parseApiKeySecret,
} from './secret';
import type {
  AuthenticateConsoleApiKeyResult,
  AuthenticateConsolePublishableKeyResult,
  ConsoleApiKey,
  CreateConsoleApiKeyRequest,
  CreateConsoleApiKeyResult,
  RevokeConsoleApiKeyRequest,
  RotateConsoleApiKeyRequest,
  RotateConsoleApiKeyResult,
  UpdateConsoleApiKeyRequest,
} from './types';
import type { ConsoleApiKeyService, ConsoleApiKeysContext } from './service';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_API_KEYS_MIGRATION_LOCK_ID = 9452360123585;
const CONSOLE_API_KEY_LOOKUP_KIND_GUC = 'app.console_api_key_lookup_kind';
const CONSOLE_API_KEY_LOOKUP_PREFIX_GUC = 'app.console_api_key_lookup_prefix';
const CONSOLE_API_KEY_LOOKUP_HASH_GUC = 'app.console_api_key_lookup_hash';

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

function parseJsonObject(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return { ...(raw as Record<string, unknown>) };
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return { ...(parsed as Record<string, unknown>) };
      }
    } catch {
      return {};
    }
  }
  return {};
}

function cloneJsonObject(input: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!input) return undefined;
  return { ...input };
}

function hasAnyDefinedField(input: UpdateConsoleApiKeyRequest): boolean {
  return Object.values(input).some((value) => value !== undefined);
}

function parseApiKeyRow(row: PgRow): StoredApiKey {
  const kind = String(row.kind || 'secret_key').trim() === 'publishable_key'
    ? 'publishable_key'
    : 'secret_key';
  const common = {
    id: String(row.id || ''),
    kind,
    orgId: String(row.org_id || ''),
    name: String(row.name || ''),
    environmentId: String(row.environment_id || ''),
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
  } satisfies Omit<
    StoredApiKey,
    | 'scopes'
    | 'ipAllowlist'
    | 'allowedOrigins'
    | 'rateLimitBucket'
    | 'quotaBucket'
    | 'riskPolicy'
    | 'paymentPolicy'
  >;
  if (kind === 'publishable_key') {
    return {
      ...common,
      allowedOrigins: parseStringArray(row.allowed_origins),
      rateLimitBucket: String(row.rate_limit_bucket || '').trim(),
      quotaBucket: String(row.quota_bucket || '').trim(),
      riskPolicy: parseJsonObject(row.risk_policy),
      paymentPolicy: parseJsonObject(row.payment_policy),
    };
  }
  return {
    ...common,
    scopes: parseStringArray(row.scopes),
    ipAllowlist: parseStringArray(row.ip_allowlist),
  };
}

function toPublicApiKey(input: StoredApiKey): ConsoleApiKey {
  const common = {
    id: input.id,
    kind: input.kind,
    orgId: input.orgId,
    name: input.name,
    environmentId: input.environmentId,
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
  } satisfies Omit<ConsoleApiKey, 'scopes' | 'ipAllowlist' | 'allowedOrigins' | 'rateLimitBucket' | 'quotaBucket' | 'riskPolicy' | 'paymentPolicy'>;
  if (input.kind === 'publishable_key') {
    return {
      ...common,
      allowedOrigins: [...(input.allowedOrigins || [])],
      rateLimitBucket: String(input.rateLimitBucket || '').trim(),
      quotaBucket: String(input.quotaBucket || '').trim(),
      riskPolicy: cloneJsonObject(input.riskPolicy),
      paymentPolicy: cloneJsonObject(input.paymentPolicy),
    };
  }
  return {
    ...common,
    scopes: [...(input.scopes || [])],
    ipAllowlist: [...(input.ipAllowlist || [])],
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
        kind TEXT NOT NULL DEFAULT 'secret_key',
        name TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        scopes JSONB NOT NULL,
        ip_allowlist JSONB NOT NULL,
        allowed_origins JSONB NOT NULL DEFAULT '[]'::jsonb,
        rate_limit_bucket TEXT NOT NULL DEFAULT '',
        quota_bucket TEXT NOT NULL DEFAULT '',
        risk_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
        payment_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
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
        CHECK (kind IN ('secret_key', 'publishable_key')),
        CHECK (status IN ('ACTIVE', 'REVOKED')),
        CHECK (jsonb_typeof(scopes) = 'array'),
        CHECK (jsonb_typeof(ip_allowlist) = 'array'),
        CHECK (jsonb_typeof(allowed_origins) = 'array'),
        CHECK (jsonb_typeof(risk_policy) = 'object'),
        CHECK (jsonb_typeof(payment_policy) = 'object'),
        CHECK (jsonb_typeof(endpoint_usage_counts) = 'object'),
        CHECK (jsonb_typeof(anomaly_flags) = 'array')
      )
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ADD COLUMN IF NOT EXISTS kind TEXT
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ADD COLUMN IF NOT EXISTS key_prefix TEXT
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ADD COLUMN IF NOT EXISTS allowed_origins JSONB
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ADD COLUMN IF NOT EXISTS rate_limit_bucket TEXT
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ADD COLUMN IF NOT EXISTS quota_bucket TEXT
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ADD COLUMN IF NOT EXISTS risk_policy JSONB
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ADD COLUMN IF NOT EXISTS payment_policy JSONB
    `);
    await pool.query(`
      UPDATE console_api_keys
         SET kind = 'secret_key'
       WHERE kind IS NULL OR kind = ''
    `);
    await pool.query(`
      UPDATE console_api_keys
         SET key_prefix = ''
       WHERE key_prefix IS NULL
    `);
    await pool.query(`
      UPDATE console_api_keys
         SET allowed_origins = '[]'::jsonb
       WHERE allowed_origins IS NULL
    `);
    await pool.query(`
      UPDATE console_api_keys
         SET rate_limit_bucket = ''
       WHERE rate_limit_bucket IS NULL
    `);
    await pool.query(`
      UPDATE console_api_keys
         SET quota_bucket = ''
       WHERE quota_bucket IS NULL
    `);
    await pool.query(`
      UPDATE console_api_keys
         SET risk_policy = '{}'::jsonb
       WHERE risk_policy IS NULL
    `);
    await pool.query(`
      UPDATE console_api_keys
         SET payment_policy = '{}'::jsonb
       WHERE payment_policy IS NULL
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN kind SET DEFAULT 'secret_key'
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN kind SET NOT NULL
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
      ALTER COLUMN allowed_origins SET DEFAULT '[]'::jsonb
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN allowed_origins SET NOT NULL
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN rate_limit_bucket SET DEFAULT ''
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN rate_limit_bucket SET NOT NULL
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN quota_bucket SET DEFAULT ''
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN quota_bucket SET NOT NULL
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN risk_policy SET DEFAULT '{}'::jsonb
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN risk_policy SET NOT NULL
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN payment_policy SET DEFAULT '{}'::jsonb
    `);
    await pool.query(`
      ALTER TABLE console_api_keys
      ALTER COLUMN payment_policy SET NOT NULL
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
      DROP INDEX IF EXISTS console_api_keys_org_key_prefix_idx
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_api_keys_auth_lookup_idx
      ON console_api_keys (namespace, kind, key_prefix)
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_api_keys',
      policyName: 'console_api_keys_tenant_rls',
    });
    await pool.query(`
      DROP POLICY IF EXISTS console_api_keys_auth_lookup_rls ON console_api_keys
    `);
    await pool.query(`
      CREATE POLICY console_api_keys_auth_lookup_rls
        ON console_api_keys
        FOR SELECT
        USING (
          namespace = current_setting('app.console_namespace', true)
          AND kind = current_setting('${CONSOLE_API_KEY_LOOKUP_KIND_GUC}', true)
          AND key_prefix = current_setting('${CONSOLE_API_KEY_LOOKUP_PREFIX_GUC}', true)
          AND secret_hash = current_setting('${CONSOLE_API_KEY_LOOKUP_HASH_GUC}', true)
        )
    `);
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

  const withAuthLookupTx = async <T>(
    input: {
      kind: 'secret_key' | 'publishable_key';
      keyPrefix: string;
      secretHash: string;
    },
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => {
    if (typeof pool.connect !== 'function') {
      throw new Error('Postgres pool does not expose connect(); API key auth lookup requires a dedicated client');
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `SELECT
           set_config($1, $2, true),
           set_config($3, $4, true),
           set_config($5, $6, true),
           set_config($7, $8, true)`,
        [
          'app.console_namespace',
          namespace,
          CONSOLE_API_KEY_LOOKUP_KIND_GUC,
          input.kind,
          CONSOLE_API_KEY_LOOKUP_PREFIX_GUC,
          input.keyPrefix,
          CONSOLE_API_KEY_LOOKUP_HASH_GUC,
          input.secretHash,
        ],
      );
      const out = await fn(client);
      await client.query('COMMIT');
      return out;
    } catch (error: unknown) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // no-op
      }
      throw error;
    } finally {
      client.release();
    }
  };

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

  async function findApiKeyBySecretFingerprint(input: {
    kind: 'secret_key' | 'publishable_key';
    keyPrefix: string;
    secretHash: string;
  }): Promise<StoredApiKey | null> {
    return withAuthLookupTx(input, async (q) => {
      const row = await queryOne(
        q,
        `SELECT *
           FROM console_api_keys
          WHERE namespace = $1
            AND kind = $2
            AND key_prefix = $3
            AND secret_hash = $4`,
        [namespace, input.kind, input.keyPrefix, input.secretHash],
      );
      return row ? parseApiKeyRow(row) : null;
    });
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

  function isAllowedOrigin(keyRow: StoredApiKey, rawOrigin: string): boolean {
    const origin = normalizeCorsOrigin(rawOrigin) || '';
    if (!origin) return false;
    return (keyRow.allowedOrigins || []).some((entry) => (normalizeCorsOrigin(entry) || '') === origin);
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
        const apiKeyId = makeApiKeyId(now);
        const secret = makeApiKeySecret({ kind: request.kind });
        const keyPrefix = makeApiKeyLookupPrefix(secret);
        const expiresAtMs = request.expiresAt ? Date.parse(request.expiresAt) : NaN;
        const scopes = request.kind === 'secret_key' ? request.scopes : [];
        const ipAllowlist = request.kind === 'secret_key' ? (request.ipAllowlist || []) : [];
        const allowedOrigins = request.kind === 'publishable_key' ? request.allowedOrigins : [];
        const rateLimitBucket =
          request.kind === 'publishable_key' ? request.rateLimitBucket : '';
        const quotaBucket = request.kind === 'publishable_key' ? request.quotaBucket : '';
        const riskPolicy =
          request.kind === 'publishable_key' ? request.riskPolicy || {} : {};
        const paymentPolicy =
          request.kind === 'publishable_key' ? request.paymentPolicy || {} : {};
        const row = await queryOne(
          q,
          `INSERT INTO console_api_keys
            (namespace, id, org_id, kind, name, environment_id, key_prefix, scopes, ip_allowlist, allowed_origins, rate_limit_bucket, quota_bucket, risk_policy, payment_policy, status, secret_hash, secret_version, secret_preview, last_used_at_ms, expires_at_ms, revoked_reason, endpoint_usage_counts, anomaly_flags, created_at_ms, updated_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::jsonb, $11, $12, $13::jsonb, $14::jsonb, $15, $16, $17, $18, NULL, $19, NULL, '{}'::jsonb, '[]'::jsonb, $20, $20)
           RETURNING *`,
          [
            namespace,
            apiKeyId,
            ctx.orgId,
            request.kind,
            request.name,
            request.environmentId,
            keyPrefix,
            JSON.stringify(scopes),
            JSON.stringify(ipAllowlist),
            JSON.stringify(allowedOrigins),
            rateLimitBucket,
            quotaBucket,
            JSON.stringify(riskPolicy),
            JSON.stringify(paymentPolicy),
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

    async deleteApiKey(
      ctx: ConsoleApiKeysContext,
      apiKeyId: string,
    ): Promise<{ deleted: boolean; apiKey: ConsoleApiKey | null }> {
      return withTenantTx(ctx, async (q) => {
        const current = await findApiKey(q, { orgId: ctx.orgId, apiKeyId });
        if (!current) {
          return { deleted: false, apiKey: null };
        }
        if (current.status !== 'REVOKED') {
          throw new ConsoleApiKeyError(
            'api_key_not_revoked',
            409,
            `API key ${apiKeyId} must be revoked before it can be deleted`,
          );
        }
        const row = await queryOne(
          q,
          `DELETE FROM console_api_keys
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [namespace, ctx.orgId, apiKeyId],
        );
        if (!row) {
          return { deleted: false, apiKey: null };
        }
        return { deleted: true, apiKey: toPublicApiKey(parseApiKeyRow(row)) };
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
        const secret = makeApiKeySecret({ kind: current.kind });
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

    async updateApiKey(
      ctx: ConsoleApiKeysContext,
      apiKeyId: string,
      request: UpdateConsoleApiKeyRequest,
    ): Promise<ConsoleApiKey | null> {
      return withTenantTx(ctx, async (q) => {
        const current = await findApiKey(q, { orgId: ctx.orgId, apiKeyId });
        if (!current) return null;
        if (!hasAnyDefinedField(request)) {
          return toPublicApiKey(current);
        }
        if (current.kind === 'publishable_key') {
          if (request.scopes !== undefined || request.ipAllowlist !== undefined) {
            throw new ConsoleApiKeyError(
              'invalid_body',
              400,
              'Fields scopes and ipAllowlist are not valid for publishable_key',
            );
          }
        } else if (
          request.allowedOrigins !== undefined ||
          request.rateLimitBucket !== undefined ||
          request.quotaBucket !== undefined ||
          request.riskPolicy !== undefined ||
          request.paymentPolicy !== undefined
        ) {
          throw new ConsoleApiKeyError(
            'invalid_body',
            400,
            'Fields allowedOrigins, rateLimitBucket, quotaBucket, riskPolicy, and paymentPolicy are not valid for secret_key',
          );
        }

        const now = nowFn();
        const row = await queryOne(
          q,
          `UPDATE console_api_keys
              SET name = COALESCE($4, name),
                  scopes = COALESCE($5::jsonb, scopes),
                  ip_allowlist = COALESCE($6::jsonb, ip_allowlist),
                  allowed_origins = COALESCE($7::jsonb, allowed_origins),
                  rate_limit_bucket = COALESCE($8, rate_limit_bucket),
                  quota_bucket = COALESCE($9, quota_bucket),
                  risk_policy = COALESCE($10::jsonb, risk_policy),
                  payment_policy = COALESCE($11::jsonb, payment_policy),
                  expires_at_ms = CASE
                    WHEN $12::boolean THEN NULL
                    WHEN $13::bigint IS NULL THEN expires_at_ms
                    ELSE $13::bigint
                  END,
                  updated_at_ms = $14
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [
            namespace,
            ctx.orgId,
            apiKeyId,
            request.name ?? null,
            request.scopes !== undefined ? JSON.stringify(request.scopes) : null,
            request.ipAllowlist !== undefined ? JSON.stringify(request.ipAllowlist) : null,
            request.allowedOrigins !== undefined ? JSON.stringify(request.allowedOrigins) : null,
            request.rateLimitBucket ?? null,
            request.quotaBucket ?? null,
            request.riskPolicy !== undefined ? JSON.stringify(request.riskPolicy) : null,
            request.paymentPolicy !== undefined ? JSON.stringify(request.paymentPolicy) : null,
            request.expiresAt === null,
            request.expiresAt ? Date.parse(request.expiresAt) : null,
            nowMs(now),
          ],
        );
        if (!row) return null;
        return toPublicApiKey(parseApiKeyRow(row));
      });
    },

    async authenticateApiKey(request): Promise<AuthenticateConsoleApiKeyResult> {
      const secret = String(request.secret || '').trim();
      if (!secret) {
        return {
          ok: false,
          status: 401,
          code: 'secret_key_missing',
          message: 'Missing secret key',
        };
      }

      const parsed = parseApiKeySecret(secret);
      if (!parsed) {
        return {
          ok: false,
          status: 401,
          code: 'secret_key_invalid',
          message: 'Invalid secret key',
        };
      }

      if (parsed.kind !== 'secret_key') {
        return {
          ok: false,
          status: 401,
          code: 'secret_key_invalid',
          message: 'Invalid secret key',
        };
      }

      const hashedSecret = await hashApiKeySecret(secret);
      const keyPrefix = makeApiKeyLookupPrefix(secret);
      const keyRow = await findApiKeyBySecretFingerprint({
        kind: parsed.kind,
        keyPrefix,
        secretHash: hashedSecret,
      });
      if (!keyRow) {
        return {
          ok: false,
          status: 401,
          code: 'secret_key_invalid',
          message: 'Invalid secret key',
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
          code: 'secret_key_revoked',
          message: 'Secret key has been revoked',
        };
      }

      if (keyRow.kind !== 'secret_key') {
        await appendAnomaly('auth.invalid_kind');
        return {
          ok: false,
          status: 401,
          code: 'secret_key_invalid',
          message: 'Invalid secret key',
        };
      }

      if (keyRow.expiresAt) {
        const expiresAtMs = Date.parse(keyRow.expiresAt);
        if (Number.isFinite(expiresAtMs) && expiresAtMs <= currentNowMs) {
          await appendAnomaly('auth.expired_attempt');
          return {
            ok: false,
            status: 403,
            code: 'secret_key_revoked',
            message: 'Secret key has expired',
          };
        }
      }

      const requestEnvironmentId = String(request.environmentId || '').trim();
      if (requestEnvironmentId && requestEnvironmentId !== keyRow.environmentId) {
        await appendAnomaly('auth.environment_mismatch');
        return {
          ok: false,
          status: 403,
          code: 'secret_key_environment_mismatch',
          message: 'Secret key is not valid for the requested environment',
        };
      }

      if (!hasRequiredScopes(keyRow.scopes || [], request.requiredScopes || [])) {
        await appendAnomaly('auth.scope_denied');
        return {
          ok: false,
          status: 403,
          code: 'secret_key_forbidden_scope',
          message: 'Secret key does not grant required scope',
        };
      }

      if (!isIpAllowlistMatch({ allowlist: keyRow.ipAllowlist || [], sourceIp: request.sourceIp })) {
        await appendAnomaly('auth.ip_blocked');
        return {
          ok: false,
          status: 403,
          code: 'secret_key_ip_blocked',
          message: 'Secret key is blocked for this source IP',
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

    async authenticatePublishableKey(request): Promise<AuthenticateConsolePublishableKeyResult> {
      const secret = String(request.secret || '').trim();
      if (!secret) {
        return {
          ok: false,
          status: 401,
          code: 'publishable_key_missing',
          message: 'Missing publishable key',
        };
      }

      const parsed = parseApiKeySecret(secret);
      if (!parsed || parsed.kind !== 'publishable_key') {
        return {
          ok: false,
          status: 401,
          code: 'publishable_key_invalid',
          message: 'Invalid publishable key',
        };
      }

      const hashedSecret = await hashApiKeySecret(secret);
      const keyPrefix = makeApiKeyLookupPrefix(secret);
      const keyRow = await findApiKeyBySecretFingerprint({
        kind: parsed.kind,
        keyPrefix,
        secretHash: hashedSecret,
      });
      if (!keyRow) {
        return {
          ok: false,
          status: 401,
          code: 'publishable_key_invalid',
          message: 'Invalid publishable key',
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
        await appendAnomaly('auth.publishable_key_revoked_attempt');
        return {
          ok: false,
          status: 403,
          code: 'publishable_key_revoked',
          message: 'Publishable key has been revoked',
        };
      }

      if (keyRow.kind !== 'publishable_key') {
        await appendAnomaly('auth.invalid_kind');
        return {
          ok: false,
          status: 401,
          code: 'publishable_key_invalid',
          message: 'Invalid publishable key',
        };
      }

      if (keyRow.expiresAt) {
        const expiresAtMs = Date.parse(keyRow.expiresAt);
        if (Number.isFinite(expiresAtMs) && expiresAtMs <= currentNowMs) {
          await appendAnomaly('auth.publishable_key_expired_attempt');
          return {
            ok: false,
            status: 403,
            code: 'publishable_key_revoked',
            message: 'Publishable key has expired',
          };
        }
      }

      const requestEnvironmentId = String(request.environmentId || '').trim();
      if (requestEnvironmentId && requestEnvironmentId !== keyRow.environmentId) {
        await appendAnomaly('auth.environment_mismatch');
        return {
          ok: false,
          status: 403,
          code: 'publishable_key_environment_mismatch',
          message: 'Publishable key is not valid for the requested environment',
        };
      }

      if (!isAllowedOrigin(keyRow, request.origin)) {
        await appendAnomaly('auth.origin_blocked');
        return {
          ok: false,
          status: 403,
          code: 'publishable_key_origin_blocked',
          message: buildPublishableKeyOriginBlockedMessage({
            origin: request.origin,
            allowedOrigins: keyRow.allowedOrigins || [],
          }),
        };
      }

      const refreshed = await withConsoleTenantContextTx(
        pool,
        { namespace, orgId: keyRow.orgId },
        async (q) => {
          const row = await queryOne(
            q,
            `UPDATE console_api_keys
                SET last_used_at_ms = $4,
                    updated_at_ms = $4
              WHERE namespace = $1 AND org_id = $2 AND id = $3
              RETURNING *`,
            [namespace, keyRow.orgId, keyRow.id, currentNowMs],
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
