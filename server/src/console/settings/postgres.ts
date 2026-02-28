import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import {
  ensureConsoleNamespace as ensureNamespace,
  toConsoleIso as toIso,
  toConsoleNumber as toNumber,
} from '../shared/postgresNormalize';
import type {
  ConsoleAppSettings,
  ConsoleSecuritySettings,
  GetConsoleSettingsRequest,
  UpdateConsoleAppSettingsRequest,
  UpdateConsoleSecuritySettingsRequest,
} from './types';
import type { ConsoleSettingsContext, ConsoleSettingsService } from './service';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_SETTINGS_MIGRATION_LOCK_ID = 9452360123593;

interface StoredSettingsRow {
  appSettings: ConsoleAppSettings;
  securitySettings: ConsoleSecuritySettings;
}

function nowMs(now: Date): number {
  return now.getTime();
}

function parseJsonObject(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
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
}

function parseStringArray(raw: unknown): string[] {
  const source = Array.isArray(raw) ? raw : [];
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

function normalizeStringList(input: string[] | undefined): string[] | undefined {
  if (!Array.isArray(input)) return undefined;
  return parseStringArray(input);
}

function cloneAppSettings(input: ConsoleAppSettings): ConsoleAppSettings {
  return {
    ...input,
    allowedOrigins: [...input.allowedOrigins],
    allowedDomains: [...input.allowedDomains],
    cookie: { ...input.cookie },
    jwt: {
      ...input.jwt,
      audience: [...input.jwt.audience],
      keyIds: [...input.jwt.keyIds],
    },
  };
}

function cloneSecuritySettings(input: ConsoleSecuritySettings): ConsoleSecuritySettings {
  return {
    ...input,
    ipAllowlist: [...input.ipAllowlist],
    riskyChangeApproval: { ...input.riskyChangeApproval },
  };
}

function defaultSettings(input: {
  orgId: string;
  environmentId: string;
  actorUserId: string;
  now: Date;
}): StoredSettingsRow {
  const iso = input.now.toISOString();
  return {
    appSettings: {
      orgId: input.orgId,
      environmentId: input.environmentId,
      allowedOrigins: [],
      allowedDomains: [],
      cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'LAX',
        domain: null,
        path: '/',
        maxAgeSeconds: 86_400,
      },
      jwt: {
        issuer: `https://console.local/${input.orgId}/${input.environmentId}`,
        audience: [],
        keyIds: [],
        accessTokenTtlSeconds: 900,
        refreshTokenTtlSeconds: 2_592_000,
      },
      ssoMetadataUrl: null,
      updatedAt: iso,
      updatedBy: input.actorUserId,
    },
    securitySettings: {
      orgId: input.orgId,
      environmentId: input.environmentId,
      ipAllowlist: [],
      enforceIpAllowlist: false,
      requireMfaForRiskyChanges: true,
      riskyChangeApproval: {
        approvalsRequired: 1,
        requireAdmin: true,
        requireMfa: true,
      },
      updatedAt: iso,
      updatedBy: input.actorUserId,
    },
  };
}

function parseAppSettings(
  raw: unknown,
  fallback: {
    orgId: string;
    environmentId: string;
    updatedAt: string;
    updatedBy: string;
  },
): ConsoleAppSettings {
  const row = parseJsonObject(raw);
  const cookie = parseJsonObject(row.cookie);
  const jwt = parseJsonObject(row.jwt);
  return {
    orgId: String(row.orgId || fallback.orgId).trim() || fallback.orgId,
    environmentId: String(row.environmentId || fallback.environmentId).trim() || fallback.environmentId,
    allowedOrigins: parseStringArray(row.allowedOrigins),
    allowedDomains: parseStringArray(row.allowedDomains),
    cookie: {
      httpOnly: cookie.httpOnly !== false,
      secure: cookie.secure !== false,
      sameSite: String(cookie.sameSite || 'LAX')
        .trim()
        .toUpperCase() as ConsoleAppSettings['cookie']['sameSite'],
      domain: cookie.domain == null ? null : String(cookie.domain || '').trim() || null,
      path: String(cookie.path || '/').trim() || '/',
      maxAgeSeconds: Math.max(1, Math.floor(toNumber(cookie.maxAgeSeconds, 86_400))),
    },
    jwt: {
      issuer:
        String(jwt.issuer || '').trim() ||
        `https://console.local/${fallback.orgId}/${fallback.environmentId}`,
      audience: parseStringArray(jwt.audience),
      keyIds: parseStringArray(jwt.keyIds),
      accessTokenTtlSeconds: Math.max(1, Math.floor(toNumber(jwt.accessTokenTtlSeconds, 900))),
      refreshTokenTtlSeconds: Math.max(1, Math.floor(toNumber(jwt.refreshTokenTtlSeconds, 2_592_000))),
    },
    ssoMetadataUrl: row.ssoMetadataUrl == null ? null : String(row.ssoMetadataUrl || '').trim() || null,
    updatedAt: String(row.updatedAt || fallback.updatedAt).trim() || fallback.updatedAt,
    updatedBy: String(row.updatedBy || fallback.updatedBy).trim() || fallback.updatedBy,
  };
}

function parseSecuritySettings(
  raw: unknown,
  fallback: {
    orgId: string;
    environmentId: string;
    updatedAt: string;
    updatedBy: string;
  },
): ConsoleSecuritySettings {
  const row = parseJsonObject(raw);
  const approval = parseJsonObject(row.riskyChangeApproval);
  return {
    orgId: String(row.orgId || fallback.orgId).trim() || fallback.orgId,
    environmentId: String(row.environmentId || fallback.environmentId).trim() || fallback.environmentId,
    ipAllowlist: parseStringArray(row.ipAllowlist),
    enforceIpAllowlist: row.enforceIpAllowlist === true,
    requireMfaForRiskyChanges: row.requireMfaForRiskyChanges !== false,
    riskyChangeApproval: {
      approvalsRequired: Math.max(1, Math.floor(toNumber(approval.approvalsRequired, 1))),
      requireAdmin: approval.requireAdmin !== false,
      requireMfa: approval.requireMfa !== false,
    },
    updatedAt: String(row.updatedAt || fallback.updatedAt).trim() || fallback.updatedAt,
    updatedBy: String(row.updatedBy || fallback.updatedBy).trim() || fallback.updatedBy,
  };
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

async function withTx<T>(pool: PgPool, fn: (q: Queryable) => Promise<T>): Promise<T> {
  await pool.query('BEGIN');
  try {
    const result = await fn(pool);
    await pool.query('COMMIT');
    return result;
  } catch (error: unknown) {
    try {
      await pool.query('ROLLBACK');
    } catch {
      // no-op
    }
    throw error;
  }
}

export interface PostgresConsoleSettingsSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleSettingsPostgresSchema(
  options: PostgresConsoleSettingsSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_SETTINGS_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_environment_settings (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        app_settings JSONB NOT NULL,
        security_settings JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, environment_id),
        CHECK (jsonb_typeof(app_settings) = 'object'),
        CHECK (jsonb_typeof(security_settings) = 'object')
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_environment_settings_org_updated_idx
      ON console_environment_settings (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
    `);
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_SETTINGS_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }

  options.logger.info('[console-settings][postgres] Schema ready');
}

export interface PostgresConsoleSettingsServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleSettingsService(
  options: PostgresConsoleSettingsServiceOptions,
): Promise<ConsoleSettingsService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console settings service');
  }

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());

  if (options.ensureSchema !== false) {
    await ensureConsoleSettingsPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);

  async function readSettings(
    q: Queryable,
    input: { orgId: string; environmentId: string; fallbackUpdatedBy: string },
  ): Promise<StoredSettingsRow> {
    const defaultRow = defaultSettings({
      orgId: input.orgId,
      environmentId: input.environmentId,
      actorUserId: input.fallbackUpdatedBy,
      now: nowFn(),
    });
    const row = await queryOne(
      q,
      `SELECT *
         FROM console_environment_settings
        WHERE namespace = $1 AND org_id = $2 AND environment_id = $3`,
      [namespace, input.orgId, input.environmentId],
    );
    if (!row) return defaultRow;

    const updatedAt =
      toIso(toNumber(row.updated_at_ms, nowMs(nowFn()))) || defaultRow.appSettings.updatedAt;
    const fallback = {
      orgId: input.orgId,
      environmentId: input.environmentId,
      updatedAt,
      updatedBy: input.fallbackUpdatedBy,
    };
    return {
      appSettings: parseAppSettings(row.app_settings, fallback),
      securitySettings: parseSecuritySettings(row.security_settings, fallback),
    };
  }

  async function ensureSettingsRow(
    q: Queryable,
    input: { orgId: string; environmentId: string; actorUserId: string },
  ): Promise<StoredSettingsRow> {
    const defaults = defaultSettings({
      orgId: input.orgId,
      environmentId: input.environmentId,
      actorUserId: input.actorUserId,
      now: nowFn(),
    });
    const createdAtMs = nowMs(new Date(defaults.appSettings.updatedAt));

    await q.query(
      `INSERT INTO console_environment_settings
        (namespace, org_id, environment_id, app_settings, security_settings, created_at_ms, updated_at_ms)
       VALUES
        ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $6)
       ON CONFLICT (namespace, org_id, environment_id) DO NOTHING`,
      [
        namespace,
        input.orgId,
        input.environmentId,
        JSON.stringify(defaults.appSettings),
        JSON.stringify(defaults.securitySettings),
        createdAtMs,
      ],
    );

    return readSettings(q, {
      orgId: input.orgId,
      environmentId: input.environmentId,
      fallbackUpdatedBy: input.actorUserId,
    });
  }

  return {
    async getAppSettings(ctx: ConsoleSettingsContext, request: GetConsoleSettingsRequest) {
      const row = await ensureSettingsRow(pool, {
        orgId: ctx.orgId,
        environmentId: request.environmentId,
        actorUserId: ctx.actorUserId,
      });
      return cloneAppSettings(row.appSettings);
    },

    async updateAppSettings(ctx: ConsoleSettingsContext, request: UpdateConsoleAppSettingsRequest) {
      return withTx(pool, async (tx) => {
        const row = await ensureSettingsRow(tx, {
          orgId: ctx.orgId,
          environmentId: request.environmentId,
          actorUserId: ctx.actorUserId,
        });
        const updatedAt = nowFn().toISOString();

        const appSettings: ConsoleAppSettings = {
          ...row.appSettings,
          ...(request.allowedOrigins !== undefined
            ? { allowedOrigins: normalizeStringList(request.allowedOrigins) || [] }
            : {}),
          ...(request.allowedDomains !== undefined
            ? { allowedDomains: normalizeStringList(request.allowedDomains) || [] }
            : {}),
          ...(request.cookie ? { cookie: { ...row.appSettings.cookie, ...request.cookie } } : {}),
          ...(request.jwt
            ? {
                jwt: {
                  ...row.appSettings.jwt,
                  ...request.jwt,
                  ...(request.jwt.audience !== undefined
                    ? { audience: normalizeStringList(request.jwt.audience) || [] }
                    : {}),
                  ...(request.jwt.keyIds !== undefined
                    ? { keyIds: normalizeStringList(request.jwt.keyIds) || [] }
                    : {}),
                },
              }
            : {}),
          ...(request.ssoMetadataUrl !== undefined ? { ssoMetadataUrl: request.ssoMetadataUrl } : {}),
          updatedAt,
          updatedBy: ctx.actorUserId,
        };

        const updatedAtMs = nowMs(new Date(updatedAt));
        await tx.query(
          `UPDATE console_environment_settings
              SET app_settings = $4::jsonb,
                  updated_at_ms = $5
            WHERE namespace = $1
              AND org_id = $2
              AND environment_id = $3`,
          [namespace, ctx.orgId, request.environmentId, JSON.stringify(appSettings), updatedAtMs],
        );

        return cloneAppSettings(appSettings);
      });
    },

    async getSecuritySettings(ctx: ConsoleSettingsContext, request: GetConsoleSettingsRequest) {
      const row = await ensureSettingsRow(pool, {
        orgId: ctx.orgId,
        environmentId: request.environmentId,
        actorUserId: ctx.actorUserId,
      });
      return cloneSecuritySettings(row.securitySettings);
    },

    async updateSecuritySettings(
      ctx: ConsoleSettingsContext,
      request: UpdateConsoleSecuritySettingsRequest,
    ) {
      return withTx(pool, async (tx) => {
        const row = await ensureSettingsRow(tx, {
          orgId: ctx.orgId,
          environmentId: request.environmentId,
          actorUserId: ctx.actorUserId,
        });
        const updatedAt = nowFn().toISOString();

        const securitySettings: ConsoleSecuritySettings = {
          ...row.securitySettings,
          ...(request.ipAllowlist !== undefined
            ? { ipAllowlist: normalizeStringList(request.ipAllowlist) || [] }
            : {}),
          ...(request.enforceIpAllowlist !== undefined
            ? { enforceIpAllowlist: request.enforceIpAllowlist }
            : {}),
          ...(request.requireMfaForRiskyChanges !== undefined
            ? { requireMfaForRiskyChanges: request.requireMfaForRiskyChanges }
            : {}),
          ...(request.riskyChangeApproval
            ? {
                riskyChangeApproval: {
                  ...row.securitySettings.riskyChangeApproval,
                  ...request.riskyChangeApproval,
                },
              }
            : {}),
          updatedAt,
          updatedBy: ctx.actorUserId,
        };

        const updatedAtMs = nowMs(new Date(updatedAt));
        await tx.query(
          `UPDATE console_environment_settings
              SET security_settings = $4::jsonb,
                  updated_at_ms = $5
            WHERE namespace = $1
              AND org_id = $2
              AND environment_id = $3`,
          [
            namespace,
            ctx.orgId,
            request.environmentId,
            JSON.stringify(securitySettings),
            updatedAtMs,
          ],
        );

        return cloneSecuritySettings(securitySettings);
      });
    },
  };
}
