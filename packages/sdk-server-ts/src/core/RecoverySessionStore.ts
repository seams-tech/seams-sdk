import type { NormalizedLogger } from './logger';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import { formatD1ExecStatement } from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';

export type RecoverySessionStatus =
  | 'prepared'
  | 'verified'
  | 'near_recovered'
  | 'evm_recovering'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type RecoverySessionRecord = {
  version: 'recovery_session_v1';
  sessionId: string;
  userId: string;
  nearAccountId: string;
  signerSlot: number;
  status: RecoverySessionStatus;
  createdAtMs: number;
  updatedAtMs: number;
  expiresAtMs: number;
  newNearPublicKey: string;
  newEvmOwnerAddress: string;
  recoveryDeadlineEpochSeconds: number;
  recoveryEmailPayloadHash: string;
  verifiedRecoveryPayloadHash?: string;
  verifiedRecoveryArtifactHash?: string;
  scope?: string;
  metadata?: Record<string, unknown>;
};

export interface RecoverySessionStore {
  get(sessionId: string): Promise<RecoverySessionRecord | null>;
  put(record: RecoverySessionRecord): Promise<void>;
  listByNearAccountId(nearAccountId: string): Promise<RecoverySessionRecord[]>;
}

export interface D1RecoverySessionStoreSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1RecoverySessionStoreOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

type NormalizedD1RecoverySessionStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema: boolean;
  readonly now: () => Date;
};

type D1RecoverySessionScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

type D1RecoverySessionRow = {
  readonly record_json?: unknown;
};

export const RECOVERY_SESSION_STORE_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS signer_recovery_sessions (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      near_account_id TEXT NOT NULL,
      record_json TEXT NOT NULL,
      expires_at_ms INTEGER NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, session_id),
      CHECK (length(session_id) > 0),
      CHECK (length(near_account_id) > 0),
      CHECK (json_valid(record_json)),
      CHECK (expires_at_ms > 0),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms > 0)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS signer_recovery_sessions_near_account_idx
      ON signer_recovery_sessions (
        namespace,
        org_id,
        project_id,
        env_id,
        near_account_id,
        updated_at_ms DESC
      )
  `,
  `
    CREATE INDEX IF NOT EXISTS signer_recovery_sessions_expiry_idx
      ON signer_recovery_sessions (
        namespace,
        org_id,
        project_id,
        env_id,
        expires_at_ms
      )
  `,
] as const);

export async function ensureRecoverySessionStoreD1Schema(
  options: D1RecoverySessionStoreSchemaOptions,
): Promise<void> {
  for (const statement of RECOVERY_SESSION_STORE_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function normalizeHexLike(value: string): string {
  return value.startsWith('0x') ? value.toLowerCase() : value;
}

function normalizeRecoverySessionStatus(value: unknown): RecoverySessionStatus | null {
  const normalized = toOptionalTrimmedString(value);
  if (
    normalized === 'prepared' ||
    normalized === 'verified' ||
    normalized === 'near_recovered' ||
    normalized === 'evm_recovering' ||
    normalized === 'completed' ||
    normalized === 'failed' ||
    normalized === 'cancelled'
  ) {
    return normalized;
  }
  return null;
}

function parseMetadata(raw: unknown): Record<string, unknown> | undefined {
  if (!isObject(raw)) return undefined;
  return { ...raw };
}

function parseRecoverySessionRecord(raw: unknown): RecoverySessionRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  const sessionId = toOptionalTrimmedString(raw.sessionId);
  const userId = toOptionalTrimmedString(raw.userId);
  const nearAccountId = toOptionalTrimmedString(raw.nearAccountId);
  const status = normalizeRecoverySessionStatus((raw as { status?: unknown }).status);
  const signerSlotRaw = (raw as { signerSlot?: unknown }).signerSlot;
  const signerSlot =
    typeof signerSlotRaw === 'number' ? signerSlotRaw : Number(signerSlotRaw);
  const createdAtMsRaw = (raw as { createdAtMs?: unknown }).createdAtMs;
  const updatedAtMsRaw = (raw as { updatedAtMs?: unknown }).updatedAtMs;
  const expiresAtMsRaw = (raw as { expiresAtMs?: unknown }).expiresAtMs;
  const createdAtMs = typeof createdAtMsRaw === 'number' ? createdAtMsRaw : Number(createdAtMsRaw);
  const updatedAtMs = typeof updatedAtMsRaw === 'number' ? updatedAtMsRaw : Number(updatedAtMsRaw);
  const expiresAtMs = typeof expiresAtMsRaw === 'number' ? expiresAtMsRaw : Number(expiresAtMsRaw);
  const newNearPublicKey = toOptionalTrimmedString((raw as { newNearPublicKey?: unknown }).newNearPublicKey);
  const newEvmOwnerAddress = normalizeHexLike(
    toOptionalTrimmedString((raw as { newEvmOwnerAddress?: unknown }).newEvmOwnerAddress) || '',
  );
  const recoveryDeadlineEpochSecondsRaw = (raw as { recoveryDeadlineEpochSeconds?: unknown })
    .recoveryDeadlineEpochSeconds;
  const recoveryDeadlineEpochSeconds =
    typeof recoveryDeadlineEpochSecondsRaw === 'number'
      ? recoveryDeadlineEpochSecondsRaw
      : Number(recoveryDeadlineEpochSecondsRaw);
  const recoveryEmailPayloadHash = toOptionalTrimmedString(
    (raw as { recoveryEmailPayloadHash?: unknown }).recoveryEmailPayloadHash,
  );
  const verifiedRecoveryPayloadHash = toOptionalTrimmedString(
    (raw as { verifiedRecoveryPayloadHash?: unknown }).verifiedRecoveryPayloadHash,
  );
  const verifiedRecoveryArtifactHash = toOptionalTrimmedString(
    (raw as { verifiedRecoveryArtifactHash?: unknown }).verifiedRecoveryArtifactHash,
  );
  const scope = toOptionalTrimmedString((raw as { scope?: unknown }).scope);
  const metadata = parseMetadata((raw as { metadata?: unknown }).metadata);

  if (version !== 'recovery_session_v1') return null;
  if (
    !sessionId ||
    !userId ||
    !nearAccountId ||
    !status ||
    !newNearPublicKey ||
    !newEvmOwnerAddress ||
    !recoveryEmailPayloadHash
  ) {
    return null;
  }
  if (!Number.isFinite(signerSlot) || signerSlot < 1) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;
  if (!Number.isFinite(recoveryDeadlineEpochSeconds) || recoveryDeadlineEpochSeconds <= 0) {
    return null;
  }

  return {
    version: 'recovery_session_v1',
    sessionId,
    userId,
    nearAccountId,
    signerSlot: Math.floor(signerSlot),
    status,
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
    newNearPublicKey,
    newEvmOwnerAddress,
    recoveryDeadlineEpochSeconds: Math.floor(recoveryDeadlineEpochSeconds),
    recoveryEmailPayloadHash,
    ...(verifiedRecoveryPayloadHash ? { verifiedRecoveryPayloadHash } : {}),
    ...(verifiedRecoveryArtifactHash ? { verifiedRecoveryArtifactHash } : {}),
    ...(scope ? { scope } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

function defaultNow(): Date {
  return new Date();
}

function parseD1RecordJson(raw: unknown): unknown {
  if (typeof raw !== 'string') return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function isD1DatabaseLike(value: unknown): value is D1DatabaseLike {
  return (
    isObject(value) &&
    typeof value.prepare === 'function' &&
    typeof value.batch === 'function' &&
    typeof value.exec === 'function'
  );
}

function resolveD1DatabaseFromConfig(config: Record<string, unknown>): D1DatabaseLike | null {
  if (isD1DatabaseLike(config.database)) return config.database;
  if (isD1DatabaseLike(config.metadataDatabase)) return config.metadataDatabase;
  if (isD1DatabaseLike(config.SIGNER_DB)) return config.SIGNER_DB;
  return null;
}

function requireD1ScopeString(input: unknown, field: string): string {
  const normalized = toOptionalTrimmedString(input);
  if (!normalized) throw new Error(`${field} is required for D1 recovery session store`);
  return normalized;
}

function normalizeD1RecoverySessionStoreOptions(
  input: D1RecoverySessionStoreOptions,
): NormalizedD1RecoverySessionStoreOptions {
  return {
    database: input.database,
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.orgId, 'orgId'),
    projectId: requireD1ScopeString(input.projectId, 'projectId'),
    envId: requireD1ScopeString(input.envId, 'envId'),
    ensureSchema: input.ensureSchema !== false,
    now: input.now || defaultNow,
  };
}

function d1ScopeFromConfig(input: {
  readonly config: Record<string, unknown>;
  readonly namespace: string;
}): Omit<D1RecoverySessionStoreOptions, 'database'> {
  return {
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.config.orgId || input.config.ORG_ID, 'orgId'),
    projectId: requireD1ScopeString(input.config.projectId || input.config.PROJECT_ID, 'projectId'),
    envId: requireD1ScopeString(input.config.envId || input.config.ENV_ID, 'envId'),
  };
}

class InMemoryRecoverySessionStore implements RecoverySessionStore {
  private readonly map = new Map<string, RecoverySessionRecord>();

  async get(sessionId: string): Promise<RecoverySessionRecord | null> {
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return null;
    const parsed = parseRecoverySessionRecord(this.map.get(id));
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async put(record: RecoverySessionRecord): Promise<void> {
    const parsed = parseRecoverySessionRecord(record);
    if (!parsed) throw new Error('Invalid recovery session record');
    this.map.set(parsed.sessionId, parsed);
  }

  async listByNearAccountId(nearAccountId: string): Promise<RecoverySessionRecord[]> {
    const accountId = toOptionalTrimmedString(nearAccountId);
    if (!accountId) return [];
    const out: RecoverySessionRecord[] = [];
    for (const value of this.map.values()) {
      const parsed = parseRecoverySessionRecord(value);
      if (!parsed || parsed.nearAccountId !== accountId) continue;
      out.push(parsed);
    }
    out.sort((a, b) => b.updatedAtMs - a.updatedAtMs);
    return out;
  }
}

export class D1RecoverySessionStore implements RecoverySessionStore {
  readonly adapterKind = 'd1';
  private readonly database: D1DatabaseLike;
  private readonly scope: D1RecoverySessionScope;
  private readonly ensureSchemaOnUse: boolean;
  private readonly now: () => Date;
  private schemaReady = false;

  constructor(input: D1RecoverySessionStoreOptions) {
    const normalized = normalizeD1RecoverySessionStoreOptions(input);
    this.database = normalized.database;
    this.scope = {
      namespace: normalized.namespace,
      orgId: normalized.orgId,
      projectId: normalized.projectId,
      envId: normalized.envId,
    };
    this.ensureSchemaOnUse = normalized.ensureSchema;
    this.now = normalized.now;
  }

  private async ensureSchema(): Promise<void> {
    if (!this.ensureSchemaOnUse || this.schemaReady) return;
    await ensureRecoverySessionStoreD1Schema({ database: this.database });
    this.schemaReady = true;
  }

  private bindScope(statement: string, values: readonly unknown[] = []) {
    return this.database
      .prepare(statement)
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        ...values,
      );
  }

  async get(sessionId: string): Promise<RecoverySessionRecord | null> {
    await this.ensureSchema();
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return null;
    const row = await this.bindScope(
      `SELECT record_json
         FROM signer_recovery_sessions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND session_id = ?
        LIMIT 1`,
      [id],
    ).first<D1RecoverySessionRow>();
    const parsed = parseRecoverySessionRecord(parseD1RecordJson(row?.record_json));
    if (!parsed) return null;
    if (this.now().getTime() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async put(record: RecoverySessionRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseRecoverySessionRecord(record);
    if (!parsed) throw new Error('Invalid recovery session record');
    await this.bindScope(
      `INSERT INTO signer_recovery_sessions (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        near_account_id,
        record_json,
        expires_at_ms,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, session_id)
      DO UPDATE SET
        near_account_id = EXCLUDED.near_account_id,
        record_json = EXCLUDED.record_json,
        expires_at_ms = EXCLUDED.expires_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        parsed.sessionId,
        parsed.nearAccountId,
        JSON.stringify(parsed),
        parsed.expiresAtMs,
        parsed.createdAtMs,
        parsed.updatedAtMs,
      ],
    ).run();
  }

  async listByNearAccountId(nearAccountId: string): Promise<RecoverySessionRecord[]> {
    await this.ensureSchema();
    const accountId = toOptionalTrimmedString(nearAccountId);
    if (!accountId) return [];
    const result = await this.bindScope(
      `SELECT record_json
         FROM signer_recovery_sessions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND near_account_id = ?
        ORDER BY updated_at_ms DESC`,
      [accountId],
    ).all<D1RecoverySessionRow>();
    return (result.results || [])
      .map((row) => parseRecoverySessionRecord(parseD1RecordJson(row.record_json)))
      .filter((record): record is RecoverySessionRecord => Boolean(record));
  }
}

class PostgresRecoverySessionStore implements RecoverySessionStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async get(sessionId: string): Promise<RecoverySessionRecord | null> {
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM recovery_sessions
        WHERE namespace = $1 AND session_id = $2
      `,
      [this.namespace, id],
    );
    const parsed = parseRecoverySessionRecord((rows[0] as { record_json?: unknown } | undefined)?.record_json);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async put(record: RecoverySessionRecord): Promise<void> {
    const parsed = parseRecoverySessionRecord(record);
    if (!parsed) throw new Error('Invalid recovery session record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO recovery_sessions (
          namespace,
          session_id,
          near_account_id,
          record_json,
          expires_at_ms,
          created_at_ms,
          updated_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (namespace, session_id)
        DO UPDATE SET
          near_account_id = EXCLUDED.near_account_id,
          record_json = EXCLUDED.record_json,
          expires_at_ms = EXCLUDED.expires_at_ms,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        this.namespace,
        parsed.sessionId,
        parsed.nearAccountId,
        parsed,
        parsed.expiresAtMs,
        parsed.createdAtMs,
        parsed.updatedAtMs,
      ],
    );
  }

  async listByNearAccountId(nearAccountId: string): Promise<RecoverySessionRecord[]> {
    const accountId = toOptionalTrimmedString(nearAccountId);
    if (!accountId) return [];
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM recovery_sessions
        WHERE namespace = $1 AND near_account_id = $2
        ORDER BY updated_at_ms DESC
      `,
      [this.namespace, accountId],
    );
    return rows
      .map((row) => parseRecoverySessionRecord((row as { record_json?: unknown }).record_json))
      .filter(Boolean) as RecoverySessionRecord[];
  }
}

export function createRecoverySessionStore(input: {
  config?: Record<string, unknown> | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): RecoverySessionStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const postgresUrl = getPostgresUrlFromConfig(config);
  const namespace =
    toOptionalTrimmedString(config.RECOVERY_SESSION_NAMESPACE) ||
    toOptionalTrimmedString(config.THRESHOLD_PREFIX) ||
    '';
  const kind = toOptionalTrimmedString(config.kind);

  if (kind === 'd1') {
    const database = resolveD1DatabaseFromConfig(config);
    if (!database) {
      throw new Error(
        '[recovery-sessions] D1 store selected but no D1 database was provided',
      );
    }
    input.logger.info('[recovery-sessions] Using D1 store for recovery sessions');
    return new D1RecoverySessionStore({
      database,
      ...d1ScopeFromConfig({ config, namespace }),
    });
  }

  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[recovery-sessions] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info('[recovery-sessions] Using Postgres store for recovery sessions');
    return new PostgresRecoverySessionStore({ postgresUrl, namespace });
  }

  input.logger.info('[recovery-sessions] Using in-memory store for recovery sessions');
  return new InMemoryRecoverySessionStore();
}
