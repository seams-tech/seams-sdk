import type { NormalizedLogger } from './logger';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import { formatD1ExecStatement } from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';

export type RecoveryExecutionStatus =
  | 'pending'
  | 'submitted'
  | 'confirmed'
  | 'failed'
  | 'skipped';

export type RecoveryExecutionRecord = {
  version: 'recovery_execution_v1';
  sessionId: string;
  userId: string;
  nearAccountId: string;
  chainIdKey: string;
  accountAddress: string;
  action: string;
  status: RecoveryExecutionStatus;
  createdAtMs: number;
  updatedAtMs: number;
  transactionHash?: string;
  errorCode?: string;
  errorMessage?: string;
  metadata?: Record<string, unknown>;
};

export interface RecoveryExecutionStore {
  get(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
  }): Promise<RecoveryExecutionRecord | null>;
  put(record: RecoveryExecutionRecord): Promise<void>;
  listBySessionId(sessionId: string): Promise<RecoveryExecutionRecord[]>;
  listByStatus(input: {
    status: RecoveryExecutionStatus;
    action?: string;
    updatedBeforeMs?: number;
    limit?: number;
  }): Promise<RecoveryExecutionRecord[]>;
}

export interface D1RecoveryExecutionStoreSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1RecoveryExecutionStoreOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema?: boolean;
}

type NormalizedD1RecoveryExecutionStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema: boolean;
};

type D1RecoveryExecutionScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

type D1RecoveryExecutionRow = {
  readonly record_json?: unknown;
};

export const RECOVERY_EXECUTION_STORE_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS signer_recovery_executions (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      chain_id_key TEXT NOT NULL,
      account_address TEXT NOT NULL,
      action TEXT NOT NULL,
      status TEXT NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        chain_id_key,
        account_address,
        action
      ),
      CHECK (length(session_id) > 0),
      CHECK (length(chain_id_key) > 0),
      CHECK (length(account_address) > 0),
      CHECK (length(action) > 0),
      CHECK (status IN ('pending', 'submitted', 'confirmed', 'failed', 'skipped')),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms > 0)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS signer_recovery_executions_session_idx
      ON signer_recovery_executions (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        chain_id_key,
        account_address,
        action
      )
  `,
  `
    CREATE INDEX IF NOT EXISTS signer_recovery_executions_status_idx
      ON signer_recovery_executions (
        namespace,
        org_id,
        project_id,
        env_id,
        status,
        action,
        updated_at_ms
      )
  `,
] as const);

export async function ensureRecoveryExecutionStoreD1Schema(
  options: D1RecoveryExecutionStoreSchemaOptions,
): Promise<void> {
  for (const statement of RECOVERY_EXECUTION_STORE_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function normalizeAccountAddress(value: string): string {
  return value.startsWith('0x') ? value.toLowerCase() : value;
}

function normalizeRecoveryExecutionStatus(value: unknown): RecoveryExecutionStatus | null {
  const normalized = toOptionalTrimmedString(value);
  if (
    normalized === 'pending' ||
    normalized === 'submitted' ||
    normalized === 'confirmed' ||
    normalized === 'failed' ||
    normalized === 'skipped'
  ) {
    return normalized;
  }
  return null;
}

function parseMetadata(raw: unknown): Record<string, unknown> | undefined {
  if (!isObject(raw)) return undefined;
  return { ...raw };
}

function parseRecoveryExecutionRecord(raw: unknown): RecoveryExecutionRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  const sessionId = toOptionalTrimmedString(raw.sessionId);
  const userId = toOptionalTrimmedString(raw.userId);
  const nearAccountId = toOptionalTrimmedString(raw.nearAccountId);
  const chainIdKey = toOptionalTrimmedString(raw.chainIdKey)?.toLowerCase() || '';
  const accountAddress = normalizeAccountAddress(
    toOptionalTrimmedString(raw.accountAddress) || '',
  );
  const action = toOptionalTrimmedString(raw.action);
  const status = normalizeRecoveryExecutionStatus((raw as { status?: unknown }).status);
  const createdAtMsRaw = (raw as { createdAtMs?: unknown }).createdAtMs;
  const updatedAtMsRaw = (raw as { updatedAtMs?: unknown }).updatedAtMs;
  const createdAtMs = typeof createdAtMsRaw === 'number' ? createdAtMsRaw : Number(createdAtMsRaw);
  const updatedAtMs = typeof updatedAtMsRaw === 'number' ? updatedAtMsRaw : Number(updatedAtMsRaw);
  const transactionHash = toOptionalTrimmedString((raw as { transactionHash?: unknown }).transactionHash);
  const errorCode = toOptionalTrimmedString((raw as { errorCode?: unknown }).errorCode);
  const errorMessage = toOptionalTrimmedString((raw as { errorMessage?: unknown }).errorMessage);
  const metadata = parseMetadata((raw as { metadata?: unknown }).metadata);

  if (version !== 'recovery_execution_v1') return null;
  if (!sessionId || !userId || !nearAccountId || !chainIdKey || !accountAddress || !action || !status) {
    return null;
  }
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;

  return {
    version: 'recovery_execution_v1',
    sessionId,
    userId,
    nearAccountId,
    chainIdKey,
    accountAddress,
    action,
    status,
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
    ...(transactionHash ? { transactionHash } : {}),
    ...(errorCode ? { errorCode } : {}),
    ...(errorMessage ? { errorMessage } : {}),
    ...(metadata ? { metadata } : {}),
  };
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
  if (!normalized) throw new Error(`${field} is required for D1 recovery execution store`);
  return normalized;
}

function normalizeD1RecoveryExecutionStoreOptions(
  input: D1RecoveryExecutionStoreOptions,
): NormalizedD1RecoveryExecutionStoreOptions {
  return {
    database: input.database,
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.orgId, 'orgId'),
    projectId: requireD1ScopeString(input.projectId, 'projectId'),
    envId: requireD1ScopeString(input.envId, 'envId'),
    ensureSchema: input.ensureSchema !== false,
  };
}

function d1ScopeFromConfig(input: {
  readonly config: Record<string, unknown>;
  readonly namespace: string;
}): Omit<D1RecoveryExecutionStoreOptions, 'database'> {
  return {
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.config.orgId || input.config.ORG_ID, 'orgId'),
    projectId: requireD1ScopeString(input.config.projectId || input.config.PROJECT_ID, 'projectId'),
    envId: requireD1ScopeString(input.config.envId || input.config.ENV_ID, 'envId'),
  };
}

class InMemoryRecoveryExecutionStore implements RecoveryExecutionStore {
  private readonly map = new Map<string, RecoveryExecutionRecord>();

  private key(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
  }): string {
    return `${input.sessionId}::${input.chainIdKey}::${input.accountAddress}::${input.action}`;
  }

  async get(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
  }): Promise<RecoveryExecutionRecord | null> {
    const sessionId = toOptionalTrimmedString(input.sessionId);
    const chainIdKey = toOptionalTrimmedString(input.chainIdKey)?.toLowerCase() || '';
    const accountAddress = normalizeAccountAddress(
      toOptionalTrimmedString(input.accountAddress) || '',
    );
    const action = toOptionalTrimmedString(input.action);
    if (!sessionId || !chainIdKey || !accountAddress || !action) return null;
    return parseRecoveryExecutionRecord(
      this.map.get(this.key({ sessionId, chainIdKey, accountAddress, action })),
    );
  }

  async put(record: RecoveryExecutionRecord): Promise<void> {
    const parsed = parseRecoveryExecutionRecord(record);
    if (!parsed) throw new Error('Invalid recovery execution record');
    this.map.set(this.key(parsed), parsed);
  }

  async listBySessionId(sessionId: string): Promise<RecoveryExecutionRecord[]> {
    const normalized = toOptionalTrimmedString(sessionId);
    if (!normalized) return [];
    const out: RecoveryExecutionRecord[] = [];
    for (const value of this.map.values()) {
      const parsed = parseRecoveryExecutionRecord(value);
      if (!parsed || parsed.sessionId !== normalized) continue;
      out.push(parsed);
    }
    out.sort((a, b) =>
      `${a.chainIdKey}:${a.accountAddress}:${a.action}`.localeCompare(
        `${b.chainIdKey}:${b.accountAddress}:${b.action}`,
      ),
    );
    return out;
  }

  async listByStatus(input: {
    status: RecoveryExecutionStatus;
    action?: string;
    updatedBeforeMs?: number;
    limit?: number;
  }): Promise<RecoveryExecutionRecord[]> {
    const status = normalizeRecoveryExecutionStatus(input.status);
    if (!status) return [];
    const action = toOptionalTrimmedString(input.action);
    const updatedBeforeMsRaw = Number(input.updatedBeforeMs);
    const updatedBeforeMs =
      Number.isFinite(updatedBeforeMsRaw) && updatedBeforeMsRaw > 0
        ? Math.floor(updatedBeforeMsRaw)
        : null;
    const limitRaw = Number(input.limit);
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : null;
    const out: RecoveryExecutionRecord[] = [];
    for (const value of this.map.values()) {
      const parsed = parseRecoveryExecutionRecord(value);
      if (!parsed || parsed.status !== status) continue;
      if (action && parsed.action !== action) continue;
      if (updatedBeforeMs !== null && parsed.updatedAtMs > updatedBeforeMs) continue;
      out.push(parsed);
    }
    out.sort((a, b) => {
      if (a.updatedAtMs !== b.updatedAtMs) return a.updatedAtMs - b.updatedAtMs;
      if (a.createdAtMs !== b.createdAtMs) return a.createdAtMs - b.createdAtMs;
      return `${a.sessionId}:${a.chainIdKey}:${a.accountAddress}:${a.action}`.localeCompare(
        `${b.sessionId}:${b.chainIdKey}:${b.accountAddress}:${b.action}`,
      );
    });
    return limit ? out.slice(0, limit) : out;
  }
}

export class D1RecoveryExecutionStore implements RecoveryExecutionStore {
  readonly adapterKind = 'd1';
  private readonly database: D1DatabaseLike;
  private readonly scope: D1RecoveryExecutionScope;
  private readonly ensureSchemaOnUse: boolean;
  private schemaReady = false;

  constructor(input: D1RecoveryExecutionStoreOptions) {
    const normalized = normalizeD1RecoveryExecutionStoreOptions(input);
    this.database = normalized.database;
    this.scope = {
      namespace: normalized.namespace,
      orgId: normalized.orgId,
      projectId: normalized.projectId,
      envId: normalized.envId,
    };
    this.ensureSchemaOnUse = normalized.ensureSchema;
  }

  private async ensureSchema(): Promise<void> {
    if (!this.ensureSchemaOnUse || this.schemaReady) return;
    await ensureRecoveryExecutionStoreD1Schema({ database: this.database });
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

  async get(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
  }): Promise<RecoveryExecutionRecord | null> {
    await this.ensureSchema();
    const sessionId = toOptionalTrimmedString(input.sessionId);
    const chainIdKey = toOptionalTrimmedString(input.chainIdKey)?.toLowerCase() || '';
    const accountAddress = normalizeAccountAddress(
      toOptionalTrimmedString(input.accountAddress) || '',
    );
    const action = toOptionalTrimmedString(input.action);
    if (!sessionId || !chainIdKey || !accountAddress || !action) return null;
    const row = await this.bindScope(
      `SELECT record_json
         FROM signer_recovery_executions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND session_id = ?
          AND chain_id_key = ?
          AND account_address = ?
          AND action = ?
        LIMIT 1`,
      [sessionId, chainIdKey, accountAddress, action],
    ).first<D1RecoveryExecutionRow>();
    return parseRecoveryExecutionRecord(parseD1RecordJson(row?.record_json));
  }

  async put(record: RecoveryExecutionRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseRecoveryExecutionRecord(record);
    if (!parsed) throw new Error('Invalid recovery execution record');
    await this.bindScope(
      `INSERT INTO signer_recovery_executions (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        chain_id_key,
        account_address,
        action,
        status,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        chain_id_key,
        account_address,
        action
      )
      DO UPDATE SET
        status = EXCLUDED.status,
        record_json = EXCLUDED.record_json,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        parsed.sessionId,
        parsed.chainIdKey,
        parsed.accountAddress,
        parsed.action,
        parsed.status,
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.updatedAtMs,
      ],
    ).run();
  }

  async listBySessionId(sessionId: string): Promise<RecoveryExecutionRecord[]> {
    await this.ensureSchema();
    const normalized = toOptionalTrimmedString(sessionId);
    if (!normalized) return [];
    const result = await this.bindScope(
      `SELECT record_json
         FROM signer_recovery_executions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND session_id = ?
        ORDER BY chain_id_key ASC, account_address ASC, action ASC`,
      [normalized],
    ).all<D1RecoveryExecutionRow>();
    return (result.results || [])
      .map((row) => parseRecoveryExecutionRecord(parseD1RecordJson(row.record_json)))
      .filter((record): record is RecoveryExecutionRecord => Boolean(record));
  }

  async listByStatus(input: {
    status: RecoveryExecutionStatus;
    action?: string;
    updatedBeforeMs?: number;
    limit?: number;
  }): Promise<RecoveryExecutionRecord[]> {
    await this.ensureSchema();
    const status = normalizeRecoveryExecutionStatus(input.status);
    if (!status) return [];
    const action = toOptionalTrimmedString(input.action);
    const updatedBeforeMsRaw = Number(input.updatedBeforeMs);
    const updatedBeforeMs =
      Number.isFinite(updatedBeforeMsRaw) && updatedBeforeMsRaw > 0
        ? Math.floor(updatedBeforeMsRaw)
        : null;
    const limitRaw = Number(input.limit);
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : 100;
    const result = await this.bindScope(
      `SELECT record_json
         FROM signer_recovery_executions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND status = ?
          AND (? = '' OR action = ?)
          AND (? IS NULL OR updated_at_ms <= ?)
        ORDER BY updated_at_ms ASC, created_at_ms ASC, session_id ASC, chain_id_key ASC, account_address ASC, action ASC
        LIMIT ?`,
      [status, action || '', action || '', updatedBeforeMs, updatedBeforeMs, limit],
    ).all<D1RecoveryExecutionRow>();
    return (result.results || [])
      .map((row) => parseRecoveryExecutionRecord(parseD1RecordJson(row.record_json)))
      .filter((record): record is RecoveryExecutionRecord => Boolean(record));
  }
}

class PostgresRecoveryExecutionStore implements RecoveryExecutionStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async get(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
  }): Promise<RecoveryExecutionRecord | null> {
    const sessionId = toOptionalTrimmedString(input.sessionId);
    const chainIdKey = toOptionalTrimmedString(input.chainIdKey)?.toLowerCase() || '';
    const accountAddress = normalizeAccountAddress(
      toOptionalTrimmedString(input.accountAddress) || '',
    );
    const action = toOptionalTrimmedString(input.action);
    if (!sessionId || !chainIdKey || !accountAddress || !action) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM recovery_executions
        WHERE namespace = $1
          AND session_id = $2
          AND chain_id_key = $3
          AND account_address = $4
          AND action = $5
      `,
      [this.namespace, sessionId, chainIdKey, accountAddress, action],
    );
    return parseRecoveryExecutionRecord((rows[0] as { record_json?: unknown } | undefined)?.record_json);
  }

  async put(record: RecoveryExecutionRecord): Promise<void> {
    const parsed = parseRecoveryExecutionRecord(record);
    if (!parsed) throw new Error('Invalid recovery execution record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO recovery_executions (
          namespace,
          session_id,
          chain_id_key,
          account_address,
          action,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (namespace, session_id, chain_id_key, account_address, action)
        DO UPDATE SET
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        this.namespace,
        parsed.sessionId,
        parsed.chainIdKey,
        parsed.accountAddress,
        parsed.action,
        parsed,
        parsed.createdAtMs,
        parsed.updatedAtMs,
      ],
    );
  }

  async listBySessionId(sessionId: string): Promise<RecoveryExecutionRecord[]> {
    const normalized = toOptionalTrimmedString(sessionId);
    if (!normalized) return [];
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM recovery_executions
        WHERE namespace = $1 AND session_id = $2
        ORDER BY chain_id_key ASC, account_address ASC, action ASC
      `,
      [this.namespace, normalized],
    );
    return rows
      .map((row) => parseRecoveryExecutionRecord((row as { record_json?: unknown }).record_json))
      .filter(Boolean) as RecoveryExecutionRecord[];
  }

  async listByStatus(input: {
    status: RecoveryExecutionStatus;
    action?: string;
    updatedBeforeMs?: number;
    limit?: number;
  }): Promise<RecoveryExecutionRecord[]> {
    const status = normalizeRecoveryExecutionStatus(input.status);
    if (!status) return [];
    const action = toOptionalTrimmedString(input.action);
    const updatedBeforeMsRaw = Number(input.updatedBeforeMs);
    const updatedBeforeMs =
      Number.isFinite(updatedBeforeMsRaw) && updatedBeforeMsRaw > 0
        ? Math.floor(updatedBeforeMsRaw)
        : null;
    const limitRaw = Number(input.limit);
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM recovery_executions
        WHERE namespace = $1
          AND record_json->>'status' = $2
          AND ($3::text = '' OR action = $3)
          AND ($4::bigint IS NULL OR updated_at_ms <= $4)
        ORDER BY updated_at_ms ASC, created_at_ms ASC, session_id ASC, chain_id_key ASC, account_address ASC, action ASC
        LIMIT $5
      `,
      [this.namespace, status, action || '', updatedBeforeMs, limit ?? 100],
    );
    return rows
      .map((row) => parseRecoveryExecutionRecord((row as { record_json?: unknown }).record_json))
      .filter(Boolean) as RecoveryExecutionRecord[];
  }
}

export function createRecoveryExecutionStore(input: {
  config?: Record<string, unknown> | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): RecoveryExecutionStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const postgresUrl = getPostgresUrlFromConfig(config);
  const namespace =
    toOptionalTrimmedString(config.RECOVERY_EXECUTION_NAMESPACE) ||
    toOptionalTrimmedString(config.THRESHOLD_PREFIX) ||
    '';
  const kind = toOptionalTrimmedString(config.kind);

  if (kind === 'd1') {
    const database = resolveD1DatabaseFromConfig(config);
    if (!database) {
      throw new Error(
        '[recovery-executions] D1 store selected but no D1 database was provided',
      );
    }
    input.logger.info('[recovery-executions] Using D1 store for recovery execution state');
    return new D1RecoveryExecutionStore({
      database,
      ...d1ScopeFromConfig({ config, namespace }),
    });
  }

  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[recovery-executions] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info('[recovery-executions] Using Postgres store for recovery execution state');
    return new PostgresRecoveryExecutionStore({ postgresUrl, namespace });
  }

  input.logger.info('[recovery-executions] Using in-memory store for recovery execution state');
  return new InMemoryRecoveryExecutionStore();
}
