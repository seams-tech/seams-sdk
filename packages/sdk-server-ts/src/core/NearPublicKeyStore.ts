import type { NormalizedLogger } from './logger';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import { formatD1ExecStatement } from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';

export type NearPublicKeyKind = 'threshold' | 'local' | 'backup' | 'ephemeral';

export type NearPublicKeyRecord = {
  version: 'near_public_key_v1';
  userId: string;
  publicKey: string;
  kind: NearPublicKeyKind;
  signerSlot?: number;
  credentialIdB64u?: string;
  rpId?: string;
  createdAtMs: number;
  updatedAtMs: number;
  addedTxHash?: string;
  removedAtMs?: number;
};

export interface NearPublicKeyStore {
  put(record: NearPublicKeyRecord): Promise<void>;
  listByUserId(userId: string): Promise<NearPublicKeyRecord[]>;
}

export interface D1NearPublicKeyStoreSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1NearPublicKeyStoreOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema?: boolean;
}

type NormalizedD1NearPublicKeyStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema: boolean;
};

type D1NearPublicKeyScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

type D1NearPublicKeyRow = {
  readonly record_json?: unknown;
};

export const NEAR_PUBLIC_KEY_STORE_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS signer_near_public_keys (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      public_key TEXT NOT NULL,
      kind TEXT NOT NULL,
      signer_slot INTEGER,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      removed_at_ms INTEGER,
      PRIMARY KEY (namespace, org_id, project_id, env_id, user_id, public_key),
      CHECK (length(user_id) > 0),
      CHECK (length(public_key) > 0),
      CHECK (kind IN ('threshold', 'local', 'backup', 'ephemeral')),
      CHECK (signer_slot IS NULL OR signer_slot >= 1),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms > 0),
      CHECK (removed_at_ms IS NULL OR removed_at_ms > 0)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS signer_near_public_keys_user_idx
      ON signer_near_public_keys (
        namespace,
        org_id,
        project_id,
        env_id,
        user_id,
        signer_slot,
        created_at_ms
      )
  `,
] as const);

export async function ensureNearPublicKeyStoreD1Schema(
  options: D1NearPublicKeyStoreSchemaOptions,
): Promise<void> {
  for (const statement of NEAR_PUBLIC_KEY_STORE_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function parseNearPublicKeyKind(input: unknown): NearPublicKeyKind | null {
  const k = toOptionalTrimmedString(input);
  if (k === 'threshold' || k === 'local' || k === 'backup' || k === 'ephemeral') return k;
  return null;
}

function parseNearPublicKeyRecord(raw: unknown): NearPublicKeyRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  if (version !== 'near_public_key_v1') return null;
  const userId = toOptionalTrimmedString(raw.userId);
  const publicKey = toOptionalTrimmedString(raw.publicKey);
  const kind = parseNearPublicKeyKind(raw.kind);
  const createdAtMsRaw = raw.createdAtMs;
  const updatedAtMsRaw = raw.updatedAtMs;
  const createdAtMs = typeof createdAtMsRaw === 'number' ? createdAtMsRaw : Number(createdAtMsRaw);
  const updatedAtMs = typeof updatedAtMsRaw === 'number' ? updatedAtMsRaw : Number(updatedAtMsRaw);

  if (!userId || !publicKey || !kind) return null;
  if (!publicKey.startsWith('ed25519:')) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;

  const signerSlotRaw = raw.signerSlot;
  const signerSlot =
    typeof signerSlotRaw === 'number' ? signerSlotRaw : Number(signerSlotRaw);
  const credentialIdB64u = toOptionalTrimmedString(raw.credentialIdB64u);
  const rpId = toOptionalTrimmedString(raw.rpId);
  const addedTxHash = toOptionalTrimmedString(raw.addedTxHash);
  const removedAtMsRaw = raw.removedAtMs;
  const removedAtMs = typeof removedAtMsRaw === 'number' ? removedAtMsRaw : Number(removedAtMsRaw);

  return {
    version: 'near_public_key_v1',
    userId,
    publicKey,
    kind,
    ...(Number.isFinite(signerSlot) && signerSlot >= 1
      ? { signerSlot: Math.floor(signerSlot) }
      : {}),
    ...(credentialIdB64u ? { credentialIdB64u } : {}),
    ...(rpId ? { rpId } : {}),
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
    ...(addedTxHash ? { addedTxHash } : {}),
    ...(Number.isFinite(removedAtMs) && removedAtMs > 0
      ? { removedAtMs: Math.floor(removedAtMs) }
      : {}),
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
  if (!normalized) throw new Error(`${field} is required for D1 NEAR public key store`);
  return normalized;
}

function normalizeD1NearPublicKeyStoreOptions(
  input: D1NearPublicKeyStoreOptions,
): NormalizedD1NearPublicKeyStoreOptions {
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
}): Omit<D1NearPublicKeyStoreOptions, 'database'> {
  return {
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.config.orgId || input.config.ORG_ID, 'orgId'),
    projectId: requireD1ScopeString(input.config.projectId || input.config.PROJECT_ID, 'projectId'),
    envId: requireD1ScopeString(input.config.envId || input.config.ENV_ID, 'envId'),
  };
}

class InMemoryNearPublicKeyStore implements NearPublicKeyStore {
  private readonly byUser = new Map<string, Map<string, NearPublicKeyRecord>>();

  async put(record: NearPublicKeyRecord): Promise<void> {
    const parsed = parseNearPublicKeyRecord(record);
    if (!parsed) throw new Error('Invalid near public key record');
    const key = parsed.userId;
    const bucket = this.byUser.get(key) || new Map<string, NearPublicKeyRecord>();
    bucket.set(parsed.publicKey, parsed);
    this.byUser.set(key, bucket);
  }

  async listByUserId(userId: string): Promise<NearPublicKeyRecord[]> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return [];
    const bucket = this.byUser.get(uid);
    if (!bucket) return [];
    const out = Array.from(bucket.values())
      .map((r) => parseNearPublicKeyRecord(r))
      .filter(Boolean) as NearPublicKeyRecord[];
    out.sort((a, b) => (a.signerSlot || 0) - (b.signerSlot || 0));
    return out;
  }
}

export class D1NearPublicKeyStore implements NearPublicKeyStore {
  readonly adapterKind = 'd1';
  private readonly database: D1DatabaseLike;
  private readonly scope: D1NearPublicKeyScope;
  private readonly ensureSchemaOnUse: boolean;
  private schemaReady = false;

  constructor(input: D1NearPublicKeyStoreOptions) {
    const normalized = normalizeD1NearPublicKeyStoreOptions(input);
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
    await ensureNearPublicKeyStoreD1Schema({ database: this.database });
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

  async put(record: NearPublicKeyRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseNearPublicKeyRecord(record);
    if (!parsed) throw new Error('Invalid near public key record');
    await this.bindScope(
      `INSERT INTO signer_near_public_keys (
        namespace,
        org_id,
        project_id,
        env_id,
        user_id,
        public_key,
        kind,
        signer_slot,
        record_json,
        created_at_ms,
        updated_at_ms,
        removed_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, user_id, public_key)
      DO UPDATE SET
        kind = EXCLUDED.kind,
        signer_slot = EXCLUDED.signer_slot,
        record_json = EXCLUDED.record_json,
        created_at_ms = MIN(signer_near_public_keys.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = MAX(signer_near_public_keys.updated_at_ms, EXCLUDED.updated_at_ms),
        removed_at_ms = EXCLUDED.removed_at_ms`,
      [
        parsed.userId,
        parsed.publicKey,
        parsed.kind,
        parsed.signerSlot ?? null,
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.updatedAtMs,
        parsed.removedAtMs ?? null,
      ],
    ).run();
  }

  async listByUserId(userId: string): Promise<NearPublicKeyRecord[]> {
    await this.ensureSchema();
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return [];
    const result = await this.bindScope(
      `SELECT record_json
         FROM signer_near_public_keys
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        ORDER BY COALESCE(signer_slot, 0) ASC, created_at_ms ASC, public_key ASC`,
      [uid],
    ).all<D1NearPublicKeyRow>();
    return (result.results || [])
      .map((row) => parseNearPublicKeyRecord(parseD1RecordJson(row.record_json)))
      .filter((record): record is NearPublicKeyRecord => Boolean(record));
  }
}

class PostgresNearPublicKeyStore implements NearPublicKeyStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async put(record: NearPublicKeyRecord): Promise<void> {
    const parsed = parseNearPublicKeyRecord(record);
    if (!parsed) throw new Error('Invalid near public key record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO near_public_keys (namespace, user_id, public_key, record_json, created_at_ms, updated_at_ms)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (namespace, user_id, public_key)
        DO UPDATE SET
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        this.namespace,
        parsed.userId,
        parsed.publicKey,
        parsed,
        parsed.createdAtMs,
        parsed.updatedAtMs,
      ],
    );
  }

  async listByUserId(userId: string): Promise<NearPublicKeyRecord[]> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return [];
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM near_public_keys
        WHERE namespace = $1 AND user_id = $2
      `,
      [this.namespace, uid],
    );
    const out: NearPublicKeyRecord[] = [];
    for (const r of rows || []) {
      const parsed = isObject(r) ? parseNearPublicKeyRecord(r.record_json) : null;
      if (parsed) out.push(parsed);
    }
    out.sort((a, b) => (a.signerSlot || 0) - (b.signerSlot || 0));
    return out;
  }
}

export function createNearPublicKeyStore(input: {
  config?: Record<string, unknown> | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): NearPublicKeyStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const postgresUrl = getPostgresUrlFromConfig(config);
  const namespace =
    toOptionalTrimmedString(config.NEAR_PUBLIC_KEY_NAMESPACE) ||
    toOptionalTrimmedString(config.THRESHOLD_PREFIX) ||
    '';
  const kind = toOptionalTrimmedString(config.kind);

  if (kind === 'd1') {
    const database = resolveD1DatabaseFromConfig(config);
    if (!database) {
      throw new Error(
        '[near-public-keys] D1 store selected but no D1 database was provided',
      );
    }
    input.logger.info('[near-public-keys] Using D1 store for NEAR public key metadata');
    return new D1NearPublicKeyStore({
      database,
      ...d1ScopeFromConfig({ config, namespace }),
    });
  }

  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[near-public-keys] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info('[near-public-keys] Using Postgres store for NEAR public key metadata');
    return new PostgresNearPublicKeyStore({ postgresUrl, namespace });
  }

  input.logger.info('[near-public-keys] Using in-memory store for NEAR public key metadata');
  return new InMemoryNearPublicKeyStore();
}
