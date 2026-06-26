import type { NormalizedLogger } from './logger';
import type {
  CloudflareDurableObjectNamespaceLike,
  ThresholdStoreConfigInput,
  ThresholdRuntimePolicyScope,
} from './types';
import {
  THRESHOLD_DO_OBJECT_NAME_DEFAULT,
  THRESHOLD_PREFIX_DEFAULT,
} from './defaultConfigsServer';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  RedisTcpClient,
  UpstashRedisRestClient,
  redisDel,
  redisGetJson,
  redisSetJson,
} from './ThresholdService/kv';
import {
  getPostgresPool,
  getPostgresUrlFromConfig,
  type PgQueryExecutor,
} from '../storage/postgres';
import { formatD1ExecStatement } from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';

export type WebAuthnCredentialBindingRecord = {
  version: 'webauthn_credential_binding_v1';
  rpId: string;
  credentialIdB64u: string;
  userId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  /** NEAR ed25519 public key (e.g. `ed25519:...`). In threshold-signer mode, this is the group public key. */
  publicKey: string;
  /** Threshold relayer key id (often equal to `publicKey`). */
  relayerKeyId?: string;
  keyVersion?: string;
  recoveryExportCapable?: boolean;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  participantIds?: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  createdAtMs: number;
  updatedAtMs: number;
};

export interface WebAuthnCredentialBindingStore {
  get(rpId: string, credentialIdB64u: string): Promise<WebAuthnCredentialBindingRecord | null>;
  put(record: WebAuthnCredentialBindingRecord): Promise<void>;
  del(rpId: string, credentialIdB64u: string): Promise<void>;
  getMaxSignerSlot?(input: { userId: string; rpId?: string }): Promise<number | null>;
  /**
   * List credential bindings for a user (optionally scoped to an RP ID).
   *
   * Optional because not all backing stores can efficiently enumerate keys.
   */
  listByUserId?(input: {
    userId: string;
    rpId?: string;
  }): Promise<WebAuthnCredentialBindingRecord[]>;
}

export interface D1WebAuthnCredentialBindingStoreSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1WebAuthnCredentialBindingStoreOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema?: boolean;
}

type NormalizedD1WebAuthnCredentialBindingStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema: boolean;
};

type D1WebAuthnCredentialBindingScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

type D1WebAuthnCredentialBindingRow = {
  readonly record_json?: unknown;
  readonly max_signer_slot?: unknown;
};

export const WEBAUTHN_CREDENTIAL_BINDING_STORE_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS signer_webauthn_credential_bindings (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      rp_id TEXT NOT NULL,
      credential_id_b64u TEXT NOT NULL,
      user_id TEXT NOT NULL,
      signer_slot INTEGER NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, rp_id, credential_id_b64u),
      CHECK (length(rp_id) > 0),
      CHECK (length(credential_id_b64u) > 0),
      CHECK (length(user_id) > 0),
      CHECK (signer_slot >= 1),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms > 0)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS signer_webauthn_credential_bindings_user_idx
      ON signer_webauthn_credential_bindings (
        namespace,
        org_id,
        project_id,
        env_id,
        user_id,
        rp_id,
        signer_slot
      )
  `,
] as const);

export async function ensureWebAuthnCredentialBindingStoreD1Schema(
  options: D1WebAuthnCredentialBindingStoreSchemaOptions,
): Promise<void> {
  for (const statement of WEBAUTHN_CREDENTIAL_BINDING_STORE_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalTrimmedString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

export function resolveWebAuthnCredentialBindingStoreNamespace(
  config: Record<string, unknown>,
): string {
  const explicit = toOptionalTrimmedString(config.WEBAUTHN_CREDENTIAL_BINDING_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');

  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  const baseWithColon = toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`);
  return `${baseWithColon}webauthn:credential_binding:`;
}

function parseWebAuthnCredentialBindingRecord(
  raw: unknown,
): WebAuthnCredentialBindingRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  const rpId = toOptionalTrimmedString(raw.rpId);
  const credentialIdB64u = toOptionalTrimmedString(raw.credentialIdB64u);
  const userId = toOptionalTrimmedString(raw.userId);
  const nearAccountId = toOptionalTrimmedString(raw.nearAccountId);
  const nearEd25519SigningKeyId = toOptionalTrimmedString(raw.nearEd25519SigningKeyId);
  const publicKey = toOptionalTrimmedString(raw.publicKey);
  const signerSlotRaw = (raw as { signerSlot?: unknown }).signerSlot;
  const signerSlot =
    typeof signerSlotRaw === 'number' ? signerSlotRaw : Number(signerSlotRaw);
  const createdAtMsRaw = (raw as { createdAtMs?: unknown }).createdAtMs;
  const updatedAtMsRaw = (raw as { updatedAtMs?: unknown }).updatedAtMs;
  const createdAtMs = typeof createdAtMsRaw === 'number' ? createdAtMsRaw : Number(createdAtMsRaw);
  const updatedAtMs = typeof updatedAtMsRaw === 'number' ? updatedAtMsRaw : Number(updatedAtMsRaw);

  if (version !== 'webauthn_credential_binding_v1') return null;
  if (!rpId || !credentialIdB64u || !userId || !nearAccountId || !nearEd25519SigningKeyId || !publicKey)
    return null;
  if (!Number.isFinite(signerSlot) || signerSlot < 1) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;

  const relayerKeyId = toOptionalTrimmedString((raw as { relayerKeyId?: unknown }).relayerKeyId);
  const keyVersion = toOptionalTrimmedString((raw as { keyVersion?: unknown }).keyVersion);
  const recoveryExportCapable =
    typeof (raw as { recoveryExportCapable?: unknown }).recoveryExportCapable === 'boolean'
      ? Boolean((raw as { recoveryExportCapable?: unknown }).recoveryExportCapable)
      : undefined;
  const clientParticipantIdRaw = (raw as { clientParticipantId?: unknown }).clientParticipantId;
  const relayerParticipantIdRaw = (raw as { relayerParticipantId?: unknown }).relayerParticipantId;
  const clientParticipantId =
    typeof clientParticipantIdRaw === 'number'
      ? clientParticipantIdRaw
      : Number(clientParticipantIdRaw);
  const relayerParticipantId =
    typeof relayerParticipantIdRaw === 'number'
      ? relayerParticipantIdRaw
      : Number(relayerParticipantIdRaw);
  const participantIdsRaw = (raw as { participantIds?: unknown }).participantIds;
  const participantIds = Array.isArray(participantIdsRaw)
    ? participantIdsRaw
        .map((v) => (typeof v === 'number' ? v : Number(v)))
        .filter((n) => Number.isFinite(n) && n >= 1)
        .map((n) => Math.floor(n))
    : null;
  const runtimePolicyScopeRaw = (raw as { runtimePolicyScope?: unknown }).runtimePolicyScope;
  const runtimePolicyScope = isObject(runtimePolicyScopeRaw)
    ? (() => {
        try {
          return normalizeRuntimePolicyScope(runtimePolicyScopeRaw) satisfies ThresholdRuntimePolicyScope;
        } catch {
          return null;
        }
      })()
    : null;

  return {
    version: 'webauthn_credential_binding_v1',
    rpId,
    credentialIdB64u,
    userId,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot: Math.floor(signerSlot),
    publicKey,
    ...(relayerKeyId ? { relayerKeyId } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(typeof recoveryExportCapable === 'boolean' ? { recoveryExportCapable } : {}),
    ...(Number.isFinite(clientParticipantId) && clientParticipantId >= 1
      ? { clientParticipantId: Math.floor(clientParticipantId) }
      : {}),
    ...(Number.isFinite(relayerParticipantId) && relayerParticipantId >= 1
      ? { relayerParticipantId: Math.floor(relayerParticipantId) }
      : {}),
    ...(participantIds && participantIds.length ? { participantIds } : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
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
  if (!normalized) throw new Error(`${field} is required for D1 WebAuthn credential store`);
  return normalized;
}

function normalizeD1WebAuthnCredentialBindingStoreOptions(
  input: D1WebAuthnCredentialBindingStoreOptions,
): NormalizedD1WebAuthnCredentialBindingStoreOptions {
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
}): Omit<D1WebAuthnCredentialBindingStoreOptions, 'database'> {
  return {
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.config.orgId || input.config.ORG_ID, 'orgId'),
    projectId: requireD1ScopeString(input.config.projectId || input.config.PROJECT_ID, 'projectId'),
    envId: requireD1ScopeString(input.config.envId || input.config.ENV_ID, 'envId'),
  };
}

export async function putWebAuthnCredentialBindingRecordWithExecutor(input: {
  executor: PgQueryExecutor;
  namespace: string;
  record: WebAuthnCredentialBindingRecord;
}): Promise<void> {
  const parsed = parseWebAuthnCredentialBindingRecord(input.record);
  if (!parsed) throw new Error('Invalid credential binding record');
  await input.executor.query(
    `
      INSERT INTO webauthn_credential_bindings (
        namespace, rp_id, credential_id_b64u, record_json, created_at_ms, updated_at_ms
      )
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (namespace, rp_id, credential_id_b64u)
      DO UPDATE SET
        record_json = EXCLUDED.record_json,
        created_at_ms = LEAST(webauthn_credential_bindings.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = GREATEST(webauthn_credential_bindings.updated_at_ms, EXCLUDED.updated_at_ms)
    `,
    [
      input.namespace,
      parsed.rpId,
      parsed.credentialIdB64u,
      parsed,
      parsed.createdAtMs,
      parsed.updatedAtMs,
    ],
  );
}

class InMemoryWebAuthnCredentialBindingStore implements WebAuthnCredentialBindingStore {
  private readonly map = new Map<string, WebAuthnCredentialBindingRecord>();
  private readonly prefix: string;

  constructor(prefix: string) {
    this.prefix = prefix;
  }

  private key(rpId: string, credentialIdB64u: string): string {
    return `${this.prefix}${rpId}:${credentialIdB64u}`;
  }

  async get(
    rpId: string,
    credentialIdB64u: string,
  ): Promise<WebAuthnCredentialBindingRecord | null> {
    const r = toOptionalTrimmedString(rpId);
    const c = toOptionalTrimmedString(credentialIdB64u);
    if (!r || !c) return null;
    return this.map.get(this.key(r, c)) || null;
  }

  async put(record: WebAuthnCredentialBindingRecord): Promise<void> {
    const parsed = parseWebAuthnCredentialBindingRecord(record);
    if (!parsed) throw new Error('Invalid credential binding record');
    this.map.set(this.key(parsed.rpId, parsed.credentialIdB64u), parsed);
  }

  async del(rpId: string, credentialIdB64u: string): Promise<void> {
    const r = toOptionalTrimmedString(rpId);
    const c = toOptionalTrimmedString(credentialIdB64u);
    if (!r || !c) return;
    this.map.delete(this.key(r, c));
  }

  async listByUserId(input: {
    userId: string;
    rpId?: string;
  }): Promise<WebAuthnCredentialBindingRecord[]> {
    const uid = toOptionalTrimmedString(input.userId);
    const rpId = toOptionalTrimmedString(input.rpId);
    if (!uid) return [];
    const out: WebAuthnCredentialBindingRecord[] = [];
    for (const v of this.map.values()) {
      const parsed = parseWebAuthnCredentialBindingRecord(v);
      if (!parsed) continue;
      if (parsed.userId !== uid) continue;
      if (rpId && parsed.rpId !== rpId) continue;
      out.push(parsed);
    }
    out.sort((a, b) => a.signerSlot - b.signerSlot);
    return out;
  }
}

export class D1WebAuthnCredentialBindingStore implements WebAuthnCredentialBindingStore {
  readonly adapterKind = 'd1';
  private readonly database: D1DatabaseLike;
  private readonly scope: D1WebAuthnCredentialBindingScope;
  private readonly ensureSchemaOnUse: boolean;
  private schemaReady = false;

  constructor(input: D1WebAuthnCredentialBindingStoreOptions) {
    const normalized = normalizeD1WebAuthnCredentialBindingStoreOptions(input);
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
    await ensureWebAuthnCredentialBindingStoreD1Schema({ database: this.database });
    this.schemaReady = true;
  }

  async get(
    rpId: string,
    credentialIdB64u: string,
  ): Promise<WebAuthnCredentialBindingRecord | null> {
    await this.ensureSchema();
    const r = toOptionalTrimmedString(rpId);
    const c = toOptionalTrimmedString(credentialIdB64u);
    if (!r || !c) return null;
    const row = await this.database
      .prepare(
        `SELECT record_json
           FROM signer_webauthn_credential_bindings
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND rp_id = ?
            AND credential_id_b64u = ?
          LIMIT 1`,
      )
      .bind(this.scope.namespace, this.scope.orgId, this.scope.projectId, this.scope.envId, r, c)
      .first<D1WebAuthnCredentialBindingRow>();
    return parseWebAuthnCredentialBindingRecord(parseD1RecordJson(row?.record_json));
  }

  async put(record: WebAuthnCredentialBindingRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseWebAuthnCredentialBindingRecord(record);
    if (!parsed) throw new Error('Invalid credential binding record');
    await this.database
      .prepare(
        `INSERT INTO signer_webauthn_credential_bindings (
          namespace,
          org_id,
          project_id,
          env_id,
          rp_id,
          credential_id_b64u,
          user_id,
          signer_slot,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, rp_id, credential_id_b64u)
        DO UPDATE SET
          user_id = EXCLUDED.user_id,
          signer_slot = EXCLUDED.signer_slot,
          record_json = EXCLUDED.record_json,
          created_at_ms = MIN(
            signer_webauthn_credential_bindings.created_at_ms,
            EXCLUDED.created_at_ms
          ),
          updated_at_ms = MAX(
            signer_webauthn_credential_bindings.updated_at_ms,
            EXCLUDED.updated_at_ms
          )`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        parsed.rpId,
        parsed.credentialIdB64u,
        parsed.userId,
        parsed.signerSlot,
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.updatedAtMs,
      )
      .run();
  }

  async del(rpId: string, credentialIdB64u: string): Promise<void> {
    await this.ensureSchema();
    const r = toOptionalTrimmedString(rpId);
    const c = toOptionalTrimmedString(credentialIdB64u);
    if (!r || !c) return;
    await this.database
      .prepare(
        `DELETE FROM signer_webauthn_credential_bindings
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND rp_id = ?
            AND credential_id_b64u = ?`,
      )
      .bind(this.scope.namespace, this.scope.orgId, this.scope.projectId, this.scope.envId, r, c)
      .run();
  }

  async getMaxSignerSlot(input: { userId: string; rpId?: string }): Promise<number | null> {
    await this.ensureSchema();
    const userId = toOptionalTrimmedString(input.userId);
    if (!userId) return null;
    const rpId = toOptionalTrimmedString(input.rpId);
    const clauses = [
      'namespace = ?',
      'org_id = ?',
      'project_id = ?',
      'env_id = ?',
      'user_id = ?',
    ];
    const values: unknown[] = [
      this.scope.namespace,
      this.scope.orgId,
      this.scope.projectId,
      this.scope.envId,
      userId,
    ];
    if (rpId) {
      clauses.push('rp_id = ?');
      values.push(rpId);
    }
    const row = await this.database
      .prepare(
        `SELECT MAX(signer_slot) AS max_signer_slot
           FROM signer_webauthn_credential_bindings
          WHERE ${clauses.join(' AND ')}`,
      )
      .bind(...values)
      .first<D1WebAuthnCredentialBindingRow>();
    const maxSignerSlot = Number(row?.max_signer_slot);
    return Number.isFinite(maxSignerSlot) && maxSignerSlot > 0
      ? Math.floor(maxSignerSlot)
      : null;
  }

  async listByUserId(input: {
    userId: string;
    rpId?: string;
  }): Promise<WebAuthnCredentialBindingRecord[]> {
    await this.ensureSchema();
    const userId = toOptionalTrimmedString(input.userId);
    if (!userId) return [];
    const rpId = toOptionalTrimmedString(input.rpId);
    const clauses = [
      'namespace = ?',
      'org_id = ?',
      'project_id = ?',
      'env_id = ?',
      'user_id = ?',
    ];
    const values: unknown[] = [
      this.scope.namespace,
      this.scope.orgId,
      this.scope.projectId,
      this.scope.envId,
      userId,
    ];
    if (rpId) {
      clauses.push('rp_id = ?');
      values.push(rpId);
    }
    const result = await this.database
      .prepare(
        `SELECT record_json
           FROM signer_webauthn_credential_bindings
          WHERE ${clauses.join(' AND ')}
          ORDER BY signer_slot ASC`,
      )
      .bind(...values)
      .all<D1WebAuthnCredentialBindingRow>();
    const records: WebAuthnCredentialBindingRecord[] = [];
    for (const row of result.results || []) {
      const parsed = parseWebAuthnCredentialBindingRecord(parseD1RecordJson(row.record_json));
      if (parsed) records.push(parsed);
    }
    return records;
  }
}

class UpstashRedisRestWebAuthnCredentialBindingStore implements WebAuthnCredentialBindingStore {
  private readonly client: UpstashRedisRestClient;
  private readonly prefix: string;

  constructor(input: { url: string; token: string; prefix: string }) {
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
    this.prefix = input.prefix;
  }

  private key(rpId: string, credentialIdB64u: string): string {
    return `${this.prefix}${rpId}:${credentialIdB64u}`;
  }

  async get(
    rpId: string,
    credentialIdB64u: string,
  ): Promise<WebAuthnCredentialBindingRecord | null> {
    const r = toOptionalTrimmedString(rpId);
    const c = toOptionalTrimmedString(credentialIdB64u);
    if (!r || !c) return null;
    const raw = await this.client.getJson(this.key(r, c));
    return parseWebAuthnCredentialBindingRecord(raw);
  }

  async put(record: WebAuthnCredentialBindingRecord): Promise<void> {
    const parsed = parseWebAuthnCredentialBindingRecord(record);
    if (!parsed) throw new Error('Invalid credential binding record');
    await this.client.setJson(this.key(parsed.rpId, parsed.credentialIdB64u), parsed);
  }

  async del(rpId: string, credentialIdB64u: string): Promise<void> {
    const r = toOptionalTrimmedString(rpId);
    const c = toOptionalTrimmedString(credentialIdB64u);
    if (!r || !c) return;
    await this.client.del(this.key(r, c));
  }
}

class RedisTcpWebAuthnCredentialBindingStore implements WebAuthnCredentialBindingStore {
  private readonly client: RedisTcpClient;
  private readonly prefix: string;

  constructor(input: { redisUrl: string; prefix: string }) {
    this.client = new RedisTcpClient(input.redisUrl);
    this.prefix = input.prefix;
  }

  private key(rpId: string, credentialIdB64u: string): string {
    return `${this.prefix}${rpId}:${credentialIdB64u}`;
  }

  async get(
    rpId: string,
    credentialIdB64u: string,
  ): Promise<WebAuthnCredentialBindingRecord | null> {
    const r = toOptionalTrimmedString(rpId);
    const c = toOptionalTrimmedString(credentialIdB64u);
    if (!r || !c) return null;
    const raw = await redisGetJson(this.client, this.key(r, c));
    return parseWebAuthnCredentialBindingRecord(raw);
  }

  async put(record: WebAuthnCredentialBindingRecord): Promise<void> {
    const parsed = parseWebAuthnCredentialBindingRecord(record);
    if (!parsed) throw new Error('Invalid credential binding record');
    await redisSetJson(this.client, this.key(parsed.rpId, parsed.credentialIdB64u), parsed);
  }

  async del(rpId: string, credentialIdB64u: string): Promise<void> {
    const r = toOptionalTrimmedString(rpId);
    const c = toOptionalTrimmedString(credentialIdB64u);
    if (!r || !c) return;
    await redisDel(this.client, this.key(r, c));
  }
}

class PostgresWebAuthnCredentialBindingStore implements WebAuthnCredentialBindingStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async get(
    rpId: string,
    credentialIdB64u: string,
  ): Promise<WebAuthnCredentialBindingRecord | null> {
    const r = toOptionalTrimmedString(rpId);
    const c = toOptionalTrimmedString(credentialIdB64u);
    if (!r || !c) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM webauthn_credential_bindings
        WHERE namespace = $1 AND rp_id = $2 AND credential_id_b64u = $3
        LIMIT 1
      `,
      [this.namespace, r, c],
    );
    return parseWebAuthnCredentialBindingRecord(rows[0]?.record_json);
  }

  async put(record: WebAuthnCredentialBindingRecord): Promise<void> {
    const pool = await this.poolPromise;
    await putWebAuthnCredentialBindingRecordWithExecutor({
      executor: pool,
      namespace: this.namespace,
      record,
    });
  }

  async del(rpId: string, credentialIdB64u: string): Promise<void> {
    const r = toOptionalTrimmedString(rpId);
    const c = toOptionalTrimmedString(credentialIdB64u);
    if (!r || !c) return;
    const pool = await this.poolPromise;
    await pool.query(
      'DELETE FROM webauthn_credential_bindings WHERE namespace = $1 AND rp_id = $2 AND credential_id_b64u = $3',
      [this.namespace, r, c],
    );
  }

  async getMaxSignerSlot(input: { userId: string; rpId?: string }): Promise<number | null> {
    const userId = toOptionalTrimmedString(input.userId);
    if (!userId) return null;
    const rpId = toOptionalTrimmedString(input.rpId);
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT MAX((record_json->>'signerSlot')::int) AS max_signer_slot
        FROM webauthn_credential_bindings
        WHERE namespace = $1
        ${rpId ? 'AND rp_id = $2' : ''}
        AND (record_json->>'userId') = $${rpId ? 3 : 2}
      `,
      rpId ? [this.namespace, rpId, userId] : [this.namespace, userId],
    );
    const raw = rows[0]?.max_signer_slot;
    const n = typeof raw === 'number' ? raw : Number(raw);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : null;
  }

  async listByUserId(input: {
    userId: string;
    rpId?: string;
  }): Promise<WebAuthnCredentialBindingRecord[]> {
    const userId = toOptionalTrimmedString(input.userId);
    const rpId = toOptionalTrimmedString(input.rpId);
    if (!userId) return [];
    const pool = await this.poolPromise;
    const query = rpId
      ? `
          SELECT record_json
          FROM webauthn_credential_bindings
          WHERE namespace = $1 AND rp_id = $2 AND record_json->>'userId' = $3
          ORDER BY (record_json->>'signerSlot')::int ASC
        `
      : `
          SELECT record_json
          FROM webauthn_credential_bindings
          WHERE namespace = $1 AND record_json->>'userId' = $2
          ORDER BY (record_json->>'signerSlot')::int ASC
        `;
    const values = rpId ? [this.namespace, rpId, userId] : [this.namespace, userId];
    const { rows } = await pool.query(query, values);
    const out: WebAuthnCredentialBindingRecord[] = [];
    for (const row of rows || []) {
      const parsed = parseWebAuthnCredentialBindingRecord(row?.record_json);
      if (parsed) out.push(parsed);
    }
    out.sort((a, b) => a.signerSlot - b.signerSlot);
    return out;
  }
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };
type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;
type DoRequest =
  | { op: 'get'; key: string }
  | { op: 'set'; key: string; value: unknown; ttlMs?: number }
  | { op: 'del'; key: string };

function isDurableObjectNamespaceLike(v: unknown): v is CloudflareDurableObjectNamespaceLike {
  return (
    Boolean(v) &&
    typeof v === 'object' &&
    !Array.isArray(v) &&
    typeof (v as CloudflareDurableObjectNamespaceLike).idFromName === 'function' &&
    typeof (v as CloudflareDurableObjectNamespaceLike).get === 'function'
  );
}

function resolveDoNamespaceFromConfig(
  config: Record<string, unknown>,
): CloudflareDurableObjectNamespaceLike | null {
  const direct = (config as { namespace?: unknown }).namespace;
  if (isDurableObjectNamespaceLike(direct)) return direct;

  const alt = (config as { durableObjectNamespace?: unknown }).durableObjectNamespace;
  if (isDurableObjectNamespaceLike(alt)) return alt;

  const envStyle = (config as { THRESHOLD_DO_NAMESPACE?: unknown })
    .THRESHOLD_DO_NAMESPACE;
  if (isDurableObjectNamespaceLike(envStyle)) return envStyle;

  return null;
}

function resolveDoStub(input: {
  namespace: CloudflareDurableObjectNamespaceLike;
  objectName: string;
}): DurableObjectStubLike {
  const id = input.namespace.idFromName(input.objectName);
  return input.namespace.get(id) as unknown as DurableObjectStubLike;
}

async function callDo<T>(stub: DurableObjectStubLike, req: DoRequest): Promise<DoResp<T>> {
  const resp = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(req),
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`WebAuthn DO store HTTP ${resp.status}: ${text}`);
  }
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`WebAuthn DO store returned non-JSON response: ${text.slice(0, 200)}`);
  }
  if (!isObject(json)) {
    throw new Error('WebAuthn DO store returned invalid JSON shape');
  }
  const ok = (json as { ok?: unknown }).ok;
  if (ok === true) return json as DoOk<T>;
  const code = toOptionalTrimmedString((json as { code?: unknown }).code);
  const message = toOptionalTrimmedString((json as { message?: unknown }).message);
  return { ok: false, code: code || 'internal', message: message || 'WebAuthn DO store error' };
}

class CloudflareDurableObjectWebAuthnCredentialBindingStore implements WebAuthnCredentialBindingStore {
  private readonly stub: DurableObjectStubLike;
  private readonly prefix: string;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    prefix: string;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.prefix = input.prefix;
  }

  private key(rpId: string, credentialIdB64u: string): string {
    return `${this.prefix}${rpId}:${credentialIdB64u}`;
  }

  async get(
    rpId: string,
    credentialIdB64u: string,
  ): Promise<WebAuthnCredentialBindingRecord | null> {
    const r = toOptionalTrimmedString(rpId);
    const c = toOptionalTrimmedString(credentialIdB64u);
    if (!r || !c) return null;
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key: this.key(r, c) });
    if (!resp.ok) return null;
    return parseWebAuthnCredentialBindingRecord(resp.value);
  }

  async put(record: WebAuthnCredentialBindingRecord): Promise<void> {
    const parsed = parseWebAuthnCredentialBindingRecord(record);
    if (!parsed) throw new Error('Invalid credential binding record');
    const resp = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key(parsed.rpId, parsed.credentialIdB64u),
      value: parsed,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async del(rpId: string, credentialIdB64u: string): Promise<void> {
    const r = toOptionalTrimmedString(rpId);
    const c = toOptionalTrimmedString(credentialIdB64u);
    if (!r || !c) return;
    const resp = await callDo<void>(this.stub, { op: 'del', key: this.key(r, c) });
    if (!resp.ok) throw new Error(resp.message);
  }
}

export function createWebAuthnCredentialBindingStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): WebAuthnCredentialBindingStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const prefix = resolveWebAuthnCredentialBindingStoreNamespace(config);

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'd1') {
    const database = resolveD1DatabaseFromConfig(config);
    if (!database) {
      throw new Error(
        '[webauthn] D1 credential binding store selected but no D1 database was provided',
      );
    }
    input.logger.info('[webauthn] Using D1 credential binding store');
    return new D1WebAuthnCredentialBindingStore({
      database,
      ...d1ScopeFromConfig({ config, namespace: prefix }),
    });
  }
  if (kind === 'cloudflare-do') {
    const namespace = resolveDoNamespaceFromConfig(config);
    if (!namespace) {
      throw new Error(
        'cloudflare-do webauthn store selected but no Durable Object namespace was provided (expected config.namespace)',
      );
    }
    const objectName =
      toOptionalTrimmedString((config as { objectName?: unknown }).objectName) ||
      toOptionalTrimmedString((config as { name?: unknown }).name) ||
      THRESHOLD_DO_OBJECT_NAME_DEFAULT;
    input.logger.info('[webauthn] Using Cloudflare Durable Object store for credential bindings');
    return new CloudflareDurableObjectWebAuthnCredentialBindingStore({
      namespace,
      objectName,
      prefix,
    });
  }

  if (kind === 'in-memory') {
    input.logger.info('[webauthn] Using in-memory credential binding store (non-persistent)');
    return new InMemoryWebAuthnCredentialBindingStore(prefix);
  }

  if (kind === 'upstash-redis-rest') {
    const url =
      toOptionalTrimmedString(config.url) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
    const token =
      toOptionalTrimmedString(config.token) ||
      toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
    if (!url || !token) {
      throw new Error('Upstash webauthn store enabled but url/token are not both set');
    }
    input.logger.info('[webauthn] Using Upstash REST credential binding store');
    return new UpstashRedisRestWebAuthnCredentialBindingStore({ url, token, prefix });
  }

  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      input.logger.warn(
        '[webauthn] redis-tcp credential binding store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryWebAuthnCredentialBindingStore(prefix);
    }
    const redisUrl =
      toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL);
    if (!redisUrl) {
      throw new Error('redis-tcp webauthn store enabled but redisUrl is not set');
    }
    input.logger.info('[webauthn] Using redis-tcp credential binding store');
    return new RedisTcpWebAuthnCredentialBindingStore({ redisUrl, prefix });
  }

  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error(
        '[webauthn] postgres credential binding store is not supported in this runtime',
      );
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl)
      throw new Error(
        '[webauthn] postgres credential binding store enabled but POSTGRES_URL is not set',
      );
    input.logger.info('[webauthn] Using Postgres credential binding store');
    return new PostgresWebAuthnCredentialBindingStore({ postgresUrl, namespace: prefix });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[webauthn] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info('[webauthn] Using Postgres credential binding store');
    return new PostgresWebAuthnCredentialBindingStore({ postgresUrl, namespace: prefix });
  }

  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash webauthn store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info('[webauthn] Using Upstash REST credential binding store');
    return new UpstashRedisRestWebAuthnCredentialBindingStore({
      url: upstashUrl,
      token: upstashToken,
      prefix,
    });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      input.logger.warn(
        '[webauthn] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryWebAuthnCredentialBindingStore(prefix);
    }
    input.logger.info('[webauthn] Using redis-tcp credential binding store');
    return new RedisTcpWebAuthnCredentialBindingStore({ redisUrl, prefix });
  }

  input.logger.info(
    '[webauthn] Using in-memory credential binding store (no persistence configured)',
  );
  return new InMemoryWebAuthnCredentialBindingStore(prefix);
}
