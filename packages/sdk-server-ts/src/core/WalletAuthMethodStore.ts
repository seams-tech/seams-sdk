import type {
  CloudflareDurableObjectNamespaceLike,
  ThresholdStoreConfigInput,
} from './types';
import {
  THRESHOLD_DO_OBJECT_NAME_DEFAULT,
  THRESHOLD_PREFIX_DEFAULT,
} from './defaultConfigsServer';
import type { NormalizedLogger } from './logger';
import {
  getPostgresPool,
  getPostgresUrlFromConfig,
  type PgQueryExecutor,
} from '../storage/postgres';
import { formatD1ExecStatement } from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import {
  walletIdFromString,
  type WalletAuthMethodRecord as SharedWalletAuthMethodRecord,
} from '@shared/utils/registrationIntent';

export type WalletAuthMethodRecord = SharedWalletAuthMethodRecord;

export interface WalletAuthMethodStore {
  put(record: WalletAuthMethodRecord): Promise<void>;
  getPasskey(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodRecord | null>;
  getEmailOtp(input: {
    walletId: string;
    emailHashHex: string;
  }): Promise<WalletAuthMethodRecord | null>;
  listForWallet(input: {
    walletId: string;
    rpId?: string;
  }): Promise<WalletAuthMethodRecord[]>;
}

export interface D1WalletAuthMethodStoreSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1WalletAuthMethodStoreOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema?: boolean;
}

type NormalizedD1WalletAuthMethodStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema: boolean;
};

type D1WalletAuthMethodStoreScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

type D1WalletAuthMethodRow = {
  readonly record_json?: unknown;
};

export const WALLET_AUTH_METHOD_STORE_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS signer_wallet_auth_methods (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      rp_id TEXT NOT NULL DEFAULT '',
      kind TEXT NOT NULL,
      status TEXT NOT NULL,
      wallet_auth_method_id TEXT NOT NULL,
      auth_identifier_key TEXT NOT NULL,
      credential_id_b64u TEXT,
      credential_public_key_b64u TEXT,
      email_hash_hex TEXT,
      registration_authority_id TEXT,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_auth_method_id),
      CHECK (length(wallet_id) > 0),
      CHECK (kind IN ('passkey', 'email_otp')),
      CHECK (status IN ('active', 'revoked')),
      CHECK (length(wallet_auth_method_id) > 0),
      CHECK (length(auth_identifier_key) > 0),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms >= 0),
      CHECK (updated_at_ms >= created_at_ms)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS signer_wallet_auth_methods_wallet_idx
      ON signer_wallet_auth_methods (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        rp_id,
        status
      )
  `,
  `
    CREATE INDEX IF NOT EXISTS signer_wallet_auth_methods_identifier_idx
      ON signer_wallet_auth_methods (
        namespace,
        org_id,
        project_id,
        env_id,
        kind,
        auth_identifier_key
      )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS signer_wallet_auth_methods_passkey_uidx
      ON signer_wallet_auth_methods (
        namespace,
        org_id,
        project_id,
        env_id,
        rp_id,
        credential_id_b64u
      )
      WHERE kind = 'passkey' AND credential_id_b64u IS NOT NULL
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS signer_wallet_auth_methods_email_uidx
      ON signer_wallet_auth_methods (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        email_hash_hex
      )
      WHERE kind = 'email_otp' AND email_hash_hex IS NOT NULL
  `,
] as const);

export async function ensureWalletAuthMethodStoreD1Schema(
  options: D1WalletAuthMethodStoreSchemaOptions,
): Promise<void> {
  for (const statement of WALLET_AUTH_METHOD_STORE_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function trimString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalTrimmedString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

function walletAuthMethodId(record: WalletAuthMethodRecord): string {
  return record.kind === 'passkey'
    ? `passkey:${record.rpId}:${record.credentialIdB64u}`
    : `email_otp:${record.walletId}:${record.emailHashHex}`;
}

export function resolveWalletAuthMethodStoreNamespace(
  config: Record<string, unknown>,
): string {
  const explicit = toOptionalTrimmedString(config.WALLET_AUTH_METHOD_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');
  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  return `${toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`)}wallet-auth-method:`;
}

export function normalizeWalletAuthMethod(
  raw: unknown,
): WalletAuthMethodRecord | null {
  if (!isObject(raw)) return null;
  const version = trimString(raw.version);
  const kind = trimString(raw.kind);
  const status = trimString(raw.status);
  const walletId = walletIdFromString(trimString(raw.walletId));
  const rpId = trimString(raw.rpId);
  const createdAtMs = Math.floor(Number(raw.createdAtMs));
  const updatedAtMs = Math.floor(Number(raw.updatedAtMs));
  if (
    version !== 'wallet_auth_method_v1' ||
    (kind !== 'passkey' && kind !== 'email_otp') ||
    (status !== 'active' && status !== 'revoked') ||
    !walletId ||
    !Number.isSafeInteger(createdAtMs) ||
    !Number.isSafeInteger(updatedAtMs)
  ) {
    return null;
  }
  if (kind === 'passkey') {
    const parsedRpId = parseWebAuthnRpId(raw.rpId);
    if (!parsedRpId.ok) return null;
    const credentialIdB64u = trimString(raw.credentialIdB64u);
    const credentialPublicKeyB64u = trimString(raw.credentialPublicKeyB64u);
    const counter = Math.floor(Number(raw.counter));
    if (!credentialIdB64u || !credentialPublicKeyB64u || !Number.isSafeInteger(counter)) {
      return null;
    }
    return {
      version: 'wallet_auth_method_v1',
      kind: 'passkey',
      status,
      walletId,
      rpId: parsedRpId.value,
      credentialIdB64u,
      credentialPublicKeyB64u,
      counter,
      createdAtMs,
      updatedAtMs,
    };
  }
  if (rpId) return null;
  const emailHashHex = trimString(raw.emailHashHex);
  const registrationAuthorityId = trimString(raw.registrationAuthorityId);
  if (!emailHashHex || !registrationAuthorityId) return null;
  return {
    version: 'wallet_auth_method_v1',
    kind: 'email_otp',
    status,
    walletId,
    emailHashHex,
    registrationAuthorityId,
    createdAtMs,
    updatedAtMs,
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
  if (!normalized) throw new Error(`${field} is required for D1 wallet auth-method store`);
  return normalized;
}

function normalizeD1WalletAuthMethodStoreOptions(
  input: D1WalletAuthMethodStoreOptions,
): NormalizedD1WalletAuthMethodStoreOptions {
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
}): Omit<D1WalletAuthMethodStoreOptions, 'database'> {
  return {
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.config.orgId || input.config.ORG_ID, 'orgId'),
    projectId: requireD1ScopeString(input.config.projectId || input.config.PROJECT_ID, 'projectId'),
    envId: requireD1ScopeString(input.config.envId || input.config.ENV_ID, 'envId'),
  };
}

function bindWalletAuthMethodIdentity(record: WalletAuthMethodRecord): {
  readonly rpId: string;
  readonly authIdentifierKey: string;
  readonly credentialIdB64u: string | null;
  readonly credentialPublicKeyB64u: string | null;
  readonly emailHashHex: string | null;
  readonly registrationAuthorityId: string | null;
} {
  switch (record.kind) {
    case 'passkey':
      return {
        rpId: record.rpId,
        authIdentifierKey: record.credentialIdB64u,
        credentialIdB64u: record.credentialIdB64u,
        credentialPublicKeyB64u: record.credentialPublicKeyB64u,
        emailHashHex: null,
        registrationAuthorityId: null,
      };
    case 'email_otp':
      return {
        rpId: '',
        authIdentifierKey: record.emailHashHex,
        credentialIdB64u: null,
        credentialPublicKeyB64u: null,
        emailHashHex: record.emailHashHex,
        registrationAuthorityId: record.registrationAuthorityId,
      };
    default:
      return assertNeverWalletAuthMethod(record);
  }
}

function assertNeverWalletAuthMethod(record: never): never {
  throw new Error(`Unexpected wallet auth method record: ${JSON.stringify(record)}`);
}

export async function putWalletAuthMethodWithExecutor(input: {
  executor: PgQueryExecutor;
  namespace: string;
  record: WalletAuthMethodRecord;
}): Promise<void> {
  const { record } = input;
  await input.executor.query(
    `
      INSERT INTO wallet_auth_methods
        (
          namespace,
          wallet_id,
          rp_id,
          kind,
          status,
          wallet_auth_method_id,
          auth_identifier_key,
          credential_id_b64u,
          credential_public_key_b64u,
          signer_slot,
          email_hash_hex,
          challenge_id,
          record_json,
          created_at_ms,
          updated_at_ms
        )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, $10, $11, $12::jsonb, $13, $14)
      ON CONFLICT (namespace, wallet_auth_method_id) DO UPDATE SET
        wallet_id = EXCLUDED.wallet_id,
        rp_id = EXCLUDED.rp_id,
        kind = EXCLUDED.kind,
        status = EXCLUDED.status,
        auth_identifier_key = EXCLUDED.auth_identifier_key,
        credential_id_b64u = EXCLUDED.credential_id_b64u,
        credential_public_key_b64u = EXCLUDED.credential_public_key_b64u,
        signer_slot = EXCLUDED.signer_slot,
        email_hash_hex = EXCLUDED.email_hash_hex,
        challenge_id = EXCLUDED.challenge_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = LEAST(wallet_auth_methods.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = GREATEST(wallet_auth_methods.updated_at_ms, EXCLUDED.updated_at_ms)
    `,
    [
      input.namespace,
      record.walletId,
      record.kind === 'passkey' ? record.rpId : null,
      record.kind,
      record.status,
      walletAuthMethodId(record),
      record.kind === 'passkey' ? record.credentialIdB64u : record.emailHashHex,
      record.kind === 'passkey' ? record.credentialIdB64u : null,
      record.kind === 'passkey' ? record.credentialPublicKeyB64u : null,
      record.kind === 'email_otp' ? record.emailHashHex : null,
      record.kind === 'email_otp' ? record.registrationAuthorityId : null,
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
    ],
  );
}

class InMemoryWalletAuthMethodStore implements WalletAuthMethodStore {
  private readonly records = new Map<string, WalletAuthMethodRecord>();

  constructor(private readonly namespace: string) {}

  async put(record: WalletAuthMethodRecord): Promise<void> {
    this.records.set(`${this.namespace}${walletAuthMethodId(record)}`, record);
  }

  async getPasskey(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodRecord | null> {
    return (
      this.records.get(`${this.namespace}passkey:${input.rpId}:${input.credentialIdB64u}`) || null
    );
  }

  async getEmailOtp(input: {
    walletId: string;
    emailHashHex: string;
  }): Promise<WalletAuthMethodRecord | null> {
    return (
      this.records.get(`${this.namespace}email_otp:${input.walletId}:${input.emailHashHex}`) ||
      null
    );
  }

  async listForWallet(input: {
    walletId: string;
    rpId?: string;
  }): Promise<WalletAuthMethodRecord[]> {
    return [...this.records.values()].filter(
      (record) =>
        record.walletId === input.walletId &&
        (record.kind === 'email_otp' || !input.rpId || record.rpId === input.rpId),
    );
  }
}

export class D1WalletAuthMethodStore implements WalletAuthMethodStore {
  readonly adapterKind = 'd1';
  private readonly database: D1DatabaseLike;
  private readonly scope: D1WalletAuthMethodStoreScope;
  private readonly ensureSchemaOnUse: boolean;
  private schemaReady = false;

  constructor(input: D1WalletAuthMethodStoreOptions) {
    const normalized = normalizeD1WalletAuthMethodStoreOptions(input);
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
    await ensureWalletAuthMethodStoreD1Schema({ database: this.database });
    this.schemaReady = true;
  }

  async put(record: WalletAuthMethodRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = normalizeWalletAuthMethod(record);
    if (!parsed) throw new Error('Invalid wallet auth method record');
    const identity = bindWalletAuthMethodIdentity(parsed);
    await this.database
      .prepare(
        `INSERT INTO signer_wallet_auth_methods (
          namespace,
          org_id,
          project_id,
          env_id,
          wallet_id,
          rp_id,
          kind,
          status,
          wallet_auth_method_id,
          auth_identifier_key,
          credential_id_b64u,
          credential_public_key_b64u,
          email_hash_hex,
          registration_authority_id,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, wallet_auth_method_id)
        DO UPDATE SET
          wallet_id = EXCLUDED.wallet_id,
          rp_id = EXCLUDED.rp_id,
          kind = EXCLUDED.kind,
          status = EXCLUDED.status,
          auth_identifier_key = EXCLUDED.auth_identifier_key,
          credential_id_b64u = EXCLUDED.credential_id_b64u,
          credential_public_key_b64u = EXCLUDED.credential_public_key_b64u,
          email_hash_hex = EXCLUDED.email_hash_hex,
          registration_authority_id = EXCLUDED.registration_authority_id,
          record_json = EXCLUDED.record_json,
          created_at_ms = MIN(
            signer_wallet_auth_methods.created_at_ms,
            EXCLUDED.created_at_ms
          ),
          updated_at_ms = MAX(
            signer_wallet_auth_methods.updated_at_ms,
            EXCLUDED.updated_at_ms
          )`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        parsed.walletId,
        identity.rpId,
        parsed.kind,
        parsed.status,
        walletAuthMethodId(parsed),
        identity.authIdentifierKey,
        identity.credentialIdB64u,
        identity.credentialPublicKeyB64u,
        identity.emailHashHex,
        identity.registrationAuthorityId,
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.updatedAtMs,
      )
      .run();
  }

  async getPasskey(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodRecord | null> {
    await this.ensureSchema();
    const rpId = toOptionalTrimmedString(input.rpId);
    const credentialIdB64u = toOptionalTrimmedString(input.credentialIdB64u);
    if (!rpId || !credentialIdB64u) return null;
    const row = await this.database
      .prepare(
        `SELECT record_json
           FROM signer_wallet_auth_methods
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_auth_method_id = ?
          LIMIT 1`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        `passkey:${rpId}:${credentialIdB64u}`,
      )
      .first<D1WalletAuthMethodRow>();
    return normalizeWalletAuthMethod(parseD1RecordJson(row?.record_json));
  }

  async getEmailOtp(input: {
    walletId: string;
    emailHashHex: string;
  }): Promise<WalletAuthMethodRecord | null> {
    await this.ensureSchema();
    const walletId = toOptionalTrimmedString(input.walletId);
    const emailHashHex = toOptionalTrimmedString(input.emailHashHex);
    if (!walletId || !emailHashHex) return null;
    const row = await this.database
      .prepare(
        `SELECT record_json
           FROM signer_wallet_auth_methods
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_auth_method_id = ?
          LIMIT 1`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        `email_otp:${walletId}:${emailHashHex}`,
      )
      .first<D1WalletAuthMethodRow>();
    return normalizeWalletAuthMethod(parseD1RecordJson(row?.record_json));
  }

  async listForWallet(input: {
    walletId: string;
    rpId?: string;
  }): Promise<WalletAuthMethodRecord[]> {
    await this.ensureSchema();
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return [];
    const rpId = toOptionalTrimmedString(input.rpId);
    const result = await this.database
      .prepare(
        `SELECT record_json
           FROM signer_wallet_auth_methods
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_id = ?
            AND (kind = 'email_otp' OR ? = '' OR rp_id = ?)
          ORDER BY created_at_ms ASC`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        walletId,
        rpId,
        rpId,
      )
      .all<D1WalletAuthMethodRow>();
    const records: WalletAuthMethodRecord[] = [];
    for (const row of result.results || []) {
      const parsed = normalizeWalletAuthMethod(parseD1RecordJson(row.record_json));
      if (parsed) records.push(parsed);
    }
    return records;
  }
}

class PostgresWalletAuthMethodStore implements WalletAuthMethodStore {
  private readonly poolPromise: ReturnType<typeof getPostgresPool>;

  constructor(private readonly input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
  }

  async put(record: WalletAuthMethodRecord): Promise<void> {
    const pool = await this.poolPromise;
    await putWalletAuthMethodWithExecutor({
      executor: pool,
      namespace: this.input.namespace,
      record,
    });
  }

  async getPasskey(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodRecord | null> {
    const pool = await this.poolPromise;
    const result = await pool.query(
      `
        SELECT record_json
        FROM wallet_auth_methods
        WHERE namespace = $1 AND wallet_auth_method_id = $2
        LIMIT 1
      `,
      [this.input.namespace, `passkey:${input.rpId}:${input.credentialIdB64u}`],
    );
    return normalizeWalletAuthMethod(result.rows[0]?.record_json);
  }

  async getEmailOtp(input: {
    walletId: string;
    emailHashHex: string;
  }): Promise<WalletAuthMethodRecord | null> {
    const pool = await this.poolPromise;
    const result = await pool.query(
      `
        SELECT record_json
        FROM wallet_auth_methods
        WHERE namespace = $1 AND wallet_auth_method_id = $2
        LIMIT 1
      `,
      [this.input.namespace, `email_otp:${input.walletId}:${input.emailHashHex}`],
    );
    return normalizeWalletAuthMethod(result.rows[0]?.record_json);
  }

  async listForWallet(input: {
    walletId: string;
    rpId?: string;
  }): Promise<WalletAuthMethodRecord[]> {
    const pool = await this.poolPromise;
    const result = await pool.query(
      `
        SELECT record_json
        FROM wallet_auth_methods
        WHERE namespace = $1
          AND wallet_id = $2
          AND (kind = 'email_otp' OR $3::text IS NULL OR rp_id = $3)
        ORDER BY created_at_ms ASC
      `,
      [this.input.namespace, input.walletId, input.rpId || null],
    );
    return result.rows
      .map((row) => normalizeWalletAuthMethod(row.record_json))
      .filter((record): record is WalletAuthMethodRecord => Boolean(record));
  }
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };

class CloudflareDurableObjectWalletAuthMethodStore
  implements WalletAuthMethodStore
{
  private readonly stub: DurableObjectStubLike;

  constructor(private readonly input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    prefix: string;
  }) {
    const id = input.namespace.idFromName(input.objectName);
    this.stub = input.namespace.get(id) as unknown as DurableObjectStubLike;
  }

  private key(id: string): string {
    return `${this.input.prefix}auth-method:${id}`;
  }

  private walletIndexKey(input: { walletId: string; rpId?: string }): string {
    return `${this.input.prefix}wallet-index:${input.rpId || '*'}:${input.walletId}`;
  }

  private async request<T>(body: unknown): Promise<T> {
    const response = await this.stub.fetch('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(`Wallet auth-method DO store HTTP ${response.status}: ${await response.text()}`);
    }
    return (await response.json().catch(() => null)) as T;
  }

  async put(record: WalletAuthMethodRecord): Promise<void> {
    const key = this.key(walletAuthMethodId(record));
    const indexKey = this.walletIndexKey({
      walletId: record.walletId,
      ...(record.kind === 'passkey' ? { rpId: record.rpId } : {}),
    });
    const allWalletIndexKey = this.walletIndexKey({ walletId: record.walletId });
    const current = await this.request<{ value?: unknown }>({ op: 'get', key: indexKey });
    const keys = Array.isArray(current?.value)
      ? current.value.filter((value): value is string => typeof value === 'string' && value.length > 0)
      : [];
    const nextKeys = keys.includes(key) ? keys : [...keys, key];
    const allCurrent = await this.request<{ value?: unknown }>({ op: 'get', key: allWalletIndexKey });
    const allKeys = Array.isArray(allCurrent?.value)
      ? allCurrent.value.filter((value): value is string => typeof value === 'string' && value.length > 0)
      : [];
    const nextAllKeys = allKeys.includes(key) ? allKeys : [...allKeys, key];
    await this.request({ op: 'set', key, value: record });
    await this.request({ op: 'set', key: indexKey, value: nextKeys });
    await this.request({ op: 'set', key: allWalletIndexKey, value: nextAllKeys });
  }

  async getPasskey(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodRecord | null> {
    const result = await this.request<{ value?: unknown }>({
      op: 'get',
      key: this.key(`passkey:${input.rpId}:${input.credentialIdB64u}`),
    });
    return normalizeWalletAuthMethod(result?.value);
  }

  async getEmailOtp(input: {
    walletId: string;
    emailHashHex: string;
  }): Promise<WalletAuthMethodRecord | null> {
    const result = await this.request<{ value?: unknown }>({
      op: 'get',
      key: this.key(`email_otp:${input.walletId}:${input.emailHashHex}`),
    });
    return normalizeWalletAuthMethod(result?.value);
  }

  async listForWallet(input: {
    walletId: string;
    rpId?: string;
  }): Promise<WalletAuthMethodRecord[]> {
    const current = await this.request<{ value?: unknown }>({
      op: 'get',
      key: this.walletIndexKey({ walletId: input.walletId }),
    });
    const keys = Array.isArray(current?.value)
      ? current.value.filter((value): value is string => typeof value === 'string' && value.length > 0)
      : [];
    const records: WalletAuthMethodRecord[] = [];
    for (const key of keys) {
      const result = await this.request<{ value?: unknown }>({ op: 'get', key });
      const record = normalizeWalletAuthMethod(result?.value);
      if (
        record &&
        (record.kind === 'email_otp' || !input.rpId || record.rpId === input.rpId)
      ) {
        records.push(record);
      }
    }
    return records;
  }
}

function resolveDoNamespaceFromConfig(
  config: Record<string, unknown>,
): CloudflareDurableObjectNamespaceLike | null {
  const isNamespace = (value: unknown): value is CloudflareDurableObjectNamespaceLike =>
    isObject(value) && typeof value.idFromName === 'function' && typeof value.get === 'function';
  if (isNamespace(config.namespace)) return config.namespace;
  if (isNamespace(config.durableObjectNamespace)) return config.durableObjectNamespace;
  if (isNamespace(config.THRESHOLD_DO_NAMESPACE)) return config.THRESHOLD_DO_NAMESPACE;
  return null;
}

export function createWalletAuthMethodStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): WalletAuthMethodStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const namespace = resolveWalletAuthMethodStoreNamespace(config);
  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'd1') {
    const database = resolveD1DatabaseFromConfig(config);
    if (!database) {
      throw new Error(
        '[wallet-auth-method] D1 store selected but no D1 database was provided',
      );
    }
    input.logger.info('[wallet-auth-method] Using D1 store');
    return new D1WalletAuthMethodStore({
      database,
      ...d1ScopeFromConfig({ config, namespace }),
    });
  }
  if (kind === 'cloudflare-do') {
    const durableObjectNamespace = resolveDoNamespaceFromConfig(config);
    if (!durableObjectNamespace) {
      throw new Error(
        'cloudflare-do wallet auth-method store selected but no Durable Object namespace was provided',
      );
    }
    const objectName =
      trimString(config.objectName) || trimString(config.name) || THRESHOLD_DO_OBJECT_NAME_DEFAULT;
    input.logger.info('[wallet-auth-method] Using Cloudflare Durable Object store');
    return new CloudflareDurableObjectWalletAuthMethodStore({
      namespace: durableObjectNamespace,
      objectName,
      prefix: namespace,
    });
  }
  const postgresUrl = getPostgresUrlFromConfig(config);
  if (kind === 'postgres' || postgresUrl) {
    if (!input.isNode) {
      throw new Error('[wallet-auth-method] Postgres store is not supported in this runtime');
    }
    if (!postgresUrl) {
      throw new Error('[wallet-auth-method] postgres store enabled but POSTGRES_URL is not set');
    }
    input.logger.info('[wallet-auth-method] Using Postgres store');
    return new PostgresWalletAuthMethodStore({ postgresUrl, namespace });
  }
  input.logger.info('[wallet-auth-method] Using in-memory store');
  return new InMemoryWalletAuthMethodStore(namespace);
}
