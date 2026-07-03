import { parseWebAuthnRpId, type WalletAuthMethodId } from '@shared/utils/domainIds';
import {
  walletAuthMethodRecordId,
  walletIdFromString,
  type WalletAuthMethodRecord as SharedWalletAuthMethodRecord,
} from '@shared/utils/registrationIntent';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { formatD1ExecStatement, parseD1JsonColumn } from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';

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
    CREATE TABLE IF NOT EXISTS wallet_auth_methods (
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
      CHECK (updated_at_ms >= created_at_ms),
      CHECK (
        (
          kind = 'passkey'
          AND length(rp_id) > 0
          AND credential_id_b64u IS NOT NULL
          AND length(credential_id_b64u) > 0
          AND credential_public_key_b64u IS NOT NULL
          AND length(credential_public_key_b64u) > 0
          AND email_hash_hex IS NULL
          AND registration_authority_id IS NULL
          AND auth_identifier_key = credential_id_b64u
          AND wallet_auth_method_id = 'passkey:' || rp_id || ':' || credential_id_b64u
        )
        OR
        (
          kind = 'email_otp'
          AND rp_id = ''
          AND credential_id_b64u IS NULL
          AND credential_public_key_b64u IS NULL
          AND email_hash_hex IS NOT NULL
          AND length(email_hash_hex) > 0
          AND registration_authority_id IS NOT NULL
          AND length(registration_authority_id) > 0
          AND auth_identifier_key = email_hash_hex
          AND wallet_auth_method_id = 'email_otp:' || wallet_id || ':' || email_hash_hex
        )
      )
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS wallet_auth_methods_wallet_idx
      ON wallet_auth_methods (
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
    CREATE INDEX IF NOT EXISTS wallet_auth_methods_identifier_idx
      ON wallet_auth_methods (
        namespace,
        org_id,
        project_id,
        env_id,
        kind,
        auth_identifier_key
      )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS wallet_auth_methods_passkey_uidx
      ON wallet_auth_methods (
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
    CREATE UNIQUE INDEX IF NOT EXISTS wallet_auth_methods_email_uidx
      ON wallet_auth_methods (
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

export function walletAuthMethodId(record: WalletAuthMethodRecord): WalletAuthMethodId {
  return walletAuthMethodRecordId(record);
}

export function normalizeWalletAuthMethod(raw: unknown): WalletAuthMethodRecord | null {
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

export function bindWalletAuthMethodIdentity(record: WalletAuthMethodRecord): {
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
        `INSERT INTO wallet_auth_methods (
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
            wallet_auth_methods.created_at_ms,
            EXCLUDED.created_at_ms
          ),
          updated_at_ms = MAX(
            wallet_auth_methods.updated_at_ms,
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
           FROM wallet_auth_methods
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
    return normalizeWalletAuthMethod(parseD1JsonColumn(row?.record_json));
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
           FROM wallet_auth_methods
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
    return normalizeWalletAuthMethod(parseD1JsonColumn(row?.record_json));
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
           FROM wallet_auth_methods
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
      const parsed = normalizeWalletAuthMethod(parseD1JsonColumn(row.record_json));
      if (parsed) records.push(parsed);
    }
    return records;
  }
}
