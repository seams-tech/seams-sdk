import {
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseWalletAuthMethodRecordV2,
  walletAuthMethodRecordId,
  walletIdFromString,
  type WalletAuthMethodRecord as SharedWalletAuthMethodRecord,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { formatD1ExecStatement, parseD1JsonColumn } from '../storage/d1Sql';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../storage/tenantRoute';

export type WalletAuthMethodRecord = SharedWalletAuthMethodRecord;

/**
 * R103E's auth-method row. The v1 record remains exported for the older
 * registration/add-factor surface while the authority cutover is composed.
 * New authority-owned writes use this type and the V2 statements below.
 */
export type WalletAuthMethodRecordV2Owned = WalletAuthMethodRecordV2;

type ActivePasskeyWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'passkey'; readonly status: 'active' }
>;

type ActiveWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly status: 'active' }
>;

type RevokedPasskeyWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'passkey'; readonly status: 'revoked' }
>;

export type WalletAuthMethodV2Store = {
  putV2(record: WalletAuthMethodRecordV2): Promise<void>;
  insertActiveV2Atomically(input: {
    readonly record: ActiveWalletAuthMethodRecordV2;
    readonly prerequisiteStatements: readonly D1PreparedStatementLike[];
  }): Promise<boolean>;
  prepareV2InsertStatements(
    record: ActiveWalletAuthMethodRecordV2,
  ): readonly D1PreparedStatementLike[];
  prepareActiveV2SourceGuardStatements(input: {
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly walletAuthorityId: WalletAuthorityId;
    readonly authorityDigestB64u: DigestB64u;
    readonly authorityRevocationEpoch: number;
  }): readonly D1PreparedStatementLike[];
  readByIdV2(input: {
    readonly walletAuthMethodId: WalletAuthMethodId;
  }): Promise<WalletAuthMethodRecordV2 | null>;
  getPasskeyV2(input: {
    readonly rpId: string;
    readonly credentialIdB64u: string;
  }): Promise<WalletAuthMethodRecordV2 | null>;
  getEmailOtpV2(input: {
    readonly walletId: string;
    readonly emailHashHex: string;
  }): Promise<WalletAuthMethodRecordV2 | null>;
  listForWalletV2(input: {
    readonly walletId: string;
    readonly walletAuthorityId?: WalletAuthorityId;
    readonly rpId?: string;
  }): Promise<WalletAuthMethodRecordV2[]>;
};

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
  listForWallet(input: { walletId: string; rpId?: string }): Promise<WalletAuthMethodRecord[]>;
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

export type D1WalletAuthMethodStoreScope = {
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

/**
 * The authority-owned table shape is kept separate from the historical
 * create-if-missing schema above. Deployments apply 0007 before using these
 * statements; keeping the SQL here lets focused D1 tests provision the V2
 * table without copying migration text into a test.
 */
export const WALLET_AUTH_METHOD_STORE_D1_SCHEMA_V2_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS wallet_auth_methods (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      wallet_authority_id TEXT NOT NULL,
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
      activated_at_ms INTEGER,
      revoked_at_ms INTEGER,
      PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_auth_method_id),
      FOREIGN KEY (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_authority_id
      ) REFERENCES wallet_authorities(
        namespace,
        org_id,
        project_id,
        env_id,
        authority_id
      ),
      CHECK (length(wallet_id) > 0),
      CHECK (length(wallet_authority_id) > 0),
      CHECK (kind IN ('passkey', 'email_otp')),
      CHECK (status IN ('pending_local_install', 'active', 'revoked')),
      CHECK (length(wallet_auth_method_id) > 0),
      CHECK (length(auth_identifier_key) > 0),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms >= 0),
      CHECK (updated_at_ms >= created_at_ms),
      CHECK (
        (status = 'pending_local_install' AND activated_at_ms IS NULL AND revoked_at_ms IS NULL)
        OR
        (status = 'active' AND activated_at_ms IS NOT NULL AND revoked_at_ms IS NULL)
        OR
        (status = 'revoked' AND activated_at_ms IS NOT NULL AND revoked_at_ms IS NOT NULL)
      ),
      CHECK (
        (kind = 'passkey'
          AND length(rp_id) > 0
          AND credential_id_b64u IS NOT NULL
          AND length(credential_id_b64u) > 0
          AND credential_public_key_b64u IS NOT NULL
          AND length(credential_public_key_b64u) > 0
          AND email_hash_hex IS NULL
          AND registration_authority_id IS NULL
          AND auth_identifier_key = credential_id_b64u)
        OR
        (kind = 'email_otp'
          AND rp_id = ''
          AND credential_id_b64u IS NULL
          AND credential_public_key_b64u IS NULL
          AND email_hash_hex IS NOT NULL
          AND length(email_hash_hex) > 0
          AND registration_authority_id IS NOT NULL
          AND length(registration_authority_id) > 0
          AND auth_identifier_key = email_hash_hex)
      ),
      CHECK (json_extract(record_json, '$.version') = 'wallet_auth_method_v2'),
      CHECK (json_extract(record_json, '$.walletAuthMethodId') = wallet_auth_method_id),
      CHECK (json_extract(record_json, '$.walletId') = wallet_id),
      CHECK (json_extract(record_json, '$.walletAuthorityId') = wallet_authority_id),
      CHECK (json_extract(record_json, '$.kind') = kind),
      CHECK (json_extract(record_json, '$.status') = status),
      CHECK (json_extract(record_json, '$.createdAtMs') = created_at_ms),
      CHECK (json_extract(record_json, '$.updatedAtMs') = updated_at_ms),
      CHECK (
        (kind = 'passkey'
          AND json_extract(record_json, '$.rpId') = rp_id
          AND json_extract(record_json, '$.credentialIdB64u') = credential_id_b64u
          AND json_extract(record_json, '$.credentialPublicKeyB64u') = credential_public_key_b64u
          AND json_extract(record_json, '$.counter') >= 0)
        OR
        (kind = 'email_otp'
          AND json_extract(record_json, '$.emailHashHex') = email_hash_hex
          AND json_extract(record_json, '$.registrationAuthorityId') = registration_authority_id)
      )
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS wallet_auth_methods_wallet_authority_status_idx
      ON wallet_auth_methods (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        wallet_authority_id,
        status
      )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS wallet_auth_methods_v2_passkey_uidx
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
] as const);

export async function ensureWalletAuthMethodStoreD1Schema(
  options: D1WalletAuthMethodStoreSchemaOptions,
): Promise<void> {
  for (const statement of WALLET_AUTH_METHOD_STORE_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export async function ensureWalletAuthMethodStoreD1SchemaV2(
  options: D1WalletAuthMethodStoreSchemaOptions,
): Promise<void> {
  for (const statement of WALLET_AUTH_METHOD_STORE_D1_SCHEMA_V2_SQL) {
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

export function normalizeWalletAuthMethodV2(raw: unknown): WalletAuthMethodRecordV2 | null {
  return parseWalletAuthMethodRecordV2(raw);
}

export function walletAuthMethodV2Id(record: WalletAuthMethodRecordV2): WalletAuthMethodId {
  return record.walletAuthMethodId;
}

export function bindWalletAuthMethodIdentityV2(record: WalletAuthMethodRecordV2): {
  readonly rpId: string;
  readonly authIdentifierKey: string;
  readonly credentialIdB64u: string | null;
  readonly credentialPublicKeyB64u: string | null;
  readonly emailHashHex: string | null;
  readonly registrationAuthorityId: string | null;
  readonly activatedAtMs: number | null;
  readonly revokedAtMs: number | null;
} {
  switch (record.kind) {
    case 'passkey':
      return {
        rpId: String(record.rpId),
        authIdentifierKey: String(record.credentialIdB64u),
        credentialIdB64u: String(record.credentialIdB64u),
        credentialPublicKeyB64u: record.credentialPublicKeyB64u,
        emailHashHex: null,
        registrationAuthorityId: null,
        activatedAtMs: record.status === 'pending_local_install' ? null : record.activatedAtMs,
        revokedAtMs: record.status === 'revoked' ? record.revokedAtMs : null,
      };
    case 'email_otp':
      return {
        rpId: '',
        authIdentifierKey: record.emailHashHex,
        credentialIdB64u: null,
        credentialPublicKeyB64u: null,
        emailHashHex: record.emailHashHex,
        registrationAuthorityId: record.registrationAuthorityId,
        activatedAtMs: record.status === 'pending_local_install' ? null : record.activatedAtMs,
        revokedAtMs: record.status === 'revoked' ? record.revokedAtMs : null,
      };
  }
}

function walletAuthMethodV2IdentityColumns(record: WalletAuthMethodRecordV2): {
  readonly walletId: string;
  readonly walletAuthorityId: string;
  readonly kind: WalletAuthMethodRecordV2['kind'];
  readonly walletAuthMethodId: string;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly rpId: string;
  readonly authIdentifierKey: string;
  readonly credentialIdB64u: string | null;
  readonly credentialPublicKeyB64u: string | null;
  readonly emailHashHex: string | null;
  readonly registrationAuthorityId: string | null;
  readonly status: WalletAuthMethodRecordV2['status'];
  readonly activatedAtMs: number | null;
  readonly revokedAtMs: number | null;
} {
  const identity = bindWalletAuthMethodIdentityV2(record);
  return {
    walletId: String(record.walletId),
    walletAuthorityId: String(record.walletAuthorityId),
    kind: record.kind,
    walletAuthMethodId: String(record.walletAuthMethodId),
    recordJson: JSON.stringify(record),
    createdAtMs: record.createdAtMs,
    updatedAtMs: record.updatedAtMs,
    rpId: identity.rpId,
    authIdentifierKey: identity.authIdentifierKey,
    credentialIdB64u: identity.credentialIdB64u,
    credentialPublicKeyB64u: identity.credentialPublicKeyB64u,
    emailHashHex: identity.emailHashHex,
    registrationAuthorityId: identity.registrationAuthorityId,
    status: record.status,
    activatedAtMs: identity.activatedAtMs,
    revokedAtMs: identity.revokedAtMs,
  };
}

export function prepareD1WalletAuthMethodV2PutStatement(input: {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletAuthMethodStoreScope;
  readonly record: WalletAuthMethodRecordV2;
  readonly insertOnly?: boolean;
}): D1PreparedStatementLike {
  const parsed = normalizeWalletAuthMethodV2(input.record);
  if (!parsed) throw new Error('Invalid V2 wallet auth method record');
  const columns = walletAuthMethodV2IdentityColumns(parsed);
  const conflictClause = input.insertOnly
    ? ''
    : `
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_auth_method_id)
      DO UPDATE SET
        wallet_id = EXCLUDED.wallet_id,
        wallet_authority_id = EXCLUDED.wallet_authority_id,
        rp_id = EXCLUDED.rp_id,
        kind = EXCLUDED.kind,
        status = EXCLUDED.status,
        auth_identifier_key = EXCLUDED.auth_identifier_key,
        credential_id_b64u = EXCLUDED.credential_id_b64u,
        credential_public_key_b64u = EXCLUDED.credential_public_key_b64u,
        email_hash_hex = EXCLUDED.email_hash_hex,
        registration_authority_id = EXCLUDED.registration_authority_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = MIN(wallet_auth_methods.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = MAX(wallet_auth_methods.updated_at_ms, EXCLUDED.updated_at_ms),
        activated_at_ms = EXCLUDED.activated_at_ms,
        revoked_at_ms = EXCLUDED.revoked_at_ms`;
  return input.database
    .prepare(
      `INSERT INTO wallet_auth_methods (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        wallet_authority_id,
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
        updated_at_ms,
        activated_at_ms,
        revoked_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ${conflictClause}`,
    )
    .bind(
      input.scope.namespace,
      input.scope.orgId,
      input.scope.projectId,
      input.scope.envId,
      columns.walletId,
      columns.walletAuthorityId,
      columns.rpId,
      columns.kind,
      columns.status,
      columns.walletAuthMethodId,
      columns.authIdentifierKey,
      columns.credentialIdB64u,
      columns.credentialPublicKeyB64u,
      columns.emailHashHex,
      columns.registrationAuthorityId,
      columns.recordJson,
      columns.createdAtMs,
      columns.updatedAtMs,
      columns.activatedAtMs,
      columns.revokedAtMs,
    );
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

export function prepareD1WalletAuthMethodPutStatement(input: {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletAuthMethodStoreScope;
  readonly record: WalletAuthMethodRecord;
}): D1PreparedStatementLike {
  const parsed = normalizeWalletAuthMethod(input.record);
  if (!parsed) throw new Error('Invalid wallet auth method record');
  const identity = bindWalletAuthMethodIdentity(parsed);
  return input.database
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
      input.scope.namespace,
      input.scope.orgId,
      input.scope.projectId,
      input.scope.envId,
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
    );
}

/** Insert-only auth-method write used when a new factor and its envelope are
 * committed together. A credential collision must abort the enclosing D1
 * batch instead of updating an existing factor's identity. */
export function prepareD1WalletAuthMethodInsertStatement(input: {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletAuthMethodStoreScope;
  readonly record: WalletAuthMethodRecord;
}): D1PreparedStatementLike {
  const parsed = normalizeWalletAuthMethod(input.record);
  if (!parsed) throw new Error('Invalid wallet auth method record');
  const identity = bindWalletAuthMethodIdentity(parsed);
  return input.database
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
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.scope.namespace,
      input.scope.orgId,
      input.scope.projectId,
      input.scope.envId,
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
    );
}

function assertNeverWalletAuthMethod(record: never): never {
  throw new Error(`Unexpected wallet auth method record: ${JSON.stringify(record)}`);
}

export class D1WalletAuthMethodStore implements WalletAuthMethodStore, WalletAuthMethodV2Store {
  readonly adapterKind = 'd1';
  private readonly database: D1DatabaseLike;
  private readonly scope: D1WalletAuthMethodStoreScope;
  private readonly ensureSchemaOnUse: boolean;
  private schemaReady = false;
  private v2SchemaReady = false;

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

  private async ensureV2Schema(): Promise<void> {
    if (!this.ensureSchemaOnUse || this.v2SchemaReady) return;
    await ensureWalletAuthMethodStoreD1SchemaV2({ database: this.database });
    this.v2SchemaReady = true;
  }

  async put(record: WalletAuthMethodRecord): Promise<void> {
    await this.ensureSchema();
    await prepareD1WalletAuthMethodPutStatement({
      database: this.database,
      scope: this.scope,
      record,
    }).run();
  }

  /**
   * Prepares the guarded auth-method mutation used when a passkey and its
   * custody envelopes are revoked in one D1 batch. The CAS guard turns a
   * missing or concurrently changed active row into a transaction failure;
   * callers must append these statements to the custody-store mutation batch.
   */
  preparePasskeyRecoveryRevocationStatements(input: {
    readonly record: WalletAuthMethodRecord;
    readonly expectedUpdatedAtMs: number;
    readonly revokedAtMs: number;
  }): readonly D1PreparedStatementLike[] {
    const record = input.record;
    if (record.kind !== 'passkey' || record.status !== 'revoked') {
      throw new Error('Passkey revocation statements require a revoked passkey record');
    }
    const parsed = normalizeWalletAuthMethod(record);
    if (!parsed || parsed.kind !== 'passkey' || parsed.status !== 'revoked') {
      throw new Error('Invalid revoked passkey auth method record');
    }
    const authMethodId = walletAuthMethodId(parsed);
    if (!Number.isSafeInteger(input.expectedUpdatedAtMs) || input.expectedUpdatedAtMs < 0) {
      throw new Error('Passkey revocation expected updatedAtMs is invalid');
    }
    if (!Number.isSafeInteger(input.revokedAtMs) || input.revokedAtMs < input.expectedUpdatedAtMs) {
      throw new Error('Passkey revocation timestamp is invalid');
    }
    const update = this.database
      .prepare(
        `UPDATE wallet_auth_methods
            SET status = 'revoked',
                record_json = ?6,
                updated_at_ms = ?7
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND wallet_auth_method_id = ?5
            AND kind = 'passkey'
            AND status = 'active'
            AND wallet_id = ?8
            AND updated_at_ms = ?9`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        authMethodId,
        JSON.stringify(parsed),
        input.revokedAtMs,
        String(parsed.walletId),
        input.expectedUpdatedAtMs,
      );
    const guard = this.database.prepare(`
      INSERT INTO router_ab_yao_versioned_json_cas_guard (guard_id)
      SELECT 1
       WHERE changes() = 0
    `);
    const sessionFilter = `
      FROM reusable_wallet_sessions AS session
      WHERE session.namespace = ?
        AND session.tenant_id = ?
        AND session.wallet_id = ?
        AND session.wallet_auth_method_id = ?`;
    const deleteTokens = this.database
      .prepare(
        `DELETE FROM opaque_wallet_session_tokens
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_session_id IN (SELECT session.wallet_session_id ${sessionFilter})`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.namespace,
        this.scope.orgId,
        parsed.walletId,
        authMethodId,
      );
    const deleteRegistrationReplayTokens = this.database
      .prepare(
        `DELETE FROM registration_replay_opaque_wallet_session_tokens_v1
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_session_id IN (SELECT session.wallet_session_id ${sessionFilter})`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.namespace,
        this.scope.orgId,
        parsed.walletId,
        authMethodId,
      );
    const exhaustQuotas = this.database
      .prepare(
        `UPDATE authorization_wallet_session_quotas
            SET remaining_uses = 0,
                lifecycle_kind = 'exhausted'
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_session_id IN (SELECT session.wallet_session_id ${sessionFilter})
            AND lifecycle_kind = 'active'`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.namespace,
        this.scope.orgId,
        parsed.walletId,
        authMethodId,
      );
    const supersedeSessions = this.database
      .prepare(
        `UPDATE reusable_wallet_sessions
            SET lifecycle_kind = 'superseded'
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_id = ?
            AND wallet_auth_method_id = ?
            AND lifecycle_kind = 'active'`,
      )
      .bind(this.scope.namespace, this.scope.orgId, parsed.walletId, authMethodId);
    return [
      update,
      guard,
      deleteTokens,
      deleteRegistrationReplayTokens,
      exhaustQuotas,
      supersedeSessions,
    ];
  }

  preparePasskeyRevocationStatements(input: {
    readonly record: WalletAuthMethodRecord;
    readonly expectedUpdatedAtMs: number;
    readonly revokedAtMs: number;
  }): readonly D1PreparedStatementLike[] {
    return this.preparePasskeyRecoveryRevocationStatements(input);
  }

  /**
   * Prepares the insert-only wallet auth-method mutation used by custody
   * linking. The statement intentionally has no conflict handler; the unique
   * credential index is part of the transaction's fail-closed boundary.
   */
  preparePasskeyRegistrationStatements(
    record: WalletAuthMethodRecord,
  ): readonly D1PreparedStatementLike[] {
    if (record.kind !== 'passkey' || record.status !== 'active') {
      throw new Error('Passkey registration statements require an active passkey record');
    }
    const insert = prepareD1WalletAuthMethodInsertStatement({
      database: this.database,
      scope: this.scope,
      record,
    });
    const guard = this.database.prepare(`
      INSERT INTO router_ab_yao_versioned_json_cas_guard (guard_id)
      SELECT 1
       WHERE changes() = 0
    `);
    return [insert, guard];
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

  async putV2(record: WalletAuthMethodRecordV2): Promise<void> {
    await this.ensureV2Schema();
    await prepareD1WalletAuthMethodV2PutStatement({
      database: this.database,
      scope: this.scope,
      record,
    }).run();
  }

  async insertActiveV2Atomically(input: {
    readonly record: ActiveWalletAuthMethodRecordV2;
    readonly prerequisiteStatements: readonly D1PreparedStatementLike[];
  }): Promise<boolean> {
    await this.ensureV2Schema();
    try {
      const statements = [
        ...input.prerequisiteStatements,
        ...this.prepareV2InsertStatements(input.record),
      ];
      const results = await this.database.batch<D1ResultLike>(statements);
      return results.length === statements.length && results.every((result) => result.success);
    } catch {
      return false;
    }
  }

  prepareActiveV2SourceGuardStatements(input: {
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly walletAuthorityId: WalletAuthorityId;
    readonly authorityDigestB64u: DigestB64u;
    readonly authorityRevocationEpoch: number;
  }): readonly D1PreparedStatementLike[] {
    if (
      !Number.isSafeInteger(input.authorityRevocationEpoch) ||
      input.authorityRevocationEpoch < 0
    ) {
      throw new Error('Source authority revocation epoch is invalid');
    }
    const sourceCheck = this.database
      .prepare(
        `UPDATE wallet_auth_methods
            SET updated_at_ms = updated_at_ms
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND wallet_auth_method_id = ? AND wallet_id = ?
            AND wallet_authority_id = ? AND status = 'active'
            AND EXISTS (
              SELECT 1
                FROM wallet_authorities AS source_authority
               WHERE source_authority.namespace = ?
                 AND source_authority.org_id = ?
                 AND source_authority.project_id = ?
                 AND source_authority.env_id = ?
                 AND source_authority.authority_id = ?
                 AND source_authority.wallet_id = ?
                 AND source_authority.lifecycle_state = 'active'
                 AND source_authority.authority_digest_b64u = ?
                 AND source_authority.revocation_epoch = ?
            )`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        String(input.walletAuthMethodId),
        String(input.walletId),
        String(input.walletAuthorityId),
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        String(input.walletAuthorityId),
        String(input.walletId),
        String(input.authorityDigestB64u),
        input.authorityRevocationEpoch,
      );
    const guard = this.database.prepare(`
      INSERT INTO wallet_authority_cas_guard (guard_id)
      SELECT 1
       WHERE changes() = 0
    `);
    return [sourceCheck, guard];
  }

  /**
   * Aborts the surrounding batch if the authority already holds an active
   * method of this family.
   *
   * Refactor 109C's admission answers `already_configured` before a ceremony
   * starts, but an admission read cannot close a race: two ceremonies can pass
   * it concurrently and both insert. The auth-method insert's own guard covers
   * only the allocated method id, and migration `0011` deliberately dropped
   * the Email uniqueness index so linked devices could share one address, so
   * nothing else in the batch enforces this.
   *
   * The idiom is the repo's existing CAS guard read backwards: the sibling
   * SELECT normally matches nothing and the INSERT is a no-op, and when a
   * sibling does exist it inserts `guard_id = 1` into a singleton table and
   * collides, which aborts the batch.
   */
  prepareActiveV2TargetFamilyAbsentGuardStatements(input: {
    readonly walletId: WalletId;
    readonly walletAuthorityId: WalletAuthorityId;
    readonly kind: WalletAuthMethodRecordV2['kind'];
  }): readonly D1PreparedStatementLike[] {
    const guard = this.database
      .prepare(
        `INSERT INTO wallet_authority_cas_guard (guard_id)
         SELECT 1
          WHERE EXISTS (
            SELECT 1
              FROM wallet_auth_methods
             WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
               AND wallet_id = ? AND wallet_authority_id = ?
               AND kind = ? AND status = 'active'
          )`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        String(input.walletId),
        String(input.walletAuthorityId),
        input.kind,
      );
    return [guard];
  }

  /**
   * Prepares an insert-only active V2 method mutation. A credential or opaque
   * method-id collision stays inside the surrounding transaction boundary.
   */
  prepareV2InsertStatements(
    record: ActiveWalletAuthMethodRecordV2,
  ): readonly D1PreparedStatementLike[] {
    const parsed = normalizeWalletAuthMethodV2(record);
    if (!parsed || parsed.status !== 'active') {
      throw new Error('V2 insert requires an active V2 auth-method record');
    }
    if (!String(parsed.walletAuthMethodId).startsWith('wallet-auth-method:')) {
      throw new Error('V2 insert requires an opaque auth-method id');
    }
    const insert = prepareD1WalletAuthMethodV2PutStatement({
      database: this.database,
      scope: this.scope,
      record: parsed,
      insertOnly: true,
    });
    const guard = this.database.prepare(`
      INSERT INTO router_ab_yao_versioned_json_cas_guard (guard_id)
      SELECT 1
       WHERE changes() = 0
    `);
    return [insert, guard];
  }

  /**
   * Prepares the exact-source V2 revocation used by recovery promotion.
   * The source row's canonical record JSON, identity, and update timestamp are
   * all part of the compare-and-swap predicate. Session material issued by
   * that exact method is retired in the same batch.
   */
  preparePasskeyRecoveryV2RevocationStatements(input: {
    readonly expected: ActivePasskeyWalletAuthMethodRecordV2;
    readonly record: RevokedPasskeyWalletAuthMethodRecordV2;
    readonly revokedAtMs: number;
  }): readonly D1PreparedStatementLike[] {
    const expected = normalizeWalletAuthMethodV2(input.expected);
    const record = normalizeWalletAuthMethodV2(input.record);
    if (
      !expected ||
      expected.kind !== 'passkey' ||
      expected.status !== 'active' ||
      !record ||
      record.kind !== 'passkey' ||
      record.status !== 'revoked'
    ) {
      throw new Error('Recovery revocation requires active and revoked V2 passkey records');
    }
    if (
      expected.walletAuthMethodId !== record.walletAuthMethodId ||
      expected.walletId !== record.walletId ||
      expected.walletAuthorityId !== record.walletAuthorityId ||
      expected.rpId !== record.rpId ||
      expected.credentialIdB64u !== record.credentialIdB64u ||
      expected.credentialPublicKeyB64u !== record.credentialPublicKeyB64u ||
      expected.counter !== record.counter ||
      expected.createdAtMs !== record.createdAtMs ||
      expected.activatedAtMs !== record.activatedAtMs ||
      record.revokedAtMs !== input.revokedAtMs ||
      record.updatedAtMs !== input.revokedAtMs ||
      !String(expected.walletAuthMethodId).startsWith('wallet-auth-method:')
    ) {
      throw new Error('Recovery revocation source and next V2 records disagree');
    }
    if (!Number.isSafeInteger(input.revokedAtMs) || input.revokedAtMs < expected.updatedAtMs) {
      throw new Error('Recovery revocation timestamp is invalid');
    }
    const authMethodId = String(expected.walletAuthMethodId);
    const update = this.database
      .prepare(
        `UPDATE wallet_auth_methods
            SET status = 'revoked',
                record_json = ?6,
                updated_at_ms = ?7,
                activated_at_ms = ?8,
                revoked_at_ms = ?9
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND wallet_auth_method_id = ?5
            AND wallet_id = ?10
            AND wallet_authority_id = ?11
            AND kind = 'passkey'
            AND status = 'active'
            AND updated_at_ms = ?12
            AND record_json = ?13`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        authMethodId,
        JSON.stringify(record),
        record.updatedAtMs,
        record.activatedAtMs,
        record.revokedAtMs,
        String(expected.walletId),
        String(expected.walletAuthorityId),
        expected.updatedAtMs,
        JSON.stringify(expected),
      );
    const guard = this.database.prepare(`
      INSERT INTO router_ab_yao_versioned_json_cas_guard (guard_id)
      SELECT 1
       WHERE changes() = 0
    `);
    const sessionFilter = `
      FROM reusable_wallet_sessions AS session
      WHERE session.namespace = ?
        AND session.tenant_id = ?
        AND session.wallet_id = ?
        AND session.wallet_auth_method_id = ?`;
    const deleteTokens = this.database
      .prepare(
        `DELETE FROM opaque_wallet_session_tokens
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_session_id IN (SELECT session.wallet_session_id ${sessionFilter})`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.namespace,
        this.scope.orgId,
        String(expected.walletId),
        authMethodId,
      );
    const deleteRegistrationReplayTokens = this.database
      .prepare(
        `DELETE FROM registration_replay_opaque_wallet_session_tokens_v1
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_session_id IN (SELECT session.wallet_session_id ${sessionFilter})`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.namespace,
        this.scope.orgId,
        String(expected.walletId),
        authMethodId,
      );
    const exhaustQuotas = this.database
      .prepare(
        `UPDATE authorization_wallet_session_quotas
            SET remaining_uses = 0,
                lifecycle_kind = 'exhausted'
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_session_id IN (SELECT session.wallet_session_id ${sessionFilter})
            AND lifecycle_kind = 'active'`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.namespace,
        this.scope.orgId,
        String(expected.walletId),
        authMethodId,
      );
    const supersedeSessions = this.database
      .prepare(
        `UPDATE reusable_wallet_sessions
            SET lifecycle_kind = 'superseded'
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_id = ?
            AND wallet_auth_method_id = ?
            AND lifecycle_kind = 'active'`,
      )
      .bind(this.scope.namespace, this.scope.orgId, String(expected.walletId), authMethodId);
    return [
      update,
      guard,
      deleteTokens,
      deleteRegistrationReplayTokens,
      exhaustQuotas,
      supersedeSessions,
    ];
  }

  async readByIdV2(input: {
    readonly walletAuthMethodId: WalletAuthMethodId;
  }): Promise<WalletAuthMethodRecordV2 | null> {
    await this.ensureV2Schema();
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
        String(input.walletAuthMethodId),
      )
      .first<D1WalletAuthMethodRow>();
    return normalizeWalletAuthMethodV2(parseD1JsonColumn(row?.record_json));
  }

  async getPasskeyV2(input: {
    rpId: string;
    credentialIdB64u: string;
  }): Promise<WalletAuthMethodRecordV2 | null> {
    await this.ensureV2Schema();
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
            AND kind = 'passkey'
            AND rp_id = ?
            AND credential_id_b64u = ?
          ORDER BY created_at_ms ASC
          LIMIT 1`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        rpId,
        credentialIdB64u,
      )
      .first<D1WalletAuthMethodRow>();
    return normalizeWalletAuthMethodV2(parseD1JsonColumn(row?.record_json));
  }

  async getEmailOtpV2(input: {
    walletId: string;
    emailHashHex: string;
  }): Promise<WalletAuthMethodRecordV2 | null> {
    await this.ensureV2Schema();
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
            AND kind = 'email_otp'
            AND wallet_id = ?
            AND email_hash_hex = ?
          ORDER BY created_at_ms ASC
          LIMIT 1`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        walletId,
        emailHashHex,
      )
      .first<D1WalletAuthMethodRow>();
    return normalizeWalletAuthMethodV2(parseD1JsonColumn(row?.record_json));
  }

  async listForWalletV2(input: {
    walletId: string;
    walletAuthorityId?: WalletAuthorityId;
    rpId?: string;
  }): Promise<WalletAuthMethodRecordV2[]> {
    await this.ensureV2Schema();
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return [];
    const authorityId = input.walletAuthorityId ? String(input.walletAuthorityId) : '';
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
            AND (? = '' OR wallet_authority_id = ?)
            AND (kind = 'email_otp' OR ? = '' OR rp_id = ?)
          ORDER BY created_at_ms ASC, wallet_auth_method_id ASC`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        walletId,
        authorityId,
        authorityId,
        rpId,
        rpId,
      )
      .all<D1WalletAuthMethodRow>();
    const records: WalletAuthMethodRecordV2[] = [];
    for (const row of result.results || []) {
      const parsed = normalizeWalletAuthMethodV2(parseD1JsonColumn(row.record_json));
      if (parsed) records.push(parsed);
    }
    return records;
  }
}
