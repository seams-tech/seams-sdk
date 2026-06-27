import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../storage/tenantRoute';
import type { CloudflareRelayAuthService } from '../authServicePort';
import { createDisabledCloudflareRelayAuthService } from './disabledRelayAuthService';

export interface CloudflareD1RelayAuthServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly relayerAccount?: string;
  readonly relayerPublicKey?: string;
  readonly googleOidcClientId?: string;
}

type ListIdentitiesInput = Parameters<CloudflareRelayAuthService['listIdentities']>[0];
type ListIdentitiesResult = Awaited<ReturnType<CloudflareRelayAuthService['listIdentities']>>;
type GetOrCreateAppSessionVersionInput = Parameters<
  CloudflareRelayAuthService['getOrCreateAppSessionVersion']
>[0];
type GetOrCreateAppSessionVersionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['getOrCreateAppSessionVersion']>
>;
type RotateAppSessionVersionInput = Parameters<
  CloudflareRelayAuthService['rotateAppSessionVersion']
>[0];
type RotateAppSessionVersionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['rotateAppSessionVersion']>
>;
type ValidateAppSessionVersionInput = Parameters<
  CloudflareRelayAuthService['validateAppSessionVersion']
>[0];
type ValidateAppSessionVersionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['validateAppSessionVersion']>
>;
type ListWebAuthnAuthenticatorsInput = Parameters<
  CloudflareRelayAuthService['listWebAuthnAuthenticatorsForUser']
>[0];
type ListWebAuthnAuthenticatorsResult = Awaited<
  ReturnType<CloudflareRelayAuthService['listWebAuthnAuthenticatorsForUser']>
>;
type ListNearPublicKeysInput = Parameters<
  CloudflareRelayAuthService['listNearPublicKeysForUser']
>[0];
type ListNearPublicKeysResult = Awaited<
  ReturnType<CloudflareRelayAuthService['listNearPublicKeysForUser']>
>;

type D1SubjectRow = {
  readonly subject?: unknown;
};

type D1SessionRow = {
  readonly session_version?: unknown;
  readonly record_json?: unknown;
};

type D1AuthenticatorRow = {
  readonly credential_id_b64u?: unknown;
  readonly created_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1RecordJsonRow = {
  readonly record_json?: unknown;
};

type AppSessionVersionRecord = {
  readonly version: 'app_session_version_v1';
  readonly userId: string;
  readonly appSessionVersion: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type WebAuthnCredentialBindingRecord = {
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly userId: string;
  readonly signerSlot: number;
  readonly publicKey?: string;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
};

type NearPublicKeyRecord = {
  readonly publicKey: string;
  readonly kind: 'threshold' | 'local' | 'backup' | 'ephemeral';
  readonly signerSlot?: number;
  readonly credentialIdB64u?: string;
  readonly rpId?: string;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
};

function requireD1RelayAuthScopeString(input: unknown, field: string): string {
  const value = toOptionalTrimmedString(input);
  if (!value) throw new Error(`${field} is required for Cloudflare D1 relay auth service`);
  return value;
}

function normalizeD1RelayAuthOptions(
  input: CloudflareD1RelayAuthServiceOptions,
): CloudflareD1RelayAuthServiceOptions {
  return {
    database: input.database,
    namespace: requireD1RelayAuthScopeString(input.namespace, 'namespace'),
    orgId: requireD1RelayAuthScopeString(input.orgId, 'orgId'),
    projectId: requireD1RelayAuthScopeString(input.projectId, 'projectId'),
    envId: requireD1RelayAuthScopeString(input.envId, 'envId'),
    relayerAccount: toOptionalTrimmedString(input.relayerAccount),
    relayerPublicKey: toOptionalTrimmedString(input.relayerPublicKey),
    googleOidcClientId: toOptionalTrimmedString(input.googleOidcClientId),
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function appSessionVersion(): string {
  return secureRandomBase64Url(32, 'app session versions');
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return Boolean(input) && typeof input === 'object' && !Array.isArray(input);
}

function parseJsonObject(input: unknown): Record<string, unknown> | null {
  if (isRecord(input)) return input;
  if (typeof input !== 'string') return null;
  try {
    const parsed: unknown = JSON.parse(input);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function positiveInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value <= 0) return null;
  return Math.floor(value);
}

function optionalNonNegativeInteger(input: unknown): number | undefined {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value < 0) return undefined;
  return Math.floor(value);
}

function parseAppSessionCreatedAt(input: unknown, fallback: number): number {
  const record = parseJsonObject(input);
  const value = positiveInteger(record?.createdAtMs);
  return value ?? fallback;
}

function appSessionRecord(input: {
  readonly userId: string;
  readonly appSessionVersion: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): AppSessionVersionRecord {
  return {
    version: 'app_session_version_v1',
    userId: input.userId,
    appSessionVersion: input.appSessionVersion,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

function parseWebAuthnBinding(row: D1RecordJsonRow): WebAuthnCredentialBindingRecord | null {
  const record = parseJsonObject(row.record_json);
  if (!record) return null;
  const rpId = toOptionalTrimmedString(record.rpId);
  const credentialIdB64u = toOptionalTrimmedString(record.credentialIdB64u);
  const userId = toOptionalTrimmedString(record.userId);
  const signerSlot = positiveInteger(record.signerSlot);
  if (!rpId || !credentialIdB64u || !userId || signerSlot === null) return null;
  return {
    rpId,
    credentialIdB64u,
    userId,
    signerSlot,
    publicKey: toOptionalTrimmedString(record.publicKey),
    createdAtMs: optionalNonNegativeInteger(record.createdAtMs),
    updatedAtMs: optionalNonNegativeInteger(record.updatedAtMs),
  };
}

function parseNearPublicKey(row: D1RecordJsonRow): NearPublicKeyRecord | null {
  const record = parseJsonObject(row.record_json);
  if (!record) return null;
  const publicKey = toOptionalTrimmedString(record.publicKey);
  const kindRaw = toOptionalTrimmedString(record.kind);
  const kind = parseNearPublicKeyKind(kindRaw);
  if (!publicKey || !kind) return null;
  return {
    publicKey,
    kind,
    signerSlot: optionalNonNegativeInteger(record.signerSlot),
    credentialIdB64u: toOptionalTrimmedString(record.credentialIdB64u),
    rpId: toOptionalTrimmedString(record.rpId),
    createdAtMs: optionalNonNegativeInteger(record.createdAtMs),
    updatedAtMs: optionalNonNegativeInteger(record.updatedAtMs),
  };
}

function parseNearPublicKeyKind(
  input: string | undefined,
): NearPublicKeyRecord['kind'] | null {
  switch (input) {
    case 'threshold':
    case 'local':
    case 'backup':
    case 'ephemeral':
      return input;
    default:
      return null;
  }
}

class CloudflareD1RelayAuthMetadataService {
  private readonly options: CloudflareD1RelayAuthServiceOptions;

  constructor(input: CloudflareD1RelayAuthServiceOptions) {
    this.options = normalizeD1RelayAuthOptions(input);
  }

  async listIdentities(input: ListIdentitiesInput): Promise<ListIdentitiesResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const result = await this.scopePrepare(
        `SELECT subject
           FROM signer_identity_links
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY created_at_ms ASC`,
        [userId],
      ).all<D1SubjectRow>();
      const subjects: string[] = [];
      for (const row of result.results || []) {
        const subject = toOptionalTrimmedString(row.subject);
        if (subject) subjects.push(subject);
      }
      return { ok: true, subjects };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list identities',
      };
    }
  }

  async getOrCreateAppSessionVersion(
    input: GetOrCreateAppSessionVersionInput,
  ): Promise<GetOrCreateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const existing = await this.readAppSessionVersion(userId);
      if (existing) return { ok: true, appSessionVersion: existing };
      const now = Date.now();
      const next = appSessionVersion();
      await this.scopePrepare(
        `INSERT INTO signer_app_session_versions (
          namespace,
          org_id,
          project_id,
          env_id,
          user_id,
          session_version,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, user_id) DO NOTHING`,
        [
          userId,
          next,
          JSON.stringify(
            appSessionRecord({
              userId,
              appSessionVersion: next,
              createdAtMs: now,
              updatedAtMs: now,
            }),
          ),
          now,
          now,
        ],
      ).run();
      return { ok: true, appSessionVersion: (await this.readAppSessionVersion(userId)) || next };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to ensure app session version',
      };
    }
  }

  async rotateAppSessionVersion(
    input: RotateAppSessionVersionInput,
  ): Promise<RotateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const existing = await this.scopePrepare(
        `SELECT record_json
           FROM signer_app_session_versions
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          LIMIT 1`,
        [userId],
      ).first<D1SessionRow>();
      const now = Date.now();
      const next = appSessionVersion();
      const createdAtMs = parseAppSessionCreatedAt(existing?.record_json, now);
      await this.scopePrepare(
        `INSERT INTO signer_app_session_versions (
          namespace,
          org_id,
          project_id,
          env_id,
          user_id,
          session_version,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, user_id)
        DO UPDATE SET
          session_version = EXCLUDED.session_version,
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms`,
        [
          userId,
          next,
          JSON.stringify(
            appSessionRecord({
              userId,
              appSessionVersion: next,
              createdAtMs,
              updatedAtMs: now,
            }),
          ),
          createdAtMs,
          now,
        ],
      ).run();
      return { ok: true, appSessionVersion: next };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to rotate app session version',
      };
    }
  }

  async validateAppSessionVersion(
    input: ValidateAppSessionVersionInput,
  ): Promise<ValidateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const appSession = toOptionalTrimmedString(input.appSessionVersion);
      if (!userId || !appSession) {
        return { ok: false, code: 'unauthorized', message: 'Invalid app session' };
      }
      const current = await this.readAppSessionVersion(userId);
      if (!current || current !== appSession) {
        return { ok: false, code: 'invalid_session_version', message: 'App session revoked' };
      }
      return { ok: true };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to validate app session version',
      };
    }
  }

  async listWebAuthnAuthenticatorsForUser(
    input: ListWebAuthnAuthenticatorsInput,
  ): Promise<ListWebAuthnAuthenticatorsResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const rpId = toOptionalTrimmedString(input.rpId);
      const authRows = await this.readWebAuthnAuthenticatorRows(userId);
      const bindingRows = await this.readWebAuthnBindingRows({ userId, rpId });
      const authByCredentialId = new Map<string, D1AuthenticatorRow>();
      for (const row of authRows) {
        const credentialId = toOptionalTrimmedString(row.credential_id_b64u);
        if (credentialId) authByCredentialId.set(credentialId, row);
      }
      const authenticators: NonNullable<
        ListWebAuthnAuthenticatorsResult['authenticators']
      > = [];
      for (const row of bindingRows) {
        const binding = parseWebAuthnBinding(row);
        if (!binding) continue;
        const authenticator = authByCredentialId.get(binding.credentialIdB64u);
        authenticators.push({
          credentialIdB64u: binding.credentialIdB64u,
          signerSlot: binding.signerSlot,
          publicKey: binding.publicKey,
          createdAtMs:
            optionalNonNegativeInteger(authenticator?.created_at_ms) ?? binding.createdAtMs,
          updatedAtMs:
            optionalNonNegativeInteger(authenticator?.updated_at_ms) ?? binding.updatedAtMs,
        });
      }
      authenticators.sort(compareAuthenticatorSlots);
      return { ok: true, authenticators };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list authenticators',
      };
    }
  }

  async listNearPublicKeysForUser(
    input: ListNearPublicKeysInput,
  ): Promise<ListNearPublicKeysResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const result = await this.scopePrepare(
        `SELECT record_json
           FROM signer_near_public_keys
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY COALESCE(signer_slot, 0) ASC, created_at_ms ASC, public_key ASC`,
        [userId],
      ).all<D1RecordJsonRow>();
      const keys: NonNullable<ListNearPublicKeysResult['keys']> = [];
      for (const row of result.results || []) {
        const record = parseNearPublicKey(row);
        if (!record) continue;
        keys.push({
          publicKey: record.publicKey,
          kind: record.kind,
          signerSlot: record.signerSlot,
          createdAtMs: record.createdAtMs,
          updatedAtMs: record.updatedAtMs,
          rpId: record.rpId,
          credentialIdB64u: record.credentialIdB64u,
        });
      }
      return { ok: true, keys };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list keys',
      };
    }
  }

  getGoogleOidcPublicConfig(): ReturnType<CloudflareRelayAuthService['getGoogleOidcPublicConfig']> {
    const clientId = toOptionalTrimmedString(this.options.googleOidcClientId);
    return {
      configured: Boolean(clientId),
      ...(clientId ? { clientId } : {}),
    };
  }

  private scopePrepare(sql: string, values: readonly unknown[]): D1PreparedStatementLike {
    return this.options.database
      .prepare(sql)
      .bind(
        this.options.namespace,
        this.options.orgId,
        this.options.projectId,
        this.options.envId,
        ...values,
      );
  }

  private async readAppSessionVersion(userId: string): Promise<string | null> {
    const row = await this.scopePrepare(
      `SELECT session_version
         FROM signer_app_session_versions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        LIMIT 1`,
      [userId],
    ).first<D1SessionRow>();
    return toOptionalTrimmedString(row?.session_version) || null;
  }

  private async readWebAuthnAuthenticatorRows(userId: string): Promise<D1AuthenticatorRow[]> {
    const result = await this.scopePrepare(
      `SELECT credential_id_b64u, created_at_ms, updated_at_ms
         FROM signer_webauthn_authenticators
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        ORDER BY created_at_ms ASC`,
      [userId],
    ).all<D1AuthenticatorRow>();
    return [...(result.results || [])];
  }

  private async readWebAuthnBindingRows(input: {
    readonly userId: string;
    readonly rpId?: string;
  }): Promise<D1RecordJsonRow[]> {
    const rpId = toOptionalTrimmedString(input.rpId);
    const sql = rpId
      ? `SELECT record_json
           FROM signer_webauthn_credential_bindings
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
            AND rp_id = ?
          ORDER BY signer_slot ASC`
      : `SELECT record_json
           FROM signer_webauthn_credential_bindings
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY signer_slot ASC`;
    const values = rpId ? [input.userId, rpId] : [input.userId];
    const result = await this.scopePrepare(sql, values).all<D1RecordJsonRow>();
    return [...(result.results || [])];
  }
}

function compareAuthenticatorSlots(
  left: NonNullable<ListWebAuthnAuthenticatorsResult['authenticators']>[number],
  right: NonNullable<ListWebAuthnAuthenticatorsResult['authenticators']>[number],
): number {
  return (Number(left.signerSlot || 0) || 0) - (Number(right.signerSlot || 0) || 0);
}

export function createCloudflareD1RelayAuthService(
  input: CloudflareD1RelayAuthServiceOptions,
): CloudflareRelayAuthService {
  const service = createDisabledCloudflareRelayAuthService({
    relayerAccount: input.relayerAccount,
    relayerPublicKey: input.relayerPublicKey,
  });
  const metadata = new CloudflareD1RelayAuthMetadataService(input);
  service.listIdentities = metadata.listIdentities.bind(metadata);
  service.getOrCreateAppSessionVersion = metadata.getOrCreateAppSessionVersion.bind(metadata);
  service.rotateAppSessionVersion = metadata.rotateAppSessionVersion.bind(metadata);
  service.validateAppSessionVersion = metadata.validateAppSessionVersion.bind(metadata);
  service.listWebAuthnAuthenticatorsForUser =
    metadata.listWebAuthnAuthenticatorsForUser.bind(metadata);
  service.listNearPublicKeysForUser = metadata.listNearPublicKeysForUser.bind(metadata);
  service.getGoogleOidcPublicConfig = metadata.getGoogleOidcPublicConfig.bind(metadata);
  return service;
}
