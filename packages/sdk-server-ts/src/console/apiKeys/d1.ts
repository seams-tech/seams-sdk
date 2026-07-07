import { normalizeCorsOrigin } from '../../core/SessionService';
import {
  d1Integer as toNumber,
  d1ChangedRows,
  formatD1ExecStatement,
  parseD1JsonArrayColumn as parseJsonArray,
  parseD1JsonObjectColumn as parseJsonObject,
  type D1Row,
} from '../../storage/d1Sql';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import {
  isApiCredentialScope,
  type ApiCredentialScope,
} from '../../../../console-shared-ts/src/apiKeyScopes';
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
  AuthenticateConsoleApiKeyRequest,
  AuthenticateConsoleApiKeyResult,
  AuthenticateConsolePublishableKeyRequest,
  AuthenticateConsolePublishableKeyResult,
  ConsoleApiKey,
  ConsoleApiKeyStatus,
  ConsoleCredentialKind,
  CreateConsoleApiKeyRequest,
  CreateConsoleApiKeyResult,
  RevokeConsoleApiKeyRequest,
  RotateConsoleApiKeyRequest,
  RotateConsoleApiKeyResult,
  UpdateConsoleApiKeyRequest,
} from './types';
import type { ConsoleApiKeysContext, ConsoleApiKeyService } from './service';


interface StoredApiKey extends ConsoleApiKey {
  readonly secretHash: string;
  readonly keyPrefix: string;
}

interface D1ConsoleApiKeyState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

type ApiKeySecretFingerprint = {
  readonly kind: ConsoleCredentialKind;
  readonly keyPrefix: string;
  readonly secretHash: string;
};

export const CONSOLE_API_KEYS_D1_RUNTIME = Symbol('consoleApiKeysD1Runtime');

export interface ConsoleApiKeysD1Runtime {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

export type ConsoleApiKeysD1Service = ConsoleApiKeyService & {
  readonly [CONSOLE_API_KEYS_D1_RUNTIME]: ConsoleApiKeysD1Runtime;
};

export interface D1ConsoleApiKeysSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1ConsoleApiKeysServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

export const CONSOLE_API_KEYS_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS api_keys (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      kind TEXT NOT NULL,
      name TEXT NOT NULL,
      environment_id TEXT NOT NULL,
      key_prefix TEXT NOT NULL,
      scopes_json TEXT NOT NULL,
      ip_allowlist_json TEXT NOT NULL,
      allowed_origins_json TEXT NOT NULL,
      rate_limit_bucket TEXT NOT NULL,
      quota_bucket TEXT NOT NULL,
      risk_policy_json TEXT NOT NULL,
      payment_policy_json TEXT NOT NULL,
      status TEXT NOT NULL,
      secret_hash TEXT NOT NULL,
      secret_version INTEGER NOT NULL,
      secret_preview TEXT NOT NULL,
      last_used_at_ms INTEGER,
      expires_at_ms INTEGER,
      revoked_reason TEXT,
      endpoint_usage_counts_json TEXT NOT NULL,
      anomaly_flags_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (kind IN ('secret_key', 'publishable_key')),
      CHECK (status IN ('ACTIVE', 'REVOKED')),
      CHECK (secret_version >= 1),
      CHECK (json_valid(scopes_json)),
      CHECK (json_valid(ip_allowlist_json)),
      CHECK (json_valid(allowed_origins_json)),
      CHECK (json_valid(risk_policy_json)),
      CHECK (json_valid(payment_policy_json)),
      CHECK (json_valid(endpoint_usage_counts_json)),
      CHECK (json_valid(anomaly_flags_json)),
      CHECK (
        (kind = 'secret_key'
          AND allowed_origins_json = '[]'
          AND rate_limit_bucket = ''
          AND quota_bucket = ''
          AND risk_policy_json = '{}'
          AND payment_policy_json = '{}')
        OR
        (kind = 'publishable_key'
          AND scopes_json = '[]'
          AND ip_allowlist_json = '[]')
      )
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS api_keys_namespace_id_uidx
      ON api_keys (namespace, id)
  `,
  `
    CREATE INDEX IF NOT EXISTS api_keys_org_updated_idx
      ON api_keys (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS api_keys_org_status_idx
      ON api_keys (namespace, org_id, status)
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS api_keys_auth_lookup_uidx
      ON api_keys (namespace, kind, key_prefix, secret_hash)
  `,
] as const);

export async function ensureConsoleApiKeysD1Schema(
  options: D1ConsoleApiKeysSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_API_KEYS_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleApiKeysD1Runtime(
  service: ConsoleApiKeyService | null | undefined,
): ConsoleApiKeysD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (service as Partial<ConsoleApiKeysD1Service>)[CONSOLE_API_KEYS_D1_RUNTIME] || null;
}

export async function createD1ConsoleApiKeyService(
  options: D1ConsoleApiKeysServiceOptions,
): Promise<ConsoleApiKeysD1Service> {
  const state: D1ConsoleApiKeyState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
  };
  if (options.ensureSchema !== false) {
    await ensureConsoleApiKeysD1Schema({ database: state.database });
  }
  return new D1ConsoleApiKeyServiceImpl(state) as ConsoleApiKeysD1Service;
}

function defaultNow(): Date {
  return new Date();
}

function ensureNamespace(namespace: string | undefined): string {
  const normalized = String(namespace || 'default').trim();
  return normalized || 'default';
}

function nowMs(now: Date): number {
  return now.getTime();
}

function toIso(ms: number): string {
  return new Date(ms).toISOString();
}

function toNullableIso(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null;
  const parsed = toNumber(value, 0);
  return parsed > 0 ? toIso(parsed) : null;
}


function toNullableMs(value: string | null): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? Math.floor(parsed) : null;
}

function normalizeString(value: unknown): string {
  return String(value || '').trim();
}

function parseStringArray(raw: unknown): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of parseJsonArray(raw)) {
    const value = normalizeString(entry);
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function parseApiCredentialScopes(raw: unknown): ApiCredentialScope[] {
  const scopes = parseStringArray(raw);
  const out: ApiCredentialScope[] = [];
  for (const scope of scopes) {
    if (!isApiCredentialScope(scope)) {
      throw new Error(`Unexpected persisted API credential scope: ${scope}`);
    }
    out.push(scope);
  }
  return out;
}

function normalizeApiCredentialScopes(input: readonly string[] | undefined): ApiCredentialScope[] {
  if (!Array.isArray(input)) return [];
  const out: ApiCredentialScope[] = [];
  const seen = new Set<string>();
  for (const raw of input) {
    const value = normalizeString(raw);
    if (!value) continue;
    if (!isApiCredentialScope(value)) {
      throw new ConsoleApiKeyError('invalid_body', 400, `Invalid secret_key scope: ${value}`);
    }
    const dedupeKey = value.toLowerCase();
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push(value);
  }
  return out;
}

function parseUsageCounts(raw: unknown): Record<string, number> {
  const source = parseJsonObject(raw);
  const out: Record<string, number> = {};
  for (const [keyRaw, valueRaw] of Object.entries(source)) {
    const key = normalizeString(keyRaw);
    if (!key) continue;
    const value = Number(valueRaw);
    if (!Number.isFinite(value) || value < 0) continue;
    out[key] = Math.floor(value);
  }
  return out;
}

function cloneJsonObject(input: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!input) return undefined;
  return { ...input };
}

function jsonArrayText(input: readonly unknown[]): string {
  return JSON.stringify(input);
}

function jsonObjectText(input: Record<string, unknown> | undefined): string {
  return JSON.stringify(input || {});
}

function parseApiKeyKind(value: unknown): ConsoleCredentialKind {
  const normalized = normalizeString(value);
  switch (normalized) {
    case 'secret_key':
    case '':
      return 'secret_key';
    case 'publishable_key':
      return 'publishable_key';
    default:
      throw new Error(`Invalid console API key kind row: ${normalized}`);
  }
}

function parseApiKeyStatus(value: unknown): ConsoleApiKeyStatus {
  const normalized = normalizeString(value);
  switch (normalized) {
    case 'ACTIVE':
    case 'REVOKED':
      return normalized;
    default:
      throw new Error(`Invalid console API key status row: ${normalized || 'empty'}`);
  }
}

function parseApiKeyRow(row: D1Row): StoredApiKey {
  const kind = parseApiKeyKind(row.kind);
  const common = {
    id: normalizeString(row.id),
    kind,
    orgId: normalizeString(row.org_id),
    name: normalizeString(row.name),
    environmentId: normalizeString(row.environment_id),
    status: parseApiKeyStatus(row.status),
    secretVersion: toNumber(row.secret_version, 1),
    secretPreview: normalizeString(row.secret_preview),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
    lastUsedAt: toNullableIso(row.last_used_at_ms),
    expiresAt: toNullableIso(row.expires_at_ms),
    revokedReason: row.revoked_reason == null ? null : normalizeString(row.revoked_reason),
    endpointUsageCounts: parseUsageCounts(row.endpoint_usage_counts_json),
    anomalyFlags: parseStringArray(row.anomaly_flags_json),
    secretHash: normalizeString(row.secret_hash),
    keyPrefix: normalizeString(row.key_prefix),
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
      allowedOrigins: parseStringArray(row.allowed_origins_json),
      rateLimitBucket: normalizeString(row.rate_limit_bucket),
      quotaBucket: normalizeString(row.quota_bucket),
      riskPolicy: parseJsonObject(row.risk_policy_json),
      paymentPolicy: parseJsonObject(row.payment_policy_json),
    };
  }
  return {
    ...common,
    scopes: parseApiCredentialScopes(row.scopes_json),
    ipAllowlist: parseStringArray(row.ip_allowlist_json),
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
  } satisfies Omit<
    ConsoleApiKey,
    | 'scopes'
    | 'ipAllowlist'
    | 'allowedOrigins'
    | 'rateLimitBucket'
    | 'quotaBucket'
    | 'riskPolicy'
    | 'paymentPolicy'
  >;
  if (input.kind === 'publishable_key') {
    return {
      ...common,
      allowedOrigins: [...(input.allowedOrigins || [])],
      rateLimitBucket: normalizeString(input.rateLimitBucket),
      quotaBucket: normalizeString(input.quotaBucket),
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

function hasAnyDefinedField(input: UpdateConsoleApiKeyRequest): boolean {
  return Object.values(input).some((value) => value !== undefined);
}

function hasRequiredScopes(
  scopes: readonly ApiCredentialScope[],
  requiredScopes: readonly ApiCredentialScope[],
): boolean {
  if (!requiredScopes.length) return true;
  const available = new Set(
    scopes.map((scope) => normalizeString(scope).toLowerCase()).filter(Boolean),
  );
  for (const scope of requiredScopes) {
    const normalized = normalizeString(scope).toLowerCase();
    if (!normalized) continue;
    if (!available.has(normalized)) return false;
  }
  return true;
}

function isAllowedOrigin(apiKey: StoredApiKey, rawOrigin: string): boolean {
  const origin = normalizeCorsOrigin(rawOrigin) || '';
  if (!origin) return false;
  const allowedOrigins = apiKey.kind === 'publishable_key' ? apiKey.allowedOrigins || [] : [];
  return allowedOrigins.some((entry) => (normalizeCorsOrigin(entry) || '') === origin);
}

function apiKeyColumnValues(apiKey: StoredApiKey): readonly unknown[] {
  const scopes = apiKey.kind === 'secret_key' ? apiKey.scopes || [] : [];
  const ipAllowlist = apiKey.kind === 'secret_key' ? apiKey.ipAllowlist || [] : [];
  const allowedOrigins = apiKey.kind === 'publishable_key' ? apiKey.allowedOrigins || [] : [];
  const rateLimitBucket = apiKey.kind === 'publishable_key' ? apiKey.rateLimitBucket || '' : '';
  const quotaBucket = apiKey.kind === 'publishable_key' ? apiKey.quotaBucket || '' : '';
  const riskPolicy = apiKey.kind === 'publishable_key' ? apiKey.riskPolicy || {} : {};
  const paymentPolicy = apiKey.kind === 'publishable_key' ? apiKey.paymentPolicy || {} : {};
  return [
    apiKey.name,
    apiKey.environmentId,
    apiKey.keyPrefix,
    jsonArrayText(scopes),
    jsonArrayText(ipAllowlist),
    jsonArrayText(allowedOrigins),
    rateLimitBucket,
    quotaBucket,
    jsonObjectText(riskPolicy),
    jsonObjectText(paymentPolicy),
    apiKey.status,
    apiKey.secretHash,
    apiKey.secretVersion,
    apiKey.secretPreview,
    apiKey.lastUsedAt ? Date.parse(apiKey.lastUsedAt) : null,
    toNullableMs(apiKey.expiresAt),
    apiKey.revokedReason,
    jsonObjectText(apiKey.endpointUsageCounts),
    jsonArrayText(apiKey.anomalyFlags),
    Date.parse(apiKey.updatedAt),
  ];
}

function applyApiKeyUpdate(
  apiKey: StoredApiKey,
  request: UpdateConsoleApiKeyRequest,
  updatedAt: string,
): StoredApiKey {
  const expiresAt = request.expiresAt === undefined ? apiKey.expiresAt : request.expiresAt;
  if (apiKey.kind === 'publishable_key') {
    if (request.scopes !== undefined || request.ipAllowlist !== undefined) {
      throw new ConsoleApiKeyError(
        'invalid_body',
        400,
        'Fields scopes and ipAllowlist are not valid for publishable_key',
      );
    }
    return {
      ...apiKey,
      name: request.name !== undefined ? request.name : apiKey.name,
      allowedOrigins:
        request.allowedOrigins !== undefined
          ? [...request.allowedOrigins]
          : [...(apiKey.allowedOrigins || [])],
      rateLimitBucket:
        request.rateLimitBucket !== undefined ? request.rateLimitBucket : apiKey.rateLimitBucket,
      quotaBucket: request.quotaBucket !== undefined ? request.quotaBucket : apiKey.quotaBucket,
      riskPolicy:
        request.riskPolicy !== undefined
          ? cloneJsonObject(request.riskPolicy) || {}
          : cloneJsonObject(apiKey.riskPolicy) || {},
      paymentPolicy:
        request.paymentPolicy !== undefined
          ? cloneJsonObject(request.paymentPolicy) || {}
          : cloneJsonObject(apiKey.paymentPolicy) || {},
      expiresAt,
      updatedAt,
    };
  }
  if (
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
  return {
    ...apiKey,
    name: request.name !== undefined ? request.name : apiKey.name,
    scopes:
      request.scopes !== undefined
        ? normalizeApiCredentialScopes(request.scopes)
        : [...(apiKey.scopes || [])],
    ipAllowlist:
      request.ipAllowlist !== undefined
        ? [...request.ipAllowlist]
        : [...(apiKey.ipAllowlist || [])],
    expiresAt,
    updatedAt,
  };
}


class D1ConsoleApiKeyServiceImpl implements ConsoleApiKeyService {
  readonly [CONSOLE_API_KEYS_D1_RUNTIME]: ConsoleApiKeysD1Runtime;

  private readonly state: D1ConsoleApiKeyState;

  constructor(state: D1ConsoleApiKeyState) {
    this.state = state;
    this[CONSOLE_API_KEYS_D1_RUNTIME] = {
      database: state.database,
      namespace: state.namespace,
      now: state.now,
    };
    this.listApiKeys = this.listApiKeys.bind(this);
    this.createApiKey = this.createApiKey.bind(this);
    this.revokeApiKey = this.revokeApiKey.bind(this);
    this.deleteApiKey = this.deleteApiKey.bind(this);
    this.rotateApiKey = this.rotateApiKey.bind(this);
    this.updateApiKey = this.updateApiKey.bind(this);
    this.authenticateApiKey = this.authenticateApiKey.bind(this);
    this.authenticatePublishableKey = this.authenticatePublishableKey.bind(this);
  }

  async listApiKeys(ctx: ConsoleApiKeysContext): Promise<ConsoleApiKey[]> {
    const out = await this.state.database
      .prepare(
        `SELECT *
           FROM api_keys
          WHERE namespace = ? AND org_id = ?
          ORDER BY updated_at_ms DESC, created_at_ms DESC`,
      )
      .bind(this.state.namespace, ctx.orgId)
      .all<D1Row>();
    return (out.results || []).map((row) => toPublicApiKey(parseApiKeyRow(row)));
  }

  async createApiKey(
    ctx: ConsoleApiKeysContext,
    request: CreateConsoleApiKeyRequest,
  ): Promise<CreateConsoleApiKeyResult> {
    const now = this.state.now();
    const iso = toIso(nowMs(now));
    const secret = makeApiKeySecret({ kind: request.kind });
    const apiKey = await this.buildNewApiKey({
      orgId: ctx.orgId,
      request,
      now,
      iso,
      secret,
    });
    await this.insertApiKey(apiKey);
    return {
      apiKey: toPublicApiKey(apiKey),
      secret,
    };
  }

  async revokeApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
    request?: RevokeConsoleApiKeyRequest,
  ): Promise<{ revoked: boolean; apiKey: ConsoleApiKey | null }> {
    const current = await this.findApiKey(ctx.orgId, apiKeyId);
    if (!current) return { revoked: false, apiKey: null };
    if (current.status === 'REVOKED') {
      return { revoked: true, apiKey: toPublicApiKey(current) };
    }

    const updatedAtMs = nowMs(this.state.now());
    await this.state.database
      .prepare(
        `UPDATE api_keys
            SET status = 'REVOKED',
                revoked_reason = ?,
                updated_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND id = ?`,
      )
      .bind(
        normalizeString(request?.reason) || null,
        updatedAtMs,
        this.state.namespace,
        ctx.orgId,
        apiKeyId,
      )
      .run();
    const updated = await this.findApiKey(ctx.orgId, apiKeyId);
    return { revoked: true, apiKey: updated ? toPublicApiKey(updated) : toPublicApiKey(current) };
  }

  async deleteApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
  ): Promise<{ deleted: boolean; apiKey: ConsoleApiKey | null }> {
    const current = await this.findApiKey(ctx.orgId, apiKeyId);
    if (!current) return { deleted: false, apiKey: null };
    if (current.status !== 'REVOKED') {
      throw new ConsoleApiKeyError(
        'api_key_not_revoked',
        409,
        `API key ${apiKeyId} must be revoked before it can be deleted`,
      );
    }

    const result = await this.state.database
      .prepare(
        `DELETE FROM api_keys
          WHERE namespace = ? AND org_id = ? AND id = ?`,
      )
      .bind(this.state.namespace, ctx.orgId, apiKeyId)
      .run();
    return {
      deleted: d1ChangedRows(result) > 0,
      apiKey: toPublicApiKey(current),
    };
  }

  async rotateApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
    _request?: RotateConsoleApiKeyRequest,
  ): Promise<RotateConsoleApiKeyResult | null> {
    const current = await this.findApiKey(ctx.orgId, apiKeyId);
    if (!current) return null;
    if (current.status === 'REVOKED') {
      throw new ConsoleApiKeyError(
        'api_key_revoked',
        409,
        `API key ${apiKeyId} is revoked and cannot be rotated`,
      );
    }

    const now = this.state.now();
    const secret = makeApiKeySecret({ kind: current.kind });
    const updatedAt = toIso(nowMs(now));
    const rotated: StoredApiKey = {
      ...current,
      secretHash: await hashApiKeySecret(secret),
      keyPrefix: makeApiKeyLookupPrefix(secret),
      secretVersion: current.secretVersion + 1,
      secretPreview: makeSecretPreview(secret),
      updatedAt,
    };
    await this.updateStoredApiKey(rotated);
    const refreshed = await this.findApiKey(ctx.orgId, apiKeyId);
    return {
      apiKey: toPublicApiKey(refreshed || rotated),
      secret,
    };
  }

  async updateApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
    request: UpdateConsoleApiKeyRequest,
  ): Promise<ConsoleApiKey | null> {
    const current = await this.findApiKey(ctx.orgId, apiKeyId);
    if (!current) return null;
    if (!hasAnyDefinedField(request)) return toPublicApiKey(current);

    const updated = applyApiKeyUpdate(current, request, toIso(nowMs(this.state.now())));
    await this.updateStoredApiKey(updated);
    const refreshed = await this.findApiKey(ctx.orgId, apiKeyId);
    return refreshed ? toPublicApiKey(refreshed) : toPublicApiKey(updated);
  }

  async authenticateApiKey(
    request: AuthenticateConsoleApiKeyRequest,
  ): Promise<AuthenticateConsoleApiKeyResult> {
    const secret = normalizeString(request.secret);
    if (!secret) {
      return {
        ok: false,
        status: 401,
        code: 'secret_key_missing',
        message: 'Missing secret key',
      };
    }

    const parsed = parseApiKeySecret(secret);
    if (!parsed || parsed.kind !== 'secret_key') {
      return {
        ok: false,
        status: 401,
        code: 'secret_key_invalid',
        message: 'Invalid secret key',
      };
    }

    const keyRow = await this.findApiKeyBySecretFingerprint({
      kind: parsed.kind,
      keyPrefix: makeApiKeyLookupPrefix(secret),
      secretHash: await hashApiKeySecret(secret),
    });
    if (!keyRow) {
      return {
        ok: false,
        status: 401,
        code: 'secret_key_invalid',
        message: 'Invalid secret key',
      };
    }

    const currentNowMs = nowMs(this.state.now());
    if (keyRow.status === 'REVOKED') {
      await this.appendAnomalyFlag(keyRow, 'auth.revoked_attempt', currentNowMs);
      return {
        ok: false,
        status: 403,
        code: 'secret_key_revoked',
        message: 'Secret key has been revoked',
      };
    }

    if (keyRow.expiresAt) {
      const expiresAtMs = Date.parse(keyRow.expiresAt);
      if (Number.isFinite(expiresAtMs) && expiresAtMs <= currentNowMs) {
        await this.appendAnomalyFlag(keyRow, 'auth.expired_attempt', currentNowMs);
        return {
          ok: false,
          status: 403,
          code: 'secret_key_revoked',
          message: 'Secret key has expired',
        };
      }
    }

    const requestEnvironmentId = normalizeString(request.environmentId);
    if (requestEnvironmentId && requestEnvironmentId !== keyRow.environmentId) {
      await this.appendAnomalyFlag(keyRow, 'auth.environment_mismatch', currentNowMs);
      return {
        ok: false,
        status: 403,
        code: 'secret_key_environment_mismatch',
        message: 'Secret key is not valid for the requested environment',
      };
    }

    if (!hasRequiredScopes(keyRow.scopes || [], request.requiredScopes || [])) {
      await this.appendAnomalyFlag(keyRow, 'auth.scope_denied', currentNowMs);
      return {
        ok: false,
        status: 403,
        code: 'secret_key_forbidden_scope',
        message: 'Secret key does not grant required scope',
      };
    }

    if (!isIpAllowlistMatch({ allowlist: keyRow.ipAllowlist || [], sourceIp: request.sourceIp })) {
      await this.appendAnomalyFlag(keyRow, 'auth.ip_blocked', currentNowMs);
      return {
        ok: false,
        status: 403,
        code: 'secret_key_ip_blocked',
        message: 'Secret key is blocked for this source IP',
      };
    }

    const refreshed = await this.recordApiKeyUse(keyRow, {
      endpoint: normalizeString(request.endpoint),
      nowMsValue: currentNowMs,
      incrementEndpointUsage: true,
    });
    return {
      ok: true,
      apiKey: toPublicApiKey(refreshed || keyRow),
    };
  }

  async authenticatePublishableKey(
    request: AuthenticateConsolePublishableKeyRequest,
  ): Promise<AuthenticateConsolePublishableKeyResult> {
    const secret = normalizeString(request.secret);
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

    const keyRow = await this.findApiKeyBySecretFingerprint({
      kind: parsed.kind,
      keyPrefix: makeApiKeyLookupPrefix(secret),
      secretHash: await hashApiKeySecret(secret),
    });
    if (!keyRow) {
      return {
        ok: false,
        status: 401,
        code: 'publishable_key_invalid',
        message: 'Invalid publishable key',
      };
    }

    const currentNowMs = nowMs(this.state.now());
    if (keyRow.status === 'REVOKED') {
      await this.appendAnomalyFlag(
        keyRow,
        'auth.publishable_key_revoked_attempt',
        currentNowMs,
      );
      return {
        ok: false,
        status: 403,
        code: 'publishable_key_revoked',
        message: 'Publishable key has been revoked',
      };
    }

    if (keyRow.expiresAt) {
      const expiresAtMs = Date.parse(keyRow.expiresAt);
      if (Number.isFinite(expiresAtMs) && expiresAtMs <= currentNowMs) {
        await this.appendAnomalyFlag(
          keyRow,
          'auth.publishable_key_expired_attempt',
          currentNowMs,
        );
        return {
          ok: false,
          status: 403,
          code: 'publishable_key_revoked',
          message: 'Publishable key has expired',
        };
      }
    }

    const requestEnvironmentId = normalizeString(request.environmentId);
    if (requestEnvironmentId && requestEnvironmentId !== keyRow.environmentId) {
      await this.appendAnomalyFlag(keyRow, 'auth.environment_mismatch', currentNowMs);
      return {
        ok: false,
        status: 403,
        code: 'publishable_key_environment_mismatch',
        message: 'Publishable key is not valid for the requested environment',
      };
    }

    if (!isAllowedOrigin(keyRow, request.origin)) {
      await this.appendAnomalyFlag(keyRow, 'auth.origin_blocked', currentNowMs);
      return {
        ok: false,
        status: 403,
        code: 'publishable_key_origin_blocked',
        message: buildPublishableKeyOriginBlockedMessage({
          origin: request.origin,
          allowedOrigins: keyRow.kind === 'publishable_key' ? keyRow.allowedOrigins || [] : [],
        }),
      };
    }

    const refreshed = await this.recordApiKeyUse(keyRow, {
      endpoint: '',
      nowMsValue: currentNowMs,
      incrementEndpointUsage: false,
    });
    return {
      ok: true,
      apiKey: toPublicApiKey(refreshed || keyRow),
    };
  }

  private async buildNewApiKey(input: {
    readonly orgId: string;
    readonly request: CreateConsoleApiKeyRequest;
    readonly now: Date;
    readonly iso: string;
    readonly secret: string;
  }): Promise<StoredApiKey> {
    const base = {
      id: makeApiKeyId(input.now),
      orgId: input.orgId,
      name: input.request.name,
      environmentId: input.request.environmentId,
      status: 'ACTIVE',
      secretVersion: 1,
      secretPreview: makeSecretPreview(input.secret),
      createdAt: input.iso,
      updatedAt: input.iso,
      lastUsedAt: null,
      expiresAt: input.request.expiresAt || null,
      revokedReason: null,
      endpointUsageCounts: {},
      anomalyFlags: [],
      secretHash: await hashApiKeySecret(input.secret),
      keyPrefix: makeApiKeyLookupPrefix(input.secret),
    } satisfies Omit<
      StoredApiKey,
      | 'kind'
      | 'scopes'
      | 'ipAllowlist'
      | 'allowedOrigins'
      | 'rateLimitBucket'
      | 'quotaBucket'
      | 'riskPolicy'
      | 'paymentPolicy'
    >;
    if (input.request.kind === 'publishable_key') {
      return {
        ...base,
        kind: 'publishable_key',
        allowedOrigins: [...input.request.allowedOrigins],
        rateLimitBucket: input.request.rateLimitBucket,
        quotaBucket: input.request.quotaBucket,
        riskPolicy: cloneJsonObject(input.request.riskPolicy) || {},
        paymentPolicy: cloneJsonObject(input.request.paymentPolicy) || {},
      };
    }
    return {
      ...base,
      kind: 'secret_key',
      scopes: normalizeApiCredentialScopes(input.request.scopes),
      ipAllowlist: input.request.ipAllowlist ? [...input.request.ipAllowlist] : [],
    };
  }

  private async insertApiKey(apiKey: StoredApiKey): Promise<void> {
    await this.state.database
      .prepare(
        `INSERT INTO api_keys
          (namespace, org_id, id, kind, name, environment_id, key_prefix,
           scopes_json, ip_allowlist_json, allowed_origins_json, rate_limit_bucket,
           quota_bucket, risk_policy_json, payment_policy_json, status, secret_hash,
           secret_version, secret_preview, last_used_at_ms, expires_at_ms,
           revoked_reason, endpoint_usage_counts_json, anomaly_flags_json,
           created_at_ms, updated_at_ms)
         VALUES
          (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?,
           NULL, '{}', '[]', ?, ?)`,
      )
      .bind(
        this.state.namespace,
        apiKey.orgId,
        apiKey.id,
        apiKey.kind,
        ...apiKeyColumnValues(apiKey).slice(0, 14),
        toNullableMs(apiKey.expiresAt),
        Date.parse(apiKey.createdAt),
        Date.parse(apiKey.updatedAt),
      )
      .run();
  }

  private async updateStoredApiKey(apiKey: StoredApiKey): Promise<void> {
    await this.state.database
      .prepare(
        `UPDATE api_keys
            SET name = ?,
                environment_id = ?,
                key_prefix = ?,
                scopes_json = ?,
                ip_allowlist_json = ?,
                allowed_origins_json = ?,
                rate_limit_bucket = ?,
                quota_bucket = ?,
                risk_policy_json = ?,
                payment_policy_json = ?,
                status = ?,
                secret_hash = ?,
                secret_version = ?,
                secret_preview = ?,
                last_used_at_ms = ?,
                expires_at_ms = ?,
                revoked_reason = ?,
                endpoint_usage_counts_json = ?,
                anomaly_flags_json = ?,
                updated_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND id = ?`,
      )
      .bind(
        ...apiKeyColumnValues(apiKey),
        this.state.namespace,
        apiKey.orgId,
        apiKey.id,
      )
      .run();
  }

  private async findApiKey(orgId: string, apiKeyId: string): Promise<StoredApiKey | null> {
    const row = await this.state.database
      .prepare(
        `SELECT *
           FROM api_keys
          WHERE namespace = ? AND org_id = ? AND id = ?`,
      )
      .bind(this.state.namespace, orgId, apiKeyId)
      .first<D1Row>();
    return row ? parseApiKeyRow(row) : null;
  }

  private async findApiKeyBySecretFingerprint(
    input: ApiKeySecretFingerprint,
  ): Promise<StoredApiKey | null> {
    const row = await this.state.database
      .prepare(
        `SELECT *
           FROM api_keys
          WHERE namespace = ?
            AND kind = ?
            AND key_prefix = ?
            AND secret_hash = ?
          LIMIT 1`,
      )
      .bind(this.state.namespace, input.kind, input.keyPrefix, input.secretHash)
      .first<D1Row>();
    return row ? parseApiKeyRow(row) : null;
  }

  private async appendAnomalyFlag(
    input: StoredApiKey,
    anomaly: string,
    nowMsValue: number,
  ): Promise<void> {
    const current = await this.findApiKey(input.orgId, input.id);
    if (!current) return;
    const normalized = normalizeString(anomaly);
    if (!normalized) return;
    const anomalyFlags = current.anomalyFlags.includes(normalized)
      ? current.anomalyFlags
      : [...current.anomalyFlags, normalized];
    await this.state.database
      .prepare(
        `UPDATE api_keys
            SET anomaly_flags_json = ?,
                updated_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND id = ?`,
      )
      .bind(
        jsonArrayText(anomalyFlags),
        nowMsValue,
        this.state.namespace,
        current.orgId,
        current.id,
      )
      .run();
  }

  private async recordApiKeyUse(
    input: StoredApiKey,
    options: {
      readonly endpoint: string;
      readonly nowMsValue: number;
      readonly incrementEndpointUsage: boolean;
    },
  ): Promise<StoredApiKey | null> {
    const current = await this.findApiKey(input.orgId, input.id);
    if (!current) return null;
    const endpointUsageCounts = { ...current.endpointUsageCounts };
    if (options.incrementEndpointUsage && options.endpoint) {
      const currentCount = Number(endpointUsageCounts[options.endpoint] || 0);
      endpointUsageCounts[options.endpoint] =
        Number.isFinite(currentCount) && currentCount > 0 ? Math.floor(currentCount) + 1 : 1;
    }
    await this.state.database
      .prepare(
        `UPDATE api_keys
            SET last_used_at_ms = ?,
                endpoint_usage_counts_json = ?,
                updated_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND id = ?`,
      )
      .bind(
        options.nowMsValue,
        jsonObjectText(endpointUsageCounts),
        options.nowMsValue,
        this.state.namespace,
        current.orgId,
        current.id,
      )
      .run();
    return await this.findApiKey(current.orgId, current.id);
  }
}
