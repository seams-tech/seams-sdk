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
import { normalizeCorsOrigin } from '@seams/sdk-server/internal/core/SessionService';
import {
  isApiCredentialScope,
  type ApiCredentialScope,
} from "@seams-internal/console-shared/apiKeyScopes";
import type {
  AuthenticateConsoleApiKeyRequest,
  AuthenticateConsoleApiKeyResult,
  AuthenticateConsolePublishableKeyRequest,
  AuthenticateConsolePublishableKeyResult,
  ConsoleApiKey,
  CreateConsoleApiKeyRequest,
  CreateConsoleApiKeyResult,
  RevokeConsoleApiKeyRequest,
  RotateConsoleApiKeyRequest,
  RotateConsoleApiKeyResult,
  UpdateConsoleApiKeyRequest,
} from './types';

interface StoredApiKey extends ConsoleApiKey {
  secretHash: string;
  keyPrefix: string;
}

export interface ConsoleApiKeysContext {
  orgId: string;
  actorUserId: string;
  roles: readonly string[];
}

export interface InMemoryConsoleApiKeyServiceOptions {
  now?: () => Date;
}

export interface ConsoleApiKeyService {
  listApiKeys(ctx: ConsoleApiKeysContext): Promise<ConsoleApiKey[]>;
  createApiKey(
    ctx: ConsoleApiKeysContext,
    request: CreateConsoleApiKeyRequest,
  ): Promise<CreateConsoleApiKeyResult>;
  revokeApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
    request?: RevokeConsoleApiKeyRequest,
  ): Promise<{ revoked: boolean; apiKey: ConsoleApiKey | null }>;
  deleteApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
  ): Promise<{ deleted: boolean; apiKey: ConsoleApiKey | null }>;
  rotateApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
    request?: RotateConsoleApiKeyRequest,
  ): Promise<RotateConsoleApiKeyResult | null>;
  updateApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
    request: UpdateConsoleApiKeyRequest,
  ): Promise<ConsoleApiKey | null>;
  authenticatePublishableKey?(
    request: AuthenticateConsolePublishableKeyRequest,
  ): Promise<AuthenticateConsolePublishableKeyResult>;
  authenticateApiKey?(
    request: AuthenticateConsoleApiKeyRequest,
  ): Promise<AuthenticateConsoleApiKeyResult>;
}

function toIso(date: Date): string {
  return date.toISOString();
}

function cloneJsonObject(input: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!input) return undefined;
  return { ...input };
}

function cloneApiKey(apiKey: StoredApiKey): ConsoleApiKey {
  const common = {
    id: apiKey.id,
    kind: apiKey.kind,
    orgId: apiKey.orgId,
    name: apiKey.name,
    environmentId: apiKey.environmentId,
    status: apiKey.status,
    secretVersion: apiKey.secretVersion,
    secretPreview: apiKey.secretPreview,
    createdAt: apiKey.createdAt,
    updatedAt: apiKey.updatedAt,
    lastUsedAt: apiKey.lastUsedAt,
    expiresAt: apiKey.expiresAt,
    revokedReason: apiKey.revokedReason,
    endpointUsageCounts: { ...apiKey.endpointUsageCounts },
    anomalyFlags: [...apiKey.anomalyFlags],
  } satisfies Omit<ConsoleApiKey, 'scopes' | 'ipAllowlist' | 'allowedOrigins' | 'rateLimitBucket' | 'quotaBucket' | 'riskPolicy' | 'paymentPolicy'>;
  if (apiKey.kind === 'publishable_key') {
    return {
      ...common,
      allowedOrigins: [...(apiKey.allowedOrigins || [])],
      rateLimitBucket: String(apiKey.rateLimitBucket || '').trim(),
      quotaBucket: String(apiKey.quotaBucket || '').trim(),
      riskPolicy: cloneJsonObject(apiKey.riskPolicy),
      paymentPolicy: cloneJsonObject(apiKey.paymentPolicy),
    };
  }
  return {
    ...common,
    scopes: [...(apiKey.scopes || [])],
    ipAllowlist: [...(apiKey.ipAllowlist || [])],
  };
}

function normalizeApiCredentialScopes(input: readonly string[] | undefined): ApiCredentialScope[] {
  if (!Array.isArray(input)) return [];
  const out: ApiCredentialScope[] = [];
  const seen = new Set<string>();
  for (const raw of input) {
    const value = String(raw || '').trim();
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

function hasAnyDefinedField(input: UpdateConsoleApiKeyRequest): boolean {
  return Object.values(input).some((value) => value !== undefined);
}

function applyApiKeyUpdate(apiKey: StoredApiKey, request: UpdateConsoleApiKeyRequest): StoredApiKey {
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
      ...(request.name !== undefined ? { name: request.name } : {}),
      ...(request.allowedOrigins !== undefined ? { allowedOrigins: [...request.allowedOrigins] } : {}),
      ...(request.rateLimitBucket !== undefined ? { rateLimitBucket: request.rateLimitBucket } : {}),
      ...(request.quotaBucket !== undefined ? { quotaBucket: request.quotaBucket } : {}),
      ...(request.riskPolicy !== undefined ? { riskPolicy: cloneJsonObject(request.riskPolicy) || {} } : {}),
      ...(request.paymentPolicy !== undefined
        ? { paymentPolicy: cloneJsonObject(request.paymentPolicy) || {} }
        : {}),
      ...(request.expiresAt !== undefined ? { expiresAt: request.expiresAt } : {}),
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
    ...(request.name !== undefined ? { name: request.name } : {}),
    ...(request.scopes !== undefined ? { scopes: normalizeApiCredentialScopes(request.scopes) } : {}),
    ...(request.ipAllowlist !== undefined ? { ipAllowlist: [...request.ipAllowlist] } : {}),
    ...(request.expiresAt !== undefined ? { expiresAt: request.expiresAt } : {}),
  };
}

export function createInMemoryConsoleApiKeyService(
  opts: InMemoryConsoleApiKeyServiceOptions = {},
): ConsoleApiKeyService {
  const now = opts.now || (() => new Date());
  const stores = new Map<string, Map<string, StoredApiKey>>();

  function requireOrgStore(orgId: string): Map<string, StoredApiKey> {
    let store = stores.get(orgId);
    if (!store) {
      store = new Map<string, StoredApiKey>();
      stores.set(orgId, store);
    }
    return store;
  }

  function sortApiKeys(keys: StoredApiKey[]): StoredApiKey[] {
    return [...keys].sort((a, b) => {
      const updatedCompare = b.updatedAt.localeCompare(a.updatedAt);
      if (updatedCompare !== 0) return updatedCompare;
      return b.createdAt.localeCompare(a.createdAt);
    });
  }

  function markAnomaly(apiKey: StoredApiKey, anomaly: string): void {
    const next = String(anomaly || '').trim();
    if (!next) return;
    if (!apiKey.anomalyFlags.includes(next)) {
      apiKey.anomalyFlags.push(next);
    }
    apiKey.updatedAt = toIso(now());
  }

  function hasRequiredScopes(
    scopes: ApiCredentialScope[],
    requiredScopes: ApiCredentialScope[],
  ): boolean {
    if (!requiredScopes.length) return true;
    const available = new Set(
      scopes.map((scope) => String(scope || '').trim().toLowerCase()).filter(Boolean),
    );
    for (const scope of requiredScopes) {
      const normalized = String(scope || '').trim().toLowerCase();
      if (!normalized) continue;
      if (!available.has(normalized)) return false;
    }
    return true;
  }

  function findBySecretFingerprint(input: {
    kind: 'secret_key' | 'publishable_key';
    keyPrefix: string;
    secretHash: string;
  }): StoredApiKey | null {
    for (const store of stores.values()) {
      for (const apiKey of store.values()) {
        if (apiKey.kind !== input.kind) continue;
        if (apiKey.keyPrefix !== input.keyPrefix) continue;
        if (apiKey.secretHash !== input.secretHash) continue;
        return apiKey;
      }
    }
    return null;
  }

  function isAllowedOrigin(apiKey: StoredApiKey, rawOrigin: string): boolean {
    const origin = normalizeCorsOrigin(rawOrigin) || '';
    if (!origin) return false;
    const allowedOrigins = Array.isArray(apiKey.allowedOrigins) ? apiKey.allowedOrigins : [];
    return allowedOrigins.some((entry) => (normalizeCorsOrigin(entry) || '') === origin);
  }

  return {
    async listApiKeys(ctx): Promise<ConsoleApiKey[]> {
      const store = requireOrgStore(ctx.orgId);
      return sortApiKeys(Array.from(store.values())).map(cloneApiKey);
    },

    async createApiKey(ctx, request): Promise<CreateConsoleApiKeyResult> {
      const createdAt = now();
      const iso = toIso(createdAt);
      const id = makeApiKeyId(createdAt);
      const secret = makeApiKeySecret({ kind: request.kind });
      const secretHash = await hashApiKeySecret(secret);
      const base: Omit<
        StoredApiKey,
        | 'kind'
        | 'scopes'
        | 'ipAllowlist'
        | 'allowedOrigins'
        | 'rateLimitBucket'
        | 'quotaBucket'
        | 'riskPolicy'
        | 'paymentPolicy'
      > = {
        id,
        orgId: ctx.orgId,
        name: request.name,
        environmentId: request.environmentId,
        status: 'ACTIVE',
        secretVersion: 1,
        secretPreview: makeSecretPreview(secret),
        createdAt: iso,
        updatedAt: iso,
        lastUsedAt: null,
        expiresAt: request.expiresAt || null,
        revokedReason: null,
        endpointUsageCounts: {},
        anomalyFlags: [],
        secretHash,
        keyPrefix: makeApiKeyLookupPrefix(secret),
      };
      const apiKey: StoredApiKey =
        request.kind === 'publishable_key'
          ? {
              ...base,
              kind: 'publishable_key',
              allowedOrigins: [...request.allowedOrigins],
              rateLimitBucket: request.rateLimitBucket,
              quotaBucket: request.quotaBucket,
              riskPolicy: cloneJsonObject(request.riskPolicy) || {},
              paymentPolicy: cloneJsonObject(request.paymentPolicy) || {},
            }
          : {
              ...base,
              kind: 'secret_key',
              scopes: normalizeApiCredentialScopes(request.scopes),
              ipAllowlist: request.ipAllowlist ? [...request.ipAllowlist] : [],
            };

      const store = requireOrgStore(ctx.orgId);
      store.set(apiKey.id, apiKey);
      return {
        apiKey: cloneApiKey(apiKey),
        secret,
      };
    },

    async revokeApiKey(
      ctx,
      apiKeyId,
      request,
    ): Promise<{ revoked: boolean; apiKey: ConsoleApiKey | null }> {
      const store = requireOrgStore(ctx.orgId);
      const apiKey = store.get(apiKeyId);
      if (!apiKey) {
        return { revoked: false, apiKey: null };
      }
      if (apiKey.status === 'REVOKED') {
        return { revoked: true, apiKey: cloneApiKey(apiKey) };
      }
      const updated = toIso(now());
      apiKey.status = 'REVOKED';
      apiKey.revokedReason = String(request?.reason || '').trim() || null;
      apiKey.updatedAt = updated;
      return { revoked: true, apiKey: cloneApiKey(apiKey) };
    },

    async deleteApiKey(
      ctx,
      apiKeyId,
    ): Promise<{ deleted: boolean; apiKey: ConsoleApiKey | null }> {
      const store = requireOrgStore(ctx.orgId);
      const apiKey = store.get(apiKeyId);
      if (!apiKey) {
        return { deleted: false, apiKey: null };
      }
      if (apiKey.status !== 'REVOKED') {
        throw new ConsoleApiKeyError(
          'api_key_not_revoked',
          409,
          `API key ${apiKeyId} must be revoked before it can be deleted`,
        );
      }
      const deleted = cloneApiKey(apiKey);
      store.delete(apiKeyId);
      return { deleted: true, apiKey: deleted };
    },

    async rotateApiKey(ctx, apiKeyId, _request): Promise<RotateConsoleApiKeyResult | null> {
      const store = requireOrgStore(ctx.orgId);
      const apiKey = store.get(apiKeyId);
      if (!apiKey) return null;
      if (apiKey.status === 'REVOKED') {
        throw new ConsoleApiKeyError(
          'api_key_revoked',
          409,
          `API key ${apiKeyId} is revoked and cannot be rotated`,
        );
      }
      const rotatedAt = now();
      const secret = makeApiKeySecret({ kind: apiKey.kind });
      apiKey.secretHash = await hashApiKeySecret(secret);
      apiKey.keyPrefix = makeApiKeyLookupPrefix(secret);
      apiKey.secretVersion += 1;
      apiKey.secretPreview = makeSecretPreview(secret);
      apiKey.updatedAt = toIso(rotatedAt);
      return {
        apiKey: cloneApiKey(apiKey),
        secret,
      };
    },

    async updateApiKey(ctx, apiKeyId, request): Promise<ConsoleApiKey | null> {
      const store = requireOrgStore(ctx.orgId);
      const apiKey = store.get(apiKeyId);
      if (!apiKey) return null;
      if (!hasAnyDefinedField(request)) {
        return cloneApiKey(apiKey);
      }
      const next = applyApiKeyUpdate(apiKey, request);
      next.updatedAt = toIso(now());
      store.set(apiKeyId, next);
      return cloneApiKey(next);
    },

    async authenticateApiKey(request): Promise<AuthenticateConsoleApiKeyResult> {
      const secret = String(request.secret || '').trim();
      if (!secret) {
        return {
          ok: false,
          status: 401,
          code: 'secret_key_missing',
          message: 'Missing secret key',
        };
      }

      const parsed = parseApiKeySecret(secret);
      if (!parsed) {
        return {
          ok: false,
          status: 401,
          code: 'secret_key_invalid',
          message: 'Invalid secret key',
        };
      }

      if (parsed.kind !== 'secret_key') {
        return {
          ok: false,
          status: 401,
          code: 'secret_key_invalid',
          message: 'Invalid secret key',
        };
      }

      const hash = await hashApiKeySecret(secret);
      const keyPrefix = makeApiKeyLookupPrefix(secret);
      const apiKey = findBySecretFingerprint({
        kind: parsed.kind,
        keyPrefix,
        secretHash: hash,
      });
      if (!apiKey) {
        return {
          ok: false,
          status: 401,
          code: 'secret_key_invalid',
          message: 'Invalid secret key',
        };
      }

      if (apiKey.status === 'REVOKED') {
        markAnomaly(apiKey, 'auth.revoked_attempt');
        return {
          ok: false,
          status: 403,
          code: 'secret_key_revoked',
          message: 'Secret key has been revoked',
        };
      }

      if (apiKey.kind !== 'secret_key') {
        markAnomaly(apiKey, 'auth.invalid_kind');
        return {
          ok: false,
          status: 401,
          code: 'secret_key_invalid',
          message: 'Invalid secret key',
        };
      }

      if (apiKey.expiresAt) {
        const expiresAtMs = Date.parse(apiKey.expiresAt);
        if (Number.isFinite(expiresAtMs) && expiresAtMs <= now().getTime()) {
          markAnomaly(apiKey, 'auth.expired_attempt');
          return {
            ok: false,
            status: 403,
            code: 'secret_key_revoked',
            message: 'Secret key has expired',
          };
        }
      }

      const requestEnvironmentId = String(request.environmentId || '').trim();
      if (requestEnvironmentId && requestEnvironmentId !== apiKey.environmentId) {
        markAnomaly(apiKey, 'auth.environment_mismatch');
        return {
          ok: false,
          status: 403,
          code: 'secret_key_environment_mismatch',
          message: 'Secret key is not valid for the requested environment',
        };
      }

      if (!hasRequiredScopes(apiKey.scopes || [], request.requiredScopes || [])) {
        markAnomaly(apiKey, 'auth.scope_denied');
        return {
          ok: false,
          status: 403,
          code: 'secret_key_forbidden_scope',
          message: 'Secret key does not grant required scope',
        };
      }

      if (!isIpAllowlistMatch({ allowlist: apiKey.ipAllowlist || [], sourceIp: request.sourceIp })) {
        markAnomaly(apiKey, 'auth.ip_blocked');
        return {
          ok: false,
          status: 403,
          code: 'secret_key_ip_blocked',
          message: 'Secret key is blocked for this source IP',
        };
      }

      const usedAt = now();
      const endpoint = String(request.endpoint || '').trim();
      apiKey.lastUsedAt = toIso(usedAt);
      apiKey.updatedAt = toIso(usedAt);
      if (endpoint) {
        const current = Number(apiKey.endpointUsageCounts[endpoint] || 0);
        apiKey.endpointUsageCounts[endpoint] =
          Number.isFinite(current) && current > 0 ? current + 1 : 1;
      }

      return {
        ok: true,
        apiKey: cloneApiKey(apiKey),
      };
    },

    async authenticatePublishableKey(
      request,
    ): Promise<AuthenticateConsolePublishableKeyResult> {
      const secret = String(request.secret || '').trim();
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

      const hash = await hashApiKeySecret(secret);
      const keyPrefix = makeApiKeyLookupPrefix(secret);
      const apiKey = findBySecretFingerprint({
        kind: parsed.kind,
        keyPrefix,
        secretHash: hash,
      });
      if (!apiKey) {
        return {
          ok: false,
          status: 401,
          code: 'publishable_key_invalid',
          message: 'Invalid publishable key',
        };
      }

      if (apiKey.status === 'REVOKED') {
        markAnomaly(apiKey, 'auth.publishable_key_revoked_attempt');
        return {
          ok: false,
          status: 403,
          code: 'publishable_key_revoked',
          message: 'Publishable key has been revoked',
        };
      }

      if (apiKey.kind !== 'publishable_key') {
        markAnomaly(apiKey, 'auth.invalid_kind');
        return {
          ok: false,
          status: 401,
          code: 'publishable_key_invalid',
          message: 'Invalid publishable key',
        };
      }

      if (apiKey.expiresAt) {
        const expiresAtMs = Date.parse(apiKey.expiresAt);
        if (Number.isFinite(expiresAtMs) && expiresAtMs <= now().getTime()) {
          markAnomaly(apiKey, 'auth.publishable_key_expired_attempt');
          return {
            ok: false,
            status: 403,
            code: 'publishable_key_revoked',
            message: 'Publishable key has expired',
          };
        }
      }

      const requestEnvironmentId = String(request.environmentId || '').trim();
      if (requestEnvironmentId && requestEnvironmentId !== apiKey.environmentId) {
        markAnomaly(apiKey, 'auth.environment_mismatch');
        return {
          ok: false,
          status: 403,
          code: 'publishable_key_environment_mismatch',
          message: 'Publishable key is not allowed for this environment',
        };
      }

      if (!isAllowedOrigin(apiKey, request.origin)) {
        markAnomaly(apiKey, 'auth.origin_blocked');
        return {
          ok: false,
          status: 403,
          code: 'publishable_key_origin_blocked',
          message: buildPublishableKeyOriginBlockedMessage({
            origin: request.origin,
            allowedOrigins: apiKey.allowedOrigins || [],
          }),
        };
      }

      apiKey.lastUsedAt = toIso(now());
      apiKey.updatedAt = apiKey.lastUsedAt;
      return {
        ok: true,
        apiKey: cloneApiKey(apiKey),
      };
    },
  };
}
