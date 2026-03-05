import { ConsoleApiKeyError } from './errors';
import { isIpAllowlistMatch } from './ipAllowlist';
import {
  hashApiKeySecret,
  makeApiKeyLookupPrefix,
  makeApiKeySecret,
  makeId,
  makeSecretPreview,
  parseApiKeySecret,
} from './secret';
import type {
  AuthenticateConsoleApiKeyRequest,
  AuthenticateConsoleApiKeyResult,
  ConsoleApiKey,
  CreateConsoleApiKeyRequest,
  CreateConsoleApiKeyResult,
  RevokeConsoleApiKeyRequest,
  RotateConsoleApiKeyRequest,
  RotateConsoleApiKeyResult,
} from './types';

interface StoredApiKey extends ConsoleApiKey {
  secretHash: string;
  keyPrefix: string;
}

export interface ConsoleApiKeysContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
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
  rotateApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
    request?: RotateConsoleApiKeyRequest,
  ): Promise<RotateConsoleApiKeyResult | null>;
  authenticateApiKey?(
    request: AuthenticateConsoleApiKeyRequest,
  ): Promise<AuthenticateConsoleApiKeyResult>;
}

function toIso(date: Date): string {
  return date.toISOString();
}

function cloneApiKey(apiKey: StoredApiKey): ConsoleApiKey {
  return {
    id: apiKey.id,
    orgId: apiKey.orgId,
    name: apiKey.name,
    environmentId: apiKey.environmentId,
    scopes: [...apiKey.scopes],
    ipAllowlist: [...apiKey.ipAllowlist],
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

  function hasRequiredScopes(scopes: string[], requiredScopes: string[]): boolean {
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

  function findByParsedSecret(input: {
    orgId: string;
    apiKeyId: string;
    keyPrefix: string;
  }): StoredApiKey | null {
    const store = stores.get(input.orgId);
    if (!store) return null;
    const apiKey = store.get(input.apiKeyId) || null;
    if (!apiKey) return null;
    if (apiKey.keyPrefix && input.keyPrefix && apiKey.keyPrefix !== input.keyPrefix) {
      return null;
    }
    return apiKey;
  }

  return {
    async listApiKeys(ctx): Promise<ConsoleApiKey[]> {
      const store = requireOrgStore(ctx.orgId);
      return sortApiKeys(Array.from(store.values())).map(cloneApiKey);
    },

    async createApiKey(ctx, request): Promise<CreateConsoleApiKeyResult> {
      const createdAt = now();
      const iso = toIso(createdAt);
      const id = makeId('ak', createdAt);
      const secret = makeApiKeySecret({ orgId: ctx.orgId, apiKeyId: id });
      const secretHash = await hashApiKeySecret(secret);
      const apiKey: StoredApiKey = {
        id,
        orgId: ctx.orgId,
        name: request.name,
        environmentId: request.environmentId,
        scopes: [...request.scopes],
        ipAllowlist: request.ipAllowlist ? [...request.ipAllowlist] : [],
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
      const secret = makeApiKeySecret({ orgId: ctx.orgId, apiKeyId });
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

    async authenticateApiKey(request): Promise<AuthenticateConsoleApiKeyResult> {
      const secret = String(request.secret || '').trim();
      if (!secret) {
        return {
          ok: false,
          status: 401,
          code: 'api_key_missing',
          message: 'Missing API key secret',
        };
      }

      const parsed = parseApiKeySecret(secret);
      if (!parsed) {
        return {
          ok: false,
          status: 401,
          code: 'api_key_invalid',
          message: 'Invalid API key',
        };
      }

      const keyPrefix = makeApiKeyLookupPrefix(secret);
      const apiKey = findByParsedSecret({ ...parsed, keyPrefix });
      if (!apiKey) {
        return {
          ok: false,
          status: 401,
          code: 'api_key_invalid',
          message: 'Invalid API key',
        };
      }

      const hash = await hashApiKeySecret(secret);
      if (hash !== apiKey.secretHash) {
        markAnomaly(apiKey, 'auth.invalid_secret');
        return {
          ok: false,
          status: 401,
          code: 'api_key_invalid',
          message: 'Invalid API key',
        };
      }

      if (apiKey.status === 'REVOKED') {
        markAnomaly(apiKey, 'auth.revoked_attempt');
        return {
          ok: false,
          status: 403,
          code: 'api_key_revoked',
          message: 'API key has been revoked',
        };
      }

      if (apiKey.expiresAt) {
        const expiresAtMs = Date.parse(apiKey.expiresAt);
        if (Number.isFinite(expiresAtMs) && expiresAtMs <= now().getTime()) {
          markAnomaly(apiKey, 'auth.expired_attempt');
          return {
            ok: false,
            status: 403,
            code: 'api_key_revoked',
            message: 'API key has expired',
          };
        }
      }

      const requestEnvironmentId = String(request.environmentId || '').trim();
      if (requestEnvironmentId && requestEnvironmentId !== apiKey.environmentId) {
        markAnomaly(apiKey, 'auth.environment_mismatch');
        return {
          ok: false,
          status: 403,
          code: 'api_key_environment_mismatch',
          message: 'API key is not valid for the requested environment',
        };
      }

      if (!hasRequiredScopes(apiKey.scopes, request.requiredScopes || [])) {
        markAnomaly(apiKey, 'auth.scope_denied');
        return {
          ok: false,
          status: 403,
          code: 'api_key_forbidden_scope',
          message: 'API key does not grant required scope',
        };
      }

      if (!isIpAllowlistMatch({ allowlist: apiKey.ipAllowlist, sourceIp: request.sourceIp })) {
        markAnomaly(apiKey, 'auth.ip_blocked');
        return {
          ok: false,
          status: 403,
          code: 'api_key_ip_blocked',
          message: 'API key is blocked for this source IP',
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
  };
}
