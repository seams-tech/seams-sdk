import { ConsoleApiKeyError } from './errors';
import type {
  ConsoleApiKey,
  CreateConsoleApiKeyRequest,
  CreateConsoleApiKeyResult,
  RotateConsoleApiKeyRequest,
  RotateConsoleApiKeyResult,
} from './types';

interface StoredApiKey extends ConsoleApiKey {
  secretHash: string;
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
  ): Promise<{ revoked: boolean; apiKey: ConsoleApiKey | null }>;
  rotateApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
    request?: RotateConsoleApiKeyRequest,
  ): Promise<RotateConsoleApiKeyResult | null>;
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function makeSecret(now: Date): string {
  return `tsk_${makeId('sec', now)}_${Math.random().toString(36).slice(2, 14)}`;
}

function makeSecretPreview(secret: string): string {
  return `${secret.slice(0, 10)}...`;
}

function toIso(date: Date): string {
  return date.toISOString();
}

function fnv1a(input: string): string {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

async function hashSecret(secret: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    return `fnv1a:${fnv1a(secret)}`;
  }
  const bytes = await subtle.digest('SHA-256', new TextEncoder().encode(secret));
  const hex = Array.from(new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `sha256:${hex}`;
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

  return {
    async listApiKeys(ctx): Promise<ConsoleApiKey[]> {
      const store = requireOrgStore(ctx.orgId);
      return sortApiKeys(Array.from(store.values())).map(cloneApiKey);
    },

    async createApiKey(ctx, request): Promise<CreateConsoleApiKeyResult> {
      const createdAt = now();
      const iso = toIso(createdAt);
      const id = makeId('ak', createdAt);
      const secret = makeSecret(createdAt);
      const secretHash = await hashSecret(secret);
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
        endpointUsageCounts: {},
        anomalyFlags: [],
        secretHash,
      };

      const store = requireOrgStore(ctx.orgId);
      store.set(apiKey.id, apiKey);
      return {
        apiKey: cloneApiKey(apiKey),
        secret,
      };
    },

    async revokeApiKey(ctx, apiKeyId): Promise<{ revoked: boolean; apiKey: ConsoleApiKey | null }> {
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
      const secret = makeSecret(rotatedAt);
      apiKey.secretHash = await hashSecret(secret);
      apiKey.secretVersion += 1;
      apiKey.secretPreview = makeSecretPreview(secret);
      apiKey.updatedAt = toIso(rotatedAt);
      return {
        apiKey: cloneApiKey(apiKey),
        secret,
      };
    },
  };
}
