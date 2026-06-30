import type { ConsoleApiKeyService } from '../console/apiKeys';
import type {
  AuthenticateConsoleApiKeyResult,
  AuthenticateConsolePublishableKeyResult,
  ConsoleApiKey,
} from '../console/apiKeys';
import type { ConsoleBillingService } from '../console/billing';
import type { ConsoleOrgProjectEnvService } from '../console/orgProjectEnv';
import type { ConsoleWalletService } from '../console/wallets';
import { normalizeSourceIp } from '../console/apiKeys/ipAllowlist';
import type {
  RouterApiKeyAuthAdapter,
  RouterApiKeyAuthResult,
  RouterApiPublishableKeyAuthAdapter,
  RouterApiPublishableKeyAuthResult,
  RouterApiUsageMeterAdapter,
} from './routerApi';

type HeaderBag = Headers | Record<string, unknown>;

function readHeader(headers: HeaderBag, name: string): string {
  if (headers instanceof Headers) {
    return String(headers.get(name) || '').trim();
  }
  const direct = (headers as Record<string, unknown>)[name];
  const lower = (headers as Record<string, unknown>)[name.toLowerCase()];
  const upper = (headers as Record<string, unknown>)[name.toUpperCase()];
  const value = direct ?? lower ?? upper;
  if (typeof value === 'string') return value.trim();
  if (Array.isArray(value)) return String(value[0] || '').trim();
  return '';
}

function toPrincipal(apiKey: ConsoleApiKey) {
  return {
    apiKeyId: apiKey.id,
    orgId: apiKey.orgId,
    environmentId: apiKey.environmentId,
    scopes: [...(apiKey.scopes || [])],
  };
}

function toRouterApiAuthResult(result: AuthenticateConsoleApiKeyResult): RouterApiKeyAuthResult {
  if (result.ok) {
    return {
      ok: true,
      principal: toPrincipal(result.apiKey),
    };
  }
  return result;
}

function toRouterApiPublishableAuthResult(
  result: AuthenticateConsolePublishableKeyResult,
): RouterApiPublishableKeyAuthResult {
  if (result.ok) {
    return {
      ok: true,
      principal: toPrincipal(result.apiKey),
    };
  }
  return result;
}

export function createRouterApiKeyAuthAdapter(apiKeys: ConsoleApiKeyService): RouterApiKeyAuthAdapter {
  const authenticateApiKey = apiKeys.authenticateApiKey;
  if (typeof authenticateApiKey !== 'function') {
    throw new Error('ConsoleApiKeyService.authenticateApiKey is required for Router API key auth');
  }
  const authenticateApiKeyFn = authenticateApiKey.bind(apiKeys);
  return {
    authenticate: async (input) => {
      const result = await authenticateApiKeyFn(input);
      return toRouterApiAuthResult(result);
    },
  };
}

export function createRouterApiPublishableKeyAuthAdapter(
  apiKeys: ConsoleApiKeyService,
): RouterApiPublishableKeyAuthAdapter {
  const authenticatePublishableKey = apiKeys.authenticatePublishableKey;
  if (typeof authenticatePublishableKey !== 'function') {
    throw new Error(
      'ConsoleApiKeyService.authenticatePublishableKey is required for Router API publishable key auth',
    );
  }
  const authenticatePublishableKeyFn = authenticatePublishableKey.bind(apiKeys);
  return {
    authenticate: async (input) => {
      const result = await authenticatePublishableKeyFn({
        secret: input.secret,
        origin: input.origin,
        environmentId: input.environmentId,
      });
      return toRouterApiPublishableAuthResult(result);
    },
  };
}

export function createRouterApiBillingUsageMeterAdapter(
  billing: ConsoleBillingService,
  options: {
    orgProjectEnv?: ConsoleOrgProjectEnvService | null;
    wallets?: ConsoleWalletService | null;
  } = {},
): RouterApiUsageMeterAdapter {
  async function recordWalletProjection(input: {
    orgId: string;
    environmentId: string;
    walletId: string;
    occurredAt?: string;
  }): Promise<void> {
    const orgProjectEnv = options.orgProjectEnv || null;
    const walletService = options.wallets || null;
    if (!orgProjectEnv || !walletService?.upsertWallet) return;
    const envs = await orgProjectEnv.listEnvironments({
      orgId: input.orgId,
      actorUserId: 'relay-api-key',
      roles: ['system'],
      environmentId: input.environmentId,
    });
    const environment =
      envs.find((entry) => entry.id === input.environmentId) || null;
    if (!environment) return;
    const nowIso = String(input.occurredAt || '').trim() || new Date().toISOString();
    await walletService.upsertWallet(
      {
        orgId: input.orgId,
        actorUserId: 'relay-api-key',
        roles: ['system'],
        projectId: environment.projectId,
        environmentId: environment.id,
      },
      {
        id: input.walletId,
        projectId: environment.projectId,
        environmentId: environment.id,
        userId: input.walletId,
        externalRefId: input.walletId,
        address: input.walletId,
        chain: 'NEAR',
        walletType: 'EOA',
        status: 'ACTIVE',
        policyId: null,
        balanceMinor: 0,
        lastActivityAt: nowIso,
        createdAt: nowIso,
        updatedAt: nowIso,
      },
    );
  }

  return {
    recordEvent: async (input) => {
      await billing.recordUsageEvent(
        {
          orgId: input.orgId,
          actorUserId: 'relay-api-key',
          roles: ['system'],
        },
        {
          walletId: input.walletId,
          action: input.action,
          succeeded: input.succeeded,
          ...(input.occurredAt ? { occurredAt: input.occurredAt } : {}),
          ...(input.sourceEventId ? { sourceEventId: input.sourceEventId } : {}),
        },
      );
      if (input.action === 'wallet_created' && input.succeeded) {
        await recordWalletProjection({
          orgId: input.orgId,
          environmentId: input.environmentId,
          walletId: input.walletId,
          ...(input.occurredAt ? { occurredAt: input.occurredAt } : {}),
        });
      }
    },
  };
}

export function extractBearerCredential(headers: HeaderBag): string | null {
  const authHeader = readHeader(headers, 'authorization');
  if (authHeader) {
    const bearerPrefix = 'bearer ';
    if (authHeader.toLowerCase().startsWith(bearerPrefix)) {
      const bearerValue = authHeader.slice(bearerPrefix.length).trim();
      if (bearerValue) return bearerValue;
    }
  }
  return null;
}

export function extractRouterApiEnvironmentId(headers: HeaderBag): string | null {
  const preferred = readHeader(headers, 'x-seams-environment-id');
  if (preferred) return preferred;
  const fallback = readHeader(headers, 'x-environment-id');
  if (fallback) return fallback;
  return null;
}

export function resolveSourceIpFromExpressRequest(input: {
  headers: Record<string, unknown>;
  ip?: string | null;
}): string | null {
  const forwarded = readHeader(input.headers, 'x-forwarded-for');
  const realIp = readHeader(input.headers, 'x-real-ip');
  return normalizeSourceIp(forwarded || realIp || String(input.ip || ''));
}

export function resolveSourceIpFromFetchHeaders(headers: HeaderBag): string | null {
  const cfConnecting = readHeader(headers, 'cf-connecting-ip');
  const forwarded = readHeader(headers, 'x-forwarded-for');
  const realIp = readHeader(headers, 'x-real-ip');
  return normalizeSourceIp(cfConnecting || forwarded || realIp);
}

export function resolveRequestOriginRateLimitKeyFromExpressRequest(input: {
  headers: Record<string, unknown>;
  ip?: string | null;
}): string {
  const sourceIp = resolveSourceIpFromExpressRequest(input);
  if (sourceIp) return `ip:${sourceIp}`;
  const origin = readHeader(input.headers, 'origin');
  if (origin) return `origin:${origin}`;
  return 'origin:unknown-express';
}

export function resolveRequestOriginRateLimitKeyFromFetchHeaders(headers: HeaderBag): string {
  const sourceIp = resolveSourceIpFromFetchHeaders(headers);
  if (sourceIp) return `ip:${sourceIp}`;
  const origin = readHeader(headers, 'origin');
  if (origin) return `origin:${origin}`;
  return 'origin:unknown-fetch';
}
