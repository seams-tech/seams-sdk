import type { ConsoleApiKeyService } from '../console/apiKeys';
import type {
  AuthenticateConsoleApiKeyResult,
  AuthenticateConsolePublishableKeyResult,
  ConsoleApiKey,
} from '../console/apiKeys';
import type { ConsoleBillingService } from '../console/billing';
import { normalizeSourceIp } from '../console/apiKeys/ipAllowlist';
import type {
  RelayApiKeyAuthAdapter,
  RelayApiKeyAuthResult,
  RelayPublishableKeyAuthAdapter,
  RelayPublishableKeyAuthResult,
  RelayUsageMeterAdapter,
} from './relay';

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

function toRelayAuthResult(result: AuthenticateConsoleApiKeyResult): RelayApiKeyAuthResult {
  if (result.ok) {
    return {
      ok: true,
      principal: toPrincipal(result.apiKey),
    };
  }
  return result;
}

function toRelayPublishableAuthResult(
  result: AuthenticateConsolePublishableKeyResult,
): RelayPublishableKeyAuthResult {
  if (result.ok) {
    return {
      ok: true,
      principal: toPrincipal(result.apiKey),
    };
  }
  return result;
}

export function createRelayApiKeyAuthAdapter(apiKeys: ConsoleApiKeyService): RelayApiKeyAuthAdapter {
  const authenticateApiKey = apiKeys.authenticateApiKey;
  if (typeof authenticateApiKey !== 'function') {
    throw new Error('ConsoleApiKeyService.authenticateApiKey is required for relay API key auth');
  }
  return {
    authenticate: async (input) => {
      const result = await authenticateApiKey(input);
      return toRelayAuthResult(result);
    },
  };
}

export function createRelayPublishableKeyAuthAdapter(
  apiKeys: ConsoleApiKeyService,
): RelayPublishableKeyAuthAdapter {
  const authenticatePublishableKey = apiKeys.authenticatePublishableKey;
  if (typeof authenticatePublishableKey !== 'function') {
    throw new Error(
      'ConsoleApiKeyService.authenticatePublishableKey is required for relay publishable key auth',
    );
  }
  return {
    authenticate: async (input) => {
      const result = await authenticatePublishableKey({
        secret: input.secret,
        origin: input.origin,
        environmentId: input.environmentId,
      });
      return toRelayPublishableAuthResult(result);
    },
  };
}

export function createRelayBillingUsageMeterAdapter(
  billing: ConsoleBillingService,
): RelayUsageMeterAdapter {
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

export function extractRelayEnvironmentId(headers: HeaderBag): string | null {
  const preferred = readHeader(headers, 'x-tatchi-environment-id');
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
