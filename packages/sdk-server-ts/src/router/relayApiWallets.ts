import {
  type ConsoleWallet,
  type ConsoleWalletPage,
  type ConsoleWalletService,
  type ConsoleWalletsContext,
  isConsoleWalletError,
  parseListConsoleWalletsRequest,
  parseSearchConsoleWalletsRequest,
} from '../console/wallets';
import { enforceRoutePolicy } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import { resolveSecretKeyApiCredentialAuth } from './relayApiCredentialAuth';
import type { RelayApiKeyAuthAdapter, RelayApiKeyPrincipal } from './relay';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import { routeJson } from './routeResponses';

type RelayApiWalletErrorBody = {
  ok: false;
  code: string;
  message: string;
  details?: Record<string, unknown>;
};

type RelayApiWalletListBody = {
  ok: true;
  wallets: ConsoleWallet[];
  nextCursor?: string;
};

type RelayApiWalletGetBody = {
  ok: true;
  wallet: ConsoleWallet;
};

interface RelayApiWalletServices {
  apiKeyAuth?: RelayApiKeyAuthAdapter | null;
  wallets?: ConsoleWalletService | null;
}

interface RelayApiWalletInput {
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  route: RouteDefinition;
  services: RelayApiWalletServices;
  sourceIp?: string;
}

interface RelayApiWalletQueryInput extends RelayApiWalletInput {
  query?: Record<string, string | string[] | undefined>;
}

interface RelayApiWalletGetInput extends RelayApiWalletInput {
  walletId?: string;
}

function parsePolicyFailureMessage(message: string): {
  code: string;
  detail: string;
} {
  const normalized = String(message || '').trim();
  const separatorIndex = normalized.indexOf(':');
  if (separatorIndex <= 0) {
    return {
      code: 'unauthorized',
      detail: normalized || 'Unauthorized',
    };
  }
  return {
    code: normalized.slice(0, separatorIndex).trim() || 'unauthorized',
    detail: normalized.slice(separatorIndex + 1).trim() || 'Unauthorized',
  };
}

function toApiWalletContext(principal: RelayApiKeyPrincipal): ConsoleWalletsContext {
  return {
    orgId: principal.orgId,
    actorUserId: `api_credentials:${principal.apiKeyId}`,
    roles: ['api_credential'],
    environmentId: principal.environmentId,
  };
}

function bindEnvironmentScope<T extends { environmentId?: string }>(
  request: T,
  environmentId: string,
): T {
  return {
    ...request,
    environmentId,
  };
}

function walletListResponse(page: ConsoleWalletPage): RouteResponse<RelayApiWalletListBody> {
  return routeJson(200, {
    ok: true,
    wallets: page.items,
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  });
}

function walletErrorResponse(error: unknown): RouteResponse<RelayApiWalletErrorBody> {
  if (isConsoleWalletError(error)) {
    return routeJson(error.status, {
      ok: false,
      code: error.code,
      message: error.message,
      ...(error.details ? { details: error.details } : {}),
    });
  }
  return routeJson(500, {
    ok: false,
    code: 'internal',
    message: error instanceof Error ? error.message : String(error),
  });
}

async function enforceApiWalletRoute(
  input: RelayApiWalletInput,
): Promise<
  Awaited<
    ReturnType<
      typeof enforceRoutePolicy<{
        apiKeyAuth?: RelayApiKeyAuthAdapter | null;
        wallets?: ConsoleWalletService | null;
      }>
    >
  >
> {
  return await enforceRoutePolicy({
    headers: input.headers,
    logger: input.logger,
    request: {
      body: {},
      headers: input.headers,
    },
    route: input.route,
    services: {
      apiKeyAuth: input.services.apiKeyAuth,
      wallets: input.services.wallets,
    },
    ...(input.sourceIp ? { sourceIp: input.sourceIp } : {}),
    resolvers: {
      apiCredentials: async () =>
        await resolveSecretKeyApiCredentialAuth({
          apiKeyAuth: input.services.apiKeyAuth,
          headers: input.headers,
          route: input.route,
          ...(input.sourceIp ? { sourceIp: input.sourceIp } : {}),
          routeAuthNotConfiguredMessage: 'API credential wallet auth is not configured on this server',
        }),
    },
  });
}

function apiWalletNotConfiguredResponse(
  status: 500 | 501,
): RouteResponse<RelayApiWalletErrorBody> {
  return routeJson(status, {
    ok: false,
    code: 'wallet_api_not_configured',
    message: 'API credential wallet access is not configured on this server',
  });
}

export async function handleRelayApiWalletList(
  input: RelayApiWalletQueryInput,
): Promise<RouteResponse<RelayApiWalletListBody | RelayApiWalletErrorBody>> {
  const resolved = await enforceApiWalletRoute(input);
  if (!resolved.ok) {
    if (
      resolved.body.code === 'route_auth_not_configured' ||
      resolved.body.code === 'service_not_configured'
    ) {
      return apiWalletNotConfiguredResponse(resolved.status === 501 ? 501 : 500);
    }
    const parsed = parsePolicyFailureMessage(resolved.body.message);
    return routeJson(resolved.status, {
      ok: false,
      code: parsed.code,
      message: parsed.detail,
    });
  }

  const principal = resolved.context.principal;
  if (principal.kind !== 'api_credentials') {
    return routeJson(500, {
      ok: false,
      code: 'internal',
      message: 'API wallet route resolved a non-API-credential principal',
    });
  }

  try {
    const request = bindEnvironmentScope(
      parseListConsoleWalletsRequest(input.query || {}),
      principal.principal.environmentId,
    );
    const page = await resolved.context.services.wallets!.listWallets(
      toApiWalletContext(principal.principal),
      request,
    );
    return walletListResponse(page);
  } catch (error: unknown) {
    return walletErrorResponse(error);
  }
}

export async function handleRelayApiWalletSearch(
  input: RelayApiWalletQueryInput,
): Promise<RouteResponse<RelayApiWalletListBody | RelayApiWalletErrorBody>> {
  const resolved = await enforceApiWalletRoute(input);
  if (!resolved.ok) {
    if (
      resolved.body.code === 'route_auth_not_configured' ||
      resolved.body.code === 'service_not_configured'
    ) {
      return apiWalletNotConfiguredResponse(resolved.status === 501 ? 501 : 500);
    }
    const parsed = parsePolicyFailureMessage(resolved.body.message);
    return routeJson(resolved.status, {
      ok: false,
      code: parsed.code,
      message: parsed.detail,
    });
  }

  const principal = resolved.context.principal;
  if (principal.kind !== 'api_credentials') {
    return routeJson(500, {
      ok: false,
      code: 'internal',
      message: 'API wallet route resolved a non-API-credential principal',
    });
  }

  try {
    const request = bindEnvironmentScope(
      parseSearchConsoleWalletsRequest(input.query || {}),
      principal.principal.environmentId,
    );
    const page = await resolved.context.services.wallets!.searchWallets(
      toApiWalletContext(principal.principal),
      request,
    );
    return walletListResponse(page);
  } catch (error: unknown) {
    return walletErrorResponse(error);
  }
}

export async function handleRelayApiWalletGet(
  input: RelayApiWalletGetInput,
): Promise<RouteResponse<RelayApiWalletGetBody | RelayApiWalletErrorBody>> {
  const walletId = String(input.walletId || '').trim();
  if (!walletId) {
    return routeJson(400, {
      ok: false,
      code: 'invalid_path',
      message: 'Missing wallet id',
    });
  }

  const resolved = await enforceApiWalletRoute(input);
  if (!resolved.ok) {
    if (
      resolved.body.code === 'route_auth_not_configured' ||
      resolved.body.code === 'service_not_configured'
    ) {
      return apiWalletNotConfiguredResponse(resolved.status === 501 ? 501 : 500);
    }
    const parsed = parsePolicyFailureMessage(resolved.body.message);
    return routeJson(resolved.status, {
      ok: false,
      code: parsed.code,
      message: parsed.detail,
    });
  }

  const principal = resolved.context.principal;
  if (principal.kind !== 'api_credentials') {
    return routeJson(500, {
      ok: false,
      code: 'internal',
      message: 'API wallet route resolved a non-API-credential principal',
    });
  }

  try {
    const wallet = await resolved.context.services.wallets!.getWallet(
      toApiWalletContext(principal.principal),
      walletId,
    );
    if (!wallet || wallet.environmentId !== principal.principal.environmentId) {
      return routeJson(404, {
        ok: false,
        code: 'wallet_not_found',
        message: `Wallet ${walletId} was not found`,
      });
    }
    return routeJson(200, { ok: true, wallet });
  } catch (error: unknown) {
    return walletErrorResponse(error);
  }
}
