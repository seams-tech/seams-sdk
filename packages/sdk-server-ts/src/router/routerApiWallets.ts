import type { ConsoleWalletService, ConsoleWalletsContext } from '../console/wallets/service';
import type { ConsoleWallet, ConsoleWalletPage } from '../console/wallets/types';
import { isConsoleWalletError } from '../console/wallets/errors';
import {
  parseListConsoleWalletsRequest,
  parseSearchConsoleWalletsRequest,
} from '../console/wallets/requests';
import { enforceRoutePolicy } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import { resolveSecretKeyApiCredentialAuth } from './routerApiCredentialAuth';
import type { RouterApiKeyAuthAdapter, RouterApiKeyPrincipal } from './routerApi';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import { routeJson } from './routeResponses';

type RouterApiWalletErrorBody = {
  ok: false;
  code: string;
  message: string;
  details?: Record<string, unknown>;
};

type RouterApiWalletListBody = {
  ok: true;
  wallets: ConsoleWallet[];
  nextCursor?: string;
};

type RouterApiWalletGetBody = {
  ok: true;
  wallet: ConsoleWallet;
};

interface RouterApiWalletServices {
  apiKeyAuth?: RouterApiKeyAuthAdapter | null;
  wallets?: ConsoleWalletService | null;
}

interface RouterApiWalletInput {
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  route: RouteDefinition;
  services: RouterApiWalletServices;
  sourceIp?: string;
}

interface RouterApiWalletQueryInput extends RouterApiWalletInput {
  query?: Record<string, string | string[] | undefined>;
}

interface RouterApiWalletGetInput extends RouterApiWalletInput {
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

function toApiWalletContext(principal: RouterApiKeyPrincipal): ConsoleWalletsContext {
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

function walletListResponse(page: ConsoleWalletPage): RouteResponse<RouterApiWalletListBody> {
  return routeJson(200, {
    ok: true,
    wallets: page.items,
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  });
}

function walletErrorResponse(error: unknown): RouteResponse<RouterApiWalletErrorBody> {
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
  input: RouterApiWalletInput,
): Promise<
  Awaited<
    ReturnType<
      typeof enforceRoutePolicy<{
        apiKeyAuth?: RouterApiKeyAuthAdapter | null;
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
): RouteResponse<RouterApiWalletErrorBody> {
  return routeJson(status, {
    ok: false,
    code: 'wallet_api_not_configured',
    message: 'API credential wallet access is not configured on this server',
  });
}

export async function handleRouterApiWalletList(
  input: RouterApiWalletQueryInput,
): Promise<RouteResponse<RouterApiWalletListBody | RouterApiWalletErrorBody>> {
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

export async function handleRouterApiWalletSearch(
  input: RouterApiWalletQueryInput,
): Promise<RouteResponse<RouterApiWalletListBody | RouterApiWalletErrorBody>> {
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

export async function handleRouterApiWalletGet(
  input: RouterApiWalletGetInput,
): Promise<RouteResponse<RouterApiWalletGetBody | RouterApiWalletErrorBody>> {
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
