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
import { resolveSecretKeyMachineAuth } from './relayMachineAuth';
import type { RelayApiKeyAuthAdapter, RelayApiKeyPrincipal } from './relay';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import { routeJson } from './routeResponses';

type RelayMachineWalletErrorBody = {
  ok: false;
  code: string;
  message: string;
  details?: Record<string, unknown>;
};

type RelayMachineWalletListBody = {
  ok: true;
  wallets: ConsoleWallet[];
  nextCursor?: string;
};

type RelayMachineWalletGetBody = {
  ok: true;
  wallet: ConsoleWallet;
};

interface RelayMachineWalletServices {
  apiKeyAuth?: RelayApiKeyAuthAdapter | null;
  wallets?: ConsoleWalletService | null;
}

interface RelayMachineWalletInput {
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  route: RouteDefinition;
  services: RelayMachineWalletServices;
  sourceIp?: string;
}

interface RelayMachineWalletQueryInput extends RelayMachineWalletInput {
  query?: Record<string, string | string[] | undefined>;
}

interface RelayMachineWalletGetInput extends RelayMachineWalletInput {
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

function toMachineWalletContext(principal: RelayApiKeyPrincipal): ConsoleWalletsContext {
  return {
    orgId: principal.orgId,
    actorUserId: `machine:${principal.apiKeyId}`,
    roles: ['machine_api_key'],
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

function walletListResponse(page: ConsoleWalletPage): RouteResponse<RelayMachineWalletListBody> {
  return routeJson(200, {
    ok: true,
    wallets: page.items,
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  });
}

function walletErrorResponse(error: unknown): RouteResponse<RelayMachineWalletErrorBody> {
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

async function enforceMachineWalletRoute(
  input: RelayMachineWalletInput,
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
      machine: async () =>
        await resolveSecretKeyMachineAuth({
          apiKeyAuth: input.services.apiKeyAuth,
          headers: input.headers,
          route: input.route,
          ...(input.sourceIp ? { sourceIp: input.sourceIp } : {}),
          routeAuthNotConfiguredMessage: 'Machine wallet API auth is not configured on this server',
        }),
    },
  });
}

function machineWalletNotConfiguredResponse(
  status: 500 | 501,
): RouteResponse<RelayMachineWalletErrorBody> {
  return routeJson(status, {
    ok: false,
    code: 'wallet_api_not_configured',
    message: 'Machine wallet API is not configured on this server',
  });
}

export async function handleRelayMachineWalletList(
  input: RelayMachineWalletQueryInput,
): Promise<RouteResponse<RelayMachineWalletListBody | RelayMachineWalletErrorBody>> {
  const resolved = await enforceMachineWalletRoute(input);
  if (!resolved.ok) {
    if (
      resolved.body.code === 'route_auth_not_configured' ||
      resolved.body.code === 'service_not_configured'
    ) {
      return machineWalletNotConfiguredResponse(resolved.status === 501 ? 501 : 500);
    }
    const parsed = parsePolicyFailureMessage(resolved.body.message);
    return routeJson(resolved.status, {
      ok: false,
      code: parsed.code,
      message: parsed.detail,
    });
  }

  const principal = resolved.context.principal;
  if (principal.kind !== 'machine') {
    return routeJson(500, {
      ok: false,
      code: 'internal',
      message: 'Machine wallet route resolved a non-machine principal',
    });
  }

  try {
    const request = bindEnvironmentScope(
      parseListConsoleWalletsRequest(input.query || {}),
      principal.principal.environmentId,
    );
    const page = await resolved.context.services.wallets!.listWallets(
      toMachineWalletContext(principal.principal),
      request,
    );
    return walletListResponse(page);
  } catch (error: unknown) {
    return walletErrorResponse(error);
  }
}

export async function handleRelayMachineWalletSearch(
  input: RelayMachineWalletQueryInput,
): Promise<RouteResponse<RelayMachineWalletListBody | RelayMachineWalletErrorBody>> {
  const resolved = await enforceMachineWalletRoute(input);
  if (!resolved.ok) {
    if (
      resolved.body.code === 'route_auth_not_configured' ||
      resolved.body.code === 'service_not_configured'
    ) {
      return machineWalletNotConfiguredResponse(resolved.status === 501 ? 501 : 500);
    }
    const parsed = parsePolicyFailureMessage(resolved.body.message);
    return routeJson(resolved.status, {
      ok: false,
      code: parsed.code,
      message: parsed.detail,
    });
  }

  const principal = resolved.context.principal;
  if (principal.kind !== 'machine') {
    return routeJson(500, {
      ok: false,
      code: 'internal',
      message: 'Machine wallet route resolved a non-machine principal',
    });
  }

  try {
    const request = bindEnvironmentScope(
      parseSearchConsoleWalletsRequest(input.query || {}),
      principal.principal.environmentId,
    );
    const page = await resolved.context.services.wallets!.searchWallets(
      toMachineWalletContext(principal.principal),
      request,
    );
    return walletListResponse(page);
  } catch (error: unknown) {
    return walletErrorResponse(error);
  }
}

export async function handleRelayMachineWalletGet(
  input: RelayMachineWalletGetInput,
): Promise<RouteResponse<RelayMachineWalletGetBody | RelayMachineWalletErrorBody>> {
  const walletId = String(input.walletId || '').trim();
  if (!walletId) {
    return routeJson(400, {
      ok: false,
      code: 'invalid_path',
      message: 'Missing wallet id',
    });
  }

  const resolved = await enforceMachineWalletRoute(input);
  if (!resolved.ok) {
    if (
      resolved.body.code === 'route_auth_not_configured' ||
      resolved.body.code === 'service_not_configured'
    ) {
      return machineWalletNotConfiguredResponse(resolved.status === 501 ? 501 : 500);
    }
    const parsed = parsePolicyFailureMessage(resolved.body.message);
    return routeJson(resolved.status, {
      ok: false,
      code: parsed.code,
      message: parsed.detail,
    });
  }

  const principal = resolved.context.principal;
  if (principal.kind !== 'machine') {
    return routeJson(500, {
      ok: false,
      code: 'internal',
      message: 'Machine wallet route resolved a non-machine principal',
    });
  }

  try {
    const wallet = await resolved.context.services.wallets!.getWallet(
      toMachineWalletContext(principal.principal),
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
