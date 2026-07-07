import type { RouterApiBootstrapGrantBroker, RouterApiKeyAuthAdapter } from '../../router/routerApi';
import { handleRouterApiBootstrapGrant } from '../../router/routerApiBootstrapGrant';
import { resolveSourceIpFromFetchHeaders } from '../../router/routerApiKeyAuth';
import type { NormalizedRouterLogger } from '../../router/logger';
import type { RouteDefinition } from '../../router/routeDefinitions';
import { toFetchRouteResponse } from '../../router/routeResponses';
import type { RouterApiRouteExtension } from '../../router/routeExtensions';
import { readJson } from '../../router/cloudflare/http';
import type { ConsoleWalletService } from '../wallets/service';
import {
  handleRouterApiWalletGet,
  handleRouterApiWalletList,
  handleRouterApiWalletSearch,
} from './routerApiWallets';

const API_WALLET_DETAIL_PREFIX = '/v1/wallets/';

export interface ConsoleRouterApiRouteExtensionsOptions {
  readonly apiKeyAuth?: RouterApiKeyAuthAdapter | null;
  readonly bootstrapGrantBroker?: RouterApiBootstrapGrantBroker | null;
  readonly wallets?: ConsoleWalletService | null;
}

function routeOrigin(headers: Headers): string | undefined {
  return String(headers.get('origin') || headers.get('Origin') || '').trim() || undefined;
}

function routeHeaders(headers: Headers): Record<string, string> {
  return Object.fromEntries(headers.entries());
}

function routeUrl(request: Request): URL {
  return new URL(request.url);
}

function registrationBootstrapGrantRoute(): RouteDefinition {
  return {
    id: 'registration_bootstrap_grants',
    surface: 'relay',
    method: 'POST',
    path: '/v1/registration/bootstrap-grants',
    summary: 'Issue managed registration bootstrap grants',
    auth: {
      plane: 'api_credentials',
      credentials: ['publishable_key'],
      environmentBinding: 'required',
      originBinding: 'required',
    },
    metering: { kind: 'none' },
    requiredServices: ['bootstrapGrantBroker'],
  };
}

function apiWalletListRoute(): RouteDefinition {
  return {
    id: 'api_wallets_list',
    surface: 'relay',
    method: 'GET',
    path: '/v1/wallets',
    summary: 'List wallets for the authenticated API credential environment',
    auth: {
      plane: 'api_credentials',
      credentials: ['secret_key'],
      scopes: ['wallets.read'],
    },
    metering: { kind: 'none' },
    requiredServices: ['apiKeyAuth', 'wallets'],
  };
}

function apiWalletSearchRoute(): RouteDefinition {
  return {
    id: 'api_wallets_search',
    surface: 'relay',
    method: 'GET',
    path: '/v1/wallets/search',
    summary: 'Search wallets for the authenticated API credential environment',
    auth: {
      plane: 'api_credentials',
      credentials: ['secret_key'],
      scopes: ['wallets.read'],
    },
    metering: { kind: 'none' },
    requiredServices: ['apiKeyAuth', 'wallets'],
  };
}

function apiWalletGetRoute(): RouteDefinition {
  return {
    id: 'api_wallets_get',
    surface: 'relay',
    method: 'GET',
    path: '/v1/wallets/:id',
    summary: 'Get a wallet for the authenticated API credential environment',
    auth: {
      plane: 'api_credentials',
      credentials: ['secret_key'],
      scopes: ['wallets.read'],
    },
    metering: { kind: 'none' },
    requiredServices: ['apiKeyAuth', 'wallets'],
  };
}

function consoleRouterApiRoutes(): readonly RouteDefinition[] {
  return [
    registrationBootstrapGrantRoute(),
    apiWalletListRoute(),
    apiWalletSearchRoute(),
    apiWalletGetRoute(),
  ];
}

async function handleConsoleBootstrapGrantRoute(input: {
  readonly request: Request;
  readonly route: RouteDefinition;
  readonly logger: NormalizedRouterLogger;
  readonly broker?: RouterApiBootstrapGrantBroker | null;
}): Promise<Response> {
  const response = await handleRouterApiBootstrapGrant({
    body: await readJson(input.request),
    headers: routeHeaders(input.request.headers),
    logger: input.logger,
    origin: routeOrigin(input.request.headers),
    route: input.route,
    services: {
      bootstrapGrantBroker: input.broker,
    },
  });
  return toFetchRouteResponse(response);
}

async function handleConsoleApiWalletRoute(input: {
  readonly request: Request;
  readonly route: RouteDefinition;
  readonly logger: NormalizedRouterLogger;
  readonly apiKeyAuth?: RouterApiKeyAuthAdapter | null;
  readonly wallets?: ConsoleWalletService | null;
  readonly walletId?: string;
}): Promise<Response> {
  const url = routeUrl(input.request);
  const common = {
    headers: routeHeaders(input.request.headers),
    logger: input.logger,
    route: input.route,
    services: {
      apiKeyAuth: input.apiKeyAuth,
      wallets: input.wallets,
    },
    sourceIp: resolveSourceIpFromFetchHeaders(input.request.headers) || undefined,
  } as const;

  if (input.route.id === 'api_wallets_list') {
    const response = await handleRouterApiWalletList({
      ...common,
      query: Object.fromEntries(url.searchParams.entries()),
    });
    return toFetchRouteResponse(response);
  }

  if (input.route.id === 'api_wallets_search') {
    const response = await handleRouterApiWalletSearch({
      ...common,
      query: Object.fromEntries(url.searchParams.entries()),
    });
    return toFetchRouteResponse(response);
  }

  const response = await handleRouterApiWalletGet({
    ...common,
    walletId: input.walletId,
  });
  return toFetchRouteResponse(response);
}

function walletIdFromPath(pathname: string): string | null {
  if (!pathname.startsWith(API_WALLET_DETAIL_PREFIX)) return null;
  const walletId = decodeURIComponent(pathname.slice(API_WALLET_DETAIL_PREFIX.length));
  if (!walletId || walletId.includes('/')) return null;
  return walletId;
}

export function createConsoleRouterApiRouteExtensions(
  options: ConsoleRouterApiRouteExtensionsOptions,
): readonly RouterApiRouteExtension[] {
  return [
    {
      kind: 'cloudflare_route_extension',
      id: 'console_router_api_managed_routes',
      routes: consoleRouterApiRoutes(),
      async handleCloudflareRoute(input) {
        const logger = input.logger;
        if (input.route.id === 'registration_bootstrap_grants') {
          return await handleConsoleBootstrapGrantRoute({
            request: input.request,
            route: input.route,
            logger,
            broker: options.bootstrapGrantBroker,
          });
        }

        const walletId = walletIdFromPath(input.pathname);
        return await handleConsoleApiWalletRoute({
          request: input.request,
          route: input.route,
          logger,
          apiKeyAuth: options.apiKeyAuth,
          wallets: options.wallets,
          ...(walletId ? { walletId } : {}),
        });
      },
    },
  ];
}
