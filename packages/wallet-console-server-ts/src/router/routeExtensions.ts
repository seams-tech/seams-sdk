import type { RouterApiKeyAuthAdapter } from '@seams/sdk-server/cloud-host';
import { resolveSourceIpFromFetchHeaders } from '@seams/sdk-server/cloud-host';
import type { NormalizedRouterLogger } from '@seams/sdk-server/cloud-host';
import type { RouteDefinition } from '@seams/sdk-server/cloud-host';
import { routeJson, toFetchRouteResponse } from '@seams/sdk-server/cloud-host';
import type { RouterApiRouteExtension } from '@seams/sdk-server/cloud-host';
import { readJson } from '@seams/sdk-server/cloud-host';
import type { RouterApiPublishableKeyAuthAdapter } from '@seams/sdk-server/cloud-host';
import type { ConsoleBillingService } from '@seams-internal/console-server/billing/index';
import type { ConsoleBillingPrepaidReservationService } from '../billingPrepaidReservations';
import type { ConsoleObservabilityIngestionService } from '@seams-internal/console-server/observability/index';
import type { ConsoleRuntimeSnapshotService } from '../runtimeSnapshots';
import type { ConsoleSponsoredCallService } from '../sponsoredCalls';
import { DEFAULT_SPONSORED_EVM_CALL_ROUTE } from '../sponsorship/evmRoutes';
import type {
  SponsoredEvmCallExecutorConfig,
  SponsoredEvmExecutionAdapterResolver,
} from '../sponsorship/evmExecutorTypes';
import type { SponsorshipSpendPricingService } from '../sponsorship/spendCaps';
import type { ConsoleSponsorshipSpendCapService } from '../sponsorshipSpendCaps';
import type { ConsoleWebhookService } from '@seams-internal/console-server/webhooks/index';
import type { ConsoleWalletService } from '../wallets/service';
import { ensureLeadingSlash } from '@seams/sdk-server/cloud-host';
import {
  handleRouterApiSignedDelegate,
  type SignedDelegateRouterApiAuthService,
} from './routerApiSignedDelegate';
import { handleRouterApiSponsoredEvmCall } from './routerApiSponsoredEvmCall';
import {
  handleRouterApiWalletGet,
  handleRouterApiWalletList,
  handleRouterApiWalletSearch,
} from './routerApiWallets';

const API_WALLET_DETAIL_PREFIX = '/v1/wallets/';
const ROUTER_API_SIGNED_DELEGATE_ROUTE_ID = 'signed_delegate';
const ROUTER_API_SPONSORED_EVM_CALL_ROUTE_ID = 'sponsored_evm_call';
export const DEFAULT_SIGNED_DELEGATE_ROUTE = '/signed-delegate';
const SPONSORED_EVM_MVP_DISABLED_MESSAGE =
  'EVM gas sponsorship pricing is not configured on this server.';
const ROUTER_API_SIGNED_DELEGATE_SERVICES = [
  'signedDelegateAuth',
  'publishableKeyAuth',
  'billing',
  'runtimeSnapshots',
  'sponsoredCalls',
] as const;

export interface ConsoleRouterApiSignedDelegateRouteOptions {
  readonly route: string;
  readonly authService: SignedDelegateRouterApiAuthService;
  readonly billing: ConsoleBillingService | null;
  readonly ledger: ConsoleSponsoredCallService | null;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService | null;
  readonly publishableKeyAuth: RouterApiPublishableKeyAuthAdapter | null;
  readonly observabilityIngestion: ConsoleObservabilityIngestionService | null;
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService | null;
  readonly pricing: SponsorshipSpendPricingService | null;
  readonly spendCaps: ConsoleSponsorshipSpendCapService | null;
  readonly webhooks: ConsoleWebhookService | null;
  readonly webhookActorUserId?: string;
}

export interface ConsoleRouterApiSponsoredEvmCallRouteOptions {
  readonly route?: string;
  readonly publishableKeyAuth: RouterApiPublishableKeyAuthAdapter;
  readonly billing: ConsoleBillingService;
  readonly ledger: ConsoleSponsoredCallService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
  readonly config: SponsoredEvmCallExecutorConfig;
  readonly resolveExecutionAdapter?: SponsoredEvmExecutionAdapterResolver | null;
  readonly observabilityIngestion: ConsoleObservabilityIngestionService | null;
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService | null;
  readonly pricing: SponsorshipSpendPricingService | null;
  readonly spendCaps: ConsoleSponsorshipSpendCapService | null;
  readonly webhooks?: ConsoleWebhookService | null;
  readonly webhookActorUserId?: string;
}

export interface ConsoleRouterApiRouteExtensionsOptions {
  readonly apiKeyAuth?: RouterApiKeyAuthAdapter | null;
  readonly signedDelegate?: ConsoleRouterApiSignedDelegateRouteOptions | null;
  readonly sponsoredEvmCall?: ConsoleRouterApiSponsoredEvmCallRouteOptions | null;
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

function signedDelegateRoute(routePath: string): RouteDefinition {
  return {
    id: ROUTER_API_SIGNED_DELEGATE_ROUTE_ID,
    surface: 'relay',
    method: 'POST',
    path: ensureLeadingSlash(routePath) || DEFAULT_SIGNED_DELEGATE_ROUTE,
    summary: 'Execute signed NEAR delegate',
    auth: {
      plane: 'api_credentials',
      credentials: ['publishable_key'],
      environmentBinding: 'required',
      originBinding: 'required',
    },
    metering: { kind: 'gas', ledger: 'near_delegate' },
    requiredServices: ROUTER_API_SIGNED_DELEGATE_SERVICES,
  };
}

function sponsoredEvmCallRoute(routePath?: string): RouteDefinition {
  return {
    id: ROUTER_API_SPONSORED_EVM_CALL_ROUTE_ID,
    surface: 'relay',
    method: 'POST',
    path: String(routePath || '').trim() || DEFAULT_SPONSORED_EVM_CALL_ROUTE,
    summary: 'Execute a sponsored EVM call',
    auth: {
      plane: 'api_credentials',
      credentials: ['publishable_key'],
      environmentBinding: 'required',
      originBinding: 'required',
    },
    metering: { kind: 'gas', ledger: 'evm' },
    requiredServices: ['routerApiSponsoredEvmCall'],
  };
}

function consoleRouterApiRoutes(
  options: ConsoleRouterApiRouteExtensionsOptions,
): readonly RouteDefinition[] {
  const routes: RouteDefinition[] = [];
  if (options.apiKeyAuth && options.wallets) {
    routes.push(apiWalletListRoute(), apiWalletSearchRoute(), apiWalletGetRoute());
  }
  if (options.signedDelegate) {
    routes.push(signedDelegateRoute(options.signedDelegate.route));
  }
  if (options.sponsoredEvmCall) {
    routes.push(sponsoredEvmCallRoute(options.sponsoredEvmCall.route));
  }
  return routes;
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

async function handleConsoleSignedDelegateRoute(input: {
  readonly request: Request;
  readonly route: RouteDefinition;
  readonly logger: NormalizedRouterLogger;
  readonly signedDelegate: ConsoleRouterApiSignedDelegateRouteOptions;
}): Promise<Response> {
  const options = input.signedDelegate;
  const response = await handleRouterApiSignedDelegate({
    body: await readJson(input.request),
    headers: routeHeaders(input.request.headers),
    logger: input.logger,
    origin: routeOrigin(input.request.headers),
    route: input.route,
    services: {
      signedDelegateAuth: options.authService,
      billing: options.billing,
      observabilityIngestion: options.observabilityIngestion,
      prepaidReservations: options.prepaidReservations,
      pricing: options.pricing,
      publishableKeyAuth: options.publishableKeyAuth,
      runtimeSnapshots: options.runtimeSnapshots,
      spendCaps: options.spendCaps,
      sponsoredCalls: options.ledger,
      webhooks: options.webhooks,
      webhookActorUserId: options.webhookActorUserId,
    },
  });
  return toFetchRouteResponse(response);
}

async function handleConsoleSponsoredEvmCallRoute(input: {
  readonly request: Request;
  readonly route: RouteDefinition;
  readonly logger: NormalizedRouterLogger;
  readonly sponsoredEvmCall: ConsoleRouterApiSponsoredEvmCallRouteOptions;
}): Promise<Response> {
  const options = input.sponsoredEvmCall;
  if (!options.pricing) {
    input.logger.warn('[sponsored-evm-call][pricing-unconfigured]', {
      path: input.route.path,
      reason: SPONSORED_EVM_MVP_DISABLED_MESSAGE,
    });
    return toFetchRouteResponse(
      routeJson(503, {
        ok: false,
        code: 'sponsorship_pricing_unavailable',
        message: SPONSORED_EVM_MVP_DISABLED_MESSAGE,
      }),
    );
  }

  const response = await handleRouterApiSponsoredEvmCall({
    body: await readJson(input.request),
    headers: routeHeaders(input.request.headers),
    logger: input.logger,
    origin: routeOrigin(input.request.headers),
    route: input.route,
    services: {
      routerApiSponsoredEvmCall: {
        billing: options.billing,
        config: options.config,
        resolveExecutionAdapter: options.resolveExecutionAdapter || null,
        observabilityIngestion: options.observabilityIngestion,
        prepaidReservations: options.prepaidReservations,
        publishableKeyAuth: options.publishableKeyAuth,
        pricing: options.pricing,
        runtimeSnapshots: options.runtimeSnapshots,
        spendCaps: options.spendCaps,
        sponsoredCalls: options.ledger,
        webhooks: options.webhooks || null,
        webhookActorUserId: options.webhookActorUserId,
      },
    },
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
  const routes = consoleRouterApiRoutes(options);
  if (routes.length === 0) return [];

  return [
    {
      kind: 'fetch_route_extension',
      id: 'console_router_api_managed_routes',
      routes,
      async handleFetchRoute(input) {
        const logger = input.logger;
        if (
          input.route.id === ROUTER_API_SPONSORED_EVM_CALL_ROUTE_ID &&
          options.sponsoredEvmCall
        ) {
          return await handleConsoleSponsoredEvmCallRoute({
            request: input.request,
            route: input.route,
            logger,
            sponsoredEvmCall: options.sponsoredEvmCall,
          });
        }

        if (
          input.route.id === ROUTER_API_SIGNED_DELEGATE_ROUTE_ID &&
          options.signedDelegate
        ) {
          return await handleConsoleSignedDelegateRoute({
            request: input.request,
            route: input.route,
            logger,
            signedDelegate: options.signedDelegate,
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
