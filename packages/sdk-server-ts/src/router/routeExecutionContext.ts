import type { NormalizedRouterLogger } from './logger';
import type { RoutePrincipal } from './routeAuthPolicy';
import type { RouteUsageData } from './routeMeteringPolicy';

export type HeaderRecord = Record<string, string | string[] | undefined>;
export type RouteMethod = 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT';

export const ROUTE_SERVICE_KEYS = [
  'account',
  'apiKeyAuth',
  'apiKeys',
  'approvals',
  'audit',
  'auditExports',
  'authService',
  'billing',
  'bootstrapGrantBroker',
  'bootstrapTokenStore',
  'enterpriseIsolation',
  'keyExports',
  'observability',
  'observabilityIngestion',
  'onboarding',
  'orgProjectEnv',
  'policies',
  'publishableKeyAuth',
  'signingSessionSeal',
  'routerApiSponsoredEvmCall',
  'routerApiWebhooks',
  'runtimeSnapshots',
  'session',
  'sponsoredCalls',
  'teamRbac',
  'threshold',
  'wallets',
  'webhooks',
] as const;
export type RouteServiceKey = (typeof ROUTE_SERVICE_KEYS)[number];

export type RouteServices = Partial<Record<RouteServiceKey, unknown>>;

export interface RouteRequest<TBody = unknown> {
  body: TBody;
  headers: HeaderRecord;
  params?: Record<string, string>;
  query?: Record<string, string | string[] | undefined>;
}

export interface RouteResponse<TBody = unknown> {
  status: number;
  body: TBody;
  headers?: Record<string, string>;
  usage?: RouteUsageData;
}

export interface RouteExecutionContext<TServices extends RouteServices = RouteServices> {
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  principal: RoutePrincipal;
  services: TServices;
  sourceIp?: string;
}
