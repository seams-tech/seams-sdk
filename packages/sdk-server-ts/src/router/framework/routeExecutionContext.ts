import type { NormalizedRouterLogger } from './logger';
import type { RoutePrincipal } from './routeAuthPolicy';
import type { RouteUsageData } from './routeMeteringPolicy';

export type HeaderRecord = Record<string, string | string[] | undefined>;
export type RouteMethod = 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT';

export const ROUTE_SERVICE_KEYS = [
  'apiKeyAuth',
  'emailOtp',
  'identity',
  'nearFunding',
  'orgProjectEnv',
  'passkeyCustody',
  'publishableKeyAuth',
  'recovery',
  'signingSessionSeal',
  'router',
  'session',
  'signedDelegateAuth',
  'thresholdRuntime',
  'walletAuthMethods',
  'walletRegistration',
  'walletUnlock',
  'webAuthn',
] as const;
export type CoreRouteServiceKey = (typeof ROUTE_SERVICE_KEYS)[number];
export type RouteServiceKey = string;

export type RouteServices = Partial<Record<CoreRouteServiceKey, unknown>>;

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

export interface RouteExecutionContext<TServices extends object = RouteServices> {
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  principal: RoutePrincipal;
  services: TServices;
  sourceIp?: string;
}
