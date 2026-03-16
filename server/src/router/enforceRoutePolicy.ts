import type { RoutePrincipal, RoutePolicyFailureCode } from './routeAuthPolicy';
import type {
  HeaderRecord,
  RouteExecutionContext,
  RouteRequest,
  RouteServices,
} from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';

export interface RoutePolicyResolutionFailure {
  ok: false;
  status: 401 | 403 | 409 | 500 | 501;
  code: RoutePolicyFailureCode;
  message: string;
}

export interface RoutePolicyResolutionSuccess {
  ok: true;
  principal: RoutePrincipal;
}

export type RoutePolicyResolutionResult =
  | RoutePolicyResolutionFailure
  | RoutePolicyResolutionSuccess;

export interface RoutePolicyResolvers<TServices extends RouteServices = RouteServices> {
  apiCredentials?: (
    input: RoutePolicyResolverInput<TServices>,
  ) => Promise<RoutePolicyResolutionResult>;
  console?: (input: RoutePolicyResolverInput<TServices>) => Promise<RoutePolicyResolutionResult>;
  thresholdSession?: (
    input: RoutePolicyResolverInput<TServices>,
  ) => Promise<RoutePolicyResolutionResult>;
  userSession?: (
    input: RoutePolicyResolverInput<TServices>,
  ) => Promise<RoutePolicyResolutionResult>;
}

export interface RoutePolicyResolverInput<TServices extends RouteServices = RouteServices> {
  headers: HeaderRecord;
  request: RouteRequest;
  route: RouteDefinition;
  services: TServices;
  sourceIp?: string;
}

export type EnforceRoutePolicyResult<TServices extends RouteServices = RouteServices> =
  | {
      ok: true;
      request: RouteRequest;
      context: RouteExecutionContext<TServices>;
    }
  | {
      ok: false;
      status: 401 | 403 | 409 | 500 | 501;
      body: { ok: false; code: RoutePolicyFailureCode; message: string };
    };

function missingService(name: string): RoutePolicyResolutionFailure {
  return {
    ok: false,
    status: 501,
    code: 'service_not_configured',
    message: `${name} is not configured for this route`,
  };
}

export async function enforceRoutePolicy<TServices extends RouteServices = RouteServices>(input: {
  headers: HeaderRecord;
  logger: RouteExecutionContext<TServices>['logger'];
  request: RouteRequest;
  resolvers?: RoutePolicyResolvers<TServices>;
  route: RouteDefinition;
  services?: TServices;
  sourceIp?: string;
}): Promise<EnforceRoutePolicyResult<TServices>> {
  const services = (input.services || {}) as TServices;
  for (const service of input.route.requiredServices || []) {
    if (services[service]) continue;
    const failure = missingService(service);
    return {
      ok: false,
      status: failure.status,
      body: { ok: false, code: failure.code, message: failure.message },
    };
  }

  const resolveInput: RoutePolicyResolverInput<TServices> = {
    headers: input.headers,
    request: input.request,
    route: input.route,
    services,
    ...(input.sourceIp ? { sourceIp: input.sourceIp } : {}),
  };

  let authResult: RoutePolicyResolutionResult;
  switch (input.route.auth.plane) {
    case 'public':
      authResult = { ok: true, principal: { kind: 'public' } };
      break;
    case 'api_credentials':
      authResult = input.resolvers?.apiCredentials
        ? await input.resolvers.apiCredentials(resolveInput)
        : {
          ok: false,
          status: 500,
          code: 'route_auth_not_configured',
          message: 'API credential auth resolver is not configured',
        };
      break;
    case 'console':
      authResult = input.resolvers?.console
        ? await input.resolvers.console(resolveInput)
        : {
          ok: false,
          status: 500,
          code: 'route_auth_not_configured',
          message: 'Console auth resolver is not configured',
        };
      break;
    case 'threshold_session':
      authResult = input.resolvers?.thresholdSession
        ? await input.resolvers.thresholdSession(resolveInput)
        : {
          ok: false,
          status: 500,
          code: 'route_auth_not_configured',
          message: 'Threshold-session auth resolver is not configured',
        };
      break;
    case 'user_session':
      authResult = input.resolvers?.userSession
        ? await input.resolvers.userSession(resolveInput)
        : {
          ok: false,
          status: 500,
          code: 'route_auth_not_configured',
          message: 'User-session auth resolver is not configured',
        };
      break;
    default: {
      const plane = (input.route.auth as { plane?: unknown }).plane;
      authResult = {
        ok: false,
        status: 500,
        code: 'route_auth_not_configured',
        message: `Unsupported route auth plane: ${String(plane || 'unknown')}`,
      };
      break;
    }
  }

  if (!authResult.ok) {
    return {
      ok: false,
      status: authResult.status,
      body: { ok: false, code: authResult.code, message: authResult.message },
    };
  }

  return {
    ok: true,
    request: input.request,
    context: {
      headers: input.headers,
      logger: input.logger,
      principal: authResult.principal,
      services,
      ...(input.sourceIp ? { sourceIp: input.sourceIp } : {}),
    },
  };
}
