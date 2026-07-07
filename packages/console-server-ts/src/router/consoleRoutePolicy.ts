import { hasConsoleRole, type ConsoleAuthClaims } from '@seams/sdk-server/internal/router/consoleAuth';
import type { RoutePolicyFailureCode } from '@seams/sdk-server/internal/router/routeAuthPolicy';
import {
  findRouteDefinitionForRequest,
  type RouteDefinition,
} from '@seams/sdk-server/internal/router/routeDefinitions';

export type ConsoleRouteAuthorizationResult =
  | { ok: true; route: RouteDefinition }
  | {
      ok: false;
      status: 403 | 500;
      body: {
        ok: false;
        code: RoutePolicyFailureCode;
        message: string;
      };
    };

function formatRoleList(roles: readonly string[]): string {
  if (roles.length === 0) return 'authorized team members';
  if (roles.length === 1) return roles[0] || 'authorized team members';
  if (roles.length === 2) return `${roles[0]} or ${roles[1]}`;
  return `${roles.slice(0, -1).join(', ')}, or ${roles[roles.length - 1]}`;
}

export function authorizeConsoleRouteRequest(input: {
  claims: ConsoleAuthClaims;
  definitions: readonly RouteDefinition[];
  method: string;
  pathname: string;
}): ConsoleRouteAuthorizationResult {
  const route = findRouteDefinitionForRequest(input.definitions, input.method, input.pathname);
  if (!route) {
    return {
      ok: false,
      status: 500,
      body: {
        ok: false,
        code: 'route_auth_not_configured',
        message: `Missing console route definition for ${input.method.toUpperCase()} ${input.pathname}`,
      },
    };
  }
  if (route.auth.plane !== 'console') {
    return {
      ok: false,
      status: 500,
      body: {
        ok: false,
        code: 'route_auth_not_configured',
        message: `Route ${route.id} is not configured for console auth`,
      },
    };
  }

  const roles = route.auth.roles || [];
  if (roles.length === 0 || roles.some((role) => hasConsoleRole(input.claims, role))) {
    return { ok: true, route };
  }

  return {
    ok: false,
    status: 403,
    body: {
      ok: false,
      code: 'forbidden',
      message:
        route.auth.forbiddenMessage ||
        `Only ${formatRoleList(roles)} can access ${route.summary.toLowerCase()}`,
    },
  };
}
