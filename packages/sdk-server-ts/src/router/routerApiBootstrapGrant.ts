import { RouterApiBootstrapGrantError, parseRouterApiBootstrapGrantIssueBody } from './bootstrapGrantBroker';
import { enforceRoutePolicy } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import { resolveBootstrapGrantApiCredentialAuth } from './routerApiCredentialAuth';
import type {
  RouterApiAuthenticatedPublishableCredential,
  RouterApiBootstrapGrantBroker,
} from './routerApi';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeJson } from './routeResponses';

export interface RouterApiBootstrapGrantInput {
  body: unknown;
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  origin?: string;
  route: RouteDefinition;
  services: {
    bootstrapGrantBroker?: RouterApiBootstrapGrantBroker | null;
  };
}

function parsePolicyFailureMessage(message: string): { code: string; detail: string } {
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

export async function handleRouterApiBootstrapGrant(
  input: RouterApiBootstrapGrantInput,
): Promise<RouteResponse<Record<string, unknown> | RouteErrorBody>> {
  const broker = input.services.bootstrapGrantBroker || null;
  let authenticatedCredential: RouterApiAuthenticatedPublishableCredential | null = null;
  const resolved = await enforceRoutePolicy({
    headers: input.headers,
    logger: input.logger,
    request: { body: input.body, headers: input.headers },
    route: input.route,
    services: {
      ...(broker ? { bootstrapGrantBroker: broker } : {}),
    },
    resolvers: broker
      ? {
          apiCredentials: async () =>
            await resolveBootstrapGrantApiCredentialAuth({
              body: input.body,
              headers: input.headers,
              origin: input.origin,
              route: input.route,
              broker,
              onAuthenticated(credential) {
                authenticatedCredential = credential;
              },
            }),
        }
      : undefined,
  });

  if (!resolved.ok) {
    if (
      resolved.body.code === 'route_auth_not_configured' ||
      resolved.body.code === 'service_not_configured'
    ) {
      const serviceCode =
        broker === null ? 'bootstrap_grants_not_configured' : resolved.body.code;
      const serviceMessage =
        broker === null
          ? 'Managed bootstrap grants are not configured on this server'
          : resolved.body.message;
      return routeJson(resolved.status, {
        ok: false,
        code: serviceCode,
        message: serviceMessage,
      });
    }
    const parsed = parsePolicyFailureMessage(resolved.body.message);
    return routeJson(resolved.status, {
      ok: false,
      code: parsed.code,
      message: parsed.detail,
    });
  }

  try {
    const parsedBody = parseRouterApiBootstrapGrantIssueBody(input.body);
    if (!authenticatedCredential) {
      return routeJson(500, {
        ok: false,
        code: 'internal',
        message: 'Authenticated publishable key was not resolved',
      });
    }
    const result = await broker!.issueGrantForAuthenticatedKey({
      authenticatedCredential,
      origin: String(input.origin || '').trim(),
      ...parsedBody,
    });
    if (!result.ok) {
      input.logger.warn('[router-api][bootstrap-grants] denied', {
        code: result.code,
        status: result.status,
        environmentId: parsedBody.environmentId,
      });
      return routeJson(result.status, {
        ok: false,
        code: result.code,
        message: result.message,
        ...(result.payment ? { payment: result.payment } : {}),
      });
    }

    input.logger.info('[router-api][bootstrap-grants] issued', {
      environmentId: parsedBody.environmentId,
      mode: result.grant.mode,
    });
    return routeJson(200, { ok: true, grant: result.grant });
  } catch (error: unknown) {
    if (error instanceof RouterApiBootstrapGrantError) {
      return routeJson(error.status, {
        ok: false,
        code: error.code,
        message: error.message,
      });
    }
    return routeJson(500, {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    });
  }
}
