import type { ConsoleApiKey } from '../console/apiKeys';
import { RelayBootstrapGrantError, parseRelayBootstrapGrantIssueBody } from './bootstrapGrantBroker';
import { enforceRoutePolicy, type RoutePolicyResolutionResult } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import type { RelayBootstrapGrantBroker } from './relay';
import { extractBearerCredential } from './relayApiKeyAuth';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeJson } from './routeResponses';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export interface RelayBootstrapGrantInput {
  body: unknown;
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  origin?: string;
  route: RouteDefinition;
  services: {
    bootstrapGrantBroker?: RelayBootstrapGrantBroker | null;
  };
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

async function resolveBootstrapGrantMachineAuth(input: {
  body: unknown;
  headers: HeaderRecord;
  origin?: string;
  route: RouteDefinition;
  broker: RelayBootstrapGrantBroker;
  onAuthenticated(apiKey: ConsoleApiKey): void;
}): Promise<RoutePolicyResolutionResult> {
  if (input.route.auth.plane !== 'machine') {
    return {
      ok: false,
      status: 500,
      code: 'route_auth_not_configured',
      message: 'Bootstrap grants require machine auth policy',
    };
  }

  const publishableKey = extractBearerCredential(input.headers);
  if (!publishableKey) {
    return {
      ok: false,
      status: 401,
      code: 'unauthorized',
      message: 'publishable_key_missing: Missing publishable key',
    };
  }

  const origin = String(input.origin || '').trim();
  if (!origin) {
    return {
      ok: false,
      status: 403,
      code: 'forbidden',
      message: 'publishable_key_origin_blocked: Origin header is required and must be a valid exact origin',
    };
  }

  const environmentId =
    isObject(input.body) && typeof input.body.environmentId === 'string'
      ? String(input.body.environmentId || '').trim()
      : undefined;
  const authResult = await input.broker.authenticatePublishableKey({
    publishableKey,
    origin,
    ...(environmentId ? { environmentId } : {}),
  });
  if (!authResult.ok) {
    return {
      ok: false,
      status: authResult.status,
      code: authResult.status === 403 ? 'forbidden' : 'unauthorized',
      message: `${authResult.code}: ${authResult.message}`,
    };
  }

  input.onAuthenticated(authResult.apiKey);
  return {
    ok: true,
    principal: {
      kind: 'machine',
      credentialType: 'publishable_key',
      principal: {
        apiKeyId: authResult.apiKey.id,
        orgId: authResult.apiKey.orgId,
        environmentId: authResult.apiKey.environmentId,
        scopes: [],
      },
    },
  };
}

export async function handleRelayBootstrapGrant(
  input: RelayBootstrapGrantInput,
): Promise<RouteResponse<Record<string, unknown> | RouteErrorBody>> {
  const broker = input.services.bootstrapGrantBroker || null;
  let authenticatedApiKey: ConsoleApiKey | null = null;
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
          machine: async () =>
            await resolveBootstrapGrantMachineAuth({
              body: input.body,
              headers: input.headers,
              origin: input.origin,
              route: input.route,
              broker,
              onAuthenticated(apiKey) {
                authenticatedApiKey = apiKey;
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
    const parsedBody = parseRelayBootstrapGrantIssueBody(input.body);
    if (!authenticatedApiKey) {
      return routeJson(500, {
        ok: false,
        code: 'internal',
        message: 'Authenticated publishable key was not resolved',
      });
    }
    const result = await broker!.issueGrantForAuthenticatedKey({
      authenticatedApiKey,
      origin: String(input.origin || '').trim(),
      ...parsedBody,
    });
    if (!result.ok) {
      input.logger.warn('[relay][bootstrap-grants] denied', {
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

    input.logger.info('[relay][bootstrap-grants] issued', {
      environmentId: parsedBody.environmentId,
      mode: result.grant.mode,
    });
    return routeJson(200, { ok: true, grant: result.grant });
  } catch (error: unknown) {
    if (error instanceof RelayBootstrapGrantError) {
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
