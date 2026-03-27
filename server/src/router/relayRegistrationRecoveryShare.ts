import type { AuthService } from '../core/AuthService';
import type {
  ThresholdEd25519BootstrapRecoveryShareRequest,
  ThresholdEd25519BootstrapRecoveryShareResponse,
} from '../core/types';
import { enforceRoutePolicy } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import { resolvePublishableKeyApiCredentialAuth } from './relayApiCredentialAuth';
import type { RelayPublishableKeyAuthAdapter } from './relay';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeError, routeJson } from './routeResponses';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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

function responseStatus(code: string | undefined): number {
  switch (String(code || '').trim()) {
    case 'invalid_body':
      return 400;
    case 'not_configured':
      return 501;
    default:
      return 500;
  }
}

export interface RelayRegistrationRecoveryShareInput {
  body: unknown;
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  origin?: string;
  route: RouteDefinition;
  services: {
    authService: AuthService;
    publishableKeyAuth?: RelayPublishableKeyAuthAdapter | null;
  };
}

export async function handleRelayRegistrationRecoveryShare(
  input: RelayRegistrationRecoveryShareInput,
): Promise<
  RouteResponse<ThresholdEd25519BootstrapRecoveryShareResponse | Record<string, unknown> | RouteErrorBody>
> {
  if (!isObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }

  const body = input.body as ThresholdEd25519BootstrapRecoveryShareRequest & Record<string, unknown>;
  const nearAccountId = String(body.nearAccountId || body.newAccountId || '').trim();
  const rpId = String(body.rpId || body.rp_id || '').trim();
  const keyVersion = String(body.keyVersion || body.key_version || '').trim();
  const publishableKeyAuth = input.services.publishableKeyAuth;

  const resolved =
    input.route.auth.plane === 'api_credentials'
      ? await enforceRoutePolicy({
          headers: input.headers,
          logger: input.logger,
          request: { body: input.body, headers: input.headers },
          route: input.route,
          services: {
            authService: input.services.authService,
            ...(publishableKeyAuth ? { publishableKeyAuth } : {}),
          },
          resolvers: publishableKeyAuth
            ? {
                apiCredentials: async () =>
                  await resolvePublishableKeyApiCredentialAuth({
                    headers: input.headers,
                    environmentId: String(body.environmentId || '').trim() || undefined,
                    missingEnvironmentMessage:
                      'registration recovery share requires environmentId',
                    missingOriginMessage:
                      'registration recovery share requires an Origin header',
                    missingPublishableKeyMessage:
                      'registration recovery share requires a publishable key',
                    origin: input.origin,
                    publishableKeyAuth,
                    route: input.route,
                    routeAuthNotConfiguredMessage:
                      'registration recovery share publishable-key auth is not configured',
                  }),
              }
            : undefined,
        })
      : {
          ok: true as const,
          request: { body: input.body, headers: input.headers },
          context: {
            headers: input.headers,
            logger: input.logger,
            principal: { kind: 'public' as const },
            services: { authService: input.services.authService },
          },
        };

  if (!resolved.ok) {
    const parsed = parsePolicyFailureMessage(resolved.body.message);
    return routeJson(resolved.status, {
      ok: false,
      code: parsed.code,
      message: parsed.detail,
    });
  }

  if (!nearAccountId) {
    return routeError(400, 'invalid_body', 'nearAccountId is required');
  }
  if (!rpId) {
    return routeError(400, 'invalid_body', 'rpId is required');
  }
  if (!keyVersion) {
    return routeError(400, 'invalid_body', 'keyVersion is required');
  }

  const result = await input.services.authService.prepareThresholdEd25519BootstrapRecoveryShare({
    nearAccountId,
    rpId,
    keyVersion,
  });
  if (!result.ok) {
    return routeJson(responseStatus(result.code), {
      ok: false,
      code: result.code,
      message: result.message,
    });
  }

  return routeJson(200, {
    ok: true,
    recoveryServerShareB64u: result.recoveryServerShareB64u,
    keyVersion: result.keyVersion,
  });
}
