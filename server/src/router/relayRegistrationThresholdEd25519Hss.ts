import type { AuthService } from '../core/AuthService';
import type {
  ThresholdEd25519HssFinalizeForRegistrationRequest,
  ThresholdEd25519HssFinalizeForRegistrationResponse,
  ThresholdEd25519HssPrepareForRegistrationRequest,
  ThresholdEd25519HssPrepareForRegistrationResponse,
  ThresholdEd25519HssRespondForRegistrationRequest,
  ThresholdEd25519HssRespondForRegistrationResponse,
} from '../core/types';
import { enforceRoutePolicy } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import { resolveRegistrationBootstrapApiCredentialAuth } from './relayApiCredentialAuth';
import type { RelayApiKeyAuthAdapter, SessionAdapter } from './relay';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeError, routeJson } from './routeResponses';
import type { ConsoleBootstrapTokenService } from '../console/bootstrapTokens';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

type RelayRegistrationThresholdEd25519HssServices = {
  authService: AuthService;
  apiKeyAuth?: RelayApiKeyAuthAdapter | null;
  bootstrapTokenStore?: ConsoleBootstrapTokenService | null;
  session?: SessionAdapter | null;
};

type RelayRegistrationThresholdEd25519HssInput = {
  body: unknown;
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  origin?: string;
  route: RouteDefinition;
  services: RelayRegistrationThresholdEd25519HssServices;
  sourceIp?: string;
};

type RelayRegistrationThresholdEd25519HssPolicyResult =
  | {
      ok: true;
      orgId: string;
    }
  | {
      ok: false;
      response: RouteResponse<RouteErrorBody>;
    };

type RelayRegistrationThresholdEd25519HssHandler<TResponse> = (
  input: RelayRegistrationThresholdEd25519HssInput,
) => Promise<RouteResponse<TResponse | RouteErrorBody>>;

async function enforceRegistrationHssPolicy(
  input: RelayRegistrationThresholdEd25519HssInput,
): Promise<RelayRegistrationThresholdEd25519HssPolicyResult> {
  const body = isObject(input.body) ? input.body : null;
  if (!body) {
    return { ok: false, response: routeError(400, 'invalid_body', 'JSON body required') };
  }
  const resolved = await enforceRoutePolicy({
    headers: input.headers,
    logger: input.logger,
    request: { body, headers: input.headers },
    route: input.route,
    services: { authService: input.services.authService },
    sourceIp: input.sourceIp,
    resolvers: {
      apiCredentials: async () =>
        await resolveRegistrationBootstrapApiCredentialAuth({
          apiKeyAuth: input.services.apiKeyAuth,
          body,
          bootstrapTokenStore: input.services.bootstrapTokenStore,
          headers: input.headers,
          origin: input.origin,
          route: input.route,
          sourceIp: input.sourceIp,
        }),
    },
  });
  if (!resolved.ok) {
    return { ok: false, response: routeJson(resolved.status, resolved.body) };
  }
  if (resolved.context.principal.kind !== 'api_credentials') {
    return {
      ok: false,
      response: routeJson(500, {
        ok: false,
        code: 'internal',
        message: 'Registration threshold-ed25519 HSS requires an API credential principal',
      }),
    };
  }
  return {
    ok: true,
    orgId: resolved.context.principal.principal.orgId,
  };
}

export const handleRelayRegistrationThresholdEd25519HssPrepare: RelayRegistrationThresholdEd25519HssHandler<
  ThresholdEd25519HssPrepareForRegistrationResponse
> = async (input) => {
  const auth = await enforceRegistrationHssPolicy(input);
  if (!auth.ok) return auth.response;

  const threshold = input.services.authService.getThresholdSigningService();
  if (!threshold || !threshold.ed25519Hss) {
    return routeJson(501, {
      ok: false,
      code: 'threshold_disabled',
      message: 'Threshold Ed25519 HSS is not configured on this server',
    });
  }

  const result = await threshold.ed25519Hss.prepareForRegistration({
    orgId: auth.orgId,
    request: (input.body || {}) as ThresholdEd25519HssPrepareForRegistrationRequest,
  });
  return routeJson(result.ok ? 200 : 400, result);
};

export const handleRelayRegistrationThresholdEd25519HssFinalize: RelayRegistrationThresholdEd25519HssHandler<
  ThresholdEd25519HssFinalizeForRegistrationResponse
> = async (input) => {
  const auth = await enforceRegistrationHssPolicy(input);
  if (!auth.ok) return auth.response;

  const threshold = input.services.authService.getThresholdSigningService();
  if (!threshold || !threshold.ed25519Hss) {
    return routeJson(501, {
      ok: false,
      code: 'threshold_disabled',
      message: 'Threshold Ed25519 HSS is not configured on this server',
    });
  }

  const result = await threshold.ed25519Hss.finalizeForRegistration({
    orgId: auth.orgId,
    request: (input.body || {}) as ThresholdEd25519HssFinalizeForRegistrationRequest,
  });
  return routeJson(result.ok ? 200 : 400, result);
};

export const handleRelayRegistrationThresholdEd25519HssRespond: RelayRegistrationThresholdEd25519HssHandler<
  ThresholdEd25519HssRespondForRegistrationResponse
> = async (input) => {
  const auth = await enforceRegistrationHssPolicy(input);
  if (!auth.ok) return auth.response;

  const threshold = input.services.authService.getThresholdSigningService();
  if (!threshold || !threshold.ed25519Hss) {
    return routeJson(501, {
      ok: false,
      code: 'threshold_disabled',
      message: 'Threshold Ed25519 HSS is not configured on this server',
    });
  }

  const result = await threshold.ed25519Hss.respondForRegistration({
    orgId: auth.orgId,
    request: (input.body || {}) as ThresholdEd25519HssRespondForRegistrationRequest,
  });
  return routeJson(result.ok ? 200 : 400, result);
};
