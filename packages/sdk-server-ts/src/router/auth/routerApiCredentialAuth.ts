import {
  enforceRoutePolicy,
  type RoutePolicyResolutionResult,
} from '../framework/enforceRoutePolicy';
import {
  extractBearerCredential,
  extractRouterApiEnvironmentId,
} from './routerApiKeyAuth';
import type {
  RouterApiKeyAuthAdapter,
  RouterApiPublishableKeyAuthAdapter,
} from '../framework/routerApi';
import type { HeaderRecord } from '../framework/routeExecutionContext';
import type { RouteDefinition } from '../framework/routeDefinitions';


interface ResolvePublishableKeyApiCredentialAuthInput {
  environmentId?: string | null;
  headers: HeaderRecord;
  missingEnvironmentMessage: string;
  missingOriginMessage: string;
  missingPublishableKeyMessage: string;
  origin?: string;
  publishableKeyAuth: RouterApiPublishableKeyAuthAdapter;
  route: RouteDefinition;
  routeAuthNotConfiguredMessage: string;
}


interface ResolveSecretKeyApiCredentialAuthInput {
  apiKeyAuth?: RouterApiKeyAuthAdapter | null;
  headers: HeaderRecord;
  route: RouteDefinition;
  sourceIp?: string;
  routeAuthNotConfiguredMessage: string;
}

function routeAuthNotConfigured(
  message: string,
): RoutePolicyResolutionResult {
  return {
    ok: false,
    status: 500,
    code: 'route_auth_not_configured',
    message,
  };
}

export async function resolvePublishableKeyApiCredentialAuth(
  input: ResolvePublishableKeyApiCredentialAuthInput,
): Promise<RoutePolicyResolutionResult> {
  if (input.route.auth.plane !== 'api_credentials') {
    return routeAuthNotConfigured(input.routeAuthNotConfiguredMessage);
  }

  const publishableKey = extractBearerCredential(input.headers);
  if (!publishableKey) {
    return {
      ok: false,
      status: 401,
      code: 'unauthorized',
      message: `publishable_key_missing: ${input.missingPublishableKeyMessage}`,
    };
  }

  const origin = String(input.origin || '').trim();
  if (!origin) {
    return {
      ok: false,
      status: 403,
      code: 'forbidden',
      message: `publishable_key_origin_blocked: ${input.missingOriginMessage}`,
    };
  }

  const environmentId = String(input.environmentId || '').trim();
  if (!environmentId) {
    return {
      ok: false,
      status: 403,
      code: 'forbidden',
      message: `publishable_key_environment_mismatch: ${input.missingEnvironmentMessage}`,
    };
  }

  const authResult = await input.publishableKeyAuth.authenticate({
    secret: publishableKey,
    origin,
    environmentId,
  });
  if (!authResult.ok) {
    return {
      ok: false,
      status: authResult.status,
      code: authResult.status === 403 ? 'forbidden' : 'unauthorized',
      message: `${authResult.code}: ${authResult.message}`,
    };
  }

  return {
    ok: true,
    principal: {
      kind: 'api_credentials',
      credentialType: 'publishable_key',
      principal: authResult.principal,
    },
  };
}


export async function resolveSecretKeyApiCredentialAuth(
  input: ResolveSecretKeyApiCredentialAuthInput,
): Promise<RoutePolicyResolutionResult> {
  if (input.route.auth.plane !== 'api_credentials') {
    return routeAuthNotConfigured(input.routeAuthNotConfiguredMessage);
  }

  const apiKeyAuth = input.apiKeyAuth;
  if (!apiKeyAuth) {
    return routeAuthNotConfigured(input.routeAuthNotConfiguredMessage);
  }

  const credential = extractBearerCredential(input.headers);
  if (!credential) {
    return {
      ok: false,
      status: 401,
      code: 'unauthorized',
      message: 'secret_key_missing: Missing secret key',
    };
  }


  const environmentId = extractRouterApiEnvironmentId(input.headers);
  const authResult = await apiKeyAuth.authenticate({
    secret: credential,
    endpoint: `${input.route.method} ${input.route.path}`,
    requiredScopes: [...(input.route.auth.scopes || [])],
    ...(input.sourceIp ? { sourceIp: input.sourceIp } : {}),
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
  return {
    ok: true,
    principal: {
      kind: 'api_credentials',
      credentialType: 'secret_key',
      principal: authResult.principal,
    },
  };
}
