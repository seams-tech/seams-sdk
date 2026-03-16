import { computeRegistrationBootstrapRequestHashSha256 } from '@shared/utils/registrationBootstrapHash';
import { parseBootstrapToken, type ConsoleBootstrapTokenService } from '../console/bootstrapTokens';
import type { ConsoleApiKey } from '../console/apiKeys';
import {
  enforceRoutePolicy,
  type RoutePolicyResolutionResult,
} from './enforceRoutePolicy';
import {
  extractBearerCredential,
  extractRelayEnvironmentId,
} from './relayApiKeyAuth';
import type {
  RelayApiKeyAuthAdapter,
  RelayBootstrapGrantBroker,
  RelayPublishableKeyAuthAdapter,
} from './relay';
import type { HeaderRecord } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';

interface ResolvePublishableKeyApiCredentialAuthInput {
  environmentId?: string | null;
  headers: HeaderRecord;
  missingEnvironmentMessage: string;
  missingOriginMessage: string;
  missingPublishableKeyMessage: string;
  origin?: string;
  publishableKeyAuth: RelayPublishableKeyAuthAdapter;
  route: RouteDefinition;
  routeAuthNotConfiguredMessage: string;
}

interface ResolveBootstrapGrantApiCredentialAuthInput {
  body: unknown;
  broker: RelayBootstrapGrantBroker;
  headers: HeaderRecord;
  origin?: string;
  onAuthenticated(apiKey: ConsoleApiKey): void;
  route: RouteDefinition;
}

interface ResolveRegistrationBootstrapApiCredentialAuthInput {
  apiKeyAuth?: RelayApiKeyAuthAdapter | null;
  body: unknown;
  bootstrapTokenStore?: ConsoleBootstrapTokenService | null;
  headers: HeaderRecord;
  origin?: string;
  route: RouteDefinition;
  sourceIp?: string;
}

interface ResolveSecretKeyApiCredentialAuthInput {
  apiKeyAuth?: RelayApiKeyAuthAdapter | null;
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

export async function resolveBootstrapGrantApiCredentialAuth(
  input: ResolveBootstrapGrantApiCredentialAuthInput,
): Promise<RoutePolicyResolutionResult> {
  if (input.route.auth.plane !== 'api_credentials') {
    return routeAuthNotConfigured('Bootstrap grants require API credential auth policy');
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
      message:
        'publishable_key_origin_blocked: Origin header is required and must be a valid exact origin',
    };
  }

  const environmentId =
    input.body && typeof input.body === 'object' && !Array.isArray(input.body)
      ? String((input.body as { environmentId?: unknown }).environmentId || '').trim() || undefined
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
      kind: 'api_credentials',
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

export async function resolveRegistrationBootstrapApiCredentialAuth(
  input: ResolveRegistrationBootstrapApiCredentialAuthInput,
): Promise<RoutePolicyResolutionResult> {
  if (input.route.auth.plane !== 'api_credentials') {
    return routeAuthNotConfigured('Registration bootstrap requires API credential auth policy');
  }

  const { apiKeyAuth, bootstrapTokenStore } = input;
  if (!apiKeyAuth && !bootstrapTokenStore) {
    return routeAuthNotConfigured('Relay API credential auth is not configured for this route');
  }

  const credential = extractBearerCredential(input.headers);
  if (!credential) {
    if (bootstrapTokenStore && !apiKeyAuth) {
      return {
        ok: false,
        status: 401,
        code: 'unauthorized',
        message: 'bootstrap_token_missing: Missing bootstrap token',
      };
    }
    return {
      ok: false,
      status: 401,
      code: 'unauthorized',
      message: 'secret_key_missing: Missing secret key',
    };
  }

  const tokenCandidate = parseBootstrapToken(credential);
  if (tokenCandidate) {
    if (!bootstrapTokenStore) {
      return {
        ok: false,
        status: 401,
        code: 'unauthorized',
        message: 'bootstrap_token_invalid: Invalid bootstrap token',
      };
    }
    const requestHashSha256 = await computeRegistrationBootstrapRequestHashSha256(
      input.body && typeof input.body === 'object' && !Array.isArray(input.body) ? input.body : {},
    );
    const redeemResult = await bootstrapTokenStore.redeemToken({
      token: credential,
      origin: String(input.origin || '').trim(),
      method: input.route.method,
      path: input.route.path,
      requestHashSha256,
    });
    if (!redeemResult.ok) {
      return {
        ok: false,
        status: redeemResult.status,
        code: redeemResult.status === 403 ? 'forbidden' : 'unauthorized',
        message: `${redeemResult.code}: ${redeemResult.message}`,
      };
    }
    return {
      ok: true,
      principal: {
        kind: 'api_credentials',
        credentialType: 'bootstrap_token',
        principal: {
          apiKeyId: redeemResult.record.publishableKeyId,
          orgId: redeemResult.record.orgId,
          environmentId: redeemResult.record.environmentId,
          scopes: [...(input.route.auth.scopes || [])],
        },
      },
    };
  }

  if (!apiKeyAuth) {
    return {
      ok: false,
      status: 401,
      code: 'unauthorized',
      message: 'secret_key_invalid: Invalid secret key',
    };
  }

  return await resolveSecretKeyApiCredentialAuth({
    apiKeyAuth,
    headers: input.headers,
    route: input.route,
    sourceIp: input.sourceIp,
    routeAuthNotConfiguredMessage: 'Relay API credential auth is not configured for this route',
  });
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

  if (parseBootstrapToken(credential)) {
    return {
      ok: false,
      status: 401,
      code: 'unauthorized',
      message: 'secret_key_invalid: Invalid secret key',
    };
  }

  const environmentId = extractRelayEnvironmentId(input.headers);
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
