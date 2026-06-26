import { computeRegistrationBootstrapRequestHashSha256 } from '@shared/utils/registrationBootstrapHash';
import type { ConsoleBootstrapTokenService } from '../console/bootstrapTokens/service';
import { parseBootstrapToken } from '../console/bootstrapTokens/secret';
import type { ConsoleApiKey } from '../console/apiKeys/types';
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

function inferEnvIdFromEnvironmentId(input: {
  projectId?: unknown;
  environmentId?: unknown;
}): string | undefined {
  const projectId = String(input.projectId || '').trim();
  const environmentId = String(input.environmentId || '').trim();
  if (!environmentId) return undefined;
  if (projectId) {
    for (const separator of [':', '-']) {
      const prefix = `${projectId}${separator}`;
      if (environmentId.startsWith(prefix)) {
        const envId = environmentId.slice(prefix.length).trim();
        if (envId) return envId;
      }
    }
  }
  const colonIndex = environmentId.lastIndexOf(':');
  if (colonIndex >= 0 && colonIndex < environmentId.length - 1) {
    return environmentId.slice(colonIndex + 1).trim() || undefined;
  }
  return undefined;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function readTrimmedString(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  return typeof value === 'string' ? value.trim() : '';
}

function extractSponsoredRequestedAccountId(
  signerSelection: Record<string, unknown>,
): string {
  const ed25519 = asRecord(signerSelection.ed25519);
  if (!ed25519) return '';
  const accountProvisioning = asRecord(ed25519.accountProvisioning);
  if (!accountProvisioning) return '';
  if (readTrimmedString(accountProvisioning, 'kind') !== 'sponsored_named_account') return '';
  return readTrimmedString(accountProvisioning, 'requestedAccountId');
}

function extractRegistrationBootstrapRequestedAccountId(body: unknown): string {
  const bodyRecord = asRecord(body);
  if (!bodyRecord) return '';
  const signerSelection = asRecord(bodyRecord.signerSelection);
  const sponsoredRequestedAccountId = signerSelection
    ? extractSponsoredRequestedAccountId(signerSelection)
    : '';
  if (sponsoredRequestedAccountId) return sponsoredRequestedAccountId;
  return (
    readTrimmedString(bodyRecord, 'newAccountId') ||
    readTrimmedString(bodyRecord, 'new_account_id') ||
    readTrimmedString(bodyRecord, 'walletId')
  );
}

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
    const tokenRecord = await bootstrapTokenStore.peekTokenRecord(credential);
    if (!tokenRecord) {
      return {
        ok: false,
        status: 401,
        code: 'unauthorized',
        message: 'bootstrap_token_invalid: Invalid bootstrap token',
      };
    }
    const requestHashSha256 = tokenRecord.requestHashSha256
      ? await computeRegistrationBootstrapRequestHashSha256(
          input.body && typeof input.body === 'object' && !Array.isArray(input.body)
            ? input.body
            : {},
        )
      : undefined;
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
    const bodyRecord = asRecord(input.body) || {};
    const requestedAccountId = extractRegistrationBootstrapRequestedAccountId(bodyRecord);
    const requestedRpId = String(bodyRecord.rp_id || bodyRecord.rpId || '').trim();
    if (
      (redeemResult.record.newAccountId &&
        redeemResult.record.newAccountId !== requestedAccountId) ||
      (redeemResult.record.rpId && redeemResult.record.rpId !== requestedRpId)
    ) {
      return {
        ok: false,
        status: 409,
        code: 'unauthorized',
        message: 'bootstrap_token_request_mismatch: Bootstrap token is not valid for this request payload',
      };
    }
    const envId = inferEnvIdFromEnvironmentId({
      projectId: redeemResult.record.projectId,
      environmentId: redeemResult.record.environmentId,
    });
    return {
      ok: true,
      principal: {
        kind: 'api_credentials',
        credentialType: 'bootstrap_token',
        principal: {
          apiKeyId: redeemResult.record.publishableKeyId,
          orgId: redeemResult.record.orgId,
          projectId: redeemResult.record.projectId,
          environmentId: redeemResult.record.environmentId,
          ...(envId ? { envId } : {}),
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
