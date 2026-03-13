import type { AuthService } from '../core/AuthService';
import type {
  CreateAccountAndRegisterRequest,
  CreateAccountAndRegisterResult,
} from '../core/types';
import { parseBootstrapToken, type ConsoleBootstrapTokenService } from '../console/bootstrapTokens';
import { computeRegistrationBootstrapRequestHashSha256 } from '@shared/utils/registrationBootstrapHash';
import { signThresholdSessionJwt } from './commonRouterUtils';
import { applyRouteMetering } from './applyRouteMetering';
import { enforceRoutePolicy, type RoutePolicyResolutionResult } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import {
  type RelayApiKeyAuthAdapter,
  type RelayUsageMeterAdapter,
  type SessionAdapter,
} from './relay';
import { extractBearerCredential, extractRelayEnvironmentId } from './relayApiKeyAuth';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeError, routeJson } from './routeResponses';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

interface RelayRegistrationBootstrapServices {
  authService: AuthService;
  apiKeyAuth?: RelayApiKeyAuthAdapter | null;
  apiKeyUsageMeter?: RelayUsageMeterAdapter | null;
  bootstrapTokenStore?: ConsoleBootstrapTokenService | null;
  session?: SessionAdapter | null;
}

export interface RelayRegistrationBootstrapInput {
  body: unknown;
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  origin?: string;
  route: RouteDefinition;
  services: RelayRegistrationBootstrapServices;
  sourceIp?: string;
}

async function resolveRegistrationBootstrapMachineAuth(
  input: RelayRegistrationBootstrapInput,
): Promise<RoutePolicyResolutionResult> {
  if (input.route.auth.plane !== 'machine') {
    return {
      ok: false,
      status: 500,
      code: 'route_auth_not_configured',
      message: 'Registration bootstrap requires machine auth policy',
    };
  }

  const { apiKeyAuth, bootstrapTokenStore } = input.services;
  if (!apiKeyAuth && !bootstrapTokenStore) {
    return {
      ok: false,
      status: 500,
      code: 'route_auth_not_configured',
      message: 'Relay machine auth is not configured for this route',
    };
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
      isObject(input.body) ? input.body : {},
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
        kind: 'machine',
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
      kind: 'machine',
      credentialType: 'secret_key',
      principal: authResult.principal,
    },
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

async function meterRegistrationBootstrap(input: {
  logger: NormalizedRouterLogger;
  response: CreateAccountAndRegisterResult;
  route: RouteDefinition;
  routeContext: Awaited<ReturnType<typeof enforceRoutePolicy>> extends infer TResult
    ? TResult extends { ok: true; context: infer TContext }
      ? TContext
      : never
    : never;
  services: RelayRegistrationBootstrapServices;
  walletId: string;
}): Promise<void> {
  try {
    await applyRouteMetering({
      context: input.routeContext,
      route: input.route,
      response: routeJson(input.response.success ? 200 : 400, input.response, {
        usage: { walletId: input.walletId },
      }),
      handlers: {
        event: async ({ action, context, response, route }) => {
          if (action !== 'wallet_created') return;
          if (context.principal.kind !== 'machine') return;
          if (!input.services.apiKeyUsageMeter) return;
          const walletId = String(response.usage?.walletId || input.walletId || '').trim();
          if (!walletId) return;
          await input.services.apiKeyUsageMeter.recordEvent({
            orgId: context.principal.principal.orgId,
            environmentId: context.principal.principal.environmentId,
            apiKeyId: context.principal.principal.apiKeyId,
            endpoint: `${route.method} ${route.path}`,
            walletId,
            action: 'wallet_created',
            succeeded: Boolean((response.body as CreateAccountAndRegisterResult).success),
            occurredAt: new Date().toISOString(),
            sourceEventId: `registration_bootstrap:${context.principal.principal.apiKeyId}:${walletId}`,
          });
        },
      },
    });
  } catch (error: unknown) {
    const routeContext = input.routeContext;
    if (routeContext.principal.kind !== 'machine') return;
    input.logger.warn('[relay][api-key] usage meter event failed', {
      endpoint: `${input.route.method} ${input.route.path}`,
      orgId: routeContext.principal.principal.orgId,
      environmentId: routeContext.principal.principal.environmentId,
      apiKeyId: routeContext.principal.principal.apiKeyId,
      walletId: input.walletId,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

export async function handleRelayRegistrationBootstrap(
  input: RelayRegistrationBootstrapInput,
): Promise<RouteResponse<CreateAccountAndRegisterResult | Record<string, unknown> | RouteErrorBody>> {
  if (!isObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }

  const body = input.body as CreateAccountAndRegisterRequest & Record<string, unknown>;
  const new_account_id = String(body.new_account_id || '').trim();
  const new_public_key =
    typeof body.new_public_key === 'string' ? String(body.new_public_key || '').trim() : '';
  const device_number = body.device_number;
  const threshold_ed25519 = body.threshold_ed25519;
  const threshold_ecdsa = body.threshold_ecdsa;
  const rp_id = typeof body.rp_id === 'string' ? String(body.rp_id || '').trim() : '';
  const webauthn_registration = isObject(body.webauthn_registration) ? body.webauthn_registration : null;
  const authenticator_options = body.authenticator_options;

  if (!new_account_id) {
    return routeError(400, 'invalid_body', 'Missing or invalid new_account_id');
  }
  if (!rp_id) {
    return routeError(400, 'invalid_body', 'Missing or invalid rp_id');
  }
  if (!webauthn_registration) {
    return routeError(400, 'invalid_body', 'Missing or invalid webauthn_registration');
  }

  const resolved = await enforceRoutePolicy({
    headers: input.headers,
    logger: input.logger,
    request: { body, headers: input.headers },
    route: input.route,
    services: { authService: input.services.authService },
    sourceIp: input.sourceIp,
    resolvers: {
      machine: async () => await resolveRegistrationBootstrapMachineAuth(input),
    },
  });
  if (!resolved.ok) {
    if (resolved.body.code === 'route_auth_not_configured' || resolved.body.code === 'service_not_configured') {
      return routeJson(resolved.status, resolved.body);
    }
    const parsed = parsePolicyFailureMessage(resolved.body.message);
    return routeJson(resolved.status, {
      ok: false,
      code: parsed.code,
      message: parsed.detail,
    });
  }

  const result = await input.services.authService.createAccountAndRegisterUser({
    new_account_id,
    ...(new_public_key ? { new_public_key } : {}),
    device_number,
    ...(threshold_ed25519 ? { threshold_ed25519 } : {}),
    ...(threshold_ecdsa ? { threshold_ecdsa } : {}),
    rp_id,
    webauthn_registration,
    expected_origin: String(input.origin || '').trim() || undefined,
    authenticator_options,
  });
  const response: CreateAccountAndRegisterResult = result;

  await meterRegistrationBootstrap({
    logger: input.logger,
    response,
    route: input.route,
    routeContext: resolved.context,
    services: input.services,
    walletId: new_account_id,
  });

  if (!response.success) {
    return routeJson(400, response, { usage: { walletId: new_account_id } });
  }

  const session = input.services.session;
  if (!session) {
    return routeJson(200, response, { usage: { walletId: new_account_id } });
  }

  if (response.thresholdEd25519?.session) {
    const signed = await signThresholdSessionJwt({
      session,
      kind: 'threshold_ed25519_session_v1',
      userId: new_account_id,
      rpId: rp_id,
      relayerKeyId: response.thresholdEd25519.relayerKeyId,
      sessionInfo: response.thresholdEd25519.session,
      fallbackParticipantIds: response.thresholdEd25519.participantIds,
      requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
      invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
    });
    if (!signed.ok) {
      return routeJson(signed.status, { success: false, error: signed.message });
    }
    response.thresholdEd25519.session.jwt = signed.jwt;
  }

  if (response.thresholdEcdsa?.session) {
    const signed = await signThresholdSessionJwt({
      session,
      kind: 'threshold_ecdsa_session_v1',
      userId: new_account_id,
      rpId: rp_id,
      relayerKeyId: response.thresholdEcdsa.relayerKeyId,
      sessionInfo: response.thresholdEcdsa.session,
      fallbackParticipantIds: response.thresholdEcdsa.participantIds,
      requireJwtErrorMessage: 'threshold_ecdsa.session_kind must be jwt',
      invalidPayloadErrorMessage: 'invalid thresholdEcdsa session payload for jwt signing',
    });
    if (!signed.ok) {
      return routeJson(signed.status, { success: false, error: signed.message });
    }
    response.thresholdEcdsa.session.jwt = signed.jwt;
  }

  return routeJson(200, response, { usage: { walletId: new_account_id } });
}
