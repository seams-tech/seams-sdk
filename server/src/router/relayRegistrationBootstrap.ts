import type { AuthService } from '../core/AuthService';
import type {
  CreateAccountAndRegisterRequest,
  CreateAccountAndRegisterResult,
} from '../core/types';
import type { ConsoleBootstrapTokenService } from '../console/bootstrapTokens';
import type { ConsoleOrgProjectEnvService } from '../console/orgProjectEnv';
import {
  resolveActiveRuntimePolicyScopeForEnvironment,
  signRegistrationContinuationJwt,
  signThresholdSessionAuthToken,
} from './commonRouterUtils';
import { applyRouteMetering } from './applyRouteMetering';
import { enforceRoutePolicy } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import { resolveRegistrationBootstrapApiCredentialAuth } from './relayApiCredentialAuth';
import {
  type RelayApiKeyAuthAdapter,
  type RelayUsageMeterAdapter,
  type SessionAdapter,
} from './relay';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeError, routeJson } from './routeResponses';
import { isPlainObject } from '@shared/utils/validation';
import {
  thresholdEcdsaChainTargetFromValue,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '../core/thresholdEcdsaChainTarget';

interface RelayRegistrationBootstrapServices {
  authService: AuthService;
  apiKeyAuth?: RelayApiKeyAuthAdapter | null;
  apiKeyUsageMeter?: RelayUsageMeterAdapter | null;
  bootstrapTokenStore?: ConsoleBootstrapTokenService | null;
  orgProjectEnv?: ConsoleOrgProjectEnvService | null;
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

function normalizeRegistrationContinuationEcdsaTargets(
  raw: unknown,
):
  | { ok: true; targets: ThresholdEcdsaChainTarget[] }
  | { ok: false; message: string } {
  if (raw == null) return { ok: true, targets: [] };
  if (!isPlainObject(raw)) {
    return { ok: false, message: 'registration_continuation must be an object' };
  }
  const targetsRaw = raw.threshold_ecdsa_chain_targets;
  if (!Array.isArray(targetsRaw)) {
    return {
      ok: false,
      message: 'registration_continuation.threshold_ecdsa_chain_targets must be an array',
    };
  }
  const targets: ThresholdEcdsaChainTarget[] = [];
  const seenTargets = new Set<string>();
  for (let index = 0; index < targetsRaw.length; index += 1) {
    const target = thresholdEcdsaChainTargetFromValue(targetsRaw[index]);
    if (!target) {
      return {
        ok: false,
        message: `registration_continuation.threshold_ecdsa_chain_targets[${index}] must be concrete`,
      };
    }
    const targetKey = thresholdEcdsaChainTargetKey(target);
    if (seenTargets.has(targetKey)) {
      return {
        ok: false,
        message: `registration_continuation.threshold_ecdsa_chain_targets contains duplicate target "${targetKey}"`,
      };
    }
    seenTargets.add(targetKey);
    targets.push(target);
  }
  return { ok: true, targets };
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
          if (context.principal.kind !== 'api_credentials') return;
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
    if (routeContext.principal.kind !== 'api_credentials') return;
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
): Promise<
  RouteResponse<CreateAccountAndRegisterResult | Record<string, unknown> | RouteErrorBody>
> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }

  const body = input.body as CreateAccountAndRegisterRequest & Record<string, unknown>;
  const new_account_id = String(body.new_account_id || '').trim();
  const signer_slot = body.signer_slot;
  const threshold_ed25519 = body.threshold_ed25519;
  const threshold_ecdsa = body.threshold_ecdsa;
  const rp_id = typeof body.rp_id === 'string' ? String(body.rp_id || '').trim() : '';
  const webauthn_registration = isPlainObject(body.webauthn_registration)
    ? body.webauthn_registration
    : null;
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
  const continuationTargetsResult = normalizeRegistrationContinuationEcdsaTargets(
    body.registration_continuation,
  );
  if (!continuationTargetsResult.ok) {
    return routeError(400, 'invalid_body', continuationTargetsResult.message);
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
    if (
      resolved.body.code === 'route_auth_not_configured' ||
      resolved.body.code === 'service_not_configured'
    ) {
      return routeJson(resolved.status, resolved.body);
    }
    const parsed = parsePolicyFailureMessage(resolved.body.message);
    return routeJson(resolved.status, {
      ok: false,
      code: parsed.code,
      message: parsed.detail,
    });
  }
  const routePrincipal = resolved.context.principal;
  if (routePrincipal.kind !== 'api_credentials') {
    return routeJson(500, {
      ok: false,
      code: 'internal',
      message: 'Registration bootstrap requires an API credential principal',
    });
  }

  const runtimePolicyScope = await resolveActiveRuntimePolicyScopeForEnvironment({
    orgProjectEnv: input.services.orgProjectEnv || null,
    orgId: routePrincipal.principal.orgId,
    environmentId: routePrincipal.principal.environmentId,
    projectId: routePrincipal.principal.projectId,
    envId: routePrincipal.principal.envId,
  });
  const thresholdEd25519Request =
    threshold_ed25519 && isPlainObject(threshold_ed25519)
      ? {
          ...threshold_ed25519,
          session_policy: isPlainObject(threshold_ed25519.session_policy)
            ? {
                ...threshold_ed25519.session_policy,
                runtimePolicyScope,
              }
            : threshold_ed25519.session_policy,
        }
      : threshold_ed25519;
  const thresholdEcdsaRequest =
    threshold_ecdsa && isPlainObject(threshold_ecdsa)
      ? {
          ...threshold_ecdsa,
          session_policy: isPlainObject(threshold_ecdsa.session_policy)
            ? {
                ...threshold_ecdsa.session_policy,
                runtimePolicyScope,
              }
            : threshold_ecdsa.session_policy,
        }
      : threshold_ecdsa;

  const result = await input.services.authService.createAccountAndRegisterUser({
    new_account_id,
    signer_slot,
    ...(thresholdEd25519Request ? { threshold_ed25519: thresholdEd25519Request } : {}),
    ...(thresholdEcdsaRequest ? { threshold_ecdsa: thresholdEcdsaRequest } : {}),
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
    if (continuationTargetsResult.targets.length > 0) {
      return routeJson(500, {
        success: false,
        error: 'Registration continuation requires session signing',
      });
    }
    return routeJson(200, response, { usage: { walletId: new_account_id } });
  }

  if (response.thresholdEd25519?.session) {
    const signed = await signThresholdSessionAuthToken({
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
    const signed = await signThresholdSessionAuthToken({
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

  if (continuationTargetsResult.targets.length > 0) {
    const signed = await signRegistrationContinuationJwt({
      session,
      walletId: new_account_id,
      rpId: rp_id,
      subjectId: new_account_id,
      thresholdEcdsaChainTargets: continuationTargetsResult.targets,
      runtimePolicyScope,
    });
    if (!signed.ok) {
      return routeJson(signed.status, { success: false, error: signed.message });
    }
    response.registrationContinuation = {
      token: signed.jwt,
      expiresAtMs: signed.expiresAtMs,
      thresholdEcdsaChainTargets: signed.thresholdEcdsaChainTargets,
    };
  }

  return routeJson(200, response, { usage: { walletId: new_account_id } });
}
