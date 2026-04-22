import type { AuthService } from '../core/AuthService';
import type {
  CreateAccountAndRegisterRequest,
  CreateAccountAndRegisterResult,
  CreateAccountAndRegisterSmartAccountDeployment,
  CreateAccountAndRegisterSmartAccountTarget,
} from '../core/types';
import type { ConsoleBootstrapTokenService } from '../console/bootstrapTokens';
import type { ConsoleOrgProjectEnvService } from '../console/orgProjectEnv';
import {
  resolveActiveRuntimePolicyScopeForEnvironment,
  signThresholdSessionJwt,
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
import { readCanonicalSmartAccountDeploymentManifest } from './smartAccountDeploymentManifest';
import { syncSmartAccountRecoverySubjectDeployments } from './smartAccountRecoverySubjectDeploymentSync';
import { executeSmartAccountDeploy } from './smartAccountDeploy';
import { isPlainObject } from '@shared/utils/validation';

interface RelayRegistrationBootstrapServices {
  authService: AuthService;
  apiKeyAuth?: RelayApiKeyAuthAdapter | null;
  apiKeyUsageMeter?: RelayUsageMeterAdapter | null;
  bootstrapTokenStore?: ConsoleBootstrapTokenService | null;
  orgProjectEnv?: ConsoleOrgProjectEnvService | null;
  session?: SessionAdapter | null;
  smartAccountDeploy?:
    | ((
        request: import('./relay').SmartAccountDeployRequest,
      ) =>
        | Promise<import('./relay').SmartAccountDeployResult>
        | import('./relay').SmartAccountDeployResult)
    | null;
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

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function normalizeRegistrationSmartAccountTargets(
  raw: unknown,
):
  | { ok: true; targets: CreateAccountAndRegisterSmartAccountTarget[] }
  | { ok: false; message: string } {
  if (raw == null) return { ok: true, targets: [] };
  if (!Array.isArray(raw)) {
    return { ok: false, message: 'threshold_ecdsa.smart_account_targets must be an array' };
  }
  const targets: CreateAccountAndRegisterSmartAccountTarget[] = [];
  const seenChains = new Set<string>();
  for (let index = 0; index < raw.length; index += 1) {
    const entry = raw[index];
    if (!isPlainObject(entry)) {
      return {
        ok: false,
        message: `threshold_ecdsa.smart_account_targets[${index}] must be an object`,
      };
    }
    const chain = String(entry.chain || '')
      .trim()
      .toLowerCase();
    if (chain !== 'evm' && chain !== 'tempo') {
      return {
        ok: false,
        message: `threshold_ecdsa.smart_account_targets[${index}].chain must be "evm" or "tempo"`,
      };
    }
    if (seenChains.has(chain)) {
      return {
        ok: false,
        message: `threshold_ecdsa.smart_account_targets contains duplicate chain "${chain}"`,
      };
    }
    const chainId = Math.floor(Number(entry.chain_id));
    if (!Number.isFinite(chainId) || chainId <= 0) {
      return {
        ok: false,
        message: `threshold_ecdsa.smart_account_targets[${index}].chain_id must be a positive integer`,
      };
    }
    seenChains.add(chain);
    targets.push({
      chain,
      chain_id: chainId,
      ...(normalizeOptionalString(entry.factory)
        ? { factory: normalizeOptionalString(entry.factory) }
        : {}),
      ...(normalizeOptionalString(entry.entry_point)
        ? { entry_point: normalizeOptionalString(entry.entry_point) }
        : {}),
      ...(normalizeOptionalString(entry.recovery_authority)
        ? { recovery_authority: normalizeOptionalString(entry.recovery_authority) }
        : {}),
      ...(normalizeOptionalString(entry.salt) ? { salt: normalizeOptionalString(entry.salt) } : {}),
      ...(normalizeOptionalString(entry.counterfactual_address)
        ? { counterfactual_address: normalizeOptionalString(entry.counterfactual_address) }
        : {}),
    });
  }
  return { ok: true, targets };
}

async function deployRegistrationSmartAccounts(input: {
  logger: NormalizedRouterLogger;
  nearAccountId: string;
  authService: AuthService;
  services: RelayRegistrationBootstrapServices;
  targets: CreateAccountAndRegisterSmartAccountTarget[];
  response: CreateAccountAndRegisterResult;
}): Promise<CreateAccountAndRegisterSmartAccountDeployment[]> {
  if (input.targets.length === 0) return [];
  const thresholdEcdsa = input.response.thresholdEcdsa;
  const derivedAccountAddress = normalizeOptionalString(thresholdEcdsa?.ethereumAddress);
  const deployments: CreateAccountAndRegisterSmartAccountDeployment[] = [];

  for (const target of input.targets) {
    const accountModel = target.chain === 'evm' ? 'erc4337' : 'tempo-native';
    const counterfactualAddress = normalizeOptionalString(target.counterfactual_address);
    const accountAddress = counterfactualAddress || derivedAccountAddress || '';
    if (!thresholdEcdsa || !derivedAccountAddress) {
      deployments.push({
        chain: target.chain,
        chainId: target.chain_id,
        accountModel,
        accountAddress,
        deployed: false,
        code: 'threshold_ecdsa_not_available',
        message: 'threshold ECDSA registration key material was not returned',
        ...(counterfactualAddress ? { counterfactualAddress } : {}),
      });
      continue;
    }
    if (!accountAddress) {
      deployments.push({
        chain: target.chain,
        chainId: target.chain_id,
        accountModel,
        accountAddress: '',
        deployed: false,
        code: 'missing_account_address',
        message: 'smart-account target did not resolve to an account address',
      });
      continue;
    }

    const manifest = await readCanonicalSmartAccountDeploymentManifest({
      authService: input.authService,
      chainIdKey: `${target.chain}:${target.chain_id}`,
      accountAddress,
    });
    if (!manifest.ok) {
      deployments.push({
        chain: target.chain,
        chainId: target.chain_id,
        accountModel,
        accountAddress,
        deployed: false,
        code: manifest.code,
        message: manifest.message,
        ...(counterfactualAddress ? { counterfactualAddress } : {}),
      });
      continue;
    }

    const result = await executeSmartAccountDeploy(
      { smartAccountDeploy: input.services.smartAccountDeploy },
      {
        nearAccountId: input.nearAccountId,
        chain: target.chain,
        chainId: target.chain_id,
        accountAddress,
        accountModel,
        deploymentManifest: manifest.manifest,
        ...(manifest.evmDeploymentPlan ? { evmDeploymentPlan: manifest.evmDeploymentPlan } : {}),
      },
    );

    const assumedDeployed = result.ok && result.code === 'assumed_deployed';
    const deployment: CreateAccountAndRegisterSmartAccountDeployment = {
      chain: target.chain,
      chainId: target.chain_id,
      accountAddress,
      accountModel,
      deployed: result.ok && !assumedDeployed,
      ...(normalizeOptionalString(result.deploymentTxHash)
        ? { deploymentTxHash: normalizeOptionalString(result.deploymentTxHash) }
        : {}),
      ...(normalizeOptionalString(result.code)
        ? { code: normalizeOptionalString(result.code) }
        : {}),
      ...(normalizeOptionalString(result.message)
        ? { message: normalizeOptionalString(result.message) }
        : {}),
      ...(counterfactualAddress ? { counterfactualAddress } : {}),
    };
    deployments.push(deployment);

    if (deployment.deployed) {
      input.logger.info('[relay][registration] smart-account deployed during registration', {
        nearAccountId: input.nearAccountId,
        chain: target.chain,
        chainId: target.chain_id,
        accountAddress,
        ...(deployment.deploymentTxHash ? { deploymentTxHash: deployment.deploymentTxHash } : {}),
      });
      continue;
    }

    input.logger.warn(
      '[relay][registration] smart-account deployment did not complete during registration',
      {
        nearAccountId: input.nearAccountId,
        chain: target.chain,
        chainId: target.chain_id,
        accountAddress,
        ...(deployment.code ? { code: deployment.code } : {}),
        ...(deployment.message ? { message: deployment.message } : {}),
      },
    );
  }

  return deployments;
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
  const smartAccountTargetsResult = normalizeRegistrationSmartAccountTargets(
    isPlainObject(body.threshold_ecdsa) ? body.threshold_ecdsa.smart_account_targets : undefined,
  );
  if (!smartAccountTargetsResult.ok) {
    return routeError(400, 'invalid_body', smartAccountTargetsResult.message);
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
    if (smartAccountTargetsResult.targets.length > 0) {
      response.smartAccountDeployments = await deployRegistrationSmartAccounts({
        logger: input.logger,
        nearAccountId: new_account_id,
        authService: input.services.authService,
        services: input.services,
        targets: smartAccountTargetsResult.targets,
        response,
      });
      await syncSmartAccountRecoverySubjectDeployments({
        authService: input.services.authService,
        deployments: response.smartAccountDeployments,
        sponsorshipScope: runtimePolicyScope,
      });
    }
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

  if (smartAccountTargetsResult.targets.length > 0) {
    response.smartAccountDeployments = await deployRegistrationSmartAccounts({
      logger: input.logger,
      nearAccountId: new_account_id,
      authService: input.services.authService,
      services: input.services,
      targets: smartAccountTargetsResult.targets,
      response,
    });
    await syncSmartAccountRecoverySubjectDeployments({
      authService: input.services.authService,
      deployments: response.smartAccountDeployments,
      sponsorshipScope: runtimePolicyScope,
    });
  }

  return routeJson(200, response, { usage: { walletId: new_account_id } });
}
