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
import type { ConsoleOrgProjectEnvService } from '../console/orgProjectEnv';
import { resolveActiveRuntimePolicyScopeForEnvironment } from './commonRouterUtils';
import { ensureEd25519Prefix, isPlainObject } from '@shared/utils/validation';

type RelayRegistrationThresholdEd25519HssServices = {
  authService: AuthService;
  apiKeyAuth?: RelayApiKeyAuthAdapter | null;
  bootstrapTokenStore?: ConsoleBootstrapTokenService | null;
  orgProjectEnv?: ConsoleOrgProjectEnvService | null;
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
      signingRootId?: string;
      signingRootVersion?: string;
    }
	  | {
	      ok: false;
	      response: RouteResponse<RouteErrorBody>;
	    };

type RelayRegistrationThresholdEd25519HssHandler<TResponse> = (
  input: RelayRegistrationThresholdEd25519HssInput,
) => Promise<RouteResponse<TResponse | RouteErrorBody>>;

type RegistrationAccountProvisioningResult =
  | {
      ok: true;
      accountProvisioning?: {
        mode: 'create_if_missing';
        status: 'created' | 'already_ready';
        transactionHash?: string;
      };
    }
  | {
      ok: false;
      response: RouteResponse<RouteErrorBody>;
    };

const ACCOUNT_PROVISIONING_KEY_VISIBILITY_DELAYS_MS = [0, 250, 750, 1_500] as const;

async function sleep(ms: number): Promise<void> {
  if (ms <= 0) return;
  await new Promise((resolve) => setTimeout(resolve, ms));
}

function wantsCreateIfMissingAccountProvisioning(body: Record<string, unknown>): boolean {
  const raw = body.account_provisioning ?? body.accountProvisioning;
  if (raw === 'create_if_missing') return true;
  if (!isPlainObject(raw)) return false;
  return String(raw.mode || '').trim() === 'create_if_missing';
}

function readSignerSlotMetadata(body: Record<string, unknown>): number | undefined {
  const raw = body.signerSlot ?? body.signer_slot;
  const value = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isFinite(value) || value < 1) return undefined;
  return Math.floor(value);
}

async function hasAccessKey(input: {
  authService: AuthService;
  nearAccountId: string;
  publicKey: string;
}): Promise<boolean> {
  const expected = ensureEd25519Prefix(input.publicKey);
  if (!expected) return false;
  const list = await input.authService.viewAccessKeyList(input.nearAccountId);
  return list.keys.some((key) => {
    return ensureEd25519Prefix(String(key?.public_key || '').trim()) === expected;
  });
}

async function waitForAccessKey(input: {
  authService: AuthService;
  nearAccountId: string;
  publicKey: string;
}): Promise<boolean> {
  for (const delayMs of ACCOUNT_PROVISIONING_KEY_VISIBILITY_DELAYS_MS) {
    await sleep(delayMs);
    if (await hasAccessKey(input)) return true;
  }
  return false;
}

async function ensureRegistrationAccountProvisioning(input: {
  body: Record<string, unknown>;
  authService: AuthService;
  publicKey: string;
}): Promise<RegistrationAccountProvisioningResult> {
  if (!wantsCreateIfMissingAccountProvisioning(input.body)) return { ok: true };

  const nearAccountId = String(input.body.new_account_id || '').trim();
  const publicKey = ensureEd25519Prefix(input.publicKey);
  if (!nearAccountId || !publicKey) {
    return {
      ok: false,
      response: routeJson(400, {
        ok: false,
        code: 'invalid_body',
        message: 'account provisioning requires new_account_id and finalized publicKey',
      }),
    };
  }

  const accountExists = await input.authService.checkAccountExists(nearAccountId);
  if (!accountExists) {
    const created = await input.authService.createAccount({
      accountId: nearAccountId,
      publicKey,
    });
    if (!created.success) {
      return {
        ok: false,
        response: routeJson(400, {
          ok: false,
          code: 'account_provisioning_failed',
          message: created.error || created.message || 'Failed to create NEAR account',
        }),
      };
    }
    const ready = await waitForAccessKey({
      authService: input.authService,
      nearAccountId,
      publicKey,
    });
    if (!ready) {
      return {
        ok: false,
        response: routeJson(503, {
          ok: false,
          code: 'access_key_not_provisioned',
          message:
            'NEAR account creation completed, but the finalized threshold Ed25519 public key is not visible as an active access key yet. Retry Email OTP registration before activating this signer locally.',
        }),
      };
    }
    return {
      ok: true,
      accountProvisioning: {
        mode: 'create_if_missing',
        status: 'created',
        ...(created.transactionHash ? { transactionHash: created.transactionHash } : {}),
      },
    };
  }

  const ready = await hasAccessKey({
    authService: input.authService,
    nearAccountId,
    publicKey,
  });
  if (ready) {
    return {
      ok: true,
      accountProvisioning: {
        mode: 'create_if_missing',
        status: 'already_ready',
      },
    };
  }

  return {
    ok: false,
    response: routeJson(409, {
      ok: false,
      code: 'wallet_id_collision',
      message: 'This wallet name is already in use. Try registering again with a new wallet name.',
    }),
  };
}

async function enforceRegistrationHssPolicy(
  input: RelayRegistrationThresholdEd25519HssInput,
): Promise<RelayRegistrationThresholdEd25519HssPolicyResult> {
  const body = isPlainObject(input.body) ? input.body : null;
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
  const principal = resolved.context.principal.principal;
  const runtimePolicyScope = await resolveActiveRuntimePolicyScopeForEnvironment({
    orgProjectEnv: input.services.orgProjectEnv || null,
    orgId: principal.orgId,
    environmentId: principal.environmentId,
    projectId: principal.projectId,
    envId: principal.envId,
  });
  return {
    ok: true,
    orgId: principal.orgId,
    ...(runtimePolicyScope
      ? {
          signingRootId: `${runtimePolicyScope.projectId}:${runtimePolicyScope.envId}`,
          signingRootVersion: runtimePolicyScope.signingRootVersion,
        }
      : {}),
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
    ...(auth.signingRootId ? { signingRootId: auth.signingRootId } : {}),
    ...(auth.signingRootVersion ? { signingRootVersion: auth.signingRootVersion } : {}),
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
  if (!result.ok) return routeJson(400, result);

  const body = isPlainObject(input.body) ? input.body : {};
  const googleEmailOtpRegistrationAttemptId =
    body.google_email_otp_registration_attempt_id ??
    body.googleEmailOtpRegistrationAttemptId ??
    body.registrationAttemptId;
  const recordedGoogleAttempt =
    await input.services.authService.recordGoogleEmailOtpRegistrationAttemptPublicKey({
      registrationAttemptId: googleEmailOtpRegistrationAttemptId,
      walletId: body.new_account_id,
      finalizedPublicKey: result.publicKey,
    });
  if (!recordedGoogleAttempt.ok) {
    return routeJson(409, {
      ok: false,
      code: recordedGoogleAttempt.code,
      message: recordedGoogleAttempt.message,
    });
  }

  const provisioning = await ensureRegistrationAccountProvisioning({
    body,
    authService: input.services.authService,
    publicKey: result.publicKey,
  });
  if (!provisioning.ok) {
    await input.services.authService.failGoogleEmailOtpRegistrationAttempt({
      registrationAttemptId: googleEmailOtpRegistrationAttemptId,
      walletId: body.new_account_id,
      failureCode: (provisioning.response.body as { code?: unknown }).code,
    });
    return provisioning.response;
  }

  await input.services.authService.recordNearPublicKeyMetadata({
    userId: body.new_account_id,
    publicKey: result.publicKey,
    kind: 'threshold',
    rpId: body.rp_id,
    signerSlot: readSignerSlotMetadata(body),
    source: 'Email OTP threshold Ed25519 registration NEAR public key metadata persistence',
  });

  return routeJson(200, {
    ...result,
    ...(provisioning.accountProvisioning
      ? { accountProvisioning: provisioning.accountProvisioning }
      : {}),
  });
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
