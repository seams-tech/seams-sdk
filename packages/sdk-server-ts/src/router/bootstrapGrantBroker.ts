import { normalizeCorsOrigin } from '../core/SessionService';
import type {
  AuthenticateConsolePublishableKeyResult,
  ConsoleApiKey,
  ConsoleApiKeyService,
} from '../console/apiKeys';
import type { ConsoleBootstrapTokenService } from '../console/bootstrapTokens';
import type { ConsoleOrgProjectEnvService } from '../console/orgProjectEnv';
import type {
  RouterApiBootstrapGrantBroker,
  RouterApiBootstrapGrantClientContext,
  RouterApiBootstrapGrantFailureCode,
  RouterApiBootstrapGrantIssueRequest,
  RouterApiBootstrapGrantIssueResult,
} from './routerApi';

export interface RouterApiBootstrapGrantRateLimitPolicy {
  windowMs: number;
  maxIssued: number;
}

export interface RouterApiBootstrapGrantQuotaPolicy {
  maxIssued: number;
}

export interface RouterApiBootstrapGrantBrokerOptions {
  apiKeys: ConsoleApiKeyService;
  tokenStore: ConsoleBootstrapTokenService;
  orgProjectEnv: ConsoleOrgProjectEnvService;
  now?: () => Date;
  tokenTtlMs?: number;
  defaultRateLimit?: RouterApiBootstrapGrantRateLimitPolicy;
  defaultQuota?: RouterApiBootstrapGrantQuotaPolicy;
  rateLimitsByBucket?: Record<string, RouterApiBootstrapGrantRateLimitPolicy>;
  quotasByBucket?: Record<string, RouterApiBootstrapGrantQuotaPolicy>;
}

export class RouterApiBootstrapGrantError extends Error {
  readonly code: RouterApiBootstrapGrantFailureCode;
  readonly status: 400 | 409;

  constructor(input: { code: RouterApiBootstrapGrantFailureCode; status: 400 | 409; message: string }) {
    super(input.message);
    this.name = 'RouterApiBootstrapGrantError';
    this.code = input.code;
    this.status = input.status;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function readRequiredString(source: Record<string, unknown>, key: string): string {
  const value = String(source[key] ?? '').trim();
  if (!value) {
    throw new RouterApiBootstrapGrantError({
      code: 'invalid_body',
      status: 400,
      message: `Missing required field: ${key}`,
    });
  }
  return value;
}

function readOptionalString(source: Record<string, unknown>, key: string): string | undefined {
  const value = String(source[key] ?? '').trim();
  return value || undefined;
}

function normalizeOrigin(input: string): string {
  return normalizeCorsOrigin(input) || '';
}

function normalizeBucketKey(value: string, fallback: string): string {
  return String(value || '').trim() || fallback;
}

function normalizeClientContext(input: unknown): RouterApiBootstrapGrantClientContext | undefined {
  if (!isRecord(input)) return undefined;
  const sdk = String(input.sdk || '').trim();
  const sdkVersion = String(input.sdkVersion || '').trim();
  const userAgentHint = String(input.userAgentHint || '').trim();
  if (!sdk && !sdkVersion && !userAgentHint) return undefined;
  return {
    ...(sdk ? { sdk } : {}),
    ...(sdkVersion ? { sdkVersion } : {}),
    ...(userAgentHint ? { userAgentHint } : {}),
  };
}

const REGISTRATION_FLOW_GRANT_ALLOWED_PATHS = [
  '/wallets/register/intent',
  '/wallets/:walletId/signers/intent',
] as const;

function normalizeRegistrationBootstrapGrantFlow(raw: unknown): 'registration_v1' {
  const flow = String(raw || '').trim();
  if (flow !== 'registration_v1') {
    throw new RouterApiBootstrapGrantError({
      code: 'invalid_body',
      status: 400,
      message: 'Field flow must be "registration_v1"',
    });
  }
  return 'registration_v1';
}

function isRpIdAllowedForOrigin(input: { origin: string; rpId: string }): boolean {
  const origin = normalizeOrigin(input.origin);
  const rpId = String(input.rpId || '')
    .trim()
    .toLowerCase();
  if (!origin || !rpId) return false;
  try {
    const host = new URL(origin).hostname.toLowerCase();
    if ((host === 'localhost' || host === '127.0.0.1') && rpId.endsWith('.localhost')) {
      return true;
    }
    return host === rpId || host.endsWith(`.${rpId}`);
  } catch {
    return false;
  }
}

export function parseRouterApiBootstrapGrantIssueBody(
  body: unknown,
): Omit<RouterApiBootstrapGrantIssueRequest, 'publishableKey' | 'origin'> {
  if (!isRecord(body)) {
    throw new RouterApiBootstrapGrantError({
      code: 'invalid_body',
      status: 400,
      message: 'Expected JSON object request body',
    });
  }
  const environmentId = readRequiredString(body, 'environmentId');
  const newAccountId = readOptionalString(body, 'newAccountId');
  const rpId = readRequiredString(body, 'rpId');
  const flow = normalizeRegistrationBootstrapGrantFlow(body.flow);
  const clientContext = normalizeClientContext(body.clientContext);
  return {
    environmentId,
    ...(newAccountId ? { newAccountId } : {}),
    rpId,
    flow,
    ...(clientContext ? { clientContext } : {}),
  };
}

export function createRouterApiBootstrapGrantBroker(
  options: RouterApiBootstrapGrantBrokerOptions,
): RouterApiBootstrapGrantBroker {
  const maybeAuthenticatePublishableKey = options.apiKeys.authenticatePublishableKey;
  if (typeof maybeAuthenticatePublishableKey !== 'function') {
    throw new Error(
      'ConsoleApiKeyService.authenticatePublishableKey is required for bootstrap grant broker',
    );
  }
  const authenticatePublishableKeyFn: NonNullable<
    ConsoleApiKeyService['authenticatePublishableKey']
  > = maybeAuthenticatePublishableKey.bind(options.apiKeys);

  const tokenTtlMs = Math.max(1_000, Math.floor(options.tokenTtlMs || 60_000));
  const now = options.now || (() => new Date());
  const defaultRateLimit = options.defaultRateLimit || { windowMs: 60_000, maxIssued: 60 };
  const defaultQuota = options.defaultQuota || { maxIssued: 1_000 };
  const tokenStore = options.tokenStore;

  async function authenticatePublishableKey(input: {
    publishableKey: string;
    origin: string;
    environmentId?: string;
  }): Promise<AuthenticateConsolePublishableKeyResult> {
    const origin = normalizeOrigin(input.origin);
    if (!origin) {
      return {
        ok: false,
        status: 403,
        code: 'publishable_key_origin_blocked',
        message: 'Origin header is required and must be a valid exact origin',
      };
    }
    return await authenticatePublishableKeyFn({
      secret: input.publishableKey,
      origin,
      ...(input.environmentId ? { environmentId: input.environmentId } : {}),
    });
  }

  async function issueGrantForAuthenticatedKey(input: {
    authenticatedApiKey: ConsoleApiKey;
    origin: string;
    environmentId: string;
    newAccountId?: string;
    rpId: string;
    flow: 'registration_v1';
    clientContext?: RouterApiBootstrapGrantClientContext;
  }): Promise<RouterApiBootstrapGrantIssueResult> {
    const origin = normalizeOrigin(input.origin);
    if (!origin) {
      return {
        ok: false,
        status: 403,
        code: 'publishable_key_origin_blocked',
        message: 'Origin header is required and must be a valid exact origin',
      };
    }
    const authenticatedApiKey = input.authenticatedApiKey;
    if (!authenticatedApiKey || authenticatedApiKey.kind !== 'publishable_key') {
      return {
        ok: false,
        status: 401,
        code: 'publishable_key_invalid',
        message: 'Invalid publishable key',
      };
    }
    if (
      String(authenticatedApiKey.environmentId || '').trim() !==
      String(input.environmentId || '').trim()
    ) {
      return {
        ok: false,
        status: 403,
        code: 'publishable_key_environment_mismatch',
        message: 'Publishable key is not valid for this environment',
      };
    }
    if (!isRpIdAllowedForOrigin({ origin, rpId: input.rpId })) {
      return {
        ok: false,
        status: 400,
        code: 'invalid_body',
        message: 'Field rpId must match the origin host or a parent domain',
      };
    }

    const orgScope = {
      orgId: authenticatedApiKey.orgId,
      actorUserId: 'relay-bootstrap-broker',
      roles: ['system'],
    };
    const environments = await options.orgProjectEnv.listEnvironments(orgScope);
    const environment = environments.find(
      (entry) => entry.id === authenticatedApiKey.environmentId,
    );
    if (!environment) {
      return {
        ok: false,
        status: 400,
        code: 'invalid_environment',
        message: `Environment ${authenticatedApiKey.environmentId} was not found for this organization`,
      };
    }
    if (environment.status !== 'ACTIVE') {
      return {
        ok: false,
        status: 409,
        code: 'environment_archived',
        message: `Environment ${environment.id} is archived and cannot issue bootstrap grants`,
      };
    }

    const projects = await options.orgProjectEnv.listProjects(orgScope);
    const project = projects.find((entry) => entry.id === environment.projectId);
    if (!project || project.status !== 'ACTIVE') {
      return {
        ok: false,
        status: 409,
        code: 'environment_archived',
        message: `Project ${environment.projectId} is archived and cannot issue bootstrap grants`,
      };
    }

    const currentNow = now();
    const currentNowMs = currentNow.getTime();
    const rateLimitBucket = normalizeBucketKey(
      authenticatedApiKey.rateLimitBucket || '',
      'default',
    );
    const quotaBucket = normalizeBucketKey(authenticatedApiKey.quotaBucket || '', 'default');
    const rateLimit = options.rateLimitsByBucket?.[rateLimitBucket] || defaultRateLimit;
    const quota = options.quotasByBucket?.[quotaBucket] || defaultQuota;
    const recentCount = await tokenStore.countIssued(orgScope, {
      publishableKeyId: authenticatedApiKey.id,
      issuedSince: new Date(currentNowMs - Math.max(1, rateLimit.windowMs) + 1).toISOString(),
    });
    if (recentCount + 1 > rateLimit.maxIssued) {
      return {
        ok: false,
        status: 429,
        code: 'publishable_key_rate_limited',
        message: `Rate limit bucket ${rateLimitBucket} exceeded`,
      };
    }

    const totalCount = await tokenStore.countIssued(orgScope, {
      publishableKeyId: authenticatedApiKey.id,
    });
    if (totalCount + 1 > quota.maxIssued) {
      return {
        ok: false,
        status: 429,
        code: 'publishable_key_quota_exhausted',
        message: `Quota bucket ${quotaBucket} exceeded`,
      };
    }

    const issued = await tokenStore.createToken(orgScope, {
      publishableKeyId: authenticatedApiKey.id,
      projectId: environment.projectId,
      environmentId: environment.id,
      newAccountId: String(input.newAccountId || '').trim(),
      rpId: input.rpId,
      origin,
      method: 'POST',
      path: '/wallets/register/intent',
      allowedPaths: [...REGISTRATION_FLOW_GRANT_ALLOWED_PATHS],
      requestHashSha256: null,
      maxUses: 1,
      ttlMs: tokenTtlMs,
      riskDecision: 'allow',
    });

    return {
      ok: true,
      grant: {
        token: issued.token,
        expiresAt: issued.record.expiresAt,
        orgId: authenticatedApiKey.orgId,
        projectId: environment.projectId,
        envId: environment.key,
        signingRootVersion: environment.signingRootVersion,
        origin,
        mode: 'free',
      },
    };
  }

  return {
    authenticatePublishableKey,
    issueGrantForAuthenticatedKey,
  };
}
