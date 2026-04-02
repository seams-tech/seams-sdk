import { normalizeCorsOrigin } from '../core/SessionService';
import type {
  AuthenticateConsolePublishableKeyResult,
  ConsoleApiKey,
  ConsoleApiKeyService,
} from '../console/apiKeys';
import type { ConsoleBootstrapTokenService } from '../console/bootstrapTokens';
import type { ConsoleOrgProjectEnvService } from '../console/orgProjectEnv';
import type {
  RelayBootstrapGrantBroker,
  RelayBootstrapGrantClientContext,
  RelayBootstrapGrantFailureCode,
  RelayBootstrapGrantIssueRequest,
  RelayBootstrapGrantIssueResult,
} from './relay';

export interface RelayBootstrapGrantRateLimitPolicy {
  windowMs: number;
  maxIssued: number;
}

export interface RelayBootstrapGrantQuotaPolicy {
  maxIssued: number;
}

export interface RelayBootstrapGrantBrokerOptions {
  apiKeys: ConsoleApiKeyService;
  tokenStore: ConsoleBootstrapTokenService;
  orgProjectEnv: ConsoleOrgProjectEnvService;
  now?: () => Date;
  tokenTtlMs?: number;
  defaultRateLimit?: RelayBootstrapGrantRateLimitPolicy;
  defaultQuota?: RelayBootstrapGrantQuotaPolicy;
  rateLimitsByBucket?: Record<string, RelayBootstrapGrantRateLimitPolicy>;
  quotasByBucket?: Record<string, RelayBootstrapGrantQuotaPolicy>;
}

export class RelayBootstrapGrantError extends Error {
  readonly code: RelayBootstrapGrantFailureCode;
  readonly status: 400 | 409;

  constructor(input: { code: RelayBootstrapGrantFailureCode; status: 400 | 409; message: string }) {
    super(input.message);
    this.name = 'RelayBootstrapGrantError';
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
    throw new RelayBootstrapGrantError({
      code: 'invalid_body',
      status: 400,
      message: `Missing required field: ${key}`,
    });
  }
  return value;
}

function isBase64UrlNoPadding(value: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(value);
}

function normalizeOrigin(input: string): string {
  return normalizeCorsOrigin(input) || '';
}

function normalizeBucketKey(value: string, fallback: string): string {
  return String(value || '').trim() || fallback;
}

function normalizeClientContext(input: unknown): RelayBootstrapGrantClientContext | undefined {
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

const REGISTRATION_BOOTSTRAP_GRANT_ALLOWED_PATHS = new Set<string>([
  '/registration/bootstrap',
  '/registration/threshold-ed25519/hss/prepare',
  '/registration/threshold-ed25519/hss/finalize',
]);

function normalizeRegistrationBootstrapGrantPath(raw: unknown): string {
  const path = String(raw || '').trim() || '/registration/bootstrap';
  if (!REGISTRATION_BOOTSTRAP_GRANT_ALLOWED_PATHS.has(path)) {
    throw new RelayBootstrapGrantError({
      code: 'invalid_body',
      status: 400,
      message: `Field path is not allowed for bootstrap grants: ${path}`,
    });
  }
  return path;
}

function isRpIdAllowedForOrigin(input: { origin: string; rpId: string }): boolean {
  const origin = normalizeOrigin(input.origin);
  const rpId = String(input.rpId || '')
    .trim()
    .toLowerCase();
  if (!origin || !rpId) return false;
  try {
    const host = new URL(origin).hostname.toLowerCase();
    return host === rpId || host.endsWith(`.${rpId}`);
  } catch {
    return false;
  }
}

export function parseRelayBootstrapGrantIssueBody(
  body: unknown,
): Omit<RelayBootstrapGrantIssueRequest, 'publishableKey' | 'origin'> {
  if (!isRecord(body)) {
    throw new RelayBootstrapGrantError({
      code: 'invalid_body',
      status: 400,
      message: 'Expected JSON object request body',
    });
  }
  const environmentId = readRequiredString(body, 'environmentId');
  const newAccountId = readRequiredString(body, 'newAccountId');
  const rpId = readRequiredString(body, 'rpId');
  const requestHashSha256 = readRequiredString(body, 'requestHashSha256');
  const path = normalizeRegistrationBootstrapGrantPath(body.path);
  if (!isBase64UrlNoPadding(requestHashSha256)) {
    throw new RelayBootstrapGrantError({
      code: 'invalid_body',
      status: 400,
      message: 'Field requestHashSha256 must be base64url without padding',
    });
  }
  const clientContext = normalizeClientContext(body.clientContext);
  return {
    environmentId,
    newAccountId,
    rpId,
    requestHashSha256,
    path,
    ...(clientContext ? { clientContext } : {}),
  };
}

export function createRelayBootstrapGrantBroker(
  options: RelayBootstrapGrantBrokerOptions,
): RelayBootstrapGrantBroker {
  const maybeAuthenticatePublishableKey = options.apiKeys.authenticatePublishableKey;
  if (typeof maybeAuthenticatePublishableKey !== 'function') {
    throw new Error(
      'ConsoleApiKeyService.authenticatePublishableKey is required for bootstrap grant broker',
    );
  }
  const authenticatePublishableKeyFn: NonNullable<
    ConsoleApiKeyService['authenticatePublishableKey']
  > = maybeAuthenticatePublishableKey;

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
    newAccountId: string;
    rpId: string;
    requestHashSha256: string;
    path?: string;
    clientContext?: RelayBootstrapGrantClientContext;
  }): Promise<RelayBootstrapGrantIssueResult> {
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
      origin,
      method: 'POST',
      path: normalizeRegistrationBootstrapGrantPath(input.path),
      requestHashSha256: input.requestHashSha256,
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
        environmentId: environment.id,
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
