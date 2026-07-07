import { normalizeCorsOrigin } from '@seams/sdk-server/internal/core/SessionService';
import type { ConsoleApiKeyService } from '../apiKeys';
import type { ConsoleBootstrapTokenService } from '../bootstrapTokens';
import type { ConsoleOrgProjectEnvService } from '../orgProjectEnv';
import type {
  RouterApiAuthenticatedPublishableCredential,
  RouterApiBootstrapGrantBroker,
  RouterApiBootstrapGrantClientContext,
  RouterApiBootstrapGrantIssueAuthority,
  RouterApiBootstrapGrantIssueRequest,
  RouterApiBootstrapGrantIssueResult,
  RouterApiBootstrapGrantPublishableKeyAuthResult,
} from '@seams/sdk-server/internal/router/routerApi';

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

const REGISTRATION_FLOW_GRANT_ALLOWED_PATHS = [
  '/wallets/register/intent',
  '/wallets/:walletId/signers/intent',
] as const;

function normalizeOrigin(input: string): string {
  return normalizeCorsOrigin(input) || '';
}

function normalizeBucketKey(value: string, fallback: string): string {
  return String(value || '').trim() || fallback;
}

function routerApiBootstrapGrantRecordRpId(
  authority: RouterApiBootstrapGrantIssueAuthority,
): string {
  switch (authority.kind) {
    case 'passkey_rp':
      return authority.rpId;
    case 'wallet_auth':
      return '';
    default: {
      const exhaustive: never = authority;
      return exhaustive;
    }
  }
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

function toAuthenticatedPublishableCredential(
  apiKey: {
    id: string;
    kind: string;
    orgId: string;
    environmentId: string;
    rateLimitBucket?: string | null;
    quotaBucket?: string | null;
  },
): RouterApiAuthenticatedPublishableCredential | null {
  if (apiKey.kind !== 'publishable_key') return null;
  return {
    kind: 'publishable_key',
    apiKeyId: apiKey.id,
    orgId: apiKey.orgId,
    environmentId: apiKey.environmentId,
    ...(apiKey.rateLimitBucket !== undefined ? { rateLimitBucket: apiKey.rateLimitBucket } : {}),
    ...(apiKey.quotaBucket !== undefined ? { quotaBucket: apiKey.quotaBucket } : {}),
  };
}

class ConsoleRouterApiBootstrapGrantBroker implements RouterApiBootstrapGrantBroker {
  private readonly authenticatePublishableKeyFn: NonNullable<
    ConsoleApiKeyService['authenticatePublishableKey']
  >;

  private readonly tokenTtlMs: number;

  private readonly now: () => Date;

  private readonly defaultRateLimit: RouterApiBootstrapGrantRateLimitPolicy;

  private readonly defaultQuota: RouterApiBootstrapGrantQuotaPolicy;

  constructor(private readonly options: RouterApiBootstrapGrantBrokerOptions) {
    const maybeAuthenticatePublishableKey = options.apiKeys.authenticatePublishableKey;
    if (typeof maybeAuthenticatePublishableKey !== 'function') {
      throw new Error(
        'ConsoleApiKeyService.authenticatePublishableKey is required for bootstrap grant broker',
      );
    }
    this.authenticatePublishableKeyFn = maybeAuthenticatePublishableKey.bind(options.apiKeys);
    this.tokenTtlMs = Math.max(1_000, Math.floor(options.tokenTtlMs || 60_000));
    this.now = options.now || (() => new Date());
    this.defaultRateLimit = options.defaultRateLimit || { windowMs: 60_000, maxIssued: 60 };
    this.defaultQuota = options.defaultQuota || { maxIssued: 1_000 };
  }

  async authenticatePublishableKey(input: {
    publishableKey: string;
    origin: string;
    environmentId?: string;
  }): Promise<RouterApiBootstrapGrantPublishableKeyAuthResult> {
    const origin = normalizeOrigin(input.origin);
    if (!origin) {
      return {
        ok: false,
        status: 403,
        code: 'publishable_key_origin_blocked',
        message: 'Origin header is required and must be a valid exact origin',
      };
    }
    const result = await this.authenticatePublishableKeyFn({
      secret: input.publishableKey,
      origin,
      ...(input.environmentId ? { environmentId: input.environmentId } : {}),
    });
    if (!result.ok) return result;
    const credential = toAuthenticatedPublishableCredential(result.apiKey);
    if (!credential) {
      return {
        ok: false,
        status: 401,
        code: 'publishable_key_invalid',
        message: 'Invalid publishable key',
      };
    }
    return { ok: true, credential };
  }

  async issueGrantForAuthenticatedKey(
    input: Omit<RouterApiBootstrapGrantIssueRequest, 'publishableKey'> & {
      authenticatedCredential: RouterApiAuthenticatedPublishableCredential;
    },
  ): Promise<RouterApiBootstrapGrantIssueResult> {
    return await this.issueGrant(input);
  }

  private async issueGrant(
    input: Omit<RouterApiBootstrapGrantIssueRequest, 'publishableKey'> & {
      authenticatedCredential: RouterApiAuthenticatedPublishableCredential;
    },
  ): Promise<RouterApiBootstrapGrantIssueResult> {
    const origin = normalizeOrigin(input.origin);
    if (!origin) {
      return {
        ok: false,
        status: 403,
        code: 'publishable_key_origin_blocked',
        message: 'Origin header is required and must be a valid exact origin',
      };
    }
    const authenticatedCredential = input.authenticatedCredential;
    if (
      String(authenticatedCredential.environmentId || '').trim() !==
      String(input.environmentId || '').trim()
    ) {
      return {
        ok: false,
        status: 403,
        code: 'publishable_key_environment_mismatch',
        message: 'Publishable key is not valid for this environment',
      };
    }
    const rpId = routerApiBootstrapGrantRecordRpId(input.authority);
    if (rpId && !isRpIdAllowedForOrigin({ origin, rpId })) {
      return {
        ok: false,
        status: 400,
        code: 'invalid_body',
        message: 'Field rpId must match the origin host or a parent domain',
      };
    }

    return await this.issueEnvironmentGrant({ input, origin, rpId });
  }

  private async issueEnvironmentGrant(args: {
    input: Omit<RouterApiBootstrapGrantIssueRequest, 'publishableKey'> & {
      authenticatedCredential: RouterApiAuthenticatedPublishableCredential;
    };
    origin: string;
    rpId: string;
  }): Promise<RouterApiBootstrapGrantIssueResult> {
    const { input, origin, rpId } = args;
    const authenticatedCredential = input.authenticatedCredential;
    const orgScope = {
      orgId: authenticatedCredential.orgId,
      actorUserId: 'relay-bootstrap-broker',
      roles: ['system'],
    };
    const environments = await this.options.orgProjectEnv.listEnvironments(orgScope);
    const environment = environments.find(
      (entry) => entry.id === authenticatedCredential.environmentId,
    );
    if (!environment) {
      return {
        ok: false,
        status: 400,
        code: 'invalid_environment',
        message: `Environment ${authenticatedCredential.environmentId} was not found for this organization`,
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

    const projects = await this.options.orgProjectEnv.listProjects(orgScope);
    const project = projects.find((entry) => entry.id === environment.projectId);
    if (!project || project.status !== 'ACTIVE') {
      return {
        ok: false,
        status: 409,
        code: 'environment_archived',
        message: `Project ${environment.projectId} is archived and cannot issue bootstrap grants`,
      };
    }

    const quotaResult = await this.checkQuota({ credential: authenticatedCredential, orgScope });
    if (!quotaResult.ok) return quotaResult;

    const issued = await this.options.tokenStore.createToken(orgScope, {
      publishableKeyId: authenticatedCredential.apiKeyId,
      projectId: environment.projectId,
      environmentId: environment.id,
      newAccountId: String(input.newAccountId || '').trim(),
      rpId,
      origin,
      method: 'POST',
      path: '/wallets/register/intent',
      allowedPaths: [...REGISTRATION_FLOW_GRANT_ALLOWED_PATHS],
      requestHashSha256: null,
      maxUses: 1,
      ttlMs: this.tokenTtlMs,
      riskDecision: 'allow',
    });

    return {
      ok: true,
      grant: {
        token: issued.token,
        expiresAt: issued.record.expiresAt,
        orgId: authenticatedCredential.orgId,
        projectId: environment.projectId,
        envId: environment.key,
        signingRootVersion: environment.signingRootVersion,
        origin,
        mode: 'free',
      },
    };
  }

  private async checkQuota(input: {
    credential: RouterApiAuthenticatedPublishableCredential;
    orgScope: { orgId: string; actorUserId: string; roles: string[] };
  }): Promise<RouterApiBootstrapGrantIssueResult | { ok: true }> {
    const currentNow = this.now();
    const currentNowMs = currentNow.getTime();
    const rateLimitBucket = normalizeBucketKey(input.credential.rateLimitBucket || '', 'default');
    const quotaBucket = normalizeBucketKey(input.credential.quotaBucket || '', 'default');
    const rateLimit = this.options.rateLimitsByBucket?.[rateLimitBucket] || this.defaultRateLimit;
    const quota = this.options.quotasByBucket?.[quotaBucket] || this.defaultQuota;
    const recentCount = await this.options.tokenStore.countIssued(input.orgScope, {
      publishableKeyId: input.credential.apiKeyId,
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

    const totalCount = await this.options.tokenStore.countIssued(input.orgScope, {
      publishableKeyId: input.credential.apiKeyId,
    });
    if (totalCount + 1 > quota.maxIssued) {
      return {
        ok: false,
        status: 429,
        code: 'publishable_key_quota_exhausted',
        message: `Quota bucket ${quotaBucket} exceeded`,
      };
    }
    return { ok: true };
  }
}

export function createRouterApiBootstrapGrantBroker(
  options: RouterApiBootstrapGrantBrokerOptions,
): RouterApiBootstrapGrantBroker {
  return new ConsoleRouterApiBootstrapGrantBroker(options);
}
