import type { D1DatabaseLike } from '../storage/tenantRoute';
import type {
  CloudflareD1RouterAbNormalSigningAdmissionStoreOptions,
  RouterAbNormalSigningAbuseDecision,
  RouterAbNormalSigningProjectPolicyDecision,
  RouterAbNormalSigningQuotaDecision,
} from './routerAbNormalSigningAdmissionStore';
// @ts-expect-error Normal-signing admission no longer exposes a partial Postgres backend.
import type { PostgresRouterAbNormalSigningAdmissionStoreOptions } from './routerAbNormalSigningAdmissionStore';

declare const signerDatabase: D1DatabaseLike;

const cloudflareD1AdmissionOptions: CloudflareD1RouterAbNormalSigningAdmissionStoreOptions = {
  database: signerDatabase,
  storageNamespace: 'seams',
};

// @ts-expect-error D1 admission stores require a storage namespace.
const missingStorageNamespace: CloudflareD1RouterAbNormalSigningAdmissionStoreOptions = {
  database: signerDatabase,
};

// @ts-expect-error Accepted quota decisions must carry the admitted request id.
const invalidAcceptedQuota: RouterAbNormalSigningQuotaDecision = { kind: 'accepted' };

// @ts-expect-error Reused quota decisions must carry the existing lifecycle id.
const invalidReuseQuota: RouterAbNormalSigningQuotaDecision = {
  kind: 'reuse_existing',
  requestId: 'request-1',
};

// @ts-expect-error Rejected project-policy decisions must carry a retry window.
const invalidRejectedProjectPolicy: RouterAbNormalSigningProjectPolicyDecision = {
  kind: 'rejected',
};

// @ts-expect-error Rate-limited abuse decisions must carry a retry window.
const invalidRateLimitedAbuse: RouterAbNormalSigningAbuseDecision = {
  kind: 'rate_limited',
};

void invalidAcceptedQuota;
void invalidReuseQuota;
void invalidRejectedProjectPolicy;
void invalidRateLimitedAbuse;
void cloudflareD1AdmissionOptions;
void missingStorageNamespace;
