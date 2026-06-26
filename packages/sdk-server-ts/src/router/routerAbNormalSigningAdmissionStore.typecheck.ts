import type { CloudflareDurableObjectNamespaceLike } from '../core/types';
import type {
  CloudflareDurableObjectRouterAbNormalSigningAdmissionStoreOptions,
  RouterAbNormalSigningAbuseDecision,
  RouterAbNormalSigningProjectPolicyDecision,
  RouterAbNormalSigningQuotaDecision,
} from './routerAbNormalSigningAdmissionStore';

declare const thresholdStore: CloudflareDurableObjectNamespaceLike;

const cloudflareDoAdmissionOptions: CloudflareDurableObjectRouterAbNormalSigningAdmissionStoreOptions =
  {
    namespace: thresholdStore,
    storageNamespace: 'seams',
  };

// @ts-expect-error Durable Object admission stores require a storage namespace.
const missingStorageNamespace: CloudflareDurableObjectRouterAbNormalSigningAdmissionStoreOptions = {
  namespace: thresholdStore,
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
void cloudflareDoAdmissionOptions;
void missingStorageNamespace;
