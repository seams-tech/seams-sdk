import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import { THRESHOLD_DO_OBJECT_NAME_DEFAULT } from '../core/defaultConfigsServer';
import type { ThresholdEd25519AuthorityScope } from '../core/types';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../core/types';
import type {
  RouterAbNormalSigningAdmissionAdapter,
  RouterAbNormalSigningAdmissionInput,
  RouterAbNormalSigningAdmissionResult,
} from './routerAbPrivateSigningWorker';

export type RouterAbNormalSigningProjectPolicyDecision =
  | { kind: 'allowed' }
  | { kind: 'rejected'; retryAfterMs: number };

export type RouterAbNormalSigningAbuseDecision =
  | { kind: 'allowed' }
  | { kind: 'rate_limited'; retryAfterMs: number }
  | { kind: 'rejected'; retryAfterMs: number };

export type RouterAbNormalSigningQuotaDecision =
  | { kind: 'accepted'; requestId: string }
  | { kind: 'reuse_existing'; requestId: string; existingLifecycleId: string }
  | { kind: 'short_window_saturated' }
  | { kind: 'signer_queue_saturated' };

export interface RouterAbNormalSigningProjectPolicyProvider {
  evaluateProjectPolicy(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningProjectPolicyDecision>;
}

export interface RouterAbNormalSigningAbuseProvider {
  evaluateAbuse(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningAbuseDecision>;
}

export interface RouterAbNormalSigningQuotaStore {
  reserveQuota(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningQuotaDecision>;
}

export interface RouterAbNormalSigningAdmissionStore
  extends
    RouterAbNormalSigningProjectPolicyProvider,
    RouterAbNormalSigningAbuseProvider,
    RouterAbNormalSigningQuotaStore {}

export type InMemoryRouterAbNormalSigningAdmissionStoreOptions = {
  readonly now?: () => number;
};

type RouterAbNormalSigningQuotaReservation = {
  readonly requestId: string;
  readonly lifecycleId: string;
  readonly expiresAtMs: number;
};

const ROUTER_AB_NORMAL_SIGNING_QUOTA_RESERVATION_TTL_MS = 5_000;
const ROUTER_AB_NORMAL_SIGNING_ADMISSION_KEY_PREFIX_DEFAULT =
  'router-ab-normal-signing-admission:';

export class InMemoryRouterAbNormalSigningAdmissionStore implements RouterAbNormalSigningAdmissionStore {
  private readonly now: () => number;
  private readonly projectPolicies = new Map<string, RouterAbNormalSigningProjectPolicyDecision>();
  private readonly abuseDecisions = new Map<string, RouterAbNormalSigningAbuseDecision>();
  private readonly quotaReservations = new Map<string, RouterAbNormalSigningQuotaReservation>();

  constructor(options: InMemoryRouterAbNormalSigningAdmissionStoreOptions = {}) {
    this.now = options.now || Date.now;
  }

  setProjectPolicy(
    scope: RuntimePolicyScope,
    decision: RouterAbNormalSigningProjectPolicyDecision,
  ): void {
    this.projectPolicies.set(runtimePolicyScopeKey(scope), decision);
  }

  clearProjectPolicy(scope: RuntimePolicyScope): void {
    this.projectPolicies.delete(runtimePolicyScopeKey(scope));
  }

  setAbuseDecision(
    input: RouterAbNormalSigningAdmissionInput,
    decision: RouterAbNormalSigningAbuseDecision,
  ): void {
    this.abuseDecisions.set(abusePrincipalKey(input), decision);
  }

  clearAbuseDecision(input: RouterAbNormalSigningAdmissionInput): void {
    this.abuseDecisions.delete(abusePrincipalKey(input));
  }

  clearExpired(nowMs = this.now()): void {
    for (const [key, reservation] of this.quotaReservations.entries()) {
      if (reservation.expiresAtMs <= nowMs) {
        this.quotaReservations.delete(key);
      }
    }
  }

  async evaluateProjectPolicy(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningProjectPolicyDecision> {
    return (
      this.projectPolicies.get(runtimePolicyScopeKey(input.runtimePolicyScope)) || {
        kind: 'allowed',
      }
    );
  }

  async evaluateAbuse(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningAbuseDecision> {
    return this.abuseDecisions.get(abusePrincipalKey(input)) || { kind: 'allowed' };
  }

  async reserveQuota(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningQuotaDecision> {
    const nowMs = this.now();
    this.clearExpired(nowMs);
    const key = quotaScopeKey(input);
    const active = this.quotaReservations.get(key);
    if (active) {
      if (active.requestId === input.requestId) {
        return {
          kind: 'reuse_existing',
          requestId: input.requestId,
          existingLifecycleId: active.lifecycleId,
        };
      }
      return { kind: 'short_window_saturated' };
    }

    this.quotaReservations.set(key, {
      requestId: input.requestId,
      lifecycleId: normalSigningLifecycleId(input),
      expiresAtMs: quotaReservationExpiresAtMs(input, nowMs),
    });
    return { kind: 'accepted', requestId: input.requestId };
  }
}

export type CloudflareDurableObjectRouterAbNormalSigningAdmissionStoreOptions = {
  readonly namespace: CloudflareDurableObjectNamespaceLike;
  readonly storageNamespace: string;
  readonly objectNamePrefix?: string;
  readonly keyPrefix?: string;
  readonly now?: () => number;
};

type AdmissionDoOk<T> = { ok: true; value: T };
type AdmissionDoErr = { ok: false; code: string; message: string };
type AdmissionDoResp<T> = AdmissionDoOk<T> | AdmissionDoErr;

type AdmissionDoGetRequest = { op: 'get'; key: string };
type AdmissionDoSetRequest = { op: 'set'; key: string; value: unknown; ttlMs?: number };
type AdmissionDoDelRequest = { op: 'del'; key: string };
type AdmissionDoReserveQuotaRequest = {
  op: 'routerAbNormalSigningReserveQuota';
  key: string;
  requestId: string;
  lifecycleId: string;
  expiresAtMs: number;
  nowMs: number;
};
type AdmissionDoRequest =
  | AdmissionDoGetRequest
  | AdmissionDoSetRequest
  | AdmissionDoDelRequest
  | AdmissionDoReserveQuotaRequest;

type CloudflareDoProjectPolicyRecord = {
  readonly kind: 'router_ab_normal_signing_project_policy_v1';
  readonly decision: RouterAbNormalSigningProjectPolicyDecision;
  readonly updatedAtMs: number;
};

type CloudflareDoAbuseRecord = {
  readonly kind: 'router_ab_normal_signing_abuse_decision_v1';
  readonly decision: RouterAbNormalSigningAbuseDecision;
  readonly updatedAtMs: number;
};

export class CloudflareDurableObjectRouterAbNormalSigningAdmissionStore
  implements RouterAbNormalSigningAdmissionStore
{
  private readonly namespace: CloudflareDurableObjectNamespaceLike;
  private readonly storageNamespace: string;
  private readonly objectNamePrefix: string;
  private readonly keyPrefix: string;
  private readonly now: () => number;

  constructor(options: CloudflareDurableObjectRouterAbNormalSigningAdmissionStoreOptions) {
    if (!isCloudflareDurableObjectNamespaceLike(options.namespace)) {
      throw new Error('Router A/B normal-signing admission Durable Object namespace is required');
    }
    this.namespace = options.namespace;
    this.storageNamespace = requireNonEmptyString('storageNamespace', options.storageNamespace);
    this.objectNamePrefix = requireNonEmptyString(
      'objectNamePrefix',
      options.objectNamePrefix || THRESHOLD_DO_OBJECT_NAME_DEFAULT,
    );
    this.keyPrefix = normalizeAdmissionKeyPrefix(options.keyPrefix);
    this.now = options.now || Date.now;
  }

  async evaluateProjectPolicy(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningProjectPolicyDecision> {
    const key = this.projectPolicyKey(input.runtimePolicyScope);
    const response = await this.call<unknown | null>(key, { op: 'get', key });
    if (!response.ok) throw new Error(response.message);
    if (response.value === null || response.value === undefined) return { kind: 'allowed' };
    const decision = parseCloudflareDoProjectPolicyRecord(response.value);
    if (!decision) {
      throw new Error('Router A/B normal-signing project-policy record is corrupt');
    }
    return decision;
  }

  async evaluateAbuse(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningAbuseDecision> {
    const key = this.abuseKey(input);
    const response = await this.call<unknown | null>(key, { op: 'get', key });
    if (!response.ok) throw new Error(response.message);
    if (response.value === null || response.value === undefined) return { kind: 'allowed' };
    const decision = parseCloudflareDoAbuseRecord(response.value);
    if (!decision) {
      throw new Error('Router A/B normal-signing abuse record is corrupt');
    }
    return decision;
  }

  async reserveQuota(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningQuotaDecision> {
    const nowMs = this.now();
    const expiresAtMs = quotaReservationExpiresAtMs(input, nowMs);
    if (expiresAtMs <= nowMs) return { kind: 'short_window_saturated' };

    const key = this.quotaKey(input);
    const response = await this.call<unknown>(key, {
      op: 'routerAbNormalSigningReserveQuota',
      key,
      requestId: input.requestId,
      lifecycleId: normalSigningLifecycleId(input),
      expiresAtMs,
      nowMs,
    });
    if (!response.ok) throw new Error(response.message);
    const decision = parseCloudflareDoQuotaDecision(response.value);
    if (!decision) {
      throw new Error('Router A/B normal-signing quota decision is corrupt');
    }
    return decision;
  }

  async setProjectPolicy(
    scope: RuntimePolicyScope,
    decision: RouterAbNormalSigningProjectPolicyDecision,
  ): Promise<void> {
    const key = this.projectPolicyKey(scope);
    const response = await this.call<boolean>(key, {
      op: 'set',
      key,
      value: createCloudflareDoProjectPolicyRecord(decision, this.now()),
    });
    if (!response.ok) throw new Error(response.message);
  }

  async clearProjectPolicy(scope: RuntimePolicyScope): Promise<void> {
    const key = this.projectPolicyKey(scope);
    const response = await this.call<boolean>(key, { op: 'del', key });
    if (!response.ok) throw new Error(response.message);
  }

  async setAbuseDecision(
    input: RouterAbNormalSigningAdmissionInput,
    decision: RouterAbNormalSigningAbuseDecision,
  ): Promise<void> {
    const key = this.abuseKey(input);
    const response = await this.call<boolean>(key, {
      op: 'set',
      key,
      value: createCloudflareDoAbuseRecord(decision, this.now()),
    });
    if (!response.ok) throw new Error(response.message);
  }

  async clearAbuseDecision(input: RouterAbNormalSigningAdmissionInput): Promise<void> {
    const key = this.abuseKey(input);
    const response = await this.call<boolean>(key, { op: 'del', key });
    if (!response.ok) throw new Error(response.message);
  }

  private projectPolicyKey(scope: RuntimePolicyScope): string {
    return this.storageKey('project-policy', runtimePolicyScopeKey(scope));
  }

  private abuseKey(input: RouterAbNormalSigningAdmissionInput): string {
    return this.storageKey('abuse', abusePrincipalKey(input));
  }

  private quotaKey(input: RouterAbNormalSigningAdmissionInput): string {
    return this.storageKey('quota', quotaScopeKey(input));
  }

  private storageKey(category: string, scope: string): string {
    return `${this.keyPrefix}namespace:${this.storageNamespace}:${category}:${scope}`;
  }

  private stubForKey(key: string): CloudflareDurableObjectStubLike {
    return resolveAdmissionDoStub({
      namespace: this.namespace,
      objectName: normalSigningAdmissionObjectName(this.objectNamePrefix, {
        storageNamespace: this.storageNamespace,
        key,
      }),
    });
  }

  private async call<T>(key: string, request: AdmissionDoRequest): Promise<AdmissionDoResp<T>> {
    return await callAdmissionDo<T>(this.stubForKey(key), request);
  }
}

export function createRouterAbNormalSigningAdmissionAdapter(
  store: RouterAbNormalSigningAdmissionStore,
  options: { readonly now?: () => number } = {},
): RouterAbNormalSigningAdmissionAdapter {
  const now = options.now || Date.now;
  return {
    async evaluate(input) {
      if (input.expiresAtMs <= now()) {
        return admissionFailure(
          408,
          'invalid_body',
          'Router A/B normal-signing request is expired',
        );
      }

      const projectPolicy = await store.evaluateProjectPolicy(input);
      switch (projectPolicy.kind) {
        case 'allowed':
          break;
        case 'rejected':
          return admissionFailure(
            403,
            'project_policy_rejected',
            'Router A/B normal-signing project policy rejected the request',
          );
        default:
          return assertNever(projectPolicy);
      }

      const abuse = await store.evaluateAbuse(input);
      switch (abuse.kind) {
        case 'allowed':
          break;
        case 'rate_limited':
          return admissionFailure(
            429,
            'rate_limited',
            'Router A/B normal-signing request is rate limited',
          );
        case 'rejected':
          return admissionFailure(
            403,
            'abuse_rejected',
            'Router A/B normal-signing abuse policy rejected the request',
          );
        default:
          return assertNever(abuse);
      }

      const quota = await store.reserveQuota(input);
      switch (quota.kind) {
        case 'accepted':
        case 'reuse_existing':
          return { ok: true };
        case 'short_window_saturated':
          return admissionFailure(
            429,
            'quota_saturated',
            'Router A/B normal-signing short-window quota is saturated',
          );
        case 'signer_queue_saturated':
          return admissionFailure(
            503,
            'quota_saturated',
            'Router A/B normal-signing signer queue is saturated',
          );
        default:
          return assertNever(quota);
      }
    },
  };
}

export function createInMemoryRouterAbNormalSigningAdmissionStore(
  options: InMemoryRouterAbNormalSigningAdmissionStoreOptions = {},
): InMemoryRouterAbNormalSigningAdmissionStore {
  return new InMemoryRouterAbNormalSigningAdmissionStore(options);
}

export function createInMemoryRouterAbNormalSigningAdmissionAdapter(
  options: InMemoryRouterAbNormalSigningAdmissionStoreOptions = {},
): {
  readonly adapter: RouterAbNormalSigningAdmissionAdapter;
  readonly store: InMemoryRouterAbNormalSigningAdmissionStore;
} {
  const store = createInMemoryRouterAbNormalSigningAdmissionStore(options);
  return {
    store,
    adapter: createRouterAbNormalSigningAdmissionAdapter(store, options),
  };
}

export function createCloudflareDurableObjectRouterAbNormalSigningAdmissionStore(
  options: CloudflareDurableObjectRouterAbNormalSigningAdmissionStoreOptions,
): CloudflareDurableObjectRouterAbNormalSigningAdmissionStore {
  return new CloudflareDurableObjectRouterAbNormalSigningAdmissionStore(options);
}

function isCloudflareDurableObjectNamespaceLike(
  value: unknown,
): value is CloudflareDurableObjectNamespaceLike {
  return (
    isPlainObject(value) &&
    typeof value.idFromName === 'function' &&
    typeof value.get === 'function'
  );
}

function normalizeAdmissionKeyPrefix(value: unknown): string {
  const prefix = toOptionalTrimmedString(value);
  if (!prefix) return ROUTER_AB_NORMAL_SIGNING_ADMISSION_KEY_PREFIX_DEFAULT;
  return prefix.endsWith(':') ? prefix : `${prefix}:`;
}

function normalSigningAdmissionObjectName(
  objectNamePrefix: string,
  input: { readonly storageNamespace: string; readonly key: string },
): string {
  return [
    objectNamePrefix,
    'namespace',
    encodeURIComponent(input.storageNamespace),
    'router-ab-admission',
    fnv1a32Hex(input.key),
  ].join(':');
}

function fnv1a32Hex(input: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

function resolveAdmissionDoStub(input: {
  readonly namespace: CloudflareDurableObjectNamespaceLike;
  readonly objectName: string;
}): CloudflareDurableObjectStubLike {
  const id = input.namespace.idFromName(input.objectName);
  return input.namespace.get(id);
}

async function callAdmissionDo<T>(
  stub: CloudflareDurableObjectStubLike,
  request: AdmissionDoRequest,
): Promise<AdmissionDoResp<T>> {
  const response = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Router A/B normal-signing admission DO HTTP ${response.status}: ${text}`);
  }
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(
      `Router A/B normal-signing admission DO returned non-JSON response: ${text.slice(0, 200)}`,
    );
  }
  if (!isPlainObject(parsed)) {
    throw new Error('Router A/B normal-signing admission DO returned invalid JSON shape');
  }
  if (parsed.ok === true) return parsed as AdmissionDoOk<T>;
  const code = toOptionalTrimmedString(parsed.code) || 'internal';
  const message =
    toOptionalTrimmedString(parsed.message) ||
    'Router A/B normal-signing admission Durable Object error';
  return { ok: false, code, message };
}

function createCloudflareDoProjectPolicyRecord(
  decision: RouterAbNormalSigningProjectPolicyDecision,
  updatedAtMs: number,
): CloudflareDoProjectPolicyRecord {
  return {
    kind: 'router_ab_normal_signing_project_policy_v1',
    decision: normalizeProjectPolicyDecision(decision),
    updatedAtMs: requirePositiveInteger('updatedAtMs', updatedAtMs),
  };
}

function createCloudflareDoAbuseRecord(
  decision: RouterAbNormalSigningAbuseDecision,
  updatedAtMs: number,
): CloudflareDoAbuseRecord {
  return {
    kind: 'router_ab_normal_signing_abuse_decision_v1',
    decision: normalizeAbuseDecision(decision),
    updatedAtMs: requirePositiveInteger('updatedAtMs', updatedAtMs),
  };
}

function parseCloudflareDoProjectPolicyRecord(
  raw: unknown,
): RouterAbNormalSigningProjectPolicyDecision | null {
  if (!isPlainObject(raw)) return null;
  if (raw.kind !== 'router_ab_normal_signing_project_policy_v1') return null;
  const updatedAtMs = requireOptionalSafePositiveInteger(raw.updatedAtMs);
  if (updatedAtMs === null) return null;
  return parseProjectPolicyDecisionValue(raw.decision);
}

function parseCloudflareDoAbuseRecord(raw: unknown): RouterAbNormalSigningAbuseDecision | null {
  if (!isPlainObject(raw)) return null;
  if (raw.kind !== 'router_ab_normal_signing_abuse_decision_v1') return null;
  const updatedAtMs = requireOptionalSafePositiveInteger(raw.updatedAtMs);
  if (updatedAtMs === null) return null;
  return parseAbuseDecisionValue(raw.decision);
}

function parseCloudflareDoQuotaDecision(
  raw: unknown,
): RouterAbNormalSigningQuotaDecision | null {
  if (!isPlainObject(raw)) return null;
  const kind = toOptionalTrimmedString(raw.kind);
  switch (kind) {
    case 'accepted':
      return parseQuotaAcceptedDecision(raw);
    case 'reuse_existing':
      return parseQuotaReuseDecision(raw);
    case 'short_window_saturated':
      return { kind: 'short_window_saturated' };
    case 'signer_queue_saturated':
      return { kind: 'signer_queue_saturated' };
    default:
      return null;
  }
}

function parseQuotaAcceptedDecision(
  raw: Record<string, unknown>,
): RouterAbNormalSigningQuotaDecision | null {
  const requestId = toOptionalTrimmedString(raw.requestId);
  return requestId ? { kind: 'accepted', requestId } : null;
}

function parseQuotaReuseDecision(
  raw: Record<string, unknown>,
): RouterAbNormalSigningQuotaDecision | null {
  const requestId = toOptionalTrimmedString(raw.requestId);
  const existingLifecycleId = toOptionalTrimmedString(raw.existingLifecycleId);
  return requestId && existingLifecycleId
    ? { kind: 'reuse_existing', requestId, existingLifecycleId }
    : null;
}

function normalizeProjectPolicyDecision(
  decision: RouterAbNormalSigningProjectPolicyDecision,
): RouterAbNormalSigningProjectPolicyDecision {
  switch (decision.kind) {
    case 'allowed':
      return { kind: 'allowed' };
    case 'rejected':
      return {
        kind: 'rejected',
        retryAfterMs: requirePositiveInteger('retryAfterMs', decision.retryAfterMs),
      };
    default:
      return assertNever(decision);
  }
}

function normalizeAbuseDecision(
  decision: RouterAbNormalSigningAbuseDecision,
): RouterAbNormalSigningAbuseDecision {
  switch (decision.kind) {
    case 'allowed':
      return { kind: 'allowed' };
    case 'rate_limited':
      return {
        kind: 'rate_limited',
        retryAfterMs: requirePositiveInteger('retryAfterMs', decision.retryAfterMs),
      };
    case 'rejected':
      return {
        kind: 'rejected',
        retryAfterMs: requirePositiveInteger('retryAfterMs', decision.retryAfterMs),
      };
    default:
      return assertNever(decision);
  }
}

function parseProjectPolicyDecisionValue(
  raw: unknown,
): RouterAbNormalSigningProjectPolicyDecision | null {
  if (!isPlainObject(raw)) return null;
  const kind = toOptionalTrimmedString(raw.kind);
  switch (kind) {
    case 'allowed':
      return { kind: 'allowed' };
    case 'rejected': {
      const retryAfterMs = requireOptionalSafePositiveInteger(raw.retryAfterMs);
      return retryAfterMs === null ? null : { kind: 'rejected', retryAfterMs };
    }
    default:
      return null;
  }
}

function parseAbuseDecisionValue(raw: unknown): RouterAbNormalSigningAbuseDecision | null {
  if (!isPlainObject(raw)) return null;
  const kind = toOptionalTrimmedString(raw.kind);
  switch (kind) {
    case 'allowed':
      return { kind: 'allowed' };
    case 'rate_limited': {
      const retryAfterMs = requireOptionalSafePositiveInteger(raw.retryAfterMs);
      return retryAfterMs === null ? null : { kind: 'rate_limited', retryAfterMs };
    }
    case 'rejected': {
      const retryAfterMs = requireOptionalSafePositiveInteger(raw.retryAfterMs);
      return retryAfterMs === null ? null : { kind: 'rejected', retryAfterMs };
    }
    default:
      return null;
  }
}

function requireOptionalSafePositiveInteger(value: unknown): number | null {
  const numeric = typeof value === 'bigint' ? Number(value) : value;
  if (typeof numeric === 'number' && Number.isSafeInteger(numeric) && numeric > 0) {
    return numeric;
  }
  return null;
}

function admissionFailure(
  status: 400 | 401 | 403 | 408 | 409 | 429 | 500 | 503,
  code:
    | 'project_policy_rejected'
    | 'quota_saturated'
    | 'abuse_rejected'
    | 'rate_limited'
    | 'invalid_body',
  message: string,
): RouterAbNormalSigningAdmissionResult {
  return { ok: false, status, code, message };
}

export function runtimePolicyScopeKey(scope: RuntimePolicyScope): string {
  return [scope.orgId, scope.projectId, scope.envId, scope.signingRootVersion].join('\x1f');
}

function ed25519AdmissionAuthorityScopeKey(scope: ThresholdEd25519AuthorityScope): string {
  switch (scope.kind) {
    case 'passkey_rp':
      return `passkey_rp:${scope.rpId}`;
    case 'email_otp':
      switch (scope.proofKind) {
        case 'otp_challenge':
          return `email_otp:otp_challenge:${scope.email}:${scope.challengeId || ''}`;
        case 'google_sso_registration':
          return [
            'email_otp',
            'google_sso_registration',
            scope.email,
            scope.googleEmailOtpRegistrationAttemptId,
            scope.googleEmailOtpRegistrationOfferId,
            scope.googleEmailOtpRegistrationCandidateId,
          ].join(':');
      }
  }
}

function admissionAuthorityScope(input: RouterAbNormalSigningAdmissionInput): string {
  switch (input.curve) {
    case 'ed25519':
      return ed25519AdmissionAuthorityScopeKey(input.authorityScope);
    case 'ecdsa-hss':
      return input.evmFamilySigningKeySlotId;
  }
  input satisfies never;
  throw new Error('Unsupported Router A/B normal-signing curve');
}

export function abusePrincipalKey(input: RouterAbNormalSigningAdmissionInput): string {
  return [
    runtimePolicyScopeKey(input.runtimePolicyScope),
    input.walletId,
    admissionAuthorityScope(input),
    input.curve,
  ].join('\x1f');
}

export function quotaScopeKey(input: RouterAbNormalSigningAdmissionInput): string {
  const base = [
    runtimePolicyScopeKey(input.runtimePolicyScope),
    input.walletId,
    admissionAuthorityScope(input),
    input.curve,
    input.phase,
    input.thresholdSessionId,
    input.signingGrantId,
    input.requestId,
    input.signingWorkerId,
  ];
  if (input.curve === 'ecdsa-hss') {
    return [...base, input.keyHandle].join('\x1f');
  }
  return base.join('\x1f');
}

export function quotaReservationExpiresAtMs(
  input: RouterAbNormalSigningAdmissionInput,
  nowMs: number,
): number {
  return Math.min(input.expiresAtMs, nowMs + ROUTER_AB_NORMAL_SIGNING_QUOTA_RESERVATION_TTL_MS);
}

export function normalSigningLifecycleId(input: RouterAbNormalSigningAdmissionInput): string {
  const base = [
    input.curve,
    input.phase,
    input.walletId,
    admissionAuthorityScope(input),
    input.thresholdSessionId,
    input.signingGrantId,
    input.requestId,
    input.signingWorkerId,
  ];
  if (input.curve === 'ecdsa-hss') {
    return [...base, input.keyHandle].join(':');
  }
  return base.join(':');
}

export function requireNonEmptyString(label: string, value: unknown): string {
  if (typeof value === 'string' && value.trim().length > 0) {
    return value.trim();
  }
  throw new Error(`${label} must be a non-empty string`);
}

export function readFirstRow(rows: unknown[], label: string): Record<string, unknown> {
  const row = rows[0];
  if (row && typeof row === 'object' && !Array.isArray(row)) {
    return row as Record<string, unknown>;
  }
  throw new Error(`${label} row is missing`);
}

export function readOptionalFirstRow(rows: unknown[]): Record<string, unknown> | null {
  const row = rows[0];
  if (!row) return null;
  if (typeof row === 'object' && !Array.isArray(row)) {
    return row as Record<string, unknown>;
  }
  throw new Error('Storage row must be an object');
}

export function parseProjectPolicyDecision(
  row: Record<string, unknown>,
): RouterAbNormalSigningProjectPolicyDecision {
  const decision = requireNonEmptyString('decision', row.decision);
  switch (decision) {
    case 'allowed':
      return { kind: 'allowed' };
    case 'rejected':
      return {
        kind: 'rejected',
        retryAfterMs: requirePositiveInteger('retry_after_ms', row.retry_after_ms),
      };
    default:
      throw new Error(`Unsupported Router A/B project-policy decision ${decision}`);
  }
}

export function parseAbuseDecision(
  row: Record<string, unknown>,
): RouterAbNormalSigningAbuseDecision {
  const decision = requireNonEmptyString('decision', row.decision);
  switch (decision) {
    case 'allowed':
      return { kind: 'allowed' };
    case 'rate_limited':
      return {
        kind: 'rate_limited',
        retryAfterMs: requirePositiveInteger('retry_after_ms', row.retry_after_ms),
      };
    case 'rejected':
      return {
        kind: 'rejected',
        retryAfterMs: requirePositiveInteger('retry_after_ms', row.retry_after_ms),
      };
    default:
      throw new Error(`Unsupported Router A/B abuse decision ${decision}`);
  }
}

function requirePositiveInteger(label: string, value: unknown): number {
  const numeric = typeof value === 'bigint' ? Number(value) : value;
  if (typeof numeric === 'number' && Number.isSafeInteger(numeric) && numeric > 0) {
    return numeric;
  }
  if (typeof numeric === 'string') {
    const parsed = Number(numeric);
    if (Number.isSafeInteger(parsed) && parsed > 0) return parsed;
  }
  throw new Error(`${label} must be a positive integer`);
}

function assertNever(value: never): never {
  throw new Error(`Unexpected Router A/B normal-signing admission branch: ${String(value)}`);
}
