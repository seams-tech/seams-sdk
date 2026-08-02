import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { ThresholdEd25519AuthorityScope } from '../core/types';
import type { D1DatabaseLike, D1PreparedStatementLike, D1ResultLike } from '../storage/tenantRoute';
import { isD1DatabaseLike } from '../storage/d1Sql';
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
    input: Extract<RouterAbNormalSigningAdmissionInput, { readonly curve: 'ed25519' }>,
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
    input: Extract<RouterAbNormalSigningAdmissionInput, { readonly curve: 'ed25519' }>,
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

export type CloudflareD1RouterAbNormalSigningAdmissionStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly storageNamespace: string;
  readonly now?: () => number;
};

type CloudflareD1AdmissionDecisionRow = {
  readonly decision?: unknown;
  readonly retry_after_ms?: unknown;
};

type CloudflareD1QuotaReservationRow = {
  readonly request_id?: unknown;
  readonly lifecycle_id?: unknown;
};

const ROUTER_AB_NORMAL_SIGNING_ADMISSION_TABLE = 'router_ab_normal_signing_admission_records';

export class CloudflareD1RouterAbNormalSigningAdmissionStore implements RouterAbNormalSigningAdmissionStore {
  private readonly database: D1DatabaseLike;
  private readonly storageNamespace: string;
  private readonly now: () => number;

  constructor(options: CloudflareD1RouterAbNormalSigningAdmissionStoreOptions) {
    if (!isD1DatabaseLike(options.database)) {
      throw new Error('Router A/B normal-signing admission D1 database is required');
    }
    this.database = options.database;
    this.storageNamespace = requireNonEmptyString('storageNamespace', options.storageNamespace);
    this.now = options.now || Date.now;
  }

  async evaluateProjectPolicy(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningProjectPolicyDecision> {
    const row = await this.readDecision(
      input.runtimePolicyScope,
      'project_policy',
      runtimePolicyScopeKey(input.runtimePolicyScope),
    );
    return row === null ? { kind: 'allowed' } : parseProjectPolicyDecision(row);
  }

  async evaluateAbuse(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningAbuseDecision> {
    const row = await this.readDecision(
      input.runtimePolicyScope,
      'abuse',
      abusePrincipalKey(input),
    );
    return row === null ? { kind: 'allowed' } : parseAbuseDecision(row);
  }

  async reserveQuota(
    input: Extract<RouterAbNormalSigningAdmissionInput, { readonly curve: 'ed25519' }>,
  ): Promise<RouterAbNormalSigningQuotaDecision> {
    const nowMs = this.now();
    const expiresAtMs = quotaReservationExpiresAtMs(input, nowMs);
    if (expiresAtMs <= nowMs) return { kind: 'short_window_saturated' };
    const scope = input.runtimePolicyScope;
    const lifecycleId = normalSigningLifecycleId(input);
    const row = await this.database
      .prepare(
        `INSERT INTO ${ROUTER_AB_NORMAL_SIGNING_ADMISSION_TABLE} (
           namespace, org_id, project_id, env_id, signing_root_version,
           record_kind, record_key, request_id, lifecycle_id, expires_at_ms, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, 'quota', ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT (
           namespace, org_id, project_id, env_id, signing_root_version, record_kind, record_key
         ) DO UPDATE SET
           request_id = excluded.request_id,
           lifecycle_id = excluded.lifecycle_id,
           expires_at_ms = excluded.expires_at_ms,
           updated_at_ms = excluded.updated_at_ms
         WHERE ${ROUTER_AB_NORMAL_SIGNING_ADMISSION_TABLE}.expires_at_ms <= ?10
         RETURNING request_id, lifecycle_id`,
      )
      .bind(
        this.storageNamespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        scope.signingRootVersion,
        quotaScopeKey(input),
        input.requestId,
        lifecycleId,
        expiresAtMs,
        nowMs,
      )
      .first<CloudflareD1QuotaReservationRow>();
    if (row !== null) {
      return { kind: 'accepted', requestId: input.requestId };
    }

    const existing = await this.readQuotaReservation(scope, quotaScopeKey(input));
    if (existing === null) {
      throw new Error('Router A/B normal-signing D1 quota reservation disappeared');
    }
    const requestId = requireNonEmptyString('request_id', existing.request_id);
    const existingLifecycleId = requireNonEmptyString('lifecycle_id', existing.lifecycle_id);
    if (requestId === input.requestId) {
      return { kind: 'reuse_existing', requestId, existingLifecycleId };
    }
    return { kind: 'short_window_saturated' };
  }

  async setProjectPolicy(
    scope: RuntimePolicyScope,
    decision: RouterAbNormalSigningProjectPolicyDecision,
  ): Promise<void> {
    const normalized = normalizeProjectPolicyDecision(decision);
    await this.putDecision(
      scope,
      'project_policy',
      runtimePolicyScopeKey(scope),
      normalized.kind,
      normalized.kind === 'rejected' ? normalized.retryAfterMs : null,
    );
  }

  async clearProjectPolicy(scope: RuntimePolicyScope): Promise<void> {
    await this.deleteRecord(scope, 'project_policy', runtimePolicyScopeKey(scope));
  }

  async setAbuseDecision(
    input: RouterAbNormalSigningAdmissionInput,
    decision: RouterAbNormalSigningAbuseDecision,
  ): Promise<void> {
    const normalized = normalizeAbuseDecision(decision);
    await this.putDecision(
      input.runtimePolicyScope,
      'abuse',
      abusePrincipalKey(input),
      normalized.kind,
      normalized.kind === 'allowed' ? null : normalized.retryAfterMs,
    );
  }

  async clearAbuseDecision(input: RouterAbNormalSigningAdmissionInput): Promise<void> {
    await this.deleteRecord(input.runtimePolicyScope, 'abuse', abusePrincipalKey(input));
  }

  private async readDecision(
    scope: RuntimePolicyScope,
    kind: 'project_policy' | 'abuse',
    key: string,
  ): Promise<CloudflareD1AdmissionDecisionRow | null> {
    return await this.database
      .prepare(
        `SELECT decision, retry_after_ms
           FROM ${ROUTER_AB_NORMAL_SIGNING_ADMISSION_TABLE}
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND signing_root_version = ?5
            AND record_kind = ?6
            AND record_key = ?7`,
      )
      .bind(
        this.storageNamespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        scope.signingRootVersion,
        kind,
        key,
      )
      .first<CloudflareD1AdmissionDecisionRow>();
  }

  private async readQuotaReservation(
    scope: RuntimePolicyScope,
    key: string,
  ): Promise<CloudflareD1QuotaReservationRow | null> {
    return await this.database
      .prepare(
        `SELECT request_id, lifecycle_id
           FROM ${ROUTER_AB_NORMAL_SIGNING_ADMISSION_TABLE}
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND signing_root_version = ?5
            AND record_kind = 'quota'
            AND record_key = ?6`,
      )
      .bind(
        this.storageNamespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        scope.signingRootVersion,
        key,
      )
      .first<CloudflareD1QuotaReservationRow>();
  }

  private async putDecision(
    scope: RuntimePolicyScope,
    kind: 'project_policy' | 'abuse',
    key: string,
    decision: string,
    retryAfterMs: number | null,
  ): Promise<void> {
    await requireSuccessfulD1Write(
      this.database
        .prepare(
          `INSERT INTO ${ROUTER_AB_NORMAL_SIGNING_ADMISSION_TABLE} (
             namespace, org_id, project_id, env_id, signing_root_version,
             record_kind, record_key, decision, retry_after_ms, updated_at_ms
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
           ON CONFLICT (
             namespace, org_id, project_id, env_id, signing_root_version, record_kind, record_key
           ) DO UPDATE SET
             decision = excluded.decision,
             retry_after_ms = excluded.retry_after_ms,
             updated_at_ms = excluded.updated_at_ms`,
        )
        .bind(
          this.storageNamespace,
          scope.orgId,
          scope.projectId,
          scope.envId,
          scope.signingRootVersion,
          kind,
          key,
          decision,
          retryAfterMs,
          this.now(),
        ),
    );
  }

  private async deleteRecord(
    scope: RuntimePolicyScope,
    kind: 'project_policy' | 'abuse',
    key: string,
  ): Promise<void> {
    await requireSuccessfulD1Write(
      this.database
        .prepare(
          `DELETE FROM ${ROUTER_AB_NORMAL_SIGNING_ADMISSION_TABLE}
            WHERE namespace = ?1
              AND org_id = ?2
              AND project_id = ?3
              AND env_id = ?4
              AND signing_root_version = ?5
              AND record_kind = ?6
              AND record_key = ?7`,
        )
        .bind(
          this.storageNamespace,
          scope.orgId,
          scope.projectId,
          scope.envId,
          scope.signingRootVersion,
          kind,
          key,
        ),
    );
  }
}

async function requireSuccessfulD1Write(statement: D1PreparedStatementLike): Promise<void> {
  const result = await statement.run();
  if (!isSuccessfulD1Result(result)) {
    throw new Error('Router A/B normal-signing admission D1 write failed');
  }
}

function isSuccessfulD1Result(result: D1ResultLike): boolean {
  return result.success === true;
}

class DefaultRouterAbNormalSigningAdmissionAdapter
  implements RouterAbNormalSigningAdmissionAdapter
{
  constructor(
    private readonly store: RouterAbNormalSigningAdmissionStore,
    private readonly now: () => number,
  ) {}

  async evaluatePolicy(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningAdmissionResult> {
    if (input.expiresAtMs <= this.now()) {
      return admissionFailure(
        408,
        'invalid_body',
        'Router A/B normal-signing request is expired',
      );
    }

    const projectPolicy = await this.store.evaluateProjectPolicy(input);
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

    const abuse = await this.store.evaluateAbuse(input);
    switch (abuse.kind) {
      case 'allowed':
        return { ok: true };
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
  }

  async evaluate(
    input: Extract<RouterAbNormalSigningAdmissionInput, { readonly curve: 'ed25519' }>,
  ): Promise<RouterAbNormalSigningAdmissionResult> {
    const policy = await this.evaluatePolicy(input);
    if (!policy.ok) return policy;

    const quota = await this.store.reserveQuota(input);
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
  }
}

export function createRouterAbNormalSigningAdmissionAdapter(
  store: RouterAbNormalSigningAdmissionStore,
  options: { readonly now?: () => number } = {},
): RouterAbNormalSigningAdmissionAdapter {
  return new DefaultRouterAbNormalSigningAdmissionAdapter(store, options.now || Date.now);
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

export function createCloudflareD1RouterAbNormalSigningAdmissionStore(
  options: CloudflareD1RouterAbNormalSigningAdmissionStoreOptions,
): CloudflareD1RouterAbNormalSigningAdmissionStore {
  return new CloudflareD1RouterAbNormalSigningAdmissionStore(options);
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
      return `email_otp:${scope.provider}:${scope.providerUserId}`;
  }
}

function admissionAuthorityScope(input: RouterAbNormalSigningAdmissionInput): string {
  switch (input.curve) {
    case 'ed25519':
      return ed25519AdmissionAuthorityScopeKey(input.authorityScope);
    case 'ecdsa':
      return `material_activation:${input.materialActivationId}`;
  }
  input satisfies never;
  throw new Error('Unsupported Router A/B normal-signing curve');
}

function admissionAuthorizationIdentityKey(input: RouterAbNormalSigningAdmissionInput): string {
  if (input.curve === 'ed25519') return input.thresholdSessionId;
  switch (input.authorizationIdentity.kind) {
    case 'reusable_wallet_session':
      return `wallet_session:${input.authorizationIdentity.walletSessionId}`;
    case 'operation_step_up':
      return `material_activation:${input.authorizationIdentity.materialActivationId}`;
  }
  input.authorizationIdentity satisfies never;
  throw new Error('Unsupported Router A/B normal-signing authorization identity');
}

export function abusePrincipalKey(input: RouterAbNormalSigningAdmissionInput): string {
  return [
    runtimePolicyScopeKey(input.runtimePolicyScope),
    input.walletId,
    admissionAuthorityScope(input),
    input.curve,
  ].join('\x1f');
}

export function quotaScopeKey(
  input: Extract<RouterAbNormalSigningAdmissionInput, { readonly curve: 'ed25519' }>,
): string {
  const base = [
    runtimePolicyScopeKey(input.runtimePolicyScope),
    input.walletId,
    admissionAuthorityScope(input),
    input.curve,
    input.phase,
    admissionAuthorizationIdentityKey(input),
    input.walletSessionId,
    input.quotaId,
    input.requestId,
    input.signingWorkerId,
  ];
  return base.join('\x1f');
}

export function quotaReservationExpiresAtMs(
  input: RouterAbNormalSigningAdmissionInput,
  nowMs: number,
): number {
  return Math.min(input.expiresAtMs, nowMs + ROUTER_AB_NORMAL_SIGNING_QUOTA_RESERVATION_TTL_MS);
}

export function normalSigningLifecycleId(
  input: Extract<RouterAbNormalSigningAdmissionInput, { readonly curve: 'ed25519' }>,
): string {
  const base = [
    input.curve,
    input.phase,
    input.walletId,
    admissionAuthorityScope(input),
    admissionAuthorizationIdentityKey(input),
    input.walletSessionId,
    input.quotaId,
    input.requestId,
    input.signingWorkerId,
  ];
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
