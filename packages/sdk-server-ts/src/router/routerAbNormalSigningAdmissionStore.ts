import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { getPostgresPool, type PgQueryExecutor } from '../storage/postgres';
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

export type PostgresRouterAbNormalSigningAdmissionStoreOptions = {
  readonly postgresUrl: string;
  readonly namespace: string;
  readonly now?: () => number;
};

export async function ensurePostgresRouterAbNormalSigningAdmissionStoreSchema(
  executor: PgQueryExecutor,
): Promise<void> {
  await executor.query(`
    CREATE TABLE IF NOT EXISTS router_ab_normal_signing_quota_reservations (
      namespace TEXT NOT NULL,
      quota_scope TEXT NOT NULL,
      request_id TEXT NOT NULL,
      lifecycle_id TEXT NOT NULL,
      expires_at_ms BIGINT NOT NULL,
      created_at_ms BIGINT NOT NULL,
      PRIMARY KEY (namespace, quota_scope)
    )
  `);
  await executor.query(`
    CREATE INDEX IF NOT EXISTS router_ab_normal_signing_quota_expires_idx
      ON router_ab_normal_signing_quota_reservations (expires_at_ms)
  `);
  await executor.query(`
    CREATE TABLE IF NOT EXISTS router_ab_normal_signing_project_policies (
      namespace TEXT NOT NULL,
      runtime_policy_scope TEXT NOT NULL,
      decision TEXT NOT NULL,
      retry_after_ms BIGINT,
      updated_at_ms BIGINT NOT NULL,
      PRIMARY KEY (namespace, runtime_policy_scope)
    )
  `);
  await executor.query(`
    CREATE TABLE IF NOT EXISTS router_ab_normal_signing_abuse_records (
      namespace TEXT NOT NULL,
      abuse_principal TEXT NOT NULL,
      decision TEXT NOT NULL,
      retry_after_ms BIGINT,
      updated_at_ms BIGINT NOT NULL,
      PRIMARY KEY (namespace, abuse_principal)
    )
  `);
}

export class PostgresRouterAbNormalSigningAdmissionStore implements RouterAbNormalSigningAdmissionStore {
  private readonly postgresUrl: string;
  private readonly namespace: string;
  private readonly now: () => number;
  private schemaReady: Promise<void> | null = null;

  constructor(options: PostgresRouterAbNormalSigningAdmissionStoreOptions) {
    this.postgresUrl = requireNonEmptyString('postgresUrl', options.postgresUrl);
    this.namespace = requireNonEmptyString('namespace', options.namespace);
    this.now = options.now || Date.now;
  }

  async evaluateProjectPolicy(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningProjectPolicyDecision> {
    await this.ensureSchema();
    const pool = await getPostgresPool(this.postgresUrl);
    const result = await pool.query(
      `
        SELECT decision, retry_after_ms
        FROM router_ab_normal_signing_project_policies
        WHERE namespace = $1
          AND runtime_policy_scope = $2
        LIMIT 1
      `,
      [this.namespace, runtimePolicyScopeKey(input.runtimePolicyScope)],
    );
    const row = readOptionalFirstRow(result.rows);
    if (!row) return { kind: 'allowed' };
    return parseProjectPolicyDecision(row);
  }

  async evaluateAbuse(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningAbuseDecision> {
    await this.ensureSchema();
    const pool = await getPostgresPool(this.postgresUrl);
    const result = await pool.query(
      `
        SELECT decision, retry_after_ms
        FROM router_ab_normal_signing_abuse_records
        WHERE namespace = $1
          AND abuse_principal = $2
        LIMIT 1
      `,
      [this.namespace, abusePrincipalKey(input)],
    );
    const row = readOptionalFirstRow(result.rows);
    if (!row) return { kind: 'allowed' };
    return parseAbuseDecision(row);
  }

  async reserveQuota(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningQuotaDecision> {
    await this.ensureSchema();
    const pool = await getPostgresPool(this.postgresUrl);
    const nowMs = this.now();
    const quotaScope = quotaScopeKey(input);

    await pool.query(
      `
        DELETE FROM router_ab_normal_signing_quota_reservations
        WHERE namespace = $1
          AND expires_at_ms <= $2
      `,
      [this.namespace, nowMs],
    );

    const insert = await pool.query(
      `
        INSERT INTO router_ab_normal_signing_quota_reservations
          (namespace, quota_scope, request_id, lifecycle_id, expires_at_ms, created_at_ms)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (namespace, quota_scope) DO NOTHING
      `,
      [
        this.namespace,
        quotaScope,
        input.requestId,
        normalSigningLifecycleId(input),
        quotaReservationExpiresAtMs(input, nowMs),
        nowMs,
      ],
    );

    if (insert.rowCount === 1) {
      return { kind: 'accepted', requestId: input.requestId };
    }

    const existing = await pool.query(
      `
        SELECT request_id, lifecycle_id
        FROM router_ab_normal_signing_quota_reservations
        WHERE namespace = $1
          AND quota_scope = $2
        LIMIT 1
      `,
      [this.namespace, quotaScope],
    );
    const row = readFirstRow(existing.rows, 'normal-signing quota reservation');
    const requestId = requireNonEmptyString('request_id', row.request_id);
    if (requestId === input.requestId) {
      return {
        kind: 'reuse_existing',
        requestId,
        existingLifecycleId: requireNonEmptyString('lifecycle_id', row.lifecycle_id),
      };
    }

    return { kind: 'short_window_saturated' };
  }

  async setProjectPolicy(
    scope: RuntimePolicyScope,
    decision: RouterAbNormalSigningProjectPolicyDecision,
  ): Promise<void> {
    await this.ensureSchema();
    const pool = await getPostgresPool(this.postgresUrl);
    await pool.query(
      `
        INSERT INTO router_ab_normal_signing_project_policies
          (namespace, runtime_policy_scope, decision, retry_after_ms, updated_at_ms)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (namespace, runtime_policy_scope) DO UPDATE SET
          decision = EXCLUDED.decision,
          retry_after_ms = EXCLUDED.retry_after_ms,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        this.namespace,
        runtimePolicyScopeKey(scope),
        decision.kind,
        decision.kind === 'rejected' ? decision.retryAfterMs : null,
        this.now(),
      ],
    );
  }

  async clearProjectPolicy(scope: RuntimePolicyScope): Promise<void> {
    await this.ensureSchema();
    const pool = await getPostgresPool(this.postgresUrl);
    await pool.query(
      `
        DELETE FROM router_ab_normal_signing_project_policies
        WHERE namespace = $1
          AND runtime_policy_scope = $2
      `,
      [this.namespace, runtimePolicyScopeKey(scope)],
    );
  }

  async setAbuseDecision(
    input: RouterAbNormalSigningAdmissionInput,
    decision: RouterAbNormalSigningAbuseDecision,
  ): Promise<void> {
    await this.ensureSchema();
    const pool = await getPostgresPool(this.postgresUrl);
    await pool.query(
      `
        INSERT INTO router_ab_normal_signing_abuse_records
          (namespace, abuse_principal, decision, retry_after_ms, updated_at_ms)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (namespace, abuse_principal) DO UPDATE SET
          decision = EXCLUDED.decision,
          retry_after_ms = EXCLUDED.retry_after_ms,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        this.namespace,
        abusePrincipalKey(input),
        decision.kind,
        decision.kind === 'allowed' ? null : decision.retryAfterMs,
        this.now(),
      ],
    );
  }

  async clearAbuseDecision(input: RouterAbNormalSigningAdmissionInput): Promise<void> {
    await this.ensureSchema();
    const pool = await getPostgresPool(this.postgresUrl);
    await pool.query(
      `
        DELETE FROM router_ab_normal_signing_abuse_records
        WHERE namespace = $1
          AND abuse_principal = $2
      `,
      [this.namespace, abusePrincipalKey(input)],
    );
  }

  private async ensureSchema(): Promise<void> {
    if (!this.schemaReady) {
      this.schemaReady = (async () => {
        const pool = await getPostgresPool(this.postgresUrl);
        await ensurePostgresRouterAbNormalSigningAdmissionStoreSchema(pool);
      })();
    }
    await this.schemaReady;
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

export function createPostgresRouterAbNormalSigningAdmissionStore(
  options: PostgresRouterAbNormalSigningAdmissionStoreOptions,
): PostgresRouterAbNormalSigningAdmissionStore {
  return new PostgresRouterAbNormalSigningAdmissionStore(options);
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

function runtimePolicyScopeKey(scope: RuntimePolicyScope): string {
  return [scope.orgId, scope.projectId, scope.envId, scope.signingRootVersion].join('\x1f');
}

function abusePrincipalKey(input: RouterAbNormalSigningAdmissionInput): string {
  return [
    runtimePolicyScopeKey(input.runtimePolicyScope),
    input.walletId,
    input.rpId,
    input.curve,
  ].join('\x1f');
}

function quotaScopeKey(input: RouterAbNormalSigningAdmissionInput): string {
  const base = [
    runtimePolicyScopeKey(input.runtimePolicyScope),
    input.walletId,
    input.rpId,
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

function quotaReservationExpiresAtMs(
  input: RouterAbNormalSigningAdmissionInput,
  nowMs: number,
): number {
  return Math.min(input.expiresAtMs, nowMs + ROUTER_AB_NORMAL_SIGNING_QUOTA_RESERVATION_TTL_MS);
}

function normalSigningLifecycleId(input: RouterAbNormalSigningAdmissionInput): string {
  const base = [
    input.curve,
    input.phase,
    input.walletId,
    input.rpId,
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

function requireNonEmptyString(label: string, value: unknown): string {
  if (typeof value === 'string' && value.trim().length > 0) {
    return value.trim();
  }
  throw new Error(`${label} must be a non-empty string`);
}

function readFirstRow(rows: unknown[], label: string): Record<string, unknown> {
  const row = rows[0];
  if (row && typeof row === 'object' && !Array.isArray(row)) {
    return row as Record<string, unknown>;
  }
  throw new Error(`${label} row is missing`);
}

function readOptionalFirstRow(rows: unknown[]): Record<string, unknown> | null {
  const row = rows[0];
  if (!row) return null;
  if (typeof row === 'object' && !Array.isArray(row)) {
    return row as Record<string, unknown>;
  }
  throw new Error('Postgres row must be an object');
}

function parseProjectPolicyDecision(
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

function parseAbuseDecision(row: Record<string, unknown>): RouterAbNormalSigningAbuseDecision {
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
