import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { getPostgresPool, type PgQueryExecutor } from '../storage/postgres';
import type { RouterAbNormalSigningAdmissionInput } from './routerAbPrivateSigningWorker';
import {
  abusePrincipalKey,
  normalSigningLifecycleId,
  parseAbuseDecision,
  parseProjectPolicyDecision,
  quotaReservationExpiresAtMs,
  quotaScopeKey,
  readFirstRow,
  readOptionalFirstRow,
  requireNonEmptyString,
  runtimePolicyScopeKey,
  type RouterAbNormalSigningAbuseDecision,
  type RouterAbNormalSigningAdmissionStore,
  type RouterAbNormalSigningProjectPolicyDecision,
  type RouterAbNormalSigningQuotaDecision,
} from './routerAbNormalSigningAdmissionCore';

export {
  CloudflareDurableObjectRouterAbNormalSigningAdmissionStore,
  InMemoryRouterAbNormalSigningAdmissionStore,
  createCloudflareDurableObjectRouterAbNormalSigningAdmissionStore,
  createInMemoryRouterAbNormalSigningAdmissionAdapter,
  createInMemoryRouterAbNormalSigningAdmissionStore,
  createRouterAbNormalSigningAdmissionAdapter,
} from './routerAbNormalSigningAdmissionCore';
export type {
  CloudflareDurableObjectRouterAbNormalSigningAdmissionStoreOptions,
  InMemoryRouterAbNormalSigningAdmissionStoreOptions,
  RouterAbNormalSigningAbuseDecision,
  RouterAbNormalSigningAbuseProvider,
  RouterAbNormalSigningAdmissionStore,
  RouterAbNormalSigningProjectPolicyDecision,
  RouterAbNormalSigningProjectPolicyProvider,
  RouterAbNormalSigningQuotaDecision,
  RouterAbNormalSigningQuotaStore,
} from './routerAbNormalSigningAdmissionCore';

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

export function createPostgresRouterAbNormalSigningAdmissionStore(
  options: PostgresRouterAbNormalSigningAdmissionStoreOptions,
): PostgresRouterAbNormalSigningAdmissionStore {
  return new PostgresRouterAbNormalSigningAdmissionStore(options);
}
