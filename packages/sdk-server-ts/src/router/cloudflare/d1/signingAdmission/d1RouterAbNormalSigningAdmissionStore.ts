import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { isD1DatabaseLike } from '../../../../storage/d1Sql';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../../../storage/tenantRoute';
import {
  abusePrincipalKey,
  runtimePolicyScopeKey,
} from '../../../domains/signingOperations/routerAbNormalSigningAdmissionCore';
import type { RouterAbNormalSigningAdmissionInput } from '../../../domains/signingOperations/routerAbPrivateSigningWorker';
import type {
  RouterAbNormalSigningAbuseDecision,
  RouterAbNormalSigningAdmissionStore,
  RouterAbNormalSigningProjectPolicyDecision,
} from '../../../domains/signingOperations/routerAbNormalSigningAdmissionCore';

export type CloudflareD1RouterAbNormalSigningAdmissionStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly storageNamespace: string;
  readonly now?: () => number;
};

type CloudflareD1AdmissionDecisionRow = {
  readonly decision?: unknown;
  readonly retry_after_ms?: unknown;
};

const ROUTER_AB_NORMAL_SIGNING_ADMISSION_TABLE = 'router_ab_normal_signing_admission_records';

export class CloudflareD1RouterAbNormalSigningAdmissionStore
  implements RouterAbNormalSigningAdmissionStore
{
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

function parseProjectPolicyDecision(
  row: CloudflareD1AdmissionDecisionRow,
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

function parseAbuseDecision(row: CloudflareD1AdmissionDecisionRow): RouterAbNormalSigningAbuseDecision {
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

async function requireSuccessfulD1Write(statement: D1PreparedStatementLike): Promise<void> {
  const result = await statement.run();
  if (!isSuccessfulD1Result(result)) {
    throw new Error('Router A/B normal-signing admission D1 write failed');
  }
}

function isSuccessfulD1Result(result: D1ResultLike): boolean {
  return result.success === true;
}

function requireNonEmptyString(label: string, value: unknown): string {
  if (typeof value === 'string' && value.trim().length > 0) {
    return value.trim();
  }
  throw new Error(`${label} must be a non-empty string`);
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
