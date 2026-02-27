import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import {
  ensureConsoleNamespace as ensureNamespace,
  toConsoleIso as toIso,
  toConsoleNumber as toNumber,
} from '../shared/postgresNormalize';
import { ConsolePolicyError } from './errors';
import {
  normalizePolicyScopeType as normalizeScopeType,
  policyScopeKey as assignmentScopeKey,
} from './normalization';
import type { ConsolePoliciesContext, ConsolePolicyService } from './service';
import type {
  ConsolePolicyAssignment,
  ConsolePolicyWalletScopeRef,
  ConsolePolicy,
  CreateConsolePolicyRequest,
  ListConsolePolicyAssignmentsRequest,
  PublishConsolePolicyResult,
  SimulateConsolePolicyRequest,
  SimulateConsolePolicyResult,
  UpsertConsolePolicyAssignmentRequest,
  UpdateConsolePolicyRequest,
} from './types';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_POLICIES_MIGRATION_LOCK_ID = 9452360123583;

function nowMs(now: Date): number {
  return now.getTime();
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function parseRules(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return { ...(raw as Record<string, unknown>) };
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return { ...(parsed as Record<string, unknown>) };
      }
    } catch {
      return {};
    }
  }
  return {};
}

function parsePolicyRow(row: PgRow): ConsolePolicy {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    name: String(row.name || ''),
    description: row.description == null ? null : String(row.description || '') || null,
    status: String(row.status || 'DRAFT') as ConsolePolicy['status'],
    version: toNumber(row.version),
    rules: parseRules(row.rules),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
    publishedAt: toIso(row.published_at_ms == null ? null : toNumber(row.published_at_ms)),
  };
}

function parsePolicyAssignmentRow(row: PgRow): ConsolePolicyAssignment {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    scopeType: String(row.scope_type || 'ORG') as ConsolePolicyAssignment['scopeType'],
    scopeId: String(row.scope_id || ''),
    policyId: String(row.policy_id || ''),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

function listStringValues(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  return input
    .map((entry) => String(entry || '').trim())
    .filter(Boolean);
}

function evaluatePolicyRules(
  policy: ConsolePolicy,
  request: SimulateConsolePolicyRequest,
): SimulateConsolePolicyResult['decision'] | null {
  const rules = policy.rules || {};
  const blockedActions = listStringValues((rules as Record<string, unknown>).blockedActions).map(
    (entry) => entry.toLowerCase(),
  );
  if (blockedActions.includes(String(request.action || '').toLowerCase())) return 'DENY';

  const allowedChains = listStringValues((rules as Record<string, unknown>).allowedChains).map(
    (entry) => entry.toLowerCase(),
  );
  if (allowedChains.length > 0 && request.chain) {
    if (!allowedChains.includes(String(request.chain || '').toLowerCase())) return 'DENY';
  }

  const maxAmountMinorRaw = (rules as Record<string, unknown>).maxAmountMinor;
  if (maxAmountMinorRaw !== undefined && request.amountMinor !== undefined) {
    const maxAmountMinor = Number(maxAmountMinorRaw);
    if (Number.isFinite(maxAmountMinor) && request.amountMinor > maxAmountMinor) return 'DENY';
  }

  return 'ALLOW';
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

async function withTx<T>(pool: PgPool, fn: (q: Queryable) => Promise<T>): Promise<T> {
  await pool.query('BEGIN');
  try {
    const result = await fn(pool);
    await pool.query('COMMIT');
    return result;
  } catch (error: unknown) {
    try {
      await pool.query('ROLLBACK');
    } catch {
      // no-op
    }
    throw error;
  }
}

export interface PostgresConsolePolicySchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsolePoliciesPostgresSchema(
  options: PostgresConsolePolicySchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_POLICIES_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_policies (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL,
        version INTEGER NOT NULL,
        rules JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        published_at_ms BIGINT,
        PRIMARY KEY (namespace, org_id, id),
        CHECK (status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
        CHECK (version >= 0),
        CHECK (jsonb_typeof(rules) = 'object')
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_policies_org_updated_idx
      ON console_policies (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_policies_org_status_idx
      ON console_policies (namespace, org_id, status)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_policy_versions (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        status TEXT NOT NULL,
        rules JSONB NOT NULL,
        published_at_ms BIGINT,
        created_at_ms BIGINT NOT NULL,
        actor_user_id TEXT NOT NULL,
        PRIMARY KEY (namespace, org_id, policy_id, version),
        FOREIGN KEY (namespace, org_id, policy_id)
          REFERENCES console_policies(namespace, org_id, id)
          ON DELETE CASCADE,
        CHECK (status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
        CHECK (version >= 0),
        CHECK (jsonb_typeof(rules) = 'object')
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_policy_versions_org_policy_created_idx
      ON console_policy_versions (namespace, org_id, policy_id, created_at_ms DESC)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_policy_assignments (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        id TEXT NOT NULL,
        scope_type TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, id),
        UNIQUE (namespace, org_id, scope_type, scope_id),
        FOREIGN KEY (namespace, org_id, policy_id)
          REFERENCES console_policies(namespace, org_id, id)
          ON DELETE CASCADE,
        CHECK (scope_type IN ('ORG', 'PROJECT', 'ENVIRONMENT', 'WALLET'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_policy_assignments_org_updated_idx
      ON console_policy_assignments (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_policy_assignments_org_scope_idx
      ON console_policy_assignments (namespace, org_id, scope_type, scope_id)
    `);
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_POLICIES_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }
  options.logger.info('[console-policies][postgres] Schema ready');
}

export interface PostgresConsolePolicyServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsolePolicyService(
  options: PostgresConsolePolicyServiceOptions,
): Promise<ConsolePolicyService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) throw new Error('Missing POSTGRES_URL for Postgres console policy service');

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());

  if (options.ensureSchema !== false) {
    await ensureConsolePoliciesPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }
  const pool = await getPostgresPool(postgresUrl);

  async function ensureDefaultPolicy(q: Queryable, ctx: ConsolePoliciesContext): Promise<void> {
    const now = nowFn();
    const createdAtMs = nowMs(now);
    const defaultPolicyId = `${ctx.orgId}:policy:default`;
    const defaultRules = {
      blockedActions: [],
      allowedChains: [],
    };

    await q.query(
      `INSERT INTO console_policies
        (namespace, org_id, id, name, description, status, version, rules, created_at_ms, updated_at_ms, published_at_ms)
       VALUES
        ($1, $2, $3, $4, $5, 'PUBLISHED', 1, $6::jsonb, $7, $7, $7)
       ON CONFLICT (namespace, org_id, id) DO NOTHING`,
      [
        namespace,
        ctx.orgId,
        defaultPolicyId,
        'Default Policy',
        'Default policy profile for this organization',
        JSON.stringify(defaultRules),
        createdAtMs,
      ],
    );

    await q.query(
      `INSERT INTO console_policy_versions
        (namespace, org_id, policy_id, version, status, rules, published_at_ms, created_at_ms, actor_user_id)
       VALUES
        ($1, $2, $3, 1, 'PUBLISHED', $4::jsonb, $5, $5, 'system-bootstrap')
       ON CONFLICT (namespace, org_id, policy_id, version) DO NOTHING`,
      [namespace, ctx.orgId, defaultPolicyId, JSON.stringify(defaultRules), createdAtMs],
    );

    await q.query(
      `INSERT INTO console_policy_assignments
        (namespace, org_id, id, scope_type, scope_id, policy_id, created_at_ms, updated_at_ms)
       VALUES
        ($1, $2, $3, 'ORG', $2, $4, $5, $5)
       ON CONFLICT (namespace, org_id, scope_type, scope_id) DO NOTHING`,
      [
        namespace,
        ctx.orgId,
        `${ctx.orgId}:policy-assignment:org-default`,
        defaultPolicyId,
        createdAtMs,
      ],
    );
  }

  async function findPolicy(
    q: Queryable,
    input: { orgId: string; policyId: string },
  ): Promise<ConsolePolicy | null> {
    const row = await queryOne(
      q,
      `SELECT *
         FROM console_policies
        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
      [namespace, input.orgId, input.policyId],
    );
    return row ? parsePolicyRow(row) : null;
  }

  async function findAssignmentById(
    q: Queryable,
    input: { orgId: string; assignmentId: string },
  ): Promise<ConsolePolicyAssignment | null> {
    const row = await queryOne(
      q,
      `SELECT *
         FROM console_policy_assignments
        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
      [namespace, input.orgId, input.assignmentId],
    );
    return row ? parsePolicyAssignmentRow(row) : null;
  }

  return {
    async listPolicies(ctx: ConsolePoliciesContext): Promise<ConsolePolicy[]> {
      await ensureDefaultPolicy(pool, ctx);
      const out = await pool.query(
        `SELECT *
           FROM console_policies
          WHERE namespace = $1 AND org_id = $2
          ORDER BY updated_at_ms DESC, created_at_ms DESC`,
        [namespace, ctx.orgId],
      );
      return out.rows.map((row) => parsePolicyRow(row as PgRow));
    },

    async createPolicy(
      ctx: ConsolePoliciesContext,
      request: CreateConsolePolicyRequest,
    ): Promise<ConsolePolicy> {
      await ensureDefaultPolicy(pool, ctx);
      const now = nowFn();
      const createdAtMs = nowMs(now);
      const policyId = String(request.id || makeId('policy', now)).trim();
      try {
        const row = await withTx(pool, async (q) => {
          const inserted = await queryOne(
            q,
            `INSERT INTO console_policies
              (namespace, org_id, id, name, description, status, version, rules, created_at_ms, updated_at_ms, published_at_ms)
             VALUES
              ($1, $2, $3, $4, $5, 'DRAFT', 0, $6::jsonb, $7, $7, NULL)
             RETURNING *`,
            [
              namespace,
              ctx.orgId,
              policyId,
              request.name,
              request.description || null,
              JSON.stringify(request.rules || {}),
              createdAtMs,
            ],
          );
          if (!inserted) {
            throw new ConsolePolicyError('internal', 500, 'Failed to create policy');
          }
          return inserted;
        });
        return parsePolicyRow(row);
      } catch (error: unknown) {
        if (typeof error === 'object' && error && (error as any).code === '23505') {
          throw new ConsolePolicyError(
            'policy_already_exists',
            409,
            `Policy ${policyId} already exists`,
          );
        }
        throw error;
      }
    },

    async updatePolicy(
      ctx: ConsolePoliciesContext,
      policyId: string,
      request: UpdateConsolePolicyRequest,
    ): Promise<ConsolePolicy | null> {
      await ensureDefaultPolicy(pool, ctx);
      const current = await findPolicy(pool, { orgId: ctx.orgId, policyId });
      if (!current) return null;
      if (current.status === 'ARCHIVED') {
        throw new ConsolePolicyError(
          'policy_archived',
          409,
          `Policy ${policyId} is archived and cannot be updated`,
        );
      }

      const row = await queryOne(
        pool,
        `UPDATE console_policies
            SET name = $4,
                description = $5,
                rules = $6::jsonb,
                status = 'DRAFT',
                updated_at_ms = $7
          WHERE namespace = $1 AND org_id = $2 AND id = $3
          RETURNING *`,
        [
          namespace,
          ctx.orgId,
          policyId,
          request.name || current.name,
          request.description || current.description,
          JSON.stringify(request.rules || current.rules || {}),
          nowMs(nowFn()),
        ],
      );
      return row ? parsePolicyRow(row) : null;
    },

    async publishPolicy(
      ctx: ConsolePoliciesContext,
      policyId: string,
    ): Promise<PublishConsolePolicyResult | null> {
      await ensureDefaultPolicy(pool, ctx);
      const current = await findPolicy(pool, { orgId: ctx.orgId, policyId });
      if (!current) return null;
      if (current.status === 'ARCHIVED') {
        throw new ConsolePolicyError(
          'policy_archived',
          409,
          `Policy ${policyId} is archived and cannot be published`,
        );
      }

      const now = nowFn();
      const publishedAtMs = nowMs(now);
      const updated = await withTx(pool, async (q) => {
        const row = await queryOne(
          q,
          `UPDATE console_policies
              SET status = 'PUBLISHED',
                  version = version + 1,
                  updated_at_ms = $4,
                  published_at_ms = $4
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [namespace, ctx.orgId, policyId, publishedAtMs],
        );
        if (!row) return null;
        const policy = parsePolicyRow(row);
        await q.query(
          `INSERT INTO console_policy_versions
            (namespace, org_id, policy_id, version, status, rules, published_at_ms, created_at_ms, actor_user_id)
           VALUES
            ($1, $2, $3, $4, $5, $6::jsonb, $7, $7, $8)
           ON CONFLICT (namespace, org_id, policy_id, version) DO NOTHING`,
          [
            namespace,
            ctx.orgId,
            policy.id,
            policy.version,
            policy.status,
            JSON.stringify(policy.rules || {}),
            publishedAtMs,
            ctx.actorUserId,
          ],
        );
        return policy;
      });
      if (!updated) return null;
      return {
        published: true,
        policy: updated,
      };
    },

    async simulatePolicy(
      ctx: ConsolePoliciesContext,
      policyId: string,
      request: SimulateConsolePolicyRequest,
    ): Promise<SimulateConsolePolicyResult | null> {
      await ensureDefaultPolicy(pool, ctx);
      const policy = await findPolicy(pool, { orgId: ctx.orgId, policyId });
      if (!policy) return null;
      const decision = evaluatePolicyRules(policy, request);
      const reasons: string[] = [];
      if (decision === 'DENY') {
        reasons.push('One or more policy rules denied this request');
      } else {
        reasons.push('All evaluated rules passed');
      }
      return {
        policyId: policy.id,
        decision: decision || 'DENY',
        reasons,
        evaluatedAt: nowFn().toISOString(),
        policyVersion: policy.version,
      };
    },

    async listAssignments(
      ctx: ConsolePoliciesContext,
      request: ListConsolePolicyAssignmentsRequest = {},
    ): Promise<ConsolePolicyAssignment[]> {
      await ensureDefaultPolicy(pool, ctx);
      const where: string[] = ['namespace = $1', 'org_id = $2'];
      const values: unknown[] = [namespace, ctx.orgId];
      let idx = values.length;

      const scopeType = request.scopeType ? normalizeScopeType(request.scopeType) : '';
      const scopeId = String(request.scopeId || '').trim();
      if (scopeType) {
        idx += 1;
        where.push(`scope_type = $${idx}`);
        values.push(scopeType);
      }
      if (scopeId) {
        idx += 1;
        where.push(`scope_id = $${idx}`);
        values.push(scopeId);
      }

      const out = await pool.query(
        `SELECT *
           FROM console_policy_assignments
          WHERE ${where.join(' AND ')}
          ORDER BY updated_at_ms DESC, created_at_ms DESC`,
        values,
      );
      return out.rows.map((row) => parsePolicyAssignmentRow(row as PgRow));
    },

    async upsertAssignment(
      ctx: ConsolePoliciesContext,
      request: UpsertConsolePolicyAssignmentRequest,
    ): Promise<ConsolePolicyAssignment> {
      await ensureDefaultPolicy(pool, ctx);
      const policy = await findPolicy(pool, { orgId: ctx.orgId, policyId: request.policyId });
      if (!policy) {
        throw new ConsolePolicyError(
          'policy_not_found',
          404,
          `Policy ${request.policyId} was not found`,
        );
      }

      const now = nowFn();
      const tsMs = nowMs(now);
      const scopeType = normalizeScopeType(request.scopeType);
      const scopeId = String(request.scopeId || '').trim();
      const assignmentId = makeId('policy_assignment', now);
      const row = await queryOne(
        pool,
        `INSERT INTO console_policy_assignments
          (namespace, org_id, id, scope_type, scope_id, policy_id, created_at_ms, updated_at_ms)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $7)
         ON CONFLICT (namespace, org_id, scope_type, scope_id)
         DO UPDATE
           SET policy_id = EXCLUDED.policy_id,
               updated_at_ms = EXCLUDED.updated_at_ms
         RETURNING *`,
        [namespace, ctx.orgId, assignmentId, scopeType, scopeId, request.policyId, tsMs],
      );
      if (!row) {
        throw new ConsolePolicyError('internal', 500, 'Failed to upsert policy assignment');
      }
      return parsePolicyAssignmentRow(row);
    },

    async deleteAssignment(
      ctx: ConsolePoliciesContext,
      assignmentId: string,
    ): Promise<{ removed: boolean; assignment: ConsolePolicyAssignment | null }> {
      await ensureDefaultPolicy(pool, ctx);
      const current = await findAssignmentById(pool, { orgId: ctx.orgId, assignmentId });
      if (!current) return { removed: false, assignment: null };

      const out = await pool.query(
        `DELETE FROM console_policy_assignments
          WHERE namespace = $1 AND org_id = $2 AND id = $3`,
        [namespace, ctx.orgId, assignmentId],
      );
      return {
        removed: Number(out.rowCount || 0) > 0,
        assignment: current,
      };
    },

    async resolvePoliciesForWallets(
      ctx: ConsolePoliciesContext,
      wallets: ConsolePolicyWalletScopeRef[],
    ): Promise<Record<string, string | null>> {
      await ensureDefaultPolicy(pool, ctx);
      const out = await pool.query(
        `SELECT *
           FROM console_policy_assignments
          WHERE namespace = $1 AND org_id = $2`,
        [namespace, ctx.orgId],
      );
      const assignments = out.rows.map((row) => parsePolicyAssignmentRow(row as PgRow));
      const byScope = new Map<string, string>();
      for (const assignment of assignments) {
        byScope.set(assignmentScopeKey(assignment.scopeType, assignment.scopeId), assignment.policyId);
      }

      const orgPolicyId = byScope.get(assignmentScopeKey('ORG', ctx.orgId)) || null;
      const resolved: Record<string, string | null> = {};
      for (const wallet of wallets) {
        const walletId = String(wallet.walletId || '').trim();
        if (!walletId) continue;

        const walletPolicyId = byScope.get(assignmentScopeKey('WALLET', walletId));
        if (walletPolicyId) {
          resolved[walletId] = walletPolicyId;
          continue;
        }
        const environmentId = String(wallet.environmentId || '').trim();
        if (environmentId) {
          const environmentPolicyId = byScope.get(assignmentScopeKey('ENVIRONMENT', environmentId));
          if (environmentPolicyId) {
            resolved[walletId] = environmentPolicyId;
            continue;
          }
        }
        const projectId = String(wallet.projectId || '').trim();
        if (projectId) {
          const projectPolicyId = byScope.get(assignmentScopeKey('PROJECT', projectId));
          if (projectPolicyId) {
            resolved[walletId] = projectPolicyId;
            continue;
          }
        }
        resolved[walletId] = orgPolicyId || wallet.fallbackPolicyId || null;
      }
      return resolved;
    },
  };
}
