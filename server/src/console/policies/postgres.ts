import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import {
  ensureConsoleNamespace as ensureNamespace,
  toConsoleIso as toIso,
  toConsoleNumber as toNumber,
} from '../shared/postgresNormalize';
import {
  ensureConsoleTenantRlsPolicies,
  withConsoleTenantContextTx,
} from '../shared/postgresTenantContext';
import { ConsolePolicyError } from './errors';
import {
  normalizePolicyScopeType as normalizeScopeType,
  policyScopeKey as assignmentScopeKey,
} from './normalization';
import {
  createDefaultConsolePolicyRules,
  evaluateConsolePolicyRules,
  isConsoleGasSponsorshipPolicyRules,
  isConsoleTransactionPolicyRules,
  parseConsolePolicyRulesInput,
  parseStoredConsolePolicyRules,
  serializeConsolePolicyRules,
  validateGasSponsorshipPolicyRulesForPublish,
} from './rules';
import type { ConsolePoliciesContext, ConsolePolicyService } from './service';
import type {
  ConsolePolicyAssignment,
  ConsolePolicyKind,
  ConsolePolicyWalletScopeRef,
  ConsolePolicy,
  ConsolePolicyVersion,
  CreateConsolePolicyRequest,
  DeleteConsolePolicyResult,
  ListConsolePoliciesRequest,
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
const DEFAULT_POLICY_NAME = 'Default Policy';
const DEFAULT_POLICY_DESCRIPTION = 'Default policy profile for this organization';
const CANONICAL_POLICY_ID_PATTERN = /^policy_([0-9a-z]+)_([0-9a-z]{8})$/;
const CANONICAL_POLICY_ID_TIMESTAMP_DRIFT_MS = 1000 * 60 * 60 * 24 * 30;

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
    return raw as Record<string, unknown>;
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return {};
    }
  }
  return {};
}

function parseBoolean(raw: unknown): boolean {
  if (typeof raw === 'boolean') return raw;
  const value = String(raw || '')
    .trim()
    .toLowerCase();
  return value === 'true' || value === 't' || value === '1';
}

function parsePolicyKind(raw: unknown): ConsolePolicyKind {
  return String(raw || '').trim().toUpperCase() === 'GAS_SPONSORSHIP'
    ? 'GAS_SPONSORSHIP'
    : 'TRANSACTION';
}

function parsePolicyRow(row: PgRow): ConsolePolicy {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    isSystemDefault: parseBoolean(row.is_system_default),
    kind: parsePolicyKind(row.kind),
    name: String(row.name || ''),
    description: row.description == null ? null : String(row.description || '') || null,
    status: String(row.status || 'DRAFT') as ConsolePolicy['status'],
    version: toNumber(row.version),
    rules: parseStoredConsolePolicyRules(parseRules(row.rules), parsePolicyKind(row.kind)),
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

function parsePolicyVersionRow(row: PgRow): ConsolePolicyVersion {
  return {
    policyId: String(row.policy_id || ''),
    kind: parsePolicyKind(row.kind),
    version: toNumber(row.version),
    status: String(row.status || 'PUBLISHED') as ConsolePolicyVersion['status'],
    rules: parseStoredConsolePolicyRules(parseRules(row.rules), parsePolicyKind(row.kind)),
    publishedAt: toIso(row.published_at_ms == null ? null : toNumber(row.published_at_ms)),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    actorUserId: String(row.actor_user_id || ''),
  };
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

function isUniqueViolation(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && (error as { code?: unknown }).code === '23505');
}

function isCanonicalPolicyId(policyId: string, createdAtMs: number): boolean {
  const match = CANONICAL_POLICY_ID_PATTERN.exec(String(policyId || '').trim());
  if (!match) return false;
  const encodedCreatedAtMs = parseInt(match[1] || '', 36);
  if (!Number.isFinite(encodedCreatedAtMs) || encodedCreatedAtMs <= 0) return false;
  if (createdAtMs <= 0) return true;
  return Math.abs(encodedCreatedAtMs - createdAtMs) <= CANONICAL_POLICY_ID_TIMESTAMP_DRIFT_MS;
}

async function tableExists(q: Queryable, tableName: string): Promise<boolean> {
  const row = await queryOne(q, 'SELECT to_regclass($1) AS regclass', [tableName]);
  return row?.regclass != null;
}

interface PolicyReferenceTables {
  approvals: boolean;
  auditEvents: boolean;
  smartWalletConfigs: boolean;
  sponsoredCallRecords: boolean;
  sponsorshipSpendCapReservations: boolean;
  sponsorshipSpendCapWindows: boolean;
  walletIndex: boolean;
}

interface ExistingPolicyRow {
  createdAtMs: number;
  id: string;
  isSystemDefault: boolean;
  namespace: string;
  namespaceIdRank: number;
  orgId: string;
}

interface PolicyIdMigrationPlan {
  forceSystemDefault: boolean;
  namespace: string;
  orgId: string;
  sourcePolicyId: string;
  targetPolicyId: string;
}

async function detectPolicyReferenceTables(q: Queryable): Promise<PolicyReferenceTables> {
  const [
    approvals,
    auditEvents,
    smartWalletConfigs,
    sponsoredCallRecords,
    sponsorshipSpendCapReservations,
    sponsorshipSpendCapWindows,
    walletIndex,
  ] = await Promise.all([
    tableExists(q, 'console_approvals'),
    tableExists(q, 'console_audit_events'),
    tableExists(q, 'console_smart_wallet_configs'),
    tableExists(q, 'console_sponsored_call_records'),
    tableExists(q, 'console_sponsorship_spend_cap_reservations'),
    tableExists(q, 'console_sponsorship_spend_cap_windows'),
    tableExists(q, 'console_wallet_index'),
  ]);
  return {
    approvals,
    auditEvents,
    smartWalletConfigs,
    sponsoredCallRecords,
    sponsorshipSpendCapReservations,
    sponsorshipSpendCapWindows,
    walletIndex,
  };
}

function buildOrgKey(namespace: string, orgId: string): string {
  return `${namespace}\n${orgId}`;
}

function allocateCanonicalPolicyId(input: {
  createdAtMs: number;
  reservedIds: Set<string>;
}): string {
  const seedMs = input.createdAtMs > 0 ? input.createdAtMs : Date.now();
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const candidate = makeId('policy', new Date(seedMs + attempt));
    if (input.reservedIds.has(candidate)) continue;
    input.reservedIds.add(candidate);
    return candidate;
  }
  throw new Error('Failed to allocate canonical policy id');
}

async function planPolicyIdMigrations(q: Queryable): Promise<PolicyIdMigrationPlan[]> {
  const out = await q.query(
    `SELECT namespace,
            org_id,
            id,
            created_at_ms,
            is_system_default,
            ROW_NUMBER() OVER (
              PARTITION BY namespace, id
              ORDER BY created_at_ms ASC, org_id ASC, id ASC
            ) AS namespace_id_rank
       FROM console_policies
      ORDER BY namespace ASC, org_id ASC, created_at_ms ASC, id ASC`,
    [],
  );
  const rows = out.rows.map((row) => ({
    createdAtMs: Math.max(0, toNumber((row as PgRow).created_at_ms)),
    id: String((row as PgRow).id || ''),
    isSystemDefault: parseBoolean((row as PgRow).is_system_default),
    namespace: String((row as PgRow).namespace || ''),
    namespaceIdRank: Math.max(1, toNumber((row as PgRow).namespace_id_rank)),
    orgId: String((row as PgRow).org_id || ''),
  }));
  const reservedIdsByNamespace = new Map<string, Set<string>>();
  const rowsByOrg = new Map<string, ExistingPolicyRow[]>();
  for (const row of rows) {
    if (!reservedIdsByNamespace.has(row.namespace)) {
      reservedIdsByNamespace.set(row.namespace, new Set<string>());
    }
    reservedIdsByNamespace.get(row.namespace)!.add(row.id);
    const orgKey = buildOrgKey(row.namespace, row.orgId);
    if (!rowsByOrg.has(orgKey)) rowsByOrg.set(orgKey, []);
    rowsByOrg.get(orgKey)!.push(row);
  }

  const plans: PolicyIdMigrationPlan[] = [];
  for (const orgRows of rowsByOrg.values()) {
    const namespace = orgRows[0]?.namespace || '';
    const orgId = orgRows[0]?.orgId || '';
    const legacyDefaultPolicyId = `${orgId}:policy:default`;
    const reservedIds = reservedIdsByNamespace.get(namespace);
    if (!namespace || !orgId || !reservedIds) continue;

    const legacyDefaultRow = orgRows.find((row) => row.id === legacyDefaultPolicyId) || null;
    const systemDefaultRow = orgRows.find((row) => row.isSystemDefault) || null;
    const defaultSource = systemDefaultRow || legacyDefaultRow;
    const handledSourceIds = new Set<string>();

    if (defaultSource) {
      const defaultNeedsRewrite =
        !isCanonicalPolicyId(defaultSource.id, defaultSource.createdAtMs) ||
        defaultSource.namespaceIdRank > 1;
      const finalDefaultId = defaultNeedsRewrite
        ? allocateCanonicalPolicyId({
            createdAtMs: defaultSource.createdAtMs,
            reservedIds,
          })
        : defaultSource.id;
      if (defaultSource.id !== finalDefaultId) {
        plans.push({
          forceSystemDefault: true,
          namespace,
          orgId,
          sourcePolicyId: defaultSource.id,
          targetPolicyId: finalDefaultId,
        });
      }
      handledSourceIds.add(defaultSource.id);

      if (legacyDefaultRow && legacyDefaultRow.id !== defaultSource.id) {
        plans.push({
          forceSystemDefault: false,
          namespace,
          orgId,
          sourcePolicyId: legacyDefaultRow.id,
          targetPolicyId: finalDefaultId,
        });
        handledSourceIds.add(legacyDefaultRow.id);
      }
    }

    for (const row of orgRows) {
      if (handledSourceIds.has(row.id)) continue;
      const needsRewrite =
        !isCanonicalPolicyId(row.id, row.createdAtMs) || row.namespaceIdRank > 1;
      if (!needsRewrite) continue;
      plans.push({
        forceSystemDefault: row.isSystemDefault,
        namespace,
        orgId,
        sourcePolicyId: row.id,
        targetPolicyId: allocateCanonicalPolicyId({
          createdAtMs: row.createdAtMs,
          reservedIds,
        }),
      });
    }
  }

  return plans;
}

async function rewritePolicyIdReferences(
  q: Queryable,
  input: {
    migratedAtMs: number;
    namespace: string;
    orgId: string;
    sourcePolicyId: string;
    targetPolicyId: string;
    tables: PolicyReferenceTables;
  },
): Promise<void> {
  const { migratedAtMs, namespace, orgId, sourcePolicyId, targetPolicyId, tables } = input;

  await q.query(
    `UPDATE console_policy_assignments
        SET policy_id = $4,
            updated_at_ms = GREATEST(updated_at_ms, $5)
      WHERE namespace = $1 AND org_id = $2 AND policy_id = $3`,
    [namespace, orgId, sourcePolicyId, targetPolicyId, migratedAtMs],
  );

  if (tables.walletIndex) {
    await q.query(
      `UPDATE console_wallet_index
          SET policy_id = $4,
              updated_at_ms = GREATEST(updated_at_ms, $5)
        WHERE namespace = $1 AND org_id = $2 AND policy_id = $3`,
      [namespace, orgId, sourcePolicyId, targetPolicyId, migratedAtMs],
    );
  }

  if (tables.smartWalletConfigs) {
    await q.query(
      `UPDATE console_smart_wallet_configs
          SET policy_id = $4,
              updated_at_ms = GREATEST(updated_at_ms, $5)
        WHERE namespace = $1 AND org_id = $2 AND policy_id = $3`,
      [namespace, orgId, sourcePolicyId, targetPolicyId, migratedAtMs],
    );
  }

  if (tables.sponsorshipSpendCapWindows) {
    await q.query(
      `UPDATE console_sponsorship_spend_cap_windows
          SET policy_id = $4,
              updated_at_ms = GREATEST(updated_at_ms, $5)
        WHERE namespace = $1 AND org_id = $2 AND policy_id = $3`,
      [namespace, orgId, sourcePolicyId, targetPolicyId, migratedAtMs],
    );
  }

  if (tables.sponsorshipSpendCapReservations) {
    await q.query(
      `UPDATE console_sponsorship_spend_cap_reservations
          SET policy_id = $4,
              updated_at_ms = GREATEST(updated_at_ms, $5)
        WHERE namespace = $1 AND org_id = $2 AND policy_id = $3`,
      [namespace, orgId, sourcePolicyId, targetPolicyId, migratedAtMs],
    );
  }

  if (tables.sponsoredCallRecords) {
    await q.query(
      `UPDATE console_sponsored_call_records
          SET policy_id = $4,
              updated_at_ms = GREATEST(updated_at_ms, $5)
        WHERE namespace = $1 AND org_id = $2 AND policy_id = $3`,
      [namespace, orgId, sourcePolicyId, targetPolicyId, migratedAtMs],
    );
  }

  if (tables.approvals) {
    await q.query(
      `UPDATE console_approvals
          SET resource_id = CASE
                WHEN resource_type = 'policy' AND resource_id = $3 THEN $4
                ELSE resource_id
              END,
              metadata = CASE
                WHEN COALESCE(metadata->>'policyId', '') = $3 AND COALESCE(metadata->>'resourceId', '') = $3
                  THEN jsonb_set(jsonb_set(metadata, '{policyId}', to_jsonb($4::text), true), '{resourceId}', to_jsonb($4::text), true)
                WHEN COALESCE(metadata->>'policyId', '') = $3
                  THEN jsonb_set(metadata, '{policyId}', to_jsonb($4::text), true)
                WHEN COALESCE(metadata->>'resourceId', '') = $3
                  THEN jsonb_set(metadata, '{resourceId}', to_jsonb($4::text), true)
                ELSE metadata
              END,
              updated_at_ms = GREATEST(updated_at_ms, $5)
        WHERE namespace = $1
          AND org_id = $2
          AND (
            (resource_type = 'policy' AND resource_id = $3)
            OR COALESCE(metadata->>'policyId', '') = $3
            OR COALESCE(metadata->>'resourceId', '') = $3
          )`,
      [namespace, orgId, sourcePolicyId, targetPolicyId, migratedAtMs],
    );
  }

  if (tables.auditEvents) {
    await q.query(
      `UPDATE console_audit_events
          SET metadata = CASE
                WHEN COALESCE(metadata->>'policyId', '') = $3 AND COALESCE(metadata->>'resourceId', '') = $3
                  THEN jsonb_set(jsonb_set(metadata, '{policyId}', to_jsonb($4::text), true), '{resourceId}', to_jsonb($4::text), true)
                WHEN COALESCE(metadata->>'policyId', '') = $3
                  THEN jsonb_set(metadata, '{policyId}', to_jsonb($4::text), true)
                WHEN COALESCE(metadata->>'resourceId', '') = $3
                  THEN jsonb_set(metadata, '{resourceId}', to_jsonb($4::text), true)
                ELSE metadata
              END,
              summary = CASE
                WHEN POSITION($3 IN summary) > 0 THEN replace(summary, $3, $4)
                ELSE summary
              END,
              created_at_ms = created_at_ms
        WHERE namespace = $1
          AND org_id = $2
          AND (
            COALESCE(metadata->>'policyId', '') = $3
            OR COALESCE(metadata->>'resourceId', '') = $3
            OR POSITION($3 IN summary) > 0
          )`,
      [namespace, orgId, sourcePolicyId, targetPolicyId],
    );
  }
}

async function migrateStoredPolicyId(
  q: Queryable,
  input: PolicyIdMigrationPlan & {
    migratedAtMs: number;
    tables: PolicyReferenceTables;
  },
): Promise<void> {
  if (input.sourcePolicyId === input.targetPolicyId) return;

  const source = await queryOne(
    q,
    `SELECT *
       FROM console_policies
      WHERE namespace = $1 AND org_id = $2 AND id = $3`,
    [input.namespace, input.orgId, input.sourcePolicyId],
  );
  if (!source) return;

  const sourceIsSystemDefault = parseBoolean(source.is_system_default);
  const target = await queryOne(
    q,
    `SELECT *
       FROM console_policies
      WHERE namespace = $1 AND org_id = $2 AND id = $3`,
    [input.namespace, input.orgId, input.targetPolicyId],
  );

  if (!target && (sourceIsSystemDefault || input.forceSystemDefault)) {
    await q.query(
      `UPDATE console_policies
          SET is_system_default = FALSE
        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
      [input.namespace, input.orgId, input.sourcePolicyId],
    );
  }

  if (!target) {
    await q.query(
      `INSERT INTO console_policies
        (namespace, org_id, id, kind, name, description, status, version, rules, created_at_ms, updated_at_ms, published_at_ms, is_system_default)
       SELECT namespace,
              org_id,
              $4,
              kind,
              name,
              description,
              status,
              version,
              rules,
              created_at_ms,
              updated_at_ms,
              published_at_ms,
              $5
         FROM console_policies
        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
      [
        input.namespace,
        input.orgId,
        input.sourcePolicyId,
        input.targetPolicyId,
        sourceIsSystemDefault || input.forceSystemDefault,
      ],
    );
  } else if (input.forceSystemDefault) {
    await q.query(
      `UPDATE console_policies
          SET is_system_default = TRUE
        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
      [input.namespace, input.orgId, input.targetPolicyId],
    );
  }

  await q.query(
    `INSERT INTO console_policy_versions
      (namespace, org_id, policy_id, kind, version, status, rules, published_at_ms, created_at_ms, actor_user_id)
     SELECT namespace, org_id, $4, kind, version, status, rules, published_at_ms, created_at_ms, actor_user_id
       FROM console_policy_versions
      WHERE namespace = $1 AND org_id = $2 AND policy_id = $3
     ON CONFLICT (namespace, org_id, policy_id, version) DO NOTHING`,
    [input.namespace, input.orgId, input.sourcePolicyId, input.targetPolicyId],
  );

  await rewritePolicyIdReferences(q, input);

  await q.query(
    `DELETE FROM console_policies
      WHERE namespace = $1 AND org_id = $2 AND id = $3`,
    [input.namespace, input.orgId, input.sourcePolicyId],
  );
}

async function normalizeStoredPolicyIds(pool: PgPool): Promise<void> {
  const plans = await planPolicyIdMigrations(pool);
  if (plans.length === 0) return;

  const tables = await detectPolicyReferenceTables(pool);
  const plansByOrg = new Map<string, PolicyIdMigrationPlan[]>();
  for (const plan of plans) {
    const orgKey = buildOrgKey(plan.namespace, plan.orgId);
    if (!plansByOrg.has(orgKey)) plansByOrg.set(orgKey, []);
    plansByOrg.get(orgKey)!.push(plan);
  }

  for (const [orgKey, orgPlans] of plansByOrg.entries()) {
    const [namespace, orgId] = orgKey.split('\n');
    await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
      const migratedAtMs = Date.now();
      for (const plan of orgPlans) {
        await migrateStoredPolicyId(q, {
          ...plan,
          migratedAtMs,
          tables,
        });
      }
    });
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
        kind TEXT NOT NULL DEFAULT 'TRANSACTION',
        name TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL,
        version INTEGER NOT NULL,
        rules JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        published_at_ms BIGINT,
        PRIMARY KEY (namespace, org_id, id),
        CHECK (kind IN ('TRANSACTION', 'GAS_SPONSORSHIP')),
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
      ALTER TABLE console_policies
      ADD COLUMN IF NOT EXISTS is_system_default BOOLEAN NOT NULL DEFAULT FALSE
    `);
    await pool.query(`
      ALTER TABLE console_policies
      ADD COLUMN IF NOT EXISTS kind TEXT
    `);
    await pool.query(`
      UPDATE console_policies
         SET kind = 'TRANSACTION'
       WHERE kind IS NULL OR kind = ''
    `);
    await pool.query(`
      ALTER TABLE console_policies
      ALTER COLUMN kind SET DEFAULT 'TRANSACTION'
    `);
    await pool.query(`
      ALTER TABLE console_policies
      ALTER COLUMN kind SET NOT NULL
    `);
    await pool.query(`
      DO $$
      BEGIN
        ALTER TABLE console_policies
          ADD CONSTRAINT console_policies_kind_check
          CHECK (kind IN ('TRANSACTION', 'GAS_SPONSORSHIP'));
      EXCEPTION
        WHEN duplicate_object THEN NULL;
      END
      $$
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_policy_versions (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT 'TRANSACTION',
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
        CHECK (kind IN ('TRANSACTION', 'GAS_SPONSORSHIP')),
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
      ALTER TABLE console_policy_versions
      ADD COLUMN IF NOT EXISTS kind TEXT
    `);
    await pool.query(`
      UPDATE console_policy_versions
         SET kind = 'TRANSACTION'
       WHERE kind IS NULL OR kind = ''
    `);
    await pool.query(`
      ALTER TABLE console_policy_versions
      ALTER COLUMN kind SET DEFAULT 'TRANSACTION'
    `);
    await pool.query(`
      ALTER TABLE console_policy_versions
      ALTER COLUMN kind SET NOT NULL
    `);
    await pool.query(`
      DO $$
      BEGIN
        ALTER TABLE console_policy_versions
          ADD CONSTRAINT console_policy_versions_kind_check
          CHECK (kind IN ('TRANSACTION', 'GAS_SPONSORSHIP'));
      EXCEPTION
        WHEN duplicate_object THEN NULL;
      END
      $$
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

    await pool.query(`ALTER TABLE console_policies DISABLE ROW LEVEL SECURITY`);
    try {
      await normalizeStoredPolicyIds(pool);

      await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS console_policies_org_system_default_uidx
        ON console_policies (namespace, org_id)
        WHERE is_system_default = TRUE
      `);
      await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS console_policies_namespace_id_uidx
        ON console_policies (namespace, id)
      `);
    } finally {
      await ensureConsoleTenantRlsPolicies({
        q: pool,
        table: 'console_policies',
        policyName: 'console_policies_tenant_rls',
      });
      await ensureConsoleTenantRlsPolicies({
        q: pool,
        table: 'console_policy_versions',
        policyName: 'console_policy_versions_tenant_rls',
      });
      await ensureConsoleTenantRlsPolicies({
        q: pool,
        table: 'console_policy_assignments',
        policyName: 'console_policy_assignments_tenant_rls',
      });
    }
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
  const withTenantTx = <T>(
    ctx: ConsolePoliciesContext,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, fn);

  async function findSystemDefaultPolicy(
    q: Queryable,
    ctx: ConsolePoliciesContext,
  ): Promise<ConsolePolicy | null> {
    const row = await queryOne(
      q,
      `SELECT *
         FROM console_policies
        WHERE namespace = $1 AND org_id = $2 AND is_system_default = TRUE
        ORDER BY created_at_ms ASC
        LIMIT 1`,
      [namespace, ctx.orgId],
    );
    return row ? parsePolicyRow(row) : null;
  }

  async function generatePolicyId(q: Queryable, ctx: ConsolePoliciesContext, now: Date): Promise<string> {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const candidate = makeId('policy', now);
      const existing = await findPolicy(q, { orgId: ctx.orgId, policyId: candidate });
      if (!existing) return candidate;
    }
    throw new ConsolePolicyError('internal', 500, 'Failed to generate a unique policy id');
  }

  async function ensureDefaultPolicy(q: Queryable, ctx: ConsolePoliciesContext): Promise<void> {
    const existingDefault = await findSystemDefaultPolicy(q, ctx);
    if (existingDefault) return;

    const now = nowFn();
    const createdAtMs = nowMs(now);
    const defaultRules = createDefaultConsolePolicyRules('TRANSACTION');
    let defaultPolicyId = '';
    let inserted = false;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      defaultPolicyId = await generatePolicyId(q, ctx, now);
      try {
        await q.query(
          `INSERT INTO console_policies
            (namespace, org_id, id, kind, name, description, status, version, rules, created_at_ms, updated_at_ms, published_at_ms, is_system_default)
           VALUES
            ($1, $2, $3, 'TRANSACTION', $4, $5, 'PUBLISHED', 1, $6::jsonb, $7, $7, $7, TRUE)`,
          [
            namespace,
            ctx.orgId,
            defaultPolicyId,
            DEFAULT_POLICY_NAME,
            DEFAULT_POLICY_DESCRIPTION,
            JSON.stringify(serializeConsolePolicyRules(defaultRules)),
            createdAtMs,
          ],
        );
        inserted = true;
        break;
      } catch (error: unknown) {
        if (isUniqueViolation(error)) {
          const concurrentDefault = await findSystemDefaultPolicy(q, ctx);
          if (concurrentDefault) return;
          continue;
        }
        throw error;
      }
    }
    if (!inserted) {
      const concurrentDefault = await findSystemDefaultPolicy(q, ctx);
      if (concurrentDefault) return;
      throw new ConsolePolicyError('internal', 500, 'Failed to create default policy');
    }

    await q.query(
      `INSERT INTO console_policy_versions
        (namespace, org_id, policy_id, kind, version, status, rules, published_at_ms, created_at_ms, actor_user_id)
       VALUES
        ($1, $2, $3, 'TRANSACTION', 1, 'PUBLISHED', $4::jsonb, $5, $5, 'system-bootstrap')
       ON CONFLICT (namespace, org_id, policy_id, version) DO NOTHING`,
      [
        namespace,
        ctx.orgId,
        defaultPolicyId,
        JSON.stringify(serializeConsolePolicyRules(defaultRules)),
        createdAtMs,
      ],
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
        makeId('policy_assignment', now),
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

  async function upsertPolicyAssignmentRow(
    q: Queryable,
    ctx: ConsolePoliciesContext,
    request: UpsertConsolePolicyAssignmentRequest,
    now: Date = nowFn(),
  ): Promise<ConsolePolicyAssignment> {
    const tsMs = nowMs(now);
    const scopeType = normalizeScopeType(request.scopeType);
    const scopeId = String(request.scopeId || '').trim();
    const assignmentId = makeId('policy_assignment', now);
    const row = await queryOne(
      q,
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
  }

  return {
    async listPolicies(ctx: ConsolePoliciesContext, request = {}): Promise<ConsolePolicy[]> {
      return withTenantTx(ctx, async (q) => {
        await ensureDefaultPolicy(q, ctx);
        const kind = request.kind ? parsePolicyKind(request.kind) : null;
        const out = await q.query(
          `SELECT *
             FROM console_policies
            WHERE namespace = $1 AND org_id = $2
              AND ($3::text IS NULL OR kind = $3)
            ORDER BY updated_at_ms DESC, created_at_ms DESC`,
          [namespace, ctx.orgId, kind],
        );
        return out.rows.map((row) => parsePolicyRow(row as PgRow));
      });
    },

    async getPolicy(ctx: ConsolePoliciesContext, policyId: string): Promise<ConsolePolicy | null> {
      return withTenantTx(ctx, async (q) => {
        await ensureDefaultPolicy(q, ctx);
        return await findPolicy(q, { orgId: ctx.orgId, policyId });
      });
    },

    async listPolicyVersions(
      ctx: ConsolePoliciesContext,
      policyId: string,
    ): Promise<ConsolePolicyVersion[] | null> {
      return withTenantTx(ctx, async (q) => {
        await ensureDefaultPolicy(q, ctx);
        const current = await findPolicy(q, { orgId: ctx.orgId, policyId });
        if (!current) return null;
        const out = await q.query(
          `SELECT *
             FROM console_policy_versions
            WHERE namespace = $1 AND org_id = $2 AND policy_id = $3
            ORDER BY version DESC, created_at_ms DESC`,
          [namespace, ctx.orgId, policyId],
        );
        return out.rows.map((row) => parsePolicyVersionRow(row as PgRow));
      });
    },

    async createPolicy(
      ctx: ConsolePoliciesContext,
      request: CreateConsolePolicyRequest,
    ): Promise<ConsolePolicy> {
      return withTenantTx(ctx, async (q) => {
        await ensureDefaultPolicy(q, ctx);
        const now = nowFn();
        const createdAtMs = nowMs(now);
        const rules = parseConsolePolicyRulesInput(request.rules, request.kind || 'TRANSACTION');
        for (let attempt = 0; attempt < 8; attempt += 1) {
          const policyId = await generatePolicyId(q, ctx, now);
          try {
            const inserted = await queryOne(
              q,
              `INSERT INTO console_policies
                (namespace, org_id, id, kind, name, description, status, version, rules, created_at_ms, updated_at_ms, published_at_ms, is_system_default)
               VALUES
                ($1, $2, $3, $4, $5, $6, 'DRAFT', 0, $7::jsonb, $8, $8, NULL, FALSE)
               RETURNING *`,
              [
                namespace,
                ctx.orgId,
                policyId,
                request.kind || 'TRANSACTION',
                request.name,
                request.description || null,
                JSON.stringify(serializeConsolePolicyRules(rules)),
                createdAtMs,
              ],
            );
            if (!inserted) {
              throw new ConsolePolicyError('internal', 500, 'Failed to create policy');
            }
            const policy = parsePolicyRow(inserted);
            if (request.assignment) {
              await upsertPolicyAssignmentRow(
                q,
                ctx,
                {
                  scopeType: request.assignment.scopeType,
                  scopeId: request.assignment.scopeId,
                  policyId: policy.id,
                },
                now,
              );
            }
            return policy;
          } catch (error: unknown) {
            if (isUniqueViolation(error)) continue;
            throw error;
          }
        }
        throw new ConsolePolicyError('internal', 500, 'Failed to generate a unique policy id');
      });
    },

    async updatePolicy(
      ctx: ConsolePoliciesContext,
      policyId: string,
      request: UpdateConsolePolicyRequest,
    ): Promise<ConsolePolicy | null> {
      return withTenantTx(ctx, async (q) => {
        await ensureDefaultPolicy(q, ctx);
        const current = await findPolicy(q, { orgId: ctx.orgId, policyId });
        if (!current) return null;
        if (current.status === 'ARCHIVED') {
          throw new ConsolePolicyError(
            'policy_archived',
            409,
            `Policy ${policyId} is archived and cannot be updated`,
          );
        }

        const rules = request.rules
          ? parseConsolePolicyRulesInput(request.rules, current.kind)
          : current.rules;
        const row = await queryOne(
          q,
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
            request.description !== undefined ? request.description || null : current.description,
            JSON.stringify(serializeConsolePolicyRules(rules)),
            nowMs(nowFn()),
          ],
        );
        return row ? parsePolicyRow(row) : null;
      });
    },

    async publishPolicy(
      ctx: ConsolePoliciesContext,
      policyId: string,
    ): Promise<PublishConsolePolicyResult | null> {
      return withTenantTx(ctx, async (q) => {
        await ensureDefaultPolicy(q, ctx);
        const current = await findPolicy(q, { orgId: ctx.orgId, policyId });
        if (!current) return null;
        if (current.status === 'ARCHIVED') {
          throw new ConsolePolicyError(
            'policy_archived',
            409,
            `Policy ${policyId} is archived and cannot be published`,
          );
        }
        if (current.kind === 'GAS_SPONSORSHIP') {
          if (!isConsoleGasSponsorshipPolicyRules(current.rules)) {
            throw new ConsolePolicyError(
              'invalid_policy_rules',
              409,
              `Policy ${policyId} does not contain gas sponsorship rules`,
            );
          }
          validateGasSponsorshipPolicyRulesForPublish(current.rules);
        }

        const now = nowFn();
        const publishedAtMs = nowMs(now);
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
            (namespace, org_id, policy_id, kind, version, status, rules, published_at_ms, created_at_ms, actor_user_id)
           VALUES
            ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $8, $9)
           ON CONFLICT (namespace, org_id, policy_id, version) DO NOTHING`,
          [
            namespace,
            ctx.orgId,
            policy.id,
            policy.kind,
            policy.version,
            policy.status,
            JSON.stringify(serializeConsolePolicyRules(policy.rules)),
            publishedAtMs,
            ctx.actorUserId,
          ],
        );
        return {
          published: true,
          policy,
        };
      });
    },

    async deletePolicy(
      ctx: ConsolePoliciesContext,
      policyId: string,
    ): Promise<DeleteConsolePolicyResult> {
      return withTenantTx(ctx, async (q) => {
        await ensureDefaultPolicy(q, ctx);
        const current = await findPolicy(q, { orgId: ctx.orgId, policyId });
        if (!current) {
          return { removed: false, policy: null };
        }
        if (current.isSystemDefault) {
          throw new ConsolePolicyError(
            'default_policy_protected',
            409,
            `Policy ${policyId} is the organization default and cannot be deleted`,
          );
        }
        await q.query(
          `DELETE FROM console_policies
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, policyId],
        );
        return {
          removed: true,
          policy: current,
        };
      });
    },

    async simulatePolicy(
      ctx: ConsolePoliciesContext,
      policyId: string,
      request: SimulateConsolePolicyRequest,
    ): Promise<SimulateConsolePolicyResult | null> {
      return withTenantTx(ctx, async (q) => {
        await ensureDefaultPolicy(q, ctx);
        const policy = await findPolicy(q, { orgId: ctx.orgId, policyId });
        if (!policy) return null;
        if (policy.kind !== 'TRANSACTION' || !isConsoleTransactionPolicyRules(policy.rules)) {
          throw new ConsolePolicyError(
            'simulation_not_supported',
            409,
            `Policy simulation is only supported for TRANSACTION policies`,
          );
        }
        const evaluation = evaluateConsolePolicyRules(policy.rules, request);
        return {
          policyId: policy.id,
          decision: evaluation.decision,
          denyReasons: evaluation.denyReasons,
          evaluatedAt: nowFn().toISOString(),
          policyVersion: policy.version,
          normalizedRequest: evaluation.normalizedRequest,
        };
      });
    },

    async listAssignments(
      ctx: ConsolePoliciesContext,
      request: ListConsolePolicyAssignmentsRequest = {},
    ): Promise<ConsolePolicyAssignment[]> {
      return withTenantTx(ctx, async (q) => {
        await ensureDefaultPolicy(q, ctx);
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

        const out = await q.query(
          `SELECT *
             FROM console_policy_assignments
            WHERE ${where.join(' AND ')}
            ORDER BY updated_at_ms DESC, created_at_ms DESC`,
          values,
        );
        return out.rows.map((row) => parsePolicyAssignmentRow(row as PgRow));
      });
    },

    async upsertAssignment(
      ctx: ConsolePoliciesContext,
      request: UpsertConsolePolicyAssignmentRequest,
    ): Promise<ConsolePolicyAssignment> {
      return withTenantTx(ctx, async (q) => {
        await ensureDefaultPolicy(q, ctx);
        const policy = await findPolicy(q, { orgId: ctx.orgId, policyId: request.policyId });
        if (!policy) {
          throw new ConsolePolicyError(
            'policy_not_found',
            404,
            `Policy ${request.policyId} was not found`,
          );
        }
        if (policy.kind !== 'TRANSACTION') {
          throw new ConsolePolicyError(
            'policy_assignment_unsupported',
            409,
            `Policy ${request.policyId} cannot be assigned through transaction policy assignments`,
          );
        }

        return await upsertPolicyAssignmentRow(q, ctx, request);
      });
    },

    async deleteAssignment(
      ctx: ConsolePoliciesContext,
      assignmentId: string,
    ): Promise<{ removed: boolean; assignment: ConsolePolicyAssignment | null }> {
      return withTenantTx(ctx, async (q) => {
        await ensureDefaultPolicy(q, ctx);
        const current = await findAssignmentById(q, { orgId: ctx.orgId, assignmentId });
        if (!current) return { removed: false, assignment: null };

        const out = await q.query(
          `DELETE FROM console_policy_assignments
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, assignmentId],
        );
        return {
          removed: Number(out.rowCount || 0) > 0,
          assignment: current,
        };
      });
    },

    async resolvePoliciesForWallets(
      ctx: ConsolePoliciesContext,
      wallets: ConsolePolicyWalletScopeRef[],
    ): Promise<Record<string, string | null>> {
      return withTenantTx(ctx, async (q) => {
        await ensureDefaultPolicy(q, ctx);
        const out = await q.query(
          `SELECT a.scope_type, a.scope_id, a.policy_id
             FROM console_policy_assignments a
             JOIN console_policies p
               ON p.namespace = a.namespace
              AND p.org_id = a.org_id
              AND p.id = a.policy_id
            WHERE a.namespace = $1
              AND a.org_id = $2
              AND p.published_at_ms IS NOT NULL
              AND p.version > 0`,
          [namespace, ctx.orgId],
        );
        const byScope = new Map<string, string>();
        for (const row of out.rows) {
          const scopeType = String((row as PgRow).scope_type || 'ORG') as ConsolePolicyAssignment['scopeType'];
          const scopeId = String((row as PgRow).scope_id || '');
          const policyId = String((row as PgRow).policy_id || '');
          if (!scopeId || !policyId) continue;
          byScope.set(assignmentScopeKey(scopeType, scopeId), policyId);
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
      });
    },
  };
}
